"""Offline checks for scheduling, crash recovery and safe synchronization state."""

from contextlib import redirect_stdout
import fcntl
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


MODULE_PATH = Path(__file__).resolve().parents[1] / 'intel_sync.py'
SPEC = importlib.util.spec_from_file_location('intel_sync', MODULE_PATH)
sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sync
SPEC.loader.exec_module(sync)

NOW = 2_000_000_000
SECRET = 'upstream-error-must-not-expose-this-secret'


class CycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / 'state.json'

    def run_cycle(self, runner, now=NOW, preflight=None):
        with redirect_stdout(io.StringIO()):
            return sync.run_cycle(self.path, runner=runner,
                                  preflight=preflight or Mock(), clock=lambda: now)

    def test_new_install_runs_each_stage_and_persists_attempt_before_runner(self):
        attempted = []

        def runner(name):
            state = sync.load_state(self.path)['stages'][name]
            self.assertEqual(state['status'], 'running')
            self.assertEqual(state['last_attempt'], NOW)
            self.assertNotIn('last_success', state)
            attempted.append(name)
            return True

        result = self.run_cycle(runner)
        self.assertEqual(attempted, ['abuseipdb', 'greynoise', 'splunk'])
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['transitions'], [])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        for stage in sync.load_state(self.path)['stages'].values():
            self.assertEqual(stage['last_success'], NOW)
            self.assertEqual(stage['status'], 'ok')

    def test_five_minute_lookup_does_not_repeat_daily_feed_downloads(self):
        self.run_cycle(Mock(return_value=True))
        runner = Mock(return_value=True)
        self.run_cycle(runner, now=NOW + 299)
        runner.assert_not_called()
        self.run_cycle(runner, now=NOW + 300)
        self.assertEqual([call.args[0] for call in runner.call_args_list], ['splunk'])
        runner.reset_mock()
        self.run_cycle(runner, now=NOW + 86400)
        self.assertEqual([call.args[0] for call in runner.call_args_list], list(sync.STAGES))

    def test_provider_failure_does_not_block_other_provider_or_lookup(self):
        runner = Mock(side_effect=lambda name: name != 'abuseipdb')
        result = self.run_cycle(runner)
        self.assertEqual([call.args[0] for call in runner.call_args_list], list(sync.STAGES))
        self.assertEqual(result['status'], 'degraded')
        self.assertEqual(result['failed'], ['abuseipdb'])
        self.assertEqual(result['transitions'], ['abuseipdb:failure'])
        self.assertNotIn('last_success', sync.load_state(self.path)['stages']['abuseipdb'])

    def test_failed_provider_obeys_cooldown_and_reports_recovery_once(self):
        self.run_cycle(Mock(side_effect=lambda name: name != 'abuseipdb'))
        runner = Mock(return_value=True)
        waiting = self.run_cycle(runner, now=NOW + 21599)
        self.assertEqual([call.args[0] for call in runner.call_args_list], ['splunk'])
        self.assertEqual(waiting['stages']['abuseipdb'], 'cooldown')
        self.assertEqual(waiting['transitions'], [])
        runner.reset_mock()
        recovered = self.run_cycle(runner, now=NOW + 21600)
        self.assertEqual([call.args[0] for call in runner.call_args_list], ['abuseipdb'])
        self.assertEqual(recovered['transitions'], ['abuseipdb:recovered'])
        self.assertEqual(recovered['status'], 'ok')
        unchanged = self.run_cycle(runner, now=NOW + 21601)
        self.assertEqual(unchanged['transitions'], [])

    def test_repeated_failure_preserves_last_success_and_deduplicates_transition(self):
        self.run_cycle(Mock(return_value=True))
        runner = Mock(side_effect=lambda name: name != 'greynoise')
        failed = self.run_cycle(runner, now=NOW + 86400)
        self.assertEqual(failed['transitions'], ['greynoise:failure'])
        repeated = self.run_cycle(runner, now=NOW + 86400 + 21600)
        self.assertEqual(repeated['transitions'], [])
        state = sync.load_state(self.path)['stages']['greynoise']
        self.assertEqual(state['last_success'], NOW)
        self.assertEqual(state['last_attempt'], NOW + 86400 + 21600)

    def test_interrupted_provider_is_not_restarted_on_next_heartbeat(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_cycle(Mock(side_effect=KeyboardInterrupt()))
        stage = sync.load_state(self.path)['stages']['abuseipdb']
        self.assertEqual(stage['status'], 'running')
        self.assertEqual(stage['last_attempt'], NOW)
        runner = Mock(return_value=True)
        result = self.run_cycle(runner, now=NOW + 300)
        self.assertEqual([call.args[0] for call in runner.call_args_list], ['greynoise', 'splunk'])
        self.assertEqual(result['stages']['abuseipdb'], 'cooldown')

    def test_service_preflight_failure_does_not_consume_provider_attempt(self):
        runner = Mock(return_value=True)
        with self.assertRaises(sync.CycleError):
            self.run_cycle(runner, preflight=Mock(side_effect=sync.CycleError('Offline')))
        runner.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_runner_exception_is_redacted_and_other_stages_continue(self):
        def runner(name):
            if name == 'abuseipdb':
                raise RuntimeError(SECRET)
            return True

        output = io.StringIO()
        with redirect_stdout(output):
            result = sync.run_cycle(self.path, runner=runner,
                                    preflight=Mock(), clock=lambda: NOW)
        self.assertNotIn(SECRET, output.getvalue())
        self.assertNotIn(SECRET, self.path.read_text())
        self.assertEqual(result['stages']['splunk'], 'ok')

    def test_corrupt_state_fails_closed_before_preflight_or_network_work(self):
        bad_states = [
            '{broken json',
            json.dumps({'version': 2, 'stages': {}}),
            json.dumps({'version': 1, 'stages': {'unexpected': {}}}),
        ]
        for timestamp in (True, -1, float('nan'), float('inf'), 'yesterday'):
            bad_states.append(json.dumps({'version': 1, 'stages': {
                'abuseipdb': {'status': 'running', 'last_attempt': timestamp}}}))
        for body in bad_states:
            with self.subTest(body=body):
                self.path.write_text(body)
                runner, preflight = Mock(), Mock()
                with self.assertRaises(sync.CycleError):
                    self.run_cycle(runner, preflight=preflight)
                runner.assert_not_called()
                preflight.assert_not_called()
                self.assertEqual(self.path.read_text(), body)

    def test_failed_atomic_state_replace_keeps_previous_state(self):
        original = {'version': 1, 'stages': {}}
        sync.save_state(self.path, original)
        with patch.object(sync.os, 'replace', side_effect=OSError('offline disk failure')):
            with self.assertRaises(OSError):
                sync.save_state(self.path, {'version': 1, 'stages': {'new': 'unfinished'}})
        self.assertEqual(sync.load_state(self.path), original)
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_busy_process_lock_prevents_overlapping_cycle(self):
        with (self.root / 'cycle.lock').open('a') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            output = io.StringIO()
            with patch.object(sync, 'STATE_DIR', self.root), \
                 patch.object(sync, 'run_cycle') as cycle, redirect_stdout(output):
                self.assertEqual(sync.main(), 0)
            cycle.assert_not_called()
        result = json.loads(output.getvalue().strip().partition('=')[2])
        self.assertEqual(result, {'status': 'busy'})


class SchedulingAndProcessTests(unittest.TestCase):
    def test_slow_lookup_does_not_skip_next_five_minute_dispatch(self):
        stage = {'last_attempt': NOW, 'last_success': NOW + 120, 'status': 'ok'}
        self.assertFalse(sync.is_due('splunk', stage, NOW + 299))
        self.assertTrue(sync.is_due('splunk', stage, NOW + 300))

    def test_clock_rollback_does_not_trigger_another_download(self):
        for stage in ({'last_attempt': NOW, 'status': 'running'},
                      {'last_attempt': NOW, 'last_success': NOW, 'status': 'ok'}):
            with self.subTest(stage=stage):
                self.assertFalse(sync.is_due('abuseipdb', stage, NOW - 3600))

    def test_child_output_is_discarded_and_return_status_controls_success(self):
        for returncode in (0, 1):
            with self.subTest(returncode=returncode):
                with patch.object(sync.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=returncode, stdout=SECRET, stderr=SECRET)) as run:
                    self.assertEqual(sync.run_stage('greynoise'), returncode == 0)
                self.assertEqual(run.call_args.kwargs['stdout'], subprocess.DEVNULL)
                self.assertEqual(run.call_args.kwargs['stderr'], subprocess.DEVNULL)
                self.assertNotIn(SECRET, repr(run.call_args))


if __name__ == '__main__':
    unittest.main()
