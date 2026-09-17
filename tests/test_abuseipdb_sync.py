"""Offline lifecycle checks: never invokes Podman or the provider API."""

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'abuseipdb_sync', Path(__file__).resolve().parents[1] / 'abuseipdb_sync.py')
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)
TEST_KEY = 'offline-test-key'


class FakePodman:
    def __init__(self, *, fetch_output='Job done.', fetch_code=0,
                 invalid_status=None, failed_mode=None, lost_response=None,
                 install_fails=False, fetch_timeout=False):
        self.commands = []
        self.modes = []
        self.fetch_output = fetch_output
        self.fetch_code = fetch_code
        self.invalid_status = invalid_status or {}
        self.failed_mode = failed_mode
        self.lost_response = lost_response
        self.install_fails = install_fails
        self.fetch_timeout = fetch_timeout
        self.enabled = False

    def __call__(self, command, **kwargs):
        self.commands.append((command, kwargs))
        arguments = command[command.index('misp-core') + 1:]
        stdout, code = '', 0
        if arguments[:2] == [sync.CAKE, 'AbuseipdbSync']:
            payload = json.loads(kwargs['input'])
            mode = payload['mode']
            self.modes.append(mode)
            result = {'ok': True, 'feed_id': 3, 'user_id': 1, 'event_id': 1}
            if mode == 'enable':
                self.enabled = True
            elif mode == 'disable':
                self.enabled = False
            elif mode == 'status':
                result.update(attribute_count=10000, ip_dst_count=10000,
                              to_ids_count=0, published=False, distribution=0)
                result.update(self.invalid_status)
            result['enabled'] = self.enabled
            stdout = 'Cake banner\n' + sync.MARKER + json.dumps(result) + '\n'
            if mode == self.failed_mode:
                stdout, code = TEST_KEY, 1
            if mode == self.lost_response:
                stdout = ''
        elif arguments[:3] == [sync.CAKE, 'Server', 'fetchFeed']:
            if not self.enabled:
                raise AssertionError('Fetching requires a known enabled feed.')
            if self.fetch_timeout:
                raise subprocess.TimeoutExpired(command, 1800, output=TEST_KEY)
            stdout, code = self.fetch_output, self.fetch_code
        elif arguments[:2] == ['sh', '-c'] and self.install_fails:
            code = 1
        return subprocess.CompletedProcess(command, code, stdout, TEST_KEY if code else '')


class SyncTests(unittest.TestCase):
    def run_sync(self, podman):
        with patch.object(sync.subprocess, 'run', side_effect=podman), \
             patch.object(sync.Path, 'read_text', return_value='<?php /* offline fixture */'), \
             patch('sys.stdout', new_callable=io.StringIO):
            return sync.Misp({'ABUSEIPDB_API_KEY': TEST_KEY}).sync()

    def assert_cleaned(self, podman):
        self.assertEqual(podman.modes[-1], 'disable')
        self.assertEqual(podman.commands[-1][0][-3:], ['rm', '-f', sync.HELPER])

    def test_success_reuses_existing_event_and_disables_feed(self):
        podman = FakePodman()
        status = self.run_sync(podman)
        self.assertEqual(status['event_id'], 1)
        self.assertEqual(status['ip_dst_count'], 10000)
        self.assertFalse(status['enabled'])
        self.assertFalse(podman.enabled)
        self.assertEqual(podman.modes, ['inspect', 'enable', 'status', 'disable'])
        self.assert_cleaned(podman)

    def test_key_only_sent_on_stdin_for_read_only_inspection(self):
        podman = FakePodman()
        self.run_sync(podman)
        for command, options in podman.commands:
            self.assertNotIn(TEST_KEY, ' '.join(command))
            self.assertTrue(options['capture_output'])
            if TEST_KEY in (options.get('input') or ''):
                payload = json.loads(options['input'])
                self.assertEqual(payload['mode'], 'inspect')
                self.assertEqual(payload['api_key'], TEST_KEY)

    def test_fetch_exit_zero_without_success_marker_is_failure(self):
        for output in ('Job failed.', 'Job done.\nJob failed.', 'No marker'):
            with self.subTest(output=output):
                podman = FakePodman(fetch_output=output)
                with self.assertRaisesRegex(RuntimeError, 'Importazione'):
                    self.run_sync(podman)
                self.assert_cleaned(podman)

    def test_fetch_nonzero_does_not_expose_sensitive_diagnostics(self):
        podman = FakePodman(fetch_output=TEST_KEY, fetch_code=1)
        with self.assertRaises(RuntimeError) as caught:
            self.run_sync(podman)
        self.assertNotIn(TEST_KEY, str(caught.exception))
        self.assert_cleaned(podman)

    def test_fetch_timeout_still_disables_and_removes_helper(self):
        podman = FakePodman(fetch_timeout=True)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_sync(podman)
        self.assert_cleaned(podman)

    def test_rejects_changed_event_or_unsafe_status(self):
        invalid = [{'event_id': 2}, {'event_id': 0}, {'ip_dst_count': 0},
                   {'ip_dst_count': 10001}, {'attribute_count': 9999},
                   {'ip_dst_count': '10000'}, {'to_ids_count': 1},
                   {'published': True}, {'distribution': 1}]
        for status in invalid:
            with self.subTest(status=status):
                podman = FakePodman(invalid_status=status)
                with self.assertRaisesRegex(RuntimeError, 'verifica finale'):
                    self.run_sync(podman)
                self.assert_cleaned(podman)

    def test_lost_inspect_response_does_not_enable_unknown_feed(self):
        podman = FakePodman(lost_response='inspect')
        with self.assertRaisesRegex(RuntimeError, 'mancante'):
            self.run_sync(podman)
        self.assertEqual(podman.modes, ['inspect'])
        self.assertFalse(podman.enabled)
        self.assertEqual(podman.commands[-1][0][-3:], ['rm', '-f', sync.HELPER])

    def test_lost_enable_response_is_still_cleaned(self):
        podman = FakePodman(lost_response='enable')
        with self.assertRaisesRegex(RuntimeError, 'mancante'):
            self.run_sync(podman)
        self.assertFalse(podman.enabled)
        self.assert_cleaned(podman)

    def test_failed_disable_removes_helper_and_reports_failure(self):
        podman = FakePodman(failed_mode='disable')
        with self.assertRaises(RuntimeError):
            self.run_sync(podman)
        self.assert_cleaned(podman)

    def test_failed_install_does_not_remove_preexisting_helper(self):
        podman = FakePodman(install_fails=True)
        with self.assertRaises(RuntimeError):
            self.run_sync(podman)
        self.assertEqual(podman.modes, [])
        self.assertFalse(any(command[-3:] == ['rm', '-f', sync.HELPER]
                             for command, _ in podman.commands))

    def test_failed_preflight_does_not_fetch_or_enable(self):
        podman = FakePodman(failed_mode='inspect')
        with self.assertRaises(RuntimeError):
            self.run_sync(podman)
        self.assertEqual(podman.modes, ['inspect'])
        self.assertFalse(podman.enabled)


if __name__ == '__main__':
    unittest.main()
