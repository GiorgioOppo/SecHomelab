"""Offline contract tests: no Podman process or HTTP request is started."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse


MODULE_PATH = Path(__file__).resolve().parents[1] / 'greynoise_sync.py'
SPEC = importlib.util.spec_from_file_location('greynoise_sync', MODULE_PATH)
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)

TEST_KEY = 'offline-test-key'
IPS = ['8.8.8.8', '1.1.1.1']


def response_data():
    return {
        'request_metadata': {
            'query': sync.QUERY,
            'adjusted_query': sync.QUERY,
            'count': 2,
            'complete': True,
        },
        'data': [{'ip': ip, 'classification': 'malicious'} for ip in IPS],
    }


class FakeResponse(io.StringIO):
    def __init__(self, data, status=200):
        super().__init__(json.dumps(data))
        self.status = status


class DownloadTests(unittest.TestCase):
    def fetch(self, payload, status=200):
        with patch.object(sync.urllib.request, 'urlopen', return_value=FakeResponse(payload, status)) as network:
            result = sync.download(TEST_KEY)
        return result, network

    def test_request_keeps_key_in_header_and_bounds_query(self):
        (ips, metadata), network = self.fetch(response_data())
        request = network.call_args.args[0]
        url = urllib.parse.urlsplit(request.full_url)
        self.assertEqual(url.scheme, 'https')
        self.assertEqual(url.netloc, 'api.greynoise.io')
        self.assertEqual(url.path, '/v3/gnql/metadata')
        self.assertNotIn(TEST_KEY, request.full_url)
        self.assertEqual(request.get_header('Key'), TEST_KEY)
        self.assertEqual(urllib.parse.parse_qs(url.query), {
            'query': [sync.QUERY], 'size': ['10000'], 'quick': ['true'],
        })
        self.assertEqual(ips, IPS)
        self.assertEqual(metadata['downloaded'], 2)
        self.assertTrue(metadata['complete'])

    def test_allows_equivalent_normalized_query(self):
        payload = response_data()
        payload['request_metadata']['adjusted_query'] = '(last_seen:1d AND classification:malicious)'
        (ips, _), _ = self.fetch(payload)
        self.assertEqual(ips, IPS)

    def test_rejects_missing_or_removed_filters(self):
        for adjusted in (None, '', 'last_seen:1d', 'classification:malicious',
                         '(last_seen:1d OR classification:malicious)',
                         'last_seen:30d classification:malicious'):
            with self.subTest(adjusted=adjusted):
                payload = response_data()
                payload['request_metadata']['adjusted_query'] = adjusted
                with self.assertRaisesRegex(RuntimeError, 'filtri'):
                    self.fetch(payload)

    def test_rejects_different_original_query(self):
        payload = response_data()
        payload['request_metadata']['query'] = 'last_seen:30d classification:malicious'
        with self.assertRaisesRegex(RuntimeError, 'non corrisponde'):
            self.fetch(payload)

    def test_rejects_nonmalicious_or_missing_classifications(self):
        for classification in ('benign', 'suspicious', 'unknown', None, 'Malicious'):
            with self.subTest(classification=classification):
                payload = response_data()
                payload['data'][0]['classification'] = classification
                with self.assertRaisesRegex(RuntimeError, 'classificazione'):
                    self.fetch(payload)

    def test_supports_nested_classification_and_deduplicates(self):
        payload = response_data()
        payload['data'][0] = {
            'ip': IPS[0],
            'internet_scanner_intelligence': {'classification': 'malicious'},
        }
        payload['data'].append(copy.deepcopy(payload['data'][0]))
        (ips, metadata), _ = self.fetch(payload)
        self.assertEqual(ips, IPS)
        self.assertEqual(metadata['downloaded'], 2)

    def test_rejects_empty_or_invalid_list(self):
        for rows in ([], None, {}, '8.8.8.8'):
            with self.subTest(rows=rows):
                payload = response_data()
                payload['data'] = rows
                with self.assertRaisesRegex(RuntimeError, 'vuota o non valida'):
                    self.fetch(payload)

    def test_rejects_private_ip_and_oversized_response(self):
        payload = response_data()
        payload['data'][0]['ip'] = '192.168.1.1'
        with self.assertRaisesRegex(RuntimeError, 'indirizzo'):
            self.fetch(payload)
        payload = response_data()
        payload['data'] = [payload['data'][0]] * (sync.LIMIT + 1)
        with self.assertRaisesRegex(RuntimeError, 'limite'):
            self.fetch(payload)

    def test_partial_response_still_requires_all_filters(self):
        payload = response_data()
        payload['request_metadata'].update(count=50000, complete=False)
        (_, metadata), _ = self.fetch(payload, status=206)
        self.assertEqual(metadata['total_matches'], 50000)
        self.assertFalse(metadata['complete'])
        payload['request_metadata']['adjusted_query'] = 'last_seen:1d'
        with self.assertRaisesRegex(RuntimeError, 'filtri'):
            self.fetch(payload, status=206)

    def test_http_error_does_not_expose_key_or_response_body(self):
        error = urllib.error.HTTPError(
            'https://api.greynoise.io/v3/gnql/metadata', 403,
            TEST_KEY, {}, io.BytesIO(TEST_KEY.encode()),
        )
        with patch.object(sync.urllib.request, 'urlopen', side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                sync.download(TEST_KEY)
        self.assertIn('HTTP 403', str(caught.exception))
        self.assertNotIn(TEST_KEY, str(caught.exception))


class FakePodman:
    """Model subprocess outcomes while inspecting every outgoing command."""

    def __init__(self, *, fetch_output='Job done.', fetch_code=0,
                 invalid_status=None, disable_fails=False, install_fails=False,
                 lost_response=None):
        self.commands = []
        self.modes = []
        self.fetch_output = fetch_output
        self.fetch_code = fetch_code
        self.invalid_status = invalid_status or {}
        self.disable_fails = disable_fails
        self.install_fails = install_fails
        self.lost_response = lost_response
        self.feed_enabled = False
        self.status = {
            'ok': True, 'event_id': 2, 'ip_dst_count': len(IPS),
            'to_ids_count': 0, 'published': False, 'distribution': 0,
        }

    def __call__(self, command, **kwargs):
        self.commands.append((command, kwargs))
        self_outer = command[command.index('misp-core') + 1:]
        stdout, code = '', 0
        if self_outer[:2] == [sync.CAKE, 'GreyNoiseSetup']:
            payload = json.loads(kwargs['input'])
            mode = payload['mode']
            self.modes.append(mode)
            result = {'ok': True}
            if mode == 'configure':
                self.feed_enabled = False
                result.update(feed_id=4, user_id=1)
            elif mode == 'enable':
                self.feed_enabled = True
            elif mode == 'status':
                result = dict(self.status, **self.invalid_status)
                result['enabled'] = self.feed_enabled
            elif mode == 'disable' and self.disable_fails:
                result = {'ok': False, 'stage': 'disable'}
            elif mode == 'disable':
                self.feed_enabled = False
            stdout = 'CakePHP banner\nGREYNOISE_RESULT=' + json.dumps(result) + '\n'
            if mode == self.lost_response:
                stdout = ''
        elif self_outer[:3] == [sync.CAKE, 'Server', 'fetchFeed']:
            if not self.feed_enabled:
                raise AssertionError('The driver must enable the known feed before fetching.')
            stdout, code = self.fetch_output, self.fetch_code
        elif self_outer[:2] == ['sh', '-c'] and 'set -C;' in self_outer[2] and self.install_fails:
            code = 1
        return subprocess.CompletedProcess(command, code, stdout, '')


class SyncTests(unittest.TestCase):
    def run_sync(self, podman, **options):
        with patch.object(sync.subprocess, 'run', side_effect=podman), \
             patch.object(sync.Path, 'read_text', return_value='<?php /* offline fixture */'), \
             patch('sys.stdout', new_callable=io.StringIO):
            return sync.Misp({'GREYNOISE_API_KEY': TEST_KEY}).sync(IPS, **options)

    def assert_cleaned(self, podman):
        self.assertEqual(podman.modes[-1], 'disable')
        self.assertEqual(podman.commands[-1][0][-3:], ['rm', '-f', sync.HELPER])

    def test_success_verifies_then_disables_and_removes_helper(self):
        podman = FakePodman()
        status = self.run_sync(podman)
        self.assertEqual(status['event_id'], 2)
        self.assertIs(status['enabled'], False)
        self.assertFalse(podman.feed_enabled)
        self.assertEqual(podman.modes, ['settings', 'configure', 'enable', 'status', 'disable'])
        self.assert_cleaned(podman)
        for command, kwargs in podman.commands:
            self.assertNotIn(TEST_KEY, ' '.join(command))
            self.assertTrue(kwargs['capture_output'])
        snapshot = next((command, kwargs) for command, kwargs in podman.commands
                        if command[-1] == sync.FEED_PATH)
        self.assertEqual(snapshot[1]['input'], '\n'.join(IPS) + '\n')
        script = snapshot[0][snapshot[0].index('-c') + 1]
        self.assertIn('mv -f "$1" "$2"', script)
        self.assertIn('trap', script)

    def test_fetch_failure_disables_feed_and_removes_helper(self):
        for output, code in (('Job failed.', 0), ('No completion marker', 0),
                             ('Job done.\nJob failed.', 0), ('', 1)):
            with self.subTest(output=output, code=code):
                podman = FakePodman(fetch_output=output, fetch_code=code)
                with self.assertRaises(RuntimeError):
                    self.run_sync(podman)
                self.assertNotIn('status', podman.modes)
                self.assert_cleaned(podman)

    def test_unsafe_or_incomplete_event_is_rejected_and_cleaned(self):
        for bad_status in ({'event_id': 0}, {'ip_dst_count': 1},
                           {'to_ids_count': 1}, {'published': True},
                           {'distribution': 1}):
            with self.subTest(status=bad_status):
                podman = FakePodman(invalid_status=bad_status)
                with self.assertRaisesRegex(RuntimeError, 'verifica finale'):
                    self.run_sync(podman)
                self.assert_cleaned(podman)

    def test_disable_failure_still_removes_helper_and_reports_failure(self):
        podman = FakePodman(disable_fails=True)
        with self.assertRaisesRegex(RuntimeError, 'disable'):
            self.run_sync(podman)
        self.assert_cleaned(podman)

    def test_lost_configure_response_never_enables_unknown_feed(self):
        podman = FakePodman(lost_response='configure')
        with self.assertRaisesRegex(RuntimeError, 'mancante'):
            self.run_sync(podman)
        self.assertEqual(podman.modes, ['settings', 'configure'])
        self.assertFalse(podman.feed_enabled)
        self.assertFalse(any('fetchFeed' in command for command, _ in podman.commands))
        self.assertEqual(podman.commands[-1][0][-3:], ['rm', '-f', sync.HELPER])

    def test_lost_enable_response_disables_known_feed(self):
        podman = FakePodman(lost_response='enable')
        with self.assertRaisesRegex(RuntimeError, 'mancante'):
            self.run_sync(podman)
        self.assertEqual(podman.modes, ['settings', 'configure', 'enable', 'disable'])
        self.assertFalse(podman.feed_enabled)
        self.assertFalse(any('fetchFeed' in command for command, _ in podman.commands))
        self.assert_cleaned(podman)
        payloads = [json.loads(kwargs['input']) for command, kwargs in podman.commands
                    if command[-2:] == [sync.CAKE, 'GreyNoiseSetup']]
        for payload in payloads:
            if payload['mode'] in ('enable', 'disable'):
                self.assertEqual(payload['feed_id'], 4)

    def test_enrichment_enabled_flag_is_preserved_unless_explicit(self):
        for options, expected in (({}, None), ({'enable_enrichment': True}, True),
                                  ({'enable_enrichment': False}, False)):
            with self.subTest(options=options):
                podman = FakePodman()
                self.run_sync(podman, **options)
                payloads = [json.loads(kwargs['input']) for command, kwargs in podman.commands
                            if command[-2:] == [sync.CAKE, 'GreyNoiseSetup']]
                settings = next(payload for payload in payloads if payload['mode'] == 'settings')
                if expected is None:
                    self.assertNotIn('enabled', settings)
                else:
                    self.assertIs(settings['enabled'], expected)

    def test_interrupt_during_fetch_disables_and_removes_helper(self):
        podman = FakePodman()

        def interrupt_fetch(command, **kwargs):
            if 'fetchFeed' in command:
                raise KeyboardInterrupt()
            return podman(command, **kwargs)

        with patch.object(sync.subprocess, 'run', side_effect=interrupt_fetch), \
             patch.object(sync.Path, 'read_text', return_value='<?php /* offline fixture */'), \
             patch('sys.stdout', new_callable=io.StringIO):
            with self.assertRaises(KeyboardInterrupt):
                sync.Misp({'GREYNOISE_API_KEY': TEST_KEY}).sync(IPS)
        self.assert_cleaned(podman)

    def test_failed_subprocess_reports_safe_stage_without_raw_output(self):
        output = TEST_KEY + '\nGREYNOISE_RESULT=' + json.dumps({
            'ok': False, 'stage': 'settings_preflight',
        }) + '\n'
        result = subprocess.CompletedProcess(['podman'], 1, output, TEST_KEY)
        with patch.object(sync.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'settings_preflight') as caught:
                sync.Misp({'GREYNOISE_API_KEY': TEST_KEY}).helper('settings', api_key=TEST_KEY)
        self.assertNotIn(TEST_KEY, str(caught.exception))

    def test_failed_exclusive_install_does_not_remove_an_existing_helper(self):
        podman = FakePodman(install_fails=True)
        with self.assertRaises(RuntimeError):
            self.run_sync(podman)
        self.assertEqual(len(podman.commands), 1)
        self.assertEqual(podman.modes, [])

    def test_failed_download_never_starts_misp_mutation(self):
        with patch.object(sync, 'read_env', return_value={'GREYNOISE_API_KEY': TEST_KEY}), \
             patch.object(sync, 'download', side_effect=RuntimeError('Rejected response')), \
             patch.object(sync.subprocess, 'run') as subprocess_mock:
            with self.assertRaisesRegex(RuntimeError, 'Rejected response'):
                sync.main()
        subprocess_mock.assert_not_called()


if __name__ == '__main__':
    unittest.main()
