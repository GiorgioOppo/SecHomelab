"""Offline contract tests for the verified MISP-to-Splunk lookup refresh."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
import urllib.error


MODULE_PATH = Path(__file__).resolve().parents[1] / 'splunk_sync.py'
SPEC = importlib.util.spec_from_file_location('splunk_sync', MODULE_PATH)
sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sync
SPEC.loader.exec_module(sync)

UUID_A = 'e8e075da-4202-4fb8-ab34-008efcab581d'
UUID_B = 'd08ac06d-064a-4fde-97d6-a5d2810d948a'
UUID_C = 'dd12b20b-1c35-4d5e-834e-a90d1fe69782'
TEST_SECRET = 'offline-secret-must-never-appear'


def misp_rows():
    return [
        {'uuid': UUID_A, 'value': '8.8.8.8', 'type': 'ip-dst'},
        {'uuid': UUID_B, 'value': '2001:4860:4860:0:0:0:0:8888', 'type': 'ip-src'},
    ]


def splunk_rows():
    return [
        {'misp_attribute_uuid': row['uuid'], 'misp_value': row['value'],
         'misp_type': row['type']}
        for row in misp_rows()
    ]


class SnapshotValidationTests(unittest.TestCase):
    def test_both_sources_preserve_identity_and_canonicalize_ipv6(self):
        expected = {UUID_A: '8.8.8.8', UUID_B: '2001:4860:4860::8888'}
        self.assertEqual(sync.validate_snapshot(misp_rows(), 'MISP'), expected)
        self.assertEqual(sync.validate_snapshot(splunk_rows(), 'Splunk'), expected)

    def test_rejects_duplicate_uuid_even_with_identical_value(self):
        for source, rows in (('MISP', misp_rows()), ('Splunk', splunk_rows())):
            with self.subTest(source=source):
                rows.append(copy.deepcopy(rows[0]))
                with self.assertRaises(RuntimeError):
                    sync.validate_snapshot(rows, source)

    def test_same_ip_from_distinct_attributes_is_valid(self):
        rows = misp_rows()
        rows[1]['value'] = rows[0]['value']
        self.assertEqual(sync.validate_snapshot(rows, 'MISP'), {
            UUID_A: '8.8.8.8', UUID_B: '8.8.8.8',
        })

    def test_rejects_missing_identity_invalid_ip_and_wrong_attribute_type(self):
        for change in ({'uuid': ''}, {'uuid': None}, {'value': 'invalid-ip'},
                       {'value': '8.8.8.8|443'}, {'type': 'domain'}):
            with self.subTest(change=change):
                rows = misp_rows()
                rows[0].update(change)
                with self.assertRaises(RuntimeError):
                    sync.validate_snapshot(rows, 'MISP')


class ApiErrorTests(unittest.TestCase):
    def test_http_error_redacts_secret_in_reason_and_body(self):
        api = sync.ApiClient(
            'https://offline.invalid', {'Authorization': TEST_SECRET},
            None, 'Offline service',
        )
        error = urllib.error.HTTPError(
            'https://offline.invalid/test', 403, TEST_SECRET, {},
            io.BytesIO(TEST_SECRET.encode()),
        )
        with patch.object(api.opener, 'open', side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                api.request('/test')
        self.assertIn('403', str(caught.exception))
        self.assertNotIn(TEST_SECRET, str(caught.exception))


class PaginationTests(unittest.TestCase):
    def test_misp_keeps_reading_after_short_pages(self):
        misp = object.__new__(sync.MispClient)
        rows = misp_rows()
        misp.request = Mock(side_effect=[
            {'response': {'Attribute': [rows[0]]}},
            {'response': {'Attribute': [rows[1]]}},
            {'response': {'Attribute': []}},
        ])
        with patch.object(sync, 'PAGE_SIZE', 2):
            actual = misp.snapshot()
        self.assertEqual(actual, sync.validate_snapshot(rows, 'MISP'))
        self.assertEqual([
            call.kwargs['json_body']['page'] for call in misp.request.call_args_list
        ], [1, 2, 3])
        for call in misp.request.call_args_list:
            payload = call.kwargs['json_body']
            self.assertIs(payload['deleted'], False)
            self.assertNotIn('to_ids', payload)
            self.assertNotIn('published', payload)

    def test_misp_rejects_duplicate_uuid_across_pages(self):
        misp = object.__new__(sync.MispClient)
        misp.request = Mock(side_effect=[
            {'response': {'Attribute': [misp_rows()[0]]}},
            {'response': {'Attribute': [misp_rows()[0]]}},
        ])
        with self.assertRaises(sync.SyncError):
            misp.snapshot()

    def test_misp_does_not_return_partial_snapshot_after_failed_page(self):
        for bad_page in ({}, {'response': {}}, {'response': {'Attribute': None}},
                         sync.SyncError('Offline page failed')):
            with self.subTest(bad_page=bad_page):
                misp = object.__new__(sync.MispClient)
                misp.request = Mock(side_effect=[
                    {'response': {'Attribute': [misp_rows()[0]]}}, bad_page,
                ])
                with self.assertRaises(sync.SyncError):
                    misp.snapshot()

    def test_empty_misp_snapshot_is_rejected(self):
        misp = object.__new__(sync.MispClient)
        misp.request = Mock(return_value={'response': {'Attribute': []}})
        with self.assertRaises(sync.SyncError):
            misp.snapshot()

    def test_splunk_paginates_by_actual_row_count(self):
        splunk = object.__new__(sync.SplunkClient)
        rows = splunk_rows()
        splunk.request = Mock(side_effect=[
            {'results': [rows[0]]}, {'results': [rows[1]]}, {'results': []},
        ])
        with patch.object(sync, 'PAGE_SIZE', 2):
            actual = splunk.results('offline.1')
        self.assertEqual(actual, rows)
        self.assertEqual([
            call.kwargs['params']['offset'] for call in splunk.request.call_args_list
        ], [0, 1, 2])

    def test_splunk_rejects_failed_or_preview_page_after_valid_page(self):
        for bad_page in ({}, {'results': None}, {'results': [], 'preview': True},
                         {'results': [], 'messages': [{'type': 'ERROR', 'text': TEST_SECRET}]},
                         sync.SyncError('Offline page failed')):
            with self.subTest(bad_page=bad_page):
                splunk = object.__new__(sync.SplunkClient)
                splunk.request = Mock(side_effect=[
                    {'results': [splunk_rows()[0]]}, bad_page,
                ])
                with self.assertRaises(sync.SyncError) as caught:
                    splunk.results('offline.1')
                self.assertNotIn(TEST_SECRET, str(caught.exception))


class JobTests(unittest.TestCase):
    def client(self, content):
        splunk = object.__new__(sync.SplunkClient)
        splunk.request = Mock(return_value={'entry': [{'content': content}]})
        return splunk

    def test_timeout_on_job_that_never_finishes(self):
        splunk = self.client({'isDone': False, 'dispatchState': 'RUNNING'})
        with patch.object(sync.time, 'monotonic', side_effect=[0, 1, 2, 4]), \
             patch.object(sync.time, 'sleep') as sleep:
            with self.assertRaisesRegex(sync.SyncError, 'timeout'):
                splunk.wait_job('offline.1', timeout=3, poll_interval=2)
        self.assertEqual(splunk.request.call_count, 1)
        sleep.assert_called_once_with(1)

    def test_failed_cancelled_or_incomplete_terminal_state_is_rejected(self):
        for content in (
            {'isDone': True, 'dispatchState': 'FAILED'},
            {'isDone': False, 'isFailed': True, 'dispatchState': 'RUNNING'},
            {'isDone': True, 'dispatchState': 'INTERNAL_CANCEL'},
            {'isDone': True, 'dispatchState': 'FINALIZING'},
        ):
            with self.subTest(content=content):
                with self.assertRaises(sync.SyncError):
                    self.client(content).wait_job('offline.1')

    def test_done_job_returns_verified_content(self):
        content = {'isDone': '1', 'isFailed': '0', 'dispatchState': 'DONE'}
        self.assertEqual(self.client(content).wait_job('offline.1'), content)

    def test_cancel_uses_native_control_action_and_validates_sid(self):
        splunk = self.client({})
        splunk.request.return_value = {'messages': []}
        splunk.cancel_job('offline.1')
        splunk.request.assert_called_once_with(
            sync.SEARCH_NAMESPACE + '/search/jobs/offline.1/control',
            data={'action': 'cancel', 'output_mode': 'json'},
        )
        splunk.request.reset_mock()
        with self.assertRaises(sync.SyncError):
            splunk.cancel_job('../other-job')
        splunk.request.assert_not_called()

    def test_dispatch_error_with_sid_cancels_job_before_raising_sanitized_error(self):
        splunk = self.client({})
        splunk.request.side_effect = [
            {'sid': 'offline.1', 'messages': [{'type': 'ERROR', 'text': TEST_SECRET}]},
            {'messages': []},
        ]
        with self.assertRaises(sync.SyncError) as caught:
            splunk.start_search('| makeresults')
        self.assertNotIn(TEST_SECRET, str(caught.exception))
        self.assertEqual(splunk.request.call_count, 2)
        self.assertEqual(splunk.request.call_args.args,
                         (sync.SEARCH_NAMESPACE + '/search/jobs/offline.1/control',))


class FakeSplunk:
    def __init__(self, rows, written=None, failure=None):
        self.rows = rows
        self.written = written if written is not None else [{'ip': '8.8.8.8'}, {'ip': '1.1.1.1'}]
        self.failure = failure
        self.searches = []
        self.events = []

    def start_search(self, search):
        self.searches.append(search)
        sid = 'offline.' + str(len(self.searches))
        self.events.append(('start', sid))
        return sid

    def wait_job(self, sid):
        self.events.append(('wait', sid))
        if self.failure is not None:
            raise self.failure
        return {'isDone': True, 'dispatchState': 'DONE'}

    def results(self, sid):
        self.events.append(('results', sid))
        return self.rows if sid == 'offline.1' else self.written

    def cancel_job(self, sid):
        self.events.append(('cancel', sid))


class RefreshTests(unittest.TestCase):
    def clients(self, rows=None, **kwargs):
        expected = {UUID_A: '8.8.8.8', UUID_B: '1.1.1.1', UUID_C: '8.8.8.8'}
        misp = Mock()
        misp.snapshot.return_value = expected
        if rows is None:
            rows = [
                {'misp_attribute_uuid': identifier, 'misp_value': value, 'misp_type': 'ip-dst'}
                for identifier, value in expected.items()
            ]
        return misp, FakeSplunk(rows, **kwargs)

    def assert_no_write(self, splunk):
        self.assertLessEqual(len(splunk.searches), 1)
        self.assertFalse(any('outputlookup' in search for search in splunk.searches))

    def test_success_writes_only_verified_job_and_preserves_shared_ip_sources(self):
        misp, splunk = self.clients()
        self.assertEqual(sync.refresh(misp, splunk), {'attributes': 3, 'unique_ips': 2})
        misp.snapshot.assert_called_once_with()
        self.assertEqual(splunk.events, [
            ('start', 'offline.1'), ('wait', 'offline.1'), ('results', 'offline.1'),
            ('start', 'offline.2'), ('wait', 'offline.2'), ('results', 'offline.2'),
            ('cancel', 'offline.2'), ('cancel', 'offline.1'),
        ])
        self.assertNotIn('outputlookup', splunk.searches[0])
        self.assertIn('expand_object=true', splunk.searches[0])
        self.assertIn('loadjob "offline.1"', splunk.searches[1])
        self.assertNotIn('mispgetioc', splunk.searches[1])
        self.assertIn('outputlookup', splunk.searches[1])
        self.assertIn('append=false', splunk.searches[1])
        self.assertIn('override_if_empty=false', splunk.searches[1])
        self.assertIn('createinapp=true', splunk.searches[1])
        self.assertIn('output_format=splunk_mv_csv', splunk.searches[1])
        self.assertIn('values(misp_attribute_uuid)', splunk.searches[1])

    def test_same_count_with_different_uuid_or_ip_cannot_overwrite_lookup(self):
        for mutation in ('uuid', 'ip'):
            with self.subTest(mutation=mutation):
                misp, splunk = self.clients()
                if mutation == 'uuid':
                    splunk.rows[0]['misp_attribute_uuid'] = '921f0b91-36f7-49d5-a8e6-dc2e6c696e8d'
                else:
                    splunk.rows[0]['misp_value'] = '9.9.9.9'
                with self.assertRaises(sync.SyncError):
                    sync.refresh(misp, splunk)
                self.assert_no_write(splunk)

    def test_noncanonical_ipv6_cannot_overwrite_lookup_even_when_snapshot_matches(self):
        misp, splunk = self.clients()
        misp.snapshot.return_value[UUID_A] = '2001:4860:4860::8888'
        splunk.rows[0]['misp_value'] = '2001:4860:4860:0:0:0:0:8888'
        self.assertEqual(sync.validate_snapshot(splunk.rows, 'Splunk'), misp.snapshot.return_value)
        with self.assertRaisesRegex(sync.SyncError, 'IP non canonico'):
            sync.refresh(misp, splunk)
        self.assert_no_write(splunk)
        self.assertEqual(splunk.events, [
            ('start', 'offline.1'), ('wait', 'offline.1'), ('results', 'offline.1'),
            ('cancel', 'offline.1'),
        ])

    def test_empty_partial_duplicate_and_invalid_results_cannot_overwrite_lookup(self):
        for mutation in ('empty', 'partial', 'duplicate', 'invalid'):
            with self.subTest(mutation=mutation):
                misp, splunk = self.clients()
                if mutation == 'empty':
                    splunk.rows.clear()
                elif mutation == 'partial':
                    splunk.rows.pop()
                elif mutation == 'duplicate':
                    splunk.rows[-1] = dict(splunk.rows[0])
                else:
                    splunk.rows[0]['misp_value'] = 'invalid-ip'
                with self.assertRaises(sync.SyncError):
                    sync.refresh(misp, splunk)
                self.assert_no_write(splunk)

    def test_empty_or_failed_misp_snapshot_does_not_start_splunk(self):
        for failure in (None, sync.SyncError('Offline MISP failed')):
            with self.subTest(failure=failure):
                misp, splunk = self.clients()
                misp.snapshot.return_value = {}
                misp.snapshot.side_effect = failure
                with self.assertRaises(sync.SyncError):
                    sync.refresh(misp, splunk)
                self.assertEqual(splunk.searches, [])

    def test_first_job_timeout_cannot_overwrite_lookup(self):
        misp, splunk = self.clients(failure=sync.SyncError('Offline timeout'))
        with self.assertRaises(sync.SyncError):
            sync.refresh(misp, splunk)
        self.assert_no_write(splunk)
        self.assertEqual(splunk.events, [
            ('start', 'offline.1'), ('wait', 'offline.1'), ('cancel', 'offline.1'),
        ])

    def test_write_timeout_cancels_writer_before_its_source_job(self):
        misp, splunk = self.clients()
        failure = sync.SyncError('Offline write timeout')
        with patch.object(splunk, 'wait_job', side_effect=[None, failure]):
            with self.assertRaises(sync.SyncError) as caught:
                sync.refresh(misp, splunk)
        self.assertIs(caught.exception, failure)
        self.assertEqual(splunk.events[-2:], [
            ('cancel', 'offline.2'), ('cancel', 'offline.1'),
        ])

    def test_result_fetch_failure_cleans_up_every_known_job(self):
        for writer in (False, True):
            with self.subTest(writer=writer):
                misp, splunk = self.clients()
                failure = sync.SyncError('Offline results failed')
                responses = [splunk.rows, failure] if writer else [failure]
                with patch.object(splunk, 'results', side_effect=responses):
                    with self.assertRaises(sync.SyncError) as caught:
                        sync.refresh(misp, splunk)
                self.assertIs(caught.exception, failure)
                self.assertEqual([event for event in splunk.events if event[0] == 'cancel'],
                                 [('cancel', 'offline.2'), ('cancel', 'offline.1')]
                                 if writer else [('cancel', 'offline.1')])

    def test_failed_cleanup_preserves_refresh_error_redacts_diagnostics_and_continues(self):
        misp, splunk = self.clients()
        failure = sync.SyncError('Offline write timeout')
        stderr = io.StringIO()
        with patch.object(splunk, 'wait_job', side_effect=[None, failure]), \
             patch.object(splunk, 'cancel_job', side_effect=[RuntimeError(TEST_SECRET), None]) as cancel, \
             patch.object(sync.sys, 'stderr', stderr):
            with self.assertRaises(sync.SyncError) as caught:
                sync.refresh(misp, splunk)
        self.assertIs(caught.exception, failure)
        self.assertEqual([call.args for call in cancel.call_args_list],
                         [('offline.2',), ('offline.1',)])
        self.assertIn('non confermata', stderr.getvalue())
        self.assertNotIn(TEST_SECRET, stderr.getvalue())

    def test_interrupted_refresh_still_cancels_search(self):
        misp, splunk = self.clients(failure=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            sync.refresh(misp, splunk)
        self.assertEqual(splunk.events[-1], ('cancel', 'offline.1'))

    def test_cleanup_failure_does_not_replace_successful_verification(self):
        misp, splunk = self.clients()
        stderr = io.StringIO()
        with patch.object(splunk, 'cancel_job', side_effect=RuntimeError(TEST_SECRET)) as cancel, \
             patch.object(sync.sys, 'stderr', stderr):
            self.assertEqual(sync.refresh(misp, splunk), {'attributes': 3, 'unique_ips': 2})
        self.assertEqual(cancel.call_count, 2)
        self.assertNotIn(TEST_SECRET, stderr.getvalue())

    def test_wrong_lookup_output_is_reported_as_failure(self):
        for written in ([], [{'ip': '8.8.8.8'}],
                        [{'ip': '8.8.8.8'}, {'ip': '9.9.9.9'}],
                        [{'ip': '8.8.8.8'}, {'ip': '8.8.8.8'}]):
            with self.subTest(written=written):
                misp, splunk = self.clients(written=written)
                with self.assertRaises(sync.SyncError):
                    sync.refresh(misp, splunk)


if __name__ == '__main__':
    unittest.main()
