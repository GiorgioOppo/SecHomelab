#!/usr/bin/env python3
"""Refresh the local Splunk IP lookup only after comparing it with MISP.

No feed is refreshed and no MISP event is modified. Called by intel_sync.py
or manually for diagnostics. Credentials come from .env and only use headers.
"""

import base64
import ipaddress
import json
from pathlib import Path
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parent
APP = 'misp42splunk'
INSTANCE = 'local_misp'
LOOKUP = 'misp_ip_intel.csv'
PAGE_SIZE = 1000
MAX_ATTRIBUTES = 1000000
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
SEARCH_NAMESPACE = '/servicesNS/admin/' + APP
MISP_FILTER = {
    'returnFormat': 'json',
    'type': ['ip-src', 'ip-dst'],
    'deleted': False,
    'includeContext': True,
    'enforceWarninglist': False,
}
# No published/to_ids/publication-time filter: the local feeds are unpublished
# and deliberately retain to_ids=false.
_query = json.dumps(MISP_FILTER, separators=(',', ':')).replace('"', '\\"')
LIVE_SEARCH = (
    f'| mispgetioc misp_instance={INSTANCE} json_request="{_query}" '
    f'limit={PAGE_SIZE} page=0 include_sightings=false expand_object=true'
)


class SyncError(RuntimeError):
    """A sanitized error suitable for displaying without exposing credentials."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        # Authorization headers must never follow a redirect to another origin.
        raise SyncError('Redirect HTTP inatteso; aggiornamento interrotto.')


def read_env(path=None):
    values = {}
    for line in (path or ROOT / '.env').read_text().splitlines():
        name, separator, value = line.partition('=')
        if separator and not line.lstrip().startswith('#'):
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[name.strip()] = value
    for name in ('SPLUNK_PASSWORD', 'MISP_SPLUNK_API_KEY'):
        if not values.get(name):
            raise SyncError(f'Impostare {name} nel file .env.')
    return values


class ApiClient:
    def __init__(self, base_url, headers, context, service):
        self.base_url = base_url.rstrip('/')
        self.headers = dict(headers, Accept='application/json')
        self.service = service
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            NoRedirect(),
        )

    def request(self, path, data=None, json_body=None, params=None):
        if not path.startswith('/') or path.startswith('//'):
            raise SyncError('Percorso API non valido.')
        url = self.base_url + path
        if params:
            url += '?' + urllib.parse.urlencode(params)
        headers = dict(self.headers)
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if json_body is not None:
            if body is not None:
                raise SyncError('Formato richiesta API ambiguo.')
            body = json.dumps(json_body).encode()
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(url, data=body, headers=headers)
        try:
            with self.opener.open(request, timeout=90) as response:
                if response.status not in (200, 201):
                    raise SyncError(f'{self.service}: risposta HTTP inattesa.')
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise SyncError(f'{self.service}: risposta troppo grande.')
            result = json.loads(raw)
        except urllib.error.HTTPError as error:
            raise SyncError(f'{self.service}: HTTP {error.code}; operazione interrotta.') from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise SyncError(f'{self.service}: connessione o verifica TLS non riuscita.') from None
        except (ValueError, UnicodeError):
            raise SyncError(f'{self.service}: risposta JSON non valida.') from None
        if not isinstance(result, dict):
            raise SyncError(f'{self.service}: struttura della risposta non valida.')
        return result


def validate_snapshot(rows, source):
    """Return canonical UUID -> IP, rejecting duplicates and unexpected rows."""
    if not isinstance(rows, list) or source not in ('MISP', 'Splunk'):
        raise SyncError('Snapshot non valido.')
    prefix = 'misp_' if source == 'Splunk' else ''
    uuid_field = 'misp_attribute_uuid' if source == 'Splunk' else 'uuid'
    result = {}
    for row in rows:
        if not isinstance(row, dict) or row.get(prefix + 'type') not in ('ip-src', 'ip-dst'):
            raise SyncError(f'{source}: attributo IP non valido.')
        try:
            identifier = row[uuid_field]
            value = row[prefix + 'value']
            if not isinstance(identifier, str) or not isinstance(value, str):
                raise ValueError
            identifier = str(uuid.UUID(identifier))
            address = str(ipaddress.ip_address(value))
        except (KeyError, ValueError, TypeError, AttributeError):
            raise SyncError(f'{source}: UUID o indirizzo IP non valido.') from None
        if identifier in result:
            raise SyncError(f'{source}: UUID duplicato; snapshot rifiutato.')
        result[identifier] = address
    return result


class MispClient(ApiClient):
    def __init__(self, key, ca_file=None):
        context = ssl.create_default_context(cafile=str(ca_file or ROOT / 'ssl' / 'cert.pem'))
        super().__init__('https://localhost:8443', {'Authorization': key}, context, 'MISP')

    def snapshot(self):
        snapshot = {}
        page = 1
        while True:
            payload = dict(MISP_FILTER, limit=PAGE_SIZE, page=page)
            response = self.request('/attributes/restSearch', json_body=payload)
            data = response.get('response')
            if not isinstance(data, dict) or not isinstance(data.get('Attribute'), list):
                raise SyncError('MISP: risposta attributi incompleta.')
            rows = data['Attribute']
            if not rows:
                break
            if len(rows) > PAGE_SIZE:
                raise SyncError('MISP: paginazione inattesa.')
            batch = validate_snapshot(rows, 'MISP')
            if snapshot.keys() & batch.keys():
                raise SyncError('MISP: UUID duplicato tra pagine; snapshot rifiutato.')
            snapshot.update(batch)
            if len(snapshot) > MAX_ATTRIBUTES:
                raise SyncError('MISP: limite di sicurezza degli attributi superato.')
            page += 1
        if not snapshot:
            raise SyncError('MISP: snapshot vuoto; lookup precedente conservato.')
        return snapshot


def checked_sid(sid):
    if not isinstance(sid, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}', sid):
        raise SyncError('Splunk: identificatore del job non valido.')
    return sid


def check_messages(response):
    messages = response.get('messages', [])
    if not isinstance(messages, list):
        raise SyncError('Splunk: messaggi della risposta non validi.')
    for message in messages:
        if isinstance(message, dict) and str(message.get('type', '')).upper() in ('ERROR', 'FATAL'):
            # Server diagnostics can contain input data: never print them.
            raise SyncError('Splunk: la ricerca ha segnalato un errore; operazione interrotta.')


def is_true(value):
    return value is True or str(value).lower() in ('1', 'true')


class SplunkClient(ApiClient):
    def __init__(self, password):
        # Splunk ships its own self-signed management certificate. This relaxed
        # context is confined to its loopback endpoint, never to MISP or feeds.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        auth = base64.b64encode(('admin:' + password).encode()).decode()
        super().__init__('https://127.0.0.1:8089', {'Authorization': 'Basic ' + auth}, context, 'Splunk')

    def start_search(self, search):
        response = self.request(SEARCH_NAMESPACE + '/search/jobs', data={
            'search': search, 'exec_mode': 'normal', 'earliest_time': '0',
            'latest_time': 'now', 'output_mode': 'json',
        })
        sid = checked_sid(response.get('sid'))
        try:
            check_messages(response)
        except (Exception, KeyboardInterrupt):
            # A failed dispatch can still return a job ID. The caller cannot
            # clean up that job because start_search has not returned it yet.
            cancel_jobs(self, [sid])
            raise
        return sid

    def cancel_job(self, sid):
        response = self.request(
            SEARCH_NAMESPACE + '/search/jobs/' + checked_sid(sid) + '/control',
            data={'action': 'cancel', 'output_mode': 'json'},
        )
        check_messages(response)

    def wait_job(self, sid, timeout=600, poll_interval=2):
        path = SEARCH_NAMESPACE + '/search/jobs/' + checked_sid(sid)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            response = self.request(path, params={'output_mode': 'json'})
            check_messages(response)
            entries = response.get('entry')
            if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
                raise SyncError('Splunk: stato del job non valido.')
            content = entries[0].get('content')
            if not isinstance(content, dict):
                raise SyncError('Splunk: stato del job incompleto.')
            state = content.get('dispatchState')
            if is_true(content.get('isFailed')) or state in ('FAILED', 'BAD_INPUT_CANCELLED', 'INTERNAL_CANCEL'):
                raise SyncError('Splunk: ricerca non riuscita; operazione interrotta.')
            if is_true(content.get('isDone')):
                if state != 'DONE':
                    raise SyncError('Splunk: ricerca terminata senza risultato completo.')
                return content
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(poll_interval, remaining))
        raise SyncError('Splunk: timeout della ricerca; aggiornamento interrotto.')

    def results(self, sid):
        path = SEARCH_NAMESPACE + '/search/jobs/' + checked_sid(sid) + '/results'
        rows = []
        while True:
            response = self.request(path, params={
                'output_mode': 'json', 'count': PAGE_SIZE, 'offset': len(rows),
            })
            check_messages(response)
            batch = response.get('results')
            if is_true(response.get('preview')) or not isinstance(batch, list):
                raise SyncError('Splunk: risultati incompleti o provvisori.')
            if len(batch) > PAGE_SIZE:
                raise SyncError('Splunk: paginazione inattesa.')
            if not batch:
                return rows
            rows.extend(batch)
            if len(rows) > MAX_ATTRIBUTES:
                raise SyncError('Splunk: limite di sicurezza dei risultati superato.')


def lookup_search(sid):
    return (
        f'| loadjob "{checked_sid(sid)}" '
        '| eval ip=misp_value '
        '| stats values(misp_event_info) as misp_sources '
        'values(misp_event_id) as misp_event_ids '
        'values(misp_attribute_uuid) as misp_attribute_uuids '
        'values(misp_to_ids) as misp_to_ids '
        'max(misp_timestamp) as misp_last_updated '
        'count as misp_attribute_count by ip '
        '| outputlookup append=false override_if_empty=false createinapp=true '
        f'output_format=splunk_mv_csv {LOOKUP}'
    )


def cancel_jobs(splunk, sids):
    """Best-effort stop/cache cleanup without hiding the original failure.

    Cancel the writer before the verified source job it consumes. A timeout is
    not proof that a remote writer stopped, and cancellation cannot undo a
    lookup already written. A lost dispatch response can also leave an unknown
    SID; callers must not treat this cleanup as a transactional rollback.
    """
    for sid in reversed(sids):
        try:
            splunk.cancel_job(sid)
        except (Exception, KeyboardInterrupt):
            # Never surface remote diagnostics or replace the refresh error.
            print('Avviso: pulizia di un job Splunk non confermata; '
                  'verificare eventuali ricerche ancora attive.', file=sys.stderr)


def refresh(misp, splunk):
    expected = misp.snapshot()
    if not expected:
        raise SyncError('MISP: snapshot vuoto; lookup precedente conservato.')
    jobs = []
    try:
        sid = splunk.start_search(LIVE_SEARCH)
        jobs.append(sid)
        splunk.wait_job(sid)
        rows = splunk.results(sid)
        actual = validate_snapshot(rows, 'Splunk')
        if not actual or actual != expected:
            raise SyncError('MISP e Splunk restituiscono snapshot diversi o parziali; lookup precedente conservato.')
        if any(str(ipaddress.ip_address(row['misp_value'])) != row['misp_value'] for row in rows):
            # The SPL aggregation uses the original value as its lookup key. Reject
            # alternate IPv6 spellings before writing rather than splitting one IP
            # across several lookup rows or failing only after the write.
            raise SyncError('Splunk: indirizzo IP non canonico; normalizzare in MISP prima di aggiornare il lookup.')
        # Freeze the verified job's results. A second live API query here could race
        # a feed update or silently return fewer pages than the validated query.
        write_sid = splunk.start_search(lookup_search(sid))
        jobs.append(write_sid)
        splunk.wait_job(write_sid)
        written = splunk.results(write_sid)
        expected_ips = set(expected.values())
        if (len(written) != len(expected_ips)
                or any(not isinstance(row, dict) for row in written)
                or {row.get('ip') for row in written} != expected_ips):
            raise SyncError('Splunk: verifica finale del lookup non riuscita; controllare il risultato prima dell’uso.')
        return {'attributes': len(actual), 'unique_ips': len(expected_ips)}
    finally:
        cancel_jobs(splunk, jobs)


def main():
    values = read_env()
    report = refresh(MispClient(values['MISP_SPLUNK_API_KEY']), SplunkClient(values['SPLUNK_PASSWORD']))
    print(f"Lookup {LOOKUP} aggiornato: {report['attributes']} attributi verificati, "
          f"{report['unique_ips']} IP univoci.")


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        if isinstance(error, SyncError):
            print('Errore: ' + str(error), file=sys.stderr)
        else:
            print('Operazione interrotta: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
