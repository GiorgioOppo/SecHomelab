#!/usr/bin/env python3
"""Configure the local, read-only MISP42 integration without logging secrets."""
import base64
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from splunk_sync import LIVE_SEARCH, NoRedirect

ROOT = Path(__file__).resolve().parent
APP = 'misp42splunk'
HELPER = '/var/www/MISP/app/Console/Command/SplunkAuthShell.php'


def read_env():
    values = {}
    for line in (ROOT / '.env').read_text().splitlines():
        name, sep, value = line.partition('=')
        if sep and not line.lstrip().startswith('#'):
            values[name.strip()] = value.strip().strip('\"\'')
    return values


def ensure_key():
    values = read_env()
    name = 'MISP_SPLUNK_API_KEY'
    if not values.get(name):
        # Save before provisioning: an interrupted operation can safely reuse it.
        key = secrets.token_hex(20)
        text = (ROOT / '.env').read_text()
        entry = name + '=' + key
        if re.search('^' + name + '=', text, re.M):
            text = re.sub('^' + name + '=.*$', lambda match: entry, text, flags=re.M)
        else:
            text = text.rstrip() + '\n\n# Chiave MISP dedicata a Splunk, sola lettura.\n' + entry + '\n'
        fd, temporary = tempfile.mkstemp(prefix='.env-', dir=ROOT)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(text)
            os.replace(temporary, ROOT / '.env')
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        values[name] = key
    return values


def run(arguments, data=None, timeout=180):
    result = subprocess.run(arguments, cwd=ROOT, input=data, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        # Helper output may contain a newly created key. Only report its stage.
        for line in result.stdout.splitlines():
            if line.startswith('SPLUNK_AUTH_RESULT='):
                stage = json.loads(line.partition('=')[2]).get('stage', 'unknown')
                raise RuntimeError('Configurazione account MISP non riuscita: ' + stage)
        raise RuntimeError('Comando locale non riuscito, codice ' + str(result.returncode))
    return result.stdout


def provision_reader(values):
    base = ['podman', 'compose', 'exec', '-T']
    installed = False
    try:
        run(base + ['misp-core', 'sh', '-c',
                    'set -C; cat > "$1" && chmod 644 "$1"', 'sh', HELPER],
            (ROOT / 'integrations' / 'SplunkAuthShell.php').read_text())
        installed = True
        run(base + ['misp-core', 'php', '-l', HELPER])
        payload = {'mode': 'configure', 'email': values.get('ADMIN_EMAIL', 'admin@localhost.test'),
                   'api_key': values['MISP_SPLUNK_API_KEY']}
        output = run(base + ['--user', 'www-data', 'misp-core',
                            '/var/www/MISP/app/Console/cake', 'SplunkAuth'], json.dumps(payload))
        for line in output.splitlines():
            if line.startswith('SPLUNK_AUTH_RESULT='):
                result = json.loads(line.partition('=')[2])
                if not result.get('ok') or not result.get('read_only'):
                    raise RuntimeError('Verifica account MISP non riuscita.')
                print(f"Account MISP: {result['email']}, user_id={result['user_id']}, sola lettura.", flush=True)
                return
        raise RuntimeError('Risultato della configurazione MISP mancante.')
    finally:
        if installed:
            run(base + ['misp-core', 'rm', '-f', HELPER])


class Splunk:
    def __init__(self, values):
        self.authorization = 'Basic ' + base64.b64encode(
            ('admin:' + values['SPLUNK_PASSWORD']).encode()).decode()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
            NoRedirect(),
        )

    def request(self, path, fields=None):
        # The management endpoint is bound to loopback and uses Splunk's own
        # self-signed certificate. MISP connections use full CA verification.
        url = 'https://127.0.0.1:8089' + path
        data = None
        if fields is None:
            url += ('&' if '?' in url else '?') + 'output_mode=json'
        else:
            data = urllib.parse.urlencode(dict(fields, output_mode='json')).encode()
        request = urllib.request.Request(url, data=data,
                    headers={'Authorization': self.authorization})
        try:
            with self.opener.open(request, timeout=180) as response:
                body = response.read()
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as error:
            raise RuntimeError(f'Splunk HTTP {error.code} per {path}.') from None


def require_app(client):
    apps = client.request('/services/apps/local?count=0')
    existing = [entry for entry in apps.get('entry', []) if entry['name'] == APP]
    if existing:
        print('MISP42 già installato: ' + str(existing[0]['content'].get('version')), flush=True)
        return
    raise RuntimeError('Installare MISP42 da Splunkbase (app 4335) prima della configurazione.')


def configure_instance(client, values):
    certificate = (ROOT / 'ssl' / 'cert.pem').read_text()
    run(['podman', 'exec', '-i', '--user', 'splunk', 'misp-splunk-1',
         'sh', '-c', 'umask 022; cat > /opt/splunk/etc/auth/misp-ca.pem'], certificate)
    run(['podman', 'exec', '--user', 'splunk', 'misp-splunk-1', 'sh', '-c',
         'set -eu; umask 022; cat /etc/pki/tls/certs/ca-bundle.crt /opt/splunk/etc/auth/misp-ca.pem '
         '> /opt/splunk/etc/auth/misp-ca-bundle.pem.tmp; '
         'mv /opt/splunk/etc/auth/misp-ca-bundle.pem.tmp /opt/splunk/etc/auth/misp-ca-bundle.pem'])
    endpoint = '/servicesNS/nobody/misp42splunk/misp42splunk_instances'
    entries = client.request(endpoint).get('entry', [])
    settings = {'misp_url': 'https://misp-nginx:8443', 'misp_key': values['MISP_SPLUNK_API_KEY'],
                'misp_verifycert': '1', 'misp_use_proxy': '0', 'prefix': 'misp_',
                'connection_timeout': '10', 'read_timeout': '200'}
    if any(entry['name'] == 'local_misp' for entry in entries):
        client.request(endpoint + '/local_misp', settings)
    else:
        client.request(endpoint, dict(settings, name='local_misp'))
    print('Istanza local_misp configurata con verifica TLS e credenziale cifrata in Splunk.', flush=True)


def save_reports(client):
    endpoint = '/servicesNS/admin/misp42splunk/saved/searches'
    existing = {entry['name'] for entry in client.request(endpoint + '?count=0').get('entry', [])}
    searches = {
        'MISP locale - Indicatori IP in tempo reale': LIVE_SEARCH,
        'MISP locale - Lookup IP': (
            '| inputlookup misp_ip_intel.csv '
            '| table ip misp_sources misp_event_ids misp_to_ids misp_attribute_count'
        ),
        'MISP locale - IP per fonte': (
            '| inputlookup misp_ip_intel.csv | mvexpand misp_sources '
            '| stats count as IP_distinti by misp_sources | sort - IP_distinti'
        ),
    }
    for name, search in searches.items():
        path = endpoint + '/' + urllib.parse.quote(name, safe='')
        settings = {'search': search, 'is_scheduled': '0', 'disabled': '0',
                    'dispatch.earliest_time': '0', 'dispatch.latest_time': 'now'}
        if name in existing:
            client.request(path, settings)
        else:
            client.request(endpoint, dict(settings, name=name))
        client.request(path + '/acl', {'sharing': 'app', 'owner': 'admin',
                                     'perms.read': 'admin', 'perms.write': 'admin'})
    print('Tre report manuali MISP salvati nell’app, accessibili agli amministratori.', flush=True)


def main():
    values = ensure_key()
    provision_reader(values)
    client = Splunk(values)
    require_app(client)
    configure_instance(client, values)
    save_reports(client)
    print('Collegamento configurato. Eseguire python3 splunk_sync.py per aggiornare gli indicatori.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        raise SystemExit('Configurazione interrotta: ' + message)
