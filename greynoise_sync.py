#!/usr/bin/env python3
"""Import a bounded, private GreyNoise IP snapshot into the local MISP stack."""

import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parent
QUERY = 'last_seen:1d classification:malicious'
LIMIT = 10000
FEED_PATH = '/var/www/MISP/app/files/feeds/greynoise-malicious.txt'
CAKE = '/var/www/MISP/app/Console/cake'
HELPER = '/var/www/MISP/app/Console/Command/GreyNoiseSetupShell.php'


def read_env():
    values = {}
    for line in (ROOT / '.env').read_text().splitlines():
        name, separator, value = line.partition('=')
        if separator and not line.lstrip().startswith('#'):
            values[name.strip()] = value.strip().strip('\"\'')
    if not values.get('GREYNOISE_API_KEY'):
        raise RuntimeError('Impostare GREYNOISE_API_KEY nel file .env.')
    return values


def download(key):
    params = urllib.parse.urlencode({'query': QUERY, 'size': LIMIT, 'quick': 'true'})
    request = urllib.request.Request(
        'https://api.greynoise.io/v3/gnql/metadata?' + params,
        headers={'key': key, 'Accept': 'application/json',
                 'User-Agent': 'misp-local-greynoise-feed'},
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            status = response.status
            data = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f'GreyNoise ha risposto HTTP {error.code}; lista precedente conservata.') from None
    metadata = data.get('request_metadata', {})
    # GreyNoise can silently remove unlicensed filters. Accept only this query
    # and its documented/observed equivalent normalization.
    allowed = {QUERY, '(last_seen:1d AND classification:malicious)'}
    adjusted = metadata.get('adjusted_query')
    if status not in (200, 206) or adjusted not in allowed:
        raise RuntimeError('GreyNoise non ha confermato tutti i filtri; lista precedente conservata.')
    if metadata.get('query') != QUERY:
        raise RuntimeError('La query restituita da GreyNoise non corrisponde alla richiesta.')
    rows = data.get('data')
    if not isinstance(rows, list) or not rows:
        raise RuntimeError('Lista GreyNoise vuota o non valida; lista precedente conservata.')
    ips = []
    for row in rows:
        address = ipaddress.ip_address(row['ip'])
        classification = row.get('classification') or row.get('internet_scanner_intelligence', {}).get('classification')
        if not address.is_global or classification != 'malicious':
            raise RuntimeError('GreyNoise ha restituito un indirizzo o una classificazione inattesi.')
        ips.append(str(address))
    if len(ips) > LIMIT:
        raise RuntimeError('GreyNoise ha superato il limite richiesto.')
    ips = list(dict.fromkeys(ips))
    return ips, {'query': QUERY, 'downloaded': len(ips),
                 'total_matches': metadata.get('count'),
                 'complete': metadata.get('complete', False)}


class Misp:
    def __init__(self, values):
        self.key = values['GREYNOISE_API_KEY']
        self.email = values.get('ADMIN_EMAIL', 'admin@localhost.test')

    def run(self, arguments, data=None, user=None, timeout=180):
        command = ['podman', 'compose', 'exec', '-T']
        if user:
            command += ['--user', user]
        command += ['misp-core'] + arguments
        result = subprocess.run(command, cwd=ROOT, input=data, capture_output=True,
                                text=True, timeout=timeout)
        if result.returncode:
            # Container output can contain configuration: do not forward it.
            for line in result.stdout.splitlines():
                if line.startswith('GREYNOISE_RESULT='):
                    report = json.loads(line.partition('=')[2])
                    raise RuntimeError('Operazione MISP non riuscita: ' + report.get('stage', 'unknown'))
            raise RuntimeError(f'Comando MISP non riuscito (codice {result.returncode}).')
        return result.stdout

    def helper(self, mode, **kwargs):
        output = self.run([CAKE, 'GreyNoiseSetup'],
                          json.dumps(dict(mode=mode, email=self.email, **kwargs)),
                          user='www-data')
        for line in output.splitlines():
            if line.startswith('GREYNOISE_RESULT='):
                result = json.loads(line.partition('=')[2])
                if not result.get('ok'):
                    raise RuntimeError('Operazione MISP non riuscita: ' + result.get('stage', mode))
                return result
        raise RuntimeError('Risultato del comando MISP mancante.')

    def write_snapshot(self, ips):
        temporary = FEED_PATH + '.' + uuid.uuid4().hex + '.tmp'
        # Atomic replacement prevents a failed download from truncating the
        # native feed and deleting its existing attributes on the next fetch.
        script = 'set -eu; umask 077; mkdir -p "$(dirname "$2")"; trap \'rm -f "$1"\' EXIT; cat > "$1"; mv -f "$1" "$2"'
        self.run(['sh', '-c', script, 'sh', temporary, FEED_PATH],
                 '\n'.join(ips) + '\n', user='www-data')

    def sync(self, ips, enable_enrichment=None):
        installed = False
        feed_id = None
        try:
            source = (ROOT / 'integrations' / 'GreyNoiseSetupShell.php').read_text()
            self.run(['sh', '-c', 'set -C; cat > "$1" && chmod 644 "$1"', 'sh', HELPER], source)
            installed = True
            self.run(['php', '-l', HELPER])
            settings = {'api_key': self.key}
            if enable_enrichment is not None:
                settings['enabled'] = enable_enrichment
            self.helper('settings', **settings)
            self.write_snapshot(ips)
            result = self.helper('configure')
            feed_id = result['feed_id']
            # Configure disabled first: even a lost configure response cannot
            # leave an enabled feed whose ID is unknown to the cleanup path.
            self.helper('enable', feed_id=feed_id)
            print(f'Feed GreyNoise {feed_id}: importazione di {len(ips)} IP...', flush=True)
            output = self.run([CAKE, 'Server', 'fetchFeed', str(result['user_id']), str(feed_id)],
                              user='www-data', timeout=1800)
            if 'Job done.' not in output or 'Job failed.' in output:
                raise RuntimeError('Importazione del feed MISP non riuscita.')
            status = self.helper('status', feed_id=feed_id)
            if (not status.get('event_id') or status.get('ip_dst_count') != len(ips)
                    or status.get('to_ids_count') != 0 or status.get('published')
                    or status.get('distribution') != 0):
                raise RuntimeError('La verifica finale dell’evento MISP non è riuscita.')
        finally:
            try:
                if feed_id is not None:
                    self.helper('disable', feed_id=feed_id)
            finally:
                if installed:
                    self.run(['rm', '-f', HELPER])
        status['enabled'] = False
        return status


def main():
    values = read_env()
    ips, metadata = download(values['GREYNOISE_API_KEY'])
    print('Download verificato: ' + json.dumps(metadata), flush=True)
    status = Misp(values).sync(ips)
    print(f"Importazione verificata: evento {status['event_id']}, "
          f"{status['ip_dst_count']} IP, privato, non pubblicato, to_ids=false.")
    print('Feed disabilitato dopo l’importazione; pronto per il prossimo ciclo.')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        # Avoid printing request objects, subprocess payloads or API secrets.
        if isinstance(error, RuntimeError):
            print('Errore: ' + str(error), file=sys.stderr)
        else:
            print('Operazione interrotta: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
