#!/usr/bin/env python3
"""Refresh the existing private AbuseIPDB feed without rewriting its credentials."""

import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
CAKE = '/var/www/MISP/app/Console/cake'
HELPER = '/var/www/MISP/app/Console/Command/AbuseipdbSyncShell.php'
MARKER = 'ABUSEIPDB_SYNC_RESULT='
LIMIT = 10000


def read_env():
    values = {}
    for line in (ROOT / '.env').read_text().splitlines():
        name, separator, value = line.partition('=')
        if separator and not line.lstrip().startswith('#'):
            values[name.strip()] = value.strip().strip('\"\'')
    if not values.get('ABUSEIPDB_API_KEY'):
        raise RuntimeError('Impostare ABUSEIPDB_API_KEY nel file .env.')
    return values


class Misp:
    def __init__(self, values):
        self.key = values['ABUSEIPDB_API_KEY']
        self.email = values.get('ADMIN_EMAIL', 'admin@localhost.test')

    def run(self, arguments, data=None, user=None, timeout=180):
        command = ['podman', 'compose', 'exec', '-T']
        if user:
            command += ['--user', user]
        command += ['misp-core'] + arguments
        result = subprocess.run(command, cwd=ROOT, input=data, capture_output=True,
                                text=True, timeout=timeout)
        if result.returncode:
            # Do not forward container diagnostics, which can contain headers.
            raise RuntimeError(f'Comando MISP non riuscito (codice {result.returncode}).')
        return result.stdout

    def helper(self, mode, **kwargs):
        payload = dict(mode=mode, email=self.email, **kwargs)
        if mode == 'inspect':
            payload['api_key'] = self.key
        output = self.run([CAKE, 'AbuseipdbSync'], json.dumps(payload), user='www-data')
        for line in output.splitlines():
            if line.startswith(MARKER):
                result = json.loads(line[len(MARKER):])
                if not result.get('ok'):
                    raise RuntimeError('Verifica del feed AbuseIPDB non riuscita.')
                return result
        raise RuntimeError('Risultato del comando MISP mancante.')

    def sync(self):
        installed = False
        feed_id = None
        try:
            source = (ROOT / 'integrations' / 'AbuseipdbSyncShell.php').read_text()
            self.run(['sh', '-c', 'set -C; cat > "$1" && chmod 644 "$1"', 'sh', HELPER], source)
            installed = True
            self.run(['php', '-l', HELPER])
            before = self.helper('inspect')
            feed_id = before['feed_id']
            self.helper('enable', feed_id=feed_id)
            print(f'Feed AbuseIPDB {feed_id}: aggiornamento della blacklist...', flush=True)
            output = self.run([CAKE, 'Server', 'fetchFeed', str(before['user_id']), str(feed_id)],
                              user='www-data', timeout=1800)
            # MISP's Cake command can exit zero even when its background job failed.
            if 'Job done.' not in output or 'Job failed.' in output:
                raise RuntimeError('Importazione del feed AbuseIPDB non riuscita.')
            status = self.helper('status', feed_id=feed_id)
            count = status.get('ip_dst_count', 0)
            if (status.get('event_id') != before['event_id']
                    or not isinstance(count, int) or not 0 < count <= LIMIT
                    or status.get('attribute_count') != count
                    or status.get('to_ids_count') != 0 or status.get('published')
                    or status.get('distribution') != 0):
                raise RuntimeError('La verifica finale dell’evento AbuseIPDB non è riuscita.')
        finally:
            try:
                # Set before enabling: even a lost enable response is cleaned up.
                if feed_id is not None:
                    self.helper('disable', feed_id=feed_id)
            finally:
                if installed:
                    self.run(['rm', '-f', HELPER])
        status['enabled'] = False
        return status


def main():
    status = Misp(read_env()).sync()
    print(f"Importazione verificata: evento {status['event_id']}, "
          f"{status['ip_dst_count']} IP, privato, non pubblicato, to_ids=false.")
    print('Feed disabilitato dopo l’importazione; pronto per il prossimo aggiornamento.')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        if isinstance(error, RuntimeError):
            print('Errore: ' + str(error), file=sys.stderr)
        else:
            print('Operazione interrotta: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
