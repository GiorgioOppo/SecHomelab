#!/usr/bin/env python3
"""One locked update cycle: daily upstream feeds and a five-minute Splunk lookup."""

import fcntl
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
STATE_DIR = ROOT / '.sync-state'
STAGES = ('abuseipdb', 'greynoise', 'splunk')
INTERVALS = {'abuseipdb': 86400, 'greynoise': 86400, 'splunk': 300}
RETRIES = {'abuseipdb': 21600, 'greynoise': 21600, 'splunk': 300}


class CycleError(RuntimeError):
    """Only fixed, non-sensitive diagnostics belong in this exception."""


def load_state(path):
    if not path.exists():
        return {'version': 1, 'stages': {}}
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or data.get('version') != 1 or not isinstance(data.get('stages'), dict):
            raise ValueError
        for name, stage in data['stages'].items():
            if name not in STAGES or not isinstance(stage, dict):
                raise ValueError
            if stage.get('status') not in ('running', 'ok', 'failed'):
                raise ValueError
            for field in ('last_attempt', 'last_success'):
                value = stage.get(field)
                if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                                          or not math.isfinite(value) or value < 0):
                    raise ValueError
            if stage.get('last_attempt') is None:
                raise ValueError
        return data
    except (ValueError, TypeError, OSError):
        raise CycleError('Stato della sincronizzazione non valido; nessun aggiornamento eseguito.') from None


def save_state(path, state):
    fd, temporary = tempfile.mkstemp(prefix='.state-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(state, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def is_due(name, stage, now):
    # A backwards clock adjustment delays work instead of repeating downloads.
    success = stage.get('last_success')
    attempt = stage.get('last_attempt')
    # Anchor the lookup cadence to dispatch, not completion: a two-minute job
    # must not cause the next five-minute heartbeat to be skipped every time.
    if name == 'splunk':
        return attempt is None or now - attempt >= INTERVALS[name]
    if success is not None and now - success < INTERVALS[name]:
        return False
    return attempt is None or now - attempt >= RETRIES[name]


def check_services():
    command = ['podman', 'inspect', '--format', '{{.State.Running}}',
               'misp-misp-core-1', 'misp-misp-nginx-1', 'misp-splunk-1']
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        raise CycleError('Podman non disponibile; nessuna fonte esterna interrogata.') from None
    if result.returncode or result.stdout.split() != ['true', 'true', 'true']:
        raise CycleError('MISP o Splunk non avviati; nessuna fonte esterna interrogata.')
    # Check the actual APIs too: a running container can still be starting up.
    from splunk_sync import MispClient, SplunkClient, read_env
    try:
        values = read_env()
        MispClient(values['MISP_SPLUNK_API_KEY']).request('/servers/getVersion')
        SplunkClient(values['SPLUNK_PASSWORD']).request('/services/server/info', params={'output_mode': 'json'})
    except Exception:
        raise CycleError('API MISP o Splunk non pronte; nessuna fonte esterna interrogata.') from None


def run_stage(name):
    scripts = {'abuseipdb': 'abuseipdb_sync.py', 'greynoise': 'greynoise_sync.py', 'splunk': 'splunk_sync.py'}
    # Each importer has its own request/job timeouts and cleanup. Do not impose
    # an outer timeout that could orphan a Cake import still running in Podman.
    try:
        result = subprocess.run([sys.executable, str(ROOT / scripts[name])], cwd=ROOT,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def run_cycle(state_path, runner=run_stage, preflight=check_services, clock=time.time):
    """Caller holds the process lock for this entire function."""
    state = load_state(state_path)
    preflight()
    results = {}
    transitions = []
    for name in STAGES:
        stage = state['stages'].setdefault(name, {})
        if not is_due(name, stage, clock()):
            results[name] = 'cooldown' if stage.get('status') in ('failed', 'running') else 'not_due'
            continue
        previous = stage.get('status')
        stage.update(status='running', last_attempt=clock())
        # Persist before invoking a quota-limited provider, including on crashes.
        save_state(state_path, state)
        print(name + ': aggiornamento in corso.', flush=True)
        try:
            ok = bool(runner(name))
        except Exception:
            ok = False  # Never echo upstream exceptions or credentials.
        stage['status'] = 'ok' if ok else 'failed'
        if ok:
            stage['last_success'] = clock()
        save_state(state_path, state)
        results[name] = stage['status']
        print(name + ': ' + ('aggiornamento verificato.' if ok else 'aggiornamento non riuscito.'), flush=True)
        if not ok and previous not in ('failed', 'running'):
            transitions.append(name + ':failure')
        elif ok and previous in ('failed', 'running'):
            transitions.append(name + ':recovered')
    failed = [name for name, stage in state['stages'].items() if stage.get('status') in ('failed', 'running')]
    return {'status': 'degraded' if failed else 'ok', 'stages': results,
            'failed': failed, 'transitions': transitions}


def main():
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    with (STATE_DIR / 'cycle.lock').open('a') as lock:
        os.chmod(lock.name, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('INTEL_SYNC_RESULT=' + json.dumps({'status': 'busy'}))
            return 0
        report = run_cycle(STATE_DIR / 'state.json')
    print('INTEL_SYNC_RESULT=' + json.dumps(report, sort_keys=True))
    return 1 if report['status'] == 'degraded' else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        message = str(error) if isinstance(error, CycleError) else type(error).__name__
        print('Ciclo interrotto: ' + message, file=sys.stderr)
        sys.exit(1)
