#!/usr/bin/env python3
"""Enable persistent raw TCP and UDP syslog inputs in the local Splunk lab."""

import json
import sys

from splunk_setup import Splunk, read_env

PORT = '5514'
INDEX = 'syslog'
NAMESPACE = '/servicesNS/nobody/search'


def enabled(value):
    return value is True or str(value).lower() in ('1', 'true')


def configure(client):
    indexes = client.request('/services/data/indexes?count=0').get('entry', [])
    existing = next((entry for entry in indexes if entry['name'] == INDEX), None)
    if existing is None:
        client.request(NAMESPACE + '/data/indexes', {
            'name': INDEX, 'maxTotalDataSizeMB': '2048',
            'frozenTimePeriodInSecs': '2592000',
        })
    elif enabled(existing['content'].get('disabled')):
        raise RuntimeError('The syslog index exists but is disabled; enable it before configuring inputs.')

    result = {}
    for protocol, endpoint in (('tcp', 'tcp/raw'), ('udp', 'udp')):
        path = NAMESPACE + '/data/inputs/' + endpoint
        entries = client.request(path + '?count=0').get('entry', [])
        current = next((entry for entry in entries if entry['name'] == PORT), None)
        settings = {'index': INDEX, 'sourcetype': 'syslog',
                    'connection_host': 'ip', 'disabled': '0'}
        if protocol == 'udp':
            settings.update(no_appending_timestamp='true', no_priority_stripping='true')
        if current is not None:
            content = current['content']
            if content.get('index') != INDEX or content.get('sourcetype') != 'syslog':
                raise RuntimeError('Port 5514 already has a different input; no changes made to that input.')
            client.request(path + '/' + PORT, settings)
        else:
            client.request(path, dict(settings, name=PORT))
        content = client.request(path + '/' + PORT)['entry'][0]['content']
        if (enabled(content.get('disabled')) or content.get('index') != INDEX
                or content.get('sourcetype') != 'syslog'
                or content.get('connection_host') != 'ip'):
            raise RuntimeError('Syslog input verification failed for ' + protocol + '.')
        if protocol == 'udp' and not all(enabled(content.get(name)) for name in
                                         ('no_appending_timestamp', 'no_priority_stripping')):
            raise RuntimeError('UDP payload preservation settings were not applied.')
        result[protocol] = {'port': int(PORT), 'index': INDEX, 'sourcetype': 'syslog'}
    return result


def main():
    values = read_env()
    if not values.get('SPLUNK_PASSWORD'):
        raise RuntimeError('Set SPLUNK_PASSWORD in .env first.')
    report = configure(Splunk(values))
    print('SYSLOG_CONFIGURED=' + json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        raise SystemExit('Syslog setup failed: ' + message)
