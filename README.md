# SecHomelab

MISP and Splunk with Podman Compose.

A stack for a new local installation: MISP core, Nginx, MISP modules,
MariaDB, Valkey (Redis-compatible), an SMTP relay, and standalone Splunk Enterprise.
The MISP configuration follows the
[official architecture with a separate Nginx container](https://github.com/MISP/misp-docker#breaking-changes).
Data is stored in named volumes. MISP uses HTTPS on port 8443, Splunk Web
uses port 8000, and the Splunk API uses port 8089. All published ports bind
to loopback by default.

## Getting started

Requirements: Podman 4.9 or later, a Compose provider such as
`podman-compose`, Python 3, and OpenSSL with `-addext` support.
On macOS and Windows, a Podman machine must be running. Check
`podman info` and `podman compose version` first.

On a Mac without a usable VM, create a dedicated one once:

```sh
podman machine init --cpus 4 --memory 8192 --disk-size 40 --rootful=false --update-connection misp-machine
podman machine start misp-machine
```

If `misp-machine` already exists, run `podman machine start misp-machine`.
To select it again, run `podman system connection default misp-machine`.
The error `failed to read identity .../machine` indicates a missing VM SSH key,
rather than a Compose issue. Before removing an old VM, check
`podman machine list` and preserve any disks and data.

From the directory containing this README, configure the Splunk terms
as described in the next section, then start the stack:

```sh
python3 init.py
podman compose pull
podman compose up -d
podman compose ps
podman compose logs -f misp-core
```

Database and MISP initialization may take a few minutes.
Open [https://localhost:8443](https://localhost:8443) and accept the
self-signed certificate for this local environment. The initial username is
`admin@localhost.test`; the password is the `ADMIN_PASSWORD` value in `.env`.

`init.py` creates `.env` from `.env.example` with random secrets and mode 0600.
It also creates a certificate valid for localhost and the loopback addresses.
Existing credentials and certificates are preserved; only a missing or empty
Splunk password is generated. If you manually copy `.env.example` to `.env`,
you must fill in every empty secret yourself. Use alphanumeric database
passwords, as the script does.

## Splunk Enterprise

The `splunk` service uses version `10.4.3` of the
[official image](https://hub.docker.com/r/splunk/splunk)
and stores its configuration and indexes in the `splunk_etc` and `splunk_var` volumes.
The image targets `linux/amd64`. On the reference ARM64 Mac, it runs through
QEMU emulation in the `misp-machine` VM using the `Haswell-v4` CPU model.
The default QEMU CPU model fails Splunk's CPU check on subsequent starts;
the configured model passes the precheck with all checks still enabled.
`SPLUNK_ANSIBLE_ENV` preserves the CPU and TLS bundle settings when container
provisioning switches users. This configuration is intended for a local lab;
startup under emulation may take several minutes.

Before starting Splunk, read and accept the
[Splunk terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html).
The [container documentation](https://github.com/splunk/docker-splunk/blob/develop/docs/ADVANCED.md)
explicitly requires both flags. Run `python3 init.py` to create `.env` if needed,
then set the following values only after accepting the terms:

```dotenv
SPLUNK_START_ARGS=--accept-license
SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com
```

`init.py` generates `SPLUNK_PASSWORD` even when `.env` already exists,
without automatically setting the acceptance flags. To add only Splunk
to an existing MISP stack:

```sh
python3 init.py
podman compose pull splunk
podman compose up -d splunk
podman compose logs -f splunk
```

Open [http://localhost:8000](http://localhost:8000), sign in as `admin`,
and use `SPLUNK_PASSWORD` from `.env`. The management API is available at
`https://localhost:8089` with Splunk's generated certificate.
Ports can be configured through `SPLUNK_WEB_PORT` and `SPLUNK_API_PORT`;
`SPLUNK_BIND_ADDRESS` controls Splunk's bind address separately.
MISP and Splunk share the Compose network. Indicator integration is described
below.

The flags acknowledge the terms; they do not install a commercial license.
Licensing remains managed by Splunk Enterprise.

## Syslog ingestion

Splunk can receive syslog over raw TCP and UDP on port **5514** and store
the events in the **`syslog`** index with `sourcetype=syslog`.
With Splunk running, configure the listeners from the repository directory:

```sh
python3 syslog_setup.py
```

The script creates the index with a 30-day retention period and a 2048 MB
size limit; older data is removed when either limit is reached. If the index
already exists, its retention settings are preserved. Input configuration
and indexed events persist in the existing Splunk volumes.

To receive logs from devices on your LAN, set these values in `.env`:

```dotenv
SPLUNK_SYSLOG_BIND_ADDRESS=0.0.0.0
SPLUNK_SYSLOG_PORT=5514
```

The default bind address is `127.0.0.1`, which accepts local connections only.
`SPLUNK_SYSLOG_PORT` changes the published host port for both protocols;
the listeners inside the container always use port 5514. Apply the port
mappings and wait for Splunk to become `healthy`:

```sh
podman compose up -d --no-deps splunk
podman compose ps splunk
```

On each sending device, select TCP or UDP syslog and use the **Mac's LAN IP
address** and the published port, not the container or VM address. These
listeners use plain TCP/UDP without TLS. Splunk Web and the management API
retain their separate loopback bindings. The Mac and Podman VM must remain
running to receive logs.

Search incoming events in Splunk:

```spl
index=syslog sourcetype=syslog
| table _time host source _raw
```

The input uses `connection_host=ip`, but Podman's forwarding can replace the
network peer IP. Splunk's built-in syslog parsing can then set `host` from
the hostname in the message. Do not treat `host` as a verified sender IP.
A successful test from the Mac confirms local ingestion; delivery from
another device also depends on the LAN path and the Mac's firewall.

See the official [Splunk input API reference](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.4/input-endpoints/input-endpoint-descriptions),
[syslog host parsing example](https://help.splunk.com/en/splunk-enterprise/get-data-in/get-started-with-getting-data-in/9.3/configure-source-types/override-source-types-on-a-per-event-basis),
and [Podman port publishing reference](https://docs.podman.io/en/latest/markdown/podman-run.1.html#publish-p-hostip-hostport-containerport-protocol)
for listener settings and forwarding behavior.

## MISP indicators in Splunk

The integration uses **MISP42 6.0.0**. Manually install the
[MISP42 app](https://splunkbase.splunk.com/app/4335) in Splunk, then run the
following command from the repository directory with both MISP and Splunk running:

```sh
python3 splunk_setup.py
```

Setup creates the `local_misp` instance using the internal URL
`https://misp-nginx:8443`, a read-only account, and the reports listed below.
The app adds search commands for querying MISP attributes from Splunk.
The included scripts require the project name `misp` and the default ports
8443 and 8089. Changing Compose alone does not update these references.

The reference lab was updated and validated on September 17, 2026:
**20,000 attributes** were verified and grouped into **18,556 distinct IPs**,
with 10,000 IPs from each source, AbuseIPDB and GreyNoise. Independent searches
verified the saved lookup and a lookup match for a known IP.
These data, accounts, and local IDs are not included in the repository.
A new installation must configure its integrations and import its own sources.

After setup, the app provides three manually run reports accessible to the
`admin` role. Their names match those created by the setup script:

- `MISP locale - Indicatori IP in tempo reale`: queries MISP directly.
- `MISP locale - Lookup IP`: displays the verified local lookup.
- `MISP locale - IP per fonte`: groups IPs by source.

The dedicated MISP account, `splunk@localhost.test`, belongs to the local
organization and has read-only API access. Its key is stored in `.env` as
`MISP_SPLUNK_API_KEY` and encrypted in Splunk's credential store.
The connection verifies MISP's certificate. The local certificate includes
`misp-nginx`, and `SSL_CERT_FILE` points to a persistent bundle containing
both public CAs and the MISP certificate.

In the reference lab, a Codex automation invokes the cycle every 5 minutes:
**external sources refresh every 24 hours, and the Splunk lookup refreshes every 5 minutes**.
This automation is external to the repository; cloning the repository or
starting Compose does not create it. To reproduce the schedule, create an
automation in your own Codex installation that runs the following command
every 5 minutes from the repository directory:

```sh
python3 intel_sync.py
```

The same command can run a single cycle manually; it does not start a scheduler.
The script uses `fcntl` and requires a macOS or Linux host.

`intel_sync.py` first updates AbuseIPDB and GreyNoise when due, then synchronizes
Splunk. It records each stage's last successful run separately in
`.sync-state/state.json` with mode 0600, records an attempt before contacting
a source, and prevents overlapping cycles. An unavailable source does not block
the other stages and is retried after 6 hours. Splunk is retried on the next
cycle. Invalid state stops the cycle without downloading the sources again.
Do not delete the state to force an update: it also protects API quotas.
The individual stage scripts remain available for troubleshooting, but use
`intel_sync.py` for normal operation.

Updates are periodic rather than instantaneous. A long import, a service still
starting, or a sleeping Mac can delay a cycle. Keep the Mac on, Codex running,
and the Podman VM running with MISP and Splunk started. Manage the schedule
in Codex's automations section; it is not a Compose service. See the
[official scheduled tasks documentation](https://learn.chatgpt.com/docs/automations?surface=app).

To run only the MISP → Splunk synchronization while troubleshooting,
ensure no automatic cycle is active, then run this command from the repository directory:

```sh
python3 splunk_sync.py
```

The script queries MISP and MISP42, compares all UUIDs and IP values, and
writes `misp_ip_intel.csv` only when the results match. Empty, partial, or
invalid results stop the update. The lookup groups duplicate IPs while
preserving their source events, sources, and UUIDs.
It includes `ip-src` and `ip-dst`, including attributes with `to_ids=false`
and unpublished events accessible to the dedicated account. Attributes marked
as deleted are excluded from the new lookup.

To view the updated lookup in the MISP42 app:

```spl
| inputlookup misp_ip_intel.csv
| table ip misp_sources misp_event_ids misp_attribute_count
```

Example correlation with logs containing a `src_ip` field:

```spl
index=YOUR_INDEX
| lookup misp_ip_intel.csv ip AS src_ip OUTPUT misp_sources misp_event_ids
| where isnotnull(misp_event_ids)
```

Run the search in the MISP42 app context. The index name and IP field depend
on the logs being analyzed. This lookup is not a Splunk event index;
full attributes remain available through the `mispgetioc` command and the
app's saved reports.

`python3 splunk_setup.py` restores the account and instance configuration
using the same key, without rotating it. MISP42 must already be installed,
and both services must be running. After changing Compose, apply
`podman compose up -d --no-deps splunk` and wait for the `healthy` status
before synchronizing. After renewing the MISP certificate, run setup again
to update the trusted copy in Splunk.

## Configuration

- For LAN access, set `BIND_ADDRESS=0.0.0.0` and
  `BASE_URL=https://server-name:8443` in `.env`, and replace the certificate
  with one valid for that hostname. `HTTPS_PORT` must match the port in
  `BASE_URL`. Recreate the containers with `podman compose up -d`.
- The SMTP relay is internal. Configure `SMARTHOST_*` and `MISP_EMAIL`
  to send through your own mail server. Without a smarthost, the relay attempts
  direct delivery, which depends on the network and DNS configuration.
- For a stable deployment, replace `latest` with verified tags from the
  [official images](https://github.com/orgs/MISP/packages). Core and Nginx
  share `CORE_RUNNING_TAG` and must use the architecture with separate Nginx.
  Do not use tags from before the Nginx split.
- Do not change database passwords only in `.env` after the first startup:
  MariaDB retains the initialized users in its volume. Keep `ENCRYPTION_KEY`
  and `GPG_PASSPHRASE` with your backups as well.

The `ssl` directory has mode 0700 on the host. Its TLS files are readable
by the container's Nginx user because they are mounted individually.
Keep the directory private when replacing the certificate and key.
For certificates supplied manually, set permissions before starting:

```sh
chmod 700 ssl
chmod 644 ssl/cert.pem ssl/key.pem
```

A key with mode 0600 owned by the host user cannot be read by Nginx running
as UID 101. Mounting individual files keeps the host directory private while
allowing access inside the container. TLS bind mounts include the SELinux
`:Z` label; Podman manages the named volumes. `privileged` is not required.
Nginx tmpfs mounts use mode 1777 to allow UID 101 to write when using the
Docker Compose provider, which does not accept `uid`/`gid` options for
Podman tmpfs mounts.

## Stopping the stack and preserving data

```sh
podman compose down
```

This command preserves volumes. The `down -v` option deletes them, including
the database, attachments, configuration, logs, GPG keys, and Splunk indexes.
Before upgrading, back up the database, persistent volumes, `.env`, and certificates.

## AbuseIPDB blacklist

`abuseipdb_sync.py` refreshes an existing feed; it does not create the initial feed.
Before using the complete cycle, configure a MISP feed named
`AbuseIPDB blacklist (confidence 100)`, with provider `AbuseIPDB` and URL
`https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=100&limit=10000&plaintext`.
Use the `freetext` format and `network` source, a fixed event,
`delta_merge` and `override_ids` enabled, publishing disabled, and distribution
restricted to your organization. Set the headers to
`Key: <ABUSEIPDB_API_KEY value>` and `Accept: text/plain` on separate lines.
Run an initial import to associate a private, unpublished event, then disable
the feed. The API key must also be set in `.env`.

In the reference lab, 10,000 IPs were imported on September 17, 2026,
using `confidenceMinimum=100` and `limit=10000`. The following IDs are local
examples and will differ in a new installation:

- [Event 1](https://localhost:8443/events/view/1): 10,000 `ip-dst` attributes,
  visible only to the local organization and unpublished.
- [Feed 3](https://localhost:8443/feeds/view/3): `AbuseIPDB blacklist (confidence 100)`.
  The feed is disabled between imports; `intel_sync.py` refreshes it every 24 hours.
- `to_ids=false`: attributes remain available for analysis and correlation.

The personal API key is stored in `.env` as `ABUSEIPDB_API_KEY` and in the
MISP feed's authentication header. Changing `.env` alone does not update
the feed configuration already saved in MISP.

To refresh manually through the UI, enable the feed in the **Feeds** list,
start fetching it, and wait for the job to finish before disabling it.
The feed reuses the same event, deduplicates IPs, and uses `delta_merge`
to soft-delete indicators no longer present in the new list.

Source: [AbuseIPDB blacklist API](https://docs.abuseipdb.com/#blacklist-endpoint).

## GreyNoise

In the reference lab, **10,000 malicious IPs** were imported on September 17, 2026,
using GNQL with the query `last_seen:1d classification:malicious`.
The following IDs are local examples:

- [Event 2](https://localhost:8443/events/view/2): `ip-dst` attributes,
  visible only to the local organization, unpublished, with `to_ids=false`.
- [Feed 4](https://localhost:8443/feeds/view/4):
  `GreyNoise malicious IPs (last 24h, max 10000)`.
- The initial query matched 122,909 results. The import is limited to the
  first 10,000 returned by the provider, not the full list.

To download a new list and update the same event, run this command
from the repository directory:

```sh
python3 greynoise_sync.py
```

The script reads `GREYNOISE_API_KEY` from `.env`, checks that GreyNoise applied
all filters, and accepts only public IPs classified as `malicious`.
The query selects IPs currently classified as malicious and observed within
the last 24 hours. The separate `last_seen_malicious` filter was not included
in the verified key's permissions. An empty or invalid list, or a failed request,
leaves the previous list intact.

The native `freetext` feed reads
`/var/www/MISP/app/files/feeds/greynoise-malicious.txt` from the persistent
`misp_files` volume. The script replaces the file atomically, imports using
`delta_merge`, and disables the feed when finished. `intel_sync.py` runs this
stage every 24 hours. IPs missing from the new list are soft-deleted from
the event. Fetching through the MISP UI alone rereads the existing file;
use the script to contact GreyNoise and download fresh data.

In the reference lab, **GreyNoise Lookup 2.0** is also configured and enabled
for enriching IPv4 `ip-src` and `ip-dst` attributes. A test against the
`misp-modules` service returned a `greynoise-ip` object. Open an attribute
and select GreyNoise enrichment; CVE queries depend on your plan's permissions.

The key is stored in `.env` with mode 0600 and in MISP's persistent configuration.
The script also updates the copy of the key in MISP while preserving the module's
enabled or disabled state. On a new installation, enable enrichment in MISP's
settings if desired. The settings are `Plugin.Enrichment_greynoise_enabled`
and `Plugin.Enrichment_greynoise_api_key`, under
**Server Settings & Maintenance → Plugin Settings → Enrichment**.
The installed version does not use the legacy `api_type` parameter.

`integrations/GreyNoiseSetupShell.php` is temporarily uploaded to the container
during the update and removed afterward. The key is passed through stdin;
saving the settings creates an audit entry with the value redacted.
The helper supports the file-based configuration used by this stack.

References: [official MISP module](https://github.com/MISP/misp-modules/blob/main/misp_modules/modules/expansion/greynoise.py),
[GreyNoise integration](https://docs.greynoise.io/docs/integration-overview-misp),
[feed access](https://docs.greynoise.io/docs/using-greynoise-as-an-indicator-feed).

This configuration targets the current official topology:
[upstream Compose](https://github.com/MISP/misp-docker/blob/master/docker-compose.yml).
Health checks manage the initial startup order. Verify the login page once
initialization is complete.
