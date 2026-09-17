# SecHomelab

MISP e Splunk con Podman Compose.

Stack per una nuova installazione locale: MISP core, Nginx, MISP modules,
MariaDB, Valkey (compatibile Redis), relay SMTP e Splunk Enterprise standalone.
La configurazione MISP segue
la [nuova architettura ufficiale con Nginx separato](https://github.com/MISP/misp-docker#breaking-changes).
I dati sono conservati in volumi nominati; MISP usa HTTPS 8443, Splunk Web
la porta 8000 e l'API Splunk la porta 8089, tutte su loopback per impostazione predefinita.

## Avvio

Servono Podman 4.9 o successivo, un provider Compose (ad esempio
`podman-compose`), Python 3 e OpenSSL con supporto `-addext`.
Su macOS/Windows deve essere attiva una Podman machine. Verificare prima
`podman info` e `podman compose version`.

Su un Mac senza una VM utilizzabile, crearne una dedicata (una sola volta):

```sh
podman machine init --cpus 4 --memory 8192 --disk-size 40 --rootful=false --update-connection misp-machine
podman machine start misp-machine
```

Se `misp-machine` esiste già, basta `podman machine start misp-machine`.
Per selezionarla nuovamente: `podman system connection default misp-machine`.
L'errore `failed to read identity .../machine` indica una chiave SSH mancante
della VM, non un problema del Compose. Prima di rimuovere una vecchia VM,
controllare `podman machine list` e conservare eventuali dischi e dati.

Dalla cartella che contiene questo README, dopo aver configurato i termini
Splunk come indicato nella sezione seguente:

```sh
python3 init.py
podman compose pull
podman compose up -d
podman compose ps
podman compose logs -f misp-core
```

L'inizializzazione del database e di MISP può richiedere alcuni minuti.
Aprire [https://localhost:8443](https://localhost:8443), accettando il
certificato autofirmato per questo ambiente locale. Utente iniziale:
`admin@localhost.test`; password: valore `ADMIN_PASSWORD` nel file `.env`.

`init.py` crea `.env` da `.env.example` con segreti casuali e permessi 0600.
Crea inoltre un certificato valido per localhost e gli indirizzi di loopback.
Conserva credenziali e certificati già presenti, aggiungendo soltanto la
password Splunk se assente o vuota. Se si copia a mano
`.env.example` in `.env`, occorre compilare tutti i segreti vuoti manualmente.
Per le password database usare valori alfanumerici, come quelli generati.

## Splunk Enterprise

Il servizio `splunk` usa l'[immagine ufficiale](https://hub.docker.com/r/splunk/splunk)
versione `10.4.3`
e conserva configurazione e indici nei volumi `splunk_etc` e `splunk_var`.
L'immagine è `linux/amd64`: sul Mac ARM64 usa l'emulazione QEMU già presente
nella VM `misp-machine`, con modello `Haswell-v4`. Il modello predefinito
di QEMU non supera il controllo CPU di Splunk ai riavvii; il modello
configurato supera il precheck mantenendo attivi tutti i controlli.
`SPLUNK_ANSIBLE_ENV` preserva CPU e bundle TLS anche durante il cambio
utente eseguito dal provisioning del container.
Questa configurazione è destinata al laboratorio
locale; l'avvio emulato può richiedere diversi minuti.

Prima dell'avvio occorre leggere e accettare i
[termini Splunk](https://www.splunk.com/en_us/legal/splunk-general-terms.html).
La [documentazione del container](https://github.com/splunk/docker-splunk/blob/develop/docs/ADVANCED.md)
richiede esplicitamente entrambi i flag. Solo dopo l'accettazione, impostare in `.env`:

```dotenv
SPLUNK_START_ARGS=--accept-license
SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com
```

`init.py` genera `SPLUNK_PASSWORD` anche per un `.env` esistente, senza
impostare automaticamente i flag di accettazione. Per aggiungere solo Splunk
allo stack MISP già in esecuzione:

```sh
python3 init.py
podman compose pull splunk
podman compose up -d splunk
podman compose logs -f splunk
```

Accesso: [http://localhost:8000](http://localhost:8000), utente `admin`,
password `SPLUNK_PASSWORD` in `.env`. L'API di gestione è su
`https://localhost:8089` con il certificato generato da Splunk.
Le porte sono configurabili tramite `SPLUNK_WEB_PORT` e `SPLUNK_API_PORT`;
`SPLUNK_BIND_ADDRESS` controlla separatamente l'esposizione di Splunk.
MISP e Splunk condividono la rete Compose. Il collegamento degli indicatori
è descritto nella sezione seguente.

I flag indicano l'accettazione dei termini; non installano una licenza
commerciale. La gestione della licenza resta quella di Splunk Enterprise.

## Indicatori MISP in Splunk

L'integrazione usa **MISP42 6.0.0**. Installare manualmente
l'[app MISP42](https://splunkbase.splunk.com/app/4335) in Splunk e, con MISP e
Splunk avviati, eseguire dalla cartella del repository:

```sh
python3 splunk_setup.py
```

Il setup crea l'istanza `local_misp` con URL interno
`https://misp-nginx:8443`, l'account di sola lettura e i report descritti sotto.
L'app aggiunge comandi di ricerca per consultare gli attributi MISP da Splunk.
Gli script inclusi richiedono il nome di progetto `misp` e le porte predefinite
8443 e 8089; modificare soltanto il Compose non aggiorna questi riferimenti.

Nel laboratorio di riferimento, aggiornamento e collaudo del 17 settembre 2026: **20.000 attributi** verificati e
**18.556 IP distinti** nel lookup, con 10.000 IP per ciascuna fonte
AbuseIPDB e GreyNoise. La lettura del file salvato e la correlazione di un
IP noto tramite `lookup` sono state verificate con ricerche indipendenti.
Questi dati, gli account e gli ID locali non sono inclusi nel repository: una
nuova installazione deve configurare le integrazioni e importare le proprie fonti.

Dopo il setup, nell'app sono disponibili tre report manuali, accessibili al ruolo `admin`:

- `MISP locale - Indicatori IP in tempo reale`: consulta direttamente MISP.
- `MISP locale - Lookup IP`: mostra la tabella locale verificata.
- `MISP locale - IP per fonte`: raggruppa gli IP per provenienza.

L'account MISP dedicato `splunk@localhost.test` appartiene all'organizzazione
locale e ha accesso API di sola lettura. La chiave è conservata in `.env`
come `MISP_SPLUNK_API_KEY` e cifrata nell'archivio credenziali di Splunk.
Il collegamento verifica il certificato MISP: il certificato locale include
il nome `misp-nginx`, mentre `SSL_CERT_FILE` punta a un bundle persistente
che contiene sia le CA pubbliche sia il certificato MISP.

Nel laboratorio di riferimento, un'automazione Codex richiama il ciclo ogni
5 minuti: **fonti esterne ogni 24 ore, lookup Splunk ogni 5 minuti**.
L'automazione è esterna al repository e non viene creata dal clone o dal Compose.
Per riprodurre questa pianificazione, creare nella propria installazione Codex
un'automazione che esegua ogni 5 minuti, dalla cartella del repository:

```sh
python3 intel_sync.py
```

Lo stesso comando esegue un singolo ciclo manuale; non avvia uno scheduler.
Lo script usa `fcntl` e richiede un host macOS o Linux.

`intel_sync.py` aggiorna prima AbuseIPDB e GreyNoise, se scaduti, poi sincronizza
Splunk. Registra separatamente l'ultimo successo di ogni fase in
`.sync-state/state.json` (permessi 0600), salva il tentativo prima di contattare
una fonte e impedisce che due cicli si sovrappongano. Una fonte non disponibile
non blocca le altre fasi; viene riprovata dopo 6 ore. Splunk viene riprovato al
ciclo successivo. Un file di stato non valido arresta il ciclo senza riscaricare
le fonti. Non cancellare lo stato per forzare aggiornamenti, perché protegge
anche le quote API. Gli script dei singoli passaggi restano disponibili per la
diagnostica, ma per l'uso ordinario usare sempre `intel_sync.py`.

La cadenza è periodica, non una notifica istantanea di ogni modifica: un'importazione
lunga, un servizio in avvio o il Mac sospeso possono ritardare il ciclo. Servono
il Mac acceso, Codex in esecuzione e la VM Podman con MISP e Splunk avviati.
La pianificazione si gestisce nella sezione delle automazioni di Codex e non è
un servizio incluso nel Compose. Vedere la
[documentazione ufficiale sulle attività pianificate](https://learn.chatgpt.com/docs/automations?surface=app).

Per eseguire soltanto la sincronizzazione MISP → Splunk durante la diagnostica,
quando nessun ciclo automatico è attivo, dalla cartella del repository:

```sh
python3 splunk_sync.py
```

Lo script interroga MISP e MISP42, confronta tutti gli UUID e i valori IP e
scrive `misp_ip_intel.csv` soltanto se i risultati coincidono. Un risultato
vuoto, parziale o non valido interrompe l'aggiornamento. Il lookup raggruppa
gli IP duplicati mantenendo gli eventi di origine, le fonti e gli UUID.
Comprende `ip-src` e `ip-dst`, anche con `to_ids=false` e in eventi non
pubblicati accessibili all'account dedicato. Gli IP marcati come eliminati
vengono esclusi dalla nuova tabella.

Per consultare il lookup aggiornato nell'app MISP42:

```spl
| inputlookup misp_ip_intel.csv
| table ip misp_sources misp_event_ids misp_attribute_count
```

Esempio di correlazione con log che contengono un campo `src_ip`:

```spl
index=IL_TUO_INDICE
| lookup misp_ip_intel.csv ip AS src_ip OUTPUT misp_sources misp_event_ids
| where isnotnull(misp_event_ids)
```

La ricerca va eseguita nel contesto dell'app MISP42. Il nome dell'indice e
il campo IP dipendono dai log da analizzare. La tabella non è un indice di
eventi Splunk: gli attributi completi restano consultabili tramite il comando
`mispgetioc` e i report salvati nell'app.

`python3 splunk_setup.py` ripristina la configurazione dell'account e
dell'istanza usando la stessa chiave, senza ruotarla. Richiede MISP42 già
installato e i due servizi avviati. Dopo una modifica al Compose applicare
`podman compose up -d --no-deps splunk` e attendere lo stato `healthy` prima
di eseguire la sincronizzazione. Dopo il rinnovo del certificato MISP,
rieseguire il setup per aggiornare anche la copia fidata in Splunk.

## Configurazione

- Per accesso dalla LAN, impostare `BIND_ADDRESS=0.0.0.0` e
  `BASE_URL=https://nome-del-server:8443` in `.env`, e sostituire il
  certificato con uno valido per quel nome. `HTTPS_PORT` e la porta in
  `BASE_URL` devono coincidere. Ricreare i container con `podman compose up -d`.
- Il relay SMTP è interno. Configurare `SMARTHOST_*` e `MISP_EMAIL` per
  l'invio tramite il proprio server email. Senza smarthost il relay tenta
  la consegna diretta, che dipende dalla rete e dalla configurazione DNS.
- Per un deployment stabile, sostituire `latest` con tag verificati delle
  [immagini ufficiali](https://github.com/orgs/MISP/packages). Core e Nginx
  usano lo stesso `CORE_RUNNING_TAG` e devono appartenere alla nuova
  architettura. Non usare tag precedenti alla separazione di Nginx.
- Non cambiare le password database soltanto in `.env` dopo il primo
  avvio: MariaDB mantiene gli utenti già inizializzati nel volume.
  Conservare anche `ENCRYPTION_KEY` e `GPG_PASSPHRASE` insieme ai backup.

La cartella `ssl` ha permessi 0700 sull'host. I file TLS al suo interno
sono leggibili dall'utente Nginx nel container perché montati singolarmente.
Mantenere privata la cartella anche sostituendo il certificato e la chiave.
Con certificati forniti manualmente, impostare i permessi prima dell'avvio:

```sh
chmod 700 ssl
chmod 644 ssl/cert.pem ssl/key.pem
```

Una chiave con permessi 0600 appartenente all'utente host non è leggibile
dal processo Nginx UID 101. Il mount dei singoli file permette di mantenere
la cartella privata sull'host senza bloccare l'accesso dentro il container.
I bind mount TLS includono le etichette SELinux `:Z`; i volumi nominati
sono gestiti da Podman. Non è richiesto `privileged`. I tmpfs di Nginx usano
permessi 1777 per consentire la scrittura all'UID 101 anche tramite il
provider Docker Compose, che non accetta `uid`/`gid` nei mount tmpfs Podman.

## Arresto e dati

```sh
podman compose down
```

Questo comando conserva i volumi. L'opzione `down -v` li elimina, inclusi
database, allegati, configurazione, log, chiavi GPG e indici Splunk. Prima degli aggiornamenti
salvare database, volumi persistenti, `.env` e certificati.

## Blacklist AbuseIPDB

`abuseipdb_sync.py` aggiorna un feed esistente: non crea il feed iniziale.
Prima di usare il ciclo completo, configurare in MISP un feed con nome
`AbuseIPDB blacklist (confidence 100)`, provider `AbuseIPDB` e URL
`https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=100&limit=10000&plaintext`.
Il formato deve essere `freetext`, la sorgente `network`, con evento fisso,
`delta_merge` e `override_ids` abilitati, pubblicazione disabilitata e
distribuzione limitata alla propria organizzazione. Gli header devono essere
`Key: <valore di ABUSEIPDB_API_KEY>` e `Accept: text/plain`, su due righe.
Eseguire una prima importazione per associare un evento privato non pubblicato,
quindi disabilitare il feed. La chiave deve essere valorizzata anche in `.env`.

Nel laboratorio di riferimento, il 17 settembre 2026 sono stati importati
10.000 IP con `confidenceMinimum=100` e `limit=10000`. Gli ID seguenti sono
esempi locali e saranno diversi in una nuova installazione:

- [Evento 1](https://localhost:8443/events/view/1): 10.000 attributi `ip-dst`,
  evento visibile solo all'organizzazione locale e non pubblicato.
- [Feed 3](https://localhost:8443/feeds/view/3): `AbuseIPDB blacklist (confidence 100)`.
  Il feed è disabilitato tra le importazioni; `intel_sync.py` lo aggiorna ogni 24 ore.
- `to_ids=false`: gli attributi sono disponibili per analisi e correlazioni.

La chiave personale è nel file `.env` (`ABUSEIPDB_API_KEY`) e nell'header
di autenticazione del feed MISP. Cambiarla in `.env` da solo non modifica
la configurazione del feed già salvata in MISP.

Per un intervento manuale dalla UI, abilitare il feed nella lista **Feeds**, avviarne
il prelievo e attendere il completamento del job prima di disabilitarlo.
Il feed riusa lo stesso evento, deduplica gli IP e, con `delta_merge`,
elimina logicamente gli indicatori non più presenti nella nuova lista.

Fonte: [API blacklist AbuseIPDB](https://docs.abuseipdb.com/#blacklist-endpoint).

## GreyNoise

Nel laboratorio di riferimento, il 17 settembre 2026 sono stati importati
**10.000 IP malevoli** tramite GNQL, con la query
`last_seen:1d classification:malicious`. Gli ID seguenti sono esempi locali:

- [Evento 2](https://localhost:8443/events/view/2): attributi `ip-dst`,
  visibilità limitata all'organizzazione locale, non pubblicato, `to_ids=false`.
- [Feed 4](https://localhost:8443/feeds/view/4):
  `GreyNoise malicious IPs (last 24h, max 10000)`.
- La ricerca iniziale aveva 122.909 risultati: l'importazione è limitata
  ai primi 10.000 restituiti dal provider, non all'intera lista.

Per scaricare una nuova lista e aggiornare lo stesso evento, dalla cartella del repository:

```sh
python3 greynoise_sync.py
```

Lo script legge `GREYNOISE_API_KEY` da `.env`, controlla che GreyNoise abbia
applicato tutti i filtri e accetta soltanto IP pubblici classificati `malicious`.
La query seleziona gli IP attualmente classificati malevoli e osservati nelle
ultime 24 ore; il filtro distinto `last_seen_malicious` non è incluso nei
permessi verificati della chiave. Una lista vuota, non valida o una richiesta
fallita conserva la lista precedente.

Il feed nativo `freetext` legge
`/var/www/MISP/app/files/feeds/greynoise-malicious.txt` dal volume persistente
`misp_files`. Lo script sostituisce il file atomicamente, importa con
`delta_merge` e disabilita il feed al termine. `intel_sync.py` esegue questo
passaggio ogni 24 ore. Gli IP assenti dalla nuova lista vengono eliminati logicamente
dall'evento. Il prelievo dalla sola UI MISP rilegge il file già presente:
per contattare GreyNoise e scaricare dati nuovi usare lo script.

Nel laboratorio di riferimento, anche **GreyNoise Lookup 2.0** è configurato
e abilitato per l'arricchimento
degli attributi IPv4 `ip-src` e `ip-dst`. Un test sul servizio `misp-modules`
ha restituito un oggetto `greynoise-ip`. Aprire un attributo e scegliere
l'arricchimento GreyNoise; le interrogazioni CVE dipendono dai permessi del piano.

La chiave è conservata in `.env` (permessi 0600) e nella configurazione
persistente di MISP. Lo script aggiorna anche la copia della chiave in MISP,
preservando lo stato abilitato/disabilitato del modulo. In una nuova
installazione, abilitare l'arricchimento dalle impostazioni MISP se desiderato. Le impostazioni sono
`Plugin.Enrichment_greynoise_enabled` e `Plugin.Enrichment_greynoise_api_key`,
in **Server Settings & Maintenance → Plugin Settings → Enrichment**.
La versione installata non usa il vecchio parametro `api_type`.

`integrations/GreyNoiseSetupShell.php` viene caricato temporaneamente nel
container durante l'aggiornamento e rimosso al termine. La chiave passa via
stdin; il salvataggio delle impostazioni registra un audit con valore oscurato.
L'helper supporta la configurazione su file utilizzata da questo stack.

Riferimenti: [modulo ufficiale MISP](https://github.com/MISP/misp-modules/blob/main/misp_modules/modules/expansion/greynoise.py),
[integrazione GreyNoise](https://docs.greynoise.io/docs/integration-overview-misp),
[accesso ai feed](https://docs.greynoise.io/docs/using-greynoise-as-an-indicator-feed).

La configurazione è destinata alla topologia ufficiale corrente:
[Compose upstream](https://github.com/MISP/misp-docker/blob/master/docker-compose.yml).
Gli healthcheck gestiscono l'ordine iniziale di avvio; lo stato della pagina
di login va verificato dopo l'inizializzazione.
