#!/usr/bin/env python3
"""Prepara credenziali e TLS locali conservando i valori già configurati."""

import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parent
    if not shutil.which("openssl"):
        raise SystemExit("OpenSSL non trovato: installarlo prima di continuare.")
    os.umask(0o077)

    env_path = root / ".env"
    if not env_path.exists():
        secret_names = {
            "ADMIN_PASSWORD", "MYSQL_PASSWORD", "MYSQL_ROOT_PASSWORD",
            "REDIS_PASSWORD", "GPG_PASSPHRASE", "ENCRYPTION_KEY", "SPLUNK_PASSWORD",
        }
        lines = []
        for line in (root / ".env.example").read_text().splitlines():
            name, separator, value = line.partition("=")
            if name in secret_names and separator and not value:
                value = secrets.token_hex(32)
                if name in {"ADMIN_PASSWORD", "SPLUNK_PASSWORD"}:
                    value += "Aa1!"
                line = f"{name}={value}"
            lines.append(line)
        with env_path.open("x") as stream:
            stream.write("\n".join(lines) + "\n")
        print("Creato .env con password casuali; permessi 0600.")
    else:
        print(".env già presente: valori configurati conservati.")

    # Aggiorna anche un'installazione MISP preesistente con il nuovo segreto.
    # Le credenziali valorizzate e i flag di accettazione restano invariati.
    lines = env_path.read_text().splitlines()
    password_lines = [i for i, line in enumerate(lines)
                      if line.partition("=")[0].strip() == "SPLUNK_PASSWORD"]
    if len(password_lines) > 1:
        raise SystemExit("SPLUNK_PASSWORD compare più volte in .env: mantenere una sola voce.")
    if not password_lines or not lines[password_lines[0]].partition("=")[2].strip().strip("\"'"):
        entry = "SPLUNK_PASSWORD=" + secrets.token_hex(32) + "Aa1!"
        if password_lines:
            lines[password_lines[0]] = entry
        else:
            lines += ["", "# Password iniziale di Splunk Enterprise (utente admin).", entry]
        env_path.write_text("\n".join(lines) + "\n")
        env_path.chmod(0o600)
        print("Aggiunta password casuale Splunk in .env; credenziali MISP conservate.")

    ssl_dir = root / "ssl"
    ssl_dir.mkdir(mode=0o700, exist_ok=True)
    cert_path, key_path = ssl_dir / "cert.pem", ssl_dir / "key.pem"
    if cert_path.exists() or key_path.exists():
        if not (cert_path.is_file() and key_path.is_file()):
            raise SystemExit("TLS incompleto: servono sia ssl/cert.pem sia ssl/key.pem.")
        print("Certificato e chiave già presenti: mantenuti senza modifiche.")
    else:
        # Directory privata sull'host; i singoli file sono montati in Nginx
        # e devono essere leggibili dal suo utente non privilegiato (UID 101).
        ssl_dir.chmod(0o700)
        with tempfile.TemporaryDirectory(dir=ssl_dir) as temporary:
            temp_dir = Path(temporary)
            subprocess.run([
                "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:3072",
                "-sha256", "-days", "365", "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,DNS:misp-nginx,IP:127.0.0.1,IP:::1",
                "-keyout", str(temp_dir / "key.pem"),
                "-out", str(temp_dir / "cert.pem"),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            for name in ("cert.pem", "key.pem"):
                (temp_dir / name).chmod(0o644)
                (temp_dir / name).rename(ssl_dir / name)
        print("Creato certificato autofirmato per localhost; directory ssl privata.")
    print("Configurazione pronta. Per l'avvio seguire README.md.")
    print("Accesso: https://localhost:8443 — credenziali nel file .env.")
    print("Splunk: http://localhost:8000 — richiede accettazione dei termini in .env.")


if __name__ == "__main__":
    main()
