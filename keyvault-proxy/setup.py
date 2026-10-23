#!/usr/bin/env python3
"""Prepare only this lab's leaf certificate and configuration; do not install trust."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess

HERE = Path(__file__).resolve().parent
HOST = "labkeyvault1022.vault.azure.net"
CA_STEM = HERE.parent / "ca/intermediate/CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL"
# ARM64 image built 2026-10-13, before the requested October 16 cutoff.
# This is NOT claimed to be an archived snapshot of the moving tag on October 16.
BASE = "mcr.microsoft.com/dotnet/aspnet@sha256:86b0047e3dbc676dc36e588f569c8dbb52ac6bf6d68a4a7afe676a2239c55cb5"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    os.umask(0o077)
    os.chdir(HERE)
    for directory in ["tls", "secrets", "logs/client", "logs/proxy"]:
        Path(directory).mkdir(parents=True, exist_ok=True)
    cert = Path(str(CA_STEM) + ".pem")
    key = Path(str(CA_STEM) + ".key")
    if not cert.is_file() or not key.is_file():
        raise SystemExit("The configured intermediate certificate/key pair was not found.")
    cert_public = run("openssl", "x509", "-in", str(cert), "-pubkey", "-noout", capture_output=True).stdout
    cert_public = run("openssl", "pkey", "-pubin", "-outform", "DER", input=cert_public, capture_output=True).stdout
    key_public = run("openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER", capture_output=True).stdout
    if cert_public != key_public:
        raise SystemExit("Intermediate certificate and private key do not match.")
    config = Path("tls/server.cnf")
    config.write_text(f"""[req]
distinguished_name = dn
prompt = no
[dn]
CN = {HOST}
[server_cert]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:{HOST}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
""")
    if not Path("tls/server.key.pem").exists():
        run("openssl", "genrsa", "-out", "tls/server.key.pem", "3072")
    run("openssl", "req", "-new", "-sha256", "-key", "tls/server.key.pem",
        "-config", str(config), "-out", "tls/server.csr.pem")
    run("openssl", "x509", "-req", "-sha256", "-days", "7", "-in", "tls/server.csr.pem",
        "-CA", str(cert), "-CAkey", str(key), "-set_serial", "0x" + secrets.token_hex(16),
        "-extfile", str(config), "-extensions", "server_cert", "-out", "tls/server.cert.pem")
    Path("tls/server.fullchain.pem").write_bytes(Path("tls/server.cert.pem").read_bytes() + cert.read_bytes())
    base = os.environ.get("CLIENT_BASE", BASE)
    Path(".env").write_text(f"CLIENT_BASE={base}\nLOCAL_UID={os.getuid()}\nLOCAL_GID={os.getgid()}\n")
    Path("logs/image-selection.json").write_text(json.dumps({
        "requested_cutoff": "2026-10-16", "selected_image": base,
        "image_created": "2026-10-13T01:41:15.414157451Z" if base == BASE else "not inspected",
        "historical_tag_snapshot_proven": False,
        "note": "Pinned pre-cutoff 8.0.31 ARM64 image." if base == BASE else "User-supplied image override; inspect its provenance separately.",
        "intermediate_spki_sha256": hashlib.sha256(cert_public).hexdigest(),
        "leaf_hostname": HOST, "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }, indent=2) + "\n")
    print("Prepared exact-host leaf, intermediate chain, and pinned client image. No trust store was modified.")


if __name__ == "__main__":
    main()
