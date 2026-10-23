#!/usr/bin/env python3
"""Generate this lab's TLS certificate, configuration, and output directories."""

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


def certificate_public_key(path):
    public_pem = run(
        "openssl", "x509", "-in", str(path), "-pubkey", "-noout",
        capture_output=True,
    ).stdout
    return run(
        "openssl", "pkey", "-pubin", "-outform", "DER",
        input=public_pem, capture_output=True,
    ).stdout


def private_public_key(path):
    return run(
        "openssl", "pkey", "-in", str(path), "-pubout", "-outform", "DER",
        capture_output=True,
    ).stdout


def generate_tls():
    ca_certificate = Path(str(CA_STEM) + ".pem")
    ca_key = Path(str(CA_STEM) + ".key")
    if not ca_certificate.is_file() or not ca_key.is_file():
        raise SystemExit("The checked-in intermediate certificate/key pair was not found.")

    ca_public = certificate_public_key(ca_certificate)
    if ca_public != private_public_key(ca_key):
        raise SystemExit("Intermediate certificate and private key do not match.")

    config = Path("tls/server.cnf")
    private_key = Path("tls/server.key.pem")
    request = Path("tls/server.csr.pem")
    certificate = Path("tls/server.cert.pem")
    fullchain = Path("tls/server.fullchain.pem")
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

    if not private_key.exists():
        run("openssl", "genrsa", "-out", str(private_key), "3072")
    run(
        "openssl", "req", "-new", "-sha256", "-key", str(private_key),
        "-config", str(config), "-out", str(request),
    )
    run(
        "openssl", "x509", "-req", "-sha256", "-days", "7",
        "-in", str(request), "-CA", str(ca_certificate), "-CAkey", str(ca_key),
        "-set_serial", "0x" + secrets.token_hex(16), "-extfile", str(config),
        "-extensions", "server_cert", "-out", str(certificate),
    )
    if certificate_public_key(certificate) != private_public_key(private_key):
        raise SystemExit("Generated certificate and private key do not match.")
    fullchain.write_bytes(certificate.read_bytes() + ca_certificate.read_bytes())
    return hashlib.sha256(ca_public).hexdigest()


def main():
    os.umask(0o077)
    os.chdir(HERE)
    for directory in ["tls", "secrets", "logs/client", "logs/proxy"]:
        Path(directory).mkdir(parents=True, exist_ok=True)

    intermediate_spki = generate_tls()
    base = os.environ.get("CLIENT_BASE", BASE)
    Path(".env").write_text(
        f"CLIENT_BASE={base}\nLOCAL_UID={os.getuid()}\nLOCAL_GID={os.getgid()}\n"
    )
    Path("logs/image-selection.json").write_text(json.dumps({
        "requested_cutoff": "2026-10-16",
        "selected_image": base,
        "image_created": (
            "2026-10-13T01:41:15.414157451Z" if base == BASE else "not inspected"
        ),
        "historical_tag_snapshot_proven": False,
        "note": (
            "Pinned pre-cutoff 8.0.31 ARM64 image."
            if base == BASE
            else "User-supplied image override; inspect its provenance separately."
        ),
        "intermediate_spki_sha256": intermediate_spki,
        "leaf_hostname": HOST,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }, indent=2) + "\n")
    print("Prepared exact-host leaf, intermediate chain, and pinned client image.")
    print("No trust store was modified.")


if __name__ == "__main__":
    main()
