#!/usr/bin/env python3
"""Run the lab as an explained, step-by-step terminal walkthrough."""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys


HERE = Path(__file__).resolve().parent
CA_CERTIFICATE = (
    HERE.parent
    / "ca/intermediate/CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL.pem"
)
TOKEN_PATTERN = re.compile(
    r"(?i)(Bearer\s+)(?!\*{5})(?!authorization=)[A-Za-z0-9._~+/=-]+"
)


class Terminal:
    def __init__(self, pause, dry_run):
        self.pause_enabled = pause and sys.stdin.isatty()
        self.dry_run = dry_run
        self.color = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    def style(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def heading(self, number, title, explanation):
        bar = "=" * 78
        print(f"\n{self.style('1;36', bar)}")
        print(self.style("1;36", f"Step {number}: {title}"))
        print(self.style("1;36", bar))
        print(explanation)
        if self.pause_enabled:
            input(self.style("2", "\nPress Enter to continue..."))

    def command(self, args, *, check=True, capture=False):
        print(self.style("1;33", f"\n$ {shlex.join(str(arg) for arg in args)}"))
        if self.dry_run:
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.run(
            [str(arg) for arg in args],
            cwd=HERE,
            check=check,
            text=capture,
            capture_output=capture,
        )

    def data(self, title, value):
        print(self.style("1;32", f"\n{title}"))
        print(redact(value.rstrip()))


def redact(value):
    return TOKEN_PATTERN.sub(r"\1*****", value)


def require_commands(names):
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise SystemExit("Missing required command(s): " + ", ".join(missing))


def show_last_json_line(terminal, path, title):
    if not path.is_file():
        print(f"\n{title}: no file was written.")
        return
    lines = [line for line in path.read_text().splitlines() if line.strip()]
    if not lines:
        print(f"\n{title}: the file is empty.")
        return
    try:
        formatted = json.dumps(json.loads(redact(lines[-1])), indent=2)
    except json.JSONDecodeError:
        formatted = redact(lines[-1])
    terminal.data(title, formatted)


def show_json_file(terminal, path, title):
    if not path.is_file():
        print(f"\n{title}: no file was written.")
        return
    value = redact(path.read_text())
    try:
        value = json.dumps(json.loads(value), indent=2)
    except json.JSONDecodeError:
        pass
    terminal.data(title, value)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--probe", action="store_true",
        help="perform only the credential-free TLS and 401 challenge test",
    )
    parser.add_argument("--no-pause", action="store_true", help="do not pause between steps")
    parser.add_argument("--dry-run", action="store_true", help="show the walkthrough without executing commands")
    args = parser.parse_args()
    terminal = Terminal(not args.no_pause, args.dry_run)
    os.chdir(HERE)
    started_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    mode = "credential-free probe" if args.probe else "authenticated Key Vault read"
    print(terminal.style("1;35", "Key Vault TLS inspection lab"))
    print(f"Mode: {mode}")
    print("Authorization values displayed by this walkthrough are always masked as Bearer *****.")

    terminal.heading(
        1,
        "Check local tools and start Colima",
        "The lab needs Python, OpenSSL, Docker, and Colima. Authenticated mode also "
        "uses the current Azure CLI login.",
    )
    required = ["openssl", "docker", "colima"]
    if not args.probe:
        required.append("az")
    if not args.dry_run:
        require_commands(required)
    status = terminal.command(["colima", "status"], check=False, capture=True)
    if not args.dry_run and status.returncode != 0:
        terminal.command(["colima", "start"])
    else:
        print("Colima is running." if not args.dry_run else "Colima would be checked and started if needed.")

    terminal.heading(
        2,
        "Inspect the checked-in intermediate CA",
        "The proxy leaf will be signed by the published eMudhra intermediate pair. "
        "Only certificate metadata is printed; private-key bytes are never displayed.",
    )
    terminal.command([
        "openssl", "x509", "-in", CA_CERTIFICATE, "-noout", "-subject", "-issuer",
        "-serial", "-dates", "-fingerprint", "-sha256",
    ])

    terminal.heading(
        3,
        "Generate the exact-host leaf certificate",
        "setup.py validates the CA pair, generates a seven-day certificate for "
        "labkeyvault1022.vault.azure.net, writes the full chain, and prepares local "
        "configuration. It does not modify the host or container trust stores.",
    )
    terminal.command([sys.executable, HERE / "setup.py"])

    terminal.heading(
        4,
        "Inspect the generated server identity",
        "The client requires the requested vault hostname in Subject Alternative Name. "
        "This output also shows the issuer, validity window, and public fingerprint.",
    )
    certificate_details = terminal.command([
        "openssl", "x509", "-in", HERE / "tls/server.cert.pem", "-text", "-noout",
    ], capture=True)
    if not args.dry_run:
        interesting = []
        keep_next = False
        for line in certificate_details.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith(("Subject:", "Issuer:", "Not Before:", "Not After :")):
                interesting.append(stripped)
            if "X509v3 Subject Alternative Name" in line:
                interesting.append(stripped)
                keep_next = True
            elif keep_next:
                interesting.append(stripped)
                keep_next = False
        fingerprint = terminal.command([
            "openssl", "x509", "-in", HERE / "tls/server.cert.pem", "-noout",
            "-fingerprint", "-sha256",
        ], capture=True)
        interesting.append(fingerprint.stdout.strip())
        terminal.data("Generated leaf certificate", "\n".join(interesting))

    terminal.heading(
        5,
        "Review the two TLS connections",
        "Inside the service container, only the vault hostname resolves to the proxy. "
        "The SDK creates TLS connection 1 to the proxy. The proxy decrypts HTTP, then "
        "creates a separate verified TLS connection 2 to the real Azure endpoint.",
    )
    print("\n  SDK service -- TLS 1 / local leaf --> proxy -- TLS 2 / Azure leaf --> Key Vault")
    print("  labkeyvault1022.vault.azure.net resolves to 172.30.67.2 only in the SDK container.")

    terminal.heading(
        6,
        "Build the containers and make the request",
        "The server starts first. The SDK then performs either an unauthenticated probe "
        "or an authenticated GetKeyAsync call. In authenticated mode, run.py obtains a "
        "short-lived token from Azure CLI without printing it.",
    )
    run_command = [sys.executable, HERE / "run.py", "--skip-setup"]
    if args.probe:
        run_command.append("--probe")
    run_result = terminal.command(run_command, check=False)

    terminal.heading(
        7,
        "Show container-side activity",
        "These are the server and SDK container logs for the request. The proxy's "
        "persistent traffic record shown next contains the detailed HTTP exchange.",
    )
    terminal.command([
        "docker", "--context", "colima", "compose", "logs", "--no-log-prefix",
        "--since", started_at, "server", "service",
    ], check=False)

    terminal.heading(
        8,
        "Show the captured HTTP exchange",
        "The latest proxy record includes the full request and upstream response. "
        "Authorization is masked. Authenticated mode also prints the full public-key "
        "JSON that the proxy saved before returning it to the SDK.",
    )
    if args.dry_run:
        print("The latest redacted traffic record and public-key JSON would be displayed here.")
    else:
        show_last_json_line(
            terminal, HERE / "logs/proxy/traffic.jsonl", "Latest redacted proxy exchange",
        )
        if not args.probe:
            show_json_file(
                terminal, HERE / "logs/proxy/latest-key-response.json",
                "Full Key Vault public-key response",
            )
            show_json_file(
                terminal, HERE / "logs/client/response.json",
                "JSON received by the SDK client",
            )

    print(terminal.style("1;35", "\nWalkthrough complete."))
    print("For a continuous live view: docker --context colima compose logs -f server service")
    return run_result.returncode


if __name__ == "__main__":
    sys.exit(main())
