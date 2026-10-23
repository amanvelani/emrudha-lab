#!/usr/bin/env python3
"""Refresh the Azure CLI token without printing it, then start the two-container lab."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", action="store_true", help="TLS and unauthenticated forwarding only; no Azure token")
    parser.add_argument("--watch", action="store_true", help="Repeat SDK reads every 60 seconds instead of a single read")
    args = parser.parse_args()
    os.chdir(HERE)
    os.umask(0o077)
    if not Path(".env").exists():
        raise SystemExit("Run python3 setup.py first.")
    network_ids = subprocess.check_output(["docker", "--context", "colima", "network", "ls", "-q"], text=True).split()
    if network_ids:
        networks = json.loads(subprocess.check_output(["docker", "--context", "colima", "network", "inspect", *network_ids]))
        for net in networks:
            if net.get("Labels", {}).get("com.docker.compose.project") == "lab-keyvault-proxy":
                continue
            for config in net.get("IPAM", {}).get("Config") or []:
                subnet = config.get("Subnet")
                if subnet and ":" not in subnet and ipaddress.ip_network(subnet).overlaps(ipaddress.ip_network("172.30.67.0/24")):
                    raise SystemExit(f"Lab subnet overlaps existing Docker network {net['Name']}; change compose.yaml first.")
    if not args.probe:
        # Keep the credential out of command arguments, environment variables, and stdout.
        result = subprocess.run(["az", "account", "get-access-token", "--resource", "https://vault.azure.net",
                                 "--output", "json"], capture_output=True, text=True)
        if result.returncode:
            print("Azure CLI token acquisition failed. Check az login/account selection.", file=sys.stderr)
            return result.returncode
        token = json.loads(result.stdout)
        if not token.get("accessToken") or "expires_on" not in token:
            raise SystemExit("Azure CLI did not return accessToken and expires_on.")
        Path("secrets").mkdir(exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix="token-", dir="secrets")
        with os.fdopen(fd, "w") as stream:
            json.dump({"accessToken": token["accessToken"], "expires_on": token["expires_on"]}, stream)
        os.replace(temporary, "secrets/token.json")
        print("Refreshed protected token file using the current Azure CLI login.")
    env = os.environ.copy()
    env["TLS_PROBE_ONLY"] = "true" if args.probe else "false"
    env["RUN_ONCE"] = "false" if args.watch else "true"
    command = ["docker", "--context", "colima", "compose"]
    subprocess.run([*command, "up", "-d", "--build", "server"], env=env, check=True)
    subprocess.run([*command, "up", "-d", "--build", "--force-recreate", "service"], env=env, check=True)
    if not args.watch:
        container = subprocess.check_output([*command, "ps", "-aq", "service"], env=env, text=True).strip()
        exit_code = subprocess.check_output(["docker", "--context", "colima", "wait", container], text=True).strip()
        subprocess.run([*command, "logs", "--no-log-prefix", "service"], env=env, check=True)
        return int(exit_code)
    print("Client is reading every 60 seconds. Re-run this command to refresh its token when needed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
