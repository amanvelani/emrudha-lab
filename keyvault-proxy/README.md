# Key Vault TLS inspection lab

This Compose project has two containers in Colima:

```text
.NET 8 service (Azure Key Vault SDK)
    https://labkeyvault1022.vault.azure.net
           | client-only hostname mapping to 172.30.67.2
           v
Local HTTPS server / proxy
           | public DNS, Azure hostname/SNI, verified TLS, same bearer token
           v
Azure Key Vault -> proxy -> SDK service
```

The only supported operation is GET for key `labkey`, version
`3858b94e860441a495683a7738aef277`, API version `7.4`. This retrieves the key's
public portion. No key or vault is modified. The proxy is not published to host ports.

## Run

```bash
cd /Users/aman/git/lab/keyvault-proxy

# Only needed if Colima is stopped.
colima start

# Generate a seven-day leaf for the exact vault hostname using the existing
# intermediate pair; write local .env and output directories. No trust is installed.
python3 setup.py

# Optional: verify the existing image trust and forwarding without credentials.
python3 run.py --probe

# Refresh a token from your current Azure CLI login and make one SDK GetKeyAsync call.
python3 run.py

# Inspect container state and the saved request/response logs.
docker --context colima compose ps -a
cat logs/proxy/traffic.jsonl
cat logs/client/events.jsonl
cat logs/client/response.json
```

The normal client completes and exits after one read. The proxy remains running.
`python3 run.py --watch` keeps the client running and reads once per minute. Tokens
are not automatically refreshed; rerun that command before the CLI token expires.

```bash
# Stop and remove the two containers and their networks. Host logs remain.
docker --context colima compose down
```

## What is trusted

The client uses the stock runtime image trust store. The server sends its leaf
certificate and `EM DV TLS CA - G3B` intermediate. The observed chain terminates at
the image's existing `AAA Certificate Services` root. There is no trust-store
installation and no callback that accepts certificate errors: the logging callback
returns true only for `SslPolicyErrors.None`.

The server uses Python's default system certificate validation for its outgoing
connection to Azure. Its own DNS has no vault hostname override. The client gets a
Compose `extra_hosts` entry; this changes name resolution only inside that container.
The client network is internal, and only the proxy also has an egress network.

This is evidence about default .NET/Linux validation in this pinned image, not a
test of browser distrust lists or explicitly enabled online revocation checking.

## Image version

The runtime is pinned to this ARM64 image:

```text
mcr.microsoft.com/dotnet/aspnet@sha256:86b0047e3dbc676dc36e588f569c8dbb52ac6bf6d68a4a7afe676a2239c55cb5
.NET/ASP.NET 8.0.31; created 2026-10-13T01:41:15.414157451Z
```

The requested October 16 moving-tag snapshot was not established. This is a
pre-cutoff image. At setup, `8.0-azurelinux3.0` and `8.0.32-azurelinux3.0` pointed
to an image built October 22. `logs/image-selection.json` records the selection.
If you have the exact historical digest, set `CLIENT_BASE` when running `setup.py`;
then rebuild through `run.py`. No package manager or CA update runs in the final
client image. The build stage uses the .NET 8 SDK; the client package is
`Azure.Security.KeyVault.Keys` 4.10.2.

## Files and credential handling

| File | Contents |
| --- | --- |
| `logs/proxy/traffic.jsonl` | Request and response headers, response body, status, verified upstream peer IP and timing; authentication/cookie values redacted |
| `logs/client/events.jsonl` | Resolved addresses, platform certificate-validation results, SDK result or error |
| `logs/client/response.json` | Latest successful public-key JSON response |
| `secrets/token.json` | Short-lived token from Azure CLI, mode 0600; mounted only into the client |
| `tls/server.key.pem` | Proxy leaf private key, mounted only into the server |
| `tls/server.fullchain.pem` | Exact-host leaf plus intermediate certificate |

The Azure CLI account directory and the CA private key are not mounted into either
container. The token is not placed in process arguments or environment variables.
The proxy copies the Authorization header unchanged to the fixed Azure endpoint;
its filesystem logs redact it. Redirects are not automatically followed. Token,
TLS, and log directories are excluded from Docker build contexts and Git.

The existing intermediate files and the earlier `vault.azure.net` leaf are left
in place. `setup.py` writes separate leaf material under this project's `tls/`.

## Validation

```bash
python3 -m unittest discover -s tests -v
```

Seven tests cover identical-token forwarding and response preservation, log
redaction, authentication challenges, wrong-host and wrong-key rejection,
upstream TLS failures, redirect handling, and the response-size limit.

The live credential-free probe returned Azure's 401. The authenticated SDK read
returned 200, and the client JSON matched the proxy's captured response. Current
token scans found no bearer token in the log files.

Sources: [GetKeyAsync](https://learn.microsoft.com/en-us/dotnet/api/azure.security.keyvault.keys.keyclient.getkeyasync?view=azure-dotnet),
[Azure Key Vault Get Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key/get-key?view=rest-keyvault-keys-2025-07-01),
[Microsoft Azure Linux .NET images](https://github.com/dotnet/dotnet-docker/blob/main/documentation/azurelinux.md),
[Docker Compose networking](https://docs.docker.com/compose/how-tos/networking/).
