"""A fixed-destination, GET-only TLS inspection proxy for this local lab."""
import datetime
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TARGET_HOST = "labkeyvault1022.vault.azure.net"
TARGET_PATH = "/keys/labkey/3858b94e860441a495683a7738aef277?api-version=7.4"
MAX_BODY = 4 * 1024 * 1024
SENSITIVE = {"authorization", "proxy-authorization", "cookie", "set-cookie"}
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
       "te", "trailer", "transfer-encoding", "upgrade", "content-length"}
WRITE_LOCK = threading.Lock()


class InvalidRequest(ValueError):
    pass


def redact(text, token):
    return text.replace(token, "[REDACTED]") if token else text


def clean_headers(headers, token):
    return {name: "[REDACTED]" if name.lower() in SENSITIVE else redact(value, token)
            for name, value in headers}


def make_handler(log_file, upstream_factory=None):
    # The injected factory is used by unit tests only; production always verifies TLS.
    if upstream_factory is None:
        def upstream_factory():
            return http.client.HTTPSConnection(TARGET_HOST, 443, timeout=30,
                                               context=ssl.create_default_context())

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(40)

        def log_message(self, *args):
            pass  # Avoid HTTP server access logs that might contain sensitive input.

        def do_GET(self):
            started = time.monotonic()
            request_id = uuid.uuid4().hex
            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth.startswith("Bearer ") else auth
            entry = {
                "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "request_id": request_id,
                "request": {"method": "GET", "path": redact(self.path, token),
                            "headers": clean_headers(self.headers.items(), token)},
                "authorization_forwarded": False,
            }
            connection = None
            try:
                if self.headers.get("Host", "").lower() not in {TARGET_HOST, TARGET_HOST + ":443"}:
                    raise InvalidRequest("Only the configured vault hostname is allowed")
                if self.path != TARGET_PATH:
                    raise InvalidRequest("Only the configured key version and api-version are allowed")
                if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
                    raise InvalidRequest("GET request bodies are not supported")
                if len(self.headers.get_all("Authorization", [])) > 1:
                    raise InvalidRequest("Duplicate Authorization headers are not allowed")
                if auth and not auth.startswith("Bearer "):
                    raise InvalidRequest("Only Bearer authentication is supported")
                blocked = HOP | {x.strip().lower() for x in self.headers.get("Connection", "").split(",")}
                headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in blocked | {"host", "accept-encoding", "authorization"}}
                headers["Host"] = TARGET_HOST
                headers["Accept-Encoding"] = "identity"
                # Pass exactly the received Authorization value to this one Azure host.
                if auth:
                    headers["Authorization"] = auth
                connection = upstream_factory()
                connection.connect()
                peer = connection.sock.getpeername()
                if peer[0] == self.server.server_address[0] or peer[0] == socket.gethostbyname(socket.gethostname()):
                    raise RuntimeError("Upstream resolved back to the proxy")
                entry["upstream"] = {"host": TARGET_HOST, "peer_ip": peer[0], "tls_verified": True}
                connection.request("GET", TARGET_PATH, headers=headers)
                entry["authorization_forwarded"] = bool(auth)
                response = connection.getresponse()
                body = response.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise RuntimeError("Upstream response exceeded the 4 MiB limit")
                response_headers = response.getheaders()
                entry["response"] = {"status": response.status,
                    "headers": clean_headers(response_headers, token),
                    "body": redact(body.decode("utf-8", errors="replace"), token)}
                self.send_response_only(response.status)
                blocked_response = HOP | {x.strip().lower() for x in response.getheader("Connection", "").split(",")}
                for name, value in response_headers:
                    if name.lower() not in blocked_response:
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                status = 400 if isinstance(exc, InvalidRequest) else 502
                entry["error"] = redact(str(exc), token)
                entry["proxy_status"] = status
                self.close_connection = True
                try:
                    body = json.dumps({"error": "Local lab proxy rejected or could not forward this request"}).encode()
                    self.send_response_only(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass
            finally:
                if connection:
                    connection.close()
                entry["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
                with WRITE_LOCK:
                    with Path(log_file).open("a") as stream:
                        stream.write(redact(json.dumps(entry), token) + "\n")
                print(json.dumps({"request_id": request_id,
                      "status": entry.get("response", {}).get("status", entry.get("proxy_status")),
                      "authorization_forwarded": entry["authorization_forwarded"]}), flush=True)
                self.close_connection = True

    return Handler


def main():
    os.umask(0o077)
    log_dir = Path(os.environ.get("LOG_DIR", "/logs/proxy"))
    log_dir.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("0.0.0.0", 443), make_handler(log_dir / "traffic.jsonl"))
    server.daemon_threads = True
    server.socket.settimeout(10)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/tls/server.fullchain.pem", "/tls/server.key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(json.dumps({"event": "ready", "target": TARGET_HOST, "port": 443}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
