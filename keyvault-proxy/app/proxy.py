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
MASK = "*****"


class InvalidRequest(ValueError):
    pass


def redact(text, token):
    return text.replace(token, MASK) if token else text


def clean_headers(headers, token):
    cleaned = {}
    for name, value in headers:
        lowered = name.lower()
        if lowered in {"authorization", "proxy-authorization"}:
            cleaned[name] = f"Bearer {MASK}" if value.startswith("Bearer ") else MASK
        elif lowered in {"cookie", "set-cookie"}:
            cleaned[name] = MASK
        else:
            cleaned[name] = redact(value, token)
    return cleaned


def tls_details(sock):
    version_method = getattr(sock, "version", None)
    cipher_method = getattr(sock, "cipher", None)
    version = version_method() if version_method else None
    cipher = cipher_method() if cipher_method else None
    return {"version": version, "cipher": cipher[0] if cipher else None}


def persist_exchange(log_file, entry, token, key_response=None):
    """Persist redacted HTTP traffic before any response reaches the client."""
    log_path = Path(log_file)
    serialized = redact(json.dumps(entry, ensure_ascii=False), token)
    with WRITE_LOCK:
        with log_path.open("a") as stream:
            stream.write(serialized + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        if key_response is not None:
            response_dir = log_path.parent / "key-responses"
            response_dir.mkdir(exist_ok=True)
            redacted_response = redact(key_response.decode("utf-8", errors="replace"), token)
            try:
                pretty_response = json.dumps(json.loads(redacted_response), indent=2,
                                             ensure_ascii=False) + "\n"
            except json.JSONDecodeError:
                pretty_response = redacted_response
            archived = response_dir / f"{entry['request_id']}.json"
            archived.write_text(pretty_response)
            latest = log_path.parent / "latest-key-response.json"
            temporary = log_path.parent / f".{latest.name}.{entry['request_id']}.tmp"
            temporary.write_text(pretty_response)
            os.replace(temporary, latest)


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
                "client": {"ip": self.client_address[0], "tls": tls_details(self.connection)},
                "request": {"method": "GET", "http_version": self.request_version,
                            "path": redact(self.path, token),
                            "headers": clean_headers(self.headers.items(), token), "body": ""},
                "authorization_forwarded": False,
            }
            connection = None
            response_status = 502
            response_headers = []
            response_body = b""
            key_response = None
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
                entry["upstream"] = {"host": TARGET_HOST, "peer_ip": peer[0],
                    "tls_verified": True, "tls": tls_details(connection.sock)}
                connection.request("GET", TARGET_PATH, headers=headers)
                entry["authorization_forwarded"] = bool(auth)
                response = connection.getresponse()
                body = response.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise RuntimeError("Upstream response exceeded the 4 MiB limit")
                response_headers = response.getheaders()
                response_status = response.status
                response_body = body
                entry["response"] = {"status": response.status,
                    "headers": clean_headers(response_headers, token),
                    "body": redact(body.decode("utf-8", errors="replace"), token)}
                content_type = response.getheader("Content-Type", "").lower()
                if 200 <= response.status < 300 and "json" in content_type:
                    key_response = body
            except Exception as exc:
                status = 400 if isinstance(exc, InvalidRequest) else 502
                entry["error"] = redact(str(exc), token)
                entry["proxy_status"] = status
                response_status = status
                response_headers = [("Content-Type", "application/json")]
                response_body = json.dumps({
                    "error": "Local lab proxy rejected or could not forward this request"
                }).encode()
            finally:
                if connection:
                    connection.close()
                entry["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
                entry["persisted_before_client_response"] = True
                try:
                    persist_exchange(log_file, entry, token, key_response)
                except Exception as exc:
                    response_status = 502
                    response_headers = [("Content-Type", "application/json")]
                    response_body = json.dumps({
                        "error": "Local lab proxy could not persist the traffic record"
                    }).encode()
                    print(json.dumps({"request_id": request_id,
                          "logging_error": str(exc)}), flush=True)
                try:
                    self.send_response_only(response_status)
                    connection_tokens = next((value for name, value in response_headers
                                              if name.lower() == "connection"), "")
                    blocked_response = HOP | {
                        value.strip().lower() for value in connection_tokens.split(",")
                    }
                    for name, value in response_headers:
                        if name.lower() not in blocked_response:
                            self.send_header(name, value)
                    self.send_header("Content-Length", str(len(response_body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(response_body)
                except OSError:
                    pass
                print(json.dumps({"request_id": request_id,
                      "status": response_status,
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
