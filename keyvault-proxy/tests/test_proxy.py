import http.client
import importlib.util
import json
from pathlib import Path
import ssl
import tempfile
import threading
import types
import unittest

spec = importlib.util.spec_from_file_location("proxy", Path(__file__).resolve().parents[1] / "app/proxy.py")
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


class FakeResponse:
    def __init__(self, status=200, body=b'{"key":{"kty":"RSA"}}', headers=None):
        self.status, self.body = status, body
        self.headers = headers or [("Content-Type", "application/json")]

    def read(self, limit):
        return self.body[:limit]

    def getheaders(self):
        return self.headers

    def getheader(self, name, default=None):
        return next((v for k, v in self.headers if k.lower() == name.lower()), default)


class FakeUpstream:
    def __init__(self, response=None, error=None):
        self.sock = types.SimpleNamespace(getpeername=lambda: ("203.0.113.11", 443))
        self.response = response or FakeResponse()
        self.error = error
        self.requests = []

    def connect(self):
        if self.error:
            raise self.error

    def request(self, method, path, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        return self.response

    def close(self):
        pass


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.log = Path(self.directory.name) / "traffic.jsonl"
        self.upstream = FakeUpstream()
        self.server = proxy.ThreadingHTTPServer(("127.0.0.1", 0),
            proxy.make_handler(self.log, lambda: self.upstream))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.directory.cleanup()

    def request(self, path=None, headers=None):
        client = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        client.request("GET", path or proxy.TARGET_PATH,
            headers={"Host": proxy.TARGET_HOST, **(headers or {})})
        response = client.getresponse()
        body = response.read()
        result = response.status, dict(response.getheaders()), body
        client.close()
        return result

    def entries(self):
        # Joining request threads ensures their finally blocks have written the log.
        self.server.server_close()
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_same_token_and_exact_response_with_redacted_disk_log(self):
        token = "test-bearer-secret-do-not-log"
        body = ('{"echo":"' + token + '"}').encode()
        self.upstream.response = FakeResponse(200, body, [("Content-Type", "application/json"),
            ("Set-Cookie", "private-cookie"), ("X-Test", token)])
        status, headers, actual = self.request(headers={"Authorization": "Bearer " + token,
                                                       "Cookie": "client-private-cookie"})
        self.assertEqual((status, actual), (200, body))
        self.assertEqual(self.upstream.requests[0][2]["Authorization"], "Bearer " + token)
        entries = self.entries()
        self.assertTrue(entries[0]["authorization_forwarded"])
        logged = self.log.read_text()
        self.assertNotIn(token, logged)
        self.assertNotIn("private-cookie", logged)
        self.assertNotIn("client-private-cookie", logged)
        latest = self.log.parent / "latest-key-response.json"
        self.assertTrue(latest.is_file())
        self.assertNotIn(token, latest.read_text())
        self.assertEqual(json.loads(latest.read_text()), {"echo": "*****"})
        self.assertEqual(entries[0]["request"]["headers"]["Authorization"], "Bearer *****")
        self.assertEqual(entries[0]["request"]["headers"]["Cookie"], "*****")

    def test_full_key_response_is_persisted_before_client_response_headers(self):
        key = {"key": {"kid": "https://example/keys/labkey/version", "kty": "RSA",
                       "n": "full-public-modulus", "e": "AQAB"},
               "attributes": {"enabled": True}}
        body = json.dumps(key).encode()
        self.upstream.response = FakeResponse(200, body)
        client = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        client.request("GET", proxy.TARGET_PATH, headers={"Host": proxy.TARGET_HOST})
        response = client.getresponse()
        latest = self.log.parent / "latest-key-response.json"
        archives = list((self.log.parent / "key-responses").glob("*.json"))
        self.assertTrue(latest.is_file())
        self.assertEqual(len(archives), 1)
        self.assertEqual(json.loads(latest.read_text()), key)
        self.assertEqual(json.loads(archives[0].read_text()), key)
        self.assertTrue(self.entries()[0]["persisted_before_client_response"])
        self.assertEqual(response.read(), body)
        client.close()

    def test_auth_challenge_reaches_client_without_an_added_token(self):
        challenge = 'Bearer authorization="https://login.microsoftonline.com/example", resource="https://vault.azure.net"'
        self.upstream.response = FakeResponse(401, b'{"error":"unauthorized"}', [("WWW-Authenticate", challenge)])
        status, headers, body = self.request()
        self.assertEqual(status, 401)
        self.assertEqual(headers["WWW-Authenticate"], challenge)
        self.assertNotIn("Authorization", self.upstream.requests[0][2])

    def test_wrong_host_rejected_without_forwarding(self):
        status, _, _ = self.request(headers={"Host": "other.vault.azure.net"})
        self.assertEqual(status, 400)
        self.assertFalse(self.upstream.requests)

    def test_other_key_or_query_rejected_without_forwarding(self):
        status, _, _ = self.request(path="/keys/another-key?api-version=7.4")
        self.assertEqual(status, 400)
        self.assertFalse(self.upstream.requests)

    def test_upstream_tls_failure_returns_502_without_forwarding(self):
        self.upstream.error = ssl.SSLCertVerificationError("certificate verify failed")
        status, _, _ = self.request(headers={"Authorization": "Bearer secret"})
        self.assertEqual(status, 502)
        self.assertFalse(self.upstream.requests)
        self.assertFalse(self.entries()[0]["authorization_forwarded"])

    def test_redirect_is_returned_without_following(self):
        self.upstream.response = FakeResponse(302, b"", [("Location", "https://example.invalid/")])
        status, headers, _ = self.request()
        self.assertEqual(status, 302)
        self.assertEqual(headers["Location"], "https://example.invalid/")
        self.assertEqual(len(self.upstream.requests), 1)

    def test_oversized_response_rejected(self):
        self.upstream.response = FakeResponse(body=b"x" * (proxy.MAX_BODY + 1))
        self.assertEqual(self.request()[0], 502)


if __name__ == "__main__":
    unittest.main()
