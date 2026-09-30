"""Hook-level tests for the ShakerProxy addon using mitmproxy.test.taddons.

They need the pinned mitmproxy and are skipped elsewhere. Run them inside
the image, for example:

  docker build --file apps/mitmproxy/Dockerfile --tag shakerproxy-mitmproxy:test .
  docker run --rm -v "$PWD/apps/mitmproxy:/tests:ro" --entrypoint /usr/local/bin/python \
    shakerproxy-mitmproxy:test -m unittest discover -s /tests -p 'test_*.py'
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import pathlib
import tempfile
import time
import tracemalloc
import unittest
import zlib
from types import SimpleNamespace

try:
    from mitmproxy import certs, connection, tls
    from mitmproxy.proxy import context as proxy_context
    from mitmproxy.test import taddons, tflow

    from shakerproxy_addon import MAX_HTTP_BODY_PREVIEW_BYTES, ShakerProxyTLS
    from shakerproxy_policy import MAX_EVENT_BYTES

    MITMPROXY = True
except ImportError:  # pragma: no cover - exercised outside the image
    MITMPROXY = False

SELECTED = "device-0123456789abcdef0123456789abcdef"
DESKTOP = "device-dddddddddddddddddddddddddddddddd"
CATALOG = pathlib.Path(__file__).with_name("resolvers.json")


@unittest.skipUnless(MITMPROXY, "mitmproxy is not installed; run inside the shakerproxy-mitmproxy image")
class AddonHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.policy_path = self.root / "policy.json"
        self.write_policy()
        self.addon = ShakerProxyTLS()
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        self.tctx = stack.enter_context(taddons.context(self.addon))
        # A Master installs a root log handler bound to its event loop; remove
        # it before the loop closes so later tests can log.
        self.addCleanup(self.tctx.master._legacy_log_events.uninstall)
        self.tctx.configure(
            self.addon,
            shakerproxy_policy_path=str(self.policy_path),
            shakerproxy_bypass_path=str(self.root / "state" / "bypasses.json"),
            shakerproxy_catalog_path=str(CATALOG),
            shakerproxy_event_spool=str(self.root / "events"),
        )
        self.addCleanup(self.addon.done)

    def write_policy(self, **tls_overrides) -> None:
        tls_policy = {
            "mode": "selective",
            "selected_device_ids": [SELECTED],
            "auto_bypass_pinning": True,
            "pinning_threshold": 1,
            "mobile_clients": [],
        }
        tls_policy.update(tls_overrides)
        document = {
            "schema_version": 1,
            "revision": 5,
            "enabled": True,
            "encrypted_dns": {"mode": "observe"},
            "tls": tls_policy,
            "device_by_ip": {"10.77.0.23": SELECTED, "10.77.0.40": DESKTOP},
            "device_platforms": {DESKTOP: "windows"},
        }
        self.policy_path.write_text(json.dumps(document), encoding="utf-8")
        future = time.time() + len(json.dumps(document)) / 1000
        os.utime(self.policy_path, (future, future))

    def events(self, kind: str | None = None) -> list[dict]:
        assert self.addon.events is not None
        self.assertTrue(self.addon.events.flush(5))
        pending = self.root / "events" / "pending"
        result = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(pending.glob("evt_*.json"))]
        return [event for event in result if kind is None or event["kind"] == kind]

    def context(self, client_ip: str, server_ip: str, sni: str = "api.example.com"):
        client = connection.Client(peername=(client_ip, 50000), sockname=("10.77.0.1", 8085), timestamp_start=time.time(), sni=sni)
        ctx = proxy_context.Context(client, self.tctx.options)
        ctx.server.address = (server_ip, 443)
        ctx.server.peername = (server_ip, 443)
        ctx.server.sni = sni
        return ctx

    def hello(self, client_ip: str, server_ip: str, sni: str = "api.example.com"):
        data = tls.ClientHelloData(self.context(client_ip, server_ip, sni), SimpleNamespace(sni=sni))
        self.addon.tls_clienthello(data)
        return data

    def test_private_destinations_and_unselected_devices_pass_through(self):
        self.assertTrue(self.hello("10.77.0.23", "192.168.1.10").ignore_connection)
        self.assertFalse(self.hello("10.77.0.23", "93.184.216.34").ignore_connection)
        self.assertTrue(self.hello("10.77.0.99", "93.184.216.34").ignore_connection)
        reasons = [event["payload"]["reason"] for event in self.events("tls_passthrough")]
        self.assertEqual(reasons, ["private_destination", "device_not_selected"])
        self.assertTrue(all(event["payload"]["explanation"] for event in self.events("tls_passthrough")))

        self.write_policy(intercept_private_destinations=True)
        self.assertFalse(self.hello("10.77.0.23", "192.168.1.10").ignore_connection)

    def test_connections_from_outside_the_lab_are_refused(self):
        outside = connection.Client(peername=("203.0.113.9", 40000), sockname=("198.51.100.1", 8085), timestamp_start=time.time())
        self.addon.client_connected(outside)
        self.assertTrue(outside.error)
        inside = connection.Client(peername=("10.77.0.23", 40000), sockname=("10.77.0.1", 8085), timestamp_start=time.time())
        self.addon.client_connected(inside)
        self.assertFalse(inside.error)

    def test_upstream_certificate_failure_is_explained_and_bypassed_on_retry(self):
        ctx = self.context("10.77.0.23", "93.184.216.34", "selfsigned.example")
        ctx.server.error = "Certificate verify failed: self-signed certificate"
        self.addon.tls_failed_server(tls.TlsData(ctx.server, ctx))
        failed = self.events("tls_interception_failed")[-1]["payload"]
        self.assertEqual(failed["side"], "upstream")
        self.assertEqual(failed["reason"], "upstream_certificate_untrusted")
        self.assertIn("self-signed", failed["error"])
        self.assertTrue(failed["dynamic_bypass_added"] and failed["retry_required"])
        self.assertTrue(self.hello("10.77.0.23", "93.184.216.34", "selfsigned.example").ignore_connection)
        self.assertEqual(self.events("tls_passthrough")[-1]["payload"]["reason"], "upstream_certificate_bypass")

    def test_upstream_certificate_is_recorded_when_server_tls_completes(self):
        store = certs.CertStore.from_store(self.root / "ca", "test", 2048)
        certificate = store.get_cert("api.example.com", []).cert
        ctx = self.context("10.77.0.23", "93.184.216.34")
        ctx.server.certificate_list = [certificate]
        ctx.server.tls_version = "TLSv1.3"
        self.addon.tls_established_server(tls.TlsData(ctx.server, ctx))
        payload = self.events("tls_upstream_established")[-1]["payload"]
        self.assertEqual(payload["upstream_certificate_sha256"], certificate.fingerprint().hex())
        self.assertIn("api.example.com", payload["upstream_certificate_subject"])
        self.assertEqual(payload["upstream_tls_version"], "TLSv1.3")
        self.assertEqual(payload["device_id"], SELECTED)

    def test_desktop_devices_never_get_automatic_pinning_bypass(self):
        ctx = self.context("10.77.0.40", "93.184.216.34", "pinned.example")
        self.addon.tls_established_client(tls.TlsData(ctx.client, ctx))
        for _ in range(3):
            self.addon.tls_failed_client(tls.TlsData(ctx.client, ctx))
        failures = self.events("tls_interception_failed")
        self.assertEqual(len(failures), 3)
        self.assertFalse(any(event["payload"]["dynamic_bypass_added"] for event in failures))
        self.assertEqual(failures[-1]["payload"]["platform"], "")

    def test_flow_error_reports_message_and_scheme(self):
        flow = tflow.tflow(err=True)
        flow.client_conn.peername = ("10.77.0.23", 50000)
        flow.error.msg = "Connection refused"
        self.addon.error(flow)
        payload = self.events("http_flow_error")[-1]["payload"]
        self.assertEqual(payload["service"], "http")
        self.assertEqual(payload["reason"], "upstream_unreachable")
        self.assertEqual(payload["error"], "Connection refused")

    def test_plain_http_is_recorded_only_for_clients_in_scope(self):
        outside = tflow.tflow(resp=True)
        outside.client_conn.peername = ("10.77.0.99", 50000)
        outside.server_conn.peername = ("93.184.216.34", 80)
        self.addon.request(outside)
        self.addon.response(outside)
        self.assertEqual(self.events("http_request"), [])
        inside = tflow.tflow(resp=True)
        inside.client_conn.peername = ("10.77.0.23", 50000)
        inside.server_conn.peername = ("93.184.216.34", 80)
        self.addon.request(inside)
        self.addon.response(inside)
        self.assertEqual(len(self.events("http_request")), 1)
        self.assertEqual(self.events("http_response")[-1]["payload"]["service"], "http")

    def test_http_host_is_the_requested_name_not_the_server_ip(self):
        # Transparent mode: request.host is the server IP, so searching by
        # host name (http.host:api.github.com) found nothing.
        flow = tflow.tflow(resp=True)
        flow.client_conn.peername = ("10.77.0.23", 50000)
        flow.server_conn.peername = ("140.82.113.5", 443)
        flow.request.host = "140.82.113.5"
        flow.request.headers["Host"] = "api.github.com"
        self.addon.request(flow)
        self.addon.response(flow)
        for kind in ("http_request", "http_response"):
            self.assertEqual(self.events(kind)[-1]["payload"]["http_host"], "api.github.com", kind)

    def test_compressed_body_preview_uses_bounded_memory(self):
        compressor = zlib.compressobj(9, zlib.DEFLATED, 31)
        chunk = b"A" * (1024 * 1024)
        raw = b"".join(compressor.compress(chunk) for _ in range(64)) + compressor.flush()
        self.assertLess(len(raw), 512 * 1024)
        flow = tflow.tflow(resp=True)
        flow.request.scheme = "https"
        flow.client_conn.peername = ("10.77.0.23", 50000)
        flow.server_conn.peername = ("93.184.216.34", 443)
        flow.response.headers["content-type"] = "text/plain"
        flow.response.headers["content-encoding"] = "gzip"
        flow.response.raw_content = raw
        tracemalloc.start()
        self.addon.response(flow)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertLess(peak, 8 * 1024 * 1024, "decoding a 64 MiB gzip body must not allocate it")
        body = self.events("http_response")[-1]["payload"]["response_body"]
        self.assertTrue(body["decoded_preview"] and body["truncated"])
        self.assertEqual(body["preview_bytes"], MAX_HTTP_BODY_PREVIEW_BYTES)
        self.assertEqual(body["sha256"], hashlib.sha256(raw).hexdigest())

    def test_streamed_body_is_metadata_only(self):
        flow = tflow.tflow(resp=True)
        flow.request.scheme = "https"
        flow.client_conn.peername = ("10.77.0.23", 50000)
        flow.response.raw_content = None
        self.addon.response(flow)
        body = self.events("http_response")[-1]["payload"]["response_body"]
        self.assertTrue(body["streamed"])
        self.assertEqual(body["preview"], "")

    def test_large_utf8_response_event_is_written_within_bounds(self):
        flow = tflow.tflow(resp=True)
        flow.request.scheme = "https"
        flow.client_conn.peername = ("10.77.0.23", 50000)
        flow.response.headers["content-type"] = "text/plain; charset=utf-8"
        for index in range(100):
            flow.response.headers[f"x-cyrillic-{index}"] = "ж" * 300
        flow.response.raw_content = ("\U0001f600" * 20000).encode("utf-8")
        self.addon.response(flow)
        self.assertTrue(self.addon.events.flush(5))
        pending = sorted((self.root / "events" / "pending").glob("evt_*.json"))
        self.assertTrue(pending, "oversized event was dropped")
        self.assertLessEqual(max(path.stat().st_size for path in pending), MAX_EVENT_BYTES)

    def test_policy_errors_pass_through_and_are_reported_once(self):
        self.policy_path.write_text("{not json", encoding="utf-8")
        self.assertTrue(self.hello("10.77.0.23", "93.184.216.34").ignore_connection)
        self.assertTrue(self.hello("10.77.0.23", "93.184.216.34").ignore_connection)
        reports = self.events("tls_policy_unavailable")
        self.assertEqual(len(reports), 1)
        self.assertTrue(reports[0]["payload"]["explanation"])


if __name__ == "__main__":
    unittest.main()
