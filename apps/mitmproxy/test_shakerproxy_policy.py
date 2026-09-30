import json
import pathlib
import base64
import struct
import tempfile
import time
import unittest

from types import SimpleNamespace

from shakerproxy_policy import DynamicBypassStore, EventSpool, PolicyCache, ResolverCatalog, address_in_cidrs, extract_doh_question, host_matches, parse_dns_question


class ShakerProxyPolicyTests(unittest.TestCase):
    def test_host_and_cidr_matching(self):
        self.assertTrue(host_matches("*.example.com", "api.example.com"))
        self.assertFalse(host_matches("*.example.com", "example.com"))
        self.assertTrue(host_matches("api.example.com", "API.EXAMPLE.COM."))
        self.assertTrue(address_in_cidrs("192.0.2.9", ["192.0.2.0/24"]))
        self.assertFalse(address_in_cidrs("198.51.100.9", ["192.0.2.0/24"]))

    def test_policy_cache_rejects_missing_sections(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "policy.json"
            path.write_text('{"schema":1,"revision":1}', encoding="utf-8")
            with self.assertRaises(ValueError):
                PolicyCache(str(path)).load()

    def test_dynamic_bypass_is_client_and_host_scoped(self):
        with tempfile.TemporaryDirectory() as root:
            store = DynamicBypassStore(str(pathlib.Path(root) / "bypasses.json"))
            store.add("10.0.0.5", "pinned.example", 300, 16, "probable_pin")
            self.assertTrue(store.contains("10.0.0.5", "pinned.example"))
            self.assertFalse(store.contains("10.0.0.6", "pinned.example"))
            self.assertFalse(store.contains("10.0.0.5", "other.example"))
            self.assertEqual(store.count(), 1)

    def test_resolver_catalog_requires_host_and_doh_signal(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "resolvers.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "revision": "test",
                        "resolvers": [
                            {
                                "id": "example",
                                "provider": "Example DNS",
                                "hostnames": ["dns.example"],
                                "doh_paths": ["/dns-query"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            catalog = ResolverCatalog(str(path))
            self.assertIsNotNone(catalog.classify("dns.example", "/dns-query", "application/dns-message"))
            self.assertIsNone(catalog.classify("dns.example", "/ordinary-api", "application/json"))
            unknown = catalog.classify("unknown.example", "/custom", "application/dns-message")
            self.assertEqual(unknown["resolver_id"], "unknown")

    def test_doh_question_extraction_is_bounded_to_first_question(self):
        wire = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        wire += b"\x03www\x07example\x04test\x00" + struct.pack("!HH", 65, 1)
        self.assertEqual(parse_dns_question(wire), ("www.example.test", "HTTPS"))
        encoded = base64.urlsafe_b64encode(wire).decode("ascii").rstrip("=")
        request = SimpleNamespace(path=f"/dns-query?dns={encoded}", headers={}, raw_content=b"")
        self.assertEqual(extract_doh_question(request), ("www.example.test", "HTTPS"))
        malformed = SimpleNamespace(path="/dns-query?dns=%%%", headers={}, raw_content=b"")
        self.assertEqual(extract_doh_question(malformed), ("", ""))

    def test_policy_identifies_only_declared_mobile_clients(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "revision": 2,
                        "encrypted_dns": {"block_known_doh": True},
                        "tls_interception": {
                            "enabled": True,
                            "auto_bypass_pinned": True,
                            "auto_bypass_ttl_seconds": 3600,
                            "max_dynamic_bypasses": 64,
                            "mobile_clients": [{"cidr": "10.44.0.0/24", "platform": "ios"}],
                        },
                    }
                ),
                encoding="utf-8",
            )
            snapshot = PolicyCache(str(path)).load()
            self.assertEqual(snapshot.mobile_platform("10.44.0.15"), "ios")
            self.assertEqual(snapshot.mobile_platform("10.45.0.15"), "")

    def test_compiled_policy_contract_supports_selective_devices_and_bypass_rules(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "policy_id": "policy-1",
                        "revision": 7,
                        "digest": "a" * 64,
                        "enabled": True,
                        "encrypted_dns": {"mode": "block", "block_known_doh": True},
                        "tls": {
                            "mode": "selective",
                            "auto_bypass_pinning": True,
                            "pinning_threshold": 3,
                            "selected_device_ids": ["device-tv"],
                            "bypass_rules": [
                                {
                                    "id": "tv-pin",
                                    "enabled": True,
                                    "platform": "android-tv",
                                    "device_id": "device-tv",
                                    "match_type": "host-suffix",
                                    "pattern": "media.example.com",
                                    "reason": "pinned",
                                    "source": "manual",
                                }
                            ],
                        },
                        "resolver_hostnames": ["dns.example.com"],
                        "resolver_addresses": ["192.0.2.53"],
                        "device_by_ip": {"10.44.0.15": "device-tv"},
                        "device_platforms": {"device-tv": "android-tv"},
                    }
                ),
                encoding="utf-8",
            )
            snapshot = PolicyCache(str(path)).load()
            self.assertTrue(snapshot.enabled)
            self.assertEqual(snapshot.tls_mode, "selective")
            self.assertEqual(snapshot.client_identity("10.44.0.15"), ("device-tv", "android-tv"))
            self.assertIsNotNone(snapshot.bypass_rule("10.44.0.15", "video.media.example.com", "203.0.113.7"))
            self.assertIsNone(snapshot.bypass_rule("10.44.0.16", "video.media.example.com", "203.0.113.7"))

    def test_null_lists_from_the_gateway_are_empty(self):
        # Regression: the gateway wrote nil lists as null and every TLS
        # connection passed through undecrypted.
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "revision": 2,
                        "enabled": True,
                        "encrypted_dns": {"mode": "observe", "upstream_servers": []},
                        "tls": {
                            "mode": "selective",
                            "exclude_hosts": None,
                            "exclude_cidrs": None,
                            "mobile_clients": None,
                            "selected_device_ids": ["device-client"],
                            "bypass_rules": None,
                        },
                        "device_by_ip": {"172.31.47.197": "device-client"},
                        "device_platforms": {},
                    }
                ),
                encoding="utf-8",
            )
            snapshot = PolicyCache(str(path)).load()
            self.assertTrue(snapshot.enabled)
            self.assertEqual(snapshot.client_identity("172.31.47.197")[0], "device-client")

    def test_event_spool_promotes_only_canonical_device_identity(self):
        with tempfile.TemporaryDirectory() as root:
            spool = EventSpool(root, "test")
            device_id = "device-0123456789abcdef0123456789abcdef"
            event_id = spool.emit("tls_intercepted", {"device_id": device_id, "sni": "api.example.test"})
            event = json.loads((pathlib.Path(root) / "pending" / f"{event_id}.json").read_text(encoding="utf-8"))
            self.assertEqual(event["device_id"], device_id)
            invalid_id = spool.emit("tls_intercepted", {"device_id": "device-tv", "sni": "api.example.test"})
            invalid = json.loads((pathlib.Path(root) / "pending" / f"{invalid_id}.json").read_text(encoding="utf-8"))
            self.assertNotIn("device_id", invalid)


if __name__ == "__main__":
    unittest.main()
