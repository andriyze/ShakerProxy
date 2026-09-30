from __future__ import annotations

import fnmatch
import base64
import ipaddress
import itertools
import json
import logging
import os
import pathlib
import queue
import re
import tempfile
import threading
import time
import struct
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# The Go writers allow 2048 bypass rules and 8192 device mappings; indented
# JSON of that size is well above the old 256 KiB bound, which made every
# ClientHello fall back to passthrough.
MAX_POLICY_BYTES = 2 * 1024 * 1024
MAX_STATE_BYTES = 2 * 1024 * 1024
# Upper bound for one spooled event file, including its trailing newline.
# The forwarder and ingestd accept exactly this much.
MAX_EVENT_BYTES = 192 * 1024
DEVICE_ID_PATTERN = re.compile(r"^device-[a-f0-9]{32}$")
MAX_EVENT_FILES = 50_000
MAX_EVENT_SPOOL_BYTES = 512 * 1024 * 1024
# Only these platforms can receive automatic pinning bypasses. Desktop and
# unknown clients never do.
MOBILE_PLATFORMS = frozenset({"android", "android-tv", "ios", "tvos"})
# Clients the proxy accepts connections from even without published lab
# prefixes: loopback, RFC 1918, CGNAT, link-local and ULA.
LOCAL_CLIENT_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
        "fe80::/10",
    )
)
PRIVATE_DESTINATION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
        "fe80::/10",
    )
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def rfc3339(value: datetime | None = None) -> str:
    current = value or utc_now()
    return current.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _read_json_file(path: pathlib.Path, maximum: int) -> dict[str, Any]:
    stat = path.stat()
    if not path.is_file() or stat.st_size <= 0 or stat.st_size > maximum:
        raise ValueError(f"{path} is not a bounded regular JSON file")
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
        if handle.read(1):
            raise ValueError(f"{path} contains trailing data")
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _atomic_json(path: pathlib.Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    if len(encoded) > MAX_STATE_BYTES:
        raise ValueError("state document exceeds maximum size")
    descriptor, temporary = tempfile.mkstemp(prefix=".shakerproxy-", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def normalize_host(value: str | None) -> str:
    return (value or "").strip().rstrip(".").lower()


def host_matches(pattern: str, host: str) -> bool:
    pattern = normalize_host(pattern)
    host = normalize_host(host)
    if not pattern or not host:
        return False
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and host != suffix[1:]
    return fnmatch.fnmatchcase(host, pattern)


def normalize_address(address: Any) -> str:
    """Canonical text form; IPv4-mapped IPv6 peers become plain IPv4."""
    text = str(address or "").strip()
    try:
        parsed = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return text
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return str(parsed.ipv4_mapped)
    return str(parsed)


def client_address_allowed(address: str | None, lab_sources: tuple[Any, ...] = ()) -> bool:
    try:
        candidate = ipaddress.ip_address(normalize_address(address))
    except ValueError:
        return False
    for network in LOCAL_CLIENT_NETWORKS + tuple(lab_sources):
        if candidate.version == network.version and candidate in network:
            return True
    return False


def is_private_destination(address: str | None) -> bool:
    """RFC 1918, CGNAT, link-local and ULA destinations (LAN and IoT backends)."""
    try:
        candidate = ipaddress.ip_address(normalize_address(address))
    except ValueError:
        return False
    return any(candidate in network for network in PRIVATE_DESTINATION_NETWORKS if candidate.version == network.version)


def address_in_cidrs(address: str | None, cidrs: list[str]) -> bool:
    if not address:
        return False
    try:
        candidate = ipaddress.ip_address(address)
    except ValueError:
        return False
    for raw in cidrs:
        try:
            if candidate in ipaddress.ip_network(raw, strict=True):
                return True
        except ValueError:
            continue
    return False


@dataclass(frozen=True)
class BypassRule:
    rule_id: str
    platform: str
    device_id: str
    match_type: str
    pattern: str
    reason: str
    source: str
    expires_at: float | None

    def matches(self, device_id: str, platform: str, hostname: str, destination_ip: str, now: float) -> bool:
        if self.expires_at is not None and self.expires_at <= now:
            return False
        if self.device_id and self.device_id != device_id:
            return False
        if self.platform not in {"any", "unknown", platform}:
            return False
        if self.match_type == "exact-host":
            return bool(hostname) and hostname == self.pattern
        if self.match_type == "host-suffix":
            return bool(hostname) and (hostname == self.pattern or hostname.endswith("." + self.pattern))
        try:
            address = ipaddress.ip_address(destination_ip)
            if self.match_type == "ip":
                return address == ipaddress.ip_address(self.pattern)
            if self.match_type == "cidr":
                return address in ipaddress.ip_network(self.pattern, strict=False)
        except ValueError:
            return False
        return False


@dataclass(frozen=True)
class PolicySnapshot:
    enabled: bool
    tls_mode: str
    exclude_hosts: tuple[str, ...]
    exclude_cidrs: tuple[str, ...]
    auto_bypass_pinned: bool
    pinning_threshold: int
    bypass_ttl_seconds: int
    max_dynamic_bypasses: int
    block_known_doh: bool
    revision: int
    mobile_clients: tuple[tuple[str, str], ...]
    selected_device_ids: frozenset[str]
    bypass_rules: tuple[BypassRule, ...]
    device_by_ip: dict[str, str]
    device_platforms: dict[str, str]
    intercept_private_destinations: bool = False
    intercept_http: bool = False
    lab_sources: tuple[Any, ...] = ()

    def client_identity(self, address: str) -> tuple[str, str]:
        """Return (device ID, mobile platform or "").

        A known device keeps its ID; its platform comes from the device map
        when that names a mobile platform, otherwise from the configured
        mobile client CIDRs. Desktop and unknown platforms return "", so they
        never receive automatic pinning bypasses.
        """
        address = normalize_address(address)
        device_id = self.device_by_ip.get(address, "")
        platform = self.device_platforms.get(device_id, "") if device_id else ""
        if platform in MOBILE_PLATFORMS:
            return device_id, platform
        try:
            candidate = ipaddress.ip_address(address)
        except ValueError:
            return device_id, ""
        for raw_network, cidr_platform in self.mobile_clients:
            try:
                if cidr_platform in MOBILE_PLATFORMS and candidate in ipaddress.ip_network(raw_network, strict=True):
                    return device_id, cidr_platform
            except ValueError:
                continue
        return device_id, ""

    def client_allowed(self, address: str) -> bool:
        """Only lab (and local) clients may use the transparent proxy."""
        return client_address_allowed(address, self.lab_sources)

    def in_scope(self, device_id: str) -> bool:
        """Whether this client's traffic may be decrypted or recorded."""
        if not self.enabled:
            return False
        return self.tls_mode != "selective" or device_id in self.selected_device_ids

    def mobile_platform(self, address: str) -> str:
        return self.client_identity(address)[1]

    def bypass_rule(self, client_ip: str, hostname: str, destination_ip: str, now: float | None = None) -> BypassRule | None:
        device_id, platform = self.client_identity(client_ip)
        current = now or time.time()
        for rule in self.bypass_rules:
            if rule.matches(device_id, platform or "unknown", hostname, destination_ip, current):
                return rule
        return None


class PolicyCache:
    def __init__(self, path: str):
        self.path = pathlib.Path(path)
        self._signature: tuple[int, int] | None = None
        self._snapshot = PolicySnapshot(
            enabled=False,
            tls_mode="off",
            exclude_hosts=(),
            exclude_cidrs=(),
            auto_bypass_pinned=False,
            pinning_threshold=1,
            bypass_ttl_seconds=86400,
            max_dynamic_bypasses=1024,
            block_known_doh=False,
            revision=0,
            mobile_clients=(),
            selected_device_ids=frozenset(),
            bypass_rules=(),
            device_by_ip={},
            device_platforms={},
        )
        self._lock = threading.Lock()

    def load(self) -> PolicySnapshot:
        with self._lock:
            stat = self.path.stat()
            signature = (stat.st_mtime_ns, stat.st_size)
            if signature == self._signature:
                return self._snapshot
            value = _read_json_file(self.path, MAX_POLICY_BYTES)
            compiled = value.get("schema_version") == 1
            legacy = value.get("schema") == 1
            if not (compiled or legacy) or not isinstance(value.get("revision"), int):
                raise ValueError("traffic policy schema or revision is invalid")
            tls_policy = value.get("tls") if compiled else value.get("tls_interception")
            dns_policy = value.get("encrypted_dns")
            if not isinstance(tls_policy, dict) or not isinstance(dns_policy, dict):
                raise ValueError("traffic policy sections are invalid")
            exclude_hosts = tuple(sorted({normalize_host(str(item)) for item in (tls_policy.get("exclude_hosts") or []) if normalize_host(str(item))}))
            exclude_cidrs = tuple(sorted({str(item).strip() for item in (tls_policy.get("exclude_cidrs") or []) if str(item).strip()}))
            mobile_clients = tuple(
                sorted(
                    {
                        (str(item.get("cidr", "")).strip(), str(item.get("platform", "")).strip().lower())
                        for item in (tls_policy.get("mobile_clients") or [])
                        if isinstance(item, dict) and str(item.get("cidr", "")).strip() and str(item.get("platform", "")).strip()
                    }
                )
            )
            bypass_rules = tuple(_parse_bypass_rule(item) for item in (tls_policy.get("bypass_rules") or []) if isinstance(item, dict) and item.get("enabled", False))
            try:
                device_by_ip = {
                    str(ipaddress.ip_address(str(address))): str(device_id)
                    for address, device_id in (value.get("device_by_ip") or {}).items()
                    if str(device_id).strip()
                }
            except ValueError as exc:
                raise ValueError("traffic policy device address is invalid") from exc
            device_platforms = {
                str(device_id): str(platform).strip().lower()
                for device_id, platform in (value.get("device_platforms") or {}).items()
                if str(device_id).strip() and str(platform).strip()
            }
            tls_mode = str(tls_policy.get("mode", "all" if tls_policy.get("enabled", False) else "off")).strip().lower()
            if tls_mode not in {"off", "all", "selective"}:
                raise ValueError("traffic policy TLS mode is invalid")
            selected_device_ids = frozenset(str(item).strip() for item in (tls_policy.get("selected_device_ids") or []) if str(item).strip())
            if tls_mode == "selective" and not selected_device_ids:
                raise ValueError("selective TLS policy has no selected devices")
            snapshot = PolicySnapshot(
                enabled=bool(value.get("enabled", True)) and (tls_mode != "off" if compiled else bool(tls_policy.get("enabled", False))),
                tls_mode=tls_mode,
                exclude_hosts=exclude_hosts,
                exclude_cidrs=exclude_cidrs,
                auto_bypass_pinned=bool(tls_policy.get("auto_bypass_pinning", tls_policy.get("auto_bypass_pinned", False))),
                pinning_threshold=max(1, min(int(tls_policy.get("pinning_threshold", 1)), 20)),
                bypass_ttl_seconds=max(300, min(int(tls_policy.get("auto_bypass_ttl_seconds", 86400)), 30 * 86400)),
                max_dynamic_bypasses=max(16, min(int(tls_policy.get("max_dynamic_bypasses", 1024)), 10_000)),
                block_known_doh=bool(dns_policy.get("block_known_doh", False)),
                revision=int(value["revision"]),
                mobile_clients=mobile_clients,
                selected_device_ids=selected_device_ids,
                bypass_rules=bypass_rules,
                device_by_ip=device_by_ip,
                device_platforms=device_platforms,
                intercept_private_destinations=bool(tls_policy.get("intercept_private_destinations", False)),
                intercept_http=bool(tls_policy.get("intercept_http", False)),
                lab_sources=_parse_lab_sources(value.get("lab_sources")),
            )
            self._signature = signature
            self._snapshot = snapshot
            return snapshot


def _parse_lab_sources(value: Any) -> tuple[Any, ...]:
    if not isinstance(value, list) or len(value) > 16:
        return ()
    result = []
    for raw in value:
        try:
            network = ipaddress.ip_network(str(raw), strict=False)
        except ValueError:
            continue
        if network.prefixlen >= 8:
            result.append(network)
    return tuple(result)


def _parse_bypass_rule(item: dict[str, Any]) -> BypassRule:
    expires_at = None
    raw_expiry = item.get("expires_at")
    if raw_expiry:
        expires_at = datetime.fromisoformat(str(raw_expiry).replace("Z", "+00:00")).timestamp()
    return BypassRule(
        rule_id=str(item.get("id", "")),
        platform=str(item.get("platform", "any")).strip().lower(),
        device_id=str(item.get("device_id", "")).strip(),
        match_type=str(item.get("match_type", "")).strip().lower(),
        pattern=str(item.get("pattern", "")).strip().lower().rstrip("."),
        reason=str(item.get("reason", ""))[:256],
        source=str(item.get("source", ""))[:128],
        expires_at=expires_at,
    )


class DynamicBypassStore:
    def __init__(self, path: str):
        self.path = pathlib.Path(path)
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}
        self._loaded = False

    @staticmethod
    def key(client_ip: str, host: str) -> str:
        return f"{client_ip}|{normalize_host(host)}"

    def contains(self, client_ip: str, host: str, now: float | None = None) -> bool:
        current = now or time.time()
        with self._lock:
            self._load_locked()
            changed = self._prune_locked(current)
            entry = self._entries.get(self.key(client_ip, host))
            if changed:
                self._save_locked()
            return bool(entry and float(entry.get("expires_at", 0)) > current)

    def add(self, client_ip: str, host: str, ttl_seconds: int, maximum: int, reason: str) -> None:
        current = time.time()
        with self._lock:
            self._load_locked()
            self._prune_locked(current)
            key = self.key(client_ip, host)
            previous = self._entries.get(key, {})
            self._entries[key] = {
                "client_ip": client_ip,
                "host": normalize_host(host),
                "created_at": previous.get("created_at", current),
                "last_failure_at": current,
                "expires_at": current + ttl_seconds,
                "failures": int(previous.get("failures", 0)) + 1,
                "reason": reason,
            }
            if len(self._entries) > maximum:
                oldest = sorted(self._entries, key=lambda item: float(self._entries[item].get("last_failure_at", 0)))
                for item in oldest[: len(self._entries) - maximum]:
                    self._entries.pop(item, None)
            self._save_locked()

    def count(self) -> int:
        with self._lock:
            self._load_locked()
            if self._prune_locked(time.time()):
                self._save_locked()
            return len(self._entries)

    def _load_locked(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            value = _read_json_file(self.path, MAX_STATE_BYTES)
        except FileNotFoundError:
            return
        if value.get("schema") != 1 or not isinstance(value.get("entries"), dict):
            raise ValueError("dynamic TLS bypass state is invalid")
        self._entries = value["entries"]

    def _prune_locked(self, current: float) -> bool:
        before = len(self._entries)
        self._entries = {
            key: entry
            for key, entry in self._entries.items()
            if isinstance(entry, dict) and float(entry.get("expires_at", 0)) > current
        }
        return len(self._entries) != before

    def _save_locked(self) -> None:
        _atomic_json(self.path, {"schema": 1, "entries": self._entries})


class ResolverCatalog:
    def __init__(self, path: str):
        value = _read_json_file(pathlib.Path(path), MAX_POLICY_BYTES)
        if value.get("schema") != 1 or not isinstance(value.get("resolvers"), list):
            raise ValueError("resolver catalog is invalid")
        self.revision = str(value.get("revision", ""))
        self.resolvers = value["resolvers"]

    def classify(self, host: str, path: str, content_type: str) -> dict[str, Any] | None:
        normalized_host = normalize_host(host)
        normalized_path = path or "/"
        semantic_dns = content_type.split(";", 1)[0].strip().lower() == "application/dns-message"
        for resolver in self.resolvers:
            if not isinstance(resolver, dict):
                continue
            host_match = any(host_matches(str(pattern), normalized_host) for pattern in resolver.get("hostnames", []))
            path_match = any(normalized_path == candidate or (candidate == "/" and normalized_path.startswith("/")) for candidate in resolver.get("doh_paths", []))
            if host_match and (path_match or semantic_dns):
                return {
                    "resolver_id": str(resolver.get("id", "")),
                    "provider": str(resolver.get("provider", "")),
                    "catalog_revision": self.revision,
                    "confidence": 100 if path_match and semantic_dns else 95,
                }
        if semantic_dns:
            return {"resolver_id": "unknown", "provider": "Unknown DoH endpoint", "catalog_revision": self.revision, "confidence": 90}
        return None


def extract_doh_question(request: Any) -> tuple[str, str]:
    """Extract only the first DNS question; never retain a DoH request body."""
    try:
        path = str(getattr(request, "path", "") or "")
        parameters = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        if parameters.get("name"):
            return normalize_host(parameters["name"][0]), str(parameters.get("type", [""])[0]).upper()
        wire = b""
        if parameters.get("dns"):
            encoded = parameters["dns"][0]
            if len(encoded) > 87384:
                return "", ""
            wire = base64.urlsafe_b64decode((encoded + "=" * (-len(encoded) % 4)).encode("ascii"))
        else:
            content_type = str(getattr(request, "headers", {}).get("content-type", "")).split(";", 1)[0].strip().lower()
            if content_type == "application/dns-message":
                wire = bytes(getattr(request, "raw_content", b"") or b"")
        return parse_dns_question(wire)
    except (ValueError, UnicodeError, TypeError, struct.error):
        return "", ""


def parse_dns_question(wire: bytes) -> tuple[str, str]:
    if len(wire) < 12 or len(wire) > 65535 or struct.unpack("!H", wire[4:6])[0] < 1:
        return "", ""
    labels: list[str] = []
    offset = 12
    final_offset = offset
    visited: set[int] = set()
    jumped = False
    for _ in range(128):
        if offset >= len(wire) or offset in visited:
            return "", ""
        visited.add(offset)
        length = wire[offset]
        if length == 0:
            if not jumped:
                final_offset = offset + 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(wire):
                return "", ""
            if not jumped:
                final_offset = offset + 2
            offset = ((length & 0x3F) << 8) | wire[offset + 1]
            jumped = True
            continue
        if length > 63 or offset + 1 + length > len(wire):
            return "", ""
        labels.append(wire[offset + 1 : offset + 1 + length].decode("ascii"))
        offset += 1 + length
        if not jumped:
            final_offset = offset
    else:
        return "", ""
    if final_offset + 4 > len(wire):
        return "", ""
    query_type = struct.unpack("!H", wire[final_offset : final_offset + 2])[0]
    names = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
    return normalize_host(".".join(labels)), names.get(query_type, str(query_type))


_EVENT_SEQUENCE = itertools.count()


def new_event_id(now_ns: int | None = None) -> str:
    """Time- and sequence-prefixed so the forwarder's name order is chronological."""
    milliseconds = (now_ns if now_ns is not None else time.time_ns()) // 1_000_000
    sequence = next(_EVENT_SEQUENCE) & 0xFFFFFF
    return f"evt_{milliseconds:012x}{sequence:06x}_{uuid.uuid4().hex}"


def _shrink_text(value: str, excess: int) -> str:
    encoded = value.encode("utf-8")
    keep = max(0, len(encoded) - excess - 16)
    return encoded[:keep].decode("utf-8", errors="ignore")


def _fit_envelope(envelope: dict[str, Any]) -> bytes:
    """Encode compactly, shrinking content previews instead of dropping the event.

    Non-ASCII text stays UTF-8 (ensure_ascii escaping tripled its size). When
    an event is still too large, body previews shrink first, then header
    snapshots, then the URL; every reduction is flagged in the payload.
    """
    limit = MAX_EVENT_BYTES - 1  # the file ends with a newline

    def encode() -> bytes:
        return json.dumps(envelope, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")

    encoded = encode()
    if len(encoded) <= limit:
        return encoded
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("mitmproxy metadata event exceeds maximum size")
    for key in ("response_body", "request_body"):
        body = payload.get(key)
        if isinstance(body, dict) and isinstance(body.get("preview"), str) and body["preview"]:
            excess = len(encoded) - limit
            preview = body["preview"]
            if body.get("preview_encoding") == "base64":
                keep = max(0, len(preview) - excess - 16)
                preview = preview[: keep - keep % 4]
                body["preview_bytes"] = len(base64.b64decode(preview)) if preview else 0
            else:
                preview = _shrink_text(preview, excess)
                body["preview_bytes"] = len(preview.encode("utf-8"))
            body["preview"] = preview
            body["truncated"] = True
            body["preview_shrunk_to_fit_event"] = True
            encoded = encode()
            if len(encoded) <= limit:
                return encoded
    for key in ("response_headers", "request_headers"):
        headers = payload.get(key)
        if isinstance(headers, dict) and isinstance(headers.get("items"), list):
            while headers["items"] and len(encoded) > limit:
                headers["items"].pop()
                headers["truncated"] = True
                encoded = encode()
            if len(encoded) <= limit:
                return encoded
    if isinstance(payload.get("http_url"), str):
        payload["http_url"] = _shrink_text(payload["http_url"], len(encoded) - limit)
        payload["http_url_truncated"] = True
        encoded = encode()
        if len(encoded) <= limit:
            return encoded
    for key in ("request_body", "response_body", "request_headers", "response_headers"):
        payload.pop(key, None)
    payload["content_omitted"] = "event_size_limit"
    encoded = encode()
    if len(encoded) > limit:
        raise ValueError("mitmproxy metadata event exceeds maximum size")
    return encoded


class EventSpool:
    """Write one normalized event per file for mitm-event-forwarderd.

    Files are written atomically (temporary file + rename) but not fsynced:
    losing the last few events on a power cut is acceptable, a disk flush per
    event on the proxy's hot path is not. Spool size is tracked in memory and
    re-synchronised with the directory periodically, because the forwarder
    deletes files behind our back.
    """

    RESCAN_EVERY_EVENTS = 1024
    RESCAN_EVERY_SECONDS = 60.0

    def __init__(self, directory: str, source_version: str):
        self.directory = pathlib.Path(directory)
        self.pending = self.directory / "pending"
        self.source_version = source_version
        self._lock = threading.Lock()
        self._ready = False
        self._files = 0
        self._bytes = 0
        self._since_scan = 0
        self._scanned_at: float | None = None

    def build(self, kind: str, payload: dict[str, Any], confidence: int = 100, flow_id: str = "", occurred_at: datetime | None = None) -> dict[str, Any]:
        envelope = {
            "schema": 1,
            "event_id": new_event_id(),
            "source": "MITMPROXY",
            "kind": kind,
            "occurred_at": rfc3339(occurred_at),
            "source_version": self.source_version,
            "parser_version": "shakerproxy-addon-1.1.0",
            "confidence": max(0, min(int(confidence), 100)),
            "payload": payload,
        }
        if flow_id:
            envelope["flow_id"] = "flow_" + "".join(character for character in flow_id if character.isalnum() or character in "_-")[:96]
        device_id = payload.get("device_id")
        if isinstance(device_id, str) and DEVICE_ID_PATTERN.fullmatch(device_id):
            envelope["device_id"] = device_id
        return envelope

    def emit(self, kind: str, payload: dict[str, Any], confidence: int = 100, flow_id: str = "", occurred_at: datetime | None = None) -> str:
        return self.write(self.build(kind, payload, confidence, flow_id, occurred_at))

    def write(self, envelope: dict[str, Any]) -> str:
        encoded = _fit_envelope(envelope) + b"\n"
        with self._lock:
            if not self._ready:
                self.pending.mkdir(parents=True, exist_ok=True, mode=0o700)
                self._ready = True
            now = time.monotonic()
            if self._scanned_at is None or self._since_scan >= self.RESCAN_EVERY_EVENTS or now - self._scanned_at >= self.RESCAN_EVERY_SECONDS:
                self._rescan_locked(now)
            if self._files >= MAX_EVENT_FILES or self._bytes + len(encoded) >= MAX_EVENT_SPOOL_BYTES:
                self._rescan_locked(now)
                if self._files >= MAX_EVENT_FILES or self._bytes + len(encoded) >= MAX_EVENT_SPOOL_BYTES:
                    self._prune_locked(len(encoded))
            destination = self.pending / f"{envelope['event_id']}.json"
            descriptor, temporary = tempfile.mkstemp(prefix=".event-", dir=self.pending)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb", closefd=True) as handle:
                    handle.write(encoded)
                os.replace(temporary, destination)
            finally:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
            self._files += 1
            self._bytes += len(encoded)
            self._since_scan += 1
        return envelope["event_id"]

    def _rescan_locked(self, now: float) -> None:
        files = 0
        total = 0
        with os.scandir(self.pending) as entries:
            for entry in entries:
                if entry.name.startswith("evt_") and entry.name.endswith(".json"):
                    try:
                        total += entry.stat(follow_symlinks=False).st_size
                        files += 1
                    except FileNotFoundError:
                        continue
        self._files, self._bytes = files, total
        self._since_scan = 0
        self._scanned_at = now

    def _prune_locked(self, incoming: int = 0) -> None:
        """Drop the oldest spooled events (names are time-ordered) down to a
        low-water mark, so a full spool is scanned once per batch of events
        rather than once per event."""
        file_mark = max(0, int(MAX_EVENT_FILES * 0.9) - 1)
        byte_mark = int(MAX_EVENT_SPOOL_BYTES * 0.9)
        with os.scandir(self.pending) as entries:
            names = sorted(entry.name for entry in entries if entry.name.startswith("evt_") and entry.name.endswith(".json"))
        for name in names:
            if self._files <= file_mark and self._bytes + incoming <= byte_mark:
                break
            path = self.pending / name
            try:
                size = path.stat().st_size
                path.unlink()
            except FileNotFoundError:
                continue
            self._files -= 1
            self._bytes -= size


class AsyncEventSpool:
    """Keep event file I/O off mitmproxy's event loop.

    Hooks enqueue a built envelope; one writer thread encodes and writes it.
    When the bounded queue is full the event is dropped and counted rather
    than blocking the proxy.
    """

    def __init__(self, spool: EventSpool, capacity: int = 10_000, capacity_bytes: int = 64 * 1024 * 1024):
        self.spool = spool
        self.dropped = 0
        self.capacity_bytes = capacity_bytes
        self._pending_bytes = 0
        self._bytes_lock = threading.Lock()
        self._queue: queue.Queue[tuple[dict[str, Any], int] | None] = queue.Queue(maxsize=capacity)
        self._thread = threading.Thread(target=self._run, name="shakerproxy-event-spool", daemon=True)
        self._thread.start()

    def emit(self, kind: str, payload: dict[str, Any], confidence: int = 100, flow_id: str = "") -> str:
        envelope = self.spool.build(kind, payload, confidence, flow_id, utc_now())
        size = _estimate_size(payload)
        with self._bytes_lock:
            accepted = self._pending_bytes + size <= self.capacity_bytes
            if accepted:
                self._pending_bytes += size
        if accepted:
            try:
                self._queue.put_nowait((envelope, size))
            except queue.Full:
                accepted = False
                with self._bytes_lock:
                    self._pending_bytes -= size
        if not accepted:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 1000 == 0:
                logging.warning("ShakerProxy event spool queue is full; %d event(s) dropped", self.dropped)
        return envelope["event_id"]

    def flush(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.005)
        return self._queue.unfinished_tasks == 0

    def close(self, timeout: float = 5.0) -> None:
        self.flush(timeout)
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            return
        self._thread.join(timeout)

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                envelope, size = item
                with self._bytes_lock:
                    self._pending_bytes -= size
                self.spool.write(envelope)
            except Exception as exc:  # observability must never stop the writer
                logging.warning("ShakerProxy event spool write failed: %s", exc)
            finally:
                self._queue.task_done()


def _estimate_size(value: Any, depth: int = 0) -> int:
    """Cheap upper-bound-ish size of an event payload, for queue accounting."""
    if isinstance(value, str):
        return len(value) * 2 + 8
    if isinstance(value, (bytes, bytearray)):
        return len(value) + 8
    if depth >= 6:
        return 64
    if isinstance(value, dict):
        return 64 + sum(len(str(key)) + _estimate_size(item, depth + 1) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return 64 + sum(_estimate_size(item, depth + 1) for item in value)
    return 16
