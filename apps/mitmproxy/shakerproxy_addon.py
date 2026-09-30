from __future__ import annotations

import base64
import hashlib
import logging
import time
import zlib
from typing import Any

from mitmproxy import ctx, http, tls
from mitmproxy.addonmanager import Loader

from shakerproxy_policy import (
    AsyncEventSpool,
    EventSpool,
    PolicyCache,
    PolicySnapshot,
    ResolverCatalog,
    address_in_cidrs,
    client_address_allowed,
    extract_doh_question,
    host_matches,
    is_private_destination,
    normalize_address,
    normalize_host,
)
from shakerproxy_stable_bypass import StableDynamicBypassStore


MAX_HTTP_BODY_PREVIEW_BYTES = 64 * 1024
# Compressed bodies are decoded only up to the preview size, and only when
# the wire body is small enough that decoding cannot dominate the hook.
MAX_DECODE_INPUT_BYTES = 1024 * 1024
MAX_HTTP_HEADER_BYTES = 32 * 1024
MAX_HTTP_HEADERS = 128
MAX_HTTP_HEADER_VALUE_BYTES = 4096
MAX_HTTP_URL_BYTES = 8192
MAX_ERROR_TEXT_BYTES = 512
POLICY_ERROR_REPORT_SECONDS = 300
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
}
TEXTUAL_CONTENT_TYPES = (
    "text/",
    "json",
    "xml",
    "javascript",
    "x-www-form-urlencoded",
    "graphql",
    "yaml",
    "csv",
    "dns-message",
)
PASSTHROUGH_EXPLANATIONS = {
    "interception_disabled": "HTTPS decryption is off.",
    "device_not_selected": "HTTPS decryption is on only for selected devices, and this device is not one of them.",
    "private_destination": "ShakerProxy does not decrypt connections to private, CGNAT or link-local addresses (LAN and IoT backends often use self-signed or mutual TLS). Turn on decryption of private destinations to include them.",
    "manual_host_exclusion": "This host is on the policy's do-not-decrypt list.",
    "manual_cidr_exclusion": "This address range is on the policy's do-not-decrypt list.",
    "policy_bypass_rule": "A bypass rule for this device or host passes it through untouched.",
    "dynamic_probable_pinning_bypass": "The app rejected ShakerProxy's certificate repeatedly (probable certificate pinning), so ShakerProxy now passes this host through for the device.",
    "upstream_certificate_bypass": "ShakerProxy could not verify this server's certificate earlier, so it passes this host through for the device.",
}


def _bounded_text(value: Any, maximum_bytes: int) -> tuple[str, bool]:
    encoded = str(value or "").encode("utf-8", errors="replace")
    truncated = len(encoded) > maximum_bytes
    encoded = encoded[:maximum_bytes]
    # Never return a partial UTF-8 sequence.
    return encoded.decode("utf-8", errors="ignore"), truncated


def _header_snapshot(headers: Any) -> dict[str, Any]:
    result: list[dict[str, Any]] = []
    total = 0
    truncated = False
    try:
        entries = list(headers.items(multi=True))
    except Exception:
        try:
            entries = list(headers.items())
        except Exception:
            entries = []
    for raw_name, raw_value in entries:
        if len(result) >= MAX_HTTP_HEADERS:
            truncated = True
            break
        name, name_truncated = _bounded_text(raw_name, 256)
        value, value_truncated = _bounded_text(raw_value, MAX_HTTP_HEADER_VALUE_BYTES)
        candidate_bytes = len(name.encode("utf-8")) + len(value.encode("utf-8"))
        if total + candidate_bytes > MAX_HTTP_HEADER_BYTES:
            truncated = True
            break
        total += candidate_bytes
        result.append(
            {
                "name": name,
                "value": value,
                "sensitive": name.lower() in SENSITIVE_HEADER_NAMES,
                "truncated": name_truncated or value_truncated,
            }
        )
    return {"items": result, "bytes": total, "truncated": truncated}


def _bounded_decode(raw: bytes, encoding: str) -> tuple[bytes, bool]:
    """Decode at most one preview's worth of a gzip/deflate body.

    Returns (preview bytes, decoded). Other encodings (br, zstd, stacked
    encodings) are previewed as wire bytes; decoding them fully could allocate
    far more than the body's wire size.
    """
    limit = MAX_HTTP_BODY_PREVIEW_BYTES + 1
    if encoding in ("", "identity"):
        return raw[:limit], False
    if encoding in ("gzip", "x-gzip", "deflate") and len(raw) <= MAX_DECODE_INPUT_BYTES:
        for window in ((47,) if encoding != "deflate" else (15, -15)):
            try:
                return zlib.decompressobj(window).decompress(raw, limit), True
            except zlib.error:
                continue
    return raw[:limit], False


def _body_snapshot(message: Any) -> dict[str, Any]:
    headers = getattr(message, "headers", {}) or {}
    content_type = str(headers.get("content-type", "") or "")
    encoding = str(headers.get("content-encoding", "") or "").strip().lower()
    raw = getattr(message, "raw_content", None)
    if raw is None:
        # Bodies above stream_large_bodies are streamed through unbuffered.
        return {
            "content_type": content_type,
            "content_encoding": encoding,
            "streamed": True,
            "body_bytes": None,
            "preview_bytes": 0,
            "preview_encoding": "utf-8",
            "preview": "",
            "truncated": True,
            "sha256": "",
        }
    raw = bytes(raw)
    decoded, was_decoded = _bounded_decode(raw, encoding)
    preview = decoded[:MAX_HTTP_BODY_PREVIEW_BYTES]
    textual = (not encoding or was_decoded) and any(marker in content_type.lower() for marker in TEXTUAL_CONTENT_TYPES)
    if (not encoding or was_decoded) and not textual and preview:
        try:
            text = preview.decode("utf-8")
            # Treat mostly printable UTF-8 bodies as text even when a device
            # omits or mislabels Content-Type.
            printable = sum(character.isprintable() or character in "\r\n\t" for character in text)
            textual = printable / max(len(text), 1) >= 0.90
        except UnicodeDecodeError:
            textual = False
    if textual:
        value = preview.decode("utf-8", errors="replace")
        preview_encoding = "utf-8"
    else:
        value = base64.b64encode(preview).decode("ascii") if preview else ""
        preview_encoding = "base64"
    return {
        "content_type": content_type,
        "content_encoding": encoding,
        "decoded_preview": was_decoded,
        "body_bytes": len(raw),
        "preview_bytes": len(preview),
        "preview_encoding": preview_encoding,
        "preview": value,
        "truncated": len(decoded) > len(preview) or (not was_decoded and len(raw) > len(preview)),
        # Hash of the bytes on the wire; hashing a decoded body would mean
        # decompressing all of it.
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sha256_scope": "wire",
    }


def _connection_tls_details(connection: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if connection is None:
        return result
    for source, target in (("tls_version", "tls_version"), ("cipher", "cipher")):
        value = getattr(connection, source, None)
        if value:
            text, _ = _bounded_text(value, 256)
            result[target] = text
    alpn = getattr(connection, "alpn", None)
    if isinstance(alpn, bytes):
        alpn = alpn.decode("ascii", errors="replace")
    if alpn:
        text, _ = _bounded_text(alpn, 128)
        result["alpn"] = text
    certificates = getattr(connection, "certificate_list", None) or []
    if certificates:
        result.update(_certificate_details(certificates[0]))
    return result


def _certificate_details(certificate: Any) -> dict[str, Any]:
    """Bounded public details of a mitmproxy.certs.Cert."""
    result: dict[str, Any] = {}

    def name_text(value: Any) -> str:
        if isinstance(value, (list, tuple)):
            return ", ".join(f"{key}={item}" for key, item in value if key)
        return str(value or "")

    try:
        result["certificate_sha256"] = certificate.fingerprint().hex()
    except Exception:
        pass
    for source, target in (("subject", "certificate_subject"), ("issuer", "certificate_issuer")):
        try:
            text, _ = _bounded_text(name_text(getattr(certificate, source)), 1024)
            if text:
                result[target] = text
        except Exception:
            continue
    try:
        result["certificate_serial"] = format(int(certificate.serial), "x")
    except Exception:
        pass
    try:
        result["certificate_not_after"] = certificate.notafter.isoformat()
    except Exception:
        pass
    return result


def _classify_upstream_tls_error(message: str) -> tuple[str, str, bool]:
    """Return (reason, plain explanation, safe to auto-bypass)."""
    lowered = message.lower()
    if "certificate required" in lowered or "certificate_required" in lowered:
        return (
            "upstream_requires_client_certificate",
            "The server asked for a client certificate (mutual TLS) that only the device holds, so ShakerProxy cannot decrypt this connection. ShakerProxy passes this host through for the device on its next attempt.",
            True,
        )
    if any(marker in lowered for marker in ("certificate verify failed", "certificate_verify_failed", "self-signed", "self signed", "unable to get local issuer", "hostname mismatch", "certificate has expired", "ip address mismatch")):
        return (
            "upstream_certificate_untrusted",
            "The server's certificate is not publicly trusted (self-signed, private CA, expired or wrong name), so ShakerProxy cannot safely decrypt this connection. ShakerProxy passes this host through for the device on its next attempt.",
            True,
        )
    return (
        "upstream_tls_failed",
        "ShakerProxy could not complete TLS with the server, so the device saw a connection error. Retry, or bypass this host for the device.",
        False,
    )


def _classify_flow_error(message: str) -> tuple[str, str]:
    lowered = message.lower()
    reason, explanation, _ = _classify_upstream_tls_error(message)
    if reason != "upstream_tls_failed":
        return reason, explanation
    if any(marker in lowered for marker in ("connection refused", "timed out", "timeout", "name or service not known", "no route", "network is unreachable", "temporary failure in name resolution")):
        return "upstream_unreachable", "ShakerProxy could not reach the server the device asked for."
    if "client disconnected" in lowered or "client closed" in lowered:
        return "client_disconnected", "The device closed the connection before the exchange finished."
    return "upstream_or_proxy_error", "The request failed between ShakerProxy and the server."


class ShakerProxyTLS:
    def __init__(self) -> None:
        self.policy: PolicyCache | None = None
        self.bypasses: StableDynamicBypassStore | None = None
        self.catalog: ResolverCatalog | None = None
        self.events: AsyncEventSpool | None = None
        self.trusted_clients: dict[str, float] = {}
        self.last_hello: dict[int, tuple[str, str, str]] = {}
        self.failure_history: dict[tuple[str, str], list[float]] = {}
        self.policy_error = ""
        self.policy_error_reported_at = 0.0

    def load(self, loader: Loader) -> None:
        loader.add_option("shakerproxy_policy_path", str, "/var/lib/shakerproxy/traffic/policy.json", "ShakerProxy traffic policy path")
        loader.add_option("shakerproxy_bypass_path", str, "/var/lib/shakerproxy/mitmproxy-state/dynamic-bypasses.json", "ShakerProxy dynamic TLS bypass state")
        loader.add_option("shakerproxy_catalog_path", str, "/opt/shakerproxy/resolvers.json", "ShakerProxy resolver catalog path")
        loader.add_option("shakerproxy_event_spool", str, "/var/lib/shakerproxy/mitmproxy-events", "ShakerProxy normalized event spool")
        loader.add_option("shakerproxy_capture_http_content", bool, True, "Capture bounded decrypted HTTP headers and body previews in local event storage")

    def configure(self, updated: set[str]) -> None:
        changed = {"shakerproxy_policy_path", "shakerproxy_bypass_path", "shakerproxy_catalog_path", "shakerproxy_event_spool"} & set(updated)
        if not self.policy or changed:
            self.policy = PolicyCache(ctx.options.shakerproxy_policy_path)
            self.bypasses = StableDynamicBypassStore(ctx.options.shakerproxy_bypass_path)
            self.catalog = ResolverCatalog(ctx.options.shakerproxy_catalog_path)
            if self.events is not None:
                self.events.close()
            self.events = AsyncEventSpool(EventSpool(ctx.options.shakerproxy_event_spool, "12.2.3"))

    def done(self) -> None:
        if self.events is not None:
            self.events.close()

    @staticmethod
    def _server_address(data: tls.TlsData | tls.ClientHelloData) -> tuple[str, int]:
        server = data.context.server
        address = server.peername or server.address or ("", 0)
        return normalize_address(address[0]), int(address[1])

    @staticmethod
    def _client_address(data: tls.TlsData | tls.ClientHelloData) -> tuple[str, int]:
        client = data.context.client
        address = client.peername or ("", 0)
        return normalize_address(address[0]), int(address[1])

    @staticmethod
    def _sni(data: tls.TlsData | tls.ClientHelloData) -> str:
        hello = getattr(data, "client_hello", None)
        value = getattr(hello, "sni", None)
        if not value:
            value = getattr(data.context.client, "sni", None) or getattr(data.context.server, "sni", None)
        return normalize_host(str(value or ""))

    @staticmethod
    def _client_identity_key(device_id: str, client_ip: str) -> str:
        return f"device:{device_id}" if device_id else f"ip:{client_ip}"

    def _hello_identity(self, data: tls.TlsData) -> tuple[str, str, str]:
        client_ip, _ = self._client_address(data)
        server_ip, _ = self._server_address(data)
        host = self._sni(data)
        previous = self.last_hello.pop(id(data.context), None)
        if previous:
            client_ip = client_ip or previous[0]
            host = host or previous[1]
            server_ip = server_ip or previous[2]
        return client_ip, host, server_ip

    def _snapshot(self) -> PolicySnapshot:
        if self.policy is None:
            raise RuntimeError("ShakerProxy TLS policy is not initialized")
        return self.policy.load()

    def _policy_or_none(self) -> PolicySnapshot | None:
        """Load the policy; report (rate-limited) when it is unusable."""
        try:
            policy = self._snapshot()
        except Exception as exc:
            message, _ = _bounded_text(exc, MAX_ERROR_TEXT_BYTES)
            now = time.monotonic()
            if message != self.policy_error or now - self.policy_error_reported_at >= POLICY_ERROR_REPORT_SECONDS:
                logging.error("ShakerProxy policy unavailable; passing TLS through: %s", message)
                self._event(
                    "tls_policy_unavailable",
                    {
                        "reason": "policy_unavailable",
                        "error": message,
                        "explanation": "ShakerProxy cannot read its interception policy, so every connection passes through without decryption until the policy is valid again.",
                    },
                )
                self.policy_error = message
                self.policy_error_reported_at = now
            return None
        self.policy_error = ""
        return policy

    def _identity(self, client_ip: str) -> tuple[PolicySnapshot | None, str, str]:
        try:
            policy = self._snapshot()
        except Exception:
            return None, "", ""
        device_id, platform = policy.client_identity(client_ip)
        return policy, device_id, platform

    def _event(self, kind: str, payload: dict[str, Any], confidence: int = 100, flow_id: str = "") -> None:
        try:
            if self.events is not None:
                self.events.emit(kind, payload, confidence, flow_id)
        except Exception as exc:  # never let observability break the packet path
            logging.warning("ShakerProxy event spool failed: %s", exc)

    def client_connected(self, client: Any) -> None:
        """Refuse connections from outside the lab.

        The listener is also protected by the gateway firewall; this keeps a
        missing rule from turning the proxy into an open relay that loops
        into itself.
        """
        address = normalize_address((getattr(client, "peername", None) or ("", 0))[0])
        try:
            policy = self._snapshot()
            allowed = policy.client_allowed(address)
        except Exception:
            allowed = client_address_allowed(address)
        if not allowed:
            client.error = "ShakerProxy accepts proxy connections only from the lab network"

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        policy = self._policy_or_none()
        if policy is None:
            data.ignore_connection = True
            return
        client_ip, client_port = self._client_address(data)
        server_ip, server_port = self._server_address(data)
        host = self._sni(data)
        device_id, mobile_platform = policy.client_identity(client_ip)
        self.last_hello[id(data.context)] = (client_ip, host, server_ip)
        if len(self.last_hello) > 8192:
            for key in list(self.last_hello)[:4096]:
                self.last_hello.pop(key, None)

        reason = ""
        bypass_rule = None
        if not policy.enabled:
            reason = "interception_disabled"
        elif policy.tls_mode == "selective" and device_id not in policy.selected_device_ids:
            reason = "device_not_selected"
        elif not policy.intercept_private_destinations and is_private_destination(server_ip):
            reason = "private_destination"
        elif any(host_matches(pattern, host) for pattern in policy.exclude_hosts):
            reason = "manual_host_exclusion"
        elif address_in_cidrs(server_ip, list(policy.exclude_cidrs)):
            reason = "manual_cidr_exclusion"
        elif (bypass_rule := policy.bypass_rule(client_ip, host, server_ip)) is not None:
            reason = "policy_bypass_rule"
        elif host and self.bypasses is not None:
            entry = self.bypasses.lookup(client_ip, host, device_id=device_id)
            if entry is not None:
                reason = "upstream_certificate_bypass" if str(entry.get("reason", "")).startswith("upstream_") else "dynamic_probable_pinning_bypass"

        if reason:
            data.ignore_connection = True
            self.last_hello.pop(id(data.context), None)
            self._event(
                "tls_passthrough",
                {
                    "source_ip": client_ip,
                    "source_port": client_port,
                    "destination_ip": server_ip,
                    "destination_port": server_port,
                    "protocol": "tcp",
                    "service": "tls",
                    "sni": host,
                    "reason": reason,
                    "explanation": PASSTHROUGH_EXPLANATIONS.get(reason, ""),
                    "policy_revision": policy.revision,
                    "device_id": device_id,
                    "platform": mobile_platform,
                    "bypass_rule_id": bypass_rule.rule_id if bypass_rule else "",
                    "bypass_source": bypass_rule.source if bypass_rule else "",
                },
            )

    def tls_established_client(self, data: tls.TlsData) -> None:
        client_ip, host, server_ip = self._hello_identity(data)
        _, client_port = self._client_address(data)
        _, server_port = self._server_address(data)
        _, device_id, mobile_platform = self._identity(client_ip)
        self.trusted_clients[self._client_identity_key(device_id, client_ip)] = time.time()
        self._prune_trusted_clients()
        tls_details = _connection_tls_details(getattr(data.context, "client", None))
        upstream_tls = _connection_tls_details(getattr(data.context, "server", None))
        payload = {
            "source_ip": client_ip,
            "source_port": client_port,
            "destination_ip": server_ip,
            "destination_port": server_port,
            "protocol": "tcp",
            "service": "tls",
            "sni": host,
            "decrypted": True,
            "device_id": device_id,
            "platform": mobile_platform,
            "client_tls": tls_details,
            "upstream_tls": upstream_tls,
        }
        # Promote common fields for simple inspectors while retaining separate
        # client/upstream detail objects for forensic clarity.
        for key in ("tls_version", "alpn", "cipher"):
            if key in tls_details:
                payload[key] = tls_details[key]
        for key in ("certificate_sha256", "certificate_subject", "certificate_issuer", "certificate_serial"):
            if key in upstream_tls:
                payload["upstream_" + key] = upstream_tls[key]
        self._event("tls_intercepted", payload)

    def tls_established_server(self, data: tls.TlsData) -> None:
        """Record the real server's certificate once the upstream TLS completes.

        With connection_strategy=lazy the server connection does not exist yet
        when the client handshake finishes, so tls_intercepted cannot carry it.
        """
        client_ip, client_port = self._client_address(data)
        server_ip, server_port = self._server_address(data)
        host = normalize_host(str(getattr(data.conn, "sni", "") or "")) or self._sni(data)
        _, device_id, mobile_platform = self._identity(client_ip)
        upstream_tls = _connection_tls_details(data.conn)
        payload: dict[str, Any] = {
            "source_ip": client_ip,
            "source_port": client_port,
            "destination_ip": server_ip,
            "destination_port": server_port,
            "protocol": "tcp",
            "service": "tls",
            "sni": host,
            "device_id": device_id,
            "platform": mobile_platform,
            "upstream_tls": upstream_tls,
        }
        for key in ("certificate_sha256", "certificate_subject", "certificate_issuer", "certificate_serial", "certificate_not_after", "tls_version", "alpn", "cipher"):
            if key in upstream_tls:
                payload["upstream_" + key] = upstream_tls[key]
        self._event("tls_upstream_established", payload)

    def tls_failed_server(self, data: tls.TlsData) -> None:
        """Explain upstream TLS failures instead of leaving a bare 502."""
        client_ip, client_port = self._client_address(data)
        server_ip, server_port = self._server_address(data)
        host = normalize_host(str(getattr(data.conn, "sni", "") or "")) or self._sni(data)
        error_text, _ = _bounded_text(getattr(data.conn, "error", "") or "", MAX_ERROR_TEXT_BYTES)
        reason, explanation, bypassable = _classify_upstream_tls_error(error_text)
        policy, device_id, mobile_platform = self._identity(client_ip)
        bypass_added = False
        if bypassable and host and policy is not None and self.bypasses is not None:
            try:
                self.bypasses.add(client_ip, host, policy.bypass_ttl_seconds, policy.max_dynamic_bypasses, reason, device_id=device_id)
                bypass_added = True
            except Exception as exc:
                logging.warning("ShakerProxy could not persist upstream TLS bypass: %s", exc)
        self._event(
            "tls_interception_failed",
            {
                "source_ip": client_ip,
                "source_port": client_port,
                "destination_ip": server_ip,
                "destination_port": server_port,
                "protocol": "tcp",
                "service": "tls",
                "sni": host,
                "side": "upstream",
                "reason": reason,
                "classification": "upstream_verification_failed" if bypassable else "upstream_tls_failed",
                "error": error_text,
                "explanation": explanation,
                "dynamic_bypass_added": bypass_added,
                "retry_required": bypass_added,
                "policy_revision": policy.revision if policy is not None else 0,
                "device_id": device_id,
                "platform": mobile_platform,
            },
            90,
        )

    def tls_failed_client(self, data: tls.TlsData) -> None:
        client_ip, host, server_ip = self._hello_identity(data)
        _, client_port = self._client_address(data)
        _, server_port = self._server_address(data)
        try:
            policy = self._snapshot()
        except Exception as exc:
            logging.warning("ShakerProxy could not classify TLS failure: %s", exc)
            return
        device_id, mobile_platform = policy.client_identity(client_ip)
        identity_key = self._client_identity_key(device_id, client_ip)
        trusted_recently = time.time() - self.trusted_clients.get(identity_key, 0) <= 24 * 60 * 60
        now = time.time()
        failure_key = (identity_key, host or server_ip)
        failures = [value for value in self.failure_history.get(failure_key, []) if value > now - 600]
        failures.append(now)
        self.failure_history[failure_key] = failures
        if len(self.failure_history) > 4096:
            for key in list(self.failure_history)[:2048]:
                self.failure_history.pop(key, None)
        failure_count = len(failures)
        reason = "ca_not_trusted_or_pinning"
        confidence = 50
        bypass_added = False
        if policy.auto_bypass_pinned and mobile_platform and trusted_recently and host and failure_count >= policy.pinning_threshold and self.bypasses is not None:
            reason = "probable_certificate_pinning_or_custom_trust_store"
            confidence = 85
            try:
                self.bypasses.add(
                    client_ip,
                    host,
                    policy.bypass_ttl_seconds,
                    policy.max_dynamic_bypasses,
                    reason,
                    device_id=device_id,
                )
                bypass_added = True
            except Exception as exc:
                logging.warning("ShakerProxy could not persist TLS bypass: %s", exc)
        self._event(
            "tls_interception_failed",
            {
                "source_ip": client_ip,
                "source_port": client_port,
                "destination_ip": server_ip,
                "destination_port": server_port,
                "protocol": "tcp",
                "service": "tls",
                "sni": host,
                "side": "client",
                "reason": reason,
                "classification": "probable_pinning_or_custom_trust" if reason.startswith("probable_") else "unclassified_trust_failure",
                "explanation": "The device rejected ShakerProxy's certificate: it does not trust the ShakerProxy CA, or the app pins its certificate." if not bypass_added else "The app rejected ShakerProxy's certificate repeatedly (probable certificate pinning); ShakerProxy passes this host through for the device on its next attempt.",
                "client_has_recent_successful_interception": trusted_recently,
                "dynamic_bypass_added": bypass_added,
                "retry_required": bypass_added,
                "failure_count": failure_count,
                "pinning_threshold": policy.pinning_threshold,
                "failure_window_seconds": 600,
                "recent_success_window_seconds": 24 * 60 * 60,
                "policy_revision": policy.revision,
                "device_id": device_id,
                "platform": mobile_platform,
                "evidence_note": "Repeated mobile TLS failure after prior successful ShakerProxy interception is evidence of probable certificate pinning or a custom trust store; it is not proof of a specific certificate pin.",
            },
            confidence,
        )

    def _http_in_scope(self, flow: http.HTTPFlow, policy: PolicySnapshot | None, device_id: str, server_ip: str) -> bool:
        """Plain HTTP is recorded only for clients inside the decrypt scope.

        Decrypted HTTPS flows already passed the ClientHello scope check.
        """
        if flow.request.scheme == "https":
            return True
        if policy is None or not policy.in_scope(device_id):
            return False
        return policy.intercept_private_destinations or not is_private_destination(server_ip)

    def request(self, flow: http.HTTPFlow) -> None:
        client_ip, client_port = self._flow_client(flow)
        server_ip, server_port = self._flow_server(flow)
        policy, device_id, mobile_platform = self._identity(client_ip)
        if not self._http_in_scope(flow, policy, device_id, server_ip):
            return
        host = normalize_host(flow.request.pretty_host)
        path = flow.request.path.split("?", 1)[0]
        content_type = flow.request.headers.get("content-type", "")
        self.trusted_clients[self._client_identity_key(device_id, client_ip)] = time.time()
        self._prune_trusted_clients()
        classification = self.catalog.classify(host, path, content_type) if self.catalog else None
        if classification:
            blocked = bool(policy and policy.block_known_doh)
            query_name, query_type = extract_doh_question(flow.request)
            self._event(
                "encrypted_dns_detected",
                {
                    "source_ip": client_ip,
                    "source_port": client_port,
                    "destination_ip": server_ip,
                    "destination_port": server_port,
                    "protocol": "tcp",
                    "service": "doh",
                    "dns_transport": "DOH",
                    "hostname": host,
                    "http_method": flow.request.method,
                    "http_path": path,
                    "resolver_id": classification["resolver_id"],
                    "resolver_provider": classification["provider"],
                    "resolver_catalog_revision": classification["catalog_revision"],
                    "blocked": blocked,
                    "decrypted": True,
                    "query_name": query_name,
                    "query_type": query_type,
                    "device_id": device_id,
                    "platform": mobile_platform,
                },
                int(classification["confidence"]),
                flow.id,
            )
            if blocked:
                flow.response = http.Response.make(
                    403,
                    b"ShakerProxy blocked encrypted DNS for this test client.\n",
                    {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"},
                )
                return
        payload: dict[str, Any] = {
            "source_ip": client_ip,
            "source_port": client_port,
            "destination_ip": server_ip,
            "destination_port": server_port,
            "protocol": "tcp",
            "service": "https" if flow.request.scheme == "https" else "http",
            "hostname": host,
            "http_method": flow.request.method,
            "http_scheme": flow.request.scheme,
            # Transparent mode: request.host is the server IP; the name the
            # device asked for is in the Host header, :authority or SNI.
            "http_host": host or flow.request.host,
            "http_port": int(flow.request.port),
            "http_path": path,
            "http_version": flow.request.http_version,
            "decrypted": flow.request.scheme == "https",
            "device_id": device_id,
            "platform": mobile_platform,
        }
        pretty_url, url_truncated = _bounded_text(flow.request.pretty_url, MAX_HTTP_URL_BYTES)
        payload["http_url"] = pretty_url
        payload["http_url_truncated"] = url_truncated
        if bool(getattr(ctx.options, "shakerproxy_capture_http_content", True)):
            payload["request_headers"] = _header_snapshot(flow.request.headers)
            payload["request_body"] = _body_snapshot(flow.request)
            payload["content_local_only"] = True
        self._event("http_request", payload, 100, flow.id)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        client_ip, client_port = self._flow_client(flow)
        server_ip, server_port = self._flow_server(flow)
        policy, device_id, mobile_platform = self._identity(client_ip)
        if not self._http_in_scope(flow, policy, device_id, server_ip):
            return
        request_raw = flow.request.raw_content
        response_raw = flow.response.raw_content
        payload: dict[str, Any] = {
            "source_ip": client_ip,
            "source_port": client_port,
            "destination_ip": server_ip,
            "destination_port": server_port,
            "protocol": "tcp",
            "service": "https" if flow.request.scheme == "https" else "http",
            "hostname": normalize_host(flow.request.pretty_host),
            "http_method": flow.request.method,
            "http_scheme": flow.request.scheme,
            "http_host": normalize_host(flow.request.pretty_host) or flow.request.host,
            "http_port": int(flow.request.port),
            "http_path": flow.request.path.split("?", 1)[0],
            "http_status": int(flow.response.status_code),
            "http_version": flow.response.http_version,
            "request_bytes": len(request_raw) if request_raw else 0,
            "response_bytes": len(response_raw) if response_raw else 0,
            "decrypted": flow.request.scheme == "https",
            "device_id": device_id,
            "platform": mobile_platform,
        }
        pretty_url, url_truncated = _bounded_text(flow.request.pretty_url, MAX_HTTP_URL_BYTES)
        payload["http_url"] = pretty_url
        payload["http_url_truncated"] = url_truncated
        if bool(getattr(ctx.options, "shakerproxy_capture_http_content", True)):
            payload["response_headers"] = _header_snapshot(flow.response.headers)
            payload["response_body"] = _body_snapshot(flow.response)
            payload["content_local_only"] = True
        self._event("http_response", payload, 100, flow.id)

    def error(self, flow: http.HTTPFlow) -> None:
        client_ip, client_port = self._flow_client(flow)
        server_ip, server_port = self._flow_server(flow)
        _, device_id, mobile_platform = self._identity(client_ip)
        message, _ = _bounded_text(getattr(flow.error, "msg", "") if flow.error else "", MAX_ERROR_TEXT_BYTES)
        reason, explanation = _classify_flow_error(message)
        scheme = flow.request.scheme if flow.request else ""
        self._event(
            "http_flow_error",
            {
                "source_ip": client_ip,
                "source_port": client_port,
                "destination_ip": server_ip,
                "destination_port": server_port,
                "protocol": "tcp",
                "service": "https" if scheme == "https" else "http",
                "hostname": normalize_host(flow.request.pretty_host if flow.request else ""),
                "reason": reason,
                "error": message,
                "explanation": explanation,
                "device_id": device_id,
                "platform": mobile_platform,
            },
            80,
            flow.id,
        )

    @staticmethod
    def _flow_client(flow: http.HTTPFlow) -> tuple[str, int]:
        address = flow.client_conn.peername or ("", 0)
        return normalize_address(address[0]), int(address[1])

    @staticmethod
    def _flow_server(flow: http.HTTPFlow) -> tuple[str, int]:
        address = flow.server_conn.peername or flow.server_conn.address or ("", 0)
        return normalize_address(address[0]), int(address[1])

    def _prune_trusted_clients(self) -> None:
        cutoff = time.time() - 24 * 60 * 60
        self.trusted_clients = {client: timestamp for client, timestamp in self.trusted_clients.items() if timestamp >= cutoff}
        if len(self.trusted_clients) > 4096:
            ordered = sorted(self.trusted_clients.items(), key=lambda item: item[1], reverse=True)
            self.trusted_clients = dict(ordered[:4096])


addons = [ShakerProxyTLS()]
