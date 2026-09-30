from __future__ import annotations

import json
import logging
import os
import pathlib
import stat
import threading
from dataclasses import dataclass
from typing import Any

MAX_CONTENT_POLICY_BYTES = 16 * 1024
_ALLOWED_FIELDS = {
    "schema",
    "revision",
    "capture_http_content",
    "updated_at",
    "updated_by",
}


@dataclass(frozen=True)
class ContentRetentionPolicy:
    revision: int
    capture_http_content: bool


class ContentRetentionPolicyCache:
    """Read the control API's bounded, atomic local policy projection."""

    def __init__(self, path: str):
        self.path = pathlib.Path(path)
        self._signature: tuple[int, int, int] | None = None
        self._policy = ContentRetentionPolicy(1, True)
        self._lock = threading.Lock()

    def reset_path(self, path: str) -> None:
        with self._lock:
            self.path = pathlib.Path(path)
            self._signature = None
            self._policy = ContentRetentionPolicy(1, True)

    def load(self) -> ContentRetentionPolicy:
        with self._lock:
            try:
                info = self.path.lstat()
            except FileNotFoundError:
                # Preserve Community's historical behavior until an
                # administrator explicitly changes the setting. Packaged
                # installs expose the missing/default state in the UI.
                self._signature = None
                self._policy = ContentRetentionPolicy(1, True)
                return self._policy
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise ValueError("HTTP content policy must be a regular non-symlink file")
            if info.st_size <= 0 or info.st_size > MAX_CONTENT_POLICY_BYTES:
                raise ValueError("HTTP content policy exceeds its storage bound")
            signature = (info.st_ino, info.st_mtime_ns, info.st_size)
            if signature == self._signature:
                return self._policy
            with self.path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
                if handle.read(1):
                    raise ValueError("HTTP content policy contains trailing data")
            if not isinstance(value, dict) or set(value) - _ALLOWED_FIELDS:
                raise ValueError("HTTP content policy has unknown fields")
            schema = value.get("schema")
            revision = value.get("revision")
            capture = value.get("capture_http_content")
            if schema != 1 or not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
                raise ValueError("HTTP content policy identity is invalid")
            if not isinstance(capture, bool):
                raise ValueError("HTTP content policy capture flag is invalid")
            policy = ContentRetentionPolicy(revision, capture)
            self._signature = signature
            self._policy = policy
            return policy


class ShakerProxyContentPolicy:
    """Synchronize durable local privacy state into the existing TLS addon."""

    def __init__(self) -> None:
        self.cache: ContentRetentionPolicyCache | None = None
        self.applied: ContentRetentionPolicy | None = None
        self.last_error = ""

    def load(self, loader: Any) -> None:
        loader.add_option(
            "shakerproxy_content_policy_path",
            str,
            "/var/lib/shakerproxy/content-policy/policy.json",
            "ShakerProxy local decrypted HTTP retention policy",
        )

    def configure(self, updated: set[str]) -> None:
        from mitmproxy import ctx

        if self.cache is None or "shakerproxy_content_policy_path" in updated:
            self.cache = ContentRetentionPolicyCache(ctx.options.shakerproxy_content_policy_path)
            self.applied = None
        self._sync()

    def running(self) -> None:
        self._sync()

    def request(self, _flow: Any) -> None:
        self._sync()

    def response(self, _flow: Any) -> None:
        self._sync()

    def _sync(self) -> None:
        from mitmproxy import ctx

        if self.cache is None:
            self.cache = ContentRetentionPolicyCache(ctx.options.shakerproxy_content_policy_path)
        try:
            policy = self.cache.load()
            self.last_error = ""
        except Exception as exc:
            # Privacy fails closed. TLS interception and metadata continue, but
            # decrypted headers/body previews are not retained until the
            # bounded policy file becomes valid again.
            message = str(exc)[:512]
            if message != self.last_error:
                logging.error("ShakerProxy HTTP content policy invalid; disabling plaintext retention: %s", message)
                self.last_error = message
            policy = ContentRetentionPolicy(0, False)
        if self.applied == policy:
            return
        previous = self.applied
        # options.update can synchronously dispatch configure hooks. Mark this
        # revision before updating so that re-entry observes a completed state
        # transition instead of recursively applying the same option.
        self.applied = policy
        try:
            ctx.options.update(shakerproxy_capture_http_content=policy.capture_http_content)
        except Exception:
            self.applied = previous
            raise
        logging.info(
            "ShakerProxy decrypted HTTP content retention is %s at revision %d",
            "enabled" if policy.capture_http_content else "disabled",
            policy.revision,
        )
