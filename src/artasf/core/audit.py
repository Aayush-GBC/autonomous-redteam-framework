"""
Audit log with HMAC-chained entries.

Every event written to the audit log is HMAC-SHA256 signed against the
previous entry's hash, forming an append-only chain.  Any post-hoc
tampering with earlier entries breaks the chain and is detectable by
verify_chain().

This satisfies legal chain-of-custody requirements for red-team engagements:
the log proves that events were recorded in order and were not modified after
the fact.

Usage::

    log = AuditLog(Path("artifacts/audit.log"))
    log.record("PHASE_START", phase="recon", session_id="abc123")
    log.record("EXPLOIT_ATTEMPT", module="exploit/multi/http/...", target="10.0.0.1")
    ok, errors = log.verify_chain()
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Secret used for HMAC signing.  Loaded from env so it's not hard-coded.
# If absent we fall back to a fixed sentinel — still detects tampering,
# but the chain is not secret.  Operators should set ARTASF_AUDIT_SECRET.
_SECRET: bytes = os.environ.get("ARTASF_AUDIT_SECRET", "artasf-audit-chain").encode()

_GENESIS_HASH = "0" * 64  # initial previous-hash for the first entry


class AuditLog:
    """
    Append-only, HMAC-chained audit log backed by a newline-delimited JSON file.

    Thread safety: this class is *not* thread-safe; it is intended to be used
    from a single async task (the orchestrator) via synchronous writes.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash: str = self._load_tail_hash()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, event: str, **fields: Any) -> str:
        """
        Append a signed audit entry and return its hash.

        Args:
            event:   Short event name, e.g. ``"PHASE_START"``.
            **fields: Arbitrary key-value metadata for the entry.

        Returns:
            The HMAC-SHA256 hash of the new entry (hex string).
        """
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
            "prev": self._prev_hash,
        }
        # Canonical JSON — sorted keys so the digest is deterministic
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        digest = _hmac_hex(canonical.encode())
        entry["hash"] = digest

        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")

        self._prev_hash = digest
        return digest

    def verify_chain(self) -> tuple[bool, list[str]]:
        """
        Re-derive every entry's hash and verify the chain is intact.

        Returns:
            ``(True, [])`` if the chain is valid, or
            ``(False, [list of error messages])`` on any break.
        """
        if not self._path.exists():
            return True, []

        errors: list[str] = []
        prev = _GENESIS_HASH
        lines = self._path.read_text(encoding="utf-8").splitlines()

        for lineno, raw in enumerate(lines, start=1):
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError as exc:
                errors.append(f"line {lineno}: JSON parse error — {exc}")
                continue

            claimed_hash = entry.pop("hash", None)
            if claimed_hash is None:
                errors.append(f"line {lineno}: missing 'hash' field")
                continue

            if entry.get("prev") != prev:
                errors.append(
                    f"line {lineno}: prev-hash mismatch "
                    f"(expected {prev[:16]}…, got {str(entry.get('prev', ''))[:16]}…)"
                )

            canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            expected = _hmac_hex(canonical.encode())
            if not hmac.compare_digest(expected, claimed_hash):
                errors.append(f"line {lineno}: HMAC mismatch — entry may have been tampered with")

            prev = claimed_hash  # advance regardless so we keep checking

        return (len(errors) == 0), errors

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_tail_hash(self) -> str:
        """Read the hash of the last entry so new records chain onto it."""
        if not self._path.exists():
            return _GENESIS_HASH
        last_line = ""
        with self._path.open(encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
        if not last_line:
            return _GENESIS_HASH
        try:
            return json.loads(last_line).get("hash", _GENESIS_HASH)
        except (json.JSONDecodeError, AttributeError):
            return _GENESIS_HASH


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _hmac_hex(data: bytes) -> str:
    return hmac.new(_SECRET, data, hashlib.sha256).hexdigest()
