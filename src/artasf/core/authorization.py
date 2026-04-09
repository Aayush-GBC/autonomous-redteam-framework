"""
Engagement authorization gate.

Before any active phase (recon, exploitation, post-exploit) the orchestrator
calls AuthorizationGate.verify().  The gate checks that a signed authorization
token is present and that the engagement scope (target network, expiry) matches
the current session.  If the check fails, an AuthorizationError is raised and
the pipeline halts — no traffic is ever sent to the target without a valid
authorization on file.

Token format (JSON, stored in ARTASF_AUTH_TOKEN env var or --auth-token flag):

    {
        "engagement": "<engagement name>",
        "target_network": "<CIDR or IP>",
        "authorized_by": "<approver name / email>",
        "expires_at": "<ISO-8601 UTC timestamp>",
        "signature": "<HMAC-SHA256 hex of canonical fields>"
    }

Generating a token (for lab use / development)::

    python -m artasf.core.authorization sign \
        --engagement "Lab Demo" \
        --target-network "192.168.56.0/24" \
        --authorized-by "lab-admin" \
        --expires-in 24h

The same secret used by AuditLog (ARTASF_AUDIT_SECRET) signs the token, so
both components share one secret in the environment.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

from artasf.core.exceptions import ARTASFError

_SECRET: bytes = os.environ.get("ARTASF_AUDIT_SECRET", "artasf-audit-chain").encode()


class AuthorizationError(ARTASFError):
    """Raised when no valid authorization token is present."""


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------

class AuthorizationGate:
    """
    Verify that the current engagement has a valid, in-scope authorization
    token before any active testing begins.

    In dry-run mode the check is skipped (token may be absent in CI).
    """

    def __init__(self, dry_run: bool = False) -> None:
        self._dry_run = dry_run

    def verify(self, target_network: str, engagement_name: str) -> None:
        """
        Assert that a valid authorization token covers this engagement.

        Args:
            target_network:  CIDR or IP from the engagement session.
            engagement_name: Name of the current engagement session.

        Raises:
            AuthorizationError: if the token is missing, expired, tampered
                with, or does not cover this target.
        """
        if self._dry_run:
            return  # CI / unit-test runs are exempt

        raw = os.environ.get("ARTASF_AUTH_TOKEN", "").strip()
        if not raw:
            raise AuthorizationError(
                "No ARTASF_AUTH_TOKEN found in environment.\n"
                f"Generate one with:\n"
                f"  artasf auth sign --target-network \"{target_network}\" "
                f"--engagement \"{engagement_name}\" --authorized-by \"<your-name>\"\n"
                "Then copy the printed export command into your shell and re-run.\n"
                "This tool will not run against a target without explicit authorization."
            )

        try:
            token: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AuthorizationError(f"ARTASF_AUTH_TOKEN is not valid JSON: {exc}") from exc

        # Verify HMAC signature first so we know the token wasn't tampered with
        claimed_sig = token.pop("signature", None)
        if claimed_sig is None:
            raise AuthorizationError("ARTASF_AUTH_TOKEN has no 'signature' field.")
        canonical = json.dumps(token, sort_keys=True, separators=(",", ":"))
        expected_sig = _hmac_hex(canonical.encode())
        if not hmac.compare_digest(expected_sig, claimed_sig):
            raise AuthorizationError(
                "ARTASF_AUTH_TOKEN signature is invalid — token may have been tampered with."
            )
        # Restore for subsequent checks
        token["signature"] = claimed_sig

        # Check expiry
        expires_raw = token.get("expires_at", "")
        try:
            expires_at = datetime.fromisoformat(expires_raw)
        except (ValueError, TypeError) as exc:
            raise AuthorizationError(
                f"ARTASF_AUTH_TOKEN has an invalid 'expires_at' field: {expires_raw!r}"
            ) from exc
        if datetime.now(timezone.utc) > expires_at:
            raise AuthorizationError(
                f"ARTASF_AUTH_TOKEN expired at {expires_at.isoformat()}. "
                "Re-generate the token to continue."
            )

        # Check target network scope
        token_network = token.get("target_network", "")
        if token_network != target_network:
            raise AuthorizationError(
                f"ARTASF_AUTH_TOKEN authorizes '{token_network}' "
                f"but this engagement targets '{target_network}'. "
                "Scope mismatch — aborting."
            )

        # All checks passed
        authorized_by = token.get("authorized_by", "unknown")
        from loguru import logger  # lazy import to avoid circular
        logger.info(
            "Authorization verified — target={} authorized_by={} expires={}",
            target_network, authorized_by, expires_at.isoformat(),
        )


# ---------------------------------------------------------------------------
# Token generator (invoked via  python -m artasf.core.authorization sign ...)
# ---------------------------------------------------------------------------

def _sign_token(
    engagement: str,
    target_network: str,
    authorized_by: str,
    expires_in_hours: float = 24.0,
) -> str:
    """Build and sign a new authorization token; return the JSON string."""
    expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
    payload: dict[str, Any] = {
        "engagement": engagement,
        "target_network": target_network,
        "authorized_by": authorized_by,
        "expires_at": expires_at.isoformat(),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload["signature"] = _hmac_hex(canonical.encode())
    return json.dumps(payload, indent=2)


def _hmac_hex(data: bytes) -> str:
    return hmac.new(_SECRET, data, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# CLI entry-point  (python -m artasf.core.authorization sign ...)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a signed ARTASF authorization token."
    )
    sub = parser.add_subparsers(dest="cmd")
    p = sub.add_parser("sign", help="Sign a new token")
    p.add_argument("--engagement",      required=True)
    p.add_argument("--target-network",  required=True)
    p.add_argument("--authorized-by",   required=True)
    p.add_argument("--expires-in",      default="24h",
                   help="Token lifetime, e.g. 8h, 48h (default: 24h)")

    args = parser.parse_args()
    if args.cmd == "sign":
        hours_str: str = args.expires_in.rstrip("hH")
        try:
            hours = float(hours_str)
        except ValueError:
            print(f"Invalid --expires-in value: {args.expires_in!r}", file=sys.stderr)
            sys.exit(1)
        token_json = _sign_token(
            engagement=args.engagement,
            target_network=args.target_network,
            authorized_by=args.authorized_by,
            expires_in_hours=hours,
        )
        print(token_json)
        print(
            "\nSet this as your auth token:\n"
            f"  export ARTASF_AUTH_TOKEN='{json.loads(token_json) and token_json}'",
            file=sys.stderr,
        )
    else:
        parser.print_help()
