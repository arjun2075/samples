# Copyright 2026 UCP Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Reference validation for transaction-bound screening evidence.

This module demonstrates one vendor-namespaced Signal carried in a Checkout
request. It validates evidence integrity and continued applicability; it does
not perform screening, select legal rules, or assert that a transaction is
lawful. The Business remains authoritative for its own policy decision.
"""

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
import datetime
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
  Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SIGNAL_KEY = "com.example.compliance.counterparty_screening"
ACTION_KEY = "com.example.compliance.counterparty_screening.refresh"


@dataclass(frozen=True)
class ScreeningContext:
  """Binding inputs that determine whether prior evidence still applies."""

  checkout_id: str
  buyer_id: str
  payer_id: str
  seller_id: str
  goods_recipient_id: str
  destination_fingerprint: str
  transaction_context_fingerprint: str

  def binding(self) -> dict[str, str]:
    """Return the canonical set of transaction facts covered by evidence."""
    return {
      "buyer": self.buyer_id,
      "payer": self.payer_id,
      "seller": self.seller_id,
      "goods_recipient": self.goods_recipient_id,
      "destination": self.destination_fingerprint,
      "transaction_context": self.transaction_context_fingerprint,
    }

  def binding_digest(self) -> str:
    """Return a stable digest of all bound roles and transaction facts."""
    binding = {
      "checkout_id": self.checkout_id,
      "subject_bindings": self.binding(),
    }
    return hashlib.sha256(_canonical_json(binding)).hexdigest()


@dataclass(frozen=True)
class ScreeningDecision:
  """Evidence validation result used by local checkout policy."""

  applicable: bool
  reasons: tuple[str, ...]
  evidence_id: str | None = None


def make_evidence_payload(
  context: ScreeningContext,
  *,
  evidence_id: str,
  screened_at: datetime.datetime,
  expires_at: datetime.datetime,
  policy: str,
) -> dict[str, Any]:
  """Build the signed payload for a test verifier or integration adapter."""
  _require_utc(screened_at)
  _require_utc(expires_at)
  return {
    "evidence_id": evidence_id,
    "checkout_id": context.checkout_id,
    "screened_at": _format_time(screened_at),
    "expires_at": _format_time(expires_at),
    "policy": policy,
    "subject_bindings": context.binding(),
    "binding_digest": context.binding_digest(),
  }


def sign_evidence(
  payload: Mapping[str, Any],
  *,
  issuer: str,
  kid: str,
  private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
  """Create a compact JSON envelope whose header and payload are signed."""
  protected = {
    "alg": "EdDSA",
    "issuer": issuer,
    "kid": kid,
    "payload": dict(payload),
  }
  signature = private_key.sign(_canonical_json(protected))
  return {**protected, "signature": _base64url_encode(signature)}


def evaluate_evidence(
  envelope: Mapping[str, Any] | None,
  *,
  context: ScreeningContext,
  trusted_keys: Mapping[tuple[str, str], Ed25519PublicKey],
  now: datetime.datetime,
  max_age: datetime.timedelta,
  maximum_clock_skew: datetime.timedelta = datetime.timedelta(minutes=2),
) -> ScreeningDecision:
  """Verify integrity, freshness, and exact transaction applicability.

  A negative result is intentionally fail-closed. Callers should keep the
  Checkout incomplete until local policy obtains applicable evidence or chooses
  a different, explicitly documented path.
  """
  _require_utc(now)
  if envelope is None:
    return ScreeningDecision(False, ("evidence_missing",))

  try:
    issuer = _required_string(envelope, "issuer")
    kid = _required_string(envelope, "kid")
    if envelope.get("alg") != "EdDSA":
      return ScreeningDecision(False, ("algorithm_unsupported",))
    payload = envelope.get("payload")
    if not isinstance(payload, Mapping):
      return ScreeningDecision(False, ("payload_malformed",))
    signature_text = _required_string(envelope, "signature")
    signature = _base64url_decode(signature_text)
  except (TypeError, ValueError):
    return ScreeningDecision(False, ("envelope_malformed",))

  key = trusted_keys.get((issuer, kid))
  if key is None:
    return ScreeningDecision(False, ("issuer_or_key_untrusted",))

  protected = {
    "alg": "EdDSA",
    "issuer": issuer,
    "kid": kid,
    "payload": dict(payload),
  }
  try:
    key.verify(signature, _canonical_json(protected))
  except InvalidSignature:
    return ScreeningDecision(False, ("signature_invalid",))

  evidence_id = payload.get("evidence_id")
  if not isinstance(evidence_id, str) or not evidence_id:
    return ScreeningDecision(False, ("payload_malformed",))

  try:
    screened_at = _parse_time(_required_string(payload, "screened_at"))
    expires_at = _parse_time(_required_string(payload, "expires_at"))
  except ValueError:
    return ScreeningDecision(False, ("payload_malformed",), evidence_id)

  reasons: list[str] = []
  if screened_at > now + maximum_clock_skew:
    reasons.append("screened_at_in_future")
  if now - screened_at > max_age:
    reasons.append("evidence_too_old")
  if expires_at <= now:
    reasons.append("evidence_expired")
  if expires_at <= screened_at:
    reasons.append("validity_window_invalid")

  if payload.get("checkout_id") != context.checkout_id:
    reasons.append("checkout_binding_changed")

  subject_bindings = payload.get("subject_bindings")
  current_bindings = context.binding()
  if not isinstance(subject_bindings, Mapping):
    reasons.append("subject_bindings_malformed")
  else:
    for role, current_value in current_bindings.items():
      if subject_bindings.get(role) != current_value:
        reasons.append(f"{role}_binding_changed")

  if payload.get("binding_digest") != context.binding_digest():
    reasons.append("binding_digest_changed")

  return ScreeningDecision(
    not reasons, tuple(dict.fromkeys(reasons)), evidence_id
  )


def checkout_gate(
  decision: ScreeningDecision,
  *,
  negotiated_refresh_action: bool = False,
) -> dict[str, Any]:
  """Map local policy to ordinary UCP status, Messages, and optional Action.

  The refresh Action is emitted only when its vendor extension was negotiated.
  Evidence validity does not require a generic Action or a Core schema change.
  """
  if decision.applicable:
    return {"status": "ready_for_complete", "messages": []}

  result: dict[str, Any] = {
    "status": "incomplete",
    "messages": [
      {
        "type": "error",
        "code": "signal",
        "severity": "recoverable",
        "path": f"$.signals['{SIGNAL_KEY}']",
        "content": (
          "Current transaction facts require applicable screening evidence."
        ),
      }
    ],
  }
  if negotiated_refresh_action:
    result["actions"] = {
      ACTION_KEY: [
        {
          "id": f"refresh-{decision.evidence_id or 'missing'}",
          "config": {"reason_codes": list(decision.reasons)},
        }
      ]
    }
    result["messages"][0]["path"] = f"$.actions['{ACTION_KEY}'][0]"
  return result


def _canonical_json(value: Any) -> bytes:
  return json.dumps(
    value,
    ensure_ascii=False,
    separators=(",", ":"),
    sort_keys=True,
  ).encode("utf-8")


def _base64url_encode(value: bytes) -> str:
  return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
  padding = "=" * (-len(value) % 4)
  try:
    return base64.b64decode(
      value + padding,
      altchars=b"-_",
      validate=True,
    )
  except (binascii.Error, ValueError) as error:
    raise ValueError("invalid base64url") from error


def _required_string(source: Mapping[str, Any], name: str) -> str:
  value = source.get(name)
  if not isinstance(value, str) or not value:
    raise ValueError(f"{name} must be a non-empty string")
  return value


def _require_utc(value: datetime.datetime) -> None:
  if value.tzinfo is None or value.utcoffset() != datetime.timedelta(0):
    raise ValueError("timestamps must be timezone-aware UTC")


def _format_time(value: datetime.datetime) -> str:
  return value.isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime.datetime:
  parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
  _require_utc(parsed)
  return parsed
