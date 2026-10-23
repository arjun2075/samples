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

"""Tests for the transaction-bound screening evidence reference."""

import copy
import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
  Ed25519PrivateKey,
)
import pytest

from screening_evidence import ACTION_KEY
from screening_evidence import ScreeningContext
from screening_evidence import checkout_gate
from screening_evidence import evaluate_evidence
from screening_evidence import make_evidence_payload
from screening_evidence import sign_evidence


NOW = datetime.datetime(2026, 10, 23, 0, 0, tzinfo=datetime.UTC)
MAX_AGE = datetime.timedelta(hours=1)
ISSUER = "https://verifier.example"
KID = "screening-2026-10"


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
  """Return an isolated key for each test."""
  return Ed25519PrivateKey.generate()


@pytest.fixture
def context() -> ScreeningContext:
  """Return one fully bound checkout context."""
  return ScreeningContext(
    checkout_id="chk-123",
    buyer_id="buyer-a",
    payer_id="payer-a",
    seller_id="seller-b",
    goods_recipient_id="recipient-a",
    destination_fingerprint="sha256:destination-d",
    transaction_context_fingerprint="sha256:items-currency-purpose-v1",
  )


def _signed(
  context: ScreeningContext,
  private_key: Ed25519PrivateKey,
  *,
  screened_at: datetime.datetime = NOW - datetime.timedelta(minutes=5),
  expires_at: datetime.datetime = NOW + datetime.timedelta(minutes=30),
) -> dict:
  payload = make_evidence_payload(
    context,
    evidence_id="ev-1",
    screened_at=screened_at,
    expires_at=expires_at,
    policy="example-policy-2026-10",
  )
  return sign_evidence(
    payload,
    issuer=ISSUER,
    kid=KID,
    private_key=private_key,
  )


def _evaluate(
  evidence: dict | None,
  context: ScreeningContext,
  private_key: Ed25519PrivateKey,
):
  return evaluate_evidence(
    evidence,
    context=context,
    trusted_keys={(ISSUER, KID): private_key.public_key()},
    now=NOW,
    max_age=MAX_AGE,
  )


def test_matching_signed_evidence_allows_progression(
  context: ScreeningContext,
  private_key: Ed25519PrivateKey,
) -> None:
  """Matching, fresh, authentic evidence allows local progression."""
  decision = _evaluate(_signed(context, private_key), context, private_key)

  assert decision.applicable
  assert decision.reasons == ()
  assert checkout_gate(decision) == {
    "status": "ready_for_complete",
    "messages": [],
  }


@pytest.mark.parametrize(
  ("changed_field", "reason"),
  [
    ("payer_id", "payer_binding_changed"),
    ("destination_fingerprint", "destination_binding_changed"),
    ("transaction_context_fingerprint", "transaction_context_binding_changed"),
    ("checkout_id", "checkout_binding_changed"),
  ],
)
def test_binding_changes_require_reevaluation(
  changed_field: str,
  reason: str,
  context: ScreeningContext,
  private_key: Ed25519PrivateKey,
) -> None:
  """A changed covered fact invalidates otherwise authentic evidence."""
  evidence = _signed(context, private_key)
  changed_values = {**context.__dict__, changed_field: "changed"}
  changed = ScreeningContext(**changed_values)

  decision = _evaluate(evidence, changed, private_key)

  assert not decision.applicable
  assert reason in decision.reasons
  assert "binding_digest_changed" in decision.reasons


def test_payload_tampering_fails_signature(
  context: ScreeningContext,
  private_key: Ed25519PrivateKey,
) -> None:
  """Mutation after signing is detected before policy evaluation."""
  evidence = copy.deepcopy(_signed(context, private_key))
  evidence["payload"]["subject_bindings"]["payer"] = "attacker-payer"

  decision = _evaluate(evidence, context, private_key)

  assert decision.reasons == ("signature_invalid",)


@pytest.mark.parametrize(
  ("screened_at", "expires_at", "reason"),
  [
    (
      NOW - datetime.timedelta(hours=2),
      NOW + datetime.timedelta(minutes=5),
      "evidence_too_old",
    ),
    (
      NOW - datetime.timedelta(minutes=5),
      NOW,
      "evidence_expired",
    ),
    (
      NOW + datetime.timedelta(minutes=3),
      NOW + datetime.timedelta(hours=1),
      "screened_at_in_future",
    ),
  ],
)
def test_freshness_failures_are_fail_closed(
  screened_at: datetime.datetime,
  expires_at: datetime.datetime,
  reason: str,
  context: ScreeningContext,
  private_key: Ed25519PrivateKey,
) -> None:
  """Expired, old, and implausibly future evidence cannot be reused."""
  evidence = _signed(
    context,
    private_key,
    screened_at=screened_at,
    expires_at=expires_at,
  )

  decision = _evaluate(evidence, context, private_key)

  assert not decision.applicable
  assert reason in decision.reasons


def test_unknown_issuer_is_rejected(
  context: ScreeningContext,
  private_key: Ed25519PrivateKey,
) -> None:
  """A valid signature from an untrusted issuer is insufficient."""
  evidence = _signed(context, private_key)

  decision = evaluate_evidence(
    evidence,
    context=context,
    trusted_keys={},
    now=NOW,
    max_age=MAX_AGE,
  )

  assert decision.reasons == ("issuer_or_key_untrusted",)


def test_missing_evidence_blocks_without_inventing_an_action(
  context: ScreeningContext,
  private_key: Ed25519PrivateKey,
) -> None:
  """Local enforcement uses ordinary status and Message primitives."""
  decision = _evaluate(None, context, private_key)

  gate = checkout_gate(decision)

  assert gate["status"] == "incomplete"
  assert "actions" not in gate
  assert gate["messages"][0]["code"] == "signal"


def test_refresh_action_requires_explicit_negotiation(
  context: ScreeningContext,
  private_key: Ed25519PrivateKey,
) -> None:
  """The vendor Action appears only after explicit negotiation."""
  decision = _evaluate(None, context, private_key)

  gate = checkout_gate(decision, negotiated_refresh_action=True)

  assert list(gate["actions"]) == [ACTION_KEY]
  assert gate["messages"][0]["path"] == f"$.actions['{ACTION_KEY}'][0]"
