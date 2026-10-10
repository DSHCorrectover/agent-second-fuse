# -*- coding: utf-8 -*-
"""Tests for Ed25519 keys and signed receipts."""

import pytest

from agent_runtime_guard.keys import Signer, load_public_key
from agent_runtime_guard.receipt import (
    Receipt,
    ReceiptSigner,
    jcs,
    verify_receipt,
)


@pytest.fixture()
def signer(tmp_path):
    return Signer.load_or_create(tmp_path / "keys")


def test_key_generation_is_stable_and_persisted(tmp_path):
    signer1 = Signer.load_or_create(tmp_path / "keys")
    signer2 = Signer.load_or_create(tmp_path / "keys")
    assert signer1.kid == signer2.kid
    assert len(signer1.kid) == 16


def test_public_pem_roundtrip(signer):
    pub = load_public_key(signer.public_pem())
    assert Signer.compute_kid(pub) == signer.kid


def test_jcs_is_order_and_whitespace_deterministic():
    a = jcs({"b": 1, "a": 2})
    b = jcs({"a": 2, "b": 1})
    assert a == b
    assert a == b'{"a":2,"b":1}'


def test_receipt_sign_and_verify(signer):
    rs = ReceiptSigner(signer)
    receipt = rs.issue(
        decision="block", action="execute_shell", layer="mutation",
        rule="danger", reason="rm -rf", parameters={"command": "x"},
    )
    assert receipt.receipt_id.startswith("r")
    assert verify_receipt(receipt, signer.public_key) is True


def test_receipt_tamper_invalidates(signer):
    rs = ReceiptSigner(signer)
    receipt = rs.issue(
        decision="block", action="execute_shell", layer="mutation",
        rule="danger", reason="rm -rf",
    )
    receipt.envelope["payload"]["decision"] = "allow"
    assert verify_receipt(receipt, signer.public_key) is False


def test_receipt_wrong_key_rejected(tmp_path, signer):
    other = Signer.load_or_create(tmp_path / "other-keys")
    rs = ReceiptSigner(signer)
    receipt = rs.issue(
        decision="allow", action="read_file", layer="kernel",
        rule="ok", reason="pass",
    )
    # signed by signer but verified with a different key -> kid mismatch / fail
    assert verify_receipt(receipt, other.public_key) is False


def test_receipt_from_dict_requires_fields():
    with pytest.raises(ValueError):
        Receipt.from_dict({"kid": "x"})
