# -*- coding: utf-8 -*-
"""Tests for the append-only ledger and incident reports."""

import json

import pytest

from agent_runtime_guard.incident import build_report, report_to_markdown
from agent_runtime_guard.keys import Signer
from agent_runtime_guard.ledger import EventLedger
from agent_runtime_guard.receipt import ReceiptSigner


@pytest.fixture()
def signer(tmp_path):
    return Signer.load_or_create(tmp_path / "keys")


@pytest.fixture()
def populated(tmp_path, signer):
    ledger = EventLedger(tmp_path / "ledger")
    rs = ReceiptSigner(signer)
    ledger.append(rs.issue(
        decision="allow", action="read_file", layer="kernel",
        rule="ok", reason="pass",
    ))
    ledger.append(rs.issue(
        decision="block", action="execute_shell", layer="mutation",
        rule="danger", reason="rm -rf", parameters={"command": "sudo rm -rf /"},
    ))
    return ledger, signer


def test_ledger_appends_in_sequence(populated):
    ledger, _ = populated
    assert ledger.count() == 2
    integrity = ledger.verify()
    assert integrity.ok is True


def test_ledger_detects_tamper(populated):
    ledger, signer = populated
    path = ledger.path
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[-1])
    entry["envelope"]["payload"]["reason"] = "changed"
    lines[-1] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    integrity = ledger.verify()
    assert integrity.ok is False
    assert integrity.broken_at_seq == 2


def test_ledger_detects_reorder(populated):
    ledger, _ = populated
    path = ledger.path
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
    assert ledger.verify().ok is False


def test_ledger_detects_deletion(populated):
    ledger, _ = populated
    path = ledger.path
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[-1] + "\n", encoding="utf-8")
    integrity = ledger.verify()
    assert integrity.ok is False  # seq reset + predecessor broken


def test_find_blocked(populated):
    ledger, _ = populated
    blocked = ledger.find_blocked()
    assert len(blocked) == 1
    assert blocked[0].decision == "block"


def test_build_report_and_markdown(populated):
    ledger, _ = populated
    report = build_report(
        ledger, incident_title="T", reporter="R",
        remediation_notes=["revoked key", "notified owner"],
    )
    assert report["evidence_integrity"]["ok"] is True
    assert len(report["timeline"]) == 1  # blocked only by default
    md = report_to_markdown(report)
    assert "# T" in md
    assert "revoked key" in md
    assert "DISCLAIMER" in md or "Disclaimer" in md


def test_report_include_allowed(populated):
    ledger, _ = populated
    report = build_report(ledger, include_allowed=True)
    assert len(report["timeline"]) == 2
