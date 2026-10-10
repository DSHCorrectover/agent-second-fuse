# -*- coding: utf-8 -*-
"""Integration tests for GuardedKernel (the second fuse)."""

import pytest

from agent_runtime_guard import GuardedKernel, PolicyConfig


@pytest.fixture()
def kernel(tmp_path):
    return GuardedKernel.bootstrap(
        PolicyConfig.builtin("general"),
        tmp_path / "evidence",
        agent_id="agent-1",
    )


def test_allow_path_is_receipted(kernel):
    out = kernel.guard("read_file", {"filename": "a.txt"})
    assert out.passed is True
    assert out.receipt.decision == "allow"


def test_block_path_is_receipted_and_chain_intact(kernel):
    out = kernel.guard("execute_shell", {"command": "sudo rm -rf /"})
    assert out.blocked is True
    assert out.receipt.decision == "block"
    integrity = kernel.verify_evidence()
    assert integrity.ok is True


def test_unknown_tool_fail_closed(kernel):
    out = kernel.guard("totally_unknown", {})
    assert out.blocked is True


def test_finance_builtin_blocks_large_amount(tmp_path):
    k = GuardedKernel.bootstrap(
        PolicyConfig.builtin("finance"), tmp_path / "ev", agent_id="fin"
    )
    assert k.guard("fund_transfer", {"amount": 50_000_000}).blocked is True
    assert k.guard("fund_transfer", {"amount": 100}).passed is True


def test_builtin_unknown_raises():
    with pytest.raises(ValueError):
        PolicyConfig.builtin("nope")


def test_no_parameter_recording(tmp_path):
    k = GuardedKernel.bootstrap(
        PolicyConfig.builtin("general"), tmp_path / "ev",
        agent_id="a", record_parameters=False,
    )
    out = k.guard("read_file", {"filename": "secret.txt"})
    assert "parameters" not in out.receipt.payload
