# -*- coding: utf-8 -*-
"""
agent_runtime_guard — Agent 第二熔断与事件取证 (v0.2.0)

两层能力：
  1) 规则引擎 SecurityKernel：工具 ACL → 参数规则 → 危险模式 → 宪法不可变
     → 身份连续性（fail-closed 短路裁决）。
  2) 第二熔断 GuardedKernel：在每次裁决上叠加 Ed25519 签名收据与 append-only
     哈希链台账，并可导出对齐 2026-10-09 白宫强制上报令的 incident report。
"""

from .guarded import GuardedKernel, GuardedResult
from .incident import build_report, report_to_markdown
from .kernel import SecurityKernel
from .keys import Signer
from .ledger import EventLedger, LedgerIntegrity
from .policy import PolicyConfig
from .receipt import Receipt, ReceiptSigner, verify_receipt
from .result import GuardResult, RollbackEvent, Snapshot

__all__ = [
    # 第二熔断
    "GuardedKernel",
    "GuardedResult",
    "Signer",
    "Receipt",
    "ReceiptSigner",
    "verify_receipt",
    "EventLedger",
    "LedgerIntegrity",
    "build_report",
    "report_to_markdown",
    # 规则引擎
    "SecurityKernel",
    "PolicyConfig",
    "GuardResult",
    "Snapshot",
    "RollbackEvent",
]

__version__ = "0.2.0"
