# -*- coding: utf-8 -*-
"""
agent_runtime_guard — Agent 第二熔断与事件取证 (v0.3.0)

能力：
  1) 规则引擎 SecurityKernel：工具 ACL → 参数规则 → 危险模式 → fail-closed。
  2) GuardedKernel：每次裁决叠加 Ed25519 签名收据 + append-only 哈希链台账。
  3) 强制点：GuardedTool/wrap_tool（进程内绕不过）+ 进程外独立裁决 proxy
     （独立信任域，只裁决不执行）。
  4) human-approval 审批门（裁决与参数指纹绑定）。
  5) SIEM 导出（NDJSON/CEF + Splunk HEC/generic webhook）。
  6) 外部锚定（链头提交见证服务，把本地自证升级为外部存在性证明）。
"""

from .anchor import AnchorLog, NotaryWebhookProvider
from .approval import ApprovalGate, ApprovalRequest, request_fingerprint
from .exceptions import ApprovalRequired, BlockedActionError, GuardError
from .guarded import GuardedKernel, GuardedResult
from .incident import build_report, report_to_markdown
from .kernel import SecurityKernel
from .keys import Signer
from .ledger import EventLedger, LedgerIntegrity
from .policy import PolicyConfig
from .proxy import build_handler, build_kernel, serve
from .receipt import Receipt, ReceiptSigner, verify_receipt
from .result import GuardResult, RollbackEvent, Snapshot
from .siem import export_file, post_webhook, receipt_to_event, to_cef, to_ndjson
from .wrap import GuardedTool, wrap_tool, wrap_tools

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
    # 强制点
    "GuardedTool",
    "wrap_tool",
    "wrap_tools",
    "BlockedActionError",
    "ApprovalRequired",
    "GuardError",
    # 审批
    "ApprovalGate",
    "ApprovalRequest",
    "request_fingerprint",
    # SIEM
    "receipt_to_event",
    "to_ndjson",
    "to_cef",
    "export_file",
    "post_webhook",
    # 锚定
    "AnchorLog",
    "NotaryWebhookProvider",
    # proxy
    "build_handler",
    "build_kernel",
    "serve",
]

__version__ = "0.3.0"
