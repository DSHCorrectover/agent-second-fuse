# -*- coding: utf-8 -*-
"""
guarded.py — GuardedKernel：第二熔断门面

在规则引擎 SecurityKernel 之上叠加「裁决留证」层：每次 guard() 不仅做
fail-closed 拦截，还把裁决签成 Ed25519 收据并追加到 append-only 台账。
这样被拦截动作有不可篡改的证据，放行动作也有据可查——日志可查升级为
运行时可控、证据可验。

用法：
    from agent_runtime_guard import GuardedKernel, PolicyConfig

    kernel = GuardedKernel.bootstrap(
        PolicyConfig.builtin("general"),
        evidence_dir=".guard-evidence",
        agent_id="checkout-agent",
    )
    result = kernel.guard("execute_shell", {"command": "sudo rm -rf /"})
    result.blocked          # True
    result.receipt.decision # "block"
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .incident import build_report, report_to_markdown
from .kernel import SecurityKernel
from .keys import Signer
from .ledger import EventLedger, LedgerIntegrity
from .policy import PolicyConfig
from .receipt import Receipt, ReceiptSigner
from .result import GuardResult


@dataclass
class GuardedResult:
    """底座裁决 + 收据。"""

    result: GuardResult
    receipt: Receipt

    @property
    def blocked(self) -> bool:
        return self.result.blocked

    @property
    def passed(self) -> bool:
        return self.result.passed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result": self.result.to_dict(),
            "receipt_id": self.receipt.receipt_id,
        }


class GuardedKernel:
    """带裁决留证的安全内核（第二熔断）。"""

    def __init__(
        self,
        policy: PolicyConfig,
        evidence_dir: os.PathLike[str] | str,
        *,
        agent_id: str = "agent",
        enable_identity: bool = True,
        record_parameters: bool = True,
    ) -> None:
        self.kernel = SecurityKernel(policy, enable_identity=enable_identity)
        self._evidence_dir = Path(evidence_dir)
        self._evidence_dir.mkdir(parents=True, exist_ok=True)

        self._agent_id = agent_id
        self._record_parameters = record_parameters
        self.signer = Signer.load_or_create(self._evidence_dir / "keys")
        self.receipt_signer = ReceiptSigner(self.signer)
        self.ledger = EventLedger(self._evidence_dir / "ledger")

    # ------------------------------------------------------------------
    @classmethod
    def bootstrap(
        cls,
        policy: PolicyConfig,
        evidence_dir: os.PathLike[str] | str = ".guard-evidence",
        *,
        agent_id: str = "agent",
        **kwargs: Any,
    ) -> "GuardedKernel":
        return cls(policy, evidence_dir, agent_id=agent_id, **kwargs)

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def kid(self) -> str:
        return self.signer.kid

    # ------------------------------------------------------------------
    def guard(
        self,
        action: str,
        arguments: Optional[Dict[str, Any]] = None,
        *,
        agent_id: Optional[str] = None,
        **kwargs: Any,
    ) -> GuardedResult:
        """裁决一次动作，签发收据并入台账。

        其余参数 (text/operation/payload/poi/risk/profile/...) 与
        SecurityKernel.guard 相同，透传给规则引擎。
        """
        result = self.kernel.guard(action, arguments=arguments, **kwargs)

        recorded_params: Optional[Dict[str, Any]]
        recorded_params = arguments if self._record_parameters else None

        receipt = self.receipt_signer.issue(
            decision="block" if result.blocked else "allow",
            action=action,
            layer=result.module,
            rule=result.rule,
            reason=result.reason,
            agent_id=agent_id or self._agent_id,
            parameters=recorded_params,
            details=result.details or None,
        )
        self.ledger.append(receipt)
        return GuardedResult(result=result, receipt=receipt)

    # ------------------------------------------------------------------
    def verify_evidence(self) -> LedgerIntegrity:
        """校验台账哈希链完整性。"""
        return self.ledger.verify()

    def stats(self) -> Dict[str, Any]:
        base = self.kernel.stats()
        base["ledger_entries"] = self.ledger.count()
        base["kid"] = self.kid
        return base

    def incident_report(
        self,
        *,
        title: str = "AI Agent runtime incident",
        reporter: str = "",
        remediation_notes: Optional[List[str]] = None,
        include_allowed: bool = False,
    ) -> Dict[str, Any]:
        """从台账生成结构化事件报告。"""
        return build_report(
            self.ledger,
            incident_title=title,
            reporter=reporter,
            remediation_notes=remediation_notes,
            include_allowed=include_allowed,
        )

    def incident_report_markdown(self, **kwargs: Any) -> str:
        return report_to_markdown(self.incident_report(**kwargs))
