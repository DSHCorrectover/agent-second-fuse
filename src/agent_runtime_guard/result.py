# -*- coding: utf-8 -*-
"""
result.py — GuardResult 数据类

所有安全检查层的统一返回值。每个 Layer 与 SecurityKernel.guard()
都返回 GuardResult，保证调用方只需处理一种结果类型。

设计语义:
    - allowed: 检查是否放行 (True=放行, False=拦截)
    - module:  触发拦截/放行的安全层标识
    - rule:    触发规则标识 (如 Rule1_PersonalityOverride / AuthorityToolPolicy)
    - action:  被检查的工具名或动作名
    - reason:  人类可读的拦截/放行原因
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class ComplianceItem:
    """一条合规依据 (法规名称 + 条款 + 具体要求)。

    由策略的 compliance_mapping 节点提供, 拦截结果通过
    GuardResult.compliance 注入, 用于金融审计展示 (如:
    《证券期货业信息安全保障管理办法》第24条 — 未经授权不得执行系统级命令)。
    """

    regulation: str
    """法规名称 + 条款 (如 "《证券法》第195条")。"""
    requirement: str
    """具体要求 (如 "任何交易指令必须经人工审批")。"""

    def to_dict(self) -> Dict[str, Any]:
        return {"regulation": self.regulation, "requirement": self.requirement}


@dataclass
class GuardResult:
    """一次安全检查的结果。

    Attributes:
        allowed:    True=放行, False=拦截
        module:     安全层标识 (authority / mutation / constitution / identity / kernel)
        reason:     拦截或放行的原因
        action:     被检查的工具名 / 动作名 (如 execute_shell, amend_weight)
        rule:       触发的规则标识 (便于审计聚合)
        details:    附加诊断信息 (参数快照 / 状态值)
        compliance: 拦截时注入的合规依据列表 ([ComplianceItem])
        timestamp:  检查时间戳 (UTC ISO-8601)
    """

    allowed: bool
    module: str = ""
    reason: str = ""
    action: str = ""
    rule: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    compliance: list = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    )

    @property
    def blocked(self) -> bool:
        """True 表示该动作被安全策略拦截。"""
        return not self.allowed

    @property
    def passed(self) -> bool:
        """True 表示该动作通过安全检查。"""
        return self.allowed

    def to_dict(self) -> Dict[str, Any]:
        """序列化为 dict，便于写入 aisi_report.json / 审计日志。"""
        out: Dict[str, Any] = {
            "allowed": self.allowed,
            "module": self.module,
            "rule": self.rule,
            "action": self.action,
            "reason": self.reason,
            "details": self.details,
            "timestamp": self.timestamp,
        }
        if self.compliance:
            out["compliance"] = [
                item.to_dict() if hasattr(item, "to_dict") else item
                for item in self.compliance
            ]
        return out

    def log_line(self, agent_id: str = "agent") -> str:
        """格式化为统一拦截日志行 (供日志采集 / 报告提取)。"""
        verdict = "被拦截" if self.blocked else "放行"
        rule_tag = f" ({self.rule})" if self.rule else ""
        return (
            f"[agent-runtime-guard] [{agent_id}] [{self.module}] "
            f"动作 {self.action} {verdict}{rule_tag}: {self.reason}"
        )

    @classmethod
    def allow(
        cls,
        module: str,
        action: str,
        reason: str = "通过安全检查",
        rule: str = "",
        details: Optional[Dict[str, Any]] = None,
        compliance: Optional[list] = None,
    ) -> "GuardResult":
        """构造放行结果。"""
        return cls(
            allowed=True,
            module=module,
            reason=reason,
            action=action,
            rule=rule,
            details=details or {},
            compliance=compliance or [],
        )

    @classmethod
    def block(
        cls,
        module: str,
        action: str,
        reason: str,
        rule: str = "",
        details: Optional[Dict[str, Any]] = None,
        compliance: Optional[list] = None,
    ) -> "GuardResult":
        """构造拦截结果。"""
        return cls(
            allowed=False,
            module=module,
            reason=reason,
            action=action,
            rule=rule,
            details=details or {},
            compliance=compliance or [],
        )


@dataclass
class Snapshot:
    """内核状态快照 (版本化)。

    由 SecurityKernel.snapshot() 产生。state 为深拷贝的快照数据,
    回滚时据此恢复内核状态 (版本化状态恢复)。
    """

    version_id: str
    """快照版本号 (如 snap-0001)。"""
    state: Dict[str, Any]
    """快照状态 (深拷贝), 包含 identity_baseline / decision_log / policy。"""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version_id": self.version_id,
            "created_at": self.created_at,
            "state": self.state,
        }


@dataclass
class RollbackEvent:
    """一次回滚事件记录。

    由 SecurityKernel.rollback() 产生, 追加到 rollback_events 日志,
    记录回滚目标版本、原因与恢复结果。
    """

    version_id: str
    """回滚到的快照版本号。"""
    reason: str
    """回滚原因。"""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    )
    restored: Dict[str, Any] = field(default_factory=dict)
    """恢复结果摘要 (如 identity_baseline / decision_log_len)。"""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version_id": self.version_id,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "restored": self.restored,
            "details": self.details,
        }
