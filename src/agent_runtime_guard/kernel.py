# -*- coding: utf-8 -*-
"""
kernel.py — SecurityKernel 统一安全入口

Security Guard 的核心门面。按固定顺序串联安全层:

    guard() → authority → param_rule → mutation → constitution → identity (短路)

任一 Layer 拦截 (blocked) 立即返回, 不再执行后续层。全部放行才返回
最终 GuardResult (module="kernel")。

设计语义:
    - 单一入口: 所有安全决策经 SecurityKernel.guard()
    - 层序固定: 工具 ACL → 参数级业务规则 → 危险/自我修改 → 宪法不可变 → 身份连续性
    - 审计可追踪: 每次调用记录 decision_log

v0.1.7 核心内核: 仅包含规则引擎 (五层裁决 + 身份基线 + 内存决策日志 +
版本化快照回滚)。
"""

from typing import Any, Dict, List, Optional
from copy import deepcopy

from .layers.authority import AuthorityLayer
from .layers.constitution import ConstitutionLayer
from .layers.identity import IdentityLayer
from .layers.mutation import MutationLayer
from .layers.param_rule import ParamRuleEngine
from .policy import PolicyConfig
from .result import GuardResult, RollbackEvent, Snapshot


class SecurityKernel:
    """统一安全内核。

    Args:
        policy: PolicyConfig (安全策略单一来源)
        enable_identity: 是否启用身份连续性检查 (默认启用)

    Example:
        >>> kernel = SecurityKernel(PolicyConfig.from_json("policies/general.json"))
        >>> result = kernel.guard("execute_shell", arguments={"command": "sudo rm -rf /"})
        >>> result.blocked
        True
    """

    def __init__(
        self,
        policy: PolicyConfig,
        enable_identity: bool = True,
    ) -> None:
        self._policy = policy
        self._enable_identity = enable_identity
        # 组装安全层 (层序固定: ACL → 参数规则 → 危险模式 → 宪法 → 身份)
        self.authority = AuthorityLayer(policy)
        self.param_rule = ParamRuleEngine(policy)
        self.mutation = MutationLayer(policy)
        self.constitution = ConstitutionLayer(policy)
        self.identity = IdentityLayer(policy)
        self._log: List[GuardResult] = []
        self._identity_baseline: Optional[str] = None
        # 快照回滚: 版本化状态保存
        self._snapshots: List[Snapshot] = []
        self._snapshot_counter: int = 0
        self._rollback_events: List[RollbackEvent] = []

    # ------------------------------------------------------------------
    # 统一入口
    # ------------------------------------------------------------------
    def guard(
        self,
        action: str,
        arguments: Optional[Dict[str, Any]] = None,
        text: Optional[str] = None,
        operation: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        vector: Optional[Dict[str, float]] = None,
        poi: Optional[float] = None,
        risk: Optional[float] = None,
        profile: Optional[Dict[str, Any]] = None,
        directives: Optional[Dict[str, Any]] = None,
        **context: Any,
    ) -> GuardResult:
        """对一次动作执行全链路安全检查 (短路)。

        Args:
            action:    工具名 / 动作名 (必填)
            arguments: 工具参数 (危险模式匹配)
            text:      提示/约束文本 (自我修改检测)
            operation: 宪法操作类型 (如 update_weight)
            payload:   宪法修改载荷 (dimension 等)
            vector:    权重向量快照 (可选, 不变量检查)
            poi:       人格覆盖风险指标 [0,1]
            risk:      通用风险分数 [0,1]
            profile:   身份画像 dict
            directives:指令集 dict

        Returns:
            GuardResult (blocked 即拦截)
        """
        layers = [
            # 1. 工具黑白名单
            self.authority.check(action, arguments=arguments),
            # 2. 参数级业务规则
            self.param_rule.check(action, arguments=arguments),
            # 3. 危险模式 + 自我修改
            self.mutation.check(action, arguments=arguments, text=text,
                                poi=poi, risk=risk),
            # 4. 宪法不可变
            self.constitution.check(action, operation=operation,
                                    payload=payload, vector=vector),
            # 5. 身份连续性
            self._check_identity(action, profile, directives),
        ]

        for result in layers:
            if result.blocked:
                self._log.append(result)
                return result

        final = GuardResult.allow(
            module="kernel",
            action=action,
            reason="全部安全层通过",
            rule="AllLayersPass",
        )
        self._log.append(final)
        return final

    # ------------------------------------------------------------------
    # 身份状态管理
    # ------------------------------------------------------------------
    def set_identity_baseline(
        self,
        profile: Optional[Dict[str, Any]] = None,
        directives: Optional[Dict[str, Any]] = None,
    ) -> str:
        """建立/更新身份基线哈希。

        Returns:
            新的基线哈希
        """
        self._identity_baseline = self.identity.compute_identity_hash(
            profile, directives
        )
        return self._identity_baseline

    def _check_identity(
        self,
        action: str,
        profile: Optional[Dict[str, Any]],
        directives: Optional[Dict[str, Any]],
    ) -> GuardResult:
        """身份连续性检查 (维护内部基线)。"""
        if not self._enable_identity or (profile is None and directives is None):
            return GuardResult.allow(
                module="identity", action=action,
                reason="身份检查未启用或无身份输入", rule="IdentitySkipped",
            )
        cur_hash = self.identity.compute_identity_hash(profile, directives)
        result = self.identity.check(self._identity_baseline, cur_hash, action=action)
        if result.passed and result.rule != "IdentityBaselineEstablished":
            # 放行且非首次 → 基线推进到当前 (仅记录, 不用于拦截)
            self._identity_baseline = cur_hash
        return result

    # ------------------------------------------------------------------
    # 审计
    # ------------------------------------------------------------------
    def decision_log(self) -> List[Dict[str, Any]]:
        """返回全部决策记录 (dict 列表, 可写审计文件)。"""
        return [r.to_dict() for r in self._log]

    def stats(self) -> Dict[str, Any]:
        """聚合统计: 总调用 / 拦截数 / 按模块拦截数。"""
        total = len(self._log)
        blocked = [r for r in self._log if r.blocked]
        per_module: Dict[str, int] = {}
        for r in blocked:
            per_module[r.module] = per_module.get(r.module, 0) + 1
        return {
            "total_calls": total,
            "blocked": len(blocked),
            "allowed": total - len(blocked),
            "blocked_by_module": per_module,
        }

    def clear_log(self) -> None:
        """清空决策日志。"""
        self._log.clear()

    # ------------------------------------------------------------------
    # 快照回滚 (版本化回滚)
    # ------------------------------------------------------------------
    def snapshot(self, reason: str = "manual") -> Snapshot:
        """捕获当前内核状态快照 (版本递增)。

        快照包含: 身份基线 / 决策日志 / 策略配置 (均为深拷贝)。

        Returns:
            Snapshot (version_id 形如 snap-0001)
        """
        self._snapshot_counter += 1
        version_id = f"snap-{self._snapshot_counter:04d}"
        state: Dict[str, Any] = {
            "identity_baseline": self._identity_baseline,
            "decision_log": [r.to_dict() for r in self._log],
            "policy": self._policy.to_dict(),
        }
        snap = Snapshot(version_id=version_id, state=deepcopy(state))
        self._snapshots.append(snap)
        return snap

    def rollback(self, version_id: str, reason: str = "security_rollback") -> RollbackEvent:
        """回滚内核状态到指定快照版本。

        恢复 identity_baseline 与 decision_log 到快照时刻, 并记录 RollbackEvent。

        Args:
            version_id: 目标快照版本号 (来自 snapshot() 返回值)
            reason:     回滚原因 (审计用)

        Returns:
            RollbackEvent

        Raises:
            ValueError: 快照版本不存在
        """
        target = next((s for s in self._snapshots if s.version_id == version_id), None)
        if target is None:
            raise ValueError(f"unknown snapshot version: {version_id!r}")

        state = target.state
        self._identity_baseline = state["identity_baseline"]
        self._log = [GuardResult(**deepcopy(d)) for d in state["decision_log"]]
        restored = {
            "identity_baseline": self._identity_baseline,
            "decision_log_len": len(self._log),
            "snapshot_created_at": target.created_at,
        }
        event = RollbackEvent(
            version_id=version_id,
            reason=reason,
            restored=restored,
            details={"snapshots_count": len(self._snapshots)},
        )
        self._rollback_events.append(event)
        return event

    def snapshots(self) -> List[Dict[str, Any]]:
        """返回全部快照索引 (version_id + created_at, 不含状态体)。"""
        return [
            {"version_id": s.version_id, "created_at": s.created_at}
            for s in self._snapshots
        ]

    def rollback_events(self) -> List[Dict[str, Any]]:
        """返回全部回滚事件记录。"""
        return [e.to_dict() for e in self._rollback_events]
