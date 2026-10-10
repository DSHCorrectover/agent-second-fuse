# -*- coding: utf-8 -*-
"""
layers/constitution.py — 不可变原则检查 (Constitution Layer)

实现不可变维度检查语义:

    - 不可变维度 (默认 truth/safety) 权重禁止运行时修改
    - 修改请求 payload 中 dimension ∈ immutables → 拦截
    - 权重向量不变量: 所有权重非负 + 不可变维度保持基线值
"""

from typing import Any, Dict, Optional

from ..policy import PolicyConfig
from ..result import GuardResult

# 兜底不可变维度
_DEFAULT_IMMUTABLES = ("truth", "safety")


class ConstitutionLayer:
    """不可变原则检查层。

    Args:
        policy: PolicyConfig (提供 immutables 维度列表)
    """

    MODULE = "constitution"

    def __init__(self, policy: PolicyConfig) -> None:
        self._policy = policy
        self._immutables: tuple = tuple(policy.immutables) or _DEFAULT_IMMUTABLES

    # ------------------------------------------------------------------
    # 入口
    # ------------------------------------------------------------------
    def check(
        self,
        action: str,
        operation: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        vector: Optional[Dict[str, float]] = None,
        **context: Any,
    ) -> GuardResult:
        """检查宪法修改请求是否触碰不可变维度。

        Args:
            action:    动作名 (如 amend_weight, update_weight)
            operation: 操作类型 (如 "update_weight", "amend_weight")
            payload:   修改载荷 (须含 dimension 键)
            vector:    权重向量快照 (可选, 用于不变量检查)

        Returns:
            GuardResult
        """
        # ---- 不可变维度修改检查 ----
        dimension = self._extract_dimension(payload)
        if dimension is not None:
            if dimension in self._immutables:
                return GuardResult.block(
                    module=self.MODULE,
                    action=action,
                    reason=(
                        f"维度 '{dimension}' 属于不可变域 {list(self._immutables)}"
                    ),
                    rule="ConstitutionImmutableDimension",
                    details={"dimension": dimension, "immutables": list(self._immutables)},
                    compliance=self._policy.get_compliance("constitution"),
                )

        # ---- 权重向量不变量检查 (可选) ----
        if vector is not None:
            bad = self._check_vector_invariants(vector)
            if bad:
                return GuardResult.block(
                    module=self.MODULE,
                    action=action,
                    reason=bad,
                    rule="ConstitutionInvariant",
                    details={"vector": vector},
                )

        return GuardResult.allow(
            module=self.MODULE,
            action=action,
            reason="未触碰不可变维度, 宪法不变量满足",
            rule="ConstitutionInvariantPass",
        )

    # ------------------------------------------------------------------
    # 工具
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_dimension(payload: Optional[Dict[str, Any]]) -> Optional[str]:
        """从载荷中提取目标维度名。"""
        if not isinstance(payload, dict):
            return None
        dim = payload.get("dimension")
        return str(dim) if dim else None

    def _check_vector_invariants(self, vector: Dict[str, float]) -> Optional[str]:
        """检查权重向量不变量, 返回违规描述 (无违规返回 None)。

        Invariants:
            1. 所有权重非负
            2. 不可变维度必须存在于向量中 (完整性)
        """
        for dim, weight in vector.items():
            if not isinstance(weight, (int, float)) or weight < 0.0:
                return f"权重 '{dim}' 为负或非法值: {weight!r}"
        for dim in self._immutables:
            if dim not in vector:
                return f"不可变维度 '{dim}' 缺失 (维度完整性违反)"
        return None
