# -*- coding: utf-8 -*-
"""
layers/identity.py — 身份哈希对比 (Identity Layer)

实现身份连续性语义 (OP-12 / check_continuity 的最简形态):

    - compute_identity_hash(profile, directives): 对身份相关状态做 SHA-256 快照
    - check(prev_hash, cur_hash): 身份快照变化时, 判定连续性

判定规则 (对齐 IdentityContinuityResult.is_continuous ∈ {0,1}):
    - prev == cur             → 连续 (放行)
    - prev 为空 (首次)        → 建立基线 (放行, 不判定)
    - 变化但仍在白名单字段    → 视为连续 (放行)
    - 变化且涉及核心身份字段  → 不连续 (拦截)
"""

import hashlib
import json
from typing import Any, Dict, List, Optional

from ..policy import PolicyConfig
from ..result import GuardResult

# 核心身份字段: 变化即视为身份漂移
_CORE_IDENTITY_FIELDS = ("name", "role", "constraints")


class IdentityLayer:
    """身份哈希对比层。

    Args:
        policy: PolicyConfig (可选, 提供 identity_drift 合规依据)
    """

    MODULE = "identity"

    def __init__(self, policy: Optional[PolicyConfig] = None) -> None:
        self._policy = policy

    def check(
        self,
        prev_hash: Optional[str],
        cur_hash: str,
        action: str = "identity_state",
        changed_fields: Optional[List[str]] = None,
    ) -> GuardResult:
        """对比前后身份快照哈希。

        Args:
            prev_hash:  上一轮身份哈希 (None 表示首次, 建立基线)
            cur_hash:   当前身份哈希
            action:     动作名 (日志用)
            changed_fields: 发生变化的字段列表 (可选, 用于细分判定)

        Returns:
            GuardResult
        """
        if prev_hash is None:
            return GuardResult.allow(
                module=self.MODULE,
                action=action,
                reason="首次快照, 建立身份基线",
                rule="IdentityBaselineEstablished",
                details={"hash": cur_hash[:16]},
            )

        if prev_hash == cur_hash:
            return GuardResult.allow(
                module=self.MODULE,
                action=action,
                reason="身份快照未变化, 连续性保持",
                rule="IdentityContinuous",
            )

        # 变化但仅限非核心字段 → 连续
        if changed_fields and not any(
            f in _CORE_IDENTITY_FIELDS for f in changed_fields
        ):
            return GuardResult.allow(
                module=self.MODULE,
                action=action,
                reason=f"身份快照变化但仅限非核心字段 {changed_fields}",
                rule="IdentityContinuous",
                details={"changed_fields": changed_fields},
            )

        return GuardResult.block(
            module=self.MODULE,
            action=action,
            reason="身份漂移被检出: 核心身份字段发生变化",
            rule="IdentityDiscontinuity",
            details={
                "prev_hash": prev_hash[:16],
                "cur_hash": cur_hash[:16],
                "changed_fields": changed_fields,
            },
            compliance=self._policy.get_compliance("identity_drift")
            if self._policy
            else [],
        )

    # ------------------------------------------------------------------
    # 工具
    # ------------------------------------------------------------------
    @staticmethod
    def compute_identity_hash(
        profile: Optional[Dict[str, Any]] = None,
        directives: Optional[Dict[str, Any]] = None,
    ) -> str:
        """基于 AI profile + directives 计算身份快照哈希。

        Args:
            profile:    身份画像 (name / role / goals)
            directives: 指令集 (constraints / resources / best_practices)

        Returns:
            SHA-256 十六进制哈希
        """
        profile = profile or {}
        directives = directives or {}
        blob = {
            "name": profile.get("name", ""),
            "role": profile.get("role", ""),
            "goals": list(profile.get("goals", []) or []),
            "constraints": list(directives.get("constraints", []) or []),
            "resources": list(directives.get("resources", []) or []),
            "best_practices": list(directives.get("best_practices", []) or []),
        }
        raw = json.dumps(blob, ensure_ascii=False, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
