# -*- coding: utf-8 -*-
"""
layers/authority.py — 工具黑白名单检查 (Authority Layer)

实现工具治理语义的最简形态:
    工具级 ACL (Access Control List)。deny 优先, allow 兜底, 未知工具默认 fail-closed
    (可通过策略 unknown_tool_default="allow" 切换为白名单模式)。

语义对齐:
    - deny_tools 命中       → 拦截 (Rule: AuthorityToolDeny)
    - allow_tools 非空且未命中 → 按 unknown_tool_default 判定
        (默认 "block" → fail-closed 拦截; "allow" → 放行)
    - allow_tools 为空       → 不限制 (仅依赖下层规则)
"""

from typing import Any, Dict, List, Optional

from ..policy import PolicyConfig
from ..result import GuardResult


class AuthorityLayer:
    """工具黑白名单检查层。

    Args:
        policy: PolicyConfig (提供 allow_tools / deny_tools / unknown_tool_default)
    """

    MODULE = "authority"

    def __init__(self, policy: PolicyConfig) -> None:
        self._policy = policy
        self._deny: set = set(policy.deny_tools)
        self._allow: set = set(policy.allow_tools)
        self._unknown_default: str = (policy.unknown_tool_default or "block").lower()

    def check(
        self,
        action: str,
        arguments: Optional[Dict[str, Any]] = None,
        **context: Any,
    ) -> GuardResult:
        """检查工具名是否在黑白名单内。

        Args:
            action:    工具名 (如 execute_shell, write_to_file)
            arguments: 工具参数 (仅供 details 记录, 本层不做参数级检查)

        Returns:
            GuardResult: 拦截或放行
        """
        # deny 优先 (强约束: 即使 allow 列表也拒绝)
        if action in self._deny:
            return GuardResult.block(
                module=self.MODULE,
                action=action,
                reason=f"工具 {action} 在 deny 名单中",
                rule="AuthorityToolDeny",
                details={"deny_tools": sorted(self._deny)},
                compliance=self._policy.get_compliance("tools", action),
            )

        # allow 列表存在时: 白名单外工具按 unknown_tool_default 判定 (默认 fail-closed)
        if self._allow and action not in self._allow:
            if self._unknown_default == "allow":
                return GuardResult.allow(
                    module=self.MODULE,
                    action=action,
                    reason=f"工具 {action} 不在 allow 名单, 按 unknown_tool_default=allow 放行",
                    rule="AuthorityToolAllowedByDefault",
                    details={"allow_tools": sorted(self._allow)},
                )
            return GuardResult.block(
                module=self.MODULE,
                action=action,
                reason=f"工具 {action} 不在 allow 名单中 (fail-closed)",
                rule="AuthorityToolNotAllowed",
                details={"allow_tools": sorted(self._allow)},
                compliance=self._policy.get_compliance("tools", action),
            )

        return GuardResult.allow(
            module=self.MODULE,
            action=action,
            reason=f"工具 {action} 通过名单检查",
            rule="AuthorityToolAllowed",
            details={"arguments": arguments or {}},
        )
