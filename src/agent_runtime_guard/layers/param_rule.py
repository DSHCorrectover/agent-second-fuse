# -*- coding: utf-8 -*-
"""
layers/param_rule.py — 参数级业务规则引擎 (Param Rule Layer)

对已放行工具的参数做业务级风险判定 (v0.1.0 新增能力):

    - 规则来源: PolicyConfig.param_rules
    - 规则 schema: {tool_name: [ {field, operator, value, action, reason}, ... ]}
    - 支持操作符: gt / lt / gte / lte / eq / neq / in / not_in / regex (v0.1.5)
    - 支持 action: block (拦截) / warn (放行但标记)
    - field 支持点号嵌套路径 (如 "config.timeout")

与 Mutation 层 (危险模式子串匹配) 的区别:
    本层做参数值的语义判定 (如 amount > 阈值 / table 是否核心表),
    而非对序列化参数文本做关键词匹配。
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional

from ..policy import PolicyConfig
from ..result import GuardResult


class ParamRuleEngine:
    """参数级业务规则引擎层。

    Args:
        policy: PolicyConfig (提供 param_rules)
    """

    MODULE = "param_rule"

    _OPERATORS = {
        "gt": lambda a, b: a > b,
        "lt": lambda a, b: a < b,
        "gte": lambda a, b: a >= b,
        "lte": lambda a, b: a <= b,
        "eq": lambda a, b: a == b,
        "neq": lambda a, b: a != b,
        "in": lambda a, b: a in b,
        "not_in": lambda a, b: a not in b,
    }

    def __init__(self, policy: PolicyConfig) -> None:
        self._rules: Dict[str, List[Dict[str, Any]]] = policy.param_rules or {}

    def check(
        self,
        action: str,
        arguments: Optional[Dict[str, Any]] = None,
        **context: Any,
    ) -> GuardResult:
        """按 action 的规则列表逐条判定; 命中 block 即拦截, 命中 warn 即放行标记。

        Args:
            action:    工具名
            arguments: 工具参数 (按 rule.field 取值判定)

        Returns:
            GuardResult
        """
        args = arguments or {}
        for rule in self._rules.get(action, []):
            field = rule.get("field")
            value = self._get_field(args, field)
            if value is None:
                continue  # 字段缺失 → 本条规则不适用
            op = rule.get("operator")
            if op == "regex":
                try:
                    hit = re.search(str(rule.get("value", "")), str(value)) is not None
                except re.error:
                    hit = False
            elif op in ("in", "not_in"):
                hit = self._in_value(value, rule.get("value"))
                if op == "not_in":
                    hit = not hit
            else:
                op_fn = self._OPERATORS.get(op)
                if op_fn is None:
                    continue
                hit = op_fn(value, rule.get("value"))
            if hit:
                details = {
                    "field": field,
                    "operator": op,
                    "expected": rule.get("value"),
                    "actual": value,
                }
                if rule.get("action") == "warn":
                    return GuardResult.allow(
                        module=self.MODULE,
                        action=action,
                        reason=rule.get("reason")
                        or f"参数规则告警: {field} {op} 条件命中",
                        rule="ParamRuleWarn",
                        details=details,
                    )
                return GuardResult.block(
                    module=self.MODULE,
                    action=action,
                    reason=rule.get("reason")
                    or f"参数规则拦截: {field} {op} 条件命中",
                    rule="ParamRuleBlock",
                    details=details,
                )
        return GuardResult.allow(
            module=self.MODULE,
            action=action,
            reason="参数级业务规则全部通过",
            rule="ParamRulesPass",
        )

    @staticmethod
    def _get_field(data: Dict[str, Any], field_path: str) -> Any:
        """按点号路径取嵌套字段 (如 "a.b.c"); 不存在返回 None。"""
        if not field_path:
            return None
        cur: Any = data
        for part in str(field_path).split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur

    @staticmethod
    def _in_value(field_val: Any, candidates: Any) -> bool:
        """in 语义: 字面成员匹配; IP 字段额外支持 CIDR 网段包含 (v0.1.3 新增)。

        示例: field_val="192.168.1.10", candidates=["192.168.0.0/16"] → True
        """
        if isinstance(candidates, (list, tuple, set)):
            if field_val in candidates:
                return True
            if isinstance(field_val, str):
                try:
                    ip = ipaddress.ip_address(field_val)
                except ValueError:
                    return False
                for c in candidates:
                    if isinstance(c, str):
                        try:
                            if ip in ipaddress.ip_network(c, strict=False):
                                return True
                        except ValueError:
                            continue
            return False
        return field_val in candidates
