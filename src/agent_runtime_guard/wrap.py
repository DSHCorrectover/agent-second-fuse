# -*- coding: utf-8 -*-
"""wrap.py — 强制点（enforcement point）。

"独立于被监控 agent" 要成立，关键是工具只能通过受控入口被调用。本模块把
任意可调用工具包成 GuardedTool：agent 拿到的对象本身就是受控的，调用它就
一定先过第二熔断——没有一条"直接调原始工具"的路径暴露给 agent。

裁决语义（fail-closed）：
- 策略 block          -> 抛 BlockedActionError，函数体绝不执行；
- 需要审批且未批准     -> 抛 ApprovalRequired（动作保持 pending），不执行；
- 策略 allow 且审批满足 -> 执行原始函数，返回结果；
- 任何内部异常/未知     -> 一律不执行（fail-closed）。

注意（诚实的边界）：进程内包装与 agent 仍在同一进程。要在信任域上真正隔离，
请用 proxy.py 提供的进程外代理；进程内包装解决的是"调用路径强制经过裁决"。
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Optional

from .exceptions import ApprovalRequired, BlockedActionError


class GuardedTool:
    """一个受控工具：调用即裁决，绕不过。"""

    def __init__(
        self,
        kernel: Any,
        func: Callable[..., Any],
        *,
        name: Optional[str] = None,
        require_approval: bool = False,
    ) -> None:
        self._kernel = kernel
        self._func = func
        self._name = name or func.__name__
        self._require_approval = require_approval
        functools.update_wrapper(self, func, updated=())

    @property
    def action_name(self) -> str:
        return self._name

    @property
    def requires_approval(self) -> bool:
        return self._require_approval

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        arguments = _build_arguments(self._func, args, kwargs)

        outcome = self._kernel.check(
            self._name, arguments, require_approval=self._require_approval
        )

        if outcome["decision"] == "block":
            raise BlockedActionError(
                self._name,
                outcome.get("reason", ""),
                rule=outcome.get("rule", ""),
                receipt_id=outcome.get("receipt_id", ""),
            )
        if outcome["decision"] == "pending":
            raise ApprovalRequired(
                outcome["request_id"], self._name,
                reason=outcome.get("reason", ""),
                ttl_seconds=outcome.get("ttl_seconds", 0),
            )
        # allow：执行原始函数
        return self._func(*args, **kwargs)


def wrap_tool(
    kernel: Any,
    func: Callable[..., Any],
    *,
    name: Optional[str] = None,
    require_approval: bool = False,
) -> GuardedTool:
    """把单个工具函数包成受控工具。"""
    return GuardedTool(
        kernel, func, name=name, require_approval=require_approval
    )


def wrap_tools(kernel: Any, funcs: Dict[str, Callable[..., Any]],
               *, approval_actions: Optional[set] = None) -> Dict[str, GuardedTool]:
    """批量包装。approval_actions 中的动作名需要人工审批。"""
    approval_actions = approval_actions or set()
    return {
        name: wrap_tool(
            kernel, func, name=name, require_approval=name in approval_actions
        )
        for name, func in funcs.items()
    }


def _build_arguments(
    func: Callable[..., Any], args: tuple, kwargs: Dict[str, Any]
) -> Dict[str, Any]:
    """尽力把位置参数映射成具名参数，便于策略与指纹使用。"""
    try:
        import inspect

        sig = inspect.signature(func)
        bound = sig.bind_partial(*args, **kwargs)
        return dict(bound.arguments)
    except (TypeError, ValueError):
        result: Dict[str, Any] = dict(kwargs)
        for index, value in enumerate(args):
            result[f"arg{index}"] = value
        return result
