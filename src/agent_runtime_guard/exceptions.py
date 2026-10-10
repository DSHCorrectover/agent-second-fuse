# -*- coding: utf-8 -*-
"""exceptions.py — 第二熔断自定义异常。"""

from __future__ import annotations

from typing import Any, Dict, Optional


class GuardError(Exception):
    """熔断器基础异常。"""


class BlockedActionError(GuardError):
    """动作被 fail-closed 策略拦截，未执行。"""

    def __init__(self, action: str, reason: str, rule: str = "",
                 receipt_id: str = "", details: Optional[Dict[str, Any]] = None):
        self.action = action
        self.reason = reason
        self.rule = rule
        self.receipt_id = receipt_id
        self.details = details or {}
        super().__init__(f"blocked action {action!r}: {reason} [{rule}]")


class ApprovalRequired(GuardError):
    """动作需要人工审批，当前处于 pending，未执行。"""

    def __init__(self, request_id: str, action: str, reason: str = "",
                 ttl_seconds: int = 0):
        self.request_id = request_id
        self.action = action
        self.reason = reason
        self.ttl_seconds = ttl_seconds
        super().__init__(
            f"approval required for {action!r} (request {request_id})"
        )
