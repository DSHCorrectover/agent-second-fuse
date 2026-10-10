# -*- coding: utf-8 -*-
"""approval.py — 人工审批门 (human-in-the-loop)。

对标记为需要审批的动作，熔断器不依赖 agent 自觉：动作保持 pending 不执行，
直到人工显式 approve / deny。审批决定本身也被签成收据、入台账，且与请求
参数绑定——审批只对「提交时那份参数」生效，参数一变即视为新请求，防止
「拿无害参数骗批准、执行时换成危险参数」。

存储布局：
    <evidence>/approval/requests.jsonl   每个请求一行（含状态与最终决定）

状态机：pending -> approved | denied | expired（只进一次，不可改）。
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .receipt import jcs

REQUESTS_NAME = "requests.jsonl"

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_DENIED = "denied"
STATUS_EXPIRED = "expired"


@dataclass
class ApprovalRequest:
    data: Dict[str, Any]

    @property
    def request_id(self) -> str:
        return self.data["request_id"]

    @property
    def status(self) -> str:
        return self.data["status"]

    @property
    def action(self) -> str:
        return self.data["action"]

    @property
    def arguments(self) -> Optional[Dict[str, Any]]:
        return self.data.get("arguments")

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.data)


def request_fingerprint(action: str, arguments: Optional[Dict[str, Any]]) -> str:
    """参数指纹：审批只绑定提交时的参数。"""
    return hashlib.sha256(jcs({"action": action, "arguments": arguments})).hexdigest()


class ApprovalGate:
    """人工审批门。"""

    def __init__(self, approval_dir: Path, *, default_ttl: int = 3600) -> None:
        self._dir = Path(approval_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / REQUESTS_NAME
        self._default_ttl = default_ttl

    # ------------------------------------------------------------------
    def _read_all(self) -> List[Dict[str, Any]]:
        if not self._path.exists():
            return []
        out: List[Dict[str, Any]] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out

    def _write_all(self, rows: List[Dict[str, Any]]) -> None:
        text = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
        self._path.write_text(text, encoding="utf-8")

    def _find(self, request_id: str) -> Optional[Dict[str, Any]]:
        for row in self._read_all():
            if row["request_id"] == request_id:
                return row
        return None

    # ------------------------------------------------------------------
    def _expire_due(self, rows: List[Dict[str, Any]]) -> bool:
        now = time.time()
        changed = False
        for row in rows:
            if (row["status"] == STATUS_PENDING and row.get("expires_at")
                    and now > row["expires_at"]):
                row["status"] = STATUS_EXPIRED
                row["resolved_at"] = _now_iso()
                changed = True
        return changed

    def create(
        self,
        action: str,
        arguments: Optional[Dict[str, Any]],
        *,
        reason: str = "",
        ttl_seconds: Optional[int] = None,
        requested_by: str = "agent",
    ) -> ApprovalRequest:
        """创建一个 pending 审批请求。已存在同指纹 pending 请求则复用。"""
        rows = self._read_all()
        if self._expire_due(rows):
            self._write_all(rows)

        fp = request_fingerprint(action, arguments)
        for row in rows:
            if row.get("fingerprint") == fp and row["status"] == STATUS_PENDING:
                return ApprovalRequest(row)

        ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        now = time.time()
        rid = "a" + hashlib.sha256(
            jcs({"action": action, "arguments": arguments, "nonce": now})
        ).hexdigest()[:15]
        record = {
            "request_id": rid,
            "action": action,
            "arguments": arguments,
            "fingerprint": fp,
            "reason": reason,
            "requested_by": requested_by,
            "status": STATUS_PENDING,
            "created_at": _now_iso(),
            "expires_at": now + ttl if ttl > 0 else None,
            "resolved_at": None,
            "approver": None,
            "note": None,
        }
        rows.append(record)
        self._write_all(rows)
        return ApprovalRequest(record)

    def is_approved(
        self, action: str, arguments: Optional[Dict[str, Any]]
    ) -> Optional[ApprovalRequest]:
        """该动作+参数是否已有一次有效批准；过期 pending 自动失效。

        Returns: 批准请求（已批准且指纹一致）；None = 未批准。
        """
        rows = self._read_all()
        changed = self._expire_due(rows)
        fp = request_fingerprint(action, arguments)
        for row in rows:
            if (row["status"] == STATUS_APPROVED and row.get("fingerprint") == fp):
                if changed:
                    self._write_all(rows)
                return ApprovalRequest(row)
        if changed:
            self._write_all(rows)
        return None

    def decide(
        self,
        request_id: str,
        approve: bool,
        *,
        approver: str = "human",
        note: Optional[str] = None,
    ) -> ApprovalRequest:
        """人工对一个 pending 请求做出最终决定。"""
        rows = self._read_all()
        self._expire_due(rows)
        for row in rows:
            if row["request_id"] == request_id:
                if row["status"] != STATUS_PENDING:
                    raise ValueError(
                        f"request {request_id} already {row['status']}"
                    )
                row["status"] = STATUS_APPROVED if approve else STATUS_DENIED
                row["approver"] = approver
                row["note"] = note
                row["resolved_at"] = _now_iso()
                self._write_all(rows)
                return ApprovalRequest(row)
        raise KeyError(f"unknown approval request: {request_id}")

    def list_requests(self, status: Optional[str] = None) -> List[ApprovalRequest]:
        rows = self._read_all()
        if self._expire_due(rows):
            self._write_all(rows)
        return [
            ApprovalRequest(r) for r in rows
            if status is None or r["status"] == status
        ]


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
