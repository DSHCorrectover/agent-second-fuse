# -*- coding: utf-8 -*-
"""anchor.py — 外部证据锚定。

自签收据只能证明「事后没被改」，无法向第三方证明「某时刻就已存在」。本模块
把台账链头（ledger head）周期性提交给外部仅追加见证服务，拿到带时间的背书，
从而把本地自证升级为外部可验证的存在性证明。

设计为 provider 抽象，默认两种落地：
- NotaryWebhookProvider：POST {head, seq} 到自有/第三方 notary，服务返回
  {anchored, witness_time, signature?}；记录到 anchors.jsonl。
- RFC9162/Certificate Transparency 风格的日志接入留作扩展点（接口一致）。

锚定记录（append-only）：
    <evidence>/anchor/anchors.jsonl
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ANCHORS_NAME = "anchors.jsonl"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class NotaryWebhookProvider:
    """HTTP 见证服务：提交链头，返回带时间的背书。"""

    def __init__(self, url: str, *, token: Optional[str] = None,
                 timeout: int = 10) -> None:
        self.url = url
        self.token = token
        self.timeout = timeout

    def witness(self, head: str, seq: int) -> Dict[str, Any]:
        payload = json.dumps(
            {"head": head, "seq": seq, "submitted_at": _now_iso()},
            ensure_ascii=False,
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.url, data=payload, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        body.setdefault("anchored", True)
        body.setdefault("witness_time", _now_iso())
        return body


class AnchorLog:
    """外部锚定记录（append-only）。"""

    def __init__(self, anchor_dir: Path) -> None:
        self._dir = Path(anchor_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / ANCHORS_NAME

    def _read(self) -> List[Dict[str, Any]]:
        if not self._path.exists():
            return []
        return [
            json.loads(line)
            for line in self._path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def records(self) -> List[Dict[str, Any]]:
        return self._read()

    def latest(self) -> Optional[Dict[str, Any]]:
        rows = self._read()
        return rows[-1] if rows else None

    def anchor(
        self,
        provider: Any,
        head: str,
        seq: int,
        *,
        provider_name: str = "notary-webhook",
    ) -> Dict[str, Any]:
        """向外部 provider 提交当前链头并落一条锚定记录。"""
        attestation = provider.witness(head, seq)
        record = {
            "anchored_at": _now_iso(),
            "provider": provider_name,
            "head": head,
            "seq": seq,
            "attestation": attestation,
        }
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record

    def covers(self, head: str) -> bool:
        """某链头是否已被外部锚定覆盖。"""
        return any(r.get("head") == head for r in self._read())
