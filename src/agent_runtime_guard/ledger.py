# -*- coding: utf-8 -*-
"""
ledger.py — Append-only 事件台账

收据按裁决顺序追加到台账。台账是 JSON Lines：每行一张收据信封。台账通过
*前驱链接* 保证顺序与不可篡改：每条 entry 的 hash 覆盖上一条 entry 的
hash，形成一条哈希链；删除、重排或改写任意一行都会让链断裂。

台账文件布局：
    <dir>/ledger.jsonl        每行一个 entry：
        {"seq": n, "receipt_id": "...", "entry_hash": "sha256(prev_hash + JCS(receipt))",
         "envelope": { ...receipt envelope... }}
    <dir>/ledger.head         最新 entry_hash（便于快速校验锚点）

校验：verify() 重放全链，返回 OK 及断链位置。纯本地、无网络。
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .receipt import Receipt, jcs

LEDGER_NAME = "ledger.jsonl"
HEAD_NAME = "ledger.head"
GENESIS = "0" * 64


@dataclass
class LedgerIntegrity:
    """台账完整性校验结果。"""

    ok: bool
    entries: int
    broken_at_seq: Optional[int] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "entries": self.entries,
            "broken_at_seq": self.broken_at_seq,
            "reason": self.reason,
        }


class EventLedger:
    """append-only 哈希链台账。"""

    def __init__(self, ledger_dir: os.PathLike[str] | str) -> None:
        self._dir = Path(ledger_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / LEDGER_NAME
        self._head_path = self._dir / HEAD_NAME

    # ------------------------------------------------------------------
    @property
    def path(self) -> Path:
        return self._path

    def _read_entries(self) -> List[Dict[str, Any]]:
        if not self._path.exists():
            return []
        entries: List[Dict[str, Any]] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
        return entries

    def count(self) -> int:
        return len(self._read_entries())

    def head(self) -> str:
        if self._head_path.exists():
            return self._head_path.read_text(encoding="utf-8").strip()
        entries = self._read_entries()
        return entries[-1]["entry_hash"] if entries else GENESIS

    # ------------------------------------------------------------------
    @staticmethod
    def _entry_hash(prev_hash: str, envelope: Dict[str, Any]) -> str:
        material = prev_hash.encode("ascii") + jcs(envelope)
        return hashlib.sha256(material).hexdigest()

    def append(self, receipt: Receipt) -> Dict[str, Any]:
        """把一张收据追加到台账尾部，返回写入的 entry。"""
        entries = self._read_entries()
        prev_hash = entries[-1]["entry_hash"] if entries else GENESIS
        seq = len(entries) + 1

        envelope = receipt.envelope
        entry_hash = self._entry_hash(prev_hash, envelope)
        entry = {
            "seq": seq,
            "receipt_id": receipt.receipt_id,
            "entry_hash": entry_hash,
            "envelope": envelope,
        }
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._head_path.write_text(entry_hash, encoding="utf-8")
        return entry

    # ------------------------------------------------------------------
    def receipts(self) -> List[Receipt]:
        """返回台账中全部收据（顺序）。"""
        return [Receipt.from_dict(e["envelope"]) for e in self._read_entries()]

    def verify(self) -> LedgerIntegrity:
        """重放哈希链，校验顺序、entry_hash 与 envelope 一致性。"""
        entries = self._read_entries()
        prev_hash = GENESIS
        for index, entry in enumerate(entries, start=1):
            expected_seq = index
            if entry.get("seq") != expected_seq:
                return LedgerIntegrity(
                    False, len(entries), index,
                    f"seq out of order: got {entry.get('seq')}, want {expected_seq}",
                )
            envelope = entry.get("envelope")
            if not envelope:
                return LedgerIntegrity(False, len(entries), index, "missing envelope")
            expected_hash = self._entry_hash(prev_hash, envelope)
            if entry.get("entry_hash") != expected_hash:
                return LedgerIntegrity(
                    False, len(entries), index, "hash chain broken (tamper/reorder)"
                )
            if entry.get("receipt_id") != envelope.get("payload", {}).get("receipt_id"):
                return LedgerIntegrity(False, len(entries), index, "receipt_id mismatch")
            prev_hash = expected_hash

        # 头部锚点一致性
        if entries and self._head_path.exists():
            if self._head_path.read_text(encoding="utf-8").strip() != prev_hash:
                return LedgerIntegrity(False, len(entries), entries[-1]["seq"],
                                       "ledger.head anchor mismatch")
        return LedgerIntegrity(True, len(entries), reason="chain intact")

    def find_blocked(self) -> List[Receipt]:
        """返回所有 decision=block 的收据。"""
        return [r for r in self.receipts() if r.decision == "block"]
