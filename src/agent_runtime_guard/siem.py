# -*- coding: utf-8 -*-
"""siem.py — SIEM/SOAR 导出。

把裁决收据转成安全运营团队能直接消费的格式，而不是让他们读私有台账：

- NDJSON：每行一条扁平事件（Elastic/Splunk 通用）。
- CEF：ArcSight Common Event Format 单条字符串。
- webhook：POST JSON（Splunk HEC 的 /services/collector 或通用接收器）。

只做格式转换与投递，不改变证据本身；收据签名与台账链仍为核验依据。
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict, List, Optional

SEVERITY_BLOCK = 7
SEVERITY_ALLOW = 2


def receipt_to_event(receipt: Any) -> Dict[str, Any]:
    """把收据压成一条扁平 SIEM 事件。"""
    p = receipt.payload
    decision = p.get("decision")
    return {
        "timestamp": receipt.envelope.get("signed_at") or p.get("signed_at"),
        "agent_id": p.get("agent_id"),
        "action": p.get("action"),
        "decision": decision,
        "outcome": "blocked" if decision == "block" else "allowed",
        "layer": p.get("layer"),
        "rule": p.get("rule"),
        "reason": p.get("reason"),
        "receipt_id": p.get("receipt_id"),
        "kid": receipt.envelope.get("kid"),
        "severity": SEVERITY_BLOCK if decision == "block" else SEVERITY_ALLOW,
        "parameters": p.get("parameters"),
    }


def to_ndjson(receipts: List[Any]) -> str:
    return "".join(
        json.dumps(receipt_to_event(r), ensure_ascii=False) + "\n" for r in receipts
    )


def to_cef(receipt: Any) -> str:
    """单条 CEF:0 字符串。字段做 CEF 转义。"""
    p = receipt.payload
    decision = p.get("decision")
    name = f"Agent action {decision}: {p.get('action')}"

    def esc(value: Any) -> str:
        s = "" if value is None else str(value)
        return (s.replace("\\", "\\\\")
                 .replace("=", "\\=")
                 .replace("\n", " ")
                 .replace("\r", " "))

    ext = " ".join([
        f"rt={esc(receipt.envelope.get('signed_at'))}",
        f"act={esc(decision)}",
        f"requestClientApplication={esc(p.get('agent_id'))}",
        f"cs1={esc(p.get('layer'))}",
        f"cs1Label=layer",
        f"cs2={esc(p.get('rule'))}",
        f"cs2Label=rule",
        f"msg={esc(p.get('reason'))}",
        f"externalId={esc(p.get('receipt_id'))}",
    ])
    sev = SEVERITY_BLOCK if decision == "block" else SEVERITY_ALLOW
    return (
        "CEF:0|Correctover|agent-second-fuse|1.0|"
        f"agent-tool-{esc(decision)}|{esc(name)}|{sev}|{ext}"
    )


def to_cef_batch(receipts: List[Any]) -> str:
    return "\n".join(to_cef(r) for r in receipts)


def export_file(receipts: List[Any], path: str, fmt: str = "ndjson") -> int:
    """把收据导出为文件。返回写入条数。"""
    fmt = fmt.lower()
    if fmt == "ndjson":
        content = to_ndjson(receipts)
    elif fmt == "cef":
        content = to_cef_batch(receipts)
    elif fmt == "json":
        content = json.dumps(
            [receipt_to_event(r) for r in receipts], ensure_ascii=False, indent=2
        )
    else:
        raise ValueError(f"unknown SIEM format: {fmt}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content if content.endswith("\n") or fmt != "ndjson" else content)
    return len(receipts)


def post_webhook(
    receipts: List[Any],
    url: str,
    *,
    token: Optional[str] = None,
    timeout: int = 10,
    splunk_hec: bool = False,
) -> int:
    """把事件 POST 到 webhook。返回投递条数。

    splunk_hec=True 时按 HEC 事件包格式发送并带 Authorization 头。
    """
    events = [receipt_to_event(r) for r in receipts]
    headers = {"Content-Type": "application/json"}
    if splunk_hec:
        if token:
            headers["Authorization"] = f"Splunk {token}"
        body = "".join(
            json.dumps({"event": e, "time": _epoch(e.get("timestamp"))},
                       ensure_ascii=False)
            for e in events
        )
    else:
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = json.dumps({"events": events}, ensure_ascii=False)

    req = urllib.request.Request(url, data=body.encode("utf-8"), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read()
        if resp.status >= 300:
            raise RuntimeError(f"webhook returned {resp.status}")
    return len(events)


def _epoch(iso_ts: Optional[str]) -> Optional[float]:
    if not iso_ts:
        return None
    try:
        from datetime import datetime
        return datetime.fromisoformat(iso_ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None
