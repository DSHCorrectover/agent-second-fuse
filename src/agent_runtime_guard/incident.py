# -*- coding: utf-8 -*-
"""
incident.py — 事件取证报告 (Incident Report)

从 append-only 台账抽取被拦截/异常事件，生成一份可直接用于内部复盘与对外
上报的事件报告，覆盖 2026-10-09 白宫「AI 事件强制上报」要求的核心要素：
发生了什么、时间线、受影响对象、影响评估、已采取的补救与后续纠正动作。

诚实边界（必须随报告输出）：
    - 报告只陈述被记录在台账中的事实与时间戳；未被监控覆盖的动作不在内。
    - 是否构成某具体法规下「应上报事件」，需由组织法务结合该法规适用范围
      判定。本报告提供证据，不替代法律认定。

输出：Markdown（默认）或 JSON。
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .ledger import EventLedger, LedgerIntegrity
from .receipt import Receipt


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _summarize_receipt(receipt: Receipt) -> Dict[str, Any]:
    payload = receipt.payload
    return {
        "receipt_id": receipt.receipt_id,
        "time": payload.get("signed_at"),
        "agent_id": payload.get("agent_id"),
        "decision": payload.get("decision"),
        "layer": payload.get("layer"),
        "rule": payload.get("rule"),
        "action": payload.get("action"),
        "reason": payload.get("reason"),
        "parameters": payload.get("parameters"),
        "details": payload.get("details"),
    }


def build_report(
    ledger: EventLedger,
    *,
    incident_title: str = "AI Agent runtime incident",
    reporter: str = "",
    remediation_notes: Optional[List[str]] = None,
    include_allowed: bool = False,
) -> Dict[str, Any]:
    """从台账构建结构化事件报告 dict。

    Args:
        ledger:            事件台账。
        incident_title:    报告标题。
        reporter:          报告主体（人/组织），可空。
        remediation_notes: 已采取/计划的补救与纠正措施（人工补充）。
        include_allowed:   是否把放行事件也列入时间线（默认只列拦截事件）。
    """
    integrity: LedgerIntegrity = ledger.verify()
    receipts = ledger.receipts()

    blocked = [r for r in receipts if r.decision == "block"]
    timeline_receipts = receipts if include_allowed else blocked
    timeline = [_summarize_receipt(r) for r in timeline_receipts]

    by_layer = Counter(r.payload.get("layer", "?") for r in blocked)
    by_rule = Counter(r.payload.get("rule", "?") for r in blocked)
    agents = sorted({r.payload.get("agent_id", "?") for r in blocked})

    times = [r.payload.get("signed_at") for r in blocked if r.payload.get("signed_at")]
    window = {
        "first": min(times) if times else None,
        "last": max(times) if times else None,
    }

    # 影响评估：由台账事实给出可核验的客观项，不做夸大定性
    impacted_actions = sorted({r.payload.get("action", "?") for r in blocked})
    impact: Dict[str, Any] = {
        "blocked_actions_count": len(blocked),
        "distinct_tools": impacted_actions,
        "agents_involved": agents,
        "data_exfiltration_indicators": [
            _summarize_receipt(r)
            for r in blocked
            if "exfil" in (r.payload.get("rule", "") + r.payload.get("layer", "")).lower()
        ],
        "note": "Only actions recorded by the guard are listed. Scope of harm "
                "beyond recorded calls requires separate investigation.",
    }

    remediation = list(remediation_notes or [])
    if not remediation:
        remediation = [
            "Blocked at runtime by the independent guard (fail-closed); the "
            "flagged action did not execute through the guarded path.",
            "Awaiting human review; root-cause and corrective actions to be filled in.",
        ]

    return {
        "report_schema": "agent-runtime-guard.incident-report/1.0",
        "generated_at": _utc_now(),
        "title": incident_title,
        "reporter": reporter,
        "executive_summary": (
            f"The independent runtime guard blocked {len(blocked)} action(s) "
            f"across {len(agents)} agent(s). This report is generated from a "
            f"cryptographically linked, append-only ledger."
        ),
        "evidence_integrity": integrity.to_dict(),
        "event_window": window,
        "timeline": timeline,
        "breakdown_by_layer": dict(by_layer),
        "breakdown_by_rule": dict(by_rule),
        "impact_assessment": impact,
        "remediation_and_corrections": remediation,
        "disclaimer": (
            "This report states only facts recorded in the ledger with their "
            "timestamps. Actions outside instrumented coverage are not included. "
            "Whether this constitutes a reportable incident under any specific "
            "regulation is a legal determination for the reporting organization; "
            "this report supplies evidence, not that determination."
        ),
    }


def report_to_markdown(report: Dict[str, Any]) -> str:
    """把结构化报告渲染成 Markdown。"""
    lines: List[str] = []
    lines.append(f"# {report['title']}")
    lines.append("")
    lines.append(f"- Report generated (UTC): {report['generated_at']}")
    if report.get("reporter"):
        lines.append(f"- Reporter: {report['reporter']}")
    integ = report["evidence_integrity"]
    integ_tag = "✅ intact" if integ["ok"] else f"❌ BROKEN at seq {integ.get('broken_at_seq')}"
    lines.append(f"- Ledger integrity: {integ_tag} ({integ['entries']} entries)")
    win = report.get("event_window", {})
    if win.get("first"):
        lines.append(f"- Event window: {win['first']} → {win['last']}")
    lines.append("")

    lines.append("## Executive summary")
    lines.append(report["executive_summary"])
    lines.append("")

    lines.append("## Timeline of blocked events")
    timeline = report["timeline"]
    if not timeline:
        lines.append("_No blocked events recorded._")
    else:
        lines.append("| Time (UTC) | Agent | Layer | Rule | Action | Reason |")
        lines.append("|---|---|---|---|---|---|")
        for item in timeline:
            reason = (item.get("reason") or "").replace("|", "\\|")
            lines.append(
                f"| {item.get('time')} | {item.get('agent_id')} | "
                f"{item.get('layer')} | {item.get('rule')} | "
                f"{item.get('action')} | {reason} |"
            )
    lines.append("")

    lines.append("## Breakdown")
    lines.append(f"- By layer: `{json.dumps(report['breakdown_by_layer'], ensure_ascii=False)}`")
    lines.append(f"- By rule: `{json.dumps(report['breakdown_by_rule'], ensure_ascii=False)}`")
    lines.append("")

    impact = report["impact_assessment"]
    lines.append("## Impact assessment")
    lines.append(f"- Blocked actions: {impact['blocked_actions_count']}")
    lines.append(f"- Tools involved: {', '.join(impact['distinct_tools']) or '—'}")
    lines.append(f"- Agents: {', '.join(impact['agents_involved']) or '—'}")
    if impact["data_exfiltration_indicators"]:
        lines.append("- ⚠️ Data-exfiltration indicators present (see timeline).")
    lines.append(f"- {impact['note']}")
    lines.append("")

    lines.append("## Remediation and corrective actions")
    for note in report["remediation_and_corrections"]:
        lines.append(f"- {note}")
    lines.append("")

    lines.append("## Disclaimer")
    lines.append(report["disclaimer"])
    lines.append("")
    return "\n".join(lines)
