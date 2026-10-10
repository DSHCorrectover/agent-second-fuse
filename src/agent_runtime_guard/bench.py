# -*- coding: utf-8 -*-
"""bench.py — 性能基准（安全件唯一硬的货币之一）。

在同一进程内对"裁决 + 签名 + 入链"全链路计时，输出 P50/P95/P99 与吞吐。
每次裁决都签 Ed25519 收据并写台账，测的是真实留证路径，不是裸规则耗时。

运行：
    arg-fuse bench --iterations 2000
"""

from __future__ import annotations

import tempfile
import time
from typing import Any, Dict, List

from .guarded import GuardedKernel
from .policy import PolicyConfig


def percentile(sorted_values: List[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    index = min(len(sorted_values) - 1,
                int(round((pct / 100.0) * (len(sorted_values) - 1))))
    return sorted_values[index]


def run_benchmark(iterations: int = 2000) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        kernel = GuardedKernel.bootstrap(
            PolicyConfig.builtin("general"), tmp, agent_id="bench-agent"
        )

        samples_allow: List[float] = []
        samples_block: List[float] = []

        for i in range(iterations):
            start = time.perf_counter_ns()
            kernel.guard("read_file", {"path": f"/tmp/{i}.txt"})
            samples_allow.append((time.perf_counter_ns() - start) / 1000.0)

        for i in range(iterations):
            start = time.perf_counter_ns()
            kernel.guard("execute_shell", {"command": "sudo rm -rf /"})
            samples_block.append((time.perf_counter_ns() - start) / 1000.0)

    def summarize(samples: List[float]) -> Dict[str, float]:
        ordered = sorted(samples)
        return {
            "p50_us": round(percentile(ordered, 50), 2),
            "p95_us": round(percentile(ordered, 95), 2),
            "p99_us": round(percentile(ordered, 99), 2),
            "mean_us": round(sum(samples) / len(samples), 2),
            "throughput_ops": int(1_000_000.0 / (sum(samples) / len(samples))),
        }

    return {
        "iterations": iterations,
        "measured": "full decision path incl. Ed25519 sign + ledger append",
        "allow": summarize(samples_allow),
        "block": summarize(samples_block),
    }


def format_benchmark(result: Dict[str, Any]) -> str:
    lines = [
        f"iterations per case: {result['iterations']}",
        f"measured: {result['measured']}",
    ]
    for case in ("allow", "block"):
        s = result[case]
        lines.append(
            f"[{case}] P50 {s['p50_us']}us | P95 {s['p95_us']}us | "
            f"P99 {s['p99_us']}us | ~{s['throughput_ops']} ops/s"
        )
    return "\n".join(lines)
