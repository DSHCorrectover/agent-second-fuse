# -*- coding: utf-8 -*-
"""proxy.py — 进程外独立执行点（独立信任域）。

wrap.py 的强制点与 agent 同进程；要在信任域上真正隔离，第二熔断应作为独立
进程运行。本模块用标准库 http.server 提供一个仅裁决（decision-only）服务：

    POST /check   {"action": ..., "arguments": {...},
                   "require_approval": false, "agent_id": "..."}

返回 JSON：
    {"decision": "allow"|"block"|"pending", "reason": ..., "receipt_id": ...,
     "request_id": ...(pending 时)}

代理不执行任何工具——它只裁决、留证。agent 侧负责在收到 allow 后才执行、
收到 block/pending 必须不执行。把该服务部署在独立容器/主机上，agent 被
prompt injection 攻陷也无法改写裁决（只能尝试访问它，而默认 fail-closed）。

启动：
    arg-fuse proxy --evidence .guard-evidence --host 127.0.0.1 --port 8765
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .guarded import GuardedKernel
from .policy import PolicyConfig


def build_handler(kernel: GuardedKernel) -> type:
    class DecisionHandler(BaseHTTPRequestHandler):
        server_version = "agent-second-fuse/0.3"

        def _send(self, code: int, obj: Any) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path.rstrip("/") in ("/health", "/healthz"):
                self._send(200, {"ok": True, "kid": kernel.kid,
                                 "ledger_entries": kernel.ledger.count()})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path.rstrip("/") != "/check":
                self._send(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length) if length else b"{}"
                payload = json.loads(raw.decode("utf-8"))
            except (ValueError, json.JSONDecodeError):
                # 非法请求：fail-closed，拒绝
                self._send(400, {"decision": "block",
                                 "reason": "malformed request"})
                return

            action = payload.get("action")
            if not action:
                self._send(400, {"decision": "block",
                                 "reason": "missing action"})
                return

            try:
                decision = kernel.check(
                    str(action),
                    payload.get("arguments"),
                    require_approval=bool(payload.get("require_approval", False)),
                    agent_id=payload.get("agent_id"),
                )
            except Exception as exc:  # 任何内部异常 -> fail-closed
                self._send(500, {"decision": "block", "reason": str(exc)})
                return
            self._send(200, decision)

        def log_message(self, *args: Any) -> None:  # 静默
            return

    return DecisionHandler


def serve(
    kernel: GuardedKernel, host: str = "127.0.0.1", port: int = 8765
) -> None:
    handler = build_handler(kernel)
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.serve_forever()


def build_kernel(
    policy_name: str = "general", evidence: str = ".guard-evidence",
    agent_id: str = "agent",
) -> GuardedKernel:
    policy = PolicyConfig.builtin(policy_name)
    return GuardedKernel.bootstrap(policy, evidence, agent_id=agent_id)
