# -*- coding: utf-8 -*-
"""
receipt.py — 裁决收据 (Decision Receipt)

每次 guard 裁决都被签成一张独立、可离线复核的收据。收据不含签名自身的
字段参与签名 (避免 signature-in-signing-input 这类自指歧义)，签名输入是
payload 的 JCS 规范化字节。

数据形状 (envelope)：
    {
      "kid":        "<signing key id>",
      "alg":        "Ed25519",
      "signed_at":   "<UTC ISO-8601>",
      "payload":     { ... 被签裁决 ... },
      "signature":   "<base64 64B signature over JCS(payload)>"
    }

payload：
    schema, version, receipt_id, decision (allow|block), layer, rule,
    action, agent_id, reason, parameters (可选), details (可选)

安全语义：
    - 签名只覆盖 JCS(payload)；篡改 payload 任一字段，验签失败。
    - 验签不访问网络、不依赖签发方，只读一张公钥。
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

RECEIPT_SCHEMA = "agent-runtime-guard.decision-receipt"
RECEIPT_VERSION = "1.0"
ALG = "Ed25519"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def jcs(data: Any) -> bytes:
    """JCS 风格规范化：键排序、无多余空白、ASCII。

    与独立 reader 使用的 preimage 规则一致，保证跨实现字节稳定。
    """
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _jsonable(value: Any) -> Any:
    """把任意入参收敛为 JSON 可表示对象；不可序列化的回退为字符串。"""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return json.loads(json.dumps(value, default=str))


@dataclass
class Receipt:
    """一张已签发的裁决收据。"""

    envelope: Dict[str, Any]

    # ------------------------------------------------------------------
    @property
    def payload(self) -> Dict[str, Any]:
        return self.envelope["payload"]

    @property
    def receipt_id(self) -> str:
        return self.payload["receipt_id"]

    @property
    def decision(self) -> str:
        return self.payload["decision"]

    @property
    def signature_b64(self) -> str:
        return self.envelope["signature"]

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.envelope, indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, envelope: Mapping[str, Any]) -> "Receipt":
        for key in ("kid", "alg", "payload", "signature"):
            if key not in envelope:
                raise ValueError(f"receipt envelope missing field: {key}")
        return cls(dict(envelope))

    @classmethod
    def from_json(cls, text: str) -> "Receipt":
        return cls.from_dict(json.loads(text))


class ReceiptSigner:
    """把 GuardResult 签成 Receipt。"""

    def __init__(self, signer: Any) -> None:
        # signer: keys.Signer (鸭子类型，避免循环导入)
        self._signer = signer

    def issue(
        self,
        *,
        decision: str,
        action: str,
        layer: str,
        rule: str,
        reason: str,
        agent_id: str = "agent",
        parameters: Optional[Dict[str, Any]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Receipt:
        """签发一张收据。

        Args:
            decision:   "allow" / "block"
            action:     被裁决动作
            layer:      裁决所在安全层
            rule:       规则标识
            reason:     人类可读原因
            agent_id:   被监控 agent 标识
            parameters: 动作参数 (留证；敏感时由调用方脱敏后再传)
            details:    附加诊断
        """
        payload: Dict[str, Any] = {
            "schema": RECEIPT_SCHEMA,
            "version": RECEIPT_VERSION,
            "receipt_id": "",  # 先占位，签名前计算
            "agent_id": str(agent_id),
            "decision": decision,
            "layer": layer,
            "rule": rule,
            "action": action,
            "reason": reason,
            "signed_at": _utc_now(),
        }
        if parameters is not None:
            payload["parameters"] = _jsonable(parameters)
        if details:
            payload["details"] = _jsonable(details)

        # receipt_id = sha256(JCS(payload))[:16]，先算 id 再签
        digest = hashlib.sha256(jcs(payload)).hexdigest()
        payload["receipt_id"] = "r" + digest[:15]

        signature = self._signer.sign(jcs(payload))
        envelope: Dict[str, Any] = {
            "kid": self._signer.kid,
            "alg": ALG,
            "signed_at": payload["signed_at"],
            "payload": payload,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        return Receipt(envelope)


def verify_receipt(receipt: Receipt, public_key: Any) -> bool:
    """用公钥验证收据签名。纯本地、无网络。

    Returns:
        True=签名有效且 alg/kid 与 payload 一致；False=验签失败。
    """
    envelope = receipt.envelope
    if envelope.get("alg") != ALG:
        return False

    payload = envelope["payload"]
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
    except Exception:
        return False

    # kid 必须与公钥指纹一致，防止拿 A 钥签的收据冒充 B 钥
    from .keys import kid_from_public

    if envelope.get("kid") != kid_from_public(public_key):
        return False

    try:
        public_key.verify(signature, jcs(payload))
        return True
    except Exception:
        return False


def verify_receipt_json(envelope: Mapping[str, Any], public_key: Any) -> bool:
    return verify_receipt(Receipt.from_dict(envelope), public_key)
