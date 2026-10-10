# -*- coding: utf-8 -*-
"""
layers/mutation.py — 危险模式匹配 + 自我修改检测 (Mutation Layer)

实现危险命令与自我修改检测规则的最简形态:
    - Rule 1 Personality Override: POI > poi_threshold → BLOCK
    - Rule 3 Gene Stability:      risk > risk_threshold → BLOCK
    - 自我提示/约束修改特征词命中 → BLOCK (PersonaOverride)

本层同时处理两类攻击:
    1. 危险工具执行 (sudo rm -rf / shutdown / taskkill ...)
    2. 自我提示修改 ("忽略所有限制" / "delete safety policy" ...)

编码绕过补丁 (v0.1.1 / v0.1.4):
    匹配前对参数/文本做解码与归一化管道, 使 dangerous_patterns /
    self_modify_patterns 自然命中编码或混淆藏匿的攻击载荷:
      - Base64 解码扩展 (v0.1.1)
      - Hex 解码扩展 (v0.1.4)
      - 连续空白压缩 (v0.1.4, 修复双空格绕过)
      - Unicode NFKC 全半角转换 (v0.1.4, 修复全角混淆)
"""

import re
import unicodedata
from typing import Any, Dict, List, Optional, Sequence

from ..policy import PolicyConfig
from ..result import GuardResult
from .base64_util import try_decode_base64


def _normalize_spaces(text: str) -> str:
    """压缩连续空白 (含全角空格) 为单个空格, 修复双空格绕过。"""
    return re.sub(r"\s+", " ", text)


def _normalize_unicode(text: str) -> str:
    """Unicode NFKC 全半角转换, 修复全角混淆 (ｓｕｄｏ → sudo)。

    注意: 只做兼容性归一化, 不处理跨脚本同形字 (如西里尔 ѕ vs 拉丁 s)。
    """
    return unicodedata.normalize("NFKC", text)


def _decode_hex_in_text(text: str) -> str:
    """尝试解码文本中的十六进制编码块 (长度>=8, 偶数个十六进制字符)。

    命中时返回 '原文本 | 解码内容' 追加形式; 未命中返回原文本。
    只保留解码后含可打印 ASCII 的内容, 减少误报。
    """
    matches = re.findall(r"[0-9a-fA-F]{8,}", text)
    decoded_parts = []
    for match in matches:
        if len(match) % 2 == 0:  # 只有偶数长度才能解码
            try:
                decoded = bytes.fromhex(match).decode("utf-8", errors="ignore")
                if decoded and any(c.isprintable() and ord(c) < 128 for c in decoded):
                    decoded_parts.append(decoded)
            except (ValueError, UnicodeDecodeError):
                continue
    if decoded_parts:
        # 拼接分隔符用 " ; " (v0.1.6): 与 _decode_extended 保持一致, 避免人造管道符
        return text + " ; " + " ".join(decoded_parts)
    return text


def _decode_extended(text: str) -> str:
    """解码 + 归一化管道 (v0.1.1 + v0.1.4)。

    顺序: Base64 解码 → Hex 解码 → 空格压缩 → NFKC 全半角。
    归一化发生在小写化之前 (调用方负责 .lower())。只做追加, 不改原始语义。
    拼接分隔符用 " ; " (v0.1.6): 避免解码拼接的人造 " | " 误触发管道外传正则
    (/etc/passwd.*\\| 等), 原始命令中的管道符仍保留在原文中可正常命中。
    """
    if not text:
        return text
    parts = [text]
    decoded_b64 = try_decode_base64(text)
    if decoded_b64:
        parts.append(decoded_b64)
    decoded_hex = _decode_hex_in_text(text)
    if decoded_hex != text:
        parts.append(decoded_hex)
    combined = _normalize_spaces(" ; ".join(parts))
    return _normalize_unicode(combined)


class MutationLayer:
    """危险模式匹配 + 自我修改检测层。

    Args:
        policy: PolicyConfig (提供 danger_patterns / self_modify_patterns /
                             poi_threshold / risk_threshold)
    """

    MODULE = "mutation"

    # 兜底危险模式 (策略未配置时的最小默认集)
    _FALLBACK_DANGER = [
        "sudo rm -rf", "rm -rf /", "rm -fr /", "shutdown", "reboot",
        "taskkill", "format c:", "del /f", "mkfs", "diskpart",
    ]
    # 兜底自我修改特征词
    _FALLBACK_SELF_MODIFY = [
        "忽略所有限制", "无视所有", "删除安全策略", "移除限制", "忽略之前",
        "ignore all", "ignore previous", "no restrictions", "disable safety",
    ]

    def __init__(self, policy: PolicyConfig) -> None:
        self._policy = policy
        self._danger: List[str] = list(policy.danger_patterns) or self._FALLBACK_DANGER
        self._self_modify: List[str] = (
            list(policy.self_modify_patterns) or self._FALLBACK_SELF_MODIFY
        )

    # ------------------------------------------------------------------
    # 入口
    # ------------------------------------------------------------------
    def check(
        self,
        action: str,
        arguments: Optional[Dict[str, Any]] = None,
        text: Optional[str] = None,
        poi: Optional[float] = None,
        risk: Optional[float] = None,
        **context: Any,
    ) -> GuardResult:
        """检查工具执行 / 文本修改是否属于危险或自我修改。

        Args:
            action:    工具名 (如 execute_shell, update_directives)
            arguments: 工具参数 (危险模式对 arguments 序列化文本做匹配)
            text:      待写入/更新的提示文本 (自我修改特征词匹配)
            poi:       人格覆盖风险 (POI) 指标 [0,1]; 提供时按 Rule 1 判定
            risk:      通用风险分数 [0,1]; 提供时按阈值判定

        Returns:
            GuardResult
        """
        # ---- 危险模式匹配 (工具参数序列化文本) ----
        blob = self._serialize(action, arguments)
        hit = self._match_any(blob, self._danger)
        if hit:
            return GuardResult.block(
                module=self.MODULE,
                action=action,
                reason=f"工具参数命中危险模式 '{hit}'",
                rule="Rule1_PersonalityOverride",
                details={"pattern": hit, "blob": blob},
                compliance=self._policy.get_compliance("self_modify"),
            )

        # ---- 自我修改检测 (提示/约束文本, 含 Base64 解码扩展) ----
        if text:
            text_low = _decode_extended(text).lower()
            hit = self._match_any(text_low, self._self_modify)
            if hit:
                return GuardResult.block(
                    module=self.MODULE,
                    action=action,
                    reason=f"自我提示修改特征 '{hit}' 被检出",
                    rule="Rule1_PersonalityOverride",
                    details={"pattern": hit},
                    compliance=self._policy.get_compliance("self_modify"),
                )

        # ---- Rule 1: POI 指标超阈值 ----
        if poi is not None and poi > self._policy.poi_threshold:
            return GuardResult.block(
                module=self.MODULE,
                action=action,
                reason=(
                    f"POI={poi:.3f} > threshold={self._policy.poi_threshold}, "
                    "system overfitting risk too high"
                ),
                rule="Rule1_PersonalityOverride",
                details={"poi": poi, "threshold": self._policy.poi_threshold},
            )

        # ---- Rule 3: 通用风险分数超阈值 ----
        if risk is not None and risk > self._policy.risk_threshold:
            return GuardResult.block(
                module=self.MODULE,
                action=action,
                reason=(
                    f"risk={risk:.3f} > threshold={self._policy.risk_threshold}"
                ),
                rule="Rule3_GeneStabilityProtection",
                details={"risk": risk, "threshold": self._policy.risk_threshold},
            )

        return GuardResult.allow(
            module=self.MODULE,
            action=action,
            reason="未命中危险模式 / 自我修改特征",
            rule="Rule4_SafeEvolutionAllowance",
        )

    # ------------------------------------------------------------------
    # 工具
    # ------------------------------------------------------------------
    @staticmethod
    def _serialize(action: str, arguments: Optional[Dict[str, Any]]) -> str:
        """把工具调用序列化为小写文本用于模式匹配 (含解码 + 归一化管道)。

        解码/归一化发生在小写化之前, 避免 Base64/Hex 大小写敏感字符被破坏。
        """
        if not arguments:
            return action.lower()
        import json

        try:
            args_str = json.dumps(arguments, ensure_ascii=False)
        except Exception:
            args_str = str(arguments)
        return _decode_extended(f"{action} {args_str}").lower()

    @staticmethod
    def _match_any(text: str, patterns: Sequence[str]) -> Optional[str]:
        """返回命中的第一个模式; 未命中返回 None。

        v0.1.2 起支持正则模式 (re.search); 无效正则回退为子串匹配。
        既有字面量模式 (如 "sudo rm -rf") 均为正则安全字面量, 行为不变。
        """
        for p in patterns:
            try:
                if re.search(p, text):
                    return p
            except re.error:
                if p.lower() in text:
                    return p
        return None
