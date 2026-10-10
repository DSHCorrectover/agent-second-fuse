# -*- coding: utf-8 -*-
"""Base64 解码工具 — 检测编码绕过攻击"""

import base64
import re
from typing import Optional

# 匹配可能的 Base64 编码字符串（只匹配连续的大小写字母、数字、+、/、=，长度>=8）
_B64_PATTERN = re.compile(r"[A-Za-z0-9+/=]{8,}")


def try_decode_base64(text: str) -> Optional[str]:
    """尝试解码文本中的 Base64 编码块。

    如果解码成功且结果包含可打印字符（英文/标点），返回解码后的文本。
    否则返回 None。
    """
    matches = _B64_PATTERN.findall(text)
    decoded_parts = []

    for match in matches:
        try:
            decoded = base64.b64decode(match, validate=True).decode(
                "utf-8", errors="ignore"
            )
            # 只保留包含可打印英文内容的结果（减少误报）
            if decoded and any(c.isprintable() and ord(c) < 128 for c in decoded):
                decoded_parts.append(decoded)
        except Exception:
            continue

    if decoded_parts:
        # 拼接分隔符用 " ; " (v0.1.6): 避免解码拼接的人造 " | " 误触发管道外传正则
        return text + " ; " + " ".join(decoded_parts)
    return None
