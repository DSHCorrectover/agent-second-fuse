# -*- coding: utf-8 -*-
"""
policy.py — PolicyConfig 安全策略配置

从 JSON (默认, 零依赖) 或 YAML (可选依赖 PyYAML) 加载安全策略。
策略是 SecurityKernel 的单一事实来源 (Single Source of Truth)：
所有安全层的规则阈值都来自同一份 PolicyConfig。

设计语义:
    - allow_tools / deny_tools       → layers.authority  (工具 ACL)
    - danger_patterns                → layers.mutation   (危险命令模式)
    - self_modify_patterns           → layers.mutation   (自我提示修改特征)
    - immutables                     → layers.constitution (不可变维度)
    - poi_threshold / risk_threshold → layers.mutation   (Rule 1: POI > 0.7 → BLOCK)
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml  # 可选依赖 (仅 from_yaml 需要)
except ImportError:  # pragma: no cover
    yaml = None

from .result import ComplianceItem


@dataclass
class ComplianceMapping:
    """合规映射: 拦截时注入的法规依据。

    对应策略 YAML 的 compliance_mapping 节点:

        compliance_mapping:
          tools:                      # {tool_name: [ComplianceItem]}
            execute_shell: [...]
          self_modify: [...]          # [ComplianceItem]
          identity_drift: [...]
          constitution: [...]
          audit: [...]
    """

    tools: dict = field(default_factory=dict)        # {tool_name: [ComplianceItem]}
    self_modify: list = field(default_factory=list)  # [ComplianceItem]
    identity_drift: list = field(default_factory=list)
    constitution: list = field(default_factory=list)
    audit: list = field(default_factory=list)


@dataclass
class PolicyConfig:
    """安全策略配置 (从 JSON / YAML / dict 加载; JSON 为零依赖默认格式)。

    Attributes:
        name:                 策略名称 (如 finance_strict)
        description:          策略用途说明
        enabled:              策略启用标记 (v0.1.4 解析存储, 供上层使用)
        allow_tools:          允许的工具名单 (authority 层 ACL 白名单)
        deny_tools:           强制拒绝的工具名单 (优先于 allow_tools)
        unknown_tool_default: 白名单外工具的默认动作 ("block"=fail-closed / "allow"=放行)
        danger_patterns:      危险命令子串/正则模式 (命中即视为高风险)
        self_modify_patterns: 自我提示/约束修改特征词
        immutables:           不可变维度 (默认 truth/safety)
        poi_threshold:        人格覆盖风险阈值 (Rule 1, 默认 0.7)
        risk_threshold:       通用风险分数阈值
        param_rules:          参数级业务规则 {tool_name: [规则列表]}
        idle_threshold:       身份连续性检查开关 (预留)
        compliance:           合规映射 (拦截时注入法规依据)
    """

    name: str
    description: str = ""
    enabled: bool = True
    allow_tools: List[str] = field(default_factory=list)
    deny_tools: List[str] = field(default_factory=list)
    unknown_tool_default: str = "block"
    danger_patterns: List[str] = field(default_factory=list)
    self_modify_patterns: List[str] = field(default_factory=list)
    immutables: List[str] = field(default_factory=lambda: ["truth", "safety"])
    poi_threshold: float = 0.7
    risk_threshold: float = 0.7
    param_rules: Dict[str, Any] = field(default_factory=dict)
    compliance: ComplianceMapping = field(default_factory=ComplianceMapping)

    # ------------------------------------------------------------------
    # 构造
    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyConfig":
        """从 dict 构造 (缺失字段使用默认值; 兼容新/旧两套 schema)。

        新 schema (JSON 默认, v0.1.4):
            tools: {allowed: [...], deny: [...], unknown_tool_default: "block"}
            enabled: true
        旧 schema (YAML 兼容):
            allow_tools / deny_tools (顶层)
        """
        data = dict(data or {})
        # 兼容示例 schema 别名 (dangerous_patterns); 规范键名为 danger_patterns
        if "dangerous_patterns" in data and "danger_patterns" not in data:
            data["danger_patterns"] = data["dangerous_patterns"]
        tools = data.get("tools")
        if isinstance(tools, dict):
            if "allowed" in tools and "allow_tools" not in data:
                data["allow_tools"] = tools["allowed"]
            if "deny" in tools and "deny_tools" not in data:
                data["deny_tools"] = tools["deny"]
            if "unknown_tool_default" in tools and "unknown_tool_default" not in data:
                data["unknown_tool_default"] = tools["unknown_tool_default"]
        known = {
            "name", "description", "enabled", "allow_tools", "deny_tools",
            "unknown_tool_default", "danger_patterns", "self_modify_patterns",
            "immutables", "poi_threshold", "risk_threshold", "param_rules",
        }
        kwargs: Dict[str, Any] = {}
        for key in known:
            if key in data:
                kwargs[key] = data[key]
        if "compliance_mapping" in data:
            kwargs["compliance"] = cls._build_compliance(data["compliance_mapping"])
        if "name" not in kwargs or not kwargs["name"]:
            raise ValueError("PolicyConfig.from_dict: 'name' is required")
        return cls(**kwargs)

    @classmethod
    def from_yaml(cls, path: "str | Path") -> "PolicyConfig":
        """从 YAML 文件加载 (需要可选依赖 PyYAML; 未安装时抛 ImportError)。

        推荐使用 from_json / from_json_file (零依赖)。
        """
        if yaml is None:
            raise ImportError(
                "PyYAML 未安装: from_yaml 需要可选依赖 PyYAML。"
                "请执行 pip install 'agent-runtime-guard[yaml]'，"
                "或改用 PolicyConfig.from_json_file('policies/general.json') "
                "加载 JSON 策略 (零依赖)。"
            )
        path = Path(path)
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls.from_dict(data)

    @classmethod
    def from_json(cls, source: "str | Path | Dict[str, Any]") -> "PolicyConfig":
        """从 JSON 加载策略 (零依赖, 默认格式)。

        Args:
            source: JSON 文件路径 (str / Path) 或已解析的 dict

        Examples:
            PolicyConfig.from_json("policies/general.json")
            PolicyConfig.from_json({"name": "custom", "allow_tools": [...]})
        """
        if isinstance(source, dict):
            return cls.from_dict(source)
        path = Path(source)
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return cls.from_dict(data)

    @staticmethod
    def from_json_file(path: "str | Path") -> "PolicyConfig":
        """便捷加载 JSON 策略文件 (等价 PolicyConfig.from_json(path))。"""
        return PolicyConfig.from_json(path)

    # ------------------------------------------------------------------
    # 内置策略 (零配置启动)
    # ------------------------------------------------------------------
    @classmethod
    def builtin(cls, name: str = "general") -> "PolicyConfig":
        """返回一份内置策略，便于零配置启动。

        Args:
            name: general（默认，常用工具 + 危险模式）/ minimal（只做
                  fail-closed ACL，不放行未知工具）/ finance（加参数级
                  金额阈值规则）。
        """
        presets = {
            "general": {
                "name": "builtin-general",
                "description": "General-purpose fail-closed runtime policy.",
                "tools": {
                    "allowed": [
                        "read_file", "write_file", "http_request",
                        "execute_shell", "search", "fund_transfer",
                    ],
                    "unknown_tool_default": "block",
                },
                "danger_patterns": [
                    "sudo rm -rf", "rm -rf /", "shred ", "shutdown",
                    "reboot", "mkfs", "format c:", "/dev/tcp",
                    # 远程下载即执行 (curl/wget ... | sh / bash)
                    r"(curl|wget|fetch)[^|;&]{0,120}\|\s*(ba)?sh",
                    # 反向 shell / 反弹连接
                    r"nc\s+(-e|-c)", r"/bin/(ba)?sh\s+-i",
                    r"bash\s+-i\s+>&", r"exec\s+[^|;&]{0,40}/dev/tcp",
                    # 脚本解释器执行 -c 内联系统调用
                    r"python3?\s+-c\s+[^|&]{0,120}(os\.system|subprocess|popen|eval)",
                    # 常见凭证/影子文件读取
                    r"cat\s+(/etc/shadow|/etc/passwd|~/.ssh/id_)",
                ],
                "self_modify_patterns": [
                    "ignore all previous", "忽略以上", "ignore all",
                    "system prompt", "进入生产模式",
                ],
                "immutables": ["truth", "safety"],
            },
            "minimal": {
                "name": "builtin-minimal",
                "description": "Minimal fail-closed ACL only.",
                "tools": {"allowed": [], "unknown_tool_default": "block"},
                "immutables": ["truth", "safety"],
            },
            "finance": {
                "name": "builtin-finance",
                "description": "Finance policy with amount limits.",
                "tools": {
                    "allowed": ["read_file", "fund_transfer"],
                    "unknown_tool_default": "block",
                },
                "param_rules": {
                    "fund_transfer": [
                        {"field": "amount", "operator": "gt",
                         "value": 10000000, "action": "block"},
                    ],
                },
                "danger_patterns": ["sudo rm -rf", "shutdown"],
                "immutables": ["truth", "safety"],
            },
        }
        if name not in presets:
            raise ValueError(
                f"unknown builtin policy {name!r}; choose from {sorted(presets)}"
            )
        return cls.from_dict(presets[name])


    def to_dict(self) -> Dict[str, Any]:
        """序列化为 dict。"""
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "allow_tools": list(self.allow_tools),
            "deny_tools": list(self.deny_tools),
            "unknown_tool_default": self.unknown_tool_default,
            "danger_patterns": list(self.danger_patterns),
            "self_modify_patterns": list(self.self_modify_patterns),
            "immutables": list(self.immutables),
            "poi_threshold": self.poi_threshold,
            "risk_threshold": self.risk_threshold,
            "param_rules": dict(self.param_rules),
            "compliance_mapping": {
                "tools": {
                    name: [item.to_dict() for item in items]
                    for name, items in self.compliance.tools.items()
                },
                "self_modify": [i.to_dict() for i in self.compliance.self_modify],
                "identity_drift": [i.to_dict() for i in self.compliance.identity_drift],
                "constitution": [i.to_dict() for i in self.compliance.constitution],
                "audit": [i.to_dict() for i in self.compliance.audit],
            },
        }

    # ------------------------------------------------------------------
    # 合规映射
    # ------------------------------------------------------------------
    def get_compliance(self, category: str, tool_name: str = None) -> list:
        """按分类获取合规依据列表。

        Args:
            category:  分类名 (tools / self_modify / identity_drift / constitution / audit)
            tool_name: category="tools" 时的工具名; 其余分类忽略

        Returns:
            [ComplianceItem]; 未配置时返回空列表
        """
        if category == "tools":
            if not tool_name:
                return []
            return list(self.compliance.tools.get(tool_name, []))
        return list(getattr(self.compliance, category, []))

    @staticmethod
    def _build_compliance(raw: Any) -> ComplianceMapping:
        """把 compliance_mapping 原始 dict 解析为 ComplianceMapping。"""
        if not isinstance(raw, dict):
            return ComplianceMapping()

        def _items(key: str) -> List[ComplianceItem]:
            entries = raw.get(key) or []
            if not isinstance(entries, list):
                return []
            return [
                ComplianceItem(
                    regulation=str(e.get("regulation", "") or ""),
                    requirement=str(e.get("requirement", "") or ""),
                )
                for e in entries
                if isinstance(e, dict)
            ]

        tools: Dict[str, List[ComplianceItem]] = {}
        raw_tools = raw.get("tools") or {}
        if isinstance(raw_tools, dict):
            for name, entries in raw_tools.items():
                tools[str(name)] = [
                    ComplianceItem(
                        regulation=str(e.get("regulation", "") or ""),
                        requirement=str(e.get("requirement", "") or ""),
                    )
                    for e in (entries or [])
                    if isinstance(e, dict)
                ]
        return ComplianceMapping(
            tools=tools,
            self_modify=_items("self_modify"),
            identity_drift=_items("identity_drift"),
            constitution=_items("constitution"),
            audit=_items("audit"),
        )

    def clone_with(self, **overrides: Any) -> "PolicyConfig":
        """基于当前策略派生新策略 (覆盖指定字段)。"""
        data = self.to_dict()
        data.update(overrides)
        return PolicyConfig.from_dict(data)
