"""代理链裁决：登记可信跳点、允许的头部族与迁移期限，按受理时策略快照
计算唯一有效来源，并为异常链（双族并存、截断、未知跳点、格式错误）
给出可解释结论。"""

from __future__ import annotations

from sanic.proxy.judge import ProxyJudge
from sanic.proxy.policy import ProxyPolicy, ProxyPolicyRegistry
from sanic.proxy.types import (
    ChainHop,
    HeaderFamily,
    MigrationWindow,
    ProxyDecision,
    ProxyVerdict,
    TrustedHop,
)


__all__ = (
    "ChainHop",
    "HeaderFamily",
    "MigrationWindow",
    "ProxyDecision",
    "ProxyJudge",
    "ProxyPolicy",
    "ProxyPolicyRegistry",
    "ProxyVerdict",
    "TrustedHop",
)
