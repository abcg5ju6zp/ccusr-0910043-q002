"""代理链裁决的公共类型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_address


IPAddress = IPv4Address | IPv6Address


class HeaderFamily(str, Enum):
    """允许登记与裁决的转发头部族。"""

    FORWARDED = "forwarded"
    XFORWARDED = "x-forwarded"


class ProxyVerdict(str, Enum):
    """裁决结论。值用于日志与诊断，不参与信任判断。"""

    # 链条完整，所有声明跳点均为可信跳点，有效来源已确认
    TRUSTED = "trusted"
    # 遇到未登记的中间跳点，链条在该跳点处截断；
    # 有效来源回退为该跳点的对端地址，其左侧声明全部丢弃
    UNKNOWN_HOP = "unknown_hop"
    # 可信链长度不足，头部中仍有无法由可信跳点担保的条目；
    # 有效来源回退为直连对端
    CHAIN_TRUNCATED = "chain_truncated"
    # Forwarded 与 X-Forwarded-* 同时存在且内容冲突，
    # 或出现了策略未授权的头部族；全部转发声明均不采信
    CONFLICT = "conflict"
    # 转发头存在但无法解析
    MALFORMED = "malformed"
    # 解析错误或无法裁决（含未知地址、_obfuscated 节点）
    UNRESOLVED = "unresolved"
    # 请求方在迁移宽限期内仍只发送旧族头；按过渡策略处理
    MIGRATION_GRACE = "migration_grace"
    # 未携带任何转发头，有效来源即直连对端
    DIRECT = "direct"


class ProxyDecisionAction(str, Enum):
    """裁决动作：唯一来源是否来自被担保的转发声明。"""

    ACCEPT = "accept"
    FALLBACK = "fallback"
    REJECT = "reject"


@dataclass(frozen=True)
class MigrationWindow:
    """头部族迁移期限。

    Args:
        active_from: 新头部族开始被要求的时刻（UTC）。
        grace_until: 宽限截止时刻（UTC）；在此之前只携带旧族头的
            请求仍被接受，结论标记为 ``migration_grace``。
    """

    active_from: datetime
    grace_until: datetime

    def __post_init__(self) -> None:
        if self.grace_until < self.active_from:
            raise ValueError(
                "Proxy migration grace_until cannot be earlier than "
                "active_from"
            )

    def grace_status(self, now: datetime) -> str:
        """返回 ``before`` / ``grace`` / ``after`` 三阶段。"""
        if now < self.active_from:
            return "before"
        if now <= self.grace_until:
            return "grace"
        return "after"


@dataclass(frozen=True)
class TrustedHop:
    """一个可信跳点。

    Args:
        cidr: 该跳点直连下游地址允许落入的网段（如 ``10.0.0.0/8``）。
        families: 该跳点被授权写入的头部族。
        secret: 可选的 Forwarded 秘密值；配置后该跳点写入的
            Forwarded 元素必须携带匹配的 ``secret``/``by``。
        depth: 在可信链中的序号，0 为最靠近应用的一跳。
    """

    cidr: str
    families: frozenset[HeaderFamily]
    secret: str | None = None
    depth: int = 0

    def __post_init__(self) -> None:
        import ipaddress

        object.__setattr__(self, "_network", ipaddress.ip_network(self.cidr))

    @property
    def network(self):
        return object.__getattribute__(self, "_network")

    def authorizes(self, addr: str, family: HeaderFamily) -> bool:
        """该跳点是否为给定对端地址与头部族背书。"""
        try:
            parsed = ip_address(_strip_port(addr))
        except ValueError:
            return False
        if parsed not in self.network:
            return False
        return family in self.families

    def validates_secret(self, value: str | None) -> bool:
        if not self.secret:
            return True
        return value == self.secret


@dataclass
class ChainHop:
    """转发链上的一个跳点（按客户端 -> 应用方向排列）。"""

    # 头部中声明的 for 地址（保留原文，用于审计与解释）
    forwarded_for: str | None
    # 该条目由哪个头部族承载
    family: HeaderFamily
    # Forwarded 元素携带的 secret/by 值
    secret: str | None = None
    proto: str | None = None
    host: str | None = None
    port: int | None = None
    path: str | None = None
    # 解析问题说明（None 表示该跳点本身可解析）
    error: str | None = None

    @property
    def address(self) -> str | None:
        """归一化后的声明地址；无法解析时为 None。"""
        if self.forwarded_for is None:
            return None
        try:
            parsed = ip_address(_strip_port(self.forwarded_for))
        except ValueError:
            return None
        return str(parsed)


@dataclass
class ProxyDecision:
    """一次请求的代理链裁决结果（可解释结论）。"""

    verdict: ProxyVerdict
    action: ProxyDecisionAction
    # 唯一有效来源地址；回退或拒绝时为直连对端地址
    effective_client: str | None
    # 直连对端（TCP 层），始终保留，供授权后的审计使用
    peer: str | None
    # 受理时使用的策略版本号
    policy_version: int
    # 原始链的逐跳保留（客户端 -> 应用方向），不做删除
    original_chain: tuple[ChainHop, ...] = field(default_factory=tuple)
    # 经担保确认的链段（截断点左侧的部分被排除）
    validated_chain: tuple[ChainHop, ...] = field(default_factory=tuple)
    # 实际采信的头部族
    family: HeaderFamily | None = None
    proto: str | None = None
    host: str | None = None
    port: int | None = None
    path: str | None = None
    # 人类可读的逐条理由
    reasons: tuple[str, ...] = field(default_factory=tuple)
    # 策略版本是否授权在日志中暴露完整原始链
    log_full_chain: bool = False

    @property
    def trusted(self) -> bool:
        return self.action == ProxyDecisionAction.ACCEPT

    @property
    def validated_hops(self) -> int:
        return len(self.validated_chain)

    def explain(self) -> str:
        """返回单行可解释结论。"""
        chain = (
            " -> ".join(
                hop.forwarded_for or "?" for hop in self.original_chain
            )
            or "-"
        )
        reasons = "; ".join(self.reasons) or self.verdict.value
        effective = self.effective_client or "-"
        peer = self.peer or "-"
        return (
            f"verdict={self.verdict.value} action={self.action.value} "
            f"effective={effective} peer={peer} "
            f"validated_hops={self.validated_hops} "
            f"policy=v{self.policy_version} chain=[{chain}] {reasons}"
        )


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _strip_port(addr: str) -> str:
    addr = addr.strip()
    # RFC 7239 节点名中的 IPv4 端口写法： 1.2.3.4:5678
    if addr.count(".") == 3 and ":" in addr and not addr.startswith("["):
        addr = addr.rpartition(":")[0]
    # [::1]:1234
    if addr.startswith("["):
        end = addr.find("]")
        if end != -1:
            addr = addr[1:end]
    return addr
