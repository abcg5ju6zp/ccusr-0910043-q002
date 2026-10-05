"""代理链裁决（proxy chain adjudication）。

当应用部署在多层反向代理之后，请求头中可能同时存在 RFC 7239
``Forwarded`` 与 ``X-Forwarded-*`` 两族头部，且链条中的部分跳点
可能由请求方自行伪造。本模块提供一套可解释的裁决能力：

* 运营方通过 :class:`ProxyTrustRegistry` 登记可信跳点、允许的
  头部族与迁移期限；每次变更都会产生新的策略版本（热更新）。
* 请求受理时捕获当时的策略版本，裁决结果在整个请求生命周期内
  保持不变，正在处理的请求不受后续热更新影响。
* 裁决保留原始代理链，并按可信跳点自右向左计算唯一的有效来源。
* 双头并存、链条截断、未知中间跳点等情形都会给出可解释的结论
  （``family_verdict`` / ``chain_verdict`` 与 ``explanations``）。
* 日志输出通过 :meth:`ProxyDecision.log_context` 与
  :class:`ProxyLogFilter` 控制，未授权时只暴露裁决结论与元信息，
  不暴露原始链地址。
"""

from __future__ import annotations

import logging

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address, ip_network
from typing import Any, Iterable, Mapping, Sequence


__all__ = (
    "ChainVerdict",
    "FamilyVerdict",
    "HeaderFamily",
    "ProxyChain",
    "ProxyDecision",
    "ProxyHop",
    "ProxyLogFilter",
    "ProxyTrustPolicy",
    "ProxyTrustRegistry",
    "adjudicate",
    "parse_forwarded_chain",
    "parse_xforwarded_chain",
)


class HeaderFamily(str, Enum):
    """转发头家族。"""

    FORWARDED = "forwarded"
    X_FORWARDED = "x-forwarded"


class FamilyVerdict(str, Enum):
    """头部族裁决结论（选用哪一族头部、为何选用）。"""

    FORWARDED_USED = "forwarded_used"
    X_FORWARDED_USED = "x_forwarded_used"
    X_FORWARDED_MIGRATION_WINDOW = "x_forwarded_migration_window"
    CONFLICT_FORWARDED_WINS = "conflict_forwarded_wins"
    CONFLICT_X_FORWARDED_WINS = "conflict_x_forwarded_wins"
    MIGRATION_EXPIRED = "migration_expired"
    FAMILY_NOT_ALLOWED = "family_not_allowed"
    NO_FORWARDED_HEADERS = "no_forwarded_headers"


class ChainVerdict(str, Enum):
    """代理链裁决结论（有效来源如何得出）。"""

    EFFECTIVE_FROM_CHAIN = "effective_from_chain"
    CHAIN_TRUNCATED = "chain_truncated"
    NO_CHAIN_ENTRIES = "no_chain_entries"
    UNTRUSTED_PEER = "untrusted_peer"
    NO_TRUSTED_HOPS = "no_trusted_hops"


def _split_quoted(value: str, sep: str) -> list[str]:
    """按分隔符切分，忽略引号内的分隔符。"""
    parts: list[str] = []
    buf: list[str] = []
    quoted = escaped = False
    for ch in value:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\" and quoted:
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif ch == sep and not quoted:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        value = value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return value


def _extract_address(node: str) -> str:
    """从 forwarded 节点标识中提取地址部分（去掉端口与方括号）。"""
    node = _unquote(node).strip()
    if not node or node.lower() == "unknown":
        return ""
    if node.startswith("["):
        end = node.find("]")
        return node[1:end] if end != -1 else node
    if node.count(":") == 1:
        host, _, maybe_port = node.rpartition(":")
        if maybe_port.isdigit():
            return host
    return node


def parse_forwarded_chain(headers: Any) -> tuple[str, ...]:
    """解析 ``Forwarded`` 头中全部 ``for=`` 节点，按客户端到代理的顺序返回。"""
    values = headers.getall("forwarded", None)
    if not values:
        return ()
    chain: list[str] = []
    for value in values:
        for element in _split_quoted(value, ","):
            for pair in _split_quoted(element, ";"):
                key, sep, val = pair.partition("=")
                if sep and key.strip().lower() == "for":
                    addr = _extract_address(val)
                    if addr:
                        chain.append(addr)
                    break
    return tuple(chain)


def parse_xforwarded_chain(
    headers: Any, header_name: str = "x-forwarded-for"
) -> tuple[str, ...]:
    """解析 ``X-Forwarded-For`` 头，按客户端到代理的顺序返回。"""
    values = headers.getall(header_name, None)
    if not values:
        return ()
    chain: list[str] = []
    for value in values:
        for element in _split_quoted(value, ","):
            addr = _extract_address(element)
            if addr:
                chain.append(addr)
    return tuple(chain)


def _normalize_deadline(
    deadline: datetime | str | None,
) -> datetime | None:
    if deadline is None or isinstance(deadline, datetime):
        parsed = deadline
    else:
        parsed = datetime.fromisoformat(str(deadline))
    if parsed is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass(frozen=True)
class ProxyTrustPolicy:
    """一次登记产生的不可变代理信任策略。

    ``version`` 由 :class:`ProxyTrustRegistry` 在每次热更新时递增，
    请求受理时绑定当时的版本，处理过程中不受后续更新影响。
    """

    trusted_hops: tuple[str, ...] = ()
    allowed_families: frozenset[HeaderFamily] = frozenset(
        {HeaderFamily.FORWARDED, HeaderFamily.X_FORWARDED}
    )
    migration_deadline: datetime | None = None
    prefer: HeaderFamily = HeaderFamily.FORWARDED
    version: int = 0
    _networks: tuple[Any, ...] = field(default=(), repr=False, compare=False)
    _literals: frozenset[str] = field(
        default=frozenset(), repr=False, compare=False
    )

    def __post_init__(self):
        networks: list[Any] = []
        literals: list[str] = []
        for hop in self.trusted_hops:
            try:
                networks.append(ip_network(str(hop), strict=False))
            except ValueError:
                literals.append(str(hop).lower())
        object.__setattr__(self, "_networks", tuple(networks))
        object.__setattr__(self, "_literals", frozenset(literals))
        object.__setattr__(
            self,
            "allowed_families",
            frozenset(HeaderFamily(f) for f in self.allowed_families),
        )
        object.__setattr__(self, "prefer", HeaderFamily(self.prefer))
        object.__setattr__(
            self,
            "migration_deadline",
            _normalize_deadline(self.migration_deadline),
        )

    def is_trusted(self, address: str) -> bool:
        """判断某个跳点地址是否已登记为可信。"""
        if not address:
            return False
        try:
            ip = ip_address(_extract_address(address))
        except ValueError:
            return address.lower() in self._literals
        return any(ip in network for network in self._networks)

    def migration_open(self, now: datetime) -> bool:
        """迁移窗口是否仍然开放（未设期限视为一直开放）。"""
        if self.migration_deadline is None:
            return True
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return now <= self.migration_deadline


class ProxyTrustRegistry:
    """可信代理策略登记表，支持热更新。

    每次 :meth:`update` 基于当前策略生成一个新版本的
    :class:`ProxyTrustPolicy` 并原子替换；已经受理的请求持有的是
    旧版本策略对象，因此热更新只影响之后受理的请求。
    """

    def __init__(self, policy: ProxyTrustPolicy | None = None):
        self._policy = policy or ProxyTrustPolicy()

    @property
    def current(self) -> ProxyTrustPolicy:
        """当前生效的策略版本。"""
        return self._policy

    def update(
        self,
        *,
        trusted_hops: Sequence[str] | None = None,
        allowed_families: Iterable[str | HeaderFamily] | None = None,
        migration_deadline: datetime | str | None = None,
        prefer: str | HeaderFamily | None = None,
    ) -> ProxyTrustPolicy:
        """登记新的策略并返回，版本号递增。"""
        changes: dict[str, Any] = {"version": self._policy.version + 1}
        if trusted_hops is not None:
            changes["trusted_hops"] = tuple(str(h) for h in trusted_hops)
        if allowed_families is not None:
            changes["allowed_families"] = frozenset(
                HeaderFamily(f) for f in allowed_families
            )
        if migration_deadline is not None:
            changes["migration_deadline"] = _normalize_deadline(
                migration_deadline
            )
        if prefer is not None:
            changes["prefer"] = HeaderFamily(prefer)
        self._policy = replace(self._policy, **changes)
        return self._policy

    @classmethod
    def from_config(cls, config: Any) -> ProxyTrustRegistry:
        """从应用配置构建登记表。"""
        return cls(
            ProxyTrustPolicy(
                trusted_hops=tuple(config.get("PROXY_TRUSTED_HOPS", ()) or ()),
                allowed_families=frozenset(
                    config.get(
                        "PROXY_ALLOWED_FAMILIES",
                        ("forwarded", "x-forwarded"),
                    )
                    or ()
                ),
                migration_deadline=config.get("PROXY_MIGRATION_DEADLINE"),
                prefer=config.get("PROXY_PREFER", "forwarded"),
            )
        )


@dataclass(frozen=True)
class ProxyHop:
    """代理链中的一个跳点。"""

    address: str
    trusted: bool
    source: str  # "peer" 或 "header"


@dataclass(frozen=True)
class ProxyChain:
    """请求受理时保留的原始代理链。"""

    peer: str
    hops: tuple[ProxyHop, ...]
    family: HeaderFamily | None
    raw_headers: Mapping[str, tuple[str, ...]]

    @property
    def addresses(self) -> tuple[str, ...]:
        """链上全部跳点地址：对端在前，其后为头部链（客户端→代理）。"""
        return tuple(h.address for h in self.hops)


@dataclass(frozen=True)
class ProxyDecision:
    """一次代理链裁决的可解释结论。"""

    effective_source: str
    family: HeaderFamily | None
    family_verdict: FamilyVerdict
    chain_verdict: ChainVerdict
    policy_version: int
    chain: ProxyChain
    explanations: tuple[str, ...]

    def log_context(self, authorized: bool = False) -> dict[str, Any]:
        """生成可写入日志的上下文字典。

        未授权（默认）时只暴露裁决结论、有效来源与链长度；
        授权后才包含原始链上的具体地址。
        """
        context: dict[str, Any] = {
            "proxy_effective_source": self.effective_source,
            "proxy_family": self.family.value if self.family else None,
            "proxy_family_verdict": self.family_verdict.value,
            "proxy_chain_verdict": self.chain_verdict.value,
            "proxy_policy_version": self.policy_version,
        }
        if authorized:
            context["proxy_peer"] = self.chain.peer
            context["proxy_chain"] = list(self.chain.addresses)
        else:
            context["proxy_chain_length"] = len(self.chain.hops)
        return context


class ProxyLogFilter(logging.Filter):
    """日志过滤器：按授权级别注入代理裁决信息。

    挂到任意 logger 上后，若日志记录带有 ``proxy_decision`` 属性，
    会把 :meth:`ProxyDecision.log_context` 的字段合并进记录，
    保证未授权日志中不会出现原始代理链地址。
    """

    def __init__(self, authorized: bool = False, name: str = ""):
        super().__init__(name)
        self.authorized = authorized

    def filter(self, record: logging.LogRecord) -> bool:
        decision = getattr(record, "proxy_decision", None)
        if isinstance(decision, ProxyDecision):
            for key, value in decision.log_context(self.authorized).items():
                setattr(record, key, value)
            if not self.authorized:
                for key in ("proxy_chain", "proxy_peer"):
                    if hasattr(record, key):
                        setattr(record, key, None)
        return True


def _select_family(
    forwarded_chain: tuple[str, ...],
    xforwarded_chain: tuple[str, ...],
    policy: ProxyTrustPolicy,
    now: datetime,
    explanations: list[str],
) -> tuple[HeaderFamily | None, tuple[str, ...], FamilyVerdict]:
    """在两族头部中选出可用的一族，并记录可解释的理由。"""
    forwarded_allowed = HeaderFamily.FORWARDED in policy.allowed_families
    x_allowed = HeaderFamily.X_FORWARDED in policy.allowed_families
    migration_open = policy.migration_open(now)

    if xforwarded_chain and not migration_open:
        explanations.append("X-Forwarded-* 迁移期限已过，该族头部不再被受理")
        x_expired = True
    else:
        x_expired = False
    x_usable = bool(xforwarded_chain) and x_allowed and not x_expired
    fwd_usable = bool(forwarded_chain) and forwarded_allowed

    if forwarded_chain and xforwarded_chain:
        if fwd_usable and (
            policy.prefer is HeaderFamily.FORWARDED or not x_usable
        ):
            explanations.append(
                "Forwarded 与 X-Forwarded-* 同时存在，按策略优先采用 Forwarded"
            )
            return (
                HeaderFamily.FORWARDED,
                forwarded_chain,
                FamilyVerdict.CONFLICT_FORWARDED_WINS,
            )
        if x_usable:
            explanations.append(
                "Forwarded 与 X-Forwarded-* 同时存在，按策略采用 X-Forwarded-*"
            )
            if policy.migration_deadline is not None:
                explanations.append(
                    "X-Forwarded-* 在迁移期限内被受理，请尽快迁移到 Forwarded"
                )
            return (
                HeaderFamily.X_FORWARDED,
                xforwarded_chain,
                FamilyVerdict.CONFLICT_X_FORWARDED_WINS,
            )
        explanations.append("两族头部均存在，但都不被当前策略允许")
        return None, (), FamilyVerdict.FAMILY_NOT_ALLOWED

    if forwarded_chain:
        if fwd_usable:
            return (
                HeaderFamily.FORWARDED,
                forwarded_chain,
                FamilyVerdict.FORWARDED_USED,
            )
        explanations.append("Forwarded 头存在，但该族未被策略允许")
        return None, (), FamilyVerdict.FAMILY_NOT_ALLOWED

    if xforwarded_chain:
        if x_expired:
            return None, (), FamilyVerdict.MIGRATION_EXPIRED
        if not x_allowed:
            explanations.append("X-Forwarded-* 头存在，但该族未被策略允许")
            return None, (), FamilyVerdict.FAMILY_NOT_ALLOWED
        if policy.migration_deadline is not None:
            explanations.append(
                "X-Forwarded-* 在迁移期限内被受理，请尽快迁移到 Forwarded"
            )
            return (
                HeaderFamily.X_FORWARDED,
                xforwarded_chain,
                FamilyVerdict.X_FORWARDED_MIGRATION_WINDOW,
            )
        return (
            HeaderFamily.X_FORWARDED,
            xforwarded_chain,
            FamilyVerdict.X_FORWARDED_USED,
        )

    return None, (), FamilyVerdict.NO_FORWARDED_HEADERS


def adjudicate(
    headers: Any,
    peer: str,
    policy: ProxyTrustPolicy,
    *,
    forwarded_for_header: str = "x-forwarded-for",
    now: datetime | None = None,
) -> ProxyDecision:
    """对一次请求执行代理链裁决。

    :param headers: 请求头（需支持 ``getall``）。
    :param peer: 直接对端地址（传输层对端 IP）。
    :param policy: 受理时捕获的信任策略版本。
    :param forwarded_for_header: X-Forwarded-For 的实际头名。
    :param now: 裁决时间（用于迁移期限判断，可注入以便测试）。
    """
    now = now or datetime.now(timezone.utc)
    explanations: list[str] = []

    forwarded_chain = parse_forwarded_chain(headers)
    xforwarded_chain = parse_xforwarded_chain(headers, forwarded_for_header)
    raw_headers: dict[str, tuple[str, ...]] = {}
    fwd_raw = tuple(headers.getall("forwarded", None) or ())
    if fwd_raw:
        raw_headers["forwarded"] = fwd_raw
    xff_raw = tuple(headers.getall(forwarded_for_header, None) or ())
    if xff_raw:
        raw_headers["x-forwarded-for"] = xff_raw

    family, chain, family_verdict = _select_family(
        forwarded_chain, xforwarded_chain, policy, now, explanations
    )

    def build(
        effective: str, verdict: ChainVerdict, entries: tuple[str, ...]
    ) -> ProxyDecision:
        hops = (ProxyHop(peer, policy.is_trusted(peer), "peer"),) + tuple(
            ProxyHop(addr, policy.is_trusted(addr), "header")
            for addr in entries
        )
        return ProxyDecision(
            effective_source=effective,
            family=family,
            family_verdict=family_verdict,
            chain_verdict=verdict,
            policy_version=policy.version,
            chain=ProxyChain(peer, hops, family, raw_headers),
            explanations=tuple(explanations),
        )

    if not policy.trusted_hops:
        explanations.append("未登记可信跳点，忽略全部转发头")
        return build(peer, ChainVerdict.NO_TRUSTED_HOPS, ())

    if not policy.is_trusted(peer):
        explanations.append(
            f"直接对端 {peer or '<unknown>'} 不在可信跳点中，"
            "转发头视为请求方伪造，予以忽略"
        )
        return build(peer, ChainVerdict.UNTRUSTED_PEER, ())

    if not chain:
        explanations.append("对端可信且无可用转发链，对端即有效来源")
        return build(peer, ChainVerdict.NO_CHAIN_ENTRIES, ())

    # 自右向左遍历：可信跳点只为它左侧的条目背书，
    # 第一个不可信跳点即为有效来源。
    for addr in reversed(chain):
        if not policy.is_trusted(addr):
            explanations.append(
                f"跳点 {addr} 未登记为可信，将其裁定为有效来源；"
                "其左侧条目可能由请求方伪造，不予采信"
            )
            return build(addr, ChainVerdict.EFFECTIVE_FROM_CHAIN, chain)

    explanations.append(
        "链上全部跳点均可信，链条在此截断；"
        "最左侧条目裁定为有效来源，但其真实性无法继续验证"
    )
    return build(chain[0], ChainVerdict.CHAIN_TRUNCATED, chain)
