"""代理链裁决器。

裁决从*最靠近应用的一跳*（TCP 直连对端）开始，沿转发头自右向左
逐跳核对：对端地址必须落入登记跳点网段、跳点必须授权该头部族、
配置了秘密值时该跳点写入的 Forwarded 元素必须携带匹配的
``secret``/``by`` 标记。

任一环节失败即停止采信其左侧全部声明，并给出对应的可解释结论：

* 遇到未登记地址的中间跳点 → ``unknown_hop``，有效来源回退为该跳点
  地址（它由已验证的右侧跳点观察并写入，仍然真实）；
* 登记可信链短于头部声明链 → ``chain_truncated``，回退到截断边界；
* 两族并存且不一致，或出现未授权族/过期族 → ``conflict``，
  全部转发声明不采信；
* 转发头无法解析 → ``malformed``。
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from sanic.proxy.parsers import (
    normalize_node,
    normalize_path,
    normalize_proto,
    parse_forwarded_elements,
    parse_xforwarded_for,
    pick_xforwarded_value,
)
from sanic.proxy.policy import ProxyPolicy
from sanic.proxy.types import (
    ChainHop,
    HeaderFamily,
    ProxyDecision,
    ProxyDecisionAction,
    ProxyVerdict,
    utcnow,
)


class ProxyJudge:
    """按给定策略版本裁决请求的转发链。

    Args:
        policy: 受理时绑定的不可变策略版本；请求处理期间持续复用。
        clock: 可注入的时钟（用于迁移期限判定与测试）。
    """

    def __init__(
        self,
        policy: ProxyPolicy,
        *,
        clock: Callable[[], datetime] | None = None,
    ):
        self.policy = policy
        self._clock = clock or utcnow

    def adjudicate(
        self,
        headers,
        peer: str | None,
        *,
        xff_header: str = "x-forwarded-for",
    ) -> ProxyDecision:
        """执行裁决，返回 :class:`ProxyDecision`。"""
        decision = self._adjudicate(headers, peer, xff_header=xff_header)
        decision.log_full_chain = self.policy.log_full_chain
        return decision

    def _adjudicate(
        self,
        headers,
        peer: str | None,
        *,
        xff_header: str = "x-forwarded-for",
    ) -> ProxyDecision:
        """执行裁决，返回 :class:`ProxyDecision`。"""
        policy = self.policy
        version = policy.version

        fwd_raw = headers.getall("forwarded", None)
        xff_raw = headers.getall(xff_header, None)
        fwd_present = fwd_raw is not None
        xff_present = xff_raw is not None

        # 已登记的 Real-IP 头作为 X 族的边缘观察头参与裁决
        real_ip = None
        if self.policy.real_ip_header:
            raw_real = headers.getone(self.policy.real_ip_header.lower(), None)
            real_ip = normalize_node(raw_real)

        # 无任何转发头：直连
        if not fwd_present and not xff_present and real_ip is None:
            return self._direct(peer, version)

        elements = (
            parse_forwarded_elements(list(fwd_raw)) if fwd_present else []
        )
        entries = parse_xforwarded_for(list(xff_raw)) if xff_present else []
        # 仅 X-Real-IP（登记过）时视为单条 X 族声明
        real_ip_only = bool(real_ip and not xff_present and not fwd_present)
        if real_ip_only and real_ip is not None:
            entries = [real_ip]

        if not elements and not entries:
            return self._direct(
                peer, version, "empty forwarding header(s) ignored"
            )

        # 迁移期限：决定 X-Forwarded-* 在当前时刻是否仍被允许
        stage = None
        x_allowed = HeaderFamily.XFORWARDED in policy.families
        if policy.migration is not None:
            stage = policy.migration.grace_status(self._clock())
            if stage in ("before", "grace"):
                x_allowed = True

        # 头部族授权
        if fwd_present and HeaderFamily.FORWARDED not in policy.families:
            return self._reject(
                ProxyVerdict.CONFLICT,
                peer,
                version,
                self._chain(elements, entries),
                HeaderFamily.FORWARDED,
                "forwarded header family is not authorized by policy",
            )
        if (xff_present or real_ip_only) and not x_allowed:
            return self._reject(
                ProxyVerdict.CONFLICT,
                peer,
                version,
                self._chain(elements, entries),
                HeaderFamily.XFORWARDED,
                "x-forwarded family is past its migration grace period "
                f"(stage={stage})",
            )

        # 语法校验
        errors = [f"forwarded: {e.error}" for e in elements if e.error]
        for value in entries:
            if self._ip(value) is None:
                errors.append(
                    f"x-forwarded-for contains non-address entry: {value!r}"
                )
        if errors:
            return self._reject(
                ProxyVerdict.MALFORMED,
                peer,
                version,
                self._chain(elements, entries),
                HeaderFamily.FORWARDED if fwd_present else None,
                *errors,
            )

        # 两族（及 X-Real-IP）并存：声明序列必须逐位一致
        if fwd_present and (xff_present or real_ip is not None):
            fwd_addrs = [self._ip(e.get("for")) for e in elements]
            consistent = True
            detail = ""
            if xff_present:
                consistent, detail = self._compare_chains(fwd_addrs, entries)
            if consistent and real_ip is not None:
                # X-Real-IP 记录的是边缘观察到的原始客户端，必须与
                # 两种链的最左（客户端侧）条目一致
                leftmost = str(fwd_addrs[0]) if fwd_addrs else None
                if real_ip != leftmost:
                    consistent = False
                    detail = (
                        f"real-ip {real_ip!r} disagrees with leftmost "
                        f"forwarded entry {leftmost!r}"
                    )
            if not consistent:
                return self._reject(
                    ProxyVerdict.CONFLICT,
                    peer,
                    version,
                    self._chain(elements, entries),
                    None,
                    detail,
                )

        # X 族元数据（最左一跳写入的客户端视角值优先）
        x_meta = self._x_metadata(headers) if not fwd_present else None

        if not fwd_present and xff_present and real_ip is not None:
            leftmost = str(self._ip(entries[0]))
            if real_ip != leftmost:
                return self._reject(
                    ProxyVerdict.CONFLICT,
                    peer,
                    version,
                    self._chain(elements, entries),
                    HeaderFamily.XFORWARDED,
                    f"real-ip {real_ip!r} disagrees with leftmost "
                    f"x-forwarded-for entry {leftmost!r}",
                )

        if fwd_present:
            return self._walk_forwarded(elements, peer, version, stage)
        return self._walk_xforwarded(
            entries, peer, version, stage, x_meta, real_ip_only
        )

    # ------------------------------------------------------------------ #
    # 逐跳校验
    # ------------------------------------------------------------------ #

    def _walk_forwarded(self, elements, peer, version, stage) -> ProxyDecision:
        """沿 Forwarded 元素自右向左校验。

        元素 ``e_j``（左→右；``e_{m-1}`` 由直连对端写入）的写入者位于
        可信链位置 ``m-1-j``；位置 p 的校验为：``e_{m-p}`` 的 ``for``
        必须落入深度 p 的登记网段，``e_{m-1-p}`` 必须带该跳点的秘密标记。
        """
        m = len(elements)
        reasons: list[str] = []
        validated: set[int] = set()

        ok, why = self._check_anchor(peer, elements[m - 1])
        if not ok:
            reasons.append(why)
            return self._build(
                ProxyVerdict.UNKNOWN_HOP,
                ProxyDecisionAction.FALLBACK,
                peer,
                peer,
                version,
                elements=elements,
                entries=[],
                validated_fwd=set(),
                family=HeaderFamily.FORWARDED,
                reasons=reasons,
            )
        validated.add(m - 1)

        verdict = ProxyVerdict.TRUSTED
        effective = peer
        for p in range(1, m):
            declared_ip = self._ip(elements[m - p].get("for"))
            hop = self.policy.hop_at(p)
            if hop is None:
                verdict = ProxyVerdict.CHAIN_TRUNCATED
                reasons.append(
                    f"trusted chain ends at depth {p - 1}; header still "
                    f"claims {m - p} element(s) to its left"
                )
            elif declared_ip is None:
                verdict = ProxyVerdict.CHAIN_TRUNCATED
                reasons.append(
                    f"element at depth {p} records no usable 'for' address; "
                    "chain cannot be traced further left"
                )
            elif not hop.authorizes(str(declared_ip), HeaderFamily.FORWARDED):
                verdict = ProxyVerdict.UNKNOWN_HOP
                reasons.append(
                    f"address {declared_ip} observed at depth {p} is outside "
                    f"registered network {hop.cidr}"
                )
            elif not self._secret_ok(hop, elements[m - 1 - p]):
                verdict = ProxyVerdict.UNKNOWN_HOP
                reasons.append(
                    f"element written at depth {p} carries no matching "
                    "secret/by marker"
                )
            else:
                # hop p 身份与本元素签名均通过：元素 e_{m-1-p} 的 for
                # 是该可信跳点的真实观察，链条可继续向左
                validated.add(m - 1 - p)
                effective = str(
                    self._ip(elements[m - 1 - p].get("for")) or declared_ip
                )
                continue
            # 截断/未知跳：边界地址（已验证跳点的真实观察）作为有效来源
            if declared_ip is not None:
                effective = str(declared_ip)
            break
        else:
            # 写入者全部验证通过：最左元素的 for 即原始客户端
            client = self._ip(elements[0].get("for"))
            if client is None:
                return self._build(
                    ProxyVerdict.CHAIN_TRUNCATED,
                    ProxyDecisionAction.FALLBACK,
                    peer,
                    peer,
                    version,
                    elements=elements,
                    entries=[],
                    validated_fwd=validated,
                    family=HeaderFamily.FORWARDED,
                    reasons=[
                        "leftmost element records no usable 'for' address"
                    ],
                )
            effective = str(client)

        action = (
            ProxyDecisionAction.ACCEPT
            if verdict is ProxyVerdict.TRUSTED
            else ProxyDecisionAction.FALLBACK
        )
        return self._build(
            verdict,
            action,
            effective,
            peer,
            version,
            elements=elements,
            entries=[],
            validated_fwd=validated,
            family=HeaderFamily.FORWARDED,
            reasons=reasons,
        )

    def _walk_xforwarded(
        self, entries, peer, version, stage, x_meta, real_ip_only
    ) -> ProxyDecision:
        """沿 X-Forwarded-For 自右向左校验。

        XFF 不记录写入者：``x_{m-1}`` 是深度 0 跳点观察到的上游，
        必须落入深度 1 的登记网段，依此类推；最左条目为候选客户端。
        """
        m = len(entries)
        reasons: list[str] = []
        hop0 = self.policy.hop_at(0)
        if hop0 is None or not hop0.authorizes(
            peer or "", HeaderFamily.XFORWARDED
        ):
            reasons.append(
                f"direct peer {peer!r} is not a registered trusted hop "
                "authorized for x-forwarded (depth 0)"
            )
            return self._build(
                ProxyVerdict.UNKNOWN_HOP,
                ProxyDecisionAction.FALLBACK,
                peer,
                peer,
                version,
                elements=[],
                entries=entries,
                validated_xff=0,
                family=HeaderFamily.XFORWARDED,
                reasons=reasons,
                x_meta=None,
            )

        verdict = ProxyVerdict.TRUSTED
        effective = peer
        validated_xff = 0
        # x_{m-1} 必须是深度 1 的登记跳点；x_0 是最左可信跳点观察到的
        # 客户端，不再要求其匹配任何网段。
        for k in range(m):
            declared_ip = self._ip(entries[m - 1 - k])
            if k < m - 1:
                hop = self.policy.hop_at(k + 1)
                if hop is None:
                    verdict = ProxyVerdict.CHAIN_TRUNCATED
                    reasons.append(
                        f"trusted chain ends at depth {k}; header still "
                        f"claims {m - 1 - k} additional entrie(s) to its left"
                    )
                    # entries[m-1-k] 是已验证跳点 hop k 的真实观察，
                    # 作为截断边界计入受担保链段
                    validated_xff = k + 1
                    effective = str(declared_ip)
                    break
                if not hop.authorizes(
                    str(declared_ip), HeaderFamily.XFORWARDED
                ):
                    verdict = ProxyVerdict.UNKNOWN_HOP
                    reasons.append(
                        f"address {declared_ip} observed at depth {k + 1} "
                        f"is outside registered network {hop.cidr}"
                    )
                    validated_xff = k + 1
                    effective = str(declared_ip)
                    break
            # 该条目已受担保（已验证跳点本身，或最左的客户端观察）
            validated_xff = k + 1
            effective = str(declared_ip)

        action = (
            ProxyDecisionAction.ACCEPT
            if verdict is ProxyVerdict.TRUSTED
            else ProxyDecisionAction.FALLBACK
        )
        if verdict is ProxyVerdict.TRUSTED and stage == "grace":
            verdict = ProxyVerdict.MIGRATION_GRACE
            reasons.append(
                "x-forwarded-* accepted during migration grace period; "
                "forwarded becomes required after it ends"
            )
        elif verdict is ProxyVerdict.TRUSTED and stage == "before":
            reasons.append("x-forwarded-* accepted before migration start")
        if real_ip_only:
            reasons.append("client derived from registered real-ip header")

        # 仅完整受担保的链才采信 X 族元数据；截断/未知跳时 proto/host
        # 等单值头无法确认写入者，可能由请求方伪造
        if action is not ProxyDecisionAction.ACCEPT:
            x_meta = None

        return self._build(
            verdict,
            action,
            effective,
            peer,
            version,
            elements=[],
            entries=entries,
            validated_xff=validated_xff,
            family=HeaderFamily.XFORWARDED,
            reasons=reasons,
            x_meta=x_meta,
        )

    def _check_anchor(self, peer, element) -> tuple[bool, str]:
        hop0 = self.policy.hop_at(0)
        if hop0 is None:
            return False, (
                f"direct peer {peer!r} is not a registered trusted hop "
                "(no depth 0 hop)"
            )
        if not hop0.authorizes(peer or "", HeaderFamily.FORWARDED):
            return False, (
                f"direct peer {peer!r} is outside registered network "
                f"{hop0.cidr} at depth 0"
            )
        if not self._secret_ok(hop0, element):
            return False, (
                "rightmost forwarded element carries no matching secret/by "
                "marker for the depth 0 hop"
            )
        return True, ""

    @staticmethod
    def _secret_ok(hop, element) -> bool:
        if not hop.secret:
            return True
        return hop.validates_secret(element.get("secret")) or (
            element.get("by") == hop.secret
        )

    # ------------------------------------------------------------------ #
    # 结论构造
    # ------------------------------------------------------------------ #

    def _build(
        self,
        verdict,
        action,
        effective,
        peer,
        version,
        *,
        elements,
        entries,
        family,
        reasons,
        validated_fwd: set[int] | None = None,
        validated_xff: int = 0,
        x_meta=None,
    ) -> ProxyDecision:
        original = self._chain(elements, entries)
        validated_hops: list[ChainHop] = []
        if elements:
            validated_hops.extend(
                self._fwd_hop(elements[i])
                for i in sorted(validated_fwd or set())
            )
        if entries and validated_xff:
            validated_hops.extend(
                ChainHop(forwarded_for=addr, family=HeaderFamily.XFORWARDED)
                for addr in entries[-validated_xff:]
            )

        proto = host = path = None
        port = None
        if action != ProxyDecisionAction.REJECT:
            if elements:
                proto, host, port, path = self._fwd_metadata(
                    elements, validated_fwd or set()
                )
            elif x_meta:
                proto, host, port, path = x_meta

        return ProxyDecision(
            verdict=verdict,
            action=action,
            effective_client=effective,
            peer=peer,
            policy_version=version,
            original_chain=original,
            validated_chain=tuple(validated_hops),
            family=family,
            proto=proto,
            host=host,
            port=port,
            path=path,
            reasons=tuple(reasons),
        )

    def _fwd_metadata(self, elements, validated):
        # 客户端可见的原始 proto/host/path 由链上最左（最靠近原始
        # 客户端）的已验证跳点记录；仅在其缺省时才回退到更近的跳点。
        proto = host = path = None
        port = None
        for i in sorted(validated):
            elem = elements[i]
            proto = proto or normalize_proto(elem.get("proto"))
            host = host or (elem.get("host") or "").lower() or None
            path = path or normalize_path(elem.get("path"))
            if port is None:
                raw_port = elem.get("port")
                if raw_port and raw_port.isdigit():
                    port = int(raw_port)
        return proto, host, port, path

    @staticmethod
    def _x_metadata(headers):
        # 最左值由最靠近原始客户端的可信跳点写入（如边缘看到的
        # https），比内部跳点之间使用的协议更接近客户端视角
        proto = normalize_proto(
            pick_xforwarded_value(headers, "x-forwarded-proto", leftmost=True)
        )
        host_raw = pick_xforwarded_value(
            headers, "x-forwarded-host", leftmost=True
        )
        host = host_raw.lower() if host_raw else None
        path = normalize_path(
            pick_xforwarded_value(headers, "x-forwarded-path", leftmost=True)
        )
        port = None
        raw_port = pick_xforwarded_value(
            headers, "x-forwarded-port", leftmost=True
        )
        if raw_port and raw_port.isdigit():
            port = int(raw_port)
        return proto, host, port, path

    @staticmethod
    def _direct(peer, version, reason: str | None = None) -> ProxyDecision:
        reasons = (reason,) if reason else ()
        return ProxyDecision(
            verdict=ProxyVerdict.DIRECT,
            action=ProxyDecisionAction.ACCEPT,
            effective_client=peer,
            peer=peer,
            policy_version=version,
            reasons=reasons,
        )

    def _reject(
        self,
        verdict,
        peer,
        version,
        original,
        family,
        *reasons: str,
    ) -> ProxyDecision:
        return ProxyDecision(
            verdict=verdict,
            action=ProxyDecisionAction.REJECT,
            effective_client=peer,
            peer=peer,
            policy_version=version,
            original_chain=original,
            family=family,
            reasons=tuple(reasons),
        )

    @staticmethod
    def _compare_chains(fwd_addrs, entries) -> tuple[bool, str]:
        f = [str(a) if a is not None else None for a in fwd_addrs]
        x = [
            str(ProxyJudge._ip(v)) if ProxyJudge._ip(v) else None
            for v in entries
        ]
        if f == x:
            return True, ""
        return False, (
            "forwarded and x-forwarded-* disagree: "
            f"forwarded-for={f} x-forwarded-for={x}; none of the claims "
            "are trusted"
        )

    @staticmethod
    def _chain(fwd_elements, xff_entries) -> tuple[ChainHop, ...]:
        hops: list[ChainHop] = [
            ProxyJudge._fwd_hop(elem) for elem in fwd_elements
        ]
        hops.extend(
            ChainHop(forwarded_for=addr, family=HeaderFamily.XFORWARDED)
            for addr in xff_entries
        )
        return tuple(hops)

    @staticmethod
    def _fwd_hop(elem) -> ChainHop:
        raw_port = elem.get("port")
        return ChainHop(
            forwarded_for=normalize_node(elem.get("for")),
            family=HeaderFamily.FORWARDED,
            secret=elem.get("secret"),
            proto=normalize_proto(elem.get("proto")),
            host=(elem.get("host") or "").lower() or None,
            port=int(raw_port) if raw_port and raw_port.isdigit() else None,
            path=normalize_path(elem.get("path")),
            error=elem.error,
        )

    @staticmethod
    def _ip(value):
        from ipaddress import ip_address

        if value is None:
            return None
        value = normalize_node(value) if isinstance(value, str) else value
        if not value or value == "unknown" or value.startswith("_"):
            return None
        try:
            return ip_address(value)
        except ValueError:
            return None
