"""版本化代理链策略与注册中心，支持配置热更新。

注册中心维护不可变的 :class:`ProxyPolicy` 版本序列；请求在受理时
通过 :meth:`ProxyPolicyRegistry.snapshot` 绑定一个版本，整个处理
周期继续使用该版本，热更新只影响之后受理的请求。"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from sanic.log import logger
from sanic.proxy.types import HeaderFamily, MigrationWindow, TrustedHop


# 信号名：策略热更新发布后触发
PROXY_POLICY_RELOADED = "proxy.policy.reloaded"

_DEFAULT_FAMILIES = frozenset(
    {HeaderFamily.FORWARDED, HeaderFamily.XFORWARDED}
)


class ProxyPolicy:
    """不可变策略版本。

    Args:
        hops: 可信跳点链，按 *应用近端 -> 边缘远端* 方向登记
            （depth 0 = 直连应用的一跳）。
        families: 全局允许的头部族；为空时继承全部两族。
        real_ip_header: 可信跳点可能写入的 Real-IP 头名（可选）。
        migration: 可选的 X-Forwarded-* -> Forwarded 迁移窗口。
        log_full_chain: 日志中是否允许暴露完整声明链。
    """

    __slots__ = (
        "families",
        "hops_by_depth",
        "log_full_chain",
        "migration",
        "real_ip_header",
        "version",
    )

    families: frozenset[HeaderFamily]
    hops_by_depth: dict[int, TrustedHop]
    log_full_chain: bool
    migration: MigrationWindow | None
    real_ip_header: str | None
    version: int

    def __init__(
        self,
        hops: Sequence[TrustedHop] | None = None,
        *,
        families: frozenset[HeaderFamily] | None = None,
        real_ip_header: str | None = None,
        migration: MigrationWindow | None = None,
        log_full_chain: bool = False,
        version: int = 1,
    ):
        sorted_hops = sorted(hops or [], key=lambda hop: hop.depth)
        object.__setattr__(
            self,
            "hops_by_depth",
            {hop.depth: hop for hop in sorted_hops},
        )
        object.__setattr__(
            self,
            "families",
            families if families is not None else _DEFAULT_FAMILIES,
        )
        object.__setattr__(self, "real_ip_header", real_ip_header)
        object.__setattr__(self, "migration", migration)
        object.__setattr__(self, "log_full_chain", log_full_chain)
        object.__setattr__(self, "version", version)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError(
            f"ProxyPolicy is immutable; publish a new version via the "
            f"registry instead of setting {name!r}"
        )

    def replace(self, **changes: Any) -> "ProxyPolicy":
        """基于当前版本派生新策略（由注册中心在发布时使用）。"""
        return ProxyPolicy(
            hops=changes.get("hops", self.hops),
            families=changes.get("families", self.families),
            real_ip_header=changes.get("real_ip_header", self.real_ip_header),
            migration=changes.get("migration", self.migration),
            log_full_chain=changes.get("log_full_chain", self.log_full_chain),
            version=changes.get("version", self.version),
        )

    @property
    def hops(self) -> list[TrustedHop]:
        """应用近端 -> 边缘远端方向的可信跳点。"""
        return [self.hops_by_depth[d] for d in sorted(self.hops_by_depth)]

    def hop_at(self, depth: int) -> TrustedHop | None:
        return self.hops_by_depth.get(depth)

    def __repr__(self) -> str:
        return (
            f"<ProxyPolicy v{self.version} hops={len(self.hops_by_depth)} "
            f"families={{{', '.join(f.value for f in self.families)}}}>"
        )


def policy_from_mapping(
    data: Mapping[str, Any],
) -> tuple[
    list[TrustedHop],
    frozenset[HeaderFamily] | None,
    str | None,
    MigrationWindow | None,
    bool,
]:
    """从普通映射构造策略参数。

    映射结构::

        {
          "hops": [
            {"cidr": "10.0.0.0/8",
             "families": ["forwarded", "x-forwarded"],
             "secret": "..."},
            ...  # 数组顺序即 depth：0=应用近端
          ],
          "families": ["forwarded"],          # 全局授权族（可选）
          "real_ip_header": "X-Real-IP",       # 可选
          "migration": {                       # 可选
            "active_from": "2026-10-01T00:00:00Z",
            "grace_until": "2026-11-01T00:00:00Z"
          },
          "log_full_chain": false
        }
    """
    raw_hops = data.get("hops") or []
    hops: list[TrustedHop] = []
    for depth, item in enumerate(raw_hops):
        fam = _parse_families(item.get("families"))
        hops.append(
            TrustedHop(
                cidr=str(item["cidr"]),
                families=fam,
                secret=item.get("secret"),
                depth=int(item.get("depth", depth)),
            )
        )
    families = _parse_families(data.get("families"))
    migration = None
    raw_migration = data.get("migration")
    if raw_migration:
        migration = MigrationWindow(
            active_from=_parse_dt(raw_migration["active_from"]),
            grace_until=_parse_dt(raw_migration["grace_until"]),
        )
    real_ip_header = (
        str(data["real_ip_header"]) if data.get("real_ip_header") else None
    )
    return (
        hops,
        families if families else None,
        real_ip_header,
        migration,
        bool(data.get("log_full_chain", False)),
    )


def _parse_families(values: Any) -> frozenset[HeaderFamily]:
    if values is None:
        return frozenset()
    if isinstance(values, str):
        values = [values]
    return frozenset(HeaderFamily(str(v).lower()) for v in values)


def _parse_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class ProxyPolicyRegistry:
    """代理链策略注册中心。

    每次发布生成一个新的不可变 :class:`ProxyPolicy` 版本；
    ``snapshot()`` 返回请求受理时刻的版本，处理期间不受热更新影响。
    """

    def __init__(
        self,
        policy: ProxyPolicy | None = None,
        *,
        on_reload: Callable[[ProxyPolicy], Any] | None = None,
    ):
        self._lock = Lock()
        self._version_seq = 0
        self._latest: ProxyPolicy | None = None
        self.on_reload = on_reload
        if policy is not None:
            self.publish(policy)

    def snapshot(self) -> ProxyPolicy | None:
        """受理时调用：获取当前生效的策略版本。"""
        with self._lock:
            return self._latest

    def __getstate__(self) -> dict[str, Any]:
        # Lock 与回调不可随进程 pickle；工作进程在反序列化后重建
        return {
            "version_seq": self._version_seq,
            "latest": self._latest,
        }

    def __setstate__(self, state: dict[str, Any]) -> None:
        self._lock = Lock()
        self._version_seq = state["version_seq"]
        self._latest = state["latest"]
        self.on_reload = None

    @property
    def latest(self) -> ProxyPolicy | None:
        return self.snapshot()

    def publish(self, policy: ProxyPolicy) -> ProxyPolicy:
        """发布新版本策略（不可变对象，原子切换）。

        传入对象会以当前版本序列派生一份只读副本，调用方持有的原
        对象不受版本号影响。
        """
        with self._lock:
            self._version_seq += 1
            published = policy.replace(version=self._version_seq)
            self._latest = published
            logger.debug("Proxy policy published: %r", published)
        if self.on_reload:
            self.on_reload(published)
        return published

    def load_dict(self, data: Mapping[str, Any]) -> ProxyPolicy:
        """从映射全量构造并发布新版本。"""
        hops, families, real_ip_header, migration, log_full_chain = (
            policy_from_mapping(data)
        )
        policy = ProxyPolicy(
            hops,
            families=families,
            real_ip_header=real_ip_header,
            migration=migration,
            log_full_chain=log_full_chain,
        )
        return self.publish(policy)

    def reload(
        self,
        source: Callable[[], Mapping[str, Any]] | Mapping[str, Any],
    ) -> ProxyPolicy:
        """从可调用外部源或映射热更新。

        源抛出异常或内容非法时保留旧版本，不影响正在或之后受理的请求；
        尚无任何已发布版本时异常向上传播。
        """
        try:
            data = source() if callable(source) else source
            return self.load_dict(data)
        except Exception as exc:  # noqa: BLE001 - 热更新失败保留旧版本
            current = self._latest
            logger.error(
                "Proxy policy reload failed; keeping v%s: %s",
                current.version if current else 0,
                exc,
            )
            if current is None:
                raise
            return current
