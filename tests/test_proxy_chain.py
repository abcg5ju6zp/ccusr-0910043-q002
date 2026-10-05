"""代理链裁决能力的回归测试。"""

from __future__ import annotations

import asyncio
import logging

from datetime import datetime, timezone

import pytest

from multidict import CIMultiDict

from sanic import Sanic
from sanic.proxy.judge import ProxyJudge
from sanic.proxy.policy import ProxyPolicy, ProxyPolicyRegistry
from sanic.proxy.types import (
    HeaderFamily,
    MigrationWindow,
    ProxyDecisionAction,
    ProxyVerdict,
    TrustedHop,
)
from sanic.response import json as json_response


F = HeaderFamily.FORWARDED
X = HeaderFamily.XFORWARDED


# --------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------- #


def make_headers(**values) -> CIMultiDict:
    headers = CIMultiDict()
    for key, value in values.items():
        headers.add(key, value)
    return headers


def make_policy(
    *,
    hops=None,
    families=None,
    secret=None,
    migration=None,
    real_ip_header=None,
    log_full_chain=False,
):
    hops = hops or [
        TrustedHop("127.0.0.0/8", frozenset({F, X}), depth=0),
        TrustedHop("10.1.0.0/16", frozenset({F, X}), depth=1),
    ]
    return ProxyPolicy(
        hops,
        families=families if families is not None else frozenset({F, X}),
        migration=migration,
        real_ip_header=real_ip_header,
        log_full_chain=log_full_chain,
    )


# --------------------------------------------------------------------- #
# 裁决器：正常链
# --------------------------------------------------------------------- #


def test_xforwarded_full_chain_trusted():
    judge = ProxyJudge(make_policy())
    decision = judge.adjudicate(
        make_headers(**{"X-Forwarded-For": "1.2.3.4, 10.1.0.5"}),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.TRUSTED
    assert decision.action is ProxyDecisionAction.ACCEPT
    assert decision.effective_client == "1.2.3.4"
    assert decision.validated_hops == 2
    assert [h.forwarded_for for h in decision.original_chain] == [
        "1.2.3.4",
        "10.1.0.5",
    ]


def test_forwarded_full_chain_with_metadata():
    judge = ProxyJudge(make_policy())
    decision = judge.adjudicate(
        make_headers(
            **{
                "Forwarded": (
                    "for=1.2.3.4;proto=https;host=site.example, "
                    "for=10.1.0.5;host=edge.local;port=8443"
                )
            }
        ),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.TRUSTED
    assert decision.effective_client == "1.2.3.4"
    assert decision.proto == "https"
    assert decision.host == "site.example"
    assert decision.port == 8443


def test_direct_request_without_forwarding_headers():
    judge = ProxyJudge(make_policy())
    decision = judge.adjudicate(make_headers(), peer="127.0.0.1")
    assert decision.verdict is ProxyVerdict.DIRECT
    assert decision.effective_client == "127.0.0.1"


# --------------------------------------------------------------------- #
# 伪造前缀、截断、未知跳
# --------------------------------------------------------------------- #


def test_spoofed_prefix_beyond_trusted_chain_is_truncated():
    judge = ProxyJudge(make_policy())
    # 登记链只有两层（应用 + 一个可信上游），头部却多出左侧两段
    decision = judge.adjudicate(
        make_headers(**{"X-Forwarded-For": "8.8.8.8, 1.2.3.4, 10.1.0.5"}),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.CHAIN_TRUNCATED
    assert decision.action is ProxyDecisionAction.FALLBACK
    # 有效来源停在截断边界，8.8.8.8 不被采信
    assert decision.effective_client == "1.2.3.4"
    assert decision.validated_hops == 2
    # 原始链仍然完整保留以供审计
    assert [h.forwarded_for for h in decision.original_chain] == [
        "8.8.8.8",
        "1.2.3.4",
        "10.1.0.5",
    ]
    assert any("depth" in r for r in decision.reasons)


def test_unknown_intermediate_hop_stops_chain():
    judge = ProxyJudge(make_policy())
    decision = judge.adjudicate(
        make_headers(**{"Forwarded": "for=1.2.3.4, for=9.9.9.9"}),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.UNKNOWN_HOP
    assert decision.effective_client == "9.9.9.9"
    # 左侧 1.2.3.4 未通过担保
    assert len(decision.validated_chain) == 1


def test_untrusted_direct_peer_falls_back_to_socket_address():
    judge = ProxyJudge(make_policy())
    decision = judge.adjudicate(
        make_headers(**{"X-Forwarded-For": "1.2.3.4"}),
        peer="203.0.113.7",
    )
    assert decision.verdict is ProxyVerdict.UNKNOWN_HOP
    assert decision.action is ProxyDecisionAction.FALLBACK
    assert decision.effective_client == "203.0.113.7"
    assert decision.validated_hops == 0


def test_client_cannot_inject_address_via_header():
    judge = ProxyJudge(make_policy())
    decision = judge.adjudicate(
        make_headers(**{"X-Forwarded-For": "1.2.3.4"}),
        peer="203.0.113.7",
    )
    assert decision.effective_client != "1.2.3.4"


# --------------------------------------------------------------------- #
# 两族并存
# --------------------------------------------------------------------- #


def test_both_families_consistent_prefer_forwarded():
    judge = ProxyJudge(make_policy())
    decision = judge.adjudicate(
        make_headers(
            **{
                "Forwarded": "for=1.2.3.4, for=10.1.0.5",
                "X-Forwarded-For": "1.2.3.4, 10.1.0.5",
            }
        ),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.TRUSTED
    assert decision.family is F
    assert decision.effective_client == "1.2.3.4"


def test_both_families_conflicting_rejects_all_claims():
    judge = ProxyJudge(make_policy())
    decision = judge.adjudicate(
        make_headers(
            **{
                "Forwarded": "for=1.2.3.4, for=10.1.0.5",
                "X-Forwarded-For": "6.6.6.6, 10.1.0.5",
            }
        ),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.CONFLICT
    assert decision.action is ProxyDecisionAction.REJECT
    assert decision.effective_client == "127.0.0.1"
    assert decision.validated_hops == 0
    assert any("disagree" in r for r in decision.reasons)


def test_unauthorized_header_family_rejected():
    policy = make_policy(families=frozenset({F}))
    judge = ProxyJudge(policy)
    decision = judge.adjudicate(
        make_headers(**{"X-Forwarded-For": "1.2.3.4, 10.1.0.5"}),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.CONFLICT
    assert decision.action is ProxyDecisionAction.REJECT


def test_forwarded_unauthorized_when_only_x_family_allowed():
    policy = make_policy(families=frozenset({X}))
    judge = ProxyJudge(policy)
    decision = judge.adjudicate(
        make_headers(**{"Forwarded": "for=1.2.3.4, for=10.1.0.5"}),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.CONFLICT
    assert decision.action is ProxyDecisionAction.REJECT


# --------------------------------------------------------------------- #
# X-Real-IP（作为已登记的边缘观察头）
# --------------------------------------------------------------------- #


def test_real_ip_alone_is_trusted_when_registered():
    policy = make_policy(real_ip_header="x-real-ip")
    judge = ProxyJudge(policy)
    decision = judge.adjudicate(
        make_headers(**{"X-Real-IP": "1.2.3.4"}), peer="127.0.0.1"
    )
    assert decision.verdict is ProxyVerdict.TRUSTED
    assert decision.effective_client == "1.2.3.4"


def test_unregistered_real_ip_header_is_ignored():
    judge = ProxyJudge(make_policy())
    decision = judge.adjudicate(
        make_headers(**{"X-Real-IP": "1.2.3.4"}), peer="203.0.113.7"
    )
    assert decision.verdict is ProxyVerdict.DIRECT
    assert decision.effective_client == "203.0.113.7"


def test_real_ip_must_match_leftmost_xff_entry():
    policy = make_policy(real_ip_header="x-real-ip")
    judge = ProxyJudge(policy)
    decision = judge.adjudicate(
        make_headers(
            **{
                "X-Forwarded-For": "1.2.3.4, 10.1.0.5",
                "X-Real-IP": "6.6.6.6",
            }
        ),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.CONFLICT
    assert decision.action is ProxyDecisionAction.REJECT
    assert decision.effective_client == "127.0.0.1"


def test_real_ip_must_match_leftmost_forwarded_entry():
    policy = make_policy(real_ip_header="x-real-ip")
    judge = ProxyJudge(policy)
    decision = judge.adjudicate(
        make_headers(
            **{
                "Forwarded": "for=1.2.3.4, for=10.1.0.5",
                "X-Real-IP": "1.2.3.4",
            }
        ),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.TRUSTED
    assert decision.effective_client == "1.2.3.4"

    decision = judge.adjudicate(
        make_headers(
            **{
                "Forwarded": "for=1.2.3.4, for=10.1.0.5",
                "X-Real-IP": "10.1.0.5",
            }
        ),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.CONFLICT


# --------------------------------------------------------------------- #
# 格式错误
# --------------------------------------------------------------------- #


def test_malformed_xforwarded_for():
    judge = ProxyJudge(make_policy())
    decision = judge.adjudicate(
        make_headers(**{"X-Forwarded-For": "1.2.3.4, not-an-address"}),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.MALFORMED
    assert decision.action is ProxyDecisionAction.REJECT
    assert decision.effective_client == "127.0.0.1"


def test_malformed_forwarded_element():
    judge = ProxyJudge(make_policy())
    decision = judge.adjudicate(
        make_headers(**{"Forwarded": "for=1.2.3.4, for=@@@"}),
        peer="127.0.0.1",
    )
    # 整个元素无法解析
    assert decision.verdict is ProxyVerdict.MALFORMED


def test_ipv6_and_quoted_values_supported():
    judge = ProxyJudge(
        make_policy(
            hops=[
                TrustedHop("127.0.0.0/8", frozenset({F}), depth=0),
                TrustedHop("2001:db8::/32", frozenset({F}), depth=1),
            ],
            families=frozenset({F}),
        )
    )
    decision = judge.adjudicate(
        make_headers(
            **{
                "Forwarded": 'for="2001:db8::2";proto=https, '
                'for="[2001:db8::1]"'
            }
        ),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.TRUSTED
    assert decision.effective_client == "2001:db8::2"


# --------------------------------------------------------------------- #
# 秘密标记
# --------------------------------------------------------------------- #


def test_forwarded_secret_required_and_validated():
    policy = make_policy(
        hops=[
            TrustedHop("127.0.0.0/8", frozenset({F}), secret="inner", depth=0),
            TrustedHop("10.1.0.0/16", frozenset({F}), secret="edge", depth=1),
        ],
        families=frozenset({F}),
    )
    judge = ProxyJudge(policy)
    decision = judge.adjudicate(
        make_headers(
            **{
                "Forwarded": (
                    "for=1.2.3.4;secret=edge, for=10.1.0.5;secret=inner"
                )
            }
        ),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.TRUSTED
    assert decision.effective_client == "1.2.3.4"

    decision = judge.adjudicate(
        make_headers(
            **{
                "Forwarded": (
                    "for=1.2.3.4;secret=forged, for=10.1.0.5;secret=inner"
                )
            }
        ),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.UNKNOWN_HOP
    assert decision.effective_client == "10.1.0.5"


def test_forwarded_by_field_satisfies_secret():
    policy = make_policy(
        hops=[
            TrustedHop("127.0.0.0/8", frozenset({F}), secret="_gw", depth=0),
            TrustedHop("10.1.0.0/16", frozenset({F}), secret="_edge", depth=1),
        ],
        families=frozenset({F}),
    )
    judge = ProxyJudge(policy)
    decision = judge.adjudicate(
        make_headers(
            **{"Forwarded": "for=1.2.3.4;by=_edge, for=10.1.0.5;by=_gw"}
        ),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.TRUSTED


# --------------------------------------------------------------------- #
# 迁移期限
# --------------------------------------------------------------------- #


@pytest.fixture
def migration():
    return MigrationWindow(
        active_from=datetime(2026, 9, 1, tzinfo=timezone.utc),
        grace_until=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )


def test_xforwarded_during_grace_marked_but_accepted(migration):
    policy = make_policy(families=frozenset({F}), migration=migration)
    judge = ProxyJudge(
        policy, clock=lambda: datetime(2026, 10, 5, tzinfo=timezone.utc)
    )
    decision = judge.adjudicate(
        make_headers(**{"X-Forwarded-For": "1.2.3.4, 10.1.0.5"}),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.MIGRATION_GRACE
    assert decision.action is ProxyDecisionAction.ACCEPT
    assert decision.effective_client == "1.2.3.4"


def test_xforwarded_rejected_after_grace(migration):
    policy = make_policy(families=frozenset({F}), migration=migration)
    judge = ProxyJudge(
        policy, clock=lambda: datetime(2026, 12, 1, tzinfo=timezone.utc)
    )
    decision = judge.adjudicate(
        make_headers(**{"X-Forwarded-For": "1.2.3.4, 10.1.0.5"}),
        peer="127.0.0.1",
    )
    assert decision.verdict is ProxyVerdict.CONFLICT
    assert decision.action is ProxyDecisionAction.REJECT


def test_xforwarded_accepted_before_migration_start(migration):
    policy = make_policy(families=frozenset({F}), migration=migration)
    judge = ProxyJudge(
        policy, clock=lambda: datetime(2026, 8, 1, tzinfo=timezone.utc)
    )
    decision = judge.adjudicate(
        make_headers(**{"X-Forwarded-For": "1.2.3.4, 10.1.0.5"}),
        peer="127.0.0.1",
    )
    assert decision.action is ProxyDecisionAction.ACCEPT


def test_invalid_migration_window_rejected():
    with pytest.raises(ValueError):
        MigrationWindow(
            active_from=datetime(2026, 11, 1, tzinfo=timezone.utc),
            grace_until=datetime(2026, 9, 1, tzinfo=timezone.utc),
        )


# --------------------------------------------------------------------- #
# 可解释结论
# --------------------------------------------------------------------- #


def test_explain_contains_verdict_chain_and_policy_version():
    judge = ProxyJudge(make_policy())
    decision = judge.adjudicate(
        make_headers(**{"X-Forwarded-For": "8.8.8.8, 1.2.3.4, 10.1.0.5"}),
        peer="127.0.0.1",
    )
    text = decision.explain()
    assert "verdict=chain_truncated" in text
    assert "policy=v" in text
    assert "8.8.8.8" in text
    assert "10.1.0.5" in text


# --------------------------------------------------------------------- #
# 注册中心：版本与热更新
# --------------------------------------------------------------------- #


def test_registry_versions_and_snapshot_stability():
    registry = ProxyPolicyRegistry()
    v1 = registry.load_dict(
        {"hops": [{"cidr": "127.0.0.0/8", "families": ["x-forwarded"]}]}
    )
    assert v1.version == 1
    snapshot = registry.snapshot()
    v2 = registry.load_dict(
        {
            "hops": [
                {"cidr": "127.0.0.0/8", "families": ["x-forwarded"]},
                {"cidr": "10.1.0.0/16", "families": ["x-forwarded"]},
            ]
        }
    )
    assert v2.version == 2
    # 已受理请求持有的快照不受热更新影响
    assert snapshot.version == 1
    assert registry.snapshot().version == 2


def test_reload_failure_keeps_previous_version():
    registry = ProxyPolicyRegistry()
    registry.load_dict(
        {"hops": [{"cidr": "127.0.0.0/8", "families": ["x-forwarded"]}]}
    )

    def broken_source():
        raise RuntimeError("config source unavailable")

    kept = registry.reload(broken_source)
    assert kept.version == 1
    assert registry.snapshot().version == 1


def test_reload_failure_without_baseline_raises():
    registry = ProxyPolicyRegistry()
    with pytest.raises(RuntimeError):
        registry.reload(lambda: (_ for _ in ()).throw(RuntimeError("boom")))


def test_policy_is_immutable_after_publication():
    registry = ProxyPolicyRegistry()
    policy = registry.load_dict(
        {"hops": [{"cidr": "127.0.0.0/8", "families": ["x-forwarded"]}]}
    )
    with pytest.raises(AttributeError):
        policy.version = 99  # type: ignore[misc]


# --------------------------------------------------------------------- #
# 框架集成
# --------------------------------------------------------------------- #


PROXY_CHAIN_CONFIG = {
    "hops": [
        {"cidr": "127.0.0.0/8", "families": ["forwarded", "x-forwarded"]},
        {"cidr": "10.1.0.0/16", "families": ["forwarded", "x-forwarded"]},
    ],
    "families": ["forwarded", "x-forwarded"],
}


def _register_verdict_route(app: Sanic):
    @app.route("/")
    async def handler(request):
        verdict = request.proxy_verdict
        return json_response(
            {
                "remote": request.remote_addr,
                "client_ip": request.client_ip,
                "verdict": verdict.verdict.value,
                "action": verdict.action.value,
                "policy": verdict.policy_version,
                "scheme": request.scheme,
                "host": request.host,
            }
        )

    @app.route("/label")
    async def label(request):
        labeled = request.proxy_log_label
        return json_response(
            {
                "host": labeled[0],
                **labeled[1],
            }
        )


def test_app_trusted_chain(app):
    app.config.PROXY_CHAIN = PROXY_CHAIN_CONFIG
    _register_verdict_route(app)
    _, response = app.test_client.get(
        "/",
        headers={"X-Forwarded-For": "1.2.3.4, 10.1.0.5"},
    )
    assert response.json["remote"] == "1.2.3.4"
    assert response.json["verdict"] == "trusted"


def test_app_conflicting_families_do_not_leak(app):
    app.config.PROXY_CHAIN = PROXY_CHAIN_CONFIG
    _register_verdict_route(app)
    _, response = app.test_client.get(
        "/",
        headers={
            "Forwarded": "for=1.2.3.4, for=10.1.0.5",
            "X-Forwarded-For": "6.6.6.6, 10.1.0.5",
        },
    )
    body = response.json
    assert body["verdict"] == "conflict"
    # 被拒声明不得成为审计/限流对象
    assert body["remote"] == ""
    assert body["client_ip"] == "127.0.0.1"


def test_app_truncated_chain(app):
    app.config.PROXY_CHAIN = PROXY_CHAIN_CONFIG
    _register_verdict_route(app)
    _, response = app.test_client.get(
        "/",
        headers={"X-Forwarded-For": "8.8.8.8, 1.2.3.4, 10.1.0.5"},
    )
    body = response.json
    assert body["verdict"] == "chain_truncated"
    assert body["remote"] == "1.2.3.4"


def test_app_in_flight_request_keeps_accepted_policy_version(app):
    app.config.PROXY_CHAIN = PROXY_CHAIN_CONFIG
    captured = {}

    @app.route("/")
    async def handler(request):
        # 受理时裁决并绑定版本
        decision = request.proxy_verdict
        captured["version"] = decision.policy_version
        # 处理期间策略热更新
        app.reload_proxy_policy(
            {
                "hops": [
                    {
                        "cidr": "127.0.0.0/8",
                        "families": ["forwarded", "x-forwarded"],
                    }
                ],
                "families": ["forwarded"],
            }
        )
        # 正在处理的请求继续使用受理时版本
        assert request.proxy_verdict.policy_version == captured["version"]
        return json_response(
            {
                "version": request.proxy_verdict.policy_version,
                "latest": app.proxy_policies.snapshot().version,
            }
        )

    _, response = app.test_client.get(
        "/", headers={"X-Forwarded-For": "1.2.3.4, 10.1.0.5"}
    )
    assert response.json["version"] == 1
    assert response.json["latest"] == 2


def test_configure_proxy_chain_api(app):
    policy = app.configure_proxy_chain(PROXY_CHAIN_CONFIG)
    assert policy.version == 1
    assert app.proxy_policies.snapshot() is policy


def test_reload_invokes_registry_callback(app):
    app.configure_proxy_chain(PROXY_CHAIN_CONFIG)
    seen = []
    app.proxy_policies.on_reload = lambda policy: seen.append(
        policy.version
    )
    app.reload_proxy_policy(
        {
            "hops": [
                {
                    "cidr": "127.0.0.0/8",
                    "families": ["forwarded", "x-forwarded"],
                }
            ]
        }
    )
    assert seen == [2]


@pytest.mark.asyncio
async def test_reload_dispatch_without_registered_listener_is_safe(app):
    # 未注册监听者时发布也不应失败（fail_not_found=False）
    app.configure_proxy_chain(PROXY_CHAIN_CONFIG)
    app._proxy_policy_reloaded(app.proxy_policies.snapshot())
    await asyncio.sleep(0)


def test_log_label_redacted_when_addresses_disallowed(app):
    app.config.PROXY_CHAIN = PROXY_CHAIN_CONFIG
    app.config.PROXY_LOG_ADDRESSES = False
    _register_verdict_route(app)
    _, response = app.test_client.get(
        "/label",
        headers={"X-Forwarded-For": "1.2.3.4, 10.1.0.5"},
    )
    assert response.json["host"] == "redacted"
    assert response.json["proxy_verdict"] == "trusted"
    assert "1.2.3.4" not in str(response.json)


def test_log_label_hides_unvalidated_prefix_by_default(app):
    app.config.PROXY_CHAIN = PROXY_CHAIN_CONFIG
    _register_verdict_route(app)
    _, response = app.test_client.get(
        "/label",
        headers={"X-Forwarded-For": "8.8.8.8, 1.2.3.4, 10.1.0.5"},
    )
    body = response.json
    # 有效来源（截断边界）可见
    assert body["host"] == "1.2.3.4"
    # 未经担保的左侧地址不进日志
    assert "8.8.8.8" not in str(body)
    assert "proxy_hops" in body


def test_log_label_full_chain_requires_both_flags(app):
    app.configure_proxy_chain({**PROXY_CHAIN_CONFIG, "log_full_chain": True})
    # 仅策略授权，全局开关默认关闭：仍不暴露完整链
    _register_verdict_route(app)
    _, response = app.test_client.get(
        "/label",
        headers={"X-Forwarded-For": "8.8.8.8, 1.2.3.4, 10.1.0.5"},
    )
    assert "proxy_chain" not in response.json

    app.config.PROXY_LOG_FULL_CHAIN = True
    _, response = app.test_client.get(
        "/label",
        headers={"X-Forwarded-For": "8.8.8.8, 1.2.3.4, 10.1.0.5"},
    )
    assert response.json["proxy_chain"] == ("8.8.8.8 -> 1.2.3.4 -> 10.1.0.5")


def test_access_log_carries_verdict(app, caplog):
    app.config.ACCESS_LOG = True
    app.config.PROXY_CHAIN = PROXY_CHAIN_CONFIG

    @app.route("/")
    async def handler(request):
        return json_response({"ok": True})

    with caplog.at_level(logging.INFO, logger="sanic.access"):
        app.test_client.get(
            "/",
            headers={"X-Forwarded-For": "1.2.3.4, 10.1.0.5"},
        )
    records = [
        record for record in caplog.records if hasattr(record, "proxy_verdict")
    ]
    assert records
    assert records[0].proxy_verdict == "trusted"
    assert records[0].host == "1.2.3.4"


def test_legacy_forwarded_handling_without_policy(app):
    app.config.PROXIES_COUNT = 1

    @app.route("/")
    async def handler(request):
        return json_response(
            {"remote": request.remote_addr, "verdict": request.proxy_verdict}
        )

    _, response = app.test_client.get(
        "/", headers={"X-Forwarded-For": "5.5.5.5"}
    )
    assert response.json == {"remote": "5.5.5.5", "verdict": None}


def test_adjudication_failure_fails_closed(app, monkeypatch):
    app.config.PROXY_CHAIN = PROXY_CHAIN_CONFIG

    def boom(*args, **kwargs):
        raise RuntimeError("judge exploded")

    monkeypatch.setattr(ProxyJudge, "adjudicate", boom)

    @app.route("/")
    async def handler(request):
        return json_response(
            {
                "verdict": request.proxy_verdict.verdict.value,
                "remote": request.remote_addr,
                "client_ip": request.client_ip,
            }
        )

    _, response = app.test_client.get(
        "/", headers={"X-Forwarded-For": "5.5.5.5"}
    )
    # 策略已启用但裁决失败：声明一律不采信，回退到直连对端
    assert response.json["verdict"] == "unresolved"
    assert response.json["remote"] == ""
    assert response.json["client_ip"] == "127.0.0.1"
