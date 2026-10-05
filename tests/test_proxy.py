import logging

from datetime import datetime, timedelta, timezone

import pytest

from sanic import Sanic
from sanic.compat import Header
from sanic.proxy import (
    ChainVerdict,
    FamilyVerdict,
    HeaderFamily,
    ProxyLogFilter,
    ProxyTrustPolicy,
    ProxyTrustRegistry,
    adjudicate,
    parse_forwarded_chain,
    parse_xforwarded_chain,
)
from sanic.response import json


TRUSTED = ("10.0.0.0/8", "192.168.0.0/16")
PEER = "10.0.0.2"


def make_policy(**overrides) -> ProxyTrustPolicy:
    params = {"trusted_hops": TRUSTED, "version": 1}
    params.update(overrides)
    return ProxyTrustPolicy(**params)


def adjudicate_with(headers, policy=None, peer=PEER, **kwargs):
    return adjudicate(headers, peer, policy or make_policy(), **kwargs)


@pytest.fixture
def proxy_app(app):
    app.proxy_registry.update(trusted_hops=TRUSTED + ("127.0.0.1",))

    @app.get("/whoami")
    async def whoami(request):
        decision = request.proxy_decision
        return json(
            {
                "effective_source": decision.effective_source,
                "family_verdict": decision.family_verdict.value,
                "chain_verdict": decision.chain_verdict.value,
                "policy_version": decision.policy_version,
            }
        )

    return app


class TestChainParsing:
    def test_parse_forwarded_chain(self):
        headers = Header(
            {
                "Forwarded": (
                    "for=203.0.113.1;proto=https, "
                    'for="[2001:db8::1]:8443";proto=https'
                ),
            }
        )
        assert parse_forwarded_chain(headers) == (
            "203.0.113.1",
            "2001:db8::1",
        )

    def test_parse_forwarded_chain_multiple_header_lines(self):
        headers = Header()
        headers.add("Forwarded", "for=203.0.113.1")
        headers.add("Forwarded", "for=10.0.0.1")
        assert parse_forwarded_chain(headers) == ("203.0.113.1", "10.0.0.1")

    def test_parse_forwarded_chain_quoted_comma(self):
        headers = Header(
            {"Forwarded": 'for="[2001:db8:1:2]:1234";by="[2001:db8::,]"'}
        )
        assert parse_forwarded_chain(headers) == ("2001:db8:1:2",)

    def test_parse_forwarded_chain_skips_unknown(self):
        headers = Header({"Forwarded": "for=unknown, for=203.0.113.1"})
        assert parse_forwarded_chain(headers) == ("203.0.113.1",)

    def test_parse_xforwarded_chain(self):
        headers = Header(
            {"X-Forwarded-For": "203.0.113.1, 10.0.0.1, 192.168.1.1"}
        )
        assert parse_xforwarded_chain(headers, "x-forwarded-for") == (
            "203.0.113.1",
            "10.0.0.1",
            "192.168.1.1",
        )

    def test_parse_xforwarded_chain_strips_port(self):
        headers = Header({"X-Forwarded-For": "203.0.113.1:5678, 10.0.0.1"})
        assert parse_xforwarded_chain(headers, "x-forwarded-for") == (
            "203.0.113.1",
            "10.0.0.1",
        )


class TestFamilySelection:
    def test_forwarded_only(self):
        headers = Header({"Forwarded": "for=203.0.113.1"})
        decision = adjudicate_with(headers)
        assert decision.family is HeaderFamily.FORWARDED
        assert decision.family_verdict is FamilyVerdict.FORWARDED_USED

    def test_xforwarded_only(self):
        headers = Header({"X-Forwarded-For": "203.0.113.1"})
        decision = adjudicate_with(headers)
        assert decision.family is HeaderFamily.X_FORWARDED
        assert decision.family_verdict is FamilyVerdict.X_FORWARDED_USED

    def test_conflict_forwarded_wins_by_default(self):
        headers = Header(
            {
                "Forwarded": "for=203.0.113.1",
                "X-Forwarded-For": "198.51.100.9",
            }
        )
        decision = adjudicate_with(headers)
        assert decision.family_verdict is FamilyVerdict.CONFLICT_FORWARDED_WINS
        assert decision.effective_source == "203.0.113.1"
        assert any("同时存在" in e for e in decision.explanations)

    def test_conflict_xforwarded_wins_when_preferred(self):
        headers = Header(
            {
                "Forwarded": "for=203.0.113.1",
                "X-Forwarded-For": "198.51.100.9",
            }
        )
        policy = make_policy(prefer="x-forwarded")
        decision = adjudicate_with(headers, policy)
        assert (
            decision.family_verdict is FamilyVerdict.CONFLICT_X_FORWARDED_WINS
        )
        assert decision.effective_source == "198.51.100.9"

    def test_conflict_falls_back_when_preferred_family_disallowed(self):
        headers = Header(
            {
                "Forwarded": "for=203.0.113.1",
                "X-Forwarded-For": "198.51.100.9",
            }
        )
        policy = make_policy(allowed_families={"x-forwarded"})
        decision = adjudicate_with(headers, policy)
        assert (
            decision.family_verdict is FamilyVerdict.CONFLICT_X_FORWARDED_WINS
        )
        assert decision.effective_source == "198.51.100.9"

    def test_family_not_allowed(self):
        headers = Header({"X-Forwarded-For": "203.0.113.1"})
        policy = make_policy(allowed_families={"forwarded"})
        decision = adjudicate_with(headers, policy)
        assert decision.family_verdict is FamilyVerdict.FAMILY_NOT_ALLOWED
        assert decision.chain_verdict is ChainVerdict.NO_CHAIN_ENTRIES
        assert decision.effective_source == PEER

    def test_no_forwarded_headers(self):
        decision = adjudicate_with(Header())
        assert decision.family_verdict is FamilyVerdict.NO_FORWARDED_HEADERS
        assert decision.chain_verdict is ChainVerdict.NO_CHAIN_ENTRIES
        assert decision.effective_source == PEER


class TestMigrationDeadline:
    def test_within_migration_window(self):
        deadline = datetime.now(timezone.utc) + timedelta(days=7)
        policy = make_policy(migration_deadline=deadline)
        headers = Header({"X-Forwarded-For": "203.0.113.1"})
        decision = adjudicate_with(headers, policy)
        assert (
            decision.family_verdict
            is FamilyVerdict.X_FORWARDED_MIGRATION_WINDOW
        )
        assert decision.effective_source == "203.0.113.1"
        assert any("迁移期限" in e for e in decision.explanations)

    def test_after_migration_deadline(self):
        deadline = datetime.now(timezone.utc) - timedelta(days=1)
        policy = make_policy(migration_deadline=deadline)
        headers = Header({"X-Forwarded-For": "203.0.113.1"})
        decision = adjudicate_with(headers, policy)
        assert decision.family_verdict is FamilyVerdict.MIGRATION_EXPIRED
        assert decision.effective_source == PEER

    def test_deadline_uses_injected_now(self):
        deadline = datetime(2026, 1, 1, tzinfo=timezone.utc)
        policy = make_policy(migration_deadline=deadline)
        headers = Header({"X-Forwarded-For": "203.0.113.1"})
        before = datetime(2025, 12, 31, tzinfo=timezone.utc)
        after = datetime(2026, 1, 2, tzinfo=timezone.utc)
        assert (
            adjudicate_with(headers, policy, now=before).family_verdict
            is FamilyVerdict.X_FORWARDED_MIGRATION_WINDOW
        )
        assert (
            adjudicate_with(headers, policy, now=after).family_verdict
            is FamilyVerdict.MIGRATION_EXPIRED
        )

    def test_naive_deadline_treated_as_utc(self):
        policy = make_policy(migration_deadline="2026-01-01T00:00:00")
        headers = Header({"X-Forwarded-For": "203.0.113.1"})
        now = datetime(2025, 6, 1, tzinfo=timezone.utc)
        decision = adjudicate_with(headers, policy, now=now)
        assert (
            decision.family_verdict
            is FamilyVerdict.X_FORWARDED_MIGRATION_WINDOW
        )


class TestChainWalk:
    def test_first_untrusted_hop_is_effective(self):
        headers = Header(
            {"Forwarded": "for=203.0.113.1, for=10.0.0.1, for=192.168.1.1"}
        )
        decision = adjudicate_with(headers)
        assert decision.chain_verdict is ChainVerdict.EFFECTIVE_FROM_CHAIN
        assert decision.effective_source == "203.0.113.1"

    def test_unknown_intermediate_hop(self):
        # 中间跳点 172.16.0.9 未登记：它成为有效来源，
        # 其左侧的 203.0.113.1 可能是伪造的，不予采信
        headers = Header(
            {"Forwarded": "for=203.0.113.1, for=172.16.0.9, for=10.0.0.1"}
        )
        decision = adjudicate_with(headers)
        assert decision.chain_verdict is ChainVerdict.EFFECTIVE_FROM_CHAIN
        assert decision.effective_source == "172.16.0.9"
        assert any("172.16.0.9" in e for e in decision.explanations)

    def test_chain_truncated_when_all_trusted(self):
        headers = Header({"Forwarded": "for=10.0.0.1, for=192.168.1.1"})
        decision = adjudicate_with(headers)
        assert decision.chain_verdict is ChainVerdict.CHAIN_TRUNCATED
        assert decision.effective_source == "10.0.0.1"
        assert any("截断" in e for e in decision.explanations)

    def test_untrusted_peer_ignores_headers(self):
        headers = Header({"Forwarded": "for=203.0.113.1"})
        decision = adjudicate_with(headers, peer="198.51.100.7")
        assert decision.chain_verdict is ChainVerdict.UNTRUSTED_PEER
        assert decision.effective_source == "198.51.100.7"
        assert any("伪造" in e for e in decision.explanations)

    def test_no_trusted_hops_configured(self):
        policy = ProxyTrustPolicy()
        headers = Header({"Forwarded": "for=203.0.113.1"})
        decision = adjudicate_with(headers, policy)
        assert decision.chain_verdict is ChainVerdict.NO_TRUSTED_HOPS
        assert decision.effective_source == PEER

    def test_original_chain_preserved(self):
        headers = Header(
            {
                "Forwarded": "for=203.0.113.1, for=10.0.0.1",
                "X-Forwarded-For": "198.51.100.9",
            }
        )
        decision = adjudicate_with(headers)
        assert decision.chain.peer == PEER
        assert decision.chain.addresses == (
            PEER,
            "203.0.113.1",
            "10.0.0.1",
        )
        assert decision.chain.raw_headers["forwarded"] == (
            "for=203.0.113.1, for=10.0.0.1",
        )
        assert decision.chain.raw_headers["x-forwarded-for"] == (
            "198.51.100.9",
        )
        trust = {h.address: h.trusted for h in decision.chain.hops}
        assert trust == {
            PEER: True,
            "203.0.113.1": False,
            "10.0.0.1": True,
        }

    def test_ipv6_trusted_hop(self):
        policy = make_policy(trusted_hops=("2001:db8::/32",))
        headers = Header({"Forwarded": 'for="[2001:db8::5]";proto=https'})
        decision = adjudicate_with(headers, policy, peer="2001:db8::1")
        assert decision.chain_verdict is ChainVerdict.CHAIN_TRUNCATED
        assert decision.effective_source == "2001:db8::5"

    def test_literal_hostname_trust(self):
        policy = make_policy(trusted_hops=("edge-gateway.internal",))
        headers = Header(
            {"Forwarded": "for=_obfuscated, for=edge-gateway.internal"}
        )
        decision = adjudicate_with(
            headers, policy, peer="edge-gateway.internal"
        )
        assert decision.chain_verdict is ChainVerdict.EFFECTIVE_FROM_CHAIN
        assert decision.effective_source == "_obfuscated"


class TestRegistry:
    def test_update_bumps_version_and_keeps_old_policy(self):
        registry = ProxyTrustRegistry()
        v0 = registry.current
        assert v0.version == 0
        v1 = registry.update(trusted_hops=TRUSTED)
        assert v1.version == 1
        assert registry.current is v1
        # 旧版本策略对象不可变，不受热更新影响
        assert v0.trusted_hops == ()
        assert v0.version == 0
        v2 = registry.update(allowed_families={"forwarded"})
        assert v2.version == 2
        assert v2.trusted_hops == TRUSTED
        assert v1.allowed_families != v2.allowed_families

    def test_from_config(self):
        app = Sanic("proxy_config_seed")
        app.config.PROXY_TRUSTED_HOPS = ("10.0.0.0/8",)
        app.config.PROXY_ALLOWED_FAMILIES = ("forwarded",)
        registry = ProxyTrustRegistry.from_config(app.config)
        policy = registry.current
        assert policy.trusted_hops == ("10.0.0.0/8",)
        assert policy.allowed_families == {HeaderFamily.FORWARDED}

    def test_hot_update_only_affects_new_adjudications(self):
        registry = ProxyTrustRegistry()
        registry.update(trusted_hops=("10.0.0.0/8",))
        inflight_policy = registry.current
        registry.update(trusted_hops=("192.168.0.0/16",))

        headers = Header({"Forwarded": "for=203.0.113.1"})
        inflight = adjudicate(headers, PEER, inflight_policy)
        assert inflight.policy_version == 1
        assert inflight.chain_verdict is ChainVerdict.EFFECTIVE_FROM_CHAIN

        new = adjudicate(headers, PEER, registry.current)
        assert new.policy_version == 2
        # 新策略下对端 10.0.0.2 不再可信
        assert new.chain_verdict is ChainVerdict.UNTRUSTED_PEER


class TestLogExposure:
    def test_unauthorized_context_hides_chain_addresses(self):
        headers = Header({"Forwarded": "for=203.0.113.1, for=10.0.0.1"})
        decision = adjudicate_with(headers)
        context = decision.log_context()
        assert context["proxy_effective_source"] == "203.0.113.1"
        assert context["proxy_chain_length"] == 3
        assert "proxy_chain" not in context
        assert "proxy_peer" not in context
        serialized = str(context)
        assert "10.0.0.1" not in serialized
        assert PEER not in serialized

    def test_authorized_context_exposes_chain(self):
        headers = Header({"Forwarded": "for=203.0.113.1, for=10.0.0.1"})
        decision = adjudicate_with(headers)
        context = decision.log_context(authorized=True)
        assert context["proxy_peer"] == PEER
        assert context["proxy_chain"] == [PEER, "203.0.113.1", "10.0.0.1"]

    def test_log_filter_injects_authorized_fields(self):
        headers = Header({"Forwarded": "for=203.0.113.1"})
        decision = adjudicate_with(headers)
        record = logging.LogRecord(
            "test", logging.INFO, __file__, 1, "msg", (), None
        )
        record.proxy_decision = decision
        record.proxy_chain = ["should", "be", "scrubbed"]

        ProxyLogFilter().filter(record)
        assert record.proxy_effective_source == "203.0.113.1"
        assert record.proxy_chain is None
        assert not hasattr(record, "proxy_peer")

        record2 = logging.LogRecord(
            "test", logging.INFO, __file__, 1, "msg", (), None
        )
        record2.proxy_decision = decision
        ProxyLogFilter(authorized=True).filter(record2)
        assert record2.proxy_chain == [PEER, "203.0.113.1"]
        assert record2.proxy_peer == PEER


class TestRequestIntegration:
    def test_request_proxy_decision(self, proxy_app):
        headers = {"Forwarded": "for=203.0.113.1, for=10.0.0.1"}
        _, response = proxy_app.test_client.get("/whoami", headers=headers)
        assert response.status == 200
        payload = response.json
        assert payload["effective_source"] == "203.0.113.1"
        assert payload["family_verdict"] == "forwarded_used"
        assert payload["chain_verdict"] == "effective_from_chain"

    def test_request_decision_cached_and_version_pinned(self, proxy_app):
        seen = {}

        @proxy_app.get("/pinned")
        async def pinned(request):
            first = request.proxy_decision
            # 模拟处理过程中的配置热更新
            request.app.proxy_registry.update(
                trusted_hops=("203.0.113.0/24", "127.0.0.1")
            )
            second = request.proxy_decision
            seen["first_version"] = first.policy_version
            seen["second_version"] = second.policy_version
            seen["same_object"] = first is second
            seen["registry_version"] = (
                request.app.proxy_registry.current.version
            )
            return json({"ok": True})

        _, response = proxy_app.test_client.get("/pinned")
        assert response.status == 200
        assert seen["same_object"] is True
        assert seen["first_version"] == seen["second_version"]
        assert seen["registry_version"] > seen["first_version"]

    def test_new_request_uses_updated_policy(self, proxy_app):
        versions = []

        @proxy_app.get("/version")
        async def version(request):
            versions.append(request.proxy_decision.policy_version)
            return json({"version": versions[-1]})

        proxy_app.test_client.get("/version")
        proxy_app.proxy_registry.update(
            trusted_hops=TRUSTED + ("127.0.0.1", "203.0.113.0/24")
        )
        proxy_app.test_client.get("/version")
        assert versions[1] == versions[0] + 1
