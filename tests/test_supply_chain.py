"""
Tests for reconhound/supply_chain.py (ReconHound Module 14, per
context.md's build order — catalog item 23, position 14 in the module
catalog).

Run with:  ./.venv/bin/python -m pytest tests/test_supply_chain.py -v

All tests mock the `requests.get` and `dns.resolver.Resolver.resolve`
boundaries so the suite is deterministic and offline-safe; no external
network access is required or performed anywhere in this file.
"""

import json
import os
import sys
from unittest import mock

import dns.exception
import dns.resolver
import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import supply_chain as sup


SAFE_TARGET = "example.com"
SAFE_PAGE_URL = "https://example.com/"


def _fake_response(status_code=200, headers=None, body=b"", final_url=None):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = dict(headers or {})
    resp.encoding = "utf-8"
    resp.content = body
    resp.url = final_url or SAFE_PAGE_URL
    resp.elapsed.total_seconds.return_value = 0.05
    resp.raw.read.return_value = body
    return resp


class _FakeCnameRdata:
    def __init__(self, target_text):
        self.target = target_text


# ---------------------------------------------------------------------------
# validate_url_target / validate_hostname_target / scope helpers
# ---------------------------------------------------------------------------

class TestValidateUrlTarget:
    def test_accepts_https_url(self):
        assert sup.validate_url_target(SAFE_PAGE_URL) == SAFE_PAGE_URL

    def test_accepts_in_scope_subdomain(self):
        assert sup.validate_url_target("https://shop.example.com/", target=SAFE_TARGET)

    def test_rejects_out_of_scope_host(self):
        with pytest.raises(sup.ScopeError):
            sup.validate_url_target("https://evil.com/", target=SAFE_TARGET)

    def test_rejects_non_http_scheme(self):
        with pytest.raises(sup.ScopeError):
            sup.validate_url_target("ftp://example.com/")

    def test_rejects_missing_hostname(self):
        with pytest.raises(sup.ScopeError):
            sup.validate_url_target("https:///")

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(sup.ScopeError):
            sup.validate_url_target(bad)

    def test_allows_ip_literal_host_without_scope_check(self):
        assert sup.validate_url_target("http://93.184.216.34/", target=SAFE_TARGET)


class TestValidateHostnameTarget:
    def test_accepts_in_scope_subdomain(self):
        assert sup.validate_hostname_target("shop.example.com", SAFE_TARGET) == "shop.example.com"

    def test_strips_trailing_dot(self):
        assert sup.validate_hostname_target("shop.example.com.", SAFE_TARGET) == "shop.example.com"

    def test_rejects_out_of_scope_hostname(self):
        with pytest.raises(sup.ScopeError):
            sup.validate_hostname_target("evil.com", SAFE_TARGET)

    def test_rejects_lookalike_suffix(self):
        with pytest.raises(sup.ScopeError):
            sup.validate_hostname_target("notexample.com", SAFE_TARGET)

    def test_rejects_empty_hostname(self):
        with pytest.raises(sup.ScopeError):
            sup.validate_hostname_target("", SAFE_TARGET)

    def test_rejects_missing_target(self):
        with pytest.raises(sup.ScopeError):
            sup.validate_hostname_target("shop.example.com", "")


class TestScopeHelpers:
    @pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "0.0.0.0"])
    def test_disallowed_redirect_ips(self, ip):
        assert sup._is_disallowed_redirect_ip(ip) is True

    def test_public_ip_allowed(self):
        assert sup._is_disallowed_redirect_ip("93.184.216.34") is False

    def test_in_scope_host_subdomain(self):
        assert sup._in_scope_host("api.example.com", SAFE_TARGET) is True

    def test_in_scope_host_rejects_unrelated(self):
        assert sup._in_scope_host("evilexample.com", SAFE_TARGET) is False

    def test_in_scope_host_empty_inputs(self):
        assert sup._in_scope_host("", SAFE_TARGET) is False
        assert sup._in_scope_host(SAFE_TARGET, "") is False


# ---------------------------------------------------------------------------
# make_finding / make_supply_chain_finding / PendingAssetsStore
# ---------------------------------------------------------------------------

class TestFindingsAndStore:
    def test_finding_structure_and_source(self):
        finding = sup.make_finding("supply_chain_trust_map", SAFE_TARGET, {"a": 1}, ["e"], sup.CONFIDENCE_MEDIUM)
        assert finding["source"] == "supply_chain.py"
        assert finding["metadata"] == {}
        json.dumps(finding)

    def test_make_supply_chain_finding_preserves_provenance(self):
        finding = sup.make_supply_chain_finding(
            "supply_chain_third_party_js_resource", SAFE_TARGET, {"url": "https://cdn.vendor.com/a.js"},
            ["e"], sup.CONFIDENCE_HIGH, source_asset=SAFE_PAGE_URL, discovery_source="script_tag",
        )
        assert finding["metadata"]["source_asset"] == SAFE_PAGE_URL
        assert finding["metadata"]["discovery_source"] == "script_tag"
        json.dumps(finding)

    def test_make_supply_chain_finding_extra_metadata_merged(self):
        finding = sup.make_supply_chain_finding(
            "x", SAFE_TARGET, {}, [], sup.CONFIDENCE_LOW, source_asset=None, discovery_source="dns_cname",
            extra_metadata={"foo": "bar"},
        )
        assert finding["metadata"]["foo"] == "bar"
        assert finding["metadata"]["source_asset"] is None

    def test_store_preserves_prior_data(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{"type": "javascript_reference", "source": "crawler.py"}]
        pending.write_text(json.dumps(pre_existing))

        store = sup.PendingAssetsStore(output_dir=str(output_dir))
        store.add(sup.make_finding("supply_chain_trust_map", SAFE_TARGET, {}, ["e"], sup.CONFIDENCE_MEDIUM))
        assert store.all() == pre_existing + [store.all()[-1]]

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = sup.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(sup.PersistenceError):
            store.add(sup.make_finding("x", SAFE_TARGET, {}, ["e"], sup.CONFIDENCE_LOW))

    def test_safe_store_add_returns_none_for_none_store(self):
        assert sup._safe_store_add(None, sup.make_finding("x", SAFE_TARGET, {}, [], sup.CONFIDENCE_LOW)) is None

    def test_safe_store_add_returns_error_on_persistence_failure(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("not json")
        store = sup.PendingAssetsStore(output_dir=str(output_dir))
        err = sup._safe_store_add(store, sup.make_finding("x", SAFE_TARGET, {}, [], sup.CONFIDENCE_LOW))
        assert err is not None


# ---------------------------------------------------------------------------
# fetch_url / fetch_page
# ---------------------------------------------------------------------------

class TestFetchUrl:
    def test_successful_fetch(self):
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=b"<html></html>")
        with mock.patch("requests.get", return_value=resp):
            result = sup.fetch_url(SAFE_PAGE_URL)
        assert result["status"] == "found"
        assert result["body"] == "<html></html>"

    def test_body_truncated_when_over_limit(self):
        resp = _fake_response(body=b"x" * 100)
        with mock.patch("requests.get", return_value=resp):
            result = sup.fetch_url(SAFE_PAGE_URL, max_body_bytes=10)
        assert result["body_truncated"] is True
        assert len(result["body"]) == 10

    def test_timeout_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout("t")):
            result = sup.fetch_url(SAFE_PAGE_URL)
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_connection_error_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = sup.fetch_url(SAFE_PAGE_URL)
        assert result["status"] == "error"

    def test_json_serializable(self):
        resp = _fake_response(headers={"X-Test": "1"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            result = sup.fetch_url(SAFE_PAGE_URL)
        json.dumps(result)


class TestFetchPage:
    def test_direct_success(self):
        resp = _fake_response(status_code=200, body=b"<html>hi</html>")
        with mock.patch("requests.get", return_value=resp):
            result = sup.fetch_page(SAFE_PAGE_URL, target=SAFE_TARGET)
        assert result["status"] == "found"
        assert len(result["hops"]) == 1

    def test_follows_in_scope_redirect(self):
        redirect = _fake_response(status_code=302, headers={"Location": "https://www.example.com/"})
        final = _fake_response(status_code=200, body=b"final content")
        with mock.patch("requests.get", side_effect=[redirect, final]):
            result = sup.fetch_page(SAFE_PAGE_URL, target=SAFE_TARGET)
        assert result["status"] == "found"
        assert result["body"] == "final content"

    def test_blocks_out_of_scope_redirect(self):
        redirect = _fake_response(status_code=302, headers={"Location": "https://evil.com/"})
        with mock.patch("requests.get", return_value=redirect):
            result = sup.fetch_page(SAFE_PAGE_URL, target=SAFE_TARGET)
        assert result["status"] == "error"
        assert "out of scope" in result["error"]

    def test_blocks_private_ip_redirect_ssrf_safeguard(self):
        redirect = _fake_response(status_code=302, headers={"Location": "http://169.254.169.254/"})
        with mock.patch("requests.get", return_value=redirect):
            result = sup.fetch_page(SAFE_PAGE_URL, target=SAFE_TARGET)
        assert result["status"] == "error"
        assert "SSRF" in result["error"] or "private" in result["error"].lower()

    def test_max_redirect_hops_exceeded(self):
        redirect = _fake_response(status_code=302, headers={"Location": SAFE_PAGE_URL})
        with mock.patch("requests.get", return_value=redirect):
            result = sup.fetch_page(SAFE_PAGE_URL, target=SAFE_TARGET, max_redirect_hops=3)
        assert result["status"] == "error"
        assert "max_redirect_hops" in result["error"]

    def test_network_failure_propagated(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = sup.fetch_page(SAFE_PAGE_URL, target=SAFE_TARGET)
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# 7. classify_third_party_host / catalog
# ---------------------------------------------------------------------------

class TestClassifyThirdPartyHost:
    def test_exact_catalog_match(self):
        result = sup.classify_third_party_host("js.stripe.com")
        assert result["vendor"] == "Stripe"
        assert result["category"] == "payment"
        assert result["category_source"] == "catalog_match"

    def test_subdomain_catalog_match(self):
        result = sup.classify_third_party_host("ingest.sentry.io")
        assert result["category"] == "error_tracking"
        assert result["category_source"] == "catalog_match"

    def test_auth_provider_category(self):
        result = sup.classify_third_party_host("mytenant.auth0.com")
        assert result["category"] == "auth"
        assert result["vendor"] == "Auth0"

    def test_analytics_category(self):
        result = sup.classify_third_party_host("www.google-analytics.com")
        assert result["category"] == "analytics"

    def test_cdn_catalog_match(self):
        result = sup.classify_third_party_host("cdn.jsdelivr.net")
        assert result["category"] == "cdn"
        assert result["category_source"] == "catalog_match"

    def test_cdn_naming_convention_heuristic(self):
        result = sup.classify_third_party_host("cdn.some-unknown-vendor.io")
        assert result["category"] == "cdn"
        assert result["category_source"] == "naming_convention_heuristic"
        assert result["vendor"] is None

    def test_static_naming_convention_heuristic(self):
        result = sup.classify_third_party_host("static.unknownvendor.com")
        assert result["category_source"] == "naming_convention_heuristic"

    def test_unmatched_host(self):
        result = sup.classify_third_party_host("totally-unknown-vendor.example.org")
        assert result["category"] == "unknown_third_party"
        assert result["category_source"] == "unmatched"
        assert result["vendor"] is None

    def test_never_claims_confirmed_identity_for_heuristic(self):
        # category_source is always present so callers can distinguish
        # catalog-confirmed vendors from unconfirmed heuristic guesses.
        result = sup.classify_third_party_host("cdn.mystery.net")
        assert result["category_source"] in ("catalog_match", "naming_convention_heuristic", "unmatched")


# ---------------------------------------------------------------------------
# 1. extract_third_party_js_resources
# ---------------------------------------------------------------------------

class TestExtractThirdPartyJsResources:
    def test_external_script_recorded(self):
        body = '<html><script src="https://js.stripe.com/v3/"></script></html>'
        result = sup.extract_third_party_js_resources(body, SAFE_PAGE_URL, SAFE_TARGET)
        assert len(result) == 1
        assert result[0]["host"] == "js.stripe.com"
        assert result[0]["classification"]["vendor"] == "Stripe"

    def test_in_scope_script_not_recorded(self):
        body = '<html><script src="/static/app.js"></script></html>'
        result = sup.extract_third_party_js_resources(body, SAFE_PAGE_URL, SAFE_TARGET)
        assert result == []

    def test_in_scope_absolute_subdomain_script_not_recorded(self):
        body = '<html><script src="https://static.example.com/app.js"></script></html>'
        result = sup.extract_third_party_js_resources(body, SAFE_PAGE_URL, SAFE_TARGET)
        assert result == []

    def test_duplicate_resources_deduplicated(self):
        body = (
            '<html><script src="https://cdn.jsdelivr.net/npm/x.js"></script>'
            '<script src="https://cdn.jsdelivr.net/npm/x.js"></script></html>'
        )
        result = sup.extract_third_party_js_resources(body, SAFE_PAGE_URL, SAFE_TARGET)
        assert len(result) == 1

    def test_script_without_src_ignored(self):
        body = '<html><script>console.log(1)</script></html>'
        result = sup.extract_third_party_js_resources(body, SAFE_PAGE_URL, SAFE_TARGET)
        assert result == []

    def test_non_http_scheme_ignored(self):
        body = '<html><script src="data:text/javascript;base64,AAAA"></script></html>'
        result = sup.extract_third_party_js_resources(body, SAFE_PAGE_URL, SAFE_TARGET)
        assert result == []

    def test_empty_body(self):
        assert sup.extract_third_party_js_resources("", SAFE_PAGE_URL, SAFE_TARGET) == []

    def test_malformed_html_does_not_raise(self):
        result = sup.extract_third_party_js_resources("<html><script src='", SAFE_PAGE_URL, SAFE_TARGET)
        assert isinstance(result, list)

    def test_evidence_present_and_json_safe(self):
        body = '<html><script src="https://static.vendor.io/a.js"></script></html>'
        result = sup.extract_third_party_js_resources(body, SAFE_PAGE_URL, SAFE_TARGET)
        assert result[0]["evidence"]
        json.dumps(result)


# ---------------------------------------------------------------------------
# 4. parse_csp_header / parse_csp_directive_value
# ---------------------------------------------------------------------------

class TestParseCspHeader:
    def test_absent_header(self):
        result = sup.parse_csp_header(None, SAFE_TARGET)
        assert result["present"] is False
        assert result["directives"] == {}

    def test_empty_header(self):
        result = sup.parse_csp_header("   ", SAFE_TARGET)
        assert result["present"] is False

    def test_basic_directive_parsed(self):
        result = sup.parse_csp_header("default-src 'self'", SAFE_TARGET)
        assert result["present"] is True
        assert "default-src" in result["directives"]
        assert "'self'" in result["directives"]["default-src"]["keywords"]

    def test_third_party_host_extracted(self):
        result = sup.parse_csp_header("script-src 'self' https://js.stripe.com", SAFE_TARGET)
        assert "js.stripe.com" in result["directives"]["script-src"]["third_party_hosts"]
        assert "js.stripe.com" in result["third_party_domains_referenced"]

    def test_in_scope_host_not_third_party(self):
        result = sup.parse_csp_header("script-src 'self' https://static.example.com", SAFE_TARGET)
        assert result["directives"]["script-src"]["third_party_hosts"] == []
        assert "static.example.com" in result["directives"]["script-src"]["in_scope_hosts"]

    def test_unsafe_inline_flagged(self):
        result = sup.parse_csp_header("script-src 'self' 'unsafe-inline'", SAFE_TARGET)
        assert result["directives"]["script-src"]["allows_unsafe_inline"] is True

    def test_unsafe_eval_flagged(self):
        result = sup.parse_csp_header("script-src 'unsafe-eval'", SAFE_TARGET)
        assert result["directives"]["script-src"]["allows_unsafe_eval"] is True

    def test_wildcard_flagged(self):
        result = sup.parse_csp_header("img-src *", SAFE_TARGET)
        assert result["directives"]["img-src"]["allows_broad_wildcard"] is True

    def test_scheme_wildcard_flagged(self):
        result = sup.parse_csp_header("script-src https:", SAFE_TARGET)
        assert result["directives"]["script-src"]["allows_broad_wildcard"] is True

    def test_unrecognized_directive_ignored(self):
        result = sup.parse_csp_header("sandbox allow-scripts", SAFE_TARGET)
        assert "sandbox" not in result["directives"]

    def test_multiple_directives(self):
        result = sup.parse_csp_header(
            "default-src 'self'; script-src 'self' https://js.stripe.com; style-src 'self' https://fonts.googleapis.com",
            SAFE_TARGET,
        )
        assert set(result["directives"].keys()) == {"default-src", "script-src", "style-src"}
        assert "fonts.googleapis.com" in result["directives"]["style-src"]["third_party_hosts"]

    def test_malformed_directive_does_not_raise(self):
        result = sup.parse_csp_header(";;; script-src ;; ", SAFE_TARGET)
        assert result["present"] is True

    def test_json_serializable(self):
        result = sup.parse_csp_header("default-src 'self' https://js.stripe.com 'unsafe-inline'", SAFE_TARGET)
        json.dumps(result)

    def test_nonce_and_hash_tokens_not_treated_as_hosts(self):
        result = sup.parse_csp_header("script-src 'nonce-abc123' 'sha256-abcdef'", SAFE_TARGET)
        assert result["directives"]["script-src"]["third_party_hosts"] == []


# ---------------------------------------------------------------------------
# 6. resolve_cname_chain / map_subdomain_third_party_dns
# ---------------------------------------------------------------------------

class TestResolveCnameChain:
    def test_single_hop_to_third_party(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve",
                                side_effect=[[_FakeCnameRdata("shops.myshopify.com.")], dns.resolver.NoAnswer()]):
            result = sup.resolve_cname_chain("shop.example.com")
        assert result["status"] == "found"
        assert result["chain"] == ["shops.myshopify.com"]

    def test_multi_hop_chain(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=[
            [_FakeCnameRdata("hop1.example.net.")],
            [_FakeCnameRdata("hop2.example.net.")],
            dns.resolver.NoAnswer(),
        ]):
            result = sup.resolve_cname_chain("sub.example.com")
        assert result["chain"] == ["hop1.example.net", "hop2.example.net"]

    def test_no_cname_record(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NoAnswer()):
            result = sup.resolve_cname_chain("sub.example.com")
        assert result["status"] == "none"
        assert result["chain"] == []

    def test_nxdomain_is_error(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = sup.resolve_cname_chain("sub.example.com")
        assert result["status"] == "error"

    def test_timeout_is_error_not_crash(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.Timeout()):
            result = sup.resolve_cname_chain("sub.example.com")
        assert result["status"] == "error"
        assert "timeout" in result["error"]

    def test_unexpected_exception_does_not_crash(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=RuntimeError("boom")):
            result = sup.resolve_cname_chain("sub.example.com")
        assert result["status"] == "error"

    def test_cname_cycle_does_not_infinite_loop(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve",
                                side_effect=[[_FakeCnameRdata("a.example.net.")], [_FakeCnameRdata("sub.example.com.")]]):
            result = sup.resolve_cname_chain("sub.example.com", max_hops=20)
        assert result["status"] == "found"
        assert len(result["chain"]) <= 20

    def test_max_hops_respected(self):
        counter = {"n": 0}

        def _fake_resolve(self, qname, rtype, *a, **kw):
            counter["n"] += 1
            return [_FakeCnameRdata(f"hop{counter['n']}.example.net.")]

        with mock.patch.object(dns.resolver.Resolver, "resolve", _fake_resolve):
            result = sup.resolve_cname_chain("sub.example.com", max_hops=3)
        assert len(result["chain"]) == 3


class TestMapSubdomainThirdPartyDns:
    def test_cname_to_known_vendor(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve",
                                side_effect=[[_FakeCnameRdata("shops.myshopify.com.")], dns.resolver.NoAnswer()]):
            result = sup.map_subdomain_third_party_dns("shop.example.com", SAFE_TARGET)
        assert result["third_party"]["vendor"] == "Shopify"
        assert result["third_party"]["category"] == "ecommerce_platform"

    def test_cname_to_in_scope_host_not_third_party(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve",
                                side_effect=[[_FakeCnameRdata("prod.internal.example.com.")], dns.resolver.NoAnswer()]):
            result = sup.map_subdomain_third_party_dns("sub.example.com", SAFE_TARGET)
        assert result["third_party"] is None

    def test_no_cname_no_third_party(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NoAnswer()):
            result = sup.map_subdomain_third_party_dns("sub.example.com", SAFE_TARGET)
        assert result["third_party"] is None
        assert result["status"] == "none"

    def test_dns_error_propagated_not_raised(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.Timeout()):
            result = sup.map_subdomain_third_party_dns("sub.example.com", SAFE_TARGET)
        assert result["status"] == "error"
        assert result["third_party"] is None

    def test_json_serializable(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve",
                                side_effect=[[_FakeCnameRdata("shops.myshopify.com.")], dns.resolver.NoAnswer()]):
            result = sup.map_subdomain_third_party_dns("shop.example.com", SAFE_TARGET)
        json.dumps(result)


# ---------------------------------------------------------------------------
# 5. build_trust_map / build_category_inventory
# ---------------------------------------------------------------------------

class TestBuildTrustMap:
    def test_script_resource_creates_relationship(self):
        js_resources = [{
            "url": "https://js.stripe.com/v3/", "host": "js.stripe.com", "source_page": SAFE_PAGE_URL,
            "classification": sup.classify_third_party_host("js.stripe.com"), "evidence": ["e"],
        }]
        trust_map = sup.build_trust_map(js_resources, {}, [])
        assert trust_map["assets"][SAFE_PAGE_URL] == ["js.stripe.com"]
        assert "js.stripe.com" in trust_map["external_services"]
        assert trust_map["external_services"]["js.stripe.com"]["category"] == "payment"
        assert "script_reference" in trust_map["external_services"]["js.stripe.com"]["relationship_types"]

    def test_csp_allowlist_creates_relationship(self):
        csp_by_page = {SAFE_PAGE_URL: sup.parse_csp_header("script-src 'self' https://js.stripe.com", SAFE_TARGET)}
        trust_map = sup.build_trust_map([], csp_by_page, [])
        assert "js.stripe.com" in trust_map["external_services"]
        assert any(rt.startswith("csp_allowlist:") for rt in trust_map["external_services"]["js.stripe.com"]["relationship_types"])

    def test_csp_absent_page_produces_no_relationship(self):
        csp_by_page = {SAFE_PAGE_URL: sup.parse_csp_header(None, SAFE_TARGET)}
        trust_map = sup.build_trust_map([], csp_by_page, [])
        assert trust_map["external_service_count"] == 0

    def test_dns_relationship_creates_edge(self):
        dns_rel = {"subdomain": "shop.example.com", "third_party": sup.classify_third_party_host("shops.myshopify.com")}
        trust_map = sup.build_trust_map([], {}, [dns_rel])
        assert "shops.myshopify.com" in trust_map["external_services"]
        assert "dns_cname" in trust_map["external_services"]["shops.myshopify.com"]["relationship_types"]

    def test_multiple_sources_merge_into_one_service_entry(self):
        js_resources = [{
            "url": "https://js.stripe.com/v3/", "host": "js.stripe.com", "source_page": SAFE_PAGE_URL,
            "classification": sup.classify_third_party_host("js.stripe.com"), "evidence": ["e"],
        }]
        csp_by_page = {SAFE_PAGE_URL: sup.parse_csp_header("script-src https://js.stripe.com", SAFE_TARGET)}
        trust_map = sup.build_trust_map(js_resources, csp_by_page, [])
        entry = trust_map["external_services"]["js.stripe.com"]
        assert len(entry["relationship_types"]) == 2

    def test_empty_input_produces_empty_map(self):
        trust_map = sup.build_trust_map([], {}, [])
        assert trust_map["assets"] == {}
        assert trust_map["external_service_count"] == 0

    def test_json_serializable(self):
        js_resources = [{
            "url": "https://cdn.jsdelivr.net/x.js", "host": "cdn.jsdelivr.net", "source_page": SAFE_PAGE_URL,
            "classification": sup.classify_third_party_host("cdn.jsdelivr.net"), "evidence": ["e"],
        }]
        trust_map = sup.build_trust_map(js_resources, {}, [])
        json.dumps(trust_map)


class TestBuildCategoryInventory:
    def test_groups_by_category(self):
        js_resources = [
            {"url": "https://js.stripe.com/v3/", "host": "js.stripe.com", "source_page": SAFE_PAGE_URL,
             "classification": sup.classify_third_party_host("js.stripe.com"), "evidence": ["e"]},
            {"url": "https://www.google-analytics.com/a.js", "host": "www.google-analytics.com", "source_page": SAFE_PAGE_URL,
             "classification": sup.classify_third_party_host("www.google-analytics.com"), "evidence": ["e"]},
        ]
        trust_map = sup.build_trust_map(js_resources, {}, [])
        inventory = sup.build_category_inventory(trust_map)
        assert "payment" in inventory
        assert "analytics" in inventory
        assert inventory["payment"][0]["host"] == "js.stripe.com"

    def test_empty_trust_map_produces_empty_inventory(self):
        assert sup.build_category_inventory(sup.build_trust_map([], {}, [])) == {}


# ---------------------------------------------------------------------------
# 8. assess_csp_risk_implications / assess_aggregate_risk_implications
# ---------------------------------------------------------------------------

class TestAssessCspRiskImplications:
    def test_absent_csp_with_third_parties_flagged(self):
        csp = sup.parse_csp_header(None, SAFE_TARGET)
        risks = sup.assess_csp_risk_implications(SAFE_PAGE_URL, csp, {"js.stripe.com"})
        assert len(risks) == 1
        assert risks[0]["risk_type"] == "csp_absent_with_third_party_scripts"
        assert risks[0]["confidence"] in (sup.CONFIDENCE_LOW, sup.CONFIDENCE_MEDIUM)

    def test_absent_csp_without_third_parties_not_flagged(self):
        csp = sup.parse_csp_header(None, SAFE_TARGET)
        risks = sup.assess_csp_risk_implications(SAFE_PAGE_URL, csp, set())
        assert risks == []

    def test_unsafe_inline_flagged(self):
        csp = sup.parse_csp_header("script-src 'self' 'unsafe-inline'", SAFE_TARGET)
        risks = sup.assess_csp_risk_implications(SAFE_PAGE_URL, csp, set())
        assert any(r["risk_type"] == "csp_directive_weakened" for r in risks)

    def test_host_not_in_allowlist_flagged(self):
        csp = sup.parse_csp_header("script-src 'self'", SAFE_TARGET)
        risks = sup.assess_csp_risk_implications(SAFE_PAGE_URL, csp, {"js.stripe.com"})
        assert any(r["risk_type"] == "third_party_script_not_in_csp_allowlist" for r in risks)

    def test_host_in_allowlist_not_flagged_for_that_risk(self):
        csp = sup.parse_csp_header("script-src 'self' https://js.stripe.com", SAFE_TARGET)
        risks = sup.assess_csp_risk_implications(SAFE_PAGE_URL, csp, {"js.stripe.com"})
        assert not any(r["risk_type"] == "third_party_script_not_in_csp_allowlist" for r in risks)

    def test_never_asserts_confirmed_vulnerability(self):
        csp = sup.parse_csp_header(None, SAFE_TARGET)
        risks = sup.assess_csp_risk_implications(SAFE_PAGE_URL, csp, {"js.stripe.com"})
        for r in risks:
            assert r["confidence"] != sup.CONFIDENCE_HIGH
            joined_evidence = " ".join(r["evidence"]).lower()
            assert "not a confirmed vulnerability" in joined_evidence

    def test_json_serializable(self):
        csp = sup.parse_csp_header("script-src 'unsafe-inline' 'unsafe-eval' *", SAFE_TARGET)
        risks = sup.assess_csp_risk_implications(SAFE_PAGE_URL, csp, {"unknown.example.org"})
        json.dumps(risks)


class TestAssessAggregateRiskImplications:
    def _catalog_service(self, host, vendor, category):
        return {"host": host, "vendor": vendor, "category": category, "category_source": "catalog_match",
                "referenced_by": [SAFE_PAGE_URL], "relationship_types": ["script_reference"]}

    def test_broad_surface_flagged_at_threshold(self):
        trust_map = {"external_service_count": 5, "external_services": {
            f"vendor{i}.example.org": self._catalog_service(f"vendor{i}.example.org", None, "unknown_third_party")
            for i in range(5)
        }}
        risks = sup.assess_aggregate_risk_implications(trust_map, {})
        assert any(r["risk_type"] == "broad_third_party_surface" for r in risks)

    def test_below_threshold_not_flagged(self):
        trust_map = {"external_service_count": 2, "external_services": {}}
        risks = sup.assess_aggregate_risk_implications(trust_map, {})
        assert not any(r["risk_type"] == "broad_third_party_surface" for r in risks)

    def test_payment_category_flagged(self):
        trust_map = {"external_service_count": 1, "external_services": {}}
        inventory = {"payment": [{"host": "js.stripe.com", "vendor": "Stripe", "category_source": "catalog_match", "referenced_by": []}]}
        risks = sup.assess_aggregate_risk_implications(trust_map, inventory)
        assert any(r["risk_type"] == "high_trust_category_dependency:payment" for r in risks)

    def test_auth_category_flagged(self):
        trust_map = {"external_service_count": 1, "external_services": {}}
        inventory = {"auth": [{"host": "x.auth0.com", "vendor": "Auth0", "category_source": "catalog_match", "referenced_by": []}]}
        risks = sup.assess_aggregate_risk_implications(trust_map, inventory)
        assert any(r["risk_type"] == "high_trust_category_dependency:auth" for r in risks)

    def test_no_high_trust_categories_no_flag(self):
        trust_map = {"external_service_count": 1, "external_services": {}}
        inventory = {"cdn": [{"host": "cdn.jsdelivr.net", "vendor": "jsDelivr", "category_source": "catalog_match", "referenced_by": []}]}
        risks = sup.assess_aggregate_risk_implications(trust_map, inventory)
        assert not any(r["risk_type"].startswith("high_trust_category_dependency") for r in risks)

    def test_empty_input_no_risks(self):
        assert sup.assess_aggregate_risk_implications({"external_service_count": 0, "external_services": {}}, {}) == []

    def test_never_high_confidence(self):
        trust_map = {"external_service_count": 5, "external_services": {
            f"vendor{i}.example.org": self._catalog_service(f"vendor{i}.example.org", None, "unknown_third_party")
            for i in range(5)
        }}
        inventory = {"payment": [{"host": "js.stripe.com", "vendor": "Stripe", "category_source": "catalog_match", "referenced_by": []}]}
        risks = sup.assess_aggregate_risk_implications(trust_map, inventory)
        for r in risks:
            assert r["confidence"] != sup.CONFIDENCE_HIGH


# ---------------------------------------------------------------------------
# analyze_page / persist_page_findings
# ---------------------------------------------------------------------------

class TestAnalyzePage:
    def test_full_analysis(self):
        body = '<html><script src="https://js.stripe.com/v3/"></script></html>'
        headers = {"Content-Security-Policy": "script-src 'self'"}
        result = sup.analyze_page(body, headers, SAFE_PAGE_URL, SAFE_TARGET)
        assert len(result["js_resources"]) == 1
        assert result["csp"]["present"] is True
        assert len(result["risk_implications"]) >= 1

    def test_empty_page_no_findings(self):
        result = sup.analyze_page("<html></html>", {}, SAFE_PAGE_URL, SAFE_TARGET)
        assert result["js_resources"] == []
        assert result["csp"]["present"] is False
        assert result["risk_implications"] == []

    def test_json_serializable(self):
        body = '<html><script src="https://js.stripe.com/v3/"></script></html>'
        result = sup.analyze_page(body, {"Content-Security-Policy": "default-src *"}, SAFE_PAGE_URL, SAFE_TARGET)
        json.dumps(result)


class TestPersistPageFindings:
    def test_persists_resource_category_and_csp_findings(self, tmp_path):
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        body = '<html><script src="https://js.stripe.com/v3/"></script></html>'
        analysis = sup.analyze_page(body, {"Content-Security-Policy": "script-src 'self'"}, SAFE_PAGE_URL, SAFE_TARGET)
        result = sup.persist_page_findings(analysis, SAFE_TARGET, store)
        assert result["errors"] == []
        types = [f["type"] for f in store.all()]
        assert "supply_chain_third_party_js_resource" in types
        assert "supply_chain_service_category" in types
        assert "supply_chain_csp_analysis" in types
        assert "supply_chain_risk_implication" in types

    def test_no_findings_persists_negative_result(self, tmp_path):
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        analysis = sup.analyze_page("<html></html>", {}, SAFE_PAGE_URL, SAFE_TARGET)
        sup.persist_page_findings(analysis, SAFE_TARGET, store)
        types = [f["type"] for f in store.all()]
        assert "supply_chain_checked_no_findings" in types

    def test_unmatched_host_does_not_get_category_finding(self, tmp_path):
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        body = '<html><script src="https://totally-unknown-vendor.example.org/a.js"></script></html>'
        analysis = sup.analyze_page(body, {}, SAFE_PAGE_URL, SAFE_TARGET)
        sup.persist_page_findings(analysis, SAFE_TARGET, store)
        category_findings = [f for f in store.all() if f["type"] == "supply_chain_service_category"]
        assert category_findings == []

    def test_persistence_failure_recorded_not_raised(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("not json")
        store = sup.PendingAssetsStore(output_dir=str(output_dir))
        analysis = sup.analyze_page(
            '<html><script src="https://js.stripe.com/v3/"></script></html>', {}, SAFE_PAGE_URL, SAFE_TARGET,
        )
        result = sup.persist_page_findings(analysis, SAFE_TARGET, store)
        assert len(result["errors"]) > 0

    def test_all_persisted_findings_json_safe(self, tmp_path):
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        body = '<html><script src="https://js.stripe.com/v3/"></script></html>'
        analysis = sup.analyze_page(body, {"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"}, SAFE_PAGE_URL, SAFE_TARGET)
        sup.persist_page_findings(analysis, SAFE_TARGET, store)
        json.dumps(store.all())


# ---------------------------------------------------------------------------
# input normalization
# ---------------------------------------------------------------------------

class TestNormalizeReferences:
    def test_normalize_page_reference_string(self):
        assert sup._normalize_page_reference(SAFE_PAGE_URL) == SAFE_PAGE_URL

    def test_normalize_page_reference_dict(self):
        assert sup._normalize_page_reference({"url": SAFE_PAGE_URL}) == SAFE_PAGE_URL

    def test_normalize_page_reference_crawler_finding(self):
        finding = {"type": "url_discovered", "value": {"url": SAFE_PAGE_URL}}
        assert sup._normalize_page_reference(finding) == SAFE_PAGE_URL

    def test_normalize_page_reference_invalid(self):
        assert sup._normalize_page_reference(123) is None
        assert sup._normalize_page_reference({}) is None

    def test_normalize_subdomain_reference_string(self):
        assert sup._normalize_subdomain_reference("shop.example.com") == "shop.example.com"

    def test_normalize_subdomain_reference_dict(self):
        assert sup._normalize_subdomain_reference({"hostname": "shop.example.com"}) == "shop.example.com"

    def test_normalize_subdomain_reference_passive_recon_finding(self):
        finding = {"type": "dns_record", "value": {"subdomain": "shop.example.com"}}
        assert sup._normalize_subdomain_reference(finding) == "shop.example.com"

    def test_normalize_subdomain_reference_invalid(self):
        assert sup._normalize_subdomain_reference(None) is None
        assert sup._normalize_subdomain_reference({}) is None


# ---------------------------------------------------------------------------
# run_supply_chain_analysis (integration)
# ---------------------------------------------------------------------------

class TestRunSupplyChainAnalysis:
    def test_requires_target(self):
        with pytest.raises(sup.ScopeError):
            sup.run_supply_chain_analysis(pages=[SAFE_PAGE_URL], target=None)

    def test_full_run_persists_and_summarizes(self, tmp_path):
        body = '<html><script src="https://js.stripe.com/v3/"></script></html>'
        resp = _fake_response(status_code=200, headers={"Content-Security-Policy": "script-src 'self'"}, body=body.encode())
        with mock.patch("requests.get", return_value=resp), \
             mock.patch.object(dns.resolver.Resolver, "resolve",
                                side_effect=[[_FakeCnameRdata("shops.myshopify.com.")], dns.resolver.NoAnswer()]):
            summary = sup.run_supply_chain_analysis(
                pages=[SAFE_PAGE_URL], subdomains=["shop.example.com"], target=SAFE_TARGET,
                output_dir=str(tmp_path / "output"),
            )
        assert summary["pages_analyzed"] == 1
        assert summary["subdomains_analyzed"] == 1
        assert summary["trust_map"]["external_service_count"] >= 2
        assert "js.stripe.com" in summary["trust_map"]["external_services"]
        assert "shops.myshopify.com" in summary["trust_map"]["external_services"]
        json.dumps(summary)

    def test_out_of_scope_page_skipped_not_fetched(self, tmp_path):
        with mock.patch("requests.get") as mock_get:
            summary = sup.run_supply_chain_analysis(
                pages=["https://evil.com/"], target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
            )
        mock_get.assert_not_called()
        assert summary["pages_skipped_out_of_scope"] == 1

    def test_page_fetch_failure_does_not_abort_run(self, tmp_path):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            summary = sup.run_supply_chain_analysis(
                pages=[SAFE_PAGE_URL], target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
            )
        assert summary["pages_failed"] == 1
        assert summary["finished_at"]

    def test_out_of_scope_subdomain_skipped_not_resolved(self, tmp_path):
        with mock.patch.object(dns.resolver.Resolver, "resolve") as mock_resolve:
            summary = sup.run_supply_chain_analysis(
                subdomains=["evil.com"], target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
            )
        mock_resolve.assert_not_called()
        assert summary["subdomains_skipped_out_of_scope"] == 1

    def test_dns_failure_does_not_abort_run(self, tmp_path):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.Timeout()):
            summary = sup.run_supply_chain_analysis(
                subdomains=["shop.example.com"], target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
            )
        assert summary["subdomains_dns_failed"] == 1
        assert summary["finished_at"]

    def test_empty_input_produces_empty_but_valid_summary(self, tmp_path):
        summary = sup.run_supply_chain_analysis(pages=[], subdomains=[], target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert summary["pages_requested"] == 0
        assert summary["subdomains_requested"] == 0
        assert summary["trust_map"]["external_service_count"] == 0
        json.dumps(summary)

    def test_accepts_crawler_style_page_records(self, tmp_path):
        resp = _fake_response(status_code=200, body=b"<html></html>")
        page_finding = {"type": "url_discovered", "value": {"url": SAFE_PAGE_URL}}
        with mock.patch("requests.get", return_value=resp):
            summary = sup.run_supply_chain_analysis(pages=[page_finding], target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert summary["pages_analyzed"] == 1

    def test_max_pages_limits_requests(self, tmp_path):
        resp = _fake_response(status_code=200, body=b"<html></html>")
        with mock.patch("requests.get", return_value=resp) as mock_get:
            summary = sup.run_supply_chain_analysis(
                pages=[SAFE_PAGE_URL, "https://example.com/other"], target=SAFE_TARGET,
                output_dir=str(tmp_path / "output"), max_pages=1,
            )
        assert summary["pages_requested"] == 1
        assert mock_get.call_count == 1

    def test_persistence_is_crash_safe_across_run(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, body=b'<html><script src="https://js.stripe.com/v3/"></script></html>')
        with mock.patch("requests.get", return_value=resp):
            sup.run_supply_chain_analysis(pages=[SAFE_PAGE_URL], target=SAFE_TARGET, output_dir=str(output_dir))
        persisted = json.loads((output_dir / "pending_assets.json").read_text())
        assert len(persisted) > 0
        assert all(f["source"] == "supply_chain.py" for f in persisted)

    def test_non_textual_page_skipped_gracefully(self, tmp_path):
        resp = _fake_response(status_code=200, headers={"Content-Type": "image/png"}, body=b"\x89PNG\r\n")
        with mock.patch("requests.get", return_value=resp):
            summary = sup.run_supply_chain_analysis(pages=[SAFE_PAGE_URL], target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert summary["pages_analyzed"] == 0
        assert summary["page_results"][0]["status"] == "non_textual_content_skipped"


# ===========================================================================
# Hardening regression tests
#
# Each class below pins a defect that was found in this module and fixed.
# Where a test's failure mode is not obvious from its name, the comment says
# what went wrong before, so a future change that reintroduces it is
# recognisable rather than merely red.
# ===========================================================================


class TestScopeAndSsrfHardening:
    """validate_url_target is the single chokepoint for every request."""

    @pytest.mark.parametrize("url", [
        "https://evil.com\r\n.example.com/",
        "https://exa\tmple.com/",
        "https://example.com/\x00",
    ])
    def test_control_characters_rejected(self, url):
        # urlsplit silently strips CR/LF/TAB, so the host that was scope-checked
        # was not the string handed to requests.
        with pytest.raises(sup.ScopeError):
            sup.validate_url_target(url, target=SAFE_TARGET)

    @pytest.mark.parametrize("url", ["http://[::1/", "http://example.com:99999999/"])
    def test_unparseable_url_raises_scope_error_not_value_error(self, url):
        # A bare ValueError escaping here aborted the whole run.
        with pytest.raises(sup.ScopeError):
            sup.validate_url_target(url, target=SAFE_TARGET)

    @pytest.mark.parametrize("url", [
        "http://127.0.0.1:8080/", "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/", "http://[::1]/", "http://192.168.1.1/",
    ])
    def test_private_ip_literal_rejected_even_though_ip_exempt_from_domain_check(self, url):
        with pytest.raises(sup.ScopeError):
            sup.validate_url_target(url, target=SAFE_TARGET)

    @pytest.mark.parametrize("url", [
        "http://2130706433/", "http://0177.0.0.1/", "http://0x7f.0.0.1/", "http://127.1/",
    ])
    def test_obfuscated_private_ip_forms_rejected(self, url):
        # The resolver accepts these; a domain-suffix check does not recognise them.
        with pytest.raises(sup.ScopeError):
            sup.validate_url_target(url, target=SAFE_TARGET)

    def test_operator_authorized_ip_target_still_allowed(self):
        assert sup.validate_url_target("http://127.0.0.1:8080/", target="127.0.0.1")
        assert sup.validate_url_target("http://2130706433/", target="127.0.0.1")

    def test_public_ip_literal_still_allowed(self):
        assert sup.validate_url_target("http://93.184.216.34/", target=SAFE_TARGET)

    @pytest.mark.parametrize("host", ["abc.de", "ff.ff", "face.book", "1e100.net", "example.com"])
    def test_hex_looking_domains_are_not_treated_as_ip_literals(self, host):
        assert sup._is_ip_literal(host) is False

    def test_userinfo_credentials_stripped_not_persisted(self):
        assert sup.validate_url_target(
            "https://admin:hunter2@example.com/x", target=SAFE_TARGET) == "https://example.com/x"

    def test_userinfo_host_confusion_still_scope_checked(self):
        # "https://example.com@evil.com/" has hostname evil.com, not example.com.
        with pytest.raises(sup.ScopeError):
            sup.validate_url_target("https://example.com@evil.com/", target=SAFE_TARGET)
        assert sup.validate_url_target("https://evil.com@example.com/", target=SAFE_TARGET) \
            == "https://example.com/"

    def test_idn_scope_matches_in_both_directions(self):
        assert sup._in_scope_host("xn--mnchen-3ya.de", "münchen.de")
        assert sup._in_scope_host("www.münchen.de", "xn--mnchen-3ya.de")

    def test_idn_homograph_still_out_of_scope(self):
        assert not sup._in_scope_host("exаmple.com", "example.com")   # Cyrillic a

    def test_lookalike_suffix_still_rejected(self):
        assert not sup._in_scope_host("evil-example.com", SAFE_TARGET)
        assert not sup._in_scope_host("example.com.evil.net", SAFE_TARGET)

    def test_redirect_to_obfuscated_private_ip_blocked(self):
        redirect = _fake_response(status_code=302, headers={"Location": "http://2130706433/"})
        with mock.patch("requests.get", return_value=redirect):
            result = sup.fetch_page(SAFE_PAGE_URL, target=SAFE_TARGET)
        assert result["status"] == "error"
        assert "SSRF" in result["error"] or "private" in result["error"].lower()

    def test_redirect_to_non_http_scheme_blocked_without_target(self):
        redirect = _fake_response(status_code=302, headers={"Location": "file:///etc/passwd"})
        with mock.patch("requests.get", return_value=redirect):
            result = sup.fetch_page(SAFE_PAGE_URL, target=None)
        assert result["status"] == "error"

    def test_hostname_with_whitespace_rejected(self):
        with pytest.raises(sup.ScopeError):
            sup.validate_hostname_target("shop .example.com", SAFE_TARGET)


class TestCspEnforcedVersusReportOnly:
    def test_report_only_is_detected_and_not_counted_as_enforcement(self):
        result = sup.analyze_csp(
            {"Content-Security-Policy-Report-Only": "script-src https://cdn.vendor.com"}, "", SAFE_TARGET)
        assert result["report_only_present"] is True
        assert result["enforced_present"] is False
        assert result["present"] is False        # `present` means ENFORCED
        assert "cdn.vendor.com" in result["all_third_party_domains_referenced"]

    def test_report_only_only_page_is_not_reported_as_having_no_csp(self):
        analysis = sup.analyze_page(
            '<script src="https://cdn.vendor.com/x.js"></script>',
            {"Content-Security-Policy-Report-Only": "script-src https://cdn.vendor.com"},
            SAFE_PAGE_URL, SAFE_TARGET)
        types = {r["risk_type"] for r in analysis["risk_implications"]}
        assert "csp_report_only_not_enforced" in types

    def test_report_only_implication_says_it_is_not_enforced(self):
        analysis = sup.analyze_page(
            "<html></html>", {"Content-Security-Policy-Report-Only": "default-src 'self'"},
            SAFE_PAGE_URL, SAFE_TARGET)
        risk = next(r for r in analysis["risk_implications"]
                    if r["risk_type"] == "csp_report_only_not_enforced")
        assert "not" in risk["description"].lower() and "enforce" in risk["description"].lower()
        assert risk["confidence"] != sup.CONFIDENCE_HIGH

    def test_enforced_and_report_only_simultaneously(self):
        result = sup.analyze_csp({
            "Content-Security-Policy": "script-src https://enforced.vendor.com",
            "Content-Security-Policy-Report-Only": "script-src https://reported.vendor.com",
        }, "", SAFE_TARGET)
        assert result["enforced_present"] and result["report_only_present"]
        assert result["third_party_domains_referenced"] == ["enforced.vendor.com"]
        assert "reported.vendor.com" in result["all_third_party_domains_referenced"]

    def test_report_only_hosts_reach_trust_map_marked_as_report_only(self):
        csp = sup.analyze_csp(
            {"Content-Security-Policy-Report-Only": "script-src https://ro.vendor.com"}, "", SAFE_TARGET)
        trust_map = sup.build_trust_map([], {SAFE_PAGE_URL: csp}, [])
        entry = trust_map["external_services"]["ro.vendor.com"]
        assert any(rt.startswith("csp_report_only_allowlist:") for rt in entry["relationship_types"])


class TestCspMultiplePoliciesAndMalformed:
    def test_comma_joined_policies_do_not_fabricate_hosts(self):
        # requests joins repeated headers with ", "; parsing that as one policy
        # produced third-party "hosts" named "'none'," and "frame-ancestors".
        result = sup.parse_csp_header(
            "script-src https://a.com; default-src 'none', frame-ancestors 'none'", SAFE_TARGET)
        assert result["third_party_domains_referenced"] == ["a.com"]
        assert result["policy_count"] == 2

    def test_repeated_header_values_are_both_preserved(self):
        result = sup.analyze_csp(
            {"Content-Security-Policy": ["script-src https://a.com", "img-src https://b.com"]},
            "", SAFE_TARGET)
        assert set(result["third_party_domains_referenced"]) == {"a.com", "b.com"}

    def test_duplicate_directive_first_occurrence_governs_and_conflict_preserved(self):
        result = sup.parse_csp_header(
            "script-src https://first.com; script-src https://second.com", SAFE_TARGET)
        assert result["directives"]["script-src"]["third_party_hosts"] == ["first.com"]
        assert "script-src" in result["duplicate_directives"]

    @pytest.mark.parametrize("value", [None, "", "   ", 123, ["script-src x"], {"a": 1}])
    def test_non_string_or_empty_policy_never_raises(self, value):
        result = sup.parse_csp_header(value, SAFE_TARGET)
        assert result["present"] is False

    @pytest.mark.parametrize("value", [
        "script-src none", "default-src frame-ancestors", "img-src data:image/png;base64,iVBOR",
        ";;;", "script-src", "!!!! ???",
    ])
    def test_malformed_policies_never_fabricate_third_party_hosts(self, value):
        result = sup.parse_csp_header(value, SAFE_TARGET)
        for host in result["third_party_domains_referenced"]:
            assert "." in host or sup._is_ip_literal(host)

    def test_ipv6_source_does_not_become_the_host_bracket(self):
        assert sup._csp_token_host("[::1]:443") == "[::1]"

    def test_wildcard_source_recorded_as_wildcard(self):
        d = sup.parse_csp_header("script-src *.vendor.com", SAFE_TARGET)["directives"]["script-src"]
        assert d["wildcard_hosts"] == ["*.vendor.com"]

    def test_csp_token_and_host_lists_are_bounded(self):
        policy = "script-src " + " ".join(["'self'"] * 5000) + " " + \
                 " ".join(f"https://h{i}.vendor.net" for i in range(5000))
        d = sup.parse_csp_header(policy, SAFE_TARGET)["directives"]["script-src"]
        assert len(d["keywords"]) <= sup.MAX_CSP_TOKENS_PER_DIRECTIVE
        assert len(d["third_party_hosts"]) <= sup.DEFAULT_MAX_CSP_HOSTS_PER_DIRECTIVE
        assert d["hosts_truncated"] is True
        assert len(d["raw"]) <= sup.MAX_RAW_POLICY_CHARS + 64

    def test_flags_still_computed_from_full_token_stream_after_capping(self):
        policy = "script-src " + " ".join(["'self'"] * 5000) + " 'unsafe-inline'"
        d = sup.parse_csp_header(policy, SAFE_TARGET)["directives"]["script-src"]
        assert d["allows_unsafe_inline"] is True


class TestCspMetaDelivery:
    def test_meta_csp_is_an_enforced_policy(self):
        body = '<meta http-equiv="Content-Security-Policy" content="script-src https://cdn.vendor.com">'
        result = sup.analyze_csp({}, body, SAFE_TARGET)
        assert result["present"] is True
        assert result["delivered_via_meta"] is True
        assert result["delivered_via_header"] is False
        assert "cdn.vendor.com" in result["third_party_domains_referenced"]

    def test_meta_report_only_is_not_honoured(self):
        # HTML does not support report-only via meta, so browsers ignore it.
        body = '<meta http-equiv="Content-Security-Policy-Report-Only" content="script-src https://x.com">'
        result = sup.analyze_csp({}, body, SAFE_TARGET)
        assert result["present"] is False
        assert result["report_only_present"] is False

    def test_meta_and_header_policies_both_preserved(self):
        body = '<meta http-equiv="Content-Security-Policy" content="img-src https://meta.vendor.com">'
        result = sup.analyze_csp({"Content-Security-Policy": "script-src https://hdr.vendor.com"},
                                 body, SAFE_TARGET)
        assert set(result["third_party_domains_referenced"]) == {"meta.vendor.com", "hdr.vendor.com"}
        assert {s["delivery"] for s in result["sources"]} == {"header", "meta"}

    def test_malformed_html_meta_extraction_does_not_raise(self):
        assert sup.extract_meta_csp_policies("<meta http-equiv=") == []
        assert sup.extract_meta_csp_policies(None) == []


class TestCspAllowlistFalsePositives:
    def test_script_src_elem_is_honoured_before_default_src(self):
        analysis = sup.analyze_page(
            '<script src="https://cdn.vendor.com/x.js"></script>',
            {"Content-Security-Policy": "default-src 'none'; script-src-elem https://cdn.vendor.com"},
            SAFE_PAGE_URL, SAFE_TARGET)
        assert not any(r["risk_type"] == "third_party_script_not_in_csp_allowlist"
                       for r in analysis["risk_implications"])

    def test_wildcard_allowlist_covers_subdomain(self):
        analysis = sup.analyze_page(
            '<script src="https://js.stripe.com/v3"></script>',
            {"Content-Security-Policy": "script-src *.stripe.com"}, SAFE_PAGE_URL, SAFE_TARGET)
        assert not any(r["risk_type"] == "third_party_script_not_in_csp_allowlist"
                       for r in analysis["risk_implications"])

    def test_wildcard_does_not_cover_the_bare_domain(self):
        assert sup._csp_source_allows_host("stripe.com", {"*.stripe.com"}) is False
        assert sup._csp_source_allows_host("js.stripe.com", {"*.stripe.com"}) is True

    def test_strict_dynamic_suppresses_allowlist_discrepancy(self):
        analysis = sup.analyze_page(
            '<script src="https://cdn.vendor.com/x.js"></script>',
            {"Content-Security-Policy": "script-src 'strict-dynamic' 'nonce-abc'"},
            SAFE_PAGE_URL, SAFE_TARGET)
        assert not any(r["risk_type"] == "third_party_script_not_in_csp_allowlist"
                       for r in analysis["risk_implications"])

    def test_broad_wildcard_suppresses_allowlist_discrepancy_but_still_flags_weakening(self):
        analysis = sup.analyze_page(
            '<script src="https://cdn.vendor.com/x.js"></script>',
            {"Content-Security-Policy": "script-src https:"}, SAFE_PAGE_URL, SAFE_TARGET)
        types = {r["risk_type"] for r in analysis["risk_implications"]}
        assert "third_party_script_not_in_csp_allowlist" not in types
        assert "csp_directive_weakened" in types

    def test_genuine_discrepancy_is_still_reported(self):
        analysis = sup.analyze_page(
            '<script src="https://cdn.vendor.com/x.js"></script>',
            {"Content-Security-Policy": "script-src 'self' https://other.vendor.com"},
            SAFE_PAGE_URL, SAFE_TARGET)
        assert any(r["risk_type"] == "third_party_script_not_in_csp_allowlist"
                   for r in analysis["risk_implications"])


class TestResourceAttribution:
    def test_base_href_changes_resolution_of_relative_scripts(self):
        body = ('<html><head><base href="https://cdn.thirdparty.net/"></head>'
                '<script src="app.js"></script></html>')
        resources = sup.extract_third_party_js_resources(body, SAFE_PAGE_URL, SAFE_TARGET)
        assert [r["host"] for r in resources] == ["cdn.thirdparty.net"]
        assert any("base href" in e for e in resources[0]["evidence"])

    def test_base_href_of_unsupported_scheme_is_ignored(self):
        body = '<html><head><base href="javascript:void(0)"></head><script src="app.js"></script></html>'
        assert sup.extract_third_party_js_resources(body, SAFE_PAGE_URL, SAFE_TARGET) == []

    def test_only_first_base_element_is_used(self):
        body = ('<base href="https://first.cdn.net/"><base href="https://second.cdn.net/">'
                '<script src="a.js"></script>')
        resources = sup.extract_third_party_js_resources(body, SAFE_PAGE_URL, SAFE_TARGET)
        assert [r["host"] for r in resources] == ["first.cdn.net"]

    def test_script_src_control_characters_normalized_like_a_browser(self):
        body = '<script src="https://cdn.ven\ndor.net/a.js"></script>'
        resources = sup.extract_third_party_js_resources(body, SAFE_PAGE_URL, SAFE_TARGET)
        assert [r["host"] for r in resources] == ["cdn.vendor.net"]
        assert all("\n" not in r["url"] for r in resources)

    def test_credentials_in_script_src_are_not_persisted(self):
        body = '<script src="https://user:secret@cdn.vendor.net/a.js"></script>'
        resources = sup.extract_third_party_js_resources(body, SAFE_PAGE_URL, SAFE_TARGET)
        assert "secret" not in json.dumps(resources)

    def test_shared_infrastructure_is_marked_and_never_ownership(self):
        cls = sup.classify_third_party_host("customer-bucket.s3.amazonaws.com")
        assert cls["shared_infrastructure"] is True
        assert cls["category_source"] == "catalog_match"

    def test_dedicated_vendor_is_not_marked_shared(self):
        assert sup.classify_third_party_host("js.stripe.com")["shared_infrastructure"] is False

    def test_longest_catalog_suffix_wins(self):
        assert sup.classify_third_party_host("ingest.sentry.io")["matched_domain"] == "ingest.sentry.io"

    def test_private_ip_script_host_is_internal_not_third_party(self):
        cls = sup.classify_third_party_host("169.254.169.254")
        assert cls["category"] == "internal_ip_reference"
        assert cls["category_source"] == "ip_literal"

    def test_wildcard_prefix_stripped_precisely(self):
        assert sup._strip_host_wildcard("*.stripe.com") == "stripe.com"
        assert sup._strip_host_wildcard("*.*.a.com") == "*.a.com"

    def test_evidence_and_url_are_bounded(self):
        huge = "https://evil.net/" + "A" * 200_000
        resources = sup.extract_third_party_js_resources(
            f'<script src="{huge}"></script>', SAFE_PAGE_URL, SAFE_TARGET)
        assert len(resources[0]["evidence"][0]) < 2000
        assert len(resources[0]["url"]) < 2200

    def test_overlong_hostname_is_not_recorded_as_an_asset(self):
        body = f'<script src="https://{"a" * 100000}.net/x.js"></script>'
        resources, stats = sup._extract_third_party_js(body, SAFE_PAGE_URL, SAFE_TARGET)
        assert resources == []
        assert stats["malformed_hosts"] == 1

    def test_resource_count_is_capped_and_the_cap_is_recorded(self):
        body = "".join(f'<script src="https://h{i}.vendor{i}.net/a.js"></script>' for i in range(3000))
        analysis = sup.analyze_page(body, {}, SAFE_PAGE_URL, SAFE_TARGET)
        assert len(analysis["js_resources"]) == sup.DEFAULT_MAX_THIRD_PARTY_RESOURCES_PER_PAGE
        assert analysis["extraction_stats"]["truncated"] is True

    def test_truncation_is_persisted_as_its_own_finding(self, tmp_path):
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        body = "".join(f'<script src="https://h{i}.vendor{i}.net/a.js"></script>' for i in range(3000))
        sup.persist_page_findings(sup.analyze_page(body, {}, SAFE_PAGE_URL, SAFE_TARGET), SAFE_TARGET, store)
        assert any(f["type"] == "supply_chain_page_resources_truncated" for f in store.all())

    def test_internal_ip_reference_gets_its_own_finding_type(self, tmp_path):
        # It must NOT become a supply_chain_third_party_js_resource: surface_mapper.py
        # turns those into third_party_service assets, and a metadata endpoint is not
        # a supply-chain dependency.
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        body = '<script src="http://169.254.169.254/latest/meta-data/x.js"></script>'
        sup.persist_page_findings(sup.analyze_page(body, {}, SAFE_PAGE_URL, SAFE_TARGET), SAFE_TARGET, store)
        types = [f["type"] for f in store.all()]
        assert "supply_chain_internal_ip_reference" in types
        assert "supply_chain_third_party_js_resource" not in types
        assert "supply_chain_service_category" not in types


class TestDnsDelegationEvidence:
    def _resolver(self, chain_map, nxdomain=()):
        def _resolve(self, name, rtype, *a, **kw):
            if name in nxdomain:
                raise dns.resolver.NXDOMAIN()
            if name in chain_map:
                return [_FakeCnameRdata(chain_map[name] + ".")]
            raise dns.resolver.NoAnswer()
        return _resolve

    def test_attribution_is_the_delegation_target_not_the_chain_terminus(self):
        # support.example.com -> example.zendesk.com -> zendesk.map.fastly.net
        # was reported as a Fastly CDN dependency; the real relationship is Zendesk.
        chain = {"support.example.com": "example.zendesk.com",
                 "example.zendesk.com": "zendesk.map.fastly.net"}
        with mock.patch.object(dns.resolver.Resolver, "resolve", self._resolver(chain)):
            result = sup.map_subdomain_third_party_dns("support.example.com", SAFE_TARGET)
        assert result["delegation_target"] == "example.zendesk.com"
        assert result["third_party"]["vendor"] == "Zendesk"
        assert result["third_party"]["category"] == "support_chat"

    def test_full_chain_is_still_preserved_for_downstream_correlation(self):
        chain = {"support.example.com": "example.zendesk.com",
                 "example.zendesk.com": "zendesk.map.fastly.net"}
        with mock.patch.object(dns.resolver.Resolver, "resolve", self._resolver(chain)):
            result = sup.map_subdomain_third_party_dns("support.example.com", SAFE_TARGET)
        assert result["chain"] == ["example.zendesk.com", "zendesk.map.fastly.net"]
        assert result["final_target"] == "zendesk.map.fastly.net"

    def test_in_scope_intermediate_hop_is_skipped_for_attribution(self):
        chain = {"a.example.com": "b.example.com", "b.example.com": "shops.myshopify.com"}
        with mock.patch.object(dns.resolver.Resolver, "resolve", self._resolver(chain)):
            result = sup.map_subdomain_third_party_dns("a.example.com", SAFE_TARGET)
        assert result["delegation_target"] == "shops.myshopify.com"

    def test_dangling_cname_preserves_the_third_party_relationship(self):
        # Previously this became a generic "dns lookup failed", destroying both the
        # third-party relationship and the CNAME chain surface_mapper.py needs.
        chain = {"assets.example.com": "unclaimed-bucket.s3.amazonaws.com"}
        with mock.patch.object(dns.resolver.Resolver, "resolve",
                                self._resolver(chain, nxdomain={"unclaimed-bucket.s3.amazonaws.com"})):
            result = sup.map_subdomain_third_party_dns("assets.example.com", SAFE_TARGET)
        assert result["third_party"] is not None
        assert result["chain"] == ["unclaimed-bucket.s3.amazonaws.com"]
        assert result["resolution_status"] == sup.RESOLUTION_UNRESOLVED_NXDOMAIN

    def test_nxdomain_on_the_queried_host_itself_is_still_an_error(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = sup.resolve_cname_chain("sub.example.com")
        assert result["status"] == "error"
        assert result["resolution_status"] == sup.RESOLUTION_ERROR

    def test_terminus_existence_is_distinguished_from_dangling(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve",
                                self._resolver({"shop.example.com": "shops.myshopify.com"})):
            result = sup.resolve_cname_chain("shop.example.com")
        assert result["resolution_status"] == sup.RESOLUTION_TERMINUS_EXISTS

    def test_no_cname_is_distinguished_from_everything_else(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NoAnswer()):
            assert sup.resolve_cname_chain("a.example.com")["resolution_status"] == sup.RESOLUTION_NO_CNAME

    def test_truncated_chain_is_flagged_not_reported_as_complete(self):
        def _resolve(self, name, rtype, *a, **kw):
            n = int(name.split(".")[0][1:]) if name.startswith("h") else 0
            return [_FakeCnameRdata(f"h{n + 1}.chain.net.")]
        with mock.patch.object(dns.resolver.Resolver, "resolve", _resolve):
            result = sup.resolve_cname_chain("h0.example.com", max_hops=4)
        assert result["resolution_status"] == sup.RESOLUTION_TRUNCATED
        assert len(result["chain"]) == 4

    def test_cycle_is_flagged_and_terminates(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=[
            [_FakeCnameRdata("a.example.net.")], [_FakeCnameRdata("sub.example.com.")],
        ]):
            result = sup.resolve_cname_chain("sub.example.com", max_hops=20)
        assert result["resolution_status"] == sup.RESOLUTION_CYCLE

    def test_multiple_cname_targets_preserved_as_a_conflict(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=[
            [_FakeCnameRdata("one.vendor.net."), _FakeCnameRdata("two.vendor.net.")],
            dns.resolver.NoAnswer(),
        ]):
            result = sup.resolve_cname_chain("sub.example.com")
        assert result["conflicting_cname_targets"]
        assert set(result["conflicting_cname_targets"][0]["targets"]) == {"one.vendor.net", "two.vendor.net"}

    @pytest.mark.parametrize("bad", [None, 123, "", "   ", [], {}])
    def test_non_string_hostname_never_raises(self, bad):
        assert sup.resolve_cname_chain(bad)["status"] == "error"

    def test_dangling_finding_never_claims_takeover_or_claimability(self, tmp_path):
        chain = {"assets.example.com": "unclaimed-bucket.s3.amazonaws.com"}
        with mock.patch.object(dns.resolver.Resolver, "resolve",
                                self._resolver(chain, nxdomain={"unclaimed-bucket.s3.amazonaws.com"})):
            sup.run_supply_chain_analysis(subdomains=["assets.example.com"], target=SAFE_TARGET,
                                          output_dir=str(tmp_path / "output"))
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        finding = next(f for f in store.all() if f["type"] == "supply_chain_subdomain_third_party_dns")
        evidence = " ".join(finding["evidence"]).lower()
        assert "not a confirmed subdomain takeover" in evidence
        assert "claimable" in evidence
        assert finding["value"]["resolves"] is False
        assert finding["value"]["delegation_target"] == "unclaimed-bucket.s3.amazonaws.com"

    def test_shared_infrastructure_delegation_says_so_in_evidence(self, tmp_path):
        with mock.patch.object(dns.resolver.Resolver, "resolve",
                                self._resolver({"shop.example.com": "shops.myshopify.com"})):
            sup.run_supply_chain_analysis(subdomains=["shop.example.com"], target=SAFE_TARGET,
                                          output_dir=str(tmp_path / "output"))
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        finding = next(f for f in store.all() if f["type"] == "supply_chain_subdomain_third_party_dns")
        assert any("multi-tenant" in e.lower() for e in finding["evidence"])

    def test_truncated_chain_lowers_confidence(self, tmp_path):
        def _resolve(self, name, rtype, *a, **kw):
            n = int(name.split(".")[0][1:]) if name.startswith("h") else 0
            return [_FakeCnameRdata(f"h{n + 1}.vendor.net.")]
        with mock.patch.object(dns.resolver.Resolver, "resolve", _resolve):
            sup.run_supply_chain_analysis(subdomains=["h0.example.com"], target=SAFE_TARGET,
                                          output_dir=str(tmp_path / "output"))
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        finding = next(f for f in store.all() if f["type"] == "supply_chain_subdomain_third_party_dns")
        assert finding["confidence"] == sup.CONFIDENCE_MEDIUM


class TestFailureSemantics:
    def test_dns_failure_is_not_counted_as_an_analyzed_check(self, tmp_path):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.Timeout()):
            summary = sup.run_supply_chain_analysis(
                subdomains=["shop.example.com"], target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert summary["subdomains_dns_failed"] == 1
        assert summary["subdomains_analyzed"] == 0
        assert summary["subdomain_results"][0]["status"] == "dns_lookup_failed"

    def test_dns_failure_never_produces_a_negative_result(self, tmp_path):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.Timeout()):
            sup.run_supply_chain_analysis(subdomains=["shop.example.com"], target=SAFE_TARGET,
                                          output_dir=str(tmp_path / "output"))
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        types = [f["type"] for f in store.all()]
        assert "supply_chain_dns_lookup_failed" in types
        assert "supply_chain_dns_checked_no_third_party" not in types

    def test_dns_failure_finding_says_nothing_can_be_concluded(self, tmp_path):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.Timeout()):
            sup.run_supply_chain_analysis(subdomains=["shop.example.com"], target=SAFE_TARGET,
                                          output_dir=str(tmp_path / "output"))
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        finding = next(f for f in store.all() if f["type"] == "supply_chain_dns_lookup_failed")
        assert any("not evidence" in e.lower() for e in finding["evidence"])

    @pytest.mark.parametrize("exc", [UnicodeError("label too long"), ValueError("bad port"),
                                      RuntimeError("boom")])
    def test_non_request_exceptions_do_not_escape_fetch_url(self, exc):
        with mock.patch("requests.get", side_effect=exc):
            result = sup.fetch_url("https://example.com/")
        assert result["status"] == "error"
        assert result["error"]

    def test_unparseable_page_url_does_not_abort_the_run(self, tmp_path):
        resp = _fake_response(status_code=200, body=b"<html></html>")
        with mock.patch("requests.get", return_value=resp):
            summary = sup.run_supply_chain_analysis(
                pages=["http://[::1/", SAFE_PAGE_URL], target=SAFE_TARGET,
                output_dir=str(tmp_path / "output"))
        assert summary["pages_skipped_out_of_scope"] == 1
        assert summary["pages_analyzed"] == 1

    def test_make_finding_does_not_shred_a_string_into_characters(self):
        assert sup.make_finding("t", "x", "v", "abc", sup.CONFIDENCE_LOW)["evidence"] == ["abc"]

    def test_make_finding_coerces_non_string_evidence(self):
        assert sup.make_finding("t", "x", "v", [1, None], sup.CONFIDENCE_LOW)["evidence"] == ["1", "None"]


class TestPersistenceHardening:
    def test_unwritable_output_dir_raises_persistence_error(self, tmp_path):
        parent = tmp_path / "ro"
        parent.mkdir()
        os.chmod(parent, 0o500)
        try:
            with pytest.raises(sup.PersistenceError):
                sup.PendingAssetsStore(output_dir=str(parent / "sub"))
        finally:
            os.chmod(parent, 0o700)

    def test_write_oserror_becomes_a_recorded_error_not_a_crash(self, tmp_path):
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("tempfile.mkstemp", side_effect=OSError("No space left on device")):
            error = sup._safe_store_add(store, sup.make_finding("t", "x", "v", [], sup.CONFIDENCE_LOW))
        assert isinstance(error, str) and "space" in error

    def test_non_json_serializable_value_becomes_a_recorded_error(self, tmp_path):
        class Weird:
            pass
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        error = sup._safe_store_add(store, sup.make_finding("t", "x", Weird(), [], sup.CONFIDENCE_LOW))
        assert isinstance(error, str)

    def test_failed_write_leaves_the_existing_file_intact(self, tmp_path):
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        store.add(sup.make_finding("t", "x", "good", [], sup.CONFIDENCE_LOW))
        class Weird:
            pass
        sup._safe_store_add(store, sup.make_finding("t", "x", Weird(), [], sup.CONFIDENCE_LOW))
        assert [f["value"] for f in store.all()] == ["good"]

    def test_add_many_is_atomic_and_preserves_prior_records(self, tmp_path):
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        store.add_many([sup.make_finding("t", "x", i, [], sup.CONFIDENCE_LOW) for i in range(3)])
        store.add_many([sup.make_finding("t", "x", 9, [], sup.CONFIDENCE_LOW)])
        assert [f["value"] for f in store.all()] == [0, 1, 2, 9]

    def test_second_writer_on_the_same_file_does_not_clobber_the_first(self, tmp_path):
        out = str(tmp_path / "output")
        a, b = sup.PendingAssetsStore(output_dir=out), sup.PendingAssetsStore(output_dir=out)
        a.add(sup.make_finding("t", "x", "A", [], sup.CONFIDENCE_LOW))
        b.add(sup.make_finding("t", "x", "B", [], sup.CONFIDENCE_LOW))
        a.add(sup.make_finding("t", "x", "C", [], sup.CONFIDENCE_LOW))
        assert [f["value"] for f in a.all()] == ["A", "B", "C"]

    def test_other_modules_records_are_preserved(self, tmp_path):
        out = tmp_path / "output"
        out.mkdir()
        (out / "pending_assets.json").write_text(json.dumps([{"type": "prior", "source": "other.py"}]))
        store = sup.PendingAssetsStore(output_dir=str(out))
        store.add(sup.make_finding("t", "x", "new", [], sup.CONFIDENCE_LOW))
        records = store.all()
        assert records[0]["source"] == "other.py" and len(records) == 2

    def test_persistence_errors_from_every_path_reach_the_summary(self, tmp_path):
        out = tmp_path / "output"
        out.mkdir()
        (out / "pending_assets.json").write_text("not json")
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.Timeout()):
            summary = sup.run_supply_chain_analysis(
                pages=["https://evil.com/"], subdomains=["shop.example.com"],
                target=SAFE_TARGET, output_dir=str(out))
        assert len(summary["errors"]) >= 2


class TestResourceSafety:
    def test_persisting_many_findings_is_not_quadratic(self, tmp_path):
        import time
        body = "".join(f'<script src="https://h{i}.v{i}.net/a.js"></script>' for i in range(400))
        analysis = sup.analyze_page(body, {}, SAFE_PAGE_URL, SAFE_TARGET)
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        started = time.time()
        sup.persist_page_findings(analysis, SAFE_TARGET, store)
        assert time.time() - started < 3.0
        assert len(store.all()) > 400

    def test_trust_map_with_many_hosts_on_one_page(self):
        import time
        resources = [{"url": f"https://h{i}.x.net/a.js", "host": f"h{i}.x.net",
                      "source_page": SAFE_PAGE_URL,
                      "classification": sup.classify_third_party_host(f"h{i}.x.net"),
                      "evidence": ["e"]} for i in range(5000)]
        started = time.time()
        trust_map = sup.build_trust_map(resources, {}, [])
        assert time.time() - started < 5.0
        assert trust_map["external_service_count"] == 5000

    def test_duplicate_pages_are_fetched_once(self, tmp_path):
        resp = _fake_response(status_code=200, body=b"<html></html>")
        with mock.patch("requests.get", return_value=resp) as mock_get:
            summary = sup.run_supply_chain_analysis(
                pages=[SAFE_PAGE_URL] * 50, target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert mock_get.call_count == 1
        assert summary["pages_skipped_duplicate"] == 49

    def test_duplicate_subdomains_are_resolved_once(self, tmp_path):
        with mock.patch.object(dns.resolver.Resolver, "resolve",
                                side_effect=dns.resolver.NoAnswer()) as mock_resolve:
            sup.run_supply_chain_analysis(subdomains=["shop.example.com"] * 20, target=SAFE_TARGET,
                                          output_dir=str(tmp_path / "output"))
        assert mock_resolve.call_count == 1

    def test_pages_converging_on_one_canonical_url_are_analyzed_once(self, tmp_path):
        resp = _fake_response(status_code=200,
                              body=b'<script src="https://a.b.net/x.js"></script>',
                              final_url="https://example.com/canonical")
        with mock.patch("requests.get", return_value=resp):
            summary = sup.run_supply_chain_analysis(
                pages=["https://example.com/a", "https://example.com/b"],
                target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert summary["pages_analyzed"] == 1
        assert summary["pages_skipped_duplicate_final_url"] == 1

    def test_huge_body_is_parsed_once_per_page(self):
        with mock.patch.object(sup, "_parse_html", wraps=sup._parse_html) as spy:
            sup.analyze_page("<html><script src='https://a.b.net/x.js'></script></html>",
                             {}, SAFE_PAGE_URL, SAFE_TARGET)
        assert spy.call_count == 1

    def test_deeply_nested_html_does_not_crash(self):
        body = "<div>" * 5000 + '<script src="https://a.b.net/x.js"></script>' + "</div>" * 5000
        assert sup.extract_third_party_js_resources(body, SAFE_PAGE_URL, SAFE_TARGET)


class TestHostileInputToPublicHelpers:
    @pytest.mark.parametrize("csp_by_page", [
        {"p": "not-a-dict"}, {"p": None}, {"p": {"present": True, "directives": "bad"}}, None,
    ])
    def test_build_trust_map_tolerates_malformed_csp_input(self, csp_by_page):
        assert sup.build_trust_map([], csp_by_page, []) ["external_service_count"] == 0

    @pytest.mark.parametrize("js_resources", [
        [{"host": "a.com"}], [{"source_page": "p"}], [None], ["string"], None,
    ])
    def test_build_trust_map_tolerates_malformed_resource_input(self, js_resources):
        assert sup.build_trust_map(js_resources, {}, [])["external_service_count"] == 0

    @pytest.mark.parametrize("dns_rels", [[{"third_party": None}], [{"subdomain": "s"}], [None], None])
    def test_build_trust_map_tolerates_malformed_dns_input(self, dns_rels):
        assert sup.build_trust_map([], {}, dns_rels)["external_service_count"] == 0

    @pytest.mark.parametrize("csp", [
        "not-a-dict", None, {"present": True, "directives": "bad"},
        {"present": False, "report_only_present": True, "report_only": None},
    ])
    def test_assess_csp_risk_implications_tolerates_malformed_input(self, csp):
        assert isinstance(sup.assess_csp_risk_implications(SAFE_PAGE_URL, csp, set()), list)

    @pytest.mark.parametrize("trust_map", ["nope", None, {}, {"external_services": "bad"}])
    def test_build_category_inventory_tolerates_malformed_input(self, trust_map):
        assert sup.build_category_inventory(trust_map) == {}

    @pytest.mark.parametrize("headers", [None, "nope", 123, []])
    def test_analyze_csp_tolerates_malformed_headers(self, headers):
        assert sup.analyze_csp(headers, "", SAFE_TARGET)["present"] is False

    def test_unicode_and_idn_hosts_do_not_crash_classification(self):
        for host in ["münchen.de", "xn--mnchen-3ya.de", "例え.テスト", "a..b.com", "-.-", ""]:
            assert isinstance(sup.classify_third_party_host(host), dict)


class TestEvidenceAndConfidenceIntegrity:
    def test_repeated_reference_does_not_inflate_category_confidence(self, tmp_path):
        # The category of a host is a property of the host, not of each page.
        def _fetch(url, **kwargs):
            return {"status": "found", "status_code": 200,
                    "headers": {"Content-Type": "text/html"},
                    "body": '<script src="https://js.stripe.com/v3"></script>',
                    "final_url": url, "hops": [], "body_truncated": False,
                    "elapsed_seconds": 0.0, "error": None}
        with mock.patch.object(sup, "fetch_page", _fetch):
            sup.run_supply_chain_analysis(
                pages=[f"https://example.com/p{i}" for i in range(20)],
                target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        categories = [f for f in store.all() if f["type"] == "supply_chain_service_category"]
        assert len(categories) == 1
        assert categories[0]["confidence"] == sup.CONFIDENCE_MEDIUM

    def test_heuristic_category_stays_low_confidence(self, tmp_path):
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        analysis = sup.analyze_page(
            '<script src="https://cdn.unknown-vendor.io/a.js"></script>', {}, SAFE_PAGE_URL, SAFE_TARGET)
        sup.persist_page_findings(analysis, SAFE_TARGET, store)
        finding = next(f for f in store.all() if f["type"] == "supply_chain_service_category")
        assert finding["confidence"] == sup.CONFIDENCE_LOW

    def test_wildcard_only_service_is_marked_as_inferred(self):
        csp = sup.analyze_csp({"Content-Security-Policy": "script-src *.vendor.com"}, "", SAFE_TARGET)
        trust_map = sup.build_trust_map([], {SAFE_PAGE_URL: csp}, [])
        assert trust_map["external_services"]["vendor.com"]["attribution"] == \
            "inferred_from_wildcard_allowlist"

    def test_observed_reference_is_marked_as_observed(self):
        resources = sup.extract_third_party_js_resources(
            '<script src="https://js.stripe.com/v3"></script>', SAFE_PAGE_URL, SAFE_TARGET)
        trust_map = sup.build_trust_map(resources, {}, [])
        assert trust_map["external_services"]["js.stripe.com"]["attribution"] == "observed_reference"

    def test_wildcard_allowance_does_not_inflate_the_third_party_surface(self):
        csp = sup.analyze_csp({"Content-Security-Policy": "script-src *.stripe.com"}, "", SAFE_TARGET)
        resources = sup.extract_third_party_js_resources(
            '<script src="https://js.stripe.com/v3"></script>', SAFE_PAGE_URL, SAFE_TARGET)
        trust_map = sup.build_trust_map(resources, {SAFE_PAGE_URL: csp}, [])
        inventory = sup.build_category_inventory(trust_map)
        risks = sup.assess_aggregate_risk_implications(trust_map, inventory)
        payment = [r for r in risks if r["risk_type"].endswith(":payment")]
        assert payment and payment[0]["related_hosts"] == ["js.stripe.com"]

    def test_conflicting_classifications_are_preserved(self):
        resources = [{"url": "https://h.example.net/a.js", "host": "h.example.net",
                      "source_page": SAFE_PAGE_URL, "evidence": ["e"],
                      "classification": {"vendor": "A", "category": "payment",
                                          "category_source": "catalog_match"}},
                     {"url": "https://h.example.net/b.js", "host": "h.example.net",
                      "source_page": "https://example.com/other", "evidence": ["e"],
                      "classification": {"vendor": "B", "category": "analytics",
                                          "category_source": "catalog_match"}}]
        entry = sup.build_trust_map(resources, {}, [])["external_services"]["h.example.net"]
        assert entry["conflicting_classifications"]

    def test_aggregate_implications_are_deterministically_ordered(self):
        resources = [{"url": f"https://{h}/a.js", "host": h, "source_page": SAFE_PAGE_URL,
                      "classification": sup.classify_third_party_host(h), "evidence": ["e"]}
                     for h in ("js.stripe.com", "mytenant.auth0.com")]
        trust_map = sup.build_trust_map(resources, {}, [])
        inventory = sup.build_category_inventory(trust_map)
        orders = {tuple(r["risk_type"] for r in
                        sup.assess_aggregate_risk_implications(trust_map, inventory)) for _ in range(20)}
        assert len(orders) == 1

    def test_no_finding_this_module_emits_claims_a_confirmed_vulnerability(self, tmp_path):
        def _fetch(url, **kwargs):
            return {"status": "found", "status_code": 200,
                    "headers": {"Content-Type": "text/html",
                                "Content-Security-Policy": "script-src * 'unsafe-inline'"},
                    "body": '<script src="https://js.stripe.com/v3"></script>',
                    "final_url": url, "hops": [], "body_truncated": False,
                    "elapsed_seconds": 0.0, "error": None}
        with mock.patch.object(sup, "fetch_page", _fetch):
            sup.run_supply_chain_analysis(pages=[SAFE_PAGE_URL], target=SAFE_TARGET,
                                          output_dir=str(tmp_path / "output"))
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        for finding in store.all():
            blob = json.dumps(finding).lower()
            assert "confirmed vulnerability" not in blob or "not a confirmed vulnerability" in blob
            assert "exploitable" not in blob

    def test_every_persisted_finding_keeps_full_provenance(self, tmp_path):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=[
            [_FakeCnameRdata("shops.myshopify.com.")], dns.resolver.NoAnswer(),
        ]):
            sup.run_supply_chain_analysis(subdomains=["shop.example.com"], target=SAFE_TARGET,
                                          output_dir=str(tmp_path / "output"))
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert store.all()
        for finding in store.all():
            assert finding["source"] == "supply_chain.py"
            assert finding["timestamp"]
            assert finding["confidence"] in (sup.CONFIDENCE_LOW, sup.CONFIDENCE_MEDIUM, sup.CONFIDENCE_HIGH)
            assert finding["metadata"]["source_asset"]
            assert finding["metadata"]["discovery_source"] in (
                "script_tag", "csp_header", "dns_cname", "aggregate_analysis")
            assert finding["evidence"]


class TestDownstreamContract:
    """The finding shapes surface_mapper.py/risk_engine.py actually read."""

    def _run(self, tmp_path):
        page = ('<html><head><base href="https://cdn.thirdparty.net/">'
                '<meta http-equiv="Content-Security-Policy" content="script-src *.stripe.com">'
                '</head><body>'
                '<script src="https://js.stripe.com/v3"></script>'
                '<script src="app.js"></script>'
                '<script src="http://169.254.169.254/x.js"></script>'
                '</body></html>')

        def _fetch(url, **kwargs):
            return {"status": "found", "status_code": 200,
                    "headers": {"Content-Type": "text/html"}, "body": page,
                    "final_url": url, "hops": [], "body_truncated": False,
                    "elapsed_seconds": 0.0, "error": None}

        chain = {"shop.example.com": "shops.myshopify.com"}
        def _resolve(self, name, rtype, *a, **kw):
            if name in chain:
                return [_FakeCnameRdata(chain[name] + ".")]
            raise dns.resolver.NoAnswer()

        with mock.patch.object(sup, "fetch_page", _fetch), \
             mock.patch.object(dns.resolver.Resolver, "resolve", _resolve):
            summary = sup.run_supply_chain_analysis(
                pages=[SAFE_PAGE_URL], subdomains=["shop.example.com"],
                target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        store = sup.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        return summary, store.all()

    def test_js_resource_findings_keep_the_keys_surface_mapper_reads(self, tmp_path):
        _, findings = self._run(tmp_path)
        for finding in [f for f in findings if f["type"] == "supply_chain_third_party_js_resource"]:
            assert finding["value"]["host"]
            assert isinstance(finding["value"]["classification"], dict)
            assert finding["value"]["classification"]["category"]
            assert finding["metadata"]["source_asset"]

    def test_dns_findings_keep_the_keys_surface_mapper_reads(self, tmp_path):
        _, findings = self._run(tmp_path)
        finding = next(f for f in findings if f["type"] == "supply_chain_subdomain_third_party_dns")
        assert finding["value"]["subdomain"] == "shop.example.com"
        assert finding["value"]["cname_chain"] == ["shops.myshopify.com"]
        assert isinstance(finding["value"]["third_party"], dict)
        assert finding["value"]["third_party"]["category"] == "ecommerce_platform"

    def test_internal_address_never_reaches_the_third_party_finding_type(self, tmp_path):
        _, findings = self._run(tmp_path)
        hosts = [f["value"]["host"] for f in findings
                 if f["type"] == "supply_chain_third_party_js_resource"]
        assert "169.254.169.254" not in hosts

    def test_base_href_dependency_reaches_downstream(self, tmp_path):
        _, findings = self._run(tmp_path)
        hosts = {f["value"]["host"] for f in findings
                 if f["type"] == "supply_chain_third_party_js_resource"}
        assert "cdn.thirdparty.net" in hosts

    def test_all_persisted_output_is_json_safe_and_credential_free(self, tmp_path):
        summary, findings = self._run(tmp_path)
        blob = json.dumps({"summary": summary, "findings": findings})
        assert json.loads(blob)
        assert "hunter2" not in blob and "password@" not in blob

    def test_summary_shape_is_stable_for_the_orchestrator(self, tmp_path):
        summary, _ = self._run(tmp_path)
        for key in ("module", "target", "started_at", "finished_at", "pages_requested",
                    "pages_analyzed", "pages_failed", "pages_skipped_out_of_scope",
                    "subdomains_requested", "subdomains_analyzed", "subdomains_dns_failed",
                    "trust_map", "category_inventory", "risk_implications", "errors"):
            assert key in summary, key
        assert summary["module"] == "supply_chain.py"


class TestCredentialRedaction:
    """No credential may reach pending_assets.json (CLAUDE.md rule 16)."""

    def test_credentials_in_a_csp_policy_are_redacted(self):
        result = sup.analyze_csp(
            {"Content-Security-Policy": "script-src https://user:pw@vendor.example/"}, "", SAFE_TARGET)
        assert "pw@" not in json.dumps(result)
        assert "redacted@" in result["raw_header"]

    def test_credentials_in_a_meta_csp_are_redacted(self):
        body = ('<meta http-equiv="Content-Security-Policy" '
                'content="script-src https://user:pw@vendor.example/">')
        analysis = sup.analyze_page(body, {}, SAFE_PAGE_URL, SAFE_TARGET)
        assert "pw@" not in json.dumps(analysis)

    def test_credentials_in_a_script_src_are_redacted_in_url_and_evidence(self):
        resources = sup.extract_third_party_js_resources(
            '<script src="https://user:pw@cdn.vendor.net/a.js"></script>', SAFE_PAGE_URL, SAFE_TARGET)
        assert "pw@" not in json.dumps(resources)
        assert resources[0]["host"] == "cdn.vendor.net"

    def test_credentials_in_a_base_href_are_redacted(self):
        body = '<base href="https://user:pw@cdn.vendor.net/"><script src="a.js"></script>'
        analysis = sup.analyze_page(body, {}, SAFE_PAGE_URL, SAFE_TARGET)
        assert "pw@" not in json.dumps(analysis)

    def test_redaction_preserves_the_host(self):
        assert sup._redact_credentials("see https://u:p@vendor.example/x") == \
            "see https://redacted@vendor.example/x"

    def test_redaction_does_not_hide_the_third_party_host_it_protects(self):
        # A bracketed redaction marker made urlsplit read the authority as an
        # IPv6 literal and raise, silently dropping the allow-listed host.
        result = sup.analyze_csp(
            {"Content-Security-Policy": "script-src https://user:pw@vendor.example/"}, "", SAFE_TARGET)
        assert result["third_party_domains_referenced"] == ["vendor.example"]
        assert "pw@" not in json.dumps(result)

    def test_redacted_policy_still_reaches_the_trust_map(self):
        csp = sup.analyze_csp(
            {"Content-Security-Policy": "script-src https://user:pw@vendor.example/"}, "", SAFE_TARGET)
        trust_map = sup.build_trust_map([], {SAFE_PAGE_URL: csp}, [])
        assert "vendor.example" in trust_map["external_services"]
        assert "pw@" not in json.dumps(trust_map)

    def test_redaction_leaves_ordinary_text_alone(self):
        for text in ["no credentials here", "a@b.com", "script-src 'self'", ""]:
            assert sup._redact_credentials(text) == text

    def test_credentials_never_survive_a_full_run(self, tmp_path):
        def _fetch(url, **kwargs):
            return {"status": "found", "status_code": 200,
                    "headers": {"Content-Type": "text/html",
                                "Content-Security-Policy": "script-src https://u:pw@a.vendor.net/"},
                    "body": '<script src="https://u:pw@b.vendor.net/x.js"></script>',
                    "final_url": url, "hops": [], "body_truncated": False,
                    "elapsed_seconds": 0.0, "error": None}
        with mock.patch.object(sup, "fetch_page", _fetch):
            summary = sup.run_supply_chain_analysis(
                pages=["https://u:pw@example.com/"], target=SAFE_TARGET,
                output_dir=str(tmp_path / "output"))
        persisted = (tmp_path / "output" / "pending_assets.json").read_text()
        assert "pw@" not in persisted
        assert "pw@" not in json.dumps(summary)


class TestPublicHelperTypeSafety:
    """Fuzz-derived: no public helper may raise on hostile input."""

    HOSTILE = [None, "", "   ", 0, 1, True, [], {}, 1.5, b"bytes", "a" * 5000, "\x00", "://", "*" * 50]

    @pytest.mark.parametrize("value", HOSTILE)
    def test_scope_helpers_never_raise(self, value):
        sup._idna_normalize(value)
        sup._unbracket(value)
        sup._strip_host_wildcard(value)
        sup._strip_userinfo(value)
        sup._clip(value)
        sup.classify_third_party_host(value)

    @pytest.mark.parametrize("value", HOSTILE)
    def test_csp_helpers_never_raise(self, value):
        assert isinstance(sup.parse_csp_header(value, SAFE_TARGET), dict)
        assert isinstance(sup.parse_csp_header("script-src https://a.com", value), dict)
        assert isinstance(sup.analyze_csp({"Content-Security-Policy": value}, value, SAFE_TARGET), dict)

    @pytest.mark.parametrize("value", HOSTILE)
    def test_correlation_helpers_never_raise(self, value):
        assert isinstance(sup.build_trust_map(value, value, value), dict)
        assert isinstance(sup.build_category_inventory(value), dict)
        assert isinstance(sup.assess_csp_risk_implications("u", value, value), list)
        assert isinstance(sup.assess_aggregate_risk_implications(value, value), list)

    @pytest.mark.parametrize("value", HOSTILE)
    def test_validators_only_raise_scope_error(self, value):
        for fn in (sup.validate_url_target, sup.validate_hostname_target):
            try:
                fn(value, SAFE_TARGET)
            except sup.ScopeError:
                pass

    def test_bs4_url_like_body_warning_is_not_emitted(self, recwarn):
        sup.analyze_page("https://example.com/looks-like-a-url", {}, SAFE_PAGE_URL, SAFE_TARGET)
        assert not [w for w in recwarn if "MarkupResemblesLocator" in type(w.message).__name__]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
