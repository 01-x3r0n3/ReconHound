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


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
