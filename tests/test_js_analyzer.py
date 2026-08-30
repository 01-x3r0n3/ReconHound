"""
Tests for reconhound/js_analyzer.py (ReconHound Module 13, per context.md's
build order — catalog item 13).

Run with:  ./.venv/bin/python -m pytest tests/test_js_analyzer.py -v

All tests mock the `requests.get` boundary so the suite is deterministic
and offline-safe; no external network access is required or performed
anywhere in this file.
"""

import json
import os
import sys
from unittest import mock

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import js_analyzer as js
from reconhound import endpoint_discovery as ed


SAFE_JS_URL = "https://example.com/static/app.js"
SAFE_TARGET = "example.com"


def _fake_response(status_code=200, headers=None, body=b"", final_url=None):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = dict(headers or {})
    resp.encoding = "utf-8"
    resp.content = body
    resp.url = final_url or SAFE_JS_URL
    resp.elapsed.total_seconds.return_value = 0.05
    resp.raw.read.return_value = body
    return resp


# ---------------------------------------------------------------------------
# validate_url_target / scope helpers
# ---------------------------------------------------------------------------

class TestValidateUrlTarget:
    def test_accepts_https_url(self):
        assert js.validate_url_target(SAFE_JS_URL) == SAFE_JS_URL

    def test_accepts_in_scope_subdomain(self):
        assert js.validate_url_target("https://cdn.example.com/app.js", target="example.com")

    def test_rejects_out_of_scope_host(self):
        with pytest.raises(js.ScopeError):
            js.validate_url_target("https://evil.com/app.js", target="example.com")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(js.ScopeError):
            js.validate_url_target("ftp://example.com/app.js")

    def test_rejects_missing_hostname(self):
        with pytest.raises(js.ScopeError):
            js.validate_url_target("https:///app.js")

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(js.ScopeError):
            js.validate_url_target(bad)

    def test_allows_ip_literal_host_without_scope_check(self):
        assert js.validate_url_target("http://93.184.216.34/app.js", target="example.com")


class TestScopeHelpers:
    @pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "0.0.0.0"])
    def test_disallowed_redirect_ips(self, ip):
        assert js._is_disallowed_redirect_ip(ip) is True

    def test_public_ip_allowed(self):
        assert js._is_disallowed_redirect_ip("93.184.216.34") is False

    def test_non_ip_host_not_disallowed(self):
        assert js._is_disallowed_redirect_ip("example.com") is False

    def test_in_scope_host_subdomain(self):
        assert js._in_scope_host("api.example.com", "example.com") is True

    def test_in_scope_host_exact(self):
        assert js._in_scope_host("example.com", "example.com") is True

    def test_in_scope_host_rejects_unrelated(self):
        assert js._in_scope_host("evilexample.com", "example.com") is False

    def test_in_scope_host_empty_inputs(self):
        assert js._in_scope_host("", "example.com") is False
        assert js._in_scope_host("example.com", "") is False


# ---------------------------------------------------------------------------
# make_finding / make_js_finding / PendingAssetsStore
# ---------------------------------------------------------------------------

class TestFindingsAndStore:
    def test_finding_structure_and_source(self):
        finding = js.make_finding("javascript_file_analyzed", SAFE_JS_URL, {"a": 1}, ["e"], js.CONFIDENCE_HIGH)
        assert finding["source"] == "js_analyzer.py"
        json.dumps(finding)

    def test_make_js_finding_preserves_relationship_to_originating_file(self):
        finding = js.make_js_finding(
            "js_analyzer_endpoint_reference", SAFE_TARGET, {"url": "x"}, ["e"], js.CONFIDENCE_MEDIUM,
            parent_js_url=SAFE_JS_URL, source_page="https://example.com/",
        )
        assert finding["metadata"]["parent_js_url"] == SAFE_JS_URL
        assert finding["metadata"]["source_page"] == "https://example.com/"
        assert finding["metadata"]["derived_from_source_map"] is False
        assert finding["metadata"]["original_source_file"] is None
        json.dumps(finding)

    def test_make_js_finding_source_map_provenance(self):
        finding = js.make_js_finding(
            "js_analyzer_endpoint_reference", SAFE_TARGET, {}, [], js.CONFIDENCE_LOW,
            parent_js_url=SAFE_JS_URL, derived_from_source_map=True, original_source_file="webpack:///src/app.js",
        )
        assert finding["metadata"]["derived_from_source_map"] is True
        assert finding["metadata"]["original_source_file"] == "webpack:///src/app.js"

    def test_store_preserves_prior_data(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{"type": "dns_record", "source": "passive_recon.py"}]
        pending.write_text(json.dumps(pre_existing))

        store = js.PendingAssetsStore(output_dir=str(output_dir))
        store.add(js.make_finding("javascript_file_analyzed", SAFE_JS_URL, {}, ["e"], js.CONFIDENCE_HIGH))
        assert store.all() == pre_existing + [store.all()[-1]]

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = js.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(js.PersistenceError):
            store.add(js.make_finding("javascript_file_analyzed", SAFE_JS_URL, {}, ["e"], js.CONFIDENCE_HIGH))

    def test_safe_store_add_returns_none_for_none_store(self):
        assert js._safe_store_add(None, js.make_finding("x", SAFE_JS_URL, {}, [], js.CONFIDENCE_LOW)) is None

    def test_safe_store_add_returns_error_on_persistence_failure(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("not json")
        store = js.PendingAssetsStore(output_dir=str(output_dir))
        err = js._safe_store_add(store, js.make_finding("x", SAFE_JS_URL, {}, [], js.CONFIDENCE_LOW))
        assert err is not None


# ---------------------------------------------------------------------------
# fetch_url
# ---------------------------------------------------------------------------

class TestFetchUrl:
    def test_successful_fetch(self):
        resp = _fake_response(status_code=200, headers={"Content-Type": "application/javascript"}, body=b"console.log(1);")
        with mock.patch("requests.get", return_value=resp):
            result = js.fetch_url(SAFE_JS_URL)
        assert result["status"] == "found"
        assert result["body"] == "console.log(1);"

    def test_body_truncated_when_over_limit(self):
        resp = _fake_response(body=b"x" * 100)
        with mock.patch("requests.get", return_value=resp):
            result = js.fetch_url(SAFE_JS_URL, max_body_bytes=10)
        assert result["body_truncated"] is True
        assert len(result["body"]) == 10

    def test_timeout_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout("t")):
            result = js.fetch_url(SAFE_JS_URL)
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_connection_error_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = js.fetch_url(SAFE_JS_URL)
        assert result["status"] == "error"

    def test_generic_request_exception_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.RequestException("boom")):
            result = js.fetch_url(SAFE_JS_URL)
        assert result["status"] == "error"

    def test_empty_body(self):
        resp = _fake_response(status_code=200, body=b"")
        with mock.patch("requests.get", return_value=resp):
            result = js.fetch_url(SAFE_JS_URL)
        assert result["status"] == "found"
        assert result["body"] == ""

    def test_json_serializable(self):
        resp = _fake_response(headers={"X-Test": "1"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            result = js.fetch_url(SAFE_JS_URL)
        json.dumps(result)


# ---------------------------------------------------------------------------
# 1. fetch_javascript_file (acquisition + redirect handling)
# ---------------------------------------------------------------------------

class TestFetchJavascriptFile:
    def test_direct_success(self):
        resp = _fake_response(status_code=200, body=b"console.log('hi');")
        with mock.patch("requests.get", return_value=resp):
            result = js.fetch_javascript_file(SAFE_JS_URL, target=SAFE_TARGET)
        assert result["status"] == "found"
        assert result["body"] == "console.log('hi');"
        assert len(result["hops"]) == 1

    def test_follows_in_scope_redirect(self):
        redirect = _fake_response(status_code=302, headers={"Location": "https://cdn.example.com/app.js"})
        final = _fake_response(status_code=200, body=b"final content")
        with mock.patch("requests.get", side_effect=[redirect, final]):
            result = js.fetch_javascript_file(SAFE_JS_URL, target=SAFE_TARGET)
        assert result["status"] == "found"
        assert result["body"] == "final content"
        assert len(result["hops"]) == 2

    def test_blocks_out_of_scope_redirect(self):
        redirect = _fake_response(status_code=302, headers={"Location": "https://evil.com/payload.js"})
        with mock.patch("requests.get", return_value=redirect):
            result = js.fetch_javascript_file(SAFE_JS_URL, target=SAFE_TARGET)
        assert result["status"] == "error"
        assert "out of scope" in result["error"]

    def test_blocks_private_ip_redirect_ssrf_safeguard(self):
        redirect = _fake_response(status_code=302, headers={"Location": "http://169.254.169.254/latest/meta-data"})
        with mock.patch("requests.get", return_value=redirect):
            result = js.fetch_javascript_file(SAFE_JS_URL, target=SAFE_TARGET)
        assert result["status"] == "error"
        assert "SSRF" in result["error"] or "private" in result["error"].lower()

    def test_redirect_without_location_header(self):
        redirect = _fake_response(status_code=302, headers={})
        with mock.patch("requests.get", return_value=redirect):
            result = js.fetch_javascript_file(SAFE_JS_URL, target=SAFE_TARGET)
        assert result["status"] == "error"
        assert "Location" in result["error"]

    def test_max_redirect_hops_exceeded(self):
        redirect = _fake_response(status_code=302, headers={"Location": SAFE_JS_URL})
        with mock.patch("requests.get", return_value=redirect):
            result = js.fetch_javascript_file(SAFE_JS_URL, target=SAFE_TARGET, max_redirect_hops=3)
        assert result["status"] == "error"
        assert "max_redirect_hops" in result["error"]
        assert len(result["hops"]) == 3

    def test_network_failure_propagated(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = js.fetch_javascript_file(SAFE_JS_URL, target=SAFE_TARGET)
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# 2a. extract_api_references
# ---------------------------------------------------------------------------

class TestExtractApiReferences:
    def test_absolute_in_scope_api_url(self):
        body = 'const x = "https://example.com/api/v1/users";'
        refs = js.extract_api_references(body, SAFE_JS_URL, target=SAFE_TARGET)
        assert any(r["url"] == "https://example.com/api/v1/users" and r["kind"] == "api_endpoint" for r in refs)

    def test_absolute_in_scope_non_api_url_is_internal_route(self):
        body = 'const x = "https://example.com/dashboard/settings";'
        refs = js.extract_api_references(body, SAFE_JS_URL, target=SAFE_TARGET)
        assert any(r["kind"] == "internal_route" for r in refs)

    def test_out_of_scope_absolute_url_excluded(self):
        body = 'const x = "https://evil.com/api/v1/steal";'
        refs = js.extract_api_references(body, SAFE_JS_URL, target=SAFE_TARGET)
        assert refs == []

    def test_fetch_call_relative_path(self):
        body = 'fetch("/api/v2/orders?limit=10").then(r => r.json());'
        refs = js.extract_api_references(body, SAFE_JS_URL, target=SAFE_TARGET)
        assert any(r["url"] == "https://example.com/api/v2/orders?limit=10" for r in refs)

    def test_axios_call_target(self):
        body = 'axios.post("/api/v1/login", data);'
        refs = js.extract_api_references(body, SAFE_JS_URL, target=SAFE_TARGET)
        assert any("api/v1/login" in r["url"] for r in refs)

    def test_relative_api_shaped_literal_without_call(self):
        body = 'const ROUTE = "/graphql/query";'
        refs = js.extract_api_references(body, SAFE_JS_URL, target=SAFE_TARGET)
        assert any("graphql" in r["url"] for r in refs)

    def test_dedup_and_evidence_merge_across_mechanisms(self):
        body = 'const x = "https://example.com/api/v1/users"; fetch("https://example.com/api/v1/users");'
        refs = js.extract_api_references(body, SAFE_JS_URL, target=SAFE_TARGET)
        matching = [r for r in refs if r["url"] == "https://example.com/api/v1/users"]
        assert len(matching) == 1
        # the literal URL text matches _ABS_URL_RE twice (the const assignment, and
        # again inside the fetch() call's own string literal) plus once via _JS_CALL_RE.
        assert len(matching[0]["evidence"]) == 3

    def test_no_target_uses_js_url_hostname_as_implicit_scope(self):
        body = 'fetch("/api/v1/ping");'
        refs = js.extract_api_references(body, SAFE_JS_URL, target=None)
        assert any("api/v1/ping" in r["url"] for r in refs)

    def test_empty_body(self):
        assert js.extract_api_references("", SAFE_JS_URL, target=SAFE_TARGET) == []

    def test_none_body(self):
        assert js.extract_api_references(None, SAFE_JS_URL, target=SAFE_TARGET) == []

    def test_data_uri_call_target_ignored(self):
        body = 'fetch("data:text/plain;base64,SGVsbG8=");'
        assert js.extract_api_references(body, SAFE_JS_URL, target=SAFE_TARGET) == []

    def test_results_sorted_by_url(self):
        body = 'fetch("/api/zzz"); fetch("/api/aaa");'
        refs = js.extract_api_references(body, SAFE_JS_URL, target=SAFE_TARGET)
        urls = [r["url"] for r in refs]
        assert urls == sorted(urls)


# ---------------------------------------------------------------------------
# 2b. extract_external_service_references
# ---------------------------------------------------------------------------

class TestExtractExternalServiceReferences:
    def test_known_vendor_matched(self):
        body = 'ga("send", "pageview"); var s = "https://www.google-analytics.com/collect";'
        result = js.extract_external_service_references(body, SAFE_JS_URL, target=SAFE_TARGET)
        assert any(r["vendor"] == "Google Analytics" for r in result)

    def test_stripe_matched(self):
        body = '<script src="https://js.stripe.com/v3/"></script>'
        result = js.extract_external_service_references(body, SAFE_JS_URL, target=SAFE_TARGET)
        assert any(r["vendor"] == "Stripe" for r in result)

    def test_in_scope_url_never_treated_as_external(self):
        body = 'const x = "https://example.com/api/v1/users";'
        assert js.extract_external_service_references(body, SAFE_JS_URL, target=SAFE_TARGET) == []

    def test_unknown_external_domain_not_matched(self):
        body = 'const x = "https://some-random-unknown-domain.example.org/thing";'
        assert js.extract_external_service_references(body, SAFE_JS_URL, target=SAFE_TARGET) == []

    def test_never_fetches_anything(self):
        body = 'const x = "https://js.stripe.com/v3/";'
        with mock.patch("requests.get") as mocked:
            js.extract_external_service_references(body, SAFE_JS_URL, target=SAFE_TARGET)
        mocked.assert_not_called()

    def test_empty_body(self):
        assert js.extract_external_service_references("", SAFE_JS_URL, target=SAFE_TARGET) == []


# ---------------------------------------------------------------------------
# 2c. extract_config_values
# ---------------------------------------------------------------------------

class TestExtractConfigValues:
    def test_api_base_url(self):
        body = 'const config = { apiBaseUrl: "https://api.example.com/v2" };'
        result = js.extract_config_values(body)
        assert any(c["key"] == "api_base_url" for c in result)

    def test_environment(self):
        body = 'window.ENV = "production";'
        result = js.extract_config_values(body)
        assert any(c["key"] == "environment" and "production" in c["value"] for c in result)

    def test_stripe_publishable_key(self):
        body = 'const stripe = Stripe("pk_live_51H8xyzABCDEFGHIJKLMNOP");'
        result = js.extract_config_values(body)
        assert any(c["key"] == "stripe_publishable_key" for c in result)

    def test_sentry_dsn(self):
        body = 'Sentry.init({dsn: "https://' + ("a" * 32) + '@o12345.ingest.sentry.io/6789"});'
        result = js.extract_config_values(body)
        assert any(c["key"] == "sentry_dsn" for c in result)

    def test_no_match(self):
        assert js.extract_config_values("console.log('nothing here');") == []

    def test_empty_body(self):
        assert js.extract_config_values("") == []


# ---------------------------------------------------------------------------
# 2d. extract_secret_indicators
# ---------------------------------------------------------------------------

class TestExtractSecretIndicators:
    def test_aws_access_key_detected(self):
        body = 'const key = "AKIAABCDEFGHIJKLMNOP";'
        result = js.extract_secret_indicators(body)
        assert any(s["pattern_name"] == "aws_access_key_id" for s in result)

    def test_raw_value_never_returned(self):
        body = 'const key = "AKIAABCDEFGHIJKLMNOP";'
        result = js.extract_secret_indicators(body)
        blob = json.dumps(result)
        assert "AKIAABCDEFGHIJKLMNOP" not in blob

    def test_redacted_value_is_masked(self):
        body = 'const key = "AKIAABCDEFGHIJKLMNOP";'
        result = js.extract_secret_indicators(body)
        assert "*" in result[0]["redacted_value"]

    def test_fingerprint_is_stable_sha256(self):
        body = 'const key = "AKIAABCDEFGHIJKLMNOP";'
        result = js.extract_secret_indicators(body)
        expected = js._fingerprint("AKIAABCDEFGHIJKLMNOP")
        assert result[0]["fingerprint_sha256"] == expected
        assert len(result[0]["fingerprint_sha256"]) == 64

    def test_generic_secret_assignment_has_verification_note(self):
        body = 'const password = "SuperSecretValue123";'
        result = js.extract_secret_indicators(body)
        matches = [s for s in result if s["pattern_name"] == "generic_secret_assignment"]
        assert matches
        assert matches[0]["note"] is not None
        assert "verify" in matches[0]["note"].lower()

    def test_high_confidence_pattern_has_no_note(self):
        body = 'const key = "AKIAABCDEFGHIJKLMNOP";'
        result = js.extract_secret_indicators(body)
        assert result[0]["note"] is None

    def test_private_key_block_detected(self):
        body = "-----BEGIN RSA PRIVATE KEY-----\nMIIExampleFakeKeyMaterial\n-----END RSA PRIVATE KEY-----"
        result = js.extract_secret_indicators(body)
        assert any(s["pattern_name"] == "private_key_block" for s in result)

    def test_jwt_detected_low_confidence(self):
        body = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ_fake_sig_here"
        result = js.extract_secret_indicators(body)
        matches = [s for s in result if s["pattern_name"] == "jwt_token"]
        assert matches
        assert matches[0]["confidence"] == js.CONFIDENCE_LOW

    def test_no_match(self):
        assert js.extract_secret_indicators("console.log('clean file');") == []

    def test_empty_body(self):
        assert js.extract_secret_indicators("") == []


# ---------------------------------------------------------------------------
# 2e/6. detect_websocket_references
# ---------------------------------------------------------------------------

class TestDetectWebsocketReferences:
    def test_literal_wss_url(self):
        body = 'const ws = new WebSocket("wss://example.com/live");'
        result = js.detect_websocket_references(body, SAFE_JS_URL)
        assert result[0]["endpoint"] == "wss://example.com/live"
        assert result[0]["confidence"] == js.CONFIDENCE_HIGH

    def test_ctor_without_literal_low_confidence(self):
        body = "const ws = new WebSocket(dynamicUrl);"
        result = js.detect_websocket_references(body, SAFE_JS_URL)
        assert result[0]["endpoint"] is None
        assert result[0]["confidence"] == js.CONFIDENCE_LOW

    def test_no_websocket_signals(self):
        assert js.detect_websocket_references("console.log('hi');", SAFE_JS_URL) == []

    def test_empty_body(self):
        assert js.detect_websocket_references("", SAFE_JS_URL) == []


# ---------------------------------------------------------------------------
# 3. Source map detection / fetch / parse / reconstruction
# ---------------------------------------------------------------------------

class TestDetectSourceMapReference:
    def test_explicit_line_comment(self):
        body = "console.log(1);\n//# sourceMappingURL=app.js.map"
        result = js.detect_source_map_reference(body, SAFE_JS_URL)
        assert result["status"] == "explicit"
        assert result["map_url"] == "https://example.com/static/app.js.map"

    def test_explicit_block_comment(self):
        body = "console.log(1);\n/*# sourceMappingURL=app.js.map */"
        result = js.detect_source_map_reference(body, SAFE_JS_URL)
        assert result["status"] == "explicit"

    def test_implicit_guess_when_no_comment(self):
        result = js.detect_source_map_reference("console.log(1);", SAFE_JS_URL, try_implicit_sibling=True)
        assert result["status"] == "implicit_guess"
        assert result["map_url"] == SAFE_JS_URL + ".map"

    def test_not_found_when_implicit_disabled(self):
        result = js.detect_source_map_reference("console.log(1);", SAFE_JS_URL, try_implicit_sibling=False)
        assert result["status"] == "not_found"
        assert result["map_url"] is None

    def test_empty_body_with_implicit_guess(self):
        result = js.detect_source_map_reference("", SAFE_JS_URL, try_implicit_sibling=True)
        assert result["status"] == "implicit_guess"


class TestFetchSourceMap:
    def test_success(self):
        resp = _fake_response(status_code=200, body=b'{"version":3,"sources":["a.js"]}')
        with mock.patch("requests.get", return_value=resp):
            result = js.fetch_source_map("https://example.com/app.js.map", target=SAFE_TARGET)
        assert result["status"] == "found"

    def test_out_of_scope_map_url_never_fetched(self):
        with mock.patch("requests.get") as mocked:
            result = js.fetch_source_map("https://evil.com/app.js.map", target=SAFE_TARGET)
        mocked.assert_not_called()
        assert result["status"] == "out_of_scope"

    def test_network_failure(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout("t")):
            result = js.fetch_source_map("https://example.com/app.js.map", target=SAFE_TARGET)
        assert result["status"] == "error"


class TestParseSourceMap:
    def test_valid_with_sources_content(self):
        raw = json.dumps({"version": 3, "sources": ["src/app.js"], "sourcesContent": ["console.log('orig');"],
                           "names": ["a", "b"], "mappings": "AAAA"})
        result = js.parse_source_map(raw)
        assert result["status"] == "parsed"
        assert result["sources_content_available"] is True
        assert result["names_count"] == 2

    def test_valid_without_sources_content(self):
        raw = json.dumps({"version": 3, "sources": ["src/app.js"], "mappings": "AAAA"})
        result = js.parse_source_map(raw)
        assert result["status"] == "parsed"
        assert result["sources_content_available"] is False

    def test_malformed_json(self):
        result = js.parse_source_map("{not valid json")
        assert result["status"] == "malformed"

    def test_non_dict_root(self):
        result = js.parse_source_map("[1, 2, 3]")
        assert result["status"] == "malformed"

    def test_empty_body(self):
        assert js.parse_source_map("")["status"] == "empty"

    def test_none_body(self):
        assert js.parse_source_map(None)["status"] == "empty"

    def test_whitespace_only_body(self):
        assert js.parse_source_map("   \n  ")["status"] == "empty"


class TestReconstructOriginalSources:
    def test_reconstructs_available_content(self):
        parsed = {"status": "parsed", "sources": ["a.js", "b.js"], "sources_content": ["contentA", "contentB"]}
        result = js.reconstruct_original_sources(parsed)
        assert result == [{"source": "a.js", "content": "contentA"}, {"source": "b.js", "content": "contentB"}]

    def test_partial_content_only_available_entries(self):
        parsed = {"status": "parsed", "sources": ["a.js", "b.js"], "sources_content": ["contentA", None]}
        result = js.reconstruct_original_sources(parsed)
        assert result == [{"source": "a.js", "content": "contentA"}]

    def test_no_sources_content_returns_empty(self):
        parsed = {"status": "parsed", "sources": ["a.js"], "sources_content": []}
        assert js.reconstruct_original_sources(parsed) == []

    def test_not_parsed_returns_empty(self):
        assert js.reconstruct_original_sources({"status": "malformed"}) == []

    def test_empty_string_content_excluded(self):
        parsed = {"status": "parsed", "sources": ["a.js"], "sources_content": ["   "]}
        assert js.reconstruct_original_sources(parsed) == []


# ---------------------------------------------------------------------------
# 4a. extract_client_side_signals
# ---------------------------------------------------------------------------

class TestExtractClientSideSignals:
    def test_source_detected(self):
        result = js.extract_client_side_signals("var x = location.hash;")
        assert any(s["kind"] == "location.hash" for s in result["sources"])

    def test_sink_detected(self):
        result = js.extract_client_side_signals("el.innerHTML = data;")
        assert any(s["kind"] == "innerHTML" for s in result["sinks"])

    def test_eval_sink_detected(self):
        result = js.extract_client_side_signals("eval(userInput);")
        assert any(s["kind"] == "eval" for s in result["sinks"])

    def test_proximity_flow_flagged_when_nearby(self):
        body = "var x = location.hash;\nel.innerHTML = x;"
        result = js.extract_client_side_signals(body)
        assert len(result["possible_data_flows"]) >= 1
        assert result["possible_data_flows"][0]["source_kind"] == "location.hash"
        assert result["possible_data_flows"][0]["sink_kind"] == "innerHTML"

    def test_no_flow_flagged_when_far_apart(self):
        body = "var x = location.hash;\n" + ("\n" * 20) + "el.innerHTML = something_else;"
        result = js.extract_client_side_signals(body)
        assert result["possible_data_flows"] == []

    def test_flow_evidence_explicitly_labeled_heuristic(self):
        body = "var x = location.hash;\nel.innerHTML = x;"
        result = js.extract_client_side_signals(body)
        evidence_text = " ".join(result["possible_data_flows"][0]["evidence"]).lower()
        assert "heuristic" in evidence_text
        assert "not a verified" in evidence_text or "manual review" in evidence_text

    def test_no_signals_in_clean_code(self):
        result = js.extract_client_side_signals("console.log('all good');")
        assert result == {"sources": [], "sinks": [], "possible_data_flows": []}

    def test_empty_body(self):
        assert js.extract_client_side_signals("") == {"sources": [], "sinks": [], "possible_data_flows": []}


# ---------------------------------------------------------------------------
# 4b. extract_postmessage_signals
# ---------------------------------------------------------------------------

class TestExtractPostmessageSignals:
    def test_listener_with_origin_check(self):
        body = 'window.addEventListener("message", function(e){ if (e.origin === "https://example.com") { } });'
        result = js.extract_postmessage_signals(body)
        assert result["listeners"][0]["origin_check_observed"] is True

    def test_listener_without_origin_check(self):
        body = 'window.addEventListener("message", function(e){ handle(e.data); });'
        result = js.extract_postmessage_signals(body)
        assert result["listeners"][0]["origin_check_observed"] is False

    def test_send_detected(self):
        body = "otherWindow.postMessage(data, '*');"
        result = js.extract_postmessage_signals(body)
        assert len(result["sends"]) == 1

    def test_none_detected(self):
        result = js.extract_postmessage_signals("console.log('nothing');")
        assert result == {"listeners": [], "sends": []}

    def test_empty_body(self):
        assert js.extract_postmessage_signals("") == {"listeners": [], "sends": []}


# ---------------------------------------------------------------------------
# 4c. extract_localstorage_signals
# ---------------------------------------------------------------------------

class TestExtractLocalstorageSignals:
    def test_get_item(self):
        result = js.extract_localstorage_signals('localStorage.getItem("auth_token");')
        assert result[0] == {"method": "getItem", "key": "auth_token",
                              "evidence": ["localStorage.getItem('auth_token') call found"]}

    def test_set_item(self):
        result = js.extract_localstorage_signals('localStorage.setItem("user_id", id);')
        assert result[0]["method"] == "setItem"
        assert result[0]["key"] == "user_id"

    def test_multiple_calls(self):
        body = 'localStorage.getItem("a"); localStorage.setItem("b", 1); localStorage.removeItem("c");'
        result = js.extract_localstorage_signals(body)
        assert [r["method"] for r in result] == ["getItem", "setItem", "removeItem"]

    def test_none_detected(self):
        assert js.extract_localstorage_signals("console.log('none');") == []

    def test_empty_body(self):
        assert js.extract_localstorage_signals("") == []


# ---------------------------------------------------------------------------
# extract_body_parameter_hints
# ---------------------------------------------------------------------------

class TestExtractBodyParameterHints:
    def test_extracts_keys_from_json_stringify(self):
        body = 'fetch("/api/login", {method:"POST", body: JSON.stringify({username: u, password: p})});'
        result = js.extract_body_parameter_hints(body)
        names = {h["name"] for h in result}
        assert names == {"username", "password"}
        assert all(h["location"] == "body" and h["method"] == "POST" for h in result)

    def test_dedupes_keys(self):
        body = 'JSON.stringify({a: 1}); JSON.stringify({a: 2, b: 3});'
        result = js.extract_body_parameter_hints(body)
        names = [h["name"] for h in result]
        assert names == ["a", "b"]

    def test_no_match(self):
        assert js.extract_body_parameter_hints("console.log('none');") == []

    def test_empty_body(self):
        assert js.extract_body_parameter_hints("") == []


# ---------------------------------------------------------------------------
# analyze_javascript_content (bundling)
# ---------------------------------------------------------------------------

class TestAnalyzeJavascriptContent:
    def test_bundles_all_categories(self):
        body = 'fetch("/api/v1/ping"); localStorage.setItem("k", "v");'
        result = js.analyze_javascript_content(body, SAFE_JS_URL, target=SAFE_TARGET)
        expected_keys = {
            "js_url", "api_references", "external_services", "config_values", "secret_indicators",
            "websocket_references", "client_side_signals", "postmessage_signals", "localstorage_signals",
            "body_parameter_hints",
        }
        assert set(result.keys()) == expected_keys

    def test_malformed_content_does_not_raise(self):
        body = '<<<not really javascript>>> """ unterminated string'
        result = js.analyze_javascript_content(body, SAFE_JS_URL, target=SAFE_TARGET)
        assert isinstance(result, dict)

    def test_none_body_handled(self):
        result = js.analyze_javascript_content(None, SAFE_JS_URL, target=SAFE_TARGET)
        assert result["api_references"] == []

    def test_empty_body_handled(self):
        result = js.analyze_javascript_content("", SAFE_JS_URL, target=SAFE_TARGET)
        assert all(v == [] or v == {} or (isinstance(v, dict) and not any(v.values())) for k, v in result.items() if k != "js_url")

    def test_json_serializable(self):
        body = 'fetch("/api/v1/ping"); const key="AKIAABCDEFGHIJKLMNOP";'
        result = js.analyze_javascript_content(body, SAFE_JS_URL, target=SAFE_TARGET)
        json.dumps(result)


# ---------------------------------------------------------------------------
# build_endpoint_discovery_js_data (responsibility #5 — existing-interface
# compatibility)
# ---------------------------------------------------------------------------

class TestBuildEndpointDiscoveryJsData:
    def test_shape_matches_endpoint_discovery_contract(self):
        api_refs = [{"url": "https://example.com/api/v1/users?id=5", "raw": "x", "kind": "api_endpoint", "evidence": ["e1"]}]
        result = js.build_endpoint_discovery_js_data(api_refs, [], SAFE_JS_URL)
        assert result == [{
            "url": "https://example.com/api/v1/users?id=5",
            "parameters": [{"name": "id", "location": "query", "method": "GET", "data_type": "integer"}],
            "evidence": ["e1"], "source_file": SAFE_JS_URL,
        }]

    def test_body_hints_attached_with_note(self):
        api_refs = [{"url": "https://example.com/api/v1/login", "raw": "x", "kind": "api_endpoint", "evidence": ["e1"]}]
        hints = [{"name": "username", "location": "body", "method": "POST", "data_type": "unknown"}]
        result = js.build_endpoint_discovery_js_data(api_refs, hints, SAFE_JS_URL)
        assert {"name": "username", "location": "body", "method": "POST", "data_type": "unknown"} in result[0]["parameters"]
        assert any("file-wide" in e for e in result[0]["evidence"])

    def test_empty_input(self):
        assert js.build_endpoint_discovery_js_data([], [], SAFE_JS_URL) == []

    def test_json_serializable(self):
        api_refs = [{"url": "https://example.com/api/v1/x", "raw": "x", "kind": "api_endpoint", "evidence": ["e"]}]
        json.dumps(js.build_endpoint_discovery_js_data(api_refs, [], SAFE_JS_URL))


# ---------------------------------------------------------------------------
# Downstream integration: js_data must be directly consumable by
# endpoint_discovery.py's ALREADY-BUILT correlate_javascript_parameters.
# ---------------------------------------------------------------------------

class TestDownstreamIntegrationWithEndpointDiscovery:
    def test_js_data_consumed_by_correlate_javascript_parameters(self, tmp_path):
        api_refs = [{"url": "https://example.com/api/v1/orders", "raw": "x", "kind": "api_endpoint",
                     "evidence": ["fetch()/axios()/XHR call target: '/api/v1/orders'"]}]
        js_data = js.build_endpoint_discovery_js_data(api_refs, [], SAFE_JS_URL)

        store = ed.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        result = ed.correlate_javascript_parameters(current_endpoints=[], js_data=js_data, target=SAFE_TARGET, store=store)

        assert len(result["endpoints"]) == 1
        assert result["endpoints"][0]["url"] == "https://example.com/api/v1/orders"
        records = store.all()
        assert any(r["type"] == "javascript_endpoint_reference" for r in records)


# ---------------------------------------------------------------------------
# persist_analysis_findings
# ---------------------------------------------------------------------------

class TestPersistAnalysisFindings:
    def test_persists_every_category_with_correct_counts(self, tmp_path):
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        body = (
            'fetch("/api/v1/ping"); '
            'const x = "https://www.google-analytics.com/collect"; '
            'window.ENV = "production"; '
            'const key = "AKIAABCDEFGHIJKLMNOP"; '
            'const ws = new WebSocket("wss://example.com/live"); '
            'el.innerHTML = location.hash; '
            'window.addEventListener("message", function(e){}); '
            'localStorage.setItem("k", "v");'
        )
        analysis = js.analyze_javascript_content(body, SAFE_JS_URL, target=SAFE_TARGET)
        result = js.persist_analysis_findings(analysis, SAFE_TARGET, store, parent_js_url=SAFE_JS_URL, source_page="https://example.com/")

        assert result["errors"] == []
        assert result["counts"]["api_references"] >= 1
        assert result["counts"]["external_services"] == 1
        assert result["counts"]["config_values"] == 1
        assert result["counts"]["secret_indicators"] == 1
        assert result["counts"]["websocket_references"] == 1
        assert result["counts"]["localstorage_signals"] == 1
        assert result["total"] > 0

        records = store.all()
        assert len(records) == result["total"]
        for r in records:
            assert r["metadata"]["parent_js_url"] == SAFE_JS_URL
            assert r["metadata"]["source_page"] == "https://example.com/"
        json.dumps(records)

    def test_no_findings_returns_zero_total(self, tmp_path):
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        analysis = js.analyze_javascript_content("console.log('clean');", SAFE_JS_URL, target=SAFE_TARGET)
        result = js.persist_analysis_findings(analysis, SAFE_TARGET, store, parent_js_url=SAFE_JS_URL)
        assert result["total"] == 0
        assert store.all() == []

    def test_derived_from_source_map_metadata_propagated(self, tmp_path):
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        analysis = js.analyze_javascript_content('fetch("/api/v1/ping");', SAFE_JS_URL, target=SAFE_TARGET)
        js.persist_analysis_findings(
            analysis, SAFE_TARGET, store, parent_js_url=SAFE_JS_URL,
            derived_from_source_map=True, original_source_file="src/original.js",
        )
        records = store.all()
        assert all(r["metadata"]["derived_from_source_map"] is True for r in records)
        assert all(r["metadata"]["original_source_file"] == "src/original.js" for r in records)

    def test_persistence_failure_recorded_not_raised(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("not json")
        store = js.PendingAssetsStore(output_dir=str(output_dir))
        analysis = js.analyze_javascript_content('fetch("/api/v1/ping");', SAFE_JS_URL, target=SAFE_TARGET)
        result = js.persist_analysis_findings(analysis, SAFE_TARGET, store, parent_js_url=SAFE_JS_URL)
        assert len(result["errors"]) > 0

    def test_websocket_endpoints_accumulated_for_normalization(self, tmp_path):
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        analysis = js.analyze_javascript_content('new WebSocket("wss://example.com/live");', SAFE_JS_URL, target=SAFE_TARGET)
        result = js.persist_analysis_findings(analysis, SAFE_TARGET, store, parent_js_url=SAFE_JS_URL)
        assert result["websocket_endpoints"] == [{
            "endpoint": "wss://example.com/live", "source_file": SAFE_JS_URL,
            "evidence": [f"Literal WebSocket URL found in JS from {SAFE_JS_URL}: wss://example.com/live"],
        }]


# ---------------------------------------------------------------------------
# process_source_map (orchestration)
# ---------------------------------------------------------------------------

class TestProcessSourceMap:
    def test_explicit_reference_full_pipeline_with_reconstruction(self, tmp_path):
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        body = "console.log(1);\n//# sourceMappingURL=app.js.map"
        map_json = json.dumps({
            "version": 3, "sources": ["src/app.js"],
            "sourcesContent": ['fetch("/api/v1/reconstructed");'],
        })
        map_resp = _fake_response(status_code=200, body=map_json.encode())
        with mock.patch("requests.get", return_value=map_resp):
            result = js.process_source_map(
                body, SAFE_JS_URL, SAFE_TARGET, SAFE_TARGET, None, store,
                retrieve_source_maps=True, analyze_reconstructed_sources=True,
                try_implicit_sibling=True, timeout=5.0,
            )
        assert result["info"]["parse_status"] == "parsed"
        assert result["info"]["reconstructed_sources"] == ["src/app.js"]
        assert any(d["url"].endswith("/api/v1/reconstructed") for d in result["js_data"])

        records = store.all()
        assert any(r["type"] == "js_analyzer_source_map_reference" for r in records)
        assert any(r["type"] == "js_analyzer_reconstructed_source" for r in records)
        reconstructed_endpoint_findings = [r for r in records if r["type"] == "js_analyzer_endpoint_reference"]
        assert any(r["metadata"]["derived_from_source_map"] is True for r in reconstructed_endpoint_findings)

    def test_implicit_guess_confirmed(self, tmp_path):
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        map_json = json.dumps({"version": 3, "sources": ["a.js"], "sourcesContent": ["console.log('x');"]})
        map_resp = _fake_response(status_code=200, body=map_json.encode())
        with mock.patch("requests.get", return_value=map_resp):
            result = js.process_source_map(
                "console.log(1);", SAFE_JS_URL, SAFE_TARGET, SAFE_TARGET, None, store,
                retrieve_source_maps=True, analyze_reconstructed_sources=False,
                try_implicit_sibling=True, timeout=5.0,
            )
        assert result["info"]["reference_type"] == "implicit_guess"
        assert result["info"]["parse_status"] == "parsed"

    def test_implicit_guess_unconfirmed_persists_nothing(self, tmp_path):
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        not_found_resp = _fake_response(status_code=404, body=b"not found")
        with mock.patch("requests.get", return_value=not_found_resp):
            result = js.process_source_map(
                "console.log(1);", SAFE_JS_URL, SAFE_TARGET, SAFE_TARGET, None, store,
                retrieve_source_maps=True, analyze_reconstructed_sources=True,
                try_implicit_sibling=True, timeout=5.0,
            )
        assert store.all() == []
        assert result["errors"] == []

    def test_malformed_map_does_not_raise_and_is_recorded(self, tmp_path):
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        body = "console.log(1);\n//# sourceMappingURL=app.js.map"
        bad_resp = _fake_response(status_code=200, body=b"{not valid json")
        with mock.patch("requests.get", return_value=bad_resp):
            result = js.process_source_map(
                body, SAFE_JS_URL, SAFE_TARGET, SAFE_TARGET, None, store,
                retrieve_source_maps=True, analyze_reconstructed_sources=True,
                try_implicit_sibling=True, timeout=5.0,
            )
        assert result["info"]["parse_status"] == "malformed"
        records = store.all()
        assert any(r["type"] == "js_analyzer_source_map_reference" and r["value"]["parse_status"] == "malformed" for r in records)

    def test_out_of_scope_map_url_handled_gracefully(self, tmp_path):
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        body = "console.log(1);\n//# sourceMappingURL=https://evil.com/app.js.map"
        with mock.patch("requests.get") as mocked:
            result = js.process_source_map(
                body, SAFE_JS_URL, SAFE_TARGET, SAFE_TARGET, None, store,
                retrieve_source_maps=True, analyze_reconstructed_sources=True,
                try_implicit_sibling=True, timeout=5.0,
            )
        mocked.assert_not_called()
        records = store.all()
        assert any(r["type"] == "js_analyzer_source_map_reference" and r["value"]["fetch_status"] == "out_of_scope" for r in records)

    def test_retrieve_disabled_still_records_explicit_reference(self, tmp_path):
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        body = "console.log(1);\n//# sourceMappingURL=app.js.map"
        with mock.patch("requests.get") as mocked:
            result = js.process_source_map(
                body, SAFE_JS_URL, SAFE_TARGET, SAFE_TARGET, None, store,
                retrieve_source_maps=False, analyze_reconstructed_sources=True,
                try_implicit_sibling=True, timeout=5.0,
            )
        mocked.assert_not_called()
        records = store.all()
        assert len(records) == 1
        assert records[0]["value"]["fetch_status"] == "not_attempted"

    def test_both_disabled_is_noop(self, tmp_path):
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("requests.get") as mocked:
            result = js.process_source_map(
                "console.log(1);", SAFE_JS_URL, SAFE_TARGET, SAFE_TARGET, None, store,
                retrieve_source_maps=False, analyze_reconstructed_sources=False,
                try_implicit_sibling=False, timeout=5.0,
            )
        mocked.assert_not_called()
        assert store.all() == []
        assert result["info"] is None

    def test_no_reference_detected_is_noop(self, tmp_path):
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        result = js.process_source_map(
            "console.log(1);", SAFE_JS_URL, SAFE_TARGET, SAFE_TARGET, None, store,
            retrieve_source_maps=True, analyze_reconstructed_sources=True,
            try_implicit_sibling=False, timeout=5.0,
        )
        assert result["info"] is None
        assert store.all() == []


# ---------------------------------------------------------------------------
# _normalize_js_reference (input acceptance — see module docstring,
# NO-CROSS-MODULE-CALLS PRECEDENT item (a))
# ---------------------------------------------------------------------------

class TestNormalizeJsReference:
    def test_plain_string(self):
        assert js._normalize_js_reference(SAFE_JS_URL) == {"url": SAFE_JS_URL, "source_page": None}

    def test_simple_dict(self):
        item = {"url": SAFE_JS_URL, "source_page": "https://example.com/"}
        assert js._normalize_js_reference(item) == {"url": SAFE_JS_URL, "source_page": "https://example.com/"}

    def test_crawler_raw_finding_record(self):
        # exact shape crawler.py persists for a `javascript_reference` finding
        record = {
            "type": "javascript_reference", "target": "example.com",
            "value": {"url": SAFE_JS_URL, "source_page": "https://example.com/", "in_scope": True, "fetched": False},
            "evidence": ["..."], "confidence": "HIGH", "source": "crawler.py", "timestamp": "...",
            "metadata": {"source_page": "https://example.com/", "for_module": "js_analyzer.py"},
        }
        result = js._normalize_js_reference(record)
        assert result == {"url": SAFE_JS_URL, "source_page": "https://example.com/"}

    def test_missing_url_returns_none(self):
        assert js._normalize_js_reference({"source_page": "x"})["url"] is None

    def test_unsupported_type_returns_none(self):
        assert js._normalize_js_reference(12345)["url"] is None


# ---------------------------------------------------------------------------
# run_js_analyzer — full orchestration
# ---------------------------------------------------------------------------

class TestRunJsAnalyzer:
    def test_full_run_persists_and_summarizes(self, tmp_path):
        js_body = 'fetch("/api/v1/ping"); const ws = new WebSocket("wss://example.com/live");'
        js_resp = _fake_response(status_code=200, headers={"Content-Type": "application/javascript"}, body=js_body.encode())
        map_probe_404 = _fake_response(status_code=404, body=b"")
        output_dir = tmp_path / "output"

        with mock.patch("requests.get", side_effect=[js_resp, map_probe_404]):
            result = js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(output_dir))

        assert result["files_analyzed"] == 1
        assert result["files_requested"] == 1
        assert len(result["js_data_for_endpoint_discovery"]) == 1
        assert len(result["websocket_endpoints"]) == 1

        store = js.PendingAssetsStore(output_dir=str(output_dir))
        records = store.all()
        assert any(r["type"] == "javascript_file_analyzed" for r in records)
        assert any(r["type"] == "js_analyzer_endpoint_reference" for r in records)
        assert any(r["type"] == "js_analyzer_websocket_endpoint" for r in records)
        json.dumps(result)

    def test_accepts_crawler_style_raw_records(self, tmp_path):
        crawler_record = {
            "type": "javascript_reference", "value": {"url": SAFE_JS_URL, "source_page": "https://example.com/"},
        }
        js_resp = _fake_response(status_code=200, body=b"console.log('clean');")
        map_404 = _fake_response(status_code=404, body=b"")
        with mock.patch("requests.get", side_effect=[js_resp, map_404]):
            result = js.run_js_analyzer([crawler_record], target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert result["files_analyzed"] == 1
        assert result["results"][0]["source_page"] == "https://example.com/"

    def test_out_of_scope_reference_skipped_not_fetched(self, tmp_path):
        with mock.patch("requests.get") as mocked:
            result = js.run_js_analyzer(["https://evil.com/app.js"], target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        mocked.assert_not_called()
        assert result["files_skipped_out_of_scope"] == 1
        assert result["files_analyzed"] == 0

        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        records = store.all()
        assert any(r["type"] == "js_analyzer_skipped_out_of_scope" for r in records)

    def test_fetch_failure_recorded_not_raised(self, tmp_path):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert result["files_failed"] == 1
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert any(r["type"] == "js_analyzer_fetch_failed" for r in store.all())

    def test_non_textual_content_skipped(self, tmp_path):
        resp = _fake_response(status_code=200, headers={"Content-Type": "image/png"}, body=b"\x89PNG\r\n")
        with mock.patch("requests.get", return_value=resp):
            result = js.run_js_analyzer(
                [SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
            )
        assert result["results"][0]["status"] == "non_textual_content_skipped"

    def test_empty_js_file_handled(self, tmp_path):
        js_resp = _fake_response(status_code=200, body=b"")
        with mock.patch("requests.get", return_value=js_resp):
            result = js.run_js_analyzer(
                [SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                try_implicit_source_map_sibling=False,
            )
        assert result["files_analyzed"] == 0  # empty body fails the textual-content check
        json.dumps(result)

    def test_checked_no_findings_persisted_for_clean_file(self, tmp_path):
        js_resp = _fake_response(status_code=200, body=b"console.log('nothing interesting');")
        map_404 = _fake_response(status_code=404, body=b"")
        with mock.patch("requests.get", side_effect=[js_resp, map_404]):
            js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert any(r["type"] == "js_analyzer_checked_no_findings" for r in store.all())

    def test_max_files_respected(self, tmp_path):
        resp = _fake_response(status_code=200, body=b"console.log(1);")
        map_404 = _fake_response(status_code=404, body=b"")
        with mock.patch("requests.get", side_effect=[resp, map_404]):
            result = js.run_js_analyzer(
                [SAFE_JS_URL, "https://example.com/other.js"], target=SAFE_TARGET,
                output_dir=str(tmp_path / "output"), max_files=1,
            )
        assert result["files_requested"] == 1
        assert result["files_analyzed"] == 1

    def test_source_maps_disabled_end_to_end(self, tmp_path):
        js_resp = _fake_response(status_code=200, body=b"console.log(1);\n//# sourceMappingURL=app.js.map")
        with mock.patch("requests.get", return_value=js_resp) as mocked:
            result = js.run_js_analyzer(
                [SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                retrieve_source_maps=False, try_implicit_source_map_sibling=False,
            )
        assert mocked.call_count == 1  # only the JS file itself, no map fetch attempted
        assert result["files_analyzed"] == 1

    def test_scope_error_target_mismatch_does_not_raise_at_top_level(self, tmp_path):
        # run_js_analyzer must never raise ScopeError itself — it records
        # per-item skips and continues.
        result = js.run_js_analyzer(
            ["not a valid url", SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
        )
        assert isinstance(result, dict)

    def test_output_json_serializable_end_to_end(self, tmp_path):
        js_body = (
            'fetch("/api/v1/ping"); const key="AKIAABCDEFGHIJKLMNOP"; '
            'localStorage.setItem("a","b"); new WebSocket("wss://example.com/live");'
        )
        js_resp = _fake_response(status_code=200, body=js_body.encode())
        map_404 = _fake_response(status_code=404, body=b"")
        with mock.patch("requests.get", side_effect=[js_resp, map_404]):
            result = js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        json.dumps(result)

    def test_no_files_requested(self, tmp_path):
        result = js.run_js_analyzer([], target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert result["files_requested"] == 0
        assert result["files_analyzed"] == 0
        assert result["results"] == []
