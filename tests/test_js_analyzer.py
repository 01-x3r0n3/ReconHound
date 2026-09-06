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
        # The literal URL text matches _ABS_URL_RE twice (the const assignment, and
        # again inside the fetch() call's own string literal) plus once via
        # _JS_CALL_RE — but those first two are the SAME mechanism producing the
        # same evidence string. context.md §8 raises confidence on independent
        # converging signals, so evidence is deduplicated by text and the raw
        # repetition count is carried separately: two distinct mechanisms here.
        assert len(matching[0]["evidence"]) == 2
        assert matching[0]["occurrences"] == 3
        assert any("Absolute URL" in e for e in matching[0]["evidence"])
        assert any("call target" in e for e in matching[0]["evidence"])

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
        # `occurrences` carries how many times this (method, key) pair was seen;
        # identical accesses are merged rather than duplicated (context.md §7).
        assert result[0] == {"method": "getItem", "key": "auth_token", "occurrences": 1,
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
        # `in_scope` distinguishes the target's own realtime endpoint from a
        # third-party socket referenced by the same script — attributing the
        # latter to the target would be a correlation error.
        assert result["websocket_endpoints"] == [{
            "endpoint": "wss://example.com/live", "in_scope": True, "source_file": SAFE_JS_URL,
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
        # Skipped for analysis, but no longer skipped for the record: the
        # outcome is persisted so "this URL was checked and yielded no usable
        # script" survives the run (context.md §12.11 — no silent drops).
        resp = _fake_response(status_code=200, headers={"Content-Type": "image/png"}, body=b"\x89PNG\r\n")
        output_dir = tmp_path / "output"
        with mock.patch("requests.get", return_value=resp):
            result = js.run_js_analyzer(
                [SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(output_dir),
            )
        assert result["results"][0]["status"] == "not_analyzable"
        assert "not textual" in result["results"][0]["error"]
        records = js.PendingAssetsStore(output_dir=str(output_dir)).all()
        assert any(r["type"] == "js_analyzer_fetch_failed" for r in records)
        assert not any(r["type"] == "javascript_file_analyzed" for r in records)

    def test_empty_js_file_handled(self, tmp_path):
        # A zero-byte 200 response is a script that was fetched and contains
        # nothing — a negative result worth remembering (context.md §8), not a
        # binary payload to skip. It used to fail the textual-content check and
        # vanish without a single persisted record.
        js_resp = _fake_response(status_code=200, body=b"")
        output_dir = tmp_path / "output"
        with mock.patch("requests.get", return_value=js_resp):
            result = js.run_js_analyzer(
                [SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(output_dir),
                try_implicit_source_map_sibling=False,
            )
        assert result["files_analyzed"] == 1
        records = js.PendingAssetsStore(output_dir=str(output_dir)).all()
        assert any(r["type"] == "javascript_file_analyzed" for r in records)
        assert any(r["type"] == "js_analyzer_checked_no_findings" for r in records)
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


# ===========================================================================
# Regression tests for the forensic audit of js_analyzer.py.
#
# Every test below pins a defect that was reproduced against the previous
# implementation before it was fixed. The comment on each names the observed
# wrong behaviour so a future change that reintroduces it fails loudly.
# ===========================================================================


class TestRegressionScopeAndSsrf:
    """Scope chokepoint: validate_url_target now guards every fetch."""

    @pytest.mark.parametrize("url", [
        "http://127.0.0.1:8080/app.js",
        "http://169.254.169.254/latest/meta-data/app.js",
        "http://10.0.0.5/app.js",
        "http://192.168.1.1/app.js",
        "http://[::1]/app.js",
    ])
    def test_private_ip_literal_rejected_under_domain_target(self, url):
        # WAS: IP literals skipped the scope check entirely, so a
        # <script src="http://127.0.0.1:8080/x.js"> on the target's own page
        # was fetched against the operator's loopback.
        with pytest.raises(js.ScopeError):
            js.validate_url_target(url, target="example.com")

    def test_public_ip_literal_still_allowed(self):
        assert js.validate_url_target("http://93.184.216.34/app.js", target="example.com")

    def test_ip_literal_target_allows_exactly_itself(self):
        # An operator who authorised an internal IP has made that address
        # in scope (mirrors crawler.py's _candidate_in_scope carve-out).
        assert js.validate_url_target("http://127.0.0.1/app.js", target="127.0.0.1")
        with pytest.raises(js.ScopeError):
            js.validate_url_target("http://127.0.0.2/app.js", target="127.0.0.1")

    @pytest.mark.parametrize("url", [
        "https://exa\rmple.com/x.js",
        "https://example.com/x.js\r\nX-Injected: 1",
        "https://example.com/\tx.js",
        "https://example.com/x.js\x00",
    ])
    def test_control_characters_rejected(self, url):
        # WAS: urlsplit silently strips CR/LF/TAB, so the host that was
        # scope-checked was not the string handed to requests.
        with pytest.raises(js.ScopeError):
            js.validate_url_target(url, target="example.com")

    def test_userinfo_credentials_stripped(self):
        # WAS: the credential travelled into pending_assets.json verbatim.
        assert js.validate_url_target(
            "https://admin:S3cret@example.com/a.js", target="example.com"
        ) == "https://example.com/a.js"

    def test_idn_homograph_host_is_out_of_scope(self):
        with pytest.raises(js.ScopeError):
            js.validate_url_target("https://exаmple.com/a.js", target="example.com")

    def test_run_skips_loopback_reference_without_fetching(self, tmp_path):
        output_dir = tmp_path / "output"
        with mock.patch("requests.get") as mocked:
            result = js.run_js_analyzer(
                ["http://127.0.0.1:8080/app.js"], target=SAFE_TARGET, output_dir=str(output_dir),
            )
        mocked.assert_not_called()
        assert result["files_skipped_out_of_scope"] == 1
        records = js.PendingAssetsStore(output_dir=str(output_dir)).all()
        assert any(r["type"] == "js_analyzer_skipped_out_of_scope" for r in records)

    def test_redirect_to_loopback_blocked(self):
        redirect = _fake_response(status_code=302, headers={"Location": "http://127.0.0.1/x.js"})
        with mock.patch("requests.get", return_value=redirect):
            result = js.fetch_javascript_file(SAFE_JS_URL, target=SAFE_TARGET)
        assert result["status"] == "error"
        assert "SSRF safeguard" in result["error"]


class TestRegressionSecretRedaction:
    """The module promises the raw matched string is never stored."""

    def test_capture_group_bound_does_not_leak_the_value_tail(self):
        # WAS: generic_api_key_assignment captures at most 64 chars, so the
        # remaining 16 characters of an 80-char key sat in the "context"
        # window as plain text.
        body = 'apiKey: "' + "K" * 80 + '"'
        for indicator in js.extract_secret_indicators(body):
            assert "K" * 20 not in indicator["context"]

    def test_neighbouring_secret_not_emitted_verbatim(self):
        # WAS: a second key within the +-40 character window was raw.
        body = 'k1="AKIAAAAAAAAAAAAAAAAA";k2="AKIABBBBBBBBBBBBBBBB";'
        for indicator in js.extract_secret_indicators(body):
            assert "AKIAAAAAAAAAAAAAAAAA" not in indicator["context"]
            assert "AKIABBBBBBBBBBBBBBBB" not in indicator["context"]

    def test_surrounding_code_context_is_still_readable(self):
        body = 'var cfg={env:"prod",token:"AKIAABCDEFGHIJKLMNOP",debug:false};'
        contexts = [i["context"] for i in js.extract_secret_indicators(body)]
        assert any("var cfg=" in c and "debug:false" in c for c in contexts)

    def test_span_widening_is_bounded(self):
        # Widening the redaction span used to walk the whole body per match:
        # 200 matches inside long secret-charset runs took 75s.
        import time
        body = ("-" * 20000 + "AKIAABCDEFGHIJKLMNOP") * 50
        start = time.time()
        indicators = js.extract_secret_indicators(body)
        assert time.time() - start < 10
        assert all("AKIAABCDEFGHIJKLMNOP" not in i["context"] for i in indicators)

    def test_no_credential_survives_into_the_analysis_output(self):
        body = 'const u="https://admin:Sup3rSecret@example.com/api/v1/keys";'
        analysis = js.analyze_javascript_content(body, SAFE_JS_URL, target=SAFE_TARGET)
        assert "Sup3rSecret" not in json.dumps(analysis)


class TestRegressionExtractionCorrectness:
    def test_xhr_open_records_the_url_not_the_http_method(self):
        # WAS: `.open("GET", "/api/v1/x")` captured the first quoted argument,
        # producing the phantom route https://example.com/GET and losing the
        # real URL.
        body = 'var x=new XMLHttpRequest(); x.open("GET", "/api/v1/secret-data"); x.send();'
        urls = {r["url"] for r in js.extract_api_references(body, SAFE_JS_URL, SAFE_TARGET)}
        assert "https://example.com/api/v1/secret-data" in urls
        assert not any(u.endswith("/GET") for u in urls)

    def test_template_literal_static_prefix_extracted(self):
        # WAS: template-literal request paths were missed entirely.
        body = 'fetch(`/api/v1/users/${id}/profile`); fetch(`/api/v2/orders`);'
        refs = {r["url"]: r for r in js.extract_api_references(body, SAFE_JS_URL, SAFE_TARGET)}
        assert "https://example.com/api/v1/users/" in refs
        assert "https://example.com/api/v2/orders" in refs

    def test_template_route_is_labelled_a_template_not_an_endpoint(self):
        body = 'fetch(`/api/v1/users/${id}/profile`);'
        ref = js.extract_api_references(body, SAFE_JS_URL, SAFE_TARGET)[0]
        joined = " ".join(ref["evidence"])
        assert "TEMPLATE" in joined and "not a concrete endpoint" in joined

    def test_template_with_no_static_prefix_is_not_invented(self):
        assert js.extract_api_references('fetch(`${BASE}/api/x`);', SAFE_JS_URL, SAFE_TARGET) == []

    def test_absolute_template_url_truncated_at_interpolation(self):
        refs = js.extract_api_references(
            'const u=`https://example.com/api/items/${id}`;', SAFE_JS_URL, SAFE_TARGET)
        assert [r["url"] for r in refs] == ["https://example.com/api/items/"]

    def test_relative_api_path_respects_scope(self):
        # WAS: _REL_PATH_RE resolved against an out-of-scope script URL and
        # attributed the route to the target anyway.
        assert js.extract_api_references(
            'x="/api/v1/keys"', "https://cdn.other.test/app.js", "example.com") == []

    def test_userinfo_stripped_from_url_and_raw_fields(self):
        refs = js.extract_api_references(
            'const u="https://admin:S3cret@example.com/api/v1/keys";', SAFE_JS_URL, SAFE_TARGET)
        assert "S3cret" not in json.dumps(refs)

    @pytest.mark.parametrize("url,expected", [
        ("https://example.com/api/v1/x", True),
        ("https://example.com/graphql", True),
        ("https://example.com/v2/x", True),
        ("https://example.com/apidocs/index.html", False),
        ("https://example.com/apiary", False),
        ("https://example.com/graphqlish", False),
    ])
    def test_api_path_matched_on_whole_segments(self, url, expected):
        # WAS: a substring test classified /apidocs and /graphqlish as APIs.
        assert js._looks_api_path(url) is expected

    def test_json_stringify_ignores_colons_inside_string_values(self):
        # WAS: {url:"https://x"} produced a phantom parameter named "https".
        hints = js.extract_body_parameter_hints(
            'fetch(u,{body:JSON.stringify({url:"https://x/y",id:1})})')
        assert {h["name"] for h in hints} == {"url", "id"}

    def test_json_stringify_captures_hyphenated_keys_whole(self):
        hints = js.extract_body_parameter_hints('JSON.stringify({"x-api-key": k})')
        assert [h["name"] for h in hints] == ["x-api-key"]

    def test_websocket_scope_is_recorded(self):
        # WAS: a third-party socket was attributed to the target at HIGH.
        body = 'new WebSocket("wss://tracker.evil.test/c"); new WebSocket("wss://example.com/live");'
        by_endpoint = {w["endpoint"]: w for w in
                       js.detect_websocket_references(body, SAFE_JS_URL, SAFE_TARGET)}
        assert by_endpoint["wss://example.com/live"]["in_scope"] is True
        assert by_endpoint["wss://example.com/live"]["confidence"] == js.CONFIDENCE_HIGH
        assert by_endpoint["wss://tracker.evil.test/c"]["in_scope"] is False

    def test_out_of_scope_websocket_still_recorded_never_dropped(self):
        refs = js.detect_websocket_references(
            'new WebSocket("wss://tracker.evil.test/c");', SAFE_JS_URL, SAFE_TARGET)
        assert len(refs) == 1
        assert "outside the scope" in " ".join(refs[0]["evidence"])


class TestRegressionMergingAndConfidence:
    def test_repetition_does_not_inflate_confidence(self):
        # WAS: the same literal repeated 8 times produced 8 evidence entries,
        # which _confidence_from_count promoted to HIGH.
        body = 'var u="https://example.com/internal/thing";' * 8
        ref = js.extract_api_references(body, SAFE_JS_URL, SAFE_TARGET)[0]
        assert len(ref["evidence"]) == 1
        assert ref["occurrences"] == 8
        assert js._confidence_from_count(len(ref["evidence"])) == js.CONFIDENCE_LOW

    def test_distinct_mechanisms_still_raise_confidence(self):
        body = ('const x="https://example.com/api/v1/u"; '
                'fetch("https://example.com/api/v1/u");')
        ref = [r for r in js.extract_api_references(body, SAFE_JS_URL, SAFE_TARGET)
               if r["url"].endswith("/api/v1/u")][0]
        assert len(ref["evidence"]) == 2

    def test_identical_secrets_merged_with_occurrence_count(self):
        indicators = js.extract_secret_indicators('const k="AKIAAAAAAAAAAAAAAAAA";' * 30)
        assert len(indicators) == 1
        assert indicators[0]["occurrences"] == 30

    def test_identical_config_values_merged(self):
        values = js.extract_config_values('apiBaseUrl:"https://example.com/api"\n' * 30)
        assert len(values) == 1 and values[0]["occurrences"] == 30

    def test_identical_localstorage_access_merged(self):
        signals = js.extract_localstorage_signals('localStorage.getItem("tok");' * 50)
        assert len(signals) == 1 and signals[0]["occurrences"] == 50

    def test_identical_postmessage_sends_merged(self):
        signals = js.extract_postmessage_signals('w.postMessage(x,"*");' * 50)
        assert len(signals["sends"]) == 1 and signals["sends"][0]["occurrences"] == 50

    def test_duplicate_input_urls_analysed_once(self, tmp_path):
        # WAS: the same script referenced from several crawled pages was
        # re-fetched and double-persisted, and burned the max_files budget.
        resp = _fake_response(status_code=200, body=b"console.log(1);")
        with mock.patch("requests.get", return_value=resp) as mocked:
            result = js.run_js_analyzer(
                [{"url": SAFE_JS_URL, "source_page": "https://example.com/p1"},
                 {"url": SAFE_JS_URL, "source_page": "https://example.com/p2"}],
                target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                try_implicit_source_map_sibling=False,
            )
        assert mocked.call_count == 1
        assert result["files_requested"] == 1
        assert result["duplicate_references_merged"] == 1
        assert result["results"][0]["also_referenced_by"] == ["https://example.com/p2"]

    def test_max_files_budget_not_spent_on_duplicates(self, tmp_path):
        resp = _fake_response(status_code=200, body=b"console.log(1);")
        with mock.patch("requests.get", return_value=resp):
            result = js.run_js_analyzer(
                [SAFE_JS_URL, SAFE_JS_URL, "https://example.com/other.js"],
                target=SAFE_TARGET, output_dir=str(tmp_path / "output"), max_files=2,
                try_implicit_source_map_sibling=False,
            )
        assert sorted({r["url"] for r in result["results"]}) == [
            "https://example.com/other.js", SAFE_JS_URL]


class TestRegressionClientSideSignalScaling:
    def test_minified_bundle_does_not_explode(self):
        # WAS: every source paired with every sink because a minified bundle
        # is one line, so all matches sat on line 0. A 9.9KB snippet produced
        # 102,400 "possible data flows", growing quadratically.
        import time
        body = ";".join(["var a=location.hash", "b.innerHTML=c", "eval(d)",
                         "e=document.referrer"] * 4000)
        start = time.time()
        signals = js.extract_client_side_signals(body)
        assert time.time() - start < 10
        assert len(signals["possible_data_flows"]) <= 48
        assert all(f["occurrences"] > 1 for f in signals["possible_data_flows"])

    def test_pretty_printed_proximity_behaviour_preserved(self):
        signals = js.extract_client_side_signals("var x = location.hash;\nel.innerHTML = x;")
        flows = signals["possible_data_flows"]
        assert len(flows) == 1
        assert (flows[0]["source_kind"], flows[0]["sink_kind"]) == ("location.hash", "innerHTML")

    def test_distant_source_and_sink_still_not_paired(self):
        body = "var x = location.hash;\n" + ("\n" * 20) + "el.innerHTML = y;"
        assert js.extract_client_side_signals(body)["possible_data_flows"] == []

    def test_line_numbers_are_one_based(self):
        # WAS: 0-based, so evidence reported "line 0" for the first line.
        signals = js.extract_client_side_signals("var x = location.hash;")
        assert signals["sources"][0]["line"] == 1

    def test_flow_evidence_remains_explicitly_heuristic(self):
        signals = js.extract_client_side_signals("var x = location.hash;\nel.innerHTML = x;")
        text = " ".join(signals["possible_data_flows"][0]["evidence"]).lower()
        assert "heuristic" in text and "manual review" in text


class TestRegressionResponseValidation:
    def test_non_2xx_response_is_not_analysed_as_javascript(self, tmp_path):
        # WAS: a 404 HTML error page was parsed as JavaScript, manufacturing
        # js_analyzer_endpoint_reference findings from the links inside it and
        # asserting at HIGH confidence that a JS file had been analysed.
        html = b'<html><a href="https://example.com/api/v1/admin">x</a></html>'
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=404, headers={"Content-Type": "text/html"}, body=html)
        with mock.patch("requests.get", return_value=resp):
            result = js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET,
                                        output_dir=str(output_dir))
        assert result["files_analyzed"] == 0
        assert result["js_data_for_endpoint_discovery"] == []
        assert result["results"][0]["status"] == "not_analyzable"
        records = js.PendingAssetsStore(output_dir=str(output_dir)).all()
        assert not any(r["type"] == "js_analyzer_endpoint_reference" for r in records)
        assert any(r["type"] == "js_analyzer_fetch_failed" for r in records)

    def test_html_soft_404_at_a_script_url_is_not_analysed(self, tmp_path):
        html = b'<html><a href="https://example.com/api/v1/admin">x</a></html>'
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=html)
        with mock.patch("requests.get", return_value=resp):
            result = js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET,
                                        output_dir=str(tmp_path / "output"))
        assert result["results"][0]["status"] == "not_analyzable"
        assert result["js_data_for_endpoint_discovery"] == []

    def test_binary_body_without_content_type_is_sniffed(self):
        assert js._looks_textual(None, "var a=1;\x00\x00") is False
        assert js._looks_textual(None, "�" * 100) is False
        assert js._looks_textual(None, "const s='日本語';") is True

    def test_truncated_body_is_flagged_in_the_evidence(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, body=b"var a=1;" * 200)
        with mock.patch("requests.get", return_value=resp):
            js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(output_dir),
                               max_body_bytes=64, try_implicit_source_map_sibling=False)
        records = js.PendingAssetsStore(output_dir=str(output_dir)).all()
        analysed = [r for r in records if r["type"] == "javascript_file_analyzed"]
        assert analysed and analysed[0]["value"]["body_truncated"] is True
        assert any("truncated" in e for e in analysed[0]["evidence"])


class TestRegressionPersistenceReporting:
    def test_run_level_persistence_errors_are_reported(self, tmp_path):
        # WAS: every run-level _safe_store_add discarded its return value, so
        # a corrupt pending_assets.json produced a run that reported success
        # while nothing reached disk.
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{ not json")
        resp = _fake_response(status_code=200, body=b'fetch("/api/x");')
        with mock.patch("requests.get", return_value=resp):
            result = js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET,
                                        output_dir=str(output_dir),
                                        try_implicit_source_map_sibling=False)
        assert len(result["errors"]) >= 2

    def test_unserialisable_payload_reported_not_raised(self, tmp_path):
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        err = js._safe_store_add(store, js.make_finding("t", "x", {"bad": object()}, [], "LOW"))
        assert err and "not JSON serializable" in err

    def test_batched_write_preserves_other_modules_records(self, tmp_path):
        output_dir = str(tmp_path / "output")
        store = js.PendingAssetsStore(output_dir=output_dir)
        store.add(js.make_finding("first", "t", {}, [], "LOW"))
        other = ed.PendingAssetsStore(output_dir=output_dir)
        other.add(ed.make_finding("endpoint_discovered", "t", {}, [], "LOW"))
        store.add_many([js.make_finding("third", "t", {}, [], "LOW")])
        assert [r["type"] for r in store.all()] == ["first", "endpoint_discovered", "third"]

    def test_large_batch_is_fast(self, tmp_path):
        import time
        store = js.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        body = "\n".join(f"el{i}.innerHTML = x{i};" for i in range(2000))
        analysis = js.analyze_javascript_content(body, SAFE_JS_URL, target=SAFE_TARGET)
        start = time.time()
        result = js.persist_analysis_findings(analysis, SAFE_TARGET, store,
                                              parent_js_url=SAFE_JS_URL)
        assert time.time() - start < 10          # was 53.7s per-finding
        assert len(store.all()) == result["total"]


class TestRegressionSourceMaps:
    def test_implicit_sibling_built_from_the_path(self):
        # WAS: "app.js?v=9f2a1&x=1" + ".map"
        info = js.detect_source_map_reference("var a=1;", "https://example.com/app.js?v=9f2a1&x=1")
        assert info["map_url"] == "https://example.com/app.js.map"
        info = js.detect_source_map_reference("var a=1;", "https://example.com/app.js#frag")
        assert info["map_url"] == "https://example.com/app.js.map"

    def test_last_source_map_reference_wins(self):
        # WAS: a decoy inside a string literal earlier in the bundle won.
        body = ('var s="//# sourceMappingURL=decoy.js.map";\ncode();\n'
                '//# sourceMappingURL=real.js.map')
        info = js.detect_source_map_reference(body, SAFE_JS_URL)
        assert info["map_url"] == "https://example.com/static/real.js.map"

    def test_quote_delimiter_trimmed_from_reference(self):
        info = js.detect_source_map_reference(
            'var s="//# sourceMappingURL=only.js.map";', SAFE_JS_URL, try_implicit_sibling=False)
        assert info["map_url"] == "https://example.com/static/only.js.map"

    def test_inline_data_uri_source_map_decoded_without_a_request(self, tmp_path):
        # WAS: reported as "out_of_scope" (a capability gap dressed up as a
        # scope decision) and the whole data URI was persisted as an id.
        import base64
        payload = base64.b64encode(
            b'{"version":3,"sources":["src/secret.js"],"sourcesContent":["const INTERNAL=1;"]}'
        ).decode()
        body = ("console.log(1);\n//# sourceMappingURL=data:application/json;base64,"
                + payload).encode()
        output_dir = tmp_path / "output"
        with mock.patch("requests.get", return_value=_fake_response(status_code=200, body=body)) as m:
            result = js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET,
                                        output_dir=str(output_dir))
        assert m.call_count == 1                                  # no map fetch
        info = result["results"][0]["source_map"]
        assert info["fetch_status"] == "found" and info["parse_status"] == "parsed"
        assert info["reconstructed_sources"] == ["src/secret.js"]
        assert "<inline source map" in info["map_url"]
        records = js.PendingAssetsStore(output_dir=str(output_dir)).all()
        assert all(len(json.dumps(r)) < 20000 for r in records)

    @pytest.mark.parametrize("uri", [
        "data:application/json;base64,",
        "data:application/json;base64,!!!!",
        "data:application/json,%7Bnope",
    ])
    def test_malformed_inline_source_maps_degrade(self, uri):
        result = js.fetch_source_map(uri)
        assert result["status"] in ("error", "found")
        if result["status"] == "found":
            assert js.parse_source_map(result["body"])["status"] in ("malformed", "empty")

    def test_oversized_inline_source_map_rejected(self):
        result = js.fetch_source_map("data:application/json;base64," + "A" * 6_000_000)
        assert result["status"] == "error" and "exceeds" in result["error"]

    def test_index_source_map_sections_are_flattened(self):
        # WAS: an index map parsed "successfully" with zero sources and
        # reconstructed nothing, silently losing every original file.
        raw = json.dumps({"version": 3, "sections": [
            {"offset": {"line": 0, "column": 0},
             "map": {"version": 3, "sources": ["src/a.js"], "sourcesContent": ["const A=1;"]}},
            {"offset": {"line": 1, "column": 0},
             "map": {"version": 3, "sources": ["src/b.js"], "sourcesContent": ["const B=2;"]}},
        ]})
        parsed = js.parse_source_map(raw)
        assert parsed["is_index_map"] is True
        assert parsed["sources"] == ["src/a.js", "src/b.js"]
        assert [r["source"] for r in js.reconstruct_original_sources(parsed)] == \
            ["src/a.js", "src/b.js"]

    def test_malformed_sections_do_not_raise(self):
        raw = json.dumps({"version": 3, "sections": [
            {"map": None}, "nope", {"map": {"sources": [1, 2, "ok"], "sourcesContent": ["x"]}}]})
        assert js.parse_source_map(raw)["sources"] == ["ok"]

    @pytest.mark.parametrize("payload", [
        "[" * 30000 + "]" * 30000,
        '{"a":' * 50000 + "1" + "}" * 50000,
    ])
    def test_deeply_nested_source_map_degrades_instead_of_raising(self, payload):
        # WAS: RecursionError (a RuntimeError, not a ValueError) escaped
        # parse_source_map and aborted the whole run.
        assert js.parse_source_map(payload)["status"] == "malformed"

    def test_deeply_nested_source_map_does_not_abort_a_run(self, tmp_path):
        js_resp = _fake_response(status_code=200,
                                 body=b'fetch("/api/x");\n//# sourceMappingURL=app.js.map')
        map_resp = _fake_response(status_code=200,
                                  headers={"Content-Type": "application/json"},
                                  body=(b"[" * 30000 + b"]" * 30000))
        with mock.patch("requests.get", side_effect=[js_resp, map_resp]):
            result = js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET,
                                        output_dir=str(tmp_path / "output"))
        assert result["files_analyzed"] == 1
        assert result["results"][0]["source_map"]["parse_status"] == "malformed"

    def test_source_map_scope_falls_back_to_the_scripts_own_host(self, tmp_path):
        # WAS: with target=None no scope check ran at all, so an explicit
        # sourceMappingURL on a third-party host was fetched — contradicting
        # this module's own SECURITY BOUNDARIES.
        body = b'console.log(1);\n//# sourceMappingURL=https://evil-cdn.attacker.test/app.js.map'
        with mock.patch("requests.get",
                        return_value=_fake_response(status_code=200, body=body)) as mocked:
            result = js.run_js_analyzer([SAFE_JS_URL], target=None,
                                        output_dir=str(tmp_path / "output"))
        assert [c.args[0] for c in mocked.call_args_list] == [SAFE_JS_URL]
        assert result["results"][0]["source_map"]["fetch_status"] == "out_of_scope"

    def test_many_reconstructed_sources_persist_quickly(self, tmp_path):
        import time
        raw = json.dumps({"version": 3,
                          "sources": [f"src/f{i}.js" for i in range(2000)],
                          "sourcesContent": [f'fetch("/api/gen/{i}");' for i in range(2000)]})
        js_resp = _fake_response(status_code=200, body=b'a=1;\n//# sourceMappingURL=app.js.map')
        map_resp = _fake_response(status_code=200, headers={"Content-Type": "application/json"},
                                  body=raw.encode())
        start = time.time()
        with mock.patch("requests.get", side_effect=[js_resp, map_resp]):
            result = js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET,
                                        output_dir=str(tmp_path / "output"))
        assert time.time() - start < 20            # was ~46s at this size
        assert len(result["results"][0]["source_map"]["reconstructed_sources"]) == 2000


class TestRegressionEmptyAndNegativeResults:
    def test_zero_byte_script_is_analysed_and_remembered(self, tmp_path):
        output_dir = tmp_path / "output"
        with mock.patch("requests.get",
                        return_value=_fake_response(status_code=200, body=b"")):
            result = js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET,
                                        output_dir=str(output_dir),
                                        try_implicit_source_map_sibling=False)
        assert result["files_analyzed"] == 1
        types = {r["type"] for r in js.PendingAssetsStore(output_dir=str(output_dir)).all()}
        assert "js_analyzer_checked_no_findings" in types

    def test_binary_response_leaves_a_record(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, headers={"Content-Type": "image/png"},
                              body=b"\x89PNG\r\n")
        with mock.patch("requests.get", return_value=resp):
            js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(output_dir))
        assert len(js.PendingAssetsStore(output_dir=str(output_dir)).all()) == 1


class TestRegressionHostileInputs:
    @pytest.mark.parametrize("body", [
        "fetch(`" + "/a" * 20000,
        "`" * 200000,
        "https://example.com/" + "a" * 500000,
        'x.open("GET","/' + "a" * 50000 + '")',
        "JSON.stringify({" + "a:1," * 20000 + "}",
        ":" * 200000,
    ])
    def test_pathological_bodies_complete_quickly(self, body):
        import time
        start = time.time()
        js.analyze_javascript_content(body, SAFE_JS_URL, target=SAFE_TARGET)
        assert time.time() - start < 20

    @pytest.mark.parametrize("js_files", [
        None, [], [None], [{}], [{"url": None}], [12345], [{"value": {"url": None}}],
        ["", "   ", "ftp://example.com/a.js", "javascript:alert(1)"],
    ])
    def test_malformed_input_lists_never_raise(self, js_files, tmp_path):
        result = js.run_js_analyzer(js_files, target=SAFE_TARGET,
                                    output_dir=str(tmp_path / "output"))
        json.dumps(result)
        assert result["files_analyzed"] == 0

    def test_redirect_loop_is_bounded(self, tmp_path):
        loop = _fake_response(status_code=302, headers={"Location": SAFE_JS_URL})
        with mock.patch("requests.get", return_value=loop) as mocked:
            result = js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET,
                                        output_dir=str(tmp_path / "output"))
        assert mocked.call_count == js.DEFAULT_MAX_REDIRECT_HOPS
        assert result["results"][0]["status"] == "fetch_failed"

    def test_large_hostile_bundle_produces_bounded_output(self, tmp_path):
        import time
        unit = ('var a=location.hash;b.innerHTML=a;eval(a);fetch("/api/v1/x");'
                'localStorage.setItem("k","v");new WebSocket("wss://example.com/s");'
                'const K="AKIAABCDEFGHIJKLMNOP";')
        body = (unit * (1_000_000 // len(unit))).encode()
        output_dir = tmp_path / "output"
        start = time.time()
        with mock.patch("requests.get",
                        return_value=_fake_response(status_code=200, body=body)):
            js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(output_dir),
                               max_body_bytes=1_000_000, try_implicit_source_map_sibling=False)
        assert time.time() - start < 30
        records = js.PendingAssetsStore(output_dir=str(output_dir)).all()
        assert len(records) < 100
        assert "AKIAABCDEFGHIJKLMNOP" not in json.dumps(records)

    def test_line_excerpt_evidence_does_not_leak_a_nearby_secret(self):
        # Found by attacking the redaction fix: the source/sink evidence
        # excerpt is raw source text, and on a minified bundle "the line" is
        # the whole file — so a credential sitting a few characters from a sink
        # was persisted verbatim even though extract_secret_indicators had
        # redacted the very same value.
        body = 'el.innerHTML=x;const K="AKIAABCDEFGHIJKLMNOP";'
        signals = js.extract_client_side_signals(body)
        assert "AKIAABCDEFGHIJKLMNOP" not in json.dumps(signals)
        assert signals["sinks"]                       # still detected

    def test_reconstructed_source_preview_does_not_leak_a_secret(self, tmp_path):
        # An original source recovered from a source map is exactly where a
        # hard-coded credential lives; its 500-char preview is persisted.
        raw = json.dumps({"version": 3, "sources": ["src/config.js"],
                          "sourcesContent": ['const AWS="AKIAABCDEFGHIJKLMNOP";']})
        output_dir = tmp_path / "output"
        js_resp = _fake_response(status_code=200, body=b'a=1;\n//# sourceMappingURL=app.js.map')
        map_resp = _fake_response(status_code=200, headers={"Content-Type": "application/json"},
                                  body=raw.encode())
        with mock.patch("requests.get", side_effect=[js_resp, map_resp]):
            js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET, output_dir=str(output_dir))
        records = js.PendingAssetsStore(output_dir=str(output_dir)).all()
        assert any(r["type"] == "js_analyzer_reconstructed_source" for r in records)
        assert "AKIAABCDEFGHIJKLMNOP" not in json.dumps(records)

    def test_config_evidence_excerpt_is_redacted_but_the_value_is_kept(self):
        # The boundary this pins: an `evidence` string is an excerpt of raw
        # source and can contain anything, so it is redacted. The `value` is
        # the finding's substance and extract_config_values is defined over
        # DELIBERATELY PUBLIC values (a Stripe publishable key, a Sentry DSN's
        # public key, an API base URL) — masking it would destroy the
        # config-detection responsibility. A key-shaped string is still
        # reported, redacted, through the secret-indicator channel.
        body = 'apiBaseUrl:"https://x/AKIAABCDEFGHIJKLMNOP"'
        values = js.extract_config_values(body)
        assert "AKIAABCDEFGHIJKLMNOP" not in json.dumps(values[0]["evidence"])
        assert values[0]["value"] == "https://x/AKIAABCDEFGHIJKLMNOP"

        indicators = js.extract_secret_indicators(body)
        assert any(i["pattern_name"] == "aws_access_key_id" for i in indicators)
        assert "AKIAABCDEFGHIJKLMNOP" not in json.dumps(indicators)

    def test_publishable_config_values_are_not_masked_away(self):
        values = js.extract_config_values('pk_live_51ABCDEFGHIJKLMNOPQRSTUV')
        assert values[0]["value"] == "pk_live_51ABCDEFGHIJKLMNOPQRSTUV"

    def test_real_javascript_misserved_as_text_html_is_still_analysed(self, tmp_path):
        # The HTML guard is judged on the BODY, not on Content-Type alone: a
        # text/html header at a script URL is usually a soft-404, but it is
        # also what a misconfigured server sends for a real script. Rejecting
        # on the header alone would turn a false positive into a false
        # negative.
        body = b'fetch("/api/v1/real-endpoint");'
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=body)
        with mock.patch("requests.get", return_value=resp):
            result = js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET,
                                        output_dir=str(tmp_path / "output"),
                                        try_implicit_source_map_sibling=False)
        assert result["files_analyzed"] == 1
        assert len(result["js_data_for_endpoint_discovery"]) == 1

    @pytest.mark.parametrize("body", [
        b"<!DOCTYPE html><html><body>404</body></html>",
        b"\n  <html><head><title>Not Found</title></head></html>",
        b"\xef\xbb\xbf<!doctype html><html></html>",
    ])
    def test_html_documents_are_rejected(self, body, tmp_path):
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=body)
        with mock.patch("requests.get", return_value=resp):
            result = js.run_js_analyzer([SAFE_JS_URL], target=SAFE_TARGET,
                                        output_dir=str(tmp_path / "output"))
        assert result["results"][0]["status"] == "not_analyzable"
