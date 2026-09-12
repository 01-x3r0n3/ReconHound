"""
Tests for reconhound/endpoint_discovery.py (ReconHound Module 10, per
context.md's build order — catalog item 10, build-order position 5).

Run with:  ./.venv/bin/python -m pytest tests/test_endpoint_discovery.py -v

All tests mock the `requests.get` boundary so the suite is deterministic
and offline-safe; no external network access is required or performed
anywhere in this file. Tests that need custom wordlists write small
fixture wordlist files under tmp_path rather than depending on the size or
exact contents of the real wordlists/ directory (those are covered
separately by TestRealWordlists).
"""

import json
import os
import time
import sys
from unittest import mock

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import endpoint_discovery as ed


SAFE_URL = "https://example.com/"
SAFE_TARGET = "example.com"


def _fake_response(status_code=200, headers=None, body=b"", final_url=None):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = dict(headers or {})
    resp.encoding = "utf-8"
    resp.content = body
    resp.url = final_url or SAFE_URL
    resp.elapsed.total_seconds.return_value = 0.02
    resp.raw.read.return_value = body
    return resp


def _write_wordlist(tmp_path, name, lines):
    d = tmp_path / "wordlists"
    d.mkdir(exist_ok=True)
    (d / name).write_text("\n".join(lines) + "\n")
    return str(d)


def _all_404(url, **kwargs):
    """Default fake_get: everything is a 404, including the soft-404 baseline probe."""
    return _fake_response(404, body=b"not found")


# ---------------------------------------------------------------------------
# validate_endpoint_target (scope enforcement)
# ---------------------------------------------------------------------------

class TestValidateEndpointTarget:
    def test_accepts_https_url(self):
        assert ed.validate_endpoint_target("https://example.com/path") == "https://example.com/path"

    def test_accepts_in_scope_subdomain(self):
        assert ed.validate_endpoint_target("https://api.example.com/", target="example.com")

    def test_rejects_out_of_scope_host(self):
        with pytest.raises(ed.ScopeError):
            ed.validate_endpoint_target("https://evil.com/", target="example.com")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(ed.ScopeError):
            ed.validate_endpoint_target("ftp://example.com/")

    def test_rejects_missing_hostname(self):
        with pytest.raises(ed.ScopeError):
            ed.validate_endpoint_target("https:///path")

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(ed.ScopeError):
            ed.validate_endpoint_target(bad)

    def test_allows_ip_literal_host_without_scope_check(self):
        assert ed.validate_endpoint_target("http://93.184.216.34/", target="example.com")


# ---------------------------------------------------------------------------
# PendingAssetsStore / make_finding / make_parameter_finding
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_finding_structure_and_source(self):
        finding = ed.make_finding("endpoint_discovered", SAFE_URL, {"a": 1}, ["e"], ed.CONFIDENCE_HIGH)
        assert finding["source"] == "endpoint_discovery.py"
        assert finding["metadata"] == {}
        json.dumps(finding)

    def test_parameter_finding_structure(self):
        param = {
            "name": "id", "location": "query", "method": "GET", "endpoint": "/users",
            "data_type": "integer", "source": "url_query_string", "confidence": ed.CONFIDENCE_MEDIUM,
            "evidence": ["observed"],
        }
        finding = ed.make_parameter_finding(param, SAFE_TARGET)
        assert finding["type"] == "endpoint_parameter"
        assert finding["value"]["name"] == "id"
        assert finding["value"]["location"] == "query"
        assert finding["value"]["method"] == "GET"
        assert finding["value"]["endpoint"] == "/users"
        assert finding["value"]["data_type"] == "integer"
        assert finding["value"]["source"] == "url_query_string"
        assert finding["metadata"]["name"] == "id"
        json.dumps(finding)

    def test_store_preserves_prior_data(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{"type": "dns_record", "source": "passive_recon.py"}]
        pending.write_text(json.dumps(pre_existing))

        store = ed.PendingAssetsStore(output_dir=str(output_dir))
        store.add(ed.make_finding("endpoint_discovered", SAFE_URL, {}, ["e"], ed.CONFIDENCE_HIGH))
        assert store.all() == pre_existing + [store.all()[-1]]

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = ed.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(ed.PersistenceError):
            store.add(ed.make_finding("endpoint_discovered", SAFE_URL, {}, ["e"], ed.CONFIDENCE_HIGH))

    def test_safe_store_add_recovers_from_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = ed.PendingAssetsStore(output_dir=str(output_dir))
        err = ed._safe_store_add(store, ed.make_finding("endpoint_discovered", SAFE_URL, {}, ["e"], ed.CONFIDENCE_HIGH))
        assert err is not None
        assert "corrupt" in err

    def test_safe_store_add_noop_without_store(self):
        assert ed._safe_store_add(None, ed.make_finding("x", SAFE_URL, {}, [], ed.CONFIDENCE_LOW)) is None


# ---------------------------------------------------------------------------
# fetch_url
# ---------------------------------------------------------------------------

class TestFetchUrl:
    def test_successful_fetch(self):
        resp = _fake_response(200, headers={"Content-Type": "text/html"}, body=b"<html>hi</html>")
        with mock.patch("requests.get", return_value=resp):
            result = ed.fetch_url(SAFE_URL)
        assert result["status"] == "found"
        assert result["status_code"] == 200
        assert result["body"] == "<html>hi</html>"
        assert result["body_truncated"] is False

    def test_body_truncated_when_over_limit(self):
        body = b"a" * 100
        resp = _fake_response(200, body=body)
        with mock.patch("requests.get", return_value=resp):
            result = ed.fetch_url(SAFE_URL, max_body_bytes=10)
        assert result["body_truncated"] is True
        assert len(result["body"]) == 10

    def test_timeout_error(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout("timed out")):
            result = ed.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_connection_error(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = ed.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert "connection error" in result["error"]

    def test_generic_request_exception(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.RequestException("boom")):
            result = ed.fetch_url(SAFE_URL)
        assert result["status"] == "error"

    def test_does_not_follow_redirects(self):
        resp = _fake_response(301, headers={"Location": "/new"})
        captured = {}

        def fake_get(url, **kwargs):
            captured.update(kwargs)
            return resp

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.fetch_url(SAFE_URL)
        assert captured["allow_redirects"] is False
        assert result["status_code"] == 301


# ---------------------------------------------------------------------------
# classify_response (avoids treating every non-404 as confirmed content)
# ---------------------------------------------------------------------------

class TestClassifyResponse:
    def test_404_is_not_found(self):
        dtype, conf, _ = ed.classify_response({"status_code": 404, "body": ""}, None)
        assert dtype == "not_found"
        assert conf == ed.CONFIDENCE_HIGH

    def test_200_without_baseline_is_confirmed_but_capped(self):
        # Behaviour change (deliberate): without a usable catch-all baseline
        # there is no reference point for "what this host returns for a path
        # that does not exist", so a soft-404 cannot be ruled out and HIGH is
        # unearned. Previously every 200 was HIGH whenever the baseline probe
        # had merely failed — a single timed-out probe turned an entire run's
        # output into false HIGH-confidence discoveries.
        dtype, conf, notes = ed.classify_response({"status_code": 200, "body": "real content"}, None)
        assert dtype == "content_confirmed"
        assert conf == ed.CONFIDENCE_MEDIUM
        assert any("baseline" in n for n in notes)

    def test_200_with_usable_baseline_is_high_confidence(self):
        baseline = {"available": True, "usable": True, "status_codes": [404],
                    "body_hashes": [ed._content_signature("nope")[1]],
                    "structural_hashes": [], "content_lengths": [4]}
        dtype, conf, _ = ed.classify_response({"status_code": 200, "body": "real content"}, baseline)
        assert dtype == "content_confirmed"
        assert conf == ed.CONFIDENCE_HIGH

    def test_200_matching_soft_404_baseline_is_flagged(self):
        baseline = {"available": True, "status_code": 200, "content_length": 9, "body_hash": ed._content_signature("not found")[1]}
        dtype, conf, notes = ed.classify_response({"status_code": 200, "body": "not found"}, baseline)
        assert dtype == "possible_soft_404_match"
        assert conf == ed.CONFIDENCE_LOW
        assert notes

    def test_200_different_from_soft_404_baseline_is_confirmed(self):
        baseline = {"available": True, "status_code": 200, "content_length": 9, "body_hash": ed._content_signature("not found")[1]}
        dtype, conf, _ = ed.classify_response({"status_code": 200, "body": "a" * 5000}, baseline)
        assert dtype == "content_confirmed"

    def test_redirect_classified(self):
        # Confidence is capped without a baseline for the same reason as the
        # 200 case: a blanket "everything redirects to /login" catch-all is
        # indistinguishable from a real redirect until the root's not-found
        # behaviour is known.
        dtype, conf, _ = ed.classify_response({"status_code": 302, "body": ""}, None)
        assert dtype == "redirect"
        assert conf == ed.CONFIDENCE_LOW

    def test_redirect_with_baseline_is_medium(self):
        baseline = {"available": True, "usable": True, "status_codes": [404],
                    "body_hashes": [ed._content_signature("nope")[1]],
                    "structural_hashes": [], "content_lengths": [4]}
        dtype, conf, _ = ed.classify_response({"status_code": 302, "body": ""}, baseline)
        assert dtype == "redirect"
        assert conf == ed.CONFIDENCE_MEDIUM

    @pytest.mark.parametrize("status", [401, 403])
    def test_access_restricted_classified(self, status):
        dtype, conf, _ = ed.classify_response({"status_code": status, "body": ""}, None)
        assert dtype == "access_restricted"

    def test_method_not_allowed_classified(self):
        dtype, _, _ = ed.classify_response({"status_code": 405, "body": ""}, None)
        assert dtype == "method_not_allowed"

    def test_server_error_classified_low_confidence(self):
        dtype, conf, _ = ed.classify_response({"status_code": 500, "body": ""}, None)
        assert dtype == "server_error_response"
        assert conf == ed.CONFIDENCE_LOW

    def test_rate_limited_classified(self):
        dtype, conf, notes = ed.classify_response({"status_code": 429, "body": ""}, None)
        assert dtype == "rate_limited"
        assert notes

    def test_no_status_code_is_error(self):
        dtype, conf, _ = ed.classify_response({"status_code": None, "body": ""}, None)
        assert dtype == "error"

    def test_unexpected_status_classified(self):
        dtype, _, _ = ed.classify_response({"status_code": 999, "body": ""}, None)
        assert dtype == "unexpected_status"


# ---------------------------------------------------------------------------
# load_wordlist / select_wordlists_for_technology (technology-aware
# wordlist selection)
# ---------------------------------------------------------------------------

class TestWordlists:
    def test_load_wordlist_strips_comments_and_blanks(self, tmp_path):
        d = _write_wordlist(tmp_path, "test.txt", ["# comment", "", "admin/", "config.php", "admin/"])
        entries = ed.load_wordlist("test.txt", wordlists_dir=d)
        assert entries == ["admin/", "config.php"]  # dedup, order preserved, comment/blank dropped

    def test_load_wordlist_missing_file_raises(self, tmp_path):
        with pytest.raises(ed.WordlistError):
            ed.load_wordlist("does_not_exist.txt", wordlists_dir=str(tmp_path))

    def test_load_wordlist_empty_file_raises(self, tmp_path):
        d = _write_wordlist(tmp_path, "empty.txt", ["# only a comment"])
        with pytest.raises(ed.WordlistError):
            ed.load_wordlist("empty.txt", wordlists_dir=d)

    def test_select_wordlists_none_when_no_technology(self):
        assert ed.select_wordlists_for_technology(None) == []
        assert ed.select_wordlists_for_technology({}) == []

    def test_select_wordlists_wordpress(self):
        result = ed.select_wordlists_for_technology({"cms": "WordPress"})
        assert result == [("wordpress_paths.txt", "wordpress")]

    def test_select_wordlists_laravel(self):
        result = ed.select_wordlists_for_technology({"framework": "Laravel"})
        assert ("laravel_paths.txt", "laravel") in result

    def test_select_wordlists_django(self):
        result = ed.select_wordlists_for_technology({"frameworks": ["Django REST"]})
        assert ("django_paths.txt", "django") in result

    def test_select_wordlists_unrelated_technology_selects_nothing(self):
        result = ed.select_wordlists_for_technology({"server": "nginx", "cms": "Ghost"})
        assert result == []

    def test_select_wordlists_multiple_matches(self):
        result = ed.select_wordlists_for_technology({"cms": "wordpress", "framework": "django"})
        names = {w for w, _ in result}
        assert names == {"wordpress_paths.txt", "django_paths.txt"}


class TestRealWordlists:
    """Sanity-check the actual wordlists/ files shipped with the repo."""

    @pytest.mark.parametrize("name", [
        "directories.txt", "api_endpoints.txt",
        "wordpress_paths.txt", "laravel_paths.txt", "django_paths.txt",
    ])
    def test_real_wordlist_loads(self, name):
        entries = ed.load_wordlist(name)
        assert len(entries) > 5
        assert all(isinstance(e, str) and e for e in entries)

    def test_directories_txt_has_both_dir_and_file_entries(self):
        entries = ed.load_wordlist("directories.txt")
        kinds = {ed._entry_kind(e) for e in entries}
        assert kinds == {"directory", "file"}


# ---------------------------------------------------------------------------
# Parameter discovery + parameter intelligence (query/body/path/header/form)
# ---------------------------------------------------------------------------

class TestExtractQueryParameters:
    def test_extracts_query_params(self):
        params = ed.extract_query_parameters("https://example.com/search?q=test&page=2")
        names = {p["name"]: p for p in params}
        assert names["q"]["location"] == "query"
        assert names["q"]["data_type"] == "string"
        assert names["page"]["data_type"] == "integer"
        assert names["q"]["source"] == "url_query_string"
        assert names["q"]["endpoint"] == "/search"

    def test_no_query_string_returns_empty(self):
        assert ed.extract_query_parameters("https://example.com/search") == []

    def test_infer_data_type_variants(self):
        assert ed._infer_data_type("42") == "integer"
        assert ed._infer_data_type("3.14") == "float"
        assert ed._infer_data_type("true") == "boolean"
        assert ed._infer_data_type("a@b.com") == "email"
        assert ed._infer_data_type("550e8400-e29b-41d4-a716-446655440000") == "uuid"
        assert ed._infer_data_type("hello") == "string"
        assert ed._infer_data_type("") == "unknown"


class TestInferPathParameters:
    def test_numeric_segment_flagged(self):
        params = ed.infer_path_parameters("https://example.com/api/v1/users/42")
        assert any(p["location"] == "path" and p["data_type"] == "integer" for p in params)
        for p in params:
            assert p["confidence"] == ed.CONFIDENCE_LOW  # inference, not certainty

    def test_uuid_segment_flagged(self):
        params = ed.infer_path_parameters("https://example.com/orders/550e8400-e29b-41d4-a716-446655440000")
        assert any(p["data_type"] == "uuid" for p in params)

    def test_static_path_no_params(self):
        assert ed.infer_path_parameters("https://example.com/about/team") == []


class TestExtractFormParameters:
    def test_get_form_is_query_location(self):
        body = '<form method="GET" action="/search"><input name="q" type="text"></form>'
        params = ed.extract_form_parameters(body, SAFE_URL)
        assert params[0]["location"] == "query"
        assert params[0]["method"] == "GET"
        assert params[0]["endpoint"] == "/search"

    def test_post_form_is_body_location(self):
        body = '<form method="POST" action="/login"><input name="username"><input name="password" type="password"></form>'
        params = ed.extract_form_parameters(body, SAFE_URL)
        assert {p["name"] for p in params} == {"username", "password"}
        assert all(p["location"] == "body" for p in params)

    def test_field_type_data_type_mapping(self):
        body = (
            '<form method="POST" action="/x">'
            '<input name="age" type="number">'
            '<input name="subscribe" type="checkbox">'
            '<input name="resume" type="file">'
            "</form>"
        )
        params = {p["name"]: p for p in ed.extract_form_parameters(body, SAFE_URL)}
        assert params["age"]["data_type"] == "integer"
        assert params["subscribe"]["data_type"] == "boolean"
        assert params["resume"]["data_type"] == "file"

    def test_no_forms_returns_empty(self):
        assert ed.extract_form_parameters("<html><body>no forms here</body></html>", SAFE_URL) == []

    def test_empty_body_returns_empty(self):
        assert ed.extract_form_parameters("", SAFE_URL) == []
        assert ed.extract_form_parameters(None, SAFE_URL) == []

    def test_field_without_name_ignored(self):
        body = '<form method="POST" action="/x"><input type="submit" value="Go"></form>'
        assert ed.extract_form_parameters(body, SAFE_URL) == []

    def test_malformed_html_does_not_raise(self):
        # Deliberately broken/garbage markup — html.parser must degrade gracefully.
        body = "<form method<><POST action=/x><input name="
        assert ed.extract_form_parameters(body, SAFE_URL) == []


class TestExtractHeaderParameterHints:
    def test_known_header_token_referenced_in_body(self):
        body = "Send your request with the X-Api-Key header set."
        params = ed.extract_header_parameter_hints(body, {})
        assert any(p["name"] == "X-Api-Key" and p["location"] == "header" for p in params)
        assert all(p["confidence"] == ed.CONFIDENCE_LOW for p in params if p["source"] == "content_reference")

    def test_www_authenticate_challenge_detected(self):
        params = ed.extract_header_parameter_hints("", {"WWW-Authenticate": "Basic realm=\"x\""})
        assert any(p["name"] == "Authorization" for p in params)

    def test_no_hints_found(self):
        assert ed.extract_header_parameter_hints("just some text", {}) == []


class TestDiscoverParameters:
    def test_combines_query_and_form_and_path(self):
        body = '<form method="POST" action="/checkout"><input name="card_number"></form>'
        result = ed.discover_parameters(
            "https://example.com/checkout/42?promo=SAVE10",
            body=body, headers={"Content-Type": "text/html"},
        )
        names = {p["name"] for p in result["parameters"]}
        assert "promo" in names
        assert "card_number" in names
        assert any(p["location"] == "path" for p in result["parameters"])

    def test_fetches_live_when_body_not_supplied(self):
        resp = _fake_response(200, headers={"Content-Type": "text/html"}, body=b'<form><input name="q"></form>')
        with mock.patch("requests.get", return_value=resp):
            result = ed.discover_parameters(SAFE_URL)
        assert result["status"] == "found"
        assert any(p["name"] == "q" for p in result["parameters"])

    def test_fetch_error_reported(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("down")):
            result = ed.discover_parameters(SAFE_URL)
        assert result["status"] == "error"
        assert result["parameters"] == []

    def test_binary_content_not_parsed_for_forms(self):
        result = ed.discover_parameters(
            "https://example.com/image.png",
            body="\x00\x01\x02binarydata", headers={"Content-Type": "image/png"},
        )
        assert result["parameters"] == []

    def test_persists_when_store_given(self, tmp_path):
        store = ed.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        ed.discover_parameters(
            "https://example.com/search?q=1", body="<html></html>",
            headers={"Content-Type": "text/html"}, store=store,
        )
        assert any(f["type"] == "endpoint_parameter" for f in store.all())


# ---------------------------------------------------------------------------
# extract_link_candidates (feeds recursive discovery + API discovery from
# evidence in already-fetched pages)
# ---------------------------------------------------------------------------

class TestExtractLinkCandidates:
    def test_extracts_href_and_src(self):
        body = '<a href="/products">Products</a><script src="/static/app.js"></script>'
        links = ed.extract_link_candidates(body, SAFE_URL)
        assert "https://example.com/products" in links
        assert "https://example.com/static/app.js" in links

    def test_extracts_fetch_call(self):
        body = '<script>fetch("/api/v1/orders").then(r => r.json())</script>'
        links = ed.extract_link_candidates(body, SAFE_URL)
        assert "https://example.com/api/v1/orders" in links

    def test_extracts_quoted_api_path(self):
        body = 'var endpoint = "/graphql/internal"; doStuff(endpoint);'
        links = ed.extract_link_candidates(body, SAFE_URL)
        assert "https://example.com/graphql/internal" in links

    def test_filters_out_of_scope_links(self):
        body = '<a href="https://evil.com/steal">click</a>'
        links = ed.extract_link_candidates(body, SAFE_URL, target=SAFE_TARGET)
        assert links == []

    def test_allows_in_scope_subdomain(self):
        body = '<a href="https://cdn.example.com/x.js">x</a>'
        links = ed.extract_link_candidates(body, SAFE_URL, target=SAFE_TARGET)
        assert "https://cdn.example.com/x.js" in links

    def test_ignores_javascript_and_mailto_and_fragment(self):
        body = '<a href="javascript:void(0)">x</a><a href="mailto:a@b.com">y</a><a href="#top">z</a>'
        assert ed.extract_link_candidates(body, SAFE_URL) == []

    def test_empty_body_returns_empty(self):
        assert ed.extract_link_candidates("", SAFE_URL) == []
        assert ed.extract_link_candidates(None, SAFE_URL) == []

    def test_malformed_html_falls_back_to_regex_only(self):
        body = '<a href<>"/broken><script>fetch("/api/status")</script>'
        links = ed.extract_link_candidates(body, SAFE_URL)
        assert "https://example.com/api/status" in links


# ---------------------------------------------------------------------------
# Historical parameter correlation (wayback_intel.py boundary)
# ---------------------------------------------------------------------------

class TestCorrelateHistoricalParameters:
    def test_no_historical_data_returns_empty(self):
        result = ed.correlate_historical_parameters([], None, target=SAFE_TARGET)
        assert result["endpoints"] == []
        assert result["parameters"] == []

    def test_historical_endpoint_marked_not_currently_verified(self):
        historical = [{"url": "https://example.com/old-api", "evidence": ["seen in wayback snapshot 2019"]}]
        result = ed.correlate_historical_parameters([], historical, target=SAFE_TARGET)
        assert result["endpoints"][0]["currently_verified"] is False
        assert result["endpoints"][0]["confidence"] == ed.CONFIDENCE_LOW
        assert result["endpoints"][0]["historical"] is True

    def test_historical_endpoint_marked_currently_verified_when_seen_live(self):
        current = [{"url": "https://example.com/api/status", "path": "/api/status"}]
        historical = [{"url": "https://example.com/api/status"}]
        result = ed.correlate_historical_parameters(current, historical, target=SAFE_TARGET)
        assert result["endpoints"][0]["currently_verified"] is True
        assert result["endpoints"][0]["confidence"] == ed.CONFIDENCE_MEDIUM

    def test_historical_parameters_extracted_and_capped_low_confidence(self):
        historical = [{
            "url": "https://example.com/legacy",
            "parameters": [{"name": "debug", "location": "query", "data_type": "boolean"}],
        }]
        result = ed.correlate_historical_parameters([], historical, target=SAFE_TARGET)
        assert result["parameters"][0]["name"] == "debug"
        assert result["parameters"][0]["confidence"] == ed.CONFIDENCE_LOW
        assert result["parameters"][0]["historical"] is True

    def test_malformed_entries_skipped_gracefully(self):
        historical = ["not a dict", {}, {"parameters": "not a list"}, None]
        result = ed.correlate_historical_parameters([], historical, target=SAFE_TARGET)
        assert result["endpoints"] == []
        assert result["parameters"] == []

    def test_persists_when_store_given(self, tmp_path):
        store = ed.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        historical = [{"url": "https://example.com/legacy"}]
        ed.correlate_historical_parameters([], historical, target=SAFE_TARGET, store=store)
        assert any(f["type"] == "historical_endpoint_reference" for f in store.all())


# ---------------------------------------------------------------------------
# JavaScript parameter correlation (js_analyzer.py boundary)
# ---------------------------------------------------------------------------

class TestCorrelateJavascriptParameters:
    def test_no_js_data_returns_empty(self):
        result = ed.correlate_javascript_parameters([], None, target=SAFE_TARGET)
        assert result["endpoints"] == []

    def test_js_endpoint_defaults_to_medium_confidence(self):
        js_data = [{"url": "https://example.com/api/internal", "source_file": "app.bundle.js"}]
        result = ed.correlate_javascript_parameters([], js_data, target=SAFE_TARGET)
        assert result["endpoints"][0]["confidence"] == ed.CONFIDENCE_MEDIUM
        assert result["endpoints"][0]["js_derived"] is True

    def test_js_parameters_extracted(self):
        js_data = [{
            "url": "https://example.com/api/search",
            "parameters": [{"name": "query", "location": "query", "data_type": "string"}],
            "source_file": "search.js",
        }]
        result = ed.correlate_javascript_parameters([], js_data, target=SAFE_TARGET)
        assert result["parameters"][0]["name"] == "query"
        assert result["parameters"][0]["js_derived"] is True

    def test_currently_verified_when_seen_live(self):
        current = [{"url": "https://example.com/api/search", "path": "/api/search"}]
        js_data = [{"url": "https://example.com/api/search"}]
        result = ed.correlate_javascript_parameters(current, js_data, target=SAFE_TARGET)
        assert result["endpoints"][0]["currently_verified"] is True


# ---------------------------------------------------------------------------
# 1/2. enumerate_directories / enumerate_files
# ---------------------------------------------------------------------------

class TestEnumerateDirectoriesAndFiles:
    def test_directory_hit_persisted_and_recognized(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["admin/", "config.php"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url.endswith("/admin/"):
                return _fake_response(200, headers={"Content-Type": "text/html"}, body=b"<html>admin</html>")
            return _fake_response(404)

        store = ed.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.enumerate_directories(SAFE_URL, target=SAFE_TARGET, store=store, wordlists_dir=wl_dir)

        assert result["kind"] == "directory"
        assert len(result["endpoints"]) == 1
        assert result["endpoints"][0]["path"] == "/admin/"
        assert result["endpoints"][0]["category"] == "directory"
        assert any(f["type"] == "endpoint_discovered" for f in store.all())

    def test_file_hit_persisted_and_recognized(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["admin/", "config.php"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url.endswith("config.php"):
                return _fake_response(200, headers={"Content-Type": "text/plain"}, body=b"db_pass=secret")
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.enumerate_files(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)

        assert result["kind"] == "file"
        assert len(result["endpoints"]) == 1
        assert result["endpoints"][0]["path"] == "/config.php"
        assert result["endpoints"][0]["category"] == "file"

    def test_all_404_yields_no_endpoints_but_counts_negative_results(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["admin/", "config.php", "backup.zip"])
        with mock.patch("requests.get", side_effect=_all_404):
            result = ed.enumerate_directories(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)
        assert result["endpoints"] == []
        assert result["negative_results_count"] >= 1

    def test_soft_404_hit_not_treated_as_confirmed(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["admin/"])
        soft_404_body = b"<html><body>Oops! Page not found</body></html>"

        def fake_get(url, **kwargs):
            # Every path — including the baseline probe — returns HTTP 200
            # with the exact same "friendly" error page (classic soft-404).
            return _fake_response(200, headers={"Content-Type": "text/html"}, body=soft_404_body)

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.enumerate_directories(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)

        # Behaviour change (deliberate): a response matching the root's
        # catch-all fingerprint is a NEGATIVE result, not a low-confidence
        # discovery. Emitting one endpoint record per soft-404 meant
        # surface_mapper minted an endpoint asset for every wordlist entry on
        # a catch-all host, and exposure_scan then re-probed those phantom
        # endpoints as if they were real surface. The observation is still
        # kept — as the negative/catch-all counters, not as an asset.
        assert result["endpoints"] == []
        assert result["negative_results_count"] >= 1

    def test_missing_wordlist_reports_error_not_crash(self, tmp_path):
        empty_dir = tmp_path / "no_wordlists_here"
        empty_dir.mkdir()
        with mock.patch("requests.get", side_effect=_all_404):
            result = ed.enumerate_directories(SAFE_URL, target=SAFE_TARGET, wordlists_dir=str(empty_dir))
        assert result["endpoints"] == []
        assert any(e["stage"] == "wordlist_load" for e in result["errors"])

    def test_out_of_scope_base_url_raises(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["admin/"])
        with pytest.raises(ed.ScopeError):
            ed.enumerate_directories("https://evil.com/", target="example.com", wordlists_dir=wl_dir)


# ---------------------------------------------------------------------------
# 4. enumerate_framework_paths (WordPress / Laravel / Django)
# ---------------------------------------------------------------------------

class TestEnumerateFrameworkPaths:
    def test_wordpress_paths_probed_when_wordpress_detected(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "wordpress_paths.txt", ["wp-login.php", "wp-admin/"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url.endswith("wp-login.php"):
                return _fake_response(200, headers={"Content-Type": "text/html"}, body=b"<html>login</html>")
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.enumerate_framework_paths(
                SAFE_URL, {"cms": "WordPress"}, target=SAFE_TARGET, wordlists_dir=wl_dir,
            )

        assert "wordpress_paths.txt" in result["wordlists_used"]
        assert len(result["endpoints"]) == 1
        assert result["endpoints"][0]["technology_association"] == "wordpress"

    def test_laravel_paths_probed_when_laravel_detected(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "laravel_paths.txt", [".env", "artisan"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url.endswith(".env"):
                return _fake_response(200, headers={"Content-Type": "text/plain"}, body=b"APP_KEY=secret")
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.enumerate_framework_paths(
                SAFE_URL, {"framework": "Laravel"}, target=SAFE_TARGET, wordlists_dir=wl_dir,
            )
        assert result["endpoints"][0]["technology_association"] == "laravel"

    def test_django_paths_probed_when_django_detected(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "django_paths.txt", ["admin/", "api/"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url.endswith("/admin/"):
                return _fake_response(200, headers={"Content-Type": "text/html"}, body=b"<html>django admin</html>")
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.enumerate_framework_paths(
                SAFE_URL, {"framework": "Django"}, target=SAFE_TARGET, wordlists_dir=wl_dir,
            )
        assert result["endpoints"][0]["technology_association"] == "django"

    def test_no_technology_probes_nothing(self, tmp_path):
        with mock.patch("requests.get", side_effect=_all_404) as mocked:
            result = ed.enumerate_framework_paths(SAFE_URL, None, target=SAFE_TARGET)
        assert result["wordlists_used"] == []
        assert result["endpoints"] == []
        mocked.assert_not_called()

    def test_unrelated_technology_does_not_probe_wordpress(self, tmp_path):
        with mock.patch("requests.get", side_effect=_all_404) as mocked:
            result = ed.enumerate_framework_paths(SAFE_URL, {"server": "nginx"}, target=SAFE_TARGET)
        assert result["wordlists_used"] == []
        mocked.assert_not_called()


# ---------------------------------------------------------------------------
# 5. discover_api_endpoints
# ---------------------------------------------------------------------------

class TestDiscoverApiEndpoints:
    def test_probes_all_four_canonical_roots(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "api_endpoints.txt", ["status"])
        requested_paths = []

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            requested_paths.append(url)
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            ed.discover_api_endpoints(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)

        for root in ("api/", "api/v1/", "api/v2/", "graphql/"):
            assert any(p.endswith(root) for p in requested_paths), f"missing root {root}"

    def test_api_root_hit_recorded_as_api_category(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "api_endpoints.txt", ["status"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url.endswith("/api/v1/"):
                return _fake_response(200, headers={"Content-Type": "application/json"}, body=b'{"ok":true}')
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.discover_api_endpoints(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)

        hit = next(e for e in result["endpoints"] if e["path"] == "/api/v1/")
        assert hit["category"] == "api"
        assert hit["discovery_type"] == "content_confirmed"

    def test_api_endpoints_wordlist_joined_under_each_root(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "api_endpoints.txt", ["users"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url.endswith("/api/v1/users"):
                return _fake_response(200, headers={"Content-Type": "application/json"}, body=b"[]")
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.discover_api_endpoints(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)

        assert any(e["path"] == "/api/v1/users" for e in result["endpoints"])

    def test_custom_api_roots_override_default(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "api_endpoints.txt", ["status"])
        requested = []

        def fake_get(url, **kwargs):
            requested.append(url)
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            ed.discover_api_endpoints(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir, api_roots=["v3/"])

        assert any(u.endswith("/v3/") for u in requested)
        assert not any(u.endswith("/api/v1/") for u in requested)


# ---------------------------------------------------------------------------
# 10. run_endpoint_discovery — recursion, dedup, limits, redirects, errors
# ---------------------------------------------------------------------------

class TestRunEndpointDiscoveryRecursion:
    def test_recursive_discovery_finds_nested_path(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["uploads/"])
        _write_wordlist(tmp_path, "api_endpoints.txt", ["status"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url == "https://example.com/uploads/":
                return _fake_response(200, headers={"Content-Type": "text/html"}, body=b"<html>listing</html>")
            if url == "https://example.com/uploads/uploads/":
                return _fake_response(200, headers={"Content-Type": "text/html"}, body=b"<html>nested</html>")
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                wordlists_dir=wl_dir, max_depth=2, max_requests=200, max_workers=4,
            )

        paths = {e["path"] for e in result["endpoints"]}
        assert "/uploads/" in paths
        assert "/uploads/uploads/" in paths
        depths = {e["path"]: e["depth"] for e in result["endpoints"]}
        assert depths["/uploads/"] == 0
        assert depths["/uploads/uploads/"] == 1

    def test_max_depth_zero_prevents_recursion(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["uploads/"])
        _write_wordlist(tmp_path, "api_endpoints.txt", ["status"])
        calls = []

        def fake_get(url, **kwargs):
            calls.append(url)
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            return _fake_response(200, headers={"Content-Type": "text/html"}, body=b"<html>x</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                wordlists_dir=wl_dir, max_depth=0, max_requests=200, max_workers=4,
            )
        assert all(e["depth"] == 0 for e in result["endpoints"])
        assert not any("uploads/uploads" in c for c in calls)

    def test_duplicate_candidates_not_reprobed(self, tmp_path):
        # A page that links to itself must not cause infinite/duplicate requests.
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["blog/"])
        _write_wordlist(tmp_path, "api_endpoints.txt", ["status"])
        call_count = {"blog": 0}

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url == "https://example.com/blog/":
                call_count["blog"] += 1
                return _fake_response(
                    200, headers={"Content-Type": "text/html"},
                    body=b'<html><a href="/blog/">self link</a></html>',
                )
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                wordlists_dir=wl_dir, max_depth=3, max_requests=200, max_workers=4,
            )
        assert call_count["blog"] == 1

    def test_request_budget_enforced(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [f"dir{i}/" for i in range(20)])
        _write_wordlist(tmp_path, "api_endpoints.txt", ["status"])

        with mock.patch("requests.get", side_effect=_all_404):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                wordlists_dir=wl_dir, max_depth=1, max_requests=5, max_workers=2,
            )
        assert result["requests_made"] <= 5
        assert result["request_budget_exhausted"] is True

    def test_redirect_recorded_with_location(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["old-page"])
        _write_wordlist(tmp_path, "api_endpoints.txt", ["status"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url.endswith("old-page"):
                return _fake_response(301, headers={"Location": "/new-page"})
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                wordlists_dir=wl_dir, max_depth=0, max_requests=50,
            )
        hit = next(e for e in result["endpoints"] if e["path"] == "/old-page")
        assert hit["discovery_type"] == "redirect"
        assert hit["redirect_location"] == "/new-page"

    def test_connection_errors_recorded_and_do_not_abort_run(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["admin/", "config.php"])
        _write_wordlist(tmp_path, "api_endpoints.txt", ["status"])

        def fake_get(url, **kwargs):
            if "config.php" in url:
                raise requests.exceptions.ConnectionError("refused")
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                wordlists_dir=wl_dir, max_depth=0, max_requests=50,
            )
        assert result["status"] == "completed_with_errors"
        assert any(e["stage"] == "fetch" for e in result["errors"])

    def test_malformed_empty_response_handled(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["weird/"])
        _write_wordlist(tmp_path, "api_endpoints.txt", ["status"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url.endswith("/weird/"):
                return _fake_response(200, headers={}, body=b"")  # no Content-Type, empty body
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                wordlists_dir=wl_dir, max_depth=1, max_requests=50,
            )
        # Must not crash; the empty-body directory is still recorded.
        assert any(e["path"] == "/weird/" for e in result["endpoints"])

    def test_technology_and_historical_and_js_all_wired_together(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [])
        _write_wordlist(tmp_path, "api_endpoints.txt", [])
        _write_wordlist(tmp_path, "wordpress_paths.txt", ["wp-login.php"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url.endswith("wp-login.php"):
                return _fake_response(200, headers={"Content-Type": "text/html"}, body=b"<html>wp login</html>")
            return _fake_response(404)

        historical_data = [{"url": "https://example.com/old-endpoint", "evidence": ["wayback 2018"]}]
        js_data = [{"url": "https://example.com/wp-login.php", "source_file": "bundle.js"}]

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                wordlists_dir=wl_dir, technology={"cms": "wordpress"},
                historical_data=historical_data, js_data=js_data,
                max_depth=0, max_requests=50,
            )

        assert any(e["technology_association"] == "wordpress" for e in result["endpoints"])
        assert result["historical_correlation"]["endpoints"][0]["currently_verified"] is False
        assert result["javascript_correlation"]["endpoints"][0]["currently_verified"] is True

    def test_wordlist_load_error_does_not_abort_run(self, tmp_path):
        empty_dir = tmp_path / "no_wordlists"
        empty_dir.mkdir()
        with mock.patch("requests.get", side_effect=_all_404):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"), wordlists_dir=str(empty_dir),
            )
        assert result["status"] == "completed_with_errors"
        assert any(e["stage"] == "wordlist_load" for e in result["errors"])
        assert result["endpoints"] == []

    def test_out_of_scope_target_raises_before_any_request(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["admin/"])
        with mock.patch("requests.get", side_effect=_all_404) as mocked:
            with pytest.raises(ed.ScopeError):
                ed.run_endpoint_discovery(
                    "https://evil.com/", target="example.com",
                    output_dir=str(tmp_path / "output"), wordlists_dir=wl_dir,
                )
        mocked.assert_not_called()

    def test_json_serializable_output(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["admin/"])
        _write_wordlist(tmp_path, "api_endpoints.txt", ["status"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url.endswith("/admin/"):
                return _fake_response(
                    200, headers={"Content-Type": "text/html"},
                    body=b'<form method="POST" action="/admin/login"><input name="user"></form>',
                )
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                wordlists_dir=wl_dir, max_depth=1, max_requests=50,
            )
        json.dumps(result)  # must not raise

    def test_persists_and_preserves_existing_data(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{"type": "dns_record", "source": "passive_recon.py", "value": "1.2.3.4"}]
        pending.write_text(json.dumps(pre_existing))

        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["admin/"])
        _write_wordlist(tmp_path, "api_endpoints.txt", ["status"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404)
            if url.endswith("/admin/"):
                return _fake_response(200, headers={"Content-Type": "text/html"}, body=b"<html>admin</html>")
            return _fake_response(404)

        with mock.patch("requests.get", side_effect=fake_get):
            ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir),
                wordlists_dir=wl_dir, max_depth=0, max_requests=50,
            )

        store = ed.PendingAssetsStore(output_dir=str(output_dir))
        all_records = store.all()
        assert pre_existing[0] in all_records
        assert any(f["type"] == "endpoint_discovered" for f in all_records)

    def test_completed_status_when_no_errors(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["admin/"])
        _write_wordlist(tmp_path, "api_endpoints.txt", ["status"])
        with mock.patch("requests.get", side_effect=_all_404):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                wordlists_dir=wl_dir, max_depth=0, max_requests=50,
            )
        assert result["status"] == "completed"
        assert result["errors"] == []


# ---------------------------------------------------------------------------
# Helper functions: normalization / URL joining
# ---------------------------------------------------------------------------

class TestUrlHelpers:
    def test_normalize_url_lowercases_scheme_and_host(self):
        assert ed._normalize_url("HTTP://Example.COM/Path") == "http://example.com/Path"

    def test_normalize_url_strips_default_port(self):
        assert ed._normalize_url("https://example.com:443/x") == ed._normalize_url("https://example.com/x")

    def test_normalize_url_sorts_query_params(self):
        assert ed._normalize_url("https://example.com/x?b=2&a=1") == ed._normalize_url("https://example.com/x?a=1&b=2")

    def test_normalize_url_collapses_duplicate_slashes(self):
        assert ed._normalize_url("https://example.com//a//b") == "https://example.com/a/b"

    def test_url_for_path_joins_correctly(self):
        assert ed._url_for_path("https://example.com", "admin/") == "https://example.com/admin/"
        assert ed._url_for_path("https://example.com/api/v1/", "users") == "https://example.com/api/v1/users"

    def test_entry_kind(self):
        assert ed._entry_kind("admin/") == "directory"
        assert ed._entry_kind("config.php") == "file"

    def test_is_directory_like(self):
        assert ed._is_directory_like("https://example.com/admin/") is True
        assert ed._is_directory_like("https://example.com/admin") is False


# ===========================================================================
# Hardening regression tests
#
# Every test below pins one defect found by auditing or adversarially
# attacking this module, and fails against the pre-hardening implementation.
# Each names the failure mode it prevents rather than only the code path it
# touches, so a future change that reintroduces the behaviour is recognisable
# from the test name alone.
# ===========================================================================


def _catch_all_get(status, body, *, headers=None, probe_status=None, probe_body=None):
    """
    fake_get in which EVERY path — the random baseline probes included —
    answers identically, i.e. a catch-all host on which nothing exists.
    """
    hdrs = headers or {"Content-Type": "text/html"}

    def fake_get(url, **kwargs):
        if "reconhound-nonexistent-check" in url and probe_status is not None:
            return _fake_response(probe_status, headers=hdrs, body=probe_body or body)
        return _fake_response(status, headers=hdrs, body=body)
    return fake_get


def _wordlists(tmp_path, dirs=("admin/", "backup/", "robots.txt"), apis=("users",)):
    d = _write_wordlist(tmp_path, "directories.txt", list(dirs))
    _write_wordlist(tmp_path, "api_endpoints.txt", list(apis))
    return d


# ---------------------------------------------------------------------------
# Request failure != endpoint absence, and != endpoint presence
# ---------------------------------------------------------------------------

class TestFailureIsNotEvidence:
    """
    The module's largest false-positive source: a server that declines or
    fails to answer produced one `endpoint_discovered` record per wordlist
    entry, which surface_mapper turned into endpoint assets and exposure_scan
    then re-probed as real surface.
    """

    def test_rate_limited_host_yields_no_endpoint_findings(self, tmp_path):
        wl_dir = _wordlists(tmp_path)
        fake = _catch_all_get(429, b"slow down", headers={"Retry-After": "120"})
        with mock.patch("requests.get", side_effect=fake):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_workers=1)
        assert result["endpoints"] == []
        assert result["blocked_probes"] > 0
        assert result["enumeration_conclusive"] is False

    def test_server_error_host_yields_no_endpoint_findings(self, tmp_path):
        wl_dir = _wordlists(tmp_path)
        with mock.patch("requests.get", side_effect=_catch_all_get(503, b"gateway down")):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir)
        assert result["endpoints"] == []
        assert result["enumeration_conclusive"] is False

    def test_connection_failures_are_not_negative_results(self, tmp_path):
        wl_dir = _wordlists(tmp_path)

        def fake_get(url, **kwargs):
            raise requests.exceptions.ConnectionError("connection refused")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir)
        assert result["endpoints"] == []
        # A request that never got an answer says nothing about the path.
        assert result["negative_results_count"] == 0
        assert result["failed_probes"] > 0
        assert result["enumeration_conclusive"] is False

    def test_500_on_one_path_is_still_reported_but_uncertain(self):
        baseline = {"available": True, "usable": True, "status_codes": [404],
                    "body_hashes": [ed._content_signature("nope")[1]],
                    "structural_hashes": [], "content_lengths": [4],
                    "error_mode_statuses": []}
        dtype, conf, notes = ed.classify_response(
            {"status_code": 500, "body": "boom", "headers": {}}, baseline)
        assert dtype == ed.DT_SERVER_ERROR
        assert conf == ed.CONFIDENCE_LOW
        assert any("uncertain" in n for n in notes)

    def test_root_wide_error_mode_marks_paths_blocked_not_absent(self):
        baseline = {"available": True, "usable": False, "error_mode_statuses": [503]}
        dtype, conf, notes = ed.classify_response(
            {"status_code": 503, "body": "down", "headers": {}}, baseline)
        assert dtype == ed.DT_BLOCKED
        assert any("not effectively tested" in n for n in notes)


# ---------------------------------------------------------------------------
# Catch-all / soft-404 detection
# ---------------------------------------------------------------------------

class TestCatchAllDetection:
    def test_dynamic_path_echoing_catch_all_is_not_confirmed_content(self, tmp_path):
        """
        A 200 catch-all that echoes the requested path and carries a
        per-request id differs from a single baseline sample in both hash and
        length, so the old fixed-tolerance comparison reported it as
        HIGH-confidence confirmed content.
        """
        wl_dir = _wordlists(tmp_path)
        counter = {"n": 0}

        def fake_get(url, **kwargs):
            counter["n"] += 1
            path = url.split("example.com", 1)[1]
            body = (f"<html>Sorry, {path} was not found here. "
                    f"request-id: {counter['n']:016x}</html>").encode()
            return _fake_response(200, headers={"Content-Type": "text/html"}, body=body)

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir)
        assert result["endpoints"] == []
        assert result["catch_all_matches"] > 0

    def test_catch_all_redirect_to_login_is_not_a_discovery(self, tmp_path):
        wl_dir = _wordlists(tmp_path)
        fake = _catch_all_get(302, b"", headers={"Location": "/login"})
        with mock.patch("requests.get", side_effect=fake):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir)
        assert result["endpoints"] == []

    def test_catch_all_401_wall_is_not_a_discovery(self, tmp_path):
        wl_dir = _wordlists(tmp_path)
        with mock.patch("requests.get", side_effect=_catch_all_get(401, b"auth required")):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir)
        assert result["endpoints"] == []

    def test_catch_all_does_not_recurse(self, tmp_path):
        """Recursing into a blanket 401 re-spends the whole wordlist per level."""
        wl_dir = _wordlists(tmp_path, dirs=[f"d{i}/" for i in range(12)], apis=["u"])
        with mock.patch("requests.get", side_effect=_catch_all_get(401, b"auth")):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_depth=3, max_requests=100000)
        assert result["requests_made"] < 200
        assert result["request_budget_exhausted"] is False

    def test_baseline_probe_failure_does_not_license_high_confidence(self, tmp_path):
        wl_dir = _wordlists(tmp_path)

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                raise requests.exceptions.Timeout("probe timed out")
            return _fake_response(200, headers={"Content-Type": "text/html"},
                                  body=b"<html>404 - page not found</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir)
        assert result["baseline_unavailable"] is True
        assert result["enumeration_conclusive"] is False
        assert all(e["confidence"] != ed.CONFIDENCE_HIGH for e in result["endpoints"])

    def test_uniform_results_without_baseline_raise_a_catch_all_conflict(self, tmp_path):
        """
        Fallback for a root that cannot be fingerprinted at all: if nearly
        every hit returns the same page, that is one catch-all, and the
        contradiction is recorded rather than silently accepted.
        """
        wl_dir = _wordlists(tmp_path, dirs=[f"p{i}" for i in range(12)], apis=["u"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                raise requests.exceptions.Timeout("probe timed out")
            return _fake_response(200, headers={"Content-Type": "text/html"},
                                  body=b"<html>Nothing to see here</html>")

        out = tmp_path / "out"
        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(out), wordlists_dir=wl_dir)
        assert result["catch_all_suspected"] is True
        assert all(e["confidence"] == ed.CONFIDENCE_LOW for e in result["endpoints"])
        persisted = json.loads((out / "pending_assets.json").read_text())
        assert any(f["type"] == "endpoint_discovery_catch_all_suspected" for f in persisted)

    def test_baseline_is_per_directory_root_not_per_host(self, tmp_path):
        """An HTML 404 at / must not be used to judge a JSON catch-all under /api/."""
        wl_dir = _wordlists(tmp_path, dirs=["api/", "admin/"], apis=["users", "orders"])

        def fake_get(url, **kwargs):
            path = url.split("example.com", 1)[1]
            if path.startswith("/api/"):
                if path.rstrip("/").endswith("orders"):
                    return _fake_response(200, headers={"Content-Type": "application/json"},
                                          body=b'{"orders":[{"id":7},{"id":8}],"total":2}')
                return _fake_response(200, headers={"Content-Type": "application/json"},
                                      body=b'{"error":"resource not found","code":404}')
            if path.rstrip("/").endswith("admin"):
                return _fake_response(200, headers={"Content-Type": "text/html"},
                                      body=b"<html>Admin panel</html>")
            return _fake_response(404, headers={"Content-Type": "text/html"},
                                  body=b"<html><h1>404</h1></html>")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_depth=1)
        paths = {e["path"] for e in result["endpoints"]}
        assert "/api/orders" in paths          # real endpoint, JSON baseline differs
        assert "/api/users" not in paths       # JSON soft-404 suppressed

    def test_similar_length_alone_never_suppresses_a_discovery(self):
        """
        A one-byte length difference between an error envelope and a real
        response is not evidence they are the same page; requiring content
        overlap is what stops the suppression logic causing false negatives.
        """
        error_body = '{"error":"resource not found","code":404}'
        real_body = '{"orders":[{"id":7},{"id":8}],"total":2}'
        assert ed._lengths_close(len(error_body), len(real_body))
        baseline = ed._probe_catch_all.__wrapped__ if False else {
            "available": True, "usable": True, "dynamic": False,
            "status_codes": [200], "body_hashes": [ed._content_signature(error_body)[1]],
            "structural_hashes": [ed._structural_signature(error_body, "/api/probe")],
            "content_lengths": [len(error_body)], "normalized_bodies": [error_body],
        }
        assert ed.matches_catch_all({"status_code": 200, "body": error_body, "headers": {}},
                                    baseline, "/api/probe") is True
        assert ed.matches_catch_all({"status_code": 200, "body": real_body, "headers": {}},
                                    baseline, "/api/orders") is False

    def test_baseline_built_from_429_or_5xx_is_not_usable(self):
        for status in (429, 503):
            baseline = {"available": True, "usable": False, "status_codes": [status],
                        "error_mode_statuses": [status]}
            assert ed.matches_catch_all(
                {"status_code": status, "body": "", "headers": {}}, baseline, "/x") is False


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------

class TestScopeHardening:
    @pytest.mark.parametrize("href", [
        "http://169.254.169.254/latest/meta-data/",   # cloud instance metadata
        "http://10.0.0.5:8080/internal",
        "http://[::1]/admin",
    ])
    def test_ip_literal_links_in_page_content_are_out_of_scope(self, href):
        body = f'<a href="{href}">x</a>'
        assert ed.extract_link_candidates(body, SAFE_URL, target=SAFE_TARGET) == []

    def test_ip_literal_link_allowed_only_when_it_is_the_target(self):
        body = '<a href="http://203.0.113.7/x">x</a>'
        assert ed.extract_link_candidates(body, "http://203.0.113.7/", target="203.0.113.7") == [
            "http://203.0.113.7/x"]

    def test_link_fragments_are_stripped(self):
        links = ed.extract_link_candidates('<a href="/x#frag">a</a>', SAFE_URL, target=SAFE_TARGET)
        assert links == ["https://example.com/x"]

    def test_credentials_are_stripped_from_urls(self):
        assert ed.validate_endpoint_target(
            "https://admin:hunter2@example.com/x", target=SAFE_TARGET) == "https://example.com/x"
        assert "hunter2" not in ed._normalize_url("https://admin:hunter2@example.com/x")
        assert "hunter2" not in ed._origin_of("https://admin:hunter2@example.com/x")

    @pytest.mark.parametrize("url", [
        "https://example.com%2f@evil.com/",
        "https://evil.com#@example.com/",
        "https://example.com:@evil.com/",
    ])
    def test_userinfo_scope_confusion_is_rejected(self, url):
        with pytest.raises(ed.ScopeError):
            ed.validate_endpoint_target(url, target=SAFE_TARGET)

    def test_idn_and_punycode_compare_equal(self):
        assert ed._in_scope_host("xn--mnchen-3ya.de", "münchen.de") is True
        assert ed._in_scope_host("münchen.de", "xn--mnchen-3ya.de") is True
        assert ed._in_scope_host("evil.xn--mnchen-3ya.de.attacker.com", "münchen.de") is False

    @pytest.mark.parametrize("entry", [
        "http://evil.com/x", "//evil.com/x", "../../../etc/passwd", "..%2f..%2fetc",
    ])
    def test_wordlist_entries_cannot_escape_the_root(self, entry):
        joined = ed._url_for_path("https://example.com/app/", entry)
        assert joined.startswith("https://example.com/app/")

    def test_out_of_scope_historical_records_are_skipped_not_persisted(self, tmp_path):
        store = ed.PendingAssetsStore(output_dir=str(tmp_path / "out"))
        result = ed.correlate_historical_parameters(
            [], [{"url": "https://attacker.invalid/pwn", "parameters": [{"name": "q"}]},
                 {"url": "https://ok.example.com/real"}],
            target=SAFE_TARGET, store=store)
        assert result["out_of_scope_skipped"] == 1
        assert [e["url"] for e in result["endpoints"]] == ["https://ok.example.com/real"]
        assert not any("attacker.invalid" in json.dumps(f) for f in store.all())

    def test_out_of_scope_js_records_are_skipped_not_persisted(self, tmp_path):
        store = ed.PendingAssetsStore(output_dir=str(tmp_path / "out"))
        result = ed.correlate_javascript_parameters(
            [], [{"url": "https://cdn.attacker.invalid/a.js"}], target=SAFE_TARGET, store=store)
        assert result["out_of_scope_skipped"] == 1
        assert result["endpoints"] == []
        assert store.all() == []


# ---------------------------------------------------------------------------
# Correlation correctness
# ---------------------------------------------------------------------------

class TestCorrelationHostAwareness:
    def test_historical_verification_is_host_qualified(self):
        result = ed.correlate_historical_parameters(
            [{"url": "https://shop.example.com/admin"}],
            [{"url": "https://blog.example.com/admin"}],
            target=SAFE_TARGET)
        # The live hit was on a different subdomain; that is not verification.
        assert result["endpoints"][0]["currently_verified"] is False
        assert result["endpoints"][0]["confidence"] == ed.CONFIDENCE_LOW

    def test_historical_verification_matches_on_the_same_host(self):
        result = ed.correlate_historical_parameters(
            [{"url": "https://shop.example.com/admin"}],
            [{"url": "https://shop.example.com/admin"}],
            target=SAFE_TARGET)
        assert result["endpoints"][0]["currently_verified"] is True

    def test_currently_verified_is_preserved_in_parameter_metadata(self):
        finding = ed.make_parameter_finding(
            {"name": "q", "location": "query", "historical": True, "currently_verified": True}, SAFE_TARGET)
        assert finding["metadata"]["currently_verified"] is True


# ---------------------------------------------------------------------------
# Negative-result memory
# ---------------------------------------------------------------------------

class TestNegativeResultMemory:
    def test_conclusive_empty_run_records_negative_result(self, tmp_path):
        wl_dir = _wordlists(tmp_path)
        out = tmp_path / "out"
        with mock.patch("requests.get", side_effect=_all_404):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(out), wordlists_dir=wl_dir)
        assert result["enumeration_conclusive"] is True
        persisted = json.loads((out / "pending_assets.json").read_text())
        assert [f["type"] for f in persisted] == ["endpoint_discovery_checked_no_endpoints"]

    def test_blocked_run_never_records_negative_result(self, tmp_path):
        """
        The finding type contains "_checked_no", which surface_mapper trusts
        as authoritative "checked and not found" memory. Writing it after a
        rate-limited run would suppress a later, unblocked attempt.
        """
        wl_dir = _wordlists(tmp_path)
        out = tmp_path / "out"
        fake = _catch_all_get(429, b"slow", headers={"Retry-After": "600"},
                              probe_status=404, probe_body=b"<html>404</html>")
        with mock.patch("requests.get", side_effect=fake):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(out),
                wordlists_dir=wl_dir, max_workers=1)
        assert result["rate_limited"] is True
        assert result["enumeration_conclusive"] is False
        persisted = json.loads((out / "pending_assets.json").read_text()) if (
            out / "pending_assets.json").exists() else []
        assert not any("_checked_no" in f["type"] for f in persisted)

    def test_rate_limit_tripwire_stops_a_persistently_limited_root(self, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=[f"d{i}/" for i in range(30)], apis=["u"])
        fake = _catch_all_get(429, b"slow", headers={"Retry-After": "300"},
                              probe_status=404, probe_body=b"<html>404</html>")
        with mock.patch("requests.get", side_effect=fake):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_workers=1)
        assert result["rate_limited"] is True
        assert result["retry_after_seen"] == ["300"]
        # The tripwire must stop the root, not keep hammering it.
        assert result["requests_made"] < 30

    def test_transient_rate_limiting_does_not_blind_the_rest_of_the_run(self, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=["admin/", "backup/", "secret/"], apis=["u"])
        state = {"n": 0}

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404, body=b"<html>404</html>")
            state["n"] += 1
            if state["n"] <= 2:
                return _fake_response(429, headers={"Retry-After": "1"}, body=b"slow")
            if url.rstrip("/").endswith("secret"):
                return _fake_response(200, headers={"Content-Type": "text/html"},
                                      body=b"<html>Real secret content</html>")
            return _fake_response(404, body=b"<html>404</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_workers=1)
        assert result["rate_limited"] is False
        assert any("secret" in e["path"] for e in result["endpoints"])


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

class TestPersistenceHardening:
    def test_add_many_writes_one_batch(self, tmp_path):
        store = ed.PendingAssetsStore(output_dir=str(tmp_path))
        findings = [ed.make_finding("endpoint_discovered", SAFE_TARGET, {"i": i}, ["e"], "LOW")
                    for i in range(25)]
        assert store.add_many(findings) == 25
        assert len(store.all()) == 25

    def test_add_many_empty_is_a_noop(self, tmp_path):
        store = ed.PendingAssetsStore(output_dir=str(tmp_path))
        assert store.add_many([]) == 0

    def test_os_error_does_not_escape_and_discard_the_discovery(self, tmp_path):
        class BrokenStore(ed.PendingAssetsStore):
            def add_many(self, findings):
                raise OSError(28, "No space left on device")

            def add(self, finding):
                raise OSError(28, "No space left on device")

        store = BrokenStore(output_dir=str(tmp_path))
        assert "No space left" in (ed._safe_store_add(store, {"type": "x"}) or "")
        assert "No space left" in (ed._safe_store_add_many(store, [{"type": "x"}]) or "")

    def test_unwritable_store_still_returns_the_discovery(self, tmp_path):
        """context.md §12.11: a persistence failure must never silently drop a finding."""
        wl_dir = _wordlists(tmp_path, dirs=["admin/"], apis=["u"])
        out = tmp_path / "out"
        out.mkdir()
        (out / "pending_assets.json").write_text("{ not a json array")

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404, body=b"<html>404</html>")
            return _fake_response(200, headers={"Content-Type": "text/html"},
                                  body=b"<html>Real page content</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(out), wordlists_dir=wl_dir)
        assert result["endpoints"], "discoveries were discarded because persistence failed"
        assert all(e.get("persisted") is False for e in result["endpoints"])
        assert any(e.get("stage") == "persistence" for e in result["errors"])

    def test_unserialisable_caller_data_does_not_lose_the_batch(self, tmp_path):
        class Weird:
            def __repr__(self):
                return "<weird>"

        out = tmp_path / "out"
        store = ed.PendingAssetsStore(output_dir=str(out))
        result = ed.correlate_historical_parameters(
            [], [{"url": "/x", "evidence": [Weird()], "parameters": [{"name": "q"}]}],
            target=SAFE_TARGET, store=store)
        assert result.get("errors") is None
        assert len(store.all()) == 2
        json.loads((out / "pending_assets.json").read_text())   # still valid JSON

    def test_jsonify_handles_nan_and_cycles(self):
        cyclic = {}
        cyclic["self"] = cyclic
        assert json.dumps(ed._jsonify(cyclic))
        assert json.dumps(ed._jsonify({"n": float("nan"), "i": float("inf")}))

    def test_atomic_write_fsyncs_the_directory(self, tmp_path):
        store = ed.PendingAssetsStore(output_dir=str(tmp_path))
        with mock.patch("os.fsync") as fsync:
            store.add(ed.make_finding("x", SAFE_TARGET, {}, [], "LOW"))
        assert fsync.call_count >= 2       # file + containing directory


# ---------------------------------------------------------------------------
# Resource bounds, cancellation and completion semantics
# ---------------------------------------------------------------------------

class TestBoundsAndCancellation:
    def test_keyboard_interrupt_returns_a_partial_summary(self, tmp_path):
        wl_dir = _wordlists(tmp_path)

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404, body=b"<html>404</html>")
            raise KeyboardInterrupt()

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_workers=2)
        assert result["status"] == "interrupted"
        assert result["cancelled"] is True
        assert result["enumeration_conclusive"] is False

    def test_max_depth_reached_reports_actual_truncation(self, tmp_path):
        """The old formulation could never be True on a run that truncated."""
        wl_dir = _wordlists(tmp_path, dirs=["admin/"], apis=["u"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404, body=b"<html>404</html>")
            if url.endswith("/"):
                return _fake_response(200, headers={"Content-Type": "text/html"},
                                      body=b"<html>a directory listing page</html>")
            return _fake_response(404, body=b"<html>404</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_depth=1, max_requests=100000)
        assert result["max_depth_reached"] is True
        assert result["depth_truncated"] is True

    def test_link_candidates_are_capped_per_page(self, tmp_path):
        body = ("<html>" + "".join(
            f'<a href="/p{i}">x</a>' for i in range(ed.DEFAULT_MAX_LINK_CANDIDATES_PER_PAGE + 500)
        ) + "</html>").encode()
        wl_dir = _wordlists(tmp_path, dirs=["admin/"], apis=["u"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404, body=b"<html>404</html>")
            if url.endswith("/admin/"):
                return _fake_response(200, headers={"Content-Type": "text/html"}, body=body)
            return _fake_response(404, body=b"<html>404</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_depth=1, max_requests=100000)
        assert any(e.get("stage") == "link_extraction" for e in result["errors"])

    def test_redirect_loop_terminates(self, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=["a"], apis=["u"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404, body=b"<html>404</html>")
            if url.endswith("/a"):
                return _fake_response(302, headers={"Location": "/b"}, body=b"")
            if url.endswith("/b"):
                return _fake_response(302, headers={"Location": "/a"}, body=b"")
            return _fake_response(404, body=b"<html>404</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_depth=5, max_requests=500)
        assert result["request_budget_exhausted"] is False

    def test_baseline_probes_are_charged_to_the_request_budget(self, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=[f"d{i}/" for i in range(50)], apis=["u"])
        with mock.patch("requests.get", side_effect=_all_404):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_requests=20)
        assert result["requests_made"] <= 20 + ed.BASELINE_PROBE_COUNT
        assert result["request_budget_exhausted"] is True
        assert result["enumeration_conclusive"] is False

    def test_oversized_body_is_bounded_without_raw_read(self):
        payload = b"A" * (5 * 1024 * 1024)
        response = _fake_response(200, headers={"Content-Type": "text/html"}, body=payload)
        response.raw.read.side_effect = Exception("raw unavailable")
        response.iter_content.return_value = iter([payload[i:i + 8192]
                                                   for i in range(0, len(payload), 8192)])
        with mock.patch("requests.get", return_value=response):
            result = ed.fetch_url(SAFE_URL)
        assert len(result["body"]) == ed.DEFAULT_MAX_BODY_BYTES
        assert result["body_truncated"] is True

    def test_cyclic_technology_structure_does_not_recurse_forever(self):
        cyclic = {"cms": "WordPress"}
        cyclic["self"] = cyclic
        assert ed.select_wordlists_for_technology(cyclic) == [("wordpress_paths.txt", "wordpress")]


# ---------------------------------------------------------------------------
# URL canonicalisation and duplicate work
# ---------------------------------------------------------------------------

class TestCanonicalisation:
    @pytest.mark.parametrize("a,b", [
        ("https://example.com/admin", "https://example.com/%61dmin"),
        ("https://example.com/a/b", "https://example.com/a/./b"),
        ("https://example.com/a/x/../b", "https://example.com/a/b"),
        ("https://example.com/", "https://example.com./"),
        ("https://example.com/x#frag", "https://example.com/x"),
        ("https://EXAMPLE.com:443/x", "https://example.com/x"),
    ])
    def test_equivalent_urls_normalise_together(self, a, b):
        assert ed._normalize_url(a) == ed._normalize_url(b)

    def test_encoded_slash_is_not_decoded_into_a_separator(self):
        # %2F is a literal slash *inside* a segment; decoding it would merge
        # two genuinely different endpoints.
        assert ed._normalize_url("https://example.com/a%2Fb") != ed._normalize_url("https://example.com/a/b")

    def test_ipv6_urls_normalise(self):
        assert ed._normalize_url("http://[2001:DB8::1]:8080/a//b/./c") == "http://[2001:db8::1]:8080/a/b/c"
        assert ed._normalize_url("http://[2001:db8::1]:80/x") == "http://[2001:db8::1]/x"

    def test_malformed_url_does_not_raise_from_the_dedup_path(self):
        assert ed._normalize_url("https://[not-an-ipv6/x")

    def test_candidate_root_is_the_parent_directory(self):
        assert ed._candidate_root_of("https://example.com/admin/") == "https://example.com/"
        assert ed._candidate_root_of("https://example.com/api/v1/users") == "https://example.com/api/v1/"
        assert ed._candidate_root_of("https://example.com/") == "https://example.com/"

    def test_enumeration_root_honours_the_base_path(self, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=["admin/"], apis=["u"])
        seen = []

        def fake_get(url, **kwargs):
            seen.append(url)
            return _fake_response(404, body=b"<html>404</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            ed.run_endpoint_discovery("https://example.com/app/v2/", target=SAFE_TARGET,
                                      output_dir=str(tmp_path / "out"), wordlists_dir=wl_dir)
        assert "https://example.com/app/v2/admin/" in seen
        assert not any(u == "https://example.com/admin/" for u in seen)

    def test_no_duplicate_endpoint_findings_for_one_url(self, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=["admin/", "admin"], apis=["u"])
        out = tmp_path / "out"

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404, body=b"<html>404</html>")
            if "/admin" in url:
                return _fake_response(200, headers={"Content-Type": "text/html"},
                                      body=b'<html><a href="/admin/">self</a>Admin console</html>')
            return _fake_response(404, body=b"<html>404</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            ed.run_endpoint_discovery(SAFE_URL, target=SAFE_TARGET, output_dir=str(out),
                                      wordlists_dir=wl_dir, max_depth=2)
        persisted = json.loads((out / "pending_assets.json").read_text())
        urls = [f["value"]["url"] for f in persisted if f["type"] == "endpoint_discovered"]
        assert len(urls) == len(set(urls))


# ---------------------------------------------------------------------------
# Parameter intelligence
# ---------------------------------------------------------------------------

class TestParameterIntelligence:
    def test_header_hints_carry_the_endpoint_they_were_seen_on(self):
        hints = ed.extract_header_parameter_hints(
            "send X-Api-Key", {}, page_url="https://example.com/api/v1/users")
        assert hints[0]["endpoint"] == "/api/v1/users"

    def test_header_hints_without_a_page_url_still_work(self):
        hints = ed.extract_header_parameter_hints("send X-Api-Key", {})
        assert hints[0]["name"] == "X-Api-Key"

    def test_form_and_link_extraction_share_one_parse(self):
        body = '<html><form method="POST"><input name="q"></form><a href="/x">l</a></html>'
        soup = ed._parse_soup(body)
        assert [p["name"] for p in ed.extract_form_parameters(body, SAFE_URL, soup=soup)] == ["q"]
        assert ed.extract_link_candidates(body, SAFE_URL, soup=soup) == ["https://example.com/x"]


# ---------------------------------------------------------------------------
# Downstream contract: findings must survive surface_mapper ingestion
# ---------------------------------------------------------------------------

class TestDownstreamContract:
    def test_findings_ingest_into_surface_mapper_without_errors(self, tmp_path):
        from reconhound import surface_mapper

        wl_dir = _wordlists(tmp_path, dirs=["admin/", "robots.txt"], apis=["users"])
        out = tmp_path / "out"

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404, headers={"Content-Type": "text/html"},
                                      body=b"<html><h1>404 Not Found</h1></html>")
            if url.endswith("/admin/"):
                return _fake_response(200, headers={"Content-Type": "text/html"}, body=(
                    b'<html><form method="POST" action="/admin/login">'
                    b'<input name="user"><input type="password" name="pw"></form></html>'))
            return _fake_response(404, headers={"Content-Type": "text/html"},
                                  body=b"<html><h1>404 Not Found</h1></html>")

        with mock.patch("requests.get", side_effect=fake_get):
            ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(out), wordlists_dir=wl_dir,
                historical_data=[{"url": "https://example.com/old", "parameters": [{"name": "t"}]},
                                 {"url": "https://evil.invalid/x"}],
                js_data=[{"url": "/admin/login", "source_file": "app.js"}])

        findings = json.loads((out / "pending_assets.json").read_text())
        required = {"type", "target", "value", "evidence", "confidence", "source",
                    "timestamp", "metadata"}
        assert all(required <= set(f) for f in findings)

        mapper = surface_mapper.SurfaceMapper(target=SAFE_TARGET, output_dir=str(tmp_path / "sm"))
        mapper.ingest_many(findings)
        assert mapper.state["ingestion_errors"] == []
        hostnames = [a["value"] for a in mapper.state["assets"].values()
                     if a["asset_type"] == surface_mapper.ASSET_HOSTNAME]
        assert not any("evil" in h for h in hostnames)
        ids = [a["id"] for a in mapper.state["assets"].values()]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Incremental persistence: the on-disk contract must be unchanged
# ---------------------------------------------------------------------------

class TestIncrementalPersistence:
    """
    add_many() no longer re-encodes already-written records on every append.
    The file format, indentation and crash-safety must be indistinguishable
    from the previous whole-array json.dump, and a writer outside this store
    must never be silently clobbered by a stale cache.
    """

    @staticmethod
    def _finding(i):
        return ed.make_finding("endpoint_discovered", SAFE_TARGET,
                               {"i": i, "url": f"https://example.com/{i}"}, [f"evidence {i}"], "HIGH")

    def test_output_is_byte_identical_to_whole_array_dump(self, tmp_path):
        store = ed.PendingAssetsStore(output_dir=str(tmp_path))
        store.add_many([self._finding(0), self._finding(1)])
        store.add(self._finding(2))
        text = (tmp_path / "pending_assets.json").read_text()
        assert text == json.dumps(json.loads(text), indent=2)
        assert len(json.loads(text)) == 3

    def test_empty_write_produces_an_empty_json_array(self, tmp_path):
        store = ed.PendingAssetsStore(output_dir=str(tmp_path))
        store._atomic_write([])
        assert json.loads((tmp_path / "pending_assets.json").read_text()) == []

    def test_external_writer_is_detected_and_preserved(self, tmp_path):
        store = ed.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(self._finding(0))
        path = tmp_path / "pending_assets.json"
        external = json.loads(path.read_text()) + [self._finding(99)]
        path.write_text(json.dumps(external, indent=2))

        store.add(self._finding(1))
        records = json.loads(path.read_text())
        assert len(records) == 3
        assert any(r["value"].get("i") == 99 for r in records)

    def test_deleted_file_is_recreated_without_phantom_records(self, tmp_path):
        store = ed.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(self._finding(0))
        (tmp_path / "pending_assets.json").unlink()
        store.add(self._finding(1))
        assert len(json.loads((tmp_path / "pending_assets.json").read_text())) == 1

    def test_failed_write_leaves_the_previous_file_intact_and_recovers(self, tmp_path):
        store = ed.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(self._finding(0))
        with mock.patch("os.replace", side_effect=OSError("disk gone")):
            with pytest.raises(OSError):
                store.add(self._finding(1))
        # The rename never happened, so the file still holds only record 0 ...
        assert len(json.loads((tmp_path / "pending_assets.json").read_text())) == 1
        # ... and the cached prefix must not still claim record 1 was written.
        assert store._serialized is None
        store.add(self._finding(2))
        records = json.loads((tmp_path / "pending_assets.json").read_text())
        assert [r["value"]["i"] for r in records] == [0, 2]

    def test_post_rename_failure_does_not_duplicate_or_lose_records(self, tmp_path):
        """
        _fsync_dir runs after os.replace, so a failure there means the data IS
        on disk. Recovery must reconcile against the file, not against a stale
        in-memory prefix that would double-write or drop the record.
        """
        store = ed.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(self._finding(0))
        with mock.patch.object(ed.PendingAssetsStore, "_fsync_dir", side_effect=RuntimeError("boom")):
            with pytest.raises(RuntimeError):
                store.add(self._finding(1))
        assert store._serialized is None
        store.add(self._finding(2))
        records = json.loads((tmp_path / "pending_assets.json").read_text())
        assert [r["value"]["i"] for r in records] == [0, 1, 2]

    def test_corrupt_file_is_never_silently_overwritten(self, tmp_path):
        (tmp_path / "pending_assets.json").write_text("{ not a json array")
        store = ed.PendingAssetsStore(output_dir=str(tmp_path))
        with pytest.raises(ed.PersistenceError):
            store.add(self._finding(0))

    def test_unicode_and_control_characters_round_trip(self, tmp_path):
        store = ed.PendingAssetsStore(output_dir=str(tmp_path))
        payload = '/café/日本\n"quoted"\\backslash'
        store.add(ed.make_finding("x", "münchen.de", {"p": payload}, ["ünicode ✓"], "LOW"))
        records = json.loads((tmp_path / "pending_assets.json").read_text())
        assert records[0]["value"]["p"] == payload
        assert records[0]["target"] == "münchen.de"

    def test_concurrent_appends_lose_nothing(self, tmp_path):
        import threading
        store = ed.PendingAssetsStore(output_dir=str(tmp_path))
        threads = [threading.Thread(target=lambda i=i: store.add_many(
            [self._finding(i * 10 + j) for j in range(10)])) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(json.loads((tmp_path / "pending_assets.json").read_text())) == 80


class TestBaselineConcurrency:
    def test_one_baseline_probe_per_root_under_concurrency(self):
        import threading
        state = ed._EnumerationState(SAFE_TARGET, None, 10_000, 2, [], [])
        calls = []

        def fake_get(url, **kwargs):
            calls.append(url)
            time.sleep(0.01)
            return _fake_response(404, body=b"<html>404</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            threads = [threading.Thread(
                target=lambda: state.get_baseline("https://example.com/x/y", 1.0)) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        # Eight workers arriving at one new root must share a single probe.
        assert len(calls) == ed.BASELINE_PROBE_COUNT
        assert len(state.baselines()) == 1

    def test_baseline_cache_is_capped(self):
        state = ed._EnumerationState(SAFE_TARGET, None, 10_000, 2, [], [], max_baselines=3)
        with mock.patch("requests.get", side_effect=_all_404):
            for i in range(10):
                state.get_baseline(f"https://example.com/d{i}/x", 1.0)
        assert len(state.baselines()) <= 3

    def test_skipped_probes_return_their_budget_reservation(self):
        state = ed._EnumerationState(SAFE_TARGET, None, 100, 0, [], [])
        assert state.reserve_request() is True
        assert state.request_count == 1
        state.release_request()
        assert state.request_count == 0


class TestControlCharacterUrls:
    @pytest.mark.parametrize("url", [
        "https://example.com/a\r\nX-Injected: 1",
        "https://example.com/a\nb",
        "https://example.com/a\x00b",
        "https://example.com/a\tb",
    ])
    def test_control_characters_are_rejected(self, url):
        with pytest.raises(ed.ScopeError):
            ed.validate_endpoint_target(url, target=SAFE_TARGET)

    def test_control_character_wordlist_entry_is_reported_not_requested(self, tmp_path):
        # An embedded newline cannot survive a line-based wordlist, so the
        # entry uses characters that do: a tab and a NUL.
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["ok/", "ba\td/", "n\x00ul/"])
        _write_wordlist(tmp_path, "api_endpoints.txt", ["u"])
        seen = []

        def fake_get(url, **kwargs):
            seen.append(url)
            return _fake_response(404, body=b"<html>404</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"), wordlists_dir=wl_dir)
        assert not any(c in u for u in seen for c in "\r\n\x00")
        assert any(e.get("stage") == "scope" for e in result["errors"])


class TestTechnologySelectionPrecision:
    @pytest.mark.parametrize("technology,expected", [
        ({"cms": "WordPress"}, ["wordpress_paths.txt"]),
        ({"frameworks": [{"name": "Laravel"}]}, ["laravel_paths.txt"]),
        ({"x": ["laravel-mix"]}, ["laravel_paths.txt"]),      # hyphen is a boundary
        ({"waf": "Djangoshield"}, []),                        # not Django
        ({"js": "wordpressify"}, []),                         # not WordPress
        ({}, []),
        (None, []),
        (42, []),
    ])
    def test_framework_matching_uses_word_boundaries(self, technology, expected):
        assert [w for w, _ in ed.select_wordlists_for_technology(technology)] == expected


class TestBlockedProbeAccounting:
    def test_a_429_that_is_also_the_root_error_mode_is_counted_once(self, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=["a/", "b/", "c/"], apis=["u"])
        with mock.patch("requests.get", side_effect=_catch_all_get(429, b"slow")):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_workers=1)
        assert result["blocked_probes"] <= result["requests_made"]
        assert result["enumeration_conclusive"] is False

    def test_requests_made_counts_only_requests_actually_sent(self, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=[f"d{i}/" for i in range(30)], apis=["u"])
        sent = []

        def fake_get(url, **kwargs):
            sent.append(url)
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404, body=b"<html>404</html>")
            return _fake_response(429, headers={"Retry-After": "300"}, body=b"slow")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_workers=1)
        assert result["requests_made"] == len(sent)


class TestRedirectHandling:
    def test_out_of_scope_redirect_target_is_recorded_but_not_followed(self, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=["a"], apis=["u"])
        sent = []

        def fake_get(url, **kwargs):
            sent.append(url)
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404, body=b"<html>404</html>")
            if url.endswith("/a"):
                return _fake_response(302, headers={"Location": "https://evil.com/x"}, body=b"")
            return _fake_response(404, body=b"<html>404</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_depth=2)
        assert not any("evil.com" in u for u in sent)
        redirects = [e for e in result["endpoints"] if e["discovery_type"] == ed.DT_REDIRECT]
        # The observation is evidence and is kept; only the request is refused.
        assert redirects and redirects[0]["redirect_location"] == "https://evil.com/x"

    def test_in_scope_redirect_target_is_queued(self, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=["a"], apis=["u"])
        sent = []

        def fake_get(url, **kwargs):
            sent.append(url)
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404, body=b"<html>404</html>")
            if url.endswith("/a"):
                return _fake_response(302, headers={"Location": "/moved-here"}, body=b"")
            if url.endswith("/moved-here"):
                return _fake_response(200, headers={"Content-Type": "text/html"},
                                      body=b"<html>The real relocated page</html>")
            return _fake_response(404, body=b"<html>404</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_depth=2)
        assert "https://example.com/moved-here" in sent
        assert any(e["path"] == "/moved-here" for e in result["endpoints"])


class TestUnstableBaseline:
    def test_inconsistent_probe_statuses_make_the_baseline_unusable(self, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=["admin/", "x.php"], apis=["u"])
        toggle = {"n": 0}

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                toggle["n"] += 1
                return _fake_response(200 if toggle["n"] % 2 else 404,
                                      headers={"Content-Type": "text/html"},
                                      body=b"<html>maybe</html>")
            return _fake_response(200, headers={"Content-Type": "text/html"},
                                  body=b"<html>a real page</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_workers=1)
        assert result["baseline_unavailable"] is True
        assert result["enumeration_conclusive"] is False
        assert all(e["confidence"] != ed.CONFIDENCE_HIGH for e in result["endpoints"])

    def test_failed_baseline_probe_is_retried_before_being_accepted(self):
        state = ed._EnumerationState(SAFE_TARGET, None, 10_000, 0, [], [])
        attempts = {"n": 0}

        def fake_get(url, **kwargs):
            attempts["n"] += 1
            if attempts["n"] <= ed.BASELINE_PROBE_COUNT:
                raise requests.exceptions.Timeout("transient")
            return _fake_response(404, body=b"<html>404 not found</html>")

        with mock.patch("requests.get", side_effect=fake_get):
            first = state.get_baseline("https://example.com/x", 1.0)
            assert first["available"] is False
            second = state.get_baseline("https://example.com/x", 1.0)
        # A transient failure must not disable catch-all detection for the run.
        assert second["available"] is True

    def test_permanently_failing_baseline_stops_retrying(self):
        state = ed._EnumerationState(SAFE_TARGET, None, 10_000, 0, [], [])
        calls = []

        def fake_get(url, **kwargs):
            calls.append(url)
            raise requests.exceptions.Timeout("always down")

        with mock.patch("requests.get", side_effect=fake_get):
            for _ in range(10):
                state.get_baseline("https://example.com/x", 1.0)
        assert len(calls) <= ed.BASELINE_MAX_ATTEMPTS * ed.BASELINE_PROBE_COUNT


class TestDynamicCatchAll:
    """
    A catch-all whose body genuinely differs per request is the hardest case:
    the structural signature can miss it, and length comparison is meaningless
    for it. Content overlap is what remains, and confidence is capped to match
    what the baseline can actually support.
    """

    @staticmethod
    def _dynamic_baseline(samples):
        return {"available": True, "usable": True, "dynamic": True, "status_codes": [200],
                "body_hashes": [ed._content_signature(s)[1] for s in samples],
                "structural_hashes": [ed._structural_signature(s, "/probe") for s in samples],
                "content_lengths": [len(s) for s in samples],
                "normalized_bodies": list(samples)}

    def test_dynamic_catch_all_is_matched_by_content_overlap(self):
        baseline = self._dynamic_baseline([
            "Sorry, that page could not be located on this server. Reference 111",
            "Sorry, that page could not be located on this server. Reference 222",
        ])
        variant = "Sorry, that page could not be located on this server. Reference 987"
        assert ed.matches_catch_all(
            {"status_code": 200, "body": variant, "headers": {}}, baseline, "/admin") is True

    def test_dynamic_catch_all_matching_does_not_swallow_real_content(self):
        baseline = self._dynamic_baseline([
            "Sorry, that page could not be located on this server. Reference 111",
            "Sorry, that page could not be located on this server. Reference 222",
        ])
        real = ("Administration console. Manage users, roles, billing and audit logs. "
                "Deploy configuration and rotate credentials.")
        assert ed.matches_catch_all(
            {"status_code": 200, "body": real, "headers": {}}, baseline, "/admin") is False

    def test_content_confirmed_against_a_dynamic_baseline_is_capped_at_medium(self):
        baseline = self._dynamic_baseline(["error one here now", "error two here now"])
        dtype, conf, notes = ed.classify_response(
            {"status_code": 200, "body": "a completely different real page", "headers": {}},
            baseline, "/x")
        assert dtype == ed.DT_CONTENT_CONFIRMED
        assert conf == ed.CONFIDENCE_MEDIUM
        assert any("different body to each request" in n for n in notes)

    def test_static_baseline_still_yields_high_confidence(self):
        baseline = {"available": True, "usable": True, "dynamic": False, "status_codes": [404],
                    "body_hashes": [ed._content_signature("nope")[1]], "structural_hashes": [],
                    "content_lengths": [4], "normalized_bodies": ["nope"]}
        dtype, conf, _ = ed.classify_response(
            {"status_code": 200, "body": "a real page with genuine content", "headers": {}},
            baseline, "/x")
        assert (dtype, conf) == (ed.DT_CONTENT_CONFIRMED, ed.CONFIDENCE_HIGH)

    def test_near_empty_body_is_not_matched_by_overlap_alone(self):
        baseline = self._dynamic_baseline([
            "the requested resource was not found on this server please check the address",
            "the requested resource was not found on this server please check the url",
        ])
        # Omits the wording the error page always uses, and has too few
        # tokens to conclude anything from vocabulary overlap.
        assert ed.matches_catch_all(
            {"status_code": 200, "body": "not found", "headers": {}}, baseline, "/x") is False

    def test_shared_chrome_does_not_suppress_real_pages(self):
        """
        The failure mode the novelty ceiling exists to prevent: when a site's
        404 page carries the same navigation and footer as every other page,
        core containment alone would classify every real page as the catch-all
        and report an entire site as empty.
        """
        chrome = ("Acme Corporation Home Products Pricing Support Careers Contact "
                  "Privacy Terms copyright 2026 all rights reserved ")
        baseline = self._dynamic_baseline([
            chrome + "The page you requested does not exist. Code 111",
            chrome + "The page you requested does not exist. Code 222",
        ])
        real_page = chrome + (
            "Billing dashboard. Review invoices, download statements, update payment "
            "methods, manage subscription tiers and configure dunning notifications "
            "for delinquent accounts across every organisation you administer.")
        assert ed.matches_catch_all(
            {"status_code": 200, "body": real_page, "headers": {}}, baseline, "/billing") is False
        # ... while a re-render of the error page itself is still suppressed.
        assert ed.matches_catch_all(
            {"status_code": 200, "body": chrome + "The page you requested does not exist. Code 987",
             "headers": {}}, baseline, "/nope") is True


class TestMalformedCallerPayloads:
    """
    historical_data / js_data come from other modules' output. A shape that is
    merely unusual must degrade, never corrupt the graph or abort the run.
    """

    @pytest.mark.parametrize("evidence,expected", [
        ("a single evidence string", ["a single evidence string"]),
        (["a", "b"], ["a", "b"]),
        (("x",), ["x"]),
        (42, ["42"]),
    ])
    def test_string_evidence_is_not_exploded_into_characters(self, evidence, expected):
        result = ed.correlate_historical_parameters(
            [], [{"url": "/x", "evidence": evidence}], target=SAFE_TARGET)
        assert result["endpoints"][0]["evidence"] == expected

    @pytest.mark.parametrize("evidence", [None, [], ["", "  "]])
    def test_empty_evidence_falls_back_to_a_real_sentence(self, evidence):
        result = ed.correlate_historical_parameters(
            [], [{"url": "/x", "evidence": evidence}], target=SAFE_TARGET)
        assert result["endpoints"][0]["evidence"] == ["Historical reference from wayback_intel.py"]

    def test_junk_entries_are_skipped_without_crashing(self, tmp_path):
        junk = [None, 42, "string", {"no_url": 1}, {"url": None},
                {"url": "/x", "parameters": "notalist"},
                {"url": "/y", "parameters": [None, {"noname": 1}, {"name": ""}, {"name": "ok"}]}]
        out = tmp_path / "out"
        store = ed.PendingAssetsStore(output_dir=str(out))
        historical = ed.correlate_historical_parameters(junk, [], target=SAFE_TARGET)  # empty data
        assert historical["endpoints"] == []
        result = ed.correlate_historical_parameters([], junk, target=SAFE_TARGET, store=store)
        assert [p["name"] for p in result["parameters"]] == ["ok"]
        json.loads((out / "pending_assets.json").read_text())

    def test_js_payload_junk_is_handled_identically(self):
        result = ed.correlate_javascript_parameters(
            [], [None, 42, {"url": "/y", "parameters": [{"name": "ok"}]}], target=SAFE_TARGET)
        assert [p["name"] for p in result["parameters"]] == ["ok"]


class TestDegenerateInputs:
    @pytest.mark.parametrize("base", [
        "https://example.com", "https://example.com/?a=1", "https://example.com/#frag",
        "https://EXAMPLE.COM./", "https://example.com:443/",
    ])
    def test_degenerate_base_urls_complete(self, base, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=["admin/"], apis=["u"])
        with mock.patch("requests.get", side_effect=_all_404):
            result = ed.run_endpoint_discovery(
                base, target=SAFE_TARGET, output_dir=str(tmp_path / "out"), wordlists_dir=wl_dir)
        assert result["status"] in ("completed", "completed_with_errors")

    @pytest.mark.parametrize("limits", [
        {"max_depth": 0}, {"max_requests": 0}, {"max_requests": -5}, {"max_depth": -1},
        {"max_workers": 0}, {"max_workers": -3}, {"timeout": 0},
    ])
    def test_degenerate_limits_do_not_crash(self, limits, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=["admin/"], apis=["u"])
        with mock.patch("requests.get", side_effect=_all_404):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, **limits)
        assert result["requests_made"] >= 0
        if limits.get("max_requests", 1) <= 0 or limits.get("max_depth", 0) < 0:
            # Nothing was probed, so nothing can be claimed about what exists.
            assert result["enumeration_conclusive"] is False

    def test_missing_content_type_still_parses_forms(self, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=["admin/"], apis=["u"])

        def fake_get(url, **kwargs):
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404, body=b"<html>404</html>")
            return _fake_response(200, headers={}, body=b'<html><form><input name="q"></form></html>')

        with mock.patch("requests.get", side_effect=fake_get):
            result = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=wl_dir, max_depth=0)
        assert any(p["name"] == "q" for p in result["parameters"])

    def test_ip_target_does_not_follow_links_to_other_ips(self, tmp_path):
        wl_dir = _wordlists(tmp_path, dirs=["admin/"], apis=["u"])
        sent = []

        def fake_get(url, **kwargs):
            sent.append(url)
            if "reconhound-nonexistent-check" in url:
                return _fake_response(404, body=b"<html>404</html>")
            return _fake_response(200, headers={"Content-Type": "text/html"}, body=(
                b'<html><a href="http://203.0.113.7/ok">self</a>'
                b'<a href="http://198.51.100.9/other">elsewhere</a></html>'))

        with mock.patch("requests.get", side_effect=fake_get):
            ed.run_endpoint_discovery("http://203.0.113.7/", target="203.0.113.7",
                                      output_dir=str(tmp_path / "out"), wordlists_dir=wl_dir,
                                      max_depth=1)
        assert any("203.0.113.7/ok" in u for u in sent)
        assert not any("198.51.100.9" in u for u in sent)

    def test_baseline_cache_falls_back_to_nearest_ancestor(self):
        state = ed._EnumerationState(SAFE_TARGET, None, 100_000, 3, [], [], max_baselines=2)
        with mock.patch("requests.get", side_effect=_all_404):
            state.get_baseline("https://example.com/x", 1.0)
            state.get_baseline("https://example.com/deep/y", 1.0)
            deepest = state.get_baseline("https://example.com/deep/deeper/z", 1.0)
        assert len(state.baselines()) == 2
        assert deepest["root"] == "https://example.com/deep/"


# ---------------------------------------------------------------------------
# Dead-origin tripwire (TRANSPORT_FAILURE_TRIP_THRESHOLD)
#
# Reproduces the performance defect found in the 2026-09-12 whole-system
# audit: against a port that accepts TCP connections and never answers HTTP,
# this module sent all 346 candidate probes, every one of them timing out —
# 71s at timeout=2 and 285s at the orchestrator's default timeout=8, for zero
# findings and zero usable baselines.
# ---------------------------------------------------------------------------


class TestDeadOriginTripwire:
    WORDS = [f"path{i}/" for i in range(200)]

    def _wl(self, tmp_path):
        return _write_wordlist(tmp_path, "directories.txt", self.WORDS)

    def test_enumeration_stops_once_the_origin_stops_answering(self, tmp_path):
        sent = []

        def never_answers(url, **kwargs):
            sent.append(url)
            raise requests.exceptions.Timeout("timed out")

        with mock.patch("requests.get", side_effect=never_answers):
            summary = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=self._wl(tmp_path), max_depth=1, max_workers=4)

        assert summary["origin_unreachable"] is True
        # Bounded by the threshold plus whatever the worker pool had already
        # dispatched when it fired — never the whole wordlist.
        assert len(sent) < len(self.WORDS), "the whole wordlist was still probed"
        assert summary["candidates_not_probed_unreachable"] > 0

    def test_a_tripped_run_is_never_conclusive_and_writes_no_negative_result(self, tmp_path):
        # The safety property: a tripwire must never poison shared
        # negative-result memory with "checked and not found".
        out = tmp_path / "out"
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout("x")):
            summary = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(out),
                wordlists_dir=self._wl(tmp_path), max_depth=1, max_workers=4)

        assert summary["origin_unreachable"] is True
        assert summary["enumeration_conclusive"] is False
        assert summary["endpoints"] == []
        pending = out / "pending_assets.json"
        blob = pending.read_text() if pending.exists() else ""
        assert "endpoint_discovery_checked_no_endpoints" not in blob

    def test_the_reason_is_reported_not_silently_swallowed(self, tmp_path):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout("x")):
            summary = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=self._wl(tmp_path), max_depth=1, max_workers=4)
        reasons = [e for e in summary["errors"] if e.get("stage") == "origin_unreachable"]
        assert len(reasons) == 1
        assert "not evidence" in reasons[0]["error"]

    def test_one_answered_probe_disarms_the_tripwire_permanently(self, tmp_path):
        # A host that is merely slow, or that drops a burst of requests, must
        # still be enumerated in full.
        state = ed._EnumerationState(SAFE_TARGET, None, 100_000, 1, [], [])
        for _ in range(ed.TRANSPORT_FAILURE_TRIP_THRESHOLD - 1):
            state.count_failed()
        assert state.origin_unreachable is False
        state.count_answered()
        for _ in range(ed.TRANSPORT_FAILURE_TRIP_THRESHOLD * 5):
            state.count_failed()
        assert state.origin_unreachable is False, (
            "an origin that answered once must never trip the dead-origin wire")

    def test_a_flaky_but_live_origin_is_enumerated_in_full(self, tmp_path):
        # Every third probe fails; nothing about that means the origin is dead.
        words = [f"p{i}/" for i in range(30)]
        seen = []

        def flaky(url, **kwargs):
            seen.append(url)
            if len(seen) % 3 == 0:
                raise requests.exceptions.Timeout("transient")
            return _fake_response(404, body=b"not found")

        with mock.patch("requests.get", side_effect=flaky):
            summary = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=_write_wordlist(tmp_path, "directories.txt", words),
                max_depth=1, max_workers=1)

        assert summary["origin_unreachable"] is False
        assert summary["candidates_not_probed_unreachable"] == 0
        assert summary["requests_made"] >= len(words)

    def test_a_404_is_an_answer_not_a_transport_failure(self, tmp_path):
        with mock.patch("requests.get", side_effect=_all_404):
            summary = ed.run_endpoint_discovery(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                wordlists_dir=self._wl(tmp_path), max_depth=1, max_workers=4)
        assert summary["origin_unreachable"] is False
        assert summary["requests_made"] >= len(self.WORDS)

    def test_connection_refused_and_dns_failure_trip_it_too(self, tmp_path):
        for exc in (requests.exceptions.ConnectionError("refused"),
                    requests.exceptions.ConnectionError("Name or service not known")):
            with mock.patch("requests.get", side_effect=exc):
                summary = ed.run_endpoint_discovery(
                    SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "out"),
                    wordlists_dir=self._wl(tmp_path), max_depth=1, max_workers=4)
            assert summary["origin_unreachable"] is True


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
