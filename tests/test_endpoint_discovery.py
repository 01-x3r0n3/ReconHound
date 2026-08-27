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

    def test_200_without_baseline_is_confirmed(self):
        dtype, conf, _ = ed.classify_response({"status_code": 200, "body": "real content"}, None)
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
        dtype, conf, _ = ed.classify_response({"status_code": 302, "body": ""}, None)
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

        assert len(result["endpoints"]) == 1
        assert result["endpoints"][0]["discovery_type"] == "possible_soft_404_match"
        assert result["endpoints"][0]["confidence"] == ed.CONFIDENCE_LOW

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


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
