"""
Tests for reconhound/crawler.py (ReconHound Module 12, per context.md's
build order — catalog item 12, build-order position 6).

Run with:  ./.venv/bin/python -m pytest tests/test_crawler.py -v

All tests mock the `requests.get` boundary so the suite is deterministic
and offline-safe; no external network access is required or performed
anywhere in this file.
"""

import io
import json
import os
import sys
from unittest import mock

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import crawler as cr


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


def _all_404(url, **kwargs):
    return _fake_response(404, body=b"not found")


# ---------------------------------------------------------------------------
# validate_crawl_target / _candidate_in_scope (scope enforcement)
# ---------------------------------------------------------------------------

class TestValidateCrawlTarget:
    def test_accepts_https_url(self):
        assert cr.validate_crawl_target("https://example.com/path") == "https://example.com/path"

    def test_accepts_in_scope_subdomain(self):
        assert cr.validate_crawl_target("https://api.example.com/", target="example.com")

    def test_rejects_out_of_scope_host(self):
        with pytest.raises(cr.ScopeError):
            cr.validate_crawl_target("https://evil.com/", target="example.com")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(cr.ScopeError):
            cr.validate_crawl_target("ftp://example.com/")

    def test_rejects_missing_hostname(self):
        with pytest.raises(cr.ScopeError):
            cr.validate_crawl_target("https:///path")

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(cr.ScopeError):
            cr.validate_crawl_target(bad)

    def test_allows_ip_literal_host_without_scope_check(self):
        assert cr.validate_crawl_target("http://93.184.216.34/", target="example.com")


class TestCandidateInScope:
    def test_in_scope_subdomain_allowed(self):
        assert cr._candidate_in_scope("https://api.example.com/x", "example.com") is True

    def test_out_of_scope_domain_rejected(self):
        assert cr._candidate_in_scope("https://evil.com/x", "example.com") is False

    def test_non_http_scheme_rejected(self):
        assert cr._candidate_in_scope("javascript:alert(1)", "example.com") is False
        assert cr._candidate_in_scope("ftp://example.com/x", "example.com") is False

    def test_ip_literal_bypass_rejected_when_private(self):
        # target is a domain; a page linking to a private IP must not be
        # allowed through the IP-literal domain-check exemption.
        assert cr._candidate_in_scope("http://169.254.169.254/", "example.com") is False
        assert cr._candidate_in_scope("http://127.0.0.1/", "example.com") is False
        assert cr._candidate_in_scope("http://10.0.0.5/", "example.com") is False

    def test_ip_literal_bypass_allowed_when_public(self):
        assert cr._candidate_in_scope("http://93.184.216.34/", "example.com") is True

    def test_ip_target_exact_match_allowed_even_if_private(self):
        # Operator explicitly authorized a private-IP target: same-host
        # links found on it must not be rejected by the SSRF safeguard.
        assert cr._candidate_in_scope("http://127.0.0.1:9999/private", "127.0.0.1") is True

    def test_ip_target_different_ip_rejected(self):
        assert cr._candidate_in_scope("http://127.0.0.2/", "127.0.0.1") is False

    def test_no_target_still_blocks_private_ip_literal(self):
        assert cr._candidate_in_scope("http://169.254.169.254/", None) is False

    def test_no_target_allows_any_public_host(self):
        assert cr._candidate_in_scope("https://anything.example/", None) is True


# ---------------------------------------------------------------------------
# PendingAssetsStore / make_finding / make_parameter_finding
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_finding_structure_and_source(self):
        finding = cr.make_finding("crawled_url", SAFE_URL, {"a": 1}, ["e"], cr.CONFIDENCE_HIGH)
        assert finding["source"] == "crawler.py"
        assert finding["metadata"] == {}
        json.dumps(finding)

    def test_parameter_finding_structure(self):
        param = {
            "name": "id", "location": "query", "method": "GET", "endpoint": "/users",
            "data_type": "integer", "source": "crawler_url_query", "confidence": cr.CONFIDENCE_MEDIUM,
            "evidence": ["observed"],
        }
        finding = cr.make_parameter_finding(param, SAFE_TARGET)
        assert finding["type"] == "crawler_parameter"
        assert finding["value"]["name"] == "id"
        assert finding["value"]["location"] == "query"
        json.dumps(finding)

    def test_store_preserves_prior_data(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{"type": "dns_record", "source": "passive_recon.py"}]
        pending.write_text(json.dumps(pre_existing))

        store = cr.PendingAssetsStore(output_dir=str(output_dir))
        store.add(cr.make_finding("crawled_url", SAFE_URL, {}, ["e"], cr.CONFIDENCE_HIGH))
        assert store.all() == pre_existing + [store.all()[-1]]

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = cr.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(cr.PersistenceError):
            store.add(cr.make_finding("crawled_url", SAFE_URL, {}, ["e"], cr.CONFIDENCE_HIGH))

    def test_safe_store_add_recovers_from_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = cr.PendingAssetsStore(output_dir=str(output_dir))
        err = cr._safe_store_add(store, cr.make_finding("crawled_url", SAFE_URL, {}, ["e"], cr.CONFIDENCE_HIGH))
        assert err is not None
        assert "corrupt" in err

    def test_safe_store_add_noop_without_store(self):
        assert cr._safe_store_add(None, cr.make_finding("x", SAFE_URL, {}, [], cr.CONFIDENCE_LOW)) is None


# ---------------------------------------------------------------------------
# fetch_url
# ---------------------------------------------------------------------------

class TestFetchUrl:
    def test_successful_fetch(self):
        with mock.patch("requests.get", return_value=_fake_response(200, {"Content-Type": "text/html"}, b"<html></html>")):
            result = cr.fetch_url(SAFE_URL)
        assert result["status"] == "found"
        assert result["status_code"] == 200
        assert result["body"] == "<html></html>"

    def test_timeout(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout()):
            result = cr.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_connection_error(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = cr.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert "connection error" in result["error"]

    def test_generic_request_exception(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.RequestException("boom")):
            result = cr.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert "request failed" in result["error"]

    def test_body_truncation(self):
        big_body = b"a" * 500
        with mock.patch("requests.get", return_value=_fake_response(200, {}, big_body)):
            result = cr.fetch_url(SAFE_URL, max_body_bytes=100)
        assert result["body_truncated"] is True
        assert len(result["body"]) == 100

    def test_no_redirects_followed_by_requests(self):
        captured = {}

        def fake_get(url, **kwargs):
            captured.update(kwargs)
            return _fake_response(302, {"Location": "/x"}, b"")

        with mock.patch("requests.get", side_effect=fake_get):
            cr.fetch_url(SAFE_URL)
        assert captured["allow_redirects"] is False


# ---------------------------------------------------------------------------
# classify_response
# ---------------------------------------------------------------------------

class TestClassifyResponse:
    @pytest.mark.parametrize("status,expected_type", [
        (404, "not_found"),
        (429, "rate_limited"),
        (301, "redirect"),
        (302, "redirect"),
        (401, "access_restricted"),
        (403, "access_restricted"),
        (405, "method_not_allowed"),
        (500, "server_error_response"),
        (200, "content_confirmed"),
        (299, "content_confirmed"),
        (600, "unexpected_status"),
    ])
    def test_status_classification(self, status, expected_type):
        discovery_type, _, _ = cr.classify_response({"status_code": status})
        assert discovery_type == expected_type

    def test_no_status_code_is_error(self):
        discovery_type, confidence, _ = cr.classify_response({"status_code": None})
        assert discovery_type == "error"
        assert confidence == cr.CONFIDENCE_LOW


# ---------------------------------------------------------------------------
# Parameter extraction
# ---------------------------------------------------------------------------

class TestParameterExtraction:
    def test_extract_query_parameters(self):
        params = cr.extract_query_parameters("https://example.com/x?id=5&name=bob")
        names = {p["name"] for p in params}
        assert names == {"id", "name"}
        assert all(p["location"] == "query" for p in params)

    def test_extract_query_parameters_empty(self):
        assert cr.extract_query_parameters("https://example.com/x") == []

    def test_infer_path_parameters_numeric(self):
        params = cr.infer_path_parameters("https://example.com/users/42/profile")
        assert any(p["data_type"] == "integer" for p in params)

    def test_infer_path_parameters_uuid(self):
        params = cr.infer_path_parameters("https://example.com/items/550e8400-e29b-41d4-a716-446655440000")
        assert any(p["data_type"] == "uuid" for p in params)

    def test_infer_path_parameters_no_match(self):
        assert cr.infer_path_parameters("https://example.com/about/team") == []

    def test_extract_form_field_parameters(self):
        form = {
            "method": "POST", "resolved_action": "https://example.com/submit", "source_page": "https://example.com/",
            "fields": [{"name": "email", "type": "email"}, {"name": None, "type": "submit"}],
        }
        params = cr.extract_form_field_parameters(form, SAFE_TARGET)
        assert len(params) == 1
        assert params[0]["name"] == "email"
        assert params[0]["location"] == "body"

    def test_extract_header_parameter_hints_token(self):
        params = cr.extract_header_parameter_hints("uses X-Api-Key for auth", {})
        assert any(p["name"] == "X-Api-Key" for p in params)

    def test_extract_header_parameter_hints_www_authenticate(self):
        params = cr.extract_header_parameter_hints(None, {"WWW-Authenticate": "Bearer"})
        assert any(p["name"] == "Authorization" for p in params)


# ---------------------------------------------------------------------------
# extract_page_links (URL discovery)
# ---------------------------------------------------------------------------

class TestExtractPageLinks:
    def test_extracts_anchor_and_iframe(self):
        body = '<a href="/about">About</a><iframe src="/embed"></iframe>'
        links = cr.extract_page_links(body, SAFE_URL, target=SAFE_TARGET)
        urls = {l["url"] for l in links}
        assert "https://example.com/about" in urls
        assert "https://example.com/embed" in urls

    def test_marks_out_of_scope_link(self):
        body = '<a href="https://evil.com/">bad</a>'
        links = cr.extract_page_links(body, SAFE_URL, target=SAFE_TARGET)
        assert links[0]["in_scope"] is False

    def test_marks_in_scope_link(self):
        body = '<a href="/about">About</a>'
        links = cr.extract_page_links(body, SAFE_URL, target=SAFE_TARGET)
        assert links[0]["in_scope"] is True

    def test_skips_fragment_mailto_javascript(self):
        body = '<a href="#top">t</a><a href="mailto:x@x.com">m</a><a href="javascript:void(0)">j</a>'
        links = cr.extract_page_links(body, SAFE_URL, target=SAFE_TARGET)
        assert links == []

    def test_deduplicates_same_normalized_url(self):
        body = '<a href="/about">A</a><a href="/about/">A2</a><a href="/about">A3</a>'
        links = cr.extract_page_links(body, SAFE_URL, target=SAFE_TARGET)
        # "/about" appears twice (identical) -> deduped to one; "/about/" is a distinct URL
        urls = [l["url"] for l in links]
        assert urls.count("https://example.com/about") == 1

    def test_malformed_html_degrades_gracefully(self):
        body = "<a href='/x'><div><span>unclosed tags <a href=/y"
        # Should not raise
        links = cr.extract_page_links(body, SAFE_URL, target=SAFE_TARGET)
        assert isinstance(links, list)

    def test_empty_body(self):
        assert cr.extract_page_links("", SAFE_URL) == []
        assert cr.extract_page_links(None, SAFE_URL) == []


# ---------------------------------------------------------------------------
# extract_forms + classify_form
# ---------------------------------------------------------------------------

class TestExtractForms:
    def test_extracts_basic_form(self):
        body = '<form action="/submit" method="post"><input type="text" name="q"></form>'
        forms = cr.extract_forms(body, SAFE_URL)
        assert len(forms) == 1
        assert forms[0]["method"] == "POST"
        assert forms[0]["resolved_action"] == "https://example.com/submit"
        assert forms[0]["fields"][0]["name"] == "q"

    def test_defaults_to_get_for_missing_method(self):
        body = '<form action="/search"><input type="text" name="q"></form>'
        forms = cr.extract_forms(body, SAFE_URL)
        assert forms[0]["method"] == "GET"

    def test_invalid_method_defaults_to_get(self):
        body = '<form action="/x" method="PUT"><input name="a"></form>'
        forms = cr.extract_forms(body, SAFE_URL)
        assert forms[0]["method"] == "GET"

    def test_captures_field_attributes(self):
        body = '<form action="/x"><input type="text" name="a" required maxlength="10"></form>'
        forms = cr.extract_forms(body, SAFE_URL)
        assert forms[0]["fields"][0]["attributes"]["maxlength"] == "10"

    def test_no_action_falls_back_to_page_url(self):
        body = '<form><input name="a"></form>'
        forms = cr.extract_forms(body, SAFE_URL)
        assert forms[0]["resolved_action"] == SAFE_URL

    def test_malformed_html_degrades_gracefully(self):
        body = "<form action=/x><input name=a<form>"
        forms = cr.extract_forms(body, SAFE_URL)
        assert isinstance(forms, list)

    def test_empty_body(self):
        assert cr.extract_forms("", SAFE_URL) == []


class TestClassifyForm:
    def test_file_upload_by_field_type(self):
        form = {"fields": [{"name": "avatar", "type": "file"}], "method": "POST",
                "resolved_action": "https://example.com/upload", "enctype": "application/x-www-form-urlencoded"}
        result = cr.classify_form(form)
        assert result["category"] == "file_upload"
        assert result["confidence"] == cr.CONFIDENCE_HIGH

    def test_file_upload_by_enctype(self):
        form = {"fields": [{"name": "a", "type": "text"}], "method": "POST",
                "resolved_action": "https://example.com/x", "enctype": "multipart/form-data"}
        result = cr.classify_form(form)
        assert result["category"] == "file_upload"

    def test_authentication_password_and_username(self):
        form = {"fields": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}],
                "method": "POST", "resolved_action": "https://example.com/do-login", "enctype": ""}
        result = cr.classify_form(form)
        assert result["category"] == "authentication"
        assert result["confidence"] == cr.CONFIDENCE_HIGH

    def test_authentication_password_only_medium_confidence(self):
        form = {"fields": [{"name": "pw", "type": "password"}],
                "method": "POST", "resolved_action": "https://example.com/x", "enctype": ""}
        result = cr.classify_form(form)
        assert result["category"] == "authentication"
        assert result["confidence"] == cr.CONFIDENCE_MEDIUM

    def test_administrative_by_action_path(self):
        form = {"fields": [{"name": "a", "type": "text"}], "method": "POST",
                "resolved_action": "https://example.com/admin/settings", "enctype": ""}
        result = cr.classify_form(form)
        assert result["category"] == "administrative"

    def test_search_by_field_name(self):
        form = {"fields": [{"name": "q", "type": "text"}], "method": "GET",
                "resolved_action": "https://example.com/results", "enctype": ""}
        result = cr.classify_form(form)
        assert result["category"] == "search"

    def test_user_input_fallback(self):
        form = {"fields": [{"name": "message", "type": "text"}], "method": "POST",
                "resolved_action": "https://example.com/contact", "enctype": ""}
        result = cr.classify_form(form)
        assert result["category"] == "user_input"
        assert result["confidence"] == cr.CONFIDENCE_LOW

    def test_no_evidence_no_classification(self):
        form = {"fields": [{"name": None, "type": "hidden"}], "method": "POST",
                "resolved_action": "https://example.com/x", "enctype": ""}
        result = cr.classify_form(form)
        assert result["category"] is None

    def test_file_upload_takes_priority_over_authentication(self):
        form = {"fields": [{"name": "password", "type": "password"}, {"name": "doc", "type": "file"}],
                "method": "POST", "resolved_action": "https://example.com/x", "enctype": "multipart/form-data"}
        result = cr.classify_form(form)
        assert result["category"] == "file_upload"


# ---------------------------------------------------------------------------
# build_file_upload_surface
# ---------------------------------------------------------------------------

class TestFileUploadSurface:
    def test_builds_surface_with_accept_attribute(self):
        form = {
            "action": "/upload", "resolved_action": "https://example.com/upload", "method": "POST",
            "enctype": "multipart/form-data", "source_page": SAFE_URL,
            "fields": [{"name": "file1", "type": "file", "attributes": {"accept": ".pdf"}}],
        }
        classification = cr.classify_form(form)
        surface = cr.build_file_upload_surface(form, classification)
        assert surface["upload_fields"] == ["file1"]
        assert surface["accept_attributes"] == {"file1": ".pdf"}


# ---------------------------------------------------------------------------
# extract_javascript_references
# ---------------------------------------------------------------------------

class TestJavaScriptReferences:
    def test_extracts_script_src(self):
        body = '<script src="/static/app.js"></script>'
        refs = cr.extract_javascript_references(body, SAFE_URL, target=SAFE_TARGET)
        assert len(refs) == 1
        assert refs[0]["url"] == "https://example.com/static/app.js"
        assert refs[0]["in_scope"] is True

    def test_ignores_inline_script_without_src(self):
        body = '<script>console.log("hi")</script>'
        refs = cr.extract_javascript_references(body, SAFE_URL)
        assert refs == []

    def test_deduplicates_same_script(self):
        body = '<script src="/a.js"></script><script src="/a.js"></script>'
        refs = cr.extract_javascript_references(body, SAFE_URL)
        assert len(refs) == 1

    def test_external_js_marked_out_of_scope(self):
        body = '<script src="https://cdn.evil.com/lib.js"></script>'
        refs = cr.extract_javascript_references(body, SAFE_URL, target=SAFE_TARGET)
        assert refs[0]["in_scope"] is False

    def test_empty_body(self):
        assert cr.extract_javascript_references("", SAFE_URL) == []


# ---------------------------------------------------------------------------
# detect_websocket_indicators
# ---------------------------------------------------------------------------

class TestWebSocketDetection:
    def test_detects_literal_wss_url(self):
        body = 'var ws = new WebSocket("wss://example.com/socket");'
        indicators = cr.detect_websocket_indicators(body, SAFE_URL)
        assert any(i["endpoint"] == "wss://example.com/socket" for i in indicators)
        assert indicators[0]["confidence"] == cr.CONFIDENCE_HIGH

    def test_detects_constructor_without_literal(self):
        body = 'var ws = new WebSocket(dynamicUrl);'
        indicators = cr.detect_websocket_indicators(body, SAFE_URL)
        assert len(indicators) == 1
        assert indicators[0]["endpoint"] is None
        assert indicators[0]["confidence"] == cr.CONFIDENCE_LOW

    def test_no_indicators_in_plain_content(self):
        assert cr.detect_websocket_indicators("<html>hello</html>", SAFE_URL) == []

    def test_empty_body(self):
        assert cr.detect_websocket_indicators("", SAFE_URL) == []


# ---------------------------------------------------------------------------
# detect_graphql_indicators
# ---------------------------------------------------------------------------

class TestGraphQLDetection:
    def test_detects_endpoint_path_in_page_url(self):
        indicators = cr.detect_graphql_indicators("", "https://example.com/graphql", headers={})
        assert any(i["indicator_type"] == "endpoint_path" for i in indicators)

    def test_detects_endpoint_path_in_referenced_urls(self):
        indicators = cr.detect_graphql_indicators("", SAFE_URL, headers={}, referenced_urls=["https://example.com/api/graphql"])
        assert any(i["indicator_type"] == "endpoint_path" for i in indicators)

    def test_detects_strong_content_reference(self):
        indicators = cr.detect_graphql_indicators("window.__APOLLO_STATE__ = {}", SAFE_URL, headers={})
        assert any(i["confidence"] == cr.CONFIDENCE_MEDIUM for i in indicators)

    def test_detects_weak_bare_keyword(self):
        indicators = cr.detect_graphql_indicators("we use graphql internally", SAFE_URL, headers={})
        assert any(i["confidence"] == cr.CONFIDENCE_LOW for i in indicators)

    def test_detects_content_type(self):
        indicators = cr.detect_graphql_indicators("", SAFE_URL, headers={"Content-Type": "application/graphql"})
        assert any(i["indicator_type"] == "content_type" for i in indicators)

    def test_no_indicators_when_nothing_present(self):
        assert cr.detect_graphql_indicators("plain page content", SAFE_URL, headers={}) == []


# ---------------------------------------------------------------------------
# Full crawl orchestration (run_crawler)
# ---------------------------------------------------------------------------

PAGES = {
    "https://example.com/": _fake_response(200, {"Content-Type": "text/html"}, b"""
        <html><body>
        <a href="/about">About</a>
        <a href="https://evil.com/">External</a>
        <form action="/upload" method="POST" enctype="multipart/form-data">
          <input type="file" name="doc">
        </form>
        <script src="/app.js"></script>
        </body></html>
    """, final_url="https://example.com/"),
    "https://example.com/about": _fake_response(200, {"Content-Type": "text/html"}, b"""
        <html><body>About page. <a href="/">home</a></body></html>
    """, final_url="https://example.com/about"),
}


def _routed_get(url, **kwargs):
    if url in PAGES:
        return PAGES[url]
    return _fake_response(404, body=b"not found")


class TestRunCrawler:
    def test_basic_recursive_crawl(self, tmp_path):
        with mock.patch("requests.get", side_effect=_routed_get):
            result = cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(tmp_path / "out"),
                max_depth=2, max_pages=20,
            )
        urls = {p["url"] for p in result["pages"]}
        assert "https://example.com/" in urls
        assert "https://example.com/about" in urls
        assert result["status"] in ("completed", "completed_with_errors")
        assert result["forms_discovered"] == 1
        assert result["file_upload_surfaces_discovered"] == 1
        assert result["javascript_references_discovered"] == 1
        assert result["external_links_observed"] == 1

    def test_out_of_scope_seed_raises(self, tmp_path):
        with pytest.raises(cr.ScopeError):
            cr.run_crawler("https://evil.com/", target="example.com", output_dir=str(tmp_path / "out"))

    def test_max_depth_limits_crawl(self, tmp_path):
        with mock.patch("requests.get", side_effect=_routed_get):
            result = cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(tmp_path / "out"), max_depth=0,
            )
        urls = {p["url"] for p in result["pages"]}
        assert urls == {"https://example.com/"}

    def test_max_pages_budget_exhausted(self, tmp_path):
        # Wide fan-out: seed page links to many distinct in-scope paths.
        many_links = "".join(f'<a href="/p{i}">p{i}</a>' for i in range(20))
        wide_page = _fake_response(200, {"Content-Type": "text/html"}, f"<html><body>{many_links}</body></html>".encode())

        def wide_get(url, **kwargs):
            if url == "https://example.com/":
                return wide_page
            return _fake_response(200, {"Content-Type": "text/html"}, b"<html></html>")

        with mock.patch("requests.get", side_effect=wide_get):
            result = cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(tmp_path / "out"),
                max_depth=3, max_pages=5,
            )
        assert result["request_budget_exhausted"] is True
        assert result["requests_made"] <= 5

    def test_loop_prevention_no_duplicate_fetch(self, tmp_path):
        loop_page = _fake_response(200, {"Content-Type": "text/html"}, b'<a href="/">self</a>')

        def loop_get(url, **kwargs):
            return loop_page

        with mock.patch("requests.get", side_effect=loop_get):
            result = cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(tmp_path / "out"),
                max_depth=5, max_pages=50,
            )
        # Self-linking page must only ever be fetched once, not once per depth level.
        assert result["requests_made"] == 1

    def test_redirect_followed_within_scope(self, tmp_path):
        def redirect_get(url, **kwargs):
            if url == "https://example.com/":
                return _fake_response(302, {"Location": "/about"}, b"")
            if url == "https://example.com/about":
                return _fake_response(200, {"Content-Type": "text/html"}, b"<html>ok</html>")
            return _fake_response(404, body=b"nf")

        with mock.patch("requests.get", side_effect=redirect_get):
            result = cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(tmp_path / "out"), max_depth=2,
            )
        urls = {p["url"]: p["discovery_type"] for p in result["pages"]}
        assert urls["https://example.com/"] == "redirect"
        assert urls["https://example.com/about"] == "content_confirmed"

    def test_redirect_out_of_scope_not_followed(self, tmp_path):
        def redirect_get(url, **kwargs):
            if url == "https://example.com/":
                return _fake_response(302, {"Location": "https://evil.com/steal"}, b"")
            return _fake_response(404, body=b"nf")

        with mock.patch("requests.get", side_effect=redirect_get):
            result = cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(tmp_path / "out"), max_depth=2,
            )
        urls = {p["url"] for p in result["pages"]}
        assert "https://evil.com/steal" not in urls
        assert result["external_links_observed"] >= 1

    def test_malformed_html_does_not_abort_crawl(self, tmp_path):
        def malformed_get(url, **kwargs):
            return _fake_response(200, {"Content-Type": "text/html"}, b"<html><body><div><span>broken<form action=/x")

        with mock.patch("requests.get", side_effect=malformed_get):
            result = cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(tmp_path / "out"), max_depth=1,
            )
        assert result["status"] in ("completed", "completed_with_errors")
        assert len(result["pages"]) == 1

    def test_network_error_recorded_not_fatal(self, tmp_path):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(tmp_path / "out"), max_depth=1,
            )
        assert result["status"] == "completed_with_errors"
        assert result["pages"] == []
        assert len(result["errors"]) == 1
        assert result["errors"][0]["stage"] == "fetch"

    def test_timeout_recorded_not_fatal(self, tmp_path):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout()):
            result = cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(tmp_path / "out"), max_depth=1,
            )
        assert result["status"] == "completed_with_errors"
        assert result["errors"][0]["error"] == "timeout"

    def test_result_is_json_serializable(self, tmp_path):
        with mock.patch("requests.get", side_effect=_routed_get):
            result = cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(tmp_path / "out"), max_depth=1,
            )
        json.dumps(result)

    def test_persistence_writes_expected_finding_types(self, tmp_path):
        output_dir = tmp_path / "out"
        with mock.patch("requests.get", side_effect=_routed_get):
            cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(output_dir), max_depth=2,
            )
        store = cr.PendingAssetsStore(output_dir=str(output_dir))
        types = {f["type"] for f in store.all()}
        assert "crawled_url" in types
        assert "crawled_form" in types
        assert "file_upload_surface" in types
        assert "javascript_reference" in types
        assert "external_link_observed" in types

    def test_persistence_preserves_prior_module_data(self, tmp_path):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{"type": "endpoint_discovered", "source": "endpoint_discovery.py"}]
        pending.write_text(json.dumps(pre_existing))

        with mock.patch("requests.get", side_effect=_routed_get):
            cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(output_dir), max_depth=0,
            )
        data = json.loads(pending.read_text())
        assert pre_existing[0] in data

    def test_file_upload_surface_marked_high_severity(self, tmp_path):
        output_dir = tmp_path / "out"
        with mock.patch("requests.get", side_effect=_routed_get):
            cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(output_dir), max_depth=0,
            )
        store = cr.PendingAssetsStore(output_dir=str(output_dir))
        upload_findings = [f for f in store.all() if f["type"] == "file_upload_surface"]
        assert len(upload_findings) == 1
        assert upload_findings[0]["metadata"]["severity"] == "HIGH"
        assert "not" in upload_findings[0]["metadata"]["note"].lower()  # non-exploitation caveat present

    def test_websocket_and_graphql_persisted(self, tmp_path):
        body = b"""<html><body>
          <script>var ws = new WebSocket("wss://example.com/ws"); window.__APOLLO_STATE__={};</script>
        </body></html>"""

        def get(url, **kwargs):
            return _fake_response(200, {"Content-Type": "text/html"}, body)

        output_dir = tmp_path / "out"
        with mock.patch("requests.get", side_effect=get):
            result = cr.run_crawler(
                "https://example.com/", target="example.com", output_dir=str(output_dir), max_depth=0,
            )
        assert result["websocket_indicators_discovered"] == 1
        assert result["graphql_indicators_discovered"] == 1
        store = cr.PendingAssetsStore(output_dir=str(output_dir))
        types = {f["type"] for f in store.all()}
        assert "websocket_indicator" in types
        assert "graphql_indicator" in types

    def test_target_defaults_to_base_url_hostname(self, tmp_path):
        with mock.patch("requests.get", side_effect=_all_404):
            result = cr.run_crawler("https://example.com/", output_dir=str(tmp_path / "out"), max_depth=0)
        assert result["target"] == "example.com"

    def test_not_found_seed_produces_no_page_record(self, tmp_path):
        with mock.patch("requests.get", side_effect=_all_404):
            result = cr.run_crawler(
                "https://example.com/missing", target="example.com", output_dir=str(tmp_path / "out"), max_depth=0,
            )
        # A 404 is still a "found" HTTP response (classify_response handles it),
        # so it IS recorded as a page — but with discovery_type "not_found".
        assert len(result["pages"]) == 1
        assert result["pages"][0]["discovery_type"] == "not_found"


# ===========================================================================
# Hardening regression tests (Module 6 audit).
#
# Every test below pins a defect that was reproduced against the previous
# implementation. The comment on each names the behaviour that regressed.
# ===========================================================================


def _routed(pages, default=(404, {"Content-Type": "text/html"}, b"not found")):
    """Build a requests.get side effect from a {path: (status, headers, body)} map."""
    import urllib.parse as _up

    def _get(url, **kwargs):
        path = _up.urlsplit(url).path or "/"
        status, headers, body = pages.get(path, default)
        return _fake_response(status, headers, body, final_url=url)
    return _get


# ---------------------------------------------------------------------------
# URL normalization / visited-set integrity
# ---------------------------------------------------------------------------

class TestNormalizeUrlHardening:
    """Each of these pairs is one resource; both used to produce two crawls."""

    @pytest.mark.parametrize("a,b", [
        ("http://example.com/a/../b", "http://example.com/b"),
        ("http://example.com/a/./b", "http://example.com/a/b"),
        ("http://example.com/a/%2e%2e/b", "http://example.com/b"),
        ("http://example.com/%7Euser", "http://example.com/~user"),
        ("http://EXAMPLE.com./x", "http://example.com/x"),
        ("http://user:pass@example.com/x", "http://example.com/x"),
        ("http://example.com:80/x", "http://example.com/x"),
        ("https://example.com:443/x", "https://example.com/x"),
        ("http://example.com/x#frag", "http://example.com/x"),
        ("http://example.com//a///b", "http://example.com/a/b"),
        ("http://münchen.de/x", "http://xn--mnchen-3ya.de/x"),
    ])
    def test_aliases_converge(self, a, b):
        assert cr._normalize_url(a) == cr._normalize_url(b)

    def test_percent_encoded_slash_is_not_decoded_into_a_separator(self):
        # %2F must survive: decoding it would invent a path boundary.
        assert "%2F" in cr._normalize_url("http://example.com/a/..%2Fb")

    def test_distinct_resources_stay_distinct(self):
        assert cr._normalize_url("http://example.com/a") != cr._normalize_url("http://example.com/b")
        assert cr._normalize_url("http://example.com/x?a=1") != cr._normalize_url("http://example.com/x?a=2")

    def test_malformed_url_does_not_raise(self):
        # Raised ValueError("Invalid IPv6 URL") straight out of the dedup path.
        assert cr._normalize_url("http://[::1/x")

    def test_credentials_never_survive_normalization(self):
        assert "s3cr3t" not in cr._normalize_url("https://user:s3cr3t@example.com/x")


class TestValidateCrawlTargetHardening:
    @pytest.mark.parametrize("bad", [
        "http://example.com/\r\nX-Injected: 1",
        "http://exam\tple.com/",
        "http://example.com/\x00",
    ])
    def test_control_characters_rejected(self, bad):
        # urlsplit silently strips these, so the validated URL was not the
        # URL that would have been requested.
        with pytest.raises(cr.ScopeError):
            cr.validate_crawl_target(bad, target="example.com")

    def test_malformed_ipv6_is_a_scope_error_not_a_valueerror(self):
        with pytest.raises(cr.ScopeError):
            cr.validate_crawl_target("http://[::1/x")

    def test_credentials_stripped_from_accepted_url(self):
        out = cr.validate_crawl_target("https://user:s3cr3t@example.com/x", target="example.com")
        assert "s3cr3t" not in out and out == "https://example.com/x"


class TestCandidateScopeHardening:
    @pytest.mark.parametrize("url", [
        "https://example.com@evil.com/",
        "https://example.com.evil.com/",
        "https://еxample.com/",          # Cyrillic homograph
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/",
        "https://example.com/\r\nHost: evil.com",
    ])
    def test_scope_escapes_rejected(self, url):
        assert cr._candidate_in_scope(url, "example.com") is False

    @pytest.mark.parametrize("url", [
        "https://example.com./", "https://sub.example.com/", "https://example.com:8443/x",
    ])
    def test_legitimate_in_scope_candidates_survive(self, url):
        assert cr._candidate_in_scope(url, "example.com") is True

    def test_idna_forms_compare_equal_both_directions(self):
        assert cr._in_scope_host("xn--mnchen-3ya.de", "münchen.de") is True
        assert cr._in_scope_host("münchen.de", "xn--mnchen-3ya.de") is True


class TestCredentialsNeverPersisted:
    def test_credentials_absent_from_pending_assets(self, tmp_path):
        body = b'<html><a href="https://user:s3cr3t@example.com/admin">x</a>' \
               b'<script src="https://user:s3cr3t@example.com/a.js"></script></html>'
        out = tmp_path / "out"
        with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                200, {"Content-Type": "text/html"}, body, final_url=u)):
            cr.run_crawler("https://user:s3cr3t@example.com/", target="example.com",
                           output_dir=str(out), max_depth=1)
        assert "s3cr3t" not in (out / "pending_assets.json").read_text()


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

class TestPersistenceHardening:
    def test_oserror_does_not_destroy_the_page_record(self, tmp_path):
        # One failed write used to take the whole page's intelligence with it.
        body = b'<form method="POST" action="/up" enctype="multipart/form-data">' \
               b'<input type="file" name="f"></form>'
        with mock.patch.object(cr.PendingAssetsStore, "add_many",
                               side_effect=OSError("No space left on device")):
            with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                    200, {"Content-Type": "text/html"}, body, final_url=u)):
                result = cr.run_crawler("https://example.com/", target="example.com",
                                        output_dir=str(tmp_path / "o"), max_depth=0)
        assert len(result["pages"]) == 1
        assert any(e["stage"] == "persistence" for e in result["errors"])
        assert result["status"] == "completed_with_errors"

    @pytest.mark.parametrize("exc", [OSError("disk"), TypeError("bad"), ValueError("bad")])
    def test_safe_store_add_catches_every_persistence_failure(self, tmp_path, exc):
        store = cr.PendingAssetsStore(output_dir=str(tmp_path))
        with mock.patch.object(cr.PendingAssetsStore, "add_many", side_effect=exc):
            assert cr._safe_store_add(store, {"type": "x"}) is not None

    def test_non_serializable_value_is_reported_not_raised(self, tmp_path):
        store = cr.PendingAssetsStore(output_dir=str(tmp_path))
        assert cr._safe_store_add(store, {"type": "x", "value": {1, 2, 3}}) is not None

    def test_add_many_is_atomic_and_preserves_prior_records(self, tmp_path):
        store = cr.PendingAssetsStore(output_dir=str(tmp_path))
        store.add({"type": "prior", "value": 1})
        store.add_many([{"type": "a"}, {"type": "b"}, {"type": "c"}])
        records = json.load(open(store.path))
        assert [r["type"] for r in records] == ["prior", "a", "b", "c"]

    def test_external_rewrite_invalidates_the_cache(self, tmp_path):
        # A stale in-memory cache would have silently dropped another
        # module's concurrently written findings.
        store = cr.PendingAssetsStore(output_dir=str(tmp_path))
        store.add({"type": "mine", "value": 1})
        json.dump([{"type": "other_module", "value": 9}], open(store.path, "w"))
        store.add({"type": "later", "value": 2})
        assert [r["type"] for r in json.load(open(store.path))] == ["other_module", "later"]

    def test_concurrent_writers_lose_nothing(self, tmp_path):
        import threading
        store = cr.PendingAssetsStore(output_dir=str(tmp_path))

        def writer(i):
            for j in range(20):
                store.add({"type": "t", "value": {"i": i, "j": j}})
        threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        records = json.load(open(store.path))
        assert len(records) == 80
        assert len({(r["value"]["i"], r["value"]["j"]) for r in records}) == 80

    def test_corrupt_store_does_not_abort_the_crawl(self, tmp_path):
        out = tmp_path / "o"
        out.mkdir()
        (out / "pending_assets.json").write_text("{not json")
        with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                200, {"Content-Type": "text/html"}, b"<a href='/a'>a</a>", final_url=u)):
            result = cr.run_crawler("https://example.com/", target="example.com",
                                    output_dir=str(out), max_depth=0)
        assert len(result["pages"]) == 1
        assert any(e["stage"] == "persistence" for e in result["errors"])


# ---------------------------------------------------------------------------
# Completeness semantics — a partial crawl must never look complete
# ---------------------------------------------------------------------------

_CHAIN = {f"/p{i}": (200, {"Content-Type": "text/html"},
                     f'<a href="/p{i + 1}">n</a>'.encode()) for i in range(60)}


class TestCompletenessSemantics:
    def test_depth_truncation_is_reported(self, tmp_path):
        # max_depth_reached could never become True, and status said
        # "completed" for a crawl that stopped 57 pages early.
        with mock.patch("requests.get", side_effect=_routed(_CHAIN)):
            r = cr.run_crawler("https://example.com/p0", target="example.com",
                               output_dir=str(tmp_path / "o"), max_depth=2, max_pages=100)
        assert r["max_depth_reached"] is True
        assert r["depth_truncated"] is True
        assert r["crawl_complete"] is False

    def test_budget_exhaustion_is_reported(self, tmp_path):
        with mock.patch("requests.get", side_effect=_routed(_CHAIN)):
            r = cr.run_crawler("https://example.com/p0", target="example.com",
                               output_dir=str(tmp_path / "o"), max_depth=50, max_pages=5)
        assert r["request_budget_exhausted"] is True
        assert r["crawl_complete"] is False
        assert r["requests_made"] == 5

    def test_a_genuinely_finished_crawl_is_complete(self, tmp_path):
        with mock.patch("requests.get", side_effect=_routed({"/": (200, {"Content-Type": "text/html"}, b"done")})):
            r = cr.run_crawler("https://example.com/", target="example.com",
                               output_dir=str(tmp_path / "o"), max_depth=3)
        assert r["crawl_complete"] is True
        assert r["depth_truncated"] is False
        assert r["status"] == "completed"

    def test_truncated_body_is_not_a_negative_result(self, tmp_path):
        big = b"<html><!--" + b"p" * 200000 + b"--><a href='/hidden'>h</a></html>"
        with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                200, {"Content-Type": "text/html"}, big, final_url=u)):
            r = cr.run_crawler("https://example.com/", target="example.com",
                               output_dir=str(tmp_path / "o"), max_depth=1)
        page = r["pages"][0]
        assert page["body_truncated"] is True
        assert page["content_complete"] is False
        assert any("not evidence of absence" in e for e in page["evidence"])
        assert r["crawl_complete"] is False

    def test_keyboard_interrupt_returns_partial_results(self, tmp_path):
        calls = {"n": 0}

        def boom(url, **kwargs):
            calls["n"] += 1
            if calls["n"] == 3:
                raise KeyboardInterrupt()
            return _fake_response(200, {"Content-Type": "text/html"},
                                  b'<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>',
                                  final_url=url)
        with mock.patch("requests.get", side_effect=boom):
            r = cr.run_crawler("https://example.com/", target="example.com",
                               output_dir=str(tmp_path / "o"), max_depth=2, max_workers=1)
        assert r["status"] == "interrupted"
        assert r["cancelled"] is True
        assert r["crawl_complete"] is False
        assert len(r["pages"]) >= 1          # nothing discovered is thrown away

    def test_upload_counter_counts_only_this_run(self, tmp_path):
        out = tmp_path / "o"
        store = cr.PendingAssetsStore(output_dir=str(out))
        for i in range(3):
            store.add(cr.make_finding("file_upload_surface", "example.com",
                                      {"action": f"/old{i}"}, ["prior run"], cr.CONFIDENCE_HIGH))
        with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                200, {"Content-Type": "text/html"}, b"<html>nothing</html>", final_url=u)):
            r = cr.run_crawler("https://example.com/", target="example.com",
                               output_dir=str(out), max_depth=0)
        assert r["file_upload_surfaces_discovered"] == 0


# ---------------------------------------------------------------------------
# Resource bounds
# ---------------------------------------------------------------------------

class TestResourceBounds:
    def test_per_page_link_cap_is_applied_and_recorded(self, tmp_path):
        body = b"<html>" + b"".join(
            f'<a href="/p{i}">x</a>'.encode() for i in range(600)) + b"</html>"
        with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                200, {"Content-Type": "text/html"}, body if u.endswith("/") else b"ok", final_url=u)):
            r = cr.run_crawler("https://example.com/", target="example.com",
                               output_dir=str(tmp_path / "o"), max_depth=1, max_pages=1000)
        assert r["requests_made"] <= cr.DEFAULT_MAX_LINKS_PER_PAGE + 1
        assert any(e["stage"] == "link_cap" for e in r["errors"])   # never silent

    def test_per_page_form_cap_is_applied_and_recorded(self, tmp_path):
        body = b"<html>" + b"".join(
            f'<form action="/f{i}"><input name="a{i}"></form>'.encode() for i in range(300)) + b"</html>"
        with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                200, {"Content-Type": "text/html"}, body, final_url=u)):
            r = cr.run_crawler("https://example.com/", target="example.com",
                               output_dir=str(tmp_path / "o"), max_depth=0)
        assert r["forms_discovered"] <= cr.DEFAULT_MAX_FORMS_PER_PAGE
        assert any(e["stage"] == "form_cap" for e in r["errors"])

    def test_cycle_and_alias_traps_collapse(self, tmp_path):
        body = (b'<a href="/">self</a><a href="/#f">frag</a><a href="/a/../">dot</a>'
                b'<a href="/x?b=2&a=1">q1</a><a href="/x?a=1&b=2">q2</a>')
        with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                200, {"Content-Type": "text/html"}, body, final_url=u)):
            r = cr.run_crawler("https://example.com/", target="example.com",
                               output_dir=str(tmp_path / "o"), max_depth=4, max_pages=100)
        assert r["requests_made"] == 2      # "/" plus the single distinct /x

    def test_huge_attribute_values_are_truncated(self):
        html = '<form action="/x"><input name="a" placeholder="' + "V" * 50000 + '"></form>'
        field = cr.extract_forms(html, "https://example.com/")[0]["fields"][0]
        assert len(field["attributes"]["placeholder"]) <= cr._MAX_ATTR_VALUE_CHARS

    def test_oversized_declared_body_is_not_materialized(self):
        class NoStream:
            status_code = 200
            headers = {"Content-Type": "text/html", "Content-Length": str(50 * 1024 * 1024)}
            encoding = "utf-8"
            url = "https://example.com/"
            elapsed = mock.MagicMock(total_seconds=lambda: 0.01)

            @property
            def raw(self):
                raise AttributeError("no raw")

            @property
            def content(self):
                raise AssertionError("whole body must never be materialized")

            def iter_content(self, chunk_size=8192):
                raise AttributeError("no iter_content")

            def close(self):
                pass
        with mock.patch("requests.get", side_effect=lambda *a, **k: NoStream()):
            result = cr.fetch_url("https://example.com/")
        assert result["status"] == "found"
        assert result.get("body_read_error")

    def test_iter_content_fallback_stops_at_the_cap(self):
        class Chunked:
            status_code = 200
            headers = {"Content-Type": "text/html"}
            encoding = "utf-8"
            url = "https://example.com/"
            elapsed = mock.MagicMock(total_seconds=lambda: 0.01)
            served = 0

            @property
            def raw(self):
                raise AttributeError("no raw")

            def iter_content(self, chunk_size=8192):
                for _ in range(10000):
                    Chunked.served += 1
                    yield b"A" * chunk_size

            def close(self):
                pass
        with mock.patch("requests.get", side_effect=lambda *a, **k: Chunked()):
            result = cr.fetch_url("https://example.com/", max_body_bytes=16384)
        assert result["body_truncated"] is True
        assert len(result["body"]) == 16384
        assert Chunked.served < 100          # stopped early, did not drain the stream

    def test_html_is_parsed_once_per_page(self, tmp_path):
        import bs4
        count = {"n": 0}

        class Counting(bs4.BeautifulSoup):
            def __init__(self, *a, **k):
                count["n"] += 1
                super().__init__(*a, **k)
        with mock.patch.object(cr, "BeautifulSoup", Counting):
            with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                    200, {"Content-Type": "text/html"}, b'<a href="/a">a</a>', final_url=u)):
                cr.run_crawler("https://example.com/", target="example.com",
                               output_dir=str(tmp_path / "o"), max_depth=0)
        assert count["n"] == 1              # was three (links, forms, scripts)


# ---------------------------------------------------------------------------
# Anti-bot challenge classification (detection only — never bypass)
# ---------------------------------------------------------------------------

_CF_CHALLENGE = (b'<html><div id="cf-challenge-running">Checking</div>'
                 b'<form action="/cdn-cgi/l/chk_jschl"><input type="hidden" name="jschl_vc"></form>'
                 b'<script src="/cdn-cgi/challenge-platform/x"></script></html>')


class TestChallengeDetection:
    def test_vendor_header_is_high_confidence(self):
        result = cr.detect_challenge_indicators(b"".decode(), {"cf-mitigated": "challenge"}, 403)
        assert result["kind"] == "bot_challenge"
        assert result["confidence"] == cr.CONFIDENCE_HIGH
        assert "cloudflare" in result["vendors"]

    def test_body_marker_alone_is_medium_confidence(self):
        result = cr.detect_challenge_indicators(_CF_CHALLENGE.decode(), {}, 403)
        assert result["kind"] == "bot_challenge"
        assert result["confidence"] == cr.CONFIDENCE_MEDIUM

    def test_prose_about_cloudflare_is_not_a_challenge(self):
        # False positive check: the bare words prove nothing.
        blog = ("<html><h1>How Cloudflare CAPTCHA works</h1>"
                "<p>A captcha blocks bots; we were blocked by cloudflare once.</p></html>")
        assert cr.detect_challenge_indicators(blog, {"Content-Type": "text/html"}, 200) is None

    def test_captcha_widget_is_not_a_block(self):
        page = '<form action="/signup"><input name="email">' \
               '<div class="g-recaptcha" data-sitekey="k"></div></form>'
        result = cr.detect_challenge_indicators(page, {}, 200)
        assert result["kind"] == "captcha_widget"
        assert result["vendors"] == ["recaptcha"]

    def test_ordinary_page_yields_nothing(self):
        assert cr.detect_challenge_indicators("<html><p>hello</p></html>", {}, 200) is None

    def test_challenge_form_is_marked_not_reported_as_application_surface(self, tmp_path):
        out = tmp_path / "o"
        with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                403, {"Content-Type": "text/html", "cf-mitigated": "challenge"},
                _CF_CHALLENGE, final_url=u)):
            r = cr.run_crawler("https://example.com/", target="example.com",
                               output_dir=str(out), max_depth=0)
        assert r["challenge_pages"] == 1
        assert r["crawl_complete"] is False          # blocked != nothing there
        assert r["pages"][0]["challenge"]["kind"] == "bot_challenge"
        forms = [f for f in json.load(open(out / "pending_assets.json"))
                 if f["type"] == "crawled_form"]
        assert forms and forms[0]["value"]["challenge_artifact"] is True
        assert forms[0]["confidence"] == cr.CONFIDENCE_LOW

    def test_challenge_page_never_raises_a_file_upload_surface(self, tmp_path):
        body = (b'<html><div id="cf-challenge-running">x</div>'
                b'<form enctype="multipart/form-data"><input type="file" name="f"></form></html>')
        with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                403, {"Content-Type": "text/html", "cf-mitigated": "challenge"}, body, final_url=u)):
            r = cr.run_crawler("https://example.com/", target="example.com",
                               output_dir=str(tmp_path / "o"), max_depth=0)
        assert r["file_upload_surfaces_discovered"] == 0


# ---------------------------------------------------------------------------
# Destructive-endpoint safety
# ---------------------------------------------------------------------------

class TestDestructiveEndpointSafety:
    """The safety mode is opt-in (avoid_destructive=False by default).

    It answers one crawler-owned question — "would requesting this URL
    change server-side state?" — and deliberately does not classify auth
    surfaces, which is http_analyzer.py's responsibility (context.md
    module 16). Hence a single reason code.
    """

    @pytest.mark.parametrize("url,matched", [
        ("https://e.com/logout", "logout"),
        ("https://e.com/LOGOUT/", "logout"),
        ("https://e.com/logout.php", "logout"),
        ("https://e.com/api/session/destroy", "destroy"),
        ("https://e.com/auth/tokens/revoke", "revoke"),
        ("https://e.com/account/delete?id=7", "delete"),
        ("https://e.com/posts/delete/42", "delete"),
        ("https://e.com/users/12/remove", "remove"),
        ("https://e.com/index.php?action=logout", "action=logout"),
        ("https://e.com/x?do=purge", "do=purge"),
    ])
    def test_state_changing_urls_are_identified(self, url, matched):
        result = cr.classify_destructive_candidate(url)
        assert result is not None
        assert result["reason"] == "state_changing_endpoint"
        assert result["matched"] == matched

    def test_single_reason_code_no_auth_taxonomy(self):
        """Module-boundary guard: the crawler must not grow an auth-surface
        vocabulary. Every withheld request reports the same request-safety
        reason; naming login/logout/OAuth/SSO surfaces belongs to
        http_analyzer.py."""
        urls = ["https://e.com/logout", "https://e.com/api/session/destroy",
                "https://e.com/account/delete?id=7", "https://e.com/x?do=purge",
                "https://e.com/auth/tokens/revoke", "https://e.com/posts/delete/42"]
        reasons = {cr.classify_destructive_candidate(u)["reason"] for u in urls}
        assert reasons == {"state_changing_endpoint"}

    def test_withheld_record_confidence_describes_the_finding(self):
        """Confidence is about the crawled_url finding (this URL was
        discovered and not fetched), which is certain — not a graded opinion
        about what the endpoint does."""
        for u in ("https://e.com/logout", "https://e.com/account/delete?id=7"):
            assert cr.classify_destructive_candidate(u)["confidence"] == cr.CONFIDENCE_HIGH

    @pytest.mark.parametrize("url", [
        # False-negative guard: ordinary GET-safe pages that merely read as
        # destructive. Suppressing these would throw away real surface.
        "https://e.com/password/reset",
        "https://e.com/account/reset-password",
        "https://e.com/newsletter/unsubscribe",
        "https://e.com/docs/remove",
        "https://e.com/blog/how-to-delete-a-file",
        "https://e.com/deleted-items",
        "https://e.com/undelete",
        "https://e.com/removals",
        "https://e.com/logout-guide.html",
        "https://e.com/admin/users",
    ])
    def test_ordinary_pages_are_not_suppressed(self, url):
        assert cr.classify_destructive_candidate(url) is None

    def test_default_fetches_destructive_urls(self, tmp_path):
        """Backward compatibility: callers that do not opt in — including
        core/orchestrator.py, which passes no such argument — must reach
        exactly what they reached before the audit."""
        out = tmp_path / "o"
        requested = []

        def spy(url, **kwargs):
            requested.append(url)
            return _fake_response(200, {"Content-Type": "text/html"},
                                  b'<a href="/logout">out</a><a href="/about">about</a>'
                                  if url.endswith("/") else b"ok", final_url=url)
        with mock.patch("requests.get", side_effect=spy):
            r = cr.run_crawler("https://example.com/", target="example.com",
                               output_dir=str(out), max_depth=1)
        assert "https://example.com/logout" in requested
        assert "https://example.com/about" in requested
        assert r["destructive_endpoints_skipped"] == 0
        # Nothing is marked unfetched, and no skip metadata reaches downstream.
        assert not [f for f in json.load(open(out / "pending_assets.json"))
                    if f["type"] == "crawled_url" and f["value"].get("skip_reason")]

    def test_opt_in_records_but_never_requests(self, tmp_path):
        out = tmp_path / "o"
        requested = []

        def spy(url, **kwargs):
            requested.append(url)
            return _fake_response(200, {"Content-Type": "text/html"},
                                  b'<a href="/logout">out</a><a href="/about">about</a>'
                                  if url.endswith("/") else b"ok", final_url=url)
        with mock.patch("requests.get", side_effect=spy):
            r = cr.run_crawler("https://example.com/", target="example.com",
                               output_dir=str(out), max_depth=1, avoid_destructive=True)
        assert "https://example.com/logout" not in requested
        assert "https://example.com/about" in requested
        assert r["destructive_endpoints_skipped"] == 1
        skipped = [f for f in json.load(open(out / "pending_assets.json"))
                   if f["type"] == "crawled_url" and f["value"].get("skip_reason")]
        assert len(skipped) == 1                       # recorded, not discarded
        assert skipped[0]["value"]["url"] == "https://example.com/logout"
        assert skipped[0]["value"]["fetched"] is False
        assert skipped[0]["value"]["skip_reason"] == "state_changing_endpoint"

    def test_operator_supplied_seed_is_never_suppressed(self, tmp_path):
        requested = []

        def spy(url, **kwargs):
            requested.append(url)
            return _fake_response(200, {"Content-Type": "text/html"}, b"ok", final_url=url)
        with mock.patch("requests.get", side_effect=spy):
            cr.run_crawler("https://example.com/logout", target="example.com",
                           output_dir=str(tmp_path / "o"), max_depth=0,
                           avoid_destructive=True)
        assert requested == ["https://example.com/logout"]

    def test_cli_flag_is_opt_in(self):
        """--avoid-destructive-endpoints turns the mode ON; absent, it is off."""
        src = io.open("reconhound/crawler.py", encoding="utf-8").read()
        assert "--avoid-destructive-endpoints" in src
        assert "avoid_destructive=args.avoid_destructive_endpoints" in src
        assert "--allow-destructive-endpoints" not in src


# ---------------------------------------------------------------------------
# Indicator scope + response-semantics counterchecks
# ---------------------------------------------------------------------------

class TestIndicatorSemantics:
    def test_out_of_scope_websocket_is_flagged(self, tmp_path):
        out = tmp_path / "o"
        body = (b'<script>new WebSocket("wss://example.com/live");'
                b'new WebSocket("wss://attacker.example/steal");</script>')
        with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                200, {"Content-Type": "text/html"}, body, final_url=u)):
            cr.run_crawler("https://example.com/", target="example.com",
                           output_dir=str(out), max_depth=0)
        flags = {f["value"]["endpoint"]: f["value"]["in_scope"]
                 for f in json.load(open(out / "pending_assets.json"))
                 if f["type"] == "websocket_indicator"}
        assert flags == {"wss://example.com/live": True, "wss://attacker.example/steal": False}

    def test_dynamic_websocket_scope_is_unknown_not_false(self):
        assert cr._ws_endpoint_in_scope(None, "example.com") is None

    def test_generic_json_errors_are_not_graphql(self):
        # False positive check: "errors" in a JSON body proves nothing.
        assert cr.detect_graphql_indicators(
            '{"errors":[{"message":"bad request"}]}', "https://example.com/api/v1/users",
            headers={"Content-Type": "application/json"}) == []

    def test_503_is_not_reported_as_rate_limiting(self):
        kind, _, _ = cr.classify_response({"status_code": 503, "headers": {}})
        assert kind == "server_error_response"

    def test_429_records_retry_after_as_evidence(self):
        kind, confidence, notes = cr.classify_response(
            {"status_code": 429, "headers": {"Retry-After": "120"}})
        assert kind == "rate_limited"
        assert confidence == cr.CONFIDENCE_LOW
        assert any("Retry-After: 120" in n for n in notes)

    def test_rate_limited_run_is_not_conclusive(self, tmp_path):
        with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                429, {"Retry-After": "60"}, b"slow down", final_url=u)):
            r = cr.run_crawler("https://example.com/", target="example.com",
                               output_dir=str(tmp_path / "o"), max_depth=0)
        assert r["rate_limited"] is True
        assert r["crawl_complete"] is False
        assert r["pages"][0]["discovery_type"] == "rate_limited"

    def test_401_is_access_restricted_not_an_api_claim(self):
        kind, _, _ = cr.classify_response({"status_code": 401, "headers": {}})
        assert kind == "access_restricted"

    def test_redirect_location_header_credentials_are_stripped(self, tmp_path):
        # A Location header carrying "user:pass@host" was persisted verbatim
        # into the crawled_url record and rendered in the report appendix.
        out = tmp_path / "o"

        def srv(url, **kwargs):
            if "/old" in url:
                return _fake_response(
                    302, {"Location": "https://user:s3cr3t@example.com/new"}, b"", final_url=url)
            return _fake_response(200, {"Content-Type": "text/html"}, b"ok", final_url=url)
        with mock.patch("requests.get", side_effect=srv):
            result = cr.run_crawler("https://example.com/old", target="example.com",
                                    output_dir=str(out), max_depth=1)
        assert "s3cr3t" not in (out / "pending_assets.json").read_text()
        assert "s3cr3t" not in json.dumps(result)
        assert result["pages"][0]["redirect_location"] == "https://example.com/new"

    def test_websocket_literal_credentials_are_stripped(self, tmp_path):
        # "wss://user:pass@host/ws" was persisted verbatim as the endpoint.
        out = tmp_path / "o"
        body = b'<script>new WebSocket("wss://user:s3cr3t@example.com/ws");</script>'
        with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                200, {"Content-Type": "text/html"}, body, final_url=u)):
            cr.run_crawler("https://example.com/", target="example.com",
                           output_dir=str(out), max_depth=0)
        text = (out / "pending_assets.json").read_text()
        assert "s3cr3t" not in text
        assert "wss://example.com/ws" in text
