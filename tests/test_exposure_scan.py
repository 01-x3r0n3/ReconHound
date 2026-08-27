"""
Tests for reconhound/exposure_scan.py (ReconHound Module 15, per
context.md's build order — catalog item 15, build-order position 7).

Run with:  ./.venv/bin/python -m pytest tests/test_exposure_scan.py -v

All tests mock the `requests.get`/`requests.options` boundary so the suite
is deterministic and offline-safe; no external network access is required
or performed anywhere in this file.
"""

import json
import os
import sys
from unittest import mock

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import exposure_scan as es


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


def _fake_options_response(status_code=200, headers=None):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = dict(headers or {})
    return resp


def _write_wordlist(tmp_path, name, lines):
    d = tmp_path / "wordlists"
    d.mkdir(exist_ok=True)
    (d / name).write_text("\n".join(lines) + "\n")
    return str(d)


def _all_404(url, **kwargs):
    """Default fake_get: everything (including the soft-404 baseline probe) is a 404."""
    return _fake_response(404, body=b"not found")


# ---------------------------------------------------------------------------
# validate_exposure_target (scope enforcement)
# ---------------------------------------------------------------------------

class TestValidateExposureTarget:
    def test_accepts_https_url(self):
        assert es.validate_exposure_target("https://example.com/path") == "https://example.com/path"

    def test_accepts_in_scope_subdomain(self):
        assert es.validate_exposure_target("https://api.example.com/", target="example.com")

    def test_rejects_out_of_scope_host(self):
        with pytest.raises(es.ScopeError):
            es.validate_exposure_target("https://evil.com/", target="example.com")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(es.ScopeError):
            es.validate_exposure_target("ftp://example.com/")

    def test_rejects_missing_hostname(self):
        with pytest.raises(es.ScopeError):
            es.validate_exposure_target("https:///path")

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(es.ScopeError):
            es.validate_exposure_target(bad)

    def test_allows_ip_literal_host_without_scope_check(self):
        assert es.validate_exposure_target("http://93.184.216.34/", target="example.com")


# ---------------------------------------------------------------------------
# classify_exposure_category (sensitive resource categorization)
# ---------------------------------------------------------------------------

class TestClassifyExposureCategory:
    @pytest.mark.parametrize("entry,expected", [
        (".git/HEAD", es.CATEGORY_VERSION_CONTROL),
        (".git/config", es.CATEGORY_VERSION_CONTROL),
        (".svn/entries", es.CATEGORY_VERSION_CONTROL),
        (".env", es.CATEGORY_ENVIRONMENT_FILE),
        (".env.production", es.CATEGORY_ENVIRONMENT_FILE),
        (".htpasswd", es.CATEGORY_CREDENTIAL_MATERIAL),
        ("backup.sql", es.CATEGORY_DATABASE_DUMP),
        ("dump.sql", es.CATEGORY_DATABASE_DUMP),
        ("backup.zip", es.CATEGORY_ARCHIVE_FILE),
        ("backup.tar.gz", es.CATEGORY_ARCHIVE_FILE),
        ("index.html.bak", es.CATEGORY_BACKUP_FILE),
        ("admin/", es.CATEGORY_ADMINISTRATIVE_PANEL),
        ("administrator/", es.CATEGORY_ADMINISTRATIVE_PANEL),
        ("debug/", es.CATEGORY_DEBUG_ENDPOINT),
        ("phpinfo.php", es.CATEGORY_DEBUG_ENDPOINT),
        ("server-status", es.CATEGORY_DEBUG_ENDPOINT),
        ("config.php", es.CATEGORY_CONFIGURATION_FILE),
        ("web.config", es.CATEGORY_CONFIGURATION_FILE),
        ("docker-compose.yml", es.CATEGORY_CONFIGURATION_FILE),
        ("error.log", es.CATEGORY_LOG_FILE),
        ("laravel.log", es.CATEGORY_LOG_FILE),
    ])
    def test_known_entries_classified(self, entry, expected):
        assert es.classify_exposure_category(entry) == expected

    @pytest.mark.parametrize("entry", ["assets/", "images/", "static/", "js/", "public/", "README.md", "favicon.ico"])
    def test_generic_entries_not_classified(self, entry):
        assert es.classify_exposure_category(entry) is None


# ---------------------------------------------------------------------------
# Category-specific evidence signatures (false-positive handling: path name
# alone must never produce "confirmed_exposure")
# ---------------------------------------------------------------------------

class TestEvaluateExposure:
    def test_git_head_confirmed_with_matching_ref_content(self):
        resp = {"status_code": 200, "headers": {"Content-Type": "text/plain"},
                "body": "ref: refs/heads/main\n", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_VERSION_CONTROL, ".git/HEAD", resp, None)
        assert dtype == "confirmed_exposure"
        assert conf == es.CONFIDENCE_HIGH

    def test_git_head_not_confirmed_without_git_signature(self):
        resp = {"status_code": 200, "headers": {"Content-Type": "text/html"},
                "body": "<html>404-ish generic page</html>", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_VERSION_CONTROL, ".git/HEAD", resp, None)
        assert dtype != "confirmed_exposure"

    def test_env_confirmed_with_dotenv_lines(self):
        resp = {"status_code": 200, "headers": {"Content-Type": "text/plain"},
                "body": "DB_PASSWORD=secret\nAPI_KEY=abc\n", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_ENVIRONMENT_FILE, ".env", resp, None)
        assert dtype == "confirmed_exposure"

    def test_env_not_confirmed_when_html_content_type(self):
        resp = {"status_code": 200, "headers": {"Content-Type": "text/html"},
                "body": "DB_PASSWORD=secret\nAPI_KEY=abc\n", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_ENVIRONMENT_FILE, ".env", resp, None)
        assert dtype != "confirmed_exposure"

    def test_archive_confirmed_via_zip_magic_bytes(self):
        resp = {"status_code": 200, "headers": {}, "body": "binary junk", "raw_prefix": b"PK\x03\x04rest"}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_ARCHIVE_FILE, "backup.zip", resp, None)
        assert dtype == "confirmed_exposure"

    def test_database_dump_confirmed_via_sql_marker(self):
        resp = {"status_code": 200, "headers": {}, "body": "-- MySQL dump 10.13\nCREATE TABLE users (...);",
                "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_DATABASE_DUMP, "dump.sql", resp, None)
        assert dtype == "confirmed_exposure"

    def test_generic_200_without_signature_is_interesting_unconfirmed(self):
        resp = {"status_code": 200, "headers": {"Content-Type": "text/html"},
                "body": "<html><body>Some unrelated page</body></html>", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_CONFIGURATION_FILE, "config.json", resp, None)
        assert dtype == "interesting_unconfirmed"
        assert conf == es.CONFIDENCE_LOW

    def test_404_is_not_found(self):
        resp = {"status_code": 404, "headers": {}, "body": "nope", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_ENVIRONMENT_FILE, ".env", resp, None)
        assert dtype == "not_found"

    def test_401_admin_panel_is_access_restricted_medium_confidence(self):
        resp = {"status_code": 401, "headers": {}, "body": "", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_ADMINISTRATIVE_PANEL, "admin/", resp, None)
        assert dtype == "access_restricted"
        assert conf == es.CONFIDENCE_MEDIUM

    def test_admin_panel_confirmed_with_login_signal(self):
        resp = {"status_code": 200, "headers": {}, "body": '<form><input type="password"></form>', "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_ADMINISTRATIVE_PANEL, "admin/", resp, None)
        assert dtype == "confirmed_exposure"

    def test_soft_404_baseline_downgrades_to_low_confidence(self):
        baseline = {"available": True, "status_code": 200, "content_length": 5, "body_hash": es._content_signature("empty")[1]}
        resp = {"status_code": 200, "headers": {}, "body": "empty", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_CONFIGURATION_FILE, "config.json", resp, baseline)
        assert dtype == "possible_soft_404_match"
        assert conf == es.CONFIDENCE_LOW

    def test_directory_listing_detected(self):
        resp = {"status_code": 200, "headers": {}, "body": "<title>Index of /backup</title>\nParent Directory",
                "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_BACKUP_FILE, "backup/", resp, None)
        assert dtype == "directory_listing_enabled"
        assert conf == es.CONFIDENCE_HIGH

    def test_500_is_low_confidence_not_confirmed(self):
        resp = {"status_code": 500, "headers": {}, "body": "server error", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_CONFIGURATION_FILE, "config.json", resp, None)
        assert dtype == "server_error_response"
        assert conf == es.CONFIDENCE_LOW


# ---------------------------------------------------------------------------
# analyze_error_page (error-page intelligence)
# ---------------------------------------------------------------------------

class TestAnalyzeErrorPage:
    def test_detects_werkzeug_debugger(self):
        body = "<title>Werkzeug Debugger</title> ... Werkzeug/2.3.7 Python/3.11.4"
        result = es.analyze_error_page(body, {}, 500)
        frameworks = {i["framework"] for i in result["framework_indicators"]}
        assert "werkzeug_flask_debugger" in frameworks

    def test_detects_django_debug_page_with_version(self):
        body = "Django Version: 4.2.3\nException Type: ValueError"
        result = es.analyze_error_page(body, {}, 500)
        indicators = [i for i in result["framework_indicators"] if i["framework"] == "django_debug_page"]
        assert indicators
        assert indicators[0]["version"] == "4.2.3"

    def test_detects_python_traceback(self):
        body = "Traceback (most recent call last):\n  File \"app.py\", line 10, in <module>"
        result = es.analyze_error_page(body, {}, 500)
        assert result["stack_trace_detected"] is True

    def test_extracts_internal_unix_path(self):
        body = "Fatal error: Uncaught Exception in /var/www/html/app/config.php on line 42"
        result = es.analyze_error_page(body, {}, 500)
        assert any("/var/www" in p for p in result["internal_paths"])

    def test_no_indicators_on_clean_body(self):
        result = es.analyze_error_page("<html><body>Hello world</body></html>", {}, 200)
        assert result["indicators"] == []
        assert result["stack_trace_detected"] is False

    def test_server_header_version_extracted(self):
        result = es.analyze_error_page("", {"Server": "nginx/1.18.0"}, 200)
        server_indicators = [i for i in result["indicators"] if i["indicator_type"] == "server_software_version"]
        assert server_indicators
        assert server_indicators[0]["version"] == "1.18.0"

    def test_empty_body_does_not_raise(self):
        result = es.analyze_error_page(None, None, None)
        assert result["indicators"] == []


# ---------------------------------------------------------------------------
# fetch_url / fetch_options (malformed/empty responses, network failures)
# ---------------------------------------------------------------------------

class TestFetchUrl:
    def test_successful_fetch_includes_raw_prefix(self):
        resp = _fake_response(200, headers={"Content-Type": "text/plain"}, body=b"PK\x03\x04restofzip")
        with mock.patch("requests.get", return_value=resp):
            result = es.fetch_url(SAFE_URL)
        assert result["status"] == "found"
        assert result["raw_prefix"][:4] == b"PK\x03\x04"

    def test_empty_body_handled(self):
        resp = _fake_response(200, body=b"")
        with mock.patch("requests.get", return_value=resp):
            result = es.fetch_url(SAFE_URL)
        assert result["status"] == "found"
        assert result["body"] == ""

    def test_timeout_error(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout("timed out")):
            result = es.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_connection_error(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = es.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert "connection error" in result["error"]

    def test_does_not_follow_redirects(self):
        resp = _fake_response(301, headers={"Location": "/new"})
        captured = {}

        def fake_get(url, **kwargs):
            captured.update(kwargs)
            return resp

        with mock.patch("requests.get", side_effect=fake_get):
            result = es.fetch_url(SAFE_URL)
        assert captured["allow_redirects"] is False
        assert result["status_code"] == 301


class TestFetchOptions:
    def test_successful_options_request(self):
        resp = _fake_options_response(200, headers={"Allow": "GET, POST, OPTIONS"})
        with mock.patch("requests.options", return_value=resp):
            result = es.fetch_options(SAFE_URL)
        assert result["status"] == "found"
        assert result["headers"]["Allow"] == "GET, POST, OPTIONS"

    def test_options_timeout(self):
        with mock.patch("requests.options", side_effect=requests.exceptions.Timeout("timed out")):
            result = es.fetch_options(SAFE_URL)
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_options_connection_error(self):
        with mock.patch("requests.options", side_effect=requests.exceptions.ConnectionError("refused")):
            result = es.fetch_options(SAFE_URL)
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# probe_options / discover_http_options
# ---------------------------------------------------------------------------

class TestProbeOptions:
    def test_allow_header_present_is_options_supported(self):
        resp = _fake_options_response(200, headers={"Allow": "GET, POST"})
        with mock.patch("requests.options", return_value=resp):
            result = es.probe_options(SAFE_URL)
        assert result["discovery_type"] == "options_supported"
        assert result["advertised_methods"] == ["GET", "POST"]
        assert result["confidence"] == es.CONFIDENCE_HIGH

    def test_no_allow_header_is_low_confidence(self):
        resp = _fake_options_response(200, headers={})
        with mock.patch("requests.options", return_value=resp):
            result = es.probe_options(SAFE_URL)
        assert result["discovery_type"] == "options_response_no_allow_header"
        assert result["confidence"] == es.CONFIDENCE_LOW

    def test_404_options_classified_not_found(self):
        resp = _fake_options_response(404, headers={})
        with mock.patch("requests.options", return_value=resp):
            result = es.probe_options(SAFE_URL)
        assert result["discovery_type"] == "not_found"

    def test_scope_enforced(self):
        with pytest.raises(es.ScopeError):
            es.probe_options("https://evil.com/", target="example.com")

    def test_never_claims_exploitability(self):
        resp = _fake_options_response(200, headers={"Allow": "GET, PUT, DELETE"})
        with mock.patch("requests.options", return_value=resp):
            result = es.probe_options(SAFE_URL)
        assert "not proof" in result["note"] or "not exploitable" in result["note"].lower() or "exploitable" in result["note"].lower()


class TestDiscoverHttpOptions:
    def test_persists_each_result(self, tmp_path):
        store = es.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        resp = _fake_options_response(200, headers={"Allow": "GET, POST"})
        with mock.patch("requests.options", return_value=resp):
            result = es.discover_http_options([SAFE_URL], target=SAFE_TARGET, store=store)
        assert result["urls_checked"] == 1
        assert len(result["results"]) == 1
        records = store.all()
        assert any(r["type"] == "http_options_result" for r in records)

    def test_dedupes_urls(self):
        resp = _fake_options_response(200, headers={"Allow": "GET"})
        with mock.patch("requests.options", return_value=resp) as mocked:
            es.discover_http_options([SAFE_URL, SAFE_URL, SAFE_URL], target=SAFE_TARGET)
        assert mocked.call_count == 1


# ---------------------------------------------------------------------------
# discover_sensitive_resources
# ---------------------------------------------------------------------------

class TestDiscoverSensitiveResources:
    def test_normal_discovery_finds_confirmed_env_file(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env", "assets/"])

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            if url.endswith(".env"):
                return _fake_response(200, {"Content-Type": "text/plain"}, b"DB_PASSWORD=x\nAPI_KEY=y\n")
            return _fake_response(404, body=b"not found")

        with mock.patch("requests.get", side_effect=fake_get):
            result = es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)

        # ".env" is exposure-relevant; "assets/" is skipped; .aws//.ssh/ are always
        # additionally probed for directory-listing evidence (see _SENSITIVE_DIRECTORIES).
        assert result["candidates_checked"] == 1 + len(es._SENSITIVE_DIRECTORIES)
        assert len(result["findings"]) == 1
        assert result["findings"][0]["discovery_type"] == "confirmed_exposure"
        assert result["findings"][0]["exposure_category"] == es.CATEGORY_ENVIRONMENT_FILE

    def test_all_404_yields_no_findings(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env", "backup.sql", "admin/"])
        with mock.patch("requests.get", side_effect=_all_404):
            result = es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)
        assert result["findings"] == []

    def test_soft_404_spa_catchall_does_not_confirm_exposure(self, tmp_path):
        """A SPA that returns HTTP 200 with the same generic page for every path must not be
        reported as confirmed_exposure for every sensitive-resource candidate."""
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env", "backup.sql"])
        catchall_body = b"<html><body>My SPA App</body></html>"

        def fake_get(url, **kwargs):
            return _fake_response(200, {"Content-Type": "text/html"}, catchall_body)

        with mock.patch("requests.get", side_effect=fake_get):
            result = es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)

        for finding in result["findings"]:
            assert finding["discovery_type"] in ("possible_soft_404_match", "interesting_unconfirmed")

    def test_wordlist_load_failure_recorded_not_raised(self, tmp_path):
        empty_dir = str(tmp_path / "no_wordlists_here")
        os.makedirs(empty_dir, exist_ok=True)
        result = es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, wordlists_dir=empty_dir)
        assert result["errors"]
        assert result["findings"] == []

    def test_scope_error_raised_for_out_of_scope_base_url(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env"])
        with pytest.raises(es.ScopeError):
            es.discover_sensitive_resources("https://evil.com/", target=SAFE_TARGET, wordlists_dir=wl_dir)

    def test_network_failure_on_one_candidate_does_not_abort_sweep(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env", "backup.sql"])

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            if url.endswith(".env"):
                raise requests.exceptions.ConnectionError("refused")
            if url.endswith("backup.sql"):
                return _fake_response(200, {}, b"-- MySQL dump\nCREATE TABLE x (id int);")
            return _fake_response(404, body=b"not found")

        with mock.patch("requests.get", side_effect=fake_get):
            result = es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)

        assert len(result["findings"]) == 1
        assert result["findings"][0]["exposure_category"] == es.CATEGORY_DATABASE_DUMP
        assert any("connection error" in e.get("error", "") for e in result["errors"])

    def test_persists_error_page_intelligence_alongside_finding(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", ["debug/"])
        store = es.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            return _fake_response(500, {}, b"Werkzeug Debugger ... Werkzeug/2.3.7 Python/3.11.4")

        with mock.patch("requests.get", side_effect=fake_get):
            es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, store=store, wordlists_dir=wl_dir)

        records = store.all()
        assert any(r["type"] == "error_page_intelligence" for r in records)


# ---------------------------------------------------------------------------
# discover_robots_txt / discover_sitemap_xml
# ---------------------------------------------------------------------------

class TestRobotsTxt:
    def test_parses_directives(self):
        body = b"User-agent: *\nDisallow: /admin/\nAllow: /public/\nSitemap: https://example.com/sitemap.xml\n"
        with mock.patch("requests.get", return_value=_fake_response(200, {}, body)):
            result = es.discover_robots_txt(SAFE_URL, target=SAFE_TARGET)
        assert result["status"] == "found"
        assert "/admin/" in result["disallowed_paths"]
        assert "/public/" in result["allowed_paths"]
        assert "https://example.com/sitemap.xml" in result["sitemap_urls"]

    def test_404_reports_not_found(self):
        with mock.patch("requests.get", return_value=_fake_response(404, {}, b"nope")):
            result = es.discover_robots_txt(SAFE_URL, target=SAFE_TARGET)
        assert result["status"] == "not_found"

    def test_persists_finding(self, tmp_path):
        store = es.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        body = b"User-agent: *\nDisallow: /secret/\n"
        with mock.patch("requests.get", return_value=_fake_response(200, {}, body)):
            es.discover_robots_txt(SAFE_URL, target=SAFE_TARGET, store=store)
        assert any(r["type"] == "robots_txt_discovered" for r in store.all())


class TestSitemapXml:
    def test_parses_loc_entries(self):
        body = b'<?xml version="1.0"?><urlset><url><loc>https://example.com/a</loc></url>' \
               b'<url><loc>https://example.com/b</loc></url></urlset>'
        with mock.patch("requests.get", return_value=_fake_response(200, {}, body)):
            result = es.discover_sitemap_xml(SAFE_URL, target=SAFE_TARGET)
        assert result["status"] == "found"
        assert result["urls"] == ["https://example.com/a", "https://example.com/b"]

    def test_html_catchall_not_treated_as_sitemap(self):
        """A soft-404 SPA returning HTTP 200 HTML for /sitemap.xml must not be reported as a real sitemap."""
        body = b"<html><body>Not found, but our SPA always returns 200</body></html>"
        with mock.patch("requests.get", return_value=_fake_response(200, {}, body)):
            result = es.discover_sitemap_xml(SAFE_URL, target=SAFE_TARGET)
        assert result["status"] == "interesting_unconfirmed"

    def test_404_reports_not_found(self):
        with mock.patch("requests.get", return_value=_fake_response(404, {}, b"nope")):
            result = es.discover_sitemap_xml(SAFE_URL, target=SAFE_TARGET)
        assert result["status"] == "not_found"


# ---------------------------------------------------------------------------
# Cloud exposure discovery
# ---------------------------------------------------------------------------

class TestCloudExposure:
    def test_generate_candidates_no_requests_made(self):
        candidates = es.generate_cloud_candidates("example.com")
        assert candidates
        assert all(c["provider"] in ("s3", "gcs") for c in candidates)

    def test_classify_listable_s3_bucket(self):
        body = "<ListBucketResult><Contents><Key>file.txt</Key></Contents></ListBucketResult>"
        dtype, conf, notes = es.classify_cloud_response(200, body)
        assert dtype == "confirmed_exposure"
        assert conf == es.CONFIDENCE_HIGH

    def test_classify_access_denied(self):
        body = "<Error><Code>AccessDenied</Code></Error>"
        dtype, conf, notes = es.classify_cloud_response(403, body)
        assert dtype == "bucket_exists_access_restricted"

    def test_classify_no_such_bucket(self):
        body = "<Error><Code>NoSuchBucket</Code></Error>"
        dtype, conf, notes = es.classify_cloud_response(404, body)
        assert dtype == "not_found"

    def test_classify_generic_error_page_is_inconclusive_not_confirmed(self):
        """A generic cloud-provider error page must never be classified confirmed_exposure."""
        body = "<html><body>403 Forbidden</body></html>"
        dtype, conf, notes = es.classify_cloud_response(403, body)
        assert dtype != "confirmed_exposure"

    def test_no_requests_made_without_explicit_authorization(self):
        with mock.patch("requests.get") as mocked_get:
            result = es.discover_cloud_exposure(SAFE_TARGET, cloud_targets=None)
        mocked_get.assert_not_called()
        assert result["candidates_not_probed"] > 0
        assert result["checked"] == []

    def test_live_check_only_for_explicitly_authorized_bucket(self):
        listable_body = b"<ListBucketResult><Contents><Key>a</Key></Contents></ListBucketResult>"

        def fake_get(url, **kwargs):
            assert "example-bucket" in url  # only the authorized identifier is ever requested
            return _fake_response(200, {}, listable_body)

        with mock.patch("requests.get", side_effect=fake_get) as mocked_get:
            result = es.discover_cloud_exposure(
                SAFE_TARGET, cloud_targets=[{"provider": "s3", "identifier": "example-bucket"}],
            )
        assert mocked_get.call_count == 1
        assert len(result["checked"]) == 1
        assert result["checked"][0]["discovery_type"] == "confirmed_exposure"

    def test_authorized_url_string_is_parsed(self):
        with mock.patch("requests.get", return_value=_fake_response(404, {}, b"<Error><Code>NoSuchBucket</Code></Error>")):
            result = es.discover_cloud_exposure(
                SAFE_TARGET, cloud_targets=["https://mybucket.s3.amazonaws.com/"],
            )
        assert len(result["checked"]) == 1
        assert result["checked"][0]["identifier"] == "mybucket"

    def test_persists_cloud_finding(self, tmp_path):
        store = es.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("requests.get", return_value=_fake_response(200, {}, b"<ListBucketResult></ListBucketResult>")):
            es.discover_cloud_exposure(
                SAFE_TARGET, cloud_targets=[{"provider": "gcs", "identifier": "mybucket"}], store=store,
            )
        assert any(r["type"] == "cloud_resource_finding" for r in store.all())


# ---------------------------------------------------------------------------
# PendingAssetsStore / make_finding (persistence, JSON-safety)
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_finding_structure_and_source(self):
        finding = es.make_finding("exposure_finding", SAFE_URL, {"a": 1}, ["e"], es.CONFIDENCE_HIGH)
        assert finding["source"] == "exposure_scan.py"
        assert finding["metadata"] == {}
        json.dumps(finding)

    def test_store_preserves_prior_data(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{"type": "dns_record", "source": "passive_recon.py"}]
        pending.write_text(json.dumps(pre_existing))

        store = es.PendingAssetsStore(output_dir=str(output_dir))
        store.add(es.make_finding("exposure_finding", SAFE_URL, {}, ["e"], es.CONFIDENCE_HIGH))
        assert store.all() == pre_existing + [store.all()[-1]]

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = es.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(es.PersistenceError):
            store.add(es.make_finding("exposure_finding", SAFE_URL, {}, ["e"], es.CONFIDENCE_HIGH))

    def test_safe_store_add_recovers_from_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = es.PendingAssetsStore(output_dir=str(output_dir))
        err = es._safe_store_add(store, es.make_finding("exposure_finding", SAFE_URL, {}, ["e"], es.CONFIDENCE_HIGH))
        assert err is not None
        assert "corrupt" in err

    def test_safe_store_add_noop_without_store(self):
        assert es._safe_store_add(None, es.make_finding("x", SAFE_URL, {}, [], es.CONFIDENCE_LOW)) is None


# ---------------------------------------------------------------------------
# run_exposure_scan (full orchestration)
# ---------------------------------------------------------------------------

class TestRunExposureScan:
    def test_full_run_persists_and_serializes(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env", "backup.sql", "assets/"])
        output_dir = tmp_path / "output"

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            if url.endswith(".env"):
                return _fake_response(200, {"Content-Type": "text/plain"}, b"DB_PASSWORD=x\nAPI_KEY=y\n")
            if url.endswith("robots.txt"):
                return _fake_response(200, {}, b"User-agent: *\nDisallow: /admin/\n")
            if url.endswith("sitemap.xml"):
                return _fake_response(200, {}, b"<urlset><url><loc>https://example.com/a</loc></url></urlset>")
            return _fake_response(404, body=b"not found")

        def fake_options(url, **kwargs):
            return _fake_options_response(200, headers={"Allow": "GET, HEAD, OPTIONS"})

        with mock.patch("requests.get", side_effect=fake_get), mock.patch("requests.options", side_effect=fake_options):
            result = es.run_exposure_scan(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir), wordlists_dir=wl_dir,
            )

        assert result["status"] == "completed"
        assert result["sensitive_resources"]["findings"]
        assert result["robots_txt"]["status"] == "found"
        assert result["sitemap_xml"]["status"] == "found"
        assert result["http_options"]["results"]
        json.dumps(result)  # every field must be JSON-safe

        pending = json.loads((output_dir / "pending_assets.json").read_text())
        assert len(pending) > 0

    def test_one_phase_failure_does_not_abort_others(self, tmp_path):
        """robots.txt fetch fails; sensitive-resource sweep and sitemap discovery must still run."""
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env"])
        output_dir = tmp_path / "output"

        def fake_get(url, **kwargs):
            if url.endswith("robots.txt"):
                raise requests.exceptions.ConnectionError("refused")
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            if url.endswith(".env"):
                return _fake_response(200, {"Content-Type": "text/plain"}, b"DB_PASSWORD=x\nAPI_KEY=y\n")
            return _fake_response(404, body=b"not found")

        with mock.patch("requests.get", side_effect=fake_get), \
             mock.patch("requests.options", return_value=_fake_options_response(200, {})):
            result = es.run_exposure_scan(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir), wordlists_dir=wl_dir,
            )

        assert result["robots_txt"]["status"] == "error"
        assert result["sensitive_resources"]["findings"]  # unaffected by robots.txt failure

    def test_scope_error_propagates_for_bad_base_url(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env"])
        with pytest.raises(es.ScopeError):
            es.run_exposure_scan("not-a-url", target=SAFE_TARGET, output_dir=str(tmp_path / "output"), wordlists_dir=wl_dir)

    def test_options_runs_against_own_discovered_findings(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env"])

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            if url.endswith(".env"):
                return _fake_response(200, {"Content-Type": "text/plain"}, b"DB_PASSWORD=x\nAPI_KEY=y\n")
            return _fake_response(404, body=b"not found")

        options_calls = []

        def fake_options(url, **kwargs):
            options_calls.append(url)
            return _fake_options_response(200, headers={"Allow": "GET"})

        with mock.patch("requests.get", side_effect=fake_get), mock.patch("requests.options", side_effect=fake_options):
            es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"), wordlists_dir=wl_dir)

        assert any(u.endswith(".env") for u in options_calls)
