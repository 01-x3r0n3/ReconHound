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
import urllib.parse
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

    def test_admin_login_page_is_not_confirmed_unrestricted_access(self):
        """A login form proves an admin surface EXISTS, not that it is reachable without
        credentials. risk_engine.py scores `confirmed_exposure` on an administrative_panel as
        HIGH "administrative panel reachable", so confirming every login page inflated
        severity for almost every admin panel on the internet."""
        resp = {"status_code": 200, "headers": {}, "body": '<form><input type="password"></form>', "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_ADMINISTRATIVE_PANEL, "admin/", resp, None)
        assert dtype == "access_restricted"
        assert conf == es.CONFIDENCE_MEDIUM
        assert any("authentication gate" in n for n in notes)

    def test_admin_panel_confirmed_when_interface_served_without_login_gate(self):
        resp = {"status_code": 200, "headers": {},
                "body": '<div id="wp-admin"><h1>Dashboard</h1><a href="/wp-admin/users.php">Users</a></div>',
                "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_ADMINISTRATIVE_PANEL, "admin/", resp, None)
        assert dtype == "confirmed_exposure"

    def test_soft_404_baseline_downgrades_to_low_confidence(self):
        baseline = {"available": True, "status_code": 200, "content_length": 5, "body_hash": es._content_signature("empty")[1]}
        resp = {"status_code": 200, "headers": {}, "body": "empty", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_CONFIGURATION_FILE, "config.json", resp, baseline)
        assert dtype == "possible_soft_404_match"
        assert conf == es.CONFIDENCE_LOW

    def test_directory_listing_detected(self):
        """An autoindex is direct evidence, so it is reported with the vocabulary downstream
        actually scores (`confirmed_exposure`) plus an explicit autoindex evidence line. The
        former private type "directory_listing_enabled" matched no risk_engine.py rule, so a
        listed /backup/ produced no risk signal at all."""
        resp = {"status_code": 200, "headers": {}, "body": "<title>Index of /backup</title>\nParent Directory",
                "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_BACKUP_FILE, "backup/", resp, None)
        assert dtype == "confirmed_exposure"
        assert conf == es.CONFIDENCE_HIGH
        assert any("directory-listing" in n or "autoindex" in n.lower() for n in notes)

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


# ===========================================================================
# Hardening regression tests.
#
# Every test below reproduces a defect that was present in the previous
# implementation of exposure_scan.py and is now fixed. Each names the
# concrete failure it prevents, because "this assertion passes" is otherwise
# indistinguishable from "this behaviour was never exercised".
# ===========================================================================


# ---------------------------------------------------------------------------
# SECURITY: scope enforcement, SSRF, credential handling
# ---------------------------------------------------------------------------

class TestScopeHardening:
    @pytest.mark.parametrize("bad", [
        "https://exam\tple.com/",
        "https://example.com/\r\npath",
        "https://example.com/\x00",
        "https://example.com/a\nb",
    ])
    def test_control_characters_rejected(self, bad):
        """urlsplit silently REMOVES \\r\\n\\t before parsing, so the host that was
        scope-checked and the host in the string handed to requests were not the same
        string."""
        with pytest.raises(es.ScopeError):
            es.validate_exposure_target(bad, target=SAFE_TARGET)

    def test_userinfo_credentials_stripped_not_persisted(self):
        """A credential in a URL must never be re-sent nor written into
        pending_assets.json, which is shared with every module and rendered verbatim in
        the report appendix (CLAUDE.md rule 16)."""
        out = es.validate_exposure_target("https://admin:hunter2@example.com/secret", target=SAFE_TARGET)
        assert "hunter2" not in out
        assert "admin" not in out
        assert out == "https://example.com/secret"

    def test_userinfo_stripping_preserves_port_and_ipv6(self):
        assert es._strip_userinfo("https://u:p@example.com:8443/x") == "https://example.com:8443/x"
        assert es._strip_userinfo("https://u:p@[2001:db8::1]:8443/x") == "https://[2001:db8::1]:8443/x"

    def test_host_at_sign_confusion_still_rejected(self):
        with pytest.raises(es.ScopeError):
            es.validate_exposure_target("https://example.com@evil.com/", target=SAFE_TARGET)

    def test_idn_and_alabel_forms_compare_equal(self):
        assert es._in_scope_host("xn--mnchen-3ya.de", "münchen.de")
        assert es._in_scope_host("münchen.de", "xn--mnchen-3ya.de")
        assert es._in_scope_host("api.xn--mnchen-3ya.de", "münchen.de")
        assert not es._in_scope_host("xn--mnchen-3ya.de", "munchen.de")

    def test_trailing_dot_host_in_scope(self):
        assert es.validate_exposure_target("https://EXAMPLE.com./x", target=SAFE_TARGET)

    @pytest.mark.parametrize("url", [
        "http://169.254.169.254/latest/meta-data/",   # cloud instance metadata
        "http://127.0.0.1:8080/admin",                # loopback
        "http://10.0.0.5/internal",                   # RFC1918
        "http://[::1]/admin",                         # IPv6 loopback
        "http://[fd00::1]/x",                         # IPv6 ULA
        "http://2130706433/",                         # decimal-encoded 127.0.0.1
        "http://0x7f000001/",                         # hex-encoded 127.0.0.1
    ])
    def test_discovered_urls_may_not_name_unrelated_hosts(self, url):
        """`endpoints` originates in crawler/endpoint_discovery output, i.e. ultimately in
        response bodies. An in-scope page must not be able to steer this module at cloud
        metadata or at internal hosts."""
        with pytest.raises(es.ScopeError):
            es.validate_discovered_url(url, SAFE_TARGET)

    def test_discovered_ip_literal_allowed_only_when_it_is_the_target(self):
        assert es.validate_discovered_url("http://93.184.216.34/x", "93.184.216.34")
        with pytest.raises(es.ScopeError):
            es.validate_discovered_url("http://93.184.216.34/x", "example.com")

    def test_operator_supplied_ip_literal_still_allowed(self):
        """validate_exposure_target keeps the project-wide rule: an operator naming an IP
        authorised it upstream."""
        assert es.validate_exposure_target("http://93.184.216.34/", target=SAFE_TARGET)

    @pytest.mark.parametrize("entry,expect_error", [
        ("https://evil.com/", True),        # absolute URL replaces the root outright
        ("//evil.com/x", False),            # protocol-relative, neutralised by lstrip
        ("../../../etc/passwd", False),     # dot segments resolved, cannot climb out
        (".git/HEAD", False),
        ("a\nb", True),
    ])
    def test_wordlist_entry_cannot_escape_the_target_origin(self, entry, expect_error):
        if expect_error:
            with pytest.raises(es.ScopeError):
                es._candidate_url("https://example.com/", entry, SAFE_TARGET)
        else:
            url = es._candidate_url("https://example.com/", entry, SAFE_TARGET)
            assert url.startswith("https://example.com/")

    def test_hostile_wordlist_entry_is_recorded_not_requested(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env"])
        # An absolute out-of-scope entry is injected through the sensitive-directory map
        # to prove the sweep refuses it rather than requesting it.
        requested = []

        def fake_get(url, **kwargs):
            requested.append(url)
            return _fake_response(404, body=b"nope")

        with mock.patch.dict(es._SENSITIVE_DIRECTORIES, {"https://evil.com/": es.CATEGORY_CREDENTIAL_MATERIAL}):
            with mock.patch("requests.get", side_effect=fake_get):
                result = es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)

        assert not any("evil.com" in u for u in requested)
        assert any(e.get("stage") == "scope" for e in result["errors"])

    def test_redirects_are_never_followed(self):
        captured = {}

        def fake_get(url, **kwargs):
            captured.update(kwargs)
            return _fake_response(302, headers={"Location": "http://169.254.169.254/"})

        with mock.patch("requests.get", side_effect=fake_get):
            es.fetch_url(SAFE_URL)
        assert captured["allow_redirects"] is False

    def test_redirect_to_out_of_scope_host_is_recorded_not_followed(self):
        resp = {"status_code": 302, "headers": {"Location": "http://169.254.169.254/latest/"},
                "body": "", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(
            es.CATEGORY_ADMINISTRATIVE_PANEL, "admin/", resp, None)
        assert dtype == "redirect"
        assert any("not followed" in n for n in notes)


# ---------------------------------------------------------------------------
# SECURITY: cloud URL construction
# ---------------------------------------------------------------------------

class TestCloudUrlSafety:
    @pytest.mark.parametrize("identifier", [
        "evil.com/", "../../x", "a@evil.com", "x?y", "x#", "x\n", "x/../y", "",
        "UPPER", "x" * 300, "-leading", "trailing-", "x y",
    ])
    def test_hostile_s3_identifier_cannot_redirect_the_request(self, identifier):
        """An unvalidated identifier turned "https://{id}.s3.amazonaws.com/" into a request
        against an entirely different host ("evil.com/" -> https://evil.com/.s3.amazonaws.com/)."""
        url = es.build_cloud_url("s3", identifier)
        if url is not None:
            host = urllib.parse.urlsplit(url).hostname or ""
            assert host.endswith(".s3.amazonaws.com")

    @pytest.mark.parametrize("identifier", ["evil.com/..", "..", "%2e%2e", "a/b", "x?y"])
    def test_hostile_gcs_identifier_rejected_or_contained(self, identifier):
        url = es.build_cloud_url("gcs", identifier)
        if url is not None:
            parsed = urllib.parse.urlsplit(url)
            assert parsed.hostname == "storage.googleapis.com"
            assert ".." not in parsed.path

    def test_azure_container_cannot_inject_query_parameters(self):
        url = es.build_cloud_url("azure", "acct", container="c?restype=account&comp=list")
        assert url is None
        good = es.build_cloud_url("azure", "acct", container="mycontainer")
        assert good == ("https://acct.blob.core.windows.net/mycontainer"
                        "?restype=container&comp=list")

    def test_valid_names_still_build(self):
        assert es.build_cloud_url("s3", "my-bucket.name") == "https://my-bucket.name.s3.amazonaws.com/"
        assert es.build_cloud_url("gcs", "my_bucket-1") == "https://storage.googleapis.com/my_bucket-1/"

    def test_check_cloud_resource_refuses_invalid_identifier_without_requesting(self):
        with mock.patch("requests.get") as mocked:
            result = es.check_cloud_resource("s3", "evil.com/")
        mocked.assert_not_called()
        assert result["status"] == "error"

    @pytest.mark.parametrize("item,provider,identifier", [
        ("https://mybucket.s3.amazonaws.com/", "s3", "mybucket"),
        ("https://mybucket.s3.us-east-1.amazonaws.com/", "s3", "mybucket"),
        ("https://mybucket.s3-eu-west-1.amazonaws.com/", "s3", "mybucket"),
        ("https://s3.amazonaws.com/mybucket/", "s3", "mybucket"),
        ("https://s3.us-west-2.amazonaws.com/mybucket", "s3", "mybucket"),
        ("https://storage.googleapis.com/mybucket/", "gcs", "mybucket"),
        ("https://mybucket.storage.googleapis.com/", "gcs", "mybucket"),
    ])
    def test_provider_url_forms_recognised(self, item, provider, identifier):
        parsed = es._parse_cloud_target(item)
        assert (parsed["provider"], parsed["identifier"]) == (provider, identifier)

    def test_azure_url_form_recognised(self):
        parsed = es._parse_cloud_target("https://acct.blob.core.windows.net/container/blob.txt")
        assert parsed == {"provider": "azure", "identifier": "acct", "container": "container"}

    @pytest.mark.parametrize("item", [
        "https://evil.com/", "not-a-url", "", None, 123, {"provider": "s3"},
        "https://acct.blob.core.windows.net/", "ftp://mybucket.s3.amazonaws.com/",
    ])
    def test_unparseable_cloud_target_raises_rather_than_being_dropped(self, item):
        with pytest.raises(es.CloudTargetError):
            es._parse_cloud_target(item)

    def test_unparseable_cloud_target_is_reported_as_an_error(self):
        """A cloud target the operator authorised and this module silently ignored is a
        coverage hole the operator cannot see."""
        with mock.patch("requests.get") as mocked:
            result = es.discover_cloud_exposure(SAFE_TARGET, cloud_targets=["https://evil.com/"])
        mocked.assert_not_called()
        assert any(e["stage"] == "cloud_target_parse" for e in result["errors"])

    def test_duplicate_authorized_targets_probed_once(self):
        with mock.patch("requests.get", return_value=_fake_response(404, {}, b"<Code>NoSuchBucket</Code>")) as mocked:
            es.discover_cloud_exposure(SAFE_TARGET, cloud_targets=[
                "https://mybucket.s3.amazonaws.com/", {"provider": "s3", "identifier": "mybucket"},
                "https://s3.amazonaws.com/mybucket/", "https://mybucket.s3.eu-west-1.amazonaws.com/",
            ])
        assert mocked.call_count == 1


# ---------------------------------------------------------------------------
# CLOUD: provider response semantics
# ---------------------------------------------------------------------------

class TestCloudResponseSemantics:
    def test_all_access_disabled_is_exists_restricted_not_unknown(self):
        dtype, conf, notes = es.classify_cloud_response(403, "<Error><Code>AllAccessDisabled</Code></Error>")
        assert dtype == es.CDT_EXISTS_RESTRICTED
        assert conf == es.CONFIDENCE_MEDIUM

    def test_permanent_redirect_is_region_not_absence(self):
        """A bucket in another region exists. Redirects are never followed, so listability
        was not tested — calling it "not found" is a false negative and calling it an
        exposure is a false positive."""
        dtype, conf, notes = es.classify_cloud_response(301, "<Error><Code>PermanentRedirect</Code></Error>")
        assert dtype == es.CDT_REGION_REDIRECT
        assert any("not tested" in n for n in notes)

    def test_provider_throttling_is_not_absence(self):
        for body, status in [("<Code>SlowDown</Code>", 503), ("", 429), ("", 500)]:
            dtype, conf, notes = es.classify_cloud_response(status, body)
            assert dtype == es.CDT_PROVIDER_REFUSED
            assert dtype != es.CDT_NOT_FOUND

    def test_gcs_json_permission_error_recognised(self):
        body = '{"error": {"code": 403, "message": "does not have storage.objects.list access"}}'
        dtype, conf, notes = es.classify_cloud_response(403, body)
        assert dtype == es.CDT_EXISTS_RESTRICTED

    def test_azure_public_access_not_permitted(self):
        dtype, conf, notes = es.classify_cloud_response(
            404, "<Error><Code>PublicAccessNotPermitted</Code></Error>")
        assert dtype == es.CDT_EXISTS_RESTRICTED

    def test_no_such_bucket_never_claims_takeover(self):
        dtype, conf, notes = es.classify_cloud_response(404, "<Error><Code>NoSuchBucket</Code></Error>")
        assert dtype == es.CDT_NOT_FOUND
        joined = " ".join(notes).lower()
        assert "takeover" in joined and "not" in joined
        assert "claimable" not in joined

    def test_listing_element_inside_an_error_body_is_not_a_listing(self):
        """A 4xx body can quote the element name back inside an error message; only a
        success status with a listing document is a listing."""
        dtype, conf, notes = es.classify_cloud_response(
            403, "<Error><Message>ListBucketResult not permitted: <ListBucketResult></Message></Error>")
        assert dtype != es.CDT_LISTABLE

    def test_empty_public_listing_is_still_listable(self):
        dtype, conf, notes = es.classify_cloud_response(200, "<ListBucketResult></ListBucketResult>")
        assert dtype == es.CDT_LISTABLE
        assert any("empty" in n for n in notes)

    def test_ownership_attribution_recorded_as_operator_asserted(self):
        """Shared provider infrastructure: a responding bucket is not evidence the target
        owns it."""
        with mock.patch("requests.get", return_value=_fake_response(200, {}, b"<ListBucketResult/>")):
            result = es.check_cloud_resource("s3", "somebucket")
        assert result["ownership_attribution"] == "operator_asserted_scope"

    def test_candidate_generation_is_deterministic(self):
        """The base names were iterated out of a set, so two identical runs produced the
        same candidates in a different order (and a different persisted record)."""
        runs = [es.generate_cloud_candidates("example.com") for _ in range(5)]
        assert all(r == runs[0] for r in runs)

    @pytest.mark.parametrize("target", [None, "", 123, "...", "-", "münchen.de"])
    def test_candidate_generation_survives_odd_targets(self, target):
        assert isinstance(es.generate_cloud_candidates(target), list)


# ---------------------------------------------------------------------------
# FALSE POSITIVES: "confirmed" requires direct content evidence
# ---------------------------------------------------------------------------

class TestConfirmationStrength:
    def test_json_error_envelope_is_not_a_config_file(self):
        """`{"error": "not found"}` served at /config.json parsed as JSON and was confirmed
        — which risk_engine.py scores CRITICAL as "exposed creds"/HIGH "major misconfig"."""
        resp = {"status_code": 200, "headers": {"Content-Type": "application/json"},
                "body": '{"error": "not found"}', "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_CONFIGURATION_FILE, "config.json", resp, None)
        assert dtype == "interesting_unconfirmed"

    def test_real_json_config_still_confirmed(self):
        resp = {"status_code": 200, "headers": {"Content-Type": "application/json"},
                "body": '{"database": {"host": "db"}, "debug": true, "secret_key": "x"}', "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_CONFIGURATION_FILE, "config.json", resp, None)
        assert dtype == "confirmed_exposure"

    def test_prose_with_one_colon_is_not_a_config_file(self):
        resp = {"status_code": 200, "headers": {"Content-Type": "text/plain"},
                "body": "Error: page not found\nplease retry", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_CONFIGURATION_FILE, "config.yml", resp, None)
        assert dtype == "interesting_unconfirmed"

    def test_real_yaml_config_still_confirmed(self):
        body = "database:\n  host: db.internal\nport: 5432\ndebug: true\ncache_driver: redis\n"
        resp = {"status_code": 200, "headers": {"Content-Type": "text/plain"}, "body": body, "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_CONFIGURATION_FILE, "config.yml", resp, None)
        assert dtype == "confirmed_exposure"

    def test_archive_content_type_alone_is_not_confirmation(self):
        """A Content-Type header is a claim ABOUT the body; an octet-stream error page was
        confirmed as an exposed archive."""
        resp = {"status_code": 200, "headers": {"Content-Type": "application/octet-stream"},
                "body": "<html>404</html>", "raw_prefix": b"<htm"}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_ARCHIVE_FILE, "backup.zip", resp, None)
        assert dtype == "interesting_unconfirmed"
        assert any("does not begin with any known archive signature" in n for n in notes)

    def test_archive_magic_bytes_still_confirmed(self):
        resp = {"status_code": 200, "headers": {"Content-Type": "application/octet-stream"},
                "body": "binary", "raw_prefix": b"PK\x03\x04"}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_ARCHIVE_FILE, "backup.zip", resp, None)
        assert dtype == "confirmed_exposure"

    def test_page_merely_mentioning_index_of_is_not_a_directory_listing(self):
        resp = {"status_code": 200, "headers": {"Content-Type": "text/html"},
                "body": "<p>Our server does not allow Index of / pages, and Parent Directory browsing is off.</p>",
                "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_BACKUP_FILE, "backup/", resp, None)
        assert dtype != "confirmed_exposure"

    @pytest.mark.parametrize("body", [
        "<html><head><title>Index of /backup</title></head><body></body></html>",
        '<h1>Index of /files</h1><a href="../">Parent Directory</a>',
        "<title>Directory listing for /uploads</title>",
        '<a href="..">[To Parent Directory]</a>',
    ])
    def test_real_directory_listings_still_detected(self, body):
        assert es.detect_directory_listing(body)

    def test_empty_2xx_body_flagged_as_no_evidence(self):
        resp = {"status_code": 204, "headers": {}, "body": "", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_CONFIGURATION_FILE, "config.json", resp, None)
        assert dtype == "interesting_unconfirmed"
        assert any("empty" in n for n in notes)

    def test_missing_baseline_is_stated_in_the_evidence(self):
        resp = {"status_code": 200, "headers": {"Content-Type": "text/html"},
                "body": "<html>hello</html>", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_CONFIGURATION_FILE, "config.json", resp, None)
        assert any("baseline" in n for n in notes)

    def test_binary_body_not_parsed_as_text_config(self):
        resp = {"status_code": 200, "headers": {"Content-Type": "image/png"},
                "body": "a: 1\nb: 2\nc: 3\n", "raw_prefix": b"\x89PNG"}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_CONFIGURATION_FILE, "config.yml", resp, None)
        assert dtype != "confirmed_exposure"


# ---------------------------------------------------------------------------
# FALSE NEGATIVES: the baseline must not veto real evidence
# ---------------------------------------------------------------------------

class TestSoft404Comparison:
    def test_length_proximity_alone_no_longer_suppresses_a_real_finding(self):
        """A genuine .env of 53 normalised characters against a 60-character catch-all was
        reported as `possible_soft_404_match` at LOW confidence and never confirmed."""
        baseline = {"available": True, "usable": True, "status_code": 200,
                    "content_length": 60, "body_hash": "notthesame"}
        body = "DB_PASSWORD=supersecret123\nAPI_KEY=abcdefghijklmn\nX=1\n"
        resp = {"status_code": 200, "headers": {"Content-Type": "text/plain"}, "body": body, "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_ENVIRONMENT_FILE, ".env", resp, baseline)
        assert dtype == "confirmed_exposure"
        assert any("close to this host's not-found baseline" in n for n in notes)

    def test_identical_body_is_still_suppressed(self):
        body = "<html>catch all</html>"
        baseline = {"available": True, "usable": True, "status_code": 200,
                    "content_length": es._content_signature(body)[0],
                    "body_hash": es._content_signature(body)[1]}
        resp = {"status_code": 200, "headers": {}, "body": body, "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_CONFIGURATION_FILE, "config.json", resp, baseline)
        assert dtype == "possible_soft_404_match"

    def test_suppressed_signature_match_is_still_reported_in_the_evidence(self):
        """Conflicting evidence is preserved, not silently dropped (context.md §8)."""
        body = "DB_PASSWORD=x\nAPI_KEY=y\n"
        sig = es._content_signature(body)
        baseline = {"available": True, "usable": True, "status_code": 200,
                    "content_length": sig[0], "body_hash": sig[1]}
        resp = {"status_code": 200, "headers": {"Content-Type": "text/plain"}, "body": body, "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_ENVIRONMENT_FILE, ".env", resp, baseline)
        assert dtype == "possible_soft_404_match"
        assert any("suppressed signature match" in n for n in notes)

    def test_dynamic_catch_all_matched_structurally(self):
        """A catch-all that echoes the requested path and a request id differs byte-wise on
        every request; comparing against one dynamic sample is meaningless."""
        def page(path, rid):
            return f"<html><body>Not found: {path} (request 550e8400-e29b-41d4-a716-{rid})</body></html>"

        calls = {"n": 0}

        def fake_get(url, **kwargs):
            calls["n"] += 1
            path = urllib.parse.urlsplit(url).path
            return _fake_response(200, {"Content-Type": "text/html"},
                                  page(path, f"{calls['n']:012d}").encode())

        with mock.patch("requests.get", side_effect=fake_get):
            baseline = es._probe_soft_404("https://example.com", 5.0)
        assert baseline["available"] and baseline["dynamic"] and baseline["usable"]

        resp = {"status_code": 200, "headers": {"Content-Type": "text/html"},
                "body": page("/config.json", "000000000099"), "raw_prefix": b""}
        assert es._matches_soft_404(resp, baseline, "https://example.com/config.json")

    def test_unusable_baseline_never_suppresses(self):
        for baseline in ({"available": False}, {"available": True, "usable": False, "status_code": 200},
                         None, {}):
            resp = {"status_code": 200, "headers": {}, "body": "x", "raw_prefix": b""}
            assert es._matches_soft_404(resp, baseline, "https://example.com/x") is False

    def test_baseline_probes_with_differing_statuses_are_unusable(self):
        seq = [_fake_response(200, {}, b"a"), _fake_response(404, {}, b"b")]

        def fake_get(url, **kwargs):
            return seq.pop(0)

        with mock.patch("requests.get", side_effect=fake_get):
            baseline = es._probe_soft_404("https://example.com", 5.0)
        assert baseline["available"] is False
        assert "differing status" in baseline["reason"]

    def test_failed_baseline_is_unavailable_not_a_clean_404(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            baseline = es._probe_soft_404("https://example.com", 5.0)
        assert baseline == {"available": False, "reason": "no baseline probe completed"}


# ---------------------------------------------------------------------------
# SECRETS: nothing usable reaches pending_assets.json
# ---------------------------------------------------------------------------

class TestSecretRedaction:
    def test_env_secrets_masked_but_key_names_preserved(self):
        body = ("DB_PASSWORD=Sup3rS3cretValue\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                "APP_ENV=production\n")
        out = es._redacted_excerpt(body)
        assert "Sup3rS3cretValue" not in out
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in out
        assert "DB_PASSWORD" in out and "AWS_SECRET_ACCESS_KEY" in out

    def test_htpasswd_hash_masked(self):
        out = es._redacted_excerpt("admin:$apr1$abcdefgh$1234567890abcdefghijklm")
        assert "1234567890abcdefghijklm" not in out
        assert "admin" in out

    def test_connection_string_password_masked(self):
        out = es._redacted_excerpt("DATABASE_URL=postgres://admin:hunter2pass@db.internal:5432/app")
        assert "hunter2pass" not in out

    def test_confirmed_env_finding_persists_no_raw_secret(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env"])
        output_dir = tmp_path / "output"
        secret = "Sup3rS3cretValue123"

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            if url.endswith(".env"):
                return _fake_response(200, {"Content-Type": "text/plain"},
                                      f"DB_PASSWORD={secret}\nAPI_KEY=abcdef123456\n".encode())
            return _fake_response(404, body=b"not found")

        with mock.patch("requests.get", side_effect=fake_get), \
             mock.patch("requests.options", return_value=_fake_options_response(200, {})):
            es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir),
                                 wordlists_dir=wl_dir)

        raw = (output_dir / "pending_assets.json").read_text()
        assert secret not in raw
        assert "DB_PASSWORD" in raw          # the finding is still useful
        assert "confirmed_exposure" in raw   # and still confirmed

    def test_debug_page_evidence_is_redacted(self):
        body = ("Werkzeug Debugger — Werkzeug/2.3.7 "
                "SECRET_KEY=aVeryLongSecretValueHere1234567890")
        result = es.analyze_error_page(body, {}, 500)
        joined = " ".join(i["evidence"] for i in result["indicators"])
        assert "aVeryLongSecretValueHere1234567890" not in joined

    def test_redaction_survives_odd_input(self):
        for value in (None, "", "a", "=" * 100, "\x00\x01", "é" * 50):
            es.redact_sensitive_text(value)


# ---------------------------------------------------------------------------
# FAILURE SEMANTICS: a refusal is never absence
# ---------------------------------------------------------------------------

class TestFailureSemantics:
    @pytest.mark.parametrize("status,expected", [
        (404, "not_found"), (410, "not_found"),
        (401, "access_restricted"), (403, "access_restricted"),
        (429, "rate_limited"), (405, "method_not_allowed"),
        (500, "server_error_response"), (502, "server_error_response"),
        (503, "server_error_response"), (504, "server_error_response"),
        (301, "redirect"), (302, "redirect"), (303, "redirect"),
        (307, "redirect"), (308, "redirect"),
        (418, "unexpected_status"), (100, "unexpected_status"),
    ])
    def test_status_code_matrix(self, status, expected):
        resp = {"status_code": status, "headers": {}, "body": "x", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_CONFIGURATION_FILE, "config.json", resp, None)
        assert dtype == expected

    @pytest.mark.parametrize("status", [429, 500, 503])
    def test_refusals_are_marked_inconclusive_not_absent(self, status):
        resp = {"status_code": status, "headers": {}, "body": "", "raw_prefix": b""}
        dtype, conf, notes, excerpt = es.evaluate_exposure(es.CATEGORY_ENVIRONMENT_FILE, ".env", resp, None)
        assert dtype in es._INCONCLUSIVE_TYPES
        assert dtype != "not_found"

    @pytest.mark.parametrize("status,expected", [
        (404, "not_found"), (403, "access_restricted"), (429, "rate_limited"),
        (500, "server_error"), (302, "redirect"), (418, "inconclusive"),
    ])
    def test_robots_non_200_semantics(self, status, expected):
        """Every non-200 was reported as `not_found`, turning a 403/429/502 — none of which
        say anything about whether robots.txt exists — into confirmed absence."""
        with mock.patch("requests.get", return_value=_fake_response(status, {}, b"x")):
            result = es.discover_robots_txt(SAFE_URL, target=SAFE_TARGET)
        assert result["status"] == expected

    @pytest.mark.parametrize("status,expected", [
        (404, "not_found"), (403, "access_restricted"), (503, "server_error"),
    ])
    def test_sitemap_non_200_semantics(self, status, expected):
        with mock.patch("requests.get", return_value=_fake_response(status, {}, b"x")):
            result = es.discover_sitemap_xml(SAFE_URL, target=SAFE_TARGET)
        assert result["status"] == expected

    def test_network_failure_does_not_become_a_negative_result(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env", "backup.sql"])
        output_dir = tmp_path / "output"

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            raise requests.exceptions.Timeout("timed out")

        with mock.patch("requests.get", side_effect=fake_get), \
             mock.patch("requests.options", return_value=_fake_options_response(200, {})):
            result = es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir),
                                          wordlists_dir=wl_dir)

        assert result["sensitive_resources"]["sweep_conclusive"] is False
        assert result["scan_complete"] is False
        records = json.loads((output_dir / "pending_assets.json").read_text())
        assert not any(r["type"] == "exposure_scan_checked_no_exposure" for r in records)

    def test_conclusive_empty_sweep_emits_negative_result(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env", "backup.sql"])
        output_dir = tmp_path / "output"

        with mock.patch("requests.get", side_effect=_all_404), \
             mock.patch("requests.options", return_value=_fake_options_response(200, {})):
            result = es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir),
                                          wordlists_dir=wl_dir)

        assert result["sensitive_resources"]["sweep_conclusive"] is True
        records = json.loads((output_dir / "pending_assets.json").read_text())
        assert any(r["type"] == "exposure_scan_checked_no_exposure" for r in records)

    def test_budget_exhaustion_blocks_the_negative_result(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt",
                                 [".env", "backup.sql", "config.php", "admin/", "debug/"])
        output_dir = tmp_path / "output"
        with mock.patch("requests.get", side_effect=_all_404), \
             mock.patch("requests.options", return_value=_fake_options_response(200, {})):
            result = es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir),
                                          wordlists_dir=wl_dir, max_requests=3)
        assert result["request_budget_exhausted"] is True
        assert result["scan_complete"] is False
        records = json.loads((output_dir / "pending_assets.json").read_text())
        assert not any(r["type"] == "exposure_scan_checked_no_exposure" for r in records)

    def test_all_phases_report_their_errors_at_the_top_level(self, tmp_path):
        """A run whose cloud checks had all failed still reported status "completed"."""
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env"])
        with mock.patch("requests.get", side_effect=_all_404), \
             mock.patch("requests.options", return_value=_fake_options_response(200, {})):
            result = es.run_exposure_scan(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                wordlists_dir=wl_dir, cloud_targets=["https://evil.com/"],
            )
        assert result["status"] == "completed_with_errors"
        assert any(e.get("stage") == "cloud_target_parse" for e in result["errors"])


# ---------------------------------------------------------------------------
# RESOURCE SAFETY
# ---------------------------------------------------------------------------

class TestResourceSafety:
    def test_hostile_body_does_not_cause_regex_blowup(self):
        """An unbounded `Fatal error:.*?on line \\d+` rescanned to the end of the body from
        every "Fatal error:" occurrence: ~4s of CPU per hostile 128 KB response, per worker,
        per candidate."""
        import time
        for body in [("Fatal error: " + "a" * 20) * 5000,
                     ("at foo (" + "b" * 20) * 5000,
                     ("Whoops looks like " + "c" * 30) * 4000]:
            started = time.time()
            es.analyze_error_page(body[:es.DEFAULT_MAX_BODY_BYTES], {}, 500)
            assert time.time() - started < 1.0

    def test_internal_path_extraction_is_bounded(self):
        body = " ".join(f"/var/www/app{i}.php" for i in range(5000))
        result = es.analyze_error_page(body, {}, 500)
        assert len(result["internal_paths"]) <= es._MAX_INTERNAL_PATHS
        assert all(len(p) <= es._MAX_INTERNAL_PATH_CHARS for p in result["internal_paths"])

    def test_huge_header_values_are_truncated_in_evidence(self):
        result = es.analyze_error_page("", {"Server": "nginx/1.1 " + "x" * 100000,
                                            "X-Powered-By": "y" * 100000}, 200)
        assert all(len(i["evidence"]) < 1000 for i in result["indicators"])

    def test_body_read_is_bounded_when_raw_is_unavailable(self):
        """`resp.content` materialised the entire body before the slice ran, so a
        decompression bomb was fully resident in memory per worker."""
        resp = mock.MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/plain"}
        resp.encoding = "utf-8"
        resp.url = SAFE_URL
        resp.elapsed.total_seconds.return_value = 0.01
        resp.raw.read.side_effect = Exception("no raw")
        resp.iter_content.side_effect = lambda chunk_size=8192: (b"A" * chunk_size for _ in range(10000))
        content_accessed = []
        type(resp).content = property(lambda self: content_accessed.append(1) or b"B" * 50_000_000)

        with mock.patch("requests.get", return_value=resp):
            result = es.fetch_url(SAFE_URL, max_body_bytes=1024)
        assert len(result["body"]) <= 1024
        assert result["body_truncated"] is True
        assert not content_accessed

    def test_oversized_declared_body_is_refused_on_the_last_resort_path(self):
        resp = mock.MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Length": str(500 * 1024 * 1024)}
        resp.encoding = "utf-8"
        resp.url = SAFE_URL
        resp.elapsed.total_seconds.return_value = 0.01
        resp.raw.read.side_effect = Exception("no raw")
        resp.iter_content.side_effect = Exception("no iter")
        content_accessed = []
        type(resp).content = property(lambda self: content_accessed.append(1) or b"B" * 100)

        with mock.patch("requests.get", return_value=resp):
            result = es.fetch_url(SAFE_URL, max_body_bytes=1024)
        assert not content_accessed
        assert result["body_read_error"]

    def test_error_log_is_bounded(self, tmp_path):
        state = es._ScanState(SAFE_TARGET, None, 10000)
        for i in range(es.MAX_RECORDED_ERRORS + 500):
            state.record_error("fetch", f"https://example.com/{i}", "connection error")
        records = state.error_records()
        assert len(records) == es.MAX_RECORDED_ERRORS + 1
        assert "suppressed" in records[-1]["error"]

    def test_options_url_count_is_capped(self):
        urls = [f"https://example.com/p{i}" for i in range(500)]
        with mock.patch("requests.options", return_value=_fake_options_response(200, {"Allow": "GET"})) as mocked:
            result = es.discover_http_options(urls, target=SAFE_TARGET, max_urls=25)
        assert mocked.call_count == 25
        assert result["urls_skipped_over_limit"] == 475

    def test_one_budget_covers_every_phase(self, tmp_path):
        """`max_requests` governed only the sweep: baseline probes, robots, sitemap and one
        OPTIONS request per finding were all made outside it."""
        wl_dir = _write_wordlist(tmp_path, "directories.txt",
                                 [".env", "backup.sql", "config.php", "admin/", "debug/", "error.log"])
        gets, options = [], []

        def fake_get(url, **kwargs):
            gets.append(url)
            return _fake_response(200, {"Content-Type": "text/plain"}, b"DB_PASSWORD=x\nAPI_KEY=y\n")

        def fake_options(url, **kwargs):
            options.append(url)
            return _fake_options_response(200, {"Allow": "GET"})

        with mock.patch("requests.get", side_effect=fake_get), \
             mock.patch("requests.options", side_effect=fake_options):
            result = es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                                          wordlists_dir=wl_dir, max_requests=6)
        assert len(gets) + len(options) <= 6
        assert result["requests_made"] <= 6

    def test_persistence_is_not_quadratic(self, tmp_path):
        import time
        store = es.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        finding = es.make_finding("exposure_finding", SAFE_TARGET, {"url": "https://example.com/x" * 10},
                                  ["e" * 100], es.CONFIDENCE_HIGH)
        started = time.time()
        for _ in range(400):
            store.add(dict(finding))
        assert time.time() - started < 3.0
        assert len(store.all()) == 400

    def test_huge_sitemap_is_bounded(self):
        body = ("<urlset>" + "".join(f"<loc>https://example.com/{i}</loc>" for i in range(5000))
                + "</urlset>").encode()
        with mock.patch("requests.get", return_value=_fake_response(200, {}, body)):
            result = es.discover_sitemap_xml(SAFE_URL, target=SAFE_TARGET)
        assert result["url_count"] <= es.MAX_SITEMAP_URLS
        assert result["urls_truncated"] is True

    def test_sitemap_scope_is_recorded_not_followed(self):
        body = (b"<urlset><loc>https://example.com/a</loc>"
                b"<loc>https://evil.com/b</loc></urlset>")
        with mock.patch("requests.get", return_value=_fake_response(200, {}, body)) as mocked:
            result = es.discover_sitemap_xml(SAFE_URL, target=SAFE_TARGET)
        assert result["in_scope_url_count"] == 1
        assert result["out_of_scope_url_count"] == 1
        assert mocked.call_count == 1  # only sitemap.xml itself was requested


# ---------------------------------------------------------------------------
# DETERMINISM, DEDUPLICATION, PROVENANCE
# ---------------------------------------------------------------------------

class TestDeterminismAndProvenance:
    def test_sweep_output_order_is_stable(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt",
                                 [".env", "backup.sql", "config.php", "error.log", "admin/"])

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            return _fake_response(200, {"Content-Type": "text/plain"}, b"generic")

        orders = []
        for _ in range(4):
            with mock.patch("requests.get", side_effect=fake_get):
                result = es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)
            orders.append([f["url"] for f in result["findings"]])
        assert all(o == orders[0] for o in orders)

    def test_duplicate_wordlist_entries_probed_once(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env", "/.env", "./.env", ".ssh/"])
        requested = []

        def fake_get(url, **kwargs):
            requested.append(url)
            return _fake_response(404, body=b"not found")

        with mock.patch("requests.get", side_effect=fake_get):
            result = es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)
        env_requests = [u for u in requested if u.endswith(".env")]
        assert len(env_requests) == 1
        # ".ssh/" appears both in the wordlist and in _SENSITIVE_DIRECTORIES.
        assert len([u for u in requested if u.endswith(".ssh/")]) == 1
        assert result["candidates_checked"] == len({u for u in requested if "reconhound-exposure-check" not in u})

    def test_finding_carries_full_provenance(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env"])

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            return _fake_response(200, {"Content-Type": "text/plain"}, b"DB_PASSWORD=x\nAPI_KEY=y\n")

        with mock.patch("requests.get", side_effect=fake_get):
            result = es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)
        record = result["findings"][0]
        for field in ("url", "path", "method", "status_code", "content_type", "exposure_category",
                      "discovery_type", "confidence", "evidence", "timestamp", "wordlist_entry",
                      "discovery_method", "baseline_available", "content_complete",
                      "existence_uncertain", "excerpt_redacted", "body_truncated"):
            assert field in record, field
        assert record["method"] == "GET"
        assert record["discovery_method"] == "exposure_category_wordlist_sweep"

    def test_options_records_who_answered(self):
        resp = _fake_options_response(200, headers={"Allow": "GET, PUT", "Server": "cloudflare",
                                                    "CF-Ray": "abc123"})
        with mock.patch("requests.options", return_value=resp):
            result = es.probe_options(SAFE_URL, target=SAFE_TARGET)
        assert result["response_provenance_headers"]["Server"] == "cloudflare"
        assert any("provenance" in e for e in result["evidence"])
        assert "not proof" in result["note"]

    def test_options_methods_deduplicated_and_sorted(self):
        resp = _fake_options_response(200, headers={"Allow": "post, GET,  get , POST, OPTIONS"})
        with mock.patch("requests.options", return_value=resp):
            result = es.probe_options(SAFE_URL, target=SAFE_TARGET)
        assert result["advertised_methods"] == ["GET", "OPTIONS", "POST"]

    def test_options_not_probed_for_soft404_or_absent_paths(self, tmp_path):
        """OPTIONS follow-ups on catch-all responses are pure request amplification."""
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env", "backup.sql", "config.php"])
        catchall = b"<html><body>SPA</body></html>"
        options_calls = []

        with mock.patch("requests.get", return_value=_fake_response(200, {"Content-Type": "text/html"}, catchall)), \
             mock.patch("requests.options",
                        side_effect=lambda url, **kw: options_calls.append(url) or _fake_options_response(200, {})):
            es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                                 wordlists_dir=wl_dir)
        assert options_calls == []

    def test_out_of_scope_caller_endpoint_rejected_from_options(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env"])
        options_calls = []

        with mock.patch("requests.get", side_effect=_all_404), \
             mock.patch("requests.options",
                        side_effect=lambda url, **kw: options_calls.append(url) or _fake_options_response(200, {})):
            result = es.run_exposure_scan(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"), wordlists_dir=wl_dir,
                endpoints=["https://example.com/ok", "http://169.254.169.254/latest/",
                           "https://evil.com/x", "http://10.0.0.1/"],
            )
        assert options_calls == ["https://example.com/ok"]
        assert result["http_options"]["urls_rejected_out_of_scope"] == 3


# ---------------------------------------------------------------------------
# FUZZ / ADVERSARIAL INPUT
# ---------------------------------------------------------------------------

_FUZZ_STRINGS = [
    "", " ", "\x00", "\r\n", "\t", "a" * 100000, "é" * 1000, "🙂" * 500,
    "<html>" * 5000, "{" * 5000, "%" * 5000, "%%%%zz", "../" * 2000,
    "\udcff", "NaN", "null", "<?xml", "-" * 5000, "\\" * 5000,
]
_FUZZ_VALUES = _FUZZ_STRINGS + [None, 0, 1, -1, 1.5, float("nan"), True, [], {}, set(), object()]


class TestFuzz:
    @pytest.mark.parametrize("value", _FUZZ_VALUES)
    def test_classify_exposure_category_survives(self, value):
        try:
            es.classify_exposure_category(value)
        except (TypeError, AttributeError):
            pass  # non-string input is the caller's contract violation, not a crash-in-parsing

    @pytest.mark.parametrize("value", _FUZZ_STRINGS)
    def test_string_helpers_survive(self, value):
        es.detect_directory_listing(value)
        es.analyze_error_page(value, {"Server": value}, 500)
        es.redact_sensitive_text(value)
        es._excerpt(value)
        es._redacted_excerpt(value)
        es._content_signature(value)
        es._structural_signature(value, "https://example.com/x")

    @pytest.mark.parametrize("value", _FUZZ_STRINGS)
    def test_evaluate_exposure_survives_hostile_bodies(self, value):
        for category in (es.CATEGORY_VERSION_CONTROL, es.CATEGORY_ENVIRONMENT_FILE,
                         es.CATEGORY_CONFIGURATION_FILE, es.CATEGORY_DATABASE_DUMP,
                         es.CATEGORY_ARCHIVE_FILE, es.CATEGORY_BACKUP_FILE,
                         es.CATEGORY_CREDENTIAL_MATERIAL, es.CATEGORY_LOG_FILE,
                         es.CATEGORY_DEBUG_ENDPOINT, es.CATEGORY_ADMINISTRATIVE_PANEL):
            resp = {"status_code": 200, "headers": {"Content-Type": value[:100]},
                    "body": value, "raw_prefix": value[:16].encode("utf-8", "replace")}
            dtype, conf, notes, excerpt = es.evaluate_exposure(category, "x", resp, None)
            assert conf in (es.CONFIDENCE_LOW, es.CONFIDENCE_MEDIUM, es.CONFIDENCE_HIGH)
            json.dumps({"d": dtype, "n": notes, "e": excerpt})

    @pytest.mark.parametrize("value", _FUZZ_VALUES)
    def test_validate_target_never_raises_anything_but_scope_error(self, value):
        try:
            es.validate_exposure_target(value, target=SAFE_TARGET)
        except es.ScopeError:
            pass

    @pytest.mark.parametrize("value", _FUZZ_VALUES)
    def test_cloud_target_parsing_never_raises_anything_but_cloud_target_error(self, value):
        try:
            es._parse_cloud_target(value)
        except es.CloudTargetError:
            pass

    @pytest.mark.parametrize("value", _FUZZ_STRINGS)
    def test_cloud_classification_survives(self, value):
        for status in (None, 200, 301, 403, 404, 429, 500):
            dtype, conf, notes = es.classify_cloud_response(status, value)
            assert isinstance(dtype, str) and conf in ("LOW", "MEDIUM", "HIGH")

    @pytest.mark.parametrize("body", [
        b"", b"\x00\x01\x02", b"<urlset>", b"<urlset><loc></loc></urlset>",
        b"<urlset><loc>" + b"a" * 100000 + b"</loc></urlset>",
        "<urlset><loc>https://exámple.com/é</loc></urlset>".encode(),
        b"<?xml version='1.0'?><!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><urlset>&e;</urlset>",
    ])
    def test_sitemap_parser_survives_hostile_xml(self, body):
        with mock.patch("requests.get", return_value=_fake_response(200, {}, body)):
            result = es.discover_sitemap_xml(SAFE_URL, target=SAFE_TARGET)
        json.dumps(result)

    def test_sitemap_parser_does_not_resolve_external_entities(self):
        """The <loc> extraction is a regex over text, never an XML parser, so no entity is
        ever expanded and no file/URL is fetched from a hostile sitemap."""
        body = (b"<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
                b"<urlset><url><loc>&xxe;</loc></url></urlset>")
        with mock.patch("requests.get", return_value=_fake_response(200, {}, body)) as mocked:
            result = es.discover_sitemap_xml(SAFE_URL, target=SAFE_TARGET)
        assert mocked.call_count == 1
        assert "root:" not in json.dumps(result)

    @pytest.mark.parametrize("body", [
        b"", b"#" * 100000, b"Disallow: " + b"a" * 100000,
        b"Sitemap: javascript:alert(1)", b"\x00\xff",
        "Disallow: /é\n".encode(),
    ])
    def test_robots_parser_survives_hostile_input(self, body):
        with mock.patch("requests.get", return_value=_fake_response(200, {}, body)):
            result = es.discover_robots_txt(SAFE_URL, target=SAFE_TARGET)
        json.dumps(result)

    def test_non_serializable_caller_input_does_not_abort_the_phase(self, tmp_path):
        """A caller-supplied payload json.dump cannot write used to raise TypeError outside
        the persistence guard and abort the whole cloud phase."""
        store = es.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        finding = es.make_finding("exposure_finding", SAFE_TARGET,
                                  {"obj": object(), "s": {1, 2}, "f": float("inf")},
                                  ["e"], es.CONFIDENCE_LOW)
        json.dumps(finding)
        assert es._safe_store_add(store, finding) is None

    def test_persistence_failure_is_reported_not_swallowed(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        store = es.PendingAssetsStore(output_dir=str(output_dir))
        with mock.patch.object(store, "add_many", side_effect=OSError("disk full")):
            err = es._safe_store_add(store, es.make_finding("x", SAFE_TARGET, {}, [], "LOW"))
        assert err and "disk full" in err


# ---------------------------------------------------------------------------
# DOWNSTREAM PIPELINE
# ---------------------------------------------------------------------------

def _assess(risk_engine_module, graph, tmp_path):
    """Run the real risk engine over a graph, without persisting to the repo."""
    return risk_engine_module.run_risk_engine(
        graph=graph.state, output_dir=str(tmp_path / "risk"), persist=False,
    )


def _signal_categories(assessment):
    categories = set()
    for key in ("signals", "assessed_assets", "investigation_queue"):
        for entry in assessment.get(key) or []:
            if isinstance(entry, dict):
                if entry.get("category"):
                    categories.add(entry["category"])
                for sub in entry.get("signals") or []:
                    if isinstance(sub, dict) and sub.get("category"):
                        categories.add(sub["category"])
    return categories


class TestDownstreamCompatibility:
    def _run(self, tmp_path, fake_get, fake_options=None, **kwargs):
        wl_dir = _write_wordlist(tmp_path, "directories.txt",
                                 [".env", "backup.sql", "admin/", "config.json", "backup/"])
        output_dir = tmp_path / "output"
        fake_options = fake_options or (lambda url, **kw: _fake_options_response(200, {"Allow": "GET"}))
        with mock.patch("requests.get", side_effect=fake_get), \
             mock.patch("requests.options", side_effect=fake_options):
            summary = es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir),
                                           wordlists_dir=wl_dir, **kwargs)
        return summary, json.loads((output_dir / "pending_assets.json").read_text())

    def test_findings_ingest_into_the_surface_mapper(self, tmp_path):
        from reconhound import surface_mapper as sm

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            if url.endswith(".env"):
                return _fake_response(200, {"Content-Type": "text/plain"}, b"DB_PASSWORD=x\nAPI_KEY=y\n")
            if url.endswith("backup/"):
                return _fake_response(200, {"Content-Type": "text/html"},
                                      b"<title>Index of /backup</title>")
            return _fake_response(404, body=b"not found")

        summary, records = self._run(tmp_path, fake_get)
        graph = sm.SurfaceMapper(target=SAFE_TARGET, output_dir=str(tmp_path / "graph"))
        result = graph.ingest_many(records)
        assert result["errors"] == 0
        assert result["ingested"] > 0

    def test_confirmed_exposure_reaches_the_risk_engine(self, tmp_path):
        from reconhound import surface_mapper as sm
        from reconhound import risk_engine as re_mod

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            if url.endswith(".env"):
                return _fake_response(200, {"Content-Type": "text/plain"},
                                      b"DB_PASSWORD=SuperSecret1\nAPI_KEY=abcdef123456\n")
            return _fake_response(404, body=b"not found")

        summary, records = self._run(tmp_path, fake_get)
        graph = sm.SurfaceMapper(target=SAFE_TARGET, output_dir=str(tmp_path / "graph"))
        graph.ingest_many(records)
        assessment = _assess(re_mod, graph, tmp_path)
        categories = _signal_categories(assessment)
        assert "exposed_credential_material" in categories

    def test_directory_listing_now_produces_a_risk_signal(self, tmp_path):
        """Regression for the downstream drop: the former "directory_listing_enabled" type
        matched no risk_engine.py rule, so a listed /backup/ scored nothing."""
        from reconhound import surface_mapper as sm
        from reconhound import risk_engine as re_mod

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            if url.endswith("backup/"):
                return _fake_response(200, {"Content-Type": "text/html"},
                                      b"<html><head><title>Index of /backup</title></head>"
                                      b"<body><a href='../'>Parent Directory</a></body></html>")
            return _fake_response(404, body=b"not found")

        summary, records = self._run(tmp_path, fake_get)
        graph = sm.SurfaceMapper(target=SAFE_TARGET, output_dir=str(tmp_path / "graph"))
        graph.ingest_many(records)
        assessment = _assess(re_mod, graph, tmp_path)
        categories = _signal_categories(assessment)
        assert "exposed_sensitive_resource" in categories

    def test_admin_login_page_does_not_produce_a_high_admin_signal(self, tmp_path):
        from reconhound import surface_mapper as sm
        from reconhound import risk_engine as re_mod

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            if url.endswith("admin/"):
                return _fake_response(200, {"Content-Type": "text/html"},
                                      b"<form action='/login'><input type='password'></form>")
            return _fake_response(404, body=b"not found")

        summary, records = self._run(tmp_path, fake_get)
        graph = sm.SurfaceMapper(target=SAFE_TARGET, output_dir=str(tmp_path / "graph"))
        graph.ingest_many(records)
        assessment = _assess(re_mod, graph, tmp_path)
        categories = _signal_categories(assessment)
        assert "exposed_administrative_panel" not in categories
        assert "sensitive_resource_present_not_readable" in categories

    def test_no_secret_survives_into_the_generated_report(self, tmp_path):
        from reconhound import surface_mapper as sm
        from reconhound import risk_engine as re_mod
        from reconhound import report_generator as rg

        secret = "Sup3rS3cretValue123"

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            if url.endswith(".env"):
                return _fake_response(200, {"Content-Type": "text/plain"},
                                      f"DB_PASSWORD={secret}\n".encode())
            return _fake_response(404, body=b"not found")

        summary, records = self._run(tmp_path, fake_get)
        graph = sm.SurfaceMapper(target=SAFE_TARGET, output_dir=str(tmp_path / "graph"))
        graph.ingest_many(records)
        assessment = _assess(re_mod, graph, tmp_path)
        document = rg.build_report_document(graph.state, assessment, output_dir=str(tmp_path / "report"))
        html = rg.render_html_report(document)
        assert secret not in html
        assert secret not in json.dumps(document)

    def test_negative_result_is_recognised_by_the_surface_mapper(self, tmp_path):
        from reconhound import surface_mapper as sm
        assert sm.SurfaceMapper._is_negative_result("exposure_scan_checked_no_exposure")
        assert sm.SurfaceMapper._is_negative_result("cloud_candidate_not_probed")

    def test_summary_is_json_serializable_with_every_phase_populated(self, tmp_path):
        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, body=b"not found")
            if url.endswith("robots.txt"):
                return _fake_response(200, {}, b"User-agent: *\nDisallow: /admin/\n")
            if url.endswith("sitemap.xml"):
                return _fake_response(200, {}, b"<urlset><url><loc>https://example.com/a</loc></url></urlset>")
            if url.endswith(".env"):
                return _fake_response(200, {"Content-Type": "text/plain"}, b"DB_PASSWORD=x\nAPI_KEY=y\n")
            if "s3.amazonaws.com" in url:
                return _fake_response(200, {}, b"<ListBucketResult><Contents/></ListBucketResult>")
            return _fake_response(404, body=b"not found")

        summary, records = self._run(tmp_path, fake_get,
                                     cloud_targets=[{"provider": "s3", "identifier": "example-bucket"}])
        json.dumps(summary)
        assert summary["robots_txt"]["status"] == "found"
        assert summary["sitemap_xml"]["status"] == "found"
        assert summary["cloud_exposure"]["checked"][0]["discovery_type"] == "confirmed_exposure"
        assert summary["http_options"]["results"]
        assert "scan_complete" in summary and "requests_made" in summary


# ---------------------------------------------------------------------------
# Self-attack regressions: defects found while attacking the fixes above
# ---------------------------------------------------------------------------

class TestSelfAttackRegressions:
    def test_hostile_server_header_does_not_burn_cpu(self):
        """Found by fuzzing the hardened build, not present in the DeepSeek inventory:
        `([A-Za-z][\\w.\\-]*)/(\\d[\\w.\\-]*)` backtracks catastrophically against a header
        with no "/" in it. A single 100 000-character `Server:` header — a value the
        *server* chooses, on every probed path — cost 70.8s of CPU in one call."""
        import time
        for header in ("Server", "X-Powered-By"):
            started = time.time()
            es.analyze_error_page("", {header: "a" * 1000000}, 500)
            assert time.time() - started < 1.0

    def test_server_version_still_extracted(self):
        result = es.analyze_error_page("", {"Server": "nginx/1.18.0"}, 200)
        versions = [i for i in result["indicators"] if i["indicator_type"] == "server_software_version"]
        assert versions and versions[0]["version"] == "1.18.0"

    def test_structural_signature_is_deterministic(self):
        """Found by attacking the new dynamic-catch-all comparison: the path variants were
        substituted out of a `set`, so "/x" and "x" could be replaced in either order and
        the same page normalised to two different signatures between calls."""
        body = "<html>Not found: /a/b/c (id 1)</html>"
        url = "https://example.com/a/b/c"
        assert len({es._structural_signature(body, url) for _ in range(50)}) == 1

    def test_structural_signature_ignores_the_requested_path_consistently(self):
        a = es._structural_signature("<html>Not found: /short</html>", "https://example.com/short")
        b = es._structural_signature("<html>Not found: /a-much-longer-path</html>",
                                     "https://example.com/a-much-longer-path")
        assert a == b

    def test_single_baseline_probe_is_marked(self):
        calls = {"n": 0}

        def fake_get(url, **kwargs):
            calls["n"] += 1
            if calls["n"] > 1:
                raise requests.exceptions.Timeout("timed out")
            return _fake_response(404, {}, b"nope")

        with mock.patch("requests.get", side_effect=fake_get):
            baseline = es._probe_soft_404("https://example.com", 5.0)
        assert baseline["available"] is True
        assert baseline["single_sample"] is True

    def test_phase_error_is_reported_exactly_once(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env"])

        def fake_get(url, **kwargs):
            if url.endswith("robots.txt"):
                raise requests.exceptions.ConnectionError("refused")
            return _fake_response(404, body=b"not found")

        with mock.patch("requests.get", side_effect=fake_get), \
             mock.patch("requests.options", return_value=_fake_options_response(200, {})):
            result = es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET,
                                          output_dir=str(tmp_path / "output"), wordlists_dir=wl_dir)
        robots_errors = [e for e in result["errors"] if e.get("stage") == "robots_txt"]
        assert len(robots_errors) == 1

    def test_rate_limited_paths_do_not_become_findings_or_assets(self, tmp_path):
        """Persisting a 429 as an `exposure_finding` mints one phantom finding asset per
        wordlist entry in surface_mapper against a rate-limiting host — the same
        "request failure == presence" bug endpoint_discovery.py documents."""
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env", "backup.sql", "admin/"])
        output_dir = tmp_path / "output"
        with mock.patch("requests.get", return_value=_fake_response(429, {}, b"slow down")), \
             mock.patch("requests.options", return_value=_fake_options_response(429, {})):
            result = es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir),
                                          wordlists_dir=wl_dir)
        assert result["sensitive_resources"]["findings"] == []
        assert result["sensitive_resources"]["candidates_untested"] > 0
        assert result["scan_complete"] is False
        records = json.loads((output_dir / "pending_assets.json").read_text())
        assert not any(r["type"] == "exposure_finding" for r in records)

    def test_soft_404_matches_are_counted_not_persisted(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env", "backup.sql", "config.php"])
        output_dir = tmp_path / "output"
        catchall = b"<html><body>My SPA App</body></html>"
        with mock.patch("requests.get", return_value=_fake_response(200, {"Content-Type": "text/html"}, catchall)), \
             mock.patch("requests.options", return_value=_fake_options_response(200, {})):
            result = es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir),
                                          wordlists_dir=wl_dir)
        sweep = result["sensitive_resources"]
        assert sweep["findings"] == []
        expected = 3 + len(es._SENSITIVE_DIRECTORIES)   # .aws/ and .ssh/ are always probed too
        assert sweep["soft_404_matches"] == expected
        assert sweep["negative_results"] == expected
        records = json.loads((output_dir / "pending_assets.json").read_text())
        assert not any(r["type"] == "exposure_finding" for r in records)

    def test_soft_404_carrying_a_real_signature_is_preserved_as_a_conflict(self, tmp_path):
        """context.md §8: a contradiction is preserved, not dropped. If the catch-all page
        itself serves dotenv content, that is worth surfacing even though the comparison
        says "same as not-found"."""
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env"])
        body = b"DB_PASSWORD=x\nAPI_KEY=y\n"
        with mock.patch("requests.get", return_value=_fake_response(200, {"Content-Type": "text/plain"}, body)):
            result = es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)
        assert len(result["findings"]) == 1
        record = result["findings"][0]
        assert record["discovery_type"] == "possible_soft_404_match"
        assert record["conflicting_evidence"] is True
        assert any("suppressed" in e for e in record["evidence"])


# ---------------------------------------------------------------------------
# End-to-end: hostile content through the real pipeline
# ---------------------------------------------------------------------------

class TestHostileContentEndToEnd:
    _XSS = b"<script>alert('pwn')</script><img src=x onerror=alert(1)>"
    _SECRET = (b"DB_PASSWORD=Sup3rS3cretValue0987654321\n"
               b"API_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")

    def _scan(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env", "admin/", "backup/", "config.json"])
        output_dir = tmp_path / "output"

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, {}, b"not found")
            if url.endswith(".env"):
                return _fake_response(200, {"Content-Type": "text/plain"}, self._SECRET + self._XSS)
            if url.endswith("admin/"):
                return _fake_response(200, {"Content-Type": "text/html"}, b"<h1>Dashboard</h1>" + self._XSS)
            if url.endswith("backup/"):
                return _fake_response(200, {"Content-Type": "text/html"},
                                      b"<title>Index of /backup</title>" + self._XSS)
            if url.endswith("robots.txt"):
                return _fake_response(200, {}, b"Disallow: /" + self._XSS)
            if url.endswith("sitemap.xml"):
                return _fake_response(200, {}, b"<urlset><url><loc>https://example.com/x</loc></url></urlset>")
            return _fake_response(404, {}, b"not found")

        with mock.patch("requests.get", side_effect=fake_get), \
             mock.patch("requests.options", return_value=_fake_options_response(200, {"Allow": "GET, POST"})):
            summary = es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir),
                                           wordlists_dir=wl_dir)
        return summary, json.loads((output_dir / "pending_assets.json").read_text())

    def test_no_secret_reaches_persistence_or_the_report(self, tmp_path):
        from reconhound import surface_mapper as sm
        from reconhound import risk_engine as re_mod
        from reconhound import report_generator as rg

        summary, records = self._scan(tmp_path)
        blob = json.dumps(records)
        assert "Sup3rS3cretValue0987654321" not in blob
        assert "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in blob
        assert "DB_PASSWORD" in blob

        graph = sm.SurfaceMapper(target=SAFE_TARGET, output_dir=str(tmp_path / "graph"))
        assert graph.ingest_many(records)["errors"] == 0
        assessment = _assess(re_mod, graph, tmp_path)
        html = rg.render_html_report(
            rg.build_report_document(graph.state, assessment, output_dir=str(tmp_path / "report")))
        assert "Sup3rS3cretValue0987654321" not in html
        assert "<script>alert('pwn')</script>" not in html
        assert "<img src=x onerror" not in html

    def test_all_three_exposure_classes_reach_the_risk_engine(self, tmp_path):
        from reconhound import surface_mapper as sm
        from reconhound import risk_engine as re_mod

        summary, records = self._scan(tmp_path)
        graph = sm.SurfaceMapper(target=SAFE_TARGET, output_dir=str(tmp_path / "graph"))
        graph.ingest_many(records)
        categories = _signal_categories(_assess(re_mod, graph, tmp_path))
        assert {"exposed_credential_material", "exposed_sensitive_resource",
                "exposed_administrative_panel"} <= categories

    def test_reingestion_creates_no_duplicate_assets(self, tmp_path):
        from reconhound import surface_mapper as sm
        summary, records = self._scan(tmp_path)
        graph = sm.SurfaceMapper(target=SAFE_TARGET, output_dir=str(tmp_path / "graph"))
        graph.ingest_many(records)
        before = len(graph.state["assets"])
        graph.ingest_many(records)
        assert len(graph.state["assets"]) == before

    def test_every_persisted_record_matches_the_canonical_schema(self, tmp_path):
        summary, records = self._scan(tmp_path)
        assert records
        for record in records:
            assert set(record) >= {"type", "target", "value", "evidence", "confidence",
                                   "source", "timestamp", "metadata"}
            assert record["source"] == "exposure_scan.py"
            assert record["confidence"] in ("LOW", "MEDIUM", "HIGH")
            assert isinstance(record["evidence"], list)

    def test_robots_directives_are_length_bounded(self):
        body = b"Disallow: /" + b"a" * 100000 + b"\n"
        with mock.patch("requests.get", return_value=_fake_response(200, {}, body)):
            result = es.discover_robots_txt(SAFE_URL, target=SAFE_TARGET)
        assert all(len(p) <= es.MAX_ROBOTS_DIRECTIVE_CHARS for p in result["disallowed_paths"])

    def test_no_module_makes_a_request_outside_the_target_or_a_provider(self, tmp_path):
        """Whole-run scope invariant: every URL requested is either on the target's own
        origin or on an explicitly authorized storage provider's host."""
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env", "admin/", ".git/HEAD"])
        requested = []

        def fake_get(url, **kwargs):
            requested.append(url)
            return _fake_response(404, {}, b"not found")

        def fake_options(url, **kwargs):
            requested.append(url)
            return _fake_options_response(200, {})

        with mock.patch("requests.get", side_effect=fake_get), \
             mock.patch("requests.options", side_effect=fake_options):
            es.run_exposure_scan(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"), wordlists_dir=wl_dir,
                cloud_targets=["https://mybucket.s3.amazonaws.com/", "https://evil.com/"],
                endpoints=["https://evil.com/x", "http://169.254.169.254/", "https://api.example.com/v1"],
            )
        for url in requested:
            host = urllib.parse.urlsplit(url).hostname or ""
            assert (host == SAFE_TARGET or host.endswith("." + SAFE_TARGET)
                    or host.endswith(".s3.amazonaws.com")), url

    def test_summary_errors_are_bounded_under_hostile_input(self, tmp_path):
        """`endpoints` and `cloud_targets` are caller-supplied and arbitrarily long; the
        rejection *count* must stay exact while the record list stays bounded."""
        wl_dir = _write_wordlist(tmp_path, "directories.txt", [".env"])
        with mock.patch("requests.get", side_effect=_all_404), \
             mock.patch("requests.options", return_value=_fake_options_response(200, {})):
            summary = es.run_exposure_scan(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"), wordlists_dir=wl_dir,
                endpoints=[f"https://evil{i}.com/x" for i in range(20000)],
                cloud_targets=[f"bad-{i}" for i in range(2000)],
            )
        assert summary["error_count"] <= es.MAX_SUMMARY_ERRORS + 1
        assert summary["http_options"]["urls_rejected_out_of_scope"] == 20000
        assert len(json.dumps(summary)) < 500_000

    def test_pathological_target_does_not_produce_giant_candidates(self):
        candidates = es.generate_cloud_candidates("a" * 100000)
        assert candidates
        assert all(len(c["identifier"]) <= 63 for c in candidates)


# ---------------------------------------------------------------------------
# Combined failure modes and boundary conditions
# ---------------------------------------------------------------------------

class TestCombinedFailureModes:
    _WORDS = [".env", "admin/", "backup.zip", "config.json", "debug/"]

    def test_every_category_status_combination_is_json_safe(self):
        import itertools
        categories = [getattr(es, n) for n in dir(es) if n.startswith("CATEGORY_")]
        statuses = [200, 201, 202, 204, 206, 301, 302, 303, 304, 307, 308,
                    400, 401, 403, 404, 405, 406, 410, 418, 429, 500, 502, 503, 504]
        bodies = [("", b"", None), ("<html>x</html>", b"<htm", "text/html"),
                  ("A=1\nB=2\n", b"A=1", "text/plain"), ("\x00\xff", b"\x00\xff", "application/octet-stream")]
        for category, status in itertools.product(categories, statuses):
            for body, prefix, content_type in bodies:
                result = es.evaluate_exposure(
                    category, "x",
                    {"status_code": status, "headers": {"Content-Type": content_type} if content_type else {},
                     "body": body, "raw_prefix": prefix},
                    None, url="https://example.com/x")
                json.dumps(result)
                if not 200 <= status < 300:
                    assert result[0] != "confirmed_exposure", (category, status)

    def test_truncated_body_confirms_but_is_marked_incomplete(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", self._WORDS)
        body = b"DB_PASSWORD=x\nAPI_KEY=y\n" + b"z" * 300000

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, {}, b"not found")
            if url.endswith(".env"):
                return _fake_response(200, {"Content-Type": "text/plain"}, body)
            return _fake_response(404, {}, b"not found")

        with mock.patch("requests.get", side_effect=fake_get):
            result = es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)
        record = next(f for f in result["findings"] if f["url"].endswith(".env"))
        assert record["discovery_type"] == "confirmed_exposure"
        assert record["body_truncated"] is True
        assert record["content_complete"] is False

    def test_confirmation_still_works_when_the_baseline_probe_fails(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", self._WORDS)

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                raise requests.exceptions.Timeout("timed out")
            if url.endswith(".env"):
                return _fake_response(200, {"Content-Type": "text/plain"}, b"A=1\nB=2\n")
            return _fake_response(404, {}, b"not found")

        with mock.patch("requests.get", side_effect=fake_get):
            result = es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)
        record = next(f for f in result["findings"] if f["url"].endswith(".env"))
        assert record["discovery_type"] == "confirmed_exposure"
        assert record["baseline_available"] is False
        assert result["baseline"]["available"] is False
        assert result["sweep_conclusive"] is False

    def test_mixed_failure_modes_in_one_run(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, "directories.txt", self._WORDS)
        output_dir = tmp_path / "output"

        def fake_get(url, **kwargs):
            if "reconhound-exposure-check" in url:
                return _fake_response(404, {}, b"not found")
            if url.endswith(".env"):
                raise requests.exceptions.ConnectionError("refused")
            if url.endswith("admin/"):
                return _fake_response(429, {}, b"slow down")
            if url.endswith("backup.zip"):
                return _fake_response(200, {}, b"PK\x03\x04zipcontent")
            if url.endswith("config.json"):
                return _fake_response(500, {}, b"boom")
            if url.endswith("robots.txt"):
                return _fake_response(403, {}, b"denied")
            if url.endswith("sitemap.xml"):
                raise requests.exceptions.Timeout("timed out")
            return _fake_response(404, {}, b"not found")

        with mock.patch("requests.get", side_effect=fake_get), \
             mock.patch("requests.options", return_value=_fake_options_response(200, {"Allow": "GET"})):
            summary = es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir),
                                           wordlists_dir=wl_dir)

        types = {f["url"].rsplit("/", 1)[-1]: f["discovery_type"]
                 for f in summary["sensitive_resources"]["findings"]}
        assert types.get("backup.zip") == "confirmed_exposure"   # unaffected by its neighbours
        assert summary["robots_txt"]["status"] == "access_restricted"
        assert summary["sitemap_xml"]["status"] == "error"
        assert summary["completeness"] == "partial"
        assert summary["incomplete_reasons"]
        records = json.loads((output_dir / "pending_assets.json").read_text())
        assert not any(r["type"] == "exposure_scan_checked_no_exposure" for r in records)

    def test_archive_magic_identical_to_the_catch_all_is_kept_as_a_conflict(self, tmp_path):
        """The catch-all page itself serves archive bytes: the comparison says "same as
        not-found" while the signature says "archive". Both are kept."""
        wl_dir = _write_wordlist(tmp_path, "directories.txt", self._WORDS)
        body = b"PK\x03\x04" + b"<html>SPA</html>"
        with mock.patch("requests.get", return_value=_fake_response(200, {"Content-Type": "text/html"}, body)), \
             mock.patch("requests.options", return_value=_fake_options_response(200, {})):
            summary = es.run_exposure_scan(SAFE_URL, target=SAFE_TARGET,
                                           output_dir=str(tmp_path / "output"), wordlists_dir=wl_dir)
        record = next(f for f in summary["sensitive_resources"]["findings"] if f["url"].endswith("backup.zip"))
        assert record["discovery_type"] == "possible_soft_404_match"
        assert record["conflicting_evidence"] is True

    def test_unwritable_output_directory_is_reported_not_raised(self, tmp_path):
        output_dir = tmp_path / "output"
        store = es.PendingAssetsStore(output_dir=str(output_dir))
        os.chmod(output_dir, 0o500)
        try:
            err = es._safe_store_add(store, es.make_finding("x", SAFE_TARGET, {}, [], es.CONFIDENCE_LOW))
            assert err is not None
        finally:
            os.chmod(output_dir, 0o700)

    def test_error_page_analysis_runs_once_per_surviving_candidate(self, tmp_path):
        """The framework patterns are the most expensive thing run against a response body;
        they must not run for a path that turned out to be a 404 or a catch-all match."""
        wl_dir = _write_wordlist(tmp_path, "directories.txt", self._WORDS)
        calls = []
        real = es.analyze_error_page

        def counting(body, headers=None, status_code=None):
            calls.append(body)
            return real(body, headers, status_code)

        with mock.patch("requests.get", side_effect=_all_404), \
             mock.patch.object(es, "analyze_error_page", side_effect=counting):
            es.discover_sensitive_resources(SAFE_URL, target=SAFE_TARGET, wordlists_dir=wl_dir)
        # Only the "debug/" candidate needs its body analysed before classification;
        # every other 404 must be discarded without analysis.
        assert len(calls) <= 1


# ---------------------------------------------------------------------------
# Persistence under concurrency and external modification
# ---------------------------------------------------------------------------

class TestPersistenceIntegrity:
    def test_concurrent_writers_lose_nothing(self, tmp_path):
        import threading
        store = es.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        errors = []

        def writer(worker):
            try:
                for i in range(40):
                    store.add(es.make_finding("exposure_finding", SAFE_TARGET,
                                              {"i": worker * 100 + i}, ["e"], es.CONFIDENCE_LOW))
            except Exception as exc:            # noqa: BLE001 — the failure is the assertion
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert len(store.all()) == 320

    def test_external_modification_invalidates_the_write_cache(self, tmp_path):
        """The serialized-body cache is an optimisation, not a source of truth: another
        module writing to the shared file between two appends must not be overwritten."""
        import time
        store = es.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        store.add(es.make_finding("exposure_finding", SAFE_TARGET, {}, ["e"], es.CONFIDENCE_LOW))
        time.sleep(0.01)
        existing = json.loads(open(store.path).read())
        existing.append({"type": "dns_record", "source": "passive_recon.py"})
        open(store.path, "w").write(json.dumps(existing))

        store.add(es.make_finding("exposure_finding", SAFE_TARGET, {}, ["e"], es.CONFIDENCE_LOW))
        final = store.all()
        assert len(final) == 3
        assert any(r.get("source") == "passive_recon.py" for r in final)

    def test_atomic_write_leaves_no_temporary_files(self, tmp_path):
        output_dir = tmp_path / "output"
        store = es.PendingAssetsStore(output_dir=str(output_dir))
        for i in range(5):
            store.add(es.make_finding("exposure_finding", SAFE_TARGET, {"i": i}, ["e"], es.CONFIDENCE_LOW))
        assert sorted(os.listdir(output_dir)) == ["pending_assets.json"]

    def test_failed_write_does_not_corrupt_the_existing_file(self, tmp_path):
        store = es.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        store.add(es.make_finding("exposure_finding", SAFE_TARGET, {"keep": True}, ["e"], es.CONFIDENCE_LOW))
        with mock.patch("os.replace", side_effect=OSError("no space left")):
            err = es._safe_store_add(store, es.make_finding("exposure_finding", SAFE_TARGET,
                                                            {"lost": True}, ["e"], es.CONFIDENCE_LOW))
        assert err is not None
        records = store.all()
        assert len(records) == 1 and records[0]["value"] == {"keep": True}
        # The cache was invalidated by the failure, so the next write rebuilds from disk.
        store.add(es.make_finding("exposure_finding", SAFE_TARGET, {"next": True}, ["e"], es.CONFIDENCE_LOW))
        assert len(store.all()) == 2


# ---------------------------------------------------------------------------
# Dead-origin tripwire (TRANSPORT_FAILURE_TRIP_THRESHOLD)
#
# Reproduces the performance defect found in the 2026-09-12 whole-system
# audit: against a port that accepts TCP and never answers HTTP, this module
# ran its whole sweep plus robots/sitemap/cloud/OPTIONS on transport failures
# alone — 69 requests / 22s at timeout=2 and 90s at the orchestrator's
# default timeout=8, for zero observations.
# ---------------------------------------------------------------------------


class TestDeadOriginTripwire:
    # Only entries classify_exposure_category() recognises are swept, so the
    # fixture uses real category-matching shapes rather than arbitrary names.
    WORDS = ([f"backup{i}.sql" for i in range(40)]
             + [f"db{i}.bak" for i in range(40)]
             + [f"dump{i}.tar.gz" for i in range(40)])

    def _wl(self, tmp_path):
        return _write_wordlist(tmp_path, "directories.txt", self.WORDS)

    def _dead(self, tmp_path, exc=None):
        exc = exc or requests.exceptions.Timeout("timed out")
        sent = []

        def fail(url, **kwargs):
            sent.append(url)
            raise exc

        with mock.patch("requests.get", side_effect=fail), \
             mock.patch("requests.options", side_effect=fail):
            summary = es.run_exposure_scan(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                wordlists_dir=self._wl(tmp_path), max_workers=4)
        return summary, sent

    def test_the_scan_stops_once_the_origin_stops_answering(self, tmp_path):
        summary, sent = self._dead(tmp_path)
        assert summary["origin_unreachable"] is True
        assert len(sent) < len(self.WORDS), "the whole candidate list was still probed"

    def test_a_tripped_scan_is_never_complete_and_writes_no_negative_result(self, tmp_path):
        out = tmp_path / "output"
        summary, _ = self._dead(tmp_path)
        assert summary["scan_complete"] is False
        assert summary["completeness"] == "partial"
        pending = out / "pending_assets.json"
        blob = pending.read_text() if pending.exists() else ""
        assert "exposure_scan_checked_no_exposure" not in blob

    def test_the_reason_is_stated_and_not_confused_with_the_request_budget(self, tmp_path):
        summary, _ = self._dead(tmp_path)
        reasons = " | ".join(summary["incomplete_reasons"])
        assert "stopped answering" in reasons
        # The budget was nowhere near exhausted; saying so would be false.
        assert summary["request_budget_exhausted"] is False
        for record in summary["errors"]:
            assert "budget" not in str(record.get("error", "")).lower(), record

    def test_one_answered_probe_disarms_the_tripwire_permanently(self):
        state = es._ScanState(SAFE_TARGET, None, 10_000)
        for _ in range(es.TRANSPORT_FAILURE_TRIP_THRESHOLD - 1):
            state.note_transport_failure()
        assert state.origin_unreachable is False
        state.note_answered()
        for _ in range(es.TRANSPORT_FAILURE_TRIP_THRESHOLD * 5):
            state.note_transport_failure()
        assert state.origin_unreachable is False
        assert state.reserve_request() is True

    def test_a_live_origin_answering_404_is_swept_in_full(self, tmp_path):
        sent = []

        def not_found(url, **kwargs):
            sent.append(url)
            return _fake_response(404, body=b"not found")

        with mock.patch("requests.get", side_effect=not_found), \
             mock.patch("requests.options", side_effect=not_found):
            summary = es.run_exposure_scan(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                wordlists_dir=self._wl(tmp_path), max_workers=4)

        assert summary["origin_unreachable"] is False
        assert len(sent) >= len(self.WORDS)

    def test_refusal_reason_distinguishes_a_dead_origin_from_an_exhausted_budget(self):
        budget = es._ScanState(SAFE_TARGET, None, 0)
        assert budget.reserve_request() is False
        assert "budget" in budget.refusal_reason()

        dead = es._ScanState(SAFE_TARGET, None, 10_000)
        for _ in range(es.TRANSPORT_FAILURE_TRIP_THRESHOLD):
            dead.note_transport_failure()
        assert dead.reserve_request() is False
        assert "stopped answering" in dead.refusal_reason()
        assert dead.budget_exhausted is False


class TestOptionsFindingIdentityIsStableAcrossRescans:
    """
    2026-09-12 whole-system audit: surface_mapper.py keys a finding asset on
    a hash of the whole `value`, and this module put this run's own clock and
    the CDN's per-request trace id (CF-Ray, X-Amz-Cf-Id) inside it — so every
    re-scan minted a new `http_options_result` finding asset, risk signal and
    report row for one unchanged endpoint. Confirmed on two consecutive live
    runs against example.com.
    """

    HEADERS = {"Allow": "GET, HEAD, OPTIONS", "Server": "cloudflare",
               "CF-Ray": "aaa111-KHI", "Content-Type": "text/html"}

    def _persisted(self, tmp_path, ray):
        out = tmp_path / f"o{ray}"
        store = es.PendingAssetsStore(output_dir=str(out))
        headers = dict(self.HEADERS, **{"CF-Ray": ray})
        with mock.patch("requests.options", side_effect=lambda u, **k:
                        _fake_options_response(200, headers=headers)):
            es.discover_http_options([SAFE_URL], target=SAFE_TARGET, store=store)
        return [r for r in store.all() if r["type"] == "http_options_result"][0]

    def test_a_new_trace_id_and_a_later_clock_do_not_change_the_value(self, tmp_path):
        first = self._persisted(tmp_path, "aaa111-KHI")
        second = self._persisted(tmp_path, "bbb222-KHI")
        assert first["value"] == second["value"], (
            "the same OPTIONS result must keep one finding identity across re-scans")

    def test_the_volatile_evidence_is_kept_as_metadata_not_discarded(self, tmp_path):
        record = self._persisted(tmp_path, "aaa111-KHI")
        assert record["metadata"]["response_provenance_headers"]["CF-Ray"] == "aaa111-KHI"
        assert record["metadata"]["observed_at"]
        # and the finding's own evidence list still states it
        assert any("CF-Ray" in line for line in record["evidence"])

    def test_the_stable_value_keeps_what_the_finding_is_about(self, tmp_path):
        value = self._persisted(tmp_path, "aaa111-KHI")["value"]
        assert value["advertised_methods"] == ["GET", "HEAD", "OPTIONS"]
        assert value["discovery_type"] == "options_supported"
        assert value["url"] == SAFE_URL
        assert "timestamp" not in value
        assert "response_provenance_headers" not in value

    def test_a_genuine_change_in_advertised_methods_is_still_a_new_finding(self, tmp_path):
        first = self._persisted(tmp_path, "aaa111-KHI")
        out = tmp_path / "changed"
        store = es.PendingAssetsStore(output_dir=str(out))
        headers = dict(self.HEADERS, Allow="GET, HEAD, OPTIONS, PUT, DELETE")
        with mock.patch("requests.options", side_effect=lambda u, **k:
                        _fake_options_response(200, headers=headers)):
            es.discover_http_options([SAFE_URL], target=SAFE_TARGET, store=store)
        second = [r for r in store.all() if r["type"] == "http_options_result"][0]
        assert first["value"] != second["value"]

    def test_the_callers_own_result_still_carries_everything(self, tmp_path):
        with mock.patch("requests.options", side_effect=lambda u, **k:
                        _fake_options_response(200, headers=self.HEADERS)):
            summary = es.discover_http_options([SAFE_URL], target=SAFE_TARGET, store=None)
        result = summary["results"][0]
        assert result["timestamp"]
        assert result["response_provenance_headers"]["CF-Ray"] == "aaa111-KHI"
