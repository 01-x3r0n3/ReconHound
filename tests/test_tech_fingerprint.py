"""
Tests for reconhound/tech_fingerprint.py (ReconHound Module 8, per
context.md's build order — catalog item 8).

Run with:  ./.venv/bin/python -m pytest tests/test_tech_fingerprint.py -v

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

from reconhound import tech_fingerprint as tf
from reconhound import endpoint_discovery as ed


SAFE_URL = "https://example.com/"
SAFE_TARGET = "example.com"


def _fake_response(status_code=200, headers=None, body=b"", set_cookie_headers=None, final_url=None):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = dict(headers or {})
    resp.encoding = "utf-8"
    resp.content = body
    resp.url = final_url or SAFE_URL
    resp.elapsed.total_seconds.return_value = 0.05
    resp.raw.read.return_value = body
    resp.raw.headers.getlist.return_value = list(set_cookie_headers or [])
    return resp


# ---------------------------------------------------------------------------
# validate_url_target (scope enforcement)
# ---------------------------------------------------------------------------

class TestValidateUrlTarget:
    def test_accepts_https_url(self):
        assert tf.validate_url_target("https://example.com/path") == "https://example.com/path"

    def test_accepts_in_scope_subdomain(self):
        assert tf.validate_url_target("https://api.example.com/", target="example.com")

    def test_rejects_out_of_scope_host(self):
        with pytest.raises(tf.ScopeError):
            tf.validate_url_target("https://evil.com/", target="example.com")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(tf.ScopeError):
            tf.validate_url_target("ftp://example.com/")

    def test_rejects_missing_hostname(self):
        with pytest.raises(tf.ScopeError):
            tf.validate_url_target("https:///path")

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(tf.ScopeError):
            tf.validate_url_target(bad)

    def test_allows_ip_literal_host_without_scope_check(self):
        assert tf.validate_url_target("http://93.184.216.34/", target="example.com")


# ---------------------------------------------------------------------------
# make_finding / make_tech_finding / PendingAssetsStore (shared conventions)
# ---------------------------------------------------------------------------

class TestFindingsAndStore:
    def test_finding_structure_and_source(self):
        finding = tf.make_finding("tech_fingerprint_detected", SAFE_URL, {"a": 1}, ["e"], tf.CONFIDENCE_HIGH)
        assert finding["source"] == "tech_fingerprint.py"
        assert finding["metadata"] == {}
        json.dumps(finding)

    def test_make_tech_finding_preserves_all_required_fields(self):
        finding = tf.make_tech_finding(
            technology="WordPress", category=tf.CATEGORY_CMS, version="6.4.2",
            evidence=["meta generator declared WordPress 6.4.2"], confidence=tf.CONFIDENCE_HIGH,
            target=SAFE_TARGET, url=SAFE_URL,
        )
        assert finding["value"]["technology"] == "WordPress"
        assert finding["value"]["category"] == tf.CATEGORY_CMS
        assert finding["value"]["version"] == "6.4.2"
        assert finding["value"]["url"] == SAFE_URL
        assert finding["confidence"] == tf.CONFIDENCE_HIGH
        assert finding["evidence"] == ["meta generator declared WordPress 6.4.2"]
        assert "timestamp" in finding
        json.dumps(finding)

    def test_make_tech_finding_never_invents_version(self):
        finding = tf.make_tech_finding(
            technology="Joomla", category=tf.CATEGORY_CMS, version=None,
            evidence=["generator tag present without version"], confidence=tf.CONFIDENCE_MEDIUM,
            target=SAFE_TARGET, url=SAFE_URL,
        )
        assert finding["value"]["version"] is None

    def test_store_preserves_prior_data(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{"type": "dns_record", "source": "passive_recon.py"}]
        pending.write_text(json.dumps(pre_existing))

        store = tf.PendingAssetsStore(output_dir=str(output_dir))
        store.add(tf.make_finding("tech_fingerprint_detected", SAFE_URL, {}, ["e"], tf.CONFIDENCE_HIGH))
        assert store.all() == pre_existing + [store.all()[-1]]

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = tf.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(tf.PersistenceError):
            store.add(tf.make_finding("tech_fingerprint_detected", SAFE_URL, {}, ["e"], tf.CONFIDENCE_HIGH))

    def test_safe_store_add_returns_none_when_store_is_none(self):
        assert tf._safe_store_add(None, tf.make_finding("x", SAFE_URL, {}, [], tf.CONFIDENCE_LOW)) is None

    def test_safe_store_add_returns_error_string_on_persistence_failure(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("not json at all")
        store = tf.PendingAssetsStore(output_dir=str(output_dir))
        err = tf._safe_store_add(store, tf.make_finding("x", SAFE_URL, {}, [], tf.CONFIDENCE_LOW))
        assert err is not None


# ---------------------------------------------------------------------------
# fetch_url
# ---------------------------------------------------------------------------

class TestFetchUrl:
    def test_successful_fetch(self):
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"},
                               body=b"<html>hi</html>", set_cookie_headers=["a=1; Path=/"])
        with mock.patch("requests.get", return_value=resp):
            result = tf.fetch_url(SAFE_URL)
        assert result["status"] == "found"
        assert result["status_code"] == 200
        assert result["body"] == "<html>hi</html>"
        assert result["body_bytes"] == b"<html>hi</html>"
        assert result["set_cookie_headers"] == ["a=1; Path=/"]

    def test_body_truncated_when_over_limit(self):
        resp = _fake_response(body=b"x" * 100)
        with mock.patch("requests.get", return_value=resp):
            result = tf.fetch_url(SAFE_URL, max_body_bytes=10)
        assert result["body_truncated"] is True
        assert len(result["body"]) == 10

    def test_timeout_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout("timed out")):
            result = tf.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_connection_error_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = tf.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert "connection error" in result["error"]

    def test_generic_request_exception_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.RequestException("boom")):
            result = tf.fetch_url(SAFE_URL)
        assert result["status"] == "error"

    def test_malformed_empty_body(self):
        resp = _fake_response(status_code=200, body=b"")
        with mock.patch("requests.get", return_value=resp):
            result = tf.fetch_url(SAFE_URL)
        assert result["status"] == "found"
        assert result["body"] == ""

    def test_json_serializable(self):
        resp = _fake_response(headers={"X-Test": "1"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            result = tf.fetch_url(SAFE_URL)
        # body_bytes is not JSON-serializable on its own; run_tech_fingerprint never
        # persists it directly, but the rest of the structure must be.
        result.pop("body_bytes")
        json.dumps(result)


# ---------------------------------------------------------------------------
# parse_cookie_names
# ---------------------------------------------------------------------------

class TestParseCookieNames:
    def test_extracts_names(self):
        names = tf.parse_cookie_names(["wordpress_logged_in=abc; Path=/; HttpOnly", "wp-settings-1=x"])
        assert names == ["wordpress_logged_in", "wp-settings-1"]

    def test_empty_list(self):
        assert tf.parse_cookie_names([]) == []

    def test_none_input(self):
        assert tf.parse_cookie_names(None) == []


# ---------------------------------------------------------------------------
# 1. detect_servers
# ---------------------------------------------------------------------------

class TestDetectServers:
    def test_nginx_with_version(self):
        result = tf.detect_servers({"Server": "nginx/1.18.0"})
        assert "Nginx" in result
        assert result["Nginx"]["version"] == "1.18.0"
        assert result["Nginx"]["score"] == tf._SCORE_STRONG

    def test_apache_with_version(self):
        result = tf.detect_servers({"Server": "Apache/2.4.41 (Ubuntu)"})
        assert result["Apache"]["version"] == "2.4.41"

    def test_iis(self):
        result = tf.detect_servers({"Server": "Microsoft-IIS/10.0"})
        assert result["Microsoft IIS"]["version"] == "10.0"

    def test_caddy(self):
        result = tf.detect_servers({"Server": "Caddy"})
        assert "Caddy" in result
        assert result["Caddy"]["version"] is None

    def test_no_server_header(self):
        assert tf.detect_servers({}) == {}

    def test_unknown_server_value_no_match(self):
        assert tf.detect_servers({"Server": "SomeCustomServer/1.0"}) == {}

    def test_single_header_never_reaches_high_alone(self):
        result = tf.detect_servers({"Server": "nginx/1.18.0"})
        assert tf._confidence_for_score(result["Nginx"]["score"]) == tf.CONFIDENCE_MEDIUM


# ---------------------------------------------------------------------------
# 2. detect_wafs
# ---------------------------------------------------------------------------

class TestDetectWafs:
    def test_cloudflare_via_header(self):
        result = tf.detect_wafs({"Server": "cloudflare", "CF-RAY": "abc123"}, [], "")
        assert "Cloudflare" in result
        assert result["Cloudflare"]["score"] >= tf._SCORE_STRONG

    def test_cloudflare_via_cookie(self):
        result = tf.detect_wafs({}, ["__cfduid=abcdef; Path=/"], "")
        assert "Cloudflare" in result

    def test_akamai_via_header(self):
        result = tf.detect_wafs({"Server": "AkamaiGHost"}, [], "")
        assert "Akamai" in result

    def test_aws_waf_via_header(self):
        result = tf.detect_wafs({"x-amzn-waf-action": "captcha"}, [], "")
        assert "AWS WAF" in result

    def test_f5_via_body(self):
        result = tf.detect_wafs({}, [], "The requested URL was rejected. Please consult with your administrator.")
        assert "F5" in result

    def test_imperva_via_header(self):
        result = tf.detect_wafs({"X-Iinfo": "1-abc"}, [], "")
        assert "Imperva" in result

    def test_no_waf_signals(self):
        assert tf.detect_wafs({"Content-Type": "text/html"}, [], "<html></html>") == {}

    def test_waf_findings_never_carry_version(self):
        result = tf.detect_wafs({"Server": "cloudflare"}, [], "")
        assert result["Cloudflare"]["version"] is None


# ---------------------------------------------------------------------------
# 3. _extract_meta_generator
# ---------------------------------------------------------------------------

class TestExtractMetaGenerator:
    def test_wordpress_with_version(self):
        body = '<html><head><meta name="generator" content="WordPress 6.4.2" /></head></html>'
        content, version = tf._extract_meta_generator(body, "WordPress")
        assert content == "WordPress 6.4.2"
        assert version == "6.4.2"

    def test_drupal_bare_major_version(self):
        body = '<meta name="generator" content="Drupal 10 (https://www.drupal.org)" />'
        content, version = tf._extract_meta_generator(body, "Drupal")
        assert version == "10"

    def test_joomla_without_version_returns_none_version(self):
        body = '<meta name="generator" content="Joomla! - Open Source Content Management" />'
        content, version = tf._extract_meta_generator(body, "Joomla")
        assert content is not None
        assert version is None  # never invented

    def test_no_match_returns_none_none(self):
        content, version = tf._extract_meta_generator("<html>nothing here</html>", "WordPress")
        assert content is None
        assert version is None

    def test_empty_body(self):
        assert tf._extract_meta_generator("", "WordPress") == (None, None)


# ---------------------------------------------------------------------------
# 3. detect_technologies_from_content — per-technology signal matching
# ---------------------------------------------------------------------------

class TestDetectTechnologiesFromContent:
    def test_wordpress_multi_signal_high_confidence(self):
        headers = {"Link": '<https://example.com/wp-json/>; rel="https://api.w.org/"'}
        body = (
            '<meta name="generator" content="WordPress 6.4.2" />'
            '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
        )
        cookies = ["wordpress_logged_in"]
        scan = tf.detect_technologies_from_content(headers, cookies, body)
        assert "WordPress" in scan
        assert scan["WordPress"]["version"] == "6.4.2"
        assert tf._confidence_for_score(scan["WordPress"]["score"]) == tf.CONFIDENCE_HIGH

    def test_drupal_header_and_cookie(self):
        headers = {"X-Generator": "Drupal 10"}
        cookies = ["SESS" + "a" * 32]
        scan = tf.detect_technologies_from_content(headers, cookies, "")
        assert "Drupal" in scan
        assert tf._confidence_for_score(scan["Drupal"]["score"]) == tf.CONFIDENCE_HIGH

    def test_joomla_via_meta_generator_only(self):
        body = '<meta name="generator" content="Joomla! 4.2 - Open Source Content Management" />'
        scan = tf.detect_technologies_from_content({}, [], body)
        assert "Joomla" in scan
        assert scan["Joomla"]["category"] == tf.CATEGORY_CMS

    def test_magento_via_html_markers(self):
        body = '<script src="/skin/frontend/rwd/default/js/main.js"></script>Mage.Cookies.set'
        scan = tf.detect_technologies_from_content({}, [], body)
        assert "Magento" in scan

    def test_django_two_weak_cookies_reach_medium(self):
        scan = tf.detect_technologies_from_content({}, ["csrftoken", "sessionid"], "")
        assert "Django" in scan
        assert tf._confidence_for_score(scan["Django"]["score"]) == tf.CONFIDENCE_MEDIUM

    def test_django_single_weak_cookie_stays_low(self):
        scan = tf.detect_technologies_from_content({}, ["sessionid"], "")
        assert tf._confidence_for_score(scan["Django"]["score"]) == tf.CONFIDENCE_LOW

    def test_flask_werkzeug_header_extracts_version(self):
        headers = {"Server": "Werkzeug/2.2.3 Python/3.11.4"}
        scan = tf.detect_technologies_from_content(headers, [], "")
        assert "Flask" in scan
        assert scan["Flask"]["version"] == "2.2.3"

    def test_fastapi_uvicorn_header_weak_alone(self):
        scan = tf.detect_technologies_from_content({"Server": "uvicorn"}, [], "")
        assert "FastAPI" in scan
        assert tf._confidence_for_score(scan["FastAPI"]["score"]) == tf.CONFIDENCE_LOW

    def test_laravel_two_cookies(self):
        scan = tf.detect_technologies_from_content({}, ["laravel_session", "XSRF-TOKEN"], "")
        assert "Laravel" in scan
        assert tf._confidence_for_score(scan["Laravel"]["score"]) == tf.CONFIDENCE_MEDIUM

    def test_express_powered_by_header(self):
        scan = tf.detect_technologies_from_content({"X-Powered-By": "Express"}, [], "")
        assert "Express" in scan
        assert tf._confidence_for_score(scan["Express"]["score"]) == tf.CONFIDENCE_MEDIUM

    def test_nextjs_header_and_html(self):
        headers = {"X-Powered-By": "Next.js"}
        body = '<script>window.__NEXT_DATA__ = {}</script><script src="/_next/static/chunk.js"></script>'
        scan = tf.detect_technologies_from_content(headers, [], body)
        assert "Next.js" in scan
        assert tf._confidence_for_score(scan["Next.js"]["score"]) == tf.CONFIDENCE_HIGH

    def test_react_generic_markers_stay_low_confidence(self):
        body = '<div id="root" data-reactroot=""></div>'
        scan = tf.detect_technologies_from_content({}, [], body)
        assert "React" in scan
        assert tf._confidence_for_score(scan["React"]["score"]) == tf.CONFIDENCE_LOW

    def test_angular_version_attribute_extracted(self):
        body = '<app-root ng-version="15.2.9"></app-root>'
        scan = tf.detect_technologies_from_content({}, [], body)
        assert "Angular" in scan
        assert scan["Angular"]["version"] == "15.2.9"

    def test_vue_markers(self):
        body = '<div id="app" data-v-1234abcd></div>'
        scan = tf.detect_technologies_from_content({}, [], body)
        assert "Vue" in scan

    def test_no_signals_empty_scan(self):
        assert tf.detect_technologies_from_content({}, [], "<html><body>hello</body></html>") == {}

    def test_ambiguous_multiple_cms_markers_both_preserved(self):
        """Conflict preservation (context.md §8): don't silently pick one when signals overlap."""
        body = (
            '<meta name="generator" content="WordPress 6.4" />'
            '<meta name="generator" content="Drupal 10" />'
        )
        scan = tf.detect_technologies_from_content({}, [], body)
        assert "WordPress" in scan
        assert "Drupal" in scan

    def test_malformed_html_does_not_raise(self):
        body = "<meta name=generator content=WordPress <<<<broken>>>"
        # Should not raise; may or may not match depending on quoting, but must not throw.
        tf.detect_technologies_from_content({}, [], body)

    def test_none_body_handled(self):
        scan = tf.detect_technologies_from_content({}, [], None)
        assert isinstance(scan, dict)


# ---------------------------------------------------------------------------
# _merge_scan_maps
# ---------------------------------------------------------------------------

class TestMergeScanMaps:
    def test_unions_evidence_and_sums_score(self):
        a = {"WordPress": {"category": "cms", "evidence": ["e1"], "score": 2, "version": None}}
        b = {"WordPress": {"category": "cms", "evidence": ["e2"], "score": 1, "version": "6.4"}}
        merged = tf._merge_scan_maps(a, b)
        assert merged["WordPress"]["evidence"] == ["e1", "e2"]
        assert merged["WordPress"]["score"] == 3
        assert merged["WordPress"]["version"] == "6.4"

    def test_disjoint_technologies_both_kept(self):
        a = {"WordPress": {"category": "cms", "evidence": ["e1"], "score": 2, "version": None}}
        b = {"Nginx": {"category": "server", "evidence": ["e2"], "score": 2, "version": "1.18.0"}}
        merged = tf._merge_scan_maps(a, b)
        assert set(merged.keys()) == {"WordPress", "Nginx"}

    def test_empty_maps(self):
        assert tf._merge_scan_maps({}, {}) == {}

    def test_first_nonnull_version_wins(self):
        a = {"X": {"category": "cms", "evidence": [], "score": 1, "version": "1.0"}}
        b = {"X": {"category": "cms", "evidence": [], "score": 1, "version": "2.0"}}
        merged = tf._merge_scan_maps(a, b)
        assert merged["X"]["version"] == "1.0"


# ---------------------------------------------------------------------------
# _confidence_for_score / _finalize_detections
# ---------------------------------------------------------------------------

class TestConfidenceScoring:
    @pytest.mark.parametrize("score,expected", [
        (1, tf.CONFIDENCE_LOW), (2, tf.CONFIDENCE_MEDIUM), (3, tf.CONFIDENCE_HIGH), (10, tf.CONFIDENCE_HIGH),
    ])
    def test_thresholds(self, score, expected):
        assert tf._confidence_for_score(score) == expected

    def test_finalize_detections_skips_zero_score(self):
        scan = {"X": {"category": "cms", "evidence": [], "score": 0, "version": None}}
        assert tf._finalize_detections(scan, SAFE_URL) == []

    def test_finalize_detections_sorted_by_name(self):
        scan = {
            "Zebra": {"category": "cms", "evidence": ["e"], "score": 1, "version": None},
            "Alpha": {"category": "cms", "evidence": ["e"], "score": 1, "version": None},
        }
        result = tf._finalize_detections(scan, SAFE_URL)
        assert [d["technology"] for d in result] == ["Alpha", "Zebra"]

    def test_finalize_detections_preserves_confirmed_url_without_splitting_asset_identity(self):
        # `url` is the asset key surface_mapper.py builds a technology asset
        # from (technology:<url>:<name>). Emitting the corroborating probe path
        # there split one WordPress install into two technology assets — and so
        # into two duplicate `technology_specific_enumeration` opportunities —
        # depending on whether known-path corroboration happened to run. The
        # corroborating URL is evidence and is preserved as such.
        scan = {"WordPress": {"category": "cms", "evidence": ["e"], "score": 2, "version": None,
                               "confirmed_url": "https://example.com/wp-login.php"}}
        result = tf._finalize_detections(scan, SAFE_URL)
        assert result[0]["url"] == SAFE_URL
        assert result[0]["corroborating_urls"] == ["https://example.com/wp-login.php"]

    def test_finalize_detections_falls_back_to_base_url(self):
        scan = {"WordPress": {"category": "cms", "evidence": ["e"], "score": 2, "version": None}}
        result = tf._finalize_detections(scan, SAFE_URL)
        assert result[0]["url"] == SAFE_URL


# ---------------------------------------------------------------------------
# 5. Favicon hashing
# ---------------------------------------------------------------------------

class TestFavicon:
    def test_compute_favicon_hash_success(self):
        content = b"\x00\x00\x01\x00fake-ico-bytes"
        resp = _fake_response(status_code=200, headers={"Content-Type": "image/x-icon"}, body=content)
        with mock.patch("requests.get", return_value=resp):
            result = tf.compute_favicon_hash(SAFE_URL)
        assert result["status"] == "found"
        assert result["md5"] == __import__("hashlib").md5(content).hexdigest()
        assert result["sha256"] == __import__("hashlib").sha256(content).hexdigest()
        assert result["byte_length"] == len(content)

    def test_compute_favicon_hash_404(self):
        resp = _fake_response(status_code=404, body=b"")
        with mock.patch("requests.get", return_value=resp):
            result = tf.compute_favicon_hash(SAFE_URL)
        assert result["status"] == "not_found"
        assert result["md5"] is None

    def test_compute_favicon_hash_empty_200(self):
        resp = _fake_response(status_code=200, body=b"")
        with mock.patch("requests.get", return_value=resp):
            result = tf.compute_favicon_hash(SAFE_URL)
        assert result["status"] == "empty"

    def test_compute_favicon_hash_network_error(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = tf.compute_favicon_hash(SAFE_URL)
        assert result["status"] == "error"
        assert result["md5"] is None

    def test_match_favicon_hash_by_md5(self):
        favicon_result = {"md5": "abc123", "sha256": "def456"}
        signatures = {"abc123": {"technology": "phpMyAdmin", "category": tf.CATEGORY_CMS}}
        match = tf.match_favicon_hash(favicon_result, signatures)
        assert match["technology"] == "phpMyAdmin"
        assert match["score"] == tf._SCORE_STRONG

    def test_match_favicon_hash_by_sha256(self):
        favicon_result = {"md5": "abc123", "sha256": "def456"}
        signatures = {"def456": {"technology": "phpMyAdmin", "category": tf.CATEGORY_CMS}}
        match = tf.match_favicon_hash(favicon_result, signatures)
        assert match is not None

    def test_match_favicon_hash_no_signatures(self):
        assert tf.match_favicon_hash({"md5": "abc"}, None) is None

    def test_match_favicon_hash_no_match(self):
        assert tf.match_favicon_hash({"md5": "abc", "sha256": "def"}, {"zzz": {}}) is None

    def test_match_favicon_hash_never_invents_version_when_absent(self):
        signatures = {"abc123": {"technology": "X", "category": tf.CATEGORY_CMS}}
        match = tf.match_favicon_hash({"md5": "abc123", "sha256": "y"}, signatures)
        assert match["version"] is None


# ---------------------------------------------------------------------------
# 6. probe_known_paths
# ---------------------------------------------------------------------------

class TestProbeKnownPaths:
    def test_marker_match_is_strong_evidence(self):
        resp = _fake_response(status_code=200, body=b"<form>user_login field here</form>")
        with mock.patch("requests.get", return_value=resp):
            result = tf.probe_known_paths(SAFE_URL, ["WordPress"])
        assert "WordPress" in result
        assert result["WordPress"]["score"] >= tf._SCORE_STRONG
        assert result["WordPress"]["confirmed_url"].endswith("wp-login.php")

    def test_no_marker_configured_is_weak_evidence(self):
        resp = _fake_response(status_code=200, body=b"some admin content")
        with mock.patch("requests.get", return_value=resp):
            result = tf.probe_known_paths(SAFE_URL, ["Magento"])
        assert "Magento" in result
        # Magento's known_paths include (errors/report.php, None) and (admin/, None)
        assert result["Magento"]["score"] >= tf._SCORE_WEAK

    def test_404_contributes_no_evidence(self):
        resp = _fake_response(status_code=404, body=b"not found")
        with mock.patch("requests.get", return_value=resp):
            result = tf.probe_known_paths(SAFE_URL, ["WordPress"])
        assert result == {}

    def test_marker_absent_on_200_contributes_no_evidence(self):
        resp = _fake_response(status_code=200, body=b"totally unrelated content")
        with mock.patch("requests.get", return_value=resp):
            result = tf.probe_known_paths(SAFE_URL, ["WordPress"])
        # wp-login.php requires "user_login" marker; xmlrpc.php requires its own marker;
        # wp-json/ requires '"name"' — none present, so nothing should match.
        assert result == {}

    def test_technology_with_no_known_paths_skipped(self):
        assert tf.probe_known_paths(SAFE_URL, ["Django"]) == {}

    def test_unknown_technology_name_skipped(self):
        assert tf.probe_known_paths(SAFE_URL, ["NotARealTech"]) == {}

    def test_probe_budget_respected(self):
        resp = _fake_response(status_code=404, body=b"")
        call_count = {"n": 0}

        def _get(*args, **kwargs):
            call_count["n"] += 1
            return resp

        with mock.patch("requests.get", side_effect=_get):
            tf.probe_known_paths(SAFE_URL, ["WordPress", "Drupal", "Joomla", "Magento"], max_probes=2)
        assert call_count["n"] <= 2

    def test_access_restricted_status_skipped(self):
        resp = _fake_response(status_code=403, body=b"user_login")
        with mock.patch("requests.get", return_value=resp):
            result = tf.probe_known_paths(SAFE_URL, ["WordPress"])
        assert result == {}


# ---------------------------------------------------------------------------
# fetch_error_page_sample
# ---------------------------------------------------------------------------

class TestFetchErrorPageSample:
    def test_fetches_a_random_nonexistent_path(self):
        resp = _fake_response(status_code=404, body=b"not found")
        captured_urls = []

        def _get(url, **kwargs):
            captured_urls.append(url)
            return resp

        with mock.patch("requests.get", side_effect=_get):
            result = tf.fetch_error_page_sample("https://example.com")
        assert result["status"] == "found"
        assert captured_urls[0].startswith("https://example.com/reconhound-tech-probe-")

    def test_network_failure_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout("t")):
            result = tf.fetch_error_page_sample("https://example.com")
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# 8. build_technology_summary
# ---------------------------------------------------------------------------

class TestBuildTechnologySummary:
    def test_buckets_by_category(self):
        detections = [
            {"technology": "WordPress", "category": tf.CATEGORY_CMS, "version": "6.4", "evidence": [], "confidence": "HIGH", "url": SAFE_URL},
            {"technology": "Nginx", "category": tf.CATEGORY_SERVER, "version": "1.18.0", "evidence": [], "confidence": "MEDIUM", "url": SAFE_URL},
            {"technology": "Cloudflare", "category": tf.CATEGORY_WAF, "version": None, "evidence": [], "confidence": "MEDIUM", "url": SAFE_URL},
        ]
        summary = tf.build_technology_summary(detections)
        assert summary["cms"] == ["WordPress"]
        assert summary["servers"] == ["Nginx"]
        assert summary["wafs"] == ["Cloudflare"]
        assert summary["frameworks"] == []
        assert len(summary["detections"]) == 3
        json.dumps(summary)

    def test_empty_detections(self):
        summary = tf.build_technology_summary([])
        assert summary == {"cms": [], "frameworks": [], "servers": [], "wafs": [], "detections": []}


# ---------------------------------------------------------------------------
# Downstream trigger behavior: technology_summary must be directly
# consumable by endpoint_discovery.py's ALREADY-BUILT `technology` param.
# ---------------------------------------------------------------------------

class TestDownstreamIntegrationWithEndpointDiscovery:
    def test_wordpress_summary_selects_wordpress_wordlist(self):
        summary = tf.build_technology_summary([
            {"technology": "WordPress", "category": tf.CATEGORY_CMS, "version": "6.4",
             "evidence": [], "confidence": "HIGH", "url": SAFE_URL},
        ])
        selected = ed.select_wordlists_for_technology(summary)
        assert ("wordpress_paths.txt", "wordpress") in selected

    def test_laravel_summary_selects_laravel_wordlist(self):
        summary = tf.build_technology_summary([
            {"technology": "Laravel", "category": tf.CATEGORY_FRAMEWORK, "version": None,
             "evidence": [], "confidence": "MEDIUM", "url": SAFE_URL},
        ])
        selected = ed.select_wordlists_for_technology(summary)
        assert ("laravel_paths.txt", "laravel") in selected

    def test_django_summary_selects_django_wordlist(self):
        summary = tf.build_technology_summary([
            {"technology": "Django", "category": tf.CATEGORY_FRAMEWORK, "version": None,
             "evidence": [], "confidence": "MEDIUM", "url": SAFE_URL},
        ])
        selected = ed.select_wordlists_for_technology(summary)
        assert ("django_paths.txt", "django") in selected

    def test_unrelated_technology_selects_nothing(self):
        summary = tf.build_technology_summary([
            {"technology": "Nginx", "category": tf.CATEGORY_SERVER, "version": "1.18.0",
             "evidence": [], "confidence": "MEDIUM", "url": SAFE_URL},
        ])
        assert ed.select_wordlists_for_technology(summary) == []


# ---------------------------------------------------------------------------
# 9. build_recommended_actions
# ---------------------------------------------------------------------------

class TestBuildRecommendedActions:
    def test_high_confidence_cms_produces_action_with_wordlist_note(self):
        detections = [{"technology": "WordPress", "category": tf.CATEGORY_CMS, "version": "6.4",
                       "evidence": ["e1", "e2"], "confidence": tf.CONFIDENCE_HIGH, "url": SAFE_URL}]
        actions = tf.build_recommended_actions(detections, SAFE_TARGET)
        assert len(actions) == 1
        assert actions[0]["technology"] == "WordPress"
        assert actions[0]["status"] == "queued_for_orchestrator"
        assert "wordlist" in actions[0]["reason"].lower()
        assert "[REASON:" in actions[0]["justification"]

    def test_technology_without_wordlist_gets_generic_note(self):
        detections = [{"technology": "FastAPI", "category": tf.CATEGORY_FRAMEWORK, "version": None,
                       "evidence": ["e1", "e2"], "confidence": tf.CONFIDENCE_HIGH, "url": SAFE_URL}]
        actions = tf.build_recommended_actions(detections, SAFE_TARGET)
        assert len(actions) == 1
        assert "no dedicated wordlist" in actions[0]["reason"].lower()

    def test_low_confidence_excluded(self):
        detections = [{"technology": "React", "category": tf.CATEGORY_FRAMEWORK, "version": None,
                       "evidence": ["e1"], "confidence": tf.CONFIDENCE_LOW, "url": SAFE_URL}]
        assert tf.build_recommended_actions(detections, SAFE_TARGET) == []

    def test_server_and_waf_categories_excluded(self):
        detections = [
            {"technology": "Nginx", "category": tf.CATEGORY_SERVER, "version": "1.18.0",
             "evidence": ["e"], "confidence": tf.CONFIDENCE_HIGH, "url": SAFE_URL},
            {"technology": "Cloudflare", "category": tf.CATEGORY_WAF, "version": None,
             "evidence": ["e"], "confidence": tf.CONFIDENCE_HIGH, "url": SAFE_URL},
        ]
        assert tf.build_recommended_actions(detections, SAFE_TARGET) == []

    def test_actions_are_json_serializable(self):
        detections = [{"technology": "Django", "category": tf.CATEGORY_FRAMEWORK, "version": None,
                       "evidence": ["e1", "e2"], "confidence": tf.CONFIDENCE_HIGH, "url": SAFE_URL}]
        json.dumps(tf.build_recommended_actions(detections, SAFE_TARGET))


# ---------------------------------------------------------------------------
# persist_no_match_findings (negative-result memory)
# ---------------------------------------------------------------------------

class TestPersistNoMatchFindings:
    def test_persists_one_per_missing_category(self, tmp_path):
        store = tf.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        errors = tf.persist_no_match_findings({tf.CATEGORY_CMS}, SAFE_TARGET, SAFE_URL, store)
        assert errors == []
        records = store.all()
        types_and_categories = {(r["type"], r["value"]["category"]) for r in records}
        assert (
            "tech_fingerprint_checked_no_match", tf.CATEGORY_FRAMEWORK,
        ) in types_and_categories
        assert (
            "tech_fingerprint_checked_no_match", tf.CATEGORY_SERVER,
        ) in types_and_categories
        assert (
            "tech_fingerprint_checked_no_match", tf.CATEGORY_WAF,
        ) in types_and_categories
        # CMS was found, so no negative-result record for it.
        assert not any(r["value"]["category"] == tf.CATEGORY_CMS for r in records)

    def test_all_categories_found_persists_nothing(self, tmp_path):
        store = tf.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        errors = tf.persist_no_match_findings(
            {tf.CATEGORY_CMS, tf.CATEGORY_FRAMEWORK, tf.CATEGORY_SERVER, tf.CATEGORY_WAF},
            SAFE_TARGET, SAFE_URL, store,
        )
        assert errors == []
        assert store.all() == []


# ---------------------------------------------------------------------------
# run_tech_fingerprint — full orchestration
# ---------------------------------------------------------------------------

class TestRunTechFingerprint:
    def _wordpress_response_sequence(self):
        """baseline (wp signals) -> error page (404) -> favicon -> known-path probes."""
        baseline = _fake_response(
            status_code=200,
            headers={"Server": "nginx/1.18.0",
                     "Link": '<https://example.com/wp-json/>; rel="https://api.w.org/"'},
            body=(
                '<meta name="generator" content="WordPress 6.4.2" />'
                '<link href="/wp-content/themes/x/style.css">'
            ).encode(),
            set_cookie_headers=["wordpress_logged_in=abc"],
        )
        error_page = _fake_response(status_code=404, body=b"not found")
        favicon = _fake_response(status_code=200, body=b"\x00\x00icon-bytes")
        known_path_hit = _fake_response(status_code=200, body=b"user_login field here")
        known_path_miss = _fake_response(status_code=404, body=b"")
        # requests.get call order inside run_tech_fingerprint:
        # 1 baseline, 2 error-page probe, 3 favicon, 4..N known-path probes
        return [baseline, error_page, favicon] + [known_path_hit, known_path_miss, known_path_miss]

    def test_full_run_persists_and_summarizes_wordpress(self, tmp_path):
        responses = self._wordpress_response_sequence()
        output_dir = tmp_path / "output"
        with mock.patch("requests.get", side_effect=responses):
            result = tf.run_tech_fingerprint(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))

        assert result["fetch_status"] == "found"
        assert "WordPress" in result["technology_summary"]["cms"]
        assert "Nginx" in result["technology_summary"]["servers"]
        assert result["recommended_next_actions"]
        assert result["recommended_next_actions"][0]["technology"] == "WordPress"

        store = tf.PendingAssetsStore(output_dir=str(output_dir))
        records = store.all()
        assert any(r["type"] == "tech_fingerprint_detected" and r["value"]["technology"] == "WordPress" for r in records)
        json.dumps(result)

    def test_baseline_fetch_failure_returns_early(self, tmp_path):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = tf.run_tech_fingerprint(SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert result["fetch_status"] == "error"
        assert result["technology_summary"] == {"cms": [], "frameworks": [], "servers": [], "wafs": [], "detections": []}
        assert result["errors"]

    def test_malformed_empty_baseline_body(self, tmp_path):
        baseline = _fake_response(status_code=200, headers={}, body=b"")
        error_page = _fake_response(status_code=404, body=b"")
        favicon = _fake_response(status_code=200, body=b"")
        with mock.patch("requests.get", side_effect=[baseline, error_page, favicon]):
            result = tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                probe_known_paths_enabled=False,
            )
        assert result["fetch_status"] == "found"
        assert result["technology_summary"]["detections"] == []
        json.dumps(result)

    def test_scope_enforcement_raises(self, tmp_path):
        with pytest.raises(tf.ScopeError):
            tf.run_tech_fingerprint("https://evil.com/", target=SAFE_TARGET, output_dir=str(tmp_path / "output"))

    def test_check_error_page_false_skips_extra_fetch(self, tmp_path):
        baseline = _fake_response(status_code=200, headers={}, body=b"<html></html>")
        favicon = _fake_response(status_code=200, body=b"icon")
        with mock.patch("requests.get", side_effect=[baseline, favicon]) as mocked:
            tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                check_error_page=False, probe_known_paths_enabled=False,
            )
        assert mocked.call_count == 2  # baseline + favicon only

    def test_check_favicon_false_skips_favicon_fetch(self, tmp_path):
        baseline = _fake_response(status_code=200, headers={}, body=b"<html></html>")
        error_page = _fake_response(status_code=404, body=b"")
        with mock.patch("requests.get", side_effect=[baseline, error_page]) as mocked:
            tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                check_favicon=False, probe_known_paths_enabled=False,
            )
        assert mocked.call_count == 2  # baseline + error page only

    def test_all_optional_stages_disabled_only_baseline_fetched(self, tmp_path):
        baseline = _fake_response(status_code=200, headers={}, body=b"<html></html>")
        with mock.patch("requests.get", side_effect=[baseline]) as mocked:
            result = tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                check_error_page=False, check_favicon=False, probe_known_paths_enabled=False,
            )
        assert mocked.call_count == 1
        assert result["fetch_status"] == "found"

    def test_favicon_signature_match_escalates_confidence(self, tmp_path):
        baseline = _fake_response(
            status_code=200,
            body='<meta name="generator" content="Joomla! 4.2" />'.encode(),
        )
        error_page = _fake_response(status_code=404, body=b"")
        favicon_bytes = b"joomla-icon-bytes"
        favicon = _fake_response(status_code=200, body=favicon_bytes)
        import hashlib
        md5_hex = hashlib.md5(favicon_bytes).hexdigest()
        signatures = {md5_hex: {"technology": "Joomla", "category": tf.CATEGORY_CMS}}

        with mock.patch("requests.get", side_effect=[baseline, error_page, favicon]):
            result = tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                probe_known_paths_enabled=False, favicon_signatures=signatures,
            )
        joomla = next(d for d in result["technology_summary"]["detections"] if d["technology"] == "Joomla")
        assert joomla["confidence"] == tf.CONFIDENCE_HIGH  # meta(strong=2) + favicon(strong=2) = 4

    def test_negative_result_memory_persisted_for_missing_categories(self, tmp_path):
        baseline = _fake_response(status_code=200, headers={}, body=b"<html>nothing here</html>")
        error_page = _fake_response(status_code=404, body=b"")
        favicon = _fake_response(status_code=404, body=b"")
        output_dir = tmp_path / "output"
        with mock.patch("requests.get", side_effect=[baseline, error_page, favicon]):
            tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir), probe_known_paths_enabled=False,
            )
        store = tf.PendingAssetsStore(output_dir=str(output_dir))
        neg_types = {r["value"]["category"] for r in store.all() if r["type"] == "tech_fingerprint_checked_no_match"}
        assert neg_types == {tf.CATEGORY_CMS, tf.CATEGORY_FRAMEWORK, tf.CATEGORY_SERVER, tf.CATEGORY_WAF}

    def test_output_is_json_serializable_end_to_end(self, tmp_path):
        responses = self._wordpress_response_sequence()
        with mock.patch("requests.get", side_effect=responses):
            result = tf.run_tech_fingerprint(SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        json.dumps(result)


# ===========================================================================
# Forensic-audit regression suite.
#
# Every test below pins a defect that was reproduced against this module and
# then fixed. Each one fails on the pre-audit implementation.
# ===========================================================================

import time as _time


def _resp_seq(*responses):
    """requests.get side_effect that replays a sequence and then repeats the last."""
    state = {"i": 0}

    def _get(*args, **kwargs):
        i = min(state["i"], len(responses) - 1)
        state["i"] += 1
        return responses[i]

    return _get


# ---------------------------------------------------------------------------
# D1 — catastrophic backtracking in the <meta generator> scan (CPU DoS)
# ---------------------------------------------------------------------------

class TestMetaGeneratorPerformanceAndParsing:
    def test_adversarial_meta_body_does_not_blow_up(self):
        # Pre-fix: `<meta[^>]+name=...` backtracked quadratically over a body
        # of repeated "<meta " tokens — 21.3 s for one 128 KB body, ~50 s for
        # a full run, from a single HTTP response.
        body = ("<meta " * (tf.DEFAULT_MAX_BODY_BYTES // 6))[: tf.DEFAULT_MAX_BODY_BYTES]
        start = _time.perf_counter()
        tf.detect_technologies_from_content({}, [], body, "baseline_response")
        assert _time.perf_counter() - start < 2.0

    def test_unterminated_and_giant_tags_are_bounded(self):
        for body in ("<" + "meta name=x " * 20000, "<meta " + "a=1 " * 30000 + ">",
                      '<meta name="generator" content="x' * 5000):
            start = _time.perf_counter()
            tf.extract_generator_declarations(body)
            assert _time.perf_counter() - start < 1.0

    def test_generator_content_before_name_is_detected(self):
        # Pre-fix the regex required content= to follow name=, so this common
        # (and equally valid) attribute order produced no detection at all.
        content, version = tf._extract_meta_generator(
            '<meta content="WordPress 6.4.2" name="generator">', "WordPress")
        assert content == "WordPress 6.4.2"
        assert version == "6.4.2"

    def test_unquoted_and_uppercase_attributes(self):
        assert tf.extract_generator_declarations("<meta name=generator content=Drupal>") == ["Drupal"]
        assert tf.extract_generator_declarations(
            '<meta NAME="generator" CONTENT="WordPress 6.4">') == ["WordPress 6.4"]

    def test_non_generator_meta_is_ignored(self):
        assert tf.extract_generator_declarations('<meta name="description" content="WordPress 9.9">') == []


# ---------------------------------------------------------------------------
# D2 — invented / implausible versions
# ---------------------------------------------------------------------------

class TestVersionPrecision:
    def test_prose_number_is_not_a_version(self):
        # Pre-fix this reported WordPress version "2003" and handed it to
        # vuln_intel.py as a fact to match CVEs against.
        content, version = tf._extract_meta_generator(
            '<meta name="generator" content="Powered by WordPress since 2003">', "WordPress")
        assert content is not None
        assert version is None

    @pytest.mark.parametrize("declared,product,expected", [
        ("WordPress 6.4.2", "WordPress", "6.4.2"),
        ("WordPress v6.4", "WordPress", "6.4"),
        ("Drupal 10 (https://www.drupal.org)", "Drupal", "10"),
        ("Drupal 7 (http://drupal.org)", "Drupal", "7"),
        ("Joomla! 4.2.3", "Joomla", "4.2.3"),
        ("Joomla! - Open Source Content Management", "Joomla", None),
        ("WordPress", "WordPress", None),
    ])
    def test_real_generator_strings(self, declared, product, expected):
        _, version = tf._extract_meta_generator(
            f'<meta name="generator" content="{declared}">', product)
        assert version == expected

    @pytest.mark.parametrize("token", ["99999999999999.1.1", "1.2.3.4.5", "a.b", "", None, "..."])
    def test_implausible_versions_rejected(self, token):
        assert tf._plausible_version(token) is None

    @pytest.mark.parametrize("token", ["1", "1.2", "1.18.0", "10.0.19041.1"])
    def test_plausible_versions_accepted(self, token):
        assert tf._plausible_version(token) == token

    def test_target_supplied_ng_version_is_not_reproduced(self):
        scan = tf.detect_technologies_from_content({}, [], '<div ng-version="99999999999999.1.1">', "b")
        assert scan["Angular"]["version"] is None
        assert tf.detect_technologies_from_content(
            {}, [], '<div ng-version="17.0.8">', "b")["Angular"]["version"] == "17.0.8"

    def test_server_header_version_is_plausibility_checked(self):
        assert tf.detect_servers({"Server": "nginx/1.18.0"})["Nginx"]["version"] == "1.18.0"
        assert tf.detect_servers({"Server": "nginx/99999999.1.1.1.1"})["Nginx"]["version"] is None


# ---------------------------------------------------------------------------
# D3 — confidence inflation from repeated (non-independent) evidence
# ---------------------------------------------------------------------------

class TestSignalKeyedConfidence:
    def test_same_marker_on_error_page_does_not_raise_confidence(self):
        # A 404 page sharing the homepage's theme (or an SPA catch-all echoing
        # the homepage) made one weak marker score twice and reach MEDIUM.
        html = '<html><link href="/wp-content/themes/x/style.css"></html>'
        base = tf.detect_technologies_from_content({}, [], html, "baseline_response")
        err = tf.detect_technologies_from_content({}, [], html, "error_page_response")
        merged = tf._merge_scan_maps(base, err)
        assert merged["WordPress"]["score"] == base["WordPress"]["score"]
        assert tf._confidence_for_score(merged["WordPress"]["score"]) == tf.CONFIDENCE_LOW
        # Evidence from both sources is still preserved in full.
        assert len(merged["WordPress"]["evidence"]) == 2

    def test_distinct_markers_still_converge(self):
        html = '<html>wp-content/ wp-includes/ wp-json</html>'
        scan = tf.detect_technologies_from_content({}, [], html, "baseline_response")
        assert tf._confidence_for_score(scan["WordPress"]["score"]) == tf.CONFIDENCE_HIGH

    def test_error_page_only_signal_still_adds(self):
        base = tf.detect_technologies_from_content({}, [], "<html>nothing</html>", "baseline_response")
        err = tf.detect_technologies_from_content(
            {}, [], "<html>Whoops, looks like something went wrong</html>", "error_page_response")
        merged = tf._merge_scan_maps(base, err)
        assert "Laravel" in merged and merged["Laravel"]["score"] == tf._SCORE_WEAK

    def test_many_cookies_matching_one_pattern_score_once(self):
        # Pre-fix: 5 WordPress cookies scored 5 (HIGH); 100 scored 100 and
        # produced 100 persisted evidence strings.
        names = tf.parse_cookie_names([f"wordpress_{i}=v" for i in range(100)])
        scan = tf.detect_technologies_from_content({}, names, "", "baseline_response")
        assert scan["WordPress"]["score"] == tf._SCORE_WEAK
        assert len(scan["WordPress"]["evidence"]) == 1
        assert "+95 more" in scan["WordPress"]["evidence"][0]

    def test_two_distinct_cookie_patterns_reach_medium(self):
        names = tf.parse_cookie_names(["wordpress_logged_in=a", "wp-settings-1=b"])
        scan = tf.detect_technologies_from_content({}, names, "", "baseline_response")
        assert tf._confidence_for_score(scan["WordPress"]["score"]) == tf.CONFIDENCE_MEDIUM

    def test_merge_of_unkeyed_records_keeps_additive_behaviour(self):
        a = {"X": {"category": "cms", "evidence": ["a"], "score": 1, "version": None}}
        b = {"X": {"category": "cms", "evidence": ["b"], "score": 2, "version": None}}
        assert tf._merge_scan_maps(a, b)["X"]["score"] == 3

    def test_merge_tolerates_records_without_category(self):
        assert tf._merge_scan_maps({"X": {"evidence": ["e"], "score": 1}})["X"]["category"] is None


# ---------------------------------------------------------------------------
# D4 — false positives from over-broad signatures
# ---------------------------------------------------------------------------

class TestFalsePositiveHardening:
    @pytest.mark.parametrize("body", [
        '<div class="training-app">',            # "ng-app" substring of a word
        '<script>var x = "ng-app"</script>',     # marker inside script text
        'we use react-dom in our docs',          # package mentioned in prose
        '{"attrs": {"data-v-model": true}}',     # JSON attribute, not Vue scoping
    ])
    def test_prose_and_json_do_not_produce_client_framework_detections(self, body):
        assert tf.detect_technologies_from_content({}, [], body, "b") == {}

    @pytest.mark.parametrize("body,tech", [
        ('<html ng-app="myApp">', "Angular"),
        ('<script src="/static/react-dom.production.min.js">', "React"),
        ('<div data-v-7ba5bd90>', "Vue"),
        ('<div data-reactroot>', "React"),
    ])
    def test_genuine_client_framework_markers_still_match(self, body, tech):
        assert tech in tf.detect_technologies_from_content({}, [], body, "b")

    def test_apache_coyote_is_not_apache(self):
        # Apache-Coyote is Tomcat's HTTP connector, not the Apache HTTP server.
        assert tf.detect_servers({"Server": "Apache-Coyote/1.1"}) == {}

    def test_real_apache_and_nginx_still_match(self):
        assert "Apache" in tf.detect_servers({"Server": "Apache/2.4.41 (Ubuntu)"})
        assert "Nginx" in tf.detect_servers({"Server": "nginx"})
        assert "Microsoft IIS" in tf.detect_servers({"Server": "Microsoft-IIS/10.0"})

    def test_waf_cookie_markers_match_names_not_values(self):
        # Pre-fix the marker was searched in the whole raw Set-Cookie string,
        # so any cookie *value* containing "akamai"/"ts01" produced a WAF hit.
        assert tf.detect_wafs({}, ["pref=my-akamai-favourite-thing"], "") == {}
        assert tf.detect_wafs({}, ["sid=ts01abcdef"], "") == {}

    def test_waf_cookie_names_still_match(self):
        assert "Cloudflare" in tf.detect_wafs({}, ["__cfduid=abc; Path=/"], "")
        assert "F5" in tf.detect_wafs({}, ["BIGipServerpool=1.2.3"], "")
        assert "Imperva" in tf.detect_wafs({}, ["incap_ses_123_456=x"], "")


# ---------------------------------------------------------------------------
# D5 — known-path corroboration on catch-all / soft-404 origins
# ---------------------------------------------------------------------------

class TestKnownPathSoft404Awareness:
    def test_catch_all_origin_suppresses_marker_less_corroboration(self):
        # An origin that answers every path with 200 makes a marker-less 200
        # meaningless; pre-fix each such path added weak evidence, taking a
        # soft-404 site with two generic markers to HIGH.
        soft = {"status": "found", "status_code": 200, "body": "<html>App shell</html>"}
        resp = _fake_response(status_code=200, body=b"some admin content")
        with mock.patch("requests.get", return_value=resp):
            assert tf.probe_known_paths(SAFE_URL, ["Magento"], soft_404=soft) == {}

    def test_body_identical_to_catch_all_control_contributes_nothing(self):
        shell = "<html>App user_login shell</html>"
        soft = {"status": "found", "status_code": 200, "body": shell}
        resp = _fake_response(status_code=200, body=shell.encode())
        with mock.patch("requests.get", return_value=resp):
            assert tf.probe_known_paths(SAFE_URL, ["WordPress"], soft_404=soft) == {}

    def test_real_404_control_keeps_corroboration(self):
        soft = {"status": "found", "status_code": 404, "body": "not found"}
        resp = _fake_response(status_code=200, body=b"<form>user_login</form>")
        with mock.patch("requests.get", return_value=resp):
            result = tf.probe_known_paths(SAFE_URL, ["WordPress"], soft_404=soft)
        assert result["WordPress"]["score"] >= tf._SCORE_STRONG

    def test_distinct_content_on_catch_all_origin_still_corroborates(self):
        soft = {"status": "found", "status_code": 200, "body": "<html>App shell</html>"}
        resp = _fake_response(status_code=200, body=b"<form>user_login field</form>")
        with mock.patch("requests.get", return_value=resp):
            result = tf.probe_known_paths(SAFE_URL, ["WordPress"], soft_404=soft)
        assert result["WordPress"]["score"] == tf._SCORE_STRONG

    @pytest.mark.parametrize("junk", [None, {}, {"status": "error"},
                                       {"status": "found", "status_code": None},
                                       {"status": "found", "status_code": "200"}])
    def test_malformed_soft_404_control_falls_back_to_original_behaviour(self, junk):
        resp = _fake_response(status_code=200, body=b"some admin content")
        with mock.patch("requests.get", return_value=resp):
            result = tf.probe_known_paths(SAFE_URL, ["Magento"], soft_404=junk)
        assert "Magento" in result

    def test_repeated_probe_of_the_same_path_scores_once(self):
        resp = _fake_response(status_code=200, body=b"<form>user_login</form>")
        with mock.patch("requests.get", return_value=resp):
            a = tf.probe_known_paths(SAFE_URL, ["WordPress"])
            b = tf.probe_known_paths(SAFE_URL, ["WordPress"])
        merged = tf._merge_scan_maps(a, b)
        assert merged["WordPress"]["score"] == a["WordPress"]["score"]


# ---------------------------------------------------------------------------
# D6 — evidence loss / asset-identity split in the merge
# ---------------------------------------------------------------------------

class TestCorroboratingUrlPreservation:
    def test_merge_preserves_corroborating_urls(self):
        # _merge_scan_maps silently dropped every key it did not copy, so
        # confirmed_url never survived to the output in the real pipeline.
        corr = {"WordPress": {"category": "cms", "evidence": ["e"], "signals": {"path:x": 2},
                               "score": 2, "version": None,
                               "confirmed_url": "https://example.com/wp-login.php"}}
        merged = tf._merge_scan_maps({}, corr)
        assert merged["WordPress"]["corroborating_urls"] == ["https://example.com/wp-login.php"]

    def test_detection_url_is_the_fingerprinted_url_not_the_probe_path(self, tmp_path):
        baseline = _fake_response(
            status_code=200,
            body=b'<html>wp-content/ wp-includes/ wp-json</html>')
        error_page = _fake_response(status_code=404, body=b"nope")
        hit = _fake_response(status_code=200, body=b"<form>user_login</form>")
        with mock.patch("requests.get", side_effect=_resp_seq(baseline, error_page, hit)):
            result = tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "o"), check_favicon=False)
        wp = next(d for d in result["technology_summary"]["detections"] if d["technology"] == "WordPress")
        assert wp["url"] == SAFE_URL
        assert any(u.endswith("wp-login.php") for u in wp["corroborating_urls"])


# ---------------------------------------------------------------------------
# D7 — failure must never become absence (negative-result memory)
# ---------------------------------------------------------------------------

class TestNegativeResultHonesty:
    def _run(self, tmp_path, response, **kwargs):
        with mock.patch("requests.get", return_value=response):
            return tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "o"),
                check_favicon=False, **kwargs)

    @pytest.mark.parametrize("code,body,label", [
        (301, b"", "redirect"),
        (403, b"<html>Attention Required! | Cloudflare</html>", "blocked"),
        (500, b"<html>server error</html>", "server error"),
        (200, b"", "empty body"),
    ])
    def test_non_representative_response_records_no_negative_memory(self, tmp_path, code, body, label):
        headers = {"Location": "https://x/"} if code == 301 else {}
        result = self._run(tmp_path, _fake_response(status_code=code, headers=headers, body=body))
        assert result["negative_result_memory"]["persisted"] is False
        assert result["negative_result_memory"]["reason"]
        store_path = tmp_path / "o" / "pending_assets.json"
        records = json.loads(store_path.read_text()) if store_path.exists() else []
        assert not any(r["type"] == "tech_fingerprint_checked_no_match" for r in records)

    def test_truncated_body_is_not_a_completed_check(self, tmp_path):
        big = b"<html>" + b"x" * (tf.DEFAULT_MAX_BODY_BYTES + 100)
        result = self._run(tmp_path, _fake_response(status_code=200, body=big))
        assert result["body_truncated"] is True
        assert result["negative_result_memory"]["persisted"] is False

    def test_undecodable_body_is_not_a_completed_check(self):
        assessment = tf.assess_response_representativeness({
            "status": "found", "status_code": 200, "headers": {}, "body": "",
            "body_error": "DecodeError: bad gzip"})
        assert assessment["representative"] is False
        assert any("could not be read" in r for r in assessment["reasons"])

    def test_failed_error_page_probe_suppresses_negative_memory(self, tmp_path):
        baseline = _fake_response(status_code=200, body=b"<html>nothing at all</html>")
        with mock.patch("requests.get", side_effect=_resp_seq(
                baseline, requests.exceptions.ConnectionError("refused"))):
            pass
        calls = {"n": 0}

        def _get(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                return baseline
            raise requests.exceptions.ConnectionError("refused")

        with mock.patch("requests.get", side_effect=_get):
            result = tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "o"), check_favicon=False)
        assert result["negative_result_memory"]["persisted"] is False
        assert "error-page" in result["negative_result_memory"]["reason"]

    def test_representative_response_still_records_negative_memory_with_audit_trail(self, tmp_path):
        baseline = _fake_response(status_code=200, headers={"Content-Type": "text/html"},
                                   body=b"<html>nothing here</html>")
        error_page = _fake_response(status_code=404, body=b"")
        with mock.patch("requests.get", side_effect=_resp_seq(baseline, error_page)):
            result = tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "o"),
                check_favicon=False, probe_known_paths_enabled=False)
        assert result["negative_result_memory"]["persisted"] is True
        records = json.loads((tmp_path / "o" / "pending_assets.json").read_text())
        negatives = [r for r in records if r["type"] == "tech_fingerprint_checked_no_match"]
        assert len(negatives) == 4
        observation = negatives[0]["metadata"]["observation"]
        assert observation["status_code"] == 200
        assert observation["content_type"] == "text/html"
        assert observation["body_truncated"] is False
        assert observation["error_page_checked"] is True

    def test_positive_evidence_on_an_error_page_is_still_reported(self, tmp_path):
        # Non-representative for *absence* claims, but a Whoops 500 page is
        # excellent positive evidence and must not be discarded.
        result = self._run(tmp_path, _fake_response(
            status_code=500, body=b"<html>Whoops, looks like something went wrong</html>"))
        assert any(d["technology"] == "Laravel" for d in result["technology_summary"]["detections"])


# ---------------------------------------------------------------------------
# D8 — conflict preservation within one fingerprint
# ---------------------------------------------------------------------------

class TestConflictDetection:
    def _det(self, name, category, confidence):
        return {"technology": name, "category": category, "version": None, "evidence": ["e"],
                "confidence": confidence, "url": SAFE_URL, "corroborating_urls": []}

    def test_multiple_cms_at_medium_plus_is_a_conflict(self):
        conflicts = tf.detect_detection_conflicts([
            self._det("WordPress", tf.CATEGORY_CMS, tf.CONFIDENCE_HIGH),
            self._det("Drupal", tf.CATEGORY_CMS, tf.CONFIDENCE_MEDIUM)])
        assert len(conflicts) == 1
        assert conflicts[0]["technologies"] == ["Drupal", "WordPress"]

    def test_low_confidence_detections_do_not_raise_a_conflict(self):
        assert tf.detect_detection_conflicts([
            self._det("WordPress", tf.CATEGORY_CMS, tf.CONFIDENCE_HIGH),
            self._det("Drupal", tf.CATEGORY_CMS, tf.CONFIDENCE_LOW)]) == []

    def test_single_cms_plus_framework_is_not_a_conflict(self):
        assert tf.detect_detection_conflicts([
            self._det("WordPress", tf.CATEGORY_CMS, tf.CONFIDENCE_HIGH),
            self._det("Express", tf.CATEGORY_FRAMEWORK, tf.CONFIDENCE_HIGH)]) == []

    def test_multiple_servers_is_a_conflict(self):
        conflicts = tf.detect_detection_conflicts([
            self._det("Nginx", tf.CATEGORY_SERVER, tf.CONFIDENCE_MEDIUM),
            self._det("Apache", tf.CATEGORY_SERVER, tf.CONFIDENCE_MEDIUM)])
        assert conflicts[0]["kind"] == "multiple_server_detected"

    def test_conflicts_reach_the_summary_and_every_persisted_finding(self, tmp_path):
        body = (b'<html>wp-content/ wp-includes/ wp-json '
                b'/sites/default/files/ Drupal.settings /sites/all/modules/</html>')
        response = _fake_response(status_code=200, body=body)
        with mock.patch("requests.get", return_value=response):
            result = tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "o"),
                check_favicon=False, probe_known_paths_enabled=False)
        assert result["conflicts"] and result["conflicts"][0]["kind"] == "multiple_cms_detected"
        wp = next(d for d in result["technology_summary"]["detections"] if d["technology"] == "WordPress")
        assert "Drupal" in wp["conflicts_with"]
        records = json.loads((tmp_path / "o" / "pending_assets.json").read_text())
        detected = [r for r in records if r["type"] == "tech_fingerprint_detected"]
        assert all(r["metadata"]["conflicts_with"] for r in detected)
        json.dumps(result)


# ---------------------------------------------------------------------------
# D9 — evidence vs. origin attribution (intermediaries / caches)
# ---------------------------------------------------------------------------

class TestIntermediaryAttribution:
    def test_intermediary_headers_are_reported(self):
        info = tf.detect_intermediaries({"Via": "1.1 varnish", "X-Cache": "HIT", "Age": "120"})
        assert info["observed"] is True
        assert info["cache_status"] == "HIT"
        assert info["age"] == "120"

    def test_no_intermediary_headers_reports_nothing(self):
        info = tf.detect_intermediaries({"Server": "nginx"})
        assert info["observed"] is False and info["note"] is None

    def test_server_detection_behind_a_cdn_is_marked_as_possibly_edge(self, tmp_path):
        response = _fake_response(status_code=200,
                                   headers={"Server": "nginx/1.18.0", "CF-RAY": "abc", "X-Cache": "HIT"},
                                   body=b"<html>plain</html>")
        with mock.patch("requests.get", return_value=response):
            result = tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "o"),
                check_favicon=False, probe_known_paths_enabled=False)
        nginx = next(d for d in result["technology_summary"]["detections"] if d["technology"] == "Nginx")
        assert nginx["observed_through_intermediary"] is True
        assert nginx["cache_status"] == "HIT"
        assert any("may belong to the edge" in e for e in nginx["evidence"])
        # Confidence is unchanged: no invented numeric penalty.
        assert nginx["confidence"] == tf.CONFIDENCE_MEDIUM

    def test_direct_response_carries_no_attribution_note(self, tmp_path):
        response = _fake_response(status_code=200, headers={"Server": "nginx/1.18.0"},
                                   body=b"<html>plain</html>")
        with mock.patch("requests.get", return_value=response):
            result = tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "o"),
                check_favicon=False, probe_known_paths_enabled=False)
        nginx = next(d for d in result["technology_summary"]["detections"] if d["technology"] == "Nginx")
        assert nginx["observed_through_intermediary"] is False
        assert not any("ATTRIBUTION" in e for e in nginx["evidence"])


# ---------------------------------------------------------------------------
# D10 — resource safety
# ---------------------------------------------------------------------------

class _BombRaw:
    """A urllib3-like raw stream whose decoded output dwarfs the requested amount."""

    def __init__(self, ratio=1000, total_decoded=200 * 1024 * 1024):
        self.ratio, self.remaining, self.served = ratio, total_decoded, 0
        self.headers = mock.MagicMock()
        self.headers.getlist.return_value = []

    def read(self, amt, decode_content=True):
        if self.remaining <= 0:
            return b""
        produced = min(amt * self.ratio, self.remaining)
        self.remaining -= produced
        self.served += produced
        return b"A" * produced


class TestResourceSafety:
    def test_compressed_response_read_is_bounded(self):
        # Pre-fix, read(max_body_bytes + 1) on a gzip response decompressed the
        # whole payload first: a 203 KB body declaring 200 MB peaked at 270 MB.
        resp = mock.MagicMock()
        resp.headers = {"Content-Encoding": "gzip"}
        resp.raw = _BombRaw()
        raw, err = tf._read_bounded_body(resp, tf.DEFAULT_MAX_BODY_BYTES)
        assert err is None
        assert len(raw) <= tf.DEFAULT_MAX_BODY_BYTES + 1
        # At most one chunk's worth of expansion was ever materialised.
        assert resp.raw.served <= tf.DEFAULT_MAX_BODY_BYTES + 1 + tf._DECODE_CHUNK_BYTES * 1000

    def test_identity_response_keeps_the_single_bounded_read(self):
        resp = mock.MagicMock()
        resp.headers = {}
        resp.raw.read.return_value = b"x" * 50
        raw, err = tf._read_bounded_body(resp, tf.DEFAULT_MAX_BODY_BYTES)
        assert raw == b"x" * 50 and err is None
        resp.raw.read.assert_called_once_with(tf.DEFAULT_MAX_BODY_BYTES + 1, decode_content=True)

    def test_body_read_failure_is_reported_not_silently_empty(self):
        resp = mock.MagicMock()
        resp.headers = {"Content-Encoding": "gzip"}
        resp.raw.read.side_effect = ValueError("bad gzip")
        type(resp).content = mock.PropertyMock(side_effect=ValueError("bad gzip"))
        raw, err = tf._read_bounded_body(resp, 1024)
        assert raw == b"" and "bad gzip" in err

    def test_evidence_volume_is_capped_and_the_cap_is_disclosed(self):
        capped = tf._cap_evidence([f"e{i}" for i in range(200)])
        assert len(capped) == tf.DEFAULT_MAX_EVIDENCE_PER_DETECTION
        assert "further evidence entries omitted" in capped[-1]

    def test_evidence_under_the_cap_is_untouched(self):
        evidence = [f"e{i}" for i in range(tf.DEFAULT_MAX_EVIDENCE_PER_DETECTION)]
        assert tf._cap_evidence(evidence) == evidence

    def test_hostile_cookie_flood_produces_a_small_finding(self):
        names = tf.parse_cookie_names([f"wordpress_{i}=v" for i in range(500)])
        scan = tf.detect_technologies_from_content({}, names, "", "b")
        finding = tf.make_tech_finding("WordPress", tf.CATEGORY_CMS, None,
                                        scan["WordPress"]["evidence"], tf.CONFIDENCE_LOW, SAFE_TARGET)
        assert len(json.dumps(finding)) < 4096


# ---------------------------------------------------------------------------
# D11 — persistence robustness
# ---------------------------------------------------------------------------

class TestPersistenceRobustness:
    def test_unusable_output_directory_raises_persistence_error(self, tmp_path):
        readonly = tmp_path / "ro"
        readonly.mkdir()
        os.chmod(readonly, 0o500)
        try:
            with pytest.raises(tf.PersistenceError):
                tf.PendingAssetsStore(output_dir=str(readonly / "out"))
        finally:
            os.chmod(readonly, 0o700)

    def test_run_degrades_instead_of_crashing_when_persistence_is_unavailable(self, tmp_path):
        readonly = tmp_path / "ro"
        readonly.mkdir()
        os.chmod(readonly, 0o500)
        response = _fake_response(status_code=200, headers={"Server": "nginx/1.18.0"},
                                   body=b"<html>wp-content/ wp-includes/ wp-json</html>")
        try:
            with mock.patch("requests.get", return_value=response):
                result = tf.run_tech_fingerprint(
                    SAFE_URL, target=SAFE_TARGET, output_dir=str(readonly / "out"),
                    check_favicon=False, probe_known_paths_enabled=False)
        finally:
            os.chmod(readonly, 0o700)
        assert result["persistence_available"] is False
        assert any(e["stage"] == "persistence_init" for e in result["errors"])
        # The reconnaissance itself still completed and is returned to the caller.
        assert any(d["technology"] == "WordPress" for d in result["technology_summary"]["detections"])
        assert result["recommended_next_actions"]

    def test_safe_store_add_reports_os_errors_instead_of_raising(self, tmp_path):
        store = tf.PendingAssetsStore(output_dir=str(tmp_path))
        os.chmod(tmp_path, 0o500)
        try:
            error = tf._safe_store_add(store, tf.make_finding("t", "x", {}, [], tf.CONFIDENCE_LOW))
        finally:
            os.chmod(tmp_path, 0o700)
        assert isinstance(error, str) and error

    def test_concurrent_runs_do_not_lose_findings(self, tmp_path):
        import concurrent.futures
        output_dir = str(tmp_path / "o")
        response = _fake_response(status_code=200, headers={"Server": "nginx/1.18.0"},
                                   body=b"<html>nothing</html>")

        def _run(_):
            with mock.patch("requests.get", return_value=response):
                return tf.run_tech_fingerprint(
                    SAFE_URL, target=SAFE_TARGET, output_dir=output_dir,
                    check_favicon=False, probe_known_paths_enabled=False)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(_run, range(8)))
        records = json.loads((tmp_path / "o" / "pending_assets.json").read_text())
        # 1 Nginx detection + 3 negative-result categories, per run, none lost.
        assert len(records) == 8 * 4


# ---------------------------------------------------------------------------
# D12 — favicon hygiene
# ---------------------------------------------------------------------------

class TestFaviconHygiene:
    def test_html_soft_404_is_not_hashed_as_a_favicon(self):
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"},
                               body=b"<html><body>404 not found</body></html>")
        with mock.patch("requests.get", return_value=resp):
            result = tf.compute_favicon_hash(SAFE_URL)
        assert result["status"] == "not_an_icon"
        assert result["md5"] is None

    def test_html_without_a_content_type_is_still_detected(self):
        resp = _fake_response(status_code=200, body=b"<!DOCTYPE html><html>nope</html>")
        with mock.patch("requests.get", return_value=resp):
            assert tf.compute_favicon_hash(SAFE_URL)["status"] == "not_an_icon"

    def test_icon_without_a_content_type_is_still_hashed(self):
        resp = _fake_response(status_code=200, body=b"\x00\x00\x01\x00some-icon")
        with mock.patch("requests.get", return_value=resp):
            assert tf.compute_favicon_hash(SAFE_URL)["md5"] is not None

    def test_svg_favicon_is_hashed(self):
        resp = _fake_response(status_code=200, headers={"Content-Type": "image/svg+xml"},
                               body=b"<svg xmlns='http://www.w3.org/2000/svg'></svg>")
        with mock.patch("requests.get", return_value=resp):
            assert tf.compute_favicon_hash(SAFE_URL)["md5"] is not None

    def test_no_favicon_observation_is_persisted_for_a_soft_404(self, tmp_path):
        baseline = _fake_response(status_code=200, body=b"<html>plain</html>")
        error_page = _fake_response(status_code=404, body=b"")
        html_favicon = _fake_response(status_code=200, headers={"Content-Type": "text/html"},
                                       body=b"<html>404</html>")
        with mock.patch("requests.get", side_effect=_resp_seq(baseline, error_page, html_favicon)):
            tf.run_tech_fingerprint(SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "o"),
                                     probe_known_paths_enabled=False)
        records = json.loads((tmp_path / "o" / "pending_assets.json").read_text())
        assert not any(r["type"] == "tech_fingerprint_favicon_observed" for r in records)


# ---------------------------------------------------------------------------
# D13 — run summary observability and downstream contract
# ---------------------------------------------------------------------------

class TestRunSummaryContract:
    def test_summary_reports_what_was_actually_observed(self, tmp_path):
        baseline = _fake_response(status_code=200, headers={"Content-Type": "text/html; charset=utf-8"},
                                   body=b"<html>plain</html>", final_url=SAFE_URL)
        error_page = _fake_response(status_code=404, body=b"")
        with mock.patch("requests.get", side_effect=_resp_seq(baseline, error_page)):
            result = tf.run_tech_fingerprint(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "o"),
                check_favicon=False, probe_known_paths_enabled=False)
        assert result["status_code"] == 200
        assert result["final_url"] == SAFE_URL
        assert result["content_type"].startswith("text/html")
        assert result["body_truncated"] is False
        assert result["baseline_representative"]["representative"] is True
        assert result["persistence_available"] is True
        json.dumps(result)

    def test_recommended_actions_carry_their_subject(self):
        detections = [{"technology": "WordPress", "category": tf.CATEGORY_CMS, "version": None,
                        "evidence": ["e"], "confidence": tf.CONFIDENCE_HIGH, "url": SAFE_URL,
                        "corroborating_urls": []}]
        action = tf.build_recommended_actions(detections, SAFE_TARGET)[0]
        # `target` was previously accepted and then never used, so the action
        # reached the orchestrator with no subject at all.
        assert action["target"] == SAFE_TARGET
        assert action["url"] == SAFE_URL
        assert action["confidence"] == tf.CONFIDENCE_HIGH

    def test_parse_cookie_names_skips_non_string_entries(self):
        assert tf.parse_cookie_names([None, 123, "a=1", {"x": 1}]) == ["a"]

    def test_technology_summary_still_drives_endpoint_discovery_wordlists(self):
        detections = [{"technology": "WordPress", "category": tf.CATEGORY_CMS, "version": None,
                        "evidence": ["e"], "confidence": tf.CONFIDENCE_HIGH, "url": SAFE_URL,
                        "corroborating_urls": ["https://example.com/wp-login.php"],
                        "conflicts_with": ["Drupal"], "observed_through_intermediary": True,
                        "cache_status": "HIT", "response_status_code": 200}]
        summary = tf.build_technology_summary(detections)
        assert ed.select_wordlists_for_technology(summary) == [("wordpress_paths.txt", "wordpress")]

    def test_derived_requests_are_scope_validated(self, tmp_path):
        with pytest.raises(tf.ScopeError):
            tf.run_tech_fingerprint("https://evil.com/", target=SAFE_TARGET,
                                     output_dir=str(tmp_path / "o"))
