"""
Tests for reconhound/http_analyzer.py (ReconHound Module 3, per context.md's
build order — catalog item 16, build-order position 3).

Run with:  ./.venv/bin/python -m pytest tests/test_http_analyzer.py -v

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

from reconhound import http_analyzer as ha


SAFE_URL = "https://example.com/"
SAFE_TARGET = "example.com"


def _fake_response(
    status_code=200,
    headers=None,
    body=b"",
    set_cookie_headers=None,
    final_url=None,
    raw_headers_getlist_raises=False,
):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = dict(headers or {})
    resp.encoding = "utf-8"
    resp.content = body
    resp.url = final_url or SAFE_URL
    resp.elapsed.total_seconds.return_value = 0.05
    resp.raw.read.return_value = body

    if raw_headers_getlist_raises:
        del resp.raw.headers.getlist  # simulate AttributeError fallback path
        resp.raw.headers = mock.Mock(spec=[])
    else:
        resp.raw.headers.getlist.return_value = list(set_cookie_headers or [])
    return resp


# ---------------------------------------------------------------------------
# validate_url_target (scope enforcement)
# ---------------------------------------------------------------------------

class TestValidateUrlTarget:
    def test_accepts_https_url(self):
        assert ha.validate_url_target("https://example.com/path") == "https://example.com/path"

    def test_accepts_in_scope_subdomain(self):
        assert ha.validate_url_target("https://api.example.com/", target="example.com")

    def test_rejects_out_of_scope_host(self):
        with pytest.raises(ha.ScopeError):
            ha.validate_url_target("https://evil.com/", target="example.com")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(ha.ScopeError):
            ha.validate_url_target("ftp://example.com/")

    def test_rejects_missing_hostname(self):
        with pytest.raises(ha.ScopeError):
            ha.validate_url_target("https:///path")

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(ha.ScopeError):
            ha.validate_url_target(bad)

    def test_allows_ip_literal_host_without_scope_check(self):
        # IP-literal hosts skip the domain in-scope comparison (documented).
        assert ha.validate_url_target("http://93.184.216.34/", target="example.com")


# ---------------------------------------------------------------------------
# PendingAssetsStore / make_finding (shared conventions)
# ---------------------------------------------------------------------------

class TestPendingAssetsStoreAndFinding:
    def test_finding_structure_and_source(self):
        finding = ha.make_finding("http_security_headers", SAFE_URL, {"a": 1}, ["e"], ha.CONFIDENCE_HIGH)
        assert finding["source"] == "http_analyzer.py"
        assert finding["metadata"] == {}
        json.dumps(finding)

    def test_store_preserves_prior_data(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{"type": "dns_record", "source": "passive_recon.py"}]
        pending.write_text(json.dumps(pre_existing))

        store = ha.PendingAssetsStore(output_dir=str(output_dir))
        store.add(ha.make_finding("http_cookie_flags", SAFE_URL, {}, ["e"], ha.CONFIDENCE_HIGH))
        assert store.all() == pre_existing + [store.all()[-1]]

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = ha.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(ha.PersistenceError):
            store.add(ha.make_finding("http_cache_headers", SAFE_URL, {}, ["e"], ha.CONFIDENCE_HIGH))


# ---------------------------------------------------------------------------
# fetch_url
# ---------------------------------------------------------------------------

class TestFetchUrl:
    def test_successful_fetch(self):
        resp = _fake_response(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=b"<html>hi</html>",
            set_cookie_headers=["a=1; Path=/"],
        )
        with mock.patch("requests.get", return_value=resp):
            result = ha.fetch_url(SAFE_URL)
        assert result["status"] == "found"
        assert result["status_code"] == 200
        assert result["body"] == "<html>hi</html>"
        assert result["set_cookie_headers"] == ["a=1; Path=/"]

    def test_body_truncated_when_over_limit(self):
        body = b"x" * 100
        resp = _fake_response(body=body)
        with mock.patch("requests.get", return_value=resp):
            result = ha.fetch_url(SAFE_URL, max_body_bytes=10)
        assert result["body_truncated"] is True
        assert len(result["body"]) == 10

    def test_timeout_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout("timed out")):
            result = ha.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_connection_error_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = ha.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert "connection error" in result["error"]

    def test_generic_request_exception_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.RequestException("boom")):
            result = ha.fetch_url(SAFE_URL)
        assert result["status"] == "error"

    def test_set_cookie_fallback_when_getlist_unavailable(self):
        resp = _fake_response(
            headers={"Set-Cookie": "single=1"}, raw_headers_getlist_raises=True,
        )
        with mock.patch("requests.get", return_value=resp):
            result = ha.fetch_url(SAFE_URL)
        assert result["set_cookie_headers"] == ["single=1"]

    def test_json_serializable(self):
        resp = _fake_response(headers={"X-Test": "1"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            result = ha.fetch_url(SAFE_URL)
        json.dumps(result)


# ---------------------------------------------------------------------------
# 1. analyze_security_headers
# ---------------------------------------------------------------------------

class TestAnalyzeSecurityHeaders:
    def test_all_present_no_notes(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        result = ha.analyze_security_headers(headers)
        for name in ha._SECURITY_HEADERS:
            assert result[name]["present"] is True
        assert result["Strict-Transport-Security"]["max_age"] == 31536000
        assert result["Strict-Transport-Security"]["notes"] == []

    def test_missing_headers_flagged(self):
        result = ha.analyze_security_headers({})
        for name in ha._SECURITY_HEADERS:
            assert result[name]["present"] is False
            assert "header not present" in result[name]["notes"]

    def test_csp_unsafe_inline_flagged(self):
        result = ha.analyze_security_headers({"Content-Security-Policy": "script-src 'unsafe-inline'"})
        assert "policy allows 'unsafe-inline'" in result["Content-Security-Policy"]["notes"]

    def test_short_hsts_max_age_flagged(self):
        result = ha.analyze_security_headers({"Strict-Transport-Security": "max-age=100"})
        assert any("180 days" in n for n in result["Strict-Transport-Security"]["notes"])

    def test_result_json_serializable(self):
        result = ha.analyze_security_headers({"X-Frame-Options": "SAMEORIGIN"})
        json.dumps(result)


# ---------------------------------------------------------------------------
# 2. analyze_cookie_flags
# ---------------------------------------------------------------------------

class TestAnalyzeCookieFlags:
    def test_fully_flagged_cookie_no_issues(self):
        result = ha.analyze_cookie_flags(["session=abc; HttpOnly; Secure; SameSite=Strict"])
        assert result[0]["http_only"] is True
        assert result[0]["secure"] is True
        assert result[0]["samesite"] == "Strict"
        assert result[0]["issues"] == []

    def test_missing_flags_reported(self):
        result = ha.analyze_cookie_flags(["session=abc"])
        assert result[0]["http_only"] is False
        assert "missing HttpOnly flag" in result[0]["issues"]
        assert "missing Secure flag" in result[0]["issues"]
        assert "SameSite attribute not set" in result[0]["issues"]

    def test_samesite_none_without_secure_flagged(self):
        result = ha.analyze_cookie_flags(["session=abc; SameSite=None"])
        assert any("SameSite=None without Secure" in i for i in result[0]["issues"])

    def test_empty_input(self):
        assert ha.analyze_cookie_flags([]) == []

    def test_multiple_cookies(self):
        result = ha.analyze_cookie_flags(["a=1; Secure", "b=2; HttpOnly"])
        assert len(result) == 2
        assert result[0]["name"] == "a"
        assert result[1]["name"] == "b"


# ---------------------------------------------------------------------------
# 3. analyze_cors
# ---------------------------------------------------------------------------

class TestAnalyzeCors:
    def test_origin_reflected_detected(self):
        def fake_get(url, timeout, headers, allow_redirects, stream):
            origin = headers.get("Origin")
            acao = origin if origin == ha._CORS_TEST_ORIGIN else None
            return _fake_response(headers={"Access-Control-Allow-Origin": acao} if acao else {})
        with mock.patch("requests.get", side_effect=fake_get):
            result = ha.analyze_cors(SAFE_URL)
        assert result["origin_reflected"] is True
        assert result["null_origin_allowed"] is False

    def test_null_origin_allowed_detected(self):
        def fake_get(url, timeout, headers, allow_redirects, stream):
            if headers.get("Origin") == "null":
                return _fake_response(headers={"Access-Control-Allow-Origin": "null"})
            return _fake_response(headers={})
        with mock.patch("requests.get", side_effect=fake_get):
            result = ha.analyze_cors(SAFE_URL)
        assert result["null_origin_allowed"] is True

    def test_wildcard_detected(self):
        resp = _fake_response(headers={"Access-Control-Allow-Origin": "*"})
        with mock.patch("requests.get", return_value=resp):
            result = ha.analyze_cors(SAFE_URL)
        assert result["wildcard"] is True

    def test_credentials_with_reflection_flagged(self):
        def fake_get(url, timeout, headers, allow_redirects, stream):
            if headers.get("Origin") == ha._CORS_TEST_ORIGIN:
                return _fake_response(headers={
                    "Access-Control-Allow-Origin": ha._CORS_TEST_ORIGIN,
                    "Access-Control-Allow-Credentials": "true",
                })
            return _fake_response(headers={})
        with mock.patch("requests.get", side_effect=fake_get):
            result = ha.analyze_cors(SAFE_URL)
        assert result["allow_credentials_with_wildcard_or_reflection"] is True

    def test_no_cors_headers_no_flags(self):
        resp = _fake_response(headers={})
        with mock.patch("requests.get", return_value=resp):
            result = ha.analyze_cors(SAFE_URL)
        assert not result["origin_reflected"]
        assert not result["null_origin_allowed"]
        assert not result["wildcard"]

    def test_fetch_error_recorded_per_check(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout()):
            result = ha.analyze_cors(SAFE_URL)
        assert len(result["checks"]) == 2
        assert all(c["status"] == "error" for c in result["checks"])


# ---------------------------------------------------------------------------
# 4. detect_auth_surfaces
# ---------------------------------------------------------------------------

class TestDetectAuthSurfaces:
    def test_login_form_detected(self):
        body = '<form><input type="password" name="password"></form>'
        result = ha.detect_auth_surfaces(SAFE_URL, body, {})
        assert "login" in result["indicators"]

    def test_oauth_and_sso_detected(self):
        body = "Continue with OAuth2 or SAML SSO"
        result = ha.detect_auth_surfaces(SAFE_URL, body, {})
        assert "oauth" in result["indicators"]
        assert "sso" in result["indicators"]

    def test_www_authenticate_header_detected(self):
        result = ha.detect_auth_surfaces(SAFE_URL, "", {"WWW-Authenticate": 'Basic realm="test"'})
        assert "http_auth_challenge" in result["indicators"]

    def test_no_indicators_empty_dict(self):
        result = ha.detect_auth_surfaces(SAFE_URL, "just a plain page", {})
        assert result["indicators"] == {}

    def test_none_body_does_not_crash(self):
        result = ha.detect_auth_surfaces(SAFE_URL, None, {})
        assert result["indicators"] == {}


# ---------------------------------------------------------------------------
# 5. detect_jwts
# ---------------------------------------------------------------------------

def _make_jwt(header_obj, payload_obj):
    import base64 as _b64
    def enc(obj):
        raw = json.dumps(obj).encode("utf-8")
        return _b64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return f"{enc(header_obj)}.{enc(payload_obj)}.fakesignature"


class TestDetectJwts:
    def test_finds_and_decodes_jwt_in_body(self):
        token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user1", "exp": 123})
        result = ha.detect_jwts(f"token={token}", {}, [])
        assert result["count"] == 1
        assert result["tokens"][0]["alg"] == "HS256"
        assert set(result["tokens"][0]["payload_claim_names"]) == {"sub", "exp"}
        assert token not in json.dumps(result)  # full raw token must never be persisted/exposed

    def test_weak_alg_none_flagged(self):
        token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "x"})
        result = ha.detect_jwts(token, {}, [])
        assert result["weak_alg_detected"] is True

    def test_no_token_found(self):
        result = ha.detect_jwts("nothing interesting here", {}, [])
        assert result["count"] == 0
        assert result["weak_alg_detected"] is False

    def test_finds_jwt_in_cookies_and_headers(self):
        token = _make_jwt({"alg": "RS256"}, {"a": 1})
        result = ha.detect_jwts(None, {"X-Auth": token}, [f"jwt={token}; Path=/"])
        assert result["count"] == 1

    def test_malformed_token_segment_handled(self):
        result = ha.detect_jwts("eyJhbGciOiJIUzI1NiJ9.notbase64!!!.sig" + "x" * 10, {}, [])
        # Either not matched by the regex (invalid chars) or decoded with an error, never raises.
        json.dumps(result)


# ---------------------------------------------------------------------------
# 6. analyze_cache_headers
# ---------------------------------------------------------------------------

class TestAnalyzeCacheHeaders:
    def test_no_cache_headers_flagged(self):
        result = ha.analyze_cache_headers({})
        assert "no Cache-Control/Pragma headers present" in result["notes"]

    def test_cacheable_without_no_store_flagged(self):
        result = ha.analyze_cache_headers({"Cache-Control": "public, max-age=3600"})
        assert any("shared caches" in n for n in result["notes"])

    def test_no_store_not_flagged(self):
        result = ha.analyze_cache_headers({"Cache-Control": "no-store"})
        assert result["notes"] == []

    def test_fields_extracted(self):
        result = ha.analyze_cache_headers({"ETag": '"abc123"', "Age": "10"})
        assert result["ETag"] == '"abc123"'
        assert result["Age"] == "10"


# ---------------------------------------------------------------------------
# 7. analyze_host_header_behavior
# ---------------------------------------------------------------------------

class TestAnalyzeHostHeaderBehavior:
    def test_reflection_detected(self):
        def fake_get(url, timeout, headers, allow_redirects, stream):
            host = headers.get("Host")
            if host == ha._HOST_HEADER_PROBE:
                return _fake_response(status_code=200, body=f"welcome to {host}".encode())
            return _fake_response(status_code=200, body=b"welcome")
        with mock.patch("requests.get", side_effect=fake_get):
            result = ha.analyze_host_header_behavior(SAFE_URL)
        assert result["status"] == "checked"
        assert result["probe_host_reflected"] is True

    def test_no_reflection_and_same_status(self):
        resp = _fake_response(status_code=200, body=b"normal page")
        with mock.patch("requests.get", return_value=resp):
            result = ha.analyze_host_header_behavior(SAFE_URL)
        assert result["probe_host_reflected"] is False
        assert result["status_code_changed"] is False

    def test_status_code_change_detected(self):
        def fake_get(url, timeout, headers, allow_redirects, stream):
            if headers.get("Host") == ha._HOST_HEADER_PROBE:
                return _fake_response(status_code=400)
            return _fake_response(status_code=200)
        with mock.patch("requests.get", side_effect=fake_get):
            result = ha.analyze_host_header_behavior(SAFE_URL)
        assert result["status_code_changed"] is True

    def test_connection_failure_is_error_status(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("down")):
            result = ha.analyze_host_header_behavior(SAFE_URL)
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# 8. map_redirect_chain
# ---------------------------------------------------------------------------

class TestMapRedirectChain:
    def test_single_hop_terminal(self):
        resp = _fake_response(status_code=200)
        with mock.patch("requests.get", return_value=resp):
            result = ha.map_redirect_chain(SAFE_URL)
        assert len(result["hops"]) == 1
        assert result["stopped_reason"] == "terminal_response"

    def test_follows_in_scope_redirect(self):
        responses = [
            _fake_response(status_code=302, headers={"Location": "https://www.example.com/"}),
            _fake_response(status_code=200),
        ]
        with mock.patch("requests.get", side_effect=responses):
            result = ha.map_redirect_chain(SAFE_URL, target="example.com")
        assert len(result["hops"]) == 2
        assert result["stopped_reason"] == "terminal_response"
        assert result["final_url"] == "https://www.example.com/"

    def test_stops_before_out_of_scope_redirect(self):
        resp = _fake_response(status_code=302, headers={"Location": "https://evil.com/"})
        with mock.patch("requests.get", return_value=resp):
            result = ha.map_redirect_chain(SAFE_URL, target="example.com")
        assert result["stopped_reason"] == "next_hop_out_of_scope"
        assert len(result["hops"]) == 1

    def test_stops_before_private_ip_redirect(self):
        resp = _fake_response(status_code=302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        with mock.patch("requests.get", return_value=resp):
            result = ha.map_redirect_chain(SAFE_URL)
        assert result["stopped_reason"] == "next_hop_disallowed_ip"

    def test_max_hops_reached(self):
        resp = _fake_response(status_code=302, headers={"Location": SAFE_URL})
        with mock.patch("requests.get", return_value=resp):
            result = ha.map_redirect_chain(SAFE_URL, max_hops=3)
        assert result["stopped_reason"] == "max_hops_reached"
        assert len(result["hops"]) == 3

    def test_redirect_without_location_stops(self):
        resp = _fake_response(status_code=302, headers={})
        with mock.patch("requests.get", return_value=resp):
            result = ha.map_redirect_chain(SAFE_URL)
        assert result["stopped_reason"] == "redirect_without_location"

    def test_fetch_error_stops_chain(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout()):
            result = ha.map_redirect_chain(SAFE_URL)
        assert result["stopped_reason"] == "fetch_error"


# ---------------------------------------------------------------------------
# 9. detect_waf
# ---------------------------------------------------------------------------

class TestDetectWaf:
    def test_cloudflare_detected_via_header(self):
        result = ha.detect_waf({"Server": "cloudflare", "CF-RAY": "abc123"})
        assert result["detected"] is True
        vendors = [v["vendor"] for v in result["vendors"]]
        assert "cloudflare" in vendors

    def test_detected_via_cookie(self):
        result = ha.detect_waf({}, set_cookie_headers=["incap_ses_123=abcdef; Path=/"])
        vendors = [v["vendor"] for v in result["vendors"]]
        assert "imperva_incapsula" in vendors

    def test_detected_via_body_marker(self):
        result = ha.detect_waf({}, body="Access Denied - Sucuri Website Firewall")
        vendors = [v["vendor"] for v in result["vendors"]]
        assert "sucuri" in vendors

    def test_no_signatures_matched(self):
        result = ha.detect_waf({"Server": "nginx"})
        assert result["detected"] is False
        assert result["vendors"] == []

    def test_result_json_serializable(self):
        result = ha.detect_waf({"Server": "cloudflare"})
        json.dumps(result)


# ---------------------------------------------------------------------------
# run_http_analysis (single-URL orchestration)
# ---------------------------------------------------------------------------

class TestRunHttpAnalysis:
    def test_full_run_persists_findings(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(
            status_code=200,
            headers={
                "X-Frame-Options": "DENY",
                "Access-Control-Allow-Origin": "*",
                "Server": "cloudflare",
            },
            body=b"<form><input type='password'></form>",
            set_cookie_headers=["session=abc; HttpOnly"],
        )
        with mock.patch("requests.get", return_value=resp):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))

        assert summary["fetch_status"] == "found"
        assert summary["security_headers"]["X-Frame-Options"]["present"] is True
        assert summary["cors"]["wildcard"] is True
        assert summary["waf"]["detected"] is True
        assert os.path.exists(output_dir / "pending_assets.json")

        with open(output_dir / "pending_assets.json") as f:
            persisted = json.load(f)
        json.dumps(persisted)
        types = {p["type"] for p in persisted}
        # Always-persisted composite checks:
        assert {"http_security_headers", "http_cookie_flags", "http_cache_headers",
                "http_host_header_behavior", "http_redirect_chain"} <= types
        # Found-only checks that should have fired given this fixture:
        assert "http_cors_misconfiguration" in types
        assert "waf_detected" in types
        assert "http_auth_surface_indicators" in types

    def test_fetch_failure_short_circuits_with_error(self, tmp_path):
        output_dir = tmp_path / "output"
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            summary = ha.run_http_analysis(SAFE_URL, output_dir=str(output_dir))
        assert summary["fetch_status"] == "error"
        assert summary["errors"]
        assert not (output_dir / "pending_assets.json").exists()

    def test_invalid_url_raises_before_persistence(self, tmp_path):
        output_dir = tmp_path / "output"
        with pytest.raises(ha.ScopeError):
            ha.run_http_analysis("not a url", output_dir=str(output_dir))
        assert not (output_dir / "pending_assets.json").exists()

    def test_out_of_scope_url_raises(self, tmp_path):
        output_dir = tmp_path / "output"
        with pytest.raises(ha.ScopeError):
            ha.run_http_analysis("https://evil.com/", target="example.com", output_dir=str(output_dir))

    def test_no_findings_when_nothing_notable(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, headers={}, body=b"plain page")
        with mock.patch("requests.get", return_value=resp):
            summary = ha.run_http_analysis(SAFE_URL, output_dir=str(output_dir))
        with open(output_dir / "pending_assets.json") as f:
            persisted = json.load(f)
        types = {p["type"] for p in persisted}
        # Only the always-persist composite checks should be present.
        assert "waf_detected" not in types
        assert "http_jwt_detected" not in types
        assert "http_cors_misconfiguration" not in types
        assert "http_auth_surface_indicators" not in types

    def test_result_and_store_are_json_serializable(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            summary = ha.run_http_analysis(SAFE_URL, output_dir=str(output_dir))
        json.dumps(summary)

    def test_single_stage_failure_does_not_abort_run(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, body=b"ok")
        with mock.patch("requests.get", return_value=resp), \
             mock.patch.object(ha, "analyze_cache_headers", side_effect=RuntimeError("boom")):
            summary = ha.run_http_analysis(SAFE_URL, output_dir=str(output_dir))
        assert any(e["stage"] == "cache_headers" for e in summary["errors"])
        # Other checks still completed despite the cache_headers failure.
        assert summary["security_headers"]
        assert summary["finished_at"]
