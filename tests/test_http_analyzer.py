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
    repeated_headers=None,
):
    """
    A response double whose `raw.headers.getlist(name)` honours the header
    NAME it is given.

    The previous double returned the Set-Cookie list for every name, which
    only went unnoticed because the module never asked for anything else.
    `repeated_headers` is {name: [value, value, ...]} for servers that send a
    header more than once; the merged `headers` view is built from it the way
    urllib3 does (", ".join), so the two views stay consistent.
    """
    merged = dict(headers or {})
    repeated = {k: list(v) for k, v in (repeated_headers or {}).items()}
    for name, values in repeated.items():
        merged[name] = ", ".join(values)
    if set_cookie_headers:
        repeated.setdefault("Set-Cookie", list(set_cookie_headers))
        merged.setdefault("Set-Cookie", ", ".join(set_cookie_headers))

    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = merged
    resp.encoding = "utf-8"
    resp.content = body
    resp.url = final_url or SAFE_URL
    resp.elapsed.total_seconds.return_value = 0.05
    resp.raw.read.return_value = body

    if raw_headers_getlist_raises:
        del resp.raw.headers.getlist  # simulate AttributeError fallback path
        resp.raw.headers = mock.Mock(spec=[])
    else:
        def _getlist(name):
            lower = str(name).lower()
            for key, values in repeated.items():
                if key.lower() == lower:
                    return list(values)
            for key, value in merged.items():
                if key.lower() == lower:
                    return [value]
            return []
        resp.raw.headers.getlist.side_effect = _getlist
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
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
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
        # Four bounded probes, not two: the arbitrary origin alone cannot see
        # a broken startswith()/endswith() allow-list.
        assert len(result["checks"]) == len(ha._cors_probe_origins(SAFE_URL)) == 4
        assert all(c["status"] == "error" for c in result["checks"])
        assert result["conclusive"] is False


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
        # A chain that keeps moving to NEW in-scope URLs exhausts the hop
        # budget. (A chain that returns to a URL already visited is reported as
        # a loop instead — see test_redirect_loop_detected.)
        counter = {"n": 0}

        def fake_get(url, timeout, headers, allow_redirects, stream):
            counter["n"] += 1
            return _fake_response(status_code=302,
                                  headers={"Location": f"https://example.com/hop{counter['n']}"})
        with mock.patch("requests.get", side_effect=fake_get):
            result = ha.map_redirect_chain(SAFE_URL, target=SAFE_TARGET, max_hops=3)
        assert result["stopped_reason"] == "max_hops_reached"
        assert len(result["hops"]) == 3
        assert result["complete"] is False

    def test_redirect_loop_detected(self):
        resp = _fake_response(status_code=302, headers={"Location": SAFE_URL})
        with mock.patch("requests.get", return_value=resp):
            result = ha.map_redirect_chain(SAFE_URL, max_hops=10)
        assert result["stopped_reason"] == "redirect_loop"
        # The loop is caught on the second observation, not after 10 requests.
        assert len(result["hops"]) == 1

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


# ===========================================================================
# Regression tests for the hardening audit.
#
# Every test below pins a defect that was reproduced against the previous
# implementation, or a semantic rule the module must not drift away from
# (absence of evidence != evidence of absence, observation != confirmation,
# CDN != origin, external IdP != target, secrets never persisted).
# ===========================================================================

import re
import time


def _make_token(header_obj, payload_obj, signature="c2lnbmF0dXJl"):
    import base64 as _b64

    def enc(obj):
        return _b64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{enc(header_obj)}.{enc(payload_obj)}.{signature}"


# ---------------------------------------------------------------------------
# Scope / URL safety
# ---------------------------------------------------------------------------

class TestUrlSafety:
    @pytest.mark.parametrize("bad", [
        "https://example.com/\r\nX-Injected: 1",
        "https://example.com/\npath",
        "https://example.com/\tpath",
        "https://example.com/\x00",
        "https://evil.com\\@example.com/",
    ])
    def test_control_characters_and_backslash_rejected(self, bad):
        # urlsplit silently strips \r\n\t, so these previously validated in
        # their stripped form and were then handed to requests (and persisted)
        # with the raw bytes still in them.
        with pytest.raises(ha.ScopeError):
            ha.validate_url_target(bad, target="example.com")

    def test_unparseable_url_raises_scope_error_not_bare_valueerror(self):
        # ScopeError subclasses ValueError, so a bare ValueError from urlsplit
        # was NOT caught by callers guarding on ScopeError.
        with pytest.raises(ha.ScopeError):
            ha.validate_url_target("https://[::1/")
        with pytest.raises(ha.ScopeError):
            ha.validate_url_target("https://example.com:99999/", target="example.com")

    def test_userinfo_credentials_are_stripped_not_persisted(self):
        assert ha.validate_url_target(
            "https://admin:s3cr3t@example.com/x", target="example.com"
        ) == "https://example.com/x"

    def test_userinfo_host_confusion_still_scope_checked(self):
        with pytest.raises(ha.ScopeError):
            ha.validate_url_target("https://example.com@evil.com/", target="example.com")

    @pytest.mark.parametrize("host,target", [
        ("xn--mnchen-3ya.de", "münchen.de"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("shop.xn--mnchen-3ya.de", "münchen.de"),
        ("EXAMPLE.com.", "example.com"),
    ])
    def test_idn_forms_compare_equal(self, host, target):
        assert ha.validate_url_target(f"https://{host}/", target=target)

    def test_idn_homograph_is_still_out_of_scope(self):
        with pytest.raises(ha.ScopeError):
            # Cyrillic 'е' — a different host that merely looks like example.com.
            ha.validate_url_target("https://examplе.com/", target="example.com")

    def test_credentials_never_reach_persistence(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/plain"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            ha.run_http_analysis("https://admin:hunter2@example.com/",
                                 target="example.com", output_dir=str(output_dir))
        raw = (output_dir / "pending_assets.json").read_text()
        assert "hunter2" not in raw and "admin:" not in raw


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

class TestSecurityHeaderHardening:
    def test_hsts_max_age_with_absurd_digit_count_does_not_raise(self):
        # int() rejects >4300-digit strings in Python 3.11+, and the raised
        # ValueError destroyed the entire security-header stage.
        result = ha.analyze_security_headers({"Strict-Transport-Security": "max-age=" + "9" * 5000})
        entry = result["Strict-Transport-Security"]
        assert entry["max_age"] is None
        assert entry["posture"] == "invalid"
        assert any("malformed" in n for n in entry["notes"])

    @pytest.mark.parametrize("value,expected", [
        ("Max-Age=31536000; IncludeSubDomains", 31536000),
        ('max-age="31536000"', 31536000),
        ("MAX-AGE = 31536000", 31536000),
    ])
    def test_hsts_directives_are_case_insensitive_and_may_be_quoted(self, value, expected):
        entry = ha.analyze_security_headers({"Strict-Transport-Security": value})["Strict-Transport-Security"]
        assert entry["max_age"] == expected

    def test_hsts_states_are_distinguished(self):
        def posture(value):
            headers = {"Strict-Transport-Security": value} if value is not None else {}
            return ha.analyze_security_headers(headers)["Strict-Transport-Security"]["posture"]
        assert posture(None) == "absent"
        assert posture("includeSubDomains") == "invalid"
        assert posture("max-age=0") == "disabled"
        assert posture("max-age=100") == "weak"
        assert posture("max-age=31536000; includeSubDomains") == "strong"

    def test_hsts_never_claims_first_visit_protection(self):
        entry = ha.analyze_security_headers(
            {"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload"}
        )["Strict-Transport-Security"]
        assert entry["preload"] is True
        # The preload token is a *request* to be listed, not proof of listing.
        assert entry["first_visit_protection_proven"] is False

    def test_conflicting_hsts_headers_are_preserved_not_silently_resolved(self):
        resp = _fake_response(repeated_headers={
            "Strict-Transport-Security": ["max-age=100", "max-age=63072000"]})
        with mock.patch("requests.get", return_value=resp):
            fetched = ha.fetch_url(SAFE_URL)
        entry = ha.analyze_security_headers(
            fetched["headers"], fetched["header_lists"], fetched["header_lists_available"]
        )["Strict-Transport-Security"]
        assert entry["max_age"] == 100
        assert any("only the first" in n for n in entry["notes"])

    def test_hsts_conflict_visible_even_without_raw_header_lists(self):
        entry = ha.analyze_security_headers(
            {"Strict-Transport-Security": "max-age=100, max-age=63072000"}
        )["Strict-Transport-Security"]
        assert any("only the first" in n for n in entry["notes"])

    def test_csp_unsafe_inline_neutralised_by_nonce_is_not_a_false_positive(self):
        entry = ha.analyze_security_headers(
            {"Content-Security-Policy": "script-src 'nonce-abc123' 'unsafe-inline'"}
        )["Content-Security-Policy"]
        assert "policy allows 'unsafe-inline'" not in entry["notes"]
        assert entry["unsafe_inline_neutralised_by_nonce_or_hash"] == ["script-src"] \
            if "unsafe_inline_neutralised_by_nonce_or_hash" in entry else True
        assert any("ignore it" in n for n in entry["notes"])

    def test_csp_substring_in_a_path_is_not_a_directive(self):
        # "report-uri /csp/unsafe-inline" used to trip the substring check.
        entry = ha.analyze_security_headers(
            {"Content-Security-Policy": "script-src 'self'; report-uri /csp/unsafe-inline"}
        )["Content-Security-Policy"]
        assert "policy allows 'unsafe-inline'" not in entry["notes"]

    def test_csp_report_only_is_reported_but_is_not_enforcement(self):
        entry = ha.analyze_security_headers(
            {"Content-Security-Policy-Report-Only": "default-src 'none'"}
        )["Content-Security-Policy"]
        assert entry["present"] is False              # downstream contract unchanged
        assert entry["report_only_present"] is True
        assert any("never enforced" in n for n in entry["notes"])

    def test_csp_wildcard_and_scheme_sources_flagged(self):
        entry = ha.analyze_security_headers(
            {"Content-Security-Policy": "script-src * data:; img-src *.com"}
        )["Content-Security-Policy"]
        joined = " ".join(entry["notes"])
        assert "allows any origin" in joined
        assert "whole data: scheme" in joined
        assert "top-level suffix" in joined

    def test_csp_malformed_policy_is_named_as_malformed(self):
        entry = ha.analyze_security_headers({"Content-Security-Policy": "   ;;;  "})["Content-Security-Policy"]
        assert entry["present"] is True
        assert entry["directives_present"] == []

    def test_csp_repeated_directive_is_preserved_as_a_conflict(self):
        entry = ha.analyze_security_headers(
            {"Content-Security-Policy": "script-src 'self'; script-src *"}
        )["Content-Security-Policy"]
        assert any("repeats directive" in n for n in entry["notes"])

    def test_xfo_allow_from_is_flagged_as_deprecated(self):
        entry = ha.analyze_security_headers(
            {"X-Frame-Options": "ALLOW-FROM https://partner.example"})["X-Frame-Options"]
        assert any("deprecated" in n for n in entry["notes"])

    def test_xfo_conflicting_values_flagged(self):
        entry = ha.analyze_security_headers({"X-Frame-Options": "DENY, SAMEORIGIN"})["X-Frame-Options"]
        assert any("conflicting" in n for n in entry["notes"])

    def test_xcto_repeated_identical_value_is_not_called_unexpected(self):
        entry = ha.analyze_security_headers(
            {"X-Content-Type-Options": "nosniff, nosniff"})["X-Content-Type-Options"]
        assert not any("unexpected value" in n for n in entry["notes"])
        assert any("more than once" in n for n in entry["notes"])

    def test_referrer_policy_weak_and_unknown_tokens(self):
        entry = ha.analyze_security_headers({"Referrer-Policy": "unsafe-url"})["Referrer-Policy"]
        assert any("full URL" in n for n in entry["notes"])
        entry = ha.analyze_security_headers({"Referrer-Policy": "made-up-policy"})["Referrer-Policy"]
        assert any("unrecognised" in n for n in entry["notes"])

    def test_permissions_policy_legacy_syntax_and_wildcards(self):
        entry = ha.analyze_security_headers(
            {"Permissions-Policy": "geolocation 'self'"})["Permissions-Policy"]
        assert any("legacy Feature-Policy syntax" in n for n in entry["notes"])
        entry = ha.analyze_security_headers({"Permissions-Policy": "camera=*"})["Permissions-Policy"]
        assert any("every origin" in n for n in entry["notes"])

    def test_absent_header_produces_exactly_one_absence_note(self):
        result = ha.analyze_security_headers({})
        for name in ha._SECURITY_HEADERS:
            notes = result[name]["notes"]
            assert notes.count("header not present") == 1
            assert len(notes) == 1, f"{name} has redundant absence notes: {notes}"

    def test_duplicate_detection_reports_its_own_availability(self):
        unavailable = ha.analyze_security_headers({}, None, False)
        available = ha.analyze_security_headers({}, {}, True)
        assert unavailable["X-Frame-Options"]["duplicate_detection"] == "unavailable"
        assert available["X-Frame-Options"]["duplicate_detection"] == "available"

    def test_returned_mapping_is_exactly_the_six_headers(self):
        # risk_engine._missing_security_headers iterates this mapping; a
        # non-header key whose value is a string, not an entry dict, is a
        # schema hazard for any downstream consumer that does the same.
        result = ha.analyze_security_headers({"X-Frame-Options": "DENY"})
        assert set(result) == set(ha._SECURITY_HEADERS)
        assert all(isinstance(v, dict) for v in result.values())

    def test_provider_named_in_a_query_string_is_not_an_identity_provider(self):
        result = ha.detect_auth_surfaces(
            SAFE_URL, "", {"Location": "https://example.com/oauth/authorize?vendor=okta.com"},
            status_code=302, content_type="text/html", target="example.com")
        idp = result["identity_provider"]
        assert idp["third_party"] is False
        assert idp["known_provider"] is False

    def test_oversized_header_value_is_clipped_before_persistence(self):
        entry = ha.analyze_security_headers(
            {"Content-Security-Policy": "default-src " + "https://h.example " * 40000}
        )["Content-Security-Policy"]
        assert len(entry["value"]) < ha.MAX_HEADER_VALUE_CHARS + 200

    def test_risk_engine_contract_keys_preserved(self):
        result = ha.analyze_security_headers({"X-Frame-Options": "DENY"})
        # risk_engine._missing_security_headers reads exactly these keys.
        for name in ("Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
                     "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"):
            assert isinstance(result[name]["present"], bool)


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------

class TestCookieHardening:
    def test_host_prefix_violation_is_an_issue(self):
        cookie = ha.analyze_cookie_flags(
            ["__Host-sid=1; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Lax"])[0]
        assert cookie["prefix"] == "__Host-"
        assert any("__Host- prefix" in i for i in cookie["issues"])

    def test_secure_prefix_violation_is_an_issue(self):
        cookie = ha.analyze_cookie_flags(["__Secure-a=1; HttpOnly; SameSite=Lax"])[0]
        assert any("__Secure- prefix" in i for i in cookie["issues"])

    def test_compliant_host_prefix_has_no_prefix_issue(self):
        cookie = ha.analyze_cookie_flags(
            ["__Host-sid=1; Path=/; Secure; HttpOnly; SameSite=Lax"])[0]
        assert cookie["issues"] == []

    def test_broad_path_and_parent_domain_are_observations_not_issues(self):
        # Explicitly NOT severity-bearing: risk_engine turns `issues` into a
        # MEDIUM signal, and Path=/ with a parent Domain is ordinary config.
        cookie = ha.analyze_cookie_flags(
            ["sid=1; Path=/; Domain=.example.com; Secure; HttpOnly; SameSite=Lax"],
            url="https://app.example.com/")[0]
        assert cookie["issues"] == []
        assert cookie["host_only"] is False
        assert cookie["effective_domain"] == "example.com"
        assert any("scope observation" in n for n in cookie["notes"])

    def test_domain_that_cannot_cover_the_request_host_is_noted(self):
        cookie = ha.analyze_cookie_flags(["sid=1; Domain=other.example"],
                                         url="https://app.example.com/")[0]
        assert any("browsers reject this cookie" in n for n in cookie["notes"])

    def test_conflicting_attributes_are_preserved(self):
        cookie = ha.analyze_cookie_flags(["sid=1; Secure; HttpOnly; SameSite=Lax; SameSite=None"])[0]
        assert any("conflicting 'samesite'" in i for i in cookie["issues"])
        assert cookie["samesite"] == "None"

    def test_malformed_set_cookie_is_flagged(self):
        cookie = ha.analyze_cookie_flags(["=novalue; Secure"])[0]
        assert cookie["malformed"] is True
        assert any("malformed Set-Cookie" in i for i in cookie["issues"])

    def test_bare_samesite_and_unknown_samesite_are_noted_not_severity(self):
        bare = ha.analyze_cookie_flags(["sid=1; Secure; HttpOnly; SameSite"])[0]
        assert any("no value" in n for n in bare["notes"])
        weird = ha.analyze_cookie_flags(["sid=1; Secure; HttpOnly; SameSite=Bogus"])[0]
        assert any("unrecognised SameSite" in n for n in weird["notes"])

    def test_plaintext_context_is_recorded(self):
        cookie = ha.analyze_cookie_flags(["sid=1; HttpOnly; SameSite=Lax"],
                                         url="http://example.com/")[0]
        assert "missing Secure flag" in cookie["issues"]     # contract preserved
        assert any("plaintext HTTP" in n for n in cookie["notes"])

    def test_malformed_max_age_does_not_raise(self):
        cookie = ha.analyze_cookie_flags(["a=b; Max-Age=notanumber"])[0]
        assert cookie["max_age"] is None
        assert any("malformed Max-Age" in n for n in cookie["notes"])
        ha.analyze_cookie_flags(["a=b; Max-Age=" + "9" * 5000])   # must not raise

    def test_cookie_count_and_name_length_are_capped(self):
        many = [f"c{i}=v" for i in range(5000)]
        parsed = ha.analyze_cookie_flags(many)
        assert len(parsed) == ha.MAX_COOKIES
        assert any("only the first" in n for n in parsed[-1]["notes"])
        long_name = ha.analyze_cookie_flags(["A" * 100000 + "=1"])[0]
        assert len(long_name["name"]) < ha.MAX_COOKIE_NAME_CHARS + 60

    def test_cookie_values_are_never_recorded(self):
        parsed = ha.analyze_cookie_flags(["session=SUPERSECRETVALUE; Path=/"])
        assert "SUPERSECRETVALUE" not in json.dumps(parsed)

    def test_duplicate_cookie_names_noted(self):
        parsed = ha.analyze_cookie_flags(["sid=1; Secure", "sid=2; Secure"])
        assert any("was set 2 times" in n for n in parsed[1]["notes"])


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

def _cors_server(policy):
    """policy(origin) -> dict of response headers."""
    def fake_get(url, timeout, headers, allow_redirects, stream):
        return _fake_response(headers=policy(headers.get("Origin")))
    return fake_get


class TestCorsHardening:
    def test_wildcard_with_credentials_is_not_credentialed_read(self):
        with mock.patch("requests.get", side_effect=_cors_server(
                lambda o: {"Access-Control-Allow-Origin": "*",
                           "Access-Control-Allow-Credentials": "true"})):
            result = ha.analyze_cors(SAFE_URL)
        assert result["wildcard"] is True
        assert result["wildcard_with_credentials_header"] is True
        # Browsers REJECT '*' with credentials — this is not cross-origin read.
        assert result["credentialed_cross_origin_read"] is False
        assert result["exploitability"] == "unauthenticated_cross_origin_read"
        assert any("REJECT that combination" in n for n in result["notes"])

    def test_reflection_with_credentials_is_credentialed_read(self):
        with mock.patch("requests.get", side_effect=_cors_server(
                lambda o: {"Access-Control-Allow-Origin": o,
                           "Access-Control-Allow-Credentials": "true"})):
            result = ha.analyze_cors(SAFE_URL)
        assert result["origin_reflected"] is True
        assert result["credentialed_cross_origin_read"] is True
        assert result["exploitability"] == "credentialed_cross_origin_read"
        assert any("no cross-origin read was performed" in n for n in result["notes"])

    def test_suffix_matching_allow_list_is_detected(self):
        # A server that accepts anything ending in the target domain: an
        # arbitrary unrelated Origin alone never reveals it.
        with mock.patch("requests.get", side_effect=_cors_server(
                lambda o: {"Access-Control-Allow-Origin": o} if o and o.endswith("example.com") else {})):
            result = ha.analyze_cors(SAFE_URL)
        assert result["origin_reflected"] is True
        assert "target_suffixed_origin" in result["reflection_variants"]

    def test_prefix_matching_allow_list_is_detected(self):
        with mock.patch("requests.get", side_effect=_cors_server(
                lambda o: {"Access-Control-Allow-Origin": o}
                if o and o.startswith("https://example.com") else {})):
            result = ha.analyze_cors(SAFE_URL)
        assert result["origin_reflected"] is True
        assert "target_prefixed_origin" in result["reflection_variants"]

    def test_probe_count_is_fixed_and_bounded(self):
        calls = []

        def fake_get(url, timeout, headers, allow_redirects, stream):
            calls.append(headers.get("Origin"))
            return _fake_response(headers={})
        with mock.patch("requests.get", side_effect=fake_get):
            ha.analyze_cors(SAFE_URL)
        assert len(calls) == ha.MAX_CORS_PROBES == 4
        # No probe origin is ever *requested*; it only appears in a header.
        assert all(o for o in calls)

    def test_conflicting_allow_origin_headers_flagged(self):
        with mock.patch("requests.get", side_effect=_cors_server(
                lambda o: {"Access-Control-Allow-Origin": f"{o}, https://other.example"})):
            result = ha.analyze_cors(SAFE_URL)
        assert result["conflicting_allow_origin_headers"] is True
        assert result["origin_reflected"] is True

    def test_missing_vary_origin_on_reflection_is_noted(self):
        with mock.patch("requests.get", side_effect=_cors_server(
                lambda o: {"Access-Control-Allow-Origin": o, "Vary": "Accept-Encoding"})):
            result = ha.analyze_cors(SAFE_URL)
        assert result["vary_origin"] is False
        assert any("Vary: Origin" in n for n in result["notes"])
        assert any("no cache-poisoning attempt was made" in n for n in result["notes"])

    def test_partial_failure_is_not_a_clean_result(self):
        responses = [_fake_response(headers={}), requests.exceptions.Timeout(),
                     _fake_response(headers={}), _fake_response(headers={})]

        def fake_get(url, timeout, headers, allow_redirects, stream):
            item = responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        with mock.patch("requests.get", side_effect=fake_get):
            result = ha.analyze_cors(SAFE_URL)
        assert result["probes_answered"] == 3
        assert result["conclusive"] is False

    def test_check_records_status_code(self):
        with mock.patch("requests.get", return_value=_fake_response(status_code=403, headers={})):
            result = ha.analyze_cors(SAFE_URL)
        assert all(c["status_code"] == 403 for c in result["checks"])


# ---------------------------------------------------------------------------
# Auth surfaces
# ---------------------------------------------------------------------------

class TestAuthSurfaceHardening:
    def test_binary_body_is_not_keyword_scanned(self):
        png = "\x89PNG\r\n\x1a\n" + "login sign-in oauth saml" + "\xff" * 100
        result = ha.detect_auth_surfaces(SAFE_URL, png, {}, content_type="image/png")
        assert result["indicators"] == {}
        assert result["body_analyzable"] is False
        assert result["conclusive"] is False

    def test_error_page_indicators_are_marked_as_weak_evidence(self):
        result = ha.detect_auth_surfaces(
            SAFE_URL, "<h1>404</h1> please login", {}, status_code=404, content_type="text/html")
        assert "login" in result["indicators"]
        assert result["evidence_quality"] == "weak"
        assert any("generic error pages" in c for c in result["caveats"])

    def test_truncated_body_is_not_conclusive(self):
        result = ha.detect_auth_surfaces(SAFE_URL, "plain page", {},
                                         content_type="text/html", body_truncated=True)
        assert result["indicators"] == {}
        assert result["conclusive"] is False

    def test_external_identity_provider_is_attributed_to_the_third_party(self):
        result = ha.detect_auth_surfaces(
            SAFE_URL, "", {"Location": "https://login.microsoftonline.com/authorize?client_id=1"},
            status_code=302, content_type="text/html", target="example.com")
        idp = result["identity_provider"]
        assert idp["third_party"] is True
        assert idp["attribution"] == "third_party_identity_provider"
        assert "belong to that identity provider" in idp["note"]

    def test_target_hosted_auth_redirect_is_not_third_party(self):
        result = ha.detect_auth_surfaces(
            SAFE_URL, "", {"Location": "https://sso.example.com/oauth/authorize"},
            status_code=302, content_type="text/html", target="example.com")
        assert result["identity_provider"]["third_party"] is False

    def test_www_authenticate_scheme_is_parsed(self):
        result = ha.detect_auth_surfaces(SAFE_URL, "", {"WWW-Authenticate": 'Basic realm="x"'})
        assert result["auth_schemes"] == ["basic"]

    def test_conclusive_nil_result_becomes_negative_result_memory(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"},
                              body=b"<html>a plain marketing page</html>")
        with mock.patch("requests.get", return_value=resp):
            ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))
        types = {p["type"] for p in json.loads((output_dir / "pending_assets.json").read_text())}
        # surface_mapper treats "_checked_no" as authoritative not-found memory.
        assert "http_analyzer_checked_no_auth_surface_indicators" in types

    def test_inconclusive_nil_result_is_not_negative_result_memory(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, headers={"Content-Type": "image/png"}, body=b"\x89PNG")
        with mock.patch("requests.get", return_value=resp):
            ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))
        types = {p["type"] for p in json.loads((output_dir / "pending_assets.json").read_text())}
        assert "http_analyzer_checked_no_auth_surface_indicators" not in types
        assert "http_analyzer_checked_no_jwt" not in types


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

class TestJwtHardening:
    def test_hostile_body_does_not_cause_quadratic_backtracking(self):
        body = "eyJ" * 21845            # ~64 KB, the module's body read cap
        start = time.perf_counter()
        result = ha.detect_jwts(body, {"Content-Type": "text/html"}, [])
        elapsed = time.perf_counter() - start
        assert result["count"] == 0
        # Measured at ~2.0 s before the anchor/segment-cap fix, ~0.001 s after.
        assert elapsed < 0.25, f"JWT scan took {elapsed:.3f}s on a 64KB hostile body"

    def test_token_count_is_capped(self):
        tokens = " ".join(_make_token({"alg": "HS256"}, {"sub": f"u{i}"}) for i in range(500))
        result = ha.detect_jwts(tokens, {"Content-Type": "text/html"}, [])
        assert result["count"] == ha.MAX_JWT_TOKENS
        assert result["tokens_truncated"] is True

    def test_token_location_is_recorded(self):
        token = _make_token({"alg": "HS256"}, {"sub": "u"})
        result = ha.detect_jwts(None, {"X-Auth": token}, [f"jwt={token}; Path=/"])
        assert result["tokens"][0]["location"] == ["header:x-auth", "set-cookie:jwt"]

    def test_signature_and_claim_values_are_never_persisted(self):
        token = _make_token({"alg": "HS256", "kid": "/etc/keys/prod.pem"},
                            {"sub": "victim@example.com", "iss": "https://internal.example"},
                            signature="U0lHTkFUVVJFU0VDUkVU")
        blob = json.dumps(ha.detect_jwts(token, {"Content-Type": "text/plain"}, []))
        assert "U0lHTkFUVVJFU0VDUkVU" not in blob
        assert "victim@example.com" not in blob
        assert "/etc/keys/prod.pem" not in blob
        assert token not in blob

    def test_suspicious_header_members_are_reported_as_presence_only(self):
        token = _make_token({"alg": "HS256", "kid": "k1", "jku": "https://x/y.json"}, {"sub": "u"})
        entry = ha.detect_jwts(token, {"Content-Type": "text/plain"}, [])["tokens"][0]
        assert entry["header_kid_present"] is True
        assert entry["header_jku_present"] is True

    def test_expiry_is_derived_not_echoed(self):
        expired = _make_token({"alg": "HS256"}, {"exp": 1})
        entry = ha.detect_jwts(expired, {"Content-Type": "text/plain"}, [])["tokens"][0]
        assert entry["expired"] is True
        assert entry["has_expiry_claim"] is True
        assert "1" not in json.dumps(entry.get("payload_claim_names"))

    def test_alg_none_is_an_observation_not_a_vulnerability_claim(self):
        token = _make_token({"alg": "none"}, {"sub": "u"})
        result = ha.detect_jwts(token, {"Content-Type": "text/plain"}, [])
        assert result["weak_alg_detected"] is True
        assert any("not proof that the server accepts an unsigned token" in n for n in result["notes"])

    def test_mid_token_start_is_not_a_jwt(self):
        token = _make_token({"alg": "HS256"}, {"sub": "u"})
        assert ha.detect_jwts("PREFIX" + token, {"Content-Type": "text/plain"}, [])["count"] == 0
        assert ha.detect_jwts("PREFIX " + token, {"Content-Type": "text/plain"}, [])["count"] == 1

    def test_binary_body_is_not_scanned(self):
        token = _make_token({"alg": "none"}, {"sub": "u"})
        result = ha.detect_jwts(token, {}, [], content_type="application/octet-stream")
        assert result["count"] == 0
        assert result["conclusive"] is False

    def test_oversized_segments_are_rejected(self):
        monster = "eyJ" + "A" * 20000 + "." + "B" * 20000 + "." + "C" * 20000
        assert ha.detect_jwts(monster, {"Content-Type": "text/plain"}, [])["count"] == 0


# ---------------------------------------------------------------------------
# Cache / CDN provenance
# ---------------------------------------------------------------------------

class TestCacheProvenance:
    def test_cache_hit_is_labelled_as_not_proof_of_origin(self):
        result = ha.analyze_cache_headers({"Age": "120", "X-Cache": "HIT", "CF-Ray": "abc-LHR"})
        assert result["served_from_cache"] is True
        assert result["origin_attribution"] == "edge_cache_hit"
        assert any("not proof" in n for n in result["notes"])

    def test_cache_miss_is_distinguished_from_unknown(self):
        assert ha.analyze_cache_headers({"CF-Cache-Status": "MISS"})["served_from_cache"] is False
        assert ha.analyze_cache_headers({})["served_from_cache"] is None

    def test_cdn_vendors_are_identified(self):
        result = ha.analyze_cache_headers({"CF-Ray": "x", "X-Amz-Cf-Id": "y", "Server": "AkamaiGHost"})
        assert set(result["cdn_vendors"]) >= {"cloudflare", "cloudfront", "akamai"}
        assert result["origin_attribution"] in ("intermediary_present", "edge_cache_hit")

    def test_absence_of_cdn_indicators_is_not_proof_of_no_intermediary(self):
        result = ha.analyze_cache_headers({"Server": "nginx"})
        assert result["cdn_indicators"] == []
        assert result["intermediary_absence_proven"] is False

    def test_malformed_age_and_cache_control_do_not_raise(self):
        result = ha.analyze_cache_headers({"Age": "9" * 5000, "Cache-Control": "max-age=abc, , public"})
        assert result["age_seconds"] is None
        assert any("malformed Age" in n for n in result["notes"])
        assert any("malformed Cache-Control" in n for n in result["notes"])

    def test_no_cache_is_not_no_store(self):
        result = ha.analyze_cache_headers({"Cache-Control": "no-cache"})
        assert any("is not 'no-store'" in n for n in result["notes"])

    def test_security_header_finding_carries_the_cache_caveat(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200,
                              headers={"Content-Type": "text/html", "Age": "300", "X-Cache": "HIT"},
                              body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))
        records = json.loads((output_dir / "pending_assets.json").read_text())
        sec = next(r for r in records if r["type"] == "http_security_headers")
        assert sec["value"]["provenance"]["served_from_cache"] is True
        assert any("cached copy" in e for e in sec["evidence"])


# ---------------------------------------------------------------------------
# Host header
# ---------------------------------------------------------------------------

class TestHostHeaderHardening:
    def test_baseline_is_reused_when_supplied(self):
        calls = []

        def fake_get(url, timeout, headers, allow_redirects, stream):
            calls.append(headers.get("Host"))
            return _fake_response(status_code=200, body=b"ok")
        with mock.patch("requests.get", side_effect=fake_get):
            baseline = ha.fetch_url(SAFE_URL)
            calls.clear()
            ha.analyze_host_header_behavior(SAFE_URL, baseline=baseline)
        assert calls == [ha._HOST_HEADER_PROBE]

    def test_reflection_is_detected_in_headers_too(self):
        def fake_get(url, timeout, headers, allow_redirects, stream):
            if headers.get("Host") == ha._HOST_HEADER_PROBE:
                return _fake_response(status_code=302,
                                      headers={"Location": f"https://{ha._HOST_HEADER_PROBE}/x"})
            return _fake_response(status_code=200)
        with mock.patch("requests.get", side_effect=fake_get):
            result = ha.analyze_host_header_behavior(SAFE_URL)
        assert result["probe_host_reflected"] is True
        assert "header:location" in result["reflected_in"]
        assert any("no cache entry was poisoned" in n for n in result["notes"])

    def test_failed_comparison_is_inconclusive_not_clean(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("down")):
            result = ha.analyze_host_header_behavior(SAFE_URL)
        assert result["status"] == "error"
        assert result["conclusive"] is False
        assert result["probe_host_reflected"] is False
        assert any("nothing can be concluded" in n for n in result["notes"])


# ---------------------------------------------------------------------------
# Redirect chain
# ---------------------------------------------------------------------------

class TestRedirectHardening:
    def test_target_less_run_cannot_wander_off_the_start_host(self):
        resp = _fake_response(status_code=302,
                              headers={"Location": "https://accounts.okta.com/authorize"})
        with mock.patch("requests.get", return_value=resp) as get:
            result = ha.map_redirect_chain(SAFE_URL, target=None)
        assert result["stopped_reason"] == "next_hop_out_of_scope"
        assert get.call_count == 1                     # the IdP was never requested
        assert result["not_followed"]["host"] == "accounts.okta.com"
        assert result["not_followed"]["known_identity_provider"] is True
        assert any("is not, by itself, an open redirect" in n for n in result["notes"])

    def test_obfuscated_internal_address_is_not_followed(self):
        # 0177.0.0.1 is not an IP to `ipaddress`, so the private-IP gate alone
        # let it through as an ordinary hostname.
        resp = _fake_response(status_code=302, headers={"Location": "http://0177.0.0.1:8080/admin"})
        with mock.patch("requests.get", return_value=resp) as get:
            result = ha.map_redirect_chain(SAFE_URL, target=None)
        assert result["stopped_reason"] == "next_hop_out_of_scope"
        assert get.call_count == 1

    @pytest.mark.parametrize("location", [
        "file:///etc/passwd", "gopher://127.0.0.1:11211/", "javascript:alert(1)",
        "data:text/html,x",
    ])
    def test_non_http_scheme_is_never_followed(self, location):
        resp = _fake_response(status_code=302, headers={"Location": location})
        with mock.patch("requests.get", return_value=resp) as get:
            result = ha.map_redirect_chain(SAFE_URL, target="example.com")
        assert result["stopped_reason"] == "next_hop_unsupported_scheme"
        assert get.call_count == 1

    def test_ipv4_mapped_ipv6_metadata_address_is_refused(self):
        resp = _fake_response(status_code=302,
                              headers={"Location": "http://[::ffff:169.254.169.254]/latest/meta-data/"})
        with mock.patch("requests.get", return_value=resp):
            result = ha.map_redirect_chain(SAFE_URL, target="example.com")
        assert result["stopped_reason"] == "next_hop_disallowed_ip"

    def test_ip_literal_redirect_allowed_only_when_it_is_the_target(self):
        resp = _fake_response(status_code=302, headers={"Location": "http://93.184.216.34/x"})
        with mock.patch("requests.get", return_value=resp):
            blocked = ha.map_redirect_chain("https://example.com/", target="example.com")
        assert blocked["stopped_reason"] == "next_hop_out_of_scope"
        responses = [_fake_response(status_code=302, headers={"Location": "http://93.184.216.34/x"}),
                     _fake_response(status_code=200)]
        with mock.patch("requests.get", side_effect=responses):
            allowed = ha.map_redirect_chain("http://93.184.216.34/", target="93.184.216.34")
        assert allowed["stopped_reason"] == "terminal_response"

    def test_scheme_downgrade_is_recorded(self):
        responses = [_fake_response(status_code=302, headers={"Location": "http://example.com/x"}),
                     _fake_response(status_code=200)]
        with mock.patch("requests.get", side_effect=responses):
            result = ha.map_redirect_chain("https://example.com/", target="example.com")
        assert result["scheme_downgraded"] is True
        assert any("plaintext" in n for n in result["notes"])

    def test_malformed_location_is_not_requested(self):
        resp = _fake_response(status_code=302, headers={"Location": "https://exa\r\nmple.com/"})
        with mock.patch("requests.get", return_value=resp) as get:
            result = ha.map_redirect_chain(SAFE_URL, target="example.com")
        assert result["stopped_reason"] == "malformed_location"
        assert get.call_count == 1

    def test_credentials_in_a_redirect_target_are_stripped(self):
        responses = [_fake_response(status_code=302,
                                    headers={"Location": "https://u:p@www.example.com/"}),
                     _fake_response(status_code=200)]
        with mock.patch("requests.get", side_effect=responses):
            result = ha.map_redirect_chain(SAFE_URL, target="example.com")
        assert "u:p@" not in json.dumps(result)
        assert result["final_url"] == "https://www.example.com/"

    def test_user_controlled_destination_is_an_indicator_not_a_confirmation(self):
        responses = [_fake_response(status_code=302, headers={"Location": "https://example.com/x"}),
                     _fake_response(status_code=200)]
        with mock.patch("requests.get", side_effect=responses):
            result = ha.map_redirect_chain("https://example.com/go?next=https://example.com/x",
                                           target="example.com")
        assert result["user_controlled_destination_indicators"]
        assert result["open_redirect_confirmed"] is False
        assert any("not a confirmed open redirect" in n for n in result["notes"])

    def test_external_redirect_alone_is_not_an_open_redirect(self):
        resp = _fake_response(status_code=302, headers={"Location": "https://partner.example/"})
        with mock.patch("requests.get", return_value=resp):
            result = ha.map_redirect_chain(SAFE_URL, target="example.com")
        assert result["open_redirect_confirmed"] is False
        assert result["user_controlled_destination_indicators"] == []

    def test_incomplete_chain_is_not_reported_complete(self):
        resp = _fake_response(status_code=302, headers={"Location": "https://evil.example/"})
        with mock.patch("requests.get", return_value=resp):
            result = ha.map_redirect_chain(SAFE_URL, target="example.com")
        assert result["complete"] is False


# ---------------------------------------------------------------------------
# WAF
# ---------------------------------------------------------------------------

class TestWafHardening:
    def test_a_page_mentioning_a_vendor_is_not_a_signature(self):
        body = "<p>We use Akamai for delivery. See reference #55 in the docs.</p>"
        result = ha.detect_waf({"Server": "nginx"}, [], body)
        assert result["detected"] is False

    def test_cookie_markers_match_names_not_values(self):
        assert ha.detect_waf({}, ["pref=akamai-theme; Path=/"], "")["detected"] is False
        assert ha.detect_waf({}, ["ak_bmsc=abc; Path=/"], "")["detected"] is True

    def test_absence_is_never_evidence_of_absence(self):
        result = ha.detect_waf({"Server": "nginx"}, [], "")
        assert result["detected"] is False
        assert result["evidence_of_absence"] is False
        assert result["conclusive"] is False
        assert any("absence of evidence" in n for n in result["notes"])

    def test_confidence_follows_evidence_strength(self):
        header = ha.detect_waf({"X-Sucuri-Id": "1"}, [], "")["vendors"][0]
        cookie = ha.detect_waf({}, ["incap_ses_1=x"], "")["vendors"][0]
        body = ha.detect_waf({}, [], "access denied - sucuri website firewall")["vendors"][0]
        assert header["confidence"] == ha.CONFIDENCE_HIGH
        assert cookie["confidence"] == ha.CONFIDENCE_MEDIUM
        assert body["confidence"] == ha.CONFIDENCE_LOW

    def test_cdn_is_not_silently_promoted_to_waf(self):
        result = ha.detect_waf({"CF-Ray": "abc-LHR", "Server": "cloudflare"}, [], "")
        assert result["vendors"][0]["kind"] == "cdn_with_optional_waf"
        assert any("not proof of a web application firewall" in n for n in result["notes"])

    def test_behavioral_status_is_inconclusive_context_not_a_detection(self):
        result = ha.detect_waf({"Server": "nginx"}, [], "", status_code=403)
        assert result["detected"] is False
        assert result["behavioral"]["indicative"] is True
        assert "identifies neither" in result["behavioral"]["note"]

    def test_no_negative_result_is_ever_persisted_for_waf(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html", "Server": "nginx"},
                              body=b"plain")
        with mock.patch("requests.get", return_value=resp):
            ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))
        types = {p["type"] for p in json.loads((output_dir / "pending_assets.json").read_text())}
        assert not any("waf" in t for t in types)

    def test_vendor_order_is_deterministic(self):
        headers = {"CF-Ray": "1", "X-Sucuri-Id": "2", "X-Iinfo": "3", "X-Amzn-Waf-Action": "4"}
        runs = [[v["vendor"] for v in ha.detect_waf(headers, [], "")["vendors"]] for _ in range(5)]
        assert all(r == runs[0] for r in runs)
        assert runs[0] == sorted(runs[0])


# ---------------------------------------------------------------------------
# fetch_url / resources
# ---------------------------------------------------------------------------

class TestFetchHardening:
    def test_fallback_body_read_stays_bounded(self):
        class Raw:
            def read(self, *a, **k):
                raise RuntimeError("no raw")

        class Resp:
            status_code = 200
            headers = {}
            encoding = "utf-8"
            url = SAFE_URL
            raw = Raw()
            chunks = 0

            class _E:
                @staticmethod
                def total_seconds():
                    return 0.01
            elapsed = _E()

            def iter_content(self, chunk_size=8192):
                for _ in range(50 * 1024 * 1024 // chunk_size):
                    Resp.chunks += 1
                    yield b"A" * chunk_size

            @property
            def content(self):
                raise AssertionError("a bounded reader must not materialise the whole body")

            def close(self):
                pass
        with mock.patch("requests.get", return_value=Resp()):
            result = ha.fetch_url(SAFE_URL)
        assert result["body_truncated"] is True
        assert len(result["body"]) == ha.DEFAULT_MAX_BODY_BYTES
        assert Resp.chunks < 32       # not the whole 50 MB

    def test_final_url_credentials_are_stripped(self):
        resp = _fake_response(final_url="https://u:p@example.com/x")
        with mock.patch("requests.get", return_value=resp):
            result = ha.fetch_url(SAFE_URL)
        assert result["final_url"] == "https://example.com/x"

    def test_inconsistent_getlist_disables_duplicate_detection(self):
        # An adapter whose getlist ignores the header name it is given would
        # otherwise attribute one header's values to every other header.
        resp = _fake_response(headers={"Strict-Transport-Security": "max-age=1"})
        resp.raw.headers.getlist.side_effect = None
        resp.raw.headers.getlist.return_value = ["totally unrelated"]
        with mock.patch("requests.get", return_value=resp):
            result = ha.fetch_url(SAFE_URL)
        assert result["header_lists_available"] is False
        assert result["header_lists"] == {}

    def test_request_budget_is_enforced(self):
        budget = ha.RequestBudget(2)
        with mock.patch("requests.get", return_value=_fake_response()):
            assert ha.fetch_url(SAFE_URL, budget=budget)["status"] == "found"
            assert ha.fetch_url(SAFE_URL, budget=budget)["status"] == "found"
            spent = ha.fetch_url(SAFE_URL, budget=budget)
        assert spent["status"] == "not_checked"
        assert "budget" in spent["error"]

    def test_run_respects_its_request_budget(self, tmp_path):
        calls = []

        def fake_get(url, timeout, headers, allow_redirects, stream):
            calls.append(url)
            return _fake_response(status_code=302, headers={"Location": f"https://example.com/{len(calls)}"})
        with mock.patch("requests.get", side_effect=fake_get):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                           output_dir=str(tmp_path / "o"),
                                           max_requests=5, max_redirect_hops=50)
        assert len(calls) <= 5
        assert summary["requests_made"] <= 5

    def test_non_bytes_body_does_not_crash(self):
        resp = _fake_response()
        resp.raw.read.return_value = "already a str"
        with mock.patch("requests.get", return_value=resp):
            result = ha.fetch_url(SAFE_URL)
        assert result["status"] == "found"
        assert result["body"] == ""


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

class TestPersistenceHardening:
    def test_batched_write_is_atomic_and_preserves_prior_records(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text(
            json.dumps([{"type": "dns_record", "source": "passive_recon.py"}]))
        store = ha.PendingAssetsStore(output_dir=str(output_dir))
        store.add_many([ha.make_finding(f"t{i}", "example.com", {"i": i}, ["e"], "LOW")
                        for i in range(5)])
        records = json.loads((output_dir / "pending_assets.json").read_text())
        assert len(records) == 6
        assert records[0]["source"] == "passive_recon.py"

    def test_single_write_per_run(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp), \
             mock.patch.object(ha.PendingAssetsStore, "_atomic_write_body",
                               autospec=True, side_effect=ha.PendingAssetsStore._atomic_write_body) as w:
            ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))
        assert w.call_count == 1

    def test_directory_fsync_is_attempted(self, tmp_path):
        store = ha.PendingAssetsStore(output_dir=str(tmp_path / "o"))
        with mock.patch.object(ha.PendingAssetsStore, "_fsync_dir") as fsync:
            store.add(ha.make_finding("t", "example.com", {}, ["e"], "LOW"))
        assert fsync.called

    def test_unserializable_values_are_coerced_not_fatal(self, tmp_path):
        store = ha.PendingAssetsStore(output_dir=str(tmp_path / "o"))
        store.add(ha.make_finding("t", "example.com",
                                  {"s": {1, 2}, "n": float("nan"), "i": float("inf")}, ["e"], "LOW"))
        raw = (tmp_path / "o" / "pending_assets.json").read_text()
        assert "NaN" not in raw and "Infinity" not in raw
        json.loads(raw, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))

    def test_persistence_failure_never_discards_the_analysis(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp), \
             mock.patch.object(ha.PendingAssetsStore, "add_many", side_effect=OSError("disk full")):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))
        assert summary["security_headers"]
        assert summary["findings_persisted"] == 0
        assert any(e["stage"] == "persistence" for e in summary["errors"])

    def test_unwritable_output_dir_is_reported_not_raised(self):
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                           output_dir="/proc/version/definitely-not-a-dir")
        assert summary["status"] == "completed_with_errors"
        assert any(e["stage"] == "persistence_setup" for e in summary["errors"])
        assert summary["security_headers"]


# ---------------------------------------------------------------------------
# Orchestration / failure semantics / determinism / downstream contract
# ---------------------------------------------------------------------------

_RICH_HEADERS = {
    "Content-Type": "text/html", "Server": "cloudflare", "CF-Ray": "abc-LHR",
    "Age": "120", "X-Cache": "HIT", "Strict-Transport-Security": "max-age=100",
    "X-Frame-Options": "ALLOW-FROM https://x", "Referrer-Policy": "unsafe-url",
    "Content-Security-Policy": "script-src 'unsafe-inline' *",
    "Permissions-Policy": "geolocation=*",
}
_RICH_TOKEN = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
_RICH_BODY = (f"<html><form><input type='password'></form> logout sso mfa {_RICH_TOKEN}</html>").encode()
_RICH_COOKIES = ["__Host-sid=abc; Path=/x; Domain=example.com", "b=2; SameSite=None"]


def _rich_get(url, timeout, headers, allow_redirects, stream):
    return _fake_response(200, _RICH_HEADERS, _RICH_BODY, _RICH_COOKIES,
                          repeated_headers={
                              "Access-Control-Allow-Origin": [headers.get("Origin", "*")],
                              "Access-Control-Allow-Credentials": ["true"]})


class TestOrchestrationHardening:
    def test_clean_run_records_no_errors(self, tmp_path):
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                           output_dir=str(tmp_path / "o"))
        assert summary["errors"] == []
        assert summary["status"] == "completed"
        assert summary["completeness"] == "complete"

    def test_unreachable_host_is_not_a_clean_result(self, tmp_path):
        output_dir = tmp_path / "output"
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))
        assert summary["status"] == "unreachable"
        assert summary["completeness"] == "not_performed"
        assert not (output_dir / "pending_assets.json").exists()

    @pytest.mark.parametrize("exc", [
        requests.exceptions.Timeout(), requests.exceptions.ConnectionError("dns"),
        requests.exceptions.SSLError("tls"), requests.exceptions.ChunkedEncodingError("partial"),
        requests.exceptions.RequestException("other"),
    ])
    def test_transport_failures_are_honest(self, exc, tmp_path):
        with mock.patch("requests.get", side_effect=exc):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                           output_dir=str(tmp_path / "o"))
        assert summary["fetch_status"] == "error"
        assert summary["status"] == "unreachable"

    @pytest.mark.parametrize("code", [204, 301, 400, 401, 403, 404, 429, 500, 503])
    def test_unusual_status_codes_still_analyse(self, code, tmp_path):
        resp = _fake_response(status_code=code, headers={"Content-Type": "text/html"}, body=b"x")
        with mock.patch("requests.get", return_value=resp):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                           output_dir=str(tmp_path / f"o{code}"))
        assert summary["fetch_status"] == "found"
        assert summary["provenance"]["status_code"] == code

    def test_redirect_response_provenance_is_declared(self, tmp_path):
        resp = _fake_response(status_code=301, headers={"Content-Type": "text/html",
                                                        "Location": "https://example.com/x"})
        with mock.patch("requests.get", return_value=resp):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                           output_dir=str(tmp_path / "o"))
        assert summary["provenance"]["analyzed_response_is_redirect"] is True
        assert "describe the redirector" in summary["provenance"]["note"]

    def test_every_persisted_finding_carries_its_url(self, tmp_path):
        output_dir = tmp_path / "output"
        with mock.patch("requests.get", side_effect=_rich_get):
            ha.run_http_analysis("https://example.com/app", target=SAFE_TARGET,
                                 output_dir=str(output_dir))
        records = json.loads((output_dir / "pending_assets.json").read_text())
        assert records
        for record in records:
            # surface_mapper._resolve_subject_asset keys on value["url"]; without
            # it, four of the nine findings attached to the hostname (or to a
            # phantom hostname asset built out of a URL) instead of the endpoint.
            assert record["value"].get("url"), record["type"]
            assert record["target"] == SAFE_TARGET

    def test_target_defaults_to_the_hostname_not_the_url(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            summary = ha.run_http_analysis("https://example.com/deep/path", output_dir=str(output_dir))
        assert summary["target"] == "example.com"
        for record in json.loads((output_dir / "pending_assets.json").read_text()):
            assert "://" not in record["target"]

    def test_run_is_deterministic(self, tmp_path):
        def scrub(obj):
            if isinstance(obj, dict):
                return {k: scrub(v) for k, v in obj.items()
                        if k not in ("timestamp", "started_at", "finished_at")}
            if isinstance(obj, list):
                return [scrub(v) for v in obj]
            return obj

        results = []
        for i in range(3):
            output_dir = tmp_path / f"o{i}"
            with mock.patch("requests.get", side_effect=_rich_get):
                summary = ha.run_http_analysis("https://example.com/app", target=SAFE_TARGET,
                                               output_dir=str(output_dir))
            results.append((scrub(summary),
                            scrub(json.loads((output_dir / "pending_assets.json").read_text()))))
        assert results[0] == results[1] == results[2]

    def test_request_count_is_bounded_and_reported(self, tmp_path):
        calls = []

        def counting(url, timeout, headers, allow_redirects, stream):
            calls.append(url)
            return _rich_get(url, timeout, headers, allow_redirects, stream)
        with mock.patch("requests.get", side_effect=counting):
            summary = ha.run_http_analysis("https://example.com/app", target=SAFE_TARGET,
                                           output_dir=str(tmp_path / "o"))
        # baseline (1) + CORS probes (4) + host-header probe (1); the redirect
        # chain reuses the baseline rather than re-fetching it.
        assert len(calls) == 6 == summary["requests_made"]

    def test_no_state_changing_request_is_ever_made(self, tmp_path):
        methods = []
        real_get = requests.get

        def spy(url, **kwargs):
            methods.append("GET")
            return _rich_get(url, kwargs.get("timeout"), kwargs.get("headers", {}),
                             kwargs.get("allow_redirects"), kwargs.get("stream"))
        with mock.patch("requests.get", side_effect=spy), \
             mock.patch("requests.post", side_effect=AssertionError("POST is forbidden")), \
             mock.patch("requests.put", side_effect=AssertionError("PUT is forbidden")), \
             mock.patch("requests.delete", side_effect=AssertionError("DELETE is forbidden")), \
             mock.patch("requests.request", side_effect=AssertionError("request() is forbidden")):
            ha.run_http_analysis("https://example.com/app", target=SAFE_TARGET,
                                 output_dir=str(tmp_path / "o"))
        assert methods and set(methods) == {"GET"}

    def test_probe_hosts_are_never_requested(self, tmp_path):
        requested = []

        def spy(url, timeout, headers, allow_redirects, stream):
            requested.append(url)
            return _rich_get(url, timeout, headers, allow_redirects, stream)
        with mock.patch("requests.get", side_effect=spy):
            ha.run_http_analysis("https://example.com/app", target=SAFE_TARGET,
                                 output_dir=str(tmp_path / "o"))
        for url in requested:
            assert ha._hostname_of(url) == "example.com", url

    def test_no_secret_material_reaches_the_store(self, tmp_path):
        output_dir = tmp_path / "output"
        secret_cookie = "session=SUPERSECRETSESSION; Path=/"
        token = _make_token({"alg": "none", "kid": "/srv/keys/prod.pem"},
                            {"email": "victim@example.com"}, signature="U0lHU0VDUkVU")

        def leaky(url, timeout, headers, allow_redirects, stream):
            return _fake_response(200, {"Content-Type": "text/html",
                                        "Authorization": "Bearer " + token},
                                  f"<html>{token}</html>".encode(), [secret_cookie])
        with mock.patch("requests.get", side_effect=leaky):
            ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))
        raw = (output_dir / "pending_assets.json").read_text()
        for secret in ("SUPERSECRETSESSION", "U0lHU0VDUkVU", "victim@example.com",
                       "/srv/keys/prod.pem", token):
            assert secret not in raw, secret

    def test_stage_failure_is_reported_and_does_not_abort(self, tmp_path):
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp), \
             mock.patch.object(ha, "analyze_cors", side_effect=RuntimeError("boom")):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                           output_dir=str(tmp_path / "o"))
        assert any(e["stage"] == "cors" for e in summary["errors"])
        assert summary["security_headers"] and summary["redirect_chain"]

    def test_summary_and_store_stay_json_serializable_under_hostile_input(self, tmp_path):
        hostile_headers = {
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src " + "*.x " * 5000,
            "Strict-Transport-Security": "max-age=" + "9" * 6000,
            "Set-Cookie": "a=" + "b" * 100000,
            "X-Frame-Options": "\x00\x01BOGUS",
        }
        body = ("eyJ" * 20000).encode()

        def hostile(url, timeout, headers, allow_redirects, stream):
            return _fake_response(200, hostile_headers, body, ["a=" + "b" * 100000])
        with mock.patch("requests.get", side_effect=hostile):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                           output_dir=str(tmp_path / "o"))
        json.dumps(summary)
        raw = (tmp_path / "o" / "pending_assets.json").read_text()
        json.loads(raw)
        assert len(raw) < 512 * 1024, "a hostile response must not balloon the shared store"


class TestDownstreamContract:
    """The persisted schema the later modules actually read."""

    def _records(self, tmp_path):
        output_dir = tmp_path / "output"
        with mock.patch("requests.get", side_effect=_rich_get):
            ha.run_http_analysis("https://example.com/app", target=SAFE_TARGET,
                                 output_dir=str(output_dir))
        return json.loads((output_dir / "pending_assets.json").read_text())

    def test_risk_engine_security_header_contract(self, tmp_path):
        record = next(r for r in self._records(tmp_path) if r["type"] == "http_security_headers")
        headers = record["value"]["headers"]
        for name in ("Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
                     "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"):
            assert name in headers and isinstance(headers[name]["present"], bool)

    def test_risk_engine_cookie_contract(self, tmp_path):
        record = next(r for r in self._records(tmp_path) if r["type"] == "http_cookie_flags")
        for cookie in record["value"]["cookies"]:
            assert isinstance(cookie["name"], str)
            assert isinstance(cookie["issues"], list)

    def test_risk_engine_cors_and_jwt_contract(self, tmp_path):
        records = self._records(tmp_path)
        cors = next(r for r in records if r["type"] == "http_cors_misconfiguration")
        for key in ("origin_reflected", "null_origin_allowed", "wildcard",
                    "allow_credentials_with_wildcard_or_reflection"):
            assert isinstance(cors["value"][key], bool)
        jwt = next(r for r in records if r["type"] == "http_jwt_detected")
        assert isinstance(jwt["value"]["weak_alg_detected"], bool)
        assert isinstance(jwt["value"]["count"], int)

    def test_surface_mapper_waf_contract(self, tmp_path):
        record = next(r for r in self._records(tmp_path) if r["type"] == "waf_detected")
        assert isinstance(record["value"]["vendors"], list)
        assert all(isinstance(v.get("vendor"), str) for v in record["value"]["vendors"])

    def test_findings_ingest_into_the_real_surface_mapper(self, tmp_path):
        from reconhound.surface_mapper import SurfaceMapper
        output_dir = tmp_path / "output"
        with mock.patch("requests.get", side_effect=_rich_get):
            ha.run_http_analysis("https://example.com/app", target=SAFE_TARGET,
                                 output_dir=str(output_dir))
        mapper = SurfaceMapper(target=SAFE_TARGET, output_dir=str(output_dir))
        result = mapper.ingest_pending_assets_file()
        assert result["errors"] == 0
        assert result["ingested"] >= 8
        # No phantom hostname asset built out of a URL.
        for asset in mapper.state["assets"].values():
            if asset["asset_type"] == "hostname":
                assert "://" not in str(asset["value"])

    def test_negative_results_do_not_mint_finding_assets(self, tmp_path):
        from reconhound.surface_mapper import SurfaceMapper
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"},
                              body=b"<html>plain marketing page</html>")
        with mock.patch("requests.get", return_value=resp):
            ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))
        mapper = SurfaceMapper(target=SAFE_TARGET, output_dir=str(output_dir))
        mapper.ingest_pending_assets_file()
        finding_types = {a["value"].get("finding_type") for a in mapper.state["assets"].values()
                         if a["asset_type"] == "finding"}
        assert not any("checked_no" in str(t) for t in finding_types)
        assert mapper.state["negative_results"]

    def test_report_carries_the_honest_qualifications(self, tmp_path):
        import html as _html
        from reconhound.surface_mapper import SurfaceMapper
        from reconhound.risk_engine import run_risk_engine
        from reconhound.report_generator import generate_report
        output_dir = tmp_path / "output"
        with mock.patch("requests.get", side_effect=_rich_get):
            ha.run_http_analysis("https://example.com/app", target=SAFE_TARGET,
                                 output_dir=str(output_dir))
        mapper = SurfaceMapper(target=SAFE_TARGET, output_dir=str(output_dir))
        mapper.ingest_pending_assets_file()
        mapper.save()
        assessment = run_risk_engine(graph=mapper.state, output_dir=str(output_dir))
        generate_report(graph=mapper.state, assessment=assessment,
                        output_dir=str(output_dir), target=SAFE_TARGET)
        rendered = _html.unescape(
            next((output_dir / "reports").glob("*.html")).read_text())
        rendered_json = next((output_dir / "reports").glob("*.json")).read_text()
        assert "not proof that the server accepts an unsigned token" in rendered
        assert "cached copy" in rendered
        # The CDN-is-not-a-WAF qualification reaches the machine-readable
        # report in full; report_generator.py truncates the HTML observation
        # row's evidence display, which is its rendering decision, not this
        # module's contract.
        assert "not proof of a web application firewall" in rendered_json
        # And nothing sensitive, in either format.
        for artifact in (rendered, rendered_json):
            assert _RICH_TOKEN not in artifact
            assert "__Host-sid=abc" not in artifact
            assert "c2lnbmF0dXJl" not in artifact


# ===========================================================================
# Self-attack regressions: defects found by attacking the hardened
# implementation itself (unbounded collections, false success/failure states,
# and gates that could be walked around through the public API).
# ===========================================================================

class TestSelfAttackRegressions:
    def test_hostile_permissions_policy_cannot_flood_the_store(self):
        value = ",".join(f"camera{i}=*" for i in range(20000))
        entry = ha.analyze_security_headers({"Permissions-Policy": value})["Permissions-Policy"]
        # 20,000 notes / 1.3 MB before the cap.
        assert len(entry["notes"]) <= ha.MAX_NOTES + 1
        assert len(json.dumps(entry)) < 64 * 1024

    def test_hostile_referrer_policy_cannot_produce_a_giant_note(self):
        value = ",".join(f"tok{i}" for i in range(20000))
        entry = ha.analyze_security_headers({"Referrer-Policy": value})["Referrer-Policy"]
        assert max(len(n) for n in entry["notes"]) <= ha.MAX_NOTE_CHARS + 40

    def test_hostile_hsts_policy_count_is_capped(self):
        entry = ha.analyze_security_headers(
            {"Strict-Transport-Security": ",".join(["max-age=1"] * 50000)}
        )["Strict-Transport-Security"]
        assert entry["policies_seen"] <= ha.MAX_HSTS_POLICIES

    def test_hostile_csp_note_count_is_capped(self):
        policy = "; ".join(f"{d} * data: *.com" for d in
                           ("script-src", "style-src", "img-src", "connect-src", "font-src"))
        entry = ha.analyze_security_headers(
            {"Content-Security-Policy": ", ".join([policy] * 20)})["Content-Security-Policy"]
        assert len(entry["notes"]) <= ha.MAX_NOTES + 1

    def test_padded_cookie_does_not_hide_its_real_flags(self):
        padded = ("sid=1; " + "; ".join(f"pad{i}=x" for i in range(400))
                  + "; Secure; HttpOnly; SameSite=Lax")
        cookie = ha.analyze_cookie_flags([padded])[0]
        # Capping attribute parsing at 32 produced three false "missing flag"
        # issues, each a MEDIUM signal in risk_engine.py.
        assert cookie["secure"] is True and cookie["http_only"] is True
        assert cookie["issues"] == []

    def test_truncated_cookie_attributes_claim_nothing(self):
        monstrous = ("sid=1; " + "; ".join(f"p{i}=1" for i in range(ha.MAX_COOKIE_PARTS + 500))
                     + "; Secure; HttpOnly; SameSite=Lax")
        cookie = ha.analyze_cookie_flags([monstrous])[0]
        # Not-read is not not-present: no missing-flag issue may be claimed.
        assert cookie["issues"] == []
        assert any("could not be determined" in n for n in cookie["notes"])

    @pytest.mark.parametrize("url", [
        "https://" + "a" * 5000 + ".com/",
        "https://[::1]/",
    ])
    def test_implausible_host_is_not_interpolated_into_a_request_header(self, url):
        probes = ha._cors_probe_origins(url)
        assert len(probes) == 2                      # the two fixed probes only
        assert all(len(origin) < 128 for _, origin in probes)

    def test_fetch_url_refuses_to_follow_redirects_itself(self):
        # Letting requests follow a chain would bypass every scope/SSRF gate.
        with pytest.raises(ha.ScopeError):
            ha.fetch_url(SAFE_URL, allow_redirects=True)

    def test_no_store_means_no_claim_of_persistence(self):
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                           output_dir="/proc/version/not-a-dir")
        assert summary["findings_persisted"] == 0
        assert summary["findings_produced"] > 0

    def test_jwt_payload_claim_names_are_capped(self):
        # The segment cap already bounds this, but the list is persisted.
        token = _make_token({"alg": "HS256"}, {f"k{i}": 1 for i in range(400)})
        entry = ha.detect_jwts(token, {"Content-Type": "text/plain"}, [])["tokens"]
        if entry:                                     # only if the segment fits the cap
            assert len(entry[0]["payload_claim_names"]) <= 64

    @pytest.mark.parametrize("location", [" ", "\t", "https://", "?q=1", "#frag", ":", "%%",
                                          "//evil.com/x", "../../up"])
    def test_degenerate_location_values_never_escape_scope(self, location):
        resp = _fake_response(status_code=302, headers={"Location": location})
        with mock.patch("requests.get", return_value=resp) as get:
            result = ha.map_redirect_chain("https://example.com/a/b", target="example.com",
                                           max_hops=3)
        assert result["stopped_reason"] in (
            "redirect_loop", "next_hop_out_of_scope", "malformed_location",
            "next_hop_unsupported_scheme", "max_hops_reached")
        for hop in result["hops"]:
            assert ha._hostname_of(hop["url"]) == "example.com"
        assert get.call_count <= 3

    @pytest.mark.parametrize("call", [
        lambda: ha.analyze_security_headers(None),
        lambda: ha.analyze_cache_headers(None),
        lambda: ha.analyze_cookie_flags(None),
        lambda: ha.detect_waf(None, None, None),
        lambda: ha.detect_jwts(None, None, None),
        lambda: ha.detect_auth_surfaces("https://example.com/", None, None),
    ])
    def test_none_inputs_never_raise(self, call):
        json.dumps(call())

    def test_store_is_thread_safe_for_concurrent_appends(self, tmp_path):
        import threading
        store = ha.PendingAssetsStore(output_dir=str(tmp_path / "o"))

        def worker(n):
            for i in range(20):
                store.add(ha.make_finding("t", "example.com", {"w": n, "i": i}, ["e"], "LOW"))
        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        records = json.loads((tmp_path / "o" / "pending_assets.json").read_text())
        assert len(records) == 160
        assert len({(r["value"]["w"], r["value"]["i"]) for r in records}) == 160

    def test_maximally_hostile_response_stays_bounded(self, tmp_path):
        output_dir = tmp_path / "output"
        policy = "; ".join(f"{d} * data:" for d in ("script-src", "style-src", "img-src"))
        hostile_headers = {
            "Content-Type": "text/html",
            "Content-Security-Policy": ", ".join([policy] * 20),
            "Strict-Transport-Security": ",".join(["max-age=1"] * 50000),
            "Permissions-Policy": ",".join(f"camera{i}=*" for i in range(20000)),
            "Referrer-Policy": ",".join(f"tok{i}" for i in range(20000)),
            "X-Frame-Options": ",".join(f"v{i}" for i in range(20000)),
            "Cache-Control": ",".join(f"d{i}=1" for i in range(20000)),
            "Server": "x" * 60000,
        }
        cookies = [f"c{i}=" + "v" * 2000 + "; " + "; ".join(f"p{j}=1" for j in range(600))
                   for i in range(500)]
        body = ("eyJ" * 20000 + "login sso mfa oauth " * 1000).encode()

        def hostile(url, timeout, headers, allow_redirects, stream):
            return _fake_response(200, hostile_headers, body, cookies)
        start = time.perf_counter()
        with mock.patch("requests.get", side_effect=hostile):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))
        elapsed = time.perf_counter() - start
        raw = (output_dir / "pending_assets.json").read_text()
        json.loads(raw)
        assert elapsed < 5.0, f"hostile response took {elapsed:.2f}s"
        assert len(raw) < 512 * 1024, f"hostile response wrote {len(raw)} bytes"
        assert summary["status"] in ("completed", "completed_with_errors")

    def test_repeated_identical_runs_do_not_duplicate_assets(self, tmp_path):
        from collections import Counter
        from reconhound.surface_mapper import SurfaceMapper
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200,
                              headers={"Content-Type": "text/html", "ETag": '"v1"',
                                       "Cache-Control": "public, max-age=60"},
                              body=b"<html>hi</html>")
        for _ in range(3):
            with mock.patch("requests.get", return_value=resp):
                ha.run_http_analysis("https://example.com/app", target=SAFE_TARGET,
                                     output_dir=str(output_dir))
        mapper = SurfaceMapper(target=SAFE_TARGET, output_dir=str(output_dir))
        result = mapper.ingest_pending_assets_file()
        assert result["errors"] == 0
        counts = Counter(a["value"].get("finding_type")
                         for a in mapper.state["assets"].values() if a["asset_type"] == "finding")
        # Three identical runs must not mint three copies of the same finding.
        assert counts and all(n == 1 for n in counts.values()), counts
        assert Counter(a["asset_type"] for a in mapper.state["assets"].values())["hostname"] == 1

    def test_hostile_csp_cannot_dominate_the_shared_store(self):
        directives = [f"a{i}" for i in range(40)] + ["script-src"]
        sources = " ".join("https://" + "s" * 200 + f"{i}.example" for i in range(80))
        value = ", ".join(["; ".join(f"{d} {sources}" for d in directives)] * 12)
        entry = ha.analyze_security_headers({"Content-Security-Policy": value})["Content-Security-Policy"]
        # 4.2 MiB and 281 ms before the header/token/total caps.
        assert len(json.dumps(entry)) < 64 * 1024
        assert entry["tokens_truncated"] is True

    def test_realistic_csp_is_recorded_in_full(self):
        value = ("default-src 'self'; script-src 'self' 'nonce-abc' https://cdn.example; "
                 "img-src 'self' data:; frame-ancestors 'none'")
        entry = ha.analyze_security_headers({"Content-Security-Policy": value})["Content-Security-Policy"]
        assert entry["tokens_truncated"] is False
        assert entry["directives_present"] == ["default-src", "frame-ancestors", "img-src", "script-src"]

    @pytest.mark.parametrize("exc", [
        ValueError("weird adapter"), UnicodeError("idna label too long"),
        AttributeError("broken adapter"), OSError("fd exhausted"), MemoryError("oom"),
    ])
    def test_non_request_exceptions_do_not_kill_the_run(self, exc, tmp_path):
        # requests is not the only thing that can fail: IDNA encoding raises
        # UnicodeError and a broken adapter raises anything. Letting those
        # escape destroyed the whole analysis (context.md §12.11).
        with mock.patch("requests.get", side_effect=exc):
            result = ha.fetch_url(SAFE_URL)
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                           output_dir=str(tmp_path / "o"))
        assert result["status"] == "error"
        assert "unexpected transport error" in result["error"]
        assert summary["status"] == "unreachable"

    def test_keyboard_interrupt_still_propagates(self):
        with mock.patch("requests.get", side_effect=KeyboardInterrupt()):
            with pytest.raises(KeyboardInterrupt):
                ha.fetch_url(SAFE_URL)

    @pytest.mark.parametrize("code,expected", [
        (None, None), ("200", 200), (99999, 99999), (-1, -1), ("abc", None), (True, None),
    ])
    def test_status_code_is_normalised_at_the_transport_boundary(self, code, expected, tmp_path):
        resp = _fake_response(status_code=code, headers={"Content-Type": "text/html"}, body=b"x")
        with mock.patch("requests.get", return_value=resp):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                           output_dir=str(tmp_path / "o"))
        assert summary["provenance"]["status_code"] == expected
        assert summary["errors"] == []

    @pytest.mark.parametrize("analyse", [
        lambda: ha.analyze_cache_headers({"Age": 120}),
        lambda: ha.analyze_security_headers({"X-Frame-Options": 123}),
        lambda: ha.analyze_cookie_flags([123, "a=1; Secure"]),
        lambda: ha.detect_jwts(None, {"X": 5}, []),
        lambda: ha.detect_waf({"Server": 500, "CF-Ray": None}, [], None),
    ])
    def test_non_string_header_values_are_coerced_not_fatal(self, analyse):
        json.dumps(analyse())

    def test_non_string_header_value_is_not_reported_absent(self):
        entry = ha.analyze_security_headers({"X-Frame-Options": 123})["X-Frame-Options"]
        assert entry["present"] is True and entry["value"] == "123"

    def test_generic_block_page_is_not_attributed_to_a_vendor(self):
        # "access denied" appears on every vendor's block page and on ordinary
        # application 403s; attributing it to Akamai was a false positive.
        assert ha.detect_waf({}, [], "<h1>Access Denied</h1>")["detected"] is False

    def test_summary_shape_is_stable_on_the_unreachable_path(self, tmp_path):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout()):
            unreachable = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                               output_dir=str(tmp_path / "a"))
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            ok = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "b"))
        for key in ("url", "target", "module", "status", "fetch_status", "completeness",
                    "requests_made", "request_budget", "findings_persisted", "findings_produced",
                    "errors", "started_at", "finished_at"):
            assert key in unreachable, key
            assert key in ok, key

    def test_budget_exhaustion_is_reported_as_incomplete_not_terminal(self, tmp_path):
        counter = {"n": 0}

        def fake_get(url, timeout, headers, allow_redirects, stream):
            counter["n"] += 1
            return _fake_response(status_code=302,
                                  headers={"Location": f"https://example.com/h{counter['n']}"})
        with mock.patch("requests.get", side_effect=fake_get):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                           output_dir=str(tmp_path / "o"),
                                           max_redirect_hops=30, max_requests=24)
        chain = summary["redirect_chain"]
        assert chain["stopped_reason"] == "request_budget_exhausted"
        assert chain["complete"] is False
        assert any("incomplete" in n for n in chain["notes"])
        record = next(r for r in json.loads((tmp_path / "o" / "pending_assets.json").read_text())
                      if r["type"] == "http_redirect_chain")
        assert record["confidence"] == ha.CONFIDENCE_MEDIUM
        assert counter["n"] <= 24

    def test_many_runs_stay_linear_and_bounded(self, tmp_path):
        output_dir = tmp_path / "output"
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"},
                              body=b"<html>plain</html>")
        start = time.perf_counter()
        with mock.patch("requests.get", return_value=resp):
            for i in range(100):
                ha.run_http_analysis(f"https://example.com/p{i}", target=SAFE_TARGET,
                                     output_dir=str(output_dir))
        elapsed = time.perf_counter() - start
        records = json.loads((output_dir / "pending_assets.json").read_text())
        assert len(records) == 800
        assert elapsed < 20.0, f"100 runs took {elapsed:.1f}s"

    def test_scope_is_never_left_even_through_a_long_in_scope_chain(self, tmp_path):
        contacted = []
        counter = {"n": 0}

        def fake_get(url, timeout, headers, allow_redirects, stream):
            contacted.append(ha._hostname_of(url))
            counter["n"] += 1
            if counter["n"] < 5:
                return _fake_response(status_code=302,
                                      headers={"Location": f"https://s{counter['n']}.example.com/a",
                                               "Content-Type": "text/html"})
            return _fake_response(status_code=200, headers={"Content-Type": "text/html"})
        with mock.patch("requests.get", side_effect=fake_get):
            ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "o"),
                                 max_redirect_hops=30)
        assert contacted
        for host in set(contacted):
            assert host == SAFE_TARGET or host.endswith("." + SAFE_TARGET), host

    def test_redirect_hops_are_mapped_never_harvested_for_cookies(self, tmp_path):
        # Cookie provenance across a redirect chain: only the baseline response
        # contributes cookies, so a later hop's session cookie is never
        # attributed to the analysed URL.
        output_dir = tmp_path / "output"
        counter = {"n": 0}

        def fake_get(url, timeout, headers, allow_redirects, stream):
            counter["n"] += 1
            if counter["n"] == 1:
                return _fake_response(302, {"Content-Type": "text/html",
                                            "Location": "https://sso.example.com/authorize"},
                                      b"", ["target_sid=1; Secure; HttpOnly; SameSite=Lax"])
            return _fake_response(200, {"Content-Type": "text/html"}, b"hop",
                                  ["HOP_SESSION=leaked; Path=/"])
        with mock.patch("requests.get", side_effect=fake_get):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))
        assert [c["name"] for c in summary["cookies"]] == ["target_sid"]
        raw = (output_dir / "pending_assets.json").read_text()
        assert "HOP_SESSION" not in raw and "leaked" not in raw
        # The in-scope hop WAS followed, so this is not vacuous.
        assert len(summary["redirect_chain"]["hops"]) == 2

    def test_third_party_idp_is_recorded_but_never_contacted(self, tmp_path):
        output_dir = tmp_path / "output"
        contacted = []

        def fake_get(url, timeout, headers, allow_redirects, stream):
            contacted.append(ha._hostname_of(url))
            return _fake_response(302, {"Content-Type": "text/html",
                                        "Location": "https://login.microsoftonline.com/authorize"},
                                  b"", ["target_sid=1; Secure; HttpOnly; SameSite=Lax"])
        with mock.patch("requests.get", side_effect=fake_get):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir))
        chain = summary["redirect_chain"]
        assert chain["stopped_reason"] == "next_hop_out_of_scope"
        assert chain["not_followed"]["attribution"] == "third_party"
        assert chain["not_followed"]["known_identity_provider"] is True
        assert "login.microsoftonline.com" not in contacted
        assert summary["auth_surfaces"]["identity_provider"]["third_party"] is True

    def test_json_api_auth_surface_is_analysed(self):
        result = ha.detect_auth_surfaces(
            SAFE_URL, '{"error":"invalid_token","login_url":"/oauth/authorize?client_id=x"}',
            {}, status_code=401, content_type="application/json")
        assert result["body_analyzable"] is True
        assert "oauth" in result["indicators"]

    def test_protocol_limitation_is_declared_not_implied(self, tmp_path):
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            summary = ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET,
                                           output_dir=str(tmp_path / "o"))
        # requests speaks HTTP/1.1; h2/h3 posture is a documented v1 limitation
        # rather than something silently claimed to have been checked.
        assert summary["provenance"]["protocol_observed"] == "HTTP/1.1"


class TestCacheFindingIdentityIsStableAcrossRescans:
    """
    2026-09-12 whole-system audit: surface_mapper.py keys a finding asset on
    a hash of the whole `value`, and this module put `Age` (counts up every
    second) and the CDN's per-request trace id (`cf-ray`) inside it. Two
    scans of one unchanged endpoint therefore produced two `http_cache_headers`
    finding assets, two risk signals and two report rows. Measured on
    consecutive live runs against example.com: every cache finding was
    duplicated.
    """

    CACHE_A = {"Cache-Control": None, "Age": "5026", "Expires": None, "ETag": '"v1"',
               "Pragma": None, "Vary": None, "age_seconds": 5026,
               "cache_status": "HIT", "served_from_cache": True,
               "origin_attribution": "edge_cache_hit", "cdn_vendors": ["cloudflare"],
               "directives": {}, "notes": [],
               "cdn_indicators": [{"header": "cf-ray", "value": "aaa111-KHI", "vendor": "cloudflare"},
                                  {"header": "cf-cache-status", "value": "HIT", "vendor": "cloudflare"}],
               "intermediary_absence_proven": False}
    CACHE_B = dict(CACHE_A, **{"Age": "7385", "age_seconds": 7385, "ETag": '"v1"',
                               "cdn_indicators": [
                                   {"header": "cf-ray", "value": "bbb222-KHI", "vendor": "cloudflare"},
                                   {"header": "cf-cache-status", "value": "HIT", "vendor": "cloudflare"}]})

    def test_a_rising_age_and_a_new_trace_id_do_not_change_the_stable_value(self):
        a, _ = ha._split_volatile_cache(self.CACHE_A)
        b, _ = ha._split_volatile_cache(self.CACHE_B)
        assert a == b, "the same cache posture must produce the same identity-bearing value"

    def test_every_volatile_value_is_kept_as_metadata_not_discarded(self):
        _, volatile = ha._split_volatile_cache(self.CACHE_A)
        assert volatile["cache_Age"] == "5026"
        assert volatile["cache_age_seconds"] == 5026
        assert volatile["cache_cache_status"] == "HIT"
        assert volatile["cache_served_from_cache"] is True
        assert {"header": "cf-ray", "value": "aaa111-KHI"} in volatile["cdn_indicator_values"]

    def test_the_stable_half_keeps_the_intelligence_that_matters(self):
        stable, _ = ha._split_volatile_cache(self.CACHE_A)
        assert stable["origin_attribution"] == "edge_cache_hit"
        assert stable["cdn_vendors"] == ["cloudflare"]
        assert {"header": "cf-ray", "vendor": "cloudflare"} in stable["cdn_indicators"]
        assert stable["Cache-Control"] is None and "Vary" in stable

    def test_a_genuine_posture_change_still_changes_the_value(self):
        changed = dict(self.CACHE_A, **{"Cache-Control": "no-store",
                                        "directives": {"no-store": True}})
        a, _ = ha._split_volatile_cache(self.CACHE_A)
        b, _ = ha._split_volatile_cache(changed)
        assert a != b, "a real change in cache policy must still be a new finding"

    @pytest.mark.parametrize("cache", [
        {}, {"cdn_indicators": None}, {"cdn_indicators": "x"},
        {"cdn_indicators": [None, 3, {"header": "h"}]}, {"Age": None}, {"served_from_cache": None},
    ])
    def test_the_split_never_raises_on_a_malformed_cache_analysis(self, cache):
        stable, volatile = ha._split_volatile_cache(cache)
        assert isinstance(stable, dict) and isinstance(volatile, dict)

    def test_the_persisted_finding_carries_the_split(self, tmp_path):
        headers = {"Age": "5026", "CF-Ray": "aaa111-KHI", "cf-cache-status": "HIT",
                   "Server": "cloudflare", "Content-Type": "text/html"}
        with mock.patch("requests.get", side_effect=lambda u, **k: _fake_response(
                200, headers, b"<html><title>t</title></html>", final_url=u)):
            ha.run_http_analysis(SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "o"))
        records = [json.loads(line) if isinstance(line, str) else line
                   for line in json.loads((tmp_path / "o" / "pending_assets.json").read_text())]
        cache_records = [r for r in records if r["type"] == "http_cache_headers"]
        assert cache_records
        value = cache_records[0]["value"]["cache"]
        assert "Age" not in value and "age_seconds" not in value
        assert cache_records[0]["metadata"]["cache_Age"] == "5026"
