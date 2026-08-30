"""
Tests for reconhound/vhost_scanner.py (ReconHound Module 9, per
context.md's build order — catalog item 9).

Run with:  ./.venv/bin/python -m pytest tests/test_vhost_scanner.py -v

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

from reconhound import vhost_scanner as vh


SAFE_IP = "93.184.216.34"
SAFE_TARGET = "example.com"


def _fake_response(status_code=200, headers=None, body=b"", final_url=None):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = dict(headers or {})
    resp.encoding = "utf-8"
    resp.content = body
    resp.url = final_url or f"http://{SAFE_IP}/"
    resp.elapsed.total_seconds.return_value = 0.05
    resp.raw.read.return_value = body
    return resp


def _write_wordlist(tmp_path, labels):
    d = tmp_path / "wordlists"
    d.mkdir(exist_ok=True)
    (d / "subdomains.txt").write_text("\n".join(labels) + "\n")
    return str(d)


# ---------------------------------------------------------------------------
# validate_scan_ip / _format_host_for_url (scope enforcement)
# ---------------------------------------------------------------------------

class TestValidateScanIp:
    def test_accepts_ipv4(self):
        assert vh.validate_scan_ip("93.184.216.34") == "93.184.216.34"

    def test_accepts_ipv6(self):
        assert vh.validate_scan_ip("2606:2800:220:1:248:1893:25c8:1946")

    def test_strips_whitespace(self):
        assert vh.validate_scan_ip("  93.184.216.34  ") == "93.184.216.34"

    def test_rejects_hostname(self):
        with pytest.raises(vh.ScopeError):
            vh.validate_scan_ip("example.com")

    def test_rejects_cidr(self):
        with pytest.raises(vh.ScopeError):
            vh.validate_scan_ip("93.184.216.0/24")

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(vh.ScopeError):
            vh.validate_scan_ip(bad)


class TestFormatHostForUrl:
    def test_ipv4_unchanged(self):
        assert vh._format_host_for_url("93.184.216.34") == "93.184.216.34"

    def test_ipv6_bracketed(self):
        assert vh._format_host_for_url("::1") == "[::1]"

    def test_non_ip_returned_unchanged(self):
        assert vh._format_host_for_url("not-an-ip") == "not-an-ip"


class TestInScopeHost:
    def test_exact_match(self):
        assert vh._in_scope_host("example.com", "example.com")

    def test_subdomain_match(self):
        assert vh._in_scope_host("admin.example.com", "example.com")

    def test_unrelated_host_rejected(self):
        assert not vh._in_scope_host("evil.com", "example.com")

    def test_lookalike_suffix_rejected(self):
        assert not vh._in_scope_host("notexample.com", "example.com")


# ---------------------------------------------------------------------------
# make_finding / make_vhost_finding / PendingAssetsStore
# ---------------------------------------------------------------------------

class TestFindingsAndStore:
    def test_finding_structure_and_source(self):
        finding = vh.make_finding("vhost_discovered", SAFE_IP, {"a": 1}, ["e"], vh.CONFIDENCE_HIGH)
        assert finding["source"] == "vhost_scanner.py"
        assert finding["metadata"] == {}
        json.dumps(finding)

    def test_make_vhost_finding_preserves_provenance_fields(self):
        finding = vh.make_vhost_finding(
            ip=SAFE_IP, port=80, scheme="http", hostname="admin.example.com",
            evidence=["status differs"], confidence=vh.CONFIDENCE_MEDIUM, target=SAFE_TARGET,
            signals={"status_diff": True},
        )
        assert finding["value"]["ip"] == SAFE_IP
        assert finding["value"]["hostname"] == "admin.example.com"
        assert finding["value"]["host_header"] == "admin.example.com"
        assert finding["value"]["connect_url"] == f"http://{SAFE_IP}:80/"
        assert finding["confidence"] == vh.CONFIDENCE_MEDIUM
        assert finding["metadata"]["signals"] == {"status_diff": True}
        assert "timestamp" in finding
        json.dumps(finding)

    def test_store_preserves_prior_data(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{"type": "open_tcp_port", "source": "active_recon.py"}]
        pending.write_text(json.dumps(pre_existing))

        store = vh.PendingAssetsStore(output_dir=str(output_dir))
        store.add(vh.make_finding("vhost_discovered", SAFE_IP, {}, ["e"], vh.CONFIDENCE_HIGH))
        assert store.all() == pre_existing + [store.all()[-1]]

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = vh.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(vh.PersistenceError):
            store.add(vh.make_finding("vhost_discovered", SAFE_IP, {}, ["e"], vh.CONFIDENCE_HIGH))

    def test_safe_store_add_returns_none_when_store_is_none(self):
        assert vh._safe_store_add(None, vh.make_finding("x", SAFE_IP, {}, [], vh.CONFIDENCE_LOW)) is None

    def test_safe_store_add_returns_error_string_on_persistence_failure(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("not json at all")
        store = vh.PendingAssetsStore(output_dir=str(output_dir))
        err = vh._safe_store_add(store, vh.make_finding("x", SAFE_IP, {}, [], vh.CONFIDENCE_LOW))
        assert err is not None


# ---------------------------------------------------------------------------
# shared helpers: _content_signature / _extract_title / _confidence_for_score
# ---------------------------------------------------------------------------

class TestContentSignature:
    def test_identical_after_whitespace_normalization_same_hash(self):
        a = vh._content_signature("<html>hello   world</html>")
        b = vh._content_signature("<html>hello world</html>")
        assert a == b

    def test_different_content_different_hash(self):
        a = vh._content_signature("<html>one</html>")
        b = vh._content_signature("<html>two</html>")
        assert a[1] != b[1]

    def test_empty_body(self):
        length, digest = vh._content_signature("")
        assert length == 0
        assert digest


class TestExtractTitle:
    def test_extracts_title(self):
        assert vh._extract_title("<html><head><title>Admin Panel</title></head></html>") == "Admin Panel"

    def test_normalizes_whitespace(self):
        assert vh._extract_title("<title>  Admin   Panel  </title>") == "Admin Panel"

    def test_no_title_tag_returns_none(self):
        assert vh._extract_title("<html><body>hi</body></html>") is None

    def test_empty_body_returns_none(self):
        assert vh._extract_title("") is None
        assert vh._extract_title(None) is None


class TestConfidenceForScore:
    def test_zero_or_below_is_low(self):
        assert vh._confidence_for_score(0) == vh.CONFIDENCE_LOW

    def test_one_is_low(self):
        assert vh._confidence_for_score(1) == vh.CONFIDENCE_LOW

    def test_two_is_medium(self):
        assert vh._confidence_for_score(2) == vh.CONFIDENCE_MEDIUM

    def test_three_or_more_is_high(self):
        assert vh._confidence_for_score(3) == vh.CONFIDENCE_HIGH
        assert vh._confidence_for_score(5) == vh.CONFIDENCE_HIGH


# ---------------------------------------------------------------------------
# load_wordlist / build_candidate_hostnames
# ---------------------------------------------------------------------------

class TestLoadWordlist:
    def test_loads_shipped_subdomains_wordlist(self):
        entries = vh.load_wordlist("subdomains.txt")
        assert len(entries) > 0
        assert "www" in entries
        assert "admin" in entries

    def test_custom_wordlist_ignores_blank_and_comment_lines(self, tmp_path):
        d = tmp_path / "wl"
        d.mkdir()
        (d / "subdomains.txt").write_text("# comment\n\nwww\nadmin\nwww\n")
        entries = vh.load_wordlist("subdomains.txt", wordlists_dir=str(d))
        assert entries == ["www", "admin"]  # dedup, order preserved

    def test_missing_file_raises_wordlist_error(self, tmp_path):
        with pytest.raises(vh.WordlistError):
            vh.load_wordlist("subdomains.txt", wordlists_dir=str(tmp_path / "nope"))


class TestBuildCandidateHostnames:
    def test_generates_labels_combined_with_target(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, ["admin", "staging"])
        result = vh.build_candidate_hostnames(SAFE_TARGET, wordlists_dir=wl_dir)
        assert result["candidates"] == ["admin.example.com", "staging.example.com"]
        assert result["labels_loaded"] == 2
        assert result["wordlist_error"] is None

    def test_extra_hostnames_merged_and_deduped(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, ["admin"])
        result = vh.build_candidate_hostnames(
            SAFE_TARGET, extra_hostnames=["api.example.com", "admin.example.com", "  "], wordlists_dir=wl_dir,
        )
        assert result["candidates"] == ["admin.example.com", "api.example.com"]

    def test_out_of_scope_hostname_skipped_by_default(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, [])
        result = vh.build_candidate_hostnames(
            SAFE_TARGET, extra_hostnames=["evil.com"], wordlists_dir=wl_dir,
        )
        assert result["candidates"] == []
        assert result["skipped_out_of_scope"] == ["evil.com"]

    def test_out_of_scope_hostname_allowed_when_opted_in(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, [])
        result = vh.build_candidate_hostnames(
            SAFE_TARGET, extra_hostnames=["evil.com"], wordlists_dir=wl_dir, allow_out_of_scope=True,
        )
        assert result["candidates"] == ["evil.com"]
        assert result["skipped_out_of_scope"] == []

    def test_missing_wordlist_still_returns_extra_hostnames(self, tmp_path):
        result = vh.build_candidate_hostnames(
            SAFE_TARGET, extra_hostnames=["api.example.com"], wordlists_dir=str(tmp_path / "nope"),
        )
        assert result["wordlist_error"] is not None
        assert result["candidates"] == ["api.example.com"]

    def test_result_json_serializable(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, ["admin"])
        json.dumps(vh.build_candidate_hostnames(SAFE_TARGET, wordlists_dir=wl_dir))


# ---------------------------------------------------------------------------
# fetch_with_host_header
# ---------------------------------------------------------------------------

class TestFetchWithHostHeader:
    def test_successful_fetch_sends_host_header(self):
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=b"<html>hi</html>")
        with mock.patch("requests.get", return_value=resp) as mocked:
            result = vh.fetch_with_host_header(SAFE_IP, 80, "http", "admin.example.com")
        assert result["status"] == "found"
        assert result["status_code"] == 200
        assert result["host_header_sent"] == "admin.example.com"
        assert result["url"] == f"http://{SAFE_IP}:80/"
        called_headers = mocked.call_args.kwargs["headers"]
        assert called_headers["Host"] == "admin.example.com"

    def test_https_disables_cert_verification(self):
        resp = _fake_response(status_code=200, body=b"hi")
        with mock.patch("requests.get", return_value=resp) as mocked:
            vh.fetch_with_host_header(SAFE_IP, 443, "https", "admin.example.com")
        assert mocked.call_args.kwargs["verify"] is False

    def test_http_keeps_cert_verification_default(self):
        resp = _fake_response(status_code=200, body=b"hi")
        with mock.patch("requests.get", return_value=resp) as mocked:
            vh.fetch_with_host_header(SAFE_IP, 80, "http", "admin.example.com")
        assert mocked.call_args.kwargs["verify"] is True

    def test_ipv6_url_bracketed(self):
        resp = _fake_response(status_code=200, body=b"hi")
        with mock.patch("requests.get", return_value=resp):
            result = vh.fetch_with_host_header("::1", 80, "http", "admin.example.com")
        assert result["url"] == "http://[::1]:80/"

    def test_timeout_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout()):
            result = vh.fetch_with_host_header(SAFE_IP, 80, "http", "admin.example.com")
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_connection_error_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = vh.fetch_with_host_header(SAFE_IP, 80, "http", "admin.example.com")
        assert result["status"] == "error"
        assert "connection error" in result["error"]

    def test_body_truncated_when_over_limit(self):
        body = b"x" * 100
        resp = _fake_response(status_code=200, body=body)
        with mock.patch("requests.get", return_value=resp):
            result = vh.fetch_with_host_header(SAFE_IP, 80, "http", "admin.example.com", max_body_bytes=10)
        assert result["body_truncated"] is True
        assert len(result["body"]) == 10

    def test_result_json_serializable(self):
        resp = _fake_response(status_code=200, body=b"hi")
        with mock.patch("requests.get", return_value=resp):
            result = vh.fetch_with_host_header(SAFE_IP, 80, "http", "admin.example.com")
        json.dumps(result)


# ---------------------------------------------------------------------------
# probe_baselines
# ---------------------------------------------------------------------------

class TestProbeBaselines:
    def test_fetches_ip_and_random_host_baselines(self):
        ip_resp = _fake_response(status_code=200, body=b"default site")
        random_resp = _fake_response(status_code=404, body=b"not found")
        with mock.patch("requests.get", side_effect=[ip_resp, random_resp]) as mocked:
            result = vh.probe_baselines(SAFE_IP, 80, "http")
        assert result["ip_host_response"]["status_code"] == 200
        assert result["random_host_response"]["status_code"] == 404
        assert result["random_host_used"].endswith(".invalid")
        assert mocked.call_count == 2
        first_headers = mocked.call_args_list[0].kwargs["headers"]
        second_headers = mocked.call_args_list[1].kwargs["headers"]
        assert first_headers["Host"] == SAFE_IP
        assert second_headers["Host"] == result["random_host_used"]


# ---------------------------------------------------------------------------
# score_vhost_candidate — the core "avoid false positives" logic
# ---------------------------------------------------------------------------

class TestScoreVhostCandidate:
    def _baseline(self, status_code=200, body="", headers=None):
        return {"status": "found", "status_code": status_code, "body": body, "headers": headers or {}}

    def test_candidate_fetch_failed_scores_zero(self):
        candidate = {"status": "error", "error": "timeout"}
        result = vh.score_vhost_candidate(candidate, self._baseline(), self._baseline())
        assert result["score"] == 0
        assert result["reason"] == "candidate_fetch_failed"

    def test_both_baselines_unavailable_scores_zero(self):
        candidate = {"status": "found", "status_code": 200, "body": "hi", "headers": {}}
        unavailable = {"status": "error", "error": "timeout"}
        result = vh.score_vhost_candidate(candidate, unavailable, unavailable)
        assert result["score"] == 0
        assert result["reason"] == "both_baselines_unavailable"

    def test_identical_to_both_baselines_scores_zero(self):
        body = "<html>default catch-all</html>"
        candidate = {"status": "found", "status_code": 200, "body": body, "headers": {}}
        result = vh.score_vhost_candidate(candidate, self._baseline(200, body), self._baseline(200, body))
        assert result["score"] == 0
        assert result["evidence"] == []

    def test_matches_ip_baseline_exactly_not_reported(self):
        # Even if it differs from the random baseline, matching the "no
        # override" baseline means it's just the default vhost.
        body = "<html>default catch-all</html>"
        candidate = {"status": "found", "status_code": 200, "body": body, "headers": {}}
        ip_baseline = self._baseline(200, body)
        random_baseline = self._baseline(404, "not found")
        result = vh.score_vhost_candidate(candidate, ip_baseline, random_baseline)
        assert result["score"] == 0

    def test_status_diff_alone_scores_medium(self):
        body = "same body everywhere"
        candidate = {"status": "found", "status_code": 403, "body": body, "headers": {}}
        result = vh.score_vhost_candidate(candidate, self._baseline(200, body), self._baseline(200, body))
        assert result["score"] == vh._SCORE_STRONG
        assert result["signals"] == {"status_diff": True}
        assert vh._confidence_for_score(result["score"]) == vh.CONFIDENCE_MEDIUM

    def test_content_diff_alone_scores_medium(self):
        candidate = {"status": "found", "status_code": 200, "body": "distinct app content, no title tag", "headers": {}}
        result = vh.score_vhost_candidate(
            candidate, self._baseline(200, "default catch-all body"), self._baseline(200, "unrecognized host body"),
        )
        assert result["signals"] == {"content_diff": True}
        assert vh._confidence_for_score(result["score"]) == vh.CONFIDENCE_MEDIUM

    def test_content_and_title_diff_converge_to_high(self):
        candidate = {
            "status": "found", "status_code": 200,
            "body": "<html><title>Admin Panel</title>distinct content</html>", "headers": {},
        }
        ip_baseline = self._baseline(200, "<html><title>Default Site</title>default content</html>")
        random_baseline = self._baseline(200, "<html><title>Default Site</title>default content</html>")
        result = vh.score_vhost_candidate(candidate, ip_baseline, random_baseline)
        assert result["signals"]["content_diff"] is True
        assert result["signals"]["title_diff"] is True
        assert vh._confidence_for_score(result["score"]) == vh.CONFIDENCE_HIGH

    def test_redirect_diff_alone_scores_medium(self):
        candidate = {
            "status": "found", "status_code": 302, "body": "",
            "headers": {"Location": "https://admin.example.com/login"},
        }
        ip_baseline = self._baseline(302, "", headers={"Location": "https://example.com/"})
        random_baseline = self._baseline(302, "", headers={"Location": "https://example.com/"})
        result = vh.score_vhost_candidate(candidate, ip_baseline, random_baseline)
        assert result["signals"] == {"redirect_diff": True}
        assert vh._confidence_for_score(result["score"]) == vh.CONFIDENCE_MEDIUM

    def test_one_baseline_unavailable_still_scores_against_available_one(self):
        candidate = {"status": "found", "status_code": 200, "body": "distinct content here", "headers": {}}
        ip_baseline = {"status": "error", "error": "timeout"}
        random_baseline = self._baseline(404, "unrecognized host body")
        result = vh.score_vhost_candidate(candidate, ip_baseline, random_baseline)
        assert result["score"] > 0
        assert any("unavailable" in e for e in result["evidence"])

    def test_result_json_serializable(self):
        candidate = {"status": "found", "status_code": 200, "body": "hi", "headers": {}}
        result = vh.score_vhost_candidate(candidate, self._baseline(), self._baseline())
        json.dumps(result)


# ---------------------------------------------------------------------------
# persist_no_distinct_response
# ---------------------------------------------------------------------------

class TestPersistNoDistinctResponse:
    def test_persists_low_confidence_negative_finding(self, tmp_path):
        store = vh.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        err = vh.persist_no_distinct_response("admin.example.com", SAFE_IP, 80, "http", SAFE_TARGET, store)
        assert err is None
        records = store.all()
        assert len(records) == 1
        assert records[0]["type"] == "vhost_checked_no_distinct_response"
        assert records[0]["confidence"] == vh.CONFIDENCE_LOW
        assert records[0]["value"]["hostname"] == "admin.example.com"

    def test_none_store_returns_none(self):
        assert vh.persist_no_distinct_response("admin.example.com", SAFE_IP, 80, "http", SAFE_TARGET, None) is None


# ---------------------------------------------------------------------------
# discover_vhosts_for_target — per ip/port/scheme orchestration
# ---------------------------------------------------------------------------

class TestDiscoverVhostsForTarget:
    def test_discovers_one_distinct_vhost_and_records_negative_for_the_rest(self, tmp_path):
        ip_baseline_resp = _fake_response(status_code=200, body=b"<html>default catch-all</html>")
        random_baseline_resp = _fake_response(status_code=200, body=b"<html>default catch-all</html>")
        # candidate 1: identical to baselines -> negative result
        candidate_no_signal = _fake_response(status_code=200, body=b"<html>default catch-all</html>")
        # candidate 2: distinct content -> discovered vhost
        candidate_distinct = _fake_response(status_code=200, body=b"<html>Admin control panel, totally different</html>")

        store = vh.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        responses = [ip_baseline_resp, random_baseline_resp, candidate_no_signal, candidate_distinct]
        with mock.patch("requests.get", side_effect=responses):
            result = vh.discover_vhosts_for_target(
                SAFE_IP, 80, "http", SAFE_TARGET,
                ["www.example.com", "admin.example.com"], store=store,
            )

        assert result["candidates_checked"] == 2
        assert result["negative_results_count"] == 1
        assert len(result["discovered_vhosts"]) == 1
        assert result["discovered_vhosts"][0]["hostname"] == "admin.example.com"

        records = store.all()
        assert any(r["type"] == "vhost_discovered" for r in records)
        assert any(r["type"] == "vhost_checked_no_distinct_response" for r in records)

    def test_both_baselines_failing_records_error_and_stops(self, tmp_path):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = vh.discover_vhosts_for_target(SAFE_IP, 80, "http", SAFE_TARGET, ["admin.example.com"])
        assert result["discovered_vhosts"] == []
        assert result["candidates_checked"] == 0
        assert any(r["stage"] == "baseline" for r in result["errors"])

    def test_candidate_failure_does_not_abort_remaining_candidates(self, tmp_path):
        ip_baseline_resp = _fake_response(status_code=200, body=b"<html>default</html>")
        random_baseline_resp = _fake_response(status_code=200, body=b"<html>default</html>")
        candidate_ok = _fake_response(status_code=200, body=b"<html>distinct admin app</html>")

        def side_effect(*args, **kwargs):
            host = kwargs["headers"]["Host"]
            if host == "broken.example.com":
                raise requests.exceptions.ConnectionError("refused")
            if host == SAFE_IP:
                return ip_baseline_resp
            if host.endswith(".invalid"):
                return random_baseline_resp
            return candidate_ok

        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.discover_vhosts_for_target(
                SAFE_IP, 80, "http", SAFE_TARGET, ["broken.example.com", "admin.example.com"],
            )

        assert result["candidates_checked"] == 2
        assert len(result["discovered_vhosts"]) == 1
        assert result["discovered_vhosts"][0]["hostname"] == "admin.example.com"
        assert any(e.get("hostname") == "broken.example.com" for e in result["errors"])

    def test_max_candidates_bounds_probing(self, tmp_path):
        ip_baseline_resp = _fake_response(status_code=200, body=b"<html>default</html>")
        random_baseline_resp = _fake_response(status_code=200, body=b"<html>default</html>")
        candidate_resp = _fake_response(status_code=200, body=b"<html>default</html>")
        with mock.patch("requests.get", side_effect=[ip_baseline_resp, random_baseline_resp, candidate_resp]) as mocked:
            result = vh.discover_vhosts_for_target(
                SAFE_IP, 80, "http", SAFE_TARGET,
                ["a.example.com", "b.example.com", "c.example.com"], max_candidates=1,
            )
        assert result["candidates_checked"] == 1
        assert mocked.call_count == 3  # 2 baselines + 1 candidate

    def test_result_json_serializable(self, tmp_path):
        ip_baseline_resp = _fake_response(status_code=200, body=b"<html>default</html>")
        random_baseline_resp = _fake_response(status_code=200, body=b"<html>default</html>")
        with mock.patch("requests.get", side_effect=[ip_baseline_resp, random_baseline_resp]):
            result = vh.discover_vhosts_for_target(SAFE_IP, 80, "http", SAFE_TARGET, [])
        json.dumps(result)


# ---------------------------------------------------------------------------
# build_downstream_recon_target / build_recommended_actions / build_vhost_summary
# ---------------------------------------------------------------------------

def _vhost_record(confidence=vh.CONFIDENCE_HIGH, scheme="http", hostname="admin.example.com"):
    return {
        "ip": SAFE_IP, "port": 80 if scheme == "http" else 443, "scheme": scheme, "hostname": hostname,
        "connect_url": f"{scheme}://{SAFE_IP}:{80 if scheme == 'http' else 443}/",
        "status_code": 200, "confidence": confidence, "score": 4,
        "evidence": ["e1", "e2"], "signals": {"content_diff": True}, "timestamp": "2026-01-01T00:00:00+00:00",
    }


class TestBuildDownstreamReconTarget:
    def test_shapes_ip_based_target_with_host_override(self):
        target = vh.build_downstream_recon_target(_vhost_record())
        assert target["connect_url"] == f"http://{SAFE_IP}:80/"
        assert target["host_header_override"] == "admin.example.com"
        assert "note" in target
        json.dumps(target)


class TestBuildRecommendedActions:
    def test_high_and_medium_confidence_included(self):
        vhosts = [_vhost_record(confidence=vh.CONFIDENCE_HIGH), _vhost_record(confidence=vh.CONFIDENCE_MEDIUM, hostname="api.example.com")]
        actions = vh.build_recommended_actions(vhosts, SAFE_TARGET)
        assert len(actions) == 2
        assert all(a["status"] == "queued_for_orchestrator" for a in actions)
        assert all("[REASON:" in a["justification"] for a in actions)

    def test_low_confidence_excluded(self):
        vhosts = [_vhost_record(confidence=vh.CONFIDENCE_LOW)]
        assert vh.build_recommended_actions(vhosts, SAFE_TARGET) == []

    def test_https_adds_ssl_analyzer_recommendation(self):
        vhosts = [_vhost_record(confidence=vh.CONFIDENCE_HIGH, scheme="https")]
        actions = vh.build_recommended_actions(vhosts, SAFE_TARGET)
        assert "ssl_analyzer.py" in actions[0]["recommended_modules"]

    def test_http_does_not_add_ssl_analyzer(self):
        vhosts = [_vhost_record(confidence=vh.CONFIDENCE_HIGH, scheme="http")]
        actions = vh.build_recommended_actions(vhosts, SAFE_TARGET)
        assert "ssl_analyzer.py" not in actions[0]["recommended_modules"]

    def test_actions_are_json_serializable(self):
        vhosts = [_vhost_record()]
        json.dumps(vh.build_recommended_actions(vhosts, SAFE_TARGET))


class TestBuildVhostSummary:
    def test_groups_by_ip_and_builds_downstream_targets(self):
        vhosts = [_vhost_record(hostname="admin.example.com"), _vhost_record(hostname="api.example.com")]
        summary = vh.build_vhost_summary(vhosts)
        assert summary["count"] == 2
        assert set(summary["by_ip"][SAFE_IP]) == {"admin.example.com", "api.example.com"}
        assert len(summary["downstream_targets"]) == 2
        json.dumps(summary)

    def test_empty_input(self):
        summary = vh.build_vhost_summary([])
        assert summary["count"] == 0
        assert summary["vhosts"] == []
        assert summary["by_ip"] == {}


# ---------------------------------------------------------------------------
# run_vhost_scan — full single-IP orchestration
# ---------------------------------------------------------------------------

class TestRunVhostScan:
    def test_scope_enforcement_raises(self, tmp_path):
        with pytest.raises(vh.ScopeError):
            vh.run_vhost_scan("not-an-ip", target=SAFE_TARGET, output_dir=str(tmp_path / "output"))

    def test_full_run_discovers_vhost_and_feeds_recommended_actions(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, ["admin"])
        default_body = b"<html>default catch-all site</html>"
        distinct_body = b"<html>Totally distinct admin control panel</html>"

        def side_effect(*args, **kwargs):
            host = kwargs["headers"]["Host"]
            if host == "admin.example.com":
                return _fake_response(status_code=200, body=distinct_body)
            return _fake_response(status_code=200, body=default_body)

        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                ports=[(80, "http")], wordlists_dir=wl_dir,
            )

        assert result["status"] in ("completed", "completed_with_errors")
        assert result["vhost_summary"]["count"] == 1
        assert result["vhost_summary"]["vhosts"][0]["hostname"] == "admin.example.com"
        assert result["recommended_next_actions"]
        assert result["recommended_next_actions"][0]["hostname"] == "admin.example.com"
        json.dumps(result)

        store = vh.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        records = store.all()
        assert any(r["type"] == "vhost_discovered" and r["value"]["hostname"] == "admin.example.com" for r in records)

    def test_no_distinct_vhosts_yields_empty_summary(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, ["admin"])
        same_body = b"<html>always the same</html>"
        with mock.patch("requests.get", return_value=_fake_response(status_code=200, body=same_body)):
            result = vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                ports=[(80, "http")], wordlists_dir=wl_dir,
            )
        assert result["vhost_summary"]["count"] == 0
        assert result["recommended_next_actions"] == []

    def test_multiple_ports_each_probed_independently(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, [])
        same_body = b"<html>same everywhere</html>"
        with mock.patch("requests.get", return_value=_fake_response(status_code=200, body=same_body)) as mocked:
            result = vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                ports=[(80, "http"), (443, "https")], wordlists_dir=wl_dir,
            )
        assert len(result["port_results"]) == 2
        assert mocked.call_count == 4  # 2 baselines per port x 2 ports

    def test_extra_hostnames_out_of_scope_skipped_without_probing(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, [])
        with mock.patch("requests.get", return_value=_fake_response(status_code=200, body=b"x")) as mocked:
            result = vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                ports=[(80, "http")], wordlists_dir=wl_dir, extra_hostnames=["totally-unrelated.evil.com"],
            )
        assert result["candidate_build"]["skipped_out_of_scope"] == ["totally-unrelated.evil.com"]
        assert mocked.call_count == 2  # only the two baseline probes, no candidate probe

    def test_wordlist_load_failure_still_completes_with_error_recorded(self, tmp_path):
        with mock.patch("requests.get", return_value=_fake_response(status_code=200, body=b"x")):
            result = vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                ports=[(80, "http")], wordlists_dir=str(tmp_path / "does-not-exist"),
            )
        assert result["status"] == "completed_with_errors"
        assert any(e.get("stage") == "wordlist_load" for e in result["errors"])

    def test_output_is_json_serializable_end_to_end(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, ["admin"])
        with mock.patch("requests.get", return_value=_fake_response(status_code=200, body=b"same")):
            result = vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                ports=[(80, "http")], wordlists_dir=wl_dir,
            )
        json.dumps(result)
