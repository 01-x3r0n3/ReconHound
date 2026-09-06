"""
Tests for reconhound/vhost_scanner.py (ReconHound Module 9, per
context.md's build order — catalog item 9).

Run with:  ./.venv/bin/python -m pytest tests/test_vhost_scanner.py -v

All tests mock the `requests.get` boundary so the suite is deterministic
and offline-safe; no external network access is required or performed
anywhere in this file.
"""

import itertools
import json
import os
import sys
import threading
import time
import uuid
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
    def test_fetches_both_baselines_twice_for_stability(self):
        ip_resp = _fake_response(status_code=200, body=b"default site")
        ip_resp_2 = _fake_response(status_code=200, body=b"default site")
        random_resp = _fake_response(status_code=404, body=b"not found")
        random_resp_2 = _fake_response(status_code=404, body=b"not found")
        with mock.patch("requests.get",
                        side_effect=[ip_resp, ip_resp_2, random_resp, random_resp_2]) as mocked:
            result = vh.probe_baselines(SAFE_IP, 80, "http")
        assert result["ip_host_response"]["status_code"] == 200
        assert result["random_host_response"]["status_code"] == 404
        assert result["random_host_used"].endswith(".invalid")
        # Each baseline is sampled twice; the repeats are the stability
        # controls, so a server whose response carries per-request dynamic
        # content is detected before any candidate is scored. The two
        # unrecognized-Host probes deliberately use *different* hostnames.
        assert mocked.call_count == 4
        assert result["random_host_used_2"].endswith(".invalid")
        assert result["random_host_used_2"] != result["random_host_used"]
        hosts = [c.kwargs["headers"]["Host"] for c in mocked.call_args_list]
        assert hosts == [SAFE_IP, SAFE_IP, result["random_host_used"], result["random_host_used_2"]]

    def test_stability_verified_when_control_probes_agree(self):
        body = b"<html><title>Default</title>same</html>"
        responses = [_fake_response(200, body=body) for _ in range(4)]
        with mock.patch("requests.get", side_effect=responses):
            result = vh.probe_baselines(SAFE_IP, 80, "http")
        stability = result["stability"]
        assert stability["verified"] is True
        assert stability["unstable_signals"] == []
        assert all(stability[f"{n}_stable"] for n in ("status", "content", "title", "location"))

    def test_dynamic_default_page_is_detected_as_unstable(self):
        def side_effect(*a, **k):
            return _fake_response(200, body=f"<html>rid={uuid.uuid4().hex}</html>".encode())
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.probe_baselines(SAFE_IP, 80, "http")
        stability = result["stability"]
        assert stability["verified"] is True
        assert stability["content_stable"] is False
        assert "content" in stability["unstable_signals"]

    def test_host_echo_alone_does_not_make_a_baseline_look_unstable(self):
        def side_effect(*a, **k):
            host = k["headers"]["Host"]
            return _fake_response(200, body=f"<html>No site configured for {host}</html>".encode())
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.probe_baselines(SAFE_IP, 80, "http")
        assert result["stability"]["content_stable"] is True

    def test_unverifiable_when_a_control_probe_fails(self):
        ok = _fake_response(200, body=b"x")
        with mock.patch("requests.get",
                        side_effect=[ok, ok, ok, requests.exceptions.Timeout()]):
            result = vh.probe_baselines(SAFE_IP, 80, "http")
        assert result["stability"]["verified"] is False
        assert "could not be verified" in result["stability"]["note"]

    def test_unreachable_ip_baseline_does_not_make_everything_unverified(self):
        """A server that simply refuses `Host: <ip>` must not poison stability."""
        refused = requests.exceptions.ConnectionError("refused")
        ok = _fake_response(200, body=b"<html>catch all</html>")
        with mock.patch("requests.get", side_effect=[refused, refused, ok, ok]):
            result = vh.probe_baselines(SAFE_IP, 80, "http")
        assert result["ip_host_response"]["status"] == "error"
        assert result["stability"]["verified"] is True
        assert result["stability"]["content_stable"] is True

    def test_dynamic_default_vhost_with_static_catch_all_is_detected(self):
        """
        Regression: measuring stability on the unrecognized-Host control
        alone missed a *dynamic default vhost* behind a static catch-all,
        and reported every wordlist candidate as a virtual host.
        """
        def side_effect(*a, **k):
            if k["headers"]["Host"].endswith(".invalid"):
                return _fake_response(404, body=b"<html>static catch all</html>")
            return _fake_response(200, body=f"<html>session={uuid.uuid4().hex}</html>".encode())
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.probe_baselines(SAFE_IP, 80, "http")
        assert result["stability"]["content_stable"] is False
        assert "content" in result["stability"]["unstable_signals"]

    def test_ipv6_baseline_host_header_is_bracketed(self):
        with mock.patch("requests.get", return_value=_fake_response(200, body=b"x")) as mocked:
            vh.probe_baselines("2606:2800:220:1:248:1893:25c8:1946", 443, "https")
        assert mocked.call_args_list[0].kwargs["headers"]["Host"] == "[2606:2800:220:1:248:1893:25c8:1946]"


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
        ip_baseline_resp_2 = _fake_response(status_code=200, body=b"<html>default catch-all</html>")
        random_baseline_resp_2 = _fake_response(status_code=200, body=b"<html>default catch-all</html>")
        responses = [ip_baseline_resp, ip_baseline_resp_2, random_baseline_resp,
                     random_baseline_resp_2, candidate_no_signal, candidate_distinct]
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
        extra = [_fake_response(status_code=200, body=b"<html>default</html>") for _ in range(2)]
        candidate_resp = _fake_response(status_code=200, body=b"<html>default</html>")
        with mock.patch("requests.get", side_effect=[
            ip_baseline_resp, extra[0], random_baseline_resp, extra[1], candidate_resp]) as mocked:
            result = vh.discover_vhosts_for_target(
                SAFE_IP, 80, "http", SAFE_TARGET,
                ["a.example.com", "b.example.com", "c.example.com"], max_candidates=1,
            )
        assert result["candidates_checked"] == 1
        assert mocked.call_count == 5  # 4 baseline probes (2 controls x2) + 1 candidate

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
        assert mocked.call_count == 8  # 4 baseline probes per port x 2 ports

    def test_extra_hostnames_out_of_scope_skipped_without_probing(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, [])
        with mock.patch("requests.get", return_value=_fake_response(status_code=200, body=b"x")) as mocked:
            result = vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                ports=[(80, "http")], wordlists_dir=wl_dir, extra_hostnames=["totally-unrelated.evil.com"],
            )
        assert result["candidate_build"]["skipped_out_of_scope"] == ["totally-unrelated.evil.com"]
        assert mocked.call_count == 4  # only the four baseline probes, no candidate probe

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


# ===========================================================================
# Regression suite for the forensic audit of vhost_scanner.py.
#
# Every test below pins a defect that was reproduced against the previous
# implementation (or against an earlier version of one of these fixes during
# adversarial self-attack). Each one states the failure it prevents.
# ===========================================================================

def _wordlist_run(tmp_path, side_effect, labels=("admin", "dev", "staging", "qa", "test"), **kwargs):
    wl_dir = _write_wordlist(tmp_path, list(labels))
    with mock.patch("requests.get", side_effect=side_effect):
        return vh.run_vhost_scan(
            SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
            ports=[(80, "http")], wordlists_dir=wl_dir, **kwargs,
        )


class TestFalsePositiveSuppression:
    """Response classes that previously reported an entire wordlist as discovered."""

    def test_dynamic_default_page_reports_nothing_and_claims_no_absence(self, tmp_path):
        # Previously: 5/5 candidates reported as MEDIUM-confidence vhosts,
        # 5 downstream recon actions queued, because the per-request id made
        # every body hash differ from both baselines.
        def side_effect(*a, **k):
            return _fake_response(200, body=f"<html>rid={uuid.uuid4().hex}</html>".encode())
        result = _wordlist_run(tmp_path, side_effect)
        assert result["counts"]["discovered"] == 0
        assert result["recommended_next_actions"] == []
        # ...and it must not have been converted into "no vhost here" either.
        assert result["counts"]["negative"] == 0
        assert result["counts"]["inconclusive"] == 5
        reasons = {i["reason"] for i in result["port_results"][0]["inconclusive"]}
        assert reasons == {"comparison_signals_unstable"}

    def test_dynamic_default_vhost_behind_static_catch_all(self, tmp_path):
        # Adversarial regression: measuring stability only on the
        # unrecognized-Host control still reported 5/5 candidates.
        def side_effect(*a, **k):
            if k["headers"]["Host"].endswith(".invalid"):
                return _fake_response(404, body=b"<html>static catch all</html>")
            return _fake_response(200, body=f"<html>session={uuid.uuid4().hex}</html>".encode())
        result = _wordlist_run(tmp_path, side_effect)
        assert result["counts"]["discovered"] == 0
        assert result["counts"]["negative"] == 0
        assert result["counts"]["inconclusive"] == 5

    def test_host_echoing_redirect_is_not_a_discovery(self, tmp_path):
        # nginx `return 301 https://$host$request_uri` previously produced a
        # unique Location for every candidate -> 5/5 MEDIUM false positives.
        def side_effect(url, **k):
            return _fake_response(301, headers={"Location": f"https://{k['headers']['Host']}/"}, body=b"")
        result = _wordlist_run(tmp_path, side_effect)
        assert result["counts"]["discovered"] == 0
        assert result["counts"]["negative"] == 5  # authoritative: same behaviour as the baselines

    def test_host_echoing_body_is_not_a_discovery(self, tmp_path):
        def side_effect(url, **k):
            return _fake_response(404, body=f"<html>No site configured for {k['headers']['Host']}</html>".encode())
        result = _wordlist_run(tmp_path, side_effect)
        assert result["counts"]["discovered"] == 0
        assert result["counts"]["negative"] == 5

    def test_rate_limiting_after_the_baselines_is_never_a_discovery(self, tmp_path):
        # Previously: once 429s started, every remaining candidate scored a
        # status difference and was reported at HIGH confidence.
        counter = itertools.count()
        def side_effect(*a, **k):
            if next(counter) < 4:
                return _fake_response(200, body=b"<html><title>D</title>hello</html>")
            return _fake_response(429, headers={"Retry-After": "120"}, body=b"slow down")
        result = _wordlist_run(tmp_path, side_effect)
        assert result["counts"]["discovered"] == 0
        assert result["counts"]["negative"] == 0
        assert result["counts"]["inconclusive"] == 5
        assert {i["reason"] for i in result["port_results"][0]["inconclusive"]} == {"non_authoritative_status"}

    @pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504, 521, 522, 530])
    def test_non_authoritative_statuses_are_inconclusive_not_absence(self, status):
        baseline = {"status": "found", "status_code": 200, "body": "default", "headers": {}}
        candidate = {"status": "found", "status_code": status, "body": "anything", "headers": {}}
        scored = vh.score_vhost_candidate(candidate, baseline, baseline)
        assert scored["score"] == 0
        assert scored["reason"] == "non_authoritative_status"
        assert scored["reason"] in vh.INCONCLUSIVE_REASONS

    def test_misdirected_request_is_an_authoritative_negative(self, tmp_path):
        counter = itertools.count()
        def side_effect(*a, **k):
            if next(counter) < 4:
                return _fake_response(200, body=b"<html><title>D</title>x</html>")
            return _fake_response(421, body=b"")
        result = _wordlist_run(tmp_path, side_effect)
        assert result["counts"]["discovered"] == 0
        assert result["counts"]["inconclusive"] == 0
        assert result["counts"]["negative"] == 5  # 421 answers the question
        records = vh.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        negatives = [r for r in records if r["type"] == "vhost_checked_no_distinct_response"]
        assert any("421" in e for e in negatives[0]["evidence"])


class TestTruePositivesStillDetected:
    """The false-positive fixes must not have cost real detections."""

    def test_genuinely_distinct_vhost_still_reaches_high_confidence(self, tmp_path):
        def side_effect(url, **k):
            host = k["headers"]["Host"]
            if host.startswith("admin"):
                return _fake_response(200, body=b"<html><title>Admin Panel</title>control panel</html>")
            return _fake_response(404, body=b"<html><title>Not Found</title>no site</html>")
        result = _wordlist_run(tmp_path, side_effect)
        assert result["counts"]["discovered"] == 1
        found = result["vhost_summary"]["vhosts"][0]
        assert found["hostname"] == "admin.example.com"
        assert found["confidence"] == vh.CONFIDENCE_HIGH
        assert result["counts"]["negative"] == 4
        assert result["recommended_next_actions"][0]["hostname"] == "admin.example.com"

    def test_distinct_vhost_detected_even_when_it_also_echoes_the_host(self, tmp_path):
        """Host-echo neutralization must not erase a real application difference."""
        def side_effect(url, **k):
            host = k["headers"]["Host"]
            if host.startswith("admin"):
                return _fake_response(200, body=f"<html><title>Admin</title>Control panel for {host}</html>".encode())
            return _fake_response(404, body=f"<html><title>NF</title>No site for {host}</html>".encode())
        result = _wordlist_run(tmp_path, side_effect)
        assert [v["hostname"] for v in result["vhost_summary"]["vhosts"]] == ["admin.example.com"]

    def test_redirect_to_a_different_target_still_scores(self):
        candidate = {"status": "found", "status_code": 302, "body": "",
                     "host_header_sent": "admin.example.com",
                     "headers": {"Location": "https://admin.example.com/login"}}
        baseline = {"status": "found", "status_code": 302, "body": "",
                    "host_header_sent": "93.184.216.34",
                    "headers": {"Location": "https://93.184.216.34/"}}
        scored = vh.score_vhost_candidate(candidate, baseline, baseline)
        assert scored["signals"].get("redirect_diff") is True

    def test_pure_host_echo_redirect_does_not_score(self):
        candidate = {"status": "found", "status_code": 301, "body": "",
                     "host_header_sent": "admin.example.com",
                     "headers": {"Location": "https://admin.example.com/"}}
        baseline = {"status": "found", "status_code": 301, "body": "",
                    "host_header_sent": "93.184.216.34",
                    "headers": {"Location": "https://93.184.216.34/"}}
        scored = vh.score_vhost_candidate(candidate, baseline, baseline)
        assert scored["signals"] == {}
        assert scored["score"] == 0


class TestConfidenceIsNotInflated:
    def test_shared_edge_infrastructure_caps_confidence_and_keeps_the_caveat(self, tmp_path):
        edge = {"Server": "cloudflare", "CF-RAY": "abc123-LHR"}
        def side_effect(url, **k):
            if k["headers"]["Host"].startswith("admin"):
                return _fake_response(200, headers=edge, body=b"<html><title>Admin</title>panel</html>")
            return _fake_response(404, headers=edge, body=b"<html><title>NF</title>nope</html>")
        result = _wordlist_run(tmp_path, side_effect)
        found = result["vhost_summary"]["vhosts"][0]
        assert found["score"] >= vh._HIGH_THRESHOLD          # the raw evidence is strong
        assert found["confidence"] == vh.CONFIDENCE_MEDIUM   # but attribution is not
        assert "cf-ray" in found["edge_indicators"]
        assert any("shared edge infrastructure" in c for c in found["caveats"])
        assert any("[CAVEAT]" in e for e in found["evidence"])
        assert result["recommended_next_actions"][0]["caveats"]

    def test_single_available_baseline_caps_confidence(self):
        candidate = {"status": "found", "status_code": 200,
                     "body": "<html><title>Admin</title>distinct</html>", "headers": {}}
        unavailable = {"status": "error", "error": "timeout"}
        baseline = {"status": "found", "status_code": 404, "body": "nope", "headers": {}}
        scored = vh.score_vhost_candidate(candidate, unavailable, baseline)
        assert scored["score"] >= vh._HIGH_THRESHOLD
        assert scored["confidence_cap"] == vh.CONFIDENCE_MEDIUM
        assert vh._apply_confidence_cap(vh._confidence_for_score(scored["score"]),
                                        scored["confidence_cap"]) == vh.CONFIDENCE_MEDIUM

    def test_confidence_cap_never_raises_confidence(self):
        assert vh._apply_confidence_cap(vh.CONFIDENCE_LOW, vh.CONFIDENCE_HIGH) == vh.CONFIDENCE_LOW
        assert vh._apply_confidence_cap(vh.CONFIDENCE_HIGH, vh.CONFIDENCE_MEDIUM) == vh.CONFIDENCE_MEDIUM
        assert vh._apply_confidence_cap(vh.CONFIDENCE_HIGH, None) == vh.CONFIDENCE_HIGH


class TestFailureIsNeverAbsence:
    def test_candidate_timeouts_are_inconclusive_not_negative(self, tmp_path):
        counter = itertools.count()
        def side_effect(*a, **k):
            if next(counter) < 4:
                return _fake_response(200, body=b"<html><title>D</title>x</html>")
            raise requests.exceptions.Timeout()
        result = _wordlist_run(tmp_path, side_effect)
        assert result["counts"]["negative"] == 0
        assert result["counts"]["inconclusive"] == 5
        assert vh.PendingAssetsStore(output_dir=str(tmp_path / "output")).all() == []

    def test_rate_limit_circuit_breaker_marks_the_rest_not_tested(self, tmp_path):
        counter = itertools.count()
        def side_effect(*a, **k):
            if next(counter) < 4:
                return _fake_response(200, body=b"<html><title>D</title>x</html>")
            return _fake_response(429, headers={"Retry-After": "600"}, body=b"slow down")
        labels = [f"l{i}" for i in range(20)]
        result = _wordlist_run(tmp_path, side_effect, labels=labels, max_consecutive_rate_limited=3)
        port = result["port_results"][0]
        assert port["candidates_checked"] == 3
        assert result["counts"]["not_tested"] == 17
        assert result["counts"]["negative"] == 0
        assert {n["reason"] for n in port["not_tested"]} == {"rate_limit_abort"}
        assert [e["retry_after"] for e in result["errors"] if e.get("stage") == "rate_limit"] == ["600"]

    def test_baselines_that_only_return_edge_failures_probe_nothing(self, tmp_path):
        def side_effect(*a, **k):
            return _fake_response(503, body=b"unavailable")
        result = _wordlist_run(tmp_path, side_effect)
        assert result["port_results"][0]["candidates_checked"] == 0
        assert result["counts"]["not_tested"] == 5
        assert result["counts"]["negative"] == 0
        assert any("non-authoritative" in str(e.get("error")) for e in result["errors"])

    def test_unverifiable_baseline_stability_blocks_negative_conclusions(self):
        baseline = {"status": "found", "status_code": 200, "body": "same", "headers": {}}
        candidate = {"status": "found", "status_code": 200, "body": "same", "headers": {}}
        unverified = {"verified": False, "status_stable": True, "content_stable": True,
                      "title_stable": True, "location_stable": True, "unstable_signals": [], "note": "x"}
        scored = vh.score_vhost_candidate(candidate, baseline, baseline, stability=unverified)
        assert scored["score"] == 0
        assert scored["reason"] == "comparison_signals_unstable"

    def test_omitting_stability_preserves_the_historical_negative_conclusion(self):
        baseline = {"status": "found", "status_code": 200, "body": "same", "headers": {}}
        candidate = {"status": "found", "status_code": 200, "body": "same", "headers": {}}
        scored = vh.score_vhost_candidate(candidate, baseline, baseline)
        assert scored["score"] == 0
        assert scored["reason"] is None  # authoritative "no distinct response"


class TestPersistenceRobustness:
    def test_os_error_while_persisting_does_not_discard_the_port_s_discoveries(self, tmp_path):
        class FullDisk(vh.PendingAssetsStore):
            def add(self, finding):
                raise OSError(28, "No space left on device")

        def side_effect(url, **k):
            if k["headers"]["Host"].startswith("admin"):
                return _fake_response(200, body=b"<html><title>Admin</title>secret</html>")
            return _fake_response(404, body=b"<html><title>NF</title>nope</html>")

        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.discover_vhosts_for_target(
                SAFE_IP, 80, "http", SAFE_TARGET,
                ["admin.example.com", "dev.example.com"], store=FullDisk(str(tmp_path / "o")),
            )
        assert [v["hostname"] for v in result["discovered_vhosts"]] == ["admin.example.com"]
        assert any(e["stage"] == "persist_vhost" for e in result["errors"])
        assert any("No space left" in str(e["error"]) for e in result["errors"])

    def test_safe_store_add_reports_os_error_instead_of_raising(self, tmp_path):
        class FullDisk(vh.PendingAssetsStore):
            def add(self, finding):
                raise OSError(13, "Permission denied")
        message = vh._safe_store_add(FullDisk(str(tmp_path / "o")), {"type": "x"})
        assert message and "Permission denied" in message

    def test_interruption_preserves_everything_already_persisted(self, tmp_path):
        store = vh.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        counter = itertools.count()
        def side_effect(url, **k):
            if next(counter) < 4:
                return _fake_response(404, body=b"<html><title>NF</title>nope</html>")
            if k["headers"]["Host"].startswith("admin"):
                return _fake_response(200, body=b"<html><title>Admin</title>panel</html>")
            raise KeyboardInterrupt()
        with pytest.raises(KeyboardInterrupt):
            with mock.patch("requests.get", side_effect=side_effect):
                vh.discover_vhosts_for_target(
                    SAFE_IP, 80, "http", SAFE_TARGET,
                    ["admin.example.com", "dev.example.com"], store=store,
                )
        persisted = store.all()
        assert [r["value"]["hostname"] for r in persisted] == ["admin.example.com"]


class TestHostnameSecurity:
    @pytest.mark.parametrize("bad", [
        "a\r\nX-Injected: 1.example.com",   # request splitting that ends in the authorized suffix
        "\x00evil.example.com",
        "admin.example.com:8080",           # port-qualified
        "user@admin.example.com",           # userinfo
        "http://admin.example.com/",        # a URL, not an authority
        "admin..example.com",               # empty label
        "-bad.example.com",                 # label may not start with a hyphen
        "*.example.com",                    # a wildcard SAN is not a Host header
        "x" * 300 + ".example.com",         # over 253 characters
        "admin example.com",
        "",
        "   ",
        None,
        123,
    ])
    def test_invalid_candidates_are_rejected_before_any_network_activity(self, bad):
        assert vh.normalize_candidate_hostname(bad) is None

    @pytest.mark.parametrize("value,expected", [
        ("ADMIN.Example.COM", "admin.example.com"),
        ("admin.example.com.", "admin.example.com"),
        ("  admin.example.com  ", "admin.example.com"),
        ("café.example.com", "xn--caf-dma.example.com"),
        ("_dmarc.example.com", "_dmarc.example.com"),
    ])
    def test_valid_candidates_are_normalized(self, value, expected):
        assert vh.normalize_candidate_hostname(value) == expected

    def test_malformed_candidates_never_reach_requests(self, tmp_path):
        sent = []
        def side_effect(url, **k):
            sent.append(k["headers"]["Host"])
            return _fake_response(200, body=b"<html>default</html>")
        hostile = ["admin.example.com", "a\r\nX: 1.example.com", "\x00x.example.com",
                   "admin.example.com:8080", "ADMIN.EXAMPLE.COM"]
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.discover_vhosts_for_target(SAFE_IP, 80, "http", SAFE_TARGET, hostile)
        probed = [h for h in sent if h != SAFE_IP and not h.endswith(".invalid")]
        assert probed == ["admin.example.com"]        # the uppercase form deduped into it
        assert result["duplicates_skipped"] == 1
        assert len(result["skipped_invalid"]) == 3

    @pytest.mark.parametrize("hostname", [
        "evil.com", "notexample.com", "example.com.evil.com",
        "a.example.com。evil.com",   # ideographic full stop is an IDNA label separator
    ])
    def test_scope_escape_attempts_are_never_probed(self, hostname, tmp_path):
        built = vh.build_candidate_hostnames(
            SAFE_TARGET, extra_hostnames=[hostname], wordlists_dir=str(tmp_path / "absent"),
        )
        assert built["candidates"] == []

    def test_invalid_target_fails_closed(self):
        for bad in ["", "   ", "not a domain!", None, "http://example.com/"]:
            with pytest.raises(vh.ScopeError):
                vh.validate_scan_target(bad)

    def test_run_vhost_scan_rejects_an_unusable_target_before_probing(self, tmp_path):
        with mock.patch("requests.get") as mocked:
            with pytest.raises(vh.ScopeError):
                vh.run_vhost_scan(SAFE_IP, target="not a domain!", output_dir=str(tmp_path / "o"))
        assert mocked.call_count == 0

    def test_invalid_candidate_is_recorded_never_silently_dropped(self, tmp_path):
        built = vh.build_candidate_hostnames(
            SAFE_TARGET, extra_hostnames=["admin.example.com:8080"],
            wordlists_dir=str(tmp_path / "absent"),
        )
        assert built["skipped_invalid"] == ["admin.example.com:8080"]

    @pytest.mark.parametrize("port,scheme", [(0, "http"), (65536, "http"), (80, "gopher"), ("x", "http")])
    def test_invalid_port_scheme_pairs_are_rejected(self, port, scheme):
        with pytest.raises(vh.ScopeError):
            vh._validate_port_scheme(port, scheme)

    def test_bad_port_does_not_stop_the_good_one(self, tmp_path):
        def side_effect(url, **k):
            return _fake_response(200, body=b"<html>default</html>")
        wl_dir = _write_wordlist(tmp_path, ["admin"])
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                ports=[(99999, "http"), (80, "gopher"), (80, "http")], wordlists_dir=wl_dir,
            )
        assert result["counts"]["ports_probed"] == 1
        assert result["counts"]["ports_rejected"] == 2
        assert sum(1 for e in result["errors"] if e.get("stage") == "target_validation") == 2


class TestHostileResponseSafety:
    def test_title_extraction_is_linear_on_a_repeated_unterminated_tag(self):
        # The previous regex backtracked quadratically: ~188 ms for 8,000
        # repetitions, seconds for a full 128 KB body, per response.
        body = "<title" * 20000 + "x" * 1000
        started = time.perf_counter()
        assert vh._extract_title(body) is None
        assert time.perf_counter() - started < 0.25

    def test_title_search_is_bounded_to_the_head_window(self):
        body = "y" * (vh._TITLE_SCAN_LIMIT + 10) + "<title>Late</title>"
        assert vh._extract_title(body) is None

    def test_oversized_title_and_location_are_clipped_in_evidence(self, tmp_path):
        huge_title = "A" * 200000
        huge_location = "http://x/" + "B" * 100000
        def side_effect(url, **k):
            if k["headers"]["Host"].startswith("admin"):
                return _fake_response(200, headers={"Location": huge_location},
                                      body=f"<html><title>{huge_title}</title></html>".encode())
            return _fake_response(404, body=b"<html><title>NF</title>nope</html>")
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.discover_vhosts_for_target(
                SAFE_IP, 80, "http", SAFE_TARGET, ["admin.example.com"],
            )
        evidence = result["discovered_vhosts"][0]["evidence"]
        assert sum(len(e) for e in evidence) < 4000   # previously 100,155 characters
        assert any("more chars]" in e for e in evidence)

    def test_binary_body_and_unknown_encoding_do_not_crash(self, tmp_path):
        def side_effect(url, **k):
            response = _fake_response(200, body=bytes(range(256)) * 100)
            response.encoding = "definitely-not-a-codec"
            return response
        result = _wordlist_run(tmp_path, side_effect)
        json.dumps(result)

    def test_a_host_header_the_client_refuses_becomes_an_error_not_an_exception(self):
        with mock.patch("requests.get", side_effect=ValueError("Invalid header value")):
            result = vh.fetch_with_host_header(SAFE_IP, 80, "http", "admin.example.com")
        assert result["status"] == "error"
        assert "invalid request" in result["error"]


class TestResourceSafety:
    @pytest.mark.parametrize("count", [1, 100, 1000, 10000])
    def test_request_count_is_exactly_one_per_candidate_plus_four_baselines(self, count):
        candidates = [f"h{i}.example.com" for i in range(count)]
        with mock.patch("requests.get",
                        return_value=_fake_response(200, body=b"<html><title>D</title>x</html>")) as mocked:
            result = vh.discover_vhosts_for_target(SAFE_IP, 80, "http", SAFE_TARGET, candidates)
        # No retries anywhere: worst-case amplification is bounded and flat.
        assert mocked.call_count == count + 4
        assert result["candidates_checked"] == count

    def test_detail_lists_are_bounded_while_counts_stay_exact(self):
        candidates = [f"h{i}.example.com" for i in range(10000)]
        counter = itertools.count()
        def side_effect(*a, **k):
            if next(counter) < 4:
                return _fake_response(200, body=b"<html><title>D</title>x</html>")
            raise requests.exceptions.Timeout()
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.discover_vhosts_for_target(SAFE_IP, 80, "http", SAFE_TARGET, candidates)
        assert result["inconclusive_count"] == 10000
        assert len(result["inconclusive"]) <= vh._MAX_RETAINED_DETAIL + 1
        assert len(json.dumps(result)) < 5_000_000

    def test_duplicate_candidates_are_probed_and_persisted_once(self, tmp_path):
        store = vh.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("requests.get",
                        return_value=_fake_response(200, body=b"<html><title>D</title>x</html>")) as mocked:
            result = vh.discover_vhosts_for_target(
                SAFE_IP, 80, "http", SAFE_TARGET,
                ["admin.example.com", "ADMIN.example.com", "admin.example.com.", "admin.example.com"],
                store=store,
            )
        assert result["candidates_checked"] == 1
        assert result["duplicates_skipped"] == 3
        assert mocked.call_count == 5
        assert len(store.all()) == 1


class TestSniHandling:
    def test_default_mode_sends_no_sni_and_preserves_the_requests_path(self):
        with mock.patch("requests.get", return_value=_fake_response(200, body=b"x")) as mocked:
            result = vh.fetch_with_host_header(SAFE_IP, 443, "https", "admin.example.com")
        assert result["sni_hostname_sent"] is None
        assert mocked.call_args.kwargs["verify"] is False

    @pytest.mark.parametrize("mode,scheme,expected", [
        (vh.SNI_MODE_CONNECTION, "https", None),
        (vh.SNI_MODE_CANDIDATE, "https", "admin.example.com"),
        (vh.SNI_MODE_CANDIDATE, "http", None),
        (vh.SNI_MODE_CONNECTION, "http", None),
    ])
    def test_resolve_sni_hostname(self, mode, scheme, expected):
        assert vh.resolve_sni_hostname(mode, scheme, "admin.example.com") == expected

    def test_candidate_mode_pins_sni_on_the_transport_adapter(self):
        captured = {}

        class FakeSession:
            def __init__(self):
                self.adapter = None
            def mount(self, prefix, adapter):
                self.adapter = adapter
            def get(self, url, **kwargs):
                captured["sni"] = self.adapter._server_hostname
                captured["verify"] = kwargs["verify"]
                captured["host"] = kwargs["headers"]["Host"]
                return _fake_response(200, body=b"x")
            def close(self):
                captured["closed"] = True

        with mock.patch("requests.Session", FakeSession):
            result = vh.fetch_with_host_header(
                SAFE_IP, 443, "https", "admin.example.com", sni_hostname="admin.example.com",
            )
        assert captured == {"sni": "admin.example.com", "verify": False,
                            "host": "admin.example.com", "closed": True}
        assert result["sni_hostname_sent"] == "admin.example.com"

    def test_sni_adapter_puts_the_hostname_into_the_pool_manager(self):
        adapter = vh._SNIAdapter("admin.example.com")
        pool = adapter.poolmanager.connection_from_host("93.184.216.34", 443, scheme="https")
        assert pool.conn_kw["server_hostname"] == "admin.example.com"

    def test_unsupported_sni_mode_is_rejected(self, tmp_path):
        with pytest.raises(vh.ScopeError):
            vh.run_vhost_scan(SAFE_IP, target=SAFE_TARGET,
                              output_dir=str(tmp_path / "o"), sni_mode="spoofed")


class TestSummaryContract:
    def test_counts_block_accounts_for_every_candidate(self, tmp_path):
        def side_effect(url, **k):
            if k["headers"]["Host"].startswith("admin"):
                return _fake_response(200, body=b"<html><title>Admin</title>panel</html>")
            return _fake_response(404, body=b"<html><title>NF</title>nope</html>")
        result = _wordlist_run(tmp_path, side_effect)
        counts = result["counts"]
        assert counts["discovered"] + counts["negative"] + counts["inconclusive"] + counts["not_tested"] \
            == counts["candidates"]
        json.dumps(result)

    def test_finding_shape_is_unchanged_for_surface_mapper(self, tmp_path):
        def side_effect(url, **k):
            if k["headers"]["Host"].startswith("admin"):
                return _fake_response(200, body=b"<html><title>Admin</title>panel</html>")
            return _fake_response(404, body=b"<html><title>NF</title>nope</html>")
        _wordlist_run(tmp_path, side_effect)
        records = vh.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        discovered = [r for r in records if r["type"] == "vhost_discovered"]
        assert len(discovered) == 1
        finding = discovered[0]
        # The exact contract surface_mapper._h_vhost_discovered reads.
        assert set(finding) == {"type", "target", "value", "evidence", "confidence",
                                "source", "timestamp", "metadata"}
        assert set(finding["value"]) == {"ip", "port", "scheme", "hostname", "host_header", "connect_url"}
        assert finding["source"] == "vhost_scanner.py"
        assert finding["value"]["hostname"] == "admin.example.com"
        assert finding["value"]["connect_url"] == f"http://{SAFE_IP}:80/"
        assert finding["confidence"] in (vh.CONFIDENCE_LOW, vh.CONFIDENCE_MEDIUM, vh.CONFIDENCE_HIGH)
        # New provenance is additive, inside metadata only.
        assert finding["metadata"]["baseline_stability_verified"] is True
        assert finding["metadata"]["sni_mode"] == vh.SNI_MODE_CONNECTION

    def test_negative_finding_shape_is_unchanged(self, tmp_path):
        def side_effect(url, **k):
            return _fake_response(404, body=b"<html><title>NF</title>nope</html>")
        _wordlist_run(tmp_path, side_effect, labels=["admin"])
        records = vh.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        negative = [r for r in records if r["type"] == "vhost_checked_no_distinct_response"][0]
        assert set(negative["value"]) == {"ip", "port", "scheme", "hostname", "connect_url"}
        assert negative["confidence"] == vh.CONFIDENCE_LOW

    def test_inconclusive_results_are_never_persisted_as_findings(self, tmp_path):
        def side_effect(*a, **k):
            return _fake_response(200, body=f"<html>rid={uuid.uuid4().hex}</html>".encode())
        _wordlist_run(tmp_path, side_effect)
        assert vh.PendingAssetsStore(output_dir=str(tmp_path / "output")).all() == []


class TestCandidateAccounting:
    """Every candidate must land in exactly one bucket, on every code path."""

    @staticmethod
    def _assert_accounted(result):
        counts = result["counts"]
        assert counts["discovered"] + counts["negative"] + counts["inconclusive"] + counts["not_tested"] \
            == counts["candidates"], counts

    def test_accounted_when_both_baselines_fail(self, tmp_path):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "o"),
                ports=[(80, "http")], wordlists_dir=_write_wordlist(tmp_path, ["a", "b", "c"]),
            )
        assert result["counts"]["not_tested"] == 3
        assert result["counts"]["negative"] == 0
        self._assert_accounted(result)

    def test_accounted_when_the_port_is_rejected(self, tmp_path):
        with mock.patch("requests.get") as mocked:
            result = vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "o"),
                ports=[(80, "gopher")], wordlists_dir=_write_wordlist(tmp_path, ["a", "b", "c"]),
            )
        assert mocked.call_count == 0
        assert result["counts"]["not_tested"] == 3
        self._assert_accounted(result)

    def test_accounted_when_probing_is_abandoned_for_rate_limiting(self, tmp_path):
        counter = itertools.count()
        def side_effect(*a, **k):
            if next(counter) < 4:
                return _fake_response(200, body=b"<html><title>D</title>x</html>")
            return _fake_response(503, body=b"unavailable")
        result = _wordlist_run(tmp_path, side_effect,
                               labels=[f"l{i}" for i in range(10)], max_consecutive_rate_limited=2)
        self._assert_accounted(result)
        assert result["counts"]["negative"] == 0


# ===========================================================================
# Regression coverage for the second round of the audit (adversarial passes
# 5-7): defects found by attacking the first round of fixes.
# ===========================================================================

class TestApplicationHeaderEvidence:
    """
    A distinct backend behind a reverse proxy can render an identical page.
    Ignoring application headers made that a *confirmed absence* — the worst
    kind of false negative, because it poisons negative-result memory.
    """

    def test_distinct_backend_with_identical_page_is_no_longer_a_negative(self, tmp_path):
        page = b"<html><title>Welcome</title></html>"
        def side_effect(url, **k):
            if k["headers"]["Host"].startswith("admin"):
                return _fake_response(200, headers={
                    "Server": "nginx", "X-Powered-By": "PHP/8.2", "Content-Type": "text/html",
                    "Set-Cookie": f"PHPSESSID={uuid.uuid4().hex}; Path=/",
                }, body=page)
            return _fake_response(200, headers={"Server": "nginx", "Content-Type": "text/html"}, body=page)
        result = _wordlist_run(tmp_path, side_effect)
        assert result["counts"]["discovered"] == 1
        found = result["vhost_summary"]["vhosts"][0]
        assert found["hostname"] == "admin.example.com"
        assert found["signals"] == {"header_diff": True}
        # A weak signal on its own stays LOW and is therefore never queued
        # for downstream reconnaissance.
        assert found["confidence"] == vh.CONFIDENCE_LOW
        assert result["recommended_next_actions"] == []
        assert result["counts"]["negative"] == 4

    def test_rotating_cookie_value_is_not_evidence(self, tmp_path):
        def side_effect(*a, **k):
            return _fake_response(200, headers={"Set-Cookie": f"sid={uuid.uuid4().hex}; Path=/",
                                                "Server": "nginx"},
                                  body=b"<html><title>Same</title>same</html>")
        result = _wordlist_run(tmp_path, side_effect)
        assert result["counts"]["discovered"] == 0
        assert result["counts"]["negative"] == 5

    def test_cookie_attributes_are_not_cookie_names(self):
        with_expiry = vh._app_header_signature(
            {"Set-Cookie": "sid=abc; Expires=Wed, 21 Oct 2025 07:28:00 GMT; Path=/; HttpOnly"}, None)
        without = vh._app_header_signature({"Set-Cookie": "sid=def; Path=/; HttpOnly"}, None)
        assert with_expiry == without == "cookies=sid"

    def test_distinct_cookie_names_still_differ(self):
        php = vh._app_header_signature({"Set-Cookie": "PHPSESSID=x; Path=/"}, None)
        java = vh._app_header_signature({"Set-Cookie": "JSESSIONID=y; Path=/"}, None)
        assert php != java

    def test_multiple_cookies_joined_by_requests_are_split_correctly(self):
        joined = "a=1; Path=/, b=2; Expires=Wed, 21 Oct 2025 07:28:00 GMT"
        assert vh._app_header_signature({"Set-Cookie": joined}, None) == "cookies=a,b"

    def test_content_type_parameters_are_ignored(self):
        a = vh._app_header_signature({"Content-Type": "text/html; charset=utf-8"}, None)
        b = vh._app_header_signature({"Content-Type": "text/html"}, None)
        assert a == b

    def test_header_that_echoes_the_host_is_neutralized(self):
        a = vh._app_header_signature({"X-Redirect-By": "admin.example.com"}, "admin.example.com")
        b = vh._app_header_signature({"X-Redirect-By": "dev.example.com"}, "dev.example.com")
        assert a == b

    def test_unstable_application_headers_are_excluded_from_scoring(self):
        stability = {"verified": True, "status_stable": True, "content_stable": True,
                     "title_stable": True, "location_stable": True, "header_stable": False,
                     "unstable_signals": ["header"], "note": "headers vary"}
        baseline = {"status": "found", "status_code": 200, "body": "same",
                    "headers": {"Server": "nginx"}}
        candidate = {"status": "found", "status_code": 200, "body": "same",
                     "headers": {"Server": "apache"}}
        scored = vh.score_vhost_candidate(candidate, baseline, baseline, stability=stability)
        assert scored["signals"] == {}
        assert "header" in scored["excluded_signals"]

    def test_dynamic_headers_are_detected_by_the_stability_controls(self):
        def side_effect(*a, **k):
            return _fake_response(200, headers={"Server": f"nginx/{uuid.uuid4().hex[:4]}"}, body=b"x")
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.probe_baselines(SAFE_IP, 80, "http")
        assert result["stability"]["header_stable"] is False
        assert "header" in result["stability"]["unstable_signals"]

    def test_edge_server_headers_are_identical_and_yield_no_signal(self, tmp_path):
        edge = {"Server": "cloudflare", "CF-RAY": "abc", "Content-Type": "text/html"}
        def side_effect(*a, **k):
            return _fake_response(200, headers=edge, body=b"<html><title>Same</title>same</html>")
        result = _wordlist_run(tmp_path, side_effect)
        assert result["counts"]["discovered"] == 0


class TestPersistenceConcurrency:
    def test_stores_on_one_path_share_a_process_wide_lock(self, tmp_path):
        a = vh.PendingAssetsStore(output_dir=str(tmp_path / "o"))
        b = vh.PendingAssetsStore(output_dir=str(tmp_path / "o"))
        c = vh.PendingAssetsStore(output_dir=str(tmp_path / "other"))
        assert a._lock is b._lock
        assert a._lock is not c._lock

    def test_concurrent_stores_on_one_file_lose_nothing(self, tmp_path):
        # Before this fix each store held a *per-instance* lock, so two
        # concurrent run_vhost_scan() calls against one output directory
        # interleaved their read/append/rewrite cycles: measured 4 of 20
        # findings persisted, 80% silently lost.
        output_dir = str(tmp_path / "o")
        def worker(n):
            store = vh.PendingAssetsStore(output_dir=output_dir)
            for i in range(25):
                store.add(vh.make_finding("t", SAFE_TARGET, {"n": n, "i": i}, ["e"], vh.CONFIDENCE_LOW))
        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(vh.PendingAssetsStore(output_dir=output_dir).all()) == 200

    def test_concurrent_scans_on_one_output_dir_persist_everything(self, tmp_path):
        wl_dir = _write_wordlist(tmp_path, ["admin", "dev", "staging", "qa", "test"])
        output_dir = str(tmp_path / "output")
        def side_effect(url, **k):
            if k["headers"]["Host"].startswith(("admin", "dev")):
                return _fake_response(200, body=b"<html><title>A</title>panel</html>")
            return _fake_response(404, body=b"<html><title>NF</title>no</html>")
        failures = []
        def runner(ip):
            try:
                vh.run_vhost_scan(ip, target=SAFE_TARGET, output_dir=output_dir,
                                  ports=[(80, "http")], wordlists_dir=wl_dir)
            except Exception as exc:                      # pragma: no cover
                failures.append(repr(exc))
        with mock.patch("requests.get", side_effect=side_effect):
            threads = [threading.Thread(target=runner, args=(f"10.0.0.{i}",)) for i in range(1, 5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        assert failures == []
        records = vh.PendingAssetsStore(output_dir=output_dir).all()
        assert len(records) == 20                          # 4 IPs x 5 candidates
        assert sorted({r["value"]["ip"] for r in records}) == [f"10.0.0.{i}" for i in range(1, 5)]


class TestTransportRobustness:
    def test_non_bytes_body_does_not_raise(self):
        response = mock.MagicMock()
        response.status_code = 200
        response.headers = {}
        response.encoding = "utf-8"
        response.content = b"x"
        response.elapsed.total_seconds.return_value = 0.01
        response.raw.read.return_value = "i am text, not bytes"
        with mock.patch("requests.get", return_value=response):
            result = vh.fetch_with_host_header(SAFE_IP, 80, "http", "admin.example.com")
        assert result["status"] == "found"
        assert result["body"] == "i am text, not bytes"

    def test_none_body_does_not_raise(self):
        response = mock.MagicMock()
        response.status_code = 204
        response.headers = {}
        response.encoding = None
        response.content = b""
        response.elapsed.total_seconds.return_value = 0.01
        response.raw.read.return_value = None
        with mock.patch("requests.get", return_value=response):
            result = vh.fetch_with_host_header(SAFE_IP, 80, "http", "admin.example.com")
        assert result["status"] == "found"
        assert result["body"] == ""

    def test_ipv6_scan_end_to_end(self, tmp_path):
        seen = []
        def side_effect(url, **k):
            seen.append((url, k["headers"]["Host"]))
            return _fake_response(404, body=b"<html><title>NF</title>x</html>")
        wl_dir = _write_wordlist(tmp_path, ["admin"])
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.run_vhost_scan(
                "2606:2800:220:1:248:1893:25c8:1946", target=SAFE_TARGET,
                output_dir=str(tmp_path / "o"), ports=[(443, "https")], wordlists_dir=wl_dir,
            )
        assert seen[0] == ("https://[2606:2800:220:1:248:1893:25c8:1946]:443/",
                           "[2606:2800:220:1:248:1893:25c8:1946]")
        assert seen[-1][1] == "admin.example.com"
        assert result["counts"]["negative"] == 1
        json.dumps(result)

    def test_idn_candidates_are_punycode_on_the_wire(self, tmp_path):
        sent = []
        def side_effect(url, **k):
            sent.append(k["headers"]["Host"])
            return _fake_response(404, body=b"<html><title>NF</title>x</html>")
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "o"),
                ports=[(80, "http")], wordlists_dir=_write_wordlist(tmp_path, []),
                extra_hostnames=["café.example.com", "münchen.example.com"],
            )
        assert result["candidate_build"]["candidates"] == [
            "xn--caf-dma.example.com", "xn--mnchen-3ya.example.com"]
        assert all(host.isascii() for host in sent)


class TestNegativeResultsCarryTheirLimits:
    def test_truncated_comparison_is_recorded_on_the_negative_finding(self, tmp_path):
        # The bodies differ only past the 128 KB read limit, so
        # "indistinguishable" was established over a partial response. The
        # negative is still recorded, but it must say so.
        prefix = b"<html><title>T</title>" + b"a" * 200000
        def side_effect(url, **k):
            suffix = b"UNIQUE" if k["headers"]["Host"].startswith("admin") else b"DEFAULT"
            return _fake_response(200, body=prefix + suffix)
        store = vh.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("requests.get", side_effect=side_effect):
            vh.discover_vhosts_for_target(SAFE_IP, 80, "http", SAFE_TARGET,
                                          ["admin.example.com"], store=store)
        negative = store.all()[0]
        assert negative["type"] == "vhost_checked_no_distinct_response"
        assert any("read limit" in e for e in negative["evidence"])

    def test_single_baseline_caveat_reaches_the_negative_finding(self, tmp_path):
        def side_effect(url, **k):
            if k["headers"]["Host"] == SAFE_IP:
                raise requests.exceptions.ConnectionError("refused")
            return _fake_response(404, body=b"<html><title>NF</title>nope</html>")
        store = vh.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("requests.get", side_effect=side_effect):
            vh.discover_vhosts_for_target(SAFE_IP, 80, "http", SAFE_TARGET,
                                          ["admin.example.com"], store=store)
        negative = store.all()[0]
        assert any("single control" in e for e in negative["evidence"])


class TestErrorListBounding:
    def test_error_listing_is_capped_while_the_count_stays_exact(self):
        counter = itertools.count()
        def side_effect(*a, **k):
            if next(counter) < 4:
                return _fake_response(200, body=b"<html><title>D</title>x</html>")
            raise requests.exceptions.ConnectionError("reset by peer")
        candidates = [f"e{i}.example.com" for i in range(10000)]
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.discover_vhosts_for_target(SAFE_IP, 80, "http", SAFE_TARGET, candidates)
        assert result["error_count"] == 10000
        assert len(result["errors"]) <= vh._MAX_RETAINED_DETAIL + 1
        assert any(e["stage"] == "errors_truncated" for e in result["errors"])
        assert len(json.dumps(result)) < 2_000_000

    def test_summary_error_count_is_exact_even_when_listings_are_capped(self, tmp_path):
        counter = itertools.count()
        def side_effect(*a, **k):
            if next(counter) < 4:
                return _fake_response(200, body=b"<html><title>D</title>x</html>")
            raise requests.exceptions.ConnectionError("reset")
        result = _wordlist_run(tmp_path, side_effect, labels=[f"l{i}" for i in range(600)])
        assert result["counts"]["errors"] == 600


class TestPublicEntryPointScope:
    """
    discover_vhosts_for_target() is a public entry point. Before this, it
    trusted its candidate list completely: an out-of-scope hostname was
    probed and persisted as a `vhost_discovered` finding carrying the
    authorized target, which surface_mapper.py promotes to an asset.
    """

    def test_out_of_scope_candidates_are_not_probed_or_persisted(self, tmp_path):
        sent = []
        def side_effect(url, **k):
            sent.append(k["headers"]["Host"])
            return _fake_response(200, body=b"<html><title>Evil</title>different app</html>")
        store = vh.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.discover_vhosts_for_target(
                SAFE_IP, 80, "http", SAFE_TARGET,
                ["evil.com", "attacker.test", "admin.example.com"], store=store,
            )
        probed = [h for h in sent if h != SAFE_IP and not h.endswith(".invalid")]
        assert probed == ["admin.example.com"]
        assert result["skipped_out_of_scope"] == ["evil.com", "attacker.test"]
        assert all(r["value"]["hostname"] == "admin.example.com" for r in store.all())
        assert any(e["stage"] == "candidate_scope" for e in result["errors"])

    def test_explicit_opt_in_still_permits_out_of_scope_probing(self, tmp_path):
        sent = []
        def side_effect(url, **k):
            sent.append(k["headers"]["Host"])
            if k["headers"]["Host"] == "partner.test":
                return _fake_response(200, body=b"<html><title>Partner</title>app</html>")
            return _fake_response(404, body=b"<html><title>NF</title>x</html>")
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.discover_vhosts_for_target(
                SAFE_IP, 80, "http", SAFE_TARGET, ["partner.test"], allow_out_of_scope=True,
            )
        assert "partner.test" in sent
        assert [v["hostname"] for v in result["discovered_vhosts"]] == ["partner.test"]

    def test_run_vhost_scan_threads_the_opt_in_through(self, tmp_path):
        sent = []
        def side_effect(url, **k):
            sent.append(k["headers"]["Host"])
            return _fake_response(404, body=b"<html><title>NF</title>x</html>")
        with mock.patch("requests.get", side_effect=side_effect):
            vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "o"),
                ports=[(80, "http")], wordlists_dir=_write_wordlist(tmp_path, []),
                extra_hostnames=["partner.test"], allow_out_of_scope_hostnames=True,
            )
        assert "partner.test" in sent


class TestInputShapeSafety:
    def test_a_bare_string_candidate_list_is_not_iterated_by_character(self, tmp_path):
        sent = []
        def side_effect(url, **k):
            sent.append(k["headers"]["Host"])
            return _fake_response(404, body=b"<html><title>NF</title>x</html>")
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.discover_vhosts_for_target(
                SAFE_IP, 80, "http", SAFE_TARGET, "admin.example.com",
            )
        probed = [h for h in sent if h != SAFE_IP and not h.endswith(".invalid")]
        assert probed == ["admin.example.com"]
        assert result["candidates_checked"] == 1

    def test_a_bare_string_extra_hostnames_is_not_iterated_by_character(self, tmp_path):
        built = vh.build_candidate_hostnames(
            SAFE_TARGET, extra_hostnames="admin.example.com",
            wordlists_dir=str(tmp_path / "absent"),
        )
        assert built["candidates"] == ["admin.example.com"]
        assert built["skipped_out_of_scope"] == []

    @pytest.mark.parametrize("bound,expected", [(None, 5), (0, 0), (2, 2), (-1, 0), (-5, 0)])
    def test_max_candidates_never_slices_from_the_end(self, bound, expected):
        candidates = [f"c{i}.example.com" for i in range(5)]
        prepared = vh.prepare_candidate_list(candidates, max_candidates=bound)
        assert len(prepared["candidates"]) == expected

    @pytest.mark.parametrize("bound", [0, -1, -100])
    def test_non_positive_rate_limit_bound_disables_the_circuit_breaker(self, bound):
        counter = itertools.count()
        def side_effect(*a, **k):
            if next(counter) < 4:
                return _fake_response(200, body=b"<html><title>D</title>x</html>")
            return _fake_response(429, body=b"stop")
        candidates = [f"c{i}.example.com" for i in range(5)]
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.discover_vhosts_for_target(
                SAFE_IP, 80, "http", SAFE_TARGET, candidates,
                max_consecutive_rate_limited=bound,
            )
        assert result["candidates_checked"] == 5
        assert result["not_tested_count"] == 0


class TestPortListHandling:
    def test_duplicate_and_case_variant_ports_are_collapsed(self, tmp_path):
        calls = []
        def side_effect(url, **k):
            calls.append(url)
            return _fake_response(404, body=b"<html><title>NF</title>x</html>")
        output_dir = str(tmp_path / "output")
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=output_dir,
                ports=[(80, "http"), (80, "http"), (80, "HTTP")],
                wordlists_dir=_write_wordlist(tmp_path, ["admin"]),
            )
        assert len(calls) == 5                    # 4 baselines + 1 candidate, probed once
        assert len(result["port_results"]) == 1
        assert len(vh.PendingAssetsStore(output_dir=output_dir).all()) == 1

    def test_duplicates_and_invalid_ports_together(self, tmp_path):
        def side_effect(url, **k):
            return _fake_response(404, body=b"<html><title>NF</title>x</html>")
        with mock.patch("requests.get", side_effect=side_effect):
            result = vh.run_vhost_scan(
                SAFE_IP, target=SAFE_TARGET, output_dir=str(tmp_path / "o"),
                ports=[(80, "http"), (80, "http"), (99999, "http"), (443, "https")],
                wordlists_dir=_write_wordlist(tmp_path, ["admin"]),
            )
        assert result["counts"]["ports_probed"] == 2
        assert result["counts"]["ports_rejected"] == 1


# ---------------------------------------------------------------------------
# Producer -> consumer contract, exercised through the real integration path.
# This module is never modified to suit a consumer; the test exists so a
# change here that would break core/orchestrator.py or surface_mapper.py
# fails loudly in this module's own suite.
# ---------------------------------------------------------------------------

class TestDownstreamIntegration:
    def test_orchestrator_ingests_discoveries_and_surfaces_the_counts(self, tmp_path):
        from reconhound.core import orchestrator as orch

        output_dir = str(tmp_path / "out")
        wordlists = tmp_path / "wordlists"
        wordlists.mkdir()
        (wordlists / "subdomains.txt").write_text("admin\ndev\nstaging\n")
        os.makedirs(output_dir, exist_ok=True)
        seed = {
            "type": "dns_record", "target": SAFE_TARGET, "source": "passive_recon.py",
            "timestamp": "2026-01-01T00:00:00+00:00", "confidence": "HIGH", "evidence": ["seed"],
            "value": {"hostname": SAFE_TARGET, "record_type": "A", "records": [SAFE_IP]},
            "metadata": {},
        }
        with open(os.path.join(output_dir, "pending_assets.json"), "w") as handle:
            json.dump([seed], handle)

        def side_effect(url, **k):
            if k["headers"]["Host"].startswith("admin"):
                return _fake_response(200, headers={"Server": "nginx"},
                                      body=b"<html><title>Admin Panel</title>control panel</html>")
            return _fake_response(404, headers={"Server": "nginx"},
                                  body=b"<html><title>Not Found</title>no site</html>")

        with mock.patch("requests.get", side_effect=side_effect):
            result = orch.run_orchestrator(
                SAFE_TARGET, output_dir=output_dir, mode="module",
                modules=["vhost_scanner"], wordlists_dir=str(wordlists),
            )

        executions = [e for e in result["executions"] if e["module"] == "vhost_scanner"]
        assert len(executions) == 1
        execution = executions[0]
        assert execution["status"] == "success"
        assert execution["subject"] == SAFE_IP
        assert execution["module_error_count"] == 0
        assert execution["observations_ingested"] > 0
        # Failure-vs-absence accounting must reach the execution record, so an
        # operator can tell "nothing there" from "could not be established".
        for key in ("counts.discovered", "counts.negative",
                    "counts.inconclusive", "counts.not_tested"):
            assert key in execution["stats"], key
        assert execution["stats"]["counts.discovered"] >= 1

        with open(os.path.join(output_dir, "surface_graph.json")) as handle:
            graph = json.load(handle)
        hostnames = [a for a in graph["assets"].values() if a["asset_type"] == "hostname"]
        vhost_assets = [a["value"] for a in hostnames
                        if "discovered_via_vhost_scan" in a["attributes"]]
        # Two ports found the same hostname: one asset, not two.
        assert vhost_assets == ["admin.example.com"]
        assert all(a.get("in_scope") for a in hostnames)
        opportunities = [o for o in (graph.get("opportunities") or {}).values()
                         if o.get("opportunity_type") == "vhost_web_followup"]
        assert len(opportunities) == 1
        for name in os.listdir(output_dir):
            if name.endswith(".json"):
                with open(os.path.join(output_dir, name)) as handle:
                    json.load(handle)


class TestCaveatsDoNotDeflateGoodEvidence:
    """
    Truncation limits *coverage*, not reliability: a difference seen inside
    the read limit is exactly as strong as it looks. Capping confidence on it
    would silently downgrade every genuine discovery on any site whose
    default page exceeds 128 KB.
    """

    def test_truncation_is_recorded_but_does_not_cap_confidence(self):
        filler = "z" * (vh.DEFAULT_MAX_BODY_BYTES + 10)
        candidate = {"status": "found", "status_code": 200, "body_truncated": True,
                     "body": f"<html><title>Admin Panel</title>{filler}</html>", "headers": {}}
        baseline = {"status": "found", "status_code": 404, "body_truncated": True,
                    "body": f"<html><title>Not Found</title>{filler}nope</html>", "headers": {}}
        scored = vh.score_vhost_candidate(candidate, baseline, baseline)
        assert scored["score"] >= vh._HIGH_THRESHOLD
        assert scored["confidence_cap"] is None
        assert any("read limit" in c for c in scored["caveats"])
        assert vh._apply_confidence_cap(vh._confidence_for_score(scored["score"]),
                                        scored["confidence_cap"]) == vh.CONFIDENCE_HIGH

    def test_reliability_caveats_still_cap(self):
        candidate = {"status": "found", "status_code": 200, "headers": {"CF-RAY": "x"},
                     "body": "<html><title>Admin</title>distinct</html>"}
        baseline = {"status": "found", "status_code": 404, "headers": {"CF-RAY": "y"},
                    "body": "<html><title>NF</title>nope</html>"}
        scored = vh.score_vhost_candidate(candidate, baseline, baseline)
        assert scored["confidence_cap"] == vh.CONFIDENCE_MEDIUM

    def test_mismatched_baseline_fingerprints_do_not_crash(self):
        candidate = {"status": "found", "status_code": 200,
                     "body": "<html><title>Admin</title>distinct</html>", "headers": {}}
        baseline = {"status": "found", "status_code": 404, "body": "nope", "headers": {}}
        # A caller supplying (None, None) while both baselines are usable must
        # not make differs() dereference None.
        scored = vh.score_vhost_candidate(candidate, baseline, baseline,
                                          baseline_fingerprints=(None, None))
        assert scored["score"] > 0
        assert scored["signals"]["status_diff"] is True
