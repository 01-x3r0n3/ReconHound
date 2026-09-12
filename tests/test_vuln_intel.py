"""
Tests for reconhound/vuln_intel.py (ReconHound Module 19, per context.md's
catalog item 19; built under a temporary, user-approved build-order
deviation ahead of surface_mapper.py and tech_fingerprint.py — see the
module docstring for details).

Run with:  ./.venv/bin/python -m pytest tests/test_vuln_intel.py -v

All tests mock the `requests.get`/`requests.post` boundary so the suite is
deterministic and offline-safe; no external network access (including to
NVD, OSV, GitHub, CISA, or GitLab) is required or performed anywhere in
this file.
"""

import json
import os
import sys
from unittest import mock

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import vuln_intel as vi


# ---------------------------------------------------------------------------
# Offline guard: the tests below (and above) mock `reconhound.vuln_intel.requests.*`
# or the provider functions themselves. If any code path slips past those
# mocks and reaches the real HTTP adapter, fail loudly instead of touching
# NVD/OSV/GitHub/CISA/GitLab/FIRST from the test suite.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    import requests.adapters

    def _blocked(self, request, *args, **kwargs):  # pragma: no cover - only fires on a defect
        raise AssertionError(f"test attempted real network access: {request.method} {request.url}")

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", _blocked)
    yield


def _fake_response(status_code=200, json_data=None, text=None, headers=None, raise_json_error=False):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = dict(headers or {})
    if raise_json_error:
        resp.json.side_effect = ValueError("bad json")
    else:
        resp.json.return_value = json_data
    resp.text = text if text is not None else (json.dumps(json_data) if json_data is not None else "")
    return resp


# ---------------------------------------------------------------------------
# make_finding / PendingAssetsStore
# ---------------------------------------------------------------------------

class TestMakeFinding:
    def test_shape(self):
        finding = vi.make_finding("vulnerability_intelligence", "example.com", {"a": 1}, ["evidence"], vi.CONFIDENCE_LOW)
        assert finding["type"] == "vulnerability_intelligence"
        assert finding["target"] == "example.com"
        assert finding["value"] == {"a": 1}
        assert finding["evidence"] == ["evidence"]
        assert finding["confidence"] == vi.CONFIDENCE_LOW
        assert finding["source"] == vi.MODULE_NAME
        assert "timestamp" in finding
        assert finding["metadata"] == {}

    def test_json_safe(self):
        finding = vi.make_finding("vulnerability_intelligence", "t", {"a": [1, 2]}, ["e"], vi.CONFIDENCE_HIGH)
        json.dumps(finding)  # must not raise


class TestPendingAssetsStore:
    def test_add_and_read_back(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        finding = vi.make_finding("vulnerability_intelligence", "t", {"x": 1}, ["e"], vi.CONFIDENCE_LOW)
        store.add(finding)
        records = store.all()
        assert len(records) == 1
        assert records[0]["type"] == "vulnerability_intelligence"

    def test_preserves_existing_unrelated_records(self, tmp_path):
        path = tmp_path / "pending_assets.json"
        path.write_text(json.dumps([{"type": "dns_record", "target": "x", "value": {}, "evidence": [],
                                      "confidence": "LOW", "source": "passive_recon.py",
                                      "timestamp": "t", "metadata": {}}]))
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(vi.make_finding("vulnerability_intelligence", "t", {}, [], vi.CONFIDENCE_LOW))
        records = store.all()
        assert len(records) == 2
        assert records[0]["type"] == "dns_record"

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        path = tmp_path / "pending_assets.json"
        path.write_text("{not valid json")
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        with pytest.raises(vi.PersistenceError):
            store.all()

    def test_safe_store_add_survives_persistence_error(self, tmp_path):
        path = tmp_path / "pending_assets.json"
        path.write_text("{not valid json")
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        err = vi._safe_store_add(store, vi.make_finding("vulnerability_intelligence", "t", {}, [], vi.CONFIDENCE_LOW))
        assert err is not None

    def test_safe_store_add_none_store_is_noop(self):
        assert vi._safe_store_add(None, {"anything": 1}) is None


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

class TestCompareVersions:
    def test_equal(self):
        assert vi.compare_versions("1.2.3", "1.2.3") == 0

    def test_less_than(self):
        assert vi.compare_versions("1.2.3", "1.10.0") == -1

    def test_greater_than(self):
        assert vi.compare_versions("2.0.0", "1.9.9") == 1

    def test_alpha_suffix(self):
        assert vi.compare_versions("8.9p1", "8.9p1") == 0
        assert vi.compare_versions("8.8", "8.9p1") == -1

    def test_none_or_empty_is_incomparable(self):
        assert vi.compare_versions(None, "1.0") is None
        assert vi.compare_versions("1.0", "") is None


class TestVersionInRange:
    def test_within_bounds(self):
        assert vi._version_in_range("7.0", start_including="6.2", end_excluding="8.8") is True

    def test_outside_bounds(self):
        assert vi._version_in_range("9.0", start_including="6.2", end_excluding="8.8") is False

    def test_no_bounds_is_none(self):
        assert vi._version_in_range("7.0") is None

    def test_exclusive_boundary(self):
        assert vi._version_in_range("8.8", start_including="6.2", end_excluding="8.8") is False
        assert vi._version_in_range("6.2", start_including="6.2", end_excluding="8.8") is True


class TestParseVersionRangeString:
    def test_range_with_two_bounds(self):
        bounds = vi._parse_version_range_string(">= 4.0.0, < 4.18.0")
        assert bounds == {"start_including": "4.0.0", "end_excluding": "4.18.0"}

    def test_empty_string(self):
        assert vi._parse_version_range_string("") == {}


# ---------------------------------------------------------------------------
# normalize_technology_observation
# ---------------------------------------------------------------------------

class TestNormalizeTechnologyObservation:
    def test_basic(self):
        norm = vi.normalize_technology_observation({"technology": "nginx", "version": "1.18.0"})
        assert norm["technology"] == "nginx"
        assert norm["version"] == "1.18.0"
        assert norm["confidence"] == vi.CONFIDENCE_MEDIUM

    def test_alias_keys(self):
        assert vi.normalize_technology_observation({"product": "Apache"})["technology"] == "Apache"
        assert vi.normalize_technology_observation({"software": "OpenSSH"})["technology"] == "OpenSSH"
        assert vi.normalize_technology_observation({"framework": "Django", "product_version": "4.2"})["version"] == "4.2"

    def test_missing_name_returns_none(self):
        assert vi.normalize_technology_observation({"version": "1.0"}) is None

    def test_non_dict_returns_none(self):
        assert vi.normalize_technology_observation("nginx") is None
        assert vi.normalize_technology_observation(None) is None

    def test_versionless_is_safe(self):
        norm = vi.normalize_technology_observation({"technology": "WordPress"})
        assert norm["technology"] == "WordPress"
        assert norm["version"] is None

    def test_invalid_confidence_defaults_to_medium(self):
        norm = vi.normalize_technology_observation({"technology": "nginx", "confidence": "VERY_HIGH"})
        assert norm["confidence"] == vi.CONFIDENCE_MEDIUM

    def test_preserves_evidence_and_target(self):
        norm = vi.normalize_technology_observation({
            "technology": "nginx", "target": "1.2.3.4", "evidence": ["Server header: nginx/1.18.0"],
        })
        assert norm["target"] == "1.2.3.4"
        assert norm["evidence"] == ["Server header: nginx/1.18.0"]


# ---------------------------------------------------------------------------
# parse_name_version_from_text (banner parsing)
# ---------------------------------------------------------------------------

class TestParseNameVersionFromText:
    def test_openssh_underscore_format(self):
        assert vi.parse_name_version_from_text("OpenSSH_8.9p1") == ("OpenSSH", "8.9p1")

    def test_proftpd_banner_with_response_code(self):
        assert vi.parse_name_version_from_text("220 ProFTPD 1.3.5e Server ready.") == ("ProFTPD", "1.3.5e")

    def test_vsftpd_parenthesized_banner(self):
        assert vi.parse_name_version_from_text("220 (vsFTPd 3.0.3)") == ("vsFTPd", "3.0.3")

    def test_full_ssh_identification_banner(self):
        assert vi.parse_name_version_from_text("SSH-2.0-OpenSSH_8.9p1") == ("OpenSSH", "8.9p1")

    def test_generic_protocol_token_rejected(self):
        assert vi.parse_name_version_from_text("HTTP/1.1 200 OK") is None

    def test_no_version_present(self):
        assert vi.parse_name_version_from_text("220 mail.example.com ESMTP Postfix") is None

    def test_empty_or_none(self):
        assert vi.parse_name_version_from_text("") is None
        assert vi.parse_name_version_from_text(None) is None


# ---------------------------------------------------------------------------
# extract_observations_from_active_recon
# ---------------------------------------------------------------------------

class TestExtractObservationsFromActiveRecon:
    def _store_with(self, tmp_path, records):
        path = tmp_path / "pending_assets.json"
        path.write_text(json.dumps(records))
        return vi.PendingAssetsStore(output_dir=str(tmp_path))

    def test_extracts_from_ssh_fingerprint(self, tmp_path):
        store = self._store_with(tmp_path, [{
            "type": "ssh_fingerprint", "target": "10.0.0.1", "confidence": "HIGH",
            "evidence": ["banner: SSH-2.0-OpenSSH_8.9p1"],
            "value": {"software": "OpenSSH_8.9p1", "protocol_version": "2.0"},
        }])
        obs, skipped = vi.extract_observations_from_active_recon(store)
        assert len(obs) == 1
        assert obs[0]["technology"] == "OpenSSH"
        assert obs[0]["version"] == "8.9p1"
        assert obs[0]["target"] == "10.0.0.1"
        assert skipped == []

    def test_extracts_from_banner(self, tmp_path):
        store = self._store_with(tmp_path, [{
            "type": "banner", "target": "10.0.0.2", "confidence": "HIGH", "evidence": [],
            "value": {"ip": "10.0.0.2", "port": 21, "banner": "220 ProFTPD 1.3.5e Server ready."},
        }])
        obs, skipped = vi.extract_observations_from_active_recon(store)
        assert len(obs) == 1
        assert obs[0]["technology"] == "ProFTPD"
        assert obs[0]["version"] == "1.3.5e"

    def test_ignores_unrelated_finding_types(self, tmp_path):
        store = self._store_with(tmp_path, [{
            "type": "open_tcp_port", "target": "10.0.0.3", "confidence": "HIGH", "evidence": [],
            "value": {"ip": "10.0.0.3", "port": 80},
        }])
        obs, skipped = vi.extract_observations_from_active_recon(store)
        assert obs == []
        assert skipped == []

    def test_unparseable_banner_is_skipped_with_note(self, tmp_path):
        store = self._store_with(tmp_path, [{
            "type": "banner", "target": "10.0.0.4", "confidence": "LOW", "evidence": [],
            "value": {"ip": "10.0.0.4", "port": 25, "banner": "220 mail.example.com ESMTP Postfix"},
        }])
        obs, skipped = vi.extract_observations_from_active_recon(store)
        assert obs == []
        assert len(skipped) == 1
        assert "10.0.0.4" in skipped[0]

    def test_service_identification_never_used_as_technology(self, tmp_path):
        store = self._store_with(tmp_path, [{
            "type": "service_identification", "target": "10.0.0.5", "confidence": "LOW", "evidence": [],
            "value": {"ip": "10.0.0.5", "port": 22, "service": "ssh"},
        }])
        obs, skipped = vi.extract_observations_from_active_recon(store)
        assert obs == []

    def test_corrupt_store_reports_error_without_raising(self, tmp_path):
        (tmp_path / "pending_assets.json").write_text("{bad")
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        obs, skipped = vi.extract_observations_from_active_recon(store)
        assert obs == []
        assert len(skipped) == 1


# ---------------------------------------------------------------------------
# query_nvd
# ---------------------------------------------------------------------------

NVD_SAMPLE = {
    "totalResults": 1,
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2021-41617",
            "published": "2021-10-06T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "A privilege escalation vulnerability in OpenSSH."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.0, "vectorString": "AV:L/AC:H"}, "baseSeverity": "HIGH"}]},
            "references": [{"url": "https://example.com/advisory"}],
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "6.2",
                        "versionEndExcluding": "8.8",
                    }],
                }],
            }],
        },
    }],
}


class TestQueryNvd:
    def test_missing_technology(self):
        result = vi.query_nvd("")
        assert result["status"] == "error"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_found_with_range_confirmed(self, mock_get):
        mock_get.return_value = _fake_response(200, NVD_SAMPLE)
        result = vi.query_nvd("OpenSSH", "7.0")
        assert result["status"] == "found"
        assert len(result["vulnerabilities"]) == 1
        vuln = result["vulnerabilities"][0]
        assert vuln["cve_id"] == "CVE-2021-41617"
        assert vuln["version_match"] == "range_confirmed"
        assert vuln["cvss_score"] == 7.0

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_version_outside_range_is_keyword_only(self, mock_get):
        mock_get.return_value = _fake_response(200, NVD_SAMPLE)
        result = vi.query_nvd("OpenSSH", "9.9")
        assert result["vulnerabilities"][0]["version_match"] == "keyword_only"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_no_version_supplied_is_unknown(self, mock_get):
        mock_get.return_value = _fake_response(200, NVD_SAMPLE)
        result = vi.query_nvd("OpenSSH")
        assert result["vulnerabilities"][0]["version_match"] == "unknown"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_empty_results_is_not_found(self, mock_get):
        mock_get.return_value = _fake_response(200, {"totalResults": 0, "vulnerabilities": []})
        result = vi.query_nvd("SomeVeryObscureThing")
        assert result["status"] == "not_found"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_rate_limited(self, mock_get):
        mock_get.return_value = _fake_response(403)
        result = vi.query_nvd("nginx")
        assert result["status"] == "rate_limited"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_server_error(self, mock_get):
        mock_get.return_value = _fake_response(500)
        result = vi.query_nvd("nginx")
        assert result["status"] == "error"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_malformed_json(self, mock_get):
        mock_get.return_value = _fake_response(200, raise_json_error=True)
        result = vi.query_nvd("nginx")
        assert result["status"] == "error"
        assert "malformed" in result["error"]

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_unexpected_structure(self, mock_get):
        mock_get.return_value = _fake_response(200, {"no_vulnerabilities_key": True})
        result = vi.query_nvd("nginx")
        assert result["status"] == "error"

    @mock.patch("reconhound.vuln_intel.requests.get", side_effect=requests.exceptions.Timeout())
    def test_timeout(self, mock_get):
        result = vi.query_nvd("nginx")
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    @mock.patch("reconhound.vuln_intel.requests.get", side_effect=requests.exceptions.ConnectionError("refused"))
    def test_connection_error(self, mock_get):
        result = vi.query_nvd("nginx")
        assert result["status"] == "error"
        assert "connection error" in result["error"]

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_api_key_sent_as_header(self, mock_get):
        mock_get.return_value = _fake_response(200, {"totalResults": 0, "vulnerabilities": []})
        vi.query_nvd("nginx", api_key="secret123")
        _, kwargs = mock_get.call_args
        assert kwargs["headers"]["apiKey"] == "secret123"

    @mock.patch.dict(os.environ, {"NVD_API_KEY": "env-key"})
    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_api_key_from_env(self, mock_get):
        mock_get.return_value = _fake_response(200, {"totalResults": 0, "vulnerabilities": []})
        vi.query_nvd("nginx")
        _, kwargs = mock_get.call_args
        assert kwargs["headers"]["apiKey"] == "env-key"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_malformed_single_entry_does_not_abort_others(self, mock_get):
        broken = {"totalResults": 2, "vulnerabilities": [{"cve": {}}, NVD_SAMPLE["vulnerabilities"][0]]}
        mock_get.return_value = _fake_response(200, broken)
        result = vi.query_nvd("OpenSSH", "7.0")
        assert result["status"] == "found"
        assert len(result["vulnerabilities"]) == 1


# ---------------------------------------------------------------------------
# query_osv
# ---------------------------------------------------------------------------

OSV_SAMPLE = {
    "vulns": [{
        "id": "GHSA-29mw-wpgm-hmr9",
        "aliases": ["CVE-2020-28500"],
        "summary": "Prototype Pollution in lodash",
        "published": "2021-02-15T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],
        "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-28500"}],
        "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}}],
    }],
}


class TestQueryOsv:
    def test_missing_technology(self):
        result = vi.query_osv("")
        assert result["status"] == "error"

    def test_unknown_ecosystem_is_skipped(self):
        result = vi.query_osv("some-totally-unknown-thing")
        assert result["status"] == "skipped"
        assert "ecosystem" in result["error"]

    @mock.patch("reconhound.vuln_intel.requests.post")
    def test_found_with_explicit_ecosystem(self, mock_post):
        mock_post.return_value = _fake_response(200, OSV_SAMPLE)
        result = vi.query_osv("lodash", version="4.17.15", ecosystem="npm")
        assert result["status"] == "found"
        assert result["vulnerabilities"][0]["cve_id"] == "CVE-2020-28500"
        assert result["vulnerabilities"][0]["version_match"] == "range_confirmed"

    @mock.patch("reconhound.vuln_intel.requests.post")
    def test_inferred_ecosystem_from_hint_table(self, mock_post):
        mock_post.return_value = _fake_response(200, OSV_SAMPLE)
        result = vi.query_osv("lodash", version="4.17.15")
        assert result["status"] == "found"
        body = mock_post.call_args.kwargs["json"]
        assert body["package"]["ecosystem"] == "npm"

    @mock.patch("reconhound.vuln_intel.requests.post")
    def test_no_version_is_unknown_match(self, mock_post):
        mock_post.return_value = _fake_response(200, OSV_SAMPLE)
        result = vi.query_osv("lodash", ecosystem="npm")
        assert result["vulnerabilities"][0]["version_match"] == "unknown"

    @mock.patch("reconhound.vuln_intel.requests.post")
    def test_non_cve_advisory_is_skipped_not_dropped_silently(self, mock_post):
        sample = {"vulns": [{"id": "OSV-2024-1", "aliases": [], "summary": "no cve here"}]}
        mock_post.return_value = _fake_response(200, sample)
        result = vi.query_osv("lodash", ecosystem="npm")
        assert result["status"] == "not_found"
        assert result["skipped_non_cve_advisories"] == 1

    @mock.patch("reconhound.vuln_intel.requests.post")
    def test_empty_vulns_not_found(self, mock_post):
        mock_post.return_value = _fake_response(200, {"vulns": []})
        result = vi.query_osv("lodash", ecosystem="npm")
        assert result["status"] == "not_found"

    @mock.patch("reconhound.vuln_intel.requests.post")
    def test_rate_limited(self, mock_post):
        mock_post.return_value = _fake_response(429)
        result = vi.query_osv("lodash", ecosystem="npm")
        assert result["status"] == "rate_limited"

    @mock.patch("reconhound.vuln_intel.requests.post")
    def test_malformed_json(self, mock_post):
        mock_post.return_value = _fake_response(200, raise_json_error=True)
        result = vi.query_osv("lodash", ecosystem="npm")
        assert result["status"] == "error"

    @mock.patch("reconhound.vuln_intel.requests.post", side_effect=requests.exceptions.Timeout())
    def test_timeout(self, mock_post):
        result = vi.query_osv("lodash", ecosystem="npm")
        assert result["status"] == "error"
        assert result["error"] == "timeout"


# ---------------------------------------------------------------------------
# query_github_advisories
# ---------------------------------------------------------------------------

GH_SAMPLE = [{
    "ghsa_id": "GHSA-r5fr-rjxr-66jc",
    "cve_id": "CVE-2026-4800",
    "html_url": "https://github.com/advisories/GHSA-r5fr-rjxr-66jc",
    "summary": "lodash vulnerable to Code Injection",
    "severity": "high",
    "cvss": {"vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 8.1},
    "published_at": "2026-04-01T23:51:12Z",
    "references": ["https://github.com/lodash/lodash/security/advisories/GHSA-r5fr-rjxr-66jc"],
    "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "lodash"},
                          "vulnerable_version_range": ">= 4.0.0, <= 4.17.23"}],
}]


class TestQueryGithubAdvisories:
    def test_missing_technology(self):
        result = vi.query_github_advisories("")
        assert result["status"] == "error"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, GH_SAMPLE)
        result = vi.query_github_advisories("lodash")
        assert result["status"] == "found"
        assert result["vulnerabilities"][0]["cve_id"] == "CVE-2026-4800"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_version_range_confirmed(self, mock_get):
        mock_get.return_value = _fake_response(200, GH_SAMPLE)
        result = vi.query_github_advisories("lodash", version="4.17.15")
        assert result["vulnerabilities"][0]["version_match"] == "range_confirmed"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_version_outside_range_is_keyword_only(self, mock_get):
        mock_get.return_value = _fake_response(200, GH_SAMPLE)
        result = vi.query_github_advisories("lodash", version="5.0.0")
        assert result["vulnerabilities"][0]["version_match"] == "keyword_only"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_advisory_without_cve_is_skipped(self, mock_get):
        sample = [dict(GH_SAMPLE[0], cve_id=None)]
        mock_get.return_value = _fake_response(200, sample)
        result = vi.query_github_advisories("lodash")
        assert result["status"] == "not_found"
        assert result["skipped_no_cve_advisories"] == 1

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_rate_limited(self, mock_get):
        mock_get.return_value = _fake_response(403, headers={"X-RateLimit-Remaining": "0"})
        result = vi.query_github_advisories("lodash")
        assert result["status"] == "rate_limited"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_forbidden_without_rate_limit_header_is_error(self, mock_get):
        mock_get.return_value = _fake_response(403, headers={})
        result = vi.query_github_advisories("lodash")
        assert result["status"] == "error"

    @mock.patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_env_token"})
    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_token_from_env_used_in_header(self, mock_get):
        mock_get.return_value = _fake_response(200, [])
        vi.query_github_advisories("lodash")
        _, kwargs = mock_get.call_args
        assert kwargs["headers"]["Authorization"] == "Bearer ghp_env_token"


# ---------------------------------------------------------------------------
# query_cisa_kev
# ---------------------------------------------------------------------------

KEV_SAMPLE = {
    "title": "KEV", "catalogVersion": "1", "dateReleased": "2026-08-26", "count": 1,
    "vulnerabilities": [{
        "cveID": "CVE-2021-41617", "vendorProject": "OpenBSD", "product": "OpenSSH",
        "vulnerabilityName": "OpenSSH Privilege Escalation", "dateAdded": "2022-01-01",
        "knownRansomwareCampaignUse": "Unknown",
    }],
}


class TestQueryCisaKev:
    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, KEV_SAMPLE)
        result = vi.query_cisa_kev()
        assert result["status"] == "found"
        assert result["entries"][0]["cve_id"] == "CVE-2021-41617"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_empty_catalog(self, mock_get):
        mock_get.return_value = _fake_response(200, {"vulnerabilities": []})
        result = vi.query_cisa_kev()
        assert result["status"] == "not_found"

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_server_error(self, mock_get):
        mock_get.return_value = _fake_response(500)
        result = vi.query_cisa_kev()
        assert result["status"] == "error"

    @mock.patch("reconhound.vuln_intel.requests.get", side_effect=requests.exceptions.ConnectionError("x"))
    def test_connection_error(self, mock_get):
        result = vi.query_cisa_kev()
        assert result["status"] == "error"

    def test_kev_lookup_hit_and_miss(self):
        entries = KEV_SAMPLE["vulnerabilities"]
        entries = [{"cve_id": "CVE-2021-41617"}]
        assert vi._kev_lookup(entries, "CVE-2021-41617") is not None
        assert vi._kev_lookup(entries, "CVE-9999-0000") is None


# ---------------------------------------------------------------------------
# fetch_exploitdb_index
# ---------------------------------------------------------------------------

EXPLOITDB_CSV = (
    "id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases\n"
    '16929,exploits/aix/dos/16929.rb,"AIX Buffer Overflow",2010-11-11,Metasploit,dos,aix,,2010-11-11,2011-03-06,1,CVE-2009-3699;OSVDB-58726,,\n'
    '99999,exploits/x/dos/99999.txt,"No CVE here",2020-01-01,Someone,dos,linux,,2020-01-01,,0,OSVDB-1234,,\n'
)


class TestFetchExploitdbIndex:
    def test_preloaded_csv_text(self):
        result = vi.fetch_exploitdb_index(preloaded_csv_text=EXPLOITDB_CSV)
        assert result["status"] == "found"
        assert "CVE-2009-3699" in result["index"]
        assert result["index"]["CVE-2009-3699"][0]["edb_id"] == "16929"
        assert result["index"]["CVE-2009-3699"][0]["verified"] is True

    def test_rows_without_cve_are_excluded(self):
        result = vi.fetch_exploitdb_index(preloaded_csv_text=EXPLOITDB_CSV)
        assert "CVE-9999-9999" not in result["index"]
        assert len(result["index"]) == 1

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_network_fetch(self, mock_get):
        mock_get.return_value = _fake_response(200, text=EXPLOITDB_CSV)
        result = vi.fetch_exploitdb_index()
        assert result["status"] == "found"
        assert "CVE-2009-3699" in result["index"]

    @mock.patch("reconhound.vuln_intel.requests.get")
    def test_http_error(self, mock_get):
        mock_get.return_value = _fake_response(404, text="")
        result = vi.fetch_exploitdb_index()
        assert result["status"] == "error"

    @mock.patch("reconhound.vuln_intel.requests.get", side_effect=requests.exceptions.Timeout())
    def test_timeout(self, mock_get):
        result = vi.fetch_exploitdb_index()
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_malformed_csv_handled(self):
        # A non-CSV blob should just yield no matches, not raise.
        result = vi.fetch_exploitdb_index(preloaded_csv_text="not,a,valid\ncsv\nfile")
        assert result["status"] in ("not_found", "error")


# ---------------------------------------------------------------------------
# query_all_sources
# ---------------------------------------------------------------------------

class TestQueryAllSources:
    def test_invalid_source_raises_configuration_error(self):
        with pytest.raises(vi.ConfigurationError):
            vi.query_all_sources("nginx", sources=["not_a_real_source"])

    @mock.patch("reconhound.vuln_intel.query_github_advisories")
    @mock.patch("reconhound.vuln_intel.query_osv")
    @mock.patch("reconhound.vuln_intel.query_nvd")
    def test_one_source_failing_does_not_block_others(self, mock_nvd, mock_osv, mock_gh):
        mock_nvd.side_effect = Exception("boom")
        mock_osv.return_value = {"status": "found", "vulnerabilities": [{"cve_id": "CVE-2020-1", "source": "osv", "version_match": "unknown", "references": []}]}
        mock_gh.return_value = {"status": "not_found", "vulnerabilities": []}

        result = vi.query_all_sources("lodash", "4.17.15")
        assert result["source_status"]["nvd"]["status"] == "error"
        assert result["source_status"]["osv"]["status"] == "found"
        assert len(result["records"]) == 1

    @mock.patch("reconhound.vuln_intel.query_github_advisories")
    @mock.patch("reconhound.vuln_intel.query_osv")
    @mock.patch("reconhound.vuln_intel.query_nvd")
    def test_sources_param_restricts_queries(self, mock_nvd, mock_osv, mock_gh):
        mock_nvd.return_value = {"status": "not_found", "vulnerabilities": []}
        vi.query_all_sources("nginx", sources=["nvd"])
        mock_nvd.assert_called_once()
        mock_osv.assert_not_called()
        mock_gh.assert_not_called()


# ---------------------------------------------------------------------------
# _merge_vulnerability_records / _assess_applicability / statements
# ---------------------------------------------------------------------------

class TestMergeAndAssess:
    def test_merge_deduplicates_by_cve_and_preserves_all_sources(self):
        records = [
            {"cve_id": "CVE-2021-1", "source": "nvd", "version_match": "range_confirmed",
             "summary": "s1", "cvss_score": 9.0, "cvss_vector": "v1", "severity": "CRITICAL",
             "references": ["https://a"], "published": "2021-01-01", "raw_evidence": "nvd hit"},
            {"cve_id": "CVE-2021-1", "source": "osv", "version_match": "unknown",
             "summary": "s1", "cvss_score": None, "cvss_vector": None, "severity": None,
             "references": ["https://b"], "published": "2021-01-01", "raw_evidence": "osv hit"},
        ]
        merged = vi._merge_vulnerability_records(records)
        assert len(merged) == 1
        rec = merged[0]
        assert rec["cve_id"] == "CVE-2021-1"
        assert len(rec["sources"]) == 2
        assert set(rec["references"]) == {"https://a", "https://b"}
        assert len(rec["cvss"]) == 1  # only the nvd record carried cvss data

    def test_range_confirmed_yields_high_confidence(self):
        rec = {"sources": [{"source": "nvd", "version_match": "range_confirmed"}]}
        applicability, confidence = vi._assess_applicability(rec)
        assert applicability == "version_range_confirmed"
        assert confidence == vi.CONFIDENCE_HIGH

    def test_unknown_everywhere_yields_low_confidence(self):
        rec = {"sources": [{"source": "nvd", "version_match": "unknown"}]}
        applicability, confidence = vi._assess_applicability(rec)
        assert applicability == "version_unknown_cannot_confirm"
        assert confidence == vi.CONFIDENCE_LOW

    def test_keyword_only_single_source_is_low(self):
        rec = {"sources": [{"source": "nvd", "version_match": "keyword_only"}]}
        applicability, confidence = vi._assess_applicability(rec)
        assert applicability == "keyword_match_version_unconfirmed"
        assert confidence == vi.CONFIDENCE_LOW

    def test_keyword_only_converging_sources_raises_to_medium(self):
        rec = {"sources": [
            {"source": "nvd", "version_match": "keyword_only"},
            {"source": "osv", "version_match": "keyword_only"},
        ]}
        applicability, confidence = vi._assess_applicability(rec)
        assert applicability == "keyword_match_version_unconfirmed"
        assert confidence == vi.CONFIDENCE_MEDIUM


class TestCapConfidence:
    def test_caps_to_lower(self):
        assert vi._cap_confidence(vi.CONFIDENCE_LOW, vi.CONFIDENCE_HIGH) == vi.CONFIDENCE_LOW
        assert vi._cap_confidence(vi.CONFIDENCE_HIGH, vi.CONFIDENCE_HIGH) == vi.CONFIDENCE_HIGH

    def test_invalid_defaults_to_medium(self):
        assert vi._cap_confidence("nonsense", vi.CONFIDENCE_HIGH) == vi.CONFIDENCE_MEDIUM


class TestFormatVulnIntelStatement:
    def test_never_claims_confirmed_exploitable(self):
        for applicability in ("version_range_confirmed", "keyword_match_version_unconfirmed", "version_unknown_cannot_confirm"):
            statement = vi.format_vuln_intel_statement("Nginx", "1.18.0", "CVE-XXXX-YYYY", applicability)
            assert "confirmed exploitable" not in statement.lower()
            assert "Nginx" in statement and "CVE-XXXX-YYYY" in statement

    def test_matches_context_md_example_style(self):
        statement = vi.format_vuln_intel_statement("Nginx", "1.18.0", "CVE-XXXX-YYYY", "version_range_confirmed")
        assert statement.startswith("Detected Nginx 1.18.0 — MAY be affected by CVE-XXXX-YYYY")

    def test_versionless_statement(self):
        statement = vi.format_vuln_intel_statement("WordPress", None, "CVE-XXXX-YYYY", "version_unknown_cannot_confirm")
        assert "version unknown" in statement


# ---------------------------------------------------------------------------
# annotate_kev / annotate_exploitdb
# ---------------------------------------------------------------------------

class TestAnnotate:
    def test_kev_hit(self):
        rec = {"cve_id": "CVE-2021-41617", "cisa_kev": None}
        kev_entries = [{"cve_id": "CVE-2021-41617", "date_added": "2022-01-01",
                         "vulnerability_name": "x", "known_ransomware_campaign_use": "Unknown"}]
        vi.annotate_kev(rec, kev_entries)
        assert rec["cisa_kev"]["listed"] is True
        assert "does NOT confirm exploitability" in rec["cisa_kev"]["note"]

    def test_kev_miss(self):
        rec = {"cve_id": "CVE-2021-99999", "cisa_kev": None}
        vi.annotate_kev(rec, [])
        assert rec["cisa_kev"] is None

    def test_exploitdb_hit(self):
        rec = {"cve_id": "CVE-2009-3699", "exploitdb_references": []}
        index = {"CVE-2009-3699": [{"edb_id": "16929", "title": "x", "verified": True, "date_published": "2010-11-11"}]}
        vi.annotate_exploitdb(rec, index)
        assert len(rec["exploitdb_references"]) == 1
        assert rec["exploitdb_references"][0]["edb_id"] == "16929"

    def test_exploitdb_miss(self):
        rec = {"cve_id": "CVE-0000-0000", "exploitdb_references": []}
        vi.annotate_exploitdb(rec, {})
        assert rec["exploitdb_references"] == []


# ---------------------------------------------------------------------------
# map_technology_to_cves (integration of the above, mocked sources)
# ---------------------------------------------------------------------------

class TestMapTechnologyToCves:
    def test_insufficient_data_no_technology(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        result = vi.map_technology_to_cves({"version": "1.0"}, store=store)
        assert result["status"] == "insufficient_data"
        assert store.all() == []

    def test_found_persists_finding(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        source_results = {
            "records": [{"cve_id": "CVE-2021-41617", "source": "nvd", "version_match": "range_confirmed",
                         "summary": "desc", "cvss_score": 7.0, "cvss_vector": "v", "severity": "HIGH",
                         "references": ["https://x"], "published": "2021-01-01", "raw_evidence": "hit"}],
            "source_status": {"nvd": {"status": "found", "error": None}},
        }
        result = vi.map_technology_to_cves(
            {"technology": "OpenSSH", "version": "7.0", "target": "10.0.0.1", "confidence": "HIGH"},
            store=store, source_results=source_results, kev_entries=[], exploitdb_index={},
        )
        assert result["status"] == "found"
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["applicability"] == "version_range_confirmed"
        assert "confirmed exploitable" not in result["vulnerabilities"][0]["statement"].lower()

        records = store.all()
        assert len(records) == 1
        assert records[0]["type"] == "vulnerability_intelligence"
        assert records[0]["value"]["cve_id"] == "CVE-2021-41617"
        assert records[0]["target"] == "10.0.0.1"

    def test_confidence_capped_by_observation_confidence(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        source_results = {
            "records": [{"cve_id": "CVE-2021-41617", "source": "nvd", "version_match": "range_confirmed",
                         "summary": None, "cvss_score": None, "cvss_vector": None, "severity": None,
                         "references": [], "published": None, "raw_evidence": "hit"}],
            "source_status": {"nvd": {"status": "found", "error": None}},
        }
        result = vi.map_technology_to_cves(
            {"technology": "OpenSSH", "version": "7.0", "confidence": "LOW"},
            store=store, source_results=source_results, kev_entries=[], exploitdb_index={},
        )
        # Even though the match itself is HIGH-confidence (range confirmed),
        # a LOW-confidence underlying detection caps the final confidence.
        assert result["vulnerabilities"][0]["confidence"] == vi.CONFIDENCE_LOW

    def test_not_found_persists_negative_result(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        source_results = {"records": [], "source_status": {"nvd": {"status": "not_found", "error": None}}}
        result = vi.map_technology_to_cves(
            {"technology": "SomeVeryObscureThing", "version": "1.0", "target": "10.0.0.1"},
            store=store, source_results=source_results, kev_entries=[], exploitdb_index={},
        )
        assert result["status"] == "not_found"
        records = store.all()
        assert len(records) == 1
        assert records[0]["type"] == "vuln_intel_checked_no_match"

    def test_all_sources_unavailable_does_not_persist_false_negative(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        source_results = {"records": [], "source_status": {
            "nvd": {"status": "error", "error": "timeout"},
            "osv": {"status": "rate_limited", "error": "429"},
        }}
        result = vi.map_technology_to_cves(
            {"technology": "nginx", "version": "1.18.0"},
            store=store, source_results=source_results, kev_entries=[], exploitdb_index={},
        )
        assert result["status"] == "sources_unavailable"
        assert store.all() == []  # must NOT record a false "checked, not found"

    def test_kev_and_exploitdb_annotations_flow_into_evidence(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        source_results = {
            "records": [{"cve_id": "CVE-2021-41617", "source": "nvd", "version_match": "range_confirmed",
                         "summary": None, "cvss_score": None, "cvss_vector": None, "severity": None,
                         "references": [], "published": None, "raw_evidence": "hit"}],
            "source_status": {"nvd": {"status": "found", "error": None}},
        }
        kev_entries = [{"cve_id": "CVE-2021-41617", "date_added": "2022-01-01",
                         "vulnerability_name": "x", "known_ransomware_campaign_use": "Unknown"}]
        exploitdb_index = {"CVE-2021-41617": [{"edb_id": "1", "title": "t", "verified": True, "date_published": "d"}]}
        result = vi.map_technology_to_cves(
            {"technology": "OpenSSH", "version": "7.0", "target": "10.0.0.1"},
            store=store, source_results=source_results, kev_entries=kev_entries, exploitdb_index=exploitdb_index,
        )
        vuln = result["vulnerabilities"][0]
        assert vuln["cisa_kev"]["listed"] is True
        assert len(vuln["exploitdb_references"]) == 1
        finding = store.all()[0]
        assert any("KEV" in e for e in finding["evidence"])
        assert any("Exploit-DB" in e for e in finding["evidence"])


# ---------------------------------------------------------------------------
# run_vuln_intel (full orchestration)
# ---------------------------------------------------------------------------

class TestRunVulnIntel:
    def test_no_observations_returns_empty_summary(self, tmp_path):
        summary = vi.run_vuln_intel(output_dir=str(tmp_path), include_active_recon=False, technology_observations=[])
        assert summary["stats"]["observations"] == 0
        assert summary["results"] == []

    def test_skips_unusable_caller_supplied_observations(self, tmp_path):
        summary = vi.run_vuln_intel(
            output_dir=str(tmp_path), include_active_recon=False,
            technology_observations=[{"version": "1.0"}],  # no technology name
        )
        assert len(summary["skipped_observations"]) == 1
        assert summary["stats"]["observations"] == 0

    @mock.patch("reconhound.vuln_intel.query_epss")
    @mock.patch("reconhound.vuln_intel.fetch_exploitdb_index")
    @mock.patch("reconhound.vuln_intel.query_cisa_kev")
    @mock.patch("reconhound.vuln_intel.query_all_sources")
    def test_end_to_end_with_caller_supplied_observation(self, mock_query_all, mock_kev, mock_exploitdb, mock_epss, tmp_path):
        mock_epss.return_value = {"status": "not_found", "outcome": "empty_authoritative", "scores": {}, "error": None}
        mock_query_all.return_value = {
            "records": [{"cve_id": "CVE-2021-41617", "source": "nvd", "version_match": "range_confirmed",
                         "summary": "d", "cvss_score": 7.0, "cvss_vector": "v", "severity": "HIGH",
                         "references": [], "published": None, "raw_evidence": "hit"}],
            "source_status": {"nvd": {"status": "found", "error": None}},
        }
        mock_kev.return_value = {"status": "not_found", "entries": [], "error": None}
        mock_exploitdb.return_value = {"status": "not_found", "index": {}, "error": None}

        summary = vi.run_vuln_intel(
            output_dir=str(tmp_path), include_active_recon=False,
            technology_observations=[{"technology": "OpenSSH", "version": "7.0", "target": "10.0.0.1"}],
        )
        assert summary["stats"]["observations"] == 1
        assert summary["stats"]["vulnerabilities_found"] == 1

        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        records = store.all()
        assert any(r["type"] == "vulnerability_intelligence" for r in records)

    @mock.patch("reconhound.vuln_intel.fetch_exploitdb_index")
    @mock.patch("reconhound.vuln_intel.query_cisa_kev")
    @mock.patch("reconhound.vuln_intel.query_all_sources")
    def test_dedupes_identical_technology_version_across_observations(self, mock_query_all, mock_kev, mock_exploitdb, tmp_path):
        mock_query_all.return_value = {"records": [], "source_status": {"nvd": {"status": "not_found", "error": None}}}
        mock_kev.return_value = {"status": "not_found", "entries": [], "error": None}
        mock_exploitdb.return_value = {"status": "not_found", "index": {}, "error": None}

        summary = vi.run_vuln_intel(
            output_dir=str(tmp_path), include_active_recon=False,
            technology_observations=[
                {"technology": "nginx", "version": "1.18.0", "target": "host-a"},
                {"technology": "nginx", "version": "1.18.0", "target": "host-b"},
            ],
        )
        assert summary["stats"]["observations"] == 2
        assert summary["stats"]["unique_technology_version_pairs"] == 1
        assert mock_query_all.call_count == 1  # queried once, reused for both targets

    def test_integrates_active_recon_extraction(self, tmp_path):
        (tmp_path / "pending_assets.json").write_text(json.dumps([{
            "type": "ssh_fingerprint", "target": "10.0.0.9", "confidence": "HIGH", "evidence": [],
            "value": {"software": "OpenSSH_8.9p1"},
        }]))
        with mock.patch("reconhound.vuln_intel.query_all_sources") as mock_query_all, \
             mock.patch("reconhound.vuln_intel.query_cisa_kev") as mock_kev, \
             mock.patch("reconhound.vuln_intel.fetch_exploitdb_index") as mock_exploitdb:
            mock_query_all.return_value = {"records": [], "source_status": {"nvd": {"status": "not_found", "error": None}}}
            mock_kev.return_value = {"status": "not_found", "entries": [], "error": None}
            mock_exploitdb.return_value = {"status": "not_found", "index": {}, "error": None}
            summary = vi.run_vuln_intel(output_dir=str(tmp_path), include_active_recon=True, technology_observations=[])
        assert summary["stats"]["observations"] == 1
        mock_query_all.assert_called_once()
        call_args = mock_query_all.call_args[0]
        assert call_args[0] == "OpenSSH"


# ===========================================================================
# Hardening regression suite
#
# Every test below reproduces a defect that was confirmed against the
# implementation (either the original one or a fix made during the hardening
# pass), or pins a semantic guarantee the module must never lose.
# ===========================================================================

import time as _time


class _RawResp:
    """A response exposing a real byte stream, so the bounded-read path (not the .json() fallback) is exercised."""

    def __init__(self, body: bytes, status=200, headers=None):
        self._b = body
        self.status_code = status
        self.headers = dict(headers or {})
        self.encoding = "utf-8"

    class _R:
        def __init__(self, b):
            self.b = b

        def read(self, n, decode_content=True):
            return self.b[:n]

    @property
    def raw(self):
        return _RawResp._R(self._b)

    def json(self):
        return json.loads(self._b)

    @property
    def text(self):
        return self._b.decode("utf-8", "replace")

    def close(self):
        pass


def _rec(cve, source="nvd", vm="keyword_only", q=None, **extra):
    r = vi._blank_record(cve, source)
    r.update({"version_match": vm, "raw_evidence": f"{source} hit"})
    if q:
        r["match_quality"] = q
    r.update(extra)
    return r


def _status(**kw):
    return {name: {"status": s, "outcome": o, "conclusive": o in vi._CONCLUSIVE_OUTCOMES, "error": None}
            for name, (s, o) in kw.items()}


FOUND = ("found", vi.OUTCOME_FOUND)
EMPTY = ("not_found", vi.OUTCOME_EMPTY_AUTHORITATIVE)
RATE = ("rate_limited", vi.OUTCOME_RATE_LIMITED)
DOWN = ("error", vi.OUTCOME_UNAVAILABLE)
SKIP = ("skipped", vi.OUTCOME_SKIPPED)


# ---------------------------------------------------------------------------
# B. CPE naming and matching
# ---------------------------------------------------------------------------

def _cpe_cve(criteria, **bounds):
    m = {"vulnerable": True, "criteria": criteria}
    m.update(bounds)
    return {"configurations": [{"nodes": [{"cpeMatch": [m]}]}]}


class TestCpeProductMatching:
    def test_related_product_name_never_range_confirms(self):
        # Reproduced against the original: nginx 1.18.0 range-confirmed
        # against an NGINX *Controller* CVE because "nginx" is a substring.
        cve = _cpe_cve("cpe:2.3:a:f5:nginx_controller:*:*:*:*:*:*:*:*",
                       versionStartIncluding="1.0.0", versionEndExcluding="9.9.9")
        assert vi._nvd_cve_version_match(cve, "nginx", "1.18.0") == "keyword_only"
        detail = vi._nvd_cpe_assessment(cve, "nginx", "1.18.0")
        assert detail["match_quality"] == vi.MATCH_QUALITY_RELATED
        assert "nginx_controller" in detail["products"]

    def test_short_generic_token_does_not_match_by_substring(self):
        cve = _cpe_cve("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", versionEndExcluding="9.9")
        assert vi._nvd_cve_version_match(cve, "ssh", "1.0") == "keyword_only"
        assert vi._product_match_quality("ssh", "openssh") is None

    def test_exact_product_still_range_confirms(self):
        cve = _cpe_cve("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", versionEndExcluding="9.9")
        assert vi._nvd_cve_version_match(cve, "OpenSSH", "7.0") == "range_confirmed"
        assert vi._nvd_cpe_assessment(cve, "OpenSSH", "7.0")["match_quality"] == vi.MATCH_QUALITY_EXACT

    def test_curated_alias_is_explicit_and_recorded(self):
        cve = _cpe_cve("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", versionEndExcluding="2.4.50")
        detail = vi._nvd_cpe_assessment(cve, "Apache", "2.4.49")
        assert detail["version_match"] == "range_confirmed"
        assert detail["match_quality"] == vi.MATCH_QUALITY_ALIAS
        # an alias can never suppress: an unrelated product is simply not matched
        assert vi._product_match_quality("Apache", "tomcat") is None

    def test_hyphen_underscore_and_case_folding(self):
        assert vi._product_match_quality("Next.js", "next.js") == vi.MATCH_QUALITY_EXACT
        assert vi._product_match_quality("ruby-on-rails", "ruby_on_rails") == vi.MATCH_QUALITY_EXACT

    def test_version_na_is_not_a_wildcard(self):
        cve = _cpe_cve("cpe:2.3:a:openbsd:openssh:-:*:*:*:*:*:*:*")
        assert vi._nvd_cve_version_match(cve, "OpenSSH", "7.0") == "keyword_only"
        assert vi._cpe_version_field("cpe:2.3:a:openbsd:openssh:-:*:*:*:*:*:*:*") == (None, True)
        assert vi._cpe_version_field("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*") == (None, False)

    def test_wildcard_version_without_bounds_does_not_confirm(self):
        cve = _cpe_cve("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")
        assert vi._nvd_cve_version_match(cve, "OpenSSH", "7.0") == "keyword_only"

    def test_non_vulnerable_and_negated_nodes_are_not_assertions(self):
        cve = {"configurations": [{"nodes": [
            {"cpeMatch": [{"vulnerable": False, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                           "versionEndExcluding": "9.9"}]},
            {"negate": True, "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                           "versionEndExcluding": "9.9"}]},
        ]}]}
        assert vi._nvd_cve_version_match(cve, "OpenSSH", "7.0") == "keyword_only"

    def test_malformed_cpe_strings_are_ignored_not_fatal(self):
        cve = {"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": 5}, {"vulnerable": True, "criteria": "cpe:2.3:a:x"},
            {"vulnerable": True, "criteria": ""}, {"vulnerable": "yes", "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionEndExcluding": "9.9"},
        ]}]}]}
        assert vi._nvd_cve_version_match(cve, "OpenSSH", "7.0") == "range_confirmed"

    def test_cpe_match_count_is_bounded(self):
        many = [{"vulnerable": True, "criteria": f"cpe:2.3:a:v:other{i}:*:*:*:*:*:*:*:*"} for i in range(5000)]
        many.append({"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionEndExcluding": "9.9"})
        cve = {"configurations": [{"nodes": [{"cpeMatch": many}]}]}
        detail = vi._nvd_cpe_assessment(cve, "OpenSSH", "7.0")
        assert detail["version_match"] == "keyword_only"  # the confirming entry lies past the cap
        assert any("truncated" in n for n in detail["notes"])

    def test_incomparable_bound_never_manufactures_a_match(self):
        cve = _cpe_cve("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", versionEndExcluding="???")
        assert vi._nvd_cve_version_match(cve, "OpenSSH", "7.0") == "keyword_only"


# ---------------------------------------------------------------------------
# D. Version matching
# ---------------------------------------------------------------------------

class TestVersionHardening:
    def test_backport_markers_detected(self):
        for v in ("2.4.6-2ubuntu1", "1.18.0-6.1+deb11u3", "2.4.29-1ubuntu4.14", "7.4p1-10+deb10u2",
                  "2.4.6-45.el7", "2.4.6-97.el7_9", "1.1.1k-r0", "1:2.4.6", "1.2.3~rc1", "1.20.1-1.amzn2", "3.1.2+dfsg-1"):
            assert vi._looks_backported(v), v

    def test_plain_upstream_versions_not_flagged(self):
        for v in ("1.18.0", "8.9p1", "4.17.15", "1.0.0-beta", "2.4.49", "1.2.3-rc1", "10.0.19041", "1.3.5e", None, "", 7):
            assert not vi._looks_backported(v), v

    def test_backported_range_match_is_capped_and_annotated(self):
        rec = {"sources": [{"source": "nvd", "version_match": "range_confirmed", "match_quality": vi.MATCH_QUALITY_EXACT}]}
        applicability, conf = vi._assess_applicability(rec, "1.18.0-6.1+deb11u3")
        assert applicability == "version_range_confirmed"   # the enum risk_engine understands is unchanged
        assert conf == vi.CONFIDENCE_MEDIUM                  # ...but never HIGH for a distro build
        detail = vi._mapping_assessment(rec, "1.18.0-6.1+deb11u3")
        assert detail["backport_uncertainty"] is True
        assert any("backport" in n for n in detail["notes"])
        statement = vi.format_vuln_intel_statement("nginx", "1.18.0-6.1+deb11u3", "CVE-2021-23017",
                                                   applicability, backport_uncertainty=True)
        assert "MAY be affected" in statement and "patch status was not determined" in statement

    def test_plain_upstream_range_match_stays_high(self):
        rec = {"sources": [{"source": "nvd", "version_match": "range_confirmed", "match_quality": vi.MATCH_QUALITY_EXACT}]}
        assert vi._assess_applicability(rec, "1.18.0") == ("version_range_confirmed", vi.CONFIDENCE_HIGH)

    def test_pathological_versions_are_bounded_in_time(self):
        started = _time.time()
        big = "1." * 200000
        for other in ("1.0", "9" * 300, big):
            vi.compare_versions(big, other)
            vi._version_in_range(big, start_including=other, end_excluding=other)
        assert _time.time() - started < 1.0
        assert len(vi._version_key("1." * 10000)) == vi.MAX_VERSION_TOKENS

    def test_unicode_digits_are_not_numeric(self):
        assert vi.compare_versions("١٢٣", "1") is None

    def test_non_string_versions_are_incomparable(self):
        assert vi.compare_versions(1, "1") is None
        assert vi._version_in_range("1.0", start_including=5) is None

    def test_range_string_parse_is_bounded(self):
        started = _time.time()
        vi._parse_version_range_string(">=" * 100000)
        vi._parse_version_range_string(">= " + "a" * 100000)
        assert _time.time() - started < 0.5
        assert vi._parse_version_range_string(None) == {}

    def test_inclusive_exclusive_boundaries(self):
        assert vi._version_in_range("1.0", start_including="1.0") is True
        assert vi._version_in_range("1.0", start_excluding="1.0") is False
        assert vi._version_in_range("2.0", end_including="2.0") is True
        assert vi._version_in_range("2.0", end_excluding="2.0") is False
        assert vi._version_in_range("1.5", start_including="1.0", end_excluding="2.0") is True
        assert vi._version_in_range("1.5", start_including="1.0", end_excluding="1.5") is False


# ---------------------------------------------------------------------------
# E. Confidence propagation
# ---------------------------------------------------------------------------

class TestConfidenceModel:
    def _map(self, tmp_path, obs_conf, records, **kw):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        return vi.map_technology_to_cves(
            {"technology": "OpenSSH", "version": "7.0", "target": "10.0.0.1", "confidence": obs_conf},
            store=store, source_results={"records": records, "source_status": _status(nvd=FOUND)},
            kev_entries=[], exploitdb_index={}, **kw), store

    def test_low_technology_confidence_caps_exact_high_match(self, tmp_path):
        result, store = self._map(tmp_path, "LOW", [_rec("CVE-2021-41617", vm="range_confirmed", q=vi.MATCH_QUALITY_EXACT)])
        vuln = result["vulnerabilities"][0]
        assert vuln["applicability"] == "version_range_confirmed"
        assert vuln["confidence_model"]["mapping_confidence"] == vi.CONFIDENCE_HIGH
        assert vuln["confidence"] == vi.CONFIDENCE_LOW
        assert store.all()[0]["confidence"] == vi.CONFIDENCE_LOW

    def test_confidence_dimensions_are_all_recorded(self, tmp_path):
        result, _ = self._map(tmp_path, "HIGH", [_rec("CVE-2021-41617", vm="range_confirmed", q=vi.MATCH_QUALITY_EXACT)])
        model = result["vulnerabilities"][0]["confidence_model"]
        assert set(model) >= {"technology_confidence", "mapping_confidence", "source_confidence", "final_confidence", "rule"}
        assert model["final_confidence"] == vi._min_confidence(
            model["technology_confidence"], model["mapping_confidence"], model["source_confidence"])

    def test_single_source_exact_range_is_high_when_technology_is_high(self, tmp_path):
        result, _ = self._map(tmp_path, "HIGH", [_rec("CVE-2021-41617", vm="range_confirmed", q=vi.MATCH_QUALITY_EXACT)])
        assert result["vulnerabilities"][0]["confidence"] == vi.CONFIDENCE_HIGH

    def test_keyword_only_never_exceeds_medium_even_with_many_sources(self, tmp_path):
        recs = [_rec("CVE-2021-1", source=s) for s in ("nvd", "osv", "github_advisories")]
        result, _ = self._map(tmp_path, "HIGH", recs)
        assert result["vulnerabilities"][0]["confidence"] == vi.CONFIDENCE_MEDIUM

    def test_versionless_observation_is_low_everywhere(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        result = vi.map_technology_to_cves(
            {"technology": "OpenSSH", "target": "10.0.0.1", "confidence": "HIGH"}, store=store,
            source_results={"records": [_rec("CVE-2021-1", vm="unknown")], "source_status": _status(nvd=FOUND)},
            kev_entries=[], exploitdb_index={})
        vuln = result["vulnerabilities"][0]
        assert vuln["applicability"] == "version_unknown_cannot_confirm"
        assert vuln["confidence"] == vi.CONFIDENCE_LOW
        assert "version unknown" in vuln["statement"]

    def test_versionless_observation_never_accepts_a_range_confirmation(self, tmp_path):
        # Found by an exhaustive property check over the confidence model: a
        # caller-supplied record claiming range_confirmed for an observation
        # with NO version produced "version_range_confirmed" at HIGH.
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        result = vi.map_technology_to_cves(
            {"technology": "OpenSSH", "target": "10.0.0.1", "confidence": "HIGH"}, store=store,
            source_results={"records": [_rec("CVE-2021-1", vm="range_confirmed", q=vi.MATCH_QUALITY_EXACT)],
                            "source_status": _status(nvd=FOUND)},
            kev_entries=[], exploitdb_index={})
        vuln = result["vulnerabilities"][0]
        assert vuln["applicability"] == "version_unknown_cannot_confirm" and vuln["confidence"] == vi.CONFIDENCE_LOW
        assert "version unknown" in vuln["statement"]
        assert any("no version was observed" in n for n in vuln["mapping_notes"])
        assert len(store.all()) == 1   # the CVE is still reported, just honestly

    def test_related_product_confirmation_is_downgraded_not_trusted(self, tmp_path):
        result, _ = self._map(tmp_path, "HIGH", [_rec("CVE-2021-1", vm="range_confirmed", q=vi.MATCH_QUALITY_RELATED)])
        vuln = result["vulnerabilities"][0]
        assert vuln["applicability"] == "keyword_match_version_unconfirmed"
        assert vuln["confidence"] == vi.CONFIDENCE_LOW

    def test_kev_and_cvss_never_raise_confidence_or_harden_language(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        kev = [{"cve_id": "CVE-2021-1", "date_added": "2022-01-01", "vulnerability_name": "x"}]
        result = vi.map_technology_to_cves(
            {"technology": "OpenSSH", "version": "7.0", "target": "10.0.0.1", "confidence": "LOW"}, store=store,
            source_results={"records": [_rec("CVE-2021-1", cvss_score=10.0, severity="CRITICAL")],
                            "source_status": _status(nvd=FOUND)},
            kev_entries=kev, exploitdb_index={"CVE-2021-1": [{"edb_id": "1"}]})
        vuln = result["vulnerabilities"][0]
        assert vuln["confidence"] == vi.CONFIDENCE_LOW
        assert vuln["statement"].startswith("Detected OpenSSH 7.0 — POSSIBLY related to CVE-2021-1")
        text = json.dumps(store.all()).lower()
        for banned in ("confirmed exploitable", "is vulnerable", "confirmed vulnerable", "successfully exploited",
                       "is being exploited", "target is exploited"):
            assert banned not in text

    def test_source_disagreement_is_preserved_not_resolved(self, tmp_path):
        recs = [_rec("CVE-2021-1", source="nvd", vm="range_confirmed", q=vi.MATCH_QUALITY_EXACT),
                _rec("CVE-2021-1", source="github_advisories", vm="keyword_only")]
        result, store = self._map(tmp_path, "HIGH", recs)
        vuln = result["vulnerabilities"][0]
        assert vuln["source_disagreement"] is True
        assert {s["version_match"] for s in vuln["matched_sources"]} == {"range_confirmed", "keyword_only"}
        assert any("disagree" in e.lower() for e in store.all()[0]["evidence"])

    def test_caller_cannot_inject_confidence_via_observation_fields(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        result = vi.map_technology_to_cves(
            {"technology": "OpenSSH", "version": "7.0", "target": "10.0.0.1", "confidence": "CERTAIN"}, store=store,
            source_results={"records": [_rec("CVE-2021-1")], "source_status": _status(nvd=FOUND)},
            kev_entries=[], exploitdb_index={})
        assert result["vulnerabilities"][0]["confidence_model"]["technology_confidence"] == vi.CONFIDENCE_MEDIUM


# ---------------------------------------------------------------------------
# Negative-result semantics (section 8)
# ---------------------------------------------------------------------------

class TestNegativeResultSemantics:
    def _run(self, tmp_path, source_status, records=None):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        result = vi.map_technology_to_cves(
            {"technology": "nginx", "version": "1.18.0", "target": "example.com"}, store=store,
            source_results={"records": records or [], "source_status": source_status},
            kev_entries=[], exploitdb_index={})
        return result, [r["type"] for r in store.all()]

    def test_partial_outage_is_inconclusive_not_clean(self, tmp_path):
        # Reproduced against the original: NVD 429 + GHSA empty persisted a
        # "checked, no match" record that surface_mapper stored as CHECK_NOT_FOUND.
        result, types = self._run(tmp_path, _status(nvd=RATE, osv=SKIP, github_advisories=EMPTY))
        assert result["status"] == "inconclusive"
        assert types == []
        assert result["source_summary"]["inconclusive_sources"] == ["nvd", "osv"]

    def test_all_sources_down_is_unavailable(self, tmp_path):
        result, types = self._run(tmp_path, _status(nvd=DOWN, github_advisories=RATE))
        assert result["status"] == "sources_unavailable" and types == []

    def test_all_conclusive_empty_persists_negative_with_sources(self, tmp_path):
        result, types = self._run(tmp_path, _status(nvd=EMPTY, github_advisories=EMPTY))
        assert result["status"] == "not_found" and types == ["vuln_intel_checked_no_match"]
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        assert store.all()[0]["metadata"]["sources_queried"] == ["github_advisories", "nvd"]

    def test_annotation_sources_cannot_vote(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        with mock.patch("reconhound.vuln_intel.query_cisa_kev",
                        return_value={"status": "found", "outcome": "found", "entries": [], "error": None}), \
             mock.patch("reconhound.vuln_intel.fetch_exploitdb_index",
                        return_value={"status": "found", "outcome": "found", "index": {}, "error": None}):
            result = vi.map_technology_to_cves(
                {"technology": "nginx", "version": "1.18.0", "target": "example.com"}, store=store,
                source_results={"records": [], "source_status": _status(nvd=RATE)})
        assert result["status"] == "sources_unavailable"
        assert store.all() == []
        assert result["source_status"]["cisa_kev"]["annotation_only"] is True

    def test_not_checked_budget_outcome_is_inconclusive(self, tmp_path):
        status = {"nvd": {"status": "error", "outcome": vi.OUTCOME_NOT_CHECKED, "conclusive": False, "error": "budget"}}
        result, types = self._run(tmp_path, status)
        assert result["status"] == "sources_unavailable" and types == []

    def test_legacy_status_only_dicts_keep_old_meaning(self, tmp_path):
        result, types = self._run(tmp_path / "a", {"nvd": {"status": "not_found", "error": None}})
        assert result["status"] == "not_found" and types == ["vuln_intel_checked_no_match"]
        result, types = self._run(tmp_path / "b", {"nvd": {"status": "error", "error": "timeout"}})
        assert result["status"] == "sources_unavailable" and types == []

    def test_unknown_outcome_value_is_treated_as_inconclusive(self):
        summary = vi._sources_conclusive({"nvd": {"status": "found", "outcome": "totally_new_state"}})
        assert summary["inconclusive_sources"] == ["nvd"]

    def test_positive_finding_records_which_providers_were_down(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        vi.map_technology_to_cves(
            {"technology": "nginx", "version": "1.18.0", "target": "example.com"}, store=store,
            source_results={"records": [_rec("CVE-2021-1", source="github_advisories")],
                            "source_status": _status(nvd=RATE, github_advisories=FOUND)},
            kev_entries=[], exploitdb_index={})
        md = store.all()[0]["metadata"]
        assert md["provider_outcomes"] == {"github_advisories": vi.OUTCOME_FOUND, "nvd": vi.OUTCOME_RATE_LIMITED}

    def test_truncated_source_is_reported_on_the_result(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        result = vi.map_technology_to_cves(
            {"technology": "nginx", "version": "1.18.0", "target": "example.com"}, store=store,
            source_results={"records": [_rec("CVE-2021-1")], "source_status": _status(nvd=FOUND), "truncated": True},
            kev_entries=[], exploitdb_index={})
        assert result["truncated"] is True


# ---------------------------------------------------------------------------
# Three-state annotation semantics (KEV / Exploit-DB / EPSS)
# ---------------------------------------------------------------------------

class TestThreeStateAnnotations:
    def test_kev_outage_is_not_checked_and_keeps_downstream_contract(self):
        rec = {"cve_id": "CVE-2021-1", "cisa_kev": None}
        vi.annotate_kev(rec, vi.KevCatalog.unavailable("feed down"))
        assert rec["cisa_kev"] is None                       # risk_engine truthiness contract
        assert rec["cisa_kev_status"] == {**rec["cisa_kev_status"], "checked": False, "listed": None}
        assert "feed down" in rec["cisa_kev_status"]["reason"]

    def test_kev_checked_not_listed(self):
        rec = {"cve_id": "CVE-2021-1", "cisa_kev": None}
        vi.annotate_kev(rec, vi.KevCatalog(entries=[], available=True))
        assert rec["cisa_kev"] is None
        assert rec["cisa_kev_status"]["checked"] is True and rec["cisa_kev_status"]["listed"] is False

    def test_kev_listed_language_denies_target_confirmation(self):
        rec = {"cve_id": "CVE-2021-1", "cisa_kev": None}
        vi.annotate_kev(rec, [{"cve_id": "CVE-2021-1", "date_added": "2022-01-01"}])
        assert rec["cisa_kev"]["listed"] is True
        assert "does NOT confirm exploitability" in rec["cisa_kev"]["note"]

    def test_kev_from_result_respects_outcome_and_legacy_status(self):
        assert not vi.KevCatalog.from_result({"status": "error", "outcome": "unavailable", "entries": []}).available
        assert vi.KevCatalog.from_result({"status": "not_found", "entries": []}).available
        assert not vi.KevCatalog.from_result({"status": "error", "entries": []}).available
        assert vi.KevCatalog.coerce(None).available is False
        assert vi.KevCatalog.coerce([]).available is True

    def test_exploitdb_outage_vs_empty(self):
        rec = {"cve_id": "CVE-2021-1", "exploitdb_references": []}
        vi.annotate_exploitdb(rec, vi.ExploitDbIndex.unavailable("down"))
        assert rec["exploitdb_references"] == [] and rec["exploitdb_status"]["checked"] is False
        rec2 = {"cve_id": "CVE-2021-1", "exploitdb_references": []}
        vi.annotate_exploitdb(rec2, {})
        assert rec2["exploitdb_status"] == {**rec2["exploitdb_status"], "checked": True, "count": 0}

    def test_exploitdb_references_are_bounded(self):
        hits = [{"edb_id": str(i)} for i in range(50)]
        rec = {"cve_id": "CVE-2021-1", "exploitdb_references": []}
        vi.annotate_exploitdb(rec, {"CVE-2021-1": hits})
        assert len(rec["exploitdb_references"]) == vi.MAX_EXPLOITDB_REFERENCES_PER_CVE
        assert rec["exploitdb_status"]["count"] == 50 and rec["exploitdb_status"]["truncated"] is True

    def test_epss_unavailable_vs_unscored_vs_zero(self):
        a = {"cve_id": "CVE-2021-1"}; vi.annotate_epss(a, None, available=False, reason="down")
        b = {"cve_id": "CVE-2021-1"}; vi.annotate_epss(b, {}, available=True)
        c = {"cve_id": "CVE-2021-1"}; vi.annotate_epss(c, {"CVE-2021-1": {"epss": 0.0, "percentile": 0.01, "date": "2026-09-07"}})
        assert (a["epss"]["checked"], a["epss"]["score"]) == (False, None)
        assert (b["epss"]["checked"], b["epss"]["score"]) == (True, None)
        assert (c["epss"]["checked"], c["epss"]["score"]) == (True, 0.0)
        assert "never target evidence" in a["epss"]["note"] or "not evidence about this target" in c["epss"]["note"]

    def test_epss_failed_batch_marks_its_cves_not_checked(self):
        first = _fake_response(200, {"data": [{"cve": "CVE-2021-1", "epss": "0.5", "percentile": "0.9", "date": "2026-09-07"}]})
        with mock.patch("reconhound.vuln_intel.requests.get", side_effect=[first, _fake_response(503)]):
            result = vi.query_epss([f"CVE-2021-{i}" for i in range(1, 151)])
        assert result["status"] == "found" and result["returned"] == 1 and len(result["unchecked"]) == 50
        scored = {"cve_id": "CVE-2021-1"}; vi.annotate_epss(scored, result["scores"])
        unscored_ok = {"cve_id": "CVE-2021-2"}; vi.annotate_epss(unscored_ok, result["scores"])
        failed = {"cve_id": "CVE-2021-120"}; vi.annotate_epss(failed, result["scores"])
        assert scored["epss"]["score"] == 0.5
        assert unscored_ok["epss"]["checked"] is True and unscored_ok["epss"]["score"] is None
        assert failed["epss"]["checked"] is False


# ---------------------------------------------------------------------------
# F. EPSS provider
# ---------------------------------------------------------------------------

class TestQueryEpss:
    def test_malformed_values_are_nulled_not_trusted(self):
        data = {"data": [{"cve": "CVE-2021-1", "epss": "1.5", "percentile": "abc"},
                         {"cve": "CVE-2021-2", "epss": 0, "percentile": 0.0},
                         {"cve": "CVE-2021-3", "epss": "-0.1"}, {"cve": "bad", "epss": 0.5}, "junk", None,
                         {"cve": "CVE-2021-4", "epss": True}]}
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(200, data)):
            result = vi.query_epss(["CVE-2021-1", "CVE-2021-2", "CVE-2021-3", "CVE-2021-4", "CVE-2021-1", "nope"])
        s = result["scores"]
        assert s["CVE-2021-1"]["epss"] is None and s["CVE-2021-1"]["percentile"] is None
        assert s["CVE-2021-2"]["epss"] == 0.0
        assert s["CVE-2021-3"]["epss"] is None and s["CVE-2021-4"]["epss"] is None
        assert "bad" not in s and result["requested"] == 4

    def test_empty_authoritative_vs_malformed_vs_unavailable(self):
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(200, {"data": []})):
            assert vi.query_epss(["CVE-2021-1"])["outcome"] == vi.OUTCOME_EMPTY_AUTHORITATIVE
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(200, {"nope": 1})):
            r = vi.query_epss(["CVE-2021-1"])
            assert r["outcome"] == vi.OUTCOME_MALFORMED and r["status"] == "error"
        with mock.patch("reconhound.vuln_intel.requests.get", side_effect=requests.exceptions.ConnectionError("x")):
            r = vi.query_epss(["CVE-2021-1"])
            assert r["outcome"] == vi.OUTCOME_UNAVAILABLE and r["returned"] == 0
            assert r["scores"]["CVE-2021-1"]["unchecked"] is True   # not "no score", NOT CHECKED
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(429)):
            assert vi.query_epss(["CVE-2021-1"])["status"] == "rate_limited"

    def test_no_ids_is_skipped_without_a_request(self):
        with mock.patch("reconhound.vuln_intel.requests.get") as g:
            r = vi.query_epss(["not-a-cve", ""])
        assert r["outcome"] == vi.OUTCOME_SKIPPED and g.call_count == 0

    def test_batches_are_capped(self):
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(200, {"data": []})) as g:
            r = vi.query_epss([f"CVE-2021-{i}" for i in range(1, 5001)])
        assert g.call_count == vi.EPSS_MAX_BATCHES and r["notes"]


# ---------------------------------------------------------------------------
# C. NVD provider behaviour, transport, budget, retry
# ---------------------------------------------------------------------------

class TestTransportHardening:
    def test_budget_exhaustion_is_not_checked(self):
        sess = vi.ProviderSession(budget=vi.RequestBudget(1))
        with mock.patch("reconhound.vuln_intel.requests.get",
                        return_value=_fake_response(200, {"totalResults": 0, "vulnerabilities": []})) as g:
            r1 = vi.query_nvd("nginx", "1", session=sess)
            r2 = vi.query_nvd("apache", "1", session=sess)
        assert r1["outcome"] == vi.OUTCOME_EMPTY_AUTHORITATIVE
        assert r2["outcome"] == vi.OUTCOME_NOT_CHECKED and r2["status"] == "error" and g.call_count == 1
        assert not vi._sources_conclusive({"nvd": r2})["any_conclusive"]

    def test_deadline_stops_before_a_request(self):
        clock = [0.0]
        sess = vi.ProviderSession(deadline=vi.Deadline(10.0, monotonic=lambda: clock[0]))
        clock[0] = 11.0
        with mock.patch("reconhound.vuln_intel.requests.get") as g:
            r = vi.query_nvd("nginx", session=sess)
        assert r["outcome"] == vi.OUTCOME_NOT_CHECKED and g.call_count == 0

    def test_429_retry_after_is_honoured_bounded_and_recovers(self):
        sleeps = []
        sess = vi.ProviderSession(retry_policy=vi.RetryPolicy(max_retries=2, jitter=False, sleep=sleeps.append),
                                  rate_limiters={"nvd": vi.RateLimiter(0, sleep=sleeps.append)})
        seq = [_fake_response(429, {}, headers={"Retry-After": "99999999"}),
               _fake_response(200, {"totalResults": 0, "vulnerabilities": []})]
        with mock.patch("reconhound.vuln_intel.requests.get", side_effect=seq) as g:
            r = vi.query_nvd("nginx", session=sess)
        assert r["status"] == "not_found" and g.call_count == 2
        assert sleeps == [vi.MAX_RETRY_AFTER_SECONDS]

    def test_persistent_429_is_rate_limited_after_bounded_attempts(self):
        sess = vi.ProviderSession(retry_policy=vi.RetryPolicy(max_retries=2, jitter=False, sleep=lambda s: None))
        with mock.patch("reconhound.vuln_intel.requests.get",
                        return_value=_fake_response(429, {}, headers={"Retry-After": "7"})) as g:
            r = vi.query_nvd("nginx", session=sess)
        assert r["status"] == "rate_limited" and g.call_count == 3 and r["retry_after"] == 7.0

    def test_no_session_means_exactly_one_attempt(self):
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(429)) as g:
            assert vi.query_nvd("nginx")["status"] == "rate_limited"
        assert g.call_count == 1

    def test_5xx_and_timeout_are_retried_then_unavailable(self):
        sess = vi.ProviderSession(retry_policy=vi.RetryPolicy(max_retries=2, jitter=False, sleep=lambda s: None))
        seq = [_fake_response(503), requests.exceptions.Timeout(), _fake_response(502)]
        with mock.patch("reconhound.vuln_intel.requests.get", side_effect=seq) as g:
            r = vi.query_nvd("nginx", session=sess)
        assert r["status"] == "error" and r["outcome"] == vi.OUTCOME_UNAVAILABLE and g.call_count == 3

    def test_retry_after_parsing_is_bounded(self):
        assert vi._parse_retry_after("30") == 30.0
        assert vi._parse_retry_after("999999") == vi.MAX_RETRY_AFTER_SECONDS
        assert vi._parse_retry_after("-5") == 0.0
        assert vi._parse_retry_after("nan") is None and vi._parse_retry_after("soon") is None
        assert vi._parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0

    def test_rate_limiter_spacing_and_penalty(self):
        clock = [0.0]; waits = []

        def _sleep(s):
            waits.append(s); clock[0] += s
        lim = vi.RateLimiter(6.0, sleep=_sleep, monotonic=lambda: clock[0])
        lim.acquire(); lim.acquire(); lim.acquire()
        assert len(waits) == 2 and all(abs(w - 6.0) < 1e-9 for w in waits)
        lim.penalize(30); lim.acquire()
        assert abs(waits[-1] - 30.0) < 1e-6

    def test_build_session_uses_nvd_documented_intervals(self, tmp_path, monkeypatch):
        monkeypatch.delenv(vi.NVD_API_KEY_ENV, raising=False)
        monkeypatch.delenv(vi.GITHUB_TOKEN_ENV, raising=False)
        s = vi.build_session(output_dir=str(tmp_path), sleep=lambda x: None)
        assert s.limiter("nvd").min_interval == vi.NVD_MIN_INTERVAL_UNAUTHENTICATED
        s2 = vi.build_session(output_dir=str(tmp_path), nvd_api_key="k", sleep=lambda x: None)
        assert s2.limiter("nvd").min_interval == vi.NVD_MIN_INTERVAL_WITH_KEY

    def test_oversized_body_is_malformed_not_partial(self):
        body = (b'{"totalResults":0,"vulnerabilities":[' + b",".join(b'{"cve":{"id":"CVE-2021-1"}}' for _ in range(400000)) + b"]}")
        assert len(body) > vi.MAX_RESPONSE_BYTES
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_RawResp(body)):
            r = vi.query_nvd("nginx")
        assert r["status"] == "error" and r["outcome"] == vi.OUTCOME_MALFORMED

    def test_empty_200_is_malformed(self):
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_RawResp(b"")):
            r = vi.query_nvd("nginx")
        assert r["outcome"] == vi.OUTCOME_MALFORMED

    def test_real_stream_is_read_bounded(self):
        with mock.patch("reconhound.vuln_intel.requests.get",
                        return_value=_RawResp(b'{"totalResults":0,"vulnerabilities":[]}')) as g:
            r = vi.query_nvd("nginx")
        assert r["status"] == "not_found"
        assert g.call_args.kwargs.get("stream") is True

    def test_oversized_feeds_are_malformed(self):
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_RawResp(b"x" * (vi.MAX_KEV_RESPONSE_BYTES + 1))):
            assert vi.query_cisa_kev()["outcome"] == vi.OUTCOME_MALFORMED
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_RawResp(b"x" * (vi.MAX_EXPLOITDB_RESPONSE_BYTES + 1))):
            assert vi.fetch_exploitdb_index()["outcome"] == vi.OUTCOME_MALFORMED

    def test_nvd_pagination_and_truncation_are_explicit(self):
        page = lambda ids, total: _fake_response(200, {"totalResults": total, "vulnerabilities": [
            {"cve": {"id": i, "descriptions": [{"lang": "en", "value": "d"}]}} for i in ids]})
        with mock.patch("reconhound.vuln_intel.requests.get",
                        side_effect=[page(["CVE-2021-1", "CVE-2021-2"], 5), page(["CVE-2021-3", "CVE-2021-4"], 5)]) as g:
            r = vi.query_nvd("nginx", results_per_page=2, max_results=4, max_pages=2)
        assert [v["cve_id"] for v in r["vulnerabilities"]] == ["CVE-2021-1", "CVE-2021-2", "CVE-2021-3", "CVE-2021-4"]
        assert r["pages"] == 2 and r["truncated"] is True and r["total_results"] == 5
        assert any("PARTIAL" in n for n in r["notes"])
        assert g.call_args_list[1].kwargs["params"]["startIndex"] == 2

    def test_nvd_pagination_failure_after_first_page_keeps_partial_flagged(self):
        page = _fake_response(200, {"totalResults": 50, "vulnerabilities": [{"cve": {"id": "CVE-2021-1"}}]})
        with mock.patch("reconhound.vuln_intel.requests.get", side_effect=[page, _fake_response(429)]):
            r = vi.query_nvd("nginx", results_per_page=1, max_results=10, max_pages=3)
        assert r["status"] == "found" and r["truncated"] is True and len(r["vulnerabilities"]) == 1

    def test_nvd_cvss_prefers_primary_over_secondary(self):
        metrics = {"cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "s"}},
            {"type": "Primary", "cvssData": {"baseScore": 5.3, "baseSeverity": "MEDIUM", "vectorString": "p"}}]}
        assert vi._extract_nvd_cvss(metrics) == (5.3, "p", "MEDIUM")
        assert len(vi._all_nvd_cvss_metrics(metrics)) == 2  # disagreement preserved

    def test_hostile_nvd_payload_shapes_never_crash(self):
        shapes = [
            {"vulnerabilities": "notalist"},
            {"vulnerabilities": [None, 1, "x", [], {"cve": None}, {"cve": "s"}]},
            {"vulnerabilities": [{"cve": {"id": "CVE-2021-1", "descriptions": "x", "metrics": [], "references": "x", "configurations": "x"}}]},
            {"vulnerabilities": [{"cve": {"id": "CVE-2021-1", "descriptions": [{"lang": "en", "value": "D" * 500000}],
                                          "references": [{"url": f"https://r/{i}"} for i in range(5000)]}}]},
            {"totalResults": "lots", "vulnerabilities": []},
            {"vulnerabilities": [{"cve": {"id": "CVE-2021-" + "9" * 5000}}]},
        ]
        for shape in shapes:
            with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(200, shape)):
                r = vi.query_nvd("nginx", "1.0")
            json.dumps(r)
            for v in r["vulnerabilities"]:
                assert len(v["summary"] or "") <= vi.MAX_SUMMARY_CHARS + 40
                assert len(v["references"]) <= vi.MAX_REFERENCES_PER_CVE

    def test_deeply_nested_payload_is_survivable(self):
        deep = {"vulnerabilities": [{"cve": {"id": "CVE-2021-1"}}]}
        node = deep
        for _ in range(500):
            node["z"] = {"z": {}}
            node = node["z"]["z"]
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(200, deep)):
            assert vi.query_nvd("nginx")["status"] == "found"
        assert isinstance(vi._jsonify(deep), dict)

    def test_ghsa_records_preserve_identifiers_and_fixed_versions(self):
        sample = [dict(GH_SAMPLE[0], vulnerabilities=[{"package": {"ecosystem": "npm", "name": "lodash"},
                                                          "vulnerable_version_range": ">= 4.0.0, <= 4.17.23",
                                                          "first_patched_version": "4.17.24"}])]
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(200, sample)):
            r = vi.query_github_advisories("lodash", version="4.17.15")
        v = r["vulnerabilities"][0]
        assert v["advisory_ids"] == ["GHSA-r5fr-rjxr-66jc"] and v["fixed_versions"] == ["4.17.24"]
        assert v["package"] == "lodash" and v["ecosystem"] == "npm" and v["match_quality"] == vi.MATCH_QUALITY_PACKAGE

    def test_ghsa_package_name_mismatch_is_not_confirmed(self):
        sample = [dict(GH_SAMPLE[0], vulnerabilities=[{"package": {"ecosystem": "npm", "name": "lodash-es"},
                                                          "vulnerable_version_range": ">= 4.0.0, <= 4.17.23"}])]
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(200, sample)):
            r = vi.query_github_advisories("lodash", version="4.17.15")
        v = r["vulnerabilities"][0]
        assert v["version_match"] == "keyword_only" and v["package"] is None and v["match_quality"] == vi.MATCH_QUALITY_KEYWORD

    def test_osv_records_preserve_fixed_versions_and_package(self):
        sample = {"vulns": [dict(OSV_SAMPLE["vulns"][0], affected=[{"package": {"name": "lodash", "ecosystem": "npm"},
                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}])]}
        with mock.patch("reconhound.vuln_intel.requests.post", return_value=_fake_response(200, sample)):
            r = vi.query_osv("lodash", version="4.17.15", ecosystem="npm")
        v = r["vulnerabilities"][0]
        assert v["fixed_versions"] == ["4.17.21"] and v["package"] == "lodash" and v["ecosystem"] == "npm"
        assert v["advisory_ids"] == ["GHSA-29mw-wpgm-hmr9"]

    def test_osv_result_count_is_bounded(self):
        vulns = [{"id": f"OSV-{i}", "aliases": [f"CVE-2021-{i}"]} for i in range(vi.MAX_RECORDS_PER_SOURCE + 50)]
        with mock.patch("reconhound.vuln_intel.requests.post", return_value=_fake_response(200, {"vulns": vulns})):
            r = vi.query_osv("lodash", ecosystem="npm")
        assert len(r["vulnerabilities"]) == vi.MAX_RECORDS_PER_SOURCE and r["truncated"] is True

    def test_kev_duplicates_and_junk_are_filtered_and_sanitized(self):
        kev = {"vulnerabilities": [{"cveID": "CVE-2021-1", "vendorProject": "A"}, {"cveID": "CVE-2021-1", "vendorProject": "B"},
                                   {"cveID": "notacve"}, {"noid": 1}, "junk", None, {"cveID": 5},
                                   {"cveID": "CVE-2021-2", "vulnerabilityName": "\x1b[31mred", "dateAdded": 12345}]}
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(200, kev)):
            r = vi.query_cisa_kev()
        assert len(r["entries"]) == 2 and r["entries"][0]["vendor_project"] == "A"
        assert "\x1b" not in r["entries"][1]["vulnerability_name"] and r["entries"][1]["date_added"] is None

    def test_exploitdb_per_cve_cap_and_three_state_verified(self):
        hdr = "id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases\n"
        rows = "".join('%d,f,"t",2020,a,dos,x,,2020,,1,CVE-2009-3699,,\n' % i for i in range(40))
        r = vi.fetch_exploitdb_index(preloaded_csv_text=hdr + rows)
        assert len(r["index"]["CVE-2009-3699"]) == vi.MAX_EXPLOITDB_ENTRIES_PER_CVE and r["truncated"] is True
        r = vi.fetch_exploitdb_index(preloaded_csv_text=hdr + '1,f,"t",2020,a,dos,x,,2020,,,CVE-2009-3699,,\n')
        assert r["index"]["CVE-2009-3699"][0]["verified"] is None
        assert vi.fetch_exploitdb_index(preloaded_csv_text="\x00\xff" * 100)["status"] in ("not_found", "error")

    def test_one_provider_down_while_another_succeeds(self):
        with mock.patch("reconhound.vuln_intel.query_nvd", return_value={"status": "error", "outcome": vi.OUTCOME_UNAVAILABLE, "vulnerabilities": [], "error": "timeout"}), \
             mock.patch("reconhound.vuln_intel.query_osv", return_value={"status": "found", "outcome": vi.OUTCOME_FOUND, "vulnerabilities": [_rec("CVE-2021-1", source="osv")], "error": None}), \
             mock.patch("reconhound.vuln_intel.query_github_advisories", side_effect=RuntimeError("boom")):
            r = vi.query_all_sources("x", "1")
        assert [x["cve_id"] for x in r["records"]] == ["CVE-2021-1"]
        assert r["source_status"]["nvd"]["conclusive"] is False
        assert r["source_status"]["osv"]["conclusive"] is True
        assert r["source_status"]["github_advisories"]["outcome"] == vi.OUTCOME_UNAVAILABLE and "boom" in r["source_status"]["github_advisories"]["error"]


# ---------------------------------------------------------------------------
# Cache (section 6)
# ---------------------------------------------------------------------------

class TestProviderCache:
    def test_outages_are_never_cached(self, tmp_path):
        c = vi.ProviderCache(str(tmp_path), "q")
        for outcome in (vi.OUTCOME_UNAVAILABLE, vi.OUTCOME_RATE_LIMITED, vi.OUTCOME_MALFORMED, vi.OUTCOME_NOT_CHECKED, "garbage"):
            c.put("k", outcome, {"x": 1})
        assert c.get("k") is None and c.writes == 0

    def test_smuggled_non_conclusive_entries_are_ignored_on_load(self, tmp_path):
        (tmp_path / "q.json").write_text(json.dumps({"format": 1, "entries": {
            "k": {"outcome": "unavailable", "payload": {}, "stored_at": _time.time()},
            "good": {"outcome": "empty_authoritative", "payload": {"vulnerabilities": []}, "stored_at": _time.time()},
            "notime": {"outcome": "found", "payload": {}, "stored_at": "yesterday"}}}))
        c = vi.ProviderCache(str(tmp_path), "q")
        assert c.get("k") is None and c.get("good") is not None and c.get("notime") is None

    @pytest.mark.parametrize("body", ["{not json", "[]", '{"format": 99, "entries": {}}', '{"format":1,"entries":[1,2]}', ""])
    def test_corrupt_cache_files_are_survivable(self, tmp_path, body):
        (tmp_path / "q.json").write_text(body)
        c = vi.ProviderCache(str(tmp_path), "q")
        c.put("k", vi.OUTCOME_FOUND, {"v": 1})
        assert c.get("k")["payload"] == {"v": 1}

    def test_oversized_entry_is_refused(self, tmp_path):
        c = vi.ProviderCache(str(tmp_path), "q", max_bytes=8192)
        c.put("big", vi.OUTCOME_FOUND, {f"k{i}": "x" * 100 for i in range(150)})  # survives _jsonify, exceeds the cap
        assert c.get("big") is None and any("size cap" in n for n in c.notes)
        assert not (tmp_path / "q.json").exists() or (tmp_path / "q.json").stat().st_size <= 8192

    def test_ttl_expiry_eviction_and_deterministic_serialization(self, tmp_path):
        now = [1000.0]
        c = vi.ProviderCache(str(tmp_path), "q", ttl_seconds=10, max_entries=3, now=lambda: now[0])
        for key in "abcd":
            c.put(key, vi.OUTCOME_FOUND, key); now[0] += 1
        assert c.get("a") is None and c.get("d") is not None
        now[0] += 100
        assert c.get("d") is None and c.stale == 1
        c.put("z", vi.OUTCOME_FOUND, 1); first = (tmp_path / "q.json").read_text()
        c.put("z", vi.OUTCOME_FOUND, 1); second = (tmp_path / "q.json").read_text()
        assert first == second

    def test_unwritable_cache_dir_is_a_note_not_a_failure(self):
        c = vi.ProviderCache("/proc/nonexistent/x", "q")
        c.put("k", vi.OUTCOME_FOUND, {})
        assert not c.available and c.get("k") is None and c.notes

    def test_write_failure_is_recorded_not_raised(self, tmp_path):
        c = vi.ProviderCache(str(tmp_path), "q")
        with mock.patch.object(c, "_atomic_write", side_effect=OSError("disk full")):
            c.put("k", vi.OUTCOME_FOUND, {})
        assert any("disk full" in n for n in c.notes)

    def test_cache_hit_serves_nvd_without_network_and_reports_freshness(self, tmp_path):
        sess = vi.build_session(output_dir=str(tmp_path), sleep=lambda s: None)
        with mock.patch("reconhound.vuln_intel.requests.get",
                        return_value=_fake_response(200, {"totalResults": 0, "vulnerabilities": []})) as g:
            r1 = vi.query_nvd("nginx", "1.18.0", session=sess)
            r2 = vi.query_nvd("nginx", "1.18.0", session=sess)
        assert g.call_count == 1 and r1["cache"] == {"hit": False}
        assert r2["cache"]["hit"] is True and r2["cache"]["age_seconds"] >= 0 and r2["status"] == "not_found"
        assert (tmp_path / vi.CACHE_DIRNAME / "queries.json").exists()

    def test_rate_limited_answer_is_not_served_from_cache_next_time(self, tmp_path):
        sess = vi.build_session(output_dir=str(tmp_path), sleep=lambda s: None,
                                retry_policy=vi.RetryPolicy(max_retries=0, sleep=lambda s: None))
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(429)) as g:
            vi.query_nvd("nginx", "1", session=sess); vi.query_nvd("nginx", "1", session=sess)
        assert g.call_count == 2

    def test_poisoned_cache_payload_types_are_neutralized(self, tmp_path):
        cache_dir = tmp_path / vi.CACHE_DIRNAME; cache_dir.mkdir()
        key = vi.ProviderCache.key("nvd", "nginx", "1.0", vi.NVD_API_BASE, vi.DEFAULT_NVD_MAX_RESULTS, vi.NVD_DEFAULT_RESULTS_PER_PAGE)
        (cache_dir / "queries.json").write_text(json.dumps({"format": 1, "entries": {key: {
            "outcome": "found", "stored_at": _time.time(),
            "payload": {"vulnerabilities": "poison", "total_results": "x", "notes": [1, 2]}}}}))
        sess = vi.build_session(output_dir=str(tmp_path), sleep=lambda s: None)
        with mock.patch("reconhound.vuln_intel.requests.get", side_effect=AssertionError("network")):
            r = vi.query_nvd("nginx", "1.0", session=sess)
        assert r["status"] == "not_found" and r["cache"]["hit"] is True and r["vulnerabilities"] == []

    def test_cache_key_is_deterministic_and_path_safe(self):
        assert vi.ProviderCache.key("nvd", "../../etc/passwd", None) == vi.ProviderCache.key("nvd", "../../etc/passwd", None)
        assert vi.ProviderCache.key("a") != vi.ProviderCache.key("b")
        assert all(ch in "0123456789abcdef" for ch in vi.ProviderCache.key("../x"))

    def test_large_feeds_round_trip_through_the_cache_intact(self, tmp_path):
        # Reproduced during the hardening pass: the cache serializer capped
        # lists at 200 items, so a 1,400-entry KEV catalogue came back as 200.
        sess = vi.build_session(output_dir=str(tmp_path), sleep=lambda s: None)
        kev = {"vulnerabilities": [{"cveID": f"CVE-2021-{i}", "vendorProject": "v"} for i in range(1400)]}
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(200, kev)):
            live = vi.query_cisa_kev(session=sess); cached = vi.query_cisa_kev(session=sess)
        assert len(live["entries"]) == len(cached["entries"]) == 1400
        assert vi.KevCatalog.from_result(cached).lookup("CVE-2021-1399") is not None
        hdr = "id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases\n"
        rows = "".join(f'{i},f,"t",2020,a,dos,x,,2020,,1,CVE-2020-{i},,\n' for i in range(3000))
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(200, text=hdr + rows)):
            live = vi.fetch_exploitdb_index(session=sess); cached = vi.fetch_exploitdb_index(session=sess)
        assert len(live["index"]) == len(cached["index"]) == 3000 and cached["cache"]["hit"] is True

    def test_feed_cache_shares_kev_across_calls(self, tmp_path):
        sess = vi.build_session(output_dir=str(tmp_path), sleep=lambda s: None)
        with mock.patch("reconhound.vuln_intel.requests.get", return_value=_fake_response(200, KEV_SAMPLE)) as g:
            a = vi.query_cisa_kev(session=sess); b = vi.query_cisa_kev(session=sess)
        assert g.call_count == 1 and a["entries"] == b["entries"] and b["cache"]["hit"] is True


# ---------------------------------------------------------------------------
# Persistence / sanitization / bounds
# ---------------------------------------------------------------------------

class TestPersistenceHardening:
    def test_batched_write_is_linear_and_bounded(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        records = [_rec(f"CVE-2021-{1000 + i}", summary="x" * 2000, cvss_score=5.0,
                        references=[f"https://r/{j}" for j in range(30)]) for i in range(400)]
        started = _time.time()
        r = vi.map_technology_to_cves({"technology": "nginx", "version": "1.18.0", "target": "example.com"},
                                      store=store, source_results={"records": records, "source_status": _status(nvd=FOUND)},
                                      kev_entries=[], exploitdb_index={})
        assert _time.time() - started < 2.0
        assert len(r["vulnerabilities"]) == vi.MAX_CVES_PER_OBSERVATION and r["truncated"] is True
        persisted = store.all()
        assert len(persisted) == vi.MAX_CVES_PER_OBSERVATION and r["persisted"] == len(persisted)
        v = persisted[0]["value"]
        assert len(v["references"]) <= vi.MAX_REFERENCES_PER_CVE and len(v["summaries"][0]) <= vi.MAX_SUMMARY_CHARS + 40

    def test_provider_strings_are_escaped_and_urls_labelled(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        vi.map_technology_to_cves(
            {"technology": "ngin\x1b[31mx", "version": "1.18.0", "target": "example.com"}, store=store,
            source_results={"records": [_rec("CVE-2021-1", summary="evil\x1b]0;pwned\x07 ‮drowssap",
                                              references=["javascript:alert(1)", "https://ok", {"url": "x"}])],
                            "source_status": _status(nvd=FOUND)},
            kev_entries=[], exploitdb_index={})
        dumped = json.dumps(store.all())
        assert "\x1b" not in dumped and "‮" not in dumped and "\x07" not in dumped
        v = store.all()[0]["value"]
        assert "[non-http reference] javascript:alert(1)" in v["references"] and "https://ok" in v["references"]

    def test_unhashable_and_mixed_type_provider_values_do_not_crash_merge(self):
        merged = vi._merge_vulnerability_records([
            {"cve_id": "CVE-2021-1", "source": "a", "references": [{"url": "x"}, ["y"], None, 42], "published": "2020-01-01"},
            {"cve_id": "CVE-2021-1", "source": "b", "published": 12345, "cvss_score": "9.8", "summary": 5},
            {"cve_id": "CVE-2021-1", "source": "c", "published": {"x": 1}, "references": "https://not-a-list"},
            {"cve_id": None}, "junk", {"cve_id": "CVE-2021-" + "9" * 50},
        ])
        assert len(merged) == 1 and merged[0]["published"] == "2020-01-01"
        assert merged[0]["cvss"][0]["score"] == 9.8

    def test_merged_cve_set_is_bounded_and_flagged(self):
        merged = vi._merge_vulnerability_records([_rec(f"CVE-2021-{i}") for i in range(vi.MAX_CVES_PER_OBSERVATION + 10)])
        assert len(merged) == vi.MAX_CVES_PER_OBSERVATION and "merged_cve_set" in merged[0]["truncated_fields"]

    def test_persistence_failure_keeps_in_memory_results(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        with mock.patch.object(store, "add_many", side_effect=OSError("disk full")):
            r = vi.map_technology_to_cves({"technology": "nginx", "version": "1.18.0", "target": "example.com"},
                                          store=store, source_results={"records": [_rec("CVE-2021-1")], "source_status": _status(nvd=FOUND)},
                                          kev_entries=[], exploitdb_index={})
        assert len(r["vulnerabilities"]) == 1 and r["persisted"] == 0 and any("disk full" in e for e in r["errors"])

    def test_store_survives_unserializable_and_directory_errors(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        assert vi._safe_store_add_many(store, [{"type": "x", "value": {1, 2}}]) is not None  # set is not JSON
        assert vi._safe_store_add(store, {"type": "x", "value": object()}) is not None

    def test_finding_values_are_json_safe_and_bounded(self):
        f = vi.make_finding("vulnerability_intelligence", "t", {"b": b"\x00", "n": float("nan"), "s": {1}},
                            ["e" * 5000] + ["x"] * 100, vi.CONFIDENCE_LOW)
        json.dumps(f)
        assert len(f["evidence"]) == vi.MAX_EVIDENCE_ITEMS + 1 and "omitted" in f["evidence"][-1]

    def test_duplicate_findings_are_suppressed_within_a_run(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        keys: set = set()
        for _ in range(3):
            r = vi.map_technology_to_cves({"technology": "nginx", "version": "1.18.0", "target": "example.com"},
                                          store=store, source_results={"records": [_rec("CVE-2021-1")], "source_status": _status(nvd=FOUND)},
                                          kev_entries=[], exploitdb_index={}, persisted_keys=keys)
        assert len(store.all()) == 1 and r["skipped_duplicates"] == 1


# ---------------------------------------------------------------------------
# Targets / phantom assets
# ---------------------------------------------------------------------------

class TestObservationTarget:
    def test_no_target_is_assessed_but_not_persisted(self, tmp_path):
        # Reproduced against the original: `target or technology` persisted the
        # finding with target="OpenSSH" and surface_mapper minted a hostname
        # asset called "openssh".
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        r = vi.map_technology_to_cves({"technology": "OpenSSH", "version": "7.0"}, store=store,
                                      source_results={"records": [_rec("CVE-2021-1")], "source_status": _status(nvd=FOUND)},
                                      kev_entries=[], exploitdb_index={})
        assert len(r["vulnerabilities"]) == 1 and store.all() == [] and r["persisted"] == 0
        assert any("phantom" in n for n in r["notes"])

    def test_no_target_negative_result_is_not_persisted_either(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        r = vi.map_technology_to_cves({"technology": "OpenSSH", "version": "7.0"}, store=store,
                                      source_results={"records": [], "source_status": _status(nvd=EMPTY)},
                                      kev_entries=[], exploitdb_index={})
        assert r["status"] == "not_found" and store.all() == []

    def test_run_level_fallback_target_is_used(self, tmp_path):
        store = vi.PendingAssetsStore(output_dir=str(tmp_path))
        vi.map_technology_to_cves({"technology": "OpenSSH", "version": "7.0"}, store=store,
                                  source_results={"records": [_rec("CVE-2021-1")], "source_status": _status(nvd=FOUND)},
                                  kev_entries=[], exploitdb_index={}, fallback_target="host.example.com")
        assert store.all()[0]["target"] == "host.example.com"

    @pytest.mark.parametrize("raw,expected", [
        ("example.com", "example.com"), ("EXAMPLE.COM.", "example.com"), ("10.0.0.1", "10.0.0.1"),
        ("https://user:pw@example.com:8443/path", "example.com"), ("example.com:443", "example.com"),
        ("[2001:db8::1]:443", "2001:db8::1"), ("2001:db8::1", "2001:db8::1"),
    ])
    def test_valid_targets_normalize(self, raw, expected):
        assert vi._observation_target(raw) == (expected, None)

    @pytest.mark.parametrize("raw", [None, "", "   ", 5, "999.1.1.1", "a b.com", "-bad.com", "x" * 300,
                                     "http://", "foo bar", "a:b:c", "‮example.com"])
    def test_invalid_targets_are_rejected_with_reason(self, raw):
        target, reason = vi._observation_target(raw)
        assert target is None and reason

    def test_normalized_observation_keeps_rejection_reason(self):
        n = vi.normalize_technology_observation({"technology": "nginx", "target": "not a host"})
        assert n["target"] is None and n["target_rejected_reason"] and n["raw_target"] == "not a host"

    def test_technology_and_version_are_hard_bounded_without_markers(self):
        n = vi.normalize_technology_observation({"technology": "A" * 300, "version": "1." * 200})
        assert len(n["technology"]) == vi.MAX_TECHNOLOGY_CHARS and "clipped" not in n["technology"]
        assert len(n["version"]) <= vi.MAX_VERSION_CHARS and "clipped" not in n["version"]


# ---------------------------------------------------------------------------
# run_vuln_intel orchestration
# ---------------------------------------------------------------------------

def _sources_for(mapping):
    def _fake(tech, version, **kw):
        return mapping.get(tech.lower(), {"records": [], "source_status": _status(nvd=EMPTY)})
    return _fake


KEV_OK = {"status": "found", "outcome": "found", "entries": [], "error": None}
EDB_OK = {"status": "not_found", "outcome": "empty_authoritative", "index": {}, "error": None}
EPSS_OK = {"status": "not_found", "outcome": "empty_authoritative", "scores": {}, "error": None}


class TestRunVulnIntelHardening:
    def _run(self, tmp_path, observations, mapping=None, kev=KEV_OK, edb=EDB_OK, epss=EPSS_OK, **kw):
        with mock.patch("reconhound.vuln_intel.query_all_sources", side_effect=_sources_for(mapping or {})) as qa, \
             mock.patch("reconhound.vuln_intel.query_cisa_kev", return_value=kev), \
             mock.patch("reconhound.vuln_intel.fetch_exploitdb_index", return_value=edb), \
             mock.patch("reconhound.vuln_intel.query_epss", return_value=epss) as qe:
            summary = vi.run_vuln_intel(output_dir=str(tmp_path), include_active_recon=False,
                                        technology_observations=observations, use_cache=False, **kw)
        return summary, qa, qe, vi.PendingAssetsStore(output_dir=str(tmp_path)).all()

    def test_one_bad_observation_does_not_kill_the_run(self, tmp_path):
        good = {"records": [_rec("CVE-2021-1")], "source_status": _status(nvd=FOUND)}
        with mock.patch("reconhound.vuln_intel.map_technology_to_cves", side_effect=[RuntimeError("boom"), {"vulnerabilities": [_rec("CVE-2021-1")], "persisted": 1, "skipped_duplicates": 0, "status": "found", "errors": []}]):
            summary, *_ = self._run(tmp_path, [{"technology": "a", "version": "1", "target": "h.example.com"},
                                               {"technology": "b", "version": "1", "target": "h.example.com"}], {"a": good, "b": good})
        assert summary["stats"]["observations"] == 2 and summary["stats"]["vulnerabilities_found"] == 1
        assert any(e["stage"] == "map_technology_to_cves" and "boom" in e["error"] for e in summary["errors"])

    def test_duplicate_observations_and_findings_are_suppressed(self, tmp_path):
        mapping = {"nginx": {"records": [_rec("CVE-2021-1")], "source_status": _status(nvd=FOUND)}}
        obs = [{"technology": "nginx", "version": "1.18.0", "target": "h.example.com"}] * 3 + \
              [{"technology": "NGINX", "version": "1.18.0", "target": "H.EXAMPLE.COM"}]
        summary, qa, _, persisted = self._run(tmp_path, obs, mapping)
        assert summary["stats"]["duplicate_observations"] == 3 and qa.call_count == 1
        assert [r["type"] for r in persisted] == ["vulnerability_intelligence"]

    def test_epss_is_batched_once_over_all_matched_cves(self, tmp_path):
        mapping = {"a": {"records": [_rec("CVE-2021-1"), _rec("CVE-2021-2")], "source_status": _status(nvd=FOUND)},
                   "b": {"records": [_rec("CVE-2021-2"), _rec("CVE-2021-3")], "source_status": _status(nvd=FOUND)}}
        epss = dict(EPSS_OK, status="found", outcome="found",
                    scores={"CVE-2021-1": {"epss": 0.7, "percentile": 0.99, "date": "2026-09-07"}})
        summary, _, qe, persisted = self._run(tmp_path, [{"technology": "a", "version": "1", "target": "h.example.com"},
                                                          {"technology": "b", "version": "1", "target": "h.example.com"}], mapping, epss=epss)
        assert qe.call_count == 1 and sorted(qe.call_args.args[0]) == ["CVE-2021-1", "CVE-2021-2", "CVE-2021-3"]
        by = {r["value"]["cve_id"]: r for r in persisted}
        assert by["CVE-2021-1"]["metadata"]["epss"]["score"] == 0.7 and by["CVE-2021-1"]["metadata"]["epss_score"] == 0.7
        assert by["CVE-2021-3"]["metadata"]["epss"]["checked"] is True and by["CVE-2021-3"]["metadata"]["epss"]["score"] is None
        assert "epss" not in by["CVE-2021-1"]["value"]  # volatile annotation lives in metadata, not identity

    def test_epss_outage_is_unknown_for_every_cve(self, tmp_path):
        mapping = {"a": {"records": [_rec("CVE-2021-1")], "source_status": _status(nvd=FOUND)}}
        epss = {"status": "error", "outcome": "unavailable", "scores": {}, "error": "down"}
        summary, _, _, persisted = self._run(tmp_path, [{"technology": "a", "version": "1", "target": "h.example.com"}], mapping, epss=epss)
        assert persisted[0]["metadata"]["epss"]["checked"] is False and persisted[0]["metadata"]["epss_score"] is None
        assert any(e["stage"] == "epss" for e in summary["errors"]) and summary["epss_status"]["conclusive"] is False

    def test_kev_outage_is_recorded_and_not_negative(self, tmp_path):
        mapping = {"a": {"records": [_rec("CVE-2021-1")], "source_status": _status(nvd=FOUND)}}
        kev = {"status": "error", "outcome": "unavailable", "entries": [], "error": "timeout"}
        summary, _, _, persisted = self._run(tmp_path, [{"technology": "a", "version": "1", "target": "h.example.com"}], mapping, kev=kev)
        md = persisted[0]["metadata"]
        assert md["cisa_kev_checked"] is False and md["cisa_kev_listed"] is False and persisted[0]["value"]["cisa_kev"] is None
        assert any("KEV" in e and "unknown" in e for e in persisted[0]["evidence"])
        assert any(e["stage"] == "cisa_kev" for e in summary["errors"])

    def test_inconclusive_observations_are_counted_and_not_persisted(self, tmp_path):
        mapping = {"a": {"records": [], "source_status": _status(nvd=RATE, github_advisories=EMPTY)}}
        summary, _, _, persisted = self._run(tmp_path, [{"technology": "a", "version": "1", "target": "h.example.com"}], mapping)
        assert summary["stats"]["inconclusive_observations"] == 1 and persisted == []
        assert summary["results"][0]["status"] == "inconclusive"

    def test_invalid_source_configuration_fails_the_run_cleanly(self, tmp_path):
        with mock.patch("reconhound.vuln_intel.query_cisa_kev", return_value=KEV_OK), \
             mock.patch("reconhound.vuln_intel.fetch_exploitdb_index", return_value=EDB_OK):
            summary = vi.run_vuln_intel(output_dir=str(tmp_path), include_active_recon=False, use_cache=False,
                                        technology_observations=[{"technology": "a", "version": "1", "target": "h.example.com"}],
                                        sources=["nope"])
        assert any(e["stage"] == "query_all_sources" and "Unsupported" in e["error"] for e in summary["errors"])
        assert summary["results"] == [] and "finished_at" in summary

    def test_observations_without_target_use_run_target(self, tmp_path):
        mapping = {"a": {"records": [_rec("CVE-2021-1")], "source_status": _status(nvd=FOUND)}}
        summary, _, _, persisted = self._run(tmp_path, [{"technology": "a", "version": "1"}], mapping, target="scan.example.com")
        assert persisted and persisted[0]["target"] == "scan.example.com" and summary["target"] == "scan.example.com"

    def test_observation_set_is_capped(self, tmp_path):
        obs = [{"technology": f"t{i}", "version": "1", "target": "h.example.com"} for i in range(vi.MAX_OBSERVATIONS + 20)]
        summary, qa, _, _ = self._run(tmp_path, obs)
        assert summary["stats"]["observations"] == vi.MAX_OBSERVATIONS and qa.call_count == vi.MAX_OBSERVATIONS
        assert any("capped" in n for n in summary["notes"])

    def test_shared_feed_exceptions_do_not_kill_the_run(self, tmp_path):
        with mock.patch("reconhound.vuln_intel.query_all_sources", side_effect=_sources_for({})), \
             mock.patch("reconhound.vuln_intel.query_cisa_kev", side_effect=AttributeError("bug")), \
             mock.patch("reconhound.vuln_intel.fetch_exploitdb_index", return_value="garbage"), \
             mock.patch("reconhound.vuln_intel.query_epss", return_value=EPSS_OK):
            summary = vi.run_vuln_intel(output_dir=str(tmp_path), include_active_recon=False, use_cache=False,
                                        technology_observations=[{"technology": "a", "version": "1", "target": "h.example.com"}])
        assert summary["stats"]["observations"] == 1
        assert summary["cisa_kev_status"]["conclusive"] is False and summary["exploitdb_status"]["conclusive"] is False
        assert {e["stage"] for e in summary["errors"]} == {"cisa_kev", "exploitdb"}

    def test_banner_derived_identification_is_capped_at_medium(self, tmp_path):
        (tmp_path / "pending_assets.json").write_text(json.dumps([
            {"type": "banner", "target": "10.0.0.9", "confidence": "HIGH", "evidence": [], "value": {"banner": "220 ProFTPD 1.3.5e Server"}},
            {"type": "ssh_fingerprint", "target": "10.0.0.8", "confidence": "LOW", "evidence": [], "value": {"software": "OpenSSH_8.9p1"}},
        ]))
        obs, _ = vi.extract_observations_from_active_recon(vi.PendingAssetsStore(output_dir=str(tmp_path)))
        by = {o["technology"]: o for o in obs}
        assert by["ProFTPD"]["confidence"] == vi.CONFIDENCE_MEDIUM   # HIGH receipt != HIGH identification
        assert by["OpenSSH"]["confidence"] == vi.CONFIDENCE_LOW      # never raised, only capped
        assert any("capped at MEDIUM" in e for e in by["ProFTPD"]["evidence"])

    def test_nvd_default_page_reaches_the_result_cap_in_one_request(self):
        with mock.patch("reconhound.vuln_intel.requests.get",
                        return_value=_fake_response(200, {"totalResults": 0, "vulnerabilities": []})) as g:
            vi.query_nvd("nginx")
        assert g.call_count == 1 and g.call_args.kwargs["params"]["resultsPerPage"] == vi.DEFAULT_NVD_MAX_RESULTS

    def test_active_recon_duplicates_are_collapsed(self, tmp_path):
        rec = {"type": "banner", "target": "10.0.0.9", "confidence": "HIGH", "evidence": [], "value": {"banner": "OpenSSH_8.9p1"}}
        (tmp_path / "pending_assets.json").write_text(json.dumps([rec, dict(rec, value={"ip": "10.0.0.9", "port": 2222, "banner": "SSH-2.0-OpenSSH_8.9p1"})]))
        obs, skipped = vi.extract_observations_from_active_recon(vi.PendingAssetsStore(output_dir=str(tmp_path)))
        assert len(obs) == 1 and skipped == []

    def test_provider_stats_and_cache_directory_are_reported(self, tmp_path):
        with mock.patch("reconhound.vuln_intel.query_all_sources", side_effect=_sources_for({})), \
             mock.patch("reconhound.vuln_intel.query_cisa_kev", return_value=KEV_OK), \
             mock.patch("reconhound.vuln_intel.fetch_exploitdb_index", return_value=EDB_OK), \
             mock.patch("reconhound.vuln_intel.query_epss", return_value=EPSS_OK):
            summary = vi.run_vuln_intel(output_dir=str(tmp_path), include_active_recon=False,
                                        technology_observations=[{"technology": "a", "version": "1", "target": "h.example.com"}])
        assert summary["provider_stats"]["query_cache"]["available"] is True
        assert (tmp_path / vi.CACHE_DIRNAME).is_dir()

    def test_repeated_runs_are_deterministic_modulo_timestamps(self, tmp_path):
        mapping = {"a": {"records": [_rec("CVE-2021-2"), _rec("CVE-2021-1", vm="range_confirmed", q=vi.MATCH_QUALITY_EXACT)],
                         "source_status": _status(nvd=FOUND)}}
        obs = [{"technology": "a", "version": "1.0", "target": "h.example.com", "confidence": "HIGH"}]
        _, _, _, first = self._run(tmp_path, obs, mapping)
        _, _, _, both = self._run(tmp_path, obs, mapping)
        second = both[len(first):]

        def strip(r):
            return json.dumps({"type": r["type"], "target": r["target"], "value": r["value"], "confidence": r["confidence"],
                               "evidence": r["evidence"]}, sort_keys=True)
        assert [strip(r) for r in first] == [strip(r) for r in second]
        assert [r["value"]["cve_id"] for r in first] == ["CVE-2021-2", "CVE-2021-1"]


# ---------------------------------------------------------------------------
# Integration: surface_mapper -> risk_engine -> report_generator
# ---------------------------------------------------------------------------

class TestDownstreamIntegration:
    def _pipeline(self, tmp_path):
        from reconhound import surface_mapper as sm, risk_engine as risk, report_generator as rg

        def nvd(cve, q=vi.MATCH_QUALITY_EXACT, vm="range_confirmed", score=9.8, sev="CRITICAL", summary="remote code execution"):
            return _rec(cve, vm=vm, q=q, summary=summary, cvss_score=score, severity=sev,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", references=[f"https://nvd.nist.gov/vuln/detail/{cve}"])
        mapping = {
            "nginx": {"records": [nvd("CVE-2021-23017"), nvd("CVE-2020-99999", q=vi.MATCH_QUALITY_RELATED, score=5.0, sev="MEDIUM", summary="controller")],
                      "source_status": _status(nvd=FOUND)},
            "openssh": {"records": [nvd("CVE-2021-41617", score=7.0, sev="HIGH", summary="privilege escalation")], "source_status": _status(nvd=FOUND)},
            "apache": {"records": [], "source_status": _status(nvd=RATE, github_advisories=EMPTY)},
        }
        kev = dict(KEV_OK, entries=[{"cve_id": "CVE-2021-41617", "date_added": "2022-01-01", "vulnerability_name": "OpenSSH PE"}])
        edb = dict(EDB_OK, status="found", outcome="found", index={"CVE-2021-23017": [{"edb_id": "50973", "title": "t", "verified": True}]})
        epss = dict(EPSS_OK, status="found", outcome="found", scores={
            "CVE-2021-23017": {"epss": 0.12, "percentile": 0.95, "date": "2026-09-07"},
            "CVE-2021-41617": {"epss": 0.0, "percentile": 0.01, "date": "2026-09-07"}})
        obs = [
            {"technology": "nginx", "version": "1.18.0-6.1+deb11u3", "target": "web.example.com", "confidence": "HIGH"},
            {"technology": "OpenSSH", "version": "8.2p1", "target": "10.0.0.5", "confidence": "LOW"},
            {"technology": "Apache", "version": "2.4.41", "target": "www.example.com", "confidence": "MEDIUM"},
            {"technology": "Obscure", "version": "1.0", "target": "www.example.com"},
            {"technology": "nginx", "version": "1.18.0-6.1+deb11u3", "target": "web.example.com", "confidence": "HIGH"},
            {"technology": "Phantom", "version": "1.0"},
        ]

        def run():
            with mock.patch("reconhound.vuln_intel.query_all_sources", side_effect=_sources_for(mapping)), \
                 mock.patch("reconhound.vuln_intel.query_cisa_kev", return_value=kev), \
                 mock.patch("reconhound.vuln_intel.fetch_exploitdb_index", return_value=edb), \
                 mock.patch("reconhound.vuln_intel.query_epss", return_value=epss):
                return vi.run_vuln_intel(output_dir=str(tmp_path), include_active_recon=False,
                                         technology_observations=obs, use_cache=False)
        return sm, risk, rg, run

    def test_full_pipeline_preserves_semantics_and_mints_no_phantoms(self, tmp_path):
        sm, risk, rg, run = self._pipeline(tmp_path)
        summary = run()
        assert summary["errors"] == [] and summary["stats"]["inconclusive_observations"] == 1
        records = vi.PendingAssetsStore(output_dir=str(tmp_path)).all()
        assert [r["type"] for r in records].count("vulnerability_intelligence") == 3
        assert [r["type"] for r in records].count("vuln_intel_checked_no_match") == 1   # Obscure only
        assert not any(r["target"] in ("Phantom", "Apache", "nginx") for r in records)

        mapper = sm.SurfaceMapper(target="example.com", output_dir=str(tmp_path))
        ingest = mapper.ingest_pending_assets_file(str(tmp_path / "pending_assets.json"))
        assert ingest["errors"] == 0
        hosts = sorted(a["value"] for a in mapper.state["assets"].values() if a["asset_type"] == sm.ASSET_HOSTNAME)
        assert hosts == ["10.0.0.5", "web.example.com", "www.example.com"]
        assert len(mapper.state["negative_results"]) == 1
        mapper.save()

        assessment = risk.run_risk_engine(graph=mapper, output_dir=str(tmp_path), persist=True)
        assert not assessment.get("errors")
        signals = {s["cve_id"]: s for s in assessment["signals"] if s.get("kind") == risk.KIND_VULN_INTEL}
        assert set(signals) == {"CVE-2021-23017", "CVE-2021-41617", "CVE-2020-99999"}
        # LOW technology confidence survives a HIGH-quality mapping and a KEV listing
        assert signals["CVE-2021-41617"]["confidence"] == "LOW"
        assert any(f["factor"] == "known_exploited_vulnerability" for f in signals["CVE-2021-41617"]["factors"])
        # backport-uncertain range match reaches the engine at MEDIUM with the public-exploit factor only
        assert signals["CVE-2021-23017"]["confidence"] == "MEDIUM" and signals["CVE-2021-23017"]["cvss_score"] == 9.8
        factors = {f["factor"] for f in signals["CVE-2021-23017"]["factors"]}
        assert "public_exploit_exists" in factors and "known_exploited_vulnerability" not in factors
        assert signals["CVE-2020-99999"]["applicability"] == "keyword_match_version_unconfirmed"
        assert signals["CVE-2020-99999"]["confidence"] == "LOW"

        report = rg.generate_report(graph=mapper, assessment=assessment, output_dir=str(tmp_path), formats=("json", "html"), persist=True)
        assert not report.get("errors")
        doc = json.load(open(report["output_paths"]["json"]))
        section = doc["vulnerability_intelligence"]
        assert section["count"] == 3 and "did not attempt to verify" in section["statement"]
        entries = {e["cve_id"]: e for e in section["entries"]}
        assert entries["CVE-2021-23017"]["applicability"] == "version_range_confirmed"
        assert entries["CVE-2021-23017"]["confidence"] == "MEDIUM"
        assert entries["CVE-2021-23017"]["detail"]["backport_uncertainty"] is True
        html = open(report["output_paths"]["html"]).read()
        assert "MAY be affected" in html and "\x1b" not in html
        for banned in ("confirmed exploitable", "confirmed vulnerable", "successfully exploited"):
            assert banned not in html.lower()

    def test_repeated_pipeline_does_not_duplicate_finding_assets_or_inflate_confidence(self, tmp_path):
        sm, risk, rg, run = self._pipeline(tmp_path)
        run(); run()
        records = vi.PendingAssetsStore(output_dir=str(tmp_path)).all()
        mapper = sm.SurfaceMapper(target="example.com", output_dir=str(tmp_path))
        mapper.ingest_pending_assets_file(str(tmp_path / "pending_assets.json"))
        finding_assets = [a for a in mapper.state["assets"].values() if a["asset_type"] == sm.ASSET_FINDING]
        assert len(finding_assets) == 3           # 6 observations merged into the same 3 findings
        confidences = {}
        for r in records:
            if r["type"] == "vulnerability_intelligence":
                confidences.setdefault(r["value"]["cve_id"], set()).add(r["confidence"])
        assert all(len(v) == 1 for v in confidences.values())
        assessment = risk.run_risk_engine(graph=mapper, output_dir=str(tmp_path), persist=False)
        signals = [s for s in assessment["signals"] if s.get("kind") == risk.KIND_VULN_INTEL]
        assert len(signals) == 3

    def test_orchestrator_style_call_signature_still_works(self, tmp_path):
        # core/orchestrator.py calls exactly this: run_vuln_intel(output_dir=, technology_observations=, timeout=)
        with mock.patch("reconhound.vuln_intel.query_all_sources", side_effect=_sources_for({})), \
             mock.patch("reconhound.vuln_intel.query_cisa_kev", return_value=KEV_OK), \
             mock.patch("reconhound.vuln_intel.fetch_exploitdb_index", return_value=EDB_OK), \
             mock.patch("reconhound.vuln_intel.query_epss", return_value=EPSS_OK):
            summary = vi.run_vuln_intel(output_dir=str(tmp_path), technology_observations=None, timeout=5.0)
        assert summary["module"] == "vuln_intel.py" and isinstance(summary["errors"], list) and "stats" in summary


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
