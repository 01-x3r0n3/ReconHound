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
            {"technology": "SomeVeryObscureThing", "version": "1.0"},
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
            {"technology": "OpenSSH", "version": "7.0"},
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

    @mock.patch("reconhound.vuln_intel.fetch_exploitdb_index")
    @mock.patch("reconhound.vuln_intel.query_cisa_kev")
    @mock.patch("reconhound.vuln_intel.query_all_sources")
    def test_end_to_end_with_caller_supplied_observation(self, mock_query_all, mock_kev, mock_exploitdb, tmp_path):
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


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
