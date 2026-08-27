"""
Tests for reconhound/wayback_intel.py (ReconHound Module 5, per
context.md's catalog item 5; built under a temporary, user-approved
build-order deviation ahead of surface_mapper.py — see the module
docstring for details).

Run with:  ./.venv/bin/python -m pytest tests/test_wayback_intel.py -v

All tests mock the `requests.get` boundary so the suite is deterministic
and offline-safe; no external network access (including to
web.archive.org) is required or performed anywhere in this file.
"""

import json
import os
import sys
from unittest import mock

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import wayback_intel as wb


SAFE_TARGET = "example.com"

CDX_HEADER = ["timestamp", "original", "statuscode", "mimetype", "digest"]


def _fake_cdx_response(status_code=200, text="", headers=None):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = dict(headers or {})
    return resp


def _cdx_body(rows):
    return json.dumps([CDX_HEADER] + rows)


SAMPLE_ROWS = [
    ["20180101000000", "http://example.com/old-page", "200", "text/html", "AAA111"],
    ["20200601000000", "http://example.com/old-page", "200", "text/html", "AAA111"],
    ["20190101000000", "http://example.com/api/v1/users?id=5&debug=true", "200", "application/json", "BBB222"],
    ["20210101000000", "http://example.com/assets/logo.png", "200", "image/png", "CCC333"],
    ["20150101000000", "http://example.com/removed-secret-page", "404", "text/html", "DDD444"],
]


# ---------------------------------------------------------------------------
# validate_target / is_in_scope
# ---------------------------------------------------------------------------

class TestValidateTarget:
    def test_accepts_plain_domain(self):
        assert wb.validate_target("example.com") == "example.com"

    def test_normalizes_case_and_trailing_dot(self):
        assert wb.validate_target("EXAMPLE.com.") == "example.com"

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(wb.ScopeError):
            wb.validate_target(bad)

    def test_rejects_url(self):
        with pytest.raises(wb.ScopeError):
            wb.validate_target("https://example.com/path")

    def test_rejects_ip_literal(self):
        with pytest.raises(wb.ScopeError):
            wb.validate_target("93.184.216.34")

    def test_rejects_wildcard(self):
        with pytest.raises(wb.ScopeError):
            wb.validate_target("*.example.com")

    def test_rejects_malformed_domain(self):
        with pytest.raises(wb.ScopeError):
            wb.validate_target("-bad-.com")


class TestIsInScope:
    def test_exact_match(self):
        assert wb.is_in_scope("example.com", "example.com") is True

    def test_subdomain_match(self):
        assert wb.is_in_scope("api.example.com", "example.com") is True

    def test_out_of_scope(self):
        assert wb.is_in_scope("evil.com", "example.com") is False

    def test_empty_hostname(self):
        assert wb.is_in_scope("", "example.com") is False

    def test_none_hostname(self):
        assert wb.is_in_scope(None, "example.com") is False


# ---------------------------------------------------------------------------
# make_finding
# ---------------------------------------------------------------------------

class TestMakeFinding:
    def test_shape(self):
        finding = wb.make_finding("historical_path", "example.com", {"a": 1}, ["evidence"], wb.CONFIDENCE_LOW)
        assert finding["type"] == "historical_path"
        assert finding["target"] == "example.com"
        assert finding["value"] == {"a": 1}
        assert finding["evidence"] == ["evidence"]
        assert finding["confidence"] == wb.CONFIDENCE_LOW
        assert finding["source"] == wb.MODULE_NAME
        assert "timestamp" in finding
        assert finding["metadata"] == {}

    def test_json_safe(self):
        finding = wb.make_finding("historical_path", "example.com", {"a": [1, 2]}, ["e"], wb.CONFIDENCE_HIGH)
        json.dumps(finding)  # must not raise


# ---------------------------------------------------------------------------
# PendingAssetsStore / _safe_store_add
# ---------------------------------------------------------------------------

class TestPendingAssetsStore:
    def test_creates_output_dir_and_file(self, tmp_path):
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        finding = wb.make_finding("historical_path", SAFE_TARGET, {}, ["e"], wb.CONFIDENCE_LOW)
        store.add(finding)
        assert os.path.exists(store.path)
        with open(store.path) as f:
            data = json.load(f)
        assert data == [finding]

    def test_appends_without_losing_previous_entries(self, tmp_path):
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        f1 = wb.make_finding("historical_path", SAFE_TARGET, {"n": 1}, ["e"], wb.CONFIDENCE_LOW)
        f2 = wb.make_finding("historical_parameter", SAFE_TARGET, {"n": 2}, ["e"], wb.CONFIDENCE_LOW)
        store.add(f1)
        store.add(f2)
        assert store.all() == [f1, f2]

    def test_preserves_existing_data_from_other_modules(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{
            "type": "endpoint_discovered", "target": "other.com", "value": {"url": "http://other.com/x"},
            "evidence": ["prior run"], "confidence": "HIGH", "source": "endpoint_discovery.py",
            "timestamp": "t", "metadata": {},
        }]
        pending.write_text(json.dumps(pre_existing))

        store = wb.PendingAssetsStore(output_dir=str(output_dir))
        new_finding = wb.make_finding("historical_path", SAFE_TARGET, {}, ["new"], wb.CONFIDENCE_LOW)
        store.add(new_finding)

        assert store.all() == pre_existing + [new_finding]

    def test_corrupt_existing_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not valid json")

        store = wb.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(wb.PersistenceError):
            store.add(wb.make_finding("historical_path", SAFE_TARGET, {}, ["e"], wb.CONFIDENCE_LOW))

    def test_write_is_atomic_no_temp_file_left_behind(self, tmp_path):
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        store.add(wb.make_finding("historical_path", SAFE_TARGET, {}, ["e"], wb.CONFIDENCE_LOW))
        leftovers = [p for p in os.listdir(store.output_dir) if p.startswith(".pending_assets_")]
        assert leftovers == []


class TestSafeStoreAdd:
    def test_noop_without_store(self):
        assert wb._safe_store_add(None, wb.make_finding("x", SAFE_TARGET, {}, [], wb.CONFIDENCE_LOW)) is None

    def test_recovers_from_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = wb.PendingAssetsStore(output_dir=str(output_dir))
        err = wb._safe_store_add(store, wb.make_finding("historical_path", SAFE_TARGET, {}, ["e"], wb.CONFIDENCE_LOW))
        assert err is not None
        assert "corrupt" in err


# ---------------------------------------------------------------------------
# build_cdx_query_url
# ---------------------------------------------------------------------------

class TestBuildCdxQueryUrl:
    def test_default_query_shape(self):
        url = wb.build_cdx_query_url("example.com")
        assert url.startswith(wb.DEFAULT_CDX_BASE_URL + "?")
        assert "url=example.com" in url
        assert "matchType=domain" in url
        assert "collapse=urlkey" in url
        assert "output=json" in url

    def test_omits_collapse_when_none(self):
        url = wb.build_cdx_query_url("example.com", collapse=None)
        assert "collapse=" not in url

    def test_includes_date_range_and_limit(self):
        url = wb.build_cdx_query_url("example.com", from_date="20200101", to_date="20211231", limit=100)
        assert "from=20200101" in url
        assert "to=20211231" in url
        assert "limit=100" in url

    def test_rejects_empty_base_url(self):
        with pytest.raises(wb.ConfigurationError):
            wb.build_cdx_query_url("example.com", base_url="")

    def test_rejects_non_http_base_url(self):
        with pytest.raises(wb.ConfigurationError):
            wb.build_cdx_query_url("example.com", base_url="ftp://archive.org/cdx")

    def test_rejects_invalid_match_type(self):
        with pytest.raises(wb.ConfigurationError):
            wb.build_cdx_query_url("example.com", match_type="bogus")

    def test_rejects_invalid_limit(self):
        with pytest.raises(wb.ConfigurationError):
            wb.build_cdx_query_url("example.com", limit="not-a-number")


# ---------------------------------------------------------------------------
# normalize_snapshot
# ---------------------------------------------------------------------------

class TestNormalizeSnapshot:
    def test_normal_row(self):
        row = dict(zip(CDX_HEADER, SAMPLE_ROWS[0]))
        snap = wb.normalize_snapshot(row)
        assert snap["timestamp"] == "20180101000000"
        assert snap["observed_at"] == "2018-01-01T00:00:00+00:00"
        assert snap["original_url"] == "http://example.com/old-page"
        assert snap["status_code"] == 200
        assert snap["mime_type"] == "text/html"
        assert snap["digest"] == "AAA111"
        assert snap["archive_url"] == "https://web.archive.org/web/20180101000000/http://example.com/old-page"

    def test_missing_timestamp_raises(self):
        with pytest.raises(ValueError):
            wb.normalize_snapshot({"original": "http://example.com/x"})

    def test_missing_original_raises(self):
        with pytest.raises(ValueError):
            wb.normalize_snapshot({"timestamp": "20180101000000"})

    def test_unparseable_timestamp_falls_back_gracefully(self):
        snap = wb.normalize_snapshot({"timestamp": "not-a-timestamp", "original": "http://example.com/x"})
        assert snap["observed_at"] is None
        assert snap["timestamp"] == "not-a-timestamp"

    def test_dash_status_code_becomes_none(self):
        snap = wb.normalize_snapshot({"timestamp": "20180101000000", "original": "http://example.com/x", "statuscode": "-"})
        assert snap["status_code"] is None
        assert snap["status_code_raw"] == "-"

    def test_non_numeric_status_code_becomes_none(self):
        snap = wb.normalize_snapshot({"timestamp": "20180101000000", "original": "http://example.com/x", "statuscode": "abc"})
        assert snap["status_code"] is None


# ---------------------------------------------------------------------------
# fetch_cdx_snapshots (mocked requests.get)
# ---------------------------------------------------------------------------

class TestFetchCdxSnapshots:
    def test_successful_query(self):
        resp = _fake_cdx_response(200, text=_cdx_body(SAMPLE_ROWS))
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "found"
        assert result["raw_row_count"] == len(SAMPLE_ROWS)
        assert len(result["snapshots"]) == len(SAMPLE_ROWS)
        assert result["row_errors"] == []
        assert result["query_url"] is not None

    def test_empty_body_is_not_found(self):
        resp = _fake_cdx_response(200, text="")
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "not_found"
        assert result["snapshots"] == []

    def test_header_only_is_not_found(self):
        resp = _fake_cdx_response(200, text=json.dumps([CDX_HEADER]))
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "not_found"

    def test_malformed_json_is_error(self):
        resp = _fake_cdx_response(200, text="{not valid json")
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "error"
        assert "malformed JSON" in result["error"]

    def test_non_list_root_is_error(self):
        resp = _fake_cdx_response(200, text=json.dumps({"unexpected": "shape"}))
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "error"
        assert "not a JSON array" in result["error"]

    def test_invalid_header_row_is_error(self):
        resp = _fake_cdx_response(200, text=json.dumps([[1, 2, 3], ["a", "b", "c"]]))
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "error"
        assert "header row" in result["error"]

    def test_malformed_row_shape_is_collected_not_fatal(self):
        rows = [SAMPLE_ROWS[0], ["only", "two"]]
        resp = _fake_cdx_response(200, text=_cdx_body(rows))
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "found"
        assert len(result["snapshots"]) == 1
        assert len(result["row_errors"]) == 1

    def test_all_rows_malformed_is_not_found_but_reports_row_errors(self):
        resp = _fake_cdx_response(200, text=json.dumps([CDX_HEADER, ["only", "two"]]))
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "not_found"
        assert len(result["row_errors"]) == 1

    def test_rate_limited(self):
        resp = _fake_cdx_response(429, text="")
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "rate_limited"

    def test_server_error(self):
        resp = _fake_cdx_response(503, text="")
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "error"
        assert "503" in result["error"]

    def test_unexpected_status_code(self):
        resp = _fake_cdx_response(403, text="")
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "error"
        assert "403" in result["error"]

    def test_timeout(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout("timed out")):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_connection_error(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "error"
        assert "connection error" in result["error"]

    def test_generic_request_exception(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.RequestException("boom")):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert result["status"] == "error"

    def test_invalid_target_raises_scope_error(self):
        with pytest.raises(wb.ScopeError):
            wb.fetch_cdx_snapshots("https://example.com/")

    def test_invalid_configuration_reported_not_raised(self):
        result = wb.fetch_cdx_snapshots(SAFE_TARGET, base_url="")
        assert result["status"] == "error"

    def test_truncation_flagged(self):
        rows = SAMPLE_ROWS[:3]
        resp = _fake_cdx_response(200, text=_cdx_body(rows))
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET, limit=3)
        assert result["truncated"] is True

    def test_no_truncation_when_under_limit(self):
        rows = SAMPLE_ROWS[:3]
        resp = _fake_cdx_response(200, text=_cdx_body(rows))
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET, limit=1000)
        assert result["truncated"] is False


# ---------------------------------------------------------------------------
# group_historical_urls / classify_historical_url / extract_historical_parameters
# ---------------------------------------------------------------------------

class TestGroupHistoricalUrls:
    def _snapshots(self):
        return [wb.normalize_snapshot(dict(zip(CDX_HEADER, r))) for r in SAMPLE_ROWS]

    def test_groups_by_normalized_url(self):
        grouped = wb.group_historical_urls(self._snapshots(), SAFE_TARGET)
        urls = {g["url"] for g in grouped}
        assert "http://example.com/old-page" in urls
        old_page = next(g for g in grouped if g["url"] == "http://example.com/old-page")
        assert old_page["capture_count"] == 2
        assert old_page["first_observed_at"] == "2018-01-01T00:00:00+00:00"
        assert old_page["last_observed_at"] == "2020-06-01T00:00:00+00:00"
        assert old_page["status_codes_seen"] == [200]

    def test_marks_in_scope(self):
        grouped = wb.group_historical_urls(self._snapshots(), SAFE_TARGET)
        assert all(g["in_scope"] for g in grouped)

    def test_marks_out_of_scope(self):
        snaps = [wb.normalize_snapshot({"timestamp": "20180101000000", "original": "http://evil.com/x", "statuscode": "200"})]
        grouped = wb.group_historical_urls(snaps, SAFE_TARGET)
        assert grouped[0]["in_scope"] is False

    def test_historically_observed_flag_always_true(self):
        grouped = wb.group_historical_urls(self._snapshots(), SAFE_TARGET)
        assert all(g["historically_observed"] is True for g in grouped)

    def test_empty_input(self):
        assert wb.group_historical_urls([], SAFE_TARGET) == []

    def test_json_safe_output(self):
        grouped = wb.group_historical_urls(self._snapshots(), SAFE_TARGET)
        json.dumps(grouped)  # must not raise (sets must have been converted to lists)


class TestClassifyHistoricalUrl:
    def test_api_path_is_endpoint(self):
        rec = {"path": "/api/v1/users", "url": "http://example.com/api/v1/users?id=5"}
        result = wb.classify_historical_url(rec)
        assert result["discovery_type"] == "historical_endpoint"
        assert result["is_endpoint_like"] is True
        assert result["has_query_parameters"] is True

    def test_static_asset(self):
        rec = {"path": "/assets/logo.png", "url": "http://example.com/assets/logo.png"}
        result = wb.classify_historical_url(rec)
        assert result["discovery_type"] == "historical_static_asset"
        assert result["is_static_asset"] is True

    def test_plain_path(self):
        rec = {"path": "/old-page", "url": "http://example.com/old-page"}
        result = wb.classify_historical_url(rec)
        assert result["discovery_type"] == "historical_path"
        assert result["is_endpoint_like"] is False
        assert result["is_static_asset"] is False

    def test_json_extension_is_endpoint(self):
        rec = {"path": "/data/export.json", "url": "http://example.com/data/export.json"}
        result = wb.classify_historical_url(rec)
        assert result["discovery_type"] == "historical_endpoint"


class TestExtractHistoricalParameters:
    def test_extracts_query_parameters(self):
        rec = {"url": "http://example.com/api/v1/users?id=5&debug=true"}
        params = wb.extract_historical_parameters(rec)
        names = {p["name"] for p in params}
        assert names == {"id", "debug"}
        assert all(p["location"] == "query" and p["method"] == "GET" for p in params)

    def test_no_query_returns_empty(self):
        assert wb.extract_historical_parameters({"url": "http://example.com/old-page"}) == []

    def test_deduplicates_repeated_names(self):
        rec = {"url": "http://example.com/x?a=1&a=2"}
        params = wb.extract_historical_parameters(rec)
        assert len(params) == 1


# ---------------------------------------------------------------------------
# load_current_surface / correlate_against_current_surface
# ---------------------------------------------------------------------------

class TestLoadCurrentSurface:
    def _seed_store(self, tmp_path):
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        store.add({
            "type": "endpoint_discovered", "target": SAFE_TARGET,
            "value": {"url": "http://example.com/old-page"},
            "evidence": [], "confidence": "HIGH", "source": "endpoint_discovery.py",
            "timestamp": "t", "metadata": {},
        })
        store.add({
            "type": "sitemap_xml_discovered", "target": SAFE_TARGET,
            "value": {"url": "http://example.com/sitemap.xml", "urls": ["http://example.com/api/v1/users"]},
            "evidence": [], "confidence": "HIGH", "source": "exposure_scan.py",
            "timestamp": "t", "metadata": {},
        })
        store.add({
            "type": "dns_record", "target": SAFE_TARGET,  # not a current-surface type; must be ignored
            "value": {"records": ["1.2.3.4"]},
            "evidence": [], "confidence": "HIGH", "source": "passive_recon.py",
            "timestamp": "t", "metadata": {},
        })
        return store

    def test_reads_current_surface_finding_types(self, tmp_path):
        store = self._seed_store(tmp_path)
        surface = wb.load_current_surface(store=store)
        assert wb._normalize_url("http://example.com/old-page") in surface["normalized_urls"]
        assert wb._normalize_url("http://example.com/api/v1/users") in surface["normalized_urls"]
        assert "/old-page" in surface["paths"]

    def test_ignores_unrelated_finding_types(self, tmp_path):
        store = self._seed_store(tmp_path)
        surface = wb.load_current_surface(store=store)
        assert wb._normalize_url("http://1.2.3.4/") not in surface["normalized_urls"]

    def test_no_store_returns_empty(self):
        surface = wb.load_current_surface(store=None)
        assert surface == {"normalized_urls": set(), "paths": set()}

    def test_extra_urls_merged_in(self):
        surface = wb.load_current_surface(store=None, extra_urls=["http://example.com/manual"])
        assert wb._normalize_url("http://example.com/manual") in surface["normalized_urls"]

    def test_corrupt_store_does_not_raise(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = wb.PendingAssetsStore(output_dir=str(output_dir))
        surface = wb.load_current_surface(store=store)
        assert surface == {"normalized_urls": set(), "paths": set()}


class TestCorrelateAgainstCurrentSurface:
    def _classified(self, url, path, status_codes):
        rec = {"url": url, "normalized_url": wb._normalize_url(url), "path": path,
               "status_codes_seen": status_codes, "is_static_asset": False}
        return wb.classify_historical_url(rec)

    def test_currently_known(self):
        rec = self._classified("http://example.com/old-page", "/old-page", [200])
        surface = {"normalized_urls": {wb._normalize_url("http://example.com/old-page")}, "paths": {"/old-page"}}
        [enriched] = wb.correlate_against_current_surface([rec], surface)
        assert enriched["relationship_to_current_surface"] == wb.STATE_CURRENTLY_KNOWN
        assert enriched["confidence"] == wb.CONFIDENCE_HIGH

    def test_historically_removed_potentially_relevant(self):
        rec = self._classified("http://example.com/removed-secret-page", "/removed-secret-page", [200])
        surface = {"normalized_urls": set(), "paths": set()}
        [enriched] = wb.correlate_against_current_surface([rec], surface)
        assert enriched["relationship_to_current_surface"] == wb.STATE_POTENTIALLY_RELEVANT

    def test_historically_removed_low_relevance(self):
        rec = self._classified("http://example.com/dead-page", "/dead-page", [404])
        surface = {"normalized_urls": set(), "paths": set()}
        [enriched] = wb.correlate_against_current_surface([rec], surface)
        assert enriched["relationship_to_current_surface"] == wb.STATE_HISTORICALLY_REMOVED

    def test_never_claims_current_accessibility(self):
        rec = self._classified("http://example.com/old-page", "/old-page", [200])
        surface = {"normalized_urls": {wb._normalize_url("http://example.com/old-page")}, "paths": {"/old-page"}}
        [enriched] = wb.correlate_against_current_surface([rec], surface)
        assert enriched["current_accessibility"] == wb.ACCESSIBILITY_UNVERIFIED
        assert "note" in enriched["current_accessibility_note"] or enriched["current_accessibility_note"]


# ---------------------------------------------------------------------------
# build_historical_data_export (endpoint_discovery.py compatibility)
# ---------------------------------------------------------------------------

class TestBuildHistoricalDataExport:
    def test_shape_matches_endpoint_discovery_expectations(self):
        rec = {
            "url": "http://example.com/api/v1/users?id=5", "capture_count": 2,
            "first_observed_at": "2019-01-01T00:00:00+00:00", "last_observed_at": "2019-06-01T00:00:00+00:00",
            "status_codes_seen": [200],
        }
        [item] = wb.build_historical_data_export([rec])
        assert item["url"] == rec["url"]
        assert item["source"] == wb.MODULE_NAME
        assert item["observed_at"] == rec["last_observed_at"]
        assert isinstance(item["parameters"], list)
        assert item["parameters"][0]["name"] == "id"
        assert isinstance(item["evidence"], list) and item["evidence"]

    def test_json_safe(self):
        rec = {
            "url": "http://example.com/old-page", "capture_count": 1,
            "first_observed_at": "t1", "last_observed_at": "t1", "status_codes_seen": [200],
        }
        json.dumps(wb.build_historical_data_export([rec]))


# ---------------------------------------------------------------------------
# persist_historical_findings
# ---------------------------------------------------------------------------

class TestPersistHistoricalFindings:
    def test_persists_endpoint_and_parameter_findings(self, tmp_path):
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        rec = {
            "url": "http://example.com/api/v1/users?id=5", "path": "/api/v1/users",
            "discovery_type": "historical_endpoint", "confidence": wb.CONFIDENCE_LOW,
            "relationship_to_current_surface": wb.STATE_HISTORICALLY_REMOVED,
            "current_accessibility": wb.ACCESSIBILITY_UNVERIFIED,
            "capture_count": 1, "first_observed_at": "t1", "last_observed_at": "t1",
            "status_codes_seen": [200], "in_scope": True,
        }
        errors = wb.persist_historical_findings([rec], SAFE_TARGET, store)
        assert errors == []
        records = store.all()
        types = [r["type"] for r in records]
        assert "historical_endpoint" in types
        assert "historical_parameter" in types

    def test_no_store_is_noop(self):
        rec = {
            "url": "http://example.com/x", "path": "/x", "discovery_type": "historical_path",
            "confidence": wb.CONFIDENCE_LOW, "relationship_to_current_surface": wb.STATE_HISTORICALLY_REMOVED,
            "current_accessibility": wb.ACCESSIBILITY_UNVERIFIED, "capture_count": 1,
            "first_observed_at": "t", "last_observed_at": "t", "status_codes_seen": [], "in_scope": True,
        }
        assert wb.persist_historical_findings([rec], SAFE_TARGET, None) == []

    def test_persistence_failure_is_collected_not_raised(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = wb.PendingAssetsStore(output_dir=str(output_dir))
        rec = {
            "url": "http://example.com/x", "path": "/x", "discovery_type": "historical_path",
            "confidence": wb.CONFIDENCE_LOW, "relationship_to_current_surface": wb.STATE_HISTORICALLY_REMOVED,
            "current_accessibility": wb.ACCESSIBILITY_UNVERIFIED, "capture_count": 1,
            "first_observed_at": "t", "last_observed_at": "t", "status_codes_seen": [], "in_scope": True,
        }
        errors = wb.persist_historical_findings([rec], SAFE_TARGET, store)
        assert len(errors) >= 1


# ---------------------------------------------------------------------------
# run_wayback_intel (full orchestration, mocked requests.get)
# ---------------------------------------------------------------------------

class TestRunWaybackIntel:
    def test_full_run_persists_and_summarizes(self, tmp_path):
        resp = _fake_cdx_response(200, text=_cdx_body(SAMPLE_ROWS))
        output_dir = str(tmp_path / "output")
        with mock.patch("requests.get", return_value=resp):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=output_dir)

        assert summary["target"] == SAFE_TARGET
        assert summary["module"] == wb.MODULE_NAME
        assert summary["stats"]["unique_urls"] == 4  # old-page collapses 2 captures into 1 URL
        assert len(summary["historical_data"]) == 4
        assert summary["errors"] == []

        store = wb.PendingAssetsStore(output_dir=output_dir)
        persisted_types = {r["type"] for r in store.all()}
        assert "historical_endpoint" in persisted_types
        assert "historical_static_asset" in persisted_types
        assert "historical_path" in persisted_types
        assert "historical_parameter" in persisted_types

    def test_preserves_existing_pending_assets(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pre_existing = [{
            "type": "endpoint_discovered", "target": SAFE_TARGET, "value": {"url": "http://example.com/current"},
            "evidence": [], "confidence": "HIGH", "source": "endpoint_discovery.py",
            "timestamp": "t", "metadata": {},
        }]
        (output_dir / "pending_assets.json").write_text(json.dumps(pre_existing))

        resp = _fake_cdx_response(200, text=_cdx_body(SAMPLE_ROWS))
        with mock.patch("requests.get", return_value=resp):
            wb.run_wayback_intel(SAFE_TARGET, output_dir=str(output_dir))

        store = wb.PendingAssetsStore(output_dir=str(output_dir))
        all_records = store.all()
        assert pre_existing[0] in all_records
        assert len(all_records) > len(pre_existing)

    def test_correlates_against_pre_existing_current_surface(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pre_existing = [{
            "type": "endpoint_discovered", "target": SAFE_TARGET, "value": {"url": "http://example.com/old-page"},
            "evidence": [], "confidence": "HIGH", "source": "endpoint_discovery.py",
            "timestamp": "t", "metadata": {},
        }]
        (output_dir / "pending_assets.json").write_text(json.dumps(pre_existing))

        resp = _fake_cdx_response(200, text=_cdx_body(SAMPLE_ROWS))
        with mock.patch("requests.get", return_value=resp):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(output_dir))

        old_page = next(r for r in summary["historical_urls"] if r["url"] == "http://example.com/old-page")
        assert old_page["relationship_to_current_surface"] == wb.STATE_CURRENTLY_KNOWN

    def test_no_snapshots_found(self, tmp_path):
        resp = _fake_cdx_response(200, text="")
        with mock.patch("requests.get", return_value=resp):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert summary["historical_urls"] == []
        assert summary["historical_data"] == []
        assert summary["stats"]["unique_urls"] == 0

    def test_network_error_reported_not_raised(self, tmp_path):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("down")):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert summary["cdx_query"]["status"] == "error"
        assert summary["errors"]

    def test_rate_limited_reported(self, tmp_path):
        resp = _fake_cdx_response(429, text="")
        with mock.patch("requests.get", return_value=resp):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert summary["cdx_query"]["status"] == "rate_limited"
        assert summary["errors"]

    def test_invalid_target_raises_scope_error(self, tmp_path):
        with pytest.raises(wb.ScopeError):
            wb.run_wayback_intel("not a domain!", output_dir=str(tmp_path / "output"))

    def test_result_is_json_serializable(self, tmp_path):
        resp = _fake_cdx_response(200, text=_cdx_body(SAMPLE_ROWS))
        with mock.patch("requests.get", return_value=resp):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"))
        json.dumps(summary)  # must not raise

    def test_current_urls_override_used_when_no_store_data(self, tmp_path):
        resp = _fake_cdx_response(200, text=_cdx_body(SAMPLE_ROWS))
        with mock.patch("requests.get", return_value=resp):
            summary = wb.run_wayback_intel(
                SAFE_TARGET, output_dir=str(tmp_path / "output"),
                current_urls=["http://example.com/old-page"],
            )
        old_page = next(r for r in summary["historical_urls"] if r["url"] == "http://example.com/old-page")
        assert old_page["relationship_to_current_surface"] == wb.STATE_CURRENTLY_KNOWN
