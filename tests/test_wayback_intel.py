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
import urllib.parse
from unittest import mock

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import wayback_intel as wb


SAFE_TARGET = "example.com"

CDX_HEADER = ["timestamp", "original", "statuscode", "mimetype", "digest"]


class _FakeResponse:
    """
    A minimal stand-in for requests.Response.

    Deliberately a real class rather than a MagicMock: fetch_cdx_snapshots
    reads the body through iter_content() so the response size is bounded
    before it is materialised, and a MagicMock silently satisfies that call
    with a non-iterable mock instead of failing loudly.
    """

    def __init__(self, status_code=200, text="", headers=None, url=None,
                  encoding="utf-8", chunks=None, iter_error=None,
                  supports_streaming=True):
        self.status_code = status_code
        self.text = text
        self.headers = dict(headers or {})
        self.url = url or "https://web.archive.org/cdx/search/cdx"
        self.encoding = encoding
        self.closed = False
        self._chunks = chunks
        self._iter_error = iter_error
        if not supports_streaming:
            # Exercise the non-streaming fallback path in _read_bounded_body:
            # a non-callable attribute makes the reader fall back to .text.
            self.iter_content = None

    def iter_content(self, chunk_size=65536):
        if self._iter_error is not None:
            raise self._iter_error
        if self._chunks is not None:
            for chunk in self._chunks:
                yield chunk
            return
        raw = self.text.encode("utf-8")
        for i in range(0, len(raw), chunk_size):
            yield raw[i:i + chunk_size]

    def close(self):
        self.closed = True


def _fake_cdx_response(status_code=200, text="", headers=None, **kwargs):
    return _FakeResponse(status_code=status_code, text=text, headers=headers, **kwargs)


def _cdx_body(rows):
    return json.dumps([CDX_HEADER] + rows)


def _surface(urls):
    """Build a current-surface mapping the way load_current_surface() does."""
    return wb.load_current_surface(store=None, extra_urls=list(urls))


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
            result = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
        assert result["status"] == "rate_limited"

    def test_server_error(self):
        resp = _fake_cdx_response(503, text="")
        with mock.patch("requests.get", return_value=resp):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
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
            result = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_connection_error(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
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
        assert surface["normalized_urls"] == set()
        assert surface["canonical_urls"] == set()
        assert surface["host_paths"] == set()
        assert surface["paths"] == set()
        assert surface["skipped"] == []

    def test_extra_urls_merged_in(self):
        surface = wb.load_current_surface(store=None, extra_urls=["http://example.com/manual"])
        assert wb._normalize_url("http://example.com/manual") in surface["normalized_urls"]

    def test_corrupt_store_does_not_raise(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = wb.PendingAssetsStore(output_dir=str(output_dir))
        surface = wb.load_current_surface(store=store)
        assert surface["normalized_urls"] == set()
        assert surface["host_paths"] == set()


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
        # A NON-empty current surface that simply does not contain this URL is
        # what makes "removed" a supportable conclusion.
        surface = _surface(["http://example.com/still-here"])
        [enriched] = wb.correlate_against_current_surface([rec], surface)
        assert enriched["relationship_to_current_surface"] == wb.STATE_POTENTIALLY_RELEVANT
        assert enriched["current_surface_compared"] is True

    def test_historically_removed_low_relevance(self):
        rec = self._classified("http://example.com/dead-page", "/dead-page", [404])
        surface = _surface(["http://example.com/still-here"])
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
            "status_codes_seen": [200], "in_scope": True,
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
            "in_scope": True,
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
        # The ingestable type surface_mapper/risk_engine already consume; the
        # endpoint/path/static-asset distinction rides in `discovery_type`.
        assert wb.HISTORICAL_URL_FINDING_TYPE in types
        assert "historical_parameter" in types
        url_finding = next(r for r in records if r["type"] == wb.HISTORICAL_URL_FINDING_TYPE)
        assert url_finding["metadata"]["discovery_type"] == "historical_endpoint"

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
        assert wb.HISTORICAL_URL_FINDING_TYPE in persisted_types
        discovery_types = {
            r["metadata"]["discovery_type"] for r in store.all()
            if r["type"] == wb.HISTORICAL_URL_FINDING_TYPE
        }
        assert "historical_static_asset" in discovery_types
        assert "historical_endpoint" in discovery_types
        assert "historical_path" in discovery_types
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
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"), backoff=0)
        assert summary["cdx_query"]["status"] == "error"
        assert summary["errors"]

    def test_rate_limited_reported(self, tmp_path):
        resp = _fake_cdx_response(429, text="")
        with mock.patch("requests.get", return_value=resp):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"), backoff=0)
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


# ===========================================================================
# MODULE 9 REMEDIATION SUITE
#
# Everything below was added by the Module 9 audit. Each class states the
# behaviour it proves; every confirmed defect has a regression test named
# after what used to go wrong, so a future change that reintroduces it fails
# here rather than in a report.
# ===========================================================================

import time as _time

import reconhound.wayback_intel as _wb_mod


def _rows_body(rows, header=None):
    return json.dumps([header or CDX_HEADER] + rows)


def _run(rows, tmp_path, **kwargs):
    """run_wayback_intel over a canned CDX row set."""
    resp = _fake_cdx_response(200, text=_rows_body(rows))
    kwargs.setdefault("backoff", 0)
    with mock.patch("requests.get", return_value=resp):
        return wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"), **kwargs)


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

class TestInputHandling:
    @pytest.mark.parametrize("raw,expected", [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("  example.com  ", "example.com"),
        ("EXAMPLE.COM...", "example.com"),
        ("sub.deep.example.co.uk", "sub.deep.example.co.uk"),
    ])
    def test_accepted_and_normalized(self, raw, expected):
        assert wb.validate_target(raw) == expected

    @pytest.mark.parametrize("bad", [
        "http://example.com", "https://example.com/", "example.com/path",
        "example.com:8080", "*.example.com", "*", "-lead.com", "trail-.com",
        "exa mple.com", "example", "..", ".com", "example..com",
        "192.168.1.1", "::1", "2001:db8::1", "[::1]",
        "exämple.com", "例え.テスト", "xn--", "example.com\x00evil.com",
        "example.com\nevil.com", "example.com\revil.com", "example.com\tx",
        "a" * 250 + ".com", "a" * 64 + ".com",
        "example.com&url=evil.com", "example.com?x=1", "example.com#frag",
        "'; DROP TABLE --", "../../etc/passwd", "%2e%2e%2f",
    ])
    def test_rejected_with_scope_error(self, bad):
        with pytest.raises(wb.ScopeError):
            wb.validate_target(bad)

    def test_extremely_long_input_is_rejected_not_processed(self):
        with pytest.raises(wb.ScopeError):
            wb.validate_target("a" * 100000 + ".com")

    def test_idn_rejection_is_a_clean_error_not_a_crash(self):
        # Unicode targets are rejected project-wide (every module shares this
        # _DOMAIN_RE). Documented limitation, but it must be a ScopeError.
        with pytest.raises(wb.ScopeError):
            wb.validate_target("bücher.example")

    def test_scope_error_before_any_network_call(self):
        with mock.patch("requests.get") as getter:
            with pytest.raises(wb.ScopeError):
                wb.fetch_cdx_snapshots("not a domain")
        getter.assert_not_called()

    def test_run_rejects_bad_target_before_creating_output(self, tmp_path):
        out = tmp_path / "output"
        with pytest.raises(wb.ScopeError):
            wb.run_wayback_intel("*.example.com", output_dir=str(out))
        assert not (out / "pending_assets.json").exists()


class TestIsInScopeEdges:
    @pytest.mark.parametrize("host,expected", [
        ("example.com", True), ("API.Example.com", True), ("a.b.example.com", True),
        ("example.com.", True), ("notexample.com", False), ("example.com.evil.net", False),
        ("evilexample.com", False), ("", False), ("xexample.com", False),
    ])
    def test_boundaries(self, host, expected):
        assert wb.is_in_scope(host, SAFE_TARGET) is expected


# ---------------------------------------------------------------------------
# CDX request construction
# ---------------------------------------------------------------------------

class TestCdxQueryConstruction:
    def test_target_is_url_encoded_into_the_query(self):
        url = wb.build_cdx_query_url("example.com")
        assert "url=example.com" in url
        assert "matchType=domain" in url
        assert "output=json" in url

    @pytest.mark.parametrize("limit", [0, None])
    def test_absent_limit_sends_no_bound(self, limit):
        assert "limit=" not in wb.build_cdx_query_url(SAFE_TARGET, limit=limit)

    def test_negative_limit_is_a_configuration_error(self):
        # REGRESSION: a negative CDX limit means "the LAST n results", which
        # silently changes the query and made every result compare as truncated.
        with pytest.raises(wb.ConfigurationError):
            wb.build_cdx_query_url(SAFE_TARGET, limit=-5)

    def test_date_filters_are_encoded_not_interpolated(self):
        url = wb.build_cdx_query_url(SAFE_TARGET, from_date="2020&x=1", to_date="2021")
        assert "from=2020%26x%3D1" in url
        assert "to=2021" in url

    def test_invalid_match_type_rejected(self):
        with pytest.raises(wb.ConfigurationError):
            wb.build_cdx_query_url(SAFE_TARGET, match_type="everything")

    @pytest.mark.parametrize("base", ["", "   ", "ftp://x/y", "not a url", "//x"])
    def test_invalid_base_url_rejected(self, base):
        with pytest.raises(wb.ConfigurationError):
            wb.build_cdx_query_url(SAFE_TARGET, base_url=base)


# ---------------------------------------------------------------------------
# Provider response matrix
# ---------------------------------------------------------------------------

class TestProviderResponseMatrix:
    @pytest.mark.parametrize("code,expected_status,expected_class", [
        (403, "error", wb.ERROR_CLASS_FORBIDDEN),
        (404, "error", wb.ERROR_CLASS_NOT_FOUND),
        (429, "rate_limited", wb.ERROR_CLASS_RATE_LIMITED),
        (418, "error", wb.ERROR_CLASS_UNEXPECTED_STATUS),
        (500, "error", wb.ERROR_CLASS_SERVER_ERROR),
        (502, "error", wb.ERROR_CLASS_SERVER_ERROR),
        (503, "error", wb.ERROR_CLASS_SERVER_ERROR),
        (504, "error", wb.ERROR_CLASS_SERVER_ERROR),
    ])
    def test_http_status_classification(self, code, expected_status, expected_class):
        resp = _fake_cdx_response(code, text="")
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
        assert r["status"] == expected_status
        assert r["error_class"] == expected_class
        # Never a negative result, and never claimed complete.
        assert r["conclusive"] is False
        assert r["completeness"] == wb.COMPLETENESS_INCONCLUSIVE
        assert r["snapshots"] == []

    @pytest.mark.parametrize("exc,expected_class", [
        (requests.exceptions.Timeout("t"), wb.ERROR_CLASS_TIMEOUT),
        (requests.exceptions.ConnectionError("c"), wb.ERROR_CLASS_CONNECTION),
        (requests.exceptions.TooManyRedirects("r"), wb.ERROR_CLASS_REQUEST_FAILED),
        (requests.exceptions.RequestException("g"), wb.ERROR_CLASS_REQUEST_FAILED),
    ])
    def test_transport_failure_classification(self, exc, expected_class):
        with mock.patch("requests.get", side_effect=exc):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
        assert r["status"] == "error"
        assert r["error_class"] == expected_class
        assert r["conclusive"] is False

    def test_empty_200_is_a_conclusive_negative_result(self):
        resp = _fake_cdx_response(200, text="")
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert r["status"] == "not_found"
        assert r["conclusive"] is True
        assert r["completeness"] == wb.COMPLETENESS_COMPLETE

    def test_header_only_200_is_a_conclusive_negative_result(self):
        resp = _fake_cdx_response(200, text=json.dumps([CDX_HEADER]))
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert r["status"] == "not_found"
        assert r["conclusive"] is True

    @pytest.mark.parametrize("body", [
        "{not json", "<html><body>502 Bad Gateway</body></html>", "null",
        '{"rows": []}', "[1, 2, 3]", '"a string"', "[[1,2,3],[4,5,6]]",
    ])
    def test_malformed_or_unexpected_body_is_error_never_not_found(self, body):
        resp = _fake_cdx_response(200, text=body)
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert r["status"] == "error"
        assert r["conclusive"] is False

    def test_connection_drop_mid_body_is_a_failure_not_a_short_result(self):
        # REGRESSION: half a JSON array is an unparseable document, not "fewer
        # historical URLs". It must never be reported as a smaller answer.
        resp = _fake_cdx_response(
            200, iter_error=requests.exceptions.ChunkedEncodingError("dropped"))
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
        assert r["status"] == "error"
        assert r["error_class"] == wb.ERROR_CLASS_CONNECTION
        assert "connection dropped" in r["error"]
        assert r["snapshots"] == []

    def test_oversize_response_is_refused_not_truncated(self):
        oversize = b"x" * (wb.MAX_RESPONSE_BYTES + 1)
        resp = _fake_cdx_response(200, chunks=[oversize])
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
        assert r["status"] == "error"
        assert r["error_class"] == wb.ERROR_CLASS_RESPONSE_TOO_LARGE
        assert r["conclusive"] is False

    def test_oversize_declared_content_length_is_refused_without_reading(self):
        resp = _fake_cdx_response(
            200, text="[]", headers={"Content-Length": str(wb.MAX_RESPONSE_BYTES + 1)})
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
        assert r["error_class"] == wb.ERROR_CLASS_RESPONSE_TOO_LARGE

    def test_unparseable_content_length_does_not_break_the_read(self):
        resp = _fake_cdx_response(200, text=_rows_body(SAMPLE_ROWS[:1]),
                                   headers={"Content-Length": "not-a-number"})
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert r["status"] == "found"

    def test_empty_chunks_are_tolerated(self):
        body = _rows_body(SAMPLE_ROWS[:1]).encode()
        resp = _fake_cdx_response(200, chunks=[b"", body[:5], b"", body[5:], b""])
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert r["status"] == "found"

    def test_non_streaming_response_object_still_works(self):
        resp = _fake_cdx_response(200, text=_rows_body(SAMPLE_ROWS[:1]),
                                   supports_streaming=False)
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert r["status"] == "found"

    @pytest.mark.parametrize("encoding", [None, "", "not-a-real-codec", 12345, object()])
    def test_bad_encoding_never_raises(self, encoding):
        # REGRESSION (self-introduced during this remediation): a non-string
        # `encoding` raised TypeError out of the bounded reader.
        resp = _fake_cdx_response(200, text=_rows_body(SAMPLE_ROWS[:1]))
        resp.encoding = encoding
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
        assert r["status"] in ("found", "error")

    def test_unusable_response_object_is_classified_not_raised(self):
        class Hostile:
            status_code = 200
            headers = {}
            url = "u"
            @property
            def encoding(self):
                raise RuntimeError("boom")
            def iter_content(self, n=1):
                raise RuntimeError("boom")
            def close(self):
                pass
        with mock.patch("requests.get", return_value=Hostile()):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
        assert r["status"] == "error"
        assert r["error_class"] == wb.ERROR_CLASS_MALFORMED_RESPONSE

    def test_response_is_always_closed(self):
        resp = _fake_cdx_response(200, text=_rows_body(SAMPLE_ROWS[:1]))
        with mock.patch("requests.get", return_value=resp):
            wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert resp.closed is True

    def test_final_url_is_recorded_for_provenance(self):
        resp = _fake_cdx_response(200, text=_rows_body(SAMPLE_ROWS[:1]),
                                   url="https://web.archive.org/cdx/search/cdx?x=1")
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET)
        assert r["final_url"] == "https://web.archive.org/cdx/search/cdx?x=1"
        assert r["http_status"] == 200


# ---------------------------------------------------------------------------
# Retry behaviour
# ---------------------------------------------------------------------------

class TestRetryBehaviour:
    @pytest.mark.parametrize("code", [429, 500, 502, 503])
    def test_transient_http_failures_are_retried_up_to_the_bound(self, code):
        resp = _fake_cdx_response(code, text="")
        with mock.patch("requests.get", return_value=resp) as getter:
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, max_attempts=3, backoff=0)
        assert getter.call_count == 3
        assert r["attempts"] == 3
        assert r["retries"] == 2

    @pytest.mark.parametrize("exc", [
        requests.exceptions.Timeout("t"),
        requests.exceptions.ConnectionError("c"),
    ])
    def test_transient_transport_failures_are_retried(self, exc):
        with mock.patch("requests.get", side_effect=exc) as getter:
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, max_attempts=3, backoff=0)
        assert getter.call_count == 3
        assert r["retries"] == 2

    @pytest.mark.parametrize("code", [403, 404, 418])
    def test_permanent_http_failures_are_never_retried(self, code):
        # Retrying a refusal is pure provider load with no chance of a
        # different answer.
        resp = _fake_cdx_response(code, text="")
        with mock.patch("requests.get", return_value=resp) as getter:
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, max_attempts=5, backoff=0)
        assert getter.call_count == 1
        assert r["retries"] == 0

    def test_malformed_body_is_never_retried(self):
        resp = _fake_cdx_response(200, text="{not json")
        with mock.patch("requests.get", return_value=resp) as getter:
            wb.fetch_cdx_snapshots(SAFE_TARGET, max_attempts=5, backoff=0)
        assert getter.call_count == 1

    def test_successful_empty_result_is_never_retried(self):
        resp = _fake_cdx_response(200, text="")
        with mock.patch("requests.get", return_value=resp) as getter:
            wb.fetch_cdx_snapshots(SAFE_TARGET, max_attempts=5, backoff=0)
        assert getter.call_count == 1

    def test_configuration_error_makes_no_request_at_all(self):
        with mock.patch("requests.get") as getter:
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, base_url="", max_attempts=5)
        getter.assert_not_called()
        assert r["error_class"] == wb.ERROR_CLASS_CONFIGURATION

    def test_retry_succeeds_and_does_not_duplicate_results(self):
        good = _fake_cdx_response(200, text=_rows_body(SAMPLE_ROWS))
        seq = [_fake_cdx_response(503, text=""), good]
        with mock.patch("requests.get", side_effect=seq) as getter:
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, max_attempts=3, backoff=0)
        assert getter.call_count == 2
        assert r["status"] == "found"
        assert len(r["snapshots"]) == len(SAMPLE_ROWS)  # not doubled

    @pytest.mark.parametrize("max_attempts", [0, -1, 1, "bad", None])
    def test_attempt_bound_is_always_at_least_one_and_never_unbounded(self, max_attempts):
        with mock.patch("requests.get",
                        side_effect=requests.exceptions.Timeout("t")) as getter:
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, max_attempts=max_attempts, backoff=0)
        assert getter.call_count == 1
        assert r["attempts"] == 1

    def test_no_retry_storm_the_request_count_is_bounded_by_max_attempts(self):
        with mock.patch("requests.get",
                        side_effect=requests.exceptions.ConnectionError("c")) as getter:
            wb.fetch_cdx_snapshots(SAFE_TARGET, max_attempts=4, backoff=0)
        assert getter.call_count == 4


class TestRetryDelay:
    def test_exponential_backoff(self):
        assert wb._retry_delay(1, 1.0, None) == 1.0
        assert wb._retry_delay(2, 1.0, None) == 2.0
        assert wb._retry_delay(3, 1.0, None) == 4.0

    def test_retry_after_wins_when_it_asks_for_longer(self):
        assert wb._retry_delay(1, 1.0, "5") == 5.0

    def test_retry_after_is_ignored_when_shorter_than_our_own_schedule(self):
        assert wb._retry_delay(3, 1.0, "1") == 4.0

    @pytest.mark.parametrize("header", ["999999", "1e9"])
    def test_retry_after_is_clamped(self, header):
        assert wb._retry_delay(1, 1.0, header) == wb.MAX_BACKOFF_SECONDS

    @pytest.mark.parametrize("header", ["Wed, 21 Oct 2015 07:28:00 GMT", "soon", "", None, "-5"])
    def test_unusable_retry_after_falls_back_to_the_schedule(self, header):
        assert wb._retry_delay(2, 1.0, header) == 2.0

    def test_schedule_is_always_bounded(self):
        assert wb._retry_delay(50, 10.0, None) == wb.MAX_BACKOFF_SECONDS

    def test_delay_is_never_negative(self):
        assert wb._retry_delay(1, -5.0, None) == 0.0

    def test_retry_after_header_is_actually_honoured_end_to_end(self):
        resp = _fake_cdx_response(429, text="", headers={"Retry-After": "2"})
        slept = []
        with mock.patch("requests.get", return_value=resp), \
             mock.patch.object(_wb_mod.time, "sleep", slept.append):
            wb.fetch_cdx_snapshots(SAFE_TARGET, max_attempts=2, backoff=1.0)
        assert slept == [2.0]


# ---------------------------------------------------------------------------
# Parsing robustness
# ---------------------------------------------------------------------------

class TestSnapshotParsing:
    def _one(self, **over):
        row = {"timestamp": "20200101000000", "original": "http://example.com/x",
               "statuscode": "200", "mimetype": "text/html", "digest": "D"}
        row.update(over)
        return wb.normalize_snapshot(row)

    def test_unicode_url_is_preserved(self):
        snap = self._one(original="http://example.com/café?q=ü")
        assert "café" in snap["original_url"]
        json.dumps(snap)

    @pytest.mark.parametrize("bad", [
        "http://example.com/a\nb", "http://example.com/a\rb",
        "http://example.com/a\x00b", "http://example.com/a\x1bb",
        "http://example.com/a\x7fb",
    ])
    def test_control_characters_reject_the_row(self, bad):
        # REGRESSION: control characters in a provider-supplied "URL" are what
        # turn a stored value into log injection and a corrupted report line.
        with pytest.raises(ValueError):
            self._one(original=bad)

    def test_overlong_url_is_rejected_not_truncated(self):
        # REGRESSION: a truncated URL names an asset that never existed.
        with pytest.raises(ValueError) as exc:
            self._one(original="http://example.com/" + "a" * wb.MAX_URL_LENGTH)
        assert "rejected rather than truncated" in str(exc.value)

    def test_url_at_the_limit_is_accepted(self):
        url = "http://example.com/" + "a" * (wb.MAX_URL_LENGTH - len("http://example.com/"))
        assert len(self._one(original=url)["original_url"]) == wb.MAX_URL_LENGTH

    @pytest.mark.parametrize("ts", ["", "notatimestamp", "2020", "202001010000000", "-"])
    def test_malformed_timestamp_yields_no_archive_url(self, ts):
        # REGRESSION: archive_url was built by raw f-string concatenation of
        # provider-controlled strings, producing links addressing no capture.
        if not ts:
            with pytest.raises(ValueError):
                self._one(timestamp=ts)
            return
        snap = self._one(timestamp=ts)
        assert snap["observed_at"] is None
        assert snap["archive_url"] is None
        assert snap["timestamp"] == ts

    def test_valid_timestamp_yields_an_archive_url(self):
        snap = self._one()
        assert snap["archive_url"] == "https://web.archive.org/web/20200101000000/http://example.com/x"

    @pytest.mark.parametrize("status", ["-", "", "abc", "20x", None])
    def test_malformed_status_code_becomes_none_not_a_crash(self, status):
        assert self._one(statuscode=status)["status_code"] is None

    @pytest.mark.parametrize("missing", ["timestamp", "original"])
    def test_missing_required_field_raises(self, missing):
        with pytest.raises(ValueError):
            self._one(**{missing: ""})

    def test_non_string_fields_are_rejected(self):
        with pytest.raises(ValueError):
            self._one(original=12345)
        with pytest.raises(ValueError):
            self._one(timestamp=20200101000000)


class TestRowLevelRobustness:
    def _fetch(self, rows, header=None, **kw):
        resp = _fake_cdx_response(200, text=_rows_body(rows, header))
        kw.setdefault("backoff", 0)
        with mock.patch("requests.get", return_value=resp):
            return wb.fetch_cdx_snapshots(SAFE_TARGET, **kw)

    def test_short_row_is_collected_not_fatal(self):
        r = self._fetch([SAMPLE_ROWS[0], ["too", "short"]])
        assert len(r["snapshots"]) == 1
        assert r["row_error_count"] == 1

    def test_long_row_is_collected_not_fatal(self):
        r = self._fetch([SAMPLE_ROWS[0], SAMPLE_ROWS[0] + ["extra"]])
        assert len(r["snapshots"]) == 1
        assert r["row_error_count"] == 1

    def test_non_list_row_is_collected_not_fatal(self):
        r = self._fetch([SAMPLE_ROWS[0], {"not": "a row"}, None, 42])
        assert len(r["snapshots"]) == 1
        assert r["row_error_count"] == 3

    def test_row_errors_are_capped_but_counted_exactly(self):
        # REGRESSION: an unbounded row_errors list retained one string per bad
        # row and then persisted and rendered every one of them.
        bad = [["only", "two"] for _ in range(2000)]
        r = self._fetch([SAMPLE_ROWS[0]] + bad)
        assert r["row_error_count"] == 2000
        assert len(r["row_errors"]) == wb.MAX_ROW_ERRORS + 1
        assert "suppressed" in r["row_errors"][-1]

    def test_row_errors_downgrade_completeness(self):
        r = self._fetch([SAMPLE_ROWS[0], ["bad"]], limit=1000)
        assert r["completeness"] == wb.COMPLETENESS_POSSIBLY_TRUNCATED
        assert r["conclusive"] is False

    def test_all_rows_bad_is_not_found_but_never_conclusive(self):
        r = self._fetch([["bad"] for _ in range(5)], limit=1000)
        assert r["status"] == "not_found"
        assert r["conclusive"] is False

    def test_extra_header_columns_are_zipped_by_name(self):
        header = CDX_HEADER + ["urlkey"]
        rows = [SAMPLE_ROWS[0] + ["com,example)/old-page"]]
        r = self._fetch(rows, header=header)
        assert r["snapshots"][0]["original_url"] == "http://example.com/old-page"

    def test_reordered_header_columns_are_honoured(self):
        header = ["original", "timestamp", "statuscode", "mimetype", "digest"]
        rows = [["http://example.com/z", "20200101000000", "200", "text/html", "D"]]
        r = self._fetch(rows, header=header)
        assert r["snapshots"][0]["original_url"] == "http://example.com/z"
        assert r["snapshots"][0]["timestamp"] == "20200101000000"

    def test_missing_optional_columns_are_tolerated(self):
        header = ["timestamp", "original"]
        r = self._fetch([["20200101000000", "http://example.com/q"]], header=header)
        assert r["snapshots"][0]["status_code"] is None
        assert r["snapshots"][0]["mime_type"] is None


# ---------------------------------------------------------------------------
# Completeness semantics
# ---------------------------------------------------------------------------

class TestCompletenessSemantics:
    def _fetch(self, n, limit):
        rows = [["2020010100000%d" % (i % 10), "http://example.com/p%d" % i,
                 "200", "text/html", "D%d" % i] for i in range(n)]
        resp = _fake_cdx_response(200, text=_rows_body(rows))
        with mock.patch("requests.get", return_value=resp):
            return wb.fetch_cdx_snapshots(SAFE_TARGET, limit=limit, backoff=0)

    def test_under_limit_is_complete_and_conclusive(self):
        r = self._fetch(5, 100)
        assert r["truncated"] is False
        assert r["completeness"] == wb.COMPLETENESS_COMPLETE
        assert r["conclusive"] is True

    def test_exactly_at_limit_is_possibly_truncated_never_certain(self):
        # The CDX API never reports how many rows it withheld, so a full page
        # is genuinely ambiguous and must be reported as such in BOTH
        # directions: not "complete", not "definitely truncated".
        r = self._fetch(10, 10)
        assert r["truncated"] is True
        assert r["completeness"] == wb.COMPLETENESS_POSSIBLY_TRUNCATED
        assert r["conclusive"] is False

    def test_above_limit_is_possibly_truncated(self):
        r = self._fetch(15, 10)
        assert r["completeness"] == wb.COMPLETENESS_POSSIBLY_TRUNCATED

    @pytest.mark.parametrize("limit", [0, None])
    def test_no_bound_means_unknown_never_complete(self, limit):
        # REGRESSION: limit=0/None removed the CDX bound AND forced
        # truncated=False, so an unbounded, possibly partial fetch was
        # reported as a complete result set.
        r = self._fetch(10, limit)
        assert r["truncated"] is False
        assert r["completeness"] == wb.COMPLETENESS_UNKNOWN
        assert r["conclusive"] is False

    def test_zero_results_with_a_bound_is_complete(self):
        r = self._fetch(0, 100)
        assert r["status"] == "not_found"
        assert r["conclusive"] is True

    @pytest.mark.parametrize("code", [403, 429, 500, 503])
    def test_provider_failure_is_never_conclusive(self, code):
        resp = _fake_cdx_response(code, text="")
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
        assert r["conclusive"] is False
        assert r["completeness"] == wb.COMPLETENESS_INCONCLUSIVE


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------

class TestUrlNormalization:
    def test_tracking_only_variants_share_one_identity(self):
        a = wb._canonical_url("http://example.com/p?utm_source=x&id=1")
        b = wb._canonical_url("http://example.com/p?utm_source=y&id=1")
        assert a == b == "http://example.com/p?id=1"

    @pytest.mark.parametrize("a,b", [
        ("http://example.com/p?id=1", "http://example.com/p?id=2"),
        ("http://example.com/p?sid=abc", "http://example.com/p?sid=admin"),
        ("http://example.com/p?page=1", "http://example.com/p?page=2"),
        ("http://example.com/p?ref=a", "http://example.com/p?ref=b"),
        ("http://example.com/p?source=a", "http://example.com/p?source=b"),
        ("http://example.com/p?cid=1", "http://example.com/p?cid=2"),
        ("http://example.com/a", "http://example.com/b"),
        ("http://a.example.com/p", "http://b.example.com/p"),
    ])
    def test_semantically_distinct_urls_are_never_collapsed(self, a, b):
        assert wb._canonical_url(a) != wb._canonical_url(b)

    def test_parameter_order_does_not_create_a_second_identity(self):
        assert (wb._canonical_url("http://example.com/p?a=1&b=2")
                == wb._canonical_url("http://example.com/p?b=2&a=1"))

    def test_repeated_parameter_values_are_both_preserved(self):
        canon = wb._canonical_url("http://example.com/p?a=1&a=2")
        assert "a=1" in canon and "a=2" in canon
        assert canon != wb._canonical_url("http://example.com/p?a=1")

    def test_percent_encoded_values_survive_a_round_trip(self):
        canon = wb._canonical_url("http://example.com/p?q=a%20b%26c")
        assert wb._canonical_url(canon) == canon

    def test_encoded_tracking_parameter_name_is_still_recognised(self):
        assert wb._canonical_url("http://example.com/p?utm%5Fsource=x&id=1") \
            == "http://example.com/p?id=1"

    def test_tracking_parameter_matching_is_case_insensitive(self):
        assert wb._canonical_url("http://example.com/p?UTM_Source=x&id=1") \
            == "http://example.com/p?id=1"

    def test_empty_parameter_values_are_kept(self):
        assert "empty=" in wb._canonical_url("http://example.com/p?empty=")

    def test_valueless_parameter_is_kept(self):
        assert "admin" in wb._canonical_url("http://example.com/p?admin")

    def test_url_with_only_tracking_parameters_loses_its_query(self):
        assert wb._canonical_url("http://example.com/p?utm_source=x") == "http://example.com/p"

    def test_fragments_are_dropped_consistently(self):
        assert (wb._canonical_url("http://example.com/p#a")
                == wb._canonical_url("http://example.com/p#b")
                == "http://example.com/p")

    @pytest.mark.parametrize("a,b", [
        ("HTTP://EXAMPLE.COM/p", "http://example.com/p"),
        ("http://example.com:80/p", "http://example.com/p"),
        ("https://example.com:443/p", "https://example.com/p"),
        ("http://example.com//a//b", "http://example.com/a/b"),
    ])
    def test_host_and_scheme_normalization(self, a, b):
        assert wb._normalize_url(a) == wb._normalize_url(b)

    def test_http_and_https_remain_distinguishable_in_the_normalized_url(self):
        assert wb._normalize_url("http://example.com/p") != wb._normalize_url("https://example.com/p")

    def test_tracking_parameters_are_reported_not_hidden(self):
        assert wb._tracking_parameters_in("http://example.com/p?utm_source=x&id=1") == ["utm_source"]
        assert wb._tracking_parameters_in("http://example.com/p?id=1") == []

    @pytest.mark.parametrize("bad", ["http://[::1", "://", "http://", ""])
    def test_unparseable_urls_do_not_raise_out_of_the_helpers(self, bad):
        wb._url_path(bad)
        wb._url_hostname(bad)
        wb._tracking_parameters_in(bad)


class TestTrackingVariantMerging:
    def _snaps(self, urls):
        return [wb.normalize_snapshot({
            "timestamp": "2020010100000%d" % i, "original": u,
            "statuscode": "200", "mimetype": "text/html", "digest": "D%d" % i,
        }) for i, u in enumerate(urls)]

    def test_variants_merge_into_one_record_preserving_every_original_url(self):
        snaps = self._snaps([
            "http://example.com/p?utm_source=a&id=1",
            "http://example.com/p?utm_source=b&id=1",
            "http://example.com/p?utm_source=c&id=1",
        ])
        [rec] = wb.group_historical_urls(snaps, SAFE_TARGET)
        assert rec["variant_count"] == 3
        assert rec["capture_count"] == 3
        assert len(rec["url_variants"]) == 3
        assert rec["tracking_parameters_seen"] == ["utm_source"]
        # No evidence destroyed: every capture is still there.
        assert len(rec["snapshots"]) == 3

    def test_merged_record_does_not_emit_tracking_parameters_as_app_parameters(self):
        snaps = self._snaps(["http://example.com/p?utm_source=a&id=1"])
        [rec] = wb.group_historical_urls(snaps, SAFE_TARGET)
        names = {p["name"] for p in wb.extract_historical_parameters(rec)}
        assert names == {"id"}

    def test_distinct_application_parameters_stay_distinct(self):
        snaps = self._snaps([
            "http://example.com/p?id=1", "http://example.com/p?id=2",
            "http://example.com/p?sid=admin",
        ])
        recs = wb.group_historical_urls(snaps, SAFE_TARGET)
        assert len(recs) == 3

    def test_merging_does_not_reduce_the_parameter_inventory(self):
        snaps = self._snaps([
            "http://example.com/p?utm_source=a&id=1&debug=true",
            "http://example.com/p?utm_source=b&id=1&debug=true",
        ])
        [rec] = wb.group_historical_urls(snaps, SAFE_TARGET)
        assert {p["name"] for p in wb.extract_historical_parameters(rec)} == {"id", "debug"}


# ---------------------------------------------------------------------------
# Historical semantics — the core contract of this module
# ---------------------------------------------------------------------------

class TestHistoricalSemantics:
    def test_capture_ordering_uses_the_raw_timestamp_only(self):
        # REGRESSION: first/last were compared across two different string
        # formats. "-" sorts below any digit, so an ISO string always compared
        # LESS than a raw timestamp in the same year, and a January capture
        # with an unparseable timestamp was reported as more recent than a
        # December capture with a valid one.
        snaps = [
            {"timestamp": "20200101000000", "observed_at": None,
             "original_url": "http://example.com/p", "status_code": 200,
             "status_code_raw": "200", "mime_type": None, "digest": None, "archive_url": None},
            {"timestamp": "20201201000000", "observed_at": "2020-12-01T00:00:00+00:00",
             "original_url": "http://example.com/p", "status_code": 200,
             "status_code_raw": "200", "mime_type": None, "digest": None, "archive_url": "a"},
        ]
        [rec] = wb.group_historical_urls(snaps, SAFE_TARGET)
        assert rec["first_capture_timestamp"] == "20200101000000"
        assert rec["last_capture_timestamp"] == "20201201000000"
        assert rec["last_observed_at"] == "2020-12-01T00:00:00+00:00"

    def test_multiple_captures_are_all_retained_and_summarized(self):
        rows = [
            ["20180101000000", "http://example.com/p", "200", "text/html", "A"],
            ["20190101000000", "http://example.com/p", "301", "text/html", "B"],
            ["20200101000000", "http://example.com/p", "404", "text/html", "C"],
        ]
        snaps = [wb.normalize_snapshot(dict(zip(CDX_HEADER, r))) for r in rows]
        [rec] = wb.group_historical_urls(snaps, SAFE_TARGET)
        assert rec["capture_count"] == 3
        assert rec["status_codes_seen"] == [200, 301, 404]
        assert rec["first_capture_timestamp"] == "20180101000000"
        assert rec["last_capture_timestamp"] == "20200101000000"

    def test_conflicting_status_codes_are_preserved_not_reduced(self):
        rows = [["20180101000000", "http://example.com/p", "200", "text/html", "A"],
                ["20190101000000", "http://example.com/p", "500", "text/html", "B"]]
        snaps = [wb.normalize_snapshot(dict(zip(CDX_HEADER, r))) for r in rows]
        [rec] = wb.group_historical_urls(snaps, SAFE_TARGET)
        assert rec["status_codes_seen"] == [200, 500]

    def test_accessibility_is_always_unverified(self):
        classified = wb.classify_historical_url({
            "url": "http://example.com/p", "normalized_url": "http://example.com/p",
            "canonical_url": "http://example.com/p", "path": "/p",
            "status_codes_seen": [200], "in_scope": True,
        })
        for surface in (_surface([]), _surface(["http://example.com/p"]),
                        _surface(["http://example.com/other"])):
            [e] = wb.correlate_against_current_surface([classified], surface)
            assert e["current_accessibility"] == wb.ACCESSIBILITY_UNVERIFIED
            assert "passive" in e["current_accessibility_note"]

    def test_cross_host_bare_path_never_creates_a_current_asset_claim(self):
        # REGRESSION (P1): matching on the bare path declared a historical URL
        # on ANY host "currently known" with HIGH confidence whenever some
        # other host's current surface happened to share the path. "/" alone
        # made essentially every historical root URL a confirmed current asset.
        rec = wb.classify_historical_url({
            "url": "http://retired.example.com/login",
            "normalized_url": wb._normalize_url("http://retired.example.com/login"),
            "canonical_url": wb._canonical_url("http://retired.example.com/login"),
            "path": "/login", "status_codes_seen": [200], "in_scope": True,
        })
        surface = _surface(["https://www.example.com/login"])
        [e] = wb.correlate_against_current_surface([rec], surface)
        assert e["relationship_to_current_surface"] != wb.STATE_CURRENTLY_KNOWN
        assert e["confidence"] == wb.CONFIDENCE_LOW

    def test_root_path_does_not_make_every_historical_host_currently_known(self):
        rec = wb.classify_historical_url({
            "url": "http://decommissioned.example.com/",
            "normalized_url": wb._normalize_url("http://decommissioned.example.com/"),
            "canonical_url": wb._canonical_url("http://decommissioned.example.com/"),
            "path": "/", "status_codes_seen": [200], "in_scope": True,
        })
        [e] = wb.correlate_against_current_surface([rec], _surface(["https://example.com/"]))
        assert e["relationship_to_current_surface"] != wb.STATE_CURRENTLY_KNOWN

    def test_same_host_and_path_does_match_across_scheme_and_tracking_noise(self):
        # The legitimate reason path matching existed in the first place must
        # keep working, host-qualified.
        rec = wb.classify_historical_url({
            "url": "http://example.com/old-page?utm_source=x",
            "normalized_url": wb._normalize_url("http://example.com/old-page?utm_source=x"),
            "canonical_url": wb._canonical_url("http://example.com/old-page?utm_source=x"),
            "path": "/old-page", "status_codes_seen": [200], "in_scope": True,
        })
        [e] = wb.correlate_against_current_surface([rec], _surface(["https://example.com/old-page"]))
        assert e["relationship_to_current_surface"] == wb.STATE_CURRENTLY_KNOWN

    def test_no_current_surface_means_unknown_not_removed(self):
        # REGRESSION (P1): in a real pipeline wayback_intel runs in the PASSIVE
        # phase, before endpoint_discovery/crawler have produced any current
        # surface. Every historical URL was therefore labelled "historically
        # removed" on every full scan — a removal conclusion drawn from an
        # absence of data.
        rec = wb.classify_historical_url({
            "url": "http://example.com/p", "normalized_url": "http://example.com/p",
            "canonical_url": "http://example.com/p", "path": "/p",
            "status_codes_seen": [200], "in_scope": True,
        })
        [e] = wb.correlate_against_current_surface([rec], _surface([]))
        assert e["relationship_to_current_surface"] == wb.STATE_UNKNOWN_NO_CURRENT_SURFACE
        assert e["current_surface_compared"] is False

    def test_every_persisted_url_finding_says_it_is_historical(self, tmp_path):
        summary = _run(SAMPLE_ROWS, tmp_path)
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        url_findings = [r for r in store.all() if r["type"] == wb.HISTORICAL_URL_FINDING_TYPE]
        assert url_findings
        for f in url_findings:
            assert f["metadata"]["historical"] is True
            assert f["metadata"]["current_accessibility"] == wb.ACCESSIBILITY_UNVERIFIED
            assert any("HISTORICAL EVIDENCE ONLY" in e for e in f["evidence"])

    def test_parameter_findings_are_marked_historical_too(self, tmp_path):
        _run(SAMPLE_ROWS, tmp_path)
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        params = [r for r in store.all() if r["type"] == "historical_parameter"]
        assert params
        for p in params:
            assert p["metadata"]["historical"] is True
            assert p["value"]["historical"] is True

    def test_historical_data_export_is_marked_historical(self, tmp_path):
        summary = _run(SAMPLE_ROWS, tmp_path)
        assert summary["historical_data"]
        for item in summary["historical_data"]:
            assert item["historical"] is True
            assert item["source"] == wb.MODULE_NAME
            assert any("HISTORICAL EVIDENCE ONLY" in e for e in item["evidence"])

    def test_provenance_survives_to_the_persisted_record(self, tmp_path):
        _run(SAMPLE_ROWS, tmp_path)
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        f = next(r for r in store.all() if r["type"] == wb.HISTORICAL_URL_FINDING_TYPE)
        assert f["source"] == wb.MODULE_NAME
        assert f["timestamp"]
        assert f["value"]["first_observed_at"] and f["value"]["last_observed_at"]
        assert f["value"]["snapshots"][0]["archive_url"]


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------

class TestScopeEnforcement:
    OUT_OF_SCOPE_ROWS = [
        ["20200101000000", "http://example.com/legit", "200", "text/html", "A"],
        ["20200101000000", "http://spam-unrelated.net/casino", "200", "text/html", "B"],
        ["20200101000000", "http://example.com.evil.net/phish", "200", "text/html", "C"],
        ["20200101000000", "http://notexample.com/x", "200", "text/html", "D"],
    ]

    def test_out_of_scope_hosts_are_not_persisted(self, tmp_path):
        # REGRESSION (P1): every CDX row was persisted as a finding of the
        # target regardless of hostname. The CDX API indexes the whole web and
        # its rows are third-party data (ownership changes, shared hosting,
        # archive spam), so an unrelated host became an asset of this target.
        summary = _run(self.OUT_OF_SCOPE_ROWS, tmp_path)
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        persisted_urls = {
            r["value"]["url"] for r in store.all()
            if r["type"] == wb.HISTORICAL_URL_FINDING_TYPE
        }
        assert persisted_urls == {"http://example.com/legit"}

    def test_out_of_scope_hosts_are_reported_not_silently_dropped(self, tmp_path):
        summary = _run(self.OUT_OF_SCOPE_ROWS, tmp_path)
        assert summary["stats"]["out_of_scope_urls"] == 3
        assert len(summary["out_of_scope_urls"]) == 3
        assert any(e.get("stage") == "scope_enforcement" for e in summary["errors"])
        # Still present in the full record set for the operator to inspect.
        assert len(summary["historical_urls"]) == 4

    def test_out_of_scope_hosts_never_reach_the_downstream_export(self, tmp_path):
        summary = _run(self.OUT_OF_SCOPE_ROWS, tmp_path)
        assert {i["url"] for i in summary["historical_data"]} == {"http://example.com/legit"}

    def test_subdomains_are_in_scope(self, tmp_path):
        rows = [["20200101000000", "http://api.example.com/v1", "200", "application/json", "A"]]
        summary = _run(rows, tmp_path)
        assert summary["stats"]["in_scope_urls"] == 1
        assert summary["stats"]["out_of_scope_urls"] == 0

    def test_records_without_a_scope_verdict_fail_closed(self, tmp_path):
        # A record that never went through group_historical_urls carries no
        # scope verdict; persisting it would be a fail-open scope check.
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        rec = {"url": "http://example.com/x", "path": "/x", "capture_count": 1,
               "discovery_type": "historical_path", "confidence": wb.CONFIDENCE_LOW,
               "relationship_to_current_surface": wb.STATE_HISTORICALLY_REMOVED,
               "current_accessibility": wb.ACCESSIBILITY_UNVERIFIED,
               "first_observed_at": "t", "last_observed_at": "t", "status_codes_seen": []}
        wb.persist_historical_findings([rec], SAFE_TARGET, store)
        assert store.all() == []

    def test_query_string_cannot_smuggle_an_out_of_scope_host(self, tmp_path):
        rows = [["20200101000000", "http://spam.net/x?target=example.com", "200", "text/html", "A"]]
        summary = _run(rows, tmp_path)
        assert summary["stats"]["in_scope_urls"] == 0

    def test_userinfo_host_confusion_is_resolved_by_the_real_hostname(self, tmp_path):
        rows = [["20200101000000", "http://example.com@evil.net/x", "200", "text/html", "A"]]
        summary = _run(rows, tmp_path)
        # urlsplit resolves the real host to evil.net, so it must be out of scope.
        assert summary["stats"]["in_scope_urls"] == 0


# ---------------------------------------------------------------------------
# Provider failure vs. genuine absence
# ---------------------------------------------------------------------------

class TestFailureVersusAbsence:
    def _fail(self, tmp_path, **resp_kwargs):
        resp = _fake_cdx_response(**resp_kwargs)
        with mock.patch("requests.get", return_value=resp):
            return wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"), backoff=0)

    @pytest.mark.parametrize("code", [403, 429, 500, 503])
    def test_provider_failure_persists_an_inconclusive_record(self, tmp_path, code):
        summary = self._fail(tmp_path, status_code=code, text="")
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        records = store.all()
        assert len(records) == 1
        assert records[0]["type"] == wb.INCONCLUSIVE_FINDING_TYPE
        assert records[0]["value"]["outcome"] == "inconclusive"
        assert records[0]["metadata"]["negative_result"] is False
        assert any("INCONCLUSIVE, not negative" in e for e in records[0]["evidence"])

    def test_inconclusive_type_can_never_be_read_as_negative_result_memory(self):
        # surface_mapper._is_negative_result() keys on these substrings.
        assert "_checked_no" not in wb.INCONCLUSIVE_FINDING_TYPE
        assert not wb.INCONCLUSIVE_FINDING_TYPE.endswith("_not_probed")

    def test_genuine_empty_archive_persists_nothing_and_is_conclusive(self, tmp_path):
        summary = self._fail(tmp_path, status_code=200, text=json.dumps([CDX_HEADER]))
        assert summary["status"] == "not_found"
        assert summary["conclusive"] is True
        assert summary["provider_failed"] is False
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert store.all() == []  # a real negative result is not a failed check

    def test_failure_and_absence_are_distinguishable_in_the_summary(self, tmp_path):
        failure = self._fail(tmp_path, status_code=503, text="")
        absence = self._fail(tmp_path, status_code=200, text=json.dumps([CDX_HEADER]))
        assert (failure["status"], failure["conclusive"], failure["provider_failed"]) \
            != (absence["status"], absence["conclusive"], absence["provider_failed"])

    def test_truncated_success_also_records_an_inconclusive_marker(self, tmp_path):
        rows = [["2020010100000%d" % (i % 10), "http://example.com/p%d" % i,
                 "200", "text/html", "D%d" % i] for i in range(5)]
        summary = _run(rows, tmp_path, limit=5)
        assert summary["results_truncated"] is True
        assert summary["conclusive"] is False
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert any(r["type"] == wb.INCONCLUSIVE_FINDING_TYPE for r in store.all())
        # ...and the URLs it DID find are still persisted.
        assert any(r["type"] == wb.HISTORICAL_URL_FINDING_TYPE for r in store.all())

    def test_a_complete_result_records_no_inconclusive_marker(self, tmp_path):
        summary = _run(SAMPLE_ROWS, tmp_path, limit=1000)
        assert summary["conclusive"] is True
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert not any(r["type"] == wb.INCONCLUSIVE_FINDING_TYPE for r in store.all())

    def test_persistence_failure_during_inconclusive_record_is_collected(self, tmp_path):
        out = tmp_path / "output"
        out.mkdir()
        (out / "pending_assets.json").write_text("{corrupt")
        resp = _fake_cdx_response(503, text="")
        with mock.patch("requests.get", return_value=resp):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(out), backoff=0)
        assert any(e.get("stage") == "persistence" for e in summary["errors"])


# ---------------------------------------------------------------------------
# Resource safety — measured, not asserted by intuition
# ---------------------------------------------------------------------------

def _bulk_records(n, prefix="http://example.com/p"):
    return [{
        "url": f"{prefix}{i}", "normalized_url": f"{prefix}{i}",
        "canonical_url": f"{prefix}{i}", "path": f"/p{i}", "in_scope": True,
        "capture_count": 1, "variant_count": 1, "url_variants": [f"{prefix}{i}"],
        "first_observed_at": "2020-01-01T00:00:00+00:00",
        "last_observed_at": "2020-01-01T00:00:00+00:00",
        "status_codes_seen": [200], "discovery_type": "historical_path",
        "confidence": wb.CONFIDENCE_LOW,
        "relationship_to_current_surface": wb.STATE_HISTORICALLY_REMOVED,
        "current_accessibility": wb.ACCESSIBILITY_UNVERIFIED,
    } for i in range(n)]


class TestResourceSafety:
    def test_batch_persistence_is_linear_not_quadratic(self, tmp_path):
        # REGRESSION (P1): persist_historical_findings called store.add() once
        # per finding, and add() re-reads and rewrites the whole file. Measured
        # before the fix: 100 records 0.24s, 400 records 3.67s, 800 records
        # 10.67s — ~4x the cost for 2x the input, on a module whose DEFAULT
        # limit is 5000 records.
        timings = {}
        for n in (200, 800):
            out = tmp_path / f"o{n}"
            store = wb.PendingAssetsStore(output_dir=str(out))
            start = _time.perf_counter()
            wb.persist_historical_findings(_bulk_records(n), SAFE_TARGET, store)
            timings[n] = _time.perf_counter() - start
            assert len(store.all()) == n
        # Quadratic growth would be ~16x for 4x the input. Allow generous
        # headroom for a loaded machine and still catch a return to O(n^2).
        assert timings[800] < max(timings[200] * 8, 0.5), timings

    def test_batch_persistence_writes_the_file_once(self, tmp_path):
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "o"))
        writes = []
        original = store._atomic_write
        store._atomic_write = lambda recs: (writes.append(len(recs)), original(recs))[1]
        wb.persist_historical_findings(_bulk_records(50), SAFE_TARGET, store)
        assert len(writes) == 1

    def test_add_many_preserves_pre_existing_records(self, tmp_path):
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "o"))
        first = wb.make_finding("other_module_finding", "x.com", {}, [], wb.CONFIDENCE_LOW)
        store.add(first)
        store.add_many([wb.make_finding("a", "x.com", {}, [], wb.CONFIDENCE_LOW)])
        assert store.all()[0] == first
        assert len(store.all()) == 2

    def test_add_many_of_nothing_is_a_noop(self, tmp_path):
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "o"))
        assert store.add_many([]) == 0
        assert store.all() == []

    def test_add_many_failure_leaves_the_previous_file_intact(self, tmp_path):
        out = tmp_path / "o"
        out.mkdir()
        (out / "pending_assets.json").write_text("{corrupt")
        store = wb.PendingAssetsStore(output_dir=str(out))
        with pytest.raises(wb.PersistenceError):
            store.add_many([wb.make_finding("a", "x.com", {}, [], wb.CONFIDENCE_LOW)])
        assert (out / "pending_assets.json").read_text() == "{corrupt"

    def test_large_result_set_completes_in_reasonable_time(self, tmp_path):
        n = 5000  # the module's own DEFAULT_LIMIT
        rows = [["2020010100000%d" % (i % 10), "http://example.com/p%d" % i,
                 "200", "text/html", "D%d" % i] for i in range(n)]
        start = _time.perf_counter()
        summary = _run(rows, tmp_path, limit=n + 1)
        elapsed = _time.perf_counter() - start
        assert summary["stats"]["unique_urls"] == n
        assert elapsed < 30, f"{n} records took {elapsed:.1f}s"

    def test_duplicate_heavy_input_collapses_without_blowing_up(self, tmp_path):
        rows = [["2020010100000%d" % (i % 10), "http://example.com/same",
                 "200", "text/html", "D"] for i in range(5000)]
        summary = _run(rows, tmp_path, limit=6000)
        assert summary["stats"]["unique_urls"] == 1
        assert summary["historical_urls"][0]["capture_count"] == 5000

    def test_tracking_parameter_explosion_collapses_to_one_record(self, tmp_path):
        rows = [["2020010100000%d" % (i % 10),
                 "http://example.com/p?utm_source=camp%d&id=1" % i,
                 "200", "text/html", "D%d" % i] for i in range(2000)]
        summary = _run(rows, tmp_path, limit=3000)
        assert summary["stats"]["unique_urls"] == 1
        assert summary["stats"]["merged_tracking_variants"] == 1999
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        params = [r for r in store.all() if r["type"] == "historical_parameter"]
        assert {p["value"]["name"] for p in params} == {"id"}

    def test_giant_individual_record_is_rejected_not_stored(self, tmp_path):
        rows = [["20200101000000", "http://example.com/" + "A" * 2_000_000,
                 "200", "text/html", "D"],
                ["20200101000000", "http://example.com/ok", "200", "text/html", "E"]]
        summary = _run(rows, tmp_path)
        assert summary["stats"]["unique_urls"] == 1
        assert summary["historical_urls"][0]["url"] == "http://example.com/ok"
        assert summary["cdx_query"]["row_error_count"] == 1

    def test_summary_is_json_serializable_at_scale(self, tmp_path):
        rows = [["2020010100000%d" % (i % 10), "http://example.com/p%d?a=%d" % (i, i),
                 "200", "text/html", "D%d" % i] for i in range(500)]
        summary = _run(rows, tmp_path, limit=1000)
        json.dumps(summary)

    def test_pathological_query_strings_do_not_explode(self, tmp_path):
        long_query = "&".join(f"p{i}={i}" for i in range(500))
        rows = [["20200101000000", f"http://example.com/x?{long_query}",
                 "200", "text/html", "D"]]
        start = _time.perf_counter()
        summary = _run(rows, tmp_path)
        assert _time.perf_counter() - start < 5
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert len([r for r in store.all() if r["type"] == "historical_parameter"]) == 500


# ---------------------------------------------------------------------------
# Security / data integrity
# ---------------------------------------------------------------------------

MALICIOUS_URLS = [
    'http://example.com/</td></tr><script>alert(1)</script>',
    'http://example.com/"><img src=x onerror=alert(1)>',
    "http://example.com/'; DROP TABLE assets; --",
    'http://example.com/{"injected": "json"}',
    "http://example.com/../../../../etc/passwd",
    "http://example.com/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "http://example.com/\\..\\..\\windows\\system32",
    "http://example.com/x?q=<svg/onload=alert(1)>",
    "http://example.com/" + "‮" + "gnp.exe",
]


class TestSecurity:
    def _persisted(self, tmp_path, urls):
        rows = [["2020010100000%d" % (i % 10), u, "200", "text/html", "D%d" % i]
                for i, u in enumerate(urls)]
        _run(rows, tmp_path)
        return wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()

    def test_malicious_urls_round_trip_through_json_intact_and_safe(self, tmp_path):
        records = self._persisted(tmp_path, MALICIOUS_URLS)
        blob = json.dumps(records)
        assert json.loads(blob) == records  # no injection into the JSON document

    def test_newline_injection_never_reaches_persistence(self, tmp_path):
        records = self._persisted(tmp_path, [
            "http://example.com/a\nFAKE LOG LINE",
            "http://example.com/b\r\nSet-Cookie: x=y",
            "http://example.com/ok",
        ])
        urls = [r["value"]["url"] for r in records if r["type"] == wb.HISTORICAL_URL_FINDING_TYPE]
        assert urls == ["http://example.com/ok"]

    def test_no_control_characters_survive_into_any_persisted_string(self, tmp_path):
        records = self._persisted(tmp_path, MALICIOUS_URLS + [
            "http://example.com/c\x00d", "http://example.com/e\x1bf"])
        blob = json.dumps(records)
        for record in records:
            for text in (json.dumps(record["value"]), " ".join(record["evidence"])):
                assert not wb._CONTROL_CHAR_RE.search(text.replace("\\n", "").replace("\\u", ""))

    def test_path_traversal_strings_are_data_not_filesystem_operations(self, tmp_path):
        out = tmp_path / "output"
        self._persisted(tmp_path, ["http://example.com/../../../../etc/passwd"])
        # Exactly one file, in the directory we asked for.
        assert sorted(p.name for p in out.iterdir()) == ["pending_assets.json"]

    def test_output_directory_is_the_only_thing_written(self, tmp_path):
        out = tmp_path / "output"
        _run(SAMPLE_ROWS, tmp_path)
        assert [p.name for p in tmp_path.iterdir()] == ["output"]
        assert [p.name for p in out.iterdir()] == ["pending_assets.json"]

    def test_no_temp_files_are_left_behind(self, tmp_path):
        _run(SAMPLE_ROWS, tmp_path)
        out = tmp_path / "output"
        assert not [p for p in out.iterdir() if p.name.startswith(".pending_assets_")]

    def test_provider_error_bodies_are_not_persisted(self, tmp_path):
        secret_body = "SECRET_TOKEN=abc123 internal.host.local"
        resp = _fake_cdx_response(500, text=secret_body)
        with mock.patch("requests.get", return_value=resp):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"),
                                            backoff=0)
        blob = json.dumps(summary) + (tmp_path / "output" / "pending_assets.json").read_text()
        assert "SECRET_TOKEN" not in blob

    def test_query_url_contains_no_credentials(self, tmp_path):
        summary = _run(SAMPLE_ROWS, tmp_path)
        q = summary["cdx_query"]["query_url"]
        assert "web.archive.org" in q
        # "urlkey" is the CDX collapse field, not a credential.
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(q).query)
        assert set(params) == {"url", "output", "fl", "matchType", "collapse", "limit"}
        for marker in ("token", "secret", "password", "authorization", "api_key"):
            assert marker not in q.lower()

    def test_module_never_contacts_the_target_only_the_archive(self, tmp_path):
        resp = _fake_cdx_response(200, text=_rows_body(SAMPLE_ROWS))
        with mock.patch("requests.get", return_value=resp) as getter:
            wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert getter.call_count == 1
        called = getter.call_args[0][0]
        assert called.startswith(wb.DEFAULT_CDX_BASE_URL)
        assert "example.com/" not in called.split("?")[0]

    def test_no_active_probe_helpers_exist_in_this_module(self):
        # The passive boundary is structural, not just documented: nothing here
        # may verify a historical URL against the live target.
        forbidden = ("probe", "verify_live", "check_alive", "head_request",
                     "exploit", "brute", "fuzz")
        for name in dir(wb):
            assert not any(f in name.lower() for f in forbidden), name

    def test_archive_url_is_never_a_javascript_or_data_scheme(self, tmp_path):
        records = self._persisted(tmp_path, ["http://example.com/ok"])
        for r in records:
            for snap in r["value"].get("snapshots", []):
                if snap.get("archive_url"):
                    assert snap["archive_url"].startswith("https://web.archive.org/web/")


# ---------------------------------------------------------------------------
# Persistence behaviour
# ---------------------------------------------------------------------------

class TestPersistenceBehaviour:
    def test_repeated_execution_preserves_prior_records(self, tmp_path):
        _run(SAMPLE_ROWS, tmp_path)
        first = len(wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all())
        _run(SAMPLE_ROWS, tmp_path)
        second = len(wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all())
        assert second == first * 2  # append-only; dedup is surface_mapper's job

    def test_other_modules_records_are_never_disturbed(self, tmp_path):
        out = tmp_path / "output"
        out.mkdir()
        foreign = [{"type": "dns_record", "target": "other.com", "value": {"records": ["1.1.1.1"]},
                    "evidence": [], "confidence": "HIGH", "source": "passive_recon.py",
                    "timestamp": "t", "metadata": {}}]
        (out / "pending_assets.json").write_text(json.dumps(foreign))
        _run(SAMPLE_ROWS, tmp_path)
        assert wb.PendingAssetsStore(output_dir=str(out)).all()[0] == foreign[0]

    def test_corrupt_persisted_state_is_reported_not_silently_ignored(self, tmp_path):
        out = tmp_path / "output"
        out.mkdir()
        (out / "pending_assets.json").write_text("{corrupt")
        summary = _run(SAMPLE_ROWS, tmp_path)
        assert any(e.get("stage") == "persistence" for e in summary["errors"])

    def test_one_unparseable_persisted_url_does_not_disable_correlation(self, tmp_path):
        # REGRESSION (P1): load_current_surface raised ValueError on a single
        # bad URL; run_wayback_intel caught it and the current surface silently
        # became EMPTY, so every historical URL in the run was misreported.
        out = tmp_path / "output"
        store = wb.PendingAssetsStore(output_dir=str(out))
        store.add(wb.make_finding("crawled_url", SAFE_TARGET,
                                   {"url": "http://example.com/old-page"}, [], "HIGH"))
        store.add(wb.make_finding("crawled_url", SAFE_TARGET,
                                   {"url": "http://[::1"}, [], "HIGH"))
        surface = wb.load_current_surface(store=store)
        assert wb._normalize_url("http://example.com/old-page") in surface["normalized_urls"]
        assert len(surface["skipped"]) == 1

    def test_skipped_surface_urls_are_reported_in_the_summary(self, tmp_path):
        out = tmp_path / "output"
        store = wb.PendingAssetsStore(output_dir=str(out))
        store.add(wb.make_finding("crawled_url", SAFE_TARGET, {"url": "http://[::1"}, [], "HIGH"))
        store.add(wb.make_finding("crawled_url", SAFE_TARGET,
                                   {"url": "http://example.com/old-page"}, [], "HIGH"))
        summary = _run(SAMPLE_ROWS, tmp_path)
        entry = next(e for e in summary["errors"] if e.get("stage") == "current_surface_load")
        assert entry["skipped"]

    def test_non_dict_and_non_string_persisted_values_are_survived(self, tmp_path):
        out = tmp_path / "output"
        out.mkdir()
        (out / "pending_assets.json").write_text(json.dumps([
            {"type": "crawled_url", "value": "not a dict"},
            {"type": "crawled_url", "value": {"url": 12345}},
            {"type": "crawled_url", "value": {"urls": "not a list"}},
            {"type": "crawled_url", "value": {"urls": [None, 5, {}]}},
            "not even a record",
            None,
        ]))
        store = wb.PendingAssetsStore(output_dir=str(out))
        surface = wb.load_current_surface(store=store)
        assert surface["normalized_urls"] == set()


# ---------------------------------------------------------------------------
# Downstream integration
# ---------------------------------------------------------------------------

from reconhound import surface_mapper as sm  # noqa: E402
from reconhound import risk_engine as rk  # noqa: E402
from reconhound import report_generator as rg  # noqa: E402
from reconhound.core.orchestrator import _compact_stats  # noqa: E402


class TestSurfaceMapperIntegration:
    def _graph(self, tmp_path, rows=None, **kwargs):
        _run(rows or SAMPLE_ROWS, tmp_path, **kwargs)
        records = wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        mapper = sm.SurfaceMapper(SAFE_TARGET, output_dir=str(tmp_path / "output"), autosave=False)
        summary = mapper.ingest_many(records)
        return mapper, summary, records

    def test_all_findings_ingest_without_errors(self, tmp_path):
        mapper, summary, records = self._graph(tmp_path)
        assert summary["errors"] == 0
        assert summary["ingested"] == len(records)
        assert mapper.state["ingestion_errors"] == []

    def test_historical_urls_become_endpoints_marked_historical(self, tmp_path):
        # REGRESSION (P1): the module emitted historical_endpoint /
        # historical_path / historical_static_asset, none of which are in
        # surface_mapper's dispatch table. They fell through to the generic
        # handler, which still minted an endpoint asset but WITHOUT the
        # `historical` marker — a historical-only URL sat in the graph
        # indistinguishable from a currently observed endpoint.
        mapper, _, _ = self._graph(tmp_path)
        endpoints = [a for a in mapper.state["assets"].values() if a["asset_type"] == "endpoint"]
        assert endpoints
        for asset in endpoints:
            assert asset["attributes"].get("historical", {}).get("value") is True, asset["value"]

    def test_discovery_type_survives_into_the_graph(self, tmp_path):
        mapper, _, _ = self._graph(tmp_path)
        seen = {
            a["attributes"]["discovery_type"]["value"]
            for a in mapper.state["assets"].values()
            if a["asset_type"] == "endpoint" and "discovery_type" in a["attributes"]
        }
        assert {"historical_endpoint", "historical_path", "historical_static_asset"} <= seen

    def test_historical_parameters_become_parameter_assets(self, tmp_path):
        mapper, _, _ = self._graph(tmp_path)
        params = [a for a in mapper.state["assets"].values() if a["asset_type"] == "parameter"]
        assert {a["value"]["name"] for a in params} >= {"id", "debug"}

    def test_out_of_scope_hosts_never_enter_the_graph(self, tmp_path):
        rows = TestScopeEnforcement.OUT_OF_SCOPE_ROWS
        mapper, _, _ = self._graph(tmp_path, rows=rows)
        hosts = {a["value"] for a in mapper.state["assets"].values() if a["asset_type"] == "hostname"}
        assert "spam-unrelated.net" not in hosts
        assert "notexample.com" not in hosts
        assert "example.com.evil.net" not in hosts

    def test_provider_failure_does_not_create_negative_result_memory(self, tmp_path):
        resp = _fake_cdx_response(503, text="")
        with mock.patch("requests.get", return_value=resp):
            wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"), backoff=0)
        records = wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        mapper = sm.SurfaceMapper(SAFE_TARGET, output_dir=str(tmp_path / "output"), autosave=False)
        mapper.ingest_many(records)
        assert mapper.state["negative_results"] == {}

    def test_duplicate_runs_do_not_inflate_the_graph(self, tmp_path):
        _run(SAMPLE_ROWS, tmp_path)
        _run(SAMPLE_ROWS, tmp_path)
        records = wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        mapper = sm.SurfaceMapper(SAFE_TARGET, output_dir=str(tmp_path / "output"), autosave=False)
        mapper.ingest_many(records)
        endpoints = [a for a in mapper.state["assets"].values() if a["asset_type"] == "endpoint"]
        single = sm.SurfaceMapper(SAFE_TARGET, output_dir=str(tmp_path / "o2"), autosave=False)
        single.ingest_many(records[: len(records) // 2])
        assert len(endpoints) == len(
            [a for a in single.state["assets"].values() if a["asset_type"] == "endpoint"])

    def test_malicious_url_strings_do_not_corrupt_the_graph(self, tmp_path):
        rows = [["2020010100000%d" % (i % 10), u, "200", "text/html", "D%d" % i]
                for i, u in enumerate(MALICIOUS_URLS)]
        mapper, summary, _ = self._graph(tmp_path, rows=rows)
        assert summary["errors"] == 0
        assert mapper.state["ingestion_errors"] == []
        json.dumps(mapper.state)

    def test_check_state_is_uncertain_not_confirmed(self, tmp_path):
        # Historical evidence must never register as a confident positive for
        # a current-state check.
        mapper, _, _ = self._graph(tmp_path)
        states = {rec["state"] for rec in mapper.state["check_states"].values()}
        assert states <= {sm.CHECK_FOUND_UNCERTAIN, sm.CHECK_FOUND}


class TestRiskEngineIntegration:
    def _assess(self, tmp_path):
        _run(SAMPLE_ROWS, tmp_path)
        records = wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        mapper = sm.SurfaceMapper(SAFE_TARGET, output_dir=str(tmp_path / "output"), autosave=False)
        mapper.ingest_many(records)
        mapper.save()
        return rk.run_risk_engine(mapper, output_dir=str(tmp_path / "output"))

    def test_no_unclassified_historical_signals(self, tmp_path):
        # REGRESSION (P1): this module used to emit historical_endpoint /
        # historical_path / historical_static_asset, types risk_engine has no
        # rule for. They were filed as "unclassified:<type>" — recorded, but
        # with no rule basis and no connection to risk_engine's own
        # "context.md §10 item 5" handling of historical assets.
        assessment = self._assess(tmp_path)
        categories = {s.get("category") for s in assessment["signals"]}
        assert not any(str(c).startswith("unclassified:historical") for c in categories)

    def test_risk_engine_completes_cleanly_over_historical_findings(self, tmp_path):
        assessment = self._assess(tmp_path)
        assert assessment["errors"] == []
        for signal in assessment["signals"]:
            assert signal["severity"] in ("LOW", "INFO", "MEDIUM", "HIGH", "CRITICAL")

    def test_historical_endpoints_never_reach_the_investigation_queue_as_confirmed(self, tmp_path):
        # Whatever severity machinery applies, historical evidence must never
        # be presented as a confirmed current finding.
        assessment = self._assess(tmp_path)
        for entry in assessment["investigation_queue"]:
            assert entry.get("severity") in ("LOW", "INFO", "MEDIUM", "HIGH", "CRITICAL")

    def test_assessment_is_serializable(self, tmp_path):
        json.dumps(self._assess(tmp_path))


class TestOrchestratorIntegration:
    def _summary(self, tmp_path, **kwargs):
        resp = _fake_cdx_response(**kwargs)
        with mock.patch("requests.get", return_value=resp):
            return wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"),
                                         backoff=0)

    def test_outcome_survives_compact_stats(self, tmp_path):
        # REGRESSION (P1): _compact_stats keeps top-level bools, numbers, list
        # lengths and the single string key "status", and DROPS nested dicts.
        # With the outcome only inside `cdx_query`, a CDX outage and a genuine
        # "no archived URLs" answer produced byte-identical execution records.
        failure = _compact_stats(self._summary(tmp_path, status_code=503, text=""))
        absence = _compact_stats(self._summary(tmp_path, status_code=200,
                                                text=json.dumps([CDX_HEADER])))
        assert failure != absence
        assert failure["status"] == "error"
        assert failure["provider_failed"] is True
        assert failure["conclusive"] is False
        assert absence["status"] == "not_found"
        assert absence["provider_failed"] is False
        assert absence["conclusive"] is True

    def test_truncation_survives_compact_stats(self, tmp_path):
        rows = [["2020010100000%d" % (i % 10), "http://example.com/p%d" % i,
                 "200", "text/html", "D%d" % i] for i in range(5)]
        stats = _compact_stats(_run(rows, tmp_path, limit=5))
        assert stats["results_truncated"] is True
        assert stats["conclusive"] is False

    def test_scope_and_volume_counters_survive_compact_stats(self, tmp_path):
        summary = _run(TestScopeEnforcement.OUT_OF_SCOPE_ROWS, tmp_path)
        stats = _compact_stats(summary)
        assert stats["stats.out_of_scope_urls"] == 3
        assert stats["stats.in_scope_urls"] == 1

    def test_provider_failure_still_persists_an_observation(self, tmp_path):
        # Without this, the orchestrator sees zero ingested observations and
        # relabels the execution STATUS_NO_RESULTS — "a check that found
        # nothing is a result" — for what was actually an outage.
        self._summary(tmp_path, status_code=503, text="")
        assert wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()

    def test_historical_data_handoff_shape_is_unchanged(self, tmp_path):
        summary = _run(SAMPLE_ROWS, tmp_path)
        for item in summary["historical_data"]:
            assert set(item) >= {"url", "parameters", "evidence", "observed_at", "source"}
            assert isinstance(item["parameters"], list)

    def test_module_failure_is_isolated_never_raised(self, tmp_path):
        with mock.patch("requests.get", side_effect=RuntimeError("unexpected")):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"),
                                            backoff=0)
        assert summary["status"] == "error"
        assert summary["errors"]


class TestReportGeneratorIntegration:
    def _report(self, tmp_path, rows):
        _run(rows, tmp_path)
        records = wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        mapper = sm.SurfaceMapper(SAFE_TARGET, output_dir=str(tmp_path / "output"), autosave=False)
        mapper.ingest_many(records)
        mapper.save()
        assessment = rk.run_risk_engine(mapper, output_dir=str(tmp_path / "output"))
        document = rg.build_report_document(graph=mapper.state, assessment=assessment,
                                             output_dir=str(tmp_path / "output"))
        return document, rg.render_html_report(document)

    def test_malicious_urls_are_escaped_in_the_html_report(self, tmp_path):
        rows = [["2020010100000%d" % (i % 10), u, "200", "text/html", "D%d" % i]
                for i, u in enumerate(MALICIOUS_URLS)]
        _, html = self._report(tmp_path, rows)
        assert "<script>alert(1)</script>" not in html
        assert "onerror=alert(1)>" not in html
        assert "&lt;script&gt;" in html

    def test_json_report_is_serializable_and_preserves_historical_marking(self, tmp_path):
        document, html = self._report(tmp_path, SAMPLE_ROWS)
        blob = json.dumps(document)
        assert "historical" in blob
        assert json.loads(blob)

    def test_report_renders_without_error_for_an_empty_historical_result(self, tmp_path):
        resp = _fake_cdx_response(200, text=json.dumps([CDX_HEADER]))
        with mock.patch("requests.get", return_value=resp):
            wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"))
        mapper = sm.SurfaceMapper(SAFE_TARGET, output_dir=str(tmp_path / "output"), autosave=False)
        mapper.save()
        document = rg.build_report_document(graph=mapper.state, output_dir=str(tmp_path / "output"))
        assert rg.render_html_report(document)


# ---------------------------------------------------------------------------
# Adversarial-pass regressions
#
# Each of these was found by attacking the fixes above, not by the original
# audit list. They are kept as regressions so the bound cannot quietly go away.
# ---------------------------------------------------------------------------

class TestAdversarialRegressions:
    def test_retry_count_has_a_hard_ceiling_regardless_of_caller(self):
        # ADVERSARIAL: max_attempts was honoured verbatim, so a misconfigured
        # caller (max_attempts=100) produced 100 requests against a free public
        # service. The per-attempt delay was bounded; the total was not.
        with mock.patch("requests.get",
                        side_effect=requests.exceptions.Timeout("t")) as getter:
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, max_attempts=100, backoff=0)
        assert getter.call_count == wb.MAX_ATTEMPTS_CEILING
        assert r["attempts"] == wb.MAX_ATTEMPTS_CEILING

    def test_per_url_capture_list_is_bounded(self, tmp_path):
        # ADVERSARIAL: a record embeds its captures and the whole record
        # becomes the finding's `value` — persisted, ingested into the graph
        # and rendered. Captures per URL are unbounded with collapse=None.
        # Measured before the bound: 20,000 captures of ONE url produced a
        # 7.7 MB pending_assets.json for a single historical URL.
        n = 3000
        rows = [["20%02d0101000000" % (i % 30 + 10), "http://example.com/busy",
                 "200", "text/html", "D%d" % i] for i in range(n)]
        summary = _run(rows, tmp_path, collapse=None, limit=n + 1)
        rec = summary["historical_urls"][0]
        assert rec["capture_count"] == n              # the exact total is kept
        assert rec["snapshots_retained"] == wb.MAX_SNAPSHOTS_PER_URL
        assert rec["snapshots_truncated"] is True
        size = (tmp_path / "output" / "pending_assets.json").stat().st_size
        assert size < 500_000, size

    def test_bounded_captures_keep_the_oldest_and_newest(self, tmp_path):
        n = 500
        rows = [["20%02d0101000000" % (i % 50 + 10), "http://example.com/busy",
                 "200", "text/html", "D%d" % i] for i in range(n)]
        summary = _run(rows, tmp_path, collapse=None, limit=n + 1)
        rec = summary["historical_urls"][0]
        stamps = [s["timestamp"] for s in rec["snapshots"]]
        assert stamps[0] == rec["first_capture_timestamp"]
        assert stamps[-1] == rec["last_capture_timestamp"]

    def test_aggregates_are_computed_over_every_capture_not_the_retained_sample(self, tmp_path):
        rows = ([["20100101000000", "http://example.com/busy", "200", "text/html", "A"]]
                + [["20%02d0101000000" % (i % 30 + 11), "http://example.com/busy",
                    "301", "text/html", "B%d" % i] for i in range(300)]
                + [["20990101000000", "http://example.com/busy", "500", "text/html", "Z"]])
        summary = _run(rows, tmp_path, collapse=None, limit=1000)
        rec = summary["historical_urls"][0]
        assert rec["status_codes_seen"] == [200, 301, 500]
        assert rec["capture_count"] == 302

    def test_url_variant_list_is_bounded_but_counted_exactly(self, tmp_path):
        rows = [["2020010100000%d" % (i % 10),
                 "http://example.com/p?utm_source=c%d&id=1" % i,
                 "200", "text/html", "D%d" % i] for i in range(500)]
        summary = _run(rows, tmp_path, limit=1000)
        rec = summary["historical_urls"][0]
        assert rec["variant_count"] == 500
        assert len(rec["url_variants"]) == wb.MAX_URL_VARIANTS_PER_RECORD
        assert rec["url_variants_truncated"] is True

    def test_one_endpoint_asset_per_endpoint_not_one_per_query_string(self, tmp_path):
        # ADVERSARIAL: the URL finding used the full captured URL as its graph
        # identity while the parameter finding used the bare path, so ONE
        # endpoint produced TWO endpoint assets and only one of them carried
        # the `historical` marker.
        rows = [["20200101000000", "http://example.com/api/users?id=1", "200", "application/json", "A"],
                ["20200102000000", "http://example.com/api/users?id=2", "200", "application/json", "B"],
                ["20200103000000", "http://example.com/api/users?page=3", "200", "application/json", "C"]]
        _run(rows, tmp_path)
        records = wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        mapper = sm.SurfaceMapper(SAFE_TARGET, output_dir=str(tmp_path / "output"), autosave=False)
        mapper.ingest_many(records)
        endpoints = [a for a in mapper.state["assets"].values() if a["asset_type"] == "endpoint"]
        assert len(endpoints) == 1
        assert endpoints[0]["value"] == "http://example.com/api/users"
        assert endpoints[0]["attributes"]["historical"]["value"] is True
        params = {a["value"]["name"] for a in mapper.state["assets"].values()
                  if a["asset_type"] == "parameter"}
        assert params == {"id", "page"}

    def test_captured_url_is_preserved_alongside_the_endpoint_identity(self, tmp_path):
        _run([["20200101000000", "http://example.com/a?id=1", "200", "text/html", "A"]], tmp_path)
        records = wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        url_finding = next(r for r in records if r["type"] == wb.HISTORICAL_URL_FINDING_TYPE)
        assert url_finding["value"]["url"] == "http://example.com/a"
        assert url_finding["value"]["captured_url"] == "http://example.com/a?id=1"

    def test_url_with_no_resolvable_host_fails_closed_and_is_reported(self, tmp_path):
        # ADVERSARIAL: a CDX row without a scheme has no parseable hostname, so
        # scope cannot be established. It must not be persisted, and it must
        # not vanish silently either.
        summary = _run([["20200101000000", "example.com/path", "200", "text/html", "D"]], tmp_path)
        assert summary["stats"]["in_scope_urls"] == 0
        assert summary["out_of_scope_urls"] == ["example.com/path"]
        assert wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all() == []

    def test_truncated_json_body_is_malformed_not_a_short_result(self):
        body = _rows_body([["20200101000000", "http://example.com/p", "200", "text/html", "D"]])[:-8]
        resp = _fake_cdx_response(200, text=body)
        with mock.patch("requests.get", return_value=resp):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
        assert r["status"] == "error"
        assert r["error_class"] == wb.ERROR_CLASS_MALFORMED_RESPONSE
        assert r["conclusive"] is False

    def test_homograph_and_punycode_hosts_are_out_of_scope(self, tmp_path):
        rows = [["20200101000000", "http://exаmple.com/x", "200", "text/html", "A"],
                ["20200101000000", "http://xn--exmple-cua.com/x", "200", "text/html", "B"]]
        summary = _run(rows, tmp_path)
        assert summary["stats"]["in_scope_urls"] == 0

    def test_trailing_dot_host_is_still_in_scope(self, tmp_path):
        summary = _run([["20200101000000", "http://EXAMPLE.COM./x", "200", "text/html", "A"]],
                       tmp_path)
        assert summary["stats"]["in_scope_urls"] == 1

    def test_canonicalization_is_idempotent_under_encoding_pressure(self):
        for url in ["http://example.com/p?utm_source=a%26b&id=1%20x",
                    "http://example.com/p?a=1&a=2&utm_medium=z",
                    "http://example.com/p?%75tm_source=x&id=1",
                    "http://example.com/p?q=%E2%9C%93&utm_id=9"]:
            once = wb._canonical_url(url)
            assert wb._canonical_url(once) == once

    def test_url_with_only_tracking_params_merges_with_its_bare_form(self, tmp_path):
        summary = _run([
            ["20200101000000", "http://example.com/p?utm_source=x", "200", "text/html", "A"],
            ["20200102000000", "http://example.com/p", "200", "text/html", "B"],
        ], tmp_path)
        assert summary["stats"]["unique_urls"] == 1
        assert summary["historical_urls"][0]["variant_count"] == 2

    def test_grouping_failure_is_never_reported_as_a_complete_empty_result(self, tmp_path):
        # ADVERSARIAL: a failure AFTER a successful fetch produced the most
        # dangerous shape possible — status "found", conclusive True,
        # unique_urls 0, nothing persisted. That asserts "the archive was
        # checked completely and there is nothing there" on the strength of an
        # internal exception.
        resp = _fake_cdx_response(200, text=_rows_body(SAMPLE_ROWS))
        with mock.patch("requests.get", return_value=resp), \
             mock.patch.object(_wb_mod, "group_historical_urls",
                                side_effect=RuntimeError("boom")):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"),
                                            backoff=0)
        assert summary["conclusive"] is False
        assert summary["completeness"] == wb.COMPLETENESS_INCONCLUSIVE
        assert any(e.get("stage") == "grouping" for e in summary["errors"])
        persisted = wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        assert [r["type"] for r in persisted] == [wb.INCONCLUSIVE_FINDING_TYPE]

    def test_one_unclassifiable_record_does_not_discard_the_rest(self, tmp_path):
        # ADVERSARIAL: classification ran in a list comprehension, so a single
        # bad record aborted the whole batch and every other historical URL
        # was silently lost.
        real = _wb_mod.classify_historical_url

        def flaky(record):
            if record.get("url", "").endswith("/removed-secret-page"):
                raise RuntimeError("bad record")
            return real(record)

        resp = _fake_cdx_response(200, text=_rows_body(SAMPLE_ROWS))
        with mock.patch("requests.get", return_value=resp), \
             mock.patch.object(_wb_mod, "classify_historical_url", flaky):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"),
                                            backoff=0)
        assert summary["stats"]["unique_urls"] == 3  # 4 grouped, 1 unclassifiable
        assert summary["conclusive"] is False
        assert any(e.get("stage") == "classification" for e in summary["errors"])

    @pytest.mark.parametrize("stage", [
        "correlate_against_current_surface",
        "persist_historical_findings",
        "build_historical_data_export",
    ])
    def test_any_late_stage_failure_downgrades_completeness(self, tmp_path, stage):
        resp = _fake_cdx_response(200, text=_rows_body(SAMPLE_ROWS))
        with mock.patch("requests.get", return_value=resp), \
             mock.patch.object(_wb_mod, stage, side_effect=RuntimeError("boom")):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"),
                                            backoff=0)
        assert summary["conclusive"] is False
        assert summary["errors"]

    def test_duplicate_header_columns_degrade_gracefully(self):
        header = ["timestamp", "original", "original", "mimetype", "digest"]
        body = json.dumps([header, ["20200101000000", "http://example.com/a",
                                     "http://example.com/b", "t", "d"]])
        with mock.patch("requests.get", return_value=_fake_cdx_response(200, text=body)):
            r = wb.fetch_cdx_snapshots(SAFE_TARGET, backoff=0)
        assert r["status"] == "found"
        assert len(r["snapshots"]) == 1

    def test_validate_target_has_no_catastrophic_backtracking(self):
        for probe in ["a" * 100 + "." * 50 + "com", ("a-" * 120) + ".com",
                      "a." * 200 + "com", "-" * 260 + ".com", ("a" * 63 + ".") * 40 + "com"]:
            start = _time.perf_counter()
            try:
                wb.validate_target(probe)
            except wb.ScopeError:
                pass
            assert _time.perf_counter() - start < 1.0, probe[:40]


# ---------------------------------------------------------------------------
# End-to-end hand-off to the documented consumer
# ---------------------------------------------------------------------------

from reconhound import endpoint_discovery as ed  # noqa: E402


class TestEndpointDiscoveryHandoff:
    """
    endpoint_discovery.correlate_historical_parameters() is the pre-existing
    consumer this module's `historical_data` export was shaped for. These
    exercise the real function, not a mock of it.
    """

    def test_export_is_consumed_without_error(self, tmp_path):
        summary = _run(SAMPLE_ROWS, tmp_path)
        result = ed.correlate_historical_parameters(
            current_endpoints=[{"url": "https://example.com/old-page"}],
            historical_data=summary["historical_data"], target=SAFE_TARGET, store=None)
        assert result["endpoints"]
        assert all(e["historical"] is True for e in result["endpoints"])

    def test_parameters_survive_the_handoff(self, tmp_path):
        summary = _run(SAMPLE_ROWS, tmp_path)
        result = ed.correlate_historical_parameters(
            current_endpoints=[], historical_data=summary["historical_data"],
            target=SAFE_TARGET, store=None)
        assert {p["name"] for p in result["parameters"]} >= {"id", "debug"}

    def test_tracking_parameters_are_not_handed_downstream(self, tmp_path):
        rows = [["20200101000000", "http://example.com/p?utm_source=x&id=1",
                 "200", "text/html", "A"]]
        summary = _run(rows, tmp_path)
        result = ed.correlate_historical_parameters(
            current_endpoints=[], historical_data=summary["historical_data"],
            target=SAFE_TARGET, store=None)
        assert {p["name"] for p in result["parameters"]} == {"id"}

    def test_out_of_scope_urls_never_reach_the_consumer(self, tmp_path):
        summary = _run(TestScopeEnforcement.OUT_OF_SCOPE_ROWS, tmp_path)
        result = ed.correlate_historical_parameters(
            current_endpoints=[], historical_data=summary["historical_data"],
            target=SAFE_TARGET, store=None)
        for endpoint in result["endpoints"]:
            assert "example.com" in urllib.parse.urlsplit(endpoint["url"]).netloc

    def test_provider_failure_hands_over_nothing_rather_than_a_false_empty(self, tmp_path):
        resp = _fake_cdx_response(503, text="")
        with mock.patch("requests.get", return_value=resp):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"),
                                            backoff=0)
        result = ed.correlate_historical_parameters(
            current_endpoints=[], historical_data=summary["historical_data"],
            target=SAFE_TARGET, store=None)
        assert result["endpoints"] == []
        # ...and the run itself still says the check was inconclusive.
        assert summary["conclusive"] is False


class TestGraphAttributeHygiene:
    """
    A historical observation must not leave attributes on a graph asset that
    read as CURRENT state. surface_mapper._h_endpoint promotes value["method"],
    value["status_code"], value["content_type"] and value["category"] straight
    onto the endpoint asset, so this module must not put any of those on a
    historical record.
    """

    CURRENT_STATE_KEYS = ("method", "status_code", "content_type", "category")

    def test_historical_findings_carry_no_current_state_keys(self, tmp_path):
        _run(SAMPLE_ROWS, tmp_path)
        records = wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        for record in records:
            if record["type"] != wb.HISTORICAL_URL_FINDING_TYPE:
                continue
            for key in self.CURRENT_STATE_KEYS:
                assert key not in record["value"], key

    def test_endpoint_assets_get_no_current_status_code_from_history(self, tmp_path):
        _run(SAMPLE_ROWS, tmp_path)
        records = wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        mapper = sm.SurfaceMapper(SAFE_TARGET, output_dir=str(tmp_path / "output"), autosave=False)
        mapper.ingest_many(records)
        for asset in mapper.state["assets"].values():
            if asset["asset_type"] != "endpoint":
                continue
            assert "status_code" not in asset["attributes"]
            assert "content_type" not in asset["attributes"]
            assert asset["attributes"]["historical"]["value"] is True

    def test_historical_status_codes_stay_plural_and_scoped_to_captures(self, tmp_path):
        summary = _run(SAMPLE_ROWS, tmp_path)
        for record in summary["historical_urls"]:
            assert "status_codes_seen" in record
            assert "status_code" not in record


class TestCurrentSurfaceFailureSemantics:
    """
    Pass-4 adversarial findings: the correlation stage can fail independently
    of the archive query, and a reader must be able to tell.
    """

    def test_unreadable_store_does_not_raise_out_of_load_current_surface(self, tmp_path):
        # ADVERSARIAL: only PersistenceError was caught, so an OSError
        # (permission change, I/O error, full disk) escaped the helper. A
        # caller cannot distinguish "no current surface" from "this helper
        # exploded" when it gets an exception instead of a result.
        store = wb.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch.object(wb.PendingAssetsStore, "all",
                                side_effect=OSError("permission denied")):
            surface = wb.load_current_surface(store=store)
        assert surface["normalized_urls"] == set()
        assert len(surface["skipped"]) == 1
        assert "could not be read" in surface["skipped"][0]

    def test_correlation_failure_is_visible_as_its_own_axis(self, tmp_path):
        # `conclusive` is about the completeness of the CDX result set. A
        # correlation that never ran is a DIFFERENT fact and needs its own
        # scalar, or the compacted orchestrator record shows a clean,
        # complete-looking run in which "historically removed" was never
        # actually established.
        resp = _fake_cdx_response(200, text=_rows_body(SAMPLE_ROWS))
        with mock.patch("requests.get", return_value=resp), \
             mock.patch.object(wb.PendingAssetsStore, "all",
                                side_effect=OSError("permission denied")):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"),
                                            backoff=0)
        assert summary["current_surface_compared"] is False
        assert _compact_stats(summary)["current_surface_compared"] is False
        assert {r["relationship_to_current_surface"] for r in summary["historical_urls"]} \
            == {wb.STATE_UNKNOWN_NO_CURRENT_SURFACE}

    def test_successful_comparison_reports_the_flag_true(self, tmp_path):
        out = tmp_path / "output"
        store = wb.PendingAssetsStore(output_dir=str(out))
        store.add(wb.make_finding("crawled_url", SAFE_TARGET,
                                   {"url": "http://example.com/old-page"}, [], "HIGH"))
        summary = _run(SAMPLE_ROWS, tmp_path)
        assert summary["current_surface_compared"] is True
        assert _compact_stats(summary)["current_surface_compared"] is True

    def test_current_surface_scales_linearly(self, tmp_path):
        out = tmp_path / "output"
        out.mkdir()
        records = [{"type": "crawled_url", "target": SAFE_TARGET,
                    "value": {"url": "http://example.com/p%d" % i},
                    "evidence": [], "confidence": "HIGH", "source": "crawler.py",
                    "timestamp": "t", "metadata": {}} for i in range(20000)]
        (out / "pending_assets.json").write_text(json.dumps(records))
        store = wb.PendingAssetsStore(output_dir=str(out))
        start = _time.perf_counter()
        surface = wb.load_current_surface(store=store)
        elapsed = _time.perf_counter() - start
        assert len(surface["normalized_urls"]) == 20000
        assert elapsed < 10, elapsed

    def test_summary_never_contains_a_raw_set(self, tmp_path):
        summary = _run(SAMPLE_ROWS, tmp_path)

        def sets_in(obj, path="root"):
            if isinstance(obj, set):
                return [path]
            if isinstance(obj, dict):
                return [p for k, v in obj.items() for p in sets_in(v, f"{path}.{k}")]
            if isinstance(obj, list):
                return [p for i, v in enumerate(obj) for p in sets_in(v, f"{path}[{i}]")]
            return []

        assert sets_in(summary) == []
        json.dumps(summary)

    def test_inconclusive_marker_never_carries_the_snapshot_payload(self, tmp_path):
        rows = [["2020010100000%d" % (i % 10), "http://example.com/p%d" % i,
                 "200", "text/html", "D%d" % i] for i in range(5)]
        _run(rows, tmp_path, limit=5)
        marker = next(r for r in wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
                      if r["type"] == wb.INCONCLUSIVE_FINDING_TYPE)
        assert "snapshots" not in marker["value"]
        assert set(marker["value"]) == {
            "check", "outcome", "status", "error_class", "error", "http_status",
            "attempts", "retries", "completeness",
        }

    @pytest.mark.parametrize("cap", [1, 2, 3, 51])
    def test_snapshot_bound_is_correct_for_degenerate_caps(self, cap, monkeypatch):
        monkeypatch.setattr(wb, "MAX_SNAPSHOTS_PER_URL", cap)
        snaps = [{"timestamp": "2020010100000%d" % (i % 10)} for i in range(100)]
        assert len(wb._bounded_snapshots(snaps)) == cap

    def test_identical_timestamps_do_not_break_grouping(self):
        snaps = [wb.normalize_snapshot({
            "timestamp": "20200101000000", "original": "http://example.com/p",
            "statuscode": "200", "mimetype": "t", "digest": "d%d" % i,
        }) for i in range(200)]
        [rec] = wb.group_historical_urls(snaps, SAFE_TARGET)
        assert rec["capture_count"] == 200
        assert rec["snapshots_retained"] == wb.MAX_SNAPSHOTS_PER_URL
        assert rec["first_capture_timestamp"] == rec["last_capture_timestamp"]


class TestComposedFailureModes:
    """
    Pass-5: the fixes must compose. Each was verified alone; these exercise
    several failing at once, which is how a real bad day looks.
    """

    def test_retry_truncation_scope_and_bad_rows_together(self, tmp_path):
        rows = [
            ["20200101000000", "http://example.com/a?utm_source=x", "200", "t", "A"],
            ["20200101000000", "http://spam-unrelated.net/b", "200", "t", "B"],
            ["bad row"],
            ["20200101000000", "http://example.com/c\nInjected", "200", "t", "C"],
        ]
        responses = [_fake_cdx_response(503, text=""),
                     _fake_cdx_response(200, text=_rows_body(rows))]
        with mock.patch("requests.get", side_effect=responses):
            summary = wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"),
                                            limit=3, backoff=0)
        assert summary["status"] == "found"
        assert summary["conclusive"] is False          # truncated + bad rows
        assert summary["results_truncated"] is True
        assert summary["stats"]["retries"] == 1        # the 503 was retried, then succeeded
        assert summary["stats"]["in_scope_urls"] == 1  # spam host excluded
        assert summary["stats"]["out_of_scope_urls"] == 1
        assert summary["stats"]["row_errors"] == 2     # short row + control-char URL
        persisted = {r["type"] for r in
                     wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()}
        # Real findings AND an honest incompleteness marker, together.
        assert persisted == {wb.HISTORICAL_URL_FINDING_TYPE, wb.INCONCLUSIVE_FINDING_TYPE}

    def test_partial_success_never_loses_the_urls_it_did_find(self, tmp_path):
        rows = [["20200101000000", "http://example.com/found", "200", "t", "A"],
                ["bad"], ["also bad"]]
        summary = _run(rows, tmp_path, limit=1000)
        assert [r["url"] for r in summary["historical_urls"]] == ["http://example.com/found"]
        assert summary["conclusive"] is False


class TestInconclusiveDownstreamSemantics:
    """
    The single most important guarantee in this module: a provider failure
    must never become remembered absence anywhere downstream.
    """

    def _ingest_failure(self, tmp_path, code=503):
        resp = _fake_cdx_response(code, text="")
        with mock.patch("requests.get", return_value=resp):
            wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"), backoff=0)
        records = wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        mapper = sm.SurfaceMapper(SAFE_TARGET, output_dir=str(tmp_path / "output"), autosave=False)
        mapper.ingest_many(records)
        return mapper

    def test_inconclusive_check_does_not_suppress_a_future_recheck(self, tmp_path):
        mapper = self._ingest_failure(tmp_path)
        host_id = next(a["id"] for a in mapper.state["assets"].values()
                       if a["asset_type"] == "hostname")
        assert mapper.state["negative_results"] == {}
        assert mapper.has_been_checked(host_id, wb.INCONCLUSIVE_FINDING_TYPE) is False

    def test_inconclusive_check_state_is_never_a_confident_positive(self, tmp_path):
        mapper = self._ingest_failure(tmp_path)
        states = {rec["state"] for rec in mapper.state["check_states"].values()}
        assert states == {sm.CHECK_FOUND_UNCERTAIN}

    def test_inconclusive_finding_never_enters_the_investigation_queue(self, tmp_path):
        mapper = self._ingest_failure(tmp_path)
        mapper.save()
        assessment = rk.run_risk_engine(mapper, output_dir=str(tmp_path / "output"))
        assert assessment["investigation_queue"] == []
        assert all(s["severity"] == "INFO" for s in assessment["signals"])

    def test_inconclusive_outcome_reaches_the_rendered_report(self, tmp_path):
        mapper = self._ingest_failure(tmp_path)
        mapper.save()
        assessment = rk.run_risk_engine(mapper, output_dir=str(tmp_path / "output"))
        document = rg.build_report_document(graph=mapper.state, assessment=assessment,
                                             output_dir=str(tmp_path / "output"))
        html = rg.render_html_report(document)
        assert "inconclusive" in html.lower()

    def test_repeated_failures_stay_distinct_observations(self, tmp_path):
        for _ in range(3):
            resp = _fake_cdx_response(503, text="")
            with mock.patch("requests.get", return_value=resp):
                wb.run_wayback_intel(SAFE_TARGET, output_dir=str(tmp_path / "output"),
                                      backoff=0)
        records = wb.PendingAssetsStore(output_dir=str(tmp_path / "output")).all()
        assert len(records) == 3
        mapper = sm.SurfaceMapper(SAFE_TARGET, output_dir=str(tmp_path / "output"), autosave=False)
        mapper.ingest_many(records)
        assert len(mapper.state["observations"]) == 3
        assert mapper.state["negative_results"] == {}


class TestStandaloneEntryPoint:
    def test_scope_error_exits_with_code_two(self, tmp_path):
        import subprocess
        env = dict(os.environ, PYTHONPATH=os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))
        proc = subprocess.run(
            [sys.executable, "-m", "reconhound.wayback_intel", "--target", "*.evil.com"],
            capture_output=True, text=True, env=env, cwd=str(tmp_path))
        assert proc.returncode == 2
        assert "scope error" in proc.stdout

    def test_successful_run_prints_json(self, tmp_path):
        resp = _fake_cdx_response(200, text=_rows_body(SAMPLE_ROWS))
        argv = ["wayback_intel.py", "--target", SAFE_TARGET,
                "--output-dir", str(tmp_path / "output")]
        with mock.patch("requests.get", return_value=resp), \
             mock.patch.object(sys, "argv", argv), \
             mock.patch("builtins.print") as printer:
            _wb_mod._main()
        payload = json.loads(printer.call_args[0][0])
        assert payload["target"] == SAFE_TARGET
        assert payload["status"] == "found"
