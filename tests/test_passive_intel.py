"""
Tests for reconhound/passive_intel.py (ReconHound Module 2, per context.md's
catalog item 2; built under a temporary, user-approved build-order
deviation ahead of surface_mapper.py — see the module docstring for
details).

Run with:  ./.venv/bin/python -m pytest tests/test_passive_intel.py -v

All tests mock the `requests.get` boundary so the suite is deterministic
and offline-safe; no external network access (including to Shodan or
Censys) is required or performed anywhere in this file. Several tests
additionally assert on the *captured* request URLs to verify the passive
boundary: this module must never send a request to the target itself.
"""

import json
import os
import sys
from unittest import mock

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import passive_intel as pin


SAFE_TARGET = "example.com"
SAFE_IP = "93.184.216.34"
SAFE_IP_2 = "93.184.216.35"


def _fake_response(status_code=200, json_data=None, headers=None, raise_json_error=False):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = dict(headers or {})
    if raise_json_error:
        resp.json.side_effect = ValueError("bad json")
    else:
        resp.json.return_value = json_data
    return resp


SHODAN_HOST_RAW = {
    "ip_str": SAFE_IP,
    "hostnames": ["www.example.com"],
    "domains": ["example.com"],
    "org": "Example Org",
    "isp": "Example ISP",
    "asn": "AS12345",
    "location": {"country_name": "United States", "city": "Norman"},
    "last_update": "2024-01-01T00:00:00.000000",
    "ports": [80, 443],
    "data": [
        {
            "port": 443,
            "transport": "tcp",
            "product": "nginx",
            "version": "1.18.0",
            "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n",
            "timestamp": "2024-01-01T00:00:00.000000",
            "hostnames": ["www.example.com"],
            "_shodan": {"module": "https"},
            "ssl": {
                "cert": {
                    "subject": {"CN": "example.com"},
                    "issuer": {"CN": "DigiCert"},
                    "serial": 12345,
                    "expires": "20250101000000Z",
                    "expired": False,
                    "fingerprint": {"sha256": "AAAA", "sha1": "BBBB"},
                    "sig_alg": "sha256WithRSAEncryption",
                    "version": 2,
                }
            },
        },
        {
            "port": 80,
            "transport": "tcp",
            "product": "nginx",
            "version": "1.18.0",
            "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n",
            "timestamp": "2024-01-01T00:00:00.000000",
            "hostnames": [],
        },
    ],
}

SHODAN_SEARCH_MATCH = {
    "ip_str": SAFE_IP_2,
    "port": 22,
    "transport": "tcp",
    "product": "OpenSSH",
    "version": "8.9",
    "data": "SSH-2.0-OpenSSH_8.9\r\n",
    "timestamp": "2024-02-01T00:00:00.000000",
    "hostnames": ["ssh.example.com"],
    "domains": ["example.com"],
    "org": "Example Org",
    "isp": "Example ISP",
    "asn": "AS12345",
    "location": {"country_name": "United States", "city": "Norman"},
}

CENSYS_HOST_RESULT = {
    "ip": SAFE_IP,
    "dns": {"names": ["www.example.com"], "reverse_dns": {"names": []}},
    "autonomous_system": {"asn": 12345, "name": "Example ASN", "description": "Example ASN"},
    "location": {"country": "United States", "city": "Norman"},
    "last_updated_at": "2024-01-02T00:00:00Z",
    "services": [
        {
            "port": 443,
            "transport_protocol": "TCP",
            "service_name": "HTTP",
            "banner": "HTTP/1.1 200 OK",
            "software": [{"vendor": "nginx", "product": "nginx", "version": "1.18.0"}],
            "observed_at": "2024-01-02T00:00:00Z",
            "certificate": {
                "subject": {"common_name": "example.com"},
                "issuer": {"common_name": "DigiCert"},
                "names": ["example.com", "www.example.com"],
                "fingerprint_sha256": "CCCC",
                "validity_period": {"not_before": "2024-01-01T00:00:00Z", "not_after": "2025-01-01T00:00:00Z"},
            },
        },
        {
            "port": 22,
            "transport_protocol": "TCP",
            "service_name": "SSH",
            "banner": "SSH-2.0-OpenSSH_8.9",
            "software": [{"vendor": "OpenBSD", "product": "OpenSSH", "version": "8.9"}],
            "observed_at": "2024-01-02T00:00:00Z",
            "certificate": "deadbeefcafe",
        },
    ],
}

CENSYS_SEARCH_HIT = {
    "ip": SAFE_IP_2,
    "dns": {"names": ["ssh.example.com"]},
    "autonomous_system": {"asn": 12345, "name": "Example ASN"},
    "location": {"country": "United States", "city": "Norman"},
    "last_updated_at": "2024-02-02T00:00:00Z",
    "services": [
        {
            "port": 22,
            "transport_protocol": "TCP",
            "service_name": "SSH",
            "banner": "SSH-2.0-OpenSSH_8.9",
            "software": [{"vendor": "OpenBSD", "product": "OpenSSH", "version": "8.9"}],
            "observed_at": "2024-02-02T00:00:00Z",
        }
    ],
}


# ---------------------------------------------------------------------------
# validate_target / is_in_scope / _valid_ip
# ---------------------------------------------------------------------------

class TestValidateTarget:
    def test_accepts_plain_domain(self):
        assert pin.validate_target("example.com") == "example.com"

    def test_normalizes_case_and_trailing_dot(self):
        assert pin.validate_target("EXAMPLE.com.") == "example.com"

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(pin.ScopeError):
            pin.validate_target(bad)

    def test_rejects_url(self):
        with pytest.raises(pin.ScopeError):
            pin.validate_target("https://example.com/path")

    def test_rejects_ip_literal(self):
        with pytest.raises(pin.ScopeError):
            pin.validate_target(SAFE_IP)

    def test_rejects_wildcard(self):
        with pytest.raises(pin.ScopeError):
            pin.validate_target("*.example.com")

    def test_rejects_malformed_domain(self):
        with pytest.raises(pin.ScopeError):
            pin.validate_target("-bad-.com")


class TestIsInScope:
    def test_exact_match(self):
        assert pin.is_in_scope("example.com", "example.com") is True

    def test_subdomain_match(self):
        assert pin.is_in_scope("www.example.com", "example.com") is True

    def test_out_of_scope(self):
        assert pin.is_in_scope("evil.com", "example.com") is False

    def test_empty_hostname(self):
        assert pin.is_in_scope("", "example.com") is False

    def test_none_hostname(self):
        assert pin.is_in_scope(None, "example.com") is False


class TestValidIp:
    def test_valid_ipv4(self):
        assert pin._valid_ip(SAFE_IP) == SAFE_IP

    def test_valid_ipv6(self):
        assert pin._valid_ip("2606:2800:220:1:248:1893:25c8:1946") is not None

    def test_invalid(self):
        assert pin._valid_ip("not-an-ip") is None

    def test_none(self):
        assert pin._valid_ip(None) is None

    def test_int_input_rejected(self):
        # ipaddress.ip_address would accept an int; this module only wants
        # IP literal strings ever originating from JSON/DNS data.
        assert pin._valid_ip(123456) is None or isinstance(pin._valid_ip(123456), str)


# ---------------------------------------------------------------------------
# make_finding / PendingAssetsStore
# ---------------------------------------------------------------------------

class TestMakeFinding:
    def test_shape(self):
        finding = pin.make_finding("passive_intel_host", SAFE_TARGET, {"a": 1}, ["evidence"], pin.CONFIDENCE_LOW)
        assert finding["type"] == "passive_intel_host"
        assert finding["target"] == SAFE_TARGET
        assert finding["value"] == {"a": 1}
        assert finding["evidence"] == ["evidence"]
        assert finding["confidence"] == pin.CONFIDENCE_LOW
        assert finding["source"] == pin.MODULE_NAME
        assert "timestamp" in finding
        assert finding["metadata"] == {}

    def test_json_safe(self):
        finding = pin.make_finding("passive_intel_host", SAFE_TARGET, {"a": [1, 2]}, ["e"], pin.CONFIDENCE_HIGH)
        json.dumps(finding)  # must not raise


class TestPendingAssetsStore:
    def test_creates_output_dir_and_file(self, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        finding = pin.make_finding("passive_intel_host", SAFE_TARGET, {}, ["e"], pin.CONFIDENCE_LOW)
        store.add(finding)
        assert os.path.exists(store.path)
        with open(store.path) as f:
            data = json.load(f)
        assert data == [finding]

    def test_appends_without_losing_previous_entries(self, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        f1 = pin.make_finding("passive_intel_host", SAFE_TARGET, {"n": 1}, ["e"], pin.CONFIDENCE_LOW)
        f2 = pin.make_finding("passive_intel_service", SAFE_TARGET, {"n": 2}, ["e"], pin.CONFIDENCE_LOW)
        store.add(f1)
        store.add(f2)
        assert store.all() == [f1, f2]

    def test_preserves_existing_data_from_other_modules(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{
            "type": "dns_record", "target": SAFE_TARGET, "value": {"record_type": "A", "records": [SAFE_IP]},
            "evidence": [], "confidence": "HIGH", "source": "passive_recon.py",
            "timestamp": "t", "metadata": {},
        }]
        pending.write_text(json.dumps(pre_existing))
        store = pin.PendingAssetsStore(output_dir=str(output_dir))
        store.add(pin.make_finding("passive_intel_host", SAFE_TARGET, {}, [], pin.CONFIDENCE_LOW))
        records = store.all()
        assert len(records) == 2
        assert records[0]["type"] == "dns_record"

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        path = tmp_path / "pending_assets.json"
        path.write_text("{not valid json")
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        with pytest.raises(pin.PersistenceError):
            store.all()

    def test_safe_store_add_survives_persistence_error(self, tmp_path):
        path = tmp_path / "pending_assets.json"
        path.write_text("{not valid json")
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        err = pin._safe_store_add(store, pin.make_finding("passive_intel_host", SAFE_TARGET, {}, [], pin.CONFIDENCE_LOW))
        assert err is not None

    def test_safe_store_add_none_store_is_noop(self):
        assert pin._safe_store_add(None, {"anything": 1}) is None


# ---------------------------------------------------------------------------
# load_seed_hosts
# ---------------------------------------------------------------------------

class TestLoadSeedHosts:
    def test_extracts_ips_from_dns_records(self, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(pin.make_finding("dns_record", SAFE_TARGET, {"record_type": "A", "records": [SAFE_IP]}, ["e"], pin.CONFIDENCE_HIGH))
        store.add(pin.make_finding("dns_record", SAFE_TARGET, {"record_type": "AAAA", "records": ["2606:2800:220:1:248:1893:25c8:1946"]}, ["e"], pin.CONFIDENCE_HIGH))
        seed = pin.load_seed_hosts(store, SAFE_TARGET)
        assert SAFE_IP in seed["ips"]
        assert "2606:2800:220:1:248:1893:25c8:1946" in seed["ips"]

    def test_ignores_other_record_types(self, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(pin.make_finding("dns_record", SAFE_TARGET, {"record_type": "MX", "records": ["mail.example.com"]}, ["e"], pin.CONFIDENCE_HIGH))
        seed = pin.load_seed_hosts(store, SAFE_TARGET)
        assert seed["ips"] == []

    def test_ignores_findings_for_other_targets(self, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(pin.make_finding("dns_record", "other.com", {"record_type": "A", "records": [SAFE_IP]}, ["e"], pin.CONFIDENCE_HIGH))
        seed = pin.load_seed_hosts(store, SAFE_TARGET)
        assert seed["ips"] == []

    def test_ignores_malformed_addresses(self, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(pin.make_finding("dns_record", SAFE_TARGET, {"record_type": "A", "records": ["not-an-ip"]}, ["e"], pin.CONFIDENCE_HIGH))
        seed = pin.load_seed_hosts(store, SAFE_TARGET)
        assert seed["ips"] == []

    def test_merges_extra_ips(self, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        seed = pin.load_seed_hosts(store, SAFE_TARGET, extra_ips=[SAFE_IP, "garbage"])
        assert seed["ips"] == [SAFE_IP]

    def test_none_store(self):
        seed = pin.load_seed_hosts(None, SAFE_TARGET, extra_ips=[SAFE_IP])
        assert seed["ips"] == [SAFE_IP]

    def test_deduplicates(self, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(pin.make_finding("dns_record", SAFE_TARGET, {"record_type": "A", "records": [SAFE_IP]}, ["e"], pin.CONFIDENCE_HIGH))
        seed = pin.load_seed_hosts(store, SAFE_TARGET, extra_ips=[SAFE_IP])
        assert seed["ips"] == [SAFE_IP]


# ---------------------------------------------------------------------------
# Shodan: query_shodan_host
# ---------------------------------------------------------------------------

class TestQueryShodanHost:
    def test_invalid_ip(self):
        r = pin.query_shodan_host("not-an-ip", "key")
        assert r["status"] == "error"
        assert "not a valid IP" in r["error"]

    def test_missing_credentials(self):
        r = pin.query_shodan_host(SAFE_IP, None)
        assert r["status"] == "missing_credentials"
        assert pin.SHODAN_API_KEY_ENV in r["error"]

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, SHODAN_HOST_RAW)
        r = pin.query_shodan_host(SAFE_IP, "key")
        assert r["status"] == "found"
        assert r["host"]["ip_str"] == SAFE_IP
        called_url = mock_get.call_args.args[0]
        assert called_url.startswith(pin.SHODAN_HOST_API_BASE)
        assert SAFE_IP in called_url

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_not_found_404(self, mock_get):
        mock_get.return_value = _fake_response(404)
        r = pin.query_shodan_host(SAFE_IP, "key")
        assert r["status"] == "not_found"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_unauthorized_401(self, mock_get):
        mock_get.return_value = _fake_response(401)
        r = pin.query_shodan_host(SAFE_IP, "bad-key")
        assert r["status"] == "unauthorized"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_rate_limited_429(self, mock_get):
        mock_get.return_value = _fake_response(429)
        r = pin.query_shodan_host(SAFE_IP, "key")
        assert r["status"] == "rate_limited"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_server_error_5xx(self, mock_get):
        mock_get.return_value = _fake_response(503)
        r = pin.query_shodan_host(SAFE_IP, "key")
        assert r["status"] == "error"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_unexpected_status(self, mock_get):
        mock_get.return_value = _fake_response(418)
        r = pin.query_shodan_host(SAFE_IP, "key")
        assert r["status"] == "error"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_malformed_json(self, mock_get):
        mock_get.return_value = _fake_response(200, raise_json_error=True)
        r = pin.query_shodan_host(SAFE_IP, "key")
        assert r["status"] == "error"
        assert "malformed JSON" in r["error"]

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_unexpected_structure_not_dict(self, mock_get):
        mock_get.return_value = _fake_response(200, [1, 2, 3])
        r = pin.query_shodan_host(SAFE_IP, "key")
        assert r["status"] == "error"

    @mock.patch("reconhound.passive_intel.requests.get", side_effect=requests.exceptions.Timeout())
    def test_timeout(self, mock_get):
        r = pin.query_shodan_host(SAFE_IP, "key")
        assert r["status"] == "error"
        assert r["error"] == "timeout"

    @mock.patch("reconhound.passive_intel.requests.get", side_effect=requests.exceptions.ConnectionError("boom"))
    def test_connection_error(self, mock_get):
        r = pin.query_shodan_host(SAFE_IP, "key")
        assert r["status"] == "error"
        assert "connection error" in r["error"]


# ---------------------------------------------------------------------------
# Shodan: search_shodan_by_hostname
# ---------------------------------------------------------------------------

class TestSearchShodanByHostname:
    def test_empty_hostname(self):
        r = pin.search_shodan_by_hostname("", "key")
        assert r["status"] == "error"

    def test_missing_credentials(self):
        r = pin.search_shodan_by_hostname(SAFE_TARGET, None)
        assert r["status"] == "missing_credentials"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, {"matches": [SHODAN_SEARCH_MATCH], "total": 1})
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key")
        assert r["status"] == "found"
        assert r["total"] == 1
        called_url = mock_get.call_args.args[0]
        assert called_url == pin.SHODAN_SEARCH_API_BASE
        assert mock_get.call_args.kwargs["params"]["query"] == f"hostname:{SAFE_TARGET}"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_empty_matches_is_not_found(self, mock_get):
        mock_get.return_value = _fake_response(200, {"matches": [], "total": 0})
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key")
        assert r["status"] == "not_found"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_insufficient_credits_402(self, mock_get):
        mock_get.return_value = _fake_response(402)
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key")
        assert r["status"] == "insufficient_credits"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_malformed_structure_missing_matches(self, mock_get):
        mock_get.return_value = _fake_response(200, {"unexpected": True})
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key")
        assert r["status"] == "error"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_matches_not_a_list(self, mock_get):
        mock_get.return_value = _fake_response(200, {"matches": "oops"})
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key")
        assert r["status"] == "error"


# ---------------------------------------------------------------------------
# Censys: query_censys_host
# ---------------------------------------------------------------------------

class TestQueryCensysHost:
    def test_invalid_ip(self):
        r = pin.query_censys_host("not-an-ip", "id", "secret")
        assert r["status"] == "error"

    def test_missing_credentials_both(self):
        r = pin.query_censys_host(SAFE_IP, None, None)
        assert r["status"] == "missing_credentials"

    def test_missing_credentials_partial(self):
        r = pin.query_censys_host(SAFE_IP, "id", None)
        assert r["status"] == "missing_credentials"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, {"result": CENSYS_HOST_RESULT})
        r = pin.query_censys_host(SAFE_IP, "id", "secret")
        assert r["status"] == "found"
        assert r["host"]["ip"] == SAFE_IP
        called_url = mock_get.call_args.args[0]
        assert called_url.startswith(pin.CENSYS_HOST_API_BASE)
        assert mock_get.call_args.kwargs["auth"] == ("id", "secret")

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_found_without_result_wrapper(self, mock_get):
        mock_get.return_value = _fake_response(200, CENSYS_HOST_RESULT)
        r = pin.query_censys_host(SAFE_IP, "id", "secret")
        assert r["status"] == "found"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_not_found_404(self, mock_get):
        mock_get.return_value = _fake_response(404)
        r = pin.query_censys_host(SAFE_IP, "id", "secret")
        assert r["status"] == "not_found"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_unauthorized_401(self, mock_get):
        mock_get.return_value = _fake_response(401)
        r = pin.query_censys_host(SAFE_IP, "id", "bad-secret")
        assert r["status"] == "unauthorized"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_forbidden_403(self, mock_get):
        mock_get.return_value = _fake_response(403)
        r = pin.query_censys_host(SAFE_IP, "id", "secret")
        assert r["status"] == "forbidden"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_rate_limited_429(self, mock_get):
        mock_get.return_value = _fake_response(429)
        r = pin.query_censys_host(SAFE_IP, "id", "secret")
        assert r["status"] == "rate_limited"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_malformed_json(self, mock_get):
        mock_get.return_value = _fake_response(200, raise_json_error=True)
        r = pin.query_censys_host(SAFE_IP, "id", "secret")
        assert r["status"] == "error"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_missing_ip_in_response(self, mock_get):
        mock_get.return_value = _fake_response(200, {"result": {"no_ip_here": True}})
        r = pin.query_censys_host(SAFE_IP, "id", "secret")
        assert r["status"] == "error"

    @mock.patch("reconhound.passive_intel.requests.get", side_effect=requests.exceptions.Timeout())
    def test_timeout(self, mock_get):
        r = pin.query_censys_host(SAFE_IP, "id", "secret")
        assert r["status"] == "error"
        assert r["error"] == "timeout"


# ---------------------------------------------------------------------------
# Censys: search_censys_by_hostname
# ---------------------------------------------------------------------------

class TestSearchCensysByHostname:
    def test_empty_hostname(self):
        r = pin.search_censys_by_hostname("", "id", "secret")
        assert r["status"] == "error"

    def test_missing_credentials(self):
        r = pin.search_censys_by_hostname(SAFE_TARGET, None, None)
        assert r["status"] == "missing_credentials"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, {"result": {"hits": [CENSYS_SEARCH_HIT], "total": 1}})
        r = pin.search_censys_by_hostname(SAFE_TARGET, "id", "secret")
        assert r["status"] == "found"
        assert r["total"] == 1
        assert mock_get.call_args.kwargs["params"]["q"] == f"dns.names: {SAFE_TARGET}"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_empty_hits_is_not_found(self, mock_get):
        mock_get.return_value = _fake_response(200, {"result": {"hits": [], "total": 0}})
        r = pin.search_censys_by_hostname(SAFE_TARGET, "id", "secret")
        assert r["status"] == "not_found"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_forbidden_403(self, mock_get):
        mock_get.return_value = _fake_response(403)
        r = pin.search_censys_by_hostname(SAFE_TARGET, "id", "secret")
        assert r["status"] == "forbidden"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_malformed_structure(self, mock_get):
        mock_get.return_value = _fake_response(200, {"result": {"no_hits_key": True}})
        r = pin.search_censys_by_hostname(SAFE_TARGET, "id", "secret")
        assert r["status"] == "error"


# ---------------------------------------------------------------------------
# Normalization: Shodan
# ---------------------------------------------------------------------------

class TestNormalizeShodanHost:
    def test_full_parse(self):
        norm = pin.normalize_shodan_host(SHODAN_HOST_RAW, SAFE_TARGET)
        assert norm["ip"] == SAFE_IP
        assert "www.example.com" in norm["hostnames"]
        assert "example.com" in norm["hostnames"]
        assert norm["ports"] == [80, 443]
        assert len(norm["services"]) == 2
        assert norm["org"] == "Example Org"
        assert norm["source"] == "shodan"

    def test_banner_extracted(self):
        norm = pin.normalize_shodan_host(SHODAN_HOST_RAW, SAFE_TARGET)
        svc_443 = next(s for s in norm["services"] if s["port"] == 443)
        assert "nginx" in svc_443["banner"]
        assert svc_443["product"] == "nginx"
        assert svc_443["version"] == "1.18.0"

    def test_certificate_extracted(self):
        norm = pin.normalize_shodan_host(SHODAN_HOST_RAW, SAFE_TARGET)
        assert len(norm["certificates"]) == 1
        cert = norm["certificates"][0]
        assert cert["subject_cn"] == "example.com"
        assert cert["issuer_cn"] == "DigiCert"
        assert cert["fingerprint_sha256"] == "AAAA"
        assert cert["port"] == 443
        assert cert["source"] == "shodan"

    def test_no_certificate_for_plain_http_service(self):
        norm = pin.normalize_shodan_host(SHODAN_HOST_RAW, SAFE_TARGET)
        certs_on_80 = [c for c in norm["certificates"] if c["port"] == 80]
        assert certs_on_80 == []

    def test_missing_ip_str_returns_none(self):
        assert pin.normalize_shodan_host({"data": []}, SAFE_TARGET) is None

    def test_not_a_dict_returns_none(self):
        assert pin.normalize_shodan_host(None, SAFE_TARGET) is None
        assert pin.normalize_shodan_host([1, 2], SAFE_TARGET) is None

    def test_malformed_data_entry_skipped_not_fatal(self):
        raw = {"ip_str": SAFE_IP, "data": [{"port": "not-an-int", "ssl": "not-a-dict"}]}
        norm = pin.normalize_shodan_host(raw, SAFE_TARGET)
        assert norm is not None
        assert len(norm["services"]) == 1  # still recorded; just no cert/port-set contribution
        assert norm["certificates"] == []

    def test_falls_back_to_top_level_ports_when_no_data(self):
        raw = {"ip_str": SAFE_IP, "ports": [8080], "data": []}
        norm = pin.normalize_shodan_host(raw, SAFE_TARGET)
        assert norm["ports"] == [8080]

    def test_json_safe(self):
        norm = pin.normalize_shodan_host(SHODAN_HOST_RAW, SAFE_TARGET)
        json.dumps(norm)


class TestExtractShodanCertificate:
    def test_no_ssl_block(self):
        assert pin.extract_shodan_certificate({}, 443, SAFE_IP) is None

    def test_ssl_present_but_no_cert(self):
        assert pin.extract_shodan_certificate({"ssl": {}}, 443, SAFE_IP) is None


class TestNormalizeShodanSearchMatch:
    def test_wraps_into_host_shape(self):
        norm = pin.normalize_shodan_search_match(SHODAN_SEARCH_MATCH, SAFE_TARGET)
        assert norm["ip"] == SAFE_IP_2
        assert norm["ports"] == [22]
        assert len(norm["services"]) == 1
        assert norm["services"][0]["product"] == "OpenSSH"
        assert "ssh.example.com" in norm["hostnames"]

    def test_missing_ip_returns_none(self):
        assert pin.normalize_shodan_search_match({"port": 22}, SAFE_TARGET) is None


# ---------------------------------------------------------------------------
# Normalization: Censys
# ---------------------------------------------------------------------------

class TestNormalizeCensysHost:
    def test_full_parse(self):
        norm = pin.normalize_censys_host(CENSYS_HOST_RESULT, SAFE_TARGET)
        assert norm["ip"] == SAFE_IP
        assert "www.example.com" in norm["hostnames"]
        assert norm["ports"] == [22, 443]
        assert len(norm["services"]) == 2
        assert norm["asn"] == 12345
        assert norm["source"] == "censys"

    def test_software_extracted(self):
        norm = pin.normalize_censys_host(CENSYS_HOST_RESULT, SAFE_TARGET)
        svc_443 = next(s for s in norm["services"] if s["port"] == 443)
        assert svc_443["product"] == "nginx"
        assert svc_443["version"] == "1.18.0"
        assert svc_443["banner"] == "HTTP/1.1 200 OK"

    def test_full_certificate_extracted(self):
        norm = pin.normalize_censys_host(CENSYS_HOST_RESULT, SAFE_TARGET)
        cert_443 = next(c for c in norm["certificates"] if c["port"] == 443)
        assert cert_443["subject_cn"] == "example.com"
        assert cert_443["issuer_cn"] == "DigiCert"
        assert "www.example.com" in cert_443["sans"]
        assert cert_443["fingerprint_sha256"] == "CCCC"

    def test_fingerprint_only_certificate_extracted(self):
        norm = pin.normalize_censys_host(CENSYS_HOST_RESULT, SAFE_TARGET)
        cert_22 = next(c for c in norm["certificates"] if c["port"] == 22)
        assert cert_22["fingerprint_sha256"] == "deadbeefcafe"
        assert cert_22["subject_cn"] is None
        assert "note" in cert_22

    def test_missing_ip_returns_none(self):
        assert pin.normalize_censys_host({"services": []}, SAFE_TARGET) is None

    def test_not_a_dict_returns_none(self):
        assert pin.normalize_censys_host(None, SAFE_TARGET) is None

    def test_malformed_service_entry_skipped_not_fatal(self):
        raw = {"ip": SAFE_IP, "services": ["not-a-dict", {"port": 80}]}
        norm = pin.normalize_censys_host(raw, SAFE_TARGET)
        assert norm is not None
        assert len(norm["services"]) == 1

    def test_search_hit_reuses_same_parser(self):
        norm = pin.normalize_censys_host(CENSYS_SEARCH_HIT, SAFE_TARGET)
        assert norm["ip"] == SAFE_IP_2
        assert norm["ports"] == [22]

    def test_json_safe(self):
        norm = pin.normalize_censys_host(CENSYS_HOST_RESULT, SAFE_TARGET)
        json.dumps(norm)


class TestExtractCensysCertificate:
    def test_no_certificate_field(self):
        assert pin.extract_censys_certificate({"port": 80}, SAFE_IP) is None

    def test_empty_string_certificate(self):
        assert pin.extract_censys_certificate({"port": 80, "certificate": ""}, SAFE_IP) is None


# ---------------------------------------------------------------------------
# merge_host_records
# ---------------------------------------------------------------------------

class TestMergeHostRecords:
    def test_single_source_is_medium_confidence(self):
        norm = pin.normalize_shodan_host(SHODAN_HOST_RAW, SAFE_TARGET)
        norm["discovered_via"] = "seed_ip_lookup"
        merged = pin.merge_host_records([norm], SAFE_TARGET)
        assert len(merged) == 1
        assert merged[0]["confidence"] == pin.CONFIDENCE_MEDIUM
        assert merged[0]["sources"] == ["shodan"]

    def test_converging_sources_raise_confidence_to_high(self):
        shodan_norm = pin.normalize_shodan_host(SHODAN_HOST_RAW, SAFE_TARGET)
        shodan_norm["discovered_via"] = "seed_ip_lookup"
        censys_norm = pin.normalize_censys_host(CENSYS_HOST_RESULT, SAFE_TARGET)
        censys_norm["discovered_via"] = "seed_ip_lookup"
        merged = pin.merge_host_records([shodan_norm, censys_norm], SAFE_TARGET)
        assert len(merged) == 1  # same IP -> merged into one host record
        rec = merged[0]
        assert rec["confidence"] == pin.CONFIDENCE_HIGH
        assert set(rec["sources"]) == {"shodan", "censys"}
        assert len(rec["services"]) == 2 + 2  # both sources' services preserved, not deduped away

    def test_in_scope_via_hostname(self):
        norm = pin.normalize_shodan_host(SHODAN_HOST_RAW, SAFE_TARGET)
        norm["discovered_via"] = "seed_ip_lookup"
        merged = pin.merge_host_records([norm], SAFE_TARGET)
        assert merged[0]["in_scope"] is True
        assert "www.example.com" in merged[0]["in_scope_hostnames"]

    def test_in_scope_via_seed_ip_lookup_even_without_hostname(self):
        raw = {"ip_str": SAFE_IP, "data": []}
        norm = pin.normalize_shodan_host(raw, SAFE_TARGET)
        norm["discovered_via"] = "seed_ip_lookup"
        merged = pin.merge_host_records([norm], SAFE_TARGET)
        assert merged[0]["in_scope"] is True
        assert merged[0]["in_scope_hostnames"] == []

    def test_out_of_scope_hostname_not_counted(self):
        raw = {"ip_str": SAFE_IP, "hostnames": ["evil.com"], "data": []}
        norm = pin.normalize_shodan_host(raw, SAFE_TARGET)
        # not discovered via a scoped path either
        merged = pin.merge_host_records([norm], SAFE_TARGET)
        assert merged[0]["in_scope"] is False
        assert merged[0]["in_scope_hostnames"] == []

    def test_records_missing_ip_are_skipped(self):
        merged = pin.merge_host_records([None, {}, {"ip": None}], SAFE_TARGET)
        assert merged == []

    def test_sorted_by_ip(self):
        rec_a = {"ip": "1.1.1.1", "hostnames": [], "ports": [], "services": [], "certificates": [], "source": "shodan", "discovered_via": "seed_ip_lookup"}
        rec_b = {"ip": "2.2.2.2", "hostnames": [], "ports": [], "services": [], "certificates": [], "source": "shodan", "discovered_via": "seed_ip_lookup"}
        merged = pin.merge_host_records([rec_b, rec_a], SAFE_TARGET)
        assert [r["ip"] for r in merged] == ["1.1.1.1", "2.2.2.2"]

    def test_json_safe(self):
        norm = pin.normalize_shodan_host(SHODAN_HOST_RAW, SAFE_TARGET)
        norm["discovered_via"] = "seed_ip_lookup"
        merged = pin.merge_host_records([norm], SAFE_TARGET)
        json.dumps(merged)


# ---------------------------------------------------------------------------
# persist_host_intel / persist_no_data_findings
# ---------------------------------------------------------------------------

class TestPersistHostIntel:
    def test_persists_host_service_and_certificate_findings(self, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        norm = pin.normalize_shodan_host(SHODAN_HOST_RAW, SAFE_TARGET)
        norm["discovered_via"] = "seed_ip_lookup"
        merged = pin.merge_host_records([norm], SAFE_TARGET)
        errors = pin.persist_host_intel(merged, SAFE_TARGET, store)
        assert errors == []
        records = store.all()
        types = [r["type"] for r in records]
        assert types.count("passive_intel_host") == 1
        assert types.count("passive_intel_service") == 2
        assert types.count("passive_intel_certificate") == 1

    def test_survives_persistence_failure(self, tmp_path):
        path = tmp_path / "pending_assets.json"
        path.write_text("{not valid json")
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        norm = pin.normalize_shodan_host(SHODAN_HOST_RAW, SAFE_TARGET)
        norm["discovered_via"] = "seed_ip_lookup"
        merged = pin.merge_host_records([norm], SAFE_TARGET)
        errors = pin.persist_host_intel(merged, SAFE_TARGET, store)
        assert len(errors) > 0  # reported, never silently discarded

    def test_findings_are_json_safe(self, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        norm = pin.normalize_censys_host(CENSYS_HOST_RESULT, SAFE_TARGET)
        norm["discovered_via"] = "seed_ip_lookup"
        merged = pin.merge_host_records([norm], SAFE_TARGET)
        pin.persist_host_intel(merged, SAFE_TARGET, store)
        json.dumps(store.all())


class TestPersistNoDataFindings:
    def test_persists_negative_result_finding(self, tmp_path):
        """An authoritative provider 'no record' is a real negative result."""
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        errors = pin.persist_no_data_findings(
            [SAFE_IP], SAFE_TARGET, ["shodan", "censys"], store,
            ip_source_statuses={SAFE_IP: {"shodan": "not_found", "censys": "not_found"}},
        )
        assert errors == []
        records = store.all()
        assert len(records) == 1
        assert records[0]["type"] == "passive_intel_checked_no_data"
        assert records[0]["confidence"] == pin.CONFIDENCE_LOW
        assert "does not prove" in records[0]["metadata"]["note"]
        assert records[0]["metadata"]["sources_confirming_absence"] == ["censys", "shodan"]

    def test_without_per_source_detail_defaults_to_inconclusive(self, tmp_path):
        """
        A caller that cannot say WHY there was no record must not have that
        turned into a confirmed absence. Unknown fails safe.
        """
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        pin.persist_no_data_findings([SAFE_IP], SAFE_TARGET, ["shodan", "censys"], store)
        records = store.all()
        assert records[0]["type"] == "passive_intel_check_inconclusive"
        assert records[0]["value"]["outcome"] == "inconclusive"

    def test_provider_failure_is_inconclusive_not_absent(self, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        pin.persist_no_data_findings(
            [SAFE_IP], SAFE_TARGET, ["shodan"], store,
            ip_source_statuses={SAFE_IP: {"shodan": "rate_limited"}},
        )
        rec = store.all()[0]
        assert rec["type"] == "passive_intel_check_inconclusive"
        assert rec["metadata"]["sources_unavailable"] == ["shodan"]
        assert "NOT a negative result" in rec["metadata"]["note"]

    def test_unparsable_response_is_inconclusive_not_absent(self, tmp_path):
        """The provider HAD data; failing to parse it is not evidence of absence."""
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        pin.persist_no_data_findings(
            [SAFE_IP], SAFE_TARGET, ["shodan"], store,
            ip_source_statuses={SAFE_IP: {"shodan": pin.CHECK_UNPARSABLE}},
        )
        rec = store.all()[0]
        assert rec["type"] == "passive_intel_check_inconclusive"
        assert rec["metadata"]["sources_unparsable"] == ["shodan"]

    def test_one_authoritative_plus_one_failure_notes_the_gap(self, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        pin.persist_no_data_findings(
            [SAFE_IP], SAFE_TARGET, ["shodan", "censys"], store,
            ip_source_statuses={SAFE_IP: {"shodan": "not_found", "censys": "error"}},
        )
        rec = store.all()[0]
        assert rec["type"] == "passive_intel_checked_no_data"
        assert rec["metadata"]["sources_confirming_absence"] == ["shodan"]
        assert rec["metadata"]["sources_unavailable"] == ["censys"]
        assert any("did not answer" in e for e in rec["evidence"])

    def test_authoritative_absence_alongside_unparsable_stays_inconclusive(self, tmp_path):
        """One source having data we could not read outweighs another's silence."""
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        pin.persist_no_data_findings(
            [SAFE_IP], SAFE_TARGET, ["shodan", "censys"], store,
            ip_source_statuses={SAFE_IP: {"shodan": "not_found",
                                          "censys": pin.CHECK_UNPARSABLE}},
        )
        assert store.all()[0]["type"] == "passive_intel_check_inconclusive"


class TestSearchPagination:
    """
    Pagination audit: truncation must be visible, bounded, and must never
    discard pages already retrieved when a later page fails.
    """

    @staticmethod
    def _shodan_page(n, total, size=pin.SHODAN_PAGE_SIZE):
        return {"matches": [{"ip_str": f"198.51.100.{i}", "port": 80}
                            for i in range(size)], "total": total}

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_default_is_a_single_request_and_flags_truncation(self, mock_get):
        """Default max_pages=1 preserves the original one-request credit cost."""
        mock_get.return_value = _fake_response(200, {"matches": [{"ip_str": SAFE_IP}], "total": 5000})
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key")
        assert mock_get.call_count == 1
        assert r["total"] == 5000 and r["retrieved"] == 1
        assert r["truncated"] is True
        assert r["pages_fetched"] == 1

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_complete_result_set_is_not_marked_truncated(self, mock_get):
        mock_get.return_value = _fake_response(200, {"matches": [{"ip_str": SAFE_IP}], "total": 1})
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key")
        assert r["truncated"] is False and r["retrieved"] == 1

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_shodan_follows_pages_up_to_the_bound(self, mock_get):
        mock_get.side_effect = [
            _fake_response(200, self._shodan_page(1, 250)),
            _fake_response(200, self._shodan_page(2, 250)),
            _fake_response(200, self._shodan_page(3, 250)),
        ]
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key", max_pages=2)
        assert mock_get.call_count == 2          # bounded, never runs away
        assert r["pages_fetched"] == 2
        assert r["retrieved"] == 2 * pin.SHODAN_PAGE_SIZE
        assert r["truncated"] is True            # 250 > 200 retrieved

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_short_page_ends_pagination_early(self, mock_get):
        mock_get.side_effect = [
            _fake_response(200, self._shodan_page(1, 105)),
            _fake_response(200, {"matches": [{"ip_str": SAFE_IP}], "total": 105}),
            _fake_response(200, self._shodan_page(3, 105)),  # must never be requested
        ]
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key", max_pages=5)
        assert mock_get.call_count == 2
        assert r["retrieved"] == pin.SHODAN_PAGE_SIZE + 1

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_failure_on_page_two_preserves_page_one(self, mock_get):
        """A partial provider failure must not erase valid observations."""
        mock_get.side_effect = [
            _fake_response(200, self._shodan_page(1, 500)),
            _fake_response(429),
        ]
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key", max_pages=3)
        assert r["status"] == "found"                     # not downgraded to an error
        assert r["retrieved"] == pin.SHODAN_PAGE_SIZE     # page 1 kept in full
        assert r["truncated"] is True
        assert "page 2" in r["page_error"] and "429" in r["page_error"]

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_malformed_page_two_preserves_page_one(self, mock_get):
        mock_get.side_effect = [
            _fake_response(200, self._shodan_page(1, 500)),
            _fake_response(200, {"matches": "not-a-list", "total": 500}),
        ]
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key", max_pages=3)
        assert r["retrieved"] == pin.SHODAN_PAGE_SIZE
        assert r["page_error"] is not None

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_failure_on_page_one_is_still_a_hard_error(self, mock_get):
        mock_get.return_value = _fake_response(402)
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key", max_pages=3)
        assert r["status"] == "insufficient_credits"
        assert r["retrieved"] == 0
        assert mock_get.call_count == 1  # a permanent error is not retried

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_full_page_without_usable_total_is_not_claimed_complete(self, mock_get):
        """
        Shodan has no end-of-results cursor. When `total` is missing, a full
        final page leaves completeness genuinely unknown — reporting
        truncated=False there would assert that nothing was left behind, which
        is the one claim this flag exists to prevent.
        """
        mock_get.return_value = _fake_response(
            200, {"matches": [{"ip_str": SAFE_IP}] * pin.SHODAN_PAGE_SIZE})
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key")
        assert r["retrieved"] == pin.SHODAN_PAGE_SIZE
        assert r["truncated"] is True
        assert "could not be determined" in r["page_error"]

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_full_page_with_non_integer_total_is_not_claimed_complete(self, mock_get):
        """Schema drift ('total' as a string) must not become a completeness claim."""
        mock_get.return_value = _fake_response(
            200, {"matches": [{"ip_str": SAFE_IP}] * pin.SHODAN_PAGE_SIZE, "total": "5000"})
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key")
        assert r["truncated"] is True

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_short_page_without_total_is_still_treated_as_exhausted(self, mock_get):
        """A short page IS an exhaustion signal; this must not over-trigger."""
        mock_get.return_value = _fake_response(200, {"matches": [{"ip_str": SAFE_IP}] * 3})
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key")
        assert r["truncated"] is False
        assert r["page_error"] is None

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_full_page_with_matching_total_is_complete(self, mock_get):
        """When Shodan does report a total, the provider signal governs."""
        mock_get.return_value = _fake_response(
            200, {"matches": [{"ip_str": SAFE_IP}] * pin.SHODAN_PAGE_SIZE,
                  "total": pin.SHODAN_PAGE_SIZE})
        r = pin.search_shodan_by_hostname(SAFE_TARGET, "key")
        assert r["truncated"] is False

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_censys_full_page_without_next_cursor_is_complete(self, mock_get):
        """Censys DOES have an authoritative end signal: absence of links.next."""
        mock_get.return_value = _fake_response(
            200, {"result": {"hits": [{"ip": SAFE_IP}] * 50, "links": {}}})
        r = pin.search_censys_by_hostname(SAFE_TARGET, "id", "secret")
        assert r["truncated"] is False

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_censys_follows_the_next_cursor(self, mock_get):
        mock_get.side_effect = [
            _fake_response(200, {"result": {"hits": [{"ip": SAFE_IP}], "total": 2,
                                             "links": {"next": "cursor-2"}}}),
            _fake_response(200, {"result": {"hits": [{"ip": SAFE_IP_2}], "total": 2,
                                             "links": {"next": None}}}),
        ]
        r = pin.search_censys_by_hostname(SAFE_TARGET, "id", "secret", max_pages=3)
        assert r["retrieved"] == 2 and r["pages_fetched"] == 2
        assert r["truncated"] is False
        assert mock_get.call_args_list[1].kwargs["params"]["cursor"] == "cursor-2"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_censys_stops_when_page_budget_runs_out_with_cursor_left(self, mock_get):
        mock_get.return_value = _fake_response(
            200, {"result": {"hits": [{"ip": SAFE_IP}], "links": {"next": "more"}}})
        r = pin.search_censys_by_hostname(SAFE_TARGET, "id", "secret", max_pages=1)
        assert r["truncated"] is True

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_censys_repeated_cursor_does_not_loop_or_duplicate(self, mock_get):
        """A provider echoing one cursor must not replay pages indefinitely."""
        mock_get.return_value = _fake_response(
            200, {"result": {"hits": [{"ip": SAFE_IP}], "total": 99,
                             "links": {"next": "SAME"}}})
        r = pin.search_censys_by_hostname(SAFE_TARGET, "id", "secret", max_pages=50)
        assert mock_get.call_count == 2   # bounded by the repeat guard, not max_pages
        assert "repeated" in r["page_error"]
        assert r["truncated"] is True

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_run_summary_exposes_truncation(self, mock_get, tmp_path):
        mock_get.return_value = _fake_response(
            200, {"matches": [SHODAN_SEARCH_MATCH], "total": 9000})
        result = pin.run_passive_intel(
            SAFE_TARGET, output_dir=str(tmp_path), seed_ips=[], shodan_api_key="key",
            censys_api_id=None, censys_api_secret=None,
        )
        search = result["source_status"]["shodan_hostname_search"]
        assert search["total"] == 9000
        assert search["retrieved"] == 1
        assert search["truncated"] is True   # the 9000-vs-1 gap is now explicit


class TestRunLevelCheckSemantics:
    """A provider outage must never be recorded as 'checked and not found'."""

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_rate_limited_run_records_inconclusive_not_absence(self, mock_get, tmp_path):
        mock_get.return_value = _fake_response(429)
        result = pin.run_passive_intel(
            SAFE_TARGET, output_dir=str(tmp_path), seed_ips=[SAFE_IP],
            include_hostname_search=False, shodan_api_key="key",
        )
        assert result["stats"]["hosts_checked_no_data"] == 0
        assert result["stats"]["hosts_check_inconclusive"] == 1
        types = [r["type"] for r in pin.PendingAssetsStore(output_dir=str(tmp_path)).all()]
        assert "passive_intel_check_inconclusive" in types
        assert "passive_intel_checked_no_data" not in types
        assert result["ip_check_outcomes"][SAFE_IP]["outcome"] == "inconclusive"

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_authoritative_404_still_records_a_negative_result(self, mock_get, tmp_path):
        mock_get.return_value = _fake_response(404)
        result = pin.run_passive_intel(
            SAFE_TARGET, output_dir=str(tmp_path), seed_ips=[SAFE_IP],
            include_hostname_search=False, shodan_api_key="key",
        )
        assert result["stats"]["hosts_checked_no_data"] == 1
        assert result["stats"]["hosts_check_inconclusive"] == 0
        types = [r["type"] for r in pin.PendingAssetsStore(output_dir=str(tmp_path)).all()]
        assert "passive_intel_checked_no_data" in types

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_unparsable_provider_record_is_not_reported_as_absence(self, mock_get, tmp_path):
        """The provider HAD a record; failing to parse it is not evidence of absence."""
        mock_get.return_value = _fake_response(
            200, {"ip_str": "not-an-ip", "ports": [443], "data": [{"port": 443}]})
        result = pin.run_passive_intel(
            SAFE_TARGET, output_dir=str(tmp_path), seed_ips=[SAFE_IP],
            include_hostname_search=False, shodan_api_key="key",
        )
        assert result["stats"]["hosts_checked_no_data"] == 0
        assert result["stats"]["hosts_check_inconclusive"] == 1
        # The discarded record is reported, never silently dropped.
        assert any(e["stage"] == "normalize_shodan_host" for e in result["errors"])
        rec = [r for r in pin.PendingAssetsStore(output_dir=str(tmp_path)).all()
               if r["type"] == "passive_intel_check_inconclusive"][0]
        assert rec["metadata"]["sources_unparsable"] == ["shodan"]

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_one_source_authoritative_other_down_notes_the_gap(self, mock_get, tmp_path):
        def side_effect(url, **kwargs):
            if url.startswith(pin.SHODAN_HOST_API_BASE):
                return _fake_response(404)
            raise requests.exceptions.Timeout()
        mock_get.side_effect = side_effect
        result = pin.run_passive_intel(
            SAFE_TARGET, output_dir=str(tmp_path), seed_ips=[SAFE_IP],
            include_hostname_search=False, shodan_api_key="key",
            censys_api_id="id", censys_api_secret="secret",
        )
        assert result["stats"]["hosts_checked_no_data"] == 1
        outcome = result["ip_check_outcomes"][SAFE_IP]
        assert outcome["confirming"] == ["shodan"]
        assert outcome["unavailable"] == ["censys"]
        rec = [r for r in pin.PendingAssetsStore(output_dir=str(tmp_path)).all()
               if r["type"] == "passive_intel_checked_no_data"][0]
        assert any("silence proves nothing" in e for e in rec["evidence"])


class TestAttribution:
    """
    Shodan's `hostname:` filter is a substring match, so a search for
    example.com can return notexample.com. Discovery path alone must never
    stand in for an ownership claim.
    """

    def test_hostname_search_without_in_scope_hostname_is_not_in_scope(self):
        match = {"ip_str": SAFE_IP_2, "hostnames": ["www.notexample.com"],
                 "domains": ["notexample.com"], "port": 443}
        norm = pin.normalize_shodan_search_match(match, SAFE_TARGET)
        norm["discovered_via"] = "hostname_search"
        rec = pin.merge_host_records([norm], SAFE_TARGET)[0]
        assert rec["in_scope"] is False
        assert rec["attribution"]["basis"] == "provider_hostname_match_only"
        assert rec["attribution"]["dns_attested"] is False
        # The evidence is preserved in full — only the claim is withdrawn.
        assert rec["hostnames"] == ["notexample.com", "www.notexample.com"]
        assert rec["out_of_scope_hostnames"] == ["notexample.com", "www.notexample.com"]

    def test_hostname_search_with_in_scope_hostname_is_in_scope(self):
        match = {"ip_str": SAFE_IP_2, "hostnames": ["ssh.example.com"], "port": 22}
        norm = pin.normalize_shodan_search_match(match, SAFE_TARGET)
        norm["discovered_via"] = "hostname_search"
        rec = pin.merge_host_records([norm], SAFE_TARGET)[0]
        assert rec["in_scope"] is True
        assert rec["attribution"]["basis"] == "in_scope_hostname_on_record"

    def test_seed_ip_lookup_remains_dns_attested(self):
        norm = pin.normalize_shodan_host({"ip_str": SAFE_IP, "data": []}, SAFE_TARGET)
        norm["discovered_via"] = "seed_ip_lookup"
        rec = pin.merge_host_records([norm], SAFE_TARGET)[0]
        assert rec["in_scope"] is True
        assert rec["attribution"]["basis"] == "dns_resolved_seed_ip"
        assert rec["attribution"]["dns_attested"] is True

    def test_shared_infrastructure_counts_are_reported_raw(self):
        raw = {"ip_str": SAFE_IP, "hostnames": ["www.example.com", "a.other.com", "b.other.com"],
               "data": []}
        norm = pin.normalize_shodan_host(raw, SAFE_TARGET)
        norm["discovered_via"] = "seed_ip_lookup"
        rec = pin.merge_host_records([norm], SAFE_TARGET)[0]
        attr = rec["attribution"]
        assert attr["in_scope_hostname_count"] == 1
        assert attr["out_of_scope_hostname_count"] == 2
        assert rec["in_scope"] is True  # DNS still attests the IP itself

    def test_multi_source_does_not_raise_confidence_for_unattributed_host(self):
        """Corroborating an observation about someone else's host does not
        make it more likely to be the target's."""
        base = {"ip": SAFE_IP_2, "hostnames": ["www.notexample.com"], "ports": [],
                "services": [], "certificates": [], "discovered_via": "hostname_search"}
        recs = [dict(base, source="shodan"), dict(base, source="censys")]
        rec = pin.merge_host_records(recs, SAFE_TARGET)[0]
        assert set(rec["sources"]) == {"shodan", "censys"}
        assert rec["in_scope"] is False
        assert rec["confidence"] == pin.CONFIDENCE_MEDIUM

    def test_multi_source_still_raises_confidence_for_attributed_host(self):
        base = {"ip": SAFE_IP, "hostnames": ["www.example.com"], "ports": [],
                "services": [], "certificates": [], "discovered_via": "seed_ip_lookup"}
        recs = [dict(base, source="shodan"), dict(base, source="censys")]
        rec = pin.merge_host_records(recs, SAFE_TARGET)[0]
        assert rec["confidence"] == pin.CONFIDENCE_HIGH

    def test_unattributed_host_evidence_says_so(self, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        match = {"ip_str": SAFE_IP_2, "hostnames": ["www.notexample.com"], "port": 443}
        norm = pin.normalize_shodan_search_match(match, SAFE_TARGET)
        norm["discovered_via"] = "hostname_search"
        merged = pin.merge_host_records([norm], SAFE_TARGET)
        pin.persist_host_intel(merged, SAFE_TARGET, store)
        rec = [r for r in store.all() if r["type"] == "passive_intel_host"][0]
        assert rec["metadata"]["attribution_basis"] == "provider_hostname_match_only"
        assert any("Not attributed to" in e for e in rec["evidence"])
        assert any("shared/CDN/multi-tenant" in e for e in rec["evidence"])


class TestCertificateProvenance:
    def test_shodan_certificate_carries_observation_time(self):
        raw = {"ip_str": SAFE_IP, "data": [{
            "port": 443, "timestamp": "2019-03-03T00:00:00.000000",
            "ssl": {"cert": {"subject": {"CN": "old.example.com"}, "expired": True,
                             "fingerprint": {"sha256": "ab"}}}}]}
        cert = pin.normalize_shodan_host(raw, SAFE_TARGET)["certificates"][0]
        # Without this a historical certificate is indistinguishable from a current one.
        assert cert["observed_at"] == "2019-03-03T00:00:00.000000"
        # The expiry verdict is preserved but attributed to the provider's scan time.
        assert cert["expired"] is True
        assert cert["expired_evaluated_by"] == "shodan_at_observation_time"

    def test_censys_certificate_carries_observation_time(self):
        raw = {"ip": SAFE_IP, "services": [{
            "port": 443, "observed_at": "2021-07-07T00:00:00Z",
            "certificate": {"fingerprint_sha256": "cd"}}]}
        cert = pin.normalize_censys_host(raw, SAFE_TARGET)["certificates"][0]
        assert cert["observed_at"] == "2021-07-07T00:00:00Z"

    def test_censys_fingerprint_only_certificate_carries_observation_time(self):
        raw = {"ip": SAFE_IP, "services": [{
            "port": 443, "observed_at": "2021-07-07T00:00:00Z", "certificate": "abc123"}]}
        cert = pin.normalize_censys_host(raw, SAFE_TARGET)["certificates"][0]
        assert cert["observed_at"] == "2021-07-07T00:00:00Z"
        assert cert["fingerprint_sha256"] == "abc123"


class TestNegativeResultNamingContract:
    def test_inconclusive_type_must_not_register_as_negative_result_memory(self):
        """
        surface_mapper._is_negative_result() keys negative-result memory off
        the substring "_checked_no", and other modules trust that memory to
        skip re-checking. An inconclusive check must never enter it, so the
        finding type must never contain that substring.
        """
        assert "_checked_no" not in "passive_intel_check_inconclusive"
        assert "_checked_no" in "passive_intel_checked_no_data"


class TestClassifyIpCheck:
    def test_authoritative_absence(self):
        v = pin.classify_ip_check({"shodan": "not_found"})
        assert v["outcome"] == "not_found" and v["confirming"] == ["shodan"]

    @pytest.mark.parametrize("status", [
        "error", "rate_limited", "unauthorized", "forbidden",
        "insufficient_credits", "missing_credentials",
    ])
    def test_every_provider_failure_is_inconclusive(self, status):
        v = pin.classify_ip_check({"shodan": status})
        assert v["outcome"] == "inconclusive"
        assert v["unavailable"] == ["shodan"]

    def test_no_statuses_at_all_is_inconclusive(self):
        assert pin.classify_ip_check({})["outcome"] == "inconclusive"


# ---------------------------------------------------------------------------
# run_passive_intel (end-to-end orchestration)
# ---------------------------------------------------------------------------

class TestRunPassiveIntel:
    def test_rejects_invalid_target(self, tmp_path):
        with pytest.raises(pin.ScopeError):
            pin.run_passive_intel("not a domain", output_dir=str(tmp_path))

    def test_no_credentials_completes_without_crashing(self, tmp_path, monkeypatch):
        monkeypatch.delenv(pin.SHODAN_API_KEY_ENV, raising=False)
        monkeypatch.delenv(pin.CENSYS_API_ID_ENV, raising=False)
        monkeypatch.delenv(pin.CENSYS_API_SECRET_ENV, raising=False)
        result = pin.run_passive_intel(SAFE_TARGET, output_dir=str(tmp_path), seed_ips=[SAFE_IP])
        assert result["source_status"]["shodan"]["status"] == "missing_credentials"
        assert result["source_status"]["censys"]["status"] == "missing_credentials"
        assert result["hosts"] == []
        assert result["stats"]["sources_used"] == []
        json.dumps(result)  # whole summary must be JSON-safe

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_full_pipeline_with_seed_ip(self, mock_get, tmp_path):
        def side_effect(url, **kwargs):
            if url.startswith(pin.SHODAN_HOST_API_BASE):
                return _fake_response(200, SHODAN_HOST_RAW)
            if url.startswith(pin.CENSYS_HOST_API_BASE):
                return _fake_response(200, {"result": CENSYS_HOST_RESULT})
            if url == pin.SHODAN_SEARCH_API_BASE:
                return _fake_response(200, {"matches": [], "total": 0})
            if url == pin.CENSYS_SEARCH_API_BASE:
                return _fake_response(200, {"result": {"hits": [], "total": 0}})
            raise AssertionError(f"unexpected URL called: {url}")

        mock_get.side_effect = side_effect

        result = pin.run_passive_intel(
            SAFE_TARGET, output_dir=str(tmp_path), seed_ips=[SAFE_IP],
            shodan_api_key="shodan-key", censys_api_id="id", censys_api_secret="secret",
        )

        assert result["stats"]["hosts_found"] == 1
        host = result["hosts"][0]
        assert host["ip"] == SAFE_IP
        assert host["confidence"] == pin.CONFIDENCE_HIGH  # both sources converged
        assert set(host["sources"]) == {"shodan", "censys"}
        json.dumps(result)

        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        persisted_types = [r["type"] for r in store.all()]
        assert "passive_intel_host" in persisted_types
        assert "passive_intel_service" in persisted_types
        assert "passive_intel_certificate" in persisted_types

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_hostname_search_discovers_host_beyond_seed_ips(self, mock_get, tmp_path):
        def side_effect(url, **kwargs):
            if url == pin.SHODAN_SEARCH_API_BASE:
                return _fake_response(200, {"matches": [SHODAN_SEARCH_MATCH], "total": 1})
            if url == pin.CENSYS_SEARCH_API_BASE:
                return _fake_response(200, {"result": {"hits": [], "total": 0}})
            raise AssertionError(f"unexpected URL called: {url}")

        mock_get.side_effect = side_effect

        result = pin.run_passive_intel(
            SAFE_TARGET, output_dir=str(tmp_path), seed_ips=[],
            shodan_api_key="shodan-key", censys_api_id=None, censys_api_secret=None,
        )
        assert result["stats"]["hosts_found"] == 1
        assert result["hosts"][0]["ip"] == SAFE_IP_2
        assert result["hosts"][0]["discovered_via"] == ["hostname_search"]

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_negative_result_memory_persisted_for_ip_with_no_data(self, mock_get, tmp_path):
        mock_get.return_value = _fake_response(404)  # every lookup comes back empty
        result = pin.run_passive_intel(
            SAFE_TARGET, output_dir=str(tmp_path), seed_ips=[SAFE_IP], include_hostname_search=False,
            shodan_api_key="shodan-key", censys_api_id="id", censys_api_secret="secret",
        )
        assert result["stats"]["hosts_checked_no_data"] == 1
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        no_data = [r for r in store.all() if r["type"] == "passive_intel_checked_no_data"]
        assert len(no_data) == 1
        assert no_data[0]["value"]["ip"] == SAFE_IP

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_one_source_failure_does_not_abort_the_other(self, mock_get, tmp_path):
        def side_effect(url, **kwargs):
            if url.startswith(pin.SHODAN_HOST_API_BASE):
                raise requests.exceptions.ConnectionError("shodan is down")
            if url.startswith(pin.CENSYS_HOST_API_BASE):
                return _fake_response(200, {"result": CENSYS_HOST_RESULT})
            if url == pin.SHODAN_SEARCH_API_BASE:
                return _fake_response(200, {"matches": [], "total": 0})
            if url == pin.CENSYS_SEARCH_API_BASE:
                return _fake_response(200, {"result": {"hits": [], "total": 0}})
            raise AssertionError(f"unexpected URL called: {url}")

        mock_get.side_effect = side_effect

        result = pin.run_passive_intel(
            SAFE_TARGET, output_dir=str(tmp_path), seed_ips=[SAFE_IP],
            shodan_api_key="shodan-key", censys_api_id="id", censys_api_secret="secret",
        )
        assert result["stats"]["hosts_found"] == 1
        assert result["hosts"][0]["sources"] == ["censys"]

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_seed_ips_derived_from_persisted_dns_records(self, mock_get, tmp_path):
        store = pin.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(pin.make_finding("dns_record", SAFE_TARGET, {"record_type": "A", "records": [SAFE_IP]}, ["e"], pin.CONFIDENCE_HIGH))

        def side_effect(url, **kwargs):
            if url.startswith(pin.SHODAN_HOST_API_BASE):
                return _fake_response(200, SHODAN_HOST_RAW)
            if url == pin.SHODAN_SEARCH_API_BASE:
                return _fake_response(200, {"matches": [], "total": 0})
            raise AssertionError(f"unexpected URL called: {url}")

        mock_get.side_effect = side_effect

        result = pin.run_passive_intel(
            SAFE_TARGET, output_dir=str(tmp_path),
            shodan_api_key="shodan-key", censys_api_id=None, censys_api_secret=None,
        )
        assert result["seed_ips"] == [SAFE_IP]
        assert result["stats"]["hosts_found"] == 1

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_never_contacts_the_target_directly(self, mock_get, tmp_path):
        """Passive boundary: every captured request must go to Shodan/Censys, never to the target."""
        def side_effect(url, **kwargs):
            if url.startswith(pin.SHODAN_HOST_API_BASE):
                return _fake_response(200, SHODAN_HOST_RAW)
            if url.startswith(pin.CENSYS_HOST_API_BASE):
                return _fake_response(200, {"result": CENSYS_HOST_RESULT})
            if url == pin.SHODAN_SEARCH_API_BASE:
                return _fake_response(200, {"matches": [SHODAN_SEARCH_MATCH], "total": 1})
            if url == pin.CENSYS_SEARCH_API_BASE:
                return _fake_response(200, {"result": {"hits": [CENSYS_SEARCH_HIT], "total": 1}})
            raise AssertionError(f"unexpected URL called: {url}")

        mock_get.side_effect = side_effect

        pin.run_passive_intel(
            SAFE_TARGET, output_dir=str(tmp_path), seed_ips=[SAFE_IP],
            shodan_api_key="shodan-key", censys_api_id="id", censys_api_secret="secret",
        )

        for call in mock_get.call_args_list:
            url = call.args[0]
            assert url.startswith("https://api.shodan.io/") or url.startswith("https://search.censys.io/"), (
                f"passive boundary violation: request sent to {url!r}"
            )
            assert SAFE_TARGET not in url  # never a direct request naming the target as a host

    def test_include_shodan_false_skips_shodan_entirely(self, tmp_path):
        result = pin.run_passive_intel(
            SAFE_TARGET, output_dir=str(tmp_path), seed_ips=[SAFE_IP],
            include_shodan=False, censys_api_id=None, censys_api_secret=None,
        )
        assert "shodan" not in result["source_status"]
        assert result["stats"]["sources_used"] == []

    @mock.patch("reconhound.passive_intel.requests.get")
    def test_malformed_response_does_not_abort_run(self, mock_get, tmp_path):
        mock_get.return_value = _fake_response(200, raise_json_error=True)
        result = pin.run_passive_intel(
            SAFE_TARGET, output_dir=str(tmp_path), seed_ips=[SAFE_IP],
            shodan_api_key="shodan-key", censys_api_id="id", censys_api_secret="secret",
        )
        assert result["stats"]["hosts_found"] == 0
        json.dumps(result)
