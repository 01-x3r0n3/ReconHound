"""
Tests for reconhound/passive_recon.py (ReconHound Module 1).

Run with:  ./.venv/bin/python -m pytest tests/test_passive_recon.py -v

Most tests mock the network boundary (dns.resolver, socket/ssl, python-whois)
so the suite is deterministic and offline-safe. A small number of live
smoke tests hit example.com — IANA's domain reserved for documentation and
testing use (RFC 2606) — and are skipped gracefully if the sandbox has no
outbound network access, rather than failing the suite.
"""

import ipaddress
import json
import os
import socket
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.resolver

from reconhound import passive_recon as pr


SAFE_TARGET = "example.com"


def _network_available() -> bool:
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(SAFE_TARGET)
        return True
    except OSError:
        return False


NETWORK_AVAILABLE = _network_available()
requires_network = pytest.mark.skipif(not NETWORK_AVAILABLE, reason="no outbound network access in this sandbox")


# ---------------------------------------------------------------------------
# validate_target / is_in_scope (scope enforcement)
# ---------------------------------------------------------------------------

class TestValidateTarget:
    def test_accepts_plain_domain(self):
        assert pr.validate_target("example.com") == "example.com"

    def test_lowercases_and_strips_trailing_dot(self):
        assert pr.validate_target("Example.COM.") == "example.com"

    def test_strips_surrounding_whitespace(self):
        assert pr.validate_target("  example.com  ") == "example.com"

    def test_accepts_subdomain(self):
        assert pr.validate_target("api.example.com") == "api.example.com"

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(pr.ScopeError):
            pr.validate_target(bad)

    def test_rejects_url(self):
        with pytest.raises(pr.ScopeError):
            pr.validate_target("https://example.com/path")

    def test_rejects_raw_ipv4(self):
        with pytest.raises(pr.ScopeError):
            pr.validate_target("93.184.216.34")

    def test_rejects_raw_ipv6(self):
        with pytest.raises(pr.ScopeError):
            pr.validate_target("::1")

    def test_rejects_wildcard(self):
        with pytest.raises(pr.ScopeError):
            pr.validate_target("*.example.com")

    def test_rejects_malformed_domain(self):
        with pytest.raises(pr.ScopeError):
            pr.validate_target("not a domain")

    def test_rejects_shell_metacharacters(self):
        with pytest.raises(pr.ScopeError):
            pr.validate_target("example.com; rm -rf /")


class TestIsInScope:
    def test_exact_match_in_scope(self):
        assert pr.is_in_scope("example.com", "example.com") is True

    def test_subdomain_in_scope(self):
        assert pr.is_in_scope("api.example.com", "example.com") is True

    def test_unrelated_domain_out_of_scope(self):
        assert pr.is_in_scope("attacker.evil.com", "example.com") is False

    def test_suffix_lookalike_out_of_scope(self):
        # "notexample.com" must NOT be considered in-scope for "example.com"
        assert pr.is_in_scope("notexample.com", "example.com") is False

    def test_case_insensitive(self):
        assert pr.is_in_scope("API.EXAMPLE.COM", "example.com") is True


# ---------------------------------------------------------------------------
# make_finding / evidence model
# ---------------------------------------------------------------------------

class TestMakeFinding:
    def test_structure_and_defaults(self):
        finding = pr.make_finding(
            finding_type="dns_record",
            target="example.com",
            value={"a": 1},
            evidence=["evidence line"],
            confidence=pr.CONFIDENCE_HIGH,
        )
        assert finding["type"] == "dns_record"
        assert finding["target"] == "example.com"
        assert finding["value"] == {"a": 1}
        assert finding["evidence"] == ["evidence line"]
        assert finding["confidence"] == pr.CONFIDENCE_HIGH
        assert finding["source"] == "passive_recon.py"
        assert "timestamp" in finding and finding["timestamp"]
        assert finding["metadata"] == {}

    def test_is_json_serializable(self):
        finding = pr.make_finding("whois", "example.com", {"x": [1, 2]}, ["e"], pr.CONFIDENCE_LOW)
        json.dumps(finding)  # must not raise


# ---------------------------------------------------------------------------
# PendingAssetsStore (crash-safe persistence)
# ---------------------------------------------------------------------------

class TestPendingAssetsStore:
    def test_creates_output_dir_and_file(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        finding = pr.make_finding("dns_record", "example.com", {}, ["e"], pr.CONFIDENCE_LOW)
        store.add(finding)
        assert os.path.exists(store.path)
        with open(store.path) as f:
            data = json.load(f)
        assert data == [finding]

    def test_appends_without_losing_previous_entries(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        f1 = pr.make_finding("dns_record", "example.com", {"n": 1}, ["e"], pr.CONFIDENCE_LOW)
        f2 = pr.make_finding("whois", "example.com", {"n": 2}, ["e"], pr.CONFIDENCE_HIGH)
        store.add(f1)
        store.add(f2)
        assert store.all() == [f1, f2]

    def test_preserves_existing_data_from_prior_run(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [pr.make_finding("whois", "other.com", {}, ["prior run"], pr.CONFIDENCE_HIGH)]
        pending.write_text(json.dumps(pre_existing))

        store = pr.PendingAssetsStore(output_dir=str(output_dir))
        new_finding = pr.make_finding("dns_record", "example.com", {}, ["new"], pr.CONFIDENCE_LOW)
        store.add(new_finding)

        assert store.all() == pre_existing + [new_finding]

    def test_corrupt_existing_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not valid json")

        store = pr.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(pr.PersistenceError):
            store.add(pr.make_finding("dns_record", "example.com", {}, ["e"], pr.CONFIDENCE_LOW))

    def test_write_is_atomic_no_temp_file_left_behind(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        store.add(pr.make_finding("dns_record", "example.com", {}, ["e"], pr.CONFIDENCE_LOW))
        leftovers = [p for p in os.listdir(store.output_dir) if p.startswith(".pending_assets_")]
        assert leftovers == []


# ---------------------------------------------------------------------------
# enumerate_dns (mocked resolver)
# ---------------------------------------------------------------------------

class _FakeRdata:
    def __init__(self, text):
        self._text = text

    def to_text(self):
        return self._text


class TestEnumerateDns:
    def test_found_record_is_persisted(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_answer = [_FakeRdata("93.184.216.34")]
        with mock.patch.object(dns.resolver.Resolver, "resolve", return_value=fake_answer):
            results = pr.enumerate_dns("example.com", store=store, record_types=["A"])
        assert results["A"]["status"] == "found"
        assert results["A"]["records"] == ["93.184.216.34"]
        persisted = store.all()
        assert len(persisted) == 1
        assert persisted[0]["type"] == "dns_record"
        assert persisted[0]["metadata"]["record_type"] == "A"

    def test_nxdomain_is_not_found_and_not_persisted(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
            results = pr.enumerate_dns("example.com", store=store, record_types=["A"])
        assert results["A"]["status"] == "not_found"
        assert store.all() == []

    def test_no_answer_is_not_found(self, tmp_path):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NoAnswer()):
            results = pr.enumerate_dns("example.com", record_types=["MX"])
        assert results["MX"]["status"] == "not_found"

    def test_timeout_is_error_not_crash(self):
        import dns.exception
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.Timeout()):
            results = pr.enumerate_dns("example.com", record_types=["TXT"])
        assert results["TXT"]["status"] == "error"

    def test_one_bad_record_type_does_not_abort_others(self):
        def fake_resolve(self, qname, rtype, *a, **kw):
            if rtype == "A":
                raise dns.resolver.NXDOMAIN()
            return [_FakeRdata("ns1.example.com.")]

        with mock.patch.object(dns.resolver.Resolver, "resolve", fake_resolve):
            results = pr.enumerate_dns("example.com", record_types=["A", "NS"])
        assert results["A"]["status"] == "not_found"
        assert results["NS"]["status"] == "found"

    def test_invalid_target_raises_scope_error(self):
        with pytest.raises(pr.ScopeError):
            pr.enumerate_dns("not a domain")


# ---------------------------------------------------------------------------
# whois_lookup (mocked python-whois)
# ---------------------------------------------------------------------------

class TestWhoisLookup:
    def test_found_data_is_persisted(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_record = {
            "domain_name": "EXAMPLE.COM",
            "registrar": "Example Registrar",
            "creation_date": None,
        }
        with mock.patch.object(pr.python_whois, "whois", return_value=fake_record):
            result = pr.whois_lookup("example.com", store=store)
        assert result["status"] == "found"
        assert result["data"]["domain_name"] == "EXAMPLE.COM"
        assert len(store.all()) == 1

    def test_empty_result_is_not_found(self):
        with mock.patch.object(pr.python_whois, "whois", return_value={}):
            result = pr.whois_lookup("example.com")
        assert result["status"] == "not_found"

    def test_library_exception_is_error_not_crash(self):
        with mock.patch.object(pr.python_whois, "whois", side_effect=Exception("whois server unreachable")):
            result = pr.whois_lookup("example.com")
        assert result["status"] == "error"
        assert "unreachable" in result["error"]

    def test_datetime_values_are_json_safe(self, tmp_path):
        import datetime
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_record = {"domain_name": "EXAMPLE.COM", "creation_date": datetime.datetime(1995, 8, 14)}
        with mock.patch.object(pr.python_whois, "whois", return_value=fake_record):
            pr.whois_lookup("example.com", store=store)
        # store.all() must be JSON round-trippable
        json.dumps(store.all())


# ---------------------------------------------------------------------------
# discover_tls_certificate (mocked socket/ssl + real cert parsing)
# ---------------------------------------------------------------------------

def _make_self_signed_der(common_name="example.com", sans=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as dt

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER)


class TestDiscoverTlsCertificate:
    def test_parses_cert_and_extracts_sans(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        der = _make_self_signed_der("example.com", sans=["example.com", "www.example.com", "evil-other.org"])

        fake_tls_sock = mock.MagicMock()
        fake_tls_sock.getpeercert.return_value = der
        fake_tls_sock.__enter__.return_value = fake_tls_sock
        fake_tls_sock.__exit__.return_value = False

        fake_context = mock.MagicMock()
        fake_context.wrap_socket.return_value = fake_tls_sock

        fake_raw_sock = mock.MagicMock()
        fake_raw_sock.__enter__.return_value = fake_raw_sock
        fake_raw_sock.__exit__.return_value = False

        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            result = pr.discover_tls_certificate("example.com", store=store)

        assert result["status"] == "found"
        assert set(result["sans"]) == {"example.com", "www.example.com", "evil-other.org"}
        assert result["certificate"]["subject"]["commonName"] == "example.com"

        persisted = store.all()
        cert_findings = [p for p in persisted if p["type"] == "tls_certificate"]
        san_findings = [p for p in persisted if p["type"] == "tls_san"]
        assert len(cert_findings) == 1
        assert len(san_findings) == 3

        out_of_scope = [s for s in san_findings if s["value"] == "evil-other.org"]
        assert out_of_scope[0]["metadata"]["in_scope"] is False
        assert out_of_scope[0]["confidence"] == pr.CONFIDENCE_MEDIUM

        in_scope = [s for s in san_findings if s["value"] == "www.example.com"]
        assert in_scope[0]["metadata"]["in_scope"] is True
        assert in_scope[0]["confidence"] == pr.CONFIDENCE_HIGH

    def test_connection_refused_is_error_not_crash(self):
        with mock.patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            result = pr.discover_tls_certificate("example.com")
        assert result["status"] == "error"

    def test_timeout_is_error_not_crash(self):
        with mock.patch("socket.create_connection", side_effect=socket.timeout("timed out")):
            result = pr.discover_tls_certificate("example.com")
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# discover_asn (mocked Cymru DNS)
# ---------------------------------------------------------------------------

class TestDiscoverAsn:
    def test_parses_cymru_response(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        origin_txt = _FakeRdata('"15133 | 93.184.216.0/24 | US | arin | 2010-08-01"')
        asname_txt = _FakeRdata('"15133 | US | arin | 2010-08-01 | EDGECAST, US"')

        def fake_resolve(self, qname, rtype, *a, **kw):
            if "origin.asn.cymru.com" in str(qname):
                return [origin_txt]
            if "asn.cymru.com" in str(qname):
                return [asname_txt]
            raise AssertionError(f"unexpected query {qname}")

        with mock.patch.object(dns.resolver.Resolver, "resolve", fake_resolve):
            result = pr.discover_asn("93.184.216.34", store=store, target="example.com")

        assert result["status"] == "found"
        assert result["data"]["asn"] == "15133"
        assert result["data"]["bgp_prefix"] == "93.184.216.0/24"
        assert result["data"]["as_name"] == "EDGECAST, US"
        assert len(store.all()) == 1

    def test_invalid_ip_is_error(self):
        result = pr.discover_asn("not-an-ip")
        assert result["status"] == "error"

    def test_ipv6_is_unsupported_error(self):
        result = pr.discover_asn("::1")
        assert result["status"] == "error"

    def test_cymru_lookup_failure_is_error_not_crash(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = pr.discover_asn("192.0.2.1")
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# analyze_email_security (mocked resolver)
# ---------------------------------------------------------------------------

class TestAnalyzeEmailSecurity:
    def test_spf_dmarc_mx_found_high_confidence(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_resolve(self, qname, rtype, *a, **kw):
            qname = str(qname)
            if rtype == "TXT" and qname.startswith("_dmarc."):
                return [_FakeRdata('"v=DMARC1; p=reject"')]
            if rtype == "TXT" and "_domainkey" in qname:
                raise dns.resolver.NXDOMAIN()
            if rtype == "TXT":
                return [_FakeRdata('"v=spf1 -all"')]
            if rtype == "MX":
                return [mock.Mock(preference=10, exchange="mail.example.com.")]
            raise AssertionError(qname)

        with mock.patch.object(dns.resolver.Resolver, "resolve", fake_resolve):
            result = pr.analyze_email_security("example.com", store=store)

        assert result["spf"]["status"] == "found"
        assert result["dmarc"]["status"] == "found"
        assert result["dkim"]["status"] == "not_found"
        assert result["mx"]["status"] == "found"
        assert result["mx"]["records"][0]["exchange"] == "mail.example.com"

        persisted = store.all()
        assert len(persisted) == 1
        assert persisted[0]["confidence"] == pr.CONFIDENCE_HIGH

    def test_nothing_found_is_low_confidence(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = pr.analyze_email_security("example.com", store=store)

        assert result["spf"]["status"] == "not_found"
        assert result["dmarc"]["status"] == "not_found"
        persisted = store.all()
        assert persisted[0]["confidence"] == pr.CONFIDENCE_LOW

    def test_dkim_selector_hit_is_recorded(self):
        def fake_resolve(self, qname, rtype, *a, **kw):
            qname = str(qname)
            if "default._domainkey" in qname:
                return [_FakeRdata('"v=DKIM1; k=rsa; p=ABC"')]
            raise dns.resolver.NXDOMAIN()

        with mock.patch.object(dns.resolver.Resolver, "resolve", fake_resolve):
            result = pr.analyze_email_security("example.com")

        assert result["dkim"]["status"] == "found"
        assert result["dkim"]["found_selectors"][0]["selector"] == "default"


# ---------------------------------------------------------------------------
# run_passive_recon (end-to-end orchestration, mocked network boundary)
# ---------------------------------------------------------------------------

class TestRunPassiveRecon:
    def test_full_run_persists_and_returns_summary(self, tmp_path):
        output_dir = tmp_path / "output"

        def fake_dns_resolve(self, qname, rtype, *a, **kw):
            if rtype == "A":
                return [_FakeRdata("93.184.216.34")]
            raise dns.resolver.NXDOMAIN()

        fake_der = _make_self_signed_der("example.com", sans=["example.com"])
        fake_tls_sock = mock.MagicMock()
        fake_tls_sock.getpeercert.return_value = fake_der
        fake_tls_sock.__enter__.return_value = fake_tls_sock
        fake_tls_sock.__exit__.return_value = False
        fake_context = mock.MagicMock()
        fake_context.wrap_socket.return_value = fake_tls_sock
        fake_raw_sock = mock.MagicMock()
        fake_raw_sock.__enter__.return_value = fake_raw_sock
        fake_raw_sock.__exit__.return_value = False

        with mock.patch.object(dns.resolver.Resolver, "resolve", fake_dns_resolve), \
             mock.patch.object(pr.python_whois, "whois", return_value={}), \
             mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            summary = pr.run_passive_recon("example.com", output_dir=str(output_dir), enable_asn=False)

        assert summary["target"] == "example.com"
        assert summary["dns"]["A"]["status"] == "found"
        assert summary["tls_certificate"]["status"] == "found"
        assert os.path.exists(output_dir / "pending_assets.json")

        with open(output_dir / "pending_assets.json") as f:
            persisted = json.load(f)
        assert len(persisted) >= 2  # at least the A record + the certificate

    def test_invalid_target_raises_before_any_persistence(self, tmp_path):
        output_dir = tmp_path / "output"
        with pytest.raises(pr.ScopeError):
            pr.run_passive_recon("*.evil.com", output_dir=str(output_dir))
        assert not (output_dir / "pending_assets.json").exists()

    def test_single_stage_failure_does_not_abort_run(self, tmp_path):
        output_dir = tmp_path / "output"
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=RuntimeError("boom")), \
             mock.patch.object(pr.python_whois, "whois", side_effect=RuntimeError("boom")), \
             mock.patch("socket.create_connection", side_effect=OSError("boom")):
            summary = pr.run_passive_recon("example.com", output_dir=str(output_dir), enable_asn=False)

        # dns/whois/tls all failed, but the run completed and reported a summary
        assert summary["target"] == "example.com"
        assert summary["finished_at"]


# ---------------------------------------------------------------------------
# Live smoke tests (real network, safe RFC 2606 documentation domain only)
# ---------------------------------------------------------------------------

@requires_network
class TestLiveSmoke:
    def test_enumerate_dns_live(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        results = pr.enumerate_dns(SAFE_TARGET, store=store, record_types=["A", "NS"])
        assert results["A"]["status"] == "found"
        assert len(results["A"]["records"]) >= 1
        for ip in results["A"]["records"]:
            ipaddress.ip_address(ip)  # must be valid IPs

    def test_discover_tls_certificate_live(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        result = pr.discover_tls_certificate(SAFE_TARGET, store=store, timeout=8.0)
        assert result["status"] in ("found", "error")  # network flakiness tolerated
        if result["status"] == "found":
            assert "example.com" in result["sans"] or result["certificate"]["subject"]

    def test_whois_lookup_live(self):
        result = pr.whois_lookup(SAFE_TARGET)
        assert result["status"] in ("found", "not_found", "error")

    def test_run_passive_recon_live_end_to_end(self, tmp_path):
        output_dir = tmp_path / "output"
        summary = pr.run_passive_recon(SAFE_TARGET, output_dir=str(output_dir), timeout=8.0)
        assert summary["target"] == SAFE_TARGET
        assert os.path.exists(output_dir / "pending_assets.json")
        with open(output_dir / "pending_assets.json") as f:
            data = json.load(f)
        json.dumps(data)  # confirm full persisted store is JSON-serializable
        assert len(data) >= 1
