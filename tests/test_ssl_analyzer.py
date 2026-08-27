"""
Tests for reconhound/ssl_analyzer.py (ReconHound Module 4 per context.md's
build order — catalog item 17, build-order position 4).

Run with:  ./.venv/bin/python -m pytest tests/test_ssl_analyzer.py -v

The seven analysis functions are pure (no network access) and are tested
directly against real certificates built with the `cryptography` library
(same technique as test_passive_recon.py's _make_self_signed_der), so most
of this suite needs no mocking at all. Only _negotiate_tls / run_ssl_analysis
(the one function that does real I/O) mock the socket/ssl boundary,
mirroring test_passive_recon.py's TestDiscoverTlsCertificate pattern.
"""

import datetime as dt
import json
import os
import socket
import ssl
import sys
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import ssl_analyzer as sa


SAFE_HOST = "example.com"


# ---------------------------------------------------------------------------
# Certificate-building helpers
# ---------------------------------------------------------------------------

def _build_cert(
    subject_cn,
    issuer_cn=None,
    signing_key=None,
    sans=None,
    not_before=None,
    not_after=None,
    key=None,
    algorithm="rsa",
):
    """
    Build an X.509 certificate. If issuer_cn/signing_key are omitted, the
    cert is self-signed (issuer == subject, signed with its own key).
    Returns (cert, key, der_bytes).
    """
    if key is None:
        key = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
            if algorithm == "rsa"
            else ec.generate_private_key(ec.SECP256R1())
        )
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = (
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
        if issuer_cn else subject
    )
    signer_key = signing_key or key

    not_before = not_before or (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1))
    not_after = not_after or (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False,
        )
    cert = builder.sign(signer_key, hashes.SHA256())
    return cert, key, cert.public_bytes(Encoding.DER)


# ---------------------------------------------------------------------------
# validate_ssl_host
# ---------------------------------------------------------------------------

class TestValidateSslHost:
    def test_accepts_domain(self):
        assert sa.validate_ssl_host("example.com") == "example.com"

    def test_accepts_ipv4_literal(self):
        assert sa.validate_ssl_host("93.184.216.34") == "93.184.216.34"

    def test_lowercases_and_strips_trailing_dot(self):
        assert sa.validate_ssl_host("Example.COM.") == "example.com"

    def test_rejects_url(self):
        with pytest.raises(sa.ScopeError):
            sa.validate_ssl_host("https://example.com/")

    def test_rejects_wildcard(self):
        with pytest.raises(sa.ScopeError):
            sa.validate_ssl_host("*.example.com")

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(sa.ScopeError):
            sa.validate_ssl_host(bad)

    def test_in_scope_subdomain_accepted(self):
        assert sa.validate_ssl_host("api.example.com", target="example.com") == "api.example.com"

    def test_out_of_scope_domain_rejected(self):
        with pytest.raises(sa.ScopeError):
            sa.validate_ssl_host("evil.com", target="example.com")

    def test_ip_literal_skips_scope_check(self):
        # IP hosts are not compared against a domain `target`.
        assert sa.validate_ssl_host("1.2.3.4", target="example.com") == "1.2.3.4"


# ---------------------------------------------------------------------------
# analyze_certificate_validity
# ---------------------------------------------------------------------------

class TestAnalyzeCertificateValidity:
    def test_currently_valid_certificate(self):
        cert, _, _ = _build_cert("example.com")
        result = sa.analyze_certificate_validity(cert)
        assert result["is_currently_valid_period"] is True
        assert result["is_expired"] is False
        assert result["is_not_yet_valid"] is False
        assert result["days_until_expiry"] > 300

    def test_expired_certificate(self):
        now = dt.datetime.now(dt.timezone.utc)
        cert, _, _ = _build_cert(
            "example.com",
            not_before=now - dt.timedelta(days=100),
            not_after=now - dt.timedelta(days=1),
        )
        result = sa.analyze_certificate_validity(cert)
        assert result["is_expired"] is True
        assert result["is_currently_valid_period"] is False
        assert result["days_until_expiry"] < 0

    def test_not_yet_valid_certificate(self):
        now = dt.datetime.now(dt.timezone.utc)
        cert, _, _ = _build_cert(
            "example.com",
            not_before=now + dt.timedelta(days=10),
            not_after=now + dt.timedelta(days=400),
        )
        result = sa.analyze_certificate_validity(cert)
        assert result["is_not_yet_valid"] is True
        assert result["is_currently_valid_period"] is False

    def test_no_arbitrary_expiring_soon_flag_invented(self):
        cert, _, _ = _build_cert("example.com")
        result = sa.analyze_certificate_validity(cert)
        assert "expiring_soon" not in result
        assert "severity" not in result

    def test_json_serializable(self):
        cert, _, _ = _build_cert("example.com")
        json.dumps(sa.analyze_certificate_validity(cert))


# ---------------------------------------------------------------------------
# analyze_tls_version
# ---------------------------------------------------------------------------

class TestAnalyzeTlsVersion:
    @pytest.mark.parametrize("version", ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"])
    def test_outdated_versions_flagged(self, version):
        result = sa.analyze_tls_version(version)
        assert result["is_outdated"] is True

    @pytest.mark.parametrize("version", ["TLSv1.2", "TLSv1.3"])
    def test_modern_versions_not_flagged(self, version):
        result = sa.analyze_tls_version(version)
        assert result["is_outdated"] is False

    def test_none_version_is_none_not_flagged(self):
        result = sa.analyze_tls_version(None)
        assert result["is_outdated"] is None


# ---------------------------------------------------------------------------
# analyze_cipher_suite
# ---------------------------------------------------------------------------

class TestAnalyzeCipherSuite:
    def test_cipher_tuple_parsed(self):
        result = sa.analyze_cipher_suite(("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256))
        assert result == {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "secret_bits": 256}

    def test_none_cipher_handled(self):
        result = sa.analyze_cipher_suite(None)
        assert result == {"name": None, "protocol": None, "secret_bits": None}


# ---------------------------------------------------------------------------
# _hostname_matches / validate_hostname_against_cert
# ---------------------------------------------------------------------------

class TestHostnameMatching:
    def test_exact_match(self):
        assert sa._hostname_matches("example.com", "example.com") is True

    def test_wildcard_matches_one_label(self):
        assert sa._hostname_matches("*.example.com", "api.example.com") is True

    def test_wildcard_does_not_match_bare_domain(self):
        assert sa._hostname_matches("*.example.com", "example.com") is False

    def test_wildcard_does_not_match_two_labels_deep(self):
        assert sa._hostname_matches("*.example.com", "a.b.example.com") is False

    def test_case_insensitive(self):
        assert sa._hostname_matches("Example.COM", "example.com") is True

    def test_unrelated_name_no_match(self):
        assert sa._hostname_matches("other.com", "example.com") is False


class TestValidateHostnameAgainstCert:
    def test_matches_san(self):
        cert, _, _ = _build_cert("irrelevant-cn.example", sans=["example.com", "www.example.com"])
        result = sa.validate_hostname_against_cert(cert, "www.example.com")
        assert result["matched"] is True
        assert "www.example.com" in result["matched_names"]

    def test_matches_wildcard_san(self):
        cert, _, _ = _build_cert("example.com", sans=["*.example.com"])
        result = sa.validate_hostname_against_cert(cert, "api.example.com")
        assert result["matched"] is True

    def test_falls_back_to_cn_when_no_matching_san(self):
        cert, _, _ = _build_cert("example.com", sans=["other.example"])
        result = sa.validate_hostname_against_cert(cert, "example.com")
        assert result["matched"] is True
        assert "example.com" in result["matched_names"]

    def test_mismatch_reported_not_silently_passed(self):
        cert, _, _ = _build_cert("example.com", sans=["example.com"])
        result = sa.validate_hostname_against_cert(cert, "evil.com")
        assert result["matched"] is False
        assert result["matched_names"] == []
        assert "example.com" in result["candidate_names"]


# ---------------------------------------------------------------------------
# extract_sans
# ---------------------------------------------------------------------------

class TestExtractSans:
    def test_normalizes_case_and_trailing_dot(self):
        cert, _, _ = _build_cert("example.com", sans=["Example.com.", "API.example.com"])
        result = sa.extract_sans(cert)
        assert result["sans"] == ["api.example.com", "example.com"]
        assert result["count"] == 2

    def test_no_san_extension(self):
        cert, _, _ = _build_cert("example.com", sans=None)
        result = sa.extract_sans(cert)
        assert result["sans"] == []
        assert result["count"] == 0


# ---------------------------------------------------------------------------
# analyze_certificate_chain
# ---------------------------------------------------------------------------

class TestAnalyzeCertificateChain:
    def test_properly_linked_two_cert_chain(self):
        root_cert, root_key, root_der = _build_cert("Test Root CA")
        leaf_cert, _, leaf_der = _build_cert(
            "example.com", issuer_cn="Test Root CA", signing_key=root_key,
        )
        result = sa.analyze_certificate_chain([leaf_der, root_der])
        assert result["length"] == 2
        assert result["properly_linked"] is True
        assert result["terminates_in_self_signed"] is True
        assert result["notes"] == []

    def test_incomplete_chain_flagged(self):
        leaf_cert, _, leaf_der = _build_cert("example.com", issuer_cn="Some CA")
        result = sa.analyze_certificate_chain([leaf_der])
        assert result["length"] == 1
        assert result["properly_linked"] is None
        assert any("fewer than 2" in n for n in result["notes"])

    def test_empty_chain(self):
        result = sa.analyze_certificate_chain([])
        assert result["length"] == 0
        assert result["certificates"] == []

    def test_malformed_der_does_not_crash(self):
        result = sa.analyze_certificate_chain([b"not a real certificate"])
        assert result["error"] is not None
        assert result["certificates"] == []

    def test_json_serializable(self):
        root_cert, root_key, root_der = _build_cert("Test Root CA")
        leaf_cert, _, leaf_der = _build_cert("example.com", issuer_cn="Test Root CA", signing_key=root_key)
        result = sa.analyze_certificate_chain([leaf_der, root_der])
        json.dumps(result)


# ---------------------------------------------------------------------------
# detect_self_signed
# ---------------------------------------------------------------------------

class TestDetectSelfSigned:
    def test_self_signed_rsa_cert_detected_high_confidence(self):
        cert, _, _ = _build_cert("Self Signed Test", algorithm="rsa")
        result = sa.detect_self_signed(cert)
        assert result["self_signed"] is True
        assert result["confidence"] == sa.CONFIDENCE_HIGH

    def test_self_signed_ec_cert_detected_high_confidence(self):
        cert, _, _ = _build_cert("Self Signed EC Test", algorithm="ec")
        result = sa.detect_self_signed(cert)
        assert result["self_signed"] is True
        assert result["confidence"] == sa.CONFIDENCE_HIGH

    def test_ca_signed_cert_not_self_signed(self):
        root_cert, root_key, _ = _build_cert("Test Root CA")
        leaf_cert, _, _ = _build_cert("example.com", issuer_cn="Test Root CA", signing_key=root_key)
        result = sa.detect_self_signed(leaf_cert)
        assert result["self_signed"] is False
        assert "differ" in result["evidence"][0]

    def test_never_claims_exploitable(self):
        cert, _, _ = _build_cert("Self Signed Test")
        result = sa.detect_self_signed(cert)
        assert "exploit" not in json.dumps(result).lower()


# ---------------------------------------------------------------------------
# _negotiate_tls (mocked socket/ssl boundary)
# ---------------------------------------------------------------------------

def _fake_tls_stack(der, version="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), chain=None):
    fake_tls_sock = mock.MagicMock()
    fake_tls_sock.getpeercert.return_value = der
    fake_tls_sock.version.return_value = version
    fake_tls_sock.cipher.return_value = cipher
    fake_tls_sock.get_unverified_chain.return_value = chain if chain is not None else [der]
    fake_tls_sock.__enter__.return_value = fake_tls_sock
    fake_tls_sock.__exit__.return_value = False

    fake_context = mock.MagicMock()
    fake_context.wrap_socket.return_value = fake_tls_sock

    fake_raw_sock = mock.MagicMock()
    fake_raw_sock.__enter__.return_value = fake_raw_sock
    fake_raw_sock.__exit__.return_value = False
    return fake_context, fake_raw_sock, fake_tls_sock


class TestNegotiateTls:
    def test_successful_handshake(self):
        _, _, der = _build_cert("example.com")[0], None, _build_cert("example.com")[2]
        fake_context, fake_raw_sock, _ = _fake_tls_stack(der)
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            result = sa._negotiate_tls("example.com", 443, "example.com", 5.0)
        assert result["status"] == "found"
        assert result["version"] == "TLSv1.3"
        assert result["leaf_der"] == der

    def test_connection_refused_is_unavailable(self):
        with mock.patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            result = sa._negotiate_tls("example.com", 443, "example.com", 5.0)
        assert result["status"] == "unavailable"

    def test_dns_failure_is_unavailable(self):
        with mock.patch("socket.create_connection", side_effect=socket.gaierror("no such host")):
            result = sa._negotiate_tls("nonexistent.invalid", 443, "nonexistent.invalid", 5.0)
        assert result["status"] == "unavailable"

    def test_connection_timeout_is_unavailable(self):
        with mock.patch("socket.create_connection", side_effect=socket.timeout("timed out")):
            result = sa._negotiate_tls("example.com", 443, "example.com", 5.0)
        assert result["status"] == "unavailable"

    def test_tls_handshake_failure_is_handshake_failed(self):
        fake_raw_sock = mock.MagicMock()
        fake_raw_sock.__enter__.return_value = fake_raw_sock
        fake_raw_sock.__exit__.return_value = False
        fake_context = mock.MagicMock()
        fake_context.wrap_socket.side_effect = ssl.SSLError("handshake failure")
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            result = sa._negotiate_tls("example.com", 443, "example.com", 5.0)
        assert result["status"] == "handshake_failed"

    def test_no_certificate_presented_is_error(self):
        fake_context, fake_raw_sock, fake_tls_sock = _fake_tls_stack(b"placeholder")
        fake_tls_sock.getpeercert.return_value = None
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            result = sa._negotiate_tls("example.com", 443, "example.com", 5.0)
        assert result["status"] == "error"

    def test_chain_retrieval_failure_falls_back_to_empty(self):
        cert, _, der = _build_cert("example.com")
        fake_context, fake_raw_sock, fake_tls_sock = _fake_tls_stack(der)
        fake_tls_sock.get_unverified_chain.side_effect = AttributeError("not supported")
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            result = sa._negotiate_tls("example.com", 443, "example.com", 5.0)
        assert result["status"] == "found"
        assert result["chain_der"] == []


# ---------------------------------------------------------------------------
# run_ssl_analysis (integration, mocked socket/ssl boundary)
# ---------------------------------------------------------------------------

class TestRunSslAnalysis:
    def test_clean_certificate_full_run(self, tmp_path):
        output_dir = tmp_path / "output"
        root_cert, root_key, root_der = _build_cert("Test Root CA")
        leaf_cert, _, leaf_der = _build_cert(
            "example.com", issuer_cn="Test Root CA", signing_key=root_key,
            sans=["example.com", "www.example.com"],
        )
        fake_context, fake_raw_sock, _ = _fake_tls_stack(leaf_der, chain=[leaf_der, root_der])
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            summary = sa.run_ssl_analysis("example.com", target="example.com", output_dir=str(output_dir))

        assert summary["status"] == "found"
        assert summary["has_certificate_or_tls_problems"] is False
        assert summary["hostname_validation"]["matched"] is True
        assert len(summary["discovered_hostnames"]) == 2
        assert os.path.exists(output_dir / "pending_assets.json")

        with open(output_dir / "pending_assets.json") as f:
            persisted = json.load(f)
        json.dumps(persisted)
        types = [p["type"] for p in persisted]
        assert types.count("tls_certificate_analysis") == 1
        assert types.count("tls_san") == 2

    def test_self_signed_expired_mismatched_cert_flagged_but_status_found(self, tmp_path):
        output_dir = tmp_path / "output"
        now = dt.datetime.now(dt.timezone.utc)
        cert, _, der = _build_cert(
            "totally-different.example", sans=["totally-different.example"],
            not_before=now - dt.timedelta(days=400), not_after=now - dt.timedelta(days=1),
        )
        fake_context, fake_raw_sock, _ = _fake_tls_stack(der, version="TLSv1", chain=[der])
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            summary = sa.run_ssl_analysis("example.com", output_dir=str(output_dir))

        # Analysis itself succeeded — the certificate problems are DATA, not an analysis failure.
        assert summary["status"] == "found"
        assert summary["has_certificate_or_tls_problems"] is True
        assert summary["validity"]["is_expired"] is True
        assert summary["tls_version"]["is_outdated"] is True
        assert summary["self_signed"]["self_signed"] is True
        assert summary["hostname_validation"]["matched"] is False

    def test_unavailable_short_circuits_no_persistence(self, tmp_path):
        output_dir = tmp_path / "output"
        with mock.patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            summary = sa.run_ssl_analysis("example.com", output_dir=str(output_dir))
        assert summary["status"] == "unavailable"
        assert summary["error"]
        assert not (output_dir / "pending_assets.json").exists()

    def test_invalid_host_raises_before_persistence(self, tmp_path):
        output_dir = tmp_path / "output"
        with pytest.raises(sa.ScopeError):
            sa.run_ssl_analysis("not a host!", output_dir=str(output_dir))
        assert not (output_dir / "pending_assets.json").exists()

    def test_out_of_scope_host_raises(self, tmp_path):
        output_dir = tmp_path / "output"
        with pytest.raises(sa.ScopeError):
            sa.run_ssl_analysis("evil.com", target="example.com", output_dir=str(output_dir))

    def test_ip_host_without_sni_skips_hostname_validation(self, tmp_path):
        output_dir = tmp_path / "output"
        cert, _, der = _build_cert("example.com", sans=["example.com"])
        fake_context, fake_raw_sock, _ = _fake_tls_stack(der, chain=[der])
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            summary = sa.run_ssl_analysis("93.184.216.34", output_dir=str(output_dir))
        assert summary["hostname_validation"]["matched"] is None
        assert "note" in summary["hostname_validation"]

    def test_prior_module_data_preserved(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{"type": "dns_record", "source": "passive_recon.py"}]
        pending.write_text(json.dumps(pre_existing))

        cert, _, der = _build_cert("example.com", sans=["example.com"])
        fake_context, fake_raw_sock, _ = _fake_tls_stack(der, chain=[der])
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            sa.run_ssl_analysis("example.com", output_dir=str(output_dir))

        with open(pending) as f:
            data = json.load(f)
        assert data[0] == pre_existing[0]
        assert len(data) > 1

    def test_result_json_serializable(self, tmp_path):
        output_dir = tmp_path / "output"
        cert, _, der = _build_cert("example.com", sans=["example.com"])
        fake_context, fake_raw_sock, _ = _fake_tls_stack(der, chain=[der])
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            summary = sa.run_ssl_analysis("example.com", output_dir=str(output_dir))
        json.dumps(summary)

    def test_malformed_leaf_certificate_is_analysis_error(self, tmp_path):
        output_dir = tmp_path / "output"
        fake_context, fake_raw_sock, _ = _fake_tls_stack(b"not a valid der certificate")
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            summary = sa.run_ssl_analysis("example.com", output_dir=str(output_dir))
        assert summary["status"] == "error"
        assert summary["error"]
        assert not (output_dir / "pending_assets.json").exists()


# ---------------------------------------------------------------------------
# PendingAssetsStore / make_finding (shared conventions)
# ---------------------------------------------------------------------------

class TestPendingAssetsStoreAndFinding:
    def test_finding_source_and_json_safe(self):
        finding = sa.make_finding("tls_certificate_analysis", SAFE_HOST, {"a": 1}, ["e"], sa.CONFIDENCE_HIGH)
        assert finding["source"] == "ssl_analyzer.py"
        json.dumps(finding)

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = sa.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(sa.PersistenceError):
            store.add(sa.make_finding("tls_san", SAFE_HOST, "x", ["e"], sa.CONFIDENCE_HIGH))

    def test_atomic_write_no_temp_file_left_behind(self, tmp_path):
        store = sa.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        store.add(sa.make_finding("tls_san", SAFE_HOST, "x", ["e"], sa.CONFIDENCE_HIGH))
        leftovers = [p for p in os.listdir(store.output_dir) if p.startswith(".pending_assets_")]
        assert leftovers == []
