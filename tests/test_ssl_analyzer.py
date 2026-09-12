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
        # The three original keys keep exactly their previous meaning.
        assert result["name"] == "TLS_AES_256_GCM_SHA384"
        assert result["protocol"] == "TLSv1.3"
        assert result["secret_bits"] == 256

    def test_none_cipher_handled(self):
        result = sa.analyze_cipher_suite(None)
        assert result["name"] is None
        assert result["protocol"] is None
        assert result["secret_bits"] is None
        assert result["forward_secrecy"] is None

    def test_tls13_forward_secrecy_is_labelled_as_a_protocol_inference(self):
        result = sa.analyze_cipher_suite(("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128))
        assert result["forward_secrecy"] is True
        assert result["aead"] is True
        assert "inferred from TLS 1.3" in result["basis"]

    @pytest.mark.parametrize("name,kx,pfs", [
        ("ECDHE-RSA-AES128-GCM-SHA256", "ECDHE", True),
        ("DHE-RSA-AES256-SHA", "DHE", True),
        ("AES256-GCM-SHA384", "RSA", False),
        ("ECDH-RSA-AES128-SHA", "ECDH (static)", False),
    ])
    def test_key_exchange_and_forward_secrecy_from_cipher_name(self, name, kx, pfs):
        result = sa.analyze_cipher_suite((name, "TLSv1.2", 128))
        assert result["key_exchange"] == kx
        assert result["forward_secrecy"] is pfs

    @pytest.mark.parametrize("name,marker", [
        ("ECDHE-RSA-RC4-SHA", "RC4"),
        ("DES-CBC3-SHA", "Triple DES"),
        ("ECDHE-RSA-NULL-SHA", "NULL"),
        ("ADH-AES256-SHA", "anonymous"),
    ])
    def test_obsolete_primitives_are_observed_without_a_severity(self, name, marker):
        result = sa.analyze_cipher_suite((name, "TLSv1.2", 128))
        assert any(marker.lower() in w.lower() for w in result["weak_indicators"])
        blob = json.dumps(result).lower()
        assert "critical" not in blob and "severity" not in blob

    @pytest.mark.parametrize("bad", [("A", "TLSv1.3"), "notatuple", ("A",)])
    def test_malformed_cipher_value_does_not_raise(self, bad):
        result = sa.analyze_cipher_suite(bad)
        assert result["malformed"] is True
        assert result["name"] is None


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


# ===========================================================================
# Regression tests — one per defect confirmed by the ssl_analyzer.py audit.
#
# Every test below reproduces a behaviour that was observed in the module
# before the fix, so a regression re-introduces a failure here rather than a
# silent wrong answer in a live scan.
# ===========================================================================

import hashlib
import ipaddress
import threading

from cryptography.hazmat.primitives.asymmetric import ed25519, padding
from cryptography.x509.name import _ASN1Type


_UNSET = object()


def _build_cert_ext(
    subject_cn,
    issuer_cn=None,
    signing_key=None,
    general_names=None,
    not_before=None,
    not_after=None,
    key=None,
    algorithm="rsa",
    hash_alg=_UNSET,
    rsa_padding=None,
    extra_subject_attrs=(),
):
    """
    Like _build_cert, but takes raw x509.GeneralName objects (so IP SANs,
    malformed DNS names and huge SAN lists can be expressed) and allows extra
    subject RDNs, an alternative signature padding and non-hash algorithms.
    """
    if key is None:
        if algorithm == "rsa":
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif algorithm == "ed25519":
            key = ed25519.Ed25519PrivateKey.generate()
        else:
            key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)] + list(extra_subject_attrs))
    issuer = (x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
              if issuer_cn else subject)
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
    if general_names is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(general_names), critical=False)

    kwargs = {}
    if rsa_padding is not None:
        kwargs["rsa_padding"] = rsa_padding
    algo = hashes.SHA256() if hash_alg is _UNSET else hash_alg
    cert = builder.sign(signer_key, algo, **kwargs)
    return cert, key, cert.public_bytes(Encoding.DER)


def _fake_stack_ext(der, version="TLSv1.3",
                    cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
                    chain=None, peer=("93.184.216.34", 443)):
    """_fake_tls_stack plus a getpeername() the analyzer now records."""
    fake_context, fake_raw_sock, fake_tls_sock = _fake_tls_stack(
        der, version=version, cipher=cipher, chain=chain)
    fake_raw_sock.getpeername.return_value = peer
    return fake_context, fake_raw_sock, fake_tls_sock


def _run(host, der, tmp_path, chain=None, **kwargs):
    fake_context, fake_raw_sock, _ = _fake_stack_ext(der, chain=chain or [der])
    with mock.patch("ssl.create_default_context", return_value=fake_context), \
         mock.patch("socket.create_connection", return_value=fake_raw_sock):
        return sa.run_ssl_analysis(host, output_dir=str(tmp_path / "output"), **kwargs)


class TestWildcardAndUnusableSansNeverBecomeHostnames:
    """
    A wildcard SAN used to be emitted as a discovered hostname. surface_mapper
    then created an asset literally named "*.example.com", marked it in scope
    (it *is* a suffix match), and the orchestrator's ssl_targets() scheduled an
    active TLS scan of it — which validate_ssl_host() rejects. Phantom asset
    plus a guaranteed scope-rejected execution, on every wildcard certificate.
    """

    def _cert(self):
        return _build_cert_ext("example.com", general_names=[
            x509.DNSName("*.example.com"),
            x509.DNSName("example.com"),
            x509.DNSName("api.example.com"),
            x509.DNSName("a b.example.com"),          # space: not a hostname
            x509.DNSName("x" * 300 + ".example.com"),  # over-long label
            x509.DNSName("localhost"),                 # single label
            x509.DNSName(""),                          # empty
            x509.DNSName("internal.corp.local"),       # out of scope
            x509.IPAddress(ipaddress.ip_address("93.184.216.34")),
        ])

    def test_only_concrete_hostnames_land_in_sans(self):
        cert, _, _ = self._cert()
        result = sa.extract_sans(cert)
        assert result["sans"] == ["api.example.com", "example.com", "internal.corp.local"]
        assert result["count"] == 3

    def test_wildcard_is_preserved_as_intelligence_not_discarded(self):
        cert, _, _ = self._cert()
        result = sa.extract_sans(cert)
        assert result["wildcard_sans"] == ["*.example.com"]

    def test_ip_sans_are_extracted(self):
        cert, _, _ = self._cert()
        result = sa.extract_sans(cert)
        assert result["ip_sans"] == ["93.184.216.34"]
        assert result["ip_san_count"] == 1
        assert result["wildcard_san_count"] == 1
        assert result["other_name_count"] == 4  # space, long label, single label, empty

    def test_unusable_dns_names_are_preserved_not_dropped(self):
        cert, _, _ = self._cert()
        others = sa.extract_sans(cert)["other_names"]
        assert "localhost" in others
        assert any(o.startswith("a b.") for o in others)
        assert any(o.startswith("xxxx") for o in others)

    def test_total_dns_names_accounts_for_everything(self):
        cert, _, _ = self._cert()
        result = sa.extract_sans(cert)
        assert result["total_dns_names"] == 8

    def test_no_tls_san_finding_is_emitted_for_a_wildcard(self, tmp_path):
        cert, _, der = self._cert()
        summary = _run("example.com", der, tmp_path, target="example.com")
        names = [e["hostname"] for e in summary["discovered_hostnames"]]
        assert "*.example.com" not in names
        persisted = json.loads((tmp_path / "output" / "pending_assets.json").read_text())
        san_values = [p["value"] for p in persisted if p["type"] == "tls_san"]
        assert "*.example.com" not in san_values
        assert set(san_values) == {"api.example.com", "example.com", "internal.corp.local"}

    def test_every_emitted_hostname_survives_this_modules_own_scope_gate(self, tmp_path):
        cert, _, der = self._cert()
        summary = _run("example.com", der, tmp_path, target="example.com")
        for entry in summary["discovered_hostnames"]:
            # No emitted name may be one run_ssl_analysis would itself refuse.
            sa.validate_ssl_host(entry["hostname"])

    def test_out_of_scope_san_is_retained_but_flagged(self, tmp_path):
        cert, _, der = self._cert()
        summary = _run("example.com", der, tmp_path, target="example.com")
        by_name = {e["hostname"]: e["in_scope"] for e in summary["discovered_hostnames"]}
        assert by_name["internal.corp.local"] is False
        assert by_name["api.example.com"] is True

    def test_only_one_connection_is_ever_made(self, tmp_path):
        cert, _, der = self._cert()
        fake_context, fake_raw_sock, _ = _fake_stack_ext(der)
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection",
                        return_value=fake_raw_sock) as connect:
            sa.run_ssl_analysis("example.com", target="example.com",
                                output_dir=str(tmp_path / "output"))
        assert connect.call_count == 1


class TestSanExtractionIsBounded:
    def test_huge_san_list_is_capped_with_explicit_accounting(self):
        names = [x509.DNSName(f"h{i}.example.com") for i in range(sa.MAX_SAN_HOSTNAMES + 500)]
        cert, _, _ = _build_cert_ext("example.com", general_names=names)
        result = sa.extract_sans(cert)
        assert len(result["sans"]) == sa.MAX_SAN_HOSTNAMES
        assert result["truncated"] is True
        assert result["total_dns_names"] == sa.MAX_SAN_HOSTNAMES + 500
        # A capped list must never read as a complete one.
        assert result["hostname_count"] == sa.MAX_SAN_HOSTNAMES + 500

    def test_huge_san_list_costs_one_atomic_write_not_one_per_san(self, tmp_path):
        names = [x509.DNSName(f"h{i}.example.com") for i in range(400)]
        cert, _, der = _build_cert_ext("example.com", general_names=names)
        fake_context, fake_raw_sock, _ = _fake_stack_ext(der)
        real_replace = os.replace
        writes = []

        def counting_replace(src, dst):
            writes.append(dst)
            return real_replace(src, dst)

        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock), \
             mock.patch("os.replace", counting_replace):
            summary = sa.run_ssl_analysis("example.com", target="example.com",
                                          output_dir=str(tmp_path / "output"))
        assert summary["findings_produced"] == 401
        assert summary["findings_persisted"] == 401
        # One batched write, not 401 whole-file rewrites (the quadratic path).
        assert len(writes) == 1

    def test_duplicate_sans_are_deduplicated(self):
        cert, _, _ = _build_cert_ext("example.com", general_names=[
            x509.DNSName("a.example.com"), x509.DNSName("A.example.com."),
            x509.DNSName("a.example.com"),
        ])
        assert sa.extract_sans(cert)["sans"] == ["a.example.com"]


class TestHostileCertificateTextIsNeutralised:
    def test_control_characters_are_escaped_not_deleted(self):
        hostile = "ex‫ample.com\r\nInjected: yes\x00tail"
        cert, _, _ = _build_cert_ext(hostile)
        rendered = sa._name_to_dict(cert.subject)["commonName"]
        # Inert: no raw control byte survives ...
        assert not any(ch in rendered for ch in "\r\n\x00‫")
        # ... but the operator can still see what was there. Deleting them
        # silently rewrote this into the plausible "example.comInjected: yes".
        assert "\\x0d" in rendered and "\\x00" in rendered and "\\u202b" in rendered

    def test_oversized_name_value_is_clipped(self):
        # commonName is length-capped by the encoder; an unconstrained OID is
        # not, and a 50 KB attribute value is exactly what used to be written
        # verbatim into the shared pending_assets.json.
        huge = [x509.NameAttribute(x509.ObjectIdentifier("1.2.3.4.5.6"), "a" * 50_000)]
        cert, _, _ = _build_cert_ext("example.com", extra_subject_attrs=huge)
        rendered = sa._name_to_dict(cert.subject)["1.2.3.4.5.6"]
        assert len(rendered) < sa.MAX_NAME_VALUE_CHARS + 64
        assert "clipped" in rendered

    def test_unregistered_oids_do_not_collapse_onto_one_key(self):
        # `oid._name` is the literal "Unknown OID" for anything outside
        # cryptography's registry, so two unregistered attributes used to
        # overwrite each other under a single "Unknown OID" key.
        extra = [x509.NameAttribute(x509.ObjectIdentifier("1.2.3.4.5.6"), "first"),
                 x509.NameAttribute(x509.ObjectIdentifier("1.2.3.4.5.7"), "second")]
        cert, _, _ = _build_cert_ext("example.com", extra_subject_attrs=extra)
        rendered = sa._name_to_dict(cert.subject)
        assert rendered["1.2.3.4.5.6"] == "first"
        assert rendered["1.2.3.4.5.7"] == "second"
        assert "Unknown OID" not in rendered

    def test_bytes_valued_rdn_does_not_break_json_persistence(self, tmp_path):
        """
        `cryptography` types an RDN value as `str | bytes`. A certificate
        carrying an x500UniqueIdentifier produced real bytes, json.dump raised
        TypeError inside the store, and the *entire completed analysis* was
        lost — the exact outcome context.md §12.11 forbids.
        """
        extra = [x509.NameAttribute(NameOID.X500_UNIQUE_IDENTIFIER, b"\x01\x02\x03",
                                    _type=_ASN1Type.BitString)]
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")],
            extra_subject_attrs=extra)
        json.dumps(sa._name_to_dict(cert.subject))
        summary = _run("example.com", der, tmp_path, target="example.com")
        assert summary["status"] == "found"
        assert summary["findings_persisted"] == 2
        assert summary["errors"] == []
        json.loads((tmp_path / "output" / "pending_assets.json").read_text())

    def test_repeated_rdn_oids_are_not_silently_overwritten(self):
        extra = [x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Unit-A"),
                 x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Unit-B")]
        cert, _, _ = _build_cert_ext("example.com", extra_subject_attrs=extra)
        assert sa._name_to_dict(cert.subject)["organizationalUnitName"] == ["Unit-A", "Unit-B"]

    def test_legitimate_non_ascii_text_survives(self):
        cert, _, _ = _build_cert_ext("Beispiel Ürünler 株式会社")
        assert sa._name_to_dict(cert.subject)["commonName"] == "Beispiel Ürünler 株式会社"


class TestSelfSignedVersusSelfIssued:
    def test_self_issued_but_cross_signed_is_not_reported_as_self_signed(self):
        """
        issuer==subject with a signature from a DIFFERENT key is a cross-signed
        or re-issued CA certificate, not a self-signed one. It used to be
        reported as self_signed=True, and risk_engine.py turns that into a
        MEDIUM `self_signed_certificate` signal — a manufactured finding.
        """
        own = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert, _, _ = _build_cert_ext("Some Root CA", key=own, signing_key=other)
        result = sa.detect_self_signed(cert)
        assert result["self_signed"] is False
        assert result["self_issued"] is True
        assert result["signature_verified"] is False
        assert result["confidence"] == sa.CONFIDENCE_HIGH

    def test_rsa_pss_self_signed_certificate_stays_self_signed(self):
        """
        Verifying every RSA certificate under PKCS#1 v1.5 made a genuinely
        self-signed RSA-PSS certificate raise InvalidSignature.
        """
        pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        cert, _, _ = _build_cert_ext("pss.example.com", rsa_padding=pss)
        result = sa.detect_self_signed(cert)
        assert result["self_signed"] is True
        assert result["signature_verified"] is True

    def test_ed25519_self_signed(self):
        cert, _, _ = _build_cert_ext("ed.example.com", algorithm="ed25519", hash_alg=None)
        result = sa.detect_self_signed(cert)
        assert result["self_signed"] is True
        assert result["signature_verified"] is True

    def test_ec_cross_signed_is_not_self_signed(self):
        own = ec.generate_private_key(ec.SECP256R1())
        other = ec.generate_private_key(ec.SECP256R1())
        cert, _, _ = _build_cert_ext("ec.example.com", key=own, signing_key=other)
        assert sa.detect_self_signed(cert)["self_signed"] is False

    def test_differing_names_are_answered_confidently(self):
        root_cert, root_key, _ = _build_cert_ext("Test Root CA")
        leaf, _, _ = _build_cert_ext("example.com", issuer_cn="Test Root CA",
                                     signing_key=root_key)
        result = sa.detect_self_signed(leaf)
        assert result["self_signed"] is False
        assert result["self_issued"] is False

    def test_never_claims_a_severity(self):
        cert, _, _ = _build_cert_ext("self.example.com")
        blob = json.dumps(sa.detect_self_signed(cert)).lower()
        assert "critical" not in blob and "vulnerab" not in blob


class TestHostnameMatchingEdgeCases:
    @pytest.mark.parametrize("cert_name,hostname,expected", [
        ("*.example.com", "a.example.com", True),
        ("*.example.com", "example.com", False),
        ("*.example.com", "a.b.example.com", False),
        ("*.*.example.com", "a.b.example.com", False),
        ("**.example.com", "a.example.com", False),
        ("*.", "a.b", False),
        ("*", "a", False),
        # A DNS wildcard must never authorise an IP identity, however neatly
        # the labels line up.
        ("*.1.2.3", "4.1.2.3", False),
        ("*.example.com", "::1", False),
    ])
    def test_wildcard_semantics(self, cert_name, hostname, expected):
        assert sa._hostname_matches(cert_name, hostname) is expected

    @pytest.mark.parametrize("cert_name,hostname", [
        ("xn--mnchen-3ya.de", "münchen.de"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("*.xn--mnchen-3ya.de", "a.münchen.de"),
    ])
    def test_idna_a_label_and_u_label_are_the_same_name(self, cert_name, hostname):
        assert sa._hostname_matches(cert_name, hostname) is True

    def test_suffix_confusion_is_not_a_match(self):
        assert sa._hostname_matches("example.com", "evil-example.com") is False
        assert sa._in_scope_host("evil-example.com", "example.com") is False
        assert sa._in_scope_host("evil-xn--mnchen-3ya.de", "münchen.de") is False

    def test_idna_scope_comparison_is_symmetric(self):
        assert sa._in_scope_host("münchen.de", "xn--mnchen-3ya.de") is True
        assert sa._in_scope_host("a.münchen.de", "xn--mnchen-3ya.de") is True


class TestCertificateIdentityReporting:
    def test_cn_only_match_on_a_san_certificate_is_flagged(self):
        cert, _, _ = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("unrelated.example")])
        result = sa.validate_hostname_against_cert(cert, "example.com")
        assert result["matched"] is True            # unchanged contract
        assert result["matched_via"] == "common_name"
        assert result["rfc6125_matched"] is False   # what a browser would say
        assert any("commonName" in n for n in result["notes"])

    def test_san_match_is_rfc6125_clean(self):
        cert, _, _ = _build_cert_ext(
            "irrelevant", general_names=[x509.DNSName("www.example.com")])
        result = sa.validate_hostname_against_cert(cert, "www.example.com")
        assert result["matched_via"] == "subject_alternative_name"
        assert result["rfc6125_matched"] is True

    def test_ip_host_matches_an_ip_san(self):
        cert, _, _ = _build_cert_ext("example.com", general_names=[
            x509.DNSName("example.com"),
            x509.IPAddress(ipaddress.ip_address("93.184.216.34"))])
        result = sa.validate_hostname_against_cert(cert, "93.184.216.34")
        assert result["matched"] is True
        assert result["matched_via"] == "subject_alternative_name"

    def test_ip_host_with_no_ip_identity_is_not_tested_rather_than_mismatched(self):
        """
        No SNI is sent for an IP literal, so nothing was asserted and nothing
        can be validated. Reporting False would flag every ordinary
        certificate as a problem the moment an IP endpoint is inspected.
        """
        cert, _, _ = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        result = sa.validate_hostname_against_cert(cert, "93.184.216.34")
        assert result["matched"] is None
        assert "note" in result

    def test_mismatch_is_never_described_as_interception(self):
        cert, _, _ = _build_cert_ext(
            "other.example", general_names=[x509.DNSName("other.example")])
        blob = json.dumps(sa.validate_hostname_against_cert(cert, "example.com")).lower()
        for forbidden in ("mitm", "man-in-the-middle", "interception", "attack"):
            assert forbidden not in blob

    def test_candidate_names_are_deduplicated_and_bounded(self):
        names = [x509.DNSName(f"h{i}.example.com")
                 for i in range(sa.MAX_CANDIDATE_NAMES + 50)]
        cert, _, _ = _build_cert_ext("h0.example.com", general_names=names)
        result = sa.validate_hostname_against_cert(cert, "h0.example.com")
        assert len(result["candidate_names"]) == sa.MAX_CANDIDATE_NAMES
        assert result["candidate_names_truncated"] is True


class TestChainAnalysisRobustness:
    def _pair(self):
        root_cert, root_key, root_der = _build_cert_ext("Test Root CA")
        leaf, _, leaf_der = _build_cert_ext("example.com", issuer_cn="Test Root CA",
                                            signing_key=root_key)
        return leaf_der, root_der

    def test_parse_failure_does_not_misassign_fingerprints(self):
        leaf_der, root_der = self._pair()
        result = sa.analyze_certificate_chain([b"garbage", leaf_der, root_der])
        assert [c["fingerprint_sha256"] for c in result["certificates"]] == [
            hashlib.sha256(leaf_der).hexdigest(),
            hashlib.sha256(root_der).hexdigest(),
        ]

    def test_linkage_is_not_asserted_when_a_certificate_failed_to_parse(self):
        leaf_der, root_der = self._pair()
        result = sa.analyze_certificate_chain([b"garbage", leaf_der, root_der])
        assert result["properly_linked"] is None
        assert result["parsed_count"] == 2
        assert result["parse_errors"][0]["index"] == 0
        assert result["error"] is not None

    def test_duplicate_chain_elements_are_counted(self):
        leaf_der, root_der = self._pair()
        result = sa.analyze_certificate_chain([leaf_der, leaf_der, root_der])
        assert result["duplicate_certificates"] == 1
        assert any("more than once" in n for n in result["notes"])

    def test_pathological_chain_is_bounded(self):
        leaf_der, _ = self._pair()
        result = sa.analyze_certificate_chain([leaf_der] * 200)
        assert result["length"] == 200
        assert result["analyzed_count"] == sa.MAX_CHAIN_CERTIFICATES
        assert len(result["certificates"]) == sa.MAX_CHAIN_CERTIFICATES
        assert result["truncated"] is True

    def test_short_chain_note_separates_transmission_from_trust(self):
        leaf_der, _ = self._pair()
        result = sa.analyze_certificate_chain([leaf_der])
        joined = " ".join(result["notes"]).lower()
        assert "not whether the certificate is trusted" in joined
        assert "untrusted" not in joined

    def test_chain_never_claims_trust_validation(self):
        leaf_der, root_der = self._pair()
        blob = json.dumps(sa.analyze_certificate_chain([leaf_der, root_der])).lower()
        assert "trusted chain" not in blob and "chain is valid" not in blob


class TestStageIsolationAndErrorReporting:
    def test_one_failing_analysis_does_not_destroy_the_others(self, tmp_path):
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        with mock.patch.object(sa, "analyze_certificate_chain",
                               side_effect=RuntimeError("boom")):
            summary = _run("example.com", der, tmp_path, target="example.com")
        assert summary["status"] == "found"
        assert summary["completeness"] == "partial"
        assert [e["stage"] for e in summary["errors"]] == ["certificate_chain"]
        # Everything else still ran and was still persisted.
        assert summary["sans"]["sans"] == ["example.com"]
        assert summary["findings_persisted"] == 2

    def test_errors_is_a_list_the_orchestrator_can_count(self, tmp_path):
        from reconhound.core import orchestrator as orch
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        summary = _run("example.com", der, tmp_path, target="example.com")
        assert summary["errors"] == []
        assert orch._module_error_count(summary) == 0
        stats = orch._compact_stats(summary)
        assert stats["status"] == "found"
        assert stats["findings_produced"] == 2

    def test_persistence_failure_never_discards_a_completed_analysis(self, tmp_path):
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])

        def boom(self, body):
            raise OSError("no space left on device")

        with mock.patch.object(sa.PendingAssetsStore, "_atomic_write_body", boom):
            summary = _run("example.com", der, tmp_path, target="example.com")
        assert summary["status"] == "found"
        assert summary["findings_produced"] == 2
        assert summary["findings_persisted"] == 0
        assert any(e["stage"] == "persistence" for e in summary["errors"])

    def test_corrupt_pending_file_is_reported_not_raised(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        fake_context, fake_raw_sock, _ = _fake_stack_ext(der)
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            summary = sa.run_ssl_analysis("example.com", target="example.com",
                                          output_dir=str(output_dir))
        assert summary["status"] == "found"
        assert any(e["stage"] == "persistence" for e in summary["errors"])
        assert [p for p in os.listdir(output_dir) if p.startswith(".pending_assets_")] == []


class TestSniHandlingAndScope:
    @pytest.mark.parametrize("sni", ["evil.com", "bad host", "a" * 300, "\x00", "*.example.com"])
    def test_out_of_scope_or_malformed_sni_is_refused(self, sni, tmp_path):
        with pytest.raises(sa.ScopeError):
            sa.run_ssl_analysis("example.com", sni_hostname=sni, target="example.com",
                                output_dir=str(tmp_path / "output"))

    def test_in_scope_sni_override_is_accepted(self, tmp_path):
        cert, _, der = _build_cert_ext(
            "api.example.com", general_names=[x509.DNSName("api.example.com")])
        summary = _run("example.com", der, tmp_path, target="example.com",
                       sni_hostname="api.example.com")
        assert summary["sni_hostname"] == "api.example.com"
        assert summary["hostname_validation"]["matched"] is True

    def test_blank_sni_still_means_no_override(self, tmp_path):
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        summary = _run("example.com", der, tmp_path, target="example.com", sni_hostname="  ")
        assert summary["sni_hostname"] == "example.com"

    def test_ip_literal_sni_is_used_for_identity_but_not_sent(self, tmp_path):
        cert, _, der = _build_cert_ext("example.com", general_names=[
            x509.IPAddress(ipaddress.ip_address("93.184.216.34"))])
        summary = _run("example.com", der, tmp_path, target="example.com",
                       sni_hostname="93.184.216.34")
        assert summary["sni_hostname"] is None
        assert summary["observation"]["sni_sent"] is False
        assert summary["hostname_validation"]["matched"] is True

    @pytest.mark.parametrize("port", [None, 0, 70000, -1, 1.5, True, "https"])
    def test_invalid_port_is_a_scope_error_not_a_typeerror(self, port, tmp_path):
        # socket.create_connection() raises a bare TypeError on a non-integer
        # port, and TypeError is not an OSError, so it escaped every handler.
        # The rejection must also happen BEFORE any socket is opened.
        with mock.patch("socket.create_connection") as connect:
            with pytest.raises(sa.ScopeError):
                sa.run_ssl_analysis("example.com", port=port,
                                    output_dir=str(tmp_path / "output"))
        assert connect.call_count == 0

    def test_numeric_string_port_is_coerced(self, tmp_path):
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        summary = _run("example.com", der, tmp_path, target="example.com", port="8443")
        assert summary["port"] == 8443

    def test_hostile_sni_never_crashes_the_module(self):
        """
        ssl.wrap_socket() rejects some server_hostname values with plain
        TypeError/ValueError/UnicodeError. Those are not OSError and escaped
        _negotiate_tls entirely, turning a bad value into a module crash.
        """
        fake_context = mock.MagicMock()
        fake_context.wrap_socket.side_effect = TypeError(
            "argument must be encoded string without null bytes")
        fake_raw_sock = mock.MagicMock()
        fake_raw_sock.__enter__.return_value = fake_raw_sock
        fake_raw_sock.__exit__.return_value = False
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            result = sa._negotiate_tls("example.com", 443, "\x00", 5.0)
        assert result["status"] == "error"
        assert "could not be attempted" in result["error"]

    def test_handshake_failure_without_sni_explains_itself(self):
        fake_context = mock.MagicMock()
        fake_context.wrap_socket.side_effect = ssl.SSLError("unrecognized name")
        fake_raw_sock = mock.MagicMock()
        fake_raw_sock.__enter__.return_value = fake_raw_sock
        fake_raw_sock.__exit__.return_value = False
        with mock.patch("ssl.create_default_context", return_value=fake_context), \
             mock.patch("socket.create_connection", return_value=fake_raw_sock):
            result = sa._negotiate_tls("93.184.216.34", 443, None, 5.0)
        assert result["status"] == "handshake_failed"
        assert "no SNI was sent" in result["error"]


class TestObservationProvenance:
    def test_resolved_peer_endpoint_is_recorded(self, tmp_path):
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        summary = _run("example.com", der, tmp_path, target="example.com")
        obs = summary["observation"]
        assert obs["peer_ip"] == "93.184.216.34"
        assert obs["peer_port"] == 443
        assert obs["sni_sent"] is True
        assert obs["sni_hostname"] == "example.com"
        assert obs["observed_at"]

    def test_untested_properties_are_marked_untested_not_absent(self, tmp_path):
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        summary = _run("example.com", der, tmp_path, target="example.com")
        obs = summary["observation"]
        assert obs["chain_trust_validated"] is False
        assert obs["revocation_checked"] is False
        assert obs["certificate_transparency_checked"] is False
        assert summary["tls_version"]["observation"] == "negotiated_only"
        assert summary["tls_version"]["supported_versions"] is None

    def test_certificate_fingerprints_are_stable_correlation_keys(self, tmp_path):
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        summary = _run("example.com", der, tmp_path, target="example.com")
        assert summary["certificate"]["fingerprint_sha256"] == hashlib.sha256(der).hexdigest()
        assert len(summary["certificate"]["spki_sha256"]) == 64
        persisted = json.loads((tmp_path / "output" / "pending_assets.json").read_text())
        for record in persisted:
            assert record["metadata"]["fingerprint_sha256"] == hashlib.sha256(der).hexdigest()

    def test_evidence_states_the_limits_of_the_observation(self, tmp_path):
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        _run("example.com", der, tmp_path, target="example.com")
        persisted = json.loads((tmp_path / "output" / "pending_assets.json").read_text())
        analysis = [p for p in persisted if p["type"] == "tls_certificate_analysis"][0]
        joined = " ".join(analysis["evidence"])
        assert "was not enumerated" in joined
        assert "not validated against a root store" in joined

    def test_edge_versus_origin_is_not_overclaimed(self, tmp_path):
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        summary = _run("example.com", der, tmp_path, target="example.com")
        assert "edge, not the origin" in summary["observation"]["endpoint_attribution"]
        assert "origin" not in json.dumps(summary["certificate"]).lower()

    def test_deterministic_across_repeated_runs(self, tmp_path):
        cert, _, der = _build_cert_ext("example.com", general_names=[
            x509.DNSName("b.example.com"), x509.DNSName("a.example.com")])
        volatile = {"started_at", "finished_at", "observation", "validity"}
        seen = set()
        for index in range(3):
            summary = _run("example.com", der, tmp_path / str(index), target="example.com")
            seen.add(json.dumps({k: v for k, v in summary.items() if k not in volatile},
                                sort_keys=True))
        assert len(seen) == 1


class TestValidityReporting:
    def test_extreme_validity_window_does_not_crash(self):
        cert, _, _ = _build_cert_ext(
            "example.com",
            not_before=dt.datetime(1950, 1, 1, tzinfo=dt.timezone.utc),
            not_after=dt.datetime(9999, 12, 31, tzinfo=dt.timezone.utc))
        result = sa.analyze_certificate_validity(cert)
        assert result["is_expired"] is False
        assert result["lifetime_days"] > 2_000_000
        json.dumps(result)

    def test_short_lived_certificate_is_reported_as_data_only(self):
        now = dt.datetime.now(dt.timezone.utc)
        cert, _, _ = _build_cert_ext("example.com", not_before=now - dt.timedelta(hours=1),
                                     not_after=now + dt.timedelta(hours=5))
        result = sa.analyze_certificate_validity(cert)
        assert result["lifetime_days"] == 0
        # No rotation/ephemerality inference from a single observation.
        blob = json.dumps(result).lower()
        assert "ephemeral" not in blob and "rotat" not in blob
        assert "expiring_soon" not in result and "severity" not in result

    def test_evaluated_at_is_recorded_so_the_comparison_is_auditable(self):
        cert, _, _ = _build_cert_ext("example.com")
        assert sa.analyze_certificate_validity(cert)["evaluated_at"].endswith("+00:00")


class TestIpv6AndIpHosts:
    def test_ipv6_literal_is_accepted(self):
        assert sa.validate_ssl_host("::1") == "::1"
        assert sa.validate_ssl_host("2001:db8::1", target="example.com") == "2001:db8::1"

    def test_ip_host_sends_no_sni(self, tmp_path):
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        summary = _run("2001:db8::1", der, tmp_path)
        assert summary["sni_hostname"] is None
        assert summary["observation"]["sni_sent"] is False
        assert summary["hostname_validation"]["matched"] is None

    def test_ip_host_does_not_manufacture_a_certificate_problem(self, tmp_path):
        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        summary = _run("93.184.216.34", der, tmp_path)
        # Self-signed here, but the *hostname* dimension must not contribute.
        assert summary["hostname_validation"]["matched"] is None


class TestDownstreamIngestionContract:
    def test_surface_mapper_creates_no_phantom_or_unscannable_hosts(self, tmp_path):
        from reconhound import surface_mapper as sm
        from reconhound.core import orchestrator as orch

        cert, _, der = _build_cert_ext("example.com", general_names=[
            x509.DNSName("*.example.com"), x509.DNSName("example.com"),
            x509.DNSName("api.example.com"), x509.DNSName("a b.example.com"),
            x509.DNSName("internal.corp.local"),
            x509.IPAddress(ipaddress.ip_address("93.184.216.34")),
        ])
        output_dir = tmp_path / "output"
        _run("example.com", der, tmp_path, target="example.com")

        mapper = sm.SurfaceMapper(target="example.com", output_dir=str(output_dir))
        mapper.ingest_pending_assets_file(str(output_dir / "pending_assets.json"))
        hosts = {a["value"]: a.get("in_scope") for a in mapper.state["assets"].values()
                 if a["asset_type"] == sm.ASSET_HOSTNAME}
        assert set(hosts) == {"example.com", "api.example.com", "internal.corp.local"}
        assert hosts["internal.corp.local"] is False

        engine = orch.Orchestrator(target="example.com", output_dir=str(output_dir))
        engine.mapper = mapper
        targets = engine.ssl_targets()
        assert ("*.example.com", 443) not in targets
        for host, _port in targets:
            sa.validate_ssl_host(host, target="example.com")  # must not raise

    def test_risk_engine_reads_the_persisted_shapes(self, tmp_path):
        from reconhound import risk_engine
        from reconhound import surface_mapper as sm

        cert, _, der = _build_cert_ext(
            "example.com", general_names=[x509.DNSName("example.com")])
        output_dir = tmp_path / "output"
        _run("example.com", der, tmp_path, target="example.com")
        mapper = sm.SurfaceMapper(target="example.com", output_dir=str(output_dir))
        mapper.ingest_pending_assets_file(str(output_dir / "pending_assets.json"))

        host_asset = [a for a in mapper.state["assets"].values()
                      if a.get("value") == "example.com"][0]
        # The dict-shaped sub-results must be unwrapped, not stored whole.
        assert host_asset["attributes"]["tls_self_signed"]["value"] is True
        assert host_asset["attributes"]["tls_version"]["value"] == "TLSv1.3"

        assessment = risk_engine.run_risk_engine(graph=mapper.state,
                                                 output_dir=str(output_dir), persist=False)
        categories = {s["category"] for s in assessment["signals"]}
        assert "self_signed_certificate" in categories

    def test_cross_signed_ca_produces_no_self_signed_risk_signal(self, tmp_path):
        from reconhound import risk_engine
        from reconhound import surface_mapper as sm

        own = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert, _, der = _build_cert_ext(
            "example.com", key=own, signing_key=other,
            general_names=[x509.DNSName("example.com")])
        output_dir = tmp_path / "output"
        _run("example.com", der, tmp_path, target="example.com")
        mapper = sm.SurfaceMapper(target="example.com", output_dir=str(output_dir))
        mapper.ingest_pending_assets_file(str(output_dir / "pending_assets.json"))
        assessment = risk_engine.run_risk_engine(graph=mapper.state,
                                                 output_dir=str(output_dir), persist=False)
        assert "self_signed_certificate" not in {s["category"] for s in assessment["signals"]}

    def test_repeated_runs_do_not_duplicate_assets_or_inflate_confidence(self, tmp_path):
        from reconhound import surface_mapper as sm
        cert, _, der = _build_cert_ext("example.com", general_names=[
            x509.DNSName("example.com"), x509.DNSName("api.example.com")])
        output_dir = tmp_path / "output"
        for _ in range(3):
            _run("example.com", der, tmp_path, target="example.com")
        mapper = sm.SurfaceMapper(target="example.com", output_dir=str(output_dir))
        mapper.ingest_pending_assets_file(str(output_dir / "pending_assets.json"))
        hosts = [a for a in mapper.state["assets"].values()
                 if a["asset_type"] == sm.ASSET_HOSTNAME]
        assert sorted(a["value"] for a in hosts) == ["api.example.com", "example.com"]
        assert {a["confidence"] for a in hosts} == {"HIGH"}


class TestLiveTlsObservability:
    """
    Real handshakes against a local TLS listener — no socket mocking. These
    pin down what this Python/OpenSSL build can actually observe, which is the
    only honest basis for the module's claims.
    """

    @staticmethod
    def _write_cert(tmp_path, general_names, cn="localhost"):
        from cryptography.hazmat.primitives import serialization
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=1))
                .not_valid_after(now + dt.timedelta(days=90))
                .add_extension(x509.SubjectAlternativeName(general_names), critical=False)
                .sign(key, hashes.SHA256()))
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        cert_path.write_bytes(cert.public_bytes(Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        return str(cert_path), str(key_path)

    @staticmethod
    def _serve(cert_path, key_path, min_v=None, max_v=None, seclevel=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if seclevel is not None:
            context.set_ciphers(f"ALL:@SECLEVEL={seclevel}")
        if min_v is not None:
            context.minimum_version = min_v
        if max_v is not None:
            context.maximum_version = max_v
        context.load_cert_chain(cert_path, key_path)
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(5)
        stop = threading.Event()

        def loop():
            server.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = server.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    with context.wrap_socket(conn, server_side=True) as wrapped:
                        wrapped.recv(16)
                except Exception:
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

        thread = threading.Thread(target=loop, daemon=True)
        thread.start()
        return server.getsockname()[1], server, stop, thread

    @staticmethod
    def _shutdown(server, stop, thread):
        stop.set()
        server.close()
        thread.join(timeout=3)

    @pytest.mark.parametrize("version,expected,outdated", [
        (ssl.TLSVersion.TLSv1, "TLSv1", True),
        (ssl.TLSVersion.TLSv1_1, "TLSv1.1", True),
        (ssl.TLSVersion.TLSv1_2, "TLSv1.2", False),
    ])
    def test_outdated_tls_versions_are_actually_observable_here(
            self, tmp_path, version, expected, outdated):
        """
        context.md's own wording for this module is "flag TLS 1.0/1.1 as
        outdated". If the default client context refused those handshakes, the
        flag could never fire and every TLS 1.0 server would be reported as an
        indistinguishable `handshake_failed`. It does not — verified against a
        real listener rather than assumed.
        """
        cert_path, key_path = self._write_cert(tmp_path, [x509.DNSName("localhost")])
        port, server, stop, thread = self._serve(
            cert_path, key_path, min_v=version, max_v=version, seclevel=0)
        try:
            summary = sa.run_ssl_analysis("127.0.0.1", port=port,
                                          output_dir=str(tmp_path / "output"))
        finally:
            self._shutdown(server, stop, thread)
        assert summary["status"] == "found"
        assert summary["tls_version"]["version"] == expected
        assert summary["tls_version"]["is_outdated"] is outdated

    def test_real_handshake_records_the_endpoint_it_observed(self, tmp_path):
        cert_path, key_path = self._write_cert(tmp_path, [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
        port, server, stop, thread = self._serve(cert_path, key_path)
        try:
            summary = sa.run_ssl_analysis("127.0.0.1", port=port,
                                          output_dir=str(tmp_path / "output"))
        finally:
            self._shutdown(server, stop, thread)
        assert summary["status"] == "found"
        assert summary["observation"]["peer_ip"] == "127.0.0.1"
        assert summary["observation"]["peer_port"] == port
        assert summary["observation"]["sni_sent"] is False
        assert summary["hostname_validation"]["matched"] is True
        assert summary["cipher"]["forward_secrecy"] is True
        json.dumps(summary)

    def test_abrupt_disconnect_is_a_handshake_failure_not_a_crash(self, tmp_path):
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(5)
        port = server.getsockname()[1]
        stop = threading.Event()

        def loop():
            server.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = server.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    conn.close()
                except OSError:
                    pass

        thread = threading.Thread(target=loop, daemon=True)
        thread.start()
        output_dir = tmp_path / "output"
        try:
            summary = sa.run_ssl_analysis("127.0.0.1", port=port, output_dir=str(output_dir))
        finally:
            self._shutdown(server, stop, thread)
        # Whether the reset lands before or after the ClientHello is a race,
        # so both honest failure statuses are acceptable; what must hold is
        # that nothing crashed and nothing was recorded as a result.
        assert summary["status"] in ("handshake_failed", "unavailable")
        assert summary["completeness"] == "not_performed"
        assert summary["error"]
        # A failed handshake is "not checked", never "checked and clean".
        assert not (output_dir / "pending_assets.json").exists()

    def test_mtls_server_is_not_inferred_from_a_completed_handshake(self, tmp_path):
        """
        Under TLS 1.3 a server requiring a client certificate still completes
        the handshake from the client's side. The module must therefore make
        no mTLS claim at all — verified against a real CERT_REQUIRED listener.
        """
        cert_path, key_path = self._write_cert(tmp_path, [x509.DNSName("localhost")])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cert_path)
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(5)
        port = server.getsockname()[1]
        stop = threading.Event()

        def loop():
            server.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = server.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    with context.wrap_socket(conn, server_side=True) as wrapped:
                        wrapped.recv(16)
                except Exception:
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

        thread = threading.Thread(target=loop, daemon=True)
        thread.start()
        try:
            summary = sa.run_ssl_analysis("127.0.0.1", port=port,
                                          output_dir=str(tmp_path / "output"))
        finally:
            self._shutdown(server, stop, thread)
        blob = json.dumps(summary).lower()
        assert "mtls" not in blob and "client certificate" not in blob


class TestIpIdentityIsCompletedNumerically:
    """
    IP identities used to be compared as strings. "2001:0DB8::0001" and
    "2001:db8::1" are the same address, but not the same string, so an IPv6
    endpoint never matched its own iPAddress SAN.
    """

    def test_ipv6_host_is_canonicalised(self):
        assert sa.validate_ssl_host("2001:0DB8:0000::0001") == "2001:db8::1"
        assert sa.validate_ssl_host("::FFFF:1.2.3.4") == "::ffff:1.2.3.4"

    def test_ipv4_form_is_unchanged(self):
        assert sa.validate_ssl_host("93.184.216.34") == "93.184.216.34"

    def test_equivalent_ipv6_forms_match(self):
        assert sa._hostname_matches("2001:db8::1", "2001:0DB8:0000::0001") is True
        assert sa._hostname_matches("2001:db8::1", "2001:db8::2") is False

    def test_ipv6_san_matches_an_ipv6_host(self):
        cert, _, _ = _build_cert_ext("v6.example.com", general_names=[
            x509.IPAddress(ipaddress.ip_address("2001:db8::1"))])
        result = sa.validate_hostname_against_cert(cert, "2001:0DB8:0000::0001")
        assert result["matched"] is True
        assert result["matched_via"] == "subject_alternative_name"

    def test_ipv6_endpoint_end_to_end(self, tmp_path):
        cert, _, der = _build_cert_ext("v6.example.com", general_names=[
            x509.DNSName("v6.example.com"),
            x509.IPAddress(ipaddress.ip_address("2001:db8::1"))])
        summary = _run("2001:0DB8::1", der, tmp_path)
        assert summary["host"] == "2001:db8::1"
        assert summary["hostname_validation"]["matched"] is True
        assert summary["observation"]["sni_sent"] is False
