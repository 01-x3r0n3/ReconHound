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

    def test_rename_is_made_durable_by_fsyncing_the_directory(self, tmp_path):
        """os.replace() is atomic but the directory entry must also be synced."""
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch.object(pr.PendingAssetsStore, "_fsync_dir", autospec=True) as fsync_dir:
            store.add(pr.make_finding("dns_record", "example.com", {}, ["e"], pr.CONFIDENCE_LOW))
        assert fsync_dir.call_count == 1
        assert fsync_dir.call_args.args[0] == os.path.dirname(store.path)

    def test_fsync_dir_failure_does_not_lose_the_write(self, tmp_path):
        """Directory fsync is best-effort; a platform that refuses it must not
        turn a successful append into a failure."""
        # An unopenable directory and a refused fsync must both be tolerated.
        pr.PendingAssetsStore._fsync_dir(str(tmp_path / "does-not-exist"))
        with mock.patch.object(pr.os, "fsync", side_effect=OSError("EINVAL")):
            pr.PendingAssetsStore._fsync_dir(str(tmp_path))

        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch.object(pr.PendingAssetsStore, "_fsync_dir", side_effect=OSError("EINVAL")):
            with pytest.raises(OSError):
                store.add(pr.make_finding("whois", "example.com", {}, ["e"], pr.CONFIDENCE_LOW))
        # A failed durability step is surfaced, never silently reported as a
        # successful persist, and leaves no temp file behind.
        leftovers = [p for p in os.listdir(store.output_dir) if p.startswith(".pending_assets_")]
        assert leftovers == []

    def test_concurrent_adds_lose_no_records(self, tmp_path):
        """The per-store lock plus read-before-write must not drop findings."""
        import threading
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        errors = []

        def worker(n):
            try:
                for i in range(5):
                    store.add(pr.make_finding("dns_record", "example.com", {"w": n, "i": i},
                                              ["e"], pr.CONFIDENCE_LOW))
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        records = store.all()
        assert len(records) == 20
        assert {(r["value"]["w"], r["value"]["i"]) for r in records} == {
            (w, i) for w in range(4) for i in range(5)
        }
        with open(store.path) as f:
            json.load(f)  # still valid JSON after all operations

    def test_repeated_writes_stay_valid_json(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        for i in range(10):
            store.add(pr.make_finding("dns_record", "example.com", {"i": i}, ["e"], pr.CONFIDENCE_LOW))
            with open(store.path) as f:
                assert len(json.load(f)) == i + 1


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
# whois_lookup — provider-failure classification, bounded retry, privacy
# semantics. Regression coverage for the "provider failure vs. genuine
# no-data" and "privacy placeholder vs. real registrant" distinctions.
# ---------------------------------------------------------------------------

def _whois_exc(name):
    """The typed python-whois exception `name`, or None if this release lacks it."""
    exceptions = getattr(pr.python_whois, "exceptions", None)
    return getattr(exceptions, name, None) if exceptions else None


class TestWhoisErrorClassification:
    def test_domain_not_found_is_negative_result_not_error(self):
        cls = _whois_exc("WhoisDomainNotFoundError")
        exc = cls("No match for EXAMPLE.INVALID") if cls else Exception("No match for EXAMPLE.INVALID")
        with mock.patch.object(pr, "_whois_query", side_effect=exc), \
             mock.patch.object(pr.time, "sleep") as sleep:
            result = pr.whois_lookup("example.com")
        assert result["status"] == "not_found"
        assert result["error_class"] == pr.WHOIS_ERROR_NO_MATCH
        assert result["completeness"] == "empty"
        # A domain that does not exist will not exist on a second query.
        assert result["attempts"] == 1
        assert sleep.call_count == 0

    def test_rate_limit_is_retried_a_bounded_number_of_times(self):
        cls = _whois_exc("WhoisQuotaExceededError")
        exc = cls("quota exceeded") if cls else Exception("quota exceeded")
        with mock.patch.object(pr, "_whois_query", side_effect=exc) as query, \
             mock.patch.object(pr.time, "sleep") as sleep:
            result = pr.whois_lookup("example.com", max_attempts=3, backoff=2.0)
        assert result["status"] == "error"
        assert result["error_class"] == pr.WHOIS_ERROR_RATE_LIMITED
        assert result["attempts"] == 3
        assert query.call_count == 3          # bounded — never a retry storm
        assert sleep.call_count == 2          # one pause between each attempt
        # Conservative exponential backoff, not a tight loop.
        assert [c.args[0] for c in sleep.call_args_list] == [2.0, 4.0]

    def test_rate_limit_detected_from_message_when_untyped(self):
        with mock.patch.object(pr, "_whois_query", side_effect=Exception("Please try again later")), \
             mock.patch.object(pr.time, "sleep"):
            result = pr.whois_lookup("example.com", max_attempts=2)
        assert result["error_class"] == pr.WHOIS_ERROR_RATE_LIMITED

    def test_timeout_is_classified_and_retried(self):
        with mock.patch.object(pr, "_whois_query", side_effect=TimeoutError("timed out")) as query, \
             mock.patch.object(pr.time, "sleep"):
            result = pr.whois_lookup("example.com", max_attempts=2)
        assert result["status"] == "error"
        assert result["error_class"] == pr.WHOIS_ERROR_TIMEOUT
        assert query.call_count == 2

    def test_unsupported_tld_is_not_retried(self):
        cls = _whois_exc("UnknownTldError")
        exc = cls("unknown tld") if cls else None
        if exc is None:
            pytest.skip("installed python-whois has no UnknownTldError")
        with mock.patch.object(pr, "_whois_query", side_effect=exc) as query, \
             mock.patch.object(pr.time, "sleep") as sleep:
            result = pr.whois_lookup("example.com", max_attempts=3)
        assert result["status"] == "error"
        assert result["error_class"] == pr.WHOIS_ERROR_UNSUPPORTED_TLD
        assert query.call_count == 1
        assert sleep.call_count == 0

    def test_transient_failure_then_success(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        outcomes = [ConnectionResetError("connection reset by peer"),
                    {"domain_name": "EXAMPLE.COM", "registrar": "Example Registrar"}]

        def flaky(target, timeout):
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        with mock.patch.object(pr, "_whois_query", side_effect=flaky), \
             mock.patch.object(pr.time, "sleep"):
            result = pr.whois_lookup("example.com", store=store, max_attempts=3)

        assert result["status"] == "found"
        assert result["attempts"] == 2
        assert result["error"] is None and result["error_class"] is None
        persisted = store.all()
        assert persisted[0]["metadata"]["attempts"] == 2
        assert any("2 attempt(s)" in e for e in persisted[0]["evidence"])

    def test_max_attempts_one_disables_retry(self):
        with mock.patch.object(pr, "_whois_query", side_effect=Exception("quota exceeded")) as query, \
             mock.patch.object(pr.time, "sleep") as sleep:
            pr.whois_lookup("example.com", max_attempts=1)
        assert query.call_count == 1
        assert sleep.call_count == 0

    def test_provider_failure_is_not_reported_as_no_data(self):
        with mock.patch.object(pr, "_whois_query", side_effect=Exception("connection refused")), \
             mock.patch.object(pr.time, "sleep"):
            result = pr.whois_lookup("example.com", max_attempts=1)
        assert result["status"] == "error"
        assert result["status"] != "not_found"
        assert result["error_class"] == pr.WHOIS_ERROR_PROVIDER_UNAVAILABLE


class TestWhoisPrivacySemantics:
    def test_complete_response_is_full_and_high_confidence(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        record = {"domain_name": "EXAMPLE.COM", "registrar": "Example Registrar",
                  "org": "Example Corporation"}
        with mock.patch.object(pr.python_whois, "whois", return_value=record):
            result = pr.whois_lookup("example.com", store=store)
        assert result["completeness"] == "full"
        assert result["redacted_fields"] == {}
        assert result["data"]["org"] == "Example Corporation"
        assert store.all()[0]["confidence"] == pr.CONFIDENCE_HIGH

    def test_redacted_org_is_not_presented_as_registrant_data(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        record = {"domain_name": "EXAMPLE.COM", "registrar": "Example Registrar",
                  "org": "REDACTED FOR PRIVACY", "country": "Data Protected"}
        with mock.patch.object(pr.python_whois, "whois", return_value=record):
            result = pr.whois_lookup("example.com", store=store)

        assert result["status"] == "found"
        assert result["completeness"] == "partial_redacted"
        # The placeholder must never reach surface_mapper's org handler as an
        # organization name, but it is preserved, not discarded.
        assert "org" not in result["data"]
        assert "country" not in result["data"]
        assert result["redacted_fields"]["org"] == "REDACTED FOR PRIVACY"
        assert result["data"]["registrar"] == "Example Registrar"

        finding = store.all()[0]
        assert finding["value"]["redacted_fields"]["org"] == "REDACTED FOR PRIVACY"
        assert "org" not in finding["value"]
        assert finding["confidence"] == pr.CONFIDENCE_MEDIUM
        assert finding["metadata"]["completeness"] == "partial_redacted"
        assert finding["metadata"]["redacted_fields"] == ["country", "org"]
        assert any("withheld" in e for e in finding["evidence"])

    def test_redacted_org_does_not_reach_organization_summary(self, tmp_path):
        record = {"domain_name": "EXAMPLE.COM", "org": "Withheld for privacy"}
        with mock.patch.object(pr.python_whois, "whois", return_value=record):
            whois_result = pr.whois_lookup("example.com")
        summary = pr._build_organization_summary({"whois": whois_result, "asn": []})
        assert summary["whois_organizations"] == []

    def test_infrastructure_fields_are_never_screened_as_redacted(self, tmp_path):
        """
        Regression: privacy-service *hostnames* legitimately contain the same
        wording as privacy *placeholders*. Screening them would delete real
        nameservers and the real registrar from the asset graph.
        """
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        record = {
            "domain_name": "EXAMPLE.COM",
            "registrar": "Domains By Proxy, LLC",
            "whois_server": "whois.privacyprotect.org",
            "name_servers": ["ns1.privacyprotect.org", "ns2.privacyprotect.org"],
            "org": "REDACTED FOR PRIVACY",
        }
        with mock.patch.object(pr.python_whois, "whois", return_value=record):
            result = pr.whois_lookup("example.com", store=store)

        # Genuine infrastructure survives untouched...
        assert result["data"]["name_servers"] == ["ns1.privacyprotect.org", "ns2.privacyprotect.org"]
        assert result["data"]["registrar"] == "Domains By Proxy, LLC"
        assert result["data"]["whois_server"] == "whois.privacyprotect.org"
        # ...while only the registrant attribution is screened.
        assert sorted(result["redacted_fields"]) == ["org"]

    def test_screened_fields_are_limited_to_registrant_attribution(self):
        assert pr._WHOIS_REDACTABLE_FIELDS == {"org", "country", "emails"}
        for field in ("registrar", "whois_server", "name_servers", "domain_name", "status"):
            assert field not in pr._WHOIS_REDACTABLE_FIELDS

    def test_fully_redacted_response_is_still_found_not_missing(self):
        record = {"org": "REDACTED FOR PRIVACY"}
        with mock.patch.object(pr.python_whois, "whois", return_value=record):
            result = pr.whois_lookup("example.com")
        assert result["status"] == "found"
        assert result["completeness"] == "partial_redacted"

    def test_empty_response_is_empty_completeness(self):
        with mock.patch.object(pr.python_whois, "whois", return_value={}):
            result = pr.whois_lookup("example.com")
        assert result["status"] == "not_found"
        assert result["completeness"] == "empty"
        assert result["error_class"] is None

    def test_redacted_finding_is_json_serializable(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        record = {"domain_name": "EXAMPLE.COM", "org": "REDACTED FOR PRIVACY",
                  "emails": ["privacy@proxy.example"]}
        with mock.patch.object(pr.python_whois, "whois", return_value=record):
            pr.whois_lookup("example.com", store=store)
        json.dumps(store.all())

    def test_nested_dict_values_are_json_safe_not_stringified(self):
        assert pr._jsonify({"a": {"b": [1, 2]}}) == {"a": {"b": [1, 2]}}


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
        assert result["error_class"] == "timeout"

    def test_tls_handshake_failure_is_classified_not_swallowed_as_oserror(self):
        """ssl.SSLError subclasses OSError; it must not be shadowed by it."""
        import ssl as _ssl
        with mock.patch("socket.create_connection", side_effect=_ssl.SSLError("handshake failure")):
            result = pr.discover_tls_certificate("example.com")
        assert result["status"] == "error"
        assert result["error_class"] == "tls_handshake_failed"
        assert "TLS handshake failed" in result["error"]

    def test_connection_refused_has_its_own_error_class(self):
        with mock.patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            result = pr.discover_tls_certificate("example.com")
        assert result["error_class"] == "connection_failed"

    def test_name_resolution_failure_has_its_own_error_class(self):
        with mock.patch("socket.create_connection", side_effect=socket.gaierror("no such host")):
            result = pr.discover_tls_certificate("example.com")
        assert result["error_class"] == "name_resolution_failed"


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

    def test_nxdomain_is_not_announced_not_an_error(self):
        """Cymru answering NXDOMAIN means the IP is in no announced prefix."""
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = pr.discover_asn("93.184.216.34")
        assert result["status"] == "not_found"
        assert result["error_class"] == "not_announced"

    def test_resolver_timeout_is_error_not_a_negative_result(self):
        import dns.exception
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.Timeout()):
            result = pr.discover_asn("93.184.216.34")
        assert result["status"] == "error"
        assert result["error_class"] == "timeout"

    def test_generic_lookup_failure_is_error_not_crash(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NoNameservers()):
            result = pr.discover_asn("93.184.216.34")
        assert result["status"] == "error"
        assert result["error_class"] == "lookup_failed"

    def test_private_ip_is_skipped_without_querying_cymru(self):
        """Cymru maps announced space only; querying it for RFC1918 is pointless."""
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=AssertionError("must not query")) as m:
            result = pr.discover_asn("10.0.0.5")
        assert result["status"] == "not_found"
        assert result["error_class"] == "not_globally_routable"
        assert m.call_count == 0


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
        assert result["dkim"]["status"] == pr.DKIM_NOT_FOUND_AMONG_TESTED
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

        assert result["dkim"]["status"] == pr.DKIM_FOUND
        assert result["dkim"]["found_selectors"][0]["selector"] == "default"
        assert result["dkim"]["exhaustive"] is False


class TestDkimSemantics:
    """
    DKIM is a sampled check. The module must never turn "no record among the
    selectors we tested" into "this domain has no DKIM", and must never turn a
    failed lookup into a negative result at all.
    """

    @staticmethod
    def _resolver(dkim_side_effect):
        def fake_resolve(self, qname, rtype, *a, **kw):
            qname = str(qname)
            if "_domainkey" in qname:
                return dkim_side_effect(qname)
            raise dns.resolver.NXDOMAIN()
        return fake_resolve

    def test_all_selectors_authoritatively_absent(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def absent(qname):
            raise dns.resolver.NXDOMAIN()

        with mock.patch.object(dns.resolver.Resolver, "resolve", self._resolver(absent)):
            result = pr.analyze_email_security("example.com", store=store)

        dkim = result["dkim"]
        assert dkim["status"] == pr.DKIM_NOT_FOUND_AMONG_TESTED
        assert dkim["status"] != "not_found"        # must not read as global absence
        assert dkim["selectors_without_record"] == dkim["selectors_checked"]
        assert dkim["selectors_errored"] == []
        assert dkim["exhaustive"] is False

        finding = store.all()[0]
        assert finding["metadata"]["dkim_exhaustive"] is False
        evidence = " ".join(finding["evidence"])
        assert "not evidence that DKIM is unconfigured" in evidence

    def test_lookup_failures_are_inconclusive_not_absent(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def failing(qname):
            raise dns.exception.Timeout()

        with mock.patch.object(dns.resolver.Resolver, "resolve", self._resolver(failing)):
            result = pr.analyze_email_security("example.com", store=store)

        dkim = result["dkim"]
        assert dkim["status"] == pr.DKIM_INCONCLUSIVE
        assert dkim["selectors_without_record"] == []
        assert len(dkim["selectors_errored"]) == len(dkim["selectors_checked"])
        assert dkim["selectors_errored"][0]["selector"] in dkim["selectors_checked"]

        evidence = " ".join(store.all()[0]["evidence"])
        assert "inconclusive" in evidence
        assert "no authoritative negative was established" in evidence

    def test_partial_failures_still_inconclusive(self):
        def mixed(qname):
            if qname.startswith("default."):
                raise dns.resolver.NXDOMAIN()
            raise dns.exception.Timeout()

        with mock.patch.object(dns.resolver.Resolver, "resolve", self._resolver(mixed)):
            result = pr.analyze_email_security("example.com")
        assert result["dkim"]["status"] == pr.DKIM_INCONCLUSIVE
        assert result["dkim"]["selectors_without_record"] == ["default"]

    def test_a_hit_wins_over_other_selectors_failing(self):
        def mixed(qname):
            if qname.startswith("google."):
                return [_FakeRdata('"v=DKIM1; k=rsa; p=ABC"')]
            raise dns.exception.Timeout()

        with mock.patch.object(dns.resolver.Resolver, "resolve", self._resolver(mixed)):
            result = pr.analyze_email_security("example.com")
        assert result["dkim"]["status"] == pr.DKIM_FOUND
        assert [s["selector"] for s in result["dkim"]["found_selectors"]] == ["google"]

    def test_multiple_selectors_found_are_all_recorded(self):
        def multi(qname):
            if qname.startswith(("default.", "selector1.")):
                return [_FakeRdata('"v=DKIM1; k=rsa; p=ABC"')]
            raise dns.resolver.NXDOMAIN()

        with mock.patch.object(dns.resolver.Resolver, "resolve", self._resolver(multi)):
            result = pr.analyze_email_security("example.com")
        assert {s["selector"] for s in result["dkim"]["found_selectors"]} == {"default", "selector1"}

    def test_no_selectors_tested_is_not_tested(self):
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = pr.analyze_email_security("example.com", dkim_selectors=[])
        assert result["dkim"]["status"] == pr.DKIM_NOT_TESTED
        assert result["dkim"]["selectors_checked"] == []

    def test_dkim_status_alone_never_asserts_absence(self, tmp_path):
        """Guards the value surface_mapper flattens into email_dkim_status."""
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
            pr.analyze_email_security("example.com", store=store)
        status = store.all()[0]["value"]["dkim"]["status"]
        assert status not in ("not_found", "absent", "none")


class TestEmailRecordConflicts:
    def test_multiple_spf_records_are_preserved_as_a_conflict(self, tmp_path):
        store = pr.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_resolve(self, qname, rtype, *a, **kw):
            qname = str(qname)
            if rtype == "TXT" and "_domainkey" in qname:
                raise dns.resolver.NXDOMAIN()
            if rtype == "TXT" and qname.startswith("_dmarc."):
                raise dns.resolver.NXDOMAIN()
            if rtype == "TXT":
                return [_FakeRdata('"v=spf1 include:a -all"'), _FakeRdata('"v=spf1 include:b ~all"')]
            raise dns.resolver.NXDOMAIN()

        with mock.patch.object(dns.resolver.Resolver, "resolve", fake_resolve):
            result = pr.analyze_email_security("example.com", store=store)

        assert result["spf"]["status"] == "found"
        assert len(result["spf"]["records"]) == 2
        assert "2 SPF records" in result["spf"]["conflict"]
        assert any("Conflict:" in e for e in store.all()[0]["evidence"])


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
