"""
Tests for reconhound/osint_engine.py (ReconHound Module 4, per context.md's
catalog item 4; built under a temporary, user-approved build-order
deviation ahead of surface_mapper.py — see the module docstring for
details).

Run with:  ./.venv/bin/python -m pytest tests/test_osint_engine.py -v

All tests mock the `requests.get` boundary so the suite is deterministic
and offline-safe; no external network access (crt.sh, Google, HIBP,
SecurityTrails, HackerTarget, BGPView) is required or performed anywhere
in this file. Several tests additionally assert on the *captured* request
URLs to verify the passive boundary: this module must never send a
request to the target itself.
"""

import datetime
import json
import os
import sys
from unittest import mock

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import osint_engine as oe


SAFE_TARGET = "example.com"
SAFE_IP = "93.184.216.34"


def _fake_response(status_code=200, json_data=None, text=None, headers=None, raise_json_error=False):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = dict(headers or {})
    if text is not None:
        resp.text = text
    elif json_data is not None:
        resp.text = json.dumps(json_data)
    else:
        resp.text = ""
    if raise_json_error:
        resp.json.side_effect = ValueError("bad json")
    else:
        resp.json.return_value = json_data
    return resp


def _make_test_certificate(email_subject=None, email_sans=None, dns_names=None):
    """Build a real, self-signed PEM certificate for CT-log-parsing tests."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.com")]
    if email_subject:
        name_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_subject))
    subject = issuer = x509.Name(name_attrs)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
    )

    san_entries = [x509.DNSName(n) for n in (dns_names or ["mail.example.com"])]
    for e in (email_sans or []):
        san_entries.append(x509.RFC822Name(e))
    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    cert = builder.sign(key, hashes.SHA256(), default_backend())
    return cert.public_bytes(encoding=serialization.Encoding.PEM).decode()


CERT_WITH_EMAILS_PEM = _make_test_certificate(
    email_subject="admin@example.com", email_sans=["security@example.com", "noreply@other.org"]
)
CERT_NO_EMAILS_PEM = _make_test_certificate()


# ---------------------------------------------------------------------------
# validate_target / is_in_scope / _valid_ip
# ---------------------------------------------------------------------------

class TestValidateTarget:
    def test_accepts_plain_domain(self):
        assert oe.validate_target("example.com") == "example.com"

    def test_normalizes_case_and_trailing_dot(self):
        assert oe.validate_target("EXAMPLE.com.") == "example.com"

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(oe.ScopeError):
            oe.validate_target(bad)

    def test_rejects_url(self):
        with pytest.raises(oe.ScopeError):
            oe.validate_target("https://example.com/path")

    def test_rejects_ip_literal(self):
        with pytest.raises(oe.ScopeError):
            oe.validate_target(SAFE_IP)

    def test_rejects_wildcard(self):
        with pytest.raises(oe.ScopeError):
            oe.validate_target("*.example.com")


class TestIsInScope:
    def test_exact_and_subdomain_match(self):
        assert oe.is_in_scope("example.com", "example.com") is True
        assert oe.is_in_scope("mail.example.com", "example.com") is True

    def test_out_of_scope(self):
        assert oe.is_in_scope("evil.com", "example.com") is False

    def test_empty_hostname(self):
        assert oe.is_in_scope("", "example.com") is False


# ---------------------------------------------------------------------------
# make_finding / PendingAssetsStore
# ---------------------------------------------------------------------------

class TestMakeFinding:
    def test_shape(self):
        finding = oe.make_finding("osint_engine_email", SAFE_TARGET, {"a": 1}, ["evidence"], oe.CONFIDENCE_LOW)
        assert finding["type"] == "osint_engine_email"
        assert finding["source"] == oe.MODULE_NAME
        assert "timestamp" in finding
        json.dumps(finding)


class TestPendingAssetsStore:
    def test_creates_output_dir_and_persists(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        finding = oe.make_finding("osint_engine_email", SAFE_TARGET, {}, ["e"], oe.CONFIDENCE_LOW)
        store.add(finding)
        assert os.path.exists(store.path)
        assert store.all() == [finding]

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        path = tmp_path / "pending_assets.json"
        path.write_text("{not valid json")
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        with pytest.raises(oe.PersistenceError):
            store.all()

    def test_safe_store_add_survives_persistence_error(self, tmp_path):
        path = tmp_path / "pending_assets.json"
        path.write_text("{not valid json")
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        err = oe._safe_store_add(store, oe.make_finding("osint_engine_email", SAFE_TARGET, {}, [], oe.CONFIDENCE_LOW))
        assert err is not None

    def test_safe_store_add_none_store_is_noop(self):
        assert oe._safe_store_add(None, {"anything": 1}) is None


# ---------------------------------------------------------------------------
# load_seed_data
# ---------------------------------------------------------------------------

class TestLoadSeedData:
    def test_reads_ip_and_asn_from_persisted_findings(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(oe.make_finding("dns_record", SAFE_TARGET, {"record_type": "A", "records": [SAFE_IP]}, ["e"], oe.CONFIDENCE_HIGH))
        store.add(oe.make_finding("asn", SAFE_TARGET, {"asn": "15133", "ip": SAFE_IP}, ["e"], oe.CONFIDENCE_MEDIUM))
        seed = oe.load_seed_data(store, SAFE_TARGET)
        assert seed["ip"] == SAFE_IP
        assert seed["asn"] == "15133"

    def test_caller_supplied_values_take_precedence(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(oe.make_finding("dns_record", SAFE_TARGET, {"record_type": "A", "records": [SAFE_IP]}, ["e"], oe.CONFIDENCE_HIGH))
        seed = oe.load_seed_data(store, SAFE_TARGET, extra_ip="1.2.3.4", extra_asn="999")
        assert seed["ip"] == "1.2.3.4"
        assert seed["asn"] == "999"

    def test_ignores_findings_for_other_targets(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        store.add(oe.make_finding("dns_record", "other.com", {"record_type": "A", "records": [SAFE_IP]}, ["e"], oe.CONFIDENCE_HIGH))
        seed = oe.load_seed_data(store, SAFE_TARGET)
        assert seed["ip"] is None

    def test_no_store_no_extras(self):
        seed = oe.load_seed_data(None, SAFE_TARGET)
        assert seed == {"ip": None, "asn": None}


# ---------------------------------------------------------------------------
# extract_emails_from_text / merge_email_records / persist_emails
# ---------------------------------------------------------------------------

class TestExtractEmailsFromText:
    def test_extracts_in_scope_emails(self):
        text = "Contact john.smith@example.com or admin@mail.example.com for help."
        emails = oe.extract_emails_from_text(text, SAFE_TARGET)
        assert "john.smith@example.com" in emails
        assert "admin@mail.example.com" in emails

    def test_ignores_out_of_scope_emails(self):
        text = "Contact us at support@othercompany.com"
        assert oe.extract_emails_from_text(text, SAFE_TARGET) == []

    def test_empty_text(self):
        assert oe.extract_emails_from_text("", SAFE_TARGET) == []
        assert oe.extract_emails_from_text(None, SAFE_TARGET) == []


class TestMergeEmailRecords:
    def test_single_source_medium_confidence(self):
        merged = oe.merge_email_records([{"email": "a@example.com", "source": "ct_log"}])
        assert merged[0]["confidence"] == oe.CONFIDENCE_MEDIUM
        assert merged[0]["sources"] == ["ct_log"]

    def test_converging_sources_raise_confidence(self):
        merged = oe.merge_email_records([
            {"email": "A@Example.com", "source": "ct_log"},
            {"email": "a@example.com", "source": "search_engine"},
        ])
        assert len(merged) == 1
        assert merged[0]["confidence"] == oe.CONFIDENCE_HIGH
        assert set(merged[0]["sources"]) == {"ct_log", "search_engine"}

    def test_skips_malformed(self):
        assert oe.merge_email_records([{"email": ""}, {"email": "not-an-email"}]) == []

    def test_json_safe(self):
        merged = oe.merge_email_records([{"email": "a@example.com", "source": "ct_log"}])
        json.dumps(merged)


class TestPersistEmails:
    def test_persists_and_labels_observed(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        merged = oe.merge_email_records([{"email": "a@example.com", "source": "ct_log"}])
        errors = oe.persist_emails(merged, SAFE_TARGET, store)
        assert errors == []
        rec = store.all()[0]
        assert rec["type"] == "osint_engine_email"
        assert rec["metadata"]["observed"] is True
        assert rec["metadata"]["inferred"] is False


# ---------------------------------------------------------------------------
# classify_local_part / infer_email_patterns / naming convention
# ---------------------------------------------------------------------------

class TestClassifyLocalPart:
    def test_first_dot_last(self):
        r = oe.classify_local_part("john.smith")
        assert r["category"] == "first.last"
        assert r["first"] == "john" and r["last"] == "smith"

    def test_first_underscore_last(self):
        assert oe.classify_local_part("john_smith")["category"] == "first_last"

    def test_first_dash_last(self):
        assert oe.classify_local_part("john-smith")["category"] == "first-last"

    def test_initial_dot_last(self):
        r = oe.classify_local_part("j.smith")
        assert r["category"] == "finitial.last"
        assert r["first"] == "j" and r["last"] == "smith"

    def test_first_dot_linitial(self):
        r = oe.classify_local_part("john.s")
        assert r["category"] == "first.linitial"

    def test_concatenated(self):
        assert oe.classify_local_part("jsmith")["category"] == "concatenated"

    def test_other_for_numeric_or_symbols(self):
        assert oe.classify_local_part("user1234!!")["category"] == "other"

    def test_empty(self):
        assert oe.classify_local_part("")["category"] == "other"


class TestInferEmailPatterns:
    def test_ranks_by_frequency(self):
        emails = ["john.smith@example.com", "jane.doe@example.com", "bob.jones@example.com", "asmith@example.com"]
        info = oe.infer_email_patterns(emails, SAFE_TARGET)
        assert info["total_observed"] == 4
        top = info["candidates"][0]
        assert top["category"] == "first.last"
        assert top["count"] == 3
        assert top["share"] == 0.75

    def test_empty_input(self):
        info = oe.infer_email_patterns([], SAFE_TARGET)
        assert info["total_observed"] == 0
        assert info["candidates"] == []


class TestPersistNamingConvention:
    def test_insufficient_data_when_fewer_than_two(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        info = oe.infer_email_patterns(["a@example.com"], SAFE_TARGET)
        value, err = oe.persist_naming_convention_finding(info, SAFE_TARGET, store)
        assert err is None
        assert value["status"] == "insufficient_data"
        rec = store.all()[0]
        assert rec["confidence"] == oe.CONFIDENCE_LOW
        assert rec["metadata"]["inferred"] is True

    def test_high_confidence_with_strong_convergence(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        emails = ["alice.brown@example.com", "carla.davis@example.com", "erin.frank@example.com"]
        info = oe.infer_email_patterns(emails, SAFE_TARGET)
        value, err = oe.persist_naming_convention_finding(info, SAFE_TARGET, store)
        assert err is None
        assert value["status"] == "inferred"
        assert value["convention"] == "first.last"
        rec = [r for r in store.all() if r["type"] == "osint_engine_naming_convention"][0]
        assert rec["confidence"] == oe.CONFIDENCE_HIGH


class TestPersistEmailPatternFindings:
    def test_persists_one_per_category(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        info = oe.infer_email_patterns(["a.b@example.com", "cdef@example.com"], SAFE_TARGET)
        errors = oe.persist_email_pattern_findings(info, SAFE_TARGET, store)
        assert errors == []
        types = [r["type"] for r in store.all()]
        assert types.count("osint_engine_email_pattern") == 2
        assert all(r["metadata"]["inferred"] for r in store.all())


# ---------------------------------------------------------------------------
# generate_employee_inferences / persist_employee_findings — always LOW,
# always inferred (input-contract decision #5).
# ---------------------------------------------------------------------------

class TestEmployeeInference:
    def test_splits_first_last(self):
        emps = oe.generate_employee_inferences(["john.smith@example.com"])
        assert emps[0]["probable_name"] == "John Smith"
        assert emps[0]["local_part_category"] == "first.last"

    def test_unsplittable_local_part_has_no_name(self):
        emps = oe.generate_employee_inferences(["jsmith@example.com"])
        assert emps[0]["probable_name"] is None
        assert emps[0]["local_part_category"] == "concatenated"

    def test_persist_always_low_confidence_and_inferred(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        emps = oe.generate_employee_inferences(["john.smith@example.com", "jsmith@example.com"])
        errors = oe.persist_employee_findings(emps, SAFE_TARGET, store)
        assert errors == []
        records = store.all()
        assert len(records) == 2
        for r in records:
            assert r["confidence"] == oe.CONFIDENCE_LOW
            assert r["metadata"]["inferred"] is True
            assert r["metadata"]["observed"] is False


# ---------------------------------------------------------------------------
# CT log: query_crtsh_certificates / fetch_crtsh_certificate_pem /
# extract_emails_from_certificate_pem / harvest_ct_emails
# ---------------------------------------------------------------------------

class TestQueryCrtshCertificates:
    @mock.patch("reconhound.osint_engine.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, [{"id": 1, "name_value": "a.example.com"}])
        r = oe.query_crtsh_certificates(SAFE_TARGET)
        assert r["status"] == "found"
        assert r["entries"][0]["id"] == 1
        called_url = mock_get.call_args.args[0]
        assert called_url == oe.CRTSH_API_BASE

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_empty_body_is_not_found(self, mock_get):
        mock_get.return_value = _fake_response(200, text="")
        r = oe.query_crtsh_certificates(SAFE_TARGET)
        assert r["status"] == "not_found"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_rate_limited(self, mock_get):
        mock_get.return_value = _fake_response(429)
        r = oe.query_crtsh_certificates(SAFE_TARGET)
        assert r["status"] == "rate_limited"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_malformed_json(self, mock_get):
        mock_get.return_value = _fake_response(200, text="{not valid json")
        r = oe.query_crtsh_certificates(SAFE_TARGET)
        assert r["status"] == "error"

    @mock.patch("reconhound.osint_engine.requests.get", side_effect=requests.exceptions.Timeout())
    def test_timeout(self, mock_get):
        r = oe.query_crtsh_certificates(SAFE_TARGET)
        assert r["status"] == "error"
        assert r["error"] == "timeout"


class TestFetchCrtshCertificatePem:
    @mock.patch("reconhound.osint_engine.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, text=CERT_WITH_EMAILS_PEM)
        r = oe.fetch_crtsh_certificate_pem(1)
        assert r["status"] == "found"
        assert "BEGIN CERTIFICATE" in r["pem"]

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_not_pem(self, mock_get):
        mock_get.return_value = _fake_response(200, text="not a cert")
        r = oe.fetch_crtsh_certificate_pem(1)
        assert r["status"] == "error"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_not_found_404(self, mock_get):
        mock_get.return_value = _fake_response(404)
        r = oe.fetch_crtsh_certificate_pem(1)
        assert r["status"] == "not_found"


class TestExtractEmailsFromCertificatePem:
    def test_extracts_subject_and_san_emails_in_scope(self):
        emails = oe.extract_emails_from_certificate_pem(CERT_WITH_EMAILS_PEM, SAFE_TARGET)
        assert "admin@example.com" in emails
        assert "security@example.com" in emails
        assert "noreply@other.org" not in emails  # out of scope

    def test_no_emails_in_certificate(self):
        assert oe.extract_emails_from_certificate_pem(CERT_NO_EMAILS_PEM, SAFE_TARGET) == []

    def test_malformed_pem_returns_empty_not_raises(self):
        assert oe.extract_emails_from_certificate_pem("not a real cert", SAFE_TARGET) == []


class TestHarvestCtEmails:
    @mock.patch("reconhound.osint_engine.requests.get")
    def test_full_pipeline(self, mock_get):
        def side_effect(url, params=None, **kwargs):
            if params and params.get("output") == "json":
                return _fake_response(200, [{"id": 1}, {"id": 2}])
            return _fake_response(200, text=CERT_WITH_EMAILS_PEM)

        mock_get.side_effect = side_effect
        result = oe.harvest_ct_emails(SAFE_TARGET, max_certs=5)
        assert result["status"] == "found"
        assert "admin@example.com" in result["emails"]
        assert result["certs_inspected"] == 2

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_no_certificates_found(self, mock_get):
        mock_get.return_value = _fake_response(200, [])
        result = oe.harvest_ct_emails(SAFE_TARGET)
        assert result["status"] == "not_found"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_respects_max_certs(self, mock_get):
        def side_effect(url, params=None, **kwargs):
            if params and params.get("output") == "json":
                return _fake_response(200, [{"id": i} for i in range(50)])
            return _fake_response(200, text=CERT_NO_EMAILS_PEM)

        mock_get.side_effect = side_effect
        oe.harvest_ct_emails(SAFE_TARGET, max_certs=3)
        # 1 listing call + 3 PEM fetches
        assert mock_get.call_count == 4

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_per_cert_failure_does_not_abort(self, mock_get):
        calls = {"n": 0}

        def side_effect(url, params=None, **kwargs):
            if params and params.get("output") == "json":
                return _fake_response(200, [{"id": 1}, {"id": 2}])
            calls["n"] += 1
            if calls["n"] == 1:
                raise requests.exceptions.ConnectionError("boom")
            return _fake_response(200, text=CERT_WITH_EMAILS_PEM)

        mock_get.side_effect = side_effect
        result = oe.harvest_ct_emails(SAFE_TARGET)
        assert result["status"] == "found"
        assert result["certs_inspected"] == 1


# ---------------------------------------------------------------------------
# Google Custom Search
# ---------------------------------------------------------------------------

class TestQueryGoogleCustomSearch:
    def test_missing_credentials(self):
        r = oe.query_google_custom_search("q", None, None)
        assert r["status"] == "missing_credentials"

    def test_empty_query(self):
        r = oe.query_google_custom_search("", "key", "cx")
        assert r["status"] == "error"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, {
            "items": [{"title": "T", "link": "https://example.com/a", "snippet": "S", "displayLink": "example.com"}],
            "searchInformation": {"totalResults": "1"},
        })
        r = oe.query_google_custom_search("site:example.com", "key", "cx")
        assert r["status"] == "found"
        assert r["total_results"] == 1
        assert r["items"][0]["link"] == "https://example.com/a"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_zero_results_no_items_key(self, mock_get):
        mock_get.return_value = _fake_response(200, {"searchInformation": {"totalResults": "0"}})
        r = oe.query_google_custom_search("q", "key", "cx")
        assert r["status"] == "not_found"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_invalid_query_400(self, mock_get):
        mock_get.return_value = _fake_response(400, {"error": {"message": "bad request"}})
        r = oe.query_google_custom_search("q", "key", "cx")
        assert r["status"] == "invalid_query"
        assert "bad request" in r["error"]

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_rate_limited_via_403_reason(self, mock_get):
        mock_get.return_value = _fake_response(403, {"error": {"errors": [{"reason": "dailyLimitExceeded"}]}})
        r = oe.query_google_custom_search("q", "key", "cx")
        assert r["status"] == "rate_limited"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_forbidden_403_other_reason(self, mock_get):
        mock_get.return_value = _fake_response(403, {"error": {"errors": [{"reason": "keyInvalid"}]}})
        r = oe.query_google_custom_search("q", "key", "cx")
        assert r["status"] == "forbidden"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_rate_limited_429(self, mock_get):
        mock_get.return_value = _fake_response(429)
        r = oe.query_google_custom_search("q", "key", "cx")
        assert r["status"] == "rate_limited"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_malformed_json(self, mock_get):
        mock_get.return_value = _fake_response(200, raise_json_error=True)
        r = oe.query_google_custom_search("q", "key", "cx")
        assert r["status"] == "error"


class TestHarvestSearchEngineEmails:
    @mock.patch("reconhound.osint_engine.requests.get")
    def test_extracts_email_from_snippet(self, mock_get):
        mock_get.return_value = _fake_response(200, {
            "items": [{"title": "Contact", "link": "https://example.com/contact", "snippet": "Email us at info@example.com"}],
        })
        r = oe.harvest_search_engine_emails(SAFE_TARGET, "key", "cx")
        assert r["status"] == "found"
        assert "info@example.com" in r["emails"]


class TestRunQueryBatch:
    @mock.patch("reconhound.osint_engine.requests.get")
    def test_stops_on_rate_limit(self, mock_get):
        """
        Strengthened from an earlier version that asserted `len(status_list) == 1`.
        That measured "only one query ran" via the size of the status list, which
        also meant the eleven queries that never ran were reported NOWHERE — a
        batch cut short after one query looked identical to a batch of one. The
        stopping behaviour is now asserted directly (one HTTP request issued),
        and the un-run queries must be explicitly accounted for.
        """
        mock_get.return_value = _fake_response(429)
        status_list, hits, no_res = oe._run_query_batch(
            oe.DEFAULT_DORK_QUERIES, SAFE_TARGET, "key", "cx", 5.0, 10, 0
        )
        # The batch really did stop: exactly one request left the process, and
        # the remaining quota was not burned.
        assert mock_get.call_count == 1
        assert status_list[0]["status"] == "rate_limited"
        assert status_list[0]["conclusive"] is False

        # ...and every query it did not run is accounted for rather than absent.
        skipped = [s for s in status_list if s["status"] == "skipped"]
        assert len(skipped) == len(oe.DEFAULT_DORK_QUERIES) - 1
        assert len(status_list) == len(oe.DEFAULT_DORK_QUERIES)
        assert all(s["conclusive"] is False for s in skipped)
        assert {s["label"] for s in skipped} == {lbl for lbl, _ in oe.DEFAULT_DORK_QUERIES[1:]}
        # A skipped query must never look like a query that found nothing.
        assert no_res == []

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_collects_hits_and_no_results(self, mock_get):
        def side_effect(url, params=None, **kwargs):
            if params["q"] == "site:example.com filetype:pdf":
                return _fake_response(200, {"items": [{"title": "T", "link": "https://example.com/x.pdf", "snippet": "s"}]})
            return _fake_response(200, {})
        mock_get.side_effect = side_effect
        status_list, hits, no_res = oe._run_query_batch(
            oe.DEFAULT_DORK_QUERIES, SAFE_TARGET, "key", "cx", 5.0, 10, 0
        )
        assert len(status_list) == len(oe.DEFAULT_DORK_QUERIES)
        assert any(h["link"] == "https://example.com/x.pdf" for h in hits)
        assert len(no_res) == len(oe.DEFAULT_DORK_QUERIES) - 1


class TestPersistSearchHits:
    def test_dedupes_and_persists(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        hits = [
            {"label": "a", "query": "q", "title": "T", "link": "https://example.com/x", "snippet": "s"},
            {"label": "a", "query": "q", "title": "T", "link": "https://example.com/x", "snippet": "s"},
        ]
        errors = oe.persist_search_hits(hits, SAFE_TARGET, store, "osint_engine_dork_result")
        assert errors == []
        assert len(store.all()) == 1


class TestInferTechFromHits:
    def test_matches_keyword(self):
        hits = [{"link": "u", "label": "l", "title": "Backend Engineer", "snippet": "Experience with Python and Django required"}]
        agg = oe.infer_tech_from_hits(hits)
        keywords = {r["keyword"] for r in agg}
        assert "Python" in keywords
        assert "Django" in keywords

    def test_no_match(self):
        hits = [{"link": "u", "label": "l", "title": "Sales Rep", "snippet": "no tech mentioned here"}]
        assert oe.infer_tech_from_hits(hits) == []


# ---------------------------------------------------------------------------
# HIBP
# ---------------------------------------------------------------------------

class TestQueryHibpDomainBreaches:
    @mock.patch("reconhound.osint_engine.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, [{"Name": "ExampleBreach", "Domain": SAFE_TARGET}])
        r = oe.query_hibp_domain_breaches(SAFE_TARGET)
        assert r["status"] == "found"
        called_url = mock_get.call_args.args[0]
        assert called_url == oe.HIBP_BREACHES_API

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_empty_list_not_found(self, mock_get):
        mock_get.return_value = _fake_response(200, [])
        r = oe.query_hibp_domain_breaches(SAFE_TARGET)
        assert r["status"] == "not_found"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_rate_limited(self, mock_get):
        mock_get.return_value = _fake_response(429)
        r = oe.query_hibp_domain_breaches(SAFE_TARGET)
        assert r["status"] == "rate_limited"


class TestQueryHibpAccountBreaches:
    def test_missing_credentials(self):
        r = oe.query_hibp_account_breaches("a@example.com", None)
        assert r["status"] == "missing_credentials"

    def test_empty_email(self):
        r = oe.query_hibp_account_breaches("", "key")
        assert r["status"] == "error"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, [{"Name": "ExampleBreach"}])
        r = oe.query_hibp_account_breaches("a@example.com", "key")
        assert r["status"] == "found"
        called_url = mock_get.call_args.args[0]
        assert called_url == f"{oe.HIBP_BREACHED_ACCOUNT_API}/a%40example.com"
        assert mock_get.call_args.kwargs["headers"]["hibp-api-key"] == "key"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_not_found_404(self, mock_get):
        mock_get.return_value = _fake_response(404)
        r = oe.query_hibp_account_breaches("a@example.com", "key")
        assert r["status"] == "not_found"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_unauthorized_401(self, mock_get):
        mock_get.return_value = _fake_response(401)
        r = oe.query_hibp_account_breaches("a@example.com", "bad-key")
        assert r["status"] == "unauthorized"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_rate_limited_429(self, mock_get):
        mock_get.return_value = _fake_response(429, headers={"Retry-After": "5"})
        r = oe.query_hibp_account_breaches("a@example.com", "key")
        assert r["status"] == "rate_limited"


class TestPersistBreachFindings:
    def test_domain_breach_persist(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        errors = oe.persist_breach_domain_findings([{"Name": "B", "Domain": SAFE_TARGET, "BreachDate": "2020-01-01"}], SAFE_TARGET, store)
        assert errors == []
        rec = store.all()[0]
        assert rec["type"] == "osint_engine_breach_domain"
        assert rec["confidence"] == oe.CONFIDENCE_HIGH
        assert rec["metadata"]["observed"] is True

    def test_account_breach_persist_tracks_provenance(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        errors = oe.persist_breach_account_findings("a@example.com", "observed", [{"Name": "B", "DataClasses": ["Emails"]}], SAFE_TARGET, store)
        assert errors == []
        rec = store.all()[0]
        assert rec["metadata"]["email_provenance"] == "observed"


# ---------------------------------------------------------------------------
# SecurityTrails DNS history
# ---------------------------------------------------------------------------

class TestQuerySecuritytrailsDnsHistory:
    def test_missing_credentials(self):
        r = oe.query_securitytrails_dns_history(SAFE_TARGET, "a", None)
        assert r["status"] == "missing_credentials"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, {"records": [{"values": [{"ip": SAFE_IP}], "first_seen": "2020-01-01", "last_seen": "2021-01-01"}]})
        r = oe.query_securitytrails_dns_history(SAFE_TARGET, "a", "key")
        assert r["status"] == "found"
        assert mock_get.call_args.kwargs["headers"]["APIKEY"] == "key"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_unauthorized(self, mock_get):
        mock_get.return_value = _fake_response(401)
        r = oe.query_securitytrails_dns_history(SAFE_TARGET, "a", "bad")
        assert r["status"] == "unauthorized"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_not_found_404(self, mock_get):
        mock_get.return_value = _fake_response(404)
        r = oe.query_securitytrails_dns_history(SAFE_TARGET, "a", "key")
        assert r["status"] == "not_found"


class TestPersistDnsHistoryFindings:
    def test_persists_and_normalizes_values(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        records = [{"values": [{"ip": SAFE_IP}], "first_seen": "2020-01-01", "last_seen": "2021-01-01"}]
        errors = oe.persist_dns_history_findings("a", records, SAFE_TARGET, store)
        assert errors == []
        rec = store.all()[0]
        assert rec["value"]["values"] == [SAFE_IP]
        assert rec["value"]["record_type"] == "A"


# ---------------------------------------------------------------------------
# HackerTarget reverse-IP
# ---------------------------------------------------------------------------

class TestQueryHackertargetReverseIp:
    def test_invalid_ip(self):
        r = oe.query_hackertarget_reverse_ip("not-an-ip")
        assert r["status"] == "error"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, text="a.example.com\nb.othersite.com\n")
        r = oe.query_hackertarget_reverse_ip(SAFE_IP)
        assert r["status"] == "found"
        assert "a.example.com" in r["domains"]
        assert "b.othersite.com" in r["domains"]

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_no_records_found(self, mock_get):
        mock_get.return_value = _fake_response(200, text="No DNS A records found")
        r = oe.query_hackertarget_reverse_ip(SAFE_IP)
        assert r["status"] == "not_found"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_quota_exceeded(self, mock_get):
        mock_get.return_value = _fake_response(200, text="API count exceeded - Increase Quota with Membership")
        r = oe.query_hackertarget_reverse_ip(SAFE_IP)
        assert r["status"] == "rate_limited"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_error_text(self, mock_get):
        mock_get.return_value = _fake_response(200, text="error check your search parameter")
        r = oe.query_hackertarget_reverse_ip(SAFE_IP)
        assert r["status"] == "error"


class TestPersistReverseIpFindings:
    def test_flags_in_scope_vs_third_party(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        errors = oe.persist_reverse_ip_findings(["mail.example.com", "othersite.com"], SAFE_IP, SAFE_TARGET, store)
        assert errors == []
        records = store.all()
        by_domain = {r["value"]["domain"]: r for r in records}
        assert by_domain["mail.example.com"]["value"]["in_scope"] is True
        assert by_domain["othersite.com"]["value"]["in_scope"] is False
        assert by_domain["othersite.com"]["metadata"]["note"] is not None


# ---------------------------------------------------------------------------
# BGPView ASN neighbors
# ---------------------------------------------------------------------------

class TestQueryBgpviewAsnPeers:
    def test_invalid_asn(self):
        r = oe.query_bgpview_asn_peers("not-an-asn")
        assert r["status"] == "error"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_found(self, mock_get):
        mock_get.return_value = _fake_response(200, {
            "status": "ok",
            "data": {"ipv4_peers": [{"asn": 456, "name": "PeerOrg", "country_code": "US"}], "ipv6_peers": []},
        })
        r = oe.query_bgpview_asn_peers("123")
        assert r["status"] == "found"
        assert r["peers"][0]["asn"] == 456
        called_url = mock_get.call_args.args[0]
        assert called_url == f"{oe.BGPVIEW_API_BASE}/asn/123/peers"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_accepts_as_prefix(self, mock_get):
        mock_get.return_value = _fake_response(200, {"status": "ok", "data": {"ipv4_peers": [], "ipv6_peers": []}})
        oe.query_bgpview_asn_peers("AS123")
        called_url = mock_get.call_args.args[0]
        assert called_url == f"{oe.BGPVIEW_API_BASE}/asn/123/peers"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_no_peers_not_found(self, mock_get):
        mock_get.return_value = _fake_response(200, {"status": "ok", "data": {"ipv4_peers": [], "ipv6_peers": []}})
        r = oe.query_bgpview_asn_peers("123")
        assert r["status"] == "not_found"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_non_ok_status(self, mock_get):
        mock_get.return_value = _fake_response(200, {"status": "error", "status_message": "ASN not found"})
        r = oe.query_bgpview_asn_peers("999999")
        assert r["status"] == "not_found"


class TestPersistAsnNeighborFindings:
    def test_persists(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        errors = oe.persist_asn_neighbor_findings([{"asn": 456, "name": "PeerOrg"}], "123", SAFE_TARGET, store)
        assert errors == []
        rec = store.all()[0]
        assert rec["type"] == "osint_engine_asn_neighbor"
        assert rec["value"]["peer_asn"] == 456


# ---------------------------------------------------------------------------
# run_osint_engine (end-to-end orchestration)
# ---------------------------------------------------------------------------

class TestRunOsintEngine:
    def test_rejects_invalid_target(self, tmp_path):
        with pytest.raises(oe.ScopeError):
            oe.run_osint_engine("not a domain", output_dir=str(tmp_path))

    def test_no_credentials_completes_without_crashing(self, tmp_path, monkeypatch):
        for var in (oe.GOOGLE_API_KEY_ENV, oe.GOOGLE_CSE_ID_ENV, oe.HIBP_API_KEY_ENV,
                    oe.SECURITYTRAILS_API_KEY_ENV, oe.HACKERTARGET_API_KEY_ENV):
            monkeypatch.delenv(var, raising=False)

        with mock.patch("reconhound.osint_engine.requests.get") as mock_get:
            mock_get.return_value = _fake_response(200, [])  # crt.sh + hibp domain: empty results
            result = oe.run_osint_engine(SAFE_TARGET, output_dir=str(tmp_path))

        assert result["source_status"]["search_engine_email"]["status"] == "missing_credentials"
        assert result["source_status"]["dorking"]["status"] == "missing_credentials"
        assert result["source_status"]["dns_history"]["status"] == "missing_credentials"
        assert result["source_status"]["hibp_account"]["status"] == "missing_credentials"
        assert result["source_status"]["reverse_ip"]["status"] == "no_seed_ip"
        assert result["source_status"]["asn_neighbors"]["status"] == "no_seed_asn"
        json.dumps(result)  # whole summary must be JSON-safe

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_full_pipeline_persists_emails_patterns_and_employees(self, mock_get, tmp_path):
        def side_effect(url, params=None, headers=None, **kwargs):
            if url == oe.CRTSH_API_BASE and params and params.get("output") == "json":
                return _fake_response(200, [{"id": 1}])
            if url == oe.CRTSH_API_BASE:
                return _fake_response(200, text=CERT_WITH_EMAILS_PEM)
            if url == oe.GOOGLE_CSE_API_BASE:
                return _fake_response(200, {})  # no search results for any dork/email query
            if url == oe.HIBP_BREACHES_API:
                return _fake_response(200, [])
            raise AssertionError(f"unexpected URL called: {url}")

        mock_get.side_effect = side_effect

        result = oe.run_osint_engine(
            SAFE_TARGET, output_dir=str(tmp_path),
            google_api_key="gkey", google_cse_id="cx",
            include_hibp_account=False, include_dns_history=False,
            include_reverse_ip=False, include_asn_neighbors=False,
        )

        assert result["stats"]["emails_found"] >= 1
        assert any(e["email"] == "admin@example.com" for e in result["emails"])
        assert result["stats"]["employees_inferred"] == result["stats"]["emails_found"]
        json.dumps(result)

        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        persisted_types = {r["type"] for r in store.all()}
        assert "osint_engine_email" in persisted_types
        assert "osint_engine_employee" in persisted_types
        assert "osint_engine_naming_convention" in persisted_types

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_negative_result_memory_persisted(self, mock_get, tmp_path):
        mock_get.return_value = _fake_response(200, [])  # every list/array-shaped source: empty
        result = oe.run_osint_engine(
            SAFE_TARGET, output_dir=str(tmp_path),
            include_search_email=False, include_dorking=False, include_paste=False,
            include_job_tech=False, include_hibp_account=False, include_dns_history=False,
            include_reverse_ip=False, include_asn_neighbors=False,
        )
        assert result["stats"]["no_result_checks"] >= 1
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        no_result = [r for r in store.all() if r["type"] == "osint_engine_checked_no_result"]
        assert len(no_result) >= 1
        assert all(r["confidence"] == oe.CONFIDENCE_LOW for r in no_result)

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_one_source_failure_does_not_abort_others(self, mock_get, tmp_path):
        def side_effect(url, params=None, **kwargs):
            if url == oe.CRTSH_API_BASE:
                raise requests.exceptions.ConnectionError("crt.sh is down")
            if url == oe.HIBP_BREACHES_API:
                return _fake_response(200, [{"Name": "B", "Domain": SAFE_TARGET}])
            raise AssertionError(f"unexpected URL called: {url}")

        mock_get.side_effect = side_effect
        result = oe.run_osint_engine(
            SAFE_TARGET, output_dir=str(tmp_path),
            include_search_email=False, include_dorking=False, include_paste=False,
            include_job_tech=False, include_hibp_account=False, include_dns_history=False,
            include_reverse_ip=False, include_asn_neighbors=False,
        )
        assert result["source_status"]["ct_log"]["status"] == "error"
        assert result["stats"]["breach_domain_records_found"] == 1
        json.dumps(result)

    def test_seed_overrides_enable_reverse_ip_and_asn(self, tmp_path):
        with mock.patch("reconhound.osint_engine.requests.get") as mock_get:
            def side_effect(url, params=None, **kwargs):
                if url == oe.CRTSH_API_BASE:
                    return _fake_response(200, [])
                if url == oe.HIBP_BREACHES_API:
                    return _fake_response(200, [])
                if url == oe.HACKERTARGET_REVERSE_IP_API:
                    return _fake_response(200, text="No records found")
                if url == f"{oe.BGPVIEW_API_BASE}/asn/123/peers":
                    return _fake_response(200, {"status": "ok", "data": {"ipv4_peers": [], "ipv6_peers": []}})
                raise AssertionError(f"unexpected URL called: {url}")

            mock_get.side_effect = side_effect
            result = oe.run_osint_engine(
                SAFE_TARGET, output_dir=str(tmp_path), seed_ip=SAFE_IP, seed_asn="123",
                include_search_email=False, include_dorking=False, include_paste=False,
                include_job_tech=False, include_hibp_account=False, include_dns_history=False,
            )
        assert result["source_status"]["reverse_ip"]["status"] == "not_found"
        assert result["source_status"]["asn_neighbors"]["status"] == "not_found"

    @mock.patch("reconhound.osint_engine.requests.get")
    def test_never_contacts_the_target_directly(self, mock_get, tmp_path):
        """Passive boundary: every captured request must go to a third-party provider, never the target."""
        def side_effect(url, params=None, **kwargs):
            if url == oe.CRTSH_API_BASE:
                return _fake_response(200, [])
            if url == oe.GOOGLE_CSE_API_BASE:
                return _fake_response(200, {})
            if url == oe.HIBP_BREACHES_API:
                return _fake_response(200, [])
            raise AssertionError(f"unexpected URL called: {url}")

        mock_get.side_effect = side_effect
        oe.run_osint_engine(
            SAFE_TARGET, output_dir=str(tmp_path), google_api_key="k", google_cse_id="cx",
            include_hibp_account=False, include_dns_history=False,
            include_reverse_ip=False, include_asn_neighbors=False,
        )

        allowed_hosts = ("https://crt.sh/", "https://www.googleapis.com/", "https://haveibeenpwned.com/")
        for call in mock_get.call_args_list:
            url = call.args[0]
            assert url.startswith(allowed_hosts), f"passive boundary violation: request sent to {url!r}"

    def test_malformed_response_does_not_abort_run(self, tmp_path):
        with mock.patch("reconhound.osint_engine.requests.get") as mock_get:
            mock_get.return_value = _fake_response(200, raise_json_error=True, text="")
            result = oe.run_osint_engine(
                SAFE_TARGET, output_dir=str(tmp_path),
                include_search_email=False, include_dorking=False, include_paste=False,
                include_job_tech=False, include_hibp_account=False, include_dns_history=False,
                include_reverse_ip=False, include_asn_neighbors=False,
            )
        json.dumps(result)


# ===========================================================================
# Module 4 remediation regression tests
#
# Each class pins one confirmed defect from the Module 4 audit. The docstrings
# record the reproduction, because several were only visible once the finding
# reached surface_mapper.py/risk_engine.py, and four of them are regressions
# found by adversarially attacking the fixes themselves.
# ===========================================================================

class TestRoleMailboxesDoNotBecomePeople:
    """
    OE-01/OE-02. `info.support@` has exactly the shape of a first.last personal
    address, so the employee generator turned it into a named human who does
    not exist ("Info Support", "No Reply", "Sales Team") and the naming-
    convention inference counted it as evidence of a personal naming policy.
    """

    ROLE_MAILBOXES = ["info.support", "no-reply", "sales.team", "help.desk",
                      "jobs.careers", "hr.team", "it.support", "info", "support",
                      "admin", "postmaster", "noreply", "do-not-reply"]

    # Real people whose names contain a role word. An earlier version of the
    # fix fired on ANY matching token and erased every one of them — a false
    # negative traded for the false positive the check exists to prevent.
    REAL_PEOPLE = ["steve.jobs", "dev.patel", "ana.it", "john.mail", "sarah.press",
                   "mark.legal", "j.service", "tim.cook", "jane.doe"]

    @pytest.mark.parametrize("local_part", ROLE_MAILBOXES)
    def test_recognises_role_mailboxes(self, local_part):
        assert oe.is_role_mailbox(local_part) is True

    @pytest.mark.parametrize("local_part", REAL_PEOPLE)
    def test_does_not_erase_real_people(self, local_part):
        assert oe.is_role_mailbox(local_part) is False

    @pytest.mark.parametrize("value", [None, "", "   ", 123, [], {}, "...", "---", "\x00"])
    def test_malformed_input_is_safe(self, value):
        assert oe.is_role_mailbox(value) is False

    def test_role_mailbox_yields_no_fabricated_name(self):
        emps = oe.generate_employee_inferences(["sales.team@example.com"])
        assert emps[0]["probable_name"] is None
        assert emps[0]["role_account"] is True
        assert "role mailbox" in emps[0]["name_withheld_reason"]

    def test_real_person_still_gets_a_probable_name(self):
        emps = oe.generate_employee_inferences(["steve.jobs@example.com"])
        assert emps[0]["probable_name"] == "Steve Jobs"
        assert emps[0]["role_account"] is False

    def test_role_mailbox_is_still_recorded_not_dropped(self, tmp_path):
        """The address is real; only the personal-identity claim is withheld."""
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        emps = oe.generate_employee_inferences(["sales.team@example.com"])
        assert oe.persist_employee_findings(emps, SAFE_TARGET, store) == []
        rec = store.all()[0]
        assert rec["value"]["source_email"] == "sales.team@example.com"
        assert rec["value"]["probable_name"] is None
        assert rec["value"]["role_account"] is True
        assert rec["confidence"] == oe.CONFIDENCE_LOW

    def test_role_mailboxes_excluded_from_naming_convention_sample(self):
        info = oe.infer_email_patterns(
            ["info.support@example.com", "sales.team@example.com", "john.smith@example.com"],
            SAFE_TARGET)
        assert info["total_observed"] == 1
        assert info["total_emails_seen"] == 3
        assert info["role_mailboxes_excluded"] == ["info.support@example.com", "sales.team@example.com"]

    def test_three_role_mailboxes_no_longer_carry_a_bogus_convention(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        info = oe.infer_email_patterns(
            ["info.support@example.com", "sales.team@example.com", "help.desk@example.com"], SAFE_TARGET)
        value, err = oe.persist_naming_convention_finding(info, SAFE_TARGET, store)
        assert err is None
        assert value["status"] == "insufficient_data"
        # The excluded addresses are named, so "0 usable" is not mistaken for
        # "no addresses were found".
        assert len(value["role_mailboxes_excluded"]) == 3
        assert any("excluded as shared/role mailboxes" in e for e in store.all()[0]["evidence"])

    def test_personal_addresses_still_reach_high_confidence(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        info = oe.infer_email_patterns(
            ["john.smith@example.com", "jane.doe@example.com", "bob.jones@example.com"], SAFE_TARGET)
        value, _ = oe.persist_naming_convention_finding(info, SAFE_TARGET, store)
        assert value["convention"] == "first.last"
        assert store.all()[0]["confidence"] == oe.CONFIDENCE_HIGH


class TestJobPostingMentionContext:
    """
    OE-03/OE-04. Keyword matching had no notion of the sentence around it, so
    "migrating away from Oracle", "legacy PHP", "nice to have: Kubernetes",
    agency boilerplate and the plain English words "Go"/"Spring" all counted as
    plain technology requirements — and a duplicate hit alone was enough to
    carry a keyword from LOW to MEDIUM.
    """

    @pytest.mark.parametrize("text,expect", [
        ("We are migrating away from Oracle to PostgreSQL", "migration away"),
        ("Maintain our legacy PHP system", "legacy/deprecated"),
        ("This service is being decommissioned", "legacy/deprecated"),
        ("Nice to have: Kubernetes", "optional/nice-to-have"),
        ("Terraform would be great", "optional/nice-to-have"),
        ("If you have Kafka experience", "hypothetical/aspirational"),
        ("Our client is a leading retailer", "recruitment-agency boilerplate"),
    ])
    def test_flags_qualified_context(self, text, expect):
        reasons = " ".join(oe.assess_mention_context(text, "Python"))
        assert expect in reasons

    def test_plain_requirement_is_not_qualified(self):
        assert oe.assess_mention_context("Required: 5 years of Python in production", "Python") == []

    @pytest.mark.parametrize("keyword", ["Go", "Spring", "Spark", "Express", "Oracle"])
    def test_ambiguous_keywords_are_flagged(self, keyword):
        reasons = oe.assess_mention_context("Backend engineer wanted", keyword)
        assert any("ordinary English word" in r for r in reasons)

    @pytest.mark.parametrize("keyword", ["Python", "Kubernetes", "PostgreSQL", "TypeScript"])
    def test_unambiguous_keywords_are_not_flagged(self, keyword):
        assert oe.assess_mention_context("Backend engineer wanted", keyword) == []

    @pytest.mark.parametrize("text", [None, "", 123, [], {}, b"bytes", "\x00"])
    def test_malformed_text_is_safe(self, text):
        assert oe.assess_mention_context(text, "Python") == []

    @pytest.mark.parametrize("keyword", [None, 123, "", []])
    def test_malformed_keyword_is_safe(self, keyword):
        assert oe.assess_mention_context("some text", keyword) == []

    def test_spring_2024_internship_is_qualified_not_a_stack_claim(self, tmp_path):
        hits = [{"title": "Spring 2024 Internship", "snippet": "Apply now!",
                 "link": "https://indeed.com/j/1", "label": "job_indeed"}]
        agg = oe.infer_tech_from_hits(hits)
        rec = [r for r in agg if r["keyword"] == "Spring"][0]
        assert rec["all_mentions_qualified"] is True
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        assert oe.persist_job_tech_findings(agg, SAFE_TARGET, store) == []
        persisted = store.all()[0]
        assert persisted["confidence"] == oe.CONFIDENCE_LOW
        assert any("Confidence reduced" in e for e in persisted["evidence"])
        # Nothing is suppressed: the mention and its examples survive intact.
        assert persisted["value"]["technology_mention"] == "Spring"
        assert persisted["value"]["examples"]

    def test_duplicate_url_no_longer_inflates_the_count(self, tmp_path):
        hit = {"title": "Backend", "snippet": "Kubernetes in production",
               "link": "https://indeed.com/j/1", "label": "job_indeed"}
        agg = oe.infer_tech_from_hits([hit, dict(hit), dict(hit)])
        assert [r["count"] for r in agg] == [1]
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        oe.persist_job_tech_findings(agg, SAFE_TARGET, store)
        assert store.all()[0]["confidence"] == oe.CONFIDENCE_LOW

    def test_linkless_duplicates_are_also_deduplicated(self):
        """Regression: dedupe originally keyed on `link`, so link-less hits escaped it."""
        hit = {"title": "Backend", "snippet": "Kubernetes in production", "link": None, "label": "l"}
        agg = oe.infer_tech_from_hits([hit, dict(hit), dict(hit)])
        assert [r["count"] for r in agg] == [1]

    def test_two_genuinely_distinct_adverts_still_corroborate(self):
        """The dedupe must not cost real corroboration."""
        agg = oe.infer_tech_from_hits([
            {"title": "Backend", "snippet": "Kubernetes required", "link": "https://indeed.com/1", "label": "a"},
            {"title": "SRE", "snippet": "Kubernetes required", "link": "https://lever.co/2", "label": "b"},
        ])
        assert agg[0]["count"] == 2
        assert agg[0]["all_mentions_qualified"] is False

    def test_unqualified_multi_advert_mention_keeps_medium(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        agg = oe.infer_tech_from_hits([
            {"title": "Backend", "snippet": "Kubernetes required", "link": "https://indeed.com/1", "label": "a"},
            {"title": "SRE", "snippet": "Kubernetes required", "link": "https://lever.co/2", "label": "b"},
        ])
        oe.persist_job_tech_findings(agg, SAFE_TARGET, store)
        assert store.all()[0]["confidence"] == oe.CONFIDENCE_MEDIUM


class TestJobTechIsNotATechnologyAssertion:
    """
    OE-09. surface_mapper.py mints a technology ASSET on the target host for any
    finding whose `value` carries a "technology" key. A keyword scraped from a
    job advert therefore became indistinguishable in the asset graph from a
    technology tech_fingerprint.py had fingerprinted on a live host, and
    risk_engine.py reported it as "<tech> observed on <target>" — the exact
    inferred-becomes-observed collapse the module is meant to prevent.
    """

    def test_value_does_not_use_the_reserved_technology_key(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        agg = oe.infer_tech_from_hits([
            {"title": "Backend", "snippet": "Kubernetes required", "link": "u1", "label": "a"}])
        oe.persist_job_tech_findings(agg, SAFE_TARGET, store)
        value = store.all()[0]["value"]
        assert "technology" not in value
        assert value["technology_mention"] == "Kubernetes"

    def test_surface_mapper_mints_no_technology_asset(self, tmp_path):
        from reconhound.surface_mapper import SurfaceMapper
        out = str(tmp_path / "output")
        store = oe.PendingAssetsStore(output_dir=out)
        agg = oe.infer_tech_from_hits([
            {"title": "Backend", "snippet": "Kubernetes required", "link": "u1", "label": "a"}])
        oe.persist_job_tech_findings(agg, SAFE_TARGET, store)
        mapper = SurfaceMapper(SAFE_TARGET, output_dir=out, autosave=True)
        mapper.ingest_pending_assets_file()
        asset_types = {a["asset_type"] for a in mapper.state["assets"].values()}
        assert "technology" not in asset_types
        # The intelligence itself is not lost — it is still a finding.
        findings = [a for a in mapper.state["assets"].values() if a["asset_type"] == "finding"]
        assert any(f["value"]["finding_type"] == "osint_engine_job_tech_inference" for f in findings)

    def test_risk_engine_no_longer_calls_it_an_observed_technology(self, tmp_path):
        from reconhound.surface_mapper import SurfaceMapper
        from reconhound import risk_engine
        out = str(tmp_path / "output")
        store = oe.PendingAssetsStore(output_dir=out)
        agg = oe.infer_tech_from_hits([
            {"title": "Spring 2024 Internship", "snippet": "apply", "link": "u1", "label": "a"}])
        oe.persist_job_tech_findings(agg, SAFE_TARGET, store)
        mapper = SurfaceMapper(SAFE_TARGET, output_dir=out, autosave=True)
        mapper.ingest_pending_assets_file()
        result = risk_engine.run_risk_engine(graph=mapper, output_dir=out, persist=False)
        assert result["errors"] == []
        assert not any(s["category"] == "technology_observation" for s in result["signals"])


class TestBreachAttributionIsVerified:
    """
    OE-05. `persist_breach_domain_findings` trusted HIBP's server-side domain
    filter without ever checking the answer. HIBP's /breaches endpoint returns
    its ENTIRE corpus when the domain parameter is absent, ignored, or dropped
    by an intermediary — which silently attributed every breach in the database
    to the target at HIGH confidence with `observed: True`.
    """

    UNRELATED = [
        {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
         "PwnCount": 152445165, "DataClasses": ["Passwords"], "IsVerified": True},
        {"Name": "LinkedIn", "Title": "LinkedIn", "Domain": "linkedin.com", "BreachDate": "2012-05-05",
         "PwnCount": 164611595, "DataClasses": ["Passwords"], "IsVerified": True},
    ]
    MATCHING = [
        {"Name": "ExampleCorp", "Title": "Example Corp", "Domain": "example.com",
         "BreachDate": "2019-03-01", "PwnCount": 1000, "DataClasses": ["Passwords"],
         "IsVerified": True, "AddedDate": "2019-05-01T00:00:00Z", "ModifiedDate": "2020-01-01T00:00:00Z"},
    ]

    def test_unrelated_breach_is_not_attributed_at_high_confidence(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        assert oe.persist_breach_domain_findings(self.UNRELATED, SAFE_TARGET, store) == []
        for rec in store.all():
            assert rec["confidence"] == oe.CONFIDENCE_LOW
            assert rec["value"]["domain_match"] is False
            assert any("Attribution unverified" in e for e in rec["evidence"])

    def test_unrelated_breach_is_still_recorded_for_review(self, tmp_path):
        """Evidence-preserving: the record is kept, just not attributed."""
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        oe.persist_breach_domain_findings(self.UNRELATED, SAFE_TARGET, store)
        assert {r["value"]["name"] for r in store.all()} == {"Adobe", "LinkedIn"}

    def test_matching_breach_keeps_high_confidence(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        oe.persist_breach_domain_findings(self.MATCHING, SAFE_TARGET, store)
        rec = store.all()[0]
        assert rec["confidence"] == oe.CONFIDENCE_HIGH
        assert rec["value"]["domain_match"] is True
        assert not any("Attribution unverified" in e for e in rec["evidence"])

    def test_subdomain_breach_counts_as_a_match(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        oe.persist_breach_domain_findings(
            [{"Name": "Sub", "Domain": "shop.example.com", "BreachDate": "2020-01-01"}], SAFE_TARGET, store)
        assert store.all()[0]["value"]["domain_match"] is True

    @pytest.mark.parametrize("domain", [None, "", "evil-example.com", "example.com.evil.net", 123])
    def test_missing_or_lookalike_domain_is_not_a_match(self, tmp_path, domain):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        oe.persist_breach_domain_findings(
            [{"Name": "X", "Domain": domain, "BreachDate": "2020-01-01"}], SAFE_TARGET, store)
        rec = store.all()[0]
        assert rec["value"]["domain_match"] is False
        assert rec["confidence"] == oe.CONFIDENCE_LOW

    def test_temporal_provenance_is_preserved(self, tmp_path):
        """OE-12: breach date, HIBP's added date and the observation date are three dates."""
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        oe.persist_breach_domain_findings(self.MATCHING, SAFE_TARGET, store)
        rec = store.all()[0]
        assert rec["value"]["breach_date"] == "2019-03-01"
        assert rec["value"]["added_date"] == "2019-05-01T00:00:00Z"
        assert rec["value"]["modified_date"] == "2020-01-01T00:00:00Z"
        assert rec["timestamp"] != rec["value"]["breach_date"]

    def test_account_breach_keeps_temporal_provenance(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        oe.persist_breach_account_findings(
            "a@example.com", "observed",
            [{"Name": "X", "BreachDate": "2019-01-07", "AddedDate": "2019-02-01T00:00:00Z",
              "ModifiedDate": "2019-03-01T00:00:00Z", "DataClasses": ["Passwords"]}],
            SAFE_TARGET, store)
        value = store.all()[0]["value"]
        assert value["breach_date"] == "2019-01-07"
        assert value["added_date"] == "2019-02-01T00:00:00Z"
        # Historical breach membership, never an active-credential claim.
        assert "never validates" in store.all()[0]["metadata"]["note"]


class TestReverseIpBodyHandling:
    """
    OE-06/OE-07. HackerTarget reports errors as a plain-text body with HTTP 200.
    The markers were searched across the WHOLE body, so one co-hosted domain
    containing "quota" discarded every real result as a rate limit; and any
    unrecognised provider message became a "co-hosted domain" finding.
    """

    def _query(self, text):
        with mock.patch("reconhound.osint_engine.requests.get",
                        return_value=_fake_response(200, text=text)):
            return oe.query_hackertarget_reverse_ip(SAFE_IP)

    def test_domain_containing_quota_no_longer_discards_the_result_set(self):
        r = self._query("www.example.com\nquota-manager.example.com\nshop.example.com")
        assert r["status"] == "found"
        assert r["domains"] == ["www.example.com", "quota-manager.example.com", "shop.example.com"]

    @pytest.mark.parametrize("host", ["error-tracking.example.com", "quota-service.example.com",
                                      "no-reply.example.com", "nodes.example.com"])
    def test_single_hostname_that_trips_a_marker_is_still_a_hostname(self, host):
        """Regression found by attacking the fix: a one-line body IS a valid result."""
        r = self._query(host)
        assert r["status"] == "found"
        assert r["domains"] == [host]

    @pytest.mark.parametrize("text", ["Invalid input.", "API key invalid",
                                      "Please upgrade your plan for more results"])
    def test_unrecognised_provider_message_is_an_error_not_a_domain(self, text):
        r = self._query(text)
        assert r["status"] == "error"
        assert r["domains"] == []
        # Not "not_found" either: an unusable response is not evidence of absence.
        assert r["status"] != "not_found"

    def test_known_status_messages_still_classify(self):
        assert self._query("API count exceeded - Increase Quota with Membership")["status"] == "rate_limited"
        assert self._query("error check your search parameter")["status"] == "error"
        assert self._query("No DNS A records found")["status"] == "not_found"
        assert self._query("")["status"] == "not_found"

    def test_mixed_body_keeps_the_parsable_hosts_and_records_the_rest(self):
        r = self._query("www.example.com\n-- truncated --\nshop.example.com")
        assert r["status"] == "found"
        assert r["domains"] == ["www.example.com", "shop.example.com"]
        assert r["unparsed_lines"] == ["-- truncated --"]

    def test_out_of_scope_cohosted_domains_are_still_flagged_not_owned(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        oe.persist_reverse_ip_findings(["othersite.com"], SAFE_IP, SAFE_TARGET, store)
        rec = store.all()[0]
        assert rec["value"]["in_scope"] is False
        assert "not part of the target's asset inventory" in rec["metadata"]["note"]


class TestCtHarvestPartialFailureIsInconclusive:
    """
    OE-08. crt.sh listed certificates, every certificate fetch failed, nothing
    was inspected — and the module reported `not_found`, which run_osint_engine
    writes into surface_mapper's check memory as a CHECK_NOT_FOUND negative
    result claiming "no emails in certificates". A conclusion was recorded that
    was never reached.
    """

    def _run(self, cert_fetch_ok):
        listing = _fake_response(200, text=json.dumps([{"id": i} for i in range(5)]))
        def side_effect(url, params=None, timeout=None, headers=None, **kwargs):
            if params and "d" in params:
                if not cert_fetch_ok:
                    raise requests.exceptions.ConnectionError("crt.sh cert fetch down")
                return _fake_response(200, text="-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----")
            return listing
        with mock.patch("reconhound.osint_engine.requests.get", side_effect=side_effect):
            return oe.harvest_ct_emails(SAFE_TARGET)

    def test_all_cert_fetches_failing_is_inconclusive(self):
        r = self._run(cert_fetch_ok=False)
        assert r["status"] == "inconclusive"
        assert r["certs_listed"] == 5
        assert r["certs_inspected"] == 0
        assert r["certs_failed"] == 5
        assert "none could be fetched or parsed" in r["error"]

    def test_certs_inspected_with_no_emails_is_a_genuine_negative(self):
        """The fix must not turn every empty CT result into 'inconclusive'."""
        r = self._run(cert_fetch_ok=True)
        assert r["status"] == "not_found"
        assert r["certs_inspected"] == 5

    def test_empty_listing_is_a_genuine_negative(self):
        with mock.patch("reconhound.osint_engine.requests.get",
                        return_value=_fake_response(200, text="[]")):
            r = oe.harvest_ct_emails(SAFE_TARGET)
        assert r["status"] == "not_found"

    def test_inconclusive_never_becomes_negative_result_memory(self, tmp_path):
        out = str(tmp_path / "output")
        listing = _fake_response(200, text=json.dumps([{"id": i} for i in range(5)]))
        def side_effect(url, params=None, timeout=None, headers=None, **kwargs):
            if "crt.sh" in url:
                if params and "d" in params:
                    raise requests.exceptions.ConnectionError("down")
                return listing
            return _fake_response(500, text="")
        with mock.patch("reconhound.osint_engine.requests.get", side_effect=side_effect), \
             mock.patch("reconhound.osint_engine.time.sleep"):
            summary = oe.run_osint_engine(
                SAFE_TARGET, output_dir=out, include_dorking=False, include_paste=False,
                include_job_tech=False, include_hibp_account=False, include_dns_history=False,
                include_reverse_ip=False, include_asn_neighbors=False,
                include_search_email=False, include_hibp_domain=False)
        assert summary["source_status"]["ct_log"]["status"] == "inconclusive"
        assert summary["stats"]["sources_inconclusive"] == ["ct_log"]
        assert summary["stats"]["sources_inconclusive_count"] == 1
        with open(os.path.join(out, "pending_assets.json")) as handle:
            types = [r["type"] for r in json.load(handle)]
        negatives = [r for r in json.load(open(os.path.join(out, "pending_assets.json")))
                     if r["type"] == "osint_engine_checked_no_result"]
        assert not any(n["value"]["check"] == "ct_log_email_harvest" for n in negatives)


class TestSearchCompletenessAndSkippedQueries:
    """OE-10/OE-11: a bounded sample and an aborted batch must both say so."""

    def test_google_result_reports_completeness(self):
        payload = {"items": [{"title": "t", "link": f"https://example.com/{i}", "snippet": "s"}
                             for i in range(10)],
                   "searchInformation": {"totalResults": "48300"}}
        with mock.patch("reconhound.osint_engine.requests.get",
                        return_value=_fake_response(200, payload)):
            r = oe.query_google_custom_search("site:example.com", "k", "c")
        assert r["items_examined"] == 10
        assert r["total_results"] == 48300
        assert r["total_results_reported"] is True
        assert r["results_truncated"] is True

    def test_complete_single_page_is_not_truncated(self):
        payload = {"items": [{"title": "t", "link": "https://example.com/1", "snippet": "s"}],
                   "searchInformation": {"totalResults": "1"}}
        with mock.patch("reconhound.osint_engine.requests.get",
                        return_value=_fake_response(200, payload)):
            r = oe.query_google_custom_search("q", "k", "c")
        assert r["results_truncated"] is False

    @pytest.mark.parametrize("total", [None, "many", {}, []])
    def test_unreported_total_is_not_assumed_complete_either_way(self, total):
        payload = {"items": [{"title": "t", "link": "https://example.com/1"}],
                   "searchInformation": {"totalResults": total}}
        with mock.patch("reconhound.osint_engine.requests.get",
                        return_value=_fake_response(200, payload)):
            r = oe.query_google_custom_search("q", "k", "c")
        assert r["total_results_reported"] is False
        assert r["results_truncated"] is False

    def test_missing_credentials_batch_records_every_skipped_query(self):
        status_list, hits, no_res = oe._run_query_batch(
            oe.DEFAULT_PASTE_QUERIES, SAFE_TARGET, None, None, 5.0, 10, 0)
        assert len(status_list) == len(oe.DEFAULT_PASTE_QUERIES)
        assert status_list[0]["status"] == "missing_credentials"
        assert all(s["status"] == "skipped" for s in status_list[1:])
        assert no_res == []


class TestProviderFailureVisibility:
    """OE-13: _compact_stats keeps only scalars, so provider outcomes needed one."""

    def test_total_provider_failure_is_countable(self, tmp_path):
        with mock.patch("reconhound.osint_engine.requests.get",
                        side_effect=requests.exceptions.ConnectionError("down")), \
             mock.patch("reconhound.osint_engine.time.sleep"):
            summary = oe.run_osint_engine(
                SAFE_TARGET, output_dir=str(tmp_path / "output"),
                google_api_key="k", google_cse_id="c", hibp_api_key="h",
                securitytrails_api_key="st", seed_ip=SAFE_IP, seed_asn="64500")
        assert summary["stats"]["source_checks_failed"] > 0
        # A total failure must not masquerade as a clean set of negatives.
        assert summary["stats"]["no_result_checks"] == 0

    def test_missing_credentials_counted_separately_from_failures(self, tmp_path):
        with mock.patch("reconhound.osint_engine.requests.get",
                        return_value=_fake_response(200, text="[]")), \
             mock.patch("reconhound.osint_engine.time.sleep"):
            summary = oe.run_osint_engine(
                SAFE_TARGET, output_dir=str(tmp_path / "output"),
                google_api_key=None, google_cse_id=None, hibp_api_key=None,
                securitytrails_api_key=None, seed_ip=SAFE_IP, seed_asn="64500")
        assert summary["stats"]["source_checks_missing_credentials"] > 0

    def test_orchestrator_compact_stats_preserves_the_counters(self, tmp_path):
        from reconhound.core.orchestrator import _compact_stats
        with mock.patch("reconhound.osint_engine.requests.get",
                        side_effect=requests.exceptions.ConnectionError("down")), \
             mock.patch("reconhound.osint_engine.time.sleep"):
            summary = oe.run_osint_engine(
                SAFE_TARGET, output_dir=str(tmp_path / "output"), hibp_api_key="h")
        compact = _compact_stats(summary)
        assert compact["stats.source_checks_failed"] > 0
        assert compact["stats.sources_inconclusive_count"] == 0


class TestPublicEntryPointRobustness:
    """
    Found by adversarially fuzzing the module's public helpers. Not reachable
    from run_osint_engine (which only ever passes well-formed collections), but
    these are documented entry points and every other malformed-input path in
    this module degrades rather than raising.
    """

    @pytest.mark.parametrize("hits", [None, [], [None, 1, "x", []], [{"title": None, "snippet": None}]])
    def test_infer_tech_from_hits_never_raises(self, hits):
        assert oe.infer_tech_from_hits(hits) == []

    @pytest.mark.parametrize("records", [None, [], [None, 7, "x"], [{}], [{"email": None}], [{"email": "no-at-sign"}]])
    def test_merge_email_records_never_raises(self, records):
        assert oe.merge_email_records(records) == []

    def test_merge_email_records_keeps_valid_entries_alongside_malformed_ones(self):
        merged = oe.merge_email_records([None, {"email": None}, {"email": "a@example.com", "source": "ct_log"}, 7])
        assert [m["email"] for m in merged] == ["a@example.com"]

    @pytest.mark.parametrize("emails", [None, [], [None, 7, "no-at-sign"]])
    def test_employee_inference_never_raises(self, emails):
        assert oe.generate_employee_inferences(emails) == []

    @pytest.mark.parametrize("emails", [None, [], [None, 7, "no-at-sign"]])
    def test_infer_email_patterns_never_raises(self, emails):
        info = oe.infer_email_patterns(emails, SAFE_TARGET)
        assert info["total_observed"] == 0
        assert info["candidates"] == []

    def test_valid_emails_survive_alongside_malformed_ones(self):
        emps = oe.generate_employee_inferences([None, "jane.doe@example.com", 7])
        assert [e["probable_name"] for e in emps] == ["Jane Doe"]


class TestInferredObservedBoundaryIsPinned:
    """
    The four boundary guarantees the module exists to hold (assignment §9).
    Three of them were asserted only by a note string in the source with no
    test behind them; this pins all four, including end-to-end through
    surface_mapper.py.
    """

    def test_asn_adjacency_is_not_corporate_ownership(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        oe.persist_asn_neighbor_findings(
            [{"asn": 174, "name": "COGENT-174", "description": "Cogent Communications",
              "country_code": "US"}], "64500", SAFE_TARGET, store)
        rec = store.all()[0]
        assert rec["confidence"] == oe.CONFIDENCE_MEDIUM
        assert "not necessarily shared organizational ownership" in rec["metadata"]["note"]
        # The peer is described as a peer, never as an asset of the target.
        assert "peer" in rec["evidence"][0].lower()
        assert rec["value"]["peer_asn"] == 174
        assert rec["value"]["source_asn"] == "64500"

    def test_transit_and_cloud_peers_are_not_promoted(self, tmp_path):
        """A transit provider or cloud ASN is the common case, not an exception."""
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        oe.persist_asn_neighbor_findings(
            [{"asn": 16509, "name": "AMAZON-02", "description": "Amazon.com, Inc."},
             {"asn": 3356, "name": "LEVEL3", "description": "Level 3 Parent, LLC"},
             {"asn": 13335, "name": "CLOUDFLARENET", "description": "Cloudflare, Inc."}],
            "64500", SAFE_TARGET, store)
        assert len(store.all()) == 3
        for rec in store.all():
            assert rec["confidence"] != oe.CONFIDENCE_HIGH
            assert "not necessarily shared organizational ownership" in rec["metadata"]["note"]

    def test_cohosted_domain_is_not_a_target_asset(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        oe.persist_reverse_ip_findings(
            ["shared-tenant.net", "mail.example.com"], SAFE_IP, SAFE_TARGET, store)
        by_domain = {r["value"]["domain"]: r for r in store.all()}
        assert by_domain["shared-tenant.net"]["value"]["in_scope"] is False
        assert by_domain["mail.example.com"]["value"]["in_scope"] is True

    def test_breach_membership_is_not_an_active_credential(self, tmp_path):
        store = oe.PendingAssetsStore(output_dir=str(tmp_path))
        oe.persist_breach_account_findings(
            "a@example.com", "observed",
            [{"Name": "OldBreach", "BreachDate": "2012-05-05", "DataClasses": ["Passwords"]}],
            SAFE_TARGET, store)
        rec = store.all()[0]
        assert "never validates the leaked credential" in rec["metadata"]["note"]
        assert rec["value"]["breach_date"] == "2012-05-05"
        # No field anywhere claims the credential is live.
        assert "active" not in json.dumps(rec).lower()

    def test_inferred_flag_survives_surface_mapper_ingestion(self, tmp_path):
        """
        The inferred/observed split must survive correlation, not just exist in
        this module. risk_engine.py has no SignalRule for osint_engine_* types
        yet, so it reads them all as generic observations — that is a
        documented downstream gap, but the flag itself must still be there for
        it to consume.
        """
        from reconhound.surface_mapper import SurfaceMapper
        out = str(tmp_path / "output")
        store = oe.PendingAssetsStore(output_dir=out)
        oe.persist_employee_findings(
            oe.generate_employee_inferences(["jane.doe@example.com"]), SAFE_TARGET, store)
        oe.persist_emails(
            oe.merge_email_records([{"email": "a@example.com", "source": "ct_log"}]),
            SAFE_TARGET, store)
        mapper = SurfaceMapper(SAFE_TARGET, output_dir=out, autosave=True)
        mapper.ingest_pending_assets_file()
        by_type = {o["type"]: o for o in mapper.state["observations"].values()}
        assert by_type["osint_engine_employee"]["metadata"]["inferred"] is True
        assert by_type["osint_engine_employee"]["metadata"]["observed"] is False
        assert by_type["osint_engine_email"]["metadata"]["observed"] is True
        assert by_type["osint_engine_email"]["metadata"]["inferred"] is False
