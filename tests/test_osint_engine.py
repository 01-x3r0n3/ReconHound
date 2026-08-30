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
        mock_get.return_value = _fake_response(429)
        status_list, hits, no_res = oe._run_query_batch(
            oe.DEFAULT_DORK_QUERIES, SAFE_TARGET, "key", "cx", 5.0, 10, 0
        )
        assert len(status_list) == 1
        assert status_list[0]["status"] == "rate_limited"

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
