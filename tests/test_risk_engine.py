"""
Tests for reconhound/risk_engine.py (ReconHound Module 20, per context.md's
build order — catalog item 20, build-order position 11).

Run with:  ./.venv/bin/python -m pytest tests/test_risk_engine.py -v

No network access anywhere in this file, and none is mocked, because
risk_engine.py never makes a request: it only evaluates evidence other
modules already produced.

Integration tests build their graphs by feeding realistic finding records —
the exact shapes the producing modules' make_finding() calls emit — through
the real surface_mapper.SurfaceMapper, rather than hand-writing graph
documents. That keeps the tests honest about the structures the engine
actually has to consume.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import risk_engine as risk
from reconhound.surface_mapper import SurfaceMapper

TARGET = "example.com"


def finding(finding_type, value, target=TARGET, evidence=None, confidence="HIGH",
            source="test_module.py", timestamp="2026-08-20T00:00:00+00:00", metadata=None):
    """A raw finding record in the exact shape every module's make_finding() produces."""
    return {
        "type": finding_type,
        "target": target,
        "value": value,
        "evidence": evidence if evidence is not None else [f"{finding_type} evidence"],
        "confidence": confidence,
        "source": source,
        "timestamp": timestamp,
        "metadata": metadata or {},
    }


@pytest.fixture
def build(tmp_path):
    """Ingest findings through the real surface mapper and return (mapper, output_dir)."""
    def _build(records, target=TARGET):
        mapper = SurfaceMapper(target=target, output_dir=str(tmp_path))
        mapper.ingest_many(records)
        return mapper, str(tmp_path)
    return _build


@pytest.fixture
def assess(build):
    def _assess(records, target=TARGET, **kwargs):
        mapper, output_dir = build(records, target=target)
        return risk.run_risk_engine(graph=mapper, output_dir=output_dir, persist=False, **kwargs)
    return _assess


def signals_of(assessment, category):
    return [s for s in assessment["signals"] if s["category"] == category]


def asset_record(assessment, asset_id):
    for record in assessment["assessed_assets"]:
        if record["asset_id"] == asset_id:
            return record
    return None


# Reusable realistic producer records ---------------------------------------

def db_exposure_finding():
    """active_recon.py check_database_exposure — annotates metadata severity CRITICAL."""
    return finding(
        "db_exposure", {"ip": "93.184.216.34", "exposed_ports": [3306], "details": {"3306": {"service": "mysql"}}},
        source="active_recon.py",
        evidence=["TCP connect() to 93.184.216.34:3306 succeeded (mysql)"],
        metadata={"ip": "93.184.216.34", "severity": "CRITICAL"},
    )


def missing_headers_finding(url="https://example.com/"):
    """http_analyzer.analyze_security_headers output shape."""
    return finding(
        "http_security_headers",
        {"url": url, "headers": {
            "Content-Security-Policy": {"present": False, "value": None, "notes": ["header not present"]},
            "Strict-Transport-Security": {"present": False, "value": None, "notes": ["header not present"]},
            "X-Frame-Options": {"present": True, "value": "DENY", "notes": []},
        }},
        source="http_analyzer.py", metadata={"url": url},
    )


def self_signed_and_old_tls_finding(host=TARGET):
    """ssl_analyzer.run_ssl_analyzer's `tls_certificate_analysis` value shape."""
    return finding(
        "tls_certificate_analysis",
        {"host": host, "port": 443,
         "certificate": {"subject": {"CN": host}, "issuer": {"CN": host}, "serial_number": "1"},
         "validity": {"is_expired": False},
         "tls_version": {"version": "TLSv1.0", "is_outdated": True},
         "self_signed": {"self_signed": True, "confidence": "HIGH", "evidence": ["issuer==subject"]},
         "sans": {"sans": [host], "count": 1}},
        source="ssl_analyzer.py", timestamp="2026-08-20T00:00:01+00:00",
    )


def cve_finding(technology="nginx", version="1.18.0", applicability="version_range_confirmed",
                score=9.4, kev=None, exploitdb=None, confidence="HIGH", cve_id="CVE-2021-23017",
                summaries=None, timestamp="2026-08-20T00:00:05+00:00"):
    """vuln_intel.map_technology_to_cves' `vulnerability_intelligence` value shape."""
    return finding(
        "vulnerability_intelligence",
        {"cve_id": cve_id, "technology": technology, "version": version, "target": TARGET,
         "statement": f"Detected {technology} {version} — MAY be affected by {cve_id}.",
         "applicability": applicability, "confidence": confidence,
         "summaries": summaries if summaries is not None else ["Off-by-one in resolver allows remote code execution"],
         "cvss": [{"source": "nvd", "score": score, "severity": "CRITICAL", "vector": "AV:N"}] if score else [],
         "references": [], "published": "2021-05-25",
         "matched_sources": [{"source": "nvd", "version_match": "range_confirmed"}],
         "cisa_kev": kev, "exploitdb_references": exploitdb or [],
         "detection_evidence": ["Server header"],
         "note": "Technology/version-to-CVE match is vulnerability intelligence, not confirmed exploitability."},
        source="vuln_intel.py", confidence=confidence, timestamp=timestamp,
        metadata={"technology": technology, "version": version, "cve_id": cve_id,
                  "applicability": applicability, "cisa_kev_listed": bool(kev),
                  "exploitdb_reference_count": len(exploitdb or [])},
    )


def tech_finding(technology="nginx", version="1.18.0", source="tech_fingerprint.py",
                 confidence="HIGH", timestamp="2026-08-20T00:00:02+00:00"):
    return finding("tech_fingerprint_detected",
                   {"technology": technology, "category": "server", "version": version,
                    "url": "https://example.com/"},
                   source=source, confidence=confidence, timestamp=timestamp)


def exposure_finding(url, category, discovery_type="confirmed_exposure", confidence="HIGH",
                     timestamp="2026-08-20T00:00:03+00:00"):
    """exposure_scan.py's `exposure_finding` value shape."""
    return finding("exposure_finding",
                   {"url": url, "path": "/x", "method": "GET", "status_code": 200,
                    "exposure_category": category, "discovery_type": discovery_type,
                    "confidence": confidence, "excerpt": "", "error_page_indicators": []},
                   source="exposure_scan.py", confidence=confidence, timestamp=timestamp,
                   metadata={"exposure_category": category, "discovery_type": discovery_type, "url": url})


# ---------------------------------------------------------------------------
# Severity vocabulary and arithmetic
# ---------------------------------------------------------------------------

class TestSeverityModel:
    def test_severity_ladder_matches_context_md(self):
        assert sorted(risk.VALID_SEVERITIES, key=risk.severity_rank) == \
            ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def test_shift_severity_clamps_at_both_ends(self):
        assert risk.shift_severity("CRITICAL", 3) == "CRITICAL"
        assert risk.shift_severity("INFO", -3) == "INFO"
        assert risk.shift_severity("MEDIUM", 2) == "CRITICAL"

    def test_cap_severity_never_raises(self):
        assert risk.cap_severity("CRITICAL", "MEDIUM") == "MEDIUM"
        assert risk.cap_severity("LOW", "CRITICAL") == "LOW"

    def test_unknown_confidence_is_treated_as_low_not_favourably(self):
        assert risk.normalize_confidence(None) == "LOW"
        assert risk.normalize_confidence("VERY HIGH") == "LOW"

    def test_confidence_aggregation_matches_context_md_section_8(self):
        # A single weak signal stays LOW; independent converging signals raise it.
        assert risk.aggregate_confidence([{"source": "a", "confidence": "LOW"}]) == "LOW"
        assert risk.aggregate_confidence([{"source": "a", "confidence": "LOW"},
                                          {"source": "b", "confidence": "LOW"}]) == "MEDIUM"
        assert risk.aggregate_confidence([{"source": "a", "confidence": "MEDIUM"},
                                          {"source": "b", "confidence": "MEDIUM"}]) == "HIGH"
        assert risk.aggregate_confidence([]) == "LOW"


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

class TestIngestion:
    def test_accepts_a_live_surface_mapper(self, build):
        mapper, output_dir = build([db_exposure_finding()])
        assessment = risk.RiskEngine(graph=mapper, output_dir=output_dir).assess()
        assert assessment["target"] == TARGET
        assert assessment["summary"]["signals"] > 0

    def test_accepts_a_state_dict_and_a_file_path(self, build, tmp_path):
        mapper, output_dir = build([db_exposure_finding()])
        mapper.save()
        from_dict = risk.RiskEngine(graph=mapper.state, output_dir=output_dir).assess()
        from_file = risk.RiskEngine(graph=os.path.join(output_dir, "surface_graph.json"),
                                     output_dir=output_dir).assess()
        assert from_dict["summary"]["signals"] == from_file["summary"]["signals"]

    def test_missing_graph_is_a_clear_fatal_error(self, tmp_path):
        with pytest.raises(risk.RiskEngineError, match="does not exist"):
            risk.RiskEngine(output_dir=str(tmp_path))

    def test_corrupt_graph_is_a_clear_fatal_error(self, tmp_path):
        path = os.path.join(str(tmp_path), "surface_graph.json")
        with open(path, "w") as handle:
            handle.write("{not json")
        with pytest.raises(risk.RiskEngineError, match="not valid JSON"):
            risk.RiskEngine(output_dir=str(tmp_path))

    def test_empty_graph_produces_an_empty_but_valid_assessment(self, tmp_path):
        assessment = risk.RiskEngine(graph={}, output_dir=str(tmp_path)).assess()
        assert assessment["summary"]["assets_assessed"] == 0
        assert assessment["investigation_queue"] == []
        assert assessment["errors"] == []

    def test_wrong_typed_graph_containers_are_recorded_not_accepted(self, tmp_path):
        assessment = risk.RiskEngine(
            graph={"target": TARGET, "assets": ["bogus"], "conflicts": 42},
            output_dir=str(tmp_path)).assess()
        errors = " ".join(e["error"] for e in assessment["errors"])
        assert "assets" in errors and "conflicts" in errors
        assert assessment["summary"]["assets_assessed"] == 0

    def test_invalid_settings_are_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="min_queue_severity"):
            risk.RiskEngine(graph={}, output_dir=str(tmp_path), min_queue_severity="URGENT")
        with pytest.raises(ValueError, match="negative"):
            risk.RiskEngine(graph={}, output_dir=str(tmp_path), stale_after_days=-1)


# ---------------------------------------------------------------------------
# Signal extraction against real producer shapes
# ---------------------------------------------------------------------------

class TestSignalExtraction:
    def test_db_exposure_is_critical_and_confirmed(self, assess):
        assessment = assess([db_exposure_finding()])
        signal = signals_of(assessment, "database_port_exposure")[0]
        assert signal["severity"] == "CRITICAL"
        assert signal["kind"] == risk.KIND_CONFIRMED
        assert signal["confirmed"] is True
        assert "exposed DB ports" in signal["severity_basis"]

    def test_producer_severity_annotation_is_honoured(self, assess):
        """active_recon.py annotates metadata severity, deferring correlation to this module."""
        record = finding("ipmi_exposure", {"ip": "10.0.0.1", "port": 623, "exposed": True},
                         source="active_recon.py", metadata={"severity": "CRITICAL"})
        signal = signals_of(assess([record]), "ipmi_exposure")[0]
        assert signal["severity"] == "CRITICAL"

    def test_missing_security_headers_is_medium(self, assess):
        signal = signals_of(assess([missing_headers_finding()]), "missing_security_headers")[0]
        assert signal["severity"] == "MEDIUM"
        assert "Content-Security-Policy" in signal["summary"]
        assert "Strict-Transport-Security" in signal["summary"]
        # A header that is present must not be reported as missing.
        assert "X-Frame-Options" not in signal["summary"]

    def test_present_headers_alone_produce_no_signal(self, assess):
        record = finding("http_security_headers",
                         {"url": "https://example.com/", "headers": {
                             "Content-Security-Policy": {"present": True, "value": "default-src 'self'"}}},
                         source="http_analyzer.py", metadata={"url": "https://example.com/"})
        assert signals_of(assess([record]), "missing_security_headers") == []

    def test_ssl_analyzer_dict_shapes_yield_tls_signals(self, assess):
        assessment = assess([self_signed_and_old_tls_finding()])
        assert signals_of(assessment, "self_signed_certificate")[0]["severity"] == "MEDIUM"
        assert signals_of(assessment, "outdated_tls_version")[0]["severity"] == "MEDIUM"

    def test_admin_panel_is_high_and_env_file_is_critical(self, assess):
        assessment = assess([
            exposure_finding("https://example.com/admin/", "administrative_panel"),
            exposure_finding("https://example.com/.env", "environment_file",
                             timestamp="2026-08-20T00:00:04+00:00"),
        ])
        assert signals_of(assessment, "exposed_administrative_panel")[0]["severity"] == "HIGH"
        assert signals_of(assessment, "exposed_credential_material")[0]["severity"] == "CRITICAL"

    def test_unconfirmed_exposure_is_an_indicator_at_low_severity(self, assess):
        """exposure_scan.py's own discovery_type vocabulary distinguishes confirmed from restricted."""
        assessment = assess([exposure_finding("https://example.com/.env", "environment_file",
                                               discovery_type="access_restricted")])
        assert signals_of(assessment, "exposed_credential_material") == []
        signal = signals_of(assessment, "sensitive_resource_present_not_readable")[0]
        assert signal["severity"] == "LOW"
        assert signal["kind"] == risk.KIND_INDICATOR

    def test_technology_detection_is_info(self, assess):
        signal = signals_of(assess([tech_finding()]), "technology_observation")[0]
        assert signal["severity"] == "INFO"
        assert signal["kind"] == risk.KIND_OBSERVATION

    def test_unrecognized_finding_type_is_preserved_as_info_not_dropped(self, assess):
        assessment = assess([finding("some_future_module_finding", {"detail": "x"}, source="future.py")])
        unclassified = [s for s in assessment["signals"] if s["category"].startswith("unclassified:")]
        assert len(unclassified) == 1
        assert unclassified[0]["severity"] == "INFO"
        assert "no risk rule matched" in " ".join(unclassified[0]["notes"])

    def test_negative_results_do_not_become_risk_signals(self, assess):
        """A 'checked and found nothing' record is negative-result memory, not a finding."""
        assessment = assess([
            finding("tech_fingerprint_checked_no_match", {"category": "cms", "url": "https://example.com/"},
                    source="tech_fingerprint.py", confidence="LOW"),
        ])
        assert assessment["summary"]["signals"] == 0

    def test_third_party_service_assets_produce_low_signals(self, assess):
        assessment = assess([
            finding("js_analyzer_external_service_reference",
                    {"vendor": "Stripe", "category": "payment", "host": "js.stripe.com",
                     "example_url": "https://js.stripe.com/v3"},
                    source="js_analyzer.py", confidence="MEDIUM",
                    metadata={"parent_js_url": "https://example.com/app.js"}),
        ])
        signal = signals_of(assessment, "third_party_dependency")[0]
        assert signal["severity"] == "LOW"
        assert signal["in_scope"] is False


# ---------------------------------------------------------------------------
# Evidence classes: observation / indicator / vuln intel / confirmed
# ---------------------------------------------------------------------------

class TestEvidenceClasses:
    def test_all_four_classes_are_representable(self, assess):
        assessment = assess([
            db_exposure_finding(),                                   # confirmed
            tech_finding(),                                          # observation
            cve_finding(),                                           # vulnerability intelligence
            finding("code_leak_exposure",
                    {"category": "api_key", "pattern_name": "aws_access_key_id",
                     "repository": "acme/app", "path": "prod.yml", "fingerprint_sha256": "abc",
                     "matched_via_queries": ["q1"]},
                    source="code_leak.py", confidence="MEDIUM",
                    timestamp="2026-08-20T00:00:06+00:00"),           # indicator
        ])
        classes = assessment["summary"]["signals_by_evidence_class"]
        assert classes[risk.KIND_CONFIRMED] >= 1
        assert classes[risk.KIND_OBSERVATION] >= 1
        assert classes[risk.KIND_VULN_INTEL] == 1
        assert classes[risk.KIND_INDICATOR] >= 1

    def test_a_cve_match_is_never_reported_as_confirmed(self, assess):
        signal = signals_of(assess([cve_finding(kev={"dateAdded": "2021-11-03"})]),
                            "vulnerability_intelligence")[0]
        assert signal["kind"] == risk.KIND_VULN_INTEL
        assert signal["confirmed"] is False

    def test_an_indicator_is_never_reported_as_confirmed(self, assess):
        record = finding("js_analyzer_secret_indicator",
                         {"category": "credential", "pattern_name": "private_key_block",
                          "redacted_value": "***", "fingerprint_sha256": "f1", "context": "..."},
                         source="js_analyzer.py", confidence="MEDIUM",
                         metadata={"parent_js_url": "https://example.com/app.js"})
        signal = signals_of(assess([record]), "secret_indicator_in_client_side_js")[0]
        assert signal["kind"] == risk.KIND_INDICATOR
        assert signal["confirmed"] is False

    def test_corroboration_never_promotes_an_indicator_to_confirmed(self, assess):
        """Two modules reporting the same leaked key raise confidence, not evidence class."""
        base = {"category": "api_key", "pattern_name": "aws_access_key_id", "repository": "acme/app",
                "path": "prod.yml", "fingerprint_sha256": "same-secret", "matched_via_queries": ["q1"]}
        assessment = assess([
            finding("code_leak_exposure", dict(base), source="code_leak.py", confidence="MEDIUM"),
            finding("code_leak_exposure", dict(base), source="code_leak.py", confidence="MEDIUM",
                    timestamp="2026-08-21T00:00:00+00:00"),
        ])
        signal = signals_of(assessment, "leaked_credential_in_public_code")[0]
        assert signal["kind"] == risk.KIND_INDICATOR
        assert signal["confirmed"] is False


# ---------------------------------------------------------------------------
# Confidence handling (context.md §8)
# ---------------------------------------------------------------------------

class TestConfidenceHandling:
    def test_low_confidence_indicator_cannot_be_presented_above_medium(self, assess):
        record = finding("code_leak_exposure",
                         {"category": "credential", "pattern_name": "generic_password",
                          "repository": "acme/x", "path": "a.yml", "fingerprint_sha256": "z",
                          "matched_via_queries": ["q"]},
                         source="code_leak.py", confidence="LOW")
        signal = signals_of(assess([record]), "leaked_credential_in_public_code")[0]
        assert signal["base_severity"] == "CRITICAL"
        assert signal["severity"] == "MEDIUM"
        assert any("capped at MEDIUM" in line for line in signal["rationale"])

    def test_high_confidence_evidence_is_not_capped(self, assess):
        signal = signals_of(assess([db_exposure_finding()]), "database_port_exposure")[0]
        assert signal["severity"] == "CRITICAL"

    def test_cap_is_applied_after_every_escalation(self, assess):
        """CVSS 10 + KEV + RCE wording still cannot outrun unknown-version evidence."""
        signal = signals_of(assess([cve_finding(
            version=None, applicability="version_unknown_cannot_confirm", score=10.0,
            kev={"dateAdded": "2021-01-01"}, exploitdb=[{"id": "1"}],
            summaries=["unauthenticated remote code execution"])]), "vulnerability_intelligence")[0]
        assert signal["confidence"] == "LOW"
        assert signal["severity"] == "MEDIUM"
        assert signal["confirmed"] is False


# ---------------------------------------------------------------------------
# Vulnerability intelligence
# ---------------------------------------------------------------------------

class TestVulnerabilityIntelligence:
    def test_cvss_score_maps_on_the_standard_scale(self):
        for score, expected in ((9.8, "CRITICAL"), (7.5, "HIGH"), (5.0, "MEDIUM"), (2.0, "LOW")):
            result = risk.classify_vulnerability_intelligence(
                {"cvss": [{"source": "nvd", "score": score}], "applicability": "version_range_confirmed",
                 "confidence": "HIGH", "summaries": []}, {})
            assert result["base_severity"] == expected

    def test_unknown_severity_is_held_at_medium_and_flagged(self):
        result = risk.classify_vulnerability_intelligence(
            {"cvss": [], "applicability": "version_range_confirmed", "confidence": "HIGH",
             "summaries": []}, {})
        assert result["base_severity"] == "MEDIUM"
        assert result["severity_unknown"] is True
        assert any("explicitly unknown severity" in note for note in result["notes"])

    def test_kev_and_exploitdb_are_not_counted_twice(self):
        result = risk.classify_vulnerability_intelligence(
            {"cvss": [{"score": 7.5}], "applicability": "version_range_confirmed", "confidence": "HIGH",
             "cisa_kev": {"dateAdded": "x"}, "exploitdb_references": [{"id": "1"}, {"id": "2"}],
             "summaries": []}, {})
        assert sum(f["steps"] for f in result["factors"]) == 1
        assert any("not counted twice" in note for note in result["notes"])

    def test_exploitdb_alone_still_counts_once(self):
        result = risk.classify_vulnerability_intelligence(
            {"cvss": [{"score": 7.5}], "applicability": "version_range_confirmed", "confidence": "HIGH",
             "cisa_kev": None, "exploitdb_references": [{"id": "1"}], "summaries": []}, {})
        assert [f["factor"] for f in result["factors"]] == ["public_exploit_exists"]

    def test_rce_wording_escalates_only_when_the_version_is_confirmed(self):
        confirmed = risk.classify_vulnerability_intelligence(
            {"cvss": [{"score": 7.5}], "applicability": "version_range_confirmed", "confidence": "HIGH",
             "summaries": ["allows remote code execution"]}, {})
        unconfirmed = risk.classify_vulnerability_intelligence(
            {"cvss": [{"score": 7.5}], "applicability": "keyword_match_version_unconfirmed",
             "confidence": "MEDIUM", "summaries": ["allows remote code execution"]}, {})
        assert any(f["factor"] == "rce_class_vulnerability" for f in confirmed["factors"])
        assert not any(f["factor"] == "rce_class_vulnerability" for f in unconfirmed["factors"])
        assert any("without escalation" in note for note in unconfirmed["notes"])

    def test_applicability_ceilings_bound_confidence(self):
        for applicability, expected in (("version_range_confirmed", "HIGH"),
                                        ("keyword_match_version_unconfirmed", "MEDIUM"),
                                        ("version_unknown_cannot_confirm", "LOW"),
                                        ("something_new", "LOW")):
            result = risk.classify_vulnerability_intelligence(
                {"cvss": [{"score": 9.8}], "applicability": applicability, "confidence": "HIGH",
                 "summaries": []}, {})
            assert result["confidence"] == expected


# ---------------------------------------------------------------------------
# Conflict preservation (context.md §8)
# ---------------------------------------------------------------------------

class TestConflictHandling:
    def test_version_conflict_suspends_the_dependent_cve_assessment(self, assess):
        assessment = assess([
            tech_finding(version="1.18.0", source="tech_fingerprint.py"),
            tech_finding(version="1.25.3", source="http_analyzer.py", confidence="MEDIUM",
                         timestamp="2026-08-20T00:00:03+00:00"),
            cve_finding(technology="nginx", version="1.18.0"),
        ])
        suspended = assessment["suspended_signals"]
        assert len(suspended) == 1
        assert suspended[0]["category"] == "vulnerability_intelligence"
        assert "suspended" in suspended[0]["reason"]
        # Preserved and reported, but driving nothing.
        assert signals_of(assessment, "vulnerability_intelligence")[0]["suspended"] is True
        assert assessment["investigation_queue"] == []

    def test_the_suspended_finding_and_its_conflict_are_both_preserved(self, assess):
        assessment = assess([
            tech_finding(version="1.18.0", source="tech_fingerprint.py"),
            tech_finding(version="1.25.3", source="http_analyzer.py", confidence="MEDIUM",
                         timestamp="2026-08-20T00:00:03+00:00"),
            cve_finding(technology="nginx", version="1.18.0"),
        ])
        signal = signals_of(assessment, "vulnerability_intelligence")[0]
        assert signal["cve_id"] == "CVE-2021-23017"
        assert signal["conflicts"] and signal["conflicts"][0]["attribute"] == "version"
        assert assessment["unresolved_conflicts"]
        # Both disputed values survive.
        values = {o["value"] for o in assessment["unresolved_conflicts"][0]["observations"]}
        assert values == {"1.18.0", "1.25.3"}

    def test_without_a_conflict_the_same_cve_drives_the_score(self, assess):
        assessment = assess([tech_finding(version="1.18.0"), cve_finding(technology="nginx")])
        assert assessment["suspended_signals"] == []
        assert signals_of(assessment, "vulnerability_intelligence")[0]["severity"] == "CRITICAL"
        assert any(entry["severity"] == "CRITICAL" for entry in assessment["investigation_queue"])

    def test_a_conflict_on_an_unrelated_technology_does_not_suspend(self, assess):
        assessment = assess([
            tech_finding(technology="WordPress", version="6.4", source="tech_fingerprint.py"),
            tech_finding(technology="WordPress", version="5.1", source="http_analyzer.py",
                         confidence="MEDIUM", timestamp="2026-08-20T00:00:03+00:00"),
            cve_finding(technology="nginx", version="1.18.0"),
        ])
        assert assessment["suspended_signals"] == []


# ---------------------------------------------------------------------------
# Relationship-based correlation (context.md §9)
# ---------------------------------------------------------------------------

class TestRelationshipCorrelation:
    def test_named_transport_cluster_escalates_once(self, assess):
        """context.md's own example: missing headers + self-signed + outdated TLS."""
        assessment = assess([missing_headers_finding(), self_signed_and_old_tls_finding(),
                             finding("dns_record", {"record_type": "A", "records": ["93.184.216.34"]},
                                      source="passive_recon.py", timestamp="2026-08-20T00:00:09+00:00")])
        host = asset_record(assessment, "hostname:example.com")
        assert host["severity"] == "HIGH"           # MEDIUM + exactly one step
        assert any("weak_transport_security_cluster" in line for line in host["rationale"])

    def test_overlapping_escalation_reasons_are_not_summed(self, assess):
        assessment = assess([missing_headers_finding(), self_signed_and_old_tls_finding()])
        host = asset_record(assessment, "hostname:example.com")
        applied = [line for line in host["rationale"] if "one escalation of" in line]
        assert len(applied) == 1
        assert "1 step(s)" in applied[0]

    def test_many_converging_medium_signals_combine_into_critical(self, assess):
        """context.md §9: several MEDIUM/LOW signals converging on one asset can combine into CRITICAL."""
        records = [
            missing_headers_finding(),
            self_signed_and_old_tls_finding(),
            finding("http_cookie_flags",
                    {"url": "https://example.com/",
                     "cookies": [{"name": "sid", "http_only": False, "secure": False,
                                  "samesite": None, "issues": ["missing HttpOnly", "missing Secure"]}]},
                    source="http_analyzer.py", metadata={"url": "https://example.com/"},
                    timestamp="2026-08-20T00:00:10+00:00"),
            finding("error_page_intelligence",
                    {"url": "https://example.com/x", "indicators": ["stack trace", "framework version"]},
                    source="exposure_scan.py", metadata={"url": "https://example.com/x"},
                    timestamp="2026-08-20T00:00:11+00:00"),
            finding("snmp_exposure", {"ip": "93.184.216.34", "port": 161,
                                       "accepted": [{"community": "public"}], "communities_tried": ["public"]},
                    source="active_recon.py", timestamp="2026-08-20T00:00:12+00:00"),
            finding("smtp_enumeration", {"ip": "93.184.216.34", "port": 25,
                                          "vrfy_supported": True, "expn_supported": False},
                    source="active_recon.py", timestamp="2026-08-20T00:00:13+00:00"),
            finding("dns_record", {"record_type": "A", "records": ["93.184.216.34"]},
                    source="passive_recon.py", timestamp="2026-08-20T00:00:14+00:00"),
        ]
        host = asset_record(assess(records), "hostname:example.com")
        assert host["severity"] == "CRITICAL"
        assert host["contributing_signal_count"] >= 6
        assert any("converge on this asset" in line for line in host["rationale"])

    def test_port_level_signals_roll_up_through_the_ip_to_the_hostname(self, assess):
        """context.md §7's hierarchy runs Domain -> IP -> Port; a port weakness belongs to the host."""
        assessment = assess([
            finding("dns_record", {"record_type": "A", "records": ["93.184.216.34"]},
                    source="passive_recon.py"),
            db_exposure_finding(),
        ])
        host = asset_record(assessment, "hostname:example.com")
        assert host["severity"] == "CRITICAL"
        assert host["related_signal_count"] >= 1
        assert any("hostname_to_ip" in line for line in host["rationale"])

    def test_explanation_names_the_relationship_a_signal_arrived_through(self, assess):
        assessment = assess([
            finding("dns_record", {"record_type": "A", "records": ["93.184.216.34"]},
                    source="passive_recon.py"),
            finding("snmp_exposure", {"ip": "93.184.216.34", "port": 161,
                                       "accepted": [{"community": "public"}]},
                    source="active_recon.py", timestamp="2026-08-20T00:00:15+00:00"),
        ])
        host = asset_record(assessment, "hostname:example.com")
        assert any("via ip_to_service -> hostname_to_ip" in line for line in host["rationale"])

    def test_a_single_signal_asset_is_not_escalated(self, assess):
        host = asset_record(assess([missing_headers_finding()]), "endpoint:https://example.com/")
        assert host["severity"] == "MEDIUM"
        assert not any("escalation" in line for line in host["rationale"])


# ---------------------------------------------------------------------------
# Double-counting / duplicate handling
# ---------------------------------------------------------------------------

class TestNoDoubleCounting:
    def test_the_same_fact_from_two_modules_is_one_signal_with_two_sources(self, assess):
        assessment = assess([
            missing_headers_finding(),
            finding("http_security_headers",
                    {"url": "https://example.com/", "headers": {
                        "Content-Security-Policy": {"present": False},
                        "Strict-Transport-Security": {"present": False},
                        "X-Frame-Options": {"present": True, "value": "DENY"}}},
                    source="tech_fingerprint.py", metadata={"url": "https://example.com/"},
                    timestamp="2026-08-21T00:00:00+00:00"),
        ])
        signals = signals_of(assessment, "missing_security_headers")
        assert len(signals) == 1
        assert set(signals[0]["corroborating_sources"]) == {"http_analyzer.py", "tech_fingerprint.py"}

    def test_corroboration_raises_confidence_rather_than_convergence_count(self, assess):
        assessment = assess([
            missing_headers_finding(),
            finding("http_security_headers",
                    {"url": "https://example.com/", "headers": {
                        "Content-Security-Policy": {"present": False},
                        "Strict-Transport-Security": {"present": False},
                        "X-Frame-Options": {"present": True, "value": "DENY"}}},
                    source="crawler.py", confidence="MEDIUM",
                    metadata={"url": "https://example.com/"}, timestamp="2026-08-21T00:00:00+00:00"),
        ])
        endpoint = asset_record(assessment, "endpoint:https://example.com/")
        assert endpoint["contributing_signal_count"] == 1
        assert endpoint["severity"] == "MEDIUM"
        signal = signals_of(assessment, "missing_security_headers")[0]
        assert any("corroborated" in line for line in signal["rationale"])

    def test_an_exact_duplicate_finding_cannot_inflate_a_score(self, assess):
        once = assess([db_exposure_finding()])
        twice = assess([db_exposure_finding(), db_exposure_finding()])
        assert once["summary"]["signals"] == twice["summary"]["signals"]
        assert (asset_record(once, "ip:93.184.216.34")["severity"]
                == asset_record(twice, "ip:93.184.216.34")["severity"])


# ---------------------------------------------------------------------------
# Prioritization
# ---------------------------------------------------------------------------

class TestPrioritization:
    def test_queue_is_ordered_critical_first(self, assess):
        assessment = assess([
            db_exposure_finding(),
            missing_headers_finding(),
            exposure_finding("https://example.com/admin/", "administrative_panel"),
            finding("dns_record", {"record_type": "A", "records": ["93.184.216.34"]},
                    source="passive_recon.py", timestamp="2026-08-20T00:00:20+00:00"),
        ])
        ranks = [risk.severity_rank(entry["severity"]) for entry in assessment["investigation_queue"]]
        assert ranks == sorted(ranks, reverse=True)
        assert assessment["investigation_queue"][0]["rank"] == 1

    def test_every_queue_entry_explains_its_score(self, assess):
        assessment = assess([db_exposure_finding(), missing_headers_finding()])
        for entry in assessment["investigation_queue"]:
            assert entry["explanation"]
            assert entry["top_signals"]
            assert "prioritization assessment" in entry["note"]

    def test_min_severity_filters_the_queue_without_dropping_evidence(self, assess):
        records = [db_exposure_finding(), missing_headers_finding()]
        low = assess(records)
        high = assess(records, min_queue_severity="CRITICAL")
        low_severities = {e["severity"] for e in low["investigation_queue"]}
        high_severities = {e["severity"] for e in high["investigation_queue"]}
        assert "MEDIUM" in low_severities and high_severities == {"CRITICAL"}
        assert len(high["investigation_queue"]) < len(low["investigation_queue"])
        # Filtering the queue must not remove any evidence from the assessment.
        assert high["summary"]["signals"] == low["summary"]["signals"]
        assert len(high["assessed_assets"]) == len(low["assessed_assets"])

    def test_info_only_assets_are_not_queued(self, assess):
        assessment = assess([tech_finding()])
        assert assessment["investigation_queue"] == []
        assert any(r["asset_type"] == "technology" for r in assessment["assessed_assets"])

    def test_queue_reports_contributing_and_total_signal_counts_separately(self, assess):
        assessment = assess([
            finding("dns_record", {"record_type": "A", "records": ["93.184.216.34"]},
                    source="passive_recon.py"),
            db_exposure_finding(),
        ])
        entry = [e for e in assessment["investigation_queue"] if e["asset_id"] == "ip:93.184.216.34"][0]
        assert entry["total_signal_count"] >= entry["contributing_signal_count"]

    def test_ordering_is_deterministic_across_runs(self, build):
        mapper, output_dir = build([db_exposure_finding(), missing_headers_finding(),
                                     exposure_finding("https://example.com/admin/", "administrative_panel")])
        first = risk.run_risk_engine(graph=mapper, output_dir=output_dir, persist=False)
        second = risk.run_risk_engine(graph=mapper, output_dir=output_dir, persist=False)
        first.pop("generated_at")
        second.pop("generated_at")
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# ---------------------------------------------------------------------------
# Scope enforcement (context.md §16)
# ---------------------------------------------------------------------------

class TestScopeEnforcement:
    def test_out_of_scope_asset_is_never_placed_in_the_queue(self, assess):
        assessment = assess([exposure_finding("https://evil-cdn.net/.env", "environment_file")])
        out_of_scope = [r for r in assessment["assessed_assets"] if r["in_scope"] is False]
        assert out_of_scope
        queued = {entry["asset_id"] for entry in assessment["investigation_queue"]}
        assert not queued & {r["asset_id"] for r in out_of_scope}

    def test_out_of_scope_evidence_is_still_assessed_and_reported(self, assess):
        assessment = assess([exposure_finding("https://evil-cdn.net/.env", "environment_file")])
        assert signals_of(assessment, "exposed_credential_material")
        assert assessment["out_of_scope_assets"]
        assert assessment["summary"]["out_of_scope_assets"] >= 1

    def test_in_scope_equivalent_finding_is_queued(self, assess):
        assessment = assess([exposure_finding("https://example.com/.env", "environment_file")])
        assert any(entry["severity"] == "CRITICAL" for entry in assessment["investigation_queue"])


# ---------------------------------------------------------------------------
# Staleness
# ---------------------------------------------------------------------------

class TestStaleness:
    def _records(self):
        return [
            exposure_finding("https://example.com/admin/", "administrative_panel",
                             timestamp="2026-01-01T00:00:00+00:00"),
            exposure_finding("https://example.com/.git/config", "version_control",
                             timestamp="2026-08-20T00:00:00+00:00"),
        ]

    def test_age_is_reported_even_without_a_staleness_policy(self, assess):
        assessment = assess(self._records())
        ages = {s["category"]: s["age_days"] for s in assessment["signals"]}
        assert ages["exposed_administrative_panel"] > 200
        assert all(not s["stale"] for s in assessment["signals"])

    def test_stale_signals_are_flagged_and_stop_driving_the_score(self, assess):
        assessment = assess(self._records(), stale_after_days=30)
        stale = [s for s in assessment["signals"] if s["stale"]]
        assert [s["category"] for s in stale] == ["exposed_administrative_panel"]
        queued = {entry["asset_id"] for entry in assessment["investigation_queue"]}
        assert "endpoint:https://example.com/admin/" not in queued

    def test_stale_evidence_is_preserved_and_explained(self, assess):
        assessment = assess(self._records(), stale_after_days=30)
        endpoint = asset_record(assessment, "endpoint:https://example.com/admin/")
        assert endpoint["severity"] == "INFO"
        assert any("stale, not scored" in line for line in endpoint["rationale"])
        assert endpoint["stale_signal_ids"]

    def test_staleness_is_measured_against_the_graph_not_the_clock(self, assess):
        """Two runs of the same graph must agree regardless of when they run."""
        first = assess(self._records(), stale_after_days=30)
        second = assess(self._records(), stale_after_days=30)
        assert [s["age_days"] for s in first["signals"]] == [s["age_days"] for s in second["signals"]]


# ---------------------------------------------------------------------------
# Malformed and unexpected input
# ---------------------------------------------------------------------------

class TestMalformedInput:
    def test_one_malformed_asset_does_not_destroy_the_assessment(self, tmp_path):
        state = {
            "target": TARGET,
            "assets": {
                "broken": "not-a-dict",
                "hostname:example.com": {
                    "id": "hostname:example.com", "asset_type": "hostname", "value": TARGET,
                    "attributes": {"tls_self_signed": {"value": True, "confidence": "HIGH",
                                                        "sources": ["ssl_analyzer.py"]}},
                    "in_scope": True, "sources": ["ssl_analyzer.py"], "observation_ids": [],
                    "confidence": "HIGH", "last_seen": "2026-08-20T00:00:00+00:00",
                },
            },
            "relationships": {}, "observations": {}, "conflicts": {},
            "updated_at": "2026-08-20T00:00:00+00:00",
        }
        assessment = risk.RiskEngine(graph=state, output_dir=str(tmp_path)).assess()
        assert any("not a JSON object" in e.get("error", "") for e in assessment["errors"])
        assert signals_of(assessment, "self_signed_certificate")

    def test_finding_detail_of_the_wrong_type_degrades_to_unclassified(self, tmp_path):
        state = {
            "target": TARGET,
            "assets": {"finding:x:1": {
                "id": "finding:x:1", "asset_type": "finding",
                "value": {"finding_type": "exposure_finding", "detail": "a-string-not-a-dict"},
                "attributes": {}, "sources": ["exposure_scan.py"], "observation_ids": [],
                "confidence": "HIGH", "last_seen": "2026-08-20T00:00:00+00:00"}},
            "relationships": {}, "observations": {}, "conflicts": {},
        }
        assessment = risk.RiskEngine(graph=state, output_dir=str(tmp_path)).assess()
        assert [s["category"] for s in assessment["signals"]] == ["unclassified:exposure_finding"]

    def test_missing_optional_fields_degrade_gracefully(self, assess):
        record = {"type": "db_exposure", "value": {"ip": "1.2.3.4", "exposed_ports": [3306]},
                  "source": "active_recon.py"}
        assessment = assess([record])
        assert signals_of(assessment, "database_port_exposure")

    def test_invalid_confidence_in_the_graph_is_treated_as_low(self, assess):
        record = finding("code_leak_exposure",
                         {"category": "api_key", "pattern_name": "p", "repository": "r",
                          "path": "a", "fingerprint_sha256": "f", "matched_via_queries": ["q"]},
                         source="code_leak.py", confidence="EXTREMELY HIGH")
        signal = signals_of(assess([record]), "leaked_credential_in_public_code")[0]
        assert signal["confidence"] == "LOW"
        assert signal["severity"] == "MEDIUM"

    def test_a_finding_with_no_observations_still_yields_a_signal(self, tmp_path):
        state = {
            "target": TARGET,
            "assets": {"finding:db:1": {
                "id": "finding:db:1", "asset_type": "finding",
                "value": {"finding_type": "db_exposure", "detail": {"ip": "1.2.3.4", "exposed_ports": [3306]}},
                "attributes": {}, "sources": ["active_recon.py"], "observation_ids": ["gone"],
                "confidence": "HIGH", "last_seen": "2026-08-20T00:00:00+00:00"}},
            "relationships": {}, "observations": {}, "conflicts": {},
        }
        assessment = risk.RiskEngine(graph=state, output_dir=str(tmp_path)).assess()
        signal = signals_of(assessment, "database_port_exposure")[0]
        assert signal["sources"] == ["active_recon.py"]
        assert signal["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# JSON safety and persistence
# ---------------------------------------------------------------------------

class TestJsonSafetyAndPersistence:
    def test_assessment_is_pure_json_with_no_default_fallback(self, assess):
        assessment = assess([db_exposure_finding(), cve_finding(), missing_headers_finding()])
        json.dumps(assessment, default=None)

    def test_non_json_safe_graph_values_are_coerced(self, tmp_path):
        import datetime

        class Weird:
            def __repr__(self):
                return "<weird>"

        state = {
            "target": TARGET,
            "assets": {"endpoint:x": {
                "id": "endpoint:x", "asset_type": "endpoint", "value": Weird(),
                "attributes": {"category": {"value": "admin", "confidence": "HIGH",
                                             "sources": {"exposure_scan.py"},
                                             "timestamp": datetime.datetime(2026, 8, 20)}},
                "in_scope": True, "sources": [Weird()], "observation_ids": [],
                "confidence": "HIGH", "last_seen": "2026-08-20T00:00:00+00:00"}},
            "relationships": {}, "observations": {}, "conflicts": {},
        }
        assessment = risk.RiskEngine(graph=state, output_dir=str(tmp_path)).assess()
        json.dumps(assessment, default=None)
        assert signals_of(assessment, "administrative_endpoint")

    def test_nan_and_infinity_are_not_emitted(self, tmp_path):
        state = {"target": TARGET, "assets": {"finding:v:1": {
            "id": "finding:v:1", "asset_type": "finding", "value": {
                "finding_type": "vulnerability_intelligence",
                "detail": {"cve_id": "CVE-1", "technology": "x", "applicability": "version_range_confirmed",
                            "confidence": "HIGH", "cvss": [{"score": float("nan")}], "summaries": []}},
            "attributes": {}, "sources": ["vuln_intel.py"], "observation_ids": [], "confidence": "HIGH",
            "last_seen": "2026-08-20T00:00:00+00:00"}},
            "relationships": {}, "observations": {}, "conflicts": {}}
        assessment = risk.RiskEngine(graph=state, output_dir=str(tmp_path)).assess()
        blob = json.dumps(assessment, default=None)
        assert "NaN" not in blob and "Infinity" not in blob

    def test_run_persists_valid_json_atomically(self, build):
        mapper, output_dir = build([db_exposure_finding()])
        assessment = risk.RiskEngine(graph=mapper, output_dir=output_dir).run()
        path = assessment["output_path"]
        with open(path) as handle:
            reloaded = json.load(handle)
        assert reloaded["module"] == "risk_engine.py"
        assert not [f for f in os.listdir(output_dir) if f.startswith(".risk_assessment_")]

    def test_repeated_runs_do_not_accumulate_state(self, build):
        mapper, output_dir = build([db_exposure_finding(), missing_headers_finding()])
        engine = risk.RiskEngine(graph=mapper, output_dir=output_dir)
        first = engine.run()
        second = engine.run()
        for record in (first, second):
            record.pop("generated_at")
            record.pop("output_path")
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

class TestProvenance:
    def test_every_signal_carries_source_evidence_and_observation_ids(self, assess):
        assessment = assess([db_exposure_finding(), missing_headers_finding()])
        for signal in assessment["signals"]:
            assert signal["sources"]
            assert signal["provenance"]
            assert signal["severity_basis"]
            assert signal["rationale"]

    def test_original_module_evidence_strings_survive_into_the_signal(self, assess):
        signal = signals_of(assess([db_exposure_finding()]), "database_port_exposure")[0]
        assert any("TCP connect()" in item for item in signal["evidence"])

    def test_observation_ids_link_back_to_the_graph(self, build):
        mapper, output_dir = build([db_exposure_finding()])
        assessment = risk.run_risk_engine(graph=mapper, output_dir=output_dir, persist=False)
        signal = signals_of(assessment, "database_port_exposure")[0]
        assert signal["observation_ids"]
        for observation_id in signal["observation_ids"]:
            assert observation_id in mapper.state["observations"]

    def test_severity_basis_cites_the_architecture(self, assess):
        assessment = assess([db_exposure_finding(), missing_headers_finding(),
                             exposure_finding("https://example.com/admin/", "administrative_panel")])
        for signal in assessment["signals"]:
            assert "context.md" in signal["severity_basis"] or "annotated" in signal["severity_basis"]


# ---------------------------------------------------------------------------
# Security posture
# ---------------------------------------------------------------------------

class TestSecurityPosture:
    def test_module_has_no_network_or_execution_capability(self):
        source = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                    "reconhound", "risk_engine.py")).read()
        for forbidden in ("import socket", "import requests", "import urllib", "import subprocess",
                          "os.system", "eval(", "exec("):
            assert forbidden not in source, f"risk_engine.py must not contain {forbidden!r}"

    def test_assessment_never_claims_exploitability(self, assess):
        assessment = assess([cve_finding(kev={"dateAdded": "x"}, exploitdb=[{"id": "1"}]),
                             db_exposure_finding()])
        blob = json.dumps(assessment).lower()
        assert "confirmed exploitable" not in blob
        assert "prioritization assessment" in blob

    def test_no_signal_is_marked_confirmed_unless_directly_observed(self, assess):
        assessment = assess([cve_finding(), tech_finding(),
                             finding("code_leak_exposure",
                                      {"category": "token", "pattern_name": "p", "repository": "r",
                                       "path": "a", "fingerprint_sha256": "f", "matched_via_queries": ["q"]},
                                      source="code_leak.py")])
        for signal in assessment["signals"]:
            if signal["kind"] in (risk.KIND_INDICATOR, risk.KIND_VULN_INTEL):
                assert signal["confirmed"] is False


if __name__ == "__main__":
    import subprocess
    subprocess.run([sys.executable, "-m", "pytest", __file__, "-v"])
