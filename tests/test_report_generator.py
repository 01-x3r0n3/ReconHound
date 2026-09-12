"""
Tests for reconhound/report_generator.py (ReconHound Module 21 — professional
reporting).

Run with:  ./.venv/bin/python -m pytest tests/test_report_generator.py -v

No network access anywhere in this file. The end-to-end tests reuse
tests/test_orchestrator.py's `install_fakes()`, so the report is generated
from a graph the real SurfaceMapper built and an assessment the real
RiskEngine produced — only the network I/O is removed.

The module's contract is transformation and presentation, so that is what is
asserted: that the report says exactly what the source state says, that it
never promotes intelligence into confirmation, and that target-controlled
content can never become markup.
"""

import json
import os
import sys
from html.parser import HTMLParser

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import report_generator as rg
from reconhound import risk_engine
from reconhound import surface_mapper
from reconhound.core import orchestrator as orch

from test_orchestrator import install_fakes, Recorder  # noqa: E402  (shared fakes)

TARGET = "example.com"

# context.md §11 places this module at reconhound/report_generator.py.
SOURCE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reconhound", "report_generator.py")

XSS = '<script>alert("xss")</script>'
ATTR = '" onmouseover="alert(1)'
URI = "javascript:alert(1)"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input",
             "link", "meta", "param", "source", "track", "wbr"}


class _HtmlAudit(HTMLParser):
    """Well-formedness + injection audit of a generated report."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.errors = []
        self.scripts = 0
        self.external = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.scripts += 1
        for name, value in attrs:
            if name.startswith("on"):
                self.errors.append(f"event handler {name}={value!r}")
            if name in ("href", "src") and value:
                lowered = value.strip().lower()
                if lowered.startswith("javascript:"):
                    self.errors.append(f"javascript: URI in {name}")
                if lowered.startswith(("http://", "https://", "//")):
                    self.external.append(value)
        if tag not in VOID_TAGS:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in VOID_TAGS:
            return
        if not self.stack:
            self.errors.append(f"stray </{tag}>")
        elif self.stack[-1] != tag:
            self.errors.append(f"</{tag}> closes <{self.stack[-1]}>")
        else:
            self.stack.pop()

    def handle_data(self, data):
        self.text.append(data)

    @property
    def plain_text(self):
        return "".join(self.text)


def audit(markup):
    parser = _HtmlAudit()
    parser.feed(markup)
    parser.close()
    if parser.stack:
        parser.errors.append(f"unclosed: {parser.stack}")
    return parser


def finding(finding_type, target=TARGET, value=None, evidence=("observed",),
            confidence="HIGH", source="crawler.py", timestamp="2026-08-01T00:00:00+00:00",
            metadata=None):
    return {"type": finding_type, "target": target, "value": value if value is not None else {},
            "evidence": list(evidence), "confidence": confidence, "source": source,
            "timestamp": timestamp, "metadata": metadata or {}}


@pytest.fixture
def outdir(tmp_path):
    return str(tmp_path / "output")


@pytest.fixture
def rec():
    return Recorder()


@pytest.fixture
def pipeline(monkeypatch, rec, outdir):
    """A complete, realistic run: real SurfaceMapper, real RiskEngine, no network."""
    install_fakes(monkeypatch, rec)
    result = orch.run_orchestrator(TARGET, output_dir=outdir)
    return {"output_dir": outdir, "execution": result}


def graph_with(outdir, findings, target=TARGET):
    mapper = surface_mapper.SurfaceMapper(target=target, output_dir=outdir)
    for record in findings:
        try:
            mapper.ingest_finding(record)
        except surface_mapper.MalformedFindingError:
            pass
    mapper.save()
    return mapper


# ===========================================================================
# Identity and architectural placement
# ===========================================================================

class TestIdentity:
    def test_lives_where_context_md_places_it(self):
        assert os.path.isfile(SOURCE_PATH)
        assert rg.MODULE_NAME == "report_generator.py"

    def test_performs_no_reconnaissance_and_no_process_execution(self):
        source = open(SOURCE_PATH, encoding="utf-8").read()
        for forbidden in ("import requests", "import socket", "import subprocess",
                          "shell=True", "eval(", "exec(", "os.system", "popen"):
            assert forbidden not in source, f"{forbidden!r} has no place in the reporting layer"

    def test_reuses_the_existing_severity_and_confidence_vocabularies(self):
        assert rg.VALID_SEVERITIES == risk_engine.VALID_SEVERITIES
        assert set(rg.KIND_LABELS) == risk_engine.VALID_KINDS

    def test_defines_no_scoring_of_its_own(self):
        source = open(SOURCE_PATH, encoding="utf-8").read()
        for forbidden in ("def score_", "def extract_signals", "CORRELATION_RULES = ",
                          "def build_investigation_queue"):
            assert forbidden not in source


# ===========================================================================
# Input resolution
# ===========================================================================

class TestInputs:
    def test_accepts_a_live_surface_mapper(self, outdir):
        mapper = graph_with(outdir, [finding("dns_record", value={"record_type": "A", "records": ["203.0.113.1"]})])
        document = rg.build_report_document(graph=mapper, output_dir=outdir)
        assert document["target"] == TARGET
        assert document["asset_inventory"]["total"] > 0

    def test_accepts_a_state_dict_and_a_path(self, outdir):
        mapper = graph_with(outdir, [finding("dns_record", value={"record_type": "A", "records": ["203.0.113.1"]})])
        from_dict = rg.build_report_document(graph=mapper.state, output_dir=outdir)
        from_path = rg.build_report_document(
            graph=os.path.join(outdir, "surface_graph.json"), output_dir=outdir)
        assert from_dict["asset_inventory"]["total"] == from_path["asset_inventory"]["total"]

    def test_defaults_to_the_output_directory_artifacts(self, pipeline):
        document = rg.build_report_document(output_dir=pipeline["output_dir"])
        assert document["severity"]["available"] is True
        assert document["scan"]["execution_record_available"] is True

    def test_missing_graph_is_the_one_fatal_input(self, tmp_path):
        with pytest.raises(rg.ReportInputError):
            rg.build_report_document(output_dir=str(tmp_path / "nothing"))

    def test_corrupt_graph_is_reported_not_swallowed(self, outdir):
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "surface_graph.json"), "w") as handle:
            handle.write("{not json")
        with pytest.raises(rg.ReportInputError):
            rg.build_report_document(output_dir=outdir)

    def test_corrupt_assessment_is_reported_not_silently_dropped(self, outdir):
        graph_with(outdir, [finding("dns_record", value={"record_type": "A", "records": ["203.0.113.1"]})])
        with open(os.path.join(outdir, "risk_assessment.json"), "w") as handle:
            handle.write("[]")
        with pytest.raises(rg.ReportInputError):
            rg.build_report_document(output_dir=outdir)

    def test_missing_assessment_and_execution_are_stated_not_faked(self, outdir):
        graph_with(outdir, [finding("dns_record", value={"record_type": "A", "records": ["203.0.113.1"]})])
        document = rg.build_report_document(output_dir=outdir)
        assert document["severity"]["available"] is False
        assert document["findings"]["available"] is False
        assert document["scan"]["execution_record_available"] is False
        # Absent, not zero.
        assert document["executive_summary"]["queue_length"] is None
        assert document["executive_summary"]["confirmed_findings"] is None
        assert len(document["warnings"]) == 2
        assert any("No risk assessment" in text for text in document["limitations"])


# ===========================================================================
# Document fidelity — the report says what the source state says
# ===========================================================================

class TestFidelity:
    def test_counts_match_the_graph(self, pipeline):
        document = rg.build_report_document(output_dir=pipeline["output_dir"])
        graph = json.load(open(os.path.join(pipeline["output_dir"], "surface_graph.json")))
        assert document["asset_inventory"]["total"] == len(graph["assets"])
        assert document["executive_summary"]["observations"] == len(graph["observations"])
        assert document["relationships"]["total"] == len(graph["relationships"])

    def test_severity_distribution_matches_the_assessment(self, pipeline):
        document = rg.build_report_document(output_dir=pipeline["output_dir"])
        assessment = json.load(open(os.path.join(pipeline["output_dir"], "risk_assessment.json")))
        summary = assessment["summary"]
        for name, count in summary["assets_by_severity"].items():
            assert document["severity"]["assets_by_severity"][name] == count
        assert document["severity"]["queue_length"] == summary["queue_length"]
        assert document["severity"]["signals"] == summary["signals"]

    def test_queue_order_and_severities_are_carried_through_unchanged(self, pipeline):
        document = rg.build_report_document(output_dir=pipeline["output_dir"])
        assessment = json.load(open(os.path.join(pipeline["output_dir"], "risk_assessment.json")))
        source = assessment["investigation_queue"]
        rendered = document["investigation_queue"]["entries"]
        assert [e["rank"] for e in rendered] == [e["rank"] for e in source[:len(rendered)]]
        for produced, original in zip(rendered, source):
            assert produced["asset_id"] == original["asset_id"]
            assert produced["severity"] == original["severity"]
            assert produced["explanation"] == original["explanation"]

    def test_every_signal_keeps_its_evidence_class(self, pipeline):
        document = rg.build_report_document(output_dir=pipeline["output_dir"])
        assessment = json.load(open(os.path.join(pipeline["output_dir"], "risk_assessment.json")))
        by_id = {s["signal_id"]: s for s in assessment["signals"]}
        for entry in document["findings"]["entries"]:
            assert entry["kind"] == by_id[entry["signal_id"]]["kind"]
            assert entry["severity"] == by_id[entry["signal_id"]]["severity"]
            assert entry["confidence"] == by_id[entry["signal_id"]]["confidence"]

    def test_evidence_and_provenance_are_preserved(self, pipeline):
        document = rg.build_report_document(output_dir=pipeline["output_dir"])
        assessment = json.load(open(os.path.join(pipeline["output_dir"], "risk_assessment.json")))
        by_id = {s["signal_id"]: s for s in assessment["signals"]}
        checked = 0
        for entry in document["findings"]["entries"]:
            source = by_id[entry["signal_id"]]
            if not source.get("evidence"):
                continue
            checked += 1
            assert entry["evidence"] == source["evidence"][:len(entry["evidence"])]
            assert entry["observation_ids"] == source["observation_ids"]
            assert entry["sources"] == sorted(set(source["sources"]))
        assert checked, "fixture produced no evidence to preserve"

    def test_vuln_intel_section_matches_the_full_signal_set(self, pipeline):
        document = rg.build_report_document(output_dir=pipeline["output_dir"])
        assessment = json.load(open(os.path.join(pipeline["output_dir"], "risk_assessment.json")))
        expected = [s for s in assessment["signals"]
                    if s["kind"] == risk_engine.KIND_VULN_INTEL]
        assert document["vulnerability_intelligence"]["count"] == len(expected)
        assert {e["cve_id"] for e in document["vulnerability_intelligence"]["entries"]} == \
               {s["cve_id"] for s in expected}

    def test_execution_status_is_reported_verbatim(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, failing={"code_leak", "ssl_analyzer"})
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        document = rg.build_report_document(output_dir=outdir, execution=result)
        assert document["scan"]["run_status"] == orch.RUN_COMPLETED_WITH_ERRORS
        failed = {m["module"] for m in document["execution"]["failed_modules"]}
        assert failed == {"code_leak", "ssl_analyzer"}
        assert any("module execution(s) failed" in text for text in document["limitations"])

    def test_attack_surface_paths_come_from_the_graph(self, pipeline):
        document = rg.build_report_document(output_dir=pipeline["output_dir"])
        paths = document["attack_surface_paths"]
        assert paths["available"] is True
        assert paths["entries"], "fixture produced no discovery chains"
        for entry in paths["entries"]:
            hops = entry["hops"]
            assert hops[0]["label"] == TARGET or hops[0].get("truncated")
            for hop in hops[1:]:
                assert hop["via"] and hop["via"].get("relationship_type")

    def test_relationship_index_matches_surface_mappers_own_lookup(self, pipeline):
        """
        The indexed lookup handed to explain_asset_path() must be exactly what
        SurfaceMapper.relationships_for() would have returned.
        """
        graph = json.load(open(os.path.join(pipeline["output_dir"], "surface_graph.json")))
        builder = rg.ReportBuilder(graph=graph, output_dir=pipeline["output_dir"])
        index = builder._relationship_index()

        reference = surface_mapper.SurfaceMapper(
            target=TARGET, output_dir=pipeline["output_dir"],
            autosave=False, load_existing=False)
        reference.state = graph
        assert graph["relationships"], "fixture produced no relationships"
        for asset_id in graph["assets"]:
            expected = surface_mapper.SurfaceMapper.relationships_for(reference, asset_id)
            assert [r["id"] for r in index.get(asset_id, [])] == [r["id"] for r in expected]

    def test_indexed_paths_match_unindexed_paths(self, pipeline):
        graph = json.load(open(os.path.join(pipeline["output_dir"], "surface_graph.json")))
        document = rg.build_report_document(graph=graph, output_dir=pipeline["output_dir"])

        plain = surface_mapper.SurfaceMapper(
            target=TARGET, output_dir=pipeline["output_dir"],
            autosave=False, load_existing=False)
        plain.state = graph
        assert document["attack_surface_paths"]["entries"]
        for entry in document["attack_surface_paths"]["entries"]:
            expected = plain.explain_asset_path(entry["asset_id"], max_hops=25)
            assert [hop["asset_id"] for hop in entry["hops"]] == \
                   [hop["asset_id"] for hop in expected]

    def test_source_state_is_never_mutated(self, pipeline):
        graph = json.load(open(os.path.join(pipeline["output_dir"], "surface_graph.json")))
        before = json.dumps(graph, sort_keys=True)
        assessment = json.load(open(os.path.join(pipeline["output_dir"], "risk_assessment.json")))
        assessment_before = json.dumps(assessment, sort_keys=True)
        execution_before = json.dumps(pipeline["execution"], sort_keys=True)
        rg.build_report_document(graph=graph, assessment=assessment,
                                 execution=pipeline["execution"],
                                 output_dir=pipeline["output_dir"])
        assert json.dumps(graph, sort_keys=True) == before
        assert json.dumps(assessment, sort_keys=True) == assessment_before
        assert json.dumps(pipeline["execution"], sort_keys=True) == execution_before

    def test_building_a_report_writes_nothing(self, pipeline):
        before = sorted(os.listdir(pipeline["output_dir"]))
        rg.build_report_document(output_dir=pipeline["output_dir"])
        assert sorted(os.listdir(pipeline["output_dir"])) == before


# ===========================================================================
# Intelligence is never promoted to confirmation
# ===========================================================================

class TestEvidenceClasses:
    def test_the_four_classes_are_kept_distinct(self, pipeline):
        document = rg.build_report_document(output_dir=pipeline["output_dir"])
        counts = document["findings"]["counts_by_evidence_class"]
        assert set(counts) <= risk_engine.VALID_KINDS
        assert counts.get(risk_engine.KIND_CONFIRMED, 0) > 0
        assert counts.get(risk_engine.KIND_VULN_INTEL, 0) > 0

    def test_a_cve_match_is_never_labelled_confirmed(self, pipeline):
        document = rg.build_report_document(output_dir=pipeline["output_dir"])
        for entry in document["vulnerability_intelligence"]["entries"]:
            assert entry["kind"] == risk_engine.KIND_VULN_INTEL
            assert entry["confirmed"] is False
            assert entry["kind_label"] == "Vulnerability intelligence (possible match)"

    def test_html_states_that_cve_matches_are_unverified(self, pipeline):
        document = rg.build_report_document(output_dir=pipeline["output_dir"])
        text = audit(rg.render_html_report(document)).plain_text
        assert "never proof that the target is affected or exploitable" in text
        assert "did not attempt to verify, reproduce or exploit" in text

    def test_html_never_claims_exploitability(self, pipeline):
        document = rg.build_report_document(output_dir=pipeline["output_dir"])
        text = audit(rg.render_html_report(document)).plain_text.lower()
        # Phrases that could only ever be a claim, never a disclaimer.
        for phrase in ("confirmed vulnerable", "successfully exploited", "is vulnerable to",
                       "proven exploitable", "exploitation succeeded", "verified exploit"):
            assert phrase not in text, f"report claims {phrase!r}"
        # ...and the disclaimers that must always be present.
        assert "not proof that anything listed here is exploitable" in text
        assert "reconnaissance only" in text

    def test_indicators_are_marked_unverified(self, outdir):
        mapper = graph_with(outdir, [
            finding("dns_record", value={"record_type": "A", "records": ["203.0.113.1"]},
                    source="passive_recon.py"),
            finding("secret_indicator", value={"indicator_type": "api_key", "url": "http://example.com/a.js"},
                    evidence=["pattern matched"], confidence="LOW", source="js_analyzer.py"),
        ])
        assessment = risk_engine.run_risk_engine(graph=mapper, output_dir=outdir, persist=False)
        document = rg.build_report_document(graph=mapper, assessment=assessment, output_dir=outdir)
        kinds = {e["kind"] for e in document["findings"]["entries"]}
        assert risk_engine.KIND_CONFIRMED not in kinds or risk_engine.KIND_INDICATOR in kinds
        for entry in document["findings"]["entries"]:
            if entry["kind"] == risk_engine.KIND_INDICATOR:
                assert "unverified" in entry["kind_label"].lower()


# ===========================================================================
# Robustness
# ===========================================================================

class TestRobustness:
    def test_empty_graph_produces_a_complete_report(self, outdir):
        os.makedirs(outdir, exist_ok=True)
        mapper = surface_mapper.SurfaceMapper(target=TARGET, output_dir=outdir)
        mapper.save()
        result = rg.generate_report(output_dir=outdir)
        document = json.load(open(result["output_paths"]["json"]))
        assert document["asset_inventory"]["total"] == 0
        assert document["executive_summary"]["assets"] == 0
        markup = open(result["output_paths"]["html"], encoding="utf-8").read()
        parsed = audit(markup)
        assert parsed.errors == []
        assert "No assets were correlated into the graph." in parsed.plain_text

    def test_malformed_containers_degrade_one_section_only(self, outdir):
        mapper = graph_with(outdir, [finding("dns_record", value={"record_type": "A", "records": ["203.0.113.1"]})])
        state = dict(mapper.state)
        state["conflicts"] = "not a dict"
        state["negative_results"] = 17
        state["relationships"] = []
        document = rg.build_report_document(graph=state, output_dir=outdir)
        assert document["asset_inventory"]["total"] > 0
        assert document["conflicts"]["entries"] == []
        assert document["relationships"]["total"] == 0

    def test_malformed_individual_records_do_not_destroy_the_report(self, outdir):
        mapper = graph_with(outdir, [finding("dns_record", value={"record_type": "A", "records": ["203.0.113.1"]})])
        state = dict(mapper.state)
        state["assets"] = dict(state["assets"])
        state["assets"]["broken:1"] = "not an asset record"
        state["assets"]["broken:2"] = {"asset_type": None, "value": object()}
        state["observations"] = dict(state["observations"])
        state["observations"]["broken"] = ["not", "an", "observation"]
        document = rg.build_report_document(graph=state, output_dir=outdir)
        assert document["asset_inventory"]["total"] >= 1
        markup = rg.render_html_report(document)
        assert audit(markup).errors == []

    def test_unknown_severity_is_never_downgraded_to_info(self, outdir):
        mapper = graph_with(outdir, [finding("dns_record", value={"record_type": "A", "records": ["203.0.113.1"]})])
        assessment = {
            "target": TARGET,
            "summary": {"assets_assessed": 1, "signals": 1, "queue_length": 1,
                        "assets_by_severity": {"WEIRD": 1}, "signals_by_severity": {"WEIRD": 1}},
            "signals": [{"signal_id": "signal:x", "category": "c", "kind": "made_up_kind",
                         "severity": "SUPER-BAD", "confidence": "PROBABLY", "summary": "odd",
                         "subject_asset_id": "hostname:example.com", "sources": ["x.py"],
                         "evidence": ["e"], "observation_ids": [], "conflicts": []}],
            "assessed_assets": [{"asset_id": "hostname:example.com", "severity": "SUPER-BAD"}],
            "investigation_queue": [{"rank": 1, "asset_id": "hostname:example.com",
                                     "severity": "SUPER-BAD", "confidence": "PROBABLY",
                                     "value": "example.com", "explanation": ["because"]}],
        }
        document = rg.build_report_document(graph=mapper, assessment=assessment, output_dir=outdir)
        entry = document["findings"]["entries"][0]
        assert entry["severity"] == rg.UNKNOWN
        assert entry["confidence"] == rg.UNKNOWN
        assert entry["kind_label"] == rg.UNKNOWN
        assert document["severity"]["assets_by_severity"][rg.UNKNOWN] == 1
        assert document["severity"]["assets_by_severity"]["INFO"] == 0
        # The raw value the source reported is preserved, not thrown away.
        assert entry["severity_reported"] == "SUPER-BAD"
        assert document["investigation_queue"]["entries"][0]["severity_reported"] == "SUPER-BAD"
        text = audit(rg.render_html_report(document)).plain_text
        assert "UNKNOWN (SUPER-BAD)" in text

    def test_conflicting_observations_are_preserved_with_both_values(self, outdir):
        mapper = graph_with(outdir, [
            finding("open_port", value={"ip": "203.0.113.1", "port": 22, "protocol": "tcp"},
                    source="active_recon.py"),
            finding("service_identification",
                    value={"ip": "203.0.113.1", "port": 22, "service": "OpenSSH_8.4"},
                    source="active_recon.py"),
            finding("service_identification",
                    value={"ip": "203.0.113.1", "port": 22, "service": "Dropbear_2020"},
                    source="passive_intel.py", timestamp="2026-08-01T00:00:01+00:00"),
        ])
        document = rg.build_report_document(graph=mapper, output_dir=outdir)
        conflicts = document["conflicts"]["entries"]
        assert conflicts, "no conflict was recorded by the graph"
        values = {o["display"] for c in conflicts for o in c["observations"]}
        assert "OpenSSH_8.4" in values and "Dropbear_2020" in values
        assert all(c["status"] == "unresolved" for c in conflicts)
        text = audit(rg.render_html_report(document)).plain_text
        assert "OpenSSH_8.4" in text and "Dropbear_2020" in text
        assert any("Contradictions between modules are preserved" in t for t in [text])

    def test_negative_results_are_reported_not_dropped(self, outdir):
        mapper = graph_with(outdir, [
            finding("dns_record", value={"record_type": "A", "records": ["203.0.113.1"]},
                    source="passive_recon.py"),
            finding("tech_fingerprint_checked_no_match", value={"category": "cms"},
                    evidence=["no signature matched"], source="tech_fingerprint.py"),
        ])
        document = rg.build_report_document(graph=mapper, output_dir=outdir)
        assert document["negative_results"]["total"] >= 1
        entry = document["negative_results"]["entries"][0]
        assert entry["check"] == "tech_fingerprint_checked_no_match"
        assert entry["state"] == "checked, not found"
        text = audit(rg.render_html_report(document)).plain_text
        assert "coverage is not mistaken for absence of evidence" in text

    def test_repeated_generation_is_stable_and_overwrites_in_place(self, pipeline):
        first = rg.generate_report(output_dir=pipeline["output_dir"])
        second = rg.generate_report(output_dir=pipeline["output_dir"])
        assert first["output_paths"] == second["output_paths"]
        assert len(os.listdir(os.path.dirname(first["output_paths"]["html"]))) == len(rg.VALID_FORMATS)
        # No temp file survives a completed write.
        assert not [n for n in os.listdir(os.path.dirname(first["output_paths"]["html"]))
                    if n.startswith(".report_")]
        a = json.load(open(first["output_paths"]["json"]))
        b = json.load(open(second["output_paths"]["json"]))
        a.pop("generated_at"), b.pop("generated_at")
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)

    def test_existing_report_directory_is_reused(self, pipeline):
        reports = os.path.join(pipeline["output_dir"], "reports")
        os.makedirs(reports, exist_ok=True)
        with open(os.path.join(reports, "keep.txt"), "w") as handle:
            handle.write("existing")
        rg.generate_report(output_dir=pipeline["output_dir"])
        assert os.path.isfile(os.path.join(reports, "keep.txt"))

    def test_large_result_sets_are_bounded_and_say_so(self, outdir):
        findings = [finding("endpoint", value={"url": f"http://example.com/p{i}"},
                            timestamp=f"2026-08-01T00:00:{i % 60:02d}+00:00")
                    for i in range(400)]
        mapper = graph_with(outdir, findings)
        document = rg.build_report_document(
            graph=mapper, output_dir=outdir, limits={"max_assets_per_type": 25})
        endpoints = document["endpoints"]
        assert endpoints["truncated"] is True
        assert endpoints["shown"] == 25
        assert endpoints["total"] >= 400
        assert endpoints["omitted"] == endpoints["total"] - 25
        assert any("bounded for readability" in text for text in document["limitations"])
        text = audit(rg.render_html_report(document)).plain_text
        assert "further record(s) are omitted here" in text

    def test_interrupted_run_is_reported_as_incomplete(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, interrupt_at="crawler")
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        document = rg.build_report_document(output_dir=outdir, execution=result)
        assert document["scan"]["run_status"] == orch.RUN_INTERRUPTED
        assert any("interrupted" in text.lower() for text in document["limitations"])

    def test_deeply_nested_values_do_not_exhaust_the_stack(self, outdir):
        deep = current = {}
        for _ in range(600):
            current["next"] = {}
            current = current["next"]
        current["leaf"] = "bottom"
        mapper = graph_with(outdir, [
            finding("dns_record", value={"record_type": "A", "records": ["203.0.113.1"]}),
        ])
        state = dict(mapper.state)
        state["assets"] = dict(state["assets"])
        asset_id = next(iter(state["assets"]))
        state["assets"][asset_id] = dict(state["assets"][asset_id])
        state["assets"][asset_id]["value"] = deep
        document = rg.build_report_document(graph=state, output_dir=outdir)
        assert document["asset_inventory"]["total"] >= 1
        assert audit(rg.render_html_report(document)).errors == []

    def test_display_value_is_depth_bounded(self):
        deep = current = {}
        for _ in range(50):
            current["n"] = {}
            current = current["n"]
        assert rg.display_value(deep).endswith("…")

    def test_a_failing_section_costs_only_that_section(self, monkeypatch, pipeline):
        monkeypatch.setattr(rg.ReportBuilder, "_build_technologies",
                            lambda self: (_ for _ in ()).throw(RuntimeError("section bug")))
        document = rg.build_report_document(output_dir=pipeline["output_dir"])
        assert document["technologies"]["entries"] == []
        assert any("section bug" in _e.get("error", "") for _e in document["errors"])
        assert document["asset_inventory"]["total"] > 0
        assert any("could not be rendered" in text for text in document["limitations"])
        assert audit(rg.render_html_report(document)).errors == []


# ===========================================================================
# Security — target-controlled content can never become markup
# ===========================================================================

class TestHtmlSafety:
    @pytest.fixture
    def hostile(self, outdir):
        mapper = graph_with(outdir, [
            finding("dns_record", value={"record_type": "A", "records": ["203.0.113.9"]},
                    evidence=[XSS], source="passive_recon.py"),
            finding("open_port", value={"ip": "203.0.113.9", "port": 8080, "protocol": "tcp"},
                    evidence=[ATTR], source=XSS),
            finding("service_identification",
                    value={"ip": "203.0.113.9", "port": 8080, "service": XSS, "banner": ATTR},
                    evidence=[URI], source="active_recon.py"),
            finding("service_identification",
                    value={"ip": "203.0.113.9", "port": 8080, "service": XSS,
                           "banner": '<img src=x onerror=alert(1)>'},
                    evidence=[XSS], source="passive_intel.py"),
            finding("tech_detected",
                    value={"url": "http://example.com/", "technology": XSS,
                           "version": ATTR, "category": URI},
                    evidence=[XSS], source="tech_fingerprint.py"),
            finding("endpoint", value={"url": "http://example.com/" + ATTR},
                    evidence=[XSS], source="crawler.py"),
            finding("tech_fingerprint_checked_no_match", value={"category": XSS},
                    evidence=[ATTR], source="tech_fingerprint.py"),
        ])
        assessment = risk_engine.run_risk_engine(graph=mapper, output_dir=outdir, persist=False)
        execution = {
            "target": TARGET, "mode": XSS, "status": XSS,
            "started_at": XSS, "finished_at": XSS, "interrupted": False,
            "modules_selected": [XSS], "executions_by_status": {XSS: 1},
            "executions": [{"module": XSS, "phase": ATTR, "subject": URI,
                            "status": "failed", "error": XSS, "error_type": ATTR,
                            "observations_ingested": 0}],
            "errors": [{"stage": XSS, "error": ATTR}],
            "scope": {"in_scope_hostnames": [XSS], "out_of_scope_hostnames_observed": [ATTR]},
            "adaptive": {"rounds": 1, "actions": 0, "deferred": [],
                         "manual_review": [{"opportunity_type": XSS, "target_value": ATTR,
                                            "priority": URI, "reason": XSS}]},
            "settings": {"output_dir": outdir, "timeout": XSS},
        }
        return rg.build_report_document(graph=mapper, assessment=assessment,
                                        execution=execution, output_dir=outdir)

    def test_no_script_element_and_no_event_handlers(self, hostile):
        parsed = audit(rg.render_html_report(hostile))
        assert parsed.scripts == 0
        assert parsed.errors == []

    def test_injected_markup_survives_only_as_text(self, hostile):
        markup = rg.render_html_report(hostile)
        parsed = audit(markup)
        assert "<script>alert" not in markup
        assert "<img src=x onerror" not in markup
        # ...but the operator still sees exactly what the target served.
        assert XSS in parsed.plain_text
        assert ATTR in parsed.plain_text
        assert URI in parsed.plain_text

    def test_the_document_loads_no_external_resource(self, hostile):
        parsed = audit(rg.render_html_report(hostile))
        assert parsed.external == []

    def test_a_restrictive_content_security_policy_is_declared(self, hostile):
        markup = rg.render_html_report(hostile)
        assert "Content-Security-Policy" in markup
        assert "default-src 'none'" in markup

    def test_the_title_is_escaped(self, outdir):
        mapper = graph_with(outdir, [finding("dns_record", target=TARGET,
                                             value={"record_type": "A", "records": ["203.0.113.1"]})])
        document = rg.build_report_document(graph=mapper, output_dir=outdir)
        document["title"] = XSS
        markup = rg.render_html_report(document)
        assert "<title>&lt;script&gt;" in markup

    def test_escaping_helper_covers_attribute_context(self):
        assert rg._e('" onmouseover="x') == "&quot; onmouseover=&quot;x"
        assert rg._e("<b>&</b>") == "&lt;b&gt;&amp;&lt;/b&gt;"
        assert rg._e("it's") == "it&#x27;s"

    def test_module_built_markup_is_not_double_escaped(self):
        chip = rg.HtmlReportRenderer.severity_chip("CRITICAL")
        assert isinstance(chip, rg._Markup)
        assert rg._e(chip) == str(chip)

    def test_redacted_secrets_are_rendered_as_stored(self, outdir):
        """The producing module redacts; this module must not widen it."""
        redacted = "AKIA…«ab**cd»…XYZ"
        mapper = graph_with(outdir, [
            finding("dns_record", value={"record_type": "A", "records": ["203.0.113.1"]},
                    source="passive_recon.py"),
            finding("leaked_credential",
                    value={"secret_type": "aws_key", "redacted_value": redacted,
                           "repository": "acme/www", "file_path": "config.py"},
                    evidence=[f"matched value (redacted): {redacted}"],
                    confidence="MEDIUM", source="code_leak.py"),
        ])
        document = rg.build_report_document(graph=mapper, output_dir=outdir)
        text = audit(rg.render_html_report(document)).plain_text
        assert redacted in text
        assert "**" in text  # the mask itself is preserved verbatim


# ===========================================================================
# Output files
# ===========================================================================

class TestOutputs:
    def test_all_formats_are_written_under_output_reports(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"])
        assert sorted(result["output_paths"]) == ["html", "json", "text"]
        assert result["output_paths"]["text"].endswith("reconhound_report.txt")
        for path in result["output_paths"].values():
            assert os.path.isfile(path)
            assert os.path.dirname(path) == os.path.abspath(
                os.path.join(pipeline["output_dir"], "reports"))

    def test_json_report_is_valid_and_complete(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"])
        document = json.load(open(result["output_paths"]["json"]))
        for key in ("module", "report_schema_version", "target", "generated_at",
                    "executive_summary", "scan", "severity", "investigation_queue",
                    "findings", "vulnerability_intelligence", "asset_inventory",
                    "technologies", "services", "endpoints", "javascript", "supply_chain",
                    "relationships", "attack_surface_paths", "conflicts", "negative_results",
                    "execution", "observations", "source_artifacts", "warnings",
                    "limitations", "errors", "notes"):
            assert key in document, f"{key} missing from the JSON report"
        assert document["module"] == "report_generator.py"

    def test_html_report_is_well_formed_and_self_contained(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"])
        markup = open(result["output_paths"]["html"], encoding="utf-8").read()
        parsed = audit(markup)
        assert parsed.errors == []
        assert parsed.scripts == 0
        assert parsed.external == []
        assert markup.startswith("<!doctype html>")
        assert "</html>" in markup

    def test_html_and_json_agree(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"])
        document = json.load(open(result["output_paths"]["json"]))
        text = audit(open(result["output_paths"]["html"], encoding="utf-8").read()).plain_text
        summary = document["executive_summary"]
        assert f"{summary['assets']} asset(s) were correlated" in text
        for entry in document["investigation_queue"]["entries"][:5]:
            assert entry["label"] in text

    def test_html_carries_the_reconhound_identity(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"])
        markup = open(result["output_paths"]["html"], encoding="utf-8").read()
        text = audit(markup).plain_text
        assert "ReconHound" in text
        assert TARGET in text
        assert "authorized targets only" in text

    def test_single_format_can_be_requested(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"], formats=["json"])
        assert list(result["output_paths"]) == ["json"]
        assert not os.path.exists(
            os.path.join(pipeline["output_dir"], "reports", "reconhound_report.html"))

    def test_persist_false_writes_nothing_and_returns_the_document(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"], persist=False)
        assert result["output_paths"] == {}
        assert result["document"]["module"] == "report_generator.py"
        assert not os.path.exists(os.path.join(pipeline["output_dir"], "reports"))

    def test_custom_filename_stem(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"], filename_stem="acme-2026")
        assert os.path.basename(result["output_paths"]["html"]) == "acme-2026.html"

    @pytest.mark.parametrize("stem", ["../escape", "sub/dir", "..", "/abs"])
    def test_filename_stem_cannot_escape_the_report_directory(self, pipeline, stem):
        with pytest.raises(rg.ReportError):
            rg.generate_report(output_dir=pipeline["output_dir"], filename_stem=stem)

    def test_unknown_format_is_rejected(self, pipeline):
        with pytest.raises(rg.ReportError):
            rg.generate_report(output_dir=pipeline["output_dir"], formats=["pdf"])
        with pytest.raises(rg.ReportError):
            rg.generate_report(output_dir=pipeline["output_dir"], formats=[])

    def test_a_failing_format_never_returns_a_path(self, monkeypatch, pipeline):
        monkeypatch.setattr(rg, "render_html_report",
                            lambda document: (_ for _ in ()).throw(RuntimeError("render bug")))
        result = rg.generate_report(output_dir=pipeline["output_dir"])
        assert "html" not in result["output_paths"]
        assert "json" in result["output_paths"]
        assert any("render bug" in str(e) for e in result["errors"])

    def test_every_reported_path_exists(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"])
        for path in result["output_paths"].values():
            assert os.path.isfile(path)
        for path in json.load(open(result["output_paths"]["json"]))["source_artifacts"].values():
            assert path is None or os.path.isfile(path)

    def test_result_document_is_json_safe(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"])
        json.dumps(result)

    def test_standalone_entry_point_writes_a_report(self, pipeline, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv",
                            ["report_generator.py", "--output-dir", pipeline["output_dir"]])
        rg._main()
        printed = json.loads(capsys.readouterr().out)
        assert printed["target"] == TARGET
        assert os.path.isfile(printed["output_paths"]["html"])


# ===========================================================================
# Hardening pass (2026-09-11): sanitization, redaction, bounds, validation,
# ordering, the terminal report, interrupt safety and contract stability.
#
# Every test below reproduces a defect that existed before the pass or
# attacks one of its fixes.
# ===========================================================================

import copy
import hashlib
import io
import re
import subprocess
import time

# Anything a terminal could act on, plus the invisible Unicode format
# characters that hide or reorder text.
RAW_CONTROL = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f\x80-\x9f​-‏ -‮⁠-⁤⁦-⁯﻿]")
ANSI_ESC = re.compile("\x1b\\[")

HOSTILE = (
    "\x1b]8;;http://evil.example/\x07click here\x1b]8;;\x07 "      # OSC 8 hyperlink
    "\x1b]52;c;SGVsbG8=\x07 "                                      # OSC 52 clipboard
    "\x1b[2J\x1b[H\x1b[31m "                                       # CSI clear/home/colour
    "\x1bP dcs \x1b\\ \x1b_ apc \x1b\\ \x1b^ pm \x1b\\ \x1bX sos \x1b\\ "  # DCS/APC/PM/SOS
    "\x9b31m \x9d0;t\x9c "                                         # 8-bit CSI / OSC (C1)
    "\x00 nul \x08 bs \x7f del "                                   # C0 / DEL
    "‮REVERSED‬ ​zero-width ﻿bom "              # bidi + invisible
    "\r\n[CRIT][HIGH CONF] fake finding"                            # line fabrication
)

SECRETS = {
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
           "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "password": "Sup3rS3cretPassw0rd!",
    "github": "ghp_" + "Q" * 36,
    "bearer": "ZXhhbXBsZS1iZWFyZXItdG9rZW4tdmFsdWU",
    "url_pw": "hunter22pw",
    "pem": "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn",
}
SECRET_TEXT = (
    f"GET /?api_key={SECRETS['aws']} ; Authorization: Bearer {SECRETS['bearer']} ; "
    f"password={SECRETS['password']} ; token {SECRETS['github']} ; jwt {SECRETS['jwt']} ; "
    f"postgres://admin:{SECRETS['url_pw']}@db.internal:5432/app ; "
    f"-----BEGIN RSA PRIVATE KEY-----\n{SECRETS['pem']}\n-----END RSA PRIVATE KEY-----"
)


def walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_strings(item)


def file_hash(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


@pytest.fixture
def state(pipeline):
    """The three state documents of a real (fake-network) run, as dicts."""
    out = pipeline["output_dir"]
    return {
        "output_dir": out,
        "graph": json.load(open(os.path.join(out, "surface_graph.json"))),
        "assessment": json.load(open(os.path.join(out, "risk_assessment.json"))),
        "execution": json.load(open(os.path.join(out, "orchestrator_run.json"))),
    }


def build_from(state, **overrides):
    kwargs = {"graph": state["graph"], "assessment": state["assessment"],
              "execution": state["execution"], "output_dir": state["output_dir"]}
    kwargs.update(overrides)
    return rg.build_report_document(**kwargs)


def first_signal(assessment):
    return assessment["signals"][0]


class TestSanitizationAtModelEntry:
    """Target-controlled bytes are neutralized when they enter the document."""

    def test_sanitize_text_neutralizes_every_class_of_attack(self):
        cleaned, count = rg.sanitize_text(HOSTILE)
        assert not RAW_CONTROL.search(cleaned)
        assert count > 20
        # Nothing hidden: every neutralized character is shown as an escape.
        assert "\\x1b]52;c;" in cleaned and "\\u202e" in cleaned and "\\x00" in cleaned
        assert "\\x9b" in cleaned and "\\x7f" in cleaned and "\\ufeff" in cleaned
        # TAB and LF are legitimate in multi-line evidence and are kept.
        assert rg.sanitize_text("a\tb\nc") == ("a\tb\nc", 0)
        assert rg.sanitize_text("") == ("", 0)

    @pytest.fixture
    def hostile_state(self, state):
        graph = copy.deepcopy(state["graph"])
        assessment = copy.deepcopy(state["assessment"])
        execution = copy.deepcopy(state["execution"])
        graph["target"] = HOSTILE + TARGET
        for asset in graph["assets"].values():
            if isinstance(asset.get("value"), str):
                asset["value"] = HOSTILE + asset["value"]
            for attribute in (asset.get("attributes") or {}).values():
                attribute["value"] = HOSTILE
        for signal in assessment["signals"]:
            signal["summary"] = HOSTILE + signal["summary"]
            signal["evidence"] = [HOSTILE]
            signal["rationale"] = [HOSTILE]
            signal["detail"] = {HOSTILE: HOSTILE}
            signal["provenance"] = [{"source": HOSTILE, "observation_id": HOSTILE,
                                     "confidence": HOSTILE, "timestamp": HOSTILE}]
            signal["category"] = HOSTILE
            signal["severity"] = HOSTILE
        for entry in assessment["investigation_queue"]:
            entry["explanation"] = [HOSTILE]
            entry["value"] = HOSTILE
        execution["status"] = HOSTILE
        execution["errors"] = [{"stage": HOSTILE, "error": HOSTILE}]
        for record in execution["executions"]:
            record["module"] = HOSTILE
            record["error"] = HOSTILE
            record["status"] = "failed"
        return {"output_dir": state["output_dir"], "graph": graph,
                "assessment": assessment, "execution": execution}

    def test_no_raw_control_character_survives_into_the_json_model(self, hostile_state):
        document = build_from(hostile_state)
        # The data model itself, not just its serialization: a downstream
        # consumer decoding the JSON gets the same strings.
        round_tripped = json.loads(json.dumps(document))
        offenders = [s for s in walk_strings(round_tripped) if RAW_CONTROL.search(s)]
        assert offenders == []
        assert document["sanitization"]["control_characters_neutralized"] > 100
        assert any("control" in line for line in document["limitations"])

    def test_no_control_character_reaches_any_renderer(self, hostile_state):
        document = build_from(hostile_state)
        text = rg.render_text_report(document, width=100)
        assert not RAW_CONTROL.search(text) and not ANSI_ESC.search(text)
        html_out = rg.render_html_report(document)
        assert not RAW_CONTROL.search(html_out)
        assert "\\x1b]52;c;" in text, "the attack is visible, not hidden"

    def test_target_text_cannot_fabricate_a_finding_heading(self, hostile_state):
        document = build_from(hostile_state)
        for width in (40, 100):
            text = rg.render_text_report(document, width=width)
            fakes = [line for line in text.split("\n") if line.startswith("[CRIT][HIGH CONF] fake")]
            assert fakes == [], "a wrapped continuation started a line with a badge"

    def test_hostile_target_is_sanitized_in_the_title(self, outdir):
        mapper = graph_with(outdir, [finding("dns_record", value={"record_type": "A", "records": ["203.0.113.9"]},
                                             source="passive_recon.py")])
        state = mapper.state
        state["target"] = "exa\x1b[31mmple.com"
        document = rg.build_report_document(graph=state, assessment=None, execution=None, output_dir=outdir)
        assert "\x1b" not in document["title"] and "\\x1b[31m" in document["title"]

    def test_lone_surrogates_cannot_make_the_report_unwritable(self, state, tmp_path):
        # Legal in JSON text, unencodable in UTF-8: without sanitization the
        # text and HTML files fail to write and the terminal print raises.
        assessment = copy.deepcopy(state["assessment"])
        lone_surrogate = json.loads('"\\ud800"')
        first_signal(assessment)["summary"] = lone_surrogate + first_signal(assessment)["summary"]
        first_signal(assessment)["evidence"] = [f"X-Header: {lone_surrogate}value"]
        result = rg.generate_report(graph=state["graph"], assessment=assessment,
                                    execution=state["execution"], output_dir=str(tmp_path))
        assert result["errors"] == [] and sorted(result["output_paths"]) == ["html", "json", "text"]
        text = open(result["output_paths"]["text"], encoding="utf-8").read()
        assert "\\ud800" in text

    def test_out_of_range_timestamps_do_not_crash_the_terminal_renderer(self, state):
        assessment = copy.deepcopy(state["assessment"])
        first_signal(assessment)["last_seen"] = "9999-12-31T23:59:59-05:00"
        document = build_from(state, assessment=assessment)
        text = rg.render_text_report(document, width=100)
        assert "9999-12-31T23:59:59-05:00" in text

    def test_sanitized_dict_keys_never_collide_silently(self):
        stats = rg._empty_hardening_stats()
        out = rg._harden({"\x1b": 1, "\\x1b": 2}, dict(rg.DEFAULT_LIMITS), stats)
        assert sorted(out) == ["\\x1b", "\\x1b (2)"]
        assert sorted(out.values()) == [1, 2]


class TestRedaction:
    def test_recognised_credential_shapes_are_masked(self):
        masked, count = rg.redact_sensitive_text(SECRET_TEXT)
        for name, secret in SECRETS.items():
            assert secret not in masked, f"{name} leaked"
        assert count >= 7
        assert "-----BEGIN PRIVATE KEY----- <redacted>" in masked

    def test_intelligence_values_stay_readable(self):
        for text in ("auth_method=bearer", "keyword=recon", "signature_algorithm=sha256WithRSA",
                     "Bearer token expired", "token expired", "key=abc", "public_key=ssh-rsa AAAAB3",
                     "csrf_token=present", "api_key=missing", "X-Frame-Options=DENY",
                     "Set-Cookie: sessionid=; Path=/", "hostname:auth.example.com",
                     "signal:leaked_credential_in_public_code:49eaa0b3a5dd076a9d96"):
            assert rg.redact_sensitive_text(text) == (text, 0), text

    def test_redaction_cost_is_linear_in_the_input(self):
        # `a.b`*1000 and `a-`*1500 made the first version of the assignment
        # pattern quadratic (0.9 s per 3 KB string).
        for text in ("a.b" * 1000, "a-" * 1500, "://" * 1000, "a:b@" * 750, "x" * 3000):
            started = time.perf_counter()
            rg.redact_sensitive_text(text)
            assert time.perf_counter() - started < 0.1, text[:8]

    def test_secrets_never_reach_json_html_or_text(self, state):
        assessment = copy.deepcopy(state["assessment"])
        signal = first_signal(assessment)
        signal["evidence"] = [SECRET_TEXT]
        signal["summary"] = f"leak {SECRETS['aws']}"
        signal["detail"] = {"header": f"Authorization: Bearer {SECRETS['bearer']}"}
        document = build_from(state, assessment=assessment)
        serialized = json.dumps(document)
        html_out = rg.render_html_report(document)
        text = rg.render_text_report(document, width=100)
        for name, secret in SECRETS.items():
            for where, blob in (("json", serialized), ("html", html_out), ("text", text)):
                assert secret not in blob, f"{name} leaked into {where}"
        assert document["sanitization"]["secrets_redacted"] >= 7
        assert any("credential-shaped" in line for line in document["limitations"])

    def test_a_secret_straddling_the_text_bound_is_still_masked(self, state):
        assessment = copy.deepcopy(state["assessment"])
        limit = rg.DEFAULT_LIMITS["max_text_chars"]
        first_signal(assessment)["evidence"] = ["x" * (limit - 10) + f" api_key={SECRETS['aws']} tail"]
        document = build_from(state, assessment=assessment)
        assert SECRETS["aws"] not in json.dumps(document)


class TestBoundedOutput:
    def test_a_ten_megabyte_evidence_line_is_bounded_with_a_visible_marker(self, state):
        assessment = copy.deepcopy(state["assessment"])
        signal = first_signal(assessment)
        signal["evidence"] = ["A" * 10_000_000]
        document = build_from(state, assessment=assessment)
        serialized = json.dumps(document)
        assert len(serialized) < 2_000_000
        entry = next(e for e in document["findings"]["entries"] if e["signal_id"] == signal["signal_id"])
        line = entry["evidence"][0]
        assert line.startswith("A" * 100)
        assert re.search(r"\[truncated: 9\d{6} more character\(s\) omitted\]$", line)
        assert document["sanitization"]["strings_truncated"] >= 1
        assert not any(len(s) > rg.DEFAULT_LIMITS["max_text_chars"] + 100 for s in walk_strings(document))

    def test_a_giant_attribute_collection_is_bounded_with_a_visible_marker(self, state):
        graph = copy.deepcopy(state["graph"])
        asset = next(iter(graph["assets"].values()))
        asset.setdefault("attributes", {})["txt_records"] = {
            "value": ["x" * 100] * 200_000, "source": "passive_recon.py", "confidence": "HIGH"}
        started = time.perf_counter()
        document = build_from(state, graph=graph)
        assert time.perf_counter() - started < 5
        assert len(json.dumps(document)) < 2_000_000
        assert document["sanitization"]["collections_truncated"] >= 1
        markers = [s for s in walk_strings(document) if s.startswith("<truncated:")]
        assert any("more item(s) omitted" in m for m in markers)

    def test_pending_opportunities_and_manual_review_are_bounded(self, state):
        execution = copy.deepcopy(state["execution"])
        execution.setdefault("opportunities", {})["pending"] = [{"id": f"o{i}"} for i in range(50_000)]
        execution.setdefault("adaptive", {})["manual_review"] = [{"id": f"m{i}"} for i in range(50_000)]
        document = build_from(state, execution=execution)
        section = document["execution"]
        assert len(section["pending_opportunities"]) == rg.DEFAULT_LIMITS["max_pending_opportunities"]
        assert section["pending_opportunities_truncation"] == {
            "shown": 200, "total": 50_000, "truncated": True, "omitted": 49_800}
        assert len(section["adaptive"]["manual_review"]) == rg.DEFAULT_LIMITS["max_manual_review"]
        assert section["adaptive"]["manual_review_truncation"]["truncated"] is True

    def test_collection_bound_never_undercuts_a_section_bound(self, state):
        document = build_from(state, limits={"max_findings": 900, "max_collection_items": 5})
        assert document["limits"]["max_collection_items"] >= 900
        assert document["limits"]["max_findings"] == 900
        assert not [s for s in document["findings"]["entries"] if isinstance(s, str)]

    def test_unknown_limit_is_warned_not_ignored_silently(self, state):
        document = build_from(state, limits={"max_findingz": 1})
        assert any("max_findingz" in w for w in document["warnings"])

    def test_text_bound_floor(self, state):
        document = build_from(state, limits={"max_text_chars": 0})
        assert document["limits"]["max_text_chars"] == 64
        assert document["target"] == TARGET


class TestFindingValidation:
    def test_a_signal_with_no_evidence_and_no_trace_is_marked_incomplete(self, state):
        assessment = copy.deepcopy(state["assessment"])
        signal = first_signal(assessment)
        signal["evidence"], signal["provenance"], signal["observation_ids"] = [], [], []
        document = build_from(state, assessment=assessment)
        entry = next(e for e in document["findings"]["entries"] if e["signal_id"] == signal["signal_id"])
        assert entry["evidence_status"] == rg.EVIDENCE_INCOMPLETE
        assert entry["evidence_from"] == "none"
        assert document["findings"]["incomplete_evidence"] == 1
        text = rg.render_text_report(document, width=100)
        assert "[INCOMPLETE_EVIDENCE]" in text
        assert rg.EVIDENCE_INCOMPLETE in rg.render_html_report(document)

    def test_evidence_less_signals_show_their_observations_evidence(self, state):
        # risk_engine leaves `evidence` empty on technology observations; the
        # cited graph observation holds the evidence, and that is shown.
        document = build_from(state)
        from_observations = [e for e in document["findings"]["entries"]
                             if e["evidence_from"] == "observation_records"]
        assert from_observations, "the fixture run has evidence-less technology observations"
        for entry in from_observations:
            assert entry["evidence"] and all("[observation " in line for line in entry["evidence"])
            assert entry["evidence_status"] == rg.EVIDENCE_SUPPORTED
        assert document["findings"]["incomplete_evidence"] == 0

    def test_nothing_is_invented_for_an_observation_without_evidence(self, state):
        graph = copy.deepcopy(state["graph"])
        assessment = copy.deepcopy(state["assessment"])
        signal = first_signal(assessment)
        signal["evidence"] = []
        for observation_id in signal["observation_ids"]:
            graph["observations"][observation_id]["evidence"] = []
        document = build_from(state, graph=graph, assessment=assessment)
        entry = next(e for e in document["findings"]["entries"] if e["signal_id"] == signal["signal_id"])
        assert entry["evidence"] == [] and entry["evidence_status"] == rg.EVIDENCE_INCOMPLETE

    def test_malformed_signal_records_are_excluded_and_counted(self, state):
        assessment = copy.deepcopy(state["assessment"])
        total = len(assessment["signals"])
        assessment["signals"].extend(["garbage", 42, None, ["x"], {"summary": "no id"}])
        document = build_from(state, assessment=assessment)
        assert document["findings"]["malformed_excluded"] == 5
        assert document["findings"]["total"] == total
        assert len([e for e in document["errors"] if "malformed signal" in e["error"]]) == 5
        assert "malformed" in rg.render_text_report(document, width=100)

    def test_duplicate_signals_are_rendered_once(self, state):
        assessment = copy.deepcopy(state["assessment"])
        assessment["signals"].append(copy.deepcopy(first_signal(assessment)))
        document = build_from(state, assessment=assessment)
        ids = [e["signal_id"] for e in document["findings"]["entries"]]
        assert len(ids) == len(set(ids))
        assert document["findings"]["duplicates_excluded"] == 1
        vuln_ids = [e["signal_id"] for e in document["vulnerability_intelligence"]["entries"]]
        assert len(vuln_ids) == len(set(vuln_ids))

    def test_duplicate_and_malformed_queue_entries_are_excluded(self, state):
        assessment = copy.deepcopy(state["assessment"])
        assessment["investigation_queue"].append(copy.deepcopy(assessment["investigation_queue"][0]))
        assessment["investigation_queue"].append("junk")
        document = build_from(state, assessment=assessment)
        queue = document["investigation_queue"]
        asset_ids = [e["asset_id"] for e in queue["entries"]]
        assert len(asset_ids) == len(set(asset_ids))
        assert queue["duplicates_excluded"] == 1 and queue["malformed_excluded"] == 1

    def test_queue_is_shown_in_rank_order_whatever_the_file_order(self, state):
        assessment = copy.deepcopy(state["assessment"])
        assessment["investigation_queue"].reverse()
        document = build_from(state, assessment=assessment)
        ranks = [e["rank"] for e in document["investigation_queue"]["entries"]]
        assert ranks == sorted(ranks)


class TestMalformedGraphRecords:
    def test_cyclic_and_malformed_assets_never_break_the_report_and_are_counted(self, state):
        graph = copy.deepcopy(state["graph"])
        asset_id = next(iter(graph["assets"]))
        cyclic = {"a": 1}
        cyclic["self"] = cyclic
        graph["assets"][asset_id]["value"] = cyclic
        graph["assets"]["bad1"] = None
        graph["assets"]["bad2"] = {"asset_type": None, "value": [1, 2, {"x": None}]}
        graph["relationships"]["r1"] = "junk"
        graph["relationships"]["r2"] = {"from_asset": "bad2", "to_asset": "bad2", "rel_type": None}
        started = time.perf_counter()
        document = build_from(state, graph=graph)
        assert time.perf_counter() - started < 5
        assert document["asset_inventory"]["malformed_excluded"] == 1
        assert document["relationships"]["malformed_excluded"] == 1
        assert any("malformed asset" in e["error"] for e in document["errors"])
        assert any("malformed relationship" in e["error"] for e in document["errors"])
        rg.render_text_report(document, width=60)
        rg.render_html_report(document)


class TestDeterministicOrdering:
    def test_findings_follow_the_documented_order(self, state):
        document = build_from(state)
        entries = document["findings"]["entries"]
        keys = [(-rg.severity_sort_key(e["severity"]),
                 -risk_engine.confidence_rank(e["confidence"]),
                 (e["subject"] or {}).get("label", ""), e["signal_id"]) for e in entries]
        assert keys == sorted(keys)
        assert document["findings"]["ordering"].startswith("severity desc, confidence desc, affected asset asc")

    def test_asset_breaks_ties_before_signal_id(self, state):
        assessment = copy.deepcopy(state["assessment"])
        base = first_signal(assessment)
        clones = []
        for index, label in enumerate(("zzz.example.com", "aaa.example.com")):
            clone = copy.deepcopy(base)
            clone["signal_id"] = f"signal:test:{index}"
            clone["subject_asset_id"] = f"hostname:{label}"
            clones.append(clone)
        assessment["signals"] = clones
        graph = copy.deepcopy(state["graph"])
        for label in ("zzz.example.com", "aaa.example.com"):
            graph["assets"][f"hostname:{label}"] = {"asset_type": "hostname", "value": label}
        document = build_from(state, graph=graph, assessment=assessment)
        labels = [e["subject"]["label"] for e in document["findings"]["entries"]]
        assert labels == ["aaa.example.com", "zzz.example.com"]

    def test_output_is_byte_identical_across_hash_seeds(self, pipeline):
        script = (
            "import json,sys; from reconhound import report_generator as rg; "
            "d = rg.build_report_document(output_dir=sys.argv[1], generated_at='2026-09-11T00:00:00+00:00'); "
            "sys.stdout.write(json.dumps(d, sort_keys=True)); sys.stdout.write(chr(0)); "
            "sys.stdout.write(rg.render_text_report(d, width=100))")
        outputs = []
        for seed in ("0", "1", "12345"):
            env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONIOENCODING="utf-8")
            result = subprocess.run([sys.executable, "-c", script, pipeline["output_dir"]],
                                    capture_output=True, env=env,
                                    cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            assert result.returncode == 0, result.stderr.decode()
            outputs.append(result.stdout)
        assert outputs[0] == outputs[1] == outputs[2]
        assert b"\x00" in outputs[0] and len(outputs[0]) > 10_000


class TestTerminalReport:
    def test_badges_carry_severity_and_confidence_as_text(self, state):
        text = rg.render_text_report(build_from(state), width=100)
        assert "ReconHound Assessment Summary" in text
        assert re.search(r"\[(CRIT|HIGH|MED|LOW|INFO)\]\[(HIGH|MED|LOW) CONF\]", text)
        for badge in ("[CRIT]", "[HIGH]", "[MED]", "[LOW]", "[INFO]"):
            assert badge in text
        # Every finding heading shows severity and confidence together.
        headings = [line for line in text.split("\n")
                    if re.match(r"^\[(CRIT|HIGH|MED|LOW|INFO|UNKN)\]", line)
                    and any(k in line for k in ("[CONFIRMED]", "[INDICATOR]", "[CVE MATCH]", "[OBSERVED]"))]
        assert headings and all(" CONF]" in line for line in headings)

    def test_each_finding_shows_asset_modules_evidence_provenance_and_date(self, state):
        text = rg.render_text_report(build_from(state), width=100)
        for label in ("Asset:", "Category:", "Modules:", "Confidence:", "Discovered:",
                      "Evidence:", "Provenance:", "Why this severity:"):
            assert label in text
        assert re.search(r"Discovered:\s+\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z", text)

    def test_every_bound_is_stated(self, state):
        document = build_from(state)
        text = rg.render_text_report(document, width=100, limits={"terminal_max_findings": 5,
                                                                   "terminal_max_queue_entries": 2})
        total = document["findings"]["total"]
        assert f"Showing 5 of {total} findings; {total - 5} more in the JSON report." in text
        assert "Showing 2 of" in text
        full = rg.render_text_report(document, width=100)
        assert f"Showing {total} of {total} findings." in full

    @pytest.mark.parametrize("width", [20, 40, 80, 120, 200])
    def test_renders_at_every_width_without_overflow_or_escapes(self, state, width):
        text = rg.render_text_report(build_from(state), width=width)
        lines = text.split("\n")
        assert lines and not any(len(line) > width for line in lines)
        assert not ANSI_ESC.search(text) and not RAW_CONTROL.search(text)
        assert "Assessment" in text and "Findings" in text

    def test_all_sections_are_present(self, state):
        text = rg.render_text_report(build_from(state), width=100)
        for title in ("Investigation queue", "Findings", "Vulnerability intelligence",
                      "Attack-surface paths", "Technology stack", "Services and ports",
                      "Endpoints", "JavaScript assets", "Supply chain", "Conflicting observations",
                      "Negative results", "Execution", "Warnings, limitations"):
            assert title in text, title

    def test_absent_assessment_is_stated_not_faked(self, outdir):
        mapper = graph_with(outdir, [finding("dns_record", value={"record_type": "A", "records": ["203.0.113.9"]},
                                             source="passive_recon.py")])
        document = rg.build_report_document(graph=mapper, assessment=None, execution=None, output_dir=outdir)
        text = rg.render_text_report(document, width=80)
        assert "not available" in text and rg.NO_ASSESSMENT in text
        assert "[CRIT] Critical" not in text

    def test_colour_policy(self, monkeypatch):
        tty = io.StringIO()
        tty.isatty = lambda: True
        assert rg.terminal_color_allowed(tty, {"TERM": "xterm"}) is True
        assert rg.terminal_color_allowed(tty, {"TERM": "xterm", "NO_COLOR": "1"}) is False
        assert rg.terminal_color_allowed(tty, {"TERM": "dumb"}) is False
        assert rg.terminal_color_allowed(tty, {"TERM": "xterm", "CI": "true"}) is False
        assert rg.terminal_color_allowed(io.StringIO(), {"TERM": "xterm"}) is False
        assert rg.terminal_color_allowed(io.StringIO(), {"TERM": "xterm", "FORCE_COLOR": "1"}) is True
        assert rg.terminal_color_allowed(io.StringIO(), {"FORCE_COLOR": "1", "NO_COLOR": "1"}) is False

    @pytest.mark.parametrize("env", [{"NO_COLOR": "1"}, {"TERM": "dumb"}, {"CI": "true"}, {}])
    def test_no_ansi_leaks_into_a_pipe_or_under_no_colour(self, pipeline, env):
        base = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "TERM", "CI", "FORCE_COLOR")}
        base["TERM"] = "xterm-256color"
        base.update(env)
        result = subprocess.run(
            [sys.executable, "-m", "reconhound.report_generator", "--output-dir",
             pipeline["output_dir"], "--terminal"],
            capture_output=True, env=base,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        out = result.stdout.decode("utf-8")
        assert result.returncode == 0, result.stderr.decode()
        assert not ANSI_ESC.search(out) and "\x1b" not in out
        assert "ReconHound Assessment Summary" in out

    def test_colour_is_emitted_on_a_real_tty(self, pipeline):
        pty = pytest.importorskip("pty")
        master, slave = pty.openpty()
        env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "CI")}
        env.update({"TERM": "xterm-256color", "COLUMNS": "100"})
        process = subprocess.Popen(
            [sys.executable, "-m", "reconhound.report_generator", "--output-dir",
             pipeline["output_dir"], "--terminal"],
            stdout=slave, stderr=slave, env=env,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        os.close(slave)
        data = b""
        while True:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            data += chunk
        process.wait()
        os.close(master)
        assert b"\x1b[" in data
        assert b"[CRIT]" in data or b"[HIGH]" in data, "badges are text even with colour"

    def test_text_file_output_is_plain(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"])
        text = open(result["output_paths"]["text"], encoding="utf-8").read()
        assert not ANSI_ESC.search(text) and not RAW_CONTROL.search(text)
        assert "ReconHound Assessment Summary" in text
        assert not any(len(line) > rg.TERMINAL_DEFAULT_WIDTH for line in text.split("\n"))

    def test_standalone_terminal_entry_point(self, pipeline, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["report_generator.py", "--output-dir",
                                          pipeline["output_dir"], "--terminal", "--width", "80",
                                          "--no-color"])
        rg._main()
        out = capsys.readouterr().out
        assert "ReconHound Assessment Summary" in out and "\x1b" not in out
        assert not os.path.exists(os.path.join(pipeline["output_dir"], "reports", "reconhound_report.txt")), \
            "--terminal prints; it does not write"

    def test_terminal_renderer_survives_marker_strings_in_entry_lists(self, state):
        document = build_from(state)
        document["findings"]["entries"].append("<truncated: 3 more item(s) omitted>")
        document["investigation_queue"]["entries"].append("<truncated: 1 more item(s) omitted>")
        text = rg.render_text_report(document, width=100)
        assert "(no summary recorded)" not in text

    def test_rendering_a_large_report_is_fast(self, state):
        assessment = copy.deepcopy(state["assessment"])
        base = first_signal(assessment)
        assessment["signals"] = []
        for index in range(2000):
            clone = copy.deepcopy(base)
            clone["signal_id"] = f"signal:test:{index:05d}"
            assessment["signals"].append(clone)
        started = time.perf_counter()
        document = build_from(state, assessment=assessment)
        text = rg.render_text_report(document, width=100)
        assert time.perf_counter() - started < 10
        assert document["findings"]["total"] == 2000 and document["findings"]["shown"] == 400
        # The statement distinguishes what the JSON report holds (400) from
        # what only risk_assessment.json holds (the other 1600).
        assert ("Showing 100 of 2000 findings; 300 more in the JSON report; 1600 more only in "
                "risk_assessment.json.") in text


class TestInterruptSafety:
    def test_an_interrupt_mid_write_leaves_the_previous_report_intact(self, pipeline, monkeypatch):
        first = rg.generate_report(output_dir=pipeline["output_dir"])
        before = {fmt: file_hash(path) for fmt, path in first["output_paths"].items()}
        reports_dir = os.path.dirname(first["output_paths"]["json"])

        real_fsync = os.fsync

        def interrupt(fd):
            raise KeyboardInterrupt

        monkeypatch.setattr(os, "fsync", interrupt)
        with pytest.raises(KeyboardInterrupt):
            rg.generate_report(output_dir=pipeline["output_dir"])
        monkeypatch.setattr(os, "fsync", real_fsync)
        after = {fmt: file_hash(path) for fmt, path in first["output_paths"].items()}
        assert after == before
        assert not [n for n in os.listdir(reports_dir) if n.startswith(".report_")], "temp file left behind"

    def test_a_write_failure_never_masks_itself_or_leaves_temp_files(self, pipeline, monkeypatch):
        def fail(fd):
            raise OSError(28, "No space left on device")
        monkeypatch.setattr(os, "fsync", fail)
        with pytest.raises(rg.PersistenceError) as excinfo:
            rg.generate_report(output_dir=pipeline["output_dir"])
        assert "No space left" in str(excinfo.value)
        reports_dir = os.path.join(pipeline["output_dir"], "reports")
        assert not [n for n in os.listdir(reports_dir) if n.startswith(".report_")]

    def test_the_rename_is_committed_to_the_directory(self, pipeline, monkeypatch):
        synced = []
        real_open = os.open

        def spy_open(path, flags, *args, **kwargs):
            if flags == os.O_RDONLY and os.path.isdir(path):
                synced.append(path)
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", spy_open)
        result = rg.generate_report(output_dir=pipeline["output_dir"], formats=["json"])
        assert os.path.dirname(result["output_paths"]["json"]) in synced


class TestContractStability:
    SCHEMA_1_0_TOP_LEVEL = {
        "asset_inventory", "attack_surface_paths", "conflicts", "endpoints", "errors", "execution",
        "executive_summary", "findings", "generated_at", "investigation_queue", "javascript",
        "limitations", "module", "negative_results", "notes", "observations", "relationships",
        "report_schema_version", "scan", "services", "severity", "source_artifacts", "supply_chain",
        "target", "technologies", "title", "vulnerability_intelligence", "warnings",
    }
    SCHEMA_1_0_FINDING = {
        "signal_id", "category", "kind", "kind_label", "severity", "severity_reported",
        "base_severity", "severity_basis", "confidence", "summary", "subject", "sources",
        "corroborating_sources", "evidence", "evidence_truncation", "provenance",
        "provenance_truncation", "observation_ids", "rationale", "notes", "factors", "detail",
        "confirmed", "suspended", "suspension_reason", "stale", "age_days", "conflicts", "last_seen",
    }

    def test_schema_1_0_keys_are_all_still_present(self, state):
        document = build_from(state)
        assert self.SCHEMA_1_0_TOP_LEVEL <= set(document)
        assert self.SCHEMA_1_0_FINDING <= set(document["findings"]["entries"][0])
        assert document["report_schema_version"] == "1.1"
        assert set(document["sanitization"]) == {
            "control_characters_neutralized", "secrets_redacted", "strings_truncated",
            "collections_truncated"}

    def test_generate_report_result_shape_is_unchanged_for_old_callers(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"], formats=["html", "json"])
        assert sorted(result["output_paths"]) == ["html", "json"]
        assert result["formats"] == ["html", "json"]
        for key in ("module", "report_schema_version", "target", "generated_at", "formats",
                    "output_paths", "reports_dir", "summary", "warnings", "limitations", "errors",
                    "persisted"):
            assert key in result

    def test_source_state_files_are_untouched_by_reporting(self, pipeline):
        out = pipeline["output_dir"]
        names = ("surface_graph.json", "risk_assessment.json", "orchestrator_run.json",
                 "pending_assets.json")
        before = {n: file_hash(os.path.join(out, n)) for n in names if os.path.exists(os.path.join(out, n))}
        rg.generate_report(output_dir=out)
        document = rg.build_report_document(output_dir=out)
        rg.render_text_report(document, width=60)
        after = {n: file_hash(os.path.join(out, n)) for n in before}
        assert after == before

    def test_the_json_report_is_valid_and_hardened(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"])
        document = json.load(open(result["output_paths"]["json"], encoding="utf-8"))
        assert "sanitization" in document and "limits" in document
        assert not [s for s in walk_strings(document) if RAW_CONTROL.search(s)]

    def test_no_phantom_findings_and_full_provenance(self, state):
        document = build_from(state)
        signal_ids = {s["signal_id"] for s in state["assessment"]["signals"]}
        for entry in document["findings"]["entries"]:
            assert entry["signal_id"] in signal_ids, "a finding not in the assessment"
            assert entry["sources"], "a finding without a producing module"
            assert entry["subject"] is not None
            if entry["evidence_status"] == rg.EVIDENCE_SUPPORTED:
                assert entry["evidence"] and (entry["provenance"] or entry["observation_ids"])


# ===========================================================================
# Conflict kinds in the report
#
# The 2026-09-12 whole-system audit found the report describing all seven of
# a real run's conflicts as "contradiction(s) between modules" when every one
# of them was a single module's own observation changing between runs — a
# bumped SOA serial, a refreshed WHOIS record, a rotated A record. The report
# must describe what actually happened.
# ===========================================================================


class TestConflictKindWording:
    def _temporal_graph(self, outdir):
        return graph_with(outdir, [
            finding("tech_fingerprint_detected",
                    value={"technology": "nginx", "category": "server", "version": "1.18.0",
                           "url": "https://example.com/"},
                    source="tech_fingerprint.py", timestamp="2026-07-01T00:00:00+00:00"),
            finding("tech_fingerprint_detected",
                    value={"technology": "nginx", "category": "server", "version": "1.20.1",
                           "url": "https://example.com/"},
                    source="tech_fingerprint.py", timestamp="2026-08-01T00:00:00+00:00"),
        ])

    def _cross_source_graph(self, outdir):
        return graph_with(outdir, [
            finding("tech_fingerprint_detected",
                    value={"technology": "nginx", "category": "server", "version": "1.18.0",
                           "url": "https://example.com/"},
                    source="tech_fingerprint.py", timestamp="2026-08-01T00:00:00+00:00"),
            finding("tech_fingerprint_detected",
                    value={"technology": "nginx", "category": "server", "version": "1.20.1",
                           "url": "https://example.com/"},
                    source="active_recon.py", timestamp="2026-08-01T00:01:00+00:00"),
        ])

    def test_a_temporal_conflict_is_not_called_a_contradiction_between_modules(self, outdir):
        document = rg.build_report_document(graph=self._temporal_graph(outdir), output_dir=outdir)
        assert document["conflicts"]["total"] == 1
        assert document["conflicts"]["temporal_total"] == 1
        assert document["conflicts"]["cross_source_total"] == 0
        headline = " ".join(document["executive_summary"]["headline"])
        assert "contradiction(s) between modules" not in headline
        assert "different times" in headline

    def test_a_cross_source_conflict_is_still_called_one(self, outdir):
        document = rg.build_report_document(graph=self._cross_source_graph(outdir), output_dir=outdir)
        assert document["conflicts"]["cross_source_total"] == 1
        assert document["conflicts"]["temporal_total"] == 0
        assert "contradiction(s) between modules" in " ".join(document["executive_summary"]["headline"])

    def test_every_conflict_entry_states_its_kind(self, outdir):
        document = rg.build_report_document(graph=self._temporal_graph(outdir), output_dir=outdir)
        entry = document["conflicts"]["entries"][0]
        assert entry["kind"] == risk_engine.CONFLICT_TEMPORAL
        assert "different times" in entry["kind_explanation"]
        # Both values are still shown; classification never drops evidence.
        assert {o["value"] for o in entry["observations"]} == {"1.18.0", "1.20.1"}

    def test_the_summary_counts_every_conflict_not_only_the_displayed_ones(self, outdir):
        records = []
        for i in range(6):
            for version, source in (("1.18.0", "tech_fingerprint.py"),
                                    ("1.20.1", "active_recon.py")):
                records.append(finding(
                    "tech_fingerprint_detected",
                    value={"technology": f"tech{i}", "category": "server", "version": version,
                           "url": "https://example.com/"},
                    source=source, timestamp="2026-08-01T00:00:00+00:00"))
        document = rg.build_report_document(
            graph=graph_with(outdir, records), output_dir=outdir,
            limits={"max_conflicts": 2})
        assert document["conflicts"]["truncated"] is True
        assert len(document["conflicts"]["entries"]) == 2
        assert document["conflicts"]["cross_source_total"] == 6

    def test_the_terminal_panel_reports_the_breakdown(self, outdir):
        document = rg.build_report_document(graph=self._temporal_graph(outdir), output_dir=outdir)
        text = rg.render_text_report(document)
        assert "changed between observations" in text
        assert "unresolved contradiction(s) between modules" not in text

    def test_a_pre_breakdown_document_still_renders_without_claiming_a_kind(self, outdir):
        # A JSON report written before the breakdown existed must not be
        # rendered as though every conflict were one kind or the other.
        document = rg.build_report_document(graph=self._temporal_graph(outdir), output_dir=outdir)
        document["executive_summary"].pop("unresolved_conflicts_cross_source", None)
        document["executive_summary"].pop("unresolved_conflicts_temporal", None)
        text = rg.render_text_report(document)
        assert "unresolved contradiction(s) between modules" not in text
        assert "1 unresolved" in text


class TestUnreachableOriginsAreReported:
    """
    An origin that answered nothing is a hole in coverage, not a clean
    result. The 2026-09-12 whole-system audit found a run in which half the
    web origins were never reached reporting "The run finished with status
    completed and no module failures" and nothing else.
    """

    def _execution_with_unreachable(self, origins):
        return {
            "module": "orchestrator.py", "target": TARGET, "status": "completed",
            "mode": "full-scan", "executions": [], "errors": [], "phases": [],
            "coverage": {"complete": False,
                         "unreachable_origins": [{"origin": o, "reported_as": "unreachable"}
                                                 for o in origins],
                         "budgets": {}},
        }

    def test_an_unreachable_origin_becomes_a_stated_limitation(self, outdir):
        graph = graph_with(outdir, [finding(
            "dns_record", value={"record_type": "A", "records": ["203.0.113.1"]})])
        document = rg.build_report_document(
            graph=graph, output_dir=outdir,
            execution=self._execution_with_unreachable(["http://example.com:8080"]))
        limitations = " ".join(document["limitations"])
        assert "http://example.com:8080" in limitations
        assert "absence of coverage, not absence" in limitations

    def test_an_unreachable_origin_is_not_counted_as_a_failed_module(self, outdir):
        graph = graph_with(outdir, [finding(
            "dns_record", value={"record_type": "A", "records": ["203.0.113.1"]})])
        document = rg.build_report_document(
            graph=graph, output_dir=outdir,
            execution=self._execution_with_unreachable(["http://example.com:8080"]))
        assert document["execution"]["failed_modules"] == []
        assert len(document["execution"]["unreachable_origins"]) == 1

    def test_a_run_with_no_unreachable_origin_states_no_such_limitation(self, outdir):
        graph = graph_with(outdir, [finding(
            "dns_record", value={"record_type": "A", "records": ["203.0.113.1"]})])
        document = rg.build_report_document(
            graph=graph, output_dir=outdir, execution=self._execution_with_unreachable([]))
        assert not any("answered no request" in line for line in document["limitations"])

    @pytest.mark.parametrize("coverage", [
        None, {}, "x", {"unreachable_origins": None}, {"unreachable_origins": "x"},
        {"unreachable_origins": [None, 3, {}, {"origin": ""}]},
    ])
    def test_a_malformed_coverage_block_never_breaks_the_report(self, outdir, coverage):
        graph = graph_with(outdir, [finding(
            "dns_record", value={"record_type": "A", "records": ["203.0.113.1"]})])
        execution = {"module": "orchestrator.py", "target": TARGET, "status": "completed",
                     "mode": "full-scan", "executions": [], "errors": [], "phases": [],
                     "coverage": coverage}
        document = rg.build_report_document(graph=graph, output_dir=outdir, execution=execution)
        assert document["execution"]["unreachable_origins"] == []

    def test_the_summary_panel_coverage_line_names_unreachable_origins(self, outdir):
        graph = graph_with(outdir, [finding(
            "dns_record", value={"record_type": "A", "records": ["203.0.113.1"]})])
        document = rg.build_report_document(
            graph=graph, output_dir=outdir,
            execution=self._execution_with_unreachable(["http://example.com:8080"]))
        text = rg.render_text_report(document)
        coverage = [l for l in text.splitlines() if "Coverage:" in l]
        assert coverage and "origin(s) never answered" in coverage[0], coverage
