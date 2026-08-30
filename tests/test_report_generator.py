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
        assert len(os.listdir(os.path.dirname(first["output_paths"]["html"]))) == 2
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
    def test_both_formats_are_written_under_output_reports(self, pipeline):
        result = rg.generate_report(output_dir=pipeline["output_dir"])
        assert sorted(result["output_paths"]) == ["html", "json"]
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
