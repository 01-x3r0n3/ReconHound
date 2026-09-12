"""
Tests for reconhound/reconhound.py (ReconHound Module 23 — the CLI entry
point).

Run with:  ./.venv/bin/python -m pytest tests/test_reconhound_cli.py -v

No network access anywhere in this file. The end-to-end tests reuse
tests/test_orchestrator.py's `install_fakes()`, which replaces every producer
module's entry point with a no-network fake that writes the real finding
shapes through the real stores — so the CLI is exercised against the real
Orchestrator, the real SurfaceMapper and the real RiskEngine.

The CLI's contract is presentation, argument mapping and exit status, so
that is what is asserted: never that a scan found something.
"""

import json
import re
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import reconhound as cli
from reconhound.core import orchestrator as orch

from test_orchestrator import install_fakes, Recorder  # noqa: E402  (shared fakes)

TARGET = "example.com"

# context.md §11 places the entry point at reconhound/reconhound.py.
CLI_SOURCE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reconhound", "reconhound.py")


@pytest.fixture
def rec():
    return Recorder()


@pytest.fixture
def outdir(tmp_path):
    return str(tmp_path / "output")


def run_cli(argv, monkeypatch=None):
    """Invoke main() and return its exit code."""
    return cli.main(argv)


# ===========================================================================
# Identity and architecture placement
# ===========================================================================


class TestIdentity:
    def test_lives_at_the_path_context_md_specifies(self):
        assert os.path.isfile(CLI_SOURCE_PATH)

    def test_declares_a_version(self):
        assert cli.__version__.split(".")[0] == "1"

    def test_version_flag_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["--version"])
        assert excinfo.value.code == 0
        assert "ReconHound" in capsys.readouterr().out

    def test_help_exits_zero_and_documents_the_contract(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["--help"])
        assert excinfo.value.code == 0
        out = capsys.readouterr().out
        for expected in ("--target", "--full-scan", "--passive-only", "--active-only",
                         "--module", "--output-dir", "--threads", "--timeout",
                         "exit codes"):
            assert expected in out

    def test_banner_is_pure_ascii(self):
        cli.BANNER.encode("ascii")

    def test_performs_no_reconnaissance_itself(self):
        """The CLI must not import scanning libraries or open sockets."""
        source = open(CLI_SOURCE_PATH, encoding="utf-8").read()
        for forbidden in ("import requests", "import socket", "import ssl",
                          "subprocess", "shell=True", "eval(", "exec("):
            assert forbidden not in source, f"{forbidden!r} has no place in the CLI"


# ===========================================================================
# Argument parsing and mapping onto the orchestrator contract
# ===========================================================================


def parse(argv):
    return cli.build_parser().parse_args(argv)


class TestArgumentMapping:
    def test_target_is_required(self):
        with pytest.raises(SystemExit) as excinfo:
            cli.build_parser().parse_args([])
        assert excinfo.value.code == 2

    def test_default_mode_is_full_scan(self):
        mode, modules = cli.resolve_execution(parse(["-t", TARGET]))
        assert mode == orch.MODE_FULL
        assert modules is None

    def test_explicit_modes(self):
        assert cli.resolve_execution(parse(["-t", TARGET, "--passive-only"]))[0] == orch.MODE_PASSIVE
        assert cli.resolve_execution(parse(["-t", TARGET, "--active-only"]))[0] == orch.MODE_ACTIVE
        assert cli.resolve_execution(parse(["-t", TARGET, "--full-scan"]))[0] == orch.MODE_FULL

    def test_modes_are_mutually_exclusive(self):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["-t", TARGET, "--passive-only", "--active-only"])

    def test_module_selection_switches_to_module_mode(self):
        mode, modules = cli.resolve_execution(parse(["-t", TARGET, "-m", "js_analyzer"]))
        assert mode == orch.MODE_MODULE
        assert modules == ["js_analyzer"]

    def test_module_is_repeatable_and_deduplicated(self):
        _, modules = cli.resolve_execution(
            parse(["-t", TARGET, "-m", "crawler", "-m", "js_analyzer", "-m", "crawler"]))
        assert modules == ["crawler", "js_analyzer"]

    def test_module_restricted_within_an_explicit_mode(self):
        mode, modules = cli.resolve_execution(
            parse(["-t", TARGET, "--passive-only", "-m", "code_leak"]))
        assert mode == orch.MODE_PASSIVE
        assert modules == ["code_leak"]

    def test_unknown_module_is_rejected_by_the_parser(self):
        with pytest.raises(SystemExit) as excinfo:
            cli.build_parser().parse_args(["-t", TARGET, "-m", "not_a_module"])
        assert excinfo.value.code == 2

    def test_removed_screenshot_module_is_rejected_by_the_parser(self):
        # screenshot.py was removed from the architecture; neither the module
        # name nor its former --no-screenshots flag may still be accepted.
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["-t", TARGET, "-m", "screenshot"])
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["-t", TARGET, "--no-screenshots"])

    def test_tuning_flags_reach_the_orchestrator(self):
        kwargs = cli.build_orchestrator_kwargs(parse([
            "-t", TARGET, "-o", "/tmp/x", "--threads", "3", "--timeout", "2.5",
            "--min-severity", "HIGH", "--wordlists-dir", "/tmp/wl", "--no-adaptive"]))
        assert kwargs["target"] == TARGET
        assert kwargs["output_dir"] == "/tmp/x"
        assert kwargs["threads"] == 3
        assert kwargs["timeout"] == 2.5
        assert kwargs["min_risk_severity"] == "HIGH"
        assert kwargs["wordlists_dir"] == "/tmp/wl"
        assert kwargs["max_adaptive_rounds"] == 0

    def test_unset_tuning_flags_leave_orchestrator_defaults_alone(self):
        kwargs = cli.build_orchestrator_kwargs(parse(["-t", TARGET]))
        for absent in ("threads", "timeout", "min_risk_severity", "max_adaptive_rounds"):
            assert absent not in kwargs

    def test_every_kwarg_is_accepted_by_the_orchestrator(self):
        import inspect
        accepted = set(inspect.signature(orch.Orchestrator.__init__).parameters)
        kwargs = cli.build_orchestrator_kwargs(parse([
            "-t", TARGET, "--threads", "2", "--timeout", "1", "--min-severity", "LOW",
            "--no-adaptive"]))
        assert set(kwargs) <= accepted

    def test_negative_top_is_rejected(self):
        with pytest.raises(cli.CliError) as excinfo:
            cli.build_orchestrator_kwargs(parse(["-t", TARGET, "--top", "-1"]))
        assert excinfo.value.exit_code == cli.EXIT_USAGE


# ===========================================================================
# Scope and input validation
# ===========================================================================


class TestScopeAndValidation:
    @pytest.mark.parametrize("bad", [
        "https://example.com/admin",   # URL, not a domain
        "203.0.113.10",                # raw IP
        "*.example.com",               # wildcard
        "not a domain",                # nonsense
    ])
    def test_invalid_targets_exit_two_without_a_traceback(self, bad, outdir, capsys):
        code = cli.main(["-t", bad, "-o", outdir, "--passive-only"])
        out = capsys.readouterr().out
        assert code == cli.EXIT_USAGE
        assert "Traceback" not in out

    def test_invalid_target_creates_no_output_directory(self, tmp_path, capsys):
        target_dir = str(tmp_path / "never")
        assert cli.main(["-t", "203.0.113.1", "-o", target_dir]) == cli.EXIT_USAGE
        capsys.readouterr()
        assert not os.path.exists(target_dir)

    def test_target_is_never_rewritten_into_another_target(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", "EXAMPLE.COM.", "-o", outdir, "--passive-only", "-q"]) == cli.EXIT_OK
        capsys.readouterr()
        record = json.load(open(os.path.join(outdir, "orchestrator_run.json")))
        # Normalized by passive_recon.validate_target, not expanded or replaced.
        assert record["target"] == "example.com"


# ===========================================================================
# Exit codes
# ===========================================================================


class TestExitCodes:
    @pytest.mark.parametrize("status,expected", [
        (orch.RUN_COMPLETED, cli.EXIT_OK),
        (orch.RUN_COMPLETED_WITH_ERRORS, cli.EXIT_PARTIAL),
        (orch.RUN_FAILED, cli.EXIT_FATAL),
        (orch.RUN_INTERRUPTED, cli.EXIT_INTERRUPTED),
    ])
    def test_run_status_maps_to_exit_code(self, status, expected):
        assert cli.exit_code_for({"status": status}) == expected

    def test_interrupted_flag_wins_over_status(self):
        assert cli.exit_code_for(
            {"status": orch.RUN_COMPLETED, "interrupted": True}) == cli.EXIT_INTERRUPTED

    def test_clean_run_exits_zero(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", TARGET, "-o", outdir]) == cli.EXIT_OK
        capsys.readouterr()

    def test_module_failure_exits_one(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec, failing={"code_leak"})
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_PARTIAL
        assert "code_leak" in out

    def test_nothing_found_is_not_a_failure(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec, empty=set(orch.ALL_MODULES))
        code = cli.main(["-t", TARGET, "-o", outdir])
        capsys.readouterr()
        assert code == cli.EXIT_OK

    def test_interrupted_run_exits_130_and_keeps_evidence(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec, interrupt_at="crawler")
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_INTERRUPTED
        assert "Traceback" not in out
        # Everything discovered before the interrupt survived.
        graph = json.load(open(os.path.join(outdir, "surface_graph.json")))
        assert graph["observations"]

    def test_fatal_orchestrator_error_exits_three(self, outdir, capsys):
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "pending_assets.json"), "w") as handle:
            handle.write("{ this is not json")
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_FATAL
        assert "Traceback" not in out
        # The panel wraps the message, so match on unwrapped fragments.
        assert "not valid JSON" in out

    def test_unexpected_failure_exits_three_without_a_traceback(self, monkeypatch, outdir, capsys):
        def boom(*args, **kwargs):
            raise ValueError("something unexpected")
        monkeypatch.setattr(orch, "Orchestrator", boom)
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_FATAL
        assert "Traceback" not in out
        assert "something unexpected" in out

    def test_debug_flag_shows_the_traceback(self, monkeypatch, outdir, capsys):
        def boom(*args, **kwargs):
            raise ValueError("something unexpected")
        monkeypatch.setattr(orch, "Orchestrator", boom)
        assert cli.main(["-t", TARGET, "-o", outdir, "--debug"]) == cli.EXIT_FATAL
        assert "ValueError" in capsys.readouterr().out


# ===========================================================================
# Truthful presentation
# ===========================================================================


class TestPresentation:
    def test_reports_the_real_module_outcomes(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec, failing={"code_leak"}, raising_scope={"js_analyzer"})
        cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert "FAILED" in out
        assert "code_leak" in out
        assert "out of scope" in out

    def test_never_reports_success_for_a_failed_module(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec, failing=set(orch.ALL_MODULES) - {"risk_engine"})
        cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert "Warnings and failures" in out
        # No module row may claim plain success when every producer exploded.
        execution_lines = [line for line in out.splitlines() if "exploded" in line]
        assert execution_lines

    def test_reports_only_paths_that_exist(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert "Output artifacts" in out
        for name in ("surface_graph.json", "risk_assessment.json",
                     "pending_assets.json", "orchestrator_run.json"):
            assert os.path.isfile(os.path.join(outdir, name)), f"{name} was advertised"

    def test_reports_are_generated_by_the_reporting_layer(
            self, monkeypatch, rec, outdir, capsys):
        """The CLI delegates to report_generator.py and shows only real paths."""
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", TARGET, "-o", outdir]) == cli.EXIT_OK
        out = capsys.readouterr().out
        assert "Report (HTML)" in out and "Report (JSON)" in out
        reports = os.path.join(outdir, "reports")
        assert os.path.isfile(os.path.join(reports, "reconhound_report.html"))
        assert os.path.isfile(os.path.join(reports, "reconhound_report.json"))

    def test_cli_contains_no_report_rendering_of_its_own(self):
        source = open(CLI_SOURCE_PATH, encoding="utf-8").read()
        for forbidden in ("<!doctype", "<html", "</table>", "text/css"):
            assert forbidden not in source.lower(), (
                f"{forbidden!r} means the CLI is rendering reports itself")

    def test_report_failure_is_warned_and_never_claims_a_path(
            self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        monkeypatch.setattr(
            cli.report_generator, "generate_report",
            lambda **kwargs: (_ for _ in ()).throw(
                cli.report_generator.ReportError("no report today")))
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_PARTIAL, "a run whose report failed must not exit 0"
        assert "Report generation failed" in out
        assert "no report today" in out
        assert "reconhound_report.html" not in out

    def test_reports_are_generated_after_an_interrupt_too(
            self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec, interrupt_at="crawler")
        assert cli.main(["-t", TARGET, "-o", outdir]) == cli.EXIT_INTERRUPTED
        capsys.readouterr()
        assert os.path.isfile(os.path.join(outdir, "reports", "reconhound_report.html"))

    def test_every_written_report_format_is_listed(self, monkeypatch, rec, outdir, capsys):
        """The artifact table lists what report_generator actually wrote, text included."""
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", TARGET, "-o", outdir]) == cli.EXIT_OK
        out = capsys.readouterr().out
        assert "Report (TEXT)" in out
        assert os.path.isfile(os.path.join(outdir, "reports", "reconhound_report.txt"))

    def test_interrupt_during_report_generation_is_handled(
            self, monkeypatch, rec, outdir, capsys):
        """Ctrl+C while the report is being written must not escape as a traceback."""
        install_fakes(monkeypatch, rec)

        def interrupt(**kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(cli.report_generator, "generate_report", interrupt)
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_INTERRUPTED
        assert "Report generation interrupted" in out
        assert "Traceback" not in out
        # The run's own artifacts were already persisted before reporting began.
        assert os.path.isfile(os.path.join(outdir, "surface_graph.json"))

    def test_risk_summary_matches_the_assessment_on_disk(self, monkeypatch, rec, outdir, capsys):
        """The terminal report carries the risk summary; the CLI's own risk panel is not repeated."""
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir, "--top", "5"])
        out = capsys.readouterr().out
        assessment = json.load(open(os.path.join(outdir, "risk_assessment.json")))
        summary = assessment["summary"]
        assert "ReconHound Assessment Summary" in out
        assert f"{summary['assets_assessed']} asset(s) were assessed" in out
        assert f"Queue:         {summary['queue_length']} asset(s) to investigate" in out
        badges = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]", "INFO": "[INFO]"}
        for entry in assessment["investigation_queue"][:5]:
            assert f"#{entry['rank']:<3d} {badges[entry['severity']]}" in out
        assert "Risk prioritization" not in out, "the old risk panel would duplicate the report"
        assert out.count("Investigation queue") == 1

    def test_skipped_risk_engine_is_not_reported_as_a_risk_result(
            self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir, "-m", "passive_recon"])
        out = capsys.readouterr().out
        assert "risk_engine was not part of this run" in out
        assert "Risk prioritization" not in out

    def test_quiet_suppresses_the_banner_but_keeps_the_summary(
            self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir, "-q"])
        out = capsys.readouterr().out
        assert "Correlated attack-surface discovery" not in out
        assert "Run result" in out

    def test_verbose_adds_the_decision_queue(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir, "-v"])
        out = capsys.readouterr().out
        assert "Decision queue" in out

    def test_default_output_omits_the_decision_queue(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir])
        assert "Decision queue" not in capsys.readouterr().out

    def test_does_not_dump_the_whole_report_to_the_terminal(
            self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        graph_size = os.path.getsize(os.path.join(outdir, "surface_graph.json"))
        assert len(out) < graph_size, "the terminal is a dashboard, not the report"

    def test_renders_without_colour(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", TARGET, "-o", outdir, "--no-color"]) == cli.EXIT_OK
        assert "\x1b[" not in capsys.readouterr().out

    def test_renders_on_an_ascii_only_terminal(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        monkeypatch.setattr(cli.Presenter, "_supports_unicode", staticmethod(lambda console: False))
        assert cli.main(["-t", TARGET, "-o", outdir]) == cli.EXIT_OK
        capsys.readouterr()

    @pytest.mark.parametrize("kwargs,argv", [
        ({}, []),
        ({"failing": {"code_leak", "ssl_analyzer"}}, []),
        ({"empty": set(orch.ALL_MODULES)}, []),
        ({"interrupt_at": "crawler"}, []),
        ({"raising_scope": {"js_analyzer"}}, ["-v"]),
        ({}, ["-m", "passive_recon"]),
    ])
    def test_every_summary_section_renders(self, kwargs, argv, monkeypatch, rec, outdir, capsys):
        """No run shape may push the summary onto its defensive fallback path."""
        install_fakes(monkeypatch, rec, **kwargs)
        cli.main(["-t", TARGET, "-o", outdir] + argv)
        out = capsys.readouterr().out
        assert "Could not render the full summary" not in out
        assert "Run result" in out
        assert "Output artifacts" in out

    def test_top_zero_prints_the_queue_size_not_an_empty_table(
            self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", TARGET, "-o", outdir, "--top", "0"]) == cli.EXIT_OK
        out = capsys.readouterr().out
        assert "top 0 of" not in out
        assert "#1   [" not in out, "--top 0 must not list queue entries"
        assert re.search(r"Showing 0 of \d+ queue entries; \d+ more in the JSON report", out)

    def test_risk_explanations_are_prose_not_python_reprs(
            self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir, "--top", "5"])
        out = capsys.readouterr().out
        assessment = json.load(open(os.path.join(outdir, "risk_assessment.json")))
        assert assessment["investigation_queue"][0]["explanation"], "fixture produced no rationale"
        assert "['" not in out and "']" not in out

    def test_a_rendering_failure_does_not_misreport_the_run(
            self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        monkeypatch.setattr(cli.Presenter, "_artifacts",
                            lambda self, result: (_ for _ in ()).throw(RuntimeError("render bug")))
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_OK
        assert "Could not render the full summary" in out

    def test_progress_callback_failure_never_breaks_a_run(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        monkeypatch.setattr(cli.LiveProgress, "_handle",
                            lambda self, event: (_ for _ in ()).throw(RuntimeError("ui bug")))
        assert cli.main(["-t", TARGET, "-o", outdir]) == cli.EXIT_OK
        capsys.readouterr()


# ===========================================================================
# Real-world execution conditions
# ===========================================================================


class TestRealWorldConditions:
    def test_creates_a_missing_output_directory(self, monkeypatch, rec, tmp_path, capsys):
        nested = str(tmp_path / "deep" / "nested" / "out")
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", TARGET, "-o", nested, "--passive-only"]) == cli.EXIT_OK
        capsys.readouterr()
        assert os.path.isfile(os.path.join(nested, "surface_graph.json"))

    def test_reuses_an_existing_output_directory(self, monkeypatch, rec, outdir, capsys):
        """Re-running against existing state is safe and never loses the graph."""
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", TARGET, "-o", outdir]) == cli.EXIT_OK
        first = json.load(open(os.path.join(outdir, "surface_graph.json")))
        assert cli.main(["-t", TARGET, "-o", outdir]) == cli.EXIT_OK
        capsys.readouterr()
        second = json.load(open(os.path.join(outdir, "surface_graph.json")))
        assert len(second["observations"]) >= len(first["observations"])
        assert not second["ingestion_errors"]
        assert set(first["assets"]) <= set(second["assets"])

    def test_malformed_graph_state_is_fatal_with_a_clear_message(self, outdir, capsys):
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "surface_graph.json"), "w") as handle:
            handle.write("not json at all")
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_FATAL
        assert "Traceback" not in out
        assert "--output-dir" in out or "output" in out

    def test_large_result_sets_stay_bounded(self, monkeypatch, rec, outdir, capsys):
        """The terminal report is bounded and says so; --top bounds only the queue."""
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir, "--top", "500"])
        out = capsys.readouterr().out
        assert "Run result" in out
        assessment = json.load(open(os.path.join(outdir, "risk_assessment.json")))
        total = len(assessment["signals"])
        assert out.count(f"Showing {total} of {total} findings.") == 1
        assert f"Showing {len(assessment['investigation_queue'])} of " in out
        assert len(out.splitlines()) < 3000

    def test_single_module_run(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", TARGET, "-o", outdir, "-m", "passive_recon"]) == cli.EXIT_OK
        capsys.readouterr()
        # passive_recon may run more than once: adaptive discovery can re-run
        # it against a newly learned hostname. Nothing else may run.
        assert set(rec.modules()) == {"passive_recon"}

    def test_passive_only_never_runs_an_active_module(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", TARGET, "-o", outdir, "--passive-only"]) == cli.EXIT_OK
        capsys.readouterr()
        for active in ("active_recon", "crawler", "endpoint_discovery", "supply_chain"):
            assert active not in rec.modules()


# ===========================================================================
# Terminal report in the normal CLI workflow (closure pass, 2026-09-11)
#
#   run completion -> report_generator's terminal report -> persisted artifacts
#
# The report is rendered from the very document report_generator wrote to
# disk; the CLI's own risk panel appears only when no report exists.
# ===========================================================================

import io
import subprocess

from reconhound import report_generator as rg  # noqa: E402
from reconhound import surface_mapper  # noqa: E402

RAW_CONTROL = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f\x80-\x9f​-‏ -‮⁠-⁤⁦-⁯﻿]")
HOSTILE = ("\x1b]8;;http://evil.example/\x07link\x1b]8;;\x07 \x1b]52;c;SGVsbG8=\x07 \x1b[2J\x1b[H "
           "\x1bP dcs \x1b\\ \x1b_ apc \x1b\\ \x9b31m \x00 ‮REVERSED‬ ​ "
           "api_key=AKIAIOSFODNN7EXAMPLE \r\n[CRIT][HIGH CONF] fake finding")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# A subprocess that runs the real CLI main() behind the shared network fakes,
# so TTY behaviour can be tested through a pty without any network access.
FAKED_CLI = f"""
import os, sys
sys.path.insert(0, {REPO_ROOT!r}); sys.path.insert(0, {os.path.join(REPO_ROOT, "tests")!r})
from test_orchestrator import install_fakes, Recorder
from reconhound import reconhound as cli
class MP:
    def setattr(self, obj, name=None, value=None, raising=True):
        if isinstance(obj, str):
            import importlib
            mod, attr = obj.rsplit(".", 1); obj = importlib.import_module(mod); name, value = attr, name
        setattr(obj, name, value)
    def setitem(self, d, k, v): d[k] = v
    def delenv(self, *a, **k): pass
    def setenv(self, k, v): os.environ[k] = v
install_fakes(MP(), Recorder())
sys.exit(cli.main(sys.argv[1:]))
"""


def run_faked_cli_on_pty(args, env_overrides):
    pty = pytest.importorskip("pty")
    master, slave = pty.openpty()
    env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "CI", "FORCE_COLOR")}
    env.update({"TERM": "xterm-256color", "COLUMNS": "100", "LINES": "50"})
    env.update(env_overrides)
    process = subprocess.Popen([sys.executable, "-c", FAKED_CLI, *args],
                               stdout=slave, stderr=slave, env=env, cwd=REPO_ROOT)
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
    code = process.wait()
    os.close(master)
    return code, data.decode("utf-8", errors="replace")


class TestTerminalReportInTheCli:
    def test_report_follows_the_run_and_precedes_the_artifacts(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", TARGET, "-o", outdir]) == cli.EXIT_OK
        out = capsys.readouterr().out
        run = out.index("Run result")
        report = out.index("ReconHound Assessment Summary")
        findings = out.index("Findings")
        artifacts = out.index("Output artifacts")
        assert run < report < findings < artifacts
        assert re.search(r"\[(CRIT|HIGH|MED|LOW|INFO)\]\[(HIGH|MED|LOW) CONF\]\[(CONFIRMED|INDICATOR|CVE MATCH|OBSERVED)\]", out)
        for label in ("Asset:", "Modules:", "Evidence:", "Provenance:", "Discovered:"):
            assert label in out

    def test_nothing_is_printed_twice(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert out.count("ReconHound Assessment Summary") == 1
        assert out.count("Investigation queue") == 1
        assert out.count("Output artifacts") == 1
        assert "Risk prioritization" not in out
        # The report's execution and source-artifact sections are omitted:
        # the CLI's module table and artifact table already show them.
        assert "Source artifacts" not in out
        # The report's own "──── Execution ────" rule is omitted (the CLI's
        # configuration panel is titled "Execution" too, hence the rule glyphs).
        assert not re.search(r"^[─-]{4} Execution [─-]+$", out, re.M), \
            "the report's execution section is omitted"
        # Every finding appears once: one "Signal:" line per distinct id.
        signals = re.findall(r"^\s+Signal:\s+(\S+)", out, re.M)
        assert signals and len(signals) == len(set(signals))

    def test_report_is_rendered_from_the_persisted_document(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        seen = {}
        real = rg.render_terminal_report

        def spy(document, *args, **kwargs):
            seen["document"] = document
            return real(document, *args, **kwargs)

        monkeypatch.setattr(cli.report_generator, "render_terminal_report", spy)
        cli.main(["-t", TARGET, "-o", outdir])
        capsys.readouterr()
        on_disk = json.load(open(os.path.join(outdir, "reports", "reconhound_report.json")))
        assert json.dumps(seen["document"], sort_keys=True) == json.dumps(on_disk, sort_keys=True)

    def test_report_generation_failure_falls_back_to_the_risk_panel(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        monkeypatch.setattr(
            cli.report_generator, "generate_report",
            lambda **kwargs: (_ for _ in ()).throw(cli.report_generator.ReportError("no report today")))
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_PARTIAL
        assert "Report generation failed" in out
        assert "ReconHound Assessment Summary" not in out
        assert "Risk prioritization" in out, "the CLI's own risk summary is the fallback"
        assert "not generated for this run" in out

    def test_report_rendering_failure_is_warned_and_never_misreports_the_run(
            self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)

        def boom(*args, **kwargs):
            raise RuntimeError("renderer exploded")

        monkeypatch.setattr(cli.report_generator, "render_terminal_report", boom)
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_OK, "the run and the report files succeeded"
        assert "Could not render the terminal report" in out and "renderer exploded" in out
        assert "Risk prioritization" in out
        assert os.path.isfile(os.path.join(outdir, "reports", "reconhound_report.txt"))
        assert "Report (TEXT)" in out

    def test_top_bounds_the_reports_queue(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir, "--top", "2"])
        out = capsys.readouterr().out
        assert "#1   [" in out and "#2   [" in out and "#3   [" not in out
        assert re.search(r"Showing 2 of \d+ queue entries; \d+ more in the JSON report", out)

    def test_quiet_still_prints_the_report(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir, "-q"])
        out = capsys.readouterr().out
        assert "ReconHound Assessment Summary" in out and "Findings" in out
        assert cli.BANNER.strip().splitlines()[0] not in out

    def test_run_without_risk_engine_says_why_no_findings(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", TARGET, "-o", outdir, "-m", "passive_recon"]) == cli.EXIT_OK
        out = capsys.readouterr().out
        assert "ReconHound Assessment Summary" in out
        assert rg.NO_ASSESSMENT in out
        assert "risk_engine was not part of this run" in out
        assert "[CRIT] Critical" not in out

    def test_failed_risk_engine_is_explained_next_to_the_report(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        monkeypatch.setattr(orch.risk_engine, "run_risk_engine",
                            lambda **kwargs: (_ for _ in ()).throw(RuntimeError("scoring exploded")))
        cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert "ReconHound Assessment Summary" in out
        assert "Risk assessment failed" in out
        assert "Risk prioritization" not in out

    def test_interrupted_run_still_gets_a_report(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec, interrupt_at="crawler")
        assert cli.main(["-t", TARGET, "-o", outdir]) == cli.EXIT_INTERRUPTED
        out = capsys.readouterr().out
        assert "ReconHound Assessment Summary" in out
        assert "INTERRUPTED" in out
        assert "interrupted before completion" in out

    def test_provider_failures_are_visible_in_the_report(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec, failing=("passive_intel", "exposure_scan"))
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_PARTIAL
        assert "module execution(s) failed" in out
        assert "absence of a finding is not evidence of absence" in out

    def test_malformed_module_output_does_not_break_the_report(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec, malformed=("passive_recon", "crawler"))
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code in (cli.EXIT_OK, cli.EXIT_PARTIAL)
        assert "ReconHound Assessment Summary" in out
        assert "Traceback" not in out

    def test_hostile_module_output_never_reaches_the_terminal_raw(self, monkeypatch, rec, outdir, capsys):
        """module output -> surface_mapper -> risk_engine -> report_generator -> CLI -> terminal."""
        install_fakes(monkeypatch, rec)
        real_ingest = surface_mapper.SurfaceMapper.ingest_finding

        def hostile_ingest(self, record, *args, **kwargs):
            if isinstance(record, dict):
                record = dict(record)
                record["evidence"] = list(record.get("evidence") or []) + [HOSTILE]
                metadata = dict(record.get("metadata") or {})
                metadata["hostile_header"] = HOSTILE
                metadata[HOSTILE] = "hostile key"
                record["metadata"] = metadata
                if record.get("type") == "endpoint" and isinstance(record.get("value"), dict):
                    value = dict(record["value"])
                    value["url"] = value.get("url", "") + "?next=" + HOSTILE
                    record["value"] = value
            return real_ingest(self, record, *args, **kwargs)

        monkeypatch.setattr(surface_mapper.SurfaceMapper, "ingest_finding", hostile_ingest)
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_OK
        assert not RAW_CONTROL.search(out), "a control character reached the terminal"
        assert "\\x1b]52;c;" in out, "the attack is shown, escaped"
        assert "AKIAIOSFODNN7EXAMPLE" not in out, "a credential reached the terminal"
        assert not [line for line in out.splitlines() if line.startswith("[CRIT][HIGH CONF] fake")]
        # The persisted JSON report is hardened identically.
        document = json.load(open(os.path.join(outdir, "reports", "reconhound_report.json")))
        assert document["sanitization"]["control_characters_neutralized"] > 0
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(document)
        # Useful evidence survives the hardening: the module's real evidence
        # line is still there, next to the escaped hostile one.
        assert "Server header [observation" in out
        assert "<script src> on" in out

    def test_colour_off_means_no_escape_sequence_at_all(self, monkeypatch):
        tty = io.StringIO()
        tty.isatty = lambda: True
        monkeypatch.setattr(cli.sys, "stdout", tty)
        monkeypatch.setenv("NO_COLOR", "1")
        console = cli.make_console(False)
        assert console.color_system is None
        console.print(cli.Text("bold", style="bold red"))
        assert "\x1b" not in tty.getvalue(), "no_color alone still emitted bold attributes"
        monkeypatch.delenv("NO_COLOR")
        monkeypatch.setenv("CI", "true")
        assert cli.make_console(False).color_system is None
        monkeypatch.delenv("CI")
        monkeypatch.setenv("TERM", "dumb")
        assert cli.make_console(False).color_system is None
        monkeypatch.setenv("TERM", "xterm")
        assert cli.make_console(True).color_system is None

    def test_tty_matrix(self, tmp_path):
        outdir = str(tmp_path / "tty")
        code, colour = run_faked_cli_on_pty(["-t", TARGET, "-o", outdir, "-q"], {})
        assert code == cli.EXIT_OK
        assert "\x1b[" in colour, "an interactive terminal gets colour"
        assert "[HIGH]" in colour or "[INFO]" in colour, "badges stay textual with colour on"
        for name, env in (("NO_COLOR", {"NO_COLOR": "1"}), ("TERM=dumb", {"TERM": "dumb"}),
                          ("CI", {"CI": "true"}), ("--no-color", {})):
            args = ["-t", TARGET, "-o", str(tmp_path / name.replace("=", "_")), "-q"]
            if name == "--no-color":
                args.append("--no-color")
            code, plain = run_faked_cli_on_pty(args, env)
            assert code == cli.EXIT_OK, name
            assert "\x1b" not in plain, f"{name}: an escape sequence leaked to the terminal"
            assert "ReconHound Assessment Summary" in plain, name

    def test_narrow_and_wide_terminals(self, tmp_path):
        for columns in ("40", "200"):
            outdir = str(tmp_path / columns)
            code, out = run_faked_cli_on_pty(["-t", TARGET, "-o", outdir, "-q", "--no-color"],
                                             {"COLUMNS": columns})
            assert code == cli.EXIT_OK
            width = int(columns)
            lines = [line.rstrip("\r") for line in out.replace("\r\n", "\n").split("\n")]
            assert not any(len(line) > width for line in lines), columns
            assert "Assessment" in out and "Findings" in out

    def test_a_format_that_could_not_be_written_is_warned_and_exits_partial(
            self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        monkeypatch.setattr(cli.report_generator, "render_html_report",
                            lambda document: (_ for _ in ()).throw(RuntimeError("html renderer died")))
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_PARTIAL, "an unwritten requested format is incomplete work"
        assert "Report format HTML could not be written" in out and "html renderer died" in out
        assert "ReconHound Assessment Summary" in out, "the other formats and the terminal report still happen"
        assert re.search(r"Report \(HTML\)\s+not written", out)
        assert os.path.isfile(os.path.join(outdir, "reports", "reconhound_report.txt"))
        assert not os.path.exists(os.path.join(outdir, "reports", "reconhound_report.html"))

    def test_disk_full_while_writing_every_format(self, monkeypatch, rec, outdir, capsys):
        import errno
        install_fakes(monkeypatch, rec)

        def enospc(self, filename, content):
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(cli.report_generator.ReportStore, "save_text", enospc)
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_PARTIAL
        assert "Report generation failed" in out and "No space left" in out
        assert "ReconHound Assessment Summary" not in out
        assert "Risk prioritization" in out
        assert not os.path.exists(os.path.join(outdir, "reports", "reconhound_report.json"))

    def test_unwritable_report_directory(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "reports"), "w") as handle:
            handle.write("not a directory")
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_PARTIAL
        assert "Report generation failed" in out and "Cannot create report directory" in out
        assert "Traceback" not in out

    def test_pathological_terminal_widths_still_produce_output(self, tmp_path):
        for columns in ("0", "5", "abc"):
            code, out = run_faked_cli_on_pty(["-t", TARGET, "-o", str(tmp_path / f"c{columns}"),
                                              "-q", "--no-color"], {"COLUMNS": columns})
            assert code == cli.EXIT_OK, columns
            assert "Assessment" in out and "Traceback" not in out, columns

    def test_findings_order_is_identical_across_hash_seeds(self, tmp_path):
        sequences = []
        for seed in ("0", "4242"):
            code, out = run_faked_cli_on_pty(
                ["-t", TARGET, "-o", str(tmp_path / seed), "-q", "--no-color"],
                {"PYTHONHASHSEED": seed, "COLUMNS": "120"})
            assert code == cli.EXIT_OK
            signals = re.findall(r"^\s+Signal:\s+(\S+)", out.replace("\r\n", "\n"), re.M)
            queue = re.findall(r"^#(\d+)\s+(\[[A-Z]+\]\[[A-Z ]+\]) (\S+)", out.replace("\r\n", "\n"), re.M)
            assert signals and queue
            sequences.append((signals, queue))
        assert sequences[0] == sequences[1]


# ===========================================================================
# CLI hardening pass (2026-09-11)
#
# Everything the CLI prints in its *own* panels (not the terminal report,
# which is rendered from report_generator's hardened document) must be safe
# against target-derived data, and no output failure may become a false run
# status or a traceback.
# ===========================================================================

import errno  # noqa: E402

from reconhound import crawler  # noqa: E402

# A payload covering every class the audit enumerated: Rich markup (open and
# an unmatched close), OSC 8 hyperlink, OSC 52 clipboard write, CSI clear,
# 8-bit CSI, DCS/APC strings, NUL, CR, bidi override, zero-width space, an
# emoji shortcode, and two credential shapes.
HOSTILE_TEXT = ("[bold red]INJECTED[/] [/bold] \x1b]8;;http://evil.example/\x07link\x1b]8;;\x07 "
                "\x1b]52;c;SGVsbG8=\x07 \x1b[2J\x1b[H \x9b31m \x1bP dcs \x1b\\ \x1b_ apc \x1b\\ "
                "\x00 \r\n[CRIT] fake \u202eREVERSED\u202c \u200b :skull: "
                "api_key=AKIAIOSFODNN7EXAMPLE token=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD")
# No whitespace: the orchestrator's subject gate rejects a URL containing
# any, so a path with spaces would never become a subject. Everything else
# here does — markup tags (one unmatched), OSC 8, CSI clear, bidi override,
# zero-width space, 8-bit CSI, an emoji shortcode.
HOSTILE_PATH = ("[bold]INJECTED[/bold][/red]\x1b]8;;http://evil.example/\x07x\x1b[2J"
                "\u202eREV\u202c\u200b\x9b31m:skull:")
FAKED_CLI_WITH_HOSTILE_MODULES = FAKED_CLI.replace(
    "sys.exit(cli.main(sys.argv[1:]))",
    """
from reconhound.core import orchestrator as orch
from reconhound import crawler
HOSTILE_TEXT = %r
HOSTILE_PATH = %r
real_crawler = orch.crawler.run_crawler
def hostile_crawler(url, target=None, output_dir="output", **kw):
    out = real_crawler(url, target=target, output_dir=output_dir, **kw)
    store = crawler.PendingAssetsStore(output_dir=output_dir)
    action = f"https://{target}/upload/{HOSTILE_PATH}"
    store.add(crawler.make_finding("crawled_form", target,
        {"action": action, "resolved_action": action, "method": "POST",
         "classification": "file_upload", "inputs": []},
        ["form with <input type=file>"], crawler.CONFIDENCE_HIGH,
        metadata={"source_page": url, "category": "file_upload"}))
    return out
orch.crawler.run_crawler = hostile_crawler
def hostile_js(js_files, target=None, output_dir="output", **kw):
    raise RuntimeError("fetch failed for " + HOSTILE_TEXT)
orch.js_analyzer.run_js_analyzer = hostile_js
sys.exit(cli.main(sys.argv[1:]))
""" % (HOSTILE_TEXT, HOSTILE_PATH))


def install_hostile_fakes(monkeypatch, rec, **kwargs):
    """
    The shared fakes plus two hostile producers: a crawler that discovers a
    file-upload form whose action URL carries HOSTILE_PATH (surface_mapper
    raises a file_upload_surface_review opportunity for it, so the URL
    becomes an adaptive *subject* — progress line, decision queue, failure
    panel) and a js_analyzer that fails with HOSTILE_TEXT in its message.
    """
    install_fakes(monkeypatch, rec, **kwargs)
    real_crawler = orch.crawler.run_crawler

    def hostile_crawler(url, target=None, output_dir="output", **kw):
        out = real_crawler(url, target=target, output_dir=output_dir, **kw)
        store = crawler.PendingAssetsStore(output_dir=output_dir)
        action = f"https://{target}/upload/{HOSTILE_PATH}"
        store.add(crawler.make_finding(
            "crawled_form", target,
            {"action": action, "resolved_action": action, "method": "POST",
             "classification": "file_upload", "inputs": []},
            ["form with <input type=file>"], crawler.CONFIDENCE_HIGH,
            metadata={"source_page": url, "category": "file_upload"}))
        return out

    def hostile_js(js_files, target=None, output_dir="output", **kw):
        raise RuntimeError("fetch failed for " + HOSTILE_TEXT)

    monkeypatch.setattr(orch.crawler, "run_crawler", hostile_crawler)
    monkeypatch.setattr(orch.js_analyzer, "run_js_analyzer", hostile_js)


def assert_terminal_safe(out):
    assert not RAW_CONTROL.search(out), "a control character reached the terminal"
    assert "\x1b" not in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out, "a credential reached the terminal"
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD" not in out
    assert "\U0001f480" not in out, ":skull: was rendered as an emoji"
    assert not [line for line in out.splitlines() if line.startswith("[CRIT] fake")], \
        "target text started a line of its own"


class TestTerminalSafetyOfTheCliPanels:
    def test_hostile_module_error_and_subject_never_reach_the_terminal_raw(
            self, monkeypatch, rec, outdir, capsys):
        """module exception / adaptive subject -> CLI failure panel, decision queue, progress lines."""
        install_hostile_fakes(monkeypatch, rec)
        code = cli.main(["-t", TARGET, "-o", outdir, "-v", "--no-color"])
        out = capsys.readouterr().out
        assert code == cli.EXIT_PARTIAL
        assert "Traceback" not in out
        assert_terminal_safe(out)
        # The adaptive round really ran against the hostile URL, so the
        # subject went through every CLI path (exposure_scan is the module
        # the mapper suggests for a file-upload surface).
        assert any(HOSTILE_PATH in str(subject) for subject in rec.subjects_for("exposure_scan")), \
            rec.subjects_for("exposure_scan")
        # Shown, escaped — the operator sees what the target sent. The CLI's
        # own progress line and failure panel cut long values, so the tags
        # are checked where they are cut and the escapes where the report
        # prints the value whole.
        assert re.search(r"exposure_scan\s+https://example\.com/upload/\[bold\]INJEC", out), \
            "the hostile subject's progress line is missing or was interpreted"
        assert "[bold red]INJECTED[/] [/bold]" in out, "markup in the error text was interpreted"
        assert "\\x1b]8;;" in out and "\\x1b[2J" in out
        assert "\\u202e" in out and "\\u200b" in out and "\\x9b31m" in out

    def test_fallback_risk_panel_shows_risk_assessment_values_safely(
            self, monkeypatch, rec, outdir, capsys):
        """risk_assessment.json is risk_engine's raw output; the fallback panel reads it directly."""
        install_fakes(monkeypatch, rec)
        real_run = orch.risk_engine.run_risk_engine

        def poison_assessment(**kwargs):
            result = real_run(**kwargs)
            path = os.path.join(outdir, "risk_assessment.json")
            assessment = json.load(open(path, encoding="utf-8"))
            for entry in assessment["investigation_queue"]:
                entry["explanation"] = [HOSTILE_TEXT]
                entry["value"] = HOSTILE_PATH
                entry["severity"] = "[bold red]CRITICAL[/]"
                entry["rank"] = {"not": "an int"}
            json.dump(assessment, open(path, "w", encoding="utf-8"))
            return result

        monkeypatch.setattr(orch.risk_engine, "run_risk_engine", poison_assessment)
        monkeypatch.setattr(
            cli.report_generator, "generate_report",
            lambda **kwargs: (_ for _ in ()).throw(cli.report_generator.ReportError("no report")))
        code = cli.main(["-t", TARGET, "-o", outdir, "--top", "3", "--no-color"])
        out = capsys.readouterr().out
        assert code == cli.EXIT_PARTIAL
        assert "Risk prioritization" in out and "Investigation queue" in out
        assert_terminal_safe(out)
        assert "[bold red]C" in out, "the severity cell was interpreted as markup"
        assert "Could not render" not in out

    def test_debug_traceback_is_sanitized_and_redacted(self, monkeypatch, outdir, capsys):
        def boom(*args, **kwargs):
            raise ValueError("bad thing " + HOSTILE_TEXT)
        monkeypatch.setattr(orch, "Orchestrator", boom)
        code = cli.main(["-t", TARGET, "-o", outdir, "--debug", "--no-color"])
        out = capsys.readouterr().out
        assert code == cli.EXIT_FATAL
        assert "ValueError" in out and "bad thing" in out
        assert_terminal_safe(out)

    def test_hostile_cli_error_text_is_sanitized(self, monkeypatch, outdir, capsys):
        def boom(*args, **kwargs):
            raise orch.OrchestratorError("cannot start " + HOSTILE_TEXT)
        monkeypatch.setattr(orch, "Orchestrator", boom)
        assert cli.main(["-t", TARGET, "-o", outdir, "--no-color"]) == cli.EXIT_FATAL
        out = capsys.readouterr().out
        assert "cannot start" in out
        assert_terminal_safe(out)

    def test_console_interprets_no_markup_and_no_emoji_codes(self, monkeypatch):
        tty = io.StringIO()
        monkeypatch.setattr(cli.sys, "stdout", tty)
        monkeypatch.setenv("NO_COLOR", "1")
        console = cli.make_console(False)
        assert console._markup is False and console._emoji is False
        presenter = cli.Presenter(console)
        presenter.note("[bold red]x[/] :skull:")
        presenter.warning("[/bold] :warning:")
        from rich.table import Table
        table = Table()
        table.add_column("c")
        table.add_row("[bold]cell[/bold] :fire:")
        console.print(table)
        text = tty.getvalue()
        assert "[bold red]x[/] :skull:" in text
        assert "[/bold] :warning:" in text
        assert "[bold]cell[/bold] :fire:" in text

    def test_live_progress_description_is_never_markup(self):
        """An unmatched closing tag in a subject used to raise MarkupError in Rich's refresh thread."""
        import time
        buffer = io.StringIO()
        console = cli._CliConsole(file=buffer, force_terminal=True, width=80,
                                  color_system="standard", markup=False, emoji=False)
        presenter = cli.Presenter(console)
        with cli.LiveProgress(presenter) as progress:
            progress.handle({"event": "run_started"})
            for subject in ("https://example.com/[/bold]x\x1b[2Jy", f"https://example.com/{HOSTILE_PATH}",
                            "https://example.com/[bold red]INJECT[/] :skull:"):
                progress.handle({"event": "module_started", "module": "exposure_scan",
                                 "phase": "adaptive", "subject": subject})
                time.sleep(0.15)
                progress.handle({"event": "module_finished", "module": "exposure_scan",
                                 "phase": "adaptive", "subject": subject, "status": "failed",
                                 "error": HOSTILE_TEXT, "observations_ingested": 0})
        out = buffer.getvalue()
        assert "MarkupError" not in out and "Traceback" not in out
        assert "\x1b[2J" not in out and "\x1b]8;;" not in out
        assert "\x1b[1;31mINJECT" not in out and "\U0001f480" not in out
        assert "[bold red]INJECT[/]" in out and "\\x1b[2J" in out and "INJECTED[/bold][/red]" in out

    def test_lone_surrogates_and_huge_values_are_bounded_not_fatal(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        huge = "\ud800" + ("api_key=AKIAIOSFODNN7EXAMPLE \x1b[2J " * 200000)  # ~6 MB

        def hostile_js(js_files, target=None, output_dir="output", **kw):
            raise RuntimeError(huge)

        monkeypatch.setattr(orch.js_analyzer, "run_js_analyzer", hostile_js)
        code = cli.main(["-t", TARGET, "-o", outdir, "-v", "--no-color"])
        out = capsys.readouterr().out
        assert code == cli.EXIT_PARTIAL
        assert "Traceback" not in out
        assert_terminal_safe(out)
        assert "\\ud800" in out
        assert len(out) < 400_000, "a hostile error message must not dump megabytes to the terminal"

    def test_sanitizer_helpers_preserve_legitimate_values(self):
        for value in ("example.com", "xn--bcher-kva.example", "bücher.example", "2001:db8::1",
                      "https://example.com/path?q=1&x=y#frag", "日本語 evidence", "😀",
                      "Server: nginx/1.18.0 (Ubuntu)", "auth_method=bearer", "key_size=2048"):
            assert cli._safe(value) == value, value
            assert cli._shorten(value, 200) == value, value
        assert cli._shorten("a\tb\r\nc", 20) == "a b c"
        assert cli._shorten("x" * 50, 10) == "x" * 9 + "…"
        assert cli._safe("api_key=AKIAIOSFODNN7EXAMPLE") != "api_key=AKIAIOSFODNN7EXAMPLE"
        assert cli._safe("\x1b[2J\x9b31m\x00\u202e") == "\\x1b[2J\\x9b31m\\x00\\u202e"
        assert cli._safe(None) == "" and cli._safe(b"\x1b") == "b'\\x1b'"
        bounded = cli._safe("y" * 5000, 100)
        assert bounded.startswith("y" * 100) and "4900 more" in bounded


class TestBrokenPipe:
    @staticmethod
    def run_with_early_closed_stdout(script, args, env_overrides=None, read_lines=1):
        env = dict(os.environ)
        env.pop("NO_COLOR", None)
        env.update(env_overrides or {})
        process = subprocess.Popen([sys.executable, "-c", script, *args], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env, cwd=REPO_ROOT)
        for _ in range(read_lines):
            process.stdout.readline()
        process.stdout.close()  # the consumer goes away, like `| head`
        err = process.stderr.read().decode("utf-8", "replace")
        return process.wait(), err

    def test_head_closing_the_pipe_does_not_abort_the_run_or_traceback(self, tmp_path):
        outdir = str(tmp_path / "bp")
        code, err = self.run_with_early_closed_stdout(FAKED_CLI, ["-t", TARGET, "-o", outdir])
        assert code == cli.EXIT_OK, err
        assert "Traceback" not in err and "Exception ignored" not in err
        assert "broken pipe" in err and "artifacts are still written" in err
        assert err.count("broken pipe") == 1, "the notice is given once, not per write"
        # The run finished and everything was written as if stdout were open.
        for name in ("surface_graph.json", "risk_assessment.json", "orchestrator_run.json"):
            assert os.path.isfile(os.path.join(outdir, name)), name
        for fmt in ("html", "json", "txt"):
            assert os.path.isfile(os.path.join(outdir, "reports", f"reconhound_report.{fmt}")), fmt
        record = json.load(open(os.path.join(outdir, "orchestrator_run.json")))
        assert record["status"] == orch.RUN_COMPLETED
        assert not [e for e in record["errors"] if "SystemExit" in str(e) or "Broken" in str(e)]

    def test_broken_pipe_during_a_failed_run_keeps_the_error_visible_on_stderr(self, tmp_path):
        code, err = self.run_with_early_closed_stdout(
            FAKED_CLI, ["-t", "203.0.113.1", "-o", str(tmp_path / "x")])
        assert code == cli.EXIT_USAGE
        assert "Traceback" not in err
        assert "error:" in err and "raw IP address" in err

    def test_broken_pipe_with_stderr_closed_too(self, tmp_path):
        """`2>&1 | head`: both streams gone — still no traceback, still the run's exit code."""
        outdir = str(tmp_path / "both")
        env = dict(os.environ)
        env.pop("NO_COLOR", None)
        process = subprocess.Popen([sys.executable, "-c", FAKED_CLI, "-t", TARGET, "-o", outdir],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, cwd=REPO_ROOT)
        process.stdout.readline()
        process.stdout.close()
        assert process.wait() == cli.EXIT_OK
        assert os.path.isfile(os.path.join(outdir, "reports", "reconhound_report.json"))

    def test_execute_no_longer_misclassifies_output_errors_as_output_dir_errors(
            self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)

        class BrokenBanner(cli.Presenter):
            def banner(self):
                raise OSError(errno.EIO, "terminal write failed")

        monkeypatch.setattr(cli, "Presenter", BrokenBanner)
        code = cli.main(["-t", TARGET, "-o", outdir])
        out = capsys.readouterr().out
        assert code == cli.EXIT_FATAL
        assert "Cannot use output directory" not in out
        assert "terminal write failed" in out


class TestEncodingEnvironments:
    def test_ascii_only_stdout_never_raises(self, tmp_path):
        """PYTHONIOENCODING=ascii / LANG=C without UTF-8 mode: escapes, not UnicodeEncodeError."""
        outdir = str(tmp_path / "ascii")
        env = dict(os.environ)
        env.update({"PYTHONIOENCODING": "ascii:strict", "NO_COLOR": "1"})
        process = subprocess.run([sys.executable, "-c", FAKED_CLI_WITH_HOSTILE_MODULES,
                                  "-t", TARGET, "-o", outdir],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=REPO_ROOT)
        out = process.stdout.decode("ascii")
        err = process.stderr.decode("utf-8", "replace")
        assert process.returncode == cli.EXIT_PARTIAL, err
        assert "Traceback" not in out and "Traceback" not in err
        assert "UnicodeEncodeError" not in out and "UnicodeEncodeError" not in err
        assert "Run result" in out and "Output artifacts" in out
        assert "ReconHound Assessment Summary" in out, "the report still prints, escaped"
        assert_terminal_safe(out)

    def test_c_locale_is_fine(self, tmp_path):
        outdir = str(tmp_path / "c")
        env = {k: v for k, v in os.environ.items() if not k.startswith("LC_") and k not in ("LANG", "PYTHONIOENCODING", "PYTHONUTF8")}
        env.update({"LANG": "C", "LC_ALL": "C"})
        process = subprocess.run([sys.executable, "-c", FAKED_CLI, "-t", TARGET, "-o", outdir, "-q"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=REPO_ROOT)
        assert process.returncode == cli.EXIT_OK, process.stderr
        assert b"Traceback" not in process.stderr


class TestInterruptionStages:
    def test_interrupt_escaping_after_the_run_ran_is_described_truthfully(
            self, monkeypatch, rec, outdir, capsys):
        """A Ctrl+C in the orchestrator's final correlation escapes run(); the modules did run."""
        install_fakes(monkeypatch, rec)
        real_run = orch.Orchestrator.run

        def run_then_interrupt(self):
            real_ingest = self._ingest

            def ingest(*args, **kwargs):
                if kwargs.get("after") == "shutdown":
                    raise KeyboardInterrupt
                return real_ingest(*args, **kwargs)

            self._ingest = ingest
            return real_run(self)

        monkeypatch.setattr(orch.Orchestrator, "run", run_then_interrupt)
        code = cli.main(["-t", TARGET, "-o", outdir, "-q", "--no-color"])
        out = capsys.readouterr().out
        assert code == cli.EXIT_INTERRUPTED
        assert "Traceback" not in out
        assert "Nothing was executed" not in out
        assert "Interrupted while the run was finishing" in out and outdir in out
        assert rec.modules(), "the modules did run"

    def test_interrupt_before_the_run_is_described_as_such(self, monkeypatch, outdir, capsys):
        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt
        monkeypatch.setattr(orch, "Orchestrator", interrupted)
        code = cli.main(["-t", TARGET, "-o", outdir, "-q", "--no-color"])
        out = capsys.readouterr().out
        assert code == cli.EXIT_INTERRUPTED
        assert "Nothing was executed" in out and "Traceback" not in out

    def test_interrupt_while_the_console_is_being_built(self, monkeypatch, outdir, capsys):
        monkeypatch.setattr(cli, "make_console", lambda no_color: (_ for _ in ()).throw(KeyboardInterrupt()))
        code = cli.main(["-t", TARGET, "-o", outdir])
        captured = capsys.readouterr()
        assert code == cli.EXIT_INTERRUPTED
        assert "Traceback" not in captured.out + captured.err
        assert "interrupted" in captured.err

    def test_interrupt_while_the_failure_panel_prints(self, monkeypatch, outdir, capsys):
        monkeypatch.setattr(cli.Presenter, "failure",
                            lambda self, message, hint=None: (_ for _ in ()).throw(KeyboardInterrupt()))
        code = cli.main(["-t", "203.0.113.1", "-o", outdir])
        captured = capsys.readouterr()
        assert code == cli.EXIT_INTERRUPTED
        assert "Traceback" not in captured.out + captured.err


class TestMalformedDownstreamResults:
    @pytest.mark.parametrize("returned", [None, [], "done", 42])
    def test_non_document_result_is_fatal_never_clean(self, monkeypatch, rec, outdir, capsys, returned):
        install_fakes(monkeypatch, rec)
        monkeypatch.setattr(orch.Orchestrator, "run", lambda self: returned)
        code = cli.main(["-t", TARGET, "-o", outdir, "-q", "--no-color"])
        out = capsys.readouterr().out
        assert code == cli.EXIT_FATAL
        assert "Traceback" not in out
        assert "instead of a result document" in out

    @pytest.mark.parametrize("result", [
        {},
        {"status": "unknown_state"},
        {"status": None},
        {"status": "completed", "executions": "not a list", "errors": {"x": 1}, "risk": "nope",
         "correlation": [], "adaptive": 3, "opportunities": None, "decision_queue": {},
         "output_paths": "x", "executions_by_status": [1, 2], "target": {"t": 1}, "mode": None},
        {"status": "completed_with_errors", "executions": [None, "x", {"status": "failed", "module": None,
                                                                          "error": {"e": 1}}]},
        {"status": "completed", "adaptive": {"actions": 2.0, "rounds": "1", "deferred": 3, "manual_review": 7},
         "opportunities": {"pending": 5}, "risk": {"status": "ok", "summary": [], "output_paths": 1},
         "correlation": {"summary": {"assets_by_type": [1], "observations": float("nan")}},
         "executions_by_status": {"success": "many", None: None}},
    ])
    def test_malformed_result_documents_fail_safe(self, monkeypatch, rec, outdir, capsys, result):
        install_fakes(monkeypatch, rec)
        monkeypatch.setattr(orch.Orchestrator, "run", lambda self: result)
        code = cli.main(["-t", TARGET, "-o", outdir, "-v", "--no-color"])
        out = capsys.readouterr().out
        assert "Traceback" not in out
        if result.get("status") == "completed":
            assert code in (cli.EXIT_OK, cli.EXIT_PARTIAL)
        elif result.get("status") == "completed_with_errors":
            assert code == cli.EXIT_PARTIAL
        else:
            assert code == cli.EXIT_FATAL, "a missing/unknown run status must not exit 0"
        assert "Could not render the full summary" not in out, "every section degrades on its own"

    def test_exit_code_for_unknown_status_is_not_success(self):
        assert cli.exit_code_for({}) == cli.EXIT_FATAL
        assert cli.exit_code_for({"status": "bogus"}) == cli.EXIT_FATAL
        assert cli.exit_code_for({"status": orch.RUN_COMPLETED}) == cli.EXIT_OK

    @pytest.mark.parametrize("returned", [None, [], "x", {"errors": "not a list"}, {"errors": [None, "x", {}]}])
    def test_non_dict_report_record_is_warned_not_crashed(self, monkeypatch, rec, outdir, capsys, returned):
        install_fakes(monkeypatch, rec)
        monkeypatch.setattr(cli.report_generator, "generate_report", lambda **kwargs: returned)
        code = cli.main(["-t", TARGET, "-o", outdir, "-q", "--no-color"])
        out = capsys.readouterr().out
        assert "Traceback" not in out
        if isinstance(returned, dict):
            assert code == cli.EXIT_OK
        else:
            assert code == cli.EXIT_PARTIAL
            assert "instead of a report record" in out

    def test_poisoned_risk_assessment_file_is_survivable(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        real_run = orch.risk_engine.run_risk_engine

        def poison(**kwargs):
            result = real_run(**kwargs)
            with open(os.path.join(outdir, "risk_assessment.json"), "w") as handle:
                handle.write('{"investigation_queue": [null, 1, "x", {"rank": [], "severity": null}]}')
            return result

        monkeypatch.setattr(orch.risk_engine, "run_risk_engine", poison)
        monkeypatch.setattr(cli.report_generator, "generate_report",
                            lambda **kwargs: (_ for _ in ()).throw(cli.report_generator.ReportError("x")))
        code = cli.main(["-t", TARGET, "-o", outdir, "--no-color"])
        out = capsys.readouterr().out
        assert code == cli.EXIT_PARTIAL
        assert "Traceback" not in out and "Could not render" not in out


class TestTuningValues:
    @pytest.mark.parametrize("value", ["nan", "inf", "1e999", "NaN", "Infinity", "-inf"])
    def test_non_finite_timeout_is_a_usage_error(self, value, outdir, capsys):
        if value.startswith("-"):
            # argparse reads "-inf" as an option name; still a usage error.
            with pytest.raises(SystemExit) as excinfo:
                cli.main(["-t", TARGET, "-o", outdir, "--timeout", value])
            assert excinfo.value.code == cli.EXIT_USAGE
            return
        code = cli.main(["-t", TARGET, "-o", outdir, "--timeout", value, "--no-color"])
        out = capsys.readouterr().out
        assert code == cli.EXIT_USAGE
        assert "finite" in out and "Traceback" not in out
        assert not os.path.exists(outdir)

    @pytest.mark.parametrize("argv", [["--timeout", "0"], ["--timeout", "-1"], ["--threads", "0"],
                                      ["--threads", "-3"]])
    def test_out_of_range_values_are_usage_errors_from_the_orchestrator(self, argv, outdir, capsys):
        code = cli.main(["-t", TARGET, "-o", outdir, "--no-color"] + argv)
        out = capsys.readouterr().out
        assert code == cli.EXIT_USAGE and "Traceback" not in out

    @pytest.mark.parametrize("argv", [["--timeout", "abc"], ["--threads", "1e3"], ["--threads", "x"],
                                      ["--top", "1.5"], ["--timeout"], ["--threads", "2", "--threads"]])
    def test_malformed_numbers_are_parser_errors(self, argv, outdir):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["-t", TARGET, "-o", outdir] + argv)
        assert excinfo.value.code == 2

    def test_repeated_values_last_one_wins_and_reaches_the_orchestrator(self):
        kwargs = cli.build_orchestrator_kwargs(parse(["-t", TARGET, "--threads", "2", "--threads", "7",
                                                      "--timeout", "1", "--timeout", "2.5"]))
        assert kwargs["threads"] == 7 and kwargs["timeout"] == 2.5

    def test_valid_extreme_values_pass_through_unchanged(self):
        kwargs = cli.build_orchestrator_kwargs(parse(["-t", TARGET, "--threads", "1000000",
                                                      "--timeout", "1e-6", "--top", "99999999999"]))
        assert kwargs["threads"] == 1000000 and kwargs["timeout"] == 1e-6


class TestNarrowTerminalBanner:
    def test_banner_degrades_below_its_width(self, tmp_path):
        code, out = run_faked_cli_on_pty(["-t", TARGET, "-o", str(tmp_path / "n"), "--no-color"],
                                         {"COLUMNS": "40"})
        assert code == cli.EXIT_OK
        assert "ReconHound" in out and "v1." in out
        assert cli.BANNER.strip().splitlines()[0] not in out, "folded ASCII art"
        # Live-progress frames overwrite in place with CR; each CR-separated
        # segment is what the terminal shows on one line.
        lines = [segment for line in re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", out).split("\n")
                 for segment in line.split("\r")]
        assert not any(len(line) > 40 for line in lines), [l for l in lines if len(l) > 40]

    def test_banner_is_shown_at_normal_widths(self, tmp_path):
        code, out = run_faked_cli_on_pty(["-t", TARGET, "-o", str(tmp_path / "w"), "--no-color"],
                                         {"COLUMNS": "100"})
        assert code == cli.EXIT_OK
        assert cli.BANNER.strip().splitlines()[0] in out

    def test_negative_columns(self, tmp_path):
        code, out = run_faked_cli_on_pty(["-t", TARGET, "-o", str(tmp_path / "neg"), "-q", "--no-color"],
                                         {"COLUMNS": "-5"})
        assert code == cli.EXIT_OK and "Assessment" in out and "Traceback" not in out


class TestRepeatedAndConcurrentInvocation:
    def test_interrupted_run_followed_by_a_clean_run(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec, interrupt_at="crawler")
        assert cli.main(["-t", TARGET, "-o", outdir, "-q"]) == cli.EXIT_INTERRUPTED
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", TARGET, "-o", outdir, "-q"]) == cli.EXIT_OK
        capsys.readouterr()
        record = json.load(open(os.path.join(outdir, "orchestrator_run.json")))
        assert record["status"] == orch.RUN_COMPLETED and not record["interrupted"]

    def test_different_targets_in_separate_directories_run_concurrently(self, tmp_path):
        procs = []
        for target in ("example.com", "example.org", "example.net"):
            outdir = str(tmp_path / target)
            procs.append((outdir, subprocess.Popen(
                [sys.executable, "-c", FAKED_CLI, "-t", target, "-o", outdir, "-q", "--no-color"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=REPO_ROOT)))
        for outdir, process in procs:
            out, err = process.communicate()
            assert process.returncode == cli.EXIT_OK, err
            record = json.load(open(os.path.join(outdir, "orchestrator_run.json")))
            assert record["target"] == os.path.basename(outdir)
            assert os.path.isfile(os.path.join(outdir, "reports", "reconhound_report.json"))

    def test_a_second_target_in_the_same_directory_is_refused_before_any_work(
            self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        assert cli.main(["-t", TARGET, "-o", outdir, "-q"]) == cli.EXIT_OK
        before = open(os.path.join(outdir, "surface_graph.json")).read()
        code = cli.main(["-t", "example.org", "-o", outdir, "-q", "--no-color"])
        out = capsys.readouterr().out
        assert code == cli.EXIT_USAGE
        assert "different" in out and "target" in out
        assert open(os.path.join(outdir, "surface_graph.json")).read() == before
