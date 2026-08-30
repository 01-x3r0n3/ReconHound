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

    def test_no_screenshots_removes_only_that_module(self):
        _, modules = cli.resolve_execution(parse(["-t", TARGET, "--no-screenshots"]))
        assert "screenshot" not in modules
        assert set(modules) == set(orch.ALL_MODULES) - {"screenshot"}

    def test_no_screenshots_with_explicit_selection(self):
        _, modules = cli.resolve_execution(
            parse(["-t", TARGET, "-m", "crawler", "-m", "screenshot", "--no-screenshots"]))
        assert modules == ["crawler"]

    def test_no_screenshots_that_empties_the_selection_is_an_error(self):
        with pytest.raises(cli.CliError) as excinfo:
            cli.resolve_execution(parse(["-t", TARGET, "-m", "screenshot", "--no-screenshots"]))
        assert excinfo.value.exit_code == cli.EXIT_USAGE

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
            "--no-adaptive", "--no-screenshots"]))
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

    def test_risk_summary_matches_the_assessment_on_disk(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir, "--top", "5"])
        out = capsys.readouterr().out
        assessment = json.load(open(os.path.join(outdir, "risk_assessment.json")))
        summary = assessment["summary"]
        assert "Risk prioritization" in out
        assert f"{summary['assets_assessed']} assets" in out
        for entry in assessment["investigation_queue"][:5]:
            assert entry["severity"] in out

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
        assert "Investigation queue holds" in out

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

    def test_large_result_sets_stay_readable(self, monkeypatch, rec, outdir, capsys):
        install_fakes(monkeypatch, rec)
        cli.main(["-t", TARGET, "-o", outdir, "--top", "500"])
        out = capsys.readouterr().out
        assert "Run result" in out
        assert len(out.splitlines()) < 400, "the dashboard must not become the report"

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
        for active in ("active_recon", "crawler", "endpoint_discovery", "screenshot"):
            assert active not in rec.modules()
