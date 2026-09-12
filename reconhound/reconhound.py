#!/usr/bin/env python3
"""
ReconHound Module 23 — reconhound.py (CLI entry point).

This is ReconHound's user-facing command line interface: the *only* module
whose job is presentation. It parses arguments, turns them into an execution
configuration, hands that configuration to `core/orchestrator.py`, renders
what the orchestrator actually reports while it runs, summarises the result,
points the operator at the artifacts on disk, and chooses a process exit
code.

    User -> reconhound.py -> core/orchestrator.py -> modules
         -> surface_mapper.py -> risk_engine.py -> output artifacts

It performs **no** reconnaissance of its own. It does not scan, crawl,
fingerprint, correlate, score, orchestrate, or exploit anything. Every fact
it prints comes from the orchestrator's own execution result or from an
artifact a module actually wrote.


IMPLEMENTATION DECISIONS
------------------------

1.  **Truthful rendering only.** Every status glyph, count, severity and
    path printed below is read out of `Orchestrator.run()`'s result document
    (see orchestrator `_build_result()`) or, for the investigation queue, out
    of the `risk_assessment.json` risk_engine.py actually wrote. Nothing is
    inferred, defaulted, or invented. A module that failed is shown as
    failed; a path that was not produced is shown as "not produced".

2.  **Progress comes from the orchestrator, not from a guess.** The CLI
    registers a `progress_callback` and renders the events the orchestrator
    emits (`run_started`, `phase_started`, `module_started`,
    `module_finished`, `run_interrupted`, `run_finished`). The total number
    of module executions is not knowable in advance — subjects are derived
    from what earlier phases discover — so the live display is an elapsed
    spinner plus a completed-work log, never a fake percentage bar.

3.  **No duplicated validation.** Target validation lives in
    `passive_recon.validate_target()` and is invoked by the Orchestrator
    constructor before any network activity. The CLI simply requires
    `--target` to be present and turns the resulting `ScopeViolationError` /
    `ConfigurationError` into a clean message and exit status. Adding a
    second target parser here could only ever disagree with the real one.

4.  **Rich is required, its absence is handled.** context.md §5 and design
    principle 9 specify a Rich terminal experience, so `rich` is a declared
    dependency. If it (or a producer module's dependency) is missing, the
    CLI says exactly what to install and exits non-zero instead of raising
    an ImportError traceback. `--help` and `--version` keep working either
    way.

5.  **Interruption preserves evidence.** `Orchestrator.run()` already
    catches `KeyboardInterrupt` internally, persists everything collected so
    far, and returns a complete partial result marked `interrupted`. The CLI
    therefore renders that partial result in full — the same summary, the
    same artifact paths — and exits 130. A `KeyboardInterrupt` raised
    outside `run()` (during construction or rendering) is caught here and
    reported without a traceback.

6.  **Exit codes describe the run, not the findings.** "Nothing was found"
    is an ordinary reconnaissance outcome and exits 0. See EXIT_* below.

7.  **No competing configuration.** The CLI stores nothing, reads no config
    file, and never handles a credential: modules read their own API keys
    from the environment and degrade gracefully without them.

8.  **Reporting is delegated, never reimplemented.** context.md §10 item 21
    assigns report generation to `report_generator.py`. After the
    orchestrator returns, the CLI hands it the run's own result plus the
    output directory; report_generator builds one report document, writes
    the text/HTML/JSON files from it, and hands the same document back so
    the CLI can print the terminal report — the primary human-facing report
    — from exactly the state that was persisted. The CLI contains no report
    rendering of its own: the terminal report is rendered by
    `report_generator.render_terminal_report()` on the CLI's console, with
    the sections the CLI's own run summary already covers (module execution
    detail, artifact paths) omitted so nothing is printed twice. When the
    report could not be generated the CLI falls back to its own risk
    summary, says so, and never claims a report that was not written.

9.  **Nothing target-derived is trusted at the terminal.** The terminal
    report is rendered from report_generator's hardened document, but the
    CLI's own panels print values that never pass through it: module
    exception text, adaptive subjects and opportunity values (URLs from
    crawled HTML), decision-queue reasons, `risk_assessment.json` entries
    in the fallback risk panel, persisted graph keys. Every such value is
    displayed through `_safe()` — report_generator's own `sanitize_text`
    (C0/C1/ESC/bidi/zero-width/lone surrogates -> visible printable escapes)
    and `redact_sensitive_text` — so the CLI shows exactly what the report
    would. The console is built with markup and emoji codes disabled, as
    report_generator's is, so no string is ever parsed as Rich markup. Only
    display copies are touched; canonical data on disk is never rewritten.

10. **Output failures are not run failures.** A consumer that closes the
    pipe early (`| head`) makes every later write raise BrokenPipeError:
    the console's `on_broken_pipe` hook stops terminal output, says so once
    on stderr, and lets the run finish and write its artifacts — the exit
    code still describes the run. A stdout encoding that cannot represent
    a character shows it as an escape instead of raising. A Ctrl+C that
    reaches the CLI after the orchestrator already ran is reported as what
    it is, never as "nothing was executed".
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import traceback
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Bootstrap
#
# This file lives *inside* the `reconhound` package but is also the executable
# entry point. When it is run as a script (`python reconhound/reconhound.py`),
# sys.path[0] is `<repo>/reconhound`, where this very file would shadow the
# `reconhound` package for `import reconhound.core...`. Drop that directory
# and put the repository root first instead.
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)

if __package__ in (None, ""):
    sys.path[:] = [
        entry for entry in sys.path
        if os.path.abspath(entry or os.getcwd()) != _HERE
    ]
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)


# ---------------------------------------------------------------------------
# Optional imports — deferred failure so --help/--version always work
# ---------------------------------------------------------------------------

try:  # pragma: no cover - exercised by the dependency-failure path
    from rich.console import Console
    from rich.padding import Padding
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
    from rich import box
    _RICH_IMPORT_ERROR: Optional[BaseException] = None
except BaseException as _exc:  # pragma: no cover
    Console = Padding = Panel = Progress = SpinnerColumn = TextColumn = None  # type: ignore
    TimeElapsedColumn = Table = Text = box = None  # type: ignore
    _RICH_IMPORT_ERROR = _exc

try:
    from reconhound.core import orchestrator as orch
    from reconhound import report_generator
    _ORCH_IMPORT_ERROR: Optional[BaseException] = None
except BaseException as _exc:  # pragma: no cover - dependency-failure path
    orch = None  # type: ignore
    report_generator = None  # type: ignore
    _ORCH_IMPORT_ERROR = _exc


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

MODULE_NAME = "reconhound.py"
PROG = "reconhound"
__version__ = "1.0.0"
TAGLINE = "Correlated attack-surface discovery"
SUBTITLE = "Authorized reconnaissance only — never exploitation"

# Pure-ASCII wordmark: renders identically on every terminal and encoding.
BANNER = r"""
 ___                    _  _                 _
| _ \___ __ ___ _ _    | || |___ _  _ _ _  __| |
|   / -_) _/ _ \ ' \   | __ / _ \ || | ' \/ _` |
|_|_\___\__\___/_||_|  |_||_\___/\_,_|_||_\__,_|
"""
BANNER_WIDTH = max(len(line) for line in BANNER.splitlines())


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_OK = 0            # run completed (finding nothing is a normal outcome)
EXIT_PARTIAL = 1       # run finished, but at least one module or stage failed
EXIT_USAGE = 2         # bad arguments, invalid target, invalid configuration
EXIT_FATAL = 3         # the run could not be performed or aborted fatally
EXIT_INTERRUPTED = 130 # Ctrl+C (128 + SIGINT); collected evidence preserved

EXIT_CODE_HELP = """exit codes:
  0    run completed (a run that discovers nothing still exits 0)
  1    run completed but one or more modules or stages failed
  2    invalid arguments, invalid target, or invalid configuration
  3    fatal error: the run could not start or aborted
  130  interrupted with Ctrl+C (everything discovered was preserved)
"""

USAGE_EXAMPLES = """examples:
  reconhound --target example.com --full-scan
  reconhound --target example.com --passive-only
  reconhound --target example.com --module js_analyzer
  reconhound --target example.com --output-dir /reports/example
  reconhound --target example.com --threads 10 --timeout 30
"""


# ---------------------------------------------------------------------------
# Presentation metadata (labels only — all values come from the orchestrator)
# ---------------------------------------------------------------------------

PHASE_LABELS: Dict[str, str] = {
    "passive": "Passive Intelligence",
    "active_network": "Active Reconnaissance / Network",
    "active_web": "Active Reconnaissance / Web + Client-side",
    "adaptive": "Adaptive Discovery",
    "intelligence": "Vulnerability Intelligence + Risk",
    "correlation": "Surface Correlation",
}

# Compact forms for the summary table, where a long label would squeeze every
# other column into an ellipsis.
PHASE_SHORT: Dict[str, str] = {
    "passive": "Passive",
    "active_network": "Active / network",
    "active_web": "Active / web",
    "adaptive": "Adaptive",
    "intelligence": "Intelligence",
    "correlation": "Correlation",
}

STATUS_STYLES: Dict[str, str] = {
    "success": "green",
    "no_results": "dim",
    "failed": "red",
    "scope_rejected": "yellow",
    "skipped": "dim",
    "interrupted": "yellow",
    # Not a result and not a failure: the subject never answered, so nothing
    # about it was checked. Shown as a warning because an unreachable subject
    # is a hole in the run's coverage, not a clean outcome.
    "unreachable": "yellow",
}

STATUS_LABELS: Dict[str, str] = {
    "success": "success",
    "no_results": "no new data",
    "failed": "FAILED",
    "scope_rejected": "out of scope",
    "skipped": "skipped",
    "interrupted": "interrupted",
    "unreachable": "no answer",
}

RUN_STATUS_STYLES: Dict[str, str] = {
    "completed": "bold green",
    "completed_with_errors": "bold yellow",
    "interrupted": "bold yellow",
    "failed": "bold red",
}

SEVERITY_STYLES: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

UNICODE_GLYPHS = {
    "success": "✔", "no_results": "·", "failed": "✖",
    "scope_rejected": "⚠", "skipped": "–", "interrupted": "!",
    "unreachable": "⊘",
    "bullet": "•", "arrow": "→",
}
ASCII_GLYPHS = {
    "success": "+", "no_results": ".", "failed": "x",
    "scope_rejected": "!", "skipped": "-", "interrupted": "!",
    "unreachable": "o",
    "bullet": "*", "arrow": "->",
}

ARTIFACT_LABELS: Dict[str, str] = {
    "pending_assets": "Raw discoveries",
    "surface_graph": "Correlated graph",
    "risk_assessment": "Risk assessment",
    "execution_record": "Execution record",
}
ARTIFACT_ORDER = ("surface_graph", "risk_assessment", "pending_assets", "execution_record")


class CliError(Exception):
    """A user-facing CLI failure carrying its own process exit code."""

    def __init__(self, message: str, exit_code: int = EXIT_USAGE, hint: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code
        self.hint = hint


# ---------------------------------------------------------------------------
# Small formatting helpers
# ---------------------------------------------------------------------------

# Longest message the CLI prints in one panel line/paragraph of its own. The
# full text always exists in the execution record or the report on disk.
MAX_MESSAGE_CHARS = 2000


def _str(value: Any) -> str:
    """str() that survives a value whose __str__ raises (a hostile exception class)."""
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return f"<{type(value).__name__}: unprintable>"


def _sanitize(value: Any) -> str:
    """
    One string with no character a terminal could act on.

    report_generator.sanitize_text() is the project's definition of that
    set (C0/C1 controls, ESC, DEL, bidi/zero-width format characters, lone
    surrogates), so the CLI shows the same visible escapes the report does.
    The fallback covers the can't-happen case of the reporting layer being
    absent: str.isprintable() is False for exactly those character classes.
    """
    text = _str(value)
    if report_generator is not None:
        return report_generator.sanitize_text(text)[0]
    return "".join(ch if ch == " " or ch.isprintable() else repr(ch)[1:-1] for ch in text)


# Widest credential shape the redaction recognises; a string is pre-cut to
# its bound plus this margin before scanning (as report_generator.harden_text
# does) so a 10 MB exception message costs milliseconds, not seconds, and a
# token straddling the bound is still recognised whole.
_REDACTION_LOOKAHEAD = 1024


def _safe(value: Any, limit: Optional[int] = MAX_MESSAGE_CHARS) -> str:
    """
    A display-safe copy of a value that may be target-derived: sanitized,
    credential shapes masked (report_generator.redact_sensitive_text, the
    same masking the report applies), bounded with a visible marker.
    """
    text = _str(value)
    original = len(text)
    if limit is not None and original > limit + _REDACTION_LOOKAHEAD:
        text = text[: limit + _REDACTION_LOOKAHEAD]
    text = _sanitize(text)
    if report_generator is not None:
        text = report_generator.redact_sensitive_text(text)[0]
    if limit is not None and (len(text) > limit or original > limit):
        omitted = max(original - limit, len(text) - limit)
        text = f"{text[:limit]}… [{omitted} more character(s) omitted]"
    return text


def _shorten(value: Any, width: int) -> str:
    """One display-safe line, whitespace collapsed, cut to `width` cells."""
    text = " ".join(_str(value).split())
    if len(text) > width + _REDACTION_LOOKAHEAD:
        text = text[: width + _REDACTION_LOOKAHEAD]
    text = _safe(text, None)
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "…"


def _join(value: Any, separator: str = "; ") -> str:
    """
    Flatten a rationale/explanation field into one line.

    risk_engine.py's `explanation` is a *list* of rationale strings; printing
    it through str() would show a Python list repr to the operator.
    """
    if isinstance(value, (list, tuple, set)):
        return separator.join(str(item) for item in value if item)
    return "" if value is None else str(value)


def _int(value: Any) -> int:
    """A count out of a result document, or 0 when it is not one."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) else 0
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _duration(seconds: Any) -> str:
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        return ""
    if value < 60:
        return f"{value:.1f}s"
    minutes, secs = divmod(int(value), 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def _elapsed(result: Dict[str, Any]) -> str:
    """Wall-clock duration of the run, from the orchestrator's own stamps."""
    from datetime import datetime

    started, finished = result.get("started_at"), result.get("finished_at")
    if not started or not finished:
        return ""
    try:
        delta = datetime.fromisoformat(finished) - datetime.fromisoformat(started)
    except (TypeError, ValueError):
        return ""
    return _duration(delta.total_seconds())


def _file_size(path: str) -> str:
    try:
        size = os.path.getsize(path)
    except OSError:
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return ""


# ---------------------------------------------------------------------------
# 1. Argument parsing
# ---------------------------------------------------------------------------

def _module_choices() -> Optional[List[str]]:
    """Known module names, or None when the package could not be imported."""
    if orch is None:
        return None
    return sorted(orch.MODULE_PHASE)


def build_parser() -> argparse.ArgumentParser:
    """The complete ReconHound CLI contract (context.md §10 items 22-23)."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=f"ReconHound {__version__} — {TAGLINE}. {SUBTITLE}.",
        epilog=USAGE_EXAMPLES + "\n" + EXIT_CODE_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-t", "--target", required=True, metavar="DOMAIN",
        help="Authorized target domain, e.g. example.com (bare domain, not a URL or IP)",
    )
    parser.add_argument(
        "-o", "--output-dir", default="output", metavar="DIR",
        help="Directory receiving all run state and output artifacts (default: output)",
    )

    mode = parser.add_argument_group("execution mode")
    exclusive = mode.add_mutually_exclusive_group()
    exclusive.add_argument("--full-scan", action="store_true",
                           help="Run the complete pipeline: passive, active and intelligence (default)")
    exclusive.add_argument("--passive-only", action="store_true",
                           help="Passive intelligence and intelligence modules only; never touches the target")
    exclusive.add_argument("--active-only", action="store_true",
                           help="Active reconnaissance and intelligence modules only")
    mode.add_argument("-m", "--module", action="append", default=None, metavar="NAME",
                      choices=_module_choices(),
                      help="Run only the named module (repeatable). Combine with a mode flag to "
                           "restrict the selection within that mode.")
    mode.add_argument("--no-adaptive", action="store_true",
                      help="Do not act on the reconnaissance opportunities surface_mapper raises")

    tuning = parser.add_argument_group("execution tuning")
    tuning.add_argument("--threads", type=int, default=None, metavar="N",
                        help=f"Worker threads inside each module (default: "
                             f"{orch.DEFAULT_THREADS if orch else 10})")
    tuning.add_argument("--timeout", type=float, default=None, metavar="SECONDS",
                        help=f"Per-request network timeout (default: "
                             f"{orch.DEFAULT_TIMEOUT if orch else 8.0})")
    tuning.add_argument("--wordlists-dir", default=None, metavar="DIR",
                        help="Directory holding the wordlists (default: the bundled wordlists/)")

    reporting = parser.add_argument_group("reporting")
    reporting.add_argument("--min-severity", default=None, metavar="LEVEL",
                           choices=sorted(orch.risk_engine.VALID_SEVERITIES) if orch else None,
                           help="Lowest severity admitted to the investigation queue (default: LOW)")
    reporting.add_argument("--top", type=int, default=10, metavar="N",
                           help="Investigation-queue entries to show in the terminal report (default: 10)")

    output = parser.add_argument_group("terminal output")
    verbosity = output.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true",
                           help="Show per-module detail, the decision queue and every recorded error")
    verbosity.add_argument("-q", "--quiet", action="store_true",
                           help="Suppress the banner and live progress; print the final summary only")
    output.add_argument("--debug", action="store_true",
                        help="Print full tracebacks for unexpected failures")
    output.add_argument("--no-color", action="store_true",
                        help="Disable colour and styling (also honoured via NO_COLOR)")

    parser.add_argument("-V", "--version", action="version",
                        version=f"ReconHound {__version__}")
    return parser


def resolve_execution(args: argparse.Namespace) -> Tuple[str, Optional[List[str]]]:
    """
    Map the parsed flags onto the orchestrator's `mode` / `modules` contract.

    The orchestrator owns module-set resolution (`_resolve_modules`); this
    only chooses which of its published sets is being asked for.
    """
    if args.passive_only:
        mode = orch.MODE_PASSIVE
    elif args.active_only:
        mode = orch.MODE_ACTIVE
    elif args.module:
        mode = orch.MODE_MODULE
    else:
        mode = orch.MODE_FULL

    modules: Optional[List[str]] = list(dict.fromkeys(args.module)) if args.module else None
    return mode, modules


def build_orchestrator_kwargs(args: argparse.Namespace) -> Dict[str, Any]:
    """Translate the namespace into Orchestrator keyword arguments."""
    mode, modules = resolve_execution(args)

    if args.top < 0:
        raise CliError("--top must not be negative.", EXIT_USAGE)
    # argparse's float() accepts "nan" and "inf". The orchestrator's
    # `timeout > 0` check lets both through, and every socket then rejects
    # them ("Invalid value NaN", "timestamp out of range") — a run in which
    # every module fails for a reason that looks like a network problem.
    if args.timeout is not None and not math.isfinite(args.timeout):
        raise CliError(f"--timeout must be a finite number of seconds, not {args.timeout!r}.",
                       EXIT_USAGE)

    kwargs: Dict[str, Any] = {
        "target": args.target,
        "output_dir": args.output_dir,
        "mode": mode,
        "modules": modules,
        "wordlists_dir": args.wordlists_dir,
    }
    # Only forward what the operator actually set, so the orchestrator's own
    # documented defaults stay the single source of truth.
    if args.threads is not None:
        kwargs["threads"] = args.threads
    if args.timeout is not None:
        kwargs["timeout"] = args.timeout
    if args.min_severity is not None:
        kwargs["min_risk_severity"] = args.min_severity
    if args.no_adaptive:
        kwargs["max_adaptive_rounds"] = 0
    return kwargs


# ---------------------------------------------------------------------------
# 2. Terminal presentation
# ---------------------------------------------------------------------------

class Presenter:
    """
    Every piece of terminal rendering ReconHound does.

    Holds no reconnaissance state: it is handed orchestrator events and the
    orchestrator's result document, and turns them into output.
    """

    def __init__(self, console: "Console", *, verbose: bool = False, quiet: bool = False):
        self.console = console
        self.verbose = verbose
        self.quiet = quiet
        self.glyphs = UNICODE_GLYPHS if self._supports_unicode(console) else ASCII_GLYPHS
        # Set by execute() the moment Orchestrator.run() is entered, so an
        # interrupt that reaches main() can be described truthfully.
        self.run_started = False

    # -- capability detection --------------------------------------------

    @staticmethod
    def _supports_unicode(console: "Console") -> bool:
        encoding = (getattr(console.file, "encoding", None) or "").lower()
        if not encoding:
            return False
        try:
            "✔✖…".encode(encoding)
        except (UnicodeEncodeError, LookupError):
            return False
        return True

    @property
    def width(self) -> int:
        return max(60, min(self.console.width, 110))

    # -- primitives -------------------------------------------------------

    def print(self, *args: Any, **kwargs: Any) -> None:
        self.console.print(*args, **kwargs)

    def blank(self) -> None:
        if not self.quiet:
            self.console.print()

    def note(self, message: str) -> None:
        if not self.quiet:
            self._line(Text(_shorten(message, MAX_MESSAGE_CHARS), style="dim"))

    def warning(self, message: str) -> None:
        if getattr(self.console, "stdout_broken", False):
            _stderr(f"warning: {_shorten(message, MAX_MESSAGE_CHARS)}")
            return
        self._line(Text(f"{self.glyphs['scope_rejected']} {_shorten(message, MAX_MESSAGE_CHARS)}",
                        style="yellow"))

    def _line(self, text: "Text") -> None:
        """
        An indented message line whose wrapped continuations stay indented.

        Newlines are already collapsed by _shorten(); the left padding keeps
        a long message's wrapped tail from starting at column 0, where quoted
        target text ("[CRIT] ...") would read as the CLI's own output.
        """
        self.console.print(Padding(text, (0, 0, 0, 2)))

    def failure(self, message: str, hint: Optional[str] = None) -> None:
        message = _safe(message)
        if getattr(self.console, "stdout_broken", False):
            # stdout is gone (see _CliConsole.on_broken_pipe); the error must
            # still reach the operator.
            _stderr(f"error: {message}" + (f" ({hint})" if hint else ""))
            return
        self.console.print()
        body = Text(message, style="red")
        if hint:
            body.append("\n\n")
            body.append(hint, style="dim")
        self.console.print(Panel(body, title="[bold red]Error[/bold red]",
                                 border_style="red", box=box.ROUNDED, width=self.width))

    # -- banner and configuration ----------------------------------------

    def banner(self) -> None:
        if self.quiet:
            return
        if self.console.width >= BANNER_WIDTH:
            self.console.print(Text(BANNER, style="bold cyan"), highlight=False)
        else:
            # Folded ASCII art is noise; a terminal too narrow for the
            # wordmark gets the name instead.
            self.console.print()
            self.console.print(Text("  ReconHound", style="bold cyan"))
        line = Text("  ")
        line.append(f"v{__version__}", style="bold white")
        line.append(f"  {self.glyphs['bullet']}  ", style="dim")
        line.append(TAGLINE, style="cyan")
        self.console.print(line)
        self.console.print(Text(f"  {SUBTITLE}", style="dim"))
        self.console.print()

    def configuration(self, orchestrator: Any) -> None:
        """
        Render the *validated* configuration.

        Everything shown is read back off the constructed Orchestrator — the
        normalized target, the module set it actually resolved, the effective
        timeout/threads — so the panel can never describe a run different
        from the one about to happen.
        """
        if self.quiet:
            return
        modules = list(orchestrator.selected_modules)
        table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1))
        table.add_column(style="dim", no_wrap=True)
        table.add_column(style="white", overflow="fold")

        table.add_row("Target", Text(orchestrator.target, style="bold cyan"))
        table.add_row("Mode", str(orchestrator.mode))
        shown = ", ".join(modules) if len(modules) <= 6 else \
            f"{', '.join(modules[:6])} (+{len(modules) - 6} more)"
        table.add_row(f"Modules ({len(modules)})", shown or "none")
        table.add_row("Output directory", _sanitize(os.path.abspath(orchestrator.output_dir)))
        settings = [
            f"threads={orchestrator.threads}",
            f"timeout={orchestrator.timeout}s",
            f"min-severity={orchestrator.min_risk_severity}",
        ]
        if not orchestrator.limits.get("max_adaptive_rounds"):
            settings.append("adaptive discovery disabled")
        table.add_row("Settings", ", ".join(settings))

        self.console.print(Panel(table, title="[bold]Execution[/bold]",
                                 border_style="cyan", box=box.ROUNDED, width=self.width))
        self.console.print(Text(
            f"  {self.glyphs['scope_rejected']} Reconnaissance is confined to "
            f"{_sanitize(orchestrator.target)} and its subdomains.\n"
            f"    Run this only where you hold explicit written authorization.",
            style="yellow"))
        self.console.print()

    # -- live progress ----------------------------------------------------

    def phase_heading(self, phase: str) -> None:
        if self.quiet:
            return
        label = PHASE_LABELS.get(phase, phase)
        self.console.rule(Text(label, style="bold cyan"), style="cyan", align="left")

    def module_started(self, module: str, subject: Any) -> str:
        return f"{module}  {self.glyphs['arrow']}  {_shorten(subject, 48) or 'target'}"

    def module_finished(self, record: Dict[str, Any]) -> None:
        if self.quiet:
            return
        status = str(record.get("status", "success"))
        style = STATUS_STYLES.get(status, "white")
        # 4 (indent + glyph) + module + subject + detail; the subject column
        # absorbs the width so the line fits the terminal instead of wrapping.
        subject_width = max(12, min(40, self.console.width - 4 - 21 - 16))
        line = Text("  ")
        line.append(f"{self.glyphs.get(status, self.glyphs['bullet'])} ", style=style)
        line.append(f"{_shorten(record.get('module'), 20):<20} ", style="bold" if status == "failed" else "")
        line.append(f"{_shorten(record.get('subject'), subject_width):<{subject_width}} ", style="dim")

        detail = STATUS_LABELS.get(status, _shorten(status, 20))
        observations = record.get("observations_ingested")
        if status == "success" and isinstance(observations, int) and observations:
            detail = f"{observations} observation{'s' if observations != 1 else ''}"
        elif status in ("failed", "scope_rejected") and record.get("error"):
            detail = f"{detail}: {_shorten(record['error'], 60)}"
        line.append(detail, style=style)
        # One terminal line per execution: cropped, never wrapped, so quoted
        # error text cannot continue at column 0 as a line of its own.
        self.console.print(line, highlight=False, no_wrap=True, overflow="ellipsis")

    # -- final summary ----------------------------------------------------

    def summary(self, result: Dict[str, Any], top: int,
                report: Optional[Dict[str, Any]] = None) -> None:
        """
        Run outcome -> terminal report -> persisted artifacts.

        The CLI's own panels describe the run (verdict, per-module execution,
        failures, surface census, adaptive round); report_generator's
        terminal report describes what was found. The report carries the
        risk summary and the investigation queue in more detail than the
        CLI's risk panel did, so that panel is shown only when no report
        document is available — never both.
        """
        self.console.print()
        self._verdict(result)
        self._execution_table(result)
        self._failures(result)
        self._surface_table(result)
        self._adaptive(result)
        if self.verbose:
            self._decision_queue(result)
        rendered = self._report(report, top)
        risk = result.get("risk")
        risk_status = risk.get("status") if isinstance(risk, dict) else None
        if not rendered or risk_status in (None, "skipped", "failed"):
            # Without a report the CLI's own risk panel is the summary. With
            # one, the report already carries the severity distribution and
            # the queue; _risk then only contributes its one-line explanation
            # of why no assessment exists (risk_engine skipped or failed).
            self._risk(result, top)
        self._artifacts(result, report)

    def _report(self, report: Optional[Dict[str, Any]], top: int) -> bool:
        """
        Print report_generator's terminal report from the document it built.

        Returns True when the report was rendered. A rendering failure is
        reported and leaves the caller to fall back to the risk panel: the
        files on disk are already complete, and a display problem must not
        hide the run's risk summary.
        """
        document = (report or {}).get("document")
        if not isinstance(document, dict) or report_generator is None:
            return False
        self.console.print()
        try:
            report_generator.render_terminal_report(
                document, console=self.console, width=self.width,
                limits={"terminal_max_queue_entries": max(0, top)},
                # Covered by this presenter's own panels and artifact table.
                omit=("execution", "source_artifacts"),
            )
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            self.warning(f"Could not render the terminal report ({type(exc).__name__}: {_str(exc)}); "
                         f"the report files on disk are complete.")
            return False
        return True

    def _verdict(self, result: Dict[str, Any]) -> None:
        status = str(result.get("status", "unknown"))
        style = RUN_STATUS_STYLES.get(status, "bold white")
        by_status = result.get("executions_by_status")
        by_status = by_status if isinstance(by_status, dict) else {}
        parts = [f"{_shorten(count, 12)} {STATUS_LABELS.get(str(name), _shorten(name, 24))}"
                 for name, count in sorted(by_status.items(), key=lambda kv: -_int(kv[1]))]

        body = Text()
        body.append(_shorten(status, 40).replace("_", " ").upper(), style=style)
        elapsed = _elapsed(result)
        if elapsed:
            body.append(f"   {self.glyphs['bullet']} {elapsed}", style="dim")
        body.append(f"\n{_shorten(result.get('target', ''), 253)}", style="bold cyan")
        body.append(f"  {self.glyphs['bullet']} mode {_shorten(result.get('mode', ''), 24)}", style="dim")
        if parts:
            body.append(f"\nModule executions: {', '.join(parts)}", style="dim")
        if result.get("interrupted"):
            body.append("\nInterrupted — everything discovered before the interrupt was "
                        "correlated and saved.", style="yellow")
        self.console.print(Panel(body, title="[bold]Run result[/bold]", border_style=style.split()[-1],
                                 box=box.ROUNDED, width=self.width))

    def _execution_table(self, result: Dict[str, Any]) -> None:
        executions = result.get("executions")
        if not isinstance(executions, list) or not executions:
            return
        self.console.print()
        table = Table(title="Module execution", box=box.SIMPLE_HEAD, title_justify="left",
                      title_style="bold", header_style="bold cyan", width=self.width,
                      pad_edge=False)
        table.add_column("Phase", style="dim", no_wrap=True)
        table.add_column("Module", no_wrap=True)
        table.add_column("Runs", justify="right", no_wrap=True)
        table.add_column("Observations", justify="right", no_wrap=True)
        table.add_column("Time", justify="right", style="dim", no_wrap=True, min_width=6)
        table.add_column("Outcome", no_wrap=True, min_width=11)

        # Aggregate: one module can run many times (once per discovered subject).
        aggregated: Dict[Tuple[str, str], Dict[str, Any]] = {}
        order: List[Tuple[str, str]] = []
        for record in executions:
            if not isinstance(record, dict):
                continue
            key = (_shorten(record.get("phase"), 24), _shorten(record.get("module"), 24))
            if key not in aggregated:
                aggregated[key] = {"runs": 0, "observations": 0, "seconds": 0.0, "statuses": {}}
                order.append(key)
            entry = aggregated[key]
            entry["runs"] += 1
            entry["observations"] += _int(record.get("observations_ingested"))
            try:
                entry["seconds"] += float(record.get("duration_seconds") or 0.0)
            except (TypeError, ValueError):
                pass
            status = _shorten(record.get("status"), 24)
            entry["statuses"][status] = entry["statuses"].get(status, 0) + 1

        for phase, module in order:
            entry = aggregated[(phase, module)]
            statuses = entry["statuses"]
            # Report the worst outcome, never the most flattering one.
            for candidate in ("failed", "interrupted", "scope_rejected", "unreachable",
                              "skipped", "success", "no_results"):
                if candidate in statuses:
                    worst = candidate
                    break
            else:
                worst = "success"
            label = STATUS_LABELS.get(worst, worst)
            if len(statuses) > 1:
                label = f"{label} ({statuses[worst]}/{entry['runs']})"
            table.add_row(
                PHASE_SHORT.get(phase, phase),
                module,
                str(entry["runs"]),
                str(entry["observations"]) if entry["observations"] else "-",
                _duration(entry["seconds"]),
                Text(label, style=STATUS_STYLES.get(worst, "white")),
            )
        self.console.print(table)

    def _failures(self, result: Dict[str, Any]) -> None:
        executions = result.get("executions")
        failed = [r for r in (executions if isinstance(executions, list) else [])
                  if isinstance(r, dict) and r.get("status") in ("failed", "scope_rejected")]
        raw_errors = result.get("errors")
        errors = [e for e in (raw_errors if isinstance(raw_errors, list) else []) if isinstance(e, dict)]
        if not failed and not errors:
            return

        self.console.print()
        body = Text()
        limit = len(failed) if self.verbose else 8
        for record in failed[:limit]:
            style = STATUS_STYLES.get(str(record.get("status")), "red")
            body.append(f"{self.glyphs.get(str(record.get('status')), '!')} ", style=style)
            body.append(f"{_shorten(record.get('module'), 24)} ", style="bold")
            body.append(f"({_shorten(record.get('subject'), 44)})\n", style="dim")
            body.append(f"    {_shorten(record.get('error_type') or 'error', 40)}: "
                        f"{_shorten(record.get('error'), self.width - 12)}\n", style=style)
        if len(failed) > limit:
            body.append(f"{self.glyphs['bullet']} {len(failed) - limit} further module failure(s) "
                        f"— see the execution record, or re-run with --verbose\n", style="dim")

        for error in (errors if self.verbose else errors[:5]):
            body.append(f"{self.glyphs['scope_rejected']} ", style="yellow")
            body.append(f"{_shorten(error.get('stage') or 'run', 40)}: ", style="bold")
            body.append(f"{_shorten(error.get('error'), self.width - 12)}\n", style="yellow")
        if not self.verbose and len(errors) > 5:
            body.append(f"{self.glyphs['bullet']} {len(errors) - 5} further run error(s) "
                        f"— re-run with --verbose\n", style="dim")

        body.rstrip()  # Text.rstrip() mutates in place and returns None
        self.console.print(Panel(body, title="[bold yellow]Warnings and failures[/bold yellow]",
                                 border_style="yellow", box=box.ROUNDED, width=self.width))

    def _surface_table(self, result: Dict[str, Any]) -> None:
        correlation = result.get("correlation")
        summary = correlation.get("summary") if isinstance(correlation, dict) else None
        if not isinstance(summary, dict) or not summary:
            return
        by_type = summary.get("assets_by_type")
        by_type = by_type if isinstance(by_type, dict) else {}

        self.console.print()
        table = Table(title="Attack surface", box=box.SIMPLE_HEAD, title_justify="left",
                      title_style="bold", header_style="bold cyan", width=self.width,
                      pad_edge=False)
        table.add_column("Asset type", no_wrap=True)
        table.add_column("Count", justify="right", no_wrap=True)
        table.add_column("Correlation", style="dim")
        table.add_column("", justify="right", style="dim", no_wrap=True)

        rows = sorted(((_shorten(kind, 32), _int(count)) for kind, count in by_type.items()),
                      key=lambda kv: (-kv[1], kv[0]))
        facts = [
            ("Observations", summary.get("observations", 0)),
            ("Assets", summary.get("assets", 0)),
            ("Relationships", summary.get("relationships", 0)),
            ("Conflicts preserved", summary.get("conflicts", 0)),
            ("Negative results", summary.get("negative_results", 0)),
            ("Pending opportunities", summary.get("pending_opportunities", 0)),
            ("Ingestion errors", summary.get("ingestion_errors", 0)),
        ]
        for index in range(max(len(rows), len(facts))):
            left = (rows[index][0].replace("_", " "), str(rows[index][1])) if index < len(rows) else ("", "")
            right = (facts[index][0], _shorten(facts[index][1], 12)) if index < len(facts) else ("", "")
            table.add_row(left[0], left[1], right[0], right[1])

        if not rows:
            table.caption = "No assets were correlated into the graph during this run."
            table.caption_justify = "left"
        self.console.print(table)

    def _risk(self, result: Dict[str, Any], top: int) -> None:
        risk = result.get("risk")
        risk = risk if isinstance(risk, dict) else {}
        status = risk.get("status")
        self.console.print()

        if status in (None, "skipped"):
            self.note("Risk assessment: risk_engine was not part of this run.")
            return
        if status == "failed":
            self.warning(f"Risk assessment failed: {_shorten(risk.get('error'), self.width - 30)}")
            return

        summary = risk.get("summary")
        summary = summary if isinstance(summary, dict) else {}
        by_severity = summary.get("assets_by_severity")
        by_severity = by_severity if isinstance(by_severity, dict) else {}

        header = Text()
        for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            header.append(f" {name} ", style=SEVERITY_STYLES[name])
            header.append(f"{_int(by_severity.get(name))}   ", style="bold")
        self.console.print(Panel(
            header,
            title=f"[bold]Risk prioritization[/bold] "
                  f"[dim]({_int(summary.get('assets_assessed'))} assets, "
                  f"{_int(summary.get('signals'))} signals)[/dim]",
            border_style="magenta", box=box.ROUNDED, width=self.width))

        queue = self._investigation_queue(risk)
        queue_length = _int(summary.get("queue_length")) or len(queue)
        if not queue or top <= 0:
            if queue_length:
                self.note(f"Investigation queue holds {queue_length} entries — "
                          f"see {_sanitize(risk.get('output_path'))}")
            else:
                self.note("Investigation queue is empty at the configured minimum severity.")
        else:
            table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", width=self.width,
                          pad_edge=False, title_justify="left", title_style="bold",
                          title=f"Investigation queue (top {min(top, len(queue))} of {queue_length})")
            table.add_column("#", justify="right", style="dim", no_wrap=True)
            table.add_column("Severity", no_wrap=True)
            table.add_column("Conf.", style="dim", no_wrap=True)
            table.add_column("Asset", no_wrap=True)
            table.add_column("Why it is ranked here")
            # risk_assessment.json is risk_engine's raw output, not the
            # hardened report document: every cell is target-derived.
            for entry in queue[:top]:
                severity = _shorten(entry.get("severity", "INFO"), 12)
                table.add_row(
                    _shorten(entry.get("rank", ""), 6),
                    Text(severity, style=SEVERITY_STYLES.get(severity, "white")),
                    _shorten(entry.get("confidence", ""), 8),
                    _shorten(entry.get("value") or entry.get("asset_id"), 34),
                    _shorten(_join(entry.get("explanation")), 300),
                )
            self.console.print(table)

        extras = []
        if _int(risk.get("unresolved_conflicts")):
            extras.append(f"{_int(risk['unresolved_conflicts'])} unresolved fingerprint conflict(s)")
        if _int(risk.get("suspended_signals")):
            extras.append(f"{_int(risk['suspended_signals'])} signal(s) suspended pending conflict resolution")
        if _int(summary.get("out_of_scope_assets")):
            extras.append(f"{_int(summary['out_of_scope_assets'])} out-of-scope asset(s) assessed but never queued")
        if extras:
            self.note(f"{self.glyphs['bullet']} " + "; ".join(extras))
        self.note("Severity is a prioritization assessment of where to look first, "
                  "not proof of exploitability.")

    @staticmethod
    def _investigation_queue(risk: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Read the queue out of the assessment risk_engine actually wrote.

        The orchestrator result carries only the risk summary, so the ranked
        entries come from the artifact itself rather than being recomputed
        here — the CLI never scores anything.
        """
        path = risk.get("output_path")
        if not isinstance(path, str) or not path or not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as handle:
                assessment = json.load(handle)
        except (OSError, ValueError):
            return []
        queue = assessment.get("investigation_queue") if isinstance(assessment, dict) else None
        return [entry for entry in queue if isinstance(entry, dict)] if isinstance(queue, list) else []

    def _adaptive(self, result: Dict[str, Any]) -> None:
        adaptive = result.get("adaptive")
        adaptive = adaptive if isinstance(adaptive, dict) else {}
        opportunities = result.get("opportunities")
        opportunities = opportunities if isinstance(opportunities, dict) else {}
        manual_raw = adaptive.get("manual_review")
        manual = [m for m in (manual_raw if isinstance(manual_raw, list) else []) if isinstance(m, dict)]
        pending = opportunities.get("pending")
        pending = pending if isinstance(pending, list) else []
        deferred = adaptive.get("deferred")
        deferred = deferred if isinstance(deferred, list) else []
        if not (_int(adaptive.get("actions")) or manual or pending):
            return

        self.console.print()
        body = Text()
        body.append(
            f"{_int(adaptive.get('actions'))} follow-up action(s) fired across "
            f"{_int(adaptive.get('rounds'))} adaptive round(s).\n", style="white")
        if deferred:
            body.append(f"{len(deferred)} opportunity/ies deferred by the run budget.\n", style="dim")
        if manual:
            body.append(f"\n{len(manual)} opportunity/ies need manual verification:\n", style="yellow")
            for item in manual[: (len(manual) if self.verbose else 5)]:
                body.append(f"  {self.glyphs['bullet']} {_shorten(item.get('opportunity_type'), 40)} "
                            f"on {_shorten(item.get('target_value'), 40)} "
                            f"[{_shorten(item.get('priority'), 12)}]\n", style="yellow")
        if pending:
            body.append(f"\n{len(pending)} opportunity/ies still pending for the next run.\n",
                        style="dim")
        body.rstrip()
        self.console.print(Panel(body, title="[bold]Adaptive discovery[/bold]",
                                 border_style="blue", box=box.ROUNDED, width=self.width))

    def _decision_queue(self, result: Dict[str, Any]) -> None:
        entries = result.get("decision_queue")
        if not isinstance(entries, list) or not entries:
            return
        self.console.print()
        table = Table(title="Decision queue", box=box.SIMPLE_HEAD, title_justify="left",
                      title_style="bold", header_style="bold cyan", width=self.width,
                      pad_edge=False)
        table.add_column("Action", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Reason")
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            status = _shorten(entry.get("status", ""), 24)
            table.add_row(
                _shorten(entry.get("action"), 26),
                Text(STATUS_LABELS.get(status, status), style=STATUS_STYLES.get(status, "white")),
                _shorten(_join(entry.get("reason")), 400),
            )
        self.console.print(table)

    def _artifacts(self, result: Dict[str, Any],
                   report: Optional[Dict[str, Any]] = None) -> None:
        paths = result.get("output_paths")
        paths = paths if isinstance(paths, dict) else {}
        self.console.print()
        table = Table(title="Output artifacts", box=box.SIMPLE_HEAD, title_justify="left",
                      title_style="bold", header_style="bold cyan", width=self.width,
                      pad_edge=False)
        table.add_column("Artifact", no_wrap=True)
        table.add_column("Path", overflow="fold")
        table.add_column("Size", justify="right", style="dim", no_wrap=True)

        for key in ARTIFACT_ORDER:
            path = paths.get(key)
            label = ARTIFACT_LABELS.get(key, key)
            if not path or not isinstance(path, str):
                table.add_row(label, Text("not produced by this run", style="dim"), "")
                continue
            if os.path.isfile(path):
                table.add_row(label, _sanitize(os.path.abspath(path)), _file_size(path))
            else:
                table.add_row(label, Text(f"{_sanitize(os.path.abspath(path))} (not written)", style="dim"), "")

        # Reports come from report_generator.py; only paths it actually wrote
        # are shown, and a format it could not write is never listed.
        report_paths = (report or {}).get("output_paths")
        report_paths = report_paths if isinstance(report_paths, dict) else {}
        for fmt in (report or {}).get("formats") or ("html", "json", "text"):
            path = report_paths.get(fmt)
            label = f"Report ({_shorten(fmt, 12).upper()})"
            if isinstance(path, str) and path and os.path.isfile(path):
                table.add_row(label, _sanitize(os.path.abspath(path)), _file_size(path))
            elif report is not None:
                table.add_row(label, Text("not written — see the warning above", style="dim"), "")
        if report is None:
            table.add_row("Report", Text("not generated for this run", style="dim"), "")
        self.console.print(table)
        if report_paths.get("text"):
            self.note(f"The terminal report above is saved as text: {report_paths['text']}")
        if report_paths.get("json"):
            self.note(f"Machine-readable report for automation: {report_paths['json']}")


class LiveProgress:
    """
    Bridges the orchestrator's `progress_callback` events to the Presenter.

    Holds only display state. Every exception is swallowed here rather than
    propagated: a rendering problem must never damage a running scan (the
    orchestrator would otherwise record it as a run error).
    """

    def __init__(self, presenter: Presenter):
        self.presenter = presenter
        self._records: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._current_phase: Optional[str] = None
        self._progress: Optional["Progress"] = None
        self._task = None

    def __enter__(self) -> "LiveProgress":
        console = self.presenter.console
        self._progress = Progress(
            SpinnerColumn(style="cyan"),
            # markup=False: the description carries the subject, which for an
            # adaptive action is a URL out of the target's own HTML.
            TextColumn("{task.description}", style="cyan", markup=False),
            TimeElapsedColumn(),
            console=console,
            transient=True,
            disable=self.presenter.quiet or not console.is_terminal,
        )
        self._progress.start()
        self._task = self._progress.add_task("initializing", start=True)
        return self

    def pause(self) -> None:
        """Stop the live region so static panels render outside it."""
        if self._progress is not None:
            try:
                self._progress.stop()
            except Exception:
                pass

    def resume(self) -> None:
        if self._progress is not None:
            try:
                self._progress.start()
            except Exception:
                pass

    def __exit__(self, *exc_info: Any) -> None:
        if self._progress is not None:
            try:
                self._progress.stop()
            except Exception:
                pass
            self._progress = None

    def _describe(self, description: str) -> None:
        if self._progress is not None and self._task is not None:
            self._progress.update(self._task, description=description)

    def handle(self, event: Dict[str, Any]) -> None:
        try:
            self._handle(event)
        except Exception:  # never let the UI break a scan
            pass

    def _handle(self, event: Dict[str, Any]) -> None:
        kind = event.get("event")

        if kind == "run_started":
            self._describe("starting")
        elif kind == "module_started":
            phase = str(event.get("phase"))
            if phase != self._current_phase:
                self._current_phase = phase
                self.presenter.phase_heading(phase)
            self._describe(self.presenter.module_started(
                str(event.get("module")), event.get("subject")))
        elif kind == "module_finished":
            self.presenter.module_finished({
                "module": event.get("module"),
                "subject": event.get("subject"),
                "status": event.get("status"),
                "observations_ingested": event.get("observations_ingested"),
            })
        elif kind == "run_interrupted":
            self._describe("interrupted — saving collected evidence")
            self.presenter.blank()
            self.presenter.warning(
                "Interrupted. Preserving every discovery collected so far...")
        elif kind == "run_finished":
            self._describe("finalizing")


# ---------------------------------------------------------------------------
# 3. Execution
# ---------------------------------------------------------------------------

def _silence(stream: Any) -> None:
    """
    Point a closed-pipe stream at /dev/null.

    After a BrokenPipeError the stream's buffer still holds what could not be
    written, and the interpreter flushes both standard streams at exit: that
    flush would raise again, print "Exception ignored ... BrokenPipeError"
    and turn the exit status into 120. Redirecting the descriptor makes the
    flush succeed silently.
    """
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, stream.fileno())
        finally:
            os.close(devnull)
    except (OSError, ValueError, AttributeError):
        pass


def _stderr(message: str) -> None:
    """One plain line on stderr; never raises (stderr may be the closed pipe too)."""
    if sys.stderr is None:  # started with fd 2 closed; print() would fall back to stdout
        return
    try:
        print(f"{PROG}: {message}", file=sys.stderr, flush=True)
    except (OSError, ValueError):
        _silence(sys.stderr)


if Console is not None:  # pragma: no branch
    class _CliConsole(Console):  # type: ignore[misc]
        """
        The CLI's Console: a closed stdout stops output, not the run.

        Rich calls `on_broken_pipe()` when a write raises BrokenPipeError
        (`reconhound ... | head`). Its default raises SystemExit(1): silent,
        collides with EXIT_PARTIAL, and — inside the progress callback —
        aborts the orchestrator mid-run as a RUN_FAILED "SystemExit". Here
        the console goes quiet (Rich discards later buffers), stdout is
        pointed at /dev/null so the interpreter's own flush at exit cannot
        fail again (exit status 120), and the operator is told once on
        stderr. The run finishes, its artifacts are written, and the exit
        code still describes the run.
        """

        stdout_broken = False

        def on_broken_pipe(self) -> None:
            self.stdout_broken = True
            self.quiet = True
            _silence(self.file)
            _stderr("standard output was closed early (broken pipe); terminal output stopped. "
                    "The run continues and its artifacts are still written.")
else:  # pragma: no cover - rich missing; main() exits before a console is built
    _CliConsole = None  # type: ignore


def make_console(no_color: bool) -> "Console":
    """
    A Console that behaves in pipes, dumb terminals and CI as well as in Kali.

    Colour is decided once, by report_generator's policy (interactive TTY,
    honouring NO_COLOR, TERM=dumb, CI and FORCE_COLOR), and the same console
    prints both the CLI's panels and the terminal report. When colour is
    off the console is built with no colour system at all: `no_color`
    alone still emits bold/dim attributes, which is not "plain text".
    Markup and emoji codes are off, as on report_generator's console: no
    string printed here may be interpreted, only `Text` styles apply.
    """
    allowed = not no_color
    if allowed and report_generator is not None:
        allowed = report_generator.terminal_color_allowed(sys.stdout)
    options: Dict[str, Any] = {"highlight": False, "soft_wrap": False, "stderr": False,
                               "markup": False, "emoji": False}
    if not allowed:
        options.update({"no_color": True, "color_system": None})
    # A stdout that cannot encode a character (LANG=C without UTF-8 mode,
    # PYTHONIOENCODING=ascii) must show it as an escape, not raise
    # UnicodeEncodeError out of the first panel that contains it.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure) and getattr(sys.stdout, "errors", None) != "backslashreplace":
        try:
            reconfigure(errors="backslashreplace")
        except (OSError, ValueError, TypeError):
            pass
    console = _CliConsole(**options)
    # A terminal that reports fewer columns than a line can hold (COLUMNS=0
    # makes Rich print nothing at all) gets the narrowest layout the report
    # supports rather than no output.
    floor = report_generator.TERMINAL_MIN_WIDTH if report_generator is not None else 20
    if console.width < floor:
        console = _CliConsole(width=floor, **options)
    return console


def execute(args: argparse.Namespace, presenter: Presenter) -> Dict[str, Any]:
    """
    Configure and run the orchestrator, rendering its progress live.

    Returns the orchestrator's result document unchanged.
    """
    kwargs = build_orchestrator_kwargs(args)
    presenter.banner()

    # Construct before rendering the configuration: the constructor performs
    # target validation, mode/module resolution and the persisted-state
    # preflight, and does no network I/O. An invalid target therefore fails
    # here, before the panel could claim a run that is not going to happen.
    with LiveProgress(presenter) as progress:
        try:
            orchestrator = orch.Orchestrator(progress_callback=progress.handle, **kwargs)
        except (orch.ConfigurationError, orch.ScopeViolationError) as exc:
            raise CliError(str(exc), EXIT_USAGE) from exc
        except orch.OrchestratorError as exc:
            raise CliError(str(exc), EXIT_FATAL) from exc
        except OSError as exc:
            # Only the constructor touches the filesystem here (output
            # directory, persisted state); an OSError from terminal output
            # is a different thing and is handled by the console itself.
            raise CliError(f"Cannot use output directory {args.output_dir!r}: {exc}",
                           EXIT_FATAL) from exc
        progress.pause()
        presenter.configuration(orchestrator)
        progress.resume()
        presenter.run_started = True
        result = orchestrator.run()
    if not isinstance(result, dict):
        # The run happened — whatever it persisted is on disk — but nothing
        # can be reported from a result that is not the documented shape,
        # and it must not be mistaken for a clean run.
        raise CliError(
            f"The orchestrator returned {type(result).__name__} instead of a result document; "
            f"the run's own artifacts (if any) are in {os.path.abspath(args.output_dir)!r}.",
            EXIT_FATAL)
    return result


def generate_reports(result: Dict[str, Any], args: argparse.Namespace,
                     presenter: Presenter) -> Optional[Dict[str, Any]]:
    """
    Hand the finished run to report_generator.py.

    The CLI performs no rendering itself: it passes the orchestrator's own
    result as the execution record and lets the reporting layer read the
    graph and the assessment from the output directory. A reporting failure
    is reported and never fabricates a path.
    """
    try:
        report = report_generator.generate_report(
            execution=result, output_dir=args.output_dir, include_document=True)
    except report_generator.ReportError as exc:
        presenter.warning(f"Report generation failed: {_str(exc)}")
        return None
    except Exception as exc:
        if args.debug:
            debug_traceback(presenter.console, exc)
        presenter.warning(f"Report generation failed: {type(exc).__name__}: {_str(exc)}")
        return None
    if not isinstance(report, dict):
        presenter.warning(f"Report generation returned {type(report).__name__} instead of a "
                          f"report record; no report can be shown or listed.")
        return None
    # report_generator writes each format independently and records a format
    # it could not write instead of raising; that is still a failed piece of
    # requested work and is said so here, format by format.
    for failure in unwritten_formats(report):
        presenter.warning(f"Report format {failure['format'].upper()} could not be written: "
                          f"{failure['error']}")
    return report


def unwritten_formats(report: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    """The formats report_generator was asked for but could not write."""
    if not isinstance(report, dict) or not report:
        return []
    failures = []
    errors = report.get("errors")
    for error in (errors if isinstance(errors, list) else []):
        stage = str((error or {}).get("stage") or "") if isinstance(error, dict) else ""
        if stage.startswith("render_"):
            failures.append({"format": _shorten(stage[len("render_"):], 12),
                             "error": str(error.get("error") or "unknown error")})
    return failures


def debug_traceback(console: "Console", exc: BaseException) -> None:
    """
    The traceback behind --debug, as plain text through `_safe()`.

    Rich's pretty traceback would print the exception message raw: an
    escape sequence or a credential inside it (a URL a module was fetching,
    quoted by the library that failed) would reach the terminal untouched.
    """
    text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    # Indented as a block (wrapped lines included): the exception message is
    # the one part of a traceback that is not the CLI's own text.
    console.print(Padding(Text(_safe(text, 20000), style="dim"), (0, 0, 0, 4)), highlight=False)


def exit_code_for(result: Dict[str, Any]) -> int:
    """
    Map the orchestrator's run status onto a process exit code.

    Only the documented statuses map to their codes. A result whose status
    is missing or unknown is not a known-clean run and must not exit 0: it
    is reported as fatal so nothing downstream mistakes it for success.
    """
    status = result.get("status")
    if status == orch.RUN_INTERRUPTED or result.get("interrupted"):
        return EXIT_INTERRUPTED
    if status == orch.RUN_FAILED:
        return EXIT_FATAL
    if status == orch.RUN_COMPLETED_WITH_ERRORS:
        return EXIT_PARTIAL
    if status == orch.RUN_COMPLETED:
        return EXIT_OK
    return EXIT_FATAL


# ---------------------------------------------------------------------------
# 4. Entry point
# ---------------------------------------------------------------------------

def _dependency_error() -> Optional[CliError]:
    if _RICH_IMPORT_ERROR is not None:
        return CliError(
            f"ReconHound's terminal interface requires the 'rich' package "
            f"({type(_RICH_IMPORT_ERROR).__name__}: {_RICH_IMPORT_ERROR}).",
            EXIT_FATAL,
            hint="Install the project dependencies:  pip install -r requirements.txt",
        )
    if _ORCH_IMPORT_ERROR is not None:
        return CliError(
            f"ReconHound could not load its modules "
            f"({type(_ORCH_IMPORT_ERROR).__name__}: {_ORCH_IMPORT_ERROR}).",
            EXIT_FATAL,
            hint="Install the project dependencies:  pip install -r requirements.txt",
        )
    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    problem = _dependency_error()
    if problem is not None:
        # Rich may itself be the missing piece, so this path stays plain.
        print(f"reconhound: {problem.message}", file=sys.stderr)
        if problem.hint:
            print(f"reconhound: {problem.hint}", file=sys.stderr)
        return problem.exit_code

    # Last-resort handlers. Everything below reports its own failures on the
    # console; these only catch what happens while that reporting itself
    # runs (a Ctrl+C during a panel, a console that cannot be built), so no
    # code path can end in a traceback or a false exit status.
    try:
        return _run(args)
    except KeyboardInterrupt:
        _stderr("interrupted.")
        return EXIT_INTERRUPTED
    except Exception as exc:  # pragma: no cover - a defect in the CLI's own reporting
        if args.debug:
            _stderr(_safe("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
                          20000))
        _stderr(f"unexpected failure: {type(exc).__name__}: {_safe(exc, 500)}")
        return EXIT_FATAL


def _run(args: argparse.Namespace) -> int:
    console = make_console(args.no_color)
    presenter = Presenter(console, verbose=args.verbose, quiet=args.quiet)

    try:
        result = execute(args, presenter)
    except CliError as exc:
        presenter.failure(exc.message, exc.hint)
        return exc.exit_code
    except KeyboardInterrupt:
        # Orchestrator.run() absorbs the first Ctrl+C and returns a partial
        # result. One that reaches here arrived either before the run began
        # or during the orchestrator's final correlation/persistence (a
        # second Ctrl+C) — after modules ran and evidence was saved.
        console.print()
        if presenter.run_started:
            presenter.warning(
                "Interrupted while the run was finishing. Everything persisted before the "
                f"interrupt is in {os.path.abspath(args.output_dir)}; no report was generated "
                "and the execution record may still say the run is in progress.")
        else:
            presenter.warning("Interrupted before the run started. Nothing was executed.")
        return EXIT_INTERRUPTED
    except MemoryError:
        presenter.failure("Ran out of memory while executing the run.",
                          "Reduce the scan budget (--module, --passive-only) and retry.")
        return EXIT_FATAL
    except Exception as exc:
        if args.debug:
            debug_traceback(console, exc)
        presenter.failure(
            f"Unexpected failure: {type(exc).__name__}: {_str(exc)}",
            None if args.debug else "Re-run with --debug for the full traceback.",
        )
        return EXIT_FATAL

    # Reporting is part of finishing the run, and is performed even after an
    # interrupt: the partial state on disk is real and worth reporting.
    try:
        report = generate_reports(result, args, presenter)
    except KeyboardInterrupt:
        # report_generator writes atomically, so whatever it finished is
        # complete and whatever it did not is absent — nothing half-written.
        console.print()
        presenter.warning("Report generation interrupted; the run's own artifacts on disk are "
                          "complete and any report file that exists is complete.")
        return EXIT_INTERRUPTED

    try:
        presenter.summary(result, max(0, args.top), report)
    except KeyboardInterrupt:
        console.print()
        presenter.warning("Summary rendering interrupted; the artifacts on disk are complete.")
        return EXIT_INTERRUPTED
    except Exception as exc:
        # The run itself finished and the orchestrator persisted its result
        # before returning — a rendering failure must not misreport the run.
        if args.debug:
            debug_traceback(console, exc)
        presenter.warning(f"Could not render the full summary ({type(exc).__name__}: {_str(exc)}). "
                          f"The run's outcome is in the artifacts under "
                          f"{os.path.abspath(args.output_dir)}.")

    code = exit_code_for(result)
    if (report is None or unwritten_formats(report)) and code == EXIT_OK:
        # The reconnaissance succeeded but requested work did not complete.
        code = EXIT_PARTIAL
    return code


if __name__ == "__main__":
    sys.exit(main())
