"""
ReconHound Module 22 — core/orchestrator.py (adaptive execution coordination).

The orchestrator is ReconHound's central execution coordinator. It owns no
reconnaissance logic of its own: it decides *what* to run, *in what order*,
*against which subject*, and *why*, then routes every producer's output
through the one central asset graph (surface_mapper.py) and finally hands
that graph to risk_engine.py.

It is not a scanner, not a vulnerability engine, not a persistence system,
and never exploits anything it discovers.


ARCHITECTURAL PIPELINE (context.md §6, §10, §13)
------------------------------------------------

    Passive Intelligence
        -> Active Reconnaissance (network)
            -> Active Reconnaissance (web / client-side)
                -> Surface Mapper correlation (continuous)
                    -> Vulnerability Intelligence
                        -> Risk Engine
                            -> (reporting / CLI, implemented elsewhere)

surface_mapper.py ingestion is *not* a phase — it runs after every single
module invocation, so a crash at any point leaves a correlated graph that
already contains everything discovered up to that moment.


IMPLEMENTATION DECISIONS
------------------------

1.  **Producer modules run sequentially, never concurrently.**
    Every producer module constructs its own `PendingAssetsStore`, and that
    store persists by read-file / append / atomic-rewrite under a *per
    instance* `threading.Lock`. Two modules writing the same
    `output/pending_assets.json` from two threads would therefore interleave
    read-modify-write cycles and silently destroy each other's discoveries —
    exactly the data loss design principle 1 and 11 forbid. Concurrency in
    ReconHound belongs *inside* a module (active_recon's port scan,
    crawler's and endpoint_discovery's per-level batches), where a single
    store instance and its lock are shared, and the orchestrator drives that
    by passing `threads` through as each module's `max_workers`. This also
    makes a run deterministic and reproducible, which "run everything in
    parallel" would not be.

2.  **No competing persistence.** The orchestrator writes exactly one file
    of its own, `output/orchestrator_run.json` — the execution record and
    decision queue (context.md §9, design principle 8), which is derived
    state and is rewritten wholesale using the same write-to-temp +
    os.replace pattern every other module already uses. Discoveries live in
    `pending_assets.json` (written by the producers), correlated state in
    `surface_graph.json` (written by surface_mapper.py), and the assessment
    in `risk_assessment.json` (written by risk_engine.py). The orchestrator
    writes none of those three itself.

3.  **Idempotent re-execution.** Re-running against an existing output
    directory is safe. `pending_assets.json` is append-only across runs, and
    `SurfaceMapper.ingest_finding()` keys every observation by a content
    hash, so re-ingesting an existing file adds nothing. Consumed
    opportunities are never resurrected by surface_mapper.py, so an adaptive
    action never re-fires on a later run.

4.  **Scope propagates from the graph, not from module output.** Subjects
    for active modules are derived from in-scope assets in the correlated
    graph: hostnames the graph marked `in_scope`, and IPv4 addresses reached
    from such a hostname by a `hostname_to_ip` relationship. An IP learned
    only from a third-party CNAME is therefore never scanned. Modules
    re-validate scope themselves; that check is a second line of defence,
    not the first.

5.  **Risk engine timing.** risk_engine.py is invoked exactly once, last,
    after vuln_intel.py's CVE matches have been ingested, and is handed the
    live `SurfaceMapper` (`load_graph_state()` accepts an object exposing
    `.state`), so it assesses the same graph the run just built rather than
    a possibly stale file.

6.  **Adaptive discovery is bounded.** surface_mapper.py publishes
    reconnaissance opportunities; the orchestrator consumes them in at most
    `max_adaptive_rounds` rounds (default 1) and at most
    `max_adaptive_actions` actions per round, running one enabled suggested
    module per opportunity. Opportunities with no suggested module (e.g.
    subdomain-takeover manual verification) are surfaced for human review
    and deliberately left pending rather than consumed and lost.

7.  **Failure is classified, never swallowed.** Six outcomes are
    distinguished: success, success-with-no-results, recoverable module
    failure, scope rejection, skipped, and fatal orchestration failure.
    Only the last stops the run, and even then everything already
    discovered is ingested and persisted first. A `KeyboardInterrupt`
    unwinds the same way and yields a complete, JSON-safe partial result.

8.  **Timeouts.** The orchestrator passes the configured per-request
    `timeout` through to every module that accepts one. It deliberately does
    not add a wall-clock watchdog per module: killing a producer mid-write
    is precisely the class of interruption the crash-safe store design
    exists to avoid, and no module exposes a cooperative cancel.

9.  **No invented interfaces.** Every call below uses a signature that
    exists in the repository today. active_recon.py deliberately ships no
    default TCP port list ("no invented default, per this module's TCP-port
    decision"), so choosing one is an orchestration decision and lives here
    as `DEFAULT_TCP_PORTS`.

10. **Credentials come from the environment.** passive_intel.py,
    code_leak.py, osint_engine.py and vuln_intel.py already read their API
    keys from environment variables and degrade gracefully when they are
    absent. The orchestrator never accepts, stores, logs, or forwards a
    credential.


PUBLIC INTERFACE (for reconhound.py)
------------------------------------

    from reconhound.core.orchestrator import Orchestrator, run_orchestrator

    Orchestrator(target, output_dir=..., mode=..., ...).run() -> dict
    run_orchestrator(target, ...) -> dict

Both return one JSON-safe execution result document; see
`_build_result()` for its shape.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from reconhound import active_recon
from reconhound import api_recon
from reconhound import code_leak
from reconhound import crawler
from reconhound import endpoint_discovery
from reconhound import exposure_scan
from reconhound import http_analyzer
from reconhound import js_analyzer
from reconhound import osint_engine
from reconhound import passive_intel
from reconhound import passive_recon
from reconhound import risk_engine
from reconhound import screenshot
from reconhound import ssl_analyzer
from reconhound import supply_chain
from reconhound import surface_mapper
from reconhound import tech_fingerprint
from reconhound import vhost_scanner
from reconhound import vuln_intel
from reconhound import wayback_intel

from reconhound.surface_mapper import SurfaceMapper

MODULE_NAME = "orchestrator.py"

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OrchestratorError(RuntimeError):
    """Fatal orchestration failure — the run cannot meaningfully continue."""


class ConfigurationError(OrchestratorError):
    """Invalid configuration or input supplied to the orchestrator."""


class ScopeViolationError(OrchestratorError):
    """A requested target is not an authorized, in-scope reconnaissance target."""


# Every producer module defines its own ScopeError (modular independence).
# A scope rejection is a *policy* outcome, not a module defect, so it is
# classified separately from a recoverable failure.
SCOPE_ERRORS: Tuple[type, ...] = tuple({
    module.ScopeError
    for module in (
        passive_recon, passive_intel, code_leak, osint_engine, wayback_intel,
        active_recon, tech_fingerprint, vhost_scanner, endpoint_discovery,
        api_recon, crawler, js_analyzer, supply_chain, exposure_scan,
        http_analyzer, ssl_analyzer, screenshot, surface_mapper,
    )
    if hasattr(module, "ScopeError")
})


# ---------------------------------------------------------------------------
# Execution modes, phases, module registry
# ---------------------------------------------------------------------------

MODE_FULL = "full-scan"
MODE_PASSIVE = "passive-only"
MODE_ACTIVE = "active-only"
MODE_MODULE = "module"
VALID_MODES = (MODE_FULL, MODE_PASSIVE, MODE_ACTIVE, MODE_MODULE)

PHASE_PASSIVE = "passive"
PHASE_ACTIVE_NETWORK = "active_network"
PHASE_ACTIVE_WEB = "active_web"
PHASE_INTELLIGENCE = "intelligence"
PHASE_CORRELATION = "correlation"
PHASE_ADAPTIVE = "adaptive"

# Execution order inside each phase. This is the dependency order, not a
# preference: tech_fingerprint feeds endpoint_discovery's wordlist selection,
# crawler feeds js_analyzer's file list, js_analyzer feeds
# endpoint_discovery's js_data, and crawler feeds supply_chain's page list.
PHASE_MODULES: Dict[str, Tuple[str, ...]] = {
    PHASE_PASSIVE: (
        "passive_recon", "passive_intel", "code_leak", "osint_engine", "wayback_intel",
    ),
    PHASE_ACTIVE_NETWORK: (
        "active_recon", "ssl_analyzer", "vhost_scanner",
    ),
    PHASE_ACTIVE_WEB: (
        "http_analyzer", "tech_fingerprint", "crawler", "js_analyzer",
        "endpoint_discovery", "api_recon", "exposure_scan", "supply_chain",
        "screenshot",
    ),
    PHASE_INTELLIGENCE: (
        "vuln_intel", "risk_engine",
    ),
}

PHASE_ORDER: Tuple[str, ...] = (
    PHASE_PASSIVE, PHASE_ACTIVE_NETWORK, PHASE_ACTIVE_WEB, PHASE_INTELLIGENCE,
)

MODULE_PHASE: Dict[str, str] = {
    name: phase for phase, names in PHASE_MODULES.items() for name in names
}
ALL_MODULES: Tuple[str, ...] = tuple(
    name for phase in PHASE_ORDER for name in PHASE_MODULES[phase]
)

# vuln_intel.py and risk_engine.py never touch the target: vuln_intel queries
# public CVE databases about versions already observed, and risk_engine only
# reads the graph. Both therefore belong to a passive-only run.
PASSIVE_MODULES: Tuple[str, ...] = PHASE_MODULES[PHASE_PASSIVE] + PHASE_MODULES[PHASE_INTELLIGENCE]
ACTIVE_MODULES: Tuple[str, ...] = (
    PHASE_MODULES[PHASE_ACTIVE_NETWORK]
    + PHASE_MODULES[PHASE_ACTIVE_WEB]
    + PHASE_MODULES[PHASE_INTELLIGENCE]
)

# Execution outcomes.
STATUS_SUCCESS = "success"
STATUS_NO_RESULTS = "no_results"
STATUS_FAILED = "failed"
STATUS_SCOPE_REJECTED = "scope_rejected"
STATUS_SKIPPED = "skipped"
STATUS_INTERRUPTED = "interrupted"

# Run-level statuses.
RUN_COMPLETED = "completed"
RUN_COMPLETED_WITH_ERRORS = "completed_with_errors"
RUN_INTERRUPTED = "interrupted"
RUN_FAILED = "failed"


# ---------------------------------------------------------------------------
# Orchestration defaults
# ---------------------------------------------------------------------------

# active_recon.py ships no default TCP port list on purpose (see module
# docstring decision 9). Choosing which ports a full scan touches is an
# orchestration policy decision, so it lives here. The list is deliberately
# small and service-oriented: it covers every port context.md §10 item 7
# names by number for a protocol-specific check (21/22/25/587/3306/5432),
# plus the web ports surface_mapper.py already treats as web-follow-up
# worthy, plus a handful of universally common services.
DEFAULT_TCP_PORTS: Tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587,
    993, 995, 1433, 1521, 3000, 3306, 3389, 5000, 5432, 5900, 6379,
    8000, 8008, 8080, 8443, 8888, 9200, 11211, 27017,
)

# Ports that make an HTTP(S) base URL worth deriving, and their scheme.
WEB_PORT_SCHEMES: Dict[int, str] = {
    80: "http", 443: "https", 3000: "http", 5000: "http",
    8000: "http", 8008: "http", 8080: "http", 8443: "https", 8888: "http",
}
TLS_PORTS: Tuple[int, ...] = (443, 8443)

DEFAULT_TIMEOUT = 8.0
DEFAULT_THREADS = 10

# Budgets. Reconnaissance breadth grows combinatorially with discovered
# assets; every per-subject loop below is bounded so one run cannot expand
# without limit. All are overridable by the caller.
DEFAULT_MAX_SCAN_IPS = 10
DEFAULT_MAX_WEB_TARGETS = 10
DEFAULT_MAX_SSL_TARGETS = 20
DEFAULT_MAX_VHOST_IPS = 5
DEFAULT_MAX_JS_FILES = 50
DEFAULT_MAX_SCREENSHOTS = 25
DEFAULT_MAX_SUPPLY_CHAIN_PAGES = 25
DEFAULT_MAX_SUPPLY_CHAIN_SUBDOMAINS = 25
DEFAULT_MAX_ADAPTIVE_ROUNDS = 1
DEFAULT_MAX_ADAPTIVE_ACTIONS = 25


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_safe(value: Any, _depth: int = 0) -> Any:
    """
    Coerce anything into something json.dump() accepts without a `default=`.

    Module summaries originate in real network data and can contain sets,
    tuples, bytes and datetimes. Coercing once, on the way out, keeps the
    execution record serializable no matter what a producer returned.
    """
    if _depth > 24:
        return "<max serialization depth exceeded>"
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if value == value and value not in (float("inf"), float("-inf")) else str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(value[k], _depth + 1) for k in sorted(value, key=lambda k: str(k))}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item, _depth + 1) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_json_safe(item, _depth + 1) for item in value), key=lambda v: str(v))
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _compact_stats(result: Any) -> Dict[str, Any]:
    """
    Reduce a module summary to a bounded, numeric execution fingerprint.

    The full evidence for every discovery already lives in the graph; the
    execution record only needs enough to show what a module actually did.
    Copying whole module summaries in here would make the record grow with
    the size of the scan and duplicate the graph's own content.
    """
    if not isinstance(result, dict):
        return {}
    stats: Dict[str, Any] = {}
    for key in sorted(result):
        value = result[key]
        if isinstance(value, bool):
            stats[key] = value
        elif isinstance(value, (int, float)):
            stats[key] = value
        elif isinstance(value, (list, tuple, set)):
            stats[f"{key}_count"] = len(value)
        elif isinstance(value, str) and key in ("status", "fetch_status"):
            stats[key] = value
    nested = result.get("stats")
    if isinstance(nested, dict):
        for key in sorted(nested):
            value = nested[key]
            if isinstance(value, (bool, int, float, str)):
                stats[f"stats.{key}"] = value
    counts = result.get("counts")
    if isinstance(counts, dict):
        for key in sorted(counts):
            value = counts[key]
            if isinstance(value, (bool, int, float, str)):
                stats[f"counts.{key}"] = value
    return stats


def _module_error_count(result: Any) -> int:
    if isinstance(result, dict) and isinstance(result.get("errors"), list):
        return len(result["errors"])
    return 0


def _hostname_of(url: Any) -> Optional[str]:
    try:
        return urllib.parse.urlsplit(str(url)).hostname
    except ValueError:
        return None


def _base_url(host: str, port: int) -> str:
    scheme = WEB_PORT_SCHEMES.get(port, "http")
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host if default_port else f"{host}:{port}"
    return f"{scheme}://{netloc}/"


def _is_ipv4(value: Any) -> bool:
    parts = str(value).split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True


# ---------------------------------------------------------------------------
# Execution-record persistence
# ---------------------------------------------------------------------------


class ExecutionRecordStore:
    """
    Atomic JSON persistence for <output_dir>/orchestrator_run.json.

    Same write-to-temp + os.replace pattern as every other store in the
    project. The execution record is a single derived document (the run's
    decision queue and per-module outcomes), so it is rewritten wholesale
    rather than appended to, and is re-saved after every module so an
    interrupted run still leaves an accurate account of what ran and why.
    """

    def __init__(self, output_dir: str = "output", filename: str = "orchestrator_run.json"):
        self.output_dir = output_dir
        self.path = os.path.join(output_dir, filename)
        self._lock = threading.Lock()
        os.makedirs(self.output_dir, exist_ok=True)

    def save(self, record: Dict[str, Any]) -> str:
        with self._lock:
            dir_name = os.path.dirname(self.path) or "."
            fd, tmp_path = tempfile.mkstemp(prefix=".orchestrator_run_", dir=dir_name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(_json_safe(record), handle, indent=2, sort_keys=True)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_path, self.path)
            except BaseException:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                raise
            return self.path

    def load(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if not os.path.exists(self.path):
                return None
            try:
                with open(self.path, "r", encoding="utf-8") as handle:
                    content = handle.read().strip()
                return json.loads(content) if content else None
            except (json.JSONDecodeError, ValueError, OSError):
                # A damaged previous record is never fatal — it is derived
                # state, and the current run is about to replace it.
                return None


# ---------------------------------------------------------------------------
# Decision queue (context.md §9, design principle 8)
# ---------------------------------------------------------------------------


class DecisionQueue:
    """
    Every significant orchestrator action, recorded with an explicit reason.

    Decisions are recorded *before* the action is attempted and updated with
    the outcome afterwards, so an interrupted or crashed run still shows what
    it was doing and why.
    """

    def __init__(self) -> None:
        self._entries: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def record(self, action: str, reason: str, *, module: Optional[str] = None,
               phase: Optional[str] = None, subject: Optional[Any] = None,
               status: str = "started") -> Dict[str, Any]:
        entry = {
            "sequence": len(self._entries) + 1,
            "at": _now(),
            "phase": phase,
            "module": module,
            "subject": subject,
            "action": action,
            "reason": f"[REASON: {reason}]",
            "status": status,
        }
        with self._lock:
            self._entries.append(entry)
        return entry

    @staticmethod
    def complete(entry: Dict[str, Any], status: str, **extra: Any) -> None:
        entry["status"] = status
        entry["completed_at"] = _now()
        entry.update(extra)

    def entries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries)


# ---------------------------------------------------------------------------
# The orchestrator
# ---------------------------------------------------------------------------


class Orchestrator:
    """
    ReconHound's adaptive execution coordinator.

    Owns the single `SurfaceMapper` instance for a run, decides which module
    runs against which subject in which order, isolates per-module failures,
    and hands the finished graph to risk_engine.py.
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "output",
        mode: str = MODE_FULL,
        modules: Optional[Sequence[str]] = None,
        timeout: float = DEFAULT_TIMEOUT,
        threads: int = DEFAULT_THREADS,
        wordlists_dir: Optional[str] = None,
        tcp_ports: Optional[Sequence[int]] = None,
        max_scan_ips: int = DEFAULT_MAX_SCAN_IPS,
        max_web_targets: int = DEFAULT_MAX_WEB_TARGETS,
        max_ssl_targets: int = DEFAULT_MAX_SSL_TARGETS,
        max_vhost_ips: int = DEFAULT_MAX_VHOST_IPS,
        max_js_files: int = DEFAULT_MAX_JS_FILES,
        max_screenshots: int = DEFAULT_MAX_SCREENSHOTS,
        max_supply_chain_pages: int = DEFAULT_MAX_SUPPLY_CHAIN_PAGES,
        max_supply_chain_subdomains: int = DEFAULT_MAX_SUPPLY_CHAIN_SUBDOMAINS,
        max_adaptive_rounds: int = DEFAULT_MAX_ADAPTIVE_ROUNDS,
        max_adaptive_actions: int = DEFAULT_MAX_ADAPTIVE_ACTIONS,
        min_risk_severity: str = risk_engine.SEVERITY_LOW,
        stale_after_days: Optional[float] = None,
        persist_execution_record: bool = True,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        # -- configuration validation (invalid input is fatal, and fails
        #    before any network activity or state mutation happens) --------
        try:
            self.target = passive_recon.validate_target(target)
        except passive_recon.ScopeError as exc:
            raise ScopeViolationError(str(exc)) from exc
        except Exception as exc:  # not a string at all, etc.
            raise ConfigurationError(f"Invalid target {target!r}: {exc}") from exc

        if mode not in VALID_MODES:
            raise ConfigurationError(
                f"Invalid mode {mode!r}; must be one of {list(VALID_MODES)}"
            )
        self.mode = mode

        self.selected_modules = self._resolve_modules(mode, modules)

        try:
            self.timeout = float(timeout)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"timeout must be a number: {exc}") from exc
        if self.timeout <= 0:
            raise ConfigurationError("timeout must be greater than zero")

        try:
            self.threads = int(threads)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"threads must be an integer: {exc}") from exc
        if self.threads < 1:
            raise ConfigurationError("threads must be at least 1")

        if min_risk_severity not in risk_engine.VALID_SEVERITIES:
            raise ConfigurationError(
                f"Invalid min_risk_severity {min_risk_severity!r}; must be one of "
                f"{sorted(risk_engine.VALID_SEVERITIES)}"
            )

        self.output_dir = output_dir
        self.wordlists_dir = wordlists_dir
        self.tcp_ports = [int(p) for p in (tcp_ports if tcp_ports is not None else DEFAULT_TCP_PORTS)]
        self.min_risk_severity = min_risk_severity
        self.stale_after_days = stale_after_days
        self.persist_execution_record = persist_execution_record
        self.progress_callback = progress_callback

        self.limits = {
            "max_scan_ips": self._positive_int(max_scan_ips, "max_scan_ips"),
            "max_web_targets": self._positive_int(max_web_targets, "max_web_targets"),
            "max_ssl_targets": self._positive_int(max_ssl_targets, "max_ssl_targets"),
            "max_vhost_ips": self._positive_int(max_vhost_ips, "max_vhost_ips"),
            "max_js_files": self._positive_int(max_js_files, "max_js_files"),
            "max_screenshots": self._positive_int(max_screenshots, "max_screenshots"),
            "max_supply_chain_pages": self._positive_int(max_supply_chain_pages, "max_supply_chain_pages"),
            "max_supply_chain_subdomains": self._positive_int(
                max_supply_chain_subdomains, "max_supply_chain_subdomains"),
            "max_adaptive_rounds": self._non_negative_int(max_adaptive_rounds, "max_adaptive_rounds"),
            "max_adaptive_actions": self._non_negative_int(max_adaptive_actions, "max_adaptive_actions"),
        }

        # -- run state ----------------------------------------------------
        self.decisions = DecisionQueue()
        self.executions: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, Any]] = []
        self.phases: List[Dict[str, Any]] = []
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None
        self.status: str = "not_started"
        self.interrupted = False
        self._execution_seq = 0

        # Cross-module data hand-offs collected during the run.
        self._historical_data: List[Dict[str, Any]] = []
        self._js_data: List[Dict[str, Any]] = []
        self._technology_by_url: Dict[str, Dict[str, Any]] = {}
        self._crawled_pages: List[str] = []
        self._risk: Dict[str, Any] = {"status": STATUS_SKIPPED}

        self.record_store = ExecutionRecordStore(output_dir=output_dir)

        # -- the one shared graph for this run ----------------------------
        # A corrupt persisted graph is fatal *before* anything runs: silently
        # discarding it would destroy a previous run's correlated state.
        try:
            self.mapper = SurfaceMapper(target=self.target, output_dir=output_dir)
        except surface_mapper.PersistenceError as exc:
            raise OrchestratorError(
                f"Cannot start: existing surface graph in {output_dir!r} is unreadable. "
                f"Move it aside or choose a different --output-dir. ({exc})"
            ) from exc
        except surface_mapper.ScopeError as exc:
            raise ScopeViolationError(str(exc)) from exc

        self._preflight_pending_assets()

    # -- configuration helpers -------------------------------------------

    @staticmethod
    def _positive_int(value: Any, name: str) -> int:
        try:
            out = int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"{name} must be an integer: {exc}") from exc
        if out < 1:
            raise ConfigurationError(f"{name} must be at least 1")
        return out

    @staticmethod
    def _non_negative_int(value: Any, name: str) -> int:
        try:
            out = int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"{name} must be an integer: {exc}") from exc
        if out < 0:
            raise ConfigurationError(f"{name} must not be negative")
        return out

    @staticmethod
    def _resolve_modules(mode: str, modules: Optional[Sequence[str]]) -> List[str]:
        """
        Resolve the requested execution mode into an ordered module set.

        Module names may be given with or without the `.py` suffix, matching
        both `--module js_analyzer` and the `suggested_modules` values
        surface_mapper.py publishes on its opportunities.
        """
        if mode == MODE_MODULE:
            if not modules:
                raise ConfigurationError("Mode 'module' requires at least one module name.")
        elif mode == MODE_PASSIVE:
            allowed: Tuple[str, ...] = PASSIVE_MODULES
        elif mode == MODE_ACTIVE:
            allowed = ACTIVE_MODULES
        else:
            allowed = ALL_MODULES

        if modules:
            requested: List[str] = []
            unknown: List[str] = []
            for raw in modules:
                name = str(raw).strip()
                if name.endswith(".py"):
                    name = name[:-3]
                if name not in MODULE_PHASE:
                    unknown.append(str(raw))
                elif name not in requested:
                    requested.append(name)
            if unknown:
                raise ConfigurationError(
                    f"Unknown module(s): {unknown}. Known modules: {sorted(MODULE_PHASE)}"
                )
            if mode != MODE_MODULE:
                out_of_mode = [n for n in requested if n not in allowed]
                if out_of_mode:
                    raise ConfigurationError(
                        f"Module(s) {out_of_mode} are not part of mode {mode!r}."
                    )
                selected = set(requested)
            else:
                selected = set(requested)
        else:
            selected = set(allowed)

        return [name for name in ALL_MODULES if name in selected]

    def _preflight_pending_assets(self) -> None:
        """
        Refuse to start against an unreadable pending_assets.json.

        Every producer module appends to that file via a read/append/rewrite
        cycle that raises on a corrupt file, so starting a run here would
        mean every module failing to persist anything it discovered. Failing
        now costs nothing; failing later costs the whole run's evidence.
        """
        path = os.path.join(self.output_dir, "pending_assets.json")
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                content = handle.read().strip()
        except OSError as exc:
            raise OrchestratorError(f"Cannot read {path!r}: {exc}") from exc
        if not content:
            return
        try:
            records = json.loads(content)
        except json.JSONDecodeError as exc:
            raise OrchestratorError(
                f"Cannot start: existing {path!r} is not valid JSON ({exc}). No module could "
                f"persist a discovery to it. Move it aside or choose a different --output-dir."
            ) from exc
        if not isinstance(records, list):
            raise OrchestratorError(
                f"Cannot start: {path!r} root must be a JSON array of finding records."
            )

    # -- progress ---------------------------------------------------------

    def _emit(self, event: Dict[str, Any]) -> None:
        if self.progress_callback is None:
            return
        try:
            self.progress_callback(event)
        except Exception as exc:  # a broken UI callback must never abort a scan
            self.errors.append({"stage": "progress_callback", "error": str(exc)})

    def _enabled(self, module_name: str) -> bool:
        return module_name in self.selected_modules

    # =====================================================================
    # Correlation — surface_mapper.py ingestion after every module
    # =====================================================================

    def _ingest(self, *, phase: str, after: str) -> Dict[str, Any]:
        """
        Route everything the producers just persisted through the central
        graph. Idempotent: observations are keyed by content hash, so a
        record already ingested is skipped, and re-reading the append-only
        pending_assets.json never duplicates anything.
        """
        before = len(self.mapper.state["observations"])
        before_errors = len(self.mapper.state["ingestion_errors"])
        result: Dict[str, Any]
        try:
            result = self.mapper.ingest_pending_assets_file()
        except surface_mapper.PersistenceError as exc:
            # Recoverable at the run level: the graph already holds
            # everything ingested so far and is saved below.
            self.errors.append({"stage": "correlation", "after": after, "error": str(exc)})
            self.decisions.record(
                "correlate", f"ingestion of pending_assets.json failed after {after}: {exc}",
                module="surface_mapper", phase=PHASE_CORRELATION, status=STATUS_FAILED,
            )
            result = {"total": 0, "ingested": 0, "duplicates": 0, "errors": 1, "error": str(exc)}
        new = len(self.mapper.state["observations"]) - before
        new_errors = len(self.mapper.state["ingestion_errors"]) - before_errors
        try:
            self.mapper.save()
        except Exception as exc:
            self.errors.append({"stage": "graph_persistence", "after": after, "error": str(exc)})
        return {
            "after": after, "phase": phase,
            "new_observations": new, "ingestion_errors": new_errors,
            **{k: v for k, v in result.items() if k in ("total", "ingested", "duplicates", "errors", "note", "error")},
        }

    # =====================================================================
    # Module invocation with failure isolation
    # =====================================================================

    def _invoke(
        self,
        module_name: str,
        subject: Any,
        reason: str,
        fn: Callable[..., Any],
        *args: Any,
        phase: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Run one module against one subject, isolate its failure, and route
        whatever it persisted into the graph.

        Ingestion happens in a `finally` block: a module that raised halfway
        through has still persisted every discovery it completed before the
        failure (crash-safe persistence, design principle 1), and that
        evidence must not be lost because of what came after it.
        """
        phase = phase or MODULE_PHASE.get(module_name, PHASE_ACTIVE_WEB)
        self._execution_seq += 1
        execution_id = f"exec:{self._execution_seq:04d}:{module_name}"
        decision = self.decisions.record(
            f"run {module_name}", reason, module=module_name, phase=phase, subject=subject,
        )
        record: Dict[str, Any] = {
            "execution_id": execution_id,
            "module": module_name,
            "phase": phase,
            "subject": subject,
            "status": STATUS_SUCCESS,
            "started_at": _now(),
            "error": None,
            "error_type": None,
            "module_error_count": 0,
            "observations_ingested": 0,
            "stats": {},
        }
        self._emit({"event": "module_started", "module": module_name, "phase": phase, "subject": subject})
        started = time.monotonic()
        result: Any = None
        try:
            result = fn(*args, **kwargs)
            record["stats"] = _compact_stats(result)
            record["module_error_count"] = _module_error_count(result)
        except SCOPE_ERRORS as exc:
            record["status"] = STATUS_SCOPE_REJECTED
            record["error"] = str(exc)
            record["error_type"] = type(exc).__name__
        except KeyboardInterrupt:
            record["status"] = STATUS_INTERRUPTED
            record["error"] = "interrupted by user"
            record["error_type"] = "KeyboardInterrupt"
            raise
        except Exception as exc:
            # Recoverable module failure: recorded in structured form, never
            # swallowed, and never allowed to terminate independent work.
            record["status"] = STATUS_FAILED
            record["error"] = str(exc)
            record["error_type"] = type(exc).__name__
        finally:
            record["duration_seconds"] = round(time.monotonic() - started, 3)
            record["finished_at"] = _now()
            ingest = self._ingest(phase=phase, after=execution_id)
            record["observations_ingested"] = ingest["new_observations"]
            record["ingestion"] = ingest
            if record["status"] == STATUS_SUCCESS and record["observations_ingested"] == 0:
                # Expected, normal outcome — a check that found nothing is a
                # result, not a failure (negative-result memory, context.md §8).
                record["status"] = STATUS_NO_RESULTS
            DecisionQueue.complete(
                decision, record["status"],
                observations_ingested=record["observations_ingested"],
                error=record["error"],
            )
            self.executions.append(record)
            self._emit({
                "event": "module_finished", "module": module_name, "phase": phase,
                "subject": subject, "status": record["status"],
                "observations_ingested": record["observations_ingested"],
            })
            self._save_record()

        # The stored record deliberately holds only the compact fingerprint:
        # the full module summary is orders of magnitude larger, duplicates
        # what already reached the graph, and would make
        # orchestrator_run.json grow with the size of the scan. The caller
        # still gets it for in-run data hand-offs.
        return {**record, "result": result}

    def _skip(self, module_name: str, reason: str, *, phase: Optional[str] = None,
              subject: Any = None) -> None:
        """Record a module that was enabled but had nothing to run against."""
        phase = phase or MODULE_PHASE.get(module_name, PHASE_ACTIVE_WEB)
        self._execution_seq += 1
        decision = self.decisions.record(
            f"skip {module_name}", reason, module=module_name, phase=phase,
            subject=subject, status=STATUS_SKIPPED,
        )
        DecisionQueue.complete(decision, STATUS_SKIPPED)
        self.executions.append({
            "execution_id": f"exec:{self._execution_seq:04d}:{module_name}",
            "module": module_name, "phase": phase, "subject": subject,
            "status": STATUS_SKIPPED, "started_at": _now(), "finished_at": _now(),
            "duration_seconds": 0.0, "error": None, "error_type": None,
            "module_error_count": 0, "observations_ingested": 0,
            "stats": {}, "skip_reason": reason,
        })

    # =====================================================================
    # Scope-aware derivation of subjects from the correlated graph
    # =====================================================================

    def _assets_of_type(self, asset_type: str) -> List[Dict[str, Any]]:
        return [a for a in self.mapper.state["assets"].values() if a.get("asset_type") == asset_type]

    def in_scope_hostnames(self) -> List[str]:
        """Hostnames the graph itself marked in scope, target first."""
        hosts = {
            str(a["value"])
            for a in self._assets_of_type(surface_mapper.ASSET_HOSTNAME)
            if a.get("in_scope") is True and a.get("value")
        }
        hosts.add(self.target)
        ordered = sorted(hosts)
        if self.target in ordered:
            ordered.remove(self.target)
            ordered.insert(0, self.target)
        return ordered

    def out_of_scope_hostnames(self) -> List[str]:
        return sorted({
            str(a["value"])
            for a in self._assets_of_type(surface_mapper.ASSET_HOSTNAME)
            if a.get("in_scope") is False and a.get("value")
        })

    def _hostnames_for_ip(self, ip: str) -> List[str]:
        ip_id = surface_mapper._aid(surface_mapper.ASSET_IP, ip)
        hosts: Set[str] = set()
        for rel in self.mapper.state["relationships"].values():
            if rel.get("rel_type") != surface_mapper.REL_HOSTNAME_TO_IP or rel.get("to_asset") != ip_id:
                continue
            host_asset = self.mapper.state["assets"].get(rel.get("from_asset"))
            if host_asset and host_asset.get("in_scope") is True and host_asset.get("value"):
                hosts.add(str(host_asset["value"]))
        return sorted(hosts)

    def scannable_ips(self) -> List[str]:
        """
        IPv4 addresses that an in-scope hostname actually resolves to.

        Scope propagation lives here: an IP reached only from a third-party
        CNAME or from a passive-intel neighbour record has no
        `hostname_to_ip` edge from an in-scope host and is therefore never
        handed to an active module. run_active_recon()/run_vhost_scan()
        accept IPv4 only, so IPv6 assets are excluded here rather than
        failing one call at a time.
        """
        ips: Set[str] = set()
        for rel in self.mapper.state["relationships"].values():
            if rel.get("rel_type") != surface_mapper.REL_HOSTNAME_TO_IP:
                continue
            host_asset = self.mapper.state["assets"].get(rel.get("from_asset"))
            ip_asset = self.mapper.state["assets"].get(rel.get("to_asset"))
            if not host_asset or not ip_asset:
                continue
            if host_asset.get("in_scope") is not True:
                continue
            value = ip_asset.get("value")
            if value and _is_ipv4(value):
                ips.add(str(value))
        return sorted(ips)

    def _open_ports_by_ip(self) -> Dict[str, List[int]]:
        by_ip: Dict[str, Set[int]] = {}
        for asset in self._assets_of_type(surface_mapper.ASSET_PORT):
            value = asset.get("value")
            if not isinstance(value, dict):
                continue
            if str(value.get("protocol", "tcp")).lower() != "tcp":
                continue
            status = asset.get("attributes", {}).get("status", {}).get("value")
            if status not in (None, "open"):
                continue
            try:
                port = int(value.get("port"))
            except (TypeError, ValueError):
                continue
            ip = str(value.get("ip") or "")
            if ip:
                by_ip.setdefault(ip, set()).add(port)
        return {ip: sorted(ports) for ip, ports in by_ip.items()}

    def web_base_urls(self) -> List[str]:
        """
        Base URLs worth running the web modules against.

        Preferred source is observed open web ports on IPs an in-scope
        hostname resolves to. When no port evidence exists (a passive-only
        run, or active_recon disabled), fall back to https:// on every
        in-scope hostname that actually resolves — still strictly in scope,
        just less informed.
        """
        urls: List[str] = []
        seen: Set[str] = set()

        def _add(url: str) -> None:
            if url not in seen:
                seen.add(url)
                urls.append(url)

        scannable = set(self.scannable_ips())
        open_ports = self._open_ports_by_ip()
        for ip in sorted(scannable):
            for port in open_ports.get(ip, []):
                if port not in WEB_PORT_SCHEMES:
                    continue
                for host in self._hostnames_for_ip(ip):
                    _add(_base_url(host, port))

        if not urls:
            for host in self.in_scope_hostnames():
                host_asset = self.mapper.get_asset(
                    surface_mapper._aid(surface_mapper.ASSET_HOSTNAME, host))
                resolves = bool(
                    host_asset
                    and (host_asset.get("attributes", {}).get("dns_a")
                         or host_asset.get("attributes", {}).get("dns_aaaa"))
                )
                if resolves or host == self.target:
                    _add(f"https://{host}/")

        # Deterministic ordering with the target's own origin first.
        urls.sort(key=lambda u: (0 if _hostname_of(u) == self.target else 1, u))
        return urls[: self.limits["max_web_targets"]]

    def ssl_targets(self) -> List[Tuple[str, int]]:
        """(hostname, port) pairs worth a TLS inspection."""
        pairs: Set[Tuple[str, int]] = set()
        open_ports = self._open_ports_by_ip()
        for ip in self.scannable_ips():
            for port in open_ports.get(ip, []):
                if port in TLS_PORTS:
                    for host in self._hostnames_for_ip(ip):
                        pairs.add((host, port))
        for host in self.in_scope_hostnames():
            pairs.add((host, ssl_analyzer.DEFAULT_PORT))
        ordered = sorted(pairs, key=lambda p: (0 if p[0] == self.target else 1, p[0], p[1]))
        return ordered[: self.limits["max_ssl_targets"]]

    def javascript_urls(self) -> List[str]:
        """
        In-scope JavaScript files worth analyzing.

        Two sources, because they are genuinely different. crawler.py emits
        its discoveries as `javascript_reference` findings, a type
        surface_mapper.py has no dedicated handler for, so those land as
        generic finding assets rather than as `javascript` assets — the raw
        observation is the established hand-off (run_js_analyzer() documents
        accepting "crawler.py's raw `javascript_reference` finding records").
        `javascript` assets proper come from js_analyzer.py's and
        supply_chain.py's own output, and matter on a re-run where the
        crawler is not repeated.
        """
        urls: Set[str] = set()

        for observation in self.mapper.state["observations"].values():
            if observation.get("type") != "javascript_reference":
                continue
            value = observation.get("value")
            if not isinstance(value, dict):
                continue
            url = value.get("url")
            if not url:
                continue
            host = _hostname_of(url)
            if host and surface_mapper.is_in_scope(host, self.target):
                urls.add(str(url))

        for asset in self._assets_of_type(surface_mapper.ASSET_JAVASCRIPT):
            if asset.get("in_scope") is True and asset.get("value"):
                urls.add(str(asset["value"]))

        return sorted(urls)[: self.limits["max_js_files"]]

    def crawled_page_urls(self) -> List[str]:
        """
        In-scope pages crawler.py actually fetched.

        Read from the graph rather than only from this run's crawler return
        value, so a resumed run (where the crawl already happened) still has
        real pages to hand to supply_chain.py and screenshot.py.
        """
        urls: Set[str] = set(self._crawled_pages)
        for observation in self.mapper.state["observations"].values():
            if observation.get("type") != "crawled_url":
                continue
            value = observation.get("value")
            url = value.get("url") if isinstance(value, dict) else None
            if not url:
                continue
            host = _hostname_of(url)
            if host and surface_mapper.is_in_scope(host, self.target):
                urls.add(str(url))
        return sorted(urls)

    def endpoint_urls(self) -> List[str]:
        """In-scope, absolute endpoint URLs the graph knows about."""
        return sorted({
            str(a["value"])
            for a in self._assets_of_type(surface_mapper.ASSET_ENDPOINT)
            if a.get("in_scope") is True and "://" in str(a.get("value") or "")
        })

    def technology_observations(self) -> List[Dict[str, Any]]:
        """
        Technology/version observations for vuln_intel.py.

        Drawn from the correlated graph rather than from tech_fingerprint.py's
        return value, so observations that reached the graph from any source
        (and from earlier runs) are covered, and duplicates are already merged.
        Keys match vuln_intel.normalize_technology_observation()'s contract.
        """
        observations: List[Dict[str, Any]] = []
        for asset in sorted(self._assets_of_type(surface_mapper.ASSET_TECHNOLOGY),
                            key=lambda a: str(a.get("id"))):
            value = asset.get("value")
            if not isinstance(value, dict) or not value.get("name"):
                continue
            if asset.get("in_scope") is False:
                continue
            attributes = asset.get("attributes", {})
            version_attr = attributes.get("version", {})
            version = version_attr.get("value")
            if not version:
                continue  # versionless observations yield no CVE match
            # `target` must be a hostname, not a URL. vuln_intel.py copies
            # this value straight onto the finding it persists, and
            # surface_mapper.py resolves a finding's `target` as a hostname:
            # handing it "https://example.com/" would mint a hostname asset
            # named after a URL and mark it out of scope.
            scope = value.get("scope")
            host = _hostname_of(scope) if "://" in str(scope) else str(scope or self.target)
            observations.append({
                "technology": str(value["name"]),
                "version": str(version),
                "confidence": version_attr.get("confidence", surface_mapper.CONFIDENCE_MEDIUM),
                "evidence": [
                    f"technology asset {asset['id']} observed on {scope!r} by "
                    f"{', '.join(version_attr.get('sources', []) or ['unknown'])}"
                ],
                "target": host or self.target,
            })
        return observations

    def _technology_for(self, url: str) -> Optional[Dict[str, Any]]:
        """
        tech_fingerprint.py's technology summary for a base URL, used by
        endpoint_discovery.select_wordlists_for_technology().
        """
        if url in self._technology_by_url:
            return self._technology_by_url[url]
        host = _hostname_of(url)
        for other_url, summary in self._technology_by_url.items():
            if _hostname_of(other_url) == host:
                return summary
        return None

    # =====================================================================
    # Phase 1 — passive intelligence
    # =====================================================================

    def _run_passive_phase(self) -> None:
        target = self.target

        if self._enabled("passive_recon"):
            self._invoke(
                "passive_recon", target,
                "authorized target requires baseline DNS/WHOIS/TLS/ASN infrastructure intelligence "
                "before any active interaction",
                passive_recon.run_passive_recon,
                target, output_dir=self.output_dir, timeout=self.timeout,
            )

        if self._enabled("passive_intel"):
            # Seed with IPs the graph already knows resolve from in-scope
            # hostnames, so external-database lookups are targeted rather
            # than blind hostname searches.
            seed_ips = self.scannable_ips()[: self.limits["max_scan_ips"]]
            self._invoke(
                "passive_intel", target,
                f"external intelligence databases may hold historical services for the "
                f"{len(seed_ips)} IP(s) already correlated to in-scope hostnames, without "
                f"touching the target",
                passive_intel.run_passive_intel,
                target, output_dir=self.output_dir, seed_ips=seed_ips or None, timeout=self.timeout,
            )

        if self._enabled("code_leak"):
            self._invoke(
                "code_leak", target,
                "public repositories may expose credentials, internal URLs or infrastructure "
                "references for the target organization",
                code_leak.run_code_leak,
                target, output_dir=self.output_dir, timeout=self.timeout,
            )

        if self._enabled("osint_engine"):
            scannable = self.scannable_ips()
            self._invoke(
                "osint_engine", target,
                "digital-footprint intelligence (emails, breaches, DNS history, reverse IP) "
                "expands the known surface without target interaction",
                osint_engine.run_osint_engine,
                target, output_dir=self.output_dir,
                seed_ip=scannable[0] if scannable else None, timeout=self.timeout,
            )

        if self._enabled("wayback_intel"):
            record = self._invoke(
                "wayback_intel", target,
                "historical URLs reveal removed-but-possibly-reachable endpoints and parameters "
                "that current enumeration cannot find",
                wayback_intel.run_wayback_intel,
                target, output_dir=self.output_dir, timeout=self.timeout,
            )
            result = record.get("result")
            if isinstance(result, dict) and isinstance(result.get("historical_data"), list):
                # Consumed by endpoint_discovery.correlate_historical_parameters().
                self._historical_data = result["historical_data"]

    # =====================================================================
    # Phase 2 — active network reconnaissance
    # =====================================================================

    def _run_active_network_phase(self) -> None:
        ips = self.scannable_ips()[: self.limits["max_scan_ips"]]

        if self._enabled("active_recon"):
            if not ips:
                self._skip("active_recon",
                           "no IPv4 address is correlated to an in-scope hostname in the graph, "
                           "so there is no authorized host to scan")
            for ip in ips:
                hosts = self._hostnames_for_ip(ip)
                self._invoke(
                    "active_recon", ip,
                    f"{ip} is resolved by in-scope hostname(s) {hosts}; enumerate exposed "
                    f"services to build the port/service layer of the graph",
                    active_recon.run_active_recon,
                    ip, target=self.target, tcp_ports=self.tcp_ports,
                    output_dir=self.output_dir, timeout=self.timeout, max_workers=self.threads,
                )

        if self._enabled("ssl_analyzer"):
            targets = self.ssl_targets()
            if not targets:
                self._skip("ssl_analyzer", "no in-scope hostname is available for TLS inspection")
            for host, port in targets:
                self._invoke(
                    "ssl_analyzer", f"{host}:{port}",
                    f"TLS inspection of {host}:{port} yields certificate posture and SAN entries "
                    f"that feed new hostnames back into the graph",
                    ssl_analyzer.run_ssl_analysis,
                    host, port=port, target=self.target,
                    output_dir=self.output_dir, timeout=self.timeout,
                )

        if self._enabled("vhost_scanner"):
            vhost_ips = ips[: self.limits["max_vhost_ips"]]
            if not vhost_ips:
                self._skip("vhost_scanner",
                           "virtual-host discovery requires a discovered in-scope IP to send "
                           "Host-header variations to")
            for ip in vhost_ips:
                self._invoke(
                    "vhost_scanner", ip,
                    f"applications served on {ip} may be reachable only by Host header and "
                    f"therefore invisible to DNS enumeration",
                    vhost_scanner.run_vhost_scan,
                    ip, self.target, output_dir=self.output_dir,
                    wordlists_dir=self.wordlists_dir, timeout=self.timeout,
                )

    # =====================================================================
    # Phase 3 — active web / client-side reconnaissance
    # =====================================================================

    def _run_active_web_phase(self) -> None:
        base_urls = self.web_base_urls()

        if not base_urls:
            for name in PHASE_MODULES[PHASE_ACTIVE_WEB]:
                if self._enabled(name):
                    self._skip(name, "no in-scope web base URL could be derived from the graph")
            return

        if self._enabled("http_analyzer"):
            for url in base_urls:
                self._invoke(
                    "http_analyzer", url,
                    f"HTTP security posture of {url} (headers, cookies, CORS, auth surfaces, "
                    f"redirects) is a prerequisite signal for relationship-based risk scoring",
                    http_analyzer.run_http_analysis,
                    url, target=self.target, output_dir=self.output_dir, timeout=self.timeout,
                )

        if self._enabled("tech_fingerprint"):
            for url in base_urls:
                record = self._invoke(
                    "tech_fingerprint", url,
                    f"identifying the technology stack behind {url} selects the tech-aware "
                    f"wordlists endpoint_discovery uses and the versions vuln_intel maps to CVEs",
                    tech_fingerprint.run_tech_fingerprint,
                    url, target=self.target, output_dir=self.output_dir, timeout=self.timeout,
                )
                result = record.get("result")
                if isinstance(result, dict) and isinstance(result.get("technology_summary"), dict):
                    self._technology_by_url[url] = result["technology_summary"]

        if self._enabled("crawler"):
            for url in base_urls:
                record = self._invoke(
                    "crawler", url,
                    f"recursive in-scope crawling of {url} discovers URLs, forms, parameters and "
                    f"the JavaScript references js_analyzer needs",
                    crawler.run_crawler,
                    url, target=self.target, output_dir=self.output_dir,
                    timeout=self.timeout, max_workers=self.threads,
                )
                result = record.get("result")
                if isinstance(result, dict):
                    for page in result.get("pages", []) or []:
                        page_url = page.get("url") if isinstance(page, dict) else None
                        if page_url:
                            self._crawled_pages.append(str(page_url))

        # js_analyzer runs before endpoint_discovery because its
        # `js_data_for_endpoint_discovery` output is exactly what
        # run_endpoint_discovery(js_data=...) consumes (context.md §6:
        # "JS file -> API reference -> endpoint -> parameter").
        if self._enabled("js_analyzer"):
            js_urls = self.javascript_urls()
            if not js_urls:
                self._skip("js_analyzer", "no in-scope JavaScript asset has been discovered yet")
            else:
                record = self._invoke(
                    "js_analyzer", f"{len(js_urls)} file(s)",
                    f"deep analysis of {len(js_urls)} in-scope JavaScript file(s) exposes API "
                    f"routes, internal endpoints and configuration references not linked in HTML",
                    js_analyzer.run_js_analyzer,
                    js_urls, target=self.target, output_dir=self.output_dir, timeout=self.timeout,
                )
                result = record.get("result")
                if isinstance(result, dict) and isinstance(
                        result.get("js_data_for_endpoint_discovery"), list):
                    self._js_data = result["js_data_for_endpoint_discovery"]

        if self._enabled("endpoint_discovery"):
            for url in base_urls:
                technology = self._technology_for(url)
                self._invoke(
                    "endpoint_discovery", url,
                    f"enumerate the web/API attack surface of {url} using "
                    f"{'tech-aware wordlists from tech_fingerprint' if technology else 'generic wordlists'}, "
                    f"{len(self._historical_data)} historical record(s) and "
                    f"{len(self._js_data)} JavaScript-derived reference(s)",
                    endpoint_discovery.run_endpoint_discovery,
                    url, target=self.target, output_dir=self.output_dir,
                    wordlists_dir=self.wordlists_dir,
                    technology=technology,
                    historical_data=self._historical_data or None,
                    js_data=self._js_data or None,
                    timeout=self.timeout, max_workers=self.threads,
                )

        if self._enabled("api_recon"):
            for url in base_urls:
                self._invoke(
                    "api_recon", url,
                    f"dedicated API reconnaissance of {url} identifies versions, specifications, "
                    f"GraphQL schemas, deprecated endpoints and authentication mechanisms",
                    api_recon.run_api_recon,
                    url, target=self.target, output_dir=self.output_dir, timeout=self.timeout,
                )

        if self._enabled("exposure_scan"):
            endpoints = self.endpoint_urls()
            for url in base_urls:
                host = _hostname_of(url)
                scoped = [e for e in endpoints if _hostname_of(e) == host]
                self._invoke(
                    "exposure_scan", url,
                    f"probe {url} for exposed VCS/config/backup resources, admin surfaces and "
                    f"cloud misconfiguration, plus HTTP OPTIONS on {len(scoped)} discovered endpoint(s)",
                    exposure_scan.run_exposure_scan,
                    url, target=self.target, output_dir=self.output_dir,
                    wordlists_dir=self.wordlists_dir,
                    endpoints=scoped or None,
                    timeout=self.timeout, max_workers=self.threads,
                )

        if self._enabled("supply_chain"):
            pages = self._supply_chain_pages(base_urls)
            subdomains = self.in_scope_hostnames()[: self.limits["max_supply_chain_subdomains"]]
            self._invoke(
                "supply_chain", f"{len(pages)} page(s) / {len(subdomains)} subdomain(s)",
                f"map third-party dependencies across {len(pages)} in-scope page(s) and "
                f"third-party DNS delegation across {len(subdomains)} subdomain(s)",
                supply_chain.run_supply_chain_analysis,
                pages=pages, subdomains=subdomains, target=self.target,
                output_dir=self.output_dir, timeout=self.timeout,
            )

        if self._enabled("screenshot"):
            urls = self._screenshot_urls(base_urls)
            self._invoke(
                "screenshot", f"{len(urls)} URL(s)",
                f"visual triage of {len(urls)} discovered web interface(s) enables rapid "
                f"identification of login pages, admin panels and default installations",
                screenshot.run_screenshot_batch,
                urls, target=self.target, output_dir=self.output_dir, timeout=self.timeout,
            )

    def _supply_chain_pages(self, base_urls: Sequence[str]) -> List[str]:
        pages: List[str] = []
        seen: Set[str] = set()
        for url in list(base_urls) + self.crawled_page_urls() + self.endpoint_urls():
            if url not in seen:
                seen.add(url)
                pages.append(url)
            if len(pages) >= self.limits["max_supply_chain_pages"]:
                break
        return pages

    def _screenshot_urls(self, base_urls: Sequence[str]) -> List[str]:
        urls: List[str] = []
        seen: Set[str] = set()
        for url in list(base_urls) + self.crawled_page_urls():
            if url not in seen:
                seen.add(url)
                urls.append(url)
            if len(urls) >= self.limits["max_screenshots"]:
                break
        return urls

    # =====================================================================
    # Adaptive round — react to surface_mapper.py's opportunities
    # =====================================================================

    # Maps an opportunity's subject asset onto a concrete, existing module
    # call. Anything not listed here is surfaced for review rather than
    # guessed at.
    def _adaptive_action(self, opportunity: Dict[str, Any]) -> Optional[Tuple[str, str, Callable[[], Any]]]:
        opp_type = opportunity.get("opportunity_type")
        value = opportunity.get("target_value")
        asset = self.mapper.get_asset(str(opportunity.get("target_asset_id")))
        if asset is not None and asset.get("in_scope") is False:
            return None  # never act on an out-of-scope asset

        suggested = [
            str(m)[:-3] if str(m).endswith(".py") else str(m)
            for m in (opportunity.get("suggested_modules") or [])
        ]
        enabled = [m for m in suggested if self._enabled(m)]
        if not enabled:
            return None
        module_name = enabled[0]

        if opp_type in ("new_hostname_via_cert_san", "vhost_web_followup"):
            host = str(value)
            if not surface_mapper.is_in_scope(host, self.target):
                return None
            url = f"https://{host}/"
            return self._call_for(module_name, url, host)

        if opp_type == "open_port_followup":
            if not isinstance(value, dict):
                return None
            ip = str(value.get("ip") or "")
            try:
                port = int(value.get("port"))
            except (TypeError, ValueError):
                return None
            if not ip or ip not in set(self.scannable_ips()):
                return None
            if port in WEB_PORT_SCHEMES:
                hosts = self._hostnames_for_ip(ip)
                if not hosts:
                    return None
                return self._call_for(module_name, _base_url(hosts[0], port), hosts[0])
            if module_name == "active_recon":
                return None  # the port is already scanned; nothing new to do
            return None

        if opp_type in ("technology_specific_enumeration",):
            if not isinstance(value, dict):
                return None
            scope = str(value.get("scope") or "")
            url = scope if "://" in scope else f"https://{scope}/"
            host = _hostname_of(url)
            if not host or not surface_mapper.is_in_scope(host, self.target):
                return None
            return self._call_for(module_name, url, host,
                                  technology={"technology": value.get("name")})

        if opp_type in ("file_upload_surface_review", "js_referenced_endpoint_verification"):
            url = str(value)
            host = _hostname_of(url)
            if not host or not surface_mapper.is_in_scope(host, self.target):
                return None
            return self._call_for(module_name, url, host)

        return None

    def _call_for(self, module_name: str, url: str, host: str,
                  technology: Optional[Dict[str, Any]] = None) -> Optional[Tuple[str, str, Callable[[], Any]]]:
        """Bind one module's real signature to a URL derived from an opportunity."""
        common = {"target": self.target, "output_dir": self.output_dir, "timeout": self.timeout}
        if module_name == "http_analyzer":
            return module_name, url, lambda: http_analyzer.run_http_analysis(url, **common)
        if module_name == "tech_fingerprint":
            return module_name, url, lambda: tech_fingerprint.run_tech_fingerprint(url, **common)
        if module_name == "ssl_analyzer":
            return module_name, host, lambda: ssl_analyzer.run_ssl_analysis(
                host, port=ssl_analyzer.DEFAULT_PORT, target=self.target,
                output_dir=self.output_dir, timeout=self.timeout)
        if module_name == "endpoint_discovery":
            return module_name, url, lambda: endpoint_discovery.run_endpoint_discovery(
                url, wordlists_dir=self.wordlists_dir,
                technology=technology or self._technology_for(url),
                historical_data=self._historical_data or None,
                js_data=self._js_data or None,
                max_workers=self.threads, **common)
        if module_name == "api_recon":
            return module_name, url, lambda: api_recon.run_api_recon(url, **common)
        if module_name == "exposure_scan":
            return module_name, url, lambda: exposure_scan.run_exposure_scan(
                url, wordlists_dir=self.wordlists_dir, max_workers=self.threads, **common)
        if module_name == "crawler":
            return module_name, url, lambda: crawler.run_crawler(
                url, max_workers=self.threads, **common)
        if module_name == "passive_recon":
            # An opportunity naming passive_recon is about a newly learned
            # hostname; validate_target() accepts only a bare domain.
            return module_name, host, lambda: passive_recon.run_passive_recon(
                host, output_dir=self.output_dir, timeout=self.timeout)
        if module_name == "vhost_scanner":
            return None  # needs an IP subject, which no opportunity carries
        return None

    def _run_adaptive_rounds(self) -> Dict[str, Any]:
        """
        Consume surface_mapper.py's reconnaissance opportunities.

        Bounded by `max_adaptive_rounds` and `max_adaptive_actions` so a
        discovery cascade cannot expand a run without limit, and consumed
        opportunities are never resurrected by the mapper, so a repeat run
        never re-fires the same action. Opportunities with no automatable
        module (subdomain-takeover manual verification) are deliberately
        left pending and surfaced for human review instead.

        The execution mode is enforced through `_enabled()` alone: an
        opportunity can only fire a module the selected mode already
        permits, so a passive-only run can still resolve a newly learned
        hostname with passive_recon.py but can never be talked into an
        active module by a discovery.
        """
        summary = {"rounds": 0, "actions": 0, "consumed": [], "manual_review": [], "deferred": []}
        rounds = self.limits["max_adaptive_rounds"]
        budget = self.limits["max_adaptive_actions"]
        if rounds == 0 or budget == 0:
            return summary

        for _ in range(rounds):
            pending = sorted(self.mapper.get_pending_opportunities(), key=lambda o: str(o.get("id")))
            if not pending:
                break
            summary["rounds"] += 1
            acted = 0
            for opportunity in pending:
                if summary["actions"] >= budget:
                    summary["deferred"].append(opportunity["id"])
                    continue
                if not opportunity.get("suggested_modules"):
                    summary["manual_review"].append({
                        "id": opportunity["id"],
                        "opportunity_type": opportunity.get("opportunity_type"),
                        "target_value": opportunity.get("target_value"),
                        "reason": opportunity.get("reason"),
                        "priority": opportunity.get("priority"),
                    })
                    self.decisions.record(
                        "defer to manual review",
                        f"{opportunity.get('opportunity_type')} on "
                        f"{opportunity.get('target_value')!r} has no automatable module: "
                        f"{opportunity.get('reason')}",
                        phase=PHASE_ADAPTIVE, subject=opportunity.get("target_value"),
                        status="manual_review",
                    )
                    continue
                action = self._adaptive_action(opportunity)
                if action is None:
                    summary["deferred"].append(opportunity["id"])
                    continue
                module_name, subject, call = action
                # Consume first: an action that fails must not be retried on
                # the next round or the next run (retry-loop prevention).
                try:
                    self.mapper.consume_opportunity(opportunity["id"])
                except KeyError:
                    continue
                summary["consumed"].append({
                    "id": opportunity["id"],
                    "opportunity_type": opportunity.get("opportunity_type"),
                    "module": module_name, "subject": subject,
                })
                summary["actions"] += 1
                acted += 1
                self._invoke(
                    module_name, subject,
                    f"surface_mapper raised {opportunity.get('opportunity_type')} "
                    f"({opportunity.get('priority')}): {opportunity.get('reason')}",
                    call, phase=PHASE_ADAPTIVE,
                )
            if acted == 0:
                break
        return summary

    # =====================================================================
    # Phase 4 — vulnerability intelligence and risk
    # =====================================================================

    def _run_intelligence_phase(self) -> None:
        if self._enabled("vuln_intel"):
            observations = self.technology_observations()
            self._invoke(
                "vuln_intel", f"{len(observations)} versioned technology observation(s)",
                f"map {len(observations)} observed technology/version pair(s) from the graph, plus "
                f"active_recon's persisted banners, to publicly known CVEs (possible matches, "
                f"never confirmed exploitability)",
                vuln_intel.run_vuln_intel,
                output_dir=self.output_dir,
                technology_observations=observations or None,
                timeout=self.timeout,
            )

        # risk_engine.py runs last, on the live graph, after every discovery
        # (including vuln_intel's CVE matches) has been ingested.
        if self._enabled("risk_engine"):
            self._run_risk_engine()

    def _run_risk_engine(self) -> None:
        decision = self.decisions.record(
            "run risk_engine",
            "all discovery and vulnerability intelligence has been correlated into the graph; "
            "relationship-based prioritization can now score assets rather than isolated findings",
            module="risk_engine", phase=PHASE_INTELLIGENCE, subject=self.target,
        )
        self._execution_seq += 1
        execution_id = f"exec:{self._execution_seq:04d}:risk_engine"
        started = time.monotonic()
        record: Dict[str, Any] = {
            "execution_id": execution_id, "module": "risk_engine",
            "phase": PHASE_INTELLIGENCE, "subject": self.target,
            "status": STATUS_SUCCESS, "started_at": _now(),
            "error": None, "error_type": None, "module_error_count": 0,
            "observations_ingested": 0, "stats": {},
        }
        self._emit({"event": "module_started", "module": "risk_engine",
                    "phase": PHASE_INTELLIGENCE, "subject": self.target})
        try:
            # The live SurfaceMapper is handed over directly:
            # load_graph_state() accepts any object exposing `.state`, so the
            # engine assesses exactly the graph this run built.
            assessment = risk_engine.run_risk_engine(
                graph=self.mapper,
                output_dir=self.output_dir,
                stale_after_days=self.stale_after_days,
                min_queue_severity=self.min_risk_severity,
                persist=True,
            )
        except KeyboardInterrupt:
            record["status"] = STATUS_INTERRUPTED
            record["error"] = "interrupted by user"
            record["error_type"] = "KeyboardInterrupt"
            self._risk = {"status": STATUS_INTERRUPTED}
            self.executions.append(record)
            DecisionQueue.complete(decision, STATUS_INTERRUPTED)
            raise
        except Exception as exc:
            record["status"] = STATUS_FAILED
            record["error"] = str(exc)
            record["error_type"] = type(exc).__name__
            self.errors.append({"stage": "risk_engine", "error": str(exc)})
            self._risk = {"status": STATUS_FAILED, "error": str(exc)}
        else:
            summary = assessment.get("summary", {})
            record["stats"] = {
                "assets_assessed": summary.get("assets_assessed", 0),
                "signals": summary.get("signals", 0),
                "queue_length": summary.get("queue_length", 0),
            }
            record["module_error_count"] = len(assessment.get("errors", []) or [])
            if not summary.get("signals"):
                record["status"] = STATUS_NO_RESULTS
            self._risk = {
                "status": record["status"],
                "summary": summary,
                "queue_length": summary.get("queue_length", 0),
                "output_path": assessment.get("output_path"),
                "generated_at": assessment.get("generated_at"),
                "errors": len(assessment.get("errors", []) or []),
                "unresolved_conflicts": len(assessment.get("unresolved_conflicts", []) or []),
                "suspended_signals": len(assessment.get("suspended_signals", []) or []),
                "out_of_scope_assets": assessment.get("out_of_scope_assets", []),
            }
        finally:
            record["duration_seconds"] = round(time.monotonic() - started, 3)
            record["finished_at"] = _now()
            if record["status"] != STATUS_INTERRUPTED:
                self.executions.append(record)
                DecisionQueue.complete(decision, record["status"], error=record["error"])
            self._emit({"event": "module_finished", "module": "risk_engine",
                        "phase": PHASE_INTELLIGENCE, "subject": self.target,
                        "status": record["status"]})
            self._save_record()

    # =====================================================================
    # Run
    # =====================================================================

    def run(self) -> Dict[str, Any]:
        """
        Execute the configured pipeline and return one JSON-safe result.

        Recoverable failures are recorded and the run continues. A
        KeyboardInterrupt stops the run cleanly: everything already
        discovered has been persisted and correlated, and a complete partial
        result is returned rather than raised.
        """
        self.started_at = _now()
        self.status = "running"
        self.decisions.record(
            "start run",
            f"mode={self.mode} against authorized target {self.target!r} with "
            f"{len(self.selected_modules)} module(s) selected",
            phase=None, subject=self.target, status="started",
        )
        self._emit({"event": "run_started", "target": self.target, "mode": self.mode,
                    "modules": list(self.selected_modules)})
        self._save_record()

        # Pick up anything an earlier interrupted run persisted but never
        # correlated, so a resumed run starts from complete state.
        self._ingest(phase=PHASE_CORRELATION, after="startup")

        adaptive: Dict[str, Any] = {"rounds": 0, "actions": 0, "consumed": [],
                                    "manual_review": [], "deferred": []}
        try:
            self._run_phase(PHASE_PASSIVE, self._run_passive_phase)
            self._run_phase(PHASE_ACTIVE_NETWORK, self._run_active_network_phase)
            self._run_phase(PHASE_ACTIVE_WEB, self._run_active_web_phase)
            adaptive = self._run_adaptive_rounds()
            self._run_phase(PHASE_INTELLIGENCE, self._run_intelligence_phase)
        except KeyboardInterrupt:
            self.interrupted = True
            self.decisions.record(
                "abort run", "keyboard interrupt received; preserving all discoveries "
                             "collected so far before exiting",
                subject=self.target, status=STATUS_INTERRUPTED,
            )
            self._emit({"event": "run_interrupted", "target": self.target})
        except Exception as exc:
            # A fatal orchestration failure. It is reported as a RUN_FAILED
            # result rather than raised, because everything discovered up to
            # this point is real evidence and must survive the failure — the
            # final ingest + save below is the whole point. Invalid
            # configuration still raises, but from __init__, before any work
            # has been done and before anything could be lost.
            self.errors.append({"stage": "orchestration", "error": str(exc),
                                "error_type": type(exc).__name__})
            self.status = RUN_FAILED

        # Final correlation + persistence, whatever happened above.
        final_ingest = self._ingest(phase=PHASE_CORRELATION, after="shutdown")
        self.finished_at = _now()
        result = self._build_result(adaptive, final_ingest)
        self._save_record(result)
        self._emit({"event": "run_finished", "target": self.target, "status": result["status"]})
        return result

    def _run_phase(self, phase: str, runner: Callable[[], None]) -> None:
        if not any(self._enabled(name) for name in PHASE_MODULES[phase]):
            return
        entry = {"phase": phase, "started_at": _now(), "finished_at": None}
        self.phases.append(entry)
        self._emit({"event": "phase_started", "phase": phase})
        try:
            runner()
        finally:
            entry["finished_at"] = _now()
            self._emit({"event": "phase_finished", "phase": phase})

    # =====================================================================
    # Result construction and persistence
    # =====================================================================

    def _run_status(self) -> str:
        if self.interrupted:
            return RUN_INTERRUPTED
        if self.status == RUN_FAILED:
            return RUN_FAILED
        if self.errors or any(e["status"] == STATUS_FAILED for e in self.executions):
            return RUN_COMPLETED_WITH_ERRORS
        return RUN_COMPLETED

    def _build_result(self, adaptive: Dict[str, Any], final_ingest: Dict[str, Any]) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        for execution in self.executions:
            by_status[execution["status"]] = by_status.get(execution["status"], 0) + 1

        pending = sorted(self.mapper.get_pending_opportunities(), key=lambda o: str(o.get("id")))
        result = {
            "module": MODULE_NAME,
            "target": self.target,
            "mode": self.mode,
            "status": self._run_status(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "interrupted": self.interrupted,
            "settings": {
                "output_dir": self.output_dir,
                "timeout": self.timeout,
                "threads": self.threads,
                "wordlists_dir": self.wordlists_dir,
                "tcp_ports": self.tcp_ports,
                "min_risk_severity": self.min_risk_severity,
                "stale_after_days": self.stale_after_days,
                "limits": dict(self.limits),
            },
            "modules_selected": list(self.selected_modules),
            "phases": list(self.phases),
            "executions": list(self.executions),
            "executions_by_status": by_status,
            "decision_queue": self.decisions.entries(),
            "adaptive": adaptive,
            "correlation": {
                "graph_path": self.mapper.store.path,
                "summary": self.mapper.summary(),
                "final_ingest": final_ingest,
                "conflicts": len(self.mapper.state["conflicts"]),
                "ingestion_errors": len(self.mapper.state["ingestion_errors"]),
            },
            "opportunities": {
                "pending": [
                    {"id": o["id"], "opportunity_type": o.get("opportunity_type"),
                     "target_value": o.get("target_value"), "priority": o.get("priority"),
                     "reason": o.get("reason"),
                     "suggested_modules": o.get("suggested_modules", [])}
                    for o in pending
                ],
                "consumed_this_run": adaptive.get("consumed", []),
                "manual_review": adaptive.get("manual_review", []),
            },
            "risk": self._risk,
            "scope": {
                "target": self.target,
                "in_scope_hostnames": self.in_scope_hostnames(),
                "out_of_scope_hostnames_observed": self.out_of_scope_hostnames(),
                "scanned_ips": self.scannable_ips()[: self.limits["max_scan_ips"]],
            },
            "errors": list(self.errors),
            "output_paths": {
                "pending_assets": os.path.join(self.output_dir, "pending_assets.json"),
                "surface_graph": self.mapper.store.path,
                "risk_assessment": self._risk.get("output_path"),
                "execution_record": self.record_store.path if self.persist_execution_record else None,
            },
            "notes": [
                "Producer modules run sequentially: they share one append-only "
                "pending_assets.json whose read/append/rewrite cycle is only safe under a "
                "single writer (orchestrator.py implementation decision 1).",
                "Findings are prioritization assessments and possible matches, never proof of "
                "exploitability (context.md §10 items 19-20).",
                "Reconnaissance only: no exploitation, credential attack, or persistence "
                "functionality is invoked at any point (context.md §16).",
            ],
        }
        return _json_safe(result)

    def _save_record(self, result: Optional[Dict[str, Any]] = None) -> None:
        if not self.persist_execution_record:
            return
        try:
            if result is None:
                result = {
                    "module": MODULE_NAME, "target": self.target, "mode": self.mode,
                    "status": "running", "started_at": self.started_at,
                    "finished_at": None, "interrupted": self.interrupted,
                    "modules_selected": list(self.selected_modules),
                    "executions": list(self.executions),
                    "decision_queue": self.decisions.entries(),
                    "errors": list(self.errors),
                }
            self.record_store.save(result)
        except Exception as exc:
            # The execution record is derived state; losing it must never
            # abort a scan that is producing real discoveries.
            self.errors.append({"stage": "execution_record", "error": str(exc)})


# ---------------------------------------------------------------------------
# Single-call entry point (this is what reconhound.py invokes)
# ---------------------------------------------------------------------------


def run_orchestrator(
    target: str,
    output_dir: str = "output",
    mode: str = MODE_FULL,
    modules: Optional[Sequence[str]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Build an Orchestrator and run it, returning the JSON-safe result."""
    orchestrator = Orchestrator(
        target=target, output_dir=output_dir, mode=mode, modules=modules, **kwargs
    )
    return orchestrator.run()


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------


def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="orchestrator.py",
        description="ReconHound Module 22 (core/orchestrator.py) — adaptive execution "
                    "coordination (standalone entry point).",
    )
    parser.add_argument("--target", required=True, help="Authorized target domain, e.g. example.com")
    parser.add_argument("--output-dir", default="output", help="Directory for all run state and output")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--full-scan", action="store_true", help="Run every module (default)")
    group.add_argument("--passive-only", action="store_true", help="Run passive + intelligence modules only")
    group.add_argument("--active-only", action="store_true", help="Run active + intelligence modules only")
    parser.add_argument("--module", action="append", default=None,
                        help="Run only the named module (repeatable)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Per-module worker threads")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout in seconds")
    parser.add_argument("--wordlists-dir", default=None, help="Directory containing the wordlists")
    parser.add_argument("--min-severity", default=risk_engine.SEVERITY_LOW,
                        choices=sorted(risk_engine.VALID_SEVERITIES),
                        help="Lowest severity to include in the investigation queue")
    parser.add_argument("--no-adaptive", action="store_true",
                        help="Do not act on surface_mapper reconnaissance opportunities")
    args = parser.parse_args()

    if args.module:
        mode = MODE_MODULE
    elif args.passive_only:
        mode = MODE_PASSIVE
    elif args.active_only:
        mode = MODE_ACTIVE
    else:
        mode = MODE_FULL

    try:
        result = run_orchestrator(
            target=args.target, output_dir=args.output_dir, mode=mode, modules=args.module,
            threads=args.threads, timeout=args.timeout, wordlists_dir=args.wordlists_dir,
            min_risk_severity=args.min_severity,
            max_adaptive_rounds=0 if args.no_adaptive else DEFAULT_MAX_ADAPTIVE_ROUNDS,
        )
    except OrchestratorError as exc:
        print(f"orchestration failed: {exc}", file=sys.stderr)
        raise SystemExit(2)

    print(json.dumps({
        "status": result["status"],
        "target": result["target"],
        "mode": result["mode"],
        "executions_by_status": result["executions_by_status"],
        "correlation": result["correlation"]["summary"],
        "risk": {k: v for k, v in result["risk"].items() if k != "summary"},
        "errors": result["errors"],
        "output_paths": result["output_paths"],
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    _main()
