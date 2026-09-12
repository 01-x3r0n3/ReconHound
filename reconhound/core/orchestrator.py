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
    writes none of those three itself. It does decide *when* the graph is
    written: the shared `SurfaceMapper` is constructed with autosave off and
    the orchestrator saves it exactly once after every module invocation
    that changed it, once after every consumed opportunity (so a crash
    mid-action cannot resurrect the action) and once at shutdown. Writing
    the whole graph is the dominant orchestration cost on a large surface,
    and the mapper's own autosave would write it twice per module. A failed
    graph write is a recorded run error, never an escaping exception: the
    in-memory graph is intact and pending_assets.json still holds every
    discovery for the next successful save or the next run.

3.  **Idempotent re-execution.** Re-running against an existing output
    directory is safe. `pending_assets.json` is append-only across runs, and
    `SurfaceMapper.ingest_finding()` keys every observation by a content
    hash, so re-ingesting an existing file adds nothing. Consumed
    opportunities are never resurrected by surface_mapper.py, so an adaptive
    action never re-fires on a later run. Within a run, every invocation is
    registered under an execution identity — module, subject and the inputs
    that change what the module would do (for endpoint_discovery the
    wordlists its `technology` input selects, plus the historical and
    JavaScript references it correlates) — and an opportunity whose action
    a phase already performed (or already attempted) is consumed as
    *satisfied* rather than run again. An output directory that holds
    another target's graph or execution record is refused outright: the
    mapper would start a fresh graph at the same path and the first save
    would overwrite the other engagement's state.

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
    `max_adaptive_actions` actions per run, highest priority first, running
    one enabled suggested module per opportunity. Opportunities with no
    suggested module (e.g. subdomain-takeover manual verification) are
    surfaced for human review and deliberately left pending rather than
    consumed and lost; opportunities the run cannot act on (module not in
    the selected mode, subject not in scope) are left pending with the
    reason reported, and only budget deferrals are reported as deferred.
    Every per-subject budget (`max_scan_ips`, `max_web_targets`, ...) is
    accounted for in the result's `coverage` block, so a bounded run never
    reads as complete coverage.

7.  **Failure is classified, never swallowed.** Six outcomes are
    distinguished: success, success-with-no-results, recoverable module
    failure, scope rejection, skipped, and fatal orchestration failure.
    Only the last stops the run, and even then everything already
    discovered is ingested and persisted first. A `KeyboardInterrupt`
    unwinds the same way and yields a complete, JSON-safe partial result —
    including one a module absorbed itself: crawler.py,
    endpoint_discovery.py and api_recon.py cancel their own worker batch on
    Ctrl+C and return their partial summary with `status: "interrupted"`,
    which the orchestrator treats exactly as the propagated interrupt it
    stands for, rather than as a result. "No results" is only concluded
    when correlation itself was clean; a module whose output could not be
    ingested did not find nothing. A persisted graph record that is not an
    object is skipped and reported once as a run error, not allowed to fail
    the run, and a hostname the graph marked in scope is only ever used as
    a subject if it is a syntactically valid hostname — every producer
    would reject anything else, but each rejected phantom would still cost
    a real subdomain its slot in a budget.

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
    credential, and scrubs credential-shaped material (`?key=`, `token=`,
    bearer values) from any error text before it reaches the execution
    record, the decision queue or the CLI — an exception escaping a module
    can carry the request URL it was making.


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
import ipaddress
import json
import os
import re
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
        http_analyzer, ssl_analyzer, surface_mapper,
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
# The subject never answered, so the module performed no reconnaissance
# against it. Distinct from STATUS_NO_RESULTS on purpose: "checked and found
# nothing" and "never reached" are opposite statements about coverage, and
# collapsing them reported an origin that answered nothing as cleanly
# surveyed. http_analyzer.py already draws exactly this distinction in its
# own summary ("a host that did not answer is 'not checked', never 'checked
# and clean'"); this is the orchestrator honouring it.
STATUS_UNREACHABLE = "unreachable"

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


def _not_a_remote_host(value: Any) -> Optional[str]:
    """
    Why an IPv4 address must never be handed to an active module, or None.

    A DNS answer is target-controlled data. An in-scope hostname whose A
    record names a loopback or link-local address does not point at the
    target: those ranges address the *scanning host's own* machine and its
    own link, so probing them scans the operator's workstation — or, at
    169.254.169.254, reads the operator's own cloud instance-metadata
    service. Following one is the authorisation-boundary violation
    endpoint_discovery.py's `_host_allowed` already refuses for hostnames
    learned from response bodies; a hostile or hijacked DNS answer is the
    same untrusted input arriving by a different route.

    Deliberately narrow. RFC1918 and CGNAT addresses are NOT rejected: an
    internal engagement against a host that resolves to 10.0.0.5 is exactly
    the reconnaissance this tool exists for, and refusing it would remove
    real capability. Only addresses that cannot denote a remote target at
    all are excluded, and every exclusion is reported under `scope`.
    """
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return "not a valid IP address"
    if ip.is_loopback:
        return "loopback address — this is the scanning host itself, not the target"
    if ip.is_link_local:
        return ("link-local address — addresses the scanning host's own link, and "
                "169.254.169.254 is the cloud instance-metadata service of the machine "
                "running ReconHound, not an asset of the target")
    if ip.is_unspecified:
        return "unspecified address"
    if ip.version == 4 and ip in ipaddress.ip_network("0.0.0.0/8"):
        # RFC 1122 "this network": valid only as a source address. Python's
        # ipaddress only flags 0.0.0.0 itself as unspecified, so the rest of
        # the block has to be named explicitly.
        return "0.0.0.0/8 'this network' address — not a valid destination"
    if ip.is_multicast:
        return "multicast address — not a unicast host"
    if ip.is_reserved:
        return "reserved address — not an assignable unicast host"
    if ip.version == 4 and ip in ipaddress.ip_network("255.255.255.255/32"):
        return "broadcast address — not a unicast host"
    return None


_HOST_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def _valid_hostname(value: Any) -> bool:
    """
    True only for a syntactically valid, multi-label DNS hostname.

    The graph marks a hostname in scope by suffix match alone, so a persisted
    name such as `evil.net/#.example.com` or `a b.example.com` (poisoned or
    pre-hardening state) would otherwise become a subject. Every producer
    rejects such a subject anyway, but each one still costs a slot of the
    per-derivation budget that a real subdomain then never gets.
    """
    if not isinstance(value, str):
        return False
    if value != value.strip():
        return False
    host = value.rstrip(".").lower()
    if not host or len(host) > 253 or "." not in host:
        return False
    labels = host.split(".")
    if not all(_HOST_LABEL_RE.match(label) for label in labels):
        return False
    try:
        return urllib.parse.urlsplit(f"https://{host}/").hostname == host
    except ValueError:
        return False


_SECRET_PATTERNS: Tuple["re.Pattern[str]", ...] = (
    # ?key=..., &api_key=..., token=..., in URLs and query strings.
    re.compile(r"(?i)\b(key|api[_-]?key|apikey|token|access[_-]?token|secret|client[_-]?secret|"
               r"password|passwd|pwd|auth|signature|sig)=([^&\s'\"]+)"),
    # `Authorization: Bearer <token>` / `Basic <b64>` — real values are long,
    # so a 16-character floor keeps "Bearer token expired" readable.
    re.compile(r"(?i)\b(bearer|basic)(\s+)([A-Za-z0-9._~+/=-]{16,})"),
    # `x-api-key: value`, `token=value`, `Authorization=...` with an explicit separator.
    re.compile(r"(?i)\b(token|apikey|api-key|x-api-key|authorization|x-auth-token)(\s*[:=]\s*)"
               r"(?!bearer\b|basic\b|<redacted>)([^\s'\"&]{6,})"),
)


def _redact_secrets(text: Any) -> str:
    """
    Strip credential-looking material from a string before it is persisted.

    Modules read their API keys from the environment and never hand them to
    the orchestrator, but an exception that escapes a module can carry the
    request it was making — `requests` embeds the full URL, query string
    included, in its connection errors — so error text is scrubbed before it
    reaches the execution record, the decision queue or the CLI.
    """
    out = str(text)
    out = _SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}=<redacted>", out)
    for pattern in _SECRET_PATTERNS[1:]:
        out = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", out)
    return out


def _subject_url_ok(url: Any, target: str) -> bool:
    """
    True for an absolute http(s) URL whose authority is a valid, in-scope
    hostname with no userinfo. A `https://x\\@example.com/` still parses to
    host example.com; every producer strips the userinfo itself, but the
    orchestrator does not hand out subjects it cannot vouch for.
    """
    try:
        parts = urllib.parse.urlsplit(str(url))
        host = parts.hostname
    except ValueError:
        return False
    if parts.scheme.lower() not in ("http", "https") or not host:
        return False
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return False
    if any(ch.isspace() for ch in str(url)):
        return False
    return _valid_hostname(host) and surface_mapper.is_in_scope(host, target)


def _origin_of(url: Any) -> Optional[str]:
    """
    "scheme://host[:port]" for a URL, with any `user:password@` removed.

    Credentials genuinely turn up in URLs this orchestrator handles: an
    opportunity's subject originates in crawled response bodies. An origin is
    a scheduling key and is echoed into the decision queue, the persisted
    execution record and the CLI, so leaving userinfo in it would write a
    password to disk (CLAUDE.md rule 16) — and would also key one origin as
    two, because `https://u:p@h/` and `https://h/` are the same origin.
    """
    try:
        parts = urllib.parse.urlsplit(str(url))
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    netloc = parts.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
        if not netloc:
            return None
    return f"{parts.scheme.lower()}://{netloc.lower()}"


# Opportunities are acted on in priority order, then by id for determinism,
# so a finite action budget is spent on the mapper's highest-value work.
_PRIORITY_RANK: Dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# A module that absorbs a KeyboardInterrupt itself (crawler.py,
# endpoint_discovery.py, api_recon.py cancel their worker batch and return
# their partial summary) reports it through this status value.
MODULE_STATUS_INTERRUPTED = "interrupted"

# http_analyzer.py's own summary vocabulary for "the subject never answered".
# It is the only module that reports origin reachability as a first-class
# outcome, and it is the first module of the web phase, so one request of its
# establishes whether the other seven have an origin to work against at all.
MODULE_STATUS_UNREACHABLE = "unreachable"
MODULE_STATUS_NOT_CHECKED = "not_checked"
MODULE_UNREACHABLE_STATUSES = (MODULE_STATUS_UNREACHABLE, MODULE_STATUS_NOT_CHECKED)

# Web-phase modules that enumerate an origin with a wordlist or a crawl, in
# the order the phase runs them. Every one of them costs hundreds of requests
# against an origin that answers none of them, so each is skipped for an
# origin already proven unreachable. http_analyzer itself is absent: it is
# what produces the proof.
WEB_MODULES_NEEDING_A_LIVE_ORIGIN: Tuple[str, ...] = (
    "tech_fingerprint", "crawler", "endpoint_discovery", "api_recon", "exposure_scan",
)

# Caps on the per-run bookkeeping lists so a hostile graph cannot make the
# execution record grow without bound.
MAX_RECORDED_NOT_ACTIONABLE = 200
MAX_RECORDED_OMITTED_SUBJECTS = 25


# ---------------------------------------------------------------------------
# Execution-record persistence
# ---------------------------------------------------------------------------


def _fsync_dir(path: str) -> None:
    """Make an os.replace() durable on POSIX; a no-op where unsupported."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


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
                _fsync_dir(dir_name)
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

        # Origin reachability learned during the run: "scheme://host:port" ->
        # the module status that proved it dead, and the set of origins that
        # have demonstrably answered at least once. See `_note_reachability`.
        self._unreachable_origins: Dict[str, str] = {}
        self._reachable_origins: Set[str] = set()
        # Pages left out of a module's input list because their origin is
        # dead. Reported under coverage, never silently dropped.
        self._unreachable_pages: List[str] = []

        # Execution identity for this run: (module, subject) key -> the
        # inputs and execution_id of every invocation that performed it (see
        # `_identity()` / `_satisfied_by()`). This is what lets an adaptive
        # opportunity be recognised as already satisfied by work the phases
        # did, instead of re-running it.
        self._executed: Dict[str, List[Tuple[Dict[str, Any], str]]] = {}
        # Per-derivation coverage: how many subjects the graph offered versus
        # how many a budget let through. Reported, never hidden.
        self._coverage: Dict[str, Dict[str, Any]] = {}
        # Malformed persisted graph records met while deriving subjects,
        # keyed by (container, key) so each is reported once.
        self._state_anomalies: Dict[Tuple[str, str], str] = {}
        # In-scope hostname values that cannot be used as a subject (not a
        # syntactically valid hostname); reported under `scope`, not as an
        # error — an underscore DNS name is real, it is just not probeable.
        self._unusable_hosts: Dict[str, str] = {}
        # IPv4 addresses an in-scope hostname resolves to that cannot denote
        # a remote target (loopback, link-local, multicast, ...), with the
        # reason. Reported under `scope`, never silently dropped: a target
        # whose A record points at 169.254.169.254 is intelligence.
        self._unscannable_ips: Dict[str, str] = {}
        self._progress_errors: Dict[str, int] = {}
        self._adaptive_summary: Dict[str, Any] = self._empty_adaptive_summary()
        # True when the in-memory graph holds changes the file does not.
        self._graph_dirty = False
        # `_hosts_by_ip()` memo, keyed by graph size: the mapper only ever
        # adds assets and relationships, so the counts version the index.
        self._hosts_by_ip_cache: Tuple[Tuple[int, int], Dict[str, List[str]]] = ((-1, -1), {})

        self.record_store = ExecutionRecordStore(output_dir=output_dir)

        # -- the one shared graph for this run ----------------------------
        # A corrupt persisted graph is fatal *before* anything runs: silently
        # discarding it would destroy a previous run's correlated state.
        # Autosave is off: the mapper would otherwise write the whole graph
        # once inside every ingest and once more when an opportunity is
        # consumed, on top of the orchestrator's own save. The orchestrator
        # persists the graph itself, exactly once after every module
        # invocation and once after every consumed opportunity, through
        # `_save_graph()`, so a write failure is recorded instead of escaping.
        try:
            self.mapper = SurfaceMapper(target=self.target, output_dir=output_dir, autosave=False)
        except surface_mapper.PersistenceError as exc:
            raise OrchestratorError(
                f"Cannot start: existing surface graph in {output_dir!r} is unreadable. "
                f"Move it aside or choose a different --output-dir. ({exc})"
            ) from exc
        except surface_mapper.ScopeError as exc:
            raise ScopeViolationError(str(exc)) from exc

        self._preflight_output_dir_target()
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

    def _preflight_output_dir_target(self) -> None:
        """
        Refuse to start inside an output directory that belongs to a
        different target.

        SurfaceMapper deliberately does not adopt another target's persisted
        graph — but it starts a fresh in-memory graph at the same path, so the
        first save of this run would overwrite that engagement's
        surface_graph.json, risk_assessment.json would follow, and the other
        target's pending_assets.json records would be correlated into this
        graph as out-of-scope noise. None of that is recoverable, so it is a
        fatal configuration error, reported before any work is done.
        """
        other: Optional[str] = None
        graph_path = self.mapper.store.path
        state = self.mapper.state
        if os.path.exists(graph_path):
            if not state["assets"] and not state["observations"]:
                # The mapper either found an empty/fresh file or discarded a
                # foreign one; only in this case is a second read needed.
                try:
                    loaded = self.mapper.store.load()
                except surface_mapper.PersistenceError:
                    loaded = None
                if isinstance(loaded, dict) and loaded.get("target") not in (None, self.target):
                    other = str(loaded.get("target"))
        else:
            # No graph: the execution record is the only witness of whose
            # directory this is (e.g. a run interrupted before its first
            # correlation, or a graph moved aside by hand).
            record = self.record_store.load()
            if isinstance(record, dict) and record.get("target") not in (None, self.target):
                other = str(record.get("target"))
        if other is not None:
            raise ConfigurationError(
                f"Cannot start: output directory {self.output_dir!r} holds state for a different "
                f"target ({other!r}). Running {self.target!r} there would overwrite that "
                f"engagement's surface graph and mix its discoveries into this one. "
                f"Choose a different --output-dir."
            )

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
            self._record_repeating_error("progress_callback", exc)

    def _record_repeating_error(self, stage: str, exc: BaseException) -> None:
        """
        One error entry per distinct (stage, message), with an occurrence
        count — a broken progress callback or a read-only record file stays
        broken for every event or save of the run, and one line per
        occurrence would only bury the other errors.
        """
        text = _redact_secrets(exc)
        key = f"{stage}\x00{text}"
        if key in self._progress_errors:
            self._progress_errors[key] += 1
            for entry in self.errors:
                if entry.get("stage") == stage and entry.get("error") == text:
                    entry["occurrences"] = self._progress_errors[key]
                    break
        else:
            self._progress_errors[key] = 1
            self.errors.append({"stage": stage, "error": text,
                                "error_type": type(exc).__name__, "occurrences": 1})

    def _enabled(self, module_name: str) -> bool:
        return module_name in self.selected_modules

    # =====================================================================
    # Correlation — surface_mapper.py ingestion after every module
    # =====================================================================

    def _ingest(self, *, phase: str, after: str, force_save: bool = False) -> Dict[str, Any]:
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
        except Exception as exc:
            # Recoverable at the run level: the graph already holds
            # everything ingested so far and is saved below. Nothing is
            # lost either way — pending_assets.json is append-only, so the
            # next ingest (or the next run) picks the records up again.
            text = _redact_secrets(exc)
            self.errors.append({"stage": "correlation", "after": after, "error": text,
                                "error_type": type(exc).__name__})
            self.decisions.record(
                "correlate", f"ingestion of pending_assets.json failed after {after}: {text}",
                module="surface_mapper", phase=PHASE_CORRELATION, status=STATUS_FAILED,
            )
            result = {"total": 0, "ingested": 0, "duplicates": 0, "errors": 1, "error": text}
        new = len(self.mapper.state["observations"]) - before
        new_errors = len(self.mapper.state["ingestion_errors"]) - before_errors
        if new or new_errors:
            self._graph_dirty = True
        saved = self._save_graph(after, force=force_save)
        return {
            "after": after, "phase": phase,
            "new_observations": new, "ingestion_errors": new_errors, "graph_saved": saved,
            **{k: v for k, v in result.items() if k in ("total", "ingested", "duplicates", "errors", "note", "error")},
        }

    def _save_graph(self, after: str, force: bool = False) -> bool:
        """
        Persist the graph once, atomically, when it has changed. Writing the
        whole graph is the single largest orchestration cost on a big
        surface, and a module that produced nothing changed nothing worth
        writing. A failed write (disk full, permissions) is recorded as a run
        error and never terminates the run: the in-memory graph is intact,
        every discovery is still in the append-only pending_assets.json, and
        the next successful save — or the next run's startup ingest —
        recovers the state.
        """
        if not self._graph_dirty and not force:
            return True
        try:
            self.mapper.save()
            self._graph_dirty = False
            return True
        except Exception as exc:
            self._record_repeating_error("graph_persistence", exc)
            return False

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
        identity: Optional["Orchestrator.Identity"] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Run one module against one subject, isolate its failure, and route
        whatever it persisted into the graph.

        Ingestion happens in a `finally` block: a module that raised halfway
        through has still persisted every discovery it completed before the
        failure (crash-safe persistence, design principle 1), and that
        evidence must not be lost because of what came after it.

        `identity` is the execution's identity key (see `_identity()`); it is
        registered whatever the outcome, so the same work is never repeated
        within the run — not even as a retry of a failure.
        """
        phase = phase or MODULE_PHASE.get(module_name, PHASE_ACTIVE_WEB)
        identity = identity or self._identity(module_name, subject)
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
        absorbed_interrupt = False
        try:
            result = fn(*args, **kwargs)
            if isinstance(result, dict) and result.get("status") == MODULE_STATUS_INTERRUPTED:
                # The module caught the user's Ctrl+C itself, cancelled its
                # own workers and returned its partial summary. That is an
                # interrupt, not a result: the run must stop here exactly as
                # if the KeyboardInterrupt had propagated, or every remaining
                # module would still run and the run would end "completed".
                absorbed_interrupt = True
                record["status"] = STATUS_INTERRUPTED
                record["error"] = "interrupted by user (reported by the module)"
                record["error_type"] = "KeyboardInterrupt"
        except SCOPE_ERRORS as exc:
            record["status"] = STATUS_SCOPE_REJECTED
            record["error"] = _redact_secrets(exc)
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
            record["error"] = _redact_secrets(exc)
            record["error_type"] = type(exc).__name__
        except BaseException as exc:
            # SystemExit / GeneratorExit are not module outcomes and must
            # keep propagating — but never behind a record that says
            # "success".
            record["status"] = STATUS_FAILED
            record["error"] = _redact_secrets(exc) or type(exc).__name__
            record["error_type"] = type(exc).__name__
            raise
        finally:
            record["duration_seconds"] = round(time.monotonic() - started, 3)
            record["finished_at"] = _now()
            # Derived from the module's summary *outside* the try above: a
            # summary the fingerprint cannot digest is not a module failure.
            try:
                record["stats"] = _compact_stats(result)
                record["module_error_count"] = _module_error_count(result)
            except Exception:
                record["stats"] = {}
            ingest = self._ingest(phase=phase, after=execution_id)
            record["observations_ingested"] = ingest["new_observations"]
            record["ingestion"] = ingest
            if (record["status"] == STATUS_SUCCESS and record["observations_ingested"] == 0
                    and not ingest.get("error") and not ingest["ingestion_errors"]):
                # Expected, normal outcome — a check that found nothing is a
                # result, not a failure (negative-result memory, context.md §8).
                # Only when correlation itself was clean: a module whose
                # output could not be ingested did not "find nothing".
                record["status"] = STATUS_NO_RESULTS
            if self._note_reachability(module_name, subject, result):
                # The module says the subject never answered. That is not a
                # negative result about the subject and must not be reported
                # as one; nothing was checked.
                if record["status"] in (STATUS_SUCCESS, STATUS_NO_RESULTS):
                    record["status"] = STATUS_UNREACHABLE
                record["subject_unreachable"] = True
            DecisionQueue.complete(
                decision, record["status"],
                observations_ingested=record["observations_ingested"],
                error=record["error"],
            )
            self.executions.append(record)
            self._executed.setdefault(identity[0], []).append((identity[1], execution_id))
            self._emit({
                "event": "module_finished", "module": module_name, "phase": phase,
                "subject": subject, "status": record["status"],
                "observations_ingested": record["observations_ingested"],
            })
            self._save_record()

        if absorbed_interrupt:
            raise KeyboardInterrupt("interrupt reported by %s" % module_name)

        # The stored record deliberately holds only the compact fingerprint:
        # the full module summary is orders of magnitude larger, duplicates
        # what already reached the graph, and would make
        # orchestrator_run.json grow with the size of the scan. The caller
        # still gets it for in-run data hand-offs.
        return {**record, "result": result}

    # One unit of work: a (module, subject) key plus the inputs that change
    # what the module would do against that subject.
    Identity = Tuple[str, Dict[str, Any]]

    @staticmethod
    def _identity(module_name: str, subject: Any, **inputs: Any) -> "Orchestrator.Identity":
        """
        Identity of one unit of work. Two invocations with the same key
        whose inputs subsume each other are the same work, so the second is
        a duplicate — whatever phase or opportunity asked for it.
        """
        return f"{module_name}|{subject}", _json_safe(inputs)

    @staticmethod
    def _subsumes(prior: Dict[str, Any], wanted: Dict[str, Any]) -> bool:
        """
        True if an execution with `prior` inputs already covers `wanted`:
        every list input is a superset, every numeric input is at least as
        large, everything else equal. A generic enumeration does not cover a
        WordPress-aware one; a WordPress+Laravel one covers a WordPress one.
        """
        for name, value in wanted.items():
            have = prior.get(name)
            if isinstance(value, list):
                if not isinstance(have, list) or not set(map(str, value)) <= set(map(str, have)):
                    return False
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                if not isinstance(have, (int, float)) or have < value:
                    return False
            elif have != value:
                return False
        return True

    def _satisfied_by(self, identity: "Orchestrator.Identity") -> Optional[str]:
        """execution_id of a prior execution in this run that covers `identity`, if any."""
        key, wanted = identity
        for prior, execution_id in self._executed.get(key, []):
            if self._subsumes(prior, wanted):
                return execution_id
        return None

    def _endpoint_discovery_identity(self, url: str, technology: Optional[Dict[str, Any]]) -> "Orchestrator.Identity":
        """
        endpoint_discovery.py's behaviour depends on which framework
        wordlists its `technology` input selects, and on the historical and
        JavaScript references it correlates — a rich tech_fingerprint summary
        and a bare {"technology": "WordPress"} that select the same wordlists
        are the same enumeration.
        """
        try:
            wordlists = sorted({name for name, _ in
                                endpoint_discovery.select_wordlists_for_technology(technology)})
        except Exception:
            wordlists = ["<unresolvable>"]
        return self._identity(
            "endpoint_discovery", url, wordlists=wordlists,
            historical=len(self._historical_data), js=len(self._js_data),
        )

    def _upstream_failure_note(self, *module_names: str) -> str:
        """Cite this run's failed executions of the modules a skip depends on."""
        failures = [
            f"{e['module']} on {e.get('subject')!r}: {e.get('error_type')}"
            for e in self.executions
            if e["module"] in module_names and e["status"] in (STATUS_FAILED, STATUS_SCOPE_REJECTED)
        ]
        if not failures:
            return ""
        shown = failures[:5]
        more = f" (+{len(failures) - 5} more)" if len(failures) > 5 else ""
        return f"; upstream failure(s) this run: {', '.join(shown)}{more}"

    # =====================================================================
    # Origin reachability (see MODULE_STATUS_UNREACHABLE)
    # =====================================================================

    def _note_reachability(self, module_name: str, subject: Any, result: Any) -> bool:
        """
        Record what one execution proved about its subject's origin.

        Returns True when the module reported that the subject never
        answered. Only http_analyzer.py's summary is read, because it is the
        only module that reports reachability as a first-class outcome rather
        than as an error count, and it is deliberately the first module of
        the web phase — so this costs one already-scheduled request and no
        new interface.

        An origin that answered is recorded as reachable and can never be
        demoted afterwards: a single later timeout against a host that has
        demonstrably served a response is a transient failure, not proof that
        the origin is gone, and must not silence the rest of the run.
        """
        if module_name != "http_analyzer" or not isinstance(result, dict):
            return False
        origin = _origin_of(subject)
        if not origin:
            return False
        status = str(result.get("status") or "")
        if status in MODULE_UNREACHABLE_STATUSES:
            if origin not in self._reachable_origins:
                self._unreachable_origins[origin] = status
            return origin in self._unreachable_origins
        # Any other status means a response was analysed.
        self._reachable_origins.add(origin)
        self._unreachable_origins.pop(origin, None)
        return False

    def _skip_unreachable(self, module_name: str, url: Any) -> bool:
        """
        Skip `module_name` for `url` when the origin is known not to answer.

        Returns True when the execution was skipped and recorded. The reason
        lands in the decision queue like any other orchestration decision, so
        the run explains why the work was not done rather than silently
        omitting it (design principle 8).
        """
        reason = self._unreachable_reason(url)
        if reason is None:
            return False
        self._skip(module_name, reason, subject=url)
        return True

    def _unreachable_reason(self, url: Any) -> Optional[str]:
        """
        Why this URL's origin should not be enumerated, or None.

        This is a *scheduling* decision, not a reconnaissance conclusion: the
        skipped module records no negative result, nothing is written into
        negative-result memory, and the coverage block reports the subject as
        not covered. Re-running when the origin is up performs the work in
        full.
        """
        origin = _origin_of(url)
        status = self._unreachable_origins.get(origin or "")
        if status is None:
            return None
        return (f"http_analyzer reported {origin} as {status}: the origin answered no request, so "
                f"enumerating it would spend the run's whole request budget on transport failures "
                f"and could produce no observation. Nothing was checked there — this is not a "
                f"negative result about {origin}")

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

    def _records(self, container: str) -> List[Tuple[str, Dict[str, Any]]]:
        """
        (key, record) pairs of one graph container, skipping — and noting —
        anything that is not a JSON object. The mapper validates the
        containers' types when it adopts a persisted graph, not every record
        inside them; a hand-edited or partially written record must cost the
        run one honest error entry, not the whole run.
        """
        out: List[Tuple[str, Dict[str, Any]]] = []
        for key, record in self.mapper.state.get(container, {}).items():
            if isinstance(record, dict):
                out.append((str(key), record))
            else:
                self._state_anomalies.setdefault(
                    (container, str(key)), f"{container}[{key!r}] is {type(record).__name__}, not an object")
        return out

    def _attrs(self, container: str, key: str, record: Dict[str, Any]) -> Dict[str, Any]:
        attributes = record.get("attributes")
        if isinstance(attributes, dict):
            return attributes
        if attributes is not None:
            self._state_anomalies.setdefault(
                (container, key), f"{container}[{key!r}].attributes is {type(attributes).__name__}, not an object")
        return {}

    @staticmethod
    def _attr_value(attributes: Dict[str, Any], name: str) -> Any:
        attr = attributes.get(name)
        return attr.get("value") if isinstance(attr, dict) else None

    def _assets_of_type(self, asset_type: str) -> List[Dict[str, Any]]:
        return [a for _, a in self._records("assets") if a.get("asset_type") == asset_type]

    def _hostname_value(self, key: str, asset: Dict[str, Any]) -> Optional[str]:
        """A hostname asset's value, only if it is a usable hostname."""
        value = asset.get("value")
        if _valid_hostname(value):
            return str(value)
        if isinstance(value, str) and value:
            self._unusable_hosts.setdefault(value[:253], "not a syntactically valid hostname")
        elif value is not None:
            self._state_anomalies.setdefault(
                ("assets", key), f"hostname asset {key!r} has a {type(value).__name__} value, not a string")
        return None

    def _host_first(self, hosts: Sequence[str]) -> List[str]:
        """Deterministic order with the authorized target itself first."""
        ordered = sorted(set(hosts))
        if self.target in ordered:
            ordered.remove(self.target)
            ordered.insert(0, self.target)
        return ordered

    def in_scope_hostnames(self) -> List[str]:
        """Hostnames the graph itself marked in scope, target first."""
        hosts = {self.target}
        for key, asset in self._records("assets"):
            if asset.get("asset_type") != surface_mapper.ASSET_HOSTNAME or asset.get("in_scope") is not True:
                continue
            host = self._hostname_value(key, asset)
            if host:
                hosts.add(host)
        return self._host_first(hosts)

    def out_of_scope_hostnames(self) -> List[str]:
        return sorted({
            str(a["value"])
            for a in self._assets_of_type(surface_mapper.ASSET_HOSTNAME)
            if a.get("in_scope") is False and a.get("value")
        })

    def _hosts_by_ip(self) -> Dict[str, List[str]]:
        """
        In-scope hostnames per IPv4 address, following `hostname_to_ip`
        edges only — the one place scope propagates from hostnames to IPs.
        Computed in a single pass over the relationships so the derivations
        below stay linear in the size of the graph.
        """
        assets = self.mapper.state["assets"]
        version = (len(self.mapper.state.get("relationships") or {}), len(assets))
        if self._hosts_by_ip_cache[0] == version:
            return self._hosts_by_ip_cache[1]
        by_ip: Dict[str, Set[str]] = {}
        for _, rel in self._records("relationships"):
            if rel.get("rel_type") != surface_mapper.REL_HOSTNAME_TO_IP:
                continue
            host_key = str(rel.get("from_asset"))
            host_asset = assets.get(host_key)
            ip_asset = assets.get(rel.get("to_asset"))
            if not isinstance(host_asset, dict) or not isinstance(ip_asset, dict):
                continue
            if host_asset.get("in_scope") is not True:
                continue
            host = self._hostname_value(host_key, host_asset)
            ip = ip_asset.get("value")
            if not host or not ip or not _is_ipv4(ip):
                continue
            # A DNS answer is target-controlled input. One that names the
            # scanning host's own loopback or link-local space is not a
            # subject; it is a way to point this tool at the operator.
            refusal = _not_a_remote_host(ip)
            if refusal is not None:
                self._unscannable_ips.setdefault(str(ip), refusal)
                continue
            by_ip.setdefault(str(ip), set()).add(host)
        index = {ip: self._host_first(hosts) for ip, hosts in by_ip.items()}
        self._hosts_by_ip_cache = (version, index)
        return index

    def _hostnames_for_ip(self, ip: str) -> List[str]:
        return self._hosts_by_ip().get(ip, [])

    def scannable_ips(self) -> List[str]:
        """
        IPv4 addresses that an in-scope hostname actually resolves to.

        Scope propagation lives here: an IP reached only from a third-party
        CNAME or from a passive-intel neighbour record has no
        `hostname_to_ip` edge from an in-scope host and is therefore never
        handed to an active module. run_active_recon()/run_vhost_scan()
        accept IPv4 only, so IPv6 assets are excluded here rather than
        failing one call at a time.

        Ordered with the target's own addresses first, then the rest sorted:
        every consumer applies a budget to this list, and a budget applied to
        a lexicographic order could exclude the authorized target itself.
        """
        by_ip = self._hosts_by_ip()
        return sorted(by_ip, key=lambda ip: (0 if self.target in by_ip[ip] else 1, ip))

    def _bounded(self, name: str, subjects: Sequence[Any], limit_name: str) -> List[Any]:
        """
        Apply one budget and account for it. A subject the budget drops is
        not scanned this run; pretending otherwise would make a bounded run
        look like complete coverage.
        """
        limit = self.limits[limit_name]
        selected = list(subjects[:limit])
        omitted = list(subjects[limit:])
        self._coverage[name] = {
            "limit_name": limit_name, "limit": limit,
            "derived": len(subjects), "selected": len(selected), "omitted": len(omitted),
            "omitted_subjects": [_json_safe(x) for x in omitted[:MAX_RECORDED_OMITTED_SUBJECTS]],
        }
        return selected

    def scan_ips(self) -> List[str]:
        """Scannable IPs under the `max_scan_ips` budget, accounted for."""
        return self._bounded("scan_ips", self.scannable_ips(), "max_scan_ips")

    def _open_ports_by_ip(self) -> Dict[str, List[int]]:
        by_ip: Dict[str, Set[int]] = {}
        for key, asset in self._records("assets"):
            if asset.get("asset_type") != surface_mapper.ASSET_PORT:
                continue
            value = asset.get("value")
            if not isinstance(value, dict):
                continue
            if str(value.get("protocol", "tcp")).lower() != "tcp":
                continue
            status = self._attr_value(self._attrs("assets", key, asset), "status")
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

        hosts_by_ip = self._hosts_by_ip()
        open_ports = self._open_ports_by_ip()
        for ip in sorted(hosts_by_ip):
            for port in open_ports.get(ip, []):
                if port not in WEB_PORT_SCHEMES:
                    continue
                for host in hosts_by_ip[ip]:
                    _add(_base_url(host, port))

        if not urls:
            for host in self.in_scope_hostnames():
                key = surface_mapper._aid(surface_mapper.ASSET_HOSTNAME, host)
                host_asset = self.mapper.get_asset(key)
                attributes = self._attrs("assets", key, host_asset) if isinstance(host_asset, dict) else {}
                resolves = bool(attributes.get("dns_a") or attributes.get("dns_aaaa"))
                if resolves or host == self.target:
                    _add(f"https://{host}/")

        # Deterministic ordering with the target's own origin first.
        urls.sort(key=lambda u: (0 if _hostname_of(u) == self.target else 1, u))
        return self._bounded("web_base_urls", urls, "max_web_targets")

    def ssl_targets(self) -> List[Tuple[str, int]]:
        """(hostname, port) pairs worth a TLS inspection."""
        pairs: Set[Tuple[str, int]] = set()
        open_ports = self._open_ports_by_ip()
        for ip, hosts in self._hosts_by_ip().items():
            for port in open_ports.get(ip, []):
                if port in TLS_PORTS:
                    for host in hosts:
                        pairs.add((host, port))
        for host in self.in_scope_hostnames():
            pairs.add((host, ssl_analyzer.DEFAULT_PORT))
        ordered = sorted(pairs, key=lambda p: (0 if p[0] == self.target else 1, p[0], p[1]))
        return self._bounded("ssl_targets", ordered, "max_ssl_targets")

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

        for _, observation in self._records("observations"):
            if observation.get("type") != "javascript_reference":
                continue
            value = observation.get("value")
            if not isinstance(value, dict):
                continue
            url = value.get("url")
            if url and _subject_url_ok(url, self.target):
                urls.add(str(url))

        for asset in self._assets_of_type(surface_mapper.ASSET_JAVASCRIPT):
            if asset.get("in_scope") is True and _subject_url_ok(asset.get("value"), self.target):
                urls.add(str(asset["value"]))

        return self._bounded("javascript_urls", sorted(urls), "max_js_files")

    def crawled_page_urls(self) -> List[str]:
        """
        In-scope pages crawler.py actually fetched.

        Read from the graph rather than only from this run's crawler return
        value, so a resumed run (where the crawl already happened) still has
        real pages to hand to supply_chain.py.
        """
        urls: Set[str] = set(self._crawled_pages)
        for _, observation in self._records("observations"):
            if observation.get("type") != "crawled_url":
                continue
            value = observation.get("value")
            url = value.get("url") if isinstance(value, dict) else None
            if url and _subject_url_ok(url, self.target):
                urls.add(str(url))
        return sorted(u for u in urls if _subject_url_ok(u, self.target))

    def endpoint_urls(self) -> List[str]:
        """In-scope, absolute endpoint URLs the graph knows about."""
        return sorted({
            str(a["value"])
            for a in self._assets_of_type(surface_mapper.ASSET_ENDPOINT)
            if a.get("in_scope") is True and _subject_url_ok(a.get("value"), self.target)
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
        technology_assets = [
            (key, asset) for key, asset in self._records("assets")
            if asset.get("asset_type") == surface_mapper.ASSET_TECHNOLOGY
        ]
        for key, asset in sorted(technology_assets, key=lambda item: item[0]):
            value = asset.get("value")
            if not isinstance(value, dict) or not value.get("name"):
                continue
            if asset.get("in_scope") is False:
                continue
            attributes = self._attrs("assets", key, asset)
            version_attr = attributes.get("version")
            if not isinstance(version_attr, dict):
                version_attr = {}
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
                    f"technology asset {key} observed on {scope!r} by "
                    f"{', '.join(str(s) for s in (version_attr.get('sources') or []) if s) or 'unknown'}"
                ],
                "target": host or self.target,
            })
        return observations

    def _run_tech_fingerprint(self, url: str) -> Any:
        """Run tech_fingerprint and keep its summary for endpoint_discovery's wordlist choice."""
        result = tech_fingerprint.run_tech_fingerprint(
            url, target=self.target, output_dir=self.output_dir, timeout=self.timeout)
        if isinstance(result, dict) and isinstance(result.get("technology_summary"), dict):
            self._technology_by_url[url] = result["technology_summary"]
        return result

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
            seed_ips = self.scan_ips()
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
        ips = self.scan_ips()

        if self._enabled("active_recon"):
            if not ips:
                self._skip("active_recon",
                           "no IPv4 address is correlated to an in-scope hostname in the graph, "
                           "so there is no authorized host to scan"
                           + self._upstream_failure_note("passive_recon"))
            hosts_by_ip = self._hosts_by_ip()
            for ip in ips:
                hosts = hosts_by_ip.get(ip, [])
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
                self._skip("ssl_analyzer", "no in-scope hostname is available for TLS inspection"
                           + self._upstream_failure_note("passive_recon"))
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
            vhost_ips = self._bounded("vhost_ips", ips, "max_vhost_ips")
            if not vhost_ips:
                self._skip("vhost_scanner",
                           "virtual-host discovery requires a discovered in-scope IP to send "
                           "Host-header variations to"
                           + self._upstream_failure_note("passive_recon"))
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
            note = self._upstream_failure_note("passive_recon", "active_recon")
            for name in PHASE_MODULES[PHASE_ACTIVE_WEB]:
                if self._enabled(name):
                    self._skip(name, "no in-scope web base URL could be derived from the graph" + note)
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
                if self._skip_unreachable("tech_fingerprint", url):
                    continue
                self._invoke(
                    "tech_fingerprint", url,
                    f"identifying the technology stack behind {url} selects the tech-aware "
                    f"wordlists endpoint_discovery uses and the versions vuln_intel maps to CVEs",
                    self._run_tech_fingerprint, url,
                )

        if self._enabled("crawler"):
            for url in base_urls:
                if self._skip_unreachable("crawler", url):
                    continue
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
                self._skip("js_analyzer", "no in-scope JavaScript asset has been discovered yet"
                           + self._upstream_failure_note("crawler"))
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
                if self._skip_unreachable("endpoint_discovery", url):
                    continue
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
                    identity=self._endpoint_discovery_identity(url, technology),
                )

        if self._enabled("api_recon"):
            for url in base_urls:
                if self._skip_unreachable("api_recon", url):
                    continue
                self._invoke(
                    "api_recon", url,
                    f"dedicated API reconnaissance of {url} identifies versions, specifications, "
                    f"GraphQL schemas, deprecated endpoints and authentication mechanisms",
                    api_recon.run_api_recon,
                    url, target=self.target, output_dir=self.output_dir, timeout=self.timeout,
                )

        if self._enabled("exposure_scan"):
            endpoints_for = self._endpoints_by_base_url(base_urls)
            for url in base_urls:
                if self._skip_unreachable("exposure_scan", url):
                    continue
                scoped = endpoints_for.get(url, [])
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
            subdomains = self._bounded("supply_chain_subdomains", self.in_scope_hostnames(),
                                       "max_supply_chain_subdomains")
            self._invoke(
                "supply_chain", f"{len(pages)} page(s) / {len(subdomains)} subdomain(s)",
                f"map third-party dependencies across {len(pages)} in-scope page(s) and "
                f"third-party DNS delegation across {len(subdomains)} subdomain(s)",
                supply_chain.run_supply_chain_analysis,
                pages=pages, subdomains=subdomains, target=self.target,
                output_dir=self.output_dir, timeout=self.timeout,
            )

    def _supply_chain_pages(self, base_urls: Sequence[str]) -> List[str]:
        pages: List[str] = []
        seen: Set[str] = set()
        for url in list(base_urls) + self.crawled_page_urls() + self.endpoint_urls():
            if url in seen:
                continue
            seen.add(url)
            # A page on an origin that answered nothing cannot yield a
            # third-party inventory; it can only spend a full timeout. The
            # subdomain DNS half of this module is unaffected and still runs.
            if self._unreachable_reason(url) is not None:
                self._unreachable_pages.append(url)
                continue
            pages.append(url)
        return self._bounded("supply_chain_pages", pages, "max_supply_chain_pages")

    def _endpoints_by_base_url(self, base_urls: Sequence[str]) -> Dict[str, List[str]]:
        """
        Assign each known in-scope endpoint to exactly one base URL for
        exposure_scan's per-endpoint OPTIONS probing: the base URL of its own
        origin, or — for an endpoint whose origin has no base URL of its
        own, e.g. an http:// URL learned from history when only https:// is
        served — the first base URL of its hostname. Handing every base URL
        of a host the host's whole endpoint list probed each endpoint once
        per base URL.
        """
        by_origin: Dict[str, str] = {}
        first_by_host: Dict[str, str] = {}
        # A base URL whose origin answered nothing is skipped, so an endpoint
        # assigned to it as its host's fallback owner would never be probed at
        # all. Reachable base URLs are therefore preferred as the fallback;
        # the per-origin assignment above is unaffected, because an endpoint
        # on a dead origin has nowhere better to go either way.
        for candidate_pass in (False, True):
            for url in base_urls:
                if (self._unreachable_reason(url) is not None) != candidate_pass:
                    continue
                origin, host = _origin_of(url), _hostname_of(url)
                if origin and origin not in by_origin:
                    by_origin[origin] = url
                if host and host not in first_by_host:
                    first_by_host[host] = url
        assigned: Dict[str, List[str]] = {url: [] for url in base_urls}
        for endpoint in self.endpoint_urls():
            origin, host = _origin_of(endpoint), _hostname_of(endpoint)
            owner = by_origin.get(origin or "") or first_by_host.get(host or "")
            if owner is not None:
                assigned[owner].append(endpoint)
        return assigned

    # =====================================================================
    # Adaptive round — react to surface_mapper.py's opportunities
    # =====================================================================

    # Maps an opportunity's subject asset onto a concrete, existing module
    # call. Anything not listed here is surfaced for review rather than
    # guessed at.
    # An adaptive action: (module, subject, callable, identity key).
    AdaptiveAction = Tuple[str, str, Callable[[], Any], "Orchestrator.Identity"]

    def _adaptive_action(self, opportunity: Dict[str, Any],
                         scannable: Set[str]) -> Tuple[Optional["Orchestrator.AdaptiveAction"], str]:
        """
        Resolve one opportunity to a concrete action, or to the reason it
        cannot be acted on this run. An unactionable opportunity is left
        pending (a later run with a different module set may act on it);
        the reason is reported rather than the opportunity being silently
        dropped or mislabelled as budget-deferred.
        """
        opp_type = opportunity.get("opportunity_type")
        value = opportunity.get("target_value")
        asset = self.mapper.get_asset(str(opportunity.get("target_asset_id")))
        if isinstance(asset, dict) and asset.get("in_scope") is False:
            return None, "subject asset is outside the authorized scope"

        suggested = [
            str(m)[:-3] if str(m).endswith(".py") else str(m)
            for m in (opportunity.get("suggested_modules") or [])
        ]
        enabled = [m for m in suggested if self._enabled(m)]
        if not enabled:
            return None, f"none of the suggested module(s) {suggested} is enabled in mode {self.mode!r}"
        module_name = enabled[0]

        if opp_type in ("new_hostname_via_cert_san", "vhost_web_followup"):
            host = str(value)
            if not _valid_hostname(host) or not surface_mapper.is_in_scope(host, self.target):
                return None, f"{host!r} is not a valid in-scope hostname"
            return self._call_for(module_name, f"https://{host}/", host)

        if opp_type == "open_port_followup":
            if not isinstance(value, dict):
                return None, "port opportunity carries no ip/port value"
            ip = str(value.get("ip") or "")
            try:
                port = int(value.get("port"))
            except (TypeError, ValueError):
                return None, "port opportunity carries no numeric port"
            if not ip or ip not in scannable:
                return None, f"{ip!r} is not resolved by any in-scope hostname"
            if port in WEB_PORT_SCHEMES:
                hosts = self._hostnames_for_ip(ip)
                if not hosts:
                    return None, f"no in-scope hostname resolves to {ip}"
                # The web phase already ran this module against every
                # hostname of this ip:port it knew of; act on the first
                # hostname it did not cover, else report it as satisfied.
                resolved: Tuple[Optional["Orchestrator.AdaptiveAction"], str] = (None, "")
                for host in hosts:
                    resolved = self._call_for(module_name, _base_url(host, port), host)
                    if resolved[0] is None or self._satisfied_by(resolved[0][3]) is None:
                        break
                return resolved
            if module_name == "active_recon":
                # The port was discovered by active_recon's own scan of this
                # IP, which enumerated services on it in the same execution.
                # If that scan happened this run the opportunity is
                # satisfied; otherwise there is nothing new to do this run.
                identity = self._identity("active_recon", ip)
                if self._satisfied_by(identity) is not None:
                    return ("active_recon", ip, lambda: None, identity), ""
                return None, "port already enumerated by the active_recon scan that discovered it"
            return None, f"non-web port {port} has no {module_name} follow-up"

        if opp_type == "technology_specific_enumeration":
            if not isinstance(value, dict):
                return None, "technology opportunity carries no name/scope value"
            scope = str(value.get("scope") or "")
            url = scope if "://" in scope else f"https://{scope}/"
            host = _hostname_of(url)
            if not host or not _subject_url_ok(url, self.target):
                return None, f"{scope!r} is not an in-scope subject"
            return self._call_for(module_name, url, host, technology={"technology": value.get("name")})

        if opp_type in ("file_upload_surface_review", "js_referenced_endpoint_verification"):
            url = str(value)
            host = _hostname_of(url)
            if not host or not _subject_url_ok(url, self.target):
                return None, f"{url!r} is not an in-scope URL"
            return self._call_for(module_name, url, host)

        return None, f"no orchestration mapping for opportunity type {opp_type!r}"

    def _call_for(self, module_name: str, url: str, host: str,
                  technology: Optional[Dict[str, Any]] = None,
                  ) -> Tuple[Optional["Orchestrator.AdaptiveAction"], str]:
        """Bind one module's real signature to a URL derived from an opportunity."""
        # An opportunity pointing at an origin the run has already proven
        # dead is left pending with the reason, exactly like one whose module
        # is not enabled: the work is still worth doing, just not against an
        # origin that answers nothing. http_analyzer is exempt — one request
        # of it is what establishes reachability for a newly learned host.
        if module_name in WEB_MODULES_NEEDING_A_LIVE_ORIGIN:
            unreachable = self._unreachable_reason(url)
            if unreachable is not None:
                return None, unreachable
        common = {"target": self.target, "output_dir": self.output_dir, "timeout": self.timeout}
        if module_name == "http_analyzer":
            return (module_name, url, lambda: http_analyzer.run_http_analysis(url, **common),
                    self._identity(module_name, url)), ""
        if module_name == "tech_fingerprint":
            return (module_name, url, lambda: self._run_tech_fingerprint(url),
                    self._identity(module_name, url)), ""
        if module_name == "ssl_analyzer":
            subject = f"{host}:{ssl_analyzer.DEFAULT_PORT}"
            return (module_name, subject, lambda: ssl_analyzer.run_ssl_analysis(
                host, port=ssl_analyzer.DEFAULT_PORT, target=self.target,
                output_dir=self.output_dir, timeout=self.timeout),
                    self._identity(module_name, subject)), ""
        if module_name == "endpoint_discovery":
            tech = technology or self._technology_for(url)
            return (module_name, url, lambda: endpoint_discovery.run_endpoint_discovery(
                url, wordlists_dir=self.wordlists_dir,
                technology=tech,
                historical_data=self._historical_data or None,
                js_data=self._js_data or None,
                max_workers=self.threads, **common),
                    self._endpoint_discovery_identity(url, tech)), ""
        if module_name == "api_recon":
            return (module_name, url, lambda: api_recon.run_api_recon(url, **common),
                    self._identity(module_name, url)), ""
        if module_name == "exposure_scan":
            return (module_name, url, lambda: exposure_scan.run_exposure_scan(
                url, wordlists_dir=self.wordlists_dir, max_workers=self.threads, **common),
                    self._identity(module_name, url)), ""
        if module_name == "crawler":
            return (module_name, url, lambda: crawler.run_crawler(
                url, max_workers=self.threads, **common),
                    self._identity(module_name, url)), ""
        if module_name == "passive_recon":
            # An opportunity naming passive_recon is about a newly learned
            # hostname; validate_target() accepts only a bare domain.
            return (module_name, host, lambda: passive_recon.run_passive_recon(
                host, output_dir=self.output_dir, timeout=self.timeout),
                    self._identity(module_name, host)), ""
        if module_name == "vhost_scanner":
            return None, "vhost_scanner needs an IP subject, which no opportunity carries"
        return None, f"module {module_name!r} has no opportunity-driven entry point"

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
        # Built in place on the instance so an interrupt inside the round
        # still leaves the actions it did fire in the result.
        summary = self._adaptive_summary = self._empty_adaptive_summary()
        rounds = self.limits["max_adaptive_rounds"]
        budget = self.limits["max_adaptive_actions"]
        if rounds == 0 or budget == 0:
            return summary

        deferred: Set[str] = set()
        not_actionable: Dict[str, str] = {}
        reviewed: Set[str] = set()
        for _ in range(rounds):
            # Highest priority first so a finite budget goes to the mapper's
            # most valuable work; id as tiebreaker for determinism.
            pending = sorted(
                self._pending_opportunities(),
                key=lambda o: (_PRIORITY_RANK.get(str(o.get("priority")).upper(), 9), str(o.get("id"))),
            )
            if not pending:
                break
            summary["rounds"] += 1
            acted = 0
            scannable = set(self.scannable_ips())
            for opportunity in pending:
                opp_id = str(opportunity["id"])
                if not opportunity.get("suggested_modules"):
                    if opp_id not in reviewed:
                        reviewed.add(opp_id)
                        summary["manual_review"].append({
                            "id": opp_id,
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
                action, reason = self._adaptive_action(opportunity, scannable)
                if action is None:
                    not_actionable[opp_id] = reason
                    continue
                module_name, subject, call, identity = action
                satisfied_by = self._satisfied_by(identity)
                if satisfied_by is None and summary["actions"] >= budget:
                    deferred.add(opp_id)
                    continue
                # Consume first: an action that fails must not be retried on
                # the next round or the next run (retry-loop prevention).
                try:
                    self.mapper.consume_opportunity(opp_id)
                except KeyError:
                    continue
                self._graph_dirty = True
                self._save_graph(f"consume:{opp_id}")
                if satisfied_by is not None:
                    # The work this opportunity asks for already happened in
                    # this run (typically in a phase, before the mapper raised
                    # it). Recorded and consumed, never re-run — a failed
                    # attempt included, since a retry within the same run and
                    # conditions is the retry loop the consume-first rule
                    # exists to prevent.
                    prior_status = next((e["status"] for e in self.executions
                                         if e["execution_id"] == satisfied_by), "unknown")
                    summary["satisfied"].append({
                        "id": opp_id, "opportunity_type": opportunity.get("opportunity_type"),
                        "module": module_name, "subject": subject, "satisfied_by": satisfied_by,
                        "satisfied_by_status": prior_status,
                    })
                    entry = self.decisions.record(
                        "satisfy opportunity",
                        f"{opportunity.get('opportunity_type')} on {subject!r} asks for "
                        f"{module_name}, which {satisfied_by} already attempted in this run "
                        f"(status: {prior_status}); not repeated",
                        module=module_name, phase=PHASE_ADAPTIVE, subject=subject, status="satisfied",
                    )
                    DecisionQueue.complete(entry, "satisfied", satisfied_by=satisfied_by,
                                           satisfied_by_status=prior_status)
                    continue
                summary["consumed"].append({
                    "id": opp_id,
                    "opportunity_type": opportunity.get("opportunity_type"),
                    "module": module_name, "subject": subject,
                })
                summary["actions"] += 1
                acted += 1
                self._invoke(
                    module_name, subject,
                    f"surface_mapper raised {opportunity.get('opportunity_type')} "
                    f"({opportunity.get('priority')}): {opportunity.get('reason')}",
                    call, phase=PHASE_ADAPTIVE, identity=identity,
                )
            if acted == 0:
                break

        # An opportunity deferred in one round and acted on in a later one
        # was not deferred by the run.
        acted_ids = {c["id"] for c in summary["consumed"]} | {c["id"] for c in summary["satisfied"]}
        summary["deferred"] = sorted(deferred - acted_ids)
        remaining = sorted((k, v) for k, v in not_actionable.items() if k not in acted_ids)
        summary["not_actionable"] = [{"id": k, "reason": v} for k, v in remaining[:MAX_RECORDED_NOT_ACTIONABLE]]
        summary["not_actionable_count"] = len(remaining)
        return summary

    @staticmethod
    def _empty_adaptive_summary() -> Dict[str, Any]:
        return {"rounds": 0, "actions": 0, "consumed": [], "satisfied": [], "manual_review": [],
                "deferred": [], "not_actionable": [], "not_actionable_count": 0}

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

        self._adaptive_summary = self._empty_adaptive_summary()
        reraise: Optional[BaseException] = None
        try:
            self._run_phase(PHASE_PASSIVE, self._run_passive_phase)
            self._run_phase(PHASE_ACTIVE_NETWORK, self._run_active_network_phase)
            self._run_phase(PHASE_ACTIVE_WEB, self._run_active_web_phase)
            self._run_adaptive_rounds()
            self._run_phase(PHASE_INTELLIGENCE, self._run_intelligence_phase)
        except KeyboardInterrupt:
            self.interrupted = True
            self.decisions.record(
                "abort run", "keyboard interrupt received; preserving all discoveries "
                             "collected so far before exiting",
                subject=self.target, status=STATUS_INTERRUPTED,
            )
            self._emit({"event": "run_interrupted", "target": self.target})
            # Persist the interrupted status *now*: a second Ctrl+C during the
            # final correlation below must not leave a record claiming the
            # run is still in progress.
            self._save_record()
        except Exception as exc:
            # A fatal orchestration failure. It is reported as a RUN_FAILED
            # result rather than raised, because everything discovered up to
            # this point is real evidence and must survive the failure — the
            # final ingest + save below is the whole point. Invalid
            # configuration still raises, but from __init__, before any work
            # has been done and before anything could be lost.
            self.errors.append({"stage": "orchestration", "error": _redact_secrets(exc),
                                "error_type": type(exc).__name__})
            self.status = RUN_FAILED
            self._save_record()
        except BaseException as exc:
            # SystemExit and friends keep propagating — after the evidence
            # collected so far has been correlated and persisted.
            self.errors.append({"stage": "orchestration", "error": _redact_secrets(exc) or type(exc).__name__,
                                "error_type": type(exc).__name__})
            self.status = RUN_FAILED
            reraise = exc

        # Final correlation + persistence, whatever happened above.
        final_ingest = self._ingest(phase=PHASE_CORRELATION, after="shutdown", force_save=True)
        self.finished_at = _now()
        result = self._build_result(self._adaptive_summary, final_ingest)
        self._save_record(result)
        self._emit({"event": "run_finished", "target": self.target, "status": result["status"]})
        if reraise is not None:
            raise reraise
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

        # The scope block below re-derives subjects, which is also where a
        # malformed persisted record would surface; derive first so the
        # anomaly report covers the whole run.
        scope = {
            "target": self.target,
            "in_scope_hostnames": self.in_scope_hostnames(),
            "out_of_scope_hostnames_observed": self.out_of_scope_hostnames(),
            # What active_recon was actually pointed at this run — not what
            # the graph would offer now, which may include addresses learned
            # after the network phase had already run.
            "scanned_ips": sorted({
                str(e["subject"]) for e in self.executions
                if e["module"] == "active_recon" and e["status"] != STATUS_SKIPPED}),
            "scannable_ips": self.scan_ips(),
            "unusable_in_scope_hostnames": {
                "count": len(self._unusable_hosts),
                "sample": [{"hostname": h, "reason": r} for h, r in
                           sorted(self._unusable_hosts.items())[:MAX_RECORDED_OMITTED_SUBJECTS]],
            },
            # Addresses an in-scope hostname resolves to that were refused as
            # active-scan subjects because they address the scanning host
            # rather than the target (see `_not_a_remote_host`).
            "refused_scan_ips": [
                {"ip": ip, "reason": reason} for ip, reason in
                sorted(self._unscannable_ips.items())[:MAX_RECORDED_OMITTED_SUBJECTS]
            ],
        }
        graph_summary = self._graph_summary()
        if self._state_anomalies and not any(e.get("stage") == "graph_state" for e in self.errors):
            samples = [text for _, text in sorted(self._state_anomalies.items())[:10]]
            self.errors.append({
                "stage": "graph_state",
                "error": f"{len(self._state_anomalies)} malformed record(s) in the persisted surface "
                         f"graph were ignored while deriving subjects; the graph may be hand-edited "
                         f"or partially written: " + "; ".join(samples),
                "error_type": "MalformedGraphState",
                "count": len(self._state_anomalies),
            })

        pending = sorted(self._pending_opportunities(), key=lambda o: str(o.get("id")))
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
                "summary": graph_summary,
                "final_ingest": final_ingest,
                "conflicts": len(self.mapper.state["conflicts"]),
                "ingestion_errors": len(self.mapper.state["ingestion_errors"]),
            },
            "opportunities": {
                "pending": [
                    {"id": o.get("id"), "opportunity_type": o.get("opportunity_type"),
                     "target_value": o.get("target_value"), "priority": o.get("priority"),
                     "reason": o.get("reason"),
                     "suggested_modules": o.get("suggested_modules", [])}
                    for o in pending
                ],
                "consumed_this_run": adaptive.get("consumed", []),
                "satisfied_this_run": adaptive.get("satisfied", []),
                "manual_review": adaptive.get("manual_review", []),
            },
            "risk": self._risk,
            "scope": scope,
            "coverage": {
                "complete": (not any(c["omitted"] for c in self._coverage.values())
                             and not self._unreachable_origins),
                "budgets": dict(sorted(self._coverage.items())),
                # Origins that answered nothing. Enumeration of them was
                # skipped rather than spent on transport failures, so they
                # are a hole in this run's coverage and are named as one —
                # "nothing was found there" would be a false statement about
                # a subject that was never checked.
                "unreachable_origins": [
                    {"origin": origin, "reported_as": status}
                    for origin, status in sorted(self._unreachable_origins.items())
                ],
                "unreachable_pages_omitted": sorted(set(self._unreachable_pages)),
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

    def _pending_opportunities(self) -> List[Dict[str, Any]]:
        """
        The mapper's pending opportunities, or — if a malformed persisted
        opportunity record makes it raise — the same selection made
        tolerantly, with the bad record noted as a state anomaly.
        """
        try:
            return [o for o in self.mapper.get_pending_opportunities() if isinstance(o, dict) and o.get("id")]
        except Exception as exc:
            self._state_anomalies.setdefault(("opportunities", "*"), f"opportunity listing failed: {exc}")
            out: List[Dict[str, Any]] = []
            for key, opp in self._records("opportunities"):
                if opp.get("status") == "pending" and opp.get("id"):
                    out.append(opp)
            return out

    def _graph_summary(self) -> Dict[str, Any]:
        """
        The mapper's own summary, or — if a malformed persisted record makes
        it raise — the same shape counted tolerantly, with the failure noted
        as a state anomaly rather than lost with the whole result document.
        """
        try:
            return self.mapper.summary()
        except Exception as exc:
            self._state_anomalies.setdefault(("summary", "assets"), f"graph summary failed: {exc}")
            state = self.mapper.state
            by_type: Dict[str, int] = {}
            for _, asset in self._records("assets"):
                kind = str(asset.get("asset_type"))
                by_type[kind] = by_type.get(kind, 0) + 1
            return {
                "target": self.target,
                "observations": len(state.get("observations") or {}),
                "assets": len(state.get("assets") or {}),
                "assets_by_type": by_type,
                "relationships": len(state.get("relationships") or {}),
                "conflicts": len(state.get("conflicts") or {}),
                "negative_results": len(state.get("negative_results") or {}),
                "check_states": len(state.get("check_states") or {}),
                "pending_opportunities": len([
                    o for o in (state.get("opportunities") or {}).values()
                    if isinstance(o, dict) and o.get("status") == "pending"]),
                "ingestion_errors": len(state.get("ingestion_errors") or []),
                "summary_error": _redact_secrets(exc),
            }

    def _save_record(self, result: Optional[Dict[str, Any]] = None) -> None:
        if not self.persist_execution_record:
            return
        try:
            if result is None:
                if self.interrupted:
                    interim = RUN_INTERRUPTED
                elif self.status == RUN_FAILED:
                    interim = RUN_FAILED
                else:
                    interim = "running"
                result = {
                    "module": MODULE_NAME, "target": self.target, "mode": self.mode,
                    "status": interim, "started_at": self.started_at,
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
            self._record_repeating_error("execution_record", exc)


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
