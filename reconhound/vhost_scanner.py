"""
reconhound/vhost_scanner.py — ReconHound Module 9 (vhost_scanner.py), per
context.md's build order — catalog item 9 in §10's module list,
build-order position 22 (context.md §13; this module was built under an
explicit deviation from the numeric build order — surface_mapper.py,
core/orchestrator.py and reconhound.py were not yet implemented at the
time. They exist now; see BUILD-ORDER NOTE below).

Phase: Active. See context.md §10 (module 9, "Virtual-host discovery") for
the authoritative responsibilities, and §8 for the evidence/confidence
data model this module implements. This file only documents
implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Active — Virtual-host discovery via Host-header variation against
  discovered IPs; surfaces hidden apps not visible via DNS; each
  discovered vhost triggers web recon. Key differentiator."

The assignment's module contract expands that into these discrete
responsibilities, each implemented below:

  1. Controlled Host-header probing against an already-discovered,
     in-scope IP                              -> fetch_with_host_header
  2. Candidate vhost hostname construction
     (wordlist-driven + caller-supplied,
     scope-filtered)                          -> build_candidate_hostnames
  3. Baseline fingerprinting (what "no distinct
     application" looks like on this IP)      -> probe_baselines
  4. Meaningful-difference scoring (never claim
     a vhost from a bare 2xx alone)           -> score_vhost_candidate
  5. Per-IP/port/scheme vhost discovery
     orchestration + negative-result memory   -> discover_vhosts_for_target,
                                                  persist_no_distinct_response
  6. Shaping each discovered vhost into a
     downstream web-recon target              -> build_downstream_recon_target
  7. Decision-queue-shaped next-action
     recommendations (feeds surface_mapper.py) -> build_recommended_actions
  8. Normalization for surface_mapper.py        -> build_vhost_summary
  (single-target orchestrator)                  -> run_vhost_scan

Plus shared plumbing: make_finding/make_vhost_finding, PendingAssetsStore,
_safe_store_add, validate_scan_ip, load_wordlist (duplicated per modular
independence, same as every other implemented module).

BUILD-ORDER NOTE: context.md §13 lists this module at build-order position
22, after surface_mapper.py (position 8). It was written under an explicit,
user-approved deviation from that order, before surface_mapper.py existed.
surface_mapper.py, core/orchestrator.py and reconhound.py are now
implemented, and this module is wired into them as a producer only:
core/orchestrator.py calls run_vhost_scan() per discovered IP, and
surface_mapper.py's `_h_vhost_discovered` ingests the `vhost_discovered`
findings this module persists. It remains a fully standalone producer that
does not implement, replace, or depend on surface_mapper.py's correlation
engine.

NO-CROSS-MODULE-CALLS PRECEDENT (responsibilities #6/#7, "each discovered
vhost triggers web recon" / "feed vhost intelligence into
surface_mapper.py"): every already-implemented Active-phase module in this
repository documents that it does NOT import or call into any sibling
module — integration is delegated to core/orchestrator.py, which routes
data between modules via surface_mapper.py. This
module follows the same precedent rather than inventing a competing
orchestration mechanism. Responsibility #6/#7 is satisfied by:

  a. build_downstream_recon_target: a normalized, JSON-safe record naming
     exactly what a downstream module needs to reach a hidden vhost — the
     already-authorized `connect_url` (IP-based, never the unresolvable
     hostname itself) plus the explicit `host_header_override` a caller
     must send. No existing module's fetch_url() accepts a Host-header
     override parameter today, so this module does not silently assume
     one does; it documents the requirement in the record's own `note`
     field for the future orchestrator/surface_mapper integration layer.
  b. build_recommended_actions: an explicit, evidence-justified
     decision-queue-shaped list (context.md §9) naming which
     already-implemented modules are appropriate next steps for a newly
     confirmed vhost. These are recommendations for the future
     orchestrator to execute — this module never invokes them itself.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other implemented module, sharing the same output file). This module
does not implement or call into surface_mapper, active_recon,
tech_fingerprint, endpoint_discovery, api_recon, crawler, js_analyzer,
supply_chain, exposure_scan, http_analyzer, ssl_analyzer, vuln_intel,
risk_engine, report_generator, orchestrator, osint_engine,
passive_recon, passive_intel, code_leak, wayback_intel, or any other module.

DISCOVERY != EXPLOITATION: this module only ever issues read-only GET
requests with a modified Host header against an IP the caller has already
identified as in-scope (e.g. via active_recon.py/passive_recon.py). It
never brute-forces credentials, never sends a state-changing request, and
never expands the scanned surface beyond that one supplied IP — every
candidate Host-header string is either derived from the authorized target
domain or explicitly scope-filtered (build_candidate_hostnames).

Implementation decisions (ambiguities resolved so implementation can
proceed without inventing requirements):

  1. Candidate hostname source: context.md §11's folder structure names
     `wordlists/subdomains.txt` explicitly as part of the locked
     architecture, but no file existed yet at that path (only
     directories.txt/api_endpoints.txt/*_paths.txt did). This module adds
     that already-specified wordlist file and loads it the same way
     endpoint_discovery.py loads directories.txt (load_wordlist,
     duplicated here per modular independence) — this fills in an
     already-approved architectural gap, it does not invent a new one.
     Each wordlist label is combined with the caller's `target` domain
     (e.g. "admin" + "example.com" -> "admin.example.com"). Callers may
     also supply `extra_hostnames` (e.g. hostnames already observed
     elsewhere — cert SANs, wayback history, OSINT — that are worth
     testing against a newly discovered IP to see if it also serves them).
  2. Scope enforcement for candidate hostnames: every constructed or
     caller-supplied candidate is checked against `target` (exact match or
     subdomain) before being probed; anything out of scope is recorded in
     `skipped_out_of_scope` (never silently dropped) rather than probed,
     unless the caller explicitly opts in via `allow_out_of_scope_hostnames`
     (default False) — mirrors CLAUDE.md rule 9's "strict target-scope
     enforcement" default. The IP itself is validated separately
     (validate_scan_ip) as a syntactically valid IP address; this module
     trusts that the caller (e.g. active_recon.py's output) already
     confirmed the IP itself belongs to the authorized engagement, the
     same trust boundary active_recon.py/tech_fingerprint.py already rely
     on for their own inputs.
  3. Two-baseline differencing (responsibility #4, the assignment's "avoid
     reporting a hostname as a discovered vhost solely because a request
     succeeded" requirement): every IP/port/scheme is first probed twice —
     once with the Host header set to the bare IP itself (approximates
     "what a client hitting this IP directly, with no vhost knowledge,
     sees") and once with a random, near-certainly-unrecognized Host value
     (approximates "what this server does with any Host it doesn't
     recognize"). A candidate is only ever reported as a discovered vhost
     when its response differs *from both* baselines on at least one
     meaningful signal (HTTP status code, response-body content hash,
     redirect Location target, or page `<title>`). A candidate that merely
     succeeds but matches either baseline exactly is recorded as a
     negative result (persist_no_distinct_response), not a discovery —
     this directly implements context.md §12.6's negative-result-memory
     principle for this module's own (potentially large) candidate list.
  4. Confidence scoring mirrors tech_fingerprint.py's weighted-signal
     model for consistency across the codebase: a status-code difference,
     a content-hash difference, or a redirect-target difference from both
     baselines is "strong" (2 points each); a `<title>` difference alone
     is "weak" (1 point). Confidence = HIGH at score >= 3, MEDIUM at
     score == 2, LOW at score == 1 (context.md §8: multiple independent
     converging signals raise confidence; a single weak signal stays LOW,
     a single strong signal reaches MEDIUM on its own). A LOW-confidence
     result is still reported (never silently dropped) but is explicitly
     flagged as uncertain, per the assignment's "represent uncertainty
     appropriately" requirement — it is only a *non-discovery* (negative
     result) when the score is exactly 0.
  5. HTTPS handling: the whole point of vhost scanning is deliberately
     sending a Host header that does not match the connection's actual
     target. For HTTPS this means the TLS layer's SNI still targets the
     bare IP (Python's `ssl`/`requests`/`urllib3` derive SNI from the
     connection host, not from a caller-supplied Host header — overriding
     that would require a custom SNI-aware HTTPAdapter, which is out of
     scope for "one module at a time" and not requested by the module
     contract). Certificate hostname validation is therefore also
     meaningless here and is disabled (`verify=False`, with the resulting
     urllib3 InsecureRequestWarning suppressed) — this mirrors
     passive_recon.py's/ssl_analyzer.py's own conscious, documented
     decision to skip certificate validation for reconnaissance purposes.
     This is a real, documented limitation: differentiation over HTTPS
     happens only at the post-TLS HTTP layer (which is exactly what many
     real deployments key their vhost routing on regardless of SNI), not
     a claim that SNI itself was spoofed.
  6. Sequential, not threaded, candidate probing: mirrors api_recon.py's
     decision #2 and its stated rationale — this module's candidate lists
     are bounded (a wordlist of common vhost labels plus a small,
     caller-supplied extra-hostnames list), so a thread pool's added
     complexity (and, more concretely, the loss of deterministic
     mock-based testability that every other implemented module's test
     suite relies on for `requests.get` call ordering) is not justified
     here. `max_candidates` lets a caller/orchestrator bound the work
     explicitly. Multiple discovered IPs are expected to be parallelized
     by the future orchestrator across separate run_vhost_scan() calls,
     not within a single call's candidate loop.
  7. "No override" baseline approximation: a real client connecting
     directly to an IP with no vhost-fuzzing intent would typically send
     `Host: <ip>` (or `Host: <ip>:<port>` for a non-default port) —
     port-qualification is not modeled separately here; the baseline Host
     header is always the bare IP string (bracketed for IPv6, because a
     bare IPv6 literal is not a valid HTTP authority). This is a documented
     simplification, not a gap: the unrecognized-Host baseline exists
     precisely to catch cases where this approximation alone would be
     misleading.

  8. HTTP status semantics — failure is not an answer. A 2xx/3xx/4xx
     response is the server answering the virtual-host question; a
     429/5xx/edge-failure response is the origin or an intermediary
     declining to answer it (NON_AUTHORITATIVE_STATUSES). Scoring one of
     those manufactures a discovery out of a provider failure, and
     recording it as a negative manufactures an absence out of one — so
     they produce an *inconclusive* outcome, which is counted and reported
     but never persisted as negative-result memory. HTTP 421 (Misdirected
     Request) is the sole exception: it is the server authoritatively
     stating it does not serve this authority, and is therefore recorded
     as a genuine negative result.

  9. Rate limiting is respected, never worked around. Nothing is ever
     retried, so worst-case request amplification is exactly one request
     per candidate plus four baseline probes per ip/port/scheme. After
     `max_consecutive_rate_limited` consecutive 429/503 responses, probing
     of that ip/port/scheme is abandoned and the remaining candidates are
     recorded as *not tested*; any `Retry-After` value is surfaced to the
     operator rather than slept on. No evasion, proxy rotation, source
     spoofing or WAF bypass is implemented — this module stays
     reconnaissance (CLAUDE.md rules 9/10).

 10. Candidate hostname syntax is validated before any network activity and
     before any persistence (normalize_candidate_hostname). A Host header
     is a bare authority: never a URL, never port-qualified, never carrying
     userinfo, and never carrying control characters. An entry such as
     "a\r\nX-Injected: 1.example.com" ends in the authorized suffix and
     would otherwise pass the scope check and be handed to the HTTP client
     as a request-splitting attempt. IDN candidates are converted to
     punycode here rather than emitted as a header value the client cannot
     encode. Rejected entries are recorded in `skipped_invalid`, never
     silently dropped. The authorized target itself is validated the same
     way (validate_scan_target) so scope enforcement fails closed.

 11. Hostile responses are handled in bounded time and bounded space.
     Title extraction scans a bounded window with linear string operations
     rather than a backtracking regex (the previous regex cost ~188 ms for
     8,000 repetitions of an unterminated `<title` in 49 KB), and every
     attacker-controlled string embedded in persisted evidence is clipped.
     Per-candidate detail lists in the module summary are capped while
     their counts stay exact.

 12. Attribution on shared infrastructure. A CDN edge, reverse proxy or
     load balancer answers for many unrelated tenants from one address, so
     a working Host header there does not establish that the origin behind
     it belongs to the authorized target. Edge indicators (`CF-Ray`,
     `X-Amz-Cf-Id`, `Via`, a known edge `Server` value, ...) are recorded
     as evidence and cap the reported confidence at MEDIUM; they never
     suppress the discovery, and the contradictory reading is preserved in
     the finding's `caveats` rather than resolved away (context.md §8).
     PTR, ASN and certificate SAN evidence are deliberately *not* consulted
     here as ownership proof — correlating them belongs to
     surface_mapper.py.

 13. Baseline stability (the primary false-positive defence). Each baseline
     is sampled twice, and any signal that does not reproduce across both
     samples is per-response noise and is excluded from scoring entirely.
     Without this, a default page carrying a request id, session id, nonce
     or timestamp makes every candidate's body differ from both baselines
     and the whole wordlist is reported as discovered virtual hosts. A
     signal that could not be compared also cannot support a *negative*:
     when the body comparison is unusable, a zero score is reported as
     inconclusive rather than as established absence.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import threading
import urllib3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

MODULE_NAME = "vhost_scanner.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_USER_AGENT = "ReconHound-VhostScanner/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_MAX_BODY_BYTES = 131072
DEFAULT_WORDLIST_NAME = "subdomains.txt"

# (port, scheme) pairs probed when the caller does not supply its own list.
DEFAULT_PORTS: Tuple[Tuple[int, str], ...] = ((80, "http"), (443, "https"))

SUPPORTED_SCHEMES: Tuple[str, ...] = ("http", "https")
_MIN_PORT, _MAX_PORT = 1, 65535

# TLS SNI selection for scheme="https" (implementation decision #5).
SNI_MODE_CONNECTION = "connection"
SNI_MODE_CANDIDATE = "candidate"
SUPPORTED_SNI_MODES: Tuple[str, ...] = (SNI_MODE_CONNECTION, SNI_MODE_CANDIDATE)

# Signal-scoring weights (implementation decision #4)
_SCORE_STRONG = 2
_SCORE_WEAK = 1
_HIGH_THRESHOLD = 3
_MEDIUM_THRESHOLD = 2

_CONFIDENCE_RANK = {CONFIDENCE_LOW: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_HIGH: 2}

# --- HTTP status semantics (implementation decision #8) --------------------
# Statuses the origin or an intermediary produced *instead of* answering the
# virtual-host question. Scoring one of these manufactures a discovery out of
# a provider/target failure; recording it as a negative manufactures an
# absence out of one. Both are forbidden — these outcomes are inconclusive.
NON_AUTHORITATIVE_STATUSES = frozenset({
    408, 425, 429,                            # request timeout / too early / rate limited
    500, 502, 503, 504, 507, 508, 509,        # origin or gateway failure
    520, 521, 522, 523, 524, 525, 526, 527, 530,  # edge-to-origin failures (Cloudflare-style)
})
# 421 is the one status where a server authoritatively answers the vhost
# question in the negative: "I am not configured to serve this authority".
MISDIRECTED_REQUEST_STATUS = 421
RATE_LIMIT_STATUSES = frozenset({429, 503})
# Consecutive rate-limit/edge-failure responses after which probing this
# ip/port/scheme is abandoned. Nothing is ever retried, so worst-case request
# amplification stays exactly 1 request per candidate (decision #9).
DEFAULT_MAX_CONSECUTIVE_RATE_LIMITED = 5

# score_vhost_candidate() reasons that mean "could not establish a result",
# never "this hostname is not a virtual host here" (decision #8).
INCONCLUSIVE_REASONS = frozenset({
    "candidate_fetch_failed",
    "both_baselines_unavailable",
    "non_authoritative_status",
    "comparison_signals_unstable",
})

# --- Candidate hostname syntax (scope enforcement, decision #10) -----------
_MAX_HOSTNAME_CHARS = 253
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_FORBIDDEN_HOST_CHARS = frozenset(" \t\r\n\x00/\\?#@:[]%&;,'\"<>(){}|^`*!$+=~")

# --- Bounded text handling (hostile-response safety, decision #11) ---------
_TITLE_SCAN_LIMIT = 65536
_MAX_EVIDENCE_TEXT = 200
_MAX_EVIDENCE_URL = 512
# Per-candidate detail entries retained in a module summary. Counts stay
# exact; only the listing is bounded (assignment §13, resource safety).
_MAX_RETAINED_DETAIL = 500
_HOST_ECHO_PLACEHOLDER = "\x00vhost-host\x00"

# --- Shared/edge infrastructure indicators (decision #12) ------------------
# Their presence means the observed response was produced or relayed by
# infrastructure shared with unrelated tenants, so a working Host header
# says nothing about who owns the origin behind it.
_EDGE_HEADER_HINTS: Tuple[str, ...] = (
    "cf-ray", "cf-cache-status", "cf-apo-via", "x-amz-cf-id", "x-amz-cf-pop",
    "x-cache", "x-cache-hits", "x-served-by", "x-fastly-request-id",
    "x-akamai-transformed", "akamai-grn", "x-akamai-request-id",
    "x-azure-ref", "x-msedge-ref", "x-vercel-id", "fly-request-id",
    "via", "x-varnish", "x-envoy-upstream-service-time",
)
# Response headers that describe the *application* answering, not the request.
# Their values are stable across requests (unlike Set-Cookie values, request
# ids or timestamps), so a difference here is real evidence that a different
# backend is being reached — see decision #14.
# Cookie *attributes* are not cookie names. requests joins several Set-Cookie
# headers with ", ", and an `Expires=Wed, 21 Oct 2025 ...` date contains a
# comma of its own, so naive splitting turns attributes and date fragments
# into fake cookie names — and a cookie that merely gained an Expires would
# then look like a different application.
_COOKIE_ATTRIBUTE_NAMES = frozenset({
    "expires", "path", "domain", "max-age", "secure", "httponly",
    "samesite", "priority", "partitioned", "version", "comment",
})

_APP_HEADER_HINTS: Tuple[str, ...] = (
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-redirect-by", "content-type",
)

_EDGE_SERVER_HINTS: Tuple[str, ...] = (
    "cloudflare", "cloudfront", "akamaighost", "akamai", "fastly", "varnish",
    "envoy", "awselb", "vercel", "netlify", "bunnycdn", "keycdn",
    "incapsula", "imperva", "sucuri", "windows-azure",
)


class ScopeError(ValueError):
    """Raised when a scan target/hostname falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


class WordlistError(ValueError):
    """Raised when a required wordlist file cannot be loaded."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors active_recon.py's validate_scan_target for the
# IP, and tech_fingerprint.py's/api_recon.py's _in_scope_host for hostnames;
# duplicated per modular independence, context.md §12.2)
# ---------------------------------------------------------------------------

def validate_scan_ip(ip: str) -> str:
    """
    Validate that `ip` is a syntactically valid IPv4 or IPv6 address.

    vhost_scanner operates on IP addresses already discovered and
    confirmed in-scope by upstream modules (e.g. active_recon.py); it never
    resolves or expands a hostname/CIDR range into an IP itself.
    """
    if not isinstance(ip, str) or not ip.strip():
        raise ScopeError("Scan target must be a non-empty IP address string.")

    candidate = ip.strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        raise ScopeError(
            f"Scan target must be a single valid IP address, not {ip!r} "
            f"(hostnames and CIDR ranges are not accepted by this function)."
        ) from None

    return candidate


def _format_host_for_url(ip: str) -> str:
    """Bracket an IPv6 literal for use in a URL; IPv4 is returned unchanged."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return f"[{ip}]" if obj.version == 6 else ip


def validate_scan_target(target: str) -> str:
    """
    Validate the authorized target domain that bounds every candidate
    Host header this module will ever send.

    Fails closed: an unusable target would otherwise silently degrade
    `_in_scope_host` into "nothing is in scope" (or, for a bare TLD-like
    string, into far too much), and scope enforcement must never fail open
    or fail silently (CLAUDE.md rule 9).
    """
    if not isinstance(target, str) or not target.strip():
        raise ScopeError("Authorized target must be a non-empty domain string.")
    normalized = normalize_candidate_hostname(target)
    if normalized is None:
        raise ScopeError(
            f"Authorized target {target!r} is not a syntactically valid hostname; "
            f"candidate Host headers cannot be scope-checked against it."
        )
    return normalized


def normalize_candidate_hostname(hostname: Any) -> Optional[str]:
    """
    Normalize one candidate Host-header value to a lowercase ASCII hostname,
    or return None when it is not a syntactically valid hostname.

    This runs *before* any network activity and *before* any persistence
    (the assignment's §14 requirement). A Host header is a bare authority:
    never a URL, never port-qualified, never carrying userinfo, and never
    carrying control characters — an embedded CR/LF that happens to end in
    the authorized suffix would otherwise pass the scope check and be handed
    to the HTTP client as a request-splitting attempt. Non-ASCII (IDN) names
    are converted to punycode here rather than being emitted as a header
    value the HTTP client cannot encode.
    """
    if not isinstance(hostname, str):
        return None
    candidate = hostname.strip().strip(".")
    if not candidate:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        return None
    if any(ch in _FORBIDDEN_HOST_CHARS for ch in candidate):
        return None
    candidate = candidate.lower()
    if not candidate.isascii():
        try:
            candidate = candidate.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            return None
    if len(candidate) > _MAX_HOSTNAME_CHARS:
        return None
    labels = candidate.split(".")
    if not labels or any(_LABEL_RE.match(label) is None for label in labels):
        return None
    return candidate


def _in_scope_host(hostname: str, target: str) -> bool:
    hostname = (hostname or "").strip().rstrip(".").lower()
    target = (target or "").strip().rstrip(".").lower()
    if not hostname or not target:
        return False
    return hostname == target or hostname.endswith("." + target)


def _validate_port_scheme(port: Any, scheme: Any) -> Tuple[int, str]:
    """Validate one (port, scheme) pair before it is turned into a URL."""
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        raise ScopeError(f"Port must be an integer, not {port!r}.") from None
    if not (_MIN_PORT <= port_int <= _MAX_PORT):
        raise ScopeError(f"Port {port_int} is outside the valid range {_MIN_PORT}-{_MAX_PORT}.")
    scheme_str = str(scheme or "").strip().lower()
    if scheme_str not in SUPPORTED_SCHEMES:
        raise ScopeError(
            f"Scheme {scheme!r} is not supported; this module only speaks "
            f"{'/'.join(SUPPORTED_SCHEMES)}."
        )
    return port_int, scheme_str


# ---------------------------------------------------------------------------
# Evidence-model helpers (mirrors every other implemented module's model;
# kept local per modular independence, context.md §12.2)
# ---------------------------------------------------------------------------

def make_finding(
    finding_type: str,
    target: str,
    value: Any,
    evidence: List[str],
    confidence: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a structured, evidence-carrying discovery record (context.md §8)."""
    return {
        "type": finding_type,
        "target": target,
        "value": value,
        "evidence": list(evidence),
        "confidence": confidence,
        "source": MODULE_NAME,
        "timestamp": _now(),
        "metadata": metadata or {},
    }


def make_vhost_finding(
    ip: str,
    port: int,
    scheme: str,
    hostname: str,
    evidence: List[str],
    confidence: str,
    target: str,
    signals: Optional[Dict[str, bool]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Wrap one discovered-vhost detection into the structured evidence record:
    ip, hostname/Host-header used, response/discovery information, and
    source — everything the assignment's provenance requirement asks for.
    """
    connect_url = f"{scheme}://{_format_host_for_url(ip)}:{port}/"
    value = {
        "ip": ip,
        "port": port,
        "scheme": scheme,
        "hostname": hostname,
        "host_header": hostname,
        "connect_url": connect_url,
    }
    return make_finding(
        finding_type="vhost_discovered",
        target=target,
        value=value,
        evidence=evidence,
        confidence=confidence,
        metadata={
            **(metadata or {}),
            "ip": ip, "port": port, "scheme": scheme, "hostname": hostname,
            "signals": signals or {},
        },
    )


# ---------------------------------------------------------------------------
# Crash-safe persistence (same file/format as every other module's
# PendingAssetsStore, duplicated here per modular independence)
# ---------------------------------------------------------------------------

class PendingAssetsStore:
    """
    Crash-safe, append-oriented persistence for <output_dir>/pending_assets.json.

    Every call to add() re-reads the current file, appends the new finding,
    and atomically rewrites the file (write-to-temp + os.replace) so a
    crash mid-write can never corrupt previously persisted discoveries, and
    pre-existing discoveries from other modules/runs are always preserved.
    """

    # One lock per output *file*, shared by every store instance in this
    # process. A per-instance lock only serializes one scan: two concurrent
    # run_vhost_scan() calls against the same output directory each build
    # their own store, so their read / append / rewrite cycles interleaved
    # and destroyed each other's findings. Measured before this fix: four
    # concurrent scans persisted 4 of 20 findings — 80% silently lost.
    # Cross-*process* concurrency remains an architectural limitation (see
    # class docstring); core/orchestrator.py runs producers sequentially.
    _PATH_LOCKS: Dict[str, threading.Lock] = {}
    _PATH_LOCKS_GUARD = threading.Lock()

    @classmethod
    def _lock_for(cls, path: str) -> threading.Lock:
        key = os.path.abspath(path)
        with cls._PATH_LOCKS_GUARD:
            lock = cls._PATH_LOCKS.get(key)
            if lock is None:
                lock = threading.Lock()
                cls._PATH_LOCKS[key] = lock
            return lock

    def __init__(self, output_dir: str = "output", filename: str = "pending_assets.json"):
        self.output_dir = output_dir
        self.path = os.path.join(output_dir, filename)
        self._lock = self._lock_for(self.path)
        os.makedirs(self.output_dir, exist_ok=True)

    def _read_all(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
            if not isinstance(data, list):
                raise ValueError("pending_assets.json root must be a JSON array")
            return data
        except (json.JSONDecodeError, ValueError) as exc:
            raise PersistenceError(
                f"Existing pending_assets.json is corrupt and cannot be safely "
                f"appended to: {exc}"
            ) from exc

    def add(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Append one finding and persist immediately. Returns the finding."""
        with self._lock:
            records = self._read_all()
            records.append(finding)
            self._atomic_write(records)
        return finding

    def _atomic_write(self, records: List[Dict[str, Any]]) -> None:
        dir_name = os.path.dirname(self.path) or "."
        fd, tmp_path = tempfile.mkstemp(prefix=".pending_assets_", dir=dir_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self._read_all()


def _safe_store_add(store: Optional["PendingAssetsStore"], finding: Dict[str, Any]) -> Optional[str]:
    """
    store.add() wrapped so a single persistence failure doesn't abort the
    rest of this module's work. Returns None on success, or an error
    message the caller is responsible for recording (never silently
    discarded).

    Every failure mode the store can raise is caught here, not just
    PersistenceError: a full disk, a read-only output directory or a
    revoked permission surfaces as OSError, and an unexpectedly
    unserializable finding as TypeError/ValueError. Letting either escape
    would abort the surrounding candidate loop and throw away every
    discovery already made for that ip/port/scheme — precisely the silent
    loss of discoveries CLAUDE.md rule 8 forbids.
    """
    if store is None:
        return None
    try:
        store.add(finding)
        return None
    except PersistenceError as exc:
        return str(exc)
    except (OSError, TypeError, ValueError) as exc:
        return f"{type(exc).__name__} while persisting to pending_assets.json: {exc}"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _ci_get(headers: Dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup (requests preserves server casing)."""
    if not headers:
        return None
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None


def _content_signature(body: str) -> Tuple[int, str]:
    """Whitespace-normalized (length, md5) signature for content-diffing (mirrors api_recon.py)."""
    normalized = re.sub(r"\s+", " ", body or "").strip()
    return len(normalized), hashlib.md5(normalized.encode("utf-8", errors="ignore")).hexdigest()


def _extract_title(body: str) -> Optional[str]:
    """
    Extract the first `<title>` from a response body using linear string
    scanning over a bounded window.

    The obvious regex (`<title[^>]*>(.*?)</title>` with DOTALL) backtracks
    quadratically on a hostile body that repeats an unterminated `<title`:
    measured at ~188 ms for 8,000 repetitions in 49 KB, so a 128 KB body of
    them costs seconds of CPU *per response*, multiplied by every candidate.
    A title only ever lives in `<head>`, so scanning the first
    `_TITLE_SCAN_LIMIT` bytes loses nothing real and bounds the work.
    """
    if not body:
        return None
    window = body[:_TITLE_SCAN_LIMIT]
    lowered = window.lower()
    start = lowered.find("<title")
    if start < 0:
        return None
    open_end = lowered.find(">", start)
    if open_end < 0:
        return None
    close = lowered.find("</title", open_end + 1)
    if close < 0:
        # Unterminated <title> — same outcome as the previous regex, which
        # required a closing tag to match at all. Preserved deliberately so
        # a malformed hostile body cannot invent a new scoring signal.
        return None
    title = re.sub(r"\s+", " ", window[open_end + 1:close]).strip()
    return title or None


def _clip(value: Any, limit: int) -> str:
    """Bound attacker-controlled text before it is embedded in persisted evidence."""
    text = str(value)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}…[+{len(text) - limit} more chars]"


def _neutralize_host_echo(text: Optional[str], host: Optional[str]) -> str:
    """
    Replace every occurrence of the Host header we sent with a fixed
    placeholder before the text is compared against a baseline.

    Without this, any server that echoes the request authority back —
    `return 301 https://$host$request_uri`, an Apache default vhost that
    prints the requested name, a title built from the hostname — produces a
    response that is trivially "different from both baselines" for *every*
    candidate, because the only thing that differed is the value we sent
    ourselves. Measured on the current implementation: a Host-preserving
    http->https redirect reported 5/5 wordlist candidates as MEDIUM
    confidence virtual hosts.
    """
    if not text:
        return ""
    if not host:
        return text
    return re.sub(re.escape(host), _HOST_ECHO_PLACEHOLDER, text, flags=re.IGNORECASE)


def _edge_indicators(headers: Optional[Dict[str, str]]) -> List[str]:
    """
    Name the shared-infrastructure signals present in a response.

    A CDN edge, reverse proxy or load balancer answers for many unrelated
    tenants from the same address, so "this Host header works here" is not
    evidence that the origin behind it belongs to the authorized target
    (assignment §10). The indicators are reported, never used to suppress a
    discovery — they cap attribution confidence and are preserved as
    evidence.
    """
    if not headers:
        return []
    found: List[str] = []
    for key in headers:
        lowered = str(key).lower()
        if lowered in _EDGE_HEADER_HINTS:
            found.append(lowered)
    server = (_ci_get(headers, "Server") or "").lower()
    powered = (_ci_get(headers, "X-Powered-By") or "").lower()
    for hint in _EDGE_SERVER_HINTS:
        if hint in server or hint in powered:
            found.append(f"server:{hint}")
    return sorted(set(found))


def _app_header_signature(headers: Optional[Dict[str, str]], host: Optional[str]) -> str:
    """
    Build a stable fingerprint of the application-identifying response headers.

    Only header *identities* that do not vary per request are used. Cookies
    contribute their **names** and never their values, so a rotating session
    id cannot manufacture a difference while a genuinely different cookie
    (PHPSESSID vs JSESSIONID) still shows one. `Content-Type` contributes
    only its media type, so a per-response multipart boundary cannot either.
    The Host we sent is neutralized out of every value, so a header that
    echoes the requested authority is not mistaken for evidence.

    Closes a reproduced false *negative*: a reverse proxy fronting two
    backends that render the same page was previously recorded as an
    authoritative "no distinct application here".
    """
    if not headers:
        return ""
    parts: List[str] = []
    for name in _APP_HEADER_HINTS:
        value = _ci_get(headers, name)
        if not value:
            continue
        value = str(value)
        if name == "content-type":
            value = value.split(";", 1)[0]
        parts.append(f"{name}={_neutralize_host_echo(value.strip().lower(), host)}")
    cookie_header = _ci_get(headers, "Set-Cookie")
    if cookie_header:
        names = set()
        for chunk in str(cookie_header).split(","):
            # Only the first `name=value` pair of each cookie is the cookie
            # itself; everything after the first ";" is attributes.
            first_pair = chunk.split(";", 1)[0]
            if "=" not in first_pair:
                continue
            name = first_pair.split("=", 1)[0].strip().lower()
            if name and name not in _COOKIE_ATTRIBUTE_NAMES:
                names.add(name)
        if names:
            parts.append("cookies=" + ",".join(sorted(names)))
    return "|".join(parts)


def _response_fingerprint(resp: Dict[str, Any]) -> Dict[str, Any]:
    """
    Reduce one response to the comparable signals, with the Host header we
    sent neutralized out of every text field first.
    """
    host = resp.get("host_header_sent") or ""
    body = _neutralize_host_echo(resp.get("body") or "", host)
    headers = resp.get("headers") or {}
    location_raw = _ci_get(headers, "Location")
    return {
        "status_code": resp.get("status_code"),
        "content_hash": _content_signature(body)[1],
        "content_empty": not body.strip(),
        "title": _extract_title(body),
        "app_headers": _app_header_signature(headers, host),
        "location": _neutralize_host_echo(location_raw, host) if location_raw else None,
        "location_raw": location_raw,
        "truncated": bool(resp.get("body_truncated")),
        "edge_indicators": _edge_indicators(headers),
    }


def _confidence_for_score(score: int) -> str:
    if score >= _HIGH_THRESHOLD:
        return CONFIDENCE_HIGH
    if score == _MEDIUM_THRESHOLD:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def _apply_confidence_cap(confidence: str, cap: Optional[str]) -> str:
    """Lower `confidence` to `cap` when the evidence cannot support more (never raises it)."""
    if not cap:
        return confidence
    if _CONFIDENCE_RANK.get(confidence, 0) <= _CONFIDENCE_RANK.get(cap, 0):
        return confidence
    return cap


# ---------------------------------------------------------------------------
# Wordlist loading (mirrors endpoint_discovery.py's load_wordlist,
# duplicated here per modular independence)
# ---------------------------------------------------------------------------

def _default_wordlists_dir() -> str:
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "wordlists"))


def load_wordlist(name: str, wordlists_dir: Optional[str] = None) -> List[str]:
    """Load a newline-delimited wordlist file (blank lines and '#' comments ignored, duplicates dropped, order preserved)."""
    directory = wordlists_dir or _default_wordlists_dir()
    path = os.path.join(directory, name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as exc:
        raise WordlistError(f"Unable to read wordlist {name!r} from {directory!r}: {exc}") from exc

    entries: List[str] = []
    seen = set()
    for line in lines:
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if entry not in seen:
            seen.add(entry)
            entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# 1. Controlled Host-header HTTP client
# ---------------------------------------------------------------------------

class _SNIAdapter(requests.adapters.HTTPAdapter):
    """
    Transport adapter that pins the TLS SNI value for one request.

    Only used when the caller opts into `SNI_MODE_CANDIDATE`. It does not
    renegotiate or reuse anything: each fetch already builds its own
    session/connection, so pinning SNI costs exactly the same one TLS
    handshake per candidate that the default path already pays.
    """

    def __init__(self, server_hostname: str, **kwargs: Any) -> None:
        self._server_hostname = server_hostname
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):  # type: ignore[override]
        pool_kwargs["server_hostname"] = self._server_hostname
        pool_kwargs["assert_hostname"] = False
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)


def resolve_sni_hostname(sni_mode: str, scheme: str, host_header: str) -> Optional[str]:
    """
    Decide what TLS SNI value a probe should carry (implementation decision #5).

    `SNI_MODE_CONNECTION` (default) preserves the historical behaviour: the
    connection targets an IP literal, and CPython's `ssl` module never puts
    an IP address in SNI, so no SNI extension is sent at all and routing is
    decided purely by the post-TLS HTTP Host header.
    `SNI_MODE_CANDIDATE` additionally sets SNI to the candidate hostname,
    which is what an SNI-routing edge (CDN, L4 SNI router, ingress
    controller) actually keys on.
    """
    if scheme != "https" or sni_mode != SNI_MODE_CANDIDATE:
        return None
    return host_header or None


def fetch_with_host_header(
    ip: str,
    port: int,
    scheme: str,
    host_header: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    sni_hostname: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Perform a single, read-only HTTP GET directly against `ip:port`,
    explicitly overriding the Host header to `host_header`. Certificate
    validation is disabled for `scheme="https"` — see module docstring,
    implementation decision #5, for why this is necessary rather than a
    security shortcut.

    `sni_hostname` (optional, opt-in) pins the TLS SNI value for this one
    request; when it is None the historical behaviour is preserved exactly
    and no SNI extension is sent for an IP-literal connection.
    """
    url = f"{scheme}://{_format_host_for_url(ip)}:{port}/"
    result: Dict[str, Any] = {
        "status": "error", "status_code": None, "headers": {}, "body": None,
        "body_truncated": False, "url": url, "host_header_sent": host_header,
        "sni_hostname_sent": sni_hostname if scheme == "https" else None,
        "elapsed_seconds": None, "error": None,
    }
    req_headers = {"Host": host_header, "User-Agent": DEFAULT_USER_AGENT}

    resp = None
    session = None
    try:
        verify = scheme != "https"
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if scheme == "https" and sni_hostname:
            session = requests.Session()
            session.mount("https://", _SNIAdapter(sni_hostname))
            getter = session.get
        else:
            getter = requests.get
        resp = getter(
            url, timeout=timeout, headers=req_headers, allow_redirects=False, stream=True, verify=verify,
        )
        try:
            raw = resp.raw.read(max_body_bytes + 1, decode_content=True)
        except Exception:
            raw = resp.content[:max_body_bytes + 1]
        # A transport that hands back str (or None) instead of bytes must not
        # crash the scan with an AttributeError the caller would only see as
        # an opaque failure.
        if raw is None:
            raw = b""
        elif isinstance(raw, str):
            raw = raw.encode("utf-8", errors="replace")
        elif not isinstance(raw, (bytes, bytearray)):
            raw = bytes(raw)
        truncated = len(raw) > max_body_bytes
        body_bytes = bytes(raw[:max_body_bytes])
        try:
            body_text = body_bytes.decode(resp.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            body_text = body_bytes.decode("utf-8", errors="replace")

        result.update({
            "status": "found",
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": body_text,
            "body_truncated": truncated,
            "elapsed_seconds": resp.elapsed.total_seconds(),
        })
    except requests.exceptions.Timeout:
        result["error"] = "timeout"
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"connection error: {exc}"
    except requests.exceptions.TooManyRedirects as exc:
        result["error"] = f"too many redirects: {exc}"
    except requests.exceptions.RequestException as exc:
        result["error"] = f"request failed: {exc}"
    except (ValueError, UnicodeError) as exc:
        # A Host header the HTTP client itself refuses to put on the wire
        # (embedded CR/LF, non-latin-1 bytes) surfaces from http.client as a
        # bare ValueError/UnicodeError, which is *not* a RequestException.
        # Candidates are validated before they get here; this is the
        # belt-and-braces path so a direct caller cannot crash the scan.
        result["error"] = f"invalid request: {type(exc).__name__}: {exc}"
    finally:
        if resp is not None:
            resp.close()
        if session is not None:
            session.close()
    return result


# ---------------------------------------------------------------------------
# 2. Candidate vhost hostname construction
# ---------------------------------------------------------------------------

def build_candidate_hostnames(
    target: str,
    extra_hostnames: Optional[List[str]] = None,
    wordlists_dir: Optional[str] = None,
    wordlist_name: str = DEFAULT_WORDLIST_NAME,
    allow_out_of_scope: bool = False,
) -> Dict[str, Any]:
    """
    Build the candidate Host-header list: every wordlist label combined
    with `target` (e.g. "admin" -> "admin.example.com"), plus any
    caller-supplied `extra_hostnames`. Deduplicated, order-preserved, and
    scope-filtered against `target` (see module docstring, decision #2).
    """
    result: Dict[str, Any] = {
        "candidates": [], "skipped_out_of_scope": [], "skipped_invalid": [],
        "wordlist_error": None, "labels_loaded": 0,
    }

    labels: List[str] = []
    try:
        labels = load_wordlist(wordlist_name, wordlists_dir)
    except WordlistError as exc:
        result["wordlist_error"] = str(exc)
    result["labels_loaded"] = len(labels)

    generated = [f"{label}.{target}" for label in labels]
    # A bare string is an iterable of characters; iterating it would turn one
    # hostname into a candidate per letter.
    if isinstance(extra_hostnames, str):
        extra_hostnames = [extra_hostnames]
    extra = [h for h in (extra_hostnames or []) if isinstance(h, str) and h.strip()]

    seen = set()
    for raw in generated + extra:
        # Syntax first, scope second: an entry carrying an embedded CR/LF or
        # NUL that happens to end in the authorized suffix would otherwise
        # pass the scope check and be handed to the HTTP client. Nothing is
        # silently dropped — a rejected entry is recorded either way.
        hostname = normalize_candidate_hostname(raw)
        if hostname is None:
            result["skipped_invalid"].append(_clip(raw, _MAX_EVIDENCE_TEXT))
            continue
        if hostname in seen:
            continue
        seen.add(hostname)
        if allow_out_of_scope or _in_scope_host(hostname, target):
            result["candidates"].append(hostname)
        else:
            result["skipped_out_of_scope"].append(hostname)

    return result


# ---------------------------------------------------------------------------
# 3. Baseline fingerprinting
# ---------------------------------------------------------------------------

def assess_baseline_stability(first: Dict[str, Any], second: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two control probes sent with two *different* unrecognized Host
    values, and mark every signal that did not reproduce as unusable.

    This is the defence against the single worst false-positive source in
    virtual-host scanning: a server whose default response carries a
    per-request nonce, request id, timestamp or CSRF token. Its body hash
    differs from both baselines for *every* candidate, so every candidate
    scores a strong content signal. Measured on the previous
    implementation: a default page containing one request id reported 5/5
    wordlist candidates as MEDIUM-confidence virtual hosts, queueing 5
    downstream recon actions each.

    Because both probes are compared after `_neutralize_host_echo`, a
    response that merely echoes the requested authority still counts as
    stable — only genuinely dynamic content is excluded.
    """
    stability: Dict[str, Any] = {
        "verified": False, "status_stable": True, "content_stable": True,
        "title_stable": True, "location_stable": True, "header_stable": True,
        "unstable_signals": [], "note": None,
    }
    if first.get("status") != "found" or second.get("status") != "found":
        stability["note"] = (
            "Baseline stability could not be verified — one of the two control probes did not "
            "complete, so per-response dynamic content cannot be ruled out. Candidate confidence "
            "is capped and a zero score is reported as inconclusive rather than as absence."
        )
        return stability

    stability["verified"] = True
    a = _response_fingerprint(first)
    b = _response_fingerprint(second)
    stability["status_stable"] = a["status_code"] == b["status_code"]
    stability["content_stable"] = a["content_hash"] == b["content_hash"]
    stability["title_stable"] = a["title"] == b["title"]
    stability["location_stable"] = a["location"] == b["location"]
    stability["header_stable"] = a["app_headers"] == b["app_headers"]
    unstable = [name for name in ("status", "content", "title", "location", "header")
                if not stability[f"{name}_stable"]]
    stability["unstable_signals"] = unstable
    if unstable:
        stability["note"] = (
            "Two control probes with different unrecognized Host values produced different "
            + ", ".join(unstable)
            + " — those signals are per-response dynamic on this server and are excluded from scoring."
        )
    return stability


def merge_baseline_stability(assessments: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Combine the per-control stability assessments conservatively: a signal
    counts as stable only when it reproduced for *every* baseline the
    candidate will actually be compared against.

    Measuring only the unrecognized-Host control is not enough. A server
    whose default vhost is dynamic (a session id in the page) but whose
    catch-all for unknown hosts is static still makes every candidate that
    falls through to that default vhost look different from both baselines.
    Reproduced adversarially against the first version of this fix: 5/5
    wordlist candidates reported as MEDIUM-confidence virtual hosts.
    """
    merged: Dict[str, Any] = {
        "verified": bool(assessments), "status_stable": True, "content_stable": True,
        "title_stable": True, "location_stable": True, "header_stable": True,
        "unstable_signals": [], "note": None,
    }
    notes: List[str] = []
    unstable: List[str] = []
    for assessment in assessments:
        merged["verified"] = merged["verified"] and bool(assessment.get("verified"))
        for name in ("status", "content", "title", "location", "header"):
            key = f"{name}_stable"
            merged[key] = merged[key] and bool(assessment.get(key, True))
        unstable.extend(assessment.get("unstable_signals") or [])
        if assessment.get("note"):
            notes.append(str(assessment["note"]))
    merged["unstable_signals"] = sorted(set(unstable))
    merged["note"] = " ".join(dict.fromkeys(notes)) or None
    return merged


def probe_baselines(
    ip: str,
    port: int,
    scheme: str,
    timeout: float = DEFAULT_TIMEOUT,
    sni_mode: str = SNI_MODE_CONNECTION,
) -> Dict[str, Any]:
    """
    Fetch the baseline responses for this ip/port/scheme (module docstring,
    decision #3):

      * two with the Host header set to the bare IP (approximates a client
        hitting the IP directly with no vhost knowledge),
      * two with *different* random, near-certainly-unrecognized Host
        values (approximates "what this server does with any Host it does
        not recognize").

    Each baseline is sampled twice so that per-response dynamic content —
    a session id, request id, nonce, timestamp — is detected *before* any
    candidate is scored against it (decision #7). Four probes per
    ip/port/scheme is ~1.9% overhead on a 210-label wordlist run and is the
    difference between reporting an entire wordlist as discovered virtual
    hosts and reporting none of it.

    The IPv6 baseline Host header is bracketed, because a bare IPv6 literal
    is not a valid HTTP authority.
    """
    ip_host = _format_host_for_url(ip)
    random_host = f"reconhound-vhost-baseline-{uuid.uuid4().hex[:12]}.invalid"
    random_host_2 = f"reconhound-vhost-baseline-{uuid.uuid4().hex[:12]}.invalid"
    ip_resp = fetch_with_host_header(ip, port, scheme, ip_host, timeout=timeout)
    ip_resp_2 = fetch_with_host_header(ip, port, scheme, ip_host, timeout=timeout)
    random_resp = fetch_with_host_header(
        ip, port, scheme, random_host, timeout=timeout,
        sni_hostname=resolve_sni_hostname(sni_mode, scheme, random_host),
    )
    random_resp_2 = fetch_with_host_header(
        ip, port, scheme, random_host_2, timeout=timeout,
        sni_hostname=resolve_sni_hostname(sni_mode, scheme, random_host_2),
    )
    # Only the baselines a candidate will actually be compared against
    # constrain scoring. A baseline that did not answer at all is excluded
    # from `differs()` anyway, so its stability is irrelevant — folding it
    # in would wrongly mark every signal unverified on the very common
    # server that simply refuses `Host: <ip>`.
    assessments: List[Dict[str, Any]] = []
    if ip_resp.get("status") == "found":
        assessments.append(assess_baseline_stability(ip_resp, ip_resp_2))
    if random_resp.get("status") == "found":
        assessments.append(assess_baseline_stability(random_resp, random_resp_2))
    return {
        "ip_host_response": ip_resp,
        "ip_host_response_2": ip_resp_2,
        "random_host_response": random_resp,
        "random_host_response_2": random_resp_2,
        "random_host_used": random_host,
        "random_host_used_2": random_host_2,
        "stability": merge_baseline_stability(assessments),
    }


# ---------------------------------------------------------------------------
# 4. Meaningful-difference scoring
# ---------------------------------------------------------------------------

def _score_result(
    score: int,
    evidence: Optional[List[str]] = None,
    signals: Optional[Dict[str, bool]] = None,
    reason: Optional[str] = None,
    **extra: Any,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "score": score,
        "evidence": list(evidence or []),
        "signals": dict(signals or {}),
        "reason": reason,
        "confidence_cap": None,
        "caveats": [],
        "excluded_signals": [],
        "status_code": None,
    }
    result.update(extra)
    return result


def score_vhost_candidate(
    candidate_resp: Dict[str, Any],
    ip_baseline: Dict[str, Any],
    random_baseline: Dict[str, Any],
    stability: Optional[Dict[str, Any]] = None,
    baseline_fingerprints: Optional[Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]] = None,
) -> Dict[str, Any]:
    """
    Score how strongly `candidate_resp` diverges from both baseline
    responses. Never scores above 0 from a bare successful fetch alone —
    only concrete, observable, *reproducible* differences count (module
    docstring, decisions #3/#4/#8).

    Beyond raw difference, three things gate the result:

      * HTTP status semantics. A 429/5xx/edge-failure response is the
        provider or target declining to answer the virtual-host question;
        scoring it manufactures a discovery out of a failure. A 421 is the
        one status that answers it authoritatively in the negative.
      * Baseline stability (`stability`, from assess_baseline_stability).
        A signal that did not reproduce across two control probes is
        per-response noise and is excluded from scoring entirely. Omitting
        the argument keeps the historical "assume every signal is stable"
        behaviour.
      * Attribution. A single available baseline, unverified stability, or
        a response relayed by shared edge infrastructure caps the reported
        confidence — the caveats are appended to the evidence, never used
        to suppress the finding.
    """
    if candidate_resp.get("status") != "found":
        return _score_result(0, reason="candidate_fetch_failed")

    code = candidate_resp.get("status_code")
    if code == MISDIRECTED_REQUEST_STATUS:
        return _score_result(
            0, reason="misdirected_request", status_code=code,
            evidence=[
                f"Server answered HTTP {MISDIRECTED_REQUEST_STATUS} (Misdirected Request): it is "
                f"explicitly not configured to serve this authority on this connection"
            ],
        )
    if code in NON_AUTHORITATIVE_STATUSES:
        return _score_result(
            0, reason="non_authoritative_status", status_code=code,
            evidence=[
                f"HTTP {code} is the origin or an intermediary declining to answer, not an answer "
                f"about this virtual host; the check is inconclusive"
            ],
        )

    ip_ok = ip_baseline.get("status") == "found"
    rand_ok = random_baseline.get("status") == "found"
    if not ip_ok and not rand_ok:
        return _score_result(0, reason="both_baselines_unavailable")

    stability = stability or {}

    def stable(name: str) -> bool:
        return bool(stability.get(f"{name}_stable", True))

    candidate = _response_fingerprint(candidate_resp)
    if baseline_fingerprints is not None:
        # Supplied by discover_vhosts_for_target so the two baselines are
        # fingerprinted once per ip/port/scheme instead of once per
        # candidate. Measured on 200 candidates with 129 KB bodies:
        # 20.7 ms/candidate -> 7.4 ms/candidate.
        ip_fp, rand_fp = baseline_fingerprints
    else:
        ip_fp = rand_fp = None
    # A supplied tuple must never disagree with what is actually comparable,
    # or `differs()` would dereference None.
    if ip_ok and ip_fp is None:
        ip_fp = _response_fingerprint(ip_baseline)
    if rand_ok and rand_fp is None:
        rand_fp = _response_fingerprint(random_baseline)

    def differs(field: str) -> bool:
        from_ip = (not ip_ok) or candidate[field] != ip_fp[field]
        from_rand = (not rand_ok) or candidate[field] != rand_fp[field]
        return from_ip and from_rand

    evidence: List[str] = []
    signals: Dict[str, bool] = {}
    excluded: List[str] = []
    score = 0
    usable = 0

    if stable("status"):
        usable += 1
        if differs("status_code"):
            score += _SCORE_STRONG
            signals["status_diff"] = True
            evidence.append(
                f"HTTP status {code} differs from both the direct-IP baseline "
                f"({ip_fp['status_code'] if ip_ok else 'unavailable'}) and the unrecognized-Host "
                f"baseline ({rand_fp['status_code'] if rand_ok else 'unavailable'})"
            )
    else:
        excluded.append("status")

    if stable("content"):
        usable += 1
        if not candidate["content_empty"] and differs("content_hash"):
            score += _SCORE_STRONG
            signals["content_diff"] = True
            evidence.append(
                "Response body content differs from both baseline responses (distinct content hash "
                "after normalizing whitespace and neutralizing the echoed Host header value)"
            )
    else:
        excluded.append("content")

    if stable("location"):
        usable += 1
        if candidate["location"] and differs("location"):
            score += _SCORE_STRONG
            signals["redirect_diff"] = True
            evidence.append(
                f"Redirect target {_clip(candidate['location_raw'], _MAX_EVIDENCE_URL)!r} differs from "
                f"both baseline redirect behaviors, and not merely by echoing the Host header sent"
            )
    else:
        excluded.append("location")

    if stable("title"):
        usable += 1
        if candidate["title"] and differs("title"):
            score += _SCORE_WEAK
            signals["title_diff"] = True
            evidence.append(
                f"Page title {_clip(candidate['title'], _MAX_EVIDENCE_TEXT)!r} differs from both "
                f"baseline page titles"
            )
    else:
        excluded.append("title")

    if stable("header"):
        usable += 1
        if candidate["app_headers"] and differs("app_headers"):
            score += _SCORE_WEAK
            signals["header_diff"] = True
            evidence.append(
                f"Application-identifying response headers "
                f"{_clip(candidate['app_headers'], _MAX_EVIDENCE_TEXT)!r} differ from both baselines "
                f"(cookie names only, never cookie values)"
            )
    else:
        excluded.append("header")

    # Two kinds of caveat, deliberately kept apart.
    #
    # `capping` ones say the evidence itself is less trustworthy than its raw
    # score suggests — a single control instead of two, unverifiable
    # reproducibility, or a response relayed by infrastructure shared with
    # unrelated tenants. Those lower the reported confidence.
    #
    # `coverage` ones say the comparison saw less than the whole response.
    # Truncation can *hide* a virtual host; it can never invent one, so a
    # difference actually observed within the read limit is exactly as strong
    # as it looks. Capping on truncation would quietly downgrade every real
    # discovery on any site whose default page exceeds the limit.
    capping: List[str] = []
    coverage: List[str] = []
    if not (ip_ok and rand_ok):
        capping.append(
            "Only one of the two baseline probes completed, so this comparison rests on a single "
            "control rather than two independent ones."
        )
    if not stability.get("verified", True):
        capping.append(str(stability.get("note") or "Baseline stability could not be verified."))
    elif excluded:
        capping.append(str(stability.get("note") or
                           f"Excluded unreproducible signal(s): {', '.join(excluded)}."))
    if candidate["edge_indicators"]:
        capping.append(
            "Response was produced or relayed by shared edge infrastructure "
            f"({', '.join(candidate['edge_indicators'])}). A working Host header on shared "
            "infrastructure does not establish that the origin behind it belongs to the "
            "authorized target; attribution is provisional."
        )
    if candidate["truncated"] or (ip_ok and ip_fp["truncated"]) or (rand_ok and rand_fp["truncated"]):
        coverage.append(
            f"At least one compared body exceeded the {DEFAULT_MAX_BODY_BYTES}-byte read limit; a "
            f"difference beyond that offset would not have been seen (this can hide a virtual host, "
            f"it cannot invent one)."
        )
    caveats = capping + coverage

    # Signals excluded as unreproducible cannot support a *negative* either:
    # if the body could not be compared, "no difference found" is an unknown,
    # not an established absence (assignment §15).
    reason: Optional[str] = None
    if score == 0:
        if usable == 0:
            reason = "comparison_signals_unstable"
        elif not stable("content") or not stability.get("verified", True):
            reason = "comparison_signals_unstable"

    return _score_result(
        score,
        evidence=evidence + [f"[CAVEAT] {c}" for c in caveats],
        signals=signals,
        reason=reason,
        status_code=code,
        confidence_cap=CONFIDENCE_MEDIUM if capping else None,
        caveats=caveats,
        excluded_signals=excluded,
        edge_indicators=candidate["edge_indicators"],
    )


# ---------------------------------------------------------------------------
# Negative-result memory (context.md §8/§12.6)
# ---------------------------------------------------------------------------

def persist_no_distinct_response(
    hostname: str, ip: str, port: int, scheme: str, target: str, store: Optional[PendingAssetsStore],
    basis: Optional[str] = None, caveats: Optional[List[str]] = None,
) -> Optional[str]:
    """
    Persist a negative-result-memory finding: this Host header was checked
    and the check produced an authoritative "no distinct application here".

    Only ever called for a *completed, comparable* check. A probe that
    failed, was rate limited, hit an edge error, or could not be compared
    because the server's responses are not reproducible is recorded as
    inconclusive by the caller instead — never as absence (assignment §15).
    """
    connect_url = f"{scheme}://{_format_host_for_url(ip)}:{port}/"
    evidence = [
        f"Host header {hostname!r} against {connect_url} produced a response indistinguishable "
        f"from both the direct-IP baseline and the unrecognized-Host baseline"
    ]
    if basis:
        evidence.append(basis)
    # Anything that limited the comparison travels with the negative result:
    # a truncated body or a single available baseline means "indistinguishable"
    # was established over less than the whole response.
    evidence.extend(f"[CAVEAT] {c}" for c in (caveats or []))
    return _safe_store_add(store, make_finding(
        finding_type="vhost_checked_no_distinct_response",
        target=target,
        value={"ip": ip, "port": port, "scheme": scheme, "hostname": hostname, "connect_url": connect_url},
        evidence=evidence,
        confidence=CONFIDENCE_LOW,
        metadata={
            "ip": ip, "port": port, "hostname": hostname,
            "note": (
                "Negative-result-memory: absence of a distinguishing signal does not prove no "
                "application is bound to this Host header — some servers deliberately normalize "
                "responses across virtual hosts, or the candidate hostname genuinely has no vhost here."
            ),
        },
    ))


# ---------------------------------------------------------------------------
# 5. Per-IP/port/scheme vhost discovery orchestration
# ---------------------------------------------------------------------------

def prepare_candidate_list(
    candidates: List[str],
    max_candidates: Optional[int] = None,
    target: Optional[str] = None,
    allow_out_of_scope: bool = False,
) -> Dict[str, Any]:
    """
    Normalize, validate, scope-check and deduplicate a candidate list before
    any of it reaches the network.

    `discover_vhosts_for_target` is a public entry point that callers reach
    directly (not only through `build_candidate_hostnames`), so hostname
    syntax *and* scope are enforced here too rather than trusted from
    upstream. Without the scope check, a direct caller could have an
    out-of-scope hostname probed and — worse — persisted as a
    `vhost_discovered` finding carrying the authorized target, which
    surface_mapper.py would then promote to an asset (CLAUDE.md rule 9).

    Duplicates are collapsed so a caller merging cert SANs, passive DNS and
    a wordlist cannot probe, or persist, the same hostname twice.
    """
    # A bare string is an iterable of characters. Iterating it would turn
    # "admin.example.com" into eleven single-letter Host headers, each of
    # which is a syntactically valid hostname.
    if isinstance(candidates, str):
        candidates = [candidates]

    prepared: List[str] = []
    invalid: List[str] = []
    out_of_scope: List[str] = []
    duplicates = 0
    seen = set()
    for raw in candidates or []:
        normalized = normalize_candidate_hostname(raw)
        if normalized is None:
            invalid.append(_clip(raw, _MAX_EVIDENCE_TEXT))
            continue
        if normalized in seen:
            duplicates += 1
            continue
        seen.add(normalized)
        if target and not allow_out_of_scope and not _in_scope_host(normalized, target):
            out_of_scope.append(normalized)
            continue
        prepared.append(normalized)
    # max(0, ...) matters: a negative bound would slice from the end and
    # silently drop the *last* candidates instead of capping the first ones.
    truncated = prepared if max_candidates is None else prepared[:max(0, int(max_candidates))]
    return {
        "candidates": truncated,
        "skipped_invalid": invalid,
        "skipped_out_of_scope": out_of_scope,
        "duplicates_skipped": duplicates,
        "capped_by_max_candidates": len(prepared) - len(truncated),
    }


def discover_vhosts_for_target(
    ip: str,
    port: int,
    scheme: str,
    target: str,
    candidates: List[str],
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_candidates: Optional[int] = None,
    sni_mode: str = SNI_MODE_CONNECTION,
    max_consecutive_rate_limited: int = DEFAULT_MAX_CONSECUTIVE_RATE_LIMITED,
    allow_out_of_scope: bool = False,
) -> Dict[str, Any]:
    """
    Run Host-header vhost discovery for one ip/port/scheme against every
    candidate hostname. A failure on one candidate (timeout, connection
    error, malformed response) never aborts the remaining candidates.

    Every candidate ends in exactly one of four states, and they are kept
    distinct (assignment §15):

      discovered    a reproducible difference from both baselines,
      negative      an authoritative "no distinct application here",
      inconclusive  the check could not establish either answer,
      not_tested    probing was abandoned before reaching this candidate.
    """
    result: Dict[str, Any] = {
        "ip": ip, "port": port, "scheme": scheme, "target": target, "connect_url": None,
        "candidates_checked": 0, "discovered_vhosts": [], "negative_results_count": 0,
        "inconclusive": [], "inconclusive_count": 0, "not_tested": [], "not_tested_count": 0,
        "skipped_invalid": [], "skipped_out_of_scope": [], "duplicates_skipped": 0,
        "baseline": None, "stability": None, "sni_mode": sni_mode,
        "errors": [], "error_count": 0,
    }

    try:
        port, scheme = _validate_port_scheme(port, scheme)
    except ScopeError as exc:
        _append_error(result, {"stage": "target_validation", "ip": ip, "port": port, "error": str(exc)})
        result["not_tested"] = _bounded_not_tested(list(candidates or []), "port_scheme_rejected")
        result["not_tested_count"] = len(candidates or [])
        return result
    if sni_mode not in SUPPORTED_SNI_MODES:
        _append_error(result, {
            "stage": "target_validation", "ip": ip, "port": port,
            "error": f"Unsupported sni_mode {sni_mode!r}; expected one of {SUPPORTED_SNI_MODES}.",
        })
        result["not_tested"] = _bounded_not_tested(list(candidates or []), "unsupported_sni_mode")
        result["not_tested_count"] = len(candidates or [])
        return result

    try:
        # A negative bound must disable the circuit breaker, never trip it on
        # the first candidate.
        max_consecutive_rate_limited = max(0, int(max_consecutive_rate_limited))
    except (TypeError, ValueError):
        max_consecutive_rate_limited = DEFAULT_MAX_CONSECUTIVE_RATE_LIMITED

    result["port"], result["scheme"] = port, scheme
    connect_url = f"{scheme}://{_format_host_for_url(ip)}:{port}/"
    result["connect_url"] = connect_url

    prepared = prepare_candidate_list(
        candidates, max_candidates=max_candidates,
        target=target, allow_out_of_scope=allow_out_of_scope,
    )
    result["skipped_invalid"] = prepared["skipped_invalid"]
    result["skipped_out_of_scope"] = prepared["skipped_out_of_scope"]
    result["duplicates_skipped"] = prepared["duplicates_skipped"]
    for out in prepared["skipped_out_of_scope"]:
        _append_error(result, {
            "stage": "candidate_scope", "hostname": out,
            "error": f"not within the authorized target {target!r}; never probed and never persisted",
        })
    for bad in prepared["skipped_invalid"]:
        _append_error(result, {
            "stage": "candidate_validation", "hostname": bad,
            "error": "not a syntactically valid hostname; never probed and never persisted",
        })

    try:
        baselines = probe_baselines(ip, port, scheme, timeout=timeout, sni_mode=sni_mode)
    except Exception as exc:
        _append_error(result, {"stage": "baseline", "ip": ip, "port": port, "error": str(exc)})
        result["not_tested"] = _bounded_not_tested(prepared["candidates"], "baseline_probe_error")
        result["not_tested_count"] = len(prepared["candidates"])
        return result

    ip_baseline = baselines["ip_host_response"]
    random_baseline = baselines["random_host_response"]
    stability = baselines["stability"]
    result["stability"] = stability
    result["baseline"] = {
        "ip_host_status": ip_baseline.get("status"),
        "ip_host_status_code": ip_baseline.get("status_code"),
        "ip_host_error": ip_baseline.get("error"),
        "random_host_status": random_baseline.get("status"),
        "random_host_status_code": random_baseline.get("status_code"),
        "random_host_error": random_baseline.get("error"),
        "random_host_used": baselines["random_host_used"],
        "random_host_status_2": baselines["random_host_response_2"].get("status"),
        "random_host_status_code_2": baselines["random_host_response_2"].get("status_code"),
        "random_host_used_2": baselines["random_host_used_2"],
        "stability": stability,
    }

    if ip_baseline.get("status") != "found" and random_baseline.get("status") != "found":
        _append_error(result, {
            "stage": "baseline", "ip": ip, "port": port,
            "error": "both baseline probes failed; cannot reliably distinguish vhosts on this ip/port/scheme",
        })
        result["not_tested"] = _bounded_not_tested(prepared["candidates"], "baselines_unavailable")
        result["not_tested_count"] = len(prepared["candidates"])
        return result

    # A server that is already rate limiting or failing at the edge cannot
    # answer the virtual-host question for anything, and probing hundreds of
    # candidates into it would be both useless and rude.
    baseline_codes = {
        r.get("status_code") for r in (ip_baseline, random_baseline) if r.get("status") == "found"
    }
    if baseline_codes and baseline_codes <= NON_AUTHORITATIVE_STATUSES:
        _append_error(result, {
            "stage": "baseline", "ip": ip, "port": port,
            "error": (
                f"baseline probes returned only non-authoritative statuses "
                f"{sorted(c for c in baseline_codes if c is not None)}; the server is not answering "
                f"virtual-host questions right now, so no candidate was probed"
            ),
        })
        result["not_tested"] = _bounded_not_tested(prepared["candidates"], "baseline_non_authoritative")
        result["not_tested_count"] = len(prepared["candidates"])
        return result

    candidate_list = prepared["candidates"]
    baseline_fingerprints = (
        _response_fingerprint(ip_baseline) if ip_baseline.get("status") == "found" else None,
        _response_fingerprint(random_baseline) if random_baseline.get("status") == "found" else None,
    )
    consecutive_rate_limited = 0
    aborted_at: Optional[int] = None

    for index, hostname in enumerate(candidate_list):
        result["candidates_checked"] += 1
        try:
            resp = fetch_with_host_header(
                ip, port, scheme, hostname, timeout=timeout,
                sni_hostname=resolve_sni_hostname(sni_mode, scheme, hostname),
            )
        except Exception as exc:
            _append_error(result, {"stage": "candidate_fetch", "hostname": hostname, "error": str(exc)})
            _record_inconclusive(result, hostname, "candidate_fetch_exception", str(exc))
            continue

        if resp.get("status") != "found":
            _append_error(result, {"stage": "candidate_fetch", "hostname": hostname, "error": resp.get("error")})
            _record_inconclusive(result, hostname, "candidate_fetch_failed", resp.get("error"))
            continue

        status_code = resp.get("status_code")
        if status_code in RATE_LIMIT_STATUSES:
            consecutive_rate_limited += 1
        else:
            consecutive_rate_limited = 0

        try:
            scoring = score_vhost_candidate(
                resp, ip_baseline, random_baseline, stability=stability,
                baseline_fingerprints=baseline_fingerprints,
            )
        except Exception as exc:
            _append_error(result, {"stage": "scoring", "hostname": hostname, "error": str(exc)})
            _record_inconclusive(result, hostname, "scoring_error", str(exc))
            continue

        if scoring["score"] <= 0:
            reason = scoring.get("reason")
            if reason in INCONCLUSIVE_REASONS:
                _record_inconclusive(
                    result, hostname, reason,
                    "; ".join(scoring["evidence"]) or None, status_code=status_code,
                    retry_after=_ci_get(resp.get("headers") or {}, "Retry-After"),
                )
            else:
                result["negative_results_count"] += 1
                err = persist_no_distinct_response(
                    hostname, ip, port, scheme, target, store,
                    basis=(scoring["evidence"][0] if reason == "misdirected_request" and scoring["evidence"] else None),
                    caveats=scoring.get("caveats"),
                )
                if err:
                    _append_error(result, {"stage": "persist_negative", "hostname": hostname, "error": err})
        else:
            confidence = _apply_confidence_cap(
                _confidence_for_score(scoring["score"]), scoring.get("confidence_cap"),
            )
            record = {
                "ip": ip, "port": port, "scheme": scheme, "hostname": hostname, "connect_url": connect_url,
                "status_code": status_code, "confidence": confidence, "score": scoring["score"],
                "evidence": scoring["evidence"], "signals": scoring["signals"],
                "caveats": scoring.get("caveats", []),
                "edge_indicators": scoring.get("edge_indicators", []),
                "excluded_signals": scoring.get("excluded_signals", []),
                "sni_hostname_sent": resp.get("sni_hostname_sent"),
                "timestamp": _now(),
            }
            result["discovered_vhosts"].append(record)

            err = _safe_store_add(store, make_vhost_finding(
                ip=ip, port=port, scheme=scheme, hostname=hostname, evidence=scoring["evidence"],
                confidence=confidence, target=target, signals=scoring["signals"],
                metadata={
                    "score": scoring["score"],
                    "status_code": status_code,
                    "caveats": scoring.get("caveats", []),
                    "edge_indicators": scoring.get("edge_indicators", []),
                    "excluded_signals": scoring.get("excluded_signals", []),
                    "baseline_stability_verified": bool(stability.get("verified")),
                    "sni_mode": sni_mode,
                    "sni_hostname_sent": resp.get("sni_hostname_sent"),
                },
            ))
            if err:
                _append_error(result, {"stage": "persist_vhost", "hostname": hostname, "error": err})

        if max_consecutive_rate_limited > 0 and consecutive_rate_limited >= max_consecutive_rate_limited:
            aborted_at = index + 1
            retry_after = _ci_get(resp.get("headers") or {}, "Retry-After")
            _append_error(result, {
                "stage": "rate_limit", "ip": ip, "port": port,
                "error": (
                    f"abandoned probing after {consecutive_rate_limited} consecutive rate-limit/"
                    f"unavailable responses (HTTP {status_code}); remaining candidates are recorded "
                    f"as not tested, never as absent"
                ),
                "retry_after": retry_after,
            })
            break

    if aborted_at is not None:
        result["not_tested"] = _bounded_not_tested(candidate_list[aborted_at:], "rate_limit_abort")
        result["not_tested_count"] = len(candidate_list) - aborted_at

    return result


def _append_error(result: Dict[str, Any], entry: Dict[str, Any]) -> None:
    """
    Record one structured error, bounding how many are retained.

    `error_count` stays exact so nothing is hidden; only the listing is
    capped, so 10,000 failing candidates cannot inflate a module summary
    without limit (assignment §13).
    """
    result["error_count"] = result.get("error_count", 0) + 1
    errors = result["errors"]
    if len(errors) < _MAX_RETAINED_DETAIL:
        errors.append(entry)
    elif len(errors) == _MAX_RETAINED_DETAIL:
        errors.append({
            "stage": "errors_truncated",
            "error": f"further per-candidate errors are counted in error_count "
                     f"but not listed individually (cap: {_MAX_RETAINED_DETAIL})",
        })


def _bounded_not_tested(hostnames: List[str], reason: str) -> List[Dict[str, Any]]:
    listed = [{"hostname": h, "reason": reason} for h in hostnames[:_MAX_RETAINED_DETAIL]]
    if len(hostnames) > _MAX_RETAINED_DETAIL:
        listed.append({
            "hostname": None, "reason": "detail_list_truncated",
            "remaining": len(hostnames) - _MAX_RETAINED_DETAIL,
        })
    return listed


def _record_inconclusive(
    result: Dict[str, Any], hostname: str, reason: str, detail: Optional[str] = None,
    status_code: Optional[int] = None, retry_after: Optional[str] = None,
) -> None:
    """
    Record a candidate whose result could not be established.

    Deliberately *not* persisted as a finding: `vhost_checked_no_distinct_response`
    means "checked, authoritatively nothing here", and writing an
    unestablished result under it would corrupt negative-result memory for
    every downstream consumer. It is surfaced through the module summary's
    `counts` instead, which core/orchestrator.py already folds into its
    execution record.
    """
    result["inconclusive_count"] = result.get("inconclusive_count", 0) + 1
    # The count stays exact; only the retained per-candidate detail is
    # bounded, so a pathological 10,000-candidate list cannot turn one
    # module summary into hundreds of megabytes of JSON.
    if len(result["inconclusive"]) < _MAX_RETAINED_DETAIL:
        result["inconclusive"].append({
            "hostname": hostname, "reason": reason,
            "detail": _clip(detail, _MAX_EVIDENCE_URL) if detail else None,
            "status_code": status_code, "retry_after": retry_after,
        })
    elif len(result["inconclusive"]) == _MAX_RETAINED_DETAIL:
        result["inconclusive"].append({
            "hostname": None, "reason": "detail_list_truncated",
            "detail": f"further inconclusive candidates are counted in inconclusive_count "
                      f"but not listed individually (cap: {_MAX_RETAINED_DETAIL})",
            "status_code": None, "retry_after": None,
        })


# ---------------------------------------------------------------------------
# 6/7. Downstream web-recon target shaping + decision-queue recommendations
# — see module docstring, NO-CROSS-MODULE-CALLS PRECEDENT. This module
# never calls tech_fingerprint.py/http_analyzer.py/endpoint_discovery.py/
# crawler.py/ssl_analyzer.py itself; it only produces justified
# recommendations for the future orchestrator to execute.
# ---------------------------------------------------------------------------

_SUGGESTED_DOWNSTREAM_MODULES: Tuple[str, ...] = (
    "tech_fingerprint.py", "http_analyzer.py", "endpoint_discovery.py", "crawler.py",
)


def build_downstream_recon_target(vhost_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Shape one discovered vhost as an appropriate downstream
    web-reconnaissance target (responsibility #6). The hostname may not be
    resolvable via DNS at all — that's the entire point of vhost
    discovery — so downstream modules must connect to `connect_url` (the
    already-authorized IP) while explicitly sending `host_header_override`.
    """
    return {
        "hostname": vhost_record["hostname"],
        "ip": vhost_record["ip"],
        "port": vhost_record["port"],
        "scheme": vhost_record["scheme"],
        "connect_url": vhost_record["connect_url"],
        "host_header_override": vhost_record["hostname"],
        "confidence": vhost_record["confidence"],
        "caveats": list(vhost_record.get("caveats") or []),
        "edge_indicators": list(vhost_record.get("edge_indicators") or []),
        "note": (
            "This hostname was discovered via Host-header variation and may not resolve via DNS. "
            "Downstream reconnaissance modules must connect to `connect_url` (the already-authorized "
            "IP) while explicitly sending an HTTP Host header equal to `host_header_override` to reach "
            "this specific virtual host."
        ),
    }


def build_recommended_actions(discovered_vhosts: List[Dict[str, Any]], target: str) -> List[Dict[str, Any]]:
    """
    Build a decision-queue-shaped list of recommended next actions
    (context.md §9) for every MEDIUM+ confidence discovered vhost. Never
    executed here — status is always "queued_for_orchestrator".
    """
    actions: List[Dict[str, Any]] = []
    for v in discovered_vhosts:
        if v["confidence"] not in (CONFIDENCE_MEDIUM, CONFIDENCE_HIGH):
            continue

        recommended_modules = list(_SUGGESTED_DOWNSTREAM_MODULES)
        if v["scheme"] == "https":
            recommended_modules.append("ssl_analyzer.py")

        actions.append({
            "action": "vhost_scanner.discovered_vhost_recon",
            "hostname": v["hostname"], "ip": v["ip"], "port": v["port"], "scheme": v["scheme"],
            "recommended_modules": recommended_modules,
            "downstream_target": build_downstream_recon_target(v),
            "justification": (
                f"[REASON: Host header {v['hostname']!r} against {v['ip']}:{v['port']} produced a "
                f"response distinguishable from both baseline probes with {v['confidence']} confidence "
                f"({len(v.get('signals') or {})} converging signal(s)) — this is a newly discovered "
                f"application surface not exposed via primary DNS, per context.md §6's "
                f"adaptive-discovery loop]"
                + (f" [CAVEAT: {' '.join(v['caveats'])}]" if v.get("caveats") else "")
            ),
            "caveats": list(v.get("caveats") or []),
            "status": "queued_for_orchestrator",
        })
    return actions


# ---------------------------------------------------------------------------
# 8. Normalization for surface_mapper.py
# ---------------------------------------------------------------------------

def build_vhost_summary(discovered_vhosts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize every discovered vhost into the shape surface_mapper.py (not
    yet implemented) is expected to consume — JSON-safe, evidence-carrying,
    and grouped by IP for the "one IP can host multiple distinct
    applications" relationship (module contract responsibility #3).
    """
    by_ip: Dict[str, List[str]] = {}
    for v in discovered_vhosts:
        hostnames = by_ip.setdefault(v["ip"], [])
        if v["hostname"] not in hostnames:
            hostnames.append(v["hostname"])

    return {
        "vhosts": discovered_vhosts,
        "count": len(discovered_vhosts),
        "by_ip": by_ip,
        "downstream_targets": [build_downstream_recon_target(v) for v in discovered_vhosts],
    }


# ---------------------------------------------------------------------------
# Module orchestration (single IP, all configured ports)
# ---------------------------------------------------------------------------

def run_vhost_scan(
    ip: str,
    target: str,
    output_dir: str = "output",
    ports: Optional[List[Tuple[int, str]]] = None,
    extra_hostnames: Optional[List[str]] = None,
    wordlist_name: str = DEFAULT_WORDLIST_NAME,
    wordlists_dir: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_candidates: Optional[int] = None,
    allow_out_of_scope_hostnames: bool = False,
    sni_mode: str = SNI_MODE_CONNECTION,
    max_consecutive_rate_limited: int = DEFAULT_MAX_CONSECUTIVE_RATE_LIMITED,
) -> Dict[str, Any]:
    """
    Run Module 9's full virtual-host discovery flow against a single,
    already-discovered IP and persist every completed discovery
    immediately to <output_dir>/pending_assets.json. A failure on one
    port/scheme does not prevent the others from running.

    The summary carries a top-level `counts` block so an orchestrator sees
    how each candidate actually ended — discovered / negative / inconclusive
    / not tested / skipped — instead of inferring absence from silence.
    """
    ip = validate_scan_ip(ip)
    target = validate_scan_target(target)
    if sni_mode not in SUPPORTED_SNI_MODES:
        raise ScopeError(f"Unsupported sni_mode {sni_mode!r}; expected one of {SUPPORTED_SNI_MODES}.")
    store = PendingAssetsStore(output_dir=output_dir)
    # Normalize and deduplicate the port list: a repeated (or case-variant)
    # (port, scheme) pair would otherwise probe the same surface twice and
    # persist a duplicate finding for every candidate.
    port_list: List[Any] = []
    seen_ports = set()
    for entry in (list(ports) if ports else list(DEFAULT_PORTS)):
        try:
            key = _validate_port_scheme(*entry)
        except (ScopeError, TypeError):
            port_list.append(entry)          # kept so the error is reported below
            continue
        if key in seen_ports:
            continue
        seen_ports.add(key)
        port_list.append(key)

    summary: Dict[str, Any] = {
        "ip": ip, "target": target, "module": MODULE_NAME, "started_at": _now(),
        "sni_mode": sni_mode,
        "candidate_build": {}, "port_results": [], "vhost_summary": {},
        "recommended_next_actions": [], "errors": [],
    }

    candidate_build = build_candidate_hostnames(
        target, extra_hostnames=extra_hostnames, wordlists_dir=wordlists_dir,
        wordlist_name=wordlist_name, allow_out_of_scope=allow_out_of_scope_hostnames,
    )
    summary["candidate_build"] = candidate_build
    if candidate_build["wordlist_error"]:
        summary["errors"].append({"stage": "wordlist_load", "error": candidate_build["wordlist_error"]})
    for bad in candidate_build["skipped_invalid"]:
        summary["errors"].append({
            "stage": "candidate_validation", "hostname": bad,
            "error": "not a syntactically valid hostname; never probed and never persisted",
        })

    own_errors = len(summary["errors"])   # wordlist/candidate-validation errors so far
    all_discovered: List[Dict[str, Any]] = []
    negatives = inconclusive = not_tested = 0
    for entry in port_list:
        try:
            port, scheme = entry
        except (TypeError, ValueError):
            summary["errors"].append({"stage": "port_validation", "port": _clip(entry, 64),
                                      "error": "expected a (port, scheme) pair"})
            own_errors += 1
            continue
        try:
            port_result = discover_vhosts_for_target(
                ip, port, scheme, target, candidate_build["candidates"], store=store,
                timeout=timeout, max_candidates=max_candidates, sni_mode=sni_mode,
                max_consecutive_rate_limited=max_consecutive_rate_limited,
                allow_out_of_scope=allow_out_of_scope_hostnames,
            )
        except Exception as exc:
            summary["errors"].append({"stage": "discover_vhosts", "port": port, "scheme": scheme, "error": str(exc)})
            own_errors += 1
            continue
        summary["port_results"].append(port_result)
        summary["errors"].extend(port_result.get("errors", []))
        all_discovered.extend(port_result.get("discovered_vhosts", []))
        negatives += port_result.get("negative_results_count", 0)
        inconclusive += port_result.get("inconclusive_count", 0)
        not_tested += port_result.get("not_tested_count", 0)

    summary["vhost_summary"] = build_vhost_summary(all_discovered)
    summary["recommended_next_actions"] = build_recommended_actions(all_discovered, target)
    summary["counts"] = {
        "candidates": len(candidate_build["candidates"]),
        # Only ports that actually got as far as a baseline probe count as
        # probed; one rejected by port/scheme validation was never contacted.
        "ports_probed": sum(1 for p in summary["port_results"] if p.get("baseline") is not None),
        "ports_rejected": sum(1 for p in summary["port_results"] if p.get("baseline") is None),
        "discovered": len(all_discovered),
        "negative": negatives,
        "inconclusive": inconclusive,
        "not_tested": not_tested,
        "skipped_out_of_scope": len(candidate_build["skipped_out_of_scope"]),
        "skipped_invalid": len(candidate_build["skipped_invalid"]),
        # Exact, even where a port's retained error listing was capped.
        "errors": own_errors + sum(p.get("error_count", 0) for p in summary["port_results"]),
    }
    summary["status"] = "completed_with_errors" if summary["errors"] else "completed"
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _parse_ports_arg(raw: str) -> List[Tuple[int, str]]:
    ports: List[Tuple[int, str]] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        port_str, _, scheme = entry.partition("/")
        try:
            ports.append(_validate_port_scheme(port_str, scheme or "http"))
        except ScopeError as exc:
            raise SystemExit(f"[argument error] --ports entry {entry!r}: {exc}")
    return ports


def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="vhost_scanner.py",
        description="ReconHound Module 9 — virtual-host discovery via Host-header variation (standalone test entry point).",
    )
    parser.add_argument("--ip", required=True, help="Target IP already confirmed in-scope, e.g. 93.184.216.34")
    parser.add_argument("--target", required=True, help="Authorized target domain (used to build in-scope candidate hostnames)")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout (seconds)")
    parser.add_argument("--ports", default="80/http,443/https", help="Comma-separated port/scheme pairs, e.g. 80/http,8443/https")
    parser.add_argument("--wordlist", default=DEFAULT_WORDLIST_NAME, help="Wordlist filename under wordlists/")
    parser.add_argument("--extra-hostnames", default=None, help="Comma-separated extra hostnames to test against this IP")
    parser.add_argument("--max-candidates", type=int, default=None, help="Cap the number of candidate hostnames probed")
    parser.add_argument(
        "--allow-out-of-scope-hostnames", action="store_true",
        help="Probe caller-supplied extra hostnames even if they are not a subdomain of --target",
    )
    parser.add_argument(
        "--sni-mode", default=SNI_MODE_CONNECTION, choices=list(SUPPORTED_SNI_MODES),
        help=("TLS SNI for https probes: 'connection' (default, no SNI is sent for an IP literal, "
              "routing is decided by the HTTP Host header only) or 'candidate' (also set SNI to the "
              "candidate hostname, which SNI-routing edges key on)"),
    )
    args = parser.parse_args()

    extra_hostnames = [h.strip() for h in args.extra_hostnames.split(",") if h.strip()] if args.extra_hostnames else None

    try:
        result = run_vhost_scan(
            args.ip, target=args.target, output_dir=args.output_dir,
            ports=_parse_ports_arg(args.ports) or None, extra_hostnames=extra_hostnames,
            wordlist_name=args.wordlist, timeout=args.timeout, max_candidates=args.max_candidates,
            allow_out_of_scope_hostnames=args.allow_out_of_scope_hostnames, sni_mode=args.sni_mode,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
