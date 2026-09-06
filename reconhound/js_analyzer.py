"""
reconhound/js_analyzer.py — ReconHound Module 13 (js_analyzer.py), per
context.md §13's build order (position 18 — after surface_mapper.py,
position 8, which is not yet implemented; this repository is already
operating under the same explicit, user-approved build-order deviation
documented in code_leak.py's/tech_fingerprint.py's/wayback_intel.py's
module docstrings).

Phase: Active. See context.md §10 (module 13, "Deep client-side intel")
for the authoritative responsibilities, and §8 for the evidence/confidence
data model this module implements. This file only documents
implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Deep client-side intel. Downloads + analyzes JS files, extracts API
  URLs/routes/internal endpoints/external service refs, config-value
  detection, secret-indicator flagging (for manual verification, never
  confirmed), source-map detection + `.js.map` parsing + original-source
  reconstruction, client-side sources/sinks/data-flows/postMessage/
  localStorage mapping, WebSocket endpoint detection, correlates JS refs
  to API endpoints via surface_mapper/api_recon. Key differentiator."

That expands into these discrete responsibilities, each implemented below:

  1. JavaScript acquisition (download, redirects handled safely,
     scope-enforced)                          -> fetch_javascript_file
  2. Content analysis:
       API URLs/routes/internal endpoints      -> extract_api_references
       external service references             -> extract_external_service_references
       config-value detection                  -> extract_config_values
       secret-indicator flagging                -> extract_secret_indicators
       WebSocket endpoints                      -> detect_websocket_references
  3. Source maps:
       detection (.js.map / sourceMappingURL)   -> detect_source_map_reference
       retrieval                                -> fetch_source_map
       safe parsing                             -> parse_source_map
       original-source reconstruction           -> reconstruct_original_sources
       (all four orchestrated per-file, with
        recursive re-analysis of reconstructed
        sources)                                -> process_source_map
  4. Client-side attack-surface intelligence:
       sources/sinks/possible data flows        -> extract_client_side_signals
       postMessage                              -> extract_postmessage_signals
       localStorage                             -> extract_localstorage_signals
  5. API correlation, normalized for the
     ALREADY-BUILT endpoint_discovery.py
     interface (see NO-CROSS-MODULE-CALLS
     PRECEDENT below)                           -> build_endpoint_discovery_js_data
                                                    (assembled inline by
                                                    persist_analysis_findings)

Plus shared plumbing: make_finding/make_js_finding, PendingAssetsStore,
_safe_store_add, fetch_url (duplicated per modular independence, same as
every other implemented module), analyze_javascript_content (bundles
responsibilities #2/#4 for one already-fetched script — independently
testable), persist_analysis_findings (persistence + js_data assembly for
one analyzed unit), and a multi-file orchestrator run_js_analyzer
(mirroring the run_http_analysis/run_endpoint_discovery/run_crawler
precedent — not itself a listed context.md responsibility).

NO-CROSS-MODULE-CALLS PRECEDENT (important for responsibility #5, "API
correlation... via surface_mapper/api_recon", and for this module's own
input): every already-implemented module in this repository documents
that it does not import or call into any sibling module — integration is
deferred to core/orchestrator.py (not yet built). This module follows the
same precedent from both ends:

  a. INPUT: crawler.py (already implemented) persists each discovered
     `<script src>` reference as a `javascript_reference` finding with
     value `{"url":, "source_page":, "in_scope":, "fetched": False}` and
     explicitly tags it `metadata={"for_module": "js_analyzer.py"}` — but
     crawler.py never calls this module directly (see crawler.py's own
     module docstring, decision #1). This module's `run_js_analyzer`
     therefore accepts `js_files` as caller-supplied input, and its
     normalization (`_normalize_js_reference`) accepts crawler.py's raw
     persisted finding records verbatim (as well as a plain list of URL
     strings, or `{"url":, "source_page":}` dicts) — no adaptation layer
     is required to wire the two together once an orchestrator exists.
  b. OUTPUT: `build_endpoint_discovery_js_data` (assembled per-file inside
     `persist_analysis_findings`) normalizes every discovered
     API/route/internal-endpoint reference into the EXACT shape
     endpoint_discovery.py's `correlate_javascript_parameters` function
     ALREADY documents as its expected `js_data` input —
     `{"url":, "parameters": [{"name":,"location":,"method":,"data_type":}],
     "evidence": [...], "source_file": str}` (see endpoint_discovery.py's
     own module docstring, decision #1, and its `correlate_javascript_
     parameters` docstring, which literally names this as "the eventual
     js_analyzer.py output"). This module never imports or calls
     endpoint_discovery.py itself — it only produces data shaped for that
     already-built, already-caller-supplied parameter, exactly as
     tech_fingerprint.py does for `technology`. The "JavaScript reference
     → API endpoint → surface_mapper.py → api_recon" chain the assignment
     describes is therefore satisfied by producing evidence-rich,
     correctly-shaped output at each existing seam, not by building a
     second, competing correlation engine inside this file.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other implemented module, sharing the same output file). This module
does not implement or call into surface_mapper, active_recon,
tech_fingerprint, vhost_scanner, endpoint_discovery, api_recon, crawler,
supply_chain, exposure_scan, http_analyzer, ssl_analyzer, screenshot,
vuln_intel, risk_engine, report_generator, orchestrator, osint_engine, or
any other module.

SECURITY BOUNDARIES (context.md §4/§16, assignment's explicit "ACTIVE
SCOPE" instructions):

  - Every fetch this module performs — the JS file itself, every redirect
    hop, and any discovered source map — goes through the SAME chokepoint,
    `validate_url_target`. That single function enforces the scheme check,
    a control-character rejection (urlsplit strips CR/LF/TAB silently, so
    without it the host that is scope-checked is not the string handed to
    `requests` — mirrors crawler.py's `_candidate_in_scope`), the
    domain-suffix scope check, the `_is_disallowed_redirect_ip`
    private/loopback/reserved-IP safeguard, and the credential strip.
    Crucially, the IP-literal exemption from the domain comparison does NOT
    exempt an address from the SSRF safeguard: this module's input is
    content the target itself served (a `<script src="http://127.0.0.1:8080/
    x.js">` on the target's page, a `sourceMappingURL` inside a bundle), so
    the exemption exists only for an IP-literal target the operator
    explicitly authorised — exactly crawler.py's carve-out. A reference to
    an out-of-scope host is recorded as a `js_analyzer_skipped_out_of_scope`
    finding — never silently dropped, and never fetched.
  - When no logical `target` is supplied, the script's OWN host is the
    implicit scope for its source map, mirroring how `extract_api_references`
    already treats a script's origin. Without that fallback `target=None`
    disabled the scope check entirely and an explicit
    `sourceMappingURL=https://third-party/app.js.map` was fetched.
  - An inline `data:` source map is decoded LOCALLY (stdlib base64) rather
    than fetched, so the common inline case is analysed without any request
    and without a scope question arising at all.
  - External service references (a JS file referencing
    `https://js.stripe.com/...`, `https://www.google-analytics.com/...`,
    etc.) are recorded as OBSERVATIONS ONLY from content already fetched
    for the JS file itself — this module never issues a request to any
    out-of-scope host, including a source map hosted on a third-party CDN
    (that reference is recorded, never fetched, mirroring the
    out-of-scope-JS-reference handling above).
  - Secret-pattern matches (`extract_secret_indicators`) are OBSERVATIONS,
    never confirmed credentials: every matched value is reduced to a
    partially-masked representation (`_redact_secret`) plus a SHA-256
    fingerprint (for downstream exact-match correlation without
    re-exposing the value) before it is ever persisted or returned — the
    raw matched string is never stored. No matched value is ever used in
    a subsequent request (no "does this credential authenticate"
    verification of any kind).
  - That promise covers the WHOLE persisted record, not only the
    `redacted_value` field. Any excerpt of raw script text that leaves this
    module goes through `_mask_residual_secrets` first: the context window
    around a match (which can contain a second, adjacent credential, or the
    tail of a value its own capture group truncated), the source/sink line
    excerpt (on a minified bundle "the line" is the whole file), the config
    evidence excerpt, and the preview of a source recovered from a source
    map. A `user:password@` component is stripped from every URL this module
    resolves, records or requests (`_strip_userinfo`).
  - Config values (`extract_config_values`) are the deliberate exception:
    that function is defined over values that are PUBLIC BY DESIGN (a Stripe
    publishable key, a Sentry DSN's public key, an API base URL, an
    environment label), so the value itself is recorded verbatim — masking it
    would destroy the responsibility. Anything genuinely credential-shaped is
    reported, redacted, through `extract_secret_indicators` instead.
  - Client-side source/sink "possible data flow" observations
    (`extract_client_side_signals`) are an explicitly-labeled PROXIMITY
    HEURISTIC (a source pattern and a sink pattern found within a few
    lines of each other in the raw, often-minified script) — not a taint
    analysis, and never persisted above LOW confidence. Every such finding
    states in its own evidence that it is unverified and requires manual
    review; none claims an exploitable vulnerability.

Implementation decisions (ambiguities resolved so implementation can
proceed without inventing requirements):

  1. Extraction throughout this module is regex-based over the raw script
     text, matching every other already-implemented module's approach for
     JS/HTML content (endpoint_discovery.py's `_JS_CALL_RE`/
     `_QUOTED_API_PATH_RE`, http_analyzer.py's JWT/auth-surface patterns).
     A full JavaScript AST parse is not implemented — this is a
     documented, deliberate scope limitation (not an oversight): it keeps
     the module dependency-free and consistent with the codebase's
     existing precedent, at the cost of missing references only
     expressible via runtime string construction (dynamically built URLs,
     computed property names, etc.).
     TEMPLATE LITERALS are not in that excluded class and are handled:
     `fetch(`/api/users/${id}`)` has a static, statically-visible head. Only
     that STATIC PREFIX (`/api/users/`) is resolved into a reference; the
     interpolated remainder makes the whole thing a ROUTE TEMPLATE, which is
     recorded in the evidence and never presented as a concrete endpoint. A
     template with no static prefix (`${BASE}/api/x`) yields nothing, because
     nothing can honestly be resolved from it.
  2. Source-map original-source reconstruction (#3) relies on the
     standard, commonly-embedded `sourcesContent` array — when a source
     map embeds each original file's full text there (the common case for
     maps meant to be publicly debuggable), reconstruction is exact. Full
     VLQ `mappings` decoding (byte-for-byte token-to-original-position
     mapping per the Source Map v3 spec) is NOT implemented — that is a
     substantial, separate parsing task disproportionate to this
     assignment's scope, and is not required to satisfy "reconstruct/
     inspect original source" when `sourcesContent` is present, which is
     the overwhelming common case for maps an attacker/analyst could
     obtain at all. When `sourcesContent` is absent, only the referenced
     original filenames (`sources`) are recorded — a real, documented
     limitation, not silently hidden.
  3. `.js.map` discovery has two tiers: an EXPLICIT `//# sourceMappingURL=`
     (or the equivalent block-comment form) reference is trusted and
     always recorded once source-map processing runs. An IMPLICIT guess —
     probing the conventional `<script-url>.map` sibling when no explicit
     comment exists — is also attempted (a very common real-world
     convention many build tools still emit even without the comment),
     but is only ever persisted as a finding once it has actually been
     fetched and confirmed (a non-2xx/parse-failure result for an
     unconfirmed guess is simply not recorded — persisting "we guessed a
     URL that turned out to be wrong" for every script would be noise,
     not evidence).
  4. Body-parameter hints (`extract_body_parameter_hints`, feeding the
     `parameters` list of #5's `js_data` output) are a best-effort,
     file-wide regex scan for `JSON.stringify({...})` object-literal keys
     near a fetch/axios call — this cannot reliably associate a specific
     key set to a specific endpoint URL without a real parser (decision
     #1), so when present they are attached to every API-reference finding
     from the same file with an explicit "file-wide heuristic, not
     confirmed specific to this endpoint" evidence note, rather than
     silently asserting a precise per-endpoint association the extraction
     method cannot actually support.
  5. `requests` is reused, no new dependency (same pattern as every other
     active module). JS files and source maps are fetched with a larger
     default body-size ceiling than HTML-oriented modules
     (`DEFAULT_MAX_BODY_BYTES` / `DEFAULT_MAX_SOURCE_MAP_BYTES`), since
     production JS bundles and their maps are routinely megabytes —
     content beyond the ceiling is truncated, not rejected, and
     `body_truncated` is preserved so downstream consumers know analysis
     may be incomplete.
  6. Only GET requests are made, and only to the JS file's own scope
     (itself, its redirect targets, and its own source map) — this module
     discovers client-side surface, it never exercises or authenticates
     to anything it finds (assignment's explicit "do not exploit... do
     not authenticate using extracted values" instruction).

  7. RESPONSE VALIDATION. A script is only analysed when the response was
     2xx and the body is textual and not HTML. `fetch_javascript_file`
     reports any non-redirect response as "found", so without this an HTML
     404 body was parsed as JavaScript and the links inside it became
     `js_analyzer_endpoint_reference` findings — endpoint intelligence
     manufactured out of an error page. A fetched-but-unusable response is
     still RECORDED (as `js_analyzer_fetch_failed`, with the reason), because
     "this URL was checked and yielded no usable script" is itself a
     negative result other modules can rely on (context.md §8/§12.11). A
     zero-byte 200 response is analysed normally: it is an empty script, not
     a binary payload.
  8. IDENTICAL OBSERVATIONS ARE MERGED, not duplicated (context.md §7), and
     each carries an `occurrences` count. Identity is: resolved URL for an
     API reference, (vendor, host) for an external service, (key, value) for
     a config value, (pattern_name, fingerprint) for a secret indicator,
     (kind, line) for a source/sink, (source_kind, sink_kind) for a possible
     data flow, (method, key) for a localStorage access, source line for a
     postMessage signal, and the URL itself for an input reference.
     Evidence strings are deduplicated per mechanism, so repetition raises
     the occurrence count but NOT confidence — context.md §8 raises
     confidence on independent converging signals, and eight copies of one
     hard-coded URL are one signal seen eight times. This is also what keeps
     a minified bundle from persisting tens of thousands of byte-identical
     findings (a 200KB one-line bundle previously produced a quadratic
     explosion of source/sink pairs that did not finish in ten minutes).
  9. Findings for one analysed unit are committed in a single atomic batch
     (`PendingAssetsStore.add_many`, mirroring endpoint_discovery.py).
     "Persist immediately" is preserved at the granularity of an analysed
     unit — one script, or one source map and everything reconstructed from
     it — rather than one full-file rewrite per finding, which was quadratic
     (measured: 53.7s for 2000 findings from one script; 116s for a map
     embedding 5000 original sources).

DISCOVERY != CONFIRMED VULNERABILITY: every record here is an observation
with explicit evidence and confidence. None of this module's output —
including secret-pattern matches and source/sink proximity observations —
should be read as "vulnerable", "exploitable", or "confirmed" absent
independent, human verification. Severity is NOT decided here: this module
produces evidence and confidence, and risk_engine.py maps that onto
CRITICAL/HIGH/MEDIUM/LOW/INFO under its own confidence ceiling — which is
why a deliberately false-positive-prone pattern such as
`generic_secret_assignment` is emitted at MEDIUM with an explicit
verification note rather than being suppressed or promoted here.

KNOWN, INTENTIONAL LIMITATIONS (v1):
  - No AST parse, no JavaScript execution, no headless browser: references
    that only exist after runtime string construction are not recoverable
    statically, and this module does not attempt to.
  - Source-map reconstruction uses embedded `sourcesContent`; VLQ `mappings`
    are not decoded (decision #2). Index maps (`sections`) ARE flattened.
  - The source/sink "possible data flow" is a textual proximity heuristic
    (within 2 lines AND 400 characters), never a taint analysis. Two
    statements more than 400 characters apart are not reported as adjacent,
    which is a deliberate narrowing: without it, every source paired with
    every sink in any minified bundle.
  - `extract_body_parameter_hints` remains file-wide, not per-endpoint
    (decision #4).
  - Analysis is sequential; there is no in-module concurrency or
    cancellation. Threading and interrupt handling belong to
    core/orchestrator.py and reconhound.py respectively.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import bisect
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import threading
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

MODULE_NAME = "js_analyzer.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"
_CONF_ORDER = [CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH]

DEFAULT_USER_AGENT = "ReconHound-JSAnalyzer/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_BODY_BYTES = 2_000_000
DEFAULT_MAX_SOURCE_MAP_BYTES = 5_000_000
DEFAULT_MAX_REDIRECT_HOPS = 5

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)


class ScopeError(ValueError):
    """Raised when a URL/target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors http_analyzer.py's/endpoint_discovery.py's/
# crawler.py's validate_url_target and SSRF safeguard; duplicated per
# modular independence, context.md §12.2)
# ---------------------------------------------------------------------------

def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_disallowed_redirect_ip(host: str) -> bool:
    """Private/loopback/link-local/multicast/reserved/unspecified IP-literal check (SSRF safeguard)."""
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified
    )


def _idna_normalize(host: str) -> str:
    """
    Reduce a hostname to the single form scope comparisons are made in.

    Without this, a target written as "münchen.de" and a hostname arriving
    as "xn--mnchen-3ya.de" (or the reverse) compare unequal even though
    they are the same host — silently dropping in-scope scripts in one
    direction, and making a homograph host look "different" from the
    target it impersonates in the other. Both sides are folded to
    lowercase A-label form; anything that will not encode is returned
    lowercased unchanged so the caller still gets a deterministic
    comparison. Mirrors crawler.py's/endpoint_discovery.py's helper of the
    same name (duplicated per modular independence, context.md §12.2).
    """
    host = (host or "").strip().rstrip(".").lower()
    if not host or host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return host


def _strip_userinfo(url: str) -> str:
    """
    Remove any `user:password@` component from a URL.

    URLs reach this module from script bodies, from source maps and from
    caller-supplied crawler records, so credentials genuinely turn up in
    them. They must not be re-requested, must not become part of an asset
    identity, and above all must never be written into
    pending_assets.json — a plain-text file shared with every other module
    and included in the report appendix (CLAUDE.md rule 16). Mirrors
    endpoint_discovery.py's helper of the same name.
    """
    if not isinstance(url, str) or "@" not in url:
        return url
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    if "@" not in parsed.netloc:
        return url
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"          # bare IPv6 literal
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port else host
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def _in_scope_host(hostname: str, target: str) -> bool:
    hostname = _idna_normalize(hostname)
    target = _idna_normalize(target)
    if not hostname or not target:
        return False
    return hostname == target or hostname.endswith("." + target)


def validate_url_target(url: str, target: Optional[str] = None) -> str:
    """
    Validate that `url` is a syntactically valid http(s) URL, and — if
    `target` is supplied — that its hostname is the target itself or a
    subdomain of it.

    An IP-literal host is still exempt from the *domain-suffix* comparison
    (mirroring http_analyzer.py's rationale: IP scope is enforced
    upstream, not by a domain comparison here), but that exemption is not
    a way into the operator's own internal network. Every URL this module
    fetches originates in content the target itself served — a
    `<script src="http://127.0.0.1:8080/x.js">` on the target's page, a
    `sourceMappingURL` comment inside a bundle — so the exemption is
    closed for private/loopback/link-local/reserved literals exactly as
    crawler.py's `_candidate_in_scope` closes it for discovered links,
    with the same carve-out: an operator who authorised a scan against an
    internal IP has already made that exact address in scope.

    Control characters are rejected outright: `urlsplit` strips CR, LF and
    TAB silently, so without this check the host that gets scope-checked
    is not the string that would be handed to `requests` (same reasoning
    as crawler.py's `_candidate_in_scope`).
    """
    if not isinstance(url, str) or not url.strip():
        raise ScopeError("URL must be a non-empty string.")

    candidate = url.strip()
    if any(ch in candidate for ch in "\r\n\t\x00"):
        raise ScopeError(f"URL contains control characters and cannot be safely scope-checked: {url!r}")

    parsed = urllib.parse.urlsplit(candidate)

    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"URL must use http:// or https://, not {parsed.scheme!r}: {url!r}")

    try:
        hostname = parsed.hostname
    except ValueError as exc:
        raise ScopeError(f"URL has an unparseable host: {url!r} ({exc})") from exc
    if not hostname:
        raise ScopeError(f"URL must include a hostname: {url!r}")

    if _is_ip_literal(hostname):
        # IP-literal host. Only an exact match for an IP-literal target is
        # unconditionally in scope; otherwise the private/reserved-range
        # safeguard applies (see docstring).
        if target and _is_ip_literal(target):
            if _idna_normalize(hostname) != _idna_normalize(target):
                raise ScopeError(
                    f"URL host {hostname!r} is not the authorized IP target {target!r}: {url!r}"
                )
        elif _is_disallowed_redirect_ip(hostname):
            raise ScopeError(
                f"URL host {hostname!r} is a private/loopback/reserved IP literal and is not an "
                f"authorized target (SSRF safeguard): {url!r}"
            )
    elif target and not _in_scope_host(hostname, target):
        raise ScopeError(f"URL host {hostname!r} is not in scope for target {target!r}: {url!r}")

    # The host is authorised; an embedded credential is not (see _strip_userinfo).
    return _strip_userinfo(candidate)


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


def make_js_finding(
    finding_type: str,
    target: str,
    value: Any,
    evidence: List[str],
    confidence: str,
    parent_js_url: str,
    source_page: Optional[str] = None,
    derived_from_source_map: bool = False,
    original_source_file: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Wrap one discovery with the OUTPUT section's required "relationship to
    the originating JavaScript file" — every finding this module persists
    goes through this helper so `parent_js_url`/`source_page`/source-map
    provenance is never lost.
    """
    metadata: Dict[str, Any] = {
        "parent_js_url": parent_js_url,
        "source_page": source_page,
        "derived_from_source_map": derived_from_source_map,
        "original_source_file": original_source_file,
    }
    if extra_metadata:
        metadata.update(extra_metadata)
    return make_finding(finding_type, target, value, evidence, confidence, metadata)


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

    def __init__(self, output_dir: str = "output", filename: str = "pending_assets.json"):
        self.output_dir = output_dir
        self.path = os.path.join(output_dir, filename)
        self._lock = threading.Lock()
        # Serialized body of everything this store has written, kept so an
        # append does not have to re-encode the whole file (see
        # _atomic_write_body). `_stamp` is the (mtime_ns, size) of the file as
        # this store last left it; anything else means somebody else wrote it
        # and the cache is void.
        self._serialized: Optional[str] = None
        self._stamp: Optional["tuple[int, int]"] = None
        os.makedirs(self.output_dir, exist_ok=True)

    def _current_stamp(self) -> Optional["tuple[int, int]"]:
        try:
            info = os.stat(self.path)
        except OSError:
            return None
        return (info.st_mtime_ns, info.st_size)

    def _cache_is_current(self) -> bool:
        return self._serialized is not None and self._stamp == self._current_stamp()

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
        except (json.JSONDecodeError, ValueError, RecursionError) as exc:
            # RecursionError (a RuntimeError) is included for the same reason as
            # in parse_source_map: a pathologically nested pending_assets.json
            # must surface as a reportable persistence failure, not as an
            # exception that unwinds the run.
            raise PersistenceError(
                f"Existing pending_assets.json is corrupt and cannot be safely "
                f"appended to: {exc}"
            ) from exc

    def add(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Append one finding and persist immediately. Returns the finding."""
        self.add_many([finding])
        return finding

    def add_many(self, findings: List[Dict[str, Any]]) -> int:
        """
        Append a batch of findings in ONE read + ONE atomic write.

        add() rewrites — and re-encodes — the whole shared file per finding,
        which is quadratic in the number of records already on disk. This
        module is a bad case for that: one bundle can legitimately yield
        thousands of client-side signal records, and pending_assets.json
        already holds every earlier module's output by the time js_analyzer
        runs. Measured on this repository with the per-finding path: 2000
        findings from one script took 53.7s to persist.

        Crash-safety is unchanged and slightly stronger: still one
        write-to-temp + os.replace, so a batch is all-or-nothing rather than
        half-applied, and previously persisted records are always preserved.
        Mirrors endpoint_discovery.py/active_recon.py/wayback_intel.py, which
        share this output file and this class. Returns the number written.
        """
        if not findings:
            return 0
        with self._lock:
            if not self._cache_is_current():
                # First write of this run, or the file changed underneath us:
                # re-encode from what is actually on disk.
                self._serialized = self._encode_body(self._read_all())
            addition = self._encode_body(findings)
            body = f"{self._serialized},\n{addition}" if self._serialized else addition
            self._atomic_write_body(body)
            self._serialized = body
        return len(findings)

    @staticmethod
    def _encode_body(records: List[Dict[str, Any]]) -> str:
        """Serialize records as the *inside* of the JSON array (no brackets)."""
        if not records:
            return ""
        return ",\n".join("  " + json.dumps(r, indent=2).replace("\n", "\n  ") for r in records)

    def _atomic_write_body(self, body: str) -> None:
        """
        Write "[<body>]" via write-to-temp + os.replace + directory fsync.

        The file format, the indentation and the crash-safety guarantee are
        exactly as before; what changed is that already-written records are no
        longer re-encoded on every append.
        """
        dir_name = os.path.dirname(self.path) or "."
        fd, tmp_path = tempfile.mkstemp(prefix=".pending_assets_", dir=dir_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("[\n" + body + "\n]" if body else "[]")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
            self._fsync_dir(dir_name)
            self._stamp = self._current_stamp()
        except BaseException:
            self._serialized = None
            self._stamp = None
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def _atomic_write(self, records: List[Dict[str, Any]]) -> None:
        """Replace the file with exactly `records` (kept for direct callers)."""
        encoded = self._encode_body(records)
        self._atomic_write_body(encoded)
        self._serialized = encoded

    @staticmethod
    def _fsync_dir(dir_name: str) -> None:
        """
        Durably commit the os.replace() rename itself.

        Without this the replacement file's *contents* are on disk but the
        directory entry pointing at them may not be, so a power loss can still
        resurrect the pre-replace file and lose every discovery appended since.
        Best-effort: some platforms/filesystems refuse to fsync a directory.
        Mirrors endpoint_discovery.py/passive_recon.py, which share this file.
        """
        try:
            fd = os.open(dir_name, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self._read_all()


# A persistence attempt can fail in more ways than PersistenceError: the disk
# fills or the path loses permissions (OSError), or an analysed script yields a
# value json.dump cannot serialise (TypeError/ValueError). Catching only
# PersistenceError meant those escaped and took the *completed discovery* down
# with them — the one outcome context.md §12.11 forbids. Mirrors
# endpoint_discovery.py.
_PERSISTENCE_FAILURES = (PersistenceError, OSError, TypeError, ValueError)


def _safe_store_add(store: Optional["PendingAssetsStore"], finding: Dict[str, Any]) -> Optional[str]:
    """
    store.add() wrapped so a single persistence failure doesn't abort the
    rest of this module's work. Returns None on success, or an error
    message the caller is responsible for recording (never silently
    discarded).
    """
    return _safe_store_add_many(store, [finding])


def _safe_store_add_many(
    store: Optional["PendingAssetsStore"], findings: List[Dict[str, Any]],
) -> Optional[str]:
    """
    store.add_many() wrapped identically to _safe_store_add. Returns None on
    success, or an error message; the in-memory findings are never discarded
    because persistence failed.
    """
    if store is None or not findings:
        return None
    try:
        store.add_many(findings)
        return None
    except _PERSISTENCE_FAILURES as exc:
        return str(exc)


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


def _truncate(text: Optional[str], limit: int = 300) -> str:
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + "…"


def _looks_textual(content_type: Optional[str], body: Optional[str]) -> bool:
    """
    Best-effort textual-content check so binary responses aren't parsed as JS.

    An EMPTY body is textual: a zero-byte script is a script that was fetched
    and contains nothing, which is a negative result worth remembering
    (context.md §8), not a binary payload. Treating it as non-textual made a
    zero-byte 200 response vanish without a single persisted record.
    """
    if body is None:
        return False
    if not body:
        return True
    if content_type:
        ct = content_type.lower()
        if any(t in ct for t in ("javascript", "ecmascript", "json", "text")):
            return True
        if any(
            t in ct for t in (
                "image/", "video/", "audio/", "font/", "application/octet-stream",
                "application/zip", "application/pdf", "application/gzip", "application/wasm",
            )
        ):
            return False
    # No usable Content-Type: sniff. A body decoded with errors="replace" turns
    # binary into U+FFFD, and a NUL byte never occurs in real script text.
    sample = body[:4096]
    if "\x00" in sample:
        return False
    replacement_ratio = sample.count("\ufffd") / len(sample)
    return replacement_ratio <= 0.10


_HTML_DOCUMENT_PREFIXES = ("<!doctype html", "<html", "<head", "<?xml")


def _looks_like_html_document(body: Optional[str]) -> bool:
    """
    Whether a response body actually is an HTML document.

    Judged on the body, not on Content-Type alone: a `text/html` header at a
    script URL is usually a soft-404 or an error page, but it is also what a
    misconfigured server sends for a perfectly real script. Refusing on the
    header alone would turn a false positive into a false negative, so the
    body has the final say.
    """
    if not body:
        return False
    head = body.lstrip("\ufeff \t\r\n")[:512].lower()
    return head.startswith(_HTML_DOCUMENT_PREFIXES)


def _infer_data_type(value: str) -> str:
    """LOW-confidence-by-nature type inference from an observed query-parameter value."""
    if value == "":
        return "unknown"
    if re.fullmatch(r"[+-]?\d+", value):
        return "integer"
    if re.fullmatch(r"[+-]?\d+\.\d+", value):
        return "float"
    if value.lower() in ("true", "false"):
        return "boolean"
    return "string"


def _confidence_from_count(n: int, floor: str = CONFIDENCE_LOW) -> str:
    """Multiple independent converging signals raise confidence (context.md §8)."""
    idx = max(_CONF_ORDER.index(floor), min(n - 1, 2))
    return _CONF_ORDER[idx]


# ---------------------------------------------------------------------------
# Secret-redaction helpers (mirrors code_leak.py's model; duplicated per
# modular independence — see module docstring, SECURITY BOUNDARIES)
# ---------------------------------------------------------------------------

def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _redact_secret(value: str) -> str:
    """Return a partially-masked representation of `value`; never the raw secret."""
    if not value:
        return ""
    if len(value) <= 8:
        return value[0] + "*" * (len(value) - 1) if len(value) > 1 else "*"
    stars = min(len(value) - 8, 24)
    return f"{value[:4]}{'*' * stars}{value[-4:]}"


# Characters that can legitimately continue a secret/credential token. Used to
# widen a redaction span past the end of a capture group whose own length bound
# truncated the value (see _context_snippet).
_SECRET_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-/+=."
)
# Any run of this many secret-charset characters inside a context window is
# treated as a high-entropy blob and masked. 20 is comfortably longer than an
# ordinary JavaScript identifier and comfortably shorter than every credential
# format JS_SECRET_PATTERNS recognises, so it masks a neighbouring secret
# without destroying the surrounding code context that makes the evidence
# readable.
_ENTROPY_RUN_MIN = 20
_ENTROPY_RUN_RE = re.compile(r"[A-Za-z0-9_\-/+=]{%d,}" % _ENTROPY_RUN_MIN)
# Upper bound on how far a redaction span is widened in each direction. Longer
# than every credential format JS_SECRET_PATTERNS recognises, so it never
# truncates a real value, while keeping the widening O(1) per match.
_SPAN_EXTENSION_LIMIT = 512


def _mask_residual_secrets(text: str) -> str:
    """
    Mask anything in `text` that still looks like a credential.

    The window around a match is raw source, so it can itself contain a
    second, distinct secret (two adjacent key assignments), and a capture
    group with a length bound can leave the tail of its own value sitting
    just outside the span. Both are masked here so a context snippet can
    never carry a usable credential into pending_assets.json.
    """
    if not text:
        return text
    spans: List["tuple[int, int]"] = []
    for pat in JS_SECRET_PATTERNS:
        # Only the self-delimiting, value_group-0 formats: those match the
        # credential itself rather than a keyword plus a bounded run, so their
        # span is exactly what must disappear. The keyword-anchored patterns
        # are covered by the entropy-run rule below.
        if pat["value_group"] != 0:
            continue
        for m in pat["regex"].finditer(text):
            spans.append(m.span(0))
    for m in _ENTROPY_RUN_RE.finditer(text):
        spans.append(m.span(0))
    if not spans:
        return text

    spans.sort()
    merged: List["List[int]"] = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])

    out: List[str] = []
    cursor = 0
    for a, b in merged:
        out.append(text[cursor:a])
        out.append(_redact_secret(text[a:b]))
        cursor = b
    out.append(text[cursor:])
    return "".join(out)


def _context_snippet(body: str, start: int, end: int, redacted_value: str, window: int = 40) -> str:
    """
    A short, already-redacted excerpt around a matched span — never the raw
    secret span, and never a usable credential in the surrounding window.

    Two leaks are closed here, both reproduced against the previous
    implementation:

      1. A capture group with a length bound (`{16,64}`, `{8,64}`, ...) stops
         at its bound, so a longer real value continued straight into the
         "context" as plain text. The redaction span is therefore widened
         outwards across every adjacent `_SECRET_CHARS` character before the
         window is taken, and the mask is recomputed over the widened span so
         the snippet does not understate what was removed.
      2. A second, unrelated secret sitting within `window` characters of this
         one was emitted verbatim. The surrounding text is therefore passed
         through `_mask_residual_secrets`.

    The module docstring's SECURITY BOUNDARIES promise ("the raw matched
    string is never stored") applies to the whole persisted record, not only
    to the `redacted_value` field.
    """
    if not body:
        return ""
    start = max(0, min(start, len(body)))
    end = max(start, min(end, len(body)))

    # The widening is bounded: an unbounded walk is O(len(body)) per match,
    # which an adversarial script made of one multi-megabyte run of
    # secret-charset characters turns into a quadratic stall (reproduced at
    # 75s for a 4MB input before this bound). Anything past the bound is
    # still caught by _mask_residual_secrets' entropy-run rule, so the bound
    # costs safety nothing.
    ext_start, ext_end = start, end
    floor = max(0, start - _SPAN_EXTENSION_LIMIT)
    ceiling = min(len(body), end + _SPAN_EXTENSION_LIMIT)
    while ext_start > floor and body[ext_start - 1] in _SECRET_CHARS:
        ext_start -= 1
    while ext_end < ceiling and body[ext_end] in _SECRET_CHARS:
        ext_end += 1

    masked = redacted_value if (ext_start, ext_end) == (start, end) else _redact_secret(body[ext_start:ext_end])

    s = max(0, ext_start - window)
    e = min(len(body), ext_end + window)
    prefix = _mask_residual_secrets(body[s:ext_start])
    suffix = _mask_residual_secrets(body[ext_end:e])
    return f"{prefix}«{masked}»{suffix}"


# ---------------------------------------------------------------------------
# Shared HTTP client (not itself a listed context.md responsibility, but
# necessary plumbing — mirrors every other module's fetch_url)
# ---------------------------------------------------------------------------

def fetch_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """Perform a single HTTP GET against `url` without auto-following redirects."""
    result: Dict[str, Any] = {
        "status": "error", "status_code": None, "headers": {}, "body": None,
        "body_truncated": False, "final_url": url, "elapsed_seconds": None, "error": None,
    }
    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        req_headers.update(headers)

    resp = None
    try:
        resp = requests.get(url, timeout=timeout, headers=req_headers, allow_redirects=False, stream=True)
        try:
            raw = resp.raw.read(max_body_bytes + 1, decode_content=True)
        except Exception:
            raw = resp.content[:max_body_bytes + 1]
        truncated = len(raw) > max_body_bytes
        body_bytes = raw[:max_body_bytes]
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
            "final_url": resp.url,
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
    finally:
        if resp is not None:
            resp.close()
    return result


# ---------------------------------------------------------------------------
# 1. JavaScript acquisition (redirects handled hop-by-hop, scope-enforced
# between hops — mirrors http_analyzer.py's map_redirect_chain technique)
# ---------------------------------------------------------------------------

def fetch_javascript_file(
    url: str,
    target: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    max_redirect_hops: int = DEFAULT_MAX_REDIRECT_HOPS,
) -> Dict[str, Any]:
    """
    Download one JS file, following redirects hop-by-hop (never via
    `requests`' `allow_redirects=True`) so scope — including the SSRF
    safeguard against private/loopback/reserved IP redirect targets — is
    enforced at every hop, not just the initial request.
    """
    current = url
    hops: List[Dict[str, Any]] = []
    for _ in range(max_redirect_hops):
        resp = fetch_url(current, timeout=timeout, max_body_bytes=max_body_bytes)
        hop_entry: Dict[str, Any] = {"url": current, "status_code": resp.get("status_code"), "error": resp.get("error")}
        hops.append(hop_entry)

        if resp["status"] != "found":
            return {"status": "error", "error": resp.get("error"), "hops": hops, "final_url": current}
        if resp["status_code"] not in _REDIRECT_STATUS_CODES:
            result = dict(resp)
            result["hops"] = hops
            result["final_url"] = resp.get("final_url", current)
            return result

        location = _ci_get(resp["headers"], "Location")
        if not location:
            return {"status": "error", "error": "redirect response without Location header", "hops": hops, "final_url": current}

        next_url = urllib.parse.urljoin(current, location)
        # Every hop goes through the same chokepoint as the initial URL, so
        # the scheme check, the control-character check, the private/reserved
        # IP-literal SSRF safeguard, the domain-suffix scope check and the
        # credential strip all apply identically at every hop.
        try:
            next_url = validate_url_target(next_url, target=target)
        except ScopeError as exc:
            return {
                "status": "error",
                "error": f"redirect target rejected as out of scope or unsafe: {exc}",
                "hops": hops, "final_url": current,
            }
        hop_entry["location"] = next_url
        current = next_url

    return {"status": "error", "error": f"exceeded max_redirect_hops ({max_redirect_hops})", "hops": hops, "final_url": current}


# ---------------------------------------------------------------------------
# 2a. API URLs / routes / internal endpoints
# ---------------------------------------------------------------------------

# A backtick is excluded so a template literal's own delimiter never becomes
# part of a captured URL.
_ABS_URL_RE = re.compile(r'https?://[^\s"\'`<>()\\]+', re.IGNORECASE)
_JS_CALL_RE = re.compile(
    r'(?:fetch|axios(?:\.(?:get|post|put|delete|patch|request))?|\.open)\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
# `xhr.open(method, url)` puts the METHOD in the first argument, so the generic
# pattern above captures "GET" and records it as a route while missing the real
# URL entirely (reproduced: `x.open("GET", "/api/v1/x")` yielded the route
# https://<host>/GET). This pattern recovers the second argument, and
# _HTTP_METHOD_TOKENS discards the bare method the generic pattern captured.
_XHR_OPEN_RE = re.compile(
    r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["\']\s*,\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_HTTP_METHOD_TOKENS = frozenset(
    ("get", "post", "put", "delete", "patch", "head", "options", "trace", "connect")
)
_REL_PATH_RE = re.compile(r'["\'](/(?:api|graphql|rest|internal|v[0-9]+)[A-Za-z0-9_\-./]*)["\']', re.IGNORECASE)

# Template-literal forms. Modern client code overwhelmingly builds
# parameterised request paths as `/api/users/${id}`; the quoted-string patterns
# above miss those completely even though the leading path is plain static text
# sitting in the file. Only the STATIC PREFIX (everything before the first
# interpolation) is resolved into a reference — a route template is not a
# concrete endpoint, and this module must not present one as the other.
_JS_CALL_TEMPLATE_RE = re.compile(
    r'(?:fetch|axios(?:\.(?:get|post|put|delete|patch|request))?)\s*\(\s*`([^`]{1,500})`',
    re.IGNORECASE,
)
_TEMPLATE_PATH_RE = re.compile(
    r'`(/(?:api|graphql|rest|internal|v[0-9]+)[^`]{0,300})`', re.IGNORECASE
)
_INTERPOLATION = "${"


def _static_prefix(raw: str) -> Optional[str]:
    """
    The literal, non-interpolated head of a template-literal path.

    `/api/users/${id}/posts` -> `/api/users/`; `${BASE}/api` -> None (nothing
    static precedes the first interpolation, so no path can honestly be
    resolved). Returns None when the prefix carries no path separator.
    """
    prefix = raw.split(_INTERPOLATION, 1)[0].strip()
    if not prefix or "/" not in prefix:
        return None
    return prefix


_API_PATH_SEGMENT_RE = re.compile(r"(?:^|/)(api|graphql|rest|internal|v[0-9]+)(?:/|$)", re.IGNORECASE)


def _looks_api_path(url: str) -> bool:
    """
    Whether a path looks like an API route rather than an ordinary page.

    Matched on whole path *segments*: the previous substring test classified
    `/apidocs/index.html`, `/apiary` and `/graphqlish` as API endpoints because
    they merely start with, or contain, the token.
    """
    try:
        path = (urllib.parse.urlsplit(url).path or "")
    except ValueError:
        return False
    return bool(_API_PATH_SEGMENT_RE.search(path))


def extract_api_references(body: str, js_url: str, target: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Extract in-scope API URLs, routes, and internal endpoints (responsibility
    #2). Absolute URLs, fetch()/axios()/XHR call targets, and relative
    API-shaped path literals are all considered; results are deduplicated
    by resolved URL and every matching mechanism's evidence is preserved.
    An explicit `target` may be supplied; otherwise the JS file's own
    hostname is used as the implicit scope (a script's own origin is
    always "in scope" for the purposes of interpreting its own references).
    """
    if not body:
        return []
    effective_target = target or (urllib.parse.urlsplit(js_url).hostname or "")
    found: Dict[str, Dict[str, Any]] = {}

    def add(raw: str, resolved: str, kind: str, evidence_text: str) -> None:
        # `raw` records what the script literally wrote, but it is persisted, so
        # an embedded credential is stripped from it too (CLAUDE.md rule 16) —
        # stripping only the resolved URL still leaked it via this field.
        raw = _strip_userinfo(raw)
        entry = found.setdefault(
            resolved, {"url": resolved, "raw": raw, "kind": kind, "evidence": [], "occurrences": 0}
        )
        if kind == "api_endpoint":
            entry["kind"] = "api_endpoint"
        entry["occurrences"] += 1
        # One *mechanism* contributes one piece of evidence, however many times
        # the same literal is repeated in the file. Appending per match both
        # grew the persisted evidence list without bound on a minified bundle
        # and inflated confidence through _confidence_from_count: eight copies
        # of one hard-coded URL are one signal seen eight times, not eight
        # independent converging signals (context.md §8).
        if evidence_text not in entry["evidence"]:
            entry["evidence"].append(evidence_text)

    def _resolve(raw: str) -> Optional[str]:
        """Resolve a reference against the script's own URL, or None if unusable."""
        if not raw or raw.startswith(("data:", "javascript:", "blob:", "mailto:", "tel:")):
            return None
        try:
            resolved = urllib.parse.urljoin(js_url, raw)
        except ValueError:
            return None
        try:
            parsed = urllib.parse.urlsplit(resolved)
        except ValueError:
            return None
        if parsed.scheme not in ("http", "https"):
            return None
        if not _in_scope_host(parsed.hostname or "", effective_target):
            return None
        # A credential embedded in a referenced URL must never be persisted
        # (CLAUDE.md rule 16) — see _strip_userinfo.
        return _strip_userinfo(resolved)

    for m in _ABS_URL_RE.finditer(body):
        raw = m.group(0).rstrip(").,;'\"\\")
        # An absolute URL written inside a template literal carries its own
        # interpolations; only its static head is a real URL.
        if _INTERPOLATION in raw:
            raw = raw.split(_INTERPOLATION, 1)[0]
            if not raw or raw.endswith("//"):
                continue
        resolved = _resolve(raw)
        if resolved is None:
            continue
        kind = "api_endpoint" if _looks_api_path(resolved) else "internal_route"
        add(raw, resolved, kind, f"Absolute URL referenced in JS: {resolved!r}")

    for m in _JS_CALL_RE.finditer(body):
        raw = m.group(1).strip()
        # `.open("GET", url)` — the generic pattern captures the method, not a
        # route. Discard bare method tokens; _XHR_OPEN_RE recovers the real URL.
        if raw.lower() in _HTTP_METHOD_TOKENS:
            continue
        resolved = _resolve(raw)
        if resolved is None:
            continue
        kind = "api_endpoint" if _looks_api_path(resolved) else "internal_route"
        add(raw, resolved, kind, f"fetch()/axios()/XHR call target: {raw!r}")

    for m in _XHR_OPEN_RE.finditer(body):
        raw = m.group(1).strip()
        resolved = _resolve(raw)
        if resolved is None:
            continue
        kind = "api_endpoint" if _looks_api_path(resolved) else "internal_route"
        add(raw, resolved, kind, f"XMLHttpRequest.open() request URL: {raw!r}")

    for m in _REL_PATH_RE.finditer(body):
        raw = m.group(1)
        resolved = _resolve(raw)
        if resolved is None:
            continue
        add(raw, resolved, "api_endpoint", f"Relative API-shaped path literal found in JS: {raw!r}")

    # Template literals. Only the static prefix is resolved — the interpolated
    # remainder is a ROUTE TEMPLATE, recorded in the evidence so the
    # distinction between a template and a concrete endpoint is never lost.
    for pattern, label in ((_JS_CALL_TEMPLATE_RE, "fetch()/axios() template-literal call target"),
                           (_TEMPLATE_PATH_RE, "API-shaped template-literal path")):
        for m in pattern.finditer(body):
            template = m.group(1)
            prefix = _static_prefix(template)
            if prefix is None:
                continue
            resolved = _resolve(prefix)
            if resolved is None:
                continue
            kind = "api_endpoint" if _looks_api_path(resolved) else "internal_route"
            if _INTERPOLATION in template:
                evidence_text = (
                    f"{label}: `{_truncate(template, 200)}` — the interpolated remainder is a route "
                    f"TEMPLATE, not a concrete endpoint, so only its static prefix {prefix!r} is "
                    f"recorded as a reference"
                )
            else:
                evidence_text = f"{label}: `{_truncate(template, 200)}`"
            add(prefix, resolved, kind, evidence_text)

    return sorted(found.values(), key=lambda r: r["url"])


# ---------------------------------------------------------------------------
# 2b. External service references (observation only — never fetched)
# ---------------------------------------------------------------------------

_EXTERNAL_SERVICE_DOMAINS: Dict[str, "tuple[str, str]"] = {
    "google-analytics.com": ("Google Analytics", "analytics"),
    "googletagmanager.com": ("Google Tag Manager", "analytics"),
    "doubleclick.net": ("Google DoubleClick", "advertising"),
    "connect.facebook.net": ("Facebook Pixel/SDK", "analytics"),
    "facebook.net": ("Facebook Pixel/SDK", "analytics"),
    "sentry.io": ("Sentry", "error_tracking"),
    "ingest.sentry.io": ("Sentry", "error_tracking"),
    "stripe.com": ("Stripe", "payment"),
    "js.stripe.com": ("Stripe", "payment"),
    "paypal.com": ("PayPal", "payment"),
    "cloudflareinsights.com": ("Cloudflare Insights", "analytics"),
    "segment.io": ("Segment", "analytics"),
    "segment.com": ("Segment", "analytics"),
    "mixpanel.com": ("Mixpanel", "analytics"),
    "hotjar.com": ("Hotjar", "analytics"),
    "intercom.io": ("Intercom", "support"),
    "auth0.com": ("Auth0", "auth"),
    "amazonaws.com": ("AWS", "cloud_infrastructure"),
    "cloudfront.net": ("AWS CloudFront", "cdn"),
    "googleapis.com": ("Google APIs", "cloud_infrastructure"),
    "firebaseio.com": ("Firebase", "backend_as_a_service"),
    "firebaseapp.com": ("Firebase", "backend_as_a_service"),
}


def _match_external_service_domain(host: str) -> Optional["tuple[str, str]"]:
    for domain, info in _EXTERNAL_SERVICE_DOMAINS.items():
        if host == domain or host.endswith("." + domain):
            return info
    return None


def extract_external_service_references(body: str, js_url: str, target: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Identify known third-party service domains referenced in already-
    fetched JS content (responsibility #2). These are OBSERVATIONS ONLY —
    this function never issues a network request; deeper third-party
    trust-mapping is supply_chain.py's (module 14) named responsibility,
    not this module's.
    """
    if not body:
        return []
    effective_target = target or (urllib.parse.urlsplit(js_url).hostname or "")
    found: Dict[Any, Dict[str, Any]] = {}
    for m in _ABS_URL_RE.finditer(body):
        raw = m.group(0).rstrip(").,;'\"\\")
        host = (urllib.parse.urlsplit(raw).hostname or "").lower()
        if not host or _in_scope_host(host, effective_target):
            continue
        vendor = _match_external_service_domain(host)
        if not vendor:
            continue
        name, category = vendor
        key = (name, host)
        entry = found.setdefault(
            key,
            {"vendor": name, "category": category, "host": host, "example_url": raw,
             "evidence": [], "occurrences": 0},
        )
        entry["occurrences"] += 1
        evidence_text = f"Reference to {host!r} found in JS ({name})"
        if evidence_text not in entry["evidence"]:
            entry["evidence"].append(evidence_text)
    return sorted(found.values(), key=lambda r: (r["vendor"], r["host"]))


# ---------------------------------------------------------------------------
# 2c. Configuration-value detection
# ---------------------------------------------------------------------------

CONFIG_KEY_PATTERNS = [
    ("api_base_url", CONFIDENCE_LOW,
     re.compile(r'(?i)\b(?:api[_-]?base[_-]?url|apiurl|base[_-]?url)["\']?\s*[:=]\s*["\']([^"\']{3,200})["\']')),
    ("environment", CONFIDENCE_LOW,
     re.compile(r'(?i)\benv(?:ironment)?["\']?\s*[:=]\s*["\'](production|staging|development|dev|prod|test)["\']')),
    ("app_version", CONFIDENCE_LOW,
     re.compile(r'(?i)\bapp[_-]?version["\']?\s*[:=]\s*["\'](\d+\.\d+(?:\.\d+)?)["\']')),
    ("sentry_dsn", CONFIDENCE_MEDIUM,
     re.compile(r'https://[a-f0-9]{32}@[a-z0-9.\-]*sentry[a-z0-9.\-]*/[0-9]+', re.IGNORECASE)),
    ("stripe_publishable_key", CONFIDENCE_MEDIUM,
     re.compile(r'\bpk_(?:live|test)_[0-9a-zA-Z]{16,}\b')),
    ("google_maps_key_reference", CONFIDENCE_LOW,
     re.compile(r'(?i)\bgoogle[_-]?maps[_-]?(?:api[_-]?)?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,60})["\']')),
]


def extract_config_values(body: str) -> List[Dict[str, Any]]:
    """
    Detect benign, non-secret configuration-value indicators (responsibility
    #3). These are informational observations (API base URLs, environment
    labels, publishable keys that are, by design, not sensitive) — kept
    entirely separate from `extract_secret_indicators`.
    """
    if not body:
        return []
    merged: Dict[Any, Dict[str, Any]] = {}
    for name, confidence, pattern in CONFIG_KEY_PATTERNS:
        for m in pattern.finditer(body):
            value = m.group(1) if m.groups() else m.group(0)
            truncated = _truncate(value, 200)
            key = (name, truncated)
            entry = merged.get(key)
            if entry is not None:
                entry["occurrences"] += 1
                continue
            merged[key] = {
                "key": name, "value": truncated, "confidence": confidence, "occurrences": 1,
                "evidence": [f"Config pattern {name!r} matched: "
                             f"{_mask_residual_secrets(_truncate(m.group(0), 200))!r}"],
            }
    return list(merged.values())


# ---------------------------------------------------------------------------
# 2d. Secret-indicator flagging (never confirmed — see module docstring,
# SECURITY BOUNDARIES; mirrors code_leak.py's model, duplicated per
# modular independence)
# ---------------------------------------------------------------------------

JS_SECRET_PATTERNS: List[Dict[str, Any]] = [
    {"name": "aws_access_key_id", "category": "api_key", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "value_group": 0},
    {"name": "aws_secret_access_key", "category": "credential", "confidence": CONFIDENCE_MEDIUM,
     "regex": re.compile(r'(?i)aws_?secret_?(?:access_?)?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})'),
     "value_group": 1},
    {"name": "github_token", "category": "token", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "value_group": 0},
    {"name": "slack_token", "category": "token", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"), "value_group": 0},
    {"name": "google_api_key", "category": "api_key", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "value_group": 0},
    {"name": "stripe_live_secret_key", "category": "api_key", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r"\bsk_live_[0-9a-zA-Z]{16,64}\b"), "value_group": 0},
    {"name": "private_key_block", "category": "credential", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "value_group": 0},
    {"name": "jwt_token", "category": "token", "confidence": CONFIDENCE_LOW,
     "regex": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "value_group": 0},
    {"name": "db_connection_string", "category": "db_connection_string", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r'(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^\s"\'<>]+'),
     "value_group": 0},
    {"name": "generic_api_key_assignment", "category": "api_key", "confidence": CONFIDENCE_MEDIUM,
     "regex": re.compile(r'(?i)\bapi[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,64})["\']?'), "value_group": 1},
    {"name": "generic_secret_assignment", "category": "credential", "confidence": CONFIDENCE_MEDIUM,
     "regex": re.compile(
         r'(?i)\b(?:secret|token|password|passwd|pwd)["\']?\s*[:=]\s*["\']?([A-Za-z0-9!@#$%^&*_\-/+=]{8,64})["\']?'
     ), "value_group": 1},
]


def extract_secret_indicators(body: str) -> List[Dict[str, Any]]:
    """
    Match known secret/credential patterns (responsibility #3). Every
    result is an unverified pattern match — see module docstring, SECURITY
    BOUNDARIES. The raw matched value is NEVER returned: only a partially-
    masked representation and a SHA-256 fingerprint (for downstream exact-
    match correlation without re-exposing the value).
    """
    if not body:
        return []
    merged: Dict[Any, Dict[str, Any]] = {}
    for pat in JS_SECRET_PATTERNS:
        for m in pat["regex"].finditer(body):
            group_idx = pat["value_group"]
            try:
                value = m.group(group_idx) if group_idx else m.group(0)
            except IndexError:
                continue
            if not value:
                continue
            fingerprint = _fingerprint(value)
            key = (pat["name"], fingerprint)
            entry = merged.get(key)
            if entry is not None:
                # The same value matched by the same pattern is one indicator,
                # however many times a bundle repeats it (context.md §7). The
                # first occurrence's context is kept as the evidence excerpt.
                entry["occurrences"] += 1
                continue
            redacted = _redact_secret(value)
            note = None
            if pat["confidence"] != CONFIDENCE_HIGH:
                note = "Generic keyword/pattern-based match; elevated false-positive risk. Verify manually before acting on it."
            start, end = m.span(group_idx) if group_idx else m.span(0)
            merged[key] = {
                "category": pat["category"], "pattern_name": pat["name"], "confidence": pat["confidence"],
                "redacted_value": redacted, "fingerprint_sha256": fingerprint, "occurrences": 1,
                "context": _context_snippet(body, start, end, redacted), "note": note,
            }
    return list(merged.values())


# ---------------------------------------------------------------------------
# 2e / 6. WebSocket endpoint detection (mirrors crawler.py's
# detect_websocket_indicators, duplicated per modular independence)
# ---------------------------------------------------------------------------

_WS_LITERAL_RE = re.compile(r"""wss?://[^\s'"<>\\]+""", re.IGNORECASE)
_WS_CTOR_RE = re.compile(r"new\s+WebSocket\s*\(", re.IGNORECASE)


def detect_websocket_references(
    body: str, js_url: str, target: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Detect ws(s):// literals and bare `new WebSocket(...)` constructor calls
    (responsibility #6).

    Each literal carries `in_scope`, because a script routinely references a
    third-party realtime service (a chat widget, an analytics socket) and
    attributing that endpoint to the target would be a correlation error. Both
    are still recorded — an out-of-scope reference is real intelligence about
    the page's dependencies (context.md §12.11: never silently discarded) — but
    only in-scope endpoints are presented as the target's own attack surface.
    """
    if not body:
        return []
    effective_target = target or (urllib.parse.urlsplit(js_url).hostname or "")
    out: List[Dict[str, Any]] = []
    literal_matches = sorted(set(m.rstrip(").,;'\"`") for m in _WS_LITERAL_RE.findall(body)))
    for endpoint in literal_matches:
        clean = _strip_userinfo(endpoint)
        try:
            host = urllib.parse.urlsplit(clean).hostname or ""
        except ValueError:
            host = ""
        in_scope = _in_scope_host(host, effective_target)
        evidence = [f"Literal WebSocket URL found in JS from {js_url}: {clean}"]
        if not in_scope:
            evidence.append(
                f"WebSocket host {host!r} is outside the scope of {effective_target!r} — recorded as a "
                f"third-party realtime dependency, not as the target's own endpoint"
            )
        out.append({
            "endpoint": clean, "in_scope": in_scope,
            "confidence": CONFIDENCE_HIGH if in_scope else CONFIDENCE_MEDIUM,
            "evidence": evidence,
        })
    if not literal_matches and _WS_CTOR_RE.search(body):
        out.append({
            "endpoint": None, "in_scope": False, "confidence": CONFIDENCE_LOW,
            "evidence": [f"`new WebSocket(...)` constructor call found in JS from {js_url} without a literal "
                         f"endpoint URL (likely constructed dynamically at runtime)"],
        })
    return out


# ---------------------------------------------------------------------------
# 3. Source maps
# ---------------------------------------------------------------------------

_SOURCEMAP_LINE_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_SOURCEMAP_BLOCK_RE = re.compile(r"/\*[#@]\s*sourceMappingURL=([^\s*]+)\s*\*/")
# A captured reference picks up the delimiter of the string it was quoted in.
# A `data:` source map legitimately contains commas and semicolons, so those are
# only trimmed off a normal URL reference.
_SOURCEMAP_TRAILING = "\"'`)"
_SOURCEMAP_TRAILING_URL = "\"'`);,"


def _display_url(url: Optional[str], limit: int = 200) -> Optional[str]:
    """
    A form of `url` that is safe to persist.

    An inline `data:` source map is the whole map — routinely megabytes — and
    writing it into pending_assets.json as an identifier bloats a file every
    other module reads. Its shape is recorded instead of its payload.
    """
    if not url:
        return url
    if url.startswith("data:"):
        head, _, payload = url.partition(",")
        return f"{head},<inline source map, {len(payload)} bytes>"
    return _truncate(url, limit)


def detect_source_map_reference(body: str, js_url: str, try_implicit_sibling: bool = True) -> Dict[str, Any]:
    """
    Detect a `.js.map` reference (responsibility #3, detection). An
    explicit `//# sourceMappingURL=` (or block-comment equivalent) comment
    is trusted directly; otherwise, if `try_implicit_sibling`, the
    conventional `<url>.map` sibling is offered as an unconfirmed guess
    (see module docstring, decision #3 — it is only ever persisted as a
    finding once confirmed by an actual fetch).
    """
    if body:
        # The LAST reference wins, per the Source Map v3 convention: a bundle
        # that concatenates dependencies routinely carries an earlier
        # sourceMappingURL inside a string literal, and taking the first match
        # followed a decoy instead of the bundle's own map.
        candidates = list(_SOURCEMAP_LINE_RE.finditer(body)) + list(_SOURCEMAP_BLOCK_RE.finditer(body))
        if candidates:
            m = max(candidates, key=lambda match: match.start())
            raw = m.group(1).strip()
            raw = raw.rstrip(_SOURCEMAP_TRAILING if raw.startswith("data:")
                             else _SOURCEMAP_TRAILING_URL)
            resolved = None
            if raw:
                if raw.startswith("data:"):
                    resolved = raw           # inline map: nothing to resolve against
                else:
                    try:
                        resolved = urllib.parse.urljoin(js_url, raw)
                    except ValueError:
                        resolved = None
            if resolved:
                return {
                    "status": "explicit", "map_url": resolved, "raw": _display_url(raw),
                    "evidence": [f"sourceMappingURL comment found in {js_url}: {_display_url(raw)!r}"],
                }
    if try_implicit_sibling:
        # Built from the PATH, not the whole URL: appending to a URL carrying a
        # cache-busting query or a fragment produced nonsense such as
        # "app.js?v=9f2a1&x=1.map".
        try:
            parts = urllib.parse.urlsplit(js_url)
            implicit = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path + ".map", "", ""))
        except ValueError:
            implicit = js_url + ".map"
        return {
            "status": "implicit_guess", "map_url": implicit, "raw": None,
            "evidence": [f"No explicit sourceMappingURL comment in {js_url}; probing the conventional "
                         f"sibling {implicit!r} (unconfirmed until fetched)"],
        }
    return {"status": "not_found", "map_url": None, "raw": None, "evidence": []}


def _decode_inline_source_map(uri: str) -> Dict[str, Any]:
    """
    Decode an inline `data:` source map without any network request.

    `//# sourceMappingURL=data:application/json;base64,...` is what most dev
    and many production builds emit, and it is the one case where the map is
    already in hand. Previously it was handed to the URL validator, rejected as
    a non-http scheme, and reported as "out_of_scope" — a real capability gap
    reported as a scope decision. Reading it is strictly local: no request is
    issued, so no scope boundary is involved.
    """
    header, _, payload = uri.partition(",")
    if not payload:
        return {"status": "error", "error": "inline source map has no payload", "status_code": None}
    if len(payload) > DEFAULT_MAX_SOURCE_MAP_BYTES:
        return {"status": "error", "status_code": None,
                "error": f"inline source map exceeds {DEFAULT_MAX_SOURCE_MAP_BYTES} bytes"}
    try:
        if ";base64" in header.lower():
            raw = base64.b64decode(payload, validate=False)
            text = raw.decode("utf-8", errors="replace")
        else:
            text = urllib.parse.unquote(payload)
    except (ValueError, binascii.Error) as exc:
        return {"status": "error", "error": f"inline source map could not be decoded: {exc}",
                "status_code": None}
    return {"status": "found", "status_code": 200, "headers": {}, "body": text,
            "body_truncated": False, "final_url": _display_url(uri), "error": None}


def fetch_source_map(map_url: str, target: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Retrieve a source map (responsibility #3, retrieval) — scope-enforced
    exactly like any other fetch. An inline `data:` map is decoded locally
    instead (no request is made).
    """
    if isinstance(map_url, str) and map_url.startswith("data:"):
        return _decode_inline_source_map(map_url)
    try:
        validated = validate_url_target(map_url, target=target)
    except ScopeError as exc:
        return {"status": "out_of_scope", "error": str(exc), "status_code": None}
    return fetch_url(validated, timeout=timeout, max_body_bytes=DEFAULT_MAX_SOURCE_MAP_BYTES)


def parse_source_map(raw_text: Optional[str]) -> Dict[str, Any]:
    """
    Safely parse a source map (responsibility #3, safe parsing). Never
    raises: malformed/empty/non-object input degrades to a `status`
    describing the problem, so a scan is never terminated by a bad map.
    """
    if not raw_text or not raw_text.strip():
        return {"status": "empty", "error": "empty source map body"}
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        return {"status": "malformed", "error": f"invalid JSON: {exc}"}
    except RecursionError:
        # A source map nested thousands of levels deep exhausts the JSON
        # scanner's stack. RecursionError is a RuntimeError, not a ValueError,
        # so it escaped this function, escaped process_source_map, and aborted
        # the whole run from one hostile or corrupt .js.map — contradicting
        # this function's own "never raises" contract and context.md §12.11.
        return {"status": "malformed", "error": "source map nesting is too deep to parse safely"}
    if not isinstance(data, dict):
        return {"status": "malformed", "error": "source map root is not a JSON object"}

    sources = data.get("sources") if isinstance(data.get("sources"), list) else []
    sources_content = data.get("sourcesContent") if isinstance(data.get("sourcesContent"), list) else []
    names = data.get("names") if isinstance(data.get("names"), list) else []
    is_index_map = False

    # Source Map v3 "index maps" carry no top-level `sources`; the real content
    # sits in `sections[].map`. Without this an index map parsed "successfully"
    # with zero sources and reconstructed nothing, silently losing every
    # original file it actually contained. Sections are flattened in order;
    # `sourcesContent` is padded so index alignment with `sources` holds.
    if not sources and isinstance(data.get("sections"), list):
        is_index_map = True
        for section in data["sections"]:
            if not isinstance(section, dict):
                continue
            sub = section.get("map")
            if not isinstance(sub, dict):
                continue
            sub_sources = sub.get("sources") if isinstance(sub.get("sources"), list) else []
            sub_content = sub.get("sourcesContent") if isinstance(sub.get("sourcesContent"), list) else []
            for idx, name in enumerate(sub_sources):
                if not isinstance(name, str):
                    continue
                sources.append(name)
                sources_content.append(sub_content[idx] if idx < len(sub_content) else None)
            if isinstance(sub.get("names"), list):
                names = list(names) + sub["names"]

    return {
        "status": "parsed",
        "version": data.get("version"),
        "file": data.get("file"),
        "is_index_map": is_index_map,
        "sources": [s for s in sources if isinstance(s, str)],
        "sources_content": sources_content,
        "sources_content_available": any(isinstance(c, str) and c.strip() for c in sources_content),
        "names_count": len(names),
        "has_mappings": bool(data.get("mappings")) or is_index_map,
    }


def reconstruct_original_sources(parsed_map: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Reconstruct original source files from an already-parsed source map's
    embedded `sourcesContent` (responsibility #3, reconstruction — see
    module docstring, decision #2 for the documented VLQ-`mappings`
    limitation). Returns [] for a map with no embedded content, or one
    that failed to parse.
    """
    if parsed_map.get("status") != "parsed":
        return []
    sources = parsed_map.get("sources") or []
    contents = parsed_map.get("sources_content") or []
    out: List[Dict[str, str]] = []
    for idx, name in enumerate(sources):
        content = contents[idx] if idx < len(contents) else None
        if isinstance(content, str) and content.strip():
            out.append({"source": name, "content": content})
    return out


# ---------------------------------------------------------------------------
# 4a. Client-side sources / sinks / possible data flows (proximity
# heuristic ONLY — see module docstring, SECURITY BOUNDARIES)
# ---------------------------------------------------------------------------

_SOURCE_PATTERNS = {
    "location.hash": re.compile(r"\blocation\.hash\b"),
    "location.search": re.compile(r"\blocation\.search\b"),
    "document.URL": re.compile(r"\bdocument\.URL\b"),
    "document.referrer": re.compile(r"\bdocument\.referrer\b"),
    "window.name": re.compile(r"\bwindow\.name\b"),
    "URLSearchParams": re.compile(r"\bnew\s+URLSearchParams\s*\("),
}
_SINK_PATTERNS = {
    "innerHTML": re.compile(r"\.innerHTML\s*="),
    "outerHTML": re.compile(r"\.outerHTML\s*="),
    "document.write": re.compile(r"\bdocument\.write(?:ln)?\s*\("),
    "eval": re.compile(r"\beval\s*\("),
    "Function_constructor": re.compile(r"\bnew\s+Function\s*\("),
    "insertAdjacentHTML": re.compile(r"\.insertAdjacentHTML\s*\("),
    "setTimeout_string_arg": re.compile(r"\bsetTimeout\s*\(\s*[\"']"),
    "dangerouslySetInnerHTML": re.compile(r"\bdangerouslySetInnerHTML\b"),
}


class _LineIndex:
    """
    One-pass line lookup for a script body.

    The previous implementation called `body.splitlines()` once per matched
    pattern to build the evidence excerpt, which is O(len(body)) per match and
    turns a bundle with a few hundred matches into hundreds of megabytes of
    copying. The offsets are computed once here and every lookup is a binary
    search. Line numbers are 1-based, as a human reading the evidence expects
    (the previous 0-based value was reported as "line 0" for everything in a
    minified single-line bundle).
    """

    __slots__ = ("_body", "_starts", "_lines")

    def __init__(self, body: str):
        self._body = body
        starts = [0]
        idx = body.find("\n")
        while idx != -1:
            starts.append(idx + 1)
            idx = body.find("\n", idx + 1)
        self._starts = starts
        self._lines: Optional[List[str]] = None

    def line_of(self, index: int) -> int:
        return bisect.bisect_right(self._starts, index)

    def text_of(self, line_no: int) -> str:
        if self._lines is None:
            self._lines = self._body.splitlines()
        pos = line_no - 1
        return self._lines[pos] if 0 <= pos < len(self._lines) else ""


def _line_number_at(body: str, index: int) -> int:
    """1-based line number of `index` within `body`."""
    return body.count("\n", 0, index) + 1


def _line_text(body: str, line_no: int) -> str:
    """Text of 1-based line `line_no`."""
    lines = body.splitlines()
    pos = line_no - 1
    return lines[pos] if 0 <= pos < len(lines) else ""


# A source and a sink are treated as "textually adjacent" only when they are
# within this many characters of each other as well as within
# _FLOW_LINE_WINDOW lines. The line test alone is meaningless for the minified
# bundles this module mostly sees: a whole bundle is one line, so every source
# paired with every sink (reproduced: a 9.9KB minified snippet produced 102,400
# "possible data flows", growing quadratically — a 200KB bundle did not finish
# in 10 minutes). For ordinary pretty-printed code two lines apart is almost
# always well under this window, so the previous behaviour is preserved there.
_FLOW_CHAR_WINDOW = 400
_FLOW_LINE_WINDOW = 2


def extract_client_side_signals(body: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract client-side sources/sinks and a PROXIMITY-HEURISTIC "possible
    data flow" observation (responsibility #4). Never claims an
    exploitable vulnerability from a source/sink/flow's presence alone —
    every possible-data-flow entry is explicitly labeled unverified.

    Identical observations are merged rather than duplicated (context.md §7:
    "Independent discoveries describing the same underlying asset must be
    merged, not duplicated"), carrying an `occurrences` count instead of
    emitting one finding per textual repetition: a source or sink is
    identified by (kind, line), a possible data flow by (source_kind,
    sink_kind). Without this a minified bundle persists tens of thousands of
    byte-identical findings, each of which rewrites pending_assets.json in
    full.
    """
    if not body:
        return {"sources": [], "sinks": [], "possible_data_flows": []}

    index = _LineIndex(body)

    # (char_index, role, kind) for every match, in one pass per pattern.
    raw: List["tuple[int, str, str]"] = []
    for name, pattern in _SOURCE_PATTERNS.items():
        raw.extend((m.start(), "source", name) for m in pattern.finditer(body))
    for name, pattern in _SINK_PATTERNS.items():
        raw.extend((m.start(), "sink", name) for m in pattern.finditer(body))
    if not raw:
        return {"sources": [], "sinks": [], "possible_data_flows": []}

    raw.sort()

    sources: Dict[Any, Dict[str, Any]] = {}
    sinks: Dict[Any, Dict[str, Any]] = {}
    entries: List[Dict[str, Any]] = []
    for char_index, role, kind in raw:
        line_no = index.line_of(char_index)
        entries.append({"index": char_index, "line": line_no, "role": role, "kind": kind})
        bucket = sources if role == "source" else sinks
        key = (kind, line_no)
        existing = bucket.get(key)
        if existing is not None:
            existing["occurrences"] += 1
            continue
        label = "Source" if role == "source" else "Sink"
        bucket[key] = {
            "kind": kind, "line": line_no, "occurrences": 1,
            # The excerpt is raw source, and on a minified bundle "the line" is
            # the whole file — so a hard-coded credential a few characters away
            # from a sink landed verbatim in pending_assets.json even though
            # extract_secret_indicators had carefully redacted the same value.
            "evidence": f"{label} pattern {kind!r} found near: "
                        f"{_mask_residual_secrets(_truncate(index.text_of(line_no), 160))!r}",
        }

    # Sweep for textually adjacent source/sink pairs. Because the emitted set
    # is keyed on (source_kind, sink_kind), a repeated pair only increments a
    # counter, and the scan stops as soon as it leaves the window — so neither
    # the work nor the output grows quadratically with the match count.
    flows: Dict[Any, Dict[str, Any]] = {}

    def _consider(src: Dict[str, Any], snk: Dict[str, Any]) -> None:
        key = (src["kind"], snk["kind"])
        existing = flows.get(key)
        if existing is not None:
            existing["occurrences"] += 1
            return
        line_distance = abs(src["line"] - snk["line"])
        char_distance = abs(src["index"] - snk["index"])
        flows[key] = {
            "source_kind": src["kind"], "sink_kind": snk["kind"],
            "source_line": src["line"], "sink_line": snk["line"],
            "occurrences": 1,
            "evidence": [
                f"Source {src['kind']!r} (line {src['line']}) and sink {snk['kind']!r} "
                f"(line {snk['line']}) appear within {line_distance} line(s) and "
                f"{char_distance} character(s) of each other in the (often minified) script — "
                f"PROXIMITY HEURISTIC ONLY, not a verified taint/data-flow analysis; requires manual review "
                f"before treating this as an actual data-flow relationship."
            ],
        }

    def _in_window(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
        return (abs(a["line"] - b["line"]) <= _FLOW_LINE_WINDOW
                and abs(a["index"] - b["index"]) <= _FLOW_CHAR_WINDOW)

    total = len(entries)
    for i, entry in enumerate(entries):
        if entry["role"] != "source":
            continue
        for j in range(i - 1, -1, -1):
            other = entries[j]
            if entry["index"] - other["index"] > _FLOW_CHAR_WINDOW:
                break
            if other["role"] == "sink" and _in_window(entry, other):
                _consider(entry, other)
        for j in range(i + 1, total):
            other = entries[j]
            if other["index"] - entry["index"] > _FLOW_CHAR_WINDOW:
                break
            if other["role"] == "sink" and _in_window(entry, other):
                _consider(entry, other)

    return {
        "sources": sorted(sources.values(), key=lambda r: (r["line"], r["kind"])),
        "sinks": sorted(sinks.values(), key=lambda r: (r["line"], r["kind"])),
        "possible_data_flows": sorted(
            flows.values(), key=lambda r: (r["source_kind"], r["sink_kind"])
        ),
    }


# ---------------------------------------------------------------------------
# 4b. postMessage
# ---------------------------------------------------------------------------

_POSTMESSAGE_LISTENER_RE = re.compile(r'addEventListener\s*\(\s*["\']message["\']', re.IGNORECASE)
_POSTMESSAGE_SEND_RE = re.compile(r"\.postMessage\s*\(", re.IGNORECASE)
_ORIGIN_CHECK_RE = re.compile(r"\.origin\s*(?:===|==|!==|!=)", re.IGNORECASE)


def extract_postmessage_signals(body: str, lookahead_window: int = 400) -> Dict[str, List[Dict[str, Any]]]:
    """
    Detect `window.addEventListener('message', ...)` receivers and
    `.postMessage(...)` senders (responsibility #4). For each listener, a
    nearby (best-effort, textual) origin-check is noted as an OBSERVATION
    only — its absence is not itself claimed as a vulnerability.
    """
    if not body:
        return {"listeners": [], "sends": []}

    index = _LineIndex(body)

    # Keyed on source location so the same receiver/sender is one observation
    # (context.md §7); a bundle that repeats `.postMessage(` a thousand times
    # previously produced a thousand byte-identical findings carrying no
    # distinguishing information at all.
    listeners: Dict[Any, Dict[str, Any]] = {}
    for m in _POSTMESSAGE_LISTENER_RE.finditer(body):
        window_text = body[m.end(): m.end() + lookahead_window]
        has_origin_check = bool(_ORIGIN_CHECK_RE.search(window_text))
        line_no = index.line_of(m.start())
        key = (line_no, has_origin_check)
        entry = listeners.get(key)
        if entry is not None:
            entry["occurrences"] += 1
            continue
        listeners[key] = {
            "origin_check_observed": has_origin_check, "line": line_no, "occurrences": 1,
            "evidence": [
                "addEventListener('message', ...) found"
                + (" with a nearby origin check" if has_origin_check else
                   " with no nearby origin check observed (textual heuristic only — not a confirmed absence)")
            ],
        }

    sends: Dict[Any, Dict[str, Any]] = {}
    for m in _POSTMESSAGE_SEND_RE.finditer(body):
        line_no = index.line_of(m.start())
        entry = sends.get(line_no)
        if entry is not None:
            entry["occurrences"] += 1
            continue
        sends[line_no] = {
            "line": line_no, "occurrences": 1, "evidence": [".postMessage(...) call found"],
        }

    return {
        "listeners": sorted(listeners.values(), key=lambda r: r["line"]),
        "sends": sorted(sends.values(), key=lambda r: r["line"]),
    }


# ---------------------------------------------------------------------------
# 4c. localStorage
# ---------------------------------------------------------------------------

_LOCALSTORAGE_RE = re.compile(r'\blocalStorage\.(getItem|setItem|removeItem)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)


def extract_localstorage_signals(body: str) -> List[Dict[str, Any]]:
    """Detect literal-keyed localStorage access (responsibility #4)."""
    if not body:
        return []
    merged: Dict[Any, Dict[str, Any]] = {}
    for m in _LOCALSTORAGE_RE.finditer(body):
        method, key = m.group(1), m.group(2)
        entry = merged.get((method, key))
        if entry is not None:
            entry["occurrences"] += 1
            continue
        merged[(method, key)] = {
            "method": method, "key": key, "occurrences": 1,
            "evidence": [f"localStorage.{method}({key!r}) call found"],
        }
    return list(merged.values())


# ---------------------------------------------------------------------------
# Body-parameter hints (supports responsibility #5's `parameters` field —
# see module docstring, decision #4 for its documented, honest limitation)
# ---------------------------------------------------------------------------

_FETCH_BODY_RE = re.compile(r"JSON\.stringify\(\s*\{([^}]{0,500})\}", re.IGNORECASE)
# Anchored on an object-literal boundary (start of the literal, or a comma), so
# a colon appearing *inside a string value* is not read as a key. Without the
# anchor, `{url:"https://x"}` yielded a phantom parameter named "https", and
# `{"x-api-key":k}` yielded "key". Hyphens are allowed inside a key so
# hyphenated header-style keys are captured whole rather than clipped.
_OBJECT_KEY_RE = re.compile(r'(?:^|[,{])\s*["\']?([A-Za-z_][A-Za-z0-9_-]*)["\']?\s*:')


def extract_body_parameter_hints(body: str) -> List[Dict[str, Any]]:
    """
    Best-effort, file-wide extraction of likely request-body parameter
    names from `JSON.stringify({...})` object literals. See module
    docstring, decision #4: this cannot be reliably tied to one specific
    endpoint without a real parser, so results are file-wide, not
    per-endpoint.
    """
    if not body:
        return []
    out: List[Dict[str, Any]] = []
    seen = set()
    for m in _FETCH_BODY_RE.finditer(body):
        for key in _OBJECT_KEY_RE.findall(m.group(1)):
            if key in seen:
                continue
            seen.add(key)
            out.append({"name": key, "location": "body", "method": "POST", "data_type": "unknown"})
    return out


# ---------------------------------------------------------------------------
# Single-file analysis (bundles responsibilities #2/#4/#6 — independently
# testable per the assignment's TESTING list)
# ---------------------------------------------------------------------------

def analyze_javascript_content(body: Optional[str], js_url: str, target: Optional[str] = None) -> Dict[str, Any]:
    """Run every content-analysis responsibility against one already-fetched script body."""
    body = body or ""
    return {
        "js_url": js_url,
        "api_references": extract_api_references(body, js_url, target),
        "external_services": extract_external_service_references(body, js_url, target),
        "config_values": extract_config_values(body),
        "secret_indicators": extract_secret_indicators(body),
        "websocket_references": detect_websocket_references(body, js_url, target),
        "client_side_signals": extract_client_side_signals(body),
        "postmessage_signals": extract_postmessage_signals(body),
        "localstorage_signals": extract_localstorage_signals(body),
        "body_parameter_hints": extract_body_parameter_hints(body),
    }


# ---------------------------------------------------------------------------
# Persistence + API correlation output (responsibility #5 — see module
# docstring, NO-CROSS-MODULE-CALLS PRECEDENT item (b))
# ---------------------------------------------------------------------------

def build_endpoint_discovery_js_data(
    api_references: List[Dict[str, Any]], body_parameter_hints: List[Dict[str, Any]], parent_js_url: str,
) -> List[Dict[str, Any]]:
    """
    Normalize extracted API references into the EXACT shape
    endpoint_discovery.py's `correlate_javascript_parameters` already
    documents as its expected `js_data` input:
    `{"url":, "parameters": [...], "evidence": [...], "source_file":}`.
    """
    out: List[Dict[str, Any]] = []
    for ref in api_references:
        params: List[Dict[str, Any]] = []
        query = urllib.parse.urlsplit(ref["url"]).query
        for name, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
            params.append({"name": name, "location": "query", "method": "GET", "data_type": _infer_data_type(value)})

        evidence = list(ref["evidence"])
        if body_parameter_hints:
            evidence.append(
                "Additional body-parameter hints observed file-wide in this script "
                "(not confirmed specific to this endpoint) — see corresponding js_analyzer_endpoint_reference finding."
            )
            params.extend(
                {"name": h["name"], "location": h["location"], "method": h["method"], "data_type": h["data_type"]}
                for h in body_parameter_hints
            )

        out.append({"url": ref["url"], "parameters": params, "evidence": evidence, "source_file": parent_js_url})
    return out


def persist_analysis_findings(
    analysis: Dict[str, Any],
    target: str,
    store: Optional[PendingAssetsStore],
    parent_js_url: str,
    source_page: Optional[str] = None,
    derived_from_source_map: bool = False,
    original_source_file: Optional[str] = None,
    defer_to: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Persist every finding produced by `analyze_javascript_content` for one
    analyzed unit (a fetched JS file, or one reconstructed original
    source), and assemble the `js_data`/`websocket_endpoints` accumulators
    `run_js_analyzer` aggregates across the whole run.

    `defer_to`, when supplied, collects this unit's findings into the caller's
    list instead of writing them, so a caller that analyses many units in a row
    can commit them in one atomic write. process_source_map needs this: a map
    embedding 5000 original sources otherwise performed 5000 separate
    full-file rewrites (measured: 116s for one such map).
    """
    errors: List[str] = []
    counts: Dict[str, int] = {}
    websocket_endpoints: List[Dict[str, Any]] = []
    # Collected and written in one atomic batch at the end of this analysed
    # unit rather than one full-file rewrite per finding — see
    # PendingAssetsStore.add_many. "Persist immediately" is preserved at the
    # granularity of an analysed unit (one script, or one reconstructed
    # original source), which is exactly endpoint_discovery.py's per-probe
    # granularity.
    batch: List[Dict[str, Any]] = []

    def _add(finding_type: str, value: Any, evidence: List[str], confidence: str,
              extra_metadata: Optional[Dict[str, Any]] = None) -> None:
        batch.append(make_js_finding(
            finding_type, target, value, evidence, confidence, parent_js_url=parent_js_url,
            source_page=source_page, derived_from_source_map=derived_from_source_map,
            original_source_file=original_source_file, extra_metadata=extra_metadata,
        ))

    api_refs = analysis["api_references"]
    counts["api_references"] = len(api_refs)
    for ref in api_refs:
        floor = CONFIDENCE_MEDIUM if any("call target" in e for e in ref["evidence"]) else CONFIDENCE_LOW
        confidence = _confidence_from_count(len(ref["evidence"]), floor=floor)
        _add("js_analyzer_endpoint_reference",
             {"url": ref["url"], "kind": ref["kind"], "raw": ref["raw"], "occurrences": ref["occurrences"]},
             ref["evidence"], confidence)

    ext = analysis["external_services"]
    counts["external_services"] = len(ext)
    for e in ext:
        confidence = _confidence_from_count(len(e["evidence"]), floor=CONFIDENCE_MEDIUM)
        _add("js_analyzer_external_service_reference",
             {"vendor": e["vendor"], "category": e["category"], "host": e["host"],
              "example_url": e["example_url"], "occurrences": e["occurrences"]},
             e["evidence"], confidence)

    cfg = analysis["config_values"]
    counts["config_values"] = len(cfg)
    for c in cfg:
        _add("js_analyzer_config_value",
             {"key": c["key"], "value": c["value"], "occurrences": c["occurrences"]},
             c["evidence"], c["confidence"])

    secrets = analysis["secret_indicators"]
    counts["secret_indicators"] = len(secrets)
    for s in secrets:
        evidence = [f"JS secret-pattern match ({s['pattern_name']}, category={s['category']}): {s['context']!r}"]
        if s.get("note"):
            evidence.append(s["note"])
        _add("js_analyzer_secret_indicator", {
            "category": s["category"], "pattern_name": s["pattern_name"], "redacted_value": s["redacted_value"],
            "fingerprint_sha256": s["fingerprint_sha256"], "context": s["context"],
            "occurrences": s["occurrences"],
        }, evidence, s["confidence"])

    ws = analysis["websocket_references"]
    counts["websocket_references"] = len(ws)
    for w in ws:
        _add("js_analyzer_websocket_endpoint",
             {"endpoint": w["endpoint"], "in_scope": w["in_scope"]},
             w["evidence"], w["confidence"])
        if w["endpoint"]:
            websocket_endpoints.append({
                "endpoint": w["endpoint"], "in_scope": w["in_scope"],
                "source_file": parent_js_url, "evidence": w["evidence"],
            })

    sig = analysis["client_side_signals"]
    counts["client_side_signals"] = len(sig["sources"]) + len(sig["sinks"]) + len(sig["possible_data_flows"])
    for s in sig["sources"]:
        _add("js_analyzer_client_side_signal",
             {"signal_category": "source", "kind": s["kind"], "line": s["line"],
              "occurrences": s["occurrences"]},
             [s["evidence"]], CONFIDENCE_MEDIUM)
    for k in sig["sinks"]:
        _add("js_analyzer_client_side_signal",
             {"signal_category": "sink", "kind": k["kind"], "line": k["line"],
              "occurrences": k["occurrences"]},
             [k["evidence"]], CONFIDENCE_MEDIUM)
    for f in sig["possible_data_flows"]:
        _add("js_analyzer_client_side_signal", {
            "signal_category": "possible_data_flow", "source_kind": f["source_kind"], "sink_kind": f["sink_kind"],
            "source_line": f["source_line"], "sink_line": f["sink_line"], "occurrences": f["occurrences"],
        }, f["evidence"], CONFIDENCE_LOW)

    pm = analysis["postmessage_signals"]
    counts["postmessage_signals"] = len(pm["listeners"]) + len(pm["sends"])
    for listener in pm["listeners"]:
        _add("js_analyzer_client_side_signal",
             {"signal_category": "postmessage_listener",
              "origin_check_observed": listener["origin_check_observed"],
              "line": listener["line"], "occurrences": listener["occurrences"]},
             listener["evidence"], CONFIDENCE_MEDIUM)
    for send in pm["sends"]:
        _add("js_analyzer_client_side_signal",
             {"signal_category": "postmessage_send", "line": send["line"],
              "occurrences": send["occurrences"]},
             send["evidence"], CONFIDENCE_MEDIUM)

    ls = analysis["localstorage_signals"]
    counts["localstorage_signals"] = len(ls)
    for entry in ls:
        _add("js_analyzer_client_side_signal",
             {"signal_category": "localstorage_access", "method": entry["method"], "key": entry["key"],
              "occurrences": entry["occurrences"]},
             entry["evidence"], CONFIDENCE_MEDIUM)

    if defer_to is None:
        err = _safe_store_add_many(store, batch)
        if err:
            errors.append(err)
    else:
        defer_to.extend(batch)

    js_data = build_endpoint_discovery_js_data(api_refs, analysis["body_parameter_hints"], parent_js_url)

    return {
        "counts": counts, "total": sum(counts.values()), "errors": errors,
        "js_data": js_data, "websocket_endpoints": websocket_endpoints,
    }


# ---------------------------------------------------------------------------
# Source-map orchestration for one already-fetched file (responsibility #3,
# end to end — never terminates the caller's per-file loop on failure)
# ---------------------------------------------------------------------------

def process_source_map(
    body: str,
    js_url: str,
    target: Optional[str],
    target_effective: str,
    source_page: Optional[str],
    store: Optional[PendingAssetsStore],
    retrieve_source_maps: bool,
    analyze_reconstructed_sources: bool,
    try_implicit_sibling: bool,
    timeout: float,
) -> Dict[str, Any]:
    """
    Detect -> (optionally) retrieve -> parse -> reconstruct -> (optionally)
    recursively analyze reconstructed sources, for one already-fetched JS
    file. Malformed/missing source maps degrade to a recorded outcome,
    never an exception.
    """
    result: Dict[str, Any] = {"info": None, "js_data": [], "websocket_endpoints": [], "errors": []}
    if not retrieve_source_maps and not try_implicit_sibling:
        return result

    ref_info = detect_source_map_reference(body, js_url, try_implicit_sibling=try_implicit_sibling)
    if not ref_info.get("map_url"):
        return result

    info: Dict[str, Any] = {
        "reference_type": ref_info["status"], "map_url": _display_url(ref_info["map_url"]),
        "fetch_status": "not_attempted", "parse_status": None, "reconstructed_sources": [],
    }
    result["info"] = info

    if not retrieve_source_maps:
        if ref_info["status"] == "explicit":
            err = _safe_store_add(store, make_js_finding(
                "js_analyzer_source_map_reference", target_effective,
                {"js_url": js_url, "map_url": _display_url(ref_info["map_url"]),
                 "reference_type": "explicit", "fetch_status": "not_attempted"},
                ref_info["evidence"], CONFIDENCE_HIGH, parent_js_url=js_url, source_page=source_page,
            ))
            if err:
                result["errors"].append(err)
        return result

    # Scope for the map fetch falls back to the script's OWN host when no
    # logical target was supplied. With target=None, validate_url_target
    # performs no domain check at all, so an explicit
    # `sourceMappingURL=https://attacker.example/app.js.map` was fetched from a
    # third-party host — contradicting this module's SECURITY BOUNDARIES
    # ("never issues a request to any out-of-scope host, including a source map
    # hosted on a third-party CDN"). A script's own origin is the implicit
    # scope, exactly as extract_api_references already treats it.
    map_scope = target or (urllib.parse.urlsplit(js_url).hostname or None)
    map_resp = fetch_source_map(ref_info["map_url"], target=map_scope, timeout=timeout)
    info["fetch_status"] = map_resp.get("status")
    info["status_code"] = map_resp.get("status_code")

    fetched_ok = (
        map_resp.get("status") == "found"
        and map_resp.get("status_code") is not None
        and 200 <= map_resp["status_code"] < 300
    )
    if not fetched_ok:
        if ref_info["status"] == "explicit":
            err = _safe_store_add(store, make_js_finding(
                "js_analyzer_source_map_reference", target_effective,
                {"js_url": js_url, "map_url": _display_url(ref_info["map_url"]), "reference_type": "explicit",
                 "fetch_status": map_resp.get("status"), "status_code": map_resp.get("status_code")},
                ref_info["evidence"] + [
                    f"Source map retrieval did not succeed (status={map_resp.get('status')}, "
                    f"http_status={map_resp.get('status_code')}, error={map_resp.get('error')})"
                ],
                CONFIDENCE_HIGH, parent_js_url=js_url, source_page=source_page,
            ))
            if err:
                result["errors"].append(err)
        # An unconfirmed implicit guess that doesn't pan out is not recorded
        # (module docstring, decision #3) — avoids noise, not a silent drop
        # of real evidence (nothing was actually discovered).
        return result

    parsed = parse_source_map(map_resp.get("body"))
    info["parse_status"] = parsed.get("status")
    sm_confidence = (
        CONFIDENCE_HIGH if ref_info["status"] == "explicit"
        else (CONFIDENCE_MEDIUM if parsed.get("status") == "parsed" else CONFIDENCE_LOW)
    )
    # Everything produced from this one map is written in a single atomic
    # batch: a map embedding thousands of original sources otherwise performed
    # one full-file rewrite per source (see PendingAssetsStore.add_many).
    pending: List[Dict[str, Any]] = [make_js_finding(
        "js_analyzer_source_map_reference", target_effective,
        {"js_url": js_url, "map_url": _display_url(ref_info["map_url"]), "reference_type": ref_info["status"],
         "fetch_status": "found", "parse_status": parsed.get("status"),
         "inline": ref_info["map_url"].startswith("data:"), "is_index_map": parsed.get("is_index_map", False)},
        ref_info["evidence"] + [
            f"Source map fetched; parse status: {parsed.get('status')}"
            + (f" ({parsed['error']})" if parsed.get("error") else "")
        ],
        sm_confidence, parent_js_url=js_url, source_page=source_page,
    )]

    def _flush() -> None:
        err = _safe_store_add_many(store, pending)
        if err:
            result["errors"].append(err)
        pending.clear()

    if parsed.get("status") != "parsed":
        _flush()
        return result

    for rec in reconstruct_original_sources(parsed):
        # An original source recovered from a source map is exactly where a
        # hard-coded credential lives; the preview is redacted for the same
        # reason every other excerpt in this module is.
        preview = _mask_residual_secrets(_truncate(rec["content"], 500))
        pending.append(make_js_finding(
            "js_analyzer_reconstructed_source", target_effective,
            {"js_url": js_url, "map_url": _display_url(ref_info["map_url"]), "original_source": rec["source"],
             "content_preview": preview, "content_length": len(rec["content"])},
            [f"Reconstructed original source {rec['source']!r} from source map "
             f"{_display_url(ref_info['map_url'])} (via embedded sourcesContent)"],
            CONFIDENCE_HIGH, parent_js_url=js_url, source_page=source_page,
            extra_metadata={"original_source_file": rec["source"]},
        ))
        info["reconstructed_sources"].append(rec["source"])

        if analyze_reconstructed_sources:
            nested_analysis = analyze_javascript_content(rec["content"], js_url, target=target)
            nested = persist_analysis_findings(
                nested_analysis, target_effective, store, parent_js_url=js_url, source_page=source_page,
                derived_from_source_map=True, original_source_file=rec["source"], defer_to=pending,
            )
            result["js_data"].extend(nested["js_data"])
            result["websocket_endpoints"].extend(nested["websocket_endpoints"])
            result["errors"].extend(nested["errors"])

    _flush()
    return result


# ---------------------------------------------------------------------------
# Input normalization — accepts a plain URL string, a
# {"url":, "source_page":} dict, OR crawler.py's raw persisted
# `javascript_reference` finding record verbatim (see module docstring,
# NO-CROSS-MODULE-CALLS PRECEDENT item (a))
# ---------------------------------------------------------------------------

def _normalize_js_reference(item: Any) -> Dict[str, Optional[str]]:
    if isinstance(item, str):
        return {"url": item, "source_page": None}
    if isinstance(item, dict):
        value = item.get("value")
        if isinstance(value, dict) and value.get("url"):
            return {"url": value.get("url"), "source_page": value.get("source_page")}
        return {"url": item.get("url"), "source_page": item.get("source_page")}
    return {"url": None, "source_page": None}


# ---------------------------------------------------------------------------
# Module orchestration (multiple JS files)
# ---------------------------------------------------------------------------

def run_js_analyzer(
    js_files: List[Any],
    target: Optional[str] = None,
    output_dir: str = "output",
    timeout: float = DEFAULT_TIMEOUT,
    max_redirect_hops: int = DEFAULT_MAX_REDIRECT_HOPS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    retrieve_source_maps: bool = True,
    analyze_reconstructed_sources: bool = True,
    try_implicit_source_map_sibling: bool = True,
    max_files: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run every Module 13 responsibility across `js_files` and persist every
    completed discovery immediately to <output_dir>/pending_assets.json.
    `js_files` accepts plain URL strings, `{"url":, "source_page":}`
    dicts, or crawler.py's raw `javascript_reference` finding records. A
    failure analyzing one file (scope, fetch, parse) never aborts the rest
    of the run.
    """
    store = PendingAssetsStore(output_dir=output_dir)
    summary: Dict[str, Any] = {
        "module": MODULE_NAME, "target": target, "started_at": _now(),
        "files_requested": 0, "files_analyzed": 0, "files_skipped_out_of_scope": 0, "files_failed": 0,
        "results": [], "js_data_for_endpoint_discovery": [], "websocket_endpoints": [], "errors": [],
    }

    # crawler.py legitimately emits the same <script src> once per page that
    # references it, so the same URL routinely arrives many times. Analysing it
    # repeatedly re-fetches the target, double-persists every finding
    # (context.md §7 requires merging, not duplicating) and — worse — spends the
    # max_files budget on duplicates while genuinely distinct scripts go
    # unanalysed. Deduplication therefore happens BEFORE the budget is applied;
    # the additional referring pages are preserved as evidence.
    seen_urls: Dict[str, Dict[str, Any]] = {}
    duplicate_references = 0
    for item in (js_files or []):
        ref = _normalize_js_reference(item)
        url = ref.get("url")
        if not url or not isinstance(url, str):
            continue
        key = url.strip()
        existing = seen_urls.get(key)
        if existing is not None:
            duplicate_references += 1
            other_page = ref.get("source_page")
            if other_page and other_page not in existing["also_referenced_by"]:
                existing["also_referenced_by"].append(other_page)
            continue
        seen_urls[key] = {
            "url": key, "source_page": ref.get("source_page"), "also_referenced_by": [],
        }
    refs = list(seen_urls.values())
    summary["duplicate_references_merged"] = duplicate_references
    if max_files is not None:
        refs = refs[:max_files]
    summary["files_requested"] = len(refs)

    def _record(finding: Dict[str, Any]) -> None:
        """
        Persist one run-level finding, capturing any failure in the summary.

        Every one of these calls previously discarded _safe_store_add's return
        value, so with an unwritable or corrupt pending_assets.json a run
        reported files as analysed while nothing at all reached disk — exactly
        the silent failure context.md §12.11 forbids, and contradicting
        _safe_store_add's own contract ("never silently discarded").
        """
        err = _safe_store_add(store, finding)
        if err:
            summary["errors"].append(err)

    for ref in refs:
        url = ref["url"]
        source_page = ref.get("source_page")
        also_referenced_by = ref.get("also_referenced_by") or []
        file_result: Dict[str, Any] = {"url": url, "source_page": source_page, "status": None}
        if also_referenced_by:
            file_result["also_referenced_by"] = list(also_referenced_by)

        try:
            validated_url = validate_url_target(url, target=target)
        except ScopeError as exc:
            summary["files_skipped_out_of_scope"] += 1
            file_result["status"] = "skipped_out_of_scope"
            file_result["error"] = str(exc)
            _record(make_js_finding(
                "js_analyzer_skipped_out_of_scope", target or _truncate(url, 200),
                {"url": _truncate(url, 500), "reason": str(exc)},
                [f"JS reference {_truncate(url, 200)!r} was not fetched: {exc}"], CONFIDENCE_LOW,
                parent_js_url=_truncate(url, 500), source_page=source_page,
            ))
            summary["results"].append(file_result)
            continue

        target_effective = target or (urllib.parse.urlsplit(validated_url).hostname or validated_url)

        fetch_result = fetch_javascript_file(
            validated_url, target=target, timeout=timeout, max_body_bytes=max_body_bytes,
            max_redirect_hops=max_redirect_hops,
        )
        if fetch_result["status"] != "found":
            summary["files_failed"] += 1
            file_result["status"] = "fetch_failed"
            file_result["error"] = fetch_result.get("error")
            _record(make_js_finding(
                "js_analyzer_fetch_failed", target_effective,
                {"url": validated_url, "error": fetch_result.get("error"), "hops": fetch_result.get("hops", [])},
                [f"Failed to fetch JS file {validated_url}: {fetch_result.get('error')}"], CONFIDENCE_LOW,
                parent_js_url=validated_url, source_page=source_page,
            ))
            summary["results"].append(file_result)
            continue

        final_url = fetch_result.get("final_url", validated_url)
        body = fetch_result.get("body") or ""
        content_type = _ci_get(fetch_result.get("headers", {}), "Content-Type")
        status_code = fetch_result.get("status_code")

        # RESPONSE VALIDATION. fetch_javascript_file reports any non-redirect
        # response as "found", so a 404/403 error page used to be parsed as
        # JavaScript: an HTML 404 body yielded js_analyzer_endpoint_reference
        # findings for the links in it, and a javascript_file_analyzed record
        # asserting at HIGH confidence that a JS file had been analysed. A
        # script that did not come back 2xx was not retrieved, and analysing
        # the error page manufactures endpoint intelligence out of nothing.
        unusable: Optional[str] = None
        if status_code is None or not (200 <= status_code < 300):
            unusable = f"HTTP {status_code} is not a successful response; the script was not retrieved"
        elif not _looks_textual(content_type, body):
            unusable = (
                f"response body is not textual (Content-Type {content_type!r}) and was not parsed as "
                f"JavaScript"
            )
        elif content_type and "text/html" in content_type.lower() and _looks_like_html_document(body):
            unusable = (
                f"response body is an HTML document (Content-Type {content_type!r}), not JavaScript — "
                f"typically a soft-404 or an error page served at a script URL; not parsed as JavaScript"
            )

        if unusable:
            summary["files_failed"] += 1
            file_result["status"] = "not_analyzable"
            file_result["final_url"] = final_url
            file_result["error"] = unusable
            # Recorded, never silently dropped (context.md §12.11): "this URL
            # was checked and yielded no usable script" is itself a
            # negative-result observation other modules can rely on.
            _record(make_js_finding(
                "js_analyzer_fetch_failed", target_effective,
                {"url": final_url, "status_code": status_code, "content_type": content_type,
                 "byte_length": len(body), "error": unusable,
                 "hops": fetch_result.get("hops", [])},
                [f"JS file {final_url} was fetched but not analysed: {unusable}"],
                CONFIDENCE_HIGH, parent_js_url=final_url, source_page=source_page,
            ))
            summary["results"].append(file_result)
            continue

        analysis = analyze_javascript_content(body, final_url, target=target)
        persisted = persist_analysis_findings(analysis, target_effective, store, parent_js_url=final_url, source_page=source_page)

        analysis_evidence = [f"Fetched and analyzed JS file {final_url} ({len(body)} bytes)"]
        if fetch_result.get("body_truncated"):
            analysis_evidence.append(
                f"Response exceeded max_body_bytes ({max_body_bytes}) and was truncated — analysis of this "
                f"script is incomplete, and a trailing sourceMappingURL comment may have been cut off"
            )
        if also_referenced_by:
            analysis_evidence.append(
                f"Also referenced by {len(also_referenced_by)} other crawled page(s): "
                f"{', '.join(_truncate(pg, 120) for pg in also_referenced_by[:5])}"
            )
        _record(make_js_finding(
            "javascript_file_analyzed", target_effective,
            {
                "url": final_url, "content_type": content_type, "status_code": status_code,
                "byte_length": len(body),
                "body_truncated": fetch_result.get("body_truncated", False), "counts": persisted["counts"],
                "also_referenced_by": list(also_referenced_by),
            },
            analysis_evidence,
            CONFIDENCE_HIGH, parent_js_url=final_url, source_page=source_page,
        ))

        if persisted["total"] == 0:
            _record(make_js_finding(
                "js_analyzer_checked_no_findings", target_effective, {"url": final_url},
                [f"No API references, secrets, config values, WebSocket endpoints, or client-side "
                 f"signals detected in {final_url}"],
                CONFIDENCE_LOW, parent_js_url=final_url, source_page=source_page,
            ))

        summary["js_data_for_endpoint_discovery"].extend(persisted["js_data"])
        summary["websocket_endpoints"].extend(persisted["websocket_endpoints"])
        summary["errors"].extend(persisted["errors"])

        sm_result = process_source_map(
            body, final_url, target, target_effective, source_page, store,
            retrieve_source_maps, analyze_reconstructed_sources, try_implicit_source_map_sibling, timeout,
        )
        summary["js_data_for_endpoint_discovery"].extend(sm_result["js_data"])
        summary["websocket_endpoints"].extend(sm_result["websocket_endpoints"])
        summary["errors"].extend(sm_result["errors"])

        file_result["status"] = "analyzed"
        file_result["final_url"] = final_url
        file_result["source_map"] = sm_result["info"]
        summary["files_analyzed"] += 1
        summary["results"].append(file_result)

    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="js_analyzer.py",
        description="ReconHound Module 13 — deep client-side JavaScript intelligence (standalone test entry point).",
    )
    parser.add_argument("--url", action="append", required=True, dest="urls",
                         help="JS file URL to analyze (repeatable)")
    parser.add_argument("--target", default=None, help="Logical target domain to enforce scope against")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout (seconds)")
    parser.add_argument("--no-source-maps", action="store_true", help="Skip source-map retrieval/parsing")
    parser.add_argument("--no-reconstructed-analysis", action="store_true",
                         help="Skip re-analyzing reconstructed original sources")
    parser.add_argument("--no-implicit-map-guess", action="store_true",
                         help="Only follow explicit sourceMappingURL comments, never guess the .map sibling")
    args = parser.parse_args()

    result = run_js_analyzer(
        args.urls, target=args.target, output_dir=args.output_dir, timeout=args.timeout,
        retrieve_source_maps=not args.no_source_maps,
        analyze_reconstructed_sources=not args.no_reconstructed_analysis,
        try_implicit_source_map_sibling=not args.no_implicit_map_guess,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
