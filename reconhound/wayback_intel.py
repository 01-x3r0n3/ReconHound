"""
reconhound/wayback_intel.py — ReconHound Module 5 (wayback_intel.py).

Phase: Passive. See context.md §10 (module 5, "Historical web intel") for
the authoritative responsibilities, and §8 for the evidence/confidence
data model this module implements. This file only documents
implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Historical web intel. Wayback Machine API, historical URLs/deleted
  paths/old endpoints/params, diff against current surface, flag
  removed-but-maybe-still-accessible assets."

That expands (per the assignment brief) into seven discrete
responsibilities, each implemented below:

  1. Wayback Machine API queries        -> fetch_cdx_snapshots (+ build_cdx_query_url)
  2. Historical URL discovery           -> group_historical_urls
  3. Historical/deleted path discovery  -> correlate_against_current_surface
                                            (STATE_HISTORICALLY_REMOVED)
  4. Historical endpoint discovery      -> classify_historical_url
  5. Historical parameter discovery     -> extract_historical_parameters (+
                                            build_historical_data_export)
  6. Current-surface comparison         -> load_current_surface (+
                                            correlate_against_current_surface)
  7. Removed-but-maybe-still-accessible -> correlate_against_current_surface
                                            (STATE_POTENTIALLY_RELEVANT)

Plus shared plumbing: make_finding, PendingAssetsStore, _safe_store_add,
and a single-target orchestrator run_wayback_intel (mirroring the
run_passive_recon / run_endpoint_discovery precedent).

BUILD-ORDER NOTE: context.md §13 lists this module at build-order
position 9 (after surface_mapper.py at position 8). This implementation
was done under an explicit, temporary, user-approved deviation from that
order — surface_mapper.py has NOT been implemented yet. context.md is
unmodified and the documented build order is unchanged; this module is
implemented as a fully standalone producer that does not implement,
replace, or depend on surface_mapper.py's correlation engine, and does
not touch any other unimplemented central module (risk_engine.py,
core/orchestrator.py, reconhound.py).

PASSIVE BOUNDARY: this module's only network interaction is with the
Wayback Machine's public CDX Server API (archive.org's historical index).
It never sends a request to the target itself — no port scanning, no
active service detection, no live crawling, no OPTIONS/HEAD/GET probes
against discovered historical URLs. Consequently it can never confirm
that a historical asset is *currently* accessible; every historical
record's `current_accessibility` is explicitly reported as "unverified"
with a note explaining that confirming liveness is an active module's
job (e.g. endpoint_discovery.py), not this one's.

Implementation decisions (ambiguities resolved so implementation can
proceed without redesigning anything context.md defines):

  1. CDX API endpoint: https://web.archive.org/cdx/search/cdx (public,
     unauthenticated, no API key/credential dependency — so, unlike
     passive_intel.py/code_leak.py/osint_engine.py, this module has no
     "missing configuration" precondition beyond a syntactically valid
     base URL, which is itself validated and reported as a configuration
     error rather than assumed).
  2. Default query shape: matchType=domain (captures the target and its
     subdomains — consistent with is_in_scope()'s subdomain model used
     throughout the codebase, e.g. passive_recon.py's SAN tagging) and
     collapse=urlkey (one representative capture per canonical URL,
     matching how established Wayback-URL recon tooling avoids returning
     every single capture of a frequently-crawled URL, which for a busy
     site can be in the tens of thousands and would make `limit` alone an
     unreliable bound). Both are overridable per call; passing
     collapse=None returns full, unbounded per-capture history instead.
  3. "Current attack surface" source: surface_mapper.py (the architecture's
     eventual owner of a unified asset graph) does not exist yet. Rather
     than invent a second asset model to stand in for it, this module
     reads the URL-bearing findings already persisted to this run's
     output/pending_assets.json by the already-implemented producer
     modules (endpoint_discovery.py's `endpoint_discovered`, crawler.py's
     `crawled_url`, exposure_scan.py's `exposure_finding` /
     `robots_txt_discovered` / `sitemap_xml_discovered` /
     `http_options_result`) — see CURRENT_SURFACE_FINDING_TYPES and
     load_current_surface(). An optional `current_urls` parameter is also
     accepted (mirroring endpoint_discovery.py's caller-supplied
     `historical_data`/`js_data` pattern) for standalone testing/callers
     that want to supply a known-asset list directly rather than via a
     populated store.
  4. Output includes a `historical_data` list shaped to match exactly what
     endpoint_discovery.py's `correlate_historical_parameters()` already
     declares it expects to consume (see that function's docstring:
     {"url", "parameters": [...], "evidence": [...], "observed_at",
     "source"}) — a pre-existing hand-off point in the codebase, not a
     new interface invented here.
  5. HTTP 429 from the CDX API is classified `rate_limited` (mirroring
     endpoint_discovery.py/exposure_scan.py's own rate-limit handling for
     the target) so the caller/evidence trail can see results may be
     incomplete. Transient failures (timeout, connection error, 429, 5xx)
     are retried a small, bounded number of times with exponential backoff
     honouring `Retry-After`; permanent outcomes (403, 404, malformed
     response, successful empty result) are never retried, because the
     answer would not change and repeating the query is pure provider
     load. This is resilience, not rate-limit evasion — no proxying, no
     rotation, no stealth behaviour, and at most `max_attempts` requests
     per query.
  6. Finding-type contract: historical URL records are emitted as
     `historical_endpoint_reference`, the type surface_mapper.py's
     dispatch table and risk_engine.py's SignalRule for "context.md §10
     item 5: removed-but-maybe-still-accessible historical assets" already
     consume. surface_mapper's `_h_endpoint` marks that type's endpoint
     asset `historical=True` — which is the entire point: a historical-only
     URL must never enter the graph looking like a currently observed
     endpoint. The finer "old endpoint vs. deleted path vs. static asset"
     distinction context.md asks for is carried in the record's
     `discovery_type` field, which `_h_endpoint` promotes to an asset
     attribute, so nothing is lost by using an ingestable type.

RESULT SEMANTICS (context.md §8): this module never collapses
fundamentally different outcomes into one status. "The Wayback Machine has
no captures for this domain" and "the CDX API did not answer" are
different facts, and only the first is a negative result. A provider
failure, a truncated result set, or an over-size response is reported as
INCONCLUSIVE — never as an empty historical dataset — via the top-level
`status` / `conclusive` / `results_truncated` / `completeness` fields and
a persisted `wayback_intel_check_inconclusive` finding. That finding type
deliberately does not contain the substring "_checked_no", which
surface_mapper._is_negative_result() treats as negative-result memory: an
inconclusive check must never suppress a future re-check.

SCOPE ENFORCEMENT (context.md §16): the CDX API is an index of the whole
web, and its rows are third-party data. A capture whose hostname is not
the target or a subdomain of it is NOT persisted into the target's asset
graph, however it got into the archive (domain ownership change, shared
infrastructure, archive spam, or a provider-side matchType quirk). Such
rows are counted and returned in the summary — never silently dropped —
but they do not become assets of this target.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other implemented module, sharing the same output file). Output is
intended to feed surface_mapper.py (module 6, not yet implemented) — this
module does not implement or call into surface_mapper, active_recon,
tech_fingerprint, vhost_scanner, api_recon, js_analyzer, supply_chain,
http_analyzer, ssl_analyzer, screenshot, vuln_intel, risk_engine,
report_generator, orchestrator, or any other module not already
implemented.

DISCOVERY != CONFIRMED VULNERABILITY / != CONFIRMED LIVE: every record
here is a historical observation (a URL was captured by the Wayback
Machine at some point, optionally with a status code from that capture).
None of this module's output should be read as "vulnerable", "exploitable",
or "currently live" — that assessment belongs to active modules and/or
vuln_intel.py / risk_engine.py.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

MODULE_NAME = "wayback_intel.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_USER_AGENT = "ReconHound-WaybackIntel/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 15.0
DEFAULT_CDX_BASE_URL = "https://web.archive.org/cdx/search/cdx"
DEFAULT_LIMIT = 5000
DEFAULT_MATCH_TYPE = "domain"
DEFAULT_COLLAPSE = "urlkey"

CDX_FIELDS = ["timestamp", "original", "statuscode", "mimetype", "digest"]
_VALID_MATCH_TYPES = ("exact", "prefix", "host", "domain")

# Bounded-retry policy for the CDX API. Only transient provider-side
# conditions are retried; see _CDX_RETRYABLE below.
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 30.0

# Hard ceiling on requests per query, independent of what a caller asks for.
# A retry count is a knob a misconfiguration can turn into a retry storm
# against a free public service; the per-attempt delay being bounded does not
# bound the total. Five attempts is already generous for a transient outage.
MAX_ATTEMPTS_CEILING = 5

# Resource bounds. Every one of these turns an unbounded provider-controlled
# quantity into a bounded one, and every one of them reports the fact that it
# engaged rather than silently producing a smaller answer.
#
# MAX_RESPONSE_BYTES: 32 MiB. A default query (limit=5000, collapse=urlkey)
# returns roughly 150 bytes per row, i.e. well under 1 MiB, so this is ~40x
# the size of the largest response the module's own defaults can request; it
# exists to stop an unbounded or hostile response body, not to trim normal
# results. Exceeding it is reported as INCONCLUSIVE, never as "not found".
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
_RESPONSE_CHUNK_BYTES = 65536

# MAX_URL_LENGTH: 8192. Browsers, proxies and the archive's own tooling stop
# well below this; a longer "URL" in a CDX row is not a real historical asset,
# and storing it would copy a multi-megabyte string into the record, the
# archive URL, the evidence text, the JSON store and the HTML report. Such a
# row is rejected as malformed rather than truncated: a truncated URL would
# fabricate an asset that never existed.
MAX_URL_LENGTH = 8192

# MAX_ROW_ERRORS: 100. Malformed rows are diagnostics, not discoveries. A
# provider returning tens of thousands of bad rows must not turn each one into
# a retained error string that is then persisted and rendered. The total count
# is always reported exactly, so nothing is hidden — only the per-row detail
# is capped.
MAX_ROW_ERRORS = 100

# MAX_SNAPSHOTS_PER_URL / MAX_URL_VARIANTS_PER_RECORD: 50 each. A grouped
# record embeds its captures, and that whole record becomes the finding's
# `value` — persisted to pending_assets.json, stored as an observation in the
# asset graph, and rendered into the report. The number of captures of one URL
# is unbounded: with collapse=urlkey the CDX API returns one row per URL, but
# collapse=None (a supported option) returns the full per-capture history, and
# a frequently-crawled page has tens of thousands. Measured: 20,000 captures of
# a single URL produced a 7.7 MB pending_assets.json for ONE historical URL.
#
# The cap costs no aggregate information. status_codes_seen, mime_types_seen,
# capture_count, first/last observed and the scope verdict are all computed
# across EVERY capture before trimming; only the per-capture detail list is
# bounded, and it keeps the oldest and newest captures — the temporal envelope
# that is the actual evidence — rather than an arbitrary prefix.
MAX_SNAPSHOTS_PER_URL = 50
MAX_URL_VARIANTS_PER_RECORD = 50

# Completeness vocabulary. "The provider answered and this is everything it
# has" is a different fact from "this is as much as we asked for" and from
# "we do not know", and the difference decides whether downstream may treat
# an absence as meaningful.
COMPLETENESS_COMPLETE = "complete"
COMPLETENESS_POSSIBLY_TRUNCATED = "possibly_truncated"
COMPLETENESS_UNKNOWN = "unknown"
COMPLETENESS_INCONCLUSIVE = "inconclusive"

# CDX outcome classes. `status` keeps the original four public values for
# backwards compatibility; `error_class` carries the finer distinction that
# decides retryability and downstream interpretation.
ERROR_CLASS_TIMEOUT = "timeout"
ERROR_CLASS_CONNECTION = "connection_error"
ERROR_CLASS_RATE_LIMITED = "rate_limited"
ERROR_CLASS_SERVER_ERROR = "server_error"
ERROR_CLASS_FORBIDDEN = "forbidden"
ERROR_CLASS_NOT_FOUND = "http_not_found"
ERROR_CLASS_UNEXPECTED_STATUS = "unexpected_status"
ERROR_CLASS_MALFORMED_RESPONSE = "malformed_response"
ERROR_CLASS_RESPONSE_TOO_LARGE = "response_too_large"
ERROR_CLASS_CONFIGURATION = "configuration_error"
ERROR_CLASS_REQUEST_FAILED = "request_failed"

# A permanent failure returns the same answer to an identical second query.
# Retrying 403/404/malformed responses adds provider load for no chance of a
# better result, so only genuinely transient conditions are retried.
_CDX_RETRYABLE = frozenset({
    ERROR_CLASS_TIMEOUT,
    ERROR_CLASS_CONNECTION,
    ERROR_CLASS_RATE_LIMITED,
    ERROR_CLASS_SERVER_ERROR,
})

# Parameters that are unambiguously campaign/click tracking: they identify the
# referral that produced a visit, never a distinct application resource. Two
# archive captures differing only in these describe the SAME historical URL,
# and keeping them apart mints duplicate endpoint assets and duplicate
# parameter findings for one real endpoint.
#
# This list is deliberately conservative and additions are not free: anything
# that MIGHT carry application semantics is excluded, because collapsing
# "?id=1" and "?id=2", or "?sid=abc" and "?sid=admin", would destroy real
# historical attack surface. That failure mode (a false negative — surface
# that existed and is never reported) is strictly worse than the one this
# fixes (duplicate records). "ref", "source", "from", "campaign", "cid" and
# similar plausible-looking names are NOT here for exactly that reason.
#
# Nothing is discarded: every original captured URL is retained under the
# merged record's "snapshots" and "url_variants", so the historical evidence
# and its provenance survive in full (see group_historical_urls).
_TRACKING_PARAMETERS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_name", "utm_reader", "utm_brand", "utm_social",
    "utm_social-type", "utm_referrer", "utm_cid",
    "gclid", "gclsrc", "dclid", "wbraid", "gbraid",
    "fbclid", "msclkid", "yclid", "twclid", "ttclid", "igshid", "mibextid",
    "mc_cid", "mc_eid", "_hsenc", "_hsmi", "hsctatracking",
    "vero_id", "vero_conv", "oly_anon_id", "oly_enc_id",
    "_openstat", "icid", "s_kwcid", "gad_source",
})

# Control characters have no place in a URL. They arrive only from a malformed
# or hostile archive record, and they are what turns a stored "URL" into log
# injection, a broken JSON/HTML field, or a misleading report line.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# CDX capture timestamps are exactly 14 digits (YYYYMMDDHHMMSS). Anything else
# is not a timestamp, and must not be concatenated into an archive URL.
_CDX_TIMESTAMP_RE = re.compile(r"^\d{14}$")

# Finding `type` values already written to pending_assets.json by
# already-implemented modules that carry a currently-known URL. This is
# the closest thing this repository has to "known current assets" until
# surface_mapper.py exists (see module docstring, decision #3).
CURRENT_SURFACE_FINDING_TYPES = {
    "endpoint_discovered",
    "crawled_url",
    "exposure_finding",
    "robots_txt_discovered",
    "sitemap_xml_discovered",
    "http_options_result",
}

# Historical-asset relationship states (context.md-required distinction
# between historically observed / currently known / historically removed /
# potentially still relevant / unverified current accessibility).
STATE_CURRENTLY_KNOWN = "currently_known"
STATE_HISTORICALLY_REMOVED = "historically_removed"
STATE_POTENTIALLY_RELEVANT = "historically_removed_potentially_relevant"
STATE_UNKNOWN_NO_CURRENT_SURFACE = "unknown_no_current_surface_available"
ACCESSIBILITY_UNVERIFIED = "unverified"

# Finding type emitted for every historical URL record.
#
# INTEGRATION CONTRACT — do not change without checking both consumers:
#   * surface_mapper.py's dispatch table routes "historical_endpoint_reference"
#     to _h_endpoint, which sets the endpoint asset's `historical` attribute to
#     True. Any other type falls through to _h_finding_generic, which still
#     mints an endpoint asset but WITHOUT that marker — a historical-only URL
#     then sits in the graph indistinguishable from a currently observed
#     endpoint. That is precisely the confusion this module exists to prevent.
#   * risk_engine.py's SignalRule for "context.md §10 item 5:
#     removed-but-maybe-still-accessible historical assets" matches
#     ("historical_endpoint_reference", "historical_parameter"). Any other type
#     is filed as "unclassified:<type>" with no rule basis, so the engine's
#     explicit handling of this module's own subject matter never fires.
HISTORICAL_URL_FINDING_TYPE = "historical_endpoint_reference"

# Emitted when the historical check could not be completed. NAMING CONTRACT:
# surface_mapper._is_negative_result() treats any type containing "_checked_no"
# (or ending "_not_probed") as negative-result memory that other modules trust
# to skip re-checking. This type must never match either pattern — an
# inconclusive check is not a negative result.
INCONCLUSIVE_FINDING_TYPE = "wayback_intel_check_inconclusive"
_ACCESSIBILITY_NOTE = (
    "wayback_intel.py is passive-only and never sends requests to the live "
    "target; confirming whether this historical asset currently responds "
    "requires an active module (e.g. endpoint_discovery.py) and is "
    "explicitly out of scope here."
)

_STATIC_ASSET_EXT_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|map)(?:$)", re.IGNORECASE
)
_ENDPOINT_HINT_RE = re.compile(r"/(?:api|graphql|rest|v[0-9]+)(?:/|$)", re.IGNORECASE)

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


class ScopeError(ValueError):
    """Raised when a target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


class ConfigurationError(ValueError):
    """Raised when the CDX API configuration (base URL, matchType) is missing/invalid."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors passive_recon.py's validate_target/is_in_scope;
# duplicated per modular independence, context.md §12.2)
# ---------------------------------------------------------------------------

def validate_target(target: str) -> str:
    """
    Validate that `target` is a syntactically valid, explicit domain name.

    wayback_intel operates on exactly one explicit target domain per
    invocation and never expands to unrelated hosts. Raises ScopeError on
    anything that is not a plausible bare domain name (URLs, IPs,
    wildcards, empty input).
    """
    if not isinstance(target, str) or not target.strip():
        raise ScopeError("Target must be a non-empty domain string.")

    candidate = target.strip().rstrip(".").lower()

    if "://" in candidate or "/" in candidate:
        raise ScopeError(f"Target must be a bare domain name, not a URL/path: {target!r}")

    is_ip_literal = True
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        is_ip_literal = False
    if is_ip_literal:
        raise ScopeError(f"Target must be a domain name, not a raw IP address: {target!r}")

    if "*" in candidate:
        raise ScopeError(f"Wildcard targets are not permitted: {target!r}")

    if not _DOMAIN_RE.match(candidate):
        raise ScopeError(f"Target is not a syntactically valid domain: {target!r}")

    return candidate


def is_in_scope(hostname: str, target: str) -> bool:
    """True if `hostname` is the target itself or a subdomain of it."""
    hostname = (hostname or "").strip().rstrip(".").lower()
    target = target.strip().rstrip(".").lower()
    if not hostname:
        return False
    return hostname == target or hostname.endswith("." + target)


# ---------------------------------------------------------------------------
# Evidence-model helpers (mirrors every other implemented module's model;
# kept local per modular independence)
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

    def add_many(self, findings: List[Dict[str, Any]]) -> int:
        """
        Append a batch of findings in ONE read + ONE atomic write.

        add() re-reads and rewrites the whole file per finding, which is
        correct but quadratic in the number of findings. That is fine for the
        handful of records most modules produce and badly wrong here: a single
        default query (limit=5000) yields thousands of records, and persisting
        them one at a time rewrites a growing file thousands of times.
        Measured on this repository: 100 records 0.24s, 400 records 3.67s, 800
        records 10.67s — i.e. ~4x the cost for 2x the input.

        Crash-safety is unchanged. The write is still a single atomic
        write-to-temp + os.replace, so a crash mid-batch leaves the previous
        complete file intact; the batch is all-or-nothing rather than
        partially applied, which is the stronger guarantee, not a weaker one.
        Returns the number of findings written.
        """
        if not findings:
            return 0
        with self._lock:
            records = self._read_all()
            records.extend(findings)
            self._atomic_write(records)
        return len(findings)

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
    """
    if store is None:
        return None
    try:
        store.add(finding)
        return None
    except PersistenceError as exc:
        return str(exc)


def _safe_store_add_many(
    store: Optional["PendingAssetsStore"], findings: List[Dict[str, Any]]
) -> Optional[str]:
    """Batch equivalent of _safe_store_add. Returns None on success, else an error message."""
    if store is None or not findings:
        return None
    try:
        store.add_many(findings)
        return None
    except PersistenceError as exc:
        return str(exc)


# ---------------------------------------------------------------------------
# URL normalization (mirrors endpoint_discovery.py's _normalize_url so
# historical/current-surface comparisons use a consistent key)
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if ":" in netloc:
        host, _, port = netloc.rpartition(":")
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            netloc = host
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
    return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))


def _canonical_url(url: str) -> str:
    """
    The identity used to decide whether two captures describe the same
    historical URL: _normalize_url() with campaign/click-tracking parameters
    removed (see _TRACKING_PARAMETERS).

    Only parameters on that conservative allowlist are dropped. Everything
    else — including anything that might carry application semantics — is
    preserved, so "?id=1" and "?id=2" remain two distinct historical URLs and
    "?sid=abc" and "?sid=admin" are never merged. Parameter ORDER and repeated
    values are already normalized by _normalize_url (sorted pairs), so
    "?a=1&b=2" and "?b=2&a=1" share one identity while "?a=1&a=2" keeps both
    values.

    This never destroys evidence: the caller retains every original captured
    URL alongside the canonical one.
    """
    parsed = urllib.parse.urlsplit(_normalize_url(url))
    if not parsed.query:
        return parsed.geturl()
    kept = [
        (name, value)
        for name, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if name.lower() not in _TRACKING_PARAMETERS
    ]
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(kept), "")
    )


def _tracking_parameters_in(url: str) -> List[str]:
    """Names of tracking-only parameters present on `url` (sorted, deduplicated)."""
    try:
        query = urllib.parse.urlsplit(url).query
    except ValueError:
        return []
    if not query:
        return []
    return sorted({
        name for name, _ in urllib.parse.parse_qsl(query, keep_blank_values=True)
        if name.lower() in _TRACKING_PARAMETERS
    })


def _url_path(url: str) -> str:
    try:
        path = urllib.parse.urlsplit(url).path
    except Exception:
        return "/"
    return path or "/"


def _strip_query(url: str) -> str:
    """`url` without its query string or fragment (empty input passes through)."""
    if not url:
        return url
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _url_hostname(url: str) -> str:
    """Lowercased hostname of `url`, or "" when it has none / is unparseable."""
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _host_path_key(url: str) -> str:
    """
    Host-qualified path identity, e.g. "shop.example.com|/login".

    A bare path is NOT an identity. "/login" on shop.example.com and "/login"
    on a decommissioned or third-party host are different endpoints, and "/"
    is shared by essentially every host that has ever been crawled. Matching a
    historical URL against the current surface on the bare path alone
    therefore declared unrelated historical URLs "currently known" with HIGH
    confidence — a fabricated current-asset claim (see
    correlate_against_current_surface).
    """
    host = _url_hostname(url)
    if not host:
        return ""
    return f"{host}|{_url_path(url)}"


# ---------------------------------------------------------------------------
# 1. Wayback Machine API queries
# ---------------------------------------------------------------------------

def build_cdx_query_url(
    target: str,
    base_url: str = DEFAULT_CDX_BASE_URL,
    match_type: str = DEFAULT_MATCH_TYPE,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    limit: Optional[int] = None,
    collapse: Optional[str] = DEFAULT_COLLAPSE,
) -> str:
    """Build the CDX Server API query URL for `target`. Raises ConfigurationError on invalid config."""
    if not isinstance(base_url, str) or not base_url.strip():
        raise ConfigurationError("CDX API base URL must be a non-empty string.")
    parsed_base = urllib.parse.urlsplit(base_url.strip())
    if parsed_base.scheme not in ("http", "https") or not parsed_base.netloc:
        raise ConfigurationError(f"CDX API base URL is not a valid http(s) URL: {base_url!r}")

    if match_type not in _VALID_MATCH_TYPES:
        raise ConfigurationError(
            f"Unsupported CDX matchType {match_type!r}; must be one of {_VALID_MATCH_TYPES}"
        )

    params: Dict[str, str] = {
        "url": target,
        "output": "json",
        "fl": ",".join(CDX_FIELDS),
        "matchType": match_type,
    }
    if collapse:
        params["collapse"] = collapse
    if from_date:
        params["from"] = from_date
    if to_date:
        params["to"] = to_date
    if limit is not None:
        try:
            limit_int = int(limit)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"limit must be an integer: {limit!r}") from exc
        # A negative CDX limit means "return the LAST n results", which silently
        # changes what the query is asking for and made every result set compare
        # as truncated. A zero limit removes the bound entirely while still
        # reading as "a limit was configured". Neither is a supported query
        # shape here; both are configuration errors rather than silent
        # behaviour changes.
        if limit_int < 0:
            raise ConfigurationError(
                f"limit must be a positive integer (a negative CDX limit requests the "
                f"last n results, not the first n): {limit!r}"
            )
        if limit_int > 0:
            params["limit"] = str(limit_int)

    return f"{base_url.rstrip('/')}?{urllib.parse.urlencode(params)}"


def normalize_snapshot(row: Dict[str, str], base_archive_url: str = "https://web.archive.org/web") -> Dict[str, Any]:
    """Normalize one raw CDX row (already zipped into a dict by field name) into a JSON-safe record."""
    timestamp = row.get("timestamp") or ""
    original = row.get("original") or ""
    if not timestamp or not original:
        raise ValueError("snapshot row is missing timestamp/original")
    if not isinstance(timestamp, str) or not isinstance(original, str):
        raise ValueError("snapshot row timestamp/original must be strings")

    # CDX rows are third-party data. A "URL" carrying control characters is not
    # a real historical asset; it is what turns a stored value into log
    # injection, a corrupted report line, or a misleading archive link. Reject
    # the row rather than sanitising it into something that never existed.
    if _CONTROL_CHAR_RE.search(original) or _CONTROL_CHAR_RE.search(timestamp):
        raise ValueError("snapshot row contains control characters")
    if len(original) > MAX_URL_LENGTH:
        raise ValueError(
            f"snapshot URL exceeds {MAX_URL_LENGTH} characters ({len(original)}); "
            f"rejected rather than truncated, because a truncated URL names an "
            f"asset that never existed"
        )

    try:
        dt = datetime.strptime(timestamp, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        observed_at = dt.isoformat()
    except ValueError:
        observed_at = None  # keep the raw timestamp as a fallback sort/display key

    status_raw = row.get("statuscode") or "-"
    status_code: Optional[int] = None
    if status_raw and status_raw != "-":
        try:
            status_code = int(status_raw)
        except ValueError:
            status_code = None

    # Only a well-formed 14-digit capture timestamp may be concatenated into a
    # replay URL. Building one from an arbitrary provider string produces a
    # link that does not address any capture, in a field a report renders as a
    # clickable archive reference.
    archive_url: Optional[str] = None
    if _CDX_TIMESTAMP_RE.match(timestamp):
        archive_url = f"{base_archive_url.rstrip('/')}/{timestamp}/{original}"

    return {
        "timestamp": timestamp,
        "observed_at": observed_at,
        "original_url": original,
        "status_code": status_code,
        "status_code_raw": status_raw,
        "mime_type": row.get("mimetype") or None,
        "digest": row.get("digest") or None,
        "archive_url": archive_url,
    }


def _retry_delay(attempt: int, backoff: float, retry_after: Optional[str]) -> float:
    """
    Delay before retry number `attempt` (1-based), honouring a provider
    `Retry-After` when it gives a usable, bounded number of seconds.

    The provider's own instruction wins over our schedule when it asks us to
    wait longer, because ignoring it is what turns a rate limit into a ban.
    Everything is clamped to MAX_BACKOFF_SECONDS so a hostile or malformed
    header cannot stall the scan indefinitely.
    """
    delay = backoff * (2 ** (attempt - 1))
    if retry_after:
        try:
            requested = float(str(retry_after).strip())
        except (TypeError, ValueError):
            requested = 0.0  # HTTP-date form is not honoured; the schedule applies
        if requested > delay:
            delay = requested
    return max(0.0, min(delay, MAX_BACKOFF_SECONDS))


def _read_bounded_body(resp: Any) -> Tuple[Optional[str], Optional[str]]:
    """
    Read at most MAX_RESPONSE_BYTES from `resp`. Returns (body, error).

    A response that does not fit is an error, never a truncated parse: half a
    JSON array is not "fewer historical URLs", it is an unparseable document,
    and silently reporting the rows that happened to arrive first would
    present a partial answer as a complete one.

    Streaming is used when the response supports it (bounding memory before
    the bytes are ever materialised) and a plain `.text` read is used
    otherwise, so this works with any response object exposing the requests
    interface.
    """
    declared = resp.headers.get("Content-Length") if getattr(resp, "headers", None) else None
    if declared:
        try:
            if int(declared) > MAX_RESPONSE_BYTES:
                return None, (
                    f"CDX response declares {int(declared)} bytes, over the "
                    f"{MAX_RESPONSE_BYTES}-byte limit; not read"
                )
        except (TypeError, ValueError):
            pass  # an unparseable Content-Length just means we bound it while reading

    iter_content = getattr(resp, "iter_content", None)
    if not callable(iter_content):
        body = resp.text or ""
        if len(body.encode("utf-8", "replace")) > MAX_RESPONSE_BYTES:
            return None, f"CDX response exceeds the {MAX_RESPONSE_BYTES}-byte limit"
        return body, None

    chunks: List[bytes] = []
    total = 0
    try:
        for chunk in iter_content(_RESPONSE_CHUNK_BYTES):
            if not chunk:
                continue  # keep-alive / empty chunk
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", "replace")
            elif not isinstance(chunk, (bytes, bytearray)):
                return None, f"CDX response yielded a non-byte chunk ({type(chunk).__name__})"
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                return None, f"CDX response exceeds the {MAX_RESPONSE_BYTES}-byte limit"
            chunks.append(bytes(chunk))
    except requests.exceptions.RequestException as exc:
        # The connection dropped mid-body. What arrived is an unknown fraction
        # of the answer, so it is a failure, not a smaller result set.
        return None, f"connection dropped while reading CDX response: {exc}"

    # `encoding` is whatever the response object says it is. A missing, empty
    # or non-string value must not raise out of the reader, and an encoding
    # name the codec registry does not know must not either — the bytes are
    # still decodable as UTF-8 with replacement.
    encoding = getattr(resp, "encoding", None)
    if not isinstance(encoding, str) or not encoding.strip():
        encoding = "utf-8"
    body = b"".join(chunks)
    try:
        return body.decode(encoding, "replace"), None
    except (LookupError, TypeError, ValueError):
        return body.decode("utf-8", "replace"), None


def _cdx_request_once(query_url: str, timeout: float) -> Dict[str, Any]:
    """
    One CDX request + body read. Returns an outcome dict with `error_class`
    set for anything that is not a usable 200 body.
    """
    outcome: Dict[str, Any] = {
        "body": None, "error": None, "error_class": None,
        "http_status": None, "retry_after": None, "final_url": None,
    }
    resp = None
    try:
        resp = requests.get(
            query_url, timeout=timeout,
            headers={"User-Agent": DEFAULT_USER_AGENT}, stream=True,
        )
        outcome["http_status"] = resp.status_code
        outcome["final_url"] = getattr(resp, "url", None)
        headers = getattr(resp, "headers", None) or {}
        outcome["retry_after"] = headers.get("Retry-After")

        if resp.status_code == 429:
            outcome["error_class"] = ERROR_CLASS_RATE_LIMITED
            outcome["error"] = "HTTP 429 Too Many Requests from Wayback CDX API"
            return outcome
        if resp.status_code == 403:
            outcome["error_class"] = ERROR_CLASS_FORBIDDEN
            outcome["error"] = (
                "Wayback CDX API returned unexpected HTTP 403 (access refused); "
                "not retried — a refusal returns the same answer to an identical query"
            )
            return outcome
        if resp.status_code == 404:
            outcome["error_class"] = ERROR_CLASS_NOT_FOUND
            outcome["error"] = (
                "Wayback CDX API returned unexpected HTTP 404 for the query endpoint; "
                "this is an endpoint/configuration outcome, NOT evidence that the "
                "target has no captures"
            )
            return outcome
        if resp.status_code >= 500:
            outcome["error_class"] = ERROR_CLASS_SERVER_ERROR
            outcome["error"] = f"Wayback CDX API returned HTTP {resp.status_code}"
            return outcome
        if resp.status_code != 200:
            outcome["error_class"] = ERROR_CLASS_UNEXPECTED_STATUS
            outcome["error"] = f"Wayback CDX API returned unexpected HTTP {resp.status_code}"
            return outcome

        body, read_error = _read_bounded_body(resp)
        if read_error is not None:
            outcome["error"] = read_error
            outcome["error_class"] = (
                ERROR_CLASS_CONNECTION if "connection dropped" in read_error
                else ERROR_CLASS_RESPONSE_TOO_LARGE
            )
            return outcome
        outcome["body"] = body
        return outcome
    except requests.exceptions.Timeout:
        outcome["error_class"] = ERROR_CLASS_TIMEOUT
        outcome["error"] = "timeout"
        return outcome
    except requests.exceptions.ConnectionError as exc:
        outcome["error_class"] = ERROR_CLASS_CONNECTION
        outcome["error"] = f"connection error: {exc}"
        return outcome
    except requests.exceptions.RequestException as exc:
        outcome["error_class"] = ERROR_CLASS_REQUEST_FAILED
        outcome["error"] = f"request failed: {exc}"
        return outcome
    except Exception as exc:
        # A response object that does not behave like requests.Response (a
        # stub, a proxy, an adapter returning odd types) must surface as a
        # classified failure, never as an exception escaping the module.
        outcome["error_class"] = ERROR_CLASS_MALFORMED_RESPONSE
        outcome["error"] = f"unusable CDX response object: {type(exc).__name__}: {exc}"
        return outcome
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:  # pragma: no cover - close() must never mask the outcome
                pass


def fetch_cdx_snapshots(
    target: str,
    base_url: str = DEFAULT_CDX_BASE_URL,
    match_type: str = DEFAULT_MATCH_TYPE,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    limit: int = DEFAULT_LIMIT,
    collapse: Optional[str] = DEFAULT_COLLAPSE,
    timeout: float = DEFAULT_TIMEOUT,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    backoff: float = DEFAULT_BACKOFF_SECONDS,
) -> Dict[str, Any]:
    """
    Query the Wayback Machine CDX Server API for `target`'s capture
    history. This is the module's ONLY network interaction, and it talks
    exclusively to archive.org's historical index — never the target
    itself (passive boundary, see module docstring).

    Transient failures are retried up to `max_attempts` times total with
    exponential backoff honouring `Retry-After`; permanent ones never are
    (see _CDX_RETRYABLE).

    Returns {"status": "found"|"not_found"|"rate_limited"|"error",
             "snapshots": [...], "raw_row_count": int, "row_errors": [...],
             "row_error_count": int, "truncated": bool,
             "completeness": str, "conclusive": bool, "error": str|None,
             "error_class": str|None, "query_url": str|None,
             "final_url": str|None, "http_status": int|None,
             "attempts": int, "retries": int}.

    `truncated` is True only when a bound was requested and the provider
    returned at least that many rows — which means the answer MAY be
    incomplete, not that it certainly is; `completeness` carries that
    distinction explicitly.
    """
    target = validate_target(target)
    result: Dict[str, Any] = {
        "status": "not_found",
        "snapshots": [],
        "raw_row_count": 0,
        "row_errors": [],
        "row_error_count": 0,
        "truncated": False,
        "completeness": COMPLETENESS_INCONCLUSIVE,
        "conclusive": False,
        "error": None,
        "error_class": None,
        "query_url": None,
        "final_url": None,
        "http_status": None,
        "attempts": 0,
        "retries": 0,
    }

    try:
        query_url = build_cdx_query_url(
            target, base_url=base_url, match_type=match_type,
            from_date=from_date, to_date=to_date, limit=limit, collapse=collapse,
        )
    except ConfigurationError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        result["error_class"] = ERROR_CLASS_CONFIGURATION
        return result
    result["query_url"] = query_url

    try:
        attempts_allowed = min(MAX_ATTEMPTS_CEILING, max(1, int(max_attempts)))
    except (TypeError, ValueError):
        attempts_allowed = 1

    outcome: Dict[str, Any] = {}
    for attempt in range(1, attempts_allowed + 1):
        outcome = _cdx_request_once(query_url, timeout)
        result["attempts"] = attempt
        result["http_status"] = outcome["http_status"]
        result["final_url"] = outcome["final_url"]
        if outcome["error_class"] is None:
            break
        if outcome["error_class"] not in _CDX_RETRYABLE or attempt >= attempts_allowed:
            break
        result["retries"] += 1
        time.sleep(_retry_delay(attempt, backoff, outcome.get("retry_after")))

    if outcome.get("error_class") is not None:
        result["error"] = outcome["error"]
        result["error_class"] = outcome["error_class"]
        result["status"] = (
            "rate_limited" if outcome["error_class"] == ERROR_CLASS_RATE_LIMITED else "error"
        )
        return result

    body = (outcome.get("body") or "").strip()
    if not body:
        # An empty 200 body is the CDX API's own way of saying "no captures
        # match this query" — a real, conclusive negative result.
        result["status"] = "not_found"
        result["completeness"] = COMPLETENESS_COMPLETE
        result["conclusive"] = True
        return result

    try:
        rows = json.loads(body)
    except json.JSONDecodeError as exc:
        result["status"] = "error"
        result["error"] = f"malformed JSON from Wayback CDX API: {exc}"
        result["error_class"] = ERROR_CLASS_MALFORMED_RESPONSE
        return result

    if not isinstance(rows, list):
        result["status"] = "error"
        result["error"] = "unexpected CDX response structure (root is not a JSON array)"
        result["error_class"] = ERROR_CLASS_MALFORMED_RESPONSE
        return result

    if len(rows) < 2:
        # A header-only (or empty) array is a well-formed "no matching
        # captures" answer, not a failure.
        result["status"] = "not_found"
        result["completeness"] = COMPLETENESS_COMPLETE
        result["conclusive"] = True
        return result

    header = rows[0]
    if not isinstance(header, list) or not all(isinstance(h, str) for h in header):
        result["status"] = "error"
        result["error"] = "unexpected CDX response structure (missing/invalid header row)"
        result["error_class"] = ERROR_CLASS_MALFORMED_RESPONSE
        return result

    result["raw_row_count"] = len(rows) - 1
    requested_limit = 0
    try:
        requested_limit = int(limit) if limit is not None else 0
    except (TypeError, ValueError):
        requested_limit = 0

    if requested_limit > 0:
        # Hitting the bound exactly is ambiguous by construction: the provider
        # returns at most `limit` rows and never reports how many it withheld,
        # so a full page may be the complete history or the first page of far
        # more. It is reported as POSSIBLY truncated, never as a certainty in
        # either direction.
        result["truncated"] = result["raw_row_count"] >= requested_limit
        result["completeness"] = (
            COMPLETENESS_POSSIBLY_TRUNCATED if result["truncated"] else COMPLETENESS_COMPLETE
        )
    else:
        # No bound was requested, so there is nothing to compare against and
        # no basis for claiming the result set is complete.
        result["completeness"] = COMPLETENESS_UNKNOWN
    result["conclusive"] = result["completeness"] == COMPLETENESS_COMPLETE

    snapshots: List[Dict[str, Any]] = []
    row_errors: List[str] = []
    row_error_count = 0
    for i, row in enumerate(rows[1:], start=1):
        try:
            if not isinstance(row, list) or len(row) != len(header):
                raise ValueError("row does not match header shape")
            snapshots.append(normalize_snapshot(dict(zip(header, row))))
        except Exception as exc:  # a single malformed row must not abort the rest
            row_error_count += 1
            if len(row_errors) < MAX_ROW_ERRORS:
                row_errors.append(f"row {i}: {exc}")
            elif len(row_errors) == MAX_ROW_ERRORS:
                row_errors.append(
                    f"... further row errors suppressed after {MAX_ROW_ERRORS}; "
                    f"see row_error_count for the exact total"
                )
            continue

    result["snapshots"] = snapshots
    result["row_errors"] = row_errors
    result["row_error_count"] = row_error_count
    if row_error_count:
        # Rows the provider sent that this module could not read are missing
        # intelligence, so the answer is no longer a complete picture.
        result["completeness"] = (
            COMPLETENESS_POSSIBLY_TRUNCATED if result["completeness"] == COMPLETENESS_COMPLETE
            else result["completeness"]
        )
        result["conclusive"] = False
    result["status"] = "found" if snapshots else "not_found"
    return result


# ---------------------------------------------------------------------------
# 2. Historical URL discovery
# ---------------------------------------------------------------------------

def _bounded_snapshots(snapshots: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    At most MAX_SNAPSHOTS_PER_URL captures, keeping the OLDEST and NEWEST.

    An arbitrary prefix would drop exactly the evidence that matters — when a
    URL was last seen alive, and what status it returned then. The temporal
    envelope is preserved instead; the exact total stays on the record as
    `capture_count`.
    """
    if len(snapshots) <= MAX_SNAPSHOTS_PER_URL:
        return sorted(snapshots, key=lambda s: str(s.get("timestamp") or ""))
    ordered = sorted(snapshots, key=lambda s: str(s.get("timestamp") or ""))
    head = MAX_SNAPSHOTS_PER_URL // 2
    tail = MAX_SNAPSHOTS_PER_URL - head
    return ordered[:head] + ordered[-tail:]


def group_historical_urls(snapshots: List[Dict[str, Any]], target: str) -> List[Dict[str, Any]]:
    """
    Dedup normalized CDX snapshots into one aggregated record per unique
    historical URL, preserving evidence across every capture rather than
    collapsing to a single boolean (first/last observed, all status codes and
    MIME types seen, full per-capture list retained under "snapshots").

    Identity is the CANONICAL url (_canonical_url): captures differing only in
    campaign/click-tracking parameters describe one historical URL, and
    keeping them apart minted a duplicate endpoint asset and a duplicate
    parameter finding per tracking value. Every distinct original URL that
    merged into a record is retained under "url_variants", and every capture
    under "snapshots", so no historical evidence or provenance is lost.
    """
    groups: Dict[str, Dict[str, Any]] = {}

    for snap in snapshots:
        try:
            url = snap["original_url"]
            norm = _normalize_url(url)
            canonical = _canonical_url(url)
        except Exception:
            continue  # malformed entry; skip this one, keep processing the rest

        group = groups.get(canonical)
        if group is None:
            group = {
                "url": url,
                "normalized_url": norm,
                "canonical_url": canonical,
                "path": _url_path(url),
                "hostname": _url_hostname(url),
                "in_scope": False,
                "snapshots": [],
                "url_variants": [],
                "tracking_parameters_seen": set(),
                "first_observed_at": None,
                "last_observed_at": None,
                "first_capture_timestamp": None,
                "last_capture_timestamp": None,
                "status_codes_seen": set(),
                "mime_types_seen": set(),
            }
            groups[canonical] = group

        group["snapshots"].append(snap)
        if url not in group["url_variants"]:
            group["url_variants"].append(url)
        group["tracking_parameters_seen"].update(_tracking_parameters_in(url))
        if snap.get("status_code") is not None:
            group["status_codes_seen"].add(snap["status_code"])
        if snap.get("mime_type"):
            group["mime_types_seen"].add(snap["mime_type"])

        # Order on the raw 14-digit CDX timestamp only. `observed_at` is an
        # ISO-8601 rendering that is absent whenever a timestamp did not
        # parse, and comparing the two forms against each other is not a
        # comparison at all: "-" sorts below any digit, so an ISO string
        # always compares LESS than a raw timestamp in the same year. A
        # January capture with an unparseable timestamp was therefore reported
        # as more recent than a December capture with a valid one.
        marker = snap.get("timestamp")
        if isinstance(marker, str) and marker:
            if group["first_capture_timestamp"] is None or marker < group["first_capture_timestamp"]:
                group["first_capture_timestamp"] = marker
                group["first_observed_at"] = snap.get("observed_at") or marker
            if group["last_capture_timestamp"] is None or marker > group["last_capture_timestamp"]:
                group["last_capture_timestamp"] = marker
                group["last_observed_at"] = snap.get("observed_at") or marker

    records: List[Dict[str, Any]] = []
    for group in groups.values():
        group["in_scope"] = is_in_scope(group["hostname"], target)
        # Aggregates are computed across EVERY capture, before any trimming, so
        # bounding the retained detail below loses no summary information.
        group["status_codes_seen"] = sorted(group["status_codes_seen"])
        group["mime_types_seen"] = sorted(group["mime_types_seen"])
        group["tracking_parameters_seen"] = sorted(group["tracking_parameters_seen"])
        group["capture_count"] = len(group["snapshots"])
        group["variant_count"] = len(group["url_variants"])
        group["historically_observed"] = True

        variants = sorted(group["url_variants"])
        group["url_variants_truncated"] = len(variants) > MAX_URL_VARIANTS_PER_RECORD
        group["url_variants"] = variants[:MAX_URL_VARIANTS_PER_RECORD]

        group["snapshots"] = _bounded_snapshots(group["snapshots"])
        group["snapshots_retained"] = len(group["snapshots"])
        group["snapshots_truncated"] = group["snapshots_retained"] < group["capture_count"]
        records.append(group)

    return sorted(records, key=lambda r: r["url"])


# ---------------------------------------------------------------------------
# 3/4. Historical/deleted path discovery + historical endpoint discovery
# ---------------------------------------------------------------------------

def _record_url(record: Dict[str, Any]) -> str:
    """
    The URL a record's query string should be read from.

    The canonical URL when the record carries one (tracking parameters
    removed, so they never become "historical parameters" of an endpoint),
    falling back to the raw captured URL for records built without one.
    """
    return record.get("canonical_url") or record.get("url") or ""


def classify_historical_url(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tag a grouped historical-URL record with a discovery_type: an
    API/GraphQL/versioned-looking path is `historical_endpoint`, a
    static-asset extension is `historical_static_asset`, everything else
    is `historical_path` (context.md's "old endpoints" vs. "deleted
    paths" distinction).
    """
    path = record.get("path") or "/"
    is_static_asset = bool(_STATIC_ASSET_EXT_RE.search(path))
    is_endpoint_like = bool(_ENDPOINT_HINT_RE.search(path)) or path.rstrip("/").endswith((".json", ".xml"))

    try:
        has_query_parameters = bool(urllib.parse.urlsplit(_record_url(record)).query)
    except Exception:
        has_query_parameters = False

    if is_endpoint_like:
        discovery_type = "historical_endpoint"
    elif is_static_asset:
        discovery_type = "historical_static_asset"
    else:
        discovery_type = "historical_path"

    return {
        **record,
        "is_static_asset": is_static_asset,
        "is_endpoint_like": is_endpoint_like,
        "has_query_parameters": has_query_parameters,
        "discovery_type": discovery_type,
    }


# ---------------------------------------------------------------------------
# 5. Historical parameter discovery
# ---------------------------------------------------------------------------

def extract_historical_parameters(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract query-string parameter names observed on a historical URL.

    Reads the canonical URL, so campaign/click-tracking parameters do not
    enter the asset graph as application parameters of the endpoint. They
    remain visible on the record as `tracking_parameters_seen`.
    """
    try:
        query = urllib.parse.urlsplit(_record_url(record)).query
    except Exception:
        return []
    if not query:
        return []

    params: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    try:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    except Exception:
        return []

    for name, _value in pairs:
        if not name or name in seen:
            continue
        seen.add(name)
        params.append({
            "name": name,
            "location": "query",
            "method": "GET",
            "data_type": "unknown",
        })
    return params


# ---------------------------------------------------------------------------
# 6/7. Current-attack-surface comparison + removed-but-maybe-still-relevant
# flagging
# ---------------------------------------------------------------------------

def load_current_surface(
    store: Optional[PendingAssetsStore] = None,
    extra_urls: Optional[List[str]] = None,
) -> Dict[str, Set[str]]:
    """
    Build the set of currently-known URLs/paths from the existing central
    persistence file (pending_assets.json), produced by already-implemented
    modules. See module docstring, decision #3: this reuses the
    established representation of current assets rather than inventing a
    second asset model — surface_mapper.py does not exist yet, so the
    shared persisted findings are the closest thing this repository has
    to "known current assets" until it does.

    Returns {"normalized_urls", "canonical_urls", "host_paths", "paths",
             "skipped"}. `host_paths` holds "host|/path" keys and is what
    correlation actually matches on; `paths` holds the bare paths and is kept
    for callers/tests that inspect it, but a bare path is not an identity (see
    _host_path_key) and is no longer used to declare a URL currently known.
    """
    normalized_urls: Set[str] = set()
    canonical_urls: Set[str] = set()
    host_paths: Set[str] = set()
    paths: Set[str] = set()
    skipped: List[str] = []

    def _absorb(raw: Any) -> None:
        if not isinstance(raw, str) or not raw:
            return
        # One unparseable URL persisted by any other module must not take the
        # whole comparison down with it. Before this guard, a single bad value
        # raised out of here, run_wayback_intel caught it, and the current
        # surface silently became empty — so every historical URL in the run
        # was reported as "historically removed" with no indication that the
        # comparison had not actually happened.
        try:
            normalized_urls.add(_normalize_url(raw))
            canonical_urls.add(_canonical_url(raw))
            paths.add(_url_path(raw))
            host_path = _host_path_key(raw)
            if host_path:
                host_paths.add(host_path)
        except (ValueError, AttributeError, TypeError) as exc:
            if len(skipped) < MAX_ROW_ERRORS:
                skipped.append(f"{raw[:200]!r}: {exc}")

    if store is not None:
        try:
            records = store.all()
        except (PersistenceError, OSError) as exc:
            # A corrupt file raises PersistenceError; an unreadable one (mode
            # change, full disk, I/O error) raises OSError. Neither may escape
            # — the caller cannot distinguish "no current surface" from "this
            # helper exploded" from an exception — so the failure is returned
            # as a recorded skip and the comparison degrades to "not compared".
            records = []
            skipped.append(f"pending_assets.json could not be read: {exc}")
        for rec in records:
            if not isinstance(rec, dict) or rec.get("type") not in CURRENT_SURFACE_FINDING_TYPES:
                continue
            value = rec.get("value")
            if not isinstance(value, dict):
                continue
            if value.get("url"):
                _absorb(value["url"])
            if isinstance(value.get("urls"), list):  # sitemap_xml_discovered's listed URLs
                for u in value["urls"]:
                    _absorb(u)

    if extra_urls:
        for u in extra_urls:
            _absorb(u)

    return {
        "normalized_urls": normalized_urls,
        "canonical_urls": canonical_urls,
        "host_paths": host_paths,
        "paths": paths,
        "skipped": skipped,
    }


def correlate_against_current_surface(
    historical_records: List[Dict[str, Any]],
    current_surface: Dict[str, Set[str]],
) -> List[Dict[str, Any]]:
    """
    Enrich each classified historical-URL record with its relationship to
    the current attack surface. Never claims current accessibility —
    current_accessibility is always "unverified" (see module docstring's
    passive-boundary note).

    Matching is on the normalized URL, the canonical URL, or the HOST-QUALIFIED
    path. It is deliberately NOT on the bare path: "/login" observed on the
    current surface of one host says nothing about "/login" on a different,
    possibly decommissioned or third-party host, and "/" is common to
    essentially every host ever crawled. Matching on the bare path declared
    such URLs "currently known" with HIGH confidence — a current-asset claim
    the module has no evidence for and, being passive-only, cannot ever have.

    When no current surface is available at all, the relationship is reported
    as unknown rather than as "historically removed": nothing was compared, so
    concluding removal would be an inference drawn from an absence of data.
    """
    normalized_known: Set[str] = current_surface.get("normalized_urls") or set()
    canonical_known: Set[str] = current_surface.get("canonical_urls") or set()
    host_paths_known: Set[str] = current_surface.get("host_paths") or set()
    surface_is_empty = not (normalized_known or canonical_known or host_paths_known)

    enriched: List[Dict[str, Any]] = []
    for rec in historical_records:
        canonical = rec.get("canonical_url") or rec.get("normalized_url") or rec.get("url") or ""
        host_path = _host_path_key(rec.get("url") or canonical)
        currently_known = (
            rec.get("normalized_url") in normalized_known
            or canonical in canonical_known
            or canonical in normalized_known
            or (bool(host_path) and host_path in host_paths_known)
        )
        looked_live_historically = any(
            isinstance(s, int) and 200 <= s < 400 for s in rec.get("status_codes_seen", [])
        )

        if currently_known:
            relationship = STATE_CURRENTLY_KNOWN
            confidence = CONFIDENCE_MEDIUM if rec.get("is_static_asset") else CONFIDENCE_HIGH
        elif surface_is_empty:
            relationship = STATE_UNKNOWN_NO_CURRENT_SURFACE
            confidence = CONFIDENCE_LOW
        elif looked_live_historically:
            relationship = STATE_POTENTIALLY_RELEVANT
            confidence = CONFIDENCE_LOW
        else:
            relationship = STATE_HISTORICALLY_REMOVED
            confidence = CONFIDENCE_LOW

        enriched.append({
            **rec,
            "relationship_to_current_surface": relationship,
            "current_surface_compared": not surface_is_empty,
            "current_accessibility": ACCESSIBILITY_UNVERIFIED,
            "current_accessibility_note": _ACCESSIBILITY_NOTE,
            "confidence": confidence,
        })
    return enriched


def build_historical_data_export(enriched_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build the `historical_data` export shape that endpoint_discovery.py's
    correlate_historical_parameters() already declares it expects to
    consume (see module docstring, decision #4).
    """
    export: List[Dict[str, Any]] = []
    for rec in enriched_records:
        if not rec.get("in_scope"):
            continue  # same scope rule as persistence: never hand another module an off-target URL
        evidence = [
            f"Wayback Machine captured {rec['capture_count']} snapshot(s) of {rec['url']} "
            f"between {rec['first_observed_at']} and {rec['last_observed_at']} "
            f"(status codes seen: {rec['status_codes_seen']})",
            "HISTORICAL EVIDENCE ONLY: not an observation of the current attack surface.",
        ]
        export.append({
            "url": rec["url"],
            "parameters": extract_historical_parameters(rec),
            "evidence": evidence,
            "observed_at": rec["last_observed_at"],
            "source": MODULE_NAME,
            "historical": True,
        })
    return export


# ---------------------------------------------------------------------------
# Persistence of enriched historical findings
# ---------------------------------------------------------------------------

def persist_historical_findings(
    enriched_records: List[Dict[str, Any]],
    target: str,
    store: Optional[PendingAssetsStore],
) -> List[str]:
    """
    Persist one finding per in-scope historical URL and one per historical
    parameter. Never aborts on a single failure.

    Out-of-scope records are NOT persisted (context.md §16). The CDX API
    indexes the whole web and its rows are third-party data; a capture whose
    hostname is not the target or a subdomain of it does not belong in the
    target's asset graph regardless of how it reached the archive — ownership
    change, shared infrastructure, archive spam, or a provider-side matchType
    quirk. They are still returned to the caller in the run summary, so
    nothing is silently discarded.

    The whole batch is written with one atomic store operation rather than one
    write per finding: this module routinely produces thousands of records,
    and per-finding writes are quadratic in that count (see
    PendingAssetsStore.add_many).
    """
    findings: List[Dict[str, Any]] = []

    for rec in enriched_records:
        if not rec.get("in_scope"):
            continue

        # Graph identity for this observation. surface_mapper's _h_endpoint
        # takes value["url"] as the endpoint asset's identity, and _h_parameter
        # takes value["endpoint"]. Giving them different shapes — a full URL
        # with its query string here, a bare path there — minted TWO endpoint
        # assets for one endpoint, only one of which carried the `historical`
        # marker. The query string is parameters, and parameters are modelled
        # as their own assets, so the endpoint identity is the query-less
        # canonical URL and both findings use it. The captured URLs keep their
        # query strings under `captured_url`, `url_variants` and `snapshots`.
        endpoint_url = _strip_query(rec.get("canonical_url") or rec.get("url") or "")

        evidence = [
            f"Wayback CDX: {rec['capture_count']} capture(s) of {rec['url']} "
            f"(first {rec['first_observed_at']}, last {rec['last_observed_at']}, "
            f"status codes seen: {rec['status_codes_seen']})",
            # Stated on every record, because this is the one thing a reader
            # must not get wrong about it.
            f"HISTORICAL EVIDENCE ONLY: the Wayback Machine captured this URL in "
            f"the past. This is not an observation of the current attack surface, "
            f"and this module never contacts the target to check.",
        ]
        if rec.get("variant_count", 1) > 1:
            evidence.append(
                f"{rec['variant_count']} captured URL variant(s) differing only in "
                f"tracking parameters were merged into this record: {rec['url_variants']}"
            )
        findings.append(make_finding(
            # See HISTORICAL_URL_FINDING_TYPE: this is the type surface_mapper
            # marks `historical=True` and risk_engine has a §10-item-5 rule for.
            # The old-endpoint / deleted-path / static-asset distinction rides
            # along in `discovery_type`, which surface_mapper promotes to an
            # asset attribute.
            finding_type=HISTORICAL_URL_FINDING_TYPE,
            target=target,
            value={**rec, "url": endpoint_url, "captured_url": rec["url"]},
            evidence=evidence,
            confidence=rec["confidence"],
            metadata={
                "discovery_type": rec["discovery_type"],
                "relationship_to_current_surface": rec["relationship_to_current_surface"],
                "current_surface_compared": rec.get("current_surface_compared", False),
                "current_accessibility": rec["current_accessibility"],
                "historical": True,
                "path": rec["path"],
                "in_scope": rec["in_scope"],
                "capture_count": rec["capture_count"],
            },
        ))

        for param in extract_historical_parameters(rec):
            findings.append(make_finding(
                finding_type="historical_parameter",
                target=target,
                value={**param, "endpoint": endpoint_url, "url": endpoint_url,
                       "captured_url": rec["url"], "path": rec["path"], "historical": True},
                evidence=[
                    f"Query parameter {param['name']!r} observed in a historical capture of {rec['url']}",
                    "HISTORICAL EVIDENCE ONLY: the parameter existed on an archived "
                    "capture; whether the endpoint still accepts it is unverified.",
                ],
                confidence=CONFIDENCE_LOW,
                metadata={
                    "url": endpoint_url, "captured_url": rec["url"],
                    "endpoint": rec["path"], "name": param["name"],
                    "historical": True,
                },
            ))

    err = _safe_store_add_many(store, findings)
    return [err] if err else []


def persist_inconclusive_check(
    target: str,
    cdx_result: Dict[str, Any],
    store: Optional[PendingAssetsStore],
) -> List[str]:
    """
    Record that the historical check could not be completed.

    Without this, a CDX outage is indistinguishable downstream from "this
    domain has no archived URLs": the run summary carries zero historical
    records either way, and core/orchestrator.py's _invoke() marks any module
    that persisted no observations as STATUS_NO_RESULTS — literally "a check
    that found nothing is a result". A provider failure is not a result.

    The finding type deliberately avoids the "_checked_no" substring that
    surface_mapper._is_negative_result() keys on, so this can never be read as
    negative-result memory and can never suppress a re-check.
    """
    reason = cdx_result.get("error") or "the CDX query did not produce a usable result"
    error_class = cdx_result.get("error_class") or cdx_result.get("status") or "unknown"
    finding = make_finding(
        finding_type=INCONCLUSIVE_FINDING_TYPE,
        target=target,
        value={
            "check": "wayback_cdx_historical_urls",
            "outcome": "inconclusive",
            "status": cdx_result.get("status"),
            "error_class": error_class,
            "error": reason,
            "http_status": cdx_result.get("http_status"),
            "attempts": cdx_result.get("attempts", 0),
            "retries": cdx_result.get("retries", 0),
            "completeness": cdx_result.get("completeness", COMPLETENESS_INCONCLUSIVE),
        },
        evidence=[
            f"Wayback CDX historical-URL check of {target} was INCONCLUSIVE, not negative: {reason}",
            f"Provider outcome: status={cdx_result.get('status')}, error_class={error_class}, "
            f"attempts={cdx_result.get('attempts', 0)}",
            "This is NOT a negative result. No absence of historical URLs was established, "
            "so this must not be used to conclude the target has no archived history, and "
            "must not suppress re-checking.",
        ],
        confidence=CONFIDENCE_LOW,
        metadata={
            "outcome": "inconclusive",
            "error_class": error_class,
            "negative_result": False,
        },
    )
    err = _safe_store_add(store, finding)
    return [err] if err else []


# ---------------------------------------------------------------------------
# Module orchestration
# ---------------------------------------------------------------------------

def run_wayback_intel(
    target: str,
    output_dir: str = "output",
    base_url: str = DEFAULT_CDX_BASE_URL,
    match_type: str = DEFAULT_MATCH_TYPE,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    limit: int = DEFAULT_LIMIT,
    collapse: Optional[str] = DEFAULT_COLLAPSE,
    timeout: float = DEFAULT_TIMEOUT,
    current_urls: Optional[List[str]] = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    backoff: float = DEFAULT_BACKOFF_SECONDS,
) -> Dict[str, Any]:
    """
    Run all Module 5 wayback-intel checks against `target` and persist
    every discovery immediately to <output_dir>/pending_assets.json.

    Returns a structured summary, including `historical_data` — directly
    consumable by endpoint_discovery.py's
    correlate_historical_parameters(current_endpoints, historical_data=...,
    target=target, store=store).

    OUTCOME FIELDS AT THE TOP LEVEL — `status`, `conclusive`,
    `results_truncated`, `provider_failed`, `completeness` — are deliberately
    scalars, not nested inside `cdx_query`. core/orchestrator.py's
    _compact_stats() reduces a module summary to bools, numbers, list lengths
    and the single string key "status"; it drops nested dicts entirely. With
    the outcome only inside `cdx_query`, a CDX outage and a genuine "no
    archived URLs" answer produced byte-identical execution records
    (historical_urls_count=0, stats.unique_urls=0) and the failure was
    invisible to the orchestrator, the decision queue and the report.
    """
    target = validate_target(target)
    store = PendingAssetsStore(output_dir=output_dir)

    summary: Dict[str, Any] = {
        "target": target,
        "module": MODULE_NAME,
        "started_at": _now(),
        # Scalar outcome fields — see the docstring; these survive _compact_stats().
        "status": "error",
        "completeness": COMPLETENESS_INCONCLUSIVE,
        "conclusive": False,
        "results_truncated": False,
        "provider_failed": False,
        # Whether the historical records were actually compared against a
        # known current surface. This is a SEPARATE axis from `conclusive`
        # (which is about the completeness of the CDX result set): the archive
        # query can succeed completely while the comparison stage never runs,
        # and a reader of the compacted orchestrator record must be able to
        # tell that "historically removed" was never actually established.
        "current_surface_compared": False,
        "cdx_query": {},
        "historical_urls": [],
        "historical_data": [],
        "out_of_scope_urls": [],
        "stats": {},
        "errors": [],
    }

    try:
        cdx_result = fetch_cdx_snapshots(
            target, base_url=base_url, match_type=match_type,
            from_date=from_date, to_date=to_date, limit=limit,
            collapse=collapse, timeout=timeout,
            max_attempts=max_attempts, backoff=backoff,
        )
    except ScopeError:
        raise
    except Exception as exc:  # never let an unexpected exception abort the whole module
        summary["errors"].append({"stage": "cdx_query", "error": str(exc)})
        cdx_result = {
            "status": "error", "snapshots": [], "error": str(exc),
            "error_class": ERROR_CLASS_REQUEST_FAILED,
            "row_errors": [], "row_error_count": 0, "raw_row_count": 0,
            "truncated": False, "completeness": COMPLETENESS_INCONCLUSIVE,
            "conclusive": False, "query_url": None, "attempts": 0, "retries": 0,
        }

    summary["cdx_query"] = {k: v for k, v in cdx_result.items() if k != "snapshots"}
    summary["status"] = cdx_result.get("status", "error")
    summary["completeness"] = cdx_result.get("completeness", COMPLETENESS_INCONCLUSIVE)
    summary["conclusive"] = bool(cdx_result.get("conclusive", False))
    summary["results_truncated"] = bool(cdx_result.get("truncated", False))
    summary["provider_failed"] = cdx_result.get("status") in ("error", "rate_limited")

    if cdx_result.get("row_errors"):
        summary["errors"].append({
            "stage": "snapshot_normalization",
            "row_error_count": cdx_result.get("row_error_count", len(cdx_result["row_errors"])),
            "row_errors": cdx_result["row_errors"],
        })
    if cdx_result.get("truncated"):
        summary["errors"].append({
            "stage": "cdx_query",
            "error": f"result set reached limit={limit}; historical intelligence may be "
                     f"incomplete (the CDX API does not report how many rows it withheld, "
                     f"so this is possible truncation, not confirmed truncation)",
        })
    if summary["provider_failed"]:
        summary["errors"].append({"stage": "cdx_query", "error": cdx_result.get("error")})

    if cdx_result.get("status") != "found":
        # Only a provider failure is inconclusive. A clean, complete "the
        # archive has no captures for this domain" is a real negative result
        # and must not be recorded as a failed check.
        if summary["provider_failed"] or not summary["conclusive"]:
            persist_errors = persist_inconclusive_check(target, cdx_result, store)
            if persist_errors:
                summary["errors"].append({"stage": "persistence", "errors": persist_errors})
        summary["stats"] = {
            "total_snapshots": cdx_result.get("raw_row_count", 0),
            "unique_urls": 0,
            "in_scope_urls": 0,
            "out_of_scope_urls": 0,
            "currently_known": 0,
            "historically_removed_potentially_relevant": 0,
            "historically_removed": 0,
            "unknown_no_current_surface": 0,
            "row_errors": cdx_result.get("row_error_count", 0),
            "attempts": cdx_result.get("attempts", 0),
            "retries": cdx_result.get("retries", 0),
        }
        summary["finished_at"] = _now()
        return summary

    # A processing failure after a SUCCESSFUL fetch is the most dangerous
    # shape this module can produce: the provider answered, so `status` reads
    # "found" and `conclusive` reads True, while the record set is empty. That
    # is the exact claim this module must never make — "the archive was checked
    # completely and there is nothing there" — asserted on the strength of an
    # internal exception. Any loss here therefore downgrades completeness.
    processing_failed = False
    classified: List[Dict[str, Any]] = []
    try:
        grouped = group_historical_urls(cdx_result["snapshots"], target)
    except Exception as exc:
        summary["errors"].append({"stage": "grouping", "error": str(exc)})
        grouped = []
        processing_failed = True

    # Classify per record: one unclassifiable record must not discard the rest.
    classify_errors: List[str] = []
    for record in grouped:
        try:
            classified.append(classify_historical_url(record))
        except Exception as exc:
            if len(classify_errors) < MAX_ROW_ERRORS:
                classify_errors.append(f"{record.get('url')!r}: {exc}")
            processing_failed = True
    if classify_errors:
        summary["errors"].append({
            "stage": "classification",
            "error": f"{len(classify_errors)} historical record(s) could not be classified "
                     f"and are missing from the results",
            "records": classify_errors,
        })

    if processing_failed:
        summary["completeness"] = COMPLETENESS_INCONCLUSIVE
        summary["conclusive"] = False

    try:
        current_surface = load_current_surface(store=store, extra_urls=current_urls)
    except Exception as exc:
        summary["errors"].append({"stage": "current_surface_load", "error": str(exc)})
        current_surface = {"normalized_urls": set(), "canonical_urls": set(),
                           "host_paths": set(), "paths": set(), "skipped": []}
    summary["current_surface_compared"] = bool(
        current_surface.get("normalized_urls")
        or current_surface.get("canonical_urls")
        or current_surface.get("host_paths")
    )
    if current_surface.get("skipped"):
        summary["errors"].append({
            "stage": "current_surface_load",
            "error": f"{len(current_surface['skipped'])} persisted URL(s) could not be parsed "
                     f"and were excluded from the current-surface comparison",
            "skipped": current_surface["skipped"],
        })

    try:
        enriched = correlate_against_current_surface(classified, current_surface)
    except Exception as exc:
        summary["errors"].append({"stage": "correlation", "error": str(exc)})
        enriched = []
        processing_failed = True
        summary["completeness"] = COMPLETENESS_INCONCLUSIVE
        summary["conclusive"] = False
    in_scope = [r for r in enriched if r.get("in_scope")]
    out_of_scope = [r for r in enriched if not r.get("in_scope")]

    try:
        persist_errors = persist_historical_findings(enriched, target, store)
    except Exception as exc:
        persist_errors = [str(exc)]
        processing_failed = True
        summary["completeness"] = COMPLETENESS_INCONCLUSIVE
        summary["conclusive"] = False
    if persist_errors:
        summary["errors"].append({"stage": "persistence", "errors": persist_errors})
    if summary["results_truncated"] or cdx_result.get("row_error_count") or processing_failed:
        # The URLs found are real; the claim that they are ALL of them is not.
        marker = dict(cdx_result)
        if processing_failed:
            marker["error_class"] = "processing_error"
            marker["error"] = (
                "the CDX response was retrieved, but this module failed while grouping or "
                "classifying it, so an unknown number of historical URLs are missing"
            )
            marker["completeness"] = COMPLETENESS_INCONCLUSIVE
        persist_errors = persist_inconclusive_check(target, marker, store)
        if persist_errors:
            summary["errors"].append({"stage": "persistence", "errors": persist_errors})
    if out_of_scope:
        summary["errors"].append({
            "stage": "scope_enforcement",
            "error": f"{len(out_of_scope)} historical URL(s) whose hostname is outside "
                     f"{target} — or which have no resolvable hostname at all, where scope "
                     f"cannot be established and the check therefore fails closed — were "
                     f"returned by the CDX API and were NOT persisted to the target's asset "
                     f"graph (context.md §16); they are reported under out_of_scope_urls",
        })

    summary["historical_urls"] = enriched
    summary["out_of_scope_urls"] = [r.get("url") for r in out_of_scope]
    try:
        summary["historical_data"] = build_historical_data_export(enriched)
    except Exception as exc:
        summary["errors"].append({"stage": "historical_data_export", "error": str(exc)})
        summary["historical_data"] = []
        summary["completeness"] = COMPLETENESS_INCONCLUSIVE
        summary["conclusive"] = False
    summary["stats"] = {
        "total_snapshots": cdx_result.get("raw_row_count", 0),
        "unique_urls": len(enriched),
        "in_scope_urls": len(in_scope),
        "out_of_scope_urls": len(out_of_scope),
        "currently_known": sum(1 for r in in_scope if r["relationship_to_current_surface"] == STATE_CURRENTLY_KNOWN),
        "historically_removed_potentially_relevant": sum(
            1 for r in in_scope if r["relationship_to_current_surface"] == STATE_POTENTIALLY_RELEVANT
        ),
        "historically_removed": sum(
            1 for r in in_scope if r["relationship_to_current_surface"] == STATE_HISTORICALLY_REMOVED
        ),
        "unknown_no_current_surface": sum(
            1 for r in in_scope if r["relationship_to_current_surface"] == STATE_UNKNOWN_NO_CURRENT_SURFACE
        ),
        "merged_tracking_variants": sum(max(0, r.get("variant_count", 1) - 1) for r in in_scope),
        "row_errors": cdx_result.get("row_error_count", 0),
        "attempts": cdx_result.get("attempts", 0),
        "retries": cdx_result.get("retries", 0),
    }
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="wayback_intel.py",
        description="ReconHound Module 5 — historical web intelligence via the Wayback Machine "
                     "(standalone test entry point).",
    )
    parser.add_argument("--target", required=True, help="Target domain, e.g. example.com")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-query network timeout (seconds)")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Max CDX rows to request")
    parser.add_argument("--from-date", default=None, help="CDX 'from' filter, e.g. 20200101")
    parser.add_argument("--to-date", default=None, help="CDX 'to' filter, e.g. 20231231")
    parser.add_argument("--match-type", default=DEFAULT_MATCH_TYPE, choices=_VALID_MATCH_TYPES)
    args = parser.parse_args()

    try:
        result = run_wayback_intel(
            args.target, output_dir=args.output_dir, timeout=args.timeout, limit=args.limit,
            from_date=args.from_date, to_date=args.to_date, match_type=args.match_type,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
