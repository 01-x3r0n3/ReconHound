"""
reconhound/exposure_scan.py — ReconHound Module 15 (exposure_scan.py),
build-order position 7.

Phase: Active. See context.md §10 (module 15, "Sensitive resource/info
exposure") for the authoritative responsibilities, and §8 for the
evidence/confidence data model this module implements. This file only
documents implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Sensitive resource/info exposure. Exposed .git, .env, backups, archives,
  DB dumps, config files, debug pages, admin panels, robots.txt,
  sitemap.xml, cloud misconfig (S3/GCS/Azure Blob) incl. authorized live
  listability checks, error-page intel (stack traces, framework versions,
  internal paths), per-endpoint HTTP OPTIONS discovery."

That expands (per the assignment brief) into five discrete responsibility
groups, each implemented below:

  1. Sensitive resource discovery   -> classify_exposure_category,
                                        discover_sensitive_resources
  2. Application exposure discovery -> discover_sensitive_resources
                                        (debug/admin categories),
                                        discover_robots_txt,
                                        discover_sitemap_xml
  3. Cloud exposure discovery       -> generate_cloud_candidates,
                                        check_cloud_resource,
                                        discover_cloud_exposure
  4. Error-page intelligence        -> analyze_error_page
  5. HTTP OPTIONS discovery         -> probe_options, discover_http_options

Plus shared plumbing: fetch_url, fetch_options, PendingAssetsStore,
make_finding, load_wordlist, and a single-target orchestrator
run_exposure_scan (mirroring the run_passive_recon / run_active_recon /
run_http_analysis / run_endpoint_discovery / run_crawler precedent — not
itself a listed context.md responsibility).

Implementation decisions (ambiguities resolved so implementation can
proceed without redesigning anything context.md defines):

  1. Sensitive-resource candidates are drawn from the existing
     wordlists/directories.txt (the same file endpoint_discovery.py
     enumerates generically) rather than a new wordlist file — context.md
     §11's folder structure defines exactly one directory/file wordlist,
     and this module does not invent a second one. classify_exposure_category()
     filters that file down to the subset of entries that name a
     recognized exposure category (version control, environment file,
     backup, archive, database dump, configuration file, credential
     material, debug endpoint, administrative panel, log file); generic,
     non-sensitive entries (assets/, images/, static/, etc.) are skipped
     here — full directory/file enumeration is endpoint_discovery.py's
     named responsibility, not this module's.
  2. Path name alone never determines "confirmed exposure"; neither does a
     header, a status code, or a body that merely parses (assignment
     brief: "classified according to observed evidence rather than path
     name alone"). evaluate_exposure() applies a category-specific content
     signature check (e.g. ".git/HEAD" must actually contain a git ref or
     SHA; ".env" must actually contain dotenv-style KEY=VALUE lines; a
     ".sql" dump must actually contain SQL-dump markers or dump-file magic
     bytes) before returning "confirmed_exposure". Without a matching
     signature, a non-404 hit is downgraded to "interesting_unconfirmed"
     rather than claimed as confirmed. A directory-listing check (Apache/
     nginx "Index of /", Python http.server, IIS) is applied to every
     candidate independent of category, since an autoindex is itself
     direct, unambiguous evidence of exposure — it is therefore reported
     with discovery_type "confirmed_exposure" plus an explicit autoindex
     evidence line, rather than with a private discovery type of its own.
     (It previously used the type "directory_listing_enabled", for which no
     downstream consumer has a rule, so a directory listing of /backup/ or
     /.ssh/ — about as direct as exposure evidence gets — produced no risk
     signal at all.) The listing patterns are anchored to the markup
     position each server actually emits them in, so a page that merely
     mentions "Index of /" is not mistaken for one.
  3. Same soft-404 baseline heuristic as endpoint_discovery.py's decision
     #2, reused here for the same reason: guessed wordlist paths are
     frequently wrong, and many apps return HTTP 200 with a generic/SPA/
     catch-all page instead of a real 404. BASELINE_PROBE_COUNT random
     probes of differing path length are taken per origin, so a *dynamic*
     catch-all is recognised as such and compared structurally rather than
     byte-wise; a baseline that cannot be taken, or whose probes disagree,
     is marked unavailable and nothing is compared against it. A candidate
     is suppressed as `possible_soft_404_match` only when its content is
     genuinely indistinguishable from that baseline — length proximity
     alone is NOT sufficient (it used to be, which silently downgraded
     real finds whose size happened to land near the catch-all page's),
     and the category content signature is evaluated first. Documented as
     a best-effort heuristic, not exhaustive.
  4. Cloud exposure discovery inherently targets infrastructure outside
     the operator's own domain (*.s3.amazonaws.com, storage.googleapis.com,
     *.blob.core.windows.net) — domain-suffix scope matching against
     `target` (as used everywhere else in ReconHound) cannot express
     authorization for those hosts. Per the assignment brief ("Only
     perform live bucket-listability checks when the target/resource is
     explicitly within the configured authorized scope"), this module
     defines that authorization as an explicit, caller-supplied
     `cloud_targets` list (bucket/container identifiers or full URLs the
     operator has explicitly put in scope for this run) — the same
     "explicit, optional, caller-supplied parameter" pattern
     endpoint_discovery.py already established for
     technology/historical_data/js_data (its decision #1). A GET against a
     cloud storage bucket root *is* its own listability check (S3/GCS
     return an XML enumeration if public; Azure returns one if the
     container allows anonymous listing) — there is no lesser-effort
     "existence only" probe distinct from the check itself, so no request
     is made against provider infrastructure unless an item explicitly
     appears in `cloud_targets`. Common bucket-name permutations derived
     from `target` are still generated (generate_cloud_candidates) for
     visibility, but recorded as `candidate_not_probed` (no request made)
     unless the operator also authorized that specific identifier.
  5. HTTP OPTIONS discovery (context.md's only explicit non-GET method
     across the whole active-phase module set) needs a set of "relevant
     discovered endpoints" to probe. No orchestrator exists yet to wire
     endpoint_discovery.py/crawler.py output through automatically (same
     gap endpoint_discovery.py's decision #1 and crawler.py's decision #1
     describe), so `run_exposure_scan` accepts an optional, caller-supplied
     `endpoints` list (the eventual endpoint_discovery.py/crawler.py
     output) using that same pattern, and additionally runs OPTIONS against
     every URL its own sweep surfaced as present (see
     _OPTIONS_WORTHY_TYPES: confirmed, interesting-unconfirmed,
     access-restricted or redirecting) — a natural, self-contained
     "relevant discovered endpoints" set requiring no external wiring.
     Paths that were answered 404 or matched the catch-all baseline are
     excluded, and the phase as a whole is capped
     (DEFAULT_MAX_OPTIONS_URLS) and charged to the run's request budget:
     against a host that answers 200 to everything, following every
     candidate with an OPTIONS request doubled the run's request count for
     no information. Every URL — caller-supplied ones especially — is
     re-validated through validate_discovered_url() first.
  6. Error-page intelligence (analyze_error_page) is applied opportunistically
     to response bodies this module already fetched for another reason —
     never by sending an extra or deliberately malformed request purely to
     provoke an error, per the assignment brief's explicit "do not
     intentionally trigger destructive or abusive errors" boundary. It runs
     at most once per candidate, and not at all for a path that turned out
     to be a 404 or a catch-all match: its framework patterns are the most
     expensive thing this module runs against an attacker-controlled body,
     and most probed paths do not exist.
  7. Only GET and OPTIONS requests are made (OPTIONS being this module's
     one explicitly named responsibility). No state-changing methods; no
     authentication attempts against discovered panels/credential files;
     no bucket writes/deletes; discovered ".env"/credential-shaped content
     is recorded as evidence text (truncated to MAX_EXCERPT_CHARS *and*
     redacted, see redact_sensitive_text) for manual verification, never
     parsed for literal secret values and never used to authenticate
     anywhere — this module discovers exposure, it does not exploit it.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other module). Records that are not discoveries are deliberately NOT
persisted: a 404 or a catch-all match is counted as a negative result, and a
429 or a transport failure is counted as "not tested" (see
_NEGATIVE_TYPES / _NON_EVIDENTIAL_TYPES). Persisting either minted one
phantom finding asset per wordlist entry in surface_mapper.py against a
rate-limiting or catch-all host.

Output feeds surface_mapper.py, which routes `exposure_finding`,
`error_page_intelligence` and `cloud_resource_finding` to its generic
finding handler and treats `exposure_scan_checked_no_exposure` /
`cloud_candidate_not_probed` as negative-result memory. risk_engine.py keys
on `discovery_type == "confirmed_exposure"` plus `exposure_category`, which
is why the confirmation rules above are strict. This module does not
implement or call into surface_mapper, http_analyzer, ssl_analyzer,
wayback_intel, vuln_intel, risk_engine, orchestrator or report_generator.

SECURITY / RESOURCE BOUNDARIES enforced by this module (each one closes a
defect reproduced against the previous implementation, and each is covered
by a regression test):

  * Scope. Control characters are rejected rather than silently stripped by
    urlsplit; hostnames are IDNA-normalised before comparison so an IDN and
    its A-label form cannot look like different hosts; `user:password@`
    credentials are stripped from every URL before it is requested, recorded
    or persisted. A URL this module did not get directly from the operator —
    a caller-supplied `endpoints` entry, a URL built from a wordlist line —
    additionally passes validate_discovered_url(), which accepts a bare IP
    literal only when it *is* the target: an in-scope page must not be able
    to steer this module's probes at 169.254.169.254 or at RFC1918 hosts.
    Redirects are never followed anywhere in this module, so a redirect
    cannot escape scope either.
  * Cloud identifiers. A bucket/container name is validated against the
    provider's own charset and the *resulting URL's host* is verified before
    any request: interpolating an unvalidated identifier let an entry of
    "evil.com/" turn "https://{id}.s3.amazonaws.com/" into a request against
    evil.com, and an Azure container of "c?comp=list" inject its own query.
  * Evidence strength. "confirmed_exposure" — the exact string
    risk_engine.py scores as a CRITICAL/HIGH confirmed finding — requires
    direct content evidence: a category signature in the body actually
    returned, or an autoindex listing. A Content-Type header claiming an
    archive, a JSON body that merely parses, a single "word: value" line and
    an administrative login page are all explicitly NOT confirmations.
  * Secrets. This module deliberately fetches .env/htpasswd/config/dump
    bodies. Every excerpt that leaves it is passed through
    redact_sensitive_text() first, because pending_assets.json is shared with
    every module and rendered verbatim in the report's raw-data appendix
    (CLAUDE.md rule 16). Key names survive; values do not.
  * Resources. One request budget covers the whole run (sweep, baseline
    probes, robots, sitemap, cloud, OPTIONS); response bodies are read
    bounded even on the fallback path, so a decompression bomb cannot be
    materialised; OPTIONS follow-ups are capped; and every regex applied to
    an attacker-controlled body is bounded (an unbounded
    "Fatal error:.*?on line N" cost ~4s of CPU per hostile 128 KB response).
  * Failure semantics. A refusal is never absence. 401/403/429/5xx/timeouts
    are outcomes distinct from 404/410, an untested path never becomes a
    negative result, and `exposure_scan_checked_no_exposure` (surface_mapper's
    "checked and not found" memory) is emitted only when every scheduled
    candidate was actually answered against a usable baseline within budget.

DISCOVERY != CONFIRMED VULNERABILITY: every record here is an observation
(a path returned certain bytes, a bucket's XML said "AccessDenied", a
header advertised a method). None of this module's output — including
"confirmed_exposure" records — should be read as "exploited" or a
statement that the underlying data was actually read/exfiltrated beyond
what the HTTP response itself already disclosed. That risk assessment
belongs to vuln_intel.py / risk_engine.py.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import threading
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

MODULE_NAME = "exposure_scan.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_USER_AGENT = "ReconHound-ExposureScan/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_MAX_BODY_BYTES = 131072
DEFAULT_MAX_WORKERS = 10
DEFAULT_MAX_REQUESTS = 400
MAX_EXCERPT_CHARS = 200

# Upper bound on how many URLs one OPTIONS phase will probe. `endpoints` is
# caller-supplied (endpoint_discovery.py/crawler.py output routed through the
# orchestrator) and the module's own sweep contributes one URL per non-404
# candidate, so without a cap a catch-all host that answers 200 to every
# wordlist entry turned a 400-request sweep into a further 400 OPTIONS
# requests, and a large caller-supplied list was unbounded outright.
DEFAULT_MAX_OPTIONS_URLS = 100

# Ceiling on recorded per-request errors. Against a host that refuses every
# connection the error list previously grew one entry per candidate and was
# then persisted and rendered in full; the count is still reported exactly.
MAX_RECORDED_ERRORS = 200

# Consecutive transport-level failures (timeout, connection refused, DNS
# failure — never an HTTP response of any status) after which the scan stops,
# and only while no probe in this run has ever been answered. An origin that
# answers nothing answers nothing per path, so every remaining candidate
# costs a full `timeout` and can produce no observation. One answered probe
# disarms the tripwire permanently, and a tripped scan is never
# `scan_complete`, so nothing is recorded as a negative result.
TRANSPORT_FAILURE_TRIP_THRESHOLD = 12

# Fields of one OPTIONS result that describe *this request* rather than the
# endpoint. They are kept as observation metadata but never put in a
# finding's `value`: surface_mapper.py derives a finding asset's identity
# from a hash of that value, so this run's clock or a per-request CDN trace
# id there splits the asset on every re-scan.
_VOLATILE_OPTIONS_KEYS = ("timestamp", "response_provenance_headers")
_PROVENANCE_EVIDENCE_PREFIX = "response provenance headers: "

# Ceiling on the aggregated per-run error list. Every phase caps its own
# errors, but the summary concatenates all of them and is itself returned to
# the orchestrator and rendered.
MAX_SUMMARY_ERRORS = 500

# Number of random probes used to fingerprint a host's "this does not exist"
# response, and how much of each probe body is retained for comparison.
# Two probes of deliberately different path lengths is the minimum that can
# tell a *static* catch-all (both bodies identical) from a *dynamic* one
# (bodies differ per request) — comparing a candidate against a single dynamic
# sample is meaningless. Mirrors endpoint_discovery.py's BASELINE_PROBE_COUNT
# rationale.
BASELINE_PROBE_COUNT = 2

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)

# Discovery-type vocabulary. Named constants because both this module's
# persistence gates and risk_engine.py's rules key on these exact strings
# (risk_engine.py's `_CONFIRMED_EXPOSURE` is DT_CONFIRMED below), so a typo in
# either silently changes what the pipeline reports.
DT_CONFIRMED = "confirmed_exposure"
DT_INTERESTING = "interesting_unconfirmed"
DT_ACCESS_RESTRICTED = "access_restricted"
DT_NOT_FOUND = "not_found"
DT_REDIRECT = "redirect"
DT_METHOD_NOT_ALLOWED = "method_not_allowed"
DT_SERVER_ERROR = "server_error_response"
DT_RATE_LIMITED = "rate_limited"
DT_UNEXPECTED_STATUS = "unexpected_status"
DT_SOFT_404 = "possible_soft_404_match"
DT_ERROR = "error"

# Outcomes that mean "this path was never actually tested". They are neither a
# discovery nor a negative result, and must never contribute to
# negative-result memory (context.md §8: a scanner failure is not "checked and
# not found").
_INCONCLUSIVE_TYPES = frozenset({DT_ERROR, DT_RATE_LIMITED, DT_SERVER_ERROR, DT_UNEXPECTED_STATUS})

# Outcomes that are NOT evidence that anything is exposed at this path, and
# must therefore never become an `exposure_finding` record. A 429 means the
# server refused to answer; `error` means no answer arrived at all. Persisting
# either mints one phantom finding asset per wordlist entry in
# surface_mapper.py against a rate-limiting or unhealthy host — the same
# "request failure == presence" bug endpoint_discovery.py documents. They are
# counted and reported instead (see `candidates_untested`).
_NON_EVIDENTIAL_TYPES = frozenset({DT_ERROR, DT_RATE_LIMITED})

# Genuine negative results: the path was tested and nothing is there. Counted
# as negative-result memory, not persisted as findings.
_NEGATIVE_TYPES = frozenset({DT_NOT_FOUND, DT_SOFT_404})

# Evidence lines that record a signature match the soft-404 comparison
# overruled. A soft-404 that nonetheless carries a category signature is a
# genuine contradiction, and context.md §8 requires contradictions to be
# preserved rather than dropped — such a record is kept even though ordinary
# soft-404 matches are not.
_SUPPRESSED_PREFIX = "suppressed "

# ---------------------------------------------------------------------------
# Sensitive-resource categories (responsibility group 1/2)
# ---------------------------------------------------------------------------

CATEGORY_VERSION_CONTROL = "version_control"
CATEGORY_ENVIRONMENT_FILE = "environment_file"
CATEGORY_BACKUP_FILE = "backup_file"
CATEGORY_ARCHIVE_FILE = "archive_file"
CATEGORY_DATABASE_DUMP = "database_dump"
CATEGORY_CONFIGURATION_FILE = "configuration_file"
CATEGORY_CREDENTIAL_MATERIAL = "credential_material"
CATEGORY_DEBUG_ENDPOINT = "debug_endpoint"
CATEGORY_ADMINISTRATIVE_PANEL = "administrative_panel"
CATEGORY_LOG_FILE = "log_file"

# Ordered (pattern, category) rules applied to a raw wordlist entry
# (case-insensitive). First match wins. Entries matching none of these are
# skipped by this module entirely (see module docstring, decision #1).
_CATEGORY_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"^\.git/", re.I), CATEGORY_VERSION_CONTROL),
    (re.compile(r"^\.svn/", re.I), CATEGORY_VERSION_CONTROL),
    (re.compile(r"^\.gitignore$", re.I), CATEGORY_VERSION_CONTROL),
    (re.compile(r"^\.env", re.I), CATEGORY_ENVIRONMENT_FILE),
    (re.compile(r"^\.htpasswd$", re.I), CATEGORY_CREDENTIAL_MATERIAL),
    (re.compile(r"^\.aws/", re.I), CATEGORY_CREDENTIAL_MATERIAL),
    (re.compile(r"^\.ssh/", re.I), CATEGORY_CREDENTIAL_MATERIAL),
    (re.compile(r"\.sql$", re.I), CATEGORY_DATABASE_DUMP),
    (re.compile(r"\.(zip|tar\.gz|tgz|7z|rar|gz)$", re.I), CATEGORY_ARCHIVE_FILE),
    (re.compile(r"\.bak$", re.I), CATEGORY_BACKUP_FILE),
    (re.compile(r"^(admin|administrator|console)/$", re.I), CATEGORY_ADMINISTRATIVE_PANEL),
    (re.compile(r"^debug/$", re.I), CATEGORY_DEBUG_ENDPOINT),
    (re.compile(r"^(phpinfo|info|test)\.php$", re.I), CATEGORY_DEBUG_ENDPOINT),
    (re.compile(r"^server-(status|info)$", re.I), CATEGORY_DEBUG_ENDPOINT),
    (re.compile(r"^(status|health|healthz|version|version\.json)$", re.I), CATEGORY_DEBUG_ENDPOINT),
    (re.compile(r"^(config\.(json|php|yml|yaml)|settings\.(py|json)|web\.config|appsettings\.json)$", re.I),
     CATEGORY_CONFIGURATION_FILE),
    (re.compile(r"^\.htaccess$", re.I), CATEGORY_CONFIGURATION_FILE),
    (re.compile(r"^(docker-compose\.yml|Dockerfile|\.dockerignore)$", re.I), CATEGORY_CONFIGURATION_FILE),
    (re.compile(r"^(composer\.(json|lock)|package(-lock)?\.json|yarn\.lock)$", re.I), CATEGORY_CONFIGURATION_FILE),
    (re.compile(r"^crossdomain\.xml$", re.I), CATEGORY_CONFIGURATION_FILE),
    (re.compile(r"(error[_.]log|debug\.log|access\.log|laravel\.log|\.log)$", re.I), CATEGORY_LOG_FILE),
    (re.compile(r"^(backup|backups|old)/$", re.I), CATEGORY_BACKUP_FILE),
]

# Directories worth an exposure-focused HEAD-of-the-list probe beyond the
# generic category rules above (recorded under CATEGORY_CREDENTIAL_MATERIAL /
# CATEGORY_VERSION_CONTROL for the sole purpose of a directory-listing check
# — see detect_directory_listing).
_SENSITIVE_DIRECTORIES: Dict[str, str] = {
    ".aws/": CATEGORY_CREDENTIAL_MATERIAL,
    ".ssh/": CATEGORY_CREDENTIAL_MATERIAL,
}


class ScopeError(ValueError):
    """Raised when a URL/target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


class WordlistError(RuntimeError):
    """Raised when a required wordlist file cannot be loaded or contains no usable entries."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors endpoint_discovery.py's validate_endpoint_target
# / crawler.py's validate_crawl_target; duplicated per modular independence,
# context.md §12.2)
# ---------------------------------------------------------------------------

def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _idna_normalize(host: str) -> str:
    """
    Reduce a hostname to the single form scope comparisons are made in.

    Without this a target written as "münchen.de" and a hostname arriving as
    "xn--mnchen-3ya.de" (or the reverse) compare unequal even though they are
    the same host — an IDN mismatch that drops in-scope assets in one
    direction and lets a homograph host look "different" from the target it
    impersonates in the other. Mirrors endpoint_discovery.py's helper of the
    same name; anything that will not encode is returned lowercased unchanged
    so the comparison stays deterministic.
    """
    host = host.strip().rstrip(".").lower()
    if not host or host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return host


def _in_scope_host(hostname: str, target: str) -> bool:
    hostname = _idna_normalize(hostname)
    target = _idna_normalize(target)
    if not hostname or not target:
        return False
    return hostname == target or hostname.endswith("." + target)


def _strip_userinfo(url: str) -> str:
    """
    Remove any `user:password@` component from a URL.

    URLs reach this module from caller-supplied endpoint lists and from
    operator-supplied base URLs, so credentials genuinely turn up in them.
    They must not be re-sent, must not become part of a finding's identity,
    and above all must never be written into pending_assets.json — a
    plain-text file shared with every other module and rendered verbatim in
    report_generator.py's raw-data appendix (CLAUDE.md rule 16). Mirrors
    endpoint_discovery.py's helper of the same name.
    """
    parsed = urllib.parse.urlsplit(url)
    if "@" not in parsed.netloc:
        return url
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"          # bare IPv6 literal
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def _host_allowed(hostname: str, target: Optional[str]) -> bool:
    """
    Scope gate for a host this module learned from *content or a caller*
    rather than from the operator's own --url argument.

    validate_exposure_target() lets a bare IP literal through unchecked
    because an operator naming an IP has authorised that IP upstream. That
    reasoning does not carry over to a URL handed in through
    `run_exposure_scan(endpoints=...)`: those come from
    endpoint_discovery.py/crawler.py, i.e. ultimately from response bodies,
    and following one unconditionally meant an in-scope page could steer this
    module's OPTIONS probes at 169.254.169.254 (cloud instance metadata), at
    RFC1918 hosts, or at any other third party — an authorisation-boundary
    violation. An IP literal from content is therefore accepted only when it
    *is* the operator-supplied target. Mirrors endpoint_discovery.py.
    """
    if not hostname or not target:
        return False
    if _is_ip_literal(hostname):
        return _idna_normalize(hostname) == _idna_normalize(target)
    return _in_scope_host(hostname, target)


def validate_exposure_target(url: str, target: Optional[str] = None) -> str:
    """
    Validate that `url` is a syntactically valid http(s) URL, and — if
    `target` is supplied — that its hostname is the target itself or a
    subdomain of it (an IP-literal host is allowed through without an
    in-scope check, matching the rest of ReconHound's active modules:
    IP scope is authorised upstream, not by a domain comparison here).

    Any `user:password@` component is stripped from the returned URL rather
    than rejected — the URL is legitimate, re-sending and persisting the
    credential is not.

    This governs the target's own web surface only. Cloud storage
    resources (S3/GCS/Azure hostnames) are never in-scope under this
    function — see check_cloud_resource / discover_cloud_exposure and
    module docstring decision #4.
    """
    if not isinstance(url, str) or not url.strip():
        raise ScopeError("URL must be a non-empty string.")

    candidate = url.strip()
    # A CR, LF, NUL or tab inside a URL is never legitimate. urlsplit silently
    # *removes* newlines and tabs before parsing, so a wordlist entry or a
    # caller-supplied URL containing them would be scope-checked in its
    # stripped form and then handed to requests still carrying the raw bytes —
    # the parsed host and the requested host are not the same string. Rejecting
    # here keeps request construction unambiguous.
    if any(ch in candidate for ch in "\r\n\t\x00"):
        raise ScopeError(f"URL contains control characters: {url!r}")

    try:
        parsed = urllib.parse.urlsplit(candidate)
        hostname = parsed.hostname
    except ValueError as exc:
        # urlsplit raises on malformed IPv6 brackets and out-of-range ports.
        raise ScopeError(f"URL cannot be parsed: {url!r} ({exc})") from exc

    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"URL must use http:// or https://, not {parsed.scheme!r}: {url!r}")

    if not hostname:
        raise ScopeError(f"URL must include a hostname: {url!r}")

    if target and not _is_ip_literal(hostname) and not _in_scope_host(hostname, target):
        raise ScopeError(f"URL host {hostname!r} is not in scope for target {target!r}: {url!r}")

    return _strip_userinfo(candidate)


def validate_discovered_url(url: str, target: Optional[str]) -> str:
    """
    validate_exposure_target() for a URL this module did not get from the
    operator directly (a caller-supplied `endpoints` entry, a URL built from a
    wordlist line). Adds the _host_allowed() gate, so an IP literal is
    accepted only when it is the target itself.
    """
    candidate = validate_exposure_target(url, target=target)
    if target:
        hostname = urllib.parse.urlsplit(candidate).hostname or ""
        if not _host_allowed(hostname, target):
            raise ScopeError(
                f"URL host {hostname!r} is not an authorised host for target {target!r} "
                f"(discovered/caller-supplied URLs may not name unrelated IP literals): {url!r}"
            )
    return candidate


# ---------------------------------------------------------------------------
# Evidence-model helpers (mirrors the other modules' model; kept local per
# modular independence)
# ---------------------------------------------------------------------------

def _jsonify(value: Any, _depth: int = 0) -> Any:
    """
    Coerce a value into something json.dump can definitely write.

    Findings carry data this module did not create — `cloud_targets` entries
    supplied by the operator/orchestrator are echoed back into
    cloud_resource_finding records, and caller-supplied endpoint URLs into
    OPTIONS records. A single value json.dump cannot serialise used to raise
    TypeError *outside* the persistence guard, aborting the whole phase and
    discarding results that were already complete. Coercing at construction
    time means every finding this module emits is writable by definition.

    Mirrors endpoint_discovery.py/passive_recon.py, which share this file.
    """
    if _depth > 12:
        return str(value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        # NaN/Infinity are accepted by json.dump but produce invalid JSON that
        # a strict reader (including this module's own _read_all) rejects.
        return value if value == value and value not in (float("inf"), float("-inf")) else str(value)
    if isinstance(value, dict):
        return {str(k): _jsonify(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonify(v, _depth + 1) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


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
        "value": _jsonify(value),
        "evidence": [_jsonify(e) for e in evidence],
        "confidence": confidence,
        "source": MODULE_NAME,
        "timestamp": _now(),
        "metadata": _jsonify(metadata or {}),
    }


# ---------------------------------------------------------------------------
# Crash-safe persistence (same file/format as the other modules'
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
        # append does not have to re-encode the whole file (see add_many).
        # `_stamp` is the (mtime_ns, size) of the file as this store last left
        # it; anything else means somebody else wrote it and the cache is void.
        self._serialized: Optional[str] = None
        self._stamp: Optional[Tuple[int, int]] = None
        os.makedirs(self.output_dir, exist_ok=True)

    def _current_stamp(self) -> Optional[Tuple[int, int]]:
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
        except (json.JSONDecodeError, ValueError) as exc:
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

        add() re-read, re-encoded and rewrote the entire shared file per
        finding, which is quadratic in the number of records already on disk —
        and pending_assets.json already holds every earlier module's output by
        the time this module runs. Measured on this repository with the
        previous implementation: 100 findings 0.19s, 300 0.91s, 600 3.49s. One
        probed candidate emits up to two records (the exposure finding plus its
        error-page intelligence), so batching a candidate's records into one
        write keeps a full 400-request sweep linear in practice.

        Crash-safety is unchanged and slightly stronger: still one
        write-to-temp + os.replace, so a batch is all-or-nothing rather than
        half-applied. Mirrors endpoint_discovery.py/active_recon.py, which
        share this output file. Returns the number of findings written.
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
# fills or the path loses permissions (OSError), or a caller-supplied
# cloud_targets/endpoints payload carries a value json.dump cannot serialise
# (TypeError/ValueError). Catching only PersistenceError meant those escaped
# the guard, killed the worker task, and took the *completed discovery* down
# with them — the one outcome context.md §12.11 forbids. Mirrors
# endpoint_discovery.py.
_PERSISTENCE_FAILURES = (PersistenceError, OSError, TypeError, ValueError)


def _safe_store_add(store: Optional["PendingAssetsStore"], finding: Dict[str, Any]) -> Optional[str]:
    """
    store.add() wrapped so a single persistence failure doesn't abort the
    scan. Returns None on success, or an error message the caller is
    responsible for recording (never silently discarded).
    """
    if store is None:
        return None
    try:
        store.add(finding)
        return None
    except _PERSISTENCE_FAILURES as exc:
        return str(exc)


def _safe_store_add_many(
    store: Optional["PendingAssetsStore"], findings: List[Dict[str, Any]],
) -> Optional[str]:
    """
    store.add_many() wrapped identically to _safe_store_add. The in-memory
    findings are never discarded because persistence failed.
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


def _origin_of(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else url + "/"


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4 dot-segment removal, so "a/../../b" cannot climb above the root."""
    out: List[str] = []
    for segment in path.split("/"):
        if segment == ".":
            continue
        if segment == "..":
            if out:
                out.pop()
            continue
        out.append(segment)
    return "/".join(out)


def _url_for_path(root: str, entry: str) -> str:
    """
    Build the absolute URL for one wordlist entry under `root`.

    urljoin() alone is not a scope boundary: an entry that is itself an
    absolute URL ("https://evil.com/") replaces the root outright, and a
    "../.." entry climbs above it. Wordlists live on disk and are only
    semi-trusted (context.md §16 requires scope enforcement "wherever
    technically possible"), so the entry is reduced to a relative path with
    its dot segments already resolved before it is joined. The caller still
    validates the result — see _candidate_url.
    """
    root = _ensure_trailing_slash(root)
    relative = _remove_dot_segments(entry.lstrip("/"))
    return urllib.parse.urljoin(root, relative)


def _candidate_url(root: str, entry: str, target: Optional[str]) -> str:
    """`_url_for_path` plus the discovered-URL scope gate. Raises ScopeError."""
    if not isinstance(entry, str) or not entry.strip():
        raise ScopeError("wordlist entry must be a non-empty string")
    if any(ch in entry for ch in "\r\n\t\x00"):
        raise ScopeError(f"wordlist entry contains control characters: {entry!r}")
    url = _url_for_path(root, entry)
    if not url.startswith(_ensure_trailing_slash(_origin_of(root))):
        raise ScopeError(f"wordlist entry {entry!r} resolves outside {root!r}: {url!r}")
    return validate_discovered_url(url, target)


def _looks_textual(content_type: Optional[str], body: Optional[str]) -> bool:
    """Best-effort textual-content check so binary responses aren't parsed as text."""
    if not body:
        return False
    if content_type:
        ct = content_type.lower()
        if any(t in ct for t in ("html", "json", "xml", "javascript", "text")):
            return True
        if any(
            t in ct for t in (
                "image/", "video/", "audio/", "font/", "application/octet-stream",
                "application/zip", "application/pdf", "application/gzip",
            )
        ):
            return False
    return True


def _content_signature(body: str) -> Tuple[int, str]:
    import hashlib
    normalized = re.sub(r"\s+", " ", body).strip()
    digest = hashlib.md5(normalized.encode("utf-8", errors="ignore")).hexdigest()
    return len(normalized), digest


def _lengths_close(a: Optional[int], b: Optional[int], tolerance: int = 25) -> bool:
    if a is None or b is None:
        return False
    return abs(a - b) <= tolerance


# ---------------------------------------------------------------------------
# Secret redaction (mirrors js_analyzer.py's / code_leak.py's model,
# duplicated per modular independence)
# ---------------------------------------------------------------------------
#
# This module deliberately fetches the bodies of .env files, htpasswd files,
# configuration files and database dumps. Persisting an excerpt of one
# verbatim writes live credentials into pending_assets.json — a plain-text
# file shared with every other module and rendered as-is in
# report_generator.py's raw-data appendix. CLAUDE.md rule 16 forbids exactly
# that, and the value of the evidence does not depend on the secret itself:
# "DB_PASSWORD=Sup3***cret" proves the exposure exactly as well as the
# password does, and keeps the key names that make the finding reviewable.

_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)([A-Za-z0-9_.\-]{1,64})(\s*[:=]\s*)(\"[^\"\n]{4,}\"|\'[^\'\n]{4,}\'|[^\s,;&]{4,})"
)
# Any run of this many credential-charset characters is treated as a
# high-entropy blob and masked wherever it appears, so a token that is not
# part of a KEY=VALUE assignment (a bare bearer token in a log line, a hash in
# an htpasswd file, a connection string) cannot survive into evidence.
_ENTROPY_RUN_MIN = 20
_ENTROPY_RUN_RE = re.compile(r"[A-Za-z0-9_\-/+]{%d,}" % _ENTROPY_RUN_MIN)
# "=" and "." are deliberately NOT in the charset above: including them let a
# single run swallow "KEY=<value>" whole and mask the key name too, destroying
# the part of the evidence that says *which* secret leaked. Values attached to
# a key are masked by _SECRET_ASSIGNMENT_RE instead, and a dotted token (a JWT)
# is masked segment by segment.
# A long run that is *only* upper- or only lower-case letters and underscores
# is an identifier, not a credential ("AWS_SECRET_ACCESS_KEY" is 21 characters
# long). Masking it destroyed exactly the part of the evidence that says
# *which* secret leaked, while every credential format that matters here
# (base64, hex, JWT segments, bcrypt/apr1 hashes) mixes case or contains
# digits.
_IDENTIFIER_RUN_RE = re.compile(r"^(?:[A-Z_.\-]+|[a-z_.\-]+)$")
# Keys whose *values* are never secrets and stay readable, because they carry
# the technology intelligence a reviewer actually needs from a config file.
_NON_SECRET_KEYS = frozenset({
    "version", "name", "host", "hostname", "port", "driver", "engine", "debug",
    "env", "app_env", "app_name", "app_debug", "db_host", "db_port", "db_connection",
    "db_database", "charset", "locale", "timezone", "true", "false", "null",
})


def _redact_secret(value: str) -> str:
    """Return a partially-masked representation of `value`; never the raw secret."""
    if not value:
        return ""
    if len(value) <= 8:
        return value[0] + "*" * (len(value) - 1) if len(value) > 1 else "*"
    stars = min(len(value) - 8, 24)
    return f"{value[:4]}{'*' * stars}{value[-4:]}"


def redact_sensitive_text(text: Optional[str]) -> Optional[str]:
    """
    Mask assigned values and high-entropy tokens in `text`, preserving the
    surrounding structure (key names, syntax, log wording) that makes an
    exposure excerpt reviewable.

    Deliberately conservative in the other direction too: this is a
    best-effort redaction of *recognisable* credential shapes, not a
    guarantee that no sensitive byte can ever survive. Free-prose secrets
    shorter than the entropy threshold and not written as an assignment are
    not recognised — which is why the excerpt stays bounded to
    MAX_EXCERPT_CHARS as well.
    """
    if not text:
        return text
    spans: List[Tuple[int, int]] = []
    for match in _SECRET_ASSIGNMENT_RE.finditer(text):
        if match.group(1).strip().lower() in _NON_SECRET_KEYS:
            continue
        spans.append(match.span(3))
    for match in _ENTROPY_RUN_RE.finditer(text):
        if _IDENTIFIER_RUN_RE.match(match.group(0)):
            continue
        spans.append(match.span(0))
    if not spans:
        return text

    spans.sort()
    merged: List[List[int]] = []
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


def _excerpt(body: Optional[str], max_chars: int = MAX_EXCERPT_CHARS) -> Optional[str]:
    """Concise, size-bounded evidence excerpt — never the full body (context.md §8's
    evidence lists should stay useful and reviewable, not a body dump)."""
    if not body:
        return None
    collapsed = re.sub(r"\s+", " ", body).strip()
    if not collapsed:
        return None
    return collapsed[:max_chars] + ("…" if len(collapsed) > max_chars else "")


def _redacted_excerpt(body: Optional[str], max_chars: int = MAX_EXCERPT_CHARS) -> Optional[str]:
    """
    `_excerpt` with credential-shaped content masked (redact_sensitive_text).

    Every excerpt this module persists goes through here rather than through
    `_excerpt`; the plain variant remains the bounded-excerpt primitive.
    Redaction happens BEFORE truncation, so a value cut in half by the length
    bound cannot leave a usable prefix behind in the record — and the input to
    the redactor is itself bounded, so the work stays proportional to what
    will actually be shown.
    """
    if not body:
        return None
    collapsed = re.sub(r"\s+", " ", body).strip()
    if not collapsed:
        return None
    masked = redact_sensitive_text(collapsed[: max_chars * 4]) or ""
    return masked[:max_chars] + ("…" if len(collapsed) > max_chars else "")


# ---------------------------------------------------------------------------
# Shared HTTP client (GET + OPTIONS — OPTIONS is this module's one named
# non-GET responsibility; see module docstring, decision #7)
# ---------------------------------------------------------------------------

def fetch_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """
    Perform a single HTTP GET against `url` without following redirects
    (redirects are inspected, not silently followed, matching every other
    active-phase module). `raw_prefix` carries the first bytes of the
    response undecoded, for binary magic-byte signature checks (archive
    files, etc.) that decoded text would corrupt.
    """
    result: Dict[str, Any] = {
        "status": "error", "status_code": None, "headers": {}, "body": None,
        "raw_prefix": b"", "body_truncated": False, "final_url": url,
        "elapsed_seconds": None, "error": None, "body_read_error": None,
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
            # Fallback for adapters/mocks without a usable .raw. It must stay
            # bounded: `resp.content` materialises the *entire* body before the
            # slice runs, so a multi-megabyte response (or a decompression
            # bomb behind Content-Encoding: gzip) was fully resident in memory
            # per worker before being truncated. iter_content stops at the cap.
            raw = b""
            try:
                for chunk in resp.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    raw += chunk
                    if len(raw) > max_body_bytes:
                        break
                raw = raw[: max_body_bytes + 1]
            except Exception:
                # Last resort for adapters exposing neither a readable .raw nor
                # a working iter_content. `.content` materialises the whole
                # body, so it is used only when the server declared a size that
                # is safe to hold; an undeclared or oversized body is reported
                # as unread rather than swallowed whole.
                declared = _ci_get(dict(getattr(resp, "headers", {}) or {}), "Content-Length")
                hard_cap = max_body_bytes * 8
                try:
                    if declared is not None and int(declared) > hard_cap:
                        raise ValueError(f"declared body of {declared} bytes exceeds the read cap")
                    raw = resp.content[: max_body_bytes + 1]
                except Exception as body_exc:
                    raw = b""
                    result["body_read_error"] = str(body_exc)
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
            "raw_prefix": body_bytes[:16],
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


def fetch_options(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Perform a single HTTP OPTIONS request against `url` (responsibility group 5)."""
    result: Dict[str, Any] = {
        "status": "error", "status_code": None, "headers": {}, "error": None,
    }
    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        req_headers.update(headers)
    resp = None
    try:
        resp = requests.options(url, timeout=timeout, headers=req_headers, allow_redirects=False)
        result.update({"status": "found", "status_code": resp.status_code, "headers": dict(resp.headers)})
    except requests.exceptions.Timeout:
        result["error"] = "timeout"
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"connection error: {exc}"
    except requests.exceptions.RequestException as exc:
        result["error"] = f"request failed: {exc}"
    finally:
        if resp is not None:
            resp.close()
    return result


# Values that change on every request and would otherwise make two renderings
# of the *same* catch-all page look like different content. Mirrors
# endpoint_discovery.py's _VOLATILE_PATTERNS.
_VOLATILE_PATTERNS = [
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?"),
    re.compile(r"\b\d{10,13}\b"),
    re.compile(r"\b[0-9a-fA-F]{32,64}\b"),
    re.compile(r"(?i)\b(?:nonce|csrf[-_]?token|request[-_]?id|trace[-_]?id)\b[\"'=:\s]+[\w\-]+"),
]


def _structural_signature(body: str, url: str) -> str:
    """
    A fingerprint of a response with the requested path and per-request
    volatile values removed, so two renderings of one catch-all page compare
    equal even when they echo the URL or carry a timestamp/CSRF token.
    """
    normalized = re.sub(r"\s+", " ", body or "").strip()
    path = urllib.parse.urlsplit(url).path if url else ""
    variants = {path, path.lstrip("/"), urllib.parse.quote(path), urllib.parse.quote(path.lstrip("/"))}
    # Longest first, and deterministically ordered. Iterating the set directly
    # meant "/x" and "x" could be substituted in either order between two
    # calls, so the same page normalised to two different signatures depending
    # on set iteration order — the signature stopped being a signature.
    for token in sorted((t for t in variants if t and len(t) > 2), key=lambda t: (-len(t), t)):
        normalized = normalized.replace(token, "<PATH>")
    for pattern in _VOLATILE_PATTERNS:
        normalized = pattern.sub("<VOLATILE>", normalized)
    return hashlib.md5(normalized.encode("utf-8", errors="ignore")).hexdigest()


def _probe_soft_404(origin: str, timeout: float, on_request: Optional[Any] = None) -> Dict[str, Any]:
    """
    Fingerprint `origin`'s "this does not exist" response.

    BASELINE_PROBE_COUNT random probes with deliberately different path
    lengths, rather than one. Two probes is what makes the result
    trustworthy: if both bodies are identical the catch-all is static and a
    hash comparison suffices; if they differ the catch-all is dynamic, and
    comparing a candidate against a single dynamic sample is meaningless — the
    path-and-volatility-normalised structural signature is used instead.

    `on_request` (optional) is called once per probe so the caller can charge
    the probes to its request budget; a False return means the budget is
    exhausted and the baseline is abandoned rather than silently skipped.
    """
    samples: List[Dict[str, Any]] = []
    for index in range(BASELINE_PROBE_COUNT):
        if on_request is not None and not on_request():
            break
        # Different lengths so a catch-all that echoes the requested path shows
        # up as a length difference instead of looking stable.
        probe_path = "reconhound-exposure-check-" + uuid.uuid4().hex[: 8 + index * 12]
        url = _ensure_trailing_slash(origin) + probe_path
        resp = fetch_url(url, timeout=timeout)
        if resp["status"] != "found":
            continue
        body = resp.get("body") or ""
        length, digest = _content_signature(body)
        samples.append({
            "status_code": resp["status_code"], "content_length": length, "body_hash": digest,
            "structural_hash": _structural_signature(body, url),
        })

    if not samples:
        # No usable answer at all. Explicitly "unavailable", never "the host
        # 404s everything" — the difference is what keeps a scanner failure
        # from becoming a negative result (context.md §8).
        return {"available": False, "reason": "no baseline probe completed"}

    statuses = {s["status_code"] for s in samples}
    if len(statuses) > 1:
        # The host does not even answer non-existent paths consistently;
        # nothing derived from it would be sound.
        return {"available": False, "reason": "baseline probes returned differing status codes"}

    status_code = samples[0]["status_code"]
    dynamic = len({s["body_hash"] for s in samples}) > 1
    structurally_stable = len({s["structural_hash"] for s in samples}) == 1
    return {
        "available": True,
        "status_code": status_code,
        "content_length": samples[0]["content_length"],
        "body_hash": samples[0]["body_hash"],
        "body_hashes": sorted({s["body_hash"] for s in samples}),
        "structural_hash": samples[0]["structural_hash"],
        "dynamic": dynamic,
        # A dynamic catch-all whose *structure* also changes per request gives
        # no comparable fingerprint; comparisons against it are not made.
        "usable": (not dynamic) or structurally_stable,
        # How many probes actually completed. One probe cannot distinguish a
        # static catch-all from a dynamic one, so a single-sample baseline can
        # only ever match exactly — recorded so a consumer can see how strong
        # the comparison behind a `possible_soft_404_match` really was.
        "probes": len(samples),
        "single_sample": len(samples) < BASELINE_PROBE_COUNT,
    }


def _matches_soft_404(resp: Dict[str, Any], baseline: Optional[Dict[str, Any]], url: str = "") -> bool:
    """
    True when `resp` is indistinguishable from this host's not-found response.

    Length proximity alone is deliberately NOT sufficient any more. The
    previous implementation accepted `abs(len - baseline_len) <= 25` as proof
    of a soft 404, which silently downgraded genuine finds: a real .env of 53
    normalised characters against a 60-character catch-all was reported as
    `possible_soft_404_match` at LOW confidence and never confirmed. Content
    identity (exact, or structural for a dynamic catch-all) is required; a
    merely similar length is reported by the caller as corroborating context,
    not as the decision.
    """
    if not baseline or not baseline.get("available") or not baseline.get("usable", True):
        return False
    if resp.get("status_code") != baseline.get("status_code"):
        return False
    body = resp.get("body") or ""
    length, digest = _content_signature(body)
    if digest in set(baseline.get("body_hashes") or [baseline.get("body_hash")]):
        return True
    if baseline.get("dynamic") and baseline.get("structural_hash"):
        return _structural_signature(body, url) == baseline["structural_hash"]
    return False


# ---------------------------------------------------------------------------
# Wordlist loading (mirrors endpoint_discovery.py's load_wordlist exactly)
# ---------------------------------------------------------------------------

def _default_wordlists_dir() -> str:
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "wordlists"))


def load_wordlist(name: str, wordlists_dir: Optional[str] = None) -> List[str]:
    """Load a newline-delimited wordlist file (blank lines and '#' comments ignored, deduped, order preserved)."""
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
        if not entry or entry.startswith("#") or entry in seen:
            continue
        seen.add(entry)
        entries.append(entry)

    if not entries:
        raise WordlistError(f"Wordlist {name!r} at {path!r} contains no usable entries.")
    return entries


# ---------------------------------------------------------------------------
# 1. Sensitive-resource categorization (responsibility group 1)
# ---------------------------------------------------------------------------

def classify_exposure_category(entry: str) -> Optional[str]:
    """
    Map a raw wordlist entry (from directories.txt) to a recognized
    exposure category, or None if this module has no dedicated evidence
    check for it (skipped — see module docstring, decision #1).
    """
    for pattern, category in _CATEGORY_RULES:
        if pattern.search(entry):
            return category
    return None


# ---------------------------------------------------------------------------
# Directory-listing detection (applies to any directory-kind candidate,
# independent of category — see module docstring, decision #2)
# ---------------------------------------------------------------------------

# Autoindex markers, anchored to the markup position each server actually
# emits them in. The previous rules matched the bare strings anywhere in a
# body, so any page that merely *mentioned* "Index of /" or contained a
# "Parent Directory" link (a hand-written file index, a WAF block page quoting
# the request, documentation) was reported as a directory listing at HIGH
# confidence — and a directory listing is direct, unambiguous evidence, so
# that false positive propagated straight into the risk assessment.
_DIRECTORY_LISTING_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"<title>\s*Index of /", re.I), "Apache/nginx autoindex <title>Index of /"),
    (re.compile(r"<h1>\s*Index of /", re.I), "Apache/nginx autoindex <h1>Index of /"),
    (re.compile(r"<title>\s*Directory listing for", re.I), "Python http.server directory listing"),
    (re.compile(r"<a[^>]+href=[\"']\.\.[/\"'][^>]*>\s*(?:Parent Directory|\.\.)", re.I),
     "autoindex parent-directory link"),
    (re.compile(r"\[To Parent Directory\]", re.I), "IIS directory listing"),
]


def detect_directory_listing(body: Optional[str]) -> Optional[str]:
    """Return matched evidence text if `body` looks like an autoindex directory listing, else None."""
    if not body:
        return None
    for pattern, description in _DIRECTORY_LISTING_RULES:
        match = pattern.search(body)
        if match:
            return f"{description}: {match.group(0)[:80]!r}"
    return None


# ---------------------------------------------------------------------------
# Category-specific evidence signatures (never claim "confirmed" from a
# path name alone — see module docstring, decision #2)
# ---------------------------------------------------------------------------

_GIT_REF_RE = re.compile(r"^ref:\s*refs/", re.IGNORECASE)
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_GIT_CONFIG_SECTION_RE = re.compile(r"\[core\]", re.IGNORECASE)
# Additional version-control artefacts with unambiguous, self-identifying
# formats. Without these, .git/index, .git/packed-refs, .git/logs/HEAD and
# .svn/entries could only ever reach `interesting_unconfirmed`, however
# plainly they were the real thing — a false negative for exactly the
# artefacts that prove a repository is served.
_GIT_PACKED_REFS_RE = re.compile(r"^#\s*pack-refs\s+with:", re.IGNORECASE | re.MULTILINE)
_GIT_LOGS_HEAD_RE = re.compile(r"^[0-9a-f]{40}\s+[0-9a-f]{40}\s+\S", re.IGNORECASE | re.MULTILINE)
_SVN_ENTRIES_RE = re.compile(r"\A(?:\d+\s*\n(?:dir|file)\b|<\?xml[^>]*\?>\s*<wc-entries)", re.IGNORECASE)
_SVN_WC_DB_MAGIC = b"SQLite format 3\x00"
_GIT_INDEX_MAGIC = b"DIRC"
_GIT_PACK_MAGIC = b"PACK"

_ENV_LINE_RE = re.compile(r"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S*$")

_SQL_DUMP_RE = re.compile(
    r"(--\s*MySQL dump|CREATE TABLE\b|INSERT INTO\b|PostgreSQL database dump|pg_dump|mysqldump)",
    re.IGNORECASE,
)

_ARCHIVE_MAGIC_BYTES: List[Tuple[bytes, str]] = [
    (b"PK\x03\x04", "ZIP local-file-header magic bytes (PK\\x03\\x04)"),
    (b"\x1f\x8b", "gzip magic bytes (\\x1f\\x8b)"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip magic bytes"),
    (b"Rar!", "RAR magic bytes"),
]

# Unambiguous, format-specific markers only. The previous rule additionally
# accepted any single line of the shape `word: value`, which matches ordinary
# English prose served as text/plain — a "Error: page not found" body at
# /config.yml was reported as `confirmed_exposure`, which risk_engine.py scores
# as HIGH "major misconfig". A YAML/INI-looking body must now show *repeated*
# structure (see _looks_like_structured_config) rather than one colon.
_CONFIG_SIGNATURE_RE = re.compile(
    r"(<\?php\s|^\[[\w.\-]+\]\s*$|^\s*<configuration\b|^\s*<\?xml[^>]*\?>\s*<configuration\b)",
    re.MULTILINE | re.IGNORECASE,
)

# A key/value line as YAML, INI or a Java properties file writes one. Used to
# require *structure*, not a single colon.
_CONFIG_KV_LINE_RE = re.compile(r"(?m)^[ \t]*[A-Za-z_][\w.\-]*[ \t]*[:=][ \t]*\S")
_CONFIG_MIN_KV_LINES = 3
# Keys a generic JSON *error envelope* is built from. A 200 JSON body of
# {"error": "not found"} at /config.json is an error page, not a configuration
# file, and must not be confirmed as one.
_JSON_ERROR_KEYS = frozenset({"error", "errors", "message", "code", "status", "detail",
                              "details", "title", "type", "timestamp", "path", "success"})
_JSON_MIN_CONFIG_KEYS = 2


def _looks_like_structured_config(body: str) -> Optional[str]:
    """Evidence string if `body` shows repeated key/value configuration structure."""
    matches = _CONFIG_KV_LINE_RE.findall(body)
    if len(matches) >= _CONFIG_MIN_KV_LINES:
        return f"body contains {len(matches)} key/value configuration line(s)"
    return None

_HTPASSWD_LINE_RE = re.compile(r"(?m)^[\w.\-]+:\$?(apr1|2y|2b|1)?\$?[\w./$]{10,}$")
# Self-identifying credential formats. Deliberately format markers only — the
# value itself is never extracted, parsed or used to authenticate anywhere
# (context.md §16: this module discovers exposure, it does not exploit it).
_PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")
_AWS_CREDENTIALS_RE = re.compile(r"(?im)^\s*aws_(?:secret_)?access_key(?:_id)?\s*=")
# NOTE: no public-key rule. An OpenSSH *public* key is public by design;
# confirming one under CATEGORY_CREDENTIAL_MATERIAL would reach risk_engine.py
# as a CRITICAL "exposed creds" signal for a file that leaks no secret.

# Markup that indicates an administrative interface is being served.
_ADMIN_SIGNAL_RE = re.compile(
    r"(wp-admin|phpmyadmin|cpanel|administration|dashboard)",
    re.IGNORECASE,
)
# Markup that indicates the response is an authentication *gate* rather than
# an accessible interface. A password field, a login form action or a sign-in
# heading all mean "credentials are required here".
_LOGIN_GATE_RE = re.compile(
    r"(type=[\"']?password[\"']?|name=[\"']?(?:password|passwd|pwd)[\"']?"
    r"|<form[^>]+action=[\"'][^\"']*(?:login|signin|sign-in|auth)"
    r"|\b(?:please\s+)?(?:log\s?in|sign\s?in)\b[^<]{0,40}(?:to continue|required)?"
    r"|wp-login\.php|/oauth2/authorize)",
    re.IGNORECASE,
)

_LOG_LINE_RE = re.compile(r"(?m)^\s*(\[\d{4}-\d{2}-\d{2}|\[\w+\]|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")


def _check_version_control(path: str, body: Optional[str], raw_prefix: bytes = b"") -> Optional[str]:
    body = body or ""
    name = path.rstrip("/")
    if name.endswith("HEAD"):
        stripped = body.strip()
        if _GIT_REF_RE.match(stripped) or _GIT_SHA_RE.match(stripped):
            return f"'{path}' body matches a git HEAD reference/SHA format"
        if _GIT_LOGS_HEAD_RE.search(body):
            return f"'{path}' body matches the git reflog (logs/HEAD) old-sha/new-sha format"
    if name.endswith("config") and _GIT_CONFIG_SECTION_RE.search(body):
        return f"'{path}' body contains a git config [core] section"
    if raw_prefix.startswith(_GIT_INDEX_MAGIC):
        return f"'{path}' body begins with the git index magic bytes (DIRC)"
    if raw_prefix.startswith(_GIT_PACK_MAGIC):
        return f"'{path}' body begins with the git packfile magic bytes (PACK)"
    if raw_prefix.startswith(_SVN_WC_DB_MAGIC):
        return f"'{path}' body is an SQLite database (Subversion wc.db working-copy metadata)"
    if _GIT_PACKED_REFS_RE.search(body):
        return f"'{path}' body contains a git packed-refs header"
    if _SVN_ENTRIES_RE.search(body):
        return f"'{path}' body matches the Subversion .svn/entries format"
    return None


def _check_environment_file(body: Optional[str], content_type: Optional[str]) -> Optional[str]:
    body = body or ""
    if content_type and "html" in content_type.lower():
        return None
    if not _looks_textual(content_type, body):
        return None
    matches = _ENV_LINE_RE.findall(body)
    if len(matches) >= 2:
        return f"body contains {len(matches)} dotenv-style KEY=VALUE line(s)"
    return None


def _check_database_dump(body: Optional[str], raw_prefix: bytes) -> Optional[str]:
    if body and _SQL_DUMP_RE.search(body):
        match = _SQL_DUMP_RE.search(body)
        return f"body contains SQL-dump marker {match.group(0)!r}"
    if raw_prefix[:2] == b"\x1f\x8b":
        return "body begins with gzip magic bytes (compressed dump)"
    return None


def _check_archive_file(raw_prefix: bytes, content_type: Optional[str]) -> Tuple[Optional[str], str]:
    """
    Returns (evidence_or_None, strength) with strength in {"strong", "weak"}.

    Only the magic bytes of the body actually returned are "strong". A
    Content-Type header is a *claim about* the body, and an
    "application/octet-stream" error page or a CDN default type previously
    produced `confirmed_exposure` at HIGH confidence for a body that was
    plainly HTML — which risk_engine.py scores as HIGH "major misconfig".
    """
    for magic, description in _ARCHIVE_MAGIC_BYTES:
        if raw_prefix.startswith(magic):
            return description, "strong"
    if content_type and any(
        m in content_type.lower() for m in ("zip", "x-gzip", "x-tar", "x-7z", "x-rar", "octet-stream")
    ):
        return (f"Content-Type {content_type!r} suggests an archive/binary payload, but the "
                f"response body does not begin with any known archive signature"), "weak"
    return None, "weak"


def _check_configuration_file(body: Optional[str], content_type: Optional[str]) -> Optional[str]:
    body = body or ""
    if content_type and "html" in content_type.lower():
        return None
    if not _looks_textual(content_type, body):
        return None
    if content_type and "json" in content_type.lower():
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, dict) and parsed:
            keys = {str(k).strip().lower() for k in parsed.keys()}
            # "parses as JSON" is not evidence of a configuration file: every
            # JSON *error page* parses too. Require more than an error
            # envelope's worth of keys, and reject a body whose keys are
            # exclusively error-envelope keys.
            if len(keys) >= _JSON_MIN_CONFIG_KEYS and not keys.issubset(_JSON_ERROR_KEYS):
                return (f"body parses as a JSON object with {len(parsed)} key(s) "
                        f"matching the requested config/manifest filename")
        elif isinstance(parsed, list) and parsed:
            return f"body parses as a JSON array of {len(parsed)} entry/entries"
        return None
    match = _CONFIG_SIGNATURE_RE.search(body)
    if match:
        return f"body contains a structured-config signature ({match.group(0).strip()[:60]!r})"
    return _looks_like_structured_config(body)


def _check_credential_material(path: str, body: Optional[str],
                               content_type: Optional[str] = None) -> Optional[str]:
    body = body or ""
    if content_type and "html" in content_type.lower():
        # A page that merely *documents* a PEM header is not an exposed key.
        return None
    if path.endswith(".htpasswd") and _HTPASSWD_LINE_RE.search(body):
        return "body contains a line matching the htpasswd username:hash format"
    if _PEM_PRIVATE_KEY_RE.search(body):
        return "body contains a PEM private-key header (the key material itself is never recorded)"
    if _AWS_CREDENTIALS_RE.search(body):
        return "body contains an AWS credentials-file key assignment (the value is never recorded)"
    return None


def _check_administrative_panel(status_code: Optional[int], body: Optional[str]) -> Tuple[Optional[str], str]:
    """
    Returns (evidence_or_None, strength) with strength in
    {"strong", "login_gate", "weak"}.

    "strong" means administrative interface markup was served *without* an
    authentication gate. A login page is deliberately NOT strong: it is
    evidence that an admin surface exists, not evidence that it is reachable
    without credentials, and the previous rule treated any `type="password"`
    field as a confirmed exposed administrative panel — which risk_engine.py
    scores HIGH as "administrative panel reachable at <url>". Almost every
    admin panel on the internet serves a login form, so that rule confirmed
    nearly all of them.
    """
    body = body or ""
    login_match = _LOGIN_GATE_RE.search(body)
    admin_match = _ADMIN_SIGNAL_RE.search(body)
    if login_match:
        detail = f" (also matched admin markup {admin_match.group(0)!r})" if admin_match else ""
        return (
            f"body presents an authentication gate ({login_match.group(0)[:60]!r}){detail} — an "
            f"administrative surface exists here, but the response is a login page, not "
            f"unrestricted access",
            "login_gate",
        )
    if admin_match:
        return (
            f"body/markup contains admin-panel signal {admin_match.group(0)!r} with no "
            f"authentication gate in the response",
            "strong",
        )
    if status_code in (401, 403):
        return f"HTTP {status_code} on an administrative-panel-shaped path (exists, access-restricted)", "weak"
    return None, "weak"


def _check_log_file(body: Optional[str], content_type: Optional[str]) -> Optional[str]:
    body = body or ""
    if content_type and "html" in content_type.lower():
        return None
    if not _looks_textual(content_type, body):
        return None
    matches = _LOG_LINE_RE.findall(body)
    if len(matches) >= 2:
        return f"body contains {len(matches)} timestamp/level-prefixed log line(s)"
    return None


# ---------------------------------------------------------------------------
# 4. Error-page intelligence (responsibility group 4) — applied
# opportunistically to already-fetched bodies only, see module docstring,
# decision #6
# ---------------------------------------------------------------------------

_FRAMEWORK_SIGNATURES: List[Tuple[str, re.Pattern, Optional[re.Pattern]]] = [
    ("werkzeug_flask_debugger", re.compile(r"Werkzeug Debugger", re.I),
     re.compile(r"Werkzeug/([\d.]+)")),
    ("django_debug_page", re.compile(r"You're seeing this because.*DEBUG.*True|Django Version:", re.I),
     re.compile(r"Django Version:\s*([\d.]+)")),
    ("laravel_whoops", re.compile(r"Whoops.{0,10}[Ll]ooks like something went wrong|Ignition", re.I), None),
    ("rails_error_page", re.compile(r"ActionController::\w*Error|Rails\.root:", re.I), None),
    ("aspnet_error_page", re.compile(r"Server Error in '/' Application", re.I),
     re.compile(r"ASP\.NET Version:\s*([\d.]+)")),
    # The span between the marker and "on line N" is bounded. Unbounded
    # `.*?` with re.S meant every "Fatal error:" occurrence in a body with no
    # following "on line N" scanned to the end of the body: a hostile 128 KB
    # response full of that literal cost ~4s of CPU *per response*, times
    # max_workers, times every candidate — a pure request-to-CPU amplifier
    # against an attacker-controlled body. A real PHP fatal error puts the
    # file/line within a few hundred characters of the marker.
    ("php_fatal_error", re.compile(r"Fatal error:.{0,400}?on line \d+", re.I | re.S), None),
    ("python_traceback", re.compile(r"Traceback \(most recent call last\):"), None),
    # Bounded for the same reason as php_fatal_error above: `[^)]+` on a body
    # with no closing parenthesis rescans to the end from every "at " match.
    ("nodejs_stack_trace", re.compile(r"at [\w.$ ]{1,120}\([^)\n]{1,300}\.js:\d+:\d+\)"), None),
]

_INTERNAL_PATH_PATTERNS = [
    re.compile(r"/(?:var|usr|home|opt|srv|etc)/[^\s\"'<>]+"),
    re.compile(r"[A-Za-z]:\\\\?[^\s\"'<>]+"),
]

# Bounded repetitions, and only ever applied to an already-truncated header
# value. `[\w.\-]*` unbounded backtracks catastrophically against a header with
# no "/" in it: a single attacker-supplied `Server:` header of 100 000
# characters cost 70.8 seconds of CPU in one call, from one response, before
# any of this module's own limits applied. Servers control their own response
# headers, so this was remotely triggerable on every probed path.
_SERVER_VERSION_RE = re.compile(r"([A-Za-z][\w.\-]{0,64})/(\d[\w.\-]{0,64})")

# Bounds on error-page intelligence extracted from an attacker-controlled body.
_MAX_INTERNAL_PATHS = 10
_MAX_INTERNAL_PATH_CHARS = 200
_MAX_HEADER_EVIDENCE_CHARS = 200
_MAX_ERROR_PAGE_SCAN_CHARS = DEFAULT_MAX_BODY_BYTES


def analyze_error_page(
    body: Optional[str],
    headers: Optional[Dict[str, str]] = None,
    status_code: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Safely extract framework/version/stack-trace/internal-path intelligence
    from an already-fetched response (responsibility group 4). Returns an
    empty `indicators` list when nothing is found — never fabricates a
    signal. No request is made here; this only inspects text already
    obtained for another purpose (module docstring, decision #6).
    """
    body = body or ""
    if len(body) > _MAX_ERROR_PAGE_SCAN_CHARS:
        # Every pattern below is bounded, but the *number of match attempts* is
        # still proportional to body length, and fetch_url's cap is a caller
        # argument rather than a guarantee. Error-page evidence lives in the
        # first part of a response in every framework this recognises.
        body = body[:_MAX_ERROR_PAGE_SCAN_CHARS]
    indicators: List[Dict[str, str]] = []

    for name, marker_re, version_re in _FRAMEWORK_SIGNATURES:
        marker_match = marker_re.search(body)  # noqa: E501 — bounded patterns only
        if not marker_match:
            continue
        version = None
        if version_re:
            version_match = version_re.search(body)
            if version_match:
                version = version_match.group(1)
        indicators.append({
            "indicator_type": "framework_debug_signature",
            "framework": name,
            "version": version,
            # A debug page routinely renders environment variables and
            # connection strings; the matched span is redacted before it
            # becomes persisted evidence (CLAUDE.md rule 16).
            "evidence": f"Matched {name!r} signature: "
                        f"{redact_sensitive_text(marker_match.group(0)[:120])!r}",
        })

    server_header = _ci_get(headers or {}, "Server")
    if server_header:
        # Truncate BEFORE matching, not only before reporting: the header is
        # attacker-controlled and the regex is applied to whatever it holds.
        server_header = str(server_header)[:_MAX_HEADER_EVIDENCE_CHARS]
        match = _SERVER_VERSION_RE.search(server_header)
        if match:
            indicators.append({
                "indicator_type": "server_software_version",
                "framework": match.group(1),
                "version": match.group(2),
                "evidence": f"Server header: {server_header[:_MAX_HEADER_EVIDENCE_CHARS]!r}",
            })

    x_powered_by = _ci_get(headers or {}, "X-Powered-By")
    if x_powered_by:
        x_powered_by = str(x_powered_by)[:_MAX_HEADER_EVIDENCE_CHARS]
        indicators.append({
            "indicator_type": "x_powered_by_header",
            "framework": x_powered_by,
            "version": None,
            "evidence": f"X-Powered-By header: {x_powered_by!r}",
        })

    internal_paths: List[str] = []
    seen_paths = set()
    for pattern in _INTERNAL_PATH_PATTERNS:
        # finditer + early exit: findall() materialised every match in a
        # 128 KB body (a directory listing of /var/... produces thousands)
        # only for the list to be truncated to ten immediately afterwards.
        for match in pattern.finditer(body):
            text = match.group(0)[:_MAX_INTERNAL_PATH_CHARS]
            if text in seen_paths:
                continue
            seen_paths.add(text)
            internal_paths.append(text)
            if len(internal_paths) >= _MAX_INTERNAL_PATHS:
                break
        if len(internal_paths) >= _MAX_INTERNAL_PATHS:
            break
    for path in internal_paths:
        indicators.append({
            "indicator_type": "internal_filesystem_path",
            "framework": None,
            "version": None,
            "evidence": f"Internal path referenced in response content: {path!r}",
        })

    # `.+` before a bounded suffix is linear here only because the alternation
    # is anchored on literal text; the JS-frame branch is bounded explicitly so
    # a body full of "at foo(" cannot make it quadratic.
    # The JS-frame branch mirrors the nodejs_stack_trace signature above,
    # including the space real V8 frames put before the parenthesis
    # ("at Object.handler (/srv/app.js:42:15)"), which the previous character
    # class excluded — so a genuine Node stack trace was reported with the
    # framework indicator set but `stack_trace_detected` False.
    stack_trace_detected = bool(
        re.search(r"Traceback \(most recent call last\)|at [\w.$ ]{1,120}\([^)\n]{1,300}:\d+:\d+\)", body)
    )

    return {
        "framework_indicators": [i for i in indicators if i["indicator_type"] != "internal_filesystem_path"],
        "internal_paths": internal_paths,
        "stack_trace_detected": stack_trace_detected,
        "indicators": indicators,
        "status_code": status_code,
    }


# ---------------------------------------------------------------------------
# Response classification vocabulary shared across the sensitive-resource
# sweep (mirrors endpoint_discovery.py's classify_response vocabulary,
# extended with confirmed/likely/interesting-unconfirmed distinctions per
# the assignment brief's "discovery quality" requirements)
# ---------------------------------------------------------------------------

def evaluate_exposure(
    category: str,
    path: str,
    resp: Dict[str, Any],
    baseline: Optional[Dict[str, Any]],
    url: str = "",
    error_intel: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str, List[str], Optional[str]]:
    """
    Classify one fetched candidate into (discovery_type, confidence,
    evidence_notes, excerpt). Never returns DT_CONFIRMED without a
    category-specific content signature match (module docstring, decision #2).

    Ordering matters and is deliberate:

      1. Non-2xx statuses are answered first, and a status that means the
         server refused or failed (429/5xx/unexpected) is reported as
         inconclusive, never as absence.
      2. A directory listing is direct evidence and is recognised before
         anything else on a 2xx.
      3. The category's own content signature is evaluated BEFORE the
         soft-404 comparison. The previous order let the baseline veto a real
         find: a genuine .env whose normalised length happened to fall within
         25 characters of the host's catch-all page was reported as
         `possible_soft_404_match` at LOW confidence and never confirmed. A
         response that carries a category signature is only suppressed when
         its content is *identical* to the catch-all (which cannot happen for
         a signature the catch-all does not itself contain).
    """
    status = resp.get("status_code")
    body = resp.get("body")
    headers = resp.get("headers") or {}
    content_type = _ci_get(headers, "Content-Type")
    raw_prefix = resp.get("raw_prefix") or b""

    if status is None:
        return DT_ERROR, CONFIDENCE_LOW, ["no status code available (request failed)"], None
    if status in (404, 410):
        return DT_NOT_FOUND, CONFIDENCE_HIGH, [f"HTTP {status}"], None
    if status == 429:
        return (DT_RATE_LIMITED, CONFIDENCE_LOW,
                ["HTTP 429 Too Many Requests — this path was not tested; absence cannot be inferred"], None)
    if status in _REDIRECT_STATUS_CODES:
        location = _ci_get(headers, "Location")
        notes = [f"HTTP {status} redirect response"]
        if location:
            notes.append(f"Location: {location[:200]!r} (not followed)")
        return DT_REDIRECT, CONFIDENCE_MEDIUM, notes, None
    if status in (401, 403):
        notes = [f"HTTP {status} access-restricted response — path exists but is not readable"]
        if category == CATEGORY_ADMINISTRATIVE_PANEL:
            return DT_ACCESS_RESTRICTED, CONFIDENCE_MEDIUM, notes, None
        return DT_ACCESS_RESTRICTED, CONFIDENCE_LOW, notes, None
    if status == 405:
        return DT_METHOD_NOT_ALLOWED, CONFIDENCE_MEDIUM, ["HTTP 405 Method Not Allowed"], None
    if 500 <= status < 600:
        # A 5xx is itself potentially useful (error-page intel handles that
        # separately); as an *exposure* signal it only proves the path
        # triggered server-side handling, not that sensitive content exists,
        # and it is explicitly not a negative result either.
        return (DT_SERVER_ERROR, CONFIDENCE_LOW,
                [f"HTTP {status} server error — this path was not conclusively tested"],
                _redacted_excerpt(body))
    if not (200 <= status < 300):
        return (DT_UNEXPECTED_STATUS, CONFIDENCE_LOW,
                [f"unexpected HTTP status {status} — inconclusive"], None)

    # --- 2xx ---------------------------------------------------------------
    soft_404 = _matches_soft_404(resp, baseline, url)

    # Directory-listing evidence always wins first — direct proof, and a
    # catch-all page does not serve an autoindex.
    listing_evidence = detect_directory_listing(body)
    if listing_evidence and not soft_404:
        return (
            DT_CONFIRMED, CONFIDENCE_HIGH,
            [f"Autoindex/directory-listing signature matched: {listing_evidence}",
             "directory listing is direct evidence that the directory's contents are publicly enumerable"],
            _redacted_excerpt(body),
        )

    signature_evidence: Optional[str] = None
    weak_evidence: Optional[str] = None
    login_gate_evidence: Optional[str] = None

    if category == CATEGORY_VERSION_CONTROL:
        signature_evidence = _check_version_control(path, body, raw_prefix)
    elif category == CATEGORY_ENVIRONMENT_FILE:
        signature_evidence = _check_environment_file(body, content_type)
    elif category == CATEGORY_DATABASE_DUMP:
        signature_evidence = _check_database_dump(body, raw_prefix)
    elif category == CATEGORY_ARCHIVE_FILE:
        signature_evidence, strength = _check_archive_file(raw_prefix, content_type)
        if strength != "strong":
            signature_evidence, weak_evidence = None, signature_evidence
    elif category == CATEGORY_BACKUP_FILE:
        archive_evidence, strength = _check_archive_file(raw_prefix, content_type)
        if archive_evidence and strength == "strong":
            signature_evidence = archive_evidence
        else:
            weak_evidence = archive_evidence
            signature_evidence = _check_configuration_file(body, content_type)
    elif category == CATEGORY_CONFIGURATION_FILE:
        signature_evidence = _check_configuration_file(body, content_type)
    elif category == CATEGORY_CREDENTIAL_MATERIAL:
        signature_evidence = _check_credential_material(path, body, content_type)
    elif category == CATEGORY_LOG_FILE:
        signature_evidence = _check_log_file(body, content_type)
    elif category == CATEGORY_DEBUG_ENDPOINT:
        # Reuse the caller's analysis when it already has one: the framework
        # patterns are the most expensive thing this module runs against an
        # attacker-controlled body, and _probe_sensitive_candidate needs the
        # same result for its error_page_intelligence record.
        if error_intel is None:
            error_intel = analyze_error_page(body, headers, status)
        framework_indicators = [
            i for i in error_intel["framework_indicators"]
            if i["indicator_type"] == "framework_debug_signature"
        ]
        if framework_indicators:
            names = ", ".join(sorted({i["framework"] for i in framework_indicators if i["framework"]}))
            signature_evidence = f"debug/error-page framework signature(s) detected: {names}"
        elif "phpinfo()" in (body or "").lower():
            signature_evidence = "body contains a phpinfo() output signature"
        elif "apache" in (body or "").lower() and "status" in path.lower():
            signature_evidence = "body contains an Apache mod_status-style report"
    elif category == CATEGORY_ADMINISTRATIVE_PANEL:
        admin_evidence, strength = _check_administrative_panel(status, body)
        if strength == "strong":
            signature_evidence = admin_evidence
        elif strength == "login_gate":
            login_gate_evidence = admin_evidence

    if signature_evidence and not soft_404:
        notes = [signature_evidence]
        if baseline and baseline.get("available") and baseline.get("usable", True):
            length, _ = _content_signature(body or "")
            if _lengths_close(length, baseline.get("content_length")):
                # Corroborating context, not a veto: reported so a reviewer can
                # see the response resembled the host's not-found page in size
                # while still carrying the category's own content signature.
                notes.append(
                    "note: response length is close to this host's not-found baseline, but its "
                    "content signature is not present in that baseline"
                )
        return DT_CONFIRMED, CONFIDENCE_HIGH, notes, _redacted_excerpt(body)

    if soft_404:
        notes = ["response is indistinguishable from this host's baseline not-found response "
                 "(same status, identical content fingerprint); treated as a soft-404, not as content"]
        if signature_evidence:
            notes.append(
                f"{_SUPPRESSED_PREFIX}signature match ({signature_evidence}) — the same content is "
                f"returned for paths that do not exist, so it is not evidence about this path"
            )
        if listing_evidence:
            notes.append(f"{_SUPPRESSED_PREFIX}directory-listing match ({listing_evidence}) for the same reason")
        return DT_SOFT_404, CONFIDENCE_LOW, notes, None

    if login_gate_evidence:
        # An administrative surface exists, but the response is an
        # authentication gate. Reported with the vocabulary downstream already
        # reads as "present, not readable" (risk_engine.py) rather than as
        # confirmed unrestricted access.
        return (DT_ACCESS_RESTRICTED, CONFIDENCE_MEDIUM,
                [f"HTTP {status} on a {category}-shaped path", login_gate_evidence],
                _redacted_excerpt(body))

    notes = [f"HTTP {status} on a {category}-shaped path with no confirming content signature; "
             f"manual verification recommended"]
    if weak_evidence:
        notes.append(weak_evidence)
    if not (baseline and baseline.get("available") and baseline.get("usable", True)):
        notes.append("no usable not-found baseline was available for this host, so a catch-all "
                     "response could not be ruled out")
    if not (body or "").strip():
        notes.append(f"response body is empty — HTTP {status} alone is not evidence of content")
    return DT_INTERESTING, CONFIDENCE_LOW, notes, _redacted_excerpt(body)


# ---------------------------------------------------------------------------
# Scan state (visited-set, request budget, error log, baseline cache —
# shared across the sensitive-resource sweep)
# ---------------------------------------------------------------------------

class _ScanState:
    """
    Shared request budget, error log and baseline cache for one scan.

    One instance is now shared by *every* phase of run_exposure_scan (the
    sweep, robots.txt, sitemap.xml, the cloud checks and OPTIONS), because
    `max_requests` previously governed only the sensitive-resource sweep: the
    baseline probes, robots/sitemap, and one OPTIONS request per surfaced
    finding were all made outside it, so an operator asking for at most 400
    requests could receive well over 800.
    """

    def __init__(self, target: str, store: Optional[PendingAssetsStore], max_requests: int):
        self.target = target
        self.store = store
        self.max_requests = max(0, int(max_requests))
        self._lock = threading.Lock()
        self.request_count = 0
        self.budget_exhausted = False
        self.errors: List[Dict[str, Any]] = []
        self.errors_suppressed = 0
        self._baseline_lock = threading.Lock()
        self._baseline_cache: Dict[str, Dict[str, Any]] = {}
        # Dead-origin tripwire (TRANSPORT_FAILURE_TRIP_THRESHOLD).
        self._consecutive_transport_failures = 0
        self._answered_any = False
        self.origin_unreachable = False

    def reserve_request(self) -> bool:
        with self._lock:
            if self.origin_unreachable:
                return False
            if self.request_count >= self.max_requests:
                self.budget_exhausted = True
                return False
            self.request_count += 1
            return True

    def note_transport_failure(self) -> None:
        """
        One probe failed below HTTP (timeout, refused connection, DNS).

        Once TRANSPORT_FAILURE_TRIP_THRESHOLD of them arrive consecutively
        and nothing in this run has ever been answered, the origin is not
        responding: every remaining candidate would cost a full `timeout` and
        return nothing. The scan stops, `scan_complete` is False and the
        reason is reported, so no absence here is ever read as a negative
        result.
        """
        with self._lock:
            self._consecutive_transport_failures += 1
            if (not self._answered_any
                    and not self.origin_unreachable
                    and self._consecutive_transport_failures >= TRANSPORT_FAILURE_TRIP_THRESHOLD):
                self.origin_unreachable = True

    def note_answered(self) -> None:
        """An HTTP response of any status permanently disarms the tripwire."""
        with self._lock:
            self._answered_any = True
            self._consecutive_transport_failures = 0

    def refusal_reason(self) -> str:
        """
        Why the last `reserve_request()` said no, in the caller's own error
        text. Two very different things stop a check running and they must
        not be reported as each other.
        """
        with self._lock:
            if self.origin_unreachable:
                return "the origin stopped answering; this check was not performed"
            return f"request budget of {self.max_requests} exhausted before this check"

    def record_error(self, stage: str, url: str, message: str) -> None:
        with self._lock:
            # Bounded: against a host refusing every connection this list
            # previously grew one entry per candidate and was then persisted
            # and rendered in full. The count of what was dropped is kept.
            if len(self.errors) >= MAX_RECORDED_ERRORS:
                self.errors_suppressed += 1
                return
            self.errors.append({"stage": stage, "url": url, "error": message, "timestamp": _now()})

    def error_records(self) -> List[Dict[str, Any]]:
        with self._lock:
            records = list(self.errors)
            if self.errors_suppressed:
                records.append({
                    "stage": "error_log", "url": "",
                    "error": f"{self.errors_suppressed} further per-request error(s) suppressed "
                             f"after {MAX_RECORDED_ERRORS} recorded",
                    "timestamp": _now(),
                })
        return records

    def get_baseline(self, origin: str, timeout: float) -> Dict[str, Any]:
        with self._baseline_lock:
            if origin not in self._baseline_cache:
                self._baseline_cache[origin] = _probe_soft_404(
                    origin, timeout, on_request=self.reserve_request,
                )
            return self._baseline_cache[origin]


def _probe_sensitive_candidate(
    state: _ScanState, url: str, entry: str, category: str, timeout: float,
) -> Optional[Dict[str, Any]]:
    """
    Fetch, classify, and persist one sensitive-resource candidate.

    Always returns a record so the caller can account for every scheduled
    candidate, but only a record describing an actual observation is
    persisted. The three shapes are:

      * a full finding record (`tested` True, no `negative` flag) — persisted;
      * a negative result (`negative` True: 404/410, or a catch-all match
        carrying no contradicting signature) — counted, not persisted;
      * an untested outcome (`tested` False: a transport failure or a 429) —
        counted and reported as an error, never as absence.
    """
    if state.origin_unreachable:
        # Checked in the worker, not at submission: every candidate is queued
        # before the first response comes back, so the submission loop cannot
        # see the tripwire fire. Reported as untested, which keeps the sweep
        # inconclusive and stops any of it becoming a negative result.
        return {"url": url, "entry": entry, "exposure_category": category,
                "discovery_type": DT_ERROR, "confidence": CONFIDENCE_LOW,
                "error": "not probed: the origin stopped answering", "tested": False}

    resp = fetch_url(url, timeout=timeout)
    if resp["status"] != "found":
        state.record_error("fetch", url, resp.get("error") or "request failed")
        state.note_transport_failure()
        # A request that never completed is not an observation about this
        # path. It is reported as an error and, crucially, is NOT a negative
        # result (context.md §8) — see the caller's conclusiveness accounting.
        return {"url": url, "entry": entry, "exposure_category": category,
                "discovery_type": DT_ERROR, "confidence": CONFIDENCE_LOW,
                "error": resp.get("error"), "tested": False}
    state.note_answered()

    baseline = state.get_baseline(_origin_of(url), timeout)
    # Analysed at most once per candidate, and not at all for a path that turns
    # out to be a 404 or a catch-all match: the framework patterns are the most
    # expensive thing this module runs against a response body, and the
    # overwhelming majority of probed paths do not exist. Only the debug
    # category needs the result *before* classification.
    error_intel = (analyze_error_page(resp.get("body"), resp["headers"], resp.get("status_code"))
                   if category == CATEGORY_DEBUG_ENDPOINT else None)
    discovery_type, confidence, notes, excerpt = evaluate_exposure(
        category, entry, resp, baseline, url=url, error_intel=error_intel,
    )

    contradiction = any(n.startswith(_SUPPRESSED_PREFIX) for n in notes)
    if discovery_type in _NEGATIVE_TYPES and not contradiction:
        # Tested, nothing there. Counted by the caller as a negative result;
        # persisting it would mint a finding asset for a non-finding.
        return {"url": url, "entry": entry, "exposure_category": category,
                "discovery_type": discovery_type, "confidence": confidence,
                "tested": True, "negative": True, "evidence": notes}
    if discovery_type in _NON_EVIDENTIAL_TYPES:
        # Refused / never answered: neither a discovery nor a negative result.
        return {"url": url, "entry": entry, "exposure_category": category,
                "discovery_type": discovery_type, "confidence": confidence,
                "tested": False, "evidence": notes}

    headers = resp["headers"]
    if error_intel is None:
        error_intel = analyze_error_page(resp.get("body"), headers, resp.get("status_code"))

    baseline_available = bool(baseline and baseline.get("available") and baseline.get("usable", True))
    record: Dict[str, Any] = {
        "target": state.target,
        "url": url,
        "path": urllib.parse.urlsplit(url).path or "/",
        "method": "GET",
        "status_code": resp["status_code"],
        "content_type": _ci_get(headers, "Content-Type"),
        "exposure_category": category,
        "discovery_type": discovery_type,
        "confidence": confidence,
        "excerpt": excerpt,
        # Provenance (assignment brief): what was requested, why, how it was
        # found, what was returned, and how complete the observation is.
        "wordlist_entry": entry,
        "discovery_method": "exposure_category_wordlist_sweep",
        "baseline_available": baseline_available,
        "body_truncated": bool(resp.get("body_truncated")),
        "content_complete": not resp.get("body_truncated") and not resp.get("body_read_error"),
        "redirect_location": _ci_get(headers, "Location") if discovery_type == DT_REDIRECT else None,
        "existence_uncertain": discovery_type in _INCONCLUSIVE_TYPES,
        "conflicting_evidence": contradiction,
        "excerpt_redacted": excerpt is not None,
        "tested": True,
        "evidence": [f"GET {url} returned HTTP {resp['status_code']}"] + notes,
        "error_page_indicators": error_intel["indicators"],
        "timestamp": _now(),
    }

    findings = [make_finding(
        finding_type="exposure_finding", target=state.target, value=dict(record),
        evidence=record["evidence"], confidence=confidence,
        metadata={"exposure_category": category, "discovery_type": discovery_type, "url": url,
                  "content_complete": record["content_complete"],
                  "baseline_available": baseline_available},
    )]

    if error_intel["indicators"]:
        findings.append(make_finding(
            finding_type="error_page_intelligence", target=state.target,
            value={"url": url, **error_intel},
            evidence=[i["evidence"] for i in error_intel["indicators"]],
            confidence=CONFIDENCE_MEDIUM,
            metadata={"url": url, "stack_trace_detected": error_intel["stack_trace_detected"]},
        ))

    # One read + one atomic write for this candidate's whole result. A
    # persistence failure is recorded but never discards the record: the
    # caller still receives everything discovered here.
    err = _safe_store_add_many(state.store, findings)
    if err:
        state.record_error("persistence", url, err)

    return record


# ---------------------------------------------------------------------------
# 1/2. Sensitive-resource + application-exposure sweep (single-wordlist-pass
# — no recursion; that is endpoint_discovery.py's/crawler.py's boundary,
# not this module's)
# ---------------------------------------------------------------------------

def discover_sensitive_resources(
    base_url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    wordlists_dir: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    state: Optional[_ScanState] = None,
) -> Dict[str, Any]:
    """
    Sweep wordlists/directories.txt for entries matching a recognized
    exposure category (classify_exposure_category) and evaluate each hit's
    evidence (responsibility groups 1 and 2's debug/admin coverage).

    `state` lets run_exposure_scan share one request budget and error log
    across every phase; when omitted a private one is created so the function
    still works standalone (context.md §12.2).
    """
    base_url = validate_exposure_target(base_url, target=target)
    target = target or (urllib.parse.urlsplit(base_url).hostname or base_url)
    root = _ensure_trailing_slash(_origin_of(base_url))

    errors: List[Dict[str, Any]] = []
    try:
        entries = load_wordlist("directories.txt", wordlists_dir)
    except WordlistError as exc:
        errors.append({"stage": "wordlist_load", "wordlist": "directories.txt", "error": str(exc)})
        entries = []

    # Build the task list deterministically and de-duplicated *by URL*: two
    # wordlist entries can name the same resource (".env" and "/.env"), and
    # _SENSITIVE_DIRECTORIES entries can repeat one already present, which
    # previously spent a request and emitted a finding twice.
    tasks: List[Tuple[str, str, str]] = []
    seen_urls = set()
    candidates = [(entry, classify_exposure_category(entry)) for entry in entries]
    candidates += [(entry, category) for entry, category in _SENSITIVE_DIRECTORIES.items()]
    for entry, category in candidates:
        if not category:
            continue
        try:
            url = _candidate_url(root, entry, target)
        except ScopeError as exc:
            # A wordlist line that resolves outside the target's own origin is
            # refused, not requested (context.md §16).
            errors.append({"stage": "scope", "url": entry, "error": str(exc)})
            continue
        if url in seen_urls:
            continue
        seen_urls.add(url)
        tasks.append((url, entry, category))

    own_state = state is None
    state = state or _ScanState(target, store, max_requests)

    # Take the not-found baseline BEFORE spending the budget on candidates.
    # Taken lazily from inside the first worker, a tight budget was consumed
    # entirely by candidates and the baseline probes then found nothing left —
    # so every candidate was evaluated with no catch-all comparison at all,
    # which is the condition most likely to produce unconfirmable noise.
    if tasks:
        state.get_baseline(_origin_of(root), timeout)
    findings: List[Dict[str, Any]] = []
    untested = 0
    negative_results = 0
    soft_404_matches = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        future_map = {}
        for url, entry, category in tasks:
            if not state.reserve_request():
                break
            future_map[executor.submit(_probe_sensitive_candidate, state, url, entry, category, timeout)] = url
        for future in concurrent.futures.as_completed(future_map):
            url = future_map[future]
            try:
                record = future.result()
            except Exception as exc:  # a single bad task must not abort the sweep
                state.record_error("probe", url, str(exc))
                untested += 1
                continue
            if record is None:
                negative_results += 1
                continue
            if record.get("negative"):
                negative_results += 1
                if record.get("discovery_type") == DT_SOFT_404:
                    soft_404_matches += 1
                continue
            if not record.get("tested", True) or record.get("discovery_type") in _INCONCLUSIVE_TYPES:
                untested += 1
            if record.get("tested", True):
                findings.append(record)

    # Deterministic output ordering: as_completed() returns tasks in whatever
    # order the threads finish, so two identical runs produced the same
    # findings in a different order.
    findings.sort(key=lambda f: (f.get("url") or "", f.get("exposure_category") or ""))

    candidates_scheduled = len(future_map)
    baseline = state.get_baseline(_origin_of(base_url), timeout) if candidates_scheduled else {"available": False}
    # "Conclusive" means every scheduled candidate was actually answered, the
    # budget was not exhausted mid-sweep, and a usable not-found baseline
    # existed to compare against. Only then may absence be recorded as a
    # negative result (context.md §8) — a blocked or truncated run must never
    # poison that memory.
    conclusive = (
        bool(tasks)
        and candidates_scheduled == len(tasks)
        and not state.budget_exhausted
        and untested == 0
        and bool(baseline.get("available")) and bool(baseline.get("usable", True))
    )

    return {
        "target": target, "base_url": base_url,
        "candidates_checked": len(tasks),
        "candidates_probed": candidates_scheduled,
        "candidates_untested": untested,
        "negative_results": negative_results,
        "soft_404_matches": soft_404_matches,
        "baseline": {k: baseline.get(k) for k in ("available", "usable", "dynamic", "status_code", "probes", "reason")},
        "sweep_conclusive": conclusive,
        "findings": findings,
        "errors": errors + (state.error_records() if own_state else []),
        "requests_made": state.request_count, "request_budget_exhausted": state.budget_exhausted,
    }


# ---------------------------------------------------------------------------
# 2b/2c. robots.txt / sitemap.xml discovery
# ---------------------------------------------------------------------------

def _classify_single_resource_status(url: str, status_code: Optional[int]) -> Dict[str, Any]:
    """
    Map a non-200 status for a single named resource (robots.txt,
    sitemap.xml) onto explicit result semantics.

    Everything that was not a 200 was previously reported as
    `status: "not_found"`, which turns a 403, a 429 and a 502 — none of which
    say anything about whether the resource exists — into confirmed absence.
    context.md §8 requires those to stay distinguishable.
    """
    if status_code in (404, 410):
        return {"status": "not_found", "status_code": status_code,
                "evidence": f"GET {url} returned HTTP {status_code}"}
    if status_code in (401, 403):
        return {"status": "access_restricted", "status_code": status_code,
                "evidence": f"GET {url} returned HTTP {status_code} — present or absent is undetermined"}
    if status_code == 429:
        return {"status": "rate_limited", "status_code": status_code,
                "evidence": f"GET {url} returned HTTP 429 — not tested"}
    if status_code is not None and 300 <= status_code < 400:
        return {"status": "redirect", "status_code": status_code,
                "evidence": f"GET {url} returned HTTP {status_code} (redirect not followed)"}
    if status_code is not None and 500 <= status_code < 600:
        return {"status": "server_error", "status_code": status_code,
                "evidence": f"GET {url} returned HTTP {status_code} — not tested"}
    return {"status": "inconclusive", "status_code": status_code,
            "evidence": f"GET {url} returned unexpected HTTP {status_code}"}


def discover_robots_txt(
    base_url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Fetch and parse robots.txt (Disallow/Allow/Sitemap directives)."""
    base_url = validate_exposure_target(base_url, target=target)
    target = target or (urllib.parse.urlsplit(base_url).hostname or base_url)
    root = _ensure_trailing_slash(_origin_of(base_url))
    url = root + "robots.txt"

    resp = fetch_url(url, timeout=timeout)
    if resp["status"] != "found":
        return {"url": url, "status": "error", "error": resp.get("error")}
    if resp["status_code"] != 200:
        return {"url": url, **_classify_single_resource_status(url, resp["status_code"])}

    body = resp.get("body") or ""
    disallow, allow, sitemaps = [], [], []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip().lower()
        value = value.strip()
        # Each directive is bounded as well as the list: a robots.txt is
        # server-controlled content, and one 100 KB "Disallow:" line otherwise
        # entered the graph and the report intact.
        value = value[:MAX_ROBOTS_DIRECTIVE_CHARS]
        if key == "disallow" and value:
            disallow.append(value)
        elif key == "allow" and value:
            allow.append(value)
        elif key == "sitemap" and value:
            sitemaps.append(value)

    truncated = len(disallow) > 100 or len(allow) > 100 or len(sitemaps) > 20
    disallow, allow, sitemaps = disallow[:100], allow[:100], sitemaps[:20]
    record = {
        "url": url, "disallowed_paths": disallow, "allowed_paths": allow, "sitemap_urls": sitemaps,
        "excerpt": _redacted_excerpt(body, max_chars=500),
        "directives_truncated": truncated or bool(resp.get("body_truncated")),
        "method": "GET", "status_code": 200,
        # A path appearing in robots.txt is a *hint about where to look*, not
        # itself evidence of sensitive exposure. Stated in the record so no
        # downstream consumer has to infer it.
        "note": "robots.txt directives are declared paths, not verified exposures; each still "
                "requires its own evidence before it can be called an exposure",
    }
    finding = make_finding(
        finding_type="robots_txt_discovered", target=target, value=record,
        evidence=[f"GET {url} returned HTTP 200 with {len(disallow)} Disallow, {len(allow)} Allow, "
                  f"{len(sitemaps)} Sitemap directive(s)"],
        confidence=CONFIDENCE_HIGH,
        metadata={"url": url, "disallow_count": len(disallow), "sitemap_count": len(sitemaps)},
    )
    err = _safe_store_add(store, finding)
    result = {"url": url, "status": "found", **record}
    if err:
        result["persistence_error"] = err
    return result


_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
MAX_SITEMAP_URLS = 200
MAX_SITEMAP_URL_CHARS = 2048
MAX_ROBOTS_DIRECTIVE_CHARS = 512


def discover_sitemap_xml(
    base_url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Fetch and parse sitemap.xml (<loc> URL entries), false-positive-guarded against soft-404 HTML pages."""
    base_url = validate_exposure_target(base_url, target=target)
    target = target or (urllib.parse.urlsplit(base_url).hostname or base_url)
    root = _ensure_trailing_slash(_origin_of(base_url))
    url = root + "sitemap.xml"

    resp = fetch_url(url, timeout=timeout)
    if resp["status"] != "found":
        return {"url": url, "status": "error", "error": resp.get("error")}
    if resp["status_code"] != 200:
        return {"url": url, **_classify_single_resource_status(url, resp["status_code"])}

    body = resp.get("body") or ""
    content_type = _ci_get(resp["headers"], "Content-Type") or ""
    looks_like_sitemap = ("<urlset" in body.lower() or "<sitemapindex" in body.lower())
    if not looks_like_sitemap:
        return {
            "url": url, "status": "interesting_unconfirmed",
            "note": "HTTP 200 but body does not contain <urlset>/<sitemapindex> — likely a soft-404/SPA "
                    "catch-all page, not a real sitemap",
            "content_type": content_type,
        }

    all_locs = _SITEMAP_LOC_RE.findall(body)
    locs = [loc[:MAX_SITEMAP_URL_CHARS] for loc in all_locs[:MAX_SITEMAP_URLS]]
    in_scope, out_of_scope = [], []
    for loc in locs:
        try:
            host = urllib.parse.urlsplit(loc).hostname or ""
        except ValueError:
            host = ""
        (in_scope if host and _in_scope_host(host, target) else out_of_scope).append(loc)
    record = {
        "url": url, "content_type": content_type, "url_count": len(locs), "urls": locs,
        "in_scope_url_count": len(in_scope), "out_of_scope_url_count": len(out_of_scope),
        "urls_truncated": len(all_locs) > MAX_SITEMAP_URLS or bool(resp.get("body_truncated")),
        "method": "GET", "status_code": 200,
        # Scope provenance: a sitemap is attacker-/owner-controlled content and
        # can name any host at all. Entries are recorded, never fetched here,
        # and their scope is stated so a downstream consumer does not have to
        # re-derive it (context.md §16).
        "note": "sitemap entries are declared URLs, not verified exposures; out-of-scope entries "
                "are recorded for correlation only and were not requested",
    }
    finding = make_finding(
        finding_type="sitemap_xml_discovered", target=target, value=record,
        evidence=[f"GET {url} returned HTTP 200 with a <urlset>/<sitemapindex> body containing {len(locs)} <loc> entries"],
        confidence=CONFIDENCE_HIGH,
        metadata={"url": url, "url_count": len(locs)},
    )
    err = _safe_store_add(store, finding)
    result = {"url": url, "status": "found", **record}
    if err:
        result["persistence_error"] = err
    return result


# ---------------------------------------------------------------------------
# 3. Cloud exposure discovery (responsibility group 3) — see module
# docstring, decision #4 for the authorization model
# ---------------------------------------------------------------------------

_CLOUD_NAME_SUFFIXES = ["", "-assets", "-static", "-backup", "-backups", "-dev", "-staging", "-prod", "-uploads"]

# Provider host suffixes/hosts a built cloud URL is allowed to address. Used
# as a post-construction check (see build_cloud_url): the URL is not merely
# formatted from an identifier, its resulting *host* is verified, so a
# malformed or hostile identifier cannot redirect the request elsewhere.
_S3_HOST_SUFFIX = ".s3.amazonaws.com"
_GCS_HOST = "storage.googleapis.com"
_AZURE_HOST_SUFFIX = ".blob.core.windows.net"

# Bucket/container name charsets, deliberately stricter than each provider's
# own maximum so nothing that could change the *structure* of the URL gets
# through. AWS bucket names are [a-z0-9.-], GCS adds "_", Azure containers are
# [a-z0-9-].
_S3_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")
_GCS_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._\-]{1,220}[a-z0-9]$")
_AZURE_ACCOUNT_RE = re.compile(r"^[a-z0-9]{3,24}$")
_AZURE_CONTAINER_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]$")
# 63 is the longest name AWS and Azure accept; GCS allows more, but a name
# this module *generates* is only ever a guess, and an over-long guess is
# noise no provider would resolve.
_MAX_CLOUD_LABEL_CHARS = 63


class CloudTargetError(ValueError):
    """Raised when a caller-supplied cloud target cannot be safely turned into a request."""


def generate_cloud_candidates(target: str) -> List[Dict[str, str]]:
    """
    Generate S3/GCS bucket-name permutations from `target` for
    informational visibility only — no request is made against any of
    these unless the same identifier is also explicitly supplied via
    `cloud_targets` (module docstring, decision #4).

    Output order is deterministic: the base names were previously iterated
    out of a `set`, so two identical runs produced the same candidates in a
    different order (and a different order in the persisted record).
    """
    if not isinstance(target, str) or not target:
        return []
    # Bounded before any derivation: `target` is a caller argument, and a
    # pathological one produced one multi-megabyte "candidate name" per
    # suffix per provider, each of which was then persisted.
    target = target[:_MAX_CLOUD_LABEL_CHARS]
    label = re.sub(r"[^a-z0-9-]", "-", target.lower()).strip("-")
    label = re.sub(r"-{2,}", "-", label)
    if not label:
        return []
    bases = sorted({label, label.replace(".", "-"), label.split(".")[0]})
    candidates: List[Dict[str, str]] = []
    seen = set()
    for base in bases:
        for suffix in _CLOUD_NAME_SUFFIXES:
            name = f"{base}{suffix}"
            if len(name) > _MAX_CLOUD_LABEL_CHARS:
                # Longer than any provider permits: it could never name a real
                # bucket, so listing it as a candidate is noise.
                continue
            for provider in ("s3", "gcs"):
                key = (provider, name)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append({"provider": provider, "identifier": name})
    return candidates


def validate_cloud_identifier(provider: str, identifier: Any, container: Any = None) -> Tuple[str, Optional[str]]:
    """
    Validate a caller-supplied bucket/container identifier before it is
    interpolated into a URL.

    This is a scope boundary, not tidiness. build_cloud_url() formats the
    identifier straight into the URL, so an identifier of "evil.com/" turned
    "https://{id}.s3.amazonaws.com/" into "https://evil.com/.s3.amazonaws.com/"
    — a request against an entirely different host than the one the operator
    authorised — and an Azure container of "c?comp=list" injected its own
    query string. Both were reachable from a single malformed cloud_targets
    entry.
    """
    provider = (provider or "").strip().lower()
    if not isinstance(identifier, str) or not identifier.strip():
        raise CloudTargetError("cloud identifier must be a non-empty string")
    identifier = identifier.strip().lower()
    container = container.strip().lower() if isinstance(container, str) and container.strip() else None

    if provider == "s3":
        if not _S3_NAME_RE.match(identifier):
            raise CloudTargetError(f"not a valid S3 bucket name: {identifier!r}")
        return identifier, None
    if provider == "gcs":
        if not _GCS_NAME_RE.match(identifier):
            raise CloudTargetError(f"not a valid GCS bucket name: {identifier!r}")
        return identifier, None
    if provider == "azure":
        if not _AZURE_ACCOUNT_RE.match(identifier):
            raise CloudTargetError(f"not a valid Azure storage account name: {identifier!r}")
        if not container:
            raise CloudTargetError("an Azure container name is required to check listability")
        if not _AZURE_CONTAINER_RE.match(container):
            raise CloudTargetError(f"not a valid Azure container name: {container!r}")
        return identifier, container
    raise CloudTargetError(f"unsupported cloud provider: {provider!r}")


def build_cloud_url(provider: str, identifier: str, container: Optional[str] = None) -> Optional[str]:
    """
    Build the single listability-check URL for one cloud resource, or None if
    the provider/identifier/container is not one this module can address
    safely.

    The built URL's host is verified against the provider's own host before it
    is returned, so no formatting mistake or hostile identifier can produce a
    request against a third party.
    """
    provider = (provider or "").strip().lower()
    try:
        identifier, container = validate_cloud_identifier(provider, identifier, container)
    except CloudTargetError:
        return None

    if provider == "s3":
        url = f"https://{identifier}{_S3_HOST_SUFFIX}/"
        expected = f"{identifier}{_S3_HOST_SUFFIX}"
    elif provider == "gcs":
        url = f"https://{_GCS_HOST}/{urllib.parse.quote(identifier, safe='')}/"
        expected = _GCS_HOST
    elif provider == "azure":
        url = (f"https://{identifier}{_AZURE_HOST_SUFFIX}/"
               f"{urllib.parse.quote(container, safe='')}?restype=container&comp=list")
        expected = f"{identifier}{_AZURE_HOST_SUFFIX}"
    else:
        return None

    if (urllib.parse.urlsplit(url).hostname or "") != expected:
        return None
    return url


# Provider error codes, grouped by what they actually prove. Substring matched
# against the response body because every provider returns them inside an XML
# or JSON error envelope.
_CLOUD_EXISTS_DENIED_CODES = (
    "AccessDenied", "AllAccessDisabled", "AuthenticationFailed", "AuthorizationFailure",
    "AuthorizationPermissionMismatch", "PublicAccessNotPermitted", "InvalidSecurity",
    "AccountIsDisabled", "storage.objects.list access",
)
_CLOUD_ABSENT_CODES = (
    "NoSuchBucket", "ContainerNotFound", "BucketNotFound", "InvalidBucketName",
    "AccountProblem",
)
# The bucket exists but lives in another region/endpoint. Redirects are never
# followed, so listability was NOT tested — reporting this as "not found" (as
# an unrecognised 301 body previously would) is a false negative, and
# reporting it as an exposure is a false positive.
_CLOUD_REDIRECT_CODES = ("PermanentRedirect", "TemporaryRedirect", "IllegalLocationConstraintException")
# The provider refused to answer. Neither presence nor absence follows.
_CLOUD_REFUSED_CODES = ("SlowDown", "RequestThrottled", "ServiceUnavailable", "InternalError",
                        "ServerBusy", "OperationTimedOut")

CDT_LISTABLE = DT_CONFIRMED
CDT_EXISTS_RESTRICTED = "bucket_exists_access_restricted"
CDT_NOT_FOUND = DT_NOT_FOUND
CDT_REGION_REDIRECT = "bucket_exists_region_redirect"
CDT_PROVIDER_REFUSED = "provider_refused_inconclusive"
CDT_INCONCLUSIVE = "inconclusive_cloud_response"


def classify_cloud_response(status_code: Optional[int], body: Optional[str]) -> Tuple[str, str, List[str]]:
    """
    Classify a cloud-storage GET response using its XML/JSON error code,
    never a bare status alone.

    The distinctions preserved here are the ones that get conflated most
    often, and each has a different meaning downstream:

      * listable      — a listing document was actually returned. This is the
                        only outcome risk_engine.py scores as a CRITICAL
                        "listable bucket".
      * exists/denied — the provider named an authorization error. The
                        resource exists; nothing was read. This includes
                        account-level blocks (AllAccessDisabled), which are
                        *more* locked down than a plain AccessDenied, not less.
      * region        — the bucket exists elsewhere; listability untested.
      * absent        — the provider explicitly said the resource is not there.
                        This is NOT evidence of a takeover opportunity: a name
                        being unclaimed says nothing about whether the target
                        ever owned it, and this module never asserts one.
      * refused/inconclusive — nothing about existence follows.
    """
    body = body or ""
    if status_code is None:
        return CDT_INCONCLUSIVE, CONFIDENCE_LOW, ["no status code available (request failed)"]

    # A listing document is only meaningful with a success status: a 4xx body
    # can quote the element name back inside an error message.
    if 200 <= status_code < 300 and ("<ListBucketResult" in body or "<EnumerationResults" in body):
        has_contents = "<Contents>" in body or "<Blob>" in body
        note = ("publicly listable — object entries present" if has_contents
                else "publicly listable — bucket/container responded with an empty listing")
        return CDT_LISTABLE, CONFIDENCE_HIGH, [f"Bucket/container listing XML returned ({note})"]

    for code in _CLOUD_REDIRECT_CODES:
        if code in body:
            return (CDT_REGION_REDIRECT, CONFIDENCE_MEDIUM,
                    [f"Response body contains {code!r} — the resource exists but is served from a "
                     f"different regional endpoint; the redirect was not followed, so listability "
                     f"was not tested"])
    for code in _CLOUD_REFUSED_CODES:
        if code in body:
            return (CDT_PROVIDER_REFUSED, CONFIDENCE_LOW,
                    [f"Provider returned {code!r} — the request was refused; neither presence nor "
                     f"absence can be inferred"])
    for code in _CLOUD_EXISTS_DENIED_CODES:
        if code in body:
            return (CDT_EXISTS_RESTRICTED, CONFIDENCE_MEDIUM,
                    [f"Response body contains error code {code!r} — resource exists, listing denied"])
    for code in _CLOUD_ABSENT_CODES:
        if code in body:
            return (CDT_NOT_FOUND, CONFIDENCE_HIGH,
                    [f"Response body contains error code {code!r}",
                     "a name that resolves to no bucket is not, on its own, evidence of an "
                     "ownership or takeover opportunity"])

    if status_code == 429 or 500 <= status_code < 600:
        return (CDT_PROVIDER_REFUSED, CONFIDENCE_LOW,
                [f"HTTP {status_code} from the storage provider — not tested"])
    if status_code == 404:
        return CDT_NOT_FOUND, CONFIDENCE_MEDIUM, ["HTTP 404 with no recognized provider error code"]
    if status_code == 403:
        return (CDT_EXISTS_RESTRICTED, CONFIDENCE_LOW,
                ["HTTP 403 with an unrecognized body format — access is denied, but the response "
                 "did not name a provider error code"])
    if 300 <= status_code < 400:
        return (CDT_REGION_REDIRECT, CONFIDENCE_LOW,
                [f"HTTP {status_code} redirect (not followed) — listability was not tested"])

    return CDT_INCONCLUSIVE, CONFIDENCE_LOW, [f"HTTP {status_code} with an unrecognized response body — inconclusive"]


def check_cloud_resource(
    provider: str, identifier: str, container: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Perform the one live request that both proves existence and tests
    listability for a single, explicitly authorized cloud resource
    (module docstring, decision #4).
    """
    try:
        identifier, container = validate_cloud_identifier(provider, identifier, container)
    except CloudTargetError as exc:
        return {"provider": provider, "identifier": identifier, "container": container,
                "status": "error", "error": str(exc)}

    url = build_cloud_url(provider, identifier, container)
    if not url:
        return {"provider": provider, "identifier": identifier, "container": container,
                "status": "error", "error": "unsupported provider or unbuildable resource URL"}

    resp = fetch_url(url, timeout=timeout)
    if resp["status"] != "found":
        return {"provider": provider, "identifier": identifier, "container": container, "url": url,
                "status": "error", "error": resp.get("error")}

    discovery_type, confidence, notes = classify_cloud_response(resp["status_code"], resp.get("body"))
    return {
        "provider": provider.strip().lower(), "identifier": identifier, "container": container, "url": url,
        "status": "checked", "status_code": resp["status_code"], "discovery_type": discovery_type,
        "confidence": confidence, "method": "GET",
        "evidence": [f"GET {url} returned HTTP {resp['status_code']}"] + notes,
        "excerpt": _redacted_excerpt(resp.get("body")),
        "content_complete": not resp.get("body_truncated") and not resp.get("body_read_error"),
        # Attribution provenance: the operator asserted this identifier is in
        # scope. Shared provider infrastructure means a responding bucket is
        # not, by itself, evidence that the target owns it.
        "ownership_attribution": "operator_asserted_scope",
        "timestamp": _now(),
    }


def _parse_cloud_target(item: Any) -> Dict[str, Any]:
    """
    Normalize one caller-supplied cloud target into
    {"provider", "identifier", "container"} — or raise CloudTargetError.

    Accepts a dict or a provider URL. URL forms recognised, matching what
    operators actually paste in: virtual-hosted S3 (with or without a region
    in the host), path-style S3, GCS bucket URLs in both the storage.googleapis
    and the *.storage.googleapis host forms, and Azure blob container URLs.
    Anything else raises rather than being silently dropped — a cloud target
    the operator listed and this module ignored without a word is a silent
    scope/coverage hole.
    """
    if isinstance(item, dict):
        provider = item.get("provider")
        identifier = item.get("identifier")
        container = item.get("container")
        if not provider or not identifier:
            raise CloudTargetError(f"cloud target dict needs 'provider' and 'identifier': {item!r}")
        validate_cloud_identifier(str(provider), identifier, container)
        return {"provider": str(provider).strip().lower(), "identifier": str(identifier).strip().lower(),
                "container": str(container).strip().lower() if isinstance(container, str) and container.strip() else None}

    if not isinstance(item, str) or not item.strip():
        raise CloudTargetError(f"unsupported cloud target entry: {item!r}")

    candidate = item.strip()
    if any(ch in candidate for ch in "\r\n\t\x00"):
        raise CloudTargetError(f"cloud target contains control characters: {item!r}")
    if "://" not in candidate:
        raise CloudTargetError(f"cloud target string must be a full https:// URL: {item!r}")
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError as exc:
        raise CloudTargetError(f"cloud target URL cannot be parsed: {item!r} ({exc})") from exc
    if parsed.scheme not in ("http", "https"):
        raise CloudTargetError(f"cloud target URL must use http(s): {item!r}")
    host = (parsed.hostname or "").lower()
    segments = [s for s in (parsed.path or "").split("/") if s]

    if host.endswith(".blob.core.windows.net"):
        identifier = host[: -len(".blob.core.windows.net")]
        container = segments[0] if segments else None
        validate_cloud_identifier("azure", identifier, container)
        return {"provider": "azure", "identifier": identifier, "container": container}

    if host == "storage.googleapis.com":
        if not segments:
            raise CloudTargetError(f"GCS URL names no bucket: {item!r}")
        validate_cloud_identifier("gcs", segments[0])
        return {"provider": "gcs", "identifier": segments[0].lower(), "container": None}
    if host.endswith(".storage.googleapis.com"):
        identifier = host[: -len(".storage.googleapis.com")]
        validate_cloud_identifier("gcs", identifier)
        return {"provider": "gcs", "identifier": identifier, "container": None}

    # S3: path-style (s3[.region].amazonaws.com/bucket) and virtual-hosted
    # (bucket.s3[.region][.dualstack].amazonaws.com), including the
    # "s3-<region>" spelling AWS still serves.
    if host == "amazonaws.com" or host.endswith(".amazonaws.com"):
        labels = host.split(".")
        if len(labels) >= 3 and (labels[0] == "s3" or labels[0].startswith("s3-")):
            if not segments:
                raise CloudTargetError(f"path-style S3 URL names no bucket: {item!r}")
            validate_cloud_identifier("s3", segments[0])
            return {"provider": "s3", "identifier": segments[0].lower(), "container": None}
        for index, label in enumerate(labels):
            if label == "s3" or label.startswith("s3-"):
                identifier = ".".join(labels[:index])
                if identifier:
                    validate_cloud_identifier("s3", identifier)
                    return {"provider": "s3", "identifier": identifier, "container": None}
                break
    raise CloudTargetError(f"not a recognized S3/GCS/Azure storage URL: {item!r}")


def discover_cloud_exposure(
    target: str,
    cloud_targets: Optional[List[Any]] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    state: Optional[_ScanState] = None,
) -> Dict[str, Any]:
    """
    Generate informational bucket-name candidates (no requests) and run
    live listability checks only for entries explicitly authorized via
    `cloud_targets` (each item either a dict {"provider", "identifier",
    "container"(azure only)} or a raw cloud-storage URL string).
    """
    candidates = generate_cloud_candidates(target)
    authorized_keys = set()
    parsed_authorized: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    seen_authorized = set()

    for item in cloud_targets or []:
        try:
            parsed = _parse_cloud_target(item)
        except CloudTargetError as exc:
            # Recorded, never silently skipped: an authorized target this
            # module could not parse is a coverage hole the operator must see.
            errors.append({"stage": "cloud_target_parse", "identifier": str(item)[:200], "error": str(exc)})
            continue
        key = (parsed["provider"], parsed["identifier"], parsed.get("container"))
        if key in seen_authorized:
            continue
        seen_authorized.add(key)
        parsed_authorized.append(parsed)
        authorized_keys.add((parsed["provider"], parsed["identifier"]))

    if len(errors) > MAX_RECORDED_ERRORS:
        suppressed = len(errors) - MAX_RECORDED_ERRORS
        errors = errors[:MAX_RECORDED_ERRORS] + [{
            "stage": "cloud_target_parse", "identifier": "",
            "error": f"{suppressed} further unparseable cloud target(s) suppressed",
        }]

    results: List[Dict[str, Any]] = []

    for item in sorted(parsed_authorized, key=lambda i: (i["provider"], i["identifier"], i.get("container") or "")):
        if state is not None and not state.reserve_request():
            errors.append({"stage": "cloud_check", "identifier": item["identifier"],
                           "error": state.refusal_reason()})
            continue
        try:
            result = check_cloud_resource(
                item["provider"], item["identifier"], item.get("container"), timeout=timeout,
            )
        except Exception as exc:  # a single bad cloud check must not abort the rest
            errors.append({"stage": "cloud_check", "identifier": item.get("identifier"), "error": str(exc)})
            continue
        results.append(result)
        if result.get("status") == "checked":
            err = _safe_store_add(store, make_finding(
                finding_type="cloud_resource_finding", target=target, value=result,
                evidence=result["evidence"], confidence=result["confidence"],
                metadata={"provider": result["provider"], "identifier": result["identifier"],
                          "discovery_type": result["discovery_type"],
                          "ownership_attribution": result["ownership_attribution"]},
            ))
            if err:
                errors.append({"stage": "persistence", "identifier": item.get("identifier"), "error": err})
        else:
            errors.append({"stage": "cloud_check", "identifier": item.get("identifier"),
                           "error": result.get("error") or "cloud check failed"})

    candidate_records = []
    for c in candidates:
        if (c["provider"], c["identifier"]) in authorized_keys:
            continue  # already recorded above as a live cloud_resource_finding
        candidate_records.append({**c, "url": build_cloud_url(c["provider"], c["identifier"])})

    if candidate_records:
        err = _safe_store_add(store, make_finding(
            finding_type="cloud_candidate_not_probed", target=target,
            value={"candidates": candidate_records, "count": len(candidate_records),
                   "note": "name permutations derived from the target's own name; no request was "
                           "made and no relationship to the target has been verified"},
            evidence=[f"{len(candidate_records)} bucket-name permutation(s) generated from target name; "
                      f"no request made — not present in the explicitly authorized cloud_targets scope"],
            confidence=CONFIDENCE_LOW,
            metadata={"count": len(candidate_records), "note": "candidate names only, not verified"},
        ))
        if err:
            errors.append({"stage": "persistence", "identifier": "cloud_candidates", "error": err})

    return {
        "target": target, "checked": results, "candidates_not_probed": len(candidate_records),
        "authorized_targets": len(parsed_authorized),
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# 5. HTTP OPTIONS discovery (responsibility group 5)
# ---------------------------------------------------------------------------

def probe_options(
    url: str, target: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Perform one OPTIONS request against `url` and classify the result."""
    url = validate_discovered_url(url, target)
    resp = fetch_options(url, timeout=timeout)
    if resp["status"] != "found":
        return {"url": url, "status": "error", "error": resp.get("error")}

    allow_header = _ci_get(resp["headers"], "Allow")
    acam = _ci_get(resp["headers"], "Access-Control-Allow-Methods")
    methods = sorted({m.strip().upper() for m in allow_header.split(",") if m.strip()}) if allow_header else []

    if allow_header:
        discovery_type, confidence = "options_supported", CONFIDENCE_HIGH
        evidence = [f"OPTIONS {url} returned HTTP {resp['status_code']} with Allow: {allow_header[:200]!r}"]
    elif resp["status_code"] in (200, 204):
        discovery_type, confidence = "options_response_no_allow_header", CONFIDENCE_LOW
        evidence = [f"OPTIONS {url} returned HTTP {resp['status_code']} without an Allow header"]
    elif resp["status_code"] in (404, 410):
        discovery_type, confidence = DT_NOT_FOUND, CONFIDENCE_HIGH
        evidence = [f"OPTIONS {url} returned HTTP {resp['status_code']}"]
    elif resp["status_code"] in (401, 403):
        discovery_type, confidence = DT_ACCESS_RESTRICTED, CONFIDENCE_MEDIUM
        evidence = [f"OPTIONS {url} returned HTTP {resp['status_code']}"]
    elif resp["status_code"] == 405:
        discovery_type, confidence = DT_METHOD_NOT_ALLOWED, CONFIDENCE_MEDIUM
        evidence = [f"OPTIONS {url} returned HTTP 405 — OPTIONS itself is not permitted here"]
    elif resp["status_code"] == 429:
        discovery_type, confidence = DT_RATE_LIMITED, CONFIDENCE_LOW
        evidence = [f"OPTIONS {url} returned HTTP 429 — not tested"]
    else:
        discovery_type, confidence = DT_UNEXPECTED_STATUS, CONFIDENCE_LOW
        evidence = [f"OPTIONS {url} returned unexpected HTTP {resp['status_code']}"]

    # Who answered matters: an edge/CDN/proxy commonly answers OPTIONS itself,
    # so the Allow header can describe the edge rather than the application.
    # Recorded as provenance instead of being asserted either way.
    served_by = {h: _ci_get(resp["headers"], h)
                 for h in ("Server", "Via", "X-Cache", "CF-Ray", "X-Amz-Cf-Id", "X-Served-By")}
    served_by = {k: v[:200] for k, v in served_by.items() if v}
    if served_by:
        evidence.append(
            _PROVENANCE_EVIDENCE_PREFIX
            + ", ".join(f"{k}: {v!r}" for k, v in sorted(served_by.items()))
        )

    return {
        "url": url, "status": "found", "status_code": resp["status_code"],
        "discovery_type": discovery_type, "confidence": confidence,
        "allow_header": allow_header[:200] if allow_header else None,
        "advertised_methods": methods,
        "access_control_allow_methods": acam[:200] if acam else None,
        "response_provenance_headers": served_by,
        "method": "OPTIONS",
        "evidence": evidence,
        "timestamp": _now(),
        "note": "An advertised method is server-side support information only, not proof it is "
                "exploitable, not proof the application implements it, and — where an edge or "
                "proxy answered — not necessarily a statement about the origin at all. No "
                "advertised method is exercised by this module.",
    }


def discover_http_options(
    urls: List[str],
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_urls: int = DEFAULT_MAX_OPTIONS_URLS,
    state: Optional[_ScanState] = None,
) -> Dict[str, Any]:
    """
    Run OPTIONS discovery across a bounded, deduplicated list of URLs,
    persisting each result.

    Bounded twice over: `max_urls` caps how many URLs one phase probes at all
    (the caller-supplied `endpoints` list is arbitrary in size, and the
    module's own sweep contributes one URL per surfaced finding — against a
    catch-all host that was one OPTIONS request per wordlist entry), and
    `state`, when supplied, charges each request to the run's shared budget.
    """
    unique_urls = sorted(set(u for u in urls if isinstance(u, str) and u.strip()))
    skipped = max(0, len(unique_urls) - max(0, max_urls))
    unique_urls = unique_urls[: max(0, max_urls)]
    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    errors_lock = threading.Lock()
    budget_exhausted = False

    def _record_error(entry: Dict[str, Any]) -> None:
        with errors_lock:
            if len(errors) < MAX_RECORDED_ERRORS:
                errors.append(entry)

    def _one(url: str) -> Optional[Dict[str, Any]]:
        try:
            return probe_options(url, target=target, timeout=timeout)
        except ScopeError as exc:
            _record_error({"stage": "scope", "url": url, "error": str(exc)})
            return None

    scheduled: List[str] = []
    origin_unreachable = False
    for url in unique_urls:
        if state is not None and not state.reserve_request():
            # Two different refusals; only one of them is the budget.
            if getattr(state, "origin_unreachable", False):
                origin_unreachable = True
            else:
                budget_exhausted = True
            break
        scheduled.append(url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        future_map = {executor.submit(_one, url): url for url in scheduled}
        for future in concurrent.futures.as_completed(future_map):
            url = future_map[future]
            try:
                result = future.result()
            except Exception as exc:  # a single bad OPTIONS probe must not abort the rest
                _record_error({"stage": "probe", "url": url, "error": str(exc)})
                continue
            if result is None:
                continue
            if result.get("status") == "error":
                _record_error({"stage": "fetch", "url": url, "error": result.get("error")})
                continue
            results.append(result)
            # surface_mapper.py keys a finding asset on a hash of the whole
            # `value`, so a per-request trace id (CF-Ray, X-Amz-Cf-Id) or this
            # run's own clock inside it mints a new finding asset, a new risk
            # signal and a new report row for the same unchanged OPTIONS
            # result on every re-scan. Both are real evidence and are kept —
            # in `metadata`, which the graph stores per observation and
            # risk_engine merges latest-wins (the split vuln_intel.py already
            # makes for its KEV/EPSS annotations).
            volatile = {k: result[k] for k in _VOLATILE_OPTIONS_KEYS if k in result}
            stable = {k: v for k, v in result.items() if k not in _VOLATILE_OPTIONS_KEYS}
            stable["evidence"] = [line for line in result["evidence"]
                                  if not line.startswith(_PROVENANCE_EVIDENCE_PREFIX)]
            err = _safe_store_add(store, make_finding(
                finding_type="http_options_result", target=target or url, value=stable,
                evidence=result["evidence"], confidence=result["confidence"],
                metadata={"url": url, "discovery_type": result["discovery_type"],
                          "advertised_methods": result["advertised_methods"],
                          "observed_at": result.get("timestamp"), **volatile},
            ))
            if err:
                _record_error({"stage": "persistence", "url": url, "error": err})

    results.sort(key=lambda r: r.get("url") or "")
    return {
        "urls_checked": len(scheduled), "urls_supplied": len(set(urls or [])),
        "urls_skipped_over_limit": skipped, "request_budget_exhausted": budget_exhausted,
        "origin_unreachable": origin_unreachable,
        "results": results, "errors": errors,
    }


# ---------------------------------------------------------------------------
# Full single-target orchestration
# ---------------------------------------------------------------------------

# Outcomes worth an OPTIONS follow-up: something is there. `not_found`,
# `possible_soft_404_match` and the inconclusive states are excluded — probing
# them is pure request amplification against a catch-all host.
_OPTIONS_WORTHY_TYPES = frozenset({DT_CONFIRMED, DT_INTERESTING, DT_ACCESS_RESTRICTED, DT_REDIRECT})


def run_exposure_scan(
    base_url: str,
    target: Optional[str] = None,
    output_dir: str = "output",
    wordlists_dir: Optional[str] = None,
    cloud_targets: Optional[List[Any]] = None,
    endpoints: Optional[List[str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    max_options_urls: int = DEFAULT_MAX_OPTIONS_URLS,
) -> Dict[str, Any]:
    """
    Run every exposure_scan.py responsibility against `base_url` and
    persist every completed discovery immediately to
    <output_dir>/pending_assets.json (crash-safe). Each phase is isolated
    (module docstring / assignment brief: "one failed endpoint must not
    unnecessarily terminate the entire exposure scan") — a failure in one
    phase is recorded in summary["errors"] and does not prevent the
    remaining phases from running.

    `max_requests` now governs the *whole* run: the sweep, its baseline
    probes, robots.txt, sitemap.xml, the authorized cloud checks and every
    OPTIONS request share one budget, so the number the operator asked for is
    the number of requests this module can make.
    """
    base_url = validate_exposure_target(base_url, target=target)
    target = target or (urllib.parse.urlsplit(base_url).hostname or base_url)

    store = PendingAssetsStore(output_dir=output_dir)
    state = _ScanState(target, store, max_requests)

    summary: Dict[str, Any] = {
        "target": target,
        "module": MODULE_NAME,
        "base_url": base_url,
        "started_at": _now(),
        "sensitive_resources": {},
        "robots_txt": {},
        "sitemap_xml": {},
        "cloud_exposure": {},
        "http_options": {},
        "errors": [],
    }

    try:
        summary["sensitive_resources"] = discover_sensitive_resources(
            base_url, target=target, store=store, wordlists_dir=wordlists_dir,
            timeout=timeout, max_workers=max_workers, max_requests=max_requests, state=state,
        )
    except (ScopeError, WordlistError) as exc:
        summary["errors"].append({"stage": "sensitive_resources", "error": str(exc)})
    except Exception as exc:
        summary["errors"].append({"stage": "sensitive_resources", "error": f"unexpected error: {exc}"})

    for stage, fn in (("robots_txt", discover_robots_txt), ("sitemap_xml", discover_sitemap_xml)):
        if not state.reserve_request():
            summary["errors"].append({"stage": stage, "error": state.refusal_reason()})
            summary[stage] = {"status": "not_checked", "reason": state.refusal_reason()}
            continue
        try:
            summary[stage] = fn(base_url, target=target, store=store, timeout=timeout)
        except Exception as exc:
            summary[stage] = {"status": "error", "error": f"unexpected error: {exc}"}
        if summary[stage].get("status") == "error":
            summary["errors"].append({"stage": stage, "error": summary[stage].get("error")})

    try:
        summary["cloud_exposure"] = discover_cloud_exposure(
            target, cloud_targets=cloud_targets, store=store, timeout=timeout, state=state,
        )
    except Exception as exc:
        summary["errors"].append({"stage": "cloud_exposure", "error": f"unexpected error: {exc}"})

    # OPTIONS targets: the caller's endpoint list plus this module's own
    # surfaced findings. Every URL is re-validated through the
    # discovered-URL gate — `endpoints` originates in crawler/endpoint_discovery
    # output, i.e. ultimately in response bodies, so an entry naming an
    # unrelated IP literal (cloud metadata, an RFC1918 host) must not be
    # probed just because it was handed in.
    options_urls: List[str] = []
    scope_rejected = 0
    for candidate in list(endpoints or []) + [
        f["url"] for f in summary.get("sensitive_resources", {}).get("findings", [])
        if f.get("discovery_type") in _OPTIONS_WORTHY_TYPES and f.get("url")
    ]:
        try:
            options_urls.append(validate_discovered_url(candidate, target))
        except ScopeError as exc:
            scope_rejected += 1
            # Bounded: `endpoints` is caller-supplied and arbitrarily long, so
            # a list of a hundred thousand out-of-scope URLs would otherwise
            # put a hundred thousand error records into the summary. The count
            # is always exact; only the individual records are capped.
            if scope_rejected <= MAX_RECORDED_ERRORS:
                summary["errors"].append({"stage": "http_options_scope", "url": str(candidate)[:200],
                                          "error": str(exc)})
            continue
    if scope_rejected > MAX_RECORDED_ERRORS:
        summary["errors"].append({
            "stage": "http_options_scope", "url": "",
            "error": f"{scope_rejected - MAX_RECORDED_ERRORS} further out-of-scope URL(s) suppressed",
        })

    try:
        summary["http_options"] = discover_http_options(
            options_urls, target=target, store=store, timeout=timeout, max_workers=max_workers,
            max_urls=max_options_urls, state=state,
        )
        summary["http_options"]["urls_rejected_out_of_scope"] = scope_rejected
    except Exception as exc:
        summary["errors"].append({"stage": "http_options", "error": f"unexpected error: {exc}"})

    # Every phase's errors are surfaced at the top level. Previously only the
    # sensitive-resource sweep's were, so a run whose cloud checks and OPTIONS
    # probes had all failed still reported status "completed".
    sweep = summary.get("sensitive_resources") or {}
    summary["errors"].extend(sweep.get("errors", []))
    summary["errors"].extend(state.error_records())
    summary["errors"].extend((summary.get("cloud_exposure") or {}).get("errors", []))
    summary["errors"].extend((summary.get("http_options") or {}).get("errors", []))

    if len(summary["errors"]) > MAX_SUMMARY_ERRORS:
        suppressed = len(summary["errors"]) - MAX_SUMMARY_ERRORS
        summary["errors"] = summary["errors"][:MAX_SUMMARY_ERRORS] + [{
            "stage": "error_log", "error": f"{suppressed} further error record(s) suppressed",
        }]
    summary["error_count"] = len(summary["errors"])

    summary["requests_made"] = state.request_count
    summary["request_budget"] = state.max_requests
    summary["request_budget_exhausted"] = state.budget_exhausted
    # Explicit completeness, so no consumer has to infer coverage from the
    # absence of findings (context.md §8: a partial scan is not a clean bill of
    # health).
    summary["origin_unreachable"] = state.origin_unreachable
    summary["scan_complete"] = bool(
        not state.budget_exhausted
        and not state.origin_unreachable
        and sweep.get("sweep_conclusive")
        and not summary["errors"]
    )
    # Why the run was not complete, in the module's own words. `status` keeps
    # its two-value contract ("completed" / "completed_with_errors"), which
    # says whether anything *errored*; on its own that reads as a clean bill
    # of health for a run in which most paths were never actually tested.
    incomplete_reasons: List[str] = []
    if state.origin_unreachable:
        incomplete_reasons.append(
            f"the origin stopped answering after {TRANSPORT_FAILURE_TRIP_THRESHOLD} consecutive "
            f"transport failures with no request ever answered; the remaining checks were not "
            f"performed and nothing here is evidence that this host exposes nothing")
    if state.budget_exhausted:
        incomplete_reasons.append(
            f"request budget of {state.max_requests} was exhausted before every check ran")
    if sweep.get("candidates_untested"):
        incomplete_reasons.append(
            f"{sweep['candidates_untested']} candidate path(s) were not conclusively tested "
            f"(refused, failed or answered inconclusively)")
    if sweep and not sweep.get("baseline", {}).get("available"):
        incomplete_reasons.append("no usable not-found baseline could be taken for this host")
    if summary["http_options"].get("urls_skipped_over_limit"):
        incomplete_reasons.append(
            f"{summary['http_options']['urls_skipped_over_limit']} OPTIONS candidate(s) exceeded "
            f"the per-run cap of {max_options_urls}")
    if summary["errors"]:
        incomplete_reasons.append(f"{len(summary['errors'])} error(s) were recorded")
    summary["completeness"] = "complete" if summary["scan_complete"] else "partial"
    summary["incomplete_reasons"] = incomplete_reasons

    # Negative-result memory (context.md §8/§12.6). Emitted ONLY when the
    # sweep was actually conclusive: the finding type contains "_checked_no",
    # which surface_mapper.py trusts as authoritative "checked and not found"
    # state, so recording it after a blocked, budget-truncated or partially
    # failed run would poison that memory and suppress a later, better run.
    if sweep.get("sweep_conclusive") and not sweep.get("findings"):
        err = _safe_store_add(store, make_finding(
            finding_type="exposure_scan_checked_no_exposure",
            target=target,
            value={"base_url": base_url,
                   "candidates_probed": sweep.get("candidates_probed"),
                   "negative_results": sweep.get("negative_results"),
                   "baseline": sweep.get("baseline")},
            evidence=[
                f"Probed {sweep.get('candidates_probed')} exposure-category candidate path(s) under "
                f"{base_url} against a usable not-found baseline; every one was answered and none "
                f"produced a response distinguishable from this host's not-found behaviour",
            ],
            confidence=CONFIDENCE_MEDIUM,
            metadata={"base_url": base_url, "conclusive": True},
        ))
        if err:
            summary["errors"].append({"stage": "persistence", "error": err})

    summary["status"] = "completed_with_errors" if summary["errors"] else "completed"
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="exposure_scan.py",
        description="ReconHound Module 15 — sensitive resource/information exposure discovery (standalone test entry point).",
    )
    parser.add_argument("--url", required=True, help="Base URL, e.g. https://example.com/")
    parser.add_argument("--target", default=None, help="Logical target domain to enforce scope against")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--wordlists-dir", default=None, help="Override wordlists/ directory")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout (seconds)")
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS, help="Total request budget")
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Concurrent worker threads")
    args = parser.parse_args()

    try:
        result = run_exposure_scan(
            args.url, target=args.target, output_dir=args.output_dir, wordlists_dir=args.wordlists_dir,
            timeout=args.timeout, max_requests=args.max_requests, max_workers=args.max_workers,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
