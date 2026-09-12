"""
reconhound/vuln_intel.py — ReconHound Module 19 (vuln_intel.py).

Phase: Intelligence. See context.md §10 (module 19, "Technology-to-CVE
mapping") for the authoritative responsibilities, and §8 for the
evidence/confidence data model this module implements. This file only
documents implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Technology-to-CVE mapping. Consumes versions from tech_fingerprint.py
  and active_recon.py, queries NVD + public vuln DBs, maps versions to
  known CVEs. Output style: 'Detected Nginx 1.18.0 — MAY be affected by
  CVE-XXXX.' Never claim 'confirmed exploitable' without actual evidence.
  Detection != confirmed vulnerability." -> risk_engine.py

THE CENTRAL RULE OF THIS MODULE: a technology/version match to a CVE is
vulnerability INTELLIGENCE, never proof of exploitability. Nothing in this
file ever emits the phrase "confirmed exploitable", and every persisted
finding/statement distinguishes:

  detected technology/version -> matching/possibly-applicable CVE ->
  supporting evidence -> confidence/applicability -> source -> timestamp.

The invariant this module holds, in one line:

  DETECTION / INTELLIGENCE != CONFIRMED VULNERABILITY != CONFIRMED EXPLOITATION

Responsibility -> implementation map:

  - Consume tech/version observations
    (tech_fingerprint.py + active_recon.py) -> normalize_technology_observation,
                                                extract_observations_from_active_recon
  - Query the NVD API                        -> query_nvd
  - Query CISA KEV                           -> query_cisa_kev
  - Query OSV                                -> query_osv
  - Query GitHub Security Advisories         -> query_github_advisories
  - Query FIRST EPSS                         -> query_epss
  - Query Exploit-DB                         -> fetch_exploitdb_index
  - Map technology/version to known CVEs     -> map_technology_to_cves
                                                 (+ query_all_sources)
  - Normalized vuln-intelligence output for
    risk_engine.py                           -> the "vulnerability_intelligence"
                                                 findings persisted by
                                                 map_technology_to_cves
  - Single-run orchestration                 -> run_vuln_intel

BUILD-ORDER NOTE: context.md §13 lists this module at build-order position
10. It was originally implemented under a user-approved deviation from
that order, ahead of surface_mapper.py and tech_fingerprint.py. Both now
exist; the input contract documented below was written to be the hand-off
point they use, and core/orchestrator.py drives exactly that path
(technology assets from the correlated graph -> technology_observations).

INPUT-CONTRACT DECISION:

  1. Every module in this repo persists findings via the same
     {type, target, value, evidence, confidence, source, timestamp,
     metadata} shape (context.md §8). Rather than inventing a second,
     vuln_intel-specific technology model, this module reads that shape
     directly: normalize_technology_observation() accepts any dict
     carrying a recognizable technology-name key (technology / product /
     name / software / framework) and an optional version key (version /
     product_version).
  2. active_recon.py persists two finding types with parseable
     software/version text: "ssh_fingerprint" (its own already-parsed
     `software` field) and "banner" (raw banner text, parsed best-effort
     via parse_name_version_from_text). active_recon.py's
     "service_identification"/"service_conflict" findings are deliberately
     NOT used as technology observations: they only ever carry a generic
     protocol name (e.g. "ssh", "ftp", "mysql"), never a vendor/product
     name, so a CVE keyword search built from them would be too broad to
     be useful and would burn API quota on noise — a documented,
     deliberate exclusion, not an oversight.
  3. A caller-supplied `technology_observations` list (run_vuln_intel /
     map_technology_to_cves) is the hand-off point core/orchestrator.py
     uses for graph-derived technology assets.

TECH_FINGERPRINT_INPUT_CONTRACT:

  {"technology": str, "version": Optional[str], "category": Optional[str],
   "target": str, "confidence": "LOW"|"MEDIUM"|"HIGH",
   "evidence": [str, ...], "source": "tech_fingerprint.py"}

  `target` must be a hostname or IP literal, NOT a URL and NOT a
  technology name. surface_mapper.py resolves a finding's `target` as a
  hostname and mints a hostname asset from it; handing it "nginx" or
  "https://example.com/" mints a phantom asset that no scan can ever
  correspond to. This module enforces that itself (see
  _observation_target) rather than trusting its callers.

CONFIDENCE MODEL (context.md §8; the hard requirement that a database hit
must never erase upstream uncertainty). Four independent dimensions are
tracked per finding and the final confidence is the MINIMUM of them —
a vulnerability database returning an exact-looking CPE can raise the
quality of the MAPPING, but it can never make a LOW-confidence technology
fingerprint into a HIGH-confidence statement about this target:

  1. technology_confidence — the upstream detection's own confidence,
     exactly as the producing module reported it. Never raised here.
  2. mapping_confidence    — how well the observed product/version could
     be tied to the advisory's own applicability data
     (see `applicability` + `match_quality` below).
  3. source_confidence     — how many independent sources agree, and
     whether their data is authoritative range data or a name search.
  4. applicability evidence — recorded (fixed versions, affected ranges,
     ecosystem, CVSS attack metadata) but never inferred as satisfied.

VERSION-MATCH HONESTY: every CVE match is tagged with an `applicability`
(the vocabulary risk_engine.classify_vulnerability_intelligence consumes;
it is deliberately NOT extended, so nuances are expressed through
confidence and notes rather than through unrecognized enum values):

  - "version_range_confirmed"       — an authoritative source's own
    version-range data (NVD CPE versionStart/EndIncluding/Excluding,
    OSV's server-side version filtering, or a parsed GitHub Advisory
    vulnerable_version_range) places the observed version inside the
    documented vulnerable range.
  - "keyword_match_version_unconfirmed" — the product name matched, but
    no source's range data could confirm (or deny) that the specific
    observed version is affected.
  - "version_unknown_cannot_confirm" — no version was observed at all;
    every resulting CVE reference is a bare product-name keyword match.

MATCH QUALITY (new, additive — recorded as `match_quality` and folded into
mapping_confidence):

  - "cpe_product_exact"   — the CPE product name equals the observed
    technology name after normalization.
  - "cpe_product_alias"   — the CPE product name is a curated, explicit
    alias of the observed technology (see _PRODUCT_ALIASES; every entry is
    version-controlled, narrow and provenance-carrying).
  - "cpe_product_related" — the names merely share a substring
    (e.g. observed "nginx" vs CPE product "nginx_controller"). This is
    NOT treated as applicable range data: a related-name CPE can never
    produce "version_range_confirmed". Before this was enforced, an
    NGINX Controller CVE range-confirmed against plain nginx 1.18.0, and
    an observed "ssh" range-confirmed against every OpenSSH CVE.
  - "package_query"       — OSV/GHSA package-ecosystem queries, where the
    provider itself did the version filtering for the exact package name
    that was queried.

  KNOWN LIMIT: the CPE VENDOR field is not matched. Two vendors can publish
  a product under the same name (cpe:/a:openresty:express vs
  cpe:/a:expressjs:express), and a keyword search plus exact product match
  cannot tell them apart. Doing so would need a curated vendor table per
  detector name; until then this is technology-identification uncertainty
  that the observation's own confidence must carry, and it is the reason
  the product-level match is called "exact", never "verified".

BACKPORTING (bounded, honest representation; full distribution-aware
applicability is deferred — see DEFERRED below). Distribution-maintained
packages carry security fixes backported onto an unchanged upstream
version, so an upstream range match cannot establish that a distro build
is affected. This module does NOT invent distribution patch status. It
detects distribution/vendor revision markers in the observed version
(_looks_backported: "1.18.0-6.1+deb11u3", "2.4.6-2ubuntu1", "1.1.1k-r0",
"...el8...") and, when one is present:

  - caps mapping_confidence at MEDIUM even for a confirmed upstream range,
  - sets `backport_uncertainty: true` on the record,
  - adds an explicit note and a qualifying clause to the statement.

  KNOWN LIMIT of that detection: it reads the VERSION STRING only. A banner
  like "Apache/2.4.41 (Ubuntu)" carries the distribution in the OS comment
  while the version itself looks like a plain upstream release, so this module
  cannot tell it is a distribution build and will not mark it uncertain. That
  is a false-negative in the safe direction for the detector but a real gap:
  it is a reason distro-advisory support is on the deferred list below, not a
  reason to treat an upstream range match as proof.

NEGATIVE-RESULT SEMANTICS (context.md §8 negative-result memory). A
provider outage must never look like a clean result. Every provider
returns, in addition to its legacy `status`, an `outcome` from an explicit
vocabulary, and only `found`/`empty_authoritative` are CONCLUSIVE. The
`vuln_intel_checked_no_match` negative-result finding is persisted ONLY
when every CVE-discovery source that ran was conclusive. Previously a
rate-limited NVD alongside any other non-failing source produced a
persisted "checked, no match" record — a false clean result that
surface_mapper.py then stored as CHECK_NOT_FOUND. KEV/Exploit-DB/EPSS are
ANNOTATION sources and are excluded from that computation entirely; they
were previously mixed into it and could single-handedly mask an outage.

THREE-STATE ANNOTATION SEMANTICS. `cisa_kev` stays None when a CVE is not
listed (risk_engine.py's contract treats it as a truthy escalation
factor), and the additive `cisa_kev_status` / `exploitdb_status` /
`epss` objects carry the checked-vs-unknown distinction: a KEV feed
outage is `{"checked": false, "listed": null}`, not "not listed". Same
for EPSS: an unavailable score is `null` with a reason, never 0.0.

PER-SOURCE DOCUMENTED LIMITATIONS:

  - NVD: keyword search, not a CPE lookup — NVD has no public
    "give me the CVEs for this CPE" endpoint that does not first require
    resolving a CPE name, so the query is `keywordSearch=<technology>`
    and the CPE configuration data of each returned CVE is then inspected
    locally. Unauthenticated requests are limited to 5 per rolling 30 s
    (50 with an API key); supply one via NVD_API_KEY or `api_key`. This
    module rate-limits itself to match, honours Retry-After on 429/403,
    and retries with bounded exponential backoff plus jitter only when a
    RetryPolicy is supplied (run_vuln_intel supplies one). Results are
    paginated up to an explicit cap and truncation is reported, never
    hidden.
  - OSV: the package-query endpoint requires a known package ecosystem.
    A small, explicit hint table (_OSV_ECOSYSTEM_HINTS) covers common
    cases; when no ecosystem can be inferred and none is supplied, OSV is
    reported as outcome="skipped" with an explicit reason — no ecosystem
    is ever guessed. Note that a PRODUCT name is not always a PACKAGE
    name; the queried package name is recorded on every record so the
    assumption is auditable rather than invisible.
  - GitHub Security Advisories: only advisories carrying a GitHub-assigned
    `cve_id` are mapped to CVEs (this module maps to CVEs specifically);
    GHSA-only advisories are counted in `skipped_no_cve_advisories`, never
    silently dropped. The GHSA id, ecosystem, package and first patched
    version are preserved on the record. Works unauthenticated (low rate
    limit); set GITHUB_TOKEN to raise it.
  - FIRST EPSS: an exploitation-LIKELIHOOD score for a CVE, in [0, 1].
    It is not evidence that this target is exploitable or exploited, and
    is annotated as such. Scores are queried in batches, the score and
    percentile are preserved as floats with the model date, and an
    unavailable score is null with a reason (never 0.0, which is a
    legitimate score).
  - Exploit-DB: there is no official query API. This module fetches the
    public files_exploits.csv index (multi-megabyte) once per run and
    looks up CVE IDs in its `codes` column. Presence of an entry means a
    public PoC exists somewhere for that CVE — NOT that it works against
    the asset being assessed.
  - CISA KEV: presence on the catalog means CISA has evidence the CVE has
    been exploited in the wild against SOME target. Real intelligence,
    but explicitly not target-specific confirmation, and annotated as
    such everywhere it is surfaced.

REJECTED / DEFERRED (recorded so the decisions are auditable):

  - Snyk: REJECTED for v1. Its vulnerability database requires a
    commercial account and its terms restrict redistribution/derived use;
    ReconHound ships no account, and dead configuration for a source that
    cannot run is worse than an honest omission.
  - Distribution security advisories (Debian DSA/DLA, Ubuntu USN, Red Hat
    OVAL, Alpine secdb): DEFERRED. Correct distro applicability needs a
    per-distro advisory ecosystem plus reliable OS identification, which
    reconnaissance-grade banners rarely provide. v1 represents the
    resulting uncertainty (see BACKPORTING) instead of guessing. The
    provider layer below is the extension point if this is built.
  - WAF/CDN/cloud perimeter context: NOT this module's call. A WAF in
    front of an asset is not evidence that a CVE is unreachable.
    http_analyzer.py/tech_fingerprint.py already emit that evidence
    independently and risk_engine.py correlates it; inferring
    exploitability from it here would be exactly the unsupported claim
    this module exists to avoid.
  - Continuous monitoring: out of scope. Findings are point-in-time and
    carry `observed_at`; nothing here implies an asset still exists.

RESOURCE AND SECURITY POSTURE. Every provider response is treated as
hostile input: bodies are read under a byte cap (never resp.content),
every provider-controlled string is control-character/bidi-escaped and
length-clipped before it is persisted, every persisted collection is
capped with an explicit `*_truncated` marker, version strings are token-
capped before comparison, and one run is bounded by a request budget, a
per-provider rate limit, a retry cap and a wall-clock deadline.

Every discovery is persisted to <output_dir>/pending_assets.json via
PendingAssetsStore (the same crash-safe atomic-write store every other
module uses, sharing the same output file), in ONE batched write per
observation rather than one whole-file rewrite per CVE.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import random
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import requests

MODULE_NAME = "vuln_intel.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"
_CONFIDENCE_ORDER = {CONFIDENCE_LOW: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_HIGH: 2}

DEFAULT_USER_AGENT = "ReconHound-VulnIntel/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 15.0

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_BASE = "https://api.osv.dev/v1/query"
GITHUB_ADVISORIES_API = "https://api.github.com/advisories"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"

NVD_API_KEY_ENV = "NVD_API_KEY"
GITHUB_TOKEN_ENV = "GITHUB_TOKEN"

# One request per rate-limit slot: a page of 100 costs exactly what a page of
# 20 did, and DEFAULT_NVD_MAX_RESULTS is reached in a single request.
NVD_DEFAULT_RESULTS_PER_PAGE = 100

DEFAULT_SOURCES: Tuple[str, ...] = ("nvd", "osv", "github_advisories")
_VALID_SOURCES = set(DEFAULT_SOURCES)

# Annotation sources. Deliberately NOT part of _VALID_SOURCES: they never
# discover a CVE, they only decorate one, so they must never take part in
# deciding whether "no CVE was found" is a conclusive answer.
_ANNOTATION_SOURCES: Tuple[str, ...] = ("cisa_kev", "exploitdb", "epss")

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{1,10}$")  # upper-bounded: an
# identifier is a bounded token, and an unbounded \d+ let a provider hand this
# module a megabyte-long "CVE id" that then propagated into every cache key,
# finding and report row. The lower bound stays at 1 digit so nothing a
# provider legitimately publishes is silently dropped.
_GHSA_ID_RE = re.compile(r"^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$")

# ---------------------------------------------------------------------------
# Provider outcome vocabulary (context.md §8 negative-result memory).
#
# `status` is kept exactly as it was for backward compatibility with every
# existing caller/test; `outcome` is the additive, precise state that the
# negative-result logic actually reasons over. Collapsing "the provider was
# unreachable" into "no vulnerabilities found" is the single most dangerous
# thing a module like this can do, so the two are never the same value.
# ---------------------------------------------------------------------------
OUTCOME_FOUND = "found"
OUTCOME_EMPTY_AUTHORITATIVE = "empty_authoritative"
OUTCOME_UNAVAILABLE = "unavailable"
OUTCOME_RATE_LIMITED = "rate_limited"
OUTCOME_MALFORMED = "malformed"
OUTCOME_SKIPPED = "skipped"
OUTCOME_NOT_CHECKED = "not_checked"
OUTCOME_INVALID_REQUEST = "invalid_request"

# The only two outcomes that license a "checked and not found" conclusion.
_CONCLUSIVE_OUTCOMES = frozenset({OUTCOME_FOUND, OUTCOME_EMPTY_AUTHORITATIVE})


def _result_conclusive(result: Any) -> bool:
    """
    Did a provider result carry an authoritative answer?

    Reads `outcome` when present. A result from before `outcome` existed (an
    older adapter, or a test double) is judged by its legacy `status`, where
    only "found"/"not_found" ever meant "the provider answered"; every other
    legacy status stays inconclusive so an old-shaped outage can never be
    promoted into a clean result.
    """
    result = result if isinstance(result, dict) else {}
    outcome = result.get("outcome")
    if outcome is not None:
        return outcome in _CONCLUSIVE_OUTCOMES
    return result.get("status") in ("found", "not_found")

# ---------------------------------------------------------------------------
# Resource bounds. Every one of these guards a path where provider-controlled
# data reaches memory, CPU, pending_assets.json or the HTML report.
# ---------------------------------------------------------------------------
MAX_RESPONSE_BYTES = 8 * 1024 * 1024          # NVD / OSV / GHSA / EPSS JSON
MAX_KEV_RESPONSE_BYTES = 32 * 1024 * 1024     # the whole KEV catalog
MAX_EXPLOITDB_RESPONSE_BYTES = 64 * 1024 * 1024   # files_exploits.csv
MAX_KEV_ENTRIES = 100_000
MAX_EXPLOITDB_ROWS = 500_000
MAX_EXPLOITDB_INDEX_CVES = 200_000
MAX_EXPLOITDB_ENTRIES_PER_CVE = 25

MAX_TECHNOLOGY_CHARS = 128
MAX_VERSION_CHARS = 128
MAX_VERSION_TOKENS = 64          # tokens compared by compare_versions
MAX_ECOSYSTEM_CHARS = 64
MAX_OBSERVATIONS = 500

MAX_RECORDS_PER_SOURCE = 200     # normalized records one provider may return
MAX_CVES_PER_OBSERVATION = 100   # merged CVEs persisted per observation
MAX_SOURCES_PER_CVE = 12
MAX_SUMMARIES_PER_CVE = 4
MAX_SUMMARY_CHARS = 1200
MAX_REFERENCES_PER_CVE = 20
MAX_REFERENCE_CHARS = 512
MAX_CVSS_ENTRIES = 8
MAX_FIXED_VERSIONS = 10
MAX_AFFECTED_RANGES = 10
MAX_ADVISORY_IDS = 10
MAX_EXPLOITDB_REFERENCES_PER_CVE = 10
MAX_CPE_CONFIGURATIONS = 50
MAX_CPE_NODES = 50
MAX_CPE_MATCHES = 200
MAX_ALIASES = 50

MAX_EVIDENCE_ITEMS = 24
MAX_EVIDENCE_CHARS = 512
MAX_NOTES = 24
MAX_NOTE_CHARS = 400
MAX_ERROR_CHARS = 512
MAX_IDENTIFIER_CHARS = 64

# Run-level bounds.
DEFAULT_MAX_REQUESTS = 400        # total HTTP requests one run may issue
DEFAULT_MAX_RUNTIME_SECONDS = 900.0
DEFAULT_MAX_RETRIES = 2
DEFAULT_RETRY_BASE_DELAY = 1.0
DEFAULT_RETRY_MAX_DELAY = 30.0
MAX_RETRY_AFTER_SECONDS = 120.0

# NVD's documented public limits: 5 requests / rolling 30 s unauthenticated,
# 50 / 30 s with an API key. Self-limiting to those intervals is the
# difference between "queried NVD" and "got 429ed on every technology".
NVD_MIN_INTERVAL_UNAUTHENTICATED = 6.0
NVD_MIN_INTERVAL_WITH_KEY = 0.6
OSV_MIN_INTERVAL = 0.0
GITHUB_MIN_INTERVAL_UNAUTHENTICATED = 1.2
GITHUB_MIN_INTERVAL_WITH_TOKEN = 0.1
EPSS_MIN_INTERVAL = 0.5

# NVD pagination.
NVD_MAX_RESULTS_PER_PAGE = 2000
DEFAULT_NVD_MAX_RESULTS = 100
DEFAULT_NVD_MAX_PAGES = 2

# EPSS batching (the public API accepts a comma-separated `cve` list).
EPSS_BATCH_SIZE = 100
EPSS_MAX_BATCHES = 20

# Cache.
CACHE_DIRNAME = "vuln_intel_cache"
DEFAULT_CACHE_TTL_SECONDS = 24 * 3600
DEFAULT_KEV_CACHE_TTL_SECONDS = 6 * 3600
DEFAULT_CACHE_MAX_ENTRIES = 500
DEFAULT_CACHE_MAX_BYTES = 32 * 1024 * 1024
DEFAULT_FEED_CACHE_MAX_BYTES = 96 * 1024 * 1024   # KEV catalogue + Exploit-DB CVE index
CACHE_FORMAT_VERSION = 1


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


class ConfigurationError(ValueError):
    """Raised when source selection or API configuration is missing/invalid."""


class BudgetExhausted(RuntimeError):
    """Raised when a run's HTTP request budget or wall-clock deadline is spent."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Sanitization / bounding of provider-controlled data
#
# Everything below this line may originate from an external service. It lands
# in pending_assets.json (read by surface_mapper.py), in the operator's
# terminal and in the HTML report, so it is escaped and clipped at the
# boundary rather than trusted. Mirrors ssl_analyzer.py/http_analyzer.py,
# which share this output file.
# ---------------------------------------------------------------------------

# C0/C1 control characters plus the Unicode bidirectional formatting controls.
_UNSAFE_TEXT_RE = re.compile(
    "[\x00-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]"
)


def _clip(value: Any, limit: int) -> Any:
    """Length-clip a string for persistence, marking that it was clipped."""
    if not isinstance(value, str) or len(value) <= limit:
        return value
    return value[:limit] + f"...[clipped {len(value) - limit} chars]"


def _escape_unsafe(match: "re.Match[str]") -> str:
    ch = match.group(0)
    code = ord(ch)
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def _safe_text(value: Any, limit: int = MAX_SUMMARY_CHARS) -> Any:
    """
    Make provider-supplied text safe to persist, display and report.

    Control characters and Unicode bidi-formatting overrides are replaced with
    their literal `\\xNN`/`\\uNNNN` spelling, then the value is clipped.

    Escaping rather than deleting matters: a CVE description of
    "evil\\x1b]0;pwned\\x07 \\u202edrowssap" is hostile input reaching the
    operator's terminal. Deleting the controls silently rewrites it into
    something plausible-looking; escaping keeps the operator able to see
    exactly what the provider sent while making it inert.
    """
    if not isinstance(value, str):
        return value
    return _clip(_UNSAFE_TEXT_RE.sub(_escape_unsafe, value), limit)


def _safe_token(value: Any, limit: int) -> Any:
    """
    Like _safe_text, but hard-truncated with no clip marker.

    For values that are subsequently QUERIED or COMPARED (technology names,
    versions): a `...[clipped N chars]` marker inside a keyword search or a
    version comparison is noise this module would then reason over.
    """
    if not isinstance(value, str):
        return value
    return _UNSAFE_TEXT_RE.sub(_escape_unsafe, value)[:limit]


def _safe_identifier(value: Any, limit: int = MAX_IDENTIFIER_CHARS) -> Optional[str]:
    """A provider-supplied identifier (GHSA id, EDB id, ecosystem, ...)."""
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    return _safe_text(value, limit)


def _safe_reference(value: Any) -> Optional[str]:
    """
    One advisory reference URL, made inert and bounded.

    Non-http(s) schemes are kept but explicitly labelled rather than dropped:
    losing a reference loses evidence, but presenting `javascript:...` as an
    ordinary advisory link would be a link the report should never invite a
    click on.
    """
    if not isinstance(value, str):
        return None
    cleaned = _safe_text(value.strip(), MAX_REFERENCE_CHARS)
    if not cleaned:
        return None
    lowered = cleaned.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return cleaned
    return f"[non-http reference] {cleaned}"


def _bound_list(values: Sequence[Any], limit: int) -> Tuple[List[Any], bool]:
    """Cap a list, reporting whether anything was dropped."""
    items = list(values[:limit])
    return items, len(values) > limit


def _bound_notes(notes: Sequence[str], limit: int = MAX_NOTES) -> List[str]:
    """Cap a notes list, and every note in it, before it is persisted."""
    bounded = [_safe_text(n, MAX_NOTE_CHARS) for n in list(notes)[:limit]]
    if len(notes) > limit:
        bounded.append(f"...[{len(notes) - limit} further note(s) omitted]")
    return bounded


def _bound_evidence(evidence: Sequence[str]) -> List[str]:
    bounded = [_safe_text(e, MAX_EVIDENCE_CHARS) for e in list(evidence)[:MAX_EVIDENCE_ITEMS]]
    if len(evidence) > MAX_EVIDENCE_ITEMS:
        bounded.append(f"...[{len(evidence) - MAX_EVIDENCE_ITEMS} further evidence item(s) omitted]")
    return bounded


def _jsonify(value: Any, _depth: int = 0) -> Any:
    """
    Coerce a value into something json.dump can definitely write.

    Findings carry data this module did not create: a provider can return a
    nested object where a string was expected, and a TypeError out of
    json.dump escapes PendingAssetsStore and destroys an otherwise complete
    analysis. Recursion is depth-capped so a deeply nested (or self-
    referential) provider payload cannot exhaust the stack.

    Mirrors passive_recon.py's/ssl_analyzer.py's `_jsonify`, which share this
    output file.
    """
    if _depth > 12:
        return _safe_text(str(value), MAX_SUMMARY_CHARS)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return _safe_text(value, MAX_SUMMARY_CHARS)
    if isinstance(value, float):
        return value if value == value and value not in (float("inf"), float("-inf")) else str(value)
    if isinstance(value, bytes):
        return value.hex()[: MAX_SUMMARY_CHARS]
    if isinstance(value, dict):
        return {_safe_text(str(k), MAX_IDENTIFIER_CHARS): _jsonify(v, _depth + 1)
                for k, v in list(value.items())[:200]}
    if isinstance(value, (list, tuple, set)):
        return [_jsonify(v, _depth + 1) for v in list(value)[:200]]
    if isinstance(value, datetime):
        return value.isoformat()
    return _safe_text(str(value), MAX_SUMMARY_CHARS)


def _as_float(value: Any) -> Optional[float]:
    """Parse a provider-supplied number without letting a bad one raise."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        num = float(value)
    elif isinstance(value, str):
        try:
            num = float(value.strip())
        except (ValueError, AttributeError):
            return None
    else:
        return None
    if num != num or num in (float("inf"), float("-inf")):
        return None
    return num


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _as_record_list(value: Any) -> List[Dict[str, Any]]:
    """
    Provider records read back from the cache, type-checked.

    A cache file is on disk under the operator's control, but "controlled" is
    not "trusted": a payload whose `vulnerabilities` had become a string was
    truthy, so the provider reported status="found" with zero usable records,
    and the run then persisted a negative-result finding for a technology one
    source had just said had matches. Only dicts with a CVE id survive.
    """
    return [r for r in _as_list(value)
            if isinstance(r, dict) and isinstance(r.get("cve_id"), str) and _CVE_ID_RE.match(r["cve_id"])]


def _ci_get(headers: Any, name: str) -> Optional[str]:
    """Case-insensitive header lookup that survives a plain dict or a mock."""
    try:
        value = headers.get(name)
        if value is not None:
            return str(value)
        lowered = name.lower()
        for key, val in headers.items():
            if str(key).lower() == lowered:
                return str(val)
    except Exception:
        return None
    return None


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
    """
    Build a structured, evidence-carrying discovery record (context.md §8).

    Value/evidence/metadata are passed through _jsonify and the evidence/notes
    bounds: this record is built from provider-controlled data and is written
    verbatim into the file every other module reads.
    """
    return {
        "type": finding_type,
        "target": target,
        "value": _jsonify(value),
        "evidence": _bound_evidence(list(evidence)),
        "confidence": confidence,
        "source": MODULE_NAME,
        "timestamp": _now(),
        "metadata": _jsonify(metadata or {}),
    }


# ---------------------------------------------------------------------------
# Crash-safe persistence (same file/format as every other module's
# PendingAssetsStore, duplicated here per modular independence)
# ---------------------------------------------------------------------------

class PendingAssetsStore:
    """
    Crash-safe, append-oriented persistence for <output_dir>/pending_assets.json.

    A write re-reads the current file (or reuses a cached serialization of what
    this store last left there), appends the new findings, and atomically
    rewrites the file (write-to-temp + os.replace + directory fsync) so a crash
    mid-write can never corrupt previously persisted discoveries, and
    pre-existing discoveries from other modules/runs are always preserved.
    """

    def __init__(self, output_dir: str = "output", filename: str = "pending_assets.json"):
        self.output_dir = output_dir
        self.path = os.path.join(output_dir, filename)
        self._lock = threading.RLock()
        # Serialized body of everything this store has written, kept so an
        # append does not have to re-encode the whole file. `_stamp` is the
        # (mtime_ns, size) of the file as this store last left it; anything
        # else means somebody else wrote it and the cache is void.
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
        except OSError as exc:
            raise PersistenceError(
                f"Existing pending_assets.json cannot be read: {exc}"
            ) from exc

    def add(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Append one finding and persist immediately. Returns the finding."""
        self.add_many([finding])
        return finding

    def add_many(self, findings: List[Dict[str, Any]]) -> int:
        """
        Append a batch of findings in ONE read + ONE atomic write.

        add() rewrites the whole shared file per finding, which is quadratic in
        the number of records already on disk. This module emits one finding
        per matched CVE and a single keyword search routinely returns dozens:
        measured on this repository, 400 CVEs for one observation cost 5.24 s
        and 400 whole-file rewrites with per-finding add(), against one write
        batched.

        Crash-safety is unchanged and slightly stronger: still one
        write-to-temp + os.replace, so the batch is all-or-nothing rather than
        half-applied. Returns the number of findings written.
        """
        if not findings:
            return 0
        with self._lock:
            if not self._cache_is_current():
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
        body = self._encode_body(records)
        self._atomic_write_body(body)
        self._serialized = body

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
# fills or the path loses permissions (OSError), or a value slips through that
# json.dump cannot serialise (TypeError/ValueError). Catching only
# PersistenceError meant those escaped and took the *completed analysis* down
# with them — the one outcome context.md §12.11 forbids.
_PERSISTENCE_FAILURES = (PersistenceError, OSError, TypeError, ValueError)


def _safe_store_add(store: Optional["PendingAssetsStore"], finding: Dict[str, Any]) -> Optional[str]:
    """
    store.add() wrapped so a single persistence failure doesn't abort the rest
    of this module's work. Returns None on success, or an error message the
    caller is responsible for recording (never silently discarded).
    """
    if store is None:
        return None
    try:
        store.add(finding)
        return None
    except _PERSISTENCE_FAILURES as exc:
        return _safe_text(str(exc), MAX_ERROR_CHARS)


def _safe_store_add_many(
    store: Optional["PendingAssetsStore"], findings: List[Dict[str, Any]],
) -> Optional[str]:
    """
    store.add_many() wrapped so a persistence failure never discards the
    in-memory results. Returns None on success, or an error message the caller
    is responsible for recording (never silently discarded).
    """
    if store is None or not findings:
        return None
    try:
        store.add_many(findings)
        return None
    except _PERSISTENCE_FAILURES as exc:
        return _safe_text(str(exc), MAX_ERROR_CHARS)


# ---------------------------------------------------------------------------
# Confidence helpers
# ---------------------------------------------------------------------------

def _cap_confidence(a: Optional[str], b: Optional[str]) -> str:
    """Return the lower (less certain) of two confidence levels. Unknown/missing values default to MEDIUM."""
    a = a if a in _CONFIDENCE_ORDER else CONFIDENCE_MEDIUM
    b = b if b in _CONFIDENCE_ORDER else CONFIDENCE_MEDIUM
    return a if _CONFIDENCE_ORDER[a] <= _CONFIDENCE_ORDER[b] else b


def _min_confidence(*levels: Optional[str]) -> str:
    """
    The least certain of any number of confidence dimensions.

    This is the mechanism that enforces the module's hard requirement: a
    vulnerability database returning an exact-looking CPE cannot raise the
    final confidence above the confidence of the technology identification it
    was built on.
    """
    result = CONFIDENCE_HIGH
    for level in levels:
        result = _cap_confidence(result, level)
    return result


# ---------------------------------------------------------------------------
# Best-effort version comparison (no external dependency; deliberately
# conservative — see compare_versions' docstring)
# ---------------------------------------------------------------------------

# ASCII only, deliberately: `\d` also matches Arabic-Indic and other Unicode
# digits, which `int()` happily converts, so a version spelled with them
# compared as a number. No advisory range is written that way.
_VERSION_TOKEN_RE = re.compile(r"[0-9]+|[A-Za-z]+")

# Markers that a version string describes a DISTRIBUTION/vendor build rather
# than a plain upstream release. Distributions backport security fixes onto an
# unchanged upstream version, so an upstream range match cannot establish that
# such a build is affected (see the module docstring's BACKPORTING section).
_BACKPORT_MARKER_RE = re.compile(
    r"(?:"
    # A distribution token, optionally preceded by the distro's own revision
    # number: "-6.1+deb11u3", "-2ubuntu1", "-0ubuntu1.7", "+dfsg".
    r"[-+~]\d*(?:deb|dfsg|ubuntu|build|bpo|rpi|raspbian)"
    r"|[-+.]\d*el\d"                                          # 2.4.6-45.el7, -97.el7_9
    r"|[-+.]\d*(?:fc|amzn|mga|oe|ph|suse|sles|opensuse)\d"     # ...fc38, ...1.amzn2
    r"|[-+.]\d*uek\d"
    r"|-r\d+$"                                                 # Alpine 1.1.1k-r0
    r"|~"                                                      # Debian pre-release/backport marker
    r"|^\d+:"                                                  # epoch, e.g. 1:2.4.6
    r")",
    re.IGNORECASE,
)


def _looks_backported(version: Optional[str]) -> bool:
    """
    True when the observed version carries a distribution/vendor revision.

    This does NOT claim the package is patched — this module never invents
    distribution patch status. It records that upstream-range reasoning is not
    conclusive for this build, which is the honest bounded representation of
    the backporting problem for v1.
    """
    if not isinstance(version, str) or not version.strip():
        return False
    return bool(_BACKPORT_MARKER_RE.search(version.strip()))


def _version_key(v: str) -> List[Tuple[int, Any]]:
    """
    Tokenize a version into comparable (kind, value) runs.

    Token count is capped: a provider (or a hostile banner) can supply a
    megabyte-long "version", and an uncapped tokenization turned every
    subsequent comparison into a multi-million element list compare, once per
    CVE per bound. The cap keeps comparison O(1) in the pathological case; a
    version needing more than MAX_VERSION_TOKENS runs to distinguish it is not
    a version any advisory range describes.
    """
    key: List[Tuple[int, Any]] = []
    if not v:
        return key
    for token in _VERSION_TOKEN_RE.finditer(v[:MAX_VERSION_CHARS]):
        text = token.group(0)
        if text.isdigit():
            # int() on a 100-digit run is fine; the slice above bounds it.
            key.append((0, int(text)))
        else:
            key.append((1, text.lower()))
        if len(key) >= MAX_VERSION_TOKENS:
            break
    return key


def compare_versions(v1: Optional[str], v2: Optional[str]) -> Optional[int]:
    """
    Best-effort version comparison: tokenizes into (numeric | alpha) runs and
    compares them positionally (e.g. "8.9p1" -> [8, 9, "p", 1]). This is not a
    full semver/CPE version-comparison implementation — it is intentionally
    simple, with no external dependency, matching this module's "no unnecessary
    dependency" convention. Returns -1/0/1, or None if either input is empty or
    contains no comparable token at all (never guesses).
    """
    if not v1 or not v2:
        return None
    if not isinstance(v1, str) or not isinstance(v2, str):
        return None
    k1, k2 = _version_key(v1), _version_key(v2)
    if not k1 or not k2:
        return None
    if k1 < k2:
        return -1
    if k1 > k2:
        return 1
    return 0


def _version_in_range(
    version: str,
    start_including: Optional[str] = None,
    start_excluding: Optional[str] = None,
    end_including: Optional[str] = None,
    end_excluding: Optional[str] = None,
) -> Optional[bool]:
    """
    True/False if `version` can be conclusively placed against the given
    bounds, or None if there are no bounds to check, or a bound could not be
    compared (never manufactures a match out of an incomparable bound).
    """
    checks: List[bool] = []
    for bound, op in (
        (start_including, ">="), (start_excluding, ">"),
        (end_including, "<="), (end_excluding, "<"),
    ):
        if not bound or not isinstance(bound, str):
            continue
        cmp = compare_versions(version, bound)
        if cmp is None:
            return None
        if op == ">=":
            checks.append(cmp >= 0)
        elif op == ">":
            checks.append(cmp > 0)
        elif op == "<=":
            checks.append(cmp <= 0)
        elif op == "<":
            checks.append(cmp < 0)
    if not checks:
        return None
    return all(checks)


_RANGE_COND_RE = re.compile(r"(>=|<=|>|<|=)\s*([\w.\-+:~]{1,64})")


def _parse_version_range_string(range_str: str) -> Dict[str, str]:
    """Parse a GitHub Advisory-style range string (e.g. '>= 4.0.0, < 4.18.0') into bound kwargs for _version_in_range."""
    bounds: Dict[str, str] = {}
    if not isinstance(range_str, str):
        return bounds
    for op, ver in _RANGE_COND_RE.findall(range_str[:512]):
        if op == ">=":
            bounds["start_including"] = ver
        elif op == ">":
            bounds["start_excluding"] = ver
        elif op == "<=":
            bounds["end_including"] = ver
        elif op == "<":
            bounds["end_excluding"] = ver
        elif op == "=":
            bounds["start_including"] = ver
            bounds["end_including"] = ver
    return bounds


# ---------------------------------------------------------------------------
# Technology/version observation normalization
# (context.md: use the existing normalized technology/version data structures
# produced by the repository; do not create a competing technology model.)
# ---------------------------------------------------------------------------

_TECH_NAME_KEYS = ("technology", "product", "name", "software", "framework")
_TECH_VERSION_KEYS = ("version", "product_version")

# A finding's `target` becomes a hostname asset in surface_mapper.py. Anything
# that is not hostname- or IP-shaped mints a phantom asset that no scan can
# ever correspond to, so the shape is enforced here rather than trusted.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$"
)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _is_ip_literal(host: str) -> bool:
    if _IPV4_RE.match(host):
        return all(0 <= int(part) <= 255 for part in host.split("."))
    # IPv6 literal, with or without brackets.
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    if ":" not in candidate:
        return False
    try:
        import ipaddress
        ipaddress.IPv6Address(candidate)
        return True
    except Exception:
        return False


def _observation_target(raw: Any) -> Tuple[Optional[str], Optional[str]]:
    """
    Validate an observation's `target` as an asset reference.

    Returns (target, rejection_reason). A rejected target is NEVER substituted
    with something else that happens to be a string: the previous behaviour
    (`target or technology`) persisted the finding with `target="OpenSSH"`,
    and surface_mapper.py duly minted a hostname asset called "openssh" — a
    phantom asset in the graph, in the report's asset inventory, and in
    risk_engine.py's scoring, describing a host that does not exist. This is
    the same defect class as ssl_analyzer.py's wildcard-SAN phantom asset.

    A URL is normalized to its hostname rather than rejected, because that is
    unambiguous and the alternative is discarding real intelligence.
    """
    if raw is None:
        return None, "no target supplied"
    if not isinstance(raw, str):
        return None, f"target is {type(raw).__name__}, not a string"
    candidate = raw.strip()
    if not candidate:
        return None, "target is empty"
    if len(candidate) > 253 + 16:
        return None, "target is implausibly long for a hostname"

    if "://" in candidate:
        try:
            import urllib.parse
            parsed = urllib.parse.urlsplit(candidate)
            host = parsed.hostname
        except ValueError:
            return None, "target is an unparseable URL"
        if not host:
            return None, "target is a URL with no host component"
        candidate = host
    # Strip any userinfo and port that survived a non-URL form.
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[: candidate.index("]") + 1]
    elif candidate.count(":") == 1:
        candidate = candidate.split(":", 1)[0]

    candidate = candidate.strip().rstrip(".")
    if not candidate:
        return None, "target reduced to nothing after normalization"
    if _is_ip_literal(candidate):
        return candidate.strip("[]"), None
    if _IPV4_RE.match(candidate):
        return None, "target looks like an IPv4 address but is not a valid one"
    if _HOSTNAME_RE.match(candidate):
        return candidate.lower(), None
    return None, "target is neither hostname- nor IP-shaped"


def normalize_technology_observation(obs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Normalize a caller-supplied (or extracted) technology observation into this
    module's internal shape. Liberal about input key names (see the module
    docstring's TECH_FINGERPRINT_INPUT_CONTRACT + _TECH_NAME_KEYS /
    _TECH_VERSION_KEYS) so this works both for active_recon.py-derived
    observations and for tech_fingerprint.py's output.

    Returns None (never raises) when no usable technology name is present —
    "insufficient data" is a normal, expected outcome for versionless or
    malformed observations, not an error.
    """
    if not isinstance(obs, dict):
        return None

    technology = None
    for key in _TECH_NAME_KEYS:
        val = obs.get(key)
        if isinstance(val, str) and val.strip():
            technology = _safe_token(val.strip(), MAX_TECHNOLOGY_CHARS).strip()
            break
    if not technology or not str(technology).strip():
        return None

    version = None
    for key in _TECH_VERSION_KEYS:
        val = obs.get(key)
        if isinstance(val, str) and val.strip():
            version = _safe_token(val.strip(), MAX_VERSION_CHARS).strip() or None
            break

    confidence = obs.get("confidence")
    if confidence not in _CONFIDENCE_ORDER:
        confidence = CONFIDENCE_MEDIUM

    raw_evidence = obs.get("evidence")
    evidence = _bound_evidence([str(e) for e in raw_evidence]) if isinstance(raw_evidence, list) else []

    target, target_rejected = _observation_target(obs.get("target"))

    return {
        "technology": technology,
        "version": version,
        "category": _safe_identifier(obs.get("category")),
        "target": target,
        "target_rejected_reason": target_rejected,
        "raw_target": _safe_text(str(obs.get("target")), MAX_IDENTIFIER_CHARS) if obs.get("target") is not None else None,
        "confidence": confidence,
        "evidence": evidence,
        "source_module": _safe_identifier(obs.get("source") or obs.get("source_module")),
        "raw_finding_type": _safe_identifier(obs.get("raw_finding_type") or obs.get("type")),
        "ecosystem": _safe_identifier(obs.get("ecosystem"), MAX_ECOSYSTEM_CHARS),
    }


# Protocol/scheme tokens that are never themselves a "product" — excluded from
# banner-derived observations so a bare "SSH"/"HTTP" match doesn't trigger an
# unusably broad, noisy CVE keyword search (module docstring, decision #2).
_GENERIC_PROTOCOL_TOKENS = {
    "http", "https", "ftp", "ftps", "sftp", "ssh", "smtp", "esmtp",
    "ssl", "tls", "pop3", "imap", "imap4", "ldap",
}

_LEADING_RESPONSE_CODE_RE = re.compile(r"^\d{3}[ \-]?")
_NAME_VERSION_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9.+]{1,30})[/_ ]v?(\d[\w.\-]{0,64})")

# A banner is attacker-controlled and unbounded; scanning all of a 10 MB one
# for a product name buys nothing a product name would ever be found in.
MAX_BANNER_SCAN_CHARS = 4096


def parse_name_version_from_text(text: Optional[str]) -> Optional[Tuple[str, str]]:
    """
    Best-effort extraction of a (product_name, version) pair from raw protocol
    banner text (e.g. "220 ProFTPD 1.3.5e Server ready.", "OpenSSH_8.9p1",
    "220 (vsFTPd 3.0.3)"). Deliberately conservative: a bare protocol/scheme
    token (see _GENERIC_PROTOCOL_TOKENS) is never accepted as the product name,
    and returns None rather than guessing when no plausible pair is found.
    """
    if not text or not isinstance(text, str):
        return None
    cleaned = _LEADING_RESPONSE_CODE_RE.sub("", text.strip()[:MAX_BANNER_SCAN_CHARS])
    for match in _NAME_VERSION_RE.finditer(cleaned):
        name, version = match.group(1), match.group(2)
        if name.lower() in _GENERIC_PROTOCOL_TOKENS:
            continue
        return _safe_token(name, MAX_TECHNOLOGY_CHARS), _safe_token(version, MAX_VERSION_CHARS)
    return None


# Finding types already written to pending_assets.json by other modules that
# carry technology/version signal (module docstring, decision #2).
_ACTIVE_RECON_TECH_FINDING_TYPES = {"ssh_fingerprint", "banner"}

MAX_EXTRACTION_SKIP_NOTES = 100


def extract_observations_from_active_recon(
    store: "PendingAssetsStore",
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Read active_recon.py's already-persisted findings out of
    pending_assets.json and derive technology/version observations from the
    ones that carry parseable software/version text. Returns
    (observations, skipped_notes) — a finding that couldn't be parsed into a
    technology/version pair is recorded in skipped_notes, never silently
    dropped.
    """
    observations: List[Dict[str, Any]] = []
    skipped: List[str] = []
    skipped_total = 0

    try:
        records = store.all()
    except _PERSISTENCE_FAILURES as exc:
        return [], [f"could not read pending_assets.json: {_safe_text(str(exc), MAX_ERROR_CHARS)}"]

    seen: set = set()
    for rec in records:
        if not isinstance(rec, dict) or rec.get("type") not in _ACTIVE_RECON_TECH_FINDING_TYPES:
            continue
        if len(observations) >= MAX_OBSERVATIONS:
            skipped_total += 1
            continue

        value = rec.get("value")
        value = value if isinstance(value, dict) else {}
        raw_target = rec.get("target")
        finding_type = rec["type"]
        parsed: Optional[Tuple[str, str]] = None

        if finding_type == "ssh_fingerprint" and isinstance(value.get("software"), str) and value["software"]:
            parsed = parse_name_version_from_text(value["software"])
        elif finding_type == "banner" and isinstance(value.get("banner"), str) and value["banner"]:
            parsed = parse_name_version_from_text(value["banner"])

        if parsed is None:
            skipped_total += 1
            if len(skipped) < MAX_EXTRACTION_SKIP_NOTES:
                skipped.append(
                    f"{finding_type} finding for target {_safe_text(str(raw_target), MAX_IDENTIFIER_CHARS)!r} "
                    f"did not yield a parseable technology name/version"
                )
            continue

        name, version = parsed
        # active_recon.py's confidence says how sure it is that this banner
        # was RECEIVED; it says nothing about whether the banner is truthful
        # or whether this module's best-effort name/version regex read it
        # correctly. A banner is one server-controlled signal (context.md §8:
        # a single signal should not be presented as certainty), so the
        # technology identification derived from it is capped at MEDIUM.
        normalized = normalize_technology_observation({
            "technology": name,
            "version": version,
            "target": raw_target,
            "confidence": _cap_confidence(rec.get("confidence", CONFIDENCE_MEDIUM), CONFIDENCE_MEDIUM),
            "evidence": list(rec.get("evidence") or []) + [
                f"Derived from active_recon.py {finding_type!r} finding by best-effort banner parsing; "
                f"identification confidence capped at MEDIUM (single server-controlled signal)"
            ],
            "source": "active_recon.py",
            "raw_finding_type": finding_type,
        })
        if not normalized:
            continue
        # The same host re-banner-grabbed on several ports yields the same
        # (technology, version, target) triple more than once; persisting a
        # CVE finding per copy is duplicate amplification, not intelligence.
        key = (normalized["technology"].lower(), (normalized.get("version") or "").lower(),
               normalized.get("target") or "")
        if key in seen:
            continue
        seen.add(key)
        observations.append(normalized)

    if skipped_total > len(skipped):
        skipped.append(f"...[{skipped_total - len(skipped)} further unparseable/over-cap finding(s) omitted]")
    return observations, skipped


# ---------------------------------------------------------------------------
# CPE product matching
#
# NVD's keywordSearch returns every CVE whose text mentions the keyword, so the
# CPE configuration data is what decides whether a CVE is about the observed
# product at all. Matching those product names by SUBSTRING (the previous
# behaviour) is the difference between intelligence and noise:
#
#   - observed "nginx" 1.18.0 range-confirmed against an "nginx_controller"
#     CVE, because "nginx" is a substring of "nginx_controller";
#   - observed "ssh" range-confirmed against every OpenSSH CVE.
#
# Both were reproduced against this file before the change. A related product
# name is still recorded (it is real evidence that something adjacent matched)
# but it can never produce "version_range_confirmed".
# ---------------------------------------------------------------------------

def _normalize_product_token(value: Optional[str]) -> str:
    """Fold a vendor/product/technology name to its comparable core."""
    if not isinstance(value, str):
        return ""
    return re.sub(r"[^a-z0-9]", "", value.lower())


# Curated, explicit CPE product aliases. Every entry maps a name this
# repository's detectors actually emit to the product name NVD publishes for
# the same software. Deliberately narrow, version-controlled and auditable:
# an alias only ever ADDS a mapping between two concrete names, it can never
# suppress a match, and `match_quality` records that an alias was used so the
# provenance survives into the finding.
_PRODUCT_ALIASES: Dict[str, Tuple[str, ...]] = {
    # Apache HTTP Server is published by NVD as apache:http_server.
    "apache": ("httpserver",),
    "apachehttpd": ("httpserver",),
    "httpd": ("httpserver",),
    "apachehttpserver": ("httpserver",),
    # Microsoft IIS.
    "iis": ("internetinformationservices", "internetinformationserver"),
    "microsoftiis": ("internetinformationservices", "internetinformationserver"),
    # Tomcat.
    "apachetomcat": ("tomcat",),
    "tomcat": ("tomcat",),
    # OpenSSH is published under the openbsd vendor.
    "openssh": ("openssh",),
    # PHP-FPM findings still describe the php product.
    "phpfpm": ("php",),
    # Node.js.
    "node": ("nodejs", "node.js"),
    "nodejs": ("nodejs",),
    # Common web frameworks whose detector name differs from the CPE product.
    "nextjs": ("next.js",),
    "next": ("next.js",),
    "aspnet": ("asp.net",),
    "aspnetcore": ("asp.net_core",),
}


def _alias_targets(technology: str) -> frozenset:
    """The normalized CPE product names a technology name is allowed to match."""
    norm = _normalize_product_token(technology)
    targets = {norm} if norm else set()
    for alias in _PRODUCT_ALIASES.get(norm, ()):  # curated, never inferred
        alias_norm = _normalize_product_token(alias)
        if alias_norm:
            targets.add(alias_norm)
    return frozenset(targets)


MATCH_QUALITY_EXACT = "cpe_product_exact"
MATCH_QUALITY_ALIAS = "cpe_product_alias"
MATCH_QUALITY_RELATED = "cpe_product_related"
MATCH_QUALITY_PACKAGE = "package_query"
MATCH_QUALITY_KEYWORD = "keyword_only"

# Below this length a product token is too generic for a substring relation to
# mean anything ("ssh" inside "openssh", "go" inside "django").
_MIN_RELATED_TOKEN_CHARS = 5


def _product_match_quality(technology: str, cpe_product: Optional[str]) -> Optional[str]:
    """
    How well a CPE product name corresponds to the observed technology.

    Returns None when the names have nothing to do with each other, so the
    caller skips the cpeMatch entirely.
    """
    product_norm = _normalize_product_token(cpe_product)
    if not product_norm:
        return None
    targets = _alias_targets(technology)
    if not targets:
        return None
    tech_norm = _normalize_product_token(technology)
    if product_norm == tech_norm:
        return MATCH_QUALITY_EXACT
    if product_norm in targets:
        return MATCH_QUALITY_ALIAS
    if len(tech_norm) < _MIN_RELATED_TOKEN_CHARS or len(product_norm) < _MIN_RELATED_TOKEN_CHARS:
        return None
    if tech_norm in product_norm or product_norm in tech_norm:
        return MATCH_QUALITY_RELATED
    return None


def _cpe_field(criteria: str, index: int) -> Optional[str]:
    """
    One field of a CPE 2.3 formatted string, or None for ANY (`*`).

    NA (`-`) is deliberately NOT folded into None by the caller that reads the
    version field: ANY means "every version", NA means "this product has no
    version", and treating the second like the first turns a versionless CPE
    into a wildcard that any observed version can fall inside.
    """
    if not isinstance(criteria, str):
        return None
    parts = criteria.split(":")
    if len(parts) <= index:
        return None
    val = parts[index]
    return None if val in ("*", "-", "") else val


def _cpe_version_field(criteria: str) -> Tuple[Optional[str], bool]:
    """Returns (concrete_version, is_na). ANY yields (None, False); NA yields (None, True)."""
    if not isinstance(criteria, str):
        return None, False
    parts = criteria.split(":")
    if len(parts) <= 5:
        return None, False
    val = parts[5]
    if val == "-":
        return None, True
    if val in ("*", ""):
        return None, False
    return val, False


# ---------------------------------------------------------------------------
# Provider transport: request budget, rate limiting, bounded retries, bounded
# response reads.
#
# Every one of these is a hard bound on a path that was previously unbounded:
# a run could issue unlimited requests, at unlimited rate (NVD's documented
# limit is 5 requests per rolling 30 s unauthenticated, so the previous code
# earned a 429 on essentially every technology after the fifth), with no retry
# and no Retry-After handling, reading whole response bodies into memory via
# resp.text / resp.json() with no size cap.
# ---------------------------------------------------------------------------

class RequestBudget:
    """
    A hard cap on how many HTTP requests one run may issue.

    Exhaustion is an explicit, honest "not checked" outcome, never a silent nil
    result: `spend()` raises BudgetExhausted and each provider converts that
    into outcome=not_checked, which is NOT conclusive and therefore cannot
    produce a negative-result finding.
    """

    __slots__ = ("limit", "used", "_lock")

    def __init__(self, limit: int = DEFAULT_MAX_REQUESTS):
        self.limit = max(1, int(limit))
        self.used = 0
        self._lock = threading.Lock()

    def spend(self) -> None:
        with self._lock:
            if self.used >= self.limit:
                raise BudgetExhausted(f"request budget of {self.limit} exhausted")
            self.used += 1

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)


class Deadline:
    """A wall-clock bound on one run. Checked before every provider request."""

    __slots__ = ("limit_seconds", "_started", "_monotonic")

    def __init__(self, limit_seconds: float = DEFAULT_MAX_RUNTIME_SECONDS,
                 monotonic=time.monotonic):
        self.limit_seconds = max(0.0, float(limit_seconds))
        self._monotonic = monotonic
        self._started = monotonic()

    @property
    def expired(self) -> bool:
        if self.limit_seconds <= 0:
            return False
        return (self._monotonic() - self._started) >= self.limit_seconds

    def check(self) -> None:
        if self.expired:
            raise BudgetExhausted(
                f"run deadline of {self.limit_seconds:.0f}s reached before this query could be issued")

    @property
    def remaining_seconds(self) -> float:
        if self.limit_seconds <= 0:
            return float("inf")
        return max(0.0, self.limit_seconds - (self._monotonic() - self._started))


class RateLimiter:
    """
    Minimum interval between requests to one provider.

    `sleep` is injected so tests are deterministic and instantaneous; nothing
    in the test suite ever sleeps for real.
    """

    __slots__ = ("min_interval", "_last", "_lock", "_sleep", "_monotonic", "waits", "waited_seconds")

    def __init__(self, min_interval: float = 0.0, sleep=time.sleep, monotonic=time.monotonic):
        self.min_interval = max(0.0, float(min_interval))
        self._last: Optional[float] = None
        self._lock = threading.Lock()
        self._sleep = sleep
        self._monotonic = monotonic
        self.waits = 0
        self.waited_seconds = 0.0

    def acquire(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = self._monotonic()
            if self._last is not None:
                wait = self.min_interval - (now - self._last)
                if wait > 0:
                    self.waits += 1
                    self.waited_seconds += wait
                    self._sleep(wait)
                    now = self._monotonic()
            self._last = now

    def penalize(self, seconds: float) -> None:
        """Push the next allowed request out (used for a provider's Retry-After)."""
        seconds = max(0.0, min(float(seconds), MAX_RETRY_AFTER_SECONDS))
        if seconds <= 0:
            return
        with self._lock:
            base = self._monotonic()
            self._last = base + seconds - self.min_interval


class RetryPolicy:
    """
    Bounded exponential backoff with jitter for retryable provider responses.

    Deliberately opt-in (providers default to `retry_policy=None`, i.e. a
    single attempt) so that a direct provider call keeps its previous,
    predictable one-request behaviour and the test suite never sleeps.
    run_vuln_intel() constructs one for the run.
    """

    __slots__ = ("max_retries", "base_delay", "max_delay", "jitter", "_sleep", "_random")

    def __init__(self, max_retries: int = DEFAULT_MAX_RETRIES,
                 base_delay: float = DEFAULT_RETRY_BASE_DELAY,
                 max_delay: float = DEFAULT_RETRY_MAX_DELAY,
                 jitter: bool = True, sleep=time.sleep, rng=None):
        self.max_retries = max(0, min(int(max_retries), 5))
        self.base_delay = max(0.0, float(base_delay))
        self.max_delay = max(0.0, float(max_delay))
        self.jitter = bool(jitter)
        self._sleep = sleep
        self._random = rng or random.random

    def delay_for(self, attempt: int, retry_after: Optional[float] = None) -> float:
        """Seconds to wait before attempt `attempt` (1-based retry number)."""
        if retry_after is not None:
            base = max(0.0, min(float(retry_after), MAX_RETRY_AFTER_SECONDS))
        else:
            base = min(self.base_delay * (2 ** max(0, attempt - 1)), self.max_delay)
        if self.jitter and base > 0:
            # Full jitter: avoids a fleet of scans synchronising their retries.
            base = base * (0.5 + 0.5 * self._random())
        return base

    def wait(self, attempt: int, retry_after: Optional[float] = None) -> float:
        delay = self.delay_for(attempt, retry_after)
        if delay > 0:
            self._sleep(delay)
        return delay


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """
    Parse an HTTP Retry-After header (delta-seconds or HTTP-date), bounded.

    A provider-supplied value is untrusted: an enormous or negative delta, or a
    date far in the future, must not be able to park the whole run.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        seconds = float(text)
        if seconds != seconds:
            return None
        return max(0.0, min(seconds, MAX_RETRY_AFTER_SECONDS))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        when = parsedate_to_datetime(text)
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        delta = (when - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, min(delta, MAX_RETRY_AFTER_SECONDS))
    except Exception:
        return None


def _read_bounded_bytes(resp: Any, max_bytes: int) -> Tuple[Optional[bytes], bool]:
    """
    Read at most `max_bytes` (+1 sentinel) bytes of a streamed response body.

    Returns (data, truncated), or (None, False) when this response object
    exposes no readable byte stream at all — in which case the caller falls
    back to the response's own decoded accessor. Never touches resp.content
    first: that materialises the ENTIRE body (a 500 MB feed, or a decompression
    bomb) in memory before any slice could bound it.
    """
    raw_stream = getattr(resp, "raw", None)
    reader = getattr(raw_stream, "read", None)
    if callable(reader):
        try:
            data = reader(max_bytes + 1, decode_content=True)
        except TypeError:
            try:
                data = reader(max_bytes + 1)
            except Exception:
                data = None
        except Exception:
            data = None
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data)
            return data[:max_bytes], len(data) > max_bytes

    iter_content = getattr(resp, "iter_content", None)
    if callable(iter_content):
        try:
            buf = bytearray()
            for chunk in iter_content(chunk_size=65536):
                if not isinstance(chunk, (bytes, bytearray)):
                    raise TypeError("non-bytes chunk")
                buf += chunk
                if len(buf) > max_bytes:
                    break
            if buf:
                data = bytes(buf)
                return data[:max_bytes], len(data) > max_bytes
            # An iterator that yielded nothing is indistinguishable from an
            # object that has no real stream behind it (a test double, or an
            # adapter whose iter_content is a stub). Reporting "empty body"
            # here would turn every such response into a malformed one, so the
            # caller falls back to the response's own decoded accessor, which
            # reports a genuinely empty body accurately.
        except Exception:
            pass
    return None, False


def _decode_json_body(resp: Any, max_bytes: int) -> Tuple[Any, Optional[str]]:
    """
    Parse a bounded JSON body. Returns (data, error_message).

    A body larger than the cap is an error, not a truncated parse: half a JSON
    document is not a partial result, it is an unusable one, and pretending
    otherwise would let a provider decide what this module concludes.
    """
    data, truncated = _read_bounded_bytes(resp, max_bytes)
    if data is not None:
        if truncated:
            return None, f"response body exceeded the {max_bytes} byte read cap"
        if not data.strip():
            return None, "empty response body"
        try:
            return json.loads(data.decode("utf-8", errors="replace")), None
        except ValueError as exc:
            return None, f"malformed JSON: {exc}"
    # No readable byte stream (a test double, or an adapter without .raw).
    try:
        return resp.json(), None
    except ValueError as exc:
        return None, f"malformed JSON: {exc}"
    except Exception as exc:
        return None, f"could not read response body: {type(exc).__name__}: {exc}"


def _decode_text_body(resp: Any, max_bytes: int) -> Tuple[Optional[str], Optional[str]]:
    """Read a bounded text body. Returns (text, error_message)."""
    data, truncated = _read_bounded_bytes(resp, max_bytes)
    if data is not None:
        if truncated:
            return None, f"response body exceeded the {max_bytes} byte read cap"
        encoding = getattr(resp, "encoding", None)
        try:
            return data.decode(encoding or "utf-8", errors="replace"), None
        except (LookupError, TypeError):
            return data.decode("utf-8", errors="replace"), None
    try:
        text = resp.text
    except Exception as exc:
        return None, f"could not read response body: {type(exc).__name__}: {exc}"
    if not isinstance(text, str):
        return None, "response body was not text"
    if len(text) > max_bytes:
        return None, f"response body exceeded the {max_bytes} byte read cap"
    return text, None


# HTTP statuses worth one bounded retry: transient server-side conditions.
_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})


def _request_with_retry(
    method: str,
    url: str,
    *,
    headers: Dict[str, str],
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    budget: Optional[RequestBudget] = None,
    deadline: Optional[Deadline] = None,
    rate_limiter: Optional[RateLimiter] = None,
    retry_policy: Optional[RetryPolicy] = None,
) -> Dict[str, Any]:
    """
    One provider request, with the run's budget/deadline/rate-limit/retry rules
    applied around it.

    Returns {"response", "error", "outcome", "attempts", "retry_after",
    "waited_seconds"}. `response` is None when no usable response was obtained;
    `outcome` then says WHY, in the explicit vocabulary the negative-result
    logic reasons over — never a value that could be mistaken for "clean".
    """
    result: Dict[str, Any] = {
        "response": None, "error": None, "outcome": OUTCOME_UNAVAILABLE,
        "attempts": 0, "retry_after": None, "waited_seconds": 0.0,
    }
    attempts_allowed = 1 + (retry_policy.max_retries if retry_policy else 0)

    for attempt in range(1, attempts_allowed + 1):
        if deadline is not None:
            try:
                deadline.check()
            except BudgetExhausted as exc:
                result["error"] = str(exc)
                result["outcome"] = OUTCOME_NOT_CHECKED
                return result
        if budget is not None:
            try:
                budget.spend()
            except BudgetExhausted as exc:
                result["error"] = str(exc)
                result["outcome"] = OUTCOME_NOT_CHECKED
                return result
        if rate_limiter is not None:
            rate_limiter.acquire()

        result["attempts"] = attempt
        resp = None
        try:
            if method == "POST":
                resp = requests.post(url, json=json_body, headers=headers, timeout=timeout, stream=True)
            else:
                resp = requests.get(url, params=params, headers=headers, timeout=timeout, stream=True)
        except requests.exceptions.Timeout:
            result["error"], result["outcome"] = "timeout", OUTCOME_UNAVAILABLE
        except requests.exceptions.ConnectionError as exc:
            result["error"] = f"connection error: {_safe_text(str(exc), MAX_ERROR_CHARS)}"
            result["outcome"] = OUTCOME_UNAVAILABLE
        except requests.exceptions.RequestException as exc:
            result["error"] = f"request failed: {_safe_text(str(exc), MAX_ERROR_CHARS)}"
            result["outcome"] = OUTCOME_UNAVAILABLE
        except Exception as exc:  # a hostile adapter/mocked transport
            result["error"] = f"request failed: {type(exc).__name__}: {_safe_text(str(exc), MAX_ERROR_CHARS)}"
            result["outcome"] = OUTCOME_UNAVAILABLE
        else:
            status = getattr(resp, "status_code", None)
            retry_after = _parse_retry_after(_ci_get(getattr(resp, "headers", {}) or {}, "Retry-After"))
            if retry_after is not None:
                result["retry_after"] = retry_after
                if rate_limiter is not None and status in (403, 429):
                    rate_limiter.penalize(retry_after)
            retryable = isinstance(status, int) and status in _RETRYABLE_STATUSES
            if not retryable or attempt >= attempts_allowed or retry_policy is None:
                result["response"] = resp
                result["error"] = None
                result["outcome"] = OUTCOME_FOUND  # transport-level success; body not yet judged
                return result
            try:
                resp.close()
            except Exception:
                pass
            result["waited_seconds"] += retry_policy.wait(attempt, retry_after)
            continue

        # Transport failure path: retry only if a policy allows another attempt.
        if retry_policy is None or attempt >= attempts_allowed:
            return result
        result["waited_seconds"] += retry_policy.wait(attempt, None)

    return result


# ---------------------------------------------------------------------------
# Bounded persistent provider cache
#
# Repeated scans of the same target re-ask NVD/OSV/GHSA the identical
# questions, and re-download the whole KEV catalogue and the multi-megabyte
# Exploit-DB CSV, every run. NVD's unauthenticated ceiling makes that the
# difference between "queried" and "rate limited".
#
# The rules that matter more than the speed:
#   - a provider OUTAGE is never cached. Only conclusive outcomes
#     (found / empty_authoritative) are stored, so a cache read can never
#     resurrect "no vulnerabilities found" out of a 429.
#   - every entry carries its own outcome + stored_at, so a hit is reported
#     with its freshness rather than passed off as a live answer.
#   - the file is bounded in entries AND bytes, corruption is survivable, and
#     a write failure is a recorded note, never an exception.
# ---------------------------------------------------------------------------

class ProviderCache:
    """
    A bounded, TTL'd, crash-tolerant JSON cache for provider responses.

    One file per namespace under <output_dir>/vuln_intel_cache/. Deliberately
    not a database and not a background service: the architecture does not
    require one, and this file is read/written a few dozen times per run.
    """

    def __init__(
        self,
        cache_dir: str,
        namespace: str = "queries",
        ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        max_entries: int = DEFAULT_CACHE_MAX_ENTRIES,
        max_bytes: int = DEFAULT_CACHE_MAX_BYTES,
        now=None,
    ):
        self.cache_dir = cache_dir
        self.namespace = re.sub(r"[^A-Za-z0-9_.-]", "_", namespace)[:64] or "queries"
        self.ttl_seconds = max(0.0, float(ttl_seconds))
        self.max_entries = max(1, int(max_entries))
        self.max_bytes = max(4096, int(max_bytes))
        self._now = now or (lambda: datetime.now(timezone.utc).timestamp())
        self.path = os.path.join(cache_dir, f"{self.namespace}.json")
        self._lock = threading.RLock()
        self._entries: Optional[Dict[str, Dict[str, Any]]] = None
        self.notes: List[str] = []
        self.hits = 0
        self.misses = 0
        self.stale = 0
        self.writes = 0
        self.available = True
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
        except OSError as exc:
            self.available = False
            self._note(f"cache directory unavailable ({exc}); running without a cache")

    def _note(self, text: str) -> None:
        if len(self.notes) < MAX_NOTES:
            self.notes.append(_safe_text(text, MAX_NOTE_CHARS))

    @staticmethod
    def key(*parts: Any) -> str:
        """A deterministic cache key. Hashed so a hostile technology name cannot become a path."""
        joined = "\x1f".join("" if p is None else str(p) for p in parts)
        return hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        if self._entries is not None:
            return self._entries
        self._entries = {}
        if not self.available:
            return self._entries
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return self._entries
        if size > self.max_bytes:
            self._note(f"cache file {self.path!r} exceeds {self.max_bytes} bytes; ignored and rebuilt")
            return self._entries
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as exc:
            # A corrupt or truncated cache is a cache miss, never a failure and
            # never a source of made-up answers.
            self._note(f"cache file is unreadable and was ignored: {_safe_text(str(exc), MAX_ERROR_CHARS)}")
            return self._entries
        if not isinstance(data, dict) or data.get("format") != CACHE_FORMAT_VERSION:
            self._note("cache file has an unrecognized format and was ignored")
            return self._entries
        entries = data.get("entries")
        if not isinstance(entries, dict):
            self._note("cache file has no usable entries object and was ignored")
            return self._entries
        clean: Dict[str, Dict[str, Any]] = {}
        for key, entry in list(entries.items())[: self.max_entries]:
            if not isinstance(key, str) or not isinstance(entry, dict):
                continue
            if not isinstance(entry.get("stored_at"), (int, float)):
                continue
            if entry.get("outcome") not in _CONCLUSIVE_OUTCOMES:
                # Defensive: an older/hand-edited file must not be able to
                # smuggle a cached outage in as an authoritative empty result.
                continue
            clean[key] = entry
        self._entries = clean
        return self._entries

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """A fresh cached entry, or None. Never raises."""
        with self._lock:
            try:
                entries = self._load()
            except Exception as exc:  # pragma: no cover - defensive
                self._note(f"cache read failed: {type(exc).__name__}: {exc}")
                return None
            entry = entries.get(key)
            if entry is None:
                self.misses += 1
                return None
            age = self._now() - float(entry.get("stored_at") or 0.0)
            if self.ttl_seconds and age > self.ttl_seconds:
                self.stale += 1
                self.misses += 1
                return None
            self.hits += 1
            return {
                "outcome": entry.get("outcome"),
                "payload": entry.get("payload"),
                "stored_at": entry.get("stored_at"),
                "age_seconds": round(age, 3),
            }

    def put(self, key: str, outcome: str, payload: Any) -> None:
        """
        Store a CONCLUSIVE provider result. Anything else is refused.

        Never raises: a cache that cannot be written is a performance
        regression, not a reason to lose an analysis.
        """
        if not self.available or outcome not in _CONCLUSIVE_OUTCOMES:
            return
        with self._lock:
            try:
                entries = self._load()
                # NOT _jsonify: that helper caps every list/dict at 200 items,
                # which is right for provider text inside a finding and wrong
                # here — it silently cut the 1,400-entry KEV catalogue to 200
                # on its way into the cache, so every cached run then reported
                # 1,200 KEV-listed CVEs as "checked, not listed". Payloads are
                # already bounded and sanitized by the provider that produced
                # them; the file byte cap below is the bound that applies here.
                try:
                    json.dumps(payload)
                except (TypeError, ValueError):
                    payload = _jsonify(payload)
                entries[key] = {
                    "outcome": outcome,
                    "payload": payload,
                    "stored_at": self._now(),
                }
                if len(entries) > self.max_entries:
                    # Oldest-first eviction, deterministic on ties by key.
                    ordered = sorted(entries.items(),
                                     key=lambda kv: (float(kv[1].get("stored_at") or 0.0), kv[0]))
                    for old_key, _ in ordered[: len(entries) - self.max_entries]:
                        entries.pop(old_key, None)
                body = json.dumps(
                    {"format": CACHE_FORMAT_VERSION, "entries": entries},
                    sort_keys=True, separators=(",", ":"),
                )
                if len(body.encode("utf-8")) > self.max_bytes:
                    # One oversized payload must not be able to poison the file
                    # for every future run.
                    entries.pop(key, None)
                    self._note("cache entry refused: it would push the cache past its size cap")
                    return
                self._atomic_write(body)
                self.writes += 1
            except Exception as exc:
                self._note(f"cache write failed: {type(exc).__name__}: {_safe_text(str(exc), MAX_ERROR_CHARS)}")
                self._entries = None

    def _atomic_write(self, body: str) -> None:
        dir_name = self.cache_dir or "."
        fd, tmp_path = tempfile.mkstemp(prefix=f".{self.namespace}_", dir=dir_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
        except BaseException:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            raise

    def stats(self) -> Dict[str, Any]:
        return {
            "namespace": self.namespace, "available": self.available,
            "hits": self.hits, "misses": self.misses, "stale": self.stale,
            "writes": self.writes, "ttl_seconds": self.ttl_seconds,
            "notes": list(self.notes),
        }


class ProviderSession:
    """
    The per-run provider context: budget, deadline, rate limits, retry policy
    and caches, in one object threaded through every provider call.

    Providers accept `session=None` and then behave exactly as they did before
    this existed (one unthrottled, unretried, uncached request), so a direct
    call from a test or from another tool is unchanged.
    """

    def __init__(
        self,
        budget: Optional[RequestBudget] = None,
        deadline: Optional[Deadline] = None,
        retry_policy: Optional[RetryPolicy] = None,
        query_cache: Optional[ProviderCache] = None,
        feed_cache: Optional[ProviderCache] = None,
        rate_limiters: Optional[Dict[str, RateLimiter]] = None,
    ):
        self.budget = budget
        self.deadline = deadline
        self.retry_policy = retry_policy
        self.query_cache = query_cache
        self.feed_cache = feed_cache
        self.rate_limiters: Dict[str, RateLimiter] = rate_limiters or {}

    def limiter(self, provider: str) -> Optional[RateLimiter]:
        return self.rate_limiters.get(provider)

    def stats(self) -> Dict[str, Any]:
        return {
            "requests_used": self.budget.used if self.budget else None,
            "requests_remaining": self.budget.remaining if self.budget else None,
            "deadline_expired": bool(self.deadline.expired) if self.deadline else False,
            "rate_limit_waits": {name: lim.waits for name, lim in sorted(self.rate_limiters.items())},
            "query_cache": self.query_cache.stats() if self.query_cache else None,
            "feed_cache": self.feed_cache.stats() if self.feed_cache else None,
        }


def build_session(
    output_dir: str = "output",
    use_cache: bool = True,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    max_runtime_seconds: float = DEFAULT_MAX_RUNTIME_SECONDS,
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
    cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
    retry_policy: Optional[RetryPolicy] = None,
    sleep=time.sleep,
) -> ProviderSession:
    """Build the provider session run_vuln_intel uses (exposed so callers can tune or disable it)."""
    cache_dir = os.path.join(output_dir, CACHE_DIRNAME)
    query_cache = ProviderCache(cache_dir, "queries", ttl_seconds=cache_ttl_seconds) if use_cache else None
    feed_cache = ProviderCache(cache_dir, "feeds", ttl_seconds=DEFAULT_KEV_CACHE_TTL_SECONDS,
                               max_entries=8, max_bytes=DEFAULT_FEED_CACHE_MAX_BYTES) if use_cache else None
    limiters = {
        "nvd": RateLimiter(
            NVD_MIN_INTERVAL_WITH_KEY if (nvd_api_key or os.environ.get(NVD_API_KEY_ENV))
            else NVD_MIN_INTERVAL_UNAUTHENTICATED, sleep=sleep),
        "osv": RateLimiter(OSV_MIN_INTERVAL, sleep=sleep),
        "github_advisories": RateLimiter(
            GITHUB_MIN_INTERVAL_WITH_TOKEN if (github_token or os.environ.get(GITHUB_TOKEN_ENV))
            else GITHUB_MIN_INTERVAL_UNAUTHENTICATED, sleep=sleep),
        "epss": RateLimiter(EPSS_MIN_INTERVAL, sleep=sleep),
        "cisa_kev": RateLimiter(0.0, sleep=sleep),
        "exploitdb": RateLimiter(0.0, sleep=sleep),
    }
    return ProviderSession(
        budget=RequestBudget(max_requests),
        deadline=Deadline(max_runtime_seconds),
        retry_policy=retry_policy if retry_policy is not None else RetryPolicy(sleep=sleep),
        query_cache=query_cache,
        feed_cache=feed_cache,
        rate_limiters=limiters,
    )


def _session_parts(session: Optional[ProviderSession], provider: str) -> Dict[str, Any]:
    """Transport kwargs for one provider, whether or not a session exists."""
    if session is None:
        return {"budget": None, "deadline": None, "rate_limiter": None, "retry_policy": None}
    return {
        "budget": session.budget,
        "deadline": session.deadline,
        "rate_limiter": session.limiter(provider),
        "retry_policy": session.retry_policy,
    }


# ---------------------------------------------------------------------------
# Normalized provider record
# ---------------------------------------------------------------------------

def _blank_record(cve_id: str, source: str) -> Dict[str, Any]:
    """The shape every provider normalizes into, so the correlation engine has no provider special cases."""
    return {
        "cve_id": cve_id,
        "summary": None,
        "severity": None,
        "cvss_score": None,
        "cvss_vector": None,
        "cvss_metrics": [],
        "published": None,
        "references": [],
        "source": source,
        "version_match": "unknown",
        "match_quality": MATCH_QUALITY_KEYWORD,
        "mapping_method": None,
        "advisory_ids": [],
        "package": None,
        "ecosystem": None,
        "affected_ranges": [],
        "fixed_versions": [],
        "matched_cpe_products": [],
        "raw_evidence": None,
    }


def _cvss_vector_metrics(vector: Optional[str]) -> Dict[str, Any]:
    """
    Structured applicability evidence already present in a CVSS v3/v4 vector.

    Preserved, never interpreted as satisfied: "AV:N" says the advisory
    describes a network-reachable weakness, not that this asset exposes it.
    """
    if not isinstance(vector, str) or not vector.strip():
        return {}
    fields = {}
    for part in vector.strip()[:256].split("/"):
        if ":" in part:
            key, _, val = part.partition(":")
            key, val = key.strip().upper(), val.strip().upper()
            if len(key) <= 4 and len(val) <= 4:
                fields[key] = val
    names = {"AV": "attack_vector", "AC": "attack_complexity", "PR": "privileges_required",
             "UI": "user_interaction", "S": "scope", "AT": "attack_requirements"}
    return {names[k]: v for k, v in fields.items() if k in names}


_NVD_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _extract_nvd_cvss(metrics: Dict[str, Any]) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    """
    Best CVSS triple (score, vector, severity) from an NVD `metrics` object.

    NVD returns several entries per metric family — the NVD/CISA "Primary"
    assessment alongside any number of CNA "Secondary" ones, in no guaranteed
    order. Taking entries[0] therefore picked a CNA's self-assessment over the
    authoritative Primary score whenever the CNA happened to be listed first
    (reproduced: a Secondary 9.8 shadowing a Primary 5.3). Primary wins; within
    a type, the newest CVSS version wins.
    """
    best: Optional[Tuple[int, int, Optional[float], Optional[str], Optional[str]]] = None
    for rank, key in enumerate(_NVD_METRIC_KEYS):
        entries = metrics.get(key) if isinstance(metrics, dict) else None
        for entry in _as_list(entries)[:MAX_CVSS_ENTRIES]:
            entry = _as_dict(entry)
            data = _as_dict(entry.get("cvssData"))
            score = _as_float(data.get("baseScore"))
            vector = _safe_text(data.get("vectorString"), 256) if isinstance(data.get("vectorString"), str) else None
            severity = entry.get("baseSeverity") or data.get("baseSeverity")
            severity = _safe_identifier(severity) if isinstance(severity, str) else None
            is_primary = 0 if str(entry.get("type") or "").strip().lower() == "primary" else 1
            candidate = (is_primary, rank, score, vector, severity)
            if best is None or candidate[:2] < best[:2]:
                best = candidate
    if best is None:
        return None, None, None
    return best[2], best[3], best[4]


def _all_nvd_cvss_metrics(metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every CVSS assessment NVD published, bounded — source disagreement is evidence, not noise."""
    out: List[Dict[str, Any]] = []
    for key in _NVD_METRIC_KEYS:
        for entry in _as_list(_as_dict(metrics).get(key))[:MAX_CVSS_ENTRIES]:
            entry = _as_dict(entry)
            data = _as_dict(entry.get("cvssData"))
            out.append({
                "family": key,
                "type": _safe_identifier(entry.get("type")),
                "source": _safe_identifier(entry.get("source")),
                "score": _as_float(data.get("baseScore")),
                "severity": _safe_identifier(entry.get("baseSeverity") or data.get("baseSeverity")),
                "vector": _safe_text(data.get("vectorString"), 256) if isinstance(data.get("vectorString"), str) else None,
            })
            if len(out) >= MAX_CVSS_ENTRIES:
                return out
    return out


def _nvd_cpe_assessment(cve_obj: Dict[str, Any], technology: str, version: Optional[str]) -> Dict[str, Any]:
    """
    Inspect one NVD CVE's CPE configurations against the observed
    technology/version.

    Returns {"version_match", "match_quality", "products", "ranges",
    "notes"}. Only an EXACT or curated-ALIAS product name may produce
    "range_confirmed": a merely related product name (nginx vs
    nginx_controller) is recorded as evidence but never treated as this
    product's own applicability data.

    AND/OR node semantics: NVD expresses applicability as configurations of
    nodes, and a `vulnerable: false` cpeMatch is a platform/condition entry,
    not an affected product. Only `vulnerable: true` entries are considered,
    and a match on any one of them is treated as the CVE claiming
    applicability for that product — which is what "MAY be affected" means.
    A negated node (`negate: true`) inverts the meaning of its own children,
    so it is skipped rather than read as an assertion.
    """
    result: Dict[str, Any] = {
        "version_match": "unknown" if not version else "keyword_only",
        "match_quality": MATCH_QUALITY_KEYWORD,
        "products": [],
        "ranges": [],
        "notes": [],
    }
    products: List[str] = []
    ranges: List[Dict[str, Any]] = []
    best_quality: Optional[str] = None
    confirmed_quality: Optional[str] = None
    related_seen = False
    matches_examined = 0

    for config in _as_list(cve_obj.get("configurations"))[:MAX_CPE_CONFIGURATIONS]:
        config = _as_dict(config)
        for node in _as_list(config.get("nodes"))[:MAX_CPE_NODES]:
            node = _as_dict(node)
            if node.get("negate") is True:
                result["notes"].append("a negated CPE node was skipped rather than read as an assertion")
                continue
            for match in _as_list(node.get("cpeMatch")):
                if matches_examined >= MAX_CPE_MATCHES:
                    result["notes"].append(
                        f"CPE configuration truncated at {MAX_CPE_MATCHES} match entries")
                    break
                matches_examined += 1
                match = _as_dict(match)
                if match.get("vulnerable") is not True:
                    continue
                criteria = match.get("criteria") or match.get("cpe23Uri") or ""
                if not isinstance(criteria, str):
                    continue
                product = _cpe_field(criteria, 4)
                if not product:
                    continue
                quality = _product_match_quality(technology, product)
                if quality is None:
                    continue
                safe_product = _safe_identifier(product)
                if safe_product and safe_product not in products and len(products) < 10:
                    products.append(safe_product)
                if quality == MATCH_QUALITY_RELATED:
                    related_seen = True
                if best_quality is None or _MATCH_QUALITY_RANK.get(quality, 0) > _MATCH_QUALITY_RANK.get(best_quality, 0):
                    best_quality = quality

                cpe_version, version_is_na = _cpe_version_field(criteria)
                bounds = {
                    "start_including": match.get("versionStartIncluding"),
                    "start_excluding": match.get("versionStartExcluding"),
                    "end_including": match.get("versionEndIncluding"),
                    "end_excluding": match.get("versionEndExcluding"),
                }
                if len(ranges) < MAX_AFFECTED_RANGES:
                    ranges.append({
                        "product": safe_product,
                        "cpe_version": _safe_identifier(cpe_version),
                        "version_na": version_is_na,
                        **{k: _safe_identifier(v) if isinstance(v, str) else None for k, v in bounds.items()},
                        "match_quality": quality,
                    })

                if not version:
                    continue
                if quality == MATCH_QUALITY_RELATED:
                    # Related-name evidence, never applicability evidence.
                    continue
                if version_is_na:
                    result["notes"].append(
                        f"CPE for {safe_product!r} declares version NA (no version applies); "
                        f"an observed version cannot fall inside it")
                    continue
                if cpe_version:
                    if compare_versions(version, cpe_version) == 0:
                        confirmed_quality = quality if confirmed_quality is None else confirmed_quality
                    continue  # this entry names one specific, different version
                in_range = _version_in_range(
                    version,
                    start_including=bounds["start_including"],
                    start_excluding=bounds["start_excluding"],
                    end_including=bounds["end_including"],
                    end_excluding=bounds["end_excluding"],
                )
                if in_range is True:
                    confirmed_quality = quality if confirmed_quality is None else confirmed_quality
                elif in_range is None and any(bounds.values()):
                    result["notes"].append(
                        "a version bound could not be compared against the observed version; "
                        "no applicability was inferred from it")

    result["products"] = products
    result["ranges"] = ranges
    if version and confirmed_quality is not None:
        result["version_match"] = "range_confirmed"
        result["match_quality"] = confirmed_quality
    else:
        result["match_quality"] = best_quality or MATCH_QUALITY_KEYWORD
        if related_seen and best_quality == MATCH_QUALITY_RELATED:
            result["notes"].append(
                f"the matching CPE product name(s) {products!r} are only related to the observed "
                f"technology {technology!r}, not the same product; version applicability was not "
                f"inferred from them")
    result["notes"] = _bound_notes(result["notes"], 8)
    return result


_MATCH_QUALITY_RANK = {
    MATCH_QUALITY_KEYWORD: 0,
    MATCH_QUALITY_RELATED: 1,
    MATCH_QUALITY_PACKAGE: 2,
    MATCH_QUALITY_ALIAS: 3,
    MATCH_QUALITY_EXACT: 4,
}


def _nvd_cve_version_match(cve_obj: Dict[str, Any], technology: str, version: Optional[str]) -> str:
    """Legacy thin wrapper: 'range_confirmed' | 'keyword_only' | 'unknown' for one NVD CVE object."""
    return _nvd_cpe_assessment(cve_obj, technology, version)["version_match"]


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

def query_nvd(
    technology: str,
    version: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    results_per_page: int = NVD_DEFAULT_RESULTS_PER_PAGE,
    base_url: str = NVD_API_BASE,
    session: Optional[ProviderSession] = None,
    max_results: int = DEFAULT_NVD_MAX_RESULTS,
    max_pages: int = DEFAULT_NVD_MAX_PAGES,
) -> Dict[str, Any]:
    """
    Query the NVD CVE API 2.0 via keywordSearch=<technology>, then inspect each
    returned CVE's CPE configuration data (when present) to determine whether
    `version` falls within its documented vulnerable range.

    Paginates up to `max_pages`/`max_results` and reports truncation
    explicitly: NVD's keyword search routinely reports thousands of
    totalResults, and silently keeping the first page while calling the outcome
    "found" hid from every downstream consumer that the answer was partial.
    """
    result: Dict[str, Any] = {
        "status": "error", "outcome": OUTCOME_UNAVAILABLE, "vulnerabilities": [],
        "error": None, "total_results": 0, "retrieved": 0, "pages": 0,
        "truncated": False, "notes": [], "cache": None,
    }
    if not isinstance(technology, str) or not technology.strip():
        result["error"] = "technology name is required"
        result["outcome"] = OUTCOME_INVALID_REQUEST
        return result
    technology = _safe_token(technology.strip(), MAX_TECHNOLOGY_CHARS)

    api_key = api_key if api_key is not None else os.environ.get(NVD_API_KEY_ENV)
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key

    cache = session.query_cache if session else None
    cache_key = ProviderCache.key("nvd", technology.lower(), version or "", base_url,
                                  max_results, results_per_page)
    if cache is not None:
        hit = cache.get(cache_key)
        if hit is not None:
            payload = _as_dict(hit.get("payload"))
            result["vulnerabilities"] = _as_record_list(payload.get("vulnerabilities"))
            result["total_results"] = int(_as_float(payload.get("total_results")) or 0)
            result["retrieved"] = len(result["vulnerabilities"])
            result["pages"] = int(_as_float(payload.get("pages")) or 0)
            result["truncated"] = bool(payload.get("truncated"))
            result["notes"] = [n for n in _as_list(payload.get("notes")) if isinstance(n, str)][:MAX_NOTES]
            result["status"] = "found" if result["vulnerabilities"] else "not_found"
            result["outcome"] = OUTCOME_FOUND if result["vulnerabilities"] else OUTCOME_EMPTY_AUTHORITATIVE
            result["cache"] = {"hit": True, "stored_at": hit.get("stored_at"),
                               "age_seconds": hit.get("age_seconds")}
            return result

    per_page = max(1, min(int(results_per_page or NVD_DEFAULT_RESULTS_PER_PAGE), NVD_MAX_RESULTS_PER_PAGE))
    max_results = max(1, int(max_results))
    max_pages = max(1, int(max_pages))
    vulns: List[Dict[str, Any]] = []
    start_index = 0
    total_results = 0

    for page in range(max_pages):
        params = {
            "keywordSearch": technology,
            "resultsPerPage": min(per_page, max_results - len(vulns)),
            "startIndex": start_index,
        }
        attempt = _request_with_retry(
            "GET", base_url, headers=headers, params=params, timeout=timeout,
            **_session_parts(session, "nvd"),
        )
        resp = attempt["response"]
        if resp is None:
            if page == 0:
                result["error"] = _safe_text(attempt["error"] or "request failed", MAX_ERROR_CHARS)
                result["outcome"] = attempt["outcome"]
                result["status"] = "error"
                return result
            result["notes"].append(f"pagination stopped after page {page}: {attempt['error']}")
            result["truncated"] = True
            break

        try:
            status_code = resp.status_code
            if status_code in (403, 429):
                if page == 0:
                    result["status"] = "rate_limited"
                    result["outcome"] = OUTCOME_RATE_LIMITED
                    retry_after = attempt.get("retry_after")
                    result["error"] = (
                        f"NVD API returned HTTP {status_code} (rate limited; consider supplying an API key)"
                        + (f"; Retry-After={retry_after}s" if retry_after is not None else ""))
                    result["retry_after"] = retry_after
                    return result
                result["notes"].append(f"pagination stopped at page {page}: HTTP {status_code} (rate limited)")
                result["truncated"] = True
                break
            if status_code != 200:
                if page == 0:
                    result["outcome"] = OUTCOME_UNAVAILABLE
                    result["error"] = (f"NVD API returned HTTP {status_code}" if status_code >= 500
                                       else f"NVD API returned unexpected HTTP {status_code}")
                    return result
                result["notes"].append(f"pagination stopped at page {page}: HTTP {status_code}")
                result["truncated"] = True
                break

            data, decode_error = _decode_json_body(resp, MAX_RESPONSE_BYTES)
        finally:
            try:
                resp.close()
            except Exception:
                pass

        if decode_error is not None:
            if page == 0:
                result["error"] = f"malformed JSON from NVD API: {_safe_text(decode_error, MAX_ERROR_CHARS)}" \
                    if "malformed" in decode_error or "empty" in decode_error else \
                    f"malformed response from NVD API: {_safe_text(decode_error, MAX_ERROR_CHARS)}"
                result["outcome"] = OUTCOME_MALFORMED
                return result
            result["notes"].append(f"pagination stopped at page {page}: {decode_error}")
            result["truncated"] = True
            break

        if not isinstance(data, dict) or "vulnerabilities" not in data:
            if page == 0:
                result["error"] = "unexpected NVD API response structure"
                result["outcome"] = OUTCOME_MALFORMED
                return result
            result["truncated"] = True
            break

        page_total = _as_float(data.get("totalResults"))
        if page_total is not None:
            total_results = max(total_results, int(page_total))
        page_items = _as_list(data.get("vulnerabilities"))
        result["pages"] = page + 1

        for item in page_items:
            if len(vulns) >= max_results or len(vulns) >= MAX_RECORDS_PER_SOURCE:
                result["truncated"] = True
                break
            try:
                record = _normalize_nvd_item(item, technology, version)
            except Exception:
                continue  # one malformed entry must not abort the rest
            if record is not None:
                vulns.append(record)

        start_index += len(page_items)
        if (not page_items or len(vulns) >= max_results or len(vulns) >= MAX_RECORDS_PER_SOURCE
                or start_index >= total_results):
            break

    result["total_results"] = total_results
    result["retrieved"] = len(vulns)
    if total_results > start_index and start_index > 0:
        result["truncated"] = True
    if result["truncated"]:
        result["notes"].append(
            f"NVD reported {total_results} total result(s); {len(vulns)} were retrieved and assessed. "
            f"This is a PARTIAL result, not a complete picture of NVD's data for {technology!r}.")
    result["vulnerabilities"] = vulns
    result["notes"] = _bound_notes(result["notes"])
    result["status"] = "found" if vulns else "not_found"
    result["outcome"] = OUTCOME_FOUND if vulns else OUTCOME_EMPTY_AUTHORITATIVE
    # A truncated page-1 answer is still authoritative about what it contains,
    # but it must not be cached as if it were the whole answer for longer than
    # the same query would be re-derived; it is cached with its truncation flag
    # so a cache hit carries the same warning.
    if cache is not None:
        cache.put(cache_key, result["outcome"], {
            "vulnerabilities": vulns, "total_results": total_results,
            "retrieved": len(vulns), "pages": result["pages"],
            "truncated": result["truncated"], "notes": result["notes"],
        })
        result["cache"] = {"hit": False}
    return result


def _normalize_nvd_item(item: Any, technology: str, version: Optional[str]) -> Optional[Dict[str, Any]]:
    """One NVD `vulnerabilities[]` entry -> the normalized provider record."""
    cve_obj = _as_dict(_as_dict(item).get("cve"))
    cve_id = cve_obj.get("id")
    if not isinstance(cve_id, str) or not _CVE_ID_RE.match(cve_id.strip()):
        return None
    cve_id = cve_id.strip()

    description = next(
        (d.get("value") for d in _as_list(cve_obj.get("descriptions"))
         if isinstance(d, dict) and d.get("lang") == "en" and isinstance(d.get("value"), str)),
        None,
    )
    metrics = _as_dict(cve_obj.get("metrics"))
    cvss_score, cvss_vector, severity = _extract_nvd_cvss(metrics)
    references, refs_truncated = _bound_list(
        [r for r in (_safe_reference(_as_dict(ref).get("url")) for ref in _as_list(cve_obj.get("references"))) if r],
        MAX_REFERENCES_PER_CVE)

    assessment = _nvd_cpe_assessment(cve_obj, technology, version)
    record = _blank_record(cve_id, "nvd")
    record.update({
        "summary": _safe_text(description, MAX_SUMMARY_CHARS) if isinstance(description, str) else None,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_metrics": _all_nvd_cvss_metrics(metrics),
        "published": _safe_identifier(cve_obj.get("published"), 64) if isinstance(cve_obj.get("published"), str) else None,
        "references": references,
        "references_truncated": refs_truncated,
        "version_match": assessment["version_match"],
        "match_quality": assessment["match_quality"],
        "mapping_method": "nvd_keyword_search_plus_cpe_configuration",
        "matched_cpe_products": assessment["products"],
        "affected_ranges": assessment["ranges"],
        "notes": assessment["notes"],
    })
    evidence = f"NVD keywordSearch={technology!r} matched {cve_id}"
    if assessment["version_match"] == "range_confirmed":
        evidence += (f"; version {version!r} falls within the CVE's documented vulnerable CPE range "
                     f"for product(s) {assessment['products']!r} ({assessment['match_quality']})")
    elif assessment["products"]:
        evidence += f"; CPE product(s) {assessment['products']!r} ({assessment['match_quality']})"
    record["raw_evidence"] = _safe_text(evidence, MAX_EVIDENCE_CHARS)
    return record


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------

_OSV_ECOSYSTEM_HINTS = {
    "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
    "jquery": "npm", "lodash": "npm", "express": "npm", "react": "npm",
    "vue": "npm", "angular": "npm", "next.js": "npm", "nextjs": "npm",
    "django": "PyPI", "flask": "PyPI", "requests": "PyPI", "fastapi": "PyPI",
    "rails": "RubyGems", "ruby on rails": "RubyGems",
    "spring": "Maven", "struts": "Maven", "log4j": "Maven",
    "laravel": "Packagist", "symfony": "Packagist",
}


def _infer_osv_ecosystem(technology: str, hint: Optional[str] = None) -> Optional[str]:
    if hint:
        return _safe_identifier(hint, MAX_ECOSYSTEM_CHARS)
    if not isinstance(technology, str):
        return None
    return _OSV_ECOSYSTEM_HINTS.get(technology.strip().lower())


def _extract_cve_id(primary_id: Optional[str], aliases: List[str]) -> Optional[str]:
    if isinstance(primary_id, str) and _CVE_ID_RE.match(primary_id.strip()):
        return primary_id.strip()
    for alias in _as_list(aliases)[:MAX_ALIASES]:
        if isinstance(alias, str) and _CVE_ID_RE.match(alias.strip()):
            return alias.strip()
    return None


def _osv_affected_detail(vuln: Dict[str, Any], package_name: str) -> Dict[str, Any]:
    """Fixed versions / introduced ranges / ecosystem for the queried package, bounded."""
    fixed: List[str] = []
    ranges: List[Dict[str, Any]] = []
    ecosystems: List[str] = []
    wanted = _normalize_product_token(package_name)
    for affected in _as_list(vuln.get("affected"))[:MAX_AFFECTED_RANGES]:
        affected = _as_dict(affected)
        pkg = _as_dict(affected.get("package"))
        name = pkg.get("name")
        if isinstance(name, str) and wanted and _normalize_product_token(name) != wanted:
            continue
        eco = _safe_identifier(pkg.get("ecosystem"), MAX_ECOSYSTEM_CHARS)
        if eco and eco not in ecosystems and len(ecosystems) < 4:
            ecosystems.append(eco)
        for rng in _as_list(affected.get("ranges"))[:MAX_AFFECTED_RANGES]:
            rng = _as_dict(rng)
            events = []
            for event in _as_list(rng.get("events"))[:MAX_AFFECTED_RANGES]:
                event = _as_dict(event)
                introduced = event.get("introduced")
                fixed_at = event.get("fixed")
                last_affected = event.get("last_affected")
                if isinstance(fixed_at, str) and fixed_at.strip():
                    clean = _safe_identifier(fixed_at, MAX_VERSION_CHARS)
                    if clean and clean not in fixed and len(fixed) < MAX_FIXED_VERSIONS:
                        fixed.append(clean)
                events.append({
                    "introduced": _safe_identifier(introduced, MAX_VERSION_CHARS) if isinstance(introduced, str) else None,
                    "fixed": _safe_identifier(fixed_at, MAX_VERSION_CHARS) if isinstance(fixed_at, str) else None,
                    "last_affected": _safe_identifier(last_affected, MAX_VERSION_CHARS) if isinstance(last_affected, str) else None,
                })
            if len(ranges) < MAX_AFFECTED_RANGES:
                ranges.append({"type": _safe_identifier(rng.get("type"), 32), "events": events})
    return {"fixed_versions": fixed, "ranges": ranges, "ecosystems": ecosystems}


def _osv_cvss(severities: Any) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    """OSV `severity` entries: prefer the newest CVSS family, keep them all as evidence."""
    entries: List[Dict[str, Any]] = []
    best: Optional[Tuple[int, str]] = None
    order = {"CVSS_V4": 0, "CVSS_V3": 1, "CVSS_V2": 2}
    for sev in _as_list(severities)[:MAX_CVSS_ENTRIES]:
        sev = _as_dict(sev)
        kind = _safe_identifier(sev.get("type"), 32)
        score = sev.get("score")
        vector = _safe_text(score, 256) if isinstance(score, str) else None
        entries.append({"family": kind, "type": None, "source": "osv", "score": None,
                        "severity": None, "vector": vector})
        rank = order.get(str(kind or "").upper(), 9)
        if vector and (best is None or rank < best[0]):
            best = (rank, vector)
    return (best[1] if best else None), entries


def query_osv(
    technology: str,
    version: Optional[str] = None,
    ecosystem: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = OSV_API_BASE,
    session: Optional[ProviderSession] = None,
) -> Dict[str, Any]:
    """
    Query OSV's package endpoint. Requires a known package ecosystem (see the
    module docstring's per-source limitations) — never guesses one.

    The queried PACKAGE name is the observed technology name. A product name is
    not always a package name, so it is recorded on every record (`package`,
    `ecosystem`) rather than left as an invisible assumption, and the
    match_quality is "package_query", not a CPE-grade product identity.
    """
    result: Dict[str, Any] = {
        "status": "skipped", "outcome": OUTCOME_SKIPPED, "vulnerabilities": [],
        "error": None, "notes": [], "cache": None, "truncated": False,
    }
    if not isinstance(technology, str) or not technology.strip():
        result["status"] = "error"
        result["outcome"] = OUTCOME_INVALID_REQUEST
        result["error"] = "technology name is required"
        return result
    technology = _safe_token(technology.strip(), MAX_TECHNOLOGY_CHARS)

    resolved_ecosystem = _infer_osv_ecosystem(technology, ecosystem)
    if not resolved_ecosystem:
        result["error"] = (
            f"OSV requires a known package ecosystem (e.g. npm, PyPI, Go, WordPress); "
            f"none could be inferred for {technology!r}"
        )
        return result

    cache = session.query_cache if session else None
    cache_key = ProviderCache.key("osv", technology.lower(), version or "", resolved_ecosystem, base_url)
    if cache is not None:
        hit = cache.get(cache_key)
        if hit is not None:
            payload = _as_dict(hit.get("payload"))
            result["vulnerabilities"] = _as_record_list(payload.get("vulnerabilities"))
            result["skipped_non_cve_advisories"] = int(_as_float(payload.get("skipped_non_cve_advisories")) or 0)
            result["notes"] = [n for n in _as_list(payload.get("notes")) if isinstance(n, str)][:MAX_NOTES]
            result["truncated"] = bool(payload.get("truncated"))
            result["status"] = "found" if result["vulnerabilities"] else "not_found"
            result["outcome"] = OUTCOME_FOUND if result["vulnerabilities"] else OUTCOME_EMPTY_AUTHORITATIVE
            result["cache"] = {"hit": True, "stored_at": hit.get("stored_at"),
                               "age_seconds": hit.get("age_seconds")}
            return result

    body: Dict[str, Any] = {"package": {"name": technology, "ecosystem": resolved_ecosystem}}
    if version:
        body["version"] = version

    attempt = _request_with_retry(
        "POST", base_url, headers={"User-Agent": DEFAULT_USER_AGENT}, json_body=body,
        timeout=timeout, **_session_parts(session, "osv"),
    )
    resp = attempt["response"]
    if resp is None:
        result["status"] = "error"
        result["outcome"] = attempt["outcome"]
        result["error"] = _safe_text(attempt["error"] or "request failed", MAX_ERROR_CHARS)
        return result

    try:
        status_code = resp.status_code
        if status_code == 429:
            result["status"], result["outcome"] = "rate_limited", OUTCOME_RATE_LIMITED
            result["error"] = "HTTP 429 from OSV API"
            result["retry_after"] = attempt.get("retry_after")
            return result
        if status_code >= 500:
            result["status"], result["outcome"] = "error", OUTCOME_UNAVAILABLE
            result["error"] = f"OSV API returned HTTP {status_code}"
            return result
        if status_code != 200:
            result["status"], result["outcome"] = "error", OUTCOME_UNAVAILABLE
            result["error"] = f"OSV API returned unexpected HTTP {status_code}"
            return result
        data, decode_error = _decode_json_body(resp, MAX_RESPONSE_BYTES)
    finally:
        try:
            resp.close()
        except Exception:
            pass

    if decode_error is not None:
        result["status"], result["outcome"] = "error", OUTCOME_MALFORMED
        result["error"] = f"malformed JSON from OSV API: {_safe_text(decode_error, MAX_ERROR_CHARS)}"
        return result
    if not isinstance(data, dict):
        result["status"], result["outcome"] = "error", OUTCOME_MALFORMED
        result["error"] = "unexpected OSV API response structure"
        return result

    vulns_raw = _as_list(data.get("vulns"))
    if len(vulns_raw) > MAX_RECORDS_PER_SOURCE:
        result["truncated"] = True
        result["notes"].append(
            f"OSV returned {len(vulns_raw)} advisories; the first {MAX_RECORDS_PER_SOURCE} were assessed")
        vulns_raw = vulns_raw[:MAX_RECORDS_PER_SOURCE]

    version_match_default = "range_confirmed" if version else "unknown"
    parsed: List[Dict[str, Any]] = []
    skipped_non_cve = 0
    for v in vulns_raw:
        try:
            v = _as_dict(v)
            osv_id = _safe_identifier(v.get("id"))
            cve_id = _extract_cve_id(v.get("id"), _as_list(v.get("aliases")))
            if not cve_id:
                skipped_non_cve += 1
                continue
            cvss_vector, cvss_entries = _osv_cvss(v.get("severity"))
            references, refs_truncated = _bound_list(
                [r for r in (_safe_reference(_as_dict(ref).get("url")) for ref in _as_list(v.get("references"))) if r],
                MAX_REFERENCES_PER_CVE)
            details = v.get("details")
            summary = v.get("summary")
            if not isinstance(summary, str) or not summary.strip():
                summary = details if isinstance(details, str) else None
            affected = _osv_affected_detail(v, technology)

            evidence = (f"OSV package query (name={technology!r}, ecosystem={resolved_ecosystem!r}) "
                        f"matched {cve_id} via {osv_id}")
            if version:
                evidence += (f"; OSV's own server-side version filtering placed {version!r} inside the "
                             f"affected range for that package")
            record = _blank_record(cve_id, "osv")
            record.update({
                "summary": _safe_text(summary, MAX_SUMMARY_CHARS) if isinstance(summary, str) else None,
                "cvss_vector": cvss_vector,
                "cvss_metrics": cvss_entries,
                "published": _safe_identifier(v.get("published"), 64) if isinstance(v.get("published"), str) else None,
                "references": references,
                "references_truncated": refs_truncated,
                "version_match": version_match_default,
                "match_quality": MATCH_QUALITY_PACKAGE,
                "mapping_method": "osv_package_version_query",
                "advisory_ids": [osv_id] if osv_id else [],
                "package": technology,
                "ecosystem": resolved_ecosystem,
                "fixed_versions": affected["fixed_versions"],
                "affected_ranges": affected["ranges"],
                "raw_evidence": _safe_text(evidence, MAX_EVIDENCE_CHARS),
            })
            parsed.append(record)
        except Exception:
            continue

    result["vulnerabilities"] = parsed
    result["skipped_non_cve_advisories"] = skipped_non_cve
    result["notes"] = _bound_notes(result["notes"])
    result["status"] = "found" if parsed else "not_found"
    result["outcome"] = OUTCOME_FOUND if parsed else OUTCOME_EMPTY_AUTHORITATIVE
    if cache is not None:
        cache.put(cache_key, result["outcome"], {
            "vulnerabilities": parsed, "skipped_non_cve_advisories": skipped_non_cve,
            "notes": result["notes"], "truncated": result["truncated"],
        })
        result["cache"] = {"hit": False}
    return result


# ---------------------------------------------------------------------------
# GitHub Security Advisories
# ---------------------------------------------------------------------------

def _ghsa_package_detail(advisory: Dict[str, Any], technology: str,
                         version: Optional[str]) -> Dict[str, Any]:
    """
    Match the advisory's affected packages against the observed technology.

    Only an exact (normalized) package-name match may confirm a version range:
    a GHSA result is not automatically equivalent to an NVD CPE match, and the
    package the advisory is about may simply not be the software observed.
    """
    detail: Dict[str, Any] = {
        "version_match": "unknown" if not version else "keyword_only",
        "package": None, "ecosystem": None,
        "fixed_versions": [], "ranges": [], "notes": [],
    }
    wanted = _normalize_product_token(technology)
    for pkg_vuln in _as_list(advisory.get("vulnerabilities"))[:MAX_AFFECTED_RANGES]:
        pkg_vuln = _as_dict(pkg_vuln)
        pkg = _as_dict(pkg_vuln.get("package"))
        name = pkg.get("name")
        if not isinstance(name, str):
            continue
        if _normalize_product_token(name) != wanted:
            continue
        detail["package"] = _safe_identifier(name, MAX_TECHNOLOGY_CHARS)
        detail["ecosystem"] = _safe_identifier(pkg.get("ecosystem"), MAX_ECOSYSTEM_CHARS)
        range_str = pkg_vuln.get("vulnerable_version_range")
        first_patched = pkg_vuln.get("first_patched_version")
        if isinstance(first_patched, dict):
            first_patched = first_patched.get("identifier")
        if isinstance(first_patched, str) and first_patched.strip():
            clean = _safe_identifier(first_patched, MAX_VERSION_CHARS)
            if clean and clean not in detail["fixed_versions"]:
                detail["fixed_versions"].append(clean)
        if isinstance(range_str, str) and range_str.strip():
            if len(detail["ranges"]) < MAX_AFFECTED_RANGES:
                detail["ranges"].append({"vulnerable_version_range": _safe_text(range_str, 256)})
            if version:
                bounds = _parse_version_range_string(range_str)
                in_range = _version_in_range(version, **bounds) if bounds else None
                if in_range is True:
                    detail["version_match"] = "range_confirmed"
                elif in_range is None and bounds:
                    detail["notes"].append(
                        f"GHSA range {range_str!r} could not be compared against {version!r}; "
                        f"no applicability was inferred from it")
    return detail


def query_github_advisories(
    technology: str,
    version: Optional[str] = None,
    ecosystem: Optional[str] = None,
    token: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    per_page: int = 20,
    base_url: str = GITHUB_ADVISORIES_API,
    session: Optional[ProviderSession] = None,
) -> Dict[str, Any]:
    """Query GitHub's public Security Advisories REST API, filtered to advisories that carry an assigned CVE ID."""
    result: Dict[str, Any] = {
        "status": "error", "outcome": OUTCOME_UNAVAILABLE, "vulnerabilities": [],
        "error": None, "notes": [], "cache": None, "truncated": False,
    }
    if not isinstance(technology, str) or not technology.strip():
        result["error"] = "technology name is required"
        result["outcome"] = OUTCOME_INVALID_REQUEST
        return result
    technology = _safe_token(technology.strip(), MAX_TECHNOLOGY_CHARS)

    token = token if token is not None else os.environ.get(GITHUB_TOKEN_ENV)
    headers = {"Accept": "application/vnd.github+json", "User-Agent": DEFAULT_USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    params: Dict[str, Any] = {"affects": technology, "per_page": max(1, min(int(per_page or 20), 100))}
    if ecosystem:
        params["ecosystem"] = str(ecosystem).lower()[:MAX_ECOSYSTEM_CHARS]

    cache = session.query_cache if session else None
    cache_key = ProviderCache.key("ghsa", technology.lower(), version or "",
                                  params.get("ecosystem") or "", base_url, params["per_page"])
    if cache is not None:
        hit = cache.get(cache_key)
        if hit is not None:
            payload = _as_dict(hit.get("payload"))
            result["vulnerabilities"] = _as_record_list(payload.get("vulnerabilities"))
            result["skipped_no_cve_advisories"] = int(_as_float(payload.get("skipped_no_cve_advisories")) or 0)
            result["notes"] = [n for n in _as_list(payload.get("notes")) if isinstance(n, str)][:MAX_NOTES]
            result["truncated"] = bool(payload.get("truncated"))
            result["status"] = "found" if result["vulnerabilities"] else "not_found"
            result["outcome"] = OUTCOME_FOUND if result["vulnerabilities"] else OUTCOME_EMPTY_AUTHORITATIVE
            result["cache"] = {"hit": True, "stored_at": hit.get("stored_at"),
                               "age_seconds": hit.get("age_seconds")}
            return result

    attempt = _request_with_retry(
        "GET", base_url, headers=headers, params=params, timeout=timeout,
        **_session_parts(session, "github_advisories"),
    )
    resp = attempt["response"]
    if resp is None:
        result["outcome"] = attempt["outcome"]
        result["error"] = _safe_text(attempt["error"] or "request failed", MAX_ERROR_CHARS)
        return result

    try:
        status_code = resp.status_code
        if status_code in (401, 403):
            remaining = _ci_get(getattr(resp, "headers", {}) or {}, "X-RateLimit-Remaining")
            if remaining == "0":
                result["status"] = "rate_limited"
                result["outcome"] = OUTCOME_RATE_LIMITED
                result["error"] = "GitHub Advisories API rate limit exceeded"
                result["retry_after"] = attempt.get("retry_after")
            else:
                result["outcome"] = OUTCOME_UNAVAILABLE
                result["error"] = f"GitHub Advisories API returned HTTP {status_code} (check token/auth)"
            return result
        if status_code >= 500:
            result["outcome"] = OUTCOME_UNAVAILABLE
            result["error"] = f"GitHub Advisories API returned HTTP {status_code}"
            return result
        if status_code != 200:
            result["outcome"] = OUTCOME_UNAVAILABLE
            result["error"] = f"GitHub Advisories API returned unexpected HTTP {status_code}"
            return result
        data, decode_error = _decode_json_body(resp, MAX_RESPONSE_BYTES)
    finally:
        try:
            resp.close()
        except Exception:
            pass

    if decode_error is not None:
        result["outcome"] = OUTCOME_MALFORMED
        result["error"] = f"malformed JSON from GitHub Advisories API: {_safe_text(decode_error, MAX_ERROR_CHARS)}"
        return result
    if not isinstance(data, list):
        result["outcome"] = OUTCOME_MALFORMED
        result["error"] = "unexpected GitHub Advisories API response structure"
        return result

    if len(data) > MAX_RECORDS_PER_SOURCE:
        result["truncated"] = True
        result["notes"].append(
            f"GitHub returned {len(data)} advisories; the first {MAX_RECORDS_PER_SOURCE} were assessed")
        data = data[:MAX_RECORDS_PER_SOURCE]

    vulns: List[Dict[str, Any]] = []
    skipped_no_cve = 0
    for advisory in data:
        try:
            advisory = _as_dict(advisory)
            cve_id_raw = advisory.get("cve_id")
            if not isinstance(cve_id_raw, str) or not _CVE_ID_RE.match(cve_id_raw.strip()):
                skipped_no_cve += 1
                continue
            cve_id = cve_id_raw.strip()
            ghsa_id = advisory.get("ghsa_id")
            ghsa_id = _safe_identifier(ghsa_id) if isinstance(ghsa_id, str) else None

            detail = _ghsa_package_detail(advisory, technology, version)
            cvss = _as_dict(advisory.get("cvss"))
            raw_refs = [_safe_reference(r) for r in _as_list(advisory.get("references"))]
            html_url = advisory.get("html_url")
            if isinstance(html_url, str):
                safe_html = _safe_reference(html_url)
                if safe_html and safe_html not in raw_refs:
                    raw_refs.append(safe_html)
            references, refs_truncated = _bound_list([r for r in raw_refs if r], MAX_REFERENCES_PER_CVE)

            record = _blank_record(cve_id, "github_advisories")
            record.update({
                "summary": _safe_text(advisory.get("summary"), MAX_SUMMARY_CHARS)
                           if isinstance(advisory.get("summary"), str) else None,
                "severity": _safe_identifier(advisory.get("severity")) if isinstance(advisory.get("severity"), str) else None,
                "cvss_score": _as_float(cvss.get("score")),
                "cvss_vector": _safe_text(cvss.get("vector_string"), 256)
                               if isinstance(cvss.get("vector_string"), str) else None,
                "published": _safe_identifier(advisory.get("published_at"), 64)
                             if isinstance(advisory.get("published_at"), str) else None,
                "references": references,
                "references_truncated": refs_truncated,
                "version_match": detail["version_match"],
                "match_quality": MATCH_QUALITY_PACKAGE if detail["package"] else MATCH_QUALITY_KEYWORD,
                "mapping_method": "ghsa_affects_search_plus_version_range",
                "advisory_ids": [ghsa_id] if ghsa_id else [],
                "package": detail["package"],
                "ecosystem": detail["ecosystem"],
                "fixed_versions": detail["fixed_versions"][:MAX_FIXED_VERSIONS],
                "affected_ranges": detail["ranges"],
                "notes": _bound_notes(detail["notes"], 4),
                "raw_evidence": _safe_text(
                    f"GitHub Security Advisory {ghsa_id} (affects={technology!r}) maps to {cve_id}"
                    + (f"; affected package {detail['package']!r} in {detail['ecosystem']!r}"
                       if detail["package"] else "; no affected package matched the observed name exactly"),
                    MAX_EVIDENCE_CHARS),
            })
            if record["cvss_score"] is not None or record["cvss_vector"]:
                record["cvss_metrics"] = [{
                    "family": "ghsa", "type": None, "source": "github_advisories",
                    "score": record["cvss_score"], "severity": record["severity"],
                    "vector": record["cvss_vector"],
                }]
            vulns.append(record)
        except Exception:
            continue

    result["vulnerabilities"] = vulns
    result["skipped_no_cve_advisories"] = skipped_no_cve
    result["notes"] = _bound_notes(result["notes"])
    result["status"] = "found" if vulns else "not_found"
    result["outcome"] = OUTCOME_FOUND if vulns else OUTCOME_EMPTY_AUTHORITATIVE
    if cache is not None:
        cache.put(cache_key, result["outcome"], {
            "vulnerabilities": vulns, "skipped_no_cve_advisories": skipped_no_cve,
            "notes": result["notes"], "truncated": result["truncated"],
        })
        result["cache"] = {"hit": False}
    return result


# ---------------------------------------------------------------------------
# FIRST EPSS (Exploit Prediction Scoring System)
#
# EPSS is a probability, in [0, 1], that a CVE will be exploited in the wild in
# the next 30 days. It is an exploitation-LIKELIHOOD signal about the CVE, not
# evidence that this target is exploitable or has been exploited, and it is
# annotated as such everywhere it surfaces.
#
# 0.0 is a legitimate score, so "unavailable" is represented as a null score
# with a reason, never as zero.
# ---------------------------------------------------------------------------

def query_epss(
    cve_ids: Sequence[str],
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = EPSS_API_BASE,
    session: Optional[ProviderSession] = None,
    batch_size: int = EPSS_BATCH_SIZE,
) -> Dict[str, Any]:
    """
    Fetch EPSS scores for a set of CVE IDs, batched.

    Returns {"status", "outcome", "scores": {cve_id: {...}}, "error", "notes",
    "requested", "returned"}. A CVE the API has no score for is simply absent
    from `scores` — which the annotator renders as "checked, no score
    published", distinct from "not checked".
    """
    result: Dict[str, Any] = {
        "status": "error", "outcome": OUTCOME_UNAVAILABLE, "scores": {},
        "error": None, "notes": [], "requested": 0, "returned": 0, "cache": None,
    }
    wanted: List[str] = []
    seen = set()
    for cve in cve_ids or []:
        if isinstance(cve, str) and _CVE_ID_RE.match(cve.strip()) and cve.strip() not in seen:
            seen.add(cve.strip())
            wanted.append(cve.strip())
    result["requested"] = len(wanted)
    if not wanted:
        result["status"] = "skipped"
        result["outcome"] = OUTCOME_SKIPPED
        result["error"] = "no CVE identifiers to score"
        return result

    batch_size = max(1, min(int(batch_size or EPSS_BATCH_SIZE), EPSS_BATCH_SIZE))
    batches = [wanted[i:i + batch_size] for i in range(0, len(wanted), batch_size)][:EPSS_MAX_BATCHES]
    if len(batches) * batch_size < len(wanted):
        result["notes"].append(
            f"EPSS lookup capped at {EPSS_MAX_BATCHES} batches; "
            f"{len(wanted) - len(batches) * batch_size} CVE(s) were not scored")

    scores: Dict[str, Dict[str, Any]] = {}
    any_success = False
    last_error: Optional[str] = None
    last_outcome = OUTCOME_UNAVAILABLE
    unchecked: List[str] = []

    for batch in batches:
        attempt = _request_with_retry(
            "GET", base_url, headers={"User-Agent": DEFAULT_USER_AGENT},
            params={"cve": ",".join(batch), "limit": len(batch)},
            timeout=timeout, **_session_parts(session, "epss"),
        )
        resp = attempt["response"]
        if resp is None:
            last_error = _safe_text(attempt["error"] or "request failed", MAX_ERROR_CHARS)
            last_outcome = attempt["outcome"]
            unchecked.extend(batch)
            continue
        try:
            status_code = resp.status_code
            if status_code == 429:
                last_error, last_outcome = "HTTP 429 from EPSS API", OUTCOME_RATE_LIMITED
                unchecked.extend(batch)
                continue
            if status_code != 200:
                last_error = f"EPSS API returned HTTP {status_code}"
                last_outcome = OUTCOME_UNAVAILABLE
                unchecked.extend(batch)
                continue
            data, decode_error = _decode_json_body(resp, MAX_RESPONSE_BYTES)
        finally:
            try:
                resp.close()
            except Exception:
                pass
        if decode_error is not None:
            last_error = f"malformed JSON from EPSS API: {_safe_text(decode_error, MAX_ERROR_CHARS)}"
            last_outcome = OUTCOME_MALFORMED
            unchecked.extend(batch)
            continue
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            last_error, last_outcome = "unexpected EPSS API response structure", OUTCOME_MALFORMED
            unchecked.extend(batch)
            continue

        any_success = True
        for row in _as_list(data.get("data"))[: batch_size * 2]:
            row = _as_dict(row)
            cve = row.get("cve")
            if not isinstance(cve, str) or not _CVE_ID_RE.match(cve.strip()):
                continue
            epss = _as_float(row.get("epss"))
            percentile = _as_float(row.get("percentile"))
            if epss is not None and not (0.0 <= epss <= 1.0):
                # A provider-supplied probability outside [0,1] is malformed,
                # not a very dangerous CVE.
                epss = None
            if percentile is not None and not (0.0 <= percentile <= 1.0):
                percentile = None
            scores[cve.strip()] = {
                "epss": epss,
                "percentile": percentile,
                "date": _safe_identifier(row.get("date"), 32) if isinstance(row.get("date"), str) else None,
            }

    result["returned"] = len(scores)
    # Per-CVE three-state: a CVE whose batch failed was NOT CHECKED. Without
    # this sentinel it would read as "checked, no score published" — the same
    # collapse of outage-into-negative this module forbids everywhere else.
    for cve in unchecked:
        if cve not in scores:
            scores[cve] = {"epss": None, "percentile": None, "date": None,
                           "unchecked": True, "reason": last_error or "EPSS batch failed"}
    result["scores"] = scores
    result["unchecked"] = sorted(set(unchecked))
    if any_success:
        result["status"] = "found" if result["returned"] else "not_found"
        result["outcome"] = OUTCOME_FOUND if result["returned"] else OUTCOME_EMPTY_AUTHORITATIVE
        if last_error:
            result["notes"].append(
                f"one or more EPSS batches failed ({last_error}); {len(result['unchecked'])} CVE(s) were "
                f"not scored and are marked not-checked, not unscored")
    else:
        result["status"] = "rate_limited" if last_outcome == OUTCOME_RATE_LIMITED else "error"
        result["outcome"] = last_outcome
        result["error"] = last_error or "EPSS API unavailable"
    result["notes"] = _bound_notes(result["notes"])
    return result


# ---------------------------------------------------------------------------
# CISA Known Exploited Vulnerabilities (KEV) catalog
# ---------------------------------------------------------------------------

def query_cisa_kev(
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = CISA_KEV_URL,
    session: Optional[ProviderSession] = None,
) -> Dict[str, Any]:
    """Fetch and normalize the full CISA KEV catalog. Intended to be fetched once per run and shared (see run_vuln_intel)."""
    result: Dict[str, Any] = {
        "status": "error", "outcome": OUTCOME_UNAVAILABLE, "entries": [],
        "error": None, "notes": [], "truncated": False, "catalog_version": None,
        "date_released": None, "cache": None,
    }

    cache = session.feed_cache if session else None
    cache_key = ProviderCache.key("cisa_kev", base_url)
    if cache is not None:
        hit = cache.get(cache_key)
        if hit is not None:
            payload = _as_dict(hit.get("payload"))
            result["entries"] = [e for e in _as_list(payload.get("entries"))
                                 if isinstance(e, dict) and isinstance(e.get("cve_id"), str)]
            result["catalog_version"] = _safe_identifier(payload.get("catalog_version"), 32) \
                if isinstance(payload.get("catalog_version"), str) else None
            result["date_released"] = _safe_identifier(payload.get("date_released"), 64) \
                if isinstance(payload.get("date_released"), str) else None
            result["truncated"] = bool(payload.get("truncated"))
            result["status"] = "found" if result["entries"] else "not_found"
            result["outcome"] = OUTCOME_FOUND if result["entries"] else OUTCOME_EMPTY_AUTHORITATIVE
            result["cache"] = {"hit": True, "stored_at": hit.get("stored_at"),
                               "age_seconds": hit.get("age_seconds")}
            return result

    attempt = _request_with_retry(
        "GET", base_url, headers={"User-Agent": DEFAULT_USER_AGENT}, timeout=timeout,
        **_session_parts(session, "cisa_kev"),
    )
    resp = attempt["response"]
    if resp is None:
        result["outcome"] = attempt["outcome"]
        result["error"] = _safe_text(attempt["error"] or "request failed", MAX_ERROR_CHARS)
        return result

    try:
        status_code = resp.status_code
        if status_code == 429:
            result["status"], result["outcome"] = "rate_limited", OUTCOME_RATE_LIMITED
            result["error"] = "HTTP 429 from CISA KEV feed"
            return result
        if status_code != 200:
            result["outcome"] = OUTCOME_UNAVAILABLE
            result["error"] = f"CISA KEV feed returned HTTP {status_code}"
            return result
        data, decode_error = _decode_json_body(resp, MAX_KEV_RESPONSE_BYTES)
    finally:
        try:
            resp.close()
        except Exception:
            pass

    if decode_error is not None:
        result["outcome"] = OUTCOME_MALFORMED
        result["error"] = f"malformed JSON from CISA KEV feed: {_safe_text(decode_error, MAX_ERROR_CHARS)}"
        return result
    if not isinstance(data, dict) or "vulnerabilities" not in data:
        result["outcome"] = OUTCOME_MALFORMED
        result["error"] = "unexpected CISA KEV feed structure"
        return result

    entries: List[Dict[str, Any]] = []
    seen: set = set()
    raw_entries = _as_list(data.get("vulnerabilities"))
    for item in raw_entries:
        if len(entries) >= MAX_KEV_ENTRIES:
            result["truncated"] = True
            break
        item = _as_dict(item)
        cve_id = item.get("cveID")
        if not isinstance(cve_id, str) or not _CVE_ID_RE.match(cve_id.strip()):
            continue
        cve_id = cve_id.strip()
        if cve_id in seen:
            continue  # the catalog has carried duplicate cveIDs before
        seen.add(cve_id)
        entries.append({
            "cve_id": cve_id,
            "vendor_project": _safe_identifier(item.get("vendorProject"), 128),
            "product": _safe_identifier(item.get("product"), 128),
            "vulnerability_name": _safe_text(item.get("vulnerabilityName"), 256)
                                   if isinstance(item.get("vulnerabilityName"), str) else None,
            "date_added": _safe_identifier(item.get("dateAdded"), 32)
                          if isinstance(item.get("dateAdded"), str) else None,
            "due_date": _safe_identifier(item.get("dueDate"), 32)
                        if isinstance(item.get("dueDate"), str) else None,
            "known_ransomware_campaign_use": _safe_identifier(item.get("knownRansomwareCampaignUse"), 32)
                                             if isinstance(item.get("knownRansomwareCampaignUse"), str) else None,
        })

    result["entries"] = entries
    result["catalog_version"] = _safe_identifier(data.get("catalogVersion"), 32) \
        if isinstance(data.get("catalogVersion"), str) else None
    result["date_released"] = _safe_identifier(data.get("dateReleased"), 64) \
        if isinstance(data.get("dateReleased"), str) else None
    if result["truncated"]:
        result["notes"].append(
            f"KEV catalog truncated at {MAX_KEV_ENTRIES} entries out of {len(raw_entries)} reported")
    result["notes"] = _bound_notes(result["notes"])
    result["status"] = "found" if entries else "not_found"
    result["outcome"] = OUTCOME_FOUND if entries else OUTCOME_EMPTY_AUTHORITATIVE
    if cache is not None:
        cache.put(cache_key, result["outcome"], {
            "entries": entries, "catalog_version": result["catalog_version"],
            "date_released": result["date_released"], "truncated": result["truncated"],
        })
        result["cache"] = {"hit": False}
    return result


class KevCatalog:
    """
    An indexed KEV catalog that knows whether it was actually retrieved.

    The three-state distinction is the point: an empty list can mean "the CVE
    is not on the catalog" or "the feed was down", and collapsing those two
    turned a KEV outage into a silent, invisible downgrade of every finding.
    """

    __slots__ = ("_index", "available", "reason", "catalog_version", "date_released", "entry_count")

    def __init__(self, entries: Optional[Iterable[Dict[str, Any]]] = None, available: bool = True,
                 reason: Optional[str] = None, catalog_version: Optional[str] = None,
                 date_released: Optional[str] = None):
        self._index: Dict[str, Dict[str, Any]] = {}
        for entry in entries or []:
            if isinstance(entry, dict) and isinstance(entry.get("cve_id"), str):
                self._index.setdefault(entry["cve_id"], entry)
        self.available = bool(available)
        self.reason = reason
        self.catalog_version = catalog_version
        self.date_released = date_released
        self.entry_count = len(self._index)

    @classmethod
    def from_result(cls, result: Dict[str, Any]) -> "KevCatalog":
        conclusive = _result_conclusive(result)
        return cls(
            entries=result.get("entries") or [],
            available=conclusive,
            reason=None if conclusive else _safe_text(result.get("error") or "KEV feed unavailable", MAX_ERROR_CHARS),
            catalog_version=result.get("catalog_version"),
            date_released=result.get("date_released"),
        )

    @classmethod
    def unavailable(cls, reason: str) -> "KevCatalog":
        return cls(entries=[], available=False, reason=_safe_text(reason, MAX_ERROR_CHARS))

    @classmethod
    def coerce(cls, value: Any) -> "KevCatalog":
        """Accept a KevCatalog, a plain entry list (legacy callers/tests), or None."""
        if isinstance(value, KevCatalog):
            return value
        if value is None:
            return cls.unavailable("KEV catalog was not supplied")
        if isinstance(value, (list, tuple)):
            # A caller-supplied list is, by construction, a retrieved catalog.
            return cls(entries=list(value), available=True)
        return cls.unavailable("KEV catalog value was not usable")

    def lookup(self, cve_id: str) -> Optional[Dict[str, Any]]:
        return self._index.get(cve_id)

    def entries(self) -> List[Dict[str, Any]]:
        return list(self._index.values())


def _kev_lookup(kev_entries: Any, cve_id: str) -> Optional[Dict[str, Any]]:
    """Legacy helper: look one CVE up in a KEV entry list or a KevCatalog."""
    if isinstance(kev_entries, KevCatalog):
        return kev_entries.lookup(cve_id)
    for entry in _as_list(kev_entries):
        if isinstance(entry, dict) and entry.get("cve_id") == cve_id:
            return entry
    return None


# ---------------------------------------------------------------------------
# Exploit-DB (public CSV index — see module docstring's per-source limitations)
# ---------------------------------------------------------------------------

class ExploitDbIndex:
    """A CVE -> Exploit-DB entries index that knows whether it was retrieved (same three-state rule as KevCatalog)."""

    __slots__ = ("_index", "available", "reason", "entry_count", "truncated")

    def __init__(self, index: Optional[Dict[str, List[Dict[str, Any]]]] = None, available: bool = True,
                 reason: Optional[str] = None, truncated: bool = False):
        self._index = index or {}
        self.available = bool(available)
        self.reason = reason
        self.truncated = bool(truncated)
        self.entry_count = len(self._index)

    @classmethod
    def from_result(cls, result: Dict[str, Any]) -> "ExploitDbIndex":
        conclusive = _result_conclusive(result)
        return cls(
            index=result.get("index") or {},
            available=conclusive,
            reason=None if conclusive else _safe_text(result.get("error") or "Exploit-DB index unavailable", MAX_ERROR_CHARS),
            truncated=bool(result.get("truncated")),
        )

    @classmethod
    def unavailable(cls, reason: str) -> "ExploitDbIndex":
        return cls(index={}, available=False, reason=_safe_text(reason, MAX_ERROR_CHARS))

    @classmethod
    def coerce(cls, value: Any) -> "ExploitDbIndex":
        if isinstance(value, ExploitDbIndex):
            return value
        if value is None:
            return cls.unavailable("Exploit-DB index was not supplied")
        if isinstance(value, dict):
            return cls(index=value, available=True)
        return cls.unavailable("Exploit-DB index value was not usable")

    def lookup(self, cve_id: str) -> List[Dict[str, Any]]:
        return list(self._index.get(cve_id) or [])

    def as_dict(self) -> Dict[str, List[Dict[str, Any]]]:
        return dict(self._index)


def fetch_exploitdb_index(
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = EXPLOITDB_CSV_URL,
    preloaded_csv_text: Optional[str] = None,
    session: Optional[ProviderSession] = None,
) -> Dict[str, Any]:
    """
    Fetch (or accept pre-fetched, for tests/offline use) Exploit-DB's public
    files_exploits.csv index and build a {cve_id: [entry, ...]} lookup table
    from its `codes` column.
    """
    result: Dict[str, Any] = {
        "status": "error", "outcome": OUTCOME_UNAVAILABLE, "index": {},
        "error": None, "notes": [], "truncated": False, "rows": 0, "cache": None,
    }

    text = preloaded_csv_text
    cache = session.feed_cache if (session and preloaded_csv_text is None) else None
    cache_key = ProviderCache.key("exploitdb", base_url)
    if cache is not None:
        hit = cache.get(cache_key)
        if hit is not None:
            payload = _as_dict(hit.get("payload"))
            index = payload.get("index")
            result["index"] = {k: [e for e in _as_list(v) if isinstance(e, dict)]
                               for k, v in index.items()
                               if isinstance(k, str) and _CVE_ID_RE.match(k)} if isinstance(index, dict) else {}
            result["rows"] = int(_as_float(payload.get("rows")) or 0)
            result["truncated"] = bool(payload.get("truncated"))
            result["status"] = "found" if result["index"] else "not_found"
            result["outcome"] = OUTCOME_FOUND if result["index"] else OUTCOME_EMPTY_AUTHORITATIVE
            result["cache"] = {"hit": True, "stored_at": hit.get("stored_at"),
                               "age_seconds": hit.get("age_seconds")}
            return result

    if text is None:
        attempt = _request_with_retry(
            "GET", base_url, headers={"User-Agent": DEFAULT_USER_AGENT}, timeout=timeout,
            **_session_parts(session, "exploitdb"),
        )
        resp = attempt["response"]
        if resp is None:
            result["outcome"] = attempt["outcome"]
            result["error"] = _safe_text(attempt["error"] or "request failed", MAX_ERROR_CHARS)
            return result
        try:
            status_code = resp.status_code
            if status_code == 429:
                result["status"], result["outcome"] = "rate_limited", OUTCOME_RATE_LIMITED
                result["error"] = "HTTP 429 from the Exploit-DB CSV index"
                return result
            if status_code != 200:
                result["outcome"] = OUTCOME_UNAVAILABLE
                result["error"] = f"Exploit-DB CSV index returned HTTP {status_code}"
                return result
            text, decode_error = _decode_text_body(resp, MAX_EXPLOITDB_RESPONSE_BYTES)
        finally:
            try:
                resp.close()
            except Exception:
                pass
        if decode_error is not None or text is None:
            result["outcome"] = OUTCOME_MALFORMED
            result["error"] = f"could not read Exploit-DB CSV index: {_safe_text(decode_error or 'no body', MAX_ERROR_CHARS)}"
            return result

    index: Dict[str, List[Dict[str, Any]]] = {}
    rows_read = 0
    try:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            rows_read += 1
            if rows_read > MAX_EXPLOITDB_ROWS:
                result["truncated"] = True
                break
            if not isinstance(row, dict):
                continue
            codes = row.get("codes")
            if not isinstance(codes, str):
                continue
            cve_ids = []
            for code in codes.split(";")[:MAX_ALIASES]:
                code = code.strip()
                if _CVE_ID_RE.match(code):
                    cve_ids.append(code)
            if not cve_ids:
                continue
            verified_raw = row.get("verified")
            entry = {
                "edb_id": _safe_identifier(row.get("id"), 32),
                "title": _safe_text(row.get("description"), 256) if isinstance(row.get("description"), str) else None,
                "date_published": _safe_identifier(row.get("date_published"), 32)
                                  if isinstance(row.get("date_published"), str) else None,
                # Three-state: the column being absent is "unknown", not "unverified".
                "verified": (verified_raw == "1") if isinstance(verified_raw, str) and verified_raw.strip() else None,
            }
            for cve_id in cve_ids:
                bucket = index.setdefault(cve_id, [])
                if len(bucket) < MAX_EXPLOITDB_ENTRIES_PER_CVE:
                    bucket.append(entry)
                else:
                    result["truncated"] = True
            if len(index) >= MAX_EXPLOITDB_INDEX_CVES:
                result["truncated"] = True
                break
    except Exception as exc:
        result["outcome"] = OUTCOME_MALFORMED
        result["error"] = f"malformed Exploit-DB CSV index: {_safe_text(str(exc), MAX_ERROR_CHARS)}"
        return result

    result["index"] = index
    result["rows"] = rows_read
    if result["truncated"]:
        result["notes"].append(
            f"Exploit-DB index truncated at {MAX_EXPLOITDB_ROWS} rows / "
            f"{MAX_EXPLOITDB_INDEX_CVES} CVEs; the lookup table is partial")
    result["notes"] = _bound_notes(result["notes"])
    result["status"] = "found" if index else "not_found"
    result["outcome"] = OUTCOME_FOUND if index else OUTCOME_EMPTY_AUTHORITATIVE
    if cache is not None:
        cache.put(cache_key, result["outcome"],
                  {"index": index, "rows": rows_read, "truncated": result["truncated"]})
        result["cache"] = {"hit": False}
    return result


# ---------------------------------------------------------------------------
# Multi-source aggregation
# ---------------------------------------------------------------------------

def query_all_sources(
    technology: str,
    version: Optional[str] = None,
    sources: Optional[List[str]] = None,
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
    osv_ecosystem: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    session: Optional[ProviderSession] = None,
) -> Dict[str, Any]:
    """
    Query every configured CVE-intelligence source for one technology + version
    pair. One source failing/erroring never prevents the others from being
    queried (context.md: "One unavailable intelligence source should not
    unnecessarily prevent other available sources from being processed").

    `source_status` carries each source's legacy `status` PLUS its precise
    `outcome` and a `conclusive` flag. The conclusive flag is what the
    negative-result logic reads: a rate-limited or unreachable source can never
    contribute to a "checked and nothing found" conclusion.
    """
    sources = list(sources) if sources is not None else list(DEFAULT_SOURCES)
    invalid = [s for s in sources if s not in _VALID_SOURCES]
    if invalid:
        raise ConfigurationError(f"Unsupported source(s) {invalid}; must be a subset of {sorted(_VALID_SOURCES)}")

    all_records: List[Dict[str, Any]] = []
    source_status: Dict[str, Dict[str, Any]] = {}
    truncated_any = False
    notes: List[str] = []

    def _run(name: str, fn) -> None:
        nonlocal truncated_any
        try:
            r = fn()
        except Exception as exc:
            r = {"status": "error", "outcome": OUTCOME_UNAVAILABLE, "vulnerabilities": [],
                 "error": f"{type(exc).__name__}: {_safe_text(str(exc), MAX_ERROR_CHARS)}"}
        outcome = r.get("outcome")
        if outcome not in (OUTCOME_FOUND, OUTCOME_EMPTY_AUTHORITATIVE, OUTCOME_UNAVAILABLE,
                           OUTCOME_RATE_LIMITED, OUTCOME_MALFORMED, OUTCOME_SKIPPED,
                           OUTCOME_NOT_CHECKED, OUTCOME_INVALID_REQUEST):
            # A provider that somehow reported an unknown outcome is treated as
            # inconclusive, never as an authoritative empty answer.
            outcome = OUTCOME_UNAVAILABLE
        source_status[name] = {
            "status": r.get("status"),
            "outcome": outcome,
            "conclusive": outcome in _CONCLUSIVE_OUTCOMES,
            "error": _safe_text(r.get("error"), MAX_ERROR_CHARS) if r.get("error") else None,
            "truncated": bool(r.get("truncated")),
            "retry_after": r.get("retry_after"),
            "cache": r.get("cache"),
            "notes": _as_list(r.get("notes"))[:4],
        }
        for extra in ("skipped_non_cve_advisories", "skipped_no_cve_advisories", "total_results", "retrieved"):
            if extra in r:
                source_status[name][extra] = r[extra]
        if r.get("truncated"):
            truncated_any = True
            notes.append(f"{name} returned a truncated result set")
        records = _as_list(r.get("vulnerabilities"))[:MAX_RECORDS_PER_SOURCE]
        all_records.extend(records)

    if "nvd" in sources:
        _run("nvd", lambda: query_nvd(technology, version, api_key=nvd_api_key,
                                      timeout=timeout, session=session))
    if "osv" in sources:
        _run("osv", lambda: query_osv(technology, version, ecosystem=osv_ecosystem,
                                      timeout=timeout, session=session))
    if "github_advisories" in sources:
        _run("github_advisories", lambda: query_github_advisories(
            technology, version=version, ecosystem=osv_ecosystem, token=github_token,
            timeout=timeout, session=session))

    return {"records": all_records, "source_status": source_status,
            "truncated": truncated_any, "notes": _bound_notes(notes)}


def _sources_conclusive(source_status: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decide whether "no CVE was found" is a conclusion this run is entitled to.

    Annotation sources (KEV/Exploit-DB/EPSS) are excluded outright: they never
    discover a CVE, and letting a healthy KEV feed vote made a rate-limited NVD
    look like a clean result — reproduced against the previous implementation,
    which persisted `vuln_intel_checked_no_match` while NVD had returned 429.
    """
    discovery = {name: info for name, info in (source_status or {}).items()
                 if name not in _ANNOTATION_SOURCES}
    conclusive, inconclusive = [], []
    for name, info in sorted(discovery.items()):
        info = _as_dict(info)
        if info.get("conclusive") is True or _result_conclusive(info):
            conclusive.append(name)
        else:
            inconclusive.append(name)
    return {
        "queried": sorted(discovery),
        "conclusive_sources": conclusive,
        "inconclusive_sources": inconclusive,
        # Every source that ran reached a conclusive answer, and at least one ran.
        "all_conclusive": bool(conclusive) and not inconclusive,
        "any_conclusive": bool(conclusive),
        "none_usable": bool(discovery) and not conclusive,
    }


def _merge_vulnerability_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Merge per-source normalized vuln records by CVE ID, preserving each source's
    own evidence/version-match/CVSS data separately rather than silently picking
    one (context.md §8 conflict-preservation: sources disagreeing on severity or
    on whether the version even applies is itself worth keeping visible).

    Every collection is bounded, and every provider-controlled value is coerced
    to a type this function can actually handle. Both matter: a GHSA advisory
    whose `references` were objects rather than strings raised
    `TypeError: unhashable type: 'dict'` out of this function and killed the
    entire run, and a `published` value of a different type than another
    source's raised `'<' not supported between instances of 'int' and 'str'`.
    """
    merged: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    truncated_cves = False

    for rec in _as_list(records):
        rec = _as_dict(rec)
        cve_id = rec.get("cve_id")
        if not isinstance(cve_id, str) or not _CVE_ID_RE.match(cve_id.strip()):
            continue
        cve_id = cve_id.strip()
        if cve_id not in merged:
            if len(merged) >= MAX_CVES_PER_OBSERVATION:
                truncated_cves = True
                continue
            merged[cve_id] = {
                "cve_id": cve_id,
                "summaries": [],
                "cvss": [],
                "references": [],
                "sources": [],
                "published": None,
                "cisa_kev": None,
                "exploitdb_references": [],
                "advisory_ids": [],
                "packages": [],
                "ecosystems": [],
                "fixed_versions": [],
                "affected_ranges": [],
                "matched_cpe_products": [],
                "provider_notes": [],
                "truncated_fields": [],
            }
            order.append(cve_id)
        m = merged[cve_id]

        summary = rec.get("summary")
        if isinstance(summary, str) and summary.strip():
            clean = _safe_text(summary, MAX_SUMMARY_CHARS)
            if clean not in m["summaries"]:
                if len(m["summaries"]) < MAX_SUMMARIES_PER_CVE:
                    m["summaries"].append(clean)
                elif "summaries" not in m["truncated_fields"]:
                    m["truncated_fields"].append("summaries")

        score = _as_float(rec.get("cvss_score"))
        vector = rec.get("cvss_vector")
        vector = _safe_text(vector, 256) if isinstance(vector, str) else None
        if score is not None or vector:
            if len(m["cvss"]) < MAX_CVSS_ENTRIES:
                m["cvss"].append({
                    "source": _safe_identifier(rec.get("source")),
                    "score": score,
                    "severity": _safe_identifier(rec.get("severity")) if isinstance(rec.get("severity"), str) else None,
                    "vector": vector,
                    "attack_metadata": _cvss_vector_metrics(vector),
                })
            elif "cvss" not in m["truncated_fields"]:
                m["truncated_fields"].append("cvss")

        for ref in _as_list(rec.get("references")):
            clean_ref = _safe_reference(ref) if isinstance(ref, str) else None
            if clean_ref is None and ref is not None and not isinstance(ref, str):
                # A provider that returned an object where a URL belonged: keep
                # a bounded rendering rather than crashing or dropping it.
                clean_ref = _safe_reference(json.dumps(_jsonify(ref), sort_keys=True)[:MAX_REFERENCE_CHARS])
            if not clean_ref or clean_ref in m["references"]:
                continue
            if len(m["references"]) < MAX_REFERENCES_PER_CVE:
                m["references"].append(clean_ref)
            elif "references" not in m["truncated_fields"]:
                m["truncated_fields"].append("references")

        version_match = _safe_identifier(rec.get("version_match")) or "unknown"
        quality = _safe_identifier(rec.get("match_quality"))
        if not quality:
            # A record from a caller/provider adapter that predates
            # `match_quality`. Its own range_confirmed claim is taken at face
            # value (exactly as it was before the field existed); anything else
            # is a bare name match.
            quality = MATCH_QUALITY_EXACT if version_match == "range_confirmed" else MATCH_QUALITY_KEYWORD
        if len(m["sources"]) < MAX_SOURCES_PER_CVE:
            m["sources"].append({
                "source": _safe_identifier(rec.get("source")),
                "version_match": version_match,
                "match_quality": quality,
                "mapping_method": _safe_identifier(rec.get("mapping_method"), 96),
                "package": _safe_identifier(rec.get("package"), MAX_TECHNOLOGY_CHARS),
                "ecosystem": _safe_identifier(rec.get("ecosystem"), MAX_ECOSYSTEM_CHARS),
                "evidence": _safe_text(rec.get("raw_evidence"), MAX_EVIDENCE_CHARS)
                            if isinstance(rec.get("raw_evidence"), str) else None,
                "truncated_references": bool(rec.get("references_truncated")),
            })
        elif "sources" not in m["truncated_fields"]:
            m["truncated_fields"].append("sources")

        for key, dest, limit in (("advisory_ids", "advisory_ids", MAX_ADVISORY_IDS),
                                 ("fixed_versions", "fixed_versions", MAX_FIXED_VERSIONS),
                                 ("matched_cpe_products", "matched_cpe_products", MAX_ADVISORY_IDS)):
            for value in _as_list(rec.get(key)):
                clean = _safe_identifier(value, MAX_VERSION_CHARS) if value is not None else None
                if clean and clean not in m[dest] and len(m[dest]) < limit:
                    m[dest].append(clean)
        for key in ("package", "ecosystem"):
            value = _safe_identifier(rec.get(key), MAX_TECHNOLOGY_CHARS)
            dest = "packages" if key == "package" else "ecosystems"
            if value and value not in m[dest] and len(m[dest]) < 6:
                m[dest].append(value)
        for rng in _as_list(rec.get("affected_ranges")):
            if len(m["affected_ranges"]) >= MAX_AFFECTED_RANGES:
                if "affected_ranges" not in m["truncated_fields"]:
                    m["truncated_fields"].append("affected_ranges")
                break
            entry = {"source": _safe_identifier(rec.get("source")), **_as_dict(_jsonify(rng))}
            if entry not in m["affected_ranges"]:
                m["affected_ranges"].append(entry)
        for note in _as_list(rec.get("notes"))[:4]:
            clean = _safe_text(note, MAX_NOTE_CHARS) if isinstance(note, str) else None
            if clean and clean not in m["provider_notes"] and len(m["provider_notes"]) < MAX_NOTES:
                m["provider_notes"].append(clean)

        published = rec.get("published")
        if isinstance(published, str) and published.strip():
            published = _safe_identifier(published, 64)
            # Compare like with like: providers publish differently-typed and
            # differently-formatted timestamps, and a raw `<` across them raised.
            if m["published"] is None or str(published) < str(m["published"]):
                m["published"] = published

    results = []
    for cve_id in order:
        m = merged[cve_id]
        m["references"] = sorted(m["references"])
        m["source_count"] = len({s.get("source") for s in m["sources"] if s.get("source")})
        results.append(m)
    if truncated_cves and results:
        results[0]["truncated_fields"].append("merged_cve_set")
    return results


# ---------------------------------------------------------------------------
# Annotation (KEV / Exploit-DB / EPSS)
#
# All three keep the SAME downstream contract they always had — `cisa_kev` is
# None unless the CVE is listed, `exploitdb_references` is a list — because
# risk_engine.py reads their truthiness as an escalation factor. The
# checked-vs-unknown distinction is carried in ADDITIVE `*_status` objects, so
# nothing downstream changes meaning and nothing is silently lost.
# ---------------------------------------------------------------------------

_KEV_NOTE = (
    "Listed in CISA's Known Exploited Vulnerabilities catalog — real-world "
    "exploitation evidence exists for this CVE against some target, but this "
    "does NOT confirm exploitability against the specific asset observed here."
)


def annotate_kev(record: Dict[str, Any], kev_entries: Any) -> Dict[str, Any]:
    """Annotate one merged record with its CISA KEV status."""
    catalog = KevCatalog.coerce(kev_entries)
    if not catalog.available:
        record["cisa_kev"] = None
        record["cisa_kev_status"] = {
            "checked": False, "listed": None,
            "reason": catalog.reason or "CISA KEV catalog was unavailable for this run",
            "note": "Not checked: absence of a KEV annotation here is not evidence of absence from the catalog.",
        }
        return record
    hit = catalog.lookup(record["cve_id"])
    if not hit:
        record["cisa_kev"] = None
        record["cisa_kev_status"] = {
            "checked": True, "listed": False, "reason": None,
            "catalog_version": catalog.catalog_version,
            "note": "Checked against the CISA KEV catalog; this CVE is not listed.",
        }
        return record
    record["cisa_kev"] = {
        "listed": True,
        "date_added": hit.get("date_added"),
        "due_date": hit.get("due_date"),
        "vulnerability_name": hit.get("vulnerability_name"),
        "vendor_project": hit.get("vendor_project"),
        "product": hit.get("product"),
        "known_ransomware_campaign_use": hit.get("known_ransomware_campaign_use"),
        "note": _KEV_NOTE,
    }
    record["cisa_kev_status"] = {
        "checked": True, "listed": True, "reason": None,
        "catalog_version": catalog.catalog_version, "note": _KEV_NOTE,
    }
    return record


def annotate_exploitdb(record: Dict[str, Any], exploitdb_index: Any) -> Dict[str, Any]:
    """Annotate one merged record with public Exploit-DB references."""
    index = ExploitDbIndex.coerce(exploitdb_index)
    if not index.available:
        record["exploitdb_references"] = []
        record["exploitdb_status"] = {
            "checked": False, "count": None,
            "reason": index.reason or "Exploit-DB index was unavailable for this run",
            "note": "Not checked: an empty reference list here is not evidence that no public exploit exists.",
        }
        return record
    hits = index.lookup(record["cve_id"])
    bounded, truncated = _bound_list(hits, MAX_EXPLOITDB_REFERENCES_PER_CVE)
    record["exploitdb_references"] = [
        {"edb_id": h.get("edb_id"), "title": h.get("title"), "verified": h.get("verified"),
         "date_published": h.get("date_published")}
        for h in bounded if isinstance(h, dict)
    ]
    record["exploitdb_status"] = {
        "checked": True, "count": len(hits), "truncated": truncated, "reason": None,
        "note": ("A public proof-of-concept/exploit is catalogued for this CVE. That is not evidence "
                 "that it works against this asset, and not evidence that it was ever used against it."),
    }
    return record


def annotate_epss(record: Dict[str, Any], epss_scores: Any, available: bool = True,
                  reason: Optional[str] = None) -> Dict[str, Any]:
    """
    Annotate one merged record with its EPSS score.

    Three states, never collapsed: not checked (provider unavailable), checked
    with no published score, and checked with a score. 0.0 is a real score, so
    it is never used to mean "unknown".
    """
    if not available or not isinstance(epss_scores, dict):
        record["epss"] = {
            "checked": False, "score": None, "percentile": None, "date": None,
            "reason": _safe_text(reason or "EPSS data was unavailable for this run", MAX_ERROR_CHARS),
            "note": "Not checked. EPSS is an exploitation-likelihood estimate for the CVE, never target evidence.",
        }
        return record
    entry = _as_dict(epss_scores.get(record["cve_id"]))
    if entry.get("unchecked"):
        record["epss"] = {
            "checked": False, "score": None, "percentile": None, "date": None,
            "reason": _safe_text(entry.get("reason") or "the EPSS batch containing this CVE failed", MAX_ERROR_CHARS),
            "note": "Not checked. EPSS is an exploitation-likelihood estimate for the CVE, never target evidence.",
        }
        return record
    if not entry:
        record["epss"] = {
            "checked": True, "score": None, "percentile": None, "date": None,
            "reason": "no EPSS score is published for this CVE",
            "note": "Checked; FIRST publishes no EPSS score for this CVE.",
        }
        return record
    record["epss"] = {
        "checked": True,
        "score": entry.get("epss"),
        "percentile": entry.get("percentile"),
        "date": entry.get("date"),
        "reason": None,
        "note": ("EPSS estimates the likelihood that this CVE is exploited in the wild in the next 30 days. "
                 "It is a property of the CVE, not evidence about this target."),
    }
    return record


# ---------------------------------------------------------------------------
# Applicability + confidence assessment
# ---------------------------------------------------------------------------

# Match qualities a "range_confirmed" claim may legitimately rest on. A merely
# related product name is deliberately absent: _nvd_cpe_assessment refuses to
# produce range_confirmed from one, and this is the second, independent gate.
_TRUSTED_MATCH_QUALITIES = frozenset({
    MATCH_QUALITY_EXACT, MATCH_QUALITY_ALIAS, MATCH_QUALITY_PACKAGE,
})

APPLICABILITY_RANGE_CONFIRMED = "version_range_confirmed"
APPLICABILITY_KEYWORD = "keyword_match_version_unconfirmed"
APPLICABILITY_UNKNOWN_VERSION = "version_unknown_cannot_confirm"


def _mapping_assessment(record: Dict[str, Any], version: Optional[str] = None) -> Dict[str, Any]:
    """
    Assess one merged CVE record: how it was matched, how far that match can be
    trusted, and what remains unknown.

    Returns {applicability, mapping_confidence, source_confidence,
    match_quality, backport_uncertainty, notes, disagreement}.

    The two confidence dimensions returned here are ABOUT THE MAPPING ONLY.
    They are combined with the technology observation's own confidence by the
    caller, and the result can never exceed the lower of the two — a
    LOW-confidence banner guess stays LOW no matter how exact NVD's CPE looks.
    """
    sources = [_as_dict(s) for s in _as_list(record.get("sources"))]
    matches = [s.get("version_match") or "unknown" for s in sources]
    qualities = [s.get("match_quality") or MATCH_QUALITY_KEYWORD for s in sources]
    distinct_sources = {s.get("source") for s in sources if s.get("source")}
    notes: List[str] = []

    best_quality = MATCH_QUALITY_KEYWORD
    for quality in qualities:
        if _MATCH_QUALITY_RANK.get(quality, 0) > _MATCH_QUALITY_RANK.get(best_quality, 0):
            best_quality = quality

    # A range_confirmed claim only counts when the source that made it also
    # identified the product precisely.
    confirmed_qualities = [
        (s.get("match_quality") or MATCH_QUALITY_EXACT)
        for s in sources if (s.get("version_match") or "unknown") == "range_confirmed"
    ]
    trusted_confirmation = any(q in _TRUSTED_MATCH_QUALITIES for q in confirmed_qualities)

    disagreement = len(set(matches)) > 1

    if trusted_confirmation:
        applicability = APPLICABILITY_RANGE_CONFIRMED
        mapping_confidence = CONFIDENCE_HIGH
    elif confirmed_qualities:
        # A confirmation that rested only on a related product name.
        applicability = APPLICABILITY_KEYWORD
        mapping_confidence = CONFIDENCE_LOW
        notes.append(
            "a source reported a version-range match, but only against a related product name, "
            "not the observed product; treated as an unconfirmed name match")
    elif matches and all(m == "unknown" for m in matches):
        applicability = APPLICABILITY_UNKNOWN_VERSION
        mapping_confidence = CONFIDENCE_LOW
    else:
        applicability = APPLICABILITY_KEYWORD
        # context.md §8's converging-signal rule: independent sources agreeing
        # raise a name-only match from LOW to MEDIUM, and no further.
        mapping_confidence = CONFIDENCE_MEDIUM if len(distinct_sources) >= 2 else CONFIDENCE_LOW

    if applicability == APPLICABILITY_RANGE_CONFIRMED:
        # The advisory source's OWN applicability data (NVD CPE range, OSV
        # version filter, GHSA range) is authoritative for that CVE. One such
        # statement is stronger evidence than any number of sources agreeing
        # that a name appeared in a description; the converging-signal rule
        # (context.md §8) is for those name-only matches, below.
        source_confidence = CONFIDENCE_HIGH
    else:
        source_confidence = CONFIDENCE_MEDIUM if len(distinct_sources) >= 2 else CONFIDENCE_LOW

    backport_uncertainty = False
    if version and _looks_backported(version):
        backport_uncertainty = True
        if applicability == APPLICABILITY_RANGE_CONFIRMED:
            mapping_confidence = _cap_confidence(mapping_confidence, CONFIDENCE_MEDIUM)
            notes.append(
                f"observed version {version!r} carries a distribution/vendor revision. Distributions "
                f"backport security fixes without changing the upstream version, so an upstream range "
                f"match cannot establish that this build is affected. ReconHound does not know this "
                f"distribution's patch status and does not guess it; confidence is capped accordingly")
        else:
            notes.append(
                f"observed version {version!r} carries a distribution/vendor revision; upstream "
                f"version reasoning is not conclusive for such builds")

    if disagreement:
        notes.append(
            f"sources disagree on version applicability ({sorted(set(matches))}); the disagreement is "
            f"preserved in `matched_sources` rather than resolved in favour of either reading")

    if applicability == APPLICABILITY_RANGE_CONFIRMED and best_quality == MATCH_QUALITY_PACKAGE:
        notes.append(
            "the match was made by package name in a package ecosystem; a product name is not always "
            "a package name, so the queried package is recorded on each source entry for review")

    return {
        "applicability": applicability,
        "mapping_confidence": mapping_confidence,
        "source_confidence": source_confidence,
        "match_quality": best_quality,
        "backport_uncertainty": backport_uncertainty,
        "disagreement": disagreement,
        "notes": _bound_notes(notes, 8),
    }


def _assess_applicability(record: Dict[str, Any], version: Optional[str] = None) -> Tuple[str, str]:
    """Legacy 2-tuple view of _mapping_assessment: (applicability, mapping confidence)."""
    assessment = _mapping_assessment(record, version)
    return assessment["applicability"], assessment["mapping_confidence"]


def format_vuln_intel_statement(
    technology: str,
    version: Optional[str],
    cve_id: str,
    applicability: str,
    backport_uncertainty: bool = False,
) -> str:
    """
    Build the context.md-mandated "Detected X 1.2.3 — MAY be affected by
    CVE-XXXX." statement.

    Never asserts confirmed exploitability, and never softens or hardens with
    CVSS/KEV: a KEV-listed critical CVE still only "MAY" affect this asset,
    because nothing in this module tested whether it does.
    """
    technology = _safe_text(str(technology), MAX_TECHNOLOGY_CHARS)
    version = _safe_text(str(version), MAX_VERSION_CHARS) if version else None
    cve_id = _safe_identifier(cve_id) or "an unidentified CVE"
    version_part = f" {version}" if version else " (version unknown)"
    if applicability == APPLICABILITY_RANGE_CONFIRMED:
        statement = (f"Detected {technology}{version_part} — MAY be affected by {cve_id} "
                     f"(version falls within the CVE's documented vulnerable range).")
        if backport_uncertainty:
            statement += (" The observed version carries a distribution/vendor revision, so the "
                          "upstream range match alone does not establish that this build is affected; "
                          "the distribution's patch status was not determined.")
        return statement
    if applicability == APPLICABILITY_KEYWORD:
        return (f"Detected {technology}{version_part} — POSSIBLY related to {cve_id} "
                f"(product name matched; version applicability not confirmed).")
    return (f"Detected {technology}{version_part} — {cve_id} references this product, but "
            f"insufficient version information is available to assess applicability.")


# Fields of the in-memory record that vary between runs without the finding
# itself changing. Kept out of the persisted `value` (finding identity) and
# carried in `metadata` instead — see map_technology_to_cves.
_VOLATILE_RECORD_KEYS = frozenset({"observed_at", "cisa_kev_status", "exploitdb_status", "epss"})

# The disclaimer carried on every persisted record. Deliberately explicit about
# each distinct thing a CVE match does NOT establish.
_INTELLIGENCE_NOTE = (
    "Technology/version-to-CVE match is vulnerability intelligence, not confirmed exploitability "
    "against this target. ReconHound did not test whether the vulnerable code path is reachable, "
    "whether the vulnerable configuration is enabled, whether compensating controls are present, "
    "or whether the component is executing at all. Observation is point-in-time."
)


# ---------------------------------------------------------------------------
# Per-observation mapping (technology/version -> CVEs), persisted
# ---------------------------------------------------------------------------

def map_technology_to_cves(
    observation: Dict[str, Any],
    store: Optional[PendingAssetsStore] = None,
    source_results: Optional[Dict[str, Any]] = None,
    kev_entries: Optional[Any] = None,
    exploitdb_index: Optional[Any] = None,
    sources: Optional[List[str]] = None,
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
    osv_ecosystem: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    include_kev: bool = True,
    include_exploitdb: bool = True,
    include_epss: bool = True,
    epss_scores: Optional[Dict[str, Any]] = None,
    epss_available: Optional[bool] = None,
    epss_reason: Optional[str] = None,
    session: Optional[ProviderSession] = None,
    fallback_target: Optional[str] = None,
    persisted_keys: Optional[set] = None,
) -> Dict[str, Any]:
    """
    Map one normalized technology observation to known CVEs across every
    configured source, and persist one "vulnerability_intelligence" finding per
    matched CVE.

    `source_results` / `kev_entries` / `exploitdb_index` / `epss_scores` may be
    pre-fetched by the caller (see run_vuln_intel) so one shared-feed fetch is
    shared across every observation instead of re-queried per call.

    Findings are written in ONE batched, atomic store write rather than one
    whole-file rewrite per CVE.
    """
    result: Dict[str, Any] = {
        "technology": None, "version": None, "target": None,
        "status": "insufficient_data", "outcome": OUTCOME_SKIPPED,
        "vulnerabilities": [], "source_status": {}, "errors": [], "notes": [],
        "persisted": 0, "skipped_duplicates": 0, "truncated": False,
        "source_summary": {},
    }

    norm = normalize_technology_observation(observation)
    if norm is None:
        result["errors"].append("observation has no usable technology/product name; skipped")
        return result

    technology, version = norm["technology"], norm.get("version")
    target = norm.get("target")
    if target is None and fallback_target:
        target, _ = _observation_target(fallback_target)
    result.update({"technology": technology, "version": version, "target": target})
    if norm.get("target_rejected_reason"):
        result["notes"].append(
            f"observation target {norm.get('raw_target')!r} was not usable as an asset reference "
            f"({norm['target_rejected_reason']})")

    if source_results is None:
        try:
            source_results = query_all_sources(
                technology, version, sources=sources, nvd_api_key=nvd_api_key,
                github_token=github_token, osv_ecosystem=osv_ecosystem, timeout=timeout,
                session=session,
            )
        except ConfigurationError as exc:
            result["errors"].append(str(exc))
            return result
        except Exception as exc:
            result["errors"].append(f"source query failed: {type(exc).__name__}: "
                                    f"{_safe_text(str(exc), MAX_ERROR_CHARS)}")
            result["status"], result["outcome"] = "sources_unavailable", OUTCOME_UNAVAILABLE
            return result
    source_results = _as_dict(source_results)
    result["source_status"] = dict(_as_dict(source_results.get("source_status")))
    if source_results.get("truncated"):
        result["truncated"] = True

    # Annotation feeds. Each carries its own availability so a feed outage is
    # never rendered as "not listed" / "no public exploit" / "score 0".
    if kev_entries is None and include_kev:
        kev_result = query_cisa_kev(timeout=timeout, session=session)
        kev_catalog = KevCatalog.from_result(kev_result)
        result["source_status"]["cisa_kev"] = {
            "status": kev_result["status"], "outcome": kev_result.get("outcome"),
            "conclusive": _result_conclusive(kev_result),
            "error": kev_result.get("error"), "annotation_only": True,
        }
    elif kev_entries is None:
        kev_catalog = KevCatalog.unavailable("CISA KEV cross-check was disabled for this run")
    else:
        kev_catalog = KevCatalog.coerce(kev_entries)

    if exploitdb_index is None and include_exploitdb:
        exploitdb_result = fetch_exploitdb_index(timeout=timeout, session=session)
        edb = ExploitDbIndex.from_result(exploitdb_result)
        result["source_status"]["exploitdb"] = {
            "status": exploitdb_result["status"], "outcome": exploitdb_result.get("outcome"),
            "conclusive": _result_conclusive(exploitdb_result),
            "error": exploitdb_result.get("error"), "annotation_only": True,
        }
    elif exploitdb_index is None:
        edb = ExploitDbIndex.unavailable("Exploit-DB cross-check was disabled for this run")
    else:
        edb = ExploitDbIndex.coerce(exploitdb_index)

    merged = _merge_vulnerability_records(_as_list(source_results.get("records")))
    if any("merged_cve_set" in _as_list(m.get("truncated_fields")) for m in merged):
        result["truncated"] = True
        result["notes"].append(
            f"more than {MAX_CVES_PER_OBSERVATION} distinct CVEs matched; the record set is partial")

    # EPSS is a RUN-level annotation, resolved once by run_vuln_intel for every
    # CVE the run matched and handed down here. The API is batched (100 CVEs
    # per request); fetching it per observation would defeat that batching and
    # would make a single-observation call issue a network request that the
    # rest of this function's inputs are explicitly allowed to pre-supply.
    if epss_scores is None:
        epss_available = False if epss_available is None else epss_available
        epss_reason = epss_reason or ("EPSS lookup was disabled for this run" if not include_epss
                                      else "no EPSS data was supplied to this call")
        epss_scores = {}
    elif epss_available is None:
        epss_available = True

    observed_at = _now()
    findings: List[Dict[str, Any]] = []
    seen_keys = persisted_keys if persisted_keys is not None else set()

    for rec in merged:
        if version is None:
            # No version was observed, so no source can have confirmed THIS
            # observation's version against a range. Real providers never emit
            # range_confirmed for a versionless query; a caller-supplied
            # source_results that does is inconsistent input, and "never treat
            # an unspecified version as a precise match" must not depend on
            # callers being consistent.
            for src_entry in rec.get("sources", []):
                if src_entry.get("version_match") == "range_confirmed":
                    src_entry["version_match"] = "unknown"
                    rec.setdefault("provider_notes", []).append(
                        f"{src_entry.get('source')} reported a version-range match, but no version was "
                        f"observed for this technology; the claim cannot be about this observation and was "
                        f"not used")
        assessment = _mapping_assessment(rec, version)
        applicability = assessment["applicability"]
        # THE confidence rule: the finding can never be more certain than the
        # least certain of the technology identification, the mapping and the
        # source agreement.
        final_confidence = _min_confidence(
            norm.get("confidence"), assessment["mapping_confidence"], assessment["source_confidence"])

        rec = annotate_kev(rec, kev_catalog)
        rec = annotate_exploitdb(rec, edb)
        rec = annotate_epss(rec, epss_scores, available=bool(epss_available), reason=epss_reason)
        statement = format_vuln_intel_statement(
            technology, version, rec["cve_id"], applicability, assessment["backport_uncertainty"])

        vuln_record = {
            "cve_id": rec["cve_id"],
            "technology": technology,
            "version": version,
            "target": target,
            "statement": statement,
            "applicability": applicability,
            "match_quality": assessment["match_quality"],
            "backport_uncertainty": assessment["backport_uncertainty"],
            "source_disagreement": assessment["disagreement"],
            "confidence": final_confidence,
            "confidence_model": {
                "technology_confidence": norm.get("confidence"),
                "mapping_confidence": assessment["mapping_confidence"],
                "source_confidence": assessment["source_confidence"],
                "final_confidence": final_confidence,
                "rule": ("final = min(technology, mapping, source). A vulnerability database match "
                         "never raises confidence above the confidence of the technology "
                         "identification it was built on."),
            },
            "summaries": rec["summaries"],
            "cvss": rec["cvss"],
            "references": rec["references"],
            "published": rec["published"],
            "matched_sources": rec["sources"],
            "source_count": rec.get("source_count", 0),
            "advisory_ids": rec.get("advisory_ids", []),
            "packages": rec.get("packages", []),
            "ecosystems": rec.get("ecosystems", []),
            "fixed_versions": rec.get("fixed_versions", []),
            "affected_ranges": rec.get("affected_ranges", []),
            "matched_cpe_products": rec.get("matched_cpe_products", []),
            "cisa_kev": rec["cisa_kev"],
            "cisa_kev_status": rec.get("cisa_kev_status"),
            "exploitdb_references": rec["exploitdb_references"],
            "exploitdb_status": rec.get("exploitdb_status"),
            "epss": rec.get("epss"),
            "detection_evidence": norm.get("evidence", []),
            "mapping_notes": _bound_notes(list(assessment["notes"]) + list(rec.get("provider_notes", []))),
            "truncated_fields": rec.get("truncated_fields", []),
            "observed_at": observed_at,
            "note": _INTELLIGENCE_NOTE,
        }
        result["vulnerabilities"].append(vuln_record)

        # Duplicate suppression. The same technology/version can be observed on
        # the same host by several producers; persisting a CVE finding per copy
        # is duplicate amplification, not corroboration.
        dedup_key = (target or "", technology.lower(), (version or "").lower(), rec["cve_id"])
        if dedup_key in seen_keys:
            result["skipped_duplicates"] += 1
            continue
        seen_keys.add(dedup_key)

        if target is None:
            # Refusing to persist is the honest outcome: surface_mapper.py
            # resolves a finding's `target` as a hostname, so persisting this
            # with `target=technology` (the previous behaviour) minted a
            # hostname asset called "openssh" — a phantom asset in the graph,
            # the report inventory and risk_engine's scoring.
            result["notes"].append(
                f"{rec['cve_id']} was assessed but not persisted: the observation carries no usable "
                f"hostname/IP target, and persisting it would mint a phantom asset in the graph")
            continue

        evidence = [f"{s.get('source')} matched {rec['cve_id']} "
                    f"({s.get('version_match')}, {s.get('match_quality')})" for s in rec["sources"]]
        if rec["cisa_kev"]:
            evidence.append("Listed in CISA KEV catalog (exploited in the wild against some target; "
                            "not target-specific confirmation)")
        elif not _as_dict(rec.get("cisa_kev_status")).get("checked"):
            evidence.append("CISA KEV catalog was not available for this run; KEV status is unknown, not negative")
        if rec["exploitdb_references"]:
            evidence.append(
                f"{len(rec['exploitdb_references'])} Exploit-DB reference(s) exist for this CVE "
                f"(a public PoC/exploit is known to exist; this is not evidence it was used against this target)")
        epss_detail = _as_dict(rec.get("epss"))
        if epss_detail.get("checked") and epss_detail.get("score") is not None:
            evidence.append(
                f"EPSS {epss_detail['score']} (exploitation-likelihood estimate for the CVE as of "
                f"{epss_detail.get('date')}; not evidence about this target)")
        if assessment["backport_uncertainty"]:
            evidence.append("Observed version carries a distribution/vendor revision; distribution patch "
                            "status is unknown and was not inferred")
        if assessment["disagreement"]:
            evidence.append("Sources disagree on version applicability; the disagreement is preserved, not resolved")

        # Identity vs. annotation. surface_mapper.py derives a finding asset's
        # identity from a hash of the whole `value`, so anything in it that
        # legitimately changes between runs (this run's timestamp, the KEV
        # catalogue version, today's EPSS score, whether a feed was reachable)
        # would mint a NEW finding asset for the same CVE on the same host on
        # every re-scan — measured: 3 findings became 6 assets after two runs.
        # Those fields are real intelligence, so they are not dropped: they go
        # in `metadata`, which the graph keeps per observation and risk_engine
        # merges latest-wins, while `value` holds only the stable finding.
        persisted_value = {k: v for k, v in vuln_record.items() if k not in _VOLATILE_RECORD_KEYS}
        findings.append(make_finding(
            finding_type="vulnerability_intelligence",
            target=target,
            value=persisted_value,
            evidence=evidence,
            confidence=final_confidence,
            metadata={
                "technology": technology, "version": version, "cve_id": rec["cve_id"],
                "applicability": applicability,
                "match_quality": assessment["match_quality"],
                "cisa_kev_listed": bool(rec["cisa_kev"]),
                "cisa_kev_checked": bool(_as_dict(rec.get("cisa_kev_status")).get("checked")),
                "cisa_kev_status": rec.get("cisa_kev_status"),
                "exploitdb_reference_count": len(rec["exploitdb_references"]),
                "exploitdb_checked": bool(_as_dict(rec.get("exploitdb_status")).get("checked")),
                "exploitdb_status": rec.get("exploitdb_status"),
                "epss_checked": bool(epss_detail.get("checked")),
                "epss_score": epss_detail.get("score"),
                "epss": rec.get("epss"),
                "backport_uncertainty": assessment["backport_uncertainty"],
                "observed_at": observed_at,
                # Which source answers came from the on-disk cache, and how old
                # they were: a cached answer is still an answer, but its
                # freshness is part of its provenance.
                "source_cache": {
                    name: info.get("cache") for name, info in result["source_status"].items()
                    if isinstance(info, dict) and isinstance(info.get("cache"), dict)
                },
                # Every provider consulted for this observation and how it
                # answered, so a finding can be read knowing which sources were
                # down when it was produced (a match with NVD rate-limited is a
                # weaker picture than one with every source answering).
                "provider_outcomes": {
                    name: _as_dict(info).get("outcome") or _as_dict(info).get("status")
                    for name, info in sorted(result["source_status"].items())
                },
            },
        ))

    conclusiveness = _sources_conclusive(result["source_status"])
    result["source_summary"] = conclusiveness

    if merged:
        result["status"] = "found"
        result["outcome"] = OUTCOME_FOUND
    elif conclusiveness["none_usable"] or not conclusiveness["queried"]:
        result["status"] = "sources_unavailable"
        result["outcome"] = OUTCOME_UNAVAILABLE
    elif not conclusiveness["all_conclusive"]:
        # Some sources answered, others could not. That is genuinely
        # inconclusive and must never be recorded as "checked, nothing found":
        # surface_mapper.py would store it as CHECK_NOT_FOUND and every later
        # run would treat the question as settled.
        result["status"] = "inconclusive"
        result["outcome"] = OUTCOME_UNAVAILABLE
        result["notes"].append(
            f"no CVE matched, but source(s) {conclusiveness['inconclusive_sources']} did not return a "
            f"conclusive answer; this is NOT a clean result and no negative-result finding was recorded")
    else:
        result["status"] = "not_found"
        result["outcome"] = OUTCOME_EMPTY_AUTHORITATIVE
        if target is not None:
            findings.append(make_finding(
                finding_type="vuln_intel_checked_no_match",
                target=target,
                value={"technology": technology, "version": version},
                evidence=[
                    f"No known CVE found for {technology} {version or '(version unknown)'} "
                    f"across {conclusiveness['conclusive_sources']} as of this check",
                ],
                confidence=CONFIDENCE_LOW,
                metadata={
                    "technology": technology, "version": version, "checked_at": observed_at,
                    "sources_queried": conclusiveness["conclusive_sources"],
                    "note": ("Negative-result memory: every queried source answered conclusively and none "
                             "reported a matching CVE. Absence of a match today does not guarantee no future "
                             "match, since vulnerability databases are updated continuously."),
                },
            ))
        else:
            result["notes"].append(
                "no CVE matched, but the observation carries no usable hostname/IP target, so no "
                "negative-result finding was persisted")

    err = _safe_store_add_many(store, findings)
    if err:
        result["errors"].append(err)
    else:
        result["persisted"] = len(findings)
    return result


# ---------------------------------------------------------------------------
# Module orchestration
# ---------------------------------------------------------------------------

def _guarded_feed(name: str, fetch, empty_key: str) -> Dict[str, Any]:
    """
    Run one shared-feed fetch so that an unexpected exception inside it is an
    UNAVAILABLE feed for this run, never the end of the run: every observation
    can still be mapped, with the annotation honestly marked not-checked.
    """
    try:
        result = fetch()
        if not isinstance(result, dict):
            raise TypeError(f"{name} returned {type(result).__name__}, not a result dict")
        return result
    except Exception as exc:
        return {"status": "error", "outcome": OUTCOME_UNAVAILABLE, empty_key: {} if empty_key != "entries" else [],
                "error": f"{type(exc).__name__}: {_safe_text(str(exc), MAX_ERROR_CHARS)}"}


def run_vuln_intel(
    output_dir: str = "output",
    technology_observations: Optional[List[Dict[str, Any]]] = None,
    include_active_recon: bool = True,
    sources: Optional[List[str]] = None,
    include_kev: bool = True,
    include_exploitdb: bool = True,
    include_epss: bool = True,
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    target: Optional[str] = None,
    use_cache: bool = True,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    max_runtime_seconds: float = DEFAULT_MAX_RUNTIME_SECONDS,
    session: Optional[ProviderSession] = None,
) -> Dict[str, Any]:
    """
    Run Module 19 across every available technology/version observation and
    persist every match immediately to <output_dir>/pending_assets.json.

    Observations come from two places (module docstring, input-contract
    decision): active_recon.py's already-persisted findings (when
    `include_active_recon`), and/or a caller-supplied `technology_observations`
    list — the hand-off point core/orchestrator.py uses for graph-derived
    technology assets.

    Shared feeds are fetched at most ONCE per run and shared across every
    observation: the CISA KEV catalogue, the Exploit-DB CSV index, and (after
    the source queries, so it can be batched over the whole CVE set) EPSS.
    External CVE-source queries (NVD/OSV/GHSA) are deduplicated per unique
    (technology, version) pair within the run and, unless `use_cache=False`,
    served from a bounded on-disk TTL cache across runs. A provider outage is
    never cached and never reported as a clean result.

    `target` is an optional run-level fallback for observations that carry no
    target of their own (the standalone `--technology` path); observations
    without any usable hostname/IP are still assessed and returned, but are not
    persisted, because a finding whose `target` is not an asset mints a phantom
    asset in surface_mapper.py's graph.
    """
    store = PendingAssetsStore(output_dir=output_dir)
    owns_session = session is None
    if owns_session:
        session = build_session(
            output_dir=output_dir, use_cache=use_cache, max_requests=max_requests,
            max_runtime_seconds=max_runtime_seconds, nvd_api_key=nvd_api_key,
            github_token=github_token,
        )

    run_target, run_target_reason = _observation_target(target) if target else (None, None)

    summary: Dict[str, Any] = {
        "module": MODULE_NAME,
        "started_at": _now(),
        "target": run_target,
        "extraction_errors": [],
        "skipped_observations": [],
        "results": [],
        "cisa_kev_status": None,
        "exploitdb_status": None,
        "epss_status": None,
        "stats": {},
        "errors": [],
        "notes": [],
        "provider_stats": {},
    }
    if target and run_target is None:
        summary["notes"].append(f"run target {target!r} was not usable as an asset reference ({run_target_reason})")

    observations: List[Dict[str, Any]] = []

    if include_active_recon:
        extracted, extraction_errors = extract_observations_from_active_recon(store)
        observations.extend(extracted)
        summary["extraction_errors"] = extraction_errors

    skipped_count = 0
    for raw_obs in (technology_observations or []):
        norm = normalize_technology_observation(raw_obs)
        if norm is None:
            skipped_count += 1
            if len(summary["skipped_observations"]) < 50:
                summary["skipped_observations"].append(_jsonify(raw_obs))
            continue
        observations.append(norm)

    # Deduplicate across both sources: the same (technology, version, target)
    # observed twice is one question, not two, and asking it twice persists the
    # same CVE findings twice.
    deduped: List[Dict[str, Any]] = []
    seen_obs: set = set()
    duplicate_observations = 0
    for obs in observations:
        key = (obs["technology"].lower(), (obs.get("version") or "").lower(), obs.get("target") or "")
        if key in seen_obs:
            duplicate_observations += 1
            continue
        seen_obs.add(key)
        deduped.append(obs)
        if len(deduped) >= MAX_OBSERVATIONS:
            break
    if len(observations) > MAX_OBSERVATIONS:
        summary["notes"].append(
            f"observation set capped at {MAX_OBSERVATIONS}; {len(observations) - len(deduped) - duplicate_observations} "
            f"observation(s) were not assessed")
    observations = deduped

    if not observations:
        summary["finished_at"] = _now()
        summary["stats"] = {"observations": 0, "vulnerabilities_found": 0,
                            "skipped_observations": skipped_count,
                            "duplicate_observations": duplicate_observations}
        if owns_session:
            summary["provider_stats"] = session.stats()
        return summary

    # --- shared feeds, fetched once ---
    kev_catalog = KevCatalog.unavailable("CISA KEV cross-check was disabled for this run")
    if include_kev:
        kev_result = _guarded_feed("cisa_kev", lambda: query_cisa_kev(timeout=timeout, session=session), "entries")
        kev_catalog = KevCatalog.from_result(kev_result)
        summary["cisa_kev_status"] = {
            "status": kev_result["status"], "outcome": kev_result.get("outcome"),
            "conclusive": kev_catalog.available, "error": kev_result.get("error"),
            "entries": kev_catalog.entry_count, "cache": kev_result.get("cache"),
            "annotation_only": True,
        }
        if not kev_catalog.available:
            summary["errors"].append({"stage": "cisa_kev", "error": kev_result.get("error"),
                                      "impact": "KEV status is unknown for every CVE in this run, not negative"})

    edb_index = ExploitDbIndex.unavailable("Exploit-DB cross-check was disabled for this run")
    if include_exploitdb:
        exploitdb_result = _guarded_feed("exploitdb", lambda: fetch_exploitdb_index(timeout=timeout, session=session), "index")
        edb_index = ExploitDbIndex.from_result(exploitdb_result)
        summary["exploitdb_status"] = {
            "status": exploitdb_result["status"], "outcome": exploitdb_result.get("outcome"),
            "conclusive": edb_index.available, "error": exploitdb_result.get("error"),
            "cves_indexed": edb_index.entry_count, "cache": exploitdb_result.get("cache"),
            "annotation_only": True,
        }
        if not edb_index.available:
            summary["errors"].append({"stage": "exploitdb", "error": exploitdb_result.get("error"),
                                      "impact": "public-exploit availability is unknown for this run, not negative"})

    # --- pass 1: query the CVE sources once per unique (technology, version) ---
    query_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for obs in observations:
        cache_key = (obs["technology"].lower(), obs.get("version") or "")
        if cache_key in query_cache:
            continue
        try:
            query_cache[cache_key] = query_all_sources(
                obs["technology"], obs.get("version"), sources=sources,
                nvd_api_key=nvd_api_key, github_token=github_token, timeout=timeout,
                osv_ecosystem=obs.get("ecosystem"), session=session,
            )
        except ConfigurationError as exc:
            # A misconfigured source list is fatal for every observation, not
            # just this one: fail the run cleanly rather than silently querying
            # nothing for the rest of it.
            summary["errors"].append({"stage": "query_all_sources", "error": str(exc)})
            summary["stats"] = {"observations": len(observations), "vulnerabilities_found": 0,
                                "skipped_observations": skipped_count,
                                "duplicate_observations": duplicate_observations}
            summary["finished_at"] = _now()
            if owns_session:
                summary["provider_stats"] = session.stats()
            return summary
        except Exception as exc:
            summary["errors"].append({
                "stage": "query_all_sources",
                "technology": obs["technology"],
                "error": f"{type(exc).__name__}: {_safe_text(str(exc), MAX_ERROR_CHARS)}",
            })
            query_cache[cache_key] = {"records": [], "source_status": {
                "*": {"status": "error", "outcome": OUTCOME_UNAVAILABLE, "conclusive": False,
                      "error": _safe_text(str(exc), MAX_ERROR_CHARS)}}}

    # --- EPSS, batched once over every CVE the run matched ---
    epss_scores: Dict[str, Any] = {}
    epss_available = False
    epss_reason: Optional[str] = "EPSS lookup was disabled for this run"
    if include_epss:
        all_cve_ids = sorted({
            rec.get("cve_id") for result in query_cache.values()
            for rec in _as_list(_as_dict(result).get("records"))
            if isinstance(_as_dict(rec).get("cve_id"), str)
        })
        if all_cve_ids:
            epss_result = _guarded_feed("epss", lambda: query_epss(all_cve_ids, timeout=timeout, session=session), "scores")
            epss_scores = epss_result.get("scores") or {}
            epss_available = _result_conclusive(epss_result)
            epss_reason = epss_result.get("error")
            summary["epss_status"] = {
                "status": epss_result["status"], "outcome": epss_result.get("outcome"),
                "conclusive": epss_available, "error": epss_result.get("error"),
                "requested": epss_result.get("requested"), "returned": epss_result.get("returned"),
                "annotation_only": True,
            }
            if not epss_available:
                summary["errors"].append({"stage": "epss", "error": epss_result.get("error"),
                                          "impact": "EPSS scores are unknown for this run, not zero"})
        else:
            epss_reason = "no CVEs matched, so no EPSS scores were requested"
            summary["epss_status"] = {"status": "skipped", "outcome": OUTCOME_SKIPPED,
                                      "conclusive": False, "error": None, "annotation_only": True}

    # --- pass 2: map, annotate and persist ---
    vulnerabilities_found = 0
    persisted = 0
    duplicate_findings = 0
    persisted_keys: set = set()
    inconclusive_observations = 0

    for obs in observations:
        cache_key = (obs["technology"].lower(), obs.get("version") or "")
        try:
            outcome = map_technology_to_cves(
                obs, store=store, source_results=query_cache.get(cache_key),
                kev_entries=kev_catalog, exploitdb_index=edb_index,
                epss_scores=epss_scores, epss_available=epss_available, epss_reason=epss_reason,
                include_kev=include_kev, include_exploitdb=include_exploitdb,
                include_epss=include_epss, timeout=timeout, session=session,
                fallback_target=run_target, persisted_keys=persisted_keys,
            )
        except Exception as exc:
            # One observation must never take the run down with it: everything
            # already persisted stays persisted, and the failure is recorded.
            summary["errors"].append({
                "stage": "map_technology_to_cves",
                "technology": obs.get("technology"),
                "target": obs.get("target"),
                "error": f"{type(exc).__name__}: {_safe_text(str(exc), MAX_ERROR_CHARS)}",
            })
            continue
        summary["results"].append(outcome)
        vulnerabilities_found += len(outcome.get("vulnerabilities", []))
        persisted += outcome.get("persisted", 0)
        duplicate_findings += outcome.get("skipped_duplicates", 0)
        if outcome.get("status") == "inconclusive":
            inconclusive_observations += 1
        for err in outcome.get("errors", []):
            summary["errors"].append({"stage": "map_technology_to_cves",
                                      "technology": obs.get("technology"), "error": err})

    if inconclusive_observations:
        summary["notes"].append(
            f"{inconclusive_observations} observation(s) ended INCONCLUSIVE (at least one source could not "
            f"answer). No negative-result finding was recorded for them: a provider outage is not a clean result")

    summary["stats"] = {
        "observations": len(observations),
        "skipped_observations": skipped_count,
        "duplicate_observations": duplicate_observations,
        "unique_technology_version_pairs": len(query_cache),
        "vulnerabilities_found": vulnerabilities_found,
        "findings_persisted": persisted,
        "duplicate_findings_suppressed": duplicate_findings,
        "inconclusive_observations": inconclusive_observations,
    }
    summary["notes"] = _bound_notes(summary["notes"])
    summary["provider_stats"] = session.stats()
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="vuln_intel.py",
        description="ReconHound Module 19 — technology-to-CVE mapping (standalone test entry point).",
    )
    parser.add_argument("--output-dir", default="output", help="Directory containing/for pending_assets.json")
    parser.add_argument("--target", default=None,
                        help="Hostname/IP the observations belong to. Required for a --technology run to be "
                             "persisted: a finding with no asset target is assessed but not written to the graph.")
    parser.add_argument("--technology", default=None, help="Query a single technology directly (e.g. 'nginx')")
    parser.add_argument("--version", default=None, help="Version for --technology (optional)")
    parser.add_argument("--no-active-recon", action="store_true", help="Skip auto-extraction from active_recon.py findings")
    parser.add_argument("--no-kev", action="store_true", help="Skip the CISA KEV cross-check")
    parser.add_argument("--no-exploitdb", action="store_true", help="Skip the Exploit-DB cross-check")
    parser.add_argument("--no-epss", action="store_true", help="Skip the EPSS exploitation-likelihood lookup")
    parser.add_argument("--no-cache", action="store_true", help="Bypass the on-disk provider cache for this run")
    parser.add_argument("--sources", default=None, help=f"Comma-separated subset of {sorted(_VALID_SOURCES)}")
    parser.add_argument("--nvd-api-key", default=None, help=f"NVD API key (or set {NVD_API_KEY_ENV})")
    parser.add_argument("--github-token", default=None, help=f"GitHub token (or set {GITHUB_TOKEN_ENV})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-query network timeout (seconds)")
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS,
                        help="Hard cap on HTTP requests this run may issue")
    parser.add_argument("--max-runtime", type=float, default=DEFAULT_MAX_RUNTIME_SECONDS,
                        help="Wall-clock budget for this run (seconds)")
    args = parser.parse_args()

    sources = [s.strip() for s in args.sources.split(",")] if args.sources else None
    technology_observations = None
    if args.technology:
        technology_observations = [{"technology": args.technology, "version": args.version,
                                    "target": args.target, "source": "cli"}]

    result = run_vuln_intel(
        output_dir=args.output_dir,
        technology_observations=technology_observations,
        include_active_recon=not args.no_active_recon,
        sources=sources,
        include_kev=not args.no_kev,
        include_exploitdb=not args.no_exploitdb,
        include_epss=not args.no_epss,
        nvd_api_key=args.nvd_api_key,
        github_token=args.github_token,
        timeout=args.timeout,
        target=args.target,
        use_cache=not args.no_cache,
        max_requests=args.max_requests,
        max_runtime_seconds=args.max_runtime,
    )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    _main()
