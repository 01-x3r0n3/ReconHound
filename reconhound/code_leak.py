"""
reconhound/code_leak.py — ReconHound Module 3 (code_leak.py).

Phase: Passive. See context.md §10 (module 3, "Public repo intel") for the
authoritative responsibilities, and §8 for the evidence/confidence data
model this module implements. This file only documents implementation-
specific detail, not the architecture itself.

context.md's exact line for this module:

  "Public repo intel. GitHub Search API, API keys/tokens, internal URLs,
  config files, DB connection strings, credentials, hardcoded infra refs."

That expands (per the assignment brief) into two discrete discovery
responsibilities, each implemented below:

  1. Discover public repositories/code relevant to the target
                                          -> search_github_repositories,
                                             search_github_code
  2. Identify + collect evidence of potentially exposed secrets/config/
     infra references                    -> extract_findings_from_code_item
                                             (secret-pattern matching,
                                             SECRET_PATTERNS) and
                                             _match_config_file_pattern
                                             (path-based config-file
                                             detection)

Plus shared plumbing: make_finding, PendingAssetsStore, _safe_store_add
(duplicated per modular independence, same as every other implemented
module), and a single-target orchestrator run_code_leak (mirroring the
run_passive_recon / run_wayback_intel / run_vuln_intel / run_passive_intel
precedent).

BUILD-ORDER NOTE: context.md §13 lists this module at build-order position
16, after surface_mapper.py (position 8). Per wayback_intel.py's,
vuln_intel.py's and passive_intel.py's module docstrings, this module was
built under an explicit, user-approved deviation from that order, before
surface_mapper.py existed. That deviation shapes what this file is and
remains true of it: it is a fully standalone producer that does not
implement, replace, call into or import surface_mapper.py's correlation
engine, risk_engine.py, core/orchestrator.py or any other module. It
communicates in one direction only, by writing findings to
pending_assets.json, and those consumers now exist and read it from there.

PASSIVE BOUNDARY (context.md §16, assignment "DISCOVERY BOUNDARY"): this
module's only network interactions are with GitHub's public REST Search
API (api.github.com/search/code, api.github.com/search/repositories).
This module never sends a request to the target itself, never fetches a
repository's raw file contents or clones a repository, never follows a
URL discovered inside matched code, never authenticates to a discovered
service, and never validates whether a discovered credential is live.
Detected secrets/credentials are recorded strictly as OBSERVATIONS
("this string, matching this pattern, was seen in this public file") —
never as confirmed-valid credentials.

PRIVATE-REPOSITORY SAFEGUARD: a configured GitHub token may carry access
to private repositories the token's owner belongs to. GitHub's Search API
will transparently include those in results if they match the query. Per
the assignment's explicit "do NOT access private repositories" boundary,
every single item returned by either search endpoint is checked for
`repository.private` / `private` truthiness (see `_is_private_repo`)
BEFORE any of its fields are read, evidenced, or persisted — a private
hit is discarded outright and only counted in `stats.private_repos_skipped`.
This is enforced even though this module never supplied credentials with
such access itself; the check does not depend on the caller's intent.

The check fails CLOSED: an item whose repository object is missing or is
not a JSON object is withheld too (counted in
`stats.items_unverifiable_repo`), because its public/private state was
never established. The raw value is passed to `_is_private_repo`
unmodified — substituting an empty dict first would read as "public" and
quietly defeat the safeguard for exactly the malformed responses it exists
to catch.

CONTENT-INSPECTION BOUNDARY: this module never fetches a matched file's
full raw contents (that would exceed "the approved GitHub API/search
mechanism" and drift toward the prohibited "clone repositories"
behavior). All content actually inspected for secret patterns is the
`text_matches[].fragment` text GitHub's Search API itself returns inline
when queried with the `application/vnd.github.text-match+json` media
type — a short, GitHub-selected excerpt around the query match. This is a
real limitation: a secret whose sensitive portion falls outside that
excerpt will not be found. That tradeoff is deliberate and documented
here rather than silently accepted.

HISTORICAL COVERAGE: for the same reason, this module sees only what
GitHub's code index currently holds for a repository's default branch. It
does not search commit history, deleted files, other branches, or forks —
a secret committed and then removed remains in the repository's history
and stays invisible here. Reaching it would require cloning and walking
repositories, which this module's content-inspection boundary above rules
out. This is an architectural limitation of passive GitHub-Search-API
intelligence, not an unimplemented feature: it is stated so the absence of
a finding is never read as the absence of a historical exposure.

CREDENTIAL HANDLING: GitHub's code-search endpoint
(GET /search/code) requires authentication — GitHub does not serve
unauthenticated code-search requests at all (unlike vuln_intel.py's
GitHub Security Advisories lookup, where a token only raises the rate
limit). A missing token is therefore reported as its own explicit status,
"missing_credentials", for the code-search stage only — never raised as
an exception. Repository search (GET /search/repositories) is usable
without a token (10 req/min) and works better with one (30 req/min); a
missing token there only lowers throughput, mirrored on
`source_status["repo_search"]`. Running this module with zero GITHUB_TOKEN
configured completes successfully: repository discovery still runs,
secret/config/infra discovery inside code is skipped with a clear reason.

NEGATIVE-RESULT MEMORY (context.md §8/§12.6): GitHub's code index only
covers what GitHub has indexed at query time; a query returning no hits is
NOT proof the target has no exposed code — it may be indexed later, or
live in a private/self-hosted repo GitHub never sees. Every code-search
query that completes with zero hits gets an explicit
`code_leak_checked_no_match` finding (mirroring passive_intel.py's
`passive_intel_checked_no_data` / vuln_intel.py's
`vuln_intel_checked_no_match` precedent) rather than silence.

"Checked and not found" is reserved for that case alone. A query is
INCONCLUSIVE — reported in `stats.code_queries_inconclusive` and never
written as a negative result — when it produced nothing usable for any
reason other than absence: every result on the page withheld as private or
unverifiable while GitHub reported matches, or GitHub setting
`incomplete_results`. surface_mapper.py stores a negative result as a
CHECK_NOT_FOUND state that suppresses repeated work, so labelling a
withheld or truncated search "not found" would write a false conclusion
into the graph's memory.

RESULT COMPLETENESS: this module issues exactly one page per query and
never paginates, so it never multiplies its request volume against GitHub's
search limits — and GitHub caps search pagination at 1,000 results per
query regardless. What it examines is therefore a bounded sample of a
potentially much larger match set. That bound is reported rather than
implied: every per-query status carries `items_examined`, `total_count`,
`total_count_reported` (GitHub omitting the count is recorded as unknown,
not as "the page is everything"), GitHub's own `incomplete_results` flag,
and `results_truncated`.

TARGET ASSOCIATION (context.md §16, strict scope enforcement): every query
this module issues is anchored on the literal target hostname, but a
GitHub text match is a *textual* link, never proof of ownership. A
repository that merely mentions the target in a README is surfaced exactly
like one the target operates, and this module has no passive way to tell
them apart. It therefore does not try: findings record what was observed
(`repo_full_name`, `path`, `source_url`, and
`target_string_in_fragment` — whether the target string was actually
present in the inspected excerpt or only in the file somewhere) and leave
attribution to the analyst. No weak textual match is ever promoted into an
ownership claim.

INPUT-CONTRACT DECISIONS (ambiguities resolved so implementation can
proceed without inventing a competing asset model, mirroring
wayback_intel.py's / vuln_intel.py's / passive_intel.py's precedent for
the same surface_mapper.py gap):

  1. Discovery queries are a fixed, target-scoped dork list
     (DEFAULT_CODE_SEARCH_QUERIES / DEFAULT_REPO_SEARCH_QUERY_TEMPLATE),
     every one of them anchored on the literal target hostname string —
     never an unscoped/broad query. Callers may override the list
     (`code_queries` / `repo_query`) for standalone testing or narrower
     runs.
  2. A single secret/config/infra "sighting" can legitimately be matched
     by more than one dork query (e.g. both the generic mention query and
     the "password" keyword query surface the same file). Findings are
     aggregated by (repository, path, category, value-fingerprint) before
     persistence — see `_aggregate_code_finding` — so the same sighting
     produces one pending_assets.json entry, and the full set of queries
     that surfaced it is recorded as evidence in `matched_via_queries`.
     Convergence across dorks does NOT raise confidence: context.md §8
     raises confidence for *independent* converging signals, and these
     queries are not independent — DEFAULT_CODE_SEARCH_QUERIES' unqualified
     `"{target}"` query is a strict superset of every keyword-qualified
     query in the list, so overlap is guaranteed by construction rather
     than corroborating. Confidence is the detection pattern's own
     confidence, adjusted only downward by decision #5.
  3. Secrets are never stored verbatim. Every matched value is reduced to
     `_redact_secret()` (first/last few characters, middle masked) plus a
     SHA-256 `fingerprint_sha256` (for downstream exact-match correlation
     without re-exposing the value) — satisfying the assignment's "avoid
     storing complete secrets unnecessarily... preserve enough evidence to
     identify and investigate" instruction. This applies to the stored
     `context` excerpt too: EVERY secret detected anywhere in a fragment is
     redacted before that fragment is stored, not just the one belonging to
     the finding being built, because a single .env excerpt routinely holds
     several secrets and each finding stores the same shared excerpt. A
     pattern whose match is a constant marker rather than a value (the PEM
     armour header) is flagged `value_is_marker` and emits no fingerprint:
     hashing a constant would give every private key ever found an
     identical `fingerprint_sha256`, and risk_engine.py discriminates
     leaked-credential signals by exactly that field.
  4. Category taxonomy (assignment's required finding categories) is
     enforced as a closed set: api_key, token, credential,
     db_connection_string, config_file, internal_url,
     infrastructure_reference — see CATEGORIES. `config_file` findings are
     path-based (a matched result's file path itself is a known
     sensitive-config filename, e.g. `.env`, `wp-config.php`,
     `.aws/credentials`) rather than content-pattern-based, and are
     reported independently of whether that same file also triggered a
     content-based secret match.
  5. Pattern matching is not judgement. A match whose value is obvious
     documentation filler (`your_password_here`, `changeme`, a vendor's
     published example key) or whose file is a template/vendored
     third-party path is still extracted, still persisted and still carries
     its full evidence — only its confidence is lowered and the reason
     recorded in `quality_notes` (see `assess_placeholder` /
     `assess_path_authority`). Suppressing such a finding would trade a
     false positive for a false negative, which for credential exposure is
     the strictly worse error. This matters downstream: risk_engine.py caps
     a signal's severity by the confidence attached to it, so an unqualified
     MEDIUM/HIGH on a placeholder is reported to the operator as a HIGH or
     CRITICAL leaked credential.
  6. GitHub Search API response shapes below reflect GitHub's public REST
     API documentation as of this implementation (`/search/code` items
     with an embedded `repository` object and optional `text_matches[]`;
     `/search/repositories` items as full repository objects). Every
     parser is deliberately defensive (`.get()` with fallbacks, try/except
     around each item) so an unexpected or evolving field layout degrades
     a single item, never the whole run.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other implemented module, sharing the same output file). Output is
intended to feed surface_mapper.py (module 6, not yet implemented) — this
module does not implement or call into surface_mapper, active_recon,
tech_fingerprint, vhost_scanner, api_recon, js_analyzer, supply_chain,
http_analyzer, ssl_analyzer, screenshot, vuln_intel, risk_engine,
report_generator, orchestrator, or any other module not already
implemented.

DISCOVERY != CONFIRMED SECRET: every finding here is an unverified pattern
match in a public, GitHub-indexed file. None of this module's output
should be read as "this credential is valid," "this service is
reachable," or "this is definitely a secret" — pattern-based detection has
a real false-positive rate (e.g. a variable literally named
`password_reset_token`), which is why every generic keyword-based pattern
is capped at MEDIUM confidence and annotated with a verification note.
That assessment belongs to a human analyst and/or risk_engine.py.
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
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

MODULE_NAME = "code_leak.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_ORDER: Dict[str, int] = {CONFIDENCE_LOW: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_HIGH: 2}

DEFAULT_USER_AGENT = "ReconHound-CodeLeak/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 15.0
DEFAULT_PER_PAGE = 30
DEFAULT_REQUEST_DELAY = 1.5  # seconds between GitHub Search API calls (secondary-rate-limit courtesy)

GITHUB_TOKEN_ENV = "GITHUB_TOKEN"

GITHUB_CODE_SEARCH_API = "https://api.github.com/search/code"
GITHUB_REPO_SEARCH_API = "https://api.github.com/search/repositories"

# Finding categories (assignment's required finding categories, closed set)
CATEGORY_API_KEY = "api_key"
CATEGORY_TOKEN = "token"
CATEGORY_CREDENTIAL = "credential"
CATEGORY_DB_CONNECTION = "db_connection_string"
CATEGORY_CONFIG_FILE = "config_file"
CATEGORY_INTERNAL_URL = "internal_url"
CATEGORY_INFRA_REFERENCE = "infrastructure_reference"

CATEGORIES = frozenset({
    CATEGORY_API_KEY, CATEGORY_TOKEN, CATEGORY_CREDENTIAL, CATEGORY_DB_CONNECTION,
    CATEGORY_CONFIG_FILE, CATEGORY_INTERNAL_URL, CATEGORY_INFRA_REFERENCE,
})

# Target-scoped GitHub code-search dorks (input-contract decision #1). Every
# query is anchored on the literal `{target}` hostname string.
DEFAULT_CODE_SEARCH_QUERIES: Tuple[Tuple[str, str], ...] = (
    ("generic_mention", '"{target}"'),
    ("password_keyword", '"{target}" password'),
    ("api_key_keyword", '"{target}" api_key'),
    ("secret_keyword", '"{target}" secret'),
    ("token_keyword", '"{target}" token'),
    ("database_url_keyword", '"{target}" DATABASE_URL'),
    ("connection_string_keyword", '"{target}" connectionstring'),
    ("env_file", '"{target}" filename:.env'),
    ("config_json_file", '"{target}" filename:config.json'),
    ("yaml_config_file", '"{target}" extension:yml'),
    ("private_key_file", '"{target}" extension:pem'),
    ("aws_credentials_file", '"{target}" filename:credentials'),
)

DEFAULT_REPO_SEARCH_QUERY_TEMPLATE = '"{target}" in:name,description,readme'


class ScopeError(ValueError):
    """Raised when a target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors passive_recon.py's/passive_intel.py's
# validate_target; duplicated per modular independence, context.md §12.2)
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def validate_target(target: str) -> str:
    """
    Validate that `target` is a syntactically valid, explicit domain name.

    code_leak operates on exactly one explicit target domain per invocation
    and never expands to unrelated hosts/orgs. Raises ScopeError on
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


# ---------------------------------------------------------------------------
# Secret-redaction helpers (input-contract decision #3)
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


def _as_text(value: Any) -> str:
    """
    Coerce a provider-supplied field to a string without raising.

    GitHub sends `path`/`name` as strings, but a malformed or evolving
    response can send anything. Passing a non-string straight into a regex
    raises TypeError, and the extractor's outer guard would then discard every
    genuine secret found in that item — silent evidence loss.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def _truncate(text: str, limit: int = 300) -> str:
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + "…"


def _redact_spans(fragment: str, spans: List[Tuple[int, int, str]]) -> str:
    """
    Return `fragment` with EVERY span in `spans` replaced by its redacted form.

    One GitHub text-match fragment routinely contains several distinct secrets
    (an AWS key, a password and a token on adjacent lines of the same .env
    excerpt). Redacting only the span belonging to the finding being built
    would leave every *other* secret in that fragment stored verbatim in the
    finding's `context`, and from there in pending_assets.json, the asset
    graph and the HTML report — defeating input-contract decision #3
    ("Secrets are never stored verbatim") for every co-located secret.
    Spans are applied right-to-left so earlier offsets stay valid.
    """
    usable = [
        (start, end, redacted_value) for start, end, redacted_value in spans
        if start is not None and end is not None and 0 <= start < end <= len(fragment)
    ]
    if not usable:
        return fragment

    # Distinct patterns overlap constantly: `generic_secret_assignment` matches
    # the `password=` inside a connection string that `db_connection_string`
    # already matched whole. Rewriting one span and then the other by raw
    # offsets both corrupts the excerpt and can re-expose part of a value, so
    # overlapping spans are merged into one interval first. A merged interval
    # is replaced wholesale, which guarantees no byte of any matched value
    # survives it.
    merged: List[Tuple[int, int, List[str]]] = []
    for start, end, redacted_value in sorted(usable, key=lambda s: (s[0], -s[1])):
        if merged and start <= merged[-1][1]:
            prev_start, prev_end, values = merged[-1]
            if redacted_value not in values:
                values.append(redacted_value)
            merged[-1] = (prev_start, max(prev_end, end), values)
        else:
            merged.append((start, end, [redacted_value]))

    out = fragment
    for start, end, values in reversed(merged):
        marker = values[0] if len(values) == 1 else " + ".join(values)
        out = f"{out[:start]}«{marker}»{out[end:]}"
    return out


# Upper bound on how much of a single provider-supplied fragment is scanned.
# GitHub's text-match fragments are short excerpts (a few hundred bytes); this
# ceiling exists only so a non-conforming or hostile response cannot turn one
# item into minutes of regex work and tens of thousands of findings. When it
# bites, the finding records it rather than pretending the fragment was fully
# inspected.
MAX_FRAGMENT_CHARS = 65536

# Upper bound on secret-pattern findings taken from a single fragment. Same
# rationale; exceeding it is reported, never silently swallowed.
MAX_FINDINGS_PER_FRAGMENT = 200


# ---------------------------------------------------------------------------
# Placeholder / non-authoritative-source assessment
#
# context.md §8 forbids presenting insufficient evidence as certainty, and
# risk_engine.py caps a signal's severity by the confidence attached to it
# (CONFIDENCE_SEVERITY_CAP). A documentation placeholder such as
# `password = "your_password_here"` is a real pattern match but not a real
# secret, and must not reach the operator as a CRITICAL leaked credential.
#
# Deliberately NOT implemented as a suppression filter: a flagged finding is
# still extracted, still persisted, and still carries its full evidence — only
# its confidence is lowered and the reason recorded. Dropping the finding
# would trade a false positive for a false negative, which for credential
# exposure is the strictly worse error.
# ---------------------------------------------------------------------------

# Whole words that only appear in filler/documentation values.
_PLACEHOLDER_WORDS = frozenset({
    "your", "yours", "here", "example", "examples", "sample", "samples",
    "changeme", "change", "placeholder", "dummy", "fake", "todo", "tbd",
    "replace", "replaceme", "insert", "myvalue", "value", "somevalue",
    "notreal", "redacted", "xxx", "xxxx", "xxxxx", "abc", "test", "testing",
})

# Values that are literally published in vendor documentation and therefore
# appear in thousands of unrelated repositories.
_KNOWN_DOC_EXAMPLE_VALUES = frozenset({
    "akiaiosfodnn7example",
    "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
})

_PLACEHOLDER_WRAPPED_RE = re.compile(r"^(?:<.*>|\{\{.*\}\}|\$\{.*\}|\[.*\])$")
_PLACEHOLDER_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")

# Path markers that mean "this file is a template or third-party code, not the
# repository's own live configuration".
_TEMPLATE_PATH_RE = re.compile(
    r"(?:^|/|\.)(?:example|examples|sample|samples|template|templates|dist|default)"
    r"(?:$|/|\.)", re.IGNORECASE
)
_VENDORED_PATH_RE = re.compile(
    r"(?:^|/)(?:node_modules|bower_components|vendor|third_party|thirdparty)/", re.IGNORECASE
)


def assess_placeholder(value: Optional[str]) -> Optional[str]:
    """
    Return a short reason if `value` looks like filler/documentation text
    rather than a real secret, else None. Never raises.
    """
    if not value or not isinstance(value, str):
        return None
    lowered = value.strip().lower()
    if not lowered:
        return None
    if lowered in _KNOWN_DOC_EXAMPLE_VALUES:
        return "value is a credential published verbatim in vendor documentation"
    if _PLACEHOLDER_WRAPPED_RE.match(value.strip()):
        return "value is a template placeholder token, not a literal"
    stripped = re.sub(r"[^A-Za-z0-9]", "", lowered)
    if stripped and len(set(stripped)) <= 2:
        return "value is filler (two or fewer distinct characters)"
    words = {w for w in _PLACEHOLDER_TOKEN_SPLIT_RE.split(lowered) if w}
    hit = sorted(words & _PLACEHOLDER_WORDS)
    if hit:
        return f"value contains documentation-placeholder word(s): {', '.join(hit)}"
    return None


def assess_path_authority(path: Optional[str]) -> Optional[str]:
    """
    Return a short reason if `path` identifies a file that is a template or
    vendored third-party code — i.e. a location whose contents are not the
    repository's own live configuration — else None.
    """
    if not path or not isinstance(path, str):
        return None
    if _VENDORED_PATH_RE.search(path):
        return "file lives in a vendored third-party dependency tree, not the repository's own code"
    if _TEMPLATE_PATH_RE.search(path):
        return "file path marks it as a template/example rather than live configuration"
    return None


_CONFIDENCE_DOWNGRADE = {
    CONFIDENCE_HIGH: CONFIDENCE_MEDIUM,
    CONFIDENCE_MEDIUM: CONFIDENCE_LOW,
    CONFIDENCE_LOW: CONFIDENCE_LOW,
}


# ---------------------------------------------------------------------------
# Secret / config-file / infra-reference pattern catalog
# (assignment's "each required finding category" responsibility)
# ---------------------------------------------------------------------------

SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "aws_access_key_id", "category": CATEGORY_API_KEY, "confidence": CONFIDENCE_HIGH,
        "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "value_group": 0,
    },
    {
        "name": "aws_secret_access_key", "category": CATEGORY_CREDENTIAL, "confidence": CONFIDENCE_MEDIUM,
        "regex": re.compile(r'(?i)aws_?secret_?(?:access_?)?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})'),
        "value_group": 1,
    },
    {
        "name": "github_token", "category": CATEGORY_TOKEN, "confidence": CONFIDENCE_HIGH,
        "regex": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "value_group": 0,
    },
    {
        "name": "slack_token", "category": CATEGORY_TOKEN, "confidence": CONFIDENCE_HIGH,
        "regex": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"), "value_group": 0,
    },
    {
        "name": "google_api_key", "category": CATEGORY_API_KEY, "confidence": CONFIDENCE_HIGH,
        "regex": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "value_group": 0,
    },
    {
        "name": "stripe_live_key", "category": CATEGORY_API_KEY, "confidence": CONFIDENCE_HIGH,
        "regex": re.compile(r"\bsk_live_[0-9a-zA-Z]{16,64}\b"), "value_group": 0,
    },
    {
        "name": "private_key_block", "category": CATEGORY_CREDENTIAL, "confidence": CONFIDENCE_HIGH,
        "regex": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "value_group": 0,
        # The matched text is a constant PEM armour header, not the key material.
        # Fingerprinting it would give every private key ever found the SAME
        # fingerprint_sha256, and risk_engine.py discriminates leaked-credential
        # signals by that fingerprint — so N distinct leaked keys would collapse
        # into one signal and N-1 would vanish from the risk assessment.
        "value_is_marker": True,
    },
    {
        "name": "jwt_token", "category": CATEGORY_TOKEN, "confidence": CONFIDENCE_LOW,
        "regex": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "value_group": 0,
    },
    {
        "name": "db_connection_string", "category": CATEGORY_DB_CONNECTION, "confidence": CONFIDENCE_HIGH,
        "regex": re.compile(r'(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|jdbc:[a-z]+)://[^\s"\'<>]+'),
        "value_group": 0,
    },
    {
        "name": "generic_api_key_assignment", "category": CATEGORY_API_KEY, "confidence": CONFIDENCE_MEDIUM,
        "regex": re.compile(r'(?i)\bapi[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,64})["\']?'),
        "value_group": 1,
    },
    {
        "name": "generic_secret_assignment", "category": CATEGORY_CREDENTIAL, "confidence": CONFIDENCE_MEDIUM,
        "regex": re.compile(
            r'(?i)\b(?:secret|token|password|passwd|pwd)["\']?\s*[:=]\s*["\']?([A-Za-z0-9!@#$%^&*_\-/+=]{8,64})["\']?'
        ),
        "value_group": 1,
    },
    {
        "name": "internal_hostname_reference", "category": CATEGORY_INTERNAL_URL, "confidence": CONFIDENCE_MEDIUM,
        "regex": re.compile(
            r"(?i)\bhttps?://(?:[a-z0-9-]+\.)*(?:internal|intranet|corp|staging|stage|dev|test|admin|vpn)"
            r"(?:-[a-z0-9-]+)?\.[a-z]{2,}[^\s\"'<>]*"
        ),
        "value_group": 0,
    },
    {
        "name": "private_ip_reference", "category": CATEGORY_INFRA_REFERENCE, "confidence": CONFIDENCE_LOW,
        "regex": re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|"
            r"192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        "value_group": 0,
    },
]

# Path-based sensitive config-file detection (input-contract decision #4):
# matched independently of content-pattern hits.
CONFIG_FILE_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    (".env file", re.compile(r"(^|/)\.env(\..+)?$", re.IGNORECASE)),
    ("config file", re.compile(r"(^|/)config\.(json|ya?ml|php|py|xml|ini)$", re.IGNORECASE)),
    ("settings.py", re.compile(r"(^|/)settings\.py$", re.IGNORECASE)),
    ("application config", re.compile(r"(^|/)application\.(properties|ya?ml)$", re.IGNORECASE)),
    ("docker-compose file", re.compile(r"(^|/)docker-compose(\..+)?\.ya?ml$", re.IGNORECASE)),
    ("aws/git credentials", re.compile(r"(^|/)\.?(aws/credentials|git-credentials)$", re.IGNORECASE)),
    ("credentials file", re.compile(r"(^|/)credentials$", re.IGNORECASE)),
    ("secrets file", re.compile(r"(^|/)secrets?\.(json|ya?ml|txt)$", re.IGNORECASE)),
    ("SSH private key file", re.compile(r"(^|/)id_rsa(\.pub)?$", re.IGNORECASE)),
    ("PEM certificate/key file", re.compile(r"\.pem$", re.IGNORECASE)),
    ("key file", re.compile(r"\.key$", re.IGNORECASE)),
    ("wp-config.php", re.compile(r"(^|/)wp-config\.php$", re.IGNORECASE)),
    (".npmrc", re.compile(r"(^|/)\.npmrc$", re.IGNORECASE)),
    (".pypirc", re.compile(r"(^|/)\.pypirc$", re.IGNORECASE)),
    ("terraform.tfvars", re.compile(r"(^|/)terraform\.tfvars$", re.IGNORECASE)),
    (".htpasswd", re.compile(r"(^|/)\.htpasswd$", re.IGNORECASE)),
]


def _match_config_file_pattern(path: str) -> Optional[str]:
    """Return a human-readable label if `path` matches a known sensitive config-file pattern, else None."""
    if not path:
        return None
    for label, pattern in CONFIG_FILE_PATTERNS:
        if pattern.search(path):
            return label
    return None


# ---------------------------------------------------------------------------
# Private-repository safeguard
# ---------------------------------------------------------------------------

def _repo_object(item: Dict[str, Any]) -> Any:
    """
    Return the repository object embedded in a /search/code item, WITHOUT
    substituting a benign default.

    Coercing a missing or non-dict `repository` to `{}` before the private
    check would defeat `_is_private_repo`'s fail-closed branch: `{}` reads as
    public, so an item whose repository object could not be parsed would be
    evidenced and persisted even though its public/private state was never
    established. Returning the raw value keeps that decision with
    `_is_private_repo`.
    """
    if not isinstance(item, dict):
        return None
    return item.get("repository")


def _is_private_repo(repo_or_item: Dict[str, Any]) -> bool:
    """
    True if the embedded/standalone repository object is marked private.
    Applied to EVERY search result before any further use (module
    docstring, PRIVATE-REPOSITORY SAFEGUARD) — a token with private-repo
    access must never cause this module to read/evidence private content.
    """
    if not isinstance(repo_or_item, dict):
        return True  # fail closed: an unparseable repo object is treated as private/unsafe to use
    return bool(repo_or_item.get("private"))


# ---------------------------------------------------------------------------
# 1. GitHub Search API integration — code search
# ---------------------------------------------------------------------------

def search_github_code(
    query: str,
    token: Optional[str],
    timeout: float = DEFAULT_TIMEOUT,
    per_page: int = DEFAULT_PER_PAGE,
    base_url: str = GITHUB_CODE_SEARCH_API,
) -> Dict[str, Any]:
    """
    Search public code via GET /search/code?q=<query>, requesting the
    text-match media type so short content fragments are returned inline
    (module docstring, CONTENT-INSPECTION BOUNDARY). This module's only
    network interaction is with GitHub's public Search API — never the
    target itself, never a matched file's raw content, never a clone.

    GitHub does not accept unauthenticated code-search requests at all, so
    a missing token is reported as "missing_credentials" rather than
    attempted (module docstring, CREDENTIAL HANDLING).

    Returns {"status": "found"|"not_found"|"missing_credentials"|
             "unauthorized"|"rate_limited"|"invalid_query"|"error",
             "items": [...], "total_count": int, "incomplete_results": bool,
             "error": str|None}.
    """
    result: Dict[str, Any] = {
        "status": "error", "items": [], "total_count": 0,
        "total_count_reported": False, "items_examined": 0,
        "incomplete_results": False, "results_truncated": False, "error": None,
    }

    if not query or not query.strip():
        result["error"] = "query is required"
        return result

    if not token:
        result["status"] = "missing_credentials"
        result["error"] = (
            f"GitHub code search requires an authenticated token (set {GITHUB_TOKEN_ENV} "
            f"or pass github_token) — the GitHub Search API does not permit unauthenticated "
            f"code search."
        )
        return result

    headers = {
        "Accept": "application/vnd.github.text-match+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": DEFAULT_USER_AGENT,
    }
    params = {"q": query, "per_page": max(1, min(per_page, 100))}

    resp = None
    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=timeout)
    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        return result
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"connection error: {exc}"
        return result
    except requests.exceptions.RequestException as exc:
        result["error"] = f"request failed: {exc}"
        return result
    finally:
        if resp is not None:
            resp.close()

    status = _classify_github_status(resp)
    if status is not None:
        result["status"], result["error"] = status
        return result

    try:
        data = resp.json()
    except ValueError as exc:
        result["error"] = f"malformed JSON from GitHub code search API: {exc}"
        return result

    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        result["error"] = "unexpected GitHub code search API response structure (missing items[])"
        return result

    items = data["items"]
    result["items"] = items
    total = data.get("total_count")
    # A missing or non-integer total_count is not evidence that this page is
    # everything there is, so completeness is recorded as unknown rather than
    # inferred from the page size.
    result["total_count"] = total if isinstance(total, int) else len(items)
    result["total_count_reported"] = isinstance(total, int)
    result["items_examined"] = len(items)
    result["incomplete_results"] = bool(data.get("incomplete_results"))
    # This module deliberately requests a single page — it never paginates, so
    # it never multiplies its request volume against GitHub's search limits.
    # Whenever GitHub reports more matches than the page it returned, what was
    # examined here is a bounded sample, and saying so is the difference
    # between "checked" and "checked as far as one page reaches".
    result["results_truncated"] = bool(
        result["total_count_reported"] and result["total_count"] > len(items)
    )
    result["status"] = "found" if items else "not_found"
    return result


# ---------------------------------------------------------------------------
# 1. GitHub Search API integration — repository search
# ---------------------------------------------------------------------------

def search_github_repositories(
    query: str,
    token: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    per_page: int = DEFAULT_PER_PAGE,
    base_url: str = GITHUB_REPO_SEARCH_API,
) -> Dict[str, Any]:
    """
    Search public repositories via GET /search/repositories?q=<query>.
    Unlike code search, this endpoint is usable without a token (module
    docstring, CREDENTIAL HANDLING) — a missing token only lowers the
    rate-limit ceiling, it is never treated as "missing_credentials" here.

    Returns {"status": "found"|"not_found"|"unauthorized"|"rate_limited"|
             "invalid_query"|"error", "items": [...], "total_count": int,
             "incomplete_results": bool, "error": str|None}.
    """
    result: Dict[str, Any] = {
        "status": "error", "items": [], "total_count": 0,
        "total_count_reported": False, "items_examined": 0,
        "incomplete_results": False, "results_truncated": False, "error": None,
    }

    if not query or not query.strip():
        result["error"] = "query is required"
        return result

    headers = {"Accept": "application/vnd.github+json", "User-Agent": DEFAULT_USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    params = {"q": query, "per_page": max(1, min(per_page, 100))}

    resp = None
    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=timeout)
    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        return result
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"connection error: {exc}"
        return result
    except requests.exceptions.RequestException as exc:
        result["error"] = f"request failed: {exc}"
        return result
    finally:
        if resp is not None:
            resp.close()

    status = _classify_github_status(resp)
    if status is not None:
        result["status"], result["error"] = status
        return result

    try:
        data = resp.json()
    except ValueError as exc:
        result["error"] = f"malformed JSON from GitHub repository search API: {exc}"
        return result

    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        result["error"] = "unexpected GitHub repository search API response structure (missing items[])"
        return result

    items = data["items"]
    result["items"] = items
    total = data.get("total_count")
    # A missing or non-integer total_count is not evidence that this page is
    # everything there is, so completeness is recorded as unknown rather than
    # inferred from the page size.
    result["total_count"] = total if isinstance(total, int) else len(items)
    result["total_count_reported"] = isinstance(total, int)
    result["items_examined"] = len(items)
    result["incomplete_results"] = bool(data.get("incomplete_results"))
    # This module deliberately requests a single page — it never paginates, so
    # it never multiplies its request volume against GitHub's search limits.
    # Whenever GitHub reports more matches than the page it returned, what was
    # examined here is a bounded sample, and saying so is the difference
    # between "checked" and "checked as far as one page reaches".
    result["results_truncated"] = bool(
        result["total_count_reported"] and result["total_count"] > len(items)
    )
    result["status"] = "found" if items else "not_found"
    return result


def _github_error_message(resp: "requests.Response") -> Optional[str]:
    """Best-effort `message` field from a GitHub error body; never raises."""
    try:
        body = resp.json()
    except Exception:
        return None
    if isinstance(body, dict) and isinstance(body.get("message"), str):
        return body["message"]
    return None


def _classify_github_status(resp: "requests.Response") -> Optional[Tuple[str, Optional[str]]]:
    """
    Shared HTTP-status classification for both GitHub Search endpoints.
    Returns (status, error) if the response is not a usable 200, else None
    (caller should proceed to parse the body).
    """
    if resp.status_code == 401:
        return "unauthorized", "GitHub API rejected the configured token (HTTP 401)"

    if resp.status_code == 403:
        if resp.headers.get("X-RateLimit-Remaining") == "0":
            return "rate_limited", "GitHub API primary rate limit exceeded (HTTP 403, X-RateLimit-Remaining=0)"
        if resp.headers.get("Retry-After"):
            return (
                "rate_limited",
                f"GitHub API secondary rate limit / abuse detection triggered "
                f"(HTTP 403, Retry-After={resp.headers.get('Retry-After')}s)",
            )
        # GitHub documents that a secondary-rate-limit 403 may arrive with no
        # Retry-After header at all, identifiable only from the body message.
        # Classifying that as "unauthorized" tells the operator their token was
        # rejected and sends them off to reissue a perfectly good credential.
        message = _github_error_message(resp)
        if message and ("secondary rate limit" in message.lower() or "abuse detection" in message.lower()):
            return "rate_limited", f"GitHub API secondary rate limit triggered (HTTP 403): {message}"
        detail = f": {message}" if message else ""
        return (
            "unauthorized",
            f"GitHub API returned HTTP 403 (insufficient token scope or blocked request){detail}",
        )

    if resp.status_code == 422:
        message = "GitHub API rejected the search query as invalid (HTTP 422)"
        try:
            body = resp.json()
            if isinstance(body, dict) and body.get("errors"):
                first = body["errors"][0] if isinstance(body["errors"], list) and body["errors"] else {}
                if isinstance(first, dict) and first.get("message"):
                    message = f"GitHub API rejected the search query: {first['message']}"
        except ValueError:
            pass
        return "invalid_query", message

    if resp.status_code == 429:
        return "rate_limited", "HTTP 429 Too Many Requests from GitHub API"

    if resp.status_code >= 500:
        return "error", f"GitHub API returned HTTP {resp.status_code}"

    if resp.status_code != 200:
        return "error", f"GitHub API returned unexpected HTTP {resp.status_code}"

    return None


# ---------------------------------------------------------------------------
# 2. Evidence extraction: secrets, config files, internal URLs, infra refs
# ---------------------------------------------------------------------------

def _scan_fragment(
    fragment: str,
) -> Tuple[List[Dict[str, Any]], List[Tuple[int, int, str]], bool, bool]:
    """
    Run every secret pattern over one fragment.

    Returns (emitted matches, redaction spans, fragment_truncated,
    findings_capped).

    Every pattern is always run to completion over the (already length-capped)
    fragment, and every match contributes a redaction span even when the
    findings cap stops it becoming a finding. Stopping the scan early would
    leave the values of the patterns that never ran unredacted in the shared
    context — reintroducing exactly the co-located-secret leak `_redact_spans`
    exists to prevent. Running every pattern over the 64 KB ceiling costs
    ~0.03 s, so there is nothing to buy by stopping early.
    """
    matches: List[Dict[str, Any]] = []
    spans: List[Tuple[int, int, str]] = []
    fragment_truncated = len(fragment) > MAX_FRAGMENT_CHARS
    if fragment_truncated:
        fragment = fragment[:MAX_FRAGMENT_CHARS]
    capped = False

    for pat in SECRET_PATTERNS:
        try:
            for m in pat["regex"].finditer(fragment):
                group_idx = pat["value_group"]
                try:
                    value = m.group(group_idx) if group_idx else m.group(0)
                    start, end = m.start(group_idx), m.end(group_idx)
                except IndexError:  # defensive: malformed group index
                    continue
                if not value:
                    continue
                redacted_value = _redact_secret(value)
                spans.append((start, end, redacted_value))
                if len(matches) >= MAX_FINDINGS_PER_FRAGMENT:
                    capped = True
                    continue
                matches.append({
                    "pattern": pat, "value": value, "redacted_value": redacted_value,
                })
        except Exception:
            continue  # one malformed pattern must not abort the rest
    return matches, spans, fragment_truncated, capped


def extract_findings_from_code_item(
    item: Dict[str, Any], target: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Extract all category findings (secret-pattern matches + a possible
    config-file-path match) from one /search/code `items[]` entry.

    Private repositories are filtered out here as a last line of defense
    (module docstring, PRIVATE-REPOSITORY SAFEGUARD) even though callers
    are also expected to filter before calling this — and an item whose
    repository object is missing or unparseable is treated the same way,
    because its public/private state cannot be established. Never raises —
    a malformed item degrades to an empty list, not a run-aborting
    exception.

    `target`, when supplied, is only used to record whether the target
    string is actually present in the inspected fragment. That is an
    observation about how strong the link between this sighting and the
    target is, never a filter (module docstring, TARGET ASSOCIATION).
    """
    findings: List[Dict[str, Any]] = []
    try:
        if not isinstance(item, dict):
            return findings
        repo = _repo_object(item)
        if _is_private_repo(repo):
            return findings
        if not isinstance(repo, dict):  # unreachable via _is_private_repo, kept explicit
            return findings

        # A non-string path (malformed provider response) must not throw inside
        # the config-file matcher and take every secret finding in this item
        # down with it.
        path = _as_text(item.get("path")) or _as_text(item.get("name"))
        repo_full_name = repo.get("full_name")
        repo_html_url = repo.get("html_url")
        source_url = item.get("html_url")
        path_note = assess_path_authority(path)

        def _apply_downgrades(
            confidence: str, placeholder_reason: Optional[str]
        ) -> Tuple[str, List[str]]:
            reasons: List[str] = []
            if placeholder_reason:
                confidence = CONFIDENCE_LOW
                reasons.append(placeholder_reason)
            if path_note:
                confidence = _CONFIDENCE_DOWNGRADE.get(confidence, CONFIDENCE_LOW)
                reasons.append(path_note)
            return confidence, reasons

        cfg_label = _match_config_file_pattern(path)
        if cfg_label:
            cfg_confidence, cfg_reasons = _apply_downgrades(CONFIDENCE_MEDIUM, None)
            findings.append({
                "category": CATEGORY_CONFIG_FILE,
                "pattern_name": cfg_label,
                "confidence": cfg_confidence,
                "redacted_value": None,
                "fingerprint_sha256": None,
                "context": None,
                "path": path,
                "repo_full_name": repo_full_name,
                "repo_html_url": repo_html_url,
                "source_url": source_url,
                "note": "Path-based match: file path matches a known sensitive config-file pattern.",
                "quality_notes": cfg_reasons,
                "target_string_in_fragment": None,
                "fragment_truncated": False,
                "findings_capped": False,
            })

        fragments: List[str] = []
        text_matches = item.get("text_matches")
        if isinstance(text_matches, list):
            for tm in text_matches:
                if isinstance(tm, dict) and isinstance(tm.get("fragment"), str):
                    fragments.append(tm["fragment"])

        target_lower = target.lower() if isinstance(target, str) and target else None

        for fragment in fragments:
            matches, spans, fragment_truncated, capped = _scan_fragment(fragment)
            if not matches:
                continue
            # Every matched value in this fragment is redacted once, up front,
            # so no finding's stored context can carry a co-located secret
            # belonging to a different finding (input-contract decision #3).
            safe_context = _truncate(_redact_spans(fragment[:MAX_FRAGMENT_CHARS], spans))
            in_fragment = (target_lower in fragment.lower()) if target_lower else None
            for match in matches:
                pat = match["pattern"]
                placeholder_reason = (
                    None if pat.get("value_is_marker") else assess_placeholder(match["value"])
                )
                confidence, quality_notes = _apply_downgrades(pat["confidence"], placeholder_reason)
                note = None
                if pat["confidence"] != CONFIDENCE_HIGH:
                    note = (
                        "Generic keyword/pattern-based match; elevated false-positive risk "
                        "(e.g. non-secret variable names). Verify manually before acting on it."
                    )
                findings.append({
                    "category": pat["category"],
                    "pattern_name": pat["name"],
                    "confidence": confidence,
                    "redacted_value": match["redacted_value"],
                    # A pattern whose match is a constant marker (a PEM armour
                    # header) has no secret value to fingerprint; emitting one
                    # would make every such finding look like the same secret.
                    "fingerprint_sha256": None if pat.get("value_is_marker") else _fingerprint(match["value"]),
                    "context": safe_context,
                    "path": path,
                    "repo_full_name": repo_full_name,
                    "repo_html_url": repo_html_url,
                    "source_url": source_url,
                    "note": note,
                    "quality_notes": quality_notes,
                    "target_string_in_fragment": in_fragment,
                    "fragment_truncated": fragment_truncated,
                    "findings_capped": capped,
                })
    except Exception:
        return findings
    return findings


# ---------------------------------------------------------------------------
# Normalization + aggregation for surface_mapper.py
# ---------------------------------------------------------------------------

def normalize_repo_item(raw: Dict[str, Any], discovered_via: str) -> Optional[Dict[str, Any]]:
    """
    Normalize one repository object (either a `/search/repositories` item,
    or the embedded `repository` object of a `/search/code` item) into the
    common repo schema. Returns None for a private or unparseable repo
    (module docstring, PRIVATE-REPOSITORY SAFEGUARD).
    """
    if not isinstance(raw, dict) or _is_private_repo(raw):
        return None
    full_name = raw.get("full_name")
    if not full_name:
        return None
    owner = raw.get("owner") if isinstance(raw.get("owner"), dict) else {}
    return {
        "full_name": full_name,
        "html_url": raw.get("html_url"),
        "description": raw.get("description"),
        "owner": owner.get("login"),
        "fork": bool(raw.get("fork")),
        "language": raw.get("language"),
        "stars": raw.get("stargazers_count"),
        # Provider-supplied lifecycle/temporal state. Without it an archived
        # repository last pushed a decade ago is indistinguishable from an
        # actively maintained one, and every downstream consumer sees only
        # this module's own discovery timestamp — which says when ReconHound
        # looked, not how old the exposure is. Kept under GitHub's own field
        # names so the provenance of each value stays obvious; absent for the
        # repository objects embedded in /search/code items, which do not
        # carry them.
        "archived": raw.get("archived"),
        "pushed_at": raw.get("pushed_at"),
        "updated_at": raw.get("updated_at"),
        "created_at": raw.get("created_at"),
        "discovered_via": {discovered_via},
    }


def _aggregate_repo(agg: Dict[str, Dict[str, Any]], record: Optional[Dict[str, Any]]) -> None:
    if not record:
        return
    key = record["full_name"]
    if key not in agg:
        agg[key] = dict(record)
    else:
        agg[key]["discovered_via"] |= record["discovered_via"]
        for field in ("description", "language", "stars", "owner", "html_url",
                      "archived", "pushed_at", "updated_at", "created_at"):
            if not agg[key].get(field) and record.get(field):
                agg[key][field] = record[field]


def _aggregate_code_finding(
    agg: Dict[Tuple[Any, ...], Dict[str, Any]],
    finding: Dict[str, Any],
    query_label: str,
) -> None:
    """
    Merge one raw finding into the aggregation dict, keyed by
    (repo, path, category, fingerprint) so the same sighting surfaced by
    multiple dork queries is persisted once (input-contract decision #2).
    """
    # A marker-only pattern (see SECRET_PATTERNS "value_is_marker") emits no
    # fingerprint, so the sighting is keyed by its path instead. The
    # pattern name is part of the key because two different marker patterns in
    # the same file are two different sightings.
    fp_key = (
        finding.get("fingerprint_sha256")
        or f"path:{finding.get('path')}:{finding.get('pattern_name')}"
    )
    key = (finding.get("repo_full_name"), finding.get("path"), finding.get("category"), fp_key)
    if key not in agg:
        rec = dict(finding)
        rec["matched_via_queries"] = {query_label}
        agg[key] = rec
    else:
        existing = agg[key]
        existing["matched_via_queries"].add(query_label)
        # Keep the most cautious reading of the same sighting seen twice: any
        # query that saw a truncated fragment means part of it went uninspected,
        # and a quality note raised by one observation still applies.
        existing["fragment_truncated"] = bool(
            existing.get("fragment_truncated") or finding.get("fragment_truncated")
        )
        existing["findings_capped"] = bool(
            existing.get("findings_capped") or finding.get("findings_capped")
        )
        merged_notes = list(existing.get("quality_notes") or [])
        for note in finding.get("quality_notes") or []:
            if note not in merged_notes:
                merged_notes.append(note)
        existing["quality_notes"] = merged_notes
        if CONFIDENCE_ORDER.get(finding.get("confidence"), 3) < CONFIDENCE_ORDER.get(
            existing.get("confidence"), 3
        ):
            existing["confidence"] = finding["confidence"]
        # "The target string was seen next to this match" only needs to be true
        # of one observation to be a fact about the sighting.
        if finding.get("target_string_in_fragment"):
            existing["target_string_in_fragment"] = True


def persist_repository_findings(
    agg: Dict[str, Dict[str, Any]], target: str, store: Optional[PendingAssetsStore]
) -> List[str]:
    """Persist one `code_leak_repository` finding per discovered public repository."""
    errors: List[str] = []
    for full_name in sorted(agg):
        rec = agg[full_name]
        discovered_via = sorted(rec["discovered_via"])
        confidence = CONFIDENCE_HIGH if len(discovered_via) > 1 else CONFIDENCE_MEDIUM
        err = _safe_store_add(store, make_finding(
            finding_type="code_leak_repository",
            target=target,
            value={
                "full_name": full_name,
                "html_url": rec.get("html_url"),
                "description": rec.get("description"),
                "owner": rec.get("owner"),
                "fork": rec.get("fork"),
                "language": rec.get("language"),
                "stars": rec.get("stars"),
                "archived": rec.get("archived"),
                "pushed_at": rec.get("pushed_at"),
                "updated_at": rec.get("updated_at"),
                "created_at": rec.get("created_at"),
                "discovered_via": discovered_via,
            },
            evidence=[
                f"Public repository '{full_name}' matched target-scoped GitHub search "
                f"via {', '.join(discovered_via)}"
            ],
            confidence=confidence,
            metadata={"full_name": full_name, "discovered_via": discovered_via},
        ))
        if err:
            errors.append(err)
    return errors


def persist_code_findings(
    agg: Dict[Tuple[Any, ...], Dict[str, Any]], target: str, store: Optional[PendingAssetsStore]
) -> List[str]:
    """Persist one `code_leak_exposure` finding per aggregated (repo, path, category, value) sighting."""
    errors: List[str] = []
    for key in sorted(agg, key=lambda k: (str(k[0]), str(k[1]), str(k[2]), str(k[3]))):
        rec = agg[key]
        matched_via = sorted(rec["matched_via_queries"])
        # Confidence is the detection pattern's own confidence, NOT a function
        # of how many dorks surfaced the sighting. context.md §8 raises
        # confidence for "multiple independent converging signals", and two
        # dorks are not independent: DEFAULT_CODE_SEARCH_QUERIES' unqualified
        # `"{target}"` query is a strict superset of every keyword-qualified
        # query in the list, so any file matching `"{target}" password` matches
        # it by construction. Escalating on that guaranteed overlap promoted
        # essentially every MEDIUM keyword match to HIGH, and risk_engine.py's
        # CONFIDENCE_SEVERITY_CAP then let HIGH be reported as CRITICAL — so a
        # documentation placeholder read as a critical leaked credential.
        # The query set is still recorded below as evidence.
        confidence = rec["confidence"]

        evidence_line = (
            f"GitHub code search matched pattern '{rec['pattern_name']}' (category={rec['category']}) "
            f"in {rec.get('repo_full_name')}/{rec.get('path')} via quer{'ies' if len(matched_via) > 1 else 'y'} "
            f"[{', '.join(matched_via)}]"
        )
        if rec.get("redacted_value"):
            evidence_line += f"; matched value (redacted): {rec['redacted_value']}"
        evidence: List[str] = [evidence_line]
        # An assessment that lowered this finding's confidence is itself
        # evidence, and must travel with the finding rather than being applied
        # invisibly.
        for quality_note in rec.get("quality_notes") or []:
            evidence.append(f"Confidence reduced: {quality_note}")
        if rec.get("target_string_in_fragment") is False:
            evidence.append(
                "Target string was not present in the inspected fragment: this sighting is "
                "linked to the target only by the search query that surfaced the file, not by "
                "any observed reference to the target near the match."
            )
        if rec.get("fragment_truncated"):
            evidence.append(
                "The provider fragment exceeded this module's inspection ceiling and was "
                "truncated; the rest of it was not scanned."
            )
        if rec.get("findings_capped"):
            evidence.append(
                "The fragment produced more pattern matches than this module reports per "
                "fragment; matches beyond that cap were not turned into findings. Every "
                "matched value was still redacted from the stored excerpt."
            )

        err = _safe_store_add(store, make_finding(
            finding_type="code_leak_exposure",
            target=target,
            value={
                "category": rec["category"],
                "pattern_name": rec["pattern_name"],
                "repository": rec.get("repo_full_name"),
                "repo_html_url": rec.get("repo_html_url"),
                "path": rec.get("path"),
                "source_url": rec.get("source_url"),
                "redacted_value": rec.get("redacted_value"),
                "fingerprint_sha256": rec.get("fingerprint_sha256"),
                "context": rec.get("context"),
                "matched_via_queries": matched_via,
                "quality_notes": list(rec.get("quality_notes") or []),
                "target_string_in_fragment": rec.get("target_string_in_fragment"),
                "fragment_truncated": bool(rec.get("fragment_truncated")),
                "findings_capped": bool(rec.get("findings_capped")),
            },
            evidence=evidence,
            confidence=confidence,
            metadata={
                "category": rec["category"],
                "pattern_name": rec["pattern_name"],
                "repository": rec.get("repo_full_name"),
                "path": rec.get("path"),
                "source_url": rec.get("source_url"),
                "matched_query_count": len(matched_via),
                "note": rec.get("note"),
                "quality_notes": list(rec.get("quality_notes") or []),
                "target_string_in_fragment": rec.get("target_string_in_fragment"),
                "fragment_truncated": bool(rec.get("fragment_truncated")),
                "findings_capped": bool(rec.get("findings_capped")),
            },
        ))
        if err:
            errors.append(err)
    return errors


def persist_no_match_findings(
    no_match_queries: List[Tuple[str, str]], target: str, store: Optional[PendingAssetsStore]
) -> List[str]:
    """Persist a negative-result-memory finding for each code-search query that returned zero non-private hits."""
    errors: List[str] = []
    for label, query in no_match_queries:
        err = _safe_store_add(store, make_finding(
            finding_type="code_leak_checked_no_match",
            target=target,
            value={"query_label": label, "query": query},
            evidence=[f"GitHub code search for [{label}] ({query!r}) returned no (non-private) results"],
            confidence=CONFIDENCE_LOW,
            metadata={
                "query_label": label,
                "query": query,
                "checked_at": _now(),
                "note": (
                    "Negative-result-memory: absence of a GitHub code-search hit does not prove "
                    "the target has no exposed public code — GitHub's index may not yet cover a "
                    "recently-published file, or the code may live outside GitHub entirely."
                ),
                "scope": (
                    "This records only that this one query returned zero results that GitHub "
                    "reported as complete. Queries whose results were truncated, withheld or "
                    "incomplete are reported under stats.code_queries_inconclusive instead and "
                    "never recorded as a negative result."
                ),
            },
        ))
        if err:
            errors.append(err)
    return errors


# ---------------------------------------------------------------------------
# Module orchestration
# ---------------------------------------------------------------------------

def run_code_leak(
    target: str,
    output_dir: str = "output",
    github_token: Optional[str] = None,
    include_repo_search: bool = True,
    include_code_search: bool = True,
    repo_query: Optional[str] = None,
    code_queries: Optional[List[Tuple[str, str]]] = None,
    max_code_queries: Optional[int] = None,
    per_page: int = DEFAULT_PER_PAGE,
    timeout: float = DEFAULT_TIMEOUT,
    request_delay: float = DEFAULT_REQUEST_DELAY,
) -> Dict[str, Any]:
    """
    Run all Module 3 public-repository-intelligence checks against
    `target` and persist every discovery immediately to
    <output_dir>/pending_assets.json.

    A missing GitHub token never raises — code search (which mandates one)
    is skipped and clearly reported in `source_status["code_search"]`;
    repository search still runs (module docstring, CREDENTIAL HANDLING).
    """
    target = validate_target(target)
    store = PendingAssetsStore(output_dir=output_dir)

    token = github_token if github_token is not None else os.environ.get(GITHUB_TOKEN_ENV)
    queries = list(code_queries) if code_queries is not None else list(DEFAULT_CODE_SEARCH_QUERIES)
    if max_code_queries is not None:
        queries = queries[:max_code_queries]

    summary: Dict[str, Any] = {
        "target": target,
        "module": MODULE_NAME,
        "started_at": _now(),
        "source_status": {},
        "repositories": [],
        "findings": [],
        "stats": {},
        "errors": [],
    }

    repo_agg: Dict[str, Dict[str, Any]] = {}
    code_agg: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    no_match_queries: List[Tuple[str, str]] = []
    private_repos_skipped = 0
    items_unverifiable = 0
    queries_run = 0
    queries_incomplete = 0
    queries_inconclusive: List[str] = []
    queries_skipped: List[str] = []

    # --- Repository search (token optional) ---
    if include_repo_search:
        q = repo_query or DEFAULT_REPO_SEARCH_QUERY_TEMPLATE.format(target=target)
        try:
            r = search_github_repositories(q, token=token, timeout=timeout, per_page=per_page)
        except Exception as exc:  # a single search call must not abort the rest
            r = {"status": "error", "error": str(exc), "items": [], "total_count": 0}
        summary["source_status"]["repo_search"] = {
            "status": r["status"], "error": r.get("error"), "total_count": r.get("total_count", 0),
            "total_count_reported": r.get("total_count_reported", False),
            "items_examined": r.get("items_examined", 0),
            "incomplete_results": r.get("incomplete_results", False),
            "results_truncated": r.get("results_truncated", False),
        }
        if r["status"] == "found":
            for raw in r["items"]:
                try:
                    # `raw` goes to _is_private_repo unchanged: a non-dict item
                    # fails closed there, whereas substituting {} would read as
                    # public and let an unverifiable result through.
                    if _is_private_repo(raw):
                        if isinstance(raw, dict):
                            private_repos_skipped += 1
                        else:
                            items_unverifiable += 1
                        continue
                    norm = normalize_repo_item(raw, "repo_search")
                except Exception as exc:
                    norm = None
                    summary["errors"].append({"stage": "normalize_repo_item", "error": str(exc)})
                _aggregate_repo(repo_agg, norm)

    # --- Code search (token mandatory) ---
    if include_code_search:
        if not token:
            summary["source_status"]["code_search"] = {
                "status": "missing_credentials",
                "error": f"GitHub code search requires a token (set {GITHUB_TOKEN_ENV})",
            }
        else:
            per_query_status: List[Dict[str, Any]] = []
            for idx, (label, template) in enumerate(queries):
                try:
                    # Callers may override the dork list; a template carrying a
                    # stray brace must cost that one query, not the whole run
                    # (including every repository already discovered above,
                    # which is not persisted until after this loop).
                    query_str = template.format(target=target)
                except (KeyError, IndexError, ValueError) as exc:
                    summary["errors"].append({
                        "stage": "code_search_query_template", "query": label,
                        "error": f"unusable query template {template!r}: {exc}",
                    })
                    queries_skipped.append(label)
                    continue
                try:
                    r = search_github_code(query_str, token=token, timeout=timeout, per_page=per_page)
                except Exception as exc:
                    r = {"status": "error", "error": str(exc), "items": [], "total_count": 0}
                queries_run += 1
                truncated = bool(r.get("results_truncated")) or bool(r.get("incomplete_results"))
                if truncated:
                    queries_incomplete += 1
                per_query_status.append({
                    "label": label, "query": query_str, "status": r["status"],
                    # Whether this query's outcome may be read as a statement
                    # about the target at all. Only a conclusive, complete,
                    # zero-result search becomes negative-result memory; every
                    # other outcome (error, truncation, withheld results) is
                    # explicitly not a conclusion.
                    "conclusive": r["status"] in ("found", "not_found"),
                    "error": r.get("error"), "total_count": r.get("total_count", 0),
                    "total_count_reported": r.get("total_count_reported", False),
                    "items_examined": r.get("items_examined", 0),
                    # GitHub's own "this search did not complete" flag. It was
                    # previously parsed and then dropped, so a provider-truncated
                    # search was indistinguishable from an exhaustive one.
                    "incomplete_results": r.get("incomplete_results", False),
                    "results_truncated": r.get("results_truncated", False),
                })

                if r["status"] == "found":
                    any_usable = False
                    withheld = 0
                    for item in r["items"]:
                        try:
                            # Unchanged, so a missing/non-dict repository object
                            # fails closed rather than being read as public.
                            repo = _repo_object(item)
                            if _is_private_repo(repo):
                                withheld += 1
                                if isinstance(repo, dict):
                                    private_repos_skipped += 1
                                else:
                                    items_unverifiable += 1
                                continue
                            any_usable = True
                            _aggregate_repo(repo_agg, normalize_repo_item(repo, "code_search"))
                            for finding in extract_findings_from_code_item(item, target=target):
                                _aggregate_code_finding(code_agg, finding, label)
                        except Exception as exc:
                            summary["errors"].append({"stage": "extract_findings", "query": label, "error": str(exc)})
                    # Negative-result memory records "checked and not found". A
                    # page whose every result was filtered out as private or
                    # unverifiable, against a total_count GitHub reports as
                    # non-zero, was not "not found" — it was not visible from
                    # here. Recording it as a negative result would write a
                    # false CHECK_NOT_FOUND state into surface_mapper's memory
                    # and suppress the check elsewhere.
                    if not any_usable:
                        # Results existed and were withheld: that is not
                        # absence, whatever total_count says.
                        if withheld or truncated:
                            queries_inconclusive.append(label)
                            per_query_status[-1]["conclusive"] = False
                            reasons = []
                            if withheld:
                                reasons.append(
                                    f"{withheld} of {len(r['items'])} result(s) on the returned "
                                    f"page were withheld (private or unverifiable repository)"
                                )
                            if truncated:
                                reasons.append(
                                    "the provider truncated the result set or reported the "
                                    "search as incomplete"
                                )
                            per_query_status[-1]["inconclusive_reason"] = "; ".join(reasons)
                        else:
                            no_match_queries.append((label, query_str))
                elif r["status"] == "not_found":
                    if truncated:
                        # Zero items but the provider says the search did not
                        # complete: inconclusive, not a clean negative.
                        queries_inconclusive.append(label)
                        per_query_status[-1]["conclusive"] = False
                        per_query_status[-1]["inconclusive_reason"] = (
                            "provider reported incomplete_results for a search that returned no items"
                        )
                    else:
                        no_match_queries.append((label, query_str))
                elif r["status"] in ("unauthorized", "rate_limited"):
                    # Further calls will fail identically or burn the same limit — stop, don't retry blindly.
                    queries_skipped.extend(lbl for lbl, _ in queries[idx + 1:])
                    summary["errors"].append({"stage": "code_search", "query": label, "error": r.get("error")})
                    break
                else:
                    summary["errors"].append({"stage": "code_search", "query": label, "error": r.get("error")})

                if request_delay > 0 and idx < len(queries) - 1:
                    time.sleep(request_delay)

            summary["source_status"]["code_search_queries"] = per_query_status

    repo_errors = persist_repository_findings(repo_agg, target, store)
    if repo_errors:
        summary["errors"].append({"stage": "persist_repositories", "errors": repo_errors})

    code_errors = persist_code_findings(code_agg, target, store)
    if code_errors:
        summary["errors"].append({"stage": "persist_code_findings", "errors": code_errors})

    if no_match_queries:
        negmem_errors = persist_no_match_findings(no_match_queries, target, store)
        if negmem_errors:
            summary["errors"].append({"stage": "negative_result_memory", "errors": negmem_errors})

    summary["repositories"] = []
    for full_name in sorted(repo_agg):
        rec = dict(repo_agg[full_name])
        rec["discovered_via"] = sorted(rec["discovered_via"])
        summary["repositories"].append(rec)

    findings_list = []
    for key in sorted(code_agg, key=lambda k: (str(k[0]), str(k[1]), str(k[2]), str(k[3]))):
        rec = dict(code_agg[key])
        rec["matched_via_queries"] = sorted(rec["matched_via_queries"])
        findings_list.append(rec)
    summary["findings"] = findings_list

    summary["stats"] = {
        "repositories_found": len(repo_agg),
        "code_findings_found": len(code_agg),
        "findings_by_category": {
            cat: sum(1 for r in code_agg.values() if r["category"] == cat) for cat in sorted(CATEGORIES)
        },
        "private_repos_skipped": private_repos_skipped,
        # Items whose repository object could not be parsed, so their
        # public/private state was never established and they were withheld.
        "items_unverifiable_repo": items_unverifiable,
        "code_queries_run": queries_run,
        "code_queries_skipped": queries_skipped,
        "code_queries_no_match": len(no_match_queries),
        # Queries whose result set the provider truncated or did not complete:
        # what was inspected is a bounded sample, not the whole match set.
        "code_queries_incomplete": queries_incomplete,
        # Queries that yielded nothing usable for a reason other than absence.
        # Deliberately NOT counted as no-match: "inconclusive" and "checked and
        # not found" are different states and only the second is negative-result
        # memory (context.md §8).
        "code_queries_inconclusive": queries_inconclusive,
        # The same signal as a scalar. core/orchestrator.py's _compact_stats
        # keeps only scalar entries from a module's nested `stats`, so without
        # this the "this run reached no conclusion" signal would not reach the
        # execution record at all — which is precisely the signal that must not
        # be lost. Emitted from this side rather than by changing the
        # orchestrator's contract.
        "code_queries_inconclusive_count": len(queries_inconclusive),
    }
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="code_leak.py",
        description="ReconHound Module 3 — public GitHub repository/code intelligence "
                     "(standalone test entry point).",
    )
    parser.add_argument("--target", required=True, help="Target domain, e.g. example.com")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--github-token", default=None, help=f"GitHub token (or set {GITHUB_TOKEN_ENV})")
    parser.add_argument("--no-repo-search", action="store_true", help="Skip repository search")
    parser.add_argument("--no-code-search", action="store_true", help="Skip code search")
    parser.add_argument("--max-code-queries", type=int, default=None, help="Cap the number of code-search dorks run")
    parser.add_argument("--per-page", type=int, default=DEFAULT_PER_PAGE, help="Results per GitHub search request")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-query network timeout (seconds)")
    parser.add_argument("--request-delay", type=float, default=DEFAULT_REQUEST_DELAY,
                         help="Delay between successive code-search requests (seconds)")
    args = parser.parse_args()

    try:
        result = run_code_leak(
            args.target,
            output_dir=args.output_dir,
            github_token=args.github_token,
            include_repo_search=not args.no_repo_search,
            include_code_search=not args.no_code_search,
            max_code_queries=args.max_code_queries,
            per_page=args.per_page,
            timeout=args.timeout,
            request_delay=args.request_delay,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
