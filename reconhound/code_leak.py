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
vuln_intel.py's and passive_intel.py's module docstrings, this repository
is already operating under an explicit, user-approved deviation from that
order — surface_mapper.py has not been implemented yet. This module
continues under the same deviation, for the same reason: it is implemented
as a fully standalone producer that does not implement, replace, or depend
on surface_mapper.py's correlation engine, and does not touch any other
unimplemented module (risk_engine.py, core/orchestrator.py, reconhound.py,
tech_fingerprint.py, osint_engine.py, etc.).

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
query that completes with zero (non-private) hits gets an explicit
`code_leak_checked_no_match` finding (mirroring passive_intel.py's
`passive_intel_checked_no_data` / vuln_intel.py's
`vuln_intel_checked_no_match` precedent) rather than silence.

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
     persistence — see `_aggregate_code_finding` — both to avoid duplicate
     pending_assets.json entries and because independent queries
     converging on the same sighting is itself a confidence signal
     (context.md §8): confidence is escalated to HIGH when >=2 distinct
     queries surface the same aggregated finding.
  3. Secrets are never stored verbatim. Every matched value is reduced to
     `_redact_secret()` (first/last few characters, middle masked) plus a
     SHA-256 `fingerprint_sha256` (for downstream exact-match correlation
     without re-exposing the value) — satisfying the assignment's "avoid
     storing complete secrets unnecessarily... preserve enough evidence to
     identify and investigate" instruction.
  4. Category taxonomy (assignment's required finding categories) is
     enforced as a closed set: api_key, token, credential,
     db_connection_string, config_file, internal_url,
     infrastructure_reference — see CATEGORIES. `config_file` findings are
     path-based (a matched result's file path itself is a known
     sensitive-config filename, e.g. `.env`, `wp-config.php`,
     `.aws/credentials`) rather than content-pattern-based, and are
     reported independently of whether that same file also triggered a
     content-based secret match.
  5. GitHub Search API response shapes below reflect GitHub's public REST
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


def _truncate(text: str, limit: int = 300) -> str:
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + "…"


def _redact_fragment(fragment: str, start: int, end: int, redacted_value: str) -> str:
    """Return `fragment` with the raw-secret span [start:end) replaced by its redacted form."""
    return f"{fragment[:start]}«{redacted_value}»{fragment[end:]}"


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
        "incomplete_results": False, "error": None,
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
    result["total_count"] = total if isinstance(total, int) else len(items)
    result["incomplete_results"] = bool(data.get("incomplete_results"))
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
        "incomplete_results": False, "error": None,
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
    result["total_count"] = total if isinstance(total, int) else len(items)
    result["incomplete_results"] = bool(data.get("incomplete_results"))
    result["status"] = "found" if items else "not_found"
    return result


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
        return "unauthorized", "GitHub API returned HTTP 403 (insufficient token scope or blocked request)"

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

def extract_findings_from_code_item(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract all category findings (secret-pattern matches + a possible
    config-file-path match) from one /search/code `items[]` entry.

    Private repositories are filtered out here as a last line of defense
    (module docstring, PRIVATE-REPOSITORY SAFEGUARD) even though callers
    are also expected to filter before calling this. Never raises — a
    malformed item degrades to an empty list, not a run-aborting
    exception.
    """
    findings: List[Dict[str, Any]] = []
    try:
        if not isinstance(item, dict):
            return findings
        repo = item.get("repository") if isinstance(item.get("repository"), dict) else {}
        if _is_private_repo(repo):
            return findings

        path = item.get("path") or item.get("name") or ""
        repo_full_name = repo.get("full_name")
        repo_html_url = repo.get("html_url")
        source_url = item.get("html_url")

        cfg_label = _match_config_file_pattern(path)
        if cfg_label:
            findings.append({
                "category": CATEGORY_CONFIG_FILE,
                "pattern_name": cfg_label,
                "confidence": CONFIDENCE_MEDIUM,
                "redacted_value": None,
                "fingerprint_sha256": None,
                "context": None,
                "path": path,
                "repo_full_name": repo_full_name,
                "repo_html_url": repo_html_url,
                "source_url": source_url,
                "note": "Path-based match: file path matches a known sensitive config-file pattern.",
            })

        fragments: List[str] = []
        text_matches = item.get("text_matches")
        if isinstance(text_matches, list):
            for tm in text_matches:
                if isinstance(tm, dict) and isinstance(tm.get("fragment"), str):
                    fragments.append(tm["fragment"])

        for fragment in fragments:
            for pat in SECRET_PATTERNS:
                try:
                    for m in pat["regex"].finditer(fragment):
                        group_idx = pat["value_group"]
                        try:
                            value = m.group(group_idx) if group_idx else m.group(0)
                        except IndexError:  # defensive: malformed group index
                            continue
                        if not value:
                            continue
                        note = None
                        if pat["confidence"] != CONFIDENCE_HIGH:
                            note = (
                                "Generic keyword/pattern-based match; elevated false-positive risk "
                                "(e.g. non-secret variable names). Verify manually before acting on it."
                            )
                        redacted_value = _redact_secret(value)
                        findings.append({
                            "category": pat["category"],
                            "pattern_name": pat["name"],
                            "confidence": pat["confidence"],
                            "redacted_value": redacted_value,
                            "fingerprint_sha256": _fingerprint(value),
                            # Never persist the raw fragment: the matched secret span itself is
                            # replaced by its already-redacted form before truncation/storage
                            # (module docstring, input-contract decision #3).
                            "context": _truncate(_redact_fragment(fragment, m.start(group_idx), m.end(group_idx), redacted_value)),
                            "path": path,
                            "repo_full_name": repo_full_name,
                            "repo_html_url": repo_html_url,
                            "source_url": source_url,
                            "note": note,
                        })
                except Exception:
                    continue  # one malformed pattern/fragment must not abort the rest
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
        for field in ("description", "language", "stars", "owner", "html_url"):
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
    fp_key = finding.get("fingerprint_sha256") or f"path:{finding.get('path')}"
    key = (finding.get("repo_full_name"), finding.get("path"), finding.get("category"), fp_key)
    if key not in agg:
        rec = dict(finding)
        rec["matched_via_queries"] = {query_label}
        agg[key] = rec
    else:
        agg[key]["matched_via_queries"].add(query_label)


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
        confidence = CONFIDENCE_HIGH if len(matched_via) > 1 else rec["confidence"]

        evidence_line = (
            f"GitHub code search matched pattern '{rec['pattern_name']}' (category={rec['category']}) "
            f"in {rec.get('repo_full_name')}/{rec.get('path')} via quer{'ies' if len(matched_via) > 1 else 'y'} "
            f"[{', '.join(matched_via)}]"
        )
        if rec.get("redacted_value"):
            evidence_line += f"; matched value (redacted): {rec['redacted_value']}"

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
            },
            evidence=[evidence_line],
            confidence=confidence,
            metadata={
                "category": rec["category"],
                "pattern_name": rec["pattern_name"],
                "repository": rec.get("repo_full_name"),
                "path": rec.get("path"),
                "source_url": rec.get("source_url"),
                "matched_query_count": len(matched_via),
                "note": rec.get("note"),
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
    queries_run = 0
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
        }
        if r["status"] == "found":
            for raw in r["items"]:
                try:
                    if _is_private_repo(raw if isinstance(raw, dict) else {}):
                        private_repos_skipped += 1
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
                query_str = template.format(target=target)
                try:
                    r = search_github_code(query_str, token=token, timeout=timeout, per_page=per_page)
                except Exception as exc:
                    r = {"status": "error", "error": str(exc), "items": [], "total_count": 0}
                queries_run += 1
                per_query_status.append({
                    "label": label, "query": query_str, "status": r["status"],
                    "error": r.get("error"), "total_count": r.get("total_count", 0),
                })

                if r["status"] == "found":
                    any_usable = False
                    for item in r["items"]:
                        try:
                            repo = item.get("repository") if isinstance(item, dict) else None
                            if _is_private_repo(repo if isinstance(repo, dict) else {}):
                                private_repos_skipped += 1
                                continue
                            any_usable = True
                            _aggregate_repo(repo_agg, normalize_repo_item(repo, "code_search"))
                            for finding in extract_findings_from_code_item(item):
                                _aggregate_code_finding(code_agg, finding, label)
                        except Exception as exc:
                            summary["errors"].append({"stage": "extract_findings", "query": label, "error": str(exc)})
                    if not any_usable:
                        no_match_queries.append((label, query_str))
                elif r["status"] == "not_found":
                    no_match_queries.append((label, query_str))
                elif r["status"] in ("unauthorized", "rate_limited"):
                    # Further calls will fail identically or burn the same limit — stop, don't retry blindly.
                    queries_skipped = [lbl for lbl, _ in queries[idx + 1:]]
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
        "code_queries_run": queries_run,
        "code_queries_skipped": queries_skipped,
        "code_queries_no_match": len(no_match_queries),
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
