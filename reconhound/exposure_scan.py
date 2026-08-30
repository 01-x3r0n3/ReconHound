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
  2. Path name alone never determines "confirmed exposure" (assignment
     brief: "classified according to observed evidence rather than path
     name alone"). evaluate_exposure() applies a category-specific content
     signature check (e.g. ".git/HEAD" must actually contain a git ref or
     SHA; ".env" must actually contain dotenv-style KEY=VALUE lines; a
     ".sql" dump must actually contain SQL-dump markers or dump-file magic
     bytes) before returning "confirmed_exposure". Without a matching
     signature, a non-404 hit is downgraded to "likely_exposure" or
     "interesting_unconfirmed" rather than claimed as confirmed. A
     directory-listing check (Apache "Index of /" / nginx "Directory
     listing for") is applied to every directory-kind candidate,
     independent of category, since it is itself direct, unambiguous
     evidence of exposure.
  3. Same soft-404 baseline heuristic as endpoint_discovery.py's decision
     #2 (one random near-certainly-absent path probed per origin, body
     fingerprinted, near-identical 2xx responses downgraded to
     `possible_soft_404_match`, LOW confidence) — reused here for the same
     reason: guessed wordlist paths are frequently wrong, and many apps
     return HTTP 200 with a generic/SPA/catch-all page instead of a real
     404. Documented as a best-effort heuristic, not exhaustive.
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
     output) using that same pattern, and additionally always runs OPTIONS
     against every URL this module itself confirms or flags as
     likely/interesting during its own sensitive-resource sweep — a
     natural, self-contained "relevant discovered endpoints" set requiring
     no external wiring.
  6. Error-page intelligence (analyze_error_page) is applied opportunistically
     to every response body this module already fetched for another reason
     (sensitive-resource probing, robots.txt/sitemap.xml, OPTIONS) — never
     by sending an extra/malformed request purely to trigger an error, per
     the assignment brief's explicit "do not intentionally trigger
     destructive or abusive errors" boundary.
  7. Only GET and OPTIONS requests are made (OPTIONS being this module's
     one explicitly named responsibility). No state-changing methods; no
     authentication attempts against discovered panels/credential files;
     no bucket writes/deletes; discovered ".env"/credential-shaped content
     is recorded as evidence text (truncated, see MAX_EXCERPT_CHARS) for
     manual verification, never parsed for literal secret values or used
     to authenticate anywhere — this module discovers exposure, it does
     not exploit it.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other implemented module). Output is intended to feed
surface_mapper.py (module 6, not yet implemented) — this module does not
implement or call into surface_mapper, http_analyzer's live analysis,
ssl_analyzer, wayback_intel, vuln_intel, risk_engine, orchestrator,
report_generator, or any other module not already implemented.

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

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)

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


def _in_scope_host(hostname: str, target: str) -> bool:
    hostname = hostname.strip().rstrip(".").lower()
    target = target.strip().rstrip(".").lower()
    return hostname == target or hostname.endswith("." + target)


def validate_exposure_target(url: str, target: Optional[str] = None) -> str:
    """
    Validate that `url` is a syntactically valid http(s) URL, and — if
    `target` is supplied — that its hostname is the target itself or a
    subdomain of it (an IP-literal host is allowed through without an
    in-scope check, matching the rest of ReconHound's active modules).

    This governs the target's own web surface only. Cloud storage
    resources (S3/GCS/Azure hostnames) are never in-scope under this
    function — see check_cloud_resource / discover_cloud_exposure and
    module docstring decision #4.
    """
    if not isinstance(url, str) or not url.strip():
        raise ScopeError("URL must be a non-empty string.")

    candidate = url.strip()
    parsed = urllib.parse.urlsplit(candidate)

    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"URL must use http:// or https://, not {parsed.scheme!r}: {url!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ScopeError(f"URL must include a hostname: {url!r}")

    if target and not _is_ip_literal(hostname) and not _in_scope_host(hostname, target):
        raise ScopeError(f"URL host {hostname!r} is not in scope for target {target!r}: {url!r}")

    return candidate


# ---------------------------------------------------------------------------
# Evidence-model helpers (mirrors the other modules' model; kept local per
# modular independence)
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
    scan. Returns None on success, or an error message the caller is
    responsible for recording (never silently discarded).
    """
    if store is None:
        return None
    try:
        store.add(finding)
        return None
    except PersistenceError as exc:
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


def _url_for_path(root: str, entry: str) -> str:
    root = _ensure_trailing_slash(root)
    return urllib.parse.urljoin(root, entry.lstrip("/"))


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


def _excerpt(body: Optional[str], max_chars: int = MAX_EXCERPT_CHARS) -> Optional[str]:
    """Concise, size-bounded evidence excerpt — never the full body (context.md §8's
    evidence lists should stay useful and reviewable, not a body dump)."""
    if not body:
        return None
    collapsed = re.sub(r"\s+", " ", body).strip()
    if not collapsed:
        return None
    return collapsed[:max_chars] + ("…" if len(collapsed) > max_chars else "")


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
        "elapsed_seconds": None, "error": None,
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


def _probe_soft_404(origin: str, timeout: float) -> Dict[str, Any]:
    """Fingerprint `origin`'s "not found" response via one random, near-certainly-absent path."""
    probe_path = f"reconhound-exposure-check-{uuid.uuid4().hex[:12]}"
    resp = fetch_url(_ensure_trailing_slash(origin) + probe_path, timeout=timeout)
    if resp["status"] != "found":
        return {"available": False}
    length, digest = _content_signature(resp.get("body") or "")
    return {"available": True, "status_code": resp["status_code"], "content_length": length, "body_hash": digest}


def _matches_soft_404(resp: Dict[str, Any], baseline: Optional[Dict[str, Any]]) -> bool:
    if not baseline or not baseline.get("available"):
        return False
    if resp.get("status_code") != baseline.get("status_code"):
        return False
    length, digest = _content_signature(resp.get("body") or "")
    return digest == baseline.get("body_hash") or _lengths_close(length, baseline.get("content_length"))


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

_DIRECTORY_LISTING_RE = re.compile(
    r"(Index of /|<title>\s*Directory listing for|\bParent Directory\b)", re.IGNORECASE
)


def detect_directory_listing(body: Optional[str]) -> Optional[str]:
    """Return matched evidence text if `body` looks like an autoindex directory listing, else None."""
    if not body:
        return None
    match = _DIRECTORY_LISTING_RE.search(body)
    return match.group(0) if match else None


# ---------------------------------------------------------------------------
# Category-specific evidence signatures (never claim "confirmed" from a
# path name alone — see module docstring, decision #2)
# ---------------------------------------------------------------------------

_GIT_REF_RE = re.compile(r"^ref:\s*refs/", re.IGNORECASE)
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_GIT_CONFIG_SECTION_RE = re.compile(r"\[core\]", re.IGNORECASE)

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

_CONFIG_SIGNATURE_RE = re.compile(
    r"(<\?php|^\[\w+\]|^[a-zA-Z_][\w.\-]*:\s|\"services\"\s*:|version:\s*[\"']?[23])",
    re.MULTILINE,
)

_HTPASSWD_LINE_RE = re.compile(r"(?m)^[\w.\-]+:\$?(apr1|2y|2b|1)?\$?[\w./$]{10,}$")

_ADMIN_SIGNAL_RE = re.compile(
    r"(wp-admin|phpmyadmin|cpanel|administration|dashboard|type=[\"']?password[\"']?)",
    re.IGNORECASE,
)

_LOG_LINE_RE = re.compile(r"(?m)^\s*(\[\d{4}-\d{2}-\d{2}|\[\w+\]|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")


def _check_version_control(path: str, body: Optional[str]) -> Optional[str]:
    body = body or ""
    if path.rstrip("/").endswith("HEAD"):
        stripped = body.strip()
        if _GIT_REF_RE.match(stripped) or _GIT_SHA_RE.match(stripped):
            return f"'{path}' body matches a git HEAD reference/SHA format"
    if path.rstrip("/").endswith("config") and _GIT_CONFIG_SECTION_RE.search(body):
        return f"'{path}' body contains a git config [core] section"
    return None


def _check_environment_file(body: Optional[str], content_type: Optional[str]) -> Optional[str]:
    body = body or ""
    if content_type and "html" in content_type.lower():
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


def _check_archive_file(raw_prefix: bytes, content_type: Optional[str]) -> Optional[str]:
    for magic, description in _ARCHIVE_MAGIC_BYTES:
        if raw_prefix.startswith(magic):
            return description
    if content_type and any(
        m in content_type.lower() for m in ("zip", "x-gzip", "x-tar", "x-7z", "x-rar", "octet-stream")
    ):
        return f"Content-Type {content_type!r} suggests an archive/binary payload"
    return None


def _check_configuration_file(body: Optional[str], content_type: Optional[str]) -> Optional[str]:
    body = body or ""
    if content_type and "html" in content_type.lower():
        return None
    if content_type and "json" in content_type.lower():
        try:
            parsed = json.loads(body)
            if isinstance(parsed, (dict, list)):
                return "body parses as valid JSON matching the requested config/manifest filename"
        except (ValueError, TypeError):
            pass
    match = _CONFIG_SIGNATURE_RE.search(body)
    if match:
        return f"body contains a structured-config signature ({match.group(0)!r})"
    return None


def _check_credential_material(path: str, body: Optional[str]) -> Optional[str]:
    body = body or ""
    if path.endswith(".htpasswd") and _HTPASSWD_LINE_RE.search(body):
        return "body contains a line matching the htpasswd username:hash format"
    return None


def _check_administrative_panel(status_code: Optional[int], body: Optional[str]) -> Tuple[Optional[str], str]:
    """Returns (evidence_or_None, strength) where strength in {'strong','weak'}."""
    body = body or ""
    match = _ADMIN_SIGNAL_RE.search(body)
    if match:
        return f"body/markup contains admin-panel signal {match.group(0)!r}", "strong"
    if status_code in (401, 403):
        return f"HTTP {status_code} on an administrative-panel-shaped path (exists, access-restricted)", "weak"
    return None, "weak"


def _check_log_file(body: Optional[str], content_type: Optional[str]) -> Optional[str]:
    body = body or ""
    if content_type and "html" in content_type.lower():
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
    ("php_fatal_error", re.compile(r"Fatal error:.*?on line \d+", re.I | re.S), None),
    ("python_traceback", re.compile(r"Traceback \(most recent call last\):"), None),
    ("nodejs_stack_trace", re.compile(r"at [\w.$ ]+\([^)]+\.js:\d+:\d+\)"), None),
]

_INTERNAL_PATH_PATTERNS = [
    re.compile(r"/(?:var|usr|home|opt|srv|etc)/[^\s\"'<>]+"),
    re.compile(r"[A-Za-z]:\\\\?[^\s\"'<>]+"),
]

_SERVER_VERSION_RE = re.compile(r"([A-Za-z][\w.\-]*)/(\d[\w.\-]*)")


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
    indicators: List[Dict[str, str]] = []

    for name, marker_re, version_re in _FRAMEWORK_SIGNATURES:
        marker_match = marker_re.search(body)
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
            "evidence": f"Matched {name!r} signature: {marker_match.group(0)[:120]!r}",
        })

    server_header = _ci_get(headers or {}, "Server")
    if server_header:
        match = _SERVER_VERSION_RE.search(server_header)
        if match:
            indicators.append({
                "indicator_type": "server_software_version",
                "framework": match.group(1),
                "version": match.group(2),
                "evidence": f"Server header: {server_header!r}",
            })

    x_powered_by = _ci_get(headers or {}, "X-Powered-By")
    if x_powered_by:
        indicators.append({
            "indicator_type": "x_powered_by_header",
            "framework": x_powered_by,
            "version": None,
            "evidence": f"X-Powered-By header: {x_powered_by!r}",
        })

    internal_paths: List[str] = []
    for pattern in _INTERNAL_PATH_PATTERNS:
        for match in pattern.findall(body):
            if match not in internal_paths:
                internal_paths.append(match)
    internal_paths = internal_paths[:10]
    for path in internal_paths:
        indicators.append({
            "indicator_type": "internal_filesystem_path",
            "framework": None,
            "version": None,
            "evidence": f"Internal path referenced in response content: {path!r}",
        })

    stack_trace_detected = bool(re.search(r"Traceback \(most recent call last\)|at [\w.$]+\(.+:\d+:\d+\)", body))

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
) -> Tuple[str, str, List[str], Optional[str]]:
    """
    Classify one fetched candidate into (discovery_type, confidence,
    evidence_notes, excerpt). Never returns "confirmed_exposure" without a
    category-specific content signature match (module docstring, decision
    #2).
    """
    status = resp.get("status_code")
    body = resp.get("body")
    headers = resp.get("headers") or {}
    content_type = _ci_get(headers, "Content-Type")
    raw_prefix = resp.get("raw_prefix") or b""

    if status is None:
        return "error", CONFIDENCE_LOW, ["no status code available (request failed)"], None
    if status == 404:
        return "not_found", CONFIDENCE_HIGH, [], None
    if status == 429:
        return "rate_limited", CONFIDENCE_LOW, ["HTTP 429 Too Many Requests — scan may be incomplete"], None
    if status in _REDIRECT_STATUS_CODES:
        return "redirect", CONFIDENCE_MEDIUM, [f"HTTP {status} redirect response"], None
    if status in (401, 403):
        notes = [f"HTTP {status} access-restricted response — path exists but is not readable"]
        if category == CATEGORY_ADMINISTRATIVE_PANEL:
            return "access_restricted", CONFIDENCE_MEDIUM, notes, None
        return "access_restricted", CONFIDENCE_LOW, notes, None
    if status == 405:
        return "method_not_allowed", CONFIDENCE_MEDIUM, ["HTTP 405 Method Not Allowed"], None
    if 500 <= status < 600:
        # A 5xx is itself potentially useful (error-page intel handles that
        # separately); as an *exposure* signal it only proves the path
        # triggered server-side handling, not that sensitive content exists.
        return "server_error_response", CONFIDENCE_LOW, [f"HTTP {status} server error — existence uncertain"], _excerpt(body)
    if not (200 <= status < 300):
        return "unexpected_status", CONFIDENCE_LOW, [f"unexpected HTTP status {status}"], None

    # 2xx: directory-listing evidence always wins first — direct proof.
    listing_evidence = detect_directory_listing(body)
    if listing_evidence:
        return (
            "directory_listing_enabled", CONFIDENCE_HIGH,
            [f"Autoindex/directory-listing signature matched: {listing_evidence!r}"],
            _excerpt(body),
        )

    if _matches_soft_404(resp, baseline):
        return (
            "possible_soft_404_match", CONFIDENCE_LOW,
            ["response closely matches this host's baseline not-found fingerprint "
             "(same status + similar body); likely a soft-404, not confirmed content"],
            None,
        )

    signature_evidence: Optional[str] = None
    if category == CATEGORY_VERSION_CONTROL:
        signature_evidence = _check_version_control(path, body)
    elif category == CATEGORY_ENVIRONMENT_FILE:
        signature_evidence = _check_environment_file(body, content_type)
    elif category == CATEGORY_DATABASE_DUMP:
        signature_evidence = _check_database_dump(body, raw_prefix)
    elif category == CATEGORY_ARCHIVE_FILE:
        signature_evidence = _check_archive_file(raw_prefix, content_type)
    elif category == CATEGORY_BACKUP_FILE:
        signature_evidence = _check_archive_file(raw_prefix, content_type) or _check_configuration_file(body, content_type)
    elif category == CATEGORY_CONFIGURATION_FILE:
        signature_evidence = _check_configuration_file(body, content_type)
    elif category == CATEGORY_CREDENTIAL_MATERIAL:
        signature_evidence = _check_credential_material(path, body)
    elif category == CATEGORY_LOG_FILE:
        signature_evidence = _check_log_file(body, content_type)
    elif category == CATEGORY_DEBUG_ENDPOINT:
        error_intel = analyze_error_page(body, headers, status)
        if error_intel["framework_indicators"]:
            names = ", ".join(sorted({i["framework"] for i in error_intel["framework_indicators"] if i["framework"]}))
            signature_evidence = f"debug/error-page framework signature(s) detected: {names}"
        elif "phpinfo()" in (body or "").lower():
            signature_evidence = "body contains a phpinfo() output signature"
        elif "apache" in (body or "").lower() and "status" in path.lower():
            signature_evidence = "body contains an Apache mod_status-style report"
    elif category == CATEGORY_ADMINISTRATIVE_PANEL:
        admin_evidence, strength = _check_administrative_panel(status, body)
        if admin_evidence and strength == "strong":
            signature_evidence = admin_evidence

    if signature_evidence:
        return "confirmed_exposure", CONFIDENCE_HIGH, [signature_evidence], _excerpt(body)

    # 2xx, no category signature match: still worth surfacing, but not
    # claimed as confirmed sensitive content (module docstring, decision #2).
    return (
        "interesting_unconfirmed", CONFIDENCE_LOW,
        [f"HTTP {status} on a {category}-shaped path with no confirming content signature; "
         f"manual verification recommended"],
        _excerpt(body),
    )


# ---------------------------------------------------------------------------
# Scan state (visited-set, request budget, error log, baseline cache —
# shared across the sensitive-resource sweep)
# ---------------------------------------------------------------------------

class _ScanState:
    def __init__(self, target: str, store: Optional[PendingAssetsStore], max_requests: int):
        self.target = target
        self.store = store
        self.max_requests = max_requests
        self._lock = threading.Lock()
        self.request_count = 0
        self.budget_exhausted = False
        self.errors: List[Dict[str, Any]] = []
        self._baseline_lock = threading.Lock()
        self._baseline_cache: Dict[str, Dict[str, Any]] = {}

    def reserve_request(self) -> bool:
        with self._lock:
            if self.request_count >= self.max_requests:
                self.budget_exhausted = True
                return False
            self.request_count += 1
            return True

    def record_error(self, stage: str, url: str, message: str) -> None:
        with self._lock:
            self.errors.append({"stage": stage, "url": url, "error": message, "timestamp": _now()})

    def get_baseline(self, origin: str, timeout: float) -> Dict[str, Any]:
        with self._baseline_lock:
            if origin not in self._baseline_cache:
                self._baseline_cache[origin] = _probe_soft_404(origin, timeout)
            return self._baseline_cache[origin]


def _probe_sensitive_candidate(
    state: _ScanState, root: str, entry: str, category: str, timeout: float,
) -> Optional[Dict[str, Any]]:
    """Fetch, classify, and persist one sensitive-resource candidate. Returns the finding value, or None."""
    url = _url_for_path(root, entry)
    resp = fetch_url(url, timeout=timeout)
    if resp["status"] != "found":
        state.record_error("fetch", url, resp.get("error") or "request failed")
        return None

    baseline = state.get_baseline(_origin_of(url), timeout)
    discovery_type, confidence, notes, excerpt = evaluate_exposure(category, entry, resp, baseline)

    if discovery_type == "not_found":
        return None

    headers = resp["headers"]
    error_intel = analyze_error_page(resp.get("body"), headers, resp.get("status_code"))

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
        "evidence": [f"GET {url} returned HTTP {resp['status_code']}"] + notes,
        "error_page_indicators": error_intel["indicators"],
        "timestamp": _now(),
    }
    err = _safe_store_add(state.store, make_finding(
        finding_type="exposure_finding", target=state.target, value=dict(record),
        evidence=record["evidence"], confidence=confidence,
        metadata={"exposure_category": category, "discovery_type": discovery_type, "url": url},
    ))
    if err:
        state.record_error("persistence", url, err)

    if error_intel["indicators"]:
        err = _safe_store_add(state.store, make_finding(
            finding_type="error_page_intelligence", target=state.target,
            value={"url": url, **error_intel},
            evidence=[i["evidence"] for i in error_intel["indicators"]],
            confidence=CONFIDENCE_MEDIUM,
            metadata={"url": url, "stack_trace_detected": error_intel["stack_trace_detected"]},
        ))
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
) -> Dict[str, Any]:
    """
    Sweep wordlists/directories.txt for entries matching a recognized
    exposure category (classify_exposure_category) and evaluate each hit's
    evidence (responsibility groups 1 and 2's debug/admin coverage).
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

    tasks: List[Tuple[str, str]] = []
    for entry in entries:
        category = classify_exposure_category(entry)
        if category:
            tasks.append((entry, category))
    for entry, category in _SENSITIVE_DIRECTORIES.items():
        if entry not in {e for e, _ in tasks}:
            tasks.append((entry, category))

    state = _ScanState(target, store, max_requests)
    findings: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        future_map = {}
        for entry, category in tasks:
            if not state.reserve_request():
                break
            future_map[executor.submit(_probe_sensitive_candidate, state, root, entry, category, timeout)] = entry
        for future in concurrent.futures.as_completed(future_map):
            entry = future_map[future]
            try:
                record = future.result()
                if record is not None:
                    findings.append(record)
            except Exception as exc:  # a single bad task must not abort the sweep
                state.record_error("probe", entry, str(exc))

    return {
        "target": target, "base_url": base_url, "candidates_checked": len(tasks),
        "findings": findings, "errors": errors + state.errors,
        "requests_made": state.request_count, "request_budget_exhausted": state.budget_exhausted,
    }


# ---------------------------------------------------------------------------
# 2b/2c. robots.txt / sitemap.xml discovery
# ---------------------------------------------------------------------------

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
        return {"url": url, "status": "not_found", "status_code": resp["status_code"]}

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
        if key == "disallow" and value:
            disallow.append(value)
        elif key == "allow" and value:
            allow.append(value)
        elif key == "sitemap" and value:
            sitemaps.append(value)

    disallow, allow, sitemaps = disallow[:100], allow[:100], sitemaps[:20]
    record = {
        "url": url, "disallowed_paths": disallow, "allowed_paths": allow, "sitemap_urls": sitemaps,
        "excerpt": _excerpt(body, max_chars=500),
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
        return {"url": url, "status": "not_found", "status_code": resp["status_code"]}

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

    locs = _SITEMAP_LOC_RE.findall(body)[:200]
    record = {"url": url, "content_type": content_type, "url_count": len(locs), "urls": locs}
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


def generate_cloud_candidates(target: str) -> List[Dict[str, str]]:
    """
    Generate S3/GCS bucket-name permutations from `target` for
    informational visibility only — no request is made against any of
    these unless the same identifier is also explicitly supplied via
    `cloud_targets` (module docstring, decision #4).
    """
    if not target:
        return []
    label = re.sub(r"[^a-z0-9-]", "-", target.lower()).strip("-")
    label = re.sub(r"-{2,}", "-", label)
    if not label:
        return []
    bases = {label, label.replace(".", "-"), label.split(".")[0]}
    candidates: List[Dict[str, str]] = []
    seen = set()
    for base in bases:
        for suffix in _CLOUD_NAME_SUFFIXES:
            name = f"{base}{suffix}"
            for provider in ("s3", "gcs"):
                key = (provider, name)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append({"provider": provider, "identifier": name})
    return candidates


def build_cloud_url(provider: str, identifier: str, container: Optional[str] = None) -> Optional[str]:
    provider = provider.lower()
    if provider == "s3":
        return f"https://{identifier}.s3.amazonaws.com/"
    if provider == "gcs":
        return f"https://storage.googleapis.com/{identifier}/"
    if provider == "azure":
        if not container:
            return None
        return f"https://{identifier}.blob.core.windows.net/{container}?restype=container&comp=list"
    return None


def classify_cloud_response(status_code: Optional[int], body: Optional[str]) -> Tuple[str, str, List[str]]:
    """
    Classify a cloud-storage GET response using its XML/error-code body,
    never bare status alone (avoids false positives from generic cloud
    error pages — assignment brief's discovery-quality requirement).
    """
    body = body or ""
    if status_code is None:
        return "error", CONFIDENCE_LOW, ["no status code available (request failed)"]

    if "<ListBucketResult" in body or "<EnumerationResults" in body:
        has_contents = "<Contents>" in body or "<Blob>" in body
        note = "publicly listable — object entries present" if has_contents else "publicly listable — bucket/container is empty"
        return "confirmed_exposure", CONFIDENCE_HIGH, [f"Bucket/container listing XML returned ({note})"]

    for code in ("AccessDenied", "AuthenticationFailed", "AuthorizationFailure"):
        if code in body:
            return "bucket_exists_access_restricted", CONFIDENCE_MEDIUM, [f"Response body contains error code {code!r} — resource exists, listing denied"]

    for code in ("NoSuchBucket", "ContainerNotFound", "BucketNotFound", "ResourceNotFound", "UserProjectMissing"):
        if code in body:
            return "not_found", CONFIDENCE_HIGH, [f"Response body contains error code {code!r}"]

    if status_code == 404:
        return "not_found", CONFIDENCE_HIGH, []
    if status_code == 403:
        return "bucket_exists_access_restricted", CONFIDENCE_LOW, [f"HTTP 403 with unrecognized body format"]

    return "inconclusive_cloud_response", CONFIDENCE_LOW, [f"HTTP {status_code} with an unrecognized response body — inconclusive"]


def check_cloud_resource(
    provider: str, identifier: str, container: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Perform the one live request that both proves existence and tests
    listability for a single, explicitly authorized cloud resource
    (module docstring, decision #4).
    """
    url = build_cloud_url(provider, identifier, container)
    if not url:
        return {"provider": provider, "identifier": identifier, "status": "error", "error": "unsupported provider or missing container"}

    resp = fetch_url(url, timeout=timeout)
    if resp["status"] != "found":
        return {"provider": provider, "identifier": identifier, "url": url, "status": "error", "error": resp.get("error")}

    discovery_type, confidence, notes = classify_cloud_response(resp["status_code"], resp.get("body"))
    return {
        "provider": provider, "identifier": identifier, "container": container, "url": url,
        "status": "checked", "status_code": resp["status_code"], "discovery_type": discovery_type,
        "confidence": confidence, "evidence": [f"GET {url} returned HTTP {resp['status_code']}"] + notes,
        "excerpt": _excerpt(resp.get("body")),
    }


def discover_cloud_exposure(
    target: str,
    cloud_targets: Optional[List[Any]] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
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
    for item in cloud_targets or []:
        if isinstance(item, str):
            parsed = urllib.parse.urlsplit(item)
            host = (parsed.hostname or "").lower()
            if host.endswith(".s3.amazonaws.com"):
                identifier = host[: -len(".s3.amazonaws.com")]
                parsed_authorized.append({"provider": "s3", "identifier": identifier})
            elif host == "storage.googleapis.com":
                identifier = (parsed.path or "/").strip("/").split("/")[0]
                if identifier:
                    parsed_authorized.append({"provider": "gcs", "identifier": identifier})
            elif host.endswith(".blob.core.windows.net"):
                identifier = host[: -len(".blob.core.windows.net")]
                container = (parsed.path or "/").strip("/").split("/")[0] or None
                parsed_authorized.append({"provider": "azure", "identifier": identifier, "container": container})
            continue
        if isinstance(item, dict) and item.get("provider") and item.get("identifier"):
            parsed_authorized.append(item)

    for item in parsed_authorized:
        authorized_keys.add((item["provider"], item["identifier"]))

    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for item in parsed_authorized:
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
                          "discovery_type": result["discovery_type"]},
            ))
            if err:
                errors.append({"stage": "persistence", "identifier": item.get("identifier"), "error": err})

    candidate_records = []
    for c in candidates:
        probed = (c["provider"], c["identifier"]) in authorized_keys
        if probed:
            continue  # already recorded above as a live cloud_resource_finding
        candidate_records.append({**c, "url": build_cloud_url(c["provider"], c["identifier"])})

    if candidate_records:
        err = _safe_store_add(store, make_finding(
            finding_type="cloud_candidate_not_probed", target=target,
            value={"candidates": candidate_records, "count": len(candidate_records)},
            evidence=[f"{len(candidate_records)} bucket-name permutation(s) generated from target name; "
                      f"no request made — not present in the explicitly authorized cloud_targets scope"],
            confidence=CONFIDENCE_LOW,
            metadata={"count": len(candidate_records), "note": "candidate names only, not verified"},
        ))
        if err:
            errors.append({"stage": "persistence", "identifier": "cloud_candidates", "error": err})

    return {
        "target": target, "checked": results, "candidates_not_probed": len(candidate_records),
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# 5. HTTP OPTIONS discovery (responsibility group 5)
# ---------------------------------------------------------------------------

def probe_options(
    url: str, target: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Perform one OPTIONS request against `url` and classify the result."""
    url = validate_exposure_target(url, target=target)
    resp = fetch_options(url, timeout=timeout)
    if resp["status"] != "found":
        return {"url": url, "status": "error", "error": resp.get("error")}

    allow_header = _ci_get(resp["headers"], "Allow")
    acam = _ci_get(resp["headers"], "Access-Control-Allow-Methods")
    methods = [m.strip().upper() for m in allow_header.split(",")] if allow_header else []

    if allow_header:
        discovery_type, confidence = "options_supported", CONFIDENCE_HIGH
        evidence = [f"OPTIONS {url} returned HTTP {resp['status_code']} with Allow: {allow_header!r}"]
    elif resp["status_code"] in (200, 204):
        discovery_type, confidence = "options_response_no_allow_header", CONFIDENCE_LOW
        evidence = [f"OPTIONS {url} returned HTTP {resp['status_code']} without an Allow header"]
    elif resp["status_code"] == 404:
        discovery_type, confidence = "not_found", CONFIDENCE_HIGH
        evidence = [f"OPTIONS {url} returned HTTP 404"]
    elif resp["status_code"] in (401, 403):
        discovery_type, confidence = "access_restricted", CONFIDENCE_MEDIUM
        evidence = [f"OPTIONS {url} returned HTTP {resp['status_code']}"]
    elif resp["status_code"] == 405:
        discovery_type, confidence = "method_not_allowed", CONFIDENCE_MEDIUM
        evidence = [f"OPTIONS {url} returned HTTP 405 — OPTIONS itself is not permitted here"]
    else:
        discovery_type, confidence = "unexpected_status", CONFIDENCE_LOW
        evidence = [f"OPTIONS {url} returned unexpected HTTP {resp['status_code']}"]

    return {
        "url": url, "status": "found", "status_code": resp["status_code"],
        "discovery_type": discovery_type, "confidence": confidence,
        "allow_header": allow_header, "advertised_methods": methods,
        "access_control_allow_methods": acam, "evidence": evidence,
        "note": "An advertised method is server-side support information only, not proof it is exploitable.",
    }


def discover_http_options(
    urls: List[str],
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> Dict[str, Any]:
    """Run OPTIONS discovery across a bounded, deduplicated list of URLs, persisting each result."""
    unique_urls = sorted(set(urls))
    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    def _one(url: str) -> Optional[Dict[str, Any]]:
        try:
            return probe_options(url, target=target, timeout=timeout)
        except ScopeError as exc:
            errors.append({"stage": "scope", "url": url, "error": str(exc)})
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        future_map = {executor.submit(_one, url): url for url in unique_urls}
        for future in concurrent.futures.as_completed(future_map):
            url = future_map[future]
            try:
                result = future.result()
            except Exception as exc:  # a single bad OPTIONS probe must not abort the rest
                errors.append({"stage": "probe", "url": url, "error": str(exc)})
                continue
            if result is None:
                continue
            if result.get("status") == "error":
                errors.append({"stage": "fetch", "url": url, "error": result.get("error")})
                continue
            results.append(result)
            err = _safe_store_add(store, make_finding(
                finding_type="http_options_result", target=target or url, value=result,
                evidence=result["evidence"], confidence=result["confidence"],
                metadata={"url": url, "discovery_type": result["discovery_type"], "advertised_methods": result["advertised_methods"]},
            ))
            if err:
                errors.append({"stage": "persistence", "url": url, "error": err})

    return {"urls_checked": len(unique_urls), "results": results, "errors": errors}


# ---------------------------------------------------------------------------
# Full single-target orchestration
# ---------------------------------------------------------------------------

_OPTIONS_WORTHY_TYPES = {"confirmed_exposure", "likely_exposure", "interesting_unconfirmed", "access_restricted", "directory_listing_enabled"}


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
) -> Dict[str, Any]:
    """
    Run every exposure_scan.py responsibility against `base_url` and
    persist every completed discovery immediately to
    <output_dir>/pending_assets.json (crash-safe). Each phase is isolated
    (module docstring / assignment brief: "one failed endpoint must not
    unnecessarily terminate the entire exposure scan") — a failure in one
    phase is recorded in summary["errors"] and does not prevent the
    remaining phases from running.
    """
    base_url = validate_exposure_target(base_url, target=target)
    target = target or (urllib.parse.urlsplit(base_url).hostname or base_url)

    store = PendingAssetsStore(output_dir=output_dir)

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
            timeout=timeout, max_workers=max_workers, max_requests=max_requests,
        )
    except (ScopeError, WordlistError) as exc:
        summary["errors"].append({"stage": "sensitive_resources", "error": str(exc)})
    except Exception as exc:
        summary["errors"].append({"stage": "sensitive_resources", "error": f"unexpected error: {exc}"})

    try:
        summary["robots_txt"] = discover_robots_txt(base_url, target=target, store=store, timeout=timeout)
    except Exception as exc:
        summary["errors"].append({"stage": "robots_txt", "error": f"unexpected error: {exc}"})

    try:
        summary["sitemap_xml"] = discover_sitemap_xml(base_url, target=target, store=store, timeout=timeout)
    except Exception as exc:
        summary["errors"].append({"stage": "sitemap_xml", "error": f"unexpected error: {exc}"})

    try:
        summary["cloud_exposure"] = discover_cloud_exposure(
            target, cloud_targets=cloud_targets, store=store, timeout=timeout,
        )
    except Exception as exc:
        summary["errors"].append({"stage": "cloud_exposure", "error": f"unexpected error: {exc}"})

    options_urls: List[str] = list(endpoints or [])
    for finding in summary.get("sensitive_resources", {}).get("findings", []):
        if finding.get("discovery_type") in _OPTIONS_WORTHY_TYPES:
            options_urls.append(finding["url"])
    in_scope_options_urls = []
    for u in options_urls:
        try:
            in_scope_options_urls.append(validate_exposure_target(u, target=target))
        except ScopeError:
            continue

    try:
        summary["http_options"] = discover_http_options(
            in_scope_options_urls, target=target, store=store, timeout=timeout, max_workers=max_workers,
        )
    except Exception as exc:
        summary["errors"].append({"stage": "http_options", "error": f"unexpected error: {exc}"})

    summary["errors"].extend(summary.get("sensitive_resources", {}).get("errors", []))
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
