"""
reconhound/tech_fingerprint.py — ReconHound Module 8 (tech_fingerprint.py),
build-order position 17 (per context.md §13; this repository, like
code_leak.py/passive_intel.py/wayback_intel.py/vuln_intel.py before it, is
operating under an explicit deviation from the numeric build order —
surface_mapper.py, core/orchestrator.py, and reconhound.py are not yet
implemented; see BUILD-ORDER NOTE below).

Phase: Active. See context.md §10 (module 8, "Technology ID") for the
authoritative responsibilities, and §8 for the evidence/confidence data
model this module implements. This file only documents implementation-
specific detail, not the architecture itself.

context.md's exact line for this module:

  "Active — Technology ID. CMS (WordPress/Drupal/Joomla/Magento),
  frameworks (Django/Flask/FastAPI/Laravel/Express/Next.js/React/Angular/
  Vue), servers (Nginx/Apache/IIS/Caddy), WAFs (Cloudflare/Akamai/AWS WAF/
  F5/Imperva). Signals: headers, cookies, HTML, JS, URLs, error pages,
  favicon hashes, known paths. Should trigger downstream recon
  automatically. Evidence+confidence required per detection."

That expands into these discrete responsibilities, each implemented below:

  1. Server identification (header-based)      -> detect_servers
  2. WAF signature detection                    -> detect_wafs
  3. CMS + framework signature detection
     (headers/cookies/HTML/JS/URL markers)      -> detect_technologies_from_content
  4. Error-page signal correlation               -> fetch_error_page_sample
                                                     (fed back into #3)
  5. Favicon hash computation + matching         -> compute_favicon_hash,
                                                     match_favicon_hash
  6. Known technology-specific path probing
     (confirmatory, bounded, signal-driven)      -> probe_known_paths
  7. Multi-signal correlation / confidence        -> _merge_scan_maps,
     scoring                                        _finalize_detections
  8. Normalization for surface_mapper.py          -> build_technology_summary
  9. Downstream-recon trigger integration         -> build_recommended_actions

Plus shared plumbing: make_finding/make_tech_finding, PendingAssetsStore,
_safe_store_add, fetch_url (duplicated per modular independence, same as
every other implemented module), and a single-target orchestrator
run_tech_fingerprint (mirroring the run_http_analysis/run_endpoint_discovery
precedent).

BUILD-ORDER NOTE: context.md §13 lists this module at build-order position
17, after surface_mapper.py (position 8) and after endpoint_discovery.py
(position 5). Per code_leak.py's/passive_intel.py's/wayback_intel.py's/
vuln_intel.py's module docstrings, this repository is already operating
under an explicit, user-approved deviation from that order —
surface_mapper.py has not been implemented yet. This module continues
under the same deviation: it is a fully standalone producer that does not
implement, replace, or depend on surface_mapper.py's correlation engine.

NO-CROSS-MODULE-CALLS PRECEDENT (important for responsibility #9,
"downstream recon trigger"): every already-implemented module in this
repository (http_analyzer.py, endpoint_discovery.py, code_leak.py, etc.)
explicitly documents that it does NOT import or call into any sibling
module, even ones already implemented — integration is deferred to
core/orchestrator.py (not yet built), which is meant to route data
between modules via surface_mapper.py. This module follows that same
precedent rather than inventing a new "tech_fingerprint calls
endpoint_discovery directly" pattern, which would be a competing
orchestration mechanism (assignment's explicit "do not create a competing
orchestration system" instruction). Instead, responsibility #9 is
satisfied by:

  a. Producing `technology_summary`, a normalized dict shaped to be passed
     straight into endpoint_discovery.py's ALREADY-BUILT, ALREADY-CALLER-
     SUPPLIED `technology` parameter (see endpoint_discovery.py's
     `select_wordlists_for_technology` / `enumerate_framework_paths` /
     `run_endpoint_discovery(technology=...)`) with zero adaptation
     required — `select_wordlists_for_technology` does a case-insensitive
     substring search over every string value in the structure, and this
     module's category buckets ("cms"/"frameworks"/"servers"/"wafs") plus
     plain technology-name strings satisfy that contract directly. This is
     "using the existing project interface", not building a new one.
  b. Producing `recommended_next_actions`: an explicit, evidence-justified
     decision-queue-shaped list (context.md §9's "decision queue with
     justification" concept) naming which existing module/function should
     be invoked next and why. These are recommendations for the future
     orchestrator to execute — this module never invokes them itself.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other implemented module, sharing the same output file). This module
does not implement or call into surface_mapper, active_recon, vhost_scanner,
endpoint_discovery, api_recon, crawler, js_analyzer, supply_chain,
exposure_scan, http_analyzer, ssl_analyzer, screenshot, vuln_intel,
risk_engine, report_generator, orchestrator, osint_engine, or any other
module.

DISCOVERY != CONFIRMED VULNERABILITY: every record here is an observation
("this signal was seen, matching this technology's known signature") with
an explicit confidence level. None of this module's output should be read
as "vulnerable" or "exploitable" — CVE mapping is vuln_intel.py's job, risk
scoring is risk_engine.py's job. A detected version is only ever reported
when the evidence itself carries a version string (a declared meta
generator tag, a `Server:`/`X-Powered-By:` header version token, a version
attribute in markup) — this module never guesses or infers a version from
absence of a patch-specific marker.

Implementation decisions (ambiguities resolved so implementation can
proceed without inventing requirements):

  1. Signal correlation / confidence scoring: each matched signal is
     weighted "strong" (2 points — a direct, hard-to-accidentally-trigger
     declaration: a meta generator tag, a vendor-specific header value, a
     confirmed known-path match with a content marker, a matched favicon
     hash) or "weak" (1 point — a generic cookie name, a generic HTML
     marker, an unconfirmed known-path 2xx with no content marker).
     Confidence = HIGH at score >= 3, MEDIUM at score == 2, LOW at score
     == 1 (context.md §8: "multiple independent converging signals raise
     confidence; a single weak signal should generally stay LOW" — two
     converging weak signals reach MEDIUM, a single strong signal alone
     also lands at MEDIUM since it is still one source, and any
     combination reaching 3+ points reaches HIGH).
  2. Known-path probing (#6) is bounded and signal-driven, not a fresh
     wordlist scan: only technologies that already have at least one
     header/cookie/HTML/error-page signal are corroborated via known
     paths (a handful of well-documented, technology-specific paths, e.g.
     `/wp-login.php`, `/CHANGELOG.txt`), capped by `max_known_path_probes`.
     This is deliberately NOT endpoint_discovery.py's wordlist-driven
     directory/file enumeration — it exists only to raise or confirm
     confidence in an already-suspected technology, using a small,
     hardcoded, well-known path list per technology, not a general
     wordlist.
  3. Favicon hashing (#5): computes both MD5 and SHA-256 of the fetched
     favicon's raw bytes. This project does not bundle a verified
     mmm3/Shodan-style favicon-hash signature database (fabricating one
     with unverified hash values would plant false "evidence" — CLAUDE.md
     rule "do not invent requirements/data"). Instead, `favicon_signatures`
     is an explicit, optional, caller-supplied
     `{hash_hex: {"technology":, "category":, "version": Optional,
     "hash_type": "md5"|"sha256"}}` mapping — the mechanism is fully
     implemented and tested, and a real signature database can be plugged
     in later without changing this module. When no match is found (or no
     signatures are supplied), the computed hash is still persisted as a
     `tech_fingerprint_favicon_observed` finding (negative-result memory —
     "checked, hash computed, no known signature yet" — so a future
     signature-database update can be correlated retroactively without
     re-fetching).
  4. Error-page correlation (#4): one near-certainly-nonexistent path is
     fetched per run (mirrors endpoint_discovery.py's soft-404 probe
     technique, but for a different purpose — content inspection, not
     soft-404 fingerprinting) and scanned with the exact same signature
     matchers as the baseline response. Some frameworks (Laravel's
     "Whoops", Django's DEBUG traceback, Werkzeug's debugger) reveal
     themselves distinctly on an error/404 response even when the
     homepage gives no signal. Evidence from the baseline and error-page
     scans are merged (union), not treated as independent detections.
  5. `requests` and no new dependency: this module reuses the same
     `requests`-based fetch pattern as http_analyzer.py/
     endpoint_discovery.py; no additional third-party dependency is
     introduced (HTML markers are matched via targeted regex over the
     already-fetched body, same approach as http_analyzer.py — full DOM
     parsing is not required for the marker/attribute patterns used here).
  6. Only GET requests are made, to the target's own origin (the base URL
     plus a small number of well-known, same-origin relative paths:
     favicon, error-page probe, known-path corroboration). No new hosts
     are ever contacted. This module discovers technology signals; it
     never exercises or exploits anything it detects.
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
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

MODULE_NAME = "tech_fingerprint.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

# Technology categories (context.md §10, module 8)
CATEGORY_CMS = "cms"
CATEGORY_FRAMEWORK = "framework"
CATEGORY_SERVER = "server"
CATEGORY_WAF = "waf"

DEFAULT_USER_AGENT = "ReconHound-TechFingerprint/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_MAX_BODY_BYTES = 131072
DEFAULT_MAX_FAVICON_BYTES = 65536
DEFAULT_MAX_KNOWN_PATH_PROBES = 12

# Signal-scoring weights (implementation decision #1)
_SCORE_STRONG = 2
_SCORE_WEAK = 1
_HIGH_THRESHOLD = 3
_MEDIUM_THRESHOLD = 2


class ScopeError(ValueError):
    """Raised when a URL/target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors http_analyzer.py's/endpoint_discovery.py's
# validate_url_target; duplicated per modular independence, context.md §12.2)
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


def validate_url_target(url: str, target: Optional[str] = None) -> str:
    """
    Validate that `url` is a syntactically valid http(s) URL, and — if
    `target` is supplied — that its hostname is the target itself or a
    subdomain of it (an IP-literal host is allowed through without an
    in-scope check, mirroring http_analyzer.py's rationale: IP scope is
    enforced upstream, not by a domain comparison here).
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


def make_tech_finding(
    technology: str,
    category: str,
    version: Optional[str],
    evidence: List[str],
    confidence: str,
    target: str,
    url: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Wrap one technology detection into the structured evidence record
    required by the assignment's "for every technology detection preserve"
    list: technology, category, version (nullable — never invented),
    evidence, source/URL, confidence, timestamp (timestamp is added by
    make_finding).
    """
    return make_finding(
        finding_type="tech_fingerprint_detected",
        target=target,
        value={
            "technology": technology,
            "category": category,
            "version": version,
            "url": url,
        },
        evidence=evidence,
        confidence=confidence,
        metadata={**(metadata or {}), "technology": technology, "category": category, "version": version, "url": url},
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


def parse_cookie_names(set_cookie_headers: List[str]) -> List[str]:
    """Extract just the cookie names from raw Set-Cookie header strings."""
    names: List[str] = []
    for raw in set_cookie_headers or []:
        first = raw.split(";", 1)[0]
        name = first.split("=", 1)[0].strip()
        if name:
            names.append(name)
    return names


# ---------------------------------------------------------------------------
# Shared HTTP client (not itself a listed context.md responsibility, but
# necessary plumbing — mirrors http_analyzer.py's/endpoint_discovery.py's
# fetch_url, extended to also return raw bytes for favicon hashing)
# ---------------------------------------------------------------------------

def fetch_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """
    Perform a single HTTP GET against `url` without following redirects
    (this module inspects one response at a time; it does not need to
    traverse redirect chains — that is http_analyzer.py's job).
    """
    result: Dict[str, Any] = {
        "status": "error", "status_code": None, "headers": {}, "set_cookie_headers": [],
        "body": None, "body_bytes": b"", "body_truncated": False, "final_url": url,
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

        try:
            set_cookie_headers = list(resp.raw.headers.getlist("Set-Cookie"))
        except AttributeError:
            single = resp.headers.get("Set-Cookie")
            set_cookie_headers = [single] if single else []

        result.update({
            "status": "found",
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "set_cookie_headers": set_cookie_headers,
            "body": body_text,
            "body_bytes": body_bytes,
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
# Signature catalogs
# ---------------------------------------------------------------------------

def _rx(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern, re.IGNORECASE)


# 1. Servers (context.md: Nginx, Apache, IIS, Caddy)
_SERVER_SIGNATURES: List[Dict[str, Any]] = [
    {"name": "Nginx", "regex": _rx(r"nginx(?:/([\d]+(?:\.[\d]+)*))?")},
    {"name": "Apache", "regex": _rx(r"apache(?:/([\d]+(?:\.[\d]+)*))?")},
    {"name": "Microsoft IIS", "regex": _rx(r"microsoft-iis(?:/([\d]+(?:\.[\d]+)*))?")},
    {"name": "Caddy", "regex": _rx(r"caddy(?:/([\d]+(?:\.[\d]+)*))?")},
]

# 2. WAFs (context.md: Cloudflare, Akamai, AWS WAF, F5, Imperva). Each
# marker is (weight, matcher) where matcher is None (presence-only) or a
# list of case-insensitive substrings. Passive signature matching only —
# no probes crafted to provoke a WAF (mirrors http_analyzer.py's
# detect_waf boundary).
_WAF_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "Cloudflare": {
        "headers": {"server": (_SCORE_STRONG, ["cloudflare"]), "cf-ray": (_SCORE_STRONG, None),
                    "cf-cache-status": (_SCORE_WEAK, None)},
        "cookies": [(_SCORE_WEAK, "__cfduid"), (_SCORE_WEAK, "cf_clearance"), (_SCORE_WEAK, "__cf_bm")],
        "body": [(_SCORE_WEAK, "cloudflare ray id"), (_SCORE_WEAK, "attention required! | cloudflare")],
    },
    "Akamai": {
        "headers": {"server": (_SCORE_STRONG, ["akamaighost"]), "x-akamai-transformed": (_SCORE_STRONG, None)},
        "cookies": [(_SCORE_WEAK, "akamai")],
        "body": [],
    },
    "AWS WAF": {
        "headers": {"x-amzn-waf-action": (_SCORE_STRONG, None)},
        "cookies": [(_SCORE_WEAK, "aws-waf-token")],
        "body": [],
    },
    "F5": {
        "headers": {"server": (_SCORE_STRONG, ["big-ip"])},
        "cookies": [(_SCORE_WEAK, "bigipserver"), (_SCORE_WEAK, "ts01")],
        "body": [(_SCORE_WEAK, "the requested url was rejected"), (_SCORE_WEAK, "support id:")],
    },
    "Imperva": {
        "headers": {"x-iinfo": (_SCORE_STRONG, None), "x-cdn": (_SCORE_STRONG, ["incapsula"])},
        "cookies": [(_SCORE_WEAK, "incap_ses"), (_SCORE_WEAK, "visid_incap")],
        "body": [(_SCORE_WEAK, "incapsula incident id"), (_SCORE_WEAK, "request unsuccessful. incapsula")],
    },
}

# 3. CMS + framework signatures. Each entry:
#   name, category, meta_generator_product (str|None), version_attr_regex
#   (compiled|None, group(1)=version), html_markers (weak, list[str]),
#   cookie_patterns (weak, list[compiled]), header_markers
#   ({header_lower: (weight, None|[substrings])}), header_version_regex
#   (compiled|None, applied to the matching header value),
#   known_paths (list[(path, marker|None)]).
_TECH_SIGNATURES: List[Dict[str, Any]] = [
    # --- CMS ---
    {
        "name": "WordPress", "category": CATEGORY_CMS,
        "meta_generator_product": "WordPress",
        "version_attr_regex": None,
        "html_markers": ["wp-content/", "wp-includes/", "wp-json"],
        "cookie_patterns": [_rx(r"^wordpress_"), _rx(r"^wp-settings-")],
        "header_markers": {"link": (_SCORE_WEAK, ["wp-json", 'rel="https://api.w.org/"'])},
        "header_version_regex": None,
        "known_paths": [
            ("wp-login.php", "user_login"),
            ("wp-json/", '"name"'),
            ("xmlrpc.php", "XML-RPC server accepts POST requests only"),
        ],
    },
    {
        "name": "Drupal", "category": CATEGORY_CMS,
        "meta_generator_product": "Drupal",
        "version_attr_regex": None,
        "html_markers": ["/sites/default/files/", "/sites/all/modules/", "Drupal.settings"],
        "cookie_patterns": [_rx(r"^SESS[a-f0-9]{32}$"), _rx(r"^SSESS[a-f0-9]{32}$")],
        "header_markers": {"x-generator": (_SCORE_STRONG, ["drupal"]), "x-drupal-cache": (_SCORE_STRONG, None),
                            "x-drupal-dynamic-cache": (_SCORE_STRONG, None)},
        "header_version_regex": None,
        "known_paths": [
            ("CHANGELOG.txt", "Drupal"),
            ("core/CHANGELOG.txt", "Drupal"),
            ("user/login", "Log in"),
        ],
    },
    {
        "name": "Joomla", "category": CATEGORY_CMS,
        "meta_generator_product": "Joomla",
        "version_attr_regex": None,
        "html_markers": ["/media/system/js/", "/media/jui/", "Joomla!"],
        "cookie_patterns": [_rx(r"^joomla_user_state$")],
        "header_markers": {},
        "header_version_regex": None,
        "known_paths": [
            ("administrator/", "Joomla"),
            ("administrator/manifests/files/joomla.xml", "<version>"),
        ],
    },
    {
        "name": "Magento", "category": CATEGORY_CMS,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": ["/skin/frontend/", "/static/frontend/", "Mage.Cookies", "Magento_Store", "/js/mage/"],
        "cookie_patterns": [_rx(r"^form_key$")],
        "header_markers": {"x-magento-cache-debug": (_SCORE_STRONG, None), "x-magento-tags": (_SCORE_STRONG, None)},
        "header_version_regex": None,
        "known_paths": [
            ("errors/report.php", None),
            ("admin/", None),
        ],
    },
    # --- Frameworks ---
    {
        "name": "Django", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": ["csrfmiddlewaretoken", "you're seeing this because you have debug = true"],
        "cookie_patterns": [_rx(r"^csrftoken$"), _rx(r"^sessionid$")],
        "header_markers": {},
        "header_version_regex": None,
        "known_paths": [],
    },
    {
        "name": "Flask", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": ["werkzeug debugger"],
        "cookie_patterns": [],
        "header_markers": {"server": (_SCORE_STRONG, ["werkzeug"])},
        "header_version_regex": _rx(r"werkzeug/([\d]+(?:\.[\d]+)*)"),
        "known_paths": [],
    },
    {
        "name": "FastAPI", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": [],
        "cookie_patterns": [],
        "header_markers": {"server": (_SCORE_WEAK, ["uvicorn"])},
        "header_version_regex": None,
        "known_paths": [
            ("openapi.json", '"openapi"'),
            ("docs", "swagger-ui"),
        ],
    },
    {
        "name": "Laravel", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": ["whoops, looks like something went wrong", "illuminate\\\\"],
        "cookie_patterns": [_rx(r"^laravel_session$"), _rx(r"^XSRF-TOKEN$")],
        "header_markers": {},
        "header_version_regex": None,
        "known_paths": [],
    },
    {
        "name": "Express", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": [],
        "cookie_patterns": [_rx(r"^connect\.sid$")],
        "header_markers": {"x-powered-by": (_SCORE_STRONG, ["express"])},
        "header_version_regex": None,
        "known_paths": [],
    },
    {
        "name": "Next.js", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": ["__next_data__", "/_next/static/"],
        "cookie_patterns": [],
        "header_markers": {"x-powered-by": (_SCORE_STRONG, ["next.js"])},
        "header_version_regex": None,
        "known_paths": [],
    },
    {
        "name": "React", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": ["data-reactroot", "_reactrootcontainer", "react-dom"],
        "cookie_patterns": [],
        "header_markers": {},
        "header_version_regex": None,
        "known_paths": [],
    },
    {
        "name": "Angular", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": _rx(r'ng-version=["\'](\d+(?:\.\d+)*)["\']'),
        "html_markers": ["ng-version", "ng-app"],
        "cookie_patterns": [],
        "header_markers": {},
        "header_version_regex": None,
        "known_paths": [],
    },
    {
        "name": "Vue", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": ["data-v-", "__vue__", "__nuxt__"],
        "cookie_patterns": [],
        "header_markers": {},
        "header_version_regex": None,
        "known_paths": [],
    },
]

# `select_wordlists_for_technology`-compatible keys (endpoint_discovery.py,
# already-built consumption interface) — used to annotate which detections
# have direct tech-aware wordlist coverage downstream.
_ENDPOINT_DISCOVERY_WORDLIST_TECHS = frozenset({"wordpress", "laravel", "django"})


# ---------------------------------------------------------------------------
# 1. Server identification
# ---------------------------------------------------------------------------

def detect_servers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Server header signature matching (responsibility #1). A single Server
    header claim is a direct declaration but from one, spoofable source —
    scored MEDIUM (score=_SCORE_STRONG=2), never HIGH on its own.
    """
    value = _ci_get(headers, "Server")
    scan: Dict[str, Any] = {}
    if not value:
        return scan
    for sig in _SERVER_SIGNATURES:
        m = sig["regex"].search(value)
        if not m:
            continue
        version = m.group(1) if m.groups() and m.group(1) else None
        scan[sig["name"]] = {
            "category": CATEGORY_SERVER,
            "evidence": [f"Server header value {value!r} matches {sig['name']}"],
            "score": _SCORE_STRONG,
            "version": version,
        }
    return scan


# ---------------------------------------------------------------------------
# 2. WAF signature detection
# ---------------------------------------------------------------------------

def detect_wafs(headers: Dict[str, str], set_cookie_headers: Optional[List[str]], body: Optional[str]) -> Dict[str, Any]:
    """Passive WAF signature matching against headers/cookies/body of an already-fetched response."""
    lower_headers = {k.lower(): (v or "") for k, v in (headers or {}).items()}
    cookies_text = " ".join(set_cookie_headers or []).lower()
    body_lower = (body or "").lower()

    scan: Dict[str, Any] = {}
    for vendor, sig in _WAF_SIGNATURES.items():
        evidence: List[str] = []
        score = 0
        for header_name, (weight, subs) in sig["headers"].items():
            value = lower_headers.get(header_name)
            if value is None:
                continue
            if subs is None:
                evidence.append(f"header {header_name!r} present: {value!r}")
                score += weight
            else:
                for sub in subs:
                    if sub in value.lower():
                        evidence.append(f"header {header_name!r} contains {sub!r}")
                        score += weight
        for weight, marker in sig["cookies"]:
            if marker in cookies_text:
                evidence.append(f"Set-Cookie contains marker {marker!r}")
                score += weight
        for weight, marker in sig["body"]:
            if marker in body_lower:
                evidence.append(f"response body contains marker {marker!r}")
                score += weight
        if evidence:
            scan[vendor] = {"category": CATEGORY_WAF, "evidence": evidence, "score": score, "version": None}
    return scan


# ---------------------------------------------------------------------------
# 3. CMS + framework signature detection (headers/cookies/HTML/JS/URLs)
# ---------------------------------------------------------------------------

def _extract_meta_generator(body: str, product_name: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Return (declared_content, version) if a <meta name="generator"
    content="..."> tag mentions `product_name`, else (None, None). Version
    is only returned when a numeric version token is actually present in
    the declared content — never invented.
    """
    pattern = _rx(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']*)["\']')
    for m in pattern.finditer(body or ""):
        content = m.group(1)
        if product_name.lower() in content.lower():
            version_match = re.search(r"(\d+(?:\.\d+)*)", content)
            return content, (version_match.group(1) if version_match else None)
    return None, None


def _scan_signature(
    sig: Dict[str, Any], headers: Dict[str, str], cookie_names: List[str], body: Optional[str], source_label: str,
) -> Optional[Tuple[List[str], int, Optional[str]]]:
    """
    Match one technology signature against one (headers, cookies, body)
    triple. Returns (evidence, score, version) if anything matched, else
    None. Signal weighting: see implementation decision #1 in the module
    docstring.
    """
    body = body or ""
    evidence: List[str] = []
    score = 0
    version: Optional[str] = None

    if sig.get("meta_generator_product"):
        content, ver = _extract_meta_generator(body, sig["meta_generator_product"])
        if content:
            evidence.append(f"{source_label}: <meta name=\"generator\"> declares {content!r}")
            score += _SCORE_STRONG
            version = ver

    if sig.get("version_attr_regex"):
        m = sig["version_attr_regex"].search(body)
        if m:
            evidence.append(f"{source_label}: version attribute matched {m.group(0)!r}")
            score += _SCORE_STRONG
            if not version:
                version = m.group(1)

    for marker in sig.get("html_markers", []):
        if marker.lower() in body.lower():
            evidence.append(f"{source_label}: content contains marker {marker!r}")
            score += _SCORE_WEAK

    for pattern in sig.get("cookie_patterns", []):
        for name in cookie_names:
            if pattern.match(name):
                evidence.append(f"Set-Cookie name {name!r} matches {sig['name']} cookie pattern")
                score += _SCORE_WEAK

    for header_name, (weight, subs) in sig.get("header_markers", {}).items():
        value = _ci_get(headers, header_name)
        if value is None:
            continue
        if subs is None:
            evidence.append(f"header {header_name!r} present: {value!r}")
            score += weight
            if sig.get("header_version_regex") and not version:
                vm = sig["header_version_regex"].search(value)
                if vm:
                    version = vm.group(1)
        else:
            for sub in subs:
                if sub.lower() in value.lower():
                    evidence.append(f"header {header_name!r} contains {sub!r} (value={value!r})")
                    score += weight
                    if sig.get("header_version_regex") and not version:
                        vm = sig["header_version_regex"].search(value)
                        if vm:
                            version = vm.group(1)

    if not evidence:
        return None
    return evidence, score, version


def detect_technologies_from_content(
    headers: Dict[str, str], cookie_names: List[str], body: Optional[str], source_label: str = "baseline_response",
) -> Dict[str, Dict[str, Any]]:
    """
    Run every CMS/framework signature (responsibility #3) against one
    (headers, cookies, body) source. Returns {tech_name: {"category":,
    "evidence": [...], "score": int, "version": Optional[str]}}.
    """
    scan: Dict[str, Any] = {}
    for sig in _TECH_SIGNATURES:
        result = _scan_signature(sig, headers, cookie_names, body, source_label)
        if result is None:
            continue
        evidence, score, version = result
        scan[sig["name"]] = {"category": sig["category"], "evidence": evidence, "score": score, "version": version}
    return scan


def _merge_scan_maps(*maps: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Union evidence and sum scores for the same technology across multiple scan sources."""
    merged: Dict[str, Dict[str, Any]] = {}
    for m in maps:
        for name, rec in m.items():
            if name not in merged:
                merged[name] = {"category": rec["category"], "evidence": list(rec["evidence"]),
                                 "score": rec["score"], "version": rec.get("version")}
            else:
                merged[name]["evidence"].extend(rec["evidence"])
                merged[name]["score"] += rec["score"]
                if not merged[name].get("version") and rec.get("version"):
                    merged[name]["version"] = rec["version"]
    return merged


# ---------------------------------------------------------------------------
# 4. Error-page signal correlation
# ---------------------------------------------------------------------------

def fetch_error_page_sample(origin: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Fetch one near-certainly-nonexistent path so its response can be
    scanned for technology-specific error/debug output (some frameworks —
    Laravel's "Whoops", Django's DEBUG traceback, Werkzeug's debugger —
    reveal themselves only on an error response). Mirrors
    endpoint_discovery.py's soft-404 probe technique for a different
    purpose (content inspection, not soft-404 fingerprinting).
    """
    probe_path = f"reconhound-tech-probe-{uuid.uuid4().hex[:12]}"
    url = origin.rstrip("/") + "/" + probe_path
    return fetch_url(url, timeout=timeout)


# ---------------------------------------------------------------------------
# 5. Favicon hashing
# ---------------------------------------------------------------------------

def compute_favicon_hash(base_url: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Fetch <origin>/favicon.ico and compute MD5 + SHA-256 of its raw bytes.
    See module docstring, implementation decision #3, for why no bundled
    signature database is shipped.
    """
    origin = _origin_of(base_url)
    url = origin.rstrip("/") + "/favicon.ico"
    resp = fetch_url(url, timeout=timeout, max_body_bytes=DEFAULT_MAX_FAVICON_BYTES)
    result: Dict[str, Any] = {
        "status": resp["status"], "url": url, "error": resp.get("error"),
        "status_code": resp.get("status_code"), "byte_length": 0, "md5": None, "sha256": None,
    }
    if resp["status"] != "found" or not resp.get("status_code") or resp["status_code"] >= 400:
        if resp["status"] == "found":
            result["status"] = "not_found"
        return result

    raw = resp.get("body_bytes") or b""
    if not raw:
        result["status"] = "empty"
        return result

    result["byte_length"] = len(raw)
    result["md5"] = hashlib.md5(raw).hexdigest()
    result["sha256"] = hashlib.sha256(raw).hexdigest()
    return result


def match_favicon_hash(
    favicon_result: Dict[str, Any], favicon_signatures: Optional[Dict[str, Dict[str, Any]]],
) -> Optional[Dict[str, Any]]:
    """
    Look up a computed favicon hash against a caller-supplied signature
    map: {hash_hex: {"technology":, "category":, "version": Optional}}.
    Checks both md5 and sha256. Returns a single-entry scan-map value
    (same shape as _scan_signature's output) if matched, else None.
    """
    if not favicon_signatures or not favicon_result.get("md5"):
        return None
    for hash_hex in (favicon_result.get("md5"), favicon_result.get("sha256")):
        sig = favicon_signatures.get(hash_hex) if hash_hex else None
        if sig:
            return {
                "technology": sig["technology"],
                "category": sig.get("category", CATEGORY_CMS),
                "evidence": [f"favicon hash {hash_hex} matched known signature for {sig['technology']}"],
                "score": _SCORE_STRONG,
                "version": sig.get("version"),
            }
    return None


# ---------------------------------------------------------------------------
# 6. Known technology-specific path probing (bounded, signal-driven —
# see module docstring, implementation decision #2)
# ---------------------------------------------------------------------------

def probe_known_paths(
    origin: str,
    candidate_names: List[str],
    timeout: float = DEFAULT_TIMEOUT,
    max_probes: int = DEFAULT_MAX_KNOWN_PATH_PROBES,
) -> Dict[str, Dict[str, Any]]:
    """
    For each already-signaled technology in `candidate_names` that has a
    known_paths list, probe up to `max_probes` (total, across all
    candidates) well-known paths to corroborate the detection. A 404
    contributes no evidence (absence isn't proof against other signals). A
    non-404 response with a matching content marker is strong evidence; a
    non-404 response with no marker configured is weak evidence.
    """
    sig_by_name = {s["name"]: s for s in _TECH_SIGNATURES}
    scan: Dict[str, Any] = {}
    probes_used = 0

    for name in candidate_names:
        sig = sig_by_name.get(name)
        if not sig or not sig.get("known_paths"):
            continue
        for path, marker in sig["known_paths"]:
            if probes_used >= max_probes:
                return scan
            url = origin.rstrip("/") + "/" + path.lstrip("/")
            resp = fetch_url(url, timeout=timeout)
            probes_used += 1
            if resp["status"] != "found" or resp.get("status_code") in (None, 404):
                continue
            if resp.get("status_code") in (401, 403):
                continue

            body = resp.get("body") or ""
            if marker is not None:
                if marker.lower() not in body.lower():
                    continue
                evidence = [f"known path {url} returned HTTP {resp['status_code']} containing marker {marker!r}"]
                score = _SCORE_STRONG
            else:
                evidence = [f"known path {url} returned HTTP {resp['status_code']} (no content marker configured)"]
                score = _SCORE_WEAK

            entry = scan.setdefault(name, {"category": sig["category"], "evidence": [], "score": 0,
                                            "version": None, "confirmed_url": None})
            entry["evidence"].extend(evidence)
            entry["score"] += score
            entry["confirmed_url"] = url

    return scan


# ---------------------------------------------------------------------------
# 7. Finalize detections (confidence scoring, context.md §8)
# ---------------------------------------------------------------------------

def _confidence_for_score(score: int) -> str:
    if score >= _HIGH_THRESHOLD:
        return CONFIDENCE_HIGH
    if score == _MEDIUM_THRESHOLD:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def _finalize_detections(scan: Dict[str, Dict[str, Any]], base_url: str) -> List[Dict[str, Any]]:
    """Turn a merged scan map into a sorted list of final detection dicts (technology/category/version/evidence/confidence/url)."""
    detections = []
    for name in sorted(scan):
        rec = scan[name]
        if rec["score"] <= 0:
            continue
        detections.append({
            "technology": name,
            "category": rec["category"],
            "version": rec.get("version"),
            "evidence": rec["evidence"],
            "confidence": _confidence_for_score(rec["score"]),
            "url": rec.get("confirmed_url") or base_url,
        })
    return detections


# ---------------------------------------------------------------------------
# 8. Normalization for surface_mapper.py (and direct pass-through
# compatibility with endpoint_discovery.py's existing `technology` param —
# see module docstring, NO-CROSS-MODULE-CALLS PRECEDENT, item (a))
# ---------------------------------------------------------------------------

def build_technology_summary(detections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize detections into the shape surface_mapper.py (not yet
    implemented) is expected to consume, and which is ALREADY directly
    consumable by endpoint_discovery.py's `technology` parameter today
    (its `select_wordlists_for_technology` substring-searches every string
    value in this structure).
    """
    summary: Dict[str, Any] = {
        "cms": sorted(d["technology"] for d in detections if d["category"] == CATEGORY_CMS),
        "frameworks": sorted(d["technology"] for d in detections if d["category"] == CATEGORY_FRAMEWORK),
        "servers": sorted(d["technology"] for d in detections if d["category"] == CATEGORY_SERVER),
        "wafs": sorted(d["technology"] for d in detections if d["category"] == CATEGORY_WAF),
        "detections": detections,
    }
    return summary


# ---------------------------------------------------------------------------
# 9. Downstream-recon trigger integration — see module docstring,
# NO-CROSS-MODULE-CALLS PRECEDENT, item (b). This module never calls
# endpoint_discovery.py itself; it only produces justified recommendations
# for the future orchestrator to execute.
# ---------------------------------------------------------------------------

def build_recommended_actions(detections: List[Dict[str, Any]], target: str) -> List[Dict[str, Any]]:
    """
    Build a decision-queue-shaped list of recommended next actions
    (context.md §9) for CMS/framework detections at MEDIUM+ confidence.
    Never executed here — status is always "queued_for_orchestrator".
    """
    actions: List[Dict[str, Any]] = []
    for d in detections:
        if d["category"] not in (CATEGORY_CMS, CATEGORY_FRAMEWORK):
            continue
        if d["confidence"] not in (CONFIDENCE_MEDIUM, CONFIDENCE_HIGH):
            continue

        tech_key = d["technology"].lower()
        has_wordlist = tech_key in _ENDPOINT_DISCOVERY_WORDLIST_TECHS
        if has_wordlist:
            note = (
                f"endpoint_discovery.py has a dedicated wordlist for {d['technology']} — "
                f"passing this module's technology_summary into "
                f"endpoint_discovery.enumerate_framework_paths()/run_endpoint_discovery(technology=...) "
                f"will select it automatically."
            )
        else:
            note = (
                f"No dedicated wordlist exists for {d['technology']} yet — "
                f"endpoint_discovery.discover_api_endpoints() and standard directory/file enumeration "
                f"remain applicable."
            )

        actions.append({
            "action": "endpoint_discovery.run_endpoint_discovery",
            "target_module": "endpoint_discovery.py",
            "technology": d["technology"],
            "category": d["category"],
            "reason": note,
            "justification": (
                f"[REASON: {d['technology']} fingerprinted with {d['confidence']} confidence "
                f"({len(d['evidence'])} converging signal(s)) — technology-aware endpoint discovery "
                f"is the adaptive-discovery next step per context.md §6]"
            ),
            "status": "queued_for_orchestrator",
        })
    return actions


# ---------------------------------------------------------------------------
# Negative-result memory (context.md §8/§12.6)
# ---------------------------------------------------------------------------

def persist_no_match_findings(
    categories_with_detections: set, target: str, url: str, store: Optional[PendingAssetsStore],
) -> List[str]:
    """Persist a negative-result-memory finding for every category with zero detections."""
    errors: List[str] = []
    for category in (CATEGORY_CMS, CATEGORY_FRAMEWORK, CATEGORY_SERVER, CATEGORY_WAF):
        if category in categories_with_detections:
            continue
        err = _safe_store_add(store, make_finding(
            finding_type="tech_fingerprint_checked_no_match",
            target=target,
            value={"category": category, "url": url},
            evidence=[f"No {category} signature matched headers/cookies/HTML/error-page content for {url}"],
            confidence=CONFIDENCE_LOW,
            metadata={
                "category": category, "url": url,
                "note": (
                    "Negative-result-memory: absence of a matching signature does not prove no such "
                    "technology is present — signatures are inherently incomplete, and some "
                    "technologies deliberately suppress identifying headers/markers."
                ),
            },
        ))
        if err:
            errors.append(err)
    return errors


# ---------------------------------------------------------------------------
# Module orchestration (single URL)
# ---------------------------------------------------------------------------

def run_tech_fingerprint(
    url: str,
    target: Optional[str] = None,
    output_dir: str = "output",
    timeout: float = DEFAULT_TIMEOUT,
    check_error_page: bool = True,
    check_favicon: bool = True,
    probe_known_paths_enabled: bool = True,
    favicon_signatures: Optional[Dict[str, Dict[str, Any]]] = None,
    max_known_path_probes: int = DEFAULT_MAX_KNOWN_PATH_PROBES,
) -> Dict[str, Any]:
    """
    Run all Module 8 technology-identification checks against a single URL
    and persist every completed detection immediately to
    <output_dir>/pending_assets.json. A failure in one stage does not
    prevent the others from running.
    """
    url = validate_url_target(url, target=target)
    target = target or (urllib.parse.urlsplit(url).hostname or url)
    origin = _origin_of(url)
    store = PendingAssetsStore(output_dir=output_dir)

    summary: Dict[str, Any] = {
        "url": url,
        "target": target,
        "module": MODULE_NAME,
        "started_at": _now(),
        "fetch_status": None,
        "technology_summary": {"cms": [], "frameworks": [], "servers": [], "wafs": [], "detections": []},
        "recommended_next_actions": [],
        "favicon": None,
        "errors": [],
    }

    baseline = fetch_url(url, timeout=timeout)
    summary["fetch_status"] = baseline["status"]
    if baseline["status"] != "found":
        summary["errors"].append({"stage": "fetch", "error": baseline.get("error")})
        summary["finished_at"] = _now()
        return summary

    headers = baseline["headers"]
    body = baseline.get("body")
    cookie_names = parse_cookie_names(baseline.get("set_cookie_headers", []))

    scans: List[Dict[str, Any]] = []

    try:
        scans.append(detect_technologies_from_content(headers, cookie_names, body, "baseline_response"))
    except Exception as exc:
        summary["errors"].append({"stage": "detect_technologies_from_content", "error": str(exc)})

    server_scan: Dict[str, Any] = {}
    try:
        server_scan = detect_servers(headers)
    except Exception as exc:
        summary["errors"].append({"stage": "detect_servers", "error": str(exc)})

    waf_scan: Dict[str, Any] = {}
    try:
        waf_scan = detect_wafs(headers, baseline.get("set_cookie_headers", []), body)
    except Exception as exc:
        summary["errors"].append({"stage": "detect_wafs", "error": str(exc)})

    if check_error_page:
        try:
            error_resp = fetch_error_page_sample(origin, timeout=timeout)
            if error_resp["status"] == "found":
                error_cookie_names = parse_cookie_names(error_resp.get("set_cookie_headers", []))
                scans.append(detect_technologies_from_content(
                    error_resp["headers"], error_cookie_names, error_resp.get("body"), "error_page_response",
                ))
            else:
                summary["errors"].append({"stage": "error_page_fetch", "error": error_resp.get("error")})
        except Exception as exc:
            summary["errors"].append({"stage": "error_page_fetch", "error": str(exc)})

    content_scan = _merge_scan_maps(*scans) if scans else {}

    if check_favicon:
        try:
            favicon_result = compute_favicon_hash(url, timeout=timeout)
            summary["favicon"] = favicon_result
            match = match_favicon_hash(favicon_result, favicon_signatures)
            if match:
                tech_name = match.pop("technology")
                content_scan = _merge_scan_maps(content_scan, {tech_name: match})
            elif favicon_result.get("md5"):
                err = _safe_store_add(store, make_finding(
                    finding_type="tech_fingerprint_favicon_observed",
                    target=target,
                    value={"url": favicon_result["url"], "md5": favicon_result["md5"], "sha256": favicon_result["sha256"]},
                    evidence=[f"Computed favicon hash for {favicon_result['url']} "
                              f"(md5={favicon_result['md5']}); no known signature matched"],
                    confidence=CONFIDENCE_LOW,
                    metadata={"url": favicon_result["url"], "md5": favicon_result["md5"],
                              "sha256": favicon_result["sha256"],
                              "note": "Negative-result memory: hash computed for future correlation "
                                      "once a signature database entry exists."},
                ))
                if err:
                    summary["errors"].append({"stage": "persist_favicon", "error": err})
        except Exception as exc:
            summary["errors"].append({"stage": "favicon", "error": str(exc)})

    if probe_known_paths_enabled and content_scan:
        try:
            corroboration = probe_known_paths(
                origin, list(content_scan.keys()), timeout=timeout, max_probes=max_known_path_probes,
            )
            content_scan = _merge_scan_maps(content_scan, corroboration)
        except Exception as exc:
            summary["errors"].append({"stage": "probe_known_paths", "error": str(exc)})

    all_scan = _merge_scan_maps(content_scan, server_scan, waf_scan)
    detections = _finalize_detections(all_scan, url)

    persistence_errors: List[str] = []
    for d in detections:
        err = _safe_store_add(store, make_tech_finding(
            technology=d["technology"], category=d["category"], version=d["version"],
            evidence=d["evidence"], confidence=d["confidence"], target=target, url=d["url"],
        ))
        if err:
            persistence_errors.append(err)
    if persistence_errors:
        summary["errors"].append({"stage": "persist_detections", "errors": persistence_errors})

    categories_found = {d["category"] for d in detections}
    negmem_errors = persist_no_match_findings(categories_found, target, url, store)
    if negmem_errors:
        summary["errors"].append({"stage": "negative_result_memory", "errors": negmem_errors})

    summary["technology_summary"] = build_technology_summary(detections)
    summary["recommended_next_actions"] = build_recommended_actions(detections, target)
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="tech_fingerprint.py",
        description="ReconHound Module 8 — technology identification (standalone test entry point).",
    )
    parser.add_argument("--url", required=True, help="Target URL, e.g. https://example.com/")
    parser.add_argument("--target", default=None, help="Logical target domain to enforce scope against")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout (seconds)")
    parser.add_argument("--no-error-page", action="store_true", help="Skip the error-page correlation probe")
    parser.add_argument("--no-favicon", action="store_true", help="Skip favicon hash computation")
    parser.add_argument("--no-known-paths", action="store_true", help="Skip known-path corroboration probing")
    args = parser.parse_args()

    try:
        result = run_tech_fingerprint(
            args.url, target=args.target, output_dir=args.output_dir, timeout=args.timeout,
            check_error_page=not args.no_error_page, check_favicon=not args.no_favicon,
            probe_known_paths_enabled=not args.no_known_paths,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
