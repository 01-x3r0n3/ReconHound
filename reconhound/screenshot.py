"""
reconhound/screenshot.py — ReconHound Module 18 per context.md's build
order (§13, position 19 in that list) and catalog item 18 in §10's module
list.

Phase: Active. See context.md §10 (module 18, "Visual asset triage") for
the authoritative responsibilities. This file only documents
implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Active — Visual asset triage. Screenshots of discovered web interfaces
  organized by subdomain; enables rapid visual identification of login
  pages/admin panels/default pages."

The assignment for this module expands that into these discrete
responsibilities, each implemented below:

  1. Capture screenshots of discovered web interfaces   -> capture_screenshot
  2. Organize screenshots by subdomain                   -> build_screenshot_paths
  3. Support rapid visual triage of large asset sets     -> run_screenshot_batch
  4. Preserve metadata associating each screenshot with
     its source URL/host                                 -> make_screenshot_finding
  5. Visual triage classification (login/admin/default)  -> classify_visual_triage

Plus shared plumbing: validate_url_target, make_finding, PendingAssetsStore,
_safe_store_add, fetch_url (duplicated per modular independence, same as
every other implemented module), and single-target/batch orchestrators
run_screenshot / run_screenshot_batch (mirroring the run_tech_fingerprint /
run_http_analysis precedent).

BUILD-ORDER NOTE: context.md §13 lists this module at build-order position
19, after surface_mapper.py (position 8). Per code_leak.py's/
passive_intel.py's/wayback_intel.py's/vuln_intel.py's/tech_fingerprint.py's
module docstrings, this repository is already operating under an explicit,
user-approved deviation from that order — surface_mapper.py has not been
implemented yet. This module continues under the same deviation: it is a
fully standalone producer that does not implement, replace, or depend on
surface_mapper.py's correlation engine.

NO-CROSS-MODULE-CALLS PRECEDENT: every already-implemented module in this
repository documents that it does NOT import or call into any sibling
module — integration is deferred to core/orchestrator.py (not yet built).
This module follows that same precedent: it does not call crawler.py,
endpoint_discovery.py, tech_fingerprint.py, or any other module to obtain
the list of URLs to capture. Callers (eventually the orchestrator) are
responsible for supplying discovered URLs; run_screenshot_batch simply
fans a caller-supplied URL list out across this module's own capture
pipeline and organizes the results.

Implementation decisions (ambiguities resolved so implementation can
proceed without inventing requirements):

  1. Capture mechanism: a real screenshot requires an actual rendering
     engine — there is no way to produce one from `requests` + BeautifulSoup
     alone. Selenium and Playwright are NOT installed in this project's
     dependencies (verified: `.venv` has neither, and requirements.txt does
     not list them), and adding either would mean a new third-party Python
     dependency plus separate browser-driver management. This Kali-based
     platform (context.md §5: "Python 3.10+, Linux/Kali") already ships a
     real headless-capable browser at `/usr/bin/chromium`, and Chromium's
     own `--headless=new --screenshot=<path>` flag is a stable, documented,
     dependency-free capture mechanism reachable via the stdlib `subprocess`
     module. This is the same reasoning tech_fingerprint.py used to reject a
     fabricated favicon-hash database: prefer a real, verifiable mechanism
     already available on the platform over inventing/adding machinery the
     project doesn't already depend on. `google-chrome`/`google-chrome-
     stable`/`chromium-browser` are also probed via `shutil.which` as
     fallbacks (`locate_browser_binary`) for portability to non-Kali hosts,
     and a caller may pass an explicit `binary_path` to override discovery
     entirely. When no such binary is found, capture is reported as
     unavailable (per-run, in `summary["errors"]`) rather than raising —
     this module must remain usable (and its other stages inert-but-safe)
     even on a host with no headless browser installed.
  2. Two-stage pipeline (cheap check before heavy capture): before invoking
     a Chromium subprocess, this module performs one lightweight `requests`
     GET (the same `fetch_url` pattern used by http_analyzer.py/
     endpoint_discovery.py/tech_fingerprint.py) against the URL. This
     achieves two things at once: (a) it is a bounded, signal-driven gate —
     a URL that is unreachable at the plain-HTTP level (DNS failure,
     connection refused, timeout) is reported as a capture failure without
     ever spawning a browser process for it, avoiding wasted process
     spawns/timeouts across a large asset set (context.md's "large asset
     sets" requirement); (b) the fetched body/title/status feed
     `classify_visual_triage` directly, so this module does not need a
     second, heavier mechanism (e.g. Chrome DevTools Protocol / --dump-dom)
     just to read back page text for triage. Any response that *was*
     reached — including 3xx/4xx/5xx — still proceeds to capture, because
     error/placeholder pages are themselves triage-relevant (context.md
     explicitly wants "default/placeholder pages" identified).
  3. Visual triage classification is evidence/confidence-scored using the
     exact same weak/strong signal-scoring model and LOW/MEDIUM/HIGH
     thresholds as tech_fingerprint.py's `_scan_signature`/
     `_confidence_for_score` (context.md §8: "multiple independent
     converging signals raise confidence; a single weak signal should
     generally stay LOW"), applied to the pre-check response's URL path,
     HTML body, and extracted `<title>` — not to screenshot pixels. No
     image-analysis/OCR dependency is introduced: the screenshot itself is
     for a human analyst's eyes (the actual "visual triage"); this
     classification is a machine-assisted hint attached as evidence-backed
     metadata, never asserted as a certainty. A finding's own top-level
     `confidence` is always HIGH when a screenshot was actually captured —
     that is a direct observation (the file exists), distinct from the
     *inferred* login/admin/default-page classification carried inside its
     `metadata["triage"]`, per context.md §8's Observation vs. Inference
     distinction.
  4. Filesystem organization ("organize screenshots by subdomain"):
     `<output_dir>/screenshots/<sanitized-host[_port]>/<sanitized-path>_
     <hash>.png`. The host segment is exactly the discovered subdomain
     (with a `_<port>` suffix only for a non-default port, so multiple
     services on the same host don't collide), satisfying "organized by
     subdomain" literally as a directory per host. Filenames are
     deterministic (derived from the URL path plus a short hash of the
     full URL) by default — same URL captured twice overwrites the same
     file, which is predictable and avoids unbounded disk growth across
     repeated runs; passing `unique_filenames=True` appends a capture
     timestamp for callers who want capture history preserved instead.
  5. Scope + safety: `validate_url_target` (duplicated per modular
     independence, same as every other module) is enforced both at
     `run_screenshot`'s entry AND re-checked inside `capture_screenshot`
     itself as defense-in-depth — `capture_screenshot` hands a
     caller-supplied URL string directly into a subprocess argv, so it
     independently refuses any non-http(s) scheme (e.g. `file://`) before
     ever building that command, rather than trusting every future caller
     to have validated first. `subprocess.run` is always called with a list
     argv (never `shell=True`), so shell metacharacter injection via the
     URL is not possible.
  6. Sandbox flag: Chromium's own sandbox refuses to start when the calling
     process is root (a well-known, narrowly-scoped Chromium constraint,
     unrelated to this module's own security posture). `no_sandbox`
     therefore defaults to `None`, meaning "auto": pass `--no-sandbox` only
     when `os.geteuid() == 0` on POSIX; explicitly pass `True`/`False` to
     override. The sandbox is left enabled for the common non-root case.
  7. Per-target failure isolation (context.md §12.11, "one module's failure
     must not unnecessarily break unrelated pipeline work"): `run_screenshot`
     never raises for a network/browser failure (only `ScopeError` for a
     caller-supplied out-of-scope/malformed URL propagates, mirroring every
     other module's `validate_url_target` boundary) — instead, failures are
     recorded per-stage in the returned summary's `errors` list, exactly
     following http_analyzer.py's/tech_fingerprint.py's established
     "`summary["errors"].append({"stage": ..., "error": ...})`, never
     persisted to pending_assets.json" precedent (only actual discoveries —
     here, successful captures — are written to the crash-safe store).
     `run_screenshot_batch` wraps each URL's `run_screenshot` call in its
     own try/except so one target's unexpected exception cannot abort the
     rest of a large batch.
  8. Negative-result memory (context.md §8/§12.6) is intentionally NOT
     emitted as a separate persisted finding per triage category here: the
     underlying check this module performs is simply "attempt capture" —
     its outcome (captured / capture_failed / browser_unavailable) is
     already a complete, non-repeatable-until-conditions-change record,
     unlike tech_fingerprint.py's per-signature-category scan where "no
     match yet" genuinely needs remembering to avoid re-scanning. Emitting
     three additional "no login/admin/default marker matched" findings per
     screenshot would be pure noise, not a memory of an expensive check
     worth skipping next time — so this module does not manufacture that
     concept where it does not fit, per CLAUDE.md's "do not invent
     requirements because they seem useful."
  9. Every discovery (a successfully captured screenshot) is persisted
     immediately to <output_dir>/pending_assets.json via PendingAssetsStore
     (the same crash-safe, atomic-write store shared by every other
     implemented module). This module does not implement or call into
     surface_mapper.py, exposure_scan.py, http_analyzer.py, or any other
     module.

DISCOVERY != EXPLOITATION: this module only ever issues GET/navigation
requests to the target's own discovered URLs to render and photograph what
is already publicly served there. It never submits forms, never attempts
authentication (no credentials are ever passed to Chromium), and never
interacts with page elements beyond passive rendering — consistent with
context.md's "reconnaissance and visual intelligence only" boundary for
this module.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests

MODULE_NAME = "screenshot.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

# Visual triage categories (context.md §10, module 18)
TRIAGE_LOGIN_PAGE = "login_page"
TRIAGE_ADMIN_PANEL = "admin_panel"
TRIAGE_DEFAULT_PLACEHOLDER = "default_placeholder_page"

DEFAULT_USER_AGENT = "ReconHound-Screenshot/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_MAX_BODY_BYTES = 131072
DEFAULT_CAPTURE_TIMEOUT_SECONDS = 25.0
DEFAULT_VIRTUAL_TIME_BUDGET_MS = 6000
DEFAULT_WINDOW_SIZE: Tuple[int, int] = (1280, 800)
DEFAULT_SCREENSHOT_SUBDIR = "screenshots"

BROWSER_BINARY_CANDIDATES: Tuple[str, ...] = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "google-chrome-unstable",
)

# Signal-scoring weights (mirrors tech_fingerprint.py's implementation
# decision #1: strong = direct/hard-to-accidentally-trigger, weak = generic)
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
# Scope enforcement (mirrors tech_fingerprint.py's/http_analyzer.py's
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
    in-scope check, mirroring the rest of the project's rationale: IP scope
    is enforced upstream, not by a domain comparison here).
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


def make_screenshot_finding(
    url: str,
    target: str,
    subdomain: str,
    screenshot_path: str,
    status_code: Optional[int],
    page_title: Optional[str],
    byte_length: int,
    capture_duration_seconds: Optional[float],
    triage: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Wrap one successful capture into the structured evidence record
    required by this module's contract: screenshot attributable to its
    source URL/host, plus enough metadata for rapid triage. `screenshot_path`
    is relative to `output_dir` so the record stays portable across hosts.
    """
    evidence = [f"Headless browser navigation to {url} returned HTTP {status_code}"] if status_code else [
        f"Headless browser navigation to {url} completed"
    ]
    evidence.append(f"Screenshot saved to {screenshot_path} ({byte_length} bytes)")
    return make_finding(
        finding_type="screenshot_captured",
        target=target,
        value={
            "url": url,
            "subdomain": subdomain,
            "screenshot_path": screenshot_path,
            "status_code": status_code,
            "page_title": page_title,
        },
        evidence=evidence,
        confidence=CONFIDENCE_HIGH,
        metadata={
            "url": url,
            "subdomain": subdomain,
            "screenshot_path": screenshot_path,
            "status_code": status_code,
            "page_title": page_title,
            "byte_length": byte_length,
            "capture_duration_seconds": capture_duration_seconds,
            "triage": triage,
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
# Shared HTTP pre-check client (mirrors tech_fingerprint.py's/
# http_analyzer.py's fetch_url; duplicated per modular independence)
# ---------------------------------------------------------------------------

def fetch_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """
    Perform a single HTTP GET against `url` (redirects followed, since this
    module wants to know what a browser would actually land on and render).
    """
    result: Dict[str, Any] = {
        "status": "error", "status_code": None, "headers": {},
        "body": None, "body_truncated": False, "final_url": url,
        "elapsed_seconds": None, "error": None,
    }
    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        req_headers.update(headers)

    resp = None
    try:
        resp = requests.get(url, timeout=timeout, headers=req_headers, allow_redirects=True, stream=True)
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


def extract_page_title(body: Optional[str]) -> Optional[str]:
    """Extract and normalize a <title> tag's text, if present."""
    if not body:
        return None
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title or None


# ---------------------------------------------------------------------------
# 2. Organize screenshots by subdomain — filesystem path construction
# ---------------------------------------------------------------------------

_SAFE_CHARS_RE = re.compile(r"[^a-z0-9._-]+")


def sanitize_path_component(value: str, fallback: str = "unknown") -> str:
    """Turn an arbitrary string into a safe single filesystem path component."""
    value = (value or "").strip().lower()
    value = _SAFE_CHARS_RE.sub("_", value)
    value = value.strip("._-")
    return value[:100] or fallback


def build_screenshot_paths(
    output_dir: str,
    url: str,
    unique_filenames: bool = False,
) -> Dict[str, str]:
    """
    Compute the subdomain-organized directory and deterministic filename for
    a screenshot of `url`, without touching the filesystem. Returns
    {"subdomain": ..., "directory": ..., "filename": ..., "absolute_path":
    ..., "relative_path": ...} — "relative_path" is relative to `output_dir`,
    which is what gets persisted in findings for portability.
    """
    parsed = urllib.parse.urlsplit(url)
    hostname = parsed.hostname or "unknown-host"
    subdomain = sanitize_path_component(hostname, fallback="unknown-host")

    default_port = 443 if parsed.scheme == "https" else 80
    if parsed.port and parsed.port != default_port:
        subdomain = f"{subdomain}_{parsed.port}"

    path_part = parsed.path.strip("/").replace("/", "_") or "root"
    if parsed.query:
        path_part = f"{path_part}_{parsed.query}"
    path_part = sanitize_path_component(path_part, fallback="root")[:60]

    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
    suffix = f"_{int(time.time())}" if unique_filenames else ""
    filename = f"{path_part}_{digest}{suffix}.png"

    directory = os.path.join(output_dir, DEFAULT_SCREENSHOT_SUBDIR, subdomain)
    relative_path = os.path.join(DEFAULT_SCREENSHOT_SUBDIR, subdomain, filename)
    return {
        "subdomain": subdomain,
        "directory": directory,
        "filename": filename,
        "absolute_path": os.path.join(directory, filename),
        "relative_path": relative_path,
    }


# ---------------------------------------------------------------------------
# 1. Capture screenshots of discovered web interfaces
# ---------------------------------------------------------------------------

def locate_browser_binary(
    candidates: Optional[Sequence[str]] = None,
    explicit_path: Optional[str] = None,
) -> Optional[str]:
    """
    Locate a usable headless-capable browser binary. An explicit_path is
    used as-is if it names an existing, executable file; otherwise each
    candidate name is looked up on PATH via shutil.which. Returns None
    (never raises) if nothing usable is found — see module docstring,
    implementation decision #1.
    """
    if explicit_path:
        if os.path.isfile(explicit_path) and os.access(explicit_path, os.X_OK):
            return explicit_path
        return None
    for name in candidates or BROWSER_BINARY_CANDIDATES:
        found = shutil.which(name)
        if found:
            return found
    return None


def _default_no_sandbox() -> bool:
    """Chromium's sandbox refuses to start as root; see implementation decision #6."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def capture_screenshot(
    url: str,
    output_path: str,
    binary_path: str,
    timeout: float = DEFAULT_CAPTURE_TIMEOUT_SECONDS,
    window_size: Tuple[int, int] = DEFAULT_WINDOW_SIZE,
    virtual_time_budget_ms: int = DEFAULT_VIRTUAL_TIME_BUDGET_MS,
    no_sandbox: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Invoke a headless Chromium-family browser to render `url` and save a
    screenshot to `output_path`. Never raises for capture-level failures
    (timeout, non-zero exit, missing output file) — those are reported in
    the returned dict's "status"/"error" fields instead, per this module's
    per-target failure-isolation contract.
    """
    result: Dict[str, Any] = {
        "status": "error", "output_path": output_path, "command": None,
        "returncode": None, "stderr_tail": None, "duration_seconds": None,
        "byte_length": 0, "error": None,
    }

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        # Defense-in-depth even though run_screenshot already validates this
        # (module docstring, implementation decision #5) — this function
        # must never hand a file://, chrome://, or similar scheme to the
        # browser subprocess.
        result["error"] = f"refusing to capture non-http(s) scheme {parsed.scheme!r}"
        return result

    try:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    except OSError as exc:
        result["error"] = f"failed to create output directory: {exc}"
        return result

    width, height = window_size
    use_no_sandbox = _default_no_sandbox() if no_sandbox is None else no_sandbox

    argv = [binary_path, "--headless=new", "--disable-gpu", "--hide-scrollbars",
            "--disable-extensions", "--disable-sync", "--mute-audio",
            f"--window-size={int(width)},{int(height)}",
            f"--virtual-time-budget={int(virtual_time_budget_ms)}",
            f"--screenshot={output_path}"]
    if use_no_sandbox:
        argv.append("--no-sandbox")
    argv.append(url)
    result["command"] = argv

    start = time.monotonic()
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        result["duration_seconds"] = time.monotonic() - start
        result["returncode"] = proc.returncode
        result["stderr_tail"] = (proc.stderr or "")[-2000:]

        if os.path.isfile(output_path) and os.path.getsize(output_path) > 0:
            result["status"] = "captured"
            result["byte_length"] = os.path.getsize(output_path)
        else:
            result["status"] = "error"
            result["error"] = (
                f"browser exited {proc.returncode} but no screenshot file was produced"
            )
    except subprocess.TimeoutExpired:
        result["duration_seconds"] = time.monotonic() - start
        result["status"] = "timeout"
        result["error"] = f"screenshot capture timed out after {timeout}s"
    except OSError as exc:
        result["duration_seconds"] = time.monotonic() - start
        result["status"] = "error"
        result["error"] = f"failed to launch browser binary {binary_path!r}: {exc}"
    return result


# ---------------------------------------------------------------------------
# Visual triage signature catalogs (mirrors tech_fingerprint.py's
# weak/strong scoring model — module docstring, implementation decision #3)
# ---------------------------------------------------------------------------

def _rx(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern, re.IGNORECASE)


_LOGIN_BODY_MARKERS: List[Tuple[int, "re.Pattern[str]"]] = [
    (_SCORE_STRONG, _rx(r'type=["\']password["\']')),
    (_SCORE_WEAK, _rx(r'name=["\']password["\']')),
    (_SCORE_WEAK, _rx(r"forgot(?: your)? password")),
    (_SCORE_WEAK, _rx(r"\bsign in\b")),
    (_SCORE_WEAK, _rx(r"\blog ?in\b")),
    (_SCORE_WEAK, _rx(r"username or email")),
]
_LOGIN_URL_MARKERS: List[str] = ["/login", "/signin", "/sign-in", "/wp-login.php", "/auth/login", "/account/login"]
_LOGIN_TITLE_MARKERS: List[str] = ["login", "sign in"]

_ADMIN_BODY_MARKERS: List[Tuple[int, "re.Pattern[str]"]] = [
    (_SCORE_WEAK, _rx(r"admin(?:istrator)? (?:panel|console|dashboard)")),
    (_SCORE_WEAK, _rx(r"control panel")),
    (_SCORE_WEAK, _rx(r"\bdashboard\b")),
]
_ADMIN_URL_MARKERS: List[str] = ["/admin", "/administrator", "/wp-admin", "/manage", "/cpanel", "/phpmyadmin"]
_ADMIN_TITLE_MARKERS: List[str] = ["admin", "dashboard", "control panel"]

# Strong because these are near-verbatim strings from specific, well-known
# default install pages — very low false-positive rate.
_DEFAULT_PAGE_BODY_MARKERS: List[Tuple[int, str]] = [
    (_SCORE_STRONG, "welcome to nginx!"),
    (_SCORE_STRONG, "apache2 ubuntu default page"),
    (_SCORE_STRONG, "if you can read this page, it means"),
    (_SCORE_STRONG, "it works!"),
    (_SCORE_STRONG, "iis windows server"),
    (_SCORE_STRONG, "test page for the apache http server"),
    (_SCORE_WEAK, "default web site page"),
]
_DEFAULT_PAGE_TITLE_MARKERS: List[str] = ["welcome to nginx", "apache2 ubuntu default page", "iis windows server", "index of /"]


def _score_category(
    body: str, path: str, title: str,
    body_markers: List[Tuple[int, Any]], url_markers: List[str], title_markers: List[str],
) -> Optional[Tuple[List[str], int]]:
    evidence: List[str] = []
    score = 0

    for weight, marker in body_markers:
        matched = marker.search(body) if hasattr(marker, "search") else (marker in body)
        if matched:
            display = marker.pattern if hasattr(marker, "pattern") else marker
            evidence.append(f"response body matches {display!r}")
            score += weight

    for marker in url_markers:
        if marker in path:
            evidence.append(f"URL path contains {marker!r}")
            score += _SCORE_WEAK

    for marker in title_markers:
        if marker in title:
            evidence.append(f"page title {title!r} contains {marker!r}")
            score += _SCORE_WEAK

    if not evidence:
        return None
    return evidence, score


def _confidence_for_score(score: int) -> str:
    if score >= _HIGH_THRESHOLD:
        return CONFIDENCE_HIGH
    if score == _MEDIUM_THRESHOLD:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def classify_visual_triage(
    body: Optional[str], final_url: str, page_title: Optional[str],
) -> List[Dict[str, Any]]:
    """
    Responsibility #5: classify an already-fetched page as a likely login
    page, administrative panel, and/or default/placeholder page, using the
    same evidence+confidence model as every other detection in this project
    (context.md §8). Multiple categories may match the same page (e.g. an
    admin login form matches both login_page and admin_panel). Returns a
    list of {"category":, "confidence":, "evidence": [...]}, empty if no
    signal matched at all.
    """
    body_lower = (body or "").lower()
    path_lower = (urllib.parse.urlsplit(final_url).path or "").lower()
    title_lower = (page_title or "").lower()

    classifications: List[Dict[str, Any]] = []
    for category, body_markers, url_markers, title_markers in (
        (TRIAGE_LOGIN_PAGE, _LOGIN_BODY_MARKERS, _LOGIN_URL_MARKERS, _LOGIN_TITLE_MARKERS),
        (TRIAGE_ADMIN_PANEL, _ADMIN_BODY_MARKERS, _ADMIN_URL_MARKERS, _ADMIN_TITLE_MARKERS),
        (TRIAGE_DEFAULT_PLACEHOLDER, _DEFAULT_PAGE_BODY_MARKERS, [], _DEFAULT_PAGE_TITLE_MARKERS),
    ):
        result = _score_category(body_lower, path_lower, title_lower, body_markers, url_markers, title_markers)
        if result is None:
            continue
        evidence, score = result
        classifications.append({
            "category": category,
            "confidence": _confidence_for_score(score),
            "evidence": evidence,
        })
    return classifications


# ---------------------------------------------------------------------------
# Module orchestration (single URL)
# ---------------------------------------------------------------------------

def run_screenshot(
    url: str,
    target: Optional[str] = None,
    output_dir: str = "output",
    timeout: float = DEFAULT_TIMEOUT,
    capture_timeout: float = DEFAULT_CAPTURE_TIMEOUT_SECONDS,
    binary_path: Optional[str] = None,
    window_size: Tuple[int, int] = DEFAULT_WINDOW_SIZE,
    virtual_time_budget_ms: int = DEFAULT_VIRTUAL_TIME_BUDGET_MS,
    no_sandbox: Optional[bool] = None,
    unique_filenames: bool = False,
    classify: bool = True,
) -> Dict[str, Any]:
    """
    Run the full Module 18 pipeline against a single URL: validate scope,
    do a lightweight reachability pre-check, capture a screenshot via a
    headless browser, classify it for visual triage, and persist a
    successful capture immediately to <output_dir>/pending_assets.json. A
    failure at any stage is recorded in the returned summary's "errors"
    list rather than raised or silently dropped (module docstring,
    implementation decisions #2 and #7).
    """
    url = validate_url_target(url, target=target)
    target = target or (urllib.parse.urlsplit(url).hostname or url)
    store = PendingAssetsStore(output_dir=output_dir)

    paths = build_screenshot_paths(output_dir, url, unique_filenames=unique_filenames)

    summary: Dict[str, Any] = {
        "url": url,
        "target": target,
        "module": MODULE_NAME,
        "started_at": _now(),
        "status": "error",
        "subdomain": paths["subdomain"],
        "screenshot_path": None,
        "status_code": None,
        "page_title": None,
        "triage": [],
        "errors": [],
    }

    precheck = fetch_url(url, timeout=timeout)
    summary["status_code"] = precheck.get("status_code")
    summary["page_title"] = extract_page_title(precheck.get("body"))

    if precheck["status"] != "found":
        summary["status"] = "unreachable"
        summary["errors"].append({"stage": "precheck", "error": precheck.get("error")})
        summary["finished_at"] = _now()
        return summary

    resolved_binary = locate_browser_binary(explicit_path=binary_path)
    if not resolved_binary:
        summary["status"] = "browser_unavailable"
        summary["errors"].append({
            "stage": "locate_binary",
            "error": (
                "No headless-capable browser binary found (tried explicit_path "
                f"and PATH candidates {BROWSER_BINARY_CANDIDATES!r})"
            ),
        })
        summary["finished_at"] = _now()
        return summary

    capture = capture_screenshot(
        url=precheck.get("final_url") or url,
        output_path=paths["absolute_path"],
        binary_path=resolved_binary,
        timeout=capture_timeout,
        window_size=window_size,
        virtual_time_budget_ms=virtual_time_budget_ms,
        no_sandbox=no_sandbox,
    )

    if capture["status"] != "captured":
        summary["status"] = "capture_failed"
        summary["errors"].append({"stage": "capture", "error": capture.get("error"),
                                   "returncode": capture.get("returncode"),
                                   "stderr_tail": capture.get("stderr_tail")})
        summary["finished_at"] = _now()
        return summary

    triage: List[Dict[str, Any]] = []
    if classify:
        try:
            triage = classify_visual_triage(precheck.get("body"), precheck.get("final_url") or url, summary["page_title"])
        except Exception as exc:
            summary["errors"].append({"stage": "classify_visual_triage", "error": str(exc)})

    finding = make_screenshot_finding(
        url=precheck.get("final_url") or url,
        target=target,
        subdomain=paths["subdomain"],
        screenshot_path=paths["relative_path"],
        status_code=precheck.get("status_code"),
        page_title=summary["page_title"],
        byte_length=capture["byte_length"],
        capture_duration_seconds=capture.get("duration_seconds"),
        triage=triage,
    )
    err = _safe_store_add(store, finding)
    if err:
        summary["errors"].append({"stage": "persist", "error": err})

    summary["status"] = "captured"
    summary["screenshot_path"] = paths["relative_path"]
    summary["triage"] = triage
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# 3. Support rapid visual triage of large asset sets — batch orchestration
# ---------------------------------------------------------------------------

def run_screenshot_batch(
    urls: Sequence[str],
    target: Optional[str] = None,
    output_dir: str = "output",
    **run_screenshot_kwargs: Any,
) -> Dict[str, Any]:
    """
    Run run_screenshot() across a list of discovered URLs. Each URL is
    isolated in its own try/except so one target's unexpected failure
    cannot abort the rest of a large batch (module docstring, implementation
    decision #7). Results are grouped by subdomain for rapid triage.
    """
    results: List[Dict[str, Any]] = []
    by_subdomain: Dict[str, List[Dict[str, Any]]] = {}
    counts = {"captured": 0, "unreachable": 0, "capture_failed": 0, "browser_unavailable": 0, "scope_rejected": 0, "unexpected_error": 0}

    for url in urls:
        try:
            result = run_screenshot(url, target=target, output_dir=output_dir, **run_screenshot_kwargs)
        except ScopeError as exc:
            result = {
                "url": url, "target": target, "module": MODULE_NAME, "status": "scope_rejected",
                "subdomain": None, "screenshot_path": None, "status_code": None, "page_title": None,
                "triage": [], "errors": [{"stage": "validate_url_target", "error": str(exc)}],
                "started_at": _now(), "finished_at": _now(),
            }
        except Exception as exc:
            result = {
                "url": url, "target": target, "module": MODULE_NAME, "status": "unexpected_error",
                "subdomain": None, "screenshot_path": None, "status_code": None, "page_title": None,
                "triage": [], "errors": [{"stage": "run_screenshot", "error": str(exc)}],
                "started_at": _now(), "finished_at": _now(),
            }

        results.append(result)
        counts[result["status"]] = counts.get(result["status"], 0) + 1
        subdomain_key = result.get("subdomain") or "_unresolved"
        by_subdomain.setdefault(subdomain_key, []).append(result)

    return {
        "module": MODULE_NAME,
        "target": target,
        "total": len(urls),
        "counts": counts,
        "by_subdomain": by_subdomain,
        "results": results,
    }


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="screenshot.py",
        description="ReconHound Module 18 — visual asset triage (standalone test entry point).",
    )
    parser.add_argument("--url", default=None, help="Single target URL, e.g. https://example.com/")
    parser.add_argument("--urls-file", default=None, help="Path to a newline-delimited file of URLs for batch capture")
    parser.add_argument("--target", default=None, help="Logical target domain to enforce scope against")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json and screenshots/")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Pre-check HTTP timeout (seconds)")
    parser.add_argument("--capture-timeout", type=float, default=DEFAULT_CAPTURE_TIMEOUT_SECONDS, help="Browser capture timeout (seconds)")
    parser.add_argument("--binary-path", default=None, help="Explicit path to a headless-capable browser binary")
    args = parser.parse_args()

    if not args.url and not args.urls_file:
        parser.error("one of --url or --urls-file is required")

    try:
        if args.urls_file:
            with open(args.urls_file, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
            result = run_screenshot_batch(
                urls, target=args.target, output_dir=args.output_dir,
                timeout=args.timeout, capture_timeout=args.capture_timeout, binary_path=args.binary_path,
            )
        else:
            result = run_screenshot(
                args.url, target=args.target, output_dir=args.output_dir,
                timeout=args.timeout, capture_timeout=args.capture_timeout, binary_path=args.binary_path,
            )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
