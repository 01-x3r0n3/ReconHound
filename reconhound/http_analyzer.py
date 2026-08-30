"""
reconhound/http_analyzer.py — ReconHound Module 3 (http_analyzer.py, per the
context.md §13 build order — catalog item 16 in §10's module list).

Phase: Active. See context.md §10 (module 16, "HTTP security posture") for
the authoritative responsibilities, and §8 for the evidence/confidence
data model this module implements. This file only documents
implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "HTTP security posture. Security headers (CSP/HSTS/X-Frame-Options/
  X-Content-Type-Options/Referrer-Policy/Permissions-Policy), cookie flags
  (HttpOnly/Secure/SameSite), CORS (origin reflection/null origin/
  wildcards), auth surfaces (login/logout/password-reset/OAuth/SSO/MFA
  indicators), JWT detection + algorithm inspection (no exploitation),
  cache intelligence, host-header behavior, redirect-chain mapping, WAF
  signal detection."

That is nine discrete responsibilities, each implemented as its own
function below, plus a shared HTTP fetch helper and a single-URL
orchestrator (mirroring the run_passive_recon/run_active_recon precedent
in Modules 1/2 — not itself a listed context.md responsibility):

  - Security headers          -> analyze_security_headers
  - Cookie flags              -> analyze_cookie_flags
  - CORS                      -> analyze_cors
  - Auth surfaces             -> detect_auth_surfaces
  - JWT detection + alg       -> detect_jwts
  - Cache intelligence        -> analyze_cache_headers
  - Host-header behavior      -> analyze_host_header_behavior
  - Redirect-chain mapping    -> map_redirect_chain
  - WAF signal detection      -> detect_waf
  - (shared HTTP client)      -> fetch_url
  - (single-host orchestrator)-> run_http_analysis

Scope boundaries (deliberately preserved, not incidental):

  - This module analyzes ONE caller-supplied URL (or a small number of
    requests derived from it — CORS/host-header checks, redirect hops). It
    does not enumerate paths, crawl links, or brute-force directories —
    that is endpoint_discovery.py's and crawler.py's job. detect_auth_
    surfaces and detect_jwts inspect the content already fetched from that
    one URL; they do not fetch additional pages to search for auth
    surfaces or tokens elsewhere on the site.
  - "Host-header behavior" here means testing whether *this* target
    reflects/trusts an arbitrary Host header on its own configured
    hostname (a security-posture question) — it is NOT vhost_scanner.py's
    job of brute-forcing many *real* candidate hostnames against a
    discovered IP to find hidden virtual hosts. Those are different
    checks; this module only does the former.
  - WAF detection is passive signature matching (headers/cookies/body of
    an already-fetched normal response, plus the extra CORS/host-header
    requests this module already makes for its own reasons). No
    additional probe requests are crafted purely to provoke a WAF, and no
    bypass/evasion technique of any kind is implemented.
  - JWT "algorithm inspection" decodes the unsigned header/payload
    segments (this is always possible — JWTs are base64url-encoded, not
    encrypted, by design) to report the declared `alg` and flag `alg:
    none`. No signature verification, cracking, or forgery is performed.
    Token values and claim values are never persisted in full — only a
    short preview and claim *names* — to avoid leaking session data.

Implementation decisions:

  1. `requests` is added as a new dependency (requirements.txt). It is
     already part of context.md §5's approved tech stack; no earlier
     module needed to make outbound JSON/HTTP calls, so it was not yet
     installed. This is the first module that genuinely requires it.
  2. Every function that follows a server-controlled redirect (Location
     header) enforces the same scope-enforcement discipline as Module 1/2:
     it will not silently follow a redirect to a hostname outside the
     supplied `target`, and refuses to follow a redirect to a private/
     loopback/link-local IP literal (a lightweight SSRF safeguard —
     protects the machine running ReconHound from a malicious/compromised
     target redirecting it at internal infrastructure; this is a
     defensive addition, not a new offensive capability).
  3. Persistence follows the same two-tier convention established in
     Modules 1/2: composite "we checked this URL's HTTP posture" results
     (security headers, cookie flags, cache headers, host-header
     behavior, redirect-chain mapping) are always persisted on successful
     completion — mirroring passive_recon.py's analyze_email_security, for
     negative-result memory. Weaker/more circumstantial signals (auth-
     surface indicators, JWTs, CORS misconfiguration, WAF detection) are
     persisted only when something is actually found, mirroring
     passive_recon.py's enumerate_dns/discover_asn (a "no WAF signature
     matched" result is not strong evidence of "no WAF present", so it
     is not persisted as a negative fact).

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
Modules 1 and 2, sharing the same output file). Output is intended to feed
surface_mapper.py (not yet implemented) — this module does not implement
or call into surface_mapper, endpoint_discovery, crawler, exposure_scan,
vuln_intel, risk_engine, orchestrator, report_generator, or any other
later module.
"""

from __future__ import annotations

import argparse
import base64
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

MODULE_NAME = "http_analyzer.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_USER_AGENT = "ReconHound-HTTPAnalyzer/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_MAX_BODY_BYTES = 65536


class ScopeError(ValueError):
    """Raised when a URL/target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------

def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_disallowed_redirect_ip(host: str) -> bool:
    """
    True if `host` is an IP literal in a private/loopback/link-local/
    reserved range — a lightweight SSRF safeguard for redirect-following
    (see module docstring, decision #2).
    """
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified
    )


def _in_scope_host(hostname: str, target: str) -> bool:
    """Mirrors passive_recon.py's is_in_scope; duplicated per modular independence."""
    hostname = hostname.strip().rstrip(".").lower()
    target = target.strip().rstrip(".").lower()
    return hostname == target or hostname.endswith("." + target)


def validate_url_target(url: str, target: Optional[str] = None) -> str:
    """
    Validate that `url` is a syntactically valid http(s) URL, and — if
    `target` is supplied — that its hostname is the target itself or a
    subdomain of it (an IP-literal host is allowed through without an
    in-scope check, since scope for IP hosts is enforced upstream, e.g. by
    active_recon.py's IP scoping, not by a domain comparison here).
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
# Evidence-model helpers (mirrors passive_recon.py's/active_recon.py's model;
# kept local per the "modular independence" design principle, context.md §12.2)
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
# Crash-safe persistence (same file/format as passive_recon.py's/
# active_recon.py's PendingAssetsStore, duplicated here per modular
# independence rather than imported, so this module works standalone)
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


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _ci_get(headers: Dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup (requests preserves server casing)."""
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None


# ---------------------------------------------------------------------------
# Shared HTTP client (not itself a listed context.md responsibility, but
# necessary plumbing for all nine analysis functions below — see module
# docstring)
# ---------------------------------------------------------------------------

def fetch_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = False,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """
    Perform a single HTTP GET against `url`.

    allow_redirects=False by default: callers that need to traverse
    redirects (map_redirect_chain) do so explicitly, hop by hop, so scope
    can be enforced between hops rather than letting the HTTP client
    follow them silently.
    """
    result: Dict[str, Any] = {
        "status": "error", "status_code": None, "headers": {}, "set_cookie_headers": [],
        "body": None, "body_truncated": False, "final_url": url,
        "elapsed_seconds": None, "error": None,
    }
    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        req_headers.update(headers)

    resp = None
    try:
        resp = requests.get(
            url, timeout=timeout, headers=req_headers, allow_redirects=allow_redirects, stream=True,
        )
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
# 1. Security headers
# ---------------------------------------------------------------------------

_SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]


def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Inspect the six security-relevant response headers context.md names.
    Reports presence/value/light structural notes — does not claim a
    security property is "confirmed" beyond what the header value itself
    states.
    """
    result: Dict[str, Any] = {}
    for name in _SECURITY_HEADERS:
        value = _ci_get(headers, name)
        entry: Dict[str, Any] = {"present": value is not None, "value": value, "notes": []}

        if name == "Content-Security-Policy" and value:
            if "unsafe-inline" in value:
                entry["notes"].append("policy allows 'unsafe-inline'")
            if "unsafe-eval" in value:
                entry["notes"].append("policy allows 'unsafe-eval'")
        elif name == "Strict-Transport-Security":
            if value:
                m = re.search(r"max-age=(\d+)", value)
                max_age = int(m.group(1)) if m else None
                entry["max_age"] = max_age
                if max_age is not None and max_age < 15552000:  # 180 days
                    entry["notes"].append("max-age is below the commonly recommended 180 days")
            else:
                entry["notes"].append("HSTS not present (relevant primarily over HTTPS)")
        elif name == "X-Content-Type-Options" and value and value.strip().lower() != "nosniff":
            entry["notes"].append(f"unexpected value {value!r} (expected 'nosniff')")

        if value is None:
            entry["notes"].append("header not present")

        result[name] = entry
    return result


# ---------------------------------------------------------------------------
# 2. Cookie flags
# ---------------------------------------------------------------------------

def analyze_cookie_flags(set_cookie_headers: List[str]) -> List[Dict[str, Any]]:
    """Parse HttpOnly/Secure/SameSite flags from each Set-Cookie header."""
    parsed: List[Dict[str, Any]] = []
    for raw in set_cookie_headers or []:
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue
        name_value = parts[0]
        name = name_value.split("=", 1)[0] if "=" in name_value else name_value
        attrs = [p.lower() for p in parts[1:]]

        http_only = any(a == "httponly" for a in attrs)
        secure = any(a == "secure" for a in attrs)
        samesite = None
        for a in parts[1:]:
            if a.lower().startswith("samesite="):
                samesite = a.split("=", 1)[1].strip()

        issues = []
        if not http_only:
            issues.append("missing HttpOnly flag")
        if not secure:
            issues.append("missing Secure flag")
        if samesite is None:
            issues.append("SameSite attribute not set")
        elif samesite.lower() == "none" and not secure:
            issues.append("SameSite=None without Secure flag")

        parsed.append({
            "name": name, "http_only": http_only, "secure": secure,
            "samesite": samesite, "issues": issues,
        })
    return parsed


# ---------------------------------------------------------------------------
# 3. CORS (origin reflection / null origin / wildcard)
# ---------------------------------------------------------------------------

_CORS_TEST_ORIGIN = "https://reconhound-cors-test.invalid"


def analyze_cors(url: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Send the same GET with an arbitrary cross-origin Origin header and
    with Origin: null, and observe the server's Access-Control-Allow-*
    response — standard, non-intrusive CORS-posture observation (no
    cross-origin request is actually completed by a browser; this only
    inspects what the server *would* allow).
    """
    result: Dict[str, Any] = {
        "origin_reflected": False, "null_origin_allowed": False, "wildcard": False,
        "allow_credentials_with_wildcard_or_reflection": False, "checks": [], "error": None,
    }
    for label, origin_value in (("arbitrary_origin", _CORS_TEST_ORIGIN), ("null_origin", "null")):
        resp = fetch_url(url, timeout=timeout, headers={"Origin": origin_value}, allow_redirects=False)
        if resp["status"] != "found":
            result["checks"].append({"label": label, "status": resp["status"], "error": resp["error"]})
            continue

        acao = _ci_get(resp["headers"], "Access-Control-Allow-Origin")
        acac = _ci_get(resp["headers"], "Access-Control-Allow-Credentials")
        result["checks"].append({
            "label": label, "origin_sent": origin_value,
            "access_control_allow_origin": acao, "access_control_allow_credentials": acac,
        })

        credentials_true = bool(acac) and acac.strip().lower() == "true"
        if label == "arbitrary_origin" and acao == _CORS_TEST_ORIGIN:
            result["origin_reflected"] = True
            if credentials_true:
                result["allow_credentials_with_wildcard_or_reflection"] = True
        if label == "null_origin" and acao == "null":
            result["null_origin_allowed"] = True
        if acao == "*":
            result["wildcard"] = True
            if credentials_true:
                result["allow_credentials_with_wildcard_or_reflection"] = True
    return result


# ---------------------------------------------------------------------------
# 4. Auth surfaces (login/logout/password-reset/OAuth/SSO/MFA indicators)
# ---------------------------------------------------------------------------

_AUTH_INDICATOR_PATTERNS = {
    "login": [r"\blogin\b", r"\bsign[\s\-]?in\b", r'name=["\']?password["\']?', r'type=["\']?password["\']?'],
    "logout": [r"\blogout\b", r"\bsign[\s\-]?out\b"],
    "password_reset": [r"forgot[\s\-]?password", r"reset[\s\-]?password", r"password[\s\-]?recovery"],
    "oauth": [r"oauth2?\b", r"/authorize\b", r"client_id="],
    "sso": [r"\bsso\b", r"\bsaml\b", r"single[\s\-]?sign[\s\-]?on"],
    "mfa": [r"\bmfa\b", r"\b2fa\b", r"multi[\s\-]?factor", r"one[\s\-]?time[\s\-]?passcode", r"\botp\b"],
}


def detect_auth_surfaces(url: str, body: Optional[str], headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Look for auth-surface indicators in the page already fetched for
    `url` — content/header keyword signals, not a path enumeration (that
    is endpoint_discovery.py's job).
    """
    body_lower = (body or "").lower()
    indicators: Dict[str, List[str]] = {}
    for category, patterns in _AUTH_INDICATOR_PATTERNS.items():
        matched = [p for p in patterns if re.search(p, body_lower)]
        if matched:
            indicators[category] = matched

    www_auth = _ci_get(headers, "WWW-Authenticate")
    if www_auth:
        indicators.setdefault("http_auth_challenge", []).append(www_auth)

    return {"url": url, "indicators": indicators}


# ---------------------------------------------------------------------------
# 5. JWT detection + algorithm inspection (no exploitation)
# ---------------------------------------------------------------------------

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")


def _b64url_decode(segment: str) -> Optional[bytes]:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        return None


def _decode_jwt(token: str) -> Dict[str, Any]:
    """
    Decode (not verify) the header/payload of a JWT-shaped string. JWTs
    are base64url-encoded, not encrypted, so this requires no key/secret —
    it is not a cryptographic attack. Only the declared algorithm and
    claim *names* are kept; the raw token and claim values are never
    persisted, to avoid leaking session data.
    """
    entry: Dict[str, Any] = {
        "token_preview": (token[:12] + "..." + token[-6:]) if len(token) > 24 else "***",
        "alg": None, "header_typ": None, "payload_claim_names": [], "error": None,
    }
    parts = token.split(".")
    if len(parts) != 3:
        entry["error"] = "not a 3-segment JWT"
        return entry

    header_bytes = _b64url_decode(parts[0])
    if header_bytes is None:
        entry["error"] = "unable to base64url-decode header segment"
        return entry
    try:
        header_json = json.loads(header_bytes.decode("utf-8", errors="replace"))
        entry["alg"] = header_json.get("alg") if isinstance(header_json, dict) else None
        entry["header_typ"] = header_json.get("typ") if isinstance(header_json, dict) else None
    except Exception:
        entry["error"] = "header segment is not valid JSON"
        return entry

    payload_bytes = _b64url_decode(parts[1])
    if payload_bytes is not None:
        try:
            payload_json = json.loads(payload_bytes.decode("utf-8", errors="replace"))
            if isinstance(payload_json, dict):
                entry["payload_claim_names"] = sorted(payload_json.keys())
        except Exception:
            pass  # payload not parseable as JSON — header info is still useful
    return entry


def detect_jwts(
    body: Optional[str], headers: Dict[str, str], set_cookie_headers: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Scan response body/headers/cookies for JWT-shaped tokens and decode their (unsigned) header/payload."""
    haystacks: List[str] = []
    if body:
        haystacks.append(body)
    haystacks.extend(headers.values())
    haystacks.extend(set_cookie_headers or [])

    found_tokens = set()
    for text in haystacks:
        found_tokens.update(_JWT_RE.findall(text))

    decoded = [_decode_jwt(t) for t in sorted(found_tokens)]
    weak_alg_detected = any((d.get("alg") or "").lower() == "none" for d in decoded)
    return {"count": len(decoded), "tokens": decoded, "weak_alg_detected": weak_alg_detected}


# ---------------------------------------------------------------------------
# 6. Cache intelligence
# ---------------------------------------------------------------------------

_CACHE_HEADERS = ["Cache-Control", "Pragma", "Expires", "ETag", "Age", "Vary"]


def analyze_cache_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    result: Dict[str, Any] = {name: _ci_get(headers, name) for name in _CACHE_HEADERS}
    cache_control = (result.get("Cache-Control") or "").lower()

    notes = []
    if not result.get("Cache-Control") and not result.get("Pragma"):
        notes.append("no Cache-Control/Pragma headers present")
    elif result.get("Cache-Control") and "no-store" not in cache_control and "private" not in cache_control:
        notes.append("response may be cacheable by shared caches (no 'no-store'/'private' directive)")
    result["notes"] = notes
    return result


# ---------------------------------------------------------------------------
# 7. Host-header behavior
# ---------------------------------------------------------------------------

_HOST_HEADER_PROBE = "reconhound-hostheader-probe.invalid"


def analyze_host_header_behavior(url: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Compare the response to the real request against a second request with
    an arbitrary Host header, to observe whether the server trusts/
    reflects an untrusted Host value (a security-posture question).

    This is distinct from vhost_scanner.py's later job of brute-forcing
    many *real* candidate vhost names against a discovered IP to find
    hidden applications — see module docstring.
    """
    baseline = fetch_url(url, timeout=timeout, allow_redirects=False)
    probe = fetch_url(url, timeout=timeout, headers={"Host": _HOST_HEADER_PROBE}, allow_redirects=False)

    result: Dict[str, Any] = {
        "status": "checked" if baseline["status"] == "found" and probe["status"] == "found" else "error",
        "baseline_status_code": baseline.get("status_code"),
        "probe_status_code": probe.get("status_code"),
        "status_code_changed": None,
        "probe_host_reflected": False,
        "error": baseline.get("error") or probe.get("error"),
    }
    if result["status"] == "checked":
        result["status_code_changed"] = baseline["status_code"] != probe["status_code"]
        probe_location = _ci_get(probe["headers"], "Location") or ""
        if _HOST_HEADER_PROBE in (probe.get("body") or "") or _HOST_HEADER_PROBE in probe_location:
            result["probe_host_reflected"] = True
    return result


# ---------------------------------------------------------------------------
# 8. Redirect-chain mapping
# ---------------------------------------------------------------------------

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)


def map_redirect_chain(
    url: str,
    target: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_hops: int = 10,
) -> Dict[str, Any]:
    """
    Follow redirects hop by hop (not via requests' built-in
    allow_redirects, so scope can be enforced between hops): stops before
    following a Location header to a host outside `target` (if supplied)
    or to a private/loopback/link-local IP literal (SSRF safeguard).
    """
    chain: List[Dict[str, Any]] = []
    current = url
    stopped_reason: Optional[str] = None

    for _ in range(max_hops):
        resp = fetch_url(current, timeout=timeout, allow_redirects=False)
        hop_entry: Dict[str, Any] = {
            "url": current, "status_code": resp.get("status_code"), "error": resp.get("error"),
        }
        chain.append(hop_entry)

        if resp["status"] != "found":
            stopped_reason = "fetch_error"
            break
        if resp["status_code"] not in _REDIRECT_STATUS_CODES:
            stopped_reason = "terminal_response"
            break

        location = _ci_get(resp["headers"], "Location")
        if not location:
            stopped_reason = "redirect_without_location"
            break

        next_url = urllib.parse.urljoin(current, location)
        hop_entry["location"] = next_url
        next_host = urllib.parse.urlsplit(next_url).hostname or ""

        if _is_disallowed_redirect_ip(next_host):
            stopped_reason = "next_hop_disallowed_ip"
            break
        if target and not _is_ip_literal(next_host) and not _in_scope_host(next_host, target):
            stopped_reason = "next_hop_out_of_scope"
            break

        current = next_url
    else:
        stopped_reason = "max_hops_reached"

    return {"start_url": url, "hops": chain, "final_url": current, "stopped_reason": stopped_reason}


# ---------------------------------------------------------------------------
# 9. WAF signal detection (detection only — no bypass/evasion)
# ---------------------------------------------------------------------------

_WAF_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "cloudflare": {
        "headers": {"server": ["cloudflare"], "cf-ray": None},
        "cookies": ["__cfduid", "cf_clearance"],
        "body": ["attention required! | cloudflare", "cloudflare ray id"],
    },
    "akamai": {
        "headers": {"server": ["akamaighost"], "x-akamai-transformed": None},
        "cookies": ["akamai"],
        "body": ["reference #", "akamai"],
    },
    "imperva_incapsula": {
        "headers": {"x-iinfo": None, "x-cdn": ["incapsula"]},
        "cookies": ["incap_ses", "visid_incap"],
        "body": ["incapsula incident id"],
    },
    "sucuri": {
        "headers": {"server": ["sucuri/cloudproxy"], "x-sucuri-id": None},
        "cookies": [],
        "body": ["access denied - sucuri website firewall"],
    },
    "aws_waf": {
        "headers": {"x-amzn-waf-action": None},
        "cookies": ["aws-waf-token"],
        "body": [],
    },
    "f5_big_ip_asm": {
        "headers": {"server": ["big-ip"]},
        "cookies": ["bigipserver", "ts01"],
        "body": ["the requested url was rejected"],
    },
    "modsecurity": {
        "headers": {"server": ["mod_security", "modsecurity"]},
        "cookies": [],
        "body": ["this error was generated by mod_security"],
    },
}


def detect_waf(
    headers: Dict[str, str],
    set_cookie_headers: Optional[List[str]] = None,
    body: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Passive WAF/security-technology signature matching against headers,
    Set-Cookie names, and body markers of an already-fetched response.
    Detection only: no additional attack-shaped payloads are crafted or
    sent to provoke a WAF, and no bypass/evasion is attempted.
    """
    lower_headers = {k.lower(): (v or "").lower() for k, v in headers.items()}
    cookies_text = " ".join(set_cookie_headers or []).lower()
    body_lower = (body or "").lower()

    detections = []
    for vendor, sig in _WAF_SIGNATURES.items():
        evidence = []
        for header_name, expected_substrings in sig["headers"].items():
            value = lower_headers.get(header_name)
            if value is None:
                continue
            if expected_substrings is None:
                evidence.append(f"header {header_name!r} present: {value!r}")
            else:
                evidence.extend(
                    f"header {header_name!r} contains {sub!r}"
                    for sub in expected_substrings if sub in value
                )
        evidence.extend(
            f"Set-Cookie contains marker {marker!r}"
            for marker in sig["cookies"] if marker in cookies_text
        )
        evidence.extend(
            f"response body contains marker {marker!r}"
            for marker in sig["body"] if marker in body_lower
        )
        if evidence:
            detections.append({"vendor": vendor, "evidence": evidence})

    return {"detected": bool(detections), "vendors": detections}


# ---------------------------------------------------------------------------
# Module orchestration (single URL)
# ---------------------------------------------------------------------------

def run_http_analysis(
    url: str,
    target: Optional[str] = None,
    output_dir: str = "output",
    timeout: float = DEFAULT_TIMEOUT,
    max_redirect_hops: int = 10,
) -> Dict[str, Any]:
    """
    Run all nine Module 3 checks against a single URL and persist every
    completed check immediately to <output_dir>/pending_assets.json.

    Returns a structured summary in addition to (not instead of) the
    crash-safe persisted store. A failure in one check does not prevent
    the others from running.
    """
    url = validate_url_target(url, target=target)
    store = PendingAssetsStore(output_dir=output_dir)

    summary: Dict[str, Any] = {
        "url": url,
        "target": target or url,
        "module": MODULE_NAME,
        "started_at": _now(),
        "fetch_status": None,
        "security_headers": {},
        "cookies": [],
        "cache": {},
        "auth_surfaces": {},
        "jwt": {},
        "waf": {},
        "cors": {},
        "host_header": {},
        "redirect_chain": {},
        "errors": [],
    }

    baseline = fetch_url(url, timeout=timeout, allow_redirects=False)
    summary["fetch_status"] = baseline["status"]
    if baseline["status"] != "found":
        summary["errors"].append({"stage": "fetch", "error": baseline.get("error")})
        summary["finished_at"] = _now()
        return summary

    headers = baseline["headers"]
    body = baseline.get("body")
    set_cookie_headers = baseline.get("set_cookie_headers", [])

    try:
        sec_headers = analyze_security_headers(headers)
        summary["security_headers"] = sec_headers
        store.add(make_finding(
            finding_type="http_security_headers", target=target or url,
            value={"url": url, "headers": sec_headers},
            evidence=[f"Fetched {url} and inspected security-relevant response headers"],
            confidence=CONFIDENCE_HIGH, metadata={"url": url},
        ))
    except Exception as exc:
        summary["errors"].append({"stage": "security_headers", "error": str(exc)})

    try:
        cookie_flags = analyze_cookie_flags(set_cookie_headers)
        summary["cookies"] = cookie_flags
        store.add(make_finding(
            finding_type="http_cookie_flags", target=target or url,
            value={"url": url, "cookies": cookie_flags},
            evidence=[f"Inspected {len(cookie_flags)} Set-Cookie header(s) from {url}"],
            confidence=CONFIDENCE_HIGH, metadata={"url": url},
        ))
    except Exception as exc:
        summary["errors"].append({"stage": "cookie_flags", "error": str(exc)})

    try:
        cache = analyze_cache_headers(headers)
        summary["cache"] = cache
        store.add(make_finding(
            finding_type="http_cache_headers", target=target or url,
            value={"url": url, "cache": cache},
            evidence=[f"Inspected cache-related headers from {url}"],
            confidence=CONFIDENCE_HIGH, metadata={"url": url},
        ))
    except Exception as exc:
        summary["errors"].append({"stage": "cache_headers", "error": str(exc)})

    try:
        auth = detect_auth_surfaces(url, body, headers)
        summary["auth_surfaces"] = auth
        if auth["indicators"]:
            store.add(make_finding(
                finding_type="http_auth_surface_indicators", target=target or url,
                value=auth,
                evidence=[f"Content/headers from {url} matched auth-surface indicators: "
                          f"{', '.join(auth['indicators'].keys())}"],
                confidence=CONFIDENCE_LOW, metadata={"url": url},
            ))
    except Exception as exc:
        summary["errors"].append({"stage": "auth_surfaces", "error": str(exc)})

    try:
        jwt_result = detect_jwts(body, headers, set_cookie_headers)
        summary["jwt"] = jwt_result
        if jwt_result["count"]:
            store.add(make_finding(
                finding_type="http_jwt_detected", target=target or url,
                value=jwt_result,
                evidence=[f"Found {jwt_result['count']} JWT-shaped token(s) in response from {url}"],
                confidence=CONFIDENCE_HIGH if jwt_result["weak_alg_detected"] else CONFIDENCE_MEDIUM,
                metadata={"url": url, "weak_alg_detected": jwt_result["weak_alg_detected"]},
            ))
    except Exception as exc:
        summary["errors"].append({"stage": "jwt", "error": str(exc)})

    try:
        waf = detect_waf(headers, set_cookie_headers, body)
        summary["waf"] = waf
        if waf["detected"]:
            store.add(make_finding(
                finding_type="waf_detected", target=target or url,
                value=waf,
                evidence=[f"{v['vendor']}: {', '.join(v['evidence'])}" for v in waf["vendors"]],
                confidence=CONFIDENCE_MEDIUM, metadata={"url": url},
            ))
    except Exception as exc:
        summary["errors"].append({"stage": "waf", "error": str(exc)})

    try:
        cors = analyze_cors(url, timeout=timeout)
        summary["cors"] = cors
        if cors["origin_reflected"] or cors["null_origin_allowed"] or cors["wildcard"]:
            store.add(make_finding(
                finding_type="http_cors_misconfiguration", target=target or url,
                value=cors,
                evidence=[f"CORS check against {url}: reflected={cors['origin_reflected']}, "
                          f"null_allowed={cors['null_origin_allowed']}, wildcard={cors['wildcard']}"],
                confidence=CONFIDENCE_HIGH,
                metadata={
                    "url": url,
                    "allow_credentials_with_wildcard_or_reflection":
                        cors["allow_credentials_with_wildcard_or_reflection"],
                },
            ))
    except Exception as exc:
        summary["errors"].append({"stage": "cors", "error": str(exc)})

    try:
        host_header = analyze_host_header_behavior(url, timeout=timeout)
        summary["host_header"] = host_header
        if host_header["status"] == "checked":
            store.add(make_finding(
                finding_type="http_host_header_behavior", target=target or url,
                value=host_header,
                evidence=[f"Compared baseline vs. spoofed-Host-header response for {url}"],
                confidence=CONFIDENCE_HIGH, metadata={"url": url},
            ))
    except Exception as exc:
        summary["errors"].append({"stage": "host_header", "error": str(exc)})

    try:
        redirect_chain = map_redirect_chain(url, target=target, timeout=timeout, max_hops=max_redirect_hops)
        summary["redirect_chain"] = redirect_chain
        store.add(make_finding(
            finding_type="http_redirect_chain", target=target or url,
            value=redirect_chain,
            evidence=[f"Mapped redirect chain from {url} ({len(redirect_chain['hops'])} hop(s))"],
            confidence=CONFIDENCE_HIGH, metadata={"url": url},
        ))
    except Exception as exc:
        summary["errors"].append({"stage": "redirect_chain", "error": str(exc)})

    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="http_analyzer.py",
        description="ReconHound Module 3 — HTTP security posture analysis (standalone test entry point).",
    )
    parser.add_argument("--url", required=True, help="Target URL, e.g. https://example.com/")
    parser.add_argument("--target", default=None, help="Logical target domain to enforce scope against")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout (seconds)")
    args = parser.parse_args()

    try:
        result = run_http_analysis(
            args.url, target=args.target, output_dir=args.output_dir, timeout=args.timeout,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
