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

  - This module analyzes ONE caller-supplied URL (plus a small, capped
    number of requests derived from it — CORS Origin probes, the
    host-header probe, redirect hops). It does not enumerate paths, crawl
    links, or brute-force directories — that is endpoint_discovery.py's
    and crawler.py's job. detect_auth_surfaces and detect_jwts inspect the
    content already fetched from that one URL; they do not fetch
    additional pages to search for auth surfaces or tokens elsewhere.
  - CSP is parsed here for the *posture of the header itself* (is the
    policy enforced or report-only, does it permit inline/eval/wildcard
    script sources, is it well-formed). Classifying CSP host sources into
    third-party trust relationships is supply_chain.py's responsibility
    (context.md §10 item 14) and is deliberately NOT duplicated: this
    module records the directive tokens it observed as evidence and stops
    there.
  - "Host-header behavior" here means testing whether *this* target
    reflects/trusts an arbitrary Host header on its own configured
    hostname (a security-posture question) — it is NOT vhost_scanner.py's
    job of brute-forcing many *real* candidate hostnames against a
    discovered IP to find hidden virtual hosts.
  - WAF detection is passive signature matching (headers/cookie names/body
    of an already-fetched response, plus the CORS/host-header requests
    this module already makes for its own reasons). No additional probe
    requests are crafted purely to provoke a WAF, and no bypass/evasion
    technique of any kind is implemented.
  - JWT "algorithm inspection" decodes the unsigned header/payload
    segments (this is always possible — JWTs are base64url-encoded, not
    encrypted, by design) to report the declared `alg`, flag `alg: none`,
    and derive expiry state. No signature verification, cracking, forgery,
    algorithm-confusion testing or `kid` traversal is performed. Token
    values, claim values and `kid` values are never persisted — only a
    short header-segment preview, claim *names*, and derived booleans.

SECURITY / RESOURCE BOUNDARIES enforced by this module (each one closes a
defect reproduced against the previous implementation, and each is covered
by a regression test):

  * Scope. Control characters and backslashes are rejected rather than
    silently stripped by urlsplit; a URL urlsplit cannot parse raises
    ScopeError instead of a bare ValueError; hostnames are IDNA-normalised
    before comparison so an IDN and its A-label form cannot look like
    different hosts; `user:password@` credentials are stripped from every
    URL before it is requested, recorded or persisted.
  * Redirects. A redirect target is chosen by the *server*, not the
    operator, so map_redirect_chain applies a stricter gate than
    validate_url_target: non-http(s) schemes are refused, private/
    loopback/link-local/reserved IP literals are refused, an IP literal is
    followed only when it *is* the target, and when no `target` was
    supplied the start URL's own host becomes the scope. Previously a
    target-less run would follow a `Location:` to an external identity
    provider, to an obfuscated internal address, or to `file:///`.
    Redirect loops are detected instead of being spent against the hop
    budget.
  * Attribution. An off-target redirect target, an external identity
    provider, and a CDN/edge cache are recorded as *what they are* and
    never merged into the target's own posture. A response served from an
    intermediary cache is labelled as such, because its headers are a
    cached copy and are not proof of current origin behaviour.
  * Evidence strength. Nothing here upgrades an observation into a
    confirmed vulnerability. `Access-Control-Allow-Origin: *` together
    with `Access-Control-Allow-Credentials: true` is recorded as a server
    misconfiguration that browsers *reject* — it is not credentialed
    cross-origin read access, and the finding says so. A WAF signature is
    a vendor indicator, not proof; the absence of one is explicitly not
    evidence of absence. An external redirect is not an open redirect.
  * Secrets. pending_assets.json is shared with every module and rendered
    in the report's raw-data appendix (CLAUDE.md rule 16), so cookie
    values, JWT payload/signature material, `kid` values and URL userinfo
    never reach it, and every persisted header value, cookie name and
    evidence string is length-clipped.
  * Resources. One request budget covers the whole run; response bodies
    are read bounded even on the fallback path, so a decompression bomb
    cannot be materialised; the JWT scanner is anchored so it cannot
    backtrack quadratically over a hostile body (a 64 KB body of "eyJ"
    repeats cost ~2.0 s of CPU before this change and ~0.001 s after).
    Every collection that reaches pending_assets.json is capped and says
    so when the cap bites: header values, note lists, cookie counts and
    attribute counts, CSP header/token/total budgets (one hostile CSP
    wrote 4.2 MiB and cost 281 ms before those caps; it now writes under
    64 KB in under 1 ms), and JWT counts.
  * Failure semantics. A refusal, a timeout or a truncated body is never
    absence. Negative-result findings (`http_analyzer_checked_no_*`,
    which surface_mapper.py trusts as authoritative "checked and not
    found" memory) are emitted only for checks that were actually
    conclusive, and never for WAF detection, where no signature matching
    is conclusive. Truncation is likewise never read as absence: a cookie
    whose attribute list was cut short claims no missing flag, and a
    persistence layer that could not be created reports zero findings
    persisted rather than a false success. No exception a transport can
    raise — including the many that are not RequestExceptions — ends the
    run; KeyboardInterrupt still does.

Implementation decisions:

  1. `requests` is part of context.md §5's approved tech stack.
  2. Persistence follows the two-tier convention established in Modules
     1/2: composite "we checked this URL's HTTP posture" results (security
     headers, cookie flags, cache headers, host-header behavior,
     redirect-chain mapping) are persisted on successful completion, for
     negative-result memory. Weaker/more circumstantial signals (auth-
     surface indicators, JWTs, CORS misconfiguration, WAF detection) are
     persisted only when something is found, plus an explicit
     `_checked_no_*` record where — and only where — a nil result is
     genuinely conclusive.
  3. Findings are persisted in ONE batched atomic write per run rather
     than one whole-file rewrite per finding, and the rename is committed
     with a directory fsync.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by the
other modules, sharing the same output file). Output feeds
surface_mapper.py; this module does not implement or call into
surface_mapper, endpoint_discovery, crawler, exposure_scan, supply_chain,
vuln_intel, risk_engine, orchestrator, report_generator, or any other
module.

KNOWN LIMITATIONS (documented rather than silently implied):

  * HTTP/1.1 only. `requests` speaks HTTP/1.1; HTTP/2 and HTTP/3 posture
    (ALPN negotiation, HPACK/QPACK header behaviour, h2-specific
    downgrade issues) is not observable here and adding it would mean a
    new transport dependency and a new module boundary — a v1 limitation,
    not a defect in this module. Recorded as `protocol_observed`.
  * CORS is probed with GET and a small fixed set of Origin values only.
    Preflight (OPTIONS) behaviour is not exercised here: per-endpoint
    OPTIONS discovery is exposure_scan.py's responsibility (context.md
    §10 item 15), and unbounded origin fuzzing is out of scope by design.
    A server whose CORS policy differs between preflight and actual
    requests, or between endpoints, will not be fully characterised.
  * Only the operator-supplied URL is analysed. Auth surfaces reachable
    only through client-side routing/JavaScript are invisible to an
    HTTP-only analyser; js_analyzer.py and crawler.py own that surface.
  * Duplicate-header detection depends on the HTTP adapter exposing the
    raw header list. When it does not, `header_lists_available` is False
    and duplicate/conflict detection is reported as unavailable rather
    than as "no duplicates".
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
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests

MODULE_NAME = "http_analyzer.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_USER_AGENT = "ReconHound-HTTPAnalyzer/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_MAX_BODY_BYTES = 65536
DEFAULT_MAX_REDIRECT_HOPS = 10

# One budget covers every request a single run makes: baseline (1) + CORS
# Origin probes (len(CORS_PROBES)) + host-header probe (1) + redirect hops
# (max_redirect_hops). The default leaves headroom over that worst case so an
# ordinary run is never truncated, while a pathological redirect chain or a
# caller passing a large max_hops still cannot make this module issue an
# unbounded number of requests.
DEFAULT_MAX_REQUESTS = 24

# Persisted-value caps. pending_assets.json is shared with every module and is
# rendered verbatim in the report's raw-data appendix, so a hostile server must
# not be able to write megabytes into it through one header.
MAX_HEADER_VALUE_CHARS = 4096
MAX_EVIDENCE_CHARS = 512
MAX_EVIDENCE_ITEMS = 24
MAX_COOKIES = 64
MAX_COOKIE_NAME_CHARS = 128
MAX_COOKIE_ATTRS = 32
MAX_CSP_POLICIES = 8
MAX_CSP_DIRECTIVES = 40
MAX_CSP_TOKENS_PER_DIRECTIVE = 60
MAX_CSP_TOKEN_CHARS = 128
MAX_CSP_TOKENS_TOTAL = 200     # across every directive of every policy in one header
MAX_CSP_HEADER_CHARS = 65536   # HTTP/1.1's own per-line limit; enforced here too
MAX_JWT_TOKENS = 32
MAX_JWT_SEGMENT_CHARS = 4096
MAX_AUTH_MATCH_SNIPPETS = 8
MAX_HSTS_DIGITS = 12          # 10^12 seconds ~= 31,000 years; anything longer is malformed
MAX_HSTS_POLICIES = 8
MAX_NOTES = 40                # per notes list, with an explicit truncation marker
MAX_NOTE_CHARS = 400
MAX_PERMISSIONS_POLICY_ITEMS = 100
MAX_REFERRER_POLICY_TOKENS = 32
MAX_COOKIE_PARTS = 512        # generous: a real Set-Cookie has fewer than ten
MAX_PROBE_HOST_CHARS = 253    # the DNS limit; a longer "host" is not probe-worthy
_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9._\-]+$")

HSTS_RECOMMENDED_MIN_MAX_AGE = 15552000   # 180 days


class ScopeError(ValueError):
    """Raised when a URL/target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


class BudgetExhausted(RuntimeError):
    """Internal signal: the run's request budget is spent. Never escapes run_http_analysis."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bound_notes(notes: List[str], limit: int = MAX_NOTES) -> List[str]:
    """
    Cap a notes list, and every note in it, before it is persisted.

    Notes are generated per directive / per policy item / per token, all of
    which are attacker-controlled: a Permissions-Policy carrying 20,000
    "feature=*" entries produced 20,000 notes and 1.3 MB in the shared
    pending_assets.json, and one Referrer-Policy produced a single 229 KB note.
    The truncation is stated rather than silent.
    """
    bounded = [_clip(n, MAX_NOTE_CHARS) for n in notes[:limit]]
    if len(notes) > limit:
        bounded.append(f"...[{len(notes) - limit} further note(s) omitted]")
    return bounded


def _clip(value: Any, limit: int) -> Any:
    """Length-clip a string for persistence, marking that it was clipped."""
    if not isinstance(value, str) or len(value) <= limit:
        return value
    return value[:limit] + f"...[clipped {len(value) - limit} chars]"


# ---------------------------------------------------------------------------
# Scope enforcement
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

    Without this, a target written as "münchen.de" and a hostname arriving as
    "xn--mnchen-3ya.de" (or the reverse) compare unequal even though they are
    the same host — an IDN mismatch that silently drops in-scope assets in one
    direction and, worse, would let a homograph host look "different" from the
    target it is impersonating. Both sides are folded to lowercase A-label
    form; anything that will not encode is returned lowercased unchanged so the
    caller still gets a deterministic comparison.

    Mirrors endpoint_discovery.py/exposure_scan.py, which share this file's
    scope vocabulary.
    """
    host = host.strip().rstrip(".").lower()
    if not host or host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return host


def _is_disallowed_redirect_ip(host: str) -> bool:
    """
    True if `host` is an IP literal in a private/loopback/link-local/
    reserved range — a lightweight SSRF safeguard for redirect-following.

    IPv4-mapped IPv6 forms (`::ffff:169.254.169.254`) are covered because
    ipaddress classifies them by their embedded IPv4 address.
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
    hostname = _idna_normalize(hostname)
    target = _idna_normalize(target)
    if not hostname or not target:
        return False
    return hostname == target or hostname.endswith("." + target)


def _strip_userinfo(url: str) -> str:
    """
    Remove any `user:password@` component from a URL.

    A credential in a URL must not be re-sent, must not become part of an
    asset identity, and above all must never be written into
    pending_assets.json — a plain-text file shared with every other module and
    included in the report appendix (CLAUDE.md rule 16). The netloc is rebuilt
    from the parsed host/port so the result is also the canonical form.
    """
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


def _host_allowed(hostname: str, target: Optional[str]) -> bool:
    """
    Scope gate for a host chosen by the *server* (a `Location:` header) rather
    than supplied by the operator.

    validate_url_target() lets a bare IP literal through unchecked, because an
    operator naming an IP has authorised that IP upstream. That reasoning does
    not carry over to a host this module read out of a redirect: a server can
    point `Location:` anywhere it likes, and following one unconditionally
    meant an in-scope host could steer the scanner at 169.254.169.254 (cloud
    instance metadata), at RFC1918 hosts, or at any third party — an
    authorisation boundary violation. An IP literal from a redirect is
    therefore accepted only when it *is* the target.
    """
    if not hostname or not target:
        return False
    if _is_ip_literal(hostname):
        return _idna_normalize(hostname) == _idna_normalize(target)
    return _in_scope_host(hostname, target)


def validate_url_target(url: str, target: Optional[str] = None) -> str:
    """
    Validate that `url` is a syntactically valid http(s) URL, and — if
    `target` is supplied — that its hostname is the target itself or a
    subdomain of it (an IP-literal host is allowed through without an
    in-scope check, since scope for IP hosts is enforced upstream, e.g. by
    active_recon.py's IP scoping, not by a domain comparison here).

    Returns the URL with any `user:password@` credentials removed.
    """
    if not isinstance(url, str) or not url.strip():
        raise ScopeError("URL must be a non-empty string.")

    candidate = url.strip()

    # A CR, LF, NUL, tab or backslash inside a URL is never legitimate.
    # urlsplit silently *removes* newlines and tabs, so such a URL validated
    # in its stripped form and was then handed to requests still carrying the
    # raw bytes — and was persisted with them. A backslash is a parser
    # differential: urlsplit reads "https://evil.com\@example.com/" as host
    # example.com while WHATWG parsers read it as evil.com, so the recorded
    # host and a browser's host can disagree. Both are refused here.
    for ch in "\r\n\t\x00\\":
        if ch in candidate:
            raise ScopeError(f"URL contains a control character or backslash: {url!r}")

    try:
        parsed = urllib.parse.urlsplit(candidate)
        hostname = parsed.hostname
        parsed.port  # raises ValueError on an out-of-range port
    except ValueError as exc:
        # urlsplit raises on malformed IPv6 brackets and out-of-range ports.
        # ScopeError subclasses ValueError, so a bare ValueError escaping here
        # was NOT caught by callers guarding on ScopeError.
        raise ScopeError(f"URL cannot be parsed: {url!r} ({exc})") from exc

    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"URL must use http:// or https://, not {parsed.scheme!r}: {url!r}")

    if not hostname:
        raise ScopeError(f"URL must include a hostname: {url!r}")

    if target and not _is_ip_literal(hostname) and not _in_scope_host(hostname, target):
        raise ScopeError(f"URL host {hostname!r} is not in scope for target {target!r}: {url!r}")

    # Credentials in an operator-supplied URL are dropped rather than
    # rejected: the URL is legitimate, but re-sending and persisting the
    # credential is not (see _strip_userinfo).
    return _strip_userinfo(candidate)


def _hostname_of(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _origin_of(url: str) -> str:
    """scheme://host[:port] for `url`, with any userinfo removed."""
    try:
        parsed = urllib.parse.urlsplit(_strip_userinfo(url))
    except ValueError:
        return ""
    if not parsed.scheme or not parsed.hostname:
        return ""
    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    return f"{parsed.scheme.lower()}://{host}" + (f":{port}" if port else "")


# ---------------------------------------------------------------------------
# Evidence-model helpers (mirrors passive_recon.py's/active_recon.py's model;
# kept local per the "modular independence" design principle, context.md §12.2)
# ---------------------------------------------------------------------------

def _jsonify(value: Any, _depth: int = 0) -> Any:
    """
    Coerce a value into something json.dump can definitely write.

    Findings carry data this module did not create — raw header values, cookie
    strings, decoded JWT header fields. A single value json.dump cannot
    serialise used to fail the whole batched write and take every other
    finding down with it. NaN/Infinity are accepted by json.dump but produce
    output a strict reader rejects, so they are stringified.

    Mirrors passive_recon.py's `_jsonify`, which shares this output file.
    """
    if _depth > 12:
        return str(value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
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
        "evidence": [_clip(_jsonify(e), MAX_EVIDENCE_CHARS)
                     for e in list(evidence)[:MAX_EVIDENCE_ITEMS]],
        "confidence": confidence,
        "source": MODULE_NAME,
        "timestamp": _now(),
        "metadata": _jsonify(metadata or {}),
    }


# ---------------------------------------------------------------------------
# Crash-safe persistence (same file/format as the other modules'
# PendingAssetsStore, duplicated here per modular independence rather than
# imported, so this module works standalone)
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
        self._lock = threading.Lock()
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

    def add(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Append one finding and persist immediately. Returns the finding."""
        self.add_many([finding])
        return finding

    def add_many(self, findings: List[Dict[str, Any]]) -> int:
        """
        Append a batch of findings in ONE read + ONE atomic write.

        add() rewrites the whole shared file per finding, which is quadratic in
        the number of records already on disk — and by the time this module
        runs in a --full-scan, pending_assets.json already holds every earlier
        module's output. Measured on this repository with 1000 pre-existing
        records, the nine findings of a single-URL run cost 0.139 s of pure
        rewrite with add() and 0.016 s batched.

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
        return str(exc)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _as_status_code(value: Any) -> Optional[int]:
    """
    Normalise a status code to an int (or None).

    Everything downstream compares it numerically (`status_code >= 400`), and
    a broken adapter or an unusual mock handing back a string turned that into
    a TypeError that killed a whole analysis stage. The transport boundary is
    the right place to fix the type once.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _ci_get(headers: Dict[str, str], name: str) -> Optional[str]:
    """
    Case-insensitive header lookup (requests preserves server casing).

    The value is coerced to str: everything downstream treats it as text, and
    a non-str value (from an unusual adapter or a caller passing a parsed
    structure) either crashed a stage on `.strip()` or was silently dropped
    and reported as "header not present" — a false negative.
    """
    if not headers:
        return None
    name_lower = name.lower()
    for k, v in headers.items():
        if str(k).lower() == name_lower:
            return v if v is None or isinstance(v, str) else str(v)
    return None


def _header_values(resp: Dict[str, Any], name: str) -> List[str]:
    """
    Every value the server sent for `name`, as a list.

    requests collapses repeated headers into one comma-joined string, which is
    lossless for some headers and actively misleading for others: two
    `Access-Control-Allow-Origin` headers become "https://a, https://b", which
    equals neither origin, and two `Strict-Transport-Security` headers hide a
    conflict behind whichever max-age happens to come first. fetch_url captures
    the raw list where the adapter exposes one; this falls back to the joined
    value when it does not.
    """
    lists = resp.get("header_lists") or {}
    values = lists.get(name.lower())
    if values:
        return [v for v in values if isinstance(v, str)]
    single = _ci_get(resp.get("headers") or {}, name)
    return [single] if isinstance(single, str) else []


_TEXTUAL_CONTENT_TYPES = (
    "text/", "application/json", "application/javascript", "application/xml",
    "application/xhtml", "application/x-www-form-urlencoded", "application/ld+json",
    "application/graphql", "application/problem+json",
)


def _looks_textual(content_type: Optional[str], body: Optional[str]) -> bool:
    """
    Whether a response body is worth running text analysis over.

    Scanning a PNG or a font for the word "login" produced auth-surface
    indicators on `/logo.png`; scanning it for JWT-shaped runs is pure cost.
    A declared textual content type is trusted; an undeclared one falls back to
    a printable-character ratio so a text/plain-ish body with no Content-Type
    is still analysed.
    """
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct:
        if any(ct.startswith(p) for p in _TEXTUAL_CONTENT_TYPES):
            return True
        if ct.endswith("+json") or ct.endswith("+xml"):
            return True
        return False
    if not body:
        return False
    sample = body[:4096]
    printable = sum(1 for ch in sample if ch == "\n" or ch == "\t" or ch == "\r" or 32 <= ord(ch) < 127 or ord(ch) > 160)
    return printable / max(1, len(sample)) > 0.85


class RequestBudget:
    """
    A hard cap on how many HTTP requests one run may issue.

    Every request this module makes is derived from a single operator-supplied
    URL, but the derivations compose (CORS probes x redirect hops x retries),
    and nothing previously bounded the total. `spend()` raises BudgetExhausted,
    which the orchestrator converts into an explicit, honest "not checked"
    outcome rather than a silent nil result.
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


# ---------------------------------------------------------------------------
# Shared HTTP client (not itself a listed context.md responsibility, but
# necessary plumbing for all nine analysis functions below)
# ---------------------------------------------------------------------------

# Headers whose repeated occurrences carry meaning this module reads. Captured
# as raw lists so duplicate/conflict detection is possible at all.
_MULTI_VALUE_HEADERS_OF_INTEREST = (
    "content-security-policy", "content-security-policy-report-only",
    "strict-transport-security", "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy", "feature-policy",
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-methods", "access-control-allow-headers",
    "vary", "cache-control", "pragma", "age", "location", "www-authenticate",
    "set-cookie",
)


def fetch_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = False,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    budget: Optional[RequestBudget] = None,
) -> Dict[str, Any]:
    """
    Perform a single HTTP GET against `url`.

    allow_redirects is False and MUST stay False: callers that need to
    traverse redirects (map_redirect_chain) do so explicitly, hop by hop, so
    scope can be enforced between hops. Letting `requests` follow a chain
    itself would take this module to any host the server names, past every
    scope and SSRF gate in this file, so the parameter is kept for signature
    compatibility and refused rather than quietly honoured.
    """
    if allow_redirects:
        raise ScopeError(
            "fetch_url cannot follow redirects: scope and SSRF gates are enforced between hops "
            "by map_redirect_chain, not by the HTTP client.")
    result: Dict[str, Any] = {
        "status": "error", "status_code": None, "headers": {}, "header_lists": {},
        "header_lists_available": False, "set_cookie_headers": [],
        "body": None, "body_truncated": False, "final_url": _strip_userinfo(url),
        "elapsed_seconds": None, "error": None,
    }
    if budget is not None:
        try:
            budget.spend()
        except BudgetExhausted as exc:
            result["status"] = "not_checked"
            result["error"] = str(exc)
            return result

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
            # Fallback for adapters/mocks without a usable .raw. It must stay
            # bounded: `resp.content` materialises the *entire* body before the
            # slice runs, so a 50 MB response (or a decompression bomb) was
            # fully resident in memory before being truncated to 64 KB.
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
                declared = _ci_get(dict(getattr(resp, "headers", {}) or {}), "Content-Length")
                hard_cap = max_body_bytes * 8
                try:
                    if declared is not None and int(declared) > hard_cap:
                        raise ValueError(f"declared body of {declared} bytes exceeds the read cap")
                    raw = resp.content[: max_body_bytes + 1]
                except Exception as body_exc:
                    raw = b""
                    result["body_read_error"] = str(body_exc)
        if not isinstance(raw, (bytes, bytearray)):
            raw = b""
        truncated = len(raw) > max_body_bytes
        body_bytes = bytes(raw[:max_body_bytes])
        try:
            body_text = body_bytes.decode(resp.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            body_text = body_bytes.decode("utf-8", errors="replace")

        merged_headers = dict(resp.headers)
        header_lists: Dict[str, List[str]] = {}
        lists_available = False
        getlist = getattr(getattr(resp, "raw", None), "headers", None)
        getlist = getattr(getlist, "getlist", None)
        if callable(getlist):
            lists_available = True
            for name in _MULTI_VALUE_HEADERS_OF_INTEREST:
                try:
                    values = [str(v) for v in getlist(name)]
                except Exception:
                    continue
                if not values:
                    continue
                # Trust the raw list only when it is consistent with the merged
                # header: urllib3 joins repeated headers with ", ", so
                # ", ".join(getlist(name)) must reproduce headers[name]. An
                # adapter (or a test double) whose getlist ignores the name it
                # was given would otherwise attribute one header's values to
                # every other header, silently corrupting CSP/CORS/HSTS
                # analysis. A mismatch disables duplicate detection rather than
                # producing a confident wrong answer.
                merged = _ci_get(merged_headers, name)
                if merged is None or ", ".join(values) != merged:
                    header_lists = {}
                    lists_available = False
                    break
                header_lists[name] = values

        set_cookie_headers = header_lists.get("set-cookie")
        if set_cookie_headers is None:
            # Set-Cookie is the one header requests' merged view genuinely
            # cannot represent (a comma is legal inside an Expires date), so it
            # is read from the raw list independently of the consistency gate
            # above, and only then falls back to the merged value.
            try:
                raw_cookies = list(getlist("Set-Cookie")) if callable(getlist) else []
            except Exception:
                raw_cookies = []
            if raw_cookies:
                set_cookie_headers = [str(v) for v in raw_cookies]
            else:
                single = _ci_get(merged_headers, "Set-Cookie")
                set_cookie_headers = [single] if single else []

        result.update({
            "status": "found",
            "status_code": _as_status_code(resp.status_code),
            "headers": merged_headers,
            "header_lists": header_lists,
            "header_lists_available": lists_available,
            "set_cookie_headers": list(set_cookie_headers),
            "body": body_text,
            "body_truncated": truncated,
            "final_url": _strip_userinfo(str(resp.url)),
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
    except Exception as exc:
        # `requests` is not the only thing that can fail here: IDNA encoding
        # raises UnicodeError, a broken transport adapter raises whatever it
        # likes, and neither is a RequestException. Letting those escape killed
        # the entire analysis for one bad response, which context.md §12.11
        # forbids. KeyboardInterrupt/SystemExit are BaseExceptions and still
        # propagate, so a Ctrl-C still stops the run.
        result["error"] = f"unexpected transport error: {type(exc).__name__}: {exc}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass
    return result


# ---------------------------------------------------------------------------
# 1. Security headers
# ---------------------------------------------------------------------------

_SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]

_CSP_KEYWORD_RE = re.compile(
    r"^'(self|none|unsafe-inline|unsafe-eval|unsafe-hashes|strict-dynamic|"
    r"report-sample|wasm-unsafe-eval|inline-speculation-rules)'$", re.IGNORECASE)
_CSP_NONCE_OR_HASH_RE = re.compile(r"^'(nonce|sha256|sha384|sha512)-", re.IGNORECASE)

# Directives whose source list actually governs code/content loading. A
# wildcard or scheme source here is materially different from one in, say,
# `report-uri`.
_CSP_FETCH_DIRECTIVES = frozenset({
    "default-src", "script-src", "script-src-elem", "script-src-attr", "style-src",
    "style-src-elem", "style-src-attr", "img-src", "connect-src", "font-src",
    "media-src", "object-src", "frame-src", "child-src", "worker-src", "manifest-src",
    "prefetch-src",
})
# Directives that are no longer honoured (or never were) by current browsers.
_CSP_DEPRECATED_DIRECTIVES = {
    "referrer": "superseded by the Referrer-Policy header",
    "reflected-xss": "removed from CSP; browsers ignore it",
    "block-all-mixed-content": "deprecated; upgrade-insecure-requests covers it",
    "plugin-types": "removed from CSP3; browsers ignore it",
    "report-uri": "deprecated in favour of report-to (still honoured by most browsers)",
}


def split_csp_policies(raw_value: str) -> List[str]:
    """
    Split one header value into the individual policies it carries.

    Two things collapse into a single string before this module sees them: a
    server sending several `Content-Security-Policy` headers (requests joins
    them with ", ") and a single header legitimately carrying several
    comma-separated policies. Both mean "these policies apply together", and
    each must be parsed on its own — a `'unsafe-inline'` inside one policy is
    not neutralised by a stricter sibling, but neither is a substring search
    over the joined text able to say which policy it came from.
    """
    # Bounded before parsing: the parsed tokens are persisted, and an
    # unbounded header produced a 4.2 MiB finding in the shared store (and
    # 281 ms of parsing) from one response.
    raw_value = (raw_value or "")[:MAX_CSP_HEADER_CHARS]
    return [p.strip() for p in raw_value.split(",") if p.strip()][:MAX_CSP_POLICIES]


def parse_csp_policy(policy: str) -> Dict[str, Any]:
    """Parse one CSP policy string into `{directive: [tokens]}` plus a malformed flag."""
    directives: Dict[str, List[str]] = {}
    duplicated: List[str] = []
    for segment in policy.split(";"):
        segment = segment.strip()
        if not segment:
            continue
        parts = segment.split()
        name = parts[0].lower()
        if not name:
            continue
        if name in directives:
            # A directive repeated inside one policy is an authoring error;
            # browsers honour the first and ignore the rest. Preserved as a
            # conflict rather than silently overwritten (context.md §8).
            if name not in duplicated:
                duplicated.append(name)
            continue
        directives[name] = [t[:MAX_CSP_TOKEN_CHARS]
                            for t in parts[1:][:MAX_CSP_TOKENS_PER_DIRECTIVE]]
        if len(directives) >= MAX_CSP_DIRECTIVES:
            break
    return {
        "directives": directives,
        "duplicate_directives": duplicated,
        "malformed": not directives and bool(policy.strip()),
    }


def analyze_csp(values: Sequence[str], disposition: str = "enforce") -> Dict[str, Any]:
    """
    Assess the posture of one or more CSP header values.

    Deliberately limited to the policy's *own* security properties. Which
    third-party hosts a policy allow-lists — and what that means for the
    supply chain — is supply_chain.py's job (context.md §10 item 14); the
    tokens are recorded here as evidence, not classified.
    """
    policies: List[Dict[str, Any]] = []
    notes: List[str] = []
    for value in values:
        for policy_text in split_csp_policies(value):
            policies.append({"policy": _clip(policy_text, MAX_HEADER_VALUE_CHARS),
                             **parse_csp_policy(policy_text)})

    if not policies:
        return {"disposition": disposition, "policies": [], "notes": [], "directives_present": [],
                "unsafe_inline_effective": [], "unsafe_inline_neutralised_by_nonce_or_hash": [],
                "unsafe_eval_directives": []}

    directives_present = sorted({name for p in policies for name in p["directives"]})
    # The per-directive and per-policy caps still allowed 8 x 40 x 60 tokens to
    # be persisted for one header (measured at 60 KiB in the shared store).
    # Real policies list a few dozen sources; a global budget keeps one
    # response from dominating pending_assets.json, and says so when it bites.
    budget = MAX_CSP_TOKENS_TOTAL
    tokens_truncated = False
    for parsed in policies:
        for name, tokens in list(parsed["directives"].items()):
            if budget <= 0:
                parsed["directives"][name] = []
                tokens_truncated = True
                continue
            if len(tokens) > budget:
                parsed["directives"][name] = tokens[:budget]
                tokens_truncated = True
            budget -= len(tokens)
    if tokens_truncated:
        notes.append(f"more than {MAX_CSP_TOKENS_TOTAL} CSP source tokens were sent; the excess was "
                     f"not recorded, so the token inventory below is incomplete")

    unsafe_inline_effective: List[str] = []
    unsafe_inline_neutralised: List[str] = []
    unsafe_eval_directives: List[str] = []
    detail_notes: List[str] = []

    for index, parsed in enumerate(policies):
        label = f"policy #{index + 1}" if len(policies) > 1 else "policy"
        if parsed["malformed"]:
            detail_notes.append(f"{label} could not be parsed into any directive (malformed)")
            continue
        for dup in parsed["duplicate_directives"]:
            detail_notes.append(
                f"{label} repeats directive {dup!r}; browsers honour the first and ignore the rest")
        for name, tokens in parsed["directives"].items():
            lowered = [t.lower() for t in tokens]
            has_nonce_or_hash = any(_CSP_NONCE_OR_HASH_RE.match(t) for t in tokens)
            if "'unsafe-inline'" in lowered:
                # CSP2+: a nonce- or hash-source in the SAME directive makes
                # browsers ignore 'unsafe-inline'. Flagging it regardless was a
                # false positive on every modern nonce-based policy.
                (unsafe_inline_neutralised if has_nonce_or_hash else unsafe_inline_effective).append(name)
            if "'unsafe-eval'" in lowered:
                unsafe_eval_directives.append(name)
            if name in _CSP_FETCH_DIRECTIVES:
                for token in tokens:
                    tl = token.lower()
                    if tl == "*":
                        detail_notes.append(f"{label} {name} allows any origin ('*')")
                    elif tl in ("http:", "https:", "data:", "blob:", "filesystem:"):
                        detail_notes.append(f"{label} {name} allows the whole {tl} scheme")
                    elif tl.startswith("*.") and tl.count(".") == 1:
                        detail_notes.append(f"{label} {name} allows a whole top-level suffix ({token})")
            if name in _CSP_DEPRECATED_DIRECTIVES:
                detail_notes.append(f"{label} uses {name!r}: {_CSP_DEPRECATED_DIRECTIVES[name]}")

    if unsafe_inline_effective:
        notes.append("policy allows 'unsafe-inline'")
        notes.append("'unsafe-inline' is effective in directive(s): "
                     + ", ".join(sorted(set(unsafe_inline_effective))))
    if unsafe_inline_neutralised:
        notes.append("'unsafe-inline' is listed in directive(s) "
                     + ", ".join(sorted(set(unsafe_inline_neutralised)))
                     + " alongside a nonce/hash source, so browsers that support nonces ignore it "
                       "(legacy fallback, not an effective relaxation)")
    if unsafe_eval_directives:
        notes.append("policy allows 'unsafe-eval'")
        notes.append("'unsafe-eval' appears in directive(s): "
                     + ", ".join(sorted(set(unsafe_eval_directives))))
    notes.extend(detail_notes)

    # Deduplicate while preserving first-seen order (determinism).
    seen: set = set()
    ordered_notes = [n for n in notes if not (n in seen or seen.add(n))]
    return {
        "disposition": disposition,
        "policies": policies,
        "directives_present": directives_present,
        "unsafe_inline_effective": sorted(set(unsafe_inline_effective)),
        "unsafe_inline_neutralised_by_nonce_or_hash": sorted(set(unsafe_inline_neutralised)),
        "unsafe_eval_directives": sorted(set(unsafe_eval_directives)),
        "tokens_truncated": tokens_truncated,
        "notes": _bound_notes(ordered_notes),
    }


_HSTS_MAX_AGE_RE = re.compile(r"^max-age$", re.IGNORECASE)


def parse_hsts(value: str) -> Dict[str, Any]:
    """
    Parse one Strict-Transport-Security value per RFC 6797.

    Directive names are case-insensitive and the value may be a quoted string,
    neither of which the previous `re.search(r"max-age=(\\d+)")` handled: a
    perfectly valid `Max-Age=31536000` or `max-age="31536000"` was read as "no
    max-age at all" and produced no note whatsoever. An implausibly long digit
    run is rejected as malformed rather than fed to int(), which raises
    ValueError above 4300 digits and previously destroyed the whole
    security-header stage.
    """
    result: Dict[str, Any] = {
        "max_age": None, "include_subdomains": False, "preload": False,
        "malformed_directives": [], "duplicate_directives": [],
    }
    seen: List[str] = []
    for segment in (value or "").split(";"):
        segment = segment.strip()
        if not segment:
            continue
        name, sep, raw = segment.partition("=")
        name = name.strip().lower()
        raw = raw.strip().strip('"').strip() if sep else ""
        if name in seen:
            if name not in result["duplicate_directives"]:
                result["duplicate_directives"].append(name)
            continue
        seen.append(name)
        if name == "max-age":
            if not sep or not raw.isdigit() or len(raw) > MAX_HSTS_DIGITS:
                result["malformed_directives"].append(_clip(segment, 120))
            else:
                result["max_age"] = int(raw)
        elif name == "includesubdomains":
            result["include_subdomains"] = True
        elif name == "preload":
            result["preload"] = True
        else:
            result["malformed_directives"].append(_clip(segment, 120))
    result["directives_seen"] = seen
    return result


def analyze_hsts(values: Sequence[str]) -> Dict[str, Any]:
    """
    Classify HSTS into the four states the previous implementation collapsed
    into two: absent / invalid / weak / strong, plus disabled (max-age=0,
    which is an explicit instruction to *forget* the policy and is not the
    same thing as a merely short max-age).
    """
    notes: List[str] = []
    if not values:
        # No note here: the caller appends the canonical "header not present".
        # Emitting a second note saying the same thing produced duplicate
        # entries in every persisted finding for an HTTPS host without HSTS.
        return {"posture": "absent", "max_age": None, "include_subdomains": False,
                "preload": False, "first_visit_protection_proven": False, "notes": []}

    # RFC 6797 gives Strict-Transport-Security no comma-delimited list form, so
    # a comma in the value means requests merged two headers into one string.
    # Expanding it here keeps the conflict visible even when the HTTP adapter
    # cannot hand over the raw header list (previously the whole merged string
    # was read as one malformed directive).
    expanded: List[str] = []
    for value in values:
        expanded.extend(part.strip() for part in (value or "").split(",") if part.strip())
    if not expanded:
        expanded = list(values)
    hsts_truncated = len(expanded) > MAX_HSTS_POLICIES
    expanded = expanded[:MAX_HSTS_POLICIES]

    parsed = [parse_hsts(v) for v in expanded]
    if len(parsed) > 1:
        # RFC 6797 §8.1: a UA that receives more than one STS header field
        # processes only the first. The disagreement is preserved rather than
        # silently resolved (context.md §8 conflict preservation).
        distinct = sorted({str(p["max_age"]) for p in parsed})
        notes.append(
            f"{len(parsed)} Strict-Transport-Security policies were received with max-age values "
            f"{', '.join(distinct)}; RFC 6797 says a browser honours only the first, so the "
            f"effective policy is ambiguous")
    if hsts_truncated:
        notes.append(f"more than {MAX_HSTS_POLICIES} Strict-Transport-Security policies were "
                     f"received; only the first {MAX_HSTS_POLICIES} were parsed")
    first = parsed[0]

    for bad in first["malformed_directives"]:
        notes.append(f"unrecognised or malformed HSTS directive {bad!r}")
    for dup in first["duplicate_directives"]:
        notes.append(f"HSTS directive {dup!r} appears more than once")

    max_age = first["max_age"]
    if max_age is None:
        posture = "invalid"
        notes.append("HSTS header present but carries no valid max-age directive, so it has no effect")
    elif max_age == 0:
        posture = "disabled"
        notes.append("max-age=0 instructs browsers to stop treating this host as HSTS-enabled")
    elif max_age < HSTS_RECOMMENDED_MIN_MAX_AGE:
        posture = "weak"
        notes.append("max-age is below the commonly recommended 180 days")
    else:
        posture = "strong"

    if posture in ("weak", "strong") and not first["include_subdomains"]:
        notes.append("includeSubDomains is not set, so subdomains are not covered by this policy")
    if first["preload"] and not (first["include_subdomains"] and (max_age or 0) >= 31536000):
        notes.append("the preload token is present but the policy does not meet the preload-list "
                     "requirements (max-age >= 1 year and includeSubDomains)")

    # HSTS never protects the very first plaintext request to a host unless the
    # host is on the browser's built-in preload list. The `preload` token is a
    # *request* to be listed, not proof of listing — which cannot be observed
    # from an HTTP response at all.
    return {
        "posture": posture,
        "max_age": max_age,
        "include_subdomains": first["include_subdomains"],
        "preload": first["preload"],
        "first_visit_protection_proven": False,
        "notes": _bound_notes(notes),
        "headers_seen": len(values),
        "policies_seen": len(parsed),
    }


_XFO_VALID = ("deny", "sameorigin")
_REFERRER_POLICY_TOKENS = frozenset({
    "", "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
    "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url",
})
_REFERRER_POLICY_WEAK = {
    "unsafe-url": "sends the full URL (path and query) to any cross-origin destination",
    "no-referrer-when-downgrade": "sends the full URL to any same- or higher-security origin",
    "origin-when-cross-origin": "sends the full URL to same-origin destinations",
}


def _analyze_x_frame_options(values: Sequence[str], csp_directives: Sequence[str]) -> List[str]:
    notes: List[str] = []
    tokens: List[str] = []
    for value in values:
        if value is None:
            continue
        # X-Frame-Options has no list form either; a comma means the header was
        # sent twice and merged.
        tokens.extend(part.strip().lower() for part in value.split(",") if part.strip())
    distinct = sorted(set(tokens))
    if len(tokens) > 1 and len(distinct) == 1:
        notes.append("X-Frame-Options sent more than once with the same value")
    if len(distinct) > 1:
        notes.append(f"conflicting X-Frame-Options values sent ({', '.join(repr(t) for t in distinct)}); "
                     f"browser behaviour is undefined")
    for token in distinct:
        if token in _XFO_VALID:
            continue
        if token.startswith("allow-from"):
            notes.append("ALLOW-FROM is deprecated and is ignored by every current browser; "
                         "use the CSP frame-ancestors directive instead")
        elif token == "allowall":
            notes.append("'ALLOWALL' is not a valid X-Frame-Options value and provides no protection")
        else:
            notes.append(f"unrecognised X-Frame-Options value {token!r} (expected DENY or SAMEORIGIN)")
    if "frame-ancestors" in csp_directives and any(t in _XFO_VALID for t in distinct):
        notes.append("a CSP frame-ancestors directive is also present and supersedes X-Frame-Options "
                     "in browsers that support it")
    return _bound_notes(notes)


def _analyze_referrer_policy(values: Sequence[str]) -> List[str]:
    notes: List[str] = []
    tokens: List[str] = []
    for value in values:
        tokens.extend(t.strip().lower() for t in (value or "").split(","))
    tokens = [t for t in tokens if t][:MAX_REFERRER_POLICY_TOKENS]
    if not tokens:
        notes.append("Referrer-Policy header present but empty")
        return notes
    unknown = sorted({t for t in tokens if t not in _REFERRER_POLICY_TOKENS})[:8]
    if unknown:
        notes.append(f"unrecognised Referrer-Policy token(s) "
                     f"{', '.join(repr(_clip(t, 60)) for t in unknown)}; "
                     f"browsers ignore tokens they do not know")
    # The *last* token a browser understands wins.
    effective = next((t for t in reversed(tokens) if t in _REFERRER_POLICY_TOKENS and t), None)
    if effective in _REFERRER_POLICY_WEAK:
        notes.append(f"effective policy {effective!r} {_REFERRER_POLICY_WEAK[effective]}")
    return _bound_notes(notes)


_PERMISSIONS_POLICY_ITEM_RE = re.compile(r"^[a-z0-9\-]+\s*=\s*(\*|\(.*\)|self|\".*\")$", re.IGNORECASE)


def _analyze_permissions_policy(values: Sequence[str]) -> List[str]:
    notes: List[str] = []
    for value in values:
        all_items = [i.strip() for i in (value or "").split(",") if i.strip()]
        # Length-cap each item too: the structural regex is linear, but it is
        # applied to attacker-controlled text and there is no analysis value
        # in a 60 KB "feature name".
        items = [i[:512] for i in all_items[:MAX_PERMISSIONS_POLICY_ITEMS]]
        if not items:
            notes.append("Permissions-Policy header present but empty")
            continue
        if len(all_items) > len(items):
            notes.append(f"only the first {MAX_PERMISSIONS_POLICY_ITEMS} of {len(all_items)} "
                         f"Permissions-Policy entries were analysed")
        for item in items:
            if "=" not in item:
                notes.append(f"Permissions-Policy entry {_clip(item, 80)!r} is not in "
                             f"feature=(allowlist) form; this is the legacy Feature-Policy syntax "
                             f"and is ignored")
            elif not _PERMISSIONS_POLICY_ITEM_RE.match(item):
                notes.append(f"Permissions-Policy entry {_clip(item, 80)!r} is malformed")
            elif item.split("=", 1)[1].strip() == "*":
                feature = item.split("=", 1)[0].strip()
                notes.append(f"Permissions-Policy allows {_clip(feature, 60)!r} for every origin ('*')")
    return _bound_notes(notes)


def analyze_security_headers(
    headers: Dict[str, str],
    header_lists: Optional[Dict[str, List[str]]] = None,
    header_lists_available: bool = False,
) -> Dict[str, Any]:
    """
    Inspect the six security-relevant response headers context.md names.

    Reports presence/value/structural notes; it does not claim a security
    property is "confirmed" beyond what the header value itself states, and it
    never claims that a policy which merely *exists* is being enforced
    correctly by any particular browser.

    The six top-level keys and their `present` booleans are the contract
    risk_engine.py's `_missing_security_headers` reads; everything else is
    additive.
    """
    lists = {k.lower(): list(v) for k, v in (header_lists or {}).items()}

    def values_for(name: str) -> List[str]:
        got = lists.get(name.lower())
        if got:
            return [v if isinstance(v, str) else str(v) for v in got if v is not None]
        single = _ci_get(headers, name)
        return [single] if isinstance(single, str) else []

    csp_values = values_for("Content-Security-Policy")
    csp_report_only_values = values_for("Content-Security-Policy-Report-Only")
    csp_enforced = analyze_csp(csp_values, disposition="enforce") if csp_values else None
    csp_report_only = (analyze_csp(csp_report_only_values, disposition="report-only")
                       if csp_report_only_values else None)
    csp_directives = (csp_enforced or {}).get("directives_present", [])

    result: Dict[str, Any] = {}
    for name in _SECURITY_HEADERS:
        raw_values = values_for(name)
        value = ", ".join(raw_values) if raw_values else None
        entry: Dict[str, Any] = {
            "present": value is not None,
            "value": _clip(value, MAX_HEADER_VALUE_CHARS),
            "notes": [],
            "headers_seen": len(raw_values),
        }
        if len(raw_values) > 1:
            entry["duplicate"] = True

        if name == "Content-Security-Policy":
            if csp_enforced:
                entry["notes"].extend(csp_enforced["notes"])
                entry["directives_present"] = csp_enforced["directives_present"]
                entry["policies"] = csp_enforced["policies"]
                entry["tokens_truncated"] = csp_enforced["tokens_truncated"]
            entry["report_only_present"] = bool(csp_report_only_values)
            if csp_report_only:
                entry["report_only"] = {
                    "value": _clip(", ".join(csp_report_only_values), MAX_HEADER_VALUE_CHARS),
                    "directives_present": csp_report_only["directives_present"],
                    "notes": csp_report_only["notes"],
                }
                if not csp_values:
                    # Absence of the enforcing header is still absence — but a
                    # report-only policy is monitoring, not enforcement, and
                    # saying nothing about it hid the distinction entirely.
                    entry["notes"].append(
                        "a Content-Security-Policy-Report-Only header is present; report-only "
                        "policies are monitored and reported, never enforced")

        elif name == "Strict-Transport-Security":
            hsts = analyze_hsts(raw_values)
            entry.update({k: v for k, v in hsts.items() if k != "notes"})
            entry["notes"].extend(hsts["notes"])

        elif name == "X-Frame-Options" and raw_values:
            entry["notes"].extend(_analyze_x_frame_options(raw_values, csp_directives))

        elif name == "X-Content-Type-Options" and raw_values:
            flat = [part.strip().lower()
                    for v in raw_values for part in v.split(",") if part.strip()]
            tokens = sorted(set(flat))
            if tokens == ["nosniff"]:
                if len(flat) > 1:
                    entry["notes"].append("X-Content-Type-Options sent more than once with the same value")
            else:
                entry["notes"].append(
                    f"unexpected value {value!r} (expected 'nosniff')")

        elif name == "Referrer-Policy" and raw_values:
            entry["notes"].extend(_analyze_referrer_policy(raw_values))

        elif name == "Permissions-Policy" and raw_values:
            entry["notes"].extend(_analyze_permissions_policy(raw_values))

        if value is None:
            entry["notes"].append("header not present")

        entry["notes"] = _bound_notes(entry["notes"])
        result[name] = entry

    # The returned mapping stays homogeneous — exactly the six header names,
    # each mapped to an entry dict — because that is what downstream code
    # iterates (risk_engine._missing_security_headers). Whether repeated
    # headers could be distinguished at all is recorded per entry
    # (`duplicate_detection`) and, for the run as a whole, in
    # run_http_analysis's provenance block.
    availability = "available" if header_lists_available else "unavailable"
    for entry in result.values():
        entry["duplicate_detection"] = availability
    if csp_report_only_values and "Content-Security-Policy" in result:
        result["Content-Security-Policy"]["report_only_headers_seen"] = len(csp_report_only_values)
    return result


# ---------------------------------------------------------------------------
# 2. Cookie flags
# ---------------------------------------------------------------------------

_SAMESITE_VALID = ("strict", "lax", "none")
_BOOLEAN_COOKIE_ATTRS = ("httponly", "secure", "partitioned")


def _parse_set_cookie(raw: str) -> Dict[str, Any]:
    """
    Split one Set-Cookie header into its name/value pair and attributes,
    preserving repeated attributes instead of letting the last one win
    silently (context.md §8 conflict preservation).
    """
    parts = [p.strip() for p in (raw or "").split(";")]
    name_value = parts[0] if parts else ""
    malformed = "=" not in name_value or not name_value.split("=", 1)[0].strip()
    name = name_value.split("=", 1)[0].strip() if "=" in name_value else name_value.strip()

    # Every attribute is parsed, not just the first few: capping at 32
    # attributes meant a Set-Cookie padded with junk attributes hid its real
    # `Secure`/`HttpOnly` flags and produced three false "missing flag" issues,
    # each of which risk_engine.py scores as a MEDIUM finding. The cap is on
    # how many are *retained*, and it is generous relative to any real cookie.
    attrs: List[Tuple[str, Optional[str]]] = []
    truncated = len(parts) - 1 > MAX_COOKIE_PARTS
    for part in parts[1:][:MAX_COOKIE_PARTS]:
        if not part:
            continue
        key, sep, val = part.partition("=")
        attrs.append((key.strip().lower(), val.strip() if sep else None))
    return {"name": name, "malformed": malformed, "attrs": attrs, "attrs_truncated": truncated}


def analyze_cookie_flags(
    set_cookie_headers: List[str],
    url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Parse HttpOnly/Secure/SameSite flags — plus Domain/Path/lifetime/prefix
    structure — from each Set-Cookie header.

    `issues` is the list risk_engine.py turns into a MEDIUM
    `insecure_cookie_flags` signal, so it stays reserved for attributes whose
    absence or misuse has a definite security meaning. Deliberately NOT an
    issue: `Path=/` and a parent `Domain=`. Both are ordinary, near-universal
    configurations whose risk depends entirely on what else lives under that
    path/domain — knowledge this module does not have. They are recorded as
    structured observations (`path`, `domain`, `host_only`) so a module that
    does have that context can use them, and they are described in `notes`.
    """
    request_host = _hostname_of(url) if url else ""
    request_scheme = (urllib.parse.urlsplit(url).scheme.lower() if url else "")

    parsed_cookies: List[Dict[str, Any]] = []
    truncated = False
    headers = list(set_cookie_headers or [])
    if len(headers) > MAX_COOKIES:
        headers = headers[:MAX_COOKIES]
        truncated = True

    seen_names: Dict[str, int] = {}
    for raw in headers:
        if not isinstance(raw, str):
            continue
        parsed = _parse_set_cookie(raw)
        name = parsed["name"]
        attrs = parsed["attrs"]

        seen_keys: Dict[str, List[Optional[str]]] = {}
        for key, val in attrs:
            seen_keys.setdefault(key, []).append(val)

        http_only = "httponly" in seen_keys
        secure = "secure" in seen_keys
        partitioned = "partitioned" in seen_keys

        samesite_values = [v for v in seen_keys.get("samesite", []) if v]
        samesite = samesite_values[-1] if samesite_values else None
        samesite_bare = "samesite" in seen_keys and not samesite_values

        domain_values = [v for v in seen_keys.get("domain", []) if v]
        domain = domain_values[-1] if domain_values else None
        path_values = [v for v in seen_keys.get("path", []) if v]
        path = path_values[-1] if path_values else None
        max_age_raw = (seen_keys.get("max-age") or [None])[-1]
        expires = (seen_keys.get("expires") or [None])[-1]

        max_age: Optional[int] = None
        max_age_malformed = False
        if max_age_raw is not None:
            candidate = max_age_raw.strip()
            neg = candidate.startswith("-")
            digits = candidate[1:] if neg else candidate
            if digits.isdigit() and len(digits) <= 18:
                max_age = -int(digits) if neg else int(digits)
            else:
                max_age_malformed = True

        issues: List[str] = []
        notes: List[str] = []

        # --- contract-preserving issues (unchanged strings) ----------------
        # Suppressed entirely when the attribute list was truncated: claiming
        # "missing Secure" about a cookie whose attributes were not all read is
        # a fabricated MEDIUM finding downstream. Not-read is not not-present.
        attrs_truncated = bool(parsed.get("attrs_truncated"))
        if attrs_truncated:
            notes.append("the attribute list was truncated, so flag presence could not be "
                         "determined; no missing-flag issue is claimed for this cookie")
        else:
            if not http_only:
                issues.append("missing HttpOnly flag")
            if not secure:
                issues.append("missing Secure flag")
            if samesite is None:
                issues.append("SameSite attribute not set")
            elif samesite.lower() == "none" and not secure:
                issues.append("SameSite=None without Secure flag")

        # --- added issues, each with a definite security meaning -----------
        if parsed["malformed"]:
            issues.append("malformed Set-Cookie header (no name=value pair)")
        lowered_name = name.lower()
        prefix = None
        if attrs_truncated:
            pass
        elif lowered_name.startswith("__host-"):
            prefix = "__Host-"
            violations = []
            if not secure:
                violations.append("Secure is missing")
            if domain is not None:
                violations.append("a Domain attribute is present")
            if (path or "/") != "/":
                violations.append(f"Path is {path!r} rather than '/'")
            if violations:
                issues.append("__Host- prefix requirements not met: " + ", ".join(violations)
                              + " — browsers reject this cookie entirely")
        elif lowered_name.startswith("__secure-"):
            prefix = "__Secure-"
            if not secure:
                issues.append("__Secure- prefix requires the Secure attribute — "
                              "browsers reject this cookie entirely")

        for key, vals in sorted(seen_keys.items()):
            distinct = sorted({v for v in vals if v is not None})
            if key in _BOOLEAN_COOKIE_ATTRS and len(vals) > 1:
                notes.append(f"attribute {key!r} repeated {len(vals)} times")
            elif len(distinct) > 1:
                issues.append(f"conflicting {key!r} attributes in one Set-Cookie header "
                              f"({', '.join(repr(v) for v in distinct)}); the last one wins")

        # --- observations that are NOT automatically issues ---------------
        if samesite_bare:
            notes.append("SameSite attribute present with no value; browsers treat it as SameSite=Lax")
        if samesite is not None and samesite.lower() not in _SAMESITE_VALID:
            notes.append(f"unrecognised SameSite value {samesite!r}; browsers fall back to Lax")
        if max_age_malformed:
            notes.append(f"malformed Max-Age value {_clip(max_age_raw, 60)!r}; browsers ignore it")
        if domain:
            host_only = False
            normalized_domain = domain.lstrip(".").lower()
            notes.append(f"Domain={domain!r} scopes this cookie to {normalized_domain} and every "
                         f"subdomain of it (a scope observation, not by itself a defect)")
            if request_host and not _in_scope_host(request_host, normalized_domain):
                notes.append(f"Domain {normalized_domain!r} does not cover the requested host "
                             f"{request_host!r}; browsers reject this cookie")
        else:
            host_only = True
            normalized_domain = request_host or None
        if path and path != "/":
            notes.append(f"Path={path!r} narrows this cookie to that path prefix")
        if request_scheme == "http" and not secure:
            notes.append("this cookie was observed over plaintext HTTP, so it is already exposed in "
                         "transit regardless of the Secure attribute")

        prior = seen_names.get(lowered_name)
        seen_names[lowered_name] = seen_names.get(lowered_name, 0) + 1
        if prior:
            notes.append(f"a cookie named {name!r} was set {prior + 1} times in this response")

        if parsed.get("attrs_truncated"):
            notes.append(f"more than {MAX_COOKIE_PARTS} attributes were sent on this cookie; only "
                         f"the first {MAX_COOKIE_PARTS} were parsed")
        parsed_cookies.append({
            "name": _clip(name, MAX_COOKIE_NAME_CHARS),
            "http_only": http_only,
            "secure": secure,
            "samesite": samesite,
            # additive, non-contract fields
            "prefix": prefix,
            "domain": domain,
            "host_only": host_only,
            "effective_domain": normalized_domain,
            "path": path,
            "max_age": max_age,
            "expires_present": expires is not None,
            "session_cookie": max_age is None and expires is None,
            "partitioned": partitioned,
            "malformed": parsed["malformed"],
            "notes": _bound_notes(notes),
            "issues": issues[:MAX_NOTES],
        })

    if truncated and parsed_cookies:
        parsed_cookies[-1]["notes"].append(
            f"only the first {MAX_COOKIES} Set-Cookie headers were analysed")
    return parsed_cookies


# ---------------------------------------------------------------------------
# 3. CORS (origin reflection / null origin / wildcard)
# ---------------------------------------------------------------------------

_CORS_TEST_ORIGIN = "https://reconhound-cors-test.invalid"
_CORS_PROBE_MARKER = "reconhound-cors-test"

# A fixed, tiny, deterministic probe set — NOT a fuzzer. Two of the four
# probes exist because the arbitrary-origin probe alone cannot see the two
# commonest broken allow-list implementations: `origin.startswith(target)` and
# `origin.endswith(target)`. Both extra Origins are constructed from the
# target's own host so the probe count is fixed at four regardless of input,
# and neither host is ever *requested* — it only appears in a request header.
MAX_CORS_PROBES = 4


def _cors_probe_origins(url: str) -> List[Tuple[str, str]]:
    host = _hostname_of(url)
    probes: List[Tuple[str, str]] = [
        ("arbitrary_origin", _CORS_TEST_ORIGIN),
        ("null_origin", "null"),
    ]
    # The host is interpolated into an outbound request header, so it is only
    # used when it is a plausible DNS name of plausible length. Anything else
    # (an over-long label, an IPv6 literal in brackets, a host carrying
    # separators urlsplit happened to tolerate) falls back to the two fixed
    # probes rather than shaping a header out of server-influenced text.
    if host and (len(host) > MAX_PROBE_HOST_CHARS or not _SAFE_HOST_RE.match(host)):
        host = ""
    if host:
        # Defeats `origin.startswith("https://" + target)` / substring checks.
        probes.append(("target_prefixed_origin", f"https://{host}.{_CORS_PROBE_MARKER}.invalid"))
        # Defeats `origin.endswith(target)`.
        probes.append(("target_suffixed_origin", f"https://{_CORS_PROBE_MARKER}-{host}"))
    return probes[:MAX_CORS_PROBES]


def analyze_cors(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    budget: Optional[RequestBudget] = None,
) -> Dict[str, Any]:
    """
    Send the same GET with a small fixed set of cross-origin `Origin` values
    and observe the server's Access-Control-Allow-* response — a standard,
    non-intrusive CORS-posture observation. No cross-origin request is
    actually completed by a browser; this only inspects what the server says
    it would allow.

    Exploitability is stated precisely rather than implied:

      * `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials:
        true` is a server misconfiguration that browsers REJECT — the wildcard
        is not usable with credentials — so it is NOT credentialed
        cross-origin read access. The previous implementation set the same
        flag for this as for genuine reflection, which risk_engine.py then
        described as "a wildcard origin with credentials enabled".
      * Reflection (or `null`) with credentials IS browser-usable, and is the
        only case recorded as such.
      * A wildcard without credentials exposes only what an unauthenticated
        request already returns.
    """
    result: Dict[str, Any] = {
        "origin_reflected": False, "null_origin_allowed": False, "wildcard": False,
        "allow_credentials_with_wildcard_or_reflection": False,
        # Additive, precise fields.
        "credentialed_cross_origin_read": False,
        "wildcard_with_credentials_header": False,
        "reflection_variants": [],
        "vary_origin": None,
        "conflicting_allow_origin_headers": False,
        "probes_attempted": 0, "probes_answered": 0,
        "conclusive": False,
        "exploitability": "none_observed",
        "notes": [],
        "checks": [], "error": None,
    }

    for label, origin_value in _cors_probe_origins(url):
        result["probes_attempted"] += 1
        resp = fetch_url(url, timeout=timeout, headers={"Origin": origin_value},
                         allow_redirects=False, budget=budget)
        if resp["status"] != "found":
            result["checks"].append({"label": label, "origin_sent": origin_value,
                                     "status": resp["status"], "error": resp["error"]})
            if result["error"] is None:
                result["error"] = resp["error"]
            continue

        result["probes_answered"] += 1
        # Access-Control-Allow-Origin's grammar admits exactly one origin (or
        # "*"), and an origin never contains a comma — so a comma means the
        # header was sent twice and requests merged the values. Expanding it
        # here keeps a duplicated/conflicting policy visible even when the HTTP
        # adapter cannot hand over the raw header list; previously the merged
        # "https://a, https://b" matched neither origin and the reflection went
        # unreported.
        acao_values: List[str] = []
        for raw_value in _header_values(resp, "Access-Control-Allow-Origin"):
            acao_values.extend(part.strip() for part in raw_value.split(",") if part.strip())
        acac_values = _header_values(resp, "Access-Control-Allow-Credentials")
        vary_values = _header_values(resp, "Vary")
        acao = acao_values[0].strip() if acao_values else None
        acac = acac_values[0].strip() if acac_values else None

        if len(set(acao_values)) > 1 or len(acao_values) > 1:
            result["conflicting_allow_origin_headers"] = True
            result["notes"].append(
                f"{label}: {len(acao_values)} Access-Control-Allow-Origin values were sent "
                f"({', '.join(repr(_clip(v, 120)) for v in sorted(set(acao_values)))}); the header "
                f"admits only one, so browser behaviour is undefined and the effective policy is "
                f"ambiguous")

        vary_joined = ", ".join(vary_values).lower()
        if vary_values:
            result["vary_origin"] = "origin" in [t.strip() for t in vary_joined.split(",")]

        credentials_true = bool(acac) and acac.lower() == "true"

        result["checks"].append({
            "label": label,
            "origin_sent": origin_value,
            "status": "found",
            "status_code": resp.get("status_code"),
            "access_control_allow_origin": _clip(acao, MAX_HEADER_VALUE_CHARS),
            "access_control_allow_credentials": _clip(acac, 64),
            "allow_origin_headers_seen": len(acao_values),
            "vary": _clip(", ".join(vary_values) or None, MAX_HEADER_VALUE_CHARS),
        })

        stripped_values = [v.strip("'\"") for v in acao_values]
        if origin_value != "null" and origin_value in stripped_values:
            if label == "arbitrary_origin":
                result["origin_reflected"] = True
            else:
                # A crafted origin derived from the target's own host was
                # echoed back: the allow-list check is broken even though a
                # wholly unrelated origin was refused.
                result["origin_reflected"] = True
            result["reflection_variants"].append(label)
            if credentials_true:
                result["allow_credentials_with_wildcard_or_reflection"] = True
                result["credentialed_cross_origin_read"] = True

        if label == "null_origin" and "null" in stripped_values:
            result["null_origin_allowed"] = True
            if credentials_true:
                result["allow_credentials_with_wildcard_or_reflection"] = True
                result["credentialed_cross_origin_read"] = True

        if "*" in stripped_values:
            result["wildcard"] = True
            if credentials_true:
                result["allow_credentials_with_wildcard_or_reflection"] = True
                result["wildcard_with_credentials_header"] = True

    result["reflection_variants"] = sorted(set(result["reflection_variants"]))
    result["conclusive"] = result["probes_answered"] == result["probes_attempted"] > 0

    if result["credentialed_cross_origin_read"]:
        result["exploitability"] = "credentialed_cross_origin_read"
        result["notes"].append(
            "the server echoed a cross-origin Origin (or 'null') together with "
            "Access-Control-Allow-Credentials: true — a browser would let that origin read "
            "authenticated responses. This is a configuration observation; no cross-origin read "
            "was performed.")
    elif result["origin_reflected"] or result["null_origin_allowed"]:
        result["exploitability"] = "unauthenticated_cross_origin_read"
        result["notes"].append(
            "an arbitrary cross-origin Origin was echoed without credentials, so a browser could "
            "read only what an unauthenticated request already returns")
    elif result["wildcard"]:
        result["exploitability"] = "unauthenticated_cross_origin_read"
        result["notes"].append(
            "Access-Control-Allow-Origin: * exposes only what an unauthenticated request already "
            "returns")

    if result["wildcard_with_credentials_header"]:
        result["notes"].append(
            "Access-Control-Allow-Credentials: true was sent alongside the '*' wildcard. Browsers "
            "REJECT that combination, so it is a server misconfiguration rather than credentialed "
            "cross-origin access.")
    if (result["origin_reflected"] or result["null_origin_allowed"]) and result["vary_origin"] is False:
        result["notes"].append(
            "the reflected Access-Control-Allow-Origin is not accompanied by 'Vary: Origin', so a "
            "shared cache may serve one origin's allow-list decision to another (observation only; "
            "no cache-poisoning attempt was made)")
    result["notes"] = _bound_notes(result["notes"])
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

# Hosts that answer an OAuth/OIDC/SAML redirect are identity providers, not the
# target's own infrastructure. Their posture must never be attributed here.
# Split by what they actually constrain: a marker matched against the whole
# URL fires on a query parameter that merely *mentions* a provider, which
# would mislabel an ordinary target host as an identity provider.
_IDP_HOSTNAME_MARKERS = (
    "accounts.google.com", "login.microsoftonline.com", "login.live.com",
    "okta.com", "oktapreview.com", "auth0.com", "onelogin.com", "pingidentity.com",
    "duosecurity.com", "id.atlassian.com", "amazoncognito.com",
    "cognito-idp", "keycloak", "sso.", "adfs.",
)
_IDP_URL_MARKERS = ("github.com/login", "gitlab.com/oauth")


def _looks_like_identity_provider(hostname: str, url: str) -> bool:
    host = (hostname or "").lower()
    lowered = (url or "").lower()
    return (any(m in host for m in _IDP_HOSTNAME_MARKERS)
            or any(m in lowered for m in _IDP_URL_MARKERS))
_OAUTH_REDIRECT_MARKERS = ("/authorize", "response_type=", "client_id=", "/saml", "/oauth", "/oidc",
                           "/adfs/ls", "openid")


def detect_auth_surfaces(
    url: str,
    body: Optional[str],
    headers: Dict[str, str],
    status_code: Optional[int] = None,
    content_type: Optional[str] = None,
    body_truncated: bool = False,
    target: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Look for auth-surface indicators in the page already fetched for `url` —
    content/header keyword signals, not a path enumeration (that is
    endpoint_discovery.py's job).

    Three things the previous version got wrong are handled explicitly:

      * A non-textual body (an image, a font, a binary blob) is no longer
        keyword-scanned; "login" bytes inside a PNG produced an auth-surface
        finding on /logo.png.
      * A truncated body and a 4xx/5xx error page are recorded, because
        indicators drawn from a generic error page or a corporate template are
        much weaker evidence than the same words on a 200 application page.
      * A redirect to an external identity provider is recorded as a
        *third-party* observation, never as the target's own auth surface.
    """
    status_code = _as_status_code(status_code)
    content_type = content_type if content_type is not None else _ci_get(headers, "Content-Type")
    analyzable = _looks_textual(content_type, body)

    indicators: Dict[str, List[str]] = {}
    if analyzable and body:
        body_lower = body.lower()
        for category, patterns in _AUTH_INDICATOR_PATTERNS.items():
            matched = [p for p in patterns if re.search(p, body_lower)]
            if matched:
                indicators[category] = matched[:MAX_AUTH_MATCH_SNIPPETS]

    www_auth = _ci_get(headers, "WWW-Authenticate")
    auth_schemes: List[str] = []
    if www_auth:
        indicators.setdefault("http_auth_challenge", []).append(_clip(www_auth, 256))
        auth_schemes = sorted({c.strip().split(" ")[0].lower()
                               for c in www_auth.split(",") if c.strip()})

    location = _ci_get(headers, "Location") or ""
    redirect_host = _hostname_of(urllib.parse.urljoin(url, location)) if location else ""
    idp: Optional[Dict[str, Any]] = None
    if redirect_host:
        location_lower = urllib.parse.urljoin(url, location).lower()
        looks_like_auth_redirect = any(m in location_lower for m in _OAUTH_REDIRECT_MARKERS)
        off_target = bool(target) and not _in_scope_host(redirect_host, target)
        if not target:
            off_target = redirect_host != _hostname_of(url)
        known_idp = _looks_like_identity_provider(redirect_host, location_lower)
        if looks_like_auth_redirect or (off_target and known_idp):
            idp = {
                "redirect_host": redirect_host,
                "third_party": bool(off_target),
                "known_provider": known_idp,
                "attribution": "third_party_identity_provider" if off_target else "target_hosted",
                "note": ("this redirect leaves the target's own hosts; any headers, cookies or "
                         "security posture at the destination belong to that identity provider, "
                         "not to the target" if off_target else
                         "the authentication redirect stays on the target's own hosts"),
            }
            if looks_like_auth_redirect:
                indicators.setdefault("auth_redirect", []).append(
                    _clip(urllib.parse.urljoin(url, location), 256))

    evidence_quality = "normal"
    caveats: List[str] = []
    if not analyzable:
        evidence_quality = "not_analyzable"
        caveats.append(f"response body is not textual (Content-Type {content_type!r}); "
                       f"no content keyword analysis was performed")
    if body_truncated:
        evidence_quality = "partial"
        caveats.append("the response body was truncated at the read cap, so content analysis is "
                       "incomplete and a nil result is not conclusive")
    if status_code is not None and status_code >= 400:
        evidence_quality = "weak" if evidence_quality == "normal" else evidence_quality
        caveats.append(f"indicators were read from a {status_code} response; generic error pages and "
                       f"catch-all corporate templates frequently mention login/SSO without hosting "
                       f"an authentication surface")
    if status_code is not None and status_code in _REDIRECT_STATUS_CODES_TUPLE:
        caveats.append(f"the analysed response is a {status_code} redirect, not the application page")

    return {
        "url": url,
        "indicators": indicators,
        "auth_schemes": auth_schemes,
        "identity_provider": idp,
        "status_code": status_code,
        "content_type": _clip(content_type, 256),
        "body_analyzable": analyzable,
        "body_truncated": bool(body_truncated),
        "evidence_quality": evidence_quality,
        "caveats": _bound_notes(caveats),
        # A nil result only means something when the body was actually readable.
        "conclusive": analyzable and not body_truncated,
    }


# ---------------------------------------------------------------------------
# 5. JWT detection + algorithm inspection (no exploitation)
# ---------------------------------------------------------------------------

# The previous pattern (`eyJ[A-Za-z0-9_-]{5,}\.…`) had no left boundary and no
# segment cap, so every one of the ~21,800 "eyJ" positions in a 64 KB body of
# "eyJ" repeats started a scan to the end of the string: quadratic, and
# measured at 2.0 s of CPU for a single 64 KB response. Requiring that the
# token not begin in the middle of another base64url run is both faster
# (0.001 s on the same input, ~2000x) and more correct — a JWT that starts
# mid-token is not a JWT. Segment lengths are capped so a single enormous run
# cannot dominate either.
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,%d}\.[A-Za-z0-9_-]{5,%d}\.[A-Za-z0-9_-]{5,%d}"
    % (MAX_JWT_SEGMENT_CHARS, MAX_JWT_SEGMENT_CHARS, MAX_JWT_SEGMENT_CHARS)
)


def _b64url_decode(segment: str) -> Optional[bytes]:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        return None


def _decode_jwt(token: str) -> Dict[str, Any]:
    """
    Decode (not verify) the header/payload of a JWT-shaped string.

    JWTs are base64url-encoded, not encrypted, so this requires no key and is
    not a cryptographic attack. Only the declared algorithm, structural header
    facts and claim *names* are kept. Claim values, `kid` values and the
    signature are never retained: pending_assets.json is shared with every
    module and rendered in the report appendix, and a `kid` value is an
    attacker-interesting server-side path or key identifier.
    """
    entry: Dict[str, Any] = {
        # Preview covers only the header segment, which by construction encodes
        # {"alg":...,"typ":...} and carries no session material. The signature
        # tail the previous preview included is dropped.
        "token_preview": (token[:12] + "...") if len(token) > 12 else "***",
        "alg": None, "header_typ": None, "header_kid_present": False,
        "header_jku_present": False, "header_x5u_present": False,
        "header_crit": None, "payload_claim_names": [], "segment_lengths": None,
        "location": None, "error": None,
    }
    parts = token.split(".")
    entry["segment_lengths"] = [len(p) for p in parts]
    if len(parts) != 3:
        entry["error"] = "not a 3-segment JWT"
        return entry

    header_bytes = _b64url_decode(parts[0])
    if header_bytes is None:
        entry["error"] = "unable to base64url-decode header segment"
        return entry
    try:
        header_json = json.loads(header_bytes.decode("utf-8", errors="replace"))
    except Exception:
        entry["error"] = "header segment is not valid JSON"
        return entry
    if isinstance(header_json, dict):
        alg = header_json.get("alg")
        entry["alg"] = alg if isinstance(alg, str) else (None if alg is None else str(alg))
        typ = header_json.get("typ")
        entry["header_typ"] = typ if isinstance(typ, str) else (None if typ is None else str(typ))
        entry["header_kid_present"] = "kid" in header_json
        entry["header_jku_present"] = "jku" in header_json
        entry["header_x5u_present"] = "x5u" in header_json
        crit = header_json.get("crit")
        if isinstance(crit, list):
            entry["header_crit"] = [str(c) for c in crit][:16]

    payload_bytes = _b64url_decode(parts[1])
    if payload_bytes is not None:
        try:
            payload_json = json.loads(payload_bytes.decode("utf-8", errors="replace"))
        except Exception:
            payload_json = None
        if isinstance(payload_json, dict):
            claim_names = sorted(str(k) for k in payload_json.keys())
            entry["payload_claim_names"] = [_clip(c, 128) for c in claim_names[:64]]
            entry["claim_names_truncated"] = len(claim_names) > 64
            # Registered-claim *state* is intelligence; the values are not
            # persisted. Expiry is derived, never echoed.
            now = int(datetime.now(timezone.utc).timestamp())
            for claim, flag in (("exp", "expired"), ("nbf", "not_yet_valid")):
                raw = payload_json.get(claim)
                if isinstance(raw, (int, float)) and not isinstance(raw, bool):
                    entry[flag] = (now > raw) if claim == "exp" else (now < raw)
            entry["has_expiry_claim"] = "exp" in payload_json
            entry["has_issuer_claim"] = "iss" in payload_json
            entry["has_audience_claim"] = "aud" in payload_json
    return entry


_WEAK_JWT_ALGS = frozenset({"none"})


def detect_jwts(
    body: Optional[str],
    headers: Dict[str, str],
    set_cookie_headers: Optional[List[str]] = None,
    content_type: Optional[str] = None,
    body_truncated: bool = False,
) -> Dict[str, Any]:
    """
    Scan the response body/headers/cookies for JWT-shaped tokens and decode
    their (unsigned) header/payload.

    Detection is passive and identification-only. No signature verification,
    no forgery, no algorithm-confusion or `kid`-traversal testing: a
    JWT-shaped value with a suspicious `alg` is an item for manual review, not
    a demonstrated vulnerability.
    """
    content_type = content_type if content_type is not None else _ci_get(headers, "Content-Type")
    body_analyzable = _looks_textual(content_type, body)

    haystacks: List[Tuple[str, str]] = []
    if body and body_analyzable:
        haystacks.append(("response_body", body))
    for key, val in (headers or {}).items():
        if isinstance(val, str):
            haystacks.append((f"header:{str(key).lower()}", val))
    for raw in (set_cookie_headers or []):
        if isinstance(raw, str):
            name = _parse_set_cookie(raw)["name"]
            haystacks.append((f"set-cookie:{_clip(name, MAX_COOKIE_NAME_CHARS)}", raw))

    locations: Dict[str, List[str]] = {}
    for where, text in haystacks:
        for token in _JWT_RE.findall(text):
            locations.setdefault(token, [])
            if where not in locations[token]:
                locations[token].append(where)
            if len(locations) >= MAX_JWT_TOKENS * 4:
                break

    ordered = sorted(locations)
    truncated = len(ordered) > MAX_JWT_TOKENS
    ordered = ordered[:MAX_JWT_TOKENS]

    decoded = []
    for token in ordered:
        entry = _decode_jwt(token)
        entry["location"] = sorted(locations[token])
        decoded.append(entry)

    weak_alg_detected = any((d.get("alg") or "").strip().lower() in _WEAK_JWT_ALGS for d in decoded)
    missing_alg = [d["token_preview"] for d in decoded if not d.get("alg") and not d.get("error")]

    notes: List[str] = []
    if weak_alg_detected:
        notes.append("at least one token declares alg 'none'; this is an observation of the token's "
                     "own header, not proof that the server accepts an unsigned token")
    if missing_alg:
        notes.append("at least one token's header carries no 'alg' member")
    if truncated:
        notes.append(f"more than {MAX_JWT_TOKENS} JWT-shaped values were present; only the first "
                     f"{MAX_JWT_TOKENS} (sorted) were decoded")
    if body and not body_analyzable:
        notes.append(f"the response body was not scanned because its Content-Type "
                     f"({content_type!r}) is not textual")
    if body_truncated:
        notes.append("the response body was truncated at the read cap, so a nil result is not "
                     "conclusive")

    return {
        "count": len(decoded),
        "tokens": decoded,
        "weak_alg_detected": weak_alg_detected,
        "tokens_truncated": truncated,
        "body_analyzable": body_analyzable,
        "notes": _bound_notes(notes),
        "conclusive": (body_analyzable or not body) and not body_truncated,
    }


# ---------------------------------------------------------------------------
# 6. Cache intelligence
# ---------------------------------------------------------------------------

_CACHE_HEADERS = ["Cache-Control", "Pragma", "Expires", "ETag", "Age", "Vary"]

# Fields of the cache analysis that describe *this request* rather than the
# endpoint's cache posture. They are kept as observation metadata but never
# put in a finding's `value`: surface_mapper.py derives a finding asset's
# identity from a hash of that value, so a per-request trace id or a
# seconds-resolution counter there splits the asset on every re-scan.
_VOLATILE_CACHE_KEYS = frozenset({"Age", "age_seconds", "Expires", "ETag", "cache_status"})
# `served_from_cache` flips with every HIT/MISS and `cdn_indicators` carries
# the raw header values (cf-ray is unique per request); the stable part of an
# indicator is which header was present and whose it is.
_VOLATILE_PROVENANCE_KEYS = frozenset({"served_from_cache", "note"})


def _split_volatile_cache(cache: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Split one cache analysis into (identity-stable, per-request) halves.

    Nothing is discarded — the caller persists the first half as the
    finding's `value` and the second as its `metadata`, so every observed
    value is still recorded, queryable and reported.
    """
    stable = {k: v for k, v in cache.items() if k not in _VOLATILE_CACHE_KEYS}
    volatile = {f"cache_{k}": cache[k] for k in _VOLATILE_CACHE_KEYS if k in cache}
    indicators = cache.get("cdn_indicators")
    if isinstance(indicators, list):
        stable["cdn_indicators"] = [
            {"header": i.get("header"), "vendor": i.get("vendor")}
            for i in indicators if isinstance(i, dict)
        ]
        volatile["cdn_indicator_values"] = [
            {"header": i.get("header"), "value": i.get("value")}
            for i in indicators if isinstance(i, dict)
        ]
    if "served_from_cache" in cache:
        stable.pop("served_from_cache", None)
        volatile["cache_served_from_cache"] = cache["served_from_cache"]
    return stable, volatile

# Header -> (vendor, kind). Presence is an indicator of an intermediary, which
# is exactly the provenance question: were the headers we just analysed
# produced by the origin, or replayed from an edge cache?
_CDN_HEADER_INDICATORS: Dict[str, str] = {
    "cf-ray": "cloudflare", "cf-cache-status": "cloudflare", "cf-apo-via": "cloudflare",
    "x-amz-cf-id": "cloudfront", "x-amz-cf-pop": "cloudfront",
    "x-akamai-transformed": "akamai", "akamai-grn": "akamai", "x-akamai-request-id": "akamai",
    "x-fastly-request-id": "fastly",
    "x-varnish": "varnish",
    "x-azure-ref": "azure_front_door", "x-msedge-ref": "azure_front_door",
    "x-served-by": "cache_intermediary", "x-cache": "cache_intermediary",
    "x-cache-hits": "cache_intermediary", "x-timer": "fastly",
    "x-sucuri-id": "sucuri", "x-iinfo": "imperva_incapsula",
}
_CACHE_HIT_TOKENS = ("hit", "hit-front", "hit_from")
_CACHE_MISS_TOKENS = ("miss", "expired", "bypass", "dynamic", "revalidated")


def _parse_cache_control(value: str) -> Dict[str, Any]:
    directives: Dict[str, Optional[str]] = {}
    malformed: List[str] = []
    for segment in (value or "").split(","):
        segment = segment.strip()
        if not segment:
            continue
        name, sep, raw = segment.partition("=")
        name = name.strip().lower()
        if not name:
            malformed.append(_clip(segment, 80))
            continue
        raw = raw.strip().strip('"') if sep else None
        if name in ("max-age", "s-maxage", "stale-while-revalidate", "stale-if-error"):
            if raw is None or not raw.isdigit() or len(raw) > 18:
                malformed.append(_clip(segment, 80))
                continue
        directives[name] = raw
    return {"directives": directives, "malformed": malformed}


def analyze_cache_headers(
    headers: Dict[str, str],
    header_lists: Optional[Dict[str, List[str]]] = None,
) -> Dict[str, Any]:
    """
    Cache/CDN intelligence for one response.

    Beyond the raw cache headers this now answers the provenance question the
    previous implementation left open: was this response served by an
    intermediary cache? If it was, the security headers, cookies and body
    analysed alongside it are a *cached copy*, and are not proof of what the
    origin is currently doing. Nothing here attempts, or claims to have
    attempted, cache poisoning.
    """
    result: Dict[str, Any] = {name: _clip(_ci_get(headers, name), MAX_HEADER_VALUE_CHARS)
                              for name in _CACHE_HEADERS}
    cache_control_raw = _ci_get(headers, "Cache-Control") or ""
    parsed_cc = _parse_cache_control(cache_control_raw)
    directives = parsed_cc["directives"]

    notes: List[str] = []
    if not result.get("Cache-Control") and not result.get("Pragma"):
        notes.append("no Cache-Control/Pragma headers present")
    elif result.get("Cache-Control") and "no-store" not in directives and "private" not in directives:
        notes.append("response may be cacheable by shared caches (no 'no-store'/'private' directive)")
    for bad in parsed_cc["malformed"]:
        notes.append(f"malformed Cache-Control directive {bad!r}")
    if "no-cache" in directives and "no-store" not in directives:
        notes.append("'no-cache' permits storage and requires revalidation; it is not 'no-store'")

    # --- intermediary / CDN provenance ------------------------------------
    lower_headers = {str(k).lower(): str(v if v is not None else "")
                     for k, v in (headers or {}).items()}
    cdn_indicators: List[Dict[str, str]] = []
    vendors: List[str] = []
    for header_name, vendor in _CDN_HEADER_INDICATORS.items():
        if header_name in lower_headers:
            cdn_indicators.append({
                "header": header_name,
                "value": _clip(lower_headers[header_name], 256),
                "vendor": vendor,
            })
            if vendor not in vendors:
                vendors.append(vendor)
    server = (lower_headers.get("server") or "").lower()
    for marker, vendor in (("cloudflare", "cloudflare"), ("akamaighost", "akamai"),
                           ("cloudfront", "cloudfront"), ("varnish", "varnish")):
        if marker in server and vendor not in vendors:
            vendors.append(vendor)
            cdn_indicators.append({"header": "server", "value": _clip(server, 256), "vendor": vendor})

    age_raw = (result.get("Age") or "").strip()
    age_seconds: Optional[int] = None
    if age_raw.isdigit() and len(age_raw) <= 18:
        age_seconds = int(age_raw)
    elif age_raw:
        notes.append(f"malformed Age header {_clip(age_raw, 60)!r}")

    status_texts = " ".join(
        lower_headers.get(h, "") for h in ("cf-cache-status", "x-cache", "x-cache-hits", "x-drupal-cache")
    ).lower()
    served_from_cache: Optional[bool] = None
    if age_seconds is not None and age_seconds > 0:
        served_from_cache = True
    if any(t in status_texts for t in _CACHE_HIT_TOKENS):
        served_from_cache = True
    elif served_from_cache is None and any(t in status_texts for t in _CACHE_MISS_TOKENS):
        served_from_cache = False

    if served_from_cache:
        notes.append("this response was served by an intermediary cache (Age/cache-status indicate a "
                     "HIT), so the headers analysed alongside it are a cached copy and are not proof "
                     "of the origin's current behaviour")
        attribution = "edge_cache_hit"
    elif cdn_indicators:
        attribution = "intermediary_present"
        notes.append("an intermediary/CDN answered this request; observed headers may be added, "
                     "removed or rewritten at the edge and cannot be attributed to the origin alone")
    else:
        attribution = "no_intermediary_indicators"

    result.update({
        "notes": _bound_notes(notes),
        "directives": dict(sorted(directives.items())[:MAX_NOTES]),
        "age_seconds": age_seconds,
        "cache_status": _clip(lower_headers.get("cf-cache-status") or lower_headers.get("x-cache"), 128),
        "served_from_cache": served_from_cache,
        "cdn_indicators": sorted(cdn_indicators, key=lambda d: (d["vendor"], d["header"])),
        "cdn_vendors": sorted(vendors),
        "origin_attribution": attribution,
        # Absence of an indicator is not proof there is no intermediary.
        "intermediary_absence_proven": False,
    })
    return result


# ---------------------------------------------------------------------------
# 7. Host-header behavior
# ---------------------------------------------------------------------------

_HOST_HEADER_PROBE = "reconhound-hostheader-probe.invalid"


def analyze_host_header_behavior(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    baseline: Optional[Dict[str, Any]] = None,
    budget: Optional[RequestBudget] = None,
) -> Dict[str, Any]:
    """
    Compare the response to the real request against a second request with an
    arbitrary Host header, to observe whether the server trusts/reflects an
    untrusted Host value (a security-posture question).

    `baseline` lets the caller hand in the response it already fetched.
    Without it this function re-fetched the URL, which made a single-URL run
    issue six requests where five suffice.

    This is distinct from vhost_scanner.py's job of brute-forcing many *real*
    candidate vhost names against a discovered IP to find hidden applications.
    """
    if baseline is None:
        baseline = fetch_url(url, timeout=timeout, allow_redirects=False, budget=budget)
    probe = fetch_url(url, timeout=timeout, headers={"Host": _HOST_HEADER_PROBE},
                      allow_redirects=False, budget=budget)

    both_ok = baseline["status"] == "found" and probe["status"] == "found"
    result: Dict[str, Any] = {
        "url": url,
        "status": "checked" if both_ok else ("not_checked"
                                             if "not_checked" in (baseline["status"], probe["status"])
                                             else "error"),
        "baseline_status_code": baseline.get("status_code"),
        "probe_status_code": probe.get("status_code"),
        "status_code_changed": None,
        "probe_host_reflected": False,
        "reflected_in": [],
        "conclusive": both_ok,
        "notes": [],
        "error": baseline.get("error") or probe.get("error"),
    }
    if both_ok:
        result["status_code_changed"] = baseline["status_code"] != probe["status_code"]
        reflected_in: List[str] = []
        if _HOST_HEADER_PROBE in (probe.get("body") or ""):
            reflected_in.append("body")
        for header_name in ("Location", "Content-Location", "Refresh", "Link", "Set-Cookie"):
            for value in _header_values(probe, header_name):
                if _HOST_HEADER_PROBE in value:
                    reflected_in.append(f"header:{header_name.lower()}")
                    break
        result["reflected_in"] = sorted(set(reflected_in))
        result["probe_host_reflected"] = bool(reflected_in)
        if result["probe_host_reflected"]:
            result["notes"].append(
                "the server echoed an unvalidated Host header back into its response. This is an "
                "observation of how the application builds absolute URLs; no cache entry was "
                "poisoned and no password-reset or redirect flow was exercised.")
        if result["status_code_changed"]:
            result["notes"].append(
                f"the status code changed from {baseline['status_code']} to {probe['status_code']} "
                f"when the Host header was replaced; this can equally mean strict virtual-host "
                f"validation (good) or routing to a different application")
    else:
        result["notes"].append("the comparison did not complete, so nothing can be concluded about "
                              "this host's Host-header handling")
    result["notes"] = _bound_notes(result["notes"])
    return result


# ---------------------------------------------------------------------------
# 8. Redirect-chain mapping
# ---------------------------------------------------------------------------

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)
_REDIRECT_STATUS_CODES_TUPLE = _REDIRECT_STATUS_CODES

# Query parameters whose value commonly *is* the redirect destination. Their
# presence turns "the server redirected somewhere" into "the caller-supplied
# URL asked the server to redirect somewhere", which is the actual distinction
# between ordinary SSO redirection and user-controlled redirect behaviour.
_REDIRECT_PARAM_NAMES = frozenset({
    "next", "url", "target", "redirect", "redirect_uri", "redirect_url", "redirecturl",
    "return", "return_to", "returnto", "return_url", "returnurl", "continue", "dest",
    "destination", "goto", "callback", "checkout_url", "rurl", "r",
})


def map_redirect_chain(
    url: str,
    target: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_hops: int = DEFAULT_MAX_REDIRECT_HOPS,
    initial_response: Optional[Dict[str, Any]] = None,
    budget: Optional[RequestBudget] = None,
) -> Dict[str, Any]:
    """
    Follow redirects hop by hop (not via requests' built-in allow_redirects,
    so scope can be enforced between hops).

    The gate is deliberately stricter than validate_url_target's, because a
    `Location:` value is chosen by the server rather than by the operator:

      * non-http(s) schemes are refused outright (a `Location: file:///etc/passwd`
        was previously turned into a request);
      * private/loopback/link-local/reserved IP literals are refused;
      * an IP literal is followed only when it *is* the target, so an
        obfuscated form such as `0177.0.0.1` — which `ipaddress` does not
        recognise as an IP at all — cannot be followed as if it were a
        hostname;
      * when no `target` is supplied the start URL's own host becomes the
        scope, instead of "anything goes". A target-less run previously
        followed a redirect to an external identity provider and recorded the
        third party's response as part of the target's chain.

    A host we decline to follow is still *recorded* — that is the SSO/IdP
    intelligence — it is simply not requested.
    """
    start = _strip_userinfo(url)
    scope_target = target or _hostname_of(start)
    chain: List[Dict[str, Any]] = []
    current = start
    stopped_reason: Optional[str] = None
    not_followed: Optional[Dict[str, Any]] = None
    visited = {current}
    left_origin = False
    scheme_downgraded = False

    start_parsed = urllib.parse.urlsplit(start)
    start_origin = _origin_of(start)
    start_query = urllib.parse.parse_qs(start_parsed.query, keep_blank_values=True)
    redirect_param_values = {
        v for name, values in start_query.items()
        if name.lower() in _REDIRECT_PARAM_NAMES for v in values if v
    }
    user_controlled_hops: List[Dict[str, Any]] = []

    for _ in range(max(1, int(max_hops))):
        if initial_response is not None and not chain:
            resp = initial_response
        else:
            resp = fetch_url(current, timeout=timeout, allow_redirects=False, budget=budget)
        hop_entry: Dict[str, Any] = {
            "url": current,
            "origin": _origin_of(current),
            "status_code": resp.get("status_code"),
            "error": resp.get("error"),
        }
        chain.append(hop_entry)

        if resp["status"] == "not_checked":
            stopped_reason = "request_budget_exhausted"
            break
        if resp["status"] != "found":
            stopped_reason = "fetch_error"
            break
        if resp["status_code"] not in _REDIRECT_STATUS_CODES:
            stopped_reason = "terminal_response"
            break

        location_values = _header_values(resp, "Location")
        location = location_values[0] if location_values else None
        if not location:
            stopped_reason = "redirect_without_location"
            break
        if len(location_values) > 1:
            hop_entry["conflicting_location_headers"] = [_clip(v, 512) for v in location_values]
        if any(ch in location for ch in "\r\n\x00"):
            hop_entry["location_raw"] = _clip(repr(location), 512)
            stopped_reason = "malformed_location"
            break

        try:
            next_url = _strip_userinfo(urllib.parse.urljoin(current, location))
            next_parsed = urllib.parse.urlsplit(next_url)
            next_host = next_parsed.hostname or ""
            next_parsed.port
        except ValueError as exc:
            hop_entry["location_raw"] = _clip(location, 512)
            hop_entry["location_error"] = str(exc)
            stopped_reason = "malformed_location"
            break

        hop_entry["location"] = _clip(next_url, 1024)
        hop_entry["location_host"] = next_host
        hop_entry["location_scheme"] = next_parsed.scheme.lower()

        if next_url in redirect_param_values or location in redirect_param_values:
            # The destination came straight from a query parameter on the URL
            # the operator supplied. Indicator only — see the note built below.
            user_controlled_hops.append({"hop_url": current, "location": _clip(next_url, 512)})
            hop_entry["destination_from_request_parameter"] = True

        if next_parsed.scheme.lower() not in ("http", "https"):
            not_followed = {"url": _clip(next_url, 1024), "host": next_host,
                            "scheme": next_parsed.scheme.lower(), "reason": "unsupported_scheme"}
            stopped_reason = "next_hop_unsupported_scheme"
            break
        if _is_disallowed_redirect_ip(next_host):
            not_followed = {"url": _clip(next_url, 1024), "host": next_host,
                            "reason": "private_or_reserved_ip"}
            stopped_reason = "next_hop_disallowed_ip"
            break
        if not _host_allowed(next_host, scope_target):
            not_followed = {"url": _clip(next_url, 1024), "host": next_host,
                            "reason": "out_of_scope",
                            "attribution": "third_party" if next_host else "unknown",
                            "known_identity_provider":
                                _looks_like_identity_provider(next_host, next_url)}
            stopped_reason = "next_hop_out_of_scope"
            left_origin = True
            break
        if next_url in visited:
            hop_entry["loop_to"] = _clip(next_url, 1024)
            stopped_reason = "redirect_loop"
            break

        if _origin_of(next_url) != start_origin:
            left_origin = True
        if start_parsed.scheme.lower() == "https" and next_parsed.scheme.lower() == "http":
            scheme_downgraded = True

        visited.add(next_url)
        current = next_url
    else:
        stopped_reason = "max_hops_reached"

    notes: List[str] = []
    if scheme_downgraded:
        notes.append("the chain downgrades from https to http; the downgraded hop and everything "
                     "after it travels in plaintext")
    if stopped_reason == "next_hop_out_of_scope" and not_followed:
        notes.append(
            f"the chain leaves the target's hosts for {not_followed['host']!r}. It was NOT requested. "
            f"An external redirect is normal for SSO/identity-provider flows and is not, by itself, "
            f"an open redirect; any posture observed at that host would belong to the third party, "
            f"not to the target.")
    if user_controlled_hops:
        notes.append(
            "at least one redirect destination came from a query parameter on the supplied URL. That "
            "is an indicator worth manual review, not a confirmed open redirect: confirming one "
            "requires testing an attacker-chosen destination, which this module does not do.")
    if stopped_reason == "redirect_loop":
        notes.append("the chain returns to a URL it has already visited (redirect loop)")
    if stopped_reason == "max_hops_reached":
        notes.append(f"the chain was still redirecting after {max_hops} hop(s); it is incomplete")
    if stopped_reason == "request_budget_exhausted":
        notes.append("the run's request budget was spent before the chain terminated; the chain "
                     "below is incomplete and its endpoint is unknown")

    return {
        "start_url": start,
        "url": start,                # subject key surface_mapper.py resolves on
        "hops": chain,
        "final_url": current,
        "stopped_reason": stopped_reason,
        "not_followed": not_followed,
        "left_origin": left_origin,
        "scheme_downgraded": scheme_downgraded,
        "user_controlled_destination_indicators": user_controlled_hops,
        "open_redirect_confirmed": False,
        "complete": stopped_reason in ("terminal_response", "redirect_without_location"),
        "notes": _bound_notes(notes),
    }


# ---------------------------------------------------------------------------
# 9. WAF signal detection (detection only — no bypass/evasion)
# ---------------------------------------------------------------------------

# `kind` records what the product actually is. Cloudflare and Akamai are
# content-delivery networks that *may* include a WAF; treating a `cf-ray`
# header as proof of a web application firewall overstates the evidence, and
# surface_mapper.py labels the resulting technology asset "waf".
_WAF_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "cloudflare": {
        "kind": "cdn_with_optional_waf",
        "headers": {"server": ["cloudflare"], "cf-ray": None, "cf-mitigated": None},
        "cookie_names": ["__cfduid", "cf_clearance", "__cf_bm"],
        # Block-page phrases only. A page that merely mentions the vendor is
        # not a signature: "akamai" and "reference #" used to match any page
        # containing those words.
        "body": ["attention required! | cloudflare", "cloudflare ray id",
                 "sorry, you have been blocked"],
    },
    "akamai": {
        "kind": "cdn_with_optional_waf",
        "headers": {"server": ["akamaighost"], "x-akamai-transformed": None,
                    "akamai-grn": None, "x-akamai-request-id": None},
        "cookie_names": ["ak_bmsc", "bm_sz", "_abck"],
        # Not "access denied": that phrase appears on block pages from every
        # vendor and on ordinary application 403s, so it attributed generic
        # refusals to Akamai.
        "body": ["akamaighost", "akamai reference number"],
    },
    "imperva_incapsula": {
        "kind": "waf",
        "headers": {"x-iinfo": None, "x-cdn": ["incapsula"]},
        "cookie_names": ["incap_ses", "visid_incap", "nlbi_"],
        "body": ["incapsula incident id", "powered by incapsula"],
    },
    "sucuri": {
        "kind": "waf",
        "headers": {"server": ["sucuri/cloudproxy"], "x-sucuri-id": None, "x-sucuri-cache": None},
        "cookie_names": [],
        "body": ["access denied - sucuri website firewall"],
    },
    "aws_waf": {
        "kind": "waf",
        "headers": {"x-amzn-waf-action": None},
        "cookie_names": ["aws-waf-token"],
        "body": [],
    },
    "f5_big_ip_asm": {
        "kind": "waf",
        "headers": {"server": ["big-ip", "bigip"]},
        "cookie_names": ["bigipserver", "ts01", "f5avraaaaaaaaaaaaaaaa"],
        "body": ["the requested url was rejected"],
    },
    "modsecurity": {
        "kind": "waf",
        "headers": {"server": ["mod_security", "modsecurity"]},
        "cookie_names": [],
        "body": ["this error was generated by mod_security"],
    },
    "cloudfront": {
        "kind": "cdn",
        "headers": {"x-amz-cf-id": None, "via": ["cloudfront"]},
        "cookie_names": [],
        "body": ["generated by cloudfront"],
    },
}

# Status codes a WAF commonly returns — and so do ordinary applications
# enforcing authorization or rate limits. Recorded as inconclusive context,
# never as a detection.
_WAF_BEHAVIORAL_STATUS = {403: "forbidden", 406: "not_acceptable", 429: "too_many_requests",
                          501: "not_implemented", 503: "service_unavailable"}

_EVIDENCE_STRENGTH_RANK = {"body": 0, "cookie_name": 1, "header": 2}


def detect_waf(
    headers: Dict[str, str],
    set_cookie_headers: Optional[List[str]] = None,
    body: Optional[str] = None,
    status_code: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Passive WAF/CDN signature matching against headers, Set-Cookie *names* and
    block-page markers of an already-fetched response.

    Detection only: no attack-shaped payload is crafted or sent to provoke a
    WAF, and no bypass/evasion is attempted.

    Two semantics the previous implementation left implicit are now explicit:

      * `detected: False` means "no signature in this table matched this one
        response". It is not evidence that no WAF exists — a WAF that passes
        traffic through without adding a header is invisible to passive
        matching. `evidence_of_absence` is therefore always False.
      * a vendor's `kind` distinguishes a CDN from a WAF, so a `cf-ray` header
        is not silently promoted into "this site has a WAF".
    """
    lower_headers = {str(k).lower(): str(v if v is not None else "").lower()
                     for k, v in (headers or {}).items()}
    body_lower = str(body or "").lower()

    cookie_names = []
    for raw in (set_cookie_headers or []):
        if isinstance(raw, str):
            cookie_names.append(_parse_set_cookie(raw)["name"].lower())

    detections = []
    for vendor, sig in _WAF_SIGNATURES.items():
        evidence: List[str] = []
        kinds: List[str] = []
        for header_name, expected_substrings in sig["headers"].items():
            value = lower_headers.get(header_name)
            if value is None:
                continue
            if expected_substrings is None:
                evidence.append(f"header {header_name!r} present: {_clip(value, 128)!r}")
                kinds.append("header")
            else:
                for sub in expected_substrings:
                    if sub in value:
                        evidence.append(f"header {header_name!r} contains {sub!r}")
                        kinds.append("header")
        for marker in sig["cookie_names"]:
            # Match the cookie NAME, not the whole Set-Cookie string: matching
            # anywhere in the header meant a cookie whose *value* happened to
            # contain "akamai" fingerprinted Akamai.
            if any(name.startswith(marker) or name == marker.rstrip("_") for name in cookie_names):
                evidence.append(f"Set-Cookie name starts with {marker!r}")
                kinds.append("cookie_name")
        for marker in sig["body"]:
            if marker in body_lower:
                evidence.append(f"response body contains block-page marker {marker!r}")
                kinds.append("body")
        if evidence:
            strength = max(_EVIDENCE_STRENGTH_RANK[k] for k in kinds)
            detections.append({
                "vendor": vendor,
                "kind": sig["kind"],
                "evidence": [_clip(e, MAX_EVIDENCE_CHARS) for e in evidence],
                "evidence_strength": ("header" if strength == 2
                                      else "cookie_name" if strength == 1 else "body"),
                "confidence": (CONFIDENCE_HIGH if strength == 2
                               else CONFIDENCE_MEDIUM if strength == 1 else CONFIDENCE_LOW),
            })

    behavioral: Dict[str, Any] = {
        "status_code": status_code,
        "status_meaning": _WAF_BEHAVIORAL_STATUS.get(status_code or -1),
        "indicative": status_code in _WAF_BEHAVIORAL_STATUS,
        "note": None,
    }
    if behavioral["indicative"]:
        behavioral["note"] = (
            f"a {status_code} response is consistent with a WAF block AND with ordinary application "
            f"authorization or rate limiting; on its own it identifies neither")

    notes: List[str] = []
    if not detections:
        notes.append("no vendor signature in this module's table matched this response. That is "
                     "absence of evidence, not evidence that no WAF or filtering device is present.")
    if detections and all(d["kind"].startswith("cdn") for d in detections):
        notes.append("the matched product(s) are content-delivery networks that may or may not have "
                     "a WAF enabled; a CDN fingerprint is not proof of a web application firewall")

    return {
        "detected": bool(detections),
        "vendors": sorted(detections, key=lambda d: d["vendor"]),
        "behavioral": behavioral,
        "evidence_of_absence": False,
        "conclusive": False,
        "notes": _bound_notes(notes),
    }


# ---------------------------------------------------------------------------
# Module orchestration (single URL)
# ---------------------------------------------------------------------------

def _cors_notable(cors: Dict[str, Any]) -> bool:
    return bool(cors.get("origin_reflected") or cors.get("null_origin_allowed")
                or cors.get("wildcard"))


def run_http_analysis(
    url: str,
    target: Optional[str] = None,
    output_dir: str = "output",
    timeout: float = DEFAULT_TIMEOUT,
    max_redirect_hops: int = DEFAULT_MAX_REDIRECT_HOPS,
    max_requests: int = DEFAULT_MAX_REQUESTS,
) -> Dict[str, Any]:
    """
    Run all nine Module 3 checks against a single URL and persist the results
    to <output_dir>/pending_assets.json in one batched, crash-safe write.

    Returns a structured summary in addition to (not instead of) the persisted
    store. A failure in one check does not prevent the others from running,
    and a failure to persist never discards a completed analysis.
    """
    url = validate_url_target(url, target=target)
    finding_target = target or _hostname_of(url) or url
    budget = RequestBudget(max_requests)

    summary: Dict[str, Any] = {
        "url": url,
        "target": finding_target,
        "module": MODULE_NAME,
        "started_at": _now(),
        "status": "running",
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
        "provenance": {},
        "requests_made": 0,
        "request_budget": budget.limit,
        "findings_persisted": 0,
        "findings_produced": 0,
        "errors": [],
    }

    try:
        store: Optional[PendingAssetsStore] = PendingAssetsStore(output_dir=output_dir)
    except OSError as exc:
        # A run whose output directory cannot be created still produces useful
        # analysis; losing it entirely to an unhandled OSError does not.
        store = None
        summary["errors"].append({"stage": "persistence_setup", "error": str(exc)})

    baseline = fetch_url(url, timeout=timeout, allow_redirects=False, budget=budget)
    summary["fetch_status"] = baseline["status"]
    if baseline["status"] != "found":
        summary["errors"].append({"stage": "fetch", "error": baseline.get("error")})
        # Honest failure semantics: a host that did not answer is "not
        # checked", never "checked and clean". Nothing is persisted, so no
        # module downstream can read this as a negative result.
        summary["status"] = ("not_checked" if baseline["status"] == "not_checked"
                             else "unreachable")
        summary["completeness"] = "not_performed"
        summary["requests_made"] = budget.used
        summary["finished_at"] = _now()
        return summary

    headers = baseline["headers"]
    body = baseline.get("body")
    set_cookie_headers = baseline.get("set_cookie_headers", [])
    content_type = _ci_get(headers, "Content-Type")
    status_code = baseline.get("status_code")

    findings: List[Dict[str, Any]] = []

    # --- cache/CDN first: its result is the provenance every other finding
    # --- needs in order to say whether it is describing the origin at all.
    cache: Dict[str, Any] = {}
    try:
        cache = analyze_cache_headers(headers, baseline.get("header_lists"))
        summary["cache"] = cache
    except Exception as exc:
        summary["errors"].append({"stage": "cache_headers", "error": str(exc)})

    provenance = {
        "status_code": status_code,
        "content_type": _clip(content_type, 256),
        "final_url": baseline.get("final_url"),
        "body_truncated": bool(baseline.get("body_truncated")),
        "body_analyzable": _looks_textual(content_type, body),
        "analyzed_response_is_redirect": status_code in _REDIRECT_STATUS_CODES,
        "served_from_cache": cache.get("served_from_cache"),
        "cdn_vendors": cache.get("cdn_vendors", []),
        "origin_attribution": cache.get("origin_attribution", "unknown"),
        "duplicate_header_detection": ("available" if baseline.get("header_lists_available")
                                       else "unavailable"),
        # requests speaks HTTP/1.1; h2/h3-specific posture is out of scope here
        # (see the module docstring's KNOWN LIMITATIONS).
        "protocol_observed": "HTTP/1.1",
    }
    if provenance["analyzed_response_is_redirect"]:
        provenance["note"] = (
            f"the analysed response is a {status_code} redirect; its headers describe the redirector, "
            f"not the application the redirect points at")
    elif cache.get("served_from_cache"):
        provenance["note"] = (
            "the analysed response came from an intermediary cache, so these headers are a cached "
            "copy and are not proof of the origin's current configuration")
    summary["provenance"] = provenance

    if cache:
        # surface_mapper.py keys a finding asset on a hash of the whole
        # `value`, so anything in it that legitimately differs between two
        # observations of the *same* cache posture mints a new finding asset,
        # a new risk signal and a new report row on every re-scan. `Age`
        # counts up every second and a CDN trace id (`cf-ray`) is unique per
        # request, so two scans an hour apart produced two of everything for
        # one unchanged endpoint. Those values are real evidence, so they are
        # not dropped: they go in `metadata`, which the graph keeps per
        # observation and risk_engine merges latest-wins (the same split
        # vuln_intel.py makes for its KEV/EPSS annotations).
        stable_cache, volatile_cache = _split_volatile_cache(cache)
        findings.append(make_finding(
            finding_type="http_cache_headers", target=finding_target,
            value={"url": url, "cache": stable_cache,
                   "provenance": {k: v for k, v in provenance.items()
                                  if k not in _VOLATILE_PROVENANCE_KEYS}},
            evidence=[f"Inspected cache-related and CDN/intermediary headers from {url}"]
                     + [f"cache provenance: {cache.get('origin_attribution')}"],
            confidence=CONFIDENCE_HIGH,
            metadata={"url": url, **volatile_cache,
                      **{k: provenance.get(k) for k in _VOLATILE_PROVENANCE_KEYS
                         if k in provenance}},
        ))

    try:
        sec_headers = analyze_security_headers(
            headers, baseline.get("header_lists"), bool(baseline.get("header_lists_available")))
        summary["security_headers"] = sec_headers
        evidence = [f"Fetched {url} and inspected security-relevant response headers "
                    f"(HTTP {status_code})"]
        if cache.get("served_from_cache"):
            evidence.append("this response was served from an intermediary cache, so these header "
                            "values are a cached copy and are not proof of current origin behaviour")
        elif cache.get("cdn_vendors"):
            evidence.append(f"an intermediary ({', '.join(cache['cdn_vendors'])}) answered this "
                            f"request; headers may be added or rewritten at the edge")
        if provenance["duplicate_header_detection"] == "unavailable":
            evidence.append("the HTTP adapter did not expose raw header lists, so repeated/"
                            "conflicting headers could not be distinguished from joined values")
        findings.append(make_finding(
            finding_type="http_security_headers", target=finding_target,
            value={"url": url, "headers": sec_headers, "provenance": provenance},
            evidence=evidence, confidence=CONFIDENCE_HIGH, metadata={"url": url},
        ))
    except Exception as exc:
        summary["errors"].append({"stage": "security_headers", "error": str(exc)})

    try:
        cookie_flags = analyze_cookie_flags(set_cookie_headers, url=url)
        summary["cookies"] = cookie_flags
        findings.append(make_finding(
            finding_type="http_cookie_flags", target=finding_target,
            value={"url": url, "cookies": cookie_flags, "provenance": provenance},
            evidence=[f"Inspected {len(cookie_flags)} Set-Cookie header(s) from {url}. Cookie "
                      f"VALUES are deliberately not recorded."],
            confidence=CONFIDENCE_HIGH, metadata={"url": url},
        ))
    except Exception as exc:
        summary["errors"].append({"stage": "cookie_flags", "error": str(exc)})

    try:
        auth = detect_auth_surfaces(
            url, body, headers, status_code=status_code, content_type=content_type,
            body_truncated=bool(baseline.get("body_truncated")), target=target)
        summary["auth_surfaces"] = auth
        if auth["indicators"]:
            evidence = [f"Content/headers from {url} matched auth-surface indicators: "
                        f"{', '.join(sorted(auth['indicators'].keys()))}"]
            evidence.extend(auth["caveats"])
            idp = auth.get("identity_provider")
            if idp and idp.get("third_party"):
                evidence.append(f"the authentication redirect leaves the target for "
                                f"{idp['redirect_host']}, which is a third-party identity provider; "
                                f"its posture is not the target's")
            findings.append(make_finding(
                finding_type="http_auth_surface_indicators", target=finding_target,
                value={**auth, "provenance": provenance},
                evidence=evidence, confidence=CONFIDENCE_LOW, metadata={"url": url},
            ))
        elif auth["conclusive"]:
            findings.append(make_finding(
                finding_type="http_analyzer_checked_no_auth_surface_indicators",
                target=finding_target,
                value={"url": url, "status_code": status_code,
                       "content_type": _clip(content_type, 256)},
                evidence=[f"Read the full textual body of {url} (HTTP {status_code}) and matched no "
                          f"login/logout/password-reset/OAuth/SSO/MFA indicator"],
                confidence=CONFIDENCE_MEDIUM, metadata={"url": url, "conclusive": True},
            ))
    except Exception as exc:
        summary["errors"].append({"stage": "auth_surfaces", "error": str(exc)})

    try:
        jwt_result = detect_jwts(body, headers, set_cookie_headers,
                                 content_type=content_type,
                                 body_truncated=bool(baseline.get("body_truncated")))
        summary["jwt"] = jwt_result
        if jwt_result["count"]:
            evidence = [f"Found {jwt_result['count']} JWT-shaped token(s) in the response from {url}; "
                        f"only the header segment preview, claim names and derived flags are recorded"]
            evidence.extend(jwt_result["notes"])
            findings.append(make_finding(
                finding_type="http_jwt_detected", target=finding_target,
                value={**jwt_result, "url": url, "provenance": provenance},
                evidence=evidence,
                confidence=CONFIDENCE_HIGH if jwt_result["weak_alg_detected"] else CONFIDENCE_MEDIUM,
                metadata={"url": url, "weak_alg_detected": jwt_result["weak_alg_detected"]},
            ))
        elif jwt_result["conclusive"]:
            findings.append(make_finding(
                finding_type="http_analyzer_checked_no_jwt", target=finding_target,
                value={"url": url, "status_code": status_code},
                evidence=[f"Scanned the body, headers and Set-Cookie headers of {url} and found no "
                          f"JWT-shaped value"],
                confidence=CONFIDENCE_MEDIUM, metadata={"url": url, "conclusive": True},
            ))
    except Exception as exc:
        summary["errors"].append({"stage": "jwt", "error": str(exc)})

    try:
        waf = detect_waf(headers, set_cookie_headers, body, status_code=status_code)
        summary["waf"] = waf
        if waf["detected"]:
            # Confidence follows the strongest evidence actually held, instead
            # of a flat MEDIUM for everything from a vendor header to a body
            # substring.
            ranks = {CONFIDENCE_LOW: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_HIGH: 2}
            best = max(waf["vendors"], key=lambda v: ranks[v["confidence"]])
            evidence = [f"{v['vendor']} ({v['kind']}, evidence: {v['evidence_strength']}): "
                        f"{', '.join(v['evidence'])}" for v in waf["vendors"]]
            evidence.extend(waf["notes"])
            findings.append(make_finding(
                finding_type="waf_detected", target=finding_target,
                value={**waf, "url": url, "provenance": provenance},
                evidence=evidence, confidence=best["confidence"],
                metadata={"url": url, "kinds": sorted({v["kind"] for v in waf["vendors"]})},
            ))
        # No `_checked_no_waf` record is ever emitted: a WAF that adds no
        # header to a normal response is invisible to passive matching, so a
        # nil result would poison surface_mapper.py's "checked and not found"
        # memory with a conclusion this module cannot support.
    except Exception as exc:
        summary["errors"].append({"stage": "waf", "error": str(exc)})

    try:
        cors = analyze_cors(url, timeout=timeout, budget=budget)
        summary["cors"] = cors
        if _cors_notable(cors):
            evidence = [f"CORS check against {url}: reflected={cors['origin_reflected']}, "
                        f"null_allowed={cors['null_origin_allowed']}, wildcard={cors['wildcard']}"]
            evidence.extend(cors["notes"])
            findings.append(make_finding(
                finding_type="http_cors_misconfiguration", target=finding_target,
                value={**cors, "url": url, "provenance": provenance},
                evidence=evidence,
                # Certainty differs by case: an echoed arbitrary Origin is
                # unambiguously a broken allow-list; a bare '*' is an observed
                # header whose risk depends on whether the resource is meant to
                # be public, which this module cannot know.
                confidence=(CONFIDENCE_HIGH
                            if (cors["origin_reflected"] or cors["null_origin_allowed"])
                            else CONFIDENCE_MEDIUM),
                metadata={
                    "url": url,
                    "allow_credentials_with_wildcard_or_reflection":
                        cors["allow_credentials_with_wildcard_or_reflection"],
                    "credentialed_cross_origin_read": cors["credentialed_cross_origin_read"],
                    "exploitability": cors["exploitability"],
                },
            ))
        elif cors["conclusive"]:
            findings.append(make_finding(
                finding_type="http_analyzer_checked_no_cors_exposure", target=finding_target,
                value={"url": url, "probes": [c["label"] for c in cors["checks"]]},
                evidence=[f"All {cors['probes_answered']} Origin probe(s) against {url} were "
                          f"answered and none produced a permissive "
                          f"Access-Control-Allow-Origin"],
                confidence=CONFIDENCE_MEDIUM, metadata={"url": url, "conclusive": True},
            ))
    except Exception as exc:
        summary["errors"].append({"stage": "cors", "error": str(exc)})

    try:
        host_header = analyze_host_header_behavior(url, timeout=timeout, baseline=baseline,
                                                   budget=budget)
        summary["host_header"] = host_header
        if host_header["status"] == "checked":
            findings.append(make_finding(
                finding_type="http_host_header_behavior", target=finding_target,
                value={**host_header, "provenance": provenance},
                evidence=[f"Compared the baseline response for {url} with the same request carrying "
                          f"Host: {_HOST_HEADER_PROBE}"] + host_header["notes"],
                confidence=CONFIDENCE_HIGH, metadata={"url": url},
            ))
    except Exception as exc:
        summary["errors"].append({"stage": "host_header", "error": str(exc)})

    try:
        redirect_chain = map_redirect_chain(url, target=target, timeout=timeout,
                                            max_hops=max_redirect_hops,
                                            initial_response=baseline, budget=budget)
        summary["redirect_chain"] = redirect_chain
        findings.append(make_finding(
            finding_type="http_redirect_chain", target=finding_target,
            value={**redirect_chain, "provenance": provenance},
            evidence=[f"Mapped the redirect chain from {url} ({len(redirect_chain['hops'])} hop(s), "
                      f"stopped: {redirect_chain['stopped_reason']})"] + redirect_chain["notes"],
            confidence=CONFIDENCE_HIGH if redirect_chain["complete"] else CONFIDENCE_MEDIUM,
            metadata={"url": url, "complete": redirect_chain["complete"]},
        ))
    except Exception as exc:
        summary["errors"].append({"stage": "redirect_chain", "error": str(exc)})

    err = _safe_store_add_many(store, findings)
    if err:
        summary["errors"].append({"stage": "persistence", "error": err})
    elif store is not None:
        summary["findings_persisted"] = len(findings)
    # store is None (its directory could not be created) => nothing was
    # written, and findings_persisted stays 0. Reporting len(findings) there
    # would have been a false success state.
    summary["findings_produced"] = len(findings)

    summary["requests_made"] = budget.used
    if budget.remaining == 0:
        summary["errors"].append({"stage": "budget",
                                  "error": f"request budget of {budget.limit} was fully consumed; "
                                           f"some checks may be incomplete"})
    summary["completeness"] = "complete" if not summary["errors"] else "partial"
    summary["status"] = "completed_with_errors" if summary["errors"] else "completed"
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
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS,
                        help="Hard cap on HTTP requests issued by this run")
    args = parser.parse_args()

    try:
        result = run_http_analysis(
            args.url, target=args.target, output_dir=args.output_dir, timeout=args.timeout,
            max_requests=args.max_requests,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
