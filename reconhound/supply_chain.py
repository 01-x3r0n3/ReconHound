"""
reconhound/supply_chain.py — ReconHound Module 14 (supply_chain.py), per
context.md §13's build order (position 23 — after surface_mapper.py,
position 8, which is not yet implemented; this repository is already
operating under the same explicit, user-approved build-order deviation
documented in code_leak.py's/tech_fingerprint.py's/js_analyzer.py's/
wayback_intel.py's module docstrings).

Phase: Active. See context.md §10 (module 14, "Third-party supply-chain
mapping") for the authoritative responsibilities, and §8 for the
evidence/confidence data model this module implements. This file only
documents implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Third-party supply-chain mapping. External JS inventory, analytics/
  tracking, CDN resources, CSP analysis, third-party trust map,
  subdomain-to-third-party DNS relationships, categorization (payment/
  analytics/CDN/auth providers), risk assessment of third-party
  relationships. Key differentiator."

That expands into these discrete responsibilities, each implemented below:

  1. Externally-hosted JS inventory      -> extract_third_party_js_resources
  2. Analytics/tracking identification   -> classify_third_party_host
                                             (category in ANALYTICS_CATEGORIES)
  3. CDN identification                  -> classify_third_party_host
                                             (category == "cdn", catalog match
                                             or naming-convention heuristic)
  4. CSP analysis                        -> parse_csp_header
  5. Third-party trust map               -> build_trust_map
  6. Subdomain-to-third-party DNS         -> resolve_cname_chain,
                                             map_subdomain_third_party_dns
  7. Categorization (payment/analytics/
     CDN/auth + others)                  -> _THIRD_PARTY_CATALOG,
                                             classify_third_party_host
  8. Risk assessment of third-party
     relationships                       -> assess_csp_risk_implications,
                                             assess_aggregate_risk_implications
  9. Feed to surface_mapper.py            -> run_supply_chain_analysis's
                                             returned summary (trust_map,
                                             category_inventory,
                                             risk_implications — see
                                             NO-CROSS-MODULE-CALLS PRECEDENT)

Plus shared plumbing: make_finding/make_supply_chain_finding,
PendingAssetsStore, _safe_store_add, fetch_url/fetch_page (duplicated per
modular independence, same as every other implemented module),
analyze_page (bundles responsibilities #1/#4 for one already-fetched page —
independently testable), and a multi-input orchestrator
run_supply_chain_analysis (mirroring the run_js_analyzer/run_crawler/
run_http_analysis precedent — not itself a listed context.md
responsibility).

NO-CROSS-MODULE-CALLS PRECEDENT (important for responsibility #9, "feed
supply-chain intelligence into surface_mapper.py", and for this module's
own input): every already-implemented module in this repository documents
that it does not import or call into any sibling module — integration is
deferred to core/orchestrator.py (not yet built). This module follows the
same precedent from both ends:

  a. INPUT: crawler.py (already implemented) discovers page URLs during
     its own crawl but does not call this module directly (see crawler.py's
     module docstring). This module's `run_supply_chain_analysis` therefore
     accepts `pages` (page URLs to fetch and inspect for third-party
     resources/CSP) and `subdomains` (hostnames to DNS-probe for
     third-party CNAME delegation) as caller-supplied input — plain strings
     or `{"url":}`/`{"hostname":}` dicts, or crawler.py's raw persisted
     finding records, mirroring js_analyzer.py's `_normalize_js_reference`
     acceptance of the same shapes. No adaptation layer is required to wire
     crawler.py's or passive_recon.py's output into this module once an
     orchestrator exists.
  b. OUTPUT: this module never imports or calls surface_mapper.py (not yet
     built) or any other module. `run_supply_chain_analysis` returns a
     `trust_map` (asset <-> external-service graph), `category_inventory`
     (third-party services grouped by category), and `risk_implications`
     list, all JSON-safe and evidence-linked back to the individual
     findings already persisted to pending_assets.json — the same seam
     tech_fingerprint.py's `technology` output and js_analyzer.py's
     `js_data` output already establish for their own downstream consumers.
     This module does not implement or call into surface_mapper,
     active_recon, tech_fingerprint, vhost_scanner, endpoint_discovery,
     api_recon, crawler, js_analyzer, exposure_scan, http_analyzer,
     ssl_analyzer, screenshot, vuln_intel, risk_engine, report_generator,
     orchestrator, osint_engine, passive_recon, passive_intel, code_leak,
     wayback_intel, or any other module.

SECURITY BOUNDARIES (context.md §4/§16, module contract's explicit scope
instructions):

  - This module fetches only in-scope target pages (`validate_url_target`
    enforces this the same way as every other active module). A discovered
    third-party resource URL (a `<script src>` pointing off-target, a CSP
    directive source, a CNAME target) is NEVER fetched, resolved beyond a
    single DNS lookup, authenticated to, or otherwise interacted with —
    every third-party observation in this module is derived exclusively
    from content/headers/DNS answers already obtained for an in-scope
    asset. This mirrors js_analyzer.py's `extract_external_service_
    references` boundary ("OBSERVATIONS ONLY... never issues a network
    request") and code_leak.py's exploitation boundary.
  - Service-category assignment (`classify_third_party_host`) is a
    string/domain lookup against a curated catalog of publicly-known
    vendor domains, or — failing a catalog match — a naming-convention
    heuristic (`cdn.`/`static.`/`assets.` hostname prefixes). Both are
    explicitly INFERENCES, never asserted as confirmed vendor identity;
    every category finding's evidence states its basis
    (`catalog_match` vs `naming_convention_heuristic`) so a consumer can
    weigh it accordingly (context.md §8's Observation/Evidence/Inference
    distinction).
  - Risk-implication findings (`assess_csp_risk_implications`,
    `assess_aggregate_risk_implications`) describe SECURITY/TRUST
    IMPLICATIONS of an observed configuration (e.g. "no CSP header
    observed", "third-party script host in a high-trust category") — they
    are never phrased as, and never imply, a confirmed vulnerability in
    the target or in the third party. The mere presence of a third-party
    domain is never treated as evidence that the third party itself is
    compromised or vulnerable; every risk-implication finding's evidence
    explicitly says it is an inference about configuration/trust exposure,
    not a confirmed finding.
  - CSP analysis (`parse_csp_header`) reflects only the actually-observed
    `Content-Security-Policy` header value returned by the target — no
    policy is assumed, guessed, or synthesized when the header is absent
    (the analysis records `present: False` and stops there for that page).

Implementation decisions (ambiguities resolved so implementation can
proceed without inventing requirements):

  1. "Externally hosted JavaScript resources" (#1) are discovered from
     `<script src>` tags in already-fetched, in-scope page HTML — the same
     extraction technique crawler.py's `extract_javascript_references`
     already uses (BeautifulSoup `find_all("script")`), duplicated here
     per modular independence, but filtered to OUT-OF-SCOPE hosts only:
     in-scope script references are crawler.py's/js_analyzer.py's concern,
     not this module's. This module fetches each page itself (mirroring
     js_analyzer.py's `fetch_javascript_file` hop-by-hop, scope-enforced
     redirect handling) rather than depending on crawler.py's persisted
     output, consistent with every other active module's independence.
  2. The "third-party trust map" (#5) is built from two directly-observed
     relationship kinds — a page referencing an external host via
     `<script src>`, and a CSP directive explicitly allow-listing an
     external host — plus DNS CNAME delegation (#6). Broader resource
     types (images, stylesheets, iframes, fonts referenced outside CSP)
     are NOT separately fetched/parsed here: the module contract names JS
     inventory and CSP analysis specifically, and expanding resource
     collection beyond those two named, directly-observed sources would
     extend this module's scope beyond what was assigned. CSP directives
     other than script-related ones (`connect-src`, `img-src`, `style-src`,
     etc.) ARE still parsed and contribute third-party hosts to the trust
     map, since the CSP header itself is one of this module's two named
     inputs and its non-script directives are still real, observed
     evidence of a third-party trust relationship.
  3. Subdomain-to-third-party DNS relationships (#6) are limited to CNAME
     chain resolution (`resolve_cname_chain`, mirroring passive_recon.py's
     `enumerate_dns` resolver conventions, duplicated per modular
     independence). A CNAME whose final target does not resolve back into
     the target's own domain is recorded as a third-party DNS relationship
     (categorized if it matches the vendor catalog, else recorded as
     `unknown_third_party`) — this module does NOT attempt subdomain-
     takeover analysis of a dangling CNAME; that correlation is
     surface_mapper.py's named responsibility (context.md §6), not this
     module's, and asserting exploitability here would violate the
     module contract's explicit "do not present an inferred relationship
     ... as a confirmed vulnerability" instruction.
  4. The vendor/category catalog (`_THIRD_PARTY_CATALOG`) is a curated,
     necessarily-incomplete list of well-known third-party domains (the
     same kind of finite, best-effort catalog js_analyzer.py's
     `_EXTERNAL_SERVICE_DOMAINS` already establishes as this codebase's
     precedent for vendor identification without an external lookup
     service/dependency). An unmatched external host is never silently
     dropped — it is still recorded as a directly-observed third-party
     resource/relationship with category `unknown_third_party`, so
     "categorization coverage" is a separate, visible property of the
     output rather than a filter on what gets recorded.
  5. `requests` and `dns.resolver`/`dns.exception` are reused (already
     project dependencies via passive_recon.py/js_analyzer.py) — no new
     dependency is introduced.
  6. Only GET requests are made, and only to the page URL's own scope
     (itself and its in-scope redirect targets) — this module discovers
     third-party relationships, it never exercises, authenticates to, or
     performs intrusive testing against any discovered third-party service
     (module contract's explicit instruction).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import tempfile
import threading
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import dns.exception
import dns.resolver
import requests
from bs4 import BeautifulSoup

MODULE_NAME = "supply_chain.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"
_CONF_ORDER = [CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH]

DEFAULT_USER_AGENT = "ReconHound-SupplyChain/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_BODY_BYTES = 2_000_000
DEFAULT_MAX_REDIRECT_HOPS = 5
DEFAULT_DNS_TIMEOUT = 5.0
DEFAULT_MAX_CNAME_HOPS = 8

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)


class ScopeError(ValueError):
    """Raised when a URL/target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors http_analyzer.py's/js_analyzer.py's/crawler.py's
# validate_url_target and SSRF safeguard; duplicated per modular
# independence, context.md §12.2)
# ---------------------------------------------------------------------------

def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_disallowed_redirect_ip(host: str) -> bool:
    """Private/loopback/link-local/multicast/reserved/unspecified IP-literal check (SSRF safeguard)."""
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified
    )


def _in_scope_host(hostname: str, target: str) -> bool:
    hostname = (hostname or "").strip().rstrip(".").lower()
    target = (target or "").strip().rstrip(".").lower()
    if not hostname or not target:
        return False
    return hostname == target or hostname.endswith("." + target)


def validate_url_target(url: str, target: Optional[str] = None) -> str:
    """
    Validate that `url` is a syntactically valid http(s) URL, and — if
    `target` is supplied — that its hostname is the target itself or a
    subdomain of it (an IP-literal host is allowed through without an
    in-scope check, mirroring http_analyzer.py's/js_analyzer.py's rationale).
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


def validate_hostname_target(hostname: str, target: str) -> str:
    """Validate a bare hostname (no scheme) is in scope for `target`, for DNS-only inputs."""
    if not isinstance(hostname, str) or not hostname.strip():
        raise ScopeError("Hostname must be a non-empty string.")
    candidate = hostname.strip().rstrip(".")
    if not target:
        raise ScopeError("A target domain is required to validate hostname scope.")
    if not _in_scope_host(candidate, target):
        raise ScopeError(f"Hostname {candidate!r} is not in scope for target {target!r}")
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


def make_supply_chain_finding(
    finding_type: str,
    target: str,
    value: Any,
    evidence: List[str],
    confidence: str,
    source_asset: Optional[str],
    discovery_source: str,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Wrap one discovery with this module's required provenance fields: the
    originating target/subdomain/page (`source_asset`) and the technique
    that produced the observation (`discovery_source`, one of
    "script_tag", "csp_header", "dns_cname", or "aggregate_analysis" for
    correlated, run-level output). Every finding this module persists goes
    through this helper so provenance is never lost.
    """
    metadata: Dict[str, Any] = {"source_asset": source_asset, "discovery_source": discovery_source}
    if extra_metadata:
        metadata.update(extra_metadata)
    return make_finding(finding_type, target, value, evidence, confidence, metadata)


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


def _looks_textual(content_type: Optional[str], body: Optional[str]) -> bool:
    """Best-effort textual-content check so binary responses aren't parsed as HTML."""
    if not body:
        return False
    if content_type:
        ct = content_type.lower()
        if any(t in ct for t in ("html", "javascript", "json", "xml", "text")):
            return True
        if any(
            t in ct for t in (
                "image/", "video/", "audio/", "font/", "application/octet-stream",
                "application/zip", "application/pdf", "application/gzip", "application/wasm",
            )
        ):
            return False
    return True


# ---------------------------------------------------------------------------
# Shared HTTP client (not itself a listed context.md responsibility, but
# necessary plumbing — mirrors every other module's fetch_url)
# ---------------------------------------------------------------------------

def fetch_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """Perform a single HTTP GET against `url` without auto-following redirects."""
    result: Dict[str, Any] = {
        "status": "error", "status_code": None, "headers": {}, "body": None,
        "body_truncated": False, "final_url": url, "elapsed_seconds": None, "error": None,
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


def fetch_page(
    url: str,
    target: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    max_redirect_hops: int = DEFAULT_MAX_REDIRECT_HOPS,
) -> Dict[str, Any]:
    """
    Fetch one in-scope page, following redirects hop-by-hop (never via
    `requests`' `allow_redirects=True`) so scope — including the SSRF
    safeguard against private/loopback/reserved IP redirect targets — is
    enforced at every hop, not just the initial request (mirrors
    js_analyzer.py's `fetch_javascript_file` technique).
    """
    current = url
    hops: List[Dict[str, Any]] = []
    for _ in range(max_redirect_hops):
        resp = fetch_url(current, timeout=timeout, max_body_bytes=max_body_bytes)
        hop_entry: Dict[str, Any] = {"url": current, "status_code": resp.get("status_code"), "error": resp.get("error")}
        hops.append(hop_entry)

        if resp["status"] != "found":
            return {"status": "error", "error": resp.get("error"), "hops": hops, "final_url": current}
        if resp["status_code"] not in _REDIRECT_STATUS_CODES:
            result = dict(resp)
            result["hops"] = hops
            result["final_url"] = resp.get("final_url", current)
            return result

        location = _ci_get(resp["headers"], "Location")
        if not location:
            return {"status": "error", "error": "redirect response without Location header", "hops": hops, "final_url": current}

        next_url = urllib.parse.urljoin(current, location)
        next_host = urllib.parse.urlsplit(next_url).hostname or ""
        if _is_disallowed_redirect_ip(next_host):
            return {
                "status": "error",
                "error": f"redirect target {next_host!r} is a private/loopback/reserved IP (SSRF safeguard)",
                "hops": hops, "final_url": current,
            }
        if target and not _is_ip_literal(next_host) and not _in_scope_host(next_host, target):
            return {
                "status": "error",
                "error": f"redirect target host {next_host!r} is out of scope for target {target!r}",
                "hops": hops, "final_url": current,
            }
        hop_entry["location"] = next_url
        current = next_url

    return {"status": "error", "error": f"exceeded max_redirect_hops ({max_redirect_hops})", "hops": hops, "final_url": current}


# ---------------------------------------------------------------------------
# 7. Third-party vendor/category catalog (responsibility #2/#3/#7)
# ---------------------------------------------------------------------------

ANALYTICS_CATEGORIES = frozenset({"analytics", "advertising", "tag_management"})

# A curated, necessarily-incomplete catalog of well-known third-party
# domains (see module docstring, decision #4). domain -> (vendor_name, category)
_THIRD_PARTY_CATALOG: Dict[str, Tuple[str, str]] = {
    # analytics / tag management / advertising
    "google-analytics.com": ("Google Analytics", "analytics"),
    "analytics.google.com": ("Google Analytics", "analytics"),
    "googletagmanager.com": ("Google Tag Manager", "tag_management"),
    "doubleclick.net": ("Google DoubleClick", "advertising"),
    "connect.facebook.net": ("Facebook Pixel/SDK", "analytics"),
    "facebook.net": ("Facebook Pixel/SDK", "analytics"),
    "segment.io": ("Segment", "analytics"),
    "segment.com": ("Segment", "analytics"),
    "mixpanel.com": ("Mixpanel", "analytics"),
    "hotjar.com": ("Hotjar", "analytics"),
    "cloudflareinsights.com": ("Cloudflare Insights", "analytics"),
    # error tracking
    "sentry.io": ("Sentry", "error_tracking"),
    "ingest.sentry.io": ("Sentry", "error_tracking"),
    # payment
    "stripe.com": ("Stripe", "payment"),
    "js.stripe.com": ("Stripe", "payment"),
    "paypal.com": ("PayPal", "payment"),
    "paypalobjects.com": ("PayPal", "payment"),
    "braintreegateway.com": ("Braintree (PayPal)", "payment"),
    "squareup.com": ("Square", "payment"),
    "square.com": ("Square", "payment"),
    "checkout.com": ("Checkout.com", "payment"),
    # authentication providers
    "auth0.com": ("Auth0", "auth"),
    "okta.com": ("Okta", "auth"),
    "oktacdn.com": ("Okta", "auth"),
    "login.microsoftonline.com": ("Microsoft Identity Platform", "auth"),
    "accounts.google.com": ("Google Identity", "auth"),
    # CDN
    "cloudfront.net": ("AWS CloudFront", "cdn"),
    "cdn.jsdelivr.net": ("jsDelivr", "cdn"),
    "jsdelivr.net": ("jsDelivr", "cdn"),
    "unpkg.com": ("unpkg", "cdn"),
    "cdnjs.cloudflare.com": ("cdnjs (Cloudflare)", "cdn"),
    "akamaized.net": ("Akamai", "cdn"),
    "akamai.net": ("Akamai", "cdn"),
    "akamaihd.net": ("Akamai", "cdn"),
    "fastly.net": ("Fastly", "cdn"),
    "stackpathcdn.com": ("StackPath", "cdn"),
    "bootstrapcdn.com": ("BootstrapCDN (StackPath)", "cdn"),
    "cdn77.org": ("CDN77", "cdn"),
    "azureedge.net": ("Azure CDN", "cdn"),
    "gstatic.com": ("Google Static Content (gstatic)", "cdn"),
    # cloud infrastructure / backend-as-a-service
    "amazonaws.com": ("AWS", "cloud_infrastructure"),
    "s3.amazonaws.com": ("AWS S3", "cloud_infrastructure"),
    "googleapis.com": ("Google APIs", "cloud_infrastructure"),
    "firebaseio.com": ("Firebase", "backend_as_a_service"),
    "firebaseapp.com": ("Firebase", "backend_as_a_service"),
    # fonts
    "fonts.googleapis.com": ("Google Fonts", "fonts"),
    "fonts.gstatic.com": ("Google Fonts", "fonts"),
    "use.typekit.net": ("Adobe Fonts (Typekit)", "fonts"),
    # maps
    "maps.googleapis.com": ("Google Maps", "maps"),
    "maps.gstatic.com": ("Google Maps", "maps"),
    # video hosting
    "youtube.com": ("YouTube", "video_hosting"),
    "ytimg.com": ("YouTube", "video_hosting"),
    "vimeo.com": ("Vimeo", "video_hosting"),
    "player.vimeo.com": ("Vimeo", "video_hosting"),
    "wistia.com": ("Wistia", "video_hosting"),
    # support / chat
    "intercom.io": ("Intercom", "support_chat"),
    "zendesk.com": ("Zendesk", "support_chat"),
    "drift.com": ("Drift", "support_chat"),
    # marketing automation / email delivery
    "hubspot.com": ("HubSpot", "marketing_automation"),
    "hs-scripts.com": ("HubSpot", "marketing_automation"),
    "mailchimp.com": ("Mailchimp", "email_delivery"),
    "sendgrid.net": ("SendGrid", "email_delivery"),
    # social widgets
    "platform.twitter.com": ("Twitter/X widget", "social_widget"),
    "platform.linkedin.com": ("LinkedIn widget", "social_widget"),
    # e-commerce platform
    "myshopify.com": ("Shopify", "ecommerce_platform"),
}

# Hostname-prefix conventions commonly used for CDN/static-asset subdomains.
# A match here without a catalog hit is an unconfirmed HEURISTIC, not a
# vendor identification (module docstring, decision #4 / security boundary).
_CDN_NAMING_CONVENTION_RE = re.compile(r"^(cdn[0-9]*|static[0-9]*|assets?|media)[.\-]", re.IGNORECASE)


def _match_third_party_catalog(host: str) -> Optional[Tuple[str, str]]:
    host = (host or "").lower()
    for domain, info in _THIRD_PARTY_CATALOG.items():
        if host == domain or host.endswith("." + domain):
            return info
    return None


def classify_third_party_host(host: str) -> Dict[str, Any]:
    """
    Categorize an external host (responsibility #2/#3/#7). Returns
    {"host":, "vendor":, "category":, "category_source":}, where
    `category_source` is one of "catalog_match" (a known-vendor domain
    match — reasonably reliable) or "naming_convention_heuristic" (an
    unconfirmed inference from hostname naming convention) or "unmatched"
    (recorded but not categorizable from this module's catalog/heuristics).
    This is always an INFERENCE, never a confirmed vendor identity.
    """
    host_norm = (host or "").lstrip("*.").lower()
    match = _match_third_party_catalog(host_norm)
    if match:
        vendor, category = match
        return {"host": host, "vendor": vendor, "category": category, "category_source": "catalog_match"}
    if _CDN_NAMING_CONVENTION_RE.match(host_norm):
        return {"host": host, "vendor": None, "category": "cdn", "category_source": "naming_convention_heuristic"}
    return {"host": host, "vendor": None, "category": "unknown_third_party", "category_source": "unmatched"}


# ---------------------------------------------------------------------------
# 1. Externally-hosted JavaScript inventory
# ---------------------------------------------------------------------------

def extract_third_party_js_resources(body: str, page_url: str, target: str) -> List[Dict[str, Any]]:
    """
    Extract `<script src>` references from already-fetched, in-scope page
    HTML that resolve to a host OUTSIDE the target's scope (responsibility
    #1). In-scope script references are crawler.py's/js_analyzer.py's
    concern, not this module's (module docstring, decision #1).
    """
    if not body:
        return []
    try:
        soup = BeautifulSoup(body, "html.parser")
        script_tags = soup.find_all("script")
    except Exception:
        return []

    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for tag in script_tags:
        src = tag.get("src")
        if not src:
            continue
        src = src.strip()
        if not src:
            continue
        try:
            abs_url = urllib.parse.urljoin(page_url, src)
        except Exception:
            continue
        parsed = urllib.parse.urlsplit(abs_url)
        if parsed.scheme not in ("http", "https"):
            continue
        host = (parsed.hostname or "").lower()
        if not host or _in_scope_host(host, target):
            continue  # in-scope resource, not a third party
        if abs_url in seen:
            continue
        seen.add(abs_url)
        out.append({
            "url": abs_url,
            "host": host,
            "source_page": page_url,
            "classification": classify_third_party_host(host),
            "evidence": [f"<script src={src!r}> referenced on {page_url} resolves to external host {host!r}"],
        })
    return sorted(out, key=lambda r: (r["host"], r["url"]))


# ---------------------------------------------------------------------------
# 4. Content-Security-Policy analysis
# ---------------------------------------------------------------------------

_CSP_DIRECTIVES_OF_INTEREST = (
    "default-src", "script-src", "script-src-elem", "style-src", "connect-src",
    "img-src", "frame-src", "font-src", "object-src", "media-src",
    "frame-ancestors", "form-action", "base-uri", "worker-src", "manifest-src",
)
_CSP_KEYWORD_RE = re.compile(
    r"^'(self|none|unsafe-inline|unsafe-eval|unsafe-hashes|strict-dynamic|report-sample)'$",
    re.IGNORECASE,
)
_CSP_NONCE_OR_HASH_RE = re.compile(r"^'(nonce|sha256|sha384|sha512)-", re.IGNORECASE)


def _csp_token_host(token: str) -> Optional[str]:
    """Extract a bare hostname from a CSP source token, or None if not a hostname source."""
    if not token or token in ("*",):
        return None
    if _CSP_KEYWORD_RE.match(token) or _CSP_NONCE_OR_HASH_RE.match(token):
        return None
    if token.endswith(":") and "/" not in token:
        return None  # bare scheme wildcard, e.g. "https:", "data:"
    candidate = token
    if "://" in candidate:
        candidate = urllib.parse.urlsplit(candidate).hostname or ""
    else:
        candidate = candidate.split("/", 1)[0].split(":", 1)[0]
    candidate = candidate.strip().lower()
    return candidate or None


def parse_csp_directive_value(raw_value: str, target: str) -> Dict[str, Any]:
    """Parse one CSP directive's source list into keywords / scheme-wildcards / hostnames."""
    tokens = raw_value.split()
    keywords: List[str] = []
    scheme_wildcards: List[str] = []
    in_scope_hosts: List[str] = []
    third_party_hosts: List[str] = []
    for token in tokens:
        if _CSP_KEYWORD_RE.match(token) or _CSP_NONCE_OR_HASH_RE.match(token):
            keywords.append(token)
            continue
        if token == "*" or (token.endswith(":") and "/" not in token):
            scheme_wildcards.append(token)
            continue
        host = _csp_token_host(token)
        if not host:
            continue
        bare_host = host.lstrip("*.")
        if _in_scope_host(bare_host, target):
            in_scope_hosts.append(host)
        else:
            third_party_hosts.append(host)

    return {
        "raw": raw_value,
        "keywords": keywords,
        "scheme_wildcards": scheme_wildcards,
        "in_scope_hosts": sorted(set(in_scope_hosts)),
        "third_party_hosts": sorted(set(third_party_hosts)),
        "allows_unsafe_inline": "'unsafe-inline'" in keywords,
        "allows_unsafe_eval": "'unsafe-eval'" in keywords,
        "allows_broad_wildcard": "*" in scheme_wildcards or any(sw in ("https:", "http:") for sw in scheme_wildcards),
    }


def parse_csp_header(csp_value: Optional[str], target: str) -> Dict[str, Any]:
    """
    Analyze the actually-observed Content-Security-Policy header value
    (responsibility #4). Records `present: False` and stops when no header
    was returned — no policy is assumed or synthesized (module docstring,
    security boundaries).
    """
    if not csp_value or not csp_value.strip():
        return {"present": False, "raw_header": None, "directives": {}, "third_party_domains_referenced": []}

    directives: Dict[str, Any] = {}
    all_third_party: Set[str] = set()
    for clause in csp_value.split(";"):
        clause = clause.strip()
        if not clause:
            continue
        parts = clause.split(None, 1)
        name = parts[0].strip().lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if name not in _CSP_DIRECTIVES_OF_INTEREST:
            continue
        parsed = parse_csp_directive_value(value, target)
        directives[name] = parsed
        all_third_party.update(parsed["third_party_hosts"])

    return {
        "present": True,
        "raw_header": csp_value,
        "directives": directives,
        "third_party_domains_referenced": sorted(all_third_party),
    }


# ---------------------------------------------------------------------------
# 6. Subdomain-to-third-party DNS relationships
# ---------------------------------------------------------------------------

def resolve_cname_chain(
    hostname: str,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    max_hops: int = DEFAULT_MAX_CNAME_HOPS,
) -> Dict[str, Any]:
    """
    Follow the CNAME chain for `hostname` (mirrors passive_recon.py's
    `enumerate_dns` resolver conventions, duplicated per modular
    independence). Returns {"status": "found"|"none"|"error",
    "chain": [...], "error": None}. `chain` is empty when no CNAME exists
    (an A/AAAA-only host, or NXDOMAIN) — that is a normal "none" result,
    not an error.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    chain: List[str] = []
    current = hostname.rstrip(".")
    seen: Set[str] = {current}
    try:
        for _ in range(max_hops):
            try:
                answer = resolver.resolve(current, "CNAME")
            except dns.resolver.NoAnswer:
                break
            except dns.resolver.NXDOMAIN:
                return {"status": "error", "chain": chain, "error": f"NXDOMAIN resolving {current!r}"}
            target_host = str(answer[0].target).rstrip(".")
            chain.append(target_host)
            if target_host in seen:
                break  # defensive: avoid an infinite loop on a CNAME cycle
            seen.add(target_host)
            current = target_host
        return {"status": "found" if chain else "none", "chain": chain, "error": None}
    except dns.exception.Timeout as exc:
        return {"status": "error", "chain": chain, "error": f"timeout: {exc}"}
    except Exception as exc:  # never let one hostname's DNS failure kill the whole run
        return {"status": "error", "chain": chain, "error": str(exc)}


def map_subdomain_third_party_dns(subdomain: str, target: str, timeout: float = DEFAULT_DNS_TIMEOUT) -> Dict[str, Any]:
    """
    Resolve `subdomain`'s CNAME chain and determine whether it is
    DNS-delegated to a third party (responsibility #6). This module
    records the observed delegation only — it does NOT assess whether a
    dangling/unclaimed CNAME target implies a takeover risk; that
    correlation belongs to surface_mapper.py (module docstring, decision #3).
    """
    dns_result = resolve_cname_chain(subdomain, timeout=timeout)
    result: Dict[str, Any] = {
        "subdomain": subdomain, "status": dns_result["status"], "chain": dns_result["chain"],
        "error": dns_result["error"], "third_party": None,
    }
    if dns_result["status"] != "found" or not dns_result["chain"]:
        return result

    final_host = dns_result["chain"][-1]
    if not _in_scope_host(final_host, target):
        result["third_party"] = classify_third_party_host(final_host)
    return result


# ---------------------------------------------------------------------------
# 5. Third-party trust map
# ---------------------------------------------------------------------------

def build_trust_map(
    js_resources: List[Dict[str, Any]],
    csp_by_page: Dict[str, Dict[str, Any]],
    dns_relationships: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Construct the third-party trust map (responsibility #5): a graph
    relating target assets (pages/subdomains) to external services, from
    every directly-observed relationship this module collected.
    """
    assets: Dict[str, List[Dict[str, Any]]] = {}
    services: Dict[str, Dict[str, Any]] = {}

    def _touch_service(host: str, classification: Dict[str, Any]) -> Dict[str, Any]:
        entry = services.setdefault(host, {
            "host": host, "vendor": classification.get("vendor"),
            "category": classification.get("category"), "category_source": classification.get("category_source"),
            "referenced_by": [], "relationship_types": set(),
        })
        return entry

    def _link(asset: str, host: str, relationship_type: str, classification: Dict[str, Any]) -> None:
        assets.setdefault(asset, [])
        if host not in assets[asset]:
            assets[asset].append(host)
        entry = _touch_service(host, classification)
        if asset not in entry["referenced_by"]:
            entry["referenced_by"].append(asset)
        entry["relationship_types"].add(relationship_type)

    for res in js_resources:
        _link(res["source_page"], res["host"], "script_reference", res["classification"])

    for page_url, csp in csp_by_page.items():
        if not csp.get("present"):
            continue
        for directive_name, directive in csp.get("directives", {}).items():
            for host in directive.get("third_party_hosts", []):
                bare_host = host.lstrip("*.")
                _link(page_url, bare_host, f"csp_allowlist:{directive_name}", classify_third_party_host(host))

    for rel in dns_relationships:
        if not rel.get("third_party"):
            continue
        classification = rel["third_party"]
        _link(rel["subdomain"], classification["host"], "dns_cname", classification)

    for entry in services.values():
        entry["relationship_types"] = sorted(entry["relationship_types"])
        entry["referenced_by"] = sorted(entry["referenced_by"])

    return {
        "assets": {asset: sorted(hosts) for asset, hosts in assets.items()},
        "external_services": services,
        "asset_count": len(assets),
        "external_service_count": len(services),
    }


def build_category_inventory(trust_map: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Group the trust map's external services by category (responsibilities #2/#3/#7)."""
    inventory: Dict[str, List[Dict[str, Any]]] = {}
    for host, entry in trust_map.get("external_services", {}).items():
        category = entry.get("category") or "unknown_third_party"
        inventory.setdefault(category, []).append({
            "host": host, "vendor": entry.get("vendor"), "category_source": entry.get("category_source"),
            "referenced_by": entry.get("referenced_by", []),
        })
    for services in inventory.values():
        services.sort(key=lambda s: s["host"])
    return inventory


# ---------------------------------------------------------------------------
# 8. Risk assessment of third-party relationships
# ---------------------------------------------------------------------------

_HIGH_TRUST_CATEGORIES = frozenset({"payment", "auth"})


def assess_csp_risk_implications(page_url: str, csp: Dict[str, Any], observed_third_party_hosts: Set[str]) -> List[Dict[str, Any]]:
    """
    Derive security/trust IMPLICATIONS (never confirmed vulnerabilities)
    from one page's observed CSP configuration (responsibility #8).
    """
    implications: List[Dict[str, Any]] = []

    if not csp.get("present"):
        if observed_third_party_hosts:
            implications.append({
                "risk_type": "csp_absent_with_third_party_scripts",
                "description": (
                    f"No Content-Security-Policy header was observed on {page_url}, which loads "
                    f"{len(observed_third_party_hosts)} third-party script host(s). Without a CSP, "
                    "the browser applies no policy-level restriction on which origins may execute "
                    "script in this page's context."
                ),
                "related_hosts": sorted(observed_third_party_hosts),
                "confidence": CONFIDENCE_MEDIUM,
                "evidence": [
                    f"No Content-Security-Policy response header observed for {page_url}",
                    f"{len(observed_third_party_hosts)} third-party <script src> host(s) observed on the same page",
                    "This is an inferred configuration/trust-exposure implication, not a confirmed vulnerability.",
                ],
            })
        return implications

    for directive_name, directive in csp.get("directives", {}).items():
        if directive.get("allows_unsafe_inline") or directive.get("allows_unsafe_eval") or directive.get("allows_broad_wildcard"):
            notes = []
            if directive.get("allows_unsafe_inline"):
                notes.append("'unsafe-inline'")
            if directive.get("allows_unsafe_eval"):
                notes.append("'unsafe-eval'")
            if directive.get("allows_broad_wildcard"):
                notes.append("a broad scheme/host wildcard")
            implications.append({
                "risk_type": "csp_directive_weakened",
                "description": (
                    f"CSP directive '{directive_name}' on {page_url} permits {', '.join(notes)}, "
                    "which broadens the set of origins/inline content the browser will execute or "
                    "load under this directive."
                ),
                "related_hosts": directive.get("third_party_hosts", []),
                "confidence": CONFIDENCE_MEDIUM,
                "evidence": [
                    f"CSP directive observed on {page_url}: {directive_name} {directive.get('raw')!r}",
                    "This is an inferred configuration-weakening implication, not a confirmed vulnerability.",
                ],
            })

    script_directive = csp["directives"].get("script-src") or csp["directives"].get("default-src")
    if script_directive is not None:
        allowlisted = set(h.lstrip("*.") for h in script_directive.get("third_party_hosts", []))
        not_allowlisted = {h for h in observed_third_party_hosts if h not in allowlisted}
        if not_allowlisted:
            implications.append({
                "risk_type": "third_party_script_not_in_csp_allowlist",
                "description": (
                    f"{len(not_allowlisted)} third-party script host(s) observed on {page_url} do not "
                    "appear in the page's own script-src/default-src CSP allowlist. This may mean the "
                    "policy is not actually enforced as observed (e.g. report-only), the script load "
                    "happened before the policy applied, or the allowlist covers the host indirectly "
                    "(e.g. via a wildcard this analysis could not resolve)."
                ),
                "related_hosts": sorted(not_allowlisted),
                "confidence": CONFIDENCE_LOW,
                "evidence": [
                    f"Observed third-party script hosts on {page_url}: {sorted(observed_third_party_hosts)}",
                    f"CSP script-src/default-src allowlisted third-party hosts: {sorted(allowlisted)}",
                    "This is an inferred discrepancy, not a confirmed CSP bypass or vulnerability.",
                ],
            })

    return implications


def assess_aggregate_risk_implications(trust_map: Dict[str, Any], category_inventory: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Derive run-level (cross-page/cross-asset) security/trust implications
    from the fully-built trust map (responsibility #8).
    """
    implications: List[Dict[str, Any]] = []

    service_count = trust_map.get("external_service_count", 0)
    if service_count >= 5:
        implications.append({
            "risk_type": "broad_third_party_surface",
            "description": (
                f"{service_count} distinct third-party services/origins were observed across the "
                "assessed assets. Each represents an additional trust dependency and a potential "
                "supply-chain compromise vector (a compromised or malicious third-party resource "
                "would execute in the target's origin context)."
            ),
            "related_hosts": sorted(trust_map.get("external_services", {}).keys()),
            "confidence": CONFIDENCE_LOW,
            "evidence": [
                f"{service_count} distinct external service(s) recorded in the third-party trust map",
                "This is an inferred exposure-surface observation, not a confirmed vulnerability.",
            ],
        })

    for category in _HIGH_TRUST_CATEGORIES:
        services = category_inventory.get(category, [])
        if not services:
            continue
        hosts = [s["host"] for s in services]
        implications.append({
            "risk_type": f"high_trust_category_dependency:{category}",
            "description": (
                f"{len(services)} third-party service(s) in the high-trust category '{category}' were "
                "observed. A compromise or misconfiguration of a service in this category has an "
                "outsized potential impact on the target's authentication/payment trust boundary."
            ),
            "related_hosts": hosts,
            "confidence": CONFIDENCE_LOW,
            "evidence": [
                f"Third-party service(s) categorized as '{category}': {hosts}",
                "This is an inferred trust-exposure implication based on service category, not a "
                "confirmed vulnerability or compromise of any listed third party.",
            ],
        })

    return implications


# ---------------------------------------------------------------------------
# Per-page analysis + persistence (bundles responsibilities #1/#4/#8 for one
# already-fetched page — independently testable, mirrors js_analyzer.py's
# analyze_javascript_content/persist_analysis_findings split)
# ---------------------------------------------------------------------------

def analyze_page(body: str, headers: Dict[str, str], page_url: str, target: str) -> Dict[str, Any]:
    """Run every per-page Module 14 responsibility against one already-fetched page."""
    js_resources = extract_third_party_js_resources(body, page_url, target)
    csp = parse_csp_header(_ci_get(headers, "Content-Security-Policy"), target)
    observed_hosts = {r["host"] for r in js_resources}
    risk_implications = assess_csp_risk_implications(page_url, csp, observed_hosts)
    return {
        "page_url": page_url, "js_resources": js_resources, "csp": csp,
        "risk_implications": risk_implications,
    }


def persist_page_findings(analysis: Dict[str, Any], target: str, store: Optional["PendingAssetsStore"]) -> Dict[str, Any]:
    """Persist every finding produced by `analyze_page` for one page."""
    errors: List[str] = []
    counts: Dict[str, int] = {}
    page_url = analysis["page_url"]

    def _add(finding_type: str, value: Any, evidence: List[str], confidence: str,
              discovery_source: str, extra_metadata: Optional[Dict[str, Any]] = None) -> None:
        err = _safe_store_add(store, make_supply_chain_finding(
            finding_type, target, value, evidence, confidence,
            source_asset=page_url, discovery_source=discovery_source, extra_metadata=extra_metadata,
        ))
        if err:
            errors.append(err)

    js_resources = analysis["js_resources"]
    counts["third_party_js_resources"] = len(js_resources)
    seen_hosts: Set[str] = set()
    for res in js_resources:
        _add("supply_chain_third_party_js_resource",
             {"url": res["url"], "host": res["host"], "classification": res["classification"]},
             res["evidence"], CONFIDENCE_HIGH, "script_tag")
        cls = res["classification"]
        if res["host"] not in seen_hosts and cls["category_source"] != "unmatched":
            seen_hosts.add(res["host"])
            basis_note = (
                f"Category {cls['category']!r} matched against known-vendor domain catalog entry for {res['host']!r}"
                if cls["category_source"] == "catalog_match" else
                f"Category {cls['category']!r} is an unconfirmed heuristic inference from hostname naming "
                f"convention for {res['host']!r}, not a known-vendor catalog match"
            )
            confidence = CONFIDENCE_MEDIUM if cls["category_source"] == "catalog_match" else CONFIDENCE_LOW
            _add("supply_chain_service_category", cls, [basis_note], confidence, "script_tag")

    csp = analysis["csp"]
    counts["csp_analysis"] = 1
    csp_evidence = (
        [f"Content-Security-Policy header observed on {page_url}: {csp['raw_header']!r}"]
        if csp["present"] else [f"No Content-Security-Policy header observed on {page_url}"]
    )
    _add("supply_chain_csp_analysis", csp, csp_evidence, CONFIDENCE_HIGH, "csp_header")

    risk_implications = analysis["risk_implications"]
    counts["risk_implications"] = len(risk_implications)
    for risk in risk_implications:
        _add("supply_chain_risk_implication",
             {"risk_type": risk["risk_type"], "description": risk["description"], "related_hosts": risk["related_hosts"]},
             risk["evidence"], risk["confidence"], "aggregate_analysis")

    total = counts["third_party_js_resources"] + counts["risk_implications"]
    if total == 0 and not csp["present"]:
        _add("supply_chain_checked_no_findings", {"url": page_url},
             [f"No externally-hosted JS resources, CSP header, or risk implications observed on {page_url}"],
             CONFIDENCE_LOW, "aggregate_analysis")

    return {"counts": counts, "errors": errors}


# ---------------------------------------------------------------------------
# Input normalization (mirrors js_analyzer.py's _normalize_js_reference)
# ---------------------------------------------------------------------------

def _normalize_page_reference(item: Any) -> Optional[str]:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        value = item.get("value")
        if isinstance(value, dict) and value.get("url"):
            return value.get("url")
        return item.get("url")
    return None


def _normalize_subdomain_reference(item: Any) -> Optional[str]:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        value = item.get("value")
        if isinstance(value, dict):
            for key in ("hostname", "subdomain", "name"):
                if value.get(key):
                    return value[key]
        for key in ("hostname", "subdomain", "name"):
            if item.get(key):
                return item[key]
    return None


# ---------------------------------------------------------------------------
# Module orchestration (multiple pages + subdomains)
# ---------------------------------------------------------------------------

def run_supply_chain_analysis(
    pages: Optional[List[Any]] = None,
    subdomains: Optional[List[Any]] = None,
    target: Optional[str] = None,
    output_dir: str = "output",
    timeout: float = DEFAULT_TIMEOUT,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    max_redirect_hops: int = DEFAULT_MAX_REDIRECT_HOPS,
    dns_timeout: float = DEFAULT_DNS_TIMEOUT,
    max_pages: Optional[int] = None,
    max_subdomains: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run every Module 14 responsibility across `pages` (fetched and
    inspected for third-party JS resources + CSP) and `subdomains`
    (DNS-probed for third-party CNAME delegation), and persist every
    completed discovery immediately to <output_dir>/pending_assets.json.
    `pages`/`subdomains` accept plain strings, `{"url":}`/`{"hostname":}`
    dicts, or crawler.py's/passive_recon.py's raw persisted finding
    records. A failure analyzing one page or subdomain (scope, fetch, DNS)
    never aborts the rest of the run.
    """
    if not target:
        raise ScopeError("A target domain is required to enforce scope for supply_chain.py.")

    store = PendingAssetsStore(output_dir=output_dir)
    summary: Dict[str, Any] = {
        "module": MODULE_NAME, "target": target, "started_at": _now(),
        "pages_requested": 0, "pages_analyzed": 0, "pages_skipped_out_of_scope": 0, "pages_failed": 0,
        "subdomains_requested": 0, "subdomains_analyzed": 0, "subdomains_skipped_out_of_scope": 0,
        "subdomains_dns_failed": 0,
        "page_results": [], "subdomain_results": [], "errors": [],
    }

    page_refs = [u for u in (_normalize_page_reference(p) for p in (pages or [])) if u]
    if max_pages is not None:
        page_refs = page_refs[:max_pages]
    summary["pages_requested"] = len(page_refs)

    all_js_resources: List[Dict[str, Any]] = []
    csp_by_page: Dict[str, Dict[str, Any]] = {}

    for url in page_refs:
        page_result: Dict[str, Any] = {"url": url, "status": None}
        try:
            validated_url = validate_url_target(url, target=target)
        except ScopeError as exc:
            summary["pages_skipped_out_of_scope"] += 1
            page_result["status"] = "skipped_out_of_scope"
            page_result["error"] = str(exc)
            _safe_store_add(store, make_supply_chain_finding(
                "supply_chain_page_skipped_out_of_scope", target, {"url": url, "reason": str(exc)},
                [f"Page {url!r} is out of scope for target {target!r}"], CONFIDENCE_LOW,
                source_asset=url, discovery_source="aggregate_analysis",
            ))
            summary["page_results"].append(page_result)
            continue

        fetch_result = fetch_page(validated_url, target=target, timeout=timeout, max_body_bytes=max_body_bytes,
                                    max_redirect_hops=max_redirect_hops)
        if fetch_result["status"] != "found":
            summary["pages_failed"] += 1
            page_result["status"] = "fetch_failed"
            page_result["error"] = fetch_result.get("error")
            _safe_store_add(store, make_supply_chain_finding(
                "supply_chain_page_fetch_failed", target,
                {"url": validated_url, "error": fetch_result.get("error"), "hops": fetch_result.get("hops", [])},
                [f"Failed to fetch page {validated_url}: {fetch_result.get('error')}"], CONFIDENCE_LOW,
                source_asset=validated_url, discovery_source="aggregate_analysis",
            ))
            summary["page_results"].append(page_result)
            continue

        final_url = fetch_result.get("final_url", validated_url)
        body = fetch_result.get("body") or ""
        headers = fetch_result.get("headers", {})
        content_type = _ci_get(headers, "Content-Type")

        if not _looks_textual(content_type, body):
            page_result["status"] = "non_textual_content_skipped"
            page_result["final_url"] = final_url
            summary["page_results"].append(page_result)
            continue

        analysis = analyze_page(body, headers, final_url, target)
        persisted = persist_page_findings(analysis, target, store)

        all_js_resources.extend(analysis["js_resources"])
        csp_by_page[final_url] = analysis["csp"]

        page_result["status"] = "analyzed"
        page_result["final_url"] = final_url
        page_result["counts"] = persisted["counts"]
        summary["pages_analyzed"] += 1
        summary["errors"].extend(persisted["errors"])
        summary["page_results"].append(page_result)

    sub_refs = [s for s in (_normalize_subdomain_reference(s) for s in (subdomains or [])) if s]
    if max_subdomains is not None:
        sub_refs = sub_refs[:max_subdomains]
    summary["subdomains_requested"] = len(sub_refs)

    dns_relationships: List[Dict[str, Any]] = []
    for hostname in sub_refs:
        sub_result: Dict[str, Any] = {"subdomain": hostname, "status": None}
        try:
            validated_host = validate_hostname_target(hostname, target)
        except ScopeError as exc:
            summary["subdomains_skipped_out_of_scope"] += 1
            sub_result["status"] = "skipped_out_of_scope"
            sub_result["error"] = str(exc)
            _safe_store_add(store, make_supply_chain_finding(
                "supply_chain_subdomain_skipped_out_of_scope", target, {"hostname": hostname, "reason": str(exc)},
                [f"Hostname {hostname!r} is out of scope for target {target!r}"], CONFIDENCE_LOW,
                source_asset=hostname, discovery_source="dns_cname",
            ))
            summary["subdomain_results"].append(sub_result)
            continue

        dns_map = map_subdomain_third_party_dns(validated_host, target, timeout=dns_timeout)
        sub_result.update(dns_map)

        if dns_map["status"] == "error":
            summary["subdomains_dns_failed"] += 1
            _safe_store_add(store, make_supply_chain_finding(
                "supply_chain_dns_lookup_failed", target, {"subdomain": validated_host, "error": dns_map["error"]},
                [f"DNS CNAME lookup for {validated_host} failed: {dns_map['error']}"], CONFIDENCE_LOW,
                source_asset=validated_host, discovery_source="dns_cname",
            ))
        elif dns_map["third_party"]:
            dns_relationships.append(dns_map)
            classification = dns_map["third_party"]
            basis_note = (
                f"Category {classification['category']!r} matched against known-vendor domain catalog entry"
                if classification["category_source"] == "catalog_match" else
                f"Category {classification['category']!r} is an unconfirmed heuristic inference, not a "
                "known-vendor catalog match"
            )
            _safe_store_add(store, make_supply_chain_finding(
                "supply_chain_subdomain_third_party_dns", target,
                {"subdomain": validated_host, "cname_chain": dns_map["chain"], "third_party": classification},
                [f"{validated_host} CNAME chain resolves to external host {dns_map['chain'][-1]!r}: {dns_map['chain']}",
                 basis_note],
                CONFIDENCE_HIGH, source_asset=validated_host, discovery_source="dns_cname",
            ))
        else:
            _safe_store_add(store, make_supply_chain_finding(
                "supply_chain_dns_checked_no_third_party", target,
                {"subdomain": validated_host, "cname_chain": dns_map["chain"]},
                [f"CNAME chain for {validated_host} (if any) does not resolve outside {target!r}'s scope: {dns_map['chain']}"],
                CONFIDENCE_LOW, source_asset=validated_host, discovery_source="dns_cname",
            ))

        sub_result["status"] = "analyzed"
        summary["subdomains_analyzed"] += 1
        summary["subdomain_results"].append(sub_result)

    trust_map = build_trust_map(all_js_resources, csp_by_page, dns_relationships)
    category_inventory = build_category_inventory(trust_map)
    aggregate_risks = assess_aggregate_risk_implications(trust_map, category_inventory)

    if trust_map["external_service_count"] > 0:
        _safe_store_add(store, make_supply_chain_finding(
            "supply_chain_trust_map", target,
            {"trust_map": trust_map, "category_inventory": category_inventory},
            [f"Third-party trust map correlated from {len(all_js_resources)} script reference(s), "
             f"{len(csp_by_page)} page CSP observation(s), and {len(dns_relationships)} DNS CNAME relationship(s)"],
            CONFIDENCE_MEDIUM, source_asset=target, discovery_source="aggregate_analysis",
        ))

    for risk in aggregate_risks:
        err = _safe_store_add(store, make_supply_chain_finding(
            "supply_chain_risk_implication", target,
            {"risk_type": risk["risk_type"], "description": risk["description"], "related_hosts": risk["related_hosts"]},
            risk["evidence"], risk["confidence"], source_asset=target, discovery_source="aggregate_analysis",
        ))
        if err:
            summary["errors"].append(err)

    summary["trust_map"] = trust_map
    summary["category_inventory"] = category_inventory
    summary["risk_implications"] = aggregate_risks
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="supply_chain.py",
        description="ReconHound Module 14 — third-party supply-chain mapping (standalone test entry point).",
    )
    parser.add_argument("--page", action="append", default=[], dest="pages",
                         help="In-scope page URL to analyze for third-party resources/CSP (repeatable)")
    parser.add_argument("--subdomain", action="append", default=[], dest="subdomains",
                         help="In-scope subdomain to DNS-probe for third-party CNAME delegation (repeatable)")
    parser.add_argument("--target", required=True, help="Target domain to enforce scope against")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout (seconds)")
    parser.add_argument("--dns-timeout", type=float, default=DEFAULT_DNS_TIMEOUT, help="Per-DNS-query timeout (seconds)")
    args = parser.parse_args()

    result = run_supply_chain_analysis(
        pages=args.pages, subdomains=args.subdomains, target=args.target, output_dir=args.output_dir,
        timeout=args.timeout, dns_timeout=args.dns_timeout,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
