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
     ssl_analyzer, vuln_intel, risk_engine, report_generator,
     orchestrator, osint_engine, passive_recon, passive_intel, code_leak,
     wayback_intel, or any other module.

SECURITY BOUNDARIES (context.md §4/§16, module contract's explicit scope
instructions):

  - This module fetches only in-scope target pages. `validate_url_target`
    is the SINGLE chokepoint every request goes through — the initial page
    fetch and every redirect hop alike — and it enforces the scheme check,
    a control-character rejection (urlsplit silently strips CR/LF/TAB, so
    without it the host that is scope-checked is not the string handed to
    `requests`), parseability, the domain-suffix scope check, the
    private/loopback/reserved-IP SSRF safeguard, and the credential strip.
    The IP-literal exemption from the domain comparison does NOT exempt an
    address from the SSRF safeguard: this module's page list is fed by
    crawler.py and by the orchestrator from DISCOVERED URLs, so an in-scope
    page linking to `http://169.254.169.254/` must not be able to steer the
    scanner at cloud instance metadata. Such a literal is accepted only
    when it IS the operator-supplied target — crawler.py's and
    endpoint_discovery.py's carve-out. Obfuscated address forms (the 32-bit
    integer, octal, hex and short forms that the resolver accepts but a
    domain-suffix check does not recognise) are normalised before that
    decision is made.
    A discovered third-party resource URL (a `<script src>` pointing
    off-target, a CSP directive source, a CNAME target) is NEVER fetched,
    authenticated to, or otherwise interacted with — every third-party
    observation in this module is derived exclusively from
    content/headers/DNS answers already obtained for an in-scope asset.
    This mirrors js_analyzer.py's `extract_external_service_references`
    boundary ("OBSERVATIONS ONLY... never issues a network request") and
    code_leak.py's exploitation boundary.
  - No credential ever reaches pending_assets.json or the wire: a
    `user:password@` component is stripped from every URL this module
    validates, resolves or records (`_strip_userinfo`), because
    pending_assets.json is a plain-text file shared with every other module
    and reproduced in the report appendix (CLAUDE.md rule 16).
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
  - CSP analysis reflects only actually-observed policies — no policy is
    assumed, guessed, or synthesized when none is present (the analysis
    records `present: False` and stops there for that page). `analyze_csp`
    distinguishes what a single-header read could not, and each distinction
    changes what the output means:
      * ENFORCED (`Content-Security-Policy`, and the `<meta http-equiv>`
        form, which is a real enforced policy) vs REPORT-ONLY
        (`Content-Security-Policy-Report-Only`). Report-only is MONITORING,
        NOT PROTECTION: it is recorded separately, never counted as
        enforcement, and never allowed to make the module claim a page is
        protected. Its allowlisted hosts are still real observed evidence
        of an intended trust relationship, so they are preserved.
      * MULTIPLE POLICIES. RFC 7230 lets repeated headers be joined with
        ", " (exactly what `dict(response.headers)` does) and CSP itself
        allows comma-separated policies in one header; each is enforced
        independently. They are split (`split_csp_policies`) rather than
        parsed as one string.
      * MALFORMED / AMBIGUOUS policies and duplicate directives are
        preserved (`malformed`, `duplicate_directives`) rather than
        silently resolved; within one policy the FIRST occurrence of a
        directive governs, as browsers do.
      * A WILDCARD source (`*.example-cloud.net`) is recorded as a broad
        ALLOWANCE, not as a confirmed dependency on a specific service: in
        the trust map such an entry is marked
        `attribution: "inferred_from_wildcard_allowlist"` and it does not
        count toward the observed third-party service surface.
    A CSP host source must actually look like a host (contain a dot, or be
    an IP literal). Without that rule a malformed or hostile policy value
    manufactured third-party "hosts" out of ordinary CSP vocabulary —
    "script-src none" yielded the host "none" — which became
    third_party_service ASSETS in surface_mapper.py and
    third_party_dependency SIGNALS in risk_engine.py.
  - DNS observations describe what DNS ACTUALLY SAID and nothing more. A
    CNAME chain carries a `resolution_status` (`terminus_exists`,
    `unresolved_nxdomain`, `truncated_max_hops`, `cycle`, `no_cname`,
    `error`). An `unresolved_nxdomain` — a delegation whose target does not
    exist, i.e. a dangling CNAME — is recorded as an OBSERVATION ONLY: it
    is explicitly NOT a confirmed subdomain takeover, NOT evidence that the
    name is claimable, and no claim/registration/interaction of any kind is
    attempted. Correlating it into a takeover indicator is
    surface_mapper.py's named responsibility (decision #3); this module's
    job is to preserve the evidence that correlation needs, which it
    previously destroyed (see limitation notes below).
  - A LOOKUP FAILURE IS NEVER AN ABSENCE. A DNS timeout/SERVFAIL is
    recorded as `supply_chain_dns_lookup_failed` and the hostname is NOT
    counted as analyzed; only a completed lookup can produce
    `supply_chain_dns_checked_no_third_party`. The same separation applies
    to page fetch failures and to out-of-scope skips.

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
  7. ATTRIBUTION IS TO THE DELEGATION TARGET, NOT THE CHAIN TERMINUS. A
     subdomain's third-party relationship is with the FIRST hop that leaves
     the target's scope, not with wherever that provider's own chain
     happens to end. Using the terminus misattributed every provider that
     fronts itself with a CDN: "support.example.com -> example.zendesk.com
     -> zendesk.map.fastly.net" was reported as a Fastly *cdn* dependency
     when the relationship the target actually has is with Zendesk
     (support_chat). The full chain is still preserved in `cname_chain`,
     unchanged, for consumers that correlate on the endpoint.
  8. SHARED INFRASTRUCTURE IS NEVER OWNERSHIP. A catalog match against a
     multi-tenant provider domain (amazonaws.com, cloudfront.net,
     azureedge.net, myshopify.com, ...) identifies the PROVIDER, never the
     owner of the specific resource. Such a match is flagged
     `shared_infrastructure: True` and says so in its evidence, so no
     consumer can turn "served from AWS" into "the target owns this" or
     into an ASN/rDNS/certificate-based ownership claim.
  9. REPETITION IS NOT CORROBORATION (context.md §8). A service's CATEGORY
     is a property of the host, not of the page that referenced it, so it
     is emitted once per run rather than once per page. Confidence reflects
     evidence quality — a catalog match is MEDIUM, a naming-convention
     guess is LOW — and never rises because the same signal was seen again.
 10. BOUNDS. A page is attacker-influenced input, so per-page third-party
     resources, per-directive CSP hosts and tokens, evidence-string length,
     raw policy length and hostname length are all bounded. Hitting a bound
     is RECORDED as its own finding
     (`supply_chain_page_resources_truncated`,
     `supply_chain_page_malformed_references`), never silently dropped, so
     an incomplete inventory can never be mistaken for a complete one.
 11. Findings for one page are committed in a single atomic batch
     (`PendingAssetsStore.add_many`, mirroring endpoint_discovery.py).
     "Persist immediately" is preserved at the granularity of an analysed
     page rather than one full-file rewrite per finding, which was
     quadratic in what pending_assets.json already holds (measured: 102
     findings 0.10s, 302 0.93s, 602 3.50s; now 0.006s for the same batch).

KNOWN, INTENTIONAL LIMITATIONS (v1):
  - STATIC ANALYSIS ONLY. Dependencies introduced at RUNTIME — a Google Tag
    Manager or Segment container that injects further `<script>` elements,
    a DOM-created resource, a fetch() to a vendor API — are not visible to
    an HTML parse and are NOT discovered here. This module deliberately
    does not add a headless browser: runtime discovery belongs to
    crawler.py/js_analyzer.py, and a tag-manager host IS detected as a
    dependency (with category `tag_management`), which is the honest signal
    that further, unenumerated dependencies probably exist behind it.
    Fourth-/nth-party dependencies (what a third party itself loads) are
    outside this module for the same reason: they are not observable from
    the target's own responses.
  - The vendor catalog is finite and best-effort. An unmatched host is
    never dropped — it is recorded with category `unknown_third_party`, so
    categorization coverage is a visible property of the output rather than
    a filter on it.
  - The `cdn.`/`static.`/`assets.`/`media.` naming heuristic is an
    unconfirmed inference, marked `naming_convention_heuristic` and emitted
    at LOW confidence.
  - Observations are POINT-IN-TIME. A/B tests, feature flags, geo/consent-
    dependent tag loading and anti-bot cloaking can all cause a different
    dependency set to be served to a different client at a different
    moment. This module does not re-sample, rotate egress, or attempt to
    evade bot detection (context.md §16); it reports what was served to
    this request, with a timestamp.
  - CSP evidence is recorded, but SEVERITY is not decided here.
    risk_engine.py owns CRITICAL/HIGH/MEDIUM/LOW/INFO scoring; this module
    emits evidence and confidence only, and does not know whether a page is
    a login/payment/admin page — that context lives in the asset graph, so
    context-sensitive risk belongs to risk_engine.py, not to a second risk
    engine here.
  - A directive value containing a literal comma (invalid CSP) is split as
    if it separated two policies; the trailing fragment then parses as an
    unrecognised directive and is ignored rather than misread as a host.
  - A single-label CSP host source (an intranet name with no dot) is not
    recorded as a third-party host — see the CSP note above.
  - Analysis is sequential; there is no in-module concurrency or
    cancellation. Threading and interrupt handling belong to
    core/orchestrator.py and reconhound.py respectively.

CROSS-MODULE NOTE (not fixed here, belongs to surface_mapper.py):
  `surface_mapper._h_supply_chain_third_party_dns` creates its
  third_party_service asset from `cname_chain[-1]`, so for a chain that
  passes through a provider's own CDN it creates the asset for the terminus
  ("zendesk.map.fastly.net") rather than for the delegation target
  ("example.zendesk.com") this module now identifies and publishes as
  `delegation_target`. Its takeover-signature matching legitimately wants
  the terminus, so the chain order is deliberately left unchanged here;
  consuming `delegation_target` for the ASSET while keeping the terminus
  for the SIGNATURE is a change to surface_mapper.py, not to this module.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import tempfile
import threading
import urllib.parse
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

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

# Bounds on what a single (potentially hostile) page may contribute. A page is
# attacker-influenced input: without these, one response could produce an
# unbounded number of findings and unbounded evidence strings, all of which are
# written to the pending_assets.json every other module shares (context.md
# §12.1/§12.11). Exceeding a bound is RECORDED as a truncation finding, never
# silently dropped.
DEFAULT_MAX_THIRD_PARTY_RESOURCES_PER_PAGE = 500
DEFAULT_MAX_CSP_HOSTS_PER_DIRECTIVE = 250
MAX_EVIDENCE_VALUE_CHARS = 512
MAX_RAW_POLICY_CHARS = 8192
MAX_CSP_TOKENS_PER_DIRECTIVE = 500
# RFC 1035: a fully-qualified domain name cannot exceed 253 characters. A
# longer "hostname" out of page content is malformed, and recording it would
# create a nonsense asset in the shared graph.
MAX_HOSTNAME_CHARS = 253

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)

# CSP delivery mechanisms and dispositions (see parse_csp_headers).
CSP_DELIVERY_HEADER = "header"
CSP_DELIVERY_META = "meta"
CSP_DISPOSITION_ENFORCE = "enforce"
CSP_DISPOSITION_REPORT_ONLY = "report-only"


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

_NUMERIC_HOST_RE = re.compile(r"^[0-9a-fA-FxX.]+$")


def _coerce_ip_literal(host: str) -> Optional[str]:
    """
    The address a host string actually resolves to, if it is an address at all.

    `ipaddress.ip_address` only accepts the canonical dotted-quad, but the
    resolver — and therefore `requests` — also accepts the classic SSRF
    obfuscations: the 32-bit integer form ("2130706433"), octal
    ("0177.0.0.1"), hex ("0x7f.0.0.1") and short forms ("127.1"). Each of
    those is 127.0.0.1 on the wire while looking like an opaque hostname to a
    domain-suffix check, so without normalising them the private-IP safeguard
    could be walked straight past. Returns the canonical address, or None when
    the host is a real name.
    """
    host = _unbracket(host)
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    # Only consider all-numeric/hex forms: a real hostname has an alphabetic
    # label, and inet_aton would otherwise never match it anyway.
    if not _NUMERIC_HOST_RE.match(host):
        return None
    try:
        return str(ipaddress.ip_address(socket.inet_aton(host)))
    except (OSError, ValueError):
        return None


def _is_ip_literal(host: str) -> bool:
    return _coerce_ip_literal(host) is not None


def _is_disallowed_redirect_ip(host: str) -> bool:
    """Private/loopback/link-local/multicast/reserved/unspecified IP-literal check (SSRF safeguard)."""
    canonical = _coerce_ip_literal(host)
    if canonical is None:
        return False
    ip_obj = ipaddress.ip_address(canonical)
    return (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified
    )


def _unbracket(host: str) -> str:
    """Strip the brackets a URL puts around an IPv6 literal."""
    if not isinstance(host, str):
        return ""
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


# scheme://user:password@  — the only place a credential is syntactically
# unambiguous inside free text this module records.
_USERINFO_IN_TEXT_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z][A-Za-z0-9+.\-]*://)[^/\s@]+@")


def _redact_credentials(text: str) -> str:
    """
    Strip `user:password@` out of any free text before it is recorded.

    `_strip_userinfo` handles a string that is a whole URL; this handles a URL
    embedded in something larger — most importantly a CSP policy, whose raw
    text is persisted verbatim as evidence. A policy source written
    `script-src https://user:pw@vendor.example/` put that credential straight
    into pending_assets.json, which is plain text shared with every other
    module and reproduced in the report appendix (CLAUDE.md rule 16).
    """
    if not text or "@" not in text:
        return text
    # The replacement must stay a PARSEABLE userinfo component. A bracketed
    # marker ("[redacted]@") makes urlsplit read the authority as an IPv6
    # literal and raise, which silently dropped the very third-party host the
    # policy was allow-listing — a false negative introduced by the redaction
    # itself. A bare label keeps the URL well-formed, so the host is still
    # extracted, while the credential is gone.
    return _USERINFO_IN_TEXT_RE.sub(r"\1redacted@", text)


def _clip(text: Any, limit: int = MAX_EVIDENCE_VALUE_CHARS) -> str:
    """
    Bound one attacker-controlled string before it becomes evidence.

    Every string this module puts in a finding can originate in the page body
    (a `src` attribute, a CSP directive, a CNAME label). A 200KB `src` produced
    a 200KB evidence line persisted verbatim to the shared pending_assets.json;
    truncation is marked so a reader can tell the value was cut rather than
    being that shape on the wire.
    """
    if text is None:
        return ""
    text = text if isinstance(text, str) else str(text)
    # Redact before truncating: this is the single chokepoint every evidence
    # string and every stored raw value passes through.
    text = _redact_credentials(text)
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[truncated, {len(text)} chars total]"


def _idna_normalize(host: str) -> str:
    """
    Reduce a hostname to the single form scope comparisons are made in.

    Without this, a target written as "münchen.de" and a hostname arriving as
    "xn--mnchen-3ya.de" (or the reverse) compare unequal even though they are
    the same host — silently misfiling an in-scope asset as a third party in
    one direction, and in the other making a homograph host look "different"
    from the target it impersonates. Both sides are folded to lowercase A-label
    form; anything that will not encode is returned lowercased unchanged so the
    caller still gets a deterministic comparison. Mirrors crawler.py's/
    js_analyzer.py's/endpoint_discovery.py's helper of the same name
    (duplicated per modular independence, context.md §12.2).
    """
    if not isinstance(host, str):
        return ""
    host = host.strip().rstrip(".").lower()
    if not host or host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return host


def _strip_userinfo(url: str) -> str:
    """
    Remove any `user:password@` component from a URL.

    URLs reach this module from operator-supplied page lists, from crawler.py
    records and from page bodies, so credentials genuinely turn up in them.
    They must not be re-sent, must not become part of an asset identity, and
    above all must never be written into pending_assets.json — a plain-text
    file shared with every other module and reproduced in the report appendix
    (CLAUDE.md rule 16). Mirrors endpoint_discovery.py's/js_analyzer.py's
    helper of the same name.
    """
    if not isinstance(url, str) or "@" not in url:
        return url
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


def _in_scope_host(hostname: str, target: str) -> bool:
    hostname = _idna_normalize(hostname)
    target = _idna_normalize(target)
    if not hostname or not target:
        return False
    return hostname == target or hostname.endswith("." + target)


def _is_internal_ip_host(host: str) -> bool:
    """True when `host` is an IP literal in private/loopback/reserved space."""
    return _is_ip_literal(_unbracket(host)) and _is_disallowed_redirect_ip(host)


def validate_url_target(url: str, target: Optional[str] = None) -> str:
    """
    The single chokepoint every URL this module fetches passes through.

    It enforces, in order: the string/scheme contract, a control-character
    rejection, parseability, the presence of a hostname, the SSRF safeguard,
    the domain-suffix scope check, and the credential strip.

    Two of those deserve a note.

    CONTROL CHARACTERS. `urllib.parse.urlsplit` silently *removes* CR, LF and
    TAB before parsing, so without an explicit rejection the host that gets
    scope-checked is not the string handed to `requests`:
    "https://evil.com\n.example.com/" scope-checks as the in-scope host
    "evil.com.example.com" while the raw bytes going onto the wire say
    something else. Mirrors crawler.py's/endpoint_discovery.py's rejection.

    THE IP-LITERAL EXEMPTION IS NOT AN SSRF HOLE. An IP literal is still
    exempt from the *domain-suffix* comparison (an operator who authorised a
    scan against a bare IP has already put that address in scope, and IP scope
    is enforced upstream, not by a string comparison here). That exemption does
    not extend to private/loopback/link-local/reserved space: this module's
    page list is fed by crawler.py and by the orchestrator from *discovered*
    URLs, so an in-scope page linking to `http://169.254.169.254/` could
    otherwise steer the scanner at cloud instance metadata or at RFC1918 hosts.
    Such a literal is accepted only when it *is* the operator-supplied target —
    exactly the carve-out crawler.py's and endpoint_discovery.py's `_host_allowed`
    already make. Previously only *redirect* hops were checked, so the very
    first request was unprotected.
    """
    if not isinstance(url, str) or not url.strip():
        raise ScopeError("URL must be a non-empty string.")

    candidate = url.strip()
    if any(ch in candidate for ch in "\r\n\t\x00"):
        raise ScopeError(f"URL contains control characters: {url!r}")

    try:
        parsed = urllib.parse.urlsplit(candidate)
        hostname = parsed.hostname
    except ValueError as exc:
        # urlsplit raises on malformed IPv6 brackets and out-of-range ports.
        # Raising ScopeError (not a bare ValueError) is what keeps one hostile
        # URL from aborting the whole run: run_supply_chain_analysis catches
        # ScopeError per page and continues.
        raise ScopeError(f"URL cannot be parsed: {url!r} ({exc})") from exc

    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"URL must use http:// or https://, not {parsed.scheme!r}: {url!r}")

    if not hostname:
        raise ScopeError(f"URL must include a hostname: {url!r}")

    try:
        parsed.port  # out-of-range ports raise here rather than at request time
    except ValueError as exc:
        raise ScopeError(f"URL has an invalid port: {url!r} ({exc})") from exc

    canonical_ip = _coerce_ip_literal(hostname)
    if canonical_ip is not None:
        target_ip = _coerce_ip_literal(target or "")
        if _is_disallowed_redirect_ip(hostname) and (
            target_ip is None or canonical_ip != target_ip
        ):
            raise ScopeError(
                f"URL host {hostname!r} is a private/loopback/reserved IP and is not the "
                f"authorized target (SSRF safeguard): {url!r}"
            )
    elif target and not _in_scope_host(hostname, target):
        raise ScopeError(f"URL host {hostname!r} is not in scope for target {target!r}: {url!r}")

    # Credentials in an operator-supplied URL are dropped rather than rejected:
    # the URL is legitimate, but re-sending and persisting the credential is not.
    return _strip_userinfo(candidate)


def validate_hostname_target(hostname: str, target: str) -> str:
    """Validate a bare hostname (no scheme) is in scope for `target`, for DNS-only inputs."""
    if not isinstance(hostname, str) or not hostname.strip():
        raise ScopeError("Hostname must be a non-empty string.")
    candidate = hostname.strip().rstrip(".")
    if any(ch in candidate for ch in "\r\n\t\x00 "):
        # A space or control character in a hostname is never legitimate, and a
        # DNS query built from one is not the name that was scope-checked.
        raise ScopeError(f"Hostname contains control characters or whitespace: {hostname!r}")
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
    # `list("abc")` silently yields ['a','b','c'] — a single evidence string
    # passed by a caller would be shredded into per-character "evidence".
    if isinstance(evidence, str):
        evidence_list = [evidence]
    elif isinstance(evidence, Iterable):
        evidence_list = [e if isinstance(e, str) else str(e) for e in evidence]
    else:
        evidence_list = [str(evidence)]
    return {
        "type": finding_type,
        "target": target,
        "value": value,
        "evidence": evidence_list,
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
        self._serialized: Optional[str] = None
        self._stamp: Optional[Tuple[int, int]] = None
        try:
            os.makedirs(self.output_dir, exist_ok=True)
        except OSError as exc:
            # An unwritable/unreachable output directory is a persistence
            # problem, not an unhandled crash of the whole module run.
            raise PersistenceError(
                f"Output directory {self.output_dir!r} cannot be created: {exc}"
            ) from exc

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
            # Unreadable file (permissions, I/O error) — a persistence failure
            # the caller can record and continue past, not a crash.
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

        add() rewrote the whole shared file per finding, which is quadratic in
        the number of records already on disk — and this module's worst case is
        a single page: one `<script src>` yields a resource record plus a
        category record, and pending_assets.json already holds every earlier
        module's output by the time supply_chain.py runs. Measured on this
        repository with the previous per-finding add(): 102 findings 0.10s,
        302 findings 0.93s, 602 findings 3.50s. Batching one page's records into
        a single write keeps a run linear in practice.

        Crash-safety is unchanged and slightly stronger: still one
        write-to-temp + os.replace, so a batch is all-or-nothing rather than
        half-applied. Mirrors endpoint_discovery.py/js_analyzer.py/crawler.py,
        which share this output file. Returns the number of findings written.
        """
        if not findings:
            return 0
        with self._lock:
            if not self._cache_is_current():
                # First write of this run, or the file changed underneath us:
                # re-encode from what is actually on disk so a concurrent
                # writer's records are preserved rather than clobbered.
                self._serialized = self._encode_body(self._read_all())
            addition = self._encode_body(findings)
            body = f"{self._serialized},\n{addition}" if self._serialized else addition
            self._atomic_write_body(body)
            self._serialized = body
            self._stamp = self._current_stamp()
        return len(findings)

    @staticmethod
    def _encode_body(records: List[Dict[str, Any]]) -> str:
        """Serialize records as the *inside* of the JSON array (no brackets)."""
        if not records:
            return ""
        try:
            return ",\n".join("  " + json.dumps(r, indent=2).replace("\n", "\n  ") for r in records)
        except (TypeError, ValueError) as exc:
            # A non-JSON-safe value must not abort the run with a raw TypeError
            # from deep inside the encoder; report it as a persistence failure.
            raise PersistenceError(f"Finding is not JSON-serializable: {exc}") from exc

    def _atomic_write_body(self, body: str) -> None:
        """Write "[<body>]" via write-to-temp + os.replace (crash-safe)."""
        dir_name = os.path.dirname(self.path) or "."
        try:
            fd, tmp_path = tempfile.mkstemp(prefix=".pending_assets_", dir=dir_name)
        except OSError as exc:
            raise PersistenceError(f"Cannot create temporary file in {dir_name!r}: {exc}") from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("[\n" if body else "[")
                f.write(body)
                f.write("\n]" if body else "]")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
        except OSError as exc:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            raise PersistenceError(f"Cannot write {self.path!r}: {exc}") from exc
        except BaseException:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
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
    return _safe_store_add_many(store, [finding])


def _safe_store_add_many(store: Optional["PendingAssetsStore"], findings: List[Dict[str, Any]]) -> Optional[str]:
    """Batched `_safe_store_add`. Same never-silently-discarded error contract."""
    if store is None or not findings:
        return None
    try:
        store.add_many(findings)
        return None
    except PersistenceError as exc:
        return str(exc)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _ci_get(headers: Dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup (requests preserves server casing)."""
    values = _ci_get_all(headers, name)
    return values[0] if values else None


def _ci_get_all(headers: Any, name: str) -> List[str]:
    """
    Every value observed for one header name, case-insensitively.

    `dict(resp.headers)` collapses repeated headers the way RFC 7230 permits
    (one entry, values joined with ", "), but a caller may equally hand this
    module a plain dict that repeats a name in different casing, or a dict
    whose value is already a list. All three shapes matter for CSP, where a
    response legitimately carries more than one policy and each policy is
    enforced independently.
    """
    if not headers or not hasattr(headers, "items"):
        return []
    name_lower = name.lower()
    out: List[str] = []
    try:
        items = list(headers.items())
    except Exception:
        return []
    for k, v in items:
        if not isinstance(k, str) or k.lower() != name_lower:
            continue
        if isinstance(v, (list, tuple)):
            out.extend(str(x) for x in v)
        elif v is not None:
            out.append(v if isinstance(v, str) else str(v))
    return out


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
            "final_url": _strip_userinfo(resp.url),
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
        # requests/urllib3 raise a handful of non-RequestException errors that
        # would otherwise abort the whole run: UnicodeError for an over-long
        # IDN label, ValueError for a malformed port. One page's transport
        # failure must never take the run down (context.md §12.11).
        result["error"] = f"request failed ({type(exc).__name__}): {exc}"
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

        try:
            next_url = urllib.parse.urljoin(current, location)
        except ValueError as exc:
            return {"status": "error", "error": f"unparseable redirect Location {location!r}: {exc}",
                    "hops": hops, "final_url": current}

        # The two established, separately-worded hop rejections are kept
        # verbatim (callers and tests read these strings), and everything else
        # a hop can smuggle in — a non-http(s) scheme, a control-character
        # host, an out-of-range port, embedded credentials — is then caught by
        # the SAME chokepoint the initial URL went through. Previously the hop
        # check was a partial hand-written copy that enforced neither.
        next_host = urllib.parse.urlsplit(next_url).hostname or "" if "\x00" not in next_url else ""
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
        try:
            next_url = validate_url_target(next_url, target=target)
        except ScopeError as exc:
            return {"status": "error", "error": f"redirect blocked: {exc}",
                    "hops": hops, "final_url": current}

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

# Catalog domains that are MULTI-TENANT: any customer of the provider can be
# served from a hostname under them, so a match identifies the PROVIDER, never
# the owner of the specific resource. A shared-infrastructure match must not be
# read as "the target owns this" or as "this vendor is the target's supplier of
# record" — an explicit requirement of this module's attribution contract.
_SHARED_INFRASTRUCTURE_DOMAINS = frozenset({
    "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "azureedge.net",
    "googleapis.com", "gstatic.com", "akamaized.net", "akamai.net", "akamaihd.net",
    "fastly.net", "cdn77.org", "stackpathcdn.com", "firebaseio.com", "firebaseapp.com",
    "myshopify.com", "cdn.jsdelivr.net", "jsdelivr.net", "unpkg.com",
    "cdnjs.cloudflare.com", "bootstrapcdn.com", "sendgrid.net",
})


def _match_third_party_catalog(host: str) -> Optional[Tuple[str, str, str]]:
    """Longest (most specific) catalog suffix match for `host`, if any."""
    host = _idna_normalize(host)
    best: Optional[Tuple[str, str, str]] = None
    best_len = -1
    for domain, info in _THIRD_PARTY_CATALOG.items():
        if host == domain or host.endswith("." + domain):
            # "ingest.sentry.io" matches both "sentry.io" and "ingest.sentry.io";
            # dict iteration order decided which one won before, which made the
            # reported vendor/category depend on catalog insertion order.
            if len(domain) > best_len:
                best, best_len = (info[0], info[1], domain), len(domain)
    return best


def classify_third_party_host(host: str) -> Dict[str, Any]:
    """
    Categorize an external host (responsibility #2/#3/#7). Returns
    {"host":, "vendor":, "category":, "category_source":, ...}, where
    `category_source` is one of "catalog_match" (a known-vendor domain
    match — reasonably reliable), "naming_convention_heuristic" (an
    unconfirmed inference from hostname naming convention), "ip_literal"
    (the reference names an address, not a vendor) or "unmatched"
    (recorded but not categorizable from this module's catalog/heuristics).
    This is always an INFERENCE, never a confirmed vendor identity.

    `shared_infrastructure` marks a match against a multi-tenant provider
    domain: it identifies the PROVIDER, never the owner of the specific
    resource, so a consumer must not turn it into an ownership claim.
    """
    raw_host = host if isinstance(host, str) else ""
    host_norm = _idna_normalize(_strip_host_wildcard(raw_host))

    if not host_norm:
        return {"host": raw_host, "vendor": None, "category": "unknown_third_party",
                "category_source": "unmatched", "shared_infrastructure": False,
                "matched_domain": None, "is_ip_literal": False}

    if _is_ip_literal(_unbracket(host_norm)):
        # An address is not a vendor. A private/loopback/reserved literal is an
        # INTERNAL reference that happens to fail the domain-suffix scope test —
        # calling it a "third-party supply-chain dependency" would be wrong in
        # both directions (it is neither third-party nor a supplier).
        internal = _is_internal_ip_host(host_norm)
        return {
            "host": raw_host, "vendor": None,
            "category": "internal_ip_reference" if internal else "unknown_third_party",
            "category_source": "ip_literal", "shared_infrastructure": False,
            "matched_domain": None, "is_ip_literal": True,
        }

    match = _match_third_party_catalog(host_norm)
    if match:
        vendor, category, domain = match
        return {"host": raw_host, "vendor": vendor, "category": category,
                "category_source": "catalog_match",
                "shared_infrastructure": domain in _SHARED_INFRASTRUCTURE_DOMAINS,
                "matched_domain": domain, "is_ip_literal": False}
    if _CDN_NAMING_CONVENTION_RE.match(host_norm):
        return {"host": raw_host, "vendor": None, "category": "cdn",
                "category_source": "naming_convention_heuristic",
                "shared_infrastructure": False, "matched_domain": None, "is_ip_literal": False}
    return {"host": raw_host, "vendor": None, "category": "unknown_third_party",
            "category_source": "unmatched", "shared_infrastructure": False,
            "matched_domain": None, "is_ip_literal": False}


# ---------------------------------------------------------------------------
# 1. Externally-hosted JavaScript inventory
# ---------------------------------------------------------------------------

def _parse_html(body: Optional[str]) -> Optional[Any]:
    """
    Parse page HTML ONCE per page.

    Three separate responsibilities read the same document (script inventory,
    `<base href>`, meta CSP). Each parsing it independently tripled the cost of
    the single most expensive operation this module performs — measured at
    11.8s versus 7.1s for one parse on a 2.4MB page — for no benefit, since
    they all see the identical body. The public helpers still accept a raw
    string so they remain independently usable.
    """
    if not body:
        return None
    try:
        with warnings.catch_warnings():
            # We are parsing an HTTP response body by construction. A short
            # body that happens to look like a URL is not a mistake here, and
            # the advisory warning would otherwise reach the operator's console.
            warnings.simplefilter("ignore")
            return BeautifulSoup(body, "html.parser")
    except Exception:
        return None


def _as_soup(body_or_soup: Any) -> Optional[Any]:
    """Accept either raw HTML or an already-parsed document."""
    if body_or_soup is None or isinstance(body_or_soup, str):
        return _parse_html(body_or_soup)
    return body_or_soup


def extract_base_href(body: Any, page_url: str) -> Optional[str]:
    """
    The effective base URL for the page's relative references.

    A `<base href>` changes what every relative `src` on the page resolves to,
    which is exactly the question this module is answering. Ignoring it
    mis-attributed dependencies in both directions: with
    `<base href="https://cdn.thirdparty.net/">` a relative
    `<script src="app.js">` resolves to a THIRD-PARTY host, but was resolved
    against the page URL instead and therefore silently classified as
    first-party and dropped. Only the first `<base>` counts (HTML ignores
    later ones), and only an http(s) base is honoured.
    """
    soup = _as_soup(body)
    if soup is None:
        return None
    try:
        tag = soup.find("base", href=True)
    except Exception:
        return None
    if tag is None:
        return None
    href = tag.get("href")
    if not isinstance(href, str) or not href.strip():
        return None
    try:
        resolved = urllib.parse.urljoin(page_url, _sanitize_url_attribute(href))
        if urllib.parse.urlsplit(resolved).scheme not in ("http", "https"):
            return None
    except ValueError:
        return None
    return _strip_userinfo(resolved)


def _sanitize_url_attribute(value: str) -> str:
    """
    Normalize a URL taken from an HTML attribute the way a browser does.

    Browsers strip leading/trailing whitespace and remove embedded TAB/CR/LF
    from URL attributes before resolving them, so that is the string whose
    resolution this module must reproduce. A NUL is not something a browser
    accepts in a URL and is removed too, so it cannot end up inside a
    persisted value.
    """
    return value.strip().translate({0x09: None, 0x0A: None, 0x0D: None, 0x00: None})


def _extract_third_party_js(
    body: Any,
    page_url: str,
    target: str,
    max_resources: int = DEFAULT_MAX_THIRD_PARTY_RESOURCES_PER_PAGE,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Implementation of extract_third_party_js_resources, plus extraction stats."""
    stats: Dict[str, Any] = {"script_src_seen": 0, "truncated": False, "internal_ip_hosts": 0,
                             "malformed_hosts": 0}
    soup = _as_soup(body)
    if soup is None:
        return [], stats
    try:
        script_tags = soup.find_all("script")
    except Exception:
        return [], stats

    base_url = extract_base_href(soup, page_url) or page_url

    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for tag in script_tags:
        raw_src = tag.get("src")
        if not isinstance(raw_src, str):
            continue
        src = _sanitize_url_attribute(raw_src)
        if not src:
            continue
        stats["script_src_seen"] += 1
        try:
            abs_url = urllib.parse.urljoin(base_url, src)
            parsed = urllib.parse.urlsplit(abs_url)
            host = (parsed.hostname or "").lower()
        except ValueError:
            continue
        if parsed.scheme not in ("http", "https"):
            continue
        if not host or _in_scope_host(host, target):
            continue  # in-scope resource, not a third party
        if len(host) > MAX_HOSTNAME_CHARS:
            # Counted, not silently dropped — but not recorded either: a
            # 100KB "hostname" from a hostile page would become a permanent
            # third_party_service asset in the shared graph.
            stats["malformed_hosts"] += 1
            continue
        abs_url = _strip_userinfo(abs_url)
        if abs_url in seen:
            continue
        if len(out) >= max_resources:
            stats["truncated"] = True
            continue
        seen.add(abs_url)
        classification = classify_third_party_host(host)
        if classification["category"] == "internal_ip_reference":
            stats["internal_ip_hosts"] += 1
        # The credential strip covers the WHOLE persisted record, not only the
        # `url` field: the evidence line quotes the raw attribute, so a
        # `<script src="https://user:secret@cdn/...">` leaked the credential
        # into pending_assets.json through the evidence even though `url` was
        # clean (CLAUDE.md rule 16).
        evidence = [
            f"<script src={_clip(_strip_userinfo(raw_src))!r}> referenced on {page_url} "
            f"resolves to external host {host!r}"
        ]
        if base_url != page_url:
            evidence.append(
                f"Resolved against the page's <base href={_clip(base_url)!r}>, not the page URL"
            )
        out.append({
            "url": _clip(abs_url, 2048),
            "host": host,
            "source_page": page_url,
            "classification": classification,
            "evidence": evidence,
        })
    return sorted(out, key=lambda r: (r["host"], r["url"])), stats


def extract_third_party_js_resources(
    body: str,
    page_url: str,
    target: str,
    max_resources: int = DEFAULT_MAX_THIRD_PARTY_RESOURCES_PER_PAGE,
) -> List[Dict[str, Any]]:
    """
    Extract `<script src>` references from already-fetched, in-scope page
    HTML that resolve to a host OUTSIDE the target's scope (responsibility
    #1). In-scope script references are crawler.py's/js_analyzer.py's
    concern, not this module's (module docstring, decision #1).

    Relative references are resolved against the page's `<base href>` when it
    has one, exactly as a browser would. The result is capped at
    `max_resources` per page — a page is attacker-influenced input and one
    response could otherwise produce an unbounded number of persisted
    findings; `analyze_page` records the fact that a cap was hit rather than
    dropping it silently.
    """
    return _extract_third_party_js(body, page_url, target, max_resources)[0]


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


def _strip_host_wildcard(host: str) -> str:
    """
    Reduce a CSP host source to the bare hostname it constrains.

    `"*.stripe.com".lstrip("*.")` happens to give the right answer, but lstrip
    strips a *character set*, so it also turns "*.*.a.com" into "a.com" and
    would eat a leading label made only of those characters. Only a literal
    leading "*." is a CSP host wildcard, so only that is removed.
    """
    if not isinstance(host, str):
        return ""
    host = host.strip().lower()
    return host[2:] if host.startswith("*.") else host


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
        try:
            candidate = urllib.parse.urlsplit(candidate).hostname or ""
        except ValueError:
            return None
    else:
        candidate = candidate.split("/", 1)[0]
        # An IPv6 source is bracketed ("[::1]:443"); splitting on the first
        # ":" turned that into the host "[" — a fabricated third-party host.
        if candidate.startswith("["):
            end = candidate.find("]")
            candidate = candidate[: end + 1] if end != -1 else candidate
        else:
            candidate = candidate.split(":", 1)[0]
    candidate = candidate.strip().rstrip(".").lower()
    if not candidate:
        return None
    # A CSP host source must actually look like a host. Without this, a
    # malformed or hostile policy value manufactured third-party "hosts" out of
    # ordinary CSP vocabulary — "script-src none" yielded the host "none",
    # "default-src frame-ancestors" yielded "frame-ancestors", and an
    # (invalid) inline data URI yielded "data". Those became third_party_service
    # ASSETS in surface_mapper.py and third_party_dependency SIGNALS in
    # risk_engine.py: fabricated supply-chain relationships from nothing.
    # A single-label intranet host source is consequently not recorded — an
    # accepted, documented trade-off, since this module's targets are public
    # domains and a bare label carries no attributable third-party identity.
    if "." not in candidate and not _is_ip_literal(candidate):
        return None
    return candidate


def parse_csp_directive_value(raw_value: str, target: str) -> Dict[str, Any]:
    """Parse one CSP directive's source list into keywords / scheme-wildcards / hostnames."""
    tokens = raw_value.split()
    keywords: List[str] = []
    scheme_wildcards: List[str] = []
    in_scope_hosts: List[str] = []
    third_party_hosts: List[str] = []
    wildcard_hosts: List[str] = []
    truncated = False
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
        if len(third_party_hosts) + len(in_scope_hosts) >= DEFAULT_MAX_CSP_HOSTS_PER_DIRECTIVE:
            truncated = True
            continue
        bare_host = _strip_host_wildcard(host)
        if host.startswith("*."):
            wildcard_hosts.append(host)
        if _in_scope_host(bare_host, target):
            in_scope_hosts.append(host)
        else:
            third_party_hosts.append(host)

    lowered_keywords = [k.lower() for k in keywords]
    # Bounded like every other collection built from response content: a header
    # can carry tens of thousands of repeated tokens, all of which would be
    # persisted verbatim. The boolean flags below are computed from the full
    # token stream, so capping the retained list changes no conclusion.
    return {
        "raw": _clip(raw_value, MAX_RAW_POLICY_CHARS),
        "keywords": keywords[:MAX_CSP_TOKENS_PER_DIRECTIVE],
        "scheme_wildcards": scheme_wildcards[:MAX_CSP_TOKENS_PER_DIRECTIVE],
        "tokens_truncated": (len(keywords) > MAX_CSP_TOKENS_PER_DIRECTIVE
                             or len(scheme_wildcards) > MAX_CSP_TOKENS_PER_DIRECTIVE),
        "in_scope_hosts": sorted(set(in_scope_hosts)),
        "third_party_hosts": sorted(set(third_party_hosts)),
        "wildcard_hosts": sorted(set(wildcard_hosts)),
        "hosts_truncated": truncated,
        "allows_unsafe_inline": "'unsafe-inline'" in keywords,
        "allows_unsafe_eval": "'unsafe-eval'" in keywords,
        "allows_broad_wildcard": "*" in scheme_wildcards or any(sw in ("https:", "http:") for sw in scheme_wildcards),
        # 'strict-dynamic' makes the host allowlist inoperative for scripts
        # loaded by an already-trusted script, so an "observed host is not in
        # the allowlist" discrepancy is expected rather than notable.
        "allows_strict_dynamic": "'strict-dynamic'" in lowered_keywords,
    }


def _parse_one_policy(raw_policy: str, target: str) -> Dict[str, Any]:
    """Parse a single CSP policy string into its directives of interest."""
    directives: Dict[str, Any] = {}
    duplicate_directives: List[str] = []
    other_directives: List[str] = []
    for clause in raw_policy.split(";"):
        clause = clause.strip()
        if not clause:
            continue
        parts = clause.split(None, 1)
        name = parts[0].strip().lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if name not in _CSP_DIRECTIVES_OF_INTEREST:
            if name:
                other_directives.append(name)
            continue
        if name in directives:
            # CSP: a directive repeated in one policy is an authoring error and
            # the FIRST occurrence governs. The later one was previously
            # allowed to overwrite it, silently reporting a policy the browser
            # does not apply. The conflict is preserved rather than dropped
            # (context.md §8 conflict preservation).
            duplicate_directives.append(name)
            continue
        directives[name] = parse_csp_directive_value(value, target)
    return {
        "raw": _clip(raw_policy, MAX_RAW_POLICY_CHARS),
        "directives": directives,
        "duplicate_directives": sorted(set(duplicate_directives)),
        "other_directives": sorted(set(other_directives)),
        "malformed": not directives and not other_directives,
    }


def split_csp_policies(csp_value: str) -> List[str]:
    """
    Split one observed header value into the individual policies it carries.

    Two things collapse several policies into one string. RFC 7230 lets a
    recipient join repeated headers with ", ", which is exactly what
    `dict(response.headers)` does; and CSP itself allows one header to carry
    comma-separated policies. Both are enforced INDEPENDENTLY by the browser
    (the effective policy is their intersection), so both must be split.

    Not splitting was a data-integrity bug, not a cosmetic one: the value
    "script-src https://a.com; default-src 'none', frame-ancestors 'none'"
    parsed as a single policy produced the third-party "hosts" "'none',"
    and "frame-ancestors" — fabricated third-party dependencies that flowed
    into the trust map, into surface_mapper.py as third_party_service assets
    and into risk_engine.py as third_party_dependency signals.
    """
    return [p.strip() for p in csp_value.split(",") if p.strip()]


def parse_csp_header(csp_value: Optional[str], target: str) -> Dict[str, Any]:
    """
    Analyze the actually-observed Content-Security-Policy header value
    (responsibility #4). Records `present: False` and stops when no header
    was returned — no policy is assumed or synthesized (module docstring,
    security boundaries).

    The returned shape is unchanged for existing consumers: `directives` is
    the effective view (the first policy to define each directive, which is
    the one that constrains it most predictably), and
    `third_party_domains_referenced` is the union across every policy carried
    by the value. `policies` is added so a consumer that cares which policy a
    directive came from can see it, and so multiple policies are preserved
    rather than mangled into one (see `split_csp_policies`).
    """
    if not isinstance(csp_value, str) or not csp_value.strip():
        # A non-string value (a list from a raw header map, None, a number)
        # is "no policy observed", not an AttributeError out of a public helper.
        return {
            "present": False, "raw_header": None, "directives": {},
            "third_party_domains_referenced": [], "policies": [], "policy_count": 0,
            "malformed": False, "duplicate_directives": [],
        }

    policies = [_parse_one_policy(p, target) for p in split_csp_policies(csp_value)]

    directives: Dict[str, Any] = {}
    all_third_party: Set[str] = set()
    duplicates: Set[str] = set()
    for policy in policies:
        duplicates.update(policy["duplicate_directives"])
        for name, parsed in policy["directives"].items():
            if name in directives:
                duplicates.add(name)
            else:
                directives[name] = parsed
            all_third_party.update(parsed["third_party_hosts"])

    return {
        "present": True,
        "raw_header": _clip(csp_value, MAX_RAW_POLICY_CHARS),
        "directives": directives,
        "third_party_domains_referenced": sorted(all_third_party),
        "policies": policies,
        "policy_count": len(policies),
        "malformed": bool(policies) and all(p["malformed"] for p in policies),
        "duplicate_directives": sorted(duplicates),
    }


_META_CSP_RE_LIMIT = 50


def extract_meta_csp_policies(body: Any) -> List[str]:
    """
    Collect `<meta http-equiv="Content-Security-Policy" content="...">` policies.

    A meta-delivered policy is a real, enforced policy (it is how a large
    number of static sites ship CSP), so ignoring it made this module report
    "No Content-Security-Policy header was observed" — and raise the
    corresponding risk implication — for pages that do have an enforced
    policy. Only the enforcing form is collected: HTML explicitly does NOT
    support `Content-Security-Policy-Report-Only` via meta, so a meta tag
    claiming report-only is not honoured by browsers and is not treated as a
    policy here either.
    """
    soup = _as_soup(body)
    if soup is None:
        return []
    try:
        metas = soup.find_all("meta", limit=_META_CSP_RE_LIMIT * 20)
    except Exception:
        return []
    out: List[str] = []
    for tag in metas:
        equiv = tag.get("http-equiv")
        if not isinstance(equiv, str) or equiv.strip().lower() != "content-security-policy":
            continue
        content = tag.get("content")
        if isinstance(content, str) and content.strip():
            out.append(content.strip())
        if len(out) >= _META_CSP_RE_LIMIT:
            break
    return out


def analyze_csp(headers: Any, body: Any, target: str) -> Dict[str, Any]:
    """
    The full CSP picture for one page (responsibility #4).

    Distinguishes what the previous single-header analysis could not, all of
    which changes what the output actually means:

      - ENFORCED vs REPORT-ONLY. `Content-Security-Policy-Report-Only` was
        ignored entirely, so a page carrying only a report-only policy was
        reported as having no CSP at all. Report-only is monitoring, NOT
        protection, so it is recorded separately and never counted as
        enforcement — but its allowlisted hosts are still real, observed
        evidence of a third-party trust relationship.
      - HEADER vs META delivery, and every policy of each, rather than the
        first one only.
      - Malformed / ambiguous policies, preserved rather than dropped.

    `present`, `raw_header`, `directives` and `third_party_domains_referenced`
    keep their existing meaning — the ENFORCED policy — so downstream
    consumers are unaffected.
    """
    enforced_values = _ci_get_all(headers, "Content-Security-Policy")
    report_only_values = _ci_get_all(headers, "Content-Security-Policy-Report-Only")
    meta_values = extract_meta_csp_policies(body)   # `body` may already be parsed

    enforced_raw = _redact_credentials(", ".join(v for v in list(enforced_values) + list(meta_values) if v))
    report_only_raw = _redact_credentials(", ".join(v for v in report_only_values if v))

    enforced = parse_csp_header(enforced_raw or None, target)
    report_only = parse_csp_header(report_only_raw or None, target)

    sources: List[Dict[str, Any]] = []
    for value in enforced_values:
        sources.append({"delivery": CSP_DELIVERY_HEADER, "disposition": CSP_DISPOSITION_ENFORCE,
                        "raw": _clip(value, MAX_RAW_POLICY_CHARS)})
    for value in meta_values:
        sources.append({"delivery": CSP_DELIVERY_META, "disposition": CSP_DISPOSITION_ENFORCE,
                        "raw": _clip(value, MAX_RAW_POLICY_CHARS)})
    for value in report_only_values:
        sources.append({"delivery": CSP_DELIVERY_HEADER, "disposition": CSP_DISPOSITION_REPORT_ONLY,
                        "raw": _clip(value, MAX_RAW_POLICY_CHARS)})

    result = dict(enforced)
    result.update({
        "enforced_present": enforced["present"],
        "report_only_present": report_only["present"],
        "report_only": report_only,
        "delivered_via_header": bool(enforced_values),
        "delivered_via_meta": bool(meta_values),
        "sources": sources,
        # Union of every observed policy, enforced or report-only: a
        # report-only allowlist is still an observed trust relationship even
        # though it grants no protection.
        "all_third_party_domains_referenced": sorted(
            set(enforced["third_party_domains_referenced"])
            | set(report_only["third_party_domains_referenced"])
        ),
    })
    return result


# ---------------------------------------------------------------------------
# 6. Subdomain-to-third-party DNS relationships
# ---------------------------------------------------------------------------

# Resolution states of an observed CNAME chain. These describe what DNS
# actually said — they are NOT takeover verdicts. Determining whether an
# unresolved delegation is claimable is surface_mapper.py's correlation
# responsibility (module docstring, decision #3) and requires evidence this
# module deliberately does not gather.
RESOLUTION_NO_CNAME = "no_cname"                      # host has no CNAME at all
RESOLUTION_TERMINUS_EXISTS = "terminus_exists"        # chain ends at a name that exists in DNS
RESOLUTION_UNRESOLVED_NXDOMAIN = "unresolved_nxdomain"  # a CNAME target does not exist (dangling)
RESOLUTION_TRUNCATED = "truncated_max_hops"           # chain longer than max_hops; endpoint unknown
RESOLUTION_CYCLE = "cycle"                            # chain loops back on itself
RESOLUTION_ERROR = "error"                            # lookup failed; nothing can be concluded


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
    if not isinstance(hostname, str) or not hostname.strip():
        return {"status": "error", "chain": [], "error": "hostname must be a non-empty string",
                "resolution_status": RESOLUTION_ERROR, "conflicting_cname_targets": []}

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    chain: List[str] = []
    conflicts: List[Dict[str, Any]] = []
    current = hostname.strip().rstrip(".")
    seen: Set[str] = {_idna_normalize(current)}
    resolution_status = RESOLUTION_NO_CNAME
    error: Optional[str] = None
    try:
        for hop in range(max_hops):
            try:
                answer = resolver.resolve(current, "CNAME")
            except dns.resolver.NoAnswer:
                # The name EXISTS in DNS but holds no CNAME: either the queried
                # hostname is A/AAAA-only (no delegation) or we have reached the
                # end of a real chain. Existence is itself evidence — it is what
                # separates a live delegation from a dangling one — and it comes
                # free with the query already being made.
                resolution_status = RESOLUTION_TERMINUS_EXISTS if chain else RESOLUTION_NO_CNAME
                break
            except dns.resolver.NXDOMAIN:
                if not chain:
                    # The queried subdomain itself does not exist. That is an
                    # absent asset, not a supply-chain observation.
                    return {"status": "error", "chain": chain,
                            "error": f"NXDOMAIN resolving {current!r}",
                            "resolution_status": RESOLUTION_ERROR,
                            "conflicting_cname_targets": conflicts}
                # A CNAME TARGET that does not exist: the delegation is real and
                # observed, the destination is not. This is the single most
                # important DNS observation this module can make, and it was
                # previously discarded as a generic "dns lookup failed" —
                # destroying the third-party relationship AND the CNAME chain
                # that surface_mapper.py's dangling-CNAME/takeover correlation
                # consumes. Recorded here as an OBSERVATION ONLY: an unresolved
                # CNAME is NOT a confirmed takeover and this module makes no
                # claimability determination (module docstring, decision #3).
                resolution_status = RESOLUTION_UNRESOLVED_NXDOMAIN
                error = f"NXDOMAIN resolving CNAME target {current!r}"
                break

            targets = sorted({str(rd.target).rstrip(".") for rd in answer})
            if len(targets) > 1:
                # Multiple CNAMEs for one name is invalid DNS; preserving the
                # conflict beats silently picking answer[0] (context.md §8).
                conflicts.append({"name": current, "targets": targets})
            target_host = targets[0]
            chain.append(target_host)
            if _idna_normalize(target_host) in seen:
                resolution_status = RESOLUTION_CYCLE
                error = f"CNAME cycle detected at {target_host!r}"
                break
            seen.add(_idna_normalize(target_host))
            current = target_host
        else:
            # Loop exhausted without terminating: the chain is TRUNCATED, so
            # its last element is not the real endpoint. Reporting this as a
            # completed chain made the truncation point look like the
            # delegation target.
            resolution_status = RESOLUTION_TRUNCATED
            error = f"CNAME chain exceeded max_hops ({max_hops}); chain is truncated"

        return {"status": "found" if chain else "none", "chain": chain, "error": error,
                "resolution_status": resolution_status, "conflicting_cname_targets": conflicts}
    except dns.exception.Timeout as exc:
        return {"status": "error", "chain": chain, "error": f"timeout: {exc}",
                "resolution_status": RESOLUTION_ERROR, "conflicting_cname_targets": conflicts}
    except Exception as exc:  # never let one hostname's DNS failure kill the whole run
        return {"status": "error", "chain": chain, "error": str(exc),
                "resolution_status": RESOLUTION_ERROR, "conflicting_cname_targets": conflicts}


def map_subdomain_third_party_dns(subdomain: str, target: str, timeout: float = DEFAULT_DNS_TIMEOUT) -> Dict[str, Any]:
    """
    Resolve `subdomain`'s CNAME chain and determine whether it is
    DNS-delegated to a third party (responsibility #6). This module
    records the observed delegation only — it does NOT assess whether a
    dangling/unclaimed CNAME target implies a takeover risk; that
    correlation belongs to surface_mapper.py (module docstring, decision #3).
    """
    dns_result = resolve_cname_chain(subdomain, timeout=timeout)
    chain = dns_result["chain"]
    resolution_status = dns_result.get("resolution_status", RESOLUTION_ERROR)
    result: Dict[str, Any] = {
        "subdomain": subdomain, "status": dns_result["status"], "chain": chain,
        "error": dns_result["error"], "third_party": None,
        "resolution_status": resolution_status,
        "delegation_target": None,
        "final_target": chain[-1] if chain else None,
        "conflicting_cname_targets": dns_result.get("conflicting_cname_targets", []),
    }
    if not chain:
        return result

    # ATTRIBUTION: the delegation is to the FIRST hop that leaves the target's
    # scope, not to wherever that provider's own chain happens to end. Using
    # chain[-1] misattributed every provider that fronts itself with a CDN:
    # "support.example.com -> example.zendesk.com -> zendesk.map.fastly.net"
    # was reported as a Fastly *cdn* dependency, when the relationship the
    # target actually has is with Zendesk (support_chat). The full chain is
    # still preserved for consumers that correlate on the endpoint.
    delegation_target = next((h for h in chain if not _in_scope_host(h, target)), None)
    if delegation_target is None:
        return result   # chain never leaves the target's own scope

    result["delegation_target"] = delegation_target
    classification = classify_third_party_host(delegation_target)
    classification = dict(classification)
    classification["resolution_status"] = resolution_status
    # A truncated chain's endpoint is unknown, but the first out-of-scope hop
    # was still directly observed, so the delegation itself stands.
    result["third_party"] = classification
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
    assets: Dict[str, Set[str]] = {}
    services: Dict[str, Dict[str, Any]] = {}

    def _touch_service(host: str, classification: Dict[str, Any]) -> Dict[str, Any]:
        entry = services.get(host)
        if entry is None:
            entry = services[host] = {
                "host": host, "vendor": classification.get("vendor"),
                "category": classification.get("category"),
                "category_source": classification.get("category_source"),
                "shared_infrastructure": bool(classification.get("shared_infrastructure")),
                "referenced_by": set(), "relationship_types": set(),
                "observed_directly": False, "wildcard_only": True,
                "conflicting_classifications": [],
            }
        elif (entry["category"], entry["vendor"]) != (classification.get("category"), classification.get("vendor")):
            # Two sources disagreeing about the same host is exactly the kind of
            # contradiction context.md §8 says to preserve, not to silently
            # resolve in favour of whichever arrived first.
            conflict = {"category": classification.get("category"), "vendor": classification.get("vendor"),
                        "category_source": classification.get("category_source")}
            if conflict not in entry["conflicting_classifications"]:
                entry["conflicting_classifications"].append(conflict)
        return entry

    def _link(asset: str, host: str, relationship_type: str, classification: Dict[str, Any],
              observed_directly: bool = True, wildcard: bool = False) -> None:
        # Sets, not lists: the membership scans this used to do were quadratic
        # in the number of hosts on one page, which a hostile page controls.
        assets.setdefault(asset, set()).add(host)
        entry = _touch_service(host, classification)
        entry["referenced_by"].add(asset)
        entry["relationship_types"].add(relationship_type)
        if observed_directly:
            entry["observed_directly"] = True
        if not wildcard:
            entry["wildcard_only"] = False

    for res in (js_resources if isinstance(js_resources, (list, tuple)) else ()):
        if not isinstance(res, dict):
            continue
        source_page, host = res.get("source_page"), res.get("host")
        if not source_page or not host:
            continue
        _link(source_page, host, "script_reference",
              res.get("classification") if isinstance(res.get("classification"), dict) else {})

    for page_url, csp in (csp_by_page if isinstance(csp_by_page, dict) else {}).items():
        if not isinstance(csp, dict):
            continue
        # An allowlist entry is a DECLARED permission, not an observed load: the
        # page may never request the host at all. It is still real, observed
        # evidence of an intended trust relationship, which is why it belongs in
        # the map — but it is marked so a consumer can tell the two apart.
        for disposition, policy in (
            (CSP_DISPOSITION_ENFORCE, csp),
            (CSP_DISPOSITION_REPORT_ONLY, csp.get("report_only") or {}),
        ):
            if not isinstance(policy, dict) or not policy.get("present"):
                continue
            prefix = "csp_allowlist" if disposition == CSP_DISPOSITION_ENFORCE else "csp_report_only_allowlist"
            directives_map = policy.get("directives")
            if not isinstance(directives_map, dict):
                continue
            for directive_name, directive in directives_map.items():
                if not isinstance(directive, dict):
                    continue
                for host in directive.get("third_party_hosts") or ():
                    bare_host = _strip_host_wildcard(host)
                    if not bare_host:
                        continue
                    is_wildcard = host.startswith("*.")
                    _link(page_url, bare_host, f"{prefix}:{directive_name}",
                          classify_third_party_host(host),
                          observed_directly=False, wildcard=is_wildcard)

    for rel in (dns_relationships if isinstance(dns_relationships, (list, tuple)) else ()):
        if not isinstance(rel, dict) or not isinstance(rel.get("third_party"), dict):
            continue
        classification = rel["third_party"]
        host = classification.get("host")
        subdomain = rel.get("subdomain")
        if not host or not subdomain:
            continue   # a relationship with no owning asset is not a relationship
        _link(subdomain, host, "dns_cname", classification)

    for entry in services.values():
        entry["relationship_types"] = sorted(entry["relationship_types"])
        entry["referenced_by"] = sorted(entry["referenced_by"])
        # A host known ONLY through a wildcard CSP source ("*.amazonaws.com")
        # is not a confirmed dependency on a specific service — it is a broad
        # allowance covering every tenant of that provider.
        entry["attribution"] = (
            "observed_reference" if entry["observed_directly"]
            else ("inferred_from_wildcard_allowlist" if entry["wildcard_only"] else "declared_allowlist_entry")
        )

    return {
        "assets": {asset: sorted(hosts) for asset, hosts in assets.items()},
        "external_services": services,
        "asset_count": len(assets),
        "external_service_count": len(services),
    }


def build_category_inventory(trust_map: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Group the trust map's external services by category (responsibilities #2/#3/#7)."""
    inventory: Dict[str, List[Dict[str, Any]]] = {}
    if not isinstance(trust_map, dict):
        return inventory
    services = trust_map.get("external_services")
    if not isinstance(services, dict):
        return inventory
    for host, entry in services.items():
        if not isinstance(entry, dict):
            continue
        category = entry.get("category") or "unknown_third_party"
        inventory.setdefault(category, []).append({
            "host": host, "vendor": entry.get("vendor"), "category_source": entry.get("category_source"),
            "referenced_by": entry.get("referenced_by", []),
            "shared_infrastructure": bool(entry.get("shared_infrastructure")),
            "attribution": entry.get("attribution"),
        })
    for services in inventory.values():
        services.sort(key=lambda s: s["host"])
    return inventory


# ---------------------------------------------------------------------------
# 8. Risk assessment of third-party relationships
# ---------------------------------------------------------------------------

# Ordered, not a set: iterating a frozenset gave a non-deterministic order for
# the emitted implications, so two runs over identical evidence produced
# different output orderings (and different pending_assets.json diffs).
_HIGH_TRUST_CATEGORIES: Tuple[str, ...] = ("auth", "payment")


def _as_directive_map(csp: Any) -> Dict[str, Dict[str, Any]]:
    """The directive map of a CSP analysis, tolerating a malformed caller value."""
    if not isinstance(csp, dict):
        return {}
    directives = csp.get("directives")
    if not isinstance(directives, dict):
        return {}
    return {name: d for name, d in directives.items() if isinstance(d, dict)}


def assess_csp_risk_implications(page_url: str, csp: Dict[str, Any], observed_third_party_hosts: Set[str]) -> List[Dict[str, Any]]:
    """
    Derive security/trust IMPLICATIONS (never confirmed vulnerabilities)
    from one page's observed CSP configuration (responsibility #8).
    """
    implications: List[Dict[str, Any]] = []
    observed_third_party_hosts = {
        h for h in (observed_third_party_hosts
                    if isinstance(observed_third_party_hosts, (set, frozenset, list, tuple)) else ())
        if isinstance(h, str) and h
    }

    if not isinstance(csp, dict):
        csp = {}
    if not csp.get("present"):
        if csp.get("report_only_present"):
            # Monitoring is not protection. Saying "no CSP observed" here would
            # have been false; saying the page is protected would be worse.
            implications.append({
                "risk_type": "csp_report_only_not_enforced",
                "description": (
                    f"{page_url} returned only a Content-Security-Policy-Report-Only policy. A "
                    "report-only policy is evaluated and reported by the browser but NOT enforced, "
                    "so it restricts nothing; violations are logged rather than blocked."
                ),
                "related_hosts": sorted(
                    (csp.get("report_only") or {}).get("third_party_domains_referenced", []) or []),
                "confidence": CONFIDENCE_MEDIUM,
                "evidence": [
                    f"Content-Security-Policy-Report-Only observed on {page_url}, with no enforcing "
                    f"Content-Security-Policy header or meta policy",
                    "This is an inferred configuration/trust-exposure implication, not a confirmed vulnerability.",
                ],
            })
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

    for directive_name, directive in (_as_directive_map(csp)).items():
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

    directives = _as_directive_map(csp)
    # CSP's own fallback chain for *element*-initiated script loads, which is
    # what a `<script src>` is: script-src-elem, else script-src, else
    # default-src. Only script-src/default-src were consulted, so a policy that
    # allowlists its CDN in script-src-elem (with `default-src 'none'`) had
    # every one of its scripts reported as "not in the CSP allowlist".
    script_directive = None
    script_directive_name = None
    for name in ("script-src-elem", "script-src", "default-src"):
        if directives.get(name) is not None:
            script_directive, script_directive_name = directives[name], name
            break

    if script_directive is not None:
        allowlisted = set(script_directive.get("third_party_hosts", []))
        # A source may be exact ("js.stripe.com") or a wildcard ("*.stripe.com").
        # Comparing observed hosts against wildcards stripped to their bare
        # domain reported `js.stripe.com` as un-allowlisted under
        # `script-src *.stripe.com`, which the browser does allow.
        suppressed_reason = None
        if script_directive.get("allows_strict_dynamic"):
            suppressed_reason = ("the policy uses 'strict-dynamic', under which the host allowlist "
                                 "does not govern scripts loaded by an already-trusted script")
        elif script_directive.get("allows_broad_wildcard"):
            suppressed_reason = ("the policy already permits a broad scheme/host wildcard for this "
                                 "directive, so every observed host is within the allowlist")
        not_allowlisted = (
            set() if suppressed_reason
            else {h for h in observed_third_party_hosts if not _csp_source_allows_host(h, allowlisted)}
        )
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
                    f"CSP {script_directive_name} allowlisted third-party hosts: {sorted(allowlisted)}",
                    "This is an inferred discrepancy, not a confirmed CSP bypass or vulnerability.",
                ],
            })

    return implications


def _csp_source_allows_host(host: str, sources: Set[str]) -> bool:
    """
    Does any CSP host source in `sources` cover `host`?

    Exact match, or a "*.example.com" wildcard covering any subdomain of
    example.com (CSP's wildcard matches one-or-more leading labels, and does
    not match the bare domain itself).
    """
    host = _idna_normalize(host)
    if not host:
        return False
    for source in sources:
        source = (source or "").strip().lower()
        if source.startswith("*."):
            suffix = _idna_normalize(source[2:])
            if suffix and host.endswith("." + suffix):
                return True
        elif _idna_normalize(source) == host:
            return True
    return False


def assess_aggregate_risk_implications(trust_map: Dict[str, Any], category_inventory: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Derive run-level (cross-page/cross-asset) security/trust implications
    from the fully-built trust map (responsibility #8).
    """
    implications: List[Dict[str, Any]] = []
    if not isinstance(trust_map, dict):
        trust_map = {}
    if not isinstance(category_inventory, dict):
        category_inventory = {}

    services_map = trust_map.get("external_services")
    if not isinstance(services_map, dict):
        services_map = {}
    # An internal-address reference fails the domain-suffix scope test but is
    # not a third-party supplier, so it must not inflate the third-party
    # surface count.
    # A wildcard CSP allowance ("*.stripe.com") is a broad permission covering
    # every tenant of a provider, not an observed dependency on a distinct
    # service — counting it alongside the concrete host actually loaded
    # ("js.stripe.com") double-counted one relationship as two.
    third_party_hosts = sorted(
        host for host, entry in services_map.items()
        if (entry or {}).get("category") != "internal_ip_reference"
        and (entry or {}).get("attribution") != "inferred_from_wildcard_allowlist"
    )
    service_count = len(third_party_hosts) if services_map else trust_map.get("external_service_count", 0)
    if service_count >= 5:
        implications.append({
            "risk_type": "broad_third_party_surface",
            "description": (
                f"{service_count} distinct third-party services/origins were observed across the "
                "assessed assets. Each represents an additional trust dependency and a potential "
                "supply-chain compromise vector (a compromised or malicious third-party resource "
                "would execute in the target's origin context)."
            ),
            "related_hosts": third_party_hosts,
            "confidence": CONFIDENCE_LOW,
            "evidence": [
                f"{service_count} distinct external service(s) recorded in the third-party trust map "
                f"(wildcard-only CSP allowances and internal-address references excluded)",
                "This is an inferred exposure-surface observation, not a confirmed vulnerability.",
            ],
        })

    for category in _HIGH_TRUST_CATEGORIES:
        services = [
            s for s in (category_inventory.get(category) or [])
            if isinstance(s, dict) and s.get("attribution") != "inferred_from_wildcard_allowlist"
        ]
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

def analyze_page(
    body: str,
    headers: Dict[str, str],
    page_url: str,
    target: str,
    max_resources: int = DEFAULT_MAX_THIRD_PARTY_RESOURCES_PER_PAGE,
) -> Dict[str, Any]:
    """Run every per-page Module 14 responsibility against one already-fetched page."""
    soup = _parse_html(body)
    js_resources, stats = _extract_third_party_js(soup, page_url, target, max_resources)
    csp = analyze_csp(headers, soup, target)
    # An internal-address reference is not a supply-chain third party, so it
    # must not drive the "third-party scripts without a CSP" implication.
    observed_hosts = {
        r["host"] for r in js_resources
        if r["classification"].get("category") != "internal_ip_reference"
    }
    risk_implications = assess_csp_risk_implications(page_url, csp, observed_hosts)
    return {
        "page_url": page_url, "js_resources": js_resources, "csp": csp,
        "risk_implications": risk_implications, "extraction_stats": stats,
    }


def persist_page_findings(
    analysis: Dict[str, Any],
    target: str,
    store: Optional["PendingAssetsStore"],
    seen_category_hosts: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """
    Persist every finding produced by `analyze_page` for one page.

    `seen_category_hosts`, when supplied by a multi-page caller, carries the
    hosts already categorized earlier in the same run. A service's CATEGORY is
    a property of the host, not of the page that referenced it, so re-emitting
    it per page wrote one identical record per page (20 pages referencing
    Stripe produced 20 byte-identical category findings). Repetition of the
    same signal is not corroboration and must not read as such (context.md §8);
    the per-page *reference* findings still record every page that referenced
    the host, which is the part that genuinely differs.
    """
    errors: List[str] = []
    counts: Dict[str, int] = {}
    page_url = analysis["page_url"]
    batch: List[Dict[str, Any]] = []

    def _add(finding_type: str, value: Any, evidence: List[str], confidence: str,
              discovery_source: str, extra_metadata: Optional[Dict[str, Any]] = None) -> None:
        # Queued, then committed as ONE atomic write below. Per-finding writes
        # rewrote the whole shared pending_assets.json each time, which is
        # quadratic in what is already on disk (see PendingAssetsStore.add_many).
        batch.append(make_supply_chain_finding(
            finding_type, target, value, evidence, confidence,
            source_asset=page_url, discovery_source=discovery_source, extra_metadata=extra_metadata,
        ))

    js_resources = analysis["js_resources"]
    counts["third_party_js_resources"] = len(js_resources)
    counts["internal_ip_references"] = 0
    seen_hosts: Set[str] = seen_category_hosts if seen_category_hosts is not None else set()
    for res in js_resources:
        cls = res["classification"]
        if cls.get("category") == "internal_ip_reference":
            # A `<script src="http://169.254.169.254/...">` on the target's page
            # is an INTERNAL reference that merely fails the domain-suffix scope
            # test. Persisting it as supply_chain_third_party_js_resource made
            # surface_mapper.py mint a third_party_service ASSET for a cloud
            # metadata endpoint and risk_engine.py raise a
            # third_party_dependency signal for it — a supply-chain
            # relationship that does not exist. It is still recorded (it is a
            # real, notable observation), under a type that says what it is.
            counts["internal_ip_references"] += 1
            counts["third_party_js_resources"] -= 1
            _add("supply_chain_internal_ip_reference",
                 {"url": res["url"], "host": res["host"], "classification": cls},
                 res["evidence"] + [
                     "The referenced host is a private/loopback/reserved IP address, so this is an "
                     "internal reference rather than a third-party supply-chain dependency. It was "
                     "never fetched."
                 ], CONFIDENCE_HIGH, "script_tag")
            continue
        _add("supply_chain_third_party_js_resource",
             {"url": res["url"], "host": res["host"], "classification": res["classification"]},
             res["evidence"], CONFIDENCE_HIGH, "script_tag")
        if res["host"] not in seen_hosts and cls["category_source"] not in ("unmatched", "ip_literal"):
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
    if csp["present"]:
        delivery = []
        if csp.get("delivered_via_header"):
            delivery.append("response header")
        if csp.get("delivered_via_meta"):
            delivery.append("<meta http-equiv>")
        csp_evidence = [
            f"Enforced Content-Security-Policy observed on {page_url} "
            f"via {' and '.join(delivery) or 'response header'}: {csp['raw_header']!r}"
        ]
    else:
        csp_evidence = [f"No enforced Content-Security-Policy observed on {page_url}"]
    if csp.get("report_only_present"):
        # Monitoring, not protection — stated as such so neither this module
        # nor a downstream consumer can read it as enforcement.
        csp_evidence.append(
            f"Content-Security-Policy-Report-Only observed on {page_url} "
            f"(reported, NOT enforced): {(csp.get('report_only') or {}).get('raw_header')!r}"
        )
    _add("supply_chain_csp_analysis", csp, csp_evidence, CONFIDENCE_HIGH, "csp_header")

    risk_implications = analysis["risk_implications"]
    counts["risk_implications"] = len(risk_implications)
    for risk in risk_implications:
        _add("supply_chain_risk_implication",
             {"risk_type": risk["risk_type"], "description": risk["description"], "related_hosts": risk["related_hosts"]},
             risk["evidence"], risk["confidence"], "aggregate_analysis")

    stats = analysis.get("extraction_stats") or {}
    if stats.get("malformed_hosts"):
        _add("supply_chain_page_malformed_references",
             {"url": page_url, "malformed_hosts": stats["malformed_hosts"]},
             [f"{stats['malformed_hosts']} <script src> reference(s) on {page_url} resolved to a "
              f"hostname longer than the {MAX_HOSTNAME_CHARS}-character DNS limit and were not "
              f"recorded as third-party services"],
             CONFIDENCE_LOW, "script_tag")
    if stats.get("truncated"):
        # Never silently dropped: the cap itself is a recorded observation, so a
        # consumer can tell "this page had 500 third-party hosts" from "this
        # page had more than we were willing to persist".
        _add("supply_chain_page_resources_truncated",
             {"url": page_url, "script_src_seen": stats.get("script_src_seen"),
              "recorded": len(js_resources)},
             [f"{page_url} referenced more third-party script hosts than the per-page cap "
              f"({len(js_resources)} recorded of {stats.get('script_src_seen')} <script src> seen); "
              f"the inventory for this page is incomplete"],
             CONFIDENCE_MEDIUM, "script_tag")

    total = (counts["third_party_js_resources"] + counts["internal_ip_references"]
             + counts["risk_implications"])
    if total == 0 and not csp["present"] and not csp.get("report_only_present"):
        _add("supply_chain_checked_no_findings", {"url": page_url},
             [f"No externally-hosted JS resources, CSP header, or risk implications observed on {page_url}"],
             CONFIDENCE_LOW, "aggregate_analysis")

    err = _safe_store_add_many(store, batch)
    if err:
        errors.append(err)
    return {"counts": counts, "errors": errors}


# ---------------------------------------------------------------------------
# Input normalization (mirrors js_analyzer.py's _normalize_js_reference)
# ---------------------------------------------------------------------------

def _dedupe_preserving_order(values: Iterable[Any]) -> Tuple[List[str], int]:
    """
    Drop repeats from a caller-supplied reference list, keeping first order.

    The orchestrator builds this module's page list by concatenating base URLs,
    crawled pages and discovered endpoints, so the same URL genuinely arrives
    several times. Each repeat was a full extra HTTP fetch (and an extra copy
    of every finding it produced); 50 identical URLs meant 50 requests against
    the target. Returns (unique values, number of duplicates dropped).
    """
    seen: Set[str] = set()
    out: List[str] = []
    duplicates = 0
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        key = value.strip()
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        out.append(key)
    return out, duplicates


def _as_reference_string(value: Any) -> Optional[str]:
    """A reference is only usable if it is actually a non-empty string."""
    return value if isinstance(value, str) and value.strip() else None


def _normalize_page_reference(item: Any) -> Optional[str]:
    if isinstance(item, str):
        return _as_reference_string(item)
    if isinstance(item, dict):
        value = item.get("value")
        if isinstance(value, dict) and value.get("url"):
            return _as_reference_string(value.get("url"))
        return _as_reference_string(item.get("url"))
    return None


def _normalize_subdomain_reference(item: Any) -> Optional[str]:
    if isinstance(item, str):
        return _as_reference_string(item)
    if isinstance(item, dict):
        value = item.get("value")
        if isinstance(value, dict):
            for key in ("hostname", "subdomain", "name"):
                if _as_reference_string(value.get(key)):
                    return _as_reference_string(value[key])
        for key in ("hostname", "subdomain", "name"):
            if _as_reference_string(item.get(key)):
                return _as_reference_string(item[key])
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
    max_resources_per_page: int = DEFAULT_MAX_THIRD_PARTY_RESOURCES_PER_PAGE,
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
        "pages_skipped_duplicate": 0, "pages_skipped_duplicate_final_url": 0,
        "subdomains_requested": 0, "subdomains_analyzed": 0, "subdomains_skipped_out_of_scope": 0,
        "subdomains_dns_failed": 0, "subdomains_skipped_duplicate": 0,
        "page_results": [], "subdomain_results": [], "errors": [],
    }

    def _record(err: Optional[str]) -> None:
        """Persistence failures are recorded, never silently discarded (CLAUDE.md rule 8)."""
        if err:
            summary["errors"].append(err)

    page_refs, dup_pages = _dedupe_preserving_order(
        _normalize_page_reference(p) for p in (pages or []))
    summary["pages_skipped_duplicate"] = dup_pages
    if max_pages is not None:
        page_refs = page_refs[:max_pages]
    summary["pages_requested"] = len(page_refs)

    all_js_resources: List[Dict[str, Any]] = []
    csp_by_page: Dict[str, Dict[str, Any]] = {}
    analyzed_final_urls: Set[str] = set()
    seen_category_hosts: Set[str] = set()

    for url in page_refs:
        safe_url = _clip(url, 2048)
        page_result: Dict[str, Any] = {"url": safe_url, "status": None}
        try:
            validated_url = validate_url_target(url, target=target)
        except ScopeError as exc:
            summary["pages_skipped_out_of_scope"] += 1
            reason = _clip(str(exc), 1024)
            page_result["status"] = "skipped_out_of_scope"
            page_result["error"] = reason
            _record(_safe_store_add(store, make_supply_chain_finding(
                "supply_chain_page_skipped_out_of_scope", target,
                {"url": safe_url, "reason": reason},
                [f"Page {safe_url!r} was not analyzed: {reason}"], CONFIDENCE_LOW,
                source_asset=safe_url, discovery_source="aggregate_analysis",
            )))
            summary["page_results"].append(page_result)
            continue

        fetch_result = fetch_page(validated_url, target=target, timeout=timeout, max_body_bytes=max_body_bytes,
                                    max_redirect_hops=max_redirect_hops)
        if fetch_result["status"] != "found":
            summary["pages_failed"] += 1
            page_result["status"] = "fetch_failed"
            page_result["error"] = _clip(fetch_result.get("error"), 1024)
            _record(_safe_store_add(store, make_supply_chain_finding(
                "supply_chain_page_fetch_failed", target,
                {"url": validated_url, "error": _clip(fetch_result.get("error"), 1024),
                 "hops": fetch_result.get("hops", [])},
                [f"Failed to fetch page {validated_url}: {_clip(fetch_result.get('error'), 1024)}"],
                CONFIDENCE_LOW,
                source_asset=validated_url, discovery_source="aggregate_analysis",
            )))
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

        if final_url in analyzed_final_urls:
            # Distinct input URLs commonly redirect to one canonical page
            # ("/" and "/index.html"), and analysing it twice persisted a
            # duplicate copy of every finding — duplicate assets and inflated
            # relationship counts downstream (context.md §7: independent
            # discoveries of the same asset are merged, not duplicated).
            summary["pages_skipped_duplicate_final_url"] += 1
            page_result["status"] = "skipped_duplicate_final_url"
            page_result["final_url"] = final_url
            summary["page_results"].append(page_result)
            continue
        analyzed_final_urls.add(final_url)

        analysis = analyze_page(body, headers, final_url, target, max_resources=max_resources_per_page)
        persisted = persist_page_findings(analysis, target, store, seen_category_hosts=seen_category_hosts)

        all_js_resources.extend(analysis["js_resources"])
        csp_by_page[final_url] = analysis["csp"]

        page_result["status"] = "analyzed"
        page_result["final_url"] = final_url
        page_result["counts"] = persisted["counts"]
        summary["pages_analyzed"] += 1
        summary["errors"].extend(persisted["errors"])
        summary["page_results"].append(page_result)

    sub_refs, dup_subs = _dedupe_preserving_order(
        _normalize_subdomain_reference(s) for s in (subdomains or []))
    summary["subdomains_skipped_duplicate"] = dup_subs
    if max_subdomains is not None:
        sub_refs = sub_refs[:max_subdomains]
    summary["subdomains_requested"] = len(sub_refs)

    dns_relationships: List[Dict[str, Any]] = []
    for hostname in sub_refs:
        safe_host = _clip(hostname, 512)
        sub_result: Dict[str, Any] = {"subdomain": safe_host, "status": None}
        try:
            validated_host = validate_hostname_target(hostname, target)
        except ScopeError as exc:
            summary["subdomains_skipped_out_of_scope"] += 1
            reason = _clip(str(exc), 1024)
            sub_result["status"] = "skipped_out_of_scope"
            sub_result["error"] = reason
            _record(_safe_store_add(store, make_supply_chain_finding(
                "supply_chain_subdomain_skipped_out_of_scope", target,
                {"hostname": safe_host, "reason": reason},
                [f"Hostname {safe_host!r} was not resolved: {reason}"], CONFIDENCE_LOW,
                source_asset=safe_host, discovery_source="dns_cname",
            )))
            summary["subdomain_results"].append(sub_result)
            continue

        dns_map = map_subdomain_third_party_dns(validated_host, target, timeout=dns_timeout)
        sub_result.update(dns_map)

        if dns_map["status"] == "error":
            # A failed lookup is NOT "checked, no third party". It is recorded
            # as a failure and the subdomain is NOT counted as analyzed — it
            # previously incremented BOTH counters and reported status
            # "analyzed", so an unreachable resolver looked like a completed,
            # negative check to every downstream consumer.
            summary["subdomains_dns_failed"] += 1
            sub_result["status"] = "dns_lookup_failed"
            _record(_safe_store_add(store, make_supply_chain_finding(
                "supply_chain_dns_lookup_failed", target,
                {"subdomain": validated_host, "error": dns_map["error"]},
                [f"DNS CNAME lookup for {validated_host} failed: {dns_map['error']}",
                 "This is a lookup FAILURE, not evidence that the hostname has no third-party "
                 "DNS delegation — nothing can be concluded about this hostname from it."],
                CONFIDENCE_LOW, source_asset=validated_host, discovery_source="dns_cname",
            )))
            summary["subdomain_results"].append(sub_result)
            continue

        if dns_map["third_party"]:
            dns_relationships.append(dns_map)
            classification = dns_map["third_party"]
            resolution_status = dns_map.get("resolution_status")
            basis_note = (
                f"Category {classification['category']!r} matched against known-vendor domain catalog entry"
                if classification["category_source"] == "catalog_match" else
                f"Category {classification['category']!r} is an unconfirmed heuristic inference, not a "
                "known-vendor catalog match"
            )
            evidence = [
                f"{validated_host} is CNAME-delegated to external host "
                f"{dns_map['delegation_target']!r} (full observed chain: {dns_map['chain']})",
                basis_note,
            ]
            if classification.get("shared_infrastructure"):
                evidence.append(
                    f"{classification.get('matched_domain')!r} is multi-tenant shared infrastructure: this "
                    "identifies the PROVIDER, not the owner of the specific resource, and is not evidence "
                    "that the target owns or exclusively controls it."
                )
            confidence = CONFIDENCE_HIGH
            if resolution_status == RESOLUTION_UNRESOLVED_NXDOMAIN:
                evidence.append(
                    f"The CNAME chain does not fully resolve: {dns_map['error']}. The delegation itself was "
                    "directly observed, but its destination does not exist in DNS (a dangling delegation). "
                    "This is an OBSERVATION ONLY — it is NOT a confirmed subdomain takeover, NOT evidence "
                    "that the name is claimable, and no claim/registration attempt was made. Correlating "
                    "this into a takeover indicator is surface_mapper.py's responsibility."
                )
            elif resolution_status == RESOLUTION_TRUNCATED:
                confidence = CONFIDENCE_MEDIUM
                evidence.append(
                    f"The CNAME chain was truncated at the hop limit ({dns_map['error']}), so its final "
                    "endpoint is unknown; only the first out-of-scope delegation is asserted."
                )
            elif resolution_status == RESOLUTION_CYCLE:
                confidence = CONFIDENCE_MEDIUM
                evidence.append(f"The CNAME chain loops: {dns_map['error']}.")
            if dns_map.get("conflicting_cname_targets"):
                evidence.append(
                    f"Conflicting DNS answers preserved (multiple CNAME targets for one name): "
                    f"{dns_map['conflicting_cname_targets']}"
                )
            _record(_safe_store_add(store, make_supply_chain_finding(
                "supply_chain_subdomain_third_party_dns", target,
                {"subdomain": validated_host, "cname_chain": dns_map["chain"],
                 "delegation_target": dns_map["delegation_target"],
                 "final_target": dns_map["final_target"],
                 "resolution_status": resolution_status,
                 "resolves": resolution_status in (RESOLUTION_TERMINUS_EXISTS, RESOLUTION_NO_CNAME),
                 "third_party": classification},
                evidence, confidence, source_asset=validated_host, discovery_source="dns_cname",
            )))
        else:
            _record(_safe_store_add(store, make_supply_chain_finding(
                "supply_chain_dns_checked_no_third_party", target,
                {"subdomain": validated_host, "cname_chain": dns_map["chain"],
                 "resolution_status": dns_map.get("resolution_status")},
                [f"CNAME chain for {validated_host} (if any) does not resolve outside {target!r}'s scope: "
                 f"{dns_map['chain']}"],
                CONFIDENCE_LOW, source_asset=validated_host, discovery_source="dns_cname",
            )))

        sub_result["status"] = "analyzed"
        summary["subdomains_analyzed"] += 1
        summary["subdomain_results"].append(sub_result)

    trust_map = build_trust_map(all_js_resources, csp_by_page, dns_relationships)
    category_inventory = build_category_inventory(trust_map)
    aggregate_risks = assess_aggregate_risk_implications(trust_map, category_inventory)

    if trust_map["external_service_count"] > 0:
        _record(_safe_store_add(store, make_supply_chain_finding(
            "supply_chain_trust_map", target,
            {"trust_map": trust_map, "category_inventory": category_inventory},
            [f"Third-party trust map correlated from {len(all_js_resources)} script reference(s), "
             f"{len(csp_by_page)} page CSP observation(s), and {len(dns_relationships)} DNS CNAME relationship(s)"],
            CONFIDENCE_MEDIUM, source_asset=target, discovery_source="aggregate_analysis",
        )))

    _record(_safe_store_add_many(store, [
        make_supply_chain_finding(
            "supply_chain_risk_implication", target,
            {"risk_type": risk["risk_type"], "description": risk["description"],
             "related_hosts": risk["related_hosts"]},
            risk["evidence"], risk["confidence"], source_asset=target,
            discovery_source="aggregate_analysis",
        )
        for risk in aggregate_risks
    ]))

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
