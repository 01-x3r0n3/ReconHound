"""
reconhound/risk_engine.py — ReconHound Module 20 (risk_engine.py).

Phase: Intelligence. See context.md §10 (module 20) for the authoritative
responsibilities, §9 for the relationship-based prioritization rule, and §8
for the evidence/confidence/conflict model this module consumes. This file
documents implementation-specific detail only, never the architecture itself.

context.md's exact line for this module:

  "Relationship-based prioritization. Scores CRITICAL/HIGH/MEDIUM/LOW/INFO,
  consumes the asset graph + relationships (not isolated findings),
  cross-module correlation (e.g. 6 converging signals on one asset,
  deprecated API + leaked cred in code_leak, missing HSTS + self-signed cert
  + outdated TLS -> combined higher severity). Produces prioritized
  investigation queue with explanation per score. [...] Severity is a
  prioritization assessment, not proof of exploitability."

And context.md §9: "scores relationships, not isolated findings. Several
MEDIUM/LOW signals converging on one asset can combine into CRITICAL; the
engine must explain *why* a score was produced."

THE CENTRAL RULE OF THIS MODULE: it evaluates evidence that other modules
already produced. It never scans, never probes, never makes a network
request, never authenticates, and never executes anything it discovered. A
severity is a *prioritization assessment* — an ordering of where a human
should look first — and is never a claim that anything is exploitable.

Responsibility -> implementation map:

  - Consume the asset graph + relationships    -> load_graph_state,
                                                  RiskEngine.__init__
  - Normalize graph content into risk signals  -> extract_signals
                                                  (+ SIGNAL_RULES catalog)
  - Score CRITICAL/HIGH/MEDIUM/LOW/INFO        -> classify_signal,
                                                  score_asset
  - Cross-module correlation / convergence     -> correlate_assets,
                                                  CORRELATION_RULES
  - Prioritized investigation queue            -> build_investigation_queue
  - Explanation per score                      -> every scored record carries
                                                  a `rationale` list built
                                                  alongside the score itself
  - Machine-readable output for
    report_generator.py / core/orchestrator.py -> RiskEngine.assess(),
                                                  persisted via
                                                  RiskAssessmentStore

PIPELINE (kept as five separable stages, each independently testable):

    ingestion -> signal extraction -> per-signal classification
              -> relationship correlation/scoring -> prioritization/output

--------------------------------------------------------------------------
INPUT-CONTRACT DECISION (why this module reads data, not code)

Every module in this repository is standalone: none imports another. This
module keeps that convention and consumes surface_mapper.py's *persisted
data model* rather than importing surface_mapper.py itself — the document
surface_mapper.py writes to <output_dir>/surface_graph.json (equivalently, a
live SurfaceMapper's `.state`). Both are accepted by `load_graph_state()`
and by `RiskEngine(graph=...)`, so the future orchestrator can hand over an
in-memory mapper without a round-trip through disk.

The structures consumed are exactly the ones surface_mapper.py produces:

  assets[asset_id]        -> {id, asset_type, value, state, attributes,
                              in_scope, sources, observation_ids,
                              confidence, first_seen, last_seen, ...}
  relationships[rel_id]   -> {id, rel_type, from_asset, to_asset, sources,
                              observation_ids, confidence, ...}
  observations[obs_id]    -> the original module finding record
                             {type, target, value, evidence, confidence,
                              source, timestamp, metadata}
  conflicts[conflict_id]  -> {asset_id, attribute, status, observations[]}
  negative_results / check_states / opportunities

Finding-type observations reach the graph as "finding" assets whose value is
{"finding_type": <type>, "detail": <the producing module's value>}, linked to
their subject asset by an `asset_to_finding` relationship. That is this
module's principal signal source; asset attributes (self-signed TLS, TLS
version, takeover indicator, endpoint category, ...) are the second.

--------------------------------------------------------------------------
SEVERITY MODEL (derived from context.md, not invented)

context.md §10 item 20 states the severity guide directly, and this module
implements exactly that guide — every rule in SIGNAL_RULES carries the
`basis` string naming the context.md phrase it implements:

  CRITICAL -> "exposed creds, listable buckets, RCE-class CVEs,
               IPMI exposure, exposed DB ports"
  HIGH     -> "admin panels, major misconfig, deprecated APIs w/ known CVEs"
  MEDIUM   -> "missing security headers, outdated TLS, SNMP defaults"
  LOW      -> "minor informational"
  INFO     -> "technology observations"

Three further inputs are taken from the repository rather than invented:

  1. PRODUCER SEVERITY ANNOTATIONS. active_recon.py and crawler.py already
     annotate metadata["severity"] for the cases context.md marks as
     auto-severity (IPMI exposure, DB exposure, file-upload surfaces), and
     their docstrings say explicitly that relationship-based scoring is
     deferred to this module. A producer's annotation is therefore honoured
     as the authoritative base severity when present.

  2. CONFIRMED vs SUSPECTED. exposure_scan.py already classifies a response
     as `discovery_type == "confirmed_exposure"` versus
     access_restricted / inconclusive / bucket_exists_access_restricted, and
     vuln_intel.py already classifies a CVE match as
     `version_range_confirmed` / `keyword_match_version_unconfirmed` /
     `version_unknown_cannot_confirm`. This module reuses those existing
     vocabularies instead of inventing a confirmation model.

  3. CVSS. Where vuln_intel.py supplies a CVSS score, the standard CVSS
     qualitative rating scale is used (9.0+ critical, 7.0+ high, 4.0+
     medium, >0 low). That is the published CVSS scale, not a local formula.

CONFIDENCE (context.md §8: "Never present insufficient evidence as
certainty"): confidence never *raises* a severity. It caps it. A signal
resting on LOW-confidence evidence cannot be presented above MEDIUM, and one
resting on MEDIUM-confidence evidence cannot be presented above HIGH. This is
what stops a single weak indicator from being reported as a confirmed
critical finding, and it is applied last, after every escalation.

CONVERGENCE (context.md §9): escalation is driven by the *number of distinct
converging signals on one asset*, never by summing invented point values.
Signals that rest on the same underlying evidence are merged before counting
(see `evidence_key`), so re-ingesting a graph, or two modules reporting the
same fact, cannot inflate a score. Independent corroboration of the same fact
is recorded as `corroborating_sources` and raises the signal's *confidence*
(the §8 treatment of converging evidence), not the convergence count.

--------------------------------------------------------------------------
FACTORS DELIBERATELY NOT IMPLEMENTED

"Exposure" and "asset criticality" weightings are not defined anywhere in
context.md v1.0, and no producing module emits a value for either. Inventing
a weighting for them would be inventing architecture, so this module does
not. Exploitability is implemented only to the extent the repository
supplies it — vuln_intel.py's CISA KEV and Exploit-DB annotations — and even
then only as a prioritization factor that can never convert an unconfirmed
match into a confirmed one.

--------------------------------------------------------------------------
DETERMINISM

Given the same graph, `assess()` produces byte-identical output except for
`generated_at`. All iteration is over sorted keys, all identifiers are
content hashes, and no scoring input depends on wall-clock time. Observation
age is measured against the newest timestamp in the graph itself rather than
"now", so staleness is a property of the data, not of when the engine ran.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

MODULE_NAME = "risk_engine.py"

# ---------------------------------------------------------------------------
# Severity vocabulary (context.md §10 item 20)
# ---------------------------------------------------------------------------

SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_ORDER: Dict[str, int] = {
    SEVERITY_INFO: 0,
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4,
}
SEVERITY_BY_RANK: Dict[int, str] = {rank: name for name, rank in SEVERITY_ORDER.items()}
VALID_SEVERITIES = frozenset(SEVERITY_ORDER)

# ---------------------------------------------------------------------------
# Confidence vocabulary — identical to every other module (context.md §8)
# ---------------------------------------------------------------------------

CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

CONFIDENCE_ORDER: Dict[str, int] = {CONFIDENCE_LOW: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_HIGH: 2}
VALID_CONFIDENCES = frozenset(CONFIDENCE_ORDER)

# context.md §8 — "Never present insufficient evidence as certainty." The
# severity a signal may be presented at is capped by the quality of the
# evidence underneath it. Applied last, after every escalation.
CONFIDENCE_SEVERITY_CAP: Dict[str, str] = {
    CONFIDENCE_LOW: SEVERITY_MEDIUM,
    CONFIDENCE_MEDIUM: SEVERITY_HIGH,
    CONFIDENCE_HIGH: SEVERITY_CRITICAL,
}

# ---------------------------------------------------------------------------
# Evidence-class vocabulary
#
# The task-critical distinction between what was directly observed and what
# was merely inferred. Sourced from the producing modules' own language:
# exposure_scan.py's "confirmed_exposure", vuln_intel.py's applicability
# levels, js_analyzer.py's "never confirmed" secret indicators,
# surface_mapper.py's takeover *indicators*.
# ---------------------------------------------------------------------------

KIND_OBSERVATION = "observation"                  # a fact about the surface, not a weakness
KIND_INDICATOR = "indicator"                      # suggestive, explicitly unverified
KIND_VULN_INTEL = "vulnerability_intelligence"    # a CVE match; never proof of exploitability
KIND_CONFIRMED = "confirmed_finding"              # the producing module directly observed the condition

VALID_KINDS = frozenset({KIND_OBSERVATION, KIND_INDICATOR, KIND_VULN_INTEL, KIND_CONFIRMED})

# Only a directly-observed condition may ever be described as confirmed. A
# CVE match and an indicator never can, no matter how much corroboration
# accumulates — corroboration raises confidence, not evidence class.
_NEVER_CONFIRMABLE = frozenset({KIND_INDICATOR, KIND_VULN_INTEL})

# ---------------------------------------------------------------------------
# Graph vocabulary consumed from surface_mapper.py's persisted data model
# ---------------------------------------------------------------------------

ASSET_HOSTNAME = "hostname"
ASSET_IP = "ip"
ASSET_PORT = "port"
ASSET_TECHNOLOGY = "technology"
ASSET_ENDPOINT = "endpoint"
ASSET_PARAMETER = "parameter"
ASSET_JAVASCRIPT = "javascript"
ASSET_THIRD_PARTY = "third_party_service"
ASSET_FINDING = "finding"
ASSET_ORGANIZATION = "organization"

REL_ASSET_TO_FINDING = "asset_to_finding"

# The asset types a risk subject rolls up to. context.md §9 asks for scoring
# over relationships: a weakness on an endpoint or a port is ultimately a
# weakness of the host that owns it, so signals converge on hosts and IPs.
ROLLUP_ASSET_TYPES = (ASSET_HOSTNAME, ASSET_IP)

# How far a signal may roll up through the relationship graph. The deepest
# chain in context.md §7's asset graph (hostname -> ip -> port -> technology,
# or hostname -> endpoint -> parameter) is well inside this bound.
MAX_ROLLUP_DEPTH = 4


class RiskEngineError(RuntimeError):
    """Raised when the risk engine cannot run at all (unusable graph input)."""


class PersistenceError(RuntimeError):
    """Raised when the risk assessment file cannot be safely read/written."""


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _short_hash(*parts: Any) -> str:
    blob = json.dumps(parts, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:20]


def _json_safe(value: Any, _depth: int = 0) -> Any:
    """
    Coerce any value into something json.dump() accepts without a `default=`
    fallback.

    Graph content originates in other modules and, through them, in real
    network data: a value can be a set, a tuple, a datetime, bytes, or a
    deeply nested structure. Producing output that cannot be serialized would
    destroy an entire assessment at the last step, so coercion happens once,
    on the way out.
    """
    if _depth > 24:
        return "<max serialization depth exceeded>"
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        # NaN/Infinity are accepted by json.dump but are not valid JSON.
        return value if value == value and value not in (float("inf"), float("-inf")) else str(value)
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key in sorted(value, key=lambda k: str(k)):
            out[str(key)] = _json_safe(value[key], _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [_json_safe(item, _depth + 1) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_json_safe(item, _depth + 1) for item in value), key=lambda v: str(v))
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def severity_rank(severity: Any) -> int:
    return SEVERITY_ORDER.get(severity, SEVERITY_ORDER[SEVERITY_INFO])


def confidence_rank(confidence: Any) -> int:
    return CONFIDENCE_ORDER.get(confidence, CONFIDENCE_ORDER[CONFIDENCE_LOW])


def shift_severity(severity: str, steps: int) -> str:
    """Move a severity up/down the CRITICAL..INFO ladder, clamped at both ends."""
    rank = severity_rank(severity) + steps
    rank = max(0, min(rank, SEVERITY_ORDER[SEVERITY_CRITICAL]))
    return SEVERITY_BY_RANK[rank]


def cap_severity(severity: str, ceiling: str) -> str:
    return severity if severity_rank(severity) <= severity_rank(ceiling) else ceiling


def normalize_confidence(value: Any) -> str:
    """Unknown/absent confidence is treated as LOW — never as a favourable assumption."""
    return value if value in VALID_CONFIDENCES else CONFIDENCE_LOW


def aggregate_confidence(contributions: Sequence[Dict[str, str]]) -> str:
    """
    context.md §8's converging-evidence rule, applied to the (source,
    confidence) pairs behind one signal: independent corroboration raises
    confidence; a single weak signal stays LOW.

    Deliberately identical in behaviour to surface_mapper.py's aggregation so
    that a confidence computed here means the same thing as one computed
    there.
    """
    if not contributions:
        return CONFIDENCE_LOW
    confidences = [normalize_confidence(c.get("confidence")) for c in contributions]
    sources = {c.get("source") for c in contributions}
    if CONFIDENCE_HIGH in confidences:
        return CONFIDENCE_HIGH
    if CONFIDENCE_MEDIUM in confidences and len(sources) >= 2:
        return CONFIDENCE_HIGH
    if CONFIDENCE_MEDIUM in confidences:
        return CONFIDENCE_MEDIUM
    if len(sources) >= 2:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=lambda v: str(v))
    return [value]


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ("" if value is None else str(value))


def _lower(value: Any) -> str:
    return _text(value).lower()


# ---------------------------------------------------------------------------
# Crash-safe persistence for the risk assessment document
# ---------------------------------------------------------------------------

class RiskAssessmentStore:
    """
    Atomic JSON persistence for <output_dir>/risk_assessment.json.

    Same write-to-temp + os.replace pattern every other module uses, so a
    crash mid-write can never leave a truncated assessment behind. The
    assessment is a single derived document (it can always be recomputed from
    the graph), so it is rewritten wholesale rather than appended to.
    """

    def __init__(self, output_dir: str = "output", filename: str = "risk_assessment.json"):
        self.output_dir = output_dir
        self.path = os.path.join(output_dir, filename)
        self._lock = threading.Lock()
        os.makedirs(self.output_dir, exist_ok=True)

    def save(self, assessment: Dict[str, Any]) -> str:
        with self._lock:
            dir_name = os.path.dirname(self.path) or "."
            fd, tmp_path = tempfile.mkstemp(prefix=".risk_assessment_", dir=dir_name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(_json_safe(assessment), handle, indent=2, sort_keys=True)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_path, self.path)
            except BaseException:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                raise
            return self.path

    def load(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if not os.path.exists(self.path):
                return None
            try:
                with open(self.path, "r", encoding="utf-8") as handle:
                    content = handle.read().strip()
                return json.loads(content) if content else None
            except (json.JSONDecodeError, ValueError, OSError) as exc:
                raise PersistenceError(f"Cannot read {self.path!r}: {exc}") from exc


# ===========================================================================
# STAGE 1 — INGESTION
# ===========================================================================

def load_graph_state(source: Any, output_dir: str = "output",
                     filename: str = "surface_graph.json") -> Dict[str, Any]:
    """
    Resolve any accepted graph input into surface_mapper.py's state document.

    Accepts a state dict, an object exposing `.state` (a live SurfaceMapper),
    a path to a surface_graph.json file, or None to read
    <output_dir>/<filename>. A graph that cannot be read at all is the one
    condition this module treats as fatal — with no graph there is nothing to
    assess.
    """
    if source is None:
        source = os.path.join(output_dir, filename)

    if hasattr(source, "state") and isinstance(getattr(source, "state"), dict):
        return getattr(source, "state")

    if isinstance(source, dict):
        return source

    if isinstance(source, (str, os.PathLike)):
        path = os.fspath(source)
        if not os.path.exists(path):
            raise RiskEngineError(f"Surface graph {path!r} does not exist; nothing to assess.")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                content = handle.read().strip()
        except OSError as exc:
            raise RiskEngineError(f"Cannot read surface graph {path!r}: {exc}") from exc
        if not content:
            raise RiskEngineError(f"Surface graph {path!r} is empty; nothing to assess.")
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RiskEngineError(f"Surface graph {path!r} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise RiskEngineError(f"Surface graph {path!r} root must be a JSON object.")
        return data

    raise RiskEngineError(
        f"Unsupported graph input {type(source).__name__!r}; expected a state dict, "
        f"a SurfaceMapper, or a path to surface_graph.json."
    )


def _normalize_graph(state: Dict[str, Any], errors: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Defensively project a graph document onto the containers this module
    reads.

    A graph may be hand-edited, truncated, produced by a different version, or
    partially written by a run that failed mid-module. A container of the
    wrong type is replaced with an empty one and the rejection is recorded —
    never silently accepted and never allowed to abort the assessment.
    """
    normalized: Dict[str, Any] = {}
    for key in ("assets", "relationships", "observations", "conflicts",
                "negative_results", "check_states", "opportunities"):
        container = state.get(key)
        if isinstance(container, dict):
            normalized[key] = container
        else:
            if key in state:
                errors.append({
                    "stage": "ingestion",
                    "error": f"graph container {key!r} is not a JSON object; treated as empty",
                    "observed_type": type(container).__name__,
                })
            normalized[key] = {}

    normalized["target"] = _text(state.get("target")) or None
    normalized["graph_updated_at"] = state.get("updated_at")
    normalized["graph_created_at"] = state.get("created_at")
    return normalized


# ===========================================================================
# STAGE 2 — SIGNAL EXTRACTION (normalization of graph content into signals)
# ===========================================================================
#
# Each rule maps one recognizable piece of graph content onto a base severity
# drawn from context.md §10 item 20's severity guide. `basis` names the exact
# context.md phrase the rule implements so that every score remains traceable
# to the architecture rather than to a local judgement call.
# ---------------------------------------------------------------------------

# Categories that represent credential material, shared by code_leak.py and
# js_analyzer.py (both use this identical vocabulary).
_CREDENTIAL_CATEGORIES = frozenset({"api_key", "token", "credential", "db_connection_string"})

# exposure_scan.py's own category constants.
_EXPOSURE_CREDENTIAL_CATEGORIES = frozenset({"credential_material", "environment_file", "database_dump"})
_EXPOSURE_MAJOR_MISCONFIG_CATEGORIES = frozenset({
    "version_control", "backup_file", "archive_file", "configuration_file",
    "debug_endpoint", "log_file",
})

# exposure_scan.py / cloud classification: the module's own word for "we
# directly observed the exposed content", as opposed to access_restricted,
# bucket_exists_access_restricted, inconclusive_cloud_response, ...
_CONFIRMED_EXPOSURE = "confirmed_exposure"

# TLS versions context.md §10 item 17 calls out as outdated.
_OUTDATED_TLS_VERSIONS = ("tlsv1.0", "tlsv1.1", "tls1.0", "tls1.1", "sslv2", "sslv3")

# Security headers whose absence context.md §10 item 16 tracks.
_TRACKED_SECURITY_HEADERS = (
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
)

_RCE_PATTERNS = (
    "remote code execution", "arbitrary code execution", "arbitrary command",
    "command injection", "code injection", "unauthenticated rce", " rce ",
    "deserialization of untrusted data",
)


def _detail_of(finding_value: Any) -> Dict[str, Any]:
    """A finding asset's value is {"finding_type": ..., "detail": <module value>}."""
    return _as_dict(_as_dict(finding_value).get("detail"))


def _cvss_severity(detail: Dict[str, Any]) -> Tuple[Optional[str], Optional[float], List[str]]:
    """
    Map vuln_intel.py's `cvss` list onto a severity using the published CVSS
    qualitative rating scale. Returns (severity, score, notes).
    """
    notes: List[str] = []
    best_score: Optional[float] = None
    textual: Optional[str] = None
    for entry in _as_list(detail.get("cvss")):
        entry = _as_dict(entry)
        raw = entry.get("score")
        try:
            score = float(raw) if raw is not None else None
        except (TypeError, ValueError):
            score = None
        if score is not None and (best_score is None or score > best_score):
            best_score = score
        label = _lower(entry.get("severity"))
        if label:
            mapped = {"critical": SEVERITY_CRITICAL, "high": SEVERITY_HIGH,
                      "moderate": SEVERITY_MEDIUM, "medium": SEVERITY_MEDIUM,
                      "low": SEVERITY_LOW}.get(label)
            if mapped and (textual is None or severity_rank(mapped) > severity_rank(textual)):
                textual = mapped

    if best_score is not None:
        if best_score >= 9.0:
            severity = SEVERITY_CRITICAL
        elif best_score >= 7.0:
            severity = SEVERITY_HIGH
        elif best_score >= 4.0:
            severity = SEVERITY_MEDIUM
        elif best_score > 0:
            severity = SEVERITY_LOW
        else:
            severity = SEVERITY_INFO
        notes.append(f"CVSS base score {best_score} maps to {severity} on the standard CVSS rating scale")
        return severity, best_score, notes

    if textual is not None:
        notes.append(f"no CVSS score available; advisory severity label maps to {textual}")
        return textual, None, notes

    return None, None, notes


def _looks_rce(detail: Dict[str, Any]) -> bool:
    haystack = " ".join(_text(s) for s in _as_list(detail.get("summaries"))).lower()
    return any(pattern in haystack for pattern in _RCE_PATTERNS)


def _missing_security_headers(detail: Dict[str, Any]) -> List[str]:
    headers = _as_dict(detail.get("headers"))
    missing = []
    for name in _TRACKED_SECURITY_HEADERS:
        entry = _as_dict(headers.get(name))
        if name in headers and not entry.get("present"):
            missing.append(name)
    return sorted(missing)


def _cookie_issues(detail: Dict[str, Any]) -> List[str]:
    issues: List[str] = []
    for cookie in _as_list(detail.get("cookies")):
        cookie = _as_dict(cookie)
        name = _text(cookie.get("name")) or "<unnamed>"
        for issue in _as_list(cookie.get("issues")):
            issues.append(f"{name}: {_text(issue)}")
    return sorted(set(issues))


class SignalRule:
    """
    One mapping from graph content to a base severity.

    `match` decides whether the rule applies to a finding's detail; `describe`
    builds the human-readable summary; `discriminator` yields the part of the
    detail that makes this signal distinct from another of the same category
    on the same asset (used to build the evidence key that prevents
    double-counting).
    """

    __slots__ = ("category", "finding_types", "severity", "kind", "basis",
                 "match", "describe", "discriminator")

    def __init__(
        self,
        category: str,
        finding_types: Sequence[str],
        severity: str,
        kind: str,
        basis: str,
        match: Optional[Callable[[Dict[str, Any], Dict[str, Any]], bool]] = None,
        describe: Optional[Callable[[Dict[str, Any]], str]] = None,
        discriminator: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ):
        self.category = category
        self.finding_types = tuple(finding_types)
        self.severity = severity
        self.kind = kind
        self.basis = basis
        self.match = match
        self.describe = describe
        self.discriminator = discriminator

    def applies(self, detail: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        if self.match is None:
            return True
        try:
            return bool(self.match(detail, metadata))
        except Exception:
            # A malformed detail must never make an entire rule unusable.
            return False


def _confirmed(detail: Dict[str, Any]) -> bool:
    return _lower(detail.get("discovery_type")) == _CONFIRMED_EXPOSURE


SIGNAL_RULES: Tuple[SignalRule, ...] = (
    # --- CRITICAL: "IPMI exposure" ---------------------------------------
    SignalRule(
        category="ipmi_exposure",
        finding_types=("ipmi_exposure",),
        severity=SEVERITY_CRITICAL,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 20 CRITICAL: 'IPMI exposure' (and §10 item 7: 'IPMI exposure -> auto CRITICAL')",
        match=lambda detail, meta: bool(detail.get("exposed")),
        describe=lambda detail: f"IPMI/RMCP responded on {detail.get('ip')}:{detail.get('port')}/udp",
    ),
    # --- CRITICAL: "exposed DB ports" ------------------------------------
    SignalRule(
        category="database_port_exposure",
        finding_types=("db_exposure",),
        severity=SEVERITY_CRITICAL,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 20 CRITICAL: 'exposed DB ports' (and §10 item 7: 'DB exposure -> auto CRITICAL')",
        match=lambda detail, meta: bool(_as_list(detail.get("exposed_ports"))),
        describe=lambda detail: (
            f"database port(s) {', '.join(str(p) for p in _as_list(detail.get('exposed_ports')))} "
            f"directly reachable on {detail.get('ip')}"
        ),
        discriminator=lambda detail: sorted(str(p) for p in _as_list(detail.get("exposed_ports"))),
    ),
    # --- CRITICAL: "listable buckets" ------------------------------------
    SignalRule(
        category="listable_cloud_storage",
        finding_types=("cloud_resource_finding",),
        severity=SEVERITY_CRITICAL,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 20 CRITICAL: 'listable buckets'",
        match=lambda detail, meta: _confirmed(detail),
        describe=lambda detail: (
            f"{detail.get('provider')} storage {detail.get('identifier')!r} returned a public listing"
        ),
        discriminator=lambda detail: _text(detail.get("url")) or _text(detail.get("identifier")),
    ),
    SignalRule(
        category="cloud_storage_exists_restricted",
        finding_types=("cloud_resource_finding",),
        severity=SEVERITY_LOW,
        kind=KIND_OBSERVATION,
        basis="context.md §10 item 20 LOW: 'minor informational' — resource exists but listing was denied",
        match=lambda detail, meta: _lower(detail.get("discovery_type")) == "bucket_exists_access_restricted",
        describe=lambda detail: (
            f"{detail.get('provider')} storage {detail.get('identifier')!r} exists but listing is denied"
        ),
        discriminator=lambda detail: _text(detail.get("url")) or _text(detail.get("identifier")),
    ),
    # --- CRITICAL: "exposed creds" ---------------------------------------
    SignalRule(
        category="exposed_credential_material",
        finding_types=("exposure_finding",),
        severity=SEVERITY_CRITICAL,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 20 CRITICAL: 'exposed creds'",
        match=lambda detail, meta: (
            _lower(detail.get("exposure_category")) in _EXPOSURE_CREDENTIAL_CATEGORIES and _confirmed(detail)
        ),
        describe=lambda detail: (
            f"{detail.get('exposure_category')} exposed at {detail.get('url')} "
            f"(HTTP {detail.get('status_code')})"
        ),
        discriminator=lambda detail: _text(detail.get("url")),
    ),
    SignalRule(
        category="leaked_credential_in_public_code",
        finding_types=("code_leak_exposure",),
        severity=SEVERITY_CRITICAL,
        # A credential-shaped string really is public, but its validity against
        # this target is never tested (code_leak.py performs no authentication),
        # so this stays an indicator and the confidence cap governs how loudly
        # it may be reported.
        kind=KIND_INDICATOR,
        basis="context.md §10 item 20 CRITICAL: 'exposed creds' — public-repository credential match",
        match=lambda detail, meta: _lower(detail.get("category")) in _CREDENTIAL_CATEGORIES,
        describe=lambda detail: (
            f"{detail.get('category')} pattern {detail.get('pattern_name')!r} matched in public repository "
            f"{detail.get('repository')}/{detail.get('path')}"
        ),
        discriminator=lambda detail: _text(detail.get("fingerprint_sha256")) or _text(detail.get("source_url")),
    ),
    SignalRule(
        category="secret_indicator_in_client_side_js",
        finding_types=("js_analyzer_secret_indicator",),
        severity=SEVERITY_CRITICAL,
        kind=KIND_INDICATOR,
        basis="context.md §10 item 20 CRITICAL: 'exposed creds' — client-side secret indicator "
              "(context.md §10 item 13: flagged for manual verification, never confirmed)",
        match=lambda detail, meta: _lower(detail.get("category")) in _CREDENTIAL_CATEGORIES,
        describe=lambda detail: (
            f"{detail.get('category')} pattern {detail.get('pattern_name')!r} present in client-side JavaScript"
        ),
        discriminator=lambda detail: _text(detail.get("fingerprint_sha256")) or _text(detail.get("pattern_name")),
    ),
    SignalRule(
        category="code_leak_infrastructure_reference",
        finding_types=("code_leak_exposure",),
        severity=SEVERITY_MEDIUM,
        kind=KIND_INDICATOR,
        basis="context.md §10 item 3: internal URLs / hardcoded infra references leaked in public repositories",
        match=lambda detail, meta: _lower(detail.get("category")) in ("internal_url", "infrastructure_reference", "config_file"),
        describe=lambda detail: (
            f"{detail.get('category')} leaked in public repository {detail.get('repository')}/{detail.get('path')}"
        ),
        discriminator=lambda detail: _text(detail.get("fingerprint_sha256")) or _text(detail.get("source_url")),
    ),
    # --- HIGH: "admin panels" --------------------------------------------
    SignalRule(
        category="exposed_administrative_panel",
        finding_types=("exposure_finding",),
        severity=SEVERITY_HIGH,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 20 HIGH: 'admin panels'",
        match=lambda detail, meta: (
            _lower(detail.get("exposure_category")) == "administrative_panel" and _confirmed(detail)
        ),
        describe=lambda detail: f"administrative panel reachable at {detail.get('url')}",
        discriminator=lambda detail: _text(detail.get("url")),
    ),
    # --- HIGH: "major misconfig" -----------------------------------------
    SignalRule(
        category="exposed_sensitive_resource",
        finding_types=("exposure_finding",),
        severity=SEVERITY_HIGH,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 20 HIGH: 'major misconfig' — sensitive resource served publicly",
        match=lambda detail, meta: (
            _lower(detail.get("exposure_category")) in _EXPOSURE_MAJOR_MISCONFIG_CATEGORIES and _confirmed(detail)
        ),
        describe=lambda detail: (
            f"{detail.get('exposure_category')} exposed at {detail.get('url')} (HTTP {detail.get('status_code')})"
        ),
        discriminator=lambda detail: _text(detail.get("url")),
    ),
    SignalRule(
        category="sensitive_resource_present_not_readable",
        finding_types=("exposure_finding",),
        severity=SEVERITY_LOW,
        kind=KIND_INDICATOR,
        basis="context.md §10 item 20 LOW: 'minor informational' — resource present but not readable",
        match=lambda detail, meta: (
            _text(detail.get("exposure_category")) != ""
            and not _confirmed(detail)
            and _lower(detail.get("discovery_type")) in ("access_restricted", "redirect", "method_not_allowed")
        ),
        describe=lambda detail: (
            f"{detail.get('exposure_category')} present but not readable at {detail.get('url')} "
            f"({detail.get('discovery_type')})"
        ),
        discriminator=lambda detail: _text(detail.get("url")),
    ),
    SignalRule(
        category="cors_misconfiguration",
        finding_types=("http_cors_misconfiguration",),
        severity=SEVERITY_HIGH,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 20 HIGH: 'major misconfig' — CORS origin reflection / null origin / wildcard",
        describe=lambda detail: (
            "CORS policy accepts "
            + ", ".join(sorted(
                label for label, flag in (
                    ("an arbitrary reflected origin", detail.get("origin_reflected")),
                    ("the null origin", detail.get("null_origin_allowed")),
                    ("a wildcard origin", detail.get("wildcard")),
                ) if flag
            ) or ["an unsafe origin"])
            + (" with credentials enabled" if detail.get("allow_credentials_with_wildcard_or_reflection") else "")
        ),
        discriminator=lambda detail: sorted(
            key for key in ("origin_reflected", "null_origin_allowed", "wildcard",
                            "allow_credentials_with_wildcard_or_reflection")
            if detail.get(key)
        ),
    ),
    SignalRule(
        category="anonymous_ftp_access",
        finding_types=("ftp_anonymous_access",),
        severity=SEVERITY_HIGH,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 20 HIGH: 'major misconfig' — anonymous FTP login accepted",
        match=lambda detail, meta: bool(detail.get("login_successful")),
        describe=lambda detail: f"anonymous FTP login accepted on {detail.get('ip')}:{detail.get('port')}",
    ),
    SignalRule(
        category="file_upload_surface",
        finding_types=("file_upload_surface",),
        severity=SEVERITY_HIGH,
        kind=KIND_OBSERVATION,
        basis="context.md §10 item 12: file-upload surfaces carry a HIGH-priority flag "
              "(crawler.py annotates metadata severity HIGH)",
        describe=lambda detail: f"file-upload form surface at {detail.get('action') or detail.get('resolved_action')}",
        discriminator=lambda detail: _text(detail.get("resolved_action")) or _text(detail.get("action")),
    ),
    SignalRule(
        category="subdomain_takeover_indicator",
        finding_types=("subdomain_takeover_indicator",),
        severity=SEVERITY_HIGH,
        kind=KIND_INDICATOR,
        basis="context.md §10 item 6: subdomain-takeover / dangling-CNAME detection — indicator only, never confirmed",
        describe=lambda detail: (
            f"CNAME points at {detail.get('final_target')!r} on takeover-susceptible provider {detail.get('provider')!r}"
        ),
        discriminator=lambda detail: _text(detail.get("final_target")),
    ),
    # --- MEDIUM: "missing security headers" ------------------------------
    SignalRule(
        category="missing_security_headers",
        finding_types=("http_security_headers",),
        severity=SEVERITY_MEDIUM,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 20 MEDIUM: 'missing security headers'",
        match=lambda detail, meta: bool(_missing_security_headers(detail)),
        describe=lambda detail: "missing security header(s): " + ", ".join(_missing_security_headers(detail)),
        discriminator=_missing_security_headers,
    ),
    SignalRule(
        category="insecure_cookie_flags",
        finding_types=("http_cookie_flags",),
        severity=SEVERITY_MEDIUM,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 16: cookie flag analysis (HttpOnly/Secure/SameSite)",
        match=lambda detail, meta: bool(_cookie_issues(detail)),
        describe=lambda detail: "cookie flag issues: " + "; ".join(_cookie_issues(detail)),
        discriminator=_cookie_issues,
    ),
    # --- MEDIUM: "SNMP defaults" -----------------------------------------
    SignalRule(
        category="snmp_default_community",
        finding_types=("snmp_exposure",),
        severity=SEVERITY_MEDIUM,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 20 MEDIUM: 'SNMP defaults'",
        match=lambda detail, meta: bool(_as_list(detail.get("accepted"))),
        describe=lambda detail: (
            f"SNMP responded on {detail.get('ip')}:{detail.get('port')} to "
            f"{len(_as_list(detail.get('accepted')))} default community string(s)"
        ),
        discriminator=lambda detail: sorted(
            _text(_as_dict(a).get("community")) for a in _as_list(detail.get("accepted"))
        ),
    ),
    SignalRule(
        category="smtp_user_enumeration",
        finding_types=("smtp_enumeration",),
        severity=SEVERITY_MEDIUM,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 7: SMTP VRFY/EXPN enumeration exposure",
        match=lambda detail, meta: bool(detail.get("vrfy_supported") or detail.get("expn_supported")),
        describe=lambda detail: (
            f"SMTP on {detail.get('ip')}:{detail.get('port')} accepts "
            + " and ".join(
                name for name, flag in (("VRFY", detail.get("vrfy_supported")),
                                        ("EXPN", detail.get("expn_supported"))) if flag
            )
        ),
    ),
    SignalRule(
        category="jwt_weak_algorithm",
        finding_types=("http_jwt_detected",),
        severity=SEVERITY_MEDIUM,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 16: JWT algorithm inspection (no exploitation) — 'alg: none' accepted",
        match=lambda detail, meta: bool(detail.get("weak_alg_detected")),
        describe=lambda detail: f"{detail.get('count')} JWT(s) observed, at least one declaring 'alg: none'",
    ),
    SignalRule(
        category="jwt_observed",
        finding_types=("http_jwt_detected",),
        severity=SEVERITY_INFO,
        kind=KIND_OBSERVATION,
        basis="context.md §10 item 20 INFO: technology/behaviour observation",
        match=lambda detail, meta: not detail.get("weak_alg_detected"),
        describe=lambda detail: f"{detail.get('count')} JWT-shaped token(s) observed in responses",
    ),
    # --- MEDIUM/LOW: informational leakage --------------------------------
    SignalRule(
        category="error_page_information_disclosure",
        finding_types=("error_page_intelligence",),
        severity=SEVERITY_MEDIUM,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 15: error-page intelligence (stack traces, framework versions, internal paths)",
        match=lambda detail, meta: bool(_as_list(detail.get("indicators"))),
        describe=lambda detail: (
            "error page discloses: " + ", ".join(sorted(_text(i) for i in _as_list(detail.get("indicators"))))
        ),
        discriminator=lambda detail: sorted(_text(i) for i in _as_list(detail.get("indicators"))),
    ),
    SignalRule(
        category="deprecated_api_endpoint",
        finding_types=("api_endpoint_deprecated",),
        severity=SEVERITY_MEDIUM,
        # context.md's HIGH line is "deprecated APIs w/ known CVEs" — the
        # combination, not deprecation alone. The escalation lives in
        # CORRELATION_RULES, so deprecation on its own stays MEDIUM.
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 20 HIGH: 'deprecated APIs w/ known CVEs' — deprecation half of that pairing",
        describe=lambda detail: (
            f"API endpoint {detail.get('url')} reported deprecated (basis: {detail.get('basis')})"
        ),
        discriminator=lambda detail: _text(detail.get("url")),
    ),
    SignalRule(
        category="virtual_host_expands_surface",
        finding_types=("vhost_discovered",),
        severity=SEVERITY_LOW,
        kind=KIND_CONFIRMED,
        basis="context.md §10 item 9: vhost discovery surfaces apps not visible via DNS",
        describe=lambda detail: (
            f"virtual host {detail.get('hostname')!r} served by {detail.get('ip')}:{detail.get('port')}"
        ),
        discriminator=lambda detail: _text(detail.get("hostname")),
    ),
    SignalRule(
        category="cross_host_port_pattern",
        finding_types=("cross_host_port_pattern",),
        severity=SEVERITY_LOW,
        kind=KIND_OBSERVATION,
        basis="context.md §10 item 7: cross-host pattern detection (org-wide unusual port)",
        describe=lambda detail: (
            f"port {detail.get('port')} open on {detail.get('host_count')} distinct hosts"
        ),
        discriminator=lambda detail: _text(detail.get("port")),
    ),
    SignalRule(
        category="historical_endpoint_reference",
        finding_types=("historical_endpoint_reference", "historical_parameter"),
        severity=SEVERITY_LOW,
        kind=KIND_INDICATOR,
        basis="context.md §10 item 5: removed-but-maybe-still-accessible historical assets",
        describe=lambda detail: f"historical reference to {detail.get('url') or detail.get('endpoint')}",
        discriminator=lambda detail: _text(detail.get("url")) or _text(detail.get("endpoint")),
    ),
    SignalRule(
        category="third_party_dependency",
        finding_types=("supply_chain_third_party_js_resource", "supply_chain_subdomain_third_party_dns",
                       "js_analyzer_external_service_reference"),
        severity=SEVERITY_LOW,
        kind=KIND_OBSERVATION,
        basis="context.md §10 item 14: third-party trust map / supply-chain relationship",
        describe=lambda detail: (
            f"third-party dependency on {detail.get('host') or detail.get('subdomain') or detail.get('vendor')}"
        ),
        discriminator=lambda detail: (
            _text(detail.get("host")) or _text(detail.get("subdomain")) or _text(detail.get("vendor"))
        ),
    ),
    # --- INFO: "technology observations" ---------------------------------
    SignalRule(
        category="technology_observation",
        finding_types=("tech_fingerprint_detected", "banner", "ssh_fingerprint", "os_fingerprint"),
        severity=SEVERITY_INFO,
        kind=KIND_OBSERVATION,
        basis="context.md §10 item 20 INFO: 'technology observations'",
        describe=lambda detail: (
            f"technology observation: {detail.get('technology') or detail.get('software') or detail.get('banner') or detail.get('os_guess')}"
        ),
        discriminator=lambda detail: (
            _text(detail.get("technology")) or _text(detail.get("software"))
            or _text(detail.get("banner")) or _text(detail.get("os_guess"))
        ),
    ),
)

# Index of rules by finding type, so extraction is a dict lookup rather than a
# scan of the whole catalog per finding.
_RULES_BY_TYPE: Dict[str, List[SignalRule]] = {}
for _rule in SIGNAL_RULES:
    for _finding_type in _rule.finding_types:
        _RULES_BY_TYPE.setdefault(_finding_type, []).append(_rule)


# ---------------------------------------------------------------------------
# Per-signal classification (severity + evidence class + confidence)
# ---------------------------------------------------------------------------

def classify_vulnerability_intelligence(detail: Dict[str, Any],
                                        metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Turn one vuln_intel.py `vulnerability_intelligence` record into a base
    severity plus the factors that modify it.

    Never asserts exploitability: applicability is vuln_intel.py's own
    assessment of whether the detected version even falls in the CVE's range,
    and it drives a hard confidence ceiling rather than a bonus.
    """
    notes: List[str] = []
    severity, score, cvss_notes = _cvss_severity(detail)
    notes.extend(cvss_notes)

    severity_unknown = severity is None
    if severity_unknown:
        # Unknown severity is neither assumed harmless nor assumed dangerous.
        severity = SEVERITY_MEDIUM
        notes.append(
            "no CVSS score or advisory severity available — held at MEDIUM as an explicitly "
            "unknown severity rather than assumed high or low"
        )

    applicability = _lower(detail.get("applicability")) or "unknown"
    # vuln_intel.py's own confidence for this record is the honest starting
    # point; the applicability ceiling below is applied on top of it.
    confidence = normalize_confidence(detail.get("confidence") or metadata.get("confidence"))

    if applicability == "version_range_confirmed":
        notes.append("detected version falls within the CVE's documented vulnerable range")
        applicability_ceiling = CONFIDENCE_HIGH
    elif applicability == "keyword_match_version_unconfirmed":
        notes.append("product name matched but version applicability was not confirmed")
        applicability_ceiling = CONFIDENCE_MEDIUM
    elif applicability == "version_unknown_cannot_confirm":
        notes.append("no version information available — CVE applicability cannot be assessed")
        applicability_ceiling = CONFIDENCE_LOW
    else:
        notes.append(f"unrecognized applicability {applicability!r} — treated as unconfirmed")
        applicability_ceiling = CONFIDENCE_LOW

    if confidence_rank(confidence) > confidence_rank(applicability_ceiling):
        confidence = applicability_ceiling

    factors: List[Dict[str, Any]] = []
    # Exploitability, only as far as the repository actually supplies it.
    kev = detail.get("cisa_kev")
    exploitdb = _as_list(detail.get("exploitdb_references"))
    if kev:
        factors.append({
            "factor": "known_exploited_vulnerability",
            "steps": 1,
            "reason": "listed in the CISA Known Exploited Vulnerabilities catalog "
                      "(exploited in the wild against some target; not confirmation against this one)",
        })
        if exploitdb:
            # KEV already accounted for exploitability. The Exploit-DB
            # references are the *same* underlying fact ("this CVE is
            # exploitable in practice"), so they are recorded as evidence but
            # never escalated a second time.
            notes.append(
                f"{len(exploitdb)} public Exploit-DB reference(s) also exist; exploitability was "
                f"already accounted for by the KEV listing and is not counted twice"
            )
    elif exploitdb:
        factors.append({
            "factor": "public_exploit_exists",
            "steps": 1,
            "reason": f"{len(exploitdb)} public Exploit-DB reference(s) exist for this CVE "
                      f"(no evidence of use against this target)",
        })

    if _looks_rce(detail):
        if applicability == "version_range_confirmed":
            factors.append({
                "factor": "rce_class_vulnerability",
                "steps": 1,
                "reason": "advisory text describes remote/arbitrary code execution and the detected "
                          "version falls in the vulnerable range (context.md CRITICAL: 'RCE-class CVEs')",
            })
        else:
            notes.append(
                "advisory text describes remote/arbitrary code execution, but version applicability "
                "is unconfirmed — recorded without escalation"
            )

    return {
        "base_severity": severity,
        "severity_unknown": severity_unknown,
        "cvss_score": score,
        "applicability": applicability,
        "confidence": confidence,
        "factors": factors,
        "notes": notes,
    }


def _observation_records(graph: Dict[str, Any], observation_ids: Iterable[Any]) -> List[Dict[str, Any]]:
    observations = graph["observations"]
    records = []
    for obs_id in observation_ids:
        record = observations.get(obs_id)
        if isinstance(record, dict):
            records.append(record)
    return records


def _build_signal(
    *,
    category: str,
    severity: str,
    kind: str,
    basis: str,
    summary: str,
    subject_asset_id: str,
    discriminator: Any,
    contributions: List[Dict[str, str]],
    evidence: List[str],
    observation_ids: List[str],
    sources: List[str],
    provenance: List[Dict[str, Any]],
    detail: Any = None,
    factors: Optional[List[Dict[str, Any]]] = None,
    notes: Optional[List[str]] = None,
    last_seen: Optional[str] = None,
) -> Dict[str, Any]:
    """Assemble one normalized risk signal. Purely structural — no scoring here."""
    evidence_key = _short_hash(category, subject_asset_id, discriminator)
    return {
        "signal_id": f"signal:{category}:{evidence_key}",
        "evidence_key": evidence_key,
        "category": category,
        "kind": kind,
        "base_severity": severity,
        "severity_basis": basis,
        "summary": summary,
        "subject_asset_id": subject_asset_id,
        "confidence": aggregate_confidence(contributions),
        "contributions": contributions,
        "sources": sorted(set(sources)),
        "corroborating_sources": sorted({c.get("source") for c in contributions if c.get("source")}),
        "evidence": evidence,
        "observation_ids": sorted(set(observation_ids)),
        "provenance": provenance,
        "detail": detail,
        "factors": list(factors or []),
        "notes": list(notes or []),
        "last_seen": last_seen,
    }


def extract_signals(graph: Dict[str, Any], errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize the graph into risk signals.

    Two sources are read, in this order:

      1. `finding` assets — surface_mapper.py's representation of every module
         finding that is not itself an asset. These carry the bulk of the risk
         content and are matched against SIGNAL_RULES.
      2. asset attributes — conditions surface_mapper.py stores as correlated
         attributes rather than findings (self-signed TLS, TLS version,
         takeover indicator, endpoint category, open port status).

    Signals sharing an `evidence_key` are merged rather than repeated, so the
    same underlying fact reported by two modules (or re-ingested twice) yields
    one signal with two corroborating sources.
    """
    merged: Dict[str, Dict[str, Any]] = {}

    def _emit(signal: Dict[str, Any]) -> None:
        key = signal["evidence_key"]
        existing = merged.get(key)
        if existing is None:
            merged[key] = signal
            return
        # Same underlying evidence seen again: corroborate, never duplicate.
        existing["contributions"].extend(signal["contributions"])
        existing["confidence"] = aggregate_confidence(existing["contributions"])
        existing["sources"] = sorted(set(existing["sources"]) | set(signal["sources"]))
        existing["corroborating_sources"] = sorted(
            {c.get("source") for c in existing["contributions"] if c.get("source")}
        )
        existing["observation_ids"] = sorted(set(existing["observation_ids"]) | set(signal["observation_ids"]))
        for item in signal["evidence"]:
            if item not in existing["evidence"]:
                existing["evidence"].append(item)
        for item in signal["provenance"]:
            if item not in existing["provenance"]:
                existing["provenance"].append(item)
        for item in signal["notes"]:
            if item not in existing["notes"]:
                existing["notes"].append(item)
        if severity_rank(signal["base_severity"]) > severity_rank(existing["base_severity"]):
            existing["base_severity"] = signal["base_severity"]
            existing["severity_basis"] = signal["severity_basis"]
        # A directly-observed confirmation outranks an inference of the same fact.
        if signal["kind"] == KIND_CONFIRMED and existing["kind"] not in _NEVER_CONFIRMABLE:
            existing["kind"] = KIND_CONFIRMED
        if _text(signal.get("last_seen")) > _text(existing.get("last_seen")):
            existing["last_seen"] = signal["last_seen"]

    subject_index = _build_finding_subject_index(graph)

    for asset_id in sorted(graph["assets"]):
        asset = graph["assets"][asset_id]
        if not isinstance(asset, dict):
            errors.append({"stage": "extraction", "asset_id": asset_id,
                           "error": f"asset record is not a JSON object ({type(asset).__name__})"})
            continue
        try:
            if _text(asset.get("asset_type")) == ASSET_FINDING:
                for signal in _signals_from_finding_asset(graph, asset_id, asset, subject_index):
                    _emit(signal)
            else:
                for signal in _signals_from_asset_attributes(graph, asset_id, asset):
                    _emit(signal)
        except Exception as exc:  # one bad asset must never destroy the assessment
            errors.append({"stage": "extraction", "asset_id": asset_id, "error": str(exc)})

    return [merged[key] for key in sorted(merged)]


def _build_finding_subject_index(graph: Dict[str, Any]) -> Dict[str, str]:
    """
    Map each `finding` asset to the asset it describes.

    surface_mapper.py links a finding to its subject with an
    `asset_to_finding` relationship whose `from_asset` is the subject.
    """
    index: Dict[str, str] = {}
    for rel_id in sorted(graph["relationships"]):
        rel = graph["relationships"][rel_id]
        if not isinstance(rel, dict) or _text(rel.get("rel_type")) != REL_ASSET_TO_FINDING:
            continue
        finding_id = _text(rel.get("to_asset"))
        subject_id = _text(rel.get("from_asset"))
        if finding_id and subject_id and finding_id not in index:
            index[finding_id] = subject_id
    return index


def _signals_from_finding_asset(graph: Dict[str, Any], asset_id: str, asset: Dict[str, Any],
                                 subject_index: Dict[str, str]) -> List[Dict[str, Any]]:
    value = _as_dict(asset.get("value"))
    finding_type = _text(value.get("finding_type"))
    detail = _detail_of(asset.get("value"))
    subject_id = subject_index.get(asset_id, asset_id)

    observations = _observation_records(graph, _as_list(asset.get("observation_ids")))
    evidence: List[str] = []
    provenance: List[Dict[str, Any]] = []
    contributions: List[Dict[str, str]] = []
    metadata: Dict[str, Any] = {}
    for record in observations:
        for item in _as_list(record.get("evidence")):
            text = _text(item)
            if text and text not in evidence:
                evidence.append(text)
        metadata.update(_as_dict(record.get("metadata")))
        entry = {
            "source": _text(record.get("source")) or "unknown",
            "observation_id": _text(record.get("observation_id")),
            "timestamp": record.get("timestamp"),
            "confidence": normalize_confidence(record.get("confidence")),
        }
        if entry not in provenance:
            provenance.append(entry)
        contributions.append({"source": entry["source"], "confidence": entry["confidence"]})

    if not contributions:
        # An asset with no resolvable observation still carries the graph's own
        # aggregated confidence and source list; use them rather than dropping it.
        for source in _as_list(asset.get("sources")):
            contributions.append({"source": _text(source) or "unknown",
                                  "confidence": normalize_confidence(asset.get("confidence"))})
    if not contributions:
        contributions.append({"source": "unknown", "confidence": CONFIDENCE_LOW})

    sources = [c["source"] for c in contributions]
    observation_ids = [_text(o) for o in _as_list(asset.get("observation_ids"))]
    last_seen = asset.get("last_seen")

    common = dict(
        subject_asset_id=subject_id, contributions=contributions, evidence=evidence,
        observation_ids=observation_ids, sources=sources, provenance=provenance,
        detail=detail, last_seen=last_seen,
    )

    # Vulnerability intelligence has its own classification path (CVSS,
    # applicability, exploitability) rather than a flat catalog entry.
    if finding_type == "vulnerability_intelligence":
        assessment = classify_vulnerability_intelligence(detail, metadata)
        cve_id = _text(detail.get("cve_id")) or "unknown-CVE"
        # vuln_intel.py's own per-record confidence is authoritative for a CVE
        # match; replace the graph-derived aggregate with it.
        vuln_contributions = [{"source": c["source"], "confidence": assessment["confidence"]}
                               for c in contributions] or [{"source": "vuln_intel.py",
                                                            "confidence": assessment["confidence"]}]
        signal = _build_signal(
            category="vulnerability_intelligence",
            severity=assessment["base_severity"],
            kind=KIND_VULN_INTEL,
            basis="context.md §10 item 19/20: technology-to-CVE mapping is vulnerability intelligence, "
                  "never proof of exploitability",
            summary=_text(detail.get("statement")) or f"{cve_id} may affect {detail.get('technology')}",
            discriminator=cve_id,
            factors=assessment["factors"],
            notes=assessment["notes"],
            **common,
        )
        signal["contributions"] = vuln_contributions
        signal["confidence"] = assessment["confidence"]
        signal["cve_id"] = cve_id
        signal["cvss_score"] = assessment["cvss_score"]
        signal["applicability"] = assessment["applicability"]
        signal["severity_unknown"] = assessment["severity_unknown"]
        signal["technology"] = _text(detail.get("technology")) or None
        signal["technology_version"] = _text(detail.get("version")) or None
        return [signal]

    # A producer's own severity annotation is authoritative (repo convention:
    # active_recon.py / crawler.py annotate metadata["severity"] for the cases
    # context.md marks auto-severity, deferring correlation to this module).
    annotated = _text(metadata.get("severity")).upper()
    annotated_severity = annotated if annotated in VALID_SEVERITIES else None

    signals: List[Dict[str, Any]] = []
    for rule in _RULES_BY_TYPE.get(finding_type, ()):
        if not rule.applies(detail, metadata):
            continue
        try:
            summary = rule.describe(detail) if rule.describe else f"{finding_type} on {subject_id}"
        except Exception:
            summary = f"{finding_type} on {subject_id}"
        try:
            discriminator = rule.discriminator(detail) if rule.discriminator else None
        except Exception:
            discriminator = None

        severity = rule.severity
        basis = rule.basis
        notes: List[str] = []
        if annotated_severity and severity_rank(annotated_severity) > severity_rank(severity):
            notes.append(
                f"producing module {sources[0]!r} annotated this finding severity={annotated_severity}; "
                f"honoured over the catalog default {severity}"
            )
            severity = annotated_severity
            basis = f"{basis}; producing module annotated metadata severity={annotated_severity}"

        signals.append(_build_signal(
            category=rule.category, severity=severity, kind=rule.kind, basis=basis,
            summary=summary, discriminator=discriminator, notes=notes, **common,
        ))

    if signals:
        return signals

    # Unrecognized finding type: recorded, never dropped, and never assumed to
    # be either harmless or dangerous.
    severity = annotated_severity or SEVERITY_INFO
    return [_build_signal(
        category=f"unclassified:{finding_type or 'unknown'}",
        severity=severity,
        kind=KIND_OBSERVATION,
        basis=(f"producing module annotated metadata severity={annotated_severity}"
                if annotated_severity else
                "finding type has no severity rule in context.md's severity guide — recorded as INFO, "
                "not assigned a risk severity"),
        summary=f"unclassified finding {finding_type or 'unknown'!r} on {subject_id}",
        discriminator=_short_hash(_json_safe(detail)),
        notes=["no risk rule matched this finding type; it is preserved for reporting without a "
               "derived severity"],
        **common,
    )]


def _attribute_contributions(attribute: Dict[str, Any]) -> Tuple[List[Dict[str, str]], List[Dict[str, Any]]]:
    confidence = normalize_confidence(attribute.get("confidence"))
    sources = [_text(s) for s in _as_list(attribute.get("sources"))] or [_text(attribute.get("source")) or "unknown"]
    contributions = [{"source": s or "unknown", "confidence": confidence} for s in sources]
    provenance = [{
        "source": _text(attribute.get("source")) or "unknown",
        "observation_id": _text(attribute.get("observation_id")),
        "timestamp": attribute.get("timestamp"),
        "confidence": confidence,
    }]
    return contributions, provenance


def _signals_from_asset_attributes(graph: Dict[str, Any], asset_id: str,
                                    asset: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract signals from conditions surface_mapper.py records as correlated
    asset attributes rather than as findings.
    """
    signals: List[Dict[str, Any]] = []
    attributes = _as_dict(asset.get("attributes"))
    asset_type = _text(asset.get("asset_type"))
    last_seen = asset.get("last_seen")

    def _attr_signal(attribute: Dict[str, Any], *, category: str, severity: str, kind: str,
                     basis: str, summary: str, discriminator: Any,
                     notes: Optional[List[str]] = None) -> None:
        contributions, provenance = _attribute_contributions(attribute)
        signals.append(_build_signal(
            category=category, severity=severity, kind=kind, basis=basis, summary=summary,
            subject_asset_id=asset_id, discriminator=discriminator, contributions=contributions,
            evidence=[f"surface_mapper.py correlated attribute {category!r} on {asset_id}"],
            observation_ids=[_text(attribute.get("observation_id"))] if attribute.get("observation_id") else [],
            sources=[c["source"] for c in contributions], provenance=provenance,
            detail={"attribute_value": attribute.get("value")}, notes=notes, last_seen=last_seen,
        ))

    # --- outdated TLS (context.md §10 item 20 MEDIUM: "outdated TLS") ------
    tls_version_attr = _as_dict(attributes.get("tls_version"))
    tls_version = _lower(tls_version_attr.get("value")).replace(" ", "").replace("_", "")
    if tls_version and any(tls_version.startswith(v) for v in _OUTDATED_TLS_VERSIONS):
        _attr_signal(
            tls_version_attr, category="outdated_tls_version", severity=SEVERITY_MEDIUM,
            kind=KIND_CONFIRMED,
            basis="context.md §10 item 20 MEDIUM: 'outdated TLS'",
            summary=f"negotiated {tls_version_attr.get('value')} — an outdated TLS version",
            discriminator=tls_version,
        )

    # --- self-signed certificate ------------------------------------------
    self_signed_attr = _as_dict(attributes.get("tls_self_signed"))
    if self_signed_attr.get("value") is True:
        _attr_signal(
            self_signed_attr, category="self_signed_certificate", severity=SEVERITY_MEDIUM,
            kind=KIND_CONFIRMED,
            basis="context.md §10 item 17: self-signed certificate detection",
            summary="TLS certificate is self-signed",
            discriminator="self_signed",
        )

    # --- subdomain takeover indicator -------------------------------------
    takeover_attr = _as_dict(attributes.get("takeover_indicator"))
    indicator = _as_dict(takeover_attr.get("value"))
    if indicator.get("provider") and _text(indicator.get("indicator_level")) in (CONFIDENCE_MEDIUM, CONFIDENCE_HIGH):
        contributions = [{"source": _text(takeover_attr.get("source")) or "surface_mapper.py",
                          "confidence": normalize_confidence(indicator.get("indicator_level"))}]
        signals.append(_build_signal(
            category="subdomain_takeover_indicator", severity=SEVERITY_HIGH, kind=KIND_INDICATOR,
            basis="context.md §10 item 6: subdomain-takeover / dangling-CNAME detection — indicator only",
            summary=(f"CNAME chain ends at {indicator.get('final_target')!r} on takeover-susceptible "
                     f"provider {indicator.get('provider')!r}"),
            subject_asset_id=asset_id, discriminator=_text(indicator.get("final_target")),
            contributions=contributions,
            evidence=[_text(indicator.get("note"))] if indicator.get("note") else [],
            observation_ids=[_text(takeover_attr.get("observation_id"))] if takeover_attr.get("observation_id") else [],
            sources=[c["source"] for c in contributions],
            provenance=[{"source": contributions[0]["source"],
                         "observation_id": _text(takeover_attr.get("observation_id")),
                         "timestamp": takeover_attr.get("timestamp"),
                         "confidence": contributions[0]["confidence"]}],
            detail=indicator,
            notes=["indicator only — never a confirmed takeover; requires manual verification, and "
                   "ReconHound never claims or interacts with the referenced third-party resource"],
            last_seen=last_seen,
        ))

    # --- file-upload surface ----------------------------------------------
    upload_attr = _as_dict(attributes.get("file_upload_surface"))
    if upload_attr.get("value") is True:
        _attr_signal(
            upload_attr, category="file_upload_surface", severity=SEVERITY_HIGH,
            kind=KIND_OBSERVATION,
            basis="context.md §10 item 12: file-upload surfaces carry a HIGH-priority flag",
            summary=f"file-upload surface on {asset.get('value')}",
            discriminator=_text(asset.get("value")),
            notes=["attack-surface observation only — presence of an upload form is not a vulnerability"],
        )

    # --- administrative endpoint ------------------------------------------
    if asset_type == ASSET_ENDPOINT:
        category_attr = _as_dict(attributes.get("category"))
        if _lower(category_attr.get("value")) in ("admin", "administrative", "administrative_panel"):
            _attr_signal(
                category_attr, category="administrative_endpoint", severity=SEVERITY_HIGH,
                kind=KIND_CONFIRMED,
                basis="context.md §10 item 20 HIGH: 'admin panels'",
                summary=f"administrative endpoint {asset.get('value')}",
                discriminator=_text(asset.get("value")),
            )

    # --- exposed service ports --------------------------------------------
    if asset_type == ASSET_PORT:
        status_attr = _as_dict(attributes.get("status"))
        if _lower(status_attr.get("value")) == "open":
            port_value = _as_dict(asset.get("value"))
            _attr_signal(
                status_attr, category="open_service_port", severity=SEVERITY_INFO,
                kind=KIND_CONFIRMED,
                basis="context.md §10 item 20 INFO: an open port is an attack-surface observation; "
                      "risk arises from what is behind it",
                summary=(f"open {port_value.get('protocol')} port {port_value.get('port')} "
                          f"on {port_value.get('ip')}"),
                discriminator=f"{port_value.get('ip')}:{port_value.get('port')}/{port_value.get('protocol')}",
            )

    # --- third-party dependencies ------------------------------------------
    # supply_chain.py / js_analyzer.py third-party references become
    # third_party_service *assets* rather than findings, so they are read here
    # rather than from the finding catalog.
    if asset_type == ASSET_THIRD_PARTY:
        category_attr = _as_dict(attributes.get("category"))
        vendor_attr = _as_dict(attributes.get("vendor"))
        contributions = [{"source": _text(src) or "unknown",
                          "confidence": normalize_confidence(asset.get("confidence"))}
                         for src in _as_list(asset.get("sources"))] or [
                            {"source": "unknown", "confidence": CONFIDENCE_LOW}]
        vendor = _text(vendor_attr.get("value"))
        category = _text(category_attr.get("value"))
        signals.append(_build_signal(
            category="third_party_dependency", severity=SEVERITY_LOW, kind=KIND_OBSERVATION,
            basis="context.md §10 item 14: third-party trust map / supply-chain relationship",
            summary=(f"third-party dependency on {asset.get('value')}"
                      + (f" ({vendor})" if vendor else "")
                      + (f" — category {category}" if category else "")),
            subject_asset_id=asset_id, discriminator=_text(asset.get("value")),
            contributions=contributions, evidence=[],
            observation_ids=[_text(o) for o in _as_list(asset.get("observation_ids"))],
            sources=[c["source"] for c in contributions],
            provenance=[{"source": c["source"], "observation_id": None, "timestamp": last_seen,
                         "confidence": c["confidence"]} for c in contributions],
            detail={"host": asset.get("value"), "vendor": vendor or None, "category": category or None},
            notes=["third-party service outside the authorized target scope — recorded as a "
                   "supply-chain relationship, never as an investigation target"],
            last_seen=last_seen,
        ))

    # --- technology observations ------------------------------------------
    if asset_type == ASSET_TECHNOLOGY:
        tech_value = _as_dict(asset.get("value"))
        version_attr = _as_dict(attributes.get("version"))
        contributions = [{"source": _text(s) or "unknown",
                          "confidence": normalize_confidence(asset.get("confidence"))}
                         for s in _as_list(asset.get("sources"))] or [
                            {"source": "unknown", "confidence": CONFIDENCE_LOW}]
        version = _text(version_attr.get("value"))
        signals.append(_build_signal(
            category="technology_observation", severity=SEVERITY_INFO, kind=KIND_OBSERVATION,
            basis="context.md §10 item 20 INFO: 'technology observations'",
            summary=f"{tech_value.get('name')}{' ' + version if version else ''} observed on {tech_value.get('scope')}",
            subject_asset_id=asset_id,
            discriminator=f"{_lower(tech_value.get('name'))}|{version}",
            contributions=contributions,
            evidence=[], observation_ids=[_text(o) for o in _as_list(asset.get("observation_ids"))],
            sources=[c["source"] for c in contributions],
            provenance=[{"source": c["source"], "observation_id": None, "timestamp": last_seen,
                         "confidence": c["confidence"]} for c in contributions],
            detail={"technology": tech_value.get("name"), "version": version or None,
                    "scope": tech_value.get("scope")},
            last_seen=last_seen,
        ))

    return signals


# ===========================================================================
# STAGE 3 — CONFLICT AND STALENESS QUALIFICATION
# ===========================================================================

def _conflict_index(graph: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Unresolved conflicts, indexed by the asset they belong to."""
    index: Dict[str, List[Dict[str, Any]]] = {}
    for conflict_id in sorted(graph["conflicts"]):
        conflict = graph["conflicts"][conflict_id]
        if not isinstance(conflict, dict):
            continue
        if _lower(conflict.get("status")) not in ("", "unresolved"):
            continue
        asset_id = _text(conflict.get("asset_id"))
        if asset_id:
            index.setdefault(asset_id, []).append(conflict)
    return index


def _disputed_technology_versions(graph: Dict[str, Any],
                                   conflicts: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Index unresolved *version* conflicts by technology name.

    surface_mapper.py scopes a technology asset by the URL or host it was
    observed on, so the same product legitimately appears under more than one
    asset id: tech_fingerprint.py reports nginx against "https://example.com/",
    while a vuln_intel.py record for the same nginx carries only the bare
    target. Matching a disputed fingerprint to the CVE it invalidates is this
    module's own correlation step — surface_mapper.py has already done its job
    by preserving the conflict — so the match is made on the technology name
    rather than on asset identity. Without it, context.md §8's "version-
    dependent CVE checks should be suspended pending resolution of a
    fingerprint conflict" would silently never fire.
    """
    index: Dict[str, List[Dict[str, Any]]] = {}
    for asset_id, asset_conflicts in conflicts.items():
        asset = _as_dict(graph["assets"].get(asset_id))
        if _text(asset.get("asset_type")) != ASSET_TECHNOLOGY:
            continue
        name = _lower(_as_dict(asset.get("value")).get("name"))
        if not name:
            continue
        for conflict in asset_conflicts:
            if _text(conflict.get("attribute")) == "version":
                index.setdefault(name, []).append(conflict)
    return index


def _newest_timestamp(graph: Dict[str, Any]) -> Optional[str]:
    """
    The newest timestamp anywhere in the graph.

    Staleness is measured against the data itself rather than wall-clock
    "now", which keeps the assessment deterministic and makes "stale" mean
    "older than the rest of this reconnaissance run" rather than "old today".
    """
    newest = _text(graph.get("graph_updated_at"))
    for asset in graph["assets"].values():
        if isinstance(asset, dict):
            candidate = _text(asset.get("last_seen"))
            if candidate > newest:
                newest = candidate
    return newest or None


def _parse_timestamp(value: Any) -> Optional[datetime]:
    text = _text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def qualify_signals(
    signals: List[Dict[str, Any]],
    graph: Dict[str, Any],
    stale_after_days: Optional[float],
    errors: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Annotate signals with the qualifications that must survive into the
    report: unresolved conflicts, scope, and observation age.

    context.md §8 requires that a contradiction is preserved and surfaced,
    and names the concrete consequence: "version-dependent CVE checks should
    be suspended pending resolution of a fingerprint conflict". A CVE match
    against a technology whose version is disputed is therefore marked
    suspended — kept and reported in full, but excluded from driving an
    asset's score until the conflict is resolved.
    """
    conflicts = _conflict_index(graph)
    disputed_versions = _disputed_technology_versions(graph, conflicts)
    reference = _parse_timestamp(_newest_timestamp(graph))

    for signal in signals:
        subject_id = signal["subject_asset_id"]
        subject = _as_dict(graph["assets"].get(subject_id))
        signal["subject_asset_type"] = _text(subject.get("asset_type")) or None
        signal["subject_value"] = subject.get("value")
        signal["in_scope"] = subject.get("in_scope")
        signal["suspended"] = False
        signal["suspension_reason"] = None
        signal["conflicts"] = []
        signal["stale"] = False
        signal["age_days"] = None

        subject_conflicts = conflicts.get(subject_id, [])
        if subject_conflicts:
            signal["conflicts"] = [
                {"conflict_id": _text(c.get("id")) or f"conflict:{subject_id}:{c.get('attribute')}",
                 "attribute": _text(c.get("attribute")),
                 "observations": _as_list(c.get("observations"))}
                for c in subject_conflicts
            ]

        if signal["category"] == "vulnerability_intelligence":
            disputed = [c for c in subject_conflicts if _text(c.get("attribute")) == "version"]
            technology = _lower(signal.get("technology"))
            if technology:
                for conflict in disputed_versions.get(technology, []):
                    if conflict not in disputed:
                        disputed.append(conflict)
            if disputed:
                signal["suspended"] = True
                signal["suspension_reason"] = (
                    "context.md §8: a version-dependent CVE assessment is suspended while the "
                    "underlying version fingerprint is in unresolved conflict. The finding is "
                    "preserved and reported, but does not drive this asset's score until the "
                    "conflict is resolved."
                )
                signal["conflicts"] = [
                    {"conflict_id": _text(c.get("id")) or f"conflict:{_text(c.get('asset_id'))}:{c.get('attribute')}",
                     "attribute": _text(c.get("attribute")),
                     "asset_id": _text(c.get("asset_id")),
                     "observations": _as_list(c.get("observations"))}
                    for c in disputed
                ]

        try:
            observed = _parse_timestamp(signal.get("last_seen"))
            if reference is not None and observed is not None:
                age_days = (reference - observed).total_seconds() / 86400.0
                signal["age_days"] = round(max(age_days, 0.0), 3)
                if stale_after_days is not None and age_days > stale_after_days:
                    signal["stale"] = True
                    signal["notes"].append(
                        f"observation is {signal['age_days']} day(s) older than the newest evidence in "
                        f"this graph (threshold {stale_after_days}); it is preserved and reported but "
                        f"does not drive escalation"
                    )
        except Exception as exc:
            errors.append({"stage": "qualification", "signal_id": signal["signal_id"], "error": str(exc)})

    return signals


# ===========================================================================
# STAGE 4 — SCORING AND RELATIONSHIP CORRELATION
# ===========================================================================

def score_signal(signal: Dict[str, Any]) -> Dict[str, Any]:
    """
    Resolve one signal's final severity: base severity, then its own
    exploitability/class factors, then the confidence ceiling.

    The confidence ceiling is applied last and unconditionally, so no
    combination of factors can present weak evidence as certainty
    (context.md §8).
    """
    rationale: List[str] = []
    severity = signal["base_severity"]
    rationale.append(f"base severity {severity} — {signal['severity_basis']}")

    for factor in signal["factors"]:
        steps = int(factor.get("steps", 0) or 0)
        if steps:
            raised = shift_severity(severity, steps)
            if raised != severity:
                rationale.append(f"{severity} -> {raised}: {factor.get('reason')}")
                severity = raised
            else:
                rationale.append(f"factor recorded without change (already {severity}): {factor.get('reason')}")
        else:
            rationale.append(f"factor recorded: {factor.get('reason')}")

    ceiling = CONFIDENCE_SEVERITY_CAP[normalize_confidence(signal["confidence"])]
    capped = cap_severity(severity, ceiling)
    if capped != severity:
        rationale.append(
            f"{severity} -> {capped}: evidence confidence is {signal['confidence']}, so this is capped at "
            f"{ceiling} — context.md §8 forbids presenting insufficient evidence as certainty"
        )
        severity = capped
    else:
        rationale.append(f"evidence confidence {signal['confidence']} permits severity up to {ceiling}")

    if len(signal["corroborating_sources"]) > 1:
        rationale.append(
            "independently corroborated by "
            + ", ".join(signal["corroborating_sources"])
            + " — corroboration raises confidence (context.md §8), it is not counted as an extra signal"
        )

    signal["severity"] = severity
    signal["rationale"] = rationale
    signal["confirmed"] = signal["kind"] == KIND_CONFIRMED
    return signal


# ---------------------------------------------------------------------------
# Named cross-module correlation rules (context.md §10 item 20's own examples)
# ---------------------------------------------------------------------------

class CorrelationRule:
    """One named combination of converging signal categories on a single asset."""

    __slots__ = ("name", "required", "steps", "reason", "min_matches")

    def __init__(self, name: str, required: Sequence[str], steps: int, reason: str,
                 min_matches: Optional[int] = None):
        self.name = name
        self.required = tuple(required)
        self.steps = steps
        self.reason = reason
        self.min_matches = min_matches if min_matches is not None else len(required)

    def matches(self, categories: Sequence[str]) -> List[str]:
        present = [c for c in self.required if c in categories]
        return present if len(present) >= self.min_matches else []


CORRELATION_RULES: Tuple[CorrelationRule, ...] = (
    CorrelationRule(
        name="weak_transport_security_cluster",
        required=("missing_security_headers", "self_signed_certificate", "outdated_tls_version"),
        min_matches=3,
        steps=1,
        reason="context.md §10 item 20's own example: missing security headers + self-signed certificate "
               "+ outdated TLS converge into a combined higher severity",
    ),
    CorrelationRule(
        name="deprecated_api_with_leaked_credential",
        required=("deprecated_api_endpoint", "leaked_credential_in_public_code",
                  "secret_indicator_in_client_side_js"),
        min_matches=2,
        steps=1,
        reason="context.md §10 item 20's own example: a deprecated API combined with credential material "
               "leaked in public code is worse than either signal alone",
    ),
    CorrelationRule(
        name="deprecated_api_with_known_cve",
        required=("deprecated_api_endpoint", "vulnerability_intelligence"),
        min_matches=2,
        steps=1,
        reason="context.md §10 item 20 HIGH: 'deprecated APIs w/ known CVEs'",
    ),
)

# context.md §9: "Several MEDIUM/LOW signals converging on one asset can
# combine into CRITICAL", and §10 item 20 gives "6 converging signals on one
# asset" as its own example of cross-module correlation. Escalation is driven
# by the count of *distinct* converging signals, never by summed point values.
CONVERGENCE_THRESHOLDS: Tuple[Tuple[int, int], ...] = (
    (6, 2),   # >= 6 distinct converging signals -> two severity steps
    (3, 1),   # >= 3 distinct converging signals -> one severity step
)


def _relationship_index(graph: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Adjacency built once: asset_id -> relationships touching it."""
    index: Dict[str, List[Dict[str, Any]]] = {}
    for rel_id in sorted(graph["relationships"]):
        rel = graph["relationships"][rel_id]
        if not isinstance(rel, dict):
            continue
        for endpoint in (_text(rel.get("from_asset")), _text(rel.get("to_asset"))):
            if endpoint:
                index.setdefault(endpoint, []).append(rel)
    return index


def _owning_assets(asset_id: str, graph: Dict[str, Any],
                   adjacency: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Walk the relationship graph from a signal's subject towards the hosts/IPs
    that own it, so a weakness on an endpoint, port, technology or finding is
    also counted against the asset it belongs to (context.md §9: score
    relationships, not isolated findings).

    Returns one entry per owning asset with the relationship chain that
    justified the roll-up, so the explanation can state *how* a child signal
    reached its parent.
    """
    assets = graph["assets"]
    owners: Dict[str, Dict[str, Any]] = {}
    visited = {asset_id}
    frontier: List[Tuple[str, List[str]]] = [(asset_id, [])]

    for _ in range(MAX_ROLLUP_DEPTH):
        next_frontier: List[Tuple[str, List[str]]] = []
        for current, chain in frontier:
            for rel in adjacency.get(current, ()):
                # Roll up along the owning direction: the parent is the
                # `from_asset` of a relationship pointing at the current node.
                if _text(rel.get("to_asset")) != current:
                    continue
                parent = _text(rel.get("from_asset"))
                if not parent or parent in visited:
                    continue
                visited.add(parent)
                parent_chain = chain + [_text(rel.get("rel_type"))]
                parent_asset = _as_dict(assets.get(parent))
                if _text(parent_asset.get("asset_type")) in ROLLUP_ASSET_TYPES:
                    if parent not in owners:
                        owners[parent] = {"asset_id": parent, "relationship_chain": parent_chain}
                # Traversal continues past an owner rather than stopping at it:
                # context.md §7's hierarchy runs Domain -> Subdomain -> IP ->
                # Port -> Service, so a weakness on a port belongs to the IP
                # *and* to the hostname that resolves to it. Stopping at the
                # first owner would leave every port-level signal invisible to
                # the host a human actually investigates.
                next_frontier.append((parent, parent_chain))
        if not next_frontier:
            break
        frontier = next_frontier

    return [owners[key] for key in sorted(owners)]


def correlate_assets(signals: List[Dict[str, Any]], graph: Dict[str, Any],
                     errors: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Group scored signals onto the assets they bear on, following
    relationships, and record for each attachment whether it was direct or
    rolled up from a related asset.
    """
    adjacency = _relationship_index(graph)
    grouped: Dict[str, Dict[str, Any]] = {}

    def _bucket(asset_id: str) -> Dict[str, Any]:
        bucket = grouped.get(asset_id)
        if bucket is None:
            asset = _as_dict(graph["assets"].get(asset_id))
            bucket = {
                "asset_id": asset_id,
                "asset_type": _text(asset.get("asset_type")) or None,
                "value": asset.get("value"),
                "in_scope": asset.get("in_scope"),
                "discovery_state": _text(asset.get("state")) or None,
                "graph_confidence": _text(asset.get("confidence")) or None,
                "first_seen": asset.get("first_seen"),
                "last_seen": asset.get("last_seen"),
                "sources": sorted({_text(s) for s in _as_list(asset.get("sources")) if _text(s)}),
                "attachments": [],
            }
            grouped[asset_id] = bucket
        return bucket

    for signal in signals:
        subject_id = signal["subject_asset_id"]
        try:
            _bucket(subject_id)["attachments"].append({
                "signal_id": signal["signal_id"], "via": "direct", "relationship_chain": [],
            })
            # A `finding` asset is a container, not a risk subject in its own
            # right; its signals belong to whatever the finding describes.
            if _text(_as_dict(graph["assets"].get(subject_id)).get("asset_type")) == ASSET_FINDING:
                continue
            for owner in _owning_assets(subject_id, graph, adjacency):
                if owner["asset_id"] == subject_id:
                    continue
                _bucket(owner["asset_id"])["attachments"].append({
                    "signal_id": signal["signal_id"], "via": "relationship",
                    "relationship_chain": owner["relationship_chain"],
                    "from_asset": subject_id,
                })
        except Exception as exc:
            errors.append({"stage": "correlation", "signal_id": signal["signal_id"], "error": str(exc)})

    return grouped


def score_asset(bucket: Dict[str, Any], signals_by_id: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Produce one asset's severity and the full explanation of how it was
    reached.

    The asset's severity starts at the highest severity among the signals
    bearing on it, then escalates by convergence (context.md §9) and by the
    named correlation rules context.md itself gives as examples. Suspended and
    stale signals are reported but never drive escalation, and every step
    appends a line to `rationale`.
    """
    attachments = bucket["attachments"]
    attached = []
    seen_signal_ids = set()
    for attachment in attachments:
        signal = signals_by_id.get(attachment["signal_id"])
        if signal is None or attachment["signal_id"] in seen_signal_ids:
            continue
        seen_signal_ids.add(attachment["signal_id"])
        attached.append((attachment, signal))

    rationale: List[str] = []
    contributing = [
        (a, s) for a, s in attached
        if not s["suspended"] and not s["stale"] and severity_rank(s["severity"]) > SEVERITY_ORDER[SEVERITY_INFO]
    ]
    suspended = [s for _, s in attached if s["suspended"]]
    stale = [s for _, s in attached if s["stale"]]

    if not contributing:
        severity = SEVERITY_INFO
        rationale.append(
            "no signal above INFO bears on this asset — recorded as an attack-surface observation"
        )
    else:
        peak_attachment, peak_signal = max(
            contributing,
            key=lambda pair: (severity_rank(pair[1]["severity"]),
                              confidence_rank(pair[1]["confidence"]),
                              pair[1]["signal_id"]),
        )
        severity = peak_signal["severity"]
        via = ("directly" if peak_attachment["via"] == "direct"
               else "via " + " -> ".join(peak_attachment["relationship_chain"]))
        rationale.append(
            f"highest single signal is {severity} ({peak_signal['category']}, {via}): {peak_signal['summary']}"
        )

        # Convergence: count distinct underlying evidence, never repeats.
        distinct_keys = {s["evidence_key"] for _, s in contributing}
        distinct_categories = sorted({s["category"] for _, s in contributing})
        convergence = len(distinct_keys)

        # The generic convergence threshold and any named correlation rule are
        # two descriptions of the *same* convergence on this asset, so they are
        # combined with max(), never summed: escalating once for "3 signals
        # converged" and again for "those same 3 signals form a named cluster"
        # would count one body of evidence twice. Every reason that applied is
        # still recorded, so the explanation shows all of them.
        escalation = 0
        reasons: List[str] = []

        for threshold, steps in CONVERGENCE_THRESHOLDS:
            if convergence >= threshold:
                escalation = max(escalation, steps)
                reasons.append(
                    f"{convergence} distinct signals converge on this asset "
                    f"({', '.join(distinct_categories)}) — context.md §9: several converging signals "
                    f"on one asset combine into a higher severity"
                )
                break

        for rule in CORRELATION_RULES:
            present = rule.matches(distinct_categories)
            if not present:
                continue
            escalation = max(escalation, rule.steps)
            reasons.append(f"correlation rule {rule.name!r} matched ({', '.join(present)}) — {rule.reason}")

        if reasons:
            raised = shift_severity(severity, escalation)
            if raised != severity:
                rationale.append(f"{severity} -> {raised} (one escalation of {escalation} step(s), "
                                  f"the strongest that applies — overlapping reasons are not summed):")
                severity = raised
            else:
                rationale.append(f"correlation applies but severity is already {severity}:")
            rationale.extend(f"    - {reason}" for reason in reasons)

        # The escalated severity may not exceed what the evidence behind the
        # converging signals can support (context.md §8).
        best_confidence = max((s["confidence"] for _, s in contributing),
                              key=confidence_rank, default=CONFIDENCE_LOW)
        ceiling = CONFIDENCE_SEVERITY_CAP[best_confidence]
        capped = cap_severity(severity, ceiling)
        if capped != severity:
            rationale.append(
                f"{severity} -> {capped}: the strongest evidence behind these signals is {best_confidence} "
                f"confidence, capping the assessment at {ceiling} (context.md §8)"
            )
            severity = capped

    for signal in suspended:
        rationale.append(f"suspended, not scored: {signal['summary']} — {signal['suspension_reason']}")
    for signal in stale:
        rationale.append(
            f"stale, not scored: {signal['summary']} (observed {signal['age_days']} day(s) before the "
            f"newest evidence in this graph)"
        )

    confirmed = [s for _, s in attached if s["confirmed"]]
    indicators = [s for _, s in attached if s["kind"] == KIND_INDICATOR]
    vuln_intel = [s for _, s in attached if s["kind"] == KIND_VULN_INTEL]

    bucket.update({
        "severity": severity,
        "severity_rank": severity_rank(severity),
        "confidence": max((s["confidence"] for _, s in attached), key=confidence_rank, default=CONFIDENCE_LOW),
        "rationale": rationale,
        "signal_ids": sorted(seen_signal_ids),
        "signal_count": len(attached),
        "contributing_signal_count": len(contributing),
        "direct_signal_count": sum(1 for a, _ in attached if a["via"] == "direct"),
        "related_signal_count": sum(1 for a, _ in attached if a["via"] == "relationship"),
        "categories": sorted({s["category"] for _, s in attached}),
        "confirmed_finding_count": len(confirmed),
        "indicator_count": len(indicators),
        "vulnerability_intelligence_count": len(vuln_intel),
        "suspended_signal_ids": sorted(s["signal_id"] for s in suspended),
        "stale_signal_ids": sorted(s["signal_id"] for s in stale),
        "conflicts": sorted(
            {c["conflict_id"] for _, s in attached for c in s["conflicts"]}
        ),
    })
    return bucket


# ===========================================================================
# STAGE 5 — PRIORITIZATION AND OUTPUT
# ===========================================================================

# Asset types that are risk subjects a human investigates. Findings are
# containers; organizations and parameters are not investigation targets on
# their own.
_QUEUEABLE_ASSET_TYPES = frozenset({
    ASSET_HOSTNAME, ASSET_IP, ASSET_PORT, ASSET_ENDPOINT, ASSET_JAVASCRIPT,
    ASSET_TECHNOLOGY, ASSET_THIRD_PARTY,
})


def build_investigation_queue(assessed: List[Dict[str, Any]],
                              signals_by_id: Dict[str, Dict[str, Any]],
                              min_severity: str = SEVERITY_LOW) -> List[Dict[str, Any]]:
    """
    Build the prioritized investigation queue: what a human should look at,
    in order, and why.

    Ordering is fully deterministic — severity, then how many distinct signals
    converge, then confidence, then confirmed-signal count, then asset id as a
    final tiebreak — so the same graph always produces the same queue.

    `contributing_signal_count` is the number of signals that actually drove
    the score (above INFO, not suspended, not stale); `total_signal_count`
    additionally covers INFO observations and anything held back, so the two
    are reported separately rather than conflated.

    Assets known to be outside the authorized target scope are never queued.
    The queue is an instruction about where to direct further investigation,
    and context.md §16 / design principle 10 forbid directing activity at
    out-of-scope systems. Such assets remain fully present in
    `assessed_assets` with their evidence intact.
    """
    threshold = severity_rank(min_severity)
    candidates = [
        record for record in assessed
        if record.get("asset_type") in _QUEUEABLE_ASSET_TYPES
        and record.get("in_scope") is not False
        and severity_rank(record["severity"]) >= threshold
        and record["contributing_signal_count"] > 0
    ]

    candidates.sort(key=lambda r: (
        -severity_rank(r["severity"]),
        -r["contributing_signal_count"],
        -confidence_rank(r["confidence"]),
        -r["confirmed_finding_count"],
        r["asset_id"],
    ))

    queue: List[Dict[str, Any]] = []
    for rank, record in enumerate(candidates, start=1):
        signals = [signals_by_id[sid] for sid in record["signal_ids"] if sid in signals_by_id]
        top = sorted(
            (s for s in signals if not s["suspended"] and not s["stale"]),
            key=lambda s: (-severity_rank(s["severity"]), -confidence_rank(s["confidence"]), s["signal_id"]),
        )[:5]
        queue.append({
            "rank": rank,
            "asset_id": record["asset_id"],
            "asset_type": record["asset_type"],
            "value": record["value"],
            "severity": record["severity"],
            "confidence": record["confidence"],
            "in_scope": record["in_scope"],
            "contributing_signal_count": record["contributing_signal_count"],
            "total_signal_count": record["signal_count"],
            "categories": record["categories"],
            "confirmed_finding_count": record["confirmed_finding_count"],
            "indicator_count": record["indicator_count"],
            "vulnerability_intelligence_count": record["vulnerability_intelligence_count"],
            "unresolved_conflicts": record["conflicts"],
            "suspended_signal_ids": record["suspended_signal_ids"],
            "explanation": record["rationale"],
            "top_signals": [
                {"signal_id": s["signal_id"], "category": s["category"], "kind": s["kind"],
                 "severity": s["severity"], "confidence": s["confidence"], "summary": s["summary"],
                 "sources": s["sources"], "observation_ids": s["observation_ids"]}
                for s in top
            ],
            "note": (
                "Severity is a prioritization assessment of where to look first, not proof that "
                "anything here is exploitable (context.md §10 item 20)."
            ),
        })
    return queue


class RiskEngine:
    """
    ReconHound's risk assessment and prioritization layer.

    Consumes surface_mapper.py's correlated asset graph and produces a scored,
    explained, prioritized investigation queue. Evaluates evidence only: no
    network access, no scanning, no exploitation, and no instruction to act on
    an out-of-scope asset.
    """

    def __init__(
        self,
        graph: Any = None,
        output_dir: str = "output",
        state_filename: str = "surface_graph.json",
        assessment_filename: str = "risk_assessment.json",
        stale_after_days: Optional[float] = None,
        min_queue_severity: str = SEVERITY_LOW,
    ):
        if min_queue_severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid min_queue_severity {min_queue_severity!r}; must be one of {sorted(VALID_SEVERITIES)}"
            )
        if stale_after_days is not None:
            try:
                stale_after_days = float(stale_after_days)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"stale_after_days must be a number or None: {exc}") from exc
            if stale_after_days < 0:
                raise ValueError("stale_after_days must not be negative")

        self.output_dir = output_dir
        self.stale_after_days = stale_after_days
        self.min_queue_severity = min_queue_severity
        self.store = RiskAssessmentStore(output_dir=output_dir, filename=assessment_filename)

        raw_state = load_graph_state(graph, output_dir=output_dir, filename=state_filename)
        self.errors: List[Dict[str, Any]] = []
        self.graph = _normalize_graph(raw_state, self.errors)
        self.target = self.graph["target"]

    # -- pipeline ---------------------------------------------------------

    def assess(self) -> Dict[str, Any]:
        """
        Run the full pipeline and return the JSON-safe assessment document.

        Re-running on the same graph is a pure function of that graph: nothing
        is accumulated between runs, so repeated ingestion cannot inflate a
        score.
        """
        errors = list(self.errors)

        signals = extract_signals(self.graph, errors)
        signals = qualify_signals(signals, self.graph, self.stale_after_days, errors)
        for signal in signals:
            try:
                score_signal(signal)
            except Exception as exc:
                errors.append({"stage": "scoring", "signal_id": signal.get("signal_id"), "error": str(exc)})
                signal.setdefault("severity", SEVERITY_INFO)
                signal.setdefault("rationale", [f"scoring failed: {exc}"])
                signal.setdefault("confirmed", False)

        signals_by_id = {s["signal_id"]: s for s in signals}
        grouped = correlate_assets(signals, self.graph, errors)

        assessed: List[Dict[str, Any]] = []
        for asset_id in sorted(grouped):
            try:
                assessed.append(score_asset(grouped[asset_id], signals_by_id))
            except Exception as exc:
                errors.append({"stage": "asset_scoring", "asset_id": asset_id, "error": str(exc)})
        assessed.sort(key=lambda r: (-severity_rank(r["severity"]), r["asset_id"]))

        queue = build_investigation_queue(assessed, signals_by_id, self.min_queue_severity)

        assessment = {
            "module": MODULE_NAME,
            "target": self.target,
            "generated_at": _now(),
            "graph_updated_at": self.graph.get("graph_updated_at"),
            "newest_evidence_at": _newest_timestamp(self.graph),
            "settings": {
                "stale_after_days": self.stale_after_days,
                "min_queue_severity": self.min_queue_severity,
            },
            "summary": self._summarize(signals, assessed, queue),
            "investigation_queue": queue,
            "assessed_assets": assessed,
            "signals": signals,
            "out_of_scope_assets": sorted(
                r["asset_id"] for r in assessed if r.get("in_scope") is False
            ),
            "suspended_signals": [
                {"signal_id": s["signal_id"], "category": s["category"],
                 "subject_asset_id": s["subject_asset_id"], "summary": s["summary"],
                 "reason": s["suspension_reason"], "conflicts": s["conflicts"]}
                for s in signals if s["suspended"]
            ],
            "unresolved_conflicts": [
                {"conflict_id": _text(c.get("id")), "asset_id": _text(c.get("asset_id")),
                 "attribute": _text(c.get("attribute")), "observations": _as_list(c.get("observations"))}
                for asset_conflicts in _conflict_index(self.graph).values()
                for c in asset_conflicts
            ],
            "errors": errors,
            "notes": [
                "Severity is a prioritization assessment, not proof of exploitability "
                "(context.md §10 item 20).",
                "Indicators and CVE matches are never reported as confirmed findings, regardless of "
                "how much corroboration accumulates.",
                "Assets outside the authorized target scope are assessed and reported but never "
                "placed in the investigation queue (context.md §16).",
            ],
        }
        return _json_safe(assessment)

    def _summarize(self, signals: List[Dict[str, Any]], assessed: List[Dict[str, Any]],
                   queue: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_severity = {name: 0 for name in SEVERITY_ORDER}
        for record in assessed:
            by_severity[record["severity"]] = by_severity.get(record["severity"], 0) + 1
        signals_by_severity = {name: 0 for name in SEVERITY_ORDER}
        for signal in signals:
            signals_by_severity[signal["severity"]] = signals_by_severity.get(signal["severity"], 0) + 1
        by_kind = {kind: 0 for kind in sorted(VALID_KINDS)}
        for signal in signals:
            by_kind[signal["kind"]] = by_kind.get(signal["kind"], 0) + 1
        return {
            "assets_assessed": len(assessed),
            "assets_by_severity": by_severity,
            "signals": len(signals),
            "signals_by_severity": signals_by_severity,
            "signals_by_evidence_class": by_kind,
            "queue_length": len(queue),
            "suspended_signals": sum(1 for s in signals if s["suspended"]),
            "stale_signals": sum(1 for s in signals if s["stale"]),
            "out_of_scope_assets": sum(1 for r in assessed if r.get("in_scope") is False),
        }

    def run(self, persist: bool = True) -> Dict[str, Any]:
        """Assess and (by default) persist to <output_dir>/risk_assessment.json."""
        assessment = self.assess()
        if persist:
            assessment["output_path"] = self.store.save(assessment)
        return assessment


def run_risk_engine(
    graph: Any = None,
    output_dir: str = "output",
    state_filename: str = "surface_graph.json",
    assessment_filename: str = "risk_assessment.json",
    stale_after_days: Optional[float] = None,
    min_queue_severity: str = SEVERITY_LOW,
    persist: bool = True,
) -> Dict[str, Any]:
    """Single-call entry point: load the graph, assess it, optionally persist."""
    engine = RiskEngine(
        graph=graph, output_dir=output_dir, state_filename=state_filename,
        assessment_filename=assessment_filename, stale_after_days=stale_after_days,
        min_queue_severity=min_queue_severity,
    )
    return engine.run(persist=persist)


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="risk_engine.py",
        description="ReconHound Module 20 — relationship-based risk prioritization (standalone entry point).",
    )
    parser.add_argument("--output-dir", default="output",
                        help="Directory containing surface_graph.json and receiving risk_assessment.json")
    parser.add_argument("--graph", default=None,
                        help="Path to a surface_graph.json (defaults to <output-dir>/surface_graph.json)")
    parser.add_argument("--min-severity", default=SEVERITY_LOW, choices=sorted(VALID_SEVERITIES),
                        help="Lowest severity to include in the investigation queue")
    parser.add_argument("--stale-after-days", type=float, default=None,
                        help="Flag signals older than this many days relative to the newest evidence in the graph")
    parser.add_argument("--no-persist", action="store_true", help="Do not write risk_assessment.json")
    parser.add_argument("--queue-only", action="store_true", help="Print only the investigation queue")
    args = parser.parse_args()

    assessment = run_risk_engine(
        graph=args.graph, output_dir=args.output_dir, stale_after_days=args.stale_after_days,
        min_queue_severity=args.min_severity, persist=not args.no_persist,
    )
    if args.queue_only:
        print(json.dumps(assessment["investigation_queue"], indent=2))
    else:
        print(json.dumps({
            "target": assessment["target"],
            "summary": assessment["summary"],
            "investigation_queue": assessment["investigation_queue"],
            "errors": assessment["errors"],
            "output_path": assessment.get("output_path"),
        }, indent=2))


if __name__ == "__main__":
    _main()
