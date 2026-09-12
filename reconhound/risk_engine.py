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
categories of weakness converging on one asset*, never by summing invented
point values. Signals that rest on the same underlying evidence are merged
before counting (see `evidence_key`), so re-ingesting a graph, or two modules
reporting the same fact, cannot inflate a score; repeated instances of one
category (the same missing header on six pages, six CVEs against one nginx,
six third-party scripts) count once, and pure surface observations
(KIND_OBSERVATION) never count as converging risk. Independent corroboration
of the same fact is recorded as `corroborating_sources` and raises the
signal's *confidence* (the §8 treatment of converging evidence), not the
convergence count. Every escalation is bounded by the confidence of the
evidence that justified it — the N-th best confidence for an N-signal
convergence, the weakest required category for a named rule — so weak
evidence cannot escalate itself past what it can support.

ATTRIBUTION (context.md §7/§9): a signal rolls up to the hosts and IPs that
*contain* its subject, along ROLLUP_RELATIONSHIP_TYPES only. Certificate
SANs, CNAME aliases and JavaScript references are identity/reference links,
not containment, and are never followed; a finding under one hostname never
crosses a shared IP onto a sibling hostname; and IP-level signals fan out to
resolving hostnames only up to MAX_SHARED_IP_ROLLUP_HOSTNAMES, beyond which
they stay on the IP with the suppression recorded. Sharing below the bound is
annotated as attribution ambiguity rather than resolved either way.

NEGATIVE-EVIDENCE SEMANTICS (context.md §8): a signal is never lowered
because a check produced nothing. vuln_intel.py's KEV / Exploit-DB / EPSS
annotations are read as three states (listed / checked-not-listed /
not-checked) and only a listing is ever an escalation factor; a provider
outage is reported as unknown, not as absence. Persisted records of checks
that did not complete (`*_fetch_failed`, `*_check_inconclusive`,
`*_not_probed`, an exposure probe that errored or was rate-limited) become
`inconclusive_check:*` observations: preserved, never scored, never read as
clean.

--------------------------------------------------------------------------
FACTORS DELIBERATELY NOT IMPLEMENTED

"Exposure" and "asset criticality" weightings are not defined anywhere in
context.md v1.0, and no producing module emits a value for either. Inventing
a weighting for them would be inventing architecture, so this module does
not. Exploitability is implemented only to the extent the repository
supplies it — vuln_intel.py's CISA KEV and Exploit-DB annotations — and even
then only as a prioritization factor that can never convert an unconfirmed
match into a confirmed one. vuln_intel.py's EPSS score is carried as
structured prioritization context (`intelligence_status.epss`, a zero-step
factor) and never as a severity step: context.md defines no EPSS weighting,
and a likelihood estimate about a CVE is not evidence about this target.

--------------------------------------------------------------------------
DETERMINISM

Given the same graph, `assess()` produces byte-identical output except for
`generated_at`. All iteration is over sorted keys, all identifiers are
content hashes, and no scoring input depends on wall-clock time. Observation
age is measured against the newest parseable timestamp in the graph itself
rather than "now", so staleness is a property of the data, not of when the
engine ran. Two records of the same evidence are merged with a deterministic
primary (highest severity, then confidence, then newest), never "whichever
asset id sorts first".

--------------------------------------------------------------------------
INPUT SAFETY

Every human-facing string this module emits (summaries, evidence, notes) is
built from values other modules extracted from network data. They are
control-character/bidi-escaped and length-bounded (MAX_SUMMARY_CHARS,
MAX_EVIDENCE_ITEM_CHARS, MAX_EVIDENCE_ITEMS with an explicit
`evidence_truncated` count) because a summary is copied into every asset and
queue record that cites it. The producing module's `detail` is carried
verbatim, once, as the evidence of record. Numeric intelligence (CVSS, EPSS)
is accepted only inside its published range; NaN, Infinity and out-of-range
values are recorded as rejected rather than mapped to a severity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
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

# ---------------------------------------------------------------------------
# Conflict-kind vocabulary — surface_mapper.py's, duplicated rather than
# imported (context.md §12.2 modular independence), exactly as the severity
# and confidence vocabularies above are.
#
# context.md §8's "version-dependent CVE checks should be suspended pending
# resolution of a fingerprint conflict" is about *modules disagreeing*. One
# module observing a different version a month later is an upgrade, not a
# disputed fingerprint, and suspending on it would disable the vulnerability
# intelligence of every repeat scan of a target that patches anything.
# ---------------------------------------------------------------------------

CONFLICT_CROSS_SOURCE = "cross_source"
CONFLICT_TEMPORAL = "temporal"

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
REL_ASSET_TO_ENDPOINT = "asset_to_endpoint"
REL_ENDPOINT_TO_PARAMETER = "endpoint_to_parameter"
REL_ASSET_TO_TECHNOLOGY = "asset_to_technology"
REL_ASSET_TO_JAVASCRIPT = "asset_to_javascript"
REL_IP_TO_SERVICE = "ip_to_service"
REL_HOSTNAME_TO_IP = "hostname_to_ip"
REL_IP_TO_VHOST = "ip_to_vhost"
REL_SUBDOMAIN_TO_THIRD_PARTY = "subdomain_to_third_party"

# The asset types a risk subject rolls up to. context.md §9 asks for scoring
# over relationships: a weakness on an endpoint or a port is ultimately a
# weakness of the host that owns it, so signals converge on hosts and IPs.
ROLLUP_ASSET_TYPES = (ASSET_HOSTNAME, ASSET_IP)

# The relationship types along which a signal is *owned* by the parent, and
# therefore may roll up (context.md §7's containment hierarchy). Deliberately
# an allowlist: surface_mapper.py also records relationships that are
# identity or reference links, not containment — `certificate_san` (a name
# on a certificate), `hostname_to_cname` (an alias), `javascript_to_endpoint`
# (a script mentioning a URL), `domain_to_organization` — and rolling a
# weakness up along those attributed one host's findings to every host that
# merely shared a certificate, aliased it, or referenced it from a script.
ROLLUP_RELATIONSHIP_TYPES = frozenset({
    REL_ASSET_TO_FINDING, REL_ASSET_TO_ENDPOINT, REL_ENDPOINT_TO_PARAMETER,
    REL_ASSET_TO_TECHNOLOGY, REL_ASSET_TO_JAVASCRIPT, REL_IP_TO_SERVICE,
    REL_HOSTNAME_TO_IP, REL_IP_TO_VHOST, REL_SUBDOMAIN_TO_THIRD_PARTY,
})

# How far a signal may roll up through the relationship graph. The deepest
# chain in context.md §7's asset graph (hostname -> ip -> port -> technology,
# or hostname -> endpoint -> parameter) is well inside this bound.
MAX_ROLLUP_DEPTH = 4

# Shared-infrastructure attribution bound. An IP-level signal (an exposed
# port, a service finding) belongs to the hostnames that resolve to that IP,
# but when an IP is shared by many hostnames — a CDN edge, a load balancer, a
# wildcard DNS record — attributing one exposed port to every one of them is
# not correlation, it is the same fact replicated N times. Above this many
# resolving hostnames the signal stays on the IP, which carries the full
# severity, and the suppression is recorded on the signal, on the IP's record
# and in the summary; below it the roll-up proceeds with the sharing noted.
MAX_SHARED_IP_ROLLUP_HOSTNAMES = 32

# Bounds on the human-facing text this module emits. Summaries, evidence and
# notes are built from values other modules extracted from network data, and
# a summary is copied into every asset/queue record that cites it, so an
# unbounded string here is amplified several times over in the output.
MAX_SUMMARY_CHARS = 512
MAX_EVIDENCE_ITEM_CHARS = 1024
MAX_EVIDENCE_ITEMS = 64
MAX_NOTE_CHARS = 1024


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


# Control characters and Unicode bidi-formatting overrides. Same treatment the
# other hardened modules give provider text: escaped to their literal
# `\xNN`/`\uNNNN` spelling rather than deleted, so an operator can still see
# exactly what arrived while it can no longer drive a terminal or reorder a
# rendered line.
_UNSAFE_TEXT_RE = re.compile(
    "[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]"
)


def _escape_unsafe(match: "re.Match[str]") -> str:
    code = ord(match.group(0))
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def _clip(value: str, limit: int) -> str:
    """Length-clip a string, marking that it was clipped."""
    if len(value) <= limit:
        return value
    return value[:limit] + f"...[clipped {len(value) - limit} chars]"


def _safe_text(value: Any, limit: int = MAX_SUMMARY_CHARS) -> str:
    """Make a string derived from network data safe to persist, print and report."""
    text = _text(value)
    if not text:
        return text
    return _clip(_UNSAFE_TEXT_RE.sub(_escape_unsafe, text), limit)


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
                self._fsync_dir(dir_name)
            except BaseException:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                raise
            return self.path

    @staticmethod
    def _fsync_dir(dir_name: str) -> None:
        """
        Durably commit the os.replace() rename itself; without it the new
        file's contents are on disk but the directory entry may not be.
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

# exposure_scan.py's own outcome vocabulary for "this path was never actually
# tested" (DT_ERROR / DT_RATE_LIMITED / DT_SERVER_ERROR / DT_UNEXPECTED_STATUS)
# and its cloud equivalents. Such a record is neither a discovery nor a
# negative result and must never be read as either (context.md §8).
_INCONCLUSIVE_DISCOVERY_TYPES = frozenset({
    "error", "rate_limited", "server_error_response", "unexpected_status",
    "provider_refused_inconclusive", "inconclusive_cloud_response",
})

# Finding types whose name says the check did not complete or was not made:
# js_analyzer_fetch_failed, supply_chain_dns_lookup_failed,
# wayback_intel_check_inconclusive, cloud_candidate_not_probed,
# js_analyzer_skipped_out_of_scope, ... They are persisted so a later run can
# tell "not checked" from "checked and clean"; they are not risk findings.
_INCONCLUSIVE_TYPE_MARKERS = (
    "_fetch_failed", "_lookup_failed", "_check_inconclusive", "_inconclusive",
    "_not_probed", "_skipped_out_of_scope",
)

# TLS versions context.md §10 item 17 calls out as outdated.
_OUTDATED_TLS_VERSIONS = ("tlsv1.0", "tlsv1.1", "tls1.0", "tls1.1", "sslv2", "sslv3")

# Security headers whose absence context.md §10 item 16 tracks.
_TRACKED_SECURITY_HEADERS = (
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
)

# Advisory wording that describes the "RCE-class" of context.md §10 item 20.
# Matched on word boundaries (so "FORCE" never contains "rce") and including
# NVD's canonical "execute arbitrary code/commands" phrasing.
_RCE_PATTERN_RE = re.compile(
    r"\b(?:"
    r"remote code execution|arbitrary code execution|arbitrary command execution|"
    r"execut(?:e|es|ing|ion of) arbitrary (?:code|commands?|os commands?|shell commands?)|"
    r"arbitrary commands?|command injection|code injection|"
    r"(?:unauthenticated |pre-auth(?:enticated)? )?rce|"
    r"deserialization of untrusted data"
    r")\b"
)
# A negation that directly governs the phrase means the advisory is saying
# what the flaw is NOT ("this is not a remote code execution vulnerability",
# "does not allow arbitrary code execution", "cannot lead to RCE"). It must
# be joined to the phrase by nothing but a short chain of linking words:
# NVD's own "does not properly validate input, leading to remote code
# execution" is an affirmative RCE and must stay one.
_RCE_NEGATION_RE = re.compile(
    r"\b(?:not|no|never|cannot|can't|without|unlike|rather than|instead of|isn't|is not|"
    r"does not|doesn't|do not|don't|prevents?|preventing|mitigates?|blocks?)\b"
    r"(?:\s+(?:a|an|the|any|to|be|been|being|lead|leading|result|resulting|used|for|in|of|"
    r"allow|allowing|permit|permitting|enable|enabling|achieve|cause|causing|possible|"
    r"exploited|exploitable|considered|actually|directly|itself|known|vulnerable|susceptible))*"
    r"[\s,]*$"
)
_CLAUSE_BOUNDARY_RE = re.compile(r"[.;:!?]")
_RCE_NEGATION_WINDOW = 60


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
    rejected: List[str] = []
    for entry in _as_list(detail.get("cvss")):
        entry = _as_dict(entry)
        raw = entry.get("score")
        score: Optional[float]
        if isinstance(raw, bool):
            score = float("nan")     # a boolean is not a score; rejected below
        else:
            try:
                score = float(raw) if raw is not None else None
            except (TypeError, ValueError):
                score = None
        # NaN compares false against every threshold and would have mapped to
        # INFO ("harmless"); Infinity and out-of-range values would have mapped
        # to CRITICAL. Neither is a CVSS score, so neither is allowed to be one.
        if score is not None and not (math.isfinite(score) and 0.0 <= score <= 10.0):
            rejected.append(_safe_text(raw, 64))
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

    if rejected:
        notes.append(
            f"ignored {len(rejected)} CVSS score value(s) outside the published 0.0-10.0 range or not "
            f"numeric ({', '.join(rejected[:5])}); severity is derived from the remaining evidence only"
        )

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


def _rce_mentions(detail: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """
    (affirmative, negated) RCE-class phrases found in the advisory summaries.

    A phrase is negated when a negation token in the same clause is joined to
    it by nothing but linking words (see _RCE_NEGATION_RE). Only affirmative
    mentions may drive an escalation; negated ones are reported so the reader
    can see why RCE wording did not count. This is a bounded lexical check,
    not language understanding: an advisory that negates in some other
    construction is still counted, which errs toward reporting, never toward
    silence.
    """
    affirmative: List[str] = []
    negated: List[str] = []
    for summary in _as_list(detail.get("summaries")):
        if not isinstance(summary, str):
            continue     # advisory text is text; a nested structure here is malformed, not wording
        text = summary.lower()
        for match in _RCE_PATTERN_RE.finditer(text):
            window_start = max(0, match.start() - _RCE_NEGATION_WINDOW)
            window = text[window_start:match.start()]
            boundary = list(_CLAUSE_BOUNDARY_RE.finditer(window))
            if boundary:
                window = window[boundary[-1].end():]
            phrase = match.group(0)
            if _RCE_NEGATION_RE.search(window):
                negated.append(phrase)
            else:
                affirmative.append(phrase)
    return sorted(set(affirmative)), sorted(set(negated))


def _looks_rce(detail: Dict[str, Any]) -> bool:
    return bool(_rce_mentions(detail)[0])


def _inapplicable_security_headers(detail: Dict[str, Any]) -> List[str]:
    """
    Tracked headers whose absence the *protocol* makes meaningless here.

    Only Strict-Transport-Security qualifies, and only over plaintext HTTP.
    RFC 6797 §7.2 forbids a host from sending the STS header over non-secure
    transport and §8.1 requires a user agent to ignore one that arrives that
    way, so its absence from an http:// response is not a configuration
    weakness — it is the only conforming behaviour. Reporting it made every
    plaintext origin carry a MEDIUM "missing security headers" signal that no
    change to the server could ever clear, and pushed the genuine finding
    (that the origin serves plaintext at all, which redirect-chain and cookie
    analysis do report) down the queue behind it.

    Every other tracked header is honoured by browsers over HTTP as well as
    HTTPS, so none of them is scheme-dependent.
    """
    url = _text(detail.get("url")) or _text(_as_dict(detail.get("provenance")).get("final_url"))
    if url.lower().startswith("http://"):
        return ["Strict-Transport-Security"]
    return []


def _missing_security_headers(detail: Dict[str, Any]) -> List[str]:
    headers = _as_dict(detail.get("headers"))
    inapplicable = set(_inapplicable_security_headers(detail))
    missing = []
    for name in _TRACKED_SECURITY_HEADERS:
        entry = _as_dict(headers.get(name))
        if name in headers and not entry.get("present") and name not in inapplicable:
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
        basis="context.md §10 item 20 LOW: 'minor informational' — resource exists but listing was denied "
              "or untested (exposure_scan.py: bucket_exists_access_restricted / bucket_exists_region_redirect)",
        match=lambda detail, meta: _lower(detail.get("discovery_type")) in (
            "bucket_exists_access_restricted", "bucket_exists_region_redirect"),
        describe=lambda detail: (
            f"{detail.get('provider')} storage {detail.get('identifier')!r} exists but "
            + ("listing is denied" if _lower(detail.get("discovery_type")) == "bucket_exists_access_restricted"
               else "is served from another region; listability was not tested")
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
        basis="context.md §10 item 20 LOW: 'minor informational' — resource present but not readable, "
              "or responding without the content signature that would confirm exposure",
        match=lambda detail, meta: (
            _text(detail.get("exposure_category")) != ""
            and not _confirmed(detail)
            and _lower(detail.get("discovery_type")) in (
                "access_restricted", "redirect", "method_not_allowed", "interesting_unconfirmed")
        ),
        describe=lambda detail: (
            f"{detail.get('exposure_category')} "
            + ("responded but exposure was not confirmed by content"
               if _lower(detail.get("discovery_type")) == "interesting_unconfirmed"
               else "present but not readable")
            + f" at {detail.get('url')} ({detail.get('discovery_type')})"
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
                                        metadata: Dict[str, Any],
                                        observation_metadata: Optional[Sequence[Dict[str, Any]]] = None
                                        ) -> Dict[str, Any]:
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
    # vuln_intel.py keeps `cisa_kev` / `exploitdb_references` as the listing
    # itself and carries the checked-vs-unavailable distinction in additive
    # `*_status` objects (in `metadata` since its hardening, in the value on
    # older graphs). Absence of a listing is therefore three different facts —
    # checked and not listed, provider unavailable, or not recorded at all —
    # and only the first is a negative result (context.md §8).
    kev = detail.get("cisa_kev")
    exploitdb = _as_list(detail.get("exploitdb_references"))
    intelligence = _intelligence_status(detail, metadata, kev, exploitdb)
    # `metadata` is the newest observation's annotation state. Every earlier
    # observation of this same finding is consulted too, so a run whose KEV
    # feed was down cannot overwrite an earlier run's "checked, not listed"
    # (or listing) with "unknown".
    combined_from_history = False
    for earlier in observation_metadata or ():
        candidate = _intelligence_status(detail, _as_dict(earlier), kev, exploitdb)
        combined = _combine_intelligence(intelligence, candidate)
        if combined != intelligence:
            combined_from_history = True
            intelligence = combined
    if combined_from_history:
        notes.append("exploitability intelligence combines every observation of this finding; a later "
                     "provider outage does not erase what an earlier run established")
    if intelligence["cisa_kev"] == "not_checked":
        notes.append(
            "CISA KEV status is UNKNOWN for this run (catalog not available: "
            f"{intelligence['cisa_kev_reason'] or 'no reason recorded'}) — not evidence that the CVE is "
            "absent from the catalog; no exploitability factor applied either way"
        )
    elif intelligence["cisa_kev"] == "unknown":
        notes.append("no CISA KEV check status was recorded for this CVE; KEV status is unknown, not negative")
    if intelligence["exploitdb"] == "not_checked":
        notes.append(
            "Exploit-DB status is UNKNOWN for this run (index not available: "
            f"{intelligence['exploitdb_reason'] or 'no reason recorded'}) — an empty reference list here "
            "is not evidence that no public exploit exists"
        )
    elif intelligence["exploitdb"] == "unknown":
        notes.append("no Exploit-DB check status was recorded for this CVE; public-exploit status is unknown")
    if intelligence["cisa_kev"] == "listed":
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

    epss = intelligence["epss"]
    if epss["status"] == "scored":
        # EPSS is an exploitation-LIKELIHOOD estimate for the CVE in general.
        # It is recorded as prioritization context and never as a severity
        # step: context.md defines no EPSS weighting, and a likelihood
        # estimate about the CVE is not evidence about this target.
        factors.append({
            "factor": "epss_exploitation_likelihood",
            "steps": 0,
            "reason": (f"EPSS {epss['score']}" + (f" (percentile {epss['percentile']})" if epss.get("percentile") is not None else "")
                       + (f" as of {epss['date']}" if epss.get("date") else "")
                       + " — exploitation-likelihood estimate for the CVE itself, not evidence about this "
                         "target; recorded for prioritization context without escalation"),
        })
    elif epss["status"] == "not_checked":
        notes.append(f"EPSS not checked for this run ({epss.get('reason') or 'provider unavailable'}); "
                     f"exploitation likelihood is unknown, not low")

    rce_affirmed, rce_negated = _rce_mentions(detail)
    if rce_affirmed:
        if applicability == "version_range_confirmed":
            factors.append({
                "factor": "rce_class_vulnerability",
                "steps": 1,
                "reason": f"advisory text describes remote/arbitrary code execution ({', '.join(rce_affirmed)}) "
                          "and the detected version falls in the vulnerable range (context.md CRITICAL: "
                          "'RCE-class CVEs')",
            })
        else:
            notes.append(
                "advisory text describes remote/arbitrary code execution, but version applicability "
                "is unconfirmed — recorded without escalation"
            )
    elif rce_negated:
        notes.append(
            f"advisory text mentions {', '.join(rce_negated)} only in a negated clause; "
            f"not treated as an RCE-class vulnerability"
        )

    return {
        "base_severity": severity,
        "severity_unknown": severity_unknown,
        "cvss_score": score,
        "applicability": applicability,
        "confidence": confidence,
        "confidence_dimensions": _confidence_dimensions(detail, applicability_ceiling, confidence),
        "intelligence_status": intelligence,
        "factors": factors,
        "notes": notes,
    }


_VALID_EPSS_STATUSES = ("scored", "no_score", "not_checked", "unknown")
_KEV_RANK = {"listed": 3, "not_listed": 2, "not_checked": 1, "unknown": 0}
_EDB_RANK = {"references": 3, "none": 2, "not_checked": 1, "unknown": 0}
_EPSS_RANK = {"scored": 3, "no_score": 2, "not_checked": 1, "unknown": 0}


def _combine_intelligence(base: Dict[str, Any], other: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combine two intelligence-status views of the same CVE by strength.

    KEV membership, public-exploit references and EPSS are properties of the
    CVE, not of the observation: a run that could not reach the KEV catalog
    says nothing that undoes a run that found the listing, and "checked, not
    listed" is knowledge that a later outage does not erase. Knowledge is
    therefore never overwritten by the newer record — listed > checked-not-
    listed > not-checked > unknown.
    """
    merged = dict(base)
    if _KEV_RANK.get(other.get("cisa_kev"), 0) > _KEV_RANK.get(base.get("cisa_kev"), 0):
        merged["cisa_kev"], merged["cisa_kev_reason"] = other.get("cisa_kev"), other.get("cisa_kev_reason")
    if _EDB_RANK.get(other.get("exploitdb"), 0) > _EDB_RANK.get(base.get("exploitdb"), 0):
        merged["exploitdb"], merged["exploitdb_reason"] = other.get("exploitdb"), other.get("exploitdb_reason")
    base_epss, other_epss = _as_dict(base.get("epss")), _as_dict(other.get("epss"))
    if _EPSS_RANK.get(other_epss.get("status"), 0) > _EPSS_RANK.get(base_epss.get("status"), 0):
        merged["epss"] = dict(other_epss)
    return merged


def _intelligence_status(detail: Dict[str, Any], metadata: Dict[str, Any],
                         kev: Any, exploitdb: List[Any]) -> Dict[str, Any]:
    """
    Resolve vuln_intel.py's KEV / Exploit-DB / EPSS annotations into explicit
    three-state outcomes. `metadata` is the latest observation's annotation
    state (surface_mapper.py keeps it per observation; the newest wins), and
    the persisted value is consulted for graphs written before the annotation
    state moved there. "unknown" means no status was recorded at all, which
    is distinct from "not_checked" (a recorded provider failure).
    """
    kev_status = _as_dict(metadata.get("cisa_kev_status")) or _as_dict(detail.get("cisa_kev_status"))
    if kev or kev_status.get("listed") is True or metadata.get("cisa_kev_listed") is True:
        kev_state = "listed"
    elif kev_status.get("checked") is True or metadata.get("cisa_kev_checked") is True:
        kev_state = "not_listed"
    elif kev_status.get("checked") is False or metadata.get("cisa_kev_checked") is False:
        kev_state = "not_checked"
    else:
        kev_state = "unknown"

    edb_status = _as_dict(metadata.get("exploitdb_status")) or _as_dict(detail.get("exploitdb_status"))
    if exploitdb:
        edb_state = "references"
    elif edb_status.get("checked") is True or metadata.get("exploitdb_checked") is True:
        edb_state = "none"
    elif edb_status.get("checked") is False or metadata.get("exploitdb_checked") is False:
        edb_state = "not_checked"
    else:
        edb_state = "unknown"

    epss_raw = _as_dict(metadata.get("epss")) or _as_dict(detail.get("epss"))
    epss: Dict[str, Any] = {"status": "unknown", "score": None, "percentile": None, "date": None, "reason": None}
    if epss_raw:
        score = _finite_unit_interval(epss_raw.get("score"))
        if epss_raw.get("checked") is False:
            epss.update(status="not_checked", reason=_safe_text(epss_raw.get("reason"), 256) or None)
        elif score is not None:
            epss.update(status="scored", score=score,
                        percentile=_finite_unit_interval(epss_raw.get("percentile")),
                        date=_safe_text(epss_raw.get("date"), 64) or None)
        elif epss_raw.get("checked") is True:
            epss.update(status="no_score", reason=_safe_text(epss_raw.get("reason"), 256) or None)
    elif metadata.get("epss_checked") is True and _finite_unit_interval(metadata.get("epss_score")) is not None:
        epss.update(status="scored", score=_finite_unit_interval(metadata.get("epss_score")))
    elif metadata.get("epss_checked") is False:
        epss.update(status="not_checked")

    return {
        "cisa_kev": kev_state,
        "cisa_kev_reason": _safe_text(kev_status.get("reason"), 256) or None,
        "exploitdb": edb_state,
        "exploitdb_reason": _safe_text(edb_status.get("reason"), 256) or None,
        "epss": epss,
    }


def _finite_unit_interval(value: Any) -> Optional[float]:
    """A float in [0, 1], or None — NaN, Infinity and out-of-range values are not scores."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and 0.0 <= number <= 1.0 else None


def _confidence_dimensions(detail: Dict[str, Any], applicability_ceiling: str,
                           final: str) -> Dict[str, Optional[str]]:
    """
    Keep vuln_intel.py's separate confidence dimensions visible alongside the
    single value this module scores with, so a report can say *which* part of
    the chain (technology identification, version mapping, source agreement,
    applicability) limited the conclusion rather than collapsing them.
    """
    model = _as_dict(detail.get("confidence_model"))
    def _level(value: Any) -> Optional[str]:
        return value if value in VALID_CONFIDENCES else None
    return {
        "technology_identification": _level(model.get("technology_confidence")),
        "version_mapping": _level(model.get("mapping_confidence")),
        "source_agreement": _level(model.get("source_confidence")),
        "producer_final": _level(model.get("final_confidence")) or _level(detail.get("confidence")),
        "applicability_ceiling": applicability_ceiling,
        "scored": final,
    }


def _observation_records(graph: Dict[str, Any], observation_ids: Iterable[Any]) -> List[Dict[str, Any]]:
    """
    The observation records behind an asset, oldest first.

    Ordered by the timestamp each record declares (then by id) rather than by
    ingestion order, so "latest wins" for merged metadata means the newest
    evidence, not whichever pending_assets.json happened to be read last.
    """
    observations = graph["observations"]
    records = []
    for obs_id in observation_ids:
        record = observations.get(obs_id) if isinstance(obs_id, str) else None
        if isinstance(record, dict):
            records.append(record)
    records.sort(key=lambda r: (_text(r.get("timestamp")), _text(r.get("observation_id"))))
    return records


def _bounded_evidence(items: Iterable[Any]) -> Tuple[List[str], int]:
    """Distinct, sanitized, length- and count-bounded evidence strings plus the number left out."""
    kept: List[str] = []
    seen = set()
    dropped = 0
    for item in items:
        text = _safe_text(item, MAX_EVIDENCE_ITEM_CHARS)
        if not text or text in seen:
            continue
        seen.add(text)
        if len(kept) >= MAX_EVIDENCE_ITEMS:
            dropped += 1
            continue
        kept.append(text)
    return kept, dropped


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
    source_asset_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Assemble one normalized risk signal. Purely structural — no scoring here."""
    evidence_key = _short_hash(category, subject_asset_id, discriminator)
    bounded_evidence, dropped = _bounded_evidence(evidence)
    return {
        "signal_id": f"signal:{category}:{evidence_key}",
        "evidence_key": evidence_key,
        "category": category,
        "kind": kind,
        "base_severity": severity,
        "severity_basis": basis,
        "summary": _safe_text(summary, MAX_SUMMARY_CHARS),
        "subject_asset_id": subject_asset_id,
        "confidence": aggregate_confidence(contributions),
        "contributions": contributions,
        "sources": sorted(set(sources)),
        "corroborating_sources": sorted({c.get("source") for c in contributions if c.get("source")}),
        "evidence": bounded_evidence,
        "evidence_truncated": dropped,
        "observation_ids": sorted(set(observation_ids)),
        "source_asset_ids": sorted(set(source_asset_ids or [])),
        "provenance": provenance,
        "detail": detail,
        "factors": list(factors or []),
        "notes": [_safe_text(n, MAX_NOTE_CHARS) for n in (notes or [])],
        "last_seen": last_seen,
        # Set when the claim itself has a ceiling (a takeover *indicator* is
        # at most as confident as the mapper's indicator level, whatever the
        # confidence of the DNS record it was derived from). Survives merging.
        "confidence_ceiling": None,
    }


def _merge_rank(signal: Dict[str, Any]) -> Tuple[int, int, str]:
    """
    Which of two records of the same evidence is the primary one.

    Two finding assets can describe the same fact about the same subject
    (the same CVE matched against two observed versions, a re-scan whose
    volatile fields minted a second finding asset). The merged signal keeps
    the stronger record's detail and classification — highest base severity,
    then highest confidence, then newest — and records the other as an
    alternate, instead of letting whichever asset id sorts first decide.
    """
    return (severity_rank(signal["base_severity"]), confidence_rank(signal["confidence"]),
            _text(signal.get("last_seen")))


def _merge_signals(primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
    """Fold `secondary` (same evidence key) into `primary`: corroborate, never duplicate."""
    primary["contributions"] = primary["contributions"] + [
        c for c in secondary["contributions"] if c not in primary["contributions"]
    ]
    primary["confidence"] = aggregate_confidence(primary["contributions"])
    ceilings = [c for c in (primary.get("confidence_ceiling"), secondary.get("confidence_ceiling")) if c]
    if ceilings:
        primary["confidence_ceiling"] = min(ceilings, key=confidence_rank)
        if confidence_rank(primary["confidence"]) > confidence_rank(primary["confidence_ceiling"]):
            primary["confidence"] = primary["confidence_ceiling"]
    primary["sources"] = sorted(set(primary["sources"]) | set(secondary["sources"]))
    primary["corroborating_sources"] = sorted(
        {c.get("source") for c in primary["contributions"] if c.get("source")}
    )
    primary["observation_ids"] = sorted(set(primary["observation_ids"]) | set(secondary["observation_ids"]))
    primary["source_asset_ids"] = sorted(set(primary["source_asset_ids"]) | set(secondary["source_asset_ids"]))
    merged_evidence, dropped = _bounded_evidence(primary["evidence"] + secondary["evidence"])
    primary["evidence"] = merged_evidence
    primary["evidence_truncated"] = primary["evidence_truncated"] + secondary["evidence_truncated"] + dropped
    for item in secondary["provenance"]:
        if item not in primary["provenance"]:
            primary["provenance"].append(item)
    for item in secondary["notes"]:
        if item not in primary["notes"]:
            primary["notes"].append(item)
    # A directly-observed confirmation outranks an inference of the same fact.
    if secondary["kind"] == KIND_CONFIRMED and primary["kind"] not in _NEVER_CONFIRMABLE:
        primary["kind"] = KIND_CONFIRMED
    if _text(secondary.get("last_seen")) > _text(primary.get("last_seen")):
        primary["last_seen"] = secondary["last_seen"]
    if secondary["category"] == "vulnerability_intelligence":
        _merge_intelligence_status(primary, secondary)
    if secondary["category"] == "vulnerability_intelligence" and (
        secondary.get("applicability") != primary.get("applicability")
        or secondary.get("technology_version") != primary.get("technology_version")
    ):
        primary["notes"].append(_safe_text(
            f"an alternate record of the same CVE on this subject (version "
            f"{secondary.get('technology_version') or 'unknown'}, applicability "
            f"{secondary.get('applicability')}, confidence {secondary['confidence']}) was merged into "
            f"this one; the stronger applicability assessment is the one presented", MAX_NOTE_CHARS))
    return primary


def _merge_intelligence_status(primary: Dict[str, Any], secondary: Dict[str, Any]) -> None:
    """
    Union the CVE-level intelligence of two records of the same CVE.

    KEV membership, public-exploit references and EPSS are properties of the
    CVE, not of the observation: a record whose run could not reach the KEV
    catalog says nothing that undoes a record whose run found the listing.
    Knowledge is therefore combined by strength (listed > checked-not-listed
    > not-checked > unknown), never overwritten by the newer or the primary
    record, and the exploitability factors are re-derived from the result so
    a provider outage can never subtract an escalation an earlier run earned.
    """
    ps = _as_dict(primary.get("intelligence_status"))
    ss = _as_dict(secondary.get("intelligence_status"))
    if not ps or not ss:
        return
    merged = _combine_intelligence(ps, ss)
    if merged == ps:
        return
    primary["intelligence_status"] = merged
    kept = [f for f in primary["factors"]
            if f.get("factor") not in ("known_exploited_vulnerability", "public_exploit_exists")]
    exploit_factors = [f for f in primary["factors"] + secondary["factors"]
                       if f.get("factor") in ("known_exploited_vulnerability", "public_exploit_exists")]
    chosen: List[Dict[str, Any]] = []
    if merged["cisa_kev"] == "listed":
        chosen = [f for f in exploit_factors if f.get("factor") == "known_exploited_vulnerability"][:1]
    elif merged["exploitdb"] == "references":
        chosen = [f for f in exploit_factors if f.get("factor") == "public_exploit_exists"][:1]
    if (_as_dict(merged.get("epss")).get("status") == "scored"
            and not any(f.get("factor") == "epss_exploitation_likelihood" for f in kept)):
        kept.extend([f for f in secondary["factors"] if f.get("factor") == "epss_exploitation_likelihood"][:1])
    primary["factors"] = kept + chosen
    primary["notes"].append(
        "exploitability intelligence was combined across records of this CVE "
        f"(KEV: {merged['cisa_kev']}, Exploit-DB: {merged['exploitdb']}, EPSS: {_as_dict(merged.get('epss')).get('status')}); "
        "a later run's provider outage never removes what an earlier run established"
    )


def extract_signals(graph: Dict[str, Any], errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize the graph into risk signals.

    Two sources are read, in this order:

      1. `finding` assets — surface_mapper.py's representation of every module
         finding that is not itself an asset. These carry the bulk of the risk
         content and are matched against SIGNAL_RULES.
      2. asset attributes — conditions surface_mapper.py stores as correlated
         attributes rather than findings (self-signed TLS, TLS version,
         takeover indicator, historical endpoint, vhost origin, form category,
         open port status).

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
        if _merge_rank(signal) > _merge_rank(existing):
            merged[key] = _merge_signals(signal, existing)
        else:
            merged[key] = _merge_signals(existing, signal)

    subject_index = _build_finding_subject_index(graph)

    for asset_id in sorted(graph["assets"]):
        asset = graph["assets"][asset_id]
        if not isinstance(asset, dict):
            errors.append({"stage": "extraction", "asset_id": asset_id,
                           "error": f"asset record is not a JSON object ({type(asset).__name__})"})
            continue
        try:
            if _text(asset.get("asset_type")) == ASSET_FINDING:
                for signal in _signals_from_finding_asset(graph, asset_id, asset, subject_index, errors):
                    _emit(signal)
            else:
                for signal in _signals_from_asset_attributes(graph, asset_id, asset):
                    _emit(signal)
        except Exception as exc:  # one bad asset must never destroy the assessment
            errors.append({"stage": "extraction", "asset_id": asset_id, "error": str(exc)})

    signals = [merged[key] for key in sorted(merged)]
    _annotate_outcome_conflicts(signals)
    return signals


def _annotate_outcome_conflicts(signals: List[Dict[str, Any]]) -> None:
    """
    Surface contradictory outcomes for one probed resource (context.md §8:
    conflicts are preserved and surfaced, never silently resolved).

    The same URL can be recorded as confirmed_exposure by one run and
    access_restricted by a later one (a fix, a WAF rule, a flapping backend).
    Each outcome is its own signal and both are kept; this pass makes each
    aware of the other so a reader sees "this changed" rather than two
    unrelated lines. It changes no score.
    """
    by_resource: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for signal in signals:
        detail = _as_dict(signal.get("detail"))
        url = _text(detail.get("url"))
        if not url or not _text(detail.get("discovery_type")) or signal.get("check_outcome"):
            continue
        by_resource.setdefault((signal["subject_asset_id"], url), []).append(signal)
    for (_, url), group in sorted(by_resource.items()):
        outcomes = {_lower(_as_dict(s.get("detail")).get("discovery_type")) for s in group}
        if len(outcomes) < 2:
            continue
        for signal in group:
            others = sorted(
                (_lower(_as_dict(o.get("detail")).get("discovery_type")), _text(o.get("last_seen")))
                for o in group if o is not signal
            )
            signal["outcome_conflict"] = True
            # One probed resource is one converging fact however many
            # outcomes were recorded for it.
            signal["convergence_group"] = f"resource:{signal['subject_asset_id']}:{url}"
            signal["notes"].append(_safe_text(
                "outcome conflict: the same resource was also recorded as "
                + ", ".join(f"{outcome!r} (last seen {seen or 'unknown'})" for outcome, seen in others)
                + " — both observations are preserved; the difference may reflect a change over time "
                  "or an inconsistent response and was not resolved", MAX_NOTE_CHARS))


def _build_finding_subject_index(graph: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Map each `finding` asset to the asset(s) it describes.

    surface_mapper.py links a finding to its subject with an
    `asset_to_finding` relationship whose `from_asset` is the subject. A
    finding asset is keyed on its value, so the same fact observed about two
    subjects is one finding asset with two such relationships — and it is a
    fact about *both* of them.
    """
    index: Dict[str, List[str]] = {}
    for rel_id in sorted(graph["relationships"]):
        rel = graph["relationships"][rel_id]
        if not isinstance(rel, dict) or _text(rel.get("rel_type")) != REL_ASSET_TO_FINDING:
            continue
        finding_id = _text(rel.get("to_asset"))
        subject_id = _text(rel.get("from_asset"))
        if finding_id and subject_id:
            subjects = index.setdefault(finding_id, [])
            if subject_id not in subjects:
                subjects.append(subject_id)
    return index


def _inconclusive_outcome(finding_type: str, detail: Dict[str, Any]) -> Optional[str]:
    """
    Recognize a persisted record that says a check did NOT complete.

    Returns the outcome label ("not_checked", "failed" or "inconclusive") or
    None for a genuine finding. These records exist so a later run can tell
    "not checked" from "checked and clean" (context.md §8); scoring them as
    findings would be wrong, and reading their presence as either safety or
    danger would be worse.
    """
    lowered = finding_type.lower()
    if lowered.endswith("_not_probed") or "_skipped_out_of_scope" in lowered:
        return "not_checked"
    if "_fetch_failed" in lowered or "_lookup_failed" in lowered:
        return "failed"
    if "_inconclusive" in lowered:
        return "inconclusive"
    discovery_type = _lower(detail.get("discovery_type"))
    if discovery_type in _INCONCLUSIVE_DISCOVERY_TYPES:
        return "failed" if discovery_type in ("error", "rate_limited") else "inconclusive"
    # exposure_scan.py's cloud probe records an unreachable resource as
    # status="error" with no discovery_type at all. A record that *does* carry
    # a discovery outcome is classified by that outcome alone — a stray status
    # field must not suppress a confirmed exposure.
    if (not discovery_type and _lower(detail.get("status")) == "error"
            and finding_type in ("cloud_resource_finding", "exposure_finding")):
        return "failed"
    return None


def _takeover_confidence_ceiling(graph: Dict[str, Any], subject_id: str,
                                 detail: Dict[str, Any]) -> Tuple[str, List[str]]:
    """
    The confidence a takeover-indicator finding may carry.

    surface_mapper.py mints the `subdomain_takeover_indicator` finding from
    the DNS observation that revealed the CNAME, so the finding asset
    inherits that observation's confidence — typically HIGH, because the
    CNAME record certainly exists. The *indicator* is a different claim, and
    the mapper's own `indicator_level` (MEDIUM without a matching "unclaimed
    resource" fingerprint, HIGH with one) is its honest confidence. The DNS
    confidence and the mapper's derived attribute are also one body of
    evidence, not two independent sources.
    """
    subject = _as_dict(graph["assets"].get(subject_id))
    current = _as_dict(_as_dict(_as_dict(subject.get("attributes")).get("takeover_indicator")).get("value"))
    notes: List[str] = []
    if not current:
        return CONFIDENCE_MEDIUM, ["takeover indicator level not available on the subject asset; "
                                   "held at MEDIUM confidence (no fingerprint confirmation is recorded)"]
    level = normalize_confidence(current.get("indicator_level"))
    if not current.get("provider") or _text(current.get("final_target")) != _text(detail.get("final_target")):
        notes.append(
            f"the subject's current takeover evaluation no longer points at this target "
            f"(now {current.get('final_target')!r}, provider {current.get('provider')!r}); this indicator "
            f"is retained as history and held at the current evaluation's confidence"
        )
        if not current.get("provider"):
            level = CONFIDENCE_LOW
    return level, notes


def _signals_from_finding_asset(graph: Dict[str, Any], asset_id: str, asset: Dict[str, Any],
                                 subject_index: Dict[str, List[str]],
                                 errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    value = _as_dict(asset.get("value"))
    finding_type = _text(value.get("finding_type"))
    detail = _detail_of(asset.get("value"))
    subjects = subject_index.get(asset_id) or [asset_id]

    observation_ids_raw = _as_list(asset.get("observation_ids"))
    observations = _observation_records(graph, observation_ids_raw)
    if len(observations) < len(observation_ids_raw):
        # surface_mapper.py never deletes observations, so a reference that
        # does not resolve to a record is graph damage worth reporting; the
        # finding is still assessed from what remains.
        errors.append({"stage": "extraction", "asset_id": asset_id,
                       "error": f"{len(observation_ids_raw) - len(observations)} of "
                                f"{len(observation_ids_raw)} referenced observation(s) missing or malformed; "
                                f"assessed from the remaining evidence"})
    evidence: List[str] = []
    provenance: List[Dict[str, Any]] = []
    contributions: List[Dict[str, str]] = []
    metadata: Dict[str, Any] = {}
    annotations_seen: List[str] = []
    observation_metadata: List[Dict[str, Any]] = []
    for record in observations:
        evidence.extend(_as_list(record.get("evidence")))
        record_metadata = _as_dict(record.get("metadata"))
        metadata.update(record_metadata)
        observation_metadata.append(record_metadata)
        annotated = _text(record_metadata.get("severity")).upper()
        if annotated in VALID_SEVERITIES and annotated not in annotations_seen:
            annotations_seen.append(annotated)
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

    # Contextual qualifications the producing module attached to its own
    # record. They are carried, never interpreted into a score.
    context_notes: List[str] = []
    producer_note = _as_dict(detail.get("provenance")).get("note")
    if _text(producer_note):
        context_notes.append(f"producer provenance note: {_text(producer_note)}")
    if _text(detail.get("ownership_attribution")):
        context_notes.append(
            f"ownership attribution: {_text(detail.get('ownership_attribution'))} — shared provider "
            f"infrastructure means a responding resource is not by itself proof that the target owns it"
        )
    if len(annotations_seen) > 1:
        context_notes.append(
            f"producer severity annotations differ across observations of this finding "
            f"({', '.join(annotations_seen)}); the newest observation's annotation is the one applied"
        )

    signals: List[Dict[str, Any]] = []
    for subject_id in subjects:
        common = dict(
            subject_asset_id=subject_id, contributions=[dict(c) for c in contributions],
            evidence=list(evidence), observation_ids=observation_ids, sources=sources,
            provenance=[dict(pv) for pv in provenance], detail=detail, last_seen=last_seen,
            source_asset_ids=[asset_id],
        )
        signals.extend(_classify_finding(graph, finding_type, detail, metadata, common, context_notes,
                                         observation_metadata))
    return signals


def _classify_finding(graph: Dict[str, Any], finding_type: str, detail: Dict[str, Any],
                      metadata: Dict[str, Any], common: Dict[str, Any],
                      context_notes: List[str],
                      observation_metadata: Optional[Sequence[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    subject_id = common["subject_asset_id"]
    contributions = common["contributions"]
    sources = common["sources"]

    # A record of a check that did not complete is neither a finding nor a
    # negative result. It is kept, labelled, and excluded from scoring.
    outcome = _inconclusive_outcome(finding_type, detail)
    if outcome is not None:
        signal = _build_signal(
            category=f"inconclusive_check:{finding_type or 'unknown'}",
            severity=SEVERITY_INFO, kind=KIND_OBSERVATION,
            basis="context.md §8 negative-result memory: a check that did not complete is recorded as "
                  "inconclusive — it is neither a finding nor evidence of absence",
            summary=f"{finding_type or 'unknown'} on {subject_id}: check {outcome.replace('_', ' ')}"
                    + (f" ({detail.get('discovery_type') or detail.get('error') or detail.get('reason')})"
                       if (detail.get("discovery_type") or detail.get("error") or detail.get("reason")) else ""),
            discriminator=_short_hash(_json_safe(detail)),
            notes=[f"check outcome {outcome}: this record is not evidence of absence and not a finding — no "
                   f"conclusion about presence or absence follows from it, and the subject should be treated "
                   f"as not checked for this condition"] + context_notes,
            **common,
        )
        signal["check_outcome"] = outcome
        return [signal]

    # Vulnerability intelligence has its own classification path (CVSS,
    # applicability, exploitability) rather than a flat catalog entry.
    if finding_type == "vulnerability_intelligence":
        assessment = classify_vulnerability_intelligence(detail, metadata, observation_metadata)
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
            notes=assessment["notes"] + context_notes,
            **common,
        )
        signal["contributions"] = vuln_contributions
        signal["confidence"] = assessment["confidence"]
        signal["confidence_dimensions"] = assessment["confidence_dimensions"]
        signal["intelligence_status"] = assessment["intelligence_status"]
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

    confidence_ceiling: Optional[str] = None
    ceiling_notes: List[str] = []
    if finding_type == "subdomain_takeover_indicator":
        confidence_ceiling, ceiling_notes = _takeover_confidence_ceiling(graph, subject_id, detail)

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
        notes: List[str] = list(context_notes) + list(ceiling_notes)
        if annotated_severity and severity_rank(annotated_severity) > severity_rank(severity):
            notes.append(
                f"producing module {sources[0]!r} annotated this finding severity={annotated_severity}; "
                f"honoured over the catalog default {severity}"
            )
            severity = annotated_severity
            basis = f"{basis}; producing module annotated metadata severity={annotated_severity}"
        elif annotated_severity and severity_rank(annotated_severity) < severity_rank(severity):
            notes.append(
                f"producing module {sources[0]!r} annotated this finding severity={annotated_severity}, "
                f"below the catalog severity {severity}; the catalog severity is kept and the annotation "
                f"is recorded here"
            )

        signal = _build_signal(
            category=rule.category, severity=severity, kind=rule.kind, basis=basis,
            summary=summary, discriminator=discriminator, notes=notes, **common,
        )
        if confidence_ceiling is not None:
            _cap_signal_confidence(signal, confidence_ceiling)
        signals.append(signal)

    if signals:
        return signals

    # Unrecognized finding type: recorded, never dropped, and never assumed to
    # be either harmless or dangerous.
    severity = annotated_severity or SEVERITY_INFO
    known_type = finding_type in _RULES_BY_TYPE
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
        notes=[("this finding type is known but this record's discovery outcome "
                f"({detail.get('discovery_type')!r}) matches no risk rule; it is preserved for reporting "
                "without a derived severity")
               if known_type and detail.get("discovery_type") else
               ("no risk rule matched this finding type; it is preserved for reporting without a "
                "derived severity")] + context_notes,
        **common,
    )]


def _cap_signal_confidence(signal: Dict[str, Any], ceiling: str) -> None:
    """Bound every contribution behind a signal (and so its aggregate) to `ceiling`."""
    for contribution in signal["contributions"]:
        if confidence_rank(contribution["confidence"]) > confidence_rank(ceiling):
            contribution["confidence"] = ceiling
    for entry in signal["provenance"]:
        if confidence_rank(entry.get("confidence")) > confidence_rank(ceiling):
            entry["confidence"] = ceiling
    signal["confidence"] = aggregate_confidence(signal["contributions"])
    if confidence_rank(signal["confidence"]) > confidence_rank(ceiling):
        signal["confidence"] = ceiling
    signal["confidence_ceiling"] = ceiling


def _attribute_alternatives(graph: Dict[str, Any], asset_id: str, key: str) -> List[Dict[str, Any]]:
    """
    The other values an unresolved conflict records for (asset, attribute).

    surface_mapper.py keeps the first-observed value on the attribute and
    preserves every disagreeing observation in the conflict record. A
    condition that appeared only in a later observation (a certificate that
    became self-signed, a downgrade to TLS 1.0) therefore lives *only* there,
    and would otherwise never become a signal — a finding silently absent.
    """
    conflict = _as_dict(graph["conflicts"].get(f"conflict:{asset_id}:{key}"))
    if _lower(conflict.get("status")) not in ("", "unresolved"):
        return []
    return [o for o in _as_list(conflict.get("observations")) if isinstance(o, dict)]


def _attribute_views(graph: Dict[str, Any], asset_id: str, attributes: Dict[str, Any],
                     key: str) -> List[Tuple[Dict[str, Any], bool]]:
    """
    Every recorded value of an attribute as (attribute-shaped record, disputed).

    The stored attribute comes first. When it is in unresolved conflict, each
    disagreeing observation follows as its own record so a rule can evaluate
    it, and every view — the stored one included — is flagged disputed.
    """
    stored = _as_dict(attributes.get(key))
    if not stored:
        return []
    alternatives = _attribute_alternatives(graph, asset_id, key)
    disputed = bool(alternatives) or bool(stored.get("has_conflict"))
    views: List[Tuple[Dict[str, Any], bool]] = [(stored, disputed)]
    seen_values = [stored.get("value")]
    for observation in alternatives:
        if any(_json_safe(observation.get("value")) == _json_safe(v) for v in seen_values):
            continue
        seen_values.append(observation.get("value"))
        views.append(({
            "value": observation.get("value"),
            "source": _text(observation.get("source")) or "unknown",
            "sources": [_text(observation.get("source")) or "unknown"],
            "observation_id": _text(observation.get("observation_id")),
            "timestamp": observation.get("timestamp"),
            # A value the graph could not reconcile is not HIGH-confidence.
            "confidence": CONFIDENCE_MEDIUM,
        }, True))
    return views


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
    asset_last_seen = asset.get("last_seen")

    def _attr_signal(attribute: Dict[str, Any], *, category: str, severity: str, kind: str,
                     basis: str, summary: str, discriminator: Any,
                     notes: Optional[List[str]] = None, disputed: bool = False,
                     attribute_key: Optional[str] = None) -> None:
        contributions, provenance = _attribute_contributions(attribute)
        notes = list(notes or [])
        if disputed:
            others = [
                f"{_json_safe(o.get('value'))!r} by {o.get('source')} at {o.get('timestamp')}"
                for o in _attribute_alternatives(graph, asset_id, attribute_key or "")
                if _json_safe(o.get("value")) != _json_safe(attribute.get("value"))
            ]
            notes.append(
                f"the underlying attribute {attribute_key!r} is in unresolved conflict"
                + (f" (also observed as {'; '.join(others[:5])})" if others else "")
                + " — context.md §8: the contradiction is preserved and surfaced, not resolved; "
                  "this signal is held at MEDIUM confidence at most until it is"
            )
        signals.append(_build_signal(
            category=category, severity=severity, kind=kind, basis=basis, summary=summary,
            subject_asset_id=asset_id, discriminator=discriminator, contributions=contributions,
            evidence=[f"surface_mapper.py correlated attribute {category!r} on {asset_id}"],
            observation_ids=[_text(attribute.get("observation_id"))] if attribute.get("observation_id") else [],
            sources=[c["source"] for c in contributions], provenance=provenance,
            detail={"attribute_value": attribute.get("value")}, notes=notes,
            # The attribute's own timestamp is when this condition was last
            # observed; the asset's last_seen is when *anything* about the
            # asset was, and would keep a year-old certificate observation
            # "fresh" for as long as DNS kept resolving the host.
            last_seen=attribute.get("timestamp") or asset_last_seen,
            source_asset_ids=[asset_id],
        ))
        if disputed:
            signals[-1]["attribute_conflict"] = f"conflict:{asset_id}:{attribute_key}"
            _cap_signal_confidence(signals[-1], CONFIDENCE_MEDIUM)

    def _views(key: str) -> List[Tuple[Dict[str, Any], bool]]:
        return _attribute_views(graph, asset_id, attributes, key)

    # --- outdated TLS (context.md §10 item 20 MEDIUM: "outdated TLS") ------
    for tls_version_attr, disputed in _views("tls_version"):
        tls_version = _lower(tls_version_attr.get("value")).replace(" ", "").replace("_", "")
        if tls_version and any(tls_version.startswith(v) for v in _OUTDATED_TLS_VERSIONS):
            _attr_signal(
                tls_version_attr, category="outdated_tls_version", severity=SEVERITY_MEDIUM,
                kind=KIND_CONFIRMED,
                basis="context.md §10 item 20 MEDIUM: 'outdated TLS'",
                summary=f"negotiated {tls_version_attr.get('value')} — an outdated TLS version",
                discriminator=tls_version, disputed=disputed, attribute_key="tls_version",
            )

    # --- self-signed certificate ------------------------------------------
    for self_signed_attr, disputed in _views("tls_self_signed"):
        if self_signed_attr.get("value") is True:
            _attr_signal(
                self_signed_attr, category="self_signed_certificate", severity=SEVERITY_MEDIUM,
                kind=KIND_CONFIRMED,
                basis="context.md §10 item 17: self-signed certificate detection",
                summary="TLS certificate is self-signed",
                discriminator="self_signed", disputed=disputed, attribute_key="tls_self_signed",
            )

    # --- subdomain takeover indicator -------------------------------------
    takeover_attr = _as_dict(attributes.get("takeover_indicator"))
    indicator = _as_dict(takeover_attr.get("value"))
    if indicator.get("provider") and _text(indicator.get("indicator_level")) in (CONFIDENCE_MEDIUM, CONFIDENCE_HIGH):
        # surface_mapper.py derives this attribute from another module's
        # observation (the DNS/CNAME record); that module, not the mapper, is
        # the evidence source, or the derived attribute and the finding it was
        # minted alongside would count as two independent corroborations.
        origin = _as_dict(graph["observations"].get(_text(takeover_attr.get("observation_id"))))
        level = normalize_confidence(indicator.get("indicator_level"))
        contributions = [{"source": _text(origin.get("source")) or _text(takeover_attr.get("source"))
                          or "surface_mapper.py", "confidence": level}]
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
            last_seen=takeover_attr.get("timestamp") or asset_last_seen,
            source_asset_ids=[asset_id],
        ))
        signals[-1]["confidence_ceiling"] = level

    # --- file-upload surface ----------------------------------------------
    for upload_attr, disputed in _views("file_upload_surface"):
        if upload_attr.get("value") is True:
            _attr_signal(
                upload_attr, category="file_upload_surface", severity=SEVERITY_HIGH,
                kind=KIND_OBSERVATION,
                basis="context.md §10 item 12: file-upload surfaces carry a HIGH-priority flag",
                summary=f"file-upload surface on {asset.get('value')}",
                discriminator=_text(asset.get("value")),
                notes=["attack-surface observation only — presence of an upload form is not a vulnerability"],
                disputed=disputed, attribute_key="file_upload_surface",
            )

    if asset_type == ASSET_ENDPOINT:
        # --- administrative endpoint (endpoint category / crawler form class) --
        admin_from_category = False
        for category_attr, disputed in _views("category"):
            if _lower(category_attr.get("value")) in ("admin", "administrative", "administrative_panel"):
                admin_from_category = True
                _attr_signal(
                    category_attr, category="administrative_endpoint", severity=SEVERITY_HIGH,
                    kind=KIND_CONFIRMED,
                    basis="context.md §10 item 20 HIGH: 'admin panels'",
                    summary=f"administrative endpoint {asset.get('value')}",
                    discriminator=_text(asset.get("value")), disputed=disputed, attribute_key="category",
                )
        if not admin_from_category:
            # crawler.py classifies a form as "administrative" from tokens in
            # its action URL — an indicator, not an observed panel.
            for form_attr, disputed in _views("form_category"):
                if _lower(form_attr.get("value")) in ("admin", "administrative"):
                    _attr_signal(
                        form_attr, category="administrative_endpoint", severity=SEVERITY_HIGH,
                        kind=KIND_INDICATOR,
                        basis="context.md §10 item 20 HIGH: 'admin panels' — crawler.py administrative form "
                              "classification (indicator from URL tokens, not an observed panel)",
                        summary=f"form classified as administrative at {asset.get('value')}",
                        discriminator=_text(asset.get("value")),
                        notes=["classification is inferred from the form's action URL; whether an "
                               "administrative interface is actually served there was not established"],
                        disputed=disputed, attribute_key="form_category",
                    )

        # --- historical (Wayback) endpoint -----------------------------------
        # wayback_intel.py's historical references become endpoint assets with
        # a `historical` attribute rather than finding assets.
        for historical_attr, disputed in _views("historical"):
            if historical_attr.get("value") is True:
                _attr_signal(
                    historical_attr, category="historical_endpoint_reference", severity=SEVERITY_LOW,
                    kind=KIND_INDICATOR,
                    basis="context.md §10 item 5: removed-but-maybe-still-accessible historical assets",
                    summary=f"historical reference to {asset.get('value')}",
                    discriminator=_text(asset.get("value")),
                    notes=["historical archive reference only — whether the endpoint is currently "
                           "accessible was not established by this record"],
                    disputed=disputed, attribute_key="historical",
                )

    # --- virtual host discovered via Host-header probing -----------------
    # vhost_scanner.py's discoveries become hostname assets carrying a
    # `discovered_via_vhost_scan` attribute rather than finding assets.
    if asset_type == ASSET_HOSTNAME:
        for vhost_attr, disputed in _views("discovered_via_vhost_scan"):
            if vhost_attr.get("value") is True:
                _attr_signal(
                    vhost_attr, category="virtual_host_expands_surface", severity=SEVERITY_LOW,
                    kind=KIND_CONFIRMED,
                    basis="context.md §10 item 9: vhost discovery surfaces apps not visible via DNS",
                    summary=f"virtual host {asset.get('value')!r} discovered by Host-header probing",
                    discriminator=_text(asset.get("value")),
                    disputed=disputed, attribute_key="discovered_via_vhost_scan",
                )

    # --- exposed service ports --------------------------------------------
    if asset_type == ASSET_PORT:
        for status_attr, disputed in _views("status"):
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
                    disputed=disputed, attribute_key="status",
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
            provenance=[{"source": c["source"], "observation_id": None, "timestamp": asset_last_seen,
                         "confidence": c["confidence"]} for c in contributions],
            detail={"host": asset.get("value"), "vendor": vendor or None, "category": category or None},
            notes=["third-party service outside the authorized target scope — recorded as a "
                   "supply-chain relationship, never as an investigation target"],
            last_seen=asset_last_seen,
            source_asset_ids=[asset_id],
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
            provenance=[{"source": c["source"], "observation_id": None, "timestamp": asset_last_seen,
                         "confidence": c["confidence"]} for c in contributions],
            detail={"technology": tech_value.get("name"), "version": version or None,
                    "scope": tech_value.get("scope")},
            last_seen=asset_last_seen,
            source_asset_ids=[asset_id],
        ))

    return signals


# ===========================================================================
# STAGE 3 — CONFLICT AND STALENESS QUALIFICATION
# ===========================================================================

def conflict_kind(conflict: Dict[str, Any]) -> str:
    """
    Whether a conflict record is an inter-module contradiction or one
    module's own observation changing over time (surface_mapper.py's
    CONFLICT_CROSS_SOURCE / CONFLICT_TEMPORAL).

    The kind is read from the record when surface_mapper.py stamped it, and
    otherwise derived from the sources the record carries, so a graph
    persisted before the field existed is classified the same way rather
    than defaulting to whichever answer happens to be convenient.
    """
    kind = _lower(conflict.get("kind"))
    if kind in (CONFLICT_CROSS_SOURCE, CONFLICT_TEMPORAL):
        return kind
    sources = {_text(s) for s in _as_list(conflict.get("sources")) if _text(s)}
    sources.update(_text(_as_dict(o).get("source"))
                   for o in _as_list(conflict.get("observations")))
    sources.discard("")
    return CONFLICT_CROSS_SOURCE if len(sources) > 1 else CONFLICT_TEMPORAL


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
    Index unresolved cross-source *version* conflicts by technology name.

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
            if (_text(conflict.get("attribute")) == "version"
                    and conflict_kind(conflict) == CONFLICT_CROSS_SOURCE):
                index.setdefault(name, []).append(conflict)
    return index


def _parse_timestamp(value: Any) -> Optional[datetime]:
    text = _text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _newest_timestamp(graph: Dict[str, Any],
                      errors: Optional[List[Dict[str, Any]]] = None) -> Optional[str]:
    """
    The newest *parseable* timestamp anywhere in the graph.

    Staleness is measured against the data itself rather than wall-clock
    "now", which keeps the assessment deterministic and makes "stale" mean
    "older than the rest of this reconnaissance run" rather than "old today".

    Candidates are compared as parsed datetimes, not as strings: one
    hand-edited or garbage `last_seen` ("yesterday") would otherwise win a
    lexical comparison, fail to parse, and silently switch staleness off for
    the whole graph while being reported as the newest evidence.
    """
    newest_text: Optional[str] = None
    newest: Optional[datetime] = None
    unparseable = 0
    candidates: List[Any] = [graph.get("graph_updated_at")]
    candidates.extend(asset.get("last_seen") for asset in graph["assets"].values() if isinstance(asset, dict))
    for candidate in candidates:
        if not _text(candidate):
            continue
        parsed = _parse_timestamp(candidate)
        if parsed is None:
            unparseable += 1
            continue
        if newest is None or parsed > newest:
            newest, newest_text = parsed, _text(candidate)
    if unparseable and errors is not None:
        errors.append({"stage": "qualification",
                       "error": f"{unparseable} asset timestamp(s) could not be parsed and were ignored "
                                f"when determining the newest evidence"})
    return newest_text


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
    reference = _parse_timestamp(_newest_timestamp(graph, errors))

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
                 "kind": conflict_kind(c),
                 "observations": _as_list(c.get("observations"))}
                for c in subject_conflicts
            ]

        if signal["category"] == "vulnerability_intelligence":
            # Only a genuine inter-module contradiction is a "fingerprint
            # conflict" in context.md §8's sense. A temporal one is the same
            # module seeing the technology change between runs — the CVE
            # assessment is about the version vuln_intel actually matched, and
            # suspending it there means every re-scan of a target that ever
            # patches anything silently loses its whole CVE queue. The
            # conflict is still attached to the signal above, so the operator
            # sees that the version changed.
            disputed = [c for c in subject_conflicts
                        if _text(c.get("attribute")) == "version"
                        and conflict_kind(c) == CONFLICT_CROSS_SOURCE]
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
    """
    One named combination of converging signal categories on a single asset.

    Every category in `required` must be present, and — when `any_of` is
    given — at least one of those as well. (An earlier "any N of the list"
    form let two credential indicators satisfy the deprecated-API rule with
    no deprecated API present at all.)
    """

    __slots__ = ("name", "required", "any_of", "steps", "reason", "ceiling", "qualify")

    def __init__(self, name: str, required: Sequence[str], steps: int, reason: str,
                 any_of: Sequence[str] = (), ceiling: Optional[str] = None,
                 qualify: Optional[Callable[[List[Dict[str, Any]], Dict[str, Any]], Tuple[bool, str]]] = None):
        self.name = name
        self.required = tuple(required)
        self.any_of = tuple(any_of)
        self.steps = steps
        self.reason = reason
        # The severity context.md assigns to the combination, when it names
        # one: the rule may raise an asset *to* it, never past it.
        self.ceiling = ceiling
        # An optional check over the asset's contributing signals that the
        # categories are actually related, not merely co-located on one host.
        # Returns (applies, explanation).
        self.qualify = qualify

    def matches(self, categories: Sequence[str]) -> List[str]:
        """The categories that satisfied the rule, or [] when it does not apply."""
        present = set(categories)
        if any(c not in present for c in self.required):
            return []
        alternatives = [c for c in self.any_of if c in present]
        if self.any_of and not alternatives:
            return []
        return list(self.required) + alternatives


def _deprecated_api_cve_link(signals: List[Dict[str, Any]], bucket: Dict[str, Any]) -> Tuple[bool, str]:
    """
    context.md's HIGH example is "deprecated APIs w/ known CVEs": CVEs about
    the software serving the API. A CVE against a technology that merely
    shares the host — an SSH daemon's user-enumeration flaw next to a
    deprecated /api/v1 — is co-location, not that relationship. The link the
    graph can establish is a web-observed technology: a technology asset
    scoped to a URL on this host (tech_fingerprint.py / http_analyzer.py saw
    it serving HTTP content) whose name is the CVE's technology. The bucket's
    `web_technologies` is read straight from the graph so the link does not
    depend on roll-up reachability.
    """
    web_technologies = set(bucket.get("web_technologies") or ())
    linked = sorted({
        _lower(s.get("technology")) for s in signals
        if s["category"] == "vulnerability_intelligence" and _lower(s.get("technology")) in web_technologies
    })
    if linked:
        return True, f"the CVE's technology ({', '.join(linked)}) was observed serving HTTP content on this host"
    unlinked = sorted({_lower(s.get("technology")) or "unknown" for s in signals
                       if s["category"] == "vulnerability_intelligence"})
    return False, (f"the CVE technology ({', '.join(unlinked)}) was not observed serving HTTP content on "
                   f"this host — co-location alone does not relate a CVE to the deprecated API")


CORRELATION_RULES: Tuple[CorrelationRule, ...] = (
    CorrelationRule(
        name="weak_transport_security_cluster",
        required=("missing_security_headers", "self_signed_certificate", "outdated_tls_version"),
        steps=1,
        reason="context.md §10 item 20's own example: missing security headers + self-signed certificate "
               "+ outdated TLS converge into a combined higher severity",
    ),
    CorrelationRule(
        name="deprecated_api_with_leaked_credential",
        required=("deprecated_api_endpoint",),
        any_of=("leaked_credential_in_public_code", "secret_indicator_in_client_side_js"),
        steps=1,
        reason="context.md §10 item 20's own example: a deprecated API combined with credential material "
               "leaked in public code is worse than either signal alone",
    ),
    CorrelationRule(
        name="deprecated_api_with_known_cve",
        required=("deprecated_api_endpoint", "vulnerability_intelligence"),
        steps=1,
        ceiling=SEVERITY_HIGH,
        qualify=_deprecated_api_cve_link,
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
    """Adjacency built once: asset_id -> relationships that point AT it (its owners)."""
    index: Dict[str, List[Dict[str, Any]]] = {}
    for rel_id in sorted(graph["relationships"]):
        rel = graph["relationships"][rel_id]
        if not isinstance(rel, dict):
            continue
        child = _text(rel.get("to_asset"))
        if child:
            index.setdefault(child, []).append(rel)
    return index


def _hostnames_per_ip(graph: Dict[str, Any], adjacency: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
    """How many distinct hostnames resolve to each IP (hostname_to_ip edges into it)."""
    counts: Dict[str, int] = {}
    for asset_id, rels in adjacency.items():
        if _text(_as_dict(graph["assets"].get(asset_id)).get("asset_type")) != ASSET_IP:
            continue
        counts[asset_id] = len({
            _text(r.get("from_asset")) for r in rels
            if _text(r.get("rel_type")) == REL_HOSTNAME_TO_IP and _text(r.get("from_asset"))
        })
    return counts


def _owning_assets(asset_id: str, graph: Dict[str, Any],
                   adjacency: Dict[str, List[Dict[str, Any]]],
                   hostnames_per_ip: Dict[str, int]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Walk the relationship graph from a signal's subject towards the hosts/IPs
    that own it, so a weakness on an endpoint, port, technology or finding is
    also counted against the asset it belongs to (context.md §9: score
    relationships, not isolated findings).

    Three rules keep "belongs to" honest:

      * Only ROLLUP_RELATIONSHIP_TYPES are followed. A certificate SAN, a
        CNAME alias or a JavaScript reference is not containment, and
        following it attributed one host's findings to every host that shared
        a certificate with it, aliased it, or mentioned it in a script.
      * A signal that has already passed through a hostname never crosses an
        IP to reach a *different* hostname, and one that has passed through
        an IP never crosses a hostname to reach a *different* IP. Hostnames
        sharing an IP (virtual hosts, a load balancer, a CDN edge) are
        siblings, and one vhost's admin panel is not a finding about the
        vhost next to it; likewise an exposed port on the IP a host resolves
        to is not a finding about the other IP that serves it as a vhost.
        IP-level signals still reach every hostname resolving there, and a
        hostname's own findings still reach the IP(s) serving it.
      * That IP-to-hostname fan-out is bounded by MAX_SHARED_IP_ROLLUP_HOSTNAMES;
        beyond it the signal stays on the IP and the suppression is returned
        so it can be recorded rather than silently applied.

    Returns (owners, suppressed): one owner entry per owning asset with the
    relationship chain that justified the roll-up, and one suppressed entry
    per IP whose hostnames were not attributed to.
    """
    assets = graph["assets"]
    owners: Dict[str, Dict[str, Any]] = {}
    suppressed: Dict[str, Dict[str, Any]] = {}
    visited = {asset_id}
    subject_type = _text(_as_dict(assets.get(asset_id)).get("asset_type"))
    # (node, chain, passed_hostname, passed_ip, shared_ip). The crossing rules
    # key on the relationship *type* (hostname_to_ip / ip_to_vhost), which
    # fixes which side is the IP, rather than on the node's own record — a
    # relationship whose IP record is missing must not become a way through.
    frontier: List[Tuple[str, List[str], bool, bool, Optional[Dict[str, Any]]]] = [
        (asset_id, [], subject_type == ASSET_HOSTNAME, subject_type == ASSET_IP, None)
    ]

    for _ in range(MAX_ROLLUP_DEPTH):
        next_frontier: List[Tuple[str, List[str], bool, bool, Optional[Dict[str, Any]]]] = []
        for current, chain, passed_hostname, passed_ip, shared in frontier:
            for rel in adjacency.get(current, ()):
                rel_type = _text(rel.get("rel_type"))
                if rel_type not in ROLLUP_RELATIONSHIP_TYPES:
                    continue
                parent = _text(rel.get("from_asset"))
                if not parent or parent in visited:
                    continue
                parent_asset = _as_dict(assets.get(parent))
                parent_type = _text(parent_asset.get("asset_type"))
                shared_here = shared
                if rel_type == REL_IP_TO_VHOST and passed_ip:
                    # Do not carry one IP's finding across a hostname onto the
                    # other IP that merely serves that hostname as a vhost.
                    continue
                if rel_type == REL_HOSTNAME_TO_IP:
                    if passed_hostname:
                        # Sibling crossing: do not carry one hostname's finding
                        # across a shared IP onto another hostname.
                        continue
                    resolving = hostnames_per_ip.get(current, 0)
                    if resolving > MAX_SHARED_IP_ROLLUP_HOSTNAMES:
                        suppressed.setdefault(current, {
                            "ip_asset_id": current, "hostname_count": resolving,
                            "bound": MAX_SHARED_IP_ROLLUP_HOSTNAMES,
                        })
                        continue
                    if resolving > 1:
                        shared_here = {"ip_asset_id": current, "hostname_count": resolving}
                visited.add(parent)
                parent_chain = chain + [rel_type]
                if parent_type in ROLLUP_ASSET_TYPES and parent not in owners:
                    owner = {"asset_id": parent, "relationship_chain": parent_chain}
                    if shared_here:
                        owner["shared_infrastructure"] = dict(shared_here)
                    owners[parent] = owner
                # Traversal continues past an owner rather than stopping at it:
                # context.md §7's hierarchy runs Domain -> Subdomain -> IP ->
                # Port -> Service, so a weakness on a port belongs to the IP
                # *and* to the hostname that resolves to it.
                next_frontier.append((
                    parent, parent_chain,
                    passed_hostname or parent_type == ASSET_HOSTNAME or rel_type == REL_HOSTNAME_TO_IP,
                    passed_ip or parent_type == ASSET_IP or rel_type == REL_IP_TO_VHOST,
                    shared_here,
                ))
        if not next_frontier:
            break
        frontier = next_frontier

    return [owners[key] for key in sorted(owners)], [suppressed[key] for key in sorted(suppressed)]


def _web_technologies_by_host(graph: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    hostname -> technology names observed serving HTTP content on it.

    surface_mapper.py scopes a technology seen over HTTP to the URL it was
    seen on (`technology:<url>:<name>`); the URL's hostname is the host it
    serves. Banner/host-scoped technologies are deliberately excluded.
    """
    index: Dict[str, set] = {}
    for asset in graph["assets"].values():
        if not isinstance(asset, dict) or _text(asset.get("asset_type")) != ASSET_TECHNOLOGY:
            continue
        value = _as_dict(asset.get("value"))
        scope, name = _text(value.get("scope")), _lower(value.get("name"))
        if "://" not in scope or not name:
            continue
        host = scope.split("://", 1)[1].split("/", 1)[0].split("@")[-1].split(":")[0].strip().lower().rstrip(".")
        if host:
            index.setdefault(host, set()).add(name)
    return {host: sorted(names) for host, names in index.items()}


def correlate_assets(signals: List[Dict[str, Any]], graph: Dict[str, Any],
                     errors: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Group scored signals onto the assets they bear on, following
    relationships, and record for each attachment whether it was direct or
    rolled up from a related asset.
    """
    adjacency = _relationship_index(graph)
    hostnames_per_ip = _hostnames_per_ip(graph, adjacency)
    web_technologies = _web_technologies_by_host(graph)
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
                "shared_infrastructure": None,
                "web_technologies": (
                    web_technologies.get(_lower(asset.get("value")).rstrip("."), [])
                    if _text(asset.get("asset_type")) == ASSET_HOSTNAME else []
                ),
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
                signal["notes"].append(
                    "this finding is not linked to any subject asset in the graph, so it cannot be "
                    "attributed to a host, IP or endpoint and does not appear in the investigation queue"
                )
                continue
            owners, suppressed = _owning_assets(subject_id, graph, adjacency, hostnames_per_ip)
            for owner in owners:
                if owner["asset_id"] == subject_id:
                    continue
                attachment = {
                    "signal_id": signal["signal_id"], "via": "relationship",
                    "relationship_chain": owner["relationship_chain"],
                    "from_asset": subject_id,
                }
                if owner.get("shared_infrastructure"):
                    attachment["shared_infrastructure"] = owner["shared_infrastructure"]
                _bucket(owner["asset_id"])["attachments"].append(attachment)
            for entry in suppressed:
                ip_bucket = _bucket(entry["ip_asset_id"])
                record = ip_bucket["shared_infrastructure"] or {
                    "hostname_count": entry["hostname_count"], "bound": entry["bound"],
                    "rollup_to_hostnames": "suppressed", "suppressed_signal_ids": [],
                }
                if signal["signal_id"] not in record["suppressed_signal_ids"]:
                    record["suppressed_signal_ids"].append(signal["signal_id"])
                ip_bucket["shared_infrastructure"] = record
                signal["notes"].append(_safe_text(
                    f"not attributed to the {entry['hostname_count']} hostnames resolving to "
                    f"{entry['ip_asset_id']}: shared infrastructure beyond the attribution bound of "
                    f"{entry['bound']} hostnames per IP. The IP itself carries this signal at full "
                    f"severity; which hostname(s) it concerns is ambiguous", MAX_NOTE_CHARS))
        except Exception as exc:
            errors.append({"stage": "correlation", "signal_id": signal["signal_id"], "error": str(exc)})

    return grouped


def _escalation_ceiling_for_convergence(confidences: List[str], threshold: int) -> str:
    """
    The confidence the evidence behind a convergence escalation can support.

    An escalation "because N signals converge" rests on N signals, so it is
    only as strong as the N-th best of them: five LOW-confidence indicators
    plus one HIGH-confidence observation are not HIGH-confidence convergence.
    """
    ordered = sorted(confidences, key=confidence_rank, reverse=True)
    index = min(max(threshold, 1), len(ordered)) - 1
    return ordered[index] if ordered else CONFIDENCE_LOW


def score_asset(bucket: Dict[str, Any], signals_by_id: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Produce one asset's severity and the full explanation of how it was
    reached.

    The asset's severity starts at the highest severity among the signals
    bearing on it, then escalates by convergence (context.md §9) and by the
    named correlation rules context.md itself gives as examples. Suspended and
    stale signals are reported but never drive escalation, and every step
    appends a line to `rationale`.

    Convergence counts distinct *categories* of weakness/indicator, not
    instances: six pages missing the same header, six CVEs against the same
    nginx, or six third-party scripts are one converging fact each, not six.
    Pure observations (KIND_OBSERVATION — "a fact about the surface, not a
    weakness") set the peak severity when they carry one but are never
    counted as converging risk. Each escalation is bounded by the confidence
    of the evidence that justified it, so weak evidence cannot escalate
    itself past what it can support (context.md §8).
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
    convergent_categories: List[str] = []
    escalation_applied: Optional[Dict[str, Any]] = None

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
        peak_severity = peak_signal["severity"]
        severity = peak_severity
        via = ("directly" if peak_attachment["via"] == "direct"
               else "via " + " -> ".join(peak_attachment["relationship_chain"]))
        rationale.append(
            f"highest single signal is {severity} ({peak_signal['category']}, {via}): {peak_signal['summary']}"
        )
        shared = peak_attachment.get("shared_infrastructure")
        if shared:
            rationale.append(
                f"attribution is ambiguous: that signal reached this asset through {shared['ip_asset_id']}, "
                f"which {shared['hostname_count']} hostnames resolve to (shared infrastructure) — it is "
                f"a property of the shared IP, not necessarily of this hostname's application"
            )

        # Convergence: distinct categories of weakness/indicator, never repeats
        # of the same category, and never pure observations.
        category_confidence: Dict[str, str] = {}
        category_instances: Dict[str, int] = {}
        observation_only = 0
        grouped_resources: Dict[str, Dict[str, Any]] = {}
        for _, signal in contributing:
            if signal["kind"] == KIND_OBSERVATION:
                observation_only += 1
                continue
            # Contradictory outcomes recorded for one resource (confirmed in
            # one run, access-restricted in the next) are one converging
            # fact: only the strongest outcome's category is counted.
            group = signal.get("convergence_group")
            if group:
                best = grouped_resources.get(group)
                if best is None or (severity_rank(signal["severity"]), confidence_rank(signal["confidence"])) > (
                        severity_rank(best["severity"]), confidence_rank(best["confidence"])):
                    grouped_resources[group] = signal
                continue
            category = signal["category"]
            category_instances[category] = category_instances.get(category, 0) + 1
            best = category_confidence.get(category)
            if best is None or confidence_rank(signal["confidence"]) > confidence_rank(best):
                category_confidence[category] = signal["confidence"]
        for signal in grouped_resources.values():
            category = signal["category"]
            category_instances[category] = category_instances.get(category, 0) + 1
            best_confidence_in_category = category_confidence.get(category)
            if best_confidence_in_category is None or confidence_rank(signal["confidence"]) > confidence_rank(
                    best_confidence_in_category):
                category_confidence[category] = signal["confidence"]
        convergent_categories = sorted(category_confidence)
        convergence = len(convergent_categories)
        instance_summary = ", ".join(
            f"{category}" + (f" x{category_instances[category]}" if category_instances[category] > 1 else "")
            for category in convergent_categories
        )

        # Each applicable reason is an alternative justification for one
        # escalation, bounded by the confidence of the evidence it rests on.
        # The strongest bounded outcome is applied once; reasons are never
        # summed, and every reason that applied is still recorded.
        candidates: List[Dict[str, Any]] = []
        for threshold, steps in CONVERGENCE_THRESHOLDS:
            if convergence >= threshold:
                ceiling_confidence = _escalation_ceiling_for_convergence(
                    list(category_confidence.values()), threshold)
                candidates.append({
                    "name": f"convergence>={threshold}", "steps": steps,
                    "ceiling_confidence": ceiling_confidence,
                    "reason": (f"{convergence} distinct signal categories converge on this asset "
                               f"({instance_summary}) — context.md §9: several converging signals "
                               f"on one asset combine into a higher severity"),
                })
                break

        for rule in CORRELATION_RULES:
            present = rule.matches(convergent_categories)
            if not present:
                continue
            if rule.qualify is not None:
                applies, explanation = rule.qualify([s for _, s in contributing], bucket)
                if not applies:
                    rationale.append(
                        f"correlation rule {rule.name!r} NOT applied although {', '.join(present)} are "
                        f"present: {explanation}"
                    )
                    continue
                qualified = f"; {explanation}"
            else:
                qualified = ""
            ceiling_confidence = min((category_confidence[c] for c in present), key=confidence_rank)
            candidates.append({
                "name": rule.name, "steps": rule.steps, "ceiling_confidence": ceiling_confidence,
                "severity_ceiling": rule.ceiling,
                "reason": f"correlation rule {rule.name!r} matched ({', '.join(present)}) — {rule.reason}{qualified}",
            })

        if candidates:
            for candidate in candidates:
                # An escalation is "the peak signal plus N steps", so it rests
                # on the peak's evidence as well as on the converging set.
                raised = shift_severity(peak_severity, candidate["steps"])
                if candidate.get("severity_ceiling"):
                    # context.md names the combination's severity: raise to it,
                    # never past it, and never below what the peak already is.
                    raised = max((cap_severity(raised, candidate["severity_ceiling"]), peak_severity),
                                 key=severity_rank)
                candidate["ceiling_confidence"] = min(
                    (candidate["ceiling_confidence"], peak_signal["confidence"]), key=confidence_rank)
                ceiling = CONFIDENCE_SEVERITY_CAP[candidate["ceiling_confidence"]]
                candidate["result"] = cap_severity(raised, ceiling)
                candidate["ceiling"] = ceiling
            best = max(candidates, key=lambda c: (severity_rank(c["result"]), -candidates.index(c)))
            escalation_applied = {
                "name": best["name"], "steps": best["steps"],
                "ceiling_confidence": best["ceiling_confidence"], "result": best["result"],
            }
            if severity_rank(best["result"]) > severity_rank(peak_severity):
                rationale.append(
                    f"{peak_severity} -> {best['result']} (one escalation of {best['steps']} step(s), "
                    f"the strongest that applies — overlapping reasons are not summed):"
                )
                severity = best["result"]
            elif severity_rank(shift_severity(peak_severity, best["steps"])) > severity_rank(peak_severity):
                rationale.append(
                    f"correlation applies but the escalation is held at {peak_severity}: the evidence "
                    f"behind it is {best['ceiling_confidence']} confidence, which supports at most "
                    f"{best['ceiling']} (context.md §8):"
                )
            else:
                rationale.append(f"correlation applies but severity is already {severity}:")
            for candidate in candidates:
                rationale.append(
                    f"    - {candidate['reason']} [evidence confidence {candidate['ceiling_confidence']}, "
                    f"bounded outcome {candidate['result']}]"
                )
        if observation_only:
            rationale.append(
                f"{observation_only} observation-class signal(s) recorded on this asset were not counted "
                f"as converging risk (a surface observation is not a weakness)"
            )
        repeated = {c: n for c, n in category_instances.items() if n > 1}
        if repeated:
            rationale.append(
                "repeated instances of one category count once toward convergence: "
                + ", ".join(f"{c} x{n}" for c, n in sorted(repeated.items()))
            )

        # The escalated severity may never exceed what the strongest evidence
        # behind the converging signals can support (context.md §8). Each
        # escalation is already bounded above; this is the invariant.
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
    shared_record = bucket.get("shared_infrastructure")
    if shared_record:
        rationale.append(
            f"shared infrastructure: {shared_record['hostname_count']} hostnames resolve to this IP, above "
            f"the attribution bound of {shared_record['bound']}; {len(shared_record['suppressed_signal_ids'])} "
            f"IP-level signal(s) were kept on this IP rather than attributed to each hostname"
        )

    confirmed = [s for _, s in attached if s["confirmed"]]
    indicators = [s for _, s in attached if s["kind"] == KIND_INDICATOR]
    vuln_intel = [s for _, s in attached if s["kind"] == KIND_VULN_INTEL]
    inconclusive = [s for _, s in attached if s.get("check_outcome")]

    # The confidence reported for the asset is that of the evidence driving
    # its severity — the peak signal, bounded by the escalation's evidence
    # when one raised it. An unrelated HIGH-confidence observation must not
    # dress a LOW-confidence MEDIUM as HIGH-confidence.
    if contributing:
        asset_confidence = peak_signal["confidence"]
        if escalation_applied and severity_rank(escalation_applied["result"]) > severity_rank(peak_severity):
            asset_confidence = escalation_applied["ceiling_confidence"]
    else:
        asset_confidence = max((s["confidence"] for _, s in attached), key=confidence_rank,
                               default=CONFIDENCE_LOW)
    bucket.update({
        "severity": severity,
        "severity_rank": severity_rank(severity),
        "confidence": asset_confidence,
        "rationale": rationale,
        "escalation": escalation_applied,
        "convergent_categories": convergent_categories,
        "signal_ids": sorted(seen_signal_ids),
        "signal_count": len(attached),
        "contributing_signal_count": len(contributing),
        "direct_signal_count": sum(1 for a, _ in attached if a["via"] == "direct"),
        "related_signal_count": sum(1 for a, _ in attached if a["via"] == "relationship"),
        "categories": sorted({s["category"] for _, s in attached}),
        "confirmed_finding_count": len(confirmed),
        "indicator_count": len(indicators),
        "vulnerability_intelligence_count": len(vuln_intel),
        "inconclusive_check_count": len(inconclusive),
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
            if not math.isfinite(stale_after_days):
                raise ValueError("stale_after_days must be a finite number or None")
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
                "A signal whose check did not complete (category inconclusive_check:*) is neither a "
                "finding nor evidence of absence; the subject is not checked for that condition.",
                "An IP shared by more hostnames than the attribution bound keeps IP-level signals on "
                "the IP; the hostnames it concerns are ambiguous and are not each scored for it.",
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
            "inconclusive_checks": sum(1 for s in signals if s.get("check_outcome")),
            "out_of_scope_assets": sum(1 for r in assessed if r.get("in_scope") is False),
            "shared_infrastructure_ips": sum(1 for r in assessed if r.get("shared_infrastructure")),
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

    try:
        assessment = run_risk_engine(
            graph=args.graph, output_dir=args.output_dir, stale_after_days=args.stale_after_days,
            min_queue_severity=args.min_severity, persist=not args.no_persist,
        )
    except (RiskEngineError, PersistenceError, ValueError, OSError) as exc:
        # A usable diagnostic, not a traceback: the graph is missing/corrupt,
        # the settings are invalid, or the assessment could not be written.
        print(f"risk_engine.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
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
