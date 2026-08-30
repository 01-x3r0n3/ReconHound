"""
reconhound/report_generator.py — ReconHound Module 21 (report_generator.py).

Phase: Output. See context.md §10 (module 21) for the authoritative
responsibilities and §11 for the `output/reports/` location this module
writes to.

This is ReconHound's reporting layer. It discovers nothing, scans nothing,
correlates nothing and scores nothing: it consumes state that already
exists — surface_mapper.py's correlated asset graph, risk_engine.py's
assessment, and core/orchestrator.py's execution record — and renders it as
an operator-readable HTML report plus a machine-readable JSON report.

    surface_mapper.py (graph)
    risk_engine.py    (assessment)   ->  report_generator.py  ->  output/reports/
    orchestrator.py   (execution record)


IMPLEMENTATION DECISIONS
------------------------

1.  **No parallel data model, and no second scoring engine.** Severity,
    confidence, signal kind, rationale, the investigation queue and the
    per-asset assessment are read verbatim out of risk_engine.py's
    assessment document. Asset types, relationships, evidence, provenance,
    conflicts and negative results are read verbatim out of
    surface_mapper.py's graph. This module classifies nothing and computes
    no severity of its own; where a severity is shown next to an asset it is
    the one risk_engine.py already assigned, and where none exists the
    report says so rather than inventing one.

2.  **Attack-surface paths come from surface_mapper.py.** Path
    reconstruction is `SurfaceMapper.explain_asset_path()`. This module
    binds the resolved state onto a non-persisting SurfaceMapper
    (`autosave=False, load_existing=False`) and calls that public method,
    rather than re-implementing a graph traversal that would drift from the
    real one.

3.  **The source state is never mutated.** Every structure the report emits
    is newly built. Nothing is written back into the graph, the assessment
    or the execution record, and no store belonging to another module is
    opened for writing.

4.  **All three inputs are optional, and their absence is stated, never
    faked.** A graph alone produces an inventory report that says plainly
    that no risk assessment was available; an assessment without an
    execution record omits execution status and says why. Missing
    information is rendered as "not available", never as zero, empty or
    "none found".

5.  **Truncation is always visible.** Large result sets are bounded by
    explicit limits, but every bounded section records `shown`, `total` and
    a pointer to the full artifact, so no evidence, provenance, conflict,
    negative result or relationship is ever *silently* dropped.

6.  **One malformed record never destroys the report.** Every section
    builder and every per-record conversion is isolated; a failure is
    appended to the report's own `errors` list and the rest of the report is
    still produced. That mirrors surface_mapper.py's and risk_engine.py's
    own per-record isolation.

7.  **All report content is untrusted.** Hostnames, banners, URLs,
    parameter names, JavaScript references and error strings are
    target-controlled. Every value that reaches the HTML is passed through
    `html.escape(..., quote=True)`; the rendered document contains no
    `<script>` element, loads no external resource, and carries a
    restrictive Content-Security-Policy meta tag so that even a defect in
    this module could not turn into script execution in the operator's
    browser. Interactivity is pure HTML `<details>`/`<summary>` — no
    JavaScript anywhere.

8.  **Secrets keep the redaction the producing module applied.** code_leak.py
    and js_analyzer.py store only redacted values and hashes; this module
    renders what the graph holds and never reconstructs, decodes or widens a
    redacted value.

9.  **Intelligence is never promoted to confirmation.** risk_engine.py's
    four evidence classes (observation / indicator / vulnerability
    intelligence / confirmed finding) are carried through to the report as
    distinct, visibly-labelled classes. A CVE match is always presented as a
    possible match against an observed version, never as a vulnerability the
    target is proven to have.


PUBLIC INTERFACE
----------------

    from reconhound import report_generator

    report_generator.generate_report(
        graph=<SurfaceMapper | state dict | path | None>,
        assessment=<dict | path | None>,
        execution=<orchestrator result dict | path | None>,
        output_dir="output",
    ) -> dict

    report_generator.build_report_document(...) -> dict   # pure, no I/O
    report_generator.render_html_report(document) -> str  # pure, no I/O
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from reconhound import risk_engine
from reconhound import surface_mapper

MODULE_NAME = "report_generator.py"

# The report document's own schema version. Independent of the ReconHound
# release version: consumers of the JSON report key off this.
REPORT_SCHEMA_VERSION = "1.0"

# context.md §11 places generated reports under output/reports/.
DEFAULT_REPORT_SUBDIR = "reports"
DEFAULT_FILENAME_STEM = "reconhound_report"

FORMAT_HTML = "html"
FORMAT_JSON = "json"
VALID_FORMATS: Tuple[str, ...] = (FORMAT_HTML, FORMAT_JSON)

# Severity / confidence vocabularies are risk_engine.py's, not new ones.
SEVERITY_ORDER: Dict[str, int] = dict(risk_engine.SEVERITY_ORDER)
VALID_SEVERITIES = frozenset(risk_engine.VALID_SEVERITIES)
SEVERITY_SEQUENCE: Tuple[str, ...] = (
    risk_engine.SEVERITY_CRITICAL, risk_engine.SEVERITY_HIGH, risk_engine.SEVERITY_MEDIUM,
    risk_engine.SEVERITY_LOW, risk_engine.SEVERITY_INFO,
)
CONFIDENCE_SEQUENCE: Tuple[str, ...] = (
    risk_engine.CONFIDENCE_HIGH, risk_engine.CONFIDENCE_MEDIUM, risk_engine.CONFIDENCE_LOW,
)

# Shown wherever a value is absent from the source state. Never rendered for a
# value that is genuinely empty — those say "none recorded" instead.
UNKNOWN = "UNKNOWN"
NOT_AVAILABLE = "not available"

# Rendered inline in section text, so they are written as complete sentences.
NO_ASSESSMENT = "No risk assessment was available for this report."
NO_EXECUTION = "No execution record was available for this report."

# risk_engine.py's evidence classes, with the wording the report must use.
# The distinction observation -> indicator -> vulnerability intelligence ->
# confirmed finding is a load-bearing part of the architecture (context.md
# §8/§10 items 19-20) and is preserved verbatim in both output formats.
KIND_LABELS: Dict[str, str] = {
    risk_engine.KIND_OBSERVATION: "Observation",
    risk_engine.KIND_INDICATOR: "Indicator (unverified)",
    risk_engine.KIND_VULN_INTEL: "Vulnerability intelligence (possible match)",
    risk_engine.KIND_CONFIRMED: "Confirmed finding (directly observed)",
}
KIND_DESCRIPTIONS: Dict[str, str] = {
    risk_engine.KIND_OBSERVATION:
        "A fact about the attack surface. Not a weakness by itself.",
    risk_engine.KIND_INDICATOR:
        "Suggestive evidence that was deliberately not verified. Requires manual confirmation "
        "before it can be treated as a finding.",
    risk_engine.KIND_VULN_INTEL:
        "A publicly known CVE matched against a version ReconHound observed. This is a "
        "possible match, never proof that the target is affected or exploitable.",
    risk_engine.KIND_CONFIRMED:
        "The producing module directly observed the condition. Still a reconnaissance "
        "observation, not an exploitation result.",
}

ASSET_TYPE_LABELS: Dict[str, str] = {
    surface_mapper.ASSET_ORGANIZATION: "Organization",
    surface_mapper.ASSET_HOSTNAME: "Hostname",
    surface_mapper.ASSET_IP: "IP address",
    surface_mapper.ASSET_PORT: "Service / port",
    surface_mapper.ASSET_TECHNOLOGY: "Technology",
    surface_mapper.ASSET_ENDPOINT: "Endpoint",
    surface_mapper.ASSET_PARAMETER: "Parameter",
    surface_mapper.ASSET_JAVASCRIPT: "JavaScript",
    surface_mapper.ASSET_THIRD_PARTY: "Third-party service",
    surface_mapper.ASSET_FINDING: "Finding",
}

CHECK_STATE_LABELS: Dict[str, str] = {
    surface_mapper.CHECK_NOT_CHECKED: "not checked",
    surface_mapper.CHECK_NOT_FOUND: "checked, not found",
    surface_mapper.CHECK_FOUND: "found",
    surface_mapper.CHECK_FOUND_UNCERTAIN: "found, uncertain",
}

# Bounds on how much of a very large surface reaches the report. Every one is
# overridable, and every section that hits its bound records the fact.
DEFAULT_LIMITS: Dict[str, int] = {
    "max_queue_entries": 100,
    "max_findings": 400,
    "max_assets_per_type": 200,
    "max_attack_surface_paths": 40,
    "max_path_hops": 25,
    "max_evidence_per_item": 12,
    "max_provenance_per_item": 12,
    "max_conflicts": 100,
    "max_negative_results": 200,
    "max_observations": 300,
    "max_module_executions": 400,
    "max_errors": 200,
}

# Standing statements that must appear on every report, whatever it contains.
REPORT_NOTES: Tuple[str, ...] = (
    "Severity is a prioritization assessment of where to look first, not proof that anything "
    "listed here is exploitable (context.md §10 item 20).",
    "Vulnerability intelligence is a possible match between an observed version and a public "
    "CVE record. It is never a confirmation that the target is affected.",
    "ReconHound performs reconnaissance only. Nothing in this report was verified by "
    "exploitation, credential use, or any other intrusive action (context.md §16).",
    "Assets outside the authorized target scope are recorded with their evidence but are never "
    "placed in the investigation queue.",
)


class ReportError(RuntimeError):
    """Reporting could not be performed at all."""


class ReportInputError(ReportError):
    """The supplied graph/assessment/execution input is unusable."""


class PersistenceError(ReportError):
    """A report file could not be written."""


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_safe(value: Any, _depth: int = 0) -> Any:
    """
    Coerce anything into something json.dump() accepts.

    Same defensive contract as surface_mapper.py's, risk_engine.py's and
    orchestrator.py's equivalents: unknown objects become strings rather than
    raising, and recursion is bounded so a self-referential structure built by
    a misbehaving producer cannot hang report generation.
    """
    if _depth > 24:
        return "<max depth exceeded>"
    if value is None or isinstance(value, (bool, int, float, str)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            return str(value)
        return value
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, item in value.items():
            try:
                out[str(key)] = _json_safe(item, _depth + 1)
            except Exception as exc:  # one bad member never breaks the document
                out[str(key)] = f"<unserializable: {exc}>"
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        try:
            items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else list(value)
        except Exception:
            items = list(value)
        return [_json_safe(item, _depth + 1) for item in items]
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set, frozenset)):
        return list(value)
    return [] if value is None else [value]


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_severity(value: Any) -> str:
    """
    Map a severity onto risk_engine.py's vocabulary, or UNKNOWN.

    A severity this module does not recognise is reported as UNKNOWN rather
    than being quietly folded into INFO: presenting an unrecognised value as
    the lowest severity would understate it.
    """
    text = _text(value).strip().upper()
    return text if text in VALID_SEVERITIES else UNKNOWN


def normalize_confidence(value: Any) -> str:
    text = _text(value).strip().upper()
    return text if text in risk_engine.CONFIDENCE_ORDER else UNKNOWN


def reported_severity(value: Any) -> Optional[str]:
    """
    The severity string the source actually carried, when it is not one of
    risk_engine.py's levels.

    Normalizing an unrecognised severity to UNKNOWN is right for grouping and
    ordering, but throwing the original away would hide what the producing
    state said. It is kept alongside so the report can show `UNKNOWN (raw)`.
    """
    raw = _text(value).strip()
    if not raw or raw.upper() == UNKNOWN:
        return None
    return raw if normalize_severity(raw) == UNKNOWN else None


def severity_sort_key(value: Any) -> int:
    """
    Ordering key only.

    UNKNOWN sorts just above INFO so it is never buried at the bottom of a
    report, but this is presentation order and implies no assessed severity.
    """
    severity = normalize_severity(value)
    if severity == UNKNOWN:
        return SEVERITY_ORDER[risk_engine.SEVERITY_INFO] + 1
    return SEVERITY_ORDER[severity]


def _empty_severity_counts() -> Dict[str, int]:
    counts = {name: 0 for name in SEVERITY_SEQUENCE}
    counts[UNKNOWN] = 0
    return counts


def display_value(value: Any, max_length: int = 400, _depth: int = 0) -> str:
    """
    Render any graph value as one readable line.

    Asset values are heterogeneous by design (a hostname is a string, a
    service is {"ip", "port", "protocol"}, a technology is {"scope", "name"}),
    so this flattens without losing which field was which. Recursion is
    bounded for the same reason `_json_safe` bounds it: a live SurfaceMapper
    handed in-process could carry a structure deep enough to exhaust the
    stack, and a report must not die of one odd value.
    """
    if value is None:
        return ""
    if _depth > 12:
        return "…"
    if isinstance(value, str):
        text = value
    elif isinstance(value, bool):
        text = "yes" if value else "no"
    elif isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, dict):
        parts = []
        for key in sorted(value, key=str):
            item = value[key]
            if item is None or item == "" or item == [] or item == {}:
                continue
            parts.append(f"{key}={display_value(item, 120, _depth + 1)}")
        text = ", ".join(parts)
    elif isinstance(value, (list, tuple, set, frozenset)):
        try:
            items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else list(value)
        except Exception:
            items = list(value)
        text = ", ".join(display_value(item, 120, _depth + 1) for item in items)
    else:
        try:
            text = str(value)
        except Exception as exc:
            text = f"<unrenderable: {exc}>"
    text = " ".join(text.split())
    if len(text) > max_length:
        text = text[: max_length - 1] + "…"
    return text


def _truncate_list(items: Sequence[Any], limit: int) -> Tuple[List[Any], Dict[str, Any]]:
    """
    Apply one bound and describe it.

    Returns the kept items plus a marker recording what was held back, so a
    bounded section is always self-describing rather than silently short.
    """
    total = len(items)
    if limit is None or limit < 0 or total <= limit:
        return list(items), {"shown": total, "total": total, "truncated": False}
    return list(items[:limit]), {"shown": limit, "total": total, "truncated": True,
                                 "omitted": total - limit}


def _service_label(value: Any) -> str:
    """`{"ip": .., "port": .., "protocol": ..}` -> "203.0.113.10:443/tcp"."""
    if not isinstance(value, dict):
        return display_value(value)
    ip = _text(value.get("ip"))
    port = value.get("port")
    protocol = _text(value.get("protocol")) or "tcp"
    if ip and port is not None:
        return f"{ip}:{port}/{protocol}"
    return display_value(value)


def _asset_label(asset: Dict[str, Any]) -> str:
    """One readable name for an asset, whatever its type."""
    asset_type = _text(asset.get("asset_type"))
    value = asset.get("value")
    if asset_type == surface_mapper.ASSET_PORT:
        return _service_label(value)
    if asset_type == surface_mapper.ASSET_TECHNOLOGY and isinstance(value, dict):
        name = display_value(value.get("name"))
        scope = display_value(value.get("scope"))
        return f"{name} on {scope}" if name and scope else (name or display_value(value))
    if asset_type == surface_mapper.ASSET_FINDING and isinstance(value, dict):
        finding_type = display_value(value.get("finding_type"))
        detail = value.get("value")
        rendered = display_value(detail, max_length=200)
        return f"{finding_type}: {rendered}" if finding_type and rendered else (finding_type or display_value(value))
    return display_value(value)


# ---------------------------------------------------------------------------
# Persistence — same atomic pattern as every other store in the project
# ---------------------------------------------------------------------------

class ReportStore:
    """
    Atomic file persistence for <output_dir>/reports/.

    Write-to-temp + os.replace, exactly like surface_mapper.py's GraphStore
    and risk_engine.py's RiskAssessmentStore, so a crash mid-write can never
    leave a half-written report that looks complete. Reports are derived
    documents and are rewritten wholesale on every generation.
    """

    def __init__(self, output_dir: str = "output", subdir: str = DEFAULT_REPORT_SUBDIR):
        self.output_dir = output_dir
        self.reports_dir = os.path.join(output_dir, subdir) if subdir else output_dir
        self._lock = threading.Lock()
        try:
            os.makedirs(self.reports_dir, exist_ok=True)
        except OSError as exc:
            raise PersistenceError(
                f"Cannot create report directory {self.reports_dir!r}: {exc}") from exc

    def path_for(self, filename: str) -> str:
        return os.path.join(self.reports_dir, filename)

    def save_text(self, filename: str, content: str) -> str:
        path = self.path_for(filename)
        with self._lock:
            dir_name = os.path.dirname(path) or "."
            try:
                fd, tmp_path = tempfile.mkstemp(prefix=".report_", dir=dir_name)
            except OSError as exc:
                raise PersistenceError(f"Cannot write report to {path!r}: {exc}") from exc
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_path, path)
            except BaseException:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                raise
        return path

    def save_json(self, filename: str, document: Dict[str, Any]) -> str:
        try:
            payload = json.dumps(_json_safe(document), indent=2, sort_keys=True)
        except (TypeError, ValueError) as exc:  # _json_safe should prevent this
            raise PersistenceError(f"Report document is not serializable: {exc}") from exc
        return self.save_text(filename, payload + "\n")


# ---------------------------------------------------------------------------
# Input resolution — reuses the loaders the producing modules already own
# ---------------------------------------------------------------------------

def load_graph(source: Any = None, output_dir: str = "output",
               filename: str = "surface_graph.json") -> Dict[str, Any]:
    """
    Resolve the correlated asset graph.

    Delegates to risk_engine.load_graph_state(), which is the established
    resolver for "a live SurfaceMapper, a state dict, a path, or None meaning
    <output_dir>/surface_graph.json" — reimplementing it here would be a
    second, divergent definition of the same contract.
    """
    try:
        return risk_engine.load_graph_state(source, output_dir=output_dir, filename=filename)
    except risk_engine.RiskEngineError as exc:
        raise ReportInputError(str(exc)) from exc


def _load_json_file(path: str, description: str) -> Optional[Dict[str, Any]]:
    """Read one optional JSON artifact. Absence is not an error; corruption is."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read().strip()
    except OSError as exc:
        raise ReportInputError(f"Cannot read {description} {path!r}: {exc}") from exc
    if not content:
        return None
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ReportInputError(f"{description} {path!r} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ReportInputError(f"{description} {path!r} root must be a JSON object.")
    return data


def _resolve_optional_document(source: Any, output_dir: str, filename: str,
                               description: str) -> Optional[Dict[str, Any]]:
    if source is None:
        return _load_json_file(os.path.join(output_dir, filename), description)
    if isinstance(source, dict):
        return source
    if isinstance(source, (str, os.PathLike)):
        path = os.fspath(source)
        if not os.path.exists(path):
            raise ReportInputError(f"{description} {path!r} does not exist.")
        return _load_json_file(path, description)
    raise ReportInputError(
        f"Unsupported {description} input {type(source).__name__!r}; expected a dict, a path, or None.")


def load_assessment(source: Any = None, output_dir: str = "output",
                    filename: str = "risk_assessment.json") -> Optional[Dict[str, Any]]:
    """Resolve risk_engine.py's assessment. Returns None when there is none."""
    return _resolve_optional_document(source, output_dir, filename, "risk assessment")


def load_execution(source: Any = None, output_dir: str = "output",
                   filename: str = "orchestrator_run.json") -> Optional[Dict[str, Any]]:
    """Resolve core/orchestrator.py's execution record. Returns None when there is none."""
    return _resolve_optional_document(source, output_dir, filename, "execution record")


# ---------------------------------------------------------------------------
# Report document construction
#
# Pure transformation: no I/O, no network, no mutation of the inputs.
# ---------------------------------------------------------------------------

class ReportBuilder:
    """
    Turns the three ReconHound state documents into one report document.

    The report document is the single source both output formats render from,
    so the HTML report and the JSON report can never disagree about what was
    found: `render_html_report()` receives exactly what `save_json()` writes.
    """

    def __init__(
        self,
        graph: Dict[str, Any],
        assessment: Optional[Dict[str, Any]] = None,
        execution: Optional[Dict[str, Any]] = None,
        target: Optional[str] = None,
        output_dir: str = "output",
        limits: Optional[Dict[str, int]] = None,
    ):
        self.errors: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.output_dir = output_dir
        self.limits = dict(DEFAULT_LIMITS)
        for key, value in (limits or {}).items():
            if key in self.limits:
                self.limits[key] = max(0, _int(value, self.limits[key]))

        self.graph = self._normalize_graph(graph)
        self.assessment = _as_dict(assessment) if assessment else None
        self.execution = _as_dict(execution) if execution else None

        self.target = (
            _text(target)
            or _text(self.graph.get("target"))
            or (_text(self.assessment.get("target")) if self.assessment else "")
            or (_text(self.execution.get("target")) if self.execution else "")
        ) or UNKNOWN

        if self.assessment is None:
            self.warnings.append(
                "No risk assessment was available, so this report contains no severity "
                "assessment, no investigation queue and no findings section. It is an "
                "attack-surface inventory only.")
        if self.execution is None:
            self.warnings.append(
                "No execution record was available, so module execution status, run mode and "
                "partial-failure information could not be reported.")

        self._assessed_by_id: Dict[str, Dict[str, Any]] = {}
        self._signals_by_id: Dict[str, Dict[str, Any]] = {}
        if self.assessment:
            for record in _as_list(self.assessment.get("assessed_assets")):
                if isinstance(record, dict) and _text(record.get("asset_id")):
                    self._assessed_by_id[_text(record["asset_id"])] = record
            for signal in _as_list(self.assessment.get("signals")):
                if isinstance(signal, dict) and _text(signal.get("signal_id")):
                    self._signals_by_id[_text(signal["signal_id"])] = signal

        self._asset_cache: Optional[Dict[str, Dict[str, Any]]] = None
        self._path_source = self._build_path_source()

    # -- input hardening --------------------------------------------------

    @staticmethod
    def _normalize_graph(graph: Any) -> Dict[str, Any]:
        """
        Coerce the graph's containers to the shapes the rest of this class
        indexes, without altering the caller's object.

        A hand-edited or partially-written state file may carry a container of
        the wrong JSON type; that must degrade one section, not raise from
        every lookup.
        """
        if not isinstance(graph, dict):
            raise ReportInputError(
                f"Surface graph must be a JSON object, got {type(graph).__name__}.")
        normalized = dict(graph)
        for key in ("observations", "assets", "relationships", "conflicts",
                    "negative_results", "check_states", "opportunities"):
            if not isinstance(normalized.get(key), dict):
                normalized[key] = {}
        for key in ("ingestion_errors", "ingested_observation_ids"):
            if not isinstance(normalized.get(key), list):
                normalized[key] = []
        return normalized

    def _build_path_source(self) -> Optional[Any]:
        """
        A non-persisting SurfaceMapper bound to this graph state, used purely
        to call its own `explain_asset_path()`.

        `autosave=False, load_existing=False` means it never reads or writes
        the graph file; it exists only so path reconstruction stays the one
        implementation surface_mapper.py owns.

        Its `relationships_for()` lookup is replaced with an indexed one. That
        method is a linear scan of every relationship, and `explain_asset_path`
        calls it once per node of a breadth-first search, per explained asset —
        quadratic on a large graph, and measurably the whole cost of report
        generation. The index returns exactly the same records in the same
        relative order (see `_relationship_index`), so the traversal logic
        itself is untouched: only the lookup it performs gets faster.
        """
        if self.target in ("", UNKNOWN):
            return None
        try:
            mapper = surface_mapper.SurfaceMapper(
                target=self.target, output_dir=self.output_dir,
                autosave=False, load_existing=False)
        except Exception as exc:
            self.errors.append({"stage": "attack_surface_paths",
                                "error": f"path reconstruction unavailable: {exc}"})
            return None
        mapper.state = self.graph
        index = self._relationship_index()
        mapper.relationships_for = lambda asset_id: index.get(asset_id, [])
        return mapper

    def _relationship_index(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        asset_id -> the relationships touching it, in graph order.

        Equivalent to calling `SurfaceMapper.relationships_for()` for every
        asset, including its treatment of a self-loop as a single entry.
        """
        index: Dict[str, List[Dict[str, Any]]] = {}
        for rel in self.graph["relationships"].values():
            if not isinstance(rel, dict):
                continue
            endpoints = []
            for key in ("from_asset", "to_asset"):
                asset_id = _text(rel.get(key))
                if asset_id and asset_id not in endpoints:
                    endpoints.append(asset_id)
            for asset_id in endpoints:
                index.setdefault(asset_id, []).append(rel)
        return index

    # -- error isolation --------------------------------------------------

    def _section(self, name: str, builder, fallback: Any) -> Any:
        """Run one section builder; a failure costs that section, not the report."""
        try:
            return builder()
        except Exception as exc:
            self.errors.append({"stage": name, "error": f"{type(exc).__name__}: {exc}"})
            return fallback

    # -- shared lookups ---------------------------------------------------

    def _assets(self) -> Dict[str, Dict[str, Any]]:
        """The graph's well-formed assets, computed once per report."""
        cached = getattr(self, "_asset_cache", None)
        if cached is None:
            cached = {k: v for k, v in self.graph["assets"].items() if isinstance(v, dict)}
            self._asset_cache = cached
        return cached

    def _assets_of_type(self, asset_type: str) -> List[Tuple[str, Dict[str, Any]]]:
        return sorted(
            ((aid, asset) for aid, asset in self._assets().items()
             if _text(asset.get("asset_type")) == asset_type),
            key=lambda pair: (-severity_sort_key(self._severity_of(pair[0])), pair[0]),
        )

    def _severity_of(self, asset_id: str) -> Optional[str]:
        """The severity risk_engine.py assigned, or None when it assessed nothing."""
        record = self._assessed_by_id.get(asset_id)
        if record is None:
            return None
        return normalize_severity(record.get("severity"))

    def _severity_reported_of(self, asset_id: str) -> Optional[str]:
        record = self._assessed_by_id.get(asset_id)
        return reported_severity(record.get("severity")) if record else None

    def _asset_brief(self, asset_id: str) -> Dict[str, Any]:
        """Minimal, always-safe description of an asset referenced elsewhere."""
        asset = self._assets().get(asset_id)
        if asset is None:
            return {"asset_id": asset_id, "asset_type": None, "label": asset_id,
                    "present_in_graph": False}
        return {
            "asset_id": asset_id,
            "asset_type": _text(asset.get("asset_type")) or None,
            "label": _asset_label(asset),
            "in_scope": asset.get("in_scope"),
            "present_in_graph": True,
        }

    def _attribute_rows(self, asset: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Flatten an asset's attributes, keeping provenance and conflict marks.

        surface_mapper.py stores each attribute as
        {value, source, sources, confidence, timestamp, has_conflict,
        conflict_id}; all of that is evidence and none of it is dropped.
        """
        rows = []
        for key in sorted(_as_dict(asset.get("attributes")), key=str):
            attribute = _as_dict(asset["attributes"][key])
            rows.append({
                "name": key,
                "value": attribute.get("value"),
                "display": display_value(attribute.get("value")),
                "confidence": normalize_confidence(attribute.get("confidence")),
                "sources": sorted({_text(s) for s in _as_list(attribute.get("sources")) if _text(s)})
                           or ([_text(attribute.get("source"))] if attribute.get("source") else []),
                "observation_id": _text(attribute.get("observation_id")) or None,
                "timestamp": attribute.get("timestamp"),
                "has_conflict": bool(attribute.get("has_conflict")) or bool(attribute.get("conflict_id")),
                "conflict_id": _text(attribute.get("conflict_id")) or None,
            })
        return rows

    # =====================================================================
    # Sections
    # =====================================================================

    def _build_scan(self) -> Dict[str, Any]:
        graph_meta = {
            "graph_created_at": self.graph.get("created_at"),
            "graph_updated_at": self.graph.get("updated_at"),
            "graph_ingestion_errors": len(self.graph["ingestion_errors"]),
        }
        assessment_meta = {
            "assessment_available": self.assessment is not None,
            "assessment_generated_at": self.assessment.get("generated_at") if self.assessment else None,
            "newest_evidence_at": self.assessment.get("newest_evidence_at") if self.assessment else None,
            "min_queue_severity": (
                _as_dict(self.assessment.get("settings")).get("min_queue_severity")
                if self.assessment else None),
        }
        if self.execution is None:
            return {"execution_record_available": False,
                    "reason": "No orchestrator_run.json was supplied or found.",
                    **graph_meta, **assessment_meta}
        settings = _as_dict(self.execution.get("settings"))
        return {
            "execution_record_available": True,
            "mode": _text(self.execution.get("mode")) or None,
            "run_status": _text(self.execution.get("status")) or None,
            "started_at": self.execution.get("started_at"),
            "finished_at": self.execution.get("finished_at"),
            "interrupted": bool(self.execution.get("interrupted")),
            "modules_selected": [_text(m) for m in _as_list(self.execution.get("modules_selected"))],
            "executions_by_status": _as_dict(self.execution.get("executions_by_status")),
            "settings": {
                "output_dir": settings.get("output_dir"),
                "timeout": settings.get("timeout"),
                "threads": settings.get("threads"),
                "min_risk_severity": settings.get("min_risk_severity"),
                "wordlists_dir": settings.get("wordlists_dir"),
            },
            "scope": _as_dict(self.execution.get("scope")),
            **graph_meta, **assessment_meta,
        }

    def _build_severity(self) -> Dict[str, Any]:
        """Severity distribution, taken verbatim from risk_engine.py's summary."""
        if not self.assessment:
            return {"available": False, "reason": NO_ASSESSMENT}
        summary = _as_dict(self.assessment.get("summary"))
        assets_by_severity = _empty_severity_counts()
        for name, count in _as_dict(summary.get("assets_by_severity")).items():
            assets_by_severity[normalize_severity(name)] = (
                assets_by_severity.get(normalize_severity(name), 0) + _int(count))
        signals_by_severity = _empty_severity_counts()
        for name, count in _as_dict(summary.get("signals_by_severity")).items():
            signals_by_severity[normalize_severity(name)] = (
                signals_by_severity.get(normalize_severity(name), 0) + _int(count))
        return {
            "available": True,
            "assets_assessed": _int(summary.get("assets_assessed")),
            "assets_by_severity": assets_by_severity,
            "signals": _int(summary.get("signals")),
            "signals_by_severity": signals_by_severity,
            "signals_by_evidence_class": {
                _text(kind): _int(count)
                for kind, count in _as_dict(summary.get("signals_by_evidence_class")).items()
            },
            "queue_length": _int(summary.get("queue_length")),
            "suspended_signals": _int(summary.get("suspended_signals")),
            "stale_signals": _int(summary.get("stale_signals")),
            "out_of_scope_assets": _int(summary.get("out_of_scope_assets")),
        }

    def _build_investigation_queue(self) -> Dict[str, Any]:
        if not self.assessment:
            return {"available": False,
                    "reason": NO_ASSESSMENT,
                    "entries": []}
        raw = [entry for entry in _as_list(self.assessment.get("investigation_queue"))
               if isinstance(entry, dict)]
        kept, marker = _truncate_list(raw, self.limits["max_queue_entries"])
        entries = []
        for entry in kept:
            try:
                entries.append(self._queue_entry(entry))
            except Exception as exc:
                self.errors.append({"stage": "investigation_queue",
                                    "rank": entry.get("rank"),
                                    "error": f"{type(exc).__name__}: {exc}"})
        return {"available": True, "entries": entries, **marker,
                "min_severity": _as_dict(self.assessment.get("settings")).get("min_queue_severity")}

    def _queue_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        signals = []
        for signal in _as_list(entry.get("top_signals")):
            if isinstance(signal, dict):
                signals.append({
                    "signal_id": _text(signal.get("signal_id")) or None,
                    "category": _text(signal.get("category")) or None,
                    "kind": _text(signal.get("kind")) or None,
                    "kind_label": KIND_LABELS.get(_text(signal.get("kind")), UNKNOWN),
                    "severity": normalize_severity(signal.get("severity")),
                    "confidence": normalize_confidence(signal.get("confidence")),
                    "summary": _text(signal.get("summary")),
                    "sources": [_text(s) for s in _as_list(signal.get("sources"))],
                    "observation_ids": [_text(o) for o in _as_list(signal.get("observation_ids"))],
                })
        return {
            "rank": _int(entry.get("rank")),
            "asset_id": _text(entry.get("asset_id")) or None,
            "asset_type": _text(entry.get("asset_type")) or None,
            "asset_type_label": ASSET_TYPE_LABELS.get(_text(entry.get("asset_type")),
                                                      _text(entry.get("asset_type")) or UNKNOWN),
            "value": entry.get("value"),
            "label": display_value(entry.get("value")) or _text(entry.get("asset_id")),
            "severity": normalize_severity(entry.get("severity")),
            "severity_reported": reported_severity(entry.get("severity")),
            "confidence": normalize_confidence(entry.get("confidence")),
            "in_scope": entry.get("in_scope"),
            "categories": [_text(c) for c in _as_list(entry.get("categories"))],
            "contributing_signal_count": _int(entry.get("contributing_signal_count")),
            "total_signal_count": _int(entry.get("total_signal_count")),
            "confirmed_finding_count": _int(entry.get("confirmed_finding_count")),
            "indicator_count": _int(entry.get("indicator_count")),
            "vulnerability_intelligence_count": _int(entry.get("vulnerability_intelligence_count")),
            "unresolved_conflicts": [_text(c) for c in _as_list(entry.get("unresolved_conflicts"))],
            "suspended_signal_ids": [_text(s) for s in _as_list(entry.get("suspended_signal_ids"))],
            "explanation": [_text(line) for line in _as_list(entry.get("explanation"))],
            "top_signals": signals,
        }

    def _finding_entry(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        kind = _text(signal.get("kind"))
        evidence, evidence_marker = _truncate_list(
            [_text(e) for e in _as_list(signal.get("evidence"))],
            self.limits["max_evidence_per_item"])
        provenance, provenance_marker = _truncate_list(
            [p for p in _as_list(signal.get("provenance")) if isinstance(p, dict)],
            self.limits["max_provenance_per_item"])
        subject_id = _text(signal.get("subject_asset_id"))
        entry = {
            "signal_id": _text(signal.get("signal_id")) or None,
            "category": _text(signal.get("category")) or None,
            "kind": kind or None,
            "kind_label": KIND_LABELS.get(kind, UNKNOWN),
            "severity": normalize_severity(signal.get("severity")),
            "severity_reported": reported_severity(signal.get("severity")),
            "base_severity": normalize_severity(signal.get("base_severity")),
            "severity_basis": _text(signal.get("severity_basis")) or None,
            "confidence": normalize_confidence(signal.get("confidence")),
            "summary": _text(signal.get("summary")),
            "subject": self._asset_brief(subject_id) if subject_id else None,
            "sources": sorted({_text(s) for s in _as_list(signal.get("sources")) if _text(s)}),
            "corroborating_sources": sorted(
                {_text(s) for s in _as_list(signal.get("corroborating_sources")) if _text(s)}),
            "evidence": evidence,
            "evidence_truncation": evidence_marker,
            "provenance": provenance,
            "provenance_truncation": provenance_marker,
            "observation_ids": [_text(o) for o in _as_list(signal.get("observation_ids"))],
            "rationale": [_text(line) for line in _as_list(signal.get("rationale"))],
            "notes": [_text(note) for note in _as_list(signal.get("notes"))],
            "factors": _json_safe(_as_list(signal.get("factors"))),
            "detail": _json_safe(signal.get("detail")),
            "confirmed": bool(signal.get("confirmed")),
            "suspended": bool(signal.get("suspended")),
            "suspension_reason": _text(signal.get("suspension_reason")) or None,
            "stale": bool(signal.get("stale")),
            "age_days": signal.get("age_days"),
            "conflicts": _json_safe(_as_list(signal.get("conflicts"))),
            "last_seen": signal.get("last_seen"),
        }
        if kind == risk_engine.KIND_VULN_INTEL:
            entry.update({
                "cve_id": _text(signal.get("cve_id")) or None,
                "cvss_score": signal.get("cvss_score"),
                "applicability": _text(signal.get("applicability")) or None,
                "severity_unknown": bool(signal.get("severity_unknown")),
                "technology": _text(signal.get("technology")) or None,
                "technology_version": _text(signal.get("technology_version")) or None,
            })
        return entry

    def _build_findings(self) -> Dict[str, Any]:
        if not self.assessment:
            return {"available": False,
                    "reason": NO_ASSESSMENT,
                    "entries": []}
        signals = [s for s in _as_list(self.assessment.get("signals")) if isinstance(s, dict)]
        signals.sort(key=lambda s: (
            -severity_sort_key(s.get("severity")),
            -risk_engine.confidence_rank(normalize_confidence(s.get("confidence"))),
            _text(s.get("signal_id")),
        ))
        kept, marker = _truncate_list(signals, self.limits["max_findings"])
        entries = []
        for signal in kept:
            try:
                entries.append(self._finding_entry(signal))
            except Exception as exc:
                self.errors.append({"stage": "findings",
                                    "signal_id": _text(signal.get("signal_id")),
                                    "error": f"{type(exc).__name__}: {exc}"})
        by_kind: Dict[str, int] = {}
        for signal in signals:
            by_kind[_text(signal.get("kind")) or UNKNOWN] = by_kind.get(
                _text(signal.get("kind")) or UNKNOWN, 0) + 1
        return {"available": True, "entries": entries, "counts_by_evidence_class": by_kind, **marker}

    def _build_vulnerability_intelligence(self) -> Dict[str, Any]:
        """
        The vulnerability-intelligence subset, presented as possible matches.

        Filtered from the *full* signal list rather than from the bounded
        findings section: filtering an already-truncated list would let this
        table show fewer CVE matches than the executive summary counts. It
        uses the same `_finding_entry()` converter as the findings section, so
        the two can still never describe the same signal differently, and it
        re-classifies nothing.
        """
        if not self.assessment:
            return {"available": False,
                    "reason": NO_ASSESSMENT,
                    "entries": [], "count": 0}
        matches = [s for s in _as_list(self.assessment.get("signals"))
                   if isinstance(s, dict) and _text(s.get("kind")) == risk_engine.KIND_VULN_INTEL]
        matches.sort(key=lambda s: (
            -severity_sort_key(s.get("severity")),
            -risk_engine.confidence_rank(normalize_confidence(s.get("confidence"))),
            _text(s.get("cve_id")), _text(s.get("signal_id")),
        ))
        kept, marker = _truncate_list(matches, self.limits["max_findings"])
        entries = []
        for signal in kept:
            try:
                entries.append(self._finding_entry(signal))
            except Exception as exc:
                self.errors.append({"stage": "vulnerability_intelligence",
                                    "signal_id": _text(signal.get("signal_id")),
                                    "error": f"{type(exc).__name__}: {exc}"})
        return {
            "available": True,
            "entries": entries,
            "count": len(matches),
            "suspended_count": sum(1 for s in matches if s.get("suspended")),
            "statement": (
                "Each entry below is a match between a version ReconHound observed and a public "
                "CVE record. ReconHound did not attempt to verify, reproduce or exploit any of "
                "them. Applicability states whether the observed version was confirmed to fall "
                "inside the CVE's documented range."
            ),
            **marker,
        }

    def _build_asset_inventory(self) -> Dict[str, Any]:
        assets = self._assets()
        by_type: Dict[str, int] = {}
        by_state: Dict[str, int] = {}
        in_scope = out_of_scope = unknown_scope = 0
        for asset in assets.values():
            asset_type = _text(asset.get("asset_type")) or UNKNOWN
            by_type[asset_type] = by_type.get(asset_type, 0) + 1
            state = _text(asset.get("state")) or UNKNOWN
            by_state[state] = by_state.get(state, 0) + 1
            scope = asset.get("in_scope")
            if scope is True:
                in_scope += 1
            elif scope is False:
                out_of_scope += 1
            else:
                unknown_scope += 1

        groups = []
        for asset_type in sorted(by_type, key=lambda t: (-by_type[t], t)):
            rows = self._assets_of_type(asset_type)
            kept, marker = _truncate_list(rows, self.limits["max_assets_per_type"])
            entries = []
            for asset_id, asset in kept:
                try:
                    entries.append(self._asset_row(asset_id, asset))
                except Exception as exc:
                    self.errors.append({"stage": "asset_inventory", "asset_id": asset_id,
                                        "error": f"{type(exc).__name__}: {exc}"})
            groups.append({
                "asset_type": asset_type,
                "label": ASSET_TYPE_LABELS.get(asset_type, asset_type),
                "count": by_type[asset_type],
                "entries": entries,
                **marker,
            })
        return {
            "total": len(assets),
            "by_type": by_type,
            "by_state": by_state,
            "scope": {"in_scope": in_scope, "out_of_scope": out_of_scope,
                      "scope_not_determined": unknown_scope},
            "groups": groups,
        }

    def _asset_row(self, asset_id: str, asset: Dict[str, Any]) -> Dict[str, Any]:
        assessed = self._assessed_by_id.get(asset_id)
        return {
            "asset_id": asset_id,
            "asset_type": _text(asset.get("asset_type")) or None,
            "value": _json_safe(asset.get("value")),
            "label": _asset_label(asset),
            "in_scope": asset.get("in_scope"),
            "discovery_state": _text(asset.get("state")) or None,
            "graph_confidence": normalize_confidence(asset.get("confidence")),
            "severity": normalize_severity(assessed.get("severity")) if assessed else None,
            "severity_reported": reported_severity(assessed.get("severity")) if assessed else None,
            "assessed": assessed is not None,
            "sources": sorted({_text(s) for s in _as_list(asset.get("sources")) if _text(s)}),
            "first_seen": asset.get("first_seen"),
            "last_seen": asset.get("last_seen"),
            "observation_count": len(_as_list(asset.get("observation_ids"))),
            "attributes": self._attribute_rows(asset),
            "check_states": {
                _text(check): CHECK_STATE_LABELS.get(_text(state), _text(state))
                for check, state in _as_dict(asset.get("check_states")).items()
            },
        }

    def _build_technologies(self) -> Dict[str, Any]:
        rows = self._assets_of_type(surface_mapper.ASSET_TECHNOLOGY)
        kept, marker = _truncate_list(rows, self.limits["max_assets_per_type"])
        entries = []
        for asset_id, asset in kept:
            value = _as_dict(asset.get("value"))
            attributes = {row["name"]: row for row in self._attribute_rows(asset)}
            version_row = attributes.get("version")
            entries.append({
                "asset_id": asset_id,
                "name": display_value(value.get("name")) or _asset_label(asset),
                "observed_on": display_value(value.get("scope")),
                "version": display_value(version_row["value"]) if version_row else None,
                "version_conflict": bool(version_row["has_conflict"]) if version_row else False,
                "category": display_value(attributes["category"]["value"]) if "category" in attributes else None,
                "confidence": normalize_confidence(asset.get("confidence")),
                "severity": self._severity_of(asset_id),
                "severity_reported": self._severity_reported_of(asset_id),
                "in_scope": asset.get("in_scope"),
                "sources": sorted({_text(s) for s in _as_list(asset.get("sources")) if _text(s)}),
                "last_seen": asset.get("last_seen"),
            })
        return {"entries": entries, **marker}

    def _build_services(self) -> Dict[str, Any]:
        rows = self._assets_of_type(surface_mapper.ASSET_PORT)
        kept, marker = _truncate_list(rows, self.limits["max_assets_per_type"])
        entries = []
        for asset_id, asset in kept:
            value = _as_dict(asset.get("value"))
            attributes = {row["name"]: row for row in self._attribute_rows(asset)}
            entries.append({
                "asset_id": asset_id,
                "label": _service_label(value),
                "ip": _text(value.get("ip")) or None,
                "port": value.get("port"),
                "protocol": _text(value.get("protocol")) or None,
                "status": display_value(attributes["status"]["value"]) if "status" in attributes else None,
                "service": display_value(attributes["service"]["value"]) if "service" in attributes else None,
                "banner": display_value(attributes["banner"]["value"]) if "banner" in attributes else None,
                "severity": self._severity_of(asset_id),
                "severity_reported": self._severity_reported_of(asset_id),
                "confidence": normalize_confidence(asset.get("confidence")),
                "sources": sorted({_text(s) for s in _as_list(asset.get("sources")) if _text(s)}),
                "attributes": self._attribute_rows(asset),
            })
        return {"entries": entries, **marker}

    def _build_simple_group(self, asset_type: str) -> Dict[str, Any]:
        """Endpoint / JavaScript / third-party listings — same shape, one label."""
        rows = self._assets_of_type(asset_type)
        kept, marker = _truncate_list(rows, self.limits["max_assets_per_type"])
        entries = []
        for asset_id, asset in kept:
            entries.append({
                "asset_id": asset_id,
                "label": _asset_label(asset),
                "in_scope": asset.get("in_scope"),
                "severity": self._severity_of(asset_id),
                "severity_reported": self._severity_reported_of(asset_id),
                "confidence": normalize_confidence(asset.get("confidence")),
                "discovery_state": _text(asset.get("state")) or None,
                "sources": sorted({_text(s) for s in _as_list(asset.get("sources")) if _text(s)}),
                "last_seen": asset.get("last_seen"),
            })
        return {"asset_type": asset_type,
                "label": ASSET_TYPE_LABELS.get(asset_type, asset_type),
                "entries": entries, **marker}

    def _build_supply_chain(self) -> Dict[str, Any]:
        """
        Third-party services and the in-scope assets that depend on them.

        Relationships are read from the graph, never inferred: an entry only
        claims a dependency surface_mapper.py actually recorded.
        """
        third_parties = self._build_simple_group(surface_mapper.ASSET_THIRD_PARTY)
        dependents: Dict[str, List[str]] = {}
        for rel in self.graph["relationships"].values():
            if not isinstance(rel, dict):
                continue
            rel_type = _text(rel.get("rel_type"))
            if rel_type not in (surface_mapper.REL_SUBDOMAIN_TO_THIRD_PARTY,):
                continue
            dependents.setdefault(_text(rel.get("to_asset")), []).append(_text(rel.get("from_asset")))
        for entry in third_parties["entries"]:
            entry["depended_on_by"] = [
                self._asset_brief(aid) for aid in sorted(set(dependents.get(entry["asset_id"], [])))
            ]
        return third_parties

    def _build_relationships(self) -> Dict[str, Any]:
        """Relationship census — the correlation the graph actually holds."""
        by_type: Dict[str, int] = {}
        for rel in self.graph["relationships"].values():
            if isinstance(rel, dict):
                rel_type = _text(rel.get("rel_type")) or UNKNOWN
                by_type[rel_type] = by_type.get(rel_type, 0) + 1
        return {"total": sum(by_type.values()), "by_type": by_type}

    def _build_attack_surface_paths(self) -> Dict[str, Any]:
        """
        Discovery chains for the highest-priority assets.

        Every chain is produced by surface_mapper.py's own
        `explain_asset_path()`; this module contributes only the choice of
        which assets to explain (the investigation queue's order) and the
        bound on how many.
        """
        if self._path_source is None:
            return {"available": False,
                    "reason": "The graph's target could not be determined, so discovery "
                              "chains could not be reconstructed.",
                    "entries": []}

        queue = self.assessment and _as_list(self.assessment.get("investigation_queue")) or []
        candidates: List[str] = []
        for entry in queue:
            if isinstance(entry, dict) and _text(entry.get("asset_id")):
                candidates.append(_text(entry["asset_id"]))
        if not candidates:
            # No assessment: explain the most-connected in-scope assets instead
            # of nothing, in deterministic order.
            degree: Dict[str, int] = {}
            for rel in self.graph["relationships"].values():
                if not isinstance(rel, dict):
                    continue
                for key in ("from_asset", "to_asset"):
                    degree[_text(rel.get(key))] = degree.get(_text(rel.get(key)), 0) + 1
            candidates = [aid for aid, _ in sorted(degree.items(), key=lambda kv: (-kv[1], kv[0]))
                          if aid in self._assets()]

        kept, marker = _truncate_list(candidates, self.limits["max_attack_surface_paths"])
        entries = []
        for asset_id in kept:
            try:
                hops = self._path_source.explain_asset_path(
                    asset_id, max_hops=self.limits["max_path_hops"])
            except Exception as exc:
                self.errors.append({"stage": "attack_surface_paths", "asset_id": asset_id,
                                    "error": f"{type(exc).__name__}: {exc}"})
                continue
            if not hops:
                continue
            entries.append({
                "asset_id": asset_id,
                "label": _asset_label(self._assets().get(asset_id, {})) or asset_id,
                "severity": self._severity_of(asset_id),
                "severity_reported": self._severity_reported_of(asset_id),
                "hop_count": len(hops),
                "hops": [{
                    "asset_id": _text(hop.get("asset_id")),
                    "asset_type": _text(hop.get("asset_type")) or None,
                    "asset_type_label": ASSET_TYPE_LABELS.get(_text(hop.get("asset_type")),
                                                              _text(hop.get("asset_type")) or UNKNOWN),
                    "label": display_value(hop.get("value")) or _text(hop.get("asset_id")),
                    "via": _as_dict(hop.get("via")) or None,
                    "truncated": bool(hop.get("truncated")),
                    "note": _text(hop.get("note")) or None,
                } for hop in hops],
            })
        return {"available": True, "entries": entries, **marker}

    def _build_conflicts(self) -> Dict[str, Any]:
        """
        Preserved contradictions (context.md §8).

        Conflicts are never resolved here; both observations are shown with
        their sources so the operator can resolve them.
        """
        raw = [c for c in self.graph["conflicts"].values() if isinstance(c, dict)]
        raw.sort(key=lambda c: (_text(c.get("asset_id")), _text(c.get("attribute"))))
        kept, marker = _truncate_list(raw, self.limits["max_conflicts"])
        suspended_by_conflict: Dict[str, List[str]] = {}
        if self.assessment:
            for signal in _as_list(self.assessment.get("suspended_signals")):
                if not isinstance(signal, dict):
                    continue
                for conflict in _as_list(signal.get("conflicts")):
                    conflict_id = _text(_as_dict(conflict).get("conflict_id")) or _text(conflict)
                    suspended_by_conflict.setdefault(conflict_id, []).append(
                        _text(signal.get("summary")))
        entries = []
        for conflict in kept:
            conflict_id = _text(conflict.get("id"))
            entries.append({
                "conflict_id": conflict_id or None,
                "asset": self._asset_brief(_text(conflict.get("asset_id"))),
                "attribute": _text(conflict.get("attribute")) or None,
                "status": _text(conflict.get("status")) or "unresolved",
                "first_seen": conflict.get("first_seen"),
                "last_seen": conflict.get("last_seen"),
                "truncated_observations": bool(conflict.get("truncated")),
                "observations": [{
                    "value": _json_safe(_as_dict(o).get("value")),
                    "display": display_value(_as_dict(o).get("value")),
                    "source": _text(_as_dict(o).get("source")) or None,
                    "observation_id": _text(_as_dict(o).get("observation_id")) or None,
                    "timestamp": _as_dict(o).get("timestamp"),
                } for o in _as_list(conflict.get("observations")) if isinstance(o, dict)],
                "suspended_signals": suspended_by_conflict.get(conflict_id, []),
            })
        return {"entries": entries, **marker}

    def _build_negative_results(self) -> Dict[str, Any]:
        """
        Checks that ran and found nothing (context.md §8 negative-result
        memory). Reported because "we looked and it was not there" is a
        result, and omitting it would misrepresent coverage.
        """
        raw = [r for r in self.graph["negative_results"].values() if isinstance(r, dict)]
        raw.sort(key=lambda r: (_text(r.get("asset_id")), _text(r.get("finding_type"))))
        kept, marker = _truncate_list(raw, self.limits["max_negative_results"])
        entries = []
        for record in kept:
            entries.append({
                "asset": self._asset_brief(_text(record.get("asset_id"))),
                "check": _text(record.get("finding_type")) or None,
                "state": CHECK_STATE_LABELS.get(_text(record.get("state")), _text(record.get("state"))),
                "source": _text(record.get("source")) or None,
                "confidence": normalize_confidence(record.get("confidence")),
                "check_count": _int(record.get("check_count")),
                "first_checked_at": record.get("first_checked_at"),
                "last_checked_at": record.get("last_checked_at"),
                "scopes_checked": len(_as_list(record.get("checks"))),
                "evidence": [_text(e) for e in _as_list(record.get("evidence"))],
            })
        check_states: Dict[str, int] = {}
        for record in self.graph["check_states"].values():
            if isinstance(record, dict):
                state = _text(record.get("state")) or UNKNOWN
                check_states[CHECK_STATE_LABELS.get(state, state)] = (
                    check_states.get(CHECK_STATE_LABELS.get(state, state), 0) + 1)
        return {"entries": entries, "check_state_census": check_states, **marker}

    def _build_execution(self) -> Dict[str, Any]:
        """Per-module execution status and every recorded failure."""
        if not self.execution:
            return {"available": False, "reason": NO_EXECUTION,
                    "modules": [], "errors": [], "phases": []}
        executions = [e for e in _as_list(self.execution.get("executions")) if isinstance(e, dict)]
        kept, marker = _truncate_list(executions, self.limits["max_module_executions"])
        modules = []
        for record in kept:
            modules.append({
                "module": _text(record.get("module")) or None,
                "phase": _text(record.get("phase")) or None,
                "subject": display_value(record.get("subject")),
                "status": _text(record.get("status")) or UNKNOWN,
                "observations_ingested": _int(record.get("observations_ingested")),
                "duration_seconds": record.get("duration_seconds"),
                "error": _text(record.get("error")) or None,
                "error_type": _text(record.get("error_type")) or None,
                "module_error_count": _int(record.get("module_error_count")),
                "skip_reason": _text(record.get("skip_reason")) or None,
            })
        errors, error_marker = _truncate_list(
            [e for e in _as_list(self.execution.get("errors")) if isinstance(e, dict)],
            self.limits["max_errors"])
        failed = [m for m in modules if m["status"] in ("failed", "scope_rejected", "interrupted")]
        adaptive = _as_dict(self.execution.get("adaptive"))
        return {
            "available": True,
            "modules": modules,
            "module_truncation": marker,
            "failed_modules": failed,
            "errors": _json_safe(errors),
            "error_truncation": error_marker,
            "phases": _json_safe(_as_list(self.execution.get("phases"))),
            "adaptive": {
                "rounds": _int(adaptive.get("rounds")),
                "actions": _int(adaptive.get("actions")),
                "manual_review": _json_safe(_as_list(adaptive.get("manual_review"))),
                "deferred": len(_as_list(adaptive.get("deferred"))),
            },
            "pending_opportunities": _json_safe(
                _as_list(_as_dict(self.execution.get("opportunities")).get("pending"))),
        }

    def _build_observations(self) -> Dict[str, Any]:
        """
        Raw-data appendix: the normalized observations behind everything above
        (context.md §10 item 21). Bounded, with a pointer to the full graph.
        """
        raw = [o for o in self.graph["observations"].values() if isinstance(o, dict)]
        raw.sort(key=lambda o: (_text(o.get("timestamp")), _text(o.get("observation_id"))),
                 reverse=True)
        kept, marker = _truncate_list(raw, self.limits["max_observations"])
        entries = []
        for observation in kept:
            evidence, evidence_marker = _truncate_list(
                [_text(e) for e in _as_list(observation.get("evidence"))],
                self.limits["max_evidence_per_item"])
            entries.append({
                "observation_id": _text(observation.get("observation_id")) or None,
                "type": _text(observation.get("type")) or None,
                "target": _text(observation.get("target")) or None,
                "source": _text(observation.get("source")) or None,
                "confidence": normalize_confidence(observation.get("confidence")),
                "timestamp": observation.get("timestamp"),
                "value": display_value(observation.get("value"), max_length=600),
                "evidence": evidence,
                "evidence_truncation": evidence_marker,
            })
        by_source: Dict[str, int] = {}
        for observation in raw:
            by_source[_text(observation.get("source")) or UNKNOWN] = (
                by_source.get(_text(observation.get("source")) or UNKNOWN, 0) + 1)
        return {"entries": entries, "by_source": by_source, **marker}

    def _build_executive_summary(self, sections: Dict[str, Any]) -> Dict[str, Any]:
        """
        The high-level statement of what this run established.

        Every number is carried up from a section above; nothing is
        recomputed, and a number that has no source is reported as null with
        the reason, never as zero.
        """
        inventory = sections["asset_inventory"]
        severity = sections["severity"]
        findings = sections["findings"]
        execution = sections["execution"]

        counts_by_kind = findings.get("counts_by_evidence_class") or {}
        headline: List[str] = []
        headline.append(
            f"{inventory['total']} asset(s) were correlated from "
            f"{len(self.graph['observations'])} observation(s) across "
            f"{sections['relationships']['total']} recorded relationship(s).")

        if severity.get("available"):
            counts = severity["assets_by_severity"]
            escalated = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
            headline.append(
                f"{severity['assets_assessed']} asset(s) were assessed; {escalated} at CRITICAL or "
                f"HIGH; the investigation queue holds {severity['queue_length']} entry/entries.")
            headline.append(
                f"{counts_by_kind.get(risk_engine.KIND_CONFIRMED, 0)} directly observed finding(s), "
                f"{counts_by_kind.get(risk_engine.KIND_INDICATOR, 0)} unverified indicator(s) and "
                f"{counts_by_kind.get(risk_engine.KIND_VULN_INTEL, 0)} possible CVE match(es) were "
                f"recorded. None of them was verified by exploitation.")
        else:
            headline.append("No risk assessment accompanied this report, so nothing here is "
                            "prioritized by severity.")

        if sections["conflicts"]["total"]:
            headline.append(
                f"{sections['conflicts']['total']} contradiction(s) between modules are preserved "
                f"unresolved and are listed for manual resolution.")

        if execution.get("available"):
            failed = len(execution["failed_modules"])
            status = _text(sections["scan"].get("run_status")) or UNKNOWN
            if failed or execution["errors"]:
                headline.append(
                    f"The run finished with status {status}: {failed} module execution(s) failed "
                    f"and {len(execution['errors'])} run-level error(s) were recorded, so coverage "
                    f"is incomplete.")
            else:
                headline.append(f"The run finished with status {status} and no module failures.")

        return {
            "target": self.target,
            "headline": headline,
            "assets": inventory["total"],
            "observations": len(self.graph["observations"]),
            "relationships": sections["relationships"]["total"],
            "in_scope_assets": inventory["scope"]["in_scope"],
            "out_of_scope_assets": inventory["scope"]["out_of_scope"],
            "assets_by_severity": severity["assets_by_severity"] if severity.get("available") else None,
            "queue_length": severity.get("queue_length") if severity.get("available") else None,
            "signals": severity.get("signals") if severity.get("available") else None,
            "confirmed_findings": counts_by_kind.get(risk_engine.KIND_CONFIRMED) if findings.get("available") else None,
            "indicators": counts_by_kind.get(risk_engine.KIND_INDICATOR) if findings.get("available") else None,
            "vulnerability_intelligence": counts_by_kind.get(risk_engine.KIND_VULN_INTEL) if findings.get("available") else None,
            "unresolved_conflicts": sections["conflicts"]["total"],
            "negative_results": sections["negative_results"]["total"],
            "failed_module_executions": len(execution["failed_modules"]) if execution.get("available") else None,
            "run_errors": len(execution["errors"]) if execution.get("available") else None,
        }

    def _build_limitations(self, sections: Dict[str, Any]) -> List[str]:
        """What this report cannot tell the reader. Stated, never implied."""
        limitations: List[str] = []
        if not self.assessment:
            limitations.append(
                "No risk assessment was available: nothing in this report is prioritized, and no "
                "finding, severity or investigation queue could be produced.")
        if not self.execution:
            limitations.append(
                "No execution record was available: which modules ran, which failed, and how "
                "complete the coverage is could not be determined.")
        execution = sections["execution"]
        if execution.get("available") and execution["failed_modules"]:
            limitations.append(
                f"{len(execution['failed_modules'])} module execution(s) failed. The attack surface "
                f"below is therefore incomplete: absence of a finding is not evidence of absence.")
        if execution.get("available") and _text(self.execution.get("status")) == "interrupted":
            limitations.append(
                "The run was interrupted before completion. Everything collected up to that point "
                "is present, but the pipeline did not finish.")
        if sections["conflicts"]["total"]:
            limitations.append(
                "Conflicting observations are preserved unresolved. Any assessment that depends on a "
                "disputed value is held back rather than guessed.")
        if self.graph["ingestion_errors"]:
            limitations.append(
                f"{len(self.graph['ingestion_errors'])} record(s) could not be correlated into the "
                f"asset graph and are not represented in this report's asset sections.")
        truncated = [name for name, section in sections.items()
                     if isinstance(section, dict) and section.get("truncated")]
        if truncated:
            limitations.append(
                f"These sections were bounded for readability and do not list every record: "
                f"{', '.join(sorted(truncated))}. The complete data is in the JSON artifacts.")
        if self.errors:
            limitations.append(
                f"{len(self.errors)} section(s) or record(s) could not be rendered and were skipped; "
                f"they are listed under report generation errors.")
        return limitations

    def _artifact_paths(self) -> Dict[str, Any]:
        """Where the underlying state lives. Only paths that actually exist."""
        candidates = {
            "surface_graph": os.path.join(self.output_dir, "surface_graph.json"),
            "risk_assessment": os.path.join(self.output_dir, "risk_assessment.json"),
            "pending_assets": os.path.join(self.output_dir, "pending_assets.json"),
            "execution_record": os.path.join(self.output_dir, "orchestrator_run.json"),
        }
        paths: Dict[str, Any] = {}
        for name, path in candidates.items():
            paths[name] = os.path.abspath(path) if os.path.isfile(path) else None
        return paths

    # -- assembly ---------------------------------------------------------

    def build(self) -> Dict[str, Any]:
        sections: Dict[str, Any] = {}
        sections["scan"] = self._section("scan", self._build_scan, {"execution_record_available": False})
        sections["severity"] = self._section("severity", self._build_severity, {"available": False})
        sections["investigation_queue"] = self._section(
            "investigation_queue", self._build_investigation_queue, {"available": False, "entries": []})
        sections["findings"] = self._section(
            "findings", self._build_findings, {"available": False, "entries": []})
        sections["vulnerability_intelligence"] = self._section(
            "vulnerability_intelligence", self._build_vulnerability_intelligence,
            {"available": False, "entries": [], "count": 0})
        sections["asset_inventory"] = self._section(
            "asset_inventory", self._build_asset_inventory,
            {"total": 0, "by_type": {}, "by_state": {}, "groups": [],
             "scope": {"in_scope": 0, "out_of_scope": 0, "scope_not_determined": 0}})
        sections["technologies"] = self._section("technologies", self._build_technologies, {"entries": []})
        sections["services"] = self._section("services", self._build_services, {"entries": []})
        sections["endpoints"] = self._section(
            "endpoints", lambda: self._build_simple_group(surface_mapper.ASSET_ENDPOINT), {"entries": []})
        sections["javascript"] = self._section(
            "javascript", lambda: self._build_simple_group(surface_mapper.ASSET_JAVASCRIPT), {"entries": []})
        sections["supply_chain"] = self._section("supply_chain", self._build_supply_chain, {"entries": []})
        sections["relationships"] = self._section(
            "relationships", self._build_relationships, {"total": 0, "by_type": {}})
        sections["attack_surface_paths"] = self._section(
            "attack_surface_paths", self._build_attack_surface_paths, {"available": False, "entries": []})
        sections["conflicts"] = self._section(
            "conflicts", self._build_conflicts, {"entries": [], "total": 0, "shown": 0, "truncated": False})
        sections["negative_results"] = self._section(
            "negative_results", self._build_negative_results,
            {"entries": [], "total": 0, "shown": 0, "truncated": False, "check_state_census": {}})
        sections["execution"] = self._section(
            "execution", self._build_execution,
            {"available": False, "modules": [], "errors": [], "failed_modules": [], "phases": []})
        sections["observations"] = self._section(
            "observations", self._build_observations, {"entries": [], "by_source": {}, "total": 0})

        # Defensive: a fallback section must still carry the keys the summary
        # and the renderer read, so a failed section degrades one panel only.
        sections["conflicts"].setdefault("total", len(sections["conflicts"].get("entries", [])))
        sections["negative_results"].setdefault(
            "total", len(sections["negative_results"].get("entries", [])))

        summary = self._section(
            "executive_summary", lambda: self._build_executive_summary(sections),
            {"target": self.target, "headline": []})
        limitations = self._section("limitations", lambda: self._build_limitations(sections), [])

        document = {
            "module": MODULE_NAME,
            "report_schema_version": REPORT_SCHEMA_VERSION,
            "title": f"ReconHound Reconnaissance Report — {self.target}",
            "generated_at": _now(),
            "target": self.target,
            "executive_summary": summary,
            **sections,
            "source_artifacts": self._artifact_paths(),
            "warnings": list(self.warnings),
            "limitations": limitations,
            "errors": list(self.errors),
            "notes": list(REPORT_NOTES),
        }
        return _json_safe(document)


def build_report_document(
    graph: Any = None,
    assessment: Any = None,
    execution: Any = None,
    output_dir: str = "output",
    target: Optional[str] = None,
    limits: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """
    Resolve the inputs and build the report document, without writing anything.

    Accepts the same input forms as `generate_report()`.
    """
    resolved_graph = load_graph(graph, output_dir=output_dir)
    resolved_assessment = load_assessment(assessment, output_dir=output_dir)
    resolved_execution = load_execution(execution, output_dir=output_dir)
    builder = ReportBuilder(
        graph=resolved_graph, assessment=resolved_assessment, execution=resolved_execution,
        target=target, output_dir=output_dir, limits=limits)
    return builder.build()


# ---------------------------------------------------------------------------
# HTML rendering
#
# Every value that reaches the document goes through `_e()`. The only markup
# that is not escaped is markup this module built itself, which is marked with
# the `_Markup` type so it cannot be confused with report data.
# ---------------------------------------------------------------------------

class _Markup(str):
    """A string this module built. Never used to wrap report-derived text."""


def _e(value: Any) -> str:
    """
    Escape one value for HTML text or attribute context.

    Every hostname, banner, URL, parameter name, error string and JavaScript
    reference in a report is target-controlled. `quote=True` also escapes
    `"` and `'`, so the same function is safe inside attributes.
    """
    if value is None:
        return ""
    if isinstance(value, _Markup):
        return str(value)
    if isinstance(value, bool):
        return "yes" if value else "no"
    return html.escape(str(value), quote=True)


def _tri_state(value: Any, true_text: str, false_text: str, unknown_text: str = "not determined") -> str:
    if value is True:
        return true_text
    if value is False:
        return false_text
    return unknown_text


HTML_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #f6f7f9; --panel: #ffffff; --panel-2: #fbfcfd; --ink: #16191d;
  --muted: #5b6672; --line: #dfe3e8; --accent: #0b6cb8; --accent-soft: #e8f1fa;
  --crit: #b3261e; --high: #d64027; --med: #b26a00; --low: #0b6cb8;
  --info: #5b6672; --unknown: #6b4fa8; --ok: #1c7a4a;
  --crit-bg: #fdeceb; --high-bg: #fdefe9; --med-bg: #fdf3e2;
  --low-bg: #e9f2fb; --info-bg: #eef0f2; --unknown-bg: #efeaf9;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14171a; --panel: #1c2024; --panel-2: #21262b; --ink: #e6e9ec;
    --muted: #98a3ad; --line: #2f363d; --accent: #61a8e8; --accent-soft: #1b2836;
    --crit: #ff6b5e; --high: #ff8a5c; --med: #e5a13a; --low: #61a8e8;
    --info: #98a3ad; --unknown: #b39ae8; --ok: #56c98a;
    --crit-bg: #3a1c1a; --high-bg: #3a241a; --med-bg: #33290f;
    --low-bg: #16283a; --info-bg: #252a2f; --unknown-bg: #2a2338;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
        "Helvetica Neue", Arial, sans-serif;
}
code, .mono, pre { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo,
  Consolas, "Liberation Mono", monospace; font-size: 0.9em; }
a { color: var(--accent); }
.wrap { max-width: 1180px; margin: 0 auto; padding: 0 20px 64px; }

.masthead { background: var(--panel); border-bottom: 1px solid var(--line); padding: 26px 0 20px; }
.masthead .wrap { padding-bottom: 0; }
.brand { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.brand h1 { margin: 0; font-size: 25px; letter-spacing: -0.015em; }
.brand .ver { color: var(--muted); font-size: 13px; }
.brand .tag { color: var(--muted); font-size: 13px; }
.subject { margin: 14px 0 0; display: flex; gap: 10px 22px; flex-wrap: wrap; align-items: center; }
.subject .target { font-size: 19px; font-weight: 650; }
.meta { color: var(--muted); font-size: 13px; }

nav.toc { margin: 22px 0 8px; display: flex; flex-wrap: wrap; gap: 6px; }
nav.toc a {
  text-decoration: none; font-size: 12.5px; padding: 4px 10px; border-radius: 999px;
  border: 1px solid var(--line); background: var(--panel); color: var(--muted);
}
nav.toc a:hover { border-color: var(--accent); color: var(--accent); }

section { margin: 30px 0 0; }
section > h2 {
  font-size: 17px; margin: 0 0 4px; padding-bottom: 8px;
  border-bottom: 2px solid var(--line); letter-spacing: -0.01em;
}
section > .lede { color: var(--muted); font-size: 13.5px; margin: 8px 0 14px; }
h3 { font-size: 14px; margin: 22px 0 8px; color: var(--muted);
     text-transform: uppercase; letter-spacing: 0.06em; }

.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
         padding: 16px 18px; margin: 12px 0; }
.cards { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(158px, 1fr)); margin: 14px 0; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 13px 14px; }
.card .n { font-size: 26px; font-weight: 660; line-height: 1.15; letter-spacing: -0.02em; }
.card .k { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 3px; }
.card.na .n { font-size: 15px; color: var(--muted); font-weight: 500; }

ul.headline { margin: 10px 0 0; padding-left: 20px; }
ul.headline li { margin: 5px 0; }

.chip { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11.5px;
        font-weight: 650; letter-spacing: 0.03em; white-space: nowrap; border: 1px solid transparent; }
.sev-CRITICAL { color: var(--crit); background: var(--crit-bg); border-color: var(--crit); }
.sev-HIGH { color: var(--high); background: var(--high-bg); border-color: var(--high); }
.sev-MEDIUM { color: var(--med); background: var(--med-bg); border-color: var(--med); }
.sev-LOW { color: var(--low); background: var(--low-bg); border-color: var(--low); }
.sev-INFO { color: var(--info); background: var(--info-bg); border-color: var(--line); }
.sev-UNKNOWN { color: var(--unknown); background: var(--unknown-bg); border-color: var(--unknown); }
.sev-NONE { color: var(--muted); background: var(--info-bg); border-color: var(--line); font-weight: 500; }
.kind { display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 11.5px;
        border: 1px solid var(--line); background: var(--panel-2); color: var(--muted); white-space: nowrap; }
.kind-confirmed_finding { color: var(--ok); border-color: var(--ok); }
.kind-vulnerability_intelligence { color: var(--unknown); border-color: var(--unknown); }
.kind-indicator { color: var(--med); border-color: var(--med); }
.flag { display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: 11px;
        border: 1px solid var(--med); color: var(--med); background: var(--med-bg); }

.tablewrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 10px; background: var(--panel); }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: var(--panel-2); font-size: 11.5px; text-transform: uppercase;
     letter-spacing: 0.05em; color: var(--muted); font-weight: 650; white-space: nowrap; }
tbody tr:last-child td { border-bottom: none; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
td.nowrap { white-space: nowrap; }
td.break { word-break: break-all; }

.bars { display: grid; gap: 6px; margin: 12px 0 4px; }
.bar { display: grid; grid-template-columns: 90px 1fr 52px; gap: 10px; align-items: center; font-size: 13px; }
.bar .track { background: var(--info-bg); border-radius: 4px; height: 12px; overflow: hidden; }
.bar .fill { height: 100%; border-radius: 4px; }
.bar .n { text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); }

details { border: 1px solid var(--line); border-radius: 8px; background: var(--panel);
          margin: 8px 0; padding: 0; }
details > summary { cursor: pointer; padding: 9px 13px; font-size: 13.5px; list-style: none; }
details > summary::-webkit-details-marker { display: none; }
details > summary::before { content: "▸ "; color: var(--muted); }
details[open] > summary::before { content: "▾ "; }
details > .body { padding: 2px 14px 13px; border-top: 1px solid var(--line); }
details.q > summary { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
details.q .rank { color: var(--muted); font-variant-numeric: tabular-nums; min-width: 2.2em; }
details.q .name { font-weight: 620; word-break: break-all; }

ul.ev { margin: 6px 0; padding-left: 18px; }
ul.ev li { margin: 3px 0; word-break: break-word; }
dl.kv { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 8px 0; font-size: 13.5px; }
dl.kv dt { color: var(--muted); }
dl.kv dd { margin: 0; word-break: break-word; }

.path { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: 8px 0; font-size: 13px; }
.hop { border: 1px solid var(--line); border-radius: 6px; padding: 3px 9px; background: var(--panel-2); word-break: break-all; }
.hop .t { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; }
.via { color: var(--muted); font-size: 11.5px; white-space: nowrap; }

.note { border-left: 3px solid var(--accent); background: var(--accent-soft);
        padding: 10px 14px; border-radius: 0 8px 8px 0; margin: 12px 0; font-size: 13.5px; }
.warn { border-left-color: var(--med); background: var(--med-bg); }
.empty { color: var(--muted); font-style: italic; font-size: 13.5px; margin: 10px 0; }
.trunc { color: var(--muted); font-size: 12.5px; margin: 8px 0 0; }
footer { margin-top: 44px; border-top: 1px solid var(--line); padding-top: 16px;
         color: var(--muted); font-size: 12.5px; }
@media (max-width: 720px) {
  .bar { grid-template-columns: 72px 1fr 42px; }
  dl.kv { grid-template-columns: 1fr; gap: 0 0; }
  dl.kv dt { margin-top: 8px; }
}
@media print {
  body { background: #fff; }
  nav.toc { display: none; }
  details { break-inside: avoid; }
  details > .body { display: block; }
}
"""


class HtmlReportRenderer:
    """
    Renders one report document as a self-contained HTML page.

    Reads only the document produced by `ReportBuilder`, so the HTML can
    never show a number the JSON report does not also contain.
    """

    def __init__(self, document: Dict[str, Any]):
        self.doc = _as_dict(document)
        self.out: List[str] = []
        self.toc: List[Tuple[str, str]] = []

    # -- primitives -------------------------------------------------------

    def _w(self, markup: str) -> None:
        self.out.append(markup)

    @staticmethod
    def chip(text: Any, css_class: str) -> _Markup:
        return _Markup(f'<span class="chip {_e(css_class)}">{_e(text)}</span>')

    @classmethod
    def severity_chip(cls, severity: Any, reported: Any = None) -> _Markup:
        """
        `severity` is the normalized level; `reported` is what the source
        actually said when that value was not a recognised level. Showing both
        keeps an unrecognised severity visible instead of hiding it behind a
        generic UNKNOWN.
        """
        if severity in (None, ""):
            return cls.chip("not assessed", "sev-NONE")
        normalized = normalize_severity(severity)
        raw = _text(reported).strip() or reported_severity(severity) or ""
        if normalized == UNKNOWN and raw:
            return cls.chip(f"UNKNOWN ({raw})", "sev-UNKNOWN")
        return cls.chip(normalized, f"sev-{normalized}")

    @classmethod
    def _sev(cls, entry: Dict[str, Any]) -> _Markup:
        """Severity chip for any entry carrying `severity`/`severity_reported`."""
        return cls.severity_chip(entry.get("severity"), entry.get("severity_reported"))

    @classmethod
    def confidence_chip(cls, confidence: Any) -> _Markup:
        normalized = normalize_confidence(confidence)
        return _Markup(f'<span class="kind">confidence {_e(normalized)}</span>')

    @classmethod
    def kind_chip(cls, kind: Any) -> _Markup:
        label = KIND_LABELS.get(_text(kind), _text(kind) or UNKNOWN)
        return _Markup(f'<span class="kind kind-{_e(_text(kind))}">{_e(label)}</span>')

    @staticmethod
    def _cell(value: Any) -> str:
        return _e(value) if not isinstance(value, _Markup) else str(value)

    def table(self, headers: Sequence[Any], rows: Sequence[Sequence[Any]],
              classes: Optional[Sequence[str]] = None, empty: str = "None recorded.") -> None:
        if not rows:
            self._w(f'<p class="empty">{_e(empty)}</p>')
            return
        classes = list(classes or [""] * len(headers))
        head = "".join(
            f'<th class="{_e(cls)}">{_e(header)}</th>' for header, cls in zip(headers, classes))
        body = []
        for row in rows:
            cells = "".join(
                f'<td class="{_e(cls)}">{self._cell(cell)}</td>'
                for cell, cls in zip(row, classes + [""] * len(row)))
            body.append(f"<tr>{cells}</tr>")
        self._w(f'<div class="tablewrap"><table><thead><tr>{head}</tr></thead>'
                f'<tbody>{"".join(body)}</tbody></table></div>')

    def truncation(self, marker: Any, artifact: str = "the JSON report") -> None:
        marker = _as_dict(marker)
        if not marker.get("truncated"):
            return
        self._w(f'<p class="trunc">Showing {_e(marker.get("shown"))} of '
                f'{_e(marker.get("total"))}; {_e(marker.get("omitted"))} further record(s) are '
                f'omitted here and available in {_e(artifact)}.</p>')

    def section(self, anchor: str, title: str, lede: str = "") -> None:
        self.toc.append((anchor, title))
        self._w(f'<section id="{_e(anchor)}"><h2>{_e(title)}</h2>')
        if lede:
            self._w(f'<p class="lede">{_e(lede)}</p>')

    def end_section(self) -> None:
        self._w("</section>")

    @staticmethod
    def _kv(pairs: Sequence[Tuple[str, Any]]) -> _Markup:
        rows = "".join(
            f"<dt>{_e(key)}</dt><dd>{_e(value) if not isinstance(value, _Markup) else value}</dd>"
            for key, value in pairs)
        return _Markup(f'<dl class="kv">{rows}</dl>')

    @staticmethod
    def _list(items: Sequence[Any], css: str = "ev") -> _Markup:
        if not items:
            return _Markup("")
        entries = "".join(
            f"<li>{_e(item) if not isinstance(item, _Markup) else item}</li>" for item in items)
        return _Markup(f'<ul class="{_e(css)}">{entries}</ul>')

    # -- sections ---------------------------------------------------------

    def _render_summary(self) -> None:
        summary = _as_dict(self.doc.get("executive_summary"))
        severity = _as_dict(self.doc.get("severity"))
        self.section("summary", "Executive summary",
                     "What this reconnaissance run established about the target's externally "
                     "visible attack surface.")

        def card(label: str, value: Any) -> str:
            if value is None:
                return (f'<div class="card na"><div class="n">{_e(NOT_AVAILABLE)}</div>'
                        f'<div class="k">{_e(label)}</div></div>')
            return (f'<div class="card"><div class="n">{_e(value)}</div>'
                    f'<div class="k">{_e(label)}</div></div>')

        cards = [
            card("assets correlated", summary.get("assets")),
            card("observations", summary.get("observations")),
            card("relationships", summary.get("relationships")),
            card("risk signals", summary.get("signals")),
            card("investigation queue", summary.get("queue_length")),
            card("unresolved conflicts", summary.get("unresolved_conflicts")),
        ]
        self._w(f'<div class="cards">{"".join(cards)}</div>')

        headline = [_text(line) for line in _as_list(summary.get("headline"))]
        if headline:
            self._w(str(self._list(headline, css="headline")))

        if severity.get("available"):
            self._w("<h3>Evidence classes</h3>")
            self._w('<p class="lede">ReconHound keeps these four classes distinct. A possible CVE '
                    'match is never reported as a confirmed weakness.</p>')
            findings = _as_dict(self.doc.get("findings"))
            counts = _as_dict(findings.get("counts_by_evidence_class"))
            rows = []
            for kind in (risk_engine.KIND_CONFIRMED, risk_engine.KIND_VULN_INTEL,
                         risk_engine.KIND_INDICATOR, risk_engine.KIND_OBSERVATION):
                rows.append([self.kind_chip(kind), counts.get(kind, 0), KIND_DESCRIPTIONS[kind]])
            self.table(["Class", "Signals", "Meaning"], rows, ["nowrap", "num", ""])
        self.end_section()

    def _render_scan(self) -> None:
        scan = _as_dict(self.doc.get("scan"))
        self.section("scan", "Scan metadata")
        if not scan.get("execution_record_available"):
            self._w(f'<p class="note warn">{_e(scan.get("reason") or NO_EXECUTION)} '
                    f'Run mode, module coverage and partial-failure information are therefore '
                    f'not part of this report.</p>')
        pairs: List[Tuple[str, Any]] = [("Target", self.doc.get("target"))]
        if scan.get("execution_record_available"):
            selected = _as_list(scan.get("modules_selected"))
            pairs.extend([
                ("Execution mode", scan.get("mode") or UNKNOWN),
                ("Run status", scan.get("run_status") or UNKNOWN),
                ("Started", scan.get("started_at") or NOT_AVAILABLE),
                ("Finished", scan.get("finished_at") or NOT_AVAILABLE),
                ("Interrupted", _tri_state(scan.get("interrupted"), "yes", "no")),
                ("Modules selected", f"{len(selected)}: {', '.join(selected)}" if selected else NOT_AVAILABLE),
            ])
            settings = _as_dict(scan.get("settings"))
            pairs.append(("Settings", ", ".join(
                f"{key}={display_value(value)}" for key, value in sorted(settings.items())
                if value is not None) or NOT_AVAILABLE))
        pairs.extend([
            ("Graph last updated", scan.get("graph_updated_at") or NOT_AVAILABLE),
            ("Risk assessment", scan.get("assessment_generated_at")
             or ("not available" if not scan.get("assessment_available") else UNKNOWN)),
            ("Newest evidence", scan.get("newest_evidence_at") or NOT_AVAILABLE),
            ("Minimum queued severity", scan.get("min_queue_severity") or NOT_AVAILABLE),
            ("Report generated", self.doc.get("generated_at")),
        ])
        self._w(f'<div class="panel">{self._kv(pairs)}</div>')

        scope = _as_dict(scan.get("scope"))
        if scope:
            in_scope = [_text(h) for h in _as_list(scope.get("in_scope_hostnames"))]
            out_scope = [_text(h) for h in _as_list(scope.get("out_of_scope_hostnames_observed"))]
            self._w("<h3>Authorized scope</h3>")
            self.table(
                ["", "Hostnames"],
                [["In scope", ", ".join(in_scope) or "none recorded"],
                 ["Observed but out of scope", ", ".join(out_scope) or "none recorded"]],
                ["nowrap", "break"])
        self.end_section()

    def _render_risk(self) -> None:
        severity = _as_dict(self.doc.get("severity"))
        self.section("risk", "Risk overview",
                     "Severity is risk_engine.py's prioritization of where to look first. It is "
                     "not proof that anything here is exploitable.")
        if not severity.get("available"):
            self._w(f'<p class="note warn">{_e(severity.get("reason") or NO_ASSESSMENT)} '
                    f'It therefore contains no severity assessment, and nothing below is '
                    f'prioritized.</p>')
            self.end_section()
            return

        for label, key in (("Assets by severity", "assets_by_severity"),
                           ("Signals by severity", "signals_by_severity")):
            counts = _as_dict(severity.get(key))
            total = sum(_int(v) for v in counts.values()) or 1
            self._w(f"<h3>{_e(label)}</h3><div class=\"bars\">")
            for name in list(SEVERITY_SEQUENCE) + [UNKNOWN]:
                count = _int(counts.get(name))
                if name == UNKNOWN and not count:
                    continue
                width = max(0.0, min(100.0, (count / total) * 100.0))
                self._w(
                    f'<div class="bar"><span class="chip sev-{_e(name)}">{_e(name)}</span>'
                    f'<span class="track"><span class="fill sev-{_e(name)}" '
                    f'style="width:{width:.1f}%"></span></span>'
                    f'<span class="n">{_e(count)}</span></div>')
            self._w("</div>")

        pairs = [
            ("Assets assessed", severity.get("assets_assessed")),
            ("Signals extracted", severity.get("signals")),
            ("Investigation queue length", severity.get("queue_length")),
            ("Signals suspended pending conflict resolution", severity.get("suspended_signals")),
            ("Signals flagged stale", severity.get("stale_signals")),
            ("Out-of-scope assets assessed but never queued", severity.get("out_of_scope_assets")),
        ]
        self._w(f'<div class="panel">{self._kv(pairs)}</div>')
        self.end_section()

    def _render_queue(self) -> None:
        queue = _as_dict(self.doc.get("investigation_queue"))
        self.section("queue", "Prioritized investigation queue",
                     "Where to look first, in order, with the reasoning risk_engine.py recorded "
                     "for each position.")
        if not queue.get("available"):
            self._w(f'<p class="note warn">{_e(queue.get("reason") or "Not available.")}</p>')
            self.end_section()
            return
        entries = _as_list(queue.get("entries"))
        if not entries:
            self._w('<p class="empty">The investigation queue is empty at the configured minimum '
                    'severity. Nothing scored above the threshold.</p>')
            self.end_section()
            return
        for entry in entries:
            entry = _as_dict(entry)
            counts = (f'{_int(entry.get("contributing_signal_count"))} contributing of '
                      f'{_int(entry.get("total_signal_count"))} signal(s)')
            self._w(
                f'<details class="q"><summary>'
                f'<span class="rank">#{_e(entry.get("rank"))}</span>'
                f'{self._sev(entry)}'
                f'{self.confidence_chip(entry.get("confidence"))}'
                f'<span class="name">{_e(entry.get("label"))}</span>'
                f'<span class="via">{_e(entry.get("asset_type_label"))} · {_e(counts)}</span>'
                f'</summary><div class="body">')
            pairs: List[Tuple[str, Any]] = [
                ("Asset", _Markup(f'<span class="mono">{_e(entry.get("asset_id"))}</span>')),
                ("In scope", _tri_state(entry.get("in_scope"), "yes", "no")),
                ("Signal categories", ", ".join(_as_list(entry.get("categories"))) or "none"),
                ("Directly observed findings", entry.get("confirmed_finding_count")),
                ("Unverified indicators", entry.get("indicator_count")),
                ("Possible CVE matches", entry.get("vulnerability_intelligence_count")),
            ]
            if _as_list(entry.get("unresolved_conflicts")):
                pairs.append(("Unresolved conflicts",
                              ", ".join(_as_list(entry.get("unresolved_conflicts")))))
            if _as_list(entry.get("suspended_signal_ids")):
                pairs.append(("Suspended signals",
                              ", ".join(_as_list(entry.get("suspended_signal_ids")))))
            self._w(str(self._kv(pairs)))
            explanation = [_text(line) for line in _as_list(entry.get("explanation"))]
            if explanation:
                self._w("<h3>Why it is ranked here</h3>")
                self._w(str(self._list(explanation)))
            signals = _as_list(entry.get("top_signals"))
            if signals:
                self._w("<h3>Strongest signals</h3>")
                rows = []
                for signal in signals:
                    signal = _as_dict(signal)
                    rows.append([
                        self.severity_chip(signal.get("severity"), signal.get("severity_reported")),
                        self.kind_chip(signal.get("kind")),
                        signal.get("summary"),
                        ", ".join(_as_list(signal.get("sources"))) or UNKNOWN,
                    ])
                self.table(["Severity", "Class", "Signal", "Sources"], rows,
                           ["nowrap", "nowrap", "", "nowrap"])
            self._w("</div></details>")
        self.truncation(queue)
        self.end_section()

    def _render_findings(self) -> None:
        findings = _as_dict(self.doc.get("findings"))
        self.section("findings", "Findings and signals",
                     "Every risk signal risk_engine.py extracted, grouped by severity, with the "
                     "evidence and the module that produced it.")
        if not findings.get("available"):
            self._w(f'<p class="note warn">{_e(findings.get("reason") or "Not available.")}</p>')
            self.end_section()
            return
        entries = [_as_dict(e) for e in _as_list(findings.get("entries"))]
        if not entries:
            self._w('<p class="empty">No risk signals were extracted from this graph.</p>')
            self.end_section()
            return

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for entry in entries:
            grouped.setdefault(normalize_severity(entry.get("severity")), []).append(entry)
        for severity in list(SEVERITY_SEQUENCE) + [UNKNOWN]:
            bucket = grouped.get(severity)
            if not bucket:
                continue
            self._w(f'<h3>{_e(severity)} — {_e(len(bucket))} signal(s)</h3>')
            for entry in bucket:
                self._render_finding(entry)
        self.truncation(findings)
        self.end_section()

    def _render_finding(self, entry: Dict[str, Any]) -> None:
        flags = []
        if entry.get("suspended"):
            flags.append('<span class="flag">suspended — not scored</span>')
        if entry.get("stale"):
            flags.append('<span class="flag">stale evidence</span>')
        subject = _as_dict(entry.get("subject"))
        self._w(
            f'<details><summary>'
            f'{self._sev(entry)}'
            f'{self.kind_chip(entry.get("kind"))}'
            f'{self.confidence_chip(entry.get("confidence"))} '
            f'{"".join(flags)} {_e(entry.get("summary"))}'
            f'</summary><div class="body">')
        pairs: List[Tuple[str, Any]] = [
            ("Category", entry.get("category") or UNKNOWN),
            ("Evidence class", _Markup(
                f'{self.kind_chip(entry.get("kind"))} — {_e(KIND_DESCRIPTIONS.get(_text(entry.get("kind")), ""))}')),
            ("Affected asset", subject.get("label") or NOT_AVAILABLE),
            ("Asset id", _Markup(f'<span class="mono">{_e(subject.get("asset_id"))}</span>')
             if subject.get("asset_id") else NOT_AVAILABLE),
            ("Producing module(s)", ", ".join(_as_list(entry.get("sources"))) or UNKNOWN),
            ("Base severity before correlation", entry.get("base_severity")),
            ("Last seen", entry.get("last_seen") or NOT_AVAILABLE),
        ]
        if entry.get("kind") == risk_engine.KIND_VULN_INTEL:
            pairs.extend([
                ("CVE", entry.get("cve_id") or UNKNOWN),
                ("Affected technology", " ".join(
                    part for part in (_text(entry.get("technology")),
                                      _text(entry.get("technology_version"))) if part) or UNKNOWN),
                ("CVSS score", entry.get("cvss_score") if entry.get("cvss_score") is not None
                 else "not published / not retrieved"),
                ("Applicability to the observed version", entry.get("applicability") or UNKNOWN),
            ])
        if entry.get("suspended"):
            pairs.append(("Suspension reason", entry.get("suspension_reason") or UNKNOWN))
        if entry.get("stale"):
            pairs.append(("Age", f"{display_value(entry.get('age_days'))} day(s) older than the "
                                 f"newest evidence in this graph"))
        self._w(str(self._kv(pairs)))

        evidence = [_text(item) for item in _as_list(entry.get("evidence"))]
        if evidence:
            self._w("<h3>Evidence</h3>")
            self._w(str(self._list(evidence)))
            self.truncation(entry.get("evidence_truncation"), "surface_graph.json")
        provenance = [_as_dict(p) for p in _as_list(entry.get("provenance"))]
        if provenance:
            self._w("<h3>Provenance</h3>")
            rows = [[p.get("source") or UNKNOWN,
                     _Markup(f'<span class="mono">{_e(p.get("observation_id"))}</span>'),
                     p.get("confidence") or UNKNOWN, p.get("timestamp") or UNKNOWN]
                    for p in provenance]
            self.table(["Module", "Observation", "Confidence", "Observed at"], rows,
                       ["nowrap", "break", "nowrap", "nowrap"])
            self.truncation(entry.get("provenance_truncation"), "surface_graph.json")
        rationale = [_text(line) for line in _as_list(entry.get("rationale"))]
        if rationale:
            self._w("<h3>How this severity was reached</h3>")
            self._w(str(self._list(rationale)))
        notes = [_text(note) for note in _as_list(entry.get("notes"))]
        if notes:
            self._w("<h3>Notes</h3>")
            self._w(str(self._list(notes)))
        detail = entry.get("detail")
        if isinstance(detail, dict) and detail:
            self._w("<h3>Recorded detail</h3>")
            rows = [[key, display_value(detail[key], max_length=600)] for key in sorted(detail, key=str)]
            self.table(["Field", "Value"], rows, ["nowrap", "break"])
        self._w("</div></details>")

    def _render_vuln_intel(self) -> None:
        vuln = _as_dict(self.doc.get("vulnerability_intelligence"))
        self.section("vulnintel", "Vulnerability intelligence",
                     "Possible matches between observed versions and public CVE records.")
        if not vuln.get("available"):
            self._w(f'<p class="note warn">{_e(vuln.get("reason") or "Not available.")}</p>')
            self.end_section()
            return
        self._w(f'<p class="note">{_e(vuln.get("statement"))}</p>')
        entries = [_as_dict(e) for e in _as_list(vuln.get("entries"))]
        if not entries:
            self._w('<p class="empty">No CVE matches were recorded. This means no observed '
                    'version matched a CVE record ReconHound retrieved — not that the target is '
                    'free of known vulnerabilities.</p>')
            self.end_section()
            return
        rows = []
        for entry in entries:
            technology = " ".join(part for part in (_text(entry.get("technology")),
                                                    _text(entry.get("technology_version"))) if part)
            rows.append([
                self._sev(entry),
                entry.get("cve_id") or UNKNOWN,
                technology or UNKNOWN,
                entry.get("cvss_score") if entry.get("cvss_score") is not None else "—",
                entry.get("applicability") or UNKNOWN,
                self.confidence_chip(entry.get("confidence")),
                _as_dict(entry.get("subject")).get("label") or NOT_AVAILABLE,
            ])
        self.table(
            ["Severity", "CVE", "Observed technology", "CVSS", "Applicability", "Confidence", "Asset"],
            rows, ["nowrap", "nowrap", "break", "num", "nowrap", "nowrap", "break"])
        self.truncation(vuln)
        self._w('<p class="lede">Applicability is vuln_intel.py\'s own assessment of whether the '
                'observed version falls inside the CVE\'s documented range. Anything other than a '
                'confirmed version range means the match is unconfirmed and requires manual '
                'verification before it can be treated as applicable.</p>')
        self.end_section()

    def _render_paths(self) -> None:
        paths = _as_dict(self.doc.get("attack_surface_paths"))
        self.section("paths", "Attack-surface paths",
                     "How each prioritized asset was reached, hop by hop, and which module "
                     "produced each hop.")
        if not paths.get("available"):
            self._w(f'<p class="note warn">{_e(paths.get("reason") or "Not available.")}</p>')
            self.end_section()
            return
        entries = [_as_dict(e) for e in _as_list(paths.get("entries"))]
        if not entries:
            self._w('<p class="empty">No discovery chains could be reconstructed from the recorded '
                    'relationships.</p>')
            self.end_section()
            return
        for entry in entries:
            hops = [_as_dict(h) for h in _as_list(entry.get("hops"))]
            chain: List[str] = []
            for index, hop in enumerate(hops):
                via = _as_dict(hop.get("via"))
                if index and via:
                    sources = ", ".join(_text(s) for s in _as_list(via.get("sources")))
                    label = _text(via.get("relationship_type")) or "related"
                    chain.append(f'<span class="via">→ {_e(label)}'
                                 f'{_e(" (" + sources + ")") if sources else ""} →</span>')
                elif index:
                    chain.append('<span class="via">→</span>')
                note = _text(hop.get("note"))
                chain.append(
                    f'<span class="hop" title="{_e(hop.get("asset_id"))}">'
                    f'<span class="t">{_e(hop.get("asset_type_label"))}</span> '
                    f'{_e(hop.get("label"))}'
                    f'{" " + _e(note) if note else ""}</span>')
            self._w(f'<details><summary>{self._sev(entry)} '
                    f'{_e(entry.get("label"))} '
                    f'<span class="via">{_e(entry.get("hop_count"))} hop(s)</span></summary>'
                    f'<div class="body"><div class="path">{"".join(chain)}</div></div></details>')
        self.truncation(paths)
        self.end_section()

    def _render_inventory(self) -> None:
        inventory = _as_dict(self.doc.get("asset_inventory"))
        self.section("inventory", "Target asset inventory",
                     "Every asset surface_mapper.py correlated, with its evidence, confidence and "
                     "scope tag.")
        scope = _as_dict(inventory.get("scope"))
        cards = [
            f'<div class="card"><div class="n">{_e(inventory.get("total", 0))}</div>'
            f'<div class="k">assets</div></div>',
            f'<div class="card"><div class="n">{_e(scope.get("in_scope", 0))}</div>'
            f'<div class="k">in scope</div></div>',
            f'<div class="card"><div class="n">{_e(scope.get("out_of_scope", 0))}</div>'
            f'<div class="k">out of scope</div></div>',
            f'<div class="card"><div class="n">{_e(scope.get("scope_not_determined", 0))}</div>'
            f'<div class="k">scope undetermined</div></div>',
        ]
        self._w(f'<div class="cards">{"".join(cards)}</div>')

        by_state = _as_dict(inventory.get("by_state"))
        if by_state:
            self._w("<h3>Discovery state</h3>")
            self.table(["State", "Assets"],
                       [[key, by_state[key]] for key in sorted(by_state, key=str)],
                       ["nowrap", "num"])

        groups = [_as_dict(g) for g in _as_list(inventory.get("groups"))]
        if not groups:
            self._w('<p class="empty">No assets were correlated into the graph.</p>')
            self.end_section()
            return
        for group in groups:
            entries = [_as_dict(e) for e in _as_list(group.get("entries"))]
            self._w(f'<h3>{_e(group.get("label"))} — {_e(group.get("count"))}</h3>')
            rows = []
            for entry in entries:
                attributes = [_as_dict(a) for a in _as_list(entry.get("attributes"))]
                attribute_text = ", ".join(
                    f'{_text(a.get("name"))}={_text(a.get("display"))}'
                    + (" [conflict]" if a.get("has_conflict") else "")
                    for a in attributes[:6])
                if len(attributes) > 6:
                    attribute_text += f", +{len(attributes) - 6} more"
                rows.append([
                    self._sev(entry),
                    entry.get("label"),
                    _tri_state(entry.get("in_scope"), "in scope", "out of scope"),
                    entry.get("discovery_state") or UNKNOWN,
                    entry.get("graph_confidence"),
                    ", ".join(_as_list(entry.get("sources"))) or UNKNOWN,
                    attribute_text or "—",
                ])
            self.table(
                ["Severity", "Asset", "Scope", "State", "Confidence", "Discovered by", "Attributes"],
                rows, ["nowrap", "break", "nowrap", "nowrap", "nowrap", "break", "break"])
            self.truncation(group, "surface_graph.json")
        self.end_section()

    def _render_technologies(self) -> None:
        technologies = _as_dict(self.doc.get("technologies"))
        self.section("tech", "Technology stack",
                     "Technologies fingerprinted on in-scope assets, with the confidence behind "
                     "each identification.")
        entries = [_as_dict(e) for e in _as_list(technologies.get("entries"))]
        rows = []
        for entry in entries:
            version = entry.get("version") or "—"
            if entry.get("version_conflict"):
                version = _Markup(f'{_e(version)} <span class="flag">disputed</span>')
            rows.append([
                self._sev(entry),
                entry.get("name"),
                version,
                entry.get("category") or "—",
                entry.get("observed_on") or UNKNOWN,
                entry.get("confidence"),
                ", ".join(_as_list(entry.get("sources"))) or UNKNOWN,
            ])
        self.table(["Severity", "Technology", "Version", "Category", "Observed on",
                    "Confidence", "Detected by"], rows,
                   ["nowrap", "break", "nowrap", "nowrap", "break", "nowrap", "break"],
                   empty="No technologies were fingerprinted.")
        self.truncation(technologies, "surface_graph.json")
        self.end_section()

    def _render_services(self) -> None:
        services = _as_dict(self.doc.get("services"))
        self.section("services", "Exposed services",
                     "Network services observed on in-scope addresses.")
        entries = [_as_dict(e) for e in _as_list(services.get("entries"))]
        rows = []
        for entry in entries:
            rows.append([
                self._sev(entry),
                entry.get("label"),
                entry.get("status") or UNKNOWN,
                entry.get("service") or "—",
                entry.get("banner") or "—",
                ", ".join(_as_list(entry.get("sources"))) or UNKNOWN,
            ])
        self.table(["Severity", "Service", "Status", "Identified as", "Banner", "Observed by"],
                   rows, ["nowrap", "nowrap", "nowrap", "break", "break", "break"],
                   empty="No open services were recorded.")
        self.truncation(services, "surface_graph.json")
        self.end_section()

    def _render_simple(self, anchor: str, title: str, lede: str, key: str, empty: str,
                       column: str = "Asset", dependencies: bool = False) -> None:
        group = _as_dict(self.doc.get(key))
        self.section(anchor, title, lede)
        entries = [_as_dict(e) for e in _as_list(group.get("entries"))]
        headers = ["Severity", column, "Scope", "Confidence", "Observed by"]
        classes = ["nowrap", "break", "nowrap", "nowrap", "break"]
        if dependencies:
            headers.append("Depended on by")
            classes.append("break")
        rows = []
        for entry in entries:
            row = [
                self._sev(entry),
                entry.get("label"),
                _tri_state(entry.get("in_scope"), "in scope", "out of scope"),
                entry.get("confidence"),
                ", ".join(_as_list(entry.get("sources"))) or UNKNOWN,
            ]
            if dependencies:
                dependents = [_text(_as_dict(d).get("label"))
                              for d in _as_list(entry.get("depended_on_by"))]
                row.append(", ".join(d for d in dependents if d) or "—")
            rows.append(row)
        self.table(headers, rows, classes, empty=empty)
        self.truncation(group, "surface_graph.json")
        self.end_section()

    def _render_relationships(self) -> None:
        relationships = _as_dict(self.doc.get("relationships"))
        self.section("relationships", "Asset relationships",
                     "The correlation itself: how many links of each type connect the graph.")
        by_type = _as_dict(relationships.get("by_type"))
        self.table(["Relationship", "Count"],
                   [[key, by_type[key]] for key in sorted(by_type, key=lambda k: (-_int(by_type[k]), k))],
                   ["nowrap", "num"], empty="No relationships were recorded.")
        self.end_section()

    def _render_conflicts(self) -> None:
        conflicts = _as_dict(self.doc.get("conflicts"))
        self.section("conflicts", "Conflicting observations",
                     "Contradictions between modules are preserved, never silently resolved. Any "
                     "assessment depending on a disputed value is held back.")
        entries = [_as_dict(e) for e in _as_list(conflicts.get("entries"))]
        if not entries:
            self._w('<p class="empty">No module contradicted another during this run.</p>')
            self.end_section()
            return
        for entry in entries:
            asset = _as_dict(entry.get("asset"))
            self._w(f'<details><summary><span class="flag">{_e(entry.get("status"))}</span> '
                    f'{_e(asset.get("label"))} — {_e(entry.get("attribute"))}</summary>'
                    f'<div class="body">')
            rows = [[o.get("display"), _as_dict(o).get("source") or UNKNOWN,
                     _Markup(f'<span class="mono">{_e(_as_dict(o).get("observation_id"))}</span>'),
                     _as_dict(o).get("timestamp") or UNKNOWN]
                    for o in (_as_dict(x) for x in _as_list(entry.get("observations")))]
            self.table(["Reported value", "Reported by", "Observation", "At"], rows,
                       ["break", "nowrap", "break", "nowrap"])
            if entry.get("truncated_observations"):
                self._w('<p class="trunc">This conflict has more recorded observations than are '
                        'shown; the full list is in surface_graph.json.</p>')
            suspended = [_text(s) for s in _as_list(entry.get("suspended_signals"))]
            if suspended:
                self._w("<h3>Assessments held back by this conflict</h3>")
                self._w(str(self._list(suspended)))
            self._w("</div></details>")
        self.truncation(conflicts, "surface_graph.json")
        self.end_section()

    def _render_negative(self) -> None:
        negative = _as_dict(self.doc.get("negative_results"))
        self.section("negative", "Checks that found nothing",
                     "Negative-result memory: what was checked and came back empty. Recorded so "
                     "coverage is not mistaken for absence of evidence.")
        census = _as_dict(negative.get("check_state_census"))
        if census:
            self.table(["Check state", "Count"],
                       [[key, census[key]] for key in sorted(census, key=str)], ["nowrap", "num"])
        entries = [_as_dict(e) for e in _as_list(negative.get("entries"))]
        rows = []
        for entry in entries:
            rows.append([
                _as_dict(entry.get("asset")).get("label") or UNKNOWN,
                entry.get("check") or UNKNOWN,
                entry.get("state") or UNKNOWN,
                entry.get("source") or UNKNOWN,
                entry.get("check_count"),
                entry.get("last_checked_at") or UNKNOWN,
            ])
        self._w("<h3>Recorded negative results</h3>")
        self.table(["Asset", "Check", "State", "Checked by", "Times", "Last checked"], rows,
                   ["break", "break", "nowrap", "nowrap", "num", "nowrap"],
                   empty="No negative results were recorded.")
        self.truncation(negative, "surface_graph.json")
        self.end_section()

    def _render_execution(self) -> None:
        execution = _as_dict(self.doc.get("execution"))
        self.section("execution", "Module execution status",
                     "Which modules ran, against what, and what failed. Coverage gaps are stated, "
                     "not hidden.")
        if not execution.get("available"):
            self._w(f'<p class="note warn">{_e(execution.get("reason") or "Not available.")}</p>')
            self.end_section()
            return
        failed = [_as_dict(m) for m in _as_list(execution.get("failed_modules"))]
        if failed:
            self._w(f'<p class="note warn">{_e(len(failed))} module execution(s) did not complete '
                    f'successfully. The attack surface below is incomplete.</p>')
        modules = [_as_dict(m) for m in _as_list(execution.get("modules"))]
        rows = []
        for module in modules:
            detail = module.get("skip_reason") or module.get("error") or "—"
            if module.get("error") and module.get("error_type"):
                detail = f'{_text(module.get("error_type"))}: {_text(module.get("error"))}'
            rows.append([
                module.get("module") or UNKNOWN,
                module.get("phase") or UNKNOWN,
                module.get("subject") or "—",
                module.get("status") or UNKNOWN,
                module.get("observations_ingested"),
                detail,
            ])
        self.table(["Module", "Phase", "Subject", "Status", "Observations", "Detail"], rows,
                   ["nowrap", "nowrap", "break", "nowrap", "num", "break"],
                   empty="No module executions were recorded.")
        self.truncation(execution.get("module_truncation"), "orchestrator_run.json")

        errors = [_as_dict(e) for e in _as_list(execution.get("errors"))]
        if errors:
            self._w("<h3>Run-level errors</h3>")
            self.table(["Stage", "Error"],
                       [[e.get("stage") or UNKNOWN, e.get("error") or UNKNOWN] for e in errors],
                       ["nowrap", "break"])
            self.truncation(execution.get("error_truncation"), "orchestrator_run.json")

        adaptive = _as_dict(execution.get("adaptive"))
        manual = [_as_dict(m) for m in _as_list(adaptive.get("manual_review"))]
        self._w("<h3>Adaptive discovery</h3>")
        self._w(str(self._kv([
            ("Follow-up actions fired", adaptive.get("actions")),
            ("Adaptive rounds", adaptive.get("rounds")),
            ("Deferred by run budget", adaptive.get("deferred")),
            ("Awaiting manual verification", len(manual)),
        ])))
        if manual:
            self.table(["Opportunity", "Asset", "Priority", "Reason"],
                       [[m.get("opportunity_type") or UNKNOWN, display_value(m.get("target_value")),
                         m.get("priority") or UNKNOWN, m.get("reason") or UNKNOWN] for m in manual],
                       ["nowrap", "break", "nowrap", "break"])
        self.end_section()

    def _render_appendix(self) -> None:
        observations = _as_dict(self.doc.get("observations"))
        self.section("appendix", "Raw data appendix",
                     "The normalized observations every conclusion above is built from, newest "
                     "first.")
        by_source = _as_dict(observations.get("by_source"))
        if by_source:
            self.table(["Producing module", "Observations"],
                       [[key, by_source[key]] for key in
                        sorted(by_source, key=lambda k: (-_int(by_source[k]), k))],
                       ["nowrap", "num"])
        entries = [_as_dict(e) for e in _as_list(observations.get("entries"))]
        self._w("<h3>Observations</h3>")
        rows = []
        for entry in entries:
            rows.append([
                entry.get("timestamp") or UNKNOWN,
                entry.get("source") or UNKNOWN,
                entry.get("type") or UNKNOWN,
                entry.get("target") or UNKNOWN,
                entry.get("confidence"),
                entry.get("value") or "—",
            ])
        self.table(["Observed at", "Module", "Type", "Subject", "Confidence", "Value"], rows,
                   ["nowrap", "nowrap", "nowrap", "break", "nowrap", "break"],
                   empty="No observations were recorded.")
        self.truncation(observations, "surface_graph.json")
        self.end_section()

    def _render_caveats(self) -> None:
        self.section("caveats", "Warnings, limitations and source data")
        warnings = [_text(w) for w in _as_list(self.doc.get("warnings"))]
        if warnings:
            self._w("<h3>Warnings</h3>")
            self._w(str(self._list(warnings)))
        limitations = [_text(item) for item in _as_list(self.doc.get("limitations"))]
        self._w("<h3>Limitations of this report</h3>")
        if limitations:
            self._w(str(self._list(limitations)))
        else:
            self._w('<p class="empty">No coverage limitations were recorded for this run.</p>')
        errors = [_as_dict(e) for e in _as_list(self.doc.get("errors"))]
        if errors:
            self._w("<h3>Report generation errors</h3>")
            self.table(["Stage", "Error"],
                       [[e.get("stage") or UNKNOWN,
                         e.get("error") or UNKNOWN] for e in errors], ["nowrap", "break"])
        self._w("<h3>Standing statements</h3>")
        self._w(str(self._list([_text(n) for n in _as_list(self.doc.get("notes"))])))
        artifacts = _as_dict(self.doc.get("source_artifacts"))
        self._w("<h3>Source artifacts</h3>")
        self.table(["Artifact", "Path"],
                   [[key, artifacts[key] or "not produced by this run"]
                    for key in sorted(artifacts, key=str)], ["nowrap", "break"])
        self.end_section()

    # -- document ---------------------------------------------------------

    def render(self) -> str:
        self._render_summary()
        self._render_scan()
        self._render_risk()
        self._render_queue()
        self._render_findings()
        self._render_vuln_intel()
        self._render_paths()
        self._render_inventory()
        self._render_technologies()
        self._render_services()
        self._render_simple("endpoints", "Endpoints", "Web and API endpoints discovered in scope.",
                            "endpoints", "No endpoints were discovered.", column="Endpoint")
        self._render_simple("javascript", "JavaScript assets",
                            "Client-side scripts analysed for endpoints, configuration and secret "
                            "indicators.", "javascript", "No JavaScript assets were recorded.",
                            column="Script")
        self._render_simple("supplychain", "Supply chain",
                            "Third-party services in-scope assets depend on.",
                            "supply_chain", "No third-party dependencies were recorded.",
                            column="Third-party service", dependencies=True)
        self._render_relationships()
        self._render_conflicts()
        self._render_negative()
        self._render_execution()
        self._render_appendix()
        self._render_caveats()

        body = "".join(self.out)
        nav = "".join(f'<a href="#{_e(anchor)}">{_e(title)}</a>' for anchor, title in self.toc)
        summary = _as_dict(self.doc.get("executive_summary"))
        scan = _as_dict(self.doc.get("scan"))
        status = _text(scan.get("run_status"))

        subject_bits = [f'<span class="target">{_e(self.doc.get("target"))}</span>']
        if status:
            subject_bits.append(f'<span class="meta">run status: {_e(status)}</span>')
        subject_bits.append(
            f'<span class="meta">generated {_e(self.doc.get("generated_at"))}</span>')
        subject_bits.append(
            f'<span class="meta">{_e(summary.get("assets", 0))} asset(s), '
            f'{_e(summary.get("observations", 0))} observation(s)</span>')

        return (
            "<!doctype html>\n"
            '<html lang="en">\n<head>\n'
            '<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            # The report is entirely self-contained: no scripts, no external
            # resources. This policy makes that structural rather than merely
            # intended, so target-controlled content can never execute.
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
            "style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'\">\n"
            '<meta name="referrer" content="no-referrer">\n'
            '<meta name="generator" content="ReconHound report_generator.py">\n'
            f"<title>{_e(self.doc.get('title'))}</title>\n"
            f"<style>{HTML_STYLE}</style>\n"
            "</head>\n<body>\n"
            '<header class="masthead"><div class="wrap">'
            '<div class="brand"><h1>ReconHound</h1>'
            f'<span class="ver">report schema {_e(self.doc.get("report_schema_version"))}</span>'
            '<span class="tag">correlated attack-surface reconnaissance — '
            'authorized targets only</span></div>'
            f'<div class="subject">{"".join(subject_bits)}</div>'
            "</div></header>\n"
            f'<div class="wrap"><nav class="toc">{nav}</nav>{body}'
            '<footer>Generated by ReconHound report_generator.py. Every severity in this report is '
            'a prioritization assessment, not proof of exploitability, and nothing here was '
            'verified by exploitation. Reconnaissance was confined to the authorized target and '
            'its subdomains.</footer>'
            "</div>\n</body>\n</html>\n"
        )


def render_html_report(document: Dict[str, Any]) -> str:
    """Render a report document as a standalone HTML page. Pure; no I/O."""
    return HtmlReportRenderer(document).render()


# ---------------------------------------------------------------------------
# Single-call entry point (this is what reconhound.py invokes)
# ---------------------------------------------------------------------------

def generate_report(
    graph: Any = None,
    assessment: Any = None,
    execution: Any = None,
    output_dir: str = "output",
    formats: Sequence[str] = VALID_FORMATS,
    filename_stem: str = DEFAULT_FILENAME_STEM,
    reports_subdir: str = DEFAULT_REPORT_SUBDIR,
    target: Optional[str] = None,
    limits: Optional[Dict[str, int]] = None,
    persist: bool = True,
) -> Dict[str, Any]:
    """
    Build the report document and write the requested formats.

    `graph` accepts a live SurfaceMapper, a state dict, a path, or None
    (meaning <output_dir>/surface_graph.json). `assessment` and `execution`
    accept a dict, a path, or None (meaning the corresponding artifact in
    `output_dir`); both are optional and their absence is reported in the
    output rather than treated as an error.

    Returns a result document describing what was generated. A format that
    fails to write is recorded in `errors` and never appears in
    `output_paths`, so a caller can never be handed a path to a file that
    does not exist.
    """
    requested: List[str] = []
    for value in formats or ():
        name = _text(value).strip().lower()
        if name not in VALID_FORMATS:
            raise ReportError(
                f"Unsupported report format {value!r}; valid formats are {list(VALID_FORMATS)}.")
        if name not in requested:
            requested.append(name)
    if not requested:
        raise ReportError("At least one report format must be requested.")

    stem = _text(filename_stem).strip() or DEFAULT_FILENAME_STEM
    # The stem names a file inside the report directory and must never be able
    # to escape it or address another directory.
    if os.path.basename(stem) != stem or stem in (".", ".."):
        raise ReportError(f"Report filename stem {filename_stem!r} must be a plain file name.")

    document = build_report_document(
        graph=graph, assessment=assessment, execution=execution,
        output_dir=output_dir, target=target, limits=limits)

    result: Dict[str, Any] = {
        "module": MODULE_NAME,
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "target": document.get("target"),
        "generated_at": document.get("generated_at"),
        "formats": list(requested),
        "output_paths": {},
        "reports_dir": None,
        "summary": _as_dict(document.get("executive_summary")),
        "warnings": list(_as_list(document.get("warnings"))),
        "limitations": list(_as_list(document.get("limitations"))),
        "errors": list(_as_list(document.get("errors"))),
        "persisted": bool(persist),
    }

    if not persist:
        result["document"] = document
        return result

    store = ReportStore(output_dir=output_dir, subdir=reports_subdir)
    result["reports_dir"] = os.path.abspath(store.reports_dir)

    for fmt in requested:
        try:
            if fmt == FORMAT_HTML:
                path = store.save_text(f"{stem}.html", render_html_report(document))
            else:
                path = store.save_json(f"{stem}.json", document)
        except Exception as exc:
            # A failed format must not cost the other one, and must never be
            # reported back as a path the caller can show an operator.
            result["errors"].append({"stage": f"render_{fmt}", "error": f"{type(exc).__name__}: {exc}"})
            continue
        result["output_paths"][fmt] = os.path.abspath(path)

    if not result["output_paths"]:
        raise PersistenceError(
            "No report could be written. " + "; ".join(
                _text(_as_dict(e).get("error")) for e in result["errors"][-len(requested):]))
    return result


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="report_generator.py",
        description="ReconHound Module 21 — professional reporting (standalone entry point). "
                    "Reads state ReconHound already produced; performs no reconnaissance.",
    )
    parser.add_argument("--output-dir", default="output",
                        help="Directory holding surface_graph.json / risk_assessment.json / "
                             "orchestrator_run.json, and receiving reports/ (default: output)")
    parser.add_argument("--graph", default=None,
                        help="Path to a surface_graph.json (defaults to <output-dir>/surface_graph.json)")
    parser.add_argument("--assessment", default=None,
                        help="Path to a risk_assessment.json (defaults to <output-dir>/risk_assessment.json)")
    parser.add_argument("--execution", default=None,
                        help="Path to an orchestrator_run.json (defaults to <output-dir>/orchestrator_run.json)")
    parser.add_argument("--format", action="append", choices=list(VALID_FORMATS), default=None,
                        help="Report format to write (repeatable; default: both)")
    parser.add_argument("--name", default=DEFAULT_FILENAME_STEM,
                        help=f"Report file name without extension (default: {DEFAULT_FILENAME_STEM})")
    args = parser.parse_args()

    try:
        result = generate_report(
            graph=args.graph, assessment=args.assessment, execution=args.execution,
            output_dir=args.output_dir, formats=args.format or VALID_FORMATS,
            filename_stem=args.name,
        )
    except ReportError as exc:
        print(f"report generation failed: {exc}", file=sys.stderr)
        raise SystemExit(2)

    print(json.dumps({
        "target": result["target"],
        "formats": result["formats"],
        "output_paths": result["output_paths"],
        "warnings": result["warnings"],
        "limitations": result["limitations"],
        "errors": result["errors"],
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    _main()
