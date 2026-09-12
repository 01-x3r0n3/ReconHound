"""
reconhound/report_generator.py — ReconHound Module 21 (report_generator.py).

Phase: Output. See context.md §10 (module 21) for the authoritative
responsibilities and §11 for the `output/reports/` location this module
writes to.

This is ReconHound's reporting layer. It discovers nothing, scans nothing,
correlates nothing and scores nothing: it consumes state that already
exists — surface_mapper.py's correlated asset graph, risk_engine.py's
assessment, and core/orchestrator.py's execution record — and renders it as
a terminal-first, Rich-based operator report (also written as a plain-text
file), a self-contained HTML report, and a machine-readable JSON report.

    surface_mapper.py (graph)
    risk_engine.py    (assessment)   ->  report_generator.py  ->  output/reports/
    orchestrator.py   (execution record)                          + the terminal


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

7.  **All report content is untrusted, and is hardened where it enters the
    data model.** Hostnames, banners, URLs, parameter names, JavaScript
    references and error strings are target-controlled. `ReportBuilder.build()`
    passes the finished document through `_harden()` once: terminal control
    characters (ESC, the C1 introducers, BEL, NUL, CR, DEL) and invisible
    Unicode format characters (bidi overrides, zero-width characters) are
    replaced by their printable escape form, credential-shaped material is
    masked, and every string and container is bounded with a visible marker.
    The JSON export carries that hardened form, so a downstream consumer that
    never touches the terminal renderer sees exactly what the terminal sees.
    On top of that, every value that reaches the HTML is passed through
    `html.escape(..., quote=True)`; the rendered document contains no
    `<script>` element, loads no external resource, and carries a
    restrictive Content-Security-Policy meta tag. The terminal renderer
    disables Rich markup, emoji codes and highlighting and only ever
    prints `Text` objects it assembled itself.

8.  **Secrets are masked twice, never widened.** code_leak.py, js_analyzer.py
    and exposure_scan.py store redacted values; this module never
    reconstructs, decodes or widens a redacted value, and its own
    `redact_sensitive_text()` (mirroring their patterns and the
    orchestrator's) masks what a producer did not recognise — a token in a
    crawled URL, an Authorization header quoted in an error string. Best
    effort against recognisable shapes; the report says how many masks it
    applied.

8a. **The terminal report is the primary operator artifact.** It is
    WinPEAS/LinPEAS-inspired in structure — a summary panel, ruled
    sections, one block per finding — and ReconHound-native in content.
    Severity, confidence and evidence class are always textual badges
    (`[CRIT][HIGH CONF][CONFIRMED]`); colour only decorates them, so the
    output reads identically for colour-blind operators, under NO_COLOR,
    TERM=dumb, CI=true, through a pipe, and in the `.txt` file. Every bound
    it applies is stated ("Showing 50 of 1273 findings"), and wrapped
    continuation lines never start at column 0, so target text cannot pose
    as a heading.

8b. **Findings are validated, ordered and deduplicated, not invented.** A
    signal that is not an object or has no id is excluded and counted; a
    repeated signal id is excluded and counted; a signal with no evidence
    line takes the evidence of the graph observations it cites (labelled
    as such) and, if there is none, is labelled INCOMPLETE_EVIDENCE. Findings
    are ordered severity desc, confidence desc, affected asset asc, signal
    id asc — byte-identical across runs and hash seeds.

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
    report_generator.render_text_report(document) -> str  # pure, no I/O, no ANSI
    report_generator.render_terminal_report(document)     # prints via Rich

    python -m reconhound.report_generator --output-dir output --terminal
"""

from __future__ import annotations

import argparse
import html
import io
import json
import os
import re
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
REPORT_SCHEMA_VERSION = "1.1"

# context.md §11 places generated reports under output/reports/.
DEFAULT_REPORT_SUBDIR = "reports"
DEFAULT_FILENAME_STEM = "reconhound_report"

FORMAT_HTML = "html"
FORMAT_JSON = "json"
FORMAT_TEXT = "text"       # the terminal report, written as a plain-text file (no ANSI)
# Default order is also the artifact listing order: the terminal report's
# text form first (primary human report), JSON (automation), then HTML
# (secondary, kept for compatibility — see README "Outputs & Reporting").
VALID_FORMATS: Tuple[str, ...] = (FORMAT_TEXT, FORMAT_JSON, FORMAT_HTML)
FORMAT_EXTENSIONS: Dict[str, str] = {FORMAT_HTML: "html", FORMAT_JSON: "json", FORMAT_TEXT: "txt"}

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

# Finding evidence status. A signal risk_engine.py scored is listed either way;
# the label says whether the report carries what a reader needs to check it.
EVIDENCE_SUPPORTED = "SUPPORTED"
EVIDENCE_INCOMPLETE = "INCOMPLETE_EVIDENCE"

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
    "max_pending_opportunities": 200,
    "max_manual_review": 200,
    # Applied to every string / container in the finished document (see
    # `_harden`): a 10 MB header, a giant certificate or a 200,000-entry DNS
    # answer reaches the report as a bounded value with a visible marker.
    "max_text_chars": 2000,
    "max_collection_items": 500,
    # Terminal rendering bounds. The JSON report keeps everything up to the
    # bounds above; the terminal shows this much of it and says so.
    "terminal_max_queue_entries": 25,
    "terminal_max_findings": 100,
    "terminal_max_vuln_intel": 50,
    "terminal_max_paths": 15,
    "terminal_max_assets_per_type": 40,
    "terminal_max_conflicts": 25,
    "terminal_max_negative_results": 25,
    "terminal_max_module_executions": 60,
    "terminal_max_evidence_per_item": 6,
    "terminal_max_provenance_per_item": 4,
    "terminal_max_line_chars": 600,
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


_LIST_MARKER_PREFIX = "<truncated:"


def _records(items: Any) -> List[Dict[str, Any]]:
    """The record entries of a bounded list; the bound marker is not one."""
    return [item for item in _as_list(items) if isinstance(item, dict)]


def _markers(items: Any) -> List[str]:
    """The bound marker(s) `_harden` left in a list, to be shown in place."""
    return [item for item in _as_list(items)
            if isinstance(item, str) and item.startswith(_LIST_MARKER_PREFIX)]


def _evidence_line(item: Any) -> str:
    """
    One evidence line. A string is kept whole (whitespace collapsed) so the
    document-wide bound in `_harden` can state exactly how much of an
    oversized line was cut; a structured item is flattened by `display_value`.
    """
    if isinstance(item, str):
        return " ".join(item.split())
    return display_value(item, max_length=DEFAULT_LIMITS["max_text_chars"])


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
# Hardening at the point data enters the report document
#
# Everything below is applied once, to the whole document, in
# `ReportBuilder.build()`. The document is the single source every output
# format renders from, so the sanitized, redacted, bounded form is what the
# JSON export carries — a downstream consumer (a SIEM, a ticketing system, a
# script) that never passes through the terminal renderer sees exactly what
# the terminal sees. Sanitizing only at display time would leave the raw
# terminal escape sequence or credential sitting in the JSON artifact.
# ---------------------------------------------------------------------------

# C0 controls except TAB/LF (kept: they are legitimate in multi-line evidence
# and the renderers collapse them), DEL, and the C1 range — which includes
# the 8-bit CSI (U+009B) and OSC (U+009D) introducers. CR is escaped: on a
# terminal it rewinds the cursor and lets target text overwrite a line.
_CONTROL_CHAR_RE = re.compile("[\\x00-\\x08\\x0b-\\x1f\\x7f\\x80-\\x9f]")
# Unicode format characters that hide or reorder text without being visible:
# zero-width spaces/joiners, bidi embeddings/overrides/isolates, the byte
# order mark, the Arabic letter mark, the Mongolian vowel separator, and the
# LINE/PARAGRAPH SEPARATOR characters (which some terminals honour as line
# breaks). Lone surrogates (U+D800-U+DFFF) are legal in JSON text but cannot
# be encoded to UTF-8: left alone, one in a header value makes the text and
# HTML files unwritable and the terminal print raise, so they get the same
# printable-escape treatment.
_FORMAT_CHAR_RE = re.compile(
    "[\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u2064\\u2066-\\u206f\\ufeff\\u061c\\u180e"
    "\\ud800-\\udfff]")


def _escape_char(match: "re.Match[str]") -> str:
    code = ord(match.group(0))
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def sanitize_text(text: str) -> Tuple[str, int]:
    """
    Neutralize terminal-significant characters, keeping them visible.

    Every escape sequence a terminal could act on starts with a control
    character (ESC, the 8-bit C1 introducers, BEL as an OSC terminator), so
    replacing each control character with its printable `\\xNN` form is
    sufficient to defeat OSC 8 hyperlinks, OSC 52 clipboard writes, CSI
    cursor movement and colour changes, DCS/APC/PM/SOS strings and NUL
    truncation — without hiding from the operator that the target sent them.
    Invisible Unicode format characters are treated the same way for the same
    reason: a bidi override or a zero-width space makes text read as
    something it is not. Returns the cleaned text and how many characters
    were neutralized.
    """
    if not text:
        return text, 0
    count = 0

    def replace(match: "re.Match[str]") -> str:
        nonlocal count
        count += 1
        return _escape_char(match)

    cleaned = _CONTROL_CHAR_RE.sub(replace, text)
    cleaned = _FORMAT_CHAR_RE.sub(replace, cleaned)
    return cleaned, count


# Credential-shaped material this module masks before any output is produced.
# Mirrors the formats the producing modules already recognise — code_leak.py's
# SECRET_PATTERNS and core/orchestrator.py's _SECRET_PATTERNS — duplicated here
# per the project's modular-independence convention (this module must not
# import a producer, and the orchestrator imports every module). Each entry is
# (pattern, group to mask); group 0 masks the whole match.
_REDACTION_PATTERNS: Tuple[Tuple["re.Pattern[str]", int], ...] = (
    # key=value / key: value assignments in URLs, query strings, headers, error
    # text and config excerpts. The name may carry a prefix (api_key,
    # aws_secret_access_key, DB_PASSWORD, x-auth-token, PHPSESSID).
    # The name prefix is bounded ({0,64}) so a long dotted or hyphenated run
    # cannot make the scan quadratic: every candidate start then costs O(64).
    (re.compile(
        r"(?i)(?<![A-Za-z0-9_])([A-Za-z0-9_.\-]{0,64}?(?:key|token|secret|password|passwd|pwd|"
        r"credentials?|signature|sig|session|sessid|sessionid|authorization|auth)s?)"
        r"(\s*[:=]\s*)(?!<redacted>)([^&\s'\"<>;,]{4,})"), 3),
    # `Authorization: Bearer <token>` / `Basic <b64>`; a 16-character floor
    # keeps "Bearer token expired" readable.
    (re.compile(r"(?i)\b(bearer|basic)(\s+)([A-Za-z0-9._~+/=-]{16,})"), 3),
    # Userinfo password in a URL: scheme://user:password@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{0,32}://[^\s/:@'\"<>]{1,255}):([^\s@/'\"<>]{1,255})@"), 2),
    # Self-delimiting token formats.
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),                    # AWS access key id
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), 0),                # GitHub token
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"), 0),                # Slack token
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), 0),                        # Google API key
    (re.compile(r"\bsk_live_[0-9a-zA-Z]{16,64}\b"), 0),                    # Stripe live key
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 0),  # JWT
)
# A PEM private key block is replaced wholesale: its armour header is the
# evidence, the material between the armour lines never is.
_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?:[A-Z ]*)PRIVATE KEY-----.*?(?:-----END (?:[A-Z ]*)PRIVATE KEY-----|$)",
    re.DOTALL)
_PRIVATE_KEY_PLACEHOLDER = "-----BEGIN PRIVATE KEY----- <redacted> -----END PRIVATE KEY-----"
# Assignments whose values are intelligence rather than credentials, kept
# readable (mirrors exposure_scan.py's _NON_SECRET_KEYS for the names that
# also match the assignment pattern above).
_NON_SECRET_NAMES = frozenset({
    "auth", "authorization", "auth_method", "auth-method", "auth_type", "auth-type",
    "auth_scheme", "auth-scheme", "session_cookie", "keyword", "keywords", "hostkey",
    "host_key", "public_key", "publickey", "pubkey", "key_type", "key_size", "keysize",
    "token_type", "token-type", "signature_algorithm", "sig_alg", "sigalg",
})


# Assigned values that describe a state rather than carry a credential
# ("csrf_token=present", "api_key=missing") stay readable.
_NON_SECRET_VALUES = frozenset({
    "present", "absent", "missing", "none", "null", "true", "false", "yes", "no", "set",
    "unset", "empty", "found", "required", "optional", "unknown", "redacted", "<redacted>",
    "expired", "invalid", "valid", "enabled", "disabled", "undefined", "n/a", "hidden",
    "masked", "omitted", "checked", "unchecked", "detected", "observed",
})


def _redact_secret(value: str) -> str:
    """Partially mask `value` — same shape as code_leak.py / js_analyzer.py."""
    if not value:
        return ""
    if len(value) <= 8:
        return value[0] + "*" * (len(value) - 1) if len(value) > 1 else "*"
    stars = min(len(value) - 8, 24)
    return f"{value[:4]}{'*' * stars}{value[-4:]}"


def redact_sensitive_text(text: str) -> Tuple[str, int]:
    """
    Mask credential-shaped material in `text`.

    Producing modules redact what they recognise before persisting it; this
    is the defence in depth for what they did not (a token in a crawled URL,
    an Authorization header quoted in an error string, a config excerpt from
    a module without its own redaction). Best effort against recognisable
    credential shapes, never a guarantee — free-prose secrets with no
    recognisable structure are not detected, and the report says so.
    Returns the masked text and the number of masks applied.
    """
    if not text:
        return text, 0
    count = 0

    def replace_block(_match: "re.Match[str]") -> str:
        nonlocal count
        count += 1
        return _PRIVATE_KEY_PLACEHOLDER

    out = _PRIVATE_KEY_BLOCK_RE.sub(replace_block, text)

    for pattern, group in _REDACTION_PATTERNS:
        def replace(match: "re.Match[str]", _group: int = group) -> str:
            nonlocal count
            if _group == 3 and match.group(1).strip().lower() in _NON_SECRET_NAMES:
                return match.group(0)
            secret = match.group(_group)
            if not secret or (_group == 3 and secret.strip().lower() in _NON_SECRET_VALUES):
                return match.group(0)
            count += 1
            start, end = match.span(_group)
            whole = match.group(0)
            offset = match.start()
            return whole[: start - offset] + _redact_secret(secret) + whole[end - offset:]
        out = pattern.sub(replace, out)
    return out, count


def bound_text(text: str, max_chars: int) -> Tuple[str, bool]:
    """Cut `text` to `max_chars` with a visible marker that says how much is gone."""
    if max_chars is None or max_chars < 0 or len(text) <= max_chars:
        return text, False
    omitted = len(text) - max_chars
    return f"{text[:max_chars]}… [truncated: {omitted} more character(s) omitted]", True


# Widest secret format above; a string is pre-cut to the bound plus this
# margin before redaction so that a token straddling the bound is still
# recognised whole, then cut to the bound itself afterwards.
_REDACTION_LOOKAHEAD = 1024


def _empty_hardening_stats() -> Dict[str, int]:
    return {"control_characters_neutralized": 0, "secrets_redacted": 0,
            "strings_truncated": 0, "collections_truncated": 0}


def harden_text(text: str, max_chars: int, stats: Dict[str, int]) -> str:
    """sanitize -> redact -> bound, in that order, for one string."""
    original_length = len(text)
    if max_chars is not None and max_chars >= 0 and original_length > max_chars + _REDACTION_LOOKAHEAD:
        text = text[: max_chars + _REDACTION_LOOKAHEAD]
    text, neutralized = sanitize_text(text)
    stats["control_characters_neutralized"] += neutralized
    text, redacted = redact_sensitive_text(text)
    stats["secrets_redacted"] += redacted
    if max_chars is not None and max_chars >= 0 and (
            len(text) > max_chars or original_length > max_chars):
        cut = text[:max_chars]
        omitted = max(original_length - max_chars, len(text) - max_chars)
        text = f"{cut}… [truncated: {omitted} more character(s) omitted]"
        stats["strings_truncated"] += 1
    return text


def _harden(value: Any, limits: Dict[str, int], stats: Dict[str, int], _depth: int = 0) -> Any:
    """
    `_json_safe` plus the three hardening steps, in one pass over a document.

    Strings are sanitized, redacted and bounded to `max_text_chars`;
    lists and dicts are bounded to `max_collection_items` with a visible
    marker in place of what was omitted; unknown objects become strings;
    recursion is bounded. Every step is counted in `stats` so the document
    can state what was done to it.
    """
    max_chars = limits.get("max_text_chars", DEFAULT_LIMITS["max_text_chars"])
    max_items = limits.get("max_collection_items", DEFAULT_LIMITS["max_collection_items"])
    if _depth > 24:
        return "<max depth exceeded>"
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return str(value)
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return harden_text(value, max_chars, stats)
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        kept = 0
        total = len(value)
        for key, item in value.items():
            if max_items is not None and max_items >= 0 and kept >= max_items:
                break
            try:
                safe_key = harden_text(str(key), 200, stats)
            except Exception:
                safe_key = "<unrenderable key>"
            if safe_key in out:
                # Two raw keys that sanitize to the same text must not
                # silently collapse into one; the second is kept, marked.
                suffix = 2
                while f"{safe_key} ({suffix})" in out:
                    suffix += 1
                safe_key = f"{safe_key} ({suffix})"
            try:
                out[safe_key] = _harden(item, limits, stats, _depth + 1)
            except Exception as exc:  # one bad member never breaks the document
                out[safe_key] = f"<unserializable: {exc}>"
            kept += 1
        if kept < total:
            out["<truncated>"] = f"{total - kept} more entr(y/ies) omitted; see the source artifacts"
            stats["collections_truncated"] += 1
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        try:
            items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else list(value)
        except Exception:
            items = list(value)
        total = len(items)
        if max_items is not None and max_items >= 0 and total > max_items:
            items = items[:max_items]
        out_list = [_harden(item, limits, stats, _depth + 1) for item in items]
        if len(items) < total:
            out_list.append(f"<truncated: {total - len(items)} more item(s) omitted; see the source artifacts>")
            stats["collections_truncated"] += 1
        return out_list
    if isinstance(value, datetime):
        return value.isoformat()
    try:
        return harden_text(str(value), max_chars, stats)
    except Exception as exc:
        return f"<unrenderable: {type(exc).__name__}>"


# ---------------------------------------------------------------------------
# Persistence — same atomic pattern as every other store in the project
# ---------------------------------------------------------------------------

def _fsync_dir(dir_name: str) -> None:
    """
    Durably commit the os.replace() rename itself (same helper as the
    producing modules' stores). Best-effort: some platforms/filesystems
    refuse to fsync a directory.
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
                try:
                    handle = os.fdopen(fd, "w", encoding="utf-8")
                except BaseException:
                    os.close(fd)  # fdopen failed: the descriptor is still ours to close
                    raise
                with handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_path, path)
            except BaseException:
                # A Ctrl+C or a full disk mid-write must leave the previous
                # report intact and no temp file behind. The cleanup itself
                # must never mask the original failure.
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
                raise
            _fsync_dir(dir_name)
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
        generated_at: Optional[str] = None,
    ):
        self.errors: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.output_dir = output_dir
        # The generation timestamp is the one field that legitimately differs
        # between two builds of the same state; a caller that needs
        # byte-identical output (a reproducible build, a test) supplies it.
        self.generated_at = _text(generated_at) or None
        self.limits = dict(DEFAULT_LIMITS)
        for key, value in (limits or {}).items():
            if key in self.limits:
                self.limits[key] = max(0, _int(value, self.limits[key]))
            else:
                # A misspelt limit must not silently leave the default in
                # force while the caller believes a bound was applied.
                self.warnings.append(
                    f"Unknown report limit {_text(key)!r} was ignored; valid limits are "
                    f"{', '.join(sorted(DEFAULT_LIMITS))}.")
        # The document-wide collection bound must never cut a section that
        # its own, explicit bound already sized: that would drop entries the
        # section's `shown`/`total` marker claims are present.
        self.limits["max_collection_items"] = max(
            self.limits["max_collection_items"],
            *(self.limits[k] for k in ("max_queue_entries", "max_findings", "max_assets_per_type",
                                       "max_attack_surface_paths", "max_path_hops",
                                       "max_evidence_per_item", "max_provenance_per_item",
                                       "max_conflicts", "max_negative_results", "max_observations",
                                       "max_module_executions", "max_errors",
                                       "max_pending_opportunities", "max_manual_review")))
        # A text bound below one line of context would turn every value into
        # a truncation marker, which is no report at all.
        self.limits["max_text_chars"] = max(64, self.limits["max_text_chars"])

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
        self._signal_cache: Optional[Tuple[List[Dict[str, Any]], Dict[str, int]]] = None
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
        raw: List[Dict[str, Any]] = []
        seen_assets: set = set()
        malformed = duplicates = 0
        for index, entry in enumerate(_as_list(self.assessment.get("investigation_queue"))):
            if not isinstance(entry, dict):
                malformed += 1
                self.errors.append({"stage": "investigation_queue", "index": index,
                                    "error": "malformed queue entry excluded: not an object"})
                continue
            asset_id = _text(entry.get("asset_id"))
            if asset_id and asset_id in seen_assets:
                # One asset holds one place in the queue; a repeated entry is
                # a corrupt assessment, not a second finding.
                duplicates += 1
                self.errors.append({"stage": "investigation_queue", "asset_id": asset_id,
                                    "error": "duplicate queue entry excluded"})
                continue
            if asset_id:
                seen_assets.add(asset_id)
            raw.append(entry)
        # The queue is presented in risk_engine.py's rank order; the rank is
        # the ordering key so a hand-edited or partially written file cannot
        # show the queue out of order.
        raw.sort(key=lambda e: (_int(e.get("rank"), sys.maxsize), _text(e.get("asset_id"))))
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
                "malformed_excluded": malformed, "duplicates_excluded": duplicates,
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

    def _observation_evidence(self, observation_ids: Sequence[Any]) -> List[str]:
        """
        Evidence lines held by the graph observations a signal cites.

        risk_engine.py leaves `evidence` empty on some signals (a technology
        observation, for instance) because the observation record it cites
        is the evidence. The report holds that record, so its stored lines
        are shown, each labelled with the observation it came from. Nothing
        is inferred: an observation with no evidence contributes nothing.
        """
        lines: List[str] = []
        for observation_id in observation_ids:
            record = self.graph["observations"].get(_text(observation_id))
            if not isinstance(record, dict):
                continue
            for item in _as_list(record.get("evidence")):
                text = _evidence_line(item)
                if text:
                    lines.append(f"{text} [observation {_text(observation_id)}, "
                                 f"{_text(record.get('source')) or UNKNOWN}]")
        return lines

    def _finding_entry(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        kind = _text(signal.get("kind"))
        own_evidence = [line for line in (_evidence_line(e) for e in _as_list(signal.get("evidence")))
                        if line]
        evidence_from = "signal"
        if not own_evidence:
            own_evidence = self._observation_evidence(_as_list(signal.get("observation_ids")))
            evidence_from = "observation_records" if own_evidence else "none"
        evidence, evidence_marker = _truncate_list(own_evidence, self.limits["max_evidence_per_item"])
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
            "evidence_from": evidence_from,
            "evidence_status": self._evidence_status(evidence, provenance, signal),
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

    @staticmethod
    def _evidence_status(evidence: List[str], provenance: List[Dict[str, Any]],
                         signal: Dict[str, Any]) -> str:
        """
        Whether the signal carries what a reader needs to check it.

        A signal with no evidence line, no provenance record and no
        observation id cannot be verified from the report; it is still
        listed (risk_engine.py scored it) but is labelled INCOMPLETE_EVIDENCE
        rather than presented as if it were supported.
        """
        has_evidence = any(_text(item).strip() for item in evidence)
        has_trace = bool(provenance) or any(
            _text(item).strip() for item in _as_list(signal.get("observation_ids")))
        return EVIDENCE_SUPPORTED if has_evidence and has_trace else EVIDENCE_INCOMPLETE

    def _signal_subject_label(self, signal: Dict[str, Any]) -> str:
        """The affected asset's label, used as the ordering key after confidence."""
        subject_id = _text(signal.get("subject_asset_id"))
        asset = self._assets().get(subject_id)
        return _asset_label(asset) if asset else subject_id

    def _signal_sort_key(self, signal: Dict[str, Any]) -> Tuple[int, int, str, str]:
        """Severity desc, confidence desc, affected asset asc, signal id asc."""
        return (
            -severity_sort_key(signal.get("severity")),
            -risk_engine.confidence_rank(normalize_confidence(signal.get("confidence"))),
            self._signal_subject_label(signal),
            _text(signal.get("signal_id")),
        )

    def _validated_signals(self, stage: str) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
        """
        The assessment's signals that are well-formed enough to report, in
        the report's ordering, with what was excluded counted.

        A record that is not an object, or carries no signal id, cannot be
        rendered honestly and is excluded and counted rather than silently
        dropped or shown as a finding with invented fields. A second record
        with a signal id already seen is a duplicate — one finding must never
        appear twice — and is excluded and counted the same way. Computed
        once per report so the exclusions are recorded once.
        """
        cached = getattr(self, "_signal_cache", None)
        if cached is not None:
            return cached
        raw = _as_list(self.assessment.get("signals")) if self.assessment else []
        malformed = 0
        duplicates = 0
        seen: set = set()
        signals: List[Dict[str, Any]] = []
        for index, signal in enumerate(raw):
            if not isinstance(signal, dict) or not _text(signal.get("signal_id")).strip():
                malformed += 1
                self.errors.append({"stage": stage, "index": index,
                                    "error": "malformed signal record excluded: not an object "
                                             "with a signal_id"})
                continue
            signal_id = _text(signal.get("signal_id"))
            if signal_id in seen:
                duplicates += 1
                self.errors.append({"stage": stage, "signal_id": signal_id,
                                    "error": "duplicate signal record excluded"})
                continue
            seen.add(signal_id)
            signals.append(signal)
        signals.sort(key=self._signal_sort_key)
        self._signal_cache = (signals, {"malformed_excluded": malformed,
                                        "duplicates_excluded": duplicates})
        return self._signal_cache

    def _build_findings(self) -> Dict[str, Any]:
        if not self.assessment:
            return {"available": False,
                    "reason": NO_ASSESSMENT,
                    "entries": []}
        signals, exclusions = self._validated_signals("findings")
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
        incomplete = sum(1 for e in entries if e.get("evidence_status") == EVIDENCE_INCOMPLETE)
        return {"available": True, "entries": entries, "counts_by_evidence_class": by_kind,
                "incomplete_evidence": incomplete,
                "ordering": "severity desc, confidence desc, affected asset asc, signal id asc",
                **exclusions, **marker}

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
        signals, _exclusions = self._validated_signals("vulnerability_intelligence")
        matches = [s for s in signals if _text(s.get("kind")) == risk_engine.KIND_VULN_INTEL]
        matches.sort(key=lambda s: self._signal_sort_key(s)[:3] + (_text(s.get("cve_id")),
                                                                    _text(s.get("signal_id"))))
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
        malformed = len(self.graph["assets"]) - len(assets)
        if malformed:
            # A graph record that is not an object cannot be inventoried; say
            # so rather than letting the asset count quietly come up short.
            self.errors.append({"stage": "asset_inventory",
                                "error": f"{malformed} malformed asset record(s) excluded: not objects"})
        return {
            "total": len(assets),
            "malformed_excluded": malformed,
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
        malformed = 0
        for rel in self.graph["relationships"].values():
            if isinstance(rel, dict):
                rel_type = _text(rel.get("rel_type")) or UNKNOWN
                by_type[rel_type] = by_type.get(rel_type, 0) + 1
            else:
                malformed += 1
        if malformed:
            self.errors.append({"stage": "relationships",
                                "error": f"{malformed} malformed relationship record(s) excluded: not objects"})
        return {"total": sum(by_type.values()), "by_type": by_type, "malformed_excluded": malformed}

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
        # Counted over *every* conflict, not only the ones that survive the
        # display cap, so the headline never describes a truncated sample.
        cross_source_total = sum(1 for c in raw
                                 if risk_engine.conflict_kind(c) == risk_engine.CONFLICT_CROSS_SOURCE)
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
            kind = risk_engine.conflict_kind(conflict)
            entries.append({
                "conflict_id": conflict_id or None,
                "asset": self._asset_brief(_text(conflict.get("asset_id"))),
                "attribute": _text(conflict.get("attribute")) or None,
                "kind": kind,
                "kind_explanation": (
                    "two or more modules recorded different values; at most one can be correct"
                    if kind == risk_engine.CONFLICT_CROSS_SOURCE else
                    "one module recorded different values at different times; the observed "
                    "value changed rather than two modules disagreeing"),
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
        return {
            "entries": entries,
            "cross_source_total": cross_source_total,
            "temporal_total": len(raw) - cross_source_total,
            **marker,
        }

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
                    "modules": [], "errors": [], "failed_modules": [],
                    "unreachable_origins": [], "phases": []}
        coverage = _as_dict(self.execution.get("coverage"))
        unreachable = [
            {"origin": _text(_as_dict(e).get("origin")),
             "reported_as": _text(_as_dict(e).get("reported_as"))}
            for e in _as_list(coverage.get("unreachable_origins"))
            if _text(_as_dict(e).get("origin"))
        ]
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
        manual_review, manual_marker = _truncate_list(
            _as_list(adaptive.get("manual_review")), self.limits["max_manual_review"])
        pending, pending_marker = _truncate_list(
            _as_list(_as_dict(self.execution.get("opportunities")).get("pending")),
            self.limits["max_pending_opportunities"])
        return {
            "available": True,
            "modules": modules,
            "module_truncation": marker,
            "failed_modules": failed,
            # Not failures — subjects that never answered, so nothing about
            # them was checked. Reported separately so "no module failures"
            # is never read as complete coverage.
            "unreachable_origins": unreachable,
            "errors": _json_safe(errors),
            "error_truncation": error_marker,
            "phases": _json_safe(_as_list(self.execution.get("phases"))),
            "adaptive": {
                "rounds": _int(adaptive.get("rounds")),
                "actions": _int(adaptive.get("actions")),
                "manual_review": _json_safe(manual_review),
                "manual_review_truncation": manual_marker,
                "deferred": len(_as_list(adaptive.get("deferred"))),
            },
            "pending_opportunities": _json_safe(pending),
            "pending_opportunities_truncation": pending_marker,
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

        # Worded from the conflict kinds, because "between modules" is only
        # true of a cross-source conflict: one module observing a different
        # value on a later run is the target changing, not two modules
        # disagreeing, and calling every repeat scan's DNS/WHOIS/SOA drift a
        # contradiction between modules is simply false.
        cross_source = _int(sections["conflicts"].get("cross_source_total"))
        temporal = _int(sections["conflicts"].get("temporal_total"))
        if cross_source:
            headline.append(
                f"{cross_source} contradiction(s) between modules are preserved "
                f"unresolved and are listed for manual resolution.")
        if temporal:
            headline.append(
                f"{temporal} attribute(s) were observed with different values by the same module at "
                f"different times; every value is preserved and listed, and the change itself is the "
                f"observation.")

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
            # Findings, ports and technologies carry no scope determination of
            # their own; showing only the first two counts made the remainder
            # look unaccounted for.
            "scope_not_determined_assets": inventory["scope"]["scope_not_determined"],
            "assets_by_severity": severity["assets_by_severity"] if severity.get("available") else None,
            "queue_length": severity.get("queue_length") if severity.get("available") else None,
            "signals": severity.get("signals") if severity.get("available") else None,
            "confirmed_findings": counts_by_kind.get(risk_engine.KIND_CONFIRMED) if findings.get("available") else None,
            "indicators": counts_by_kind.get(risk_engine.KIND_INDICATOR) if findings.get("available") else None,
            "vulnerability_intelligence": counts_by_kind.get(risk_engine.KIND_VULN_INTEL) if findings.get("available") else None,
            "unresolved_conflicts": sections["conflicts"]["total"],
            "unresolved_conflicts_cross_source": cross_source,
            "unresolved_conflicts_temporal": temporal,
            "negative_results": sections["negative_results"]["total"],
            "failed_module_executions": len(execution["failed_modules"]) if execution.get("available") else None,
            "unreachable_origins": (len(_as_list(execution.get("unreachable_origins")))
                                    if execution.get("available") else None),
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
        unreachable = _as_list(execution.get("unreachable_origins")) if execution.get("available") else []
        if unreachable:
            limitations.append(
                f"{len(unreachable)} origin(s) answered no request and were not enumerated: "
                + ", ".join(sorted(_text(_as_dict(e).get('origin')) for e in unreachable))
                + ". Nothing below describes them — this is absence of coverage, not absence "
                  "of attack surface.")
        if execution.get("available") and _text(self.execution.get("status")) == "interrupted":
            limitations.append(
                "The run was interrupted before completion. Everything collected up to that point "
                "is present, but the pipeline did not finish.")
        if _int(sections["conflicts"].get("cross_source_total")):
            limitations.append(
                "Conflicting observations from different modules are preserved unresolved. Any "
                "assessment that depends on a disputed value is held back rather than guessed.")
        if _int(sections["conflicts"].get("temporal_total")):
            limitations.append(
                "Some attributes changed value between observations by the same module. The graph "
                "keeps the first value it recorded as the asset's attribute and every later value "
                "in the conflicts section, so the attribute shown may not be the most recent "
                "observation.")
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
            "conflicts", self._build_conflicts,
            {"entries": [], "total": 0, "shown": 0, "truncated": False,
             "cross_source_total": 0, "temporal_total": 0})
        sections["negative_results"] = self._section(
            "negative_results", self._build_negative_results,
            {"entries": [], "total": 0, "shown": 0, "truncated": False, "check_state_census": {}})
        sections["execution"] = self._section(
            "execution", self._build_execution,
            {"available": False, "modules": [], "errors": [], "failed_modules": [],
             "unreachable_origins": [], "phases": []})
        sections["observations"] = self._section(
            "observations", self._build_observations, {"entries": [], "by_source": {}, "total": 0})

        # Defensive: a fallback section must still carry the keys the summary
        # and the renderer read, so a failed section degrades one panel only.
        sections["conflicts"].setdefault("total", len(sections["conflicts"].get("entries", [])))
        sections["conflicts"].setdefault("cross_source_total", 0)
        sections["conflicts"].setdefault("temporal_total", 0)
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
            "generated_at": self.generated_at or _now(),
            "target": self.target,
            "executive_summary": summary,
            **sections,
            "source_artifacts": self._artifact_paths(),
            "limits": dict(self.limits),
            "warnings": list(self.warnings),
            "limitations": limitations,
            "errors": list(self.errors),
            "notes": list(REPORT_NOTES),
        }
        # Sanitize, redact and bound the whole document here, once, at the
        # point it becomes the report's data model. Every renderer and the
        # JSON export read the hardened form; nothing reads the raw one.
        stats = _empty_hardening_stats()
        hardened = _harden(document, self.limits, stats)
        hardened["sanitization"] = stats
        statements = []
        if stats["control_characters_neutralized"]:
            statements.append(
                f"{stats['control_characters_neutralized']} terminal control or invisible "
                f"formatting character(s) in target-derived content were replaced by their "
                f"printable escape form.")
        if stats["secrets_redacted"]:
            statements.append(
                f"{stats['secrets_redacted']} credential-shaped value(s) were masked before "
                f"output; the producing modules' own artifacts hold what they persisted.")
        if stats["strings_truncated"] or stats["collections_truncated"]:
            statements.append(
                f"{stats['strings_truncated']} oversized value(s) and "
                f"{stats['collections_truncated']} oversized collection(s) were cut to the "
                f"report's bounds with a visible marker; the complete data is in the source "
                f"artifacts.")
        if statements:
            hardened["limitations"] = list(_as_list(hardened.get("limitations"))) + statements
        return hardened


def build_report_document(
    graph: Any = None,
    assessment: Any = None,
    execution: Any = None,
    output_dir: str = "output",
    target: Optional[str] = None,
    limits: Optional[Dict[str, int]] = None,
    generated_at: Optional[str] = None,
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
        target=target, output_dir=output_dir, limits=limits, generated_at=generated_at)
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
        entries = _records(findings.get("entries"))
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
        if entry.get("evidence_status") == EVIDENCE_INCOMPLETE:
            flags.append(f'<span class="flag">{_e(EVIDENCE_INCOMPLETE)}</span>')
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
        entries = _records(vuln.get("entries"))
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
        entries = _records(paths.get("entries"))
        if not entries:
            self._w('<p class="empty">No discovery chains could be reconstructed from the recorded '
                    'relationships.</p>')
            self.end_section()
            return
        for entry in entries:
            hops = _records(entry.get("hops"))
            chain: List[str] = [f'<span class="trunc">{_e(m)}</span>' for m in _markers(entry.get("hops"))]
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
                attributes = _records(entry.get("attributes"))
                attribute_text = ", ".join(
                    f'{_text(a.get("name"))}={_text(a.get("display"))}'
                    + (" [conflict]" if a.get("has_conflict") else "")
                    for a in attributes[:6])
                if len(attributes) > 6:
                    attribute_text += f", +{len(attributes) - 6} more"
                for marker in _markers(entry.get("attributes")):
                    attribute_text += f", {marker}"
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
        modules = _records(execution.get("modules"))
        for marker in _markers(execution.get("modules")):
            self._w(f'<p class="trunc">{_e(marker)}</p>')
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

        errors = _records(execution.get("errors"))
        for marker in _markers(execution.get("errors")):
            self._w(f'<p class="trunc">{_e(marker)}</p>')
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
# Terminal rendering
#
# The terminal report is the operator-facing form of the document: Rich-based,
# sectioned like WinPEAS/LinPEAS, and readable without colour. Every severity,
# confidence and evidence class is a textual badge — `[CRIT][HIGH CONF]` —
# and colour only ever decorates a badge, so the same output reads correctly
# for colour-blind operators, under NO_COLOR, on TERM=dumb, in CI, through a
# pipe and in the plain-text file this module writes.
#
# Rich is used only through renderables built from `Text` objects with markup
# disabled, so target-derived content is never parsed as Rich markup; the
# document it renders has already been sanitized in `ReportBuilder.build()`.
# ---------------------------------------------------------------------------

SEVERITY_BADGES: Dict[str, str] = {
    risk_engine.SEVERITY_CRITICAL: "CRIT",
    risk_engine.SEVERITY_HIGH: "HIGH",
    risk_engine.SEVERITY_MEDIUM: "MED",
    risk_engine.SEVERITY_LOW: "LOW",
    risk_engine.SEVERITY_INFO: "INFO",
    UNKNOWN: "UNKN",
}
CONFIDENCE_BADGES: Dict[str, str] = {
    risk_engine.CONFIDENCE_HIGH: "HIGH CONF",
    risk_engine.CONFIDENCE_MEDIUM: "MED CONF",
    risk_engine.CONFIDENCE_LOW: "LOW CONF",
    UNKNOWN: "CONF ?",
}
KIND_BADGES: Dict[str, str] = {
    risk_engine.KIND_CONFIRMED: "CONFIRMED",
    risk_engine.KIND_VULN_INTEL: "CVE MATCH",
    risk_engine.KIND_INDICATOR: "INDICATOR",
    risk_engine.KIND_OBSERVATION: "OBSERVED",
}
# Colour is an enhancement layered on the badge text, never the carrier.
TERMINAL_SEVERITY_STYLES: Dict[str, str] = {
    risk_engine.SEVERITY_CRITICAL: "bold white on red",
    risk_engine.SEVERITY_HIGH: "bold red",
    risk_engine.SEVERITY_MEDIUM: "bold yellow",
    risk_engine.SEVERITY_LOW: "bold blue",
    risk_engine.SEVERITY_INFO: "bold",
    UNKNOWN: "bold magenta",
}
TERMINAL_KIND_STYLES: Dict[str, str] = {
    risk_engine.KIND_CONFIRMED: "bold green",
    risk_engine.KIND_VULN_INTEL: "bold magenta",
    risk_engine.KIND_INDICATOR: "bold yellow",
    risk_engine.KIND_OBSERVATION: "dim",
}
TERMINAL_STYLE_HEADING = "bold cyan"
TERMINAL_STYLE_RULE = "cyan"
TERMINAL_STYLE_LABEL = "bold"
TERMINAL_STYLE_DIM = "dim"
TERMINAL_STYLE_WARN = "bold yellow"
TERMINAL_STYLE_BAD = "bold red"

TERMINAL_DEFAULT_WIDTH = 100
TERMINAL_MIN_WIDTH = 20

_UNICODE_GLYPHS = {"rule": "─", "bullet": "•", "arrow": "→", "tree": "└─", "sep": " │ "}
_ASCII_GLYPHS = {"rule": "-", "bullet": "*", "arrow": "->", "tree": "`-", "sep": " | "}


def terminal_color_allowed(file: Any = None, environ: Optional[Dict[str, str]] = None) -> bool:
    """
    Whether colour may be emitted to `file` (stdout when None).

    Colour requires an interactive terminal and is disabled by the NO_COLOR
    convention, by TERM=dumb/unknown, and by CI=true (CI logs are captured,
    not viewed). FORCE_COLOR overrides the TTY check only — it never
    overrides NO_COLOR — so colour can be forced into a pipe deliberately.
    """
    env = os.environ if environ is None else environ
    if env.get("NO_COLOR", "") != "":
        return False
    term = env.get("TERM", "").strip().lower()
    if term in ("dumb", "unknown"):
        return False
    if env.get("CI", "").strip().lower() in ("1", "true", "yes"):
        return False
    if env.get("FORCE_COLOR", "").strip() not in ("", "0", "false"):
        return True
    stream = sys.stdout if file is None else file
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _terminal_width(file: Any, width: Optional[int]) -> Optional[int]:
    """An explicit width wins; a TTY is measured; anything else gets the default."""
    if width is not None:
        return max(TERMINAL_MIN_WIDTH, _int(width, TERMINAL_DEFAULT_WIDTH))
    try:
        if file.isatty():
            return None  # let Rich measure the terminal
    except (AttributeError, ValueError, OSError):
        pass
    return TERMINAL_DEFAULT_WIDTH


def make_report_console(file: Any = None, width: Optional[int] = None,
                        color: Optional[bool] = None) -> Any:
    """
    A Rich Console configured for report output.

    Markup, emoji codes and syntax highlighting are all disabled: the console
    only ever receives `Text` objects this module assembled, and nothing in
    the document may be interpreted as Rich markup. `color=None` means
    auto-detect via `terminal_color_allowed()`.
    """
    from rich.console import Console  # imported here so the module loads without rich

    stream = sys.stdout if file is None else file
    allowed = terminal_color_allowed(stream) if color is None else bool(color)
    console = Console(
        file=stream,
        width=_terminal_width(stream, width),
        force_terminal=True if allowed else False,
        color_system="standard" if allowed else None,
        no_color=not allowed,
        markup=False,
        emoji=False,
        highlight=False,
        soft_wrap=False,
        legacy_windows=False,
        safe_box=True,
    )
    return console


class TerminalReportRenderer:
    """
    Renders one report document to a Rich Console.

    Reads only the document produced by `ReportBuilder`, so the terminal can
    never show a number the JSON report does not also contain, and everything
    it prints has already been sanitized, redacted and bounded there. It
    applies its own, smaller display bounds (the `terminal_*` limits) and
    states every one it hits.
    """

    def __init__(self, document: Dict[str, Any], console: Any,
                 limits: Optional[Dict[str, int]] = None,
                 omit: Optional[Sequence[str]] = None,
                 width: Optional[int] = None):
        self.doc = _as_dict(document)
        self.console = console
        self.limits = dict(DEFAULT_LIMITS)
        self.limits.update({k: v for k, v in _as_dict(self.doc.get("limits")).items()
                            if k in self.limits and isinstance(v, int)})
        for key, value in (limits or {}).items():
            if key in self.limits:
                self.limits[key] = max(0, _int(value, self.limits[key]))
        # Sections a host that already shows the same information (the CLI's
        # own run summary) can leave out. Unknown names are ignored: omitting
        # is a courtesy to the host, never a way to lose a section by typo.
        self.omit = frozenset(_text(name) for name in (omit or ()))
        self.glyphs = _UNICODE_GLYPHS if self._supports_unicode() else _ASCII_GLYPHS
        console_width = int(getattr(console, "width", TERMINAL_DEFAULT_WIDTH) or TERMINAL_DEFAULT_WIDTH)
        # An explicit width never exceeds the console's: text wrapped wider
        # than the console would be re-wrapped by it and lose its indents.
        chosen = console_width if width is None else min(_int(width, console_width), console_width)
        self.width = max(TERMINAL_MIN_WIDTH, chosen)
        self.compact = self.width < 72

    # -- capability detection --------------------------------------------

    def _supports_unicode(self) -> bool:
        encoding = (getattr(getattr(self.console, "file", None), "encoding", None) or "").lower()
        if not encoding:
            return False
        try:
            "─•→└│".encode(encoding)
        except (UnicodeEncodeError, LookupError):
            return False
        return True

    # -- primitives -------------------------------------------------------

    def _line(self, value: Any, max_chars: Optional[int] = None) -> str:
        """
        One display line of target-derived text.

        Whitespace (including newlines) is collapsed so a value can never
        fabricate a new line that looks like a badge or a heading; the length
        is bounded with a visible marker. The document was sanitized at build
        time, so this is layout, not the security boundary.
        """
        text = " ".join(_text(value).split())
        limit = self.limits["terminal_max_line_chars"] if max_chars is None else max_chars
        bounded, _cut = bound_text(text, limit)
        return bounded

    def _print(self, renderable: Any) -> None:
        self.console.print(renderable, markup=False, highlight=False, emoji=False)

    def _blank(self) -> None:
        self.console.print()

    def _text(self, *parts: Any) -> Any:
        """Text.assemble with markup disabled: (string, style) pairs or strings."""
        from rich.text import Text
        return Text.assemble(*parts)

    def _hang(self, body: Any, indent: int = 0, marker: str = "", marker_style: str = "") -> None:
        """
        Print `body` with a hanging indent: continuation lines wrap under the
        first line's text, never under its marker, so a long URL or evidence
        line stays visibly attached to its bullet or label at any width.
        """
        from rich.text import Text
        if not isinstance(body, Text):
            body = Text(self._line(body))
        indent = max(0, min(indent, self.width - 12))
        prefix = Text(" " * indent)
        if marker:
            prefix.append(marker, style=marker_style)
        prefix_width = prefix.cell_len
        if prefix_width > self.width - 8:
            # Too narrow for a hanging indent: the marker gets its own line so
            # the text still has room and never spills past the width.
            self._print(prefix)
            prefix = Text("  ")
            prefix_width = 2
        available = max(8, self.width - max(prefix_width, 4 if not prefix_width else 0))
        lines = body.wrap(self.console, available, overflow="fold", justify="left")
        if not lines:
            self._print(prefix)
            return
        # A continuation line never starts at column 0: badges are the only
        # thing that begins a line there, so wrapped target text cannot pose
        # as a new finding heading.
        continuation = Text(" " * (prefix_width or 4))
        for index, line in enumerate(lines):
            out = (prefix if index == 0 else continuation).copy()
            out.append_text(line)
            out.rstrip()
            self._print(out)

    def _rule(self, title: str) -> None:
        """A WinPEAS-style section rule: `──── Title ────`."""
        from rich.text import Text
        glyph = self.glyphs["rule"]
        label = f" {title} "
        pad = max(0, self.width - len(label) - 4)
        left = glyph * 4
        right = glyph * pad
        line = Text()
        line.append(left, style=TERMINAL_STYLE_RULE)
        line.append(label, style=TERMINAL_STYLE_HEADING)
        line.append(right, style=TERMINAL_STYLE_RULE)
        line.truncate(self.width)
        self._blank()
        self._print(line)

    def _subrule(self, title: str) -> None:
        self._blank()
        self._print(self._text((f"{self.glyphs['bullet']} {title}", TERMINAL_STYLE_HEADING)))

    def _note(self, message: str, style: str = TERMINAL_STYLE_DIM, indent: int = 2) -> None:
        from rich.text import Text
        self._hang(Text(self._line(message), style=style), indent=indent)

    def _kv(self, pairs: Sequence[Tuple[str, Any]], indent: int = 2) -> None:
        """Aligned `label: value` lines; a long value wraps under itself."""
        from rich.text import Text
        pairs = [(k, v) for k, v in pairs if v not in (None, "")]
        if not pairs:
            return
        width = min(20, max(len(k) for k, _ in pairs)) + 1
        for key, value in pairs:
            body = value if isinstance(value, Text) else Text(self._line(value))
            self._hang(body, indent=indent, marker=f"{key}:".ljust(width + 1),
                       marker_style=TERMINAL_STYLE_LABEL)

    def _bullets(self, items: Sequence[Any], indent: int = 4, style: str = "") -> None:
        from rich.text import Text
        for item in items:
            self._hang(Text(self._line(item), style=style), indent=indent,
                       marker=f"{self.glyphs['bullet']} ", marker_style=TERMINAL_STYLE_DIM)

    def _showing(self, shown: int, total: int, what: str, where: str = "the JSON report",
                 in_document: Optional[int] = None, source_artifact: str = "the source artifacts") -> None:
        """
        Always state a bound that was hit; never leave a list silently short.

        `in_document` is how many of `total` the JSON report itself holds
        (its own bound). The statement distinguishes what the JSON report
        has from what only the producing module's artifact has, so it never
        points the reader at a file for records that are not in it.
        """
        if total <= shown:
            self._note(f"Showing {shown} of {total} {what}.")
            return
        if in_document is None or in_document >= total:
            self._note(f"Showing {shown} of {total} {what}; {total - shown} more in {where}.",
                       TERMINAL_STYLE_WARN)
            return
        parts = [f"Showing {shown} of {total} {what}"]
        if in_document > shown:
            parts.append(f"{in_document - shown} more in {where}")
        parts.append(f"{total - in_document} more only in {source_artifact}")
        self._note("; ".join(parts) + ".", TERMINAL_STYLE_WARN)

    # -- badges -----------------------------------------------------------

    def severity_badge(self, severity: Any, reported: Any = None) -> Any:
        from rich.text import Text
        if severity in (None, ""):
            return Text("[NOT ASSESSED]", style=TERMINAL_STYLE_DIM)
        normalized = normalize_severity(severity)
        label = SEVERITY_BADGES.get(normalized, "UNKN")
        raw = self._line(reported, 24) if reported else ""
        if normalized == UNKNOWN and raw:
            label = f"UNKN:{raw}"
        return Text(f"[{label}]", style=TERMINAL_SEVERITY_STYLES.get(normalized, ""))

    def confidence_badge(self, confidence: Any) -> Any:
        from rich.text import Text
        normalized = normalize_confidence(confidence)
        return Text(f"[{CONFIDENCE_BADGES.get(normalized, 'CONF ?')}]", style=TERMINAL_STYLE_LABEL)

    def kind_badge(self, kind: Any) -> Any:
        from rich.text import Text
        key = _text(kind)
        return Text(f"[{KIND_BADGES.get(key, 'UNCLASSIFIED')}]",
                    style=TERMINAL_KIND_STYLES.get(key, ""))

    def flag_badge(self, label: str, style: str = TERMINAL_STYLE_WARN) -> Any:
        from rich.text import Text
        return Text(f"[{label}]", style=style)

    def _badges(self, entry: Dict[str, Any], kind: bool = True) -> Any:
        from rich.text import Text
        line = Text()
        line.append_text(self.severity_badge(entry.get("severity"), entry.get("severity_reported")))
        line.append_text(self.confidence_badge(entry.get("confidence")))
        if kind and entry.get("kind") is not None:
            line.append_text(self.kind_badge(entry.get("kind")))
        if entry.get("evidence_status") == EVIDENCE_INCOMPLETE:
            line.append_text(self.flag_badge(EVIDENCE_INCOMPLETE, TERMINAL_STYLE_BAD))
        if entry.get("suspended"):
            line.append_text(self.flag_badge("SUSPENDED"))
        if entry.get("stale"):
            line.append_text(self.flag_badge("STALE"))
        if entry.get("in_scope") is False:
            line.append_text(self.flag_badge("OUT OF SCOPE"))
        return line

    @staticmethod
    def _date(value: Any) -> str:
        """`2026-09-11T14:24:17.415169+00:00` -> `2026-09-11 14:24:17Z` when parseable."""
        text = _text(value)
        if not text:
            return NOT_AVAILABLE
        try:
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is not None:
                # A year-9999 stamp with an offset overflows the conversion.
                parsed = parsed.astimezone(timezone.utc)
                return parsed.strftime("%Y-%m-%d %H:%M:%SZ")
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OverflowError):
            return " ".join(text.split())[:40]

    # -- sections ---------------------------------------------------------

    def _render_header(self) -> None:
        from rich.panel import Panel
        from rich.text import Text
        from rich import box

        summary = _as_dict(self.doc.get("executive_summary"))
        severity = _as_dict(self.doc.get("severity"))
        findings = _as_dict(self.doc.get("findings"))
        scan = _as_dict(self.doc.get("scan"))

        body = Text()
        body.append("ReconHound Assessment Summary\n", style=TERMINAL_STYLE_HEADING)
        body.append("Target:    ", style=TERMINAL_STYLE_LABEL)
        body.append(self._line(self.doc.get("target"), 200) + "\n")
        body.append("Generated: ", style=TERMINAL_STYLE_LABEL)
        body.append(f"{self._date(self.doc.get('generated_at'))}   ")
        body.append(f"report schema {self._line(self.doc.get('report_schema_version'), 12)}\n",
                    style=TERMINAL_STYLE_DIM)
        if scan.get("execution_record_available"):
            body.append("Run:       ", style=TERMINAL_STYLE_LABEL)
            status = self._line(scan.get("run_status") or UNKNOWN, 40)
            body.append(status, style=TERMINAL_STYLE_WARN if status != "completed" else "")
            body.append(f"   mode {self._line(scan.get('mode') or UNKNOWN, 40)}", style=TERMINAL_STYLE_DIM)
            if scan.get("interrupted"):
                body.append("   INTERRUPTED", style=TERMINAL_STYLE_WARN)
            body.append("\n")
        body.append("\n")
        body.append("Assets:        ", style=TERMINAL_STYLE_LABEL)
        body.append(f"{_int(summary.get('assets'))}  ")
        undetermined = _int(summary.get("scope_not_determined_assets"))
        body.append(f"({_int(summary.get('in_scope_assets'))} in scope, "
                    f"{_int(summary.get('out_of_scope_assets'))} out of scope"
                    + (f", {undetermined} not scope-bearing" if undetermined else "")
                    + ")\n", style=TERMINAL_STYLE_DIM)
        body.append("Observations:  ", style=TERMINAL_STYLE_LABEL)
        body.append(f"{_int(summary.get('observations'))}   ")
        body.append("Relationships: ", style=TERMINAL_STYLE_LABEL)
        body.append(f"{_int(summary.get('relationships'))}\n")

        if severity.get("available"):
            by_signal = _as_dict(severity.get("signals_by_severity"))
            body.append("Findings:      ", style=TERMINAL_STYLE_LABEL)
            body.append(f"{_int(severity.get('signals'))}")
            excluded = _int(findings.get("malformed_excluded")) + _int(findings.get("duplicates_excluded"))
            if excluded:
                body.append(f"  ({excluded} malformed/duplicate record(s) excluded)", style=TERMINAL_STYLE_WARN)
            if _int(findings.get("incomplete_evidence")):
                body.append(f"  ({_int(findings.get('incomplete_evidence'))} {EVIDENCE_INCOMPLETE})",
                            style=TERMINAL_STYLE_BAD)
            body.append("\n")
            for name in list(SEVERITY_SEQUENCE) + [UNKNOWN]:
                count = _int(by_signal.get(name))
                if name == UNKNOWN and not count:
                    continue
                body.append("  ")
                badge = self.severity_badge(name)
                body.append_text(badge)
                body.append(" " * (7 - badge.cell_len))
                body.append(f"{name.title() if name != UNKNOWN else 'Unknown'}: ".ljust(11))
                body.append(f"{count}\n", style=TERMINAL_STYLE_LABEL)
            counts = _as_dict(findings.get("counts_by_evidence_class"))
            body.append("Classes:       ", style=TERMINAL_STYLE_LABEL)
            body.append(f"confirmed {_int(counts.get(risk_engine.KIND_CONFIRMED))}, "
                        f"indicator {_int(counts.get(risk_engine.KIND_INDICATOR))}, "
                        f"CVE match {_int(counts.get(risk_engine.KIND_VULN_INTEL))}, "
                        f"observation {_int(counts.get(risk_engine.KIND_OBSERVATION))}\n")
            by_asset = _as_dict(severity.get("assets_by_severity"))
            body.append("Assets by sev: ", style=TERMINAL_STYLE_LABEL)
            body.append("  ".join(
                f"{SEVERITY_BADGES[name]} {_int(by_asset.get(name))}"
                for name in SEVERITY_SEQUENCE) + "\n")
            body.append("Queue:         ", style=TERMINAL_STYLE_LABEL)
            body.append(f"{_int(severity.get('queue_length'))} asset(s) to investigate")
            if _int(severity.get("suspended_signals")):
                body.append(f"   {_int(severity.get('suspended_signals'))} signal(s) suspended",
                            style=TERMINAL_STYLE_WARN)
            body.append("\n")
        else:
            body.append("Findings:      ", style=TERMINAL_STYLE_LABEL)
            body.append(f"{NOT_AVAILABLE} — {NO_ASSESSMENT}\n", style=TERMINAL_STYLE_WARN)
        if _int(summary.get("unresolved_conflicts")):
            cross = _int(summary.get("unresolved_conflicts_cross_source"))
            temporal = _int(summary.get("unresolved_conflicts_temporal"))
            body.append("Conflicts:     ", style=TERMINAL_STYLE_LABEL)
            parts = []
            if cross:
                parts.append(f"{cross} unresolved contradiction(s) between modules")
            if temporal:
                parts.append(f"{temporal} attribute(s) that changed between observations")
            # A pre-1.1 document carries neither breakdown; report the total
            # without claiming which kind it is rather than claiming wrongly.
            body.append((", ".join(parts) if parts else
                         f"{_int(summary.get('unresolved_conflicts'))} unresolved") + "\n",
                        style=TERMINAL_STYLE_WARN if cross or not parts else "")
        if summary.get("failed_module_executions") is not None:
            failed = _int(summary.get("failed_module_executions"))
            # An origin that answered nothing is a hole in coverage. Naming
            # only failures on this line let "0 failed" read as full coverage
            # for a run that never reached half its web origins.
            unreachable = _int(summary.get("unreachable_origins"))
            body.append("Coverage:      ", style=TERMINAL_STYLE_LABEL)
            body.append(f"{failed} failed module execution(s), "
                        f"{_int(summary.get('run_errors'))} run-level error(s)"
                        + (f", {unreachable} origin(s) never answered" if unreachable else "")
                        + "\n",
                        style=TERMINAL_STYLE_WARN if failed or unreachable else "")
        body.rstrip()
        self._print(Panel(body, box=box.ROUNDED if self.glyphs is _UNICODE_GLYPHS else box.ASCII,
                          border_style=TERMINAL_STYLE_RULE, width=self.width, expand=True))
        for line in _as_list(summary.get("headline")):
            self._note(line)

    def _render_queue(self) -> None:
        queue = _as_dict(self.doc.get("investigation_queue"))
        self._rule("Investigation queue")
        if not queue.get("available"):
            self._note(queue.get("reason") or NOT_AVAILABLE, TERMINAL_STYLE_WARN)
            return
        entries = _records(queue.get("entries"))
        total = _int(queue.get("total"), len(entries))
        if not entries:
            self._note("The investigation queue is empty at the configured minimum severity.")
            return
        shown = entries[: self.limits["terminal_max_queue_entries"]]
        for entry in shown:
            line = self._text((f"#{_int(entry.get('rank')):<3d} ", TERMINAL_STYLE_LABEL))
            line.append_text(self._badges(entry, kind=False))
            line.append(" " + self._line(entry.get("label") or entry.get("asset_id"), 300))
            line.append(f"  ({self._line(entry.get('asset_type_label') or UNKNOWN, 30)})",
                        style=TERMINAL_STYLE_DIM)
            self._hang(line)
            counts = (f"{_int(entry.get('confirmed_finding_count'))} confirmed, "
                      f"{_int(entry.get('indicator_count'))} indicator(s), "
                      f"{_int(entry.get('vulnerability_intelligence_count'))} CVE match(es); "
                      f"{_int(entry.get('contributing_signal_count'))} of "
                      f"{_int(entry.get('total_signal_count'))} signal(s) contributed")
            self._note(counts, indent=6)
            explanation = [_text(x) for x in _as_list(entry.get("explanation"))][:4]
            self._bullets(explanation, indent=6)
        self._showing(len(shown), total, "queue entries", in_document=_int(queue.get("shown"), len(entries)), source_artifact="risk_assessment.json")

    def _render_finding(self, entry: Dict[str, Any]) -> None:
        from rich.text import Text
        self._blank()
        head = self._badges(entry)
        head.append(" " + self._line(entry.get("summary") or "(no summary recorded)", 400),
                    style=TERMINAL_STYLE_LABEL)
        self._hang(head)
        subject = _as_dict(entry.get("subject"))
        asset = Text(self._line(subject.get("label") or NOT_AVAILABLE, 300))
        if subject:
            scope = _tri_state(subject.get("in_scope"), "in scope", "OUT OF SCOPE", "scope not determined")
            asset.append(f"  ({self._line(ASSET_TYPE_LABELS.get(_text(subject.get('asset_type')), subject.get('asset_type') or UNKNOWN), 30)}, {scope})",
                         style=TERMINAL_STYLE_DIM)
            if subject.get("present_in_graph") is False:
                asset.append("  [NOT IN GRAPH]", style=TERMINAL_STYLE_BAD)
        else:
            asset.append("  [NO SUBJECT RECORDED]", style=TERMINAL_STYLE_BAD)
        pairs: List[Tuple[str, Any]] = [
            ("Asset", asset),
            ("Category", entry.get("category") or UNKNOWN),
            ("Class", f"{KIND_LABELS.get(_text(entry.get('kind')), UNKNOWN)} — "
                      f"{KIND_DESCRIPTIONS.get(_text(entry.get('kind')), '')}".rstrip(" —")),
            ("Modules", ", ".join(_text(s) for s in _as_list(entry.get("sources"))) or UNKNOWN),
            ("Confidence", normalize_confidence(entry.get("confidence"))),
            ("Discovered", self._date(entry.get("last_seen"))),
            ("Signal", entry.get("signal_id")),
        ]
        if entry.get("kind") == risk_engine.KIND_VULN_INTEL:
            technology = " ".join(part for part in (_text(entry.get("technology")),
                                                    _text(entry.get("technology_version"))) if part)
            pairs.extend([
                ("CVE", entry.get("cve_id") or UNKNOWN),
                ("Technology", technology or UNKNOWN),
                ("CVSS", entry.get("cvss_score") if entry.get("cvss_score") is not None
                 else "not published / not retrieved"),
                ("Applies", entry.get("applicability") or UNKNOWN),
            ])
        if entry.get("suspended"):
            pairs.append(("Suspended", entry.get("suspension_reason") or UNKNOWN))
        if entry.get("stale"):
            pairs.append(("Stale", f"{display_value(entry.get('age_days'))} day(s) older than the "
                                   f"newest evidence in this graph"))
        self._kv(pairs, indent=4)

        evidence = [_text(x) for x in _as_list(entry.get("evidence"))]
        marker = _as_dict(entry.get("evidence_truncation"))
        total_evidence = _int(marker.get("total"), len(evidence))
        self._print(self._text(("    Evidence:", TERMINAL_STYLE_LABEL)))
        if evidence:
            shown = evidence[: self.limits["terminal_max_evidence_per_item"]]
            self._bullets(shown, indent=6)
            if total_evidence > len(shown):
                self._note(f"    Showing {len(shown)} of {total_evidence} evidence line(s); the rest "
                           f"is in the JSON report and surface_graph.json.", TERMINAL_STYLE_WARN)
        else:
            self._note(f"    none recorded — {EVIDENCE_INCOMPLETE}", TERMINAL_STYLE_BAD)

        provenance = [_as_dict(p) for p in _as_list(entry.get("provenance"))]
        marker = _as_dict(entry.get("provenance_truncation"))
        total_provenance = _int(marker.get("total"), len(provenance))
        if provenance:
            self._print(self._text(("    Provenance:", TERMINAL_STYLE_LABEL)))
            shown_prov = provenance[: self.limits["terminal_max_provenance_per_item"]]
            self._bullets([
                f"{_text(p.get('source')) or UNKNOWN}  obs {_text(p.get('observation_id')) or UNKNOWN}  "
                f"{normalize_confidence(p.get('confidence'))}  {self._date(p.get('timestamp'))}"
                for p in shown_prov], indent=6, style=TERMINAL_STYLE_DIM)
            if total_provenance > len(shown_prov):
                self._note(f"    Showing {len(shown_prov)} of {total_provenance} provenance "
                           f"record(s).", TERMINAL_STYLE_WARN)
        rationale = [_text(x) for x in _as_list(entry.get("rationale"))]
        if rationale:
            self._print(self._text(("    Why this severity:", TERMINAL_STYLE_LABEL)))
            self._bullets(rationale, indent=6)
        notes = [_text(x) for x in _as_list(entry.get("notes"))]
        if notes:
            self._bullets(notes, indent=6, style=TERMINAL_STYLE_DIM)

    def _render_findings(self) -> None:
        findings = _as_dict(self.doc.get("findings"))
        self._rule("Findings")
        if not findings.get("available"):
            self._note(findings.get("reason") or NOT_AVAILABLE, TERMINAL_STYLE_WARN)
            return
        entries = _records(findings.get("entries"))
        total = _int(findings.get("total"), len(entries))
        if not entries:
            self._note("No risk signals were extracted from this graph.")
            return
        self._note(f"Ordered by {self._line(findings.get('ordering') or 'severity', 120)}.")
        limit = self.limits["terminal_max_findings"]
        shown = entries[:limit]
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for entry in shown:
            grouped.setdefault(normalize_severity(entry.get("severity")), []).append(entry)
        for severity in list(SEVERITY_SEQUENCE) + [UNKNOWN]:
            bucket = grouped.get(severity)
            if not bucket:
                continue
            self._subrule(f"{severity} — {len(bucket)} shown")
            for entry in bucket:
                self._render_finding(entry)
        self._blank()
        self._showing(len(shown), total, "findings", in_document=_int(findings.get("shown"), len(entries)), source_artifact="risk_assessment.json")
        excluded = _int(findings.get("malformed_excluded")) + _int(findings.get("duplicates_excluded"))
        if excluded:
            self._note(f"{_int(findings.get('malformed_excluded'))} malformed and "
                       f"{_int(findings.get('duplicates_excluded'))} duplicate signal record(s) were "
                       f"excluded; see report generation errors.", TERMINAL_STYLE_WARN)

    def _render_vuln_intel(self) -> None:
        vuln = _as_dict(self.doc.get("vulnerability_intelligence"))
        self._rule("Vulnerability intelligence (possible CVE matches)")
        if not vuln.get("available"):
            self._note(vuln.get("reason") or NOT_AVAILABLE, TERMINAL_STYLE_WARN)
            return
        entries = _records(vuln.get("entries"))
        total = _int(vuln.get("count"), len(entries))
        if not entries:
            self._note("No CVE matches were recorded against observed versions.")
            return
        self._note(vuln.get("statement") or "")
        shown = entries[: self.limits["terminal_max_vuln_intel"]]
        for entry in shown:
            line = self._badges(entry, kind=False)
            technology = " ".join(part for part in (_text(entry.get("technology")),
                                                    _text(entry.get("technology_version"))) if part)
            line.append(f" {self._line(entry.get('cve_id') or UNKNOWN, 40)}", style=TERMINAL_STYLE_LABEL)
            line.append(f"  {self._line(technology or UNKNOWN, 80)}")
            cvss = entry.get("cvss_score")
            line.append(f"  CVSS {self._line(cvss, 10) if cvss is not None else 'n/a'}", style=TERMINAL_STYLE_DIM)
            line.append(f"  applies: {self._line(entry.get('applicability') or UNKNOWN, 40)}",
                        style=TERMINAL_STYLE_DIM)
            self._hang(line)
            subject = _as_dict(entry.get("subject"))
            self._note(f"on {self._line(subject.get('label') or NOT_AVAILABLE, 200)}", indent=4)
        self._showing(len(shown), total, "CVE matches", in_document=_int(vuln.get("shown"), len(entries)), source_artifact="risk_assessment.json")

    def _render_paths(self) -> None:
        paths = _as_dict(self.doc.get("attack_surface_paths"))
        self._rule("Attack-surface paths (how each asset was reached)")
        if not paths.get("available"):
            self._note(paths.get("reason") or NOT_AVAILABLE, TERMINAL_STYLE_WARN)
            return
        entries = _records(paths.get("entries"))
        total = _int(paths.get("total"), len(entries))
        if not entries:
            self._note("No discovery chains could be reconstructed.")
            return
        shown = entries[: self.limits["terminal_max_paths"]]
        arrow = self.glyphs["arrow"]
        for entry in shown:
            line = self.severity_badge(entry.get("severity"), entry.get("severity_reported"))
            line.append(" " + self._line(entry.get("label"), 200), style=TERMINAL_STYLE_LABEL)
            line.append(f"  ({_int(entry.get('hop_count'))} hop(s))", style=TERMINAL_STYLE_DIM)
            self._print(line)
            hops = _records(entry.get("hops"))
            for marker in _markers(entry.get("hops")):
                self._note(marker, TERMINAL_STYLE_WARN, indent=6)
            for index, hop in enumerate(hops):
                via = _as_dict(hop.get("via"))
                text = self._text((self._line(hop.get("label"), 200), ""),
                                  (f"  [{self._line(hop.get('asset_type_label') or UNKNOWN, 30)}]",
                                   TERMINAL_STYLE_DIM))
                if via:
                    rel_type = via.get("relationship_type") or via.get("rel_type") or UNKNOWN
                    sources = ", ".join(_text(x) for x in _as_list(via.get("sources"))) or UNKNOWN
                    text.append(f"  via {self._line(rel_type, 60)} ({self._line(sources, 120)})",
                                style=TERMINAL_STYLE_DIM)
                if hop.get("truncated"):
                    text.append("  [PATH TRUNCATED]", style=TERMINAL_STYLE_WARN)
                if hop.get("note"):
                    text.append(f"  {self._line(hop.get('note'), 120)}", style=TERMINAL_STYLE_DIM)
                self._hang(text, indent=6, marker="" if index == 0 else f"{arrow} ",
                           marker_style=TERMINAL_STYLE_DIM)
        self._showing(len(shown), total, "attack-surface paths", in_document=_int(paths.get("shown"), len(entries)), source_artifact="surface_graph.json")

    def _table(self, headers: Sequence[str], rows: Sequence[Sequence[Any]],
               styles: Optional[Sequence[str]] = None) -> None:
        """
        A Rich table whose every column folds (never ellipsizes) so no text
        is hidden; below 72 columns the same rows are printed as labelled
        lines instead, which is what remains readable there.
        """
        from rich.table import Table
        from rich.text import Text
        from rich import box
        if self.compact:
            for row in rows:
                for header, cell in zip(headers, row):
                    if cell in (None, ""):
                        continue
                    line = Text("    ")
                    line.append(f"{header}: ", style=TERMINAL_STYLE_LABEL)
                    if isinstance(cell, Text):
                        line.append_text(cell)
                    else:
                        line.append(self._line(cell))
                    self._print(line)
                self._print(Text("    " + self.glyphs["rule"] * 8, style=TERMINAL_STYLE_DIM))
            return
        table = Table(box=box.SIMPLE_HEAD if self.glyphs is _UNICODE_GLYPHS else box.ASCII2,
                      header_style=TERMINAL_STYLE_HEADING, pad_edge=False, width=self.width,
                      show_edge=False)
        for index, header in enumerate(headers):
            style = styles[index] if styles and index < len(styles) else ""
            table.add_column(header, overflow="fold", no_wrap=False, style=style)
        for row in rows:
            table.add_row(*[cell if isinstance(cell, Text) else self._line(cell) for cell in row])
        self._print(table)

    def _render_technologies(self) -> None:
        section = _as_dict(self.doc.get("technologies"))
        entries = _records(section.get("entries"))
        total = _int(section.get("total"), len(entries))
        self._rule("Technology stack")
        if not entries:
            self._note("No technologies were fingerprinted.")
            return
        shown = entries[: self.limits["terminal_max_assets_per_type"]]
        rows = []
        for entry in shown:
            version = self._line(entry.get("version") or "?", 40)
            if entry.get("version_conflict"):
                version += " [CONFLICT]"
            rows.append([
                self.severity_badge(entry.get("severity"), entry.get("severity_reported")),
                entry.get("name") or UNKNOWN, version, entry.get("observed_on") or UNKNOWN,
                CONFIDENCE_BADGES.get(normalize_confidence(entry.get("confidence")), "CONF ?"),
                ", ".join(_text(s) for s in _as_list(entry.get("sources"))) or UNKNOWN,
            ])
        self._table(["Sev", "Technology", "Version", "Observed on", "Confidence", "Modules"], rows)
        self._showing(len(shown), total, "technologies", in_document=_int(section.get("shown"), len(entries)), source_artifact="surface_graph.json")

    def _render_services(self) -> None:
        section = _as_dict(self.doc.get("services"))
        entries = _records(section.get("entries"))
        total = _int(section.get("total"), len(entries))
        self._rule("Services and ports")
        if not entries:
            self._note("No services were recorded.")
            return
        shown = entries[: self.limits["terminal_max_assets_per_type"]]
        rows = [[
            self.severity_badge(entry.get("severity"), entry.get("severity_reported")),
            entry.get("label") or UNKNOWN, entry.get("status") or UNKNOWN,
            entry.get("service") or "", self._line(entry.get("banner") or "", 120),
            ", ".join(_text(s) for s in _as_list(entry.get("sources"))) or UNKNOWN,
        ] for entry in shown]
        self._table(["Sev", "Service", "State", "Identified as", "Banner", "Modules"], rows)
        self._showing(len(shown), total, "services", in_document=_int(section.get("shown"), len(entries)), source_artifact="surface_graph.json")

    def _render_group(self, key: str, title: str, empty: str) -> None:
        section = _as_dict(self.doc.get(key))
        entries = _records(section.get("entries"))
        total = _int(section.get("total"), len(entries))
        self._rule(title)
        if not entries:
            self._note(empty)
            return
        shown = entries[: self.limits["terminal_max_assets_per_type"]]
        for entry in shown:
            line = self.severity_badge(entry.get("severity"), entry.get("severity_reported"))
            line.append(" " + self._line(entry.get("label"), 300))
            scope = _tri_state(entry.get("in_scope"), "", " [OUT OF SCOPE]", " [scope ?]")
            if scope:
                line.append(scope, style=TERMINAL_STYLE_WARN)
            line.append(f"  {', '.join(_text(s) for s in _as_list(entry.get('sources'))) or UNKNOWN}",
                        style=TERMINAL_STYLE_DIM)
            dependents = [_as_dict(d) for d in _as_list(entry.get("depended_on_by"))]
            if dependents:
                line.append(f"  used by: {', '.join(self._line(d.get('label'), 80) for d in dependents[:6])}"
                            + (f" (+{len(dependents) - 6} more)" if len(dependents) > 6 else ""),
                            style=TERMINAL_STYLE_DIM)
            self._hang(line)
        self._showing(len(shown), total, title.lower(), in_document=_int(section.get("shown"), len(entries)), source_artifact="surface_graph.json")

    def _render_conflicts(self) -> None:
        section = _as_dict(self.doc.get("conflicts"))
        entries = _records(section.get("entries"))
        total = _int(section.get("total"), len(entries))
        self._rule("Conflicting observations (preserved, not resolved)")
        if not entries:
            self._note("No contradictions between modules were recorded.")
            return
        shown = entries[: self.limits["terminal_max_conflicts"]]
        for entry in shown:
            asset = _as_dict(entry.get("asset"))
            line = self.flag_badge("CONFLICT")
            line.append(f" {self._line(asset.get('label') or asset.get('asset_id'), 200)}",
                        style=TERMINAL_STYLE_LABEL)
            line.append(f"  attribute {self._line(entry.get('attribute') or UNKNOWN, 60)}  "
                        f"({self._line(entry.get('status') or 'unresolved', 30)})", style=TERMINAL_STYLE_DIM)
            self._hang(line)
            self._bullets([
                f"{self._line(o.get('display') or o.get('value'), 200)}  "
                f"— {self._line(o.get('source') or UNKNOWN, 40)} at {self._date(o.get('timestamp'))}"
                for o in (_as_dict(o) for o in _as_list(entry.get("observations")))], indent=6)
            suspended = [_text(s) for s in _as_list(entry.get("suspended_signals"))]
            if suspended:
                self._note(f"    Held back pending resolution: {'; '.join(self._line(s, 120) for s in suspended[:5])}",
                           TERMINAL_STYLE_WARN)
        self._showing(len(shown), total, "conflicts", in_document=_int(section.get("shown"), len(entries)), source_artifact="surface_graph.json")

    def _render_negative(self) -> None:
        section = _as_dict(self.doc.get("negative_results"))
        entries = _records(section.get("entries"))
        total = _int(section.get("total"), len(entries))
        self._rule("Negative results (checked, not found)")
        census = _as_dict(section.get("check_state_census"))
        if census:
            self._note("Check states: " + ", ".join(
                f"{_int(census[k])} {self._line(k, 40)}" for k in sorted(census, key=str)))
        if not entries:
            self._note("No negative results were recorded.")
            return
        shown = entries[: self.limits["terminal_max_negative_results"]]
        for entry in shown:
            asset = _as_dict(entry.get("asset"))
            line = self._text(("[NOT FOUND]", TERMINAL_STYLE_DIM))
            line.append(f" {self._line(entry.get('check') or UNKNOWN, 80)}", style=TERMINAL_STYLE_LABEL)
            line.append(f" on {self._line(asset.get('label') or asset.get('asset_id'), 200)}")
            line.append(f"  {self._line(entry.get('source') or UNKNOWN, 40)}, "
                        f"{CONFIDENCE_BADGES.get(normalize_confidence(entry.get('confidence')), 'CONF ?')}, "
                        f"checked {_int(entry.get('check_count'))}x, last {self._date(entry.get('last_checked_at'))}",
                        style=TERMINAL_STYLE_DIM)
            self._hang(line)
        self._showing(len(shown), total, "negative results", in_document=_int(section.get("shown"), len(entries)), source_artifact="surface_graph.json")

    def _render_execution(self) -> None:
        section = _as_dict(self.doc.get("execution"))
        scan = _as_dict(self.doc.get("scan"))
        self._rule("Execution")
        if not section.get("available"):
            self._note(section.get("reason") or NOT_AVAILABLE, TERMINAL_STYLE_WARN)
            return
        by_status = _as_dict(scan.get("executions_by_status"))
        self._kv([
            ("Status", scan.get("run_status") or UNKNOWN),
            ("Mode", scan.get("mode") or UNKNOWN),
            ("Started", self._date(scan.get("started_at"))),
            ("Finished", self._date(scan.get("finished_at"))),
            ("Modules", ", ".join(f"{_int(by_status[k])} {self._line(k, 30)}" for k in sorted(by_status, key=str))
             or NOT_AVAILABLE),
            ("Adaptive", f"{_int(_as_dict(section.get('adaptive')).get('rounds'))} round(s), "
                         f"{_int(_as_dict(section.get('adaptive')).get('actions'))} action(s), "
                         f"{_int(_as_dict(section.get('adaptive')).get('deferred'))} deferred"),
        ])
        failed = [_as_dict(m) for m in _as_list(section.get("failed_modules"))]
        if failed:
            self._subrule(f"Failed / rejected / interrupted executions — {len(failed)}")
            for record in failed[: self.limits["terminal_max_module_executions"]]:
                line = self.flag_badge(self._line(record.get("status") or UNKNOWN, 20).upper(), TERMINAL_STYLE_BAD)
                line.append(f" {self._line(record.get('module') or UNKNOWN, 40)}", style=TERMINAL_STYLE_LABEL)
                line.append(f" on {self._line(record.get('subject') or UNKNOWN, 120)}")
                reason = record.get("error") or record.get("skip_reason")
                if reason:
                    line.append(f"  {self._line(reason, 300)}", style=TERMINAL_STYLE_DIM)
                self._hang(line)
            if len(failed) > self.limits["terminal_max_module_executions"]:
                self._showing(self.limits["terminal_max_module_executions"], len(failed),
                              "failed executions")
        errors = [_as_dict(e) for e in _as_list(section.get("errors"))]
        if errors:
            self._subrule(f"Run-level errors — {len(errors)}")
            self._bullets([f"{self._line(e.get('stage') or UNKNOWN, 40)}: {self._line(e.get('error') or UNKNOWN, 300)}"
                           for e in errors[: self.limits["terminal_max_module_executions"]]], indent=4)
        pending_marker = _as_dict(section.get("pending_opportunities_truncation"))
        pending_total = _int(pending_marker.get("total"), len(_as_list(section.get("pending_opportunities"))))
        if pending_total:
            self._note(f"{pending_total} reconnaissance opportunit(y/ies) remain pending; see the "
                       f"execution record.", TERMINAL_STYLE_WARN)

    def _render_caveats(self) -> None:
        self._rule("Warnings, limitations and report integrity")
        warnings = [_text(w) for w in _as_list(self.doc.get("warnings"))]
        if warnings:
            self._bullets(warnings, indent=2, style=TERMINAL_STYLE_WARN)
        limitations = [_text(x) for x in _as_list(self.doc.get("limitations"))]
        if limitations:
            self._bullets(limitations, indent=2)
        else:
            self._note("No coverage limitations were recorded for this run.")
        errors = [_as_dict(e) for e in _as_list(self.doc.get("errors"))]
        if errors:
            self._subrule(f"Report generation errors — {len(errors)}")
            self._bullets([f"{self._line(e.get('stage') or UNKNOWN, 40)}: {self._line(e.get('error') or UNKNOWN, 300)}"
                           for e in errors[:25]], indent=4, style=TERMINAL_STYLE_DIM)
            if len(errors) > 25:
                self._showing(25, len(errors), "report generation errors")
        stats = _as_dict(self.doc.get("sanitization"))
        if stats:
            self._note("Content hardening: " + ", ".join(
                f"{_int(stats[k])} {k.replace('_', ' ')}" for k in sorted(stats, key=str)))
        self._subrule("Standing statements")
        self._bullets([_text(n) for n in _as_list(self.doc.get("notes"))], indent=2, style=TERMINAL_STYLE_DIM)
        if "source_artifacts" in self.omit:
            return
        artifacts = _as_dict(self.doc.get("source_artifacts"))
        self._subrule("Source artifacts")
        self._kv([(key, artifacts[key] or "not produced by this run") for key in sorted(artifacts, key=str)])

    # -- document ---------------------------------------------------------

    def render(self) -> None:
        steps: List[Tuple[str, Any]] = [
            ("header", self._render_header),
            ("queue", self._render_queue),
            ("findings", self._render_findings),
            ("vulnerability_intelligence", self._render_vuln_intel),
            ("attack_surface_paths", self._render_paths),
            ("technologies", self._render_technologies),
            ("services", self._render_services),
            ("endpoints", lambda: self._render_group(
                "endpoints", "Endpoints", "No endpoints were discovered.")),
            ("javascript", lambda: self._render_group(
                "javascript", "JavaScript assets", "No JavaScript assets were recorded.")),
            ("supply_chain", lambda: self._render_group(
                "supply_chain", "Supply chain (third-party services)",
                "No third-party dependencies were recorded.")),
            ("conflicts", self._render_conflicts),
            ("negative_results", self._render_negative),
            ("execution", self._render_execution),
            ("caveats", self._render_caveats),
        ]
        for name, step in steps:
            if name not in self.omit:
                step()
        self._blank()


def render_terminal_report(document: Dict[str, Any], console: Any = None, *,
                           file: Any = None, width: Optional[int] = None,
                           color: Optional[bool] = None,
                           limits: Optional[Dict[str, int]] = None,
                           omit: Optional[Sequence[str]] = None) -> None:
    """
    Print a report document to a terminal (stdout by default).

    `console` may be a pre-built Rich Console (the CLI passes its own, so the
    report shares the CLI's colour and width decisions); otherwise one is
    built with `make_report_console(file, width, color)`, which auto-detects
    colour support and honours NO_COLOR, TERM=dumb, CI and non-TTY output.
    `omit` names sections the host already shows (see
    `TerminalReportRenderer.render`).
    """
    if console is None:
        console = make_report_console(file=file, width=width, color=color)
        width = None  # the console was sized from it
    TerminalReportRenderer(document, console, limits=limits, omit=omit, width=width).render()


def render_text_report(document: Dict[str, Any], width: int = TERMINAL_DEFAULT_WIDTH,
                       limits: Optional[Dict[str, int]] = None) -> str:
    """
    The terminal report as plain text: no colour, no escape sequences, fixed
    width. This is what the `text` format writes to disk. Pure; no I/O.
    """
    buffer = _Utf8StringIO()
    console = make_report_console(file=buffer, width=width, color=False)
    TerminalReportRenderer(document, console, limits=limits).render()
    return buffer.getvalue()


class _Utf8StringIO(io.StringIO):
    """A StringIO that declares UTF-8, so the text file gets the Unicode glyph set."""
    encoding = "utf-8"


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
    text_width: int = TERMINAL_DEFAULT_WIDTH,
    include_document: bool = False,
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
    does not exist. With `include_document=True` (or `persist=False`) the
    result also carries the report document itself under `document`, so a
    caller can render the terminal report from exactly the state that was
    written to disk instead of building it a second time.
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

    if include_document or not persist:
        result["document"] = document
    if not persist:
        return result

    store = ReportStore(output_dir=output_dir, subdir=reports_subdir)
    result["reports_dir"] = os.path.abspath(store.reports_dir)

    for fmt in requested:
        try:
            filename = f"{stem}.{FORMAT_EXTENSIONS[fmt]}"
            if fmt == FORMAT_HTML:
                path = store.save_text(filename, render_html_report(document))
            elif fmt == FORMAT_TEXT:
                path = store.save_text(filename, render_text_report(document, width=text_width))
            else:
                path = store.save_json(filename, document)
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
                        help="Report format to write (repeatable; default: all)")
    parser.add_argument("--name", default=DEFAULT_FILENAME_STEM,
                        help=f"Report file name without extension (default: {DEFAULT_FILENAME_STEM})")
    parser.add_argument("--terminal", action="store_true",
                        help="Print the terminal report to stdout instead of writing files "
                             "(colour when stdout is a TTY; NO_COLOR, TERM=dumb and CI disable it)")
    parser.add_argument("--width", type=int, default=None, metavar="COLS",
                        help="Terminal/text report width (default: the terminal's, or "
                             f"{TERMINAL_DEFAULT_WIDTH} when not a TTY)")
    parser.add_argument("--no-color", action="store_true",
                        help="Never emit colour in the terminal report")
    args = parser.parse_args()

    try:
        if args.terminal:
            document = build_report_document(
                graph=args.graph, assessment=args.assessment, execution=args.execution,
                output_dir=args.output_dir)
            render_terminal_report(document, width=args.width,
                                   color=False if args.no_color else None)
            return
        result = generate_report(
            graph=args.graph, assessment=args.assessment, execution=args.execution,
            output_dir=args.output_dir, formats=args.format or VALID_FORMATS,
            filename_stem=args.name,
            text_width=args.width if args.width else TERMINAL_DEFAULT_WIDTH,
        )
    except ReportError as exc:
        print(f"report generation failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except ImportError as exc:
        print(f"the terminal report requires the 'rich' package ({exc}); "
              f"install the project dependencies: pip install -r requirements.txt", file=sys.stderr)
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
