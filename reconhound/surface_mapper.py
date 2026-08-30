"""
reconhound/surface_mapper.py — ReconHound Module 6 (surface_mapper.py).

Phase: Continuous. See context.md §10 (module 6) for the authoritative
responsibilities, and §7/§8 for the asset-graph and evidence/confidence/
negative-result/conflict data model this module implements and owns.

This is the central intelligence layer of ReconHound: it does not scan
anything itself. It consumes the structured finding records already
produced by the other reconnaissance modules (every module's
`make_finding()` output — {type, target, value, evidence, confidence,
source, timestamp, metadata}, typically read from
<output_dir>/pending_assets.json) and turns them into:

  Observation -> Evidence -> Asset/Relationship -> Confidence -> State
  -> Reconnaissance opportunity

Responsibilities implemented here (context.md §10 item 6):
  - Normalize outputs from every ReconHound module into common structures.
  - Deduplicate/correlate assets discovered by multiple sources.
  - Maintain the unified asset relationship graph.
  - Detect subdomain-takeover indicators and dangling-CNAME relationships
    (indicators only — never a claim of confirmed takeover; no
    exploitation, no claiming of discovered resources).
  - Map virtual-host relationships.
  - Store evidence and track confidence for individual findings.
  - Detect and preserve conflicting observations (never silently overwrite).
  - Maintain negative-result / check-state memory over all four context.md
    §8 states (not checked / checked and not found / found / found with
    uncertainty).
  - Construct attack-surface paths from discovered relationships.
  - Track discovery state (discovered/queued/investigated/completed/failed).
  - Expose structured reconnaissance opportunities for the (not-yet-built)
    core/orchestrator.py to consume. An opportunity is an instruction to
    point an active module at an asset, so it is never emitted for an asset
    known to be outside the authorized target scope, and never resurrected
    once the orchestrator has consumed it.

Every state-changing call persists immediately to
<output_dir>/surface_graph.json via crash-safe atomic writes (same
write-to-temp + os.replace pattern every other module's
PendingAssetsStore uses), and re-ingesting the same finding record (or the
same pending_assets.json file) more than once is a no-op — this module
never needs to be told what it has already processed.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

MODULE_NAME = "surface_mapper.py"

# ---------------------------------------------------------------------------
# Confidence levels (context.md §8) — identical vocabulary to every other
# module so ingested finding records need no translation.
# ---------------------------------------------------------------------------

CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"
_CONFIDENCE_ORDER = {CONFIDENCE_LOW: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_HIGH: 2}
_VALID_CONFIDENCE = set(_CONFIDENCE_ORDER)

# ---------------------------------------------------------------------------
# Discovery state machine (context.md §10 item 6 / task contract)
# ---------------------------------------------------------------------------

# Negative-result / check-state memory (context.md §8: "track check state per
# (asset, check): Not checked / Checked and not found / Found / Found with
# uncertainty"). All four states are representable; CHECK_NOT_CHECKED is the
# implicit default for any (asset, check) pair never recorded.
CHECK_NOT_CHECKED = "not_checked"
CHECK_NOT_FOUND = "checked_not_found"
CHECK_FOUND = "found"
CHECK_FOUND_UNCERTAIN = "found_with_uncertainty"

STATE_DISCOVERED = "discovered"
STATE_QUEUED = "queued"
STATE_INVESTIGATED = "investigated"
STATE_COMPLETED = "completed"
STATE_FAILED = "failed"
VALID_STATES = {STATE_DISCOVERED, STATE_QUEUED, STATE_INVESTIGATED, STATE_COMPLETED, STATE_FAILED}

# ---------------------------------------------------------------------------
# Asset types (context.md §7 unified asset graph)
# ---------------------------------------------------------------------------

ASSET_ORGANIZATION = "organization"
ASSET_HOSTNAME = "hostname"          # covers both domain and subdomain layers
ASSET_IP = "ip"
ASSET_PORT = "port"                  # ip:port/protocol — the "service" layer
ASSET_TECHNOLOGY = "technology"
ASSET_ENDPOINT = "endpoint"
ASSET_PARAMETER = "parameter"
ASSET_JAVASCRIPT = "javascript"
ASSET_THIRD_PARTY = "third_party_service"
ASSET_FINDING = "finding"

# ---------------------------------------------------------------------------
# Relationship types (context.md §7/§8 "relationships must be first-class")
# ---------------------------------------------------------------------------

REL_HOSTNAME_TO_IP = "hostname_to_ip"
REL_HOSTNAME_TO_CNAME = "hostname_to_cname"
REL_IP_TO_SERVICE = "ip_to_service"
REL_IP_TO_VHOST = "ip_to_vhost"
REL_SUBDOMAIN_TO_THIRD_PARTY = "subdomain_to_third_party"
REL_ASSET_TO_ENDPOINT = "asset_to_endpoint"
REL_ENDPOINT_TO_PARAMETER = "endpoint_to_parameter"
REL_ASSET_TO_TECHNOLOGY = "asset_to_technology"
REL_ASSET_TO_FINDING = "asset_to_finding"
REL_ASSET_TO_JAVASCRIPT = "asset_to_javascript"
REL_JAVASCRIPT_TO_ENDPOINT = "javascript_to_endpoint"
REL_CERTIFICATE_SAN = "certificate_san"
REL_DOMAIN_TO_ORGANIZATION = "domain_to_organization"


class ScopeError(ValueError):
    """Raised when scope enforcement rejects a hostname/target."""


class MalformedFindingError(ValueError):
    """Raised when a single finding record is not a usable observation."""


class PersistenceError(RuntimeError):
    """Raised when the surface graph state file cannot be safely read/written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _short_hash(*parts: Any) -> str:
    blob = json.dumps(parts, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:20]


# ---------------------------------------------------------------------------
# Scope enforcement (context.md §16 — mirrors passive_recon.py's model)
# ---------------------------------------------------------------------------

def is_in_scope(hostname: str, target: str) -> bool:
    """True if `hostname` is the target itself or a subdomain of it."""
    if not hostname or not target:
        return False
    h = str(hostname).strip().rstrip(".").lower()
    t = str(target).strip().rstrip(".").lower()
    return h == t or h.endswith("." + t)


# ---------------------------------------------------------------------------
# Normalization helpers — identity keys used for asset deduplication
# ---------------------------------------------------------------------------

def _norm_host(value: Any) -> str:
    return str(value).strip().rstrip(".").lower()


def _norm_ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return str(value).strip().lower()


def _norm_url(value: Any) -> str:
    """Scheme/host lower-cased, path defaulted to '/', query preserved, fragment dropped."""
    try:
        raw = str(value).strip()
        parts = urlsplit(raw)
        if not parts.scheme or not parts.netloc:
            return raw
        scheme = parts.scheme.lower()
        netloc = parts.netloc.lower()
        path = parts.path or "/"
        return urlunsplit((scheme, netloc, path, parts.query, ""))
    except Exception:
        return str(value).strip()


def _hostname_of_url(url: str) -> Optional[str]:
    try:
        host = urlsplit(str(url)).hostname
        return _norm_host(host) if host else None
    except Exception:
        return None


def _is_absolute_url(value: Any) -> bool:
    try:
        parts = urlsplit(str(value).strip())
        return bool(parts.scheme and parts.netloc)
    except Exception:
        return False


def _aid(asset_type: str, *parts: Any) -> str:
    key = ":".join(str(p) for p in parts if p is not None and p != "")
    return f"{asset_type}:{key}"


# ---------------------------------------------------------------------------
# Subdomain-takeover / dangling-CNAME fingerprint catalog
#
# Public, widely-documented CNAME-suffix / "unclaimed page" signatures
# (the same class of data used by well-known open-source takeover
# fingerprint lists). Matching a signature is an INDICATOR only — it
# means "this hostname's CNAME points at a provider known to allow
# subdomain takeover when the referenced resource is unclaimed", not a
# confirmed vulnerability. Never used to claim or interact with the
# referenced third-party resource (context.md §16 — recon, not exploit).
# ---------------------------------------------------------------------------

TAKEOVER_SIGNATURES: List[Dict[str, Any]] = [
    {"provider": "GitHub Pages", "cname_suffixes": ["github.io", "github.map.fastly.net"],
     "fingerprints": ["there isn't a github pages site here"]},
    {"provider": "Heroku", "cname_suffixes": ["herokuapp.com", "herokudns.com"],
     "fingerprints": ["no such app"]},
    {"provider": "Amazon S3", "cname_suffixes": ["s3.amazonaws.com", "s3-website"],
     "fingerprints": ["nosuchbucket", "the specified bucket does not exist"]},
    {"provider": "Microsoft Azure", "cname_suffixes": [
        "azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
        "trafficmanager.net", "blob.core.windows.net"],
     "fingerprints": ["404 web site not found"]},
    {"provider": "Shopify", "cname_suffixes": ["myshopify.com"],
     "fingerprints": ["sorry, this shop is currently unavailable"]},
    {"provider": "Fastly", "cname_suffixes": ["fastly.net"],
     "fingerprints": ["fastly error: unknown domain"]},
    {"provider": "Pantheon", "cname_suffixes": ["pantheonsite.io"],
     "fingerprints": ["the gods are wise"]},
    {"provider": "Unbounce", "cname_suffixes": ["unbouncepages.com"],
     "fingerprints": ["the requested url was not found on this server"]},
    {"provider": "Surge.sh", "cname_suffixes": ["surge.sh"],
     "fingerprints": ["project not found"]},
    {"provider": "Zendesk", "cname_suffixes": ["zendesk.com"],
     "fingerprints": ["help center closed"]},
    {"provider": "Tumblr", "cname_suffixes": ["tumblr.com"],
     "fingerprints": ["there's nothing here", "whatever you were looking for doesn't currently exist"]},
    {"provider": "WordPress.com", "cname_suffixes": ["wordpress.com"],
     "fingerprints": ["do you want to register"]},
    {"provider": "Netlify", "cname_suffixes": ["netlify.app", "netlify.com"],
     "fingerprints": ["not found - request id"]},
    {"provider": "Cargo Collective", "cname_suffixes": ["cargocollective.com"],
     "fingerprints": ["404 not found"]},
    {"provider": "Statuspage", "cname_suffixes": ["statuspage.io"],
     "fingerprints": ["you are being redirected"]},
]


def _match_takeover_provider(cname_target: str) -> Optional[Dict[str, Any]]:
    t = _norm_host(cname_target)
    for sig in TAKEOVER_SIGNATURES:
        for suffix in sig["cname_suffixes"]:
            if t == suffix or t.endswith("." + suffix):
                return sig
    return None


# ---------------------------------------------------------------------------
# Crash-safe persistence for the surface graph state file
# ---------------------------------------------------------------------------

class GraphStore:
    """
    Crash-safe, atomic JSON persistence for <output_dir>/surface_graph.json.

    Mirrors every module's PendingAssetsStore write pattern (write-to-temp
    + os.replace) but persists a single evolving state document rather
    than an append-only list, since the graph is mutated (assets/
    relationships updated in place, not merely appended) as new
    observations correlate with existing ones.
    """

    def __init__(self, output_dir: str = "output", filename: str = "surface_graph.json"):
        self.output_dir = output_dir
        self.path = os.path.join(output_dir, filename)
        self._lock = threading.Lock()
        os.makedirs(self.output_dir, exist_ok=True)

    def load(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if not os.path.exists(self.path):
                return None
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                if not content:
                    return None
                data = json.loads(content)
                if not isinstance(data, dict):
                    raise ValueError("surface_graph.json root must be a JSON object")
                return data
            except (json.JSONDecodeError, ValueError) as exc:
                raise PersistenceError(
                    f"Existing surface_graph.json is corrupt and cannot be safely loaded: {exc}"
                ) from exc

    def save(self, state: Dict[str, Any]) -> None:
        with self._lock:
            self._atomic_write(state)

    def _atomic_write(self, state: Dict[str, Any]) -> None:
        dir_name = os.path.dirname(self.path) or "."
        fd, tmp_path = tempfile.mkstemp(prefix=".surface_graph_", dir=dir_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, sort_keys=True, default=str)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise


# ---------------------------------------------------------------------------
# The central asset graph / correlation engine
# ---------------------------------------------------------------------------

class SurfaceMapper:
    """
    Central asset graph, normalization, correlation, and state layer.

    `target` is the authorized root domain this graph belongs to (used for
    scope tagging, not for enforcing what may be ingested — findings about
    out-of-scope hosts, e.g. third-party services, are still recorded, per
    the evidence model, and explicitly tagged out of scope).
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "output",
        state_filename: str = "surface_graph.json",
        autosave: bool = True,
        load_existing: bool = True,
    ):
        if not target or not isinstance(target, str):
            raise ScopeError("SurfaceMapper requires a non-empty target domain string.")
        self.target = _norm_host(target)
        self.output_dir = output_dir
        self.autosave = autosave
        self.store = GraphStore(output_dir=output_dir, filename=state_filename)
        # core/orchestrator.py coordinates threading (context.md §10 item 22)
        # and every module routes its output through this single shared graph,
        # so every state-mutating entry point is serialized. Re-entrant because
        # ingest_many() nests into ingest_finding().
        self._lock = threading.RLock()

        loaded = self.store.load() if load_existing else None
        if loaded is not None and loaded.get("target") not in (None, self.target):
            # Never silently repurpose another target's persisted graph —
            # preserve it untouched and start a fresh in-memory state instead.
            loaded = None
        self.state: Dict[str, Any] = self._adopt_loaded_state(loaded) if loaded is not None else self._new_state()

        self._dispatch: Dict[str, Callable[[Dict[str, Any], str], Dict[str, Any]]] = self._build_dispatch()

    # -- state skeleton ----------------------------------------------------

    def _new_state(self) -> Dict[str, Any]:
        now = _now()
        return {
            "target": self.target,
            "module": MODULE_NAME,
            "created_at": now,
            "updated_at": now,
            "observations": {},          # observation_id -> raw normalized finding
            "assets": {},                # asset_id -> asset record
            "relationships": {},         # relationship_id -> relationship record
            "conflicts": {},             # conflict_id -> conflict record
            "negative_results": {},      # "<asset_id>|<finding_type>" -> negative-result record
            "check_states": {},          # "<asset_id>|<finding_type>" -> four-state check record
            "opportunities": {},         # opportunity_id -> opportunity record
            "ingested_observation_ids": [],
            "ingestion_errors": [],
        }

    _STATE_MAPS = ("observations", "assets", "relationships", "conflicts",
                    "negative_results", "check_states", "opportunities")
    _STATE_LISTS = ("ingested_observation_ids", "ingestion_errors")

    def _adopt_loaded_state(self, loaded: Dict[str, Any]) -> Dict[str, Any]:
        """
        Adopt a persisted graph document written by any earlier run.

        A state file may legitimately predate a container added later, and a
        hand-edited or partially-written file may carry a container of the
        wrong JSON type. Neither may leave the mapper in a state where every
        subsequent operation raises KeyError, and neither may cause data to
        be dropped without a trace: a rejected container is preserved verbatim
        under `ingestion_errors` before being replaced with an empty one.
        """
        state = self._new_state()
        state.update(loaded)
        state["target"] = self.target
        state["module"] = MODULE_NAME
        errors = state.get("ingestion_errors")
        if not isinstance(errors, list):
            errors = []
        for key in self._STATE_MAPS:
            if not isinstance(state.get(key), dict):
                if key in loaded:
                    errors.append({"error": f"persisted state container {key!r} was not a JSON object; "
                                            f"replaced with an empty one", "raw": loaded[key], "at": _now()})
                state[key] = {}
        for key in self._STATE_LISTS:
            if not isinstance(state.get(key), list):
                if key in loaded and key != "ingestion_errors":
                    errors.append({"error": f"persisted state container {key!r} was not a JSON array; "
                                            f"replaced with an empty one", "raw": loaded[key], "at": _now()})
                state[key] = []
        state["ingestion_errors"] = errors
        return state

    # -- persistence ---------------------------------------------------

    def save(self) -> None:
        with self._lock:
            self.state["updated_at"] = _now()
            self.store.save(self.state)

    def _maybe_save(self) -> None:
        if self.autosave:
            self.save()

    # =======================================================================
    # Observation ingestion (crash-safe, idempotent)
    # =======================================================================

    def ingest_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingest one raw finding record (the shape produced by every module's
        make_finding(): type/target/value/evidence/confidence/source/
        timestamp/metadata) into the graph.

        Returns {"status": "ingested"|"duplicate_skipped", "observation_id": ...}.
        Raises MalformedFindingError for input that is not a usable
        observation at all (not a dict, or missing a `type`). Callers doing
        bulk ingestion should use ingest_many()/ingest_pending_assets_file(),
        which catch this per item instead of aborting the whole batch.
        """
        if not isinstance(finding, dict):
            raise MalformedFindingError(f"Finding must be a JSON object, got {type(finding).__name__}")
        finding_type = finding.get("type")
        if not finding_type or not isinstance(finding_type, str):
            raise MalformedFindingError("Finding is missing a non-empty string 'type' field")

        target = finding.get("target")
        target = _norm_host(target) if target else self.target
        value = finding.get("value")
        if value is None:
            value = {}
        evidence = finding.get("evidence")
        evidence = [str(e) for e in evidence] if isinstance(evidence, list) else ([] if evidence is None else [str(evidence)])
        confidence = finding.get("confidence")
        if confidence not in _VALID_CONFIDENCE:
            confidence = CONFIDENCE_LOW
        source = finding.get("source") or "unknown"
        # Identity must come from what the record itself carries. Substituting
        # _now() for a missing timestamp and then hashing it would give the same
        # record a fresh identity on every run, so re-reading a
        # pending_assets.json that contains a timestamp-less record would keep
        # re-ingesting it and grow the graph without bound.
        declared_timestamp = finding.get("timestamp")
        timestamp = declared_timestamp or _now()
        metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}

        normalized = {
            "type": finding_type, "target": target, "value": value, "evidence": evidence,
            "confidence": confidence, "source": source, "timestamp": timestamp, "metadata": metadata,
        }

        obs_id = _short_hash(finding_type, target, value, source, declared_timestamp)
        with self._lock:
            if obs_id in self.state["observations"]:
                return {"status": "duplicate_skipped", "observation_id": obs_id}

            normalized["observation_id"] = obs_id
            normalized["ingested_at"] = _now()
            self.state["observations"][obs_id] = normalized
            self.state["ingested_observation_ids"].append(obs_id)

            is_negative = self._is_negative_result(finding_type)
            try:
                if is_negative:
                    result = self._handle_negative_result(normalized, obs_id)
                else:
                    handler = self._resolve_handler(finding_type)
                    result = handler(normalized, obs_id)
            except Exception as exc:  # a bad/unexpected observation must never break ingestion
                result = {"status": "handler_error", "error": str(exc)}
                self.state["ingestion_errors"].append({
                    "observation_id": obs_id, "finding_type": finding_type, "error": str(exc), "at": _now(),
                })

            if not is_negative and isinstance(result, dict) and result.get("asset_id"):
                self._record_check_state(
                    result["asset_id"], normalized,
                    CHECK_FOUND if confidence in (CONFIDENCE_MEDIUM, CONFIDENCE_HIGH) else CHECK_FOUND_UNCERTAIN,
                )

            self._maybe_save()
            return {"status": "ingested", "observation_id": obs_id, **(result or {})}

    def ingest_many(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Ingest a list of raw finding records. One bad record never aborts the rest."""
        summary = {"total": len(findings), "ingested": 0, "duplicates": 0, "errors": 0}
        with self._lock:
            return self._ingest_many_locked(findings, summary)

    def _ingest_many_locked(self, findings: List[Dict[str, Any]], summary: Dict[str, Any]) -> Dict[str, Any]:
        was_autosave = self.autosave
        self.autosave = False
        try:
            for item in findings:
                try:
                    result = self.ingest_finding(item)
                    if result["status"] == "duplicate_skipped":
                        summary["duplicates"] += 1
                    else:
                        summary["ingested"] += 1
                except MalformedFindingError as exc:
                    summary["errors"] += 1
                    self.state["ingestion_errors"].append({
                        "error": str(exc), "raw": item if isinstance(item, (dict, list, str, int, float, bool)) else str(item),
                        "at": _now(),
                    })
        finally:
            self.autosave = was_autosave
        self._maybe_save()
        return summary

    def ingest_pending_assets_file(self, path: Optional[str] = None) -> Dict[str, Any]:
        """Read <output_dir>/pending_assets.json (as written by every discovery module) and ingest it."""
        path = path or os.path.join(self.output_dir, "pending_assets.json")
        if not os.path.exists(path):
            return {"total": 0, "ingested": 0, "duplicates": 0, "errors": 0, "note": f"{path} does not exist"}
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            records = json.loads(content) if content else []
        except (json.JSONDecodeError, OSError) as exc:
            raise PersistenceError(f"Cannot read pending_assets.json at {path!r}: {exc}") from exc
        if not isinstance(records, list):
            raise PersistenceError(f"{path!r} root must be a JSON array of finding records")
        return self.ingest_many(records)

    # =======================================================================
    # Negative-result state memory
    # =======================================================================

    @staticmethod
    def _is_negative_result(finding_type: str) -> bool:
        return "_checked_no" in finding_type or finding_type.endswith("_not_probed")

    def _handle_negative_result(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        subject = self._resolve_subject_asset(finding, obs_id)
        key = f"{subject['id']}|{finding['type']}"
        existing = self.state["negative_results"].get(key)
        # A single negative finding type covers many distinct concrete checks
        # (tech_fingerprint_checked_no_match is emitted once per signature
        # category, code_leak_checked_no_match once per search query). The
        # record is keyed by (asset, finding type), so keeping only the latest
        # `value` would silently discard which checks were actually performed.
        # Each distinct check scope is therefore appended to a bounded trail.
        checks = list(existing.get("checks", [])) if existing else []
        scope_entry = {"value": finding["value"], "evidence": finding["evidence"],
                        "source": finding["source"], "at": finding["timestamp"]}
        if not any(self._values_equal(c.get("value"), finding["value"]) for c in checks):
            checks.append(scope_entry)
        else:
            checks = [scope_entry if self._values_equal(c.get("value"), finding["value"]) else c for c in checks]
        if len(checks) > 100:
            del checks[: len(checks) - 100]
        record = {
            "asset_id": subject["id"],
            "finding_type": finding["type"],
            "state": CHECK_NOT_FOUND,
            "source": finding["source"],
            "confidence": finding["confidence"],
            "evidence": finding["evidence"],
            "value": finding["value"],
            "checks": checks,
            "observation_id": obs_id,
            "first_checked_at": existing["first_checked_at"] if existing else finding["timestamp"],
            "last_checked_at": finding["timestamp"],
            "check_count": (existing["check_count"] + 1) if existing else 1,
        }
        self.state["negative_results"][key] = record
        subject.setdefault("negative_checks", {})[finding["type"]] = finding["timestamp"]
        self._record_check_state(subject["id"], finding, CHECK_NOT_FOUND)
        return {"kind": "negative_result", "key": key, "asset_id": subject["id"]}

    def _record_check_state(self, asset_id: str, finding: Dict[str, Any], check_state: str) -> Dict[str, Any]:
        """
        Record the outcome of one (asset, check) pair using the full four-state
        model of context.md §8. The finding type is the check identity — the
        same vocabulary the rest of this module keys on — so a later module can
        ask "has anything already produced this observation for this asset?"
        instead of repeating an expensive check, and can distinguish a confident
        positive from an uncertain one.
        """
        key = f"{asset_id}|{finding['type']}"
        existing = self.state["check_states"].get(key)
        record = {
            "asset_id": asset_id,
            "check": finding["type"],
            "state": check_state,
            "source": finding["source"],
            "confidence": finding["confidence"],
            "observation_id": finding.get("observation_id", ""),
            "first_checked_at": existing["first_checked_at"] if existing else finding["timestamp"],
            "last_checked_at": finding["timestamp"],
            "check_count": (existing["check_count"] + 1) if existing else 1,
        }
        self.state["check_states"][key] = record
        asset = self.state["assets"].get(asset_id)
        if asset is not None:
            asset.setdefault("check_states", {})[finding["type"]] = check_state
        return record

    def has_been_checked(self, asset_id: str, finding_type: str) -> bool:
        """True if this (asset, check) pair was checked and nothing was found."""
        return f"{asset_id}|{finding_type}" in self.state["negative_results"]

    def get_check_state(self, asset_id: str, finding_type: str) -> str:
        """
        The context.md §8 check state for one (asset, check) pair: one of
        CHECK_NOT_CHECKED / CHECK_NOT_FOUND / CHECK_FOUND /
        CHECK_FOUND_UNCERTAIN.
        """
        record = self.state["check_states"].get(f"{asset_id}|{finding_type}")
        return record["state"] if record else CHECK_NOT_CHECKED

    def get_check_record(self, asset_id: str, finding_type: str) -> Optional[Dict[str, Any]]:
        return self.state["check_states"].get(f"{asset_id}|{finding_type}")

    def get_negative_result(self, asset_id: str, finding_type: str) -> Optional[Dict[str, Any]]:
        return self.state["negative_results"].get(f"{asset_id}|{finding_type}")

    # =======================================================================
    # Asset / relationship primitives
    # =======================================================================

    def _touch_record(self, record: Dict[str, Any], finding: Dict[str, Any], obs_id: str) -> None:
        """Shared bookkeeping for both assets and relationships: sources, evidence trail, confidence, timestamps."""
        record["last_seen"] = finding["timestamp"]
        if not record.get("first_seen"):
            record["first_seen"] = finding["timestamp"]
        sources = set(record.get("sources", []))
        sources.add(finding["source"])
        record["sources"] = sorted(sources)
        obs_ids = record.setdefault("observation_ids", [])
        if obs_id not in obs_ids:
            obs_ids.append(obs_id)
            if len(obs_ids) > 500:
                del obs_ids[: len(obs_ids) - 500]
        contributions = record.setdefault("_contributions", [])
        contributions.append({"source": finding["source"], "confidence": finding["confidence"]})
        if len(contributions) > 100:
            del contributions[: len(contributions) - 100]
        record["confidence"] = self._aggregate_confidence(contributions)

    @staticmethod
    def _aggregate_confidence(contributions: List[Dict[str, str]]) -> str:
        """context.md §8: multiple independent converging signals raise confidence; a single weak signal stays LOW."""
        if not contributions:
            return CONFIDENCE_LOW
        confidences = [c["confidence"] for c in contributions]
        sources = {c["source"] for c in contributions}
        if CONFIDENCE_HIGH in confidences:
            return CONFIDENCE_HIGH
        if CONFIDENCE_MEDIUM in confidences and len(sources) >= 2:
            return CONFIDENCE_HIGH
        if CONFIDENCE_MEDIUM in confidences:
            return CONFIDENCE_MEDIUM
        if len(sources) >= 2:
            return CONFIDENCE_MEDIUM
        return CONFIDENCE_LOW

    def _get_or_create_asset(self, asset_type: str, asset_id: str, value: Any, finding: Dict[str, Any], obs_id: str,
                              in_scope: Optional[bool] = None) -> Dict[str, Any]:
        asset = self.state["assets"].get(asset_id)
        if asset is None:
            asset = {
                "id": asset_id, "asset_type": asset_type, "value": value,
                "state": STATE_DISCOVERED, "state_history": [{"state": STATE_DISCOVERED, "at": finding["timestamp"], "reason": "first observed"}],
                "attributes": {}, "negative_checks": {}, "in_scope": in_scope,
            }
            self.state["assets"][asset_id] = asset
        elif in_scope is not None and asset.get("in_scope") is None:
            asset["in_scope"] = in_scope
        self._touch_record(asset, finding, obs_id)
        return asset

    def get_or_create_host_asset(self, hostname: str, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        host = _norm_host(hostname)
        return self._get_or_create_asset(ASSET_HOSTNAME, _aid(ASSET_HOSTNAME, host), host, finding, obs_id,
                                          in_scope=is_in_scope(host, self.target))

    def get_or_create_ip_asset(self, ip: str, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        norm = _norm_ip(ip)
        return self._get_or_create_asset(ASSET_IP, _aid(ASSET_IP, norm), norm, finding, obs_id)

    def get_or_create_port_asset(self, ip: str, port: Any, protocol: str, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        norm_ip = _norm_ip(ip)
        aid = _aid(ASSET_PORT, norm_ip, port, protocol)
        return self._get_or_create_asset(ASSET_PORT, aid, {"ip": norm_ip, "port": port, "protocol": protocol}, finding, obs_id)

    def get_or_create_technology_asset(self, scope_key: str, technology: str, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        is_url = "://" in str(scope_key)
        key = _norm_url(scope_key) if is_url else _norm_host(scope_key)
        aid = _aid(ASSET_TECHNOLOGY, key, str(technology).strip().lower())
        # A technology is only ever observed on some host/URL; it inherits that
        # asset's scope so technology-triggered enumeration cannot be scheduled
        # against an out-of-scope host.
        in_scope = self._scope_of_url(key, self.target) if is_url else is_in_scope(key, self.target)
        return self._get_or_create_asset(ASSET_TECHNOLOGY, aid, {"scope": scope_key, "name": technology},
                                          finding, obs_id, in_scope=in_scope)

    def qualify_reference(self, reference: Any, host_hint: Optional[str] = None) -> str:
        """
        Host-qualify one endpoint/JavaScript/parameter reference before it
        becomes a graph identity.

        Producing modules legitimately emit both absolute URLs and bare paths:
        endpoint_discovery.py's JS/historical correlation records carry
        `"url": "/api/v1/users"`, and wayback_intel.py's parameter records
        carry `"endpoint": "/search"`. A bare path is not an identity — the
        same path under two different subdomains is two different endpoints —
        so an unqualified reference is resolved against the hostname the
        observation belongs to. When a matching endpoint already exists under
        a concrete scheme, that existing asset is reused so a path-only
        observation still correlates with the absolute-URL observation of the
        same endpoint instead of forking a near-duplicate asset.
        """
        raw = str(reference).strip()
        if not raw:
            return raw
        if _is_absolute_url(raw):
            return _norm_url(raw)
        host = _norm_host(host_hint) if host_hint else None
        if not host or _is_absolute_url(host) or "/" in host:
            return raw
        path = raw if raw.startswith("/") else "/" + raw
        candidates = [_norm_url(f"https://{host}{path}"), _norm_url(f"http://{host}{path}")]
        for candidate in candidates:
            if _aid(ASSET_ENDPOINT, candidate) in self.state["assets"]:
                return candidate
        return candidates[0]

    @staticmethod
    def _scope_of_url(url: Any, target: str) -> Optional[bool]:
        host = _hostname_of_url(url)
        return is_in_scope(host, target) if host else None

    def get_or_create_endpoint_asset(self, url_or_path: str, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        norm = _norm_url(url_or_path) if "://" in str(url_or_path) else str(url_or_path).strip()
        return self._get_or_create_asset(ASSET_ENDPOINT, _aid(ASSET_ENDPOINT, norm), norm, finding, obs_id,
                                          in_scope=self._scope_of_url(norm, self.target))

    def get_or_create_parameter_asset(self, endpoint_ref: str, location: str, name: str, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        # Must use the same normalization the endpoint asset itself uses, or
        # "HTTP://Example.com/a" and "http://example.com/a" produce one endpoint
        # asset but two parameter assets for the same parameter.
        endpoint_ref = _norm_url(endpoint_ref) if "://" in str(endpoint_ref) else str(endpoint_ref).strip()
        aid = _aid(ASSET_PARAMETER, endpoint_ref, location, name)
        return self._get_or_create_asset(ASSET_PARAMETER, aid, {"endpoint": endpoint_ref, "location": location, "name": name},
                                          finding, obs_id, in_scope=self._scope_of_url(endpoint_ref, self.target))

    def get_or_create_javascript_asset(self, js_url: str, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        norm = _norm_url(js_url)
        return self._get_or_create_asset(ASSET_JAVASCRIPT, _aid(ASSET_JAVASCRIPT, norm), norm, finding, obs_id,
                                          in_scope=self._scope_of_url(norm, self.target))

    def get_or_create_third_party_asset(self, hostname: str, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        host = _norm_host(hostname)
        return self._get_or_create_asset(ASSET_THIRD_PARTY, _aid(ASSET_THIRD_PARTY, host), host, finding, obs_id,
                                          in_scope=is_in_scope(host, self.target))

    def get_or_create_organization_asset(self, name: str, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        key = str(name).strip().lower()
        return self._get_or_create_asset(ASSET_ORGANIZATION, _aid(ASSET_ORGANIZATION, key), name, finding, obs_id)

    def get_or_create_finding_asset(self, finding_type: str, value: Any, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        aid = _aid(ASSET_FINDING, finding_type, _short_hash(value))
        return self._get_or_create_asset(ASSET_FINDING, aid, {"finding_type": finding_type, "detail": value}, finding, obs_id)

    def link(self, rel_type: str, from_id: str, to_id: str, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        rel_id = f"rel:{rel_type}:{from_id}->{to_id}"
        rel = self.state["relationships"].get(rel_id)
        if rel is None:
            rel = {"id": rel_id, "rel_type": rel_type, "from_asset": from_id, "to_asset": to_id}
            self.state["relationships"][rel_id] = rel
        self._touch_record(rel, finding, obs_id)
        return rel

    def relationships_for(self, asset_id: str) -> List[Dict[str, Any]]:
        return [r for r in self.state["relationships"].values() if r["from_asset"] == asset_id or r["to_asset"] == asset_id]

    # -- attribute storage with conflict preservation -----------------------

    def _set_attribute(self, asset: Dict[str, Any], key: str, value: Any, finding: Dict[str, Any], obs_id: str) -> None:
        """
        Record a single-valued attribute observation. If a different value
        was already recorded for this (asset, key) by any observation, the
        original value is preserved as-is and the disagreement is recorded
        as a conflict instead of being silently overwritten (context.md §8).
        """
        if value is None:
            return
        attrs = asset["attributes"]
        existing = attrs.get(key)
        if existing is None:
            attrs[key] = {
                "value": value, "source": finding["source"], "observation_id": obs_id,
                "confidence": finding["confidence"], "timestamp": finding["timestamp"],
                "sources": [finding["source"]], "has_conflict": False,
            }
            return
        if self._values_equal(existing["value"], value):
            sources = set(existing.get("sources", [existing.get("source")]))
            sources.add(finding["source"])
            existing["sources"] = sorted(sources)
            existing["timestamp"] = finding["timestamp"]
            existing["confidence"] = self._aggregate_confidence(
                [{"source": s, "confidence": finding["confidence"]} for s in sources]
                if existing["confidence"] == finding["confidence"] else
                [{"source": existing["source"], "confidence": existing["confidence"]},
                 {"source": finding["source"], "confidence": finding["confidence"]}]
            )
            return
        # Disagreement: preserve both, never overwrite.
        self._record_conflict(asset, key, existing, value, finding, obs_id)
        existing["has_conflict"] = True

    @staticmethod
    def _values_equal(a: Any, b: Any) -> bool:
        try:
            if isinstance(a, list) and isinstance(b, list):
                return sorted(map(str, a)) == sorted(map(str, b))
            return a == b
        except Exception:
            return str(a) == str(b)

    def _record_conflict(self, asset: Dict[str, Any], attribute: str, existing_attr: Dict[str, Any],
                          new_value: Any, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        conflict_id = f"conflict:{asset['id']}:{attribute}"
        conflict = self.state["conflicts"].get(conflict_id)
        if conflict is None:
            conflict = {
                "id": conflict_id, "asset_id": asset["id"], "attribute": attribute,
                "status": "unresolved", "first_seen": finding["timestamp"],
                "observations": [
                    {"value": existing_attr["value"], "source": existing_attr["source"],
                     "observation_id": existing_attr["observation_id"], "timestamp": existing_attr["timestamp"]},
                ],
            }
            self.state["conflicts"][conflict_id] = conflict
        entry = {"value": new_value, "source": finding["source"], "observation_id": obs_id, "timestamp": finding["timestamp"]}
        if entry not in conflict["observations"]:
            conflict["observations"].append(entry)
            # A genuinely flapping attribute (round-robin DNS, a load balancer
            # answering with different banners) would otherwise grow this list
            # without bound across a long run. The originally-recorded
            # observation is the one a conflict is defined against, so it is
            # always kept; the newest ones are kept after it.
            if len(conflict["observations"]) > 50:
                conflict["observations"] = conflict["observations"][:1] + conflict["observations"][-49:]
                conflict["truncated"] = True
        conflict["last_seen"] = finding["timestamp"]
        asset["attributes"].setdefault(attribute, existing_attr)["conflict_id"] = conflict_id
        return conflict

    def get_conflicts(self, asset_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conflicts = list(self.state["conflicts"].values())
        if asset_id:
            conflicts = [c for c in conflicts if c["asset_id"] == asset_id]
        return conflicts

    # =======================================================================
    # Discovery-state transitions
    # =======================================================================

    def set_asset_state(self, asset_id: str, new_state: str, reason: Optional[str] = None) -> Dict[str, Any]:
        if new_state not in VALID_STATES:
            raise ValueError(f"Invalid discovery state {new_state!r}; must be one of {sorted(VALID_STATES)}")
        with self._lock:
            asset = self.state["assets"].get(asset_id)
            if asset is None:
                raise KeyError(f"No such asset: {asset_id!r}")
            asset["state"] = new_state
            asset.setdefault("state_history", []).append({"state": new_state, "at": _now(), "reason": reason})
            self._maybe_save()
            return asset

    # =======================================================================
    # Reconnaissance opportunities (adaptive discovery, for the orchestrator)
    # =======================================================================

    def _add_opportunity(self, opportunity_type: str, asset: Dict[str, Any], suggested_modules: List[str],
                          reason: str, priority: str, finding: Dict[str, Any], obs_id: str) -> Optional[Dict[str, Any]]:
        """
        Publish one reconnaissance opportunity for the orchestrator.

        Two invariants are enforced here rather than in each caller:

        * Strict scope (context.md §16, design principle 10). An opportunity is
          an instruction to point another module at an asset, so it is never
          emitted for an asset known to be outside the authorized target scope
          — a JavaScript file may reference a third-party API, and correlating
          that reference is in scope while probing it is not. The suppression
          is recorded on the asset rather than silently dropped.
        * Opportunities are not resurrected. Once the orchestrator has consumed
          an opportunity, a later observation of the same asset must not flip it
          back to pending, or the orchestrator re-runs the same work every time
          fresh evidence arrives for that asset.
        """
        if asset.get("in_scope") is False:
            suppressed = asset.setdefault("suppressed_opportunities", {})
            suppressed[opportunity_type] = {
                "reason": reason, "suggested_modules": suggested_modules,
                "suppressed_because": "asset is outside the authorized target scope",
                "observation_id": obs_id, "at": finding["timestamp"],
            }
            return None

        opp_id = f"opp:{asset['id']}:{opportunity_type}"
        opp = self.state["opportunities"].get(opp_id)
        if opp is not None:
            opp["updated_at"] = finding["timestamp"]
            if obs_id not in opp.setdefault("observation_ids", []):
                opp["observation_ids"].append(obs_id)
            return opp
        opp = {
            "id": opp_id, "opportunity_type": opportunity_type, "target_asset_id": asset["id"],
            "target_value": asset["value"], "suggested_modules": suggested_modules, "reason": reason,
            "priority": priority, "status": "pending", "created_at": finding["timestamp"],
            "updated_at": finding["timestamp"], "consumed_at": None, "observation_ids": [obs_id],
        }
        self.state["opportunities"][opp_id] = opp
        return opp

    def get_pending_opportunities(self) -> List[Dict[str, Any]]:
        return [o for o in self.state["opportunities"].values() if o["status"] == "pending"]

    def consume_opportunity(self, opportunity_id: str) -> Dict[str, Any]:
        with self._lock:
            opp = self.state["opportunities"].get(opportunity_id)
            if opp is None:
                raise KeyError(f"No such opportunity: {opportunity_id!r}")
            opp["status"] = "consumed"
            opp["consumed_at"] = _now()
            self._maybe_save()
            return opp

    # =======================================================================
    # Subject resolution (used by negative-result memory + generic fallback)
    # =======================================================================

    def _resolve_subject_asset(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        """
        Resolve the asset a finding is *about*, and attach it to the asset that
        owns it.

        The owning link matters as much as the subject itself: context.md §7
        defines one connected graph (Domain -> Subdomain -> IP -> Port -> ... ->
        URL -> ... -> Finding), and §9's attack-surface paths are reconstructed
        by walking it from the target's root hostname. A subject minted here
        without its parent edge is unreachable from the root, so
        explain_asset_path() returns nothing for it and
        build_attack_surface_tree() omits it entirely — the finding is stored
        but drops out of every relationship-based view of the surface.
        """
        value = finding.get("value")
        target = finding.get("target") or self.target
        if isinstance(value, dict):
            if value.get("hostname"):
                return self.get_or_create_host_asset(value["hostname"], finding, obs_id)
            if value.get("subdomain"):
                return self.get_or_create_host_asset(value["subdomain"], finding, obs_id)
            for url_key in ("url", "connect_url"):
                if value.get(url_key):
                    return self._subject_endpoint(value[url_key], finding, obs_id)
            if value.get("ip") and value.get("port"):
                ip_asset = self.get_or_create_ip_asset(value["ip"], finding, obs_id)
                port_asset = self.get_or_create_port_asset(
                    value["ip"], value["port"], value.get("protocol", "tcp"), finding, obs_id)
                self.link(REL_IP_TO_SERVICE, ip_asset["id"], port_asset["id"], finding, obs_id)
                return port_asset
            if value.get("ip"):
                return self.get_or_create_ip_asset(value["ip"], finding, obs_id)
            if value.get("technology"):
                host_asset = self.get_or_create_host_asset(target, finding, obs_id)
                tech_asset = self.get_or_create_technology_asset(target, value["technology"], finding, obs_id)
                self.link(REL_ASSET_TO_TECHNOLOGY, host_asset["id"], tech_asset["id"], finding, obs_id)
                return tech_asset
        return self.get_or_create_host_asset(target, finding, obs_id)

    def _subject_endpoint(self, url: Any, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        """Create the endpoint asset for a finding's URL and link it to its owning hostname."""
        host = _hostname_of_url(url) or finding.get("target") or self.target
        qualified = self.qualify_reference(url, host)
        endpoint_asset = self.get_or_create_endpoint_asset(qualified, finding, obs_id)
        if host:
            host_asset = self.get_or_create_host_asset(host, finding, obs_id)
            if host_asset["id"] != endpoint_asset["id"]:
                self.link(REL_ASSET_TO_ENDPOINT, host_asset["id"], endpoint_asset["id"], finding, obs_id)
        return endpoint_asset

    # =======================================================================
    # Dispatch table
    # =======================================================================

    def _resolve_handler(self, finding_type: str) -> Callable[[Dict[str, Any], str], Dict[str, Any]]:
        handler = self._dispatch.get(finding_type)
        if handler is not None:
            return handler
        return self._h_finding_generic

    def _build_dispatch(self) -> Dict[str, Callable[[Dict[str, Any], str], Dict[str, Any]]]:
        d: Dict[str, Callable[[Dict[str, Any], str], Dict[str, Any]]] = {}
        d["dns_record"] = self._h_dns_record
        d["whois"] = self._h_whois
        d["tls_certificate"] = self._h_tls_certificate
        d["tls_certificate_analysis"] = self._h_tls_certificate
        d["tls_san"] = self._h_tls_san
        d["asn"] = self._h_asn
        d["email_security"] = self._h_email_security
        for t in ("open_tcp_port", "open_udp_port", "open_or_filtered_udp_port"):
            d[t] = self._h_open_port
        for t in ("banner", "os_fingerprint", "ssh_fingerprint", "smtp_enumeration",
                  "snmp_exposure", "ftp_anonymous_access", "ipmi_exposure", "db_exposure"):
            d[t] = self._h_port_finding
        d["service_identification"] = self._h_service_identification
        d["service_conflict"] = self._h_service_conflict
        d["vhost_discovered"] = self._h_vhost_discovered
        d["tech_fingerprint_detected"] = self._h_tech_detected
        d["waf_detected"] = self._h_waf_detected
        for t in ("endpoint_discovered", "crawled_url", "historical_endpoint_reference"):
            d[t] = self._h_endpoint
        for t in ("endpoint_parameter", "crawler_parameter", "historical_parameter"):
            d[t] = self._h_parameter
        d["crawled_form"] = self._h_form
        for t in ("javascript_endpoint_reference", "js_analyzer_endpoint_reference"):
            d[t] = self._h_js_endpoint_ref
        d["js_analyzer_external_service_reference"] = self._h_js_third_party
        d["supply_chain_subdomain_third_party_dns"] = self._h_supply_chain_third_party_dns
        d["supply_chain_third_party_js_resource"] = self._h_supply_chain_js_resource
        d["passive_intel_host"] = self._h_passive_intel_host
        d["passive_intel_service"] = self._h_passive_intel_service
        for t in ("exposure_finding", "error_page_intelligence", "code_leak_exposure", "code_leak_repository",
                  "vulnerability_intelligence", "cloud_resource_finding", "cross_host_port_pattern"):
            d[t] = self._h_finding_generic
        return d

    # =======================================================================
    # DNS / infra handlers
    # =======================================================================

    @staticmethod
    def _as_str_list(value: Any) -> List[str]:
        """
        Coerce a record/SAN/vendor payload into a list of non-empty strings.

        A bare string must never be iterated character by character (that would
        mint one phantom asset per character), and a dict/None payload must not
        abort the whole observation.
        """
        if value is None:
            return []
        if isinstance(value, str):
            return [value.strip()] if value.strip() else []
        if isinstance(value, dict):
            return []
        if isinstance(value, (list, tuple, set)):
            return [str(v).strip() for v in value if isinstance(v, (str, int, float)) and str(v).strip()]
        return []

    def _h_dns_record(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        rtype = value.get("record_type")
        records = self._as_str_list(value.get("records"))
        host_asset = self.get_or_create_host_asset(finding["target"], finding, obs_id)

        if rtype in ("A", "AAAA"):
            for ip in records:
                ip_asset = self.get_or_create_ip_asset(ip, finding, obs_id)
                self.link(REL_HOSTNAME_TO_IP, host_asset["id"], ip_asset["id"], finding, obs_id)
            self._set_attribute(host_asset, f"dns_{rtype.lower()}", sorted(records), finding, obs_id)
        elif rtype == "CNAME":
            for cname_target in records:
                cname_asset = self.get_or_create_host_asset(cname_target, finding, obs_id)
                self.link(REL_HOSTNAME_TO_CNAME, host_asset["id"], cname_asset["id"], finding, obs_id)
            self._set_attribute(host_asset, "cname_target", records[0] if records else None, finding, obs_id)
            if records:
                self._reevaluate_takeover(host_asset, records, finding, obs_id)
        elif rtype in ("MX", "TXT", "NS", "SOA"):
            self._set_attribute(host_asset, f"dns_{rtype.lower()}", sorted(records), finding, obs_id)

        self._maybe_reevaluate_takeover_for(finding, obs_id)
        return {"asset_id": host_asset["id"]}

    def _h_whois(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        host_asset = self.get_or_create_host_asset(finding["target"], finding, obs_id)
        for key in ("registrar", "creation_date", "expiration_date", "updated_date", "name_servers", "status", "country"):
            if key in value:
                self._set_attribute(host_asset, f"whois_{key}", value[key], finding, obs_id)
        org = value.get("org")
        if org:
            org_name = org[0] if isinstance(org, list) and org else org
            if org_name:
                org_asset = self.get_or_create_organization_asset(str(org_name), finding, obs_id)
                self.link(REL_DOMAIN_TO_ORGANIZATION, host_asset["id"], org_asset["id"], finding, obs_id)
        return {"asset_id": host_asset["id"]}

    @staticmethod
    def _extract_sans(value: Dict[str, Any], cert: Dict[str, Any]) -> List[str]:
        """
        SAN lists arrive in two real shapes: passive_recon.py's `tls_certificate`
        value is the flat parsed certificate with `sans` as a list, while
        ssl_analyzer.py's `tls_certificate_analysis` value nests the certificate
        and carries `sans` as extract_sans()'s dict {"sans": [...], "count": n}.
        Iterating the dict form directly would create hostname assets literally
        named "sans" and "count".
        """
        for candidate in (cert.get("sans"), value.get("sans")):
            if isinstance(candidate, dict):
                candidate = candidate.get("sans")
            names = SurfaceMapper._as_str_list(candidate)
            if names:
                return names
        return []

    def _h_tls_certificate(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        if not isinstance(value, dict):
            return self._h_finding_generic(finding, obs_id)
        host = value.get("host") or value.get("sni_hostname") or finding["target"]
        host_asset = self.get_or_create_host_asset(host, finding, obs_id)

        # ssl_analyzer.py nests the parsed certificate under "certificate";
        # passive_recon.py's value *is* the parsed certificate. Treating only
        # the nested shape as valid silently dropped every subject/issuer/SAN
        # observation passive_recon.py produced.
        cert = value.get("certificate")
        if not isinstance(cert, dict):
            cert = value if ("subject" in value or "issuer" in value) else {}

        self._set_attribute(host_asset, "tls_cert_subject", cert.get("subject"), finding, obs_id)
        self._set_attribute(host_asset, "tls_cert_issuer", cert.get("issuer"), finding, obs_id)
        for san in self._extract_sans(value, cert):
            san_asset = self.get_or_create_host_asset(san, finding, obs_id)
            self.link(REL_CERTIFICATE_SAN, host_asset["id"], san_asset["id"], finding, obs_id)

        if "self_signed" in value:
            # ssl_analyzer.py's detect_self_signed() returns a dict; storing it
            # whole makes "not self-signed" a truthy value downstream.
            self_signed = value["self_signed"]
            if isinstance(self_signed, dict):
                self_signed = self_signed.get("self_signed")
            self._set_attribute(host_asset, "tls_self_signed", self_signed, finding, obs_id)
        if "tls_version" in value:
            tv = value["tls_version"]
            self._set_attribute(host_asset, "tls_version", tv.get("version") if isinstance(tv, dict) else tv, finding, obs_id)
        return {"asset_id": host_asset["id"]}

    def _h_tls_san(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        observing_host = self.get_or_create_host_asset(finding["target"], finding, obs_id)
        san = finding["value"]
        if not isinstance(san, str):
            return self._h_finding_generic(finding, obs_id)
        san_asset = self.get_or_create_host_asset(san, finding, obs_id)
        self.link(REL_CERTIFICATE_SAN, observing_host["id"], san_asset["id"], finding, obs_id)
        if san_asset.get("in_scope") and len(san_asset.get("observation_ids", [])) <= 1:
            self._add_opportunity(
                "new_hostname_via_cert_san", san_asset, ["passive_recon.py", "ssl_analyzer.py", "http_analyzer.py"],
                f"New in-scope hostname {san_asset['value']!r} discovered via certificate SAN on {observing_host['value']!r}",
                "MEDIUM", finding, obs_id,
            )
        return {"asset_id": san_asset["id"]}

    def _h_asn(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        ip_asset = self.get_or_create_ip_asset(value.get("ip", finding["target"]), finding, obs_id)
        for key in ("asn", "as_name", "bgp_prefix", "country", "registry"):
            if value.get(key) is not None:
                self._set_attribute(ip_asset, key, value[key], finding, obs_id)
        return {"asset_id": ip_asset["id"]}

    def _h_email_security(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        host_asset = self.get_or_create_host_asset(finding["target"], finding, obs_id)
        value = finding["value"]
        for key in ("spf", "dmarc", "dkim", "mx"):
            if key in value and isinstance(value[key], dict):
                self._set_attribute(host_asset, f"email_{key}_status", value[key].get("status"), finding, obs_id)
        return {"asset_id": host_asset["id"]}

    # =======================================================================
    # Network / service handlers
    # =======================================================================

    _WEB_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888, 3000, 5000}

    def _h_open_port(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        ip_asset = self.get_or_create_ip_asset(value["ip"], finding, obs_id)
        protocol = value.get("protocol", "tcp")
        port_asset = self.get_or_create_port_asset(value["ip"], value["port"], protocol, finding, obs_id)
        self.link(REL_IP_TO_SERVICE, ip_asset["id"], port_asset["id"], finding, obs_id)
        self._set_attribute(port_asset, "status", "open", finding, obs_id)

        already_raised = port_asset["attributes"].get("recon_opportunity_raised", {}).get("value")
        if not already_raised:
            try:
                port_num = int(value["port"])
            except (TypeError, ValueError):
                port_num = None
            if port_num in self._WEB_PORTS:
                modules = ["tech_fingerprint.py", "http_analyzer.py", "vhost_scanner.py", "ssl_analyzer.py"]
                priority = "HIGH"
            else:
                modules = ["active_recon.py"]
                priority = "LOW"
            self._add_opportunity(
                "open_port_followup", port_asset, modules,
                f"Newly discovered open {protocol} port {value['port']} on {value['ip']}",
                priority, finding, obs_id,
            )
            self._set_attribute(port_asset, "recon_opportunity_raised", True, finding, obs_id)
        return {"asset_id": port_asset["id"]}

    def _h_port_finding(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        ip = value.get("ip", finding["target"])
        port = value.get("port")
        ip_asset = self.get_or_create_ip_asset(ip, finding, obs_id)
        parent = ip_asset
        if port is not None:
            port_asset = self.get_or_create_port_asset(ip, port, value.get("protocol", "tcp"), finding, obs_id)
            self.link(REL_IP_TO_SERVICE, ip_asset["id"], port_asset["id"], finding, obs_id)
            parent = port_asset
        finding_asset = self.get_or_create_finding_asset(finding["type"], value, finding, obs_id)
        self.link(REL_ASSET_TO_FINDING, parent["id"], finding_asset["id"], finding, obs_id)
        return {"asset_id": parent["id"], "finding_asset_id": finding_asset["id"]}

    def _h_service_identification(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        ip_asset = self.get_or_create_ip_asset(value["ip"], finding, obs_id)
        port_asset = self.get_or_create_port_asset(value["ip"], value["port"], value.get("protocol", "tcp"), finding, obs_id)
        self.link(REL_IP_TO_SERVICE, ip_asset["id"], port_asset["id"], finding, obs_id)
        if value.get("service"):
            self._set_attribute(port_asset, "service", value["service"], finding, obs_id)
        return {"asset_id": port_asset["id"]}

    def _h_service_conflict(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        """active_recon.py already detected disagreement between port-heuristic and banner-signature; preserve it explicitly."""
        value = finding["value"]
        ip_asset = self.get_or_create_ip_asset(value["ip"], finding, obs_id)
        port_asset = self.get_or_create_port_asset(value["ip"], value["port"], value.get("protocol", "tcp"), finding, obs_id)
        self.link(REL_IP_TO_SERVICE, ip_asset["id"], port_asset["id"], finding, obs_id)

        attrs = port_asset["attributes"]
        if "service" not in attrs:
            attrs["service"] = {
                "value": value.get("port_guess"), "source": f"{finding['source']}:port_heuristic",
                "observation_id": obs_id, "confidence": CONFIDENCE_LOW, "timestamp": finding["timestamp"],
                "sources": [finding["source"]], "has_conflict": True,
            }
        banner_finding = dict(finding)
        banner_finding["source"] = f"{finding['source']}:banner_signature"
        self._record_conflict(port_asset, "service", attrs["service"], value.get("banner_guess"), banner_finding, obs_id)
        attrs["service"]["has_conflict"] = True
        return {"asset_id": port_asset["id"]}

    # =======================================================================
    # Vhost handler
    # =======================================================================

    def _h_vhost_discovered(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        ip_asset = self.get_or_create_ip_asset(value["ip"], finding, obs_id)
        vhost_asset = self.get_or_create_host_asset(value["hostname"], finding, obs_id)
        is_new = len(vhost_asset.get("observation_ids", [])) <= 1
        self.link(REL_IP_TO_VHOST, ip_asset["id"], vhost_asset["id"], finding, obs_id)
        self._set_attribute(vhost_asset, "discovered_via_vhost_scan", True, finding, obs_id)
        if is_new:
            connect_url = value.get("connect_url", f"http://{value['ip']}:{value.get('port', 80)}/")
            self._add_opportunity(
                "vhost_web_followup", vhost_asset, ["http_analyzer.py", "tech_fingerprint.py", "endpoint_discovery.py"],
                f"New virtual host {value['hostname']!r} discovered on {value['ip']}:{value.get('port')} "
                f"(Host header probe, {connect_url})",
                "MEDIUM", finding, obs_id,
            )
        return {"asset_id": vhost_asset["id"]}

    # =======================================================================
    # Technology handlers
    # =======================================================================

    _TECH_TRIGGER_MODULES = {
        "wordpress": (["endpoint_discovery.py"], "WordPress detected — WordPress-aware wordlist enumeration is actionable"),
        "drupal": (["endpoint_discovery.py"], "Drupal detected — CMS-specific enumeration is actionable"),
        "joomla": (["endpoint_discovery.py"], "Joomla detected — CMS-specific enumeration is actionable"),
        "magento": (["endpoint_discovery.py"], "Magento detected — CMS-specific enumeration is actionable"),
        "laravel": (["endpoint_discovery.py"], "Laravel detected — framework-aware path list is actionable"),
        "django": (["endpoint_discovery.py"], "Django detected — framework-aware path list is actionable"),
    }

    def _h_tech_detected(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        scope_key = value.get("url") or finding["target"]
        parent_asset = (self.get_or_create_endpoint_asset(scope_key, finding, obs_id) if "://" in str(scope_key)
                         else self.get_or_create_host_asset(scope_key, finding, obs_id))
        tech_asset = self.get_or_create_technology_asset(scope_key, value["technology"], finding, obs_id)
        self.link(REL_ASSET_TO_TECHNOLOGY, parent_asset["id"], tech_asset["id"], finding, obs_id)
        self._set_attribute(tech_asset, "category", value.get("category"), finding, obs_id)
        if value.get("version"):
            self._set_attribute(tech_asset, "version", value["version"], finding, obs_id)

        trigger = self._TECH_TRIGGER_MODULES.get(str(value["technology"]).strip().lower())
        if trigger and len(tech_asset.get("observation_ids", [])) <= 1:
            modules, reason = trigger
            self._add_opportunity("technology_specific_enumeration", tech_asset, modules,
                                   f"{reason} on {scope_key!r}", "MEDIUM", finding, obs_id)
        return {"asset_id": tech_asset["id"]}

    def _h_waf_detected(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        url = finding.get("metadata", {}).get("url") or finding["target"]
        parent_asset = (self.get_or_create_endpoint_asset(url, finding, obs_id) if "://" in str(url)
                         else self.get_or_create_host_asset(url, finding, obs_id))
        # http_analyzer.detect_waf() returns {"detected": bool, "vendors":
        # [{"vendor": ..., "evidence": [...]}, ...]} — a list, not a mapping.
        # Only handling the mapping form dropped every WAF detection silently.
        raw_vendors = value.get("vendors") if isinstance(value, dict) else None
        if isinstance(raw_vendors, dict):
            vendor_names = [str(name) for name in raw_vendors if str(name).strip()]
        elif isinstance(raw_vendors, list):
            vendor_names = [
                str(v.get("vendor")) if isinstance(v, dict) else str(v)
                for v in raw_vendors
                if (v.get("vendor") if isinstance(v, dict) else v)
            ]
        else:
            vendor_names = []

        last_tech_id = parent_asset["id"]
        for vendor_name in vendor_names:
            tech_asset = self.get_or_create_technology_asset(url, vendor_name, finding, obs_id)
            self.link(REL_ASSET_TO_TECHNOLOGY, parent_asset["id"], tech_asset["id"], finding, obs_id)
            self._set_attribute(tech_asset, "category", "waf", finding, obs_id)
            last_tech_id = tech_asset["id"]
        return {"asset_id": last_tech_id}

    # =======================================================================
    # Endpoint / parameter / form handlers
    # =======================================================================

    def _h_endpoint(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        if not isinstance(value, dict):
            return self._h_finding_generic(finding, obs_id)
        url = value.get("url") or value.get("path")
        if not url:
            return self._h_finding_generic(finding, obs_id)
        host = _hostname_of_url(url) or finding["target"]
        parent_asset = self.get_or_create_host_asset(host, finding, obs_id)
        # endpoint_discovery.py's historical/JS correlation records carry a bare
        # path in "url"; without host qualification "/search" observed on two
        # different subdomains collapses into a single endpoint asset.
        endpoint_asset = self.get_or_create_endpoint_asset(self.qualify_reference(url, host), finding, obs_id)
        self.link(REL_ASSET_TO_ENDPOINT, parent_asset["id"], endpoint_asset["id"], finding, obs_id)
        for key in ("method", "status_code", "content_type", "category", "discovery_type"):
            if value.get(key) is not None:
                self._set_attribute(endpoint_asset, key, value[key], finding, obs_id)
        if finding["type"] == "historical_endpoint_reference":
            self._set_attribute(endpoint_asset, "historical", True, finding, obs_id)
        return {"asset_id": endpoint_asset["id"]}

    def _h_parameter(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        if not isinstance(value, dict):
            return self._h_finding_generic(finding, obs_id)
        name = value.get("name")
        if not name:
            return self._h_finding_generic(finding, obs_id)
        raw_ref = value.get("endpoint") or value.get("url") or finding["target"]
        # wayback_intel.py emits {"endpoint": "/search", "url": "https://shop..."}:
        # the path names the endpoint, the sample URL names its host. Using the
        # bare path as the identity merged every subdomain's "/search" into one
        # endpoint and one parameter asset.
        host_hint = _hostname_of_url(raw_ref) or _hostname_of_url(value.get("url")) or finding["target"]
        endpoint_ref = self.qualify_reference(raw_ref, host_hint)
        endpoint_asset = self.get_or_create_endpoint_asset(endpoint_ref, finding, obs_id)
        location = value.get("location") or "unknown"
        param_asset = self.get_or_create_parameter_asset(endpoint_ref, location, name, finding, obs_id)
        self.link(REL_ENDPOINT_TO_PARAMETER, endpoint_asset["id"], param_asset["id"], finding, obs_id)
        for key in ("method", "data_type", "source"):
            if value.get(key) is not None:
                self._set_attribute(param_asset, key, value[key], finding, obs_id)
        return {"asset_id": param_asset["id"]}

    def _h_form(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        page_url = value.get("resolved_action") or value.get("action") or finding.get("metadata", {}).get("source_page") or finding["target"]
        host = _hostname_of_url(page_url) or finding["target"]
        parent_asset = self.get_or_create_host_asset(host, finding, obs_id)
        form_endpoint = self.get_or_create_endpoint_asset(page_url, finding, obs_id)
        self.link(REL_ASSET_TO_ENDPOINT, parent_asset["id"], form_endpoint["id"], finding, obs_id)
        category = value.get("classification") or finding.get("metadata", {}).get("category")
        self._set_attribute(form_endpoint, "form_category", category, finding, obs_id)
        # crawler.classify_form() labels this category "file_upload"; matching
        # only "upload" meant the HIGH-priority file-upload surface required by
        # context.md §10 item 12 was never raised.
        if category in ("file_upload", "upload"):
            self._set_attribute(form_endpoint, "file_upload_surface", True, finding, obs_id)
            self._add_opportunity(
                "file_upload_surface_review", form_endpoint, ["exposure_scan.py"],
                f"File-upload form discovered at {page_url!r} — high-priority manual/exposure review candidate",
                "HIGH", finding, obs_id,
            )
        return {"asset_id": form_endpoint["id"]}

    # =======================================================================
    # JavaScript handlers
    # =======================================================================

    def _h_js_endpoint_ref(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        if not isinstance(value, dict):
            return self._h_finding_generic(finding, obs_id)
        metadata = finding.get("metadata", {})
        js_url = metadata.get("parent_js_url") or value.get("js_url")
        parent_asset = self.get_or_create_host_asset(finding["target"], finding, obs_id)
        js_asset = self.get_or_create_javascript_asset(js_url, finding, obs_id) if js_url else parent_asset
        if js_url:
            self.link(REL_ASSET_TO_JAVASCRIPT, parent_asset["id"], js_asset["id"], finding, obs_id)

        ref_url = value.get("url")
        if not ref_url:
            return {"asset_id": js_asset["id"]}
        # A relative reference inside a script belongs to that script's origin,
        # not to the run's root target.
        ref_url = self.qualify_reference(ref_url, _hostname_of_url(js_url) or finding["target"])
        endpoint_asset = self.get_or_create_endpoint_asset(ref_url, finding, obs_id)
        is_new = len(endpoint_asset.get("observation_ids", [])) <= 1
        self.link(REL_JAVASCRIPT_TO_ENDPOINT, js_asset["id"], endpoint_asset["id"], finding, obs_id)
        if is_new:
            self._add_opportunity(
                "js_referenced_endpoint_verification", endpoint_asset, ["endpoint_discovery.py", "api_recon.py"],
                f"Endpoint {ref_url!r} referenced from JavaScript ({js_url!r}) — not yet independently verified",
                "MEDIUM", finding, obs_id,
            )
        return {"asset_id": endpoint_asset["id"]}

    def _h_js_third_party(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        host = value.get("host")
        if not host:
            return self._h_finding_generic(finding, obs_id)
        parent_asset = self.get_or_create_host_asset(finding["target"], finding, obs_id)
        tp_asset = self.get_or_create_third_party_asset(host, finding, obs_id)
        self.link(REL_SUBDOMAIN_TO_THIRD_PARTY, parent_asset["id"], tp_asset["id"], finding, obs_id)
        for key in ("vendor", "category"):
            if value.get(key):
                self._set_attribute(tp_asset, key, value[key], finding, obs_id)
        return {"asset_id": tp_asset["id"]}

    # =======================================================================
    # Supply-chain handlers
    # =======================================================================

    def _h_supply_chain_third_party_dns(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        subdomain = value.get("subdomain") or finding["target"]
        host_asset = self.get_or_create_host_asset(subdomain, finding, obs_id)
        chain = value.get("cname_chain") or []
        third_party_info = value.get("third_party") or {}
        result = {"asset_id": host_asset["id"]}
        if chain:
            final_host = chain[-1]
            tp_asset = self.get_or_create_third_party_asset(final_host, finding, obs_id)
            self.link(REL_SUBDOMAIN_TO_THIRD_PARTY, host_asset["id"], tp_asset["id"], finding, obs_id)
            if third_party_info.get("category"):
                self._set_attribute(tp_asset, "category", third_party_info["category"], finding, obs_id)
            result["third_party_asset_id"] = tp_asset["id"]
        self._reevaluate_takeover(host_asset, chain, finding, obs_id)
        return result

    def _h_supply_chain_js_resource(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        host = value.get("host")
        if not host:
            return self._h_finding_generic(finding, obs_id)
        source_asset_url = finding.get("metadata", {}).get("source_asset")
        parent_host = _hostname_of_url(source_asset_url) if source_asset_url else finding["target"]
        parent_asset = self.get_or_create_host_asset(parent_host, finding, obs_id)
        tp_asset = self.get_or_create_third_party_asset(host, finding, obs_id)
        self.link(REL_SUBDOMAIN_TO_THIRD_PARTY, parent_asset["id"], tp_asset["id"], finding, obs_id)
        classification = value.get("classification")
        if isinstance(classification, dict) and classification.get("category"):
            self._set_attribute(tp_asset, "category", classification["category"], finding, obs_id)
        return {"asset_id": tp_asset["id"]}

    # =======================================================================
    # passive_intel handlers
    # =======================================================================

    def _h_passive_intel_host(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        ip_asset = self.get_or_create_ip_asset(value.get("ip", finding["target"]), finding, obs_id)
        for key in ("sources", "in_scope", "discovered_via"):
            if value.get(key) is not None:
                self._set_attribute(ip_asset, f"passive_intel_{key}", value[key], finding, obs_id)
        return {"asset_id": ip_asset["id"]}

    def _h_passive_intel_service(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        value = finding["value"]
        ip = value.get("ip", finding["target"])
        port = value.get("port")
        ip_asset = self.get_or_create_ip_asset(ip, finding, obs_id)
        if port is None:
            return {"asset_id": ip_asset["id"]}
        port_asset = self.get_or_create_port_asset(ip, port, "tcp", finding, obs_id)
        self.link(REL_IP_TO_SERVICE, ip_asset["id"], port_asset["id"], finding, obs_id)
        for key in ("product", "version", "source"):
            if value.get(key):
                self._set_attribute(port_asset, f"passive_intel_{key}", value[key], finding, obs_id)
        return {"asset_id": port_asset["id"]}

    # =======================================================================
    # Generic finding handler (covers every other finding_type safely)
    # =======================================================================

    def _h_finding_generic(self, finding: Dict[str, Any], obs_id: str) -> Dict[str, Any]:
        subject = self._resolve_subject_asset(finding, obs_id)
        finding_asset = self.get_or_create_finding_asset(finding["type"], finding["value"], finding, obs_id)
        self.link(REL_ASSET_TO_FINDING, subject["id"], finding_asset["id"], finding, obs_id)
        self._maybe_reevaluate_takeover_for(finding, obs_id)
        return {"asset_id": subject["id"], "finding_asset_id": finding_asset["id"]}

    # =======================================================================
    # Subdomain takeover / dangling-CNAME correlation
    # =======================================================================

    def _maybe_reevaluate_takeover_for(self, finding: Dict[str, Any], obs_id: str) -> None:
        """If new evidence lands on a hostname that already has a recorded CNAME target, re-run the indicator check."""
        target_host = finding.get("target")
        if not target_host:
            return
        host_asset = self.state["assets"].get(_aid(ASSET_HOSTNAME, _norm_host(target_host)))
        if host_asset is None:
            return
        cname_attr = host_asset["attributes"].get("cname_target")
        if cname_attr and cname_attr.get("value"):
            self._reevaluate_takeover(host_asset, [cname_attr["value"]], finding, obs_id)

    def _related_asset_ids_for_takeover_scan(self, host_asset: Dict[str, Any]) -> List[str]:
        """host asset id plus every endpoint/javascript asset that belongs to this hostname (its URL's host matches)."""
        ids = [host_asset["id"]]
        host_value = host_asset["value"]
        for aid, asset in self.state["assets"].items():
            if asset["asset_type"] in (ASSET_ENDPOINT, ASSET_JAVASCRIPT) and _hostname_of_url(str(asset["value"])) == host_value:
                ids.append(aid)
        return ids

    def _reevaluate_takeover(self, host_asset: Dict[str, Any], cname_chain: List[str], finding: Dict[str, Any], obs_id: str) -> None:
        if not cname_chain:
            return
        final_target = cname_chain[-1]
        provider = _match_takeover_provider(final_target)

        fingerprint_hits: List[str] = []
        if provider:
            haystacks: List[str] = []
            for related_id in self._related_asset_ids_for_takeover_scan(host_asset):
                for rel in self.relationships_for(related_id):
                    for oid in rel.get("observation_ids", [])[-20:]:
                        obs = self.state["observations"].get(oid)
                        if obs:
                            haystacks.append(" ".join(obs.get("evidence", [])).lower())
                            haystacks.append(json.dumps(obs.get("value"), default=str).lower())
            for fp in provider["fingerprints"]:
                if any(fp in h for h in haystacks):
                    fingerprint_hits.append(fp)

        if provider and fingerprint_hits:
            level, note = CONFIDENCE_HIGH, (
                f"CNAME points to known takeover-susceptible provider {provider['provider']!r}, and a matching "
                f"'unclaimed resource' fingerprint was observed in content associated with this hostname"
            )
        elif provider:
            level, note = CONFIDENCE_MEDIUM, (
                f"CNAME points to known takeover-susceptible provider {provider['provider']!r}; no confirming "
                f"'unclaimed resource' page content observed yet — resolution status of the CNAME target was "
                f"not independently re-verified by surface_mapper.py (see reported limitations)"
            )
        else:
            level, note = CONFIDENCE_LOW, (
                "CNAME target does not match any known takeover-susceptible provider signature; "
                "no takeover/dangling-CNAME indicator raised"
            )

        indicator = {
            "cname_chain": cname_chain, "final_target": final_target,
            "provider": provider["provider"] if provider else None,
            "fingerprint_matches": fingerprint_hits, "indicator_level": level, "note": note,
            "evaluated_at": _now(), "confirmed": False,
        }
        history = host_asset["attributes"].setdefault("takeover_indicator_history", {"value": []})
        history["value"] = (history["value"] + [indicator])[-10:]
        host_asset["attributes"]["takeover_indicator"] = {
            "value": indicator, "source": MODULE_NAME, "observation_id": obs_id,
            "confidence": level, "timestamp": _now(), "sources": [MODULE_NAME], "has_conflict": False,
        }

        if provider:
            finding_asset = self.get_or_create_finding_asset(
                "subdomain_takeover_indicator",
                {"hostname": host_asset["value"], "final_target": final_target, "provider": provider["provider"]},
                finding, obs_id,
            )
            self.link(REL_ASSET_TO_FINDING, host_asset["id"], finding_asset["id"], finding, obs_id)
            if level in (CONFIDENCE_MEDIUM, CONFIDENCE_HIGH):
                self._add_opportunity(
                    "subdomain_takeover_manual_verification", host_asset, [],
                    f"Possible subdomain-takeover indicator on {host_asset['value']!r}: CNAME -> {final_target!r} "
                    f"({provider['provider']}). Indicator only, not confirmed — requires manual verification. "
                    f"Do not claim/interact with the referenced third-party resource.",
                    "HIGH" if level == CONFIDENCE_HIGH else "MEDIUM", finding, obs_id,
                )

    # =======================================================================
    # Attack-surface path construction
    # =======================================================================

    def explain_asset_path(self, asset_id: str, max_hops: int = 25) -> List[Dict[str, Any]]:
        """
        Reconstruct one discovery chain from the target's root hostname to
        `asset_id`, via BFS over relationships (context.md §9 example: domain
        -> subdomain (via cert SAN) -> endpoint -> parameter -> ...).
        Returns an ordered list of hops, each annotated with the
        relationship that produced it and its contributing module(s).
        """
        root_id = _aid(ASSET_HOSTNAME, self.target)
        if asset_id == root_id or root_id not in self.state["assets"]:
            asset = self.state["assets"].get(asset_id)
            return [{"asset_id": asset_id, "asset_type": asset.get("asset_type") if asset else None,
                     "value": asset.get("value") if asset else None, "via": None}] if asset else []

        parents: Dict[str, Tuple[str, Dict[str, Any]]] = {}
        visited = {root_id}
        queue: List[str] = [root_id]
        found = asset_id == root_id
        while queue and not found:
            current = queue.pop(0)
            for rel in self.relationships_for(current):
                nxt = rel["to_asset"] if rel["from_asset"] == current else (
                    rel["from_asset"] if rel["to_asset"] == current else None)
                if nxt is None or nxt in visited:
                    continue
                visited.add(nxt)
                parents[nxt] = (current, rel)
                if nxt == asset_id:
                    found = True
                    break
                queue.append(nxt)

        if asset_id not in parents and asset_id != root_id:
            return []

        chain: List[Tuple[str, Optional[Dict[str, Any]]]] = []
        node = asset_id
        truncated = False
        while node != root_id:
            parent, rel = parents[node]
            chain.append((node, rel))
            node = parent
            if node != root_id and len(chain) >= max_hops:
                # Stop at the ancestor actually reached. Appending root_id here
                # would claim a direct root -> node hop that does not exist.
                truncated = True
                break
        chain.append((node, None))
        chain.reverse()

        path = []
        for index, (node_id, rel) in enumerate(chain):
            asset = self.state["assets"].get(node_id, {})
            hop = {
                "asset_id": node_id, "asset_type": asset.get("asset_type"), "value": asset.get("value"),
                "via": ({"relationship_type": rel["rel_type"], "sources": rel.get("sources", []),
                         "evidence": rel.get("evidence", rel.get("_contributions", []))} if rel else None),
            }
            if truncated and index == 0:
                hop["truncated"] = True
                hop["note"] = f"path truncated at max_hops={max_hops}; this is not the target root hostname"
            path.append(hop)
        return path

    def build_attack_surface_tree(self, root_id: Optional[str] = None, max_depth: int = 8) -> Dict[str, Any]:
        """Full outward tree of everything reachable from `root_id` (defaults to the target's root hostname)."""
        root_id = root_id or _aid(ASSET_HOSTNAME, self.target)
        if root_id not in self.state["assets"]:
            return {}

        def _node(asset_id: str, visited: set, depth: int) -> Dict[str, Any]:
            asset = self.state["assets"][asset_id]
            out = {"asset_id": asset_id, "asset_type": asset["asset_type"], "value": asset["value"],
                   "state": asset["state"], "confidence": asset.get("confidence"), "children": []}
            if depth >= max_depth:
                return out
            for rel in self.relationships_for(asset_id):
                if rel["from_asset"] != asset_id:
                    continue
                child_id = rel["to_asset"]
                if child_id in visited or child_id not in self.state["assets"]:
                    continue
                visited.add(child_id)
                child = _node(child_id, visited, depth + 1)
                child["via_relationship"] = rel["rel_type"]
                out["children"].append(child)
            return out

        return _node(root_id, {root_id}, 0)

    # =======================================================================
    # Queries / summary
    # =======================================================================

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        return self.state["assets"].get(asset_id)

    def get_evidence(self, asset_id: str) -> List[Dict[str, Any]]:
        asset = self.state["assets"].get(asset_id)
        if not asset:
            return []
        return [self.state["observations"][oid] for oid in asset.get("observation_ids", []) if oid in self.state["observations"]]

    def summary(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for a in self.state["assets"].values():
            by_type[a["asset_type"]] = by_type.get(a["asset_type"], 0) + 1
        return {
            "target": self.target,
            "observations": len(self.state["observations"]),
            "assets": len(self.state["assets"]),
            "assets_by_type": by_type,
            "relationships": len(self.state["relationships"]),
            "conflicts": len(self.state["conflicts"]),
            "negative_results": len(self.state["negative_results"]),
            "check_states": len(self.state["check_states"]),
            "pending_opportunities": len(self.get_pending_opportunities()),
            "ingestion_errors": len(self.state["ingestion_errors"]),
        }


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="surface_mapper.py",
        description="ReconHound Module 6 — central asset graph / correlation (standalone test entry point).",
    )
    parser.add_argument("--target", required=True, help="Target domain, e.g. example.com")
    parser.add_argument("--output-dir", default="output", help="Directory containing pending_assets.json")
    args = parser.parse_args()

    mapper = SurfaceMapper(target=args.target, output_dir=args.output_dir)
    result = mapper.ingest_pending_assets_file()
    print(json.dumps({"ingest_result": result, "summary": mapper.summary()}, indent=2, default=str))


if __name__ == "__main__":
    _main()
