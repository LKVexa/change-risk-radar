"""Deterministic advisory change-risk analysis. No network or write effects."""
from __future__ import annotations
from bisect import bisect_right
import copy
from dataclasses import dataclass
import hashlib
import json
import math
import statistics
from types import MappingProxyType

VERSION = "0.1.2a1"
MAX_RECORDS = 10000
MAX_JSON_BYTES = 16 * 1024 * 1024
REQUIRED_EVENT_FIELDS = {"service", "kind", "version", "target_env", "applied_at"}
DRIVER_WEIGHTS = MappingProxyType({"deviation_pressure": 0.5, "incident_similarity": 0.3,
                                  "blast_radius": 0.2})

def _number(value, name, *, minimum=-1e100, maximum=1e100):
    if type(value) not in (int, float) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be a finite number within its supported range")
    return float(value)

def _label(value, name):
    if type(value) is not str or not value.strip() or len(value) > 512:
        raise ValueError(f"{name} must be a nonempty bounded string")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ValueError(f"{name} must be valid Unicode") from None
    if any(ord(c) < 32 for c in value):
        raise ValueError(f"{name} cannot contain control characters")
    return value

def _json_snapshot(value):
    try:
        serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(serialized) > MAX_JSON_BYTES:
            raise ValueError("input exceeds JSON size limit")
        return json.loads(serialized)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("input must be bounded, finite JSON data") from exc

def _records(values, name):
    if type(values) is not list or len(values) > MAX_RECORDS:
        raise ValueError(f"{name} must be a list of at most {MAX_RECORDS} records")
    if not all(type(value) is dict for value in values):
        raise ValueError(f"{name} must contain dictionaries")
    return _json_snapshot(values)

def _tags(value):
    if type(value) is not list or len(value) > 100:
        raise ValueError("tags must be a list of at most 100 strings")
    return sorted({_label(tag, "tag") for tag in value})

def _event(event):
    if type(event) is not dict or not REQUIRED_EVENT_FIELDS <= set(event):
        raise ValueError("event is missing required identity fields")
    for key in REQUIRED_EVENT_FIELDS - {"applied_at"}:
        _label(event[key], key)
    _number(event["applied_at"], "applied_at", minimum=0, maximum=1e12)
    _tags(event.get("tags", []))
    return event

def canonical_change_id(event: dict) -> str:
    """Full SHA-256 identity; integer and float timestamps canonicalize alike."""
    _event(event)
    identity = {key: event[key] for key in REQUIRED_EVENT_FIELDS}
    identity["applied_at"] = float(identity["applied_at"])
    body = json.dumps(identity, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "chg-" + hashlib.sha256(body.encode("utf-8")).hexdigest()

def normalize_events(events: list[dict]) -> list[dict]:
    out = []
    seen = set()
    for event in _records(events, "events"):
        _event(event)
        ident = canonical_change_id(event)
        if ident in seen:
            raise ValueError("duplicate canonical change identity")
        if "change_id" in event and event["change_id"] != ident:
            raise ValueError("change identity does not match event")
        seen.add(ident)
        out.append(dict(event, change_id=ident))
    return sorted(out, key=lambda event: (event["applied_at"], event["change_id"]))

def _check_sample(sample, index, need_value):
    required = {"service", "t"} | ({"metric", "value"} if need_value else set())
    if type(sample) is not dict or not required <= set(sample):
        raise ValueError(f"sample[{index}] is missing required fields")
    _label(sample["service"], "service")
    _number(sample["t"], "sample time", minimum=0, maximum=1e12)
    if "target_env" in sample:
        _label(sample["target_env"], "target_env")
    if need_value:
        _label(sample["metric"], "metric")
        _number(sample["value"], "sample value")

def _metric_key(sample):
    key = (sample["service"], sample["metric"])
    return key + (sample["target_env"],) if "target_env" in sample else key

def bind_telemetry(events: list[dict], samples: list[dict], window_s: float = 1800.0) -> dict:
    """Bind to latest rollout; ambiguous environments or ties remain unattributed."""
    window = _number(window_s, "window_s", minimum=0, maximum=1e12)
    if window == 0:
        raise ValueError("window_s must be positive")
    events = normalize_events(events)
    groups, environments = {}, {}
    for event in events:
        key = (event["service"], event["target_env"])
        groups.setdefault(key, {}).setdefault(event["applied_at"], []).append(event)
        environments.setdefault(event["service"], set()).add(event["target_env"])
    times = {key: sorted(group) for key, group in groups.items()}
    bound = {event["change_id"]: [] for event in events}
    unattributed, gaps = [], []
    for index, sample in enumerate(_records(samples, "samples")):
        _check_sample(sample, index, False)
        env = sample.get("target_env")
        candidates = environments.get(sample["service"], set())
        reason, hits = "outside rollout window", []
        if env is None and len(candidates) > 1:
            reason = "environment missing for service with multiple environments"
        else:
            if env is None and candidates:
                env = next(iter(candidates))
            key = (sample["service"], env)
            ticks = times.get(key, [])
            position = bisect_right(ticks, sample["t"]) - 1
            if position >= 0 and sample["t"] - ticks[position] < window:
                hits = groups[key][ticks[position]]
                if len(hits) == 1:
                    bound[hits[0]["change_id"]].append(sample)
                    continue
                reason = "multiple changes share the latest rollout time"
        unattributed.append(sample)
        gaps.append({"sample_index": index, "reason": reason,
                     "candidate_change_ids": sorted(event["change_id"] for event in hits)})
    return {"bound": bound, "unattributed": unattributed, "attribution_gaps": gaps}

@dataclass(frozen=True)
class Baseline:
    median: float
    mad: float
    n: int

    def __post_init__(self):
        _number(self.median, "baseline median")
        _number(self.mad, "baseline MAD", minimum=0)
        if self.mad <= 0 or type(self.n) is not int or not 1 <= self.n <= MAX_RECORDS:
            raise ValueError("baseline requires positive MAD and bounded sample count")

def learn_baselines(history: list[dict]) -> dict:
    by_key = {}
    for index, sample in enumerate(_records(history, "history")):
        _check_sample(sample, index, True)
        by_key.setdefault(_metric_key(sample), []).append(float(sample["value"]))
    output = {}
    for key, values in by_key.items():
        median = statistics.median(values)
        mad = max(statistics.median([abs(value - median) for value in values]), 1e-9)
        output[key] = Baseline(median, mad, len(values))
    return output

def detect_deviations(samples: list[dict], baselines: dict, threshold: float = 3.0) -> list[dict]:
    """Require a baseline for every sample; no baseline is not a normal reading."""
    threshold = _number(threshold, "threshold", minimum=1.5)
    if type(baselines) is not dict:
        raise ValueError("baselines must be a dictionary")
    deviations = []
    for index, sample in enumerate(_records(samples, "samples")):
        _check_sample(sample, index, True)
        baseline = baselines.get(_metric_key(sample))
        if not isinstance(baseline, Baseline):
            raise ValueError("sample has no valid baseline for its service, metric, and environment")
        baseline.__post_init__()
        scale = max(baseline.mad, 1e-9)
        z = abs(float(sample["value"]) - baseline.median) / (1.4826 * scale)
        if z >= 1.5:
            deviation = {"service": sample["service"], "metric": sample["metric"],
                         "t": sample["t"], "value": sample["value"],
                         "baseline_median": baseline.median, "baseline_n": baseline.n,
                         "baseline_mad": baseline.mad, "effective_mad": scale,
                         "robust_z": round(z, 3), "severity": "high" if z >= threshold else "low"}
            if "target_env" in sample:
                deviation["target_env"] = sample["target_env"]
            deviations.append(deviation)
    return sorted(deviations, key=lambda d: (-d["robust_z"], d["service"],
                                             d.get("target_env", ""), d["metric"], d["t"]))

def incident_similarity(change: dict, incidents: list[dict]) -> list[dict]:
    if type(change) is not dict:
        raise ValueError("change must be a dictionary")
    tags = set(_tags(change.get("tags", [])))
    scored, seen = [], set()
    for incident in _records(incidents, "incidents"):
        ident = _label(incident.get("incident_id"), "incident_id")
        if ident in seen:
            raise ValueError("duplicate incident identifier")
        seen.add(ident)
        itags = set(_tags(incident.get("tags", [])))
        union = tags | itags
        similarity = len(tags & itags) / len(union) if union else 0.0
        if similarity > 0:
            scored.append({"incident_id": ident, "similarity": round(similarity, 3),
                           "shared_tags": sorted(tags & itags)})
    return sorted(scored, key=lambda row: (-row["similarity"], row["incident_id"]))

def risk_brief(change: dict, deviations: list[dict], similar_incidents: list[dict],
               dependents: list[str]) -> dict:
    _event(change)
    ident = canonical_change_id(change)
    if change.get("change_id") != ident:
        raise ValueError("brief requires a correctly normalized change")
    deviations = _records(deviations, "deviations")
    for index, deviation in enumerate(deviations):
        _check_sample(deviation, index, True)
        _number(deviation.get("robust_z"), "robust_z", minimum=0, maximum=1e110)
        if deviation["service"] != change["service"] or deviation["t"] < change["applied_at"]:
            raise ValueError("deviation belongs to a different service or predates the change")
        if "target_env" in deviation and deviation["target_env"] != change["target_env"]:
            raise ValueError("deviation belongs to a different environment")
    similar_incidents = _records(similar_incidents, "similar incidents")
    seen = set()
    for incident in similar_incidents:
        ident_inc = _label(incident.get("incident_id"), "incident_id")
        if ident_inc in seen:
            raise ValueError("duplicate similar incident")
        seen.add(ident_inc)
        _number(incident.get("similarity"), "similarity", minimum=0, maximum=1)
    similar_incidents.sort(key=lambda row: (-row["similarity"], row["incident_id"]))
    if type(dependents) is not list or len(dependents) > MAX_RECORDS:
        raise ValueError("dependents must be a bounded list")
    dependents = list(dict.fromkeys(_label(dep, "dependent") for dep in dependents
                                   if dep != change["service"]))
    dev_component = min(1.0, math.fsum(min(d["robust_z"], 10.0) for d in deviations) / 20.0)
    sim_component = max((row["similarity"] for row in similar_incidents), default=0)
    radius_component = min(1.0, len(dependents) / 10.0)
    drivers = [
        {"driver": "deviation_pressure", "weight": DRIVER_WEIGHTS["deviation_pressure"],
         "component": round(dev_component, 3), "inputs": [f"{d['metric']} z={d['robust_z']}" for d in deviations],
         "per_deviation_cap": 10.0, "saturation_total": 20.0},
        {"driver": "incident_similarity", "weight": DRIVER_WEIGHTS["incident_similarity"],
         "component": round(sim_component, 3), "inputs": [f"{i['incident_id']} sim={i['similarity']}" for i in similar_incidents],
         "aggregation": "maximum"},
        {"driver": "blast_radius", "weight": DRIVER_WEIGHTS["blast_radius"],
         "component": round(radius_component, 3), "inputs": dependents.copy(),
         "saturation_count": 10},
    ]
    score = round(sum(driver["weight"] * driver["component"] for driver in drivers), 3)
    return {"schema": "radar/brief/v1", "radar_version": VERSION,
            "change_id": ident, "service": change["service"], "target_env": change["target_env"],
            "risk_score": score, "score_decomposition": drivers,
            "impact_radius": {"directly_changed": change["service"], "plausible_dependents": dependents},
            "deviations": deviations, "similar_incidents": similar_incidents,
            "advisory_only": True, "human_decision_required": True,
            "production_access": "read-only inputs supplied by caller (GRD-04)",
            "no_escalation_no_comms": True,
            "coverage_note": "Score uses caller-supplied context only; absence of evidence is not proof of low risk."}
