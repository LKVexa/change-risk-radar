# Change Risk Radar

**0.1.2a1 — experimental partial candidate, JY-S005-P001**

A pure Python library for change identity, telemetry attribution, median/MAD
deviation detection, incident-tag similarity, and decomposed advisory risk scores.
It opens no network connections, changes no production systems, and sends no alerts.
Every brief requires a human decision.

## Install and run

Python 3.10 or newer; no third-party runtime dependencies.

~~~sh
python -m pip install .
python -m unittest discover -s tests -t .
~~~

~~~python
from radar.core import normalize_events, bind_telemetry, learn_baselines, detect_deviations, risk_brief
events = normalize_events([{
    "service": "api", "kind": "config", "version": "v2",
    "target_env": "prod", "applied_at": 100, "tags": ["database"]
}])
history = [{"service": "api", "metric": "latency", "target_env": "prod",
            "t": i, "value": value} for i, value in enumerate([10, 11, 9, 10])]
samples = [{"service": "api", "metric": "latency", "target_env": "prod",
            "t": 110, "value": 20}]
binding = bind_telemetry(events, samples)
deviations = detect_deviations(binding["bound"][events[0]["change_id"]],
                               learn_baselines(history))
brief = risk_brief(events[0], deviations, [], ["web"])
~~~

## Attribution and evidence

Binding validates and sorts events internally, then selects the latest matching
rollout in a half-open time window. Samples without an environment remain
unattributed when a service spans environments. Simultaneous latest changes also
remain unattributed. attribution_gaps explains each unresolved sample.

Baselines are keyed by service, metric, and environment when supplied. Explicitly
scoped samples require equally scoped baselines. Missing baselines raise ValueError,
so an unavailable baseline cannot silently become a normal reading.

Deviation detection uses absolute robust z, with a low threshold of 1.5 and a
configurable high threshold >=1.5 (default 3). Effective MAD is floored at 1e-9
and exposed with sample count. Both rising and falling values can be flagged;
the caller must interpret each metric's meaning.

## Score and input boundaries

Risk score is bounded to [0,1]: deviation pressure contributes 0.5, maximum
incident similarity 0.3, and distinct dependent-service count 0.2. Every driver
lists all contributing inputs and its saturation rule. The rounded score is
recomputable from the reported rounded components and weights. These weights
are provisional heuristics, not a calibrated probability.

Inputs must be finite JSON-shaped records: lists up to 10,000 entries and 16 MiB
serialized JSON; labels up to 512 characters; tags up to 100 entries. Numeric
telemetry values are bounded to +/-1e100; timestamps and windows to 0..1e12,
with strictly positive windows. Boolean values are rejected as numeric input.
Returned records are detached snapshots.

## Compatibility and limits

This version changes change_id from truncated SHA-256 to the full digest, and
normalizes integer/float timestamp identity. Persisted IDs must be regenerated;
there is no persisted state inside the library. Duplicate event identities and
forged supplied IDs are rejected. Missing baselines and malformed score inputs
now raise ValueError. Caller-supplied old IDs cannot be mixed with new ones.

No live ingestion, causal inference, escalation, risk acceptance, or repository
service architecture is implemented. Unscoped legacy telemetry is supported only
where attribution is unambiguous. Callers remain responsible for binding deviations,
choosing representative prechange baseline history, and supplying complete incident
and dependency context. A zero score is not proof of safety.

47 tests include the 22 inherited checks and 25 hardening regressions. Source and
installed-wheel checks are recorded in [CHECK_RUNS](docs/CHECK_RUNS.json);
see [audit](docs/AUDIT.md) and [security boundaries](SECURITY.md).
CI covers Linux Python 3.10/3.12/3.14 and Windows Python 3.12. No completion is
claimed for the original carrier's 198 parent items, 166 P0 items, or phase gates.

## License

Copyright 2026 **RUSSELL PHILIP SMITHSON**.
[Apache License 2.0](LICENSE), with [NOTICE](NOTICE).
No third-party code is vendored.
