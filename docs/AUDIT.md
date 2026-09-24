# Audit and hardening — 0.1.2a1

Date: 2026-09-23. Source: JY-S005-P001 / 0.1.1-partial / run-0001 / product.
Reviewed the complete deterministic core and inherited tests. Source files were
preserved separately from the maintenance checkout.

## Repaired findings

- Latest-rollout selection depended on caller event order. Binding now validates,
  sorts and indexes events, with explicit ambiguity on simultaneous changes.
- Telemetry and baselines could mix production/staging for the same service.
  Environment-scoped binding/baselines now isolate them; missing environment in
  a multi-environment service remains unattributed with an explicit reason.
- Canonical identity leaked KeyError and accepted invalid types/boolean timestamps;
  timestamps 100 and 100.0 hashed differently. Identity is now validated and
  normalized, uses full SHA-256, and rejects duplicate/forged normalized IDs.
- Numeric validation covered only nonfinite float values, allowing booleans,
  strings, enormous integers, invalid thresholds/windows, and corrupt baseline
  values. Bounded finite numeric contracts prevent downstream math corruption.
- Missing baselines were silently interpreted as no detected anomaly. Detection
  now raises a clear input error for missing or mismatched baseline scope.
- Incident pressure depended on the first similarity item, and repeated/self
  dependent names inflated blast radius. Inputs are validated, maximum similarity
  is selected, and radius uses distinct other services.
- Invalid/negative/nonfinite risk components and mismatched deviations could
  escape the [0,1] score contract. These now fail before scoring.
- Shallow copies retained nested caller aliases. Outputs now use detached JSON
  snapshots. All score inputs and saturation rules are exposed, and weights
  cannot be mutated through the exported mapping.

## Release and validation

Version 0.1.1-partial -> 0.1.2a1. Canonical IDs change and must be regenerated;
there is no on-disk library state. Missing-baseline behavior is intentionally stricter.
22 baseline tests passed; 47 source/installed-wheel tests pass after changes,
including 25 regressions. Historical check evidence is retained separately.
The four CI jobs cover Linux Python 3.10/3.12/3.14 and Windows Python 3.12.

Added installable packaging, Apache 2.0 LICENSE and NOTICE naming
RUSSELL PHILIP SMITHSON, README, security documentation, and pinned-action CI.
There are no third-party runtime dependencies to upgrade or audit. Build-tool
vulnerability scanning is not claimed. The statistical choices remain provisional,
and this release does not complete the original product roadmap.
