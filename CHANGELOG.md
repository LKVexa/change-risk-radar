# 0.1.2a1 — 2026-09-23

- Validate and normalize full change identities; reject duplicate/forged IDs.
- Bind latest events deterministically and expose environmental/time ambiguity.
- Scope baselines by environment; reject missing baselines and invalid numerics.
- Bound and explain scores, deduplicate radius, and detach nested output data.
- Add 25 regression tests, packaging, Apache 2.0 LICENSE/NOTICE, README and CI.
- Compatibility: regenerate stored change IDs; missing baselines now raise.

# Changelog — Change Risk Radar & Regression Warning (JY-S005-P001)

## 0.1.1-partial — 2026-09-14 (maintenance repairs, A006)

Baseline fingerprint: build-0001 `product.zip`
sha256 `a7693db89f00ce3105bd7010d02930f94d335707708c154cf8ab6abf2c720595`
(7291 bytes), baseline version `0.1.0-partial`, 12/12 baseline tests
passing before repair. All findings below were reproduced on the
baseline with saved probe output before fixing.

### A006-F1 — error-contract leaks (bare KeyError escaping ValueError contract)
- Observed: `bind_telemetry` raised bare `KeyError: 'service'` /
  `KeyError: 't'` on malformed samples; `incident_similarity` raised
  bare `KeyError: 'incident_id'`; `learn_baselines`/`detect_deviations`
  likewise leaked KeyError on samples missing required fields, while
  the documented validation contract (as in `normalize_events`) is
  `ValueError`.
- Expected: malformed records rejected with `ValueError` naming the
  index and missing fields.
- Fix: `_check_sample` validator applied in `bind_telemetry`,
  `learn_baselines`, `detect_deviations`; explicit incident_id check in
  `incident_similarity`; non-dict events rejected with ValueError in
  `normalize_events`.

### A006-F2 — NaN accepted / non-strict canonicalization
- Observed: `canonical_change_id` happily hashed `applied_at=NaN`
  (json.dumps default emits non-strict `NaN`); `learn_baselines` with a
  NaN history value silently produced a corrupted baseline (MAD
  collapsed to 1e-9); a NaN/Inf post-rollout sample was silently
  reported as "no deviation" — an anomaly masked as normal.
- Expected: non-finite numeric inputs rejected with `ValueError`;
  canonical JSON strict (`allow_nan=False`).
- Fix: `_require_finite` on `applied_at`, sample `t` and `value`;
  `allow_nan=False` in canonical serialization with a ValueError wrap.

### A006-F3 — output aliasing / isolation
- Observed: the risk brief aliased the caller's `deviations` and
  `dependents` lists — mutating them after the call tampered the
  already-issued brief; `bind_telemetry` results aliased input sample
  dicts.
- Expected: returned artifacts are isolated snapshots.
- Fix: brief copies `dependents` and deep-copies deviation dicts;
  bound/unattributed samples are copied.

### Compatibility
- No public API removed or renamed; all valid inputs behave as before
  (verified: original 12 baseline tests still pass unmodified).
  Previously-accepted *invalid* inputs (malformed samples, NaN values)
  now raise `ValueError` instead of leaking KeyError or silently
  corrupting output — a strengthened contract, not a capability loss.
- 10 new hardening tests added (positive + negative); suite now 22.

### Rollback
- Restore build-0001 `product.zip` (sha256 above). No data migration:
  the radar is a pure, stateless library.
