# Security and interpretation boundaries

The library is stateless and does not perform I/O, authentication, escalation,
or production changes. Its outputs are advisory only. Inputs are trusted as
observations supplied by the caller; identity hashes are not signatures.

Scope validation prevents obvious cross-service/environment mixing but does not
prove causal attribution. Simultaneous rollouts remain unresolved. Callers must
inspect attribution_gaps and provide environment labels wherever possible.
Baselines must come from suitable prechange history with enough observations.
The library does not certify history provenance or a minimum statistical power.

The fixed weights, thresholds, 1e-9 MAD floor, and linear saturation rules are
prototype choices. A score is not a calibrated incident probability. Missing
context can lower scores; a zero score does not establish that a change is safe.
Metric direction, seasonality, delayed effects, and confounding changes need
human analysis. Repeated deviation samples can contribute repeatedly by design.

Numeric/record limits and strict JSON protect normal API boundaries, not against
hostile Python subclasses, concurrent mutation, process-memory exhaustion, or
malicious caller code. Use OS-level isolation and request quotas in an exposed
service. Output metadata can contain caller-supplied sensitive information;
sanitize records before logging or sharing briefs.

There are no external runtime dependencies. Packaging uses setuptools with a
bounded build requirement; no build-tool vulnerability scan is claimed here.
Report defects privately to the owner with synthetic, sanitized reproductions.
