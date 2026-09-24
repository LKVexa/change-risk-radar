import unittest

from radar.core import (bind_telemetry, canonical_change_id, detect_deviations,
                        incident_similarity, learn_baselines, normalize_events,
                        risk_brief)

EVENTS = [
    {"service": "api", "kind": "deploy", "version": "1.4.0",
     "target_env": "prod", "applied_at": 1000.0, "tags": ["db-migration", "api"]},
    {"service": "api", "kind": "config", "version": "cfg-77",
     "target_env": "prod", "applied_at": 5000.0, "tags": ["timeout-change"]},
    {"service": "worker", "kind": "deploy", "version": "2.0.0",
     "target_env": "prod", "applied_at": 1200.0, "tags": ["queue"]},
]

HISTORY = ([{"service": "api", "metric": "p99_ms", "value": v, "t": t}
            for t, v in enumerate([100, 102, 98, 101, 99, 100, 103, 97, 100, 101])]
           + [{"service": "api", "metric": "error_rate", "value": v, "t": t}
              for t, v in enumerate([0.01, 0.012, 0.009, 0.011, 0.01, 0.01,
                                     0.013, 0.008, 0.01, 0.011])])

INCIDENTS = [
    {"incident_id": "INC-9", "tags": ["db-migration", "latency"]},
    {"incident_id": "INC-4", "tags": ["queue", "oom"]},
    {"incident_id": "INC-2", "tags": ["dns"]},
]


class Identity(unittest.TestCase):
    def test_canonical_id_field_order_independent(self):
        e = EVENTS[0]
        shuffled = {k: e[k] for k in reversed(list(e))}
        self.assertEqual(canonical_change_id(e), canonical_change_id(shuffled))

    def test_incidental_metadata_ignored(self):
        self.assertEqual(canonical_change_id(EVENTS[0]),
                         canonical_change_id(dict(EVENTS[0], operator="dave")))

    def test_distinct_events_distinct_ids(self):
        ids = {canonical_change_id(e) for e in EVENTS}
        self.assertEqual(len(ids), 3)

    def test_missing_fields_rejected(self):
        with self.assertRaises(ValueError):
            normalize_events([{"service": "x"}])


class Binding(unittest.TestCase):
    def test_samples_tied_to_specific_rollout(self):
        events = normalize_events(EVENTS)
        samples = [
            {"service": "api", "metric": "p99_ms", "value": 300, "t": 1100.0},
            {"service": "api", "metric": "p99_ms", "value": 310, "t": 5100.0},
            {"service": "api", "metric": "p99_ms", "value": 90, "t": 100.0},
            {"service": "worker", "metric": "depth", "value": 5, "t": 1300.0},
        ]
        res = bind_telemetry(events, samples)
        api_deploy = next(e for e in events if e["version"] == "1.4.0")
        api_cfg = next(e for e in events if e["version"] == "cfg-77")
        self.assertEqual(len(res["bound"][api_deploy["change_id"]]), 1)
        self.assertEqual(res["bound"][api_deploy["change_id"]][0]["t"], 1100.0)
        self.assertEqual(len(res["bound"][api_cfg["change_id"]]), 1)
        self.assertEqual(len(res["unattributed"]), 1)   # pre-rollout sample


class Deviations(unittest.TestCase):
    def test_baseline_and_detection(self):
        baselines = learn_baselines(HISTORY)
        post = [
            {"service": "api", "metric": "p99_ms", "value": 250, "t": 1100.0},
            {"service": "api", "metric": "p99_ms", "value": 101, "t": 1101.0},
            {"service": "api", "metric": "error_rate", "value": 0.014, "t": 1102.0},
        ]
        devs = detect_deviations(post, baselines)
        metrics = {(d["metric"], d["severity"]) for d in devs}
        self.assertIn(("p99_ms", "high"), metrics)         # 250 vs ~100
        self.assertIn(("error_rate", "low"), metrics)      # low-severity deviation
        self.assertNotIn(("p99_ms", "low"),
                         {(d["metric"], d["severity"]) for d in devs
                          if d["value"] == 101})           # normal sample silent

    def test_deterministic(self):
        b = learn_baselines(HISTORY)
        post = [{"service": "api", "metric": "p99_ms", "value": 250, "t": 1.0}]
        self.assertEqual(detect_deviations(post, b), detect_deviations(post, b))


class Similarity(unittest.TestCase):
    def test_jaccard_with_shared_tags(self):
        events = normalize_events(EVENTS)
        sims = incident_similarity(events[0], INCIDENTS)
        self.assertEqual(sims[0]["incident_id"], "INC-9")
        self.assertEqual(sims[0]["shared_tags"], ["db-migration"])
        self.assertNotIn("INC-2", [s["incident_id"] for s in sims])


class Brief(unittest.TestCase):
    def build(self):
        events = normalize_events(EVENTS)
        change = events[0]
        baselines = learn_baselines(HISTORY)
        post = [{"service": "api", "metric": "p99_ms", "value": 250, "t": 1100.0}]
        devs = detect_deviations(post, baselines)
        sims = incident_similarity(change, INCIDENTS)
        return risk_brief(change, devs, sims, dependents=["web", "billing"])

    def test_guardrails_structural(self):
        brief = self.build()
        self.assertTrue(brief["advisory_only"])
        self.assertTrue(brief["human_decision_required"])
        self.assertTrue(brief["no_escalation_no_comms"])
        import radar.core as m
        for name in dir(m):
            low = name.lower()
            for bad in ("escalate", "page", "notify", "ship", "accept_risk",
                        "deploy", "rollback"):
                self.assertNotIn(bad, low)

    def test_score_explainable_and_bounded(self):
        brief = self.build()
        self.assertGreaterEqual(brief["risk_score"], 0.0)
        self.assertLessEqual(brief["risk_score"], 1.0)
        recomputed = round(sum(d["weight"] * d["component"]
                               for d in brief["score_decomposition"]), 3)
        self.assertEqual(brief["risk_score"], recomputed)   # GRD-05 auditability
        for d in brief["score_decomposition"]:
            self.assertIn("inputs", d)

    def test_impact_radius(self):
        brief = self.build()
        self.assertEqual(brief["impact_radius"]["plausible_dependents"],
                         ["web", "billing"])

    def test_deterministic(self):
        self.assertEqual(self.build(), self.build())


class Hardening(unittest.TestCase):
    """A006 fixes: error contract, NaN strictness, output isolation."""

    def _events(self):
        return normalize_events(EVENTS)

    # A006-F1 — documented ValueError instead of bare KeyError leaks
    def test_bind_malformed_sample_valueerror(self):
        events = self._events()
        with self.assertRaises(ValueError):
            bind_telemetry(events, [{"metric": "p99_ms", "value": 1, "t": 1.0}])
        with self.assertRaises(ValueError):
            bind_telemetry(events, [{"service": "api", "value": 1}])

    def test_similarity_missing_incident_id_valueerror(self):
        with self.assertRaises(ValueError):
            incident_similarity(self._events()[0], [{"tags": ["db-migration"]}])

    def test_learn_and_detect_malformed_sample_valueerror(self):
        with self.assertRaises(ValueError):
            learn_baselines([{"service": "api", "metric": "m", "t": 1.0}])
        b = learn_baselines(HISTORY)
        with self.assertRaises(ValueError):
            detect_deviations([{"service": "api", "metric": "p99_ms"}], b)

    def test_normalize_non_dict_valueerror(self):
        with self.assertRaises(ValueError):
            normalize_events(["not-a-dict"])

    # A006-F2 — NaN / strict canonicalization
    def test_canonical_id_rejects_nan(self):
        bad = dict(EVENTS[0], applied_at=float("nan"))
        with self.assertRaises(ValueError):
            canonical_change_id(bad)
        with self.assertRaises(ValueError):
            normalize_events([bad])

    def test_nan_history_rejected(self):
        with self.assertRaises(ValueError):
            learn_baselines([{"service": "api", "metric": "m",
                              "value": float("nan"), "t": 0.0}])

    def test_nan_sample_rejected_not_silently_normal(self):
        b = learn_baselines(HISTORY)
        with self.assertRaises(ValueError):
            detect_deviations([{"service": "api", "metric": "p99_ms",
                                "value": float("inf"), "t": 1.0}], b)

    def test_finite_inputs_still_accepted(self):
        b = learn_baselines(HISTORY)
        devs = detect_deviations([{"service": "api", "metric": "p99_ms",
                                   "value": 250, "t": 1.0}], b)
        self.assertEqual(devs[0]["severity"], "high")

    # A006-F3 — output isolation from caller-held mutable inputs
    def test_brief_isolated_from_caller_mutation(self):
        import copy
        events = self._events()
        change = events[0]
        b = learn_baselines(HISTORY)
        devs = detect_deviations([{"service": "api", "metric": "p99_ms",
                                   "value": 250, "t": 1100.0}], b)
        deps = ["web", "billing"]
        brief = risk_brief(change, devs, [], deps)
        snap = copy.deepcopy(brief)
        deps.append("HACKED")
        devs[0]["metric"] = "TAMPERED"
        self.assertEqual(brief, snap)

    def test_bound_samples_isolated(self):
        events = self._events()
        sample = {"service": "api", "metric": "p99_ms", "value": 300,
                  "t": 1100.0}
        res = bind_telemetry(events, [sample])
        sample["value"] = -1
        cid = next(e for e in events if e["version"] == "1.4.0")["change_id"]
        self.assertEqual(res["bound"][cid][0]["value"], 300)


if __name__ == "__main__":
    unittest.main()
