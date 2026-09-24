import copy
import json
import unittest
from radar.core import (Baseline, DRIVER_WEIGHTS, bind_telemetry, canonical_change_id,
    detect_deviations, incident_similarity, learn_baselines, normalize_events, risk_brief)

def event(**changes):
    result = dict(service="api", kind="config", version="v1", target_env="prod",
                  applied_at=100, tags=["database"])
    result.update(changes)
    return result

def sample(**changes):
    result = dict(service="api", metric="latency", t=110, value=5)
    result.update(changes)
    return result

class IdentityBoundaries(unittest.TestCase):
    def test_direct_identity_validation_is_value_error(self):
        for change in (None, {}, event(service=[]), event(applied_at=True),
                       event(applied_at="100"), event(version=""), event(applied_at=10**400)):
            with self.assertRaises(ValueError):
                canonical_change_id(change)

    def test_integer_and_float_timestamps_have_same_full_digest(self):
        ident = canonical_change_id(event())
        self.assertEqual(ident, canonical_change_id(event(applied_at=100.0)))
        self.assertEqual(len(ident), 68)

    def test_duplicate_and_forged_identifiers_rejected(self):
        with self.assertRaises(ValueError):
            normalize_events([event(), event(applied_at=100.0)])
        with self.assertRaises(ValueError):
            normalize_events([event(change_id="forged")])

    def test_nested_metadata_detached(self):
        source = event(meta={"items": ["original"]})
        normalized = normalize_events([source])
        source["meta"]["items"].append("changed")
        self.assertEqual(normalized[0]["meta"]["items"], ["original"])

    def test_invalid_tags_and_unicode_rejected(self):
        for change in (event(tags="database"), event(tags=[{}]), event(service="\ud800")):
            with self.assertRaises(ValueError):
                canonical_change_id(change)

    def test_nonfinite_nested_metadata_rejected(self):
        with self.assertRaises(ValueError):
            normalize_events([event(metadata={"x": float("nan")})])

class BindingBoundaries(unittest.TestCase):
    def test_latest_window_independent_of_event_order(self):
        events = normalize_events([event(), event(applied_at=105, version="v2")])
        result = bind_telemetry(list(reversed(events)), [sample()])
        self.assertEqual(len(result["bound"][events[1]["change_id"]]), 1)
        self.assertEqual(result, bind_telemetry(events, [sample()]))

    def test_environment_is_required_when_service_spans_environments(self):
        events = [event(), event(target_env="stage")]
        result = bind_telemetry(events, [sample()])
        self.assertEqual(len(result["unattributed"]), 1)
        self.assertIn("environment missing", result["attribution_gaps"][0]["reason"])
        explicit = bind_telemetry(events, [sample(target_env="prod")])
        self.assertEqual(len(explicit["bound"][canonical_change_id(event())]), 1)

    def test_simultaneous_changes_are_ambiguous(self):
        events = [event(), event(version="v2")]
        result = bind_telemetry(events, [sample()])
        self.assertEqual(len(result["unattributed"]), 1)
        self.assertEqual(len(result["attribution_gaps"][0]["candidate_change_ids"]), 2)

    def test_window_edges_and_prechange_samples(self):
        result = bind_telemetry([event()], [sample(t=99), sample(t=100), sample(t=110)], window_s=10)
        self.assertEqual([s["t"] for s in result["bound"][canonical_change_id(event())]], [100])
        self.assertEqual([s["t"] for s in result["unattributed"]], [99, 110])

    def test_invalid_window_and_sample_types_rejected(self):
        for window in (True, 0, -1, float("inf"), "1"):
            with self.assertRaises(ValueError):
                bind_telemetry([event()], [], window)
        with self.assertRaises(ValueError):
            bind_telemetry([event()], [sample(t=False)])

    def test_nested_sample_snapshot(self):
        record = sample(meta={"tags": ["original"]})
        result = bind_telemetry([event()], [record])
        record["meta"]["tags"].append("changed")
        self.assertEqual(result["bound"][canonical_change_id(event())][0]["meta"]["tags"], ["original"])

class NumericBoundaries(unittest.TestCase):
    def test_baselines_do_not_mix_environments(self):
        history = [sample(target_env="prod", value=10), sample(target_env="stage", value=100)]
        baselines = learn_baselines(history)
        self.assertEqual(baselines[("api", "latency", "prod")].median, 10)
        self.assertEqual(baselines[("api", "latency", "stage")].median, 100)
        self.assertEqual(detect_deviations([sample(target_env="prod", value=10)], baselines), [])

    def test_missing_baseline_is_not_a_normal_reading(self):
        with self.assertRaises(ValueError):
            detect_deviations([sample()], {})
        with self.assertRaises(ValueError):
            detect_deviations([sample(target_env="prod")], learn_baselines([sample()]))

    def test_invalid_numeric_samples_and_thresholds(self):
        for value in (True, "5", [], float("nan"), float("inf"), 10**400):
            with self.assertRaises(ValueError):
                learn_baselines([sample(value=value)])
        for threshold in (0, 1, True, float("nan")):
            with self.assertRaises(ValueError):
                detect_deviations([], {}, threshold)

    def test_invalid_baseline_rejected(self):
        for args in ((0, 0, 1), (0, -1, 1), (0, 1, True), (0, 1, 0), (float("nan"), 1, 1)):
            with self.assertRaises(ValueError):
                Baseline(*args)

    def test_extreme_finite_values_remain_json_finite(self):
        baseline = {("api", "latency"): Baseline(-1e100, 1e-300, 10)}
        deviation = detect_deviations([sample(value=1e100)], baseline)[0]
        json.dumps(deviation, allow_nan=False)
        self.assertEqual(deviation["effective_mad"], 1e-9)
        self.assertEqual(deviation["severity"], "high")

class BriefBoundaries(unittest.TestCase):
    def setUp(self):
        self.change = normalize_events([event()])[0]
        self.deviation = dict(sample(), robust_z=3)

    def test_similarity_maximum_not_first_record(self):
        incidents = [{"incident_id":"A", "similarity":0.1}, {"incident_id":"B", "similarity":0.9}]
        first = risk_brief(self.change, [], incidents, [])
        second = risk_brief(self.change, [], list(reversed(incidents)), [])
        self.assertEqual(first, second)
        self.assertEqual(first["risk_score"], 0.27)

    def test_invalid_score_components_rejected(self):
        for z in (-1, float("nan"), True):
            with self.assertRaises(ValueError):
                risk_brief(self.change, [dict(self.deviation, robust_z=z)], [], [])
        for sim in (-0.1, 1.1, float("nan")):
            with self.assertRaises(ValueError):
                risk_brief(self.change, [], [{"incident_id":"X", "similarity":sim}], [])

    def test_mismatched_deviations_rejected(self):
        for changes in ({"service":"other"}, {"target_env":"stage"}, {"t":99}):
            with self.assertRaises(ValueError):
                risk_brief(self.change, [dict(self.deviation, **changes)], [], [])

    def test_duplicate_dependents_and_changed_service_not_inflated(self):
        report = risk_brief(self.change, [], [], ["web", "web", "api"])
        self.assertEqual(report["impact_radius"]["plausible_dependents"], ["web"])
        self.assertEqual(report["risk_score"], 0.02)

    def test_every_score_input_is_disclosed(self):
        deviations = [dict(self.deviation, metric=f"metric{i}") for i in range(8)]
        report = risk_brief(self.change, deviations, [], [f"s{i}" for i in range(12)])
        self.assertEqual(len(report["score_decomposition"][0]["inputs"]), 8)
        self.assertEqual(len(report["score_decomposition"][2]["inputs"]), 12)
        self.assertEqual(report["risk_score"], round(sum(d["weight"]*d["component"] for d in report["score_decomposition"]), 3))

    def test_nested_deviation_and_incident_snapshots(self):
        deviations = [dict(self.deviation, metadata={"items":[1]})]
        incidents = [{"incident_id":"I", "similarity":0.5, "shared_tags":["x"]}]
        report = risk_brief(self.change, deviations, incidents, [])
        snapshot = copy.deepcopy(report)
        deviations[0]["metadata"]["items"].append(2)
        incidents[0]["shared_tags"].append("y")
        self.assertEqual(report, snapshot)

    def test_weights_are_immutable(self):
        with self.assertRaises(TypeError):
            DRIVER_WEIGHTS["blast_radius"] = -1

    def test_duplicate_incidents_rejected(self):
        incident = {"incident_id":"I", "tags":["database"]}
        with self.assertRaises(ValueError):
            incident_similarity(self.change, [incident, incident])
