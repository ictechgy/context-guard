from __future__ import annotations

import unittest

import context_guard_receipt.router as router


class G005RouterV2Tests(unittest.TestCase):
    def api(self):
        names = (
            "RouteV2Context",
            "RouteV2Policy",
            "TotalCostComponents",
            "decide_total_cost_route",
        )
        self.assertTrue(all(hasattr(router, name) for name in names))
        return tuple(getattr(router, name) for name in names)

    def test_complete_low_risk_quality_pass_recommends_defer_without_applying(self) -> None:
        RouteV2Context, RouteV2Policy, TotalCostComponents, decide_total_cost_route = self.api()
        decision = decide_total_cost_route(
            baseline_total_microusd=1_000,
            candidate=TotalCostComponents(
                provider_input=200,
                provider_output=250,
                cache=20,
                expansion=30,
                retry=0,
                helper=50,
                local=0,
            ),
            context=RouteV2Context(
                evidence_complete=True,
                full_wire_ceiling_respected=True,
                quality_gate="pass",
                risk="low",
            ),
            policy=RouteV2Policy(
                minimum_savings_microusd=100,
                minimum_savings_basis_points=1_000,
            ),
        )

        self.assertEqual(decision.recommended_disposition, "defer")
        self.assertEqual(decision.reason, "beneficial_total_cost")
        self.assertEqual(decision.candidate_total_microusd, 550)
        self.assertEqual(decision.predicted_savings_microusd, 450)
        self.assertFalse(decision.runtime_applied)
        self.assertEqual(decision.mode, "shadow")

    def test_output_and_shifted_cost_inflation_forces_pass_through(self) -> None:
        RouteV2Context, RouteV2Policy, TotalCostComponents, decide_total_cost_route = self.api()
        decision = decide_total_cost_route(
            baseline_total_microusd=1_000,
            candidate=TotalCostComponents(
                provider_input=100,
                provider_output=700,
                cache=100,
                expansion=100,
                retry=100,
                helper=100,
                local=100,
            ),
            context=RouteV2Context(True, True, "pass", "low"),
            policy=RouteV2Policy(1, 1),
        )

        self.assertEqual(decision.recommended_disposition, "pass_through")
        self.assertEqual(decision.reason, "candidate_total_cost_not_lower")
        self.assertEqual(decision.candidate_total_microusd, 1_300)
        self.assertEqual(decision.predicted_savings_microusd, -300)

    def test_safety_and_evidence_gates_precede_economic_benefit(self) -> None:
        RouteV2Context, RouteV2Policy, TotalCostComponents, decide_total_cost_route = self.api()
        cases = (
            (RouteV2Context(False, True, "pass", "low"), "incomplete_evidence"),
            (RouteV2Context(True, False, "pass", "low"), "full_wire_ceiling_failed"),
            (RouteV2Context(True, True, "fail", "low"), "quality_gate_failed"),
            (RouteV2Context(True, True, "unknown", "low"), "quality_gate_unavailable"),
            (RouteV2Context(True, True, "pass", "high"), "risk_not_eligible"),
        )
        candidate = TotalCostComponents(1, 1, 1, 1, 1, 1, 1)
        policy = RouteV2Policy(1, 1)

        for context, reason in cases:
            with self.subTest(reason=reason):
                decision = decide_total_cost_route(
                    baseline_total_microusd=10_000,
                    candidate=candidate,
                    context=context,
                    policy=policy,
                )
                self.assertEqual(decision.recommended_disposition, "pass_through")
                self.assertEqual(decision.reason, reason)
                self.assertFalse(decision.runtime_applied)

    def test_bool_and_out_of_range_values_are_rejected(self) -> None:
        RouteV2Context, RouteV2Policy, TotalCostComponents, _ = self.api()
        with self.assertRaises(ValueError):
            TotalCostComponents(True, 0, 0, 0, 0, 0, 0)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            RouteV2Policy(0, 10_001)
        with self.assertRaises(ValueError):
            RouteV2Context(True, True, "pass", "unknown")


if __name__ == "__main__":
    unittest.main()
