from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


def router_module():
    try:
        return importlib.import_module("context_guard_receipt.router")
    except ModuleNotFoundError as error:
        raise AssertionError("G005 router implementation is missing") from error


class G005RouterTests(unittest.TestCase):
    def test_exact_integer_thresholds_reject_each_value_below_the_boundary(self) -> None:
        """Break caught: any one of the three conservative gates is weakened."""

        router = router_module()
        cases = (
            (511, 100, "input_too_small"),
            (1_000, 745, "savings_too_small"),
            (3_000, 2_701, "savings_ratio_too_small"),
        )
        for input_bytes, predicted_cost, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason):
                result = router.decide_route(
                    router.RouteCosts(
                        input_bytes=input_bytes,
                        wrapper_bytes=predicted_cost,
                        handle_bytes=0,
                        blueprint_bytes=0,
                        mandatory_expansion_bytes=0,
                        retained_wire_bytes=0,
                    )
                )
                self.assertEqual(result.disposition.value, "pass_through")
                self.assertEqual(result.reason.value, expected_reason)

    def test_exact_boundaries_defer_and_cost_components_sum_without_float_math(self) -> None:
        """Break caught: a component is omitted or an inclusive threshold becomes exclusive."""

        router = router_module()
        result = router.decide_route(
            router.RouteCosts(
                input_bytes=2_560,
                wrapper_bytes=100,
                handle_bytes=49,
                blueprint_bytes=2_155,
                mandatory_expansion_bytes=0,
                retained_wire_bytes=0,
            )
        )
        self.assertEqual(result.disposition.value, "defer")
        self.assertEqual(result.reason.value, "beneficial")
        self.assertEqual(result.predicted_cost_bytes, 2_304)
        self.assertEqual(result.predicted_savings_bytes, 256)
        self.assertEqual(result.savings_basis_points, 1_000)

    def test_mandatory_expansion_is_not_hidden_from_the_decision(self) -> None:
        """Break caught: required blueprint bytes are treated as free future work."""

        router = router_module()
        result = router.decide_route(
            router.RouteCosts(
                input_bytes=4_096,
                wrapper_bytes=200,
                handle_bytes=98,
                blueprint_bytes=400,
                mandatory_expansion_bytes=3_500,
                retained_wire_bytes=0,
            )
        )
        self.assertEqual(result.disposition.value, "pass_through")
        self.assertEqual(result.reason.value, "mandatory_expansion_cost")
        self.assertEqual(result.predicted_cost_bytes, 4_198)
        self.assertEqual(result.predicted_savings_bytes, -102)


if __name__ == "__main__":
    unittest.main()
