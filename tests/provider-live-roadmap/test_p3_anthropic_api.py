from __future__ import annotations

import copy
import datetime
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
V1 = ROOT / "research/provider-live-roadmap/p3-api/v1"
RUNNER = V1 / "live_runner.py"
CONTRACT = V1 / "contract.json"
RESULT = V1 / "result.json"


def load_runner():
    spec = importlib.util.spec_from_file_location("p3_anthropic_api_runner_test", RUNNER)
    if spec is None or spec.loader is None:
        raise AssertionError("runner unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class P3AnthropicAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()
        cls.contract_raw = CONTRACT.read_bytes()
        cls.contract = json.loads(cls.contract_raw)

    def test_contract_is_exact_cache_off_bounded_and_cost_claim_limited(self) -> None:
        self.runner.validate_contract(self.contract, repo_root=ROOT)
        self.assertEqual(
            self.contract["provider"],
            {
                "auth_method": "standard_api_key_in_memory",
                "id": "anthropic-first-party",
                "model_id": "claude-sonnet-5",
            },
        )
        self.assertEqual(self.contract["request"]["cache_control"], "omitted")
        self.assertEqual(self.contract["request"]["max_tokens"], 2048)
        self.assertEqual(self.contract["request"]["temperature"], "omitted")
        self.assertEqual(self.contract["request"]["thinking"], "disabled")
        self.assertEqual(self.contract["limits"]["call_cap"], 240)
        self.assertEqual(self.contract["limits"]["max_answer_bytes"], 32768)
        self.assertEqual(self.contract["limits"]["spend_cap_usd"], "20.00")
        self.assertEqual(
            self.contract["pricing"],
            {
                "authority": "published_list_price_not_billing_receipt",
                "currency": "USD",
                "effective_end": "2026-08-31",
                "effective_start": "2026-07-01",
                "input_micro_usd_per_token": 2,
                "output_micro_usd_per_token": 10,
                "source": "anthropic_sonnet_5_introductory_pricing",
            },
        )
        self.assertFalse(any(self.contract["claims"].values()))

        for mutation in (
            lambda value: value["request"].__setitem__("cache_control", "automatic"),
            lambda value: value["limits"].__setitem__("call_cap", 241),
            lambda value: value["claims"].__setitem__("provider_cost_savings", True),
        ):
            changed = copy.deepcopy(self.contract)
            mutation(changed)
            with self.assertRaises(Exception):
                self.runner.validate_contract(changed, repo_root=ROOT)

    def test_request_body_is_bounded_and_omits_cache_tools_and_sampling(self) -> None:
        raw = self.runner.build_request_body(
            {"prompt": "Task and authenticated context"}, contract=self.contract
        )
        self.assertLessEqual(len(raw), self.contract["limits"]["max_request_bytes"])
        value = json.loads(raw)
        self.assertEqual(
            value,
            {
                "max_tokens": 2048,
                "messages": [
                    {"content": "Task and authenticated context", "role": "user"}
                ],
                "model": "claude-sonnet-5",
                "thinking": {"type": "disabled"},
            },
        )
        self.assertNotIn("cache_control", raw.decode("ascii"))
        self.assertNotIn("tools", value)
        self.assertEqual(value["thinking"], {"type": "disabled"})

        with self.assertRaises(Exception):
            self.runner.build_request_body(
                {"prompt": "x" * 20_000}, contract=self.contract
            )

    def test_response_parser_preserves_provider_usage_and_exact_list_price(self) -> None:
        raw = json.dumps(
            {
                "content": [{"text": "READY", "type": "text"}],
                "id": "msg_0123456789",
                "model": "claude-sonnet-5",
                "role": "assistant",
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "type": "message",
                "usage": {
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 0,
                    "input_tokens": 10,
                    "output_tokens": 2,
                },
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        parsed = self.runner.parse_anthropic_response(raw, contract=self.contract)
        self.assertEqual(parsed["answer"], "READY")
        self.assertEqual(parsed["message_id_sha256"], self.runner.sha256(b"msg_0123456789"))
        self.assertEqual(
            parsed["usage"],
            {
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "input_tokens": 10,
                "list_price_micro_usd": 40,
                "output_tokens": 2,
                "provider_total_input_tokens": 10,
                "provider_total_tokens": 12,
            },
        )

    def test_response_parser_accepts_current_null_stop_details(self) -> None:
        raw = json.dumps(
            {
                "content": [{"text": "READY", "type": "text"}],
                "id": "msg_0123456789",
                "model": "claude-sonnet-5",
                "role": "assistant",
                "stop_details": None,
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "type": "message",
                "usage": {"input_tokens": 10, "output_tokens": 2},
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        parsed = self.runner.parse_anthropic_response(raw, contract=self.contract)
        self.assertEqual(parsed["answer"], "READY")

    def test_response_parser_accepts_bounded_explanations_and_rejects_oversize(self) -> None:
        def response(answer: str) -> bytes:
            return json.dumps(
                {
                    "content": [{"text": answer, "type": "text"}],
                    "id": "msg_0123456789",
                    "model": "claude-sonnet-5",
                    "role": "assistant",
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "type": "message",
                    "usage": {"input_tokens": 10, "output_tokens": 2},
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()

        parsed = self.runner.parse_anthropic_response(
            response("x" * 517), contract=self.contract
        )
        self.assertEqual(len(parsed["answer"]), 517)
        with self.assertRaises(Exception):
            self.runner.parse_anthropic_response(
                response("x" * 32769), contract=self.contract
            )

    def test_response_parser_rejects_cache_model_tool_and_error_drift(self) -> None:
        valid = {
            "content": [{"text": "READY", "type": "text"}],
            "id": "msg_0123456789",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "type": "message",
            "usage": {
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "input_tokens": 10,
                "output_tokens": 2,
            },
        }
        mutations = (
            lambda value: value["usage"].__setitem__("cache_read_input_tokens", 1),
            lambda value: value.__setitem__("model", "claude-other"),
            lambda value: value.__setitem__(
                "content", [{"id": "toolu_1", "name": "shell", "type": "tool_use"}]
            ),
            lambda value: value.update({"type": "error", "error": {"message": "private"}}),
        )
        for mutation in mutations:
            changed = copy.deepcopy(valid)
            mutation(changed)
            with self.assertRaises(Exception) as caught:
                self.runner.parse_anthropic_response(
                    json.dumps(changed).encode(), contract=self.contract
                )
            self.assertNotIn("private", str(caught.exception))

    def test_https_invocation_uses_only_the_exact_messages_destination_and_secret_header(self) -> None:
        response_raw = json.dumps(
            {
                "content": [{"text": "READY", "type": "text"}],
                "id": "msg_0123456789",
                "model": "claude-sonnet-5",
                "role": "assistant",
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "type": "message",
                "usage": {"input_tokens": 10, "output_tokens": 2},
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        calls: list[dict[str, object]] = []

        class FakeResponse:
            status = 200

            def read(self, amount: int) -> bytes:
                self.amount = amount
                return response_raw

        class FakeConnection:
            def __init__(self, host, *, port, timeout, context):
                calls.append(
                    {
                        "context": context,
                        "host": host,
                        "port": port,
                        "timeout": timeout,
                    }
                )

            def request(self, method, path, *, body, headers):
                calls[-1].update(
                    {"body": body, "headers": headers, "method": method, "path": path}
                )

            def getresponse(self):
                return FakeResponse()

            def close(self):
                calls[-1]["closed"] = True

        key = b"sk-ant-api03-test-secret-never-publish"
        raw = self.runner.invoke_anthropic(
            {"prompt": "Task and authenticated context"},
            contract=self.contract,
            api_key=key,
            connection_factory=FakeConnection,
        )
        self.assertEqual(raw, response_raw)
        self.assertEqual((calls[0]["host"], calls[0]["port"]), ("api.anthropic.com", 443))
        self.assertEqual((calls[0]["method"], calls[0]["path"]), ("POST", "/v1/messages"))
        self.assertEqual(calls[0]["headers"]["anthropic-version"], "2023-06-01")
        self.assertEqual(calls[0]["headers"]["x-api-key"], key.decode("ascii"))
        self.assertNotIn(key, calls[0]["body"])
        self.assertTrue(calls[0]["closed"])

        with self.assertRaises(Exception) as caught:
            self.runner.invoke_anthropic(
                {"prompt": "Task"},
                contract=self.contract,
                api_key=key + b"\n",
                connection_factory=FakeConnection,
            )
        self.assertNotIn("test-secret", str(caught.exception))

    def test_all_240_calls_seal_before_scorer_and_preserve_usage_and_price(self) -> None:
        base = self.runner.load_base(self.contract, repo_root=ROOT)
        capture = base.capture_frozen_packs(
            contract=base.CAPTURED_CONTRACT, repo_root=ROOT
        )
        schedule_raw = (
            ROOT / "research/provider-free-roadmap/g5/v1/schedule.json"
        ).read_bytes()
        schedule = json.loads(schedule_raw)
        schema_raw = (
            ROOT
            / "research/provider-free-roadmap/g5/v1/schemas/authoritative-observation.schema.json"
        ).read_bytes()
        calls: list[str] = []

        def invoke(item: dict[str, object]) -> bytes:
            calls.append(item["scheduled_unit_id"])
            return json.dumps(
                {
                    "content": [{"text": "READY", "type": "text"}],
                    "id": "msg_" + item["scheduled_unit_id"],
                    "model": "claude-sonnet-5",
                    "role": "assistant",
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "type": "message",
                    "usage": {
                        "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 0,
                        "input_tokens": 10,
                        "output_tokens": 2,
                    },
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()

        execution = self.runner.execute_schedule(
            contract=self.contract,
            schedule=schedule,
            observation_schema_bytes=schema_raw,
            tasks=capture.tasks,
            packs=capture.packs,
            invoke=invoke,
            scorer_loader=capture.load_scorer,
            repo_root=ROOT,
        )
        self.assertEqual(len(calls), 240)
        self.assertEqual(capture.scorer_load_count, 1)
        self.assertEqual(len(execution["sealed_runs"]), 240)
        self.assertEqual(
            execution["token_usage"],
            {
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "completed_calls": 240,
                "input_tokens": 2400,
                "list_price_micro_usd": 9600,
                "output_tokens": 480,
                "provider_total_input_tokens": 2400,
                "provider_total_tokens": 2880,
            },
        )

    def test_authorized_run_is_one_use_and_publishes_no_secret_or_content(self) -> None:
        base = self.runner.load_base(self.contract, repo_root=ROOT)
        boundary = base.load_approval_boundary(base.CAPTURED_CONTRACT, repo_root=ROOT)
        signing_key = bytes(range(32))
        registry_key = bytes(reversed(range(32)))
        api_key = b"sk-ant-api03-test-secret-never-publish"
        now = int(time.time())
        approval_box: dict[str, object] = {}
        calls: list[str] = []

        def approval_factory(scope: dict[str, object]) -> dict[str, object]:
            if "approval" not in approval_box:
                approval_box["approval"] = boundary.create_approval(
                    scope=scope,
                    issued_at=now - 1,
                    expires_at=now + 3600,
                    nonce="a" * 64,
                    revocation_handle="b" * 64,
                    signing_key=signing_key,
                )
            return approval_box["approval"]

        def invoke(item: dict[str, object]) -> bytes:
            calls.append(item["scheduled_unit_id"])
            return json.dumps(
                {
                    "content": [{"text": "READY", "type": "text"}],
                    "id": "msg_" + item["scheduled_unit_id"],
                    "model": "claude-sonnet-5",
                    "role": "assistant",
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "type": "message",
                    "usage": {"input_tokens": 10, "output_tokens": 2},
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()

        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            os.chmod(root, 0o700)
            output = root / "output"
            state = root / "state"
            output.mkdir(mode=0o700)
            state.mkdir(mode=0o700)
            result = self.runner.run_live_authorized(
                contract_path=CONTRACT,
                repo_root=ROOT,
                output_root=output,
                state_root=state,
                approval=approval_factory,
                verification_key=signing_key,
                registry_key=registry_key,
                api_key=api_key,
                invoke=invoke,
            )
            self.assertEqual(result["status"], "p3_api_measurement_recorded")
            self.assertEqual(len(calls), 240)
            evidence_path = output / "p3-api-evidence.json"
            evidence_raw = evidence_path.read_bytes()
            evidence = json.loads(evidence_raw)
            self.runner.validate_public_evidence(
                evidence, contract_raw=self.contract_raw, repo_root=ROOT
            )
            self.assertEqual(oct(evidence_path.stat().st_mode & 0o777), "0o600")
            self.assertNotIn(api_key, evidence_raw)
            self.assertNotIn(b"Task and authenticated context", evidence_raw)
            self.assertEqual(
                evidence["provider_cost"],
                {
                    "availability": "unavailable",
                    "currency": None,
                    "reason": "admin_usage_cost_receipt_unavailable",
                    "value": None,
                },
            )
            self.assertEqual(
                evidence["list_price_estimate"]["amount_micro_usd"], 9600
            )

            with self.assertRaises(Exception):
                self.runner.run_live_authorized(
                    contract_path=CONTRACT,
                    repo_root=ROOT,
                    output_root=output,
                    state_root=state,
                    approval=approval_factory,
                    verification_key=signing_key,
                    registry_key=registry_key,
                    api_key=api_key,
                    invoke=invoke,
                )
            self.assertEqual(len(calls), 240)

    def test_direct_mutable_execution_refuses(self) -> None:
        self.assertEqual(self.runner.main([]), 2)

    def test_introductory_price_window_fails_closed_after_august(self) -> None:
        self.runner.validate_pricing_window(
            self.contract, observed_date=datetime.date(2026, 8, 17)
        )
        for date in (datetime.date(2026, 6, 30), datetime.date(2026, 9, 1)):
            with self.assertRaises(Exception):
                self.runner.validate_pricing_window(
                    self.contract, observed_date=date
                )

    def test_published_result_is_hash_bound_arithmetic_consistent_and_non_authoritative(self) -> None:
        raw = RESULT.read_bytes()
        result = json.loads(raw)
        self.assertEqual(
            result["schema_version"],
            "contextguard.p3-anthropic-api-live-result/v1",
        )
        self.assertEqual(
            result["source"]["contract_sha256"],
            self.runner.sha256(self.contract_raw),
        )
        self.assertEqual(
            result["source"]["runner_sha256"],
            self.runner.sha256(RUNNER.read_bytes()),
        )
        self.assertTrue(all(value is False for value in result["claims"].values()))
        self.assertFalse(result["p3_gate"]["eligible"])
        self.assertEqual(result["call_accounting"]["completed_calls"], 240)
        self.assertEqual(result["call_accounting"]["excluded_calls"], 0)
        self.assertEqual(result["provider"]["cache_creation_input_tokens"], 0)
        self.assertEqual(result["provider"]["cache_read_input_tokens"], 0)

        arms = [
            result["analysis"][stratum]["arms"][arm]
            for stratum in ("closed_pack", "realistic_fallback")
            for arm in ("ordinary", "adaptive_only", "symbol_only", "combined")
        ]
        self.assertEqual(sum(row["input_tokens"] for row in arms), 174710)
        self.assertEqual(sum(row["output_tokens"] for row in arms), 23127)
        self.assertEqual(sum(row["total_tokens"] for row in arms), 197837)
        self.assertEqual(
            sum(row["list_price_micro_usd"] for row in arms), 580690
        )
        for row in arms:
            self.assertEqual(
                row["total_tokens"], row["input_tokens"] + row["output_tokens"]
            )
            self.assertEqual(
                row["list_price_micro_usd"],
                row["input_tokens"] * 2 + row["output_tokens"] * 10,
            )
        self.assertEqual(
            result["analysis"]["overall"]["combined_minus_ordinary"]
            ["total_token_delta"],
            -7104,
        )
        self.assertEqual(
            result["analysis"]["overall"]["combined_minus_ordinary"]
            ["list_price_delta_micro_usd"],
            1600,
        )
        self.assertFalse(
            {"api_key", "answer", "prompt", "raw", "response", "secret"}
            & self.runner._recursive_keys(result)
        )
        self.assertNotIn(b"/private/tmp", raw)


if __name__ == "__main__":
    unittest.main()
