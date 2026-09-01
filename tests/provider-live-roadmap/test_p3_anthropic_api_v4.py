import importlib.util
import copy
import datetime
import functools
import inspect
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
V3 = ROOT / "research/provider-live-roadmap/p3-api/v3"
V4 = ROOT / "research/provider-live-roadmap/p3-api/v4"
RUNNER = V4 / "live_runner.py"
CONTRACT = V4 / "live-contract.json"
LAUNCHER = V4 / "live_launcher.py"
CAPTURE = V3 / "provider-input-freeze.json"
POLICY = V4 / "budget_policy.py"
REPORT = V4 / "budget-policy-report.json"


# 계약의 가격 유효기간 안에 있는 고정 날짜.
#
# 이 테스트들이 검증하는 것은 프로토콜(봉투 재시작, 단위별 1회 실행)이지 달력이
# 아니다. 그런데 run_live_authorized 는 실제 시계로 가격창을 확인하므로,
# effective_end 가 지나는 순간 프로토콜 테스트가 통째로 썩는다. 실제로 2026-09-01
# 자정에 그렇게 됐다.
#
# 가드 자체는 옳다 - 만료된 공시가로 실제 provider 호출을 하면 안 된다. 그래서
# 프로덕션 시그니처에 날짜 우회 경로를 만들지 않고, 테스트 경계에서만 고정한다.
# 창 밖에서 여전히 거부하는지는 test_pricing_window_still_refuses_outside_the_window
# 가 따로 지킨다.
PINNED_PRICING_DATE = datetime.date(2026, 8, 15)


def pinned_pricing_window(runner):
    """가격창 검사를 고정 날짜로 수행하게 만드는 컨텍스트 매니저.

    검사 로직 자체는 그대로 돈다. 관측 날짜만 주입하므로 EXPECTED_PRICING 불일치나
    창 경계 계산이 여전히 검증된다.
    """
    # 대체물을 스파이로 둔다. 날짜만 고정하면 "가드가 살아 있다" 는 것만 알 뿐,
    # run_live_authorized 가 실제로 그것을 부르는지는 알 수 없다. 호출을 기록해두면
    # 라이브 경로에서 가드를 떼어내는 리팩터가 조용히 통과하지 못한다.
    return mock.patch.object(
        runner,
        "validate_pricing_window",
        mock.MagicMock(
            side_effect=functools.partial(
                runner.validate_pricing_window, observed_date=PINNED_PRICING_DATE
            ),
            __name__="validate_pricing_window",
        ),
    )


def load_runner():
    if not RUNNER.is_file():
        raise AssertionError("V4 live runner is not implemented")
    spec = importlib.util.spec_from_file_location("p3_anthropic_api_v4_test", RUNNER)
    if spec is None or spec.loader is None:
        raise AssertionError("V4 live runner is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class P3AnthropicAPIV4Tests(unittest.TestCase):
    @staticmethod
    def _selection(runner, *, prompt: str = "selected provider input") -> dict[str, object]:
        prompt_raw = prompt.encode("utf-8")
        return {
            "decision_sha256": "a" * 64,
            "ordinary_prompt_ceiling_bytes": 14678,
            "policy": copy.deepcopy(runner.EXPECTED_POLICY_IDENTITY),
            "requested": {
                "arm_id": "a111",
                "cell_id": "requests_boundary_hardening:a111",
                "prompt_bytes": 22436,
                "prompt_sha256": "c" * 64,
            },
            "selected": {
                "arm_id": "a110",
                "cell_id": "requests_boundary_hardening:a110",
                "prompt_bytes": len(prompt_raw),
                "prompt_sha256": runner.sha256(prompt_raw),
            },
        }

    @classmethod
    def _plan(cls, runner, *, count: int = 288) -> tuple[list[dict[str, object]], dict[str, object]]:
        selection = cls._selection(runner)
        plan = []
        for index in range(count):
            item = {
                "arm_id": "a111",
                "payload_sha256": selection["selected"]["prompt_sha256"],
                "prompt": "selected provider input",
                "repetition": index % 3,
                "scheduled_unit_id": f"v4-unit-{index:03d}",
                "selection_identity": selection,
                "task_id": "requests_boundary_hardening",
            }
            item["request_id"] = runner._request_identity(item)
            plan.append(item)
        return plan, selection

    def test_contract_binds_v3_generation_inputs_and_exact_budget_policy(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())

        runner.validate_contract(contract, repo_root=ROOT)
        artifacts = contract["artifacts"]
        self.assertEqual(artifacts["evaluator"]["path"], "research/provider-live-roadmap/p3-api/v3/evaluator.py")
        self.assertEqual(artifacts["provider_input_capture"]["path"], str(CAPTURE.relative_to(ROOT)))
        self.assertEqual(artifacts["schedule"]["path"], "research/provider-live-roadmap/p3-api/v3/schedule.json")
        self.assertEqual(artifacts["budget_policy"]["path"], str(POLICY.relative_to(ROOT)))
        self.assertEqual(artifacts["budget_policy_report"]["path"], str(REPORT.relative_to(ROOT)))

    def test_external_scope_describes_actual_manual_evidence_retention(self) -> None:
        """A finite-looking retention duration must not mask manual cleanup."""

        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan, selection = self._plan(runner)
        with mock.patch.object(
            runner, "_bound_selection_identity", return_value=selection
        ):
            batch = runner.build_batch_plans(plan)[0]
            scope = runner.build_external_approval_scope(
                contract=contract,
                batch=batch,
                plan_sha256=runner.request_plan_sha256(plan),
                runner_sha256="f" * 64,
                output_root=Path("/private/tmp/contextguard-v4-output"),
            )

        self.assertEqual(
            scope["retention"],
            {
                "mode": "manual_owner_cleanup",
                "maximum_seconds": None,
            },
        )

    def test_v1_approval_refuses_before_state_or_provider_preparation(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state = root / "state"
            output = root / "output"
            with mock.patch.object(runner, "prepare_live_plan") as prepare:
                with self.assertRaisesRegex(
                    runner.LiveRunError, "approval_unavailable"
                ):
                    runner.run_live_authorized(
                        contract_path=root / "missing-contract.json",
                        repo_root=ROOT,
                        corpus_root=root,
                        output_root=output,
                        state_root=state,
                        approvals=[
                            {"schema_version": "contextguard.external-approval/v1"},
                            {"schema_version": "contextguard.external-approval/v1"},
                        ],
                        verification_key=b"v" * 32,
                        registry_key=b"r" * 32,
                        api_key=b"sk-ant-api03-test-value",
                    )
            prepare.assert_not_called()
            self.assertFalse(state.exists())
            self.assertFalse(output.exists())

    def test_pricing_window_still_refuses_outside_the_window(self) -> None:
        """가격창 가드는 그대로여야 한다.

        위 두 테스트는 창 안의 고정 날짜를 주입해 달력 의존을 없앤다. 그 주입이 가드를
        무력화하지 않았는지를 여기서 지킨다. 창 밖 날짜는 여전히 거부해야 한다.
        """
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        pricing = runner.EXPECTED_PRICING
        start = datetime.date.fromisoformat(pricing["effective_start"])
        end = datetime.date.fromisoformat(pricing["effective_end"])
        self.assertLessEqual(start, PINNED_PRICING_DATE)
        self.assertLessEqual(PINNED_PRICING_DATE, end)

        one_day = datetime.timedelta(days=1)
        for outside in (start - one_day, end + one_day):
            with self.subTest(observed_date=outside.isoformat()):
                with self.assertRaises(runner.LiveRunError) as caught:
                    runner.validate_pricing_window(contract, observed_date=outside)
                self.assertEqual(str(caught.exception), "pricing_window_unavailable")

        for inside in (start, PINNED_PRICING_DATE, end):
            with self.subTest(observed_date=inside.isoformat()):
                runner.validate_pricing_window(contract, observed_date=inside)

    def test_pricing_window_refuses_a_contract_whose_pricing_was_altered(self) -> None:
        """날짜를 고정해도 가격표 자체의 검증은 살아 있어야 한다.

        pinned_pricing_window 의 docstring 이 "EXPECTED_PRICING 불일치는 여전히
        검증된다" 고 주장하는데, 창 경계만 검사하는 테스트는 그것을 지키지 못한다.
        """
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        altered = copy.deepcopy(contract)
        pricing = dict(altered["pricing"])
        pricing["effective_end"] = "2099-12-31"
        altered["pricing"] = pricing
        with self.assertRaises(runner.LiveRunError) as caught:
            runner.validate_pricing_window(altered, observed_date=PINNED_PRICING_DATE)
        self.assertEqual(str(caught.exception), "invalid_pricing")

    def test_authorized_v2_envelopes_execute_each_unit_once(self) -> None:
        runner = load_runner()
        pricing_guard = self.enterContext(pinned_pricing_window(runner))
        contract = json.loads(CONTRACT.read_bytes())
        plan, selection = self._plan(runner)
        verification_key = b"v" * 32
        registry_key = b"r" * 32
        response = {
            "body": json.dumps(
                {
                    "content": [{"text": "READY", "type": "text"}],
                    "id": "msg-v4-v2-approval",
                    "model": "claude-sonnet-5",
                    "role": "assistant",
                    "stop_reason": "end_turn",
                    "type": "message",
                    "usage": {"input_tokens": 10, "output_tokens": 2},
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
            "http_status": 200,
            "provider_request_id": None,
        }
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state, output = root / "state", root / "output"
            state.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            with mock.patch.object(
                runner, "_bound_selection_identity", return_value=selection
            ), mock.patch.object(
                runner, "_expected_bound_selection", return_value=selection
            ):
                batches = runner.build_batch_plans(plan)
                plan_sha = runner.request_plan_sha256(plan)
                runner_sha = runner._runner_identity()
                approval_module = runner._load_bound_approval_module(
                    contract=contract, repo_root=ROOT
                )
                now = int(time.time())
                approvals = []
                for index, batch in enumerate(batches):
                    scope = runner.build_external_approval_scope(
                        contract=contract,
                        batch=batch,
                        plan_sha256=plan_sha,
                        runner_sha256=runner_sha,
                        output_root=output,
                    )
                    approvals.append(
                        approval_module.create_approval(
                            scope=scope,
                            issued_at=now - 1,
                            expires_at=now + 3600,
                            nonce=f"{index + 1:064x}",
                            revocation_handle=f"{index + 3:064x}",
                            signing_key=verification_key,
                        )
                    )
                calls: list[str] = []
                with mock.patch.object(
                    runner, "prepare_live_plan", return_value=plan
                ), mock.patch.object(
                    runner,
                    "invoke_anthropic",
                    side_effect=lambda item, **kwargs: (
                        calls.append(item["scheduled_unit_id"]) or response
                    ),
                ), mock.patch.object(
                    runner,
                    "_bound_scorer_loader",
                    return_value=lambda: (
                        lambda capsules, prepared: {
                            "exact_historical_patch_units": len(prepared),
                            "failed_units": 0,
                            "passed_units": len(prepared),
                            "scorer_artifact_sha256": runner.EXPECTED_SCORER_SHA256,
                            "status": "complete",
                            "total_units": len(prepared),
                        }
                    ),
                ):
                    result = runner.run_live_authorized(
                        contract_path=CONTRACT,
                        repo_root=ROOT,
                        corpus_root=root,
                        output_root=output,
                        state_root=state,
                        approvals=approvals,
                        verification_key=verification_key,
                        registry_key=registry_key,
                        api_key=b"sk-ant-api03-test-value",
                    )
            self.assertEqual(result["status"], "completed")
            # 라이브 경로가 실제로 가격창 가드를 통과했는지 확인한다. 날짜 고정만으로는
            # 가드가 호출되지 않게 되는 리팩터를 잡을 수 없다.
            pricing_guard.assert_called()
            self.assertEqual(len(calls), 288)

    def test_registry_commit_crash_restarts_same_v2_approvals_without_redispatch(self) -> None:
        runner = load_runner()
        pricing_guard = self.enterContext(pinned_pricing_window(runner))
        contract = json.loads(CONTRACT.read_bytes())
        plan, selection = self._plan(runner)
        verification_key = b"v" * 32
        registry_key = b"r" * 32
        response = {
            "body": json.dumps(
                {
                    "content": [{"text": "READY", "type": "text"}],
                    "id": "msg-v4-crash-recovery",
                    "model": "claude-sonnet-5",
                    "role": "assistant",
                    "stop_reason": "end_turn",
                    "type": "message",
                    "usage": {"input_tokens": 10, "output_tokens": 2},
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
            "http_status": 200,
            "provider_request_id": None,
        }
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state, output = root / "state", root / "output"
            state.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            with mock.patch.object(
                runner, "_bound_selection_identity", return_value=selection
            ), mock.patch.object(
                runner, "_expected_bound_selection", return_value=selection
            ):
                batches = runner.build_batch_plans(plan)
                plan_sha = runner.request_plan_sha256(plan)
                runner_sha = runner._runner_identity()
                approval_module = runner._load_bound_approval_module(
                    contract=contract, repo_root=ROOT
                )
                now = int(time.time())
                approvals = []
                for index, batch in enumerate(batches):
                    scope = runner.build_external_approval_scope(
                        contract=contract,
                        batch=batch,
                        plan_sha256=plan_sha,
                        runner_sha256=runner_sha,
                        output_root=output,
                    )
                    approvals.append(
                        approval_module.create_approval(
                            scope=scope,
                            issued_at=now - 1,
                            expires_at=now + 3600,
                            nonce=f"{index + 11:064x}",
                            revocation_handle=f"{index + 21:064x}",
                            signing_key=verification_key,
                        )
                    )

                original_authorize = approval_module.authorize_and_consume
                crashed = False

                def crash_once(**kwargs):
                    nonlocal crashed
                    if crashed:
                        return original_authorize(**kwargs)
                    crashed = True
                    without_materialize = {
                        key: value
                        for key, value in kwargs.items()
                        if key != "materialize"
                    }
                    return original_authorize(
                        **without_materialize,
                        materialize=lambda scope: (_ for _ in ()).throw(
                            SystemExit("crash after registry commit")
                        ),
                    )

                with mock.patch.object(
                    runner, "prepare_live_plan", return_value=plan
                ), mock.patch.object(
                    runner, "_load_bound_approval_module", return_value=approval_module
                ), mock.patch.object(
                    approval_module, "authorize_and_consume", side_effect=crash_once
                ):
                    with self.assertRaises(SystemExit):
                        runner.run_live_authorized(
                            contract_path=CONTRACT,
                            repo_root=ROOT,
                            corpus_root=root,
                            output_root=output,
                            state_root=state,
                            approvals=approvals,
                            verification_key=verification_key,
                            registry_key=registry_key,
                            api_key=b"sk-ant-api03-test-value",
                        )

                calls: list[str] = []
                with mock.patch.object(
                    runner, "prepare_live_plan", return_value=plan
                ), mock.patch.object(
                    runner, "_load_bound_approval_module", return_value=approval_module
                ), mock.patch.object(
                    runner,
                    "invoke_anthropic",
                    side_effect=lambda item, **kwargs: (
                        calls.append(item["scheduled_unit_id"]) or response
                    ),
                ), mock.patch.object(
                    runner,
                    "_bound_scorer_loader",
                    return_value=lambda: (
                        lambda capsules, prepared: {
                            "exact_historical_patch_units": len(prepared),
                            "failed_units": 0,
                            "passed_units": len(prepared),
                            "scorer_artifact_sha256": runner.EXPECTED_SCORER_SHA256,
                            "status": "complete",
                            "total_units": len(prepared),
                        }
                    ),
                ):
                    result = runner.run_live_authorized(
                        contract_path=CONTRACT,
                        repo_root=ROOT,
                        corpus_root=root,
                        output_root=output,
                        state_root=state,
                        approvals=approvals,
                        verification_key=verification_key,
                        registry_key=registry_key,
                        api_key=b"sk-ant-api03-test-value",
                    )
            self.assertEqual(result["status"], "completed")
            # 라이브 경로가 실제로 가격창 가드를 통과했는지 확인한다. 날짜 고정만으로는
            # 가드가 호출되지 않게 되는 리팩터를 잡을 수 없다.
            pricing_guard.assert_called()
            self.assertEqual(len(calls), 288)
            ledger = json.loads((state / "ledger.json").read_bytes())
            self.assertTrue(
                all(
                    batch["authorization_journal"]["status"] == "committed"
                    for batch in ledger["batches"].values()
                )
            )

    def test_selection_artifacts_are_reverified_but_parsed_once_per_snapshot(self) -> None:
        """Cached decisions still require fresh bound-byte verification."""

        runner = load_runner()
        with mock.patch.object(
            runner, "_read_bound", wraps=runner._read_bound
        ) as read_bound, mock.patch.object(
            runner, "parse_json", wraps=runner.parse_json
        ) as parse_json:
            first = runner._expected_bound_selection(
                "requests_boundary_hardening", "a111"
            )
            second = runner._expected_bound_selection(
                "requests_boundary_hardening", "a111"
            )

        self.assertEqual(first, second)
        self.assertEqual(read_bound.call_count, 6)
        self.assertEqual(parse_json.call_count, 2)

    def test_selection_cache_refuses_artifact_changed_after_identity_collection(self) -> None:
        """A warm cache cannot authorize bytes changed before its reuse decision."""

        runner = load_runner()
        with tempfile.TemporaryDirectory() as name:
            temporary_root = Path(name)
            artifacts = copy.deepcopy(runner.EXPECTED_ARTIFACTS)
            for artifact_name in (
                "budget_policy",
                "provider_input_capture",
                "budget_policy_report",
            ):
                source = ROOT / artifacts[artifact_name]["path"]
                copied = temporary_root / source.name
                copied.write_bytes(source.read_bytes())
                artifacts[artifact_name]["path"] = str(copied)

            with mock.patch.object(runner, "EXPECTED_ARTIFACTS", artifacts):
                runner._expected_bound_selection(
                    "requests_boundary_hardening", "a111"
                )
                original_identity = runner._selection_artifact_identity
                changed = False

                def change_after_identity(path, expected_sha256, label):
                    nonlocal changed
                    identity = original_identity(path, expected_sha256, label)
                    if label == "budget_policy_report" and not changed:
                        path.write_bytes(path.read_bytes() + b"\n")
                        changed = True
                    return identity

                with mock.patch.object(
                    runner,
                    "_selection_artifact_identity",
                    side_effect=change_after_identity,
                ):
                    with self.assertRaisesRegex(
                        runner.LiveRunError, "changed_budget_policy_report"
                    ):
                        runner._expected_bound_selection(
                            "requests_boundary_hardening", "a111"
                        )

    def test_reservation_builds_each_request_body_once(self) -> None:
        """A duplicate request-body pass must fail this call-count contract."""

        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan, selection = self._plan(runner)
        with mock.patch.object(
            runner, "_bound_selection_identity", return_value=selection
        ):
            batches = runner.build_batch_plans(plan)
            with mock.patch.object(
                runner, "build_request_body", wraps=runner.build_request_body
            ) as build_body:
                runner.calculate_worst_case_reservation(
                    contract=contract, batches=batches
                )

        self.assertEqual(build_body.call_count, len(plan))

    def test_ledger_snapshot_does_not_rewrite_durable_state(self) -> None:
        """A logical read must preserve ledger inode, bytes, and timestamps."""

        runner = load_runner()
        key = b"l" * 32
        with tempfile.TemporaryDirectory() as name:
            state_root = Path(name) / "state"
            state_root.mkdir(mode=0o700)
            runner._ledger_write(
                state_root,
                {"schema_version": "snapshot-test", "value": 1},
                key,
            )
            path = state_root / "ledger.json"
            before_stat = path.stat()
            before_bytes = path.read_bytes()

            snapshot = runner._ledger_snapshot(state_root, key)

            after_stat = path.stat()
            self.assertEqual(snapshot["value"], 1)
            self.assertEqual(path.read_bytes(), before_bytes)
            self.assertEqual(after_stat.st_ino, before_stat.st_ino)
            self.assertEqual(after_stat.st_mtime_ns, before_stat.st_mtime_ns)

    def test_authorized_lock_refuses_within_a_bounded_wait(self) -> None:
        """A second launcher must fail fast instead of waiting for a live run."""

        runner = load_runner()
        with tempfile.TemporaryDirectory() as name:
            output_root = Path(name) / "output"
            output_root.mkdir(mode=0o700)
            entered = threading.Event()
            release = threading.Event()
            errors: list[BaseException] = []

            def hold() -> None:
                entered.set()
                if not release.wait(timeout=5):
                    raise AssertionError("lock holder was not released")

            def first() -> None:
                try:
                    runner._with_authorized_run_lock(output_root, hold)
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=first)
            worker.start()
            self.assertTrue(entered.wait(timeout=2))
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(
                    runner.LiveRunError, "authorization_busy"
                ):
                    runner._with_authorized_run_lock(
                        output_root,
                        lambda: None,
                        wait_timeout_seconds=0.05,
                    )
            finally:
                release.set()
                worker.join(timeout=5)
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])

    def test_selection_is_sealed_into_request_batch_and_approval_identities(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        prompt = "selected provider input"
        selection = {
            "decision_sha256": "a" * 64,
            "ordinary_prompt_ceiling_bytes": 14678,
            "policy": runner.EXPECTED_POLICY_IDENTITY,
            "requested": {
                "arm_id": "a111",
                "cell_id": "requests_boundary_hardening:a111",
                "prompt_bytes": 22436,
                "prompt_sha256": "c" * 64,
            },
            "selected": {
                "arm_id": "a110",
                "cell_id": "requests_boundary_hardening:a110",
                "prompt_bytes": len(prompt.encode("utf-8")),
                "prompt_sha256": runner.sha256(prompt.encode("utf-8")),
            },
        }
        item = {
            "arm_id": "a111",
            "prompt": prompt,
            "payload_sha256": selection["selected"]["prompt_sha256"],
            "repetition": 0,
            "scheduled_unit_id": "requests_boundary_hardening:r0:a111",
            "selection_identity": selection,
            "task_id": "requests_boundary_hardening",
        }
        item["request_id"] = runner._request_identity(item)
        plan = [item] * 288
        plan = [{**unit, "scheduled_unit_id": f"unit-{index:03d}"} for index, unit in enumerate(plan)]
        for unit in plan:
            unit["request_id"] = runner._request_identity(unit)

        with mock.patch.object(runner, "_bound_selection_identity", return_value=selection):
            body = json.loads(runner.build_request_body(item, contract=contract))
            validated = runner._validate_plan(plan)
            batch = runner.build_batch_plans(validated)[0]
            projection = batch["items"][0]
            scope = runner.build_approval_scope(
                contract=contract,
                batch=batch,
                plan_sha256=runner.request_plan_sha256(plan),
            )
        self.assertEqual(
            runner.sha256(body["messages"][0]["content"].encode()),
            selection["selected"]["prompt_sha256"],
        )
        for value in (item["request_id"], projection["request_id"], scope["request_ids"][0]):
            self.assertIsInstance(value, str)
        self.assertEqual(projection["selection_identity"], selection)

    def test_direct_callable_and_production_launcher_are_closed(self) -> None:
        runner = load_runner()

        self.assertEqual(runner.main([]), 2)
        self.assertFalse(hasattr(runner, "run_live"))
        spec = importlib.util.spec_from_file_location("p3_anthropic_api_v4_launcher_test", LAUNCHER)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec else None)
        launcher = importlib.util.module_from_spec(spec)
        assert spec is not None and spec.loader is not None
        spec.loader.exec_module(launcher)
        self.assertEqual(launcher.main([]), 2)

    def test_launcher_activation_binds_exact_core_commit_and_blobs(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "p3_anthropic_api_v4_activation_test", LAUNCHER
        )
        if spec is None or spec.loader is None:
            raise AssertionError("V4 launcher is unavailable")
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)

        self.assertEqual(
            launcher.EXPECTED_CORE_COMMIT,
            "6546e0392056b8d046ce4b49e1aee503c6a2610e",
        )
        launcher._verify_core_commit(ROOT)
        with mock.patch.object(launcher, "EXPECTED_CORE_COMMIT", "0" * 40):
            with self.assertRaises(Exception):
                launcher._verify_core_commit(ROOT)
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaises(Exception):
                launcher._verify_core_commit(Path(name))

        expected = b"committed-v4-core"
        digest = __import__("hashlib").sha256(expected).hexdigest()
        launcher._verify_blob_triple(expected, expected, expected, digest)
        for changed in (
            (b"changed-core", expected, expected),
            (expected, b"changed-head", expected),
            (expected, expected, b"changed-worktree"),
        ):
            with self.assertRaises(Exception):
                launcher._verify_blob_triple(*changed, digest)

    def test_activated_launcher_calls_only_the_bound_v4_surface(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "p3_anthropic_api_v4_launch_test", LAUNCHER
        )
        if spec is None or spec.loader is None:
            raise AssertionError("V4 launcher is unavailable")
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        runner = mock.Mock()
        runner.parse_json.side_effect = [
            {"approval": "batch-1"},
            {"approval": "batch-2"},
        ]
        arguments = [
            "--execute",
            "--contract", str(CONTRACT),
            "--repo-root", str(ROOT),
            "--corpus-root", str(ROOT),
            "--output-root", str(ROOT / "output"),
            "--state-root", str(ROOT / "state"),
            "--approval-1", str(ROOT / "approval-1.json"),
            "--approval-2", str(ROOT / "approval-2.json"),
            "--verification-key-file", str(ROOT / "verification.key"),
            "--registry-key-file", str(ROOT / "registry.key"),
        ]
        with (
            mock.patch.object(launcher, "_load_runner", return_value=runner),
            mock.patch.object(launcher, "_verify_core_commit"),
            mock.patch.object(
                launcher, "_read_bound", return_value=CONTRACT.read_bytes()
            ),
            mock.patch.object(launcher, "_read_owner_file", return_value=b"k" * 32),
            mock.patch.object(
                launcher, "_read_keychain_secret", return_value=b"sk-ant-api03-test"
            ),
        ):
            self.assertEqual(launcher.main(arguments), 0)
        runner.run_live_authorized.assert_called_once()
        call = runner.run_live_authorized.call_args.kwargs
        self.assertEqual(call["contract_path"], CONTRACT)
        self.assertEqual(call["repo_root"], ROOT)
        self.assertEqual(call["approvals"], [
            {"approval": "batch-1"},
            {"approval": "batch-2"},
        ])
        self.assertNotIn("previous_output_root", call)
        self.assertNotIn("previous_state_root", call)

    def test_v4_launcher_keychain_lookup_is_fixed_and_value_free(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "p3_anthropic_api_v4_keychain_test", LAUNCHER
        )
        if spec is None or spec.loader is None:
            raise AssertionError("V4 launcher is unavailable")
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        completed = mock.Mock(returncode=0, stdout=b"sk-ant-api03-test-key\n")
        with mock.patch.object(
            launcher.subprocess, "run", return_value=completed
        ) as run:
            value = launcher._read_keychain_secret()
        self.assertEqual(value, b"sk-ant-api03-test-key")
        self.assertEqual(
            run.call_args.args[0][:4],
            [
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                "contextguard-anthropic-p3",
            ],
        )
        self.assertNotIn(value.decode(), str(run.call_args))

    def test_selection_mutation_changes_request_batch_approval_and_plan_identities(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan, selection = self._plan(runner)
        with mock.patch.object(runner, "_bound_selection_identity", return_value=selection):
            baseline_batches = runner.build_batch_plans(plan)
            baseline_plan_sha = runner.request_plan_sha256(plan)
            baseline_scope = runner.build_approval_scope(
                contract=contract,
                batch=baseline_batches[0],
                plan_sha256=baseline_plan_sha,
            )
            changed = copy.deepcopy(plan)
            changed[0]["selection_identity"] = copy.deepcopy(
                changed[0]["selection_identity"]
            )
            changed[0]["selection_identity"]["selected"]["prompt_sha256"] = "d" * 64
            changed[0]["request_id"] = runner._request_identity(changed[0])
            changed_batches = runner.build_batch_plans(changed)
            changed_plan_sha = runner.request_plan_sha256(changed)
            changed_scope = runner.build_approval_scope(
                contract=contract,
                batch=changed_batches[0],
                plan_sha256=changed_plan_sha,
            )
        self.assertNotEqual(plan[0]["request_id"], changed[0]["request_id"])
        self.assertNotEqual(baseline_batches[0]["plan_sha256"], changed_batches[0]["plan_sha256"])
        self.assertNotEqual(baseline_plan_sha, changed_plan_sha)
        self.assertEqual(baseline_scope["body_sha256"], changed_scope["body_sha256"])
        self.assertNotEqual(
            baseline_scope["selection_identities"], changed_scope["selection_identities"]
        )

    def test_bound_policy_capture_and_report_tampering_refuses(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        for name in ("budget_policy", "budget_policy_report", "provider_input_capture"):
            changed = copy.deepcopy(contract)
            changed["artifacts"][name]["sha256"] = "0" * 64
            with self.subTest(name=name), self.assertRaisesRegex(
                runner.LiveRunError, "invalid_artifacts"
            ):
                runner.validate_contract(changed, repo_root=ROOT)

    def test_prompt_mutation_refuses_before_request_body_construction(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan, selection = self._plan(runner, count=1)
        changed = dict(plan[0])
        changed["prompt"] = "mutated provider input"
        with mock.patch.object(runner, "_bound_selection_identity", return_value=selection):
            with self.assertRaisesRegex(
                runner.LiveRunError, "payload_identity_mismatch"
            ):
                runner.build_request_body(changed, contract=contract)

    def test_v4_domains_state_and_capsule_schema_do_not_accept_v3_values(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan, _selection = self._plan(runner)
        with mock.patch.object(runner, "_bound_selection_identity", return_value=plan[0]["selection_identity"]):
            batches = runner.build_batch_plans(plan)
            reservation = runner.calculate_worst_case_reservation(
                contract=contract, batches=batches
            )
        self.assertTrue(runner.SCHEMA.endswith("/v4"))
        self.assertTrue(runner.EVIDENCE_SCHEMA.endswith("/v4"))
        self.assertTrue(runner._request_identity(plan[0]).startswith("v4-request-"))
        state: dict[str, object] = {}
        with mock.patch.object(runner, "_bound_selection_identity", return_value=plan[0]["selection_identity"]):
            runner._initialize_ledger(
                state,
                contract=contract,
                batches=batches,
                plan_sha256=runner.request_plan_sha256(plan),
                reservation=reservation,
            )
        self.assertEqual(state["schema_version"], "contextguard.p3-v4-ledger/v1")
        old_state = {**state, "schema_version": "contextguard.p3-v3-ledger/v1"}
        with self.assertRaisesRegex(runner.LiveRunError, "ledger_schema_mismatch"):
            with mock.patch.object(runner, "_bound_selection_identity", return_value=plan[0]["selection_identity"]):
                runner._initialize_ledger(
                    old_state,
                    contract=contract,
                    batches=batches,
                    plan_sha256=runner.request_plan_sha256(plan),
                    reservation=reservation,
                )

    def test_public_evidence_seals_exact_requested_and_selected_identity(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan, selection = self._plan(runner)
        response = json.dumps({
            "content": [{"text": "READY", "type": "text"}],
            "id": "msg-v4-evidence",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_reason": "end_turn",
            "type": "message",
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }, separators=(",", ":"), sort_keys=True).encode()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state, output = root / "state", root / "output"
            state.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            with mock.patch.object(runner, "_bound_selection_identity", return_value=selection), \
                mock.patch.object(runner, "_expected_bound_selection", return_value=selection):
                result = runner._execute_schedule_test_core(
                    contract=contract,
                    plan=plan,
                    state_root=state,
                    output_root=output,
                    approval_consume=lambda scope: {"approved": scope["batch_id"]},
                    invoke=lambda item: {
                        "body": response, "http_status": 200,
                        "provider_request_id": None,
                    },
                    scorer_loader=lambda: (lambda capsules, prepared: {
                        "exact_historical_patch_units": len(prepared),
                        "failed_units": 0,
                        "passed_units": len(prepared),
                        "scorer_artifact_sha256": runner.EXPECTED_SCORER_SHA256,
                        "status": "complete",
                        "total_units": len(prepared),
                    }),
                )
                evidence = json.loads((output / "p3-api-evidence.json").read_bytes())
                self.assertEqual(result["status"], "completed")
                self.assertEqual(len(evidence["sealed_units"]), 288)
                self.assertTrue(all(
                    unit["selection_identity"] == selection
                    for unit in evidence["sealed_units"]
                ))
                changed = copy.deepcopy(evidence)
                changed["sealed_units"][0]["selection_identity"]["requested"]["arm_id"] = "a000"
                with self.assertRaisesRegex(
                    runner.LiveRunError, "invalid_public_evidence"
                ):
                    runner.validate_public_evidence(
                        changed, contract_raw=runner.canonical(contract)
                    )
                changed = copy.deepcopy(evidence)
                changed["scoring"].update({
                    "exact_historical_patch_units": 288,
                    "failed_units": 1,
                    "passed_units": 287,
                })
                changed["analysis"] = copy.deepcopy(changed["scoring"])
                with self.assertRaisesRegex(
                    runner.LiveRunError, "invalid_public_evidence"
                ):
                    runner.validate_public_evidence(
                        changed, contract_raw=runner.canonical(contract)
                    )

    def test_authorized_entry_has_no_injectable_invoke_scorer_selector_or_plan(self) -> None:
        runner = load_runner()
        parameters = inspect.signature(runner.run_live_authorized).parameters
        for forbidden in ("plan", "invoke", "scorer_loader", "selector", "approval_consume"):
            self.assertNotIn(forbidden, parameters)
        self.assertIn("approvals", parameters)
        self.assertIn("api_key", parameters)

    def test_v3_transport_capsule_is_not_accepted_by_v4_reader(self) -> None:
        runner = load_runner()
        plan, selection = self._plan(runner, count=1)
        identity = plan[0]
        with tempfile.TemporaryDirectory() as name:
            private = Path(name)
            key = b"z" * 32
            runner._write_transport_capsule(
                private,
                identity["scheduled_unit_id"],
                {"body": b"body", "http_status": 200, "provider_request_id": None},
                key,
                identity,
            )
            metadata_path = private / (
                runner._capsule_stem(identity["scheduled_unit_id"]) + ".json"
            )
            metadata = json.loads(metadata_path.read_bytes())
            metadata["capsule_hmac_sha256"] = "0" * 64
            metadata_path.write_bytes(runner.canonical(metadata))
            with self.assertRaisesRegex(
                runner.LiveRunError, "transport_capsule_tampered"
            ):
                runner._read_transport_capsule(
                    private, identity["scheduled_unit_id"], key, identity
                )

    def test_authorized_output_root_lock_serializes_distinct_state_roots(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan, selection = self._plan(runner)
        response = {
            "body": json.dumps({
                "content": [{"text": "READY", "type": "text"}],
                "id": "msg-v4-lock",
                "model": "claude-sonnet-5",
                "role": "assistant",
                "stop_reason": "end_turn",
                "type": "message",
                "usage": {"input_tokens": 10, "output_tokens": 2},
            }, separators=(",", ":"), sort_keys=True).encode(),
            "http_status": 200,
            "provider_request_id": None,
        }
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            output = root / "shared-output"
            output.mkdir(mode=0o700)
            state_roots = [root / "state-a", root / "state-b"]
            for state in state_roots:
                state.mkdir(mode=0o700)
            calls: list[str] = []
            errors: list[BaseException] = []
            first_invoke_entered = threading.Event()
            release_first_invoke = threading.Event()
            second_lock_attempted = threading.Event()

            def invoke(item):
                calls.append(item["scheduled_unit_id"])
                if len(calls) == 1:
                    first_invoke_entered.set()
                    if not release_first_invoke.wait(timeout=30):
                        raise AssertionError("first invoke was not released")
                return response

            original_lock = runner._with_authorized_run_lock

            def observed_lock(lock_root, function):
                if threading.current_thread().name == "second-authorized-run":
                    second_lock_attempted.set()
                return original_lock(lock_root, function)

            def run(state_root: Path) -> None:
                try:
                    runner._execute_schedule_test_core(
                        contract=contract,
                        plan=plan,
                        state_root=state_root,
                        output_root=output,
                        approval_consume=lambda scope: {"approved": scope["batch_id"]},
                        invoke=invoke,
                        scorer_loader=lambda: (lambda capsules, prepared: {
                            "exact_historical_patch_units": len(prepared),
                            "failed_units": 0,
                            "passed_units": len(prepared),
                            "scorer_artifact_sha256": runner.EXPECTED_SCORER_SHA256,
                            "status": "complete",
                            "total_units": len(prepared),
                        }),
                        _authorized_lock_root=output,
                    )
                except BaseException as error:  # report both worker failures
                    errors.append(error)

            first = threading.Thread(
                name="first-authorized-run", target=run, args=(state_roots[0],)
            )
            second = threading.Thread(
                name="second-authorized-run", target=run, args=(state_roots[1],)
            )
            with (
                mock.patch.object(
                    runner, "_with_authorized_run_lock", side_effect=observed_lock
                ),
                mock.patch.object(
                    runner, "_bound_selection_identity", return_value=selection
                ),
                mock.patch.object(
                    runner, "_expected_bound_selection", return_value=selection
                ),
            ):
                first.start()
                self.assertTrue(first_invoke_entered.wait(timeout=30))
                second.start()
                self.assertTrue(second_lock_attempted.wait(timeout=30))
                release_first_invoke.set()
                completion_deadline = time.monotonic() + 120
                for worker in (first, second):
                    worker.join(
                        timeout=max(0.0, completion_deadline - time.monotonic())
                    )
            self.assertFalse(first.is_alive() or second.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], runner.LiveRunError)
            self.assertIn(
                str(errors[0]),
                {"authorization_busy", "output_exists"},
            )
            self.assertEqual(len(calls), 288)

    def test_opt_in_frozen_corpus_preparation_has_no_selected_growth(self) -> None:
        corpus_value = os.environ.get("CONTEXTGUARD_V3_CORPUS_ROOT")
        if not corpus_value:
            self.skipTest("set CONTEXTGUARD_V3_CORPUS_ROOT to run the 288-cell integration")
        corpus_root = Path(corpus_value).expanduser().resolve()
        if not corpus_root.is_dir():
            self.skipTest("CONTEXTGUARD_V3_CORPUS_ROOT is not a directory")
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan = runner.prepare_live_plan(
            contract=contract, repo_root=ROOT, corpus_root=corpus_root
        )
        self.assertEqual(len(plan), 288)
        self.assertEqual(len({item["request_id"] for item in plan}), 288)
        boundary = [
            item for item in plan
            if item["task_id"] == "requests_boundary_hardening"
            and item["arm_id"] == "a111"
        ]
        self.assertTrue(boundary)
        self.assertTrue(all(
            item["selection_identity"]["selected"]["arm_id"] == "a110"
            for item in boundary
        ))
        self.assertTrue(all(
            item["selection_identity"]["selected"]["prompt_bytes"]
            <= item["selection_identity"]["ordinary_prompt_ceiling_bytes"]
            for item in plan
        ))
        report = json.loads(REPORT.read_bytes())
        self.assertEqual(
            report["policy_summary"]["factor_decisions"],
            {
                "adaptive": {"applied": 24, "suppressed_or_no_op": 24},
                "graph_closure": {"applied": 0, "suppressed_or_no_op": 48},
                "symbol_memory": {"applied": 12, "suppressed_or_no_op": 36},
            },
        )


if __name__ == "__main__":
    unittest.main()
