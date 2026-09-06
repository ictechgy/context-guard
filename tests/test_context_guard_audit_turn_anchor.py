"""The reducer must expose where a response group started, not only where it ended.

`UsageReducer` groups the transcript rows of one assistant response by message id
and selects the LAST of them, because that row carries the final usage numbers.
A consumer that snapshots per row and asks "what entered the context before this
turn" cannot use that selection: by the time the last row arrives, the answer was
observed several rows earlier. `group_first_row_ordinal` is that earlier point.

These tests pin the field's contract. They do not exercise the audit, which
reads it; the audit lives behind a Gate-B freeze and changes separately.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILE_IDENTITY = "a" * 64


def load_reducer(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"reducer module is unavailable: {path}")
    module = importlib.util.module_from_spec(spec)
    # dataclass() resolves annotations through sys.modules on 3.12+.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def usage_row(message_id: str, created: int, timestamp: str) -> dict:
    return {
        "type": "assistant",
        "sessionId": "session-1",
        "timestamp": timestamp,
        "message": {
            "id": message_id,
            "role": "assistant",
            "model": "claude-test",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "cache_creation_input_tokens": created,
                "cache_read_input_tokens": 0,
            },
        },
    }


class GroupFirstRowOrdinalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reducer_module = load_reducer(
            ROOT / "context-guard-kit" / "transcript_usage_reducer.py", "cg_reducer_kit"
        )

    def reduce(self, rows: list[tuple[dict, int]]):
        reducer = self.reducer_module.UsageReducer()
        for row, ordinal in rows:
            reducer.observe(row, file_identity=FILE_IDENTITY, row_ordinal=ordinal)
        return reducer.finalize()

    def test_multi_row_response_anchors_at_its_first_row(self) -> None:
        """One response split over three rows: selection is last, anchor is first."""
        rows = [
            (usage_row("msg_a", 500, f"2026-09-06T00:00:0{index}Z"), 10 + index)
            for index in range(3)
        ]
        selections = self.reduce(rows).selections
        self.assertEqual(len(selections), 1)
        selection = selections[0]
        self.assertEqual(selection.row_ordinal, 12)
        self.assertEqual(selection.group_first_row_ordinal, 10)

    def test_single_row_response_anchors_at_itself(self) -> None:
        selections = self.reduce(
            [(usage_row("msg_b", 700, "2026-09-06T00:00:09Z"), 20)]
        ).selections
        self.assertEqual(len(selections), 1)
        self.assertEqual(selections[0].row_ordinal, 20)
        self.assertEqual(selections[0].group_first_row_ordinal, 20)

    def test_anchor_is_the_minimum_ordinal_not_the_observation_order(self) -> None:
        """observe() takes a caller-supplied ordinal, so append order proves nothing."""
        selections = self.reduce(
            [
                (usage_row("msg_c", 1, "2026-09-06T00:01:05Z"), 5),
                (usage_row("msg_c", 1, "2026-09-06T00:01:02Z"), 2),
            ]
        ).selections
        self.assertEqual(len(selections), 1)
        self.assertEqual(selections[0].group_first_row_ordinal, 2)

    def test_separate_responses_keep_separate_anchors(self) -> None:
        rows = [
            (usage_row("msg_d", 100, "2026-09-06T00:02:00Z"), 1),
            (usage_row("msg_d", 100, "2026-09-06T00:02:01Z"), 2),
            (usage_row("msg_e", 200, "2026-09-06T00:02:05Z"), 7),
        ]
        anchors = {
            selection.row_ordinal: selection.group_first_row_ordinal
            for selection in self.reduce(rows).selections
        }
        self.assertEqual(anchors, {2: 1, 7: 7})

    def test_field_is_last_so_the_frozen_dataclass_still_constructs(self) -> None:
        """A defaulted field ahead of a required one raises TypeError at import."""
        fields = list(self.reducer_module.UsageSelection.__dataclass_fields__)
        self.assertEqual(fields[-1], "group_first_row_ordinal")

    def test_schema_string_is_unchanged(self) -> None:
        """statusline.sh silently disables its cache metrics on a schema mismatch."""
        self.assertEqual(self.reducer_module.REDUCER_SCHEMA, "usage-reducer-v2")

    def test_packaged_reducer_reports_the_same_anchor(self) -> None:
        packaged = load_reducer(
            ROOT / "plugins" / "context-guard" / "lib" / "transcript_usage_reducer.py",
            "cg_reducer_packaged",
        )
        reducer = packaged.UsageReducer()
        for index in range(2):
            reducer.observe(
                usage_row("msg_f", 42, f"2026-09-06T00:03:0{index}Z"),
                file_identity=FILE_IDENTITY,
                row_ordinal=30 + index,
            )
        selections = reducer.finalize().selections
        self.assertEqual(len(selections), 1)
        self.assertEqual(selections[0].group_first_row_ordinal, 30)
        self.assertEqual(selections[0].row_ordinal, 31)


class ReducerTimestampAnchorTests(unittest.TestCase):
    """Timestamps decide the selection; they must not decide the anchor."""

    def setUp(self) -> None:
        self.reducer_module = load_reducer(
            ROOT / "context-guard-kit" / "transcript_usage_reducer.py", "cg_reducer_ts"
        )

    def test_rows_without_timestamps_still_anchor_at_the_lowest_ordinal(self) -> None:
        reducer = self.reducer_module.UsageReducer()
        for ordinal in (9, 4):
            row = usage_row("msg_g", 7, "2026-09-06T00:04:00Z")
            del row["timestamp"]
            reducer.observe(row, file_identity=FILE_IDENTITY, row_ordinal=ordinal)
        selections = reducer.finalize().selections
        self.assertEqual(len(selections), 1)
        self.assertEqual(selections[0].group_first_row_ordinal, 4)

    def test_anchor_follows_the_ordinal_when_timestamps_disagree_with_it(self) -> None:
        """Separate the two axes, which every other fixture here conflates.

        Elsewhere timestamp order and ordinal order agree, so "the ordinal of
        the group's earliest-timestamped row" would satisfy the whole suite
        without being the contract. Here they are deliberately opposed: the row
        with the LOWER ordinal carries the LATER timestamp. Selection follows the
        timestamp and lands on ordinal 4; the anchor is the lowest ordinal, which
        is also 4 — while the timestamp-based reading would answer 9.
        """
        reducer = self.reducer_module.UsageReducer()
        reducer.observe(
            usage_row("msg_h", 11, "2026-09-06T00:05:00Z"),  # earliest timestamp
            file_identity=FILE_IDENTITY,
            row_ordinal=9,
        )
        reducer.observe(
            usage_row("msg_h", 11, "2026-09-06T00:05:30Z"),  # latest timestamp
            file_identity=FILE_IDENTITY,
            row_ordinal=4,
        )
        selections = reducer.finalize().selections
        self.assertEqual(len(selections), 1)
        selection = selections[0]
        self.assertEqual(selection.row_ordinal, 4, "selection follows the timestamp")
        self.assertEqual(
            selection.group_first_row_ordinal,
            4,
            "anchor is the lowest ordinal, not the earliest-timestamped row",
        )

    def test_anchor_ignores_a_late_timestamp_on_the_lowest_ordinal(self) -> None:
        """The mirror image, so neither direction can pass by coincidence."""
        reducer = self.reducer_module.UsageReducer()
        reducer.observe(
            usage_row("msg_i", 13, "2026-09-06T00:06:30Z"),  # latest timestamp
            file_identity=FILE_IDENTITY,
            row_ordinal=3,
        )
        reducer.observe(
            usage_row("msg_i", 13, "2026-09-06T00:06:00Z"),  # earliest timestamp
            file_identity=FILE_IDENTITY,
            row_ordinal=8,
        )
        selections = reducer.finalize().selections
        self.assertEqual(len(selections), 1)
        selection = selections[0]
        self.assertEqual(selection.row_ordinal, 3, "selection follows the timestamp")
        self.assertEqual(selection.group_first_row_ordinal, 3)

    def test_the_same_id_reappearing_far_later_still_anchors_at_its_first_row(self) -> None:
        """Non-adjacent rows sharing one id are one group, anchored at the first.

        The audit approximates the reducer's grouping with (file, session,
        message id) and treats a repeat of that id as a boundary. Pinning the
        reducer side here means the two cannot silently disagree about which
        row a consumer should read.
        """
        reducer = self.reducer_module.UsageReducer()
        reducer.observe(
            usage_row("msg_far", 17, "2026-09-06T00:08:00Z"),
            file_identity=FILE_IDENTITY,
            row_ordinal=4,
        )
        reducer.observe(  # a different response lands in between
            usage_row("msg_between", 5, "2026-09-06T00:08:10Z"),
            file_identity=FILE_IDENTITY,
            row_ordinal=40,
        )
        reducer.observe(
            usage_row("msg_far", 17, "2026-09-06T00:08:20Z"),
            file_identity=FILE_IDENTITY,
            row_ordinal=90,
        )
        anchors = {
            selection.row_ordinal: selection.group_first_row_ordinal
            for selection in reducer.finalize().selections
        }
        self.assertEqual(anchors, {90: 4, 40: 40})

    def test_no_id_fallback_anchors_within_its_own_group(self) -> None:
        """Rows with no message id group by row digest, so only identical rows meet.

        The anchor is then the lowest ordinal at which that exact row appeared,
        which is a weaker statement than "what preceded this turn"; the field's
        contract comment says so, and `used_no_id_fallback` marks the selection.
        The fixture observes ordinal 6 before ordinal 2 so that "lowest" cannot
        be read as "first observed".
        """
        reducer = self.reducer_module.UsageReducer()
        for ordinal in (6, 2):
            row = usage_row("unused", 21, "2026-09-06T00:07:00Z")
            del row["message"]["id"]
            reducer.observe(row, file_identity=FILE_IDENTITY, row_ordinal=ordinal)
        selections = reducer.finalize().selections
        self.assertEqual(len(selections), 1)
        selection = selections[0]
        self.assertTrue(selection.used_no_id_fallback)
        self.assertEqual(selection.group_first_row_ordinal, 2)


class TurnAttributionTests(unittest.TestCase):
    """The audit must attribute a turn to what actually preceded *that* turn.

    Two defects made it do otherwise, and they have to be fixed together.
    `last_result` is reset only per file, so a turn with no new tool result
    inherited the previous turn's label. And the per-turn snapshot was taken on
    every accepted row and cleared each time, while the reducer selects the LAST
    row of a response group — so a multi-row response read an already-cleared
    snapshot. Fixing the label alone is worse than shipping neither: every
    multi-row turn would then be relabelled `no_tool_result`.

    Each test below asserts the LABEL before the counters, so a tree with the
    label fix and not the anchor fails here on the label.
    """

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(ROOT / "context-guard-kit"))
        import claude_transcript_cost_audit as audit_module

        cls.audit = audit_module

    def report(self, rows: list[dict]) -> dict:
        import json as _json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (root / "session.jsonl").open("w", encoding="utf-8") as handle:
                for row in rows:
                    handle.write(_json.dumps(row, ensure_ascii=False) + "\n")
            return self.audit.summary_json(self.audit.scan([str(root)]), 15)

    def section(self, rows: list[dict]) -> dict:
        return self.report(rows)["new_tokens_per_turn"]["by_preceding_tool"]

    @staticmethod
    def tool_use(use_id: str, name: str) -> dict:
        return {
            "type": "assistant",
            "sessionId": "s1",
            "message": {
                "role": "assistant",
                "id": f"call_{use_id}",
                "content": [{"type": "tool_use", "id": use_id, "name": name, "input": {}}],
            },
        }

    @staticmethod
    def tool_result(use_id: str, text: str) -> dict:
        return {
            "type": "user",
            "sessionId": "s1",
            "message": {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": use_id, "content": text}],
            },
        }

    @staticmethod
    def usage(message_id: str, created: int, cache_read: int, timestamp: str) -> dict:
        return {
            "type": "assistant",
            "sessionId": "s1",
            "timestamp": timestamp,
            "message": {
                "role": "assistant",
                "id": message_id,
                "model": "claude-test",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 5,
                    "cache_creation_input_tokens": created,
                    "cache_read_input_tokens": cache_read,
                },
            },
        }

    def test_a_multi_row_response_still_sees_what_preceded_it(self) -> None:
        """Three parallel results, then one response split over two rows.

        The reducer selects the second row. Reading the snapshot there finds it
        already cleared, so before the fix this turn reported no results at all.
        """
        rows = [
            self.tool_use("u1", "Bash"),
            self.tool_use("u2", "Bash"),
            self.tool_use("u3", "Read"),
            self.tool_result("u1", "x" * 6_000),
            self.tool_result("u2", "y" * 6_000),
            self.tool_result("u3", "z" * 6_000),
            self.usage("msg_multi", 5_000, 900_000, "2026-09-06T10:00:00Z"),
            self.usage("msg_multi", 5_000, 900_000, "2026-09-06T10:00:01Z"),
        ]
        section = self.section(rows)
        labels = {row["label"]: row for row in section["rows"]}
        self.assertIn("Read", labels, "the turn must keep the tool that preceded it")
        self.assertNotIn(
            "no_tool_result",
            labels,
            "a multi-row response must not be read as having no preceding result",
        )
        self.assertEqual(section["multi_result_turns"], 1)

    def test_b_a_turn_with_no_new_result_does_not_inherit_the_previous_label(self) -> None:
        """A Bash turn, then a plain prompt turn. Only the first is Bash's."""
        rows = [
            self.tool_use("u1", "Bash"),
            self.tool_result("u1", "x" * 6_000),
            self.usage("msg_1", 2_000, 900_000, "2026-09-06T11:00:00Z"),
            {"type": "user", "sessionId": "s1", "message": {"role": "user", "content": "next question"}},
            self.usage("msg_2", 80_000, 900_000, "2026-09-06T11:01:00Z"),
        ]
        section = self.section(rows)
        labels = {row["label"]: row for row in section["rows"]}
        self.assertIn("no_tool_result", labels, "the prompt turn must not be blamed on Bash")
        self.assertEqual(labels["no_tool_result"]["cache_creation_tokens"], 80_000)
        self.assertEqual(labels["Bash"]["cache_creation_tokens"], 2_000)
        self.assertEqual(labels["Bash"]["turns"], 1)

    def test_the_three_way_cache_axis_partitions_every_counted_turn(self) -> None:
        """cold_start / cache_rewrite / incremental are orthogonal to the rows.

        They must sum to the same total, or `covers_all_turns` is a lie.
        """
        rows = [
            self.tool_use("u1", "Bash"),
            self.tool_result("u1", "x" * 6_000),
            self.usage("msg_cold", 3_000, 0, "2026-09-06T12:00:00Z"),
            self.tool_use("u2", "Bash"),
            self.tool_result("u2", "y" * 6_000),
            self.usage("msg_rewrite", 9_000, 4_000, "2026-09-06T12:01:00Z"),
            self.tool_use("u3", "Bash"),
            self.tool_result("u3", "z" * 6_000),
            self.usage("msg_incr", 1_000, 500_000, "2026-09-06T12:02:00Z"),
        ]
        section = self.section(rows)
        self.assertEqual(section["cold_start_turns"], 1)
        self.assertEqual(section["cold_start_tokens"], 3_000)
        self.assertEqual(section["cache_rewrite_turns"], 1)
        self.assertEqual(section["cache_rewrite_tokens"], 9_000)
        self.assertEqual(section["incremental_turns"], 1)
        self.assertEqual(section["incremental_tokens"], 1_000)
        self.assertEqual(
            section["cold_start_tokens"]
            + section["cache_rewrite_tokens"]
            + section["incremental_tokens"],
            section["total_cache_creation_tokens"],
        )
        self.assertTrue(section["covers_all_turns"])
        self.assertNotIn(
            "cache_rewrite",
            {row["label"] for row in section["rows"]},
            "the cache axis must never become a row; it would outrank every tool",
        )

    def test_a_result_arriving_between_two_rows_lands_on_the_next_turn(self) -> None:
        """Snapshots reset at group boundaries, so nothing falls between turns."""
        rows = [
            self.tool_use("u1", "Bash"),
            self.tool_result("u1", "x" * 6_000),
            self.usage("msg_a", 2_000, 900_000, "2026-09-06T13:00:00Z"),
            self.tool_use("u2", "Read"),
            self.tool_result("u2", "y" * 6_000),
            self.usage("msg_a", 2_000, 900_000, "2026-09-06T13:00:01Z"),
            self.usage("msg_b", 4_000, 900_000, "2026-09-06T13:00:02Z"),
        ]
        section = self.section(rows)
        labels = {row["label"]: row for row in section["rows"]}
        self.assertIn("Bash", labels)
        self.assertIn("Read", labels, "the mid-response Read must be attributed, not dropped")
        self.assertEqual(labels["Read"]["cache_creation_tokens"], 4_000)
    def test_scanning_does_not_leave_the_recursion_limit_raised(self) -> None:
        """`parse_json_line` raises a process-global limit; scan must put it back.

        Leaving it raised makes every later `json.loads` in the same process
        accept nesting the rest of the codebase treats as hostile. It was found
        exactly that way: adding audit tests to the core partition made the
        benchmark stream parser accept a 2,000-deep payload it is supposed to
        reject, and CI failed twice on a test this change never touches.
        """
        import sys as _sys

        before = _sys.getrecursionlimit()
        self.section(
            [
                self.tool_use("u1", "Bash"),
                self.tool_result("u1", "x" * 100),
                self.usage("msg_only", 1_000, 900_000, "2026-09-06T14:00:00Z"),
            ]
        )
        self.assertEqual(_sys.getrecursionlimit(), before)

    def test_scanning_restores_the_limit_even_when_it_raises(self) -> None:
        """The restore is a finally, not a happy-path line."""
        import sys as _sys

        before = _sys.getrecursionlimit()
        with self.assertRaises(ZeroDivisionError):
            with self.audit.restored_recursion_limit():
                _sys.setrecursionlimit(before + 5_000)
                raise ZeroDivisionError("boom")
        self.assertEqual(_sys.getrecursionlimit(), before)


if __name__ == "__main__":  # pragma: no cover - manual invocation
    unittest.main()
