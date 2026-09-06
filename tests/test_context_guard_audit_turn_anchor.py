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
        selection = reducer.finalize().selections[0]
        self.assertEqual(selection.row_ordinal, 3, "selection follows the timestamp")
        self.assertEqual(selection.group_first_row_ordinal, 3)

    def test_no_id_fallback_anchors_within_its_own_group(self) -> None:
        """Rows with no message id group by row digest, so only identical rows meet.

        The anchor is then the first ordinal at which that exact row appeared,
        which is a weaker statement than "what preceded this turn"; the field's
        contract comment says so, and `used_no_id_fallback` marks the selection.
        """
        reducer = self.reducer_module.UsageReducer()
        for ordinal in (6, 2):
            row = usage_row("unused", 21, "2026-09-06T00:07:00Z")
            del row["message"]["id"]
            reducer.observe(row, file_identity=FILE_IDENTITY, row_ordinal=ordinal)
        selection = reducer.finalize().selections[0]
        self.assertTrue(selection.used_no_id_fallback)
        self.assertEqual(selection.group_first_row_ordinal, 2)


if __name__ == "__main__":  # pragma: no cover - manual invocation
    unittest.main()
