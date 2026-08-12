from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
G2 = ROOT / "research/provider-free-roadmap/g2"
V1 = G2 / "v1"
VERIFY = V1 / "verify.py"
LOCK = G2 / "freeze-lock.json"
ARMS = ("ordinary", "adaptive_only", "symbol_only", "combined")
FORBIDDEN_PUBLIC_KEYS = {
    "answer_signature",
    "expected_output",
    "graph_evidence",
    "hidden_oracle",
    "oracle",
    "required_paths",
    "required_symbols",
}


class G2AblationContractTests(unittest.TestCase):
    def load_verifier(self, root: Path = ROOT):
        path = root / VERIFY.relative_to(ROOT)
        self.assertTrue(path.is_file(), "versioned g2 verifier is missing")
        module = types.ModuleType(f"g2_verify_{id(root)}")
        module.__file__ = str(path)
        source = (
            globals().get("__G2_CAPTURED_VERIFIER_BYTES__")
            if root == ROOT
            else None
        ) or path.read_bytes()
        exec(compile(source, str(path), "exec"), module.__dict__, module.__dict__)
        return module

    def verify(self, root: Path = ROOT, **kwargs):
        if root == ROOT:
            injected = {
                "captured_lock_bytes": globals().get("__G2_CAPTURED_LOCK_BYTES__"),
                "expected_lock_sha256": globals().get("__G2_EXPECTED_LOCK_SHA256__"),
                "expected_tree_root": globals().get("__G2_EXPECTED_TREE_ROOT__"),
            }
            for key, value in injected.items():
                if value is not None:
                    kwargs.setdefault(key, value)
        return self.load_verifier(root).verify_repository(root, **kwargs)

    def copied_root(self) -> Path:
        self.assertTrue(V1.is_dir(), "versioned g2 corpus is missing")
        temporary = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, temporary)
        for relative in (
            Path("research/provider-free-roadmap/g2"),
            Path("context-guard-kit"),
            Path("plugins/context-guard/bin/context-guard-pack"),
        ):
            source = ROOT / relative
            destination = temporary / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)
        return temporary

    def write_json(self, path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def read_json(self, root: Path, relative: str) -> dict:
        path = root / relative
        self.assertTrue(path.is_file(), f"missing JSON artifact: {relative}")
        return json.loads(path.read_text(encoding="utf-8"))

    def relock(self, root: Path) -> None:
        # Synthetic mutation fixtures must not inherit the caller's umask.
        # Preserve executable files copied from the frozen tree; newly-created
        # fixture files are data and use the contract's canonical 0644 mode.
        for path in (root / V1.relative_to(ROOT)).rglob("*"):
            if path.is_file() and not path.is_symlink():
                path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
        verifier = self.load_verifier(root)
        self.write_json(root / LOCK.relative_to(ROOT), verifier.rebuild_lock(root))

    def update_fixture_tree_hash(self, root: Path, task_id: str) -> None:
        verifier = self.load_verifier(root)
        path = root / "research/provider-free-roadmap/g2/v1/tasks.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        task = next(item for item in value["tasks"] if item["task_id"] == task_id)
        fixture = root / "research/provider-free-roadmap/g2/v1" / task["fixture_root"]
        task["fixture_tree_sha256"] = verifier.fixture_tree_hash(fixture)
        self.write_json(path, value)

    def mutate_json(self, root: Path, relative: str, mutation, *, relock: bool = True) -> Path:
        path = root / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        mutation(value)
        self.write_json(path, value)
        if relock:
            self.relock(root)
        return path

    def assert_rejected(self, root: Path, pattern: str) -> None:
        verifier = self.load_verifier(root)
        with self.assertRaisesRegex(verifier.VerificationError, pattern):
            verifier.verify_repository(root)

    def test_versioned_freeze_executes_real_bound_packer(self) -> None:
        report = self.verify()
        self.assertEqual(report["schema_version"], "contextguard.g2-verification-report/v1")
        self.assertEqual(report["task_count"], 6)
        self.assertEqual(report["sealed_output_count"], 24)
        self.assertEqual(report["arms"], list(ARMS))
        self.assertEqual(report["adaptive_label_count"], 24)
        self.assertEqual(report["adaptive_label_score_count"], 48)
        self.assertEqual(report["required_symbol_count"], 3)
        self.assertEqual(report["structure_profile_count"], 6)

    def test_hidden_adaptive_labels_cover_every_candidate_and_both_adaptive_arms(self) -> None:
        oracle = self.read_json(
            ROOT, "research/provider-free-roadmap/g2/v1/scorer-only/oracle.json"
        )
        for entry in oracle["entries"]:
            with self.subTest(task_id=entry["task_id"]):
                self.assertIn("adaptive_labels", entry)
                labels = entry["adaptive_labels"]
                self.assertEqual(len(labels), 4)
                self.assertEqual(
                    {item["decision"] for item in labels}, {"retain", "drop"}
                )
                self.assertTrue(
                    any(
                        item["decision"] == "retain" and item["origin"] == "heuristic"
                        for item in labels
                    )
                )
                self.assertTrue(
                    any(
                        item["decision"] == "drop" and item["origin"] == "heuristic"
                        for item in labels
                    )
                )

        report = self.verify()
        scored = report["adaptive_label_scores"]
        self.assertEqual(len(scored), 48)
        self.assertTrue(all(item["correct"] is True for item in scored))
        self.assertEqual(
            {(item["task_id"], item["arm"]) for item in scored},
            {
                (entry["task_id"], arm)
                for entry in oracle["entries"]
                for arm in ("adaptive_only", "combined")
            },
        )

    def test_required_symbols_must_exist_in_fixture_and_bound_packer_evidence(self) -> None:
        root = self.copied_root()
        self.mutate_json(
            root,
            "research/provider-free-roadmap/g2/v1/scorer-only/oracle.json",
            lambda value: value["entries"][1].update(
                required_symbols=["fabricated_missing_symbol"]
            ),
        )
        self.assert_rejected(root, "required symbol")

    def test_required_symbol_must_live_on_the_neighbor_missed_by_ordinary(self) -> None:
        root = self.copied_root()
        fixture = root / (
            "research/provider-free-roadmap/g2/v1/fixtures/train/realistic_fallback"
        )
        checksum = fixture / "app/routing/checksum.py"
        checksum.write_text(
            checksum.read_text(encoding="utf-8").replace(
                "compute_route", "compute_checksum"
            ),
            encoding="utf-8",
        )
        entry = fixture / "app/entry.py"
        entry.write_text(
            entry.read_text(encoding="utf-8")
            + "\n\ndef compute_route(color: str, offset: int) -> str:\n"
            + "    return f'SEED-{color}-{offset}'\n",
            encoding="utf-8",
        )
        self.update_fixture_tree_hash(root, "train_graph")
        self.relock(root)
        self.assert_rejected(root, "required symbol.*missed|missed.*required symbol")

    def test_public_contract_makes_no_unsupported_commonjs_claim(self) -> None:
        claims = []
        for pattern in ("*.md", "*.json"):
            for path in V1.rglob(pattern):
                if "commonjs" in path.read_text(encoding="utf-8").lower():
                    claims.append(path.relative_to(V1).as_posix())
        self.assertEqual(claims, [])

    def test_all_six_fixture_structures_have_distinct_derived_profiles(self) -> None:
        verifier = self.load_verifier()
        tasks = self.read_json(
            ROOT, "research/provider-free-roadmap/g2/v1/tasks.json"
        )["tasks"]
        derive = getattr(verifier, "derive_structure_profiles", None)
        self.assertTrue(callable(derive), "missing derived structure-profile verifier")
        profiles = derive(ROOT, tasks)
        self.assertEqual(len(profiles), 6)
        self.assertEqual(len(set(profiles.values())), 6)

    def test_graph_profiles_are_semantic_topologies_not_extension_signatures(self) -> None:
        verifier = self.load_verifier()
        tasks = self.read_json(
            ROOT, "research/provider-free-roadmap/g2/v1/tasks.json"
        )["tasks"]
        profiles = verifier.derive_graph_topology_profiles(ROOT, tasks)
        self.assertEqual(
            set(profiles), {"train_graph", "calibration_graph", "evaluation_graph"}
        )
        self.assertEqual(len({item["topology_sha256"] for item in profiles.values()}), 3)
        for task_id, profile in profiles.items():
            with self.subTest(task_id=task_id):
                self.assertNotIn("extensions", profile)
                self.assertGreaterEqual(profile["node_count"], 3)
                self.assertGreaterEqual(profile["directed_edge_count"], 2)
                self.assertEqual(profile["entry_to_required_shortest_path"], 1)
                self.assertEqual(profile["disconnected_edge_count"], 0)
                self.assertTrue(profile["import_mechanisms"])
                self.assertTrue(profile["depth_distribution"])
        self.assertEqual(profiles["train_graph"]["family"], "outgoing_chain")
        self.assertEqual(profiles["train_graph"]["required_adjacency_direction"], "outgoing")
        self.assertEqual(profiles["calibration_graph"]["family"], "outgoing_fork")
        self.assertTrue(profiles["calibration_graph"]["has_branching"])
        self.assertEqual(profiles["evaluation_graph"]["family"], "incoming_fan_in")
        self.assertTrue(profiles["evaluation_graph"]["has_reexport"])
        self.assertEqual(profiles["evaluation_graph"]["required_adjacency_direction"], "incoming")
        self.assertIn("esm_reexport", profiles["evaluation_graph"]["import_mechanisms"])

    def test_language_translated_graph_topology_clone_is_rejected(self) -> None:
        root = self.copied_root()
        fixture = root / (
            "research/provider-free-roadmap/g2/v1/fixtures/evaluation/realistic_fallback"
        )
        shutil.rmtree(fixture)
        (fixture / "app/routing").mkdir(parents=True)
        translated = {
            "app/entry.js": (
                'import { computeRoute } from "./routing/checksum.js";\n'
                "export const start = () => computeRoute();\n"
            ),
            "app/routing/checksum.js": (
                'import { BASE } from "./constants.js";\n'
                "export function computeRoute() { return BASE; }\n"
            ),
            "app/routing/constants.js": "export const BASE = 'clone';\n",
            "notes.md": "# translated graph fixture\n",
        }
        for relative, content in translated.items():
            path = fixture / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        tasks_path = root / "research/provider-free-roadmap/g2/v1/tasks.json"
        tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
        task = next(item for item in tasks["tasks"] if item["task_id"] == "evaluation_graph")
        task["pack"]["files"] = ["app/entry.js"]
        task["structure_id"] = "translated-language-chain-declaration"
        task["fixture_tree_sha256"] = self.load_verifier(root).fixture_tree_hash(fixture)
        self.write_json(tasks_path, tasks)
        self.relock(root)
        self.assert_rejected(root, "cloned graph topology")

    def test_graph_family_rejects_rewire_and_disconnected_padding_after_relock(self) -> None:
        cases = ("fork_to_chain", "fan_in_to_fork", "disconnected_padding")
        for case in cases:
            with self.subTest(case=case):
                root = self.copied_root()
                tasks_path = root / "research/provider-free-roadmap/g2/v1/tasks.json"
                tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
                if case == "fork_to_chain":
                    fixture = root / (
                        "research/provider-free-roadmap/g2/v1/fixtures/calibration/realistic_fallback"
                    )
                    entry = fixture / "src/controllers/entry.ts"
                    entry.write_text(
                        'import { AmberCalibrator } from "../calibration/amber-calibrator";\n'
                        "export const amberWindow = () => new AmberCalibrator(240).window(6);\n",
                        encoding="utf-8",
                    )
                    calibrator = fixture / "src/calibration/amber-calibrator.ts"
                    calibrator.write_text(
                        'import { recordProbe } from "../telemetry/probe";\n'
                        "export class AmberCalibrator { window(trim: number) { "
                        "recordProbe('x'); return `AMBER-${trim}`; } }\n",
                        encoding="utf-8",
                    )
                    task = next(item for item in tasks["tasks"] if item["task_id"] == "calibration_graph")
                    task["structure_id"] = "falsely-declared-calibration-fork"
                elif case == "fan_in_to_fork":
                    fixture = root / (
                        "research/provider-free-roadmap/g2/v1/fixtures/evaluation/realistic_fallback"
                    )
                    (fixture / "app/runner.js").write_text(
                        'import { verifyIndigo } from "../validators/index.js";\n'
                        'import { auditColor } from "../auditors/check.js";\n'
                        "export const releaseToken = () => verifyIndigo(800, 52) + auditColor('x');\n",
                        encoding="utf-8",
                    )
                    (fixture / "validators/index.js").write_text(
                        "export function verifyIndigo() { return 'INDIGO'; }\n",
                        encoding="utf-8",
                    )
                    (fixture / "auditors/check.js").write_text(
                        "export function auditColor() { return 'audit'; }\n",
                        encoding="utf-8",
                    )
                    task = next(item for item in tasks["tasks"] if item["task_id"] == "evaluation_graph")
                    task["structure_id"] = "falsely-declared-evaluation-fan-in"
                else:
                    fixture = root / (
                        "research/provider-free-roadmap/g2/v1/fixtures/train/realistic_fallback"
                    )
                    padding = fixture / "detached/padding.py"
                    padding.parent.mkdir()
                    padding.write_text("PADDING = 'detached'\n", encoding="utf-8")
                    task = next(item for item in tasks["tasks"] if item["task_id"] == "train_graph")
                    task["structure_id"] = "falsely-declared-connected-chain"
                task["fixture_tree_sha256"] = self.load_verifier(root).fixture_tree_hash(fixture)
                self.write_json(tasks_path, tasks)
                self.relock(root)
                self.assert_rejected(root, "graph topology family|disconnected graph topology")

    def test_jsts_static_import_scanner_excludes_comments_strings_and_templates(self) -> None:
        verifier = self.load_verifier()
        scan = getattr(verifier, "scan_jsts_static_module_specifiers", None)
        self.assertTrue(callable(scan), "missing bounded JS/TS lexical import scanner")
        source = r'''
// import { lineFake } from "./line-fake.js";
/* export { blockFake } from "./block-fake.js"; */
const ordinary = "import { stringFake } from './string-fake.js';";
const escaped = "prefix \" export { escapeFake } from './escape-fake.js';";
const template = `import { templateFake } from "./template-fake.js";
  ${"export { nestedFake } from './nested-fake.js';"}`;
import { realImport } from "./real-import.js";
export { realExport } from "../real-export.js";
'''
        records = scan(source)
        self.assertEqual(
            [(item["kind"], item["target"]) for item in records],
            [
                ("import", "./real-import.js"),
                ("reexport", "../real-export.js"),
            ],
        )
        for label, malformed in {
            "block_comment": "/* import { x } from './x.js';",
            "single_quote": "const x = 'unterminated",
            "double_quote": 'const x = "unterminated',
            "template": "const x = `unterminated ${value}",
            "escaped_quote": 'const x = "unterminated \\\"',
        }.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                verifier.VerificationError, "unterminated JS/TS lexical"
            ):
                scan(malformed)

    def test_jsts_static_import_scanner_rejects_every_noncomment_slash(self) -> None:
        verifier = self.load_verifier()
        for label, unsupported in {
            "plain_division": "const ratio = numerator / denominator;",
            "control_paren_regex_then_division": (
                'if (enabled) /; export { releaseToken } from "app.runner";/'
                '.test("x"); const ratio = numerator / denominator;'
            ),
            "escaped_regex": r"const x = /prefix\/suffix[;]+/gi;",
            "character_class": r"const x = /[a-z\]\/]+/g;",
        }.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                verifier.VerificationError, "unsupported non-comment JS/TS slash"
            ):
                verifier.scan_jsts_static_module_specifiers(unsupported)

    def test_jsts_static_import_scanner_rejects_template_interpolation_regex_bypass(self) -> None:
        verifier = self.load_verifier()
        bypass = (
            'const t = `${ /}`; export { releaseToken } from "app.runner";`/// hidden\n'
            '}`;'
        )
        with self.assertRaisesRegex(
            verifier.VerificationError, "unsupported non-comment JS/TS slash"
        ):
            verifier.scan_jsts_static_module_specifiers(bypass)

    def test_jsts_static_import_scanner_rejects_delimiter_underflow_and_unclosed_eof(self) -> None:
        verifier = self.load_verifier()
        for closer in ("}", ")", "]"):
            with self.subTest(kind="underflow", closer=closer), self.assertRaisesRegex(
                verifier.VerificationError, "unmatched closing JS/TS delimiter"
            ):
                verifier.scan_jsts_static_module_specifiers(
                    closer + '\nexport { releaseToken } from "app.runner";'
                )
        for opener in ("{", "(", "["):
            with self.subTest(kind="unclosed", opener=opener), self.assertRaisesRegex(
                verifier.VerificationError, "unclosed JS/TS delimiter"
            ):
                verifier.scan_jsts_static_module_specifiers(
                    'export { realEdge } from "./real-edge.js";\n' + opener
                )

    def test_jsts_static_import_scanner_rejects_crossed_delimiter_nesting(self) -> None:
        verifier = self.load_verifier()
        for crossed in ("{ ( } )", "{ [ } ]", "( [ ) ]"):
            with self.subTest(crossed=crossed), self.assertRaisesRegex(
                verifier.VerificationError, "mismatched closing JS/TS delimiter"
            ):
                verifier.scan_jsts_static_module_specifiers(
                    crossed + '\nexport { releaseToken } from "app.runner";'
                )

    def test_jsts_static_import_scanner_rejects_template_interpolation_delimiter_state(self) -> None:
        verifier = self.load_verifier()
        cases = {
            "unclosed_paren": 'const t = `${ ( }`;\nexport { releaseToken } from "app.runner";',
            "crossed_paren_bracket": 'const t = `${ ([) }`;\nexport { releaseToken } from "app.runner";',
        }
        for label, source in cases.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                verifier.VerificationError,
                "mismatched closing JS/TS template interpolation delimiter",
            ):
                verifier.scan_jsts_static_module_specifiers(source)

    def test_relocked_fake_imports_cannot_counterfeit_graph_topology(self) -> None:
        root = self.copied_root()
        fixture = root / (
            "research/provider-free-roadmap/g2/v1/fixtures/evaluation/realistic_fallback"
        )
        counterfeit = r'''
// export { releaseToken } from "../app/runner.js";
/* export { releaseToken } from "../app/runner.js"; */
const quoted = "export { releaseToken } from '../app/runner.js';";
const escaped = "prefix \" export { releaseToken } from '../app/runner.js';";
const template = `export { releaseToken } from "../app/runner.js";`;
'''
        (fixture / "validators/index.js").write_text(
            counterfeit + "\nexport function verifyIndigo() { return 'INDIGO'; }\n",
            encoding="utf-8",
        )
        (fixture / "auditors/check.js").write_text(
            counterfeit + "\nexport function auditColor() { return 'audit'; }\n",
            encoding="utf-8",
        )
        tasks_path = root / "research/provider-free-roadmap/g2/v1/tasks.json"
        tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
        task = next(item for item in tasks["tasks"] if item["task_id"] == "evaluation_graph")
        task["structure_id"] = "counterfeit-fan-in-from-non-code-text"
        task["fixture_tree_sha256"] = self.load_verifier(root).fixture_tree_hash(fixture)
        self.write_json(tasks_path, tasks)
        self.relock(root)
        self.assert_rejected(root, "graph topology family|disconnected graph topology")

    def test_relocked_control_paren_regex_and_division_cannot_counterfeit_topology(self) -> None:
        root = self.copied_root()
        fixture = root / (
            "research/provider-free-roadmap/g2/v1/fixtures/evaluation/realistic_fallback"
        )
        counterfeit = (
            'if (enabled) /; export { releaseToken } from "app.runner";/'
            '.test("x"); const ratio = numerator / denominator;\n'
        )
        (fixture / "validators/index.js").write_text(
            counterfeit + "\nexport function verifyIndigo() { return 'INDIGO'; }\n",
            encoding="utf-8",
        )
        (fixture / "auditors/check.js").write_text(
            counterfeit + "\nexport function auditColor() { return 'audit'; }\n",
            encoding="utf-8",
        )
        tasks_path = root / "research/provider-free-roadmap/g2/v1/tasks.json"
        tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
        task = next(item for item in tasks["tasks"] if item["task_id"] == "evaluation_graph")
        task["structure_id"] = "counterfeit-fan-in-from-control-paren-regex"
        task["fixture_tree_sha256"] = self.load_verifier(root).fixture_tree_hash(fixture)
        self.write_json(tasks_path, tasks)
        self.relock(root)
        self.assert_rejected(root, "unsupported non-comment JS/TS slash")

    def test_relocked_template_interpolation_regex_cannot_counterfeit_topology(self) -> None:
        root = self.copied_root()
        fixture = root / (
            "research/provider-free-roadmap/g2/v1/fixtures/evaluation/realistic_fallback"
        )
        counterfeit = (
            'const t = `${ /}`; export { releaseToken } from "app.runner";`/// hidden\n'
            '}`;\n'
        )
        (fixture / "validators/index.js").write_text(
            counterfeit + "\nexport function verifyIndigo() { return 'INDIGO'; }\n",
            encoding="utf-8",
        )
        (fixture / "auditors/check.js").write_text(
            counterfeit + "\nexport function auditColor() { return 'audit'; }\n",
            encoding="utf-8",
        )
        tasks_path = root / "research/provider-free-roadmap/g2/v1/tasks.json"
        tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
        task = next(item for item in tasks["tasks"] if item["task_id"] == "evaluation_graph")
        task["structure_id"] = "counterfeit-fan-in-from-template-interpolation-regex"
        task["fixture_tree_sha256"] = self.load_verifier(root).fixture_tree_hash(fixture)
        self.write_json(tasks_path, tasks)
        self.relock(root)
        self.assert_rejected(root, "unsupported non-comment JS/TS slash")

    def test_relocked_unmatched_closer_cannot_counterfeit_graph_topology(self) -> None:
        root = self.copied_root()
        fixture = root / (
            "research/provider-free-roadmap/g2/v1/fixtures/evaluation/realistic_fallback"
        )
        counterfeit = '}\nexport { releaseToken } from "app.runner";\n'
        (fixture / "validators/index.js").write_text(
            counterfeit + "\nexport function verifyIndigo() { return 'INDIGO'; }\n",
            encoding="utf-8",
        )
        (fixture / "auditors/check.js").write_text(
            counterfeit + "\nexport function auditColor() { return 'audit'; }\n",
            encoding="utf-8",
        )
        tasks_path = root / "research/provider-free-roadmap/g2/v1/tasks.json"
        tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
        task = next(item for item in tasks["tasks"] if item["task_id"] == "evaluation_graph")
        task["structure_id"] = "counterfeit-fan-in-after-unmatched-closer"
        task["fixture_tree_sha256"] = self.load_verifier(root).fixture_tree_hash(fixture)
        self.write_json(tasks_path, tasks)
        self.relock(root)
        self.assert_rejected(root, "unmatched closing JS/TS delimiter")

    def test_relocked_crossed_delimiters_cannot_counterfeit_graph_topology(self) -> None:
        root = self.copied_root()
        fixture = root / (
            "research/provider-free-roadmap/g2/v1/fixtures/evaluation/realistic_fallback"
        )
        counterfeit = '{ ( } )\nexport { releaseToken } from "app.runner";\n'
        (fixture / "validators/index.js").write_text(
            counterfeit + "\nexport function verifyIndigo() { return 'INDIGO'; }\n",
            encoding="utf-8",
        )
        (fixture / "auditors/check.js").write_text(
            counterfeit + "\nexport function auditColor() { return 'audit'; }\n",
            encoding="utf-8",
        )
        tasks_path = root / "research/provider-free-roadmap/g2/v1/tasks.json"
        tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
        task = next(item for item in tasks["tasks"] if item["task_id"] == "evaluation_graph")
        task["structure_id"] = "counterfeit-fan-in-after-crossed-delimiters"
        task["fixture_tree_sha256"] = self.load_verifier(root).fixture_tree_hash(fixture)
        self.write_json(tasks_path, tasks)
        self.relock(root)
        self.assert_rejected(root, "mismatched closing JS/TS delimiter")

    def test_relocked_template_interpolation_delimiters_cannot_counterfeit_topology(self) -> None:
        root = self.copied_root()
        fixture = root / (
            "research/provider-free-roadmap/g2/v1/fixtures/evaluation/realistic_fallback"
        )
        counterfeit = (
            'const t = `${ ([) }`;\n'
            'export { releaseToken } from "app.runner";\n'
        )
        (fixture / "validators/index.js").write_text(
            counterfeit + "\nexport function verifyIndigo() { return 'INDIGO'; }\n",
            encoding="utf-8",
        )
        (fixture / "auditors/check.js").write_text(
            counterfeit + "\nexport function auditColor() { return 'audit'; }\n",
            encoding="utf-8",
        )
        tasks_path = root / "research/provider-free-roadmap/g2/v1/tasks.json"
        tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
        task = next(item for item in tasks["tasks"] if item["task_id"] == "evaluation_graph")
        task["structure_id"] = "counterfeit-fan-in-after-template-interpolation-crossing"
        task["fixture_tree_sha256"] = self.load_verifier(root).fixture_tree_hash(fixture)
        self.write_json(tasks_path, tasks)
        self.relock(root)
        self.assert_rejected(
            root, "mismatched closing JS/TS template interpolation delimiter"
        )

    def test_scorer_bytes_are_not_read_until_all_public_outputs_are_sealed(self) -> None:
        timeline: list[str] = []
        verifier = self.load_verifier()
        original_safe_read = verifier.safe_read_file

        def monitored_safe_read(root: Path, relative: str, *args, **kwargs) -> bytes:
            path = root / relative
            if "scorer-only" in path.parts:
                timeline.append("scorer_read")
            return original_safe_read(root, relative, *args, **kwargs)

        def phase(event: str, _payload: dict) -> None:
            if event == "output_sealed":
                timeline.append("output_sealed")

        with mock.patch.object(verifier, "safe_read_file", monitored_safe_read):
            verifier.verify_repository(ROOT, phase_observer=phase)
        first_scorer_read = timeline.index("scorer_read")
        self.assertEqual(timeline[:first_scorer_read].count("output_sealed"), 24)

    def test_public_snapshot_closes_fixture_packer_and_lock_path_races(self) -> None:
        root = self.copied_root()
        mutated = {"done": False}
        events: list[str] = []

        def phase(event: str, _payload: dict) -> None:
            events.append(event)
            if event != "public_snapshot_sealed" or mutated["done"]:
                return
            fixture = root / (
                "research/provider-free-roadmap/g2/v1/fixtures/train/closed_pack/brief.txt"
            )
            fixture.write_text("post-capture replacement\n", encoding="utf-8")
            packer = root / "context-guard-kit/context_pack.py"
            packer.write_text("raise SystemExit('post-capture replacement')\n", encoding="utf-8")
            (root / "research/provider-free-roadmap/g2/freeze-lock.json").write_text(
                "{}\n", encoding="utf-8"
            )
            mutated["done"] = True

        verifier = self.load_verifier(root)
        with self.assertRaisesRegex(verifier.VerificationError, "post-capture.*drift"):
            verifier.verify_repository(root, phase_observer=phase)
        self.assertTrue(mutated["done"], "public immutable snapshot phase was not reached")
        self.assertEqual(events.count("output_sealed"), 24)

    def test_group_world_write_and_special_mode_bits_are_rejected(self) -> None:
        root = self.copied_root()
        public_file = root / "research/provider-free-roadmap/g2/v1/arms.json"
        public_file.chmod(0o664)
        verifier = self.load_verifier(root)
        with self.assertRaisesRegex(verifier.VerificationError, "unsafe mode|mode mismatch"):
            verifier.verify_repository(root)

        root = self.copied_root()
        public_file = root / "research/provider-free-roadmap/g2/v1/arms.json"
        public_file.chmod(0o1755)
        verifier = self.load_verifier(root)
        with self.assertRaisesRegex(verifier.VerificationError, "unsafe mode|special mode"):
            verifier.verify_repository(root)

    def test_unsupported_json_schema_keywords_are_rejected_at_every_depth(self) -> None:
        mutations = (
            lambda schema: schema.update(allOf=[]),
            lambda schema: schema["properties"]["tasks"].update(contains={}),
            lambda schema: schema["properties"]["tasks"]["items"].update(
                unevaluatedProperties=False
            ),
            lambda schema: schema["properties"]["tasks"]["items"]["properties"][
                "prompt"
            ].update(format="hostname"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                root = self.copied_root()
                schema_path = root / (
                    "research/provider-free-roadmap/g2/v1/schemas/tasks.schema.json"
                )
                schema = json.loads(schema_path.read_text(encoding="utf-8"))
                mutation(schema)
                self.write_json(schema_path, schema)
                verifier = self.load_verifier(root)
                with self.assertRaisesRegex(
                    verifier.VerificationError, "unsupported schema keyword"
                ):
                    verifier.validate_instances(
                        root / "research/provider-free-roadmap/g2/v1",
                        include_scorer=False,
                    )

    def test_packer_child_audit_boundary_denies_network_process_write_and_external_read(self) -> None:
        verifier = self.load_verifier()
        run_child = getattr(verifier, "run_captured_packer_child", None)
        self.assertTrue(callable(run_child), "missing captured packer child boundary")
        probes = {
            "network": b"import socket\nsocket.socket()\n",
            "dns": b"import socket\nsocket.getaddrinfo('invalid.test', 443)\n",
            "process": b"import subprocess\nsubprocess.Popen(['/usr/bin/true'])\n",
            "exec": b"import os\nos.execv('/usr/bin/true', ['true'])\n",
            "native_load": b"import ctypes\nctypes.CDLL('/usr/lib/libc.dylib')\n",
            "write": b"open('forbidden-write', 'w').write('x')\n",
            "mkdir": b"import os\nos.mkdir('forbidden-directory')\n",
            "external_read": b"open('/etc/hosts', 'rb').read(1)\n",
            "environment": b"import os\nos.environ['FORBIDDEN_MUTATION'] = 'x'\n",
        }
        for label, source in probes.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                result = run_child(
                    packer_bytes=source,
                    sanitizer_bytes=b"class LineSanitizer: pass\n",
                    workspace=workspace,
                    arguments=[],
                    frozen_inventory=[],
                    entrypoint="probe",
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("audit boundary denied", result.stderr.decode("utf-8", "replace"))

    def test_packer_child_boundary_uses_only_lang_and_supported_pinned_python(self) -> None:
        verifier = self.load_verifier()
        run_child = getattr(verifier, "run_captured_packer_child", None)
        result = run_child(
            packer_bytes=(
                b"import json, os, sys\n"
                b"json.dump({'env': sorted(os.environ), 'isolated': sys.flags.isolated, "
                b"'no_bytecode': sys.flags.dont_write_bytecode}, sys.stdout)\n"
            ),
            sanitizer_bytes=b"class LineSanitizer: pass\n",
            workspace=ROOT,
            arguments=[],
            frozen_inventory=[],
            entrypoint="probe",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["env"], ["LANG"])
        self.assertEqual(payload["isolated"], 1)
        self.assertEqual(payload["no_bytecode"], 1)

    def test_packer_child_timeout_is_bounded_and_reports_task_arm_context(self) -> None:
        verifier = self.load_verifier()
        secret_query = "never-echo-this-timeout-input"
        task = {
            "task_id": "timeout_probe",
            "pack": {
                "budget_bytes": 1024,
                "files": ["input.txt"],
                "query": secret_query,
                "top": 1,
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(verifier.VerificationError) as captured:
                verifier.execute_arm(
                    b"while True:\n    pass\n",
                    Path(temporary),
                    ["input.txt"],
                    task,
                    "ordinary",
                    timeout_seconds=0.05,
                )
        self.assertEqual(
            str(captured.exception),
            "bound packer failed for timeout_probe/ordinary: "
            "captured packer child timed out",
        )
        self.assertNotIn(secret_query, str(captured.exception))
        self.assertIsNone(captured.exception.__cause__)

    def test_arms_are_exact_factor_isolated_auto_operations(self) -> None:
        arms = self.read_json(ROOT, "research/provider-free-roadmap/g2/v1/arms.json")
        self.assertEqual([item["name"] for item in arms["arms"]], list(ARMS))
        expected = {
            "ordinary": [],
            "adaptive_only": ["adaptive_k"],
            "symbol_only": ["symbol_memory"],
            "combined": ["adaptive_k", "symbol_memory"],
        }
        common = arms["common"]
        self.assertEqual(common["operation"], "auto")
        self.assertEqual(
            set(common),
            {"budget_bytes", "files", "json", "no_artifact", "operation", "query", "root", "top"},
        )
        for arm in arms["arms"]:
            self.assertEqual(arm["factors"], expected[arm["name"]])
        self.assertEqual(arms["application_order"], ["ordinary", "adaptive_k", "symbol_memory"])

    def test_all_public_arm_projections_physically_exclude_oracle_data(self) -> None:
        verifier = self.load_verifier()
        tasks = self.read_json(ROOT, "research/provider-free-roadmap/g2/v1/tasks.json")["tasks"]
        oracle_raw = (V1 / "scorer-only/oracle.json").read_text(encoding="utf-8")
        secret_values = {
            value
            for row in json.loads(oracle_raw)["entries"]
            for key in ("answer_signature", "expected_output")
            for value in (row[key],)
        }
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            for task in tasks:
                for arm in ARMS:
                    destination = base / task["task_id"] / arm
                    projection = verifier.materialize_arm_projection(
                        ROOT, task["task_id"], arm, destination
                    )
                    serialized = json.dumps(projection, sort_keys=True)
                    self.assertTrue(destination.is_dir())
                    self.assertFalse(FORBIDDEN_PUBLIC_KEYS & self.recursive_keys(projection))
                    self.assertFalse(any(secret in serialized for secret in secret_values))
                    self.assertFalse(any("scorer-only" in p.as_posix() for p in destination.rglob("*")))

    def recursive_keys(self, value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | set().union(*(self.recursive_keys(v) for v in value.values()))
        if isinstance(value, list):
            return set().union(*(self.recursive_keys(v) for v in value)) if value else set()
        return set()

    def test_oracle_load_occurs_only_after_all_four_outputs_per_task_are_sealed(self) -> None:
        events: list[tuple[str, dict]] = []
        self.verify(phase_observer=lambda event, payload: events.append((event, payload)))
        oracle_index = next(index for index, (event, _) in enumerate(events) if event == "oracle_load")
        seals = [payload for event, payload in events[:oracle_index] if event == "output_sealed"]
        self.assertEqual(len(seals), 24)
        self.assertTrue(
            all(
                item["sealed_fields"]
                == [
                    "adaptive_k_application",
                    "adaptive_k_selected_evidence",
                    "graph_application",
                    "selected_paths",
                    "symbol_memory",
                ]
                for item in seals
            )
        )
        self.assertEqual(
            {(item["task_id"], item["arm"]) for item in seals},
            {
                (task_id, arm)
                for task_id in (
                    "train_closed",
                    "train_graph",
                    "calibration_closed",
                    "calibration_graph",
                    "evaluation_closed",
                    "evaluation_graph",
                )
                for arm in ARMS
            },
        )

    def test_transitive_oracle_leakage_in_nested_public_content_is_rejected(self) -> None:
        root = self.copied_root()
        oracle = self.read_json(root, "research/provider-free-roadmap/g2/v1/scorer-only/oracle.json")
        signature = oracle["entries"][0]["answer_signature"]
        self.mutate_json(
            root,
            "research/provider-free-roadmap/g2/v1/tasks.json",
            lambda value: value["tasks"][0].update(
                prompt=value["tasks"][0]["prompt"] + " " + signature
            ),
        )
        self.assert_rejected(root, "oracle leakage")

    def test_duplicate_or_similar_cross_partition_structure_is_rejected(self) -> None:
        root = self.copied_root()
        self.mutate_json(
            root,
            "research/provider-free-roadmap/g2/v1/tasks.json",
            lambda value: value["tasks"][2].update(
                structure_id=value["tasks"][0]["structure_id"]
            ),
        )
        self.assert_rejected(root, "structure_id")

        root = self.copied_root()
        source = sorted(
            (root / "research/provider-free-roadmap/g2/v1/fixtures/train/closed_pack").iterdir()
        )
        target = sorted(
            (root / "research/provider-free-roadmap/g2/v1/fixtures/calibration/closed_pack").iterdir()
        )
        for index, (source_path, target_path) in enumerate(zip(source, target)):
            target_path.write_bytes(source_path.read_bytes() + f"\npartition-calibration-{index}\n".encode())
        self.update_fixture_tree_hash(root, "calibration_closed")
        self.relock(root)
        self.assert_rejected(
            root, "cross-partition public-content similarity|cross-partition structure profile"
        )

    def test_shared_fixture_file_hash_and_duplicate_answer_signature_are_rejected(self) -> None:
        root = self.copied_root()
        first = root / "research/provider-free-roadmap/g2/v1/fixtures/train/closed_pack/distractor.txt"
        second = root / "research/provider-free-roadmap/g2/v1/fixtures/calibration/closed_pack/tides.txt"
        second.write_bytes(first.read_bytes())
        self.update_fixture_tree_hash(root, "calibration_closed")
        self.relock(root)
        self.assert_rejected(root, "shared fixture file hash")

        root = self.copied_root()
        self.mutate_json(
            root,
            "research/provider-free-roadmap/g2/v1/scorer-only/oracle.json",
            lambda value: value["entries"][1].update(
                answer_signature=value["entries"][0]["answer_signature"]
            ),
        )
        self.assert_rejected(root, "duplicate answer signature")

    def test_symlink_and_hardlink_fixture_aliases_are_rejected(self) -> None:
        root = self.copied_root()
        fixture = root / "research/provider-free-roadmap/g2/v1/fixtures/train/closed_pack"
        (fixture / "alias.txt").symlink_to("distractor.txt")
        self.assert_rejected(root, "symlink|nonregular")

        root = self.copied_root()
        fixture = root / "research/provider-free-roadmap/g2/v1/fixtures/train/closed_pack"
        os.link(fixture / "distractor.txt", fixture / "hardlink.txt")
        self.assert_rejected(root, "hardlink|link count")

    def test_fabricated_missing_import_edge_or_rank_is_rejected(self) -> None:
        for mutation in (
            lambda value: value["cases"][0]["derived_evidence"]["import_edges"][0].update(
                source_line=999
            ),
            lambda value: value["cases"][0]["derived_evidence"]["graph_ranks"][0].update(
                rank=9
            ),
            lambda value: value["cases"][0]["derived_evidence"].update(import_edges=[]),
        ):
            with self.subTest(mutation=mutation):
                root = self.copied_root()
                self.mutate_json(
                    root,
                    "research/provider-free-roadmap/g2/v1/scorer-only/graph.json",
                    mutation,
                )
                self.assert_rejected(root, "import.edge|graph rank|too few items")

    def test_graph_ordinary_miss_and_symbol_recovery_are_enforced(self) -> None:
        root = self.copied_root()
        self.mutate_json(
            root,
            "research/provider-free-roadmap/g2/v1/scorer-only/oracle.json",
            lambda value: value["entries"][1].update(
                required_paths=["app/entry.py", "operator-handbook.md"]
            ),
        )
        self.assert_rejected(root, "ordinary.*miss|required neighbor")

    def test_arm_contamination_and_application_order_are_rejected(self) -> None:
        for mutation, pattern in (
            (
                lambda value: value["arms"][0].update(factors=["symbol_memory"]),
                "canonical arms|factor",
            ),
            (
                lambda value: value.update(
                    application_order=["ordinary", "symbol_memory", "adaptive_k"]
                ),
                "application order|application_order",
            ),
            (
                lambda value: value["common"].update(provider_argv=["provider"]),
                "schema validation|unknown",
            ),
        ):
            with self.subTest(pattern=pattern):
                root = self.copied_root()
                self.mutate_json(
                    root, "research/provider-free-roadmap/g2/v1/arms.json", mutation
                )
                self.assert_rejected(root, pattern)

    def test_strata_are_assigned_only_by_exact_public_policy(self) -> None:
        root = self.copied_root()
        self.mutate_json(
            root,
            "research/provider-free-roadmap/g2/v1/tasks.json",
            lambda value: value["tasks"][0]["workspace_policy"].update(workspace_access=True),
        )
        self.assert_rejected(root, "stratum policy")

    def test_strict_schemas_reject_unknown_version_nonfinite_and_duplicate_json(self) -> None:
        mutations = (
            lambda value: value.update(unknown=True),
            lambda value: value.update(schema_version="contextguard.g2-tasks/v2"),
            lambda value: value["tasks"][0]["pack"].update(top=float("nan")),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                root = self.copied_root()
                self.mutate_json(
                    root, "research/provider-free-roadmap/g2/v1/tasks.json", mutation
                )
                self.assert_rejected(root, "schema validation|non-finite")

        root = self.copied_root()
        path = root / "research/provider-free-roadmap/g2/v1/tasks.json"
        raw = path.read_text(encoding="utf-8")
        path.write_text(raw.replace('"schema_version":', '"schema_version": "duplicate",\n  "schema_version":', 1))
        self.relock(root)
        self.assert_rejected(root, "duplicate key")

    def test_duplicate_arm_task_and_oracle_rows_are_rejected(self) -> None:
        cases = (
            ("arms.json", lambda value: value["arms"].append(value["arms"][0]), "duplicate arm|too many items"),
            ("tasks.json", lambda value: value["tasks"].append(value["tasks"][0]), "duplicate task|too many items"),
            (
                "scorer-only/oracle.json",
                lambda value: value["entries"].append(value["entries"][0]),
                "duplicate oracle|too many items",
            ),
        )
        for relative, mutation, pattern in cases:
            with self.subTest(relative=relative):
                root = self.copied_root()
                self.mutate_json(
                    root, f"research/provider-free-roadmap/g2/v1/{relative}", mutation
                )
                self.assert_rejected(root, pattern)

    def test_lock_rejects_added_missing_unsafe_and_substituted_inventory(self) -> None:
        root = self.copied_root()
        added = root / "research/provider-free-roadmap/g2/v1/added.txt"
        added.write_text("not frozen\n", encoding="utf-8")
        added.chmod(0o644)
        self.assert_rejected(root, "unlisted|extra")

        root = self.copied_root()
        missing = root / "research/provider-free-roadmap/g2/v1/fixtures/train/closed_pack/history.md"
        missing.unlink()
        self.assert_rejected(root, "missing frozen file")

        for replacement, pattern in (("../escape", "unsafe"), ("/absolute", "unsafe")):
            with self.subTest(replacement=replacement):
                root = self.copied_root()
                self.mutate_json(
                    root,
                    "research/provider-free-roadmap/g2/freeze-lock.json",
                    lambda value, replacement=replacement: value["public_inventory"][0].update(
                        path=replacement
                    ),
                    relock=False,
                )
                self.assert_rejected(root, pattern)

        root = self.copied_root()
        self.mutate_json(
            root,
            "research/provider-free-roadmap/g2/freeze-lock.json",
            lambda value: value.update(tree_root_sha256="0" * 64),
            relock=False,
        )
        self.assert_rejected(root, "tree root")

    def test_verifier_and_both_packer_byte_drift_is_rejected(self) -> None:
        for relative, pattern in (
            ("research/provider-free-roadmap/g2/v1/verify.py", "frozen content drift"),
            ("context-guard-kit/context_pack.py", "canonical packer drift"),
            ("plugins/context-guard/bin/context-guard-pack", "plugin packer drift"),
        ):
            with self.subTest(relative=relative):
                root = self.copied_root()
                path = root / relative
                path.write_bytes(path.read_bytes() + b"\n")
                self.assert_rejected(root, pattern)

    def test_structural_results_encode_unavailable_observers_as_null_not_zero(self) -> None:
        result = self.read_json(ROOT, "research/provider-free-roadmap/g2/v1/result.example.json")
        observers = result["observers"]
        self.assertEqual(
            set(observers), {"provider", "retrieval", "correction", "latency", "cost"}
        )
        for observer in observers.values():
            self.assertEqual(observer, {"status": "unavailable", "value": None})
        serialized = json.dumps(result).lower()
        self.assertNotIn("bootstrap", serialized)
        self.assertNotIn("savings", serialized)

        root = self.copied_root()
        self.mutate_json(
            root,
            "research/provider-free-roadmap/g2/v1/result.example.json",
            lambda value: value["observers"]["cost"].update(value=0),
        )
        self.assert_rejected(root, "schema validation.*cost.value")

    def test_direct_unbound_g2_command_is_unavailable(self) -> None:
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(VERIFY)],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("direct unbound g2 command is unavailable", result.stderr)

    def test_structural_replay_is_deterministic(self) -> None:
        first = self.verify()
        second = self.verify()
        self.assertEqual(first, second)
        encoded = json.dumps(first["output_seals"], sort_keys=True, separators=(",", ":"))
        self.assertEqual(hashlib.sha256(encoded.encode()).hexdigest(), first["replay_sha256"])


if __name__ == "__main__":
    unittest.main()
