#!/usr/bin/env python3
"""Build the provider-live v3 preregistration artifacts deterministically."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
V3 = Path(__file__).resolve().parent
SEED = "contextguard-p3-v3-factorial-public-projects-20260817"
ARMS = tuple(f"a{adaptive}{symbol}{graph}" for adaptive in (0, 1) for symbol in (0, 1) for graph in (0, 1))
PROMPT_TEMPLATE = b"""You are editing an exported source tree with no Git history or network access.\n\nTASK\n{task_prompt}\n\nALLOWED PATCH PATHS (canonical JSON array)\n{allowed_patch_paths_json}\n\nFROZEN SOURCE CONTEXT\n{context_pack}\n\nOPTIONAL PURE SYMBOL PROJECTION\n{symbol_projection_or_empty}\n\nReturn exactly one UTF-8 unified diff. Do not include prose or code fences. Modify only the paths listed above.\n"""


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def task(
    *,
    task_id: str,
    project_id: str,
    taxonomy: str,
    commit: str,
    parent: str,
    parent_tree: str,
    target_tree: str,
    patch_sha: str,
    patch_bytes: int,
    paths: list[str],
    prompt: str,
    subject: str,
    historical_date: str,
    excluded_upstream_changed_paths: list[str] | None = None,
) -> dict[str, object]:
    return {
        "allowed_patch_paths": paths,
        "checker_id": f"checker_{task_id}",
        "historical_commit": commit,
        "historical_date": historical_date,
        "historical_subject": subject,
        "excluded_upstream_changed_paths": excluded_upstream_changed_paths or [],
        "id": task_id,
        "parent_commit": parent,
        "parent_tree_sha": parent_tree,
        "project_id": project_id,
        "prompt": prompt,
        "prompt_sha256": sha256(prompt.encode("utf-8")),
        "selected_path_historical_patch_bytes": patch_bytes,
        "selected_path_historical_patch_sha256": patch_sha,
        "target_tree_sha": target_tree,
        "taxonomy": taxonomy,
    }


PROJECTS = [
    {
        "cache_directory": "requests",
        "first_commit": "e7615cbc6b4af5985c4e0d4848a426e2d35f79c3",
        "first_commit_date": "2011-02-13",
        "history_years_at_intake": 15,
        "id": "requests",
        "independent_repository": True,
        "intake_commit": "8068356288978c4f54661ae6f95afe0e0831885e",
        "intake_tree": "271ed3be81c5d263a4293f30924c0ee95484511d",
        "repository_url": "https://github.com/psf/requests.git",
    },
    {
        "cache_directory": "typescript",
        "first_commit": "99ec3a96880649eeaa08c3df30e3ae802048f4fe",
        "first_commit_date": "2014-07-07",
        "history_years_at_intake": 12,
        "id": "typescript",
        "independent_repository": True,
        "intake_commit": "b465fdbfe175304d9b977da137b2c178ae1091d3",
        "intake_tree": "6b5535faf840e0b8e5acebd6a50d9714ca2411b8",
        "repository_url": "https://github.com/microsoft/TypeScript.git",
    },
    {
        "cache_directory": "swift-argument-parser",
        "first_commit": "f6ac7b8118ff5d1bc0faee7f37bf6f8fd8f95602",
        "first_commit_date": "2020-02-20",
        "history_years_at_intake": 6,
        "id": "swift_argument_parser",
        "independent_repository": True,
        "intake_commit": "25fa69e8eab18c6034e7a050edf96dbf9a0490f4",
        "intake_tree": "2b993f1b37cb385e1efb734a8411949241c46c9d",
        "repository_url": "https://github.com/apple/swift-argument-parser.git",
    },
]


TASKS = [
    task(
        task_id="requests_bug_fix",
        project_id="requests",
        taxonomy="bug_fix",
        commit="2d5517682b3b38547634d153cea43d48fbc8cdb5",
        parent="8bce583b9547c7b82d44c8e97f37cf9a16cbe758",
        parent_tree="05defac1bc37ba431927957db76c574a478bd11a",
        target_tree="7c69ff569860f96c96b0ae07c0e6cdf7c0b6e93d",
        patch_sha="82c34df5e895f5317c4c5fb35a6fe1c335df106ce43bba459e54ec8fdd23771f",
        patch_bytes=1999,
        paths=["requests/models.py", "tests/test_lowlevel.py"],
        prompt="Repair Response.json so alternate UTF JSON decoding failures use the public Requests JSON exception hierarchy without exposing the decoded response body. Preserve existing behavior for successful JSON responses and add focused regression coverage.",
        subject="Fix inconsistent exception for JSONDecode error (#6097)",
        historical_date="2022-03-28",
    ),
    task(
        task_id="requests_boundary_hardening",
        project_id="requests",
        taxonomy="boundary_hardening",
        commit="3331e2aecdbf575dd60abef4df79c52d78610a83",
        parent="dd754d13de250a6af8a68a6a83a8b4419fd429c6",
        parent_tree="268204727be68432d8670069e44d9e6bc282dc59",
        target_tree="3a23504bfffaeaceddc429e93d48bcdc78686831",
        patch_sha="fda629ba0cc4a38d1ebe13bdcd1b2d6bb51c6c20632a34834b9732a706b9cec6",
        patch_bytes=1821,
        paths=["requests/sessions.py", "tests/test_requests.py"],
        prompt="Harden redirect authentication handling so Authorization is stripped whenever the redirect changes the origin host, port, or scheme, while preserving same-origin behavior. Add focused coverage for the changed-origin case.",
        subject="Strip Authorization header whenever root URL changes",
        historical_date="2018-06-28",
    ),
    task(
        task_id="requests_feature",
        project_id="requests",
        taxonomy="feature",
        commit="e45b428960ff3927812fc9b555e2ac627ba95769",
        parent="2a438c27b5a5828c8ea0dc958112eecffca70b12",
        parent_tree="477e646a462e6203801788cd824c7aca643de3bc",
        target_tree="6d72690327378214a8e8c724d682f216619d42c2",
        patch_sha="c545938e67d4420a0f0a7d7ddd86c8f2fe29ace496db191a52566571bec844fd",
        patch_bytes=1445,
        paths=["src/requests/status_codes.py"],
        prompt="Add the RFC 9110 replacement or alias names for HTTP status codes 102, 413, 414, and 422 while retaining all existing Requests aliases.",
        subject="Add rfc9110 HTTP status code names",
        historical_date="2024-04-08",
    ),
    task(
        task_id="requests_maintenance",
        project_id="requests",
        taxonomy="maintenance",
        commit="d58d8aa2f45c3575268d6d5250745ef69f9cf8b7",
        parent="91a3eabd3dcc4d7f36dd8249e4777a90ef9b4305",
        parent_tree="759c0d1b05ebe8f99c1099c215c9de1811d317ab",
        target_tree="bd7a2ebe6a94d575b449caa8ef67501d1786f2b6",
        patch_sha="f0ca4bddf5e608d09290dc6df472bcea14bce29d59768a3b20536a13d677aae9",
        patch_bytes=756,
        paths=["src/requests/sessions.py"],
        prompt="Clarify the unit used by the Session.request timeout parameter without changing runtime behavior or the surrounding documentation contract.",
        subject="docs: clarify timeout parameter uses seconds in Session.request (#6994)",
        historical_date="2025-07-17",
    ),
    task(
        task_id="typescript_bug_fix",
        project_id="typescript",
        taxonomy="bug_fix",
        commit="6afd0fb73fa18a48021ed54f44a0c51794519bf6",
        parent="069de743dbd17b47cc2fc58e1d16da5410911284",
        parent_tree="733ca444b0d428be39b5f46f25947dbc8f5e2c69",
        target_tree="a96b861fc59e155632640ab7ff9af86b529e989f",
        patch_sha="9d4a278e8bba7ab5922fad987a169fad292ddaf939a8b76a5e417a55d89a919b",
        patch_bytes=4974,
        paths=["src/compiler/checker.ts", "tests/baselines/reference/exportAssignmentExpressionIsExpressionNode.errors.txt", "tests/cases/compiler/exportAssignmentExpressionIsExpressionNode.ts"],
        prompt="Prevent a debug assertion crash while serializing a default export type error from a CommonJS declaration package imported as a namespace. Preserve the expected type diagnostic and add a compiler regression case.",
        subject="Fix crash when serializing default export in error (#61582)",
        historical_date="2025-04-16",
    ),
    task(
        task_id="typescript_boundary_hardening",
        project_id="typescript",
        taxonomy="boundary_hardening",
        commit="7be4b2c6977c9d81006ac1fe080321247d025371",
        parent="ac2cfccd64d5f4a860b7c24335679da9c04bf525",
        parent_tree="d2e46f5446ccc353abe9a4cad7110aa0fb05b1dd",
        target_tree="8a46141eb56c642db63649c3349e97fd5f72c2b7",
        patch_sha="9a5b76fa46b06c9031c69c8af86cda846e483016df49b88fbee97f651c9db023",
        patch_bytes=1692,
        paths=["src/harness/tsserverLogger.ts"],
        prompt="Harden tsserver log sanitization so only complete TypeScript version tokens are replaced and longer version-like strings remain intact. Apply the same boundary rule to package tags.",
        subject="Harden sanitizeLog against incorrect matches on TypeScript versions. (#60794)",
        historical_date="2024-12-17",
    ),
    task(
        task_id="typescript_feature",
        project_id="typescript",
        taxonomy="feature",
        commit="32e8f8b81c84acb929c77cc06929e7e5f59f309a",
        parent="7901a397214e8c7b39de8954eecc707dce8cb099",
        parent_tree="b32c2228fefd0d7f8436c016cb342662f6108ce8",
        target_tree="240d44094d608e5eacfbe8abb8d6777f93fadb9b",
        patch_sha="1f6deb4bc403d90400ced147c108c7ce5173fde0a9e98a8318160a192906b5d5",
        patch_bytes=1722,
        paths=["src/compiler/checker.ts", "src/compiler/types.ts", "tests/baselines/reference/api/typescript.d.ts"],
        prompt="Expose getUnknownType on the public TypeChecker API, implement it using the existing canonical unknown type, and update the generated public API declaration baseline.",
        subject="feat(60475): Add getUnknownType to checker api (#60502)",
        historical_date="2025-01-17",
    ),
    task(
        task_id="typescript_maintenance",
        project_id="typescript",
        taxonomy="maintenance",
        commit="e1cef5fa3a616bd800fa5e23c2312fc9f951e59f",
        parent="717d05cc2d528deb51cf7785bdd71891935d19a8",
        parent_tree="7f86988c407199b73d12576e2d7a4a4fe338725c",
        target_tree="191349f85f701709c396cbc17771608cd4971279",
        patch_sha="bc53ec21c1b4318d8c759988125ba110f3de1b4d74d61a3a96562507d672fe6f",
        patch_bytes=901,
        paths=["README.md"],
        prompt="Update the README CI badge and link to the repository's current ci.yml GitHub Actions workflow without changing the other badges.",
        subject="Fix GHA badge in readme (#60937)",
        historical_date="2025-01-08",
    ),
    task(
        task_id="swift_argument_parser_bug_fix",
        project_id="swift_argument_parser",
        taxonomy="bug_fix",
        commit="6c7ec363da47357aaf1f2f423d30117ff077f696",
        parent="40d23425e142b96ed7e78262fdc8441b38ea5ab0",
        parent_tree="84544d51d55f20edc3f392a06ad2ca4d3d3dbd52",
        target_tree="4045c69c8c72a51b2559d21c9c8dd609a18f7378",
        patch_sha="7e2d5791b82c8477981854d5be732cb9f05708ec214effff2dc7dc9334ae8350",
        patch_bytes=2418,
        paths=["Sources/ArgumentParser/Parsing/CommandParser.swift", "Tests/ArgumentParserEndToEndTests/DefaultSubcommandEndToEndTests.swift"],
        prompt="Recognize the single-dash long help spelling when a default subcommand captures passthrough arguments, while retaining short and double-dash help handling. Add an end-to-end regression test.",
        subject="Fix unrecognized -help flag with default command (#612)",
        historical_date="2024-01-04",
    ),
    task(
        task_id="swift_argument_parser_boundary_hardening",
        project_id="swift_argument_parser",
        taxonomy="boundary_hardening",
        commit="1fb5308335f6eba91aed9764525542a48780c428",
        parent="3633633642a299bd80e198861267d232e6517d91",
        parent_tree="5b646eb3efea2e56f395cd06176f57836454c73b",
        target_tree="0cbb5b84d6f1ec8d2495dc7af5ba4e057ca4917d",
        patch_sha="7b3cb65d215d33d8856484bacc861b038339289ac1af5238f890dea97a54961e",
        patch_bytes=401,
        paths=[".github/workflows/pull_request.yml"],
        prompt="Apply least-privilege permissions to the pull request workflow so its token can read repository contents but receives no broader implicit access.",
        subject="chore: restrict GitHub workflow permissions (#828)",
        historical_date="2025-10-20",
    ),
    task(
        task_id="swift_argument_parser_feature",
        project_id="swift_argument_parser",
        taxonomy="feature",
        commit="05cfc384b9346613704331497de50d9d531906f6",
        parent="d1ddac82d70f0ffc1b3dad8f87ddafb28c3d0dcb",
        parent_tree="ac1c9164b367a03d929e4d6b093f78fce5272cee",
        target_tree="d2a6fad41dba9be53e5073bff35ad0f58a667b4a",
        patch_sha="15edf3854ad8e8c841405a99a3af953b70855834656971df902a6e51a0b37b09",
        patch_bytes=5378,
        paths=["Sources/ArgumentParser/Parsable Properties/ParentCommand.swift", "Sources/ArgumentParser/Parsing/ParserError.swift", "Sources/ArgumentParser/Usage/UsageGenerator.swift", "Sources/ArgumentParserTestHelpers/TestHelpers.swift"],
        prompt="Add a ParentCommand property wrapper that lets a child command read parsed parent state without leaking parent options into child help or tool-info output. Fail with a clear parser error when the requested type is not the actual parent and provide the supporting test-helper introspection API.",
        subject="Add a parent command property wrapper to gain access to parent state (#802)",
        historical_date="2025-09-12",
        excluded_upstream_changed_paths=["Tests/ArgumentParserEndToEndTests/DefaultSubcommandEndToEndTests.swift"],
    ),
    task(
        task_id="swift_argument_parser_maintenance",
        project_id="swift_argument_parser",
        taxonomy="maintenance",
        commit="41d58ffe702cfe7b00b2c4c6a6611d9d25a0adc1",
        parent="d6836f4508b0a6a3c7f5e9db614a031db914cacd",
        parent_tree="9199b1d98d69b34e1fe8f8103b2f9e146ee3fda0",
        target_tree="89d953ef387099f48647229d27a2f023b6a27d75",
        patch_sha="36dfa439428b50b34d786a74173ce0a349883f4d8b6591b125ea738478b02d69",
        patch_bytes=3029,
        paths=["README.md", "Sources/ArgumentParser/Documentation.docc/Articles/GettingStarted.md", "Sources/ArgumentParser/Documentation.docc/Extensions/AsyncParsableCommand.md"],
        prompt="Correct and clarify the documented Swift version requirements, including the getting-started tools version and the legacy Swift 5.5 async entry-point guidance, without changing runtime code.",
        subject="Fix incorrect or confusing documentation about Swift versions (#678)",
        historical_date="2024-12-04",
    ),
]


CHECKERS = {
    "checkers": [
        {"assertions": [{"forbidden_literals": [], "path": "requests/models.py", "required_literals": ["except JSONDecodeError as e:", "raise RequestsJSONDecodeError(e.msg, e.doc, e.pos)"]}, {"forbidden_literals": [], "path": "tests/test_lowlevel.py", "required_literals": ["test_json_decode_compatibility_for_alt_utf_encodings", "assert r.text not in str(excinfo.value)"]}], "id": "checker_requests_bug_fix", "task_id": "requests_bug_fix", "type": "source_assertions_v1"},
        {"assertions": [{"forbidden_literals": [], "path": "requests/sessions.py", "required_literals": ["or original_parsed.port != redirect_parsed.port", "or original_parsed.scheme != redirect_parsed.scheme"]}], "id": "checker_requests_boundary_hardening", "task_id": "requests_boundary_hardening", "type": "source_assertions_v1"},
        {"assertions": [{"forbidden_literals": [], "path": "src/requests/status_codes.py", "required_literals": ["early-hints", "content_too_large", "uri_too_long", "unprocessable_content"]}], "id": "checker_requests_feature", "task_id": "requests_feature", "type": "source_assertions_v1"},
        {"assertions": [{"forbidden_literals": ["How long to wait for the server to send"], "path": "src/requests/sessions.py", "required_literals": ["How many seconds to wait for the server to send"]}], "id": "checker_requests_maintenance", "task_id": "requests_maintenance", "type": "source_assertions_v1"},
        {"assertions": [{"forbidden_literals": ["Debug.assert(isExpressionNode(node));"], "path": "src/compiler/checker.ts", "required_literals": []}], "id": "checker_typescript_bug_fix", "task_id": "typescript_bug_fix", "type": "source_assertions_v1"},
        {"assertions": [{"forbidden_literals": ["replaceAll(s, ts.version, \"FakeVersion\")"], "path": "src/harness/tsserverLogger.ts", "required_literals": ["ts.regExpEscape(ts.version)", "ts.regExpEscape(ts.versionMajorMinor)"]}], "id": "checker_typescript_boundary_hardening", "task_id": "typescript_boundary_hardening", "type": "source_assertions_v1"},
        {"assertions": [{"forbidden_literals": [], "path": "src/compiler/checker.ts", "required_literals": ["getUnknownType: () => unknownType"]}, {"forbidden_literals": [], "path": "src/compiler/types.ts", "required_literals": ["getUnknownType(): Type;"]}, {"forbidden_literals": [], "path": "tests/baselines/reference/api/typescript.d.ts", "required_literals": ["getUnknownType(): Type;"]}], "id": "checker_typescript_feature", "task_id": "typescript_feature", "type": "source_assertions_v1"},
        {"assertions": [{"forbidden_literals": ["workflows/CI/badge.svg"], "path": "README.md", "required_literals": ["actions/workflows/ci.yml/badge.svg", "actions/workflows/ci.yml"]}], "id": "checker_typescript_maintenance", "task_id": "typescript_maintenance", "type": "source_assertions_v1"},
        {"assertions": [{"forbidden_literals": ["split.count == 1"], "path": "Sources/ArgumentParser/Parsing/CommandParser.swift", "required_literals": ["split.originalInput.count == 1"]}], "id": "checker_swift_argument_parser_bug_fix", "task_id": "swift_argument_parser_bug_fix", "type": "source_assertions_v1"},
        {"assertions": [{"forbidden_literals": [], "path": ".github/workflows/pull_request.yml", "required_literals": ["permissions:\n  contents: read"]}], "id": "checker_swift_argument_parser_boundary_hardening", "task_id": "swift_argument_parser_boundary_hardening", "type": "source_assertions_v1"},
        {"assertions": [{"forbidden_literals": [], "path": "Sources/ArgumentParser/Parsable Properties/ParentCommand.swift", "required_literals": ["@propertyWrapper", "public struct ParentCommand", "previousValue(Value.self)"]}, {"forbidden_literals": [], "path": "Sources/ArgumentParser/Parsing/ParserError.swift", "required_literals": ["case notParentCommand(String)"]}, {"forbidden_literals": [], "path": "Sources/ArgumentParser/Usage/UsageGenerator.swift", "required_literals": ["is not a parent of the current command"]}], "id": "checker_swift_argument_parser_feature", "task_id": "swift_argument_parser_feature", "type": "source_assertions_v1"},
        {"assertions": [{"forbidden_literals": [], "path": "Sources/ArgumentParser/Documentation.docc/Articles/GettingStarted.md", "required_literals": ["// swift-tools-version:5.7"]}, {"forbidden_literals": [], "path": "Sources/ArgumentParser/Documentation.docc/Extensions/AsyncParsableCommand.md", "required_literals": ["obsolete versions 1.1.x & 1.2.x"]}], "id": "checker_swift_argument_parser_maintenance", "task_id": "swift_argument_parser_maintenance", "type": "source_assertions_v1"},
    ],
    "claim_boundary": {
        "full_upstream_suite_equivalence": False,
        "historical_target_must_pass": True,
        "selected_path_historical_patch_byte_equivalence": True,
        "unmodified_parent_must_fail": True,
    },
    "schema_version": "contextguard.p3-v3-source-checkers/v1",
}

_TASKS_BY_ID = {str(item["id"]): item for item in TASKS}
for _checker in CHECKERS["checkers"]:
    _task = _TASKS_BY_ID[str(_checker["task_id"])]
    _checker["expected_selected_path_patch"] = {
        "bytes": _task["selected_path_historical_patch_bytes"],
        "sha256": _task["selected_path_historical_patch_sha256"],
    }
    _checker["type"] = "source_assertions_and_exact_selected_path_historical_patch_v1"


def build_corpus() -> dict[str, object]:
    return {
        "intake": {
            "approved_network_scope": "public_github_https_read_only",
            "approved_on_utc_date": "2026-08-17",
            "blob_filter": "blob:none",
        },
        "projects": PROJECTS,
        "sampling": {
            "curator_knew_historical_solutions": True,
            "kind": "retrospective_curated_finite_corpus",
            "probability_sample": False,
            "selection_criteria": [
                "single_parent_non_merge_commit",
                "selected_path_historical_patch_at_most_8192_bytes",
                "at_most_5_allowed_patch_paths",
                "self_contained_task_prompt",
                "offline_source_assertion_checker_discriminates_target_from_parent",
                "one_task_per_project_and_taxonomy_cell",
            ],
            "selection_limit": "claims_apply_only_to_the_12_selected_tasks_not_all_project_history",
        },
        "schema_version": "contextguard.p3-v3-corpus/v1",
        "tasks": TASKS,
        "taxonomy": ["bug_fix", "boundary_hardening", "feature", "maintenance"],
    }


def build_arms() -> list[dict[str, object]]:
    arms: list[dict[str, object]] = []
    for adaptive in (False, True):
        for symbol in (False, True):
            for graph in (False, True):
                arm_id = f"a{int(adaptive)}{int(symbol)}{int(graph)}"
                if graph:
                    repo_map_mode = "apply_symbol_memory_graph_pack_only"
                elif symbol:
                    repo_map_mode = "symbol_memory_advisory_only"
                else:
                    repo_map_mode = "none"
                arms.append(
                    {
                        "adaptive": adaptive,
                        "graph_closure": graph,
                        "id": arm_id,
                        "intervention": {
                            "manifest_adaptive_pruned": adaptive,
                            "manifest_graph_expanded": graph,
                            "packer_repo_map_mode": repo_map_mode,
                            "provider_sees_pure_symbol_projection": symbol,
                            "provider_sees_raw_symbol_memory": False,
                            "pure_symbol_projection_forbidden_fields": ["graph_context", "graph_edges", "graph_rank"] if symbol else [],
                        },
                        "symbol_memory": symbol,
                    }
                )
    return arms


def build_schedule() -> dict[str, object]:
    block_specs: list[tuple[str, int, str]] = []
    for item in TASKS:
        task_id = str(item["id"])
        for repetition in range(3):
            identity = f"{task_id}:r{repetition}"
            order_key = sha256(f"{SEED}\0block\0{identity}".encode("utf-8"))
            block_specs.append((task_id, repetition, order_key))
    block_specs.sort(key=lambda item: (item[2], item[0], item[1]))
    blocks: list[dict[str, object]] = []
    for task_id, repetition, order_key in block_specs:
        arm_order = sorted(
            ARMS,
            key=lambda arm: (
                sha256(f"{SEED}\0arm\0{task_id}\0{repetition}\0{arm}".encode("utf-8")),
                arm,
            ),
        )
        units = [
            {
                "arm_id": arm,
                "repetition": repetition,
                "task_id": task_id,
                "unit_id": f"{task_id}:r{repetition}:{arm}",
            }
            for arm in arm_order
        ]
        blocks.append(
            {
                "arm_order": arm_order,
                "block_id": f"{task_id}:r{repetition}",
                "block_order_key": order_key,
                "repetition": repetition,
                "task_id": task_id,
                "units": units,
            }
        )
    return {
        "arms_per_block": 8,
        "block_count": 36,
        "blocks": blocks,
        "order_algorithm": "ascending_sha256_seed_nul_domain_nul_identity",
        "repetitions_per_task_arm": 3,
        "scheduled_units": 288,
        "schema_version": "contextguard.p3-v3-schedule/v1",
        "seed": SEED,
        "stopping_rule": "one_terminal_receipt_per_scheduled_unit_no_reruns_replacements_or_extension",
    }


def artifact_binding(path: Path, raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "path": str(path.relative_to(ROOT)), "sha256": sha256(raw)}


def build_preregistration(bindings: dict[str, dict[str, object]]) -> dict[str, object]:
    return {
        "analysis": {
            "predeclared_contrasts": ["a111_minus_a000", "adaptive_main_effect", "symbol_memory_main_effect", "graph_closure_main_effect"],
            "inferential_claim_status": "unavailable_only_3_independent_project_clusters",
            "complete_case_rule": "all_3_repetitions_and_all_8_arms_per_task",
            "factorial_effect_count": 7,
            "independent_cluster": "project",
            "independent_cluster_count": 3,
            "interactions_and_arm_rows": "descriptive_with_intervals",
            "missingness_rule": "any_missing_unit_blocks_all_predeclared_contrast_and_factorial_effect_estimates",
            "multiplicity": "no_null_rejection_claims_report_all_4_predeclared_contrasts_and_all_7_factorial_effects",
            "main_effect_formulas": {
                "adaptive": "mean_task((a100+a101+a110+a111-a000-a001-a010-a011)/4)",
                "graph_closure": "mean_task((a001+a011+a101+a111-a000-a010-a100-a110)/4)",
                "symbol_memory": "mean_task((a010+a011+a110+a111-a000-a001-a100-a101)/4)",
            },
            "primary_percent_reduction": "100 * (sum_task_mean_a000 - sum_task_mean_a111) / sum_task_mean_a000",
            "primary_usage_estimand": "task_balanced_mean_total_provider_tokens_a111_minus_a000",
            "quality_gate": {
                "allowed_baseline_pass_candidate_fail_pairs": 0,
                "allowed_technical_missing_units": 0,
                "any_failure_blocks_quality_preserving_savings_claim": True,
                "required_checker_pass_rate": 1.0,
                "required_pass_scope": ["every_task", "every_taxonomy", "every_project"],
                "required_terminal_receipts": 288,
            },
            "technical_repetitions_reduced_within_task": 3,
            "total_provider_tokens": "input_tokens_plus_output_tokens",
            "uncertainty": {
                "claim": "descriptive_finite_corpus_sensitivity_only",
                "leave_one_project_out_rows": 3,
                "method": "all_27_ordered_project_cluster_resamples",
            },
        },
        "artifacts": bindings,
        "claims": {
            "all_task_quality_guarantee": False,
            "future_project_generalization": False,
            "probability_sample": False,
            "quality_outcome": "exact_selected_path_historical_patch_reproduction_plus_source_assertions",
            "scope": "these_12_retrospective_tasks_in_3_public_projects",
            "semantic_alternative_patch_acceptance": False,
            "semantic_correctness_guarantee": False,
        },
        "cost_evidence": {
            "calculated_list_price_authority": "calculated_not_provider_reported",
            "eight_exclusive_standard_keys": "provider_arm_aggregates_at_best",
            "messages_api_per_request_authority": "token_usage_only",
            "one_exclusive_standard_key": "provider_experiment_total_aggregate_only",
            "provider_confirmed_per_request_usd": "unavailable_without_request_level_export_or_unique_bucket_per_request",
            "raw_key_identifiers_public": False,
        },
        "design": {
            "arms": build_arms(),
            "factors": ["adaptive", "symbol_memory", "graph_closure"],
            "provider_input_rehearsal_gate": {
                "committed_before_provider_calls": True,
                "exact_pairwise_factor_byte_isolation": True,
                "required_unique_task_arm_inputs": 96,
                "required_units": 288,
                "scorer_fields_absent_from_every_provider_input": True,
            },
            "provider_prompt_variability": "only_context_pack_and_pure_symbol_projection_may_vary_by_arm",
            "provider_visible_factor_definition": "only_bytes_in_the_provider_prompt_are_interventions",
            "transformation_order": ["ordinary_selection", "adaptive_pruning", "graph_expansion", "pack_build", "pure_symbol_projection"],
        },
        "execution_authorized": False,
        "execution_protocol": {
            "apply_steps": ["git_apply_check", "git_apply", "verify_exact_selected_path_patch", "run_frozen_source_assertions"],
            "checker_timeout_seconds": 30,
            "completed_quality_failures": ["invalid_patch", "truncated_patch", "forbidden_path", "apply_failure", "checker_failure"],
            "dirty_tree_policy": "only_allowed_patch_paths_may_change",
            "network_during_checker": "denied",
            "provider_input_allowed_task_fields": ["allowed_patch_paths", "prompt"],
            "provider_input_non_allowlisted_fields_forbidden": True,
            "provider_input_task_field_policy": "closed_allowlist",
            "provider_worktree": "exported_parent_tree_without_git_history",
            "rejected_patch_features": ["absolute_path", "path_traversal", "symlink", "submodule", "binary_patch", "outside_allowed_paths"],
            "response_grammar": "exactly_one_utf8_unified_diff_no_prose_or_fences",
            "seal_raw_response_and_usage_before_parse": True,
            "technical_missingness": ["pre_receipt_transport_error", "pre_receipt_timeout", "cancellation", "identity_mismatch", "malformed_or_missing_receipt"],
        },
        "freeze": {
            "effective_after_tracked_commit": True,
            "provider_calls_before_tracked_commit_allowed": False,
            "tracked_commit": None,
        },
        "model_contract": {
            "adaptive_thinking": "disabled",
            "max_output_tokens": 4096,
            "messages_requests_per_unit": 1,
            "model": "claude-sonnet-5",
            "prompt_caching": "absent",
            "request_timeout_seconds": 120,
            "temperature": 0,
            "tools": "disabled",
        },
        "prepared_at_utc": "2026-08-17T10:20:00Z",
        "provider_calls_during_preregistration": 0,
        "schema_version": "contextguard.p3-api-factorial-preregistration/v3",
        "status": "draft_preregistered_no_execution",
    }


def write_artifacts() -> None:
    corpus_raw = canonical(build_corpus())
    schedule_raw = canonical(build_schedule())
    checkers_raw = canonical(CHECKERS)
    corpus_path = V3 / "corpus-manifest.json"
    schedule_path = V3 / "schedule.json"
    checkers_path = V3 / "scorer-only/checkers.json"
    prompt_template_path = V3 / "provider-prompt-template.txt"
    checkers_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    corpus_path.write_bytes(corpus_raw)
    schedule_path.write_bytes(schedule_raw)
    checkers_path.write_bytes(checkers_raw)
    prompt_template_path.write_bytes(PROMPT_TEMPLATE)
    bindings = {
        "checkers": artifact_binding(checkers_path, checkers_raw),
        "corpus": artifact_binding(corpus_path, corpus_raw),
        "prompt_template": artifact_binding(prompt_template_path, PROMPT_TEMPLATE),
        "schedule": artifact_binding(schedule_path, schedule_raw),
    }
    (V3 / "preregistration.json").write_bytes(canonical(build_preregistration(bindings)))
    for path in (corpus_path, schedule_path, checkers_path, prompt_template_path, V3 / "preregistration.json"):
        path.chmod(0o644)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if not args.write:
        parser.error("refusing to write without --write")
    write_artifacts()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
