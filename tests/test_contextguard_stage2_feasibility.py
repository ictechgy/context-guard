from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
import unittest
from pathlib import Path, PurePosixPath

from tests.test_contextguard_stage2_protected_surfaces import portable_regular_mode


REPO_ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = REPO_ROOT / "research/contextguard-stage2/host-observability.json"
BROKER_ROOT = REPO_ROOT / "research/contextguard-broker"
BROKER_RESEARCH_PATHS = {
    path.relative_to(REPO_ROOT).as_posix()
    for path in BROKER_ROOT.rglob("*")
    if path.is_file()
}

EXPECTED_BLOCKERS = [
    "EXACT_FRAMING_UNPROVEN",
    "HOST_OBSERVER_CONTRACT_UNSUPPORTED",
    "INERT_RESPONSE_UNPROVEN",
    "PROVIDER_JOIN_MISSING",
    "REAL_HOST_PERMISSION_OUTCOME_UNPROVEN",
]
EXPECTED_EVIDENCE_KINDS = {
    "fake_self_authored_fixture_limitations",
    "hook_payload_shape",
    "inert_response_proof_absent",
    "lifecycle_parsing",
    "measurement_gap_requirements",
    "model_visible_framed_bytes_proof_absent",
    "real_host_permission_outcomes_absent",
}
EXPECTED_EVIDENCE_ANCHORS_SHA256 = (
    "0b7decab25063c9dacb25d0a1314273a2bbbacea8564f8c6a21d2a3c752c2a03"
)
EXPECTED_BROKER_RESEARCH_PATHS_COUNT = 30
EXPECTED_BROKER_RESEARCH_PATHS_SHA256 = (
    "c17061a0a8d7a674c515032a3aa65b20c67c3a78dc4909d4b235d4a63b75d4aa"
)
EXPECTED_STAGE2_BASELINE_COMMIT = "d7d53b9a63b367fd6a868e3ed018bb8bc1b79e67"
EXPECTED_STAGE2_BASELINE_PRODUCTION_INVENTORY_COUNT = 152
EXPECTED_STAGE2_BASELINE_PRODUCTION_INVENTORY_SHA256 = (
    "3146a2c380e206c9b609ed4150f125a0c8f41ad65364910334e0ce70dbb3dd25"
)
RECEIPT_PACKAGE_PREFIX = "packages/context-guard-receipt/"
PROVIDER_FREE_BASE_REF = "origin/main"
PROVIDER_FREE_HEAD_REF = "HEAD"
PROVIDER_FREE_SUPPORT_PATHS = frozenset(
    {
        ".claude-plugin/marketplace.json",
        ".github/workflows/ci.yml",
        ".github/workflows/npm-candidate.yml",
        ".github/workflows/npm-promote.yml",
        ".github/workflows/npm-publish.yml",
        "CHANGELOG.md",
        "README.ko.md",
        "README.md",
        "bench/token-savings-12task/README.md",
        "bench/token-savings-12task/study-plan-v2.json",
        "context-guard-kit/bash_reference_policy.py",
        "context-guard-kit/benchmark_runner.py",
        "context-guard-kit/context_guard_commands.py",
        "context-guard-kit/rewrite_bash_for_token_budget.py",
        "context-guard-kit/setup_wizard.py",
        "context-guard-kit/trim_command_output.py",
        "docs/distribution.md",
        "docs/release-runbook.md",
        "package.json",
        "plugins/context-guard/.claude-plugin/plugin.json",
        "plugins/context-guard/README.ko.md",
        "plugins/context-guard/README.md",
        "plugins/context-guard/bin/bash_reference_policy.py",
        "plugins/context-guard/bin/context-guard-bench",
        "plugins/context-guard/bin/context-guard-rewrite-bash",
        "plugins/context-guard/bin/context-guard-setup",
        "plugins/context-guard/bin/context-guard-trim-output",
        "plugins/context-guard/lib/context_guard_commands.py",
        "research/benchmark-plan.md",
        "research/p1-live-authorization-packet.md",
        "research/token-savings-roadmap.md",
        "scripts/build_npm_candidates.py",
        "scripts/rehearse_measurement_study.py",
        "scripts/release_smoke.py",
        "scripts/verify_gate_b_rollback.py",
        "tests/test_bash_reference_v1.py",
        "tests/test_benchmark_study_v2.py",
        "tests/test_context_guard_kit.py",
        "tests/test_context_guard_kit_benchmark_surfaces.py",
        "tests/test_context_guard_receipt_suite.py",
        "tests/test_gate_b_rollback_proof.py",
        "tests/test_contextguard_stage2_completion.py",
        "tests/test_contextguard_stage2_feasibility.py",
        "tests/test_contextguard_stage2_protected_surfaces.py",
        "tests/test_npm_candidates.py",
        "tests/test_release_candidate_smoke.py",
        "tests/test_workflows.py",
    }
)
EXPECTED_RECEIPT_COMPANION_INVENTORY_COUNT = 113
RECEIPT_COMPANION_INVENTORY = [
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/LICENSE', 'sha256': 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/NOTICE', 'sha256': '40978c42e96a7b452cb77ef41f28961ca880e46ee7fa7c9589afa4d532655779'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/README.md', 'sha256': 'b075742abc57962a5c10c9edcc41c67a16947a2ddd13fb64fb97e7c4d27e57e7'},
    {'file_type': 'regular', 'mode': '0755', 'path': 'packages/context-guard-receipt/bin/context-guard-receipt-mcp.cjs', 'sha256': '883b893d5ee484d63b78174ace60e171dc26e032d05dd19298fb6d6c5229cffd'},
    {'file_type': 'regular', 'mode': '0755', 'path': 'packages/context-guard-receipt/bin/context-guard-receipt.cjs', 'sha256': 'bdab50b0476e40024ea64f1f6cd0a46260b4707e2297d212bf5034cfd5a87ff8'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/bin/launcher.cjs', 'sha256': '7f9c630fdcd8df5fe561a15dcafe1961218b9d5b28b3a3b0c6ccfba4ffa96fed'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/dev/package_check.py', 'sha256': 'f2512995ad2773a028e5efee87f7545e696d8f188fcf8b566e8f5c43591d13c8'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/dev/packaged_acceptance.py', 'sha256': '4e19ffbc8ac97affed3c1bfc7204b09e09fa63cd750c745cac8ef1adf63e78dd'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/package-files.json', 'sha256': '17a930f7877127698c8189181d19fae7e973c446d03cf65dc9cb4b520f316f6e'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/package.json', 'sha256': 'daf789323e9b194943b7222bd0bf112432460afe0174d0a3363cbadbbd37c475'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/__init__.py', 'sha256': '1046588c63e24a72c3a57ab0ebd6d60d86c158358b5bbd50ca15cf26322fabc6'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/assembly.py', 'sha256': '0e28b6e0874477314436eecb532c767d61efe6d506ae8f79d98fae4b41dd35ea'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/blueprint.py', 'sha256': 'f4b8b617832ebe4bd5dc585f762a20b71b37ce79d54b6cd751f1e5fde5b785f0'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/bootstrap.py', 'sha256': 'fa846a8968c5199618ab68a86424c0cb88c32250291faf3ac37f26d14d4b018e'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/canonical.py', 'sha256': '91b57a1ebf2cc8fa0025ccfc8eaf6f50bc9363e6d3bc05c517b2014bf8a590c7'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/cli.py', 'sha256': 'e93c8970a1f06cff4511e62c1e6d7803f94d083239b159a2839da7e8ca3a0bb9'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/cli_io.py', 'sha256': '2de5ef56762e015264527306f19b1b72995cc3fffd8cd6cb58c8206e255c5baf'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/contracts.py', 'sha256': '1127a9b90bf2da63a097b066c7f1678109dcf622f40dd6746ef055aa7a98e39e'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/diagnostic_ledger.py', 'sha256': '3cc7865709c273b72136c48b1026ed5cd2830ea1bf76da4e424da08ccc13499d'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/diagnostics.py', 'sha256': '9a95f511b639091d0aacef69c0d4a311ad81e5a97299ab45ddc7fc23579e0e52'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/evidence_pack.py', 'sha256': '3fb5540dcee31cd6ded4883e4f4c99fb89ee17c2484f3e2ee33ebe741454d0f8'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/execution_twin.py', 'sha256': '510239b13c37ef15dcc838222b07ada49877e5540c351a51a121983b1fe031af'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/expansion.py', 'sha256': '9b848e555f05a621665c6b167a49e5d8085ffc9c6906f040f43fd2a87e981f2b'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/identity.py', 'sha256': '31d4a0ba5e2a04b277a027a872ee0172c5d27ed09b60c41f53f286dd2d8b963c'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/mcp.py', 'sha256': 'db251fdd3e3d98cd83fd9a29ee0b90cb308c1bfa3fbed9122a217c80e75fe4c2'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/merged_capture.py', 'sha256': 'a19c605a47b666f302b8b993d1e0973bfded46c1974022c2620c5ef5d598b7cf'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/protection.py', 'sha256': '67ae06abb102292b3db09a6731a4aab90b3bc6ceb6dbe836fc636f82f783c347'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/receipts.py', 'sha256': '11c02d9df36be0dec2316594fd083ec39a1284325ded440de075081d2e56ddb0'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/reference_expiry.py', 'sha256': '2445292456776d5fcbf789f75a71781d64f12865958249d192cfc5a5ff27f2f6'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/router.py', 'sha256': '22b395d0a8a0522fcc9b12c1b12493e90aafb9e374937725a2bdaf223188529c'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/runner.py', 'sha256': '2193f7ae1032990b2ff5d954bd97ea6de67d58a9eb2cf395e939b25593a79cf8'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/sanitizer.py', 'sha256': 'ddf7d4d81dbb73156fa2274c7adf06475c4688b1e08341835aff4eeb81a72fc8'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/store.py', 'sha256': '6bf5f033ebc1cfaf72dbfa685ed4ce3339dfe0af53b88bab726ed0847767e8ed'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/python/context_guard_receipt/tool_schemas.py', 'sha256': 'f84a8bc2f2232250dfe0782aaddf35c9842720f4815c6d2d8e4bd95757546bbc'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/assembly-receipt.schema.json', 'sha256': '05ab76b261ca18ed8d165cb4e43395006e7196fdeccb53603c3ed77ca3bdfe88'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/blueprint-descriptor.schema.json', 'sha256': '4424c2c482dc8d4184f1bd7ac6e1e45ad4ee36ee97da13e75b0986b2da8c9b09'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/capability-record.schema.json', 'sha256': '86df8398c5199a0d4e3d58ee7d8e2a4171e0103a5ea05644f00f1c343889c114'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/command-capture-receipt.schema.json', 'sha256': '7bcdaeb52fdfa4cbb3dc57b8d4b3b1cfa318bb7d8af11574ae0e23126ffa954b'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/diagnostic-ledger-entry.schema.json', 'sha256': '8ea3ee4db48fb6d54b1bb613253f3313a38d33516ff328887feb6dfcc5c6c2ef'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/diagnostic-ledger-inspection.schema.json', 'sha256': '2258c63aba7ada14949fe7db2e757d42551009d026d3152e3d95191c934b110f'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/diagnostic-ledger-metadata.schema.json', 'sha256': '2ab1092790c97e0aa9439dd6f1f59004368a9e71e9b7dc1d849a2d2f59369e2a'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/diagnostics-report.schema.json', 'sha256': 'b779475abbfdd76c9b6fca8f39b9b0c4e058f8e65a0ff9d7f583a1b8b01db38c'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/diagnostics-request.schema.json', 'sha256': '7779d364170db90b8e7b71a342156d0b5bb0fe8ff8b423c21df29005d7efa2b4'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/evidence-boundary.schema.json', 'sha256': 'b510303bd09adcaf7150415aab5cae3adbe4c99b8482c07a45bb978ad4e82ba7'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/evidence-descriptor.schema.json', 'sha256': '29fa127eeafb8c52c05c7cdc8b1b929919e47e8e94aa8a5e6cd81ea2cf973dff'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/evidence-pack.schema.json', 'sha256': '5ff6823d166b245a488e6d0f96512ae025b7836f7f46e5e14dc4508edfad6692'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/evidence-reference.schema.json', 'sha256': 'f94fa353dac99a08793461ca9ec72962ce12de2e5328f94039048190db70071e'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/expansion-envelope.schema.json', 'sha256': 'f838f84a06a433e62706467aa40097194f458bb2b3d42c600159558bed292d71'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/expansion-refusal.schema.json', 'sha256': 'c5196da89d9b96349deb4c2c0ad2970d6f27d7760f9236b6d07d702443ee9da0'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/protection-decision.schema.json', 'sha256': 'e7cf1b413d286347fda8f0f3a993676212e257f7e280757657032c23b5f9415f'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/reference-expiry-inspection.schema.json', 'sha256': '6f862e4e39ebb09e14952b542d4a28a52c618900ecfa07dca063846c638721e1'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/reference-expiry-metadata.schema.json', 'sha256': 'a72ed7c5f422732437cdc9e61e00efc5ea7e765c74955243f5b11b8a6eb12a73'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/reference-expiry-record.schema.json', 'sha256': '450940d3f9d6d0baf7540c2bb2269f23ce8c53106658d7e9fdfe80392b7bad0e'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/reference-expiry-request.schema.json', 'sha256': '9b96d2dac7ed9e23af17fbcb9311b4d2a5f3c7c04d042de380af3732887d6c89'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/reference-expiry-result.schema.json', 'sha256': 'ed0c72aed6f21fdd3d78332768981da8db19e69a130cb881d3b86b7d61c13d82'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/shadow-firewall-report.schema.json', 'sha256': '016a0d7320b9dc8c444f7488fdcd8bd33752fcfd27c1e906741972b9de50d04c'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/source-identity.schema.json', 'sha256': 'c20007a9a03e8168feb7b413e035e1d3ef2cdad23a7c404dc25014a03411b047'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/store-commit.schema.json', 'sha256': 'e078e14eade2395772936ecd8ec8a9add8b4a71ea45a1b6935645a83a46147ad'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/store-metadata.schema.json', 'sha256': 'be6a83707fa541436e5930e444cfc6431d618ef65f561718a5ed66bf42f447db'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/tool-schema-bundle.schema.json', 'sha256': 'bebb1d2ef79cfd76a870f6be554f7e1708e5015912885adc720ab3bc9495428d'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/tool-schema-catalog-reference.schema.json', 'sha256': '306109a80512c6c6685bfcc00592fd81961030c459115717775ead6d79e8b4e7'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/tool-schema-descriptor.schema.json', 'sha256': '1ebf3da9f7e81fc7de2eb9c19769011e6dbb590323a17a1febb2def9c85d3c87'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/tool-schema-expansion-envelope.schema.json', 'sha256': '870aaafcd8e40bad739ebd9de316fe4ef15dc2e46ccee015dcb9ad1d886b68d2'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/tool-schema-expansion-refusal.schema.json', 'sha256': 'e2bc67e71069d3f4c493db4e4aa946d65ee037eded5963ba00bf5c6bae51eefd'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/tool-schema-expansion-request.schema.json', 'sha256': '0f21e070d4480279a849ba510c74cd26df8a1f8c0cfed5f0e7f73d6b9079dc39'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/tool-schema-receipt.schema.json', 'sha256': '08621631baf4bc9abd01681c7e5194a73c6d7dd6f42571e7b91baffe323e2745'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/tool-schema-reference.schema.json', 'sha256': '09f047b9d935e49e9b50e8e13e792a99bfe72eb356c1ad87e51dc0d0ac47f571'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/twin-event.schema.json', 'sha256': 'fb74363bd595b8f8034ba33622bfa4018f566b75491232b462e8674de13671fb'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/twin-metadata.schema.json', 'sha256': 'ab137d319fd151beaf9ae595633ab2d2be748b4efb6e1636b3052b663da6f9b8'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/twin-request.schema.json', 'sha256': '0955de5d331555fb5662a3038022df6a7cf679692f77d4747923fbd9121d9acd'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/twin-result.schema.json', 'sha256': '14b7cec1a2818d1fa0fac61b05dd77ffc683a01812372b64a8c5f24660b73735'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/twin-snapshot.schema.json', 'sha256': 'c80da58c9c3ef2d49fdf0527d3310b611c87fde6c9fc6e9ee889d2cb127b65ff'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/schemas/typed-blueprint.schema.json', 'sha256': 'd784099a65a700d9e9e72ea6993b8480c9bf7c7efa2f222a7f341a271526b97c'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/scripts/verify_protected_surfaces.py', 'sha256': 'ad4f22c1fcff118a24787ca3b09badac03523342151c2111d1adeaff16cadeb9'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/adversarial/__init__.py', 'sha256': 'cc7bab82ee31fa4e8bd55746442746877fee99a76cf1c9376ec95d5f3f8a11ba'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/adversarial/test_g012_mcp_capabilities.py', 'sha256': '668635b035bf72078c65ca8695eafe7869073caf8004915ae8ec73ca48506adf'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/adversarial/test_g012_mcp_limits.py', 'sha256': 'f08aa835ab1ed03c24df35caa3c8bf97640886ddde467f2532ff722a9bf1aa82'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/__init__.py', 'sha256': '5075760cded34ab259a764674a6620d857ab3eb623e037bf5066abe132de88bd'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_boundary.py', 'sha256': '85fb9bae2b76687bf26086de651feab872113623fd9a27325634ec23c36e3b97'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g001_distribution_contract.py', 'sha256': '7af1c294242bb9739befda35491622e65664c4c574a25b5802a3e1eb378e3ebd'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g002_canonical.py', 'sha256': '574a66140918d02765e5de7a1fa2e243843e32d464e438fe637c42aae41d7fe5'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g002_protection.py', 'sha256': 'b05064c39f88962a7b561532cfa2ef00b8a90605375cd06d9052ced8d0ef352e'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g003_identity.py', 'sha256': '0c6c7f18bed584fe707b8203d1534f78e21f192226f2dc5d961696eac4fa9bd9'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g004_store.py', 'sha256': 'a28e4157d1f82018e9ac13b5d81711a4c95805efe8d7a25ec4f3b206dc2ae7f1'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g005_assembly.py', 'sha256': 'cd4f9085021f8140a8548abffe1b5e43d21e448a805af4655211bd3a52314dec'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g005_cli.py', 'sha256': '644615a87a30b78aff4b1853ce20e48c37cc7de57f50e3f3d13b7032adbaffd6'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g005_evidence_pack.py', 'sha256': '32103f3dac04d1030433277df8cbc29384c1a7018bb24fee1151a3b8188b3462'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g005_expansion.py', 'sha256': 'f95483364192035ae1f5a1c081f4cb7da361da69f3854bfe7cb6c318bb260c81'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g005_router.py', 'sha256': '4175e98ba75763cc8057e5311b5d9886587791e3190d30dd0d154860f4943230'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g005_schemas.py', 'sha256': '82d0e21c77bef68d3a2f5ffc74826739f85739a86dffbeac7d187ec73c0522fd'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g006_cli.py', 'sha256': '38137caa415eb4cdf04a062f11b0f2324d59d163d1b2456272041087f4a7ad90'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g006_schemas.py', 'sha256': 'a3ab27bf36dde335b2e4611381e8099f2a34c2e0ceed6cd05795d8ef0932114a'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g006_tool_schemas.py', 'sha256': '2f279112fb96e6b99085b34d22a80ee67d57f9204037614a337487c08a4ccbe3'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g007_sanitizer.py', 'sha256': '933397c2b0d1dc2f4944dadab5ce83af97eb5a79a42670d9e5ba26d6cd504200'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g008_cli.py', 'sha256': '541d9f1a3218b0225bee6015cd26b9d027d59663d1974b91dc51ba5c5f98e0ae'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g008_expansion.py', 'sha256': '4a3d1bbd3b5ee6fffde6eb4c523e55d749894807d991af083fc0cdae263605da'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g008_runner.py', 'sha256': '489252498bce09bfb57b5237a60ac7df587a8cc52df1e598327f75e863bf772b'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g009_cli.py', 'sha256': '9c967aff4e2961890953865e7c4598d031b14761eee3e3ce3a76a194383b165a'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g009_diagnostics.py', 'sha256': '454031b9b2bf48d17b8108f616d34484dc9c0366d03deb5b8252b76365c497c8'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g009_ledger.py', 'sha256': 'b5bfc17842d505cf1c3deaa497bf286578ca8843b9b41ee9f1995467f19b9de4'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g010_cli.py', 'sha256': 'cbed019a922c50a21cb1d572d164ef0e4cfd8aa092ff16263449f31dc68821b9'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g010_schemas.py', 'sha256': '057d2e6afbda38d8673efd88cf31d5a752bac6288b53f9c92adb4699c18bad08'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g010_twin.py', 'sha256': 'b84f0ea7898b04b8b925ca039cca4f3ecc3f482d07709075d127c5ffc00c4fd7'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g011_cli.py', 'sha256': 'c8425596db359b0c0fb32f1051d216addb3d558a8bfc1fcde5e923d682a0bff9'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g011_reference_expiry.py', 'sha256': 'f8091435e1407b7480980e44b2d06e0f571f2e25a65421128af87186ac1ea22a'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g011_schemas.py', 'sha256': '83028fec21ca7dfd31f91e9afe98751b9bd67241d7aad4f0c7c73d4da3cf6439'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g012_mcp.py', 'sha256': '8599153ce43b6f6cfce4972b550b3cffdad867557f8b566e0832f85b7c6e4a7e'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g012_mcp_cli.py', 'sha256': '539014f2009a78832467115d6b671c5807d2c4e16e7519ccde6ed70e629ec70a'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g013_package_audit.py', 'sha256': '948e8c6ff27851ef60a43570c7b5a0f30185d15b06e9504780943a3bd3067158'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/contract/test_g014_merged_capture.py', 'sha256': 'dacc04f7ac0b09b210ce9cbb2081d049707fff92cb9effad7c1e03a95669c600'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/e2e/__init__.py', 'sha256': '48a5ccfc49a840928c6de0ea2c978a12a0abd78e2f361ec96f6e9a0f15bddca0'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/e2e/test_g001_offline_distribution.py', 'sha256': '01d856590d17f5a457c1664b49c92f6b52378314a9b272df802a759113413b7d'},
    {'file_type': 'regular', 'mode': '0644', 'path': 'packages/context-guard-receipt/tests/e2e/test_g012_mcp_stdio.py', 'sha256': '96ac49c60d27d2558bbfaec9805135605c15ab25bd5de682dc63620ade52a8fc'},
]
FORBIDDEN_TOP_LEVEL_FIELDS = {
    "host_id",
    "host_version",
    "permission_outcome",
    "provider_attribution",
    "provider_turn_id",
    "settings_hash",
}
FORBIDDEN_RUNTIME_NAMES = {
    "host-observer.py",
    "runtime-observer.py",
    "stage2-runner.py",
    "transport.py",
}
EXPECTED_STAGE2_ARTIFACT_NAMES = {
    "S3D-ARF-charter.json",
    "host-observability.json",
    "protected-surface-manifest.json",
    "verification-record.json",
    "verification-record.schema.json",
}
EXPECTED_STAGE2_ARTIFACT_PATHS = {
    f"research/contextguard-stage2/{name}" for name in EXPECTED_STAGE2_ARTIFACT_NAMES
}
NON_PRODUCTION_TOP_LEVEL_DOCS = {
    "CHANGELOG.md",
    "LICENSE",
    "NOTICE",
    "README.ko.md",
    "README.md",
}


def provider_free_changed_paths(
    repo_root: Path = REPO_ROOT,
    base_ref: str = PROVIDER_FREE_BASE_REF,
    head_ref: str = PROVIDER_FREE_HEAD_REF,
) -> set[str]:
    merge_bases = subprocess.run(
        ["git", "merge-base", "--all", base_ref, head_ref],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.splitlines()
    if len(merge_bases) != 1:
        raise AssertionError("provider-free history must have exactly one merge base")
    merge_base = merge_bases[0]
    if len(merge_base) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in merge_base
    ):
        raise AssertionError("provider-free merge base is not a full Git object id")
    raw_paths = subprocess.run(
        [
            "git",
            "diff",
            "--no-ext-diff",
            "--name-only",
            "--no-renames",
            "-z",
            "--ignore-submodules=none",
            f"{merge_base}..{head_ref}",
            "--",
        ],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    try:
        return {
            encoded_path.decode("utf-8")
            for encoded_path in raw_paths.split(b"\0")
            if encoded_path
        }
    except UnicodeDecodeError as exc:
        raise AssertionError("changed paths must be valid UTF-8") from exc


def validate_provider_free_changed_paths(paths: set[str]) -> None:
    allowed_paths = {
        *(entry["path"] for entry in RECEIPT_COMPANION_INVENTORY),
        *PROVIDER_FREE_SUPPORT_PATHS,
    }
    for path_text in paths:
        path = PurePosixPath(path_text)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != path_text:
            raise AssertionError("changed paths must be normalized repository-relative paths")
        if path_text in allowed_paths:
            continue
        if path_text.startswith("research/contextguard-broker/"):
            raise AssertionError(f"unexpected broker research surface changed: {path_text}")
        if path_text.startswith("research/contextguard-stage2/"):
            raise AssertionError(f"unexpected Stage 2 evidence surface changed: {path_text}")
        raise AssertionError(f"production or undeclared surface changed: {path_text}")


def validate_broker_research_paths(paths: set[str]) -> None:
    encoded = json.dumps(
        sorted(paths), ensure_ascii=True, separators=(",", ":")
    ).encode()
    if len(paths) != EXPECTED_BROKER_RESEARCH_PATHS_COUNT:
        raise AssertionError("broker research path count drifted")
    if hashlib.sha256(encoded).hexdigest() != EXPECTED_BROKER_RESEARCH_PATHS_SHA256:
        raise AssertionError("broker research path set drifted")


def repository_visible_paths() -> list[str]:
    raw_paths = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return sorted({item.decode("utf-8") for item in raw_paths.split(b"\0") if item})


def surface_inventory(visible_paths: list[str]) -> list[dict[str, str]]:
    inventory: list[dict[str, str]] = []
    for path_text in visible_paths:
        path = PurePosixPath(path_text)
        if path_text.startswith(("docs/", "tests/")) or path_text in NON_PRODUCTION_TOP_LEVEL_DOCS:
            continue
        if path_text in BROKER_RESEARCH_PATHS or path_text in EXPECTED_STAGE2_ARTIFACT_PATHS:
            continue
        if path_text.startswith("research/") and path.suffix == ".md":
            continue
        try:
            mode = (REPO_ROOT / path_text).lstat().st_mode
        except OSError as exc:
            raise AssertionError(f"production inventory path is unavailable: {path_text}") from exc
        if stat.S_ISREG(mode):
            file_type = "regular"
            content = (REPO_ROOT / path_text).read_bytes()
            portable_mode = portable_regular_mode(mode)
        elif stat.S_ISLNK(mode):
            file_type = "symlink"
            content = os.fsencode(os.readlink(REPO_ROOT / path_text))
            portable_mode = "symlink"
        else:
            raise AssertionError(f"unsupported production inventory type: {path_text}")
        inventory.append(
            {
                "file_type": file_type,
                "mode": portable_mode,
                "path": path_text,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return inventory


def is_legacy_production_path(path_text: str) -> bool:
    path = PurePosixPath(path_text)
    return not (
        path_text.startswith(RECEIPT_PACKAGE_PREFIX)
        or path_text.startswith(("docs/", "tests/"))
        or path_text in NON_PRODUCTION_TOP_LEVEL_DOCS
        or path_text in BROKER_RESEARCH_PATHS
        or path_text in EXPECTED_STAGE2_ARTIFACT_PATHS
        or (path_text.startswith("research/") and path.suffix == ".md")
    )


def production_surface_inventory() -> list[dict[str, str]]:
    visible_paths = [
        path_text
        for path_text in repository_visible_paths()
        if is_legacy_production_path(path_text)
    ]
    return surface_inventory(visible_paths)


def receipt_companion_surface_inventory() -> list[dict[str, str]]:
    return surface_inventory(
        [
            path_text
            for path_text in repository_visible_paths()
            if path_text.startswith(RECEIPT_PACKAGE_PREFIX)
        ]
    )


def historical_production_surface_inventory(
    revision: str = EXPECTED_STAGE2_BASELINE_COMMIT,
) -> list[dict[str, str]]:
    raw_tree = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", revision],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    inventory: list[dict[str, str]] = []
    for record in (item for item in raw_tree.split(b"\0") if item):
        metadata, raw_path = record.split(b"\t", maxsplit=1)
        mode_text, object_type, object_id = metadata.decode("ascii").split()
        path_text = raw_path.decode("utf-8")
        if object_type != "blob" or not is_legacy_production_path(path_text):
            continue
        content = subprocess.run(
            ["git", "cat-file", "blob", object_id],
            cwd=REPO_ROOT,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        mode = int(mode_text, 8)
        if stat.S_ISREG(mode):
            file_type = "regular"
            portable_mode = portable_regular_mode(mode)
        elif stat.S_ISLNK(mode):
            file_type = "symlink"
            portable_mode = "symlink"
        else:
            raise AssertionError(f"unsupported historical inventory type: {path_text}")
        inventory.append(
            {
                "file_type": file_type,
                "mode": portable_mode,
                "path": path_text,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return sorted(inventory, key=lambda entry: entry["path"])


def validate_production_surface_inventory(inventory: list[dict[str, str]]) -> None:
    if inventory != sorted(inventory, key=lambda entry: entry.get("path", "")):
        raise AssertionError("production inventory must be sorted")
    for entry in inventory:
        if set(entry) != {"file_type", "mode", "path", "sha256"}:
            raise AssertionError("production inventory entries must be closed")
    canonical = json.dumps(
        inventory, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    if len(inventory) != EXPECTED_STAGE2_BASELINE_PRODUCTION_INVENTORY_COUNT:
        raise AssertionError("production inventory path count drifted")
    if (
        hashlib.sha256(canonical).hexdigest()
        != EXPECTED_STAGE2_BASELINE_PRODUCTION_INVENTORY_SHA256
    ):
        raise AssertionError("production inventory path/type/mode digest drifted")


def validate_receipt_companion_surface_inventory(inventory: list[dict[str, str]]) -> None:
    if len(inventory) != EXPECTED_RECEIPT_COMPANION_INVENTORY_COUNT:
        raise AssertionError("receipt companion inventory path count drifted")
    if inventory != RECEIPT_COMPANION_INVENTORY:
        raise AssertionError("receipt companion inventory path/type/mode/hash drifted")


def validate_stage2_historical_baseline_identity(
    inventory: list[dict[str, str]] | None = None,
    revision: str = EXPECTED_STAGE2_BASELINE_COMMIT,
) -> None:
    if revision != EXPECTED_STAGE2_BASELINE_COMMIT:
        raise AssertionError("Stage 2 historical baseline revision drifted")
    historical_inventory = (
        historical_production_surface_inventory(revision) if inventory is None else inventory
    )
    validate_production_surface_inventory(historical_inventory)
    historical_unchanged = [
        entry for entry in historical_inventory
        if entry["path"] not in PROVIDER_FREE_SUPPORT_PATHS
    ]
    current_unchanged = [
        entry for entry in production_surface_inventory()
        if entry["path"] not in PROVIDER_FREE_SUPPORT_PATHS
    ]
    if historical_unchanged != current_unchanged:
        raise AssertionError("current legacy inventory drifted from the Stage 2 baseline")


def validate_record(record: object) -> None:
    if not isinstance(record, dict):
        raise AssertionError("record must be an object")
    expected_keys = {
        "blockers",
        "claim_allowed",
        "evidence_anchors",
        "provider_join_status",
        "requested_mode",
        "runtime_observer_authorized",
        "schema_version",
        "selected_branch",
        "selected_transport",
    }
    if set(record) != expected_keys:
        raise AssertionError("record has missing or invented top-level fields")
    if FORBIDDEN_TOP_LEVEL_FIELDS & set(record):
        raise AssertionError("host/provider identifiers must not be invented or normalized")
    expected_scalars = {
        "schema_version": "contextguard-stage2-host-observability/v1",
        "requested_mode": "runtime_feasibility",
        "selected_branch": "S2-UNSUPPORTED",
        "selected_transport": "NONE",
        "runtime_observer_authorized": False,
        "provider_join_status": "missing",
        "claim_allowed": False,
    }
    for field, expected in expected_scalars.items():
        if record.get(field) != expected:
            raise AssertionError(f"{field} must be {expected!r}")
    if record.get("blockers") != EXPECTED_BLOCKERS:
        raise AssertionError("blockers must be the exact sorted closed set")

    anchors = record.get("evidence_anchors")
    if not isinstance(anchors, list) or not anchors:
        raise AssertionError("evidence anchors must be a non-empty list")
    if [anchor.get("kind") for anchor in anchors] != sorted(EXPECTED_EVIDENCE_KINDS):
        raise AssertionError("evidence kinds must be exact, unique, and sorted")
    anchor_digest = hashlib.sha256(
        json.dumps(anchors, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    if anchor_digest != EXPECTED_EVIDENCE_ANCHORS_SHA256:
        raise AssertionError("evidence authority, path, and support tuples must remain exact")
    for anchor in anchors:
        if set(anchor) != {"authority", "kind", "path", "supports"}:
            raise AssertionError("evidence anchor shape is closed")
        path_text = anchor["path"]
        path = PurePosixPath(path_text)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != path_text:
            raise AssertionError("evidence paths must be normalized repository-relative paths")
        if not (REPO_ROOT / path_text).is_file():
            raise AssertionError(f"missing evidence anchor: {path_text}")
        if anchor["authority"] not in {"repository_contract", "limitation_only"}:
            raise AssertionError("fake or provider authority is forbidden")
        if anchor["kind"] == "fake_self_authored_fixture_limitations":
            if anchor["authority"] != "limitation_only":
                raise AssertionError("self-authored fixtures cannot establish host authority")
        if not isinstance(anchor["supports"], str) or not anchor["supports"]:
            raise AssertionError("each anchor needs a bounded support statement")


class ContextGuardStage2FeasibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = RECORD_PATH.read_bytes()
        cls.record = json.loads(cls.raw)

    def test_canonical_unsupported_record_and_repository_anchors(self) -> None:
        canonical = json.dumps(
            self.record, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode() + b"\n"
        self.assertEqual(self.raw, canonical)
        validate_record(self.record)

    def test_rejects_degraded_or_invented_authority(self) -> None:
        mutations = {
            "framed branch": {"selected_branch": "S2-FRAMED"},
            "shape degradation": {"selected_branch": "S2-SHAPE"},
            "path fallback": {"selected_transport": "PATH"},
            "runtime observer": {"runtime_observer_authorized": True},
            "provider attribution": {"provider_join_status": "attributed"},
            "claim": {"claim_allowed": True},
            "invented host": {"host_id": "normalized-host"},
        }
        for label, changes in mutations.items():
            candidate = copy.deepcopy(self.record)
            candidate.update(changes)
            with self.subTest(label=label), self.assertRaises(AssertionError):
                validate_record(candidate)

        fake_authority = copy.deepcopy(self.record)
        fake_anchor = next(
            anchor
            for anchor in fake_authority["evidence_anchors"]
            if anchor["kind"] == "fake_self_authored_fixture_limitations"
        )
        fake_anchor["authority"] = "repository_contract"
        with self.assertRaises(AssertionError):
            validate_record(fake_authority)

        detached_anchor = copy.deepcopy(self.record)
        detached_anchor["evidence_anchors"][0]["path"] = "package.json"
        detached_anchor["evidence_anchors"][0]["supports"] = "x"
        with self.assertRaises(AssertionError):
            validate_record(detached_anchor)

    def test_historical_baseline_is_reconstructed_from_the_frozen_commit(self) -> None:
        historical_inventory = historical_production_surface_inventory()
        validate_stage2_historical_baseline_identity(historical_inventory)
        self.assertEqual(
            [
                entry for entry in historical_inventory
                if entry["path"] not in PROVIDER_FREE_SUPPORT_PATHS
            ],
            [
                entry for entry in production_surface_inventory()
                if entry["path"] not in PROVIDER_FREE_SUPPORT_PATHS
            ],
        )

        with self.assertRaises(AssertionError):
            validate_stage2_historical_baseline_identity(
                historical_production_surface_inventory(
                    f"{EXPECTED_STAGE2_BASELINE_COMMIT}^"
                ),
                revision=f"{EXPECTED_STAGE2_BASELINE_COMMIT}^",
            )

    def test_no_runtime_observer_or_transport_surface_exists(self) -> None:
        stage2_root = RECORD_PATH.parent
        present = {path.name for path in stage2_root.iterdir() if path.is_file()}
        self.assertEqual(present, EXPECTED_STAGE2_ARTIFACT_NAMES)
        self.assertTrue(FORBIDDEN_RUNTIME_NAMES.isdisjoint(present))
        self.assertFalse(any(path.suffix in {".py", ".sh"} for path in stage2_root.iterdir()))

        changed = provider_free_changed_paths()
        validate_stage2_historical_baseline_identity()
        validate_broker_research_paths(BROKER_RESEARCH_PATHS)
        validate_provider_free_changed_paths(changed)
        validate_provider_free_changed_paths(set())
        with self.assertRaises(AssertionError):
            validate_provider_free_changed_paths(changed | {"research/unrelated-user-notes.md"})

        inventory = production_surface_inventory()
        self.assertTrue(
            all(set(entry) == {"file_type", "mode", "path", "sha256"} for entry in inventory)
        )
        self.assertEqual(inventory, sorted(inventory, key=lambda entry: entry["path"]))
        content_mutation = copy.deepcopy(inventory)
        content_mutation[0]["sha256"] = "0" * 64
        with self.assertRaises(AssertionError):
            validate_production_surface_inventory(content_mutation)
        for committed_runtime_path in (
            ".claude/hooks/contextguard-observer",
            "src/contextguard_observer.rs",
            "tools/contextguard-observer",
        ):
            invented_inventory = inventory + [
                {
                    "file_type": "regular",
                    "mode": "0755",
                    "path": committed_runtime_path,
                    "sha256": "0" * 64,
                }
            ]
            with self.subTest(committed_runtime_path=committed_runtime_path):
                with self.assertRaises(AssertionError):
                    validate_production_surface_inventory(invented_inventory)
        for runtime_path in (
            "runtime_observer.py",
            "context-guard-kit/alternate_observer.py",
            "plugins/context-guard/bin/context-guard-stage2",
            "scripts/stage2-runner.py",
            "bench/contextguard-broker/canary-settings.json",
            "package-lock.json",
            "research/canary-settings.json",
            "tools/contextguard-observer",
            "src/contextguard_observer.rs",
            ".claude/hooks/contextguard-observer",
        ):
            with self.subTest(runtime_path=runtime_path), self.assertRaises(AssertionError):
                validate_provider_free_changed_paths(changed | {runtime_path})


if __name__ == "__main__":
    unittest.main()
