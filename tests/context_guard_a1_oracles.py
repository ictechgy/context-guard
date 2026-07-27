#!/usr/bin/env python3
"""Deterministic shared property/oracle fixtures for the ContextGuard A1 gate.

This module intentionally contains no production imports. Feature-owned tests
may consume these cases from either the checkout or a staged package without
letting the implementation define its own expected behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random
import re
import shlex
from typing import Callable, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = (
    ROOT
    / "tests"
    / "fixtures"
    / "context_guard_contracts"
    / "a1-property-oracle-v1.json"
)
FIXTURE_SCHEMA_VERSION = 1
ROUTE_POLICY_VERSION = "minishell-route-v1"
ROUTE_SEED = 0xA10003
ASSIGNMENT_SEED = 0xA1B1
SANITIZER_SEED = 0xA15A
ENTRYPOINTS = ("canonical", "packaged")
ASSIGNMENT_POSITIONS = ("direct_prefix", "ordinary_argv", "restricted_env")
MINISHELL_FORBIDDEN_BASENAMES = (
    "curl",
    "wget",
    "fetch",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "ftp",
    "sftp",
    "scp",
    "ssh",
    "telnet",
    "tee",
    "eval",
    "exec",
)
MINISHELL_FORBIDDEN_SHELL_BASENAMES = (
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
)
SANITIZATION_MODES = (
    "unknown_text",
    "command_search_diff",
    "filesystem_listing",
    "source_code",
)
PRIVATE_ROOT = "/Users/contextguard/private"


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "case"


def _case_id(prefix: str, *parts: object) -> str:
    digest_input = "\0".join(str(part) for part in parts).encode("utf-8")
    digest = hashlib.sha256(digest_input).hexdigest()[:10]
    readable = "-".join(_slug(str(part))[:24] for part in parts[:3])
    return f"{prefix}-{readable}-{digest}"


def _route_command(command: str, role: str) -> str:
    if role == "standalone":
        return command
    if role == "first":
        return f"{command} | cat"
    if role == "filter":
        return f"printf '%s\\n' ok | {command}"
    raise ValueError(f"unsupported route role: {role}")


def _route_examples() -> list[dict[str, str]]:
    examples: list[dict[str, str]] = []

    def add(
        family: str,
        roles: Sequence[str],
        positives: Sequence[str],
        positive_outcome: str | Mapping[str, str],
        negatives: Sequence[str],
        *,
        negative_outcome: str = "deny",
        note: str = "",
    ) -> None:
        for role in roles:
            if isinstance(positive_outcome, str):
                outcome = positive_outcome
            else:
                outcome = positive_outcome[role]
            for command in positives:
                examples.append(
                    {
                        "family": family,
                        "role": role,
                        "command": _route_command(command, role),
                        "expected_decision": outcome,
                        "expectation": "accept",
                        "note": note,
                    }
                )
            if isinstance(negative_outcome, str):
                negative_decision = negative_outcome
            else:
                negative_decision = negative_outcome[role]
            for command in negatives:
                examples.append(
                    {
                        "family": family,
                        "role": role,
                        "command": _route_command(command, role),
                        "expected_decision": negative_decision,
                        "expectation": "reject",
                        "note": note,
                    }
                )

    add(
        "printf",
        ("standalone", "first"),
        ("printf '%s\\n' ok", "printf -- '%s\\n' ok"),
        {"standalone": "noop", "first": "rewrite_trim"},
        ("printf -v out ok",),
    )
    add(
        "cat-producer",
        ("standalone", "first"),
        ("cat -n -- README.md", "cat -b README.md"),
        {"standalone": "noop", "first": "rewrite_trim"},
        ("cat --number README.md",),
    )
    add(
        "cat-filter",
        ("filter",),
        ("cat", "cat -n"),
        "rewrite_trim",
        ("cat README.md", "cat --number"),
    )
    add(
        "git-diff",
        ("standalone", "first"),
        ("git diff --stat -- README.md", "git diff -U3"),
        "rewrite_sanitize",
        ("git --no-pager diff", "git diff --ext-diff", "git diff --textconv"),
    )
    add(
        "ripgrep",
        ("standalone", "first"),
        ("rg -n -- token .", "rg --glob='*.py' token tests"),
        "rewrite_sanitize",
        ("rg --files", "rg --pre cat token .", "rg --replace x token ."),
    )
    add(
        "grep-producer",
        ("standalone", "first"),
        ("grep -n -e token -- README.md", "egrep -m2 token README.md"),
        "rewrite_sanitize",
        ("grep -f patterns README.md", "grep --binary-files=text token README.md"),
    )
    add(
        "grep-filter",
        ("filter",),
        ("grep -n token", "fgrep -m2 token"),
        "rewrite_sanitize",
        ("grep token README.md", "grep -f patterns"),
    )
    add(
        "head-tail-producer",
        ("standalone", "first"),
        ("head -20 README.md", "head -n20 README.md", "tail -50 README.md"),
        {"standalone": "rewrite_trim", "first": "rewrite_trim"},
        ("head -c 20 README.md", "tail -f README.md"),
    )
    add(
        "head-tail-filter",
        ("filter",),
        ("head -n 20", "tail --lines=50"),
        "rewrite_trim",
        ("head -n 20 README.md", "tail -F"),
    )
    add(
        "cut",
        ("standalone", "filter"),
        ("cut -f1", "cut -d: -f1", "cut --complement -c1-3 --"),
        {"standalone": "noop", "filter": "rewrite_trim"},
        ("cut -f1 README.md", "cut -d:"),
    )
    add(
        "sed",
        ("standalone", "filter"),
        ("sed -n '1,3p'", "sed -n -e '5p'"),
        {"standalone": "noop", "filter": "rewrite_trim"},
        ("sed -n 's/x/y/'", "sed -i '1p'", "sed -n -f script.sed"),
    )
    add(
        "sort",
        ("standalone", "filter"),
        ("sort -k1,1", "sort -r -t: -k1"),
        {"standalone": "noop", "filter": "rewrite_trim"},
        ("sort -o output.txt", "sort README.md"),
    )
    add(
        "uniq",
        ("standalone", "filter"),
        ("uniq -f1", "uniq -f 1", "uniq -c -w10"),
        {"standalone": "noop", "filter": "rewrite_trim"},
        ("uniq input.txt", "uniq -f0"),
    )
    add(
        "wc",
        ("standalone", "filter"),
        ("wc -cl", "wc --"),
        {"standalone": "noop", "filter": "rewrite_trim"},
        ("wc README.md", "wc -L"),
    )
    add(
        "direct-noisy",
        ("standalone", "first"),
        ("pytest -q", "tox -q", "jest --runInBand", "vitest run"),
        "rewrite_trim",
        ("pytest -q > result.txt",),
    )
    add(
        "language-noisy",
        ("standalone", "first"),
        ("python3 -m pytest -q", "python -m unittest", "go test ./...", "cargo test"),
        "rewrite_trim",
        ("python3 -m pip test", "go env test", "cargo metadata test"),
        negative_outcome={"standalone": "noop", "first": "deny"},
        note="negative examples prove exact subcommand positions, not invalid grammar",
    )
    add(
        "npm-family",
        ("standalone", "first"),
        (
            "npm --prefix . test",
            "pnpm run test:unit -- --runInBand",
            "yarn --cwd . build",
        ),
        "rewrite_trim",
        ("npm --unknown value test",),
    )
    add(
        "npx",
        ("standalone", "first"),
        ("npx --no-install jest", "npx -p jest jest --runInBand"),
        "rewrite_trim",
        ("npx echo jest",),
        negative_outcome={"standalone": "noop", "first": "deny"},
        note="shifted noisy word is a normal unknown-standalone command",
    )
    add(
        "make",
        ("standalone", "first"),
        ("make -C . test", "make --silent lint"),
        "rewrite_trim",
        ("make -C test help",),
        negative_outcome={"standalone": "noop", "first": "deny"},
        note="only the first target is classification evidence",
    )
    add(
        "jvm-noisy",
        ("standalone", "first"),
        ("mvn -q test", "./mvnw test", "gradle --quiet test", "./gradlew test"),
        "rewrite_trim",
        ("mvn package test", "gradle tasks test"),
        negative_outcome={"standalone": "noop", "first": "deny"},
    )
    add(
        "forbidden",
        ("standalone", "first", "filter"),
        ("curl https://example.invalid", "tee output.txt", "bash -lc 'echo blocked'"),
        "deny",
        (),
        note="forbidden basename/path spelling is immutable deny",
    )
    add(
        "unknown",
        ("standalone",),
        ("custom-tool alpha beta",),
        "noop",
        (),
    )
    add(
        "unknown-pipeline",
        ("first", "filter"),
        (),
        "deny",
        ("custom-tool alpha",),
        note="unknown commands are admitted only as standalone commands",
    )
    return examples


def route_cases(seed: int = ROUTE_SEED) -> list[dict[str, object]]:
    """Return the route-table corpus crossed with canonical/package entrypoints."""
    rng = random.Random(seed)
    examples = _route_examples()
    rng.shuffle(examples)
    cases: list[dict[str, object]] = []
    for entrypoint in ENTRYPOINTS:
        for ordinal, example in enumerate(examples):
            case = {
                "case_id": _case_id(
                    "route",
                    entrypoint,
                    example["family"],
                    example["role"],
                    example["command"],
                ),
                "seed": seed,
                "ordinal": ordinal,
                "policy_version": ROUTE_POLICY_VERSION,
                "entrypoint": entrypoint,
                **example,
            }
            cases.append(case)
    return cases


def minishell_normative_cases() -> list[dict[str, object]]:
    """Return the compact MiniShell-v1 grammar/route security contract.

    Commands at the large parser bounds are generated separately so the
    checked-in oracle remains reviewable and never embeds multi-megabyte test
    payloads.
    """
    cases: list[dict[str, object]] = [
        {
            "case_id": "minishell-parenthesized-printf-data",
            "family": "original-false-positive",
            "command": "printf '%s\\n' '(1) normal'",
            "expected_decision": "noop",
            "expected_argv": ("printf", "%s\\n", "(1) normal"),
        },
        {
            "case_id": "minishell-parenthesized-rg-data",
            "family": "original-false-positive",
            "command": "rg '(1) normal' README.md",
            "expected_decision": "sanitize",
            "expected_argv": ("rg", "(1) normal", "README.md"),
        },
        {
            "case_id": "minishell-quoted-syntax-data",
            "family": "original-false-positive",
            "command": "printf '%s\\n' '|' '&&' '$()' '${x}' '`id`'",
            "expected_decision": "noop",
            "expected_argv": ("printf", "%s\\n", "|", "&&", "$()", "${x}", "`id`"),
        },
        {
            "case_id": "minishell-boundary-comment-data",
            "family": "comment",
            "command": "printf '%s\\n' ok # grep | git diff > out; curl x",
            "expected_decision": "noop",
            "expected_argv": ("printf", "%s\\n", "ok"),
        },
        {
            "case_id": "minishell-opaque-single-quoted-heredoc",
            "family": "heredoc",
            "command": "sort <<'DATA'\ncurl https://example.invalid\n$(touch SHOULD_NOT_RUN)\n| && (1)\nDATA",
            "expected_decision": "noop",
            "expected_argv": ("sort",),
            "expected_heredoc_delimiter": "DATA",
        },
        {
            "case_id": "minishell-opaque-double-quoted-heredoc",
            "family": "heredoc",
            "command": 'wc -l <<"DATA"\n$(touch SHOULD_NOT_RUN)\ncurl example.invalid\nDATA',
            "expected_decision": "noop",
            "expected_argv": ("wc", "-l"),
            "expected_heredoc_delimiter": "DATA",
        },
        {
            "case_id": "minishell-unquoted-heredoc-denied",
            "family": "heredoc",
            "command": "sort <<DATA\n$(touch SHOULD_NOT_RUN)\nDATA",
            "expected_decision": "deny",
            "expected_denial_reason": "unquoted_heredoc_delimiter",
        },
        {
            "case_id": "minishell-multiple-heredocs-denied",
            "family": "heredoc",
            "command": "sort <<'A' <<'B'\nopaque\nA\nopaque\nB",
            "expected_decision": "deny",
        },
        {
            "case_id": "minishell-pipeline-heredoc-denied",
            "family": "heredoc",
            "command": "printf ok | sort <<'DATA'\nopaque\nDATA",
            "expected_decision": "deny",
        },
        {
            "case_id": "minishell-nonconsumer-heredoc-denied",
            "family": "heredoc",
            "command": "printf ok <<'DATA'\nopaque\nDATA",
            "expected_decision": "deny",
        },
        {
            "case_id": "minishell-heredoc-leftover-denied",
            "family": "heredoc",
            "command": "sort <<'DATA'\nopaque\nDATA\nprintf leftover",
            "expected_decision": "deny",
            "expected_denial_reason": "leftover_after_heredoc",
        },
        {
            # FIX-5: 이름이 시드 화이트리스트 안이므로(NODE_ENV, CI) 여전히 noop —
            # `env NAME=val -- cmd` 파싱 형태 자체가 허용됨을 검증하는 케이스.
            # 원래는 FOO/EMPTY 를 썼으나 화이트리스트 밖이라 deny 로 바뀌므로
            # 파싱-형태 검증이라는 이 케이스의 원래 취지를 유지하려면 화이트리스트
            # 안의 이름으로 교체해야 한다(§5.5 5열: 위치는 워킹 리포 밖 읽기 없음,
            # 자격증명 표면 없음, 출력 유계, 축 b 무영향, 역방향은 바로 아래 신규
            # 케이스가 원본 FOO/EMPTY 입력으로 고정).
            "case_id": "minishell-restricted-env-accepted",
            "family": "restricted-env",
            "command": "env NODE_ENV=production CI= -- printf ok",
            "expected_decision": "noop",
            "expected_argv": ("env", "NODE_ENV=production", "CI=", "--", "printf", "ok"),
        },
        {
            # 역방향 케이스(신규) — 위 케이스의 원래 입력을 그대로 고정한다. FOO/EMPTY
            # 는 시드 화이트리스트 밖이므로 이제 unsafe_env_name_denied 로 거부되어야
            # 한다. INV-A: 기존에 이미 deny 는 아니었지만(noop→deny 전환), FIX-5 는
            # 이 전환 방향을 명시적으로 허용한다(AC-5.5는 반대 방향 0건만 요구).
            "case_id": "minishell-restricted-env-unsafe-name-denied",
            "family": "restricted-env",
            "command": "env FOO=bar EMPTY= -- printf ok",
            "expected_decision": "deny",
        },
    ]

    for segment_count in range(1, 9):
        command = "printf '%s\\n' ok"
        if segment_count > 1:
            command += " | " + " | ".join("cat" for _ in range(segment_count - 1))
        cases.append(
            {
                "case_id": f"minishell-pipeline-{segment_count}-segments",
                "family": "pipeline",
                "command": command,
                "expected_decision": "noop" if segment_count == 1 else "trim",
                "expected_segments": segment_count,
            }
        )

    restricted_env_commands = (
        "env -i printf ok",
        "env --ignore-environment printf ok",
        "env -u HOME printf ok",
        "env --unset=HOME printf ok",
        "env --chdir=/tmp printf ok",
        "env --unknown printf ok",
        "env FOO=bar",
    )
    for command in restricted_env_commands:
        cases.append(
            {
                "case_id": _case_id("minishell-restricted-env", command),
                "family": "restricted-env",
                "command": command,
                "expected_decision": "deny",
            }
        )

    wrapper_commands = (
        (
            "context-guard-trim-output --max-lines 220 -- bash -lc 'pytest -q'",
            "incoming_wrapper_denied",
        ),
        (
            "context-guard-sanitize-output --context-guard-wrapper-v1 command_search_diff -- bash -lc 'rg x .'",
            "incoming_wrapper_denied",
        ),
        (
            "claude-trim-output --max-lines 220 -- bash -lc 'pytest -q'",
            "incoming_wrapper_denied",
        ),
        (
            "python3 /tmp/trim_command_output.py --max-lines 220 -- bash -lc 'pytest -q'",
            "incoming_wrapper_denied",
        ),
        (
            "context-guard-sanitize-output x--context-guard-wrapper-v1 -- bash -lc 'rg x .'",
            "nested_wrapper_denied",
        ),
        (
            "context-guard-sanitize-output --context-guard-wrapper-v1 --context-guard-wrapper-v1",
            "nested_wrapper_denied",
        ),
    )
    for command, expected_wrapper_code in wrapper_commands:
        cases.append(
            {
                "case_id": _case_id("minishell-incoming-wrapper", command),
                "family": "incoming-wrapper",
                "command": command,
                "expected_decision": "deny",
                "expected_wrapper_code": expected_wrapper_code,
            }
        )

    for basename in MINISHELL_FORBIDDEN_BASENAMES:
        for spelling in (basename, f"/usr/bin/{basename}", f"./bin/{basename}"):
            cases.append(
                {
                    "case_id": _case_id("minishell-forbidden", spelling),
                    "family": "forbidden-name",
                    "command": f"{spelling} literal-argument",
                    "expected_decision": "deny",
                }
            )
            cases.append(
                {
                    "case_id": _case_id("minishell-forbidden-filter", spelling),
                    "family": "forbidden-name",
                    "command": f"printf '%s\\n' ok | {spelling} literal-argument",
                    "expected_decision": "deny",
                }
            )

    for basename in MINISHELL_FORBIDDEN_SHELL_BASENAMES:
        for spelling in (basename, f"/bin/{basename}", f"./bin/{basename}"):
            for option in ("-c", "-lc", "-xc"):
                cases.append(
                    {
                        "case_id": _case_id(
                            "minishell-forbidden-shell",
                            spelling,
                            option,
                        ),
                        "family": "forbidden-shell",
                        "command": f"{spelling} {option} 'printf safe'",
                        "expected_decision": "deny",
                    }
                )
    for case in cases:
        case["policy_version"] = ROUTE_POLICY_VERSION
    return cases


def minishell_bound_cases() -> list[dict[str, object]]:
    """Generate exact/+1 MiniShell-v1 bound cases without fixture bloat."""
    exact_command = "echo " + ("a" * (65_536 - len("echo ")))
    oversized_command = exact_command + "a"

    exact_words = "echo " + " ".join("x" for _ in range(255))
    oversized_words = exact_words + " x"

    exact_segments = " | ".join("cat" for _ in range(8))
    oversized_segments = exact_segments + " | cat"

    segment_words: list[list[str]] = []
    for segment_index in range(8):
        command_word = "echo" if segment_index == 0 else "cat"
        segment_words.append([command_word, *("x" for _ in range(255))])
    segment_words[0][0] += "''" * 2_041
    exact_items = " | ".join(" ".join(words) for words in segment_words)
    segment_words[0][0] += "''"
    oversized_items = " | ".join(" ".join(words) for words in segment_words)

    delimiter_64 = "D" * 64
    delimiter_65 = "D" * 65
    exact_delimiter = f"sort <<'{delimiter_64}'\nopaque\n{delimiter_64}"
    oversized_delimiter = f"sort <<'{delimiter_65}'\nopaque\n{delimiter_65}"

    cases = [
        {
            "case_id": "minishell-command-bytes-exact",
            "command": exact_command,
            "expected_denial_reason": None,
            "expected_command_bytes": 65_536,
        },
        {
            "case_id": "minishell-command-bytes-plus-one",
            "command": oversized_command,
            "expected_denial_reason": "command_bytes_exceeded",
            "expected_command_bytes": 65_537,
        },
        {
            "case_id": "minishell-lexical-items-exact",
            "command": exact_items,
            "expected_denial_reason": None,
            "expected_lexical_items": 4_096,
        },
        {
            "case_id": "minishell-lexical-items-plus-one",
            "command": oversized_items,
            "expected_denial_reason": "lexical_items_exceeded",
        },
        {
            "case_id": "minishell-words-per-segment-exact",
            "command": exact_words,
            "expected_denial_reason": None,
            "expected_words_per_segment": 256,
        },
        {
            "case_id": "minishell-words-per-segment-plus-one",
            "command": oversized_words,
            "expected_denial_reason": "segment_words_exceeded",
        },
        {
            "case_id": "minishell-segments-exact",
            "command": exact_segments,
            "expected_denial_reason": None,
            "expected_segments": 8,
        },
        {
            "case_id": "minishell-segments-plus-one",
            "command": oversized_segments,
            "expected_denial_reason": "invalid_pipeline",
        },
        {
            "case_id": "minishell-heredoc-delimiter-exact",
            "command": exact_delimiter,
            "expected_denial_reason": None,
            "expected_heredoc_delimiter": delimiter_64,
        },
        {
            "case_id": "minishell-heredoc-delimiter-plus-one",
            "command": oversized_delimiter,
            "expected_denial_reason": "invalid_heredoc_delimiter",
        },
    ]
    for case in cases:
        case["policy_version"] = ROUTE_POLICY_VERSION
    return cases


def _logical_word(raw_word: str) -> str:
    """Compute the literal logical word for the bounded fixture alphabet only."""
    without_continuations = raw_word.replace("\\\n", "")
    logical: list[str] = []
    i = 0
    quote: str | None = None
    while i < len(without_continuations):
        char = without_continuations[i]
        if quote is not None:
            if char == quote:
                quote = None
            else:
                logical.append(char)
            i += 1
            continue
        if char in {"'", '"'}:
            quote = char
            i += 1
            continue
        if char == "\\" and i + 1 < len(without_continuations):
            logical.append(without_continuations[i + 1])
            i += 2
            continue
        logical.append(char)
        i += 1
    if quote is not None:
        raise ValueError(f"unterminated oracle fixture word: {raw_word!r}")
    return "".join(logical)


def _assignment_command(raw_word: str, position: str) -> str:
    if position == "direct_prefix":
        return f"{raw_word} printf '%s\\n' ok"
    if position == "ordinary_argv":
        return f"printf '%s\\n' {raw_word}"
    if position == "restricted_env":
        return f"/usr/bin/env {raw_word} /usr/bin/printenv FOO"
    raise ValueError(f"unsupported assignment position: {position}")


def _assignment_templates() -> list[dict[str, object]]:
    deny = "deny"
    noop = "noop"
    return [
        {"raw_word": "FOO=~", "expected_decision": deny, "site": "first_equal"},
        {"raw_word": "FOO=prefix:~", "expected_decision": deny, "site": "later_colon"},
        {"raw_word": "FOO=~:~", "expected_decision": deny, "site": "multiple_active"},
        {"raw_word": "FOO=a:~:~", "expected_decision": deny, "site": "multiple_active"},
        {
            "raw_word": "FOO=\\\n~",
            "expected_decision": deny,
            "site": "removed_continuation_equal",
        },
        {
            "raw_word": "FOO=prefix:\\\n~",
            "expected_decision": deny,
            "site": "removed_continuation_colon",
        },
        {
            "raw_word": "FO\\\nO=~",
            "expected_decision": deny,
            "site": "removed_continuation_name",
        },
        {"raw_word": "F'O'O=~", "expected_decision": noop, "site": "quoted_name"},
        {"raw_word": "F\\OO=~", "expected_decision": noop, "site": "escaped_name"},
        {"raw_word": "'FOO'=~", "expected_decision": noop, "site": "quoted_name"},
        {"raw_word": "F''OO=~", "expected_decision": noop, "site": "empty_quote_name"},
        {"raw_word": "FOO''=~", "expected_decision": noop, "site": "empty_quote_name"},
        {
            "raw_word": "FOO='prefix':~",
            "expected_decision": deny,
            "site": "later_colon_after_quote",
        },
        {
            "raw_word": 'FOO="prefix":~',
            "expected_decision": deny,
            "site": "later_colon_after_quote",
        },
        {"raw_word": "9FOO=~", "expected_decision": noop, "site": "invalid_name"},
        {"raw_word": "FOO'='~", "expected_decision": noop, "site": "quoted_equal"},
        {"raw_word": "FOO\\=~", "expected_decision": noop, "site": "escaped_equal"},
        {
            "raw_word": "FOO=a=~",
            "expected_decision": noop,
            "site": "later_equal_literal",
            "env_prefix_name_recognized": True,
        },
        {"raw_word": "FOO=a=:~", "expected_decision": deny, "site": "scan_after_equal"},
        {"raw_word": "FOO=a=~:~", "expected_decision": deny, "site": "later_colon"},
        {
            "raw_word": "FOO=''~",
            "expected_decision": noop,
            "site": "empty_quote_suppression",
            "env_prefix_name_recognized": True,
        },
        {
            'raw_word': 'FOO=""~',
            "expected_decision": noop,
            "site": "empty_quote_suppression",
            "env_prefix_name_recognized": True,
        },
        {
            "raw_word": "FOO=prefix:''~",
            "expected_decision": noop,
            "site": "empty_quote_suppression",
            "env_prefix_name_recognized": True,
        },
        {
            "raw_word": 'FOO=prefix:""~',
            "expected_decision": noop,
            "site": "empty_quote_suppression",
            "env_prefix_name_recognized": True,
        },
        {"raw_word": "FOO='':~", "expected_decision": deny, "site": "locality"},
        {"raw_word": "FOO=''prefix:~", "expected_decision": deny, "site": "locality"},
        {
            "raw_word": "FOO=\\\n''~",
            "expected_decision": noop,
            "site": "removed_plus_retained",
            "env_prefix_name_recognized": True,
        },
        {
            'raw_word': 'FOO=\\\n""~',
            "expected_decision": noop,
            "site": "removed_plus_retained",
            "env_prefix_name_recognized": True,
        },
        {
            "raw_word": "FOO=prefix:\\\n''~",
            "expected_decision": noop,
            "site": "removed_plus_retained",
            "env_prefix_name_recognized": True,
        },
        {
            "raw_word": 'FOO=prefix:\\\n""~',
            "expected_decision": noop,
            "site": "removed_plus_retained",
            "env_prefix_name_recognized": True,
        },
        {"raw_word": "''FOO=~", "expected_decision": noop, "site": "leading_empty_name"},
        {
            "raw_word": "FOO=x~",
            "expected_decision": noop,
            "site": "nonprefix_tilde",
            "env_prefix_name_recognized": True,
        },
        {
            "raw_word": "FOO='prefix:'~",
            "expected_decision": noop,
            "site": "quoted_colon",
            "env_prefix_name_recognized": True,
        },
        {
            "raw_word": "FOO=prefix\\:~",
            "expected_decision": noop,
            "site": "escaped_colon",
            "env_prefix_name_recognized": True,
        },
        {
            "raw_word": "FOO=prefix:'~'",
            "expected_decision": noop,
            "site": "quoted_tilde",
            "env_prefix_name_recognized": True,
        },
        {
            "raw_word": "FOO=prefix:\\~",
            "expected_decision": noop,
            "site": "escaped_tilde",
            "env_prefix_name_recognized": True,
        },
    ]


def _generated_assignment_templates(seed: int) -> list[dict[str, object]]:
    rng = random.Random(seed)
    generated: list[dict[str, object]] = []
    separators = (
        ("", True, "direct_adjacency"),
        ("\\\n", True, "removed_continuation"),
        ("''", False, "empty_single_quote"),
        ('""', False, "empty_double_quote"),
        ("'x'", False, "nonempty_quote"),
    )
    for index in range(24):
        name = rng.choice(("A", "VAR", "PATH", "A1_NAME", "TOKEN_COUNT"))
        prefix = rng.choice(("", "prefix", "a=b", "x:y"))
        delimiter = "=" if index % 2 == 0 else ":"
        separator, active, mutation = separators[index % len(separators)]
        if delimiter == "=":
            raw_word = f"{name}={separator}~"
        else:
            raw_word = f"{name}={prefix}:{separator}~"
        if not active and index % 3 == 0:
            raw_word += ":~"
            active = True
            mutation += "_later_active"
        generated.append(
            {
                "raw_word": raw_word,
                "expected_decision": "deny" if active else "noop",
                "site": f"seeded_{mutation}",
                "generated": True,
                # 이름 풀(A/VAR/PATH/A1_NAME/TOKEN_COUNT)이 항상 인용되지 않은 유효
                # 식별자이므로 assignment_index 는 항상 인식된다(FIX-5 무관 상수).
                "env_prefix_name_recognized": True,
            }
        )
    return generated


# FIX-5 가 라우팅 접두사 이름을 검사하는 위치. `ordinary_argv` 는 할당 word 가
# 명령 뒤(단순 인자)에 오므로 `_routing_start` 의 접두사 스캔에 전혀 닿지 않는다.
_ENV_PREFIX_ROUTED_POSITIONS = frozenset({"direct_prefix", "restricted_env"})


def _assignment_effective_expectation(
    template: Mapping[str, object],
    position: str,
) -> tuple[str, str | None]:
    """B1 템플릿의 (decision, reason) 을 FIX-5 접두사 이름 게이트까지 반영해 계산한다.

    B1 오라클은 항상 화이트리스트 밖 이름(FOO/A/VAR/...)만 쓴다 — 애초에 tilde
    출처 판정을 시험하려는 목적이지 이름 정책을 시험하려는 게 아니다. 템플릿이
    tilde-active 로 이미 deny 이면 FIX-5 는 절대 관여하지 않는다(tilde 검사가
    라우팅보다 먼저 실행됨, `classify_command` 참고). 템플릿이 noop 이고 이름이
    문법적으로 인식되며(`env_prefix_name_recognized`) 위치가 접두사 스캔 구간이면
    FIX-5 가 새로 deny 로 승격시킨다 — noop→deny 는 INV-A 가 명시적으로 허용하는
    강화 방향 전환이다.
    """
    expected_decision = str(template["expected_decision"])
    if expected_decision == "deny":
        return "deny", "active_shell_expansion_denied"
    name_recognized = bool(template.get("env_prefix_name_recognized", False))
    if position in _ENV_PREFIX_ROUTED_POSITIONS and name_recognized:
        return "deny", "unsafe_env_name_denied"
    return "noop", None


def assignment_provenance_cases(
    seed: int = ASSIGNMENT_SEED,
) -> list[dict[str, object]]:
    """Return fixed and seeded B1 provenance cases across every command position."""
    templates = [*_assignment_templates(), *_generated_assignment_templates(seed)]
    cases: list[dict[str, object]] = []
    for entrypoint in ENTRYPOINTS:
        for position in ASSIGNMENT_POSITIONS:
            for ordinal, template in enumerate(templates):
                raw_word = str(template["raw_word"])
                expected_decision, expected_reason = _assignment_effective_expectation(
                    template, position
                )
                case = {
                    "case_id": _case_id(
                        "assignment",
                        entrypoint,
                        position,
                        ordinal,
                        raw_word,
                        expected_decision,
                    ),
                    "seed": seed,
                    "ordinal": ordinal,
                    "entrypoint": entrypoint,
                    "position": position,
                    "raw_word": raw_word,
                    "logical_word": _logical_word(raw_word),
                    "command": _assignment_command(raw_word, position),
                    "expected_wrapper_launches": 0,
                    "expected_side_effects": 0,
                    **{key: value for key, value in template.items() if key != "raw_word"},
                    "expected_decision": expected_decision,
                    "expected_reason": expected_reason,
                }
                cases.append(case)
    return cases


def prepare_path_lookup_canary(root: Path) -> dict[str, object]:
    """Create a controlled bare-target PATH lookup canary without executing it."""
    root = root.resolve()
    home = root / "home"
    probe = home / "bin" / "cg_probe"
    marker = root / "probe-executed.marker"
    probe.parent.mkdir(parents=True, exist_ok=True)
    probe.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' executed > {shlex.quote(str(marker))}\n",
        encoding="utf-8",
    )
    probe.chmod(0o700)
    return {
        "case_id": "path-cg-probe-bare-target-v1",
        "command": "/usr/bin/env PATH=/missing:~/bin cg_probe ARG",
        "environment": {"HOME": str(home)},
        "probe_path": str(probe),
        "marker_path": str(marker),
        "expected_decision": "deny",
        "expected_reason": "active_shell_expansion_denied",
        "expected_wrapper_launches": 0,
        "expected_probe_executions": 0,
        "expected_marker_exists": False,
        "claim": "bare target proves denial before PATH lookup",
    }


def path_lookup_canary() -> dict[str, object]:
    """Return the serializable canary contract without creating files."""
    return {
        "case_id": "path-cg-probe-bare-target-v1",
        "command": "/usr/bin/env PATH=/missing:~/bin cg_probe ARG",
        "controlled_home_layout": "$HOME/bin/cg_probe",
        "expected_decision": "deny",
        "expected_reason": "active_shell_expansion_denied",
        "expected_wrapper_launches": 0,
        "expected_probe_executions": 0,
        "expected_marker_exists": False,
        "claim": "bare target proves denial before PATH lookup",
        "absolute_control": (
            "/usr/bin/env PATH=/missing:~/bin /usr/bin/printenv PATH"
        ),
        "absolute_control_claim": "expansion observation only; not PATH lookup proof",
    }


def _sanitizer_literals() -> list[dict[str, object]]:
    return [
        {
            "category": "route",
            "input": "/api/v1/users",
            "default_expectation": "preserve",
        },
        {
            "category": "route",
            "input": "/health/check",
            "default_expectation": "preserve",
        },
        {
            "category": "source_regex",
            "input": 'r"/foo/bar"',
            "default_expectation": "preserve",
        },
        {
            "category": "private_path_plain",
            "input": f"{PRIVATE_ROOT}/project/secrets.txt",
            "expectation_by_mode": {
                "unknown_text": "preserve",
                "command_search_diff": "preserve",
                "filesystem_listing": "redact_path",
                "source_code": "preserve",
            },
        },
        {
            "category": "traceback_location",
            "input": (
                f'  File "{PRIVATE_ROOT}/project/app.py", line 17, in main'
            ),
            "expectation_by_mode": {
                "unknown_text": "preserve",
                "command_search_diff": "redact_path",
                "filesystem_listing": "redact_path",
                "source_code": "preserve",
            },
        },
        {
            "category": "grep_location",
            "input": f"{PRIVATE_ROOT}/project/app.py:12:match",
            "expectation_by_mode": {
                "unknown_text": "preserve",
                "command_search_diff": "redact_path",
                "filesystem_listing": "redact_path",
                "source_code": "preserve",
            },
        },
        {
            "category": "source_import",
            "input": "from app.routes import users",
            "default_expectation": "preserve",
        },
        {
            "category": "benign_usage",
            "input": "token_count = 123; output_tokens: 313; max_tokens=4096",
            "default_expectation": "preserve",
        },
        {
            "category": "benign_types",
            "input": "token: str; Optional[str]; token: string; tokenizer",
            "default_expectation": "preserve",
        },
        {
            "category": "benign_identifiers",
            "input": "secretary signature_algorithm token_budget=100",
            "default_expectation": "preserve",
        },
        {
            "category": "authorization_header",
            "input": "Authorization: Bearer sk-test-abcdefghijklmnopqrstuvwxyz123456",
            "default_expectation": "redact_secret",
        },
        {
            "category": "cookie_header",
            "input": "Cookie: session=abcdefghijklmnopqrstuvwxyz0123456789",
            "default_expectation": "redact_secret",
        },
        {
            "category": "credential_url",
            "input": "https://fixture-user:fixture-password@example.invalid/private",
            "default_expectation": "redact_secret",
        },
        {
            "category": "private_key",
            "input": (
                "-----BEGIN PRIVATE KEY-----\n"
                "ZmFrZS1maXh0dXJlLW9ubHk=\n"
                "-----END PRIVATE KEY-----"
            ),
            "default_expectation": "redact_secret",
        },
        {
            "category": "credential_assignment",
            "input": "api_key=sk-test-abcdefghijklmnopqrstuvwxyz123456",
            "default_expectation": "redact_secret",
        },
    ]


def sanitizer_mode_cases(seed: int = SANITIZER_SEED) -> list[dict[str, object]]:
    """Return the four-mode literal matrix plus deterministic case mutations."""
    rng = random.Random(seed)
    literals = _sanitizer_literals()
    rng.shuffle(literals)
    cases: list[dict[str, object]] = []
    for mode in SANITIZATION_MODES:
        for ordinal, literal in enumerate(literals):
            by_mode = literal.get("expectation_by_mode")
            if isinstance(by_mode, Mapping):
                expectation = str(by_mode[mode])
            else:
                expectation = str(literal["default_expectation"])
            cases.append(
                {
                    "case_id": _case_id(
                        "sanitize",
                        mode,
                        literal["category"],
                        literal["input"],
                    ),
                    "seed": seed,
                    "ordinal": ordinal,
                    "mode": mode,
                    "private_roots": [PRIVATE_ROOT],
                    "category": literal["category"],
                    "input": literal["input"],
                    "expectation": expectation,
                    "idempotence_required": True,
                    "counter_rule": "changed spans and values exactly",
                }
            )
    return cases


def consumer_mode_cases() -> list[dict[str, object]]:
    """Return the normative canonical/plugin consumer-mode handoff table."""
    rows = (
        (
            "rewrite",
            "context-guard-kit/rewrite_bash_for_token_budget.py",
            "plugins/context-guard/bin/context-guard-rewrite-bash",
            "command_search_diff",
            "flat",
        ),
        (
            "direct_sanitizer",
            "context-guard-kit/sanitize_output.py",
            "plugins/context-guard/bin/context-guard-sanitize-output",
            "unknown_text",
            "flat",
        ),
        (
            "trim",
            "context-guard-kit/trim_command_output.py",
            "plugins/context-guard/bin/context-guard-trim-output",
            "unknown_text",
            "flat",
        ),
        (
            "symbol",
            "context-guard-kit/read_symbol.py",
            "plugins/context-guard/bin/context-guard-read-symbol",
            "source_code",
            "flat",
        ),
        (
            "compress",
            "context-guard-kit/context_compress.py",
            "plugins/context-guard/bin/context-guard-compress",
            "source_code_or_declared",
            "flat",
        ),
        (
            "pack",
            "context-guard-kit/context_pack.py",
            "plugins/context-guard/bin/context-guard-pack",
            "per_entry_or_unknown_text",
            "flat",
        ),
        (
            "escrow",
            "context-guard-kit/context_escrow.py",
            "plugins/context-guard/bin/context-guard-artifact",
            "persisted_or_unknown_text",
            "flat",
        ),
        (
            "schema_pruner",
            "context-guard-kit/tool_schema_pruner.py",
            "plugins/context-guard/bin/context-guard-tool-prune",
            "structural_only",
            "structural",
        ),
    )
    return [
        {
            "case_id": f"consumer-{_slug(feature)}",
            "feature": feature,
            "canonical": canonical,
            "packaged": packaged,
            "required_mode": mode,
            "sanitizer_kind": kind,
            "pair_parity_required": True,
        }
        for feature, canonical, packaged, mode, kind in rows
    ]


def format_minimized_failure(
    case: Mapping[str, object],
    actual: object,
    *,
    expected_field: str,
) -> str:
    """Format a stable, compact replay record for the first failing case."""
    keep = (
        "case_id",
        "seed",
        "policy_version",
        "entrypoint",
        "position",
        "mode",
        "family",
        "role",
        "command",
        "raw_word",
        "input",
        expected_field,
    )
    payload = {key: case[key] for key in keep if key in case}
    payload["expected_field"] = expected_field
    payload["actual"] = actual
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def assert_oracle_cases(
    cases: Iterable[Mapping[str, object]],
    evaluator: Callable[[Mapping[str, object]], object],
    *,
    expected_field: str,
) -> None:
    """Evaluate in order and raise one minimized deterministic replay record."""
    for case in cases:
        actual = evaluator(case)
        expected = case[expected_field]
        if actual != expected:
            raise AssertionError(
                format_minimized_failure(
                    case,
                    actual,
                    expected_field=expected_field,
                )
            )


def oracle_document() -> dict[str, object]:
    route = route_cases()
    assignment = assignment_provenance_cases()
    sanitizer = sanitizer_mode_cases()
    consumers = consumer_mode_cases()
    return {
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "route_policy_version": ROUTE_POLICY_VERSION,
        "seeds": {
            "route": ROUTE_SEED,
            "assignment": ASSIGNMENT_SEED,
            "sanitizer": SANITIZER_SEED,
        },
        "counts": {
            "route": len(route),
            "assignment": len(assignment),
            "sanitizer": len(sanitizer),
            "consumers": len(consumers),
        },
        "route_cases": route,
        "assignment_provenance_cases": assignment,
        "path_lookup_canary": path_lookup_canary(),
        "sanitizer_mode_cases": sanitizer,
        "consumer_mode_cases": consumers,
    }


def render_fixture() -> str:
    return json.dumps(
        oracle_document(),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def write_fixture(path: Path = FIXTURE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_fixture(), encoding="utf-8")


def check_fixture(path: Path = FIXTURE_PATH) -> bool:
    return path.is_file() and path.read_text(encoding="utf-8") == render_fixture()


def _validate_document(document: Mapping[str, object]) -> None:
    for collection_name in (
        "route_cases",
        "assignment_provenance_cases",
        "sanitizer_mode_cases",
        "consumer_mode_cases",
    ):
        collection = document[collection_name]
        if not isinstance(collection, list) or not collection:
            raise AssertionError(f"{collection_name} must be a non-empty list")
        ids = [case["case_id"] for case in collection]
        if len(ids) != len(set(ids)):
            raise AssertionError(f"{collection_name} contains duplicate case IDs")

    route_rows = {
        (case["family"], case["role"], case["entrypoint"])
        for case in document["route_cases"]
    }
    for entrypoint in ENTRYPOINTS:
        for required in (
            ("printf", "standalone", entrypoint),
            ("git-diff", "first", entrypoint),
            ("grep-filter", "filter", entrypoint),
            ("unknown-pipeline", "first", entrypoint),
            ("forbidden", "filter", entrypoint),
        ):
            if required not in route_rows:
                raise AssertionError(f"missing route cross-product row: {required}")

    assignment_rows = {
        (case["position"], case["entrypoint"])
        for case in document["assignment_provenance_cases"]
    }
    expected_assignment_rows = {
        (position, entrypoint)
        for position in ASSIGNMENT_POSITIONS
        for entrypoint in ENTRYPOINTS
    }
    if assignment_rows != expected_assignment_rows:
        raise AssertionError("assignment position/entrypoint cross-product is incomplete")

    sanitizer_rows = {
        (case["mode"], case["category"])
        for case in document["sanitizer_mode_cases"]
    }
    for mode in SANITIZATION_MODES:
        for category in (
            "route",
            "private_path_plain",
            "grep_location",
            "authorization_header",
            "benign_usage",
        ):
            if (mode, category) not in sanitizer_rows:
                raise AssertionError(f"missing sanitizer mode/category row: {(mode, category)}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-fixture", action="store_true")
    parser.add_argument("--check-fixture", action="store_true")
    args = parser.parse_args(argv)

    _validate_document(oracle_document())
    if args.write_fixture:
        write_fixture()
    if args.check_fixture and not check_fixture():
        print(f"stale or missing A1 oracle fixture: {FIXTURE_PATH}")
        return 1
    if not args.write_fixture and not args.check_fixture:
        print(render_fixture(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
