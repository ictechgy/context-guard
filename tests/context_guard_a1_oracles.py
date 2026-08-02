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
    # -------------------------------------------------------------------
    # ls producer route (design doc route-readmission-design-20260729.md §4.1).
    # `ls`는 명령 자체로는 거부되지 않는다 — standalone `ls -la docs`는 이미
    # 오늘도 `noop`이다. 13건의 실측 거부는 전부 파이프라인 역할(role=="first")
    # 거부였다: `role == "first"`가 `{trim, sanitize}` 밖의 라우트를 전부
    # deny하는데, `ls`는 어떤 라우트도 갖지 않아 항상 걸렸다. 그래서 이
    # 변경은 "ls를 허용"하는 게 아니라 "ls에 producer 라우트를 부여"하는
    # 것이다. standalone은 의도적으로 그대로 둔다(noop 유지) — 이미
    # 동작하는 것을 건드리지 않는다는 설계 원칙(§4.1 "Deliberately not
    # proposed").
    #   1. before/after: role=="first"만 route_policy_denied -> rewrite_trim.
    #      standalone은 허용목록 안팎을 가리지 않고 noop -> noop, 변화 없음
    #      (`ls-standalone-invariant` family 가 이를 고정한다).
    #   2. output boundedness: trim_command_output.py의 220줄 캡이 그대로
    #      적용된다.
    #   3. axis-b non-impact: `_ls_is_safe`는 순수 허용목록이며 값(value)을
    #      소비하지 않는다. 파서/게이트에는 손대지 않는다.
    #   4. reverse case: `ls`를 파이프라인 filter로 쓰는 경우(`ls`는 stdin을
    #      무시하므로 항상 실수) 및 표 밖의 롱 플래그는 여전히 deny.
    #   5. reads outside the repo: 오늘도 `ls`가 이미 저장소 밖 경로를 열람할
    #      수 있으므로(standalone noop) 이 변경으로 새로 생기는 표면이 아니다.
    # -------------------------------------------------------------------
    add(
        "ls-producer",
        ("first",),
        ("ls -la docs", "ls -R src"),
        "rewrite_trim",
        ("ls --sort=size docs", "ls -Z docs"),
        note="AC ls producer: role==first newly admitted "
        "(route_policy_denied -> rewrite_trim). Negatives: long flags "
        "outside the table and unknown short flags stay denied.",
    )
    # standalone 불변식 — `_ls_is_safe` 는 producer 재승인 게이트일 뿐이고
    # standalone 판정에 개입하지 않는다. 허용목록 밖 플래그(`--sort=`, `-Z`,
    # `-G`, `--color=always`)를 쓴 standalone `ls` 도 변경 전과 동일하게 `noop`
    # 이어야 한다. 이 family 가 없으면 게이트가 standalone 까지 좁혀
    # 지금 통과하는 형태를 새로 거부해도 아무 테스트도 깨지지 않는다.
    add(
        "ls-standalone-invariant",
        ("standalone",),
        (
            "ls -la docs",
            "ls -R src",
            "ls --sort=size docs",
            "ls -Z docs",
            "ls -G",
            "ls --color=always",
        ),
        "noop",
        (),
        note="standalone ls is untouched by this change — every form, "
        "allowlisted or not, keeps today's noop decision.",
    )
    add(
        "ls-filter",
        ("filter",),
        (),
        "deny",
        ("ls -la",),
        note="ls as a pipeline filter always stays denied — ls ignores "
        "stdin, so `... | ls` is always a mistake.",
    )
    # -------------------------------------------------------------------
    # FIX-2 — `cat <bigfile>` read guard bypass (plan §6.2, AC-2.1/AC-2.4).
    # standalone cat이 `noop`(무변형 통과)이었던 것이 Read 가드
    # (`guard_large_read.py`, `tool_name == "Read"` 전용)와 Bash 훅 사이의
    # 정확한 틈이었다 — 48KB 초과 파일을 `cat <bigfile>`로 읽으면 두 가드
    # 어느 쪽도 발동하지 않고 파일 전체가 통과했다(161,544바이트 ≈ 40,000토큰
    # 실측). first/filter 역할은 이미 `trim`이었으므로 standalone만 맞춘다.
    # `cat-filter`(바로 아래)는 이 변경과 무관 — 필터 역할은 이미 `trim`이었고
    # 그대로 유지된다(AC-2.2).
    #
    # §5.5 5열 표:
    #   1. 변경 전/후 기대값: standalone cat 양성 케이스 `noop -> rewrite_trim`.
    #   2. 출력 유계성 근거: `trim_command_output.py`가 `--max-lines 220`으로
    #      래핑하므로 파일 크기와 무관하게 출력이 유계화된다(이전에는 무제한).
    #   3. 축 b 무영향 근거: `_cat_is_safe`(허용 플래그, `allow_files`)는 전혀
    #      바뀌지 않았다 — 라우트 코드만 바뀐다. 이 변경은 deny -> allow
    #      전환이 아니므로(둘 다 accept) INV-A/INV-B 대상이 아니다 — 대신
    #      새로 진입하는 `bash -c` 재래핑 경로는 INV-C(AC-2.3)로 검증한다.
    #   4. 역방향 케이스: `cat --number README.md`(아래 negatives)는
    #      `--number`가 허용 플래그 집합(`bnsETAvet`) 밖이라 여전히 deny —
    #      완화가 플래그 검증을 재승인하지 않음을 보인다.
    #   5. 저장소 밖 읽기 / 자격증명 저장소 접근 여부: 아니오 — `cat`은 Bash가
    #      전달한 경로 인자를 그대로 여는 표준 파일 읽기이고, 이 표의 대상은
    #      저장소 내부 파일(README.md 등)이다. 환경변수나 credential helper를
    #      암묵적으로 읽지 않는다. `cat ~/.netrc`처럼 저장소 밖 경로를 명시하는
    #      경우는 개조 전에도 `_cat_is_safe`가 파일 인자를 허용하면 이미
    #      `noop`으로 통과했다 — 라우트 코드 변경(`noop -> trim`)은 이
    #      표면(무엇을 읽을 수 있는가)에 전혀 영향을 주지 않는다.
    # -------------------------------------------------------------------
    add(
        "cat-producer",
        ("standalone", "first"),
        ("cat -n -- README.md", "cat -b README.md"),
        "rewrite_trim",
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
    # -------------------------------------------------------------------
    # FIX-1b — git (subcommand, argument-shape) pair allowlist (plan §6.1b).
    # git-diff was the only pre-existing git family (AC-1b.3 defect: a
    # pair-allowlist prototype measured 0 oracle impact because nothing else
    # watched git route decisions — absence of surveillance, not safety).
    # One family per *subcommand* (not per table row) so `diff`/`show`/`grep`
    # — which share one table row — still get independent surveillance.
    # `test_ac_1b_3_git_oracle_family_set_matches_table_subcommands` asserts
    # this family set equals `GIT_TABLE_SUBCOMMANDS`; a row added without a
    # family fails that test (R-11).
    #
    # §5.5 5-column check (applies to every family below, per plan's own
    # "나머지 11행 판정" conclusion, reproduced here per-subcommand):
    #   1. before/after: route_policy_denied -> rewrite_sanitize (all new
    #      subcommands) or unchanged (diff/show/grep, extraction only).
    #   2. output boundedness: sanitize_output.py's 240-line cap already
    #      bounds every git subcommand's output regardless of flags/args.
    #   3. axis-b non-impact: none of these predicates touch parsing,
    #      `_routing_start`, or gates 1-10 — only the route gate.
    #   4. reverse case: every family below carries >=1 negative (positional
    #      overflow, a write flag absent from the table, an unlisted
    #      adjacent subcommand, or an R-5 global-option bypass).
    #   5. reads outside the repo / credential store: no — `status`, `log`,
    #      `branch`, `tag`, `rev-parse`, `describe`, `ls-files`, `shortlog`,
    #      `blame`, `stash list|show`, `diff`, `show`, `grep` all print
    #      refs/commits/file content from the working repository, never a
    #      bare value with no key context (unlike `git config --get`, R-13)
    #      and never a URL with embedded credentials (unlike `git remote -v`,
    #      R-13) — both of those rows were deleted from the table for
    #      exactly this reason and are not reintroduced here.
    # -------------------------------------------------------------------
    add(
        "git-status",
        ("standalone", "first"),
        ("git status -s", "git status --porcelain --branch"),
        "rewrite_sanitize",
        ("git status README.md", "git --no-pager status"),
        note="positional overflow negative + R-5 global-option-bypass negative",
    )
    add(
        "git-log",
        ("standalone", "first"),
        (
            "git log --oneline -20",
            "git log -5",
            "git log --graph --decorate --pretty=oneline",
        ),
        "rewrite_sanitize",
        ("git log -p --output=/tmp/x", "git -c core.pager=cat log -p"),
        note="AC-1.9 bundled/attached-value positives; AC-1b.2 write-flag + "
        "R-5 global-option-bypass negatives",
    )
    add(
        "git-branch",
        ("standalone", "first"),
        ("git branch -a", "git branch -r --no-color"),
        "rewrite_sanitize",
        ("git branch newfeature", "git branch -ad"),
        note="AC-1.4 zero-arity-write negative; AC-1.9 bundled-write-flag negative",
    )
    add(
        "git-tag",
        ("standalone", "first"),
        ("git tag -l", "git tag -l -n3"),
        "rewrite_sanitize",
        ("git tag v1.0.0", "git tag -l -- v1.0.0"),
        note="AC-1.4 zero-arity-write negative; AC-1.10 -- counting negative "
        "(positional after -- still counts)",
    )
    # -------------------------------------------------------------------
    # FIX-6 — `git remote`/`git remote -v` re-admitted to the pair allowlist
    # (plan §6.1b row 12) after credential_policy.py's URL-userinfo redaction
    # was hardened to also cover password-less (token-only) URLs. FIX-1b's
    # 5-column note above (5th column) explicitly named `git remote -v` as a
    # row deleted for R-13 (structurally unredactable). That premise no
    # longer holds — the redaction gap was in the *regex*, not the row: the
    # old pattern required both `user:pass@` parts and let vendor-unrecognized
    # token-only URLs (e.g. `https://TOKEN@host/...`, the most common PAT
    # form) through unredacted. FIX-6 widened the pattern (password part now
    # optional); this family is the surveillance for that re-admission.
    #
    # §5.5 5-column check:
    #   1. before/after: route_policy_denied -> rewrite_sanitize (new row).
    #   2. output boundedness: unchanged — sanitize_output.py's 240-line cap.
    #   3. axis-b non-impact: unchanged — only the route gate is touched.
    #   4. reverse case: `remote add/remove/rename/set-url` (positional
    #      overflow — 0-arity strict, same rule as branch/tag) and an R-5
    #      global-option-bypass negative.
    #   5. reads outside the repo / credential store: yes — `.git/config`
    #      remote URLs can carry embedded credentials. What makes this row
    #      safe *now* (and not before) is the hardened redaction from FIX-6's
    #      first commit: credential_policy.py's INLINE_PATTERNS now redacts
    #      both `user:pass@` and bare `TOKEN@` userinfo before the URL ever
    #      reaches Claude's context.
    # -------------------------------------------------------------------
    add(
        "git-remote",
        ("standalone", "first"),
        ("git remote", "git remote -v"),
        "rewrite_sanitize",
        (
            "git remote add origin https://example.invalid/repo.git",
            "git --no-pager remote -v",
        ),
        note="AC-1.4 zero-arity-write negative (remote add, positional overflow, "
        "same rule as branch/tag); R-5 global-option-bypass negative",
    )
    add(
        "git-rev-parse",
        ("standalone", "first"),
        ("git rev-parse --show-toplevel", "git rev-parse --abbrev-ref HEAD"),
        "rewrite_sanitize",
        ("git rev-parse --resolve-git-dir=/tmp", "git -C /tmp rev-parse HEAD"),
        note="unknown-flag negative + R-5 global-option-bypass negative",
    )
    add(
        "git-describe",
        ("standalone", "first"),
        ("git describe --tags --always", "git describe --dirty --long"),
        "rewrite_sanitize",
        ("git describe --match=foo", "git --exec-path=/evil describe"),
        note="unknown-flag negative + R-5 global-option-bypass negative",
    )
    add(
        "git-ls-files",
        ("standalone", "first"),
        ("git ls-files --cached --modified", "git ls-files -o --exclude-standard"),
        "rewrite_sanitize",
        ("git ls-files --recurse-submodules", "git ls-files -z"),
        note="unknown long-flag negative + unknown bundled-short-flag negative",
    )
    add(
        "git-shortlog",
        ("standalone", "first"),
        ("git shortlog -sn HEAD", "git shortlog --summary --email HEAD"),
        "rewrite_sanitize",
        ("git shortlog -sn", "git --paginate shortlog -sn"),
        note="AC-1.9 bundled-flag positive (subcommand-local -n=--numbered); "
        "missing-required-revision negative (>=1 revision rule — bare shortlog "
        "reads commits from stdin and blocks until the 600s wrapper watchdog) "
        "+ R-5 global-option-bypass negative",
    )
    add(
        "git-blame",
        ("standalone", "first"),
        ("git blame -w README.md", "git blame -- README.md"),
        "rewrite_sanitize",
        ("git blame -w", "git --no-pager blame README.md"),
        note="missing-required-path negative (>=1 path rule) + R-5 "
        "global-option-bypass negative",
    )
    add(
        "git-stash",
        ("standalone", "first"),
        ("git stash list", "git stash show"),
        "rewrite_sanitize",
        ("git stash", "git stash pop"),
        note="AC-1.4 zero-arity-write negative (bare `git stash`) + "
        "unlisted-adjacent-subcommand negative (`pop`)",
    )
    add(
        "git-show",
        ("standalone", "first"),
        ("git show --stat HEAD", "git show HEAD~1 -- README.md"),
        "rewrite_sanitize",
        ("git --no-pager show", "git show --output=/tmp/x"),
        note="R-5 global-option-bypass negative + write-flag negative "
        "(arbitrary-file-write --output=, same class as AC-1b.2 case 9)",
    )
    add(
        "git-grep",
        ("standalone", "first"),
        ("git grep -n token -- README.md", "git grep -e token README.md"),
        "rewrite_sanitize",
        ("git grep -f patterns.txt", "git --no-pager grep token"),
        note="pre-existing _grep_is_safe negative (-f/--file) + R-5 "
        "global-option-bypass negative — delegation unchanged by FIX-1b, "
        "family added purely for surveillance (AC-1b.3)",
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
        (
            "grep -n -e token -- README.md",
            "egrep -m2 token README.md",
            "grep -o token README.md",
            "grep -q token README.md",
            "grep --only-matching token README.md",
            "grep --color=auto token README.md",
        ),
        "rewrite_sanitize",
        (
            "grep -f patterns README.md",
            "grep --binary-files=text token README.md",
            "grep --color=always token README.md",
            "grep --only-matchingx token README.md",
        ),
        note="AC grep flag surface (design route-readmission-design-20260729.md "
        "§4.2): -o/-q short flags plus exact-match long-flag alias table. "
        "Negatives: value-taking long flags, --color=always (only never/auto "
        "are in the table), and a near-miss long flag proving no startswith "
        "matching.",
    )
    add(
        "grep-filter",
        ("filter",),
        (
            "grep -n token",
            "fgrep -m2 token",
            "grep -o token",
            "grep --quiet token",
        ),
        "rewrite_sanitize",
        (
            "grep token README.md",
            "grep -f patterns",
            "grep -o token README.md",
        ),
        note="grep -o token README.md is rejected in filter role because "
        "allow_files=False still applies to file operands — the newly "
        "admitted flag does not relax that unrelated gate.",
    )
    add(
        "head-tail-producer",
        ("standalone", "first"),
        (
            "head -20 README.md",
            "head -n20 README.md",
            "tail -50 README.md",
            "head README.md",
            "tail README.md",
            "head",
            "tail",
        ),
        {"standalone": "rewrite_trim", "first": "rewrite_trim"},
        ("head -c 20 README.md", "tail -f README.md"),
    )
    add(
        "head-tail-filter",
        ("filter",),
        ("head -n 20", "tail --lines=50", "head", "tail"),
        "rewrite_trim",
        ("head -n 20 README.md", "tail -F", "head README.md"),
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
        "sed-producer",
        ("standalone", "first"),
        (
            "sed -n '1,80p' README.md",
            "sed -n -e '1,80p' README.md",
            "sed -n --expression='1,80p' README.md",
        ),
        "rewrite_trim",
        (
            "sed -i '1,80p' README.md",
            "sed -n '1,5p' -i README.md",
            "sed -ni '1,5p' README.md",
            "sed --i -n '1,5p' README.md",
            "sed -I .bak -n '1,5p' README.md",
            "sed -s -n '1,5p' README.md",
            "sed -n '1,1000001p' README.md",
            "sed -n '/re/,/re/p' README.md",
        ),
        note="AC sed range-read flag surface (design "
        "route-readmission-design-20260729.md §2.3): whole-argv scan admits "
        "file operands for producer roles. Negatives: in-place edit (plain "
        "and permuted-position), a short-cluster smuggling -i, the GNU "
        "unambiguous-prefix abbreviation --i (which GNU getopt_long resolves "
        "to --in-place, i.e. the same file-mutating capability as the spelled-"
        "out form), a non-writing but out-of-allowlist flag (-s), a line "
        "number past the _valid_n upper bound, and a regex address that fails "
        "the numeric-range script regex.",
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
        "wc-producer",
        ("standalone",),
        ("wc -cl", "wc --", "wc README.md", "wc -- README.md"),
        "noop",
        ("wc -L",),
    )
    add(
        "wc-filter",
        ("filter",),
        ("wc -cl", "wc --"),
        "rewrite_trim",
        ("wc README.md", "wc -L", "wc -- README.md"),
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
        ("mvn -q test", "mvnw test", "gradle --quiet test", "gradlew test"),
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
            # 원인까지 고정한다 — `deny` 만 단언하면 restricted_env_denied 같은 다른
            # 원인으로 거부돼도 통과해, FOO/EMPTY 가 "이름 때문에" 막힌다는 성질이
            # 검증되지 않는다. 파싱 자체는 성공하므로 parsed.denial_reason 이 아니라
            # 분류 단계의 reason_code 로 단언해야 한다.
            "expected_reason_code": "unsafe_env_name_denied",
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
            "context-guard-trim-output --max-lines 220 -- bash -c 'pytest -q'",
            "incoming_wrapper_denied",
        ),
        (
            "context-guard-sanitize-output --context-guard-wrapper-v1 command_search_diff -- bash -c 'rg x .'",
            "incoming_wrapper_denied",
        ),
        (
            "claude-trim-output --max-lines 220 -- bash -c 'pytest -q'",
            "incoming_wrapper_denied",
        ),
        (
            "python3 /tmp/trim_command_output.py --max-lines 220 -- bash -c 'pytest -q'",
            "incoming_wrapper_denied",
        ),
        (
            "context-guard-sanitize-output x--context-guard-wrapper-v1 -- bash -c 'rg x .'",
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
    if position == "restricted_env" and "=" in str(template["raw_word"]):
        # `env` 피연산자 자리는 셸 할당 문법을 따르지 않는다. coreutils `env` 는
        # 인용 제거가 끝난 argv 원소가 `=` 를 포함하기만 하면 그대로 putenv() 하므로
        # (`env F'O'O=v printenv FOO` 가 실제로 v 를 출력한다) 셸이 할당으로 보지 않는
        # 인용 형태도 환경에 적용된다. B1 템플릿의 이름은 전부 화이트리스트 밖이므로
        # 이 위치에서는 인식 여부와 무관하게 이름 게이트에 걸린다.
        return "deny", "unsafe_env_name_denied"
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
        # ---------------------------------------------------------------
        # FIX-6 — credential_policy.py:108 URL userinfo 리댁션 정규식이
        # `user:pass@` 두 파트를 모두 요구해 콜론 없는 토큰 전용 URL(가장 흔한
        # PAT 임베딩 형태, 예: `git remote -v`가 출력하는
        # `https://TOKEN@host/repo.git`)을 통과시켰다(실측: Azure DevOps PAT,
        # 사내 PAT, 범용 토큰 3/3 누수). 기존 4개 userinfo 오라클 케이스(위
        # `credential_url`)는 전부 `fixture-user:fixture-password` 형태만
        # 다뤄 이 구멍이 감시되지 않았다 — 이 완화가 AC-1.3(섹션 불변) 범위를
        # 명시적으로 벗어나는 이유: `sanitizer_mode_cases`의 카운트/내용이
        # 바뀐다(60 -> 68). `assignment_provenance_cases`/`consumer_mode_cases`/
        # `path_lookup_canary`는 이 함수의 생성 로직과 무관하므로 계속 불변이다.
        {
            "category": "credential_url_token_only",
            "input": "https://fixture-token@example.invalid/private",
            "default_expectation": "redact_secret",
        },
        # 음성 케이스 — 과잉 리댁션 경계 고정. `scheme://` 접두사가 없는 평범한
        # 이메일 언급(예: `git log`/`git show` 저자 줄의 `<user@host>`)은 넓힌
        # 정규식으로도 건드리지 않아야 한다 — credential_policy.py는 git 전용이
        # 아니라 grep/rg/kubectl logs 등 모든 sanitize 루트가 공유하므로, 스킴
        # 없는 `word@word` 형태까지 잡으면 사람 이름이 포함된 정상 출력을
        # 과잉 리댁션한다.
        {
            "category": "bare_userinfo_without_scheme",
            "input": "Author: Fixture User <fixture-user@example.invalid>",
            "default_expectation": "preserve",
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
