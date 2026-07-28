#!/usr/bin/env python3
"""안전 회귀 고정용 적대적 코퍼스(hand-authored) — 샘플링/재생성 대상이 아니다.

`corpus_measured_n82.json`(트랜스크립트에서 재생성되는 이득 측정용 코퍼스)과 이름을
분리한다 — 이 파일의 케이스는 실제 에이전트 트랜스크립트에 나타나지 않는다. 에이전트는
`git -c alias.x='!id' x` 나 `GIT_EXTERNAL_DIFF=/tmp/evil.sh git diff` 같은 명령을
스스로 타이핑하지 않기 때문이다(§0.5, R-10). 이 파일은 각 FIX 레인이 자신의 적대적
케이스 섹션을 추가하는 공유 저장소이며, 레인별로 구획을 분리해 병합 충돌을 줄인다.

`tests/context_guard_a1_oracles.py` 와 마찬가지로 이 모듈도 production import 가
없다 — 기대값은 구현을 호출해 계산되는 것이 아니라 사람이 직접 판정해 고정한다.
"""
from __future__ import annotations

from typing import TypedDict


class _AdversarialPinRequired(TypedDict):
    """모든 핀이 반드시 채워야 하는 필드.

    `expected_reason_code` 를 필수로 둔다 — 선택 필드였을 때 핀이 이 값을 생략하면
    계약 테스트가 `deny` 여부만 보고 통과해, 원인 코드가 오염돼도(예: 파서 우연이나
    assignment_only 로의 대체) 아무도 눈치채지 못하는 공허한 단언이 된다. 허용 핀은
    명시적으로 `None` 을 적어 "원인 코드가 없어야 함"을 단언하게 한다.
    """

    case_id: str
    fix: str
    command: str
    expected_decision: str
    expected_reason_code: str | None


class AdversarialPin(_AdversarialPinRequired, total=False):
    note: str


# ---------------------------------------------------------------------------
# FIX-5 — 환경변수 접두사 이름 화이트리스트 (AC-5.1, 19개 벡터)
#
# 근본 원인 실측(§6.5): `_routing_start` 가 할당 접두사의 "이름"을 전혀 보지 않고
# 스킵했다. 19개 벡터 중 17개가 기존 코드에서 통과(sanitize/trim)했고, 나머지 2개
# (GIT_PAGER, LESSOPEN)는 화이트리스트와 무관한 우연(각각 `git log`의 patch_output
# 요구 실패, 값에 포함된 `|`가 활성 파이프로 파싱됨)으로 이미 deny 였다. FIX-5 이후
# 19개 전부 deny 이어야 한다(AC-5.1). 이름 검사가 라우팅과 할당 전용 조기 반환보다
# 먼저 실행되므로, 우연히 deny 였던 2개를 포함해 19개 모두 신규
# `unsafe_env_name_denied`(AC-5.2)를 원인으로 갖는다 — 검사 순서가
# "세그먼트 분해 -> 이름 화이트리스트 -> 라우팅" 임을 이 핀들이 고정한다.
# ---------------------------------------------------------------------------
FIX5_ADVERSARIAL_PINS: list[AdversarialPin] = [
    {
        "case_id": "fix5-adv-git-external-diff",
        "fix": "FIX-5",
        "command": "GIT_EXTERNAL_DIFF=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "git diff --ext-diff 플래그 형태는 이미 negative 로 고정됨"
        "(context_guard_a1_oracles.py:163) — 접두사 형태가 누락돼 있었다.",
    },
    {
        "case_id": "fix5-adv-git-ssh-command",
        "fix": "FIX-5",
        "command": "GIT_SSH_COMMAND=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "SSH 전송 프로그램 치환 — 원격 조작 시 임의 명령 실행.",
    },
    {
        "case_id": "fix5-adv-git-config-global",
        "fix": "FIX-5",
        "command": "GIT_CONFIG_GLOBAL=/tmp/evil git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "전역 git config 파일 치환 — hook/alias 경로로 확장 가능.",
    },
    {
        "case_id": "fix5-adv-bash-env",
        "fix": "FIX-5",
        "command": "BASH_ENV=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "비대화형 bash 시작 스크립트 강제 로드.",
    },
    {
        "case_id": "fix5-adv-dyld-insert-libraries",
        "fix": "FIX-5",
        "command": "DYLD_INSERT_LIBRARIES=/tmp/evil.dylib git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "macOS 동적 라이브러리 주입.",
    },
    {
        "case_id": "fix5-adv-ld-preload",
        "fix": "FIX-5",
        "command": "LD_PRELOAD=/tmp/evil.so cat README.md",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "실측: 개조 전 noop 으로 무변형 통과(§0 defect report). "
        "키 기반 새니타이저조차 거치지 않는 최악의 사례.",
    },
    {
        "case_id": "fix5-adv-path",
        "fix": "FIX-5",
        "command": "PATH=/tmp git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "`_prefix_overrides_path` 는 pipeline(segments>1)에서만 검사되어 "
        "단일 세그먼트는 통과했다 — 이름 화이트리스트가 구조적으로 이 구멍을 막는다.",
    },
    {
        "case_id": "fix5-adv-ifs",
        "fix": "FIX-5",
        "command": "IFS=: git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "필드 분리자 조작 — 후속 파싱 신뢰 불가.",
    },
    {
        "case_id": "fix5-adv-pager",
        "fix": "FIX-5",
        "command": "PAGER=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "최소 denylist(G2)가 놓친 8종 중 하나 — git/less 가 페이저를 임의 실행.",
    },
    {
        "case_id": "fix5-adv-editor",
        "fix": "FIX-5",
        "command": "EDITOR=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "최소 denylist(G2)가 놓친 8종 중 하나.",
    },
    {
        "case_id": "fix5-adv-visual",
        "fix": "FIX-5",
        "command": "VISUAL=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "최소 denylist(G2)가 놓친 8종 중 하나.",
    },
    {
        "case_id": "fix5-adv-perl5lib",
        "fix": "FIX-5",
        "command": "PERL5LIB=/tmp/evil git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "perl 모듈 검색 경로 주입 — 최소 denylist(G2)가 놓친 8종 중 하나.",
    },
    {
        "case_id": "fix5-adv-rubyopt",
        "fix": "FIX-5",
        "command": "RUBYOPT=-r/tmp/evil git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "`-r` 강제 require — 최소 denylist(G2)가 놓친 8종 중 하나.",
    },
    {
        "case_id": "fix5-adv-git-alternate-object-directories",
        "fix": "FIX-5",
        "command": "GIT_ALTERNATE_OBJECT_DIRECTORIES=/tmp/evil git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "대체 오브젝트 저장소 경로 주입.",
    },
    {
        "case_id": "fix5-adv-pythonpath",
        "fix": "FIX-5",
        "command": "PYTHONPATH=/tmp/evil python3 -m pytest",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "sitecustomize/모듈 섀도잉으로 인터프리터 기동 시 임의 코드 실행 — "
        "trim 라우트 전반에 걸친 취약점의 대표 예시(§6.5).",
    },
    {
        "case_id": "fix5-adv-node-options",
        "fix": "FIX-5",
        "command": "NODE_OPTIONS=--require=/tmp/evil.js npm test",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "`--require` 강제 로드 — trim 라우트 전반에 걸친 취약점의 대표 예시.",
    },
    {
        "case_id": "fix5-adv-pythonstartup",
        "fix": "FIX-5",
        "command": "PYTHONSTARTUP=/tmp/evil.py python3 -m pytest",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "대화형 세션에서만 발화(비대화형 sentinel=False, 대화형=True 검증됨) — "
        "헤드라인 예시로는 부적합하지만 라우팅 결론(trim→통과)은 불변이므로 벡터로 유지.",
    },
    {
        "case_id": "fix5-adv-git-pager-accidental-deny",
        "fix": "FIX-5",
        "command": "GIT_PAGER=/tmp/evil.sh git log --oneline",
        "expected_decision": "deny",
        # 개조 전에도 deny 였지만 `git log`의 patch_output 요구 실패라는 우연에 불과했다
        # (FIX-1b가 log/status 행을 allow 로 바꾸면 이 우연한 방어가 사라진다 — N-1).
        # 이제는 라우팅 이전 단계에서 이름 자체로 확정적으로 deny 된다.
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "N-1: 이 우연한 방어가 FIX-1b 머지 게이트의 근거다. 화이트리스트가 "
        "라우팅보다 먼저 실행되므로 이제는 구조적으로 deny 된다.",
    },
    {
        "case_id": "fix5-adv-lessopen-accidental-deny",
        "fix": "FIX-5",
        "command": "LESSOPEN=|/tmp/evil.sh %s git diff",
        "expected_decision": "deny",
        # 값에 포함된 인용되지 않은 `|` 가 활성 파이프 구분자로 파싱되어 첫 세그먼트가
        # "LESSOPEN=" 단독(명령 없음)이 된다. 예전에는 이 우연한 파싱 덕분에
        # assignment_only_denied 로만 거부됐지만, 이제 이름 검사가 할당 전용 조기
        # 반환보다 먼저 실행되므로 LESSOPEN 이라는 이름 자체로 확정 deny 된다.
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "예전의 우연한 파이프 방어가 아니라 이름 화이트리스트가 원인이 된다 — "
        "파이프를 제거한 형태(fix5-adv-lessopen-no-pipe)도 같은 코드로 거부된다.",
    },
]


# ---------------------------------------------------------------------------
# FIX-5 — `env` 래퍼 우회 회귀 (리뷰 루프에서 발견된 실증 우회)
#
# 아래 두 형태는 최초 FIX-5 구현에서 noop(허용)으로 통과했다. coreutils `env` 는
# `--` 뒤에서도 선행 NAME=VALUE 를 환경 할당으로 처리하고 중첩 호출도 허용하므로,
# 두 경우 모두 FIX-5 가 막으려던 ride-along RCE 가 그대로 재현됐다.
# AC-5.1 의 19개 카운트를 보존하기 위해 별도 리스트로 분리한다.
# ---------------------------------------------------------------------------
FIX5_ENV_WRAPPER_BYPASS_PINS: list[AdversarialPin] = [
    {
        "case_id": "fix5-bypass-env-double-dash",
        "fix": "FIX-5",
        "command": "env -- GIT_EXTERNAL_DIFF=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "`--` 이후 할당 구간이 재검사되지 않아 라우팅이 할당 word 에서 시작하고 "
        "noop 으로 통과했다(실증). `env -- NAME=VALUE cmd` 는 실제로 변수를 설정한다.",
    },
    {
        "case_id": "fix5-bypass-env-nested",
        "fix": "FIX-5",
        "command": "env env GIT_EXTERNAL_DIFF=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "`env` 를 한 번만 소비해 중첩 호출의 할당 구간이 검사되지 않고 noop "
        "으로 통과했다(실증). `env env NAME=VALUE cmd` 도 실제로 변수를 설정한다.",
    },
    {
        "case_id": "fix5-bypass-env-double-dash-ld-preload",
        "fix": "FIX-5",
        "command": "env -- LD_PRELOAD=/tmp/evil.so cat README.md",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "동적 링커 계열도 같은 `--` 우회로 통과했음을 고정한다.",
    },
    {
        "case_id": "fix5-adv-lessopen-no-pipe",
        "fix": "FIX-5",
        "command": "LESSOPEN=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        # 우연한 `|` 파이프 방어를 제거한 형태 — 이름 화이트리스트가 유일한 방어선이다.
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "파이프 파싱 우연에 기대지 않고 이름 화이트리스트만으로 deny 됨을 고정한다.",
    },
    {
        "case_id": "fix5-bypass-env-double-dash-allowlisted-routes",
        "fix": "FIX-5",
        "command": "env -- LANG=C git diff",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "대조군 — 허용 이름은 `--` 뒤에서도 계속 통과하며, 라우팅 헤드가 할당 "
        "word 가 아니라 실제 명령(git)으로 잡혀야 한다.",
    },
]


# ---------------------------------------------------------------------------
# FIX-5 — 시드 화이트리스트 양성 회귀 (AC-5.3) 및 글롭/접두사 오탐 거부 (AC-5.6)
# ---------------------------------------------------------------------------
FIX5_ALLOWLIST_POSITIVE_PINS: list[AdversarialPin] = [
    {
        "case_id": "fix5-pos-node-env",
        "fix": "FIX-5",
        "command": "NODE_ENV=production npm test",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "AC-5.3 — 시드 화이트리스트 안의 무해 접두사는 계속 허용된다.",
    },
    {
        "case_id": "fix5-pos-lang",
        "fix": "FIX-5",
        "command": "LANG=C.UTF-8 git diff",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "AC-5.3 — LANG 은 LOCPATH/NLSPATH 가 배제되었기 때문에만 안전하다.",
    },
    {
        "case_id": "fix5-pos-tz",
        "fix": "FIX-5",
        "command": "TZ=UTC git diff",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "AC-5.3 — TZ 는 코드를 실행하지 않고 tzfile 을 읽을 뿐인 최약체 허용 항목.",
    },
    {
        "case_id": "fix5-pos-term",
        "fix": "FIX-5",
        "command": "TERM=xterm-256color git diff",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "AC-5.3/AC-5.6 대조군 — TERM 자체는 허용되지만 TERMINFO 는 거부된다.",
    },
]

FIX5_GLOB_REJECTION_PINS: list[AdversarialPin] = [
    {
        "case_id": "fix5-adv-terminfo-not-term-prefix",
        "fix": "FIX-5",
        "command": "TERMINFO=/tmp/evil-terminfo git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "AC-5.6 — 정확 이름 일치만 허용. `TERM*` 글롭이었다면 TERMINFO 가 "
        "재승인되어 denylist(G2)를 침몰시킨 것과 동일한 실패 형태가 재현된다.",
    },
    {
        "case_id": "fix5-adv-locpath-not-lang-prefix",
        "fix": "FIX-5",
        "command": "LOCPATH=/tmp/evil git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "LANG/LC_* 는 LOCPATH 가 배제되었기 때문에만 안전하다는 조건부 "
        "안전성(§6.5)을 고정한다.",
    },
]


ALL_PINS: list[AdversarialPin] = [
    *FIX5_ADVERSARIAL_PINS,
    *FIX5_ALLOWLIST_POSITIVE_PINS,
    *FIX5_GLOB_REJECTION_PINS,
    *FIX5_ENV_WRAPPER_BYPASS_PINS,
]


def fix5_case_count() -> int:
    """AC-5.1 이 요구하는 19개 적대적 벡터 수를 고정 검증하기 위한 헬퍼."""
    return len(FIX5_ADVERSARIAL_PINS)
