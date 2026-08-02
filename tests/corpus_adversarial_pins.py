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
        "case_id": "fix5-bypass-env-safe-assignment-then-double-dash",
        "fix": "FIX-5",
        "command": "env LANG=C -- GIT_EXTERNAL_DIFF=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "`--` 는 할당 목록 앞뒤 어디에나 올 수 있다. 허용 이름을 먼저 두어 "
        "`--` 를 할당 뒤로 밀면 그 뒤의 할당 구간이 검사되지 않고 통과했다(실증).",
    },
    {
        "case_id": "fix5-bypass-env-double-dash-twice",
        "fix": "FIX-5",
        "command": "env -- env -- GIT_PAGER=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "중첩 `env` 와 반복 `--` 를 조합한 형태도 매 단계 재검사되어야 한다.",
    },
    {
        "case_id": "fix5-bypass-env-double-dash-then-safe-routes",
        "fix": "FIX-5",
        "command": "env LANG=C -- git diff",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "대조군 — 할당 뒤 `--` 형태에서 라우팅 헤드가 `--` 가 아니라 git 으로 "
        "잡혀야 한다(기존 구현은 `--` 를 명령으로 오인해 라우팅했다).",
    },
    {
        "case_id": "fix5-bypass-env-split-string",
        "fix": "FIX-5",
        "command": "env -S 'GIT_EXTERNAL_DIFF=/tmp/evil.sh git diff'",
        "expected_decision": "deny",
        # `-S`/`--split-string` 는 할당과 명령을 한 argv 원소로 묶어 env 가 다시 쪼갠다.
        # 현재는 미지의 `env` 플래그로 걸러지므로 원인 코드가 restricted_env_denied 다.
        # 이름 게이트가 아니라 플래그 게이트가 막고 있다는 사실을 명시적으로 고정한다.
        "expected_reason_code": "restricted_env_denied",
        "note": "AC-5.2 원인 구분 — `-S` 는 이름 게이트가 아니라 플래그 게이트가 막는다. "
        "향후 `env` 플래그를 허용하게 되면 이 핀이 먼저 깨져 재심사를 강제한다.",
    },
    {
        "case_id": "fix5-bypass-env-path-qualified",
        "fix": "FIX-5",
        "command": "/usr/bin/env GIT_EXTERNAL_DIFF=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "command_identity_denied",
        "note": "F-11 이후 경로 한정 `env` 는 환경 래퍼로 신뢰하지 않고 명령 "
        "identity 단계에서 먼저 거부한다.",
    },
    {
        "case_id": "fix5-bypass-env-path-qualified-quoted",
        "fix": "FIX-5",
        "command": "/usr/bin/env -- 'GIT_PAGER'=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "command_identity_denied",
        "note": "경로 한정 + `--` + 인용 피연산자 조합도 F-11 명령 identity "
        "단계에서 먼저 거부한다.",
    },
    {
        "case_id": "fix5-bypass-env-quoted-operand",
        "fix": "FIX-5",
        "command": "env 'GIT_EXTERNAL_DIFF'=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "coreutils `env` 는 셸 할당 문법이 아니라 `=` 를 포함한 argv 원소를 "
        "그대로 putenv() 한다. 인용 때문에 assignment_index 가 남지 않아 명령어로 "
        "취급되며 통과했다(실측: env 'X'=v 는 실제로 X 를 설정한다).",
    },
    {
        "case_id": "fix5-bypass-env-escaped-operand",
        "fix": "FIX-5",
        "command": "env GIT_EXTERNAL_DIFF\\=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "백슬래시로 `=` 를 인용한 형태도 env 는 동일하게 적용한다.",
    },
    {
        "case_id": "fix5-bypass-env-quoted-operand-allowlisted",
        "fix": "FIX-5",
        "command": "env 'LANG'=C git diff",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "대조군 — 인용된 허용 이름은 계속 통과하며 라우팅 헤드는 git 이어야 한다.",
    },
    {
        "case_id": "fix5-bypass-append-assignment",
        "fix": "FIX-5",
        "command": "GIT_EXTERNAL_DIFF+=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "bash 는 `NAME+=VALUE` 를 접두사 할당으로 실제 적용하지만(실측) "
        "MiniShell 은 이름 문법 불일치로 할당 표시를 남기지 않아 이름 검사를 건너뛰고 "
        "통과했다. 모델링 못하는 할당 형태는 fail-closed 로 거부한다.",
    },
    {
        "case_id": "fix5-bypass-append-assignment-in-env",
        "fix": "FIX-5",
        "command": "env -- LD_PRELOAD+=/tmp/evil.so cat README.md",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "`env` 래퍼와 결합한 append 할당도 같은 경로로 막혀야 한다.",
    },
    {
        "case_id": "fix5-bypass-append-assignment-allowlisted-name",
        "fix": "FIX-5",
        "command": "LANG+=C git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "허용 이름이라도 append 의미를 모델링하지 않으므로 과잉 거부 방향으로 "
        "닫는다 — 화이트리스트는 정확한 이름+대입 형태에 대해서만 안전을 주장한다.",
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


# ---------------------------------------------------------------------------
# FIX-1a — 비-git 라우트 술어 정밀화(`wc`/`head`/`tail`), INV-A/B 회귀 앵커
# (AC-1a.2, plan §5.2). AC-0.5 재확인: 실 트랜스크립트 코퍼스는 이 ContextGuard
# 조사 세션 트리 자체에서만 route_policy_denied 가 나와 오염 제거 후 N=0 이므로
# (plan §0.5), 실측 코퍼스 대신 이 hand-authored 코퍼스만 사용한다.
#
# baseline_reason_code 는 "개조 전" 코드를 읽어 수기로 판정했다(재실행으로 재검증
# 불가 — 개조 전 predicate 는 더 이상 존재하지 않는다). expected_decision/
# expected_reason_code 는 "개조 후" 기대값이다. 두 테스트가 이 표를 code-state에
# 무관하게 소비한다:
#   - INV-A 는 expected_decision == "deny" 인 행만 보고, 개조 전/후 어느 코드에
#     대해 실행해도 항상 참이어야 한다("여전히 거부").
#   - INV-B 는 baseline_reason_code == "route_policy_denied" 인 행만 보고,
#     실제로 deny → non-deny 전환이 관측된 경우에만 expected_decision 과
#     대조한다(개조 전 코드에서는 전환이 없어 이 대조가 트리거되지 않는다) — 이
#     구조 덕분에 "1) 하네스+코퍼스 추가, 현행 녹색 확인 → 2) 술어 변경" 두 단계
#     커밋이 모두 초록으로 통과한다(plan §6.1a 커밋 경계 1/2).
# FIX-1b/FIX-2 는 자신의 항목을 이 표에 이어 붙인다(레인별 구획 분리로 병합 충돌
# 축소, corpus_adversarial_pins.py:7-8 과 동일한 관례).
# ---------------------------------------------------------------------------
class RoutePredicateCase(TypedDict, total=False):
    case_id: str
    fix: str
    command: str
    baseline_reason_code: str | None
    expected_decision: str
    expected_reason_code: str | None
    note: str


FIX1A_ROUTE_PREDICATE_CASES: list[RoutePredicateCase] = [
    # --- wc: _wc_is_safe 에 allow_files 신설 (완화, INV-B 대상) ---
    {
        "case_id": "fix1a-wc-file-standalone-allowed",
        "fix": "FIX-1a",
        "command": "wc README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "noop",
        "expected_reason_code": None,
        "note": "핵심 완화 — _cat_is_safe 와 대칭으로 allow_files 신설, standalone 은 "
        "파일 피연산자를 허용한다.",
    },
    {
        "case_id": "fix1a-wc-multi-file-standalone-allowed",
        "fix": "FIX-1a",
        "command": "wc -l a.txt b.txt",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "noop",
        "expected_reason_code": None,
        "note": "다중 파일 피연산자도 operand 계수만 사용하므로 개수 무관하게 허용된다.",
    },
    # --- wc: 역방향 케이스 — 완화 표면에 인접하지만 여전히 거부(INV-A 대상) ---
    {
        "case_id": "fix1a-wc-file-filter-still-denied",
        "fix": "FIX-1a",
        "command": "printf '%s\\n' ok | wc README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "역방향 — filter 역할은 allow_files=False 라 파일 피연산자가 여전히 거부된다"
        "(stdin 과 파일을 동시에 요구하는 모순 방지).",
    },
    {
        "case_id": "fix1a-wc-unknown-flag-still-denied",
        "fix": "FIX-1a",
        "command": "wc -L README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "역방향 — 미지 플래그는 allow_files 와 무관하게 항상 거부된다.",
    },
    {
        "case_id": "fix1a-wc-first-role-still-denied",
        "fix": "FIX-1a",
        "command": "wc -l README.md | tee out.txt",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "역방향 — wc 는 role=='first' 자체가 무조건 거부라 allow_files 완화와 "
        "무관하게 여전히 route_policy_denied 로 거부되고, 두 번째 세그먼트(tee)까지 "
        "도달하지 않는다(command_search_diff 의 wc 분기가 _wc_is_safe 호출 전에 컷).",
    },
    # --- head/tail: count_seen 필수 요구 완화 (완화, INV-B 대상) ---
    {
        "case_id": "fix1a-head-bare-file-standalone-allowed",
        "fix": "FIX-1a",
        "command": "head README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "핵심 완화 — bare head 는 기본 10줄 상한이 있어 -n 없이도 안전하다.",
    },
    {
        "case_id": "fix1a-tail-bare-file-standalone-allowed",
        "fix": "FIX-1a",
        "command": "tail README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "tail 도 동일 완화 대상(-f/-F 가 아닌 한 기본 10줄 상한 적용).",
    },
    {
        "case_id": "fix1a-head-bare-no-operand-filter-allowed",
        "fix": "FIX-1a",
        "command": "printf '%s\\n' ok | head",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "filter 역할에서도 count 없는 bare head 는 이제 허용된다(파일 피연산자가 "
        "없어 allow_files=False 조건도 만족).",
    },
    # --- head/tail: 역방향 케이스 (INV-A 대상) ---
    {
        "case_id": "fix1a-tail-f-still-denied",
        "fix": "FIX-1a",
        "command": "tail -f README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "역방향 — -f/-F 는 count_seen 완화와 무관하게 항상 거부(무제한 스트림 방어, "
        "plan A3 폐기 이유이자 §0 정정 1의 A3 결함).",
    },
    {
        "case_id": "fix1a-head-c-still-denied",
        "fix": "FIX-1a",
        "command": "head -c 20 README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "역방향 — -c(바이트 단위)는 범위 밖. trim 예산 단위(줄)와 섞이면 "
        "--max-lines 220 상한을 우회할 수 있다(plan §6.1a 항목 3).",
    },
    {
        "case_id": "fix1a-head-file-filter-still-denied",
        "fix": "FIX-1a",
        "command": "printf '%s\\n' ok | head README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "역방향 — filter 역할은 파일 피연산자가 있으면 count_seen 완화와 무관하게 "
        "여전히 거부된다.",
    },
    # --- INV-A 실증 — reason_code 이동은 허용되지만 최종 deny 는 보존된다 ---
    {
        "case_id": "fix1a-inv-a-reason-code-drift-head-pipe-tee",
        "fix": "FIX-1a",
        "command": "head setup.py | tee out.txt",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "forbidden_command_denied",
        "note": "plan §5.2 실증 사례 — head 완화로 첫 세그먼트(role=first)는 통과하지만 "
        "두 번째 세그먼트의 tee 가 forbidden_command_denied 로 거부한다. reason_code 는 "
        "이동했지만 최종 판정은 여전히 deny — INV-A 위반이 아니다(축 b/a 게이트가 "
        "classify_command 의 단일 세그먼트 루프에 교차 배치된 결과, plan 원칙 1).",
    },
    {
        "case_id": "fix1a-inv-a-tail-f-in-pipe-still-denied",
        "fix": "FIX-1a",
        "command": "tail -f README.md | grep error",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "무제한 스트림 방어는 파이프 첫 세그먼트에서도 유지되어 두 번째 세그먼트에 "
        "도달하지 않는다(reason_code 도 이동하지 않음).",
    },
]


def fix1a_route_predicate_relaxations() -> list[RoutePredicateCase]:
    """INV-B 가 실제로 전환을 검사해야 하는 행(완화 대상)만 골라낸다."""
    return [
        case
        for case in FIX1A_ROUTE_PREDICATE_CASES
        if case.get("expected_decision") != "deny"
    ]


# ---------------------------------------------------------------------------
# FIX-1b — git (subcommand, 인자 형태) 쌍 화이트리스트, INV-A/B 회귀 앵커
# (plan §6.1b, AC-1.4, AC-1b.2). D1이 무효화한 두 프로토타입을 실증 고정한다:
#   1라운드 — 서브커맨드 이름만으로 허용 → 쓰기 6/6 누수.
#   2라운드 — "위치 인자 0개면 거부" → 위치 인자 0개 쓰기 8건 누수(AC-1.4의
#             stash/gc/prune/repack/clean -fd/reset --hard/commit --amend
#             --no-edit/branch --edit-description). clean -fd 와 reset --hard
#             는 단순 쓰기가 아니라 **데이터 손실**이다.
#   3라운드 — 전역 옵션이 서브커맨드 앞에 올 수 있음을 무시 → `argv[1]`을
#             찾으려 선행 플래그를 스킵하면 `git -c alias.zz='!...' zz`가
#             임의 셸을 실행한다(AC-1b.2, 실행 확인, R-5).
# baseline_reason_code 는 개조 전 코드(`subcommand not in {"diff","show","log"}`
# 만으로 판정하던 버전)를 읽어 수기로 판정했다 — 개조 전 코드에서 이 명령들은
# 전부 route_policy_denied 였다(config/stash/branch/tag/remote/gc/prune/repack/
# clean/reset/commit 은 옛 allow-set 에 아예 없었고, AC-1b.2의 9개는 `argv[1]`이
# 이미 리터럴이라 `-`로 시작하는 값이 옛 allow-set 과도 결코 일치하지 않았다 —
# 즉 R-5 불변식은 "새로 추가"가 아니라 "실수로 이미 있던 안전성을 명시적
# 불변식으로 승격 + 유지"다).
# ---------------------------------------------------------------------------
FIX1B_ROUTE_PREDICATE_CASES: list[RoutePredicateCase] = [
    # --- AC-1.4: 위치 인자 0개 쓰기 14건(D2 반증 사례) — 전부 INV-A 앵커 ---
    {
        "case_id": "fix1b-ac1-4-config-user-name",
        "fix": "FIX-1b",
        "command": "git config user.name Bob",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "config 행은 표에서 삭제됨(R-13) — 키 없이 값만 출력해 리댁션 불가.",
    },
    {
        "case_id": "fix1b-ac1-4-config-global-email",
        "fix": "FIX-1b",
        "command": "git config --global user.email x@y.z",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "config 행 삭제(R-13) — 전역 설정 파일 쓰기이기도 함.",
    },
    {
        "case_id": "fix1b-ac1-4-stash-bare-1",
        "fix": "FIX-1b",
        "command": "git stash",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "0-arity writer — stash 행은 list/show 만 허용, 맨 stash 는 거부.",
    },
    {
        "case_id": "fix1b-ac1-4-branch-newfeature",
        "fix": "FIX-1b",
        "command": "git branch newfeature",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "branch 는 위치 인자 0개 엄격 — arity 가 조회를 생성으로 뒤집는다.",
    },
    {
        "case_id": "fix1b-ac1-4-tag-v1",
        "fix": "FIX-1b",
        "command": "git tag v1.0.0",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "tag 도 위치 인자 0개 엄격 — branch 와 동일한 arity 반전 사유.",
    },
    {
        "case_id": "fix1b-ac1-4-remote-add",
        "fix": "FIX-1b",
        "command": "git remote add origin url",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "FIX-1b 시점에는 remote 행 자체가 표에서 삭제됨(R-13). FIX-6이 "
        "credential_policy.py 하드닝 후 `remote`/`remote -v` 조회 형태만 재도입했다 "
        "— 위치 인자가 있는 `add`는 branch/tag와 동일한 0-arity 규칙으로 여전히 "
        "거부된다(이 케이스의 expected_decision 은 변경 없음, FIX6_ROUTE_PREDICATE_"
        "CASES 의 fix6-inv-a-remote-add-still-denied 가 FIX-6 관점에서 재확인).",
    },
    {
        "case_id": "fix1b-ac1-4-gc",
        "fix": "FIX-1b",
        "command": "git gc",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "0-arity writer(2라운드 8건 누수 사례) — 오브젝트 스토어 재작성.",
    },
    {
        "case_id": "fix1b-ac1-4-prune",
        "fix": "FIX-1b",
        "command": "git prune",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "0-arity writer — 도달 불가 오브젝트 삭제.",
    },
    {
        "case_id": "fix1b-ac1-4-repack",
        "fix": "FIX-1b",
        "command": "git repack",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "0-arity writer — 오브젝트 스토어 재작성.",
    },
    {
        "case_id": "fix1b-ac1-4-clean-fd",
        "fix": "FIX-1b",
        "command": "git clean -fd",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "0-arity writer — 단순 쓰기가 아니라 **데이터 손실**(추적 안 된 파일 삭제).",
    },
    {
        "case_id": "fix1b-ac1-4-reset-hard",
        "fix": "FIX-1b",
        "command": "git reset --hard",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "0-arity writer — 단순 쓰기가 아니라 **데이터 손실**(워킹 트리 변경 폐기).",
    },
    {
        "case_id": "fix1b-ac1-4-commit-amend",
        "fix": "FIX-1b",
        "command": "git commit --amend --no-edit",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "0-arity writer — 직전 커밋을 재작성한다.",
    },
    {
        "case_id": "fix1b-ac1-4-branch-edit-description",
        "fix": "FIX-1b",
        "command": "git branch --edit-description",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "0-arity writer — branch 표에 없는 쓰기 플래그라 미지 플래그로도 거부됨.",
    },
    {
        "case_id": "fix1b-ac1-4-stash-bare-2",
        "fix": "FIX-1b",
        "command": "git stash",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "plan AC-1.4 목록의 중복 항목을 그대로 보존한다(14건 카운트, AC-0.5 산식).",
    },
    # --- AC-1b.2: argv[1] 리터럴 불변식(R-5) — 전역 옵션 우회 9건, 전부 앵커 ---
    {
        "case_id": "fix1b-ac1b2-c-core-pager",
        "fix": "FIX-1b",
        "command": "git -c core.pager=cat log -p",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "argv[1]='-c' — 서브커맨드로 인정되지 않아 즉시 거부.",
    },
    {
        "case_id": "fix1b-ac1b2-c-alias-rce",
        "fix": "FIX-1b",
        "command": "git -c alias.x='!id' x",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "R-5 핵심 사례 — 선행 옵션 스킵 패턴을 쓰면 임의 셸 실행이 확인된 벡터"
        "(`_package_script_route:1436` 패턴 재사용 금지).",
    },
    {
        "case_id": "fix1b-ac1b2-p-pager-flag",
        "fix": "FIX-1b",
        "command": "git -p log -p",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "argv[1]='-p'(페이저 강제) — 서브커맨드 자리에 전역 옵션.",
    },
    {
        "case_id": "fix1b-ac1b2-paginate",
        "fix": "FIX-1b",
        "command": "git --paginate log -p",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "argv[1]='--paginate'.",
    },
    {
        "case_id": "fix1b-ac1b2-no-pager",
        "fix": "FIX-1b",
        "command": "git --no-pager log -p",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "argv[1]='--no-pager' — 기존 git-diff family 의 negative 와 동일 계열.",
    },
    {
        "case_id": "fix1b-ac1b2-capital-c",
        "fix": "FIX-1b",
        "command": "git -C /tmp log -p",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "argv[1]='-C'(작업 디렉터리 변경) — 저장소 밖 경로로 이동 가능.",
    },
    {
        "case_id": "fix1b-ac1b2-exec-path",
        "fix": "FIX-1b",
        "command": "git --exec-path=/evil log -p",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "argv[1]='--exec-path=/evil' — git 내장 실행 파일 탐색 경로 치환.",
    },
    {
        "case_id": "fix1b-ac1b2-git-dir",
        "fix": "FIX-1b",
        "command": "git --git-dir=/other/.git log -p",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "argv[1]='--git-dir=/other/.git' — 다른 저장소를 대상으로 재지정.",
    },
    {
        "case_id": "fix1b-ac1b2-log-output",
        "fix": "FIX-1b",
        "command": "git log -p --output=/tmp/x",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "전역 옵션 우회가 아니라 서브커맨드 뒤 쓰기 플래그(임의 파일 쓰기) — "
        "log 의 허용 집합에 --output 이 없어 거부.",
    },
    # --- FIX-1b 완화 — deny -> sanitize 전환(INV-B 대상), 표의 각 신규 행 대표 1건 ---
    {
        "case_id": "fix1b-relax-status",
        "fix": "FIX-1b",
        "command": "git status -s",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "status 행 신설 — 위치 인자 0개 조건으로 조회만 허용.",
    },
    {
        "case_id": "fix1b-relax-log-oneline",
        "fix": "FIX-1b",
        "command": "git log --oneline -20",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "핵심 완화 — 개조 전에는 -p 없는 log 가 patch_output 요구로 거부됐다"
        "(§0 정정 1). AC-1.9 부착형 -20 도 함께 검증.",
    },
    {
        "case_id": "fix1b-relax-branch",
        "fix": "FIX-1b",
        "command": "git branch -a",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "branch 행 신설 — 위치 인자 0개 조건으로 조회만 허용.",
    },
    {
        "case_id": "fix1b-relax-tag",
        "fix": "FIX-1b",
        "command": "git tag -l",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "tag 행 신설 — 위치 인자 0개 조건으로 조회만 허용.",
    },
    {
        "case_id": "fix1b-relax-rev-parse",
        "fix": "FIX-1b",
        "command": "git rev-parse --show-toplevel",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "rev-parse 행 신설 — 위치 인자 무제한(revision 문자열).",
    },
    {
        "case_id": "fix1b-relax-describe",
        "fix": "FIX-1b",
        "command": "git describe --tags --always",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "describe 행 신설.",
    },
    {
        "case_id": "fix1b-relax-ls-files",
        "fix": "FIX-1b",
        "command": "git ls-files --cached --modified",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "ls-files 행 신설.",
    },
    {
        "case_id": "fix1b-relax-shortlog",
        "fix": "FIX-1b",
        "command": "git shortlog -sn HEAD",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "shortlog 행 신설 — AC-1.9 묶음 단축 플래그(-sn -> {s,n}) 검증 겸용. "
        "리비전 HEAD 를 주어 stdin 을 읽지 않는 형태만 승인된다.",
    },
    {
        "case_id": "fix1b-inv-a-shortlog-no-revision",
        "fix": "FIX-1b",
        "command": "git shortlog -sn",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": None,
        "note": "리비전 없는 shortlog 는 stdin 에서 커밋 로그를 읽어 래퍼의 600초 "
        "워치독까지 블록한다(실측). `tail -f` 를 거부하는 것과 같은 비종료 방지 "
        "불변식이므로 승인 범위를 좁히는 방향으로 고정한다.",
    },
    {
        "case_id": "fix1b-inv-a-shortlog-pathspec-only",
        "fix": "FIX-1b",
        "command": "git shortlog -sn -- README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": None,
        "note": "`--` 뒤 토큰은 pathspec 이라 리비전 요건을 충족하지 못한다 — "
        "위치 인자 총계만 세면 이 형태가 승인되지만 git 은 여전히 stdin 을 "
        "읽고 블록한다(실측).",
    },
    {
        "case_id": "fix1b-relax-blame",
        "fix": "FIX-1b",
        "command": "git blame -w README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "blame 행 신설 — 경로 1개 이상 필수 조건 충족.",
    },
    {
        "case_id": "fix1b-relax-stash-list",
        "fix": "FIX-1b",
        "command": "git stash list",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "stash 행 신설 — list/show 만 허용(맨 stash 는 계속 거부, 위 앵커 참고).",
    },
    {
        "case_id": "fix1b-relax-stash-show",
        "fix": "FIX-1b",
        "command": "git stash show",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "stash show 도 동일 완화 대상.",
    },
    # --- 완화 표면 인접 역방향 케이스(INV-A 대상) — D1/AC-1.9/AC-1.10 고정 ---
    {
        "case_id": "fix1b-inv-a-branch-bundled-write-flag",
        "fix": "FIX-1b",
        "command": "git branch -ad",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "AC-1.9 역방향 — 묶음 단축 플래그를 분해해도({a,d}) d 가 branch 의 "
        "허용 집합에 없어 거부된다. 완화가 쓰기 플래그를 재승인하지 않는지 확인.",
    },
    {
        "case_id": "fix1b-inv-a-tag-positional-after-double-dash",
        "fix": "FIX-1b",
        "command": "git tag -l -- v1.0.0",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "AC-1.10 역방향 — `--` 자체는 위치 인자로 계수하지 않지만 그 이후 토큰은 "
        "정상 계수한다. v1.0.0 이 위치 인자 1개로 계수되어 tag 의 엄격 0 상한을 "
        "위반한다(-- 뒤에 두면 우회된다는 오독을 막는다).",
    },
    {
        "case_id": "fix1b-inv-a-stash-unlisted-subcommand",
        "fix": "FIX-1b",
        "command": "git stash pop",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "미등재 인접 서브커맨드 — stash 행은 list/show 만 허용, pop 은 실제 쓰기"
        "(스태시 적용+삭제)이며 표에 없어 거부된다.",
    },
]


def fix1b_route_predicate_relaxations() -> list[RoutePredicateCase]:
    """INV-B 가 실제로 전환을 검사해야 하는 행(완화 대상)만 골라낸다."""
    return [
        case
        for case in FIX1B_ROUTE_PREDICATE_CASES
        if case.get("expected_decision") != "deny"
    ]


def fix1b_relaxation_case_count() -> int:
    """AC-1b.1 이 요구하는 11건의 완화 대상(표 신설 행) 케이스 수를 검증한다.

    `fix1b_route_predicate_relaxations` 는 `expected_decision != "deny"` 로
    구성원을 고르므로, 어떤 행의 기대값을 `deny` 로 오염시키면 그 행이 완화
    집합에서 조용히 빠져 단언이 공허해진다. 이 개수 가드가 그 이탈을 즉시
    빌드 실패로 만든다(AC-1.4/AC-1b.2 가드와 같은 역할)."""
    return len(fix1b_route_predicate_relaxations())


def fix1b_ac1_4_case_count() -> int:
    """AC-1.4 가 요구하는 14건의 위치 인자 0개 쓰기 고정 케이스 수를 검증한다."""
    return sum(
        1
        for case in FIX1B_ROUTE_PREDICATE_CASES
        if case["case_id"].startswith("fix1b-ac1-4-")
    )


def fix1b_ac1b2_case_count() -> int:
    """AC-1b.2 가 요구하는 9건의 전역 옵션 우회 고정 케이스 수를 검증한다."""
    return sum(
        1
        for case in FIX1B_ROUTE_PREDICATE_CASES
        if case["case_id"].startswith("fix1b-ac1b2-")
    )


# ---------------------------------------------------------------------------
# FIX-2 — `cat <bigfile>` read guard bypass 차단 (plan §6.2, AC-2.1/AC-2.2/
# AC-2.4/AC-2.5). FIX-1a/1b 와 달리 이 표의 관계 케이스는 deny -> allow 전환이
# 아니다 — 개조 전 standalone `cat`은 애초에 거부된 적이 없다(`noop`, 즉
# 무변형 통과). Read 가드(`guard_large_read.py`)는 `tool_name == "Read"`에서만
# 발동하고 Bash 훅의 standalone `cat`은 그 가드를 거치지 않으므로, 48KB 초과
# 파일을 `cat <bigfile>`로 읽으면 두 가드 사이의 정확한 틈을 통과해 파일
# 전체가 무제한으로 출력됐다(161,544바이트 ≈ 40,000토큰 실측). 이 표는 그래서
# INV-A/INV-B 대상이 아니며(라우트 *코드*만 `noop -> trim`으로 바뀔 뿐 어떤
# 명령이 허용되는지의 경계는 그대로다), `baseline_reason_code`는 실제로 거부된
# 적이 있는 행(§5.5 4번째 열의 역방향 케이스, AC-2.5의 범위 외 확인)에만
# 채우고 나머지는 None 이다 — 거부 이력이 없기 때문이다.
#
# `cat`이 이번에 처음 `bash -c` 재래핑 경로(INV-C)에 진입한다 — 왕복 실행
# 검증은 `test_context_guard_shell_contract.py`의 e2e 테스트(AC-2.3)가 실제
# `bash -c`를 통해 담당하므로 이 표에서는 라우트 판정만 고정한다.
# ---------------------------------------------------------------------------
FIX2_ROUTE_PREDICATE_CASES: list[RoutePredicateCase] = [
    {
        "case_id": "fix2-ac2-1-cat-standalone-bigfile",
        "fix": "FIX-2",
        "command": "cat README.ko.md",
        "baseline_reason_code": None,
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "AC-2.1 핵심 사례 — README.ko.md 는 72,517바이트(48KB 초과)로 "
        "저장소 안에 실재하는 파일이다. 라우트 판정 자체는 argv 형태만 보고 "
        "파일 크기를 읽지 않으므로(순수 문법적 판정) 어떤 크기의 파일에도 "
        "동일하게 적용된다 — 실제 결함 재현 규모(161,544바이트)와 같은 부류를 "
        "실재하는 저장소 파일로 구체화했다. 개조 전에는 noop(무변형 통과)이라 "
        "파일 전체가 유계화 없이 출력됐다.",
    },
    {
        "case_id": "fix2-ac2-1-cat-standalone-bare-flag",
        "fix": "FIX-2",
        "command": "cat -s README.ko.md",
        "baseline_reason_code": None,
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "허용 플래그 집합(`bnsETAvet`) 안의 `-s`(squeeze-blank)도 동일하게 "
        "trim 으로 전환된다 — 완화가 무플래그 형태에만 국한되지 않음을 보인다.",
    },
    {
        "case_id": "fix2-ac2-2-cat-filter-unchanged",
        "fix": "FIX-2",
        "command": "printf '%s\\n' ok | cat -n",
        "baseline_reason_code": None,
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "AC-2.2 — filter 역할은 개조 전에도 이미 trim 이었다(코퍼스 수준 "
        "회귀 고정). 이번 FIX-2 는 standalone 만 바꾸므로 이 케이스는 개조 "
        "전/후 어느 코드에도 동일하게 trim 이어야 한다 — 오라클 생성기의 "
        "`cat-filter` family(불변) 와 동일한 결론을 별도 경로로 재확인한다.",
    },
    {
        "case_id": "fix2-inv-a-cat-long-option-denied",
        "fix": "FIX-2",
        "command": "cat --show-all README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "§5.5 4번째 열(역방향 케이스) — `--`로 시작하는 장옵션은 "
        "`_cat_is_safe`의 허용 집합 검사에서 무조건 거부된다(플래그 문자 집합 "
        "검사 이전에 `argument.startswith(\"--\")`로 이미 걸린다). 완화가 "
        "장옵션 형태까지 재승인하지 않는지 고정한다.",
    },
    {
        "case_id": "fix2-inv-a-cat-unknown-short-flag-denied",
        "fix": "FIX-2",
        "command": "cat -z README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "§5.5 4번째 열 — `z`는 허용 플래그 집합(`bnsETAvet`) 밖이라 "
        "여전히 거부된다.",
    },
    {
        "case_id": "fix2-ac2-5-head-dash-c-out-of-scope",
        "fix": "FIX-2",
        "command": "head -c 100 README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "AC-2.5 — `head -c`/`tail -c`는 이 FIX 의 범위 밖이며 여전히 "
        "deny 다. trim 의 예산 단위는 줄(`CGW1_MAX_LINES`)인데 `-c`는 바이트 "
        "단위라, 개행 없는 거대한 한 줄을 `--max-lines 220`으로 유계화할 수 "
        "없다 — 이 조합을 trim 으로 보내면 가드가 작동하는 것처럼 보이면서 "
        "막지 못한다. 별도 바이트 예산 신설이 필요한 후속 변경이다.",
    },
    {
        "case_id": "fix2-ac2-5-tail-dash-c-out-of-scope",
        "fix": "FIX-2",
        "command": "tail -c 100 README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "AC-2.5 — head -c 와 동일한 사유로 tail -c 도 범위 밖이며 "
        "여전히 deny 다.",
    },
]


def fix2_route_predicate_relaxations() -> list[RoutePredicateCase]:
    """이번 FIX 가 라우트 *코드*를 바꾼(거부 이력이 없는) 행만 골라낸다.

    FIX1A/1B 의 동명 함수와 달리 deny -> allow 전환을 고르는 것이 아니다 —
    FIX-2 에는 그런 전환이 없다(§0 참고, 위 섹션 헤더). 대신
    `baseline_reason_code`가 없는(=개조 전에도 거부된 적이 없는) 행을 골라
    AC-2.1/AC-2.2 가 실제로 검사해야 할 대상만 좁힌다.
    """
    return [
        case for case in FIX2_ROUTE_PREDICATE_CASES if case.get("baseline_reason_code") is None
    ]


# ---------------------------------------------------------------------------
# FIX-LS — `ls`에 producer 라우트를 부여한다 (design doc
# route-readmission-design-20260729.md §4.1). FIX-1a와 동일한 shape — 실측
# 코퍼스 재플레이에서 13건의 `ls` 거부가 전부 `route_policy_denied`였고
# (`role == "first"`가 `{trim, sanitize}` 밖 라우트를 전부 deny), `ls` 자체는
# 오늘도 standalone에서 이미 `noop`으로 통과한다 — 이 표의 완화 대상은 전부
# deny -> allow(trim) 전환이므로(§0 대칭) INV-A/INV-B/INV-C 하네스로 검증한다.
# standalone 은 설계가 의도적으로 그대로 둔 것(§4.1 "Deliberately not
# proposed")이라 이 표에 없다 — 오라클의 `ls-producer` family가 대신 고정한다.
# ---------------------------------------------------------------------------
FIX_LS_ROUTE_PREDICATE_CASES: list[RoutePredicateCase] = [
    {
        "case_id": "fix-ls-first-basic-allowed",
        "fix": "FIX-LS",
        "command": "ls -la docs | head -30",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "핵심 완화 — 파이프라인 첫 세그먼트(role=first) `ls`가 새로 "
        "producer 라우트(trim)를 받는다. 재플레이로 실측된 13건 중 하나와 "
        "같은 형태.",
    },
    {
        "case_id": "fix-ls-first-recursive-allowed",
        "fix": "FIX-LS",
        "command": "ls -R src | wc -l",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "재귀 플래그(-R)도 허용목록 안이라 동일하게 trim 으로 전환된다.",
    },
    {
        "case_id": "fix-ls-first-cluster-allowed",
        "fix": "FIX-LS",
        "command": "ls -ltrh | cat",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "짧은 플래그 클러스터(-ltrh)는 값(value)을 소비하는 ls 플래그가 "
        "없다는 성질 덕분에 안전하게 분해된다(설계 §4.1 — sed/git과 달리 이 "
        "패턴이 성립하는 이유). 두 번째 세그먼트는 trim 을 요구하는 cat 으로 "
        "골라 전체 파이프 판정이 sanitize 로 밀리지 않게 한다(grep 처럼 "
        "sanitize 를 요구하는 세그먼트를 섞으면 전체 판정이 sanitize 로 "
        "지배된다 — ls 자체의 라우트와는 무관한 별개 축).",
    },
    {
        "case_id": "fix-ls-first-double-dash-operands-allowed",
        "fix": "FIX-LS",
        "command": "ls -la -- docs | head -30",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "`--` 이후는 전부 피연산자다 — 허용목록 검사는 거기서 멈춰야 "
        "한다. 이 행이 없으면 `--` 처리를 지워도 아무 테스트가 깨지지 않는다"
        "(변이 M8 생존).",
    },
    {
        "case_id": "fix-ls-first-double-dash-flaglike-operand-allowed",
        "fix": "FIX-LS",
        "command": "ls -- -weird | head -30",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "`--` 뒤의 플래그처럼 보이는 피연산자(`-weird`)는 플래그로 "
        "재해석되지 않는다 — ls 자신의 해석과 일치한다.",
    },
    {
        "case_id": "fix-ls-inv-a-filter-role-still-denied",
        "fix": "FIX-LS",
        "command": "printf '%s\\n' ok | ls -la",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "§5.5 4번째 열(역방향 케이스) — `ls`는 stdin을 읽지 않으므로 "
        "파이프라인 filter 역할은 항상 실수다. role == \"filter\" 는 무조건 "
        "deny — 완화가 filter 역할까지 재승인하지 않는다.",
    },
    {
        "case_id": "fix-ls-inv-a-long-flag-outside-table-denied",
        "fix": "FIX-LS",
        "command": "ls --sort=size docs | head",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "§5.5 4번째 열 — 값(value)을 취하는 롱플래그 `--sort=`는 허용목록 "
        "밖이라 여전히 deny. 완화가 표 밖 롱플래그까지 재승인하지 않는다.",
    },
    {
        "case_id": "fix-ls-inv-a-unknown-short-flag-denied",
        "fix": "FIX-LS",
        "command": "ls -Z docs | head",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "§5.5 4번째 열 — `-Z`(SELinux 컨텍스트)는 허용 짧은 플래그 집합 "
        "밖이라 여전히 deny.",
    },
    # 짧은 플래그 클러스터 분해가 성립하는 근거는 "허용목록 안의 어떤 ls 플래그도
    # 값을 소비하지 않는다"는 성질 하나뿐이다. 값을 소비하는 짧은 플래그가 단 하나
    # 라도 허용목록에 새로 들어오면 그 근거가 무너지고 클러스터 분해가 값 인자를
    # 플래그로 오독한다. 아래 4행이 그 경계를 고정한다 — GNU coreutils 의
    # `-w COLS`/`-T COLS`/`-I PATTERN`, BSD(macOS)의 `-D format`.
    {
        "case_id": "fix-ls-inv-a-gnu-width-value-flag-denied",
        "fix": "FIX-LS",
        "command": "ls -w 80 docs | head -30",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "GNU `-w COLS` 는 값을 소비한다 — 허용목록에 들어오면 클러스터 "
        "분해 논거가 깨진다.",
    },
    {
        "case_id": "fix-ls-inv-a-gnu-ignore-value-flag-denied",
        "fix": "FIX-LS",
        "command": "ls -I '*.pyc' docs | head -30",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "GNU `-I PATTERN` 은 값을 소비한다.",
    },
    {
        "case_id": "fix-ls-inv-a-gnu-tabsize-value-flag-denied",
        "fix": "FIX-LS",
        "command": "ls -T 4 docs | head -30",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "GNU `-T COLS` 는 값을 소비한다.",
    },
    {
        "case_id": "fix-ls-inv-a-bsd-date-format-value-flag-denied",
        "fix": "FIX-LS",
        "command": "ls -D '%F' docs | head -30",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "BSD(macOS) `-D format` 은 값을 소비한다 — 두 구현 모두에서 "
        "값 소비 플래그가 허용목록 밖임을 고정한다.",
    },
    {
        "case_id": "fix-ls-inv-a-color-always-denied",
        "fix": "FIX-LS",
        "command": "ls --color=always docs | head -30",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`--color=always` 는 ANSI 이스케이프를 출력에 주입해 trim/"
        "sanitize 대상 텍스트를 오염시키므로 허용목록 밖으로 유지한다 "
        "(`--color=never`/`--color=auto` 만 허용).",
    },
]


def ls_route_predicate_relaxations() -> list[RoutePredicateCase]:
    """INV-B 가 실제로 전환을 검사해야 하는 행(완화 대상)만 골라낸다."""
    return [
        case
        for case in FIX_LS_ROUTE_PREDICATE_CASES
        if case.get("expected_decision") != "deny"
    ]


def ls_relaxation_case_count() -> int:
    """FIX-LS 완화 대상(deny -> trim) 행 수를 고정한다.

    `ls_route_predicate_relaxations` 는 `expected_decision != "deny"` 로 구성원을
    고르므로, 행이 사라지거나 기대값이 `deny` 로 오염되면 INV-B/INV-C 루프가
    조용히 0회 반복하며 공허하게 통과한다. FIX-1b 의 개수 가드와 동일한 역할."""
    return len(ls_route_predicate_relaxations())


def ls_stay_denied_case_count() -> int:
    """FIX-LS 거부 보존(INV-A) 행 수를 고정한다 — 루프 공허 통과 방지."""
    return sum(
        1
        for case in FIX_LS_ROUTE_PREDICATE_CASES
        if case["expected_decision"] == "deny"
    )


# standalone 불변식 앵커 — `_ls_is_safe` 는 producer(role == "first") 재승인의
# 게이트일 뿐이므로 standalone 판정에는 영향을 주면 안 된다. 허용목록 밖 플래그를
# 쓴 standalone `ls` 도 변경 전(`noop`)과 동일해야 한다. 이 앵커가 없으면 게이트가
# standalone 까지 좁혀 오늘 통과하는 `ls -G` 류를 새로 거부해도 통과한다.
FIX_LS_STANDALONE_INVARIANT_COMMANDS: tuple[str, ...] = (
    "ls",
    "ls -la docs",
    "ls -R src",
    "ls --sort=size docs",
    "ls -Z docs",
    "ls -G",
    "ls -x docs",
    "ls -w 80",
    "ls --color=always",
    "ls --block-size=1K",
)


# ---------------------------------------------------------------------------
# FIX-GREP — `grep -o`/`-q` 와 롱플래그 표면을 재도입한다 (design doc
# route-readmission-design-20260729.md §4.2). FIX-1a/FIX-6 과 동일한 shape —
# `grep -r`/`-c`/`-l`/`-L`는 오늘도 이미 허용되어 있고(§4.2 서두, 브리핑 정정),
# 실제 gap 은 `-o`/`-q` 두 짧은 플래그와 `:1479-1487`의 네 예외를 제외한 모든
# `--` 접두 토큰 전체다. 이 표의 완화 대상은 전부 deny -> sanitize 전환이므로
# (라우트 자체는 `_grep_is_safe`가 이미 `sanitize`로 배선돼 있다 — 새 라우트가
# 아니라 predicate 문만 넓어진다) INV-A/INV-B/INV-C 하네스로 검증한다. ls와
# 달리 grep 은 standalone 에서도 이미 `_grep_is_safe`를 통과하면 sanitize 이므로
# (ls 처럼 "standalone 은 그대로 두는" 별도 설계 결정이 없다) standalone
# invariant 표가 없다 — 완화 대상 자체가 standalone 명령이다(파이프 불필요).
# ---------------------------------------------------------------------------
FIX_GREP_ROUTE_PREDICATE_CASES: list[RoutePredicateCase] = [
    # --- 완화 — deny -> sanitize 전환(INV-B 대상) ---
    {
        "case_id": "fix-grep-short-o-allowed",
        "fix": "FIX-GREP",
        "command": "grep -o token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "핵심 완화 1 — `-o`는 매치된 부분 문자열만 출력한다. **바이트 기준**"
        "으로는 이미 허용된 `-n` 형태보다 항상 적거나 같다. 다만 줄 수 기준으로는 "
        "그렇지 않다 — 한 줄에 매치가 N개면 `-o`는 N줄을 낸다. 줄 수는 sanitize "
        "래퍼의 `--max-lines` 상한이 잡으므로 예산 위험은 없다.",
    },
    {
        "case_id": "fix-grep-short-q-allowed",
        "fix": "FIX-GREP",
        "command": "grep -q token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "핵심 완화 2 — `-q`는 아무것도 출력하지 않고 종료 코드만 낸다. "
        "이 문서 전체에서 가장 출력이 유계인 명령.",
    },
    {
        "case_id": "fix-grep-long-only-matching-allowed",
        "fix": "FIX-GREP",
        "command": "grep --only-matching token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-o`의 정확 일치 롱 별칭.",
    },
    {
        "case_id": "fix-grep-long-quiet-allowed",
        "fix": "FIX-GREP",
        "command": "grep --quiet token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-q`의 정확 일치 롱 별칭.",
    },
    {
        "case_id": "fix-grep-long-silent-allowed",
        "fix": "FIX-GREP",
        "command": "grep --silent token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-q`의 GNU 동의어(`--silent`)도 별도 정확 일치 항목으로 고정한다.",
    },
    {
        "case_id": "fix-grep-long-count-allowed",
        "fix": "FIX-GREP",
        "command": "grep --count token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "짧은 형태 `-c`는 이미 허용됐지만 그 롱 별칭 자체는 예전에는 "
        "`:1479-1487`의 네 예외 밖이라 거부됐다 — 별칭 표가 이를 메운다.",
    },
    {
        "case_id": "fix-grep-long-line-number-allowed",
        "fix": "FIX-GREP",
        "command": "grep --line-number token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-n`의 롱 별칭.",
    },
    {
        "case_id": "fix-grep-long-no-filename-allowed",
        "fix": "FIX-GREP",
        "command": "grep --no-filename token README.md README2.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "브리핑이 명시적으로 거부 사례로 든 형태(§0) — `-h`의 롱 별칭.",
    },
    {
        "case_id": "fix-grep-long-invert-match-allowed",
        "fix": "FIX-GREP",
        "command": "grep --invert-match token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-v`의 롱 별칭.",
    },
    {
        "case_id": "fix-grep-long-extended-regexp-allowed",
        "fix": "FIX-GREP",
        "command": "grep --extended-regexp token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-E`의 롱 별칭.",
    },
    {
        "case_id": "fix-grep-long-color-never-allowed",
        "fix": "FIX-GREP",
        "command": "grep --color=never token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "브리핑이 명시적으로 거부 사례로 든 형태(§0) — 값이 `never`인 경우만 "
        "표에 정확히 일치해 허용된다.",
    },
    {
        "case_id": "fix-grep-long-color-auto-allowed",
        "fix": "FIX-GREP",
        "command": "grep --color=auto token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`--color=auto`도 `--color=never`와 동일하게 정확 일치로 허용된다.",
    },
    {
        "case_id": "fix-grep-long-dereference-recursive-allowed",
        "fix": "FIX-GREP",
        "command": "grep --dereference-recursive token src",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-r`/`--recursive`와 별개로 심볼릭 링크를 따라가는 변형 — 재귀 자체는 "
        "이미 허용됐으므로 순수 표면 확장이다.",
    },
    {
        "case_id": "fix-grep-cluster-oq-allowed",
        "fix": "FIX-GREP",
        "command": "grep -oq token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`o`/`q`가 `allowed_flags`에 들어가 클러스터(`-oq`) 형태로도 허용된다.",
    },
    {
        "case_id": "fix-grep-double-dash-terminator-with-o-allowed",
        "fix": "FIX-GREP",
        "command": "grep -o -- --token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`--` 종결자 처리는 이번 변경으로 건드리지 않았다 — `-o` 추가 이후에도 "
        "`--` 뒤 플래그처럼 보이는 패턴(`--token`)이 옵션으로 재해석되지 않고 "
        "패턴 피연산자로 남는지 고정한다(변이: `--` 종결자 무시).",
    },
    # --- 역방향 케이스(INV-A 대상) — 값 소비 롱플래그와 표 밖 형태는 여전히 거부 ---
    {
        "case_id": "fix-grep-inv-a-file-eq-denied",
        "fix": "FIX-GREP",
        "command": "grep --file=patterns.txt README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "패턴 목록을 predicate 가 볼 수 없는 파일에서 읽는다 — 기존 "
        "명시적 거부(`:1449` 상당)를 그대로 보존한다.",
    },
    {
        "case_id": "fix-grep-inv-a-binary-files-denied",
        "fix": "FIX-GREP",
        "command": "grep --binary-files=text README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "값을 취하는 롱플래그 — 별칭 표에 넣지 않는다.",
    },
    {
        "case_id": "fix-grep-inv-a-color-always-denied",
        "fix": "FIX-GREP",
        "command": "grep --color=always token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "ANSI 이스케이프를 출력에 주입해 컨텍스트를 오염시킨다 — "
        "`never`/`auto`만 표에 있고 `always`는 없다. `--color` 접두 매칭을 "
        "허용했다면(금지된 startswith 규칙) 이 케이스가 통과했을 것이다.",
    },
    {
        "case_id": "fix-grep-inv-a-devices-denied",
        "fix": "FIX-GREP",
        "command": "grep --devices=skip token src",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "값이 동작을 바꾸는 롱플래그 — 표 밖.",
    },
    {
        "case_id": "fix-grep-inv-a-directories-denied",
        "fix": "FIX-GREP",
        "command": "grep --directories=read token src",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`--directories=read`는 디렉터리 피연산자를 읽기 대상으로 바꾼다 — "
        "값이 동작을 바꾸는 롱플래그라 표 밖으로 유지한다.",
    },
    {
        "case_id": "fix-grep-inv-a-short-a-denied",
        "fix": "FIX-GREP",
        "command": "grep -a token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-a`는 `--binary-files=text`와 동일한 스위치의 짧은 표기다 — 같은 "
        "불변식을 두 곳에 모순되게 적어두지 않으려 셋 다 거부 상태로 둔다.",
    },
    {
        "case_id": "fix-grep-inv-a-short-cap-i-denied",
        "fix": "FIX-GREP",
        "command": "grep -I token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-I`(대문자)는 `--binary-files=without-match`의 짧은 표기 — 소문자 "
        "`-i`(대소문자 무시, 이미 허용)와 혼동하지 않도록 별도로 고정한다.",
    },
    {
        "case_id": "fix-grep-inv-a-short-z-denied",
        "fix": "FIX-GREP",
        "command": "grep -z token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-z`(NUL 구분)는 출력 프레이밍을 바꾼다 — 허용 짧은 플래그 집합 밖.",
    },
    {
        "case_id": "fix-grep-inv-a-null-long-denied",
        "fix": "FIX-GREP",
        "command": "grep --null token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-Z`/`--null`은 출력 프레이밍을 바꾼다 — 별칭 표 밖.",
    },
    {
        "case_id": "fix-grep-inv-a-label-eq-denied",
        "fix": "FIX-GREP",
        "command": "grep --label=x token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "값을 취하는 롱플래그 — 별칭 표 밖.",
    },
    {
        "case_id": "fix-grep-inv-a-near-miss-long-flag-denied",
        "fix": "FIX-GREP",
        "command": "grep --only-matchingx token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`--only-matching`과 접두사가 같지만 정확히 일치하지 않는 미등재 "
        "롱플래그 — 정확 일치 규율(exact-match, startswith 금지)을 직접 "
        "고정한다. startswith 매칭으로 회귀하면 이 케이스가 허용으로 뒤집힌다.",
    },
    {
        "case_id": "fix-grep-inv-a-filter-role-file-operand-still-denied",
        "fix": "FIX-GREP",
        "command": "printf '%s\\n' ok | grep -o token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "역방향 — `-o`가 새로 허용됐어도 filter 역할(`allow_files=False`, "
        "`:1490` 상당)의 파일 피연산자 거부 불변식은 그대로 유지된다.",
    },
    # --- 변이 생존 차단 보강 (PR #251 리뷰 라운드 1) ---
    # 아래 행들은 새 동작을 만들지 않는다. 전부 현재 실측 결정을 그대로 고정할
    # 뿐이며, 목적은 감시 공백(surveillance gap)을 메우는 것이다. 리뷰 라운드에서
    # `_GREP_LONG_ALIASES` 를 대상으로 변이 테스트를 돌린 결과, 표의 22개 항목 중
    # 10개는 삭제해도 어떤 테스트도 깨지지 않았고(축소 방향), `--colour=always` /
    # `--regexp=` / `--include=` 접두 허용을 새로 추가하는 변이(확대 방향)도
    # 전부 생존했다. 특히 `--colour=always` 는 PR 이 "ANSI 이스케이프 주입"으로
    # 명시 금지한 바로 그 능력의 다른 철자인데, 기존 핀은 `--color=always` 라는
    # **철자 하나만** 고정하고 있었다.
    {
        "case_id": "fix-grep-long-ignore-case-allowed",
        "fix": "FIX-GREP",
        "command": "grep --ignore-case token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-i`의 롱 별칭 — 표에서 삭제해도 어떤 테스트도 깨지지 않던 항목.",
    },
    {
        "case_id": "fix-grep-long-with-filename-allowed",
        "fix": "FIX-GREP",
        "command": "grep --with-filename token README.md README2.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-H`의 롱 별칭.",
    },
    {
        "case_id": "fix-grep-long-files-with-matches-allowed",
        "fix": "FIX-GREP",
        "command": "grep --files-with-matches token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-l`의 롱 별칭.",
    },
    {
        "case_id": "fix-grep-long-files-without-match-allowed",
        "fix": "FIX-GREP",
        "command": "grep --files-without-match token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-L`의 롱 별칭 — `--files-with-matches`와 한 글자 차이라 함께 고정한다.",
    },
    {
        "case_id": "fix-grep-long-word-regexp-allowed",
        "fix": "FIX-GREP",
        "command": "grep --word-regexp token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-w`의 롱 별칭.",
    },
    {
        "case_id": "fix-grep-long-line-regexp-allowed",
        "fix": "FIX-GREP",
        "command": "grep --line-regexp token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-x`의 롱 별칭.",
    },
    {
        "case_id": "fix-grep-long-fixed-strings-allowed",
        "fix": "FIX-GREP",
        "command": "grep --fixed-strings token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-F`의 롱 별칭.",
    },
    {
        "case_id": "fix-grep-long-basic-regexp-allowed",
        "fix": "FIX-GREP",
        "command": "grep --basic-regexp token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-G`의 롱 별칭.",
    },
    {
        "case_id": "fix-grep-long-perl-regexp-allowed",
        "fix": "FIX-GREP",
        "command": "grep --perl-regexp token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`-P`의 롱 별칭.",
    },
    {
        "case_id": "fix-grep-inv-a-long-no-messages-denied",
        "fix": "FIX-GREP",
        "command": "grep --no-messages token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "짧은 형태 `-s`가 `allowed_flags` 밖이므로 롱 형태도 표에서 뺐다"
        "(바로 아래 `fix-grep-inv-a-short-s-denied`와 짝). 리뷰 라운드는 이것을 "
        "'표는 이미 허용된 짧은 옵션과 동치인 것만 담는다'는 주석과 표가 어긋나는 "
        "비대칭으로 보고했고, 표를 좁혀 주석이 참이 되도록 정렬했다. `-s`는 stderr "
        "진단만 억제해 위험하지 않지만, 규칙에 예외를 하나 두면 주석이 거짓이 되고 "
        "거짓 주석은 이 저장소에서 결함이 전파되는 경로다. 넓히기로 결정한다면 "
        "짧은 옵션 쪽을 먼저 넓히고 그 다음 롱 형태를 표에 넣는다. 실측상 실사용 "
        "트랜스크립트에서 이 형태의 이동은 0건이라 좁혀도 잃는 것이 없다.",
    },
    {
        "case_id": "fix-grep-inv-a-short-s-denied",
        "fix": "FIX-GREP",
        "command": "grep -s token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`--no-messages`의 짧은 형태 — `allowed_flags` 밖이라 거부다. "
        "바로 위 항목과 짝을 이루는 비대칭 핀.",
    },
    {
        "case_id": "fix-grep-inv-a-colour-always-denied",
        "fix": "FIX-GREP",
        "command": "grep --colour=always token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`--color=always`의 영연방 철자. GNU grep 은 `--colour`를 `--color`의 "
        "동의어로 받으므로 이 철자는 PR 이 금지한 ANSI 이스케이프 주입 능력에 "
        "**다른 이름으로 도달한다**. 기존 핀은 `--color=always` 한 철자만 "
        "고정하고 있어서, 표에 `--colour=always`를 넣는 변이가 전 테스트를 "
        "통과했다. 능력 기준으로 고정하기 위해 철자별 핀을 추가한다.",
    },
    {
        "case_id": "fix-grep-inv-a-colour-never-denied",
        "fix": "FIX-GREP",
        "command": "grep --colour=never token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "표는 `--color=` 철자만 담는다 — `--colour=never`는 무해하지만 "
        "미등재라 거부다(fail-closed). 철자 집합의 경계를 명시적으로 고정한다.",
    },
    {
        "case_id": "fix-grep-inv-a-regexp-eq-denied",
        "fix": "FIX-GREP",
        "command": "grep --regexp=token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-e`의 값 결합 롱 형태. `-e PAT`는 이미 허용되지만 `--regexp=`는 "
        "값 소비 롱플래그라 표 밖이다 — 이 경계에 `--regexp=` 접두 허용을 "
        "추가하는 변이가 감시 없이 통과하지 못하게 한다.",
    },
    {
        "case_id": "fix-grep-inv-a-quoted-exclude-dir-glob-denied",
        "fix": "FIX-GREP",
        "command": "grep -rn --exclude-dir='.git' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "위와 같은 이유 — 인용된 `--exclude-dir=` 도 route 축에서 죽는다.",
    },
    # --- `git grep` 동반 확장 (PR #251 리뷰 라운드 1, Claude 트랙 MEDIUM) ---
    # `_git_is_safe` 는 `grep` 서브커맨드를 `_grep_is_safe(("grep", *arguments),
    # allow_files=True)` 로 그대로 위임한다. 즉 이 PR 의 predicate 확장은 `grep`/
    # `egrep`/`fgrep` 뿐 아니라 **`git grep` 에도 동시에 적용된다**. 실측으로
    # `git grep -o`/`-q`/롱 별칭이 deny -> sanitize 로 함께 움직였는데 케이스 표에는
    # `git grep` 행이 하나도 없었다 — 공유 predicate 의 폭발 반경 중 절반이 감시
    # 밖이었다. 두 호출 지점 모두를 고정한다.
    {
        "case_id": "fix-grep-git-grep-short-o-allowed",
        "fix": "FIX-GREP",
        "command": "git grep -o token",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`git grep` 도 같은 predicate 를 쓰므로 `-o` 완화가 함께 적용된다.",
    },
    {
        "case_id": "fix-grep-git-grep-short-q-allowed",
        "fix": "FIX-GREP",
        "command": "git grep -q token",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "`git grep -q` 도 함께 열린다 — 두 번째 호출 지점의 완화를 고정한다.",
    },
    {
        "case_id": "fix-grep-git-grep-long-only-matching-allowed",
        "fix": "FIX-GREP",
        "command": "git grep --only-matching token",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "롱 별칭 표도 `git grep` 경로에 그대로 적용된다.",
    },
    {
        "case_id": "fix-grep-git-grep-color-always-denied",
        "fix": "FIX-GREP",
        "command": "git grep --color=always token",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "역방향 — `git grep` 경로에서도 ANSI 주입 금지가 동일하게 유지된다.",
    },
    # --- 표에서 명시 제외했으나 어떤 핀도 감시하지 않던 능력들 ---
    # (PR #251 리뷰 라운드 1, Claude 트랙 MEDIUM). 특히 `-D`/`-U` 는 GNU 에서
    # 값을 소비하는 형태(`-D ACTION`)라, `allowed_flags` 에 `D` 를 넣는 변이는
    # 능력을 여는 동시에 다음 피연산자를 조용히 삼킨다.
    {
        "case_id": "fix-grep-inv-a-exclude-eq-denied",
        "fix": "FIX-GREP",
        "command": "grep --exclude='*.py' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`--include=`/`--exclude-dir=` 와 같은 부류인데 핀이 없었다.",
    },
    {
        "case_id": "fix-grep-inv-a-short-cap-z-denied",
        "fix": "FIX-GREP",
        "command": "grep -Z token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`--null` 의 짧은 형태 — 롱 형태만 핀이 있었다.",
    },
    {
        "case_id": "fix-grep-inv-a-short-cap-d-value-consuming-denied",
        "fix": "FIX-GREP",
        "command": "grep -D read token src",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-D ACTION` 은 값을 소비하는 짧은 플래그다 — `allowed_flags` 에 "
        "`D` 를 넣는 변이는 능력을 여는 동시에 다음 토큰(`read`)을 플래그 값으로 "
        "삼켜 피연산자 회계까지 망가뜨린다. 명시 제외 목록에 있었으나 감시가 없었다.",
    },
    {
        "case_id": "fix-grep-inv-a-short-cap-u-denied",
        "fix": "FIX-GREP",
        "command": "grep -U token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-U`(바이너리 취급) — 명시 제외 목록에 있었으나 감시가 없었다.",
    },
    {
        "case_id": "fix-grep-inv-a-null-data-denied",
        "fix": "FIX-GREP",
        "command": "grep --null-data token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-z`(입력 줄 구분자를 NUL 로) 의 롱 형태 — 출력/입력 프레이밍을 "
        "바꾼다. 짧은 형태만 핀이 있었다.",
    },
]


def fix_grep_route_predicate_relaxations() -> list[RoutePredicateCase]:
    """INV-B 가 실제로 전환을 검사해야 하는 행(완화 대상)만 골라낸다."""
    return [
        case
        for case in FIX_GREP_ROUTE_PREDICATE_CASES
        if case.get("expected_decision") != "deny"
    ]


def fix_grep_relaxation_case_count() -> int:
    """FIX-GREP 완화 대상(deny -> sanitize) 행 수를 고정한다 — 루프 공허 통과 방지."""
    return len(fix_grep_route_predicate_relaxations())


def fix_grep_stay_denied_case_count() -> int:
    """FIX-GREP 거부 보존(INV-A) 행 수를 고정한다 — 루프 공허 통과 방지."""
    return sum(
        1
        for case in FIX_GREP_ROUTE_PREDICATE_CASES
        if case["expected_decision"] == "deny"
    )


# ---------------------------------------------------------------------------
# S010 — incidence-gated recursive grep with exactly one include glob.
# The value grammar is intentionally smaller than shell glob syntax and the
# route remains limited to the bare `grep` producer with a real file/directory
# operand.  `git grep`, egrep/fgrep aliases, stdin operands, excludes, duplicate
# includes, and every near-prefix spelling remain denied.
# ---------------------------------------------------------------------------
S010_GREP_INCLUDE_CASES: list[RoutePredicateCase] = [
    {
        "case_id": "s010-include-py-allowed",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -rn --include='*.py' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "Canonical recursive include-only form with an ordinary extension glob.",
    },
    {
        "case_id": "s010-include-question-json-allowed",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -R --include='test_?.json' token src",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "Question-mark wildcard is allowed when the value also has literals.",
    },
    {
        "case_id": "s010-include-literal-allowed",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep --recursive --include='a' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "The minimum one-byte literal value is admissible.",
    },
    {
        "case_id": "s010-include-dotfile-allowed",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='.env*' token config",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "A leading dot is a literal and therefore not wildcard-only.",
    },
    {
        "case_id": "s010-include-mixed-grammar-double-dash-allowed",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='a-b_c.1' token -- src tests",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "All grammar characters plus multiple operands after `--` remain bounded.",
    },
    {
        "case_id": "s010-96-byte-value-allowed",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='" + ("a" * 96) + "' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "The exact 96-byte upper boundary remains admissible.",
    },
    {
        "case_id": "s010-include-producer-pipeline-allowed",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='*.md' token docs | head -5",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "The same file-backed form is safe as the first pipeline segment.",
    },
    {
        "case_id": "s010-wildcard-star-only-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='*' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Wildcard-only values provide no include selectivity.",
    },
    {
        "case_id": "s010-wildcard-question-only-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='???' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Question-mark-only values are also wildcard-only.",
    },
    {
        "case_id": "s010-star-dashes-without-literal-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='*--' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Hyphen is allowed syntax but does not satisfy the literal requirement.",
    },
    {
        "case_id": "s010-leading-dash-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='-a' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "A value may not begin with a dash.",
    },
    {
        "case_id": "s010-slash-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='a/b' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Include values are ASCII basenames, not paths.",
    },
    {
        "case_id": "s010-backslash-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='a\\b' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Backslash/escape syntax is outside the canonical grammar.",
    },
    {
        "case_id": "s010-whitespace-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='a b' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Quoted whitespace still lies outside the value grammar.",
    },
    {
        "case_id": "s010-bracket-syntax-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='a[b]' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Bracket glob syntax is deliberately unsupported.",
    },
    {
        "case_id": "s010-brace-syntax-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='a{b}' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Brace syntax is deliberately unsupported.",
    },
    {
        "case_id": "s010-newline-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='a\nb' token .",
        "baseline_reason_code": "forbidden_quoted_whitespace",
        "expected_decision": "deny",
        "expected_reason_code": "forbidden_quoted_whitespace",
        "note": "A literal newline is rejected before route evaluation.",
    },
    {
        "case_id": "s010-nul-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='a\0b' token .",
        "baseline_reason_code": "nul_denied",
        "expected_decision": "deny",
        "expected_reason_code": "nul_denied",
        "note": "NUL is rejected before route evaluation.",
    },
    {
        "case_id": "s010-empty-value-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "The value length lower bound is one.",
    },
    {
        "case_id": "s010-97-byte-value-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='" + ("a" * 97) + "' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "The value length upper bound is 96 ASCII bytes.",
    },
    {
        "case_id": "s010-duplicate-include-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='*.py' --include='*.json' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Exactly one include option is required.",
    },
    {
        "case_id": "s010-nonrecursive-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep --include='*.py' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "An include option is admitted only with recursive grep.",
    },
    {
        "case_id": "s010-operand-free-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='*.py' token",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "The route must have a file or directory operand.",
    },
    {
        "case_id": "s010-included-prefix-typo-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --included='*.py' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Unknown --include* prefixes are not accepted by startswith matching.",
    },
    {
        "case_id": "s010-includes-prefix-typo-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --includes='*.py' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "A second near-prefix spelling pins the exact option name.",
    },
    {
        "case_id": "s010-separated-value-form-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include '*.py' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Only the exact --include=<glob> token form is allowed.",
    },
    {
        "case_id": "s010-exclude-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='*.py' --exclude='test*' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Exclude forms remain reserved for the later C011 checkpoint.",
    },
    {
        "case_id": "s010-exclude-dir-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='*.py' --exclude-dir='.git' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Exclude-dir forms remain reserved for the later C011 checkpoint.",
    },
    {
        "case_id": "s010-filter-file-operand-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "printf '%s\\n' ok | grep -r --include='*.py' token README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "A grep filter may not acquire file operands through this route.",
    },
    {
        "case_id": "s010-git-grep-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "git grep -r --include='*.py' token -- README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "The shared predicate must not widen git grep, which has different semantics.",
    },
    {
        "case_id": "s010-egrep-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "egrep -r --include='*.py' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "The incidence gate covered the bare grep command, not legacy aliases.",
    },
    {
        "case_id": "s010-fgrep-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "fgrep -r --include='*.py' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "The incidence gate covered the bare grep command, not legacy aliases.",
    },
    {
        "case_id": "s010-stdin-operand-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='*.py' token -",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "Explicit stdin is not a file/directory operand and may block.",
    },
    {
        "case_id": "s010-double-dash-stdin-operand-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='*.py' token -- -",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "The stdin operand remains stdin after the option terminator.",
    },
    {
        "case_id": "s010-nonascii-denied",
        "fix": "S010-GREP-INCLUDE",
        "command": "grep -r --include='é.py' token .",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "The canonical value grammar is ASCII only.",
    },
]


def s010_grep_include_route_predicate_relaxations() -> list[RoutePredicateCase]:
    """Return only S010 deny-to-sanitize admissions for the F-15 proof."""
    return [
        case
        for case in S010_GREP_INCLUDE_CASES
        if case["expected_decision"] != "deny"
    ]


def s010_grep_include_stay_denied() -> list[RoutePredicateCase]:
    """Return the S010-adjacent shapes that must remain denied."""
    return [
        case
        for case in S010_GREP_INCLUDE_CASES
        if case["expected_decision"] == "deny"
    ]


# ---------------------------------------------------------------------------
# FIX-SED — `sed -n 'N,Mp' <file>` 범위 읽기에 파일 피연산자 슬롯을 연다
# (design doc route-readmission-design-20260729.md §2.3). 기존 `_sed_is_safe`
# 는 `len(argv) in {3,4}` 형태 매처로 파일 피연산자 슬롯이 아예 없었다 —
# stdin 형태만 통과시켰고, 그 형태는 Read 를 절약하지 않는 유일한 형태였다.
# 세 클래스 중 유일하게 실패 모드가 **파일 변조**다(`-i`) — 그래서 predicate
# 는 전체 argv 를 `--` 까지 스캔하고(GNU 순열 방어), 클러스터를 전부
# 거부하며(정확한 토큰만 허용), 스크립트 본문의 `fullmatch` 경계는 전혀
# 느슨해지지 않는다. 이 표의 완화 대상은 전부 deny -> allow(trim) 전환이므로
# (§0 대칭) INV-A/INV-B/INV-C 하네스로 검증한다.
# ---------------------------------------------------------------------------
FIX_SED_ROUTE_PREDICATE_CASES: list[RoutePredicateCase] = [
    # --- 완화 — deny -> trim 전환(INV-B 대상) ---
    {
        "case_id": "fix-sed-standalone-basic-allowed",
        "fix": "FIX-SED",
        "command": "sed -n '1,80p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "핵심 완화 — standalone `sed -n 'N,Mp' <file>` 이 새로 파일 "
        "피연산자 슬롯을 받는다. `sed -n '1,80p' README.md` 는 가장 값싼 "
        "부분 읽기이자, 이걸 거부하면 에이전트가 파일 전체를 읽게 만드는 "
        "정확한 역효과였다.",
    },
    {
        "case_id": "fix-sed-first-basic-allowed",
        "fix": "FIX-SED",
        "command": "sed -n '1,80p' README.md | head -5",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "파이프라인 첫 세그먼트(role=first)도 파일 피연산자가 있으면 "
        "동일하게 trim 으로 전환된다 — role==\"first\" 는 이번에 처음 열리는 "
        "축이다(기존에는 무조건 deny).",
    },
    {
        "case_id": "fix-sed-standalone-multi-file-allowed",
        "fix": "FIX-SED",
        "command": "sed -n '1,80p' a.txt b.txt",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "여러 파일 피연산자도 개수만 세므로(files > 0) 허용된다.",
    },
    {
        "case_id": "fix-sed-standalone-dash-e-form-allowed",
        "fix": "FIX-SED",
        "command": "sed -n -e '1,80p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "`-e` 가 있으면 모든 피연산자가 파일이라는 조건부 스크립트 위치 "
        "규칙(design §2.2 함정 1)이 정확히 반영됐는지 고정한다.",
    },
    {
        "case_id": "fix-sed-standalone-long-expression-form-allowed",
        "fix": "FIX-SED",
        "command": "sed -n --expression='1,80p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "`--expression=` 롱 스펠링도 `-e` 와 동일하게 처리된다.",
    },
    {
        "case_id": "fix-sed-standalone-double-dash-operand-allowed",
        "fix": "FIX-SED",
        "command": "sed -n '1,80p' -- README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "`--` 이후는 전부 피연산자다 — 옵션 스캔은 거기서 멈춰야 한다.",
    },
    # --- S009 — 안전한 p-only SEG를 세미콜론으로 조합한다 ---
    {
        "case_id": "s009-multi-range-basic-allowed",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;10,20p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "S009 핵심 완화 — 이미 허용된 숫자 p-only SEG 둘을 `;` 로 "
        "조합한 부분 읽기다. 각 SEG를 독립적으로 같은 문법으로 검증해야 한다.",
    },
    {
        "case_id": "s009-multi-range-first-allowed",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;10,20p' README.md | head -5",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "파이프라인 producer 역할에서도 파일 피연산자가 있는 동일한 "
        "multi-range 스크립트는 trim 으로 재래핑된다.",
    },
    {
        "case_id": "s009-multi-range-single-and-dollar-allowed",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1p;5,9p;20,$p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "단일 숫자, 숫자 범위, `$` 끝 범위를 한 스크립트에서 조합한다. "
        "새 문법은 기존 SEG의 합성일 뿐 각 SEG의 주소 범위를 넓히지 않는다.",
    },
    {
        "case_id": "s009-multi-range-dash-e-allowed",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n -e '1,5p;10p;20,$p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "허용된 단일 `-e` 표현식에서도 같은 합성 문법을 적용한다.",
    },
    {
        "case_id": "s009-multi-range-long-expression-allowed",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n --expression='1,5p;10,20p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "허용된 `--expression=` 스펠링도 단일 스크립트라는 기존 "
        "조건을 유지한 채 multi-range 를 받는다.",
    },
    {
        "case_id": "s009-multi-range-double-dash-allowed",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;10,20p' -- README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "trim",
        "expected_reason_code": None,
        "note": "`--` 뒤 파일 피연산자 처리와 multi-range 문법이 함께 유지된다.",
    },
    # --- 역방향 — 완화 표면에 인접하지만 여전히 거부(INV-A 대상) ---
    {
        "case_id": "fix-sed-inv-a-filter-role-with-file-denied",
        "fix": "FIX-SED",
        "command": "printf '%s\\n' ok | sed -n '1,80p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "filter 역할에 파일 피연산자가 있으면 여전히 거부된다 — stdin 과 "
        "파일을 동시에 요구하는 모순을 막는 기존 규칙은 이번 변경으로 전혀 "
        "움직이지 않는다.",
    },
    {
        "case_id": "fix-sed-inv-a-producer-file-less-denied",
        "fix": "FIX-SED",
        "command": "sed -n '1,80p' | head -5",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`files == 0 -> deny` 불변식(design §2.3, `_git_shortlog_is_safe` "
        "와 동일한 non-termination 방어) — 파일 없는 producer sed 는 훅이 "
        "물려준 stdin 을 읽어 600초 워치독까지 블록한다.",
    },
    {
        "case_id": "fix-sed-inv-a-in-place-plain-denied",
        "fix": "FIX-SED",
        "command": "sed -i '1p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-i` 는 파일을 변조한다 — 이 클래스의 유일한 파괴적 실패 모드. "
        "정확 토큰 허용목록 밖이라 즉시 거부된다.",
    },
    {
        "case_id": "fix-sed-inv-a-in-place-suffix-attached-denied",
        "fix": "FIX-SED",
        "command": "sed -i.bak '1p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "붙여쓴 백업 접미사(`-i.bak`)도 `-i` 로 시작하는 별도 토큰이라 "
        "정확 토큰 매칭에 걸려 거부된다.",
    },
    {
        "case_id": "fix-sed-inv-a-in-place-bsd-empty-suffix-denied",
        "fix": "FIX-SED",
        "command": "sed -i '' '1p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "BSD 형태(`-i ''`)도 `-i` 토큰 자체가 이미 거부 대상이라 뒤따르는 "
        "빈 인자와 무관하게 거부된다.",
    },
    {
        "case_id": "fix-sed-inv-a-permuted-in-place-after-operand-denied",
        "fix": "FIX-SED",
        "command": "sed -n '1,5p' -i README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "GNU sed 는 옵션을 순열(permute)한다 — 피연산자처럼 보이는 "
        "`'1,5p'` 뒤에 `-i` 가 와도 여전히 옵션이다(design §2.2 함정 2). "
        "접두부만 훑는 스캔이면 이 형태를 놓친다 — 전체 argv 스캔이 그 "
        "함정을 막는지 고정한다.",
    },
    {
        "case_id": "fix-sed-inv-a-long-in-place-denied",
        "fix": "FIX-SED",
        "command": "sed --in-place -n '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`--in-place` 롱 스펠링도 정확 토큰 허용목록 밖이라 거부된다.",
    },
    {
        "case_id": "fix-sed-inv-a-long-in-place-with-suffix-denied",
        "fix": "FIX-SED",
        "command": "sed --in-place=.bak -n '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`--in-place=` 값 붙임 형태도 동일하게 거부된다.",
    },
    {
        "case_id": "fix-sed-inv-a-cluster-ni-smuggles-in-place-denied",
        "fix": "FIX-SED",
        "command": "sed -ni '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "짧은 옵션 클러스터 `-ni` == `-n -i` — `-i` 를 밀반입한다(design "
        "§2.2 함정 3). 클러스터를 전부 거부하는 규칙이 이 형태를 막는지 "
        "고정한다.",
    },
    {
        "case_id": "fix-sed-inv-a-cluster-in-smuggles-in-place-denied",
        "fix": "FIX-SED",
        "command": "sed -in '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "순서를 뒤집은 클러스터(`-in` == `-i -n`)도 동일하게 거부된다.",
    },
    {
        "case_id": "fix-sed-inv-a-cluster-ne-false-deny",
        "fix": "FIX-SED",
        "command": "sed -ne '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-ne` 는 `-i` 를 밀반입하지 않는 무해한 클러스터지만, '클러스터는 "
        "전부 거부, 정확한 토큰만 허용'이라는 값싼 정답이 만드는 의도적인 "
        "false-deny 다(design §2.4).",
    },
    {
        "case_id": "fix-sed-inv-a-regex-address-denied",
        "fix": "FIX-SED",
        "command": "sed -n '/re/,/re/p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "정규식 주소는 숫자 범위 전용 `_SED_SCRIPT_RE` 를 통과하지 못한다 "
        "— 선택 범위가 무계(unbounded)일 수 있어 Tier-2 로 유보된다.",
    },
    {
        "case_id": "s009-empty-script-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "빈 스크립트는 SEG가 하나도 없으므로 거부된다.",
    },
    {
        "case_id": "s009-leading-semicolon-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n ';1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "선행 세미콜론은 첫 SEG가 비어 있으므로 거부된다.",
    },
    {
        "case_id": "s009-trailing-semicolon-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "후행 세미콜론은 마지막 SEG가 비어 있으므로 거부된다.",
    },
    {
        "case_id": "s009-double-semicolon-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;;10,20p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "연속 세미콜론 사이의 빈 SEG를 허용하지 않는다.",
    },
    {
        "case_id": "s009-write-command-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;w out.txt' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "명세의 필수 역방향 핀 — `w` 는 파일을 쓰므로 한 SEG가 "
        "안전해도 전체 스크립트를 거부해야 한다.",
    },
    {
        "case_id": "s009-write-first-line-command-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;W out.txt' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "GNU `W` 도 파일 쓰기 능력이므로 거부한다.",
    },
    {
        "case_id": "s009-execute-command-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;e id' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "GNU `e` 는 명령 실행 능력이므로 거부한다.",
    },
    {
        "case_id": "s009-read-file-command-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;r other.txt' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`r` 로 추가 파일을 읽는 스크립트는 predicate가 그 경로를 "
        "회계할 수 없으므로 거부한다.",
    },
    {
        "case_id": "s009-read-first-line-command-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;R other.txt' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "GNU `R` 도 추가 파일 읽기 능력이므로 거부한다.",
    },
    {
        "case_id": "s009-quit-command-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;q' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`q` 는 허용된 p-only SEG가 아니므로 거부한다.",
    },
    {
        "case_id": "s009-substitute-command-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;s/x/y/' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`s` 변환은 p-only 부분 읽기가 아니므로 거부한다.",
    },
    {
        "case_id": "s009-regex-address-segment-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;/re/p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "세그먼트 하나라도 정규식 주소면 숫자 전용 경계를 벗어난다.",
    },
    {
        "case_id": "s009-permuted-in-place-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;10,20p' -i README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "multi-range 뒤에 순열된 `-i` 도 전체 argv 옵션 스캔이 막는다.",
    },
    {
        "case_id": "s009-cluster-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -ne '1,5p;10,20p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "S009도 기존의 모든 짧은 옵션 클러스터 거부를 유지한다.",
    },
    {
        "case_id": "s009-multiple-script-options-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n -e '1,5p' -e '10,20p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "여러 `-e`를 조합하는 별도 문법은 여전히 범위 밖이다.",
    },
    {
        "case_id": "s009-fileless-producer-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;10,20p' | head -5",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "파일 없는 producer는 stdin을 상속해 블록할 수 있으므로 "
        "multi-range여도 거부한다.",
    },
    {
        "case_id": "s009-zero-address-segment-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;0p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "각 SEG는 기존의 1-based 숫자 주소를 그대로 사용한다.",
    },
    {
        "case_id": "s009-line-number-upper-bound-segment-denied",
        "fix": "S009-SED-MULTI-RANGE",
        "command": "sed -n '1,5p;10,1000001p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "한 SEG라도 `_valid_n` 상한을 넘으면 전체 스크립트를 거부한다.",
    },
    {
        "case_id": "fix-sed-inv-a-substitute-script-denied",
        "fix": "FIX-SED",
        "command": "sed -n 's/x/y/' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`s/x/y/` 는 출력이 입력과 거의 같은 '변환 옷을 입은 전체 파일 "
        "읽기'다 — 스크립트 정규식이 여전히 막는다.",
    },
    {
        "case_id": "fix-sed-inv-a-script-file-denied",
        "fix": "FIX-SED",
        "command": "sed -f script.sed -n '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-f` 는 predicate 가 볼 수 없는 파일에서 스크립트를 읽는다 — "
        "허용목록 밖 토큰이라 여전히 거부된다.",
    },
    # --- 변이 테스트로 드러난 감시 공백을 메우는 핀(추가 라운드) ---
    {
        "case_id": "fix-sed-inv-a-missing-dash-n-denied",
        "fix": "FIX-SED",
        "command": "sed '1,80p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-n` 없이는 매칭되지 않은 모든 줄도 그대로 출력된다(sed 의 실제 "
        "의미) — `quiet_seen` 요구가 정확히 한 번 검사되는지 고정한다. 변이 "
        "테스트에서 `quiet_seen` 체크를 완전히 생략하는 변이가 이 케이스 "
        "없이는 생존했다.",
    },
    {
        "case_id": "fix-sed-inv-a-write-command-suffix-denied",
        "fix": "FIX-SED",
        "command": "sed -n '1,80w' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "스크립트 마지막 글자가 `p` 대신 `w`(write) 면 `_SED_SCRIPT_RE` "
        "가 거부해야 한다 — 정규식을 `[pwer]` 로 느슨하게 하는 변이가 이 "
        "케이스 없이는 생존했다(스크립트 본문의 안전 경계가 진짜 안전 "
        "경계라는 주장을 직접 검사).",
    },
    {
        "case_id": "fix-sed-inv-a-permuted-attached-suffix-in-place-denied",
        "fix": "FIX-SED",
        "command": "sed -n '1,5p' -i.bak README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "GNU 순열 위치(피연산자처럼 보이는 스크립트 뒤)에 붙임 접미사형 "
        "`-i.bak` 이 와도 여전히 거부된다 — 기존 `-i.bak` 핀은 `-n` 이 없어 "
        "quiet_seen 검사에서 먼저 걸렸고, 이 케이스는 `-i` 접두 토큰 자체의 "
        "거부를 독립적으로 검사한다.",
    },
    {
        "case_id": "fix-sed-inv-a-double-quiet-denied",
        "fix": "FIX-SED",
        "command": "sed -n -n '1,80p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-n` 을 두 번 주면 거부된다(design §2.3 `quiet_seen` — 정확히 "
        "한 번). `-n` 이 이미 나온 뒤 또 나오면 즉시 거부하는 가드가 실제로 "
        "동작하는지 고정한다.",
    },
    {
        "case_id": "fix-sed-inv-a-multi-expression-denied",
        "fix": "FIX-SED",
        "command": "sed -n -e '1,40p' -e '41,80p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "다중 `-e` 스크립트는 범위 밖이다(design §2.3 — "
        "`len(expressions) > 1` 가드). 두 표현식이 각각은 유효한 범위라도 "
        "합쳐지면 거부되는지 고정한다.",
    },
    # --- 리뷰 라운드에서 드러난 감시 공백을 메우는 핀 ---
    # 공통 원인은 이 시리즈가 반복해 온 "능력이 아니라 철자로 고정"이다
    # (`grep` 리뷰의 `--colour=always`). 아래 세 묶음은 각각 변이 테스트에서
    # 생존한 변이를 하나씩 직접 사살한다.
    {
        "case_id": "fix-sed-inv-a-gnu-abbrev-in-place-denied",
        "fix": "FIX-SED",
        "command": "sed --i -n '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "GNU `getopt_long` 은 **모호하지 않은 접두사 축약**을 받는다. GNU "
        "sed 의 롱옵션 중 `i` 로 시작하는 것은 `--in-place` 하나뿐이므로 "
        "`--i` 는 모호하지 않고, 따라서 GNU sed 에서 `--i` 는 곧 "
        "`--in-place` 다 — 즉 파일 변조 능력이다. 철자 열거(`--in-place`, "
        "`--in-place=.bak`)만으로는 이 능력이 감시되지 않는다. 정확 토큰 "
        "표가 축약형까지 막는지 능력 단위로 고정한다.",
    },
    {
        "case_id": "fix-sed-inv-a-gnu-abbrev-mid-length-in-place-denied",
        "fix": "FIX-SED",
        "command": "sed --in-p -n '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "축약은 길이가 임의다 — `--in`, `--in-p`, `--in-plac` 이 전부 "
        "`--in-place` 로 해석된다. 중간 길이 축약도 같은 능력이므로 함께 "
        "고정한다(`--in-place` 접두사 매칭으로 우회 불가함을 보인다).",
    },
    {
        "case_id": "fix-sed-inv-a-long-in-place-separate-suffix-arg-denied",
        "fix": "FIX-SED",
        "command": "sed --in-place .bak -n '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "롱 형태의 접미사를 별도 인자로 분리한 형태다. `--in-place` 토큰 "
        "자체가 이미 거부되지만, 값 소비 분기가 새로 생겨도 이 형태가 "
        "열리지 않는지 독립적으로 고정한다.",
    },
    {
        "case_id": "fix-sed-inv-a-bsd-capital-i-in-place-denied",
        "fix": "FIX-SED",
        "command": "sed -I .bak -n '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "BSD/macOS sed 의 **대문자 `-I`** 도 제자리 편집이다(`-i` 와 달리 "
        "파일별 줄 번호를 리셋하지 않는다는 차이뿐, 파일을 쓴다는 능력은 "
        "동일하다). in-place 철자 열거에서 통째로 빠져 있었다 — `-i` 소문자 "
        "계열과 GNU 롱 스펠링만 세었기 때문이다. macOS `/usr/bin/sed` 로 "
        "실측했다: `sed -I .bak -n '1,5p' f` 는 `f` 를 덮어쓰고 `f.bak` 을 "
        "만든다. 정확 토큰 표가 이 능력도 막는지 고정한다.",
    },
    {
        "case_id": "fix-sed-inv-a-bsd-capital-i-attached-suffix-denied",
        "fix": "FIX-SED",
        "command": "sed -I.bak -n '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-I` 의 붙임 접미사 형태. 실측에서 `f` 를 덮어쓰고 `f.bak` 을 "
        "만든다 — `-i.bak` 과 동일한 능력의 대문자 짝이다.",
    },
    {
        "case_id": "fix-sed-inv-a-bsd-capital-i-empty-suffix-denied",
        "fix": "FIX-SED",
        "command": "sed -I '' -n '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-I ''`(백업 없는 BSD 형태)는 실측에서 백업조차 남기지 않고 `f` "
        "를 덮어쓴다 — 이 표면에서 가장 파괴적인 단일 형태다. `-i ''` 핀과 "
        "달리 이 행은 `-n` 을 포함하므로 quiet 검사가 아니라 **`-I` 토큰 "
        "자체의 거부**를 검사한다(PR 이 공개한 M11 과 같은 종의 함정을 "
        "피한다).",
    },
    {
        "case_id": "fix-sed-inv-a-separate-flag-denied",
        "fix": "FIX-SED",
        "command": "sed -s -n '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-s`(separate)는 파일을 쓰지는 않지만 정확 토큰 허용목록 밖이다. "
        "이 행은 **허용목록을 no-op 으로 넓히는 변이**를 잡는다 — `-s` 가 "
        "무시되면 `-n` 이 quiet 를 채워 이 명령이 통과한다.",
    },
    {
        "case_id": "fix-sed-inv-a-separate-flag-without-quiet-denied",
        "fix": "FIX-SED",
        "command": "sed -s '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "위 행과 **두 축의 교차**다. `-n` 을 뺀 형태는 허용목록을 "
        "`{-n, --quiet, --silent}` **집합에 얹어** 넓히는 변이(`-s` 가 "
        "quiet 자리를 대신 채우는 변이)를 잡는다. `-n` 이 붙은 형태만 "
        "있으면 그 변이에서 이 명령이 '중복 quiet' 라는 **엉뚱한 이유로** "
        "거부돼 변이가 살아남는다 — 실제로 리뷰 라운드에서 그렇게 "
        "생존했다(M11 과 같은 종). 두 행이 함께 있어야 감시가 성립한다.",
    },
    {
        "case_id": "fix-sed-inv-a-extended-regexp-flag-denied",
        "fix": "FIX-SED",
        "command": "sed -E -n '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-E`/`-r`(확장 정규식)도 허용목록 밖이다 — 스크립트 문법을 "
        "바꾸는 플래그를 받으면 `_SED_SCRIPT_RE` 가 검사하는 문법과 sed 가 "
        "실제로 해석하는 문법이 어긋난다.",
    },
    {
        "case_id": "fix-sed-inv-a-extended-regexp-flag-without-quiet-denied",
        "fix": "FIX-SED",
        "command": "sed -E '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-E` 에 대한 quiet 축 교차(위 `-s` 쌍과 동일한 이유).",
    },
    {
        "case_id": "fix-sed-inv-a-null-data-flag-denied",
        "fix": "FIX-SED",
        "command": "sed -z -n '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-z`(null-data)는 '줄'의 정의를 바꾼다 — `N,Mp` 가 뽑는 양이 "
        "무계가 되므로 범위 읽기라는 전제가 깨진다. 허용목록 밖임을 "
        "고정한다.",
    },
    {
        "case_id": "fix-sed-inv-a-null-data-flag-without-quiet-denied",
        "fix": "FIX-SED",
        "command": "sed -z '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-z` 에 대한 quiet 축 교차(위 `-s` 쌍과 동일한 이유).",
    },
    {
        "case_id": "fix-sed-inv-a-line-length-flag-denied",
        "fix": "FIX-SED",
        "command": "sed -n -l 80 '1,5p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`-l N` 은 값을 먹는 플래그다 — 값 소비 분기가 없으므로 토큰 "
        "단계에서 거부돼야 한다. 값 소비 분기를 새로 추가하는 변경이 "
        "스크립트 위치 계산을 어긋내지 않는지 감시한다.",
    },
    {
        "case_id": "fix-sed-inv-a-line-number-upper-bound-denied",
        "fix": "FIX-SED",
        "command": "sed -n '1,1000001p' README.md",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "`_valid_n` 의 상한(1..1_000_000)이 실제로 검사되는지 고정한다. "
        "이 검사는 옛 `_sed_is_safe` 에서 그대로 옮겨왔지만 어느 테스트도 "
        "그 경계를 밟지 않았다 — `_valid_n` 루프를 통째로 삭제하는 변이가 "
        "이 핀 없이는 생존했다(범위가 없는 검사, 이 저장소의 반복 실패 "
        "유형).",
    },
]


def sed_route_predicate_relaxations() -> list[RoutePredicateCase]:
    """INV-B 가 실제로 전환을 검사해야 하는 행(완화 대상)만 골라낸다."""
    return [
        case
        for case in FIX_SED_ROUTE_PREDICATE_CASES
        if case.get("expected_decision") != "deny"
    ]


def sed_relaxation_case_count() -> int:
    """FIX-SED 완화 대상(deny -> trim) 행 수를 고정한다 — 루프 공허 통과 방지."""
    return len(sed_route_predicate_relaxations())


def sed_stay_denied_case_count() -> int:
    """FIX-SED 거부 보존(INV-A) 행 수를 고정한다 — 루프 공허 통과 방지."""
    return sum(
        1
        for case in FIX_SED_ROUTE_PREDICATE_CASES
        if case["expected_decision"] == "deny"
    )


def s009_sed_multi_range_cases() -> list[RoutePredicateCase]:
    """S009가 추가한 multi-range 허용/거부 표면만 반환한다."""
    return [
        case
        for case in FIX_SED_ROUTE_PREDICATE_CASES
        if case["fix"] == "S009-SED-MULTI-RANGE"
    ]


def s009_sed_multi_range_relaxations() -> list[RoutePredicateCase]:
    """S009의 deny -> trim 전환만 반환한다."""
    return [
        case
        for case in s009_sed_multi_range_cases()
        if case["expected_decision"] != "deny"
    ]


def s009_sed_multi_range_stay_denied() -> list[RoutePredicateCase]:
    """S009 인접 표면에서 계속 거부되어야 하는 케이스만 반환한다."""
    return [
        case
        for case in s009_sed_multi_range_cases()
        if case["expected_decision"] == "deny"
    ]


# ---------------------------------------------------------------------------
# FIX-6 — `git remote`/`git remote -v` 를 §6.1b 쌍 화이트리스트에 재도입한다
# (11행 -> 12행). FIX-1a/1b 와 동일하게 deny -> allow(sanitize) 전환이므로
# INV-A/INV-B 하네스로 검증한다(FIX-1a 의 케이스 shape 를 그대로 따른다).
#
# 전제 — remote 행은 FIX-1b 당시 R-13(구조적으로 리댁션 불가능)을 이유로
# 삭제됐었다(`fix1b-ac1-4-remote-add`의 옛 note 참고). 그 전제가 이제 거짓이다:
# `git remote -v`가 위험했던 건 행 자체가 아니라 credential_policy.py:108의
# 정규식이 `user:pass@` 두 파트를 모두 요구해 콜론 없는 토큰 전용 URL(가장 흔한
# PAT 임베딩 형태)을 통과시켰기 때문이다. FIX-6 커밋 1(사전 조건)이 그 정규식을
# 넓혔고(비밀번호 파트 선택적), 이 커밋(2)이 그 하드닝을 전제로 행을 재도입한다.
# `add`/`remove`/`rename`/`set-url`/`get-url` 등 위치 인자가 있는 서브서브커맨드는
# branch/tag와 동일한 0-arity 엄격 규칙으로 여전히 거부된다 — `remote add`는
# 이미 FIX1B_ROUTE_PREDICATE_CASES 의 `fix1b-ac1-4-remote-add`에 고정돼 있으므로
# (AC-1.4, 위 섹션) 여기서는 나머지 쓰기 서브서브커맨드로 커버리지를 넓힌다.
# ---------------------------------------------------------------------------
FIX6_ROUTE_PREDICATE_CASES: list[RoutePredicateCase] = [
    # --- 완화 — deny -> sanitize 전환(INV-B 대상), 재도입된 remote 행 ---
    {
        "case_id": "fix6-relax-remote-bare",
        "fix": "FIX-6",
        "command": "git remote",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "remote 행 재도입 — 위치 인자 0개 조건으로 조회(원격 이름 나열)만 "
        "허용한다. 이 형태는 URL 을 출력하지 않아 credential_policy.py 하드닝과도 "
        "무관하게 이미 안전했다.",
    },
    {
        "case_id": "fix6-relax-remote-verbose",
        "fix": "FIX-6",
        "command": "git remote -v",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "핵심 완화 — URL 을 노출하는 유일한 조회 형태. 이 행이 FIX-6 커밋 1보다 "
        "먼저 재도입됐다면 콜론 없는 토큰 전용 URL 이 그대로 노출됐을 것이다 — 두 "
        "커밋의 순서(하드닝 먼저)가 바로 이 케이스를 안전하게 만드는 이유다.",
    },
    {
        "case_id": "fix6-relax-remote-verbose-long",
        "fix": "FIX-6",
        "command": "git remote --verbose",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "장옵션 형태도 `_GIT_REMOTE_LONG_FLAGS` 로 동일하게 허용된다.",
    },
    # --- 역방향 케이스(INV-A 대상) — 위치 인자가 있는 쓰기 서브서브커맨드는
    # remote 행 재도입 이후에도 여전히 거부된다 ---
    {
        "case_id": "fix6-inv-a-remote-add-still-denied",
        "fix": "FIX-6",
        "command": "git remote add origin https://example.invalid/repo.git",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "AC-1.4 에 이미 고정된 fix1b-ac1-4-remote-add 와 동일한 사실을 FIX-6 "
        "관점에서 재확인한다 — 위치 인자(add/origin/url)가 있어 0-arity 엄격 조건을 "
        "위반해 여전히 거부된다.",
    },
    {
        "case_id": "fix6-inv-a-remote-remove-still-denied",
        "fix": "FIX-6",
        "command": "git remote remove origin",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "역방향 — remove 도 위치 인자가 있어 여전히 거부된다.",
    },
    {
        "case_id": "fix6-inv-a-remote-rename-still-denied",
        "fix": "FIX-6",
        "command": "git remote rename origin upstream",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "역방향 — rename 도 위치 인자가 있어 여전히 거부된다.",
    },
    {
        "case_id": "fix6-inv-a-remote-set-url-still-denied",
        "fix": "FIX-6",
        "command": "git remote set-url origin https://example.invalid/repo.git",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "역방향 — set-url 은 원격 URL 을 자격증명째로 재지정할 수 있는 쓰기 "
        "형태다. 위치 인자가 있어 여전히 거부된다.",
    },
    {
        "case_id": "fix6-inv-a-remote-get-url-unlisted-subcommand",
        "fix": "FIX-6",
        "command": "git remote get-url origin",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "미등재 인접 서브서브커맨드 — get-url 도 위치 인자(get-url/origin)가 있어 "
        "`-v`/`--verbose`만 허용하는 표에 없어 거부된다.",
    },
    {
        "case_id": "fix6-inv-a-remote-no-pager-bypass-denied",
        "fix": "FIX-6",
        "command": "git --no-pager remote -v",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "R-5 전역 옵션 우회 음성 — argv[1]='--no-pager' 라 서브커맨드로 인정되지 "
        "않아 remote 행 신설과 무관하게 여전히 거부된다(AC-1b.2 와 동일 계열).",
    },
    {
        "case_id": "fix6-inv-a-remote-verbose-extra-positional-denied",
        "fix": "FIX-6",
        "command": "git remote -v origin",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "deny",
        "expected_reason_code": "route_policy_denied",
        "note": "역방향 — `-v` 뒤에 위치 인자(origin)가 남으면 0-arity 엄격 조건을 "
        "위반해 거부된다(`git remote -v <name>`은 유효한 git 문법도 아니다).",
    },
]


def fix6_route_predicate_relaxations() -> list[RoutePredicateCase]:
    """INV-B 가 실제로 전환을 검사해야 하는 행(완화 대상)만 골라낸다."""
    return [
        case
        for case in FIX6_ROUTE_PREDICATE_CASES
        if case.get("expected_decision") != "deny"
    ]
