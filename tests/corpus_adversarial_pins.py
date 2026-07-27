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
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "경로 한정 `env` 도 basename 으로 인식되므로 동일하게 막혀야 한다.",
    },
    {
        "case_id": "fix5-bypass-env-path-qualified-quoted",
        "fix": "FIX-5",
        "command": "/usr/bin/env -- 'GIT_PAGER'=/tmp/evil.sh git diff",
        "expected_decision": "deny",
        "expected_reason_code": "unsafe_env_name_denied",
        "note": "경로 한정 + `--` + 인용 피연산자 조합.",
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
        "note": "remote 행은 표에서 삭제됨(R-13) — FIX-6 완료 후 재도입 심사 대상.",
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
        "command": "git shortlog -sn",
        "baseline_reason_code": "route_policy_denied",
        "expected_decision": "sanitize",
        "expected_reason_code": None,
        "note": "shortlog 행 신설 — AC-1.9 묶음 단축 플래그(-sn -> {s,n}) 검증 겸용.",
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
