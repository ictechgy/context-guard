# ContextGuard

ContextGuard는 AI 코딩·도구 에이전트를 위한 로컬 우선 컨텍스트 관리 도구 모음입니다. Claude Code 플러그인으로 먼저 시작할 수 있으며, 한 번 설치한 뒤 프로젝트별로 명시적으로 활성화하고 필요하면 되돌릴 수 있습니다. 출력 축약, 심볼 단위 읽기 유도, 반복 실패 알림, 민감정보 패턴 가림, 사용량 측정 가드레일은 로컬 헬퍼 명령과 brief 모드 안내 스니펫을 통해 다른 에이전트에서도 재사용할 수 있습니다.

- 영문 문서: [`README.md`](README.md)
- HTML 랜딩 페이지: [GitHub Pages](https://ictechgy.github.io/context-guard/) ([소스](docs/index.html))

## 빠른 시작

```bash
/plugin marketplace add ictechgy/context-guard && /plugin install context-guard@context-guard   # Claude Code
/context-guard:setup          # applies the recommended project-local hooks after showing a plan
/context-guard:audit          # shows where your tokens went, by tool and per turn
```

npm 사용자는 `npx @ictechgy/context-guard setup --profile recommended --plan`을 실행한 뒤 `--yes`로 적용하세요.

## 해결하는 세 가지 문제

**빌드나 테스트가 수천 줄을 대화에 쏟아붓는 경우.** 기본 Bash 래퍼가 가림 처리한
출력을 로컬 보관본에 넣고 대화에는 짧은 요약 기록만 남깁니다. 필요한 범위만 다시
꺼내면 됩니다.

```bash
context-guard-artifact get <id> --lines a:b
```

**토큰이 어디로 갔는지 모르는 경우.** 감사 명령은 로컬 Claude 대화 기록을 읽어
턴별 신규 토큰과 그 턴 직전에 쓰인 도구를 함께 보고하고, 결과 바이트가 어느 도구·
콘텐츠 유형·파일 확장자에서 왔는지도 보여줍니다.

```bash
context-guard-audit ~/.claude/projects --recommend
```

이는 절감 주장이 아니라 관측입니다. 바이트와 신규 토큰이 어디에 쌓였는지를 말할
뿐, 그것을 줄이면 얼마를 회수한다는 뜻은 아닙니다.

**에이전트가 함수 하나 때문에 큰 파일 전체를 읽는 경우.** 선택형 Read 가드는
검색 → 심볼 구간 → 작은 줄 범위 순서로 유도하고, 심볼 리더가 해당 구간만 바로
반환합니다.

```bash
context-guard-read-symbol path/to/file.py TargetSymbol
```

적용 범위는 의도적으로 Claude Code `PreToolUse`의 `Read` matcher 훅으로 한정됩니다.

| Claude 도구 | 보호 범위 |
| --- | --- |
| `Read` | 제한된 대용량 파일 범위를 검사하고, basename이 `.env`로 시작하면 차단합니다. 단, 정확히 `.env.example`, `.env.sample`, `.env.template`인 템플릿 이름은 허용합니다. 중첩 경로도 포함하며 symlink 여부가 모호하면 닫힌 상태로 실패합니다. |
| `Glob` | 일치하는 이름을 나열할 수 있습니다. 이 `Read` 훅을 통해 파일 내용을 읽지는 않습니다. |
| `Grep` | 이 훅의 범위 밖이며 일치하는 파일 내용을 읽을 수 있습니다. |
| `Bash` | 이 훅의 범위 밖이며 파일 내용을 읽을 수 있습니다. |

이는 Claude `Read` 보호이지 범용 `.env` 보호나 Bash 보호가 아닙니다. 훅은 symlink를 따라가지 않고 직접 연 파일 descriptor의 상태를 다시 검증하지만, 실제 Claude `Read`는 훅이 반환된 뒤 파일을 다시 엽니다. 그 사이 파일이 교체될 수 있는 post-hook 구간은 문서화된 TOCTOU 한계입니다.

## 설치

설치와 활성화는 의도적으로 분리되어 있습니다. 설치만 하면 로컬 헬퍼나 Claude 플러그인 스킬이 준비될 뿐이며, 설정 파일은 사용자가 `setup`을 명시적으로 실행할 때만 기록됩니다.

| 쓰는 도구 | 설치 | 활성화 |
| --- | --- | --- |
| Claude Code | `/plugin marketplace add ictechgy/context-guard` 후 `/plugin install context-guard@context-guard` | 프로젝트에서 `/context-guard:setup` 실행 |
| npm·npx 또는 터미널 기반 에이전트 | `npm install -g @ictechgy/context-guard` 또는 일회성 `npx @ictechgy/context-guard ...` | `context-guard setup --agent codex --scope project --with-init --with-skill --with-mcp --plan` 확인 후 `--yes`로 적용 |

`context-guard setup --profile recommended --plan`으로 권장 프로파일을 미리 보고
`--yes`로 적용합니다. 적용 전에는 `context-guard setup --verify`로 읽기 전용
상태를 먼저 확인하세요. `context-guard doctor`는 이 명령의 별칭입니다. Homebrew
경로, 사용자 단위 설정, 에이전트별 연동 표는 [docs/guide.md](docs/guide.md)에,
생성된 플래그 참조는 [docs/setup-reference.md](docs/setup-reference.md)에 있습니다.

## 먼저 audit 부터 실행하기

무엇이든 켜기 전에 감사부터 실행하세요. 가드레일도 실행 비용이 들고 모든
프로젝트에서 이득이 되지는 않으므로, 자신의 작업량을 먼저 측정해야 합니다.

```bash
context-guard-audit ~/.claude/projects --top 20 --recommend
```

설치 후에는 `context-guard doctor --root . --json`으로 설치된 훅 기록과 설정을
바꾸지 않고 다시 점검할 수 있습니다. 감사가 보고하는 바이트 수치는 절감이 아니라
관측값입니다.

## 나머지 문서 위치

- [docs/guide.md](docs/guide.md) — 모든 헬퍼 명령, brief 모드, 조용한 진행 설명, 에이전트별 연동, 벤치마크 실행기, 로컬 MCP 어댑터, 선택적 `bash_reference_v1`, Receipt 동반 패키지. `--explain`, `--adaptive-k-policy`, `--apply-adaptive-k`, `--apply-symbol-memory` 같은 pack 옵션도 여기 있습니다.
- [docs/safety-reference.md](docs/safety-reference.md) — 신뢰 경계, `PATH` 헬퍼 정책, ContextGuard가 하지 않는 일, 안내용 규칙 블록의 상시 비용·손익분기 표, Read 가드의 TOCTOU 한계, 절감 주장 문구 규칙.
- [docs/builtin-overlap.md](docs/builtin-overlap.md) — Claude Code 내장 기능과 기능별로 겹침/보완/내장 없음을 비교한 표.
- [docs/experiments.md](docs/experiments.md) — 기본 비활성 실험 lane과 그 gate.
- [docs/setup-reference.md](docs/setup-reference.md) — 생성된 setup 기능·플래그 참조.
- [docs/release-runbook.md](docs/release-runbook.md) — 릴리스 절차, 증거 체크리스트, 롤백 체크리스트.
- [`docs/experimental-benchmark-fixtures.md`](docs/experimental-benchmark-fixtures.md) — fixture-only 실험 시작 예시. 절감 주장을 하려면 같은 matched-task benchmark gate를 먼저 통과해야 합니다.

## 실험 기능

모든 실험 planner는 기본 비활성이고 plan 전용이며, 자세한 내용은 [`docs/experiments.md`](docs/experiments.md)에 있습니다. 이 lane들은 later-roadmap gate와 provider가 측정한 matched-task 근거를 통과하기 전까지 experimental/non-shipped이며 제공 기능이 아닙니다. 더 넓은 연구 lane은 [`research/experimental-token-reduction-radar.md`](research/experimental-token-reduction-radar.md)에서 추적합니다. ContextGuard는 고정된 토큰·비용 절감률을 보장하지 않으며, 주장 경계는 [docs/safety-reference.md](docs/safety-reference.md)에 있습니다.

## 라이선스

Copyright 2026 jinhongan. Apache License 2.0으로 배포됩니다. 자세한 내용은 [LICENSE](LICENSE)와 [NOTICE](NOTICE)를 참고하세요.
