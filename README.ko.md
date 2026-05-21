# claude-token-tools

Claude Code 세션에서 토큰 사용량을 줄이고, 컨텍스트를 집중된 상태로 유지하며, 크거나 민감한 출력이 Claude에 그대로 전달되는 일을 방지하는 Claude Code 플러그인과 헬퍼 도구 모음입니다.

영문 문서: [`README.md`](README.md)

## 한눈에 보기

플러그인을 설치하고 프로젝트에서 `/claude-token-optimizer:setup`을 실행하면, Claude가 잡음 많은 출력을 자동으로 압축하고, 대용량 파일 전체 읽기를 막으며, 민감한 값을 redact합니다 — 전역 설정은 건드리지 않습니다. Gemini나 Codex CLI를 갖고 있다면 읽기 전용 작업을 위임해 토큰을 추가로 절약할 수 있습니다.

## 제공 기능

- **Claude Code 플러그인** — 가이드 설정, 최적화, 사용량 감사, 선택적 보조 AI 위임을 위한 설치형 스킬을 제공합니다.
- **프로젝트 설정 마법사** — 전역 Claude 설정은 건드리지 않고 권장 `.claude/settings.json` 옵션을 프로젝트에 적용합니다.
- **컨텍스트 위생 스캐너** — 누락된 가드레일, 불필요한 출력을 유발하는 훅, 비용이 큰 기본값, 광범위한 읽기, 과도한 MCP 서버, 크거나 민감한 컨텍스트 파일을 진단합니다.
- **대용량 읽기 가드와 심볼 리더** — 파일 전체 읽기 대신 `rg`와 심볼·줄 범위 읽기를 사용하도록 안내합니다.
- **출력 압축 및 정제** — 테스트·빌드·검색·diff 출력을 줄이고, Claude에 전달하기 전에 민감한 값을 제거합니다.
- **상태표시줄과 트랜스크립트 감사 헬퍼** — 토큰·비용·모델 상태와 토큰 사용량 집중 지점을 확인합니다.
- **선택적 보조 AI 위임** — Gemini CLI나 Codex CLI가 안전한 읽기 전용 컨텍스트를 요약하고, Claude에는 제한된 미리보기만 전달합니다.

## Claude Code에서 설치

마켓플레이스를 추가하고 플러그인을 설치합니다.

```text
/plugin marketplace add ictechgy/claude-token-tools
/plugin install claude-token-optimizer@claude-token-tools
```

설치 후 Claude Code 안에서 설정 마법사를 실행합니다.

```text
/claude-token-optimizer:setup
```

사용 가능한 스킬:

```text
/claude-token-optimizer:setup
/claude-token-optimizer:optimize
/claude-token-optimizer:audit
/claude-token-optimizer:delegate
```

플러그인은 설치만으로 전역 훅을 자동 활성화하지 않습니다. 설정은 프로젝트 단위이며 사용자가 명시적으로 적용해야 합니다. 예시는 `plugins/claude-token-optimizer/examples/settings.example.json`을 참고하세요.

## 저장소에서 로컬 테스트

플러그인 디렉터리를 지정해 Claude Code를 실행합니다.

```bash
claude --plugin-dir ./plugins/claude-token-optimizer
```

저장소 루트에서 마켓플레이스 설치를 테스트합니다.

```text
/plugin marketplace add ./
/plugin install claude-token-optimizer@claude-token-tools
```

플러그인 헬퍼 바이너리는 기본적으로 셸 `PATH`에 포함되지 않습니다. 로컬 테스트 시 경로를 직접 지정하세요.

```bash
./plugins/claude-token-optimizer/bin/claude-token-setup --plan
./plugins/claude-token-optimizer/bin/claude-token-setup --yes
```

개발 중 짧은 명령으로 실행하려면 플러그인 bin 경로를 현재 셸에 추가하세요.

```bash
export PATH="$PWD/plugins/claude-token-optimizer/bin:$PATH"
claude-token-setup --plan
```

## 자주 쓰는 헬퍼 명령

프로젝트 컨텍스트 위생 검사:

```bash
./plugins/claude-token-optimizer/bin/claude-token-diet scan .
```

대용량 파일 전체 대신 심볼 단위로 읽기:

```bash
./plugins/claude-token-optimizer/bin/claude-read-symbol path/to/file.py TargetSymbol
```

긴 테스트·빌드 로그를 줄이면서 원래 명령의 종료 코드 보존:

```bash
./plugins/claude-token-optimizer/bin/claude-trim-output --max-lines 120 -- npm test
```

Claude에 전달하기 전에 검색·diff 출력 정제:

```bash
./plugins/claude-token-optimizer/bin/claude-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/claude-token-optimizer/bin/claude-sanitize-output -- git diff
```

로컬 Claude 트랜스크립트 사용량 감사:

```bash
./plugins/claude-token-optimizer/bin/claude-token-audit ~/.claude/projects --top 20 --recommend
```

## 보조 AI 위임 (선택 기능)

Gemini CLI나 Codex CLI가 있다면, 광범위한 파일 분류, 긴 로그 요약, 원인 가설 생성, 플래닝 검토 같은 읽기 전용 작업을 외부 AI CLI에 맡길 수 있습니다.

```text
/claude-token-optimizer:delegate enable --provider gemini
/claude-token-optimizer:delegate auto-enable
/claude-token-optimizer:delegate ask --provider gemini --prompt "Summarize this failing test log" --context ./log.txt
/claude-token-optimizer:delegate disable
```

수동 위임은 **기본 비활성화** 상태이며, 프로젝트 로컬 상태를 `.claude-token-optimizer/` 아래에 저장합니다. 자동 위임은 공급자별로 별도 opt-in이 필요합니다. 외부 공급자와 공유해도 되는 컨텍스트만 위임하세요 — 시크릿, 고객 데이터, 정책상 금지된 내용은 위임하지 마세요. 보조 AI 출력은 검증 전까지 신뢰하지 마세요.

## 저장소 구조

- `.claude-plugin/marketplace.json` — Claude Code 마켓플레이스 매니페스트
- `plugins/claude-token-optimizer/` — 설치형 Claude Code 플러그인 패키지
- `claude-token-kit/` — 기반 Python/Bash 헬퍼 도구
- `tests/` — 헬퍼 동작 검증을 위한 회귀 테스트

## 릴리스 확인

릴리스에 민감한 변경을 배포하거나 머지하기 전에는 두 게이트를 모두 실행하세요:

```bash
python3 scripts/prepublish_check.py
python3 scripts/release_smoke.py
```

`prepublish_check.py`는 패키지 불변식, 동기화된 플러그인 바이너리, 매니페스트, 회귀 테스트를 확인합니다. `release_smoke.py`는 임시 프로젝트에서 `plugins/claude-token-optimizer/bin`의 대표 패키징 엔트리포인트를 실제 실행해, 배포 전 깨진 CLI 연결을 잡습니다.

## 라이선스

Copyright 2026 jinhongan. Apache License 2.0으로 배포됩니다. 자세한 내용은 [LICENSE](LICENSE)와 [NOTICE](NOTICE)를 참고하세요.
