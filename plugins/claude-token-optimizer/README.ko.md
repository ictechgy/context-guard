# claude-token-optimizer

Claude Code의 토큰 사용량을 줄이는 플러그인입니다. 설정 마법사, 사용량 감사, 설정/context 스캔, 대용량 Read guard, 출력 trim/sanitize, 선택적 Gemini/Codex 보조 AI 위임 기능을 제공합니다.

## Skills

설치 후 Claude Code 안에서 다음 skill을 사용할 수 있습니다.

```text
/claude-token-optimizer:setup
/claude-token-optimizer:optimize
/claude-token-optimizer:audit
/claude-token-optimizer:delegate
```

가장 먼저 `/claude-token-optimizer:setup`을 실행하는 것을 권장합니다.

## Helper commands와 PATH 주의사항

플러그인은 `bin/` 아래 helper 실행 파일들을 포함합니다. Claude Code skill은 이 helper를 호출할 수 있지만, 일반 shell의 `PATH`에 plugin `bin/`이 자동으로 추가된다고 보장할 수 없습니다.

명령어를 찾을 수 없다고 나오면 이 저장소 루트에서 경로를 직접 명시하세요.

```bash
./plugins/claude-token-optimizer/bin/claude-token-setup --plan
```

개발 중 짧은 명령으로 실행하고 싶다면 현재 shell에만 `PATH`를 추가하세요.

```bash
export PATH="$PWD/plugins/claude-token-optimizer/bin:$PATH"
claude-token-setup --plan
```

`PATH`가 설정된 경우 사용할 수 있는 주요 명령은 다음과 같습니다.

```bash
claude-token-audit ~/.claude/projects --top 20 --recommend
claude-token-setup
claude-token-diet scan . --json
claude-trim-output --max-lines 120 -- npm test
claude-read-symbol path/to/file.py TargetSymbol
claude-sanitize-output -- rg -n "TOKEN|SECRET" .
claude-sanitize-output -- git diff
claude-token-guard-read
claude-token-statusline
claude-token-rewrite-bash
claude-token-delegate status
claude-token-delegate enable --provider gemini
claude-token-delegate ask --provider gemini --prompt "Summarize this log" --context ./log.txt
claude-token-delegate disable
```

## Setup wizard

`claude-token-setup`은 설치 후 설정 마법사입니다. Claude Code 안에서는 `/claude-token-optimizer:setup`을 선호하세요.

일반 터미널에서 로컬 테스트하려면:

```bash
./plugins/claude-token-optimizer/bin/claude-token-setup --plan
./plugins/claude-token-optimizer/bin/claude-token-setup --yes
```

마법사는 `.claude/settings.json`을 덮어쓰지 않고 병합합니다. Gemini/Codex 수동 보조 AI delegation은 `--aux-provider gemini|codex`처럼 명시적으로 선택할 때만 켜지고, 자동 위임은 `--auto-delegate`를 함께 지정할 때만 해당 provider에 대해 켜집니다. `--aux-provider`만으로 setup을 다시 실행하면 이전 자동 위임 동의 상태는 해제됩니다.

## 주요 기능

### 사용량 감사

```bash
./plugins/claude-token-optimizer/bin/claude-token-audit ~/.claude/projects --top 20 --recommend
```

기본 출력은 공유 안전성을 위해 transcript 경로와 command string을 익명화합니다. 로컬 비공개 디버깅에서만 `--show-paths`, `--show-commands`를 사용하세요.

JSON 출력은 `cache_metrics` 블록(`cache_hit_rate`, `cache_amortization`, 원본 cache_read/cache_creation/input 토큰)을 포함합니다. prompt cache가 write 비용을 회수하고 있는지 한눈에 보기 위한 것입니다. `improve-prompt-cache-reuse` 권장 사항은 amortization(`cache_read / cache_creation`)이 1.0 미만이고 cache write가 충분히 큰 경우에 발생하며, `evaluate-1h-ttl-cache`는 write는 크지만 재사용이 보통 수준일 때 — 즉 기본 5분 TTL보다 1h TTL 베타가 amortize에 유리한 구간을 가리킬 때 — 발생합니다.

### 설정/컨텍스트 스캔

```bash
./plugins/claude-token-optimizer/bin/claude-token-diet scan . --json
```

`permissions.deny`, Bash trim hook, statusline, broad read allow, 비싼 model/effort defaults, 많은 MCP server, 큰 `CLAUDE.md`/`AGENTS.md`, secret-like context를 점검합니다. 기본 출력은 project root를 익명화하며, 로컬 비공개 보고서에서만 `--show-paths`를 사용하세요.

### 대용량 Read guard와 symbol 읽기

`claude-token-guard-read`는 opt-in `PreToolUse` Read hook입니다. 큰 파일 전체를 Claude context에 넣기 전에 `rg -n`과 `claude-read-symbol`을 사용하도록 안내합니다.

`claude-token-statusline`은 project settings로 활성화했을 때 token/cost/model 정보를 짧은 statusline으로 출력합니다. Claude Code statusline payload에 읽기 가능한 `transcript_path`가 포함되면 `cache <N>%`도 함께 표시됩니다 — 이는 transcript 끝부분에서 계산한 cache_read 비중입니다. transcript가 없거나 읽을 수 없거나 `python3`가 없으면 cache 라벨만 빠지고 나머지 statusline은 그대로 동작합니다.

`claude-token-rewrite-bash`는 예시 settings에서 사용하는 opt-in `PreToolUse` Bash hook입니다. 안전한 단일 test/build/lint 명령은 `claude-trim-output`으로, 안전한 단일 `rg`/`grep`/`git diff` 계열 명령은 `claude-sanitize-output`으로 감쌉니다.

```bash
./plugins/claude-token-optimizer/bin/claude-read-symbol path/to/file.py TargetSymbol
```

### 긴 output 축약

```bash
./plugins/claude-token-optimizer/bin/claude-trim-output --max-lines 120 -- npm test
```

감싼 명령의 exit code를 보존하며, pytest/Jest/Vitest/Go/Rust test 실패 요약을 우선 보존합니다. ANSI color code는 제거하고 absolute path는 기본적으로 익명화합니다.

### grep/diff sanitizer

```bash
./plugins/claude-token-optimizer/bin/claude-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/claude-token-optimizer/bin/claude-sanitize-output -- git diff
```

credential pattern, private key block, auth header, credential URL을 redact하고, 긴 결과는 head / grep·diff·security anchor / tail로 줄입니다. Wrapper mode는 감싼 명령의 exit code를 그대로 보존합니다. Stdin pipe mode는 임시 정리에 쓸 수 있지만 producer exit code는 shell `pipefail` 없이는 알 수 없습니다.

## 로컬 배포 테스트

Marketplace 저장소 루트에서:

```bash
claude --plugin-dir ./plugins/claude-token-optimizer
```

Claude Code 안에서:

```text
/claude-token-optimizer:setup
```

Marketplace 설치 테스트:

```text
/plugin marketplace add ./
/plugin install claude-token-optimizer@claude-token-tools
```

## 보조 AI delegation

`claude-token-delegate`는 Gemini CLI나 Codex CLI 같은 별도 AI CLI를 read-only 분석 비서로 쓰는 opt-in 기능입니다. 기본값은 OFF이고, `.claude-token-optimizer/` 아래에 project-local 상태를 저장합니다.

```bash
./plugins/claude-token-optimizer/bin/claude-token-delegate status
./plugins/claude-token-optimizer/bin/claude-token-delegate enable --provider gemini
./plugins/claude-token-optimizer/bin/claude-token-delegate enable --provider codex
./plugins/claude-token-optimizer/bin/claude-token-delegate auto-enable
./plugins/claude-token-optimizer/bin/claude-token-delegate ask --provider codex --prompt "Find likely files to inspect" --context ./error.log
./plugins/claude-token-optimizer/bin/claude-token-delegate disable
```

외부 provider와 공유해도 되는 context만 위임하세요. helper는 Claude에 요약된 preview만 출력하고, 전체 보조 AI 응답은 untrusted 상태로 로컬에 저장합니다.

자동 위임은 수동 delegation과 분리된 provider별 opt-in 기능입니다. 수동 delegation을 켠 뒤, plugin skill이 non-sensitive project-local source/log context를 현재/default provider와 공유해도 되는 경우에만 `claude-token-delegate auto-enable`을 실행하세요. 자동 호출은 `--auto`를 사용하되 `--provider`는 생략해 helper가 승인된 provider만 쓰게 합니다. `--context`는 helper가 검증한 파일만 사용하고, `--prompt`에는 짧은 read-only 지시만 넣으세요. blocked/sensitive/customer/policy-prohibited data를 피하고, 보조 AI 출력은 검증한 뒤 사용해야 합니다.

Delegation은 기본적으로 project root 아래 context file만 허용하며, outside-project path, secret-like path, credential-like content를 차단합니다. 정책 검토 후 필요한 경우 trusted private config의 `context_policy`에 exact path만 허용하세요. CLI flag로 차단을 우회할 수 없습니다.

저장된 보조 AI 응답은 `.claude-token-optimizer/` 아래에서 제한된 파일 권한과 `.gitignore`로 보호됩니다. Provider CLI는 자격 증명 노출을 줄이기 위해 sanitized environment와 격리된 `HOME`/XDG/TMP 디렉터리에서 실행됩니다. 따라서 기존 홈 디렉터리 OAuth 상태가 자동으로 보이지 않을 수 있으며, API key 기반 인증이나 검토된 custom provider 설정이 필요할 수 있습니다.

## 라이선스

Copyright 2026 jinhongan. Apache License 2.0으로 배포됩니다. [LICENSE](LICENSE)와 [NOTICE](NOTICE)를 참고하세요.
