# Claude Code Token Reduction Research

조사일: 2026-05-01

이 폴더는 Claude Code CLI의 토큰 사용량을 줄이기 위한 리서치/실험 워크스페이스입니다.

## 산출물

- `research/claude-code-token-reduction.md` — 핵심 리서치 보고서와 우선순위별 실행안
- `research/benchmark-plan.md` — 절감 효과를 검증하기 위한 벤치마크 설계
- `claude-token-kit/` — 바로 적용/변형 가능한 상태바, 출력 절단 훅, transcript 감사/설정 스캔 스크립트

## 5분 적용 요약

1. Claude Code 안에서 `/usage`, `/context`, `/model`, `/effort`를 먼저 확인한다.
2. 서로 다른 작업으로 넘어갈 때는 `/clear`; 긴 작업은 `/compact <보존할 내용>`로 요약한다.
3. 기본은 `sonnet`, 설계만 `opusplan`, 단순 작업은 낮은 `/effort`를 쓴다.
4. `CLAUDE.md`는 핵심만 남기고, 긴 워크플로 지침은 skills/custom commands로 분리한다.
5. MCP 서버를 최소화하고, `gh`, `rg`, `jq`, `aws`, `gcloud` 같은 CLI를 우선 사용한다.
6. 테스트/빌드 로그는 훅이나 wrapper로 실패 주변만 Claude에게 돌려준다.
7. subagent는 noisy research/log 분석 격리에 쓰되, agent team은 토큰 배수 효과가 있으므로 작게 유지한다.

자세한 근거와 안전한/비추천 방법 구분은 `research/claude-code-token-reduction.md`를 참고하세요.

## Claude Code plugin distribution

This repository is also structured as a Claude Code plugin marketplace.

- Marketplace file: `.claude-plugin/marketplace.json`
- Plugin: `plugins/claude-token-optimizer/`
- Main skills after install:
  - `/claude-token-optimizer:optimize`
  - `/claude-token-optimizer:audit`

Local test:

```bash
claude --plugin-dir ./plugins/claude-token-optimizer
```

Marketplace test from this repository root:

```text
/plugin marketplace add ./
/plugin install claude-token-optimizer@claude-token-tools
```

After publishing to GitHub, users can add the marketplace with:

```text
/plugin marketplace add YOUR_GITHUB_USER/YOUR_REPO
/plugin install claude-token-optimizer@claude-token-tools
```

This plugin intentionally does not auto-enable hooks globally. See `plugins/claude-token-optimizer/examples/settings.example.json` for an opt-in project settings example.

For local project hygiene, run:

```bash
claude-token-diet scan .
```

It reports missing `permissions.deny` guardrails, noisy-output hook/statusline gaps, broad reads, expensive defaults, many MCP servers, and large/secret-like context files.

### Optional: auxiliary AI delegation

If you also have Gemini CLI or Codex CLI access, the plugin can use them as an opt-in read-only assistant to save Claude tokens on broad exploration or long logs:

```text
/claude-token-optimizer:delegate enable --provider gemini
/claude-token-optimizer:delegate ask --provider gemini --prompt "Summarize this failing test log" --context ./log.txt
/claude-token-optimizer:delegate disable
```

The underlying command is `claude-token-delegate`. It is OFF by default, stores local state in `.claude-token-optimizer/`, prints only a bounded preview back to Claude, and saves full auxiliary responses locally. Do not delegate secrets or private data to another AI provider unless your policy allows it.
