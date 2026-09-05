# ContextGuard experimental features (removed in 0.14.0)

The `context-guard experiments` command and its plan-only experimental lanes
were **removed in 0.14.0**. None of them produced runtime behaviour: every lane
was a review gate that recorded project-local intent and emitted metadata, and
no lane ever enabled omission, replacement, or a hosted API token/cost savings
claim. Keeping a shipped command for that surface cost more than it returned.
ContextGuard does not guarantee a token or cost reduction, and no provider-measured
matched-task evidence ever supported one for these lanes.

Nothing replaces the command. The design notes and the evidence gates behind
these lanes remain under `research/`, in particular
[`../research/experimental-token-reduction-radar.md`](../research/experimental-token-reduction-radar.md).
Benchmark fixture documentation stays at
[`experimental-benchmark-fixtures.md`](experimental-benchmark-fixtures.md).

If a script invoked `context-guard experiments …`, delete the call. The command
no longer exists and there is no compatible successor.

---

## 한국어

`context-guard experiments` 명령과 plan 전용 실험 lane 들은 **0.14.0 에서
제거됐다.** 어떤 lane 도 런타임 동작을 만들지 않았다. 각 lane 은 프로젝트 로컬
의도를 기록하고 메타데이터만 출력하는 리뷰 게이트였고, 생략·치환·hosted API
토큰/비용 절감 주장을 활성화한 적이 없다. 그 표면을 명령으로 계속 배포하는
비용이 얻는 것보다 컸다. ContextGuard 는 토큰·비용 절감을 보장하지 않으며, 이
lane 들에 대해 provider 가 측정한 matched-task 근거도 없었다.

대체 명령은 없다. 설계 노트와 근거 게이트는 `research/` 아래에 그대로 남아
있다. 특히
[`../research/experimental-token-reduction-radar.md`](../research/experimental-token-reduction-radar.md)
를 참고한다. 벤치마크 fixture 문서는
[`experimental-benchmark-fixtures.md`](experimental-benchmark-fixtures.md)
에 그대로 있다.

`context-guard experiments …` 를 호출하던 스크립트가 있다면 그 호출을 삭제한다.
명령이 더는 존재하지 않고 호환되는 후속 명령도 없다.
