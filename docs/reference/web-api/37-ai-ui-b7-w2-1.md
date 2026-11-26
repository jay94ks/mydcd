## AI 설정 (UI-B7, W2.1, 시스템 관리자)

AI 기능은 모두 mydc-web 안에서 돈다(mydcd는 AI를 모른다). Claude·OpenAI API 키는 봉인 파일(`ai-key-claude`·`ai-key-openai`, 봉인 키 `MYDC_WEB_SEAL_KEY`)에만 있고, bbolt에는 끝 4자리·등록한 사람·시각과 그 키로 읽은 모델 목록만 둔다. 키는 응답·로그·감사에 나오지 않는다. 공급자는 공식 Go SDK(`anthropic-sdk-go/v2`, `openai-go/v3`)로 부른다. 공급자 주소는 `MYDC_WEB_AI_CLAUDE_URL`·`MYDC_WEB_AI_OPENAI_URL`(비우면 공식 API, 프록시용)이다.

- `GET /system/ai` → `{sealReady, revision, providers, roles, data, limits}`.
  - `providers`: `[{provider: claude|openai, configured, last4?, setBy?, setAt?, catalogAt?, models, modelsTotal, error?}]`. `models`는 대화용(숨김 제외), `modelsTotal`은 전체 수. `error`는 마지막 목록 새로고침 실패 분류.
  - `roles`: `{coordinator|diagnosis|impact|simple: {main, fallback, mainMissing, fallbackMissing, sameProvider, effort, thinking, maxOutputTokens, stream}}`. `main`·`fallback`은 `{provider, model}` 또는 `null`. `…Missing`은 키가 없거나 목록에 그 모델이 없음(조용히 다른 모델로 바꾸지 않는다). `sameProvider`는 메인·예비가 같은 공급자(경고). `effort`: low·medium·high, `thinking`: auto·off(현재 Claude 모델은 생각 끄기를 받지 않으므로 off는 두 공급자 모두 가장 낮은 effort로 보낸다).
  - 기본값: 코디네이터·진단 `claude-opus-5-5`(effort high), 단순 결정 `claude-haiku-5-5`(low, off), 영향 평가는 메인 없음(진단과 다른 공급자를 고르게). 예비는 모두 없음.
  - `data`: `{maskSecretLikeEnv(기본 true), logTailLines(기본 200, 0..200), excludeTenants}`. 보관함 값은 어떤 경우에도 보내지 않는다.
  - `limits`: `{dailyTokensPerUser(기본 2,000,000), toolCallsPerConversation(40, 0..1000), tokensPerConversation(1,000,000), compaction: {enabled(false), triggerTokens(150,000, 50,000..900,000)}}`. 0은 무제한이고, 대화당 두 상한의 0은 compaction이 켜졌을 때만 된다.
- `PUT /system/ai/keys/{provider}` `{key}` → provider 행. 그 키로 모델 목록(Claude `GET /v1/models` 끝까지, OpenAI `GET /v1/models`)을 읽어 연결을 시험하고, 성공해야 봉인해 저장하고 목록을 바꾼다. 실패하면 저장하지 않고 422 `key-rejected`(`error.detail`: `auth`·`rate-limited`·`unavailable`·`invalid`). 봉인 키가 없으면 503 `seal-unavailable`, 형식이 틀리면 422 `invalid`(8..512자 출력 가능한 ASCII), 모르는 공급자는 404.
- `DELETE /system/ai/keys/{provider}` → 204. 봉인 파일과 목록을 지우고, 그 공급자를 쓰는 역할은 `…Missing`이 된다.
- `POST /system/ai/models/{provider}/refresh` → provider 행. 키가 없으면 409 `not-configured`. 실패하면 옛 목록을 두고 `error`에 분류를 남긴다. 웹은 시작할 때와 하루에 한 번 연결된 공급자의 목록을 다시 읽는다.
- `GET /system/ai/models/{provider}?all=1` → `{provider, fetchedAt?, items: [{id, displayName?, createdAt, hidden}]}` 최신 순. OpenAI의 대화용이 아닌 모델(임베딩·음성·이미지·검열 등)은 `hidden`이고 `all=1`일 때만 나온다. 숨김 규칙은 `MYDC_WEB_AI_HIDE_MODELS_FILE`(줄마다 Go 정규식, `#` 주석)로 바꾼다.
- `PUT /system/ai/settings` `{revision, roles, data, limits}` → GET과 같은 응답. `roles`에는 바꿀 역할만 넣는다. 409 `revision-changed`, 422 `model-not-in-catalog`(키 없는 공급자 포함), 422 `unlimited-needs-compaction`, 그 밖의 범위 오류는 422 `invalid`. 웹 설정 변경 기록(`area: ai`)에도 남는다.
- `GET /system/ai/usage?days=7`(1..90) → `{items: [{day, role, provider, model, fallback, requests, inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens}], roles: {role: {hitRate}}}`. 사용자를 합친 하루 단위(UTC)이고 최신 날 먼저. `hitRate` = cacheRead ÷ (input + cacheRead + cacheWrite). 두 공급자 모두 `inputTokens`는 캐시에서 읽지 않은 입력이다.
- `GET /system/ai/audit?cursor=&limit=`(1..500, 기본 50) → `{items: [{id, at, user?, username?, kind, role?, provider?, model?, fallback?, reason?, tokens?, cacheRead?, proposal?, decision?}], cursor?, total}` 최신 순. kind: `key-set`·`key-deleted`·`settings`·`request`·`fallback`. `reason`은 예비로 넘어간 이유(`main-missing`·`unavailable`·`rate-limited`·`refused`·`auth`·`invalid`) 또는 실패 분류다. 프롬프트·답·도구 결과 원문은 남기지 않는다.
- `DELETE /system/ai/audit` `{before}`(RFC 3339) → `{deleted}`. 대화를 지워도 감사 행은 남고, 시스템 관리자만 지운다.
- 프롬프트 캐싱: 고정 앞부분(시스템 지시)은 Claude에서 1시간 캐시 지점, 대화 끝은 자동 캐시 지점이다. OpenAI는 같은 앞부분을 스스로 캐시하므로 역할마다 고정 `prompt_cache_key`(`mydc-<역할>-v1`)를 보내고 `store: false`로 공급자 쪽에 응답을 남기지 않는다. 시스템 지시에는 날짜·사용자 이름·지금 화면을 넣지 않는다.
- 예비로 넘어가는 때: 메인 모델이 목록에 없거나 키가 없음, 응답 없음·5xx, 429(SDK 재시도 2회 뒤), 거부(refusal), 키 무효. 예비가 답한 행은 `fallback: true`다. 사용자별 하루 토큰 예산을 넘으면 부르지 않는다.

