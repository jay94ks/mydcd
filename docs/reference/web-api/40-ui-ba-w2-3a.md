## 행동 지침 (UI-BA, W2.3a)

사람이 범위마다 적는 장애 대응 지침이다. 웹 bbolt `ai-guidelines`에 버전마다 남고, 범위를 지울 때 모든 버전이 지워진다. 권한은 매 요청 sfcd에 묻는다(whoami·작업 공간 역할).

| scope | 경로 | 바꾸기 | 읽기 |
|---|---|---|---|
| 클러스터 | `/guides/cluster` | 시스템 관리자 | 시스템 관리자 |
| 작업 공간 | `/guides/tenant/{t}` | 그 작업 공간 관리자 | 구성원 |
| 앱 | `/guides/app/{t}/{app}` | 그 작업 공간 관리자 | 구성원 |

- `GET /guides` → `{items:[{scope, tenant?, app?, version, updatedBy, updatedAt, summary, lines, chars}]}`. 볼 수 있는 것만. `summary`는 첫 줄 인용과 "외 N줄"이다.
- `GET {scope}` → `{scope, tenant?, app?, version, revision, text, fields, deliver, warnings:[{line, text}], summary, lines, chars, updatedBy?, updatedAt?, choices}`. 없으면 `version: 0`, 빈 내용, `deliver` 둘 다 true다. 볼 수 없는 범위는 404다.
  - `fields`: `{prefer:[actionId], avoid:{actions:[actionId], services:[name]}, mcpServers:[name], notify:[문구], critical:[문구]}`.
  - `choices`: `{actions:[{id, label, blockedBy?: cluster|tenant}], services:[name](앱 범위, 지금 app.yaml), mcpServers:[{name, summary, state: ok|error|unchecked|off}]}`(그 범위가 쓸 수 있는 MCP 서버: 클러스터는 전부, 작업 공간·앱은 서버의 `users.tenants`에 든 것). 작업 공간·앱 범위의 조치는 앱 조치만이다.
  - `warnings`: 목록 밖 조치(재부팅·ssh), 지우기, 비밀값 요구, 등급·자동 실행 조건을 바꾸려는 문장이다. 저장은 막지 않는다.
  - `summary`("외 N줄", 영어 "and N more lines"), `warnings[].text`, `choices`의 `label`·`summary`는 읽는 사람의 언어로 만든다([알림](21-ui-c0.md)과 같은 순서). 지침 본문은 쓴 그대로다.
- `PUT {scope} {revision, text, fields, deliver?:{diagnose, coordinator}}` → 같은 모양, `version+1`. 409 `stale`. 422 `invalid`: 4,000자 초과, 범위 밖 조치, 위 범위가 avoid로 막은 조치를 prefer, prefer 10개·avoid.services 32개·notify/critical 16개(한 줄 200자) 초과, `mcpServers` 8개 초과 또는 그 범위가 쓸 수 없는 서버.
- `GET {scope}/versions` → `{items:[{version, updatedBy, updatedAt, summary, incidents, current}]}`(새 것부터). `incidents`는 그 버전을 쓴 사건 수.
- `GET {scope}/versions/{v}` → 그 버전 전체(GET 모양).
- `POST {scope}/restore {revision, version}` → 옛 내용을 새 버전으로 저장. 지금 위 범위에 맞지 않으면 422 `invalid`.
- `DELETE {scope} {confirmName: scope 문자열}` → 200 `{trash:{id, expiresAt}}`. 지난 버전까지 [지운 것](53-ops-trash.md)에 남아 보관 기간 동안 되살린다. 다르면 422 `confirm-name`.
- `POST {scope}/test {incident, text?, fields?}` (바꾸기 권한) → `{current, draft?}`, 각각 `{hypothesis, candidates:[{action, label, impact(규칙 하한), note?}], mcpCalls:{}, model, tokens:{total, cachedRatio}}`. 그 사건에 규칙이 만든 후보(`built`)로 진단(A)만 다시 돌린다. 평가·실행·저장은 하지 않는다. `text`나 `fields`를 주면 이 범위를 그것으로 바꾼 draft도 돌린다(검사는 PUT과 같다). 진단이 꺼졌거나 모델이 없거나 제외한 작업 공간이면 409 `ai-unavailable`, 그 범위가 쓰지 않는 사건이면 422, 모델 실패는 502.
- 사건에 쓰는 법(코드가 강제):
  - 사건의 범위 묶음은 클러스터 사건이면 `cluster`, 앱 사건이면 `cluster`·`tenant/{t}`·`app/{t}/{app}`이다.
  - avoid.actions에 든 조치와 avoid.services의 서비스를 재시작하는 후보는 빠진다("뺀 것: …: cluster 지침이 막음"). prefer 순서로 후보가 앞으로 온다. 등급 하한은 그대로다.
  - 진단(A): `deliver.diagnose`인 범위의 `text`와 prefer를 `<guidelines>`로 사건 사실 앞에 넣는다(고정 시스템 프롬프트가 캐시 앞부분으로 남는다). 타임라인 `inputs`에 "행동 지침"이 붙는다.
  - 영향 평가(B): `critical`만 사실 "지침의 중요 사항"으로 넘긴다. 지침 글은 넘기지 않는다.
  - 코디네이터: 붙인 사건 칩과 화면 경로(`/t/{t}`, `/t/{t}/apps/{app}`)의 범위 중 `deliver.coordinator`이고 그 사람이 읽을 수 있는 것만 턴 맥락에 넣는다.
  - 제외한 작업 공간은 어디로도 보내지 않는다.
- 사건 상세 `guides`: `{cluster?|tenant?|app?: {version(그 사건이 쓴 버전), current(지금 버전, 지워졌으면 0)}}`.
- 앱 탭 `GET /t/{t}/apps/{app}/incident`의 `guides`: `{cluster?|tenant?|app?: {version, summary}}`(볼 수 있는 것만).

