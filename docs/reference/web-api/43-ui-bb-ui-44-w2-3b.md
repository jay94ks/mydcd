## 웹훅 (UI-BB·UI-44, W2.3b)

sfc-web이 사건·자동 배포·외부 접속 이벤트를 보내고 판단을 묻는 곳이다. 외부 웹훅은 웹이 공개 https 주소로 직접 보낸다. 클러스터 내부 웹훅은 작업 공간 앱 서비스로 sfcd의 `service-call`을 거쳐 보낸다. 서명 비밀과 헤더 토큰은 봉인 파일에만 있고, 응답에는 `set`과 토큰 끝 4자리만 나온다. 권한은 매 요청 sfcd에 묻는다.

- 누가: 클러스터 웹훅(`tenant` 없음)은 시스템 관리자가, 작업 공간 웹훅은 그 작업 공간 관리자(와 시스템 관리자)가 만들고 본다. 연결은 그 작업 공간 구성원도 읽는다.
- `GET /webhooks?tenant=` → `{items:[웹훅]}`, `GET /webhooks/{name}`.
  - 웹훅: `{name, tenant?, kind: external|internal, url?, target?:{app, service, port, path, scheme: http|https}, role: notify|decide, format: sfc|slack|teams|pagerduty, sign: hmac|token|none, secret:{set, rotatingUntil?}, token?:{set, last4}, enabled, disabledReason?: failures|manual, state: ok|failing|disabled, lastDelivery?:{at, status?, ms, error?, retry?:{attempt, of}}, stats:{today, failed, avgMs}, links, revision, createdBy, createdAt}`.
- `POST /webhooks {name, tenant?, kind, url|target, role, format?(sfc), sign?(hmac), token?}` → 201 웹훅. `sign: hmac`이면 `secret.value`를 이때 한 번만 준다. `token`이면 `token`(헤더 값, 보이는 ASCII 512자까지)이 필요하다.
  - `name`: `^[a-z][a-z0-9-]{0,30}$`, 전체에서 하나. 있으면 409 `exists`.
  - `url`: https만, 사용자 정보 없음. 사설·루프백·링크 로컬·CGNAT·NAT64·6to4·Teredo·문서용·벤치마크용·예약 주소와 `localhost`·`.local`·`.internal`은 거부한다(보낼 때 접속 주소도 다시 확인). 리다이렉트는 따라가지 않는다.
  - 내부 웹훅은 `tenant`가 있어야 하고 대상은 그 작업 공간의 앱·서비스·포트·경로로만 정한다. `target.scheme: https`는 `service-call`의 TLS로 보내고, 작업 공간 CA가 믿지 않는 인증서는 `target.insecureSkipVerify: true`일 때만 받는다. 실패는 `SERVICE_CALL_TLS`이다.
  - 판단 웹훅은 `format: sfc`만 쓴다.
- `PUT /webhooks/{name} {revision, url?, target?, format?, sign?, token?, enabled?}`. 이름·작업 공간·kind·role은 바뀌지 않는다(422 `immutable`). hmac으로 바꾸면 새 비밀을 한 번 준다. `enabled: true`는 실패 횟수를 지운다. 409 `stale`.
- `DELETE /webhooks/{name} {confirmName}` → 200 `{trash:{id, expiresAt}}`. 전송 기록·봉인 비밀도 지운다. 정의와 연결은 [지운 것](53-ops-trash.md)에 남는다(비밀 없이).
- `POST /webhooks/{name}/rotate` → `{secret:{set, value, rotatingUntil}}`. 24시간 동안 두 서명을 함께 보낸다.
- `POST /webhooks/{name}/test` → `{delivery, steps:[{label, detail}]}`. 시험 이벤트 하나(`event: test`)를 부른 사람 세션으로 보낸다(내부 웹훅의 `service-call`도). 꺼진 웹훅도 시험할 수 있고, 시험은 실패 횟수에 들지 않는다. 판단 웹훅이면 응답이 `action`·`decision`·`result` 중 하나를 가진 JSON 객체인지 본다.
- `GET /webhooks/{name}/deliveries?cursor=` → `{items:[{id, at, point, event, status?, ms, error?, retries?, firstStatus?, retry?, decision?, accepted?, reason?, done}], cursor?}`. 새 것부터 50개씩, 웹훅마다 최근 1,000건.
- 보내기:
  - 헤더: `Content-Type: application/json`, `X-SFC-Event`, `X-SFC-Delivery`, 그리고 `X-SFC-Signature: t=<unix>,v1=<hex hmac_sha256(secret, t + "." + body)>`(hmac) 또는 `X-SFC-Token`(token). 내부 웹훅도 같은 헤더다(REQ-24가 허용하는 `X-SFC-*`).
  - 본문(`sfcli`): 이벤트마다의 필드와 `{event, deliveryId, at, point}`. `slack`은 `{text}`, `teams`는 MessageCard, `pagerduty`는 Events v2 모양이다. 본문은 256 KiB, 응답은 64 KiB까지만 읽는다.
  - 판단 웹훅: 10초, 재시도 없음. 알림 웹훅: 한 번에 30초, 답한 429·5xx는 1초·10초·1분 뒤 세 번 더 보낸다(같은 `X-SFC-Delivery`라 받는 쪽이 같은 전송인지 안다). 외부 웹훅은 연결 실패·시간 초과도 다시 보낸다. 내부 웹훅은 sfcd `service-call`이 한 번만 보내고 다시 보내지 않으므로([service-diagnostics.md](../service-diagnostics.md)), 앱에 닿지 않은 것이 확실한 `SERVICE_NO_READY_TASK`·`RATE_LIMITED`만 다시 보낸다. `SERVICE_CALL_TIMEOUT`·`SERVICE_CALL_REFUSED`·sfcd 응답을 잃은 경우는 앱이 이미 받았을 수 있어 다시 보내지 않는다.
  - 오류 코드(`error`): `timeout`, `connect`, `tls`, `redirect`, `address-not-allowed`, `http-<status>`, 그리고 내부 웹훅은 `service-call` 결과 코드를 그대로 쓴다.
  - 잇달아 3번 실패한 전송(재시도 뒤)이 나오면 웹훅을 끄고(`disabledReason: failures`) 만든 사람에게 알림(`webhook-off`)을 보낸다.
- 연결 `GET /webhook-links?point=&tenant=&app=` → `{items:[{id, point, scope:{tenant?, app?, gateway?, route?}, events, webhook, role, kind?, waitSeconds?, onTimeout?, when?, onFail?, openIncident?, approver?, threshold?, minutes?, recover?, condition?, last?:{at, status?, error?}, createdBy, createdAt, revision}]}`. `last`는 그 연결로 보낸 마지막 전송이다.
  - `POST /webhook-links` → 201, `PUT /webhook-links/{id} {revision, …}`(point·scope는 바뀌지 않음), `DELETE /webhook-links/{id}` → 204.
  - 작업 공간 웹훅은 그 작업 공간 안에서만 연결한다. 클러스터 범위 연결과 클러스터 웹훅 연결은 시스템 관리자만 한다.
  - `incident` 이벤트: `opened`, `approval-required`, `auto-run`, `approved`, `rejected`, `expired`, `recovered`, `closed`. 판단 웹훅은 이벤트 없이 연결하고, 범위마다 하나다.
  - `ingress` 연결은 게이트웨이 범위 `scope:{gateway: external|local}`(시스템 관리자) 또는 앱 범위 `scope:{tenant, app, route?}`(그 작업 공간 manager)다. 게이트웨이 이벤트는 `down`, `tls-rejects`, `source-rejects`, `error-rate`, `blocked`(작업 공간 없는 차단), `certificate-expiring`, `limit-90`, `recovered`(= `recover: true`)이고, 앱·경로 이벤트는 `error-rate`, `latency`, `no-backends`, `probe-failed`, `cert`, `blocked`, `balance-fallback`이다. 범위에 맞지 않는 이벤트는 422.
  - `threshold`(error-rate는 5xx %, latency는 p95 ms)와 `minutes`(0~60, 그만큼 이어져야 보냄)는 error-rate나 latency에만 쓰고, 둘을 한 연결에 같이 고르면 threshold를 줄 수 없다. `recover: true`면 보낸 알림의 회복도 보낸다. `group: true`면 같은 대상의 같은 이벤트는 10분에 한 번만 보낸다. `condition`은 웹이 만든 한 줄(예: "5xx 2% 넘게 3분")이다.
  - `cd`: 앱 범위, `kind: pre-sync|post-sync|notify`와 그 설정(기본값과 뜻은 /mnt/project-files/w2/cd-webhooks-contract.md; `waitSeconds`는 pre-sync 5~30·기본 10, post-sync 5~600·기본 60). `pre-sync`·`post-sync`는 판단 웹훅, `notify`는 알림 웹훅이다(다르면 422 `role`). `pre-sync`·`post-sync`는 앱마다 하나다(409 `exists`). `pre-sync`는 자동 배포가 승인 방식이어야 하고(422 `cd-mode`), 저장하면 저장한 사람 세션으로 자동 대응 계정에 그 앱의 `ApproveCD`를 주며 지우면 거둔다. `approver:{account, scope, state: ok|missing|denied}`.

### 웹훅을 보내는 때 (W2.3b)

- 사건 알림: 사건이 열릴 때(`opened`, 이어서 `approval-required` 또는 `auto-run`), 승인(`approved`)·거절(`rejected`)·만료(`expired`)·회복(`recovered`) 때, 그 사건을 덮는 `incident` 알림 연결로 보낸다(클러스터 사건은 클러스터 범위 연결만). 본문 `{event: "incident.<이름>", incident:{id, title, scope, signal, rule, state, decision, at, link, tenant?, app?, node?, target?, impact?, mitigation?}, dedupKey, link}`. 신호 원문(detail)은 넣지 않는다.
- 사건 판단: 판단 순서는 `["ai","webhook","rules"]`(판단 웹훅이 연결된 범위)이다. AI가 판단하지 않은 사건(키 없음·역할 꺼짐·제외한 작업 공간·실패)은 가장 좁은 범위(앱 → 작업 공간 → 클러스터)의 판단 웹훅에 묻는다.
  - 본문 `{event: "incident.decide", incident, candidates:[{action, label, impact(규칙 하한), note?}], allowed:[…, "none"], link}`. 응답 `{action, reason?}`.
  - `allowed` 안이면 그 후보가 첫째가 되고, `none`이면 사람에게 넘긴다. 영향 하한·자동 실행 조건은 그대로다(웹훅은 등급을 내리지 못한다). AI 실패 뒤 웹훅이 고르면 그 실패로 승인을 요청하지는 않는다.
  - 다른 답, 형식 오류, 실패는 버리고 규칙으로 판단한다. 사건 타임라인에 `{kind: "webhook", text, webhook, status, accepted, reason?}`, 전송 기록에 `decision`·`accepted`·`reason`이 남는다.
  - 정책(`GET /incidents/policy`, 앱 `GET …/incident`)에 `decide`, `decideNow: ai|webhook|rules`, `decideSkip: {ai?: no-key|role-off|excluded, webhook?: none-linked|disabled}`이 붙는다.
- 자동 배포(`cd`, REQ-25 이벤트): 감시기가 `cd-*` 이벤트를 읽어(장애 대응이 꺼져 있어도 cd 연결이 있으면 읽는다) 다음을 한다. 뜻과 본문은 /mnt/project-files/w2/cd-webhooks-contract.md이다.
  - `notify` 연결: 고른 이벤트를 `cd.<이름>`으로 보낸다.
  - `cd-*` 이벤트는 최근 30분 안이고 끊김 없이 읽기 시작한 뒤의 것만 다룬다(처음 읽을 때·cursor 만료 뒤·멈췄다 다시 읽을 때 쌓여 있던 것은 웹훅·알림을 보내지 않는다).
  - `pre-sync`: `cd-approval-required`에 판단 웹훅을 부른다(`waitSeconds` 5~30초, 기본 10). `pass`면 자동 대응 계정으로 `candidate/approve`, `reject`면 `candidate/reject`를 보내고(이유 "웹훅 {이름}: …"), `hold`면 둔다. 시간 초과·오류는 `onTimeout`이다. 이벤트의 후보가 지금 기다리는 후보가 아니면 부르지 않고, `approver.state`가 `ok`가 아니면 부르지 않고 확인 결과를 `failed`(사람이 승인)로 둔다.
  - `post-sync`: `cd-sync-succeeded`에(`when: healthy`면 앱이 healthy가 될 때까지 `waitSeconds` 기다려) 부른다. `fail`(또는 `onTimeout: fail`인 시간 초과)이면 자동 대응 계정으로 `cd/pause`를 보낸다. `openIncident`이거나 `onFail: pause-rollback`이면 앱 사건 `cd-post-check-failed`(후보: 직전 버전으로 되돌리기, 늘 승인)를 연다.
  - `GET /t/{t}/apps/{app}/cd`에 `webhook`(가장 최근 확인)과 `checks:{pre-sync?, post-sync?}`가 붙는다. 모양은 `{kind, link, webhook, state, at, candidate, reason?, status?, actions?:[{kind: pause|rollback-request, state, code?, incident?}]}`.
- `ingress` 알림(REQ-22 G 이벤트): 감시기가 읽은 `ingress-*` 이벤트를 연결 이벤트로 바꿔 notify 웹훅에 보낸다. `listener-down/up` → `down`(sfcd는 수신 주소 이름을 주지 않으므로 대상은 `ingress.node`·`gateway`로 본다), `certificate-missing` → 경로면 `cert`, 게이트웨이면 `tls-rejects`, `source-rejected-spike` → `source-rejects`, `backends-empty/restored` → `no-backends`, 앱의 `probe-failed` → `probe-failed`, `ingress-blocked/unblocked` → `blocked`. 본문은 `{point:"ingress", event:"ingress.{e}"(회복은 ".recovered"), state: firing|recovered, ingress:{node, gateway, tenant?, app?, route?, host?, prefix?, metric?, value?, threshold?}, observedAt, condition?, link, dedupKey}`. 회복이 없는 이벤트는 같은 대상에 10분에 한 번만 보낸다. 경로가 없는 이벤트(`probe-failed`, `blocked`)는 그 앱의 모든 연결(경로 연결 포함)이 받는다. 기다리는 알림과 보낸 기록은 메모리에만 있어서 재시작하면 그 전 알림의 회복은 보내지 않는다. `balance-fallback`은 sfcd 이벤트가 없어 아직 보내지 않는다. 게이트웨이의 `certificate-expiring`(그 게이트웨이 수신 주소가 쓰는 인증서의 지금 버전이 14일 안에 끝남, `detail`에 이름과 끝 시각)과 `limit-90`(서버 연결이 한도 합의 90% 이상, metric `connections-share`. 한도는 게이트웨이가 아니라 서버 것이라 서버마다 한 번, `ingress.gateway` 없이 모든 게이트웨이 연결이 받는다)은 sfcd 이벤트가 아니라 웹이 5분마다 읽어 바뀔 때만 보낸다(그런 연결이 있을 때만 읽음). 게이트웨이 이벤트는 자동 조치 계정이 시스템 관리자일 때만 읽힌다. `error-rate`·`latency`도 sfcd 이벤트가 아니다(sfcd는 최근 지표만 주고 사건을 만들지 않는다, [ingress-management.md](../ingress-management.md) '이벤트'). 그런 앱 연결이 있으면 웹이 1분마다 그 앱 매핑의 `ingresses` Part `metrics`(최근 60초)를 읽어 경로마다 한 번 판단한다: 앱의 모든 서버를 합친 5xx 응답 비율(metric `5xx-ratio`, 0~1)과 가장 나쁜 p95(`latency-p95-ms`). 연결의 `threshold`(5xx는 %, 지연은 ms)를 넘으면 그 연결에 대해 넘은 것이고, `minutes` 동안 계속 넘으면 보낸다. 그 아래로 내려오면 회복이다(그동안 기다리던 알림은 버린다). `threshold`가 없는 연결은 5%·1000ms로 본다. 본문의 `threshold`는 판단한 기준(5xx는 비율)이다. 요청이 없으면 0으로 본다. 앱 연결의 지표는 자동 조치 계정이 그 작업 공간을 읽을 수 있을 때만 읽힌다.

