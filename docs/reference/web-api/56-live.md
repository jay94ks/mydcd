# 실시간 반영 (WebSocket)

`GET /api/v1/live?from=N` — 로그인 세션 쿠키로 여는 WebSocket. 같은 출처만 받는다. 설계: 웹 UI 실시간 반영, sfcd 쪽: [변경 감시](../change-watch.md).

웹 데몬은 로그인마다 sfcd 변경 감시 하나를 열고 그 로그인의 모든 탭에 나눠 준다. 웹 데몬 자체 기록(작업 기록·알림·장애 대응 사건)의 변경도 같은 소켓으로 보낸다. 소켓은 **바뀐 기록의 참조**만 보낸다. 화면은 참조가 가리키는 항목만 평소 API로 다시 읽어 바꾼다. 웹 데몬도 화면도 시계로 다시 읽지 않는다.

- `from`: 이 탭이 마지막으로 반영한 `index`. 처음이면 뺀다. `index`는 웹 데몬이 매기는 번호(sfcd Raft 인덱스가 아니다)로, 데몬이 다시 시작해도 이전 번호를 다시 쓰지 않는다.
- 브라우저는 아무것도 보내지 않는다.

## 받는 메시지

| 모양 | 뜻 |
|---|---|
| `{"type":"state","state":"live"}` | 뒤의 sfcd 감시가 이어져 있다 |
| `{"type":"state","state":"reconnecting"}` | sfcd 감시가 끊겨 다시 잇는 중(1초부터 두 배씩, 최대 30초). 이어지면 끊긴 동안의 변경이 온다 |
| `{"type":"changes","index":N}` | 시작점. 소켓을 연 뒤 처음이면 화면은 보고 있는 것을 한 번 다시 읽는다(먼저 읽은 값과 감시 시작 사이를 메운다) |
| `{"type":"changes","index":N,"refs":[…]}` | `index` N까지의 변경. `refs`의 항목만 다시 읽는다 |
| `{"type":"changes","index":N,"resync":true}` | 이 탭의 `from` 이후를 이어 줄 수 없다. 보고 있는 것을 한 번 다시 읽고 N부터 잇는다 |
| `{"type":"error","code":"session-expired"}` | 로그인이 끝났다. 소켓이 닫힌다 |

`refs` 항목: `{"kind","tenant","name","deleted"}`. `kind`는 `app`(`name` = 앱 이름), `volume`(볼륨 키), `network`(네트워크 ID, 시스템 네트워크는 `tenant` 없음), `tenant`(작업 공간 ID), `node`(서버 ID), `registry`·`registry-maintenance`(Registry ID), `ingress`(바뀐 부분 `block/<ID>`·`balance/<앱>/<경로>`·`drain/<앱>/<서버>`·`gateway/<서버>`·`cluster-app-route/<앱>`·`history`, 클러스터 부분은 `tenant` 없음), `dns`(관리 DNS의 네트워크 ID), `certificate`(인증서 ID), `domain`(클러스터 도메인), `host-grant`(`tenant` = 그 작업 공간, `name` = `<작업 공간>/<host>`: route host 승인·거절 결정, 시스템 관리자와 그 작업 공간 읽기 권한), `acme-responder`, `vps`(`account/<이름>`·`server/<이름>`), `node-shell`(`policy`·`node/<서버>`), `node-shell-session`(세션 ID, 내 것이나 관리자만). 웹 데몬 자체 기록은 `op`(작업 ID, 내 것만), `notification`(알림 ID, 내 것만. `name`이 비면 여러 건이 한꺼번에 바뀌었다: 모두 읽음), `incident`(사건 ID, `tenant` = 사건의 작업 공간, 클러스터 사건은 없음), `webhook`(웹훅 이름), `webhook-link`(연결 ID), `webhook-delivery`(`name` = 웹훅 이름, 배달 기록이 늘었다), `guide`(안내 범위 `cluster`·`tenant/T`·`app/T/A`), `ai-conversation`(대화 ID, 내 것만. `name`이 비면 모두 지움), `mcp-server`(서버 이름), `settings`(`web`), `acme-cert`(발급 정의 이름, 주문 단계가 늘어도 온다), `acme-account`(계정 ID), `acme-auto`(`auto`), `dns-provider`(업체 연결 ID), `dns-domain`(도메인 이름: 연결 행·관리 표시·변경 이력·서버 연결·도달 확인 결과가 바뀜. 시스템 관리자와, 그 도메인이 배정됐거나 배정됐던 작업 공간에 권한이 있는 로그인에게 간다), `vps-dns-hold`(서버 이름), `trash`(휴지통 항목 ID, `tenant` = 그 작업 공간. 기한이 지나 빠져도 온다), `archived-app`(`tenant`, `name` = 앱 이름: 내린 앱 보관이 늘거나 줄었다), `cd-check`(`tenant`, `name` = 앱 이름: 배포 전후 점검 결과), `audit`(감사 기록 ID, 작업 공간 기록이면 `tenant`). 서버 보고(sfcd가 받아 저장한 값이 실제로 바뀜)는 `node-observation`(`name` = 서버 ID, `source` = 관측 종류, 앱 작업이면 `tenant`·`app`), `node-report`, `diagnostic`(`name` = 서버 ID). 웹 데몬이 떠 있는 서버의 엔진 사건은 `engine.container`(`name` = 서버 ID, `container`, 작업이면 `tenant`·`app`), `engine.node`(`name` = 서버 ID)이고, `reasons`에 다시 읽을 까닭을 쉼표로 잇는다(예: `die,start`). 보고는 이어 받기가 없어, 놓쳤거나 sfcd 감시가 끊겼다 이어지면 `resync`가 온다. `deleted`면 그 항목을 목록에서 뺀다. 모르는 `kind`는 무시한다. 권한은 sfcd가 걸러서, 그 사용자가 읽을 수 없는 기록은 오지 않는다. 웹 데몬 자체 기록 가운데 내 것(`op`·`notification`·`ai-conversation`)이 아닌 것은 시스템 관리자에게 가고, 작업 공간에 속하면(`tenant`가 있으면) 그 작업 공간에 권한이 있는 로그인에게도 간다.

## 끊김

- 탭이 소켓을 다시 열 때 `from`에 마지막 `index`를 준다. 웹 데몬이 그 뒤 1024개 묶음 안에서 기억하면 놓친 참조를 한 번에 보내고, 아니면 `resync`를 보낸다.
- 탭이 메시지를 제때 받지 못하면(64개 쌓임) 웹 데몬은 그 뒤 메시지를 하나로 합친다: 같은 기록은 한 번만 이름을 대고, 512개를 넘으면 `resync` 하나가 된다. 소켓은 닫지 않는다.
- 화면은 참조를 300ms 동안 모아 한 번에 읽고, 여러 화면이 한꺼번에 다시 읽어야 하면 4개씩 150ms 간격으로 나눠 읽는다.
