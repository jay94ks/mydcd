# 관측 이벤트와 이어 읽기

`events`는 짧은 Task 재시작·종료, 검사 실패, 노드 자원·Mesh·Raft 관측과 CD/유지보수 상태 전이를 읽는다. 이벤트는 진단 사실이다. 관리 변경의 수락·순서·확정은 기존 사용자 operation과 Raft가 담당하며, 이벤트의 존재·부재나 cursor가 실행 권한·작업 완료를 증명하지 않는다.

## 사용자 명령과 메시지

```sh
mydc --tenant shop events --limit 50
mydc --tenant shop events --app website --kind task-restarted
mydc --tenant shop events --since '이전 응답 Cursor' --limit 50
mydc events --all --kind quorum-degraded
mydc --tenant shop events -f
```

명시하지 않은 tenant는 현재 CLI profile의 tenant다. `--all`은 전체 tenant 및 cluster/node 이벤트를 읽는 시스템 관리자용 선택이며 `--app`과 함께 쓰지 않는다. `-f`는 Ctrl-C까지 새 이벤트를 계속 읽는다. `--node`는 대상 노드 또는 기록한 source 노드, `--kind`는 정확한 종류 하나다. 읽기에 작업 ID·동작 사유를 붙이지 않는다. `events --help`는 접속·wallet 없이 볼 수 있다.

Unix `/var/run/mydc.sock`과 네트워크 MYDCP의 같은 User purpose/kind1·Session/challenge 서명 요청을 사용한다. 평문 Unix JSON/HTTP가 아니다. body 예시는 다음과 같다. 공통 nonce·서명 envelope는 [Unix API](unix-sockets.md)를 따른다.

```json
{"Schema":1,"Method":"events","Nonce":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Tenant":"shop","Events":{"Tenant":"shop","App":"website","Kind":"task-restarted","After":"이전 Cursor","Limit":50}}
```

`Nonce`는 공통 Request의 고정32 byte array다. 실제 호출에는 매번 새 nonce를 생성하고 예시의 고정값을 재사용하지 않는다. 첫 조회에는 `After`를 생략한다. `Events`의 필드는 아래와 같다.

| 필드 | 형식·규칙 |
|---|---|
| `Tenant` | 선택 ID. 바깥 `Tenant`와 같아야 한다. 생략은 system-admin cluster scope |
| `App` | 선택 ID. Tenant가 있어야 한다 |
| `Node` | 선택 ID. 현재 tenant에 허용되지 않은 노드는 거부 |
| `Kind` | 선택한 정확한 종류. 알 수 없는 값은 거부 |
| `After` | 선택 opaque cursor, 최대1536 bytes. 첫 조회에는 생략 |
| `Limit` | 0은 기본50, 최대100. CLI는1–100만 받음 |

query의 filter/cursor는 전부 `Events` 안에 둔다. 바깥 `After`·`Node`·`App`, 다른 method payload·Secret·operation과 섞으면 거부한다. 정상 응답은 `Reply{Schema:1,Code:"ok",Events:Page}`다.

```json
{"Schema":1,"Code":"ok","Events":{"Schema":1,"Items":[{"ID":"source-key/stream/00000000000000000002","Cursor":"opaque-item-cursor","SourceNode":"node-a","Kind":"task-restarted","Scope":"app","At":1800000000000,"Target":{"Tenant":"shop","App":"website","Service":"web","Task":"workload/task/shop/website/web","Native":"docker-container-id","Node":"node-a","Generation":1,"Revision":2},"Detail":{"Reason":"restart"}}],"Cursor":"opaque-page-cursor","More":false,"Incomplete":false}}
```

ID/cursor/시간은 설명용 값이다. 실제 `ID`는 source key·stream·순번 또는 `raft/<Authority>`다. `Authority`가 있는 항목은 그 공개 관리 전이 식별자도 반환한다. 필드명의 대소문자는 위 Go JSON 명세를 따른다. 선택 필드는 생략하며 `Items`가 없을 때 `null`일 수 있다.

| Page·Item 필드 | 의미 |
|---|---|
| `Schema` | 1 |
| `Items` | 권한·filter를 적용한 수신 저장 순서의 이벤트. 요청 개수·응답 바이트 한도에 따라 일찍 끝날 수 있음 |
| `Cursor` | 다음 조회의 `Events.After`. 빈 페이지도 반환된 cursor를 보존 |
| `More` | 현재 저장 범위에 읽을 항목이 더 있음. false는 미래 이벤트·미수신 source의 부재를 뜻하지 않음 |
| `Incomplete` | 이 observer DB에서 source history 누락이 확인됨. 명시 재조회 후에도 남으며 완전한 이력이라고 주장하지 않음 |
| Item `ID` | 중복 알림 방지용 공개 이벤트 신원. 사용자 operation ID와 구분 |
| Item `Cursor` | 해당 항목까지 읽은 위치 |
| `SourceNode` | 이 사실을 기록한 노드. 실행 대상 노드와 다를 수 있음 |
| `Kind`, `Scope` | 아래 종류, `app`·`tenant`·`node`·`cluster` |
| `Authority` | 선택 SHA-256 hex 공개 committed-transition ID. 여러 control의 같은 전이를 한 알림으로 합칠 때 사용 |
| `At` | source Unix milliseconds. 서로 다른 노드의 전역 시각 정렬·인과관계 보장은 없음 |
| `Target` | 아래 대상의 공개 식별자 |
| `Detail` | 아래 허용된 공개 진단 metadata |

`Target`의 선택 문자열은 `Tenant,App,Service,Deployment,Task,Native,Node,FilesystemID,PairID,Gateway,RouteID,Host,Prefix`, 정수는 `Generation,Revision,Term`이다. FilesystemID는 `node-disks`와, PairID는 `mesh-links`와, Term/Node는 `raft-status`와 같은 식별자를 사용한다. Task/native/세대를 원 관측에 고정하고 현재 컨테이너 신원으로 과거를 바꾸지 않는다.

`Detail`의 선택 문자열은 `Reason,OperatorReason,Code,Actor,IncidentID,ApprovedBy,Operation,CandidateID,Commit,Checker,RunID,Resource,State`, 정수는 `FromVersion,ToVersion,ConsecutiveFailures,ExitCode,Value`다. `ExitCode`는 확인한 경우에만 있으며0과 미확인을 구분한다. `ConsecutiveFailures`는 실제 계수 증거가 있을 때만 제공한다. Docker health 전이 하나로 실패 횟수를 추정하지 않는다. OperatorReason·사건 ID·승인자 표시는 서명된 원 작업의 표시 metadata이며 권한 증거가 아니다.

## 종류와 관측 근거

| Kind | 원 근거 |
|---|---|
| `task-restarted`, `task-exited` | 원 Task/labels와 일치하는 Docker SDK start/restart/die. die의 실제 exitCode, 별도 oom 관측. 같은 재시작의 start/restart를 중복 발행하지 않음 |
| `probe-failed` | 원 checker run 또는 Docker unhealthy 전이. script 출력·오류 원문은 제외 |
| `node-resource-low` | 기존 owner 서명 관측에서 디스크 available<10% 또는 메모리 used≥90%로 진입한 전이. 반복 정상 poll마다 발행하지 않음 |
| `tunnel-down`, `node-unreachable` | 기존 Mesh down 관측과 PairID. node-unreachable은 같은 down 관측이10초 이상 유지된 경우 |
| `quorum-degraded` | SDK election/candidate·리더 미확인 관측, 같은 term/node. 이것만으로 투표 노드 전체의 실시간 생사를 단정하지 않음 |
| `registry-stopped` | 원 Registry run의 ready→정지/미확인 상태 전이 |
| `cd-candidate-created`, `cd-approval-required`, `cd-approved`, `cd-rejected` | 수락된 후보·현재 수동 승인 요구·정확한 후보 결정. candidate ID/commit·원 이유 포함 |
| `cd-sync-started`, `cd-sync-succeeded`, `cd-sync-failed` | 원 CD execution ID의 상태 전이 |
| `cd-drift-detected`, `cd-paused`, `cd-resumed`, `cd-rolled-back` | 현재 CD 계획의 OutOfSync 진입, pause 상태 변경, 보존된 과거 성공 입력으로 돌아간 완료 버전 |
| `raft-compact-started`, `raft-compact-completed` | 원 유지보수 job의 노드별 running/terminal. completed의 State/Code를 읽어 실패·skipped를 구분 |
| `node-cache-cleaned`, `tunnel-reconnected` | 원 job의 항목별 결과. State/Code가 실패이면 성공 효과로 해석하지 않음 |
| `task-restart-requested`, `node-cordoned`, `node-uncordoned` | 해당 사용자 관리 변경의 수락. restart-requested는 실제 restart 완료가 아님 |
| `event-source-gap` | Docker stream 중단·신원/보존 누락, committed outbox/snapshot 누락, SDK 관측 유실 등. 완전한 이력 대신 명시 누락 처리 |
| `cert-expiring`, `cert-expired`, `ingress-certificate-missing` | 현재 host/route 인증서의 만료 임박·만료·공급 실패. 개인키 없이 지문/host 범위와 필요한 잔여 초를 관측 |
| `ingress-blocked`, `ingress-unblocked` | 원 사용자 block/extend/unblock의 확정 전이. 실제 owner 설치 완료와 구분 |
| `ingress-backends-empty`, `ingress-backends-restored`, `ingress-listener-down`, `ingress-listener-up`, `ingress-source-rejected-spike` | 실제 backend health/listener 수명 및 source gate의 유한 계수. [Ingress 종류·scope·기준](ingress-management.md#이벤트) |

종료/재시작 최근 내역은 `compose inspect --history N`에도 같은 이벤트 ID·원 native·generation/revision으로 제공한다. `HistoryIncomplete:true`이면 수집 누락/이력 접근 실패가 있으며 빈 History를 완전한 이력으로 해석하지 않는다. 스크립트 검사 pass는 실제 컨테이너 종료·Volume fence를 대신하지 않는다. SDK가 종료 이유를 알려 주지 않은 경우 `exit`/`restart`로 보존하고 원인 정보를 지어내지 않는다.

`oom`은 별도 Docker oom 사실로, `node-restart`는 저장된 원 native의 OS boot ID 변경과 새 boot 시각 이후의 start로 구분한다. mydcd 재시작·인증서 변경만으로 노드 재부팅을 추정하지 않는다. `health`/`user`는 같은 원 native·세대의 실제 Stop/Start sent 제어 기록이 남아 있을 때 연결한다. 아직 보내지 않은 요청이나 과거 terminal 제어로 무관한 종료를 분류하지 않는다. 로그 정리의 원 recreate/native 목록은 `log-clear`를 연결한다. 확정된 OOM·OS boot 원인은 작업 표시 metadata로 덮어쓰지 않는다.

## 권한·cursor·보존

현재 Session·계정 revision·tenant Read·허용 노드를 조회마다 검사한 뒤 filter와 limit를 적용한다. Tenant 조회로 cluster/node 범위의 다른 정보나 다른 tenant 이벤트를 읽지 못한다. control이 기록한 논리 CD 이벤트의 SourceNode는 배치 권한으로 취급하지 않으며, 명시 대상 노드가 있으면 tenant의 현재 허용 노드를 검사한다. 계정 회수·권한 축소 뒤 cursor가 과거 접근 권한을 복원하지 않는다. cluster scope는 현재 ManageCluster/system-admin 권한이 필요하다. 일반 사용자 조회처럼 quorum-backed view·leader forwarding을 사용한다.

노드의 기존 private `observations.db`에 최대4096개, 이벤트당8KiB, 최대7일의 관측을 보관한다. cursor는 query filter·응답한 journal owner/DB epoch·누락 generation·위치·시간에 고정한다. 같은 DB를 재개하면 계속 쓸 수 있으나 보존 초과·해당 journal 교체/응답 노드 변경·수집 누락 뒤에는 `CURSOR_EXPIRED`다. 다른 filter를 붙인 cursor는 유효하지 않은 요청이다.

`CURSOR_EXPIRED`는 CLI 종료3, 권한 거부는 denied, 수집/저장 실패는 unavailable로 구분한다. client가 자동으로 첫 페이지로 돌아가 누락을 숨기지 않는다. 사용자가 명시 `--since`를 빼고 다시 받되 ID로 중복을 처리한다. `Incomplete`를 함께 표시해야 한다. source clock의 허용 오차30초 안에서 미래 시각으로 기록된 항목도 반환하며 cursor를 넘기면서 버리지 않는다.

## 노드 내부 전달과 저장

실제 Docker 이벤트는 기존 SDK Events stream에서 읽고 원 labels/Task/세대/native를 확인한다. source cursor·native mapping과 이벤트를 같은 observer DB write에 저장한다. SDK가 무제한 과거 이벤트를 보관한다고 가정하지 않으며 stream 중단·복원 실패를 gap으로 표시한다.

관리 전이 이벤트는 pure before/after projection으로 allowlist 필드만 만들고 FSM checkpoint와 같은 transaction의 private outbox에 기록한다. outbox는 최대512개/8MiB이며 snapshot의 관리 상태에는 넣지 않는다. 누락/손상은 별도 진단 실패로 표시하고 기존 관리 변경 성공을 다른 변경으로 대체하지 않는다. diagnostic journal의 metadata가 손상된 경우 원 bytes를 보존하고 이벤트 조회를 unavailable로 처리하며, 이를 이유로 기존 관리 엔진 기동을 막지 않는다.

현재 설치 멤버 간에는 기존 MYDCP Observation report의 `Kind:"node-events"` signed batch를 전달한다. Batch는 Schema1·Cluster/Key/Node/Stream·Floor/Last/At·최대8 Records·Signature, 최대32KiB다. Record는 Schema1·Cluster/SourceKey/SourceNode/Stream/Sequence/Tag/Event/Signature다. Key는 고정32 byte array, Stream은16 byte array, Signature는 Go JSON byte slice의 base64다. 서명 domain은 각각 `mydc-diagnostic-event-batch-1\0`, `mydc-diagnostic-event-1\0`이고 Signature를 nil로 한 JSON을 붙여 Ed25519로 검증한다.

member Management read `event-receipt`는 `{Key:[32]byte,Stream:[16]byte}`를 받아 `{Schema:1,Query:{Key,Stream},Last:uint64}`로 durable source prefix를 알려 준다. caller key와 Query.Key가 같아야 하며 일반 User method가 아니다. batch source는 현재 멤버 key/node와 일치해야 한다. observer는 원 source의 연속 순번·중복·retention floor를 검사하고 같은 committed Authority를 중복 발행하지 않는다. 배치 거부는 일부 prefix 저장/ACK 증가를 만들지 않는다.

이 순번과 공개 digest는 관측 ID·중복 방지용이다. 별도 해시체인·Raft 대체 log·관리 동기화 알고리즘이 아니다. Secret 값·보호 verifier·private key·환경 값·probe 출력·provider 오류 원문·컨테이너 로그를 이벤트 detail에 저장하지 않는다.

Ingress의 차단·listener·backend health·인증서·source 거부 이벤트는 [Ingress 운영](ingress-management.md#이벤트)의 종류·scope·기준을 따른다. node/gateway 전역 사건은 tenant 조회로 공개하지 않는다.
