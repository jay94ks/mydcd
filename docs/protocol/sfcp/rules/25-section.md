## 컨테이너 운영 조회 메시지

User kind1의 `container-observe`는 현재 사용자 Read session·Tenant·Container Query로 논리 app/service/instance의 로그·top·stats를 요청한다. kind2는 Container Result와 현재 검증 index를 반환한다. schema/purpose/kind를 새 번호로 올리지 않으며 미지원 서버의 unsupported/필드 거부를 성공으로 바꾸지 않는다. 기존 session/challenge 서명·digest·유한 RPC/EOF를 유지한다.

node 간 owner 조회는 기존 member Management의 `container-observe`, 최신 quorum 확인은 `container-read-permit`이다. 전자는 원 native owner에서만 로컬 읽기를 실행하며 후자는 현재 사용자 권한/Task/Binding·owner와 source index를 검증한다. 사용자 요청과 node 내부 호출의 같은 이름이 서로의 입장 권한을 대체하지 않는다. 전체 메시지/출력 필드는 [컨테이너 운영 API](../../../reference/container-operations.md)를 따른다.

### 로그 지우기

로그는 각 서버의 sfcd 로그 보관소에서 지운다(User `logs-clear`, [컨테이너 운영 API](../../../reference/container-operations.md)). Raft 명령이 아니며 컨테이너를 다시 만들지 않는다. 옛 재생성 경로(`app-log-clear-plan/status`, `clear-app-logs`, app-progress `recreate-continue`)는 없앴다.

### ContainerSession — purpose15

purpose15는 컨테이너 interactive exec·logs follow·top/stats watch용 schema1 양방향 확장이다. Unix/TLS와 QUIC은 같은 사용자 인증·원 intent·owner/현재 quorum permit·record를 사용한다. 일반 User의 유한 container-observe와 별도 목적이며 terminal 데이터를 일반 관리 명령으로 해석하지 않는다. 기능 확인/resolve에서 Supported를 받지 못하면 이 기능의 지원을 가정하지 않는다. 구현·검증의 완료 근거는 루트 MILESTONES/HISTORY를 따른다.

| kind | 송신 주체 | TLV1 | TLV2 |
|---|---|---|---|
| 1 | 현재 사용자 | Envelope JSON. Body에 ContainerSessionRequest | SHA-256(Envelope JSON),32바이트 |
| 2 | 서버 | ContainerSessionReply JSON | 요청의 Envelope digest |
| 3 | 설치 member relay | 원 사용자 proof·destination/challenge에 결합한 Relay Envelope | 해당 Envelope digest |
| 5 | 사용자/owner | SessionRecord JSON | 원 서명된 SessionIntent.Digest,32바이트 |

kind4는 거부한다. Request는 스트림 수명 동안 동일하고 TLV1/2는 required·오름차순·각1회, frame body 상한128KiB다. resolve와 open은 별도 RPC다. 사용자가 resolve의 정확한 Task/Binding/native ID/StartedAt/세대와 argv/spec에 서명한 뒤 open을 제출하며, ready는 I/O 수락이지 native 시작/종료의 증명이 아니다. 원 ExecReceipt는 해당 owner의 기존 private DB에서 저장하고 Raft는 현재 권한/순서/원 앱 상태를 제공한다. stdin/stdout/stderr 본문을 Raft에 복제하지 않는다.

stdin-eof는 입력 쓰기만 닫고 출력 읽기는 유지한다. output-eof·연결 단절·권한 회수로 프로세스 exit를 추론하지 않는다. 원 ExecID의 status는 현재 같은 계정 권한으로만 조회하고 재Attach/재실행하지 않는다. [메시지/필드·방향·오류·예산 명세](../../../reference/unix-sockets/21-purpose15.md)와 [CLI](../../../reference/container-operations.md#interactive-exec와-원-실행-조회)를 함께 따른다.

### 사용자·tenant 구성원 페이지

User purpose의 기존 인증 envelope로 `users`·`tenant-members`를 Unix/TLS와 네트워크 SFCP에서 동일하게 호출한다. 별도 node 신원 우회·웹 전용 인증은 없다. 페이지 cursor는 현재 catalog revision과 method/tenant에 고정되며 변경 시 `conflict`를 반환한다. 계정/구성원 형식과 권한은 [사용자·구성원 조회 API](../../../reference/user-catalog.md)를 따른다.

User의 `my-credentials` 및 signed Operation `add-credential`/`disable-credential`은 schema1을 유지한다. 새 `credentials` scope는 Tenant=*에서만 유효하며 기본 password/private-key 새 login에 포함하고 과거 발급 Session을 변경하지 않는다. 정확한 소유 증명 bytes·재결합·pin·voter 선택은 [client 인증](../../../reference/client-authentication.md)에 있다.


`UserOperation.Reason`은 선택 `{Text,IncidentID,ApprovedBy}` 표시 metadata다. operation signature와 원 request identity에 함께 고정되며 submit/result/resume의 성공한 원 결과에 `OperationReason`으로 반환한다. Text는 UTF-8 최대512자, IncidentID는 최대128바이트(개행/NUL 금지), ApprovedBy는 선택 계정 ID다. ApprovedBy는 제출자의 표시이고 그 계정의 승인 signature가 아니다. 관리 권한·Secret Group 승인·독립 사용자 승인을 대체하지 않는다. nil일 때 기존 schema1 서명 bytes를 유지한다. 기존 원 operation을 result/resume할 때 metadata를 바꿔 다시 서명하지 않는다.

### Secret 전달과 로그 가림

[Secret 공급](../../../reference/secret-delivery.md)의 파일/환경 변수 방식은 기존 User app 계획·수락과 member app-binding-permit를 사용한다. `Needs.Files[].Kind`의 빈 값/`file`은 읽기 전용 파일, `env`는 환경 변수 이름 target이다. Blueprint/AppDiff의 optional `SecretEnvRequiresNewGeneration`은 해당 서비스 이름 목록이다. 공유 record에는 공급값·가림 matcher를 넣지 않는다. logs/follow의 원 공급값 가림은 Docker owner가 frame/chunk 경계에 걸쳐 수행한 뒤 같은 User/Session 출력으로 보낸다. 원문 fallback·별도 비인증 전달 경로를 두지 않는다. wire/schema 번호는 1이다.

User `container-observe`의 logs는 optional Query.Cursor/Result.NextCursor로 [가림 완료 로그 구간](../../../reference/container-operations.md#로그-페이지의-원-구간)을 페이지 조회한다. cursor는 owner의 무작위 메모리 window ID/바이트 위치이며 Session/권한을 대신하지 않는다. member owner의 Result.LogCode는 User invalid/InputCode로 매핑하고 현재 권한 검사를 생략하지 않는다. wire frame 크기를 늘리거나 로그 본문을 Raft에 넣지 않는다.

User `container-observe`의 Kind=inspect는 [공개 실제 설정 projection](../../../reference/container-detail.md)을 반환한다. owner는 원 native ID/labels와 최신 사용자 permit을 검사하고 env 키/허용 literal·Secret 참조만 공개한다. 설정 차이의 조회를 lifecycle Start/Gone·Volume fence로 사용하지 않으며 raw Inspect·host bind source·health/script 출력은 wire에 복제하지 않는다.

inspect의 큰 Result.Detail은 DetailPart(무작위 Snapshot, 연속 Offset, 전체 Length/Digest, 최대24KiB Data)와 NextCursor로 분할한다. 각 부분은 원 Target/ObservedAt/LogDriver/TTY를 고정하고 현재 사용자/owner permit을 다시 거친다. client는 전체 길이/SHA-256/canonical JSON 확인 전 완전한 상세로 소비하지 않는다. 원문/matcher는 전송/cache에 넣지 않고 frame/schema 번호는 유지한다.

### 명시 사용자 Task 재시작

RQ4의 User `task-restart-plan`/`task-restart-status`와 서명 `restart-task`는 [Task 재시작 계약](../../../reference/task-actions.md)의 payload를 사용한다. 노드 간 Management `task-restart-permit`은 원 수락 행의 현재 허가를 quorum으로 읽고, `task-restart-report`는 Schema1/Kind=task-restart/Cluster/Reporter/Tenant/App/Operation/Expected/RootRevision/Epoch/At/Control/Signature를 보낸다. 서명 domain은 `sfc-task-restart-report-1\x00`, 원 요청 지문은 `sfc-task-restart-request-1\x00`와 원 OperationBytes의 SHA-256이다. 진행 보고는 사용자 승인을 생성하지 않는다. 새 instance의 Observation.Restart.User는 원 Operation/Request와 완료 Control을 같은 Apps 상태에서 검증한다. lifecycle checker의 기존 Program/Checker/Status 증거와 구별하며 둘을 혼합하지 않는다.

노드 scheduling은 기존 User signed operation의 `cordon-node`/`uncordon-node`, payload `{ID}`(cordon-node는 `{ID, Reason?}`, Reason은 256자 이하 한 줄)와 scheduling Expected CAS로 변경한다. 기존 `members` 결과의 `NodeLifecycle[].Scheduling`은 Enabled/Revision만 노출한다. 변경자의 원 grant는 Members 내부 검증에 보존하고 public scheduling 조회에 반환하지 않는다. 이는 노드 설치 키·Raft membership 변경이나 native 명령이 아니다.

CD 입력 결정 `cd-approve`/`cd-reject`는 같은 User 서명 operation의 payload `{Tenant,App,Candidate,Target,Strict?}`와 기존 공개 Reason metadata를 사용한다. 원 앱/후보 의도 CAS와 현재 tenant ManageCD·credential 동작 제한을 검사한다. readonly app/CD 결과의 Decision/Status 형식은 [CD 후보 결정](../../../reference/cd-candidate-decisions.md)에 정의한다. 같은 commit의 반려 보존과 후보 승인을 Vault Group 암호 승인/배포 권한과 혼합하지 않는다. wire/schema 번호는1이다.

### 수동 Raft snapshot·로그 압축

기존 User purpose의 `raft-compact-plan`/`raft-compact-status`는 `Request.Compact`에 Selection 또는 Operation/After를 넣는다. 새 실행은 사용자 서명 `raft-compact` action이며 원 journal·현재 시스템 관리자/credential·maintenance root·epoch를 검사한다. Reply의 CompactPlan/CompactStatus와 raft-status.LastManualCompact 형식은 [Raft 유지보수](../../../reference/raft-maintenance.md)에 정의한다.

노드 Management `compact-work`는 원 owner의 현재 quorum 허가/진행을 읽고 `compact-report`는 begin/finish/cancel 또는 queued unreachable skip을 서명 보고한다. SDK 호출 자체는 해당 owner의 기존 Raft 인스턴스에서 수행하며 비인증 RPC나 별도 합의·로그 삭제 계층을 만들지 않는다. 원 private sent/result·SDK future 종료·보관 설정 복원·공유 결과를 구분한다. wire/schema 번호는1이다.

User typed method `registry-action-plan`은 `Params:{Tenant,Query:{Action,ID}}`를 받아 기존 registry typed action의 읽기 계획을 `Data`로 반환한다. Action은 start-registry/stop-registry만 허용하고 다른 selector는 거부한다. 실행은 새 메시지/비인증 RPC가 아닌 기존 사용자 서명 operation/원 result를 사용한다. [Registry 조치](../../../reference/registry-actions.md)의 공개 필드·권한·수락/실제 정지 경계를 따른다.

User `tunnel-reconnect-plan`/`tunnel-reconnect-status`는 typed method로 `Params:{Node,Peer}` 또는 `Params:{Operation}`을 보내고 `Data`로 TunnelPlan/TunnelStatus를 받는다. 실행은 기존 서명 reconnect-tunnel action·현재 시스템 관리자/credential·root/epoch·원 결과를 사용한다. 노드 Management tunnel-reconnect-work/report는 해당 owner의 기존 Dial에 대한 현재 quorum 허가와 실제 진행만 다룬다. Unix 사용자에 노드 권한을 주거나 별도 비인증 RPC를 만들지 않는다. 필드/단위·down 관측·원 불명 결과는 [Mesh 복구 API](../../../reference/tunnel-reconnect.md)를 따르며 wire/schema는1이다.

User typed method image-cache-plan/image-cache-status는 `Params:{Query:{Node,Images?,After}}` 또는 `Params:{Operation}`을 받고 계획 또는 상태를 `Data`로 반환한다. 원 실행은 기존 사용자 서명 prune-node-images action·현재 시스템 관리자/credential·root/epoch와 원 result를 사용한다. 노드 native-plan은 owner 로컬 조회, plan-permit/work는 현재 quorum 허가, report는 이미지별 원 진행이다. 해당 설치 owner 외에 native 접근을 부여하지 않으며 비인증 Docker/RPC 경로를 만들지 않는다. 필드/단위·서명 domain·불명 정산·예산은 [캐시 API](../../../reference/node-image-cache.md)를 따른다. schema/frame 번호는1이다.

User kind1의 `app-cd-toggle-plan`은 Tenant와 CDToggle `{App,Action}`만 추가로 받는 인증된 조회다. CDTogglePlan의 현재 revision/root/epoch·Paused/WouldPause·ActiveOperation은 실행 예약이 아니다. Unix와 네트워크는 같은 [CD 조치 계약](../../../reference/cd-candidate-decisions.md#일시정지재개와-이전-버전)을 사용한다.

User kind1의 `initial-credential-stage`/`initial-credential-observe`/`initial-credential-profile`은 owner에 직접 연결하는 보호 사용자 요청이다. 기존 연결 challenge·Session·현재 ManageCluster·credential action 제한을 검사하고 member relay/redirect는 금지한다. 공개 owner fact만 정상 `submit/result/resume`의 issue-initial-credential action·Catalog CAS로 적용한다. token 원문은 첫 private stage 응답에만 있으며 소비자는 계정 Applied 확인 후 한 번 표시하고 지운다. [메시지·원 기록](../../../reference/initial-credentials.md)을 따른다.

User kind1 `events`는 현재 사용자 권한을 먼저 확인하는 read-only cursor 조회다. 같은 원 Request/Session·quorum/leader 전달을 사용한다. member Management `event-receipt`는 caller 자신의 source stream의 durable ACK만 읽고, Observation report `Kind:node-events`는 현재 설치 key/node에 고정한 signed Batch를 최대32KiB/8개 Record로 전달한다. 중복 source와 같은 committed Authority를 합치고 source prefix/retention gap을 명시한다. 관리 상태 동기화·실행 권한을 이 알림으로 대체하지 않는다. [메시지/서명 domain·JSON 필드·보존/누락](../../../reference/events.md)을 따른다.

`replan-app`의 payload는 `{Tenant,App,Target?}`이다. Target이 있으면 현재 후보·등록·정책/override·실행/종료 의도에 고정한 CAS이며 source fetch·health 관측 revision만으로 거부하지 않는다. Target을 생략한 기존 원 요청과 CLI의 명시 `--expected-revision`은 CD/root revision의 strict CAS를 유지한다. 현재 ManageCD·credential 동작 제한·quorum과 원 operation replay 규칙은 동일하다.

