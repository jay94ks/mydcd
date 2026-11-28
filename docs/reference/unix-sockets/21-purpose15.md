## 컨테이너 양방향 스트림 purpose15

interactive exec·logs follow·top/stats watch는 purpose15의 동일 handler를 Unix와 QUIC에서 사용한다. Unix session 하나는 전용 TLS/local 연결을 소유한다. 일반 User/SecretInput RPC에 stdin 데이터를 붙이지 않는다. 실제 구현·검증 상태는 MILESTONES/HISTORY를 따른다.

### 요청·수락 메시지

kind1은 현재 사용자 Envelope, kind3은 원 사용자 proof를 보존한 설치 member Relay Envelope다. TLV1은 Envelope의 정규 JSON, TLV2는 그 바이트의 SHA-256이다. Envelope의 Body/Signature는 byte slice의 base64 문자열, Session은 기존 사용자 grant다. Body를 디코딩하면 아래 ContainerSessionRequest가 된다. JSON은 Go 필드명/순서·생략 규칙을 포함한 정규 형식이며 알 수 없는 키·중복 키·후행 값은 거부한다. `[32]byte` 필드는 JSON에서32개 정수의 배열이며 byte slice와 구분한다.

공통 요청 필드는 `Schema:uint8=1`, `Method:string`, `Tenant:string`, `Selection:{App,Service,Instance:string}`, 선택 `Spec/Intent`, `Nonce:[32]byte`다. Nonce는0이 아니어야 한다. 사용하지 않는 Tenant/Selection의 문자열은 빈 값이고 Spec/Intent는 없으면 생략한다.

| Method | 추가 필수 입력 | 결과·효과 |
|---|---|---|
| capabilities | Tenant/Selection 비움, Spec/Intent 없음 | 지원 여부만 확인 |
| resolve | Tenant, Selection.App/Service, Spec | 현재 Read(실행은 Deploy도 필요)·quorum으로 정확한 Target 반환. native exec 생성 없음 |
| open | Tenant, 서명된 Intent. Selection 비움, Spec 없음 | 같은 target/spec·현재 session proof 검증 후 ready, 이어서 kind5. 원 ID가 있으면 receipt/end만 반환 |
| status | Tenant, 원 exec Intent. Selection 비움, Spec 없음 | 현재 같은 계정의 Read/Deploy로 원 ExecID 상태 조회. 새 Create/Attach 없음 |

kind2의 TLV1은 `ContainerSessionReply{Schema:uint8=1,Code:string,Supported:bool,Target?:Target,Status?:ExecStatus}`, TLV2는 요청 Envelope digest다. capabilities는 `ok/Supported=true`, resolve는 `ok/Target`, status는 `ok/Status`, open은 `ready/Target`을 반환한다. `denied/unavailable/target-changed/unsupported/conflict`는 Supported=false·Target/Status 없음이다. ready 이후의 오류는 kind5 error로 처리한다. 유한 요청은 클라이언트 쓰기 EOF와 서버 응답 EOF를 확인하며, open은 transport EOF를 기다리지 않는다. kind4는 허용하지 않는다.

| 구조 | 필드 |
|---|---|
| SessionIntent | Schema=1, Request/User=string, Session=완전한 원 grant의 domain-separated digest32, At=Unix초, Target, Spec, Signature=Ed25519 base64 |
| Target | Cluster/Owner/Binding=digest32, Tenant/App/Service/Node/Instance=string, Generation/Revision=uint64, NativeID/StartedAt=정확한 Docker ID/RFC3339Nano |
| SessionSpec | Kind=exec/logs/top/stats, Exec? 또는 Query?, Interval=int64 나노초 |
| ExecSpec | Argv=string 배열, Stdin/TTY=bool, Rows/Cols=uint16. argv1–128개·각4096바이트·합계16KiB, 유효 UTF-8·NUL 금지. argv[0] 필수, 나머지 빈 문자열 보존. TTY 크기>0, 비TTY 크기0 |
| Query | 기존 container-observe Query. Spec.Kind와 Query.Kind/Selection 일치. logs Until 비움·Interval=0, top/stats Interval=1초–1분 |

Intent 서명은 `sfc-container-session-intent-1\0` + Signature를 nil로 둔 정규 JSON에 적용한다. Intent.Digest는 `sfc-container-session-record-1\0` + 서명까지 포함한 정규 JSON의 SHA-256이다. Session digest는 `sfc-exact-user-session-1\0` + 독립 Approval까지 포함한 원 grant JSON의 SHA-256이다. open의 At는 미래가 아니며 최대30초 전이다. status는 원 시각/서명을 유지하고 현재 로그인으로 인증한다. 설치 노드 키는 사용자의 intent 서명을 대신하지 못한다.

### kind5 record 목록·포맷

TLV1은 정규 `SessionRecord` JSON, TLV2는 Intent.Digest다. 바깥 Request와 digest를 유지하고 각 방향의 Sequence는1부터 독립 증가한다. 공통 `Schema=1,Sequence:uint64,Kind:string` 뒤 Data/Rows/Cols/Sample/Receipt/Code는 해당 kind에만 둔다.0/빈/없는 선택 필드는 생략한다. 단일 Data는 최대16KiB이며 전체 frame body는128KiB다.

| 방향 | Kind | payload·조건 |
|---|---|---|
| client→owner | stdin | Data=비어 있지 않은 base64 bytes. Stdin=true인 exec만, EOF 이전 |
| client→owner | stdin-eof | payload 없음. 실제 SDK CloseWrite, 출력 방향 유지.1회 |
| client→owner | resize | Rows/Cols>0. TTY exec만 |
| client→owner | cancel | payload 없음. I/O 종료 요청이며 프로세스 kill 아님 |
| 양방향 | ping | payload 없음. 유휴 방지이며 권한 증거 아님 |
| owner→client | stdout/stderr | Data=base64 bytes. exec/logs만, output-eof 이전. TTY exec는 stdout으로 합침 |
| owner→client | sample | Sample=기존 Container Result. logs는 최초1회 실제 TTY/driver/Target metadata 뒤 데이터, top/stats는 시각이 있는 반복 표본 |
| owner→client | receipt | Receipt=ExecReceipt. Intent digest가 일치해야 함 |
| owner→client | output-eof | payload 없음. exec/logs 출력 종료, 실제 process exit 아님.1회 |
| owner→client | end | payload 없음. 스트림 정상 종료 |
| owner→client | error | Code=denied/unavailable/target-changed/timeout/stream-error/conflict/unsupported. 스트림 오류 종료 |

예를 들어 `{"Schema":1,"Sequence":1,"Kind":"stdin","Data":"aGVsbG8K"}`는 hello와 개행을 입력한다. 다음 `{"Schema":1,"Sequence":2,"Kind":"stdin-eof"}` 뒤에도 서버 출력은 계속 읽는다. 방향 위장·sequence gap/replay/overflow·payload 혼합·EOF 중복·end/error 이후 record는 거부한다.

`ExecReceipt`는 Schema=1, Intent=digest32, ExecID=string, Phase=creating/created/start-sent/started/finished, StdinClosed/OutputEnded/Detached=bool, ExitCode?=int다. Create 전 marker→ID 저장→Start 전 marker→양성 시작→실제 exit의 단방향 전이이며 finished에만 알려진0–255 exit를 둔다. Start 응답을 잃고 Running=false/ExitCode=0만 관측하면 미실행과 구분되지 않으므로 성공으로 확정하지 않는다.

`ExecStatus`는 Schema=1, Request=원 ID, Target=원 대상, Receipt, Running?=bool, ObservedAt=RFC3339Nano다. Running 생략은 신선한 native 관측 부재이며 finished는 과거의 확정 결과다. 원 Task 교체나 원 로그인 만료 뒤에도 현재 같은 계정 권한으로 원 기록을 조회하며 다른 컨테이너/새 ID로 바꾸지 않는다.

### 예산·종료

기존30초 header/RPC 제한은 유지한다. purpose15는 admission5초, client 접속 수립 기본10초/최대1분, 인증 뒤 read-idle60초/write5초·원 session 만료, ping10초·현재 quorum/권한/원 native 재검사2초, 노드 동시 handler8개를 적용한다. 일반 SDK는 기존 timeout을 유지하고 stream client만 같은 로컬 Docker UDS의 dial5초/header10초·caller context를 쓴다. slow reader는 유한 chunk/backpressure 뒤 I/O를 닫으며 누적 무한 buffer를 만들지 않는다. 취소·단절·회수·daemon 종료는 reader/writer/SDK body와 goroutine을 회수하지만 컨테이너나 내부 프로세스의 종료를 뜻하지 않는다. 자동 재접속/재Attach/재실행은 없다.

장수 client의 동일 proof key 재결합·다중 사용자/소스 예산·현재 상한·voter 직접 login과 `add-credential`/`disable-credential`의 payload·독립 승인/소유 증명 포맷은 [client 인증 명세](../client-authentication.md)를 따른다. Session은 연결 challenge 자체에 고정되지 않으며, `login`의 Ticket/Proof 교환만 원 연결에 고정된다.

관리 operation의 선택 Reason metadata·동작 제한도 네트워크 SFCP와 같다. [공통 서명 계약](../../protocol/sfcp.md)과 [credential 목록/동작 제한](../user-catalog.md)을 따르며 Unix socket이라는 이유로 권한을 넓히지 않는다.

### 앱 Secret 전달 metadata

`app-plan`/`app-plan-stream`의 Blueprint와 Diff의 AppDiff에는 optional `SecretEnvRequiresNewGeneration: string[]`이 있다. 환경 변수 Secret을 사용하는 서비스 이름을 정렬한 목록이며 변경 시 새 Task 세대가 필요함을 표시한다. 원 바이트 digest/part paging과 현재 Deploy/Group 승인 검사는 같다. Binding의 `Needs.Files` 원소에서 optional `Kind`는 빈 값/`file`(파일 target) 또는 `env`(환경 변수 name)이며 Key/UID/GID/Mode만 공개한다. 실제 값·호스트 projection 경로는 포함하지 않는다. [공급/가림 계약](../secret-delivery.md)을 따른다. logs/follow의 가림은 owner 노드에서 전송 전에 수행한다.

다중 배치에서 Diff의 `AppDiff`와 분할된 `app-cd-diff` 객체는 optional `Replacement`를 반환한다. `{Required:true,BlockedCode?,Blocker?,Waves:[{Node,Tasks:[exactTaskKey],Targets:[{Key,Revision,Generation}]}]}` 형식이다. 원 claim의 같은 종료 closure를 노드별로 계산하며 다른 노드의 Task까지 종료해야 하는 의존은 `ROLLING_DEPENDENCY_CONFLICT`와 원 Task key를 반환한다. 미정산 실행/전송은 `ORIGINAL_OPERATION_PENDING`이다. blocked일 때 Waves는 비어 있다. 이 값은 조회 시점의 영향 계획이며 종료·health·실행 승인·다음 파동 진행의 증거가 아니다. 조회된 계획을 순차 갱신 완료로 해석하지 않는다. 같은 part/digest·현재 사용자/tenant 권한을 적용한다.


`container-observe`의 Container.Cursor는 logs 전용이다. Result.NextCursor로 같은 가림 완료 구간을 이어 읽고, 모든 query 옵션/현재 사용자/원 Task·native를 고정한다. owner의 LogCode는 User의 `Code=invalid, InputCode=CURSOR_EXPIRED|LOG_WINDOW_LIMIT|LOG_CURSOR_CAPACITY`로 전달한다. 상세 한도·10분 수명은 [로그 페이지](../container-operations.md#로그-페이지의-원-구간)를 따른다. follow 목적에 cursor를 섞지 않는다.

`container-observe`는 Container.Kind=inspect와 optional HistoryLimit(0=기본20, 1–100)로 [실제 설정](../container-detail.md)을 조회한다. Result.Detail 또는 DetailPart/NextCursor로 같은 상세를 조회하며 logs/top/stats payload와 섞지 않는다. 원 native ID/labels를 검사하되 목표와 실제 설정의 차이는 Drift로 표시하며 제어 증거로 승격하지 않는다. purpose15 stream의 inspect/watch는 지원하지 않는다.

inspect의 DetailPart는 Snapshot/Offset/Length/Digest/Data를 반환하며 동일 사용자·query·원 Task/native·관측 metadata에 고정한다. 최대16MiB의 가림 완료 상세를 기존24KiB 이하 Data로 보내고 전체 canonical JSON/해시 검증 뒤 소비한다. wire frame 상한은 유지하며 상세 cache 한도/만료는 [상세 분할](../container-detail.md#대형-상세-분할과-수집)을 따른다.

### Task 재시작 메시지

RQ4 연결 중인 User 메시지 `task-restart-plan`/`task-restart-status`와 서명 action `restart-task`의 요청·응답은 [Task 재시작 계약](../task-actions.md)에 정의한다. 관리 Unix 소켓에서도 같은 Tenant/TaskRestart와 TaskRestartPlan/TaskRestartStatus 필드 및 현재 사용자 권한을 사용한다. owner 간 `task-restart-permit`/`task-restart-report` Management 요청은 노드 간 경계이며 Unix 사용자 연결에 노드 보고 권한을 주지 않는다. purpose·frame/record 번호는 기존 1을 유지한다.

User 서명 action `cordon-node`/`uncordon-node`는 `{ID}`를 받고(cordon-node는 선택 `Reason`도), `Change.Expected`로 node scheduling revision을 검사한다. 별도 Unix message kind를 만들지 않는다. 기존 `members` Reply의 `NodeLifecycle[].Scheduling={Enabled,Revision}`로 현재 상태를 읽으며, 원 변경의 결과/재개는 기존 operation API를 사용한다. [노드 scheduling 계약](../task-actions.md#노드의-새-배치-제외복원)을 참조한다.

### CD 후보 승인·반려 메시지

기존 User submit/result/resume의 서명 Change.Action에 `cd-approve`/`cd-reject`를 사용한다. payload는 `{Tenant,App,Candidate,Target,Strict?}`, Expected는 CD revision, RootRevision은 Apps root이며 선택 Reason은 원 UserOperation metadata다. 새 purpose/kind를 만들지 않는다. 기존 apps/CD 조회에 `CD.Decision`과 `CD.Status.Rejected/Rejection/ApprovalActor/ApprovalReason`을 추가한다. [형식·CAS·권한](../cd-candidate-decisions.md)을 따른다. Secret Group 승인 요청의 메시지나 비밀번호 필드를 후보 결정에 사용하지 않는다.

### Raft 수동 유지보수 메시지

관리 Unix 소켓에서도 기존 User 인증/서명 envelope 안의 같은 메시지를 사용한다. 둘 다 [typed method](10-user.md#typed-method)다. `raft-compact-plan`은 `Params:{Selection:{Nodes?,Mode,Retain,Parallel},After?}`을, `raft-compact-status`는 `Params:{Operation,After?}`을 받는다. 응답 `Data`는 각각 계획 페이지(최대64개 대상), 상태 페이지(최대4개 노드 결과)이며 Next는 다음 `Params.After`에 전달한다. roster/root 변경은 `Code:"conflict"`, `InputCode:"COMPACT_VIEW_CHANGED"`다.

수동 실행은 별도 socket kind가 아닌 기존 UserOperation의 `Change.Action=raft-compact`, Expected=0, Payload `{Operation,Selection,Target}`와 현재 RootRevision/Epoch를 사용한다. 시스템 관리자·credential 제한·원 intent/result를 검사하고 수락을 SDK 완료로 표시하지 않는다. whoami의 CompactRootRevision과 raft-status의 전역/노드별 LastManualCompact를 함께 제공한다. 상세 Result/metrics·단위·내구/복구·예산은 [Raft 유지보수 API](../raft-maintenance.md)를 따른다.

노드 간 compact-work/compact-report는 기존 네트워크 Management 경계다. Unix 사용자 연결에는 이 노드 보고·Raft RPC 권한을 주지 않으며 protocol/frame/record 번호는 변경하지 않는다.

### Registry 시작·정지 계획 메시지

User typed method `registry-action-plan`은 `Params:{Tenant,Query:{Action:"start-registry"|"stop-registry",ID}}`를 받고 계획을 `Data`로 반환한다. 다른 필드는 허용하지 않는다. 응답의 Schema/Cluster/Action/Tenant/ID, Expected/RootRevision/Epoch, Current RegistryView, WouldEnable/DataPreserved는 [Registry 조치 API](../registry-actions.md)에 정의한다. 계획은 인증된 quorum read이며 실행 가능한 unsigned operation이 아니다.

실행은 기존 서명 start-registry/stop-registry action, record/root CAS와 원 operation/result를 사용한다. Unix·네트워크 SFCP가 같은 현재 사용자·credential 제한을 검사한다. 소켓 프로토콜·frame·schema 번호는1이며 새로운 노드 관리 권한을 부여하지 않는다.

### Tunnel reconnect 메시지

User `tunnel-reconnect-plan`은 typed `Params:{Node,Peer}`, `tunnel-reconnect-status`는 typed `Params:{Operation}`을 받고 `Data`로 답한다([typed method](10-user.md#typed-method)). 응답 TunnelPlan은 owner/peer 키·주소·PairID·원 서명 down 관측/Target이며, TunnelStatus는 원 job·사용자/이유·revision·실제 handshake 결과다. whoami는 TunnelRootRevision을 제공한다.

실행은 기존 UserOperation의 reconnect-tunnel, Expected=0, Payload `{Operation,Plan}`·현재 root/epoch를 사용한다. 노드 간 tunnel-reconnect-work/report는 네트워크 Management 경계이며 Unix 사용자 연결의 메시지로 허용하지 않는다. 전체 필드·서명 domain·정산/예산은 [Mesh 복구 API](../tunnel-reconnect.md)를 따른다. schema/frame/record 번호는1이다.

### 노드 이미지 캐시 메시지

User typed method image-cache-plan은 `Params:{Query:{Node,Images?,After,Operation:""}}`을, image-cache-status는 `Params:{Operation}`을 받고 결과를 `Data`로 반환한다. 다른 필드는 허용하지 않는다. Plan은 원 owner 서명 Image ID/별칭/Bytes·Containers/References·Next이며 status는 원 job/주체/이유·revision과 이미지별 Parts다. whoami는 ImageCacheRootRevision을 제공한다.

실행은 기존 UserOperation의 prune-node-images, Expected=0, Payload `{Operation,Plan}`과 현재 root/epoch를 사용한다. owner의 image-cache-native-plan/plan-permit/work/report는 기존 네트워크 Management 경계이며 Unix 사용자에게 이 노드 권한을 주지 않는다. 전체 공개 메시지·서명·정산/예산은 [노드 캐시 API](../node-image-cache.md)에 정의하며 protocol/record/frame 번호는1이다.

RQ4의 `app-cd-toggle-plan`은 현재 tenant ManageCD·credential 동작 제한으로 `{CDToggle:{App,Action}}`를 평가해 `CDTogglePlan`을 반환한다. 실행과 동일한 순수 전이/CAS·원 ActiveOperation 보존 조건을 사용한다. 필드와 예시는 [CD 조치](../cd-candidate-decisions.md#일시정지재개와-이전-버전)를 따른다.

