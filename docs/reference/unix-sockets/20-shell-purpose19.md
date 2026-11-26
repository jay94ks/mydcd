## 노드 shell purpose19

사용법·로컬 계정·sudo·종료 해석은 [노드 shell](../node-shell.md)을 따른다. 관리 socket은 기존 TLS/MYDCP 사용자 인증을 사용한다. purpose19의 Unix 접속은 전용 TLS/local 연결 하나를 끝까지 소유하며 일반 User RPC나 Docker API로 바꾸지 않는다. UDP/QUIC에서는 같은 frame/payload를 인증된 reliable stream으로 전달한다. 별도 일반 TCP MYDCP 또는 원격 SSH fallback은 없다.

### User 조회와 서명된 관리 변경

조회는 기존 User=8 kind1/2를 사용한다. Request의 공통 `Schema=1,Nonce:[32]byte`와 현재 사용자 Envelope는 동일하며 아래 허용 필드 외 Tenant/Node/업무 selector를 섞지 않는다.

| Method | Request의 추가 필드 | Reply의 공개 필드 |
|---|---|---|
| `node-shell-policy` | 없음 | `NodeShellPolicy:{Enabled,MaxSessions,IdleSeconds,Account,Nodes,Grants,Revision,Index,RootRevision}`, `NodeShellRootRevision` |
| `node-shell-sessions` | `After?:string`, `State?:"open"\|"closed"`, `Node?:string` | `NodeShellSessions:{Schema:1,Index,RootRevision,Sessions,Next,Total}`, `NodeShellRootRevision` |

`Nodes`는 `{Node,Shell,Sudo,Enabled,Ready,NotReady?}`이고 `Grants`는 `{User,Nodes:[node ID,...]}`다. `Sessions`는 최대 8개이며 원 SessionID의 문자열 오름차순이다. `State=open`은 queued/opened/closing, closed는 종료, 생략/빈 값은 전체 상태다. `Node`는 선택 노드 ID이며 생략/빈 값이면 모든 허용 노드다. closed의 공개 목록은 노드별 최근200개(ClosedAt 내림차순, 동률 SessionID 오름차순 선택)이며 열린 세션은 숨기지 않는다. 현재 사용자 권한·보존 한도·필터를 적용한 뒤 `Total`과 페이지를 계산한다. Total은 After와 무관한 해당 조건의 전체 공개 수, Next는 다음 페이지가 있을 때만 마지막 반환 ID다. 같은 필터에서 Next를 After로 보낸다. 목록 숨김으로 원 operation 결과/서명/owner receipt/event를 삭제하지 않는다. 관리자는 전체, 그 밖의 `node-shell` scope 사용자는 자기 grant/노드·자기 세션만 읽는다. 현재 계정·credential·issuer와 scope를 매 조회 확인하며 과거 grant가 현재 접근권을 대신하지 않는다.

변경은 같은 User `submit/result/resume`의 `UserOperation`이다. `Change.Action`·Payload와 policy CAS를 서명하고 `control/node-shell` checkpoint에서 확정한다. 관리 변경의 RootRevision과 아래 정책 Expected를 구분한다.

| Action | Payload | Expected·권한 |
|---|---|---|
| `set-node-shell-policy` | `{Enabled:bool,MaxSessions:int,IdleSeconds:int}` | 공유 Policy.Revision, 현재 system-admin/ManageCluster |
| `set-node-shell-node` | `{Node:string,Shell:"inherit"\|"on"\|"off",Sudo:bool}` | 같은 Policy.Revision·현재 관리자, 설치된 Node |
| `set-node-shell-grant` | `{User:string,Nodes:[string,...]}` | 같은 Policy.Revision·현재 관리자, 등록 User/설치 Node. 빈 Nodes는 회수 |
| `open-node-shell` | `{Node:string,Cols:uint16,Rows:uint16}` | 0. 현재 global `node-shell` scope와 해당 사용자 grant, effective enabled/Ready/한도 |
| `close-node-shell` | `{SessionID:string}` | 0. 현재 관리자, 원 세션 ID |

open의 `UserOperation.RequestID`가 원 SessionID다. open 수락은 queued 예약이며 실제 SSH PTY Ready와 다르다. 같은 ID의 결과/재개는 원 record를 보존하고 다른 PTY를 만들지 않는다. Policy.MaxSessions는 1–16, IdleSeconds는 60–86400, Cols/Rows는 1–1000이다. 시스템 관리자 계정의 grant 생략도 session의 `node-shell` scope를 생략하는 규칙이 아니다. credential Operations와 독립 사용자 승인도 동일하게 적용한다.

### purpose19 요청·응답

Unix는 kind1만 새 요청으로 허용한다. kind3은 원 사용자 Envelope/Body/서명을 보존하는 설치 member 간 relay 전용이며 Unix에서 받지 않는다. kind2는 응답, kind5는 후속 record이고 kind4는 없다. 공통 frame의 schema는 1, Request는 0이 아닌 원 wire 교환 번호다. wire Request와 원 SessionID는 서로 다른 식별자다.

| kind | TLV1 | TLV2 |
|---|---|---|
| 1 | `Envelope{Body,Session,Signature}`의 정규 JSON | 해당 Envelope 바이트의 SHA-256, 32바이트 |
| 3 | 위 원 사용자 proof에 signed member `Relay`를 붙인 Envelope | 해당 relay Envelope의 SHA-256 |
| 2 | `NodeShellReply{Schema:1,Code,Session?}` JSON | **그 연결의 원 요청 Envelope** SHA-256 |
| 5 | 아래 NodeShellRecord JSON | **원 NodeShellRequest Body 바이트** SHA-256 |

Envelope.Body는 정규 `NodeShellRequest{Schema:1,SessionID:string,Nonce:[32]byte}`의 bytes다. SessionID는 이미 수락된 원 작업 ID, Nonce는 0이 아닌 32바이트이며 새 stream 요청에 생성한다. Envelope의 bytes/서명은 JSON base64, 고정 `[32]byte`는 32개 정수의 JSON 배열이다. proof는 현재 연결 challenge와 Body에 결합한다. nonce/새 wire Request가 원 operation이나 SSH 실행을 새로 만드는 권한은 아니다.

Code=`ready`에는 열린 원 `Session`이 필수다. 나머지 `forbidden|node-shell-disabled|node-shell-not-ready|limit|node-unreachable|unavailable`에는 Session이 없다. 거부 응답은 방향 EOF를 확인하고 닫는다. ready 후에는 요청 방향 transport EOF를 먼저 기다리지 않고 양방향 record를 처리한다.

공개 Session 형식은 다음과 같다. 값이 0/빈 값인 일반 필드도 JSON에 남으며 `End`만 nil일 때 생략한다. 공유 원 Origin·준비 증거·개인키·SSH 설정 경로는 이 형식에 포함하지 않는다.

```text
{
  SessionID, User, Username, Node, Account: string,
  Sudo: bool,
  CreatedAt, OpenedAt, LastActivity, ClosedAt: int64 Unix초,
  BytesIn, BytesOut: uint64,
  State: "queued" | "opened" | "closing" | "closed",
  End?: {Code: int, Reason: "exit" | "idle" | "closed" | "policy",
         ClosedBy?: {User: string, Username: string}}
}
```

### kind5 record와 종료 주체

형식은 `NodeShellRecord{Schema:uint8=1,Sequence:uint64,Kind:string,Data?:bytes,Cols?:uint16,Rows?:uint16,End?:NodeShellEnd}`다. 선택 필드는 nil/0이면 생략하며 해당 kind 외 payload를 섞으면 거부한다. 단일 Data는 최대 24KiB이고 frame body는 128KiB 이하다. 두 방향의 Sequence는 1부터 각각 정확히 1씩 증가하고 같은 wire Request·Body digest를 유지한다.

| 방향 | Kind | 필드·효과 |
|---|---|---|
| client→owner | `stdin` | 비어 있지 않은 base64 Data. 입력 half-close 전만 허용 |
| client→owner | `resize` | Cols/Rows 각각 1–1000. 원 SSH PTY 크기 변경 |
| client→owner | `half-close` | payload 없음, 1회. SSH 입력 EOF를 보내고 출력 수신 유지 |
| 양방향 | `ping` | payload 없음. server가 client ping에 ping으로 응답하며 byte activity가 아님 |
| owner→client | `stdout` | 비어 있지 않은 base64 Data. PTY의 stdout/stderr를 한 흐름으로 전달 |
| owner→client | `end` | End 필수, Data/Cols/Rows 없음. 이 방향의 terminal record |

End.Code는 0–255다. `Reason=closed|policy`에는 비어 있지 않은 유효 UTF-8의 `ClosedBy:{User,Username}`가 필수이고 제어문자를 금지한다. 명시 close 또는 권한/정책 변경을 승인한 **원 사용자**를 기록한다. `exit|idle`에는 ClosedBy를 넣지 않는다. wire에 임의의 종료 사용자를 넣어 공유 CloseOrigin을 대체할 수 없다.

```json
{"Schema":1,"Sequence":1,"Kind":"stdin","Data":"aWQK"}
{"Schema":1,"Sequence":2,"Kind":"half-close"}
```

서버 종료 record의 예시는 `{"Schema":1,"Sequence":7,"Kind":"end","End":{"Code":0,"Reason":"closed","ClosedBy":{"User":"admin","Username":"operator"}}}`다. 이는 일반 `Kind=end`와 달리 종료 코드/이유를 포함한다. end 뒤 record, sequence 재전송/누락/overflow, 방향 위장, 중복 half-close나 그 뒤 stdin을 거부한다. `half-close`는 transport record의 length=0 EOF나 전체 TLS 연결 종료가 아니다.

설정/stream 수립은 최대 10초, 인증된 채널 read-idle은 60초, write는 5초이며 원 session 만료를 적용한다. CLI는 10초 ping을 보내고 실제 stdin/stdout bytes만 제품 idle clock을 갱신한다. purpose19 동시 handler는 Transport당 64개다. Unix도 전용 연결을 반환/닫기 전까지 동일 stream을 소유한다. 정상 end 없는 EOF·부분 frame·context 종료는 정상 exit가 아니며 원 unknown/receipt를 유지한다. 자동 재접속·새 SSH 실행은 하지 않는다.

### 내부 owner 메시지와 감사

다음은 인증된 member Management=2의 내부 메시지이며 Unix 사용자 method가 아니다. 현재 설치된 대상 node key와 최신 quorum을 확인하고 원 원격 사용자 승인 대신 새 사용자 operation을 만들지 않는다.

| Method | 입력 | 응답/의미 |
|---|---|---|
| `node-shell-owner-view` | `{Node,Report?:NodeShellReport}` | `{Book,Epoch,RootRevision,Result?,Rejected?}`. 자기 원 노드의 정책/기록과 원 보고 결과를 읽는다 |
| `node-shell-permit` | `{SessionID}` | `{Record,IdleSeconds,PolicyRevision}`. 현재 사용자·정책·원 owner·준비 검사, 새 SSH 실행 전/계속 실행 권한 |
| `node-shell-report` | 서명된 NodeShellReport | 기존 ModuleReport 결과. 준비/open/activity/실제 종료 관측 게시 |

NodeShellReport 필드는 `Schema:1,Cluster:[32],Reporter:[32],Node,PolicyRevision,Epoch,RootRevision,RequestID,At,LastActivity,Kind,SessionID,Ready,NotReady,Sudo,BytesIn,BytesOut,Sequence,Code,Reason,Signature`다. 시각은 Unix 초, Kind는 `ready|opened|activity|closed`이고 Signature는 `mydc-node-shell-report-1\0` 뒤 Signature=nil인 정규 JSON의 Ed25519 서명이다. 준비에는 SessionID/byte 수/종료 payload를 섞지 않고, session 보고에는 Ready/NotReady/Sudo를 섞지 않는다. 새 보고는 현재 설치 키만 제출하고, 원 수락/보고 bytes와 알려진 결과는 재개에서 보존한다. 보고 payload의 `RequestID`와 Raft command ID는 구분한다. ModuleReport command의 `RequestID`는 공통 `state.ReportRequestID(command)`가 산출하는 `checkpoint/<digest>`이며 원 서명이 포함된 전체 payload/CAS에 결합한다.

공개 event의 kind는 `node-shell-denied|node-shell-opened|node-shell-closed`다. Detail에는 기존 `Actor,Operation,Code?,Reason?,ExitCode?`와 선택 `BytesIn,BytesOut,ClosedBy:{User,Username}`만 담는다. 0 byte 수·nil ClosedBy는 생략하여 해당 필드가 없던 event JSON을 유지한다. closed/policy의 종료 actor는 서명된 원 변경에서 도출하며 화면·stdin·명령문·키·원 SSH 오류를 event에 넣지 않는다.

