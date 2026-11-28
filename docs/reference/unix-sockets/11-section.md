## 중첩 객체 포맷

아래 `{Field:type,...}`는 타입 표기이며 실제 JSON 원문이 아니다. `?`는 선택 필드다. 타입별 필드 순서와 생략 규칙의 최종 기준은 연결된 제품 struct다.

### 로그인 증거

| 객체 | 필드 |
|---|---|
| Ticket | `Schema:uint8, Cluster:key32, User:string, Username:string, Credential:string, AccountRevision:uint64, SessionKey:key32, UserKey:key32, Challenge:nonce32, Nonce:nonce32, Issuer:key32, IssuedAt:int64, Deadline:int64, Signature:bytes, AuthMethod?:string, VerifierRef?:string` |
| KeyProof | `Schema:uint8, Cluster:key32, User:string, Username:string, Credential:string, Challenge:nonce32, SessionKey:key32, Deadline:int64, Signature:bytes` |
| Session | `Schema:uint8, ID:string, Cluster:key32, User:string, Credential:string, AccountRevision:uint64, Key:key32, Issuer:key32, IssuerEpoch:uint64, IssuedAt:int64, ExpiresAt:int64, Scopes:Scope[], Signature:bytes, Approval?:SessionApproval` |
| SessionApproval | `Schema:uint8, PublicKey:key32, Session:key32, Signature:bytes` — 같은 계정에 등록된 사용자 키의 독립 session 승인 |
| Scope | `Tenant:string, Actions:string[]` |
| Enrollment | `Schema:uint8, RequestID:string, User:User` |
| User | `ID:string, Username:string, Revision:uint64, Enabled:bool, SystemAdmin:bool, Credentials:Credential[]` |
| Credential | `ID:string, Method:string, PublicKey:key32, VerifierRef:string, Enabled:bool` |

시각 값은 Unix 초 정수다. Ticket은 발행 후300초, Session은 최대3600초다. Ticket/KeyProof/Session 서명은 각각 `sfc-user-login-ticket-1\x00` / `sfc-user-key-proof-1\x00` / `sfc-user-session-1\x00` domain과 Signature=nil로 직렬화한 canonical JSON에 결합한다. credential-login의 Envelope.Signature는 TLS client key로 `"sfc-user-credential-login-1\x00" || cluster32 || clientKey32 || serverChallenge32 || SHA256(Body)`에 서명한다. 최초 enroll-admin은 bootstrap 관리자 키로 `"sfc-admin-enrollment-1\x00" || cluster32 || clientTLSKey32 || serverChallenge32 || Body`에 서명한다. 이 단계에는 Session을 넣지 않는다. 인증 경로의 상세는 [session.go](../../../internal/access/session.go)・[credential.go](../../../internal/userauth/credential.go)・[enrollment.go](../../../internal/userauth/enrollment.go)를 참조한다.

Session issuer 서명은 `Approval`을 제외한다. `SessionApproval.Session`은 `SHA256("sfc-issued-user-session-1\x00" || canonicalJSON(Session{Approval:nil}))`로, issuer Signature까지 포함한 정확한 grant를 고정한다. 사용자 서명은 `"sfc-user-session-approval-1\x00" || canonicalJSON(SessionApproval{Signature:nil})`에 결합한다. `Approval:nil`은 JSON에서 생략하므로 기존 schema1 session/issuer 서명은 바뀌지 않는다. 개인키 login은 확인한 grant에 그 사용자 키로 승인하고, password/token login은 명시 wallet 키를 사용할 수 있다. 승인 키는 원 login credential을 교체하거나 token scope를 넓히지 않는다. 현재 계정 revision·활성 private-key credential과 일치해야 한다. 승인 증거를 받지 않는 구형 peer로 자동 fallback하지 않는다.

`node-remove-plan`·`node-demote-plan`·`node-force-remove-plan`도 같은 User record/frame·EOF·session 검증과 latest quorum 경계를 사용한다. 입력/응답과 원 `Result.Reason`의 보존 규칙은 [노드 운영 SFCP 계약](../../protocol/sfcp.md)을 따른다. force 계획은 원 operation을 지정하고 별도 인증된 노드 간 Management status probe를 수행하므로 Unix 접속 자체나 이전 node-summary timestamp를 미응답 증거로 사용하지 않는다. 실제 force 변경은 원 signed UserOperation/CAS에 probe를 고정하며 논리 retired와 owner native closure를 구분한다.

`node-drain-plan`의 `Params:{Node,Operation}`·`node-drain-status`의 `Params:{Node,Operation}`(비우기 기록이 없으면 `missing`)과 `node-diagnostics`의 `Params:{Node}`, `node-logs`의 `Params:control.NodeLogsQuery`도([typed method](10-user.md#typed-method)) 같은 User session/record·유한 응답/EOF 경계를 사용한다. drain/rotate-identity 변경은 기존 signed UserOperation/journal/CAS에 고정하며 Unix UID로 관리 권한을 대체하지 않는다. status에서만 Operation을 빈 값으로 보내면 그 노드의 진행 중 원 drain을 우선하고, 없으면 가장 최근 것을 조회한다. 여러 후보는 Directory에 확정된 등록 순서의 최근 것을 선택하며 응답 `Data.Operation`은 실제 원 ID다. 명시 ID는 그 작업만 읽고, 기록이 없으면 `missing`이다(권한이 없으면 denied). 시스템 관리자 권한은 그대로이며 plan/변경의 원 ID 필수 조건을 완화하거나 새 drain을 만들지 않는다. 진단은 owner가 별도 authenticated Management permit의 quorum index까지 로컬 durable prefix를 기다리고 session/target/epoch/현재 권한을 재검사한 뒤 압축64KiB·확장128KiB tar.gz allowlist를 반환한다. `ReadAtLeast` 뒤 Local 표시는 이 barrier의 정상 결과다. 진단에 원문 설정/환경·Secret/키·자유 형식 로그/오류를 넣지 않으며 CLI는 기존 파일을 덮어쓰지 않고0600으로 저장한다. 신원 전환은 원 Unix listener/연결 join 뒤 동일 설치 socket을 새 TLS runtime으로 다시 연다. 과거 node key·session issuer를 현재 인증 fallback으로 쓰지 않는다.

managed cluster의 새 login issuer는 현재 설치된 활성 control voter다. non-voter의 개인 키 login은 leader로 relay해 leader가 발급한다. password/token login과 격리 issuer의 login은 `not-session-issuer`로 거부하며 활성 control의 기존 pin으로 명시 접속한다. 활성 follower는 비밀번호/토큰을 relay하지 않고, node Management의 `status` 최신 barrier와 로컬 복제 prefix를 결합하여 직접 인증한다. 이 node 간 status에는 사용자 자격을 넣지 않는다. 클러스터 공통 `disable_node_cli_operation`은 기본 false다. true인 현재 요청은 같은 계정의 등록 사용자 키 승인과 system-admin/대상 tenant-manager 권한을 요구한다. Directory의 등록 node key는 승인 키로 거부한다. 인증 직후 grant 발급과 현재 관리 요청을 구분하므로 password/token login 자체는 유지한다. 원 accepted grant/result·내부 owner 정산은 보존한다.

유한 container-observe 응답의 선택 `Container.LogDriver`는 native driver/plugin 이름이며 logger options나 backend 자격을 담지 않는다. 생략을 local/json-file로 추정하지 않는다. 명시 삭제/교체는 별도 사용자 작업이다.

### UserOperation — 내구 관리 변경

| 필드 | 타입·의미 |
|---|---|
| `Schema`, `Session`, `At` | uint8=1, 원 Session, int64 Unix초 |
| `Epoch`, `RequestID`, `RootRevision` | uint64 요청 보존 window, string 원 ID, uint64 root CAS |
| `Change` | `{Schema:uint8,Action:string,Principal:string,Expected:uint64,Payload:json.RawMessage}` |
| `Signature` | bytes: 원 session key로 `sfc-user-operation-1\x00` + Signature=nil인 operation JSON 서명 |

CAS 경계(upload·app-down·app-field·standalone 관리 의도)는 따로 표시하는 필드가 없다. 서버가 `Change`(Action과 payload의 Target)에서 정한다.

새 submit의 At는 미래일 수 없고 현재보다300초 넘게 오래된 입력은 거부한다. result/resume에는 **처음 서명한 operation**을 보낸다. 현재 Envelope.Session으로 다시 인증하더라도 원 Session/At/ID/서명을 바꾸지 않는다. Change.Payload는 Action별 typed JSON이며 [operation.go](../../../internal/cluster/control/operation.go)의 원 명령 변환/검증을 따른다.

standalone-up/pin/remove/stop/start/restart/extend의 관리 의도 CAS는 payload Target으로 정해진다. `standalone-list/get`의 각 `StandaloneView.Target`은 digest32이며 pin/remove payload는 `{Tenant,Name,NewName,Restart,Operation,Target?:digest32}`다. up은 기존 `AppBegin.Target`, stop/start/restart는 `TaskRestartPlan.Target`과 선택 `ManagementTarget:digest32`를 같은 `TaskRestartChange`에 보존한다. 이 모드는 현재 관리 의도·정확한 native 제어 대상 일치와 미래 revision 거부를 검사하며 연결/진행 관측의 변경은 제외한다. 결과 유실 뒤 새 Target으로 원 요청을 다시 서명하지 않는다. [단독 컨테이너](../standalone.md)를 따른다.

### CD 로컬 서비스 편집 메시지

별도 Method 없이 기존 User `submit/result/resume`의 signed Operation을 쓴다. Action은 `put-app-local-services` 또는 `clear-app-local-services`다. Payload는 `{Tenant:string,App:string,Upload:string,Registration:[32]byte,Digest:[32]byte,Revision:uint64,Services:[]string,Target?:[32]byte}`다. Registration은 원 CD 등록 digest, Revision은 정확한 이전 local revision이다. put의 Upload는 같은 사용자·tenant/app/deployment 소유의 완료 app-upload이며 Digest는 전체 YAML 바이트, Services는 정렬된 고유 새 서비스 이름이다. 서버가 실제 내용과 다시 대조한다. clear는 Upload 빈 문자열·Digest 영·Services 비어 있음을 요구한다.

Expected는 CD revision이다. nonzero Target은 앱 조회의 `CD.LocalTarget`으로 기존 ModuleAppCAS를 선택하며, Target 생략은 원 Apps root/CD revision의 strict CAS를 유지한다. local revision은 두 모드 모두 정확해야 한다. 새 schema/RPC·노드 권한은 추가하지 않는다. 현재 Deploy와 자원별 권한·원 등록 grant를 검사하며 성공은 미래 후보 편집이다. 원 실행/Secret 공급·종료는 별도 sync 계약이다. [세부 동작·CLI·재개](../cd-inspection.md#별도-로컬-서비스-추가분)를 따른다.

### Node CLI 보안 정책 변경

별도 wire Method를 추가하지 않고 `submit`의 UserOperation을 사용한다. `Change.Action="set-node-cli-policy"`, Principal은 현재 system-admin, Expected는 `node-cli-policy`로 조회한 정책 Revision이며 payload는 `{"disable_node_cli_operation":true}` 또는 false다. 같은 operation의 RootRevision은 기존 access catalog CAS다. managed root만 허용하며 on/off 모두 독립 등록 사용자 키 승인을 검사한다. 활성화 뒤 마지막 독립 관리자 키를 제거할 수 없다. 정책은 같은 catalog checkpoint에 저장되고 재시작/Snapshot에도 유지한다.

node 간 Management의 raw `submit/get/plan`은 활성 정책에서 거부한다. 내부 최신 `status`·Raft/Snapshot·원 result·정확한 owner 보고/permit/종료는 기존 인증/원 참조 검증을 계속한다. Unix User/SecretInput과 네트워크 User/relay는 동일한 현재 사용자 정책을 사용한다. 원 Operation의 Session/At/서명을 고쳐 승인 또는 새 issuer로 대체하지 않는다.

### 업무 선택·계획

| 필드/타입 | 객체 포맷 |
|---|---|
| AppOperation | `{App:string,ID:string}` |
| AppCDField | `{App:string,Path:string[]}` |
| AppCDApproval | `{App:string,Selection:AppApprovalSelection}` |
| AppApprovalSelection | `{Operation?:string,Candidate?:digest32}`: 정확히 하나의 원 operation 또는 candidate 선택 |
| AppInput | `{Length:int,Digest:digest32}`: 뒤따르는 전체 입력 길이/hash |
| AppPlan | `{SourceEnvelope?:bool,PrepareSources?:bool,SourceProvider?:key32,Move?:AppMovePlanRequest,Document:bytes,Project:string,Deployment:string,Node:string,Part:int,Digest:digest32,External?:map[string]map[string]NetworkBinding,Diff?:bool,CheckerSources?:map[string]SourceFact}` |
| AppPlan 응답 part | `{Digest:digest32,Length:int,Part:int,Data:bytes}`; Part는0부터, Data 연결 뒤 전체 길이/SHA256 확인 |
| 이관 AppMovePlan 원문 | `{Schema:1,Expected:uint64,Epoch:uint64,Begin:VolumeMoveBegin,Artifact:Blueprint,StoragePreflight?:MoveStoragePreflight}`; 기존 app-plan-stream으로 조립하는 JSON |
| MoveStoragePreflight | `{Node:string,State:string,RequiredBytes:uint64,AvailableBytes?:uint64,ObservedAt:uint64,ObservationMaxAge:uint64,MeasurementOnly:true}`; 시각/최대 나이는 밀리초. State=`available/insufficient/stale/unknown`. unknown에는 AvailableBytes가 없고 ObservedAt=0. 디스크 경로/장치/서명 원문은 반환하지 않음 |
| VaultPlan | `{Selection?:AppApprovalSelection,Realm:string,ID:string,Issuer:key32,Uses:Use[],Part:int,Digest:digest32,Origin?:UserOperation}` |
| VaultPlan 응답 part | `{RootRevision:uint64,Digest:digest32,Length:int,Part:int,Data:bytes}` |
| VaultWritePlan 입력 | `{Realm:string,ID:string,Object:string,Profile:string,Kind:string,Keys:string[]}`; Kind=`value` 또는 `verifier` |
| SourceDescriptor (CheckerStageQuery.Source) | `{Tenant:string,Digest:digest32,Length:uint64,SDK:uint8,Modules:ModulePin[]}`; SDK=1 |
| ModulePin | `{Path:string,Version:string,Digest:digest32,Length:uint64}` |

복합 계획/관측 응답은 [앱 계획](../../../internal/cluster/control/app_plan.go), [Vault 승인](../../../internal/cluster/control/vault_approval.go), [Vault 쓰기](../../../internal/cluster/control/vault_write_plan.go), [checker artifact](../../../internal/workload/lifecycle/artifact.go)의 공개 metadata 타입을 그대로 직렬화한다. 이는 Secret 원문을 반환하는 API가 아니다.

이관 계획의 StoragePreflight는 target node의 기존 서명 디스크 측정을 공개 숫자로 투영한 값이다. 현재 tenant의 ManageVolumes/Deploy와 installed key를 확인하고 오래됨/누락을 구분한다. 측정은 자원 예약·native 준비/실행 승인이나 transfer staging 공간 보장이 아니며, 실제 대상 준비에서 공간을 재확인한다. StoragePreflight가 없는 기존 저장 계획과 원 signed Begin/Artifact는 유지한다. [상세 CLI 계약](../../cli/volume.md#다른-서버로-옮기기)을 따른다.

