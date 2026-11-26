## User 메시지 목록

아래 표는 현재 Unix User handler가 처리하는 **45개 전체 Method 목록**이다. 별도 URL/path는 없으며 모두 User kind1의 `Envelope.Body.Method`로 구별한다. `S`는 현재 Session과 연결 서명이 필요하다는 뜻이다. S 외에도 현재 계정·tenant 권한·정책·quorum 검사가 적용된다. 응답 열은 Reply의 주요 필드다.

### 최초 등록·로그인·계정

| Method | 인증·입력 | 응답·의미 |
|---|---|---|
| `enroll-admin` | bootstrap anchor 서명; UserKey, Enrollment | Result, Found: 빈 catalog에 최초 system admin을 명시 등록 |
| `challenge` | 세션 없음; Username, UserKey | Ticket: 등록 개인키 로그인 도전 |
| `login` | 세션 없음; Ticket, Proof | Session: 같은 연결에 묶인 개인키 proof 검증 |
| `credential-challenge` | 세션 없음; Username, AuthMethod=`password` 또는 `token`, 선택 Credential | Ticket: 보호 backend 자격 선택 |
| `credential-login` | TLS client key 서명; Ticket, Secret | Session: 비밀번호/토큰 검증. AuthMethod/Username/Credential은 이 단계에서 생략 |
| `users` | S; 선택 After, Tenant/Node/TargetUser 없음 | Users, UsersNext, UsersRevision, RootRevision. 현재 system-admin + 서명 ManageCluster. 공개 credential만 반환하고 VerifierRef 필드 없음 |
| `tenant-members` | S; Tenant 필수, 선택 After, Node/TargetUser 없음 | TenantMembers, TenantAllowedNodes, TenantMembersNext, TenantRevision, TenantMembersRevision, RootRevision. 대상 tenant의 현재 ManageMembers + 서명 scope 필수 |
| `my-credentials` | S; Tenant/After/Node/TargetUser 없음 | SelfCredentials: 현재 로그인 계정의 공개 credential과 Revision. verifier 참조 없음 |
| `tasks` | S; 선택 Tenant/App/Node/After | Tasks, TasksNext, TasksRootRevision. 현재 Read·tenant/허용 node로 먼저 거른 Task·관측 페이지. [행 형식·한도](../task-observability.md) |
| `node-summary` | S; 선택 Tenant/Node/After | NodeSummary:{Nodes,Next,RootRevision,CanAcceptChanges}. tenant Read의 허용 node·자기 사용량 또는 명시 system-admin 전체 현황 |
| `node-disks` | S; 선택 Tenant/Node/After | NodeDisks:{Disks,Next,RootRevision}. 전체 system-admin, tenant ManageVolumes의 허용 root만 먼저 골라 파일시스템별 합산 |
| `node-tenant-usage` | S; Node 필수, 선택 After, Tenant 금지 | NodeTenantUsage:{Usage,Next,RootRevision}. system-admin의 노드별 tenant 사용량8행 |
| `mesh-links` | S; 선택 Tenant/Node/After | MeshLinks:{Links,Next,RootRevision}. 전체 관리자 양쪽 지표, tenant Read는 허용 node 쌍 상태 요약 |
| `raft-status` | S; 선택 After, Tenant/Node 금지 | RaftStatus: system-admin의 로컬 SDK/내구 FSM·복제 ACK·snapshot/선거/ledger 진단. 리더 전달·quorum 대기 없이 마지막 적용 정책으로 인증 |
| `app-source` | S; Tenant·AppSource 필수, After/Node/TargetUser 없음 | AppSource:{Section,Version,RootRevision,Part,Data,Pending?}. 24KiB source/local-services/overlays/pending-local part(pending-local은 Pending이 문서를 고정), 고정 버전·Section별 digest와 현재 tenant Read |
| `app-revisions` | S; Tenant·AppSource{App,Deployment?} 필수, 선택 After | AppRevisions, AppRevisionsNext, AppRevisionsRootRevision. 원문 버전16행/64KiB, 현재 권한과 root 고정 cursor |
| `user-credentials` | S; TargetUser, Tenant/After/Node 없음 | CredentialUser: system-admin/ManageCluster 전용 전체 공개 User record·계정 Revision. private-key 원문·password/token 값은 없음 |
| `node-cli-policy` | S; Tenant/After/Node 없음 | NodeCLI: system-admin/ManageCluster 전용 `{Revision:uint64,disable_node_cli_operation:bool}`. 미변경은 revision0/false |
| `whoami` | S | User, 각 root revision, LedgerRootRevision 등 현재 계정/관리 기준 |
| `tenants` | S | Tenants: 현재 접근 가능한 tenant |
| `select-tenant` | S; Tenant | Tenant: 현재 접근 검사. 서버에 연결별 기본 tenant를 생성하지 않음 |

관측 행/단위·quota와 실제 사용량·stale/unknown·반환 한도·단절 시 인증은 [노드 관측 API](../node-observations.md)를 따른다. 일반 관측 페이지는8행, Raft node 페이지는32행이다.

### 원 관리 변경·조회·재개

| Method | 입력 | 응답·의미 |
|---|---|---|
| `submit` | S; Operation | Result, Found: 현재 인증/서명/CAS로 원 관리 변경 제출 |
| `result` | S; **원 Operation 그대로** | Found, Result: 원 결과 조회. 없다는 응답이 미실행 증명은 아님 |
| `resume` | S; **원 Operation 그대로** | Result, Found: 현재 권한으로 동일 원 명령의 명시 재개. 새 ID/CAS로 대체하지 않음 |

node 추가/삭제, tenant·망·Volume·Vault 정책 변경 같은 쓰기는 각기 다른 wire Method를 만들지 않고 `submit`의 `Operation.Change.Action/Payload`로 전달한다. CLI 대응은 [명령 대상표](../../architecture/command-targets.md), typed 변경은 [control](../../../internal/cluster/control/catalog.go)을 따른다.

### 클러스터·노드·관리 자원

| Method | S 이외의 입력 | 응답 |
|---|---|---|
| `members` | 선택 After | Members, MembersNext, NodeLifecycle, NodeRuntimeRevision, NodeOperationEpoch, NodeConfigurationIndex, NodeVoters, NodeQuorum |
| `node-invitation` | Node | Invitation: 승인된 ID/key/endpoint/Join ID에 묶인 서명 초대 |
| `node-storage` | 선택 Node, After; Tenant 없음 | NodeStorage, NodeStorageNext, NodeStorageRootRevision, NodeStorageRevision |
| `node-storage-space` | NodeStorage; Tenant/After 없음 | NodeStorageSpace, NodeStorageObservedIndex |
| `tenant-retirement` | Tenant, 선택 After | TenantRetirement: tenant 종료·owner 정산 상태 |
| `resources` | 선택 Tenant, After | Resources, ResourcesNext, ResourcesRootRevision, ResourceRevision, ResourcesViewIndex, NetworkRevision, QuotaRevision |
| `legacy-resource-closure` | LegacySource | LegacyTarget, LegacyRetirement: 정확한 기존 참조의 종료 근거 |

### 앱·CD

| Method | S 이외의 입력 | 응답 |
|---|---|---|
| `apps` | 선택 Tenant, After | Apps, AppsNext, AppsRootRevision, AppRevision |
| `service-call` | Tenant, ServiceCall, ServiceInput; continue 뒤 kind4 본문·EOF | ServiceCall: 현재 CallService·원 Task/owner 검사 후 한 번 POST. HTTP Status/Content-Type/본문 또는 제한 코드. 자동 재전송 없음 |
| `cd-probe` | Tenant, CDProbe | CDProbe: 현재 Deploy·기존 앱/설치 credential로 고정 Commit·Size·Node 또는 제한 코드. CD/app 변경 없음 |
| `app-log-clear-plan` | Tenant, LogClear(서비스/선택 instance, 빈 Operation) | LogClearPlan: Read/Deploy·실제 local/json-file 대상/파급 계획. 원 effect 없음. |
| `app-log-clear-status` | Tenant, LogClear(App/Operation만) | LogClearStatus: 현재 Read 권한의 원 정리/교체 결과. |
| `app-operation` | Tenant, AppOperation | AppOperation: 특정 앱/원 operation 상태. 지금 배포라면 Waiting에 아직 시작되지 않은 단계와 그 서버·기다리는 의존 단계, 그리고 그 tenant의 TUN 망을 열지 못한 서버의 이유(Host.TunnelWaits)를 최대 8개씩 문장으로 담는다. 상태 표시용이고 허가 판단에 쓰지 않는다 |
| `app-cd-field` | Tenant, AppCDField{App,Path,Part?,Digest?} | AppCDField: 명시 앱 field/override/참조와 Values 또는 ValuesPart. Git/현재 값 분리 |
| `app-cd-history` | S; Tenant, AppCDRead{App}, 선택 After | AppCDHistory: 후보/원 실행 이력16행, 현재 history/권한 고정 cursor |
| `app-cd-diff` | S; Tenant, AppCDRead{App,Part,Digest} | AppCDSnapshot: 원 후보와 수락 실행의 서비스 field diff JSON 조각, 같은 ChangeCount |
| `app-cd-registration` | Tenant, AppCDApproval | AppCDRegistration: 원 등록 operation·선택·승인이 필요한 realm |
| `app-uploads` | Tenant, 선택 After | Uploads, UploadsNext |
| `app-plan` | Tenant, AppPlan | AppPlan: digest/길이에 고정된 계획의 한 part |
| `app-plan-stream` | Tenant, AppPlan, AppInput; 후속 kind4 입력 | continue 뒤 여러 kind2의 AppPlan part. 아래 전송 순서 참조 |

### Volume·Vault

| Method | S 이외의 입력 | 응답 |
|---|---|---|
| `volumes` | 선택 Tenant, After | Volumes, VolumesNext, VolumesRootRevision, VolumeRevision |
| `volume-restores` | 선택 Tenant, After | VolumeRestores, VolumeRestoresNext |
| `volume-backups` | 선택 Tenant, After | VolumeBackups, VolumeBackupsNext |
| `volume-usage` | Tenant, VolumeUsage | VolumeUsage, VolumeUsageIndex |
| `volume-backup-source` | Tenant, VolumeSource | VolumeSource, VolumeSourceIndex |
| `vault` | 선택 Tenant, After | Vault, VaultNext, VaultRootRevision, VaultRevision, VaultTreeRevision, VaultWriteEpoch, VaultApprovalRevision: 공개 metadata |
| `vault-approval-plan` | Tenant, VaultPlan | VaultPlan: Secret Group 승인 대상 계획 part |
| `vault-write-plan` | Tenant와 VaultWritePlan.Realm 일치, VaultWritePlan | VaultWritePlan: 보호 원문 없이 provider/원 write 계획 |

### Lifecycle script·registry

| Method | S 이외의 입력 | 응답 |
|---|---|---|
| `lifecycles` | Tenant, 선택 After | Lifecycles, LifecyclesNext, LifecycleRootRevision, LifecycleRevision |
| `checker-source-stage` | Tenant, CheckerSource, 선택 CheckerUpload; 후속 kind4 | continue 뒤 CheckerSource 서명 사실 |
| `checker-source-recover` | 같은 source 선택, 원 CheckerUpload가 있으면 보존 | CheckerSource: 원 저장 사실 조회, source 원문 재전송 없음 |
| `checker-module-stage` | Tenant, CheckerSource, CheckerModule, 선택 CheckerUpload; 후속 kind4 | continue 뒤 CheckerModule 서명 사실 |
| `checker-module-recover` | 같은 source/module 선택, 원 CheckerUpload가 있으면 보존 | CheckerModule: 원 module 저장 사실 조회 |
| `registries` | Tenant, 선택 After | Registries, RegistriesNext, RegistriesRootRevision, RegistriesRevision |
| `external-registries` | Tenant, 선택 After | ExternalRegistriesRootRevision, ExternalRegistriesNext, ExternalRegistries: 공개 source 참조·선택 reader metadata |
| `external-registry-bind-plan` | Tenant, ExternalRegistryBind:{ID,Node} | ExternalRegistryBindPlan: source 지문·record/root CAS·epoch·realm별 공개 Uses |
| `image-usages` | Tenant, ImageUsage:{Refs?,ExternalSource?}, 선택 After | ImageUsages:{Schema,Tenant,Root,Index,Rows,Next}. Read 또는 ManageRegistry, 16행/페이지 |
| `image-resolve` | Tenant, ImageResolve:{Ref} | ImageResolve: 정규화·managed/external/unknown source·현재 Trust·제한 Code·Image digest/index/platform. Read 또는 ManageRegistry 필요 |
| `external-registry-pulls` | Tenant, 선택 After | RegistryPulls:{Schema,Tenant,Root,Index,Rows,Next}. 실제 pull 결과 8행/페이지, 현재 Read 또는 ManageRegistry |
| `registry-catalog` | Tenant, RegistryCatalog:{Kind,ID,Repository?}, 선택 After | RegistryCatalog:{Kind,ID,Page}. 내장/외부 목록·metadata 8행/페이지, 현재 Read 또는 ManageRegistry |
| `registry-maintenance-plan` | Tenant, RegistryMaintenance:{Action,ID,Repository,Reference,Digest,External?}; Operation은 빈 문자열 | RegistryMaintenancePlan:{Schema,Cluster,Tenant,Action,Expected,RootRevision,Epoch,Change,InUse}. 현재 ManageRegistry·동작 제한 필요 |
| `registry-prune-preview` | Tenant, RegistryPrune:{ID,External?,Part,Conditions,Fact?}, 선택 After | RegistryPrune:{Schema,Tenant,Plan,Page}. ManageRegistry의 서명된 일괄 선택, 8행/페이지 |
| `registry-prune-results` | Tenant, RegistryPrune:{Operation,Part:"items"}, 선택 After | 같은 원 부모의 항목별 사유/Native 결과. 현재 Read 또는 ManageRegistry |
| `registry-maintenance-status` | Tenant, RegistryMaintenance:{Operation}; 나머지 선택은 비움 | RegistryMaintenanceStatus:{Schema,Tenant,Operation,Action,User,State,Revision,RootRevision,At,Change,Result?}. 현재 Read 또는 ManageRegistry |
| `registry-login-test` | Tenant, ExternalRegistryProbe:{ID,Image?} | ExternalRegistryProbe: 선택 source 세대·owner·At·제한 Code, 성공 시 선택 Image/Pull metadata. ManageRegistry 필요 |
| `registry-credential` | Tenant, Registry | RegistryCredential(base64), RegistryAuthority, RegistryCredentialExpires: 제한된 단기 자격. login 권한 요청은 거부 |

`users`·`tenant-members`의 정확한 행 형식·페이지 한도·revision 충돌은 [사용자·구성원 조회](../user-catalog.md)를 따른다. 기존 user-credentials의 공개 필드 이름/타입을 재사용하지만 목록에는 보호 backend의 VerifierRef를 포함하지 않는다. 구성원 조회는 tenant의 명시 membership과 암묵적 활성 system-admin을 보여 주며 credential 목록은 노출하지 않는다.

페이지의 다음 cursor는 응답의 `*Next`를 그대로 다음 Request.After로 보낸다. After는 최대512바이트이며 위에서 표시한 페이지 method만 허용한다. `tenant-retirement`의 cursor는 TenantRetirement 객체 안에 있다. 페이지 크기를 클라이언트가 임의로 지정하는 필드는 없다. revision이 바뀐 페이지를 하나의 snapshot으로 합치지 않는다.

