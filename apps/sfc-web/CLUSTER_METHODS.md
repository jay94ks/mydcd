# sfc-web ↔ sfcd method 상태표

sfc-web 데몬은 [`internal/web/sfc`](../../internal/web/sfc/client.go)의 `Client`/`Conn` 인터페이스로만 sfcd와 이야기한다. 실제 어댑터(`sfc.NewReal`, [real.go](../../internal/web/sfc/real.go))는 로그인마다 세션 키·SFCP transport·`userauth.Client`를 하나씩 만들어 `/run/sfcdp.sock`에 붙는다. 소켓 뒤 노드의 클러스터 ID·노드 ID·신원 키는 설정으로 고정한다. W1.2에서 모든 method를 옮겼다(가짜에만 맞춘 계약은 R15에서 sfcd 모양으로 바꿨다). 지금 실제 어댑터에 있는 것: 로그인(`CredentialChallenge`·`CredentialLogin`·`Challenge`·`Login`·`ApproveSession`·`Session`·`Close`), `Whoami`·`Tenants`·`SelectTenant`, `Prepare`·`PrepareRequest`·`Submit`·`Result`·`Resume`, 계정·서버 조회(`UserCredentials`·`OwnCredentials`·`Users`·`TenantMembers`·`NodeCLIPolicy`·`TenantRetirement`·`Members`·`NodeInvitation`·`NodeSummary`·`NodeDisks`·`MeshLinks`·`NodeStorage`·`NodeStorageSpace`·`TenantStoragePage`·`RaftStatus`·`Events`·`ServerVersion`·`NodeShellPolicy`·`NodeShellSessions`·`QueryNodeShellSessions`·노드 수명 계획 6개·터널·압축·이미지 캐시 계획/상태·`PublicRead`), 작업 공간의 단순 호출(볼륨 목록·파일 작업, 보관함 목록 한 페이지(경로는 server가 만든다)·계획, 앱 수명 단계·복구, CD·서비스 호출·작업 재시작, 외부 레지스트리·이미지 사용처·레지스트리 정리, 이미지 빌드와 초안, 인증서·인그레스 — [real_tenant.go](../../internal/web/sfc/real_tenant.go)). 화면 타입으로 바꿔 주는 목록: 앱·업로드·상태 검사·앱 원본·버전·작업, 작업 목록, 단독 컨테이너, 리소스(CLI처럼 모든 쪽을 한 revision으로 읽고 서버별 네트워크 행을 네트워크 하나로 묶는다), 레지스트리·외부 레지스트리, 볼륨 백업·복원·백업 원본 — [real_views.go](../../internal/web/sfc/real_views.go), [real_resources.go](../../internal/web/sfc/real_resources.go), [real_lists.go](../../internal/web/sfc/real_lists.go). 컨테이너: container-observe(logs·top·stats)와 inspect 상세로 만든 작업 상세·기록·로그·통계(통계는 sfcd가 기록을 두지 않아 지금 값 하나), 컨테이너 세션(resolve·의도 서명·open·exec 상태; 스트림은 세션 키 사본과 자기 transport를 가진다) — [real_containers.go](../../internal/web/sfc/real_containers.go), [real_stream.go](../../internal/web/sfc/real_stream.go). 그 밖에 작업 사유를 서명에 넣는 `PrepareReason`·`PrepareRequestReason`, `RegistryCredential`, `AccountScope`(계정 기록에서 읽음; `set-account-scope`는 sfcd action), `AppLogClearPlan`, `AppPlan`(단독 컨테이너 계획 포함; sfcd가 Changes·Impact·Limits 요약을 보내지 않아 `AppPlan.Standalone`은 비어 있다). CD 화면: 기록·변경 목록·필드 값·로컬 서비스 — [real_cd.go](../../internal/web/sfc/real_cd.go). 보관함 비공개 입력(`WriteVault`·`ApproveVault`): sfcd는 SecretInput을 중계하지 않으므로 받는 노드가 고정 노드면 소켓으로, 아니면 그 노드의 endpoint에 그 키만 믿는 transport로 직접 보낸다(웹 컨테이너가 노드 endpoint에 닿아야 한다) — [real_vault.go](../../internal/web/sfc/real_vault.go). 노드 셸(`OpenNodeShell`): server가 제출한 open-node-shell 원본의 ID로 채널을 열고, 컨테이너 스트림처럼 세션 키 사본과 자기 transport를 쓴다 — [real_node_shell.go](../../internal/web/sfc/real_node_shell.go). `Close`는 연결을 먼저 닫아 진행 중인 호출(긴 파일 전송 포함)을 끝내고, 그 호출들이 돌아온 뒤 세션 키를 지운다. 가짜 어댑터(`sfc.NewFake`)는 server 시험 대역으로 남는다. 책임 경계는 internal/web/AGENTS.md를 따른다.

이 표는 2026-11-24 main 코드에서 새로 만들었다(R04 1단계, devel/refactor/04). `Conn`의 method를 reflect로 읽고, 가짜의 wire 이름(`const m`), `userauth` 서비스의 method 목록·`Client` method와 맞췄다. 바뀌면 이 표도 같이 고친다.

상태:

- **실제**: 서버에 그 wire가 있고 `Conn`이 실제 제품 타입(`control`·`access`·`userauth`… 또는 그 별칭)을 돌려준다.
- **실제 호출·웹 타입**: 서버에 짝이 있지만 `Conn`이 웹이 만든 타입을 돌려준다. 실제 어댑터에서 변환이 필요하다. 아래 '반환 타입 대조'에 차이를 적었다. R04 2단계에서 실제 타입(별칭)으로 바꾸고 가공은 `internal/web/server`에서 한다.
- **확인 필요**: 짝이 될 서버 method를 아직 못 정했다.
- **서버에 없음**: sfcd에 그 기능이 없다(가짜만 있음).

개수: 실제 116, 실제 호출·웹 타입 24, 실제(웹 타입 같은 모양) 1 (모두 141). `IssueInitialCredential`은 웹 화면·server가 쓰지 않아 지웠다. `OperationReason`은 서명 원본에서 읽는 `sfc.SignedReason`으로 바꿨다(R15). `CDApprovers`와 `RelocationCheck`도 지웠다(승인자는 CD 기록, 이동 전 검사는 server가 AppPlan으로).

묶음은 R04 2단계 담당이다. 계정·서버는 데몬 스레드, 리소스·앱은 가짜 어댑터 스레드가 맡는다. 한 method의 반환 타입을 바꾸면 가짜와 server를 한 PR에서 같이 고친다.

Ticket·KeyProof·Session·SessionApproval·Change·UserOperation·Result는 실제 제품 타입의 별칭이라 서명 바이트와 bbolt에 저장하는 원 operation(`SignedOp`)이 sfcd와 같다.

## 계정·서버

| method | wire | 상태 | 실제 호출(`userauth.Client`) | 메모 |
|---|---|---|---|---|
| `AccountScope` | `my-credentials`·`users` | 실제 호출·웹 타입 | `MyCredentials`·`Users` | 계정 기록의 Operations·AutomationOnly |
| `ApproveSession` |  | 실제 | `access.AttachSessionApproval` | 교환 없음 |
| `CallService` | `service-call` | 실제 | `CallService` |  |
| `Challenge` | `challenge` | 실제 | `KeyLoginChallenge` |  |
| `Close` |  | 실제 |  | 로컬 |
| `CredentialChallenge` | `credential-challenge` | 실제 | `LoginCredential` |  |
| `CredentialLogin` | `credential-login` | 실제 | `LoginCredential` |  |
| `Events` | `events` | 실제 | `EventsPage` | `eventlog.Page`, 서버가 화면·웹훅·장애 감시용 행으로 바꾼다 |
| `ExecStatus` | `container-exec-status` | 실제 | `ContainerExecStatus` |  |
| `ImageCachePlan` | `image-cache-plan` | 실제 | `QueryImageCache(plan=true)` | `imagecache.Plan`(목록 8개씩 또는 선택 8개까지). 서버가 미사용 첫 8개를 정리 계획으로 보여 준다 |
| `ImageCacheStatus` | `image-cache-status` | 실제 | `QueryImageCache(plan=false)` | `control.ImageCacheStatus` |
| `Login` | `login` | 실제 | `KeyLogin` | Login(로컬 키)과 다름 |
| `Members` | `members` | 실제 | `MembersPage` | `membership.Entry`·`membership.NodeView` 그대로(Reply의 Members·NodeLifecycle·MembersNext·MembersRootRevision·Node* 칸). 화면 행은 `internal/web/server`가 ID로 합친다 |
| `MeshLinks` | `mesh-links` | 실제 | `NodeObservationPage` | 서버가 화면 행(초 단위)으로 바꾼다 |
| `NodeCLIPolicy` | `node-cli-policy` | 실제 | `NodeCLIPolicy` | `access.NodeCLIPolicy` |
| `NodeDisks` | `node-disks` | 실제 | `NodeObservationPage` | 서버가 화면 행(초 단위)으로 바꾼다 |
| `NodeDrainStatus` | `node-drain-status` | 실제 | `NodeDrainStatus` |  |
| `NodeInvitation` | `node-invitation` | 실제 | `NodeInvitation` |  |
| `NodeShellPolicy` | `node-shell-policy` | 실제 | `NodeShellPolicy` |  |
| `NodeShellSessions` | `node-shell-sessions` | 실제 | `NodeShellSessions` |  |
| `NodeStorage` | `node-storage` | 실제 | `NodeStoragePage` | `Page[nodestorage.Root]`, 서버가 화면 행으로 바꾼다 |
| `NodeStorageSpace` | `node-storage-space` | 실제 | `NodeStorageSpace` | `nodestorage.Space` + ObservedIndex |
| `NodeSummary` | `node-summary` | 실제 | `NodeObservationPage` | 서버가 화면 행(초 단위)으로 바꾼다 |
| `OpenNodeShell` | `open-node-shell` | 실제 호출·웹 타입 | `OpenNodeShell` |  |
| `OpenStream` | `open` | 실제 호출·웹 타입 | `OpenContainerSession` |  |
| `OwnCredentials` | `my-credentials` | 실제 | `MyCredentials` | `access.PublicUser`. 화면용 accountRevision은 server가 붙임 |
| `LoginRecords` | `login-records` | 실제 | `LoginRecords` | 자기 최근 로그인(`loginlog.Page`, 서버별 기록을 리더가 합침)과 `LoginBudget`. 로그인 때 `WithLoginClient`로 브라우저 user agent·주소를 보낸다 |
| `OwnSessions` | `own-sessions` | 실제 | `OwnSessions` | 성공한 로그인 기록 가운데 아직 열려 있을 수 있는 세션(만료·끊김·계정 변경 제외). 끊기는 `revoke-session` |
| `NetworkDNSNames` | `network-dns-names` | 실제 | `QueryRequest` | 네트워크 관리 DNS가 답하는 이름·앱 서비스·예약 주소와 직접 더한 레코드(A·AAAA·CNAME·TXT·MX·SRV·CAA)(`control.NetworkDNSNames`). 작업 공간 Read. 직접 더한 이름 쓰기는 `configure-network-dns` 정책의 `Records` |
| `PlanNodeDemotion` | `node-demote-plan` | 실제 | `NodeDemotePlan` |  |
| `PlanNodeDrain` | `node-drain-plan` | 실제 | `NodeDrainPlan` |  |
| `PlanNodeForceRemoval` | `node-force-remove-plan` | 실제 | `NodeForceRemovePlan` |  |
| `PlanNodeRemoval` | `node-remove-plan` | 실제 | `NodeRemovePlan` |  |
| `PlanTunnelReconnect` | `tunnel-reconnect-plan` | 실제 | `QueryTunnelReconnect` |  |
| `Prepare` |  | 실제 | `Prepare` | 로컬 서명 |
| `PrepareReason` |  | 실제 | `Prepare` | 로컬 서명, 사유 |
| `PrepareRequest` |  | 실제 | `Prepare` | 로컬 서명 |
| `PrepareRequestReason` |  | 실제 | `Prepare` | 로컬 서명, 사유 |
| `PrepareStream` |  | 실제 호출·웹 타입 | `containerops.SessionIntent 서명` | 로컬 |
| `PublicRead` |  | 실제 | `PublicRead` |  |
| `QueryCertificates` | `certificates` | 실제 | `QueryCertificates` |  |
| `QueryIngresses` | `ingresses` | 실제 | `Ingresses` |  |
| `QueryNodeShellSessions` | `node-shell-sessions` | 실제 | `NodeShellSessions` |  |
| `QueryVPS` | `vps` | 실제 | `QueryVPS` |  |
| `QueryVPSOffer` | `vps` | 실제 | `QueryVPSOffer` | 투표 서버가 공급자를 읽음 |
| `QueryVPSStatus` | `vps` | 실제 | `QueryVPSStatus` | 리더 메모리 |
| `RaftCompactPlan` | `raft-compact-plan` | 실제 | `CompactPlan` | `control.CompactPlanPage`(64개씩). 서버가 쪽을 모아 Target을 얻는다 |
| `RaftCompactStatus` | `raft-compact-status` | 실제 | `CompactStatus` | `control.CompactStatusPage`(4개씩) |
| `RaftStatus` | `raft-status` | 실제 | `RaftStatusPage` | 서버가 화면 행(초 단위)으로 바꾼다 |
| `ReadNodeDiagnostics` | `node-diagnostics` | 실제 | `NodeDiagnostics` |  |
| `ResolveStream` | `resolve` | 실제 | `ResolveContainerSession` |  |
| `Result` | `result` | 실제 | `Result` |  |
| `Resume` | `resume` | 실제 | `Resume` |  |
| `SealVPSCredential` | `vps-credential` | 실제 | `SealVPSCredential` | 투표 서버, 키는 보관 안 함 |
| `SelectTenant` | `select-tenant` | 실제 | `Query` | 허용 서버·set-nodes의 revision도 이것(옛 AllowedNodes는 지움) |
| `ServerVersion` | `server-version` | 실제 | `ServerVersion` |  |
| `Session` |  | 실제 |  | 로컬 |
| `Submit` | `submit` | 실제 | `Operation` |  |
| `TenantMembers` | `tenant-members` | 실제 | `TenantMembers` | `access.TenantMember` 행 |
| `TenantRetirement` | `tenant-retirement` | 실제 | `TenantRetirement` | `control.TenantRetirementStatus`. 화면 모양(revision·phase·operation, remaining "kind/id", ready)은 server가 만듦 |
| `TenantStoragePage` | `tenant-storage` | 실제 | `TenantStoragePage` |  |
| `Tenants` | `tenants` | 실제 | `Query` |  |
| `TunnelReconnectStatus` | `tunnel-reconnect-status` | 실제 | `QueryTunnelReconnect` |  |
| `UserCredentials` | `user-credentials` | 실제 | `UserCredentials` | `access.User` |
| `Users` | `users` | 실제 | `Users` | `access.PublicUser` 행 |
| `Whoami` | `whoami` | 실제 호출·웹 타입 | `Query` |  |
| `WriteCertificate` | `certificate-input` | 실제 | `WriteCertificate` |  |

## 리소스·앱

| method | wire | 상태 | 실제 호출(`userauth.Client`) | 메모 |
|---|---|---|---|---|
| `AppDeliveryChanges` | `app-cd-diff` | 실제 호출·웹 타입 | `AppDeliveryDiff` |  |
| `AppDeliveryField` | `app-cd-field` | 실제 | `AppDeliveryField` |  |
| `AppDeliveryHistory` | `app-cd-history` | 실제 호출·웹 타입 | `AppDeliveryHistory` |  |
| `AppDeliveryLocal` | `apps` + `app-source` | 실제 호출·웹 타입 | `AppPage` + `ReadAppSource` | 앱 행 `CD.LocalRevision/LocalTarget/LocalActor/LocalServices`와 AppSource Section `pending-local`(다음 sync를 기다리는 문서), 실행 중 버전의 source 서비스 이름 |
| `AppDeliveryRegistration` | `app-cd-registration` | 실제 | `AppDeliveryRegistration` |  |
| `AppDeliveryValues` | `app-cd-field` | 실제 호출·웹 타입 | `AppDeliveryField` | Conn.AppDeliveryField와 겹침 |
| `AppLogClearPlan` | `app-log-clear-plan` | 실제 호출·웹 타입 | `QueryLogClear(plan=true)` |  |
| `AppLogClearStatus` | `app-log-clear-status` | 실제 | `QueryLogClear(plan=false)` |  |
| `AppOperation` | `app-operation` | 실제 호출·웹 타입 | `AppOperation` |  |
| `AppPlan` | `app-plan-stream` | 실제 호출·웹 타입 | `StreamAppPlan` |  |
| `AppRevisions` | `app-revisions` | 실제 호출·웹 타입 | `AppRevisions` |  |
| `AppSource` | `app-source` | 실제 호출·웹 타입 | `AppSource` |  |
| `AppUploads` | `app-uploads` | 실제(웹 타입 같은 모양) | `AppUploadPage` |  |
| `ApproveVault` | `secret-input` | 실제 | `ApproveVault` |  |
| `Apps` | `apps` | 실제 호출·웹 타입 | `AppPage` |  |
| `BuildContextContent` | `build-context-content` | 실제 | `BuildContextContent` |  |
| `BuildDraft` | `build-draft` | 실제 | `BuildDraft` |  |
| `CheckBuildContext` | `check-build-context` | 실제 | `CheckBuildContext` |  |
| `CommitDraftFile` |  | 실제 | `CommitDraftFile` |  |
| `ContainerObserve` | `container-observe` | 실제 호출·웹 타입 | `ObserveContainer` |  |
| `DraftEditResult` |  | 실제 | `DraftEditResult` |  |
| `DraftFileStatus` |  | 실제 | `DraftFileStatus` |  |
| `DraftFreezeResult` |  | 실제 | `DraftFreezeResult` |  |
| `EditBuildDraft` |  | 실제 | `EditBuildDraft` |  |
| `ExternalRegistryPage` | `external-registries` | 실제 | `ExternalRegistryPage` |  |
| `FreezeBuildDraft` |  | 실제 | `FreezeBuildDraft` |  |
| `ImageBuildCacheUsage` | `image-build-cache` | 실제 | `ImageBuildCacheUsage` |  |
| `ImageBuildLogs` |  | 실제 | `ImageBuildLogs` |  |
| `ImageBuilds` | `image-builds` | 실제 | `ImageBuilds` |  |
| `ImageUsages` | `image-usages` | 실제 | `ImageUsages` |  |
| `LifecycleModuleRecover` | `lifecycle-module-recover` | 실제 | `RecoverLifecycleModule` |  |
| `LifecycleModuleStage` | `lifecycle-module-stage` | 실제 | `StageLifecycleModule` |  |
| `LifecycleSourcePage` | `lifecycle-source` | 실제 | `LifecycleSourcePage` |  |
| `LifecycleSourceRecover` | `lifecycle-source-recover` | 실제 | `RecoverLifecycleSource` |  |
| `LifecycleSourceStage` | `lifecycle-source-stage` | 실제 | `StageLifecycleSource` |  |
| `Lifecycles` | `lifecycles` | 실제 | `LifecyclePage` |  |
| `PlanExternalRegistryBind` | `external-registry-bind-plan` | 실제 | `PlanExternalRegistryBind` |  |
| `PlanImageBuildJob` | `image-build-job-plan` | 실제 | `PlanImageBuildJob` |  |
| `PlanRegistryMaintenance` | `registry-maintenance-plan` | 실제 | `RegistryMaintenance` |  |
| `PlanVaultApprovals` | `vault-approval-plan` | 실제 | `PlanVaultApprovals` |  |
| `PlanVaultWrite` | `vault-write-plan` | 실제 | `PlanVaultWrite` |  |
| `ProbeCD` | `cd-probe` | 실제 | `ProbeCD` |  |
| `ProbeExternalRegistry` | `registry-login-test` | 실제 | `ProbeExternalRegistry` |  |
| `PutBuildZIPPart` | `build-zip-transfer` | 실제 | `PutBuildZIPPart` |  |
| `PutDraftFilePart` |  | 실제 | `PutDraftFilePart` |  |
| `Registries` | `registries` | 실제 | `RegistryPage` |  |
| `RegistryCatalogue` | `registry-catalog` | 실제 | `RegistryCatalogue` |  |
| `RegistryCredential` | `registry-credential` | 실제 | `RegistryCredential` |  |
| `RegistryMaintenanceStatus` | `registry-maintenance-status` | 실제 | `RegistryMaintenance` |  |
| `RegistryPrune` |  | 실제 | `RegistryPrune` |  |
| `RegistryPulls` | `external-registry-pulls` | 실제 | `RegistryPulls` |  |
| `ResolveImage` | `image-resolve` | 실제 | `ResolveImage` |  |
| `Resources` | `resources` | 실제 | `ResourcePage` | `control.ResourceEntry` 한 쪽 그대로(8행). 네트워크 하나에 한 행으로 묶는 화면 모양(구성원·DNS·resolver, network-users 개수)은 server `resource_screen.go`가 모든 쪽을 한 revision으로 합쳐 만듦 |
| `SealBuildZIP` |  | 실제 | `SealBuildZIP` |  |
| `Standalone` | `standalone-get` | 실제 호출·웹 타입 | `StandalonePage` |  |
| `StandaloneOperation` | `app-operation` | 실제 호출·웹 타입 | `AppOperation` |  |
| `Standalones` | `standalone-list` | 실제 호출·웹 타입 | `StandalonePage` |  |
| `TaskDetail` | `container-observe` | 실제 호출·웹 타입 | `InspectContainer` | Kind `inspect` |
| `TaskHistory` | `container-observe` | 실제 호출·웹 타입 | `InspectContainer` | Kind `inspect` + `HistoryLimit`(1~100) |
| `TaskLogs` | `container-observe` | 실제 호출·웹 타입 | `ObserveContainer` | Kind `logs` + Cursor, 비밀값은 서버가 가림 |
| `TaskRestartPlan` | `task-restart-plan` | 실제 | `QueryTaskRestart` |  |
| `TaskRestartStatus` | `task-restart-status` | 실제 | `QueryTaskRestart` |  |
| `TaskStats` | `container-observe` | 실제 호출·웹 타입 | `ObserveContainer` | Kind `stats`. 서버는 지난 표본을 두지 않아 표본 쌓기는 웹 몫 |
| `Tasks` | `tasks` | 실제 호출·웹 타입 | `TasksPage` |  |
| `Vault` | `vault` | 실제 | `QueryVault` | 한 페이지를 그대로 돌려준다. 경로는 server(vault_screen.go)가 만든다 |
| `VolumeArchives` | `volume-archives` | 실제 | `VolumeArchivePage` | `userauth.VolumeArchivesPage`(보관 행 + 공개 수신자 키). 화면 행은 server `volume_archive.go`가 만듦 |
| `VolumeBackupSource` | `volume-backup-source` | 실제 | `VolumeBackupSource` | `userauth.VolumeBackupSourceReply` |
| `VolumeBackups` | `volume-backups` | 실제 | `VolumeBackupPage` | `userauth.VolumeBackupsPage`. 화면 행(B)은 server `volume_ops.go`가 만듦. CreatedAt은 begin-volume-backup 원본 서명 시각 |
| `VolumeFile` | `volume-file` | 실제 | `VolumeFile` |  |
| `VolumeFilePlan` | `volume-file-plan` | 실제 | `VolumeFilePlan` |  |
| `VolumeFileStatus` | `volume-file-status` | 실제 | `VolumeFileStatus` |  |
| `VolumeRestores` | `volume-restores` | 실제 | `VolumeRestorePage` | `userauth.VolumeRestoresPage`. 화면 행(R)은 server `volume_ops.go`가 만듦 |
| `Volumes` | `volumes` | 실제 | `VolumePage` | `control.VolumeView`. 화면 행(이름·앱·서버·fixed/shared, writer는 volume-users)은 server `volume_view.go`가 만듦. UsedBytes·UsageObservedAt은 소유 서버의 주기 측정(관측, Raft 밖), 없으면 모름 |
| `WriteVault` | `secret-input` | 실제 | `WriteVault` | `userauth.Reply` 별칭 |

## 반환 타입 대조

'실제 호출·웹 타입' 중 짝이 분명한 것의 필드 차이다. 실제 타입은 `userauth.Reply`에서 그 method가 채우는 칸의 원소 타입이다. '웹에만'은 대부분 화면 가공(작업 공간·서버 이름 붙이기, 쪽 정보)이거나 요청 문안에서 만든 칸이다.

| method | 웹 타입 | 실제 타입 | 웹에 없는 칸 | 웹에만 있는 칸 | 타입이 다른 칸 |
|---|---|---|---|---|---|
| `AppDeliveryHistory` | `CDHistoryRow` | `control.AppCDHistoryPage` | App, First, Last, Next, Records, Schema, Tenant, Truncated | Actor, CandidateDigest, Commit, FinishedAt, Note, Operation, PlannedAt, Reason 외 1 |  |
| `AppLogClearPlan` | `LogClearPlan` | `control.AppLogClearPlan` | App, Container, Impact, InventoryRevision, Schema, SourceArtifact, SourceCandidate, SourcePlan 외 2 | Code, Plan |  |
| `AppOperation` | `AppOperation` | `control.AppOperationView` | Current, Deployment, Found, Operation, Revision, Standalone | CompletedAt, Failed, StartedAt, Status, Steps, Submitter |  |
| `AppPlan` | `AppPlan` | `control.AppPlanPart` | Part | App, Diff, Move, Services, Standalone |  |
| `AppRevisions` | `AppRevision` | `control.AppRevisionView` | App, Automatic, Commit, CompletedAt, Deployment, Length, LocalActor, LocalDigest 외 10 | Kind, Submitter, Version | AcceptedAt(int64≠uint64) |
| `AppSource` | `AppSource` | `control.AppSourcePart` | Data, Part, RootRevision, Section, Standalone | AcceptedAt, App, Digest, Document, Kind, Operation, Submitter, Tenant | Version(uint64≠control.AppRevisionView) |
| `AppUploads` | `AppUploadView` | `control.AppUploadView` |  |  |  |
| `Apps` | `AppView` | `control.AppView` | BeginTarget, DownTarget, ImageSourceNoLongerTrusted, LogClear, ObservationMaxAge, Replacement, Retirement | Retiring | CD(*AppCD≠*control.AppCDView), Operation(OperationSummary≠deployment.OperationSummary) |
| `ContainerObserve` | `ContainerResult` | `containerops.Result` | Detail, DetailCode, DetailPart, LogCode, NextCursor, Schema, Stderr, Stdout 외 3 | Logs, NativeID, Node, Selection, ViewIndex | ObservedAt(int64≠time.Time), Processes([]Process≠[][]string), Stats(*ContainerStats≠*containerops.Stats) |
| `OpenNodeShell` | `NodeShell` | `control.NodeShellSession` | Account, BytesIn, BytesOut, ClosedAt, CreatedAt, End, LastActivity, Node 외 6 | (kind) |  |
| `Standalone` | `StandaloneView` | `control.StandaloneView` | Definition, Metadata, Tasks, Workload | Connections, CreatedAt, DisconnectedAt, Document, EndedAt, ExitCode, ExpiresAt, Generation 외 15 |  |
| `StandaloneOperation` | `AppOperation` | `control.AppOperationView` | Current, Deployment, Found, Operation, Revision, Standalone | CompletedAt, Failed, StartedAt, Status, Steps, Submitter |  |
| `Standalones` | `StandaloneView` | `control.StandaloneView` | Definition, Metadata, Tasks, Workload | Connections, CreatedAt, DisconnectedAt, Document, EndedAt, ExitCode, ExpiresAt, Generation 외 15 |  |
| `TaskDetail` | `TaskDetail` | `containerops.Result` | Detail, DetailCode, DetailPart, Kind, LogCode, NextCursor, Processes, Schema 외 7 | CPUs, CapAdd, Command, Digest, Drift, Entrypoint, Env, Generation 외 16 | ObservedAt(int64≠time.Time) |
| `Tasks` | `Task` | `control.TaskView` | Container, ContainerName, Deployment, EndpointPresent, ImageID, Kind, ObservationMaxAge, Resources 외 4 | Health, Instance, Restarts | ExitCode(int≠*int64), LastCheck(string≠*containerops.TaskCheck), ObservedAt(int64≠uint64), StartedAt(int64≠string) |
| `Whoami` | `Whoami` | `userauth.UserView` | ID, Revision, SystemAdmin, Username | LedgerEpoch, LedgerRootRevision, RootRevision, Roots, Session, User |  |

## 서버에 없음·확인 필요

- 없음. `CDApprovers`는 지웠다: 승인자는 sfcd CD 기록(`AppCDView.Approvers` → `AppCD.Approvers`)에 있고 server가 구성원 username으로 바꿔 보여 준다(R15-5).

리소스·앱 묶음의 짝은 가짜 어댑터 스레드가 근거를 확인했다(2026-11-24). 정말 없는 기능이고 화면에 필요하면 서버 PR로 만든다(REQUEST.md는 닫혔다).
