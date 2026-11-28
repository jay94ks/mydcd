## 계정·tenant typed 변경 payload

모두 `manage apply`의 기존 서명 UserOperation(Principal=현재 user, module epoch·root CAS·원 request ID)을 사용한다. Payload에는 아래 JSON 객체만 들어간다. 읽기 목록은 새 권한이나 변경 동작을 부여하지 않는다. `Expected`는 대상 객체 revision(신규 생성=0)이며 catalog root CAS와 별개다.

| Action | Payload | 현재 필요 권한·CAS |
|---|---|---|
| `put-user` | 새 계정(Expected 0): `access.User{ID,Username,Revision:0,Enabled,SystemAdmin,AutomationOnly?,Operations?,Credentials}`. 있는 계정: `{ID,Username,Enabled,SystemAdmin}`만 | system-admin/ManageCluster, 대상 User.Revision. 있는 계정은 그 세 칸만 바꿈(로그인 수단·상한 칸이 있으면 Invalid); 변경 시 해당 계정 전체 session 회수 |
| `set-account-scope` | `access.AccountScope{User,Add?,Remove?,Unlimited?,KeyOnly?}` | system-admin, 대상 계정 revision. 계정 action 상한(credential 상한과 교집합)을 변경분으로, KeyOnly(=AutomationOnly)를 값으로 바꿈. 있는 이름 Add·없는 이름 Remove는 ConditionFailed; 변경 시 해당 계정 전체 session 회수. 시스템 관리자에게는 범위를 둘 수 없음 |
| `add-credential` (관리자) | `access.CredentialAddition{User,Credential,Label?,Operations?,VolumeFiles?}` (Challenge·Proof 없음) | system-admin/ManageCluster, 대상 계정 revision. 어느 계정에나 키 하나를 더함. 상한은 이때 정해짐 |
| `create-tenant` | `{ID}` | system-admin/ManageCluster, 신규0. tenant 생성은 로컬 CLI profile 등록과 다름 |
| `set-membership` | `{Tenant,User,Role:manager 또는 viewer,Revision:0,Enabled}` | 대상 tenant ManageMembers, 해당 membership.Revision. 종료 중에는 기존 원 membership의 비활성화만 허용 |
| `set-nodes` | `{Tenant,Add?:[node ID...],Remove?:[node ID...]}`: 바뀐 서버만. 둘 다 비면 Invalid, 이미 있는 서버 Add·없는 서버 Remove는 ConditionFailed | system-admin/ManageCluster, 대상 tenant.Revision. managed root는 Add에 실제 사용 가능한 노드만 허용(클러스터를 떠난 서버도 Remove는 된다) |
| `set-trust` | `{Tenant,Add?:[{Registry,Repository}...],Remove?:[...]}`: 바뀐 규칙만. 둘 다 비면 Invalid, 이미 있는 규칙 Add·없는 규칙 Remove는 ConditionFailed | 대상 tenant ManageTrust, 대상 tenant.Revision |
| `begin-tenant-retirement` | `{Tenant,Operation}` | system-admin/ManageCluster, 대상 tenant.Revision. 원 inventory 수집과 신규 수락 중단 |
| `finish-tenant-retirement` | `{Tenant,Operation}` | system-admin/ManageCluster, 대상 tenant.Revision. 동일 원 Operation과 owner 전체의 양성 종료/잔여0 필요 |
| `revoke-session` | `{User,Session}` | system-admin/ManageCluster, 대상 User.Revision(계정 revision CAS). 자기 logout은 기존 SelfLogout의 제한된 별도 예외이며 타 사용자 회수 권한을 주지 않음 |

정확한 CAS·정산은 [catalog reducer](../../../internal/cluster/control/catalog.go)와 [사용자 operation 권한](../../../internal/cluster/control/operation.go)이 결정한다. password/token verifier 값·Secret 원문은 typed payload에 넣지 않는다.

| 본인 credential 명령/Action | 적용 대상 | 현재 권한·원 결과 |
|---|---|---|
| `manage self-credentials` / `my-credentials` | 현재 Session.User의 공개 계정·credential·revision | 현재 session만, 임의 TargetUser/Tenant/Node/After 금지. verifier 참조 없음 |
| `manage apply`의 `add-credential` | `{User,Credential:{ID,Method:private-key,PublicKey},Label?,Challenge,Proof}` | 자기 User만 + Tenant=* credentials scope, 원 User revision Expected와 catalog root CAS·서명 operation·새 key 소유 증명. 계정의 다른 필드 변경 불가 |
| `manage apply`의 `disable-credential` | `{User,Credential:ID}` | 자기 private-key만 + 같은 credentials scope/CAS, 또는 system-admin이면 어느 계정의 어느 수단이든. 마지막 인증수단/독립 admin key 보호, 계정 전체 session 회수. 새 로그인으로 원 result 조회 |

node CLI 제한이 켜져 있으면 본인 변경에도 기존 독립 승인·관리자 조건을 그대로 추가한다. 관리자용 계정·credential 편의 명령의 권한은 유지한다. [정확한 proof와 승인 bytes](../../reference/client-authentication.md)를 따른다.

전역 --reason/--incident-id/--approved-by는 user-auth 관리 명령의 첫 UserOperation에만 고정되는 표시 metadata다. result/resume의 원 사유·서명·ID를 교체하지 않고, claimed approved-by는 독립 승인으로 취급하지 않는다. Credential.Operations는 현재 역할/Session scope에 더하는 typed action ceiling이며 권한을 부여하지 않는다.

`app check/diff/deploy`의 Secret 전달 선언은 [파일/환경 변수 공급](../../reference/secret-delivery.md)을 따른다. `x-sfc.secrets.env`는 앱 소유 참조이고 Vault 값을 생성/변경하는 명령이 아니다. 계획/diff의 `SecretEnvRequiresNewGeneration`은 해당 서비스 이름 목록이며 새 Task 세대의 필요성을 표시한다. 현재 권한·Group 승인·원 Binding·정산 정책은 유지한다.

`app logs --cursor`는 같은 사용자·tenant/app/service/instance·원 Task/native와 로그 옵션의 가림 완료 구간만 이어 읽는다. 현재 Read/owner permit을 매번 요구하며 follow/다른 종류의 조회와 혼합하지 않는다. cursor가 배포·로그 삭제·권한 확대를 실행하지 않는다.

`app inspect APP SERVICE [--instance TASK --history N]`는 현재 tenant Read로 원 소유 Docker의 공개 설정·drift·최근 서비스 검사 결과를 조회한다. 이미지/일반 환경 값과 Secret 참조·native-only 값을 구분하고, 쓰기·재시작·배포 권한을 부여하지 않는다. [상세 필드](../../reference/container-detail.md)를 따른다.

`app inspect --max-bytes`는 frame 크기 한도다. CLI는 큰 가림 완료 snapshot을 같은 원 cursor로 수집하고 전체 검증 뒤 JSON을 출력한다. 사용자/원 Task/native·query가 바뀌면 다른 snapshot으로 자동 대체하지 않는다. 이 cursor도 권한이나 실행 승인 증거가 아니다.

### 명시 Task 재시작

RQ4 연결 중인 [Task 재시작 계약](../../reference/task-actions.md)을 따른다.

| 명령/동작 | 적용대상·인증 | 원 결과/재개 |
|---|---|---|
| `app restart APP SERVICE [--instance TASK] (확인 질문)` / `task-restart-plan` | tenant Read+노드 Deploy, credential의 restart-task 제한 교집합. 원 등록·Task/native/실행 시각 고정 | 읽기만 수행 |
| `app restart APP SERVICE -y [--id ID] [--instance TASK]` / `restart-task` | 같은 사용자 서명 operation·현재 quorum·현재 accepted grant/원 Binding. 앱 버전/배치 유지 | journal을 먼저 읽어 원 대상/ID 유지. 불명 Stop/Start 자동 재전송 금지 |
| `op show ID (app restart)` / `task-restart-status` | 현재 tenant Read | 원 수락/진행 행, 서비스/instance 재선택 없음 |

owner `task-restart-permit`은 다음 미전송 SDK 호출의 현재 허가를 확인하는 quorum read이며 사용자 관리 권한을 발급하지 않는다. `task-restart-report`는 원 owner 서명·원 수락 행·행 CAS/Apps root/epoch를 검사하는 진행 보고다. 상세 payload는 Task 재시작 계약에 둔다.

| 노드 scheduling 명령 | 적용대상·권한 | 보존·결과 |
|---|---|---|
| `node cordon/uncordon NODE --preview` | 시스템 관리자, 현재 members quorum read | scheduling revision/원 상태·후보만 표시 |
| `node cordon/uncordon NODE --expected-revision N --request-id ID` / `cordon-node,uncordon-node` | 시스템 관리자 사용자 서명과 credential 동작 제한의 교집합 | Members root·별도 scheduling CAS, 원 journal/result/resume. 기존 Task·Raft 구성 유지 |

`members`의 public `NodeLifecycle[].Scheduling`과 기존 `AdmitsWork`는 새 배치 제외와 기존 업무 권한을 각각 표시한다. [운영 조치](../../reference/task-actions.md#노드의-새-배치-제외복원)를 따른다.

### CD 후보 결정

| 명령/동작 | 적용대상·인증 | 원 결과/경계 |
|---|---|---|
| `cd approve-candidate APP --candidate SHA --request-id ID` / `cd-approve` | tenant ManageCD 또는 이 앱의 승인자(tenant Read)·credential 동작 제한 | 원 후보/실행 의도 CAS, --expected-revision은 strict CAS. 수동 모드 worker 실행을 허용하지만 원 Deploy/Group 승인 유지 |
| `cd reject-candidate APP --candidate SHA --request-id ID` / `cd-reject` | 같은 권한 | 같은 commit/digest fetch·복귀에도 반려 보존. 명시 replan만 현재 source 반려 해제 |
| `cd approver-add APP USER` / `grant-cd-approver`, `cd approver-remove APP USER` / `revoke-cd-approver` | `control.AppCDApproverChange{Tenant,App,User}`(User = user ID), tenant ManageCD, Expected = CD(delivery) revision | 승인자는 정렬된 user ID 목록(최대 64)으로 CD 기록에 남는다. 더할 때 계정이 있고 켜져 있어야 하며, 바뀌지 않는 요청(이미 있는 승인자 더하기, 없는 승인자 빼기)은 ConditionFailed. 승인자는 그 앱 후보의 cd-approve/cd-reject만 할 수 있다 |
| `cd status APP`, `manage result --request-id ID` | 기존 현재 조회 권한 | 공개 CD.Decision/Status와 원 operation 결과. 재실행/--resume-original은 원 서명·선택 유지 |

기존 `cd approve`는 Secret Group 승인이고 위 후보 결정과 혼합하지 않는다. 전역 reason은 새 원 operation의 공개 metadata다. tenant ManageCD를 app별 승인 권한으로 축소했다고 주장하지 않는다. [후보 결정 명세](../../reference/cd-candidate-decisions.md)를 따른다.

### Raft 수동 유지보수

| 명령/메시지 | 적용대상·권한 | 원 결과·경계 |
|---|---|---|
| `raft compact --preview` / `raft-compact-plan` | 시스템 관리자, credential의 raft-compact 허용, 현재 quorum | voter 기본/설치 노드 명시 선택·roster 지문, 최대64개 계획 페이지 |
| `raft compact --operation ID --request-id ID` / 서명 action `raft-compact` | 같은 권한과 현재 maintenance root/epoch | 원 journal·대상 키/CAS, 겹친 pending 거부, keep/minimal·순차/parallel, 현재 leader-last |
| `raft compact-status OP [--after CURSOR]` / `raft-compact-status` | 현재 시스템 관리자 quorum read | 원 job Summary·이유·노드별 결과4개/root 고정 페이지, 수락과 SDK 완료 구분 |
| `cluster backup create` / 서명 action `cluster-backup` + purpose20 | 시스템 관리자, credential의 cluster-backup 허용, 현재 quorum | 기록 뒤 15분 안의 같은 사용자. voter가 직접, non-voter는 리더로 relay. 마스터 키는 기록한 1회용 X25519 키로만 봉인([클러스터 백업](../../reference/cluster-backup.md)) |
| `raft-status`의 LastManualCompact | 기존 시스템 관리자 로컬 진단 | 마지막 공유 job/노드별 요약, stale/마지막 적용 권한 표시 유지 |
| 노드 Management `compact-work` / `compact-report` | 설치된 원 owner, queued skip은 현재 leader | 원 grant 확인·원 SDK 효과/진행 보고. 사용자 관리 권한 발급 경로 아님 |

`--nodes`, `--mode`, `--retain`, `--parallel`은 새 원 계획에만 적용하고 `--resume-original`은 같은 서명만 재개한다. 상세 필드·페이지·로그 파일 의미는 [유지보수 명세](../../reference/raft-maintenance.md)를 따른다.

### Registry 시작·정지 미리보기

| 명령/메시지 | 적용대상·권한 | 원 결과·경계 |
|---|---|---|
| `registry start/stop ID --preview` / `registry-action-plan` | 선택 tenant, 해당 start-registry/stop-registry credential 제한과 기존 관리/cleanup 권한 | 현재 registry record/root·원 Volume의 읽기 계획, 효과·서명 operation 생성 없음 |
| `registry start/stop ID --request-id ID [--expected-revision N] [--resume-original]` | 기존 typed 사용자 action·tenant/node 관리 권한 | 원 journal/record CAS와 결과, 같은 요청의 현재 revision 재계획 금지 |
| `registry show/wait ID` / 기존 registries 조회 | 현재 tenant Read | 원 writer 정지/공유 closure 또는 serving 관측. 수락과 실제 완료 구분 |

재시작은 명시 stop→stopped 확인→start 순서다. 데이터/Volume은 보존하며 별도 restart-registry 권한을 만들지 않는다. [Registry 조치](../../reference/registry-actions.md)를 따른다.

### Tunnel reconnect

| 명령/메시지 | 적용대상·권한 | 원 결과·보존 |
|---|---|---|
| `mesh reconnect --node NODE --peer PEER --preview` / tunnel-reconnect-plan | 시스템 관리자·reconnect-tunnel credential, 현재 quorum | owner 서명 down·현재 설치 키/주소·PairID 계획, 효과/승인 생성 없음 |
| `mesh reconnect --operation ID --request-id ID` / 서명 reconnect-tunnel | 같은 권한·현재 root/epoch, 새 요청은 명시 node/peer | 원 서명/job/키·journal/CAS 고정, 같은 쌍 pending 중복 거부. --resume-original은 같은 원 요청만 명시 재개 |
| `mesh reconnect-status OP` / tunnel-reconnect-status | 현재 시스템 관리자 quorum read | 원 Plan·주체/사유·공유 진행·실제 인증 결과, Session/grant 비노출 |
| 노드 tunnel-reconnect-work/report | 설치된 원 owner의 quorum 허가·서명 진행 | private sent/result와 기존 Dial, 새 사용자/tenant 권한 생성 없음 |

살아 있는 경로는 강제로 닫지 않고 TUN·Raft·업무 격리를 재설정하지 않는다. 공개 형식/불명 복구는 [Mesh 복구 계약](../../reference/tunnel-reconnect.md)을 따른다.

### 노드 이미지 캐시

| 명령/메시지 | 적용대상·권한 | 원 결과·보존 |
|---|---|---|
| node cache plan NODE / image-cache-plan | 시스템 관리자·prune-node-images credential, 설치 owner의 현재 quorum | 원 owner 서명 ID/별칭·실제 모든 컨테이너·수락된 참조, 최대8개/24KiB 계획 |
| node cache delete NODE --images ID,... --operation ID --request-id ID / prune-node-images | 같은 권한·현재 root/epoch·명시 full image ID | 원 journal/서명·job/원 선택, 현재 참조 재검사와 비강제 SDK 삭제, pending 별칭의 새 app/CD/build 수락 검사 |
| node cache status OP / image-cache-status | 현재 시스템 관리자 quorum read | 이미지별 removed/already-absent/skipped/failed와 미정산 범위, 실제 회수 bytes와 구분 |
| 노드 image-cache-native-plan/plan-permit/work/report | 설치된 원 owner·현재 사용자/원 grant | native 소유 관측·quorum 허가·private sent/result·원 이미지 순서의 서명 진행 |

이 작업은 app/cluster.yaml 선언·registry GC·Volume 삭제로 대체하지 않는다. --resume-original은 같은 원 요청만 명시 재개한다. [노드 캐시 API](../../reference/node-image-cache.md)를 따른다.

| 명령·method | 인증·범위 | 적용 대상·보존 |
|---|---|---|
| `cd pause/resume APP --preview` / `app-cd-toggle-plan` | 현재 tenant ManageCD + 해당 credential action | Apps/CD 현재 revision과 같은 reducer 전이, 읽기만 수행·원 ActiveOperation 보존 |
| `cd pause/resume APP --request-id ID` | 기존 사용자 서명·동일 권한 | 원 journal/result/resume·사유 보존, pause를 원 효과 취소로 취급하지 않음 |

| 명령·method | 인증·범위 | 적용 대상·원 결과 |
|---|---|---|
| `user issue-password/issue-token USER` / `initial-credential-stage` | 현재 system-admin/ManageCluster + issue-initial-credential 동작 제한, owner pin·User kind1 | 시스템 credential provider의 원 immutable write, target user revision 고정. 보호 입력은 relay/Raft에 넣지 않음 |
| `op resume`의 provider 관측 / `initial-credential-observe` | 같은 현재 권한·원 owner/intent | 원 receipt/version만 조회, token 원문 재반환·재발급 없음 |
| `issue-initial-credential` / `op show`·`op resume` | 관리자 UserOperation·Catalog root/사용자 CAS | owner fact를 같은 access FSM으로 적용. 원 공개 operation·사유·결과 보존, 기존 수단 교체 없음 |

| 명령·method | 현재 인증·권한 | 대상·원 결과 |
|---|---|---|
| `events --since CURSOR --limit N [--app/--node/--kind]` / User `events` | 현재 사용자 Session·tenant Read·허용 노드, 일반 quorum read | 선택 tenant의 observer journal. filter/응답 owner 고정 cursor, 원 ID 보존. 만료/누락은 명시 오류/Incomplete |
| `events --cluster-scope` | 현재 system-admin/ManageCluster | cluster/node와 모든 tenant 알림. 명시 tenant/app과 혼합 금지. 읽기가 실행 승인을 만들지 않음 |
| member `event-receipt`, Observation `node-events` | 현재 설치 member key/node·원 source 서명, ACK query는 자기 key | 기존 observer DB의 source prefix/이벤트 전달. 일반 사용자 명령·관리 consensus 대체 경로가 아님 |

각 메시지·필터·종류·retention/원 신원은 [관측 이벤트](../../reference/events.md)를 따른다.

CD field의 원 Git 값/현재 값·ValuesPart와 history/diff의 메시지 및 제약은 [CD 조회 명세](../../reference/cd-inspection.md)를 따른다. UI의 독자 DTO나 mock 응답을 SFCP 원 메시지로 취급하지 않는다.

`app diff`의 AppDiff와 `cd diff`의 AppCDDiff는 앱 범위 `Replacement` 영향 계획을 함께 반환할 수 있다. 같은 원 Inventory claim의 노드별 종료 closure를 읽으며 현재 권한과 exact 원 Key/Generation/Revision에 고정한다. 이 결과는 새로운 operation·종료 증명·다음 파동 실행 권한이 아니다. 기존 source 입력이나 관리 범위는 바꾸지 않는다.

내부 SFCP app-progress의 `advance-wave`는 활성 WorkKey의 원 app/operation/Inventory 보고다. 현재 원 사용자 권한과 원 파동의 실제 종료·새 세대 health를 재확인하며 사용자 승인·새 배포·Unknown 자동 재제출 권한을 추가하지 않는다. CLI/Unix 사용자는 기존 앱 배포/CD 명령과 원 결과 조회를 사용하며 AppView.Replacement로 노드별 진행을 본다.

기존 plain 앱의 `app deploy`/`begin-app` 갱신은 `AppView.BeginTarget`을 원 `AppBegin.Target`에 서명·보존하여 관측 revision과 배포 의도 변경을 구분한다. 현재 권한·같은 Blueprint/원 claim/종료 CAS는 유지하고 과거 Target 없는 intent는 엄격 CAS로 재생한다. 신규 생성은 expected=0과 해당 cluster/tenant/app/deployment의 부재 지문을 고정하고 서버가 entry 부재를 확인한다. 기존 앱 갱신·CD sync·Volume move와 혼합하거나 거부 뒤 새 ID로 자동 재제출하지 않는다. 상세는 [Unix API](../../reference/unix-sockets/22-credential.md#rq5-begin-app-대상-cas)를 따른다.

`registry external bind NAME --node NODE`는 User `external-registry-bind-plan`(ManageRegistry+해당 노드 Deploy의 공개 승인 계획)을 읽고, 원 `bind-external-registry`를 기존 Group 승인과 함께 보낸다(`--group-password-fd`는 그 Group 승인). CLI는 계획 전에 출처 상태(꺼짐·이미 reader 있음·정지 중)와 서버의 AdmitsWork를 읽어 이유를 먼저 말한다. `registry external check ID [--image REF]`/User `registry-login-test`는 ManageRegistry의 source owner 읽기이며 현재 source 세대·원 Secret 승인으로 제한된다. Vault 값·앱 제어·이미지 trust를 부여하지 않는다. `unbind-external-registry`는 관리 명령의 tenant cleanup action이며 실제 owner I/O 종료 전 usage를 반환하지 않는다. [입력·응답·종료 코드](../../reference/external-registries.md#앱-없는-관리-source-승인과-로그인-시험)를 따른다.

`image show/resolve IMAGE`/User `image-resolve`는 선택 tenant의 Read 또는 ManageRegistry 조회다. 현재 tenant의 같은 배포 신뢰 규칙으로 주소를 검사하고, 내장 run의 metadata 또는 승인된 외부 source reader가 읽은 공개 digest/index만 반환한다. 원 실행·image trust·Vault 권한·registry credential을 생성하지 않는다. 결과/오류는 [이미지 확인](../../reference/image-resolution.md)에 규정하며 원 operation 재개 대상이 아니다.

`image usages IMAGE`/`image usages --source NAME`은 User `image-usages`의 현재 tenant Read 또는 ManageRegistry 조회다. 전자는 ref/digest, 후자는 tenant 외부 source를 선택하며 원 Task·수락 실행·CD·직전 버전의 선언 참조를 공개한다. 기존 native 생존 관측·원 operation·삭제 허가를 만들지 않는다. [메시지와 결과 범위](../../reference/image-usages.md)를 따른다.

`registry external pulls`/User `external-registry-pulls`는 현재 선택 tenant의 Read 또는 ManageRegistry로 기존 관측 DB의 실제 외부 이미지 받기 결과를 조회한다. 원격 로그인 시험·Vault 원문 조회·이미지 받기를 실행하지 않으며 관측으로 앱/이미지 허가를 대체하지 않는다. Source 이름·authority·노드·제한 코드·실제 완료/보고 시각만 반환한다. [메시지](../../reference/external-registries.md#실제-이미지-받기-결과-조회)를 따른다.

`image list NAME [REPOSITORY]`와 User `registry-catalog`는 현재 tenant Read 또는 ManageRegistry의 목록 조회다. 기본 대상은 내장 registry이며 `--external`이면 승인된 같은 tenant의 source다. 원 credential·grant를 반환하거나 사용자 session에 Vault 원문 권한을 부여하지 않는다. `--repository`는 정확한 repository이며 registry authority·이미지 tag·패턴과 구분한다. [입력·응답·페이지](../../reference/registry-images.md)를 따른다.

`registry delete-image NAME --repository REPO --reference REF --expected-digest DIGEST`/`registry gc NAME`은 선택 tenant의 내장 registry를 대상으로 하는 ManageRegistry signed action `delete-registry-image/gc-registry`다. `--preview`는 User registry-maintenance-plan만 읽고 실행은 안정적인 request-id·원 run/record/root CAS를 고정한다. User registry-maintenance-status와 CLI maintenance-status는 현재 tenant Read 또는 ManageRegistry의 원 결과 조회다. worker의 registry-maintenance-work/report는 원 installed owner의 현재 허가·참조 재검사/원 receipt 정산이며 node 키가 새 사용자 관리 동작을 발급하는 경로가 아니다. [수락·효과·복구의 메시지](../../reference/registry-maintenance.md)를 따른다.

`registry delete-image NAME --external`/registry-maintenance-plan의 External=true는 같은 tenant의 외부 source·원 approved reader/read-set을 선택한다. Action은 같은 delete-registry-image이며 managed/source 선택도 원 서명에 고정한다. 외부 digest의 실제 HTTP 전송 직전에 현재 사용자·source·공통 참조를 재검사한다. DENIED/UNSUPPORTED와 unknown을 구분하고 후자는 원 결과 없는 pending 상태로 유지한다. source reader의 실제 I/O join/closure는 이미지 원 작업의 성공을 뜻하지 않는다. [외부 이미지 삭제](../../reference/registry-maintenance.md#외부-registry-삭제)를 따른다.

`registry prune NAME`/User registry-prune-preview는 tenant ManageRegistry의 일괄 선택이고 signed prune-registry-images가 그 고정 선택을 실행한다. 선택 GC에는 gc-registry 동작 허가도 필요하다. registry-prune-results/CLI prune-items는 현재 Read 또는 ManageRegistry의 같은 원 부모 결과 조회다. 기본 대상은 내장 registry이고 --external은 승인 source다. 원 tenant/조건/owner/run·Public 지문과 request-id를 보존하며 node owner 전달이 새 사용자 권한을 발급하지 않는다. [명세](../../reference/registry-maintenance.md#일괄-정리)를 따른다.

