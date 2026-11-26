## tenant 내장 registry의 관리 경계

`registry-work`는 기존 member/latest 관리 read다. cluster/tenant/registry ID·명시 시각을 검사하고 현재 spec/원 active run·MayStart와 index/epoch/root CAS를 반환한다. 현재 node/key·원 grant·Volume/고정 경로 정책·writer activation이 맞아야 MayStart이며 원 run의 정산 조회는 creator 권한 철회 후에도 해당 installed owner에게 허용한다. source bytes·로그인 자격·private key를 이 응답에 넣지 않는다.

`registry-report`는 같은 member/latest 경계에서 owner 서명 RegistryReport를 ModuleReport로 수락한다. schema1·cluster/reporter·원 ID·spec revision/run generation·epoch/root CAS/index·시각과 reserve/serving/drain/closed의 배타적 payload를 확인한다. reserve/closed의 Volume consumer와 관리 CPU/메모리 예산은 같은 후보에서 예약/반환하며 관련 patch 권한은 해당 Volumes/Resources checkpoint에 한정한다. serving은 boot/인증서 관측이고 closed는 원 Gone과 budget closure다. 관측 부재/단절을 종료로 바꾸거나 새 run ID로 재제출하지 않는다. 원 보고 결과의 재조회와 신규 보고의 신선도 검사는 구분한다.

사용자 `registries`는 명시 tenant와 현재 Read session으로 공개 Spec/관측 페이지를 조회한다. 최초 정의·Spec put·start grant의 원 사용자 서명과 자격은 공개하지 않는다. manage는 같은 put/start/stop/delete-registry 코어와 원 operation/현재 인증을 사용한다. 실제 외부 OCI/TLS·Engine 동작 완료는 관리 수락/이 codec만으로 주장하지 않는다.

registry-work는 검증된 compact run 참조와 원 Definition/Origin command digest·NativeReady를 반환한다. 원 사용자 session/서명을 중복 전달하지 않으며 원문은 FSM에 보존한다. node의 private journal도 같은 참조·원 native lease/세대만 소비하고 이 view를 새로운 수락 권위로 사용하지 않는다.

`registry-credential`은 현재 session/request proof로 명시 tenant/registry·repository/actions를 전달하는 보호 사용자 요청이다. 응답은 별도 registry login domain의 짧은 파생 자격·authority·만료이며 공개 관리/Raft 변경이 아니다. 기존 password/개인키/token login을 그대로 재사용하고 외부 registry는 이 원 자격으로 한 repo의 별도 access token을 교환한다. 두 token domain·원 session 만료·현재 issuer/member/account/credential/session/tenant 권한을 검사하며 원 proof private key를 전달하지 않는다. 사용자 CLI의 보호 전달과 실제 Task-bound Engine pull 연동은 해당 소비 계약으로 별도 연결한다.

### registry의 Task 이미지 허가

installed member read `registry-image-permit`는 AppBindingRequest(Task key/revision/generation·Binding digest·At)와 pinned Image를 받는다. latest quorum에서 caller가 원 Task owner인지, 현재 AppBindingPermit·원 수락 grant·현재 image trust가 유효한지 검사한다. 응답은 TaskSubject(Task/Binding/Node/정규 image)·선택 내장 Registry Spec 또는 외부 External 참조(둘 다 없으면 익명 외부 source)·committed index/epoch이며 secret은 없다. Runtime은 해당 barrier 이후의 같은 local immutable 상태와 대조한다. 임의 비인증 RPC나 사용자 session 대체 경로를 만들지 않는다.

내장 OCI login grant의 Subject는 Session·TaskSubject·BuildSubject 중 하나다. 빌드 job은 [BuildSubject/내장 registry 허가](../../reference/image-build-jobs/04-owner.md)의 원 Snapshot/owner·현재 권한·정확한 repository를 사용하며 Basic username은 mydc-build다. Task login은 해당 Task node가 서명하고 외부 /token은 같은 원 Task의 현재 허가와 고정 repository pull ceiling을 검사해 서버 owner가 별도 access domain으로 교환한다. Basic username은 이 subject 전용 mydc-task이며 새 계정이 아니다. 현재 정책·Task/Binding·trust 철회는 cached image나 과거 서명으로 우회하지 못한다. HTTP pull 권한 단위는 repository이고 실제 image digest 선택은 Task/SDK 소비에서 고정한다. 자격/토큰은 관리 Raft에 기록하지 않는다.

### Native consumer budget 조회

기존 인증/latest quorum `app-native-permit`의 bridge/tunnel 응답에는 선택 `Consumers`(Scope: Tenant/Node/physical Owner, NodeMaxConsumers, TenantMaxConsumers)를 같은 committed view에서 제공한다. 기존 MaxConsumers는 두 한도의 min이다. source revision/generation·spec digest·member owner와 결합하고 별도 비인증 RPC로 조회하지 않는다. 관리 Runtime의 새 실제 pin은 이 필드를 요구하며 누락/0/불명 응답을 legacy 성공으로 fallback하지 않는다. 원 pin 조회·반환은 새 권한 부여가 아니다. ConsumerScope는 node-local 원 journal metadata이고 새 공유 복제 로그/핀 종료 영수증이 아니다. wire 번호는1을 유지한다.


### 앱 CD source의 관리 stream

기존 authenticated member/latest Management 안에서 `app-delivery-permit`와 `app-delivery-progress`를 사용한다. permit은 현재 등록 tenant/app·source policy·원 fetch ticket·Apps root/Delivery revision·module epoch를 고정하고 reader key에 결합한다. source 전송 중이면 원 commit/upload identity·길이/digest/누락 part만 반환하고 실제 source part나 Git 자격을 이 응답에 넣지 않는다.

progress는 `mydc-app-delivery-progress-1` domain의 원 member 서명을 검증한 ModuleReport다. fetch/input/part/received/source-error의 필드 조합·현재 member·원 ticket/policy/CAS/현재 CD 권한을 FSM에서 검사한다. part는 기존24KiB payload·전체4MiB Upload digest를 사용하며 raw Git credential이나 임의 caller의 완성 Delivery/Inventory를 수락하지 않는다. 원 body/commit은 source adapter의 공개 attestation이며 Git 서버 서명이나 native Ready 증거로 해석하지 않는다. 파싱/정책 오류와 source-error는 원 앱/native 작업을 변경하지 않는다. module/schema/wire 번호는1을 유지한다.

동일 authenticated Management의 `app-delivery-sync-work`는 현재 member에게 latest quorum의 원 앱·candidate·module epoch·Apps root/CD revision과 가능한 replan/auto-sync/continue만 반환한다. preview와 report는 같은 결정적 코어를 사용하며 현재 권한·원 실행/health·정책·미종료 전환을 다시 검사한다. 이 읽기는 native 작업 제출 권한이나 성공 영수증이 아니다. `app-delivery-progress`의 replan/auto-sync/continue는 현재 preview와 정확히 일치할 때만 확정한다. manual/paused/실패/Unknown 조건을 자동 recover로 우회하지 않는다.

사용자 sync/recover는 기존 signed UserOperation의 `sync-app`/`recover-app` action과 tenant/app·등록 digest·정확한 candidate·operation을 고정한다. 원 signed 등록은 보존하고 선택의 signed UserOperation 또는 auto-sync member report를 별도 원본으로 저장한다. 과거 member가 제거돼도 기존 증명의 서명/바이트는 보존하지만 새 보고 수락에는 현재 member가 필요하다. 실제 prepare/send/Unknown/collect·retirement는 기존 app Management와 원 A1 요청/owner 관측을 그대로 사용한다. source 전송과 달리 native 작업을 CAS 재시도용 새 operation으로 바꾸지 않는다.

사용자 조회 `app-cd-field`는 정확한 app field와 current ownership refs·Target, `app-cd-registration`은 명시 Selection에 대한 signed 등록/필요 Vault realm만 반환한다. 두 요청은 사용자 인증/tenant 범위·latest quorum을 사용하며 member 전용 source permit과 구분한다. field 변경은 `override-app`/`release-app-override`의 signed UserOperation·원 Apps root/CD 좌표·field revision/원 Task refs와 Target을 사용한다. field CAS 경계는 서버가 `Change`에서 정한다. 조회 응답은 native 실행 권한이 아니다.

공개 DeliveryStatus의 Sync는 활성 override의 Git 대비 차이를 표시할 수 있고 EffectiveSync는 override를 적용한 실제 Desired 일치를 나타낸다. 자동 선택은 EffectiveSync와 이미 선택된 artifact/commit·의미상 목표·policy/override revision을 대조하여 동일 선택을 반복하지 않는다. 두 필드 모두 native health/실행 완료나 Unknown 정산을 대신하지 않는다.

CD Group 승인 selector는 operation 또는 candidate digest 중 하나다. 원 signed 등록과 현재 등록자의 login·CD/단계 권한을 확인하고 current candidate의 현재 plan 또는 accepted execution/transition만 사용한다. optional Selection을 기존 vault-approval-plan/permit·SecretInput·signed VaultApprovalReport에 그대로 전달해 원 Target을 다시 검사한다. 기존 selector 부재의 schema1 바이트/동작은 유지한다. 실제 패스워드는 보호 SecretInput에만 있으며 source/등록 조회/공유 보고/CLI private intent에는 값·verifier를 복제하지 않는다. sync의 native 전환 시작과 종료 뒤 계속은 기존 Tree.Plan/Approvals.Missing을 현재 시점 입력으로 확인한다.


### CD 앱의 명시 Volume move와 원 증명

기존 app move plan stream/Upload·signed begin-volume-move·member move 보고를 사용한다. VolumeMoveApp의 optional CD anchor는 등록 digest/principal/requester·policy/override revision·의미상 target plan/input digest를 signed 원문에 포함한다. target은 기존 실제 copy/owner/Arm과 같은 FSM의 BeginMoved로만 시작하고 CD 실행 선택의 User 원본은 그 signed move다. 원 등록/submitter/requester·source/Git 후보를 보존하며 이관 관리자와 Blueprint actor를 구분한다. 이후 Binding·target 활성/원 결과와 Snapshot은 이 증명을 따라가고 다른 key/target/원 입력을 채택하지 않는다.

Group selector의 accepted operation에는 같은 등록에 고정된 명시 move target도 포함된다. 원 등록자의 current login/단계 권한과 signed move의 현재 권한·필요 realm/Group을 같은 기존 approval 경계에서 검사한다. target 파일이나 새 이관 signer가 다른 사용자 명의로 Group을 승인하지 못한다. schema/wire 번호와 기존 CD anchor 부재의 바이트는1로 유지한다.

앱 소유자 사실 관측의 내부 `ModuleReport`는 schema1 Command의 예약 `Target=app-observation`을 사용한다. 이 값은 `control/apps`의 signed `AppProgress.Action=observe`에서만 유효하다. 원 Expected/root·서명·content-bound request ID를 바꾸지 않고 현재 동일 operation/원 command·native·owner·generation·sequence를 검증한다. 미래 좌표/대상 변경은 거부하며 준비·송신·Unknown/수락/정산·관리 변경에는 적용하지 않는다. 기존 빈 Target의 보고와 bounded receipt/replay floor는 보존한다.

관측 병합은 `observe` 보고(`ModuleReport.Target=app-observation`)로 한다. 모드는 action으로 정해지고 따로 서명하는 필드는 없다.

내부 `app-progress`의 observe가 아닌 보고는 `ModuleReport.Target=app-inventory`로 같은 tenant/app의 정확한 inventory Expected를 검사한다. 공유 Apps root는 양수/현재 이하 basis이며 다른 앱·source bookkeeping의 갱신만으로 거부하지 않는다. 자기 inventory revision·원 operation/Step/journal·현재 member/권한·epoch·원 native 명령/owner·동일 atomic cross-resource 검증은 유지한다. prepare/send/Unknown/collect/finish·binding/retirement는 같은 reducer를 사용한다. Target/서명 변조·미래/zero basis는 거부한다. 원 불명 native 명령을 재서명/재제출하는 모드가 아니며 user 관리 CAS도 바꾸지 않는다.

이미 저장된 schema1 명령에서 bool이 없고 `Target=app-observation`인 원 관측도 같은 byte/ID/병합 결과로 재생한다. 이는 저장된 Command의 명시 Target을 복원하는 경계다. 새 RPC의 false 기본값으로 생성하는 Command는 빈 Target을 유지하고 모드를 자동 추가하지 않는다.

앱 계획의 `invalid` 응답은 선택적 `InputCode`로 planner의 심볼 오류만 전달한다. 최대64 ASCII 대문자/숫자/밑줄이며 원문/경로/Secret이나 임의 error 문자열은 전송하지 않는다. 현재 인증된 일반/stream 계획에서 같은 필드를 사용하고 denied/conflict 및 Completed/Unknown 전송 수명은 유지한다. 이 코드가 재제출이나 권한을 허가하지 않는다.

### 원 route dispatch 보고의 참조 CAS

node 전용 route-dispatch 보고의 ModuleReport Target은 늘 `route-dispatch`이며 RequestID는 그 Target/원 서명 봉투에 고정된다. Apps root는 basis 좌표이고 reducer가 현재 원 ref/generation/lifetime/owner·boot/journal/native spec/operation·양측 권한을 검증해 동일 dispatch만 확정한다. zero/future basis·권한 회수/철회/종료·원 identity 교체·epoch/replay floor는 거부한다. 앱 관측의 app-observation Target과 다른 효과 전이다. Unknown 봉투를 재서명하지 않는다. native Apply는 기존 fresh permit/원 로컬 journal/boot 검증을 별도로 요구한다. 자체 schema 번호는1이다.

새 route dispatch Target을 사용하기 전 control/owner 전체에 같은 고정 제품을 정지·배치한다. schema1이라는 이유로 이전 제품과 새 Target의 혼합 실행을 호환으로 간주하지 않는다. 원 legacy log의 해석은 보존하며 혼합 버전 rolling upgrade는 이 변경의 완료 근거에 포함하지 않는다.

`AppDeliveryRequest`/`AppDeliveryWorkRequest`의 optional `TargetCAS` read mode가 참이면 응답에 optional `Target`을 준다. 새 progress의 Target은 서명된 source ticket/input 또는 `appSyncTarget` 지문이며 health/bookkeeping을 제외한다. nil은 과거 CD revision mode 그대로다. 같은 artifact/intent의 기준 rebase와 수락은 한 reducer transaction이며 원 Choice/서명/ID를 다시 쓰지 않는다.


사용자 `configure-app-cd`도 명시 signed `AppCDChange.Target`이 있을 때 기존 `ModuleAppCAS` 경로를 사용한다. 같은 공개 실행 의도 지문과 원 PolicyRevision을 모두 검증하며 기본 CLI는 이를 `app-configure-target`으로 표시한다. Target 없는 legacy/명시 expected-revision은 기존 전체 root/CD revision CAS를 유지한다. 동시 정책·등록·후보/실행·pause/down/override·현재 권한 변경 거부와 원 요청 결과 조회는 그대로다. 새 protocol RPC/번호는 추가하지 않는다.


