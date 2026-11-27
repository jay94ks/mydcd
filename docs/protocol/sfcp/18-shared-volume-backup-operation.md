## Shared Volume backup operation

새 metadata 변경 set-volume-backup-limit/begin-volume-backup/cancel-volume-backup/delete-volume-backup은 기존 User submit/result/resume과 control/volumes의 같은 root CAS/FSM/Snapshot 경계를 사용한다. begin은 원 accepted user operation/session ceiling·signed NativeReady·readonly consumer/한도·compatibility를 같은 후보로 저장하며 partial pin/예산을 게시하지 않는다. byte/count 한도는 system admin의 global+tenant/node reservation이며 physical quota가 아니다. User typed method `volume-backups`는 현재 tenant Read로 필터한 공개 metadata `Items`/`Next` cursor와 같은 `RootRevision`(Volumes root)을 반환하고 원 session/envelope/data/path를 노출하지 않는다.

Management volume-backup-permit는 current member의 Latest=true/quorum read에서 정확한 원 owner/selection을 검사한다. copy는 accepted session의 원 scope·acceptedAt와 현재 account/credential/membership/node 권한을 AuthorizeAccepted로 소비하며 원 transport session logout/expiry만으로 수락된 작업을 취소하지 않는다. Cancelling/Deleting은 cleanup 전용이고 native 관측을 새로운 권위로 쓰지 않는다. volume-backup-report는 original owner의 고정 signed report를 node actor 명령으로 제출하며 epoch/root CAS/job revision/binding을 검증한다. 원 request/result를 저장하고 결과 재생 시 서명/ID/receipt를 바꾸지 않는다. 새 보고는 adapter clock의300초 경계를, 원 committed 결과는 해당 고정 입력의 재생을 따른다.

Ready에는 원 consumer 종료·clean source/compatibility·receipt와 file/directory sync를 요구한다. 취소와 실제 Ready가 경합하면 artifact를 Deleting으로 보존하고 실패/삭제도 artifact 부재+directory sync 이후에만 예약을 반환한다. 최초 completion과 tombstone을 유지하고 같은 ID를 재사용하지 않는다. 이 wire 계약은 실제 source 정지·native job/FD 정산·SQL consistency를 만들어 주지 않으며 owner producer가 직접 확인해야 한다.


### Backup source 선행 조회

User typed method `volume-backup-source`의 `Params:{Tenant,Volume:{App,ID}}`는 논리 App/ID이며 원 session envelope에 결합한다. 모르는 필드(After·native/path 포함)와 빈 tenant를 거부한다. current issuer/session/tenant Read에서 등록 NativeReady와 Volume revision을 선택하고, 원 owner 관측 뒤 최신 quorum/current 권한·같은 materialization/Volume revision을 다시 검사한다. `Data.Source`는 schema1 Scope/node/public owner key·NativeReady binding digest·정확한 원 writer recipe digest·고정 image/원 writer generation·정상 process exit만 반환한다. `Index`·`RootRevision`(Volumes root)·`VolumeRevision`·`ModuleEpoch`는 최종 view를 따른다. 원 Native name/path·command/env·credential/session·file 내용은 보내지 않는다.

Management `volume-backup-source-observe`는 기존 node-local 관측과 같은 current member/Latest=false 경계를 사용한다. owner는 native 수명 잠금 밖에서 `volume-usage-permit`의 기존 Latest=true/quorum/원 owner·materialization 검사를 앞뒤로 수행하고, 그 사이 실제 activation ColdSource를 읽는다. 관측 동시1개·원 context를 지키며 source/권한/과반수/종료 기록 부재는 unavailable/denied다. 선행 조회는 writer/reader grant나 SQL 복원 성공을 만들지 않는다. 공개 recipe digest는 이후 동일 관리 operation의 compatibility 입력이며 부작용 수락은 기존 A1/CAS/Volume AcquireCold 경계를 사용한다.

### Shared inactive restore

User metadata `begin-volume-restore`/`cancel-volume-restore`는 같은 signed operation·root CAS/FSM/Snapshot을 사용한다. 원 Ready backup/receipt와 같은 owner의 새 target·독점 staging consumer·global+tenant/node staging bytes/count·Volume slot을 한 후보로 예약한다. pending restore는 원 backup 삭제를 막는다. User `volume-restores`는 현재 tenant Read·안정 cursor/root 검사를 사용하고 공개 target scope/phase/binding만 반환한다. 파일/원 session·consumer/native path를 보내지 않는다.

Management `volume-restore-permit`는 current member/Latest=true·quorum에서 원 owner와 job binding·현재 accepted 권한을 검사한다. cleanup 허가와 copy 허가를 구분한다. `volume-restore-report`는 domain `sfc-volume-restore-report-1`의 원 owner 서명·module epoch/root CAS/job revision·원 binding/consumer closure를 검사한다. 새 보고는300초 clock 경계, 원 committed 결과는 같은 서명/ID의 재생을 따른다. file/directory sync·receipt 비교·artifact 참조 반환과 정확한 signed NativeReady가 모두 있어야 target 등록/원 writer 반환을 원자 확정한다. 취소 선행 시 늦은 완료를 거부하고 TargetGone/원 참조 반환 뒤에만 정산한다.

Restored는 파일 검증 결과다. 새 앱 writer는 같은 배포 코어의 현재 app/Secret/Volume 허가와 원 종료 recipe의 image/process/mount 호환성 검사를 별도로 통과해야 한다. SQL 복구 성공은 실제 앱 프로토콜의 데이터 조회/쓰기로 확인하며 이 보고 비트만으로 만들지 않는다. 전송/생성 불명은 원 A2 ID/target/A3 참조를 유지하고 자동 새 copy/ID를 발급하지 않는다. 교차 node 파일 전송은 별도 E4의 인증 stream 계약이다.

### 명시 native Volume 삭제

User의 signed `delete-volume`은 원 scope와 Volume revision으로 Deleting을 확정한다. 소비자·진행 중 이관/미정산 보존본을 허용하지 않으며, 앱이 원 A1 Goal을 보존한 경우에는 활성/종료 중 Inventory가 없고 그 native의 정확한 서명 RetainReceipt가 있어야 한다. 단순히 Goal이 남았다는 이유로 새 native 생성 허가나 삭제 거부를 대신하지 않는다.

Management `volume-delete-permit`는 현재 member/Latest quorum에서 원 owner와 Deleting·accepted intent를 확인하고 정확한 signed NativeReady/삭제 revision만 반환한다. `volume-delete-report`는 schema1 ModuleReport와 원 owner의 `sfc-volume-native-removed-1` 서명으로 scope/owner/native key·generation/delete revision을 검사한다. 원 native journal과 실제 SDK의 Gone 후에만 공유 Deleted를 확정한다. 원 metadata/앱·backup/restore 이력은 tombstone으로 남기며 복원 staging 예약은 그 Gone 뒤에만 반환한다. 새 보고의 edge 시각은300초이며 원 결과 재생과 구분한다. 무과반수/단절/부재를 미실행이나 참조 반환으로 바꾸지 않는다.

### 전용 native Volume 생성

User signed `begin-volume-create`는 논리 Scope/Node·UID/GID/Mode·observe profile과 원 operation을 공유 slot/spec/materialization에 고정한다. `control/volumes`의 optional Creations는 schema1이며 registered NativeReady를 생성 예약으로 위장하지 않는다. 생성 중 같은 logical ID의 새 app native materialization·raw 등록/restore를 막고, `volumes`/inspect에는 native name 없는 Reserved/Creating/Cancelling을 반환한다. 현재 user/tenant 권한과 global/tenant node consumer 한도를 확인한다.

Management `volume-create-permit`는 member/Latest quorum에서 exact owner/spec/job phase/revision·현재 accepted 권한을 검사한다. owner는 원 native Desired를 먼저 sync하고 `sfc-volume-create-report-1`로 서명한 Prepared report를 Raft로 확정한다. 그 뒤 Creating에서만 원 Apply1을 실행한다. `volume-create-report`는 schema1 ModuleReport·서명된 전체 scope/epoch/root/job CAS/시각과 NativeReady 또는 NativeRemoved를 확인한다. Prepared 서명은 Snapshot에도 보존한다. native ID/물리 generation은 원 spec과 묶으며 현재 권한 회수 뒤 Ready를 게시하지 않는다.

`cancel-volume-create`는 원 Scope/job CAS로 Cancelling을 확정한다. SDK 전에 미전송인 경우와 SDK dispatch 후 불명을 구분하고, 원 worker 정산·native A2 retirement/nonforce Gone 뒤에만 Cancelled가 된다. 늦은 Ready는 취소를 되돌리지 않는다. dispatch 허가 뒤 원 journal 유실은 새 Desired/Create/채택/부재 기반 Gone을 허가하지 않으며 원 DB/ID를 보존·복구한다. 확실히 미실행 종료한 원 Apply1도 자동 Apply2로 교체하지 않는다. 원 결과/명시 resume와 이후 더 높은 logical generation을 구분한다. observe는 물리 quota 보장이 아니고 원본 bytes 정책을 대신하지 않는다.

### Volume 원본 예약

schema1 `begin-volume-create`/`begin-volume-restore`에 optional CapacityBytes를 결합한다. Compose의 `x-sfc.capacity_bytes`는 같은 projection에 들어간다. `set-volume-backup-limit`의 optional Original(bytes/count)은 node와 tenant/node에 적용하고 양수 신규 예약은 양쪽을 요구한다. 정책이 하나라도 있으면 예약0·raw 등록으로 우회할 수 없다. 미설정 checkpoint는 예약 적용을 주장하지 않는 기존 observe 상태이며 원본 데이터의 크기를0으로 추정하지 않는다.

`set-volume-capacity`는 같은 User submit/result/resume·control/volumes root CAS에서 system admin의 현재 Scope/Volume revision·원 signed NativeReady digest·양수 bytes를 검사한다. native identity나 journal을 바꾸지 않는다. VolumeView는 CapacityBytes/NativeBinding, VolumeRestoreView는 원본 CapacityBytes와 staging MaxBytes를 분리해 공개하며 원 session/서명 envelope/host path를 추가하지 않는다. 같은 결정적 projection이 등록 원본·pending 생성/복원·미게시 앱 Goal을 합산하고 Ready 게시에서 중복 계산하지 않는다. retain/Unknown/Deleting은 예약을 유지하고 원 signed Gone 뒤에만 반환한다.


Volume 관리의 `activate-app`은 설치된 target member가 원 move digest/epoch/root/Volume revision을 서명해 제출한다. payload로 다른 app recipe/native 결과를 공급하지 않는다. 기존 management/ModuleReport의 현재 quorum·고정 target 선언·검증된 복사/source 참조 종료를 사용해 owner CAS/Arm·같은 Inventory의 대상 operation을 원자 게시한다. 노드 간 파일 복사는 기존 VolumeTransfer=12이며 별도 app 실행/합의 프로토콜을 만들지 않는다. app Origin은 원 begin-volume-move 서명을 유지하고 target operation으로 해석한다.


### 읽기 전용 이관 계획

기존 User `app-plan-stream`의 schema1 AppPlanRequest.Move는 원 app/Volume·move ID·byte/entry·유한 transfer allowance를 선택한다. 목표 앱 전체 파일은 기존4MiB/24KiB chunk·인증 digest/EOF 경계를 사용하고 답은 원 typed begin 입력과 target Blueprint를 결합한 최대4MiB artifact다. 일반 app plan/dispatch는 이 preview를 실행 권한으로 사용하지 않는다. 요청자가 native witness를 공급하지 못하며 leader 서비스가 현재 source owner의 `volume-move-recipe-observe`를 읽는다. owner는 원 Activations의 현재 live writer recipe와 전후 quorum permit만 확인하고 clean 종료/fence/복사 허가를 만들지 않는다. 서비스는 새 quorum view에서 현재 caller 권한·동일 NativeBinding/공유 consumer·owner revision을 다시 검사한 뒤 계획한다. readonly 계획 자체는 Raft upload/reservation을 만들지 않는다. 실제 move는 기존 user operation/upload/관리 CAS·Group 승인·VolumeTransfer12를 사용한다.

