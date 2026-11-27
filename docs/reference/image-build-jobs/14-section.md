## 수동 캐시 정리의 수락과 대기 조회

실행 연결 중인 관리 형식이다. 아래 관리 수락·owner 보고 형식만으로 실제 SDK 삭제를 주장하지 않는다. native
유지보수 dispatcher와 실제 종료 증거 공급 연결 전까지 정리 완료 기능으로 사용하지 않는다.

관리 change `prune-build-cache`는 `Expected:0`과 다음 Payload를 사용한다.

```text
{"Tenant":"tenant","ID":"cleanup-one","Node":"node-a","Cache":[32개의 바이트],"Filter":{"Mode":"unused","UnusedDays":7}}
```

`Cache`는 inventory가 반환한 원 cache identity이며 CLI의 소문자64자리 hex와 동일한
32바이트다. 위 `[32개의 바이트]`는 배열 길이를 나타내는 표기다. `Filter.Mode`는
`all`, `unused`, `entries` 중 하나다. `all`은 IDs/UnusedDays 없이, `unused`는 양수
UnusedDays만, `entries`는 중복 없이 정렬한 SDK 항목 ID 1–64개만 받는다. 항목 선택은
정리 의도이며 과거 관측의 InUse를 현재 삭제 허가로 사용하지 않는다.

현재 tenant/node의 ManageRegistry·operation ceiling·설치 owner·원 저장 root 권한과
builder 신뢰/이미지 삭제 예약을 확인한다. 같은 ID와 같은 cache의 미종결 정리는
중복 수락하지 않는다. 원 shared job의 ID/Spec digest로 scope를 고정하며 그 job이
삭제 표시됐어도 보존 cache를 대상으로 삼을 수 있다. 새 빌드로 재등록하지 않는다.

`sfcli build cache prune`의 진행 조회는 기존 User
`image-builds`에 `ImageBuild:{Part:"cache-prunes",ID?,Node?}`를 보낸다. 현재 tenant/node
Read 또는 ManageRegistry를 요구한다. 페이지는 공통 Schema/Tenant/Part/RootRevision/
Epoch/Next와 optional `CachePrunes`를 담으며 한 행은 다음 형식이다.

```text
{ID,Node,Context,User,State,Cache:[32],Filter:{Mode,IDs?,UnusedDays?},Revision,At,
 Code?,ClosedAt?,RemovedCount?,ReportedBytes?,Automatic?,Sequence?}
```

원 UserOperation/Session/Spec·host path는 반환하지 않는다. 한 페이지는 최대8행이며
공통 본문 예산도 적용한다. cursor는 cluster/tenant/ID/node/공유 root revision/epoch에
묶는다. 명시 node가 권한 밖이면 빈 성공으로 숨기지 않고 거부한다.

`Automatic:true,Sequence>0`인 행은 [주기 정책 정리](16-idle-cache.md)이며
Filter.Mode는 내부 값 `policy`다. 수동 제출에는 이 값을 받지 않는다. 생략된 두 필드는
기존 수동 행과 같고 수동 JSON을 바꾸지 않는다.

내부 member Management `image-build-cache-prune-work`는 `{Tenant,ID,At}`를 받아 원
설치 owner에게만 `{Schema:1,Cluster,Record,Source,RootRevision,Epoch,Index,Allowed,Blocked}`를
반환한다. 서버가 At을 현재 시각으로 대체하고 latest quorum 상태에서 원 권한/root를
검사한다. Source는 보존 job의 원 Spec이고 Record는 원 승인·source digest와 queued
기록이다. 외부 사용자에게 이 내부 자료를 반환하지 않는다. Blocked는
`PERMISSION_REVOKED`, `UNTRUSTED_BUILDER`, `BUILDER_UNAVAILABLE`, `WAITING_FOR_CACHE`,
`WAITING_FOR_SLOT`, `WAITING_FOR_BUDGET`, `NOT_READY`, `TIMEOUT`, `CLOSED`를 구분한다. Allowed는 현재 실행 허가이며 실행/종료
사실이 아니다.

먼저 수락된 같은 cache의 미종결 빌드는 정리보다 먼저 끝낸다. 이후 수락된 queued
빌드는 `WAITING_FOR_CACHE`로 기다린다. 순서는 같은 Raft namespace의 수락
RootRevision으로 결정하며 벽시계로 추정하지 않는다. pending 정리는 원 root/node/
tenant 종료와 builder 이미지 사용처에 포함된다. builder 이미지 삭제와 cache 내용
정리는 다른 관리 작업이며 registry 이미지 삭제·GC와도 구분한다.


### 수동 cache 정리의 owner 보고와 예산

member Management `image-build-cache-prune-report`는 기존 latest quorum 경로로 다음
서명 보고를 전달한다. 별도 SDK listener나 사용자 계정을 대신하는 node 권한은 만들지 않는다.

```text
{Schema:1,Kind:"cache-prune",Cluster:[32],Owner:[32],Intent:[32],Tenant,ID,
 Action:"begin"|"uncertain"|"complete",Expected,RootRevision,Epoch,At,
 Native?:[32],Code?,ClosedAt?,RemovedCount?,ReportedBytes?,Signature:base64}
```

`Intent`는 원 UserOperation/source ID/Spec digest의 domain-separated SHA-256이다.
서명은 Signature를 nil로 한 JSON 앞에 `sfc-build-cache-prune-report-1`과 NUL을 붙인
bytes에 대한 원 owner의 Ed25519 서명이다. Command는 ImageBuildKey의 ModuleReport,
Actor는 `node/<owner hex>`, Expected는 RootRevision이며 RequestID는 기존
ReportRequestID다. 원 row CAS·epoch·설치 owner를 확인하고 새 envelope의 At은 서버
현재 시각에서 최대30초 전까지 받는다. ClosedAt은 원 native 종료 시각을 그대로 보존한다.

`begin`은 queued/현재 Allowed일 때만 가능하며 running으로 바꾸고 원 Source 정책의
CPU/메모리를 공통 ProjectResources에 예약한다. 일반 빌드와 정리는 같은 tenant 동시
실행 slot을 센다. 이미 running/unknown인 정리는 자신의 예산을 다시 요구하지 않는다.
`uncertain`은 running에서 unknown으로 한 번만 전이하며 참조/예약을 유지한다.
`complete`는 비영 Native 지문·실제 ClosedAt·확인된 결과를 요구한다. Code는
`OK`, `FAILED`, `PERMISSION_REVOKED`, `TIMEOUT`이며 확인된 SDK 응답의 RemovedCount/
ReportedBytes만 보고한다. 실제 파일시스템 여유 공간 증가량을 의미하지 않는다.

queued에서 성공/삭제량을 합성하거나 unknown을 다시 begin하지 않는다. 미시작 실패도
원 native 미실행/정리 증거가 있어야 닫는다. 성공은 succeeded, 나머지 완료는 failed로
전이한다. Reports는 최대3개로 원 서명/순서/CAS/시각을 보존하고 restore 때 같은 전이
검사를 수행한다. 현재 사용자 권한 회수는 새 실행을 막지만 원 설치 owner의 종료
보고를 지우지 않는다. 공유 complete가 수락된 뒤에만 root/node/이미지 참조와 공통
예산을 반환한다. 실제 native 컨테이너/I/O/cache 종료는 이 보고에 앞서 확인해야 한다.


### 수동 정리의 유한 native 실행

정리 컨테이너는 원 maintenance 요청 시각과 보존 Source 정책의 Seconds로 절대 기한을
고정한다. 큐 대기·재시작으로 새 시간 창을 주거나 Source 빌드의 과거 생성 시각을
재사용하지 않는다. 현재 work는 기한 전 NOT_READY/기한 도달 TIMEOUT을 구분한다.
Source 정책의 CPU·메모리·PID·tmpfs 제한과 pinned rootless BuildKit 이미지의 기존
격리를 사용한다. 빌드와 같은 SDK 생성/시작/Stop/Wait/Remove를 소비하되 Dockerfile/
Secret 입력과 registry push를 실행하지 않는다.

원 root 아래 `.sfc-imagebuild/cache-maintenance/<intent hex>/output`만 새로 준비하고
원 cache를 배타적으로 빌린다. 컨테이너에는 output·cache 두 mount만 제공하며 network
mode는 none이다. 소켓은 output 안의 `buildkit.sock`이고 외부 TCP listener가 아니다.
원 FD/inode·UID·동일 이미지/옵션·원 native ID와 pinned SDK server를 확인한다. 디렉터리
Ready/소켓 준비 확인/SDK Prune Sent/최종 종료는 서로 다른 사실이다.

fresh DiskUsage 뒤 현재 권한과 경로를 다시 확인하고 선택 지문/count·UNKNOWN/Sent를
같은 원 native record에 저장한 다음 단회 Prune를 호출한다. 빈 선택은 SKIPPED로
기록하고 RPC를 보내지 않는다. ACK는 선택된 ID/중복/현재 InUse·Shared/크기 합을
검사하며 오류 뒤에도 cancel/drain/join한다. partial/외래 ACK·완료 commit 유실의
UNKNOWN은 재전송하지 않는다. 정리 reader는 SDK와 FD 종료까지 유지하며 그동안
native Remove와 cache 반환을 허용하지 않는다. 원 컨테이너 종료 자체는 새 사용자
권한이나 quorum을 기다리지 않는다.

Runtime은 기존 빌드 스케줄러에서 이 원 정리 요청을 소비한다. 아래 종료/반환과 원
owner 보고를 사용하며, 실제 성공 여부는 해당 사용자·컨테이너 경로의 검증으로 판단한다.


### 정리 종료·캐시 점유 반환·원 결과 보고

SDK 결과는 원 native Outcome에 고정한다. OK는 원 RPC의 OK/SKIPPED에서만 만들고
컨테이너 exit 0만으로 합성하지 않는다. 부분/불명 RPC의 실패도 확인된 ACK 수량만
보존한다. Outcome 뒤에는 새 Create/Start/Prune를 허용하지 않는다. 현재 quorum이
없거나 사용자 권한이 회수돼도 원 컨테이너 Stop/Wait/Remove와 로컬 정산은 수행한다.

임시 디렉터리 정리는 실제 원 native 제거/확실한 미전송·SDK reader 종료 뒤에만
가능하다. root/cache inode와 active cache-root lease를 대조하고 원 maintenance
디렉터리의 output만 검사한다. Removing을 먼저 저장한 뒤 confined RemoveAll·부모
fsync를 수행하고, 원 cache owner 반환과 Closed를 같은 DB 트랜잭션으로 확정한다.
cache 내용과 cache-root lease는 보존한다. Removing 전의 경로 유실/교체는 오류이고,
원 unlink 뒤 commit 유실은 같은 intent로 재개한다. 다른 build/정리의 점유는 반환하지 않는다.

native 완료는 원 Spec 지문·root/cache identity·container effects·RPC·Outcome/닫힘의
지문을 owner 키로 서명해 저장한다. 완료 시각/결과는 재시작·보고 재시도에도 바꾸지
않는다. 별도 fresh quorum/CAS envelope인 기존 complete 보고에 Native/ClosedAt/
Code/확인 수량을 공급한다. 공유 완료 응답이 유실되면 같은 원 보고 결과와 비교하며
새 작업이나 새 cache/root pin을 만들지 않는다.

스케줄러는 원 local journal을 발견하고 원 Source/사용자 승인을 latest quorum으로
확인해 실행한다. 같은 cache의 후행 queued build는 먼저 준비하지 않는다. 로컬 상태에서
원 공유 요청이 보이지 않으면 이를 삭제 확정으로 간주하지 않고 알려진 native만
정지하며 파일·cache owner·원 결과를 보존한다. 실제 종료 사실은 현재 실행 권한과
구분하며 완료된 실패 작업을 살아 있는 native 오류로 표시하지 않는다.


Runtime 종료는 readiness 재관측 사이에 활성 worker가 없던 원 journal도 worker join
뒤 정산한다. 이미 서명/저장된 native 완료는 다시 만들지 않으며 로컬 정산 실패는
Runtime 종료 오류로 반환한다. 공유 결과는 다음 현재 quorum 보고까지 미완료로 유지한다.


### 수동 정리 관측과 조회의 출처

수동 정리의 fresh DiskUsage와 Prune 뒤 readback은 같은 cache 관측 DB를 갱신한다.
원 maintenance journal의 마지막 성공 snapshot/시각과 현재 cache inode·source Spec/
intent를 같은 트랜잭션으로 고정한다. 조회는 실제 생산한 원 journal을 검증하며 없는
자료를 빌드 관측이나 새 빈 namespace로 대체하지 않는다. 관측에는 opaque SDK
Description/오류 본문·과거 RUN 인자를 저장하지 않는다.

공개 CachePage/CacheSummary의 optional `ObservedKind:"cache-prune"`일 때 ObservedBy는
원 정리 intent digest다. 기본 생략은 기존 원 build Spec digest이며 nil 필드의 기존
직렬화·snapshot/cursor를 유지한다. 신규 관측은 출처까지 포함한 snapshot에 고정하고
kind가 다르거나 관측이 바뀐 cursor는 혼용하지 않는다. 대표 job을 새로 실행하지 않는다.

readback 실패는 이전 성공 관측을 남기고 LastAttemptCode를 UNAVAILABLE로 구분한다.
성공한 Prune ACK는 그 실패 때문에 바꾸지 않는다. 반대로 UNKNOWN Prune는 readback의
현재 상태로 성공 판정/재전송하지 않는다. 관측 failure는 실제 빈 cache가 아니고,
관측만으로 cache 반환이나 native 종료를 증명하지 않는다. 완료 서명은 그 시점의
원 observation witness도 고정한다.


### CLI 수동 정리

`sfcli build cache prune [CONTEXT] [--node NODE] [--cache CACHE] [--entry ID] [--unused-days N]`은
현재 cache 목록 하나(같은 epoch)에서 대상 cache를 고르고, 물어본 뒤 cache마다 위의
`prune-build-cache` change를 하나씩 보낸다. 작업 ID는 `--id`(기본 새 ID)에 `-1`, `-2`, ...를
붙인다. 이 일괄 제출은 원자적이지 않다. 중간에 거부되거나 결과를 모르면 뒤 cache는 보내지
않고, 같은 명령을 같은 `--id`로 다시 실행하면 저장된 원 요청부터 이어 보낸다. 각 cache의
실제 정리 완료는 owner 결과로 판단하며 `sfcli op show ID-N`으로 확인한다.
[명령](../../cli/build.md#빌드-캐시)


