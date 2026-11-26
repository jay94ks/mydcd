## owner 실행·정산 경계

FROM/COPY/RUN `--from`의 digest 해결은 member `image-build-base-work`와
`image-build-base-owner`를 사용한다. 두 메시지는 기존 Management/MYDCP 경계이며
사용자 CLI 명령이나 새 비인증 registry proxy가 아니다.

```text
image-build-base-work request:
{Tenant,Job,Snapshot:[32],Source:{Reference,Platform,Stage,Kind,Line},At}
reply: {Cluster:[32],Builder:[32],Query,Target,Index,Epoch}

image-build-base-owner request: 위 reply 전체
reply: {Schema:1,Cluster:[32],Builder:[32],Tenant,Job,Snapshot:[32],Source,
        Result:{Normalized,Kind,Source,Code,Trust,Image?}}
```

Source.Kind는 `from|copy|mount`이고 Reference는 canonical tag 또는 digest 참조다.
Stage/Line은0 이상이며 Source.Platform은 Policy.Platforms 안에 있어야 한다.
Context.Platforms는 출력 대상이므로 정책에서 허용하면 출력과 다른 build stage platform을
사용할 수 있다. 예를 들어 정책이 amd64/arm64를 허용할 때 출력 arm64·빌드 stage amd64가 가능하다.
Target과 내부 Result는 기존 [이미지 해결](../registry-images.md)의 source/신뢰·공개 manifest
metadata 형식을 사용한다. 저장소 접근 성공이나 digest 해결은 실제 layer pull/BuildKit 성공이 아니다.

work는 원 builder key·수락 job/Spec·현재 사용자 권한·기한/정책을 확인한다. At은 서버의
현재 시각으로 대체한다. queued에서는 원 보존 Dockerfile의 sources를 해결하고,
begin 후에는 원 Inputs에 고정한 Source/digest만
재조회한다. owner 요청의 authenticated sender는 Builder와 같아야 하며 실제 registry/source
owner가 조회 전후 current quorum·job/신뢰·source reader generation/read-set을 검사한다.
기존 외부 source reader의 승인·SecretFetch·usage는 그 owner에 남고 builder에는 공개 digest만
반환한다. 폐기된 좁은 source를 넓은 source나 익명 접근으로 바꾸지 않는다.

Bearer 교환은 member `image-build-base-token-owner`를 사용한다. 요청은
`{Read:<image-build-base-work 응답>,Challenge:{Host,Realm,Service,Scopes:["repository:REPO:pull",...]},Additional?:[<다른 repository의 원 Read>,...]}`이고
응답은 보호된 일시 값 `{Token,IssuedAt,ExpiresIn}`이다. 노드 간 MYDCP의 설치된 원 Builder만
호출하며 `Latest:false`로 원 source owner에 직접 전달한다. owner가 별도로 current quorum과
running/unknown의 서명된 begin/source binding을 조회한다. queued job은 token을 받을 수 없다.
같은 host에 repository가 여러 개면 frozen Inputs에서 요청된 scope 각각의 source를 고른다. Additional은 최대7개로, 총8개 scope/서로 다른 repository까지 같은 원 job/Spec·owner·external reader 선택/세대·ReadSet인지 확인한다. 공용 anonymous source도 같은 owner만 결합한다. 중복 scope는 같은 reader를 추가하지 않으며 요청된 scope가 하나라도 고정 입력에 없으면 전체를 거부한다. 외부 reader가 다르거나 push/catalog를 포함한 요청은 결합하지 않는다.

원 owner는 기존 reader/SecretFetch의 자격·tenant CA client로 실제 `/v2/` challenge를 확인하고
Realm/Service가 요청과 일치할 때만 채택 OCI SDK로 선택한 scope 전부를 교환한다. 중복 scope를 제거하되 첫 repository만 요청하거나 서로 다른 token을 결합하지 않는다. 임의 token URL로 자격을
보내지 않으며 HTTP downgrade를 하지 않는다. 응답에는 password·refresh token·CA를 넣지
않고 job/관측/Raft/log에도 token을 보관하지 않는다. 교환 뒤 현재 권한을 다시 확인한다.
ExpiresIn은 upstream 응답(누락 시 OCI 기본60초)을 사용하되 client 재사용 기한을 원 job
deadline 이하로 줄인다. upstream token 자체의 scope/실제 만료를 MyDC가 재서명한다는 뜻은 아니다.

내장 managed source는 원 builder가 고정 BuildSubject의 pull login으로 registry owner의
token을 교환하며 외부 source owner 메시지로 managed 자격을 발급하지 않는다. BuildKit
session adapter는 이 경로를 repository scope callback에 연결하고 host-only Credentials에
password를 반환하지 않는다. ambient Docker config/helper/token seed를 읽거나 만들지 않는다.
SDK의 client token 위임을 위해 Get/VerifyTokenAuthority에 job-local 메모리 키로 응답하고
session 종료 뒤 폐기한다. registry access token을 MyDC가 새로 발급하는 키가 아니다.
Basic-only source와 서로 다른 reader/managed repository는 아래 FROM graph 본문
경계에서 각각의 owner가 읽는다. host-only 인증에 자격이나 복수 scope를 합치지 않는다.
실제 SDK solve/session·CA의 native 검증은 별도 수락 조건이며,
이 token/API/session 코드만으로 전체 private FROM 지원 완료를 뜻하지 않는다.

worker 준비는 원 ZIP pin/seal/본문을 확인한 동일 Dockerfile 분석·FreezeSources 코어로
고정 Inputs를 만들며, begin 뒤 재개는 기존 Inputs를 사용한다. 실제 BuildKit의 private pull
자격 연결과 전체 worker 기동/종료는 아직 진행 중이다. 이 metadata 경로만으로 private build를
지원 완료로 표시하지 않는다.

내장 registry의 member `image-build-registry-permit` 요청은
`{Tenant,Job,Snapshot:[32],Action:"pull"|"push",Image,At}`다. push의 Image는 빈 값이며
현재 running/unknown job의 고정 출력 repository만 허용한다. pull은 canonical image와
현재 tenant trust·회수 fence를 검사한다. running/unknown의 pull은 원 Inputs의 digest와
begin에 고정한 managed source의 owner/generation/definition까지 일치해야 한다.
응답은 `{Subject,Run,Repository,Index,Epoch}`이고
Subject는 `{Tenant,Job,Snapshot:[32],Node:[32],Image}`인 BuildSubject다. 고정된 active
registry run·원 job/owner·현재 accepted 권한을 확인하며, 다른 repository에 같은 자격을 쓸 수 없다.
이 관리 허가는 현재 내장 registry 경계이며 외부 private FROM 자격 연결을 대체하지 않는다.

registry-only login grant의 `Subject.Build`는 Session/Task와 배타적이다. 원 builder node가
서명하고 Basic username `mydc-build`로 `/token`에 제출한다. registry owner는 원 job과
실제 요청 repository/action을 다시 확인한 뒤 자신의 서명으로 access token을 발급한다.
기존 login/access 도메인과 최대300초·job deadline 한도를 유지한다. builder의 로그인 키와
registry owner의 access issuer를 혼동하지 않으며, 취소·현재 권한/정책 회수·종결 뒤에는
과거 토큰으로 새 I/O를 허용하지 않는다. 사용자 Session을 복제하거나 가짜 앱 Task를 만들지 않는다.

기존 member Management `image-build-job-work {Tenant,ID,At}`는 설치된 원 owner에게
`{Schema:1,Run,Allowed,RootRevision,Epoch,Index,Blocked?}`를 반환한다. Allowed는 현재 accepted grant·
context/policy revision·owner/root·builder/FROM trust·registry generation·이미지 회수 fence와
tenant 동시성·현재 node/tenant CPU·메모리 예산의 공유 조건이다. SecretFetch·native 저장 한도·Docker 실행/종료를 대신하는
Ready나 실제 실행 증거가 아니다. 수락 grant 검사는 원 Origin.At을 사용하므로 Session 만료만으로
이미 수락한 실행을 취소하지 않으며, 현재 계정/credential/role/노드 권한은 계속 검사한다.

Blocked는 `WAITING_FOR_SLOT|WAITING_FOR_BUDGET|NOT_READY|CANCELLED|TIMEOUT|PERMISSION_REVOKED|CLOSED`다.
slot/budget 대기는 원 queued job을 유지하며 취소·권한 회수로 바꾸지 않는다. queued 기한 만료나
회수도 원 identity만 기록한 cleanup을 거쳐 종료 보고하며 native 실행 권한을 새로 만들지 않는다.

managed workload의 mydcd는 같은 observations DB/Engine을 사용하는 worker를 기동한다.
한 노드의 queued 준비는 한 번에 하나이며 shared begin이 예산을 예약하면 다른 job을
설정된 tenant 동시성 안에서 진행한다. 로컬 view는 발견·대기에만 사용하고 새 native
Create/Copy/Start/게시에는 current quorum 허가가 필요하다. 원 native journal 유실을
새 작업으로 초기화하지 않는다. 실패 결과는 정리 전에 고정하고 실제 종료·I/O join·원
publication 정산 뒤 같은 원 operation의 terminal을 보고한다. shutdown은 workers를
join하고 원 native를 유한 cleanup으로 정리한 뒤 DB/RootManager를 닫는다. 알 수 없는
게시 root는 원 자료·참조와 함께 남긴다.

새 worker 실행은 원 rootless 이미지의 유한 daemon과 SDK solve/session을 사용한다.
Bearer 자격은 원 source owner에서 교환하며 관리·빌드 Applied를 실제 성공으로 해석하지 않는다.
새 SourceContent 작업의 외부 source 인증/TLS는 원 owner가 담당하며, 기존 직접 pull
모드는 원 고정 CA/daemon 설정을 유지한다. 내장 registry 게시에는 원 serving chain을
호출별 publisher client에 적용한다. 실제 native/private TLS 경계 검증은 남아 있다. 전체 RQ6 수락은
이 범위와 cache/Git/자료 회수·실제 사용자 경로 검증까지 포함한다.

`image-build-job-report`의 형식은
`{Schema:1,Kind:"job",Cluster,Owner,Tenant,Job,Action,Expected,RootRevision,Epoch,At,Inputs?,Sources?,Closure?,Secrets?,Signature}`다.
owner가 `mydc-imagebuild-job-report-1\x00`와 Signature를 nil로 한 JSON을 서명한다.
Action은 `begin|uncertain|complete`이고 현재 원 job Revision과 root/epoch를 사용한다.
Secrets는 complete에서만 허용하는 realm 순서의 `[]secrets.UseGone`이다. 각 증거의
purpose·원 consumer/generation/selection/lifetime·owner 서명·Stopped/MountsGone을 대조한다.
원 grant가 있으면 증거를 생략할 수 없으며 같은 FSM에서 usage를 반환한다. job 수락과 취소 시
미래 terminal 증거를 64KiB record 안에 보관할 공간도 확인한다.
begin은 Dockerfile에서 해석·해결한 `Inputs:[{Source:{Reference,Platform,Stage,Kind,Line},Image}]`를
고정하며 현재 trust·회수 fence를 다시 검사한다. 최대128개/JSON16KiB이며 같은 source를
서로 다른 digest로 덮거나 다른 repository/platform으로 바꿀 수 없다. 실행 동시성은
begin의 같은 Raft 변경에서 검사하며 unknown도 슬롯을 차지한다. 같은 live job을
`workload/imagebuild/TENANT/JOB/builder` 예약으로 투영해 Task·registry와 공통 한도에 합산한다.
CPU는 `CPUMillis × 1,000,000` NanoCPU, 메모리는 `MemoryBytes`다. queued는 아직 예약하지
않고 begin에서 현재 여유를 재검사한다. cancel·unknown은 예약을 유지하고 terminal owner
closure가 확정되면 반환한다. 별도의 수동 예약이나 가짜 앱 Task를 만들지 않으며 노드 사용량
조회도 같은 완전 projection을 사용한다. 이는 디스크 공간의 강제 quota나 실제 컨테이너 종료 증명이 아니다.

`Sources`는 begin에서만 쓰는 공개 원 참조 목록이다. 각 항목은
`{Image,Owner:[32],External?:{Tenant,ID,Generation},ReadSet?:[32],Managed?:{ID,Generation,Definition:[32]}}`다.
Image는 Inputs에 있는 canonical digest이며 Image 오름차순·중복 없음이다. 같은 digest를
여러 stage/platform에서 사용해도 한 번만 기록한다. External과 Managed는 배타적이며
외부 항목의 ReadSet은 원 reader/provider 선택을 고정한다. managed 항목의 Definition은
원 registry spec digest다. 익명 source에는 보존할 reader가 없어 항목을 만들지 않는다.
서버는 현재 동일 source 선택으로 목록 전체를 다시 계산하여 누락·추가·다른 세대를 거부한다.
원 begin 서명으로 Inputs와 Sources를 검증하며 각 목록은 같은 job record에 한 번만 보관한다.
빈 Sources는 생략하므로 기존 서명 JSON을 변경하지 않는다. begin 시 미래 terminal 보고도
64KiB record에 들어갈 공간을 확인한다.

source 폐기·unbind·권한/Secret 변경은 새 I/O를 막고 job 허가를 회수하지만 원 참조를
반환하지 않는다. 외부 reader owner의 RPC가 모두 끝났어도 같은 reader 세대를 참조하는
미종결 job이 있으면 reader closed와 Vault usage 반환을 거부한다. 내장 source의 원
registry Store도 해당 job이 종결되기 전에는 반환하지 않는다. 이 보존은 listener나
새 token 발급 허가를 유지하는 뜻이 아니다. unknown·취소·복구에서도 원 reader/run을
보존하고 실제 native/I/O 종료가 확인된 job complete와 함께 참조를 해제한다. legacy job에
현재 source를 덧붙여 인증하지 않으며 원 begin의 binding이 없는 registered source는
running base 조회·managed pull에 사용할 수 없다.

Closure는 `{Schema:1,Job:[32],Native:[32],Result,At,Signature}`다. 원 Spec digest와 실제
정리 근거 Native·결과·시각을 `mydc-imagebuild-job-closure-1\x00` 도메인으로 owner가 서명한다.
Closure.At은 실제 종료 증거를 고정한 시각이며 report.At보다 늦을 수 없다. quorum 단절 뒤
재보고할 때는 저장된 Closure를 그대로 사용하고 보고 envelope의 At·현재 CAS/epoch만 갱신한다.
현재 보고의 freshness 검사를 과거 종료 시각으로 대체하지 않는다. queued 취소는 native
실행이 없더라도 수락된 Secret usage를 정산할 owner 종료 증거가 필요하다. running/unknown의
원 native journal이 없으면 신규 작업으로 재생성하지 않는다.
현재 권한이 회수돼도 설치 owner의 정리 보고는 별도로 수락하지만, timeout/연결 단절·원 관측 부재만으로
closure를 만들 수 없다. 실제 Docker/BuildKit 실행·push·로그·Secret 공급과 tenant 전체 삭제의
owner 조율은 RQ6 마지막 실제 어댑터 검증에서 함께 확인한다.


