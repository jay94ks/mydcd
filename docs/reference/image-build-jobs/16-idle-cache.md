## Idle cache의 주기 정책 정리

`sfcd`는 기존 빌드 루프에서 idle cache를 순서대로 살펴보고, 현재 빌드 정책의 기간·용량
기준으로 유한 정리 작업을 실행한다. 별도 상시 BuildKit worker를 두지 않는다. 같은 cache의
미종결 빌드나 수동/자동 정리가 있으면 새 자동 작업을 수락하지 않는다. 원 cache가 실제
존재하고 대여 중이 아니며 최근 관측 시도에서 최소300초가 지난 경우에만 제안한다.
이전 자동 작업이 있으면 실제 ClosedAt에서도 최소300초를 기다린다. 이 간격은 정확한
실행 시각을 보장하는 스케줄이 아니며 자원·권한·quorum 대기는 별도로 적용된다.

설치 owner만 latest quorum member Management `image-build-cache-automatic-report`로
다음 서명 메시지를 제출한다. 관리 Unix 사용자 메시지나 새 CLI 명령은 아니다.

```text
{Schema:1,Kind:"cache-automatic",Cluster:[32],Owner:[32],Definition:[32],
 Tenant,Node,Source,Cache:[32],SourceDigest:[32],PolicyRevision,Sequence,
 RootRevision,Epoch,At,Signature:base64}
```

Definition은 현재 `set-image-build-policy` 원 UserOperation의 OperationBytes를 SHA-256한
값이다. Signature는 Signature를 nil로 직렬화한 JSON 앞에
`sfc-imagebuild-cache-automatic-1`과 NUL을 붙인 bytes의 Ed25519 서명이다. Command는
ImageBuildKey의 ModuleReport·`node/<owner hex>` Actor·RootRevision Expected와 기존
ReportRequestID를 쓴다. 새 제안은 서버 현재 시각의 최대30초 전까지 받고, 이미 수락한
같은 보고의 결과 조회는 원 명령으로 처리한다. 시간 값은 Unix 초, `[32]`는 JSON 정수 배열이다.

Raft 수락은 원 정책의 사용자 서명·accepted 승인과 현재 계정/credential·operation ceiling·
tenant/node/root 권한·builder 신뢰를 함께 확인한다. 원 로그인 session의 만료와 현재 권한
회수는 구분한다. 정책 변경/삭제·권한 회수 뒤에는 새 실행을 허용하지 않지만 원 작업의
실제 종료 보고는 계속 정산한다. 새 로그인이나 사용자 서명을 노드가 합성하지 않는다.

cache별 공유 자동 기록은 현재 slot 하나다. Sequence는 이전 값에서1 증가하며 정책 정의와
cache/Sequence로 고유 실행 ID를 만든다. 실제 종료 보고가 없는 queued/running/unknown은
교체하지 않는다. 수동 작업의 ID/결과는 이 slot과 분리해 보존한다. 공개 `build-cache-prunes`
조회에는 현재 자동 행의 `Automatic:true,Sequence`와 내부 Filter.Mode `policy`가 표시된다.
이전 자동 행은 다음 pass의 현재 행으로 교체되므로 이 목록은 전체 자동 실행 이력이 아니다.

기존 maintenance work/report·유한 daemon이 실행을 담당한다. Source는 보존 job의 원 Spec으로
cache/root/builder를 식별하고, 이번 실행의 CPU/메모리/동시성/시간·age/size는 수락된 현재
정책으로 고정한다. 실제 pass의 At/RootRevision을 기한·빌드와의 선후에 쓰며 과거 정책 등록
시각을 쓰지 않는다. begin은 공통 예산을 예약하고 unknown에서도 실제 종료 수락 전까지
유지한다. SDK age→fresh 관측→size의 각각의 Sent/ACK·관측 실패·native 종료는 구분한다.

로컬 반복 기록은 현재 공유 작업·진행 중 I/O·미종결·로컬 applied index보다 앞선 증거와
마지막 성공 관측을 만든 원 native 기록을 보호한 뒤 회수한다. 수동 기록·cache bytes·root
lease·workspace를 이 metadata 회수로 삭제하지 않는다. 관측의 `ObservedKind:"cache-prune"`는
자동/수동 모두 원 maintenance intent를 가리킨다. 캐시 정리 기준은 디스크 hard quota가 아니다.

