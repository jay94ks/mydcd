## 노드·컨텍스트별 캐시 목록

`mydc build cache list [CONTEXT] [--node NODE]`는 현재 tenant에서
조회 가능한 모든 알려진 cache namespace를 나열한다. 원 job의 tenant/context/root/
builder digest로 묶어 여러 job이 같은 cache를 재사용해도 중복 합산하지 않는다.
삭제된 job/컨텍스트의 namespace도 보존한 원 공유 기록과 현재 조회 권한 아래 표시한다.

사용자 요청은 기존 `image-builds`의 새 part다.

```text
Request = {Schema:1,Method:"image-builds",Nonce:[32],Tenant,
           ImageBuild:{Part:"caches",ID?:context,Node?:node,Upload:""},After?}
Reply.ImageBuild = {Schema:1,Tenant,Part:"caches",RootRevision,Epoch,
  InventoryRoot:[32],Next?,Caches:[{
    Cache:[32],Owner:[32],RepresentativeSnapshot:[32],
    Node,Context,Root,Builder,RepresentativeJob,RootGeneration,
    JobDeleted,ContextDeleted,Code,Usage?:{
      Schema:1,Cache:[32],Snapshot:[32],ObservedBy:[32],ObservedKind?:"cache-prune",
      Recorded,Allocated,Available,Borrowed,ObservedAt,LastAttemptAt,LastAttemptCode,
      ReportedBytes,Count,Kinds:[{Kind,Count,InUse,ReportedBytes,SharedBytes}],Cleanup?
    }
  }]}
```

현재 tenant/node Read 또는 ManageRegistry가 필요하다. tenant가 다르거나 조회 범위 밖의
node는 행에 포함하지 않는다. `Node`를 명시했는데 읽을 권한이 없으면 요청을 거부한다.
한 페이지는 최대4행·24KiB이며 owner별 조회는 요청 전체 기한 안에서 최대5초다. 원 Session·Spec·Secret 참조/값·저장 root의 host path는
공개 페이지에 넣지 않는다. `Root`는 등록 root의 ID이며 filesystem 경로가 아니다.

각 행의 `Code=OK`는 owner에서 요약을 읽었다는 뜻이다. 노드 불통/owner 교체·원 자료
손상·조회 불가 등은 해당 행을 `UNAVAILABLE`로 반환하고 Usage를 넣지 않는다. 실패한
노드의 usage를0으로 계산하지 않는다. `Recorded`는 원 native cache record의 존재,
`Allocated`는 원 directory identity가 기록됐다는 뜻이다. 조회 시 filesystem의 현재
존재를 새로 조사한 결과가 아니다. `Available=false`는 성공 관측이 없다는 뜻이며 실제
빈 cache와 다르다. `Kinds`는 관측 시 SDK 항목을 종류별 집계한 값이고 shared 포함
논리 크기를 합한다. physical 사용량·회수량·강제 quota로 해석하지 않는다.

대표 job은 같은 namespace의 최신 CreatedAt, 같으면 job ID 순으로 선택한다. 새 queued
대표 job에 native 기록이 없어도 같은 cache의 원 관측 job을 검증해 그 자료를 반환한다.
`ObservedBy`와 `Cleanup.Job`은 대표 job과 다를 수 있다. 대표 job의 실행/재실행을
요구하지 않는다. 보존 관측의 원 native job이 유실되거나 scope가 다르면 성공 관측으로
꾸미지 않는다. 원 allocation·daemon·root pin을 조회로 생성하지 않는다.

`InventoryRoot/Next`는 현재 보이는 namespace metadata·selector·module epoch에 고정한다.
job의 진행 revision만 바뀌면 목록을 무효화하지 않으며 namespace/대표/삭제 상태가 바뀌면
conflict로 처음부터 다시 읽는다. 각 행의 node 관측은 자체 Snapshot/ObservedAt으로
구분한다. 페이지 전체가 클러스터의 동시 filesystem snapshot이라는 보장은 하지 않는다.

내부 member Management `image-build-caches-owner` 입력은
`{Session,Tenant,Query,After,Root:[32],Cache:[32],Epoch}`다. 설치 member의 `Latest=false`
원 owner 조회이며 owner가 현재 페이지/권한·원 job/owner를 전후 재검사하고 `CacheSummary`를
반환한다. 새 endpoint나 비인증 SDK listener를 열지 않는다. cache ID를 대상으로 한 보존
항목 조회는 아래 계약을 사용한다. 수동 prune·idle 주기 정리는 별도 연결한다.


