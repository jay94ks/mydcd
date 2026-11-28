## 빌드 캐시 관측 페이지

User `image-build-cache`의 Job selector는 선택한 tenant의 원 job이 사용하는
**tenant/context/등록 root/builder digest** 캐시의 마지막 SDK 관측을 읽는다. 동일 범위의
후속 실행이 같은 캐시를 재사용하므로 관측한 실행은 `Page.ObservedBy`와 optional
`ObservedKind`로 구분한다. 종류 생략은 기존 빌드, `cache-prune`는 수동 정리다.
삭제된 job이나 현재 사용자·tenant·노드 범위에서 조회할 수 없는 job은 거부한다.

사용자 Unix와 네트워크 SFCP User 요청은 같다.

```text
Request = {Schema:1,Method:"image-build-cache",Nonce:[32],Params:{Tenant,
           Query:{Job},After?}}
Reply   = {Schema:1,Code:"ok",Data:{
  Tenant,Job,Context,Node,JobSnapshot:[32],Epoch,Next,
  Page:{Schema:1,Cache:[32],Snapshot:[32],ObservedBy:[32],ObservedKind?:"cache-prune",
        Available,Borrowed,ObservedAt,LastAttemptAt,LastAttemptCode,
        ReportedBytes,Count,Offset,Next,
        Entries:[{ID,Kind,Bytes,CreatedAt,LastUsedAt,Uses,InUse,Mutable,Shared}]}
}}
```

`Code`는 기존 `denied/invalid/conflict/unavailable` 오류를 사용한다. 현재 Read 또는
ManageRegistry 권한과 원 node 범위를 페이지 전후 다시 확인한다. 내부 member Management
`image-build-cache-owner`는 `{Session,Tenant,Query:{Job},After,Spec,Epoch}`를 원 owner에
전달한다. 설치 member만 호출하고 owner가 사용자 권한을 재검사한다. `Latest=false`로
원 node에 머무르며 leader forwarding이나 별도 비인증 BuildKit API를 제공하지 않는다.

관측은 원 finite SDK solve가 반환한 뒤 daemon/SDK/원 cache reader가 살아 있는 동안
실제 `DiskUsage`로 수행한다. 조회 요청은 native journal/캐시를 생성하거나 daemon을
기동하지 않는다. 관측은 node DB에만 저장하며 Raft에 대형 항목 목록을 복제하지 않는다.
한 관측은 최대16,384항목, 페이지는 최대32항목·24KiB다. 원문 `Description`, RUN 명령,
URL·오류 body는 저장하지 않는다. `Kind`는 `internal/frontend/source.local/
source.git.checkout/exec.cachemount/regular/other`의 안전한 요약이다.

- `Available=false`: 성공 관측이 없다. 실제 사용량0을 뜻하지 않는다.
- `ObservedAt/ObservedBy`: 보존한 성공 관측의 Unix 초·원 실행 지문이다. ObservedKind가
  생략되면 기존 job Spec digest, `cache-prune`면 원 maintenance intent digest다.
- `LastAttemptCode`: 미시도는 빈 값, 성공은 `OK`, SDK 읽기/응답 변환 실패는
  `UNAVAILABLE`이다. 실패 후에도 이전 성공 관측과 시각은 유지한다.
- `Borrowed`: 현재 native cache record에 job 참조가 남았다는 뜻이다. 항목별 `InUse`는
  **관측 시점**의 SDK 값이며 조회 시점의 실시간 상태나 삭제 허가는 아니다.
- `ReportedBytes`: shared record를 포함한 SDK 항목 크기의 합이다. 실제 filesystem
  할당량·회수 가능량·디스크 강제 quota와 구분한다.
- `Snapshot`은 성공 관측 전체의 지문이다. outer `Next` cursor는 같은 관측·선택 job
  Spec digest·module epoch·다음 offset에 고정된다. 관측이 바뀌면 `conflict`로 처음부터
  다시 조회한다. 실패 관측만 갱신된 경우 이전 항목 페이지는 계속 읽을 수 있다.

이 경로는 마지막 관측 조회다. 서버/컨텍스트 요약 inventory는 아래 조회를 사용한다. idle daemon의 명시 재관측,
선택 삭제·idle 주기 정리는 후속 연결 대상이다. 빌드 종료 시 자동 정리는 아래 계약을 따른다. 관측 조회를 실제 cache 회수나
원 job 재실행의 성공으로 취급하지 않는다.


