## 빌드 종료 시 자동 캐시 정리

### idle 정책 정리를 위한 native 경계

수동 정리와 같은 유한 maintenance daemon에 optional `NativeCachePruneSpec.Automatic`
정책을 전달할 수 있다. 이는 내부 grant 형식이며 공개 수동 filter는 계속
`all|unused|entries`다. 원 Source JobSpec·cache/root identity는 보존하고 Automatic의
CPU·메모리·tmpfs·시간·기간/용량 기준을 이번 daemon에 적용한다. 현재 정책의
BuilderImage와 root가 원 cache scope와 맞아야 하며, 변경된 builder의 옛 cache를
자동으로 다시 실행하거나 다른 namespace로 열지 않는다.

한 pass는 최신 DiskUsage→기간 기준 Prune→최신 DiskUsage→용량 기준 Prune→최신
DiskUsage 순서다. SDK가 사용 중/shared/internal/frontend로 보고한 항목은 보호한다.
원 age receipt는 RPC, size receipt는 optional PolicySize로 각각 선택 지문·Sent와
응답을 보존한다. 빈 선택도 SKIPPED를 명시하고 무제한 빈 filter Prune를 보내지 않는다.
양쪽이 OK/SKIPPED인 경우만 전체 SDK 성공이며, 중간 실패/UNKNOWN 뒤 size를 보내거나
보존된 원 pass를 재전송하지 않는다. SDK 성공과 실제 Stop/Wait/Remove·FD/cache 점유
반환·owner 완료 서명은 별도로 판정한다. 후행 관측 실패는 기존 성공 snapshot과
긍정 RPC를 지우지 않는다. 두 단계의 양수 ACK만 합산하고 int64를 넘는 ACK는 그
stream을 불명/실패로 정산해 보존 가능한 prefix를 유지한다.

이 경계의 공유 정책 승인·주기 수락/예약·idle scheduler 연결은 RQ6의 남은 작업이다.
현재 사용자 조회는 저장된 관측을 읽으며 새 daemon/정리 작업을 생성하지 않는다.

### 빌드 종료 pass

새 SDK solve가 반환하면 원 finite daemon·SDK client·cache 배타 참조를 유지한 채
정책 `Cleanup.UnusedDays`와 `CacheBytes × Cleanup.HighWaterPercent / 100`을 적용한다.
이것은 cache 정리 목표이며 빌드 디스크 hard quota가 아니다. 별도 상시 worker나
추가 컨테이너를 기동하지 않고 원 job의 수락 정책/현재 실행 허가를 사용한다.

먼저 마지막 사용 시각, 없으면 생성 시각이 기간 경계 이전인 항목을 선택한다. 시각이
없거나 미래인 항목은 기간 정리에서 보존한다. 다음 관측에서 shared를 제외한 SDK
record 크기가 용량 목표보다 크면, 같은 cache의 미사용 항목으로 한정해 SDK LRU
정리를 요청한다. 목표가 1바이트 미만이면 SDK의 0=무제한 동작을 피하기 위해 1을 쓴다.
관측 시 InUse/shared/internal/frontend는 자동 선택에서 제외하며 실행 시점의 실제
참조 보호와 삭제는 SDK에 맡긴다. 기본 SDK의 shared/internal 보호를 해제하지 않는다.
빈 선택은 RPC를 보내지 않는다. 기간 정리의 불명/거부 뒤 용량 정리를 이어가지 않는다.

현재 `image-build-cache` Job 응답의 `Page`에는 optional `Cleanup`이 추가된다.

```text
Cleanup = {Schema:1,Cache:[32],Job:[32],Steps:[{
  Kind:"age"|"size",Snapshot:[32],Selection:[32],Selected,MaxUsedSpace,
  SentAt,ReturnedAt,Code,RemovedCount,ReportedBytes
}]}
```

`Job`은 정리를 시도한 원 job Spec digest다. 기간→용량 순서이며 최대2단계다.
`Snapshot/Selection`은 원 관측·선택 ID/옵션의 지문이다. 요청마다 현재 허가를 확인하고
전송 의도와 `SentAt`을 node DB에 먼저 기록한다. `SentAt`은 **실제 전송을 단독으로
증명하지 않는다**. SDK 호출 전 중단이나 응답 유실이 있을 수 있다.

- `SKIPPED`: 선택 항목이 없어 전송하지 않았다.
- `NOT_AUTHORIZED`: 현재 실행 허가를 확보하지 못해 전송하지 않았다. quorum을 확인할
  수 없는 경우도 포함한다.
- `UNKNOWN`: 원 전송 의도를 기록했으며 완전한 성공 응답은 없다. `ReturnedAt=0`이면
  아직 응답을 기록하지 못한 상태다. 진행 중/중단/유실을 구분하지 못하며 재전송하지 않는다.
- `OK`: SDK stream이 정상 EOF로 끝났다. 실제 삭제된 항목이 없을 수도 있다.

`RemovedCount/ReportedBytes`는 검증한 SDK 응답만 합한 값이다. UNKNOWN의 합계는 확인된
일부이며 전체 회수량·filesystem 할당 감소를 뜻하지 않는다. 다른 ID·중복·InUse/shared
응답은 오류로 취급하고 stream을 cancel/drain/join한다. 원문 설명/오류 body는 저장하지 않는다.
완료 기록이 유실돼도 원 의도는 보존하며 같은 단계나 새 job으로 자동 재제출하지 않는다.
정리 후 조회는 원 결과를 대체하거나 UNKNOWN을 성공으로 바꾸지 않는다.

정리 결과와 SDK solve 결과는 별개다. solve의 반환 시점 결과를 먼저 고정하며 후속
관측·정리의 timeout을 소급해 solve 실패로 만들지 않는다. 현재 앱 결과 게시의 허가·
기한은 계속 확인한다. 원 daemon의 실제 Stop/Wait/Remove와 SDK/file/auth/log I/O join
전까지 cache 참조를 반환하지 않는다. 기존 journal/JSON에서 optional Cleanup이 없으면
원 형식을 유지한다. idle 재관측·수동 선택 prune와 주기 정리는
이 빌드 종료 경로와 별도로 연결한다.


