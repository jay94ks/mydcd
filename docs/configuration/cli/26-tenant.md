## tenant 허용 저장 경로 선택

`mydc --tenant shop manage tenant-storage --node node-b` 또는 `mydc --tenant shop node storage list`로 자기 tenant에 허용된 root를 조회한다. 다음 페이지는 응답의 cursor를 `--after`에 그대로 전달한다. 현재 ManageVolumes 또는 ManageRegistry가 필요하며 viewer/Read-only 자격은 거부된다. 전체 `Root`는 빌드 정책의 `Nodes[].Root`에 그대로 사용하되 저장 시 현재 ACL·generation·Draining·CAS 검사를 다시 받는다. 다른 tenant ACL은 응답에 없다. [입출력과 예시](../../reference/tenant-storage.md)를 참조한다.

Ingress와 인증서 명령은 [mydc ingress](../../cli/ingress.md), [mydc certificate](../../cli/certificate.md)에 있다.

`ingress unblock`의 원 operation 확정과 실제 owner의 차단 해제는 별개다. `ingress list`의 `BlockRevision`(현재 정책 book 목표)과 각 owner의 `Runtime.BlockRevision`을 비교한다. Runtime이 유효하고 목표 이상이면 적용됨, 미만이면 대기, Runtime 부재/오류이면 관측 불가다. `RootRevision`이나 블록별 CAS는 비교에 사용하지 않으며, 목표 목록에서 ID가 사라진 것만으로 실제 적용 완료로 판단하지 않는다. [관측 계약](../../reference/ingress-management.md)을 따른다.


