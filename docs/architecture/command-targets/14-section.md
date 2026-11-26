## 관리 자원 읽기 대상

| 명령 | 인증/대상 | 의미 |
|---|---|---|
| server-version | 선택 cluster/peer TLS pin; 로그인 불필요 | 응답한 mydcd의 공개 판·protocol/build metadata |
| manage network-users/image-trust, volume users | 현재 사용자·선택 tenant Read | 원 Task/Binding·소비자·신뢰 규칙의 공개 projection |
| manage network-closure | 현재 사용자·선택 tenant ManageNetwork cleanup | 정확 owner 관측/서명 closure만 조회; fence/retire는 별도 변경 |
| volume backup limits | tenant Read, --all은 system-admin | 동일 한도/CAS와 archive/staging 예약량 |
| manage route-endpoints | 어느 tenant든 현재 ManageRoutes; 선택 tenant는 받는 쪽 | 공개 활성 TUN 멤버의 안전한 endpoint 이름만 발견 |
| manage lifecycle-uses | tenant ManageServices | 같은 삭제 blocker의 원 named revision/app-binding/build-job |
| secret approvals/usages | realm ManageSecrets; --all은 클러스터 realm | 공개 승인/현재 참조만; 비밀값·서명/provider 비노출 |
| volume show(남은 옛 사본) | tenant Read | 원 move별 retained/deleting/removed; 실제 삭제 명령 아님 |
| volume files grants | tenant manager 또는 위임받은 본인 | 기존 volume-file-grant/revoke의 사용자별 폴더 위임 metadata; 자격 ceiling과 구분 |

method별 selector·페이지·반환 형식은 [관리 자원 조회](../../reference/resource-queries.md)를 따른다. 현재 권한과 원 cleanup 참조를 구분하며 조회 성공을 새 작업 승인으로 사용하지 않는다.

