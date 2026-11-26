## Tenant 단독 컨테이너와 파일 위임

| 자원 | 정의/변경 주체 | 참조·수명 |
|---|---|---|
| tenant 소유 단독 컨테이너(temp/fixed) | tenant Deploy, 다른 사용자의 temp 연결·종료는 tenant 관리자 | 명시 owner kind와 불변 내부 scope; 기존 Task/Binding/native를 사용. 앱/CD/down에서 제외. temp 정책 만료도 원 Inventory retirement로 정산 |
| Volume 폴더 위임 | tenant Volume manager | 기존 access Catalog의 사용자·Volume·상대 폴더 접두어 grant. credential ceiling과 현재 계정/tenant Read를 함께 검사 |
| Volume 파일 작업 | Volume manager 또는 위임 사용자 | 기존 Volume consumer/native pin에 고정. 본문은 이력 밖 purpose18. 빌린 Volume·망은 컨테이너 종료로 삭제하지 않음 |

자세한 계약은 [단독 컨테이너](../../reference/standalone.md)와 [Volume 파일](../../reference/volume-files.md)을 따른다.

단독 temp의 TTL 연장은 생성자 또는 해당 tenant 관리자(현재 Deploy)가 원 관리 Target CAS로 요청한다. 새 만료는 원 요청 At+N, 같은 생성 시각부터 최대86400초다. 앱/CD가 이 수명을 변경하지 않으며 연장은 원 Task/native·Binding·Volume/Secret 참조·연결 해제 유예를 바꾸지 않는다. fixed/종료/정리 상태는 연장할 수 없다.

