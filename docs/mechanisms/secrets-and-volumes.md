# Secret·Volume

## Secret Vault

비밀은 실행 중 입력할 수 있다. 클러스터 전역 → tenant root → 다단 Secret Group → Secret의 격리 구조를 사용한다. 여러 Group/Secret을 적용할 때는 선언한 순서대로 동일 키를 덮어써 최종 keyset을 만든다.

배포에 필요한 Group 비밀번호는 원 배포의 승인 대상마다 최초 한 번 입력한다. 승인 시점·사실·대상에 결합된 서명을 보존하고 검증해 승인 상태를 판단한다. 원 승인 보존과 현재 계정/tenant 권한 검사는 별도다. 원 참조가 있다는 이유로 철회된 현재 권한을 되살리지 않는다.

Secret 값 입력과 backup/restore/이관은 명시 작업이다. `app.yaml`과 CD는 관리 자원의 값을 자동으로 만들거나 새 Group 승인을 대신하지 않는다. 실제 값의 projection·교체·회수는 원 Task/참조와 종료 경계에 연결한다.

## 저장 경로와 Volume

| 자원 | 정의·소비 |
|---|---|
| 노드 저장 root | 시스템 관리자가 노드별 HDD/SSD 경로를 등록. OS 포맷/마운트를 자동 수행하지 않음 |
| node-fixed Volume | tenant가 특정 노드의 실제 경로로 사전 등록. 앱은 이름으로 참조하며 이관 불가 |
| 이동 가능한 Volume | owner/native·writer·보존 정책과 명시 이관 작업을 관리 |

앱이 임의 host 경로를 자동 생성하거나 fixed Volume을 다른 노드로 옮기지 않는다. 등록 해제와 원 데이터 삭제를 구분한다.

이관은 원 writer의 확실한 종료/fence와 MYDCP 전송·복원 결과를 정산한 뒤 소유권과 consumer를 연결한다. timeout이나 응답 유실은 새 copy/새 operation을 자동 실행할 근거가 아니다. 원 작업·보존 source·전송/복원 참조를 유지해 결과를 확인한다.

[자원표](../architecture/resource-ownership.md), [Secret 예시](../examples/php-mysql/secret-groups.example.yaml), [fixed Volume 예시](../examples/php-mysql/fixed-volume.example.app.yaml)를 참조한다. 상세 계약은 Secret Group·Vault/Volume·노드 저장에 있다.
