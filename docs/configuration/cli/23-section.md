## 컨테이너 로그 정리

`app clear-logs APP SERVICE`가 먼저 실제 local/json-file native와 종속 중단 범위를 확인한다. 확인 질문에 답해야(스크립트는 `-y`) 삭제/재생성을 요청한다. Volume/외부 보관본을 보존하고 로컬 로그/writable layer는 복구할 수 없다. `mydc op show ID`로 원 상태와 교체 ID/세대를 읽는다. 같은 ID 재실행은 새 target을 선택하지 않는다. 전송 불명은 출력의 원 request ID로 manage result/resume을 사용한다. 접속/계정/tenant 선택과 wallet·현재 권한/독립 승인 규칙은 다른 관리 명령과 같다. [메시지·상태·예시](../../reference/container-operations.md)를 참조한다.

