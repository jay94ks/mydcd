# 메커니즘

| 문서 | 동작 |
|---|---|
| [클러스터·tenant·노드](cluster.md) | init/join·N1·권한·runtime membership·tenant 종료 |
| [노드 키·사용자 자격](security.md) | 설치 노드/issuer 신뢰·격리/키 회수 구분·사용자 복수 키 |
| [CLI 신원·프로필](cli-identity.md) | Linux user 저장소·cluster/tenant 선택·wallet·login |
| [네트워크](networking.md) | CIDR·Docker IPAM·MYDCP TUN·DNS·route·Ingress |
| [앱과 lifecycle](workloads.md) | app 목표·Docker SDK·검사 결과·Yaegi/컴파일 |
| [Secret·Volume](secrets-and-volumes.md) | 계층/병합/승인·저장 경로·writer·이관·보존 |
| [내장 CD](delivery.md) | Git 후보·목표 비교·기존 배포 코어의 지속 실행 |
| [관측 이벤트](../reference/events.md#노드-내부-전달과-저장) | Docker/SDK 사실·관리 전이 outbox·source 중복 제거·누락 표시 |

각 문서는 제품의 책임과 동작을 설명한다. 자세한 구현 설계·재사용 라이브러리 검토·시험/결함 기록은 devel/에서 관리한다.
