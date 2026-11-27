# 아키텍처

| 문서 | 설명 |
|---|---|
| [Go 재작성 결과](go-rewrite-outcome.md) | 실제 채택 구성·구현 결과·검증 범위와 한계 |
| [모듈·소유권](modules.md) | 하나의 sfcd 안의 제어·네트워크·워크로드·Ingress, 공유/노드별 상태 |
| [관리 명령과 앱 선언](commands-and-declarations.md) | 관리 작업과 지속할 앱 목표 상태의 구분 |
| [app.yaml과 tenant 설정](app-and-cluster-spec.md) | 앱 입력과 tenant별 관리 입력의 책임 |
| [자원표](resource-ownership.md) | 생성·관리·참조·삭제 주체 |
| [명령 대상표](command-targets.md) | 실제 명령의 대상·인증·효과·재개 |
| [Raft와 SFCP](raft-and-sfcp.md) | Raft에 쓰는 것과 SFCP로 보내는 것, 노드 보고 method 분류 |

상태 전이의 원리는 [주요 알고리즘](../algorithms/README.md), 기능별 실제 동작은 [메커니즘](../mechanisms/README.md), 프로토콜은 [SFCP](../protocol/sfcp.md)에서 설명한다.
