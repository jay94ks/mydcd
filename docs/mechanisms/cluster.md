# 클러스터·tenant·노드

노드는 새 클러스터 생성과 기존 클러스터 가입을 선택한다. 자신만 구성원이면 N1/Q1의 단일 노드 클러스터로 동작한다. 초기 클러스터는 백지이며 tenant·앱·망·Volume 등을 임의로 만든 기본 운영 상태를 두지 않는다.

가입·승격·격리·복귀·삭제는 명시 관리 작업이다. voter 구성은 Raft로 확정하며, 노드가 응답하지 않는다는 이유로 자동으로 quorum이나 membership을 축소하지 않는다. 격리/삭제에서는 새 작업 입장과 이미 소유한 native 자원의 종료·보존을 구분한다.

계정은 여러 tenant에 소속될 수 있고, username으로 로그인한다. password·개인키·token 중 등록된 인증 방식을 사용한다. 시스템 관리자는 모든 tenant를 관리할 수 있으며 tenant manager는 자기 tenant의 허용된 자원만 관리한다.

| tenant 자원 | 관리 책임 |
|---|---|
| 망·주소·DNS·교차 tenant 경로 | 전역 CIDR 유일성과 소유/승인 경계를 따름 |
| 앱·CD | 자기 tenant의 이름 있는 앱과 실행 정책 |
| Secret Vault·Volume | 자기 tenant의 비밀/저장 자원 및 앱 참조 |
| private registry·신뢰 출처 | sfcd 내장 registry와 허용 이미지 출처 |

새 tenant의 기본 신뢰 출처는 Docker Hub다. private registry는 `go-containerregistry` 기반으로 sfcd가 서비스하고 저장·인증·tenant 경계를 관리한다.

전체 tenant 삭제는 관리 상태의 삭제 의도와 실제 owner의 종료 보고를 연결한다. 보존 데이터의 명시 정산 정책을 따르며 다른 tenant의 앱·데이터를 종료하지 않는다.

명령은 [대상표](../architecture/command-targets.md), 생성/가입 세부 설계는 bootstrap, tenant/삭제 설계는 tenant·retirement를 참조한다.

노드의 복제/issuer 신뢰와 업무 격리·키 회수의 차이, 사용자 복수 키의 현재 계약은 [신뢰 경계](security.md)를 따른다.
