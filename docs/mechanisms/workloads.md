# 앱과 lifecycle

`app.yaml`은 특정 tenant의 이름 있는 앱 묶음을 정의한다. 서비스별 이미지·노드 배치·관리 망 이름·설정·Volume/Secret 참조와 앱 정책을 담는다. 관리 자원의 생성/삭제는 별도 관리 명령(`tenant`·`network`·`route`, `manage apply`)의 책임이다.

같은 배포 코어가 CLI와 내장 CD의 입력을 처리한다. 확정된 Task와 참조를 담당 노드가 소비하고 Docker SDK로 컨테이너 생성·시작·정지·삭제를 수행한다. 컨테이너의 수명과 실제 효과는 Docker 기능을 우선 사용한다.

## 기본 검사와 사용자 검사

기본 healthz·depends_on·cmd/file 등 Docker 호환 검사는 엔진이 직접 구현한다. 사용자 lifecycle 스크립트는 접속 방법을 커스텀해 생존 여부를 검사하고 결과별 부가 동작을 수행한다.

| 실행 방식 | 처리 |
|---|---|
| `compile: false` | 내장 Yaegi로 실행 |
| `compile: true` | 허용된 tenant builder 노드의 임시 compiler 컨테이너에서 Go CLI를 생성하고 tenant별 compiled cache로 등록 |
| named script 참조 | tenant에 등록된 이름을 해석하며 없으면 오류 |

컴파일러는 job이 있을 때만 시작하고 유한 batch 뒤 실제 종료/Wait·정리를 수행한다. 앱·컴파일러 소스는 `apps/<name>/`에 두며 운영 workspace/cache와 혼합하지 않는다.

컨테이너 담당 노드의 `sfcd`가 검사 결과·현재 앱 목표·정책을 바탕으로 시작·정지·재시작을 결정한다. 스크립트의 Result는 검사 결과이며 제어 명령이 아니다. CLI를 상시 실행할 필요는 없다. 검사 pass가 컨테이너 종료나 Volume writer fence를 증명하지는 않는다.

[입력 명세](../architecture/app-and-cluster-spec.md), [lifecycle 예시](../examples/php-mysql/lifecycle.example.app.yaml), 고정 Contract·소비 설계를 참조한다.
