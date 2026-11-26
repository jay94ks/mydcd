# 예제

예제의 이름·키·주소·이미지·경로는 실제 환경 값으로 바꾼다. 관리 자원을 준비하고 계정/tenant 권한을 확인한 뒤 앱이 이름으로 참조하도록 한다.

| 예제 | 내용 |
|---|---|
| [PHP/MySQL app.yaml](php-mysql/app.yaml) | 두 노드 샘플 앱 |
| [망 설정](php-mysql/network-services.example.yaml) | 관리 망·내장 DNS 관련 입력 |
| [Secret Group](php-mysql/secret-groups.example.yaml) | 계층·순서 적용과 앱 참조 |
| [Volume 이관](php-mysql/vault-volume-migration.example.yaml) | Secret/Volume·명시 이관 관련 입력 |
| [fixed Volume 앱 참조](php-mysql/fixed-volume.example.app.yaml) | node-fixed Volume 이름 참조 |
| [lifecycle 앱 참조](php-mysql/lifecycle.example.app.yaml) | named script의 앱 mapping |
| [망 network.yaml](../cli/network.md)·[교차 tenant 경로](../cli/route.md) | 망 파일과 route 양측 승인 |
| [CLI context](../cli/context.md#파일) | `~/.mydc/config.yaml`과 trust 파일의 모양 |

PHP/MySQL은 범용 컨테이너 엔진을 설명하는 샘플이다. 제품이 이 이름·포트·SQL 초기화에 최적화되도록 요구하지 않는다. 원 시험 절차와 결과는 개발 검증에서 관리한다.
