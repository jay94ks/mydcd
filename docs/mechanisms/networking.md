# 네트워크

클러스터는 CIDR의 전역 유일성, tenant·노드 소유권과 주소/참조를 통제한다. 실제 컨테이너의 주소 설정과 자동 할당은 Docker IPAM/SDK를 사용한다. Sfc의 제품 범위는 CIDR·IPAM 통제이며 DHCP 서버를 제공하지 않는다.

SFCP TUN 망은 관리 자원이다. tenant 관리 명령이 이름 있는 논리 망과 노드별 구성을 정의하고 앱은 그 이름을 참조한다. 앱 종료는 빌린 관리 망을 삭제하지 않는다.

내장 DNS는 관리된 주소/서비스와 소유 노드의 현재 상태를 사용한다. CIDR·IPAM·DNS 설정은 실행 중 관리 변경이 가능하며, 변경 후보와 기존 consumer·주소/질의/flow 참조를 구분한다. 기존 참조가 있는 망의 종료는 원 owner의 실제 정산을 기다린다.

교차 tenant 경로는 승인된 source/destination 경계를 따른다. Seafield Cluster 소유 Docker 망은 SDK의 `nat-unprotected`와 Sfc의 기본 차단 책임을 결합한다. 다른 망이나 Docker daemon 전체의 방화벽 책임을 변경하지 않는다.

Ingress는 외부 HTTP/1.1·HTTP/2·HTTP/3 요청을 처리한다. 노드 제어·복제·터널 데이터는 SFCP 경계 안에 유지한다. 일반 TCP/UDP 포트 노출과 ACME/Certbot 자동화는 현재 MVP 이후의 확장이다.

[자원표](../architecture/resource-ownership.md), [SFCP](../protocol/sfcp.md), [network.yaml](../cli/network.md)를 먼저 읽는다. 구체적인 내부 경계는 CIDR/IPAM/DNS·관리 TUN·커널 경계를 참조한다.


## Replica DNS의 예약과 가용성

같은 논리 서비스의 명시 replica는 여러 exact Task endpoint로 DNS 이름을 공유한다. 이름·IPAM·망 참조는 실제 종료/closure까지 보존하며, 응답에서 제외하는 것만으로 회수하지 않는다. DNS 소유 노드는 현재 WorkKey와 원 Task/native·세대/리비전, 신선한 Applied/Healthy를 대조하여 격리·실패·오래된 replica 주소를 제외한다. 다른 정상 주소는 계속 반환하고 전부 제외된 예약 이름은 NODATA로 응답한다. 원 DNS policy의 Source/Serial·주소 예약을 health polling으로 재작성하지 않으며, 현재 시각에 따른 가용성은 policy cache 밖에서 재평가한다.

순차 갱신의 미교체 replica는 원 recipe·workload journal과 BindingSource 승인을 사용해 검사/복구한다. 새 목표가 성공한 것으로 표시하지 않으며, 선택된 파동의 종료 대상과 whole-app down에는 기존 fence를 유지한다. 실제 DNS/Ingress·두 노드 장애 수락은 RQ5 계획을 따른다.


## Replica Ingress의 listener와 backend 수명

명시 replica backend 서비스는 정확한 instance key들로 연결하며 세대별 Task 참조를 listener 자체의 종료 의존성으로 쓰지 않는다. 고정 망 의존은 유지하고, 같은 instance 집합의 이미지 교체는 원 listener를 보존한다. 실제 backend는 현재 같은 tenant/app/deployment·논리 서비스·Task owner·세대/리비전과 원 Binding 권한에서 얻는다. 이름이 같은 다른 서비스나 stale Task를 채택하지 않는다. listener/배치 집합 변경은 계획의 별도 교체 영향을 따른다.

backend update는 기존 balancer와 내구 journal을 사용한다. 교체 backend의 새 요청을 막고 원 요청 lease가 끝날 때까지 다른 backend를 유지한다. 원 네트워크 pin 반환과 새 pin 확보 후 pool을 게시한다. 응답이 유실된 Acquire도 같은 pin identity로 확인/반환하며, Task 삭제 뒤에는 최신 Task의 망을 찾아 반환하지 않는다. 원 native journal의 consumer/lease를 반환하므로 새 세대의 pin을 건드리지 않는다. 일시 중지된 backend를 새 건강한 backend로 표시하거나 오래된 probe 결과를 새 세대로 옮기지 않는다.

네트워크 consumer 예산도 각 Ingress route의 service/network를 펼친 같은 선언 그래프로 계산한다. 같은 Task가 여러 route의 backend로 쓰이면 gateway가 갖는 route별 lease만큼 별도 consumer다. 예를 들어 Task3개와 web 복제본2개를 쓰는 두 route·고정 Task1개를 쓰는 한 route는 Task용3개와 Ingress용5개의 망 참조가 필요하다. network-reference·DNS·다른 앱의 참조는 별도로 합산하며 node/tenant 한도를 모두 적용한다. 기존 단일 backend 선언의 consumer 식별자는 유지한다.

SystemWildcard는 shared route의 현재 권한을 검사하는 파생 값이다. 같은 세대의 listener를 종료할 때는 물리 설정 비교에서 제외하며 원 bound NativeID는 보존한다. 이 차이를 새 listener/owner/backend 설정 변경을 허용하는 근거로 사용하지 않는다. 실제 wildcard 활성화에는 계속 현재 권한 검사를 적용한다.

사용자/노드 권한과 원 listener source는 유지한다. 실제 next-wave 조건은 새 Task health와 소유자가 관측한 새 Ingress backend의 exact ref를 함께 요구한다. listener 하나가 응답 가능하다는 사실과 모든 replica가 준비됐다는 사실을 구분한다. 컴파일·fake native facts만으로 이 동작의 실제 수락을 주장하지 않는다.

한번 Drain한 backend 세대를 다시 serving 상태로 되돌리지 않는다. 그런 후속 view는 거부하고 원 pending 목표와 참조를 보존하며, 교체는 원 consumer 정산 뒤 새 Task 세대로 진행한다. 전체 listener 종료는 현재 pool과 미정산 교체 pool을 함께 정산하며 빈 최신 투영만으로 기존 참조가 사라졌다고 판단하지 않는다.

순차 교체에서 원 Task 종료는 listener owner의 원 backend Drain·진행 중 요청 반환 확인 뒤 진행한다. 실제 요청이 남아 있거나 원 세대의 양의 서명 사실이 없으면 Task의 첫 Drain을 전송하지 않는다. backend를 health 목록에서 제외한 것만으로 원 요청 종료를 판정하지 않는다. 같은 세대 Drain의 단조성과 기존 Unknown 정산을 유지한다.
