# app.yaml과 tenant 설정 입력 명세

관리 DNS 정책/앱 이름 등록의 세부 계약은 관리 망 DNS를 따른다. 서버 정책은 명시 `configure-network-dns` 관리 변경, 추가 서비스 이름은 앱 attachment의 `aliases`다. 기본 이름은 `<service>.<app>`이고 주소는 원 Task/주소 예약 세대에서 파생한다. 현재 소비 capability가 연결되지 않은 aliases 계획은 거부하며 단순 설정 저장을 실제 DNS 준비로 취급하지 않는다.

명령별 적용대상·권한·로컬 등록/원격 변경·원 결과/재개의 구분은 [명령어 적용대상표](command-targets.md)를 따른다.

두 명세는 책임이 다른 입력이다. `app.yaml`은 특정 tenant에 올릴 앱/서비스 묶음의 목표를 선언한다. tenant 설정은 그 tenant가 클러스터를 사용하는 데 필요한 설정을 그룹 명령과 자원 파일로 바꾼다. 어느 파일도 클러스터 전체를 한 번에 덮어쓰는 권위를 갖지 않는다. 자체 schema는1이다.

이 문서는 입력 의미의 기준이며 자원별 정의 주체·소유권·종료 경계는 [클러스터/앱 자원표](resource-ownership.md)를 따른다. 관리 입력은 아래 명시한 typed 관리 action만 사용한다. 관리 망 member 재구성/전체 폐기·CIDR/IPAM·DNS 정책은 관리 경로, Git source의 앱 후보와 sync는 앱 CD 경로를 사용한다. 실제 native 준비/종료는 각 owner의 결과로 확인한다.

app.yaml artifact의 전송 준비는 실행 수락과 구분한다. upload 요청(서버가 Change로 upload CAS를 정한다)은 사용자/tenant별 upload의 생성0·조각/폐기 revision을 비교하며 다른 앱 관측으로 바뀐 전체 Apps root를 요구하지 않는다. 현재 권한/예산과 원 digest·ID·결과는 유지한다. 앱 수락·이관·자원 변경과 과거 strict 원 요청에는 기존 CAS를 적용하며 파일 재전송으로 원 실패/불명을 새 요청으로 대체하지 않는다.

앱 종료도 선언 파일 재적용과 구분한다. 새 app down은 현재 수락 Origin의 DownTarget을 Target으로 서명해(down CAS 경계는 서버가 Change로 정한다) 동일 선언을 종료한다. 자동 관측으로 바뀐 root/Inventory revision은 원 read point로 보존하되 새 배포/이관 Origin·다른 종료·미래 좌표·현재 cleanup 권한 부재는 거부한다. 기존 Retire/실제 종료·참조 반환 코어를 사용하며 수락을 Gone으로 표시하지 않는다. 과거 Target 없는 원 요청은 strict CAS·bytes/서명/결과를 유지하고 자동 대체하지 않는다.

서비스별 `stop_grace_period`/`stop_signal`은 lifecycle 종료 정책을 따른다. 문자열 grace는 유한0–24시간·초 단위 올림/기본10초이며 signal은 명시 override 또는 원 이미지/SIGTERM 상속이다. 정책은 Task/Process/recipe에 고정해 일반 종료·retirement·Volume 정산에서 함께 사용한다. 원 Stop 전송 표식을 내구 보존하고 timeout 뒤 재전송/강제 삭제로 덮지 않는다. 실제 종료·Volume writer fence는 엔진이 원 native ID로 확인한다.

node 저장 root와 `node-fixed` Volume의 계약은 노드 저장/고정 Volume을 따른다. root는 system admin의 node 관리 명령, fixed Volume은 tenant 관리 명령의 사전 등록, 앱은 external 이름 참조만 사용한다. host path·node/storage 등록을 app.yaml에 넣지 않으며 없는 fixed를 managed 빈 Volume으로 생성하지 않는다.

## app.yaml: tenant의 이름 있는 앱 묶음

Compose 스타일의 `name/services/networks/volumes/secrets` 구조를 사용한다. 대상 tenant와 묶음 이름을 정하고, 각 컨테이너가 **어떤 승인된 노드에서 어떻게 실행되며 어떤 이름의 가상 망에 배치되는지**, 설정·Volume·Secret Vault 입력을 어떻게 소비하는지 정의한다. 앱별 Ingress와 선택 CD 정책도 이 묶음의 운영 범위다. 명칭은 `app.yaml` 명세이며 CLI의 기존 `sfcli compose` 명령군은 이 명세를 소비한다.

| 앱에 정의할 내용 | 참조·권한 경계 |
|---|---|
| tenant·앱 묶음 이름·안정 deployment ID | 현재 로그인/선택 tenant와 일치. 계정·tenant·membership을 생성하지 않음 |
| 컨테이너 이미지/argv·설정·자원·준비 조건·의존·노드 배치 | 현재 node 허가·image trust·예산을 검사. node 가입/투표/underlay 변경은 하지 않음 |
| 이름 기반 가상 망 attachment·서비스 주소/이름 | 이미 관리된 tenant network를 참조. CIDR/pool/owner·DNS/IPAM 서버 설정을 생성/변경하지 않음 |
| Volume 정의/기존 Volume 참조·mount·retain/단일 writer·보호 정책 | 앱이 생성할 자원과 빌려 쓸 자원의 소유권을 구분. backup/restore/이관·기존 데이터 삭제는 명시 작업 |
| 기존 Secret/Group의 순서 있는 선택·고정 공급 참조·파일/환경 변수 projection | [공급 계약](../reference/secret-delivery.md). Group/Secret 생성·ACL/비밀번호·값 입력/교체와 분리. 기존 보호 Group별 승인과 현재 권한을 요구 |
| 앱 Ingress·서비스 DNS 등록 요청·앱 CD 정책 | 허가된 network/zone/노드 예산 안에서 앱 endpoint를 게시. tenant DNS/IPAM 정책·registry/trust·route를 관리하지 않음 |
| 앱/서비스 lifecycle·inline Go script·named script 참조·optimizer/compile | lifecycle 계약. builtin은 직접 구현하며 script는 Yaegi/compiled CLI로 실행. tenant named registry·compiler spawn·의존/캐시 정책을 앱으로 변경하지 않음. 선언 parser는 제품 Program 코어로 shape/scope·기존 DAG를 검사한다. 고정 계획/source selection·Task projection과 실제 staging/runner 준비를 구분하며 담당 노드의 live capability가 없으면 배포를 명시 거부 |

network 이름은 단순 표시 문자열이 아니라 현재 tenant의 관리 객체 참조다. SFCP 기반 TUN 망 자체도 이름 있는 클러스터 관리 자원으로 먼저 정의하며, 참여 노드·CIDR/pool·TUN/Bridge·경로와 운영 상한은 관리 영역이 소유한다. 앱은 그 이름으로 연결하고 사용 참조만 소유한다. 계획 시 서비스별 node에 해당하는 pool/owner·source revision/generation을 고정하고 수락/사용 시 재검사한다. 같은 논리 망이 여러 노드의 CIDR을 포함해도 이름을 해석해 정확한 node-local 권위를 선택한다. 없는 이름을 암묵 생성하거나 다른 tenant/동명 객체로 대체하지 않는다.

앱 제거/prune는 그 앱이 소유한 inventory만 정산한다. 참조한 network/Group/외부 Volume의 삭제 권한으로 확대되지 않는다. Secret source 목록의 순서, 현재 승인, Volume writer/fence와 원 native 참조는 기존 제품 코어를 유지한다.

새 입력은 `x-sfc.nodes/vault/routing/registries`와 network의 `driver/x-sfc`를 빈 값/null인 경우에도 거부한다. network는 기존 이름의 참조이며 `external: false`를 허용하지 않는다. `external`을 생략해도 참조로 정규화한다. CLI `config/plan`과 daemon의 새 계획·수락, CD의 새 파일/Git 후보는 같은 app 입력 계약을 사용한다. 새 `up --plan`도 앱 계약의 artifact만 수락한다.

schema1의 새 artifact에는 `InputKind: app`을 명시한다. 표시만으로 권한을 부여하지 않으며 현재 재컴파일로 선언과 그래프의 일치를 확인한다. 기존 표시 없는 artifact는 과거 수락 작업의 원 조회/재개·Raft 재생·checkpoint 복구에 보존한다. 과거 artifact를 새로운 앱 제출로 수락하거나 원 작업을 새 ID로 바꾸지 않는다.

자동 이름 해석은 tenant catalog에서 서비스 배치 노드의 정확한 member를 선택한다. 관리 TUN 계약의 논리 이름 하나가 여러 node-local pool/owner에 연결되며, 앱 참조는 원 Bridge/TUN source의 revision/generation·해시와 group 구성을 고정한다. 기존 단일-owner network도 정확한 이름/노드/source로 읽는다. 후보가 없거나 중복·drain·변경 중이면 오류이며 native 이름만으로 채택하지 않는다. catalog/앱 metadata 수락은 native 준비 성공이 아니고 실제 borrow/현재 read-back과 별도로 판정한다.

### 서비스의 호스트 포트 직접 공개

앱과 단독 컨테이너는 같은 서비스 `ports` 입력을 사용한다. 기존 compose-go 정규화와 Docker SDK `ExposedPorts`/`PortBindings`를 연결하며 Ingress listener/backend를 자동 생성하지 않는다.

```yaml
services:
  web:
    ports:
      - "127.0.0.1:18080:8080/tcp"
      - target: 53100
        published: "15353"
        host_ip: "127.0.0.1"
        protocol: udp
```

단축/확장 형식과 TCP/UDP를 받으며 기본 protocol은 `tcp`다. target은 컨테이너 포트, published는 해당 배치 노드의 호스트 포트다. published 생략/0은 Docker 동적 할당, `"20000-20010"` 같은 단일 target의 published 범위는 Docker의 범위 내 선택이다. 짝지은 host/target 범위는 compose-go가 개별 항목으로 정규화한다. `mode: ingress/host`는 일반 Docker 컨테이너의 같은 포트 바인딩이며 Swarm routing mesh를 구성하지 않는다. host_ip 생략 시 실제 바인딩 주소는 Docker 기본값을 따른다.

고정 포트는 같은 노드의 수락된 Task/미반환 claim·진행 중 계획·이관 예약·앱 전용 Ingress listener와 주소 wildcard/TCP/UDP를 비교하며 충돌하면 `HOST_PORT_CONFLICT`다. 같은 노드의 여러 replica도 같은 고정 포트를 중복 사용할 수 없다. 동적/선택 범위를 클러스터가 미리 할당하지 않으므로 실제 Docker bind의 실패는 원 작업 결과로 남는다. 노드 파일의 shared gateway나 외부 프로세스와의 충돌도 실제 bind가 최종 판단한다. 계획 성공은 포트 독점이나 native 시작 성공이 아니다.

포트 의도는 원 Task/spec/Binding에 고정되고, 실제 native inspect의 PortBindings/선택 결과를 확인한다. 같은 DB 복구는 원 native와 설정을 대조하며 stop/start는 같은 컨테이너를 제어한다. Docker가 고른 동적 포트는 재시작 시 달라질 수 있으므로 고정 endpoint가 필요하면 published를 명시한다. 선언 변경은 기존 원 종료/교체 절차를 사용하고, 종료 불명을 포트 반환으로 간주하지 않는다. 공개 포트는 배치 노드의 Docker 네트워킹 설정에 따르며 관리 망/CIDR 소유권을 변경하지 않는다.

### 서비스의 다중 노드 배치

서비스는 여러 노드와 노드별 복제본 수를 명시해 배치할 수 있다.

```yaml
services:
  web:
    # image, resources, networks 등은 일반 서비스 선언과 동일
    x-sfc:
      nodes: [node-a, node-b]
      per_node: 1
```

기존 `x-sfc.node`는 단일 배치이며 `nodes`와 함께 쓸 수 없다. `nodes`의 노드 이름은 중복될 수 없고 `per_node` 기본값은1이다. 서비스와 앱 전체의 Task 수는 각각 최대128이며, 각 Task의 노드 허용·이미지 신뢰·자원 한도·Secret consumer를 별도로 검사한다. 모든 노드에 공유하는 명시 static IP와 복제본 2개 이상의 writable/node-fixed Volume은 거부한다. Volume 이관은 기존 명시 move/fence 절차를 따른다.

논리 서비스 이름은 그대로 유지한다. 명시 `nodes` 배치의 Task ID는 `workload/task/<tenant>/<app>/<service>/<node>/r<ordinal>`이며 ordinal은1부터 시작한다. 기존 singleton Task ID는 유지한다. 내부 `Instance` metadata는 입력 필드가 아니며 사용자가 지정할 수 없다. Secret 사용의 `Use.Service`는 논리 서비스 이름이고, 별도 Task/consumer·`Needs.Instance`가 각 파일 투영과 세대를 구분한다.

### 서비스 재배치와 Volume

Volume이 없는 서비스의 `x-sfc.node`를 바꾼 app.yaml은 기존 plan/upload/up 경로로 제출한다. 원 Task의 정확한 종료·Gone·참조 반환을 확인한 뒤 대상 노드에서 새 세대로 시작하며, 다른 노드의 무관한 Task는 유지한다. 응답 유실/Unknown을 원 종료로 간주하거나 원 native가 살아 있는 동안 같은 singleton을 새 노드에 만들지 않는다.

서비스와 Volume의 배치 노드가 다르거나 기존 managed Volume의 owner를 일반 up으로 바꾸려 하면 `VOLUME_MOVE_REQUIRED`다. node-fixed Volume의 원 노드 변경은 `VOLUME_NOT_MOVABLE`이며, 서비스/Volume 선언 자체의 노드 불일치라면 앞선 배치 검사에서 `VOLUME_MOVE_REQUIRED`가 먼저 나올 수 있다. 복제본 2개 이상의 writer는 `REPLICA_SINGLE_WRITER_FORBIDDEN`, node-fixed 참조는 `REPLICA_FIXED_VOLUME_FORBIDDEN`으로 거부한다.

데이터 이관은 [volume move](../cli/volume.md#다른-서버로-옮기기)의 기존 서버 조율을 사용한다. 목표 app.yaml 전체와 원 Volume/operation/plan·기한을 고정하고, 대상 망·입력/Secret 승인·공간 준비를 먼저 확인한다. 이어 source 앱의 cold retirement와 writer fence→복사/검증→owner CAS/Arm→목표 앱의 같은 데이터 활성화→전송 참조 정산을 수행한다. source 앱 전체의 종료 영향을 계획에서 확인해야 하며 별도 CLI 상주 제어 루프는 필요 없다. 원 데이터는 보존하고 명시 삭제 전까지 새 writer와 혼동하지 않는다.

owner 확정 전의 취소는 양쪽 원 작업/reader·native 종료 사실을 정산한 뒤 현재 배치 권한으로 원 노드에 새 앱 operation을 명시 제출해 원 Volume과 데이터로 재시작한다. 원 Task 세대·fence·consumer를 되살리지 않는다. owner 확정 후의 복귀는 별도 명시 역방향 이관이며, 대상에서 새로 쓴 데이터를 버리는 자동 source 재시작으로 처리하지 않는다. 계획의 권한·quota·이름 기반 망·선언 용량 검사와 StoragePreflight 측정은 실제 target 준비/종료 증명을 대신하지 않는다.

관리 DNS는 같은 `<service>.<app>.<zone>` 이름에 각 replica의 정확한 endpoint를 등록한다. 노드 로컬 gateway를 resolver로 사용하고 기본 검색 영역은 `<app>.<zone>`, `<zone>`이다. 명시 DNS/search 설정은 유지한다. Ingress는 같은 논리 서비스의 여러 Task를 기존 health balancer에 연결한다. 일반 서비스 의존은 대상 서비스의 모든 replica를 기다리지만, replica의 갱신 순서는 자원 수명 의존성으로 연결하지 않는다.

Task 범위 lifecycle 검사는 모든 replica에 적용한다. 기존 app 범위 검사의 서비스 역할은 선언된 첫 instance에 고정하며 app coordinator도 하나의 구체적인 Task다. 한 대표 Task의 결과를 모든 replica의 health 성공으로 표시하지 않는다.

## tenant 설정: 그룹 명령과 자원 파일

tenant가 클러스터를 쓰는 데 필요한 설정(망·DNS, route, 구성원, 허용 서버, 한도 등)은 app.yaml에 넣지 않고 그룹 명령으로 바꾼다. 복잡한 자원 하나는 파일 하나(`network.yaml` 등), 단순한 자원은 옵션이다. 같은 파일을 다시 적용해도 결과가 같다. 명령과 파일 형식은 [sfc 명령](../cli/README.md)과 CLI 명령과 파일 형식을 따른다. 아직 그룹 명령으로 옮기지 않은 action은 `manage apply`의 typed 변경 하나로 보낸다. 옛 partial `cluster.yaml`과 `manage cluster`는 없다.

- 파일에 없는 객체를 지우지 않는다. 삭제는 정확한 대상에 대한 명시 명령과 수명 정산을 요구한다.
- 현재 인증 user/session·tenant·CAS·quorum을 같은 관리 코어가 검사한다. tenant 명령으로 system admin 권한·node 가입/투표 권한을 얻지 않는다.
- 여러 단계가 필요한 변경(망 주소 변경, tenant 삭제)은 한 명령이 차례로 밟고, 끊기면 `sfcli op resume`으로 이어 간다. 각 단계는 고정 ID로 한 번만 실행된다.
- Secret 원문·비밀번호·개인키와 실제 데이터는 파일에 넣지 않는다.

app.yaml과 tenant 설정은 include·자동 merge 관계가 아니다. tenant 설정을 먼저 확정한 뒤 앱이 그 이름을 참조한다.

## 범용 명세와 샘플 값

이 명세의 서비스·이미지·노드/포트·mount·Secret 키·health/의존 조건은 앱 입력이다. PHP/MySQL 예시의 이름/경로·SQL 준비/데이터 판정은 샘플 요구이며 parser·배포/이관 코어의 고정 특례가 아니다. 다른 앱도 같은 자원 소유권·이름 참조·원 operation/정산 계약을 사용한다. 앱별 구현은 이미지/fixture 또는 지원되는 명시 lifecycle 검사에 둔다.


## 서비스 로그 설정 — RV4 구현 중·검증 전

목표 입력은 서비스의 `logging: {driver: local, options: {max-size: "10m", max-file: "3", compress: "true"}}`다. `local/json-file`과 문자열 회전 옵션만 다루며 앱 소유 field로 계획/Task/spec digest·Docker 생성/관측에 연결한다. 생략은 Engine 기본 상속이고 클러스터·호스트의 기본 driver를 변경하는 선언이 아니다. 설정 변경은 컨테이너 교체가 필요하며 명시 로그 정리는 별도 재생성 동의/원 작업/Volume 보존 경계를 따른다. 이 절은 RV4의 전체 실제 검증 전 목표 계약이며 로그 삭제 완료나 외부 로그 backend 지원을 뜻하지 않는다.

노드의 캐시 정리는 별도 시스템 관리 operation이며 app.yaml/cluster.yaml 자원으로 선언하지 않는다. 수락된 명시 이미지 삭제가 pending이면 같은 노드의 해당 원 image ID/별칭을 새 app/CD 또는 컴파일 배치가 참조하는 수락은 일시 충돌한다. 기존 수락된 실행·미제거 claim·native 사용은 정리 계획에서 먼저 보호하며 이미지 제거를 앱 새 버전이나 데이터 삭제로 바꾸지 않는다. [노드 이미지 캐시](../reference/node-image-cache.md)를 따른다.

다중 배치의 `app diff`/CD diff는 원 Inventory의 종료 closure로 계산한 `Replacement.Waves`를 보여 준다. 각 항목은 한 노드의 Task 목록과 원 Key/Generation/Revision으로 고정한 종료 대상이다. 앞 노드의 종료가 뒤 노드의 Task까지 전파되는 경우 이를 순차 교체로 표시하지 않고 `ROLLING_DEPENDENCY_CONFLICT`를 반환한다. 진행 중인 원 전송/작업은 `ORIGINAL_OPERATION_PENDING`으로 구분한다. 계획은 현재 권한/원 claim을 읽은 결과이며 실제 종료·다음 노드 시작 허가가 아니다. 실제 실행에서는 원 종료와 새 세대 health를 확인한다.

## 단독 컨테이너 입력

단독 컨테이너는 app.yaml 서비스 하나의 스키마를 재사용하며 `depends_on`·서비스 간 참조·복제·CD만 제외한다. tenant 소유 owner kind와 생성/고정 수명 정책은 서비스 정의 밖 typed metadata다. shell 모드는 기본 `/bin/sh`와 TTY/stdin을 사용하고 entrypoint 모드는 이미지 기본값을 보존한다. 망·Volume·Secret·Ingress·logging·자원·서버·이미지 신뢰는 기존 서비스와 같은 검증/소비 경계다. pin 공개 이름 변경은 내부 scope나 기존 서비스 DNS 별칭을 재작성하지 않는다. 자세한 계약은 [단독 컨테이너](../reference/standalone.md)를 따른다.

### 서비스 주소의 생략과 노드 이관

단일 컨테이너도 attachment의 IPv4/IPv6를 모두 생략하면 기존 네트워크 Book 규칙으로 사용 가능한 주소를 계획하고 원 Task goal에 고정한다. 실제 컨테이너 설정은 Docker SDK/IPAM 경로로 수행한다. 공개 앱 선언은 생략 상태를 유지하므로 노드를 옮길 때 대상 노드 pool로 다시 계획할 수 있다. 명시한 주소는 기존 정적 주소 정책을 유지하며 drain이 임의의 다른 주소로 바꾸지 않는다. 계획 주소는 native 생성/할당 receipt가 아니며 원 Binding·같은 주소 예약과 실제 owner 검증을 거쳐야 한다.
