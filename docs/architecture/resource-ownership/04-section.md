## 사용자 컨테이너 운영 조회의 소유권

노드 CPU/메모리·승인된 경로의 파일시스템·tenant 실제 사용량·QUIC 링크·SDK 합의 관측은 담당 sfcd의 observations.db/SDK에 속한다. 현재 멤버 신원·서명·node/source를 검사한 read projection이며 공유 quota·배치·실행 허가를 대체하지 않는다. tenant의 허용 node/root를 먼저 골라 시스템/다른 tenant 정보를 숨기고 같은 파일시스템은 한 번만 합산한다. 합의 순서·term/vote/log/snapshot은 기존 Raft SDK가 소유하며 진단 observer가 합의를 구현하지 않는다. [노드 관측 API](../../reference/node-observations.md)를 따른다.

수락된 앱의 원 app.yaml·버전·별도 로컬 서비스 YAML·CD field overlay는 Apps가 Inventory 수락과 같은 FSM 변경으로 보존하는 앱 소유 metadata다. 앱은 이름으로 빌린 관리 망·Volume·Secret 자체를 소유하지 않는다. 원문 query는 현재 tenant Read로만 읽고 Secret provider 값을 채워 넣지 않는다. 이력 회수는 기존 전부 종료·정산·원장 만료 조건을 재사용하며 버전 counter와 빌린 자원은 보존한다. [원문·버전 API](../../reference/app-source.md)를 따른다.

`tasks`는 Apps의 원 Task/Claim·같은 FSM의 정확한 Binding·소유자 서명 Observation을 읽는 공개 projection이다. 소유 노드가 Docker 상태·재시작 수·검사 metadata를 보고하며 웹·CLI가 독립 상태나 권한을 만들지 않는다. 미수집 Task·낡은 관측은 unknown으로 유지하고 관측 metadata로 원 제어·반환·fence를 변경하지 않는다. [Task 관측 API](../../reference/task-observability.md)를 따른다.

로그/top/stats 결과는 담당 노드가 보유한 실제 컨테이너의 transient 관측이다. app.yaml/cluster.yaml에 결과를 선언하거나 Raft에 본문/지표를 계속 저장하지 않는다. 요청 대상은 현재 tenant/app/service/Task/Binding이며 앱 소유권·현재 Read session·설치 owner의 Work admission을 함께 검사한다. 세대/실제 ID/StartedAt를 조회 전후 대조하고 취소/변경 시 결과를 폐기한다.

유한 SDK 조회는 정확한 native ID와 journal 전후 검사를 사용하고 별도 내구 reader pin을 생성하지 않는다. 해당 handler가 SDK body/연결을 닫고 Runtime 종료와 함께 I/O를 회수한다. 컨테이너 제어·Secret/Volume writer·lifecycle 실행 grant를 소유하지 않으며 앞의 checker read pin 계약과 구분한다. 필드와 사용자 명령은 [운영 API](../../reference/container-operations.md)를 따른다.

### 앱 로그 설정과 정리의 경계

서비스 `logging`은 앱 소유 설정이며 app.yaml과 명시 앱 field override로 관리한다. 노드 Docker daemon 설정·Docker 소유 로그 경로는 앱이 직접 관리하는 자원이 아니다. 로그 정리는 명시 컨테이너 재생성 동의와 원 대상/세대·작업에 결합하고 빌린 Volume/Secret/망을 삭제하지 않는다. 설정/명령·상태는 [컨테이너 운영 API](../../reference/container-operations.md)를 따른다.

### 계정·tenant 구성원 조회의 소유권

공개 사용자 목록·membership·허용 노드는 기존 cluster catalog의 읽기 projection이다. 앱이나 웹 컨테이너가 별도 권한 목록을 소유하지 않는다. `users`는 system-admin, `tenant-members`는 대상 tenant 관리 권한을 현재 signed session과 교차 검사한다. 조회와 페이지 이동은 revision을 변경하거나 계정·membership을 생성하지 않는다. [공개 조회 API](../../reference/user-catalog.md)를 따른다.

본인 공개 key는 cluster catalog의 같은 User credential 소유다. `add-credential`/`disable-credential`은 자기 계정의 제한된 필드만 기존 계정 교체 코어로 변경하며 새 권한 DB를 만들지 않는다. 브라우저 private key는 client 소유이며 새 key의 공개 proof만 관리 operation에 들어간다. 계정 revision 변경 시 기존 전체 session을 회수하고 미정산 원 operation은 그대로 보존한다.

컨테이너 [실제 설정 조회](../../reference/container-detail.md)는 Task 소유 노드가 원 ID/labels·Binding으로 만든 읽기 전용 projection이다. 원 Inspector 전체·호스트 bind source·실제 환경 값을 관리 자원으로 복제하지 않는다. 최근 checker 요약은 기존 노드 관측 레코드가 보관하고 원 run/세대/native와 함께 정리한다. 조회가 새로운 컨테이너 수명이나 제어 승인을 만들지 않는다.

가림 완료 로그/상세의 읽기 window는 원 native owner 프로세스가 사용자·query·Task/native에 고정해 한시 보관한다. 합계64MiB/16개/10분 안에서 로그8MiB·상세16MiB를 받고 새 관리 자원·Raft 상태·실행 grant로 취급하지 않는다. 만료/재시작/정상 종료에서 정리하며 현재 읽기 권한을 매번 검사한다.

명시 Task 재시작의 승인·진행 행은 기존 app/Apps 상태가 소유하며 원 사용자 operation·Task·generation·revision·native에 고정한다. owner의 private 전송 기록은 그 원 요청만 정산한다. 이 행은 새 앱 버전·컨테이너·망·Volume을 소유하지 않는다. 종료/권한 회수로 새 Start가 금지되어도 이미 보낸 호출의 불명 기록을 삭제하지 않는다. [Task 재시작](../../reference/task-actions.md)을 따른다.

노드 scheduling(cordon)은 시스템 관리 자원이며 Members Directory의 별도 행으로 저장한다. app/CD는 새 배치 계획에서 이를 소비한다. 기존 Task·Binding·Volume의 소유권/업무 권한·Raft 멤버십은 유지하고, 앱 종료가 scheduling 행을 삭제하지 않는다. uncordon은 제외만 해제하며 별도 node 격리를 복원하지 않는다.

CD 후보 승인·반려는 tenant 앱의 CD 상태가 소유한다. 원 서명 결정은 Apps metadata에, 반려 source/commit/digest는 같은 Delivery에 저장한다. 새 source가 과거 반려를 삭제하지 않으며 명시 replan만 현재 source를 재고한다. 결정은 Vault Group 승인이나 Volume/배포 권한을 소유하지 않는다. 공개 조회에는 원 계정 ID/이유/후보만 제공한다.

Raft 수동 유지보수 job은 시스템 관리 자원으로 `control/raft-maintenance`가 원 사용자 서명·선택/키·노드별 진행을 소유한다. owner의 private 전송/결과 기록과 SDK snapshot/log store는 그 원 job을 소비한다. queued/running은 node activity·원장 회수의 outstanding 참조이며 앱·tenant 종료가 삭제하지 않는다. 완료 결과·설정 복원과 물리 파일 회수는 구분한다. [Raft 유지보수](../../reference/raft-maintenance.md)를 따른다.

Registry 시작·정지 [미리보기](../../reference/registry-actions.md)는 기존 cluster 관리 RegistryEntry/Volume의 공개 읽기 projection이다. 실행은 같은 원 signed action과 기존 run/writer·Volume consumer/closure 소유권을 재사용한다. 별도 앱 자원이나 새 Volume을 만들지 않고 정지·응답 유실로 원 데이터/진행 참조를 삭제하지 않는다.

Tunnel reconnect job은 시스템 관리 자원 `control/tunnel-reconnects`가 원 사용자 operation·owner/peer 설치 키·주소·서명 down 관측/PairID를 소유한다. owner private maintenance/tunnel 기록은 그 원 Dial 효과만 정산한다. queued/running은 양쪽 노드와 원장 회수의 outstanding 참조이며 앱/tenant가 종료시 삭제하지 않는다. 새 가상망·TUN·주소·컨테이너 수명을 소유하지 않는다. [Mesh 복구](../../reference/tunnel-reconnect.md)를 따른다.

노드 이미지 캐시 정리는 시스템 관리 원 job `control/image-cache`가 선택 node/key·원 signed plan·전체 image ID/별칭·항목별 결과를 소유한다. owner private maintenance/image-cache 기록과 기존 Docker SDK가 원 효과를 소비한다. pending은 node activity/원장 회수에 포함하고 원 별칭의 새 app/CD/컴파일 배치 수락을 검사한다. 기존 앱/claim·native 컨테이너가 쓰는 이미지는 빌려 삭제하지 않으며 정리가 app/Volume/registry 데이터를 소유하지 않는다. [명시 캐시 정리](../../reference/node-image-cache.md)를 따른다.

| 자원 | 정의·변경 주체 | 앱 참조·수명 경계 |
|---|---|---|
| 사용자 최초 password/일회 token | system-admin의 보호 stage/원 관측과 서명 issue-initial-credential. 고정 설치된 시스템 credential provider와 같은 access/Raft 계정 CAS | tenant/app Secret Vault와 별개. 검증값·consumed marker는 시스템 provider, 공개 fact/reference만 Raft. CLI 원 intent/journal은 Linux user profile/account별. 앱 종료·로그아웃으로 provider record/one-use marker를 지우지 않음. token 원문은 첫 성공 호출의 memory/보호 출력만 허용 |
| 관측 이벤트·source cursor/native mapping | 각 원 Task/노드의 기존 SDK 관측과 control committed-transition projection. 기존 node observations.db가 bounded journal·ACK를 소유 | 앱/tenant 관리 자원·실행 grant가 아닌 읽기 projection. 원 Task/native·세대와 공유 공개 ID를 보존하고 Secret/로그 원문을 넣지 않음. 앱 down이 빌린 자원이나 과거 원 이벤트 신원을 바꾸지 않으며7일/4096개 retention으로 회수. private outbox는 FSM checkpoint와 atomic하되 snapshot의 관리 상태와 분리 |

다중 배치에서도 논리 서비스와 각 Task/inputs는 앱 소유 자원이다. 사용자 `nodes`/`per_node`를 고정한 instance metadata는 독립 owner·세대·예약·consumer를 식별하며 클러스터 망/Volume 소유권을 바꾸지 않는다. 같은 논리 서비스의 DNS 이름은 여러 exact endpoint에 연결할 수 있지만 다른 앱/서비스의 이름을 가져올 수 없다. 이 다중 배치 경계는 [app.yaml의 다중 배치 명세](../app-and-cluster-spec.md#서비스의-다중-노드-배치)를 따른다.

순차 교체의 파동 cursor와 Previous 원 claim은 같은 앱 Inventory/Execution의 metadata다. 별도 앱·노드 agent·새 DB/승인 주체를 만들지 않는다. 아직 교체하지 않은 원 Task와 그 Secret/Volume/주소 pin은 보존하고, 선택된 원 종료/삭제 증명 뒤에만 새 세대가 소비한다. 조회된 원 native의 건강을 새 목표의 적용 성공으로 취급하지 않는다. 원 operation의 최종 Finish 전에는 전체 배포 성공을 기록하지 않는다.


### CD의 별도 새 서비스 추가분

로컬 추가분은 해당 tenant/app 소유의 별도 source 문서다. 현재 Deploy 권한 사용자가 signed `put-app-local-services`/`clear-app-local-services`로 전체 교체/제거하고, 앱은 공유 망/Volume/Secret을 이름으로 빌린다. Git 서비스나 관리 자원을 수정하지 않는다. Git 원문·현재 실행 source·추가분의 바이트/버전/작성자를 구분하고 새 sync가 수락한 local grant를 원 BindingSource에 보존한다. 현재 후보를 clear해도 원 실행의 참조를 지우지 않으며 실제 종료/positive closure/Binding 반환 뒤 정산한다. 원 CD 등록자 권한과 새 작성자의 자원 권한을 서로 대체하지 않는다. [CLI와 수명](../../reference/cd-inspection.md#별도-로컬-서비스-추가분)을 따른다.


순차 replica 교체의 held native는 원 BindingSource grant·recipe·journal과 원 주소/입력 참조를 유지한다. 파동의 정확한 종료 closure 밖 자원은 검사·원 native 복구를 계속할 수 있지만 선택된 종료 대상과 whole-app down은 면제하지 않는다. DNS 가용성 필터가 이름·IPAM/망 참조나 Secret/Volume 소비자를 반환하지 않으며, 모든 원 대상의 positive closure 뒤에만 이전 실행의 읽기용 recipe 정보를 회수한다.


명시 replica Ingress의 서비스 연결은 instance identity 목록이며 Task의 세대별 lifetime pin과 구분한다. listener는 원 source/망 pin을 유지하고 backend별 원 요청 lease·네트워크 consumer는 교체 journal이 소유한다. 기존 요청 정산 전 backend pin을 반환하지 않으며 Task 종료나 새 generation으로 원 consumer를 덮어쓰지 않는다. backend 집합·현재 권한·관측의 변화는 새 사용자 앱이나 새 rollout을 만들지 않는다. listener/선언 변경의 cold 교체는 별도 계획/종료 계약을 따른다.

순차 replica 교체의 Ingress backend 수명: 앱 Inventory가 원 Task 종료를 선택하더라도 listener owner의 원 세대 요청 차단·내구 HTTP lease 반환 보고 전에는 Task 첫 Drain을 dispatch하지 않는다. listener는 앱의 같은 source로 유지하며 파동마다 새 listener 자원을 만들지 않는다. 이미 dispatch한 원 명령의 Unknown·원 종료 proof/삭제 정산은 유지한다.

이관 계획의 StoragePreflight는 기존 node-observation의 공개 측정이며 앱/tenant 소유의 새 자원이나 용량 예약이 아니다. 원 node key·현재 tenant 권한에 따라 Docker 데이터 저장소의 여유 숫자만 투영하고 호스트 경로를 노출하지 않는다. 앱 종료가 node 관측을 삭제하지 않으며 stale/unknown 측정은 owner 전환·writer 종료를 허가하지 않는다. 실제 target preparation의 공간 재검사와 원 native/Volume 보존 규칙은 유지한다.

외부 source의 관리 reader는 tenant 관리 자원이다. `bind-external-registry`가 원 사용자·노드·정의 지문과 `registry-source` purpose의 Secret 사용 참조를 같은 FSM에서 예약한다. 앱은 이 reader나 grant를 소유하지 않고 자기 Binding의 별도 RegistryGrants를 사용한다. source put/delete/unbind 뒤 owner의 실제 Secret/HTTP I/O join·서명된 원 grant closure로만 반환한다. 빌드 begin이 고정한 source reader 세대는 원 job 실제 종결 전 반환하지 않으며, RPC 종료·취소·unknown만으로 Vault usage를 해제하지 않는다. 내장 FROM registry도 원 owner/generation/definition에 고정해 미종결 job 동안 Store를 보유한다. 원 Secret/삭제 흔적·종료 영수증은 보존하고 살아 있는 reader는 node activity·tenant 종료·원장 회수에 포함한다. [관리 reader 경계](../../reference/external-registries.md#source-읽기-중지와-사용-참조-반환)를 따른다.

빌드의 Bearer 교환은 원 reader가 실제 registry challenge·current source/job 권한을 확인한 뒤 수행하는 일시 I/O다. builder에는 frozen repository의 pull token만 보호 전달하고 원 Vault password/refresh token/CA를 보내지 않는다. token을 새 공유 관리 자원·관측·Raft 값으로 보존하지 않으며 token RPC 종료가 원 job/source 참조 반환을 뜻하지 않는다.

이미지 참조 확인은 새 관리 자원을 만들지 않는 tenant Read projection이다. 내장 이미지는 기존 registry owner의 열린 metadata Store를 빌리고 close와 같은 lock으로 합류한다. 외부 이미지는 source reader의 원 승인 read-set·세대 fence·I/O 수명을 재사용하며 호출 사용자에게 Secret 값이나 파생 registry credential을 반환하지 않는다. 조회가 app/Volume/native writer를 소유하거나 이미지 신뢰를 추가하지 않는다. [조회 경계](../../reference/image-resolution.md)를 따른다.

이미지 사용처는 공유 Task·앱 Inventory/held/retirement·CD의 retained plan·직전 앱 원문/overlay·실행 중 compiler job에서 유도한다. 별도 usage DB나 lease를 만들지 않는다. 사용자 페이지는 현재 tenant로 제한하고 미매핑 legacy 참조를 노출하지 않는다. 이미지 캐시의 실제 owner는 같은 공유 참조와 private Desired/Applied/Pending 레시피의 검증된 native image ID·Docker container 사용을 함께 검사한다. 원문 없는 과거 버전이나 진행 원 작업을 관측 부재로 반환하지 않는다. [참조 분류](../../reference/image-usages.md)를 따른다.

외부 이미지 받기 관측은 컨테이너 담당 노드가 실제 OCI 다운로드·Docker 적재 결과로 생성하고 기존 노드 관측 DB/Report 경로가 보관·전달한다. tenant × authority × 노드별 마지막 제한 코드와 원 완료 시각만 유지한다. 앱·사용자가 생성/갱신하는 관리 자원이 아니며 source 삭제·관측 재보고가 원 완료 시각을 바꾸지 않는다. 현재 tenant Read/ManageRegistry는 공개 결과만 읽으며 자격 원문·사용 grant를 소유하지 않는다. [형식과 한계](../../reference/external-registries.md#실제-이미지-받기-결과-조회)를 따른다.

내장 이미지 reference의 게시 시각은 registry owner가 manifest/태그를 수락할 때 같은 metadata DB 트랜잭션으로 기록한다. 사용자 임의 timestamp·image config Created로 대체하지 않으며, 기존 원문에 시각 fact가 없으면 읽기에서 채우지 않는다. 목록/graph 용량은 같은 retained Store의 투영이며 새 공유 관리 자원이나 Volume writer가 아니다. 외부 source 목록은 원 reader의 자격/CA·선택 범위를 사용하고 사용자에게 원문 자격을 반환하지 않는다. [이미지 목록 계약](../../reference/registry-images.md)을 따른다.

명시 이미지 정리의 native owner는 기존 registry Store의 manifest/ref/pub fact와 원 maintenance receipt를 같은 DB에서 관리하고 파일 unlink는 원 GC intent로 정산한다. tenant 관리자의 signed delete-registry-image/gc-registry가 원 run/target/grant를 공유 job으로 고정하며 같은 pending job이 새 push·이미지 소비·정의 교체/stop·drain과 원장 회수를 막는다. 원 작업은 owner node activity에 포함하고 tenant 전체 삭제도 미정산 maintenance가 있으면 시작하지 않는다. 원 worker는 실제 I/O/양성 결과 전에 pin을 반환하지 않는다. 태그 제거·digest/manifest 제거·물리 blob 회수는 별개 효과이며 registry/app 종료가 이를 자동 수행하지 않는다. [계약](../../reference/registry-maintenance.md)과 남은 검증을 따른다.

내장 registry push 자격의 repository/만료 범위와 원 maintenance fence는 그 registry의 기존 owner DB에 속한다. 원문 자격·Session을 기록하거나 별도 공유 관리 자원으로 복제하지 않는다. 현재 권한 검증 뒤 token 발급 전에 기록하며 native GC의 양성 원 결과와 함께 fence를 반환한다. 이 local 기록은 사용자/Raft job의 허가·정산을 대체하지 않는다.

일괄 정리의 native 항목 receipt는 같은 원 부모 operation 안에서 Item으로 구분한다. 별도 사용자 작업·앱 자원·Volume writer가 아니며 같은 부모의 일반 단건 결과와 다른 namespace에 둔다. digest 제거는 당시 별칭 집합의 지문까지 metadata transaction 직전에 검사하고 새 별칭으로 원 선택을 확대하지 않는다. 원자 receipt/retired blob과 GC의 원 증거·같은 DB 복구는 기존 소유권을 유지한다. 공개 일괄 action의 남은 연결은 마일스톤에서 관리한다.

외부 이미지 삭제는 원 사용자 maintenance job이 image target·source 정의/승인 ReadSet·owner를 소유하고, 자격/CA 값은 기존 source reader가 일시 공급한다. 단회 DELETE의 원 응답 유실은 unknown 이미지 fence/원 작업으로 보존하며 source/tenant 이름 변경으로 우회하지 않는다. source reader는 실제 Secret/HTTP I/O join 후 원 closure로 사용 참조를 반환하고 Closed에 증거를 보존할 수 있다. 이 반환은 원격 효과의 완료나 이미지 참조 반환이 아니며, 관측 부재·새 ID로 정산하지 않는다. [정확한 경계](../../reference/registry-maintenance.md#외부-registry-삭제)를 따른다.

일괄 이미지 정리의 큰 preview는 기존 node observations DB에 tenant/owner/원 target 지문으로 격리하며 원 maintenance 부모가 시작한 preview와 항목 결과를 소유한다. 미시작 만료 preview만 유한 cache에서 회수하고 원 native 불명·미정산 항목은 보존한다. 사용자/앱이 항목별 새 작업으로 교체하지 않으며 같은 부모의 선택 GC만 물리 blob을 회수한다. 공개 페이지는 원 preview/결과의 투영이고 새 권한·독립 동기화 저장소가 아니다. [소유·수명 계약](../../reference/registry-maintenance.md#일괄-정리)을 따른다.

이미지 본문 읽기의 원 registry Store/승인 외부 source reader가 실제 native/HTTP reader와 I/O hold를 소유한다. 호출 사용자에게 원 Vault 자격·새 registry grant를 넘기지 않으며 다른 manifest/repository blob을 임의로 읽지 않는다. 실제 Close 뒤 Store gate/reader hold를 반환한다. consumer의 cache commit은 전체 길이/지문과 최종 사용자 응답/EOF 성공 뒤이며, 일부 받은 바이트나 연결 EOF만으로 완료/사용 참조 반환을 주장하지 않는다. [경계](../../reference/image-content.md)를 따른다.

유한 빌드 SDK session은 원 native job이 input/context·output/image FD와 source/Secret/auth/status I/O를 보유한다. Create 전에 optional SDK 모드를 고정하고 기존 daemonless journal을 변경하지 않는다. Sent solve는 재제출하지 않으며 SDK 긍정 결과와 원 daemon Stop/Wait/Remove 뒤에만 OCI 출력을 소비한다. 원 image inode와 모든 session/log callback join 전에는 작업 공간/cache/root를 반환하지 않는다. 이 private Unix socket은 별도 관리 자원·외부 listener가 아니며 [빌드 수명](../../reference/image-build-jobs/07-section.md)을 따른다.

빌드 TLS 자료의 정의는 원 tenant registry source의 CA 참조 또는 내장 registry의 serving chain이다. 원 reader/provider 승인과 registry owner가 공개 인증서만 공급하고 builder는 원 frozen authority의 job-private read-only config를 소유한다. private key/password/Vault 원문과 host CA 저장소를 소유하지 않는다. native TLS/Trust optional 필드는 기존 journal을 변경하지 않으며 원 controls 전송 뒤 다른 trust로 대체하지 않는다. 같은 host의 서로 다른 root 집합은 union하지 않는다([형식·수명](../../reference/image-build-jobs/06-tls.md)).


빌드 cache 관측은 원 cache를 보유한 node의 observations DB가 소유한다. cache의
정체성은 tenant/context/등록 root/builder digest이며 job 재실행과 분리한다. 원 finite
SDK daemon이 사용량을 읽고 현재 사용자 Read/ManageRegistry·node 권한으로 조회한다.
관측 시각·항목별 사용 여부는 과거 관측이지 cache 삭제/원 root 반환 허가가 아니다.
원 native journal·배타 참조·실제 종료/I/O join을 조회 자료로 대체하지 않는다.
[캐시 관측 페이지](../../reference/image-build-jobs/10-section.md)를 따른다.


빌드 종료 자동 cache 정리는 원 job의 수락 정책과 현재 실행 허가로 원 finite daemon이
수행한다. 같은 등록 root/cache 배타 참조 아래 SDK가 live 참조를 확인하고 실제 prune한다.
원 node DB의 job별 native receipt와 cache 관측의 마지막 참조를 같은 트랜잭션으로 저장한다.
Sent/부분 응답/Unknown은 기존 job에 보존하며 조회나 재접속으로 새 정리를 만들지 않는다.
SDK solve 결과·정리 합계·실제 daemon 종료/원 참조 반환을 구분한다.

idle 주기 정리도 원 cache owner의 유한 maintenance 경계를 사용한다. 현재 accepted
빌드 정책의 원 사용자 승인을 현재 권한과 함께 검사해 cache별 자동 slot/단조 Sequence를
수락한다. 앱/CLI가 별도 worker를 소유하지 않는다. 원 source/cache identity와 이번 실행
정책·수락 시각을 분리하고 기존 공통 동시성/CPU/메모리 예약을 사용한다. 미종결 pass를
교체하지 않으며 실제 완료 뒤 현재 행만 교체한다. 로컬 반복 metadata 회수는 현재/진행 중/
미종결/앞선 applied 증거와 마지막 성공 관측의 원 생산자를 보존하고 수동 기록·물리 cache·
root lease는 회수하지 않는다. [메시지·수명](../../reference/image-build-jobs/16-idle-cache.md)을 따른다.

tenant owner의 종료 점검은 빌드/maintenance의 원 native 완료·열린 본문/SDK/log I/O와
job/cache root lease도 센다. 공유 job의 terminal/삭제만으로 로컬 종료를 증명하지 않는다.
빌드 모듈을 비활성화해도 기존 observations DB의 원 기록과 미반환 lease는 조회하며,
저장된 원 source·lease 유실/외래 owner·귀속 없는 활성 I/O는 빈 성공으로 처리하지 않는다.
Docker inventory에는 원 image-build·image-build-cache-prune label도 포함하고 다른 tenant는
종료 대상에 넣지 않는다. 보존 cache bytes 자체와 실제 미반환 참조를 구분한다.

물리 build cache 회수는 되돌릴 수 없는 tenant 종료의 원 승인 아래 공유 잔여0과 실제
native/Docker/I/O 종료를 확인한 owner만 수행한다. cache 행의 원 삭제 intent·root/cache
inode를 보존하고 confined unlink/fsync→관측 제거/Returning→정확한 원 RootManager Return→
Returned 순서로 정산한다. 실패/응답 유실로 새 lease·cache를 만들지 않는다. 일반 job/
context/policy 삭제·재등록은 이 경로를 사용하지 않으며 namespace 재사용을 유지한다.
원 signed job/maintenance 완료와 수동 기록은 보존하고 실제 tenant 종료 보고는 회수 뒤
다시 census한다. [소유·복구 계약](../../reference/image-build-jobs/17-tenant.md)을 따른다.

draft/Git/archive 입력의 root consumer는 같은 제품 코어의 scope/plan hash 함수로 식별한다.
native 원 anchor·Git plan·upload header와 실제 RootManager lease를 대조해 tenant별로
센다. 준비 scope만 저장된 archive의 선택적 pin과, 실제 allocation이 있어 필수인 stage/
archive pin을 구분하며 귀속 불명·필수 lease 유실은 빈 종료가 아니다. 실제 lease가 반환되지
않은 입력 자료는 build job 종결과 별개로 tenant 종료를 막는다.

draft 전체 디렉터리는 context 삭제 또는 더 높은 데이터 생성 수명의 확정 뒤에만 원
anchor로 회수한다. 일반 설정 변경은 같은 파일/편집 결과를 유지한다. 원 scope/lease의
삭제 intent→원 namespace unlink/fsync→Removed/Returning→descriptor Close/원 Return→
Returned 순서를 사용하며 반환 기록 미정산도 종료 대기로 센다. metadata·재생성된 현재
데이터·별도 Spool에 채택된 archive는 보존한다. [데이터 수명 회수](../../reference/image-build-contexts/09-draft.md)를 따른다.
아직 인계되지 않은 prepared archive나 rename 전 header가 있으면 전체 draft 삭제를
보류하고 원 archive 경로의 독립 정산을 먼저 수행한다.

Git stage는 sealed archive로 원 inode가 인계됐으면 stage 참조만 반환한다. 미완료 stage는
최신 context/policy 단조 변경/삭제가 원 게시를 막는 경우 원 intent·inode로 회수한다.
원 plan/metadata와 archive는 보존하고 반환 미정산도 census에 남긴다. 반환 뒤 재조회는
원 archive pin만 열며 stage를 다시 생성하지 않는다. [Git staging 정산](../../reference/image-build-contexts/14-git-archive.md#git-staging의-정산)을 따른다.

미게시 생성 archive는 공유 upload 부재와 최신 context/policy의 단조 게시 fence를 같은
quorum 상태에서 확인한 owner만 회수한다. 원 source metadata를 남기고 기존 inode
인계·Reclaim을 사용하며, native header에는 artifact 지문/좌표와 원 pin의 borrow 여부/
lease·Returning/Returned만 보관한다. 새 upload/작업·pin·seal을 만들지 않는다. 원 pin을
아직 빌리지 않았다면 source stage pin으로 정리하고 archive의 미정산 반환도 census에
포함한다. 현재/게시/참조된 자료·다른 tenant·교체 inode는 이 경로로 회수하지 않는다.
[미게시 archive 수명](../../reference/image-build-contexts/08-archive.md)을 따른다.

과거 편집의 `draft-result`는 현재 tenant ManageRegistry/operation ceiling과 원 Scope/
Edit 지문의 result-purpose proof로 native metadata만 읽는다. 설정 변경/삭제·원 pin
반환으로 결과를 초기화하지 않으며 새 편집/파일/lease·Scope/ID/CAS 변경을 하지 않는다.
완료 결과·미완료·폐기·기록 부재를 구분하고 과거 편집 승인을 새 조회 권한으로 대체하지
않는다. [원 결과 조회](../../reference/image-build-contexts/06-draft.md#과거-편집의-원-결과-조회)를 따른다.

완료 scope가 없는 미완료 freeze는 설정의 단조 revision 변경/삭제로 게시가 불가능해진 뒤
원 삭제 intent·inode·unlink/fsync·완료 표시로 정리할 수 있다. 원 ID와 edit 결과는 보존하며
실제 완료 전에는 입력 본문의 보호를 해제하지 않는다. 현재 freeze·준비/채택된 archive·
전체 과거 draft 수명과 혼합하지 않는다. [입력 수명](../../reference/image-build-contexts/07-freeze.md)을 따른다.


freeze/Git 보관의 과거 결과는 현재 creator/권한과 result-purpose proof로 원 native
metadata만 읽는다. 저장된 seal이 있을 때만 원 signing bytes의 owner 증거를 복원하며
내구 삭제가 확인된 경우 Reclaimed를 표시한다. 조회는 원 plan/commit/기한을 연장하거나
파일·pin·fetch·seal 저장·게시를 수행하지 않는다. 현재 가용성과 과거 완료를 구분한다.
[과거 보관 결과](../../reference/image-build-contexts/15-freeze-git.md)를 따른다.

cache inventory의 namespace 목록은 보존한 공유 job Spec의 tenant/context/root/builder
정체성에서 투영하며 원 node가 관측 요약을 소유한다. job/컨텍스트 기록 삭제는 cache
바이트 삭제가 아니다. 대표 job이 바뀌어도 같은 cache의 원 관측을 사용하고 현재 tenant/
node 권한으로만 읽는다. [목록/요약 경계](../../reference/image-build-jobs/12-section.md)를 따른다.


보존 cache 항목 조회는 cache-ID/node의 현재 tenant 권한과 보존 공유 Spec의 cache 정체성을
사용한다. 대표 job의 생성·기록 삭제 수명과 별개이며 관측을 만든 원 native job/SDK 증거는
계속 필요하다. 항목·요약이 같은 검사를 사용하고 원 증거 유실을 빈 cache로 복구하지 않는다.
[selector·cursor 계약](../../reference/image-build-jobs/13-cache-id.md)을 따른다.


수동 build cache 정리의 정의·수락은 tenant/node ManageRegistry 사용자, 실행은 원 cache의
설치 owner가 담당한다. 원 보존 job ID/Spec digest로 root/cache/builder를 고정하며 앱은
이 정리 작업을 소유하지 않는다. pending 요청은 root/node/tenant 종료와 builder 이미지
사용처에 포함하고 원 job 삭제 표시로 참조를 잃지 않는다. cache 내용 정리는 Docker
이미지 삭제나 registry GC와 구분한다. [현재 수락/대기 계약](../../reference/image-build-jobs/14-section.md)을 따른다.


수동 cache 정리의 begin은 일반 빌드와 같은 tenant 동시성·node/tenant CPU/메모리
예약을 사용한다. unknown/권한 회수로 반환하지 않고 설치 원 owner의 실제 native
종료 보고가 공유 FSM에 수락된 뒤 반환한다. [owner 보고](../../reference/image-build-jobs/14-section.md#수동-cache-정리의-owner-보고와-예산)는
기존 ImageBuildKey 안의 원 intent에 고정하며 별도 자원 DB나 가짜 build job을 만들지 않는다.


수동 cache 정리의 native admission은 원 사용자 intent와 보존 Source Spec을 별도로
고정한다. 새 build job을 만들지 않으며 원 node observations DB에서 cache 점유와
정리 journal의 root/cache inode를 같은 트랜잭션에 저장한다. 기존 cache의 active
RootManager lease만 빌리고 새 root/cache를 자동 생성하지 않는다. `Claimed`는 cache
점유이며 daemon Ready·SDK 삭제·종료 증거가 아니다. cleanup-only 수락은 후속 실행
권한으로 승격하지 않는다. 기존 build의 종료 재조회로 다른 정리의 점유를 반환하지 않는다.


수동 cache 정리의 원 maintenance 디렉터리와 유한 daemon은 같은 native record의
소유물이다. 보존 Source job의 입력/출력 디렉터리를 재사용하지 않고 output/socket과
원 cache만 mount한다. 빌드와 정리는 같은 Docker SDK 생성·일치·시작·종료 코어를
쓰지만 공유 job/사용자 승인은 구분한다. SDK reader/FD가 종료되기 전 Remove·cache
반환을 하지 않으며 known native의 실제 종료에 새 quorum을 요구하지 않는다.


수동 cache 정리의 종료는 원 Outcome·native 완료 서명으로 보존한다. output unlink/
부모 fsync 뒤 cache owner 반환과 Closed를 같은 node DB 변경으로 확정하고 cache
bytes/cache-root lease는 유지한다. 기존 scheduler는 최신 quorum/CAS에서 같은
원 intent의 완료를 보고한다. 로컬 공유 metadata 부재만으로 원 파일·점유·결과를
버리지 않고 known native 정지에 한정한다. 원 완료는 새 보고 envelope와 구분한다.


수동 정리의 SDK 관측은 원 maintenance journal과 node 관측 DB의 소유물이다. 원
intent/source/cache inode·마지막 성공 snapshot을 같은 DB 변경으로 기록하고 item/
summary는 해당 원 생산자를 검사한다. public ObservedKind/ObservedBy는 실행 출처를
알리는 지문이며 권한이나 새 관리 자원이 아니다. 실패한 재관측으로 기존 성공을
지우거나 독립 Prune 결과·실제 종료를 판정하지 않는다.


서버/컨텍스트 cache 일괄 계획은 사용자 CLI의 검토 입력이다. 공유 관리 자원은 각
기존 단일 cache 정리이며 같은 batch prefix의 독립 원 journal을 사용한다. 계획은
cache 소유권·사용자 권한을 부여하지 않고 app/CD 자원도 생성하지 않는다. 순차
수락의 일부 결과를 전체 atomic 성공이나 모든 cache의 실제 종료로 표시하지 않는다.


FROM의 복수 Bearer scope는 자격 소유권을 바꾸지 않는다. 같은 job의 원 signed begin에 예약된 repository들이 같은 owner·external reader 선택/세대·ReadSet을 사용하는 경우에만 한 토큰 교환으로 묶는다. 자격·CA·사용 참조는 원 reader에 남고, 각 원 입력의 현재 권한을 교환 전후 확인한다. 노드/host가 같다는 이유로 다른 reader의 자격을 합치거나 요청 거부·token 교환 종료만으로 원 job의 참조를 반환하지 않는다.

정책 기반 cache maintenance의 cache/root/builder 신원은 원 immutable Source JobSpec,
이번 CPU·메모리·시간과 기간/용량 기준은 별도 Automatic 정책, 각 Prune 결과는 같은
native journal의 RPC/PolicySize가 소유한다. 원 JobSpec을 바꿔 새 빌드처럼 만들지
않는다. native의 policy filter는 사용자 수동 명령으로 수락하지 않으며 공유 승인·
예약/주기 조율이 연결되어야 자동 작업을 시작할 수 있다. SDK 결과·관측·실제 daemon
종료/원 cache 점유 반환을 서로 대신하지 않는다.

신규 SDK FROM 본문의 정의/인증/TLS는 원 source owner, 원 signed begin의 참조는
기존 job, BuildKit에 공급하는 임시 본문은 그 job의 원 native 작업 공간이 소유한다.
OCI session store의 metadata/이름 없는 layer 파일은 solve 동안만 유지하며 독립
관리 자원·영속 build cache가 아니다. 전체 본문 검증 뒤 SDK에 노출하고 원 세션
취소/I/O join·FD Close 뒤 기존 작업 공간 수명으로 반환한다. source 자격이나 CA를
builder의 host별 자격으로 합치지 않으며 다른 source의 승인/캐시로 대체하지 않는다.


Ingress의 일시 block은 별도 cluster 관리 자원(`control/ingress-management`)이며 앱 목표/Task가 아니다. 시스템 또는 tenant Network 관리자가 명시 범위와 record CAS로 생성·해제·연장한다. 앱 종료·target 부재·만료로 원 ID/사용자 승인 기록을 자동 삭제하지 않는다. tenant host grant는 시스템 관리가 소유하며 앱은 이미 허가된 host/gateway만 참조한다. 최근 요청 계수/가린 오류/Applied·Runtime.BlockRevision 관측은 node-local 운영 자료이며 Raft 목표와 혼합하지 않는다. BlockRevision은 실제 설치 정책의 receipt이며 해제된 목표 ID의 부재를 적용 완료로 대체하지 않는다. [Ingress 운영](../../reference/ingress-management.md)을 따른다.

공유 node gateway의 주소·listener 설정은 시스템 관리자가 `set-node-gateways`로 소유한다. 앱은 이름으로 빌리며 파일 초기값과 클러스터 목표/실제 적용 revision을 구분한다. 활성 TCP/HTTP3 UDP listener는 direct Compose ports와 같은 node host namespace를 예약하고, 앱 종료로 shared listener를 반환하지 않는다. 원 gateway claim은 신원 교체·단절로 자동 해제하지 않고 정확한 CAS 교체만 허용한다.

앱 경로의 balance·drain/undrain overlay는 tenant Network 관리자가 별도 관리 명령으로 소유한다. 앱의 원 Goal/Task/container 세대나 원 Ingress native를 재생성하지 않으며 명시 overlay revision과 원 선언을 함께 보여 준다. 공개 변경 이력은 같은 관리 checkpoint의 원 사용자 operation에 귀속하고 현재 Read 범위의 공개 이전/다음 값만 조회한다. 진행 flow와 native pin은 실제 deadline 취소/반환으로 정산하며 이력 생성만으로 종료를 주장하지 않는다.

새 앱 계획의 Planned 상태가 기존 확정 Ingress source/claim·로컬 journal의 소유권을 대체하지 않는다. 원 source가 그대로인 동안 정확한 원 Native를 선택하고, 실제 변경은 새 stage/원 결과와 현재 native 허가를 확인한다. 다음 계획의 stage 부재를 원 listener 부재로 해석하거나 새 ID로 재생성하지 않는다.

클러스터 인증서 보관함(`control/certificates`)은 시스템 관리자 자원이다. 앱·shared gateway는 TLS 수신 주소에서 SNI 호스트로 빌리며 앱 종료로 항목을 삭제하지 않는다. 공개 chain/봉인 ciphertext와 signed receipt는 Raft, version key는 현재 holder의 identity로 봉인된 node DB가 소유한다. 보호 입력 intent·원 결과는 원 sealer에 보존하고 새 owner가 receipt를 합성하지 않는다. 삭제/만료의 확정 fence 이후에만 해당 payload/key를 정리한다. [인증서 보관함](../../reference/certificate-store.md)을 따른다.

