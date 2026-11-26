## 이름 참조와 수명

논리 network generation은 공유 Authority/reference의 신원이고 native Bridge goal/journal generation은 실제 lease/Task/DNS binding의 신원이다. 서로 다른 카운터를 같은 값으로 맞추지 않는다. 관리 source와 현재 정책이 두 신원을 연결하며 앱이나 시험 입력이 이전 native 세대나 다른 논리 세대의 참조를 채택할 수 없다.

관리 source의 종료 관측은 해당 native owner가 기존 Book/참조 정산과 Bridge/TUN Gone을 확인한 뒤 `NetworkClosure`로 서명한다. 기존 observe의 Retirement이며 새 정책/카탈로그나 새 자원이 아니다. 원 앱의 반복 관측도 모든 원 pin/spec을 Inspect할 뿐 새 사용 권한을 만들지 않는다. 각 member의 local native 종료와 전체 논리 망의 공유 확정·재사용 권한을 구분한다.

fence는 이 원 증거와 주소/참조 정산 뒤 해당 member의 source만 tombstone으로 철회한다. 원 논리 network/변경·서명은 유지하고 Closed projection은 활성 사용 권한을 주지 않는다. 전체 member의 명시 commit은 원 Authority의 archive/주소 floor·DNS serial을 보존하고 target/새 source를 같은 transaction에서 게시한다. 같은 key 재생성의 실제 FSM generation을 native journal에 연결하며 세대 floor를 초기화하지 않는다. member 추가/삭제는 이 교체 batch에 암묵적으로 섞지 않는다.

노드 구성을 바꾸는 reconfigure-tun-network는 원 member 전체의 종료와 별도의 명시 전체 목표를 소비한다. 원 변경/target·native key/generation/spec은 같은 archive에 보관하고 제거된 source는 Closed로만 투영한다. 현재 source를 역사로 대체하거나 폐기로 앱/Volume 데이터를 삭제/이관하지 않는다. target member 목록은 반드시 명시하며 빈 목록의 전체 망 폐기에는 DNS disable과 원 참조 정산을 요구한다. 새 native는 원자 관리 게시 후 적용한다.

DNS Current의 로컬 파생 정책 cache는 node Runtime의 임시 최적화다. 질의마다 읽은 동일 committed view/owner·tenant/id의 성공한 정책만 bounded하게 재사용하며 관리 source·권한·native Ready/query/TTL 수명이나 소유권을 대체하지 않는다. 새 view/읽기 실패를 지난 정책으로 우회하지 않고 앱이 cache를 선언·소유·삭제하는 자원으로 노출하지 않는다.

앱 종료 operation은 원 사용자와 tenant/app에 귀속되며 수락 Origin의 digest를 Target으로 고정한다. 관측 갱신은 종료 대상을 변경하지 않지만 새 Origin이나 이미 수락된 다른 종료를 차용할 수 없다. 원 expected/root·서명·ID와 현재 cleanup 권한을 유지하고 기존 Inventory retirement가 실제 native 종료/빌린 자원 참조 반환을 정산한다. 이 종료 CAS는 앱 수락·이관이나 관리 자원의 CAS를 대체하지 않는다.

예를 들어 `php-mysql-network`라는 MYDCP TUN 망은 클러스터의 tenant 관리 자원으로 먼저 정의한다. 관리 영역이 참여 노드와 각 CIDR/pool, TUN/Bridge 및 연결 경로를 담당한다. app.yaml은 다음처럼 이름을 참조한다.

```yaml
networks:
  app:
    external: true
    name: php-mysql-network
```

`app`은 앱 안의 별칭이며 `php-mysql-network`가 현재 tenant의 관리 망 이름이다. 서비스는 이 별칭에 연결하고, 계획은 서비스 배치 노드에 맞는 현재 owner/pool과 원 source revision/generation을 고정한다. 없는 이름을 암묵 생성하거나 다른 tenant의 동명 망으로 대체하지 않는다. 위 조각은 참조 형식이며 망 provisioning이나 다중 노드 native 연결의 완료 증거가 아니다.

앱 down/prune는 앱 컨테이너·listener·서비스 등록과 빌린 자원의 사용 참조를 정산한다. 마지막 앱이 종료되어도 관리 망 자체를 자동 삭제하지 않는다. 관리 망 삭제는 별도 요청으로 Drain한 뒤 원 주소 예약/query/flow·사용 참조·native 종료를 확인한다. Group/공유 Volume도 같은 소유권 원칙을 적용하며 앱 전용 Volume의 실제 데이터는 retain/명시 삭제 규칙을 따른다.

lifecycle의 내장/스크립트 실행·tenant compiler/cache·원 참조 경계는 D6 명세를 따른다. 선언 parser의 shape/scope/DAG 검사와 실제 수락·소비 경계를 구분한다. lifecycle 배포는 실제 inline staging/준비와 runner capability 연결 전까지 명시 거부하며 원 내부 source 사실을 앱에서 주입할 수 없다.

compiler의 sealed manifest·로컬 scratch·산출물 report는 원 내구 build job의 하위 자료다. 컨테이너 entrypoint가 새 job/tenant 정책을 생성하거나 cache 공유 pin을 자체 수락하지 않는다. 부모 job owner가 현재 정책·실제 Docker 자원/종료·artifact read-back과 원 pin 정산을 책임진다. 스크립트 Probe FD도 해당 run의 로컬 위임이며 복사한 Request/결과만으로 다른 Task/native 자원 권한을 얻지 않는다.

원격 native Probe의 하위 실행은 대상 node가 기존 observations DB의 `checker/remote/`에서 소유한다. coordinator의 원 Task/run/call·consumer 키와 대상 provider/native에 고정하며 원문 argv/응답을 공유 상태에 넣지 않는다. 한 call의 I/O 종료는 그 대상의 정확한 reader만 반환하고 다른 call의 pin을 반환하지 않는다. 수신 기록·exec closure와 송신 원 Active/Binding 정산은 별개이며 단절 뒤 새 call로 대체하지 않는다. 기록 없는 복구도 no-effect tombstone을 저장하여 늦은 실행과 순서를 정한다. target owner는 기존 workload SDK·실제 종료/Gone으로 원 exec를 정산하며 스크립트가 Task/Volume/컨테이너 제어 권한을 소유하지 않는다.

송신 node는 원 checker observation의 RemoteCalls에 provider/Binding·현재 policy·원 call/header/hash·sent/closed를 저장한다. 원 Run/Request는 같은 Active/Last를 참조하며 raw typed payload/출력을 복제하지 않는다. local exec/remote callback이 같은 checkpoint lock으로 저장하고, 미정산 원격 호출이 있으면 Finish·binding 교체·원 shared usage 반환을 금지한다. 클라이언트 I/O가 끝났다는 이유로 provider exec를 종료 처리하지 않는다. 명시 down과 local reader 반환은 진행할 수 있으며 provider의 원 closure를 확인한 뒤 같은 Active를 unknown으로 정산한다. 원격 native exec의 receipt는 provider namespace가, 송신 receipt와 상위 앱/script 사용 참조는 원 coordinator가 소유한다.

앱/script 사용 참조 반환의 서명 주체는 원 Task owner다. 실제 native Gone 뒤 같은 Task의 checker 실행/Probe 정산·Machine retirement를 저장해야 하며 prepared/dispatched·미정산 제어가 남은 상태에서 공유 pin을 반환하지 않는다. 미정산 제어는 Gone 확인 뒤 canceled로 보존하고 원 run/결과·재시작 receipt·세대/sequence floor를 삭제하지 않는다. named 등록 tombstone과 source/compiled cache bytes의 실제 회수는 별개다. native exec의 원 call/Target·payload hash·exec ID/전송 상태는 같은 node checker observation 소유다. read pin 반환은 클라이언트 I/O 종료만 뜻하며 미정산 exec를 삭제하지 않는다. 원 Active를 유지한 채 기존 down이 native를 제거할 수 있어야 하고 공유 사용 참조 반환은 exec 정산 뒤의 closure만 소비한다.

build job과 source/policy pin은 같은 lifecycle checkpoint의 원 app use/compile=true Task에 귀속한다. live build가 있으면 앱 use도 반환하지 않는다. 원 builder의 서명된 journal/미생성 확정 또는 실제 종료·제거 증거로만 job을 closed로 바꾸며 정책 철회/timeout은 반환 근거가 아니다. 공유 catalog의 원 job ID/closure 이력과 node의 실제 journal/workspace/cache 소유권은 구분하고, closed 기록으로 새 compiler를 자동 생성하지 않는다.

node compiler owner는 기존 observations DB와 mydcd의 전용 state root를 사용한다. input/output은 원 job, Go cache는 tenant/image/toolchain/target별 보존 자원이다. Create/Start의 내구 전송 표식·원 native ID와 output/cache 정산을 보존하고, 취소 시 원 native 정리를 새 Start 승인·현재 source 파일/SDK 검사와 분리한다. quorum 부재라도 원 컨테이너의 종료/제거는 가능하며 shared pin은 확정 전 반환하지 않는다. collector의 확인 없이 산출물 참조를 삭제하거나 다른 tenant의 cache를 채택하지 않는다.

compiled build provenance는 원 builder, local cache 사실은 실제 저장 node, job collection/진단은 원 node job owner의 책임이다. 수신 node는 builder 서명을 보존하며 앱은 이름/source/recipe의 사용 참조만 갖는다. binary/서명/진단은 node observations DB에 저장하고 shared Raft에는 원 job/선택/closure만 둔다. cached fact·부분 성공/종료 receipt는 실행 grant나 앱 Ready가 아니다. cache pruning·원 build 이력 회수는 실제 소비 pin과 원 참조의 정산을 먼저 확인해야 한다.

Volume 이관 취소는 원 operation의 양쪽 정산 증거를 관리한다. source retirement/reader/fence 전의 미변경 취소는 실제 native/gate와 공유 이력을 대조한 source 서명·실제 target Gone/전송 정산 뒤 원 writer/consumer·owner revision을 보존한다. 이미 종료/fence를 시작한 취소는 기존 원 참조를 정산하고 새 owner revision/Task 세대로 명시 재개한다. 미변경 취소를 위해 앱을 종료하거나, 취소 완료로 기존 Volume 데이터를 삭제하지 않는다. 새 Target 생성·복원과 취소는 같은 소유 worker를 join하며 Unknown/미반환 pin/legacy reader 이력을 보존한다.

연속 이관은 같은 FSM의 직전 확정 native와 다음 Source의 spec/물리 generation/owner를 대조하고 마지막 확정 값만 현재 등록 native와 비교한다. 과거 source/target 서명·ID·보존 물리 용량은 유지한다. 역이관도 새 materialization/추가 용량을 요구하며 옛 보존본을 재활성하지 않는다. 미정산 앱 이관의 Inventory는 다른 upload의 일반 begin-app이 교체하지 못한다.

이관 보존본은 완료된 move의 source와 원 삭제 의도를 지정한 별도 `delete-retained-volume`/CLI 작업으로 정산한다. 같은 Volume FSM의 SourceDeletion과 원 native A2·signed NativeRemoved를 사용한다. 원 source의 spec/key/물리 generation·삭제 revision이 맞는 실제 Remove/Gone 뒤에만 해당 Retained/Original 예약을 반환한다. 현재 owner/consumer·다른 보존본·과거 job/서명/digest·Used native 이력과 fence는 유지한다. pending/Unknown·없는 journal/단절은 완료가 아니며 앱 down/CD가 자동 삭제하지 않는다. 현재 Volume 삭제는 모든 보존본의 정산과 기존 앱 종료/참조 반환 조건을 별도로 따른다.

대상 활성 사실은 원 목표의 사용 형태를 따른다. writable/readonly mount는 원 Task/Binding/consumer와 실제 Running으로 확인한다. 다중 readonly 선언은 모든 공유 참조를 대조하고 정해진 원 consumer로 보고한다. 원 목표에 mount가 없는 Volume만 별도 Idle 사실을 허용하며 공유 consumer0·원 native/activation/Start 및 pin 정산·실제 Engine 연결 container0을 모두 확인한다. Idle을 위해 가짜 Task/consumer를 만들지 않으며 target native·보존 source의 소유권/물리 예약·fence는 동일하게 유지한다.

