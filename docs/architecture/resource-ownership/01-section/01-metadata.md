### 설치 정책의 명시 활성화 metadata

원 node의 `installation.db` adoption intent/certificate는 설치 소유 데이터다. 원 관리자의 signed plan과 실제 original FSM/Raft 구성을 확인한 동일 node만 생성하며 app.yaml·tenant cluster.yaml·CD가 생성/삭제/이관하지 않는다. 원 key/DB/작업·서명을 보존하고 같은 준비의 재실행은 원 사실을 sync/재사용한다. 원 directory의 adoption provenance도 불변 이력이며 새 가입·승격 A2나 tenant 권한을 자동 생성하지 않는다.

static root의 원 구성 provenance는 소유자가 바꾸는 새 관리 자원이 아니다. 기존 SDK LogConfiguration/Snapshot metadata와 durable FSM을 readonly 대조하며 별도 index DB·가짜 node ACK·Init/Join 작업을 만들거나 source checkpoint/바인딩을 고치지 않는다. 조회가 다른 노드의 managed 설치를 대신하지 않는다.

| 자원 | 생성·변경 주체 | 앱 참조·삭제 | 수명 |
|---|---|---|---|
| `control/catalog-policy`의 signed static-root catalog activation | 원 bootstrap node-admin의 exact source/target manifest·policy·epoch·request ID, 기존 A1 Module command | app.yaml/tenant cluster.yaml/CD의 입력·참조·삭제 대상이 아님 | 같은 원 Raft/FSM/DB에서 불변 보존. target binding/checkpoint 원자 sync, source prefix의 기존 receipt·native source/key/journal/pin 보존. user/tenant/managed directory는 별도 등록·이행 |

전환의 source/canonical/managed mode는 같은 shared state의 불변 marker와 root binding으로 선택한다. source native 구성 index 관측은 source checkpoint/Snapshot에 추가하지 않고, managed 확정 시 원 receipt·state·target binding/config-index를 원자 sync한다. 원 source pending/Unknown·native key/journal/pin은 정산 대상으로 보존하며 전환 정지를 미실행·native Gone으로 판정하지 않는다. committed target에서 복구한 Managed local certificate는 새 source import 권한이 아니다.

