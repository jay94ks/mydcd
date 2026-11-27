# 관리 명령과 앱 선언의 경계

Seafield Cluster 입력은 **명시적으로 요청하는 관리·운영 작업**과 **지속해서 유지할 앱의 목표 상태**로 구분한다. [app.yaml·cluster.yaml 명세](app-and-cluster-spec.md)가 책임 경계의 기준이다. `app.yaml`은 특정 tenant의 이름 있는 앱 묶음이고, `cluster.yaml`은 관리 명령/UI가 실행할 tenant 설정의 부분 변경이다. full-cluster definition은 diff로 관리 변경을 순차 실행해 달성한다. CLI와 Unix socket은 접근 수단이다. `sfcli app deploy`는 앱 선언을 제출하는 명령이다.

## 입력별 책임

자원별 정의·관리 주체와 삭제/보존 경계는 [클러스터/앱 자원표](resource-ownership.md)를 기준으로 유지한다. 명령별 로컬/cluster/tenant/app·원 작업 대상은 [명령어 적용대상표](command-targets.md)를 따른다. 아래 표는 그 입력 경계를 요약한다.

| 영역 | 관리·운영 명령 / tenant 관리 명령 | app.yaml에 선언 |
|---|---|---|
| 클러스터·노드 | init/join·추가/삭제·격리/복귀·투표 구성은 시스템 관리 명령. tenant의 허용 node/한도는 권한 있는 관리 변경 | 이미 승인된 node의 이름으로 서비스 배치 참조 |
| 계정·tenant·신뢰 | 로그인/세션·user/tenant 생성·membership/역할·허용 node·quota·repository trust·교차 tenant 승인 | 대상 tenant 선택·기존 허가/객체 참조 |
| 서비스·Ingress | 적용/중지·원 결과 조회/재개·명시 sync/pause | 이미지 digest·실행 argv·자원·배치·의존/준비 조건·listener/backend |
| 망·DNS·route | 이름 있는 SFCP TUN 망·tenant network/CIDR·pool/owner·DNS/IPAM·양측 승인 route·runtime 변경. 파괴적 전환은 명시 승인/정산 | 이름 기반 관리 망 attachment·주소/서비스 이름 등록 요청. TUN 망 자체·DNS/IPAM 서버/route 설정을 만들지 않음 |
| Secret | Group/Secret metadata·정책 CRUD는 tenant 관리 변경. 원문/비밀번호 입력·검증·승인/회수는 보호된 명시 작업 | 기존 공급자/고정 revision·Secret/Group 참조·순서 병합·projection |
| Volume | backup/restore·이관·취소/복구·retained 데이터의 명시 삭제 | 생성/기존 객체 참조·용량·단일 writer·retain·backup/이관 허용 정책·목표 배치 |
| registry·CD | tenant registry·trust/자격·CD 관리 정책·수동 sync·pause/resume·source/override 승인 | 앱에 허가된 Git 출처·동기화/drift/prune 정책. tenant registry/trust를 생성하지 않음 |
| lifecycle·스크립트 | tenant named script/CAS·실행/resolver 정책·compiler 허용 node·build job/compiled cache 관리 | 앱/서비스 내장 검사와 inline/named script 매핑·phase/일정·optimizer/compile. lifecycle 계약에 따라 내장 검사는 직접 실행하고 사용자 검사는 Yaegi/선택 compiled CLI로 실행 |

app.yaml은 앱 운영에 필요한 **목표 구성과 참조/정책**을 한 곳에 담는다. tenant 설정 변경은 app 파일과 합치거나 자동 실행하지 않는다. 원문 Secret·비밀번호·개인키·설치 자격·실제 데이터·승인 서명·작업 ID/진행 증거는 보호 입력/저장 또는 엔진 journal에 둔다. Group의 보호 정책 변경은 비밀번호 설치/사용 승인 완료가 아니다. 서비스의 `command`는 컨테이너 시작 argv다. 관리 명령은 임의 원격 shell/host 명령 실행을 뜻하지 않는다.

클러스터 전역/공유 자원은 원 소유자와 관리 권한을 유지한다. 참조한 기존 Group/network/Volume을 앱 소유로 바꾸거나 임의 삭제하지 않는다. 새 앱 소유 객체는 같은 inventory의 생성·갱신·정산 규칙을 따른다. 선언으로 tenant·membership·trust·노드 가입 권한을 자가 부여하지 않는다.

## 적용·작업·소유권

`config/plan/diff`는 선언을 검사·비교하고, `up` 또는 승인된 CD sync가 정확한 artifact/plan·현재 권한/CAS를 원 operation에 묶어 제출한다. daemon의 기존 Inventory/Execution이 실제 모듈을 진행한다. 명시 작업은 현재 대상·revision/generation·원 요청 ID·정책/승인에 결합한다. 작업 요청을 JSON 파일로 전달해도 Compose 선언이 되지 않는다. CLI와 CD는 별도 배포 실행기를 갖지 않는다.

MySQL을 node-b에서 node-a로 옮길 때 목표 파일에는 새 배치와 Secret/망/Volume 정책을 작성한다. diff의 `MoveRequired`는 이관 필요성을 알리고 일반 up은 이를 우회하지 않는다. 운영자는 고정 목표 artifact와 현재 source owner를 결합한 **별도 이관 작업**을 명시적으로 승인·제출한다. 같은 daemon 코어가 준비→source 종료/fence→전송/검증→owner CAS/Arm→목표 앱 실행을 진행한다. 파일 재적용/Git polling만으로 backup/restore/이관·데이터 삭제를 반복 실행하지 않는다. 명시 `volume move`(`--dry-run --save-plan`, `--plan`)와 `op show/resume`은 [CLI 계약](../cli/volume.md#다른-서버로-옮기기)을 따르고 SQL/DNS·전체 이관 정산은 E4 직접 근거를 따른다.

앱 소유 설정은 파일 변경→같은 앱 실행 경로로 갱신한다. 명령으로 긴급 변경할 때는 CD override 계약의 현재 owner/base CAS·field claim·원 결과를 기록한다. CD 활성 여부와 관계없이 미등록 직접 덮어쓰기는 거부한다. override를 diff/status에 표시하고 해당 field의 CD 자동 복원을 막는다. 원 파일/Git은 보존하며 운영자가 파일에 반영하거나 명시 release한 뒤 재계획한다. Unknown·consumer/writer 정산은 override로 해제하지 않는다. override와 controller는 같은 원 앱 실행기와 retirement 경로를 사용한다.

## 접속 수단과 공통 실행 경계

현재 `sfcli`의 클러스터 접속은 인증된 SFCP다. 설정의 `unix:///var/run/docker.sock`은 daemon의 Docker Engine 어댑터다. **Seafield Cluster 로컬 관리 Unix socket의 기본 경로는 `/run/sfcdp.sock`이다.** CLI는 `unix:///run/sfcdp.sock`으로 접속하며 TLS와 User/SecretInput 인증을 수행한다. 원격 관리는 QUIC/UDP SFCP를 사용한다. 두 접속 수단의 사용자 메시지와 프레이밍 차이는 [Unix 소켓 API](../reference/unix-sockets.md)를 따른다. TCP SFCP listener는 제공하지 않는다.

CLI 선행 명세는 Linux user의 wallet/pubs·다중 cluster/tenant 프로필과 `--cluster/--tenant` 선택·Unix/remote endpoint를 정의한다. endpoint 생략은 로컬 Seafield Cluster Unix socket을 의미하되, 이미 선택한 프로필의 접속 대상을 덮어쓰지 않는다. 최초 키 신뢰와 원 user/session 인증은 별개이며 socket 접근 권한으로 관리 권한을 부여하지 않는다. cluster/tenant add는 로컬 등록이고 실제 자원 생성은 별도 명시 관리 명령이다.

로컬 관리 socket의 파일 접근 권한은 접속 허용만 결정한다. 현재 user/session·tenant·서명·CAS·quorum과 원 결과 규칙은 같은 관리 코어에서 검사한다. 로컬 UID/root·daemon 신원으로 cluster admin 권한을 자동 부여하지 않는다. 원격 노드 통신은 SFCP 경계를 유지한다.

두 입력 모두 수락·실제 적용·관측 성공을 구분한다. CLI/socket 단절 뒤 이미 수락한 작업은 daemon이 원 operation으로 이어간다. 송신 후 불명은 원 ID/서명/참조를 보존하고 결과 조회/명시 재개로 정산한다. 새 ID 발급·자동 재제출로 불명을 덮지 않는다.

## 원 앱 종료 명령의 명시 재개

`app show`의 `Retirement.Pending`은 다음 미종결 내부 명령 한 개의 실제 retirement ID·자원 Key·Phase·원 Request·Command 지문과 미소비 재전송 허가 여부를 제공한다. 명령 본문과 자격은 노출하지 않는다. 이 관측이 없거나 원 결과가 없다는 사실만으로 미실행을 판정하지 않는다.

`sfcli app resend`(action `resume-app-step`)는 같은 방식을 배포 단계에 쓴다. 현재 배포의 정확한 단계 명령이 RecoveryRequired이고 결과가 없을 때 한 번의 재전송을 허가하며, 서버는 허가된 단계만 같은 명령으로 다시 보낸다. 원장이 같은 RequestID를 한 번만 적용하므로 먼저 도착했던 명령은 결과만 거둔다.

관리 명령 `manage apply`의 `resume-app-retirement`는 Tenant/App/Retirement/Key/Phase/Command와 현재 Inventory revision(Expected)을 고정한다. 현재 로그인/tenant Deploy cleanup 권한·원 종료 권한·root CAS/quorum을 확인하고, 정확한 원 명령이 RecoveryRequired이며 원 ledger epoch가 보존되고 결과가 없을 때만 한 번의 재전송을 허가한다. 허가는 기존 Inventory에 남으며 원 pending ID/Command/Unknown을 초기화하지 않는다. 같은 관리 요청의 재개는 같은 결과를 반환하고 소진된 허가를 새로 만들지 않는다. 다음 시도에는 사용자의 새 명시 관리 요청이 필요하다.

담당 daemon은 원 결과를 먼저 조회한다. 늦은 결과가 있으면 수집하고, 없으면 허가를 원자 소비한 뒤 동일한 Raft 명령만 전송한다. 중복/늦은 제안은 기존 ledger가 같은 결과로 확정한다. 전송 실패는 다시 Unknown으로 남는다. 이것은 원 내부 제안의 재개이며 native 종료 증명·새 앱 배포·새 이관·기한 연장·권한 우회가 아니다. app.yaml·CD나 관리 명령에서 자동 실행하지 않는다.
