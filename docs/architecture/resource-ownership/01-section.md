## 자원 분류표

native Exec의 연결·reader·bounded stdout과 원 call/exec 전송 receipt는 node owner가 소유한다. 현재 Task/A3·명시 exec capability를 확인하고 SDK Create/Attach 전에 원 기록을 저장한다. 끊긴 frame/timeout을 정상 결과로 바꾸지 않으며 !Running과 실제 nonnull ExitCode 또는 원 native Gone으로 종료를 정산한다. client I/O pin은 join 뒤 반환할 수 있지만 불명인 exec의 원 Active/receipt·공유 사용 참조는 보존한다. 별도 helper/group·모든 자식 종료 증명은 이 MVP의 필수 조건이 아니다.

원격 Probe의 상위 사용 참조는 원 coordinator Task/Binding·검사 run 소유이며 실제 native/A3·하위 실행/종료는 대상 owner 책임이다. checker-probe-permit는 현재 quorum 판정 metadata일 뿐 bearer 권한이나 종료 영수증이 아니다. 같은 tenant/app/deployment/user와 원 call/서비스/payload hash·대상 서명 관측을 대조한다. 허가/연결 timeout을 원 하위 호출의 미실행으로 바꾸거나 provider 참조 정산 전에 상위 사용 참조를 반환하지 않는다. raw 요청/응답은 공유 Raft 상태에 넣지 않는다.

read Probe의 원 Task/run/call A3 pin은 첫 native 조회 전에 node journal에 저장한다. 현재 native/원 record·pin 검사가 끝나기 전에는 접속/exec를 시작하지 않으며, 조회 실패나 취소로 생성된 pin을 없던 것으로 처리하지 않는다. 원 I/O 종료 뒤 같은 pin만 명시 반환한다.

로컬 생존 읽기의 원 run·Task/Binding·read pin은 기존 checker/Task owner 소유다. service scope의 같은 노드 healthz/connect/file만 원 quorum 승인 run 안에서 현재 로컬 정책을 매 호출 검증한다. run의 source 시작/결과 채택 quorum·native/StartedAt/세대 확인을 유지하며 마지막 quorum 실패 결과는 Unknown이다. 같은 fresh run view의 compiled metadata 검증은 이미 확인한 Binding 권한을 대체하거나 새 artifact 전송 grant를 만들지 않는다. 로컬 read 허가는 새 provider/activation·exec·원격 호출·컨테이너 제어·Volume writer 권한을 소유하지 않는다.

shutdown의 operation/revision·한 번의 시도는 같은 원 Task observation 소유다. 원 retirement 전용 검사 허가로만 실행하고 새 배포/Start·source/build 권한을 얻지 않는다. fail/unknown 뒤에도 명시 down은 기존 Stop/Remove를 수행하되 실제 exec/Gone·Volume fence·참조 반환은 별도로 정산한다. 앱 scope는 coordinator Task의 종료 시점에 수행하며 전역 종료 barrier를 소유하지 않는다.

같은 live 자원의 Noop 재사용은 원 Command/receipt·Binding source·Native 소유권을 새 operation으로 이전하지 않는다. Inventory는 동일 값/result/owner/node의 원 live·unretained claim을 보존하고 현재 Execution은 자신의 Noop 단계와 새 서명 health 관측을 갖는다. 삭제·retained 자원의 복귀는 각각 기존 재생성/명시 재활성 절차를 따르며 Noop로 채택하지 않는다. 현재 실행의 원 claim을 종료하는 동안에는 같은 Retirement의 정확한 원 Command/Result·Operation/Plan과 연결된 Closed target·Delete/Gone 또는 Retain 증거로 Removed/Retained 이력을 보존한다. 이 종료 기록은 새 Noop 재사용의 수락이 아니다.



표는 영역별로 나뉘어 있다.

- [자원 분류: 클러스터·노드·사용자](01-section/02-cluster-node-user.md)
- [자원 분류: 망·Secret·Volume](01-section/03-network-secret-volume.md)
- [자원 분류: 앱·lifecycle·registry·CD](01-section/04-app-registry-cd.md)


| 절 | 파일 |
|---|---|
| 설치 정책의 명시 활성화 metadata | [01-metadata.md](01-section/01-metadata.md) |
