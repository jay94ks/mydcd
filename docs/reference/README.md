# API·입력 명세

- [이미지 빌드 정책·컨텍스트 metadata](image-build-contexts.md): tenant 정의·원 upload CAS/owner receipt·버전·현재 공개 조회와 연결 범위.
- [이미지 빌드 job](image-build-jobs.md): 고정 입력·원 operation·상태/취소/기록 삭제·owner 정산

| 문서 | 규정하는 경계 |
|---|---|
| [Unix 소켓 끝점·프로토콜](unix-sockets.md) | 로컬 관리 소켓의 주소·권한·TLS·record·전체 메시지 목록/필드·JSON 포맷·종료 |
| [최초 password·일회 token](initial-credentials.md) | 시스템 provider 보호 입력·owner fact·계정 CAS·일회 소비/반환·원 기록 복구 |
| [장수 client·본인 키 관리](client-authentication.md) | pin·다중 사용자·원 Session 재사용·자기 credential scope/소유 증명 |
| [사용자·구성원 조회](user-catalog.md) | 공개 계정 목록·tenant membership·현재 권한·revision 고정 페이지 |
| [Ingress 공유 게이트웨이·SNI·분배](ingress-gateways.md) | 외부/내부 shared listener·tenant host 권한·동적 인증서·분배 정책 |
| [Ingress 매핑·지표·차단](ingress-management.md) | 현재 권한별 owner 관측·60초 계수·가린 오류·Raft 차단/CAS·원 결과 |
| [클러스터 인증서 보관함](certificate-store.md) | 시스템 보호 PEM 입력·봉인 receipt·공개 버전·전용 member 키 공급 |
| [서비스·Git 진단](service-diagnostics.md) | 현재 logical service의 유한 POST/HTTPS·owner relay·read-only Git probe·한도와 불명 결과 |
| [Task 관측](task-observability.md) | 수락된 Task·서명된 Docker 관측·자원 참조·권한 필터와 페이지 |
| [노드·디스크·Mesh·Raft 관측](node-observations.md) | 권한별 노드 사용량·파일시스템 중복 제거·실제 QUIC/SDK 지표·단절 시 합의 진단 |
| [관측 이벤트](events.md) | Task/노드/CD의 내구 알림·종류/메시지·현재 권한·cursor/보존·수집 누락 |
| [app.yaml 원문·버전](app-source.md) | 원문 바이트·수락 버전·CD overlay·분할 조회와 이력 회수 |
| [단독 컨테이너](standalone.md) | tenant 소유 단일 서비스·temp/fixed 수명·원 attach/exec·pin·정산 |
| [클러스터 백업](cluster-backup.md) | `cluster-backup` 작업 기록·purpose20 스트림·백업 파일 형식 |
| [정족수 복구](quorum-recovery.md) | `sfcd recover`: voter 과반을 영구히 잃었을 때 남은 voter로 다시 세우기 |
| [가입한 서버의 주소 바꾸기](server-endpoint-move.md) | `sfcli node set-endpoint`·`sfcd set-listen`: IP나 포트가 바뀐 서버를 빼지 않고 옮기기 |
| [전체 복구](cluster-restore.md) | `sfcd restore`: voter를 모두 잃었을 때 새 서버에서 클러스터 백업으로 다시 세우기 |
| [변경 감시](change-watch.md) | purpose22 스트림: 세션이 읽을 수 있는 기록 중 바뀐 것의 참조(Raft index 기준, 이어 받기·resync) |
| [Volume 파일 작업](volume-files.md) | 상대 경로 위임·purpose18 유한 전송·원 publication/권한·소유 참조 |

| [Lifecycle 원본](lifecycle-sources.md) | 사용자 source/module 업로드·resolver/타입 진단·원 token 복구·정확한 버전 원문 읽기 |
| [컨테이너 운영](container-operations.md) | logs/top/stats·follow/watch·interactive exec/원 결과·로그 설정/정리·담당 노드/권한 |
| [노드 이미지 캐시](node-image-cache.md) | 명시 image ID 계획·현재 참조·원 job·Docker 비강제 삭제·불명 결과 |
| [끊긴 Mesh 링크 복구](tunnel-reconnect.md) | 원 노드 쌍·서명 down 관측·현재 grant·기존 Dial·원 결과 |
| [이미지 내용 전송](image-content.md) | 고정 manifest/config/layer·원 source/사용자 proof·bounded stream·지문/EOF·큰 blob 한도 |
| [Registry 이미지 목록](registry-images.md) | 내장/외부 repository·태그/digest·graph 용량·게시 시각·권한과 페이지 |
| [Registry 이미지 삭제·GC](registry-maintenance.md) | 내장/외부 원 서명 작업·digest CAS·진행/불명·push 대기·같은 DB 복구와 완료 경계 |
| [Registry 시작·정지](registry-actions.md) | 기존 typed action의 미리보기·원 요청/CAS·실제 정지/serving 관측 |
| [외부 registry 정의](external-registries.md) | tenant별 공개 자격 참조·CAS·조회·회수와 실제 인증 연결 범위 |
| [이미지 참조 확인](image-resolution.md) | digest/index·신뢰 규칙·내장/외부 source 조회 |
| [이미지 사용처](image-usages.md) | 수락된 Task·앱/직전 버전·CD·compiler 참조와 동일 root 페이지 |
| [Raft 수동 유지보수](raft-maintenance.md) | 시스템 관리자 수동 snapshot·로그 압축·원 job·노드별 결과와 복구 |
| [CD 후보 승인·반려](cd-candidate-decisions.md) | 원 후보/의도 CAS·이유·수동 모드 실행·반려 source 보존 |
| [CD 이력·설정값·변경점](cd-inspection.md) | 원 후보/실행 metadata·Git/현재 값·서비스 field diff·분할 조회 |
| [Task 재시작](task-actions.md) | 원 Task/native·사용자 승인·Stop/Start 내구 기록·원 결과 |
| [컨테이너 실제 설정](container-detail.md) | inspect·목표와 실제 drift·보호된 환경 참조·최근 서비스 검사 결과 |
| [Secret 파일·환경 변수 공급](secret-delivery.md) | 기존 승인/Binding·경로/이름·native 전달·새 세대·로그 가림 |
| [sfc-web HTTP API](web-api.md) | 웹 UI 데몬의 `/api/v1`: 로그인 세션·작업(원 operation 저장 후 전송)·화면 조회·보관된 앱 |
| [SFCP](../protocol/sfcp.md) | 공통 바이너리 frame/TLV, 목적별 메시지와 인증 |
| [명령어 적용대상표](../architecture/command-targets.md) | 명령·옵션·인증 주체·local/cluster/tenant/app 범위 |
| [CLI·설정](../configuration/cli.md) | 실행 파일의 옵션·설정 탐색·명령 문법·종료 코드 |
| [app.yaml과 tenant 설정](../architecture/app-and-cluster-spec.md) | 앱 묶음과 관리 자원의 명시 부분 변경 |
| [클러스터/앱 자원표](../architecture/resource-ownership.md) | 정의·변경·삭제 주체와 앱 참조·수명 |
| [서버 방화벽](node-firewall.md) | node.yaml `firewall`, `SFC-INPUT` 체인·잠금 규칙, `node-firewall` method·revision+delta·변경 기록, 클러스터 방화벽(`control/firewall`, 필수 규칙, `inherit`) |
| [VPS 서버 자동 가입](vps-enroll.md) | `.well-known/sfc/node` 경로, 사용자 스크립트 예시 |

관리 API는 SFCP 메시지로 처리한다. CLI의 하위 명령 이름과 wire의 `Purpose`/`Kind`는 서로 다른 분류다. 예를 들어 node 관리 명령도 사용자 관리 요청으로 전달하며, Unix 소켓에서 node 간 Raft 스트림을 열 수 있다는 뜻은 아니다.

- [관리 자원·사용처 조회](resource-queries.md): 실제 blocker/원 참조·한도/CAS·망 closure/DNS·위임·현재 권한과 페이지.
