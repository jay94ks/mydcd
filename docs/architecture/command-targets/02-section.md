## 로컬 설정·접속·계정

| 명령 계열 | 적용대상 | 입력/선택 | 효과와 경계 |
|---|---|---|---|
| help·version | 실행 중 CLI | 인자 | 접속/로그인·클러스터 변경 없음 |
| 기존 `identity create DIR` | 지정 로컬 설치/신원 디렉터리 | 명시 경로 | 기존 신원 생성 경계. wallet 등록·클러스터 가입·계정 생성과 다름 |
| U0 `wallet init/generate/import/list/public/passwd` | `~/.sfc/wallet.bin`의 named key | 보호된 passphrase/키 입력 | 암호화 로컬 저장. 원격 user/권한 생성 없음. 미정산 signer를 삭제/교체하지 않음 |
| U0 `wallet status/recover` | Linux user의 원 wallet 저장 intent/암호화 후보 | status는 공개 진행 metadata, recover는 원 ciphertext/digest | 원 저장만 정산. 새 passphrase/key/goal을 만들지 않음. abort는 미게시 상태에 한정하며 remote 권한/데이터를 변경하지 않음 |
| `context add/list/use/show/set/remove/trust` | Linux user의 `~/.sfc/config.yaml`·`trust/` | endpoint·context 이름·확인한 노드 키 | 로컬 접속 정보와 trust만 바꾼다. 원격 init/join·계정·tenant 생성 없음. [사용법](../../cli/context.md) |
| `tenant list/show/members/resources` | 계정이 접근 가능한 원격 tenant와 그 구성원·허용 노드·한도·망·route | 현재 user/session. members는 해당 tenant ManageMembers 또는 system-admin, `resources --all`은 system-admin | 읽기 전용. 페이지를 모두 이어 읽어 보여 줌. [sfcli tenant](../../cli/tenant.md) |
| `login/enroll-admin` | 선택한 cluster의 user·인증/세션 | username·password/개인키/token 중 허용 방식 | login은 확인한 계정·발급 session/proof key를 wallet에 저장하고 다른 계정과 공존. 독립 승인은 private-key의 등록 키 또는 password/token의 명시 --approval-key NAME을 사용하며 원 scope를 확대하지 않음. enroll-admin은 초기 관리자 등록 계약만 사용. tenant 기본값은 계정/권한 부여가 아님 |
| `user list/show` / User `users`·`user-credentials` | cluster의 공개 계정 목록·한 계정의 공개 record | 현재 system-admin + ManageCluster scope, tenant 선택 무시 | 읽기 전용, 비밀 원문·보호 verifier 참조 없음. [sfcli user](../../cli/user.md) |
| `user create`·`user key add/disable` | 대상 계정과 그 private-key credential | system-admin; 계정 revision CAS(`--if-revision`) | create는 새 계정 put-user, key add/disable은 add-credential·disable-credential 한 줄 변경. 마지막 인증수단/관리자 보호. 키를 바꾸면 계정의 모든 session 회수 |
| `manage node-cli-policy` / `manage apply`의 `set-node-cli-policy` | cluster 전역 access 보안 정책, tenant 선택 무시 | system-admin/ManageCluster; on/off 모두 독립 등록 사용자 승인과 정책 Revision/CAS. managed root만 | 기본 false. true이면 현재 요청에 승인+system-admin/해당 tenant-manager 필수, node key 승인 금지. raw node submit/get/plan 차단, 원 accepted 실행·owner 정산/복제 유지. app.yaml/tenant cluster.yaml field 아님 |
| `whoami/logout` | 원 cluster/account/session | 원 세션과 내구 logout intent | 조회/원격 세션 회수·로컬 정산. 응답 유실은 원 요청으로 확인하며 session/profile 초기화로 숨기지 않음 |

### 기존 root 정책의 시스템 명령

| 명령 | 주체·대상 | 효과·원 작업 |
|---|---|---|
| `catalog-policy show` | `auth: node`의 원 bootstrap admin, 선택 cluster의 static root | latest quorum·현재 admin 권한/epoch·고정 source/target manifest/policy·원 SDK 구성 index/applied floor/full-key·endpoint·voter 조회. 원 LogConfiguration/SDK Snapshot+durable FSM provenance이며 타 노드 설치 ACK/tenant 권한 아님 |
| `catalog-policy prepare --request ID` | 같은 원 admin·cluster | 고정 plan/epoch/ID의 signed canonical A1 Module command를 stdout으로만 출력. 자동 submit·새 계정/tenant/role 생성 없음 |
| `submit FILE` / `result FILE`의 activation artifact | 원 signer·cluster·exact 원 command | 기존 A1 quorum/CAS/ledger/Unknown 조회. 원 receipt와 정책 row/root binding을 같은 FSM sync에 확정. app.yaml/관리 명령/CD에서 실행하지 않음 |
| `catalog-policy plan-managed --genesis VOTER --request OPERATION` | auth:node 원 admin·선택 static cluster, 최신 quorum | 원 source/현재 native 구성·원 epoch/operation과 기존 voter genesis의 서명 계획만 출력. tenant/계정·shared 정책 변경 없음 |
| `sfcd --config STATIC adopt --plan FILE` | 원 daemon이 정지한 해당 node의 root·identity·signed plan | root lock·original FSM/Raft readonly 대조 후 local intent/fact sync. 동일 plan 재사용 또는 committed managed marker에서 local Managed fact 복구. source fact와 managed local fact 구분, init/join·새 key/DB 생성 없음 |
| `catalog-policy prepare-managed --plan FILE --source FILE` | auth:node 원 admin·원 cluster·원 static source voter fact | 원 actor/epoch/operation의 canonical A1 command만 출력. 자동 submit/새 ID 없음 |
| adoption 이후 원 node-admin `result FILE` | 현재 nonmember 원 signer의 exact retained command | 같은 original receipt/Expired 조회만 허용. 일반 get·새 submit/tenant 관리 권한을 상속하지 않음 |

