## compose·login CLI

상세 CLI 계약은 password/private-key/token login·whoami/logout·tenant 선택과 app check/diff/deploy/list/show/down과 op show/resume의 동작을 정의한다. 배포 명세 명칭은 app.yaml이다. [입력 명세](../../architecture/app-and-cluster-spec.md)의 앱 범위와 tenant 관리 명령은 parser/CLI·daemon에서 분리한다. 현재 compose 명령과 원 작업 재개는 보존하며 미지원 문법을 무시하지 않는다. login은 username + password/private-key/token의 등록된 방식 하나를 검증하고 user session을 저장한다. 원 password/token을 client YAML/argv에 저장하지 않는다.

현재 LoadClient는 auth:user에서 node identity_dir를 금지하고 로그인 전 node identity를 열지 않는다. 사용자 인증 성공과 앱 실행 수락/실제 효과는 구분한다. 앱은 같은 사용자·tenant/Binding·원 operation을 통해 실행된다.


`mydc op show ID`는 현재/과거 배포 operation 하나를 원 Inventory에서 조회한다. 현재 tenant Read 권한과 quorum이 필요하고 로컬 Compose intent는 필요 없다. 응답의 `original-result`는 원 결과 조회 성공이며 현재 Healthy를 뜻하지 않는다. 부재/회수는 `unknown`·코드4다. down 요청 ID 조회는 이 옵션의 대상이 아니며 원 down 재개/`wait --condition retired`를 사용한다.

종료·후속 배포 뒤 같은 ID의 `up/resume`은 원 scope/Plan/epoch와 accept command의 submitter를 검사해 `original-result`를 반환한다. 이미 끝난 앱의 Group 비밀번호/승인을 새로 요구하지 않는다. 원 accept intent는 있고 결과만 미확인이면 그 서명 명령의 결과를 조회/기록한다. 로컬 원 accept 자체가 없거나 원 결과를 확인할 수 없으면4/Unknown을 유지하며 새 서명/ID/CAS로 바꾸지 않는다. 원 결과 조회는 새 native 실행을 허가하지 않는다. 실제 적용 상태는 현재 owner 관측과 원 retirement 결과로 확인한다.

D5.04 완료 근거의 사용자 요청은 승인된 member가 원 proof와 대상/새 연결 증거를 보존해 leader로1회 전달한다. logout 기본 재실행은 원 결과만 조회한다. 미정산 intent의 명시 재제출은 logout --resume-original이며 원 actor/ID/CAS/서명을 유지하고 현재 같은 user의 scope를 추가 검사한다. 재로그인 뒤 원 logout을 정산해도 새 session은 유지한다. 다른 user의 Pending을 덮거나 인수하지 않는다. 동적 제어 bootstrap은 D5.14 완료 근거를 따르며 password/token/backend 로그인은 D5.05로 완료했다.


Managed 설치는 [설치 예시](../../../configs/node.managed.example.yaml)의 node.managed=true·user_catalog=true와 명시 init --admin-public-key KEY --request-id ID를 사용한다. 빈 run이나 다른 operation/신원으로 기존 root를 초기화하지 않는다. --client-config-out FILE은 pinned auth:user profile을 출력하고 최초 등록은 mydc enroll-admin --user-id ID --username USER --key-file PATH --request-id ID로만 수행한다. native 모듈 비활성의 초기 설치·Join/non-voter·원 ACK/DB·승격은 D5.14 완료 근거를 따른다.


