## User 목적의 실제 개인키 로그인·조회

User=8은 schema1 kind1(request)/kind2(reply)/kind3(member relay), 필수 TLV1=정규 JSON envelope, TLV2=envelope SHA256으로 최대128KiB다. Gate의 UserAuth 권한만으로 Management/Raft/Snapshot/Observation/Packet/PathControl을 허용하지 않는다. 응답에는 현재 peer Respond 권한과 원 request ID/digest 결합을 검사한다. 서버가 node identity와 구분한 임시 TLS key의 proof를 확인했다는 사실은 등록 user 인증 성공이 아니다.

User kind4는 인증한 `app-plan-stream` 안의 입력 조각이다. TLV1=LE64 offset·TLV2=최대24KiB data·TLV3=원 signed envelope SHA256이며 body 상한은24KiB+64B다. 현재 UserAuth 또는 Member transport 권한이 필요하며 별도 첫 요청/다른 목적/early data/datagram으로 사용할 수 없다. 가입용 Replicate나 Respond/Manage만으로는 허용하지 않는다. 이 transport 권한은 catalog의 사용자/tenant 권한을 대신하지 않는다.

Request는 Schema/Method/Nonce와 method별 Username/UserKey/Tenant/Ticket/Proof/Operation이다. Envelope는 Body와 선택 Session/Signature/Relay이며 모든 JSON은 미지/중복 필드·비정규 표현을 거부한다. challenge는 현재 username/등록 개인키를 찾아 원 연결 challenge·user/account revision·credential·임시 SessionKey·300초 deadline의 node 서명 ticket을 발급한다. login은 같은 연결에서 access.KeyProof를 검증하고 ticket에 고정된 session ID/발급 시각으로 서명한다. 원 사용자 개인키는 전송하지 않는다.

whoami/tenants/select-tenant는 session proof key로 기존 access.RequestBytes(session, server challenge, canonical Body)를 서명한다. 현재 활성 control voter issuer/credential/account revision·quorum view의 권한·회수와 연결별 proof를 검사한다. 임시 key의 handshake admission을 node membership이나 user 변경 권한으로 승격하지 않는다. password/token 로그인은 [보호 자격 계약](13-user/04-password-token.md)을 따른다.


managed issuer는 설치된 활성 control voter로 제한한다. 세션을 발급하지 못하는 member(non-voter, 예: `inbound_only` 공개 gateway)는 개인 키 login(`challenge`, `login`)만 leader에게 kind 3 relay로 넘긴다. relay는 호출자 키와 그 연결의 challenge를 그대로 실으므로 ticket·proof는 처음 연결에 묶이고, 응답의 `SessionIssuer`에 넘긴 leader의 member 항목(ID, key, endpoint)을 적는다. leader를 아직 모르거나 leader가 아직 session issuer로 보이지 않으면(가입 직후, 선거 중) `not-leader`라 client가 challenge를 다시 시도하고, 격리된 자기 자신이 leader면 `not-session-issuer`이고, password/token(`credential-*`)은 relay하지 않고 늘 `not-session-issuer`다. 활성 follower의 login은 자격을 relay하지 않는다. 현재 leader의 인증된 Management `status, Latest=true` barrier를 얻고, 그 management-command ordinal와 Raft FSM 위치 이상으로 자기 복제본이 반영될 때까지 기다려 직접 인증한다. password/token backend 작업 뒤에도 같은 최신 확인을 수행한다.

Session에는 선택 `Approval:{Schema:1,PublicKey:key32,Session:key32,Signature:bytes}`를 담는다. 정확한 [승인 digest·서명 형식](../../../reference/unix-sockets/11-section.md#로그인-증거)을 사용하며 issuer 서명과 독립적이다. private-key login의 키 또는 password/token 뒤 명시 wallet 키가 승인한다. 기존 credential/scopes·proof key·계정 revision·기한을 바꾸지 않고 새 UserOperation 서명은 Approval을 포함한 원 Session을 고정한다. 이미 커밋한 grant의 현재 계정/credential 재검사와 현재 issuer의 새 요청 허용은 별도다. 클러스터 공통 `disable_node_cli_operation`의 기본값은 false다. managed root의 system-admin은 `set-node-cli-policy` UserOperation으로 정책 Revision/CAS·독립 승인을 갖춰 on/off한다. true이면 현재 User/SecretInput 요청은 독립 승인과 system-admin/대상 tenant-manager 권한을 요구한다. 등록 node key는 승인 키로 사용할 수 없다. node Management raw submit/get/plan은 차단하며 내부 status·복제·원 owner 보고/permit/정산은 보존한다. 원 accepted grant의 후속 실행은 정책 활성화로 재서명/초기화하지 않는다.

User kind1의 system-admin 전용 typed method `user-credentials`는 `Params:{Username}`을 받아 `Data`로 전체 공개 User/Revision을 반환하고, `node-cli-policy`는 `Params:{}`에 `Data` `{Revision,disable_node_cli_operation}`를 반환한다. 다른 Request 필드는 허용하지 않는다. `manage user add-key/disable-key`는 이 공개 record와 현재 account CAS로 기존 put-user를 재사용한다. 원 request ID의 result/resume은 기존 full intent를 보존한다. 정확한 [메시지 형식](../../../reference/unix-sockets.md)을 따른다.

