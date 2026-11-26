# 장수 client·세션 재사용·본인 키 관리

웹과 다른 장수 client는 `mydc`의 wallet이나 CLI 프로세스를 상시 실행할 필요가 없다. [User API](unix-sockets.md)의 기존 인증·현재 tenant 권한·signed scope·CAS를 사용한다. 서버가 client의 Linux UID나 웹 신원을 사용자 관리 권한으로 바꾸지 않는다.

## 최초 신뢰와 로그인 대상

설치자가 별도 채널로 받은 cluster ID와 대상 node Ed25519 공개키를 pin한다. Unix도 동일하다. endpoint에서 discovery로 받은 값 자체를 신뢰 근거로 쓰지 않는다.

1. `mydcp.Discover(ctx,"unix","/var/run/mydc.sock")` 또는 `Discover(ctx,"mydcp","host:port")`로 nonce/TLS에 결합된 공개 응답을 읽는다. node discovery가 켜져 있어야 한다.
2. 반환 Cluster·Key·Node를 설치자의 기대 pin과 대조하고 저장한다. 여기서 성공해도 user·node 권한은 아직 없다. pin 불일치/교체는 명시 관리자 재승인 없이 덮어쓰지 않는다.
3. client는 독립 proof/TLS key를 생성하고 `mydcp.Peer{ID,Endpoint,Policy{Key,Respond:true}}`와 `Client{Self,Mesh,Cluster,Peers}`를 구성한다. 설치 노드 private key를 가져오지 않는다.
4. password/token은 보호 login 교환에만 전달하고 메모리에서 지운다. private-key 방식은 계정 키가 서명한 proof만 보낸다. 메모리에 보관하는 proof key와 발급 Session은 로그인한 원 계정에 매핑한다.

managed cluster에서 Session issuer는 현재 활성 control voter다. non-voter/격리 노드의 로컬 Unix login은 `not-session-issuer`다. password/token을 그 노드가 voter로 중계하지 않는다. non-voter에 있는 client 컨테이너는 **설치 시 pin한 활성 voter의 MYDCP endpoint에 직접 접속**해서 로그인한다. 컨테이너에 그 voter로 가는 UDP/QUIC 경로가 있어야 한다. 로컬 Unix만 쓸 설치는 voter 노드에 배치한다. 발견된 임의 voter나 임의 redirect로 자격을 보내지 않는다. 발급된 Session은 issuer pin을 유지한 채 현재 허용된 로컬 관리 endpoint에서도 원 권한으로 요청할 수 있다.

## 여러 계정과 새 연결

한 client TLS/proof identity에 여러 계정의 Session이 공존할 수 있고, 같은 identity로 여러 연결을 열 수도 있다. 매 요청에 해당 계정의 Session과 그 요청의 서명을 명시한다. 서버는 최근 로그인한 계정·연결의 마지막 계정으로 대체하지 않는다. client의 연결 cache가 같은 서버로 향하는 Unix RPC를 직렬화하는 것과 사용자 Session의 공존은 별개다.

Session은 socket이나 최초 challenge를 저장하지 않는다. `Session.Key`는 proof key다. 연결이 바뀌어도 같은 proof key로 **새 연결 challenge에 대한 기존 `access.RequestBytes(Session,challenge,Body)`**를 서명하면 원 Session을 그대로 사용한다. 이것이 재결합 절차이며 별도 session-rebind method·갱신 grant는 필요 없다. 사용자 계정 키가 화면을 떠난 브라우저에 있어도 메모리에 보관한 proof key로 이 요청 서명은 가능하다.

만료·logout/revoke-session·계정 revision/credential 회수·현재 issuer·tenant/signed scope는 매 요청 다시 검사한다. 새 연결이 원 ID·계정·scope·ExpiresAt을 바꾸거나 늘리지 않는다. 계정 키 변경 후 옛 Session으로 원 변경 결과를 확인할 때는 새 정상 login과 기존 원 operation의 result를 사용한다. 불명 작업을 자동 재서명·재제출하지 않는다.

## 서버 한도

| 경계 | 한도·처리 |
|---|---|
| Unix 연결 | Transport별 실제 client/server 연결 최대64. 초과는 admission/budget 실패. 연결 하나에서 교환은 순차 |
| Unix 유휴/RPC | 마지막 교환 기준30초 cache 재사용·header/RPC 예산. 유휴 회수 후 같은 proof key·원 Session으로 새 연결 가능 |
| QUIC | handshake5초, idle30초, keepalive5초, 연결당 동시 incoming stream64. 전체 연결 수는 이 설정에서 별도 사용자별 hard cap을 두지 않음 |
| handler | Transport 전체 worker64, User16, ContainerSession8. 이 수는 사용자별 할당이 아니라 공유 동시 실행 상한이며 초과는 budget/admission 실패 |
| purpose15 | admission5초, 인증 후 read-idle60초/write5초, ping10초, 원 Session 만료, 현재 권한/실행 신원2초 재확인. 자세한 종료·초과 의미는 [컨테이너 API](container-operations.md) |
| password/token verifier | 비싼 검증 동시1, global20회/초 burst20, username당12초에1회 burst5, source당2초에1회 burst10, 사용자/source map 각각1024·5분 유휴 회수 |

Unix source는 `unix-uid:<UID>`이고 QUIC source는 관측한 원격 IP다. username 예산은 같은 사용자의 credential/method를 바꿔도 공유한다. 여러 사용자는 각자 username 예산을 갖지만 UID/IP source·global·동시 검증 상한은 공유한다. 어느 예산/동시 실행에서 거부된 시도도 다른 bucket의 토큰을 소모하지 않는다. 한 사용자의 잘못된 password 다섯 번과 추가 거부가 같은 UID의 다른 세 사용자 예산을 고갈시키지 않는다. 여러 사용자로 source/global을 실제 소모하거나 verifier가 실행 중인 경우에는 공동 한도 거부가 여전히 가능하다. 거부는 인증 실패와 구분 가능한 password oracle을 제공하지 않으며, client는 과도한 동시 login을 직렬화한다.

## 본인 공개 credential

`my-credentials`는 authenticated Session만으로 자기 `SelfCredentials`를 읽는다. Tenant·Node·After·TargetUser를 받지 않는다. `{ID,Username,Revision,Enabled,SystemAdmin,Credentials:[{ID,Method,PublicKey,Enabled,Label?}]}`이고 verifier 참조나 비밀번호·token·개인키는 없다. `mydc manage self-credentials`로도 조회한다. node CLI 제한이 켜진 경우 기존 독립 승인/관리자 조건을 우회하지 않는다.

본인 변경은 기존 signed UserOperation의 두 action이다. 관리자 전용 `put-user`와 달리 다른 계정이나 사용자 전체 record를 받지 않는다. `Principal=Session.User`, `Expected=현재 User.Revision`과 catalog root CAS를 모두 유지한다.

| Action | Payload | 효과 |
|---|---|---|
| add-credential | `{User,Credential:{ID,Method:"private-key",PublicKey},Label?,Challenge,Proof}` | 소유 증명한 Ed25519 공개키만 활성 credential로 추가. ID·키 중복 및 계정당64개 초과 거부 |
| disable-credential | `{User,Credential:credential ID}` | 자기 private-key credential만 비활성화. 다른 자격/계정 필드를 보존하며 마지막 인증수단·활성 node CLI 정책의 마지막 독립 admin key는 보호 |

두 action은 **Tenant `*`의 `credentials` scope**가 필요하다. scope 배열은 최대256개, 각 Actions는 최대13개이며 cluster와 credentials action은 Tenant=*에서만 유효하다. 새 password/private-key login의 기본 scope에 포함하며 token은 보호 발급 정의에 명시한 경우만 포함한다. read/deploy/cluster scope만으로는 허용되지 않는다. 기존 발급 Session에 새 scope를 자동 추가하지 않으므로 필요한 경우 다시 로그인한다. tenant 관리 권한이나 system-admin 지위를 새로 부여하지 않는다. node CLI 제한이 켜지면 여기에 기존 독립 사용자 승인과 system-admin/tenant-manager 조건도 추가된다.

계정 revision을 올리므로 추가만 해도 해당 계정의 **모든 기존 Session을 회수**한다. 현재 로그인한 key를 비활성화한 경우도 같다. 다른 활성 수단으로 새로 로그인해야 한다. 비밀번호/토큰 credential의 새 발급·변경은 이 action의 범위가 아니다.

## 새 key 소유 증명

브라우저는 새 Ed25519 개인키를 외부로 보내지 않고 다음 bytes를 서명해 Proof(base64 JSON bytes)로 넣는다. Challenge는 client CSPRNG의32바이트이며 모두0은 거부한다. PublicKey·Challenge는 JSON에서32개 숫자 배열이다.

```text
UTF8("mydc-self-credential-addition-1") || 0x00
|| Cluster[32]
|| LE64(ExpectedUserRevision)
|| LE64(len(UTF8(User))) || UTF8(User)
|| LE64(len(UTF8(Credential.ID))) || UTF8(Credential.ID)
|| LE64(len(UTF8(Credential.Method))) || UTF8(Credential.Method)
|| LE64(len(UTF8(Label))) || UTF8(Label)  # 없으면 빈 문자열
|| Credential.PublicKey[32]
|| Challenge[32]
```

Label은 UTF-8 최대128바이트, NUL/CR/LF/TAB 금지다. 이 원문은 JSON property 순서·문자 escape와 독립적이다. proof는 cluster·계정·원 계정 revision·ID·key·label·challenge를 모두 고정한다. 수락 후 revision CAS로 재사용할 수 없다. Go client는 `Client.NewCredentialAddition`을 사용하고 기존 Prepare/Operation에 payload를 넣는다. CLI는 보호 private-key 바이트를 app.yaml에 쓰지 않고 외부에서 만든 공개 증명을 `manage apply`의 metadata 입력으로 제출할 수 있다.

## password Session의 독립 관리 승인

이미 발급된 Session에 등록된 사용자 key의 별도 승인을 붙이는 형식은 `access.ApproveSession`과 동일하다. Session에서 Approval을 제외한 Go 정규 JSON 앞에 `mydc-issued-user-session-1`+NUL을 붙인 SHA-256이 `SessionApproval.Session`이다. `{Schema:1,PublicKey,Session,Signature:null}`의 Go 정규 JSON 앞에 `mydc-user-session-approval-1`+NUL을 붙여 해당 등록 key로 서명한 뒤 Signature를 bytes/base64로 넣고 Session.Approval에 첨부한다. 정규 JSON의 필드 순서는 [타입 선언](../../internal/access/session_approval.go)과 같으며 Go encoding/json의 기본 escaping을 사용한다.

이는 정확한 issuer 서명·계정·proof key·scope·수명에만 위임하고 새 권한/수명을 만들지 않는다. 승인 key는 현재 같은 계정에 활성 등록되어 있어야 하고 설치 node key는 승인 key로 쓸 수 없다. 최초 key 등록의 소유 증명과 기존 등록 key의 관리 승인은 서로 다르다. node CLI 제한이 켜진 상태에서 등록 key가 전혀 없는 사용자가 새 key의 Proof만으로 기존 독립 승인 조건을 우회할 수 없다.
