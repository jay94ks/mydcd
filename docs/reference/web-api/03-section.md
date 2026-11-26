## 로그인

| 끝점 | 본문 → 응답 |
|---|---|
| `POST /auth/credential/challenge` | `{username, method:"password"\|"token", credential?}` → `{ticketId, deadline}` |
| `POST /auth/credential/login` | `{ticketId, secret}` → 세션 보기 + 쿠키. secret은 이 요청 동안만 메모리에 있다 |
| `POST /auth/key/challenge` | `{username, publicKey(hex 32B)}` → `{ticketId, ticket, ticketBytes(base64), proof(base64), deadline}` |
| `POST /auth/key/login` | `{ticketId, signature(hex 64B)}` → `{approve:true, ticketId, sessionDigest(hex 32B), approval(base64), deadline}`. 아직 쿠키 없음 |
| `POST /auth/key/approve` | `{ticketId(key/login이 돌려준 것), signature(hex 64B)}` → 세션 보기 + 쿠키. 다른 키의 서명·승인이 이미 붙은 세션은 403, ticketId가 없거나 지났으면 401 `ticket-expired` |
| `GET /auth/methods` | 로그인 없이 → `{credential:true, key}`. 로그인 화면이 브라우저 키 로그인을 보일지 정한다. 웹 앱 설정에서 끄면(`allowKeyLogin:false`) `key/challenge`·`key/login`·`key/approve`는 403 `key-login-disabled`. 이미 키로 들어와 있는 로그인은 끝내지 않는다 |
| `POST /auth/logout` | → 204. mydcd 연결을 닫고, 이 로그인으로 연 로그·감시 스트림과 터미널도 끝낸다(만료·session-expired도 같다) |
| `GET /auth/session` | → `{user:{id,username,revision,systemAdmin}, tenants:[{id,revision,role}], expiresAt, method, rootRevision}` |

개인키 로그인: 서버가 연결을 열고 `challenge`로 받은 Ticket(세션 키는 서버 연결이 생성)을 돌려준다. 브라우저는 `ticketBytes`에 대한 `ticket.signature`를 `ticket.issuer` 키로 검증할 수 있고, `proof` 바이트(`mydc-user-key-proof-1\x00` + canonical JSON)를 사용자 개인키(Ed25519)로 서명해 보낸다. **개인키는 브라우저 밖으로 나가지 않는다.** challenge와 login은 같은 mydcd 연결에서 끝나야 하므로 ticket은 서버 메모리에만 있고 5분(또는 Ticket 기한) 뒤 사라진다. 실패하면 연결을 닫고 처음부터 다시 한다. login이 받아들여지면 mydcd가 발급한 세션에는 아직 사용자 승인이 없다(R02, `userauth.KeyLogin`). 브라우저는 `approval` 바이트(`mydc-user-session-approval-1\x00` + canonical `access.SessionApproval{Schema:1, PublicKey:사용자 키, Session:sessionDigest}`, `sessionDigest` = `access.IssuedSessionDigest(발급 세션)`)를 같은 개인키로 서명해 `key/approve`로 보낸다. 데몬이 세션과 연결을 들고 있고 브라우저에는 서명할 바이트만 준다. 승인은 데몬 안에서 붙이므로 연결과 상관없지만 key/login 응답의 `deadline` 안에 보낸다. **challenge와 login 사이가 30초를 넘으면 안 된다**: mydcd는 30초 유휴 Unix 연결을 닫고, ticket은 그 연결의 challenge에 묶여 있어 다시 연결하면 쓸 수 없다. 화면은 비밀번호(또는 passphrase로 키 복호화)를 다 받은 뒤 challenge → login을 바로 이어 부른다.

로그인 뒤의 세션은 연결이 아니라 세션 키에 묶인다(R03). mydcd가 유휴 연결을 닫아도 데몬은 다음 요청에서 다시 연결해 같은 세션을 쓰고, 연결을 붙잡는 keepalive는 보내지 않는다. 한 로그인의 요청은 동시에 처리된다. 세션 만료·계정 변경·폐기만 로그아웃(401 `session-expired`)이 된다. 세션은 mydcd Session의 `ExpiresAt`(최대 3600초)에 끝난다. 자동 연장은 없다. 데몬이 다시 시작되면 모든 세션이 끝난다(남은 세션 행은 `restart`로 닫힘).

