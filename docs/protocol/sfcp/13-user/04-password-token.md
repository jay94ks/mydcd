### 보호 password/token 로그인

D5.05 완료 근거의 User kind1은 credential-challenge / credential-login을 제공한다. 둘 다 세션 없는 typed method다(`Params`/`Data`, R09). challenge는 `Params:{Username,AuthMethod,Credential?}`를 받고 envelope Session과 Request.Secret은 금지한다. 답 `Data`는 Ticket이다. Ticket의 optional AuthMethod/VerifierRef는 현재 user/credential/account revision·원 SessionKey/Challenge·issuer·최대300초 deadline과 함께 서명한다. 기존 개인키 ticket/요청은 추가 필드가 없으면 같은 바이트다.

credential-login은 `Params:{Ticket,Secret,LoginClient?}`(답 `Data`=Session)와 임시 연결 key의 sfc-user-credential-login-1 + cluster32 + key32 + challenge32 + SHA256(Body) proof를 사용한다. 다른 challenge·변조 ticket·일반 method의 Secret 혼입을 거부하며 credential 인증을 member relay하지 않는다. Secret은 pinned TLS 안에서만 전송하고 session/원 요청 결과에는 보존하지 않는다. signature/원 issuer/연결이 바뀌면 새 시도로 명시 진행하며 원 password/token을 자동 재전송하지 않는다. Fetch/KDF 뒤 latest quorum policy를 확인한 다음 기존 schema1 Session/현재 권한 경로로 발급한다. scope와 expires는 token의 보호 grant 및 현재 catalog로 제한한다.

