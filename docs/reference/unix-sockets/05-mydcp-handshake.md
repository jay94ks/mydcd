## MYDCP 인증 handshake

일반 TLS 연결이 수립되면 **record를 붙이기 전의 MYDCP frame**을 직접 교환한다. 목적은 `Handshake=1`, frame request는1, body 예산은4096바이트다.

| 순서 | 송신자 | frame과 의미 |
|---|---|---|
| 1 | client | kind1: 자기 TLS key32·cluster32·새 challenge32 |
| 2 | server | kind1: 자기 key32·cluster32·서버 challenge32 |
| 3 | server | kind2: 자기 key32·cluster32·client challenge32·signature64 |
| 4 | client | kind2: 자기 key32·cluster32·server challenge32·signature64 |
| 5 | server | kind1 ACK: 자기 key32·cluster32·client challenge32 |

kind2의 Ed25519 서명 원문은 `mydc-go-auth-1`의 ASCII 바이트 뒤에 `fullKey32 || cluster32 || 상대 challenge32`를 붙인 값이다. 이 domain에는 종료 NUL을 추가하지 않는다. TLS 상대 키와 frame 키·현재 승인 키가 같아야 하고, cluster와 fresh challenge를 대조한다.

인증/공개 확인 메시지의 TLV는 다음과 같다. 모든 필드는 required이며 tag 순서는 표의 순서다. 이 메시지는 JSON이 아니라 지정 길이의 raw 바이트다.

| purpose/kind | ALPN·방향 | TLV 포맷 |
|---|---|---|
| Handshake / 1 | 일반 인증 양방향·서버 ACK | tag1 public key32, tag2 cluster32, tag3 challenge32 |
| Handshake / 2 | 일반 인증 양방향 proof | 위 tag1..3 + tag4 Ed25519 signature64 |
| Handshake / 3 | discovery client→server | tag1 새 nonce32 |
| Handshake / 4 | discovery server→client | tag1 서버 key32, tag2 cluster32, tag3 원 nonce32, tag4 node ID UTF-8, tag5 signature64 |

공개 확인의 request도1, body 예산도4096바이트다. kind3/4는 discovery ALPN에서만 공개 확인 목적으로 처리하며 일반 인증 메시지를 대신하지 않는다.

이 handshake가 끝난 뒤 아래 record 계층으로 요청/응답을 전달한다. 인증 handshake에는 record 길이 prefix를 붙이지 않는다.

