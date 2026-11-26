## 최초 등록용 공개 확인 Contract1

`mydcp-discovery-1` ALPN은 첫 접속의 제한된 공개 확인 전용이다. 일반 인증의 `mydcp-go-1` pin/cluster/challenge와 별도로 dispatch하며 인증 Gate나 User/관리·Raft handler로 승격하지 않는다. 확인을 위해 client는 새 in-memory TLS key를 사용하고 account password/token/사용자 개인키 서명을 보내지 않는다. TLS 인증서의 Ed25519 key/유효 기간/자체 서명과 실제 TLS proof를 먼저 확인하되 이 key를 자동 신뢰하지 않는다.

| 공개 확인 frame | 필수 TLV·제한 |
|---|---|
| Handshake kind3 요청 | request1, TLV1 새 nonce32. cluster/계정/운영 catalog 입력 없음 |
| Handshake kind4 응답 | request1, TLV1 server key32·TLV2 cluster32·TLV3 원 nonce32·TLV4 node ID(최대128B)·TLV5 Ed25519 signature64 |
| 서명 원문 | `mydc-public-discovery-1\0` + cluster32 + server key32 + client TLS key32 + nonce32 + TLS exporter32 + node ID 길이 u16 big-endian + node ID |
| TLS exporter | label `mydcp-discovery-1`, context=nil,32B. nonce/identity가 같아도 다른 연결의 proof를 재사용하지 못함 |
| 예산/종료 | frame 최대4096B·공개 확인 동시4개·5초 handshake/IO. 한 응답 뒤 연결 종료, 뒤따른 관리 요청을 dispatch하지 않음 |

client는 응답 key=실제 TLS 상대 key·nonce·node/cluster·exporter에 결합된 서명을 검증한다. 이는 해당 상대의 키 소유 확인이며 사용자 승인·노드 membership·현재 quorum을 증명하지 않는다. 최초 신뢰의 보호 TTY 확인 또는 명시 out-of-band cluster/key pin이 일치한 다음 profile/pubs 게시를 수행한다. 확인 실패/거부로 다른 endpoint/protocol이나 계정 인증을 자동 시도하지 않는다. 일반 ALPN에서는 기존 key approval을 유지하고 이 공개 경로의 key 허용을 재사용하지 않는다.


