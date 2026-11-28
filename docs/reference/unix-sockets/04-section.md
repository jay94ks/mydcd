## 연결 수립과 최초 신뢰

일반 관리 연결은 ALPN **`sfcp-go-1`**을 사용한다. TLS 최소 버전은1.3이며 양쪽 인증서의 Ed25519 키와 현재 승인/pin 정책을 검사한다. 인증서의 키·유효 기간·자체 서명·실제 TLS proof를 확인한다.

최초 cluster 등록에는 별도 ALPN **`sfcp-discovery-1`**을 사용한다. 이 연결은 제한된 공개 키/cluster/node 확인만 수행하고 응답 뒤 종료한다. 응답은 nonce·client/server TLS 키·cluster·TLS exporter에 서명으로 결합된다. 사용자가 보호 TTY에서 확인하거나 명시 out-of-band pin과 일치시킨 후 신뢰를 게시한다. discovery 연결을 관리 세션으로 승격하지 않는다. 상세 바이트 계약은 [공개 확인 Contract1](../../protocol/sfcp/rules/20-contract1.md)을 따른다.

