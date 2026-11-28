# 세션: mesh, 재사용, 끊김

## mesh

- 노드 사이 연결은 mesh다. 먼저 연결한 쪽의 QUIC 연결을 두 방향 모두 쓴다.
- 노드는 그 peer와 세션이 없을 때만 dial한다(재시도 간격 1–10초).
- `node.yaml`의 `node.inbound_only: true`면 dial하지 않고 다른 노드가 연 세션만 쓴다. 공인 주소의 ingress gateway처럼 안쪽으로 들어올 수 없는 서버에 쓴다.
- 같은 peer에 연결이 둘 생기면 두 노드가 같은 규칙으로 하나를 고른다(작은 키 쪽이 연 것, 같은 쪽이면 새 것). 진 연결은 닫지 않고 기다리다가, 고른 연결이 끝나면 넘겨받는다. 이때는 끊김으로 보지 않는다.

## 연락과 끊김 판단

연락은 하나로 판단한다.

1. **마지막 수신 시각.** 서버(정식 구성원 ID)마다 그 서버에서 마지막으로 패킷을 받은 시각을 둔다(`Transport.LastReceived`). 인증된 연결에 온 패킷이면 종류와 상관없이 센다(데이터, DATAGRAM, ACK, PING).
2. **침묵할 때만 ping.** 한 연결에서 10초 동안 아무것도 받지 못했을 때만 QUIC PING을 보낸다. 다른 패킷이 오가는 동안에는 보내지 않는다.
3. **끊김.** 30초 동안 아무것도 받지 못한 연결은 닫는다. 그 서버의 마지막 연결이 의도치 않게 끝나면 `OnPeerLost`가 알린다.

Raft는 따로 주기 heartbeat를 보내지 않고 이 시각을 쓴다. leader는 그 follower에게서 heartbeat 간격(10초) 안에 무엇이든 받았으면 heartbeat를 건너뛰고, follower는 leader에게서 온 아무 패킷이나 leader 연락으로 센다. 읽기·쓰기의 leader 확인은 지금처럼 실제 AppendEntries로 한다.

QUIC idle timeout은 두 끝의 값 가운데 작은 것으로 정해진다.

## 로컬 연결

Unix 관리 소켓의 연결은 handshake로 TLS 키를 증명한 뒤, 같은 로그인의 대화가 차례로 재사용한다. 재사용은 마지막 대화 시작에서 30초까지다. 자세한 것은 [Unix 소켓](../../reference/unix-sockets.md)과 [대화 모양](03-shapes.md#unix에서)에 있다.
