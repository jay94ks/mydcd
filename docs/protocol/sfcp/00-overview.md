# SFCP 개요: 계층, 연결, 인증

SFCP는 Seafield Cluster 노드 사이의 관리·복제·상태 보고·터널 데이터와 사용자 관리 API에 쓰는 바이너리 프로토콜이다. 자체 schema는 1이고, 옛 C++ 바이트 형식과 섞어 쓰지 않는다. 같은 major 안에서는 wire 호환을 지키고, 깨는 변경은 major를 올릴 때만 한다.

## 계층

```
QUIC (TLS 1.3, ALPN sfcp) ─┐                     ┌─ Unix TLS (/run/sfcdp.sock, 로컬 purpose만)
                           └─ Handshake (purpose 1)┘   상호 Ed25519 증명
                                    │
                                Session (Gate)
                                    │  스트림마다 첫 frame의 purpose로 handler를 고른다
     ┌──────────┬───────────┬───────┴──────┬───────────┬──────────┐
   unary     sensitive    bulk(조각)      duplex      report    DATAGRAM(Packet)
```

- **노드 사이**는 QUIC 연결 하나에 스트림을 여럿 연다. 대화 하나가 스트림 하나다. Packet(purpose 6)만 QUIC DATAGRAM으로 간다.
- **로컬 관리**(sfcli, sfc-web)는 Unix 소켓 위의 TLS에 같은 frame을 4바이트 길이 record로 싣는다. 스트림 다중화가 없어서 한 연결에서 대화를 하나씩 차례로 한다. 자세한 것은 [Unix 소켓](../../reference/unix-sockets.md)에 있다.
- 두 어댑터는 같은 frame·TLV, 같은 인증·권한 검사, 같은 handler를 쓴다. Unix에서는 표에 `local`로 적힌 purpose만 받는다([purpose 지도](02-purposes.md)).

## 인증

연결마다 Handshake(purpose 1)로 서로의 Ed25519 키를 증명한다. 인증 전에는 Handshake frame만 받는다. 인증이 끝나면 Session의 Gate가 상대 키의 현재 정책(Policy 비트: Member, Replicate, Manage, Read, Respond, Report, Tunnel, UserAuth, Snapshot)을 들고, frame마다 그 kind를 보낼 수 있는지 확인한다.

- 정책은 커밋된 membership에서 온다. membership이 바뀌면 다음 frame부터 새 정책으로 판단한다.
- Handshake 확장 tag 129는 그 빌드의 기능 목록이다. 양쪽 목록의 교집합으로 보낼 수 있는 purpose·kind를 정한다. 교집합은 노드마다 메모리에만 두고 Raft에 넣지 않는다.

## 이 문서 묶음

| 문서 | 내용 |
|---|---|
| [01-frame.md](01-frame.md) | frame header, TLV, kind의 공통 뜻 |
| [02-purposes.md](02-purposes.md) | purpose 지도(코드 표와 시험으로 대조) |
| [03-shapes.md](03-shapes.md) | 대화 모양: unary, sensitive, bulk, duplex, report, datagram |
| [04-sessions.md](04-sessions.md) | mesh, 연결 재사용, inbound_only, 연락·끊김 판단 |
| [05-reports.md](05-reports.md) | 노드 사이 보고와 Topic 채널 |
| [rules/](../sfcp.md#기능별-규칙) | 기능별 메시지 규칙 |
