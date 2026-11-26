## 구현 위치

노드 shell의 사용자 명령·권한·로컬 SSH 준비는 [전용 명세](../node-shell.md), purpose19의 메시지/record는 [아래 형식](20-shell-purpose19.md)을 따른다. 일반 node 관리 권한과 사용자의 명시 shell grant를 구분한다.

| 경계 | 소스 |
|---|---|
| 경로·listener·TLS·peer UID·소유 inode | [unix.go](../../../internal/mydcp/unix.go) |
| record·EOF | [unix_stream.go](../../../internal/mydcp/unix_stream.go) |
| 공통 관리 handler·목적 제한 | [management.go](../../../internal/mydcp/management.go) |
| 인증 handshake | [authenticate.go](../../../internal/mydcp/authenticate.go) |
| frame/TLV | [frame.go](../../../internal/mydcp/frame.go) |
| 사용자 요청/응답·보호 입력 | [service.go](../../../internal/userauth/service.go), [secret.go](../../../internal/userauth/secret.go) |
| 데몬 listener 연결 | [mydcd main](../../../cmd/mydcd/main.go) |

