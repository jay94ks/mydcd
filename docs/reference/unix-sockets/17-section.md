## 서버 실패 진단 로그

Unix와 네트워크 QUIC의 서버 처리 경로는 기존 표준 로그에 다음 형식으로 관측 가능한 실패를 기록한다. wire 응답이나 인증·재전송 정책을 바꾸는 메시지는 아니다.

```text
MYDCP server failure: transport=unix stage=handler cause=broken-pipe peer=<공개키HEX> purpose=8 kind=1 request=42
```

| 필드 | 의미 |
|---|---|
| `transport` | unix 또는 quic |
| `stage` | accept/track-connection·authenticate(TLS는 Unix tls-handshake)·receive·admit·capacity·dispatch·handler·receive-eof/send-eof 등 실제 실패 경계. QUIC은 parse/connection-capacity·accept-stream, 공개 확인은 discovery 계열 |
| `cause` | 고정 원인 분류. admission/frame/budget·deadline/io-deadline/timeout·unexpected-eof/eof/closed·broken-pipe/connection-reset·TLS/QUIC 오류 타입·other 등 |
| `peer` | 인증된 연결의 상대 공개키 HEX. MYDCP 인증 전 실패는 unknown |
| `purpose`, `kind`, `request` | 검증된 frame의 숫자 식별자. 첫 frame을 읽지 못했으면0. request는 wire 교환 ID이며 내구 operation ID가 아님 |

오류 원문·TLS record·endpoint·사용자명·payload/Secret·ticket/서명은 로그에 넣지 않는다. 임의 오류는 문자열을 출력하지 않고 other로 분류한다. 일반 업무의 denied/unknown Reply는 전송 handler 실패와 구별한다.

daemon/로컬 listener의 정상 종료, 요청 사이 Unix 유휴 종료·정상 client close, QUIC의 정상 연결 종료/유휴 만료, 성공한 discovery는 실패 로그를 남기지 않는다. 부분 record/header를 받은 뒤의 종료·기한 만료와 처리 중 EOF는 실제 실패로 기록한다. QUIC TLS가 SDK 내부에서 listener 수락 전에 거부되는 경우는 이 애플리케이션 로그의 관측 범위 밖이다. 로그가 없다는 사실로 관리 작업 미실행을 판단하지 않는다.

