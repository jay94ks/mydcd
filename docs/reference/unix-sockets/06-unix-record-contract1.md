## Unix record Contract1

| 필드 | 크기·인코딩 | 의미 |
|---|---|---|
| `length` | unsigned32, **big-endian** | 뒤따르는 data 길이, 최대65536 |
| `data` | 정확히 `length`바이트 | 연속 SFCP 바이트 스트림의 일부 |
| 방향 EOF | `length=0`, 즉 `00 00 00 00` | 현재 교환의 해당 송신 방향 종료 |

하나의 SFCP frame을 여러 record로 나눌 수 있다. record 경계와 frame 경계는 일치할 필요가 없으며, TLS read/write 경계도 의미 경계가 아니다. receiver는 길이만큼 정확히 읽고 그 바이트를 기존 frame decoder로 전달한다.

일반 RPC는 연결 하나에서 한 교환씩 순차 처리한다. 요청 송신자는 마지막 frame 뒤 **요청 방향 EOF record**를 보낸 후 응답을 계속 읽는다. 서버는 응답 frame과 응답 방향 EOF를 보낸다. 양쪽 EOF를 모두 소비한 뒤 다음 교환을 시작한다. `Stream.Close()`는 이 write 방향 EOF이며 전체 TLS 연결 종료가 아니다. 로그인 challenge/proof처럼 여러 교환은 같은 TLS/양방향 challenge 결합을 유지한다. purpose15 open과 purpose19 node shell은 각각 명시 stdin-eof 또는 half-close/end record를 사용하며 전용 연결을 점유한 뒤 종료한다.

유한 User RPC는 빠른 denied 응답도 요청 EOF를 확인한 뒤 반환한다. 요청 뒤 추가 byte는 거부하고 관리 효과를 실행하지 않는다. QUIC에서도 같은 순서를 지켜 server의 읽기 취소가 client FIN보다 앞서 정상 응답을 전송 실패로 바꾸지 않게 한다. `app-plan-stream`, `checker-source-stage`, `checker-module-stage`는 continue→body→EOF를 사용하는 별도 입력 stream이며 최초 header 뒤 EOF를 먼저 기다리지 않는다. checker recover와 initial credential 요청은 유한 RPC다.

과대 record·잘린 header/data·방향 EOF 전 TLS 종료는 오류다. 취소/오류는 해당 연결을 닫을 수 있으므로 다음 교환을 기존 연결에 억지로 이어 쓰지 않는다.

