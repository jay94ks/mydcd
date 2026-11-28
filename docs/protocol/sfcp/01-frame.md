# frame과 TLV

코드: `pkg/sfcp/wire`(표준 라이브러리만 쓰는 codec, Seafield 엔진도 같은 사본을 쓴다), `internal/sfcp/purposes.go`(purpose·kind마다의 규칙).

## header (24바이트, little endian)

| 위치 | 크기 | 값 |
|---|---|---|
| 0 | 4 | `MDG1` |
| 4 | 2 | schema = 1 |
| 6 | 1 | purpose |
| 7 | 1 | kind |
| 8 | 4 | 예약, 0 |
| 12 | 8 | request ID. Packet(datagram)만 0이고, 나머지는 0이 아니다 |
| 20 | 4 | 본문 길이 |

본문은 최대 256KiB이고, purpose·kind마다 더 작은 한도가 있다([purpose 지도](02-purposes.md)). 받는 쪽은 본문을 할당하기 전에 header·purpose·kind·길이를 먼저 검사한다.

## 본문: TLV

`tag u16 | flags u16 | length u32 | value`를 tag 오름차순으로 잇는다.

- tag 1..n은 그 kind의 필수 필드다. 순서대로 모두 있어야 하고, flags는 1(required)이다. 길이가 정해진 필드(32바이트 digest 등)는 그 길이와 정확히 같아야 하고, 나머지는 비어 있으면 안 된다.
- tag 128 이상은 선택 확장이다. flags는 0이다. 모르는 확장은 무시한다. 같은 major 안에서 필드를 더할 때는 여기에 더한다.
- 그 밖의 tag, 중복, 내림차순, 32개를 넘는 필드, 잘린 본문은 frame 오류다.

## kind의 공통 뜻

모든 purpose가 같은 번호를 같은 뜻으로 쓴다. purpose 고유 kind는 16부터다. Handshake와 Packet은 대화가 아니라서 자기 번호를 쓴다.

| kind | 뜻 |
|---|---|
| 1 | 요청(대화를 여는 frame) |
| 2 | 응답 |
| 3 | member relay(원 요청을 바꾸지 않고 다른 노드가 대신 전달) |
| 4 | 데이터 조각 |
| 5 | duplex record |
| 6 | 끝: 전체 길이와 digest |
| 7 | 저장 ACK: 받는 쪽이 어느 위치까지 내구 저장했다 |
| 8 | 최종 ACK: 전체 검증이 끝났다 |
| 16+ | purpose 고유 |

없어진 kind 번호는 다시 쓰지 않는다. Observation의 17(노드 관측)과 20(알림)은 Topic 채널로 옮겨 비어 있고, 21은 경유 부하 보고용으로 예약돼 있다.

## 봉투

관리·사용자 요청의 tag 1은 서명된 봉투(JSON)이고 tag 2는 그 SHA-256이다. 응답은 요청 digest를 되돌려 짝을 맞춘다. 봉투의 Body는 서명한 compact JSON 바이트를 그대로 싣는다(base64가 아니다). 형식은 [관리/전송 계약](rules/04-section.md)에 있다.
