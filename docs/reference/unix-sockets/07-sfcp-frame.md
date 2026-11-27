## 공통 SFCP frame

record의 data를 이어 붙이면 다음 **24바이트 고정 header**와 body를 얻는다. 이 header와 TLV 정수는 **little-endian**이다. 바깥 record의 길이와 byte order가 다르다.

| offset | 크기 | 필드 | 값/규칙 |
|---|---|---|---|
| 0 | 4 | magic | ASCII `MDG1` |
| 4 | 2 | schema | u16,1 |
| 6 | 1 | purpose | 아래 허용 목적 |
| 7 | 1 | kind | 목적별 메시지 종류 |
| 8 | 4 | reserved | u32,0 |
| 12 | 8 | request | u64, 관리 교환에서는0이 아님 |
| 20 | 4 | body length | u32, TLV body 길이 |

body는 `tag:u16 | flags:u16 | length:u32 | value:length bytes`의 반복이다. tag는 오름차순이고 필수 field는1부터 연속이며 누락/중복/역순을 거부한다. flags는 optional0/required1이고 전체 field는 최대32개다. 선택 확장은 tag128 이상이다. 알 수 없는 필수 확장은 거부한다. 공통 body 상한은256KiB이며 목적별 더 작은 예산을 적용한다.

