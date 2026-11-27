# sfcli events: 진단 이벤트

```sh
sfcli events                          # 현재 작업 공간, 오래된 것부터 100개까지
sfcli events --app website --kind task-restarted
sfcli events --all --kind quorum-degraded   # 클러스터와 모든 작업 공간(시스템 관리자)
sfcli events -f                       # 새 이벤트를 계속 읽는다. Ctrl-C로 끝
sfcli events -o json                  # Cursor 포함
sfcli events --since CURSOR           # 지난번 -o json의 Cursor 다음부터
```

| 옵션 | 뜻 |
|---|---|
| `--app APP`, `--node NODE`, `--kind KIND` | 거르기. `--app`은 작업 공간이 있어야 한다 |
| `--all` | 클러스터·모든 작업 공간 범위 |
| `--since CURSOR` | 그 뒤부터. 너무 오래된 cursor는 거절되니 없이 다시 시작한다 |
| `--limit N` | 최대 개수(기본 100, `-f`에는 적용하지 않음) |
| `-f` | 따라가기 |

빈 목록이 건강하다는 뜻은 아니다. 표 끝의 `INCOMPLETE`는 수집에 빈틈이 있었다는 뜻이다. 종류와 보존 기간은 [이벤트](../reference/events.md).
