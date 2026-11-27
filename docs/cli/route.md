# sfcli route: 작업 공간 사이 연결

두 작업 공간의 망을 정해진 포트로 잇는다. 양쪽 작업 공간이 모두 승인해야 열린다. 명령은 `--tenant`나 context의 작업 공간 쪽에서 동작한다.

| 명령 | 하는 일 |
|---|---|
| `sfcli route list` | 내 작업 공간에서 나가거나 들어오는 route |
| `sfcli route endpoints TENANT` | TENANT의 망 중 route가 닿을 수 있는 서버·주소 pool |
| `sfcli route propose NAME --from T/NET@NODE --to T/NET@NODE --tcp 3306` | route를 제안한다 |
| `sfcli route approve NAME [--source TENANT]` | 내 쪽을 승인한다 |
| `sfcli route withdraw NAME [--source TENANT]` | 내 쪽 승인을 거두고 route를 닫는다 |

- `--from`은 내 작업 공간의 망 member, `--to`는 상대 작업 공간의 것이다. member에 주소 pool이 여럿이면 `T/NET@NODE:POOL`로 고른다.
- 포트는 `--tcp` 또는 `--udp`에 `3306`이나 `8000-8100`처럼 쓴다.
- 제안한 쪽도 `approve`를 해야 한다. 상대 작업 공간의 관리자가 자기 쪽에서 `approve`하면 열린다.
- 이름이 같은 route가 둘이면 `--source`로 출발 작업 공간을 고른다.
- `list`는 양쪽을 `TENANT/망이름@서버`로 보여 준다. 상대 작업 공간 망의 주소(CIDR)는 보이지 않는다.

예:

```sh
sfcli --tenant shop route endpoints db
sfcli --tenant shop route propose to-db --from shop/shop-net@node-a --to db/db-net@node-a --tcp 3306
sfcli --tenant shop route approve to-db
sfcli --tenant db route approve to-db
```
