# 네트워크 DNS 이름

네트워크 화면의 "DNS 이름" 탭이다. 이 네트워크의 관리 DNS가 답하는 이름과, 서버마다 지금 정책이 반영됐는지를 보여 준다. 작업 공간을 읽을 수 있는 사용자면 볼 수 있다. 코드는 [network_dns_names.go](../../../internal/web/server/network_dns_names.go)에 있다.

이름은 sfcd가 정한다. 관리 DNS 정책(`POST /t/{t}/networks/{name}/dns`)이 켜진 네트워크에서, 그 네트워크에 붙은 앱 서비스마다 이름이 생긴다.
- 기본 이름: `<서비스>.<앱>.<zone>`
- 별칭: app.yaml의 `aliases`, `x-sfc` dns records로 더한 이름

각 이름은 그 작업에 예약된 주소로 답한다. 이 이름들은 저절로 생기고 지워진다. 사람이 직접 더하는 레코드(A·AAAA·CNAME·TXT·MX·SRV·CAA)는 아래 `PATCH …/dns/records`에서 다룬다.

## `GET /t/{t}/networks/{name}/dns/names`

```json
{"managed":true,"enabled":true,"revision":3,"zone":"shop.internal.",
 "names":[
   {"name":"web.php-shop.shop.internal.","app":"php-shop","service":"web","family":"ipv4","address":"10.80.1.10"},
   {"name":"shared.shop.internal.","app":"php-shop","service":"web","family":"ipv4","address":"10.80.1.10"}],
 "records":[
   {"name":"www.shop.internal.","type":"CNAME","value":"web.php-shop.shop.internal.","served":true},
   {"name":"legacy.shop.internal.","type":"A","value":"192.0.2.7","served":true},
   {"name":"legacy.shop.internal.","type":"TXT","value":"\"hello\"","ttl":5,"served":true}],
 "servers":[{"node":"node-a","state":"ready","ready":true,"resolvers":["10.80.1.1:53"]}]}
```

| 칸 | 뜻 |
|---|---|
| `managed` | 관리 DNS 정책이 있는지. 없으면 `names`와 `servers`가 비어 있다 |
| `enabled`, `revision`, `zone` | 정책이 켜졌는지, 정책 revision, zone |
| `names[].task` | 복제본이 여럿인 서비스면 그 복제본 작업 키 |
| `names[].family`, `address` | 이름이 돌려주는 예약 주소와 그 종류(`ipv4`·`ipv6`, 주소로 정함). 예약을 찾지 못하면 둘 다 빈 문자열 |
| `records[]` | 직접 더한 레코드. `type`·`value`는 아래 표, `ttl`은 레코드에 정한 TTL(없으면 망의 TTL) |
| `records[].served` | 지금 답하는지. 같은 이름을 앱 서비스가 가지면 `false`이고, 그동안은 앱 서비스의 주소로 답한다 |
| `servers[]` | 네트워크 멤버 서버마다 DNS 반영 상태. [자원](../web-api.md)의 네트워크 행과 같은 값이다 |
| `servers[].state` | sfcd가 그 서버에서 읽은 상태: `ready`, `not-ready`, `unreachable`, `unknown` |
| `servers[].ready` | 지금 정책 revision을 그 서버가 반영했는지. 아직 모르면 없다 |
| `servers[].resolvers` | 그 서버의 DNS가 실제로 듣는 주소 |

이름 목록은 클러스터에 확정된 작업과 주소 예약으로 만든다. 각 서버의 DNS가 그 이름을 실제로 답하는지는 `servers[].ready`로 본다. 없는 네트워크는 `404`다.

`/resources`의 네트워크 멤버 행에도 이제 서버마다 `dns`(state·ready·resolvers)가 붙는다.

## `PATCH /t/{t}/networks/{name}/dns/records`

직접 더한 레코드를 읽은 revision 기준의 변경분(delta)으로 바꾼다. 목록 전체를 보내지 않는다. 관리 DNS 정책을 바꾸는 일이라 `configure-network-dns`로 서명되고, 네트워크 서비스 관리 권한이 필요하다(판단은 sfcd가 한다).

```json
{"opId":"…","expected":3,
 "remove":[{"name":"legacy","type":"A","value":"192.0.2.7"}],
 "add":[{"name":"legacy","type":"A","value":"192.0.2.8"},
        {"name":"www","type":"CNAME","value":"web.php-shop.shop.internal"},
        {"name":"@","type":"MX","value":"10 mail.example.org","ttl":300}]}
```

| 칸 | 뜻 |
|---|---|
| `expected` | 목록을 읽은 때의 `revision`(`dns/names`). 필수다. 그 뒤 정책이 바뀌었으면 `409 stale`이고 아무것도 바뀌지 않는다. 다시 읽고 보낸다 |
| `remove[]` | 뺄 줄. 지금 목록에 꼭 그대로 있어야 한다(없으면 `422 no-such-record`) |
| `add[]` | 더할 줄. 이미 있는 줄이면 `422 exists` |
| `name` | zone 아래 이름. `www`처럼 쓰면 `www.<zone>`이 되고, `www.<zone>`으로 써도 같다. zone 자체는 `@`나 zone 이름으로 쓰며 CNAME만 안 된다. `ns.<zone>`은 안 된다 |
| `type` | `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `SRV`, `CAA`(대소문자 무관). PTR은 망의 reverse 설정이 만들고, NS·SOA는 zone이 가지므로 직접 더할 수 없다 |
| `value` | 레코드 데이터를 zone 파일 형식 한 줄로 쓴 것(아래 표). sfcd가 정규형으로 바꿔 두며, 읽을 때와 `remove`에 쓸 값은 그 정규형이다 |
| `ttl` | 선택. 1~3600초. 비우면 망의 TTL을 쓴다. 답할 때는 망의 TTL(캐시 TTL 상한, 기본 10초)을 넘지 않는다. 한 이름의 같은 종류 레코드는 TTL이 같아야 한다 |

종류별 `value`:

| 종류 | 형식 | 예 | 한도 |
|---|---|---|---|
| `A` | IPv4 주소 | `192.0.2.7` | 0.0.0.0·멀티캐스트·255.255.255.255 제외 |
| `AAAA` | IPv6 주소 | `2001:db8::7` | ::·멀티캐스트·IPv4 매핑 제외 |
| `CNAME` | 대상의 전체 이름 | `example.org`, `api.sample.<zone>` | 자기 자신은 안 됨 |
| `TXT` | 문자열. 따옴표 없이 쓰면 문자열 하나다. 여러 조각은 `"a" "b"`처럼 따옴표로 쓴다 | `v=spf1 -all` | 조각마다 255바이트, 16조각, 값 전체 1024바이트 |
| `MX` | 우선순위 호스트 | `10 mail.example.org` | 우선순위 0~65535 |
| `SRV` | 우선순위 가중치 포트 호스트 | `10 5 5432 db.shop.internal` | 각 수 0~65535. 이름은 보통 `_서비스._tcp` |
| `CAA` | 플래그 태그 값 | `0 issue "letsencrypt.org"` | 플래그 0·128, 태그 `issue`·`issuewild`·`iodef`, 값 255바이트 |

호스트 이름(CNAME·MX·SRV)은 전체 이름으로 쓴다. 끝의 점은 있어도 없어도 같다. 줄바꿈은 쓸 수 없다. 형식이 틀리면 `422 invalid`이고, 메시지에 그 종류의 예가 붙는다.

줄 하나를 고치는 일은 같은 요청에 옛 줄을 `remove`, 새 줄을 `add`로 넣는 것이다. 둘 중 적어도 하나는 있어야 하고, 각각 최대 64개다. 빼기를 먼저 하고 더하기를 한 뒤의 목록에 아래 규칙을 적용한다.

규칙:
- CNAME이 있는 이름에는 다른 레코드를 둘 수 없다(CNAME도 하나만).
- 한 이름에 같은 종류는 최대 8개다.
- 목록은 최대 64개다.
- 앱 서비스가 이미 가진 이름을 새로 더하면 `422 name-taken`이다. 목록에 원래 있던 이름을 나중에 앱 서비스가 갖게 되면, 그 줄은 남고 `served:false`가 된다.
- 관리 DNS 정책이 없는 네트워크는 `422 no-dns`다.
- zone을 바꾸면(`POST …/dns`) 직접 더한 이름도 새 zone으로 옮겨진다. zone 안을 가리키는 CNAME·MX·SRV 대상도 같이 옮겨진다.

웹은 받은 변경분을 `expected` revision의 정책에 적용한 뒤, sfcd에 같은 revision CAS로 정책을 쓴다. 그 사이 다른 쓰기가 끼어들면 작업은 `failed`가 된다.

DNS는 이렇게 답한다:
- 그 이름의 그 종류 질의에 레코드들로 답한다. 이름은 있는데 그 종류가 없으면 빈 답(NODATA)이다.
- CNAME 이름은 어느 질의에든 CNAME으로 답한다. 대상이 같은 zone 안이면 대상의 답까지 한 응답에 붙인다(최대 8단계, 고리는 거기서 멈춘다). zone 밖 대상은 클라이언트가 다시 묻는다.
- 직접 더한 이름은 역방향(PTR) 이름을 만들지 않는다.
