# 서버의 실제 주소 목록 (게이트웨이 설정)

게이트웨이 설정 대화상자가 서버에 실제로 있는 주소를 보여 주고 그중에서 고를 수 있게 한다. `GET /nodes/{n}/gateways`(시스템 관리자) 응답에 `localAddresses`가 붙는다. 이 목록은 sfcd가 응답할 때마다 그 서버에서 직접 읽어 온 값이다. 클러스터에는 저장하지 않고, 설정 값도 아니다. 코드는 [local_addresses.go](../../../internal/ingress/local_addresses.go)와 [ingress_config.go](../../../internal/web/server/ingress_config.go)에 있다.

```json
{"source":"file","revision":0,"appliedRevision":0,"external":{…},"local":{…},
 "localAddresses":[
  {"iface":"eth0","address":"203.0.113.21","cidr":"203.0.113.21/24","scope":"public"},
  {"iface":"eth1","address":"192.168.1.101","cidr":"192.168.1.101/24","scope":"private"},
  {"iface":"lo","address":"127.0.0.1","cidr":"127.0.0.1/8","scope":"loopback"}]}
```

- **목록에 들어가는 주소:** 켜진 인터페이스의 주소만 넣는다. link-local(`169.254.0.0/16`, `fe80::/10`), multicast, 0.0.0.0·`::`는 게이트웨이가 쓸 수 없어서 뺀다.
- **`scope` 구분:**
  - `public`: 인터넷에서 닿는 주소.
  - `private`: 사설 주소(RFC 1918, `fc00::/7`)와 `100.64.0.0/10`.
  - `loopback`: 루프백 주소.
- **`cidr`:** 주소에 인터페이스의 prefix 길이를 붙인 값이다.
- **정렬:** `public`, `private`, `loopback` 순서로 놓는다. 같은 구분 안에서는 인터페이스 이름 순, 그다음 주소 순이다.
- **목록에 함께 보이는 주소:** sfc의 서버 IP(`10.254.240.0/20`)와 Docker bridge 주소도 그 서버의 인터페이스라서 `private`으로 보인다.
- **빈 목록이 오는 경우:** 그 서버에 연결되지 않으면 웹은 빈 목록 `[]`을 준다. 인터페이스를 읽지 못한 경우도 같다.
- **고른 주소의 확인:** 목록은 고르기 위한 것이다. `PUT /nodes/{n}/gateways`로 보낸 주소는 그 서버가 서명하기 전에 다시 확인한다(`INGRESS_ADDRESS_NOT_LOCAL`).
