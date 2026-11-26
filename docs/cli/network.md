# mydc network: 망

작업 공간의 MYDCP TUN 망 하나를 `network.yaml` 파일 하나로 만들고 바꾼다. 같은 파일을 다시 적용하면 아무것도 바뀌지 않는다. 명령은 `--tenant`나 context의 작업 공간에서 동작한다.

| 명령 | 하는 일 |
|---|---|
| `mydc network list [--all]` | 망 목록. `--all`은 모든 작업 공간(시스템 관리자) |
| `mydc network show NAME` | 서버별 주소, MTU, DNS, 진행 중인 변경. `state`의 `configured`는 클러스터에 망이 정해졌다는 뜻이고, 각 서버가 망을 열었는지는 아니다 |
| `mydc network create -f network.yaml` | 망을 만들고, 파일에 `dns`가 있으면 DNS도 켠다 |
| `mydc network update -f network.yaml [--no-wait]` | 망을 파일대로 바꾼다 |
| `mydc network delete NAME [--no-wait]` | 쓰는 컨테이너가 없어지면 망을 지운다 |
| `mydc network users NAME` | 망을 쓰는 앱과 컨테이너 |

`-f -`는 표준 입력에서 읽는다.

## network.yaml

```yaml
version: 1
name: shop-net
gateway: nat          # 생략 가능. 지금은 nat만
mtu: 1280             # 생략 가능. 서버 1대면 1500, 2대 이상이면 1280
toggles:              # 생략 가능. 망 옵션 켜기·끄기, 적지 않은 것은 지금 값 그대로
  local: false        # true면 이 망은 서버 한 대에만 둔다
members:
  node-a: {subnet: 10.240.10.0/24, dynamic: 10.240.10.0/25, tunnel: 10.240.30.1/32}
  node-b: {subnet: 10.240.20.0/24, gateway: 10.240.20.1, tunnel: 10.240.30.2}
dns:                  # 생략하면 DNS 없음
  zone: shop.mydc.test
  ttl: 30s            # 생략 가능(30s). 1s~1h, 초 단위
  upstreams: [1.1.1.1, 9.9.9.9:53]   # 생략 가능. 4개까지
  reverse: false
```

| 필드 | 뜻 |
|---|---|
| `version` | 1 |
| `toggles.NAME` | 망 옵션 하나를 켜거나(`true`) 끈다(`false`). 적지 않은 옵션은 만들 때 꺼져 있고, 바꿀 때 지금 값을 그대로 둔다. 장치와 주소는 그대로라 아무것도 끊기지 않는다. 지금 있는 옵션은 아래 표 |
| `name` | 망 이름. 소문자로 시작하고 a-z·0-9·`-`로 63자까지 |
| `mtu` | 컨테이너가 보는 MTU. 1280~9000. 서버가 2대 이상이면 서버 사이 터널이 이 크기를 실어야 하므로, 모든 서버의 서버망 MTU가 `mtu + 205` 이상이어야 한다(IPv6 기준, `network show`의 `underlay_mtu`). 서버망이 1500이면 1295까지 쓸 수 있다. 넘으면 create·update가 경고한다 |
| `members.SERVER.subnet` | 그 서버의 컨테이너 주소 대역. IPv4, /29까지 |
| `members.SERVER.gateway` | 대역의 게이트웨이 주소. 생략하면 대역의 첫 주소 |
| `members.SERVER.dynamic` | 자동 배정할 범위. 대역 안이어야 한다. 생략하면 따로 정하지 않는다 |
| `members.SERVER.tunnel` | 서버 사이 터널 주소. IPv4 한 주소(`/32`는 생략 가능) |
| `dns.zone` | 이 망의 관리 DNS가 맡을 영역 이름 |

대역끼리, 대역과 다른 서버의 터널 주소는 겹치면 안 된다. 모르는 필드는 오류다. DNS의 캐시·연결 한도는 고정 기본값을 쓰고, 이미 있는 망은 지금 값을 유지한다.

### 망 옵션(toggles)

| 이름 | 켜면 | 규칙 |
|---|---|---|
| `local` | 망을 서버 한 대에만 둔다(다른 서버와 잇지 않음) | 켜려면 서버가 한 대여야 한다. 켜져 있으면 서버를 더할 수 없다(파일에 서버를 더하면 `local: false`를 함께 적는다). 끄기는 언제든 된다 |

`mydc network show`의 `toggles`는 모든 옵션과 지금 값을 보여 준다.

## 바꾸기

- DNS만 바뀌면 바로 적용한다. `dns`를 지우면 DNS를 끈다.
- 옵션은 `set-network-toggle`로 바로 바꾼다. 새 값이 지금 서버 수에 맞으면 서버를 바꾸기 전에, 아니면(서버를 빼고 `local`을 켜기) 서버를 바꾼 뒤에 한다.
- 서버만 더하거나 빼고 남는 서버의 주소가 그대로면 한 서버씩 바꾼다. 더할 서버는 하나씩 붙이고(join), 뺄 서버는 새 사용을 막은 뒤(drain) 그 서버가 망을 쓰는 컨테이너가 없다고 알리면 뗀다(leave). 남는 서버의 컨테이너는 끊기지 않는다(경로만 바뀐다). 빼는 서버를 쓰는 앱만 먼저 멈춘다. 더하기를 빼기보다 먼저 한다. 빼는 중인 서버가 있으면 그 서버를 먼저 끝낸다.
- 파일에 `mtu`가 없으면 바꾸기는 지금 MTU를 그대로 쓴다. 다만 서버 한 대에서 쓰던 1500처럼 터널에 맞지 않는 MTU는 서버가 둘 이상이 될 때 기본값(1280)으로 바뀐다. MTU가 바뀌면 아래처럼 망 전체를 바꾼다.
- 남는 서버의 주소나 MTU가 바뀌면 망을 잠시 쓸 수 없다. 서버마다 변경을 예약하고(plan) 새 사용을 막은 뒤(drain), 그 서버가 망을 쓰는 컨테이너가 없다고 알리면 닫고(fence), 마지막에 새 망을 한 번에 적용한다(같은 서버면 commit, 서버가 바뀌면 reconfigure). 앱을 먼저 멈춘다. 명령은 무엇을 기다리는지 보여 주며 기다린다.
- `--no-wait`은 기다릴 필요 없는 단계만 보내고 돌아온다. 멈춘 작업은 `mydc op resume ID`로 이어 간다. 파일은 끝날 때까지 `~/.mydc/network/ID.yaml`에 두고 이어 갈 때 그 파일을 쓴다. `mydc op show ID`는 다음 단계만 알려 주고 아무것도 보내지 않는다.
- 단계마다 지금 상태에서 정해지는 고정 ID를 쓴다. 응답을 못 받고 다시 실행해도 같은 단계를 두 번 하지 않는다.

`delete`는 DNS를 먼저 끄고, 서버마다 새 사용을 막은 뒤 쓰는 컨테이너가 없어지면 지운다. 기다리기와 이어 가기는 `update`와 같다.
