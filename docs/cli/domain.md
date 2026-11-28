# sfcli domain: 클러스터에 등록한 도메인

클러스터가 맡는 도메인 목록이다. 도메인 하나는 그 이름과 그 아래 모든 이름을 덮는다(`shop.example`은 `api.shop.example`도 덮는다). 인증서는 등록한 도메인 안의 호스트에만 연결된다. 도메인마다 주인 작업 공간이 있거나(작업 공간 도메인) 없다(클러스터 수준 도메인). 바꾸는 명령은 시스템 관리자 명령이고, 작업 공간 사용자는 `list --tenant`로 자기 작업 공간 도메인만 본다.

| 명령 | 하는 일 |
|---|---|
| `sfcli domain list [--tenant T]` | 등록한 도메인과 주인(`(cluster)`는 클러스터 수준). 국제화 도메인은 A-label과 유니코드 모양을 함께 보여 준다. `--tenant`는 그 작업 공간 도메인만, 그 작업 공간의 읽기·배포·routes 권한으로 본다 |
| `sfcli domain add DOMAIN [--tenant T]` | 도메인이나 IP 주소를 등록한다. `--tenant`가 없으면 클러스터 수준이다 |
| `sfcli domain assign DOMAIN --tenant T` · `--cluster` | 주인을 바꾼다 |
| `sfcli domain remove DOMAIN` | 도메인을 뺀다 |
| `sfcli domain requests list [--tenant T]` | 클러스터 수준 도메인 아래의 작업 공간 route host와 상태(`pending` 대기, `open` 승인, `denied` 거절), 그 host를 쓰는 앱. `--tenant` 없이는 시스템 관리자만 |
| `sfcli domain certificates --tenant T` | 그 작업 공간 도메인과 승인된 host에 연결된 인증서의 공개 정보(이름, 발급자, 만료, 상태, 연결). 그 작업 공간의 읽기·배포·routes 권한으로 본다. 다른 작업 공간 이름과 chain·키는 보이지 않는다 |
| `sfcli domain requests approve` · `deny` · `revoke TENANT HOST` | host를 그 작업 공간에 승인하거나 거절하거나 결정을 지운다 |
| `sfcli domain acme-responder show` | ACME HTTP-01 응답기 주소 |
| `sfcli domain acme-responder set IP:PORT` · `clear` | 응답기 주소를 정하거나 지운다 |

지워진 작업 공간이 주인인 도메인은 클러스터 수준으로 다루며, `list`의 owner 칸에 `(cluster; deleted tenant T)`로(JSON은 `tenant_deleted: true`) 보인다. 다만 기록에는 옛 주인이 남아서, 그 아래에 클러스터 수준 도메인을 더하거나 다른 작업 공간에 하위 도메인을 주려면 먼저 `assign --cluster`(또는 `assign --tenant`)로 주인을 다시 정한다.

`--tenant`는 명령줄에 직접 준 값만 쓴다. context의 기본 작업 공간은 주인이나 목록 범위가 되지 않는다. `remove`는 `--tenant`를 받지 않는다.

바꾸는 명령은 묻고 나서 보내며 `--id ID`와 `--if-revision N`을 받는다. revision은 인증서 저장소 전체의 revision이다.

- 이름은 소문자 A-label로 바꿔 저장한다(`예시.한국` → `xn--vv4b11d.xn--3e0b707e`). 끝의 점은 뗀다.
- 와일드카드, 점 없는 이름, `com`이나 `co.kr` 같은 공개 접미사는 받지 않는다(종료 코드 2).
- IP 주소(`10.0.0.5`, `2001:db8::5`)도 등록할 수 있다. 그 주소 하나만 덮어서, 그 IP를 SAN에 가진 인증서가 연결된다. 사내망 IP로 접속하는 registry가 이렇게 인증서를 찾는다. zone 붙은 주소, `0.0.0.0`·`::`, 멀티캐스트는 받지 않는다.
- 최대 128개다.
- 작업 공간 도메인은 클러스터 수준 도메인 아래에 둘 수 있다(클러스터 `example.com` 아래 작업 공간 `shop`의 `shop.example.com`). 다른 작업 공간 도메인 아래의 도메인, 작업 공간 도메인 아래의 클러스터 수준 도메인은 거절한다. host 하나의 주인은 그 host를 덮는 가장 긴 등록 도메인이 정한다.
- 주인은 지금 있는 활성 작업 공간만 될 수 있다. 작업 공간을 끝내 지워지면(deleted) 그 도메인은 기록을 고치지 않아도 클러스터 수준으로 본다.
- `remove`는 그 도메인 아래 호스트에 연결된 인증서가 있어도 거절하지 않는다. 인증서는 그 호스트와의 연결만 잃고, 연결이 하나도 남지 않은 인증서는 `미연결`로 옮겨 간다. 인증서 자체는 지우지 않는다.
- 도메인 목록은 공급자(Hostinger 등)와 따로 관리한다. 공급자 연결은 웹에서 DNS로 ACME 인증서를 받을 때만 쓴다.

## route host 승인

작업 공간 앱의 route host가 클러스터 수준 도메인 아래에 있으면 배포는 되고, 그 host는 시스템 관리자가 승인할 때까지 트래픽을 받지 않는다. 승인은 (작업 공간, host) 한 건이며 route가 적은 host 그대로다(`*.shop.example`은 그 패턴 한 건). 승인은 그 작업 공간의 다른 앱과 다음 배포에도 쓰이고, route가 없어져도 `revoke`하기 전까지 남는다.

- 한 host는 한 작업 공간에만 승인한다. 다른 작업 공간에 승인된 host와 겹치는 host, 작업 공간 도메인을 덮는 host(`*.example.com` 아래에 작업 공간 도메인이 있을 때), 클러스터 앱 route host와 겹치는 host는 승인할 수 없다.
- `deny`한 host는 `denied`로 남고 열리지 않는다. `revoke`는 결정을 지워서 승인된 host는 다시 기다리고, 거절된 host는 route가 아직 쓰면 다시 대기가 된다.
- 결정은 인증서 저장소에 도메인과 함께 두어서 같은 revision으로 비교한다(최대 1024건).
- 작업 공간에 도메인을 주는 `add --tenant`·`assign --tenant`는 그 이름 아래를 다른 작업 공간 route나 결정, 클러스터 앱 route가 이미 쓰고 있으면 거절한다.
- 작업 공간이 지워지면 그 결정은 더 이상 쓰이지 않는다.

## ACME HTTP-01 응답기

ingress는 등록된 도메인 호스트의 평문 HTTP 수신 주소에서 `/.well-known/acme-challenge/` 경로만 이 주소(웹 앱의 ACME 응답기, TUN 망 안의 IP:port)로 넘긴다. 앱의 경로 규칙보다 먼저 적용된다. 주소가 없으면 그 경로는 404다. 웹 앱(sfc-web)이 시작할 때 자기 응답기 주소로 직접 채우므로 보통은 손댈 일이 없다. 웹 자동 작업 계정은 시스템 관리자여야 하고, credential 허용 동작 목록을 정해 두었다면 `set-acme-responder`를 넣어야 한다([웹 API](../reference/web-api/23-ui-57-59.md#http-01-응답기-주소-sfcd-설정-웹이-채움)). 주소는 IP:port만 받는다(이름, port 0, zone, `0.0.0.0`·`::`, 멀티캐스트는 받지 않음). 같은 주소를 다시 넣으면 바뀐 것이 없다고 거절한다.

설계: 인증서 보관함, 작업 공간 단위 도메인.
