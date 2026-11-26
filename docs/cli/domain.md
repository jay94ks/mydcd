# mydc domain: 클러스터에 등록한 도메인

클러스터가 맡는 도메인 목록이다. 도메인 하나는 그 이름과 그 아래 모든 이름을 덮는다(`shop.example`은 `api.shop.example`도 덮는다). 인증서는 등록한 도메인 안의 호스트에만 연결된다. 시스템 관리자 명령이다.

| 명령 | 하는 일 |
|---|---|
| `mydc domain list` | 등록한 도메인. 국제화 도메인은 A-label과 유니코드 모양을 함께 보여 준다 |
| `mydc domain add DOMAIN` | 도메인이나 IP 주소를 등록한다 |
| `mydc domain remove DOMAIN` | 도메인을 뺀다 |
| `mydc domain acme-responder show` | ACME HTTP-01 응답기 주소 |
| `mydc domain acme-responder set IP:PORT` · `clear` | 응답기 주소를 정하거나 지운다 |

바꾸는 명령은 묻고 나서 보내며 `--id ID`와 `--if-revision N`을 받는다. revision은 인증서 저장소 전체의 revision이다.

- 이름은 소문자 A-label로 바꿔 저장한다(`예시.한국` → `xn--vv4b11d.xn--3e0b707e`). 끝의 점은 뗀다.
- 와일드카드, 점 없는 이름, `com`이나 `co.kr` 같은 공개 접미사는 받지 않는다(종료 코드 2).
- IP 주소(`10.0.0.5`, `2001:db8::5`)도 등록할 수 있다. 그 주소 하나만 덮어서, 그 IP를 SAN에 가진 인증서가 연결된다. 사내망 IP로 접속하는 registry가 이렇게 인증서를 찾는다. zone 붙은 주소, `0.0.0.0`·`::`, 멀티캐스트는 받지 않는다.
- 최대 128개다.
- `remove`는 그 도메인 아래 호스트에 연결된 인증서가 있어도 거절하지 않는다. 인증서는 그 호스트와의 연결만 잃고, 연결이 하나도 남지 않은 인증서는 `미연결`로 옮겨 간다. 인증서 자체는 지우지 않는다.
- 도메인 목록은 공급자(Hostinger 등)와 따로 관리한다. 공급자 연결은 웹에서 DNS로 ACME 인증서를 받을 때만 쓴다.

## ACME HTTP-01 응답기

ingress는 등록된 도메인 호스트의 평문 HTTP 수신 주소에서 `/.well-known/acme-challenge/` 경로만 이 주소(웹 앱의 ACME 응답기, TUN 망 안의 IP:port)로 넘긴다. 앱의 경로 규칙보다 먼저 적용된다. 주소가 없으면 그 경로는 404다. 웹 앱(mydc-web)이 시작할 때 자기 응답기 주소로 직접 채우므로 보통은 손댈 일이 없다. 웹 자동 작업 계정은 시스템 관리자여야 하고, credential 허용 동작 목록을 정해 두었다면 `set-acme-responder`를 넣어야 한다([웹 API](../reference/web-api/23-ui-57-59.md#http-01-응답기-주소-mydcd-설정-웹이-채움)). 주소는 IP:port만 받는다(이름, port 0, zone, `0.0.0.0`·`::`, 멀티캐스트는 받지 않음). 같은 주소를 다시 넣으면 바뀐 것이 없다고 거절한다.

설계: 인증서 보관함.
