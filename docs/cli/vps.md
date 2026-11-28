# sfcli vps: VPS 공급자 계정과 VPS 서버

클러스터가 VPS 공급자 API로 VPS 서버를 만들고 관리하려면 공급자 계정을 먼저 연결한다. 지금 공급자는 iwinv 하나다. 모두 시스템 관리자 명령이다. 설계: VPS 서버.

| 명령 | 하는 일 |
|---|---|
| `vps account list` | 연결한 계정, 액세스 키 끝 네 글자, 트래픽 단가 |
| `vps account add NAME --access-key KEY [--vendor iwinv] [--traffic-price KRW] [--secret-key-file FILE]` | 계정 연결 |
| `vps account rotate-key NAME --access-key KEY [--secret-key-file FILE]` | 키 쌍 바꾸기 |
| `vps account set NAME [--traffic-price KRW] [--ssh-key-id ID] [--guard-window MIN] [--guard-average MIN] [--guard-pattern on\|off]` | 트래픽 단가, 공급자에 등록한 계정 SSH 키 ID, 트래픽 조기 감시 설정 바꾸기 |
| `vps account ssh-key NAME` | 공급자에 등록할 계정 SSH 공개키 |
| `vps account remove NAME` | 연결 끊기 |

- `NAME`은 1~32자의 소문자·숫자·가운데 하이픈이다.
- 시크릿 키는 `--secret-key-file`, 터미널이 아닌 표준 입력, 숨긴 입력 순서로 읽는다. 명령줄 인자로는 받지 않는다.
- 시크릿 키는 접속한 서버가 봉인한다. 봉인은 클러스터 마스터 키를 가진 투표 서버만 할 수 있으니, 투표 서버에 접속한 context로 실행한다. 봉인된 키만 클러스터에 저장되고 다시 보여 주지 않는다.
- `--traffic-price`는 기본 제공량을 넘는 트래픽의 GB당 가격(원)이다. 공급자 API가 이 값을 알려 주지 않아서 직접 넣는다. 0이면 트래픽 요금을 세지 않는다. 공급자가 요금표를 공개한 경우(iwinv) 그 요금표를 쓰고 이 값은 쓰지 않는다.
- 트래픽 조기 감시: 각 VPS 서버가 1분마다 자기 송신량을 재 리더에 알리고, 리더는 앞으로 21분 동안 보낼 양을 예측해 상한에 닿기 15분 전에 상한 처리(`CapAction`)를 한다. `--guard-window`는 증가세를 재는 창(분, 기본 5), `--guard-average`는 함께 보는 누적 평균 기간(분, 기본 60, 창의 2배 이상), `--guard-pattern`은 지난 한 달의 같은 시각대 패턴을 쓸지(기본 on, 기록이 7일 미만이면 켜 두어도 쓰지 않는다). 0은 기본값이다.
- 변경은 계정 목록 전체 revision으로 CAS를 건다. `set`과 `remove`는 `--if-revision`을 받는다. 결과를 모르면 `sfcli op show ID`, `sfcli op resume ID`로 같은 원본을 이어 보낸다.

## VPS 서버

| 명령 | 하는 일 |
|---|---|
| `vps catalog ACCOUNT [--zone Z] [--core-type SINGLE,MAXIO] [--min-vcpu N] [--max-vcpu N] [--min-memory MiB] [--max-memory MiB] [--all]` | 공급자가 지금 파는 존·리눅스 이미지·인스턴스 타입(요금, 존별 재고)·SSH 키·사용자 스크립트 |
| `vps list` | 클러스터가 만든 VPS 서버와 단계 |
| `vps create NAME --account A --zone Z --image I --type T --cap KRW [--cap-action stop\|notify] [--script S] [--ssh-key K]... [--voter] [--port 7443]` | VPS 서버 만들고 클러스터에 넣기. `--script`가 있으면 `.well-known`으로 스스로 가입, 없으면 리더가 SSH로 설치 |
| `vps status` | 서버별 이번 달 지금까지·월말 예상 요금, 상한, 트래픽, 계정별 공급자 실시간 요금 |
| `vps set-cap NAME [--cap KRW] [--cap-action stop\|notify] [--if-revision R]` | 월 요금 상한과 넘었을 때 할 일 바꾸기 |
| `vps stop NAME [--dns-wait 5m] [--if-revision R]` | VPS 서버 끄기(클러스터에는 cordon된 채 남음) |
| `vps start NAME [--if-revision R]` | 끈 VPS 서버 다시 켜기 |
| `vps delete NAME [--if-revision R]` | VPS 서버와 공급자 인스턴스 삭제(되돌릴 수 없음) |

- `catalog`는 접속한 투표 서버가 공급자 API를 바로 읽는다. 요금은 부가세 포함이다. 기본으로 리눅스 이미지와 테스트가 아닌 타입만 보이고, `--all`이면 모두 보인다. 지금 재고가 없는 존은 `(out of stock)`으로 표시한다.
- `create`는 공급자에게 바로 요금이 나가는 작업이다. 리더가 서버를 만들고(`creating`), 공인 IP가 붙으면 `installing`, 가입을 마치면 `running`이 된다. 30분 안에 실행되지 않거나 공급자가 거절하면 `failed`와 그 이유가 남는다. 실패한 VPS가 공급자에 남아 있으면 요금이 계속 나갈 수 있으니 `vps delete`로 지운다.
- 리더는 공급자에게 만들기를 보내기 전에 "보냄"을 클러스터에 먼저 기록하고, 만들기는 서버마다 딱 한 번만 보낸다. 공급자 메모 칸에 이 작업의 태그를 쓰고, 그 뒤로는 태그로 찾기만 한다. 공급자 목록이 늦거나 응답을 잃거나 리더가 바뀌어도 VPS가 두 대 생기지 않는다. 보낸 뒤 30분 안에 나타나지 않으면 `failed`(`TIMEOUT`)로 끝난다.
- 외부 접속 경로가 있으면 VPS의 사용자 스크립트가 `.well-known` 경로로 리더와 같은 sfcd를 받고 가입한다: [VPS 서버 자동 가입](../reference/vps-enroll.md).
- 새 서버는 투표하지 않는 서버로 들어온다. `--voter`면 가입한 뒤 따로 투표 서버로 올린다.
- `--cap`은 이 서버의 월 요금 상한(원)이다. 리더가 10분마다 실행 중인 서버의 이번 달 트래픽을 읽어 월말 예상 요금을 낸다. 지금까지 요금이 이미 상한을 넘었거나, 1시간치 읽기가 모인 뒤 예상이 상한을 넘으면 `--cap-action`대로 한다.
  - `stop`(기본): drain 없이 그 서버를 끈다. `stopping`이 되고 5분(DNS 대기) 뒤 공급자에서 끄면 `capped`가 된다. 그 서버의 앱은 꺼지는 순간 멈추니 다른 서버로 옮기는 것은 운영자가 한다. 투표 서버는 남은 투표 서버가 한 대 더 잃어도 버틸 때만 끄고, 아니면 계속 켜 두고 `vps status`에 보인다.
  - `notify`: 끄지 않고 `vps status`에 상한 초과로 보인다.
  - 읽은 값은 리더 메모리에만 있다. 리더가 바뀌면 새 리더가 처음부터 다시 읽으므로, 그때부터 1시간 동안은 예상만으로 끄지 않는다.
  - `capped` 서버는 상한을 끈 때 기록한 월말 예상보다 높여야(`vps set-cap`) `vps start`로 켤 수 있다. 다음 달이 되면 그대로 켤 수 있다.
- `status`는 접속한 서버가 리더에게 물어 보여 준다. 공급자를 못 읽은 회차는 판정하지 않고 실패 코드를 보인다. 계정 줄은 공급자 실시간 요금과 우리 계산 합을 나란히 보인다.
- `delete`는 되돌릴 수 없다. 리더가 공급자에서 인스턴스를 지우고(`deleting`), 공급자가 받으면 기록을 지운다. 인스턴스 ID를 아직 모르면 태그로 찾는다. 만들기를 보냈는데 아직 안 보이면 30분까지 기다렸다가 지운다. 공급자 응답을 모르면 다음 회차에 다시 한다.
- 클러스터에 들어온(`running`) 서버는 먼저 `sfcli node drain NAME`과 `sfcli node remove NAME`으로 뺀다. 가입하지 않은 서버(`failed`, `creating`, `installing`)는 바로 지운다. 초대만 받고 가입하지 않은 서버의 이름은 `sfcli node remove NAME`으로 초대를 취소하면 다시 쓸 수 있다.
- `stop`은 먼저 `sfcli node cordon NAME`과 `sfcli node drain NAME`을 한 뒤에 한다. cordon되어 있고 가장 최근 drain이 모든 작업을 옮긴(`Succeeded`) 서버만 끌 수 있다. 투표 서버는 남은 투표 서버들이 한 대 더 고장 나도 버틸 수 있을 때만 끈다(투표 서버 5대 이상).
- `stop`을 하면 `stopping`이 되고, `--dns-wait`(레코드 TTL, 기본 5분, 최대 1시간)가 지나면 리더가 공급자에서 끄고, 꺼진 것을 확인하면 `stopped`가 된다. 끈 서버도 공급자가 요금을 받을 수 있다.
- sfc-web이 돌고 있으면 `stopping`을 보고 그 서버가 '연결된 서버'인 외부 도메인의 Seafield Cluster A·AAAA 레코드에서 그 주소를 잠시 빼고, 다시 `running`이 되면 되돌린다([웹 API](../reference/web-api/54-vps.md#중지할-때-dns-웹이-하는-임시-변경)). 그 서버 주소만 있는 레코드는 남기고, 그 밖의 DNS 레코드는 직접 고친다. `--dns-wait`는 그 레코드의 TTL보다 길게 준다.
- `start`를 하면 `starting`이 되고, 리더가 켠 뒤 실행 중인 것을 확인하면 `running`이 된다. 그다음 `sfcli node uncordon NAME`으로 작업을 다시 받게 한다.
- 리더는 공급자 상태를 먼저 읽고, 끄기·켜기는 2분에 한 번까지만 보낸다. 공급자 작업이 도는 동안에는 다시 보내지 않는다.

## 보유 VPS (Hostinger)

내가 공급자에서 이미 사서 갱신하는 VPS를 클러스터에 붙인다. 클러스터는 사지도, 갱신하지도, 지우지도 않는다. 위의 `vps list`·`vps account`에는 나오지 않고 여기에만 나온다(관리형과 목적이 달라서다). 설계: Hostinger 보유 VPS.

| 명령 | 하는 일 |
|---|---|
| `vps owned account list` | 보유 VPS 공급자 계정 |
| `vps owned account add NAME [--vendor hostinger] [--token-file FILE]` | API 토큰 하나로 계정 연결(접속한 투표 서버가 봉인) |
| `vps owned account rotate-key NAME [--token-file FILE]` | 토큰 교체 |
| `vps owned account remove NAME [--if-revision R]` | 계정 연결 끊기(붙은 서버가 있으면 거절) |
| `vps owned list` | 붙인 보유 VPS |
| `vps owned attach NAME --account A --instance ID [--ssh \| --existing NAME] [--voter] [--port P] [--near-limit exclude\|low-weight]` | VPS를 서버 NAME으로 붙이기 |
| `vps owned set NAME [--near-limit exclude\|low-weight] [--restore] [--if-revision R]` | 월 대역폭이 다 되기 전 동작 바꾸기, `--restore`는 지금의 보류를 바로 끝냄(그달에는 다시 보류하지 않음) |
| `vps owned detach NAME [--if-revision R]` | 붙인 기록만 지우기(VPS는 공급자에 그대로) |

- 설치 방법은 운영자가 고른다. `--ssh`면 리더가 계정 SSH 키로 sfcd를 넣는다(이 서버는 투표하지 않는다). 기본은 직접 설치로, 보이는 설치 명령을 VPS에서 30분 안에 실행한다. `--existing NAME`은 손으로 넣어 이미 가입한 서버에 기록만 묶는다.
- `--near-limit`: 공급자는 월 대역폭을 다 쓰면 그달 끝까지 10 Mbps로 느리게 한다. 그 전에 `exclude`(기본)는 그 서버를 DNS와 라우팅 대상에서 잠시 빼고, `low-weight`는 그 서버 backend에 다른 backend의 1/16 몫만 보낸다. `exclude`여도 route에 다른 backend가 없으면 빼지 않고 작은 몫을 남긴다. 다음 달이 되면 되돌린다.
- 남은 구독 기간만 보여 주고, 갱신과 결제는 Hostinger 패널에서 한다. 금액은 공급자 통화 그대로다.
- `detach`는 언제든 할 수 있다. 가입한 서버는 `sfcli node drain NAME`, `sfcli node remove NAME`으로 따로 뺀다.
