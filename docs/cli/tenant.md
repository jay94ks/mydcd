# mydc tenant: 작업 공간

작업 공간(tenant)과 그 구성원, 쓸 수 있는 서버, 서버별 한도를 다룬다. 만들기·지우기·서버 지정·한도는 시스템 관리자만 한다.

| 명령 | 하는 일 |
|---|---|
| `mydc tenant list` | 내가 속한 작업 공간 목록(시스템 관리자는 전부) |
| `mydc tenant show TENANT` | 상태, 쓸 수 있는 서버, 구성원 |
| `mydc tenant status TENANT` | 작업 공간 기록(단계·revision·신뢰 규칙)과, 지우는 중이면 남은 자원과 닫은 서버 수(시스템 관리자) |
| `mydc tenant create TENANT [--nodes a,b]` | 작업 공간을 만들고 쓸 서버를 정한다 |
| `mydc tenant set TENANT --nodes a,b` | 쓸 수 있는 서버 목록을 통째로 바꾼다(빈 값이면 없음) |
| `mydc tenant delete TENANT [--no-wait]` | 종료 절차 전체: 새 작업을 막고, 남은 자원이 없어지고 서버가 닫았다고 알리면 끝낸다 |
| `mydc tenant members [TENANT]` | 구성원과 역할 |
| `mydc tenant member set TENANT USER --role manager\|viewer` | 구성원을 더하거나 역할을 바꾼다 |
| `mydc tenant member remove TENANT USER` | 구성원을 뺀다 |
| `mydc tenant resources [TENANT] [--all]` | 한도, 망, route. `--all`은 모든 작업 공간과 서버 전체 한도(시스템 관리자). `-o json`은 `{tenant, network_revision, quota_revision, items}`이고 두 revision은 망·한도 변경이 확인하는 값이다 |
| `mydc tenant quota set TENANT NODE --cpu 1.5 --memory 4GiB [--consumers N] [--packet-queue N --packet-queue-bytes SIZE]` | 그 서버에서 쓸 CPU 코어 수와 메모리. `--consumers`는 관리 망·DNS에 붙을 수 있는 컨테이너 수, `--packet-queue`·`--packet-queue-bytes`는 TUN 망 하나에 쌓아 둘 수 있는 패킷 수와 크기(모두 서버 한도 이하) |
| `mydc tenant trust list TENANT` | 이 작업 공간의 컨테이너가 이미지를 받아도 되는 곳(신뢰 규칙) |
| `mydc tenant trust add\|remove TENANT REGISTRY/REPOSITORY` | 신뢰 규칙을 더하거나 뺀다. `REGISTRY/**`는 그 registry의 모든 저장소 |

TENANT를 생략할 수 있는 명령은 `--tenant`나 context의 작업 공간을 쓴다. 이름은 소문자로 시작하고 a-z·0-9·`-`로 63자까지다.

## 지우기

`tenant delete`는 아무것도 대신 지우지 않는다. 남은 앱·망·registry·volume·백업을 나열하며 기다린다. 각자의 명령으로 지우면 이어서 진행한다. `--no-wait`이나 Ctrl-C로 멈추면 `mydc op resume ID`로 끝낸다. `mydc op show ID`는 진행 상태만 묻고 아무것도 보내지 않는다.

## 한도

`quota set`은 서버 전체 한도([`mydc node quota set`](node.md#서버-전체-한도)로 정함) 안에서만 정할 수 있다. 처음 정할 때 망 수·연결 수 같은 다른 한도는 서버 전체 한도를 따르고, 바꿀 때는 지금 값을 유지한다. 연결 수는 `--consumers`로, 패킷 큐는 `--packet-queue`와 `--packet-queue-bytes`를 함께 줘서 바꾼다. 연결 수가 0이면 그 서버에서 앱 컨테이너가 시작되지 않고 배포가 planned에 머문다. 패킷 큐가 0이거나 TUN 패킷 하나(망 MTU + 120바이트)보다 작아도 TUN 망을 쓰는 앱은 planned에 머문다. 이때 `mydc op show`가 그 이유를 알려 준다.

## 이미지 신뢰

앱의 이미지는 작업 공간의 신뢰 규칙 하나와 맞아야 한다. 맞는 규칙이 없으면 `app diff`·`app deploy`가 `IMAGE_NOT_TRUSTED`(경로 `services.NAME.image`)로 거절된다. 새 작업 공간은 `docker.io/**`로 시작한다. 규칙을 바꾸는 것은 작업 공간의 신뢰 관리 권한(시스템 관리자 포함)이 있어야 한다.

## 동시 변경

바꾸는 명령은 지금 revision을 읽고 그 값으로 보낸다. 다른 사람이 먼저 바꾸면 거절된다. `--if-revision N`은 그 revision일 때만 바꾼다(새로 만들 때 0).
