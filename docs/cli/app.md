# app: app.yaml로 앱 배포하고 돌보기

앱은 tenant 하나에 배포한 app.yaml 하나다. 명령은 현재 context의 tenant(또는 `--tenant`)에서 일한다. `-f FILE`을 생략하면 이 디렉터리의 `app.yaml`(또는 `compose.yaml`)을 읽는다.

```sh
sfcli app check                         # 서버 없이 문법만 확인
sfcli app diff                          # 배포하면 무엇이 바뀌는지
sfcli app deploy                        # 배포하고 모든 서비스가 healthy가 될 때까지 기다림
sfcli app list
sfcli app show shop
sfcli app logs shop web -f
sfcli app exec shop web -i -t -- /bin/sh
sfcli app restart shop web
sfcli app down shop
```

## 배포와 내리기

| 명령 | 하는 일 |
|---|---|
| `app check [-f FILE]` | 서버에 보내지 않고 파일을 읽어 본다. `-o json`이면 정규화한 앱을 출력한다 |
| `app diff [-f FILE] [--save PLAN]` | 서버가 계획한 변경 목록. `--save`는 고정한 계획을 파일로 남긴다. ingress 규칙이 인증서 자동화 경로(`/.well-known/acme-challenge` 이하)를 쓰면 무시된다는 경고를 stderr에 쓴다([자세히](../reference/ingress-gateways.md#인증서-자동화-경로)) |
| `app deploy [-f FILE \| --plan PLAN] [--force]` | 계획하고 올리고 배포를 시작한 뒤 healthy까지 기다린다. `--plan`은 `diff --save`로 남긴 계획을 그대로 배포한다. 자동화 경로 경고는 diff와 같다. 같은 작업 공간의 다른 앱이 같은 서버·게이트웨이에서 쓰는 host+prefix면 `INGRESS_ROUTE_TAKEN`으로 멈추고, `--force`면 두 앱이 함께 받는다(`--plan`에는 `diff --save --force`로 준다, [게이트웨이](../reference/ingress-gateways.md)). Git을 따르는 앱이면 파일의 `x-sfc.cd`로 정책만 바꾸거나, 블록이 없으면 확인 뒤 CD를 끈다([cd](cd.md#appyaml-x-sfccd)) |
| `app down APP` | 앱의 컨테이너를 모두 멈추고 지운다(확인 질문). 다 지워질 때까지 기다린다 |
| `app archive APP [--store NAME] [--no-compress]` | 내린 앱의 볼륨을 모두 압축·봉인해 보관하고 비운다. 되살리기는 `volume unarchive`. [볼륨 보관](volume.md#내린-앱의-볼륨-보관하기) |
| `app resend APP [STEP]` | 배포가 `unknown`이면, 보냈지만 도착했는지 모르는 단계를 한 번 더 보낸다(확인 질문). 같은 명령이라 이미 도착했으면 두 번 적용되지 않는다. 그런 단계가 하나면 STEP을 빼도 된다 |
| `app list` | tenant의 앱 목록 |
| `app show APP` | 배포 상태, health, 마지막 작업, CD |
| `app history APP [--after CURSOR]` | 배포한 버전 목록(최근 것부터) |
| `app source APP [--revision N] [--section S]` | 서버가 보관한 그 버전의 app.yaml 원문 |

`deploy`와 `down`은 시작할 때 작업 ID를 보여 주고 `sfcli op` 목록에 적는다.

- `--no-wait`: 서버가 받기만 하면 돌아온다.
- `--wait-timeout 15m`: 기다리는 시간. 넘기면 종료 코드 4로 돌아오지만 배포는 계속된다.
- Ctrl-C는 기다리기만 멈추고 배포를 멈추지 않는다.
- 끊긴 작업은 `sfcli op show ID`로 확인하고 `sfcli op resume ID`로 같은 작업을 이어 간다. 새 배포를 보내지 않는다.
- `--id ID`로 ID를 직접 정할 수 있다. 같은 ID로 다시 실행하면 새로 보내지 않고 그 작업을 이어 가거나 결과를 보여 준다.
- 비밀번호가 걸린 Group의 승인이 필요하면 터미널에서 묻는다. 스크립트는 `--group-password-fd REALM/GROUP=FD`로 열린 파일 서술자에서 읽게 한다. 둘 다 없거나 `SFC_NONINTERACTIVE=1`이면 묻지 않고 실패한다.
- 배포의 한 단계를 보낸 직후 leader가 바뀌면, 서버는 그 단계가 도착했는지 모르니 배포를 `unknown`으로 두고 스스로 다시 보내지 않는다. `sfcli op show ID`가 그 단계를 "sent but unknown"으로 보여 주면 `sfcli app resend APP`로 같은 단계를 다시 보낸다. 이미 도착했던 단계는 결과만 거둬들인다.
- 서버가 배포의 한 단계를 거절하면 어느 단계를 왜 거절했는지 보여 주고 종료 코드 3으로 끝난다.
- 컨테이너는 0이 아닌 숫자 UID:GID로만 돈다. 이미지의 `USER`가 비어 있거나(root) 이름이면 서비스에 `user: "10001:10001"`처럼 적어야 한다. 그러지 않으면 그 서버가 이미지를 받은 뒤 Task를 만들지 않고, 배포는 `failed`로 끝난다. `sfcli op show ID`(또는 deploy 결과)는 "<task> on <server> cannot start: the image runs as root or a named user; ..."처럼 이유를 보여 준다. 이미지 실행 설정이 지원되지 않는 다른 경우도 같은 방식으로 `failed`가 된다(digest가 고정된 이미지와 같은 설정은 다시 시도해도 바뀌지 않는다). 고친 뒤 다시 배포한다.

### 웹 UI route (`cluster-app/web`)

웹 UI(sfc-web)로 가는 ingress route는 앱이 아니라 클러스터 설정이다. 시스템 관리자만 바꿀 수 있다. 파일의 `name`을 `cluster-app/web`으로 쓰고 `x-sfc.ingress`만 적는다. `services`, Volume, Secret, 망, CD, backend(망·포트·health 경로)는 적지 않는다. backend는 sfc-web 자신이고 고정이다.

```yaml
name: cluster-app/web
x-sfc:
  ingress:                  # 앱 ingress와 같은 route 목록
    - node: node-a          # 이 route를 여는 서버(모든 route가 같은 서버)
      host: sfc.example.com
      prefix: /             # 기본 /
      gateway: local        # external | local, 기본 external
```

수신 주소는 적지 않는다. route를 여는 서버의 gateways 설정에서 그 게이트웨이의 공유 수신 주소를 모두 쓴다. 요청·연결 한도도 적지 않고 고정 기본값을 쓴다.

- `sfcli app diff -f web.yaml`: 지금 설정과 무엇이 다른지 보여 준다. `--save`는 쓰지 않는다.
- `sfcli app deploy -f web.yaml`: 설정을 바꾼다. 확인 질문 뒤 바로 적용되며 기다리지 않는다.
- `sfcli app down cluster-app/web`: route를 지운다. 그 서버의 ingress가 진행 중인 요청을 마치고 닫는다.
- 같은 서버·수신 주소·게이트웨이에서 작업 공간 앱과 host가 같으면 prefix와 상관없이 거절한다. 반대로 작업 공간 앱도 이 route의 host를 쓸 수 없다. ingress는 같은 host에서 더 긴 prefix를 먼저 고르므로, 다른 앱이 `/api`만 가져가도 웹 UI 로그인이 그 앱으로 가기 때문이다.
- route를 바꾸면 옛 listener를 먼저 닫고 새것을 연다(잠깐 끊긴다). 웹 컨테이너 주소가 바뀌는 것만으로는 끊기지 않는다.

## 컨테이너

| 명령 | 하는 일 |
|---|---|
| `app logs APP CONTAINER` | [`sfcli logs --app APP --container CONTAINER`](logs.md)의 별칭. 마지막 200줄, `-f`는 Ctrl-C까지 새 줄을 계속 출력 |
| `app top APP SERVICE` | 프로세스 목록. `--watch [--interval 2s]`는 반복 |
| `app stats APP SERVICE` | CPU·메모리 사용. `--watch` |
| `app inspect APP SERVICE [--history N]` | 컨테이너 설정과 최근 수명 이벤트 |
| `app exec APP SERVICE [-i] [-t] -- COMMAND...` | 실행 중인 컨테이너에서 명령을 한 번 실행. 끊기면 다시 실행하지 않는다. 같은 `--id`로 다시 부르면 그 실행의 결과만 본다 |
| `app restart APP SERVICE` | 컨테이너를 제자리에서 다시 시작(확인 질문). 로그와 writable layer는 남는다 |
| `app clear-logs APP [SERVICE]` | 서버마다 보관한 로그를 지운다(확인 질문). SERVICE를 빼면 앱 전체. 컨테이너는 그대로 돈다. 지운 로그는 되살릴 수 없다 |

모든 컨테이너 명령은 `--instance TASK`로 서비스의 여러 Task 중 하나를 고르고, `--max-bytes N`으로 출력 크기를 줄인다. `-o json`은 logs·top·stats의 구조화된 결과를 준다. 자세한 동작은 [컨테이너 운영](../reference/container-operations.md)에 있다.

`restart`는 서버가 받으면 돌아오고, 진행은 `sfcli op show ID`로 본다. `clear-logs`는 작업 기록이 없는 요청 하나다. 서버마다 결과(`ok`, `denied`, `unreachable`, `unavailable`)와 지운 줄 수를 보여 주고, 지우지 못한 서버가 있으면 "N대 중 M대 지움"을 알리고 1로 끝난다. 같은 명령을 다시 실행하면 나머지 서버도 지운다.

## 종료 코드

| 코드 | 뜻 |
|---|---|
| 3 | 서버가 거절했다(권한, 충돌) |
| 4 | 결과를 아직 모른다. `sfcli op show ID`로 확인한다 |

`sfcli compose`는 `sfcli app`으로 바뀌었다. 옛 명령은 시험(tests/kvm)을 옮기는 마지막 정리 때까지 도움말 없이 남아 있다.
