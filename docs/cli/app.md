# app: app.yaml로 앱 배포하고 돌보기

앱은 tenant 하나에 배포한 app.yaml 하나다. 명령은 현재 context의 tenant(또는 `--tenant`)에서 일한다. `-f FILE`을 생략하면 이 디렉터리의 `app.yaml`(또는 `compose.yaml`)을 읽는다.

```sh
mydc app check                         # 서버 없이 문법만 확인
mydc app diff                          # 배포하면 무엇이 바뀌는지
mydc app deploy                        # 배포하고 모든 서비스가 healthy가 될 때까지 기다림
mydc app list
mydc app show shop
mydc app logs shop web -f
mydc app exec shop web -i -t -- /bin/sh
mydc app restart shop web
mydc app down shop
```

## 배포와 내리기

| 명령 | 하는 일 |
|---|---|
| `app check [-f FILE]` | 서버에 보내지 않고 파일을 읽어 본다. `-o json`이면 정규화한 앱을 출력한다 |
| `app diff [-f FILE] [--save PLAN]` | 서버가 계획한 변경 목록. `--save`는 고정한 계획을 파일로 남긴다. ingress 규칙이 인증서 자동화 경로(`/.well-known/acme-challenge` 이하)를 쓰면 무시된다는 경고를 stderr에 쓴다([자세히](../reference/ingress-gateways.md#인증서-자동화-경로)) |
| `app deploy [-f FILE \| --plan PLAN]` | 계획하고 올리고 배포를 시작한 뒤 healthy까지 기다린다. `--plan`은 `diff --save`로 남긴 계획을 그대로 배포한다. 자동화 경로 경고는 diff와 같다 |
| `app down APP` | 앱의 컨테이너를 모두 멈추고 지운다(확인 질문). 다 지워질 때까지 기다린다 |
| `app list` | tenant의 앱 목록 |
| `app show APP` | 배포 상태, health, 마지막 작업, CD |
| `app history APP [--after CURSOR]` | 배포한 버전 목록(최근 것부터) |
| `app source APP [--revision N] [--section S]` | 서버가 보관한 그 버전의 app.yaml 원문 |

`deploy`와 `down`은 시작할 때 작업 ID를 보여 주고 `mydc op` 목록에 적는다.

- `--no-wait`: 서버가 받기만 하면 돌아온다.
- `--wait-timeout 15m`: 기다리는 시간. 넘기면 종료 코드 4로 돌아오지만 배포는 계속된다.
- Ctrl-C는 기다리기만 멈추고 배포를 멈추지 않는다.
- 끊긴 작업은 `mydc op show ID`로 확인하고 `mydc op resume ID`로 같은 작업을 이어 간다. 새 배포를 보내지 않는다.
- `--id ID`로 ID를 직접 정할 수 있다. 같은 ID로 다시 실행하면 새로 보내지 않고 그 작업을 이어 가거나 결과를 보여 준다.
- 비밀번호가 걸린 Group의 승인이 필요하면 터미널에서 묻는다. 스크립트는 `--group-password-fd REALM/GROUP=FD`로 열린 파일 서술자에서 읽게 한다. 둘 다 없거나 `MYDC_NONINTERACTIVE=1`이면 묻지 않고 실패한다.
- 서버가 배포의 한 단계를 거절하면 어느 단계를 왜 거절했는지 보여 주고 종료 코드 3으로 끝난다.

## 컨테이너

| 명령 | 하는 일 |
|---|---|
| `app logs APP SERVICE` | 마지막 200줄. `-f`는 Ctrl-C까지 새 줄을 계속 출력. `--tail N`, `--since`, `--until`, `--timestamps`, `--stdout`, `--stderr`, `--cursor` |
| `app top APP SERVICE` | 프로세스 목록. `--watch [--interval 2s]`는 반복 |
| `app stats APP SERVICE` | CPU·메모리 사용. `--watch` |
| `app inspect APP SERVICE [--history N]` | 컨테이너 설정과 최근 수명 이벤트 |
| `app exec APP SERVICE [-i] [-t] -- COMMAND...` | 실행 중인 컨테이너에서 명령을 한 번 실행. 끊기면 다시 실행하지 않는다. 같은 `--id`로 다시 부르면 그 실행의 결과만 본다 |
| `app restart APP SERVICE` | 컨테이너를 제자리에서 다시 시작(확인 질문). 로그와 writable layer는 남는다 |
| `app clear-logs APP SERVICE` | 컨테이너를 다시 만들어 로컬 로그를 지운다(확인 질문). 로컬 로그와 writable layer는 되살릴 수 없고 volume은 남는다 |

모든 컨테이너 명령은 `--instance TASK`로 서비스의 여러 Task 중 하나를 고르고, `--max-bytes N`으로 출력 크기를 줄인다. `-o json`은 logs·top·stats의 구조화된 결과를 준다. 자세한 동작은 [컨테이너 운영](../reference/container-operations.md)에 있다.

`restart`와 `clear-logs`는 서버가 받으면 돌아오고, 진행은 `mydc op show ID`로 본다.

## 종료 코드

| 코드 | 뜻 |
|---|---|
| 3 | 서버가 거절했다(권한, 충돌) |
| 4 | 결과를 아직 모른다. `mydc op show ID`로 확인한다 |

`mydc compose`는 `mydc app`으로 바뀌었다. 옛 명령은 시험(tests/kvm)을 옮기는 마지막 정리 때까지 도움말 없이 남아 있다.
