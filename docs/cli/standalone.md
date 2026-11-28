# sfcli standalone: 앱 밖의 단독 컨테이너

단독 컨테이너는 서비스 하나짜리 app.yaml로 띄우는 컨테이너 하나다. 앱이 아니라 작업 공간에 속하고, 앱 목록·`app down`·CD는 이것을 건드리지 않는다. 디버그 셸, 일회성 작업, 앱과 따로 두고 싶은 작은 서비스에 쓴다. 입력 규칙, 한도, 자동 정리는 [단독 컨테이너](../reference/standalone.md)에 있다.

모든 명령은 작업 공간이 필요하다(`--tenant` 또는 context의 작업 공간).

| 명령 | 하는 일 |
|---|---|
| `sfcli standalone run NAME -f app.yaml` | 계획하고 올린 뒤 컨테이너를 시작한다. `--dry-run`은 계획만 출력하고 아무것도 보내지 않는다 |
| `sfcli standalone list` | 작업 공간의 단독 컨테이너를 보여 준다 |
| `sfcli standalone show NAME` | 하나의 상태와 저장된 app.yaml을 보여 준다 |
| `sfcli standalone stop NAME` · `start NAME` · `restart NAME` | 컨테이너를 멈추거나(지우지 않음) 다시 시작하거나 그 자리에서 재시작한다. `--dry-run`은 대상만 보여 준다 |
| `sfcli standalone keep NAME [--name NEW] [--restart no\|on-failure\|always]` | 임시(temp)를 영구(fixed)로 바꾼다. 같은 컨테이너, 쓰기 계층, 자원 연결을 그대로 둔다 |
| `sfcli standalone extend NAME DURATION` | 임시의 만료를 지금부터 DURATION(예: `2h`) 뒤로 늦춘다. 만든 때부터 24시간을 넘길 수 없다 |
| `sfcli standalone remove NAME` | 지운다. 컨테이너와 쓰기 계층은 되돌릴 수 없다 |
| `sfcli standalone logs NAME [-f]` | 컨테이너 로그. [`sfcli logs --standalone NAME`](logs.md)의 별칭 |
| `sfcli standalone top NAME` · `stats NAME` · `inspect NAME` | 프로세스, 자원 사용량, 컨테이너 상세. `--watch`로 계속 본다 |
| `sfcli standalone exec NAME -- COMMAND [ARG...]` | 실행 중인 컨테이너에서 명령 하나를 실행한다. `-i` 입력 전달, `-t` 터미널 |
| `sfcli standalone attach NAME [-i] [-t]` | 주 프로세스(`--mode shell`이면 셸)에 붙는다. 끊어도 프로세스는 계속 돈다 |
| `sfcli standalone clear-logs NAME` | 서버마다 보관한 로그를 지운다(확인 질문). 컨테이너는 그대로 돈다. 결과는 [app clear-logs](app.md)와 같다 |

## run 옵션

| 옵션 | 뜻 |
|---|---|
| `--lifetime temp\|fixed` | 기본 `temp`. `temp`는 시간이 다 되거나 아무도 붙어 있지 않은 채 `--grace`가 지나면 지워진다. `fixed`는 시간 제한이 없다 |
| `--ttl D` | temp의 수명. 기본 `1h`, 최대 `24h` |
| `--grace D` | temp에 아무도 붙어 있지 않을 때 기다리는 시간. 기본 `10m` |
| `--restart no\|on-failure\|always` | fixed가 끝났을 때. 기본 `on-failure`. temp는 `no`만 된다 |
| `--mode entrypoint\|shell` | 기본 `entrypoint`(이미지의 명령). `shell`은 `attach`할 대화형 셸을 띄운다 |
| `--node SERVER` | 띄울 서버. 서비스의 `x-sfc.node`와 같다 |
| `--group-password-fd REALM/GROUP=FD` | 스크립트용. 승인할 Secret 그룹의 비밀번호를 열린 파일 서술자에서 읽는다(그룹마다 하나). 없으면 터미널에서 묻는다 |

시간은 `30s`, `10m`, `2h`처럼 초 단위로 끝나는 길이로 쓴다.

이미 있는 NAME을 새 `--id`로 다시 `run`하면 그 파일의 정의로 바꾼다. 컨테이너를 새로 만들므로 쓰기 계층과 로컬 로그는 새로 시작하고 볼륨 데이터는 남는다.

## 작업 ID와 재개

바꾸는 명령은 모두 `--id ID`를 받는다(주지 않으면 새 ID를 만들어 알려 준다). 같은 `--id`로 다시 실행하면 지금 상태를 다시 읽지 않고 저장해 둔 같은 요청을 이어 보낸다. `run`은 올리기와 시작을 이어 가고, 이미 결과가 있으면 그 결과를 보여 준다. `sfcli op show ID`와 `sfcli op resume ID`도 같다([op](op.md)).

- `run`, `stop`, `start`, `restart`는 서버가 받은 뒤 서버(노드)가 실제로 한다. 명령은 받은 것까지 보고하고(`accepted`), `sfcli op show ID`가 끝났는지 알려 준다.
- `extend`의 `-o json` 결과 `extension`에는 서버가 서명한 시각 계산(`At`, `ProposedExpiresAt`, `MaximumExpiresAt`, `AllowedTTLSeconds`, `RemainingExtensionSeconds`)이 있다. 거절되면 `extension_applied`가 `false`이고, 그 시각에 줄 수 있었던 최대 길이가 `AllowedTTLSeconds`에 있다.
- `clear-logs`는 `--id`를 받지 않고 작업 기록도 남기지 않는다. 같은 명령을 다시 보내면 된다.
- `exec`와 `attach`는 작업 기록을 남기지 않는다. 연결이 끊기면 명령을 다시 시작하지 않는다. 같은 `--id`로 `exec`를 다시 실행하면 처음 실행의 결과를 보여 준다.

## 종료 코드

0 성공, 1 실패(서버가 거절), 2 잘못된 명령줄, 3 대상이 없거나 지금 그 일을 할 수 없음(예: fixed나 정리 중인 것을 `extend`), 4 결과를 아직 모름.
