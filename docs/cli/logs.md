# logs: 컨테이너 로그 읽기

`sfcli logs` 하나가 앱 컨테이너, 단독 컨테이너, 서버가 보관한 컨테이너 로그를 모두 읽는다. 읽을 대상은 옵션으로 고른다.

```sh
sfcli logs --app shop --container web -f             # 앱 shop의 web 컨테이너
sfcli logs --app shop --container web --instance workload/task/t/shop/web-2
sfcli logs --standalone debug                         # 단독 컨테이너
sfcli logs --node jay2 web --tail 500                 # jay2에서 도는 클러스터 앱 web
sfcli logs --node jay2 --container 3f9a2c             # jay2가 보관한 아무 컨테이너 로그(이름이나 ID 앞부분)
```

## 대상 고르기

| 옵션 | 읽는 것 | 권한 |
|---|---|---|
| `--app APP --container CONTAINER [--instance TASK]` | 앱의 컨테이너. 둘 다 써야 한다. `--instance`는 같은 컨테이너가 여럿일 때 하나를 고른다 | 작업 공간 읽기 |
| `--standalone NAME` | 단독 컨테이너 | 작업 공간 읽기 |
| `--node NODE NAME` | 그 서버에서 도는 클러스터 앱(예: `web`) | 시스템 관리자 |
| `--node NODE --container CONTAINER` | 그 서버의 sfcd가 보관한 컨테이너 로그. 컨테이너 이름, 전체 ID, 4자 이상의 ID 앞부분 | 시스템 관리자 |

- `--container`만으로는 앱 컨테이너를 고르지 않는다. `--app`이나 `--node`와 함께 쓴다.
- `--node`는 그 서버의 sfcd가 보관한 로그를 읽는다. 그래서 이미 없어진 컨테이너의 로그도 남아 있는 동안 읽을 수 있다. 서버에 docker CLI가 없어도 된다.
- 같은 이름이 여러 세대에 있으면(클러스터 앱을 다시 만든 경우) 마지막 줄이 가장 최근인 로그를 읽는다. ID 앞부분이 로그 여럿에 맞으면 종료 코드 1로 실패하니 ID를 더 길게 준다.

## 공통 옵션

| 옵션 | 하는 일 |
|---|---|
| `-f` | Ctrl-C까지 새 줄을 계속 출력 |
| `--tail N` | 마지막 N줄(1–10000, 기본 200) |
| `--since TIME`, `--until TIME` | RFC3339 시각 범위. `-f`와 `--until`은 함께 쓸 수 없다 |
| `--timestamps` | 줄마다 시각을 붙인다 |
| `--stdout`, `--stderr` | 한쪽만. 둘 다 빼면 둘 다 |
| `--max-bytes N` | 최대 N바이트까지 출력. 남은 줄이 있으면 이어 읽을 `--cursor`를 stderr에 알려 준다 |
| `--cursor CURSOR` | 앞선 읽기가 알려 준 곳부터 이어 읽는다 |

표 출력에서 표준 오류 줄은 stderr로, 표준 출력 줄은 stdout으로 나간다. `-o json`은 `--node`에서 받은 쪽(page)마다 JSON 한 줄을 쓴다(`Lines`, 이어 읽을 `Next`). `-o yaml`은 `-f`와 함께 쓸 수 없다.

## 별칭

아래 명령은 인자를 위 옵션으로 바꿔 `sfcli logs`와 똑같이 동작한다.

| 별칭 | 같은 명령 |
|---|---|
| `sfcli app logs APP CONTAINER [--instance TASK]` | `sfcli logs --app APP --container CONTAINER` |
| `sfcli standalone logs NAME` | `sfcli logs --standalone NAME` |
| `sfcli node logs NODE NAME` | `sfcli logs --node NODE NAME` |
| `sfcli node logs NODE --container CONTAINER` | `sfcli logs --node NODE --container CONTAINER` |
