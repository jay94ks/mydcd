# sfcli lifecycle: lifecycle 스크립트와 정책

lifecycle 스크립트는 앱 서비스가 이름으로 부르는 Go 프로그램이다(app.yaml의 `x-sfc` lifecycle). `script put`을 할 때마다 새 revision이 생기고, 앱은 배포할 때의 revision을 계속 쓴다. 모든 명령은 작업 공간이 필요하다.

| 명령 | 하는 일 |
|---|---|
| `sfcli lifecycle script list` | 스크립트 revision 목록. 상태는 active·retired·deleted |
| `sfcli lifecycle script show NAME [--revision N] [--source]` | revision 하나를 보여 준다. 기본은 가장 새 active revision. `--source`는 Go 원문을 출력한다 |
| `sfcli lifecycle script put NAME -f FILE.go [--modules modules.yaml] [--module PATH=FILE.zip]...` | 새 revision을 올린다. 모듈 ZIP이 서버에 없으면 `--module`로 함께 올린다 |
| `sfcli lifecycle script retire NAME --revision N` | 새 앱이 그 revision을 쓰지 못하게 한다. 실행 중인 앱은 계속 쓴다 |
| `sfcli lifecycle script delete NAME --revision N` | retire한 revision을 지운다 |
| `sfcli lifecycle policy show` | 작업 공간 정책을 lifecycle-policy.yaml 형식으로 출력한다 |
| `sfcli lifecycle policy set -f lifecycle-policy.yaml` | 정책을 바꾼다 |
| `sfcli lifecycle check FILE.go [--modules modules.yaml] [--node NODE]` | 서버에서 컴파일·타입 검사만 한다. 등록하지 않는다. 오류는 `파일:줄:열: 내용`으로 출력하고 종료 코드 3 |

바꾸는 명령은 `--id ID`와 `--if-revision N`을 받는다. `script put`을 같은 `--id`로 다시 실행하면 저장한 진행 상태에서 이어 간다. 이미 올린 원문과 ZIP은 다시 읽지 않는다.

## modules.yaml

스크립트가 import하는 모듈의 정확한 판이다.

```yaml
- path: example.invalid/safe
  version: v1.0.0
  sha256: 3b1f...  # 모듈 ZIP의 sha256, 64자 hex
  size: 1024       # ZIP 크기(바이트)
```

## lifecycle-policy.yaml

크기는 `512MiB`, 시간은 `30s`, CPU는 코어 수(`0.5`)로 쓴다. `policy show`의 출력을 고쳐 그대로 `policy set`에 넣을 수 있다.

```yaml
version: 1
enabled: true
execution:
  max_concurrent: 1
  timeout: 5s
  cpu: 0.1
  memory: 32MiB      # 16MiB 이상
  max_pids: 16
  output: 4KiB
  probe: 4KiB
  capabilities: [file]   # connect, dependency, exec, file, healthz
resolver:
  allow_packages: [context, github.com/jay94ks/seafield/lifecycle/v1]
  deny_packages: []
  modules: []        # modules.yaml과 같은 항목
  source_cache: 1MiB
# build는 스크립트를 서버에서 컴파일할 때만 쓴다. 쓰면 모든 값이 필요하다.
# build:
#   nodes: [node-a]
#   targets: [linux/amd64]
#   image: golang@sha256:...
#   toolchain: go1.24.0
#   max_jobs: 1
#   cpu: 1
#   memory: 256MiB
#   workspace: 64MiB
#   artifact: 16MiB
#   timeout: 1m
# compiled_cache: 64MiB   # build를 쓰면 artifact 이상
```
