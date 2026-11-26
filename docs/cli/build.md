# mydc build: 이미지 빌드

빌드는 세 단계다.

1. **정책** 한 번: 작업 공간의 빌드가 어느 서버에서, 얼마의 CPU·메모리·공간으로, 어느 registry로 올라가는지 정한다.
2. **컨텍스트**: 빌드할 파일이 어디서 오는지 정한다. ZIP 올리기(`upload`), Git 저장소(`git`), 여기서 고치는 초안(`draft`) 셋 중 하나다. 파일 묶음을 저장할 때마다 번호가 붙은 **버전**이 하나 생긴다.
3. **빌드**: 컨텍스트의 버전 하나로 이미지를 만든다.

```sh
mydc build policy set -f build-policy.yaml
mydc build context create web -f build-context.yaml
mydc build context upload web web.zip
mydc build run web --logs
```

## 정책

| 명령 | 하는 일 |
|---|---|
| `mydc build policy show` | 지금 정책. `-o yaml`은 아래 파일 모양으로 출력한다 |
| `mydc build policy set -f build-policy.yaml` | 정책을 정하거나 바꾼다(바꿀 때는 묻는다) |

```yaml
# build-policy.yaml
version: 1
nodes: {node-a: data}        # 빌드 서버: 그 서버의 저장 경로(mydc node storage)
concurrency: 2               # 동시에 도는 빌드 수 (1-32)
timeout: 30m                 # 빌드 하나의 최대 시간 (최대 24h)
cpu: 2
memory: 4GiB
workspace: 10GiB             # 컨텍스트 하나를 펼친 최대 크기
cache: 20GiB                 # 서버별 빌드 캐시 목표 크기
registry: shop-registry      # 만든 이미지를 올릴 내장 registry
platforms: [linux/amd64]
builder_image: registry.example/moby/buildkit:v0.35.1-rootless   # digest로 고정해 저장한다
cleanup: {high_water_percent: 80, unused_days: 14}
```

- `builder_image`는 rootless BuildKit v0.35.1 이미지여야 한다. 서버는 이 이미지를 받아 오지 않는다. 빌드 서버마다 Docker에 미리 받아 둔다. `policy set`은 정책의 빌드 서버마다 그 이미지가 있는지 보고, 없는 서버 이름을 말하며 거절한다. 서버 이미지 목록은 시스템 관리자만 읽을 수 있어서, 다른 사용자가 하면 확인하지 못했다고 알리고 그대로 진행한다. 이름에 digest가 없으면 `policy set`이 지금 digest로 고정하는데, 그 registry를 작업 공간이 믿어야 한다(`mydc tenant trust add`).
- 빌드 서버의 저장 경로는 `mydc node storage`의 `--max-volumes` 한도를 볼륨과 함께 쓴다. 컨텍스트 버전 하나, 컨텍스트마다의 캐시 하나, 돌고 있는 빌드 하나가 각각 한 칸이다.

## 컨텍스트와 버전

| 명령 | 하는 일 |
|---|---|
| `mydc build context list` · `show CONTEXT` | 목록과 설정. `show -o yaml`은 build-context.yaml 모양 |
| `mydc build context create CONTEXT -f build-context.yaml` | 컨텍스트를 만들거나 설정을 바꾼다(바꿀 때는 묻는다) |
| `mydc build context delete CONTEXT` | 컨텍스트를 지운다. 버전이 남아 있으면 먼저 `--version`으로 지운다 |
| `mydc build context delete CONTEXT --version N` | 버전 하나를 지운다. 그 버전으로 만든 빌드가 남아 있으면 먼저 `mydc build delete`로 지운다 |
| `mydc build context upload CONTEXT FILE.zip` | upload 컨텍스트: ZIP(최대 500MB)을 새 버전으로 올린다 |
| `mydc build context upload CONTEXT` | git 컨텍스트: 설정한 ref의 지금 commit을 새 버전으로 저장한다 |
| `mydc build context check CONTEXT` | git 컨텍스트의 저장소를 읽을 수 있는지, Dockerfile과 FROM 이미지가 괜찮은지 본다. 실패하면 종료 코드 3 |
| `mydc build context versions CONTEXT` | 남아 있는 버전, 최신부터 |
| `mydc build context ls CONTEXT [--version N]` | 버전의 파일 목록(기본 최신 버전) |
| `mydc build context cat CONTEXT PATH [--version N] [-O FILE]` | 버전의 파일 하나 |

```yaml
# build-context.yaml
version: 1
kind: git                    # upload, git, draft
node: node-a                 # 정책의 빌드 서버 중 하나
dockerfile: Dockerfile       # 기본 Dockerfile
args: {NODE_ENV: production}
secrets:                     # 빌드 중에 RUN --mount=type=secret,id=npm 으로 읽는다
  - {id: npm, realm: shop, secret: npm-token, key: token}
repository: shop/web         # 정책 registry 안의 repository
tags: [latest]
platforms: [linux/amd64]     # 기본은 정책의 platforms
git:                         # kind git에만
  repository: https://git.example/shop/web.git
  ref: main
  path: web                  # 저장소 안의 하위 경로
  credential_profile: git-read
  automatic: true            # 새 commit이 보이면 버전을 저장하고 빌드한다
```

컨텍스트 이름은 처음 정한 `kind`와 서버(저장 경로)를 지운 뒤에도 그대로 가진다. 둘 중 하나를 바꾸려면 새 이름으로 만든다.

ZIP 올리기가 중간에 끊기면 같은 명령을 같은 `--id`로 다시 실행하거나 `mydc op resume ID`로 이어 보낸다. 이미 받은 조각은 다시 보내지 않는다.

## 초안(draft)

kind draft 컨텍스트는 파일을 서버에서 바로 고친 뒤 얼려(freeze) 버전으로 저장한다.

| 명령 | 하는 일 |
|---|---|
| `mydc build draft ls CONTEXT` | 초안의 파일 목록과 지금 revision |
| `mydc build draft cat CONTEXT PATH [-O FILE]` | 파일 하나 |
| `mydc build draft put CONTEXT PATH [LOCAL-FILE] [--executable]` | 파일을 쓴다. LOCAL-FILE이 없으면 여기의 PATH 파일 |
| `mydc build draft rm CONTEXT PATH` | 파일이나 디렉터리를 지운다 |
| `mydc build draft mv CONTEXT PATH NEW-PATH` | 옮긴다 |
| `mydc build draft freeze CONTEXT` | 지금 파일들을 새 버전으로 저장한다 |

편집(`put`·`rm`·`mv`)은 작업 기록에 남지 않는 바로 끝나는 호출이다. 같은 `--id`로 다시 하면 한 번만 적용된다. 큰 파일의 `put`이 끊기면 같은 `--id`로 다시 실행하면 남은 조각만 보낸다. `--if-revision N`은 초안이 아직 그 revision일 때만 바꾼다.

## 빌드

| 명령 | 하는 일 |
|---|---|
| `mydc build run CONTEXT [VERSION] [--logs] [--no-wait] [--group-password-fd REALM/GROUP=FD ...]` | 버전(기본 최신) 하나를 빌드하고 끝날 때까지 기다린다. 빌드 이름은 작업 ID다. 보호된 Vault 비밀을 쓰면 Group 비밀번호를 터미널에서 묻거나 `--group-password-fd`로 읽는다 |
| `mydc build list [CONTEXT]` | 빌드 목록, 최신부터 |
| `mydc build show BUILD` | 빌드 하나의 상태와 결과 이미지 |
| `mydc build logs BUILD [-f] [--tail]` | 빌드 출력. `-f`는 끝날 때까지 계속 읽는다. 실패한 빌드는 실패한 단계를 `# failed 단계 (exit code N)`로 보여 주고, 그 단계의 출력이 바로 위에 있다. 서버 로그에는 고정 코드(`BUILD_FAILED` 등)만 남는다 |
| `mydc build cancel BUILD` | 대기 중이거나 도는 빌드를 취소한다 |
| `mydc build delete BUILD` | 끝난 빌드의 기록을 지운다 |

컨텍스트가 보호된 Vault 비밀을 쓰면 `run`이 그 Group 비밀번호를 묻는다. 기다리다 Ctrl-C를 누르면 기다리기만 멈춘다. 빌드는 서버에서 계속되고 `mydc build logs BUILD -f`나 `mydc op show BUILD`로 다시 본다.

## 빌드 캐시

| 명령 | 하는 일 |
|---|---|
| `mydc build cache list [CONTEXT] [--node NODE]` | 서버·컨텍스트별 캐시와 크기 |
| `mydc build cache show CACHE --node NODE` | 캐시 하나의 항목 |
| `mydc build cache prune [CONTEXT] [--node NODE] [--cache CACHE] [--entry ID] [--unused-days N]` | 캐시를 비운다. 물어본 뒤 캐시마다 작업 하나를 보낸다(`ID-1`, `ID-2`, ...) |

## 종료 코드

0 성공, 1 실패(빌드 실패 포함), 2 잘못된 명령줄, 3 `context check` 실패, 4 결과를 아직 모름(`mydc op show ID`로 확인).

서버 쪽 동작(버전이 어떻게 만들어지고 지켜지는지, 빌드가 어떤 자격으로 이미지를 받고 올리는지)은 [빌드 컨텍스트](../reference/image-build-contexts.md)와 [빌드 작업](../reference/image-build-jobs.md)에 있다.
