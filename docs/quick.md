# Quick-start

이 가이드는 새 Seafield Cluster 클러스터 생성부터 노드 추가·제거까지 설명한다. **첫 노드를 단일 노드 클러스터로 초기화하고, 나머지 노드를 가입·승격하여 확장한다.** 새 노드마다 별도 클러스터를 초기화하지 않는다.

## 준비

- Linux 머신에 같은 버전의 `sfcli`, `sfcd`를 준비하고 PATH에 둔다. 소스 빌드는 [CLI·설정](configuration/cli.md)을 따른다.
- 각 노드는 고유 ID·개인키·영속 상태 디렉터리를 사용한다. 아래 명령은 노드 설정/상태 경로를 만들 수 있는 관리자 권한으로 실행한다. 원격 관리용 CLI의 wallet·프로필은 명령을 실행하는 Linux user의 `~/.sfc`에 저장된다.
- 노드끼리는 설정한 **UDP 7443**으로 양방향 통신할 수 있어야 한다. SFCP는 QUIC를 사용한다. 로컬 관리는 기본 `unix:///run/sfcdp.sock`이며 TLS/사용자 인증도 수행한다. 소켓은0600이므로 해당 소켓에 접근 가능한 사용자로 로컬 CLI를 실행한다.
- 이 가이드에서는 제어 클러스터를 먼저 구성하기 위해 network/workload/ingress를 비활성화한다. 앱을 배포하려면 Docker Engine, 모듈 활성화, 노드/tenant 예산과 이름 있는 망·Volume 등의 준비가 추가로 필요하다.

3대 예시는 다음 주소를 사용한다. 실제 네트워크에 맞게 바꾸며 `listen`에는 다른 노드가 접근할 수 있는 해당 머신의 주소를 쓴다. 부팅 직후 DHCP가 아직 그 주소를 붙이지 않았으면 sfcd는 주소가 붙을 때까지 기다렸다가 연다.

| 노드 | 주소 | SFCP 끝점 |
|---|---|---|
| node-a | 192.168.10.11 | 192.168.10.11:7443 |
| node-b | 192.168.10.12 | 192.168.10.12:7443 |
| node-c | 192.168.10.13 | 192.168.10.13:7443 |

`<...>` 표시는 출력에서 읽은 실제 값으로 바꾼다. 클러스터 ID와 공개키 HEX는 소문자64자리다. 요청 ID는 작업마다 고유하게 정하고, 중단 후 같은 작업을 확인할 때는 원 ID를 유지한다.

## 1. 단일 노드 클러스터 구축

### 1.1 최초 관리자 키와 노드 설정 준비

**node-a의 관리용 셸**에서 실행한다. `identity create`는 공개키 HEX를 출력하고 개인키는 지정 디렉터리의 `key.pem`에 저장한다. 관리자 키와 노드 키는 서로 다르다.

```sh
umask 077
install -d -m 0700 /etc/sfc /var/lib/sfc
sfcli identity create /etc/sfc/admin-identity
```

출력된 공개키를 보관한다. 다음 내용으로 `/etc/sfc/node.yaml`을 만든다.

```yaml
version: 1
node:
  id: node-a
  state_dir: /var/lib/sfc/state
  identity_dir: /var/lib/sfc/identity
  listen: "192.168.10.11:7443"
  management_socket: /run/sfcdp.sock
modules:
  network:
    enabled: false
  workload:
    enabled: false
  ingress:
    enabled: false
```

컨테이너를 실행할 서버는 `modules.network`와 `modules.workload`를 켠다. 컨테이너는 sfcd와 함께 설치되는 Seafield 엔진(sfed)이 실행하고, sfcd는 엔진을 항상 `/run/sfe/sfed.sock`에서 찾는다. node.yaml에 엔진 경로를 적는 설정은 없다. `sfcd check`와 `sfcd run`은 엔진에 닿지 못하면 이유를 말하고 멈춘다.

```yaml
modules:
  network:
    enabled: true
  workload:
    enabled: true
```

새 설치에는 정적 `common.peers`, `common.cluster`, `common.admin`, `node.bootstrap`을 추가하지 않는다. init이 클러스터 ID와 최초 노드 신원·설치를 생성한다. 설치 템플릿은 [node.managed.example.yaml](../configs/node.managed.example.yaml)을 참고한다.

### 1.2 빈 클러스터 초기화와 데몬 실행

```sh
sfcd --config /etc/sfc/node.yaml check
sfcd --config /etc/sfc/node.yaml init \
  --admin-public-key <최초_관리자_공개키_HEX> \
  --request-id init-node-a \
  --client-config-out /etc/sfc/initial-client.yaml
```

init 출력의 `cluster`, `node_key`, `endpoint`를 보관한다. 기대 상태는 `standalone: true`, `voters: 1`, `quorum: 1`, `users: 0`, `tenants: 0`과 `AwaitingAdminEnrollment`다. **운영 계정·tenant·망·앱은 자동 생성되지 않는다.** `initial-client.yaml`은 공개 pin을 포함한 client 설정이며 실제 계정 등록/로그인을 대신하지 않는다.

이후 **node-a의 별도 데몬 터미널**에서 같은 설정으로 실행하고 유지한다.

```sh
sfcd --config /etc/sfc/node.yaml run
```

init은 초기화를 마치고 종료하는 명령이다. run이 계속 실행되어야 관리 연결을 받을 수 있다. 재기동할 때도 같은 설정·신원·DB로 run하며, 새 init이나 상태 디렉터리 삭제로 복구하지 않는다.

### 1.3 관리 CLI 등록·최초 계정 등록·로그인

**관리용 셸**에서 관리자 키를 wallet에 넣고 접속할 context를 만든다. 첫 키를 넣을 때 wallet을 만들며 새 비밀번호를 두 번 묻는다.

```sh
sfcli key import cluster-admin /etc/sfc/admin-identity/key.pem
sfcli context add lab --user admin --wallet-key cluster-admin
```

endpoint를 생략했으므로 로컬 Unix 소켓을 사용한다. 노드 키 확인에서는 **1.2에서 보관한 cluster ID와 node_key를 대조**한 뒤 승인한다. 다른 관리 머신에서는 아래처럼 접근 가능한 노드 주소로 등록한다.

```sh
sfcli context add lab sfcp://192.168.10.11:7443 --user admin --wallet-key cluster-admin
```

두 등록 명령은 대체 방법이다. 같은 이름으로 중복 실행하지 않는다. 별도 관리 머신을 쓰면 관리자 키도 그 머신의 wallet에 안전하게 준비한다.

```sh
sfcli enroll admin --key cluster-admin
sfcli login
sfcli whoami
sfcli node list
```

최초 등록에는 init에 지정한 관리자 공개키에 대응하는 개인키를 사용한다. `whoami`에서 system admin 계정, `node list`에서 node-a와 `voters: 1`, `quorum: 1`을 확인하면 제어 클러스터 구성이 끝난다. tenant가 없는 상태에서도 system admin의 node 관리는 가능하다.

## 2. 다중 노드 클러스터 구축 — 3대

**1절을 node-a에서 먼저 완료한다.** node-b와 node-c는 init하지 않고 기존 클러스터에 순서대로 가입한다.

### 2.1 node-b 설정과 공개키 준비

**node-b**에서 다음 내용을 `/etc/sfc/node.yaml`로 저장한다. 준비 디렉터리와 키는 아래 명령으로 만든다.

```sh
umask 077
install -d -m 0700 /etc/sfc /var/lib/sfc
sfcli identity create /var/lib/sfc/identity
```

```yaml
version: 1
node:
  id: node-b
  state_dir: /var/lib/sfc/state
  identity_dir: /var/lib/sfc/identity
  listen: "192.168.10.12:7443"
  management_socket: /run/sfcdp.sock
modules:
  network:
    enabled: false
  workload:
    enabled: false
  ingress:
    enabled: false
```

출력된 **node-b의 공개키 HEX**를 관리자에게 전달한다. 개인키는 node-b에 그대로 둔다.

### 2.2 기존 클러스터에서 가입 승인

**관리용 셸**에서 실행한다. node add는 기존 클러스터에 가입 대상을 승인하는 관리 변경이며 실제 새 노드 실행은 아니다.

```sh
sfcli node add node-b --endpoint 192.168.10.12:7443 --public-key <NODE_B_공개키_HEX>
sfcli node show node-b
sfcli node invite node-b --out node-b.invitation.json
```

만든 초대 파일을 node-b의 `/etc/sfc/node-b.invitation.json`으로 전달한다. 초대의 대상 ID·키·endpoint와 실제 node-b 설정을 대조한다. `Source.Key`는 초대에 서명한 기존 control의 공개키 HEX이며, 기존에 신뢰한 노드 키와 별도 경로로 대조한다. `<SOURCE_공개키_HEX>`에 임의의 다른 control 키를 넣지 않는다.

### 2.3 node-b 가입·운영·승격

**node-b**에서 실행한다. `<CLUSTER_ID_HEX>`는 1.2의 init 출력 값이다.

```sh
sfcd --config /etc/sfc/node.yaml join \
  --cluster <CLUSTER_ID_HEX> \
  --source-public-key <SOURCE_공개키_HEX> \
  --invitation /etc/sfc/node-b.invitation.json
sfcd --config /etc/sfc/node.yaml run
```

join은 설치/동기화와 서명 ACK를 수행하고 종료한다. 성공 출력 `Joined`의 `voter: false`가 정상이다. 다음 run은 **node-b의 데몬 터미널에서 유지**한다.

**관리용 셸**에서 Ready/설치 ACK를 확인하고 해당 entry의 현재 revision으로 승격한다.

```sh
sfcli node list --all
sfcli node promote node-b
sfcli node list --all
```

`node list --all`의 MEMBER가 `ready`인 서버를 승격한다. 승격 뒤 MEMBER `active`, VOTER `yes`이고 `node list --all -o json`의 `voters: 2`, `quorum: 2`를 확인한다.

### 2.4 node-c도 같은 순서로 추가

2.1~2.3을 node-c에 반복하되 다음 값으로 바꾼다. node-c에서도 독립된 identity를 생성한다.

| 항목 | node-c 값 |
|---|---|
| node.id / node 명령의 대상 | node-c |
| listen / 승인 endpoint | 192.168.10.13:7443 |
| 공개키 | node-c에서 생성한 키 |
| 초대 파일 | node-c.invitation.json |

가입이 끝난 뒤 다음을 확인한다.

```sh
sfcli node list --all
```

- 세 서버가 모두 active voter다.
- 실제 `voters: 3`, `quorum: 2`다.
- 각 노드의 DB·신원·설치 초대/원 ID를 보존하고 sfcd run을 유지한다.

voter 수가2인 중간 단계에서는 두 노드가 모두 살아 있어야 관리 변경이 가능하다. 세 노드가 voter가 된 뒤에는1대 장애까지 과반수를 유지한다. 사용자 CLI가 다른 노드에도 접속해야 한다면 [`sfcli context trust`](cli/context.md)로 그 노드의 키를 확인해 등록한다. 노드 가입과 Linux user의 로컬 접속 프로필은 별개다.

## 3. 가동 중인 클러스터에 새 노드 추가

기존 클러스터를 중단하지 않고 **2.1~2.3의 절차**를 새 노드에 적용한다. 예를 들어 node-d의 끝점이 `192.168.10.14:7443`이면 다음과 같다.

1. 새 머신에 같은 제품을 준비하고, 고유 node-d ID·state/identity 경로·listen 주소로 managed 설정을 만든다. `sfcli identity create`로 키를 생성한다.
2. 기존 system admin이 현재 quorum과 node 목록을 확인한다.
3. 아래 명령으로 공개키·endpoint를 등록하고 초대를 전달한다.

```sh
sfcli node list --all
sfcli node add node-d --endpoint 192.168.10.14:7443 --public-key <NODE_D_공개키_HEX>
sfcli node invite node-d --out node-d.invitation.json
```

4. 새 머신에서 원 cluster ID·초대 서명 source key를 pin하여 `sfcd join`한 뒤 같은 설정으로 `run`한다.
5. 기존 관리자 셸에서 `node list --all`로 ready를 확인하고 `node promote node-d`를 실행한다.
6. 실제 voter/구성 index와 active 상태를 확인한다. node-d를 voter로 승격하지 않고 non-voter로 운영할 수도 있다. 이 경우 정족수에는 포함되지 않는다.

3→4 voter 확장은 quorum도2→3으로 바뀐다. 단순히 노드를 추가한다고 허용 장애 수가 늘지는 않는다. 관리 변경 quorum은 `floor(voters/2)+1`이다. 한 구성 변경이 정산된 뒤 다음 변경을 진행한다.

## 4. 가동 중인 클러스터에서 노드 제거

예시는 **node-c를 제거**한다. 제거 명령은 node-c가 아닌 **남을 노드에 연결한 system admin CLI**에서 수행한다. 앱이나 데이터가 있는 노드는 먼저 정상 정산할 수 있어야 하므로 대상 sfcd를 미리 끄지 않는다.

### 4.1 제거 전 확인

```sh
sfcli node list --all
sfcli node remove node-c --dry-run
```

`--dry-run`은 남는 voter와 quorum, 막는 이유를 보여 주고 아무것도 보내지 않는다. 현재 구성의 과반수가 가동 중인지 확인한다. 3대 중1대를 제거하려면 삭제 전 quorum인2대를 충족해야 하며, 2→1 제거에는 삭제 전 두 voter가 모두 필요하다. 마지막 member/voter는 일반 node remove로 제거할 수 없다. 응답하지 않는 노드를 삭제해서 잃은 quorum을 임의로 되살리는 절차가 아니다.

node-c의 앱·서비스·registry·망 참조·Volume 사용을 확인하고 각 자원의 명시 관리 작업으로 종료/이관·정산한다. node-fixed Volume은 이관하지 못하며 원 경로/데이터를 자동 삭제하지 않는다. node remove는 앱을 다른 노드로 자동 재배치하는 명령이 아니다. [자원 수명](architecture/resource-ownership.md)과 [종료·정산](algorithms/reconciliation.md)을 따른다.

### 4.2 제거

```sh
sfcli node cordon node-c
sfcli node drain node-c
sfcli node remove node-c
```

`remove`는 남는 voter와 막는 이유를 보여 주고 확인을 받은 뒤 보낸다. revision과 작업 ID는 CLI가 정한다. 끝날 때까지 진행을 보여 주며, Ctrl-C로 나가도 제거는 서버에서 계속된다. active 또는 isolated 노드에서 제거를 시작할 수 있다. 미정산 자원이나 불명 효과가 있으면 그 상태가 보존된다.

### 4.3 완료 확인과 대상 데몬 정지

`node show node-c`와 `node list --all`에서 다음을 확인한다.

- 대상 lifecycle `Node.Phase`가 `removed`, `Node.Pending`이 `null`이고 원 `Node.Closure`가 있다.
- 실제 구성 index가 갱신되고 voter 수가 예상대로 줄었다. 위3→2 예시는 `voters: 2`, `quorum: 2`다.
- `removing`·pending·native 불명 상태가 남아 있으면 완료로 판단하지 않는다. node 목록에 이력 entry가 남아 있는 것 자체는 실패가 아니다.

완료 후 대상 머신의 원 sfcd를 SIGINT/SIGTERM으로 정상 종료한다. 백그라운드 서비스로 운영했다면 해당 서비스 관리자를 사용한다. 데이터·DB·신원·원 초대/작업 기록은 보존한다. 더 이상 사용하지 않을 CLI 접속 pin은 별도 로컬 신뢰 관리로 정리한다. `sfcli cluster remove`는 Linux user의 로컬 등록을 제거하는 명령이며 실제 노드 제거 명령이 아니다.

### 중단·불명 결과 처리

끊기거나 응답을 못 받았으면 새 명령을 다시 보내지 않는다. 명령이 출력한 작업 ID로 묻고 이어 간다.

```sh
sfcli op show <작업_ID>
sfcli op resume <작업_ID>
```

제거를 시작한 관리자의 권한이 사라져 멈췄으면 `sfcli node renew node-c`로 지금 관리자가 같은 작업을 이어 간다. join 중단도 원 초대·Join ID·identity·DB를 유지하며, 기존 클러스터 가입 실패를 새 standalone init으로 대체하지 않는다.

## 5. 명령별 세부 사용법

이 절은 위 구축·가입·제거 절차에 쓰는 Seafield Cluster 명령과 관련 조회/복구 명령을 정리한다. `<값>`은 실제 값으로 대체하고 대괄호 `[...]`는 선택 인자이므로 입력할 때 제거한다. 전체 명령의 대상·권한은 [명령어 적용대상표](architecture/command-targets.md), 앱 배포 등 나머지 명령은 [CLI 설명](configuration/cli.md)을 참고한다.

### 5.1 공통 옵션과 입력 규칙

```text
sfcli [전역 옵션] 명령 [하위 명령] [대상] [명령 옵션]
sfcd --config NODE.yaml 명령 [명령 옵션]
```

| sfc 전역 옵션 | 의미 |
|---|---|
| `--cluster NAME` / `--context NAME` | 접속할 [context](cli/context.md). 생략하면 현재 context |
| `--user USERNAME` | wallet에 저장된 로그인 계정 선택. 현재 대상에 계정이 여러 개면 필수 |
| `--tenant TENANT` | 작업할 tenant. 생략하면 context의 tenant. node 운영은 system admin의 클러스터 전역 작업이므로 tenant 선택으로 범위가 좁아지지 않음 |
| `--peer NODE_ID` | 현재 client 설정의 접속 peer 선택. 접속하려면 해당 peer의 신뢰/pin이 준비되어 있어야 함 |
| `--timeout DURATION` | 요청 대기 기한. 예: `30s`, `1m`. 기한 만료가 원 작업 취소/미실행을 뜻하지 않음 |

묻지 않게 하는 옵션은 없다. 스크립트는 환경 변수 `SFC_NONINTERACTIVE=1`(터미널이 있어도 묻지 않고 실패)과 `SFC_WALLET_PASSWORD_FILE`(wallet 비밀번호가 든 mode 0600 파일)을 쓴다. 옛 `--no-input`·`--wallet-password-fd`는 지원하지 않는다. 새 명령 앞에 주면 sfcli는 이 두 변수를 쓰라고 알려 주고 실패한다.

전역 옵션은 **명령 앞**, 하위 명령 전용 옵션은 **하위 명령 뒤**에 둔다. 예를 들어 `sfcli --cluster lab --user admin whoami`가 올바른 순서다(새 명령 그룹은 옵션을 어디에 써도 된다). wallet 자체의 보호 입력 옵션은 아래 wallet 명령 뒤에 지정한다. 접속할 곳은 [context](cli/context.md)를 따른다.

### 5.2 `identity create` — 디스크 신원 생성

```sh
sfcli identity create /var/lib/sfc/identity
```

| 인자·출력 | 설명 |
|---|---|
| `DIR` | 생성할 신원 디렉터리. 상대 경로면 현재 작업 디렉터리 기준 |
| 표준 출력 | Ed25519 공개키의 소문자64자리 HEX. node add의 `--public-key` 또는 init의 `--admin-public-key`에 사용 |
| 생성 파일 | `key.pem` 개인키와 `cert.pem` 인증서. 개인키는0600, 새 디렉터리는0700 |

기존 신원을 덮어쓰지 않는다. node-b의 개인키를 node-c에 복사하지 않는다. 관리자 신원은 관리자 계정용이며 노드 신원과 분리한다. 이 명령에는 cluster 등록이나 로그인이 필요하지 않다.

### 5.3 `key` — Linux user의 키 저장소

```sh
sfcli key import cluster-admin /etc/sfc/admin-identity/key.pem
sfcli key create another-key
sfcli key list
sfcli key show cluster-admin
sfcli key passwd
```

키는 `~/.sfc/wallet.bin`에 wallet 비밀번호로 암호화해 둔다. 첫 `create`·`import`가 wallet을 만든다. 개인키는 출력하지 않고 `show`는 공개키(hex)만 보여 준다. 스크립트는 `SFC_WALLET_PASSWORD_FILE`(0600 파일)로 비밀번호를 준다. 한 Linux user가 여러 클러스터용 키를 함께 보관한다. 전체 사용법은 [key·login](cli/account.md)에 있다.

### 5.4 `sfcd check` — 노드 설정 검사

```sh
sfcd --config /etc/sfc/node.yaml check
```

`--config`는 **node YAML** 경로다. 설정을 읽어 형식·필드를 확인하며 노드 runtime/관리 listener를 열지 않는다. 성공 시 `valid node configuration, version=1`을 출력한다. 이는 클러스터 가입·quorum·Docker/앱 상태 검사가 아니다. `sfcd --config FILE --check-config`도 같은 설정 검사 경로다.

### 5.5 `sfcd init` — 새 단일 노드 클러스터 생성

```sh
sfcd --config /etc/sfc/node.yaml init \
  --admin-public-key <ADMIN_HEX> --request-id init-node-a \
  --client-config-out /etc/sfc/initial-client.yaml --timeout 30s
```

| 옵션 | 필수·기본값 | 설명 |
|---|---|---|
| `--config FILE` | 필수 | 새 설치의 node.yaml (`common.peers`·`common.cluster` 없이) |
| `--admin-public-key HEX` | 필수 | 최초 관리자 등록을 승인할 공개키. 계정 자체를 자동 생성하지 않음 |
| `--request-id ID` | 필수 | 원 초기화 작업 ID. 중단 후 동일 작업은 같은 ID/설정/키로 확인 |
| `--client-config-out FILE` | 선택 | 공개 pin이 포함된 user client YAML 저장. 부모 디렉터리는 이미 있어야 하며 다른 내용의 기존 파일은 덮어쓰지 않음 |
| `--timeout DURATION` | 기본30s | 초기 Raft commit 대기. 0 초과, 최대5m |

주요 출력은 `cluster`, `node_key`, `status`, `standalone`, `voters`, `quorum`, `configuration_index`, `applied_index`, `users`, `tenants`다. 초기 계정0이면 `AwaitingAdminEnrollment`다. init은 유한 명령이므로 성공 후 같은 설치로 run한다. 기존 클러스터에 추가할 노드에서는 init 대신 join을 사용한다.

### 5.6 `sfcd run` — 설치된 노드 운영

```sh
sfcd --config /etc/sfc/node.yaml run
```

같은 노드의 신원·설치 DB·Raft/FSM을 열고 복구한 뒤 관리 listener와 활성 모듈을 운영한다. `started` 이벤트의 `node`, `listener`, `management_socket`으로 실제 접속 주소를 확인한다. 이 이벤트만으로 클러스터 quorum이나 앱 Healthy까지 판단하지 않는다.

포그라운드에서 실행되므로 별도 터미널이나 서비스 관리자로 유지한다. 종료는 Ctrl+C(SIGINT) 또는 SIGTERM을 사용하고 정리 완료를 기다린다. 같은 설치를 동시에 두 프로세스로 열지 않는다.

### 5.7 `sfcd join` — 승인받은 기존 클러스터에 가입

```sh
sfcd --config /etc/sfc/node.yaml join \
  --cluster <CLUSTER_HEX> --source-public-key <SOURCE_HEX> \
  --invitation /etc/sfc/node-b.invitation.json --timeout 30s
```

| 옵션 | 필수·기본값 | 설명 |
|---|---|---|
| `--config FILE` | 필수 | 새 노드의 managed 설정. 승인받은 실제 identity가 먼저 존재해야 함 |
| `--cluster HEX` | 필수 | 기존 클러스터 ID. CLI 로컬 프로필 이름 `lab`을 넣는 옵션이 아님 |
| `--source-public-key HEX` | 필수 | 초대의 `Source.Key`에 해당하는 기존 control의 신뢰된 공개키 |
| `--invitation FILE` | 필수 | `sfcli node invite`로 받은 canonical signed JSON 원문 |
| `--timeout DURATION` | 기본30s | 가입·초기 동기화 대기. 0 초과, 최대5m |

초대의 대상 ID·공개키·endpoint가 새 노드와 같아야 한다. 성공 출력은 `status: Joined`, `join_id`, 실제 구성/적용 index와 voter 정보다. 처음에는 non-voter이며 join이 종료된 뒤 run으로 운영한다. timeout이면 원 초대·설치·키·DB를 보존한다.

새 노드가 초대 Source의 endpoint로 접속할 수 없어도(예: 공인 VPS가 NAT 뒤 집 서버의 사설 주소를 받은 경우) 가입된다. 기존 멤버는 연결이 없는 멤버·가입 대상 노드의 등록 endpoint로 1초부터 최대 10초 간격으로 접속을 시도하고, 새 노드는 들어온 연결로 가입 요청을 보낸다. 이미 연결이 있는 노드로는 접속을 시도하지 않는다. 초대 Source가 그 사이 리더가 아니게 되었으면 Source가 가입 요청을 현재 리더로 넘기고, 넘기지 못하면 리더를 알려 주어 새 노드가 리더에게 다시 요청한다(1초부터 최대 8초 간격). 새 노드는 Source가 알려 준 현재 멤버들의 복제를 받아들인다.

다른 노드들이 접속해 오기만 하고 이 노드에서는 다른 노드로 접속할 수 없거나 접속하지 않아야 하면(ingress gateway처럼 NAT 뒤 서버들 앞에 둔 공인 노드) node.yaml에 `inbound_only: true`를 둔다. 이 노드는 다른 노드로 QUIC 접속을 시도하지 않고, 다른 노드가 열어 둔 연결만 양방향으로 쓴다. 연결해 오지 않은 노드로 보낼 요청은 바로 실패한다. 관리 Unix 소켓에는 영향이 없다.

```yaml
node:
  id: vps1
  listen: "203.0.113.10:7443"
  inbound_only: true
```

### 5.8 `context add` — CLI에 접속 클러스터 등록

```sh
sfcli context add lab
sfcli context add remote sfcp://192.168.10.11:7443
sfcli context trust remote sfcp://192.168.10.12:7443   # 같은 클러스터의 다른 노드
```

endpoint를 생략하면 `unix:///run/sfcdp.sock`이다. 노드 키 지문을 보여 주고 확인을 묻는다. 스크립트는 init 출력의 `node_key`(hex)를 `--key`로 준다. 등록은 원격 클러스터·tenant 생성이나 노드 가입이 아니다. 전체 사용법은 [context](cli/context.md)에 있다.

### 5.9 `enroll` — 최초 관리자 계정 등록

```sh
sfcli enroll admin --key cluster-admin
```

init의 `--admin-public-key`에 준 공개키에 맞는 wallet 키로 빈 클러스터에 첫 system admin을 등록한다. 한 번만 받으며, 같은 사용자로 다시 실행하면 같은 요청의 결과를 확인한다. 등록 뒤 login을 따로 한다.

### 5.10 `login`·`whoami` — 계정 인증과 확인

```sh
sfcli login                     # context의 user와 wallet 키
sfcli login alice --password    # 비밀번호(터미널에서 입력)
sfcli whoami
```

login 성공 자격은 wallet에 사용자별로 보관된다. 이후 명령에서 유효 후보가 여러 개면 `--user USER`를 명시한다. 최근 로그인 계정을 임의로 고르지 않는다. 옵션은 [key·login](cli/account.md)에 있다.

### 5.11 `node` — 서버 조회와 운영

서버 명령은 [sfcli node](cli/node.md)에 모았다. 작업 ID와 revision은 CLI가 정하고, 끊긴 작업은 [sfcli op](cli/op.md)로 이어 간다.

### 5.12 도움말과 결과 판독

도움말은 설정·wallet·로그인·서버 없이 조회할 수 있다. 최상위 목록은 로컬 프로필·계정·원격 운영과 설치 신원 명령을 구분한다. 전역 옵션은 명령 앞에 둔다.

```sh
sfcli --help
sfcli node --help
sfcli node storage --help
sfcli cluster status --help
sfcli tenant --help
sfcli network --help
sfcli app --help
sfcli login --help
sfcli cluster --help
sfcli wallet --help
sfcd --help
sfcd init --help
sfcd join --help
```

일반 업무 출력은 JSON이며 identity create의 공개키 HEX, `node invite`의 정규 JSON 원문, 설정 검사 문구는 각 절의 설명을 따른다. 진단은 stderr로 출력하므로 초대/원 JSON 파일에 stderr를 합치지 않는다.

| 코드·상태 | 의미 |
|---|---|
| 종료 코드 `0` | 해당 CLI 호출 성공. node 변경의 실제 native 완료 여부는 별도 status로 확인 |
| 종료 코드 `1` | 런타임/전송·I/O 등 오류. 오류 문구와 원 작업 존재 여부 확인 |
| 종료 코드 `2` | 인자·설정·입력 오류 |
| 종료 코드 `3` | 확정된 관리 거부/CAS 실패 등 |
| 종료 코드 `4` | 원 관리 결과 미확정·불명 등. 원 journal/ID를 보존하고 조회 |
| node 출력 `accepted` | 관리 변경 수락 |
| manage result 출력 `applied` | 원 FSM 명령 적용. native 작업 완료 증명은 아님 |
| `rejected` / `unknown` | 거부 / 원 결과 불명. 자동으로 새 ID를 발급하여 반복하지 않음 |

종료 코드는 각 명령의 의미와 함께 판독한다. 예를 들어 join의 실패 코드4는 원 가입이 미실행이라는 보장이 아니며, sfcd run의 내구 적용 실패 종료70은 별도 daemon 실패다. 상태 정산 전에는 원 DB/identity·초대·wallet journal을 지우지 않는다.
