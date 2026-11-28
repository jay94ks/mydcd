# sfcli node: 서버

클러스터의 서버(노드)를 보고, 넣고, 빼고, 손본다. 조회 일부(`list`, `disks`, `storage list`)는 작업 공간 사용자도 쓸 수 있고, 나머지는 시스템 관리자 명령이다.

바꾸는 명령은 모두 같은 규칙을 따른다.

- 작업 ID는 CLI가 만든다(`--id`로 직접 줄 수 있다). 서버 쪽 작업 ID도 같은 값이다. 끊기면 `sfcli op show ID`, `sfcli op resume ID`로 이어 간다([op](op.md)).
- revision은 보내기 직전에 CLI가 읽는다. 스크립트는 `--if-revision N`으로 "그 revision일 때만"을 걸 수 있다.
- 위험한 변경(demote, drain, isolate, remove, rotate-key, images delete, storage remove)은 영향을 보여 주고 y/N을 묻는다. `-y`는 묻지 않고, `--dry-run`은 보여 주기만 한다.
- 오래 걸리는 변경(drain, isolate, restore, remove, rotate-key, images delete)은 끝날 때까지 진행을 보여 준다. Ctrl-C나 `--no-wait`이면 작업은 서버에서 계속되고 CLI만 나간다.

## 보기

| 명령 | 하는 일 |
|---|---|
| `node list` | 작업 공간이 쓸 수 있는 서버와 상태, 빌드 가능 여부(`build` 칸: `yes`, 또는 `no (ENGINE_BUILD_OFF/WORKLOAD_OFF/UNKNOWN)`). 작업 공간이 정해지지 않았으면 `--all`과 같다 |
| `node list --all` | 모든 서버의 가입 상태, 투표 여부, 생명주기, 배치 상태(open/cordoned), 진행 중 작업 |
| `node show NODE` | 한 서버의 전체 기록(가입 정보, 생명주기, 마지막 관측). `-o json`이면 모든 값. 서버가 켠 cluster app(sfc-web 등)은 `Summary.Admin.Host.ClusterApps`에 이름·고정 이미지 digest·상태·시스템 망 주소·제어 정책으로 보인다. `starting`에 머물면 `Reason`이 막힌 이유를 말한다: `not-work-server`, `no-server-address`, `no-server-quota`, `server-quota-owner`, `server-network-limit`, `no-free-system-pool`(시스템 망에 들어가지 못함). 같은 이유가 sfcd 로그에 `system network: node … cannot join the system network: …`로 한 번 남는다 |
| `node disks [NODE] [--all]` | 디스크 크기·여유·용도 |
| `node tenants NODE` | 작업 공간별 CPU·메모리 사용량과 할당 |
| `node diagnostics NODE [--out FILE]` | 비밀이 없는 진단 묶음(tar.gz)을 새 파일로 저장 |
| `node logs NODE NAME` | 그 서버의 클러스터 앱(예: `web`) 로그. `--container C`는 그 서버가 보관한 아무 컨테이너 로그. [`sfcli logs --node`](logs.md)의 별칭(시스템 관리자) |
| `node images NODE` | 서버에 캐시된 컨테이너 이미지와 쓰는 곳 |

## 서버 넣기

```sh
# 새 서버에서: sfcd identity 로 공개키를 확인한다
sfcli node add node-b --endpoint 10.0.0.12:7443 --public-key 3f1a...   # 64자 hex
sfcli node invite node-b --out node-b.invitation.json
# 새 서버에서: sfcd join --invitation node-b.invitation.json
sfcli node list --all
sfcli node promote node-b       # 투표 멤버로
```

초대는 지금 리더가 서명한다(접속한 서버가 요청을 리더에게 넘긴다). 그 리더를 context가 신뢰하지 않아도, 접속한 서버의 멤버 목록에 같은 키와 주소의 투표 멤버로 있으면 `invite`가 받아들인다. 둘 다 아니면 서명한 서버 이름과 키 앞부분을 보여 주며 멈추니, 그 서버를 확인하고 `sfcli context trust`로 신뢰시킨다.

### 가입 전 서버 취소하기

`add`만 하고 아직 가입하지 않은 서버(`invited`)는 `sfcli node remove NODE`로 초대를 취소한다. 그 이름·키·주소가 풀려서 같은 이름으로 다시 `add`할 수 있다. 키나 주소를 잘못 넣었으면 `sfcli node add NODE --replace --endpoint ... --public-key ...`로 초대를 취소하고 바로 다시 등록한다.

- `sfcd join`을 했지만 결과를 모르는 서버: 리더가 커밋된 Raft 구성(읽기 장벽 뒤)에 그 서버가 없으면 "추가되지 않음"으로 정리한다. 그러면 다시 `sfcd join`을 하거나 `node remove`로 취소할 수 있다. 정리 중이면 `remove`가 잠시 뒤 다시 하라고 알려 준다.
- Raft에 learner로 들어갔지만 설치 확인(ack)을 끝내지 못한 서버: `node remove`가 가입 포기(`abort-node-join`)를 보낸다. 리더가 Raft에서 빼고, 커밋된 구성에서 빠진 것을 본 뒤 항목을 지운다. 그 서버가 아직 돌고 있으면 먼저 그 서버의 sfcd를 멈춘다. 포기한 뒤에는 설치 확인을 받지 않는다.
- 셋 다 끝나면 이름·키·주소가 풀려 같은 이름으로 다시 `add`할 수 있다. 가입을 마친 서버는 `drain`·`remove`로 뺀다.
- 등록되지 않은 이름이면 `remove`는 "등록되지 않은 서버"라고 알려 준다.

`add`의 작업 ID가 초대의 join ID가 된다. 서버는 투표하지 않는 멤버로 들어오고 `promote`로 투표 멤버가 된다. `demote`는 반대이며, 남는 투표 멤버와 quorum을 먼저 보여 준다.

## 서버 빼기

```sh
sfcli node cordon node-c '디스크 교체'   # 새 컨테이너를 놓지 않는다. 돌던 것은 그대로
sfcli node drain node-c         # 옮길 수 있는 컨테이너를 다른 서버로 옮기고 끝날 때까지 기다린다
sfcli node remove node-c        # 비어 있으면 클러스터에서 뺀다
```

- `drain`은 옮길 컨테이너 수, 옮길 수 없는 컨테이너, 막는 이유를 먼저 보여 준다. 옮길 수 없는 컨테이너가 있으면 멈춘다. `--leave-blocked`는 옮길 수 있는 것만 옮긴다.
- `remove`는 남는 투표 멤버 수와 막는 이유(`LAST_VOTER`, `QUORUM_LOSS` 등)를 보여 준다. 막히면 아무것도 보내지 않고 종료 코드 3으로 끝난다.
- `remove --force`는 다시 돌아오지 않는 서버를 뺀다. 그 서버의 컨테이너·볼륨 기록은 지우지 않고 남겨 둔다.
- `isolate`는 데이터를 둔 채 서버를 클러스터 일에서 뺀다. `restore`로 되돌린다.
- `cordon`의 사유는 선택이며 한 줄, 256자 이하다. `node list --all`의 배치 칸(`cordoned: 사유`)과 `node show`의 `Scheduling.Reason`에 보인다.
- `uncordon`은 배치를 다시 허용한다.
- isolate·restore·remove는 시작한 관리자의 권한으로 계속 진행된다. 그 권한이 사라져(계정 비활성, 역할 회수) 멈췄으면 `node renew NODE`로 지금 관리자가 같은 작업을 이어 간다. 새 작업을 만들지 않는다.

## 주소 바꾸기

가입한 서버의 IP나 포트가 바뀌면 빼지 않고 주소만 바꾼다. 서버에서 sfcd를 멈추고 node.yaml의 `listen`을 고친 뒤 `sfcd set-listen`을 하고, `sfcli node set-endpoint NODE HOST:PORT`로 클러스터에 알린 다음 sfcd를 켠다. 이름·키·투표 여부·컨테이너는 그대로다. 명령은 리더가 새 주소를 Raft 구성에 넣을 때까지 기다린다(그동안 단계 `moving`). 자세한 절차: [가입한 서버의 주소 바꾸기](../reference/server-endpoint-move.md).

## 키 바꾸기

`node rotate-key NODE`는 서버에 새 신원 키를 준다. 새 키가 설치될 때까지 따라간다. 요청 시각과 단계는 `node show`의 `Identity`(`RequestedAt`, `Phase`)에 보인다. 단계가 `Activated`가 되는 순간 옛 키는 접속·보고에 더는 쓰이지 않고, 그 서버가 원래 가진 컨테이너·볼륨은 그대로 새 키가 이어받는다. 키가 새어 나갔다고 의심될 때 쓴다. 서버 디스크 자체를 잃었다면 키 회전 대신 `node remove`로 빼고 다시 가입시킨다([보안](../mechanisms/security.md#설치-키-회전)).

## 셸

| 명령 | 하는 일 |
|---|---|
| `node shell NODE` | 서버의 셸 계정으로 대화형 셸을 연다. 끊기면 세션은 닫히고 새로 열지 않는다 |
| `node shell policy` | 클러스터 기본값, 서버별 설정, 허용 목록 |
| `node shell policy --enable\|--disable [--max-sessions N] [--idle 30m]` | 클러스터 기본값 |
| `node shell policy NODE --shell on\|off\|inherit [--sudo]` | 서버별 설정 |
| `node shell grant USER NODE...` | 사용자가 셸을 열 수 있는 서버를 정확히 그 목록으로 바꾼다. `--revoke`는 허용을 없앤다 |
| `node shell sessions [--state open\|closed] [--node NODE]` | 세션 목록 |
| `node shell close SESSION` | 열린 세션을 닫는다 |

동작과 보안 규칙은 [노드 셸](../reference/node-shell.md).

## 이미지 캐시

`node images delete NODE sha256:... [...]`는 아무 컨테이너·배포도 쓰지 않는 이미지 1~8개를 지운다. 하나라도 쓰이고 있으면 보내지 않는다. 자세한 규칙은 [노드 이미지 캐시](../reference/node-image-cache.md).

## 저장 디렉터리

볼륨과 내장 registry를 둘 수 있는 서버의 기존 디렉터리다. sfc는 디렉터리를 만들거나 포맷·마운트·삭제하지 않는다. 아래의 기본 저장 경로만 예외로 서버가 디렉터리를 만든다.

**기본 저장 경로.** 서버는 클러스터에서 처음 돌 때(init·join 뒤) 스스로 `default` 저장 경로를 한 번 등록한다. 경로는 `state_dir` 옆의 `<state_dir>-storage`(보통 `/var/lib/sfc-storage`)이고, 모든 작업 공간이 쓸 수 있고, 용량 한도가 없다. 데몬 상태 디렉터리 밖에 두므로 상태를 지워 다시 init해도 그 안의 파일은 남는다. 다른 저장 경로처럼 `set`으로 바꾸고 `drain`·`remove`로 뺄 수 있고, 한 번 뺀 뒤에는 재시작하거나 다시 join해도 다시 만들지 않는다. 그 파일시스템이 ext4가 아니면 등록하지 않는다(로그에 남긴다). 기본 저장 경로는 보통 데몬 상태(Raft·bbolt)와 같은 파일시스템에 있어서, 볼륨이 디스크를 채우면 데몬 쓰기도 함께 막힌다. 운영 데이터는 별도 디스크에 저장 경로를 따로 등록하고, 기본 저장 경로에는 `node storage set NODE default --capacity SIZE`로 한도를 거는 것을 권한다. 등록된 저장 경로는 서버를 클러스터에서 빼기 전에 비워야 하므로, 기본 저장 경로도 `node storage drain`·`remove`를 먼저 한다.

**용량 한도**(`--capacity`)는 그 저장 경로에 등록한 고정 볼륨들의 예약 크기(`volume register --size`) 합의 상한이다. 한도가 있는 저장 경로에는 `--size`를 준 볼륨만 등록되고, 지금 예약된 합보다 낮게 줄일 수는 없다. 파일시스템 quota가 아니다. 저장 경로마다 볼륨 개수 상한은 없다.

| 명령 | 하는 일 |
|---|---|
| `node storage list [NODE]` | 작업 공간이 쓸 수 있는 디렉터리 |
| `node storage list [NODE] --all` | 모든 디렉터리와 설정 |
| `node storage show NODE NAME` | 한 디렉터리 |
| `node storage space [NODE]` | 지금 관측한 파일시스템별 여유 공간(예약이 아니다) |
| `node storage add NODE NAME --path DIR [--tenants a,b \| --all-tenants] [--capacity SIZE]` | 등록. 작업 공간을 주지 않으면 아무도 못 쓴다. `--capacity`의 기본은 `unlimited` |
| `node storage set NODE NAME [--add-tenants a,b] [--remove-tenants c] [--all-tenants=true\|false] [--capacity SIZE\|unlimited]` | 쓸 수 있는 작업 공간과 용량 한도. 바뀌는 것만 보낸다. 이미 허용된 작업 공간을 더하거나 없는 것을 빼면, 모든 작업 공간이 허용된 동안 목록을 고치면 거절된다. `--all-tenants=false`는 `--add-tenants`로 새 목록을 시작한다 |
| `node storage archive-default NODE NAME [--clear]` | 내린 앱의 볼륨을 보관할 때 쓸 이 서버의 기본 보관 위치. 서버마다 하나이고, 새로 정하면 앞의 것은 풀린다. `--clear`는 NAME을 기본에서 뺀다. 기본이 없으면 그 서버의 `default` 저장 경로에 보관한다. drain하는 디렉터리는 기본이 될 수 없고, drain하면 기본에서 빠진다 |
| `node storage drain NODE NAME` | 새 볼륨을 두지 않는다 |
| `node storage remove NODE NAME` | 비운 디렉터리를 등록에서 뺀다 |

## 방화벽

node.yaml `firewall.managed: true`인 서버로 들어오는 연결 규칙을 다룬다. 운영자 iptables·nftables 규칙은 그대로 두고 그 앞에서 판정한다. 시스템 관리자 명령이다. 자세한 동작: [서버 방화벽](../reference/node-firewall.md). 모든 서버에 같이 걸리는 클러스터 값은 [`sfcli firewall`](cluster.md#방화벽)이다.

| 명령 | 하는 일 |
|---|---|
| `node firewall show NODE` | 정책(지금 적용 중인 값), 잠금 규칙, 클러스터 필수 규칙, 서버 규칙(필수 규칙에 일부 가려지면 표시), 클러스터 일반 규칙, 서버에 원래 있던 들어오는 연결 규칙(nft 표현식, 읽기만) |
| `node firewall allow\|deny NODE tcp/PORT\|udp/PORT\|icmp\|any [--from PREFIX]... [--comment TEXT]` | 규칙 하나 추가. 포트 범위는 `tcp/30000-30100`. deny가 allow보다 먼저 |
| `node firewall update NODE RULE [--action] [--match] [--from]... [--from-anywhere] [--comment]` | 준 칸만 바꾼다 |
| `node firewall remove NODE RULE...` | 규칙 빼기 |
| `node firewall policy NODE inherit\|return\|drop` | 안 걸린 연결: `inherit`(기본, 클러스터 값 따름), `return`(서버의 원래 규칙으로), `drop` |
| `node firewall log NODE [--before REVISION]` | 바꾼 기록, 최신부터 |

## 서버 전체 한도

한 서버에서 모든 작업 공간이 함께 쓸 수 있는 양이다. 작업 공간 한도([`tenant quota set`](tenant.md))는 이 값 안에서만 정할 수 있으므로, 서버마다 먼저 정해 둔다. 시스템 관리자 명령이다.

| 명령 | 하는 일 |
|---|---|
| `node quota show NODE` | 지금 한도. `-o json`이면 모든 값 |
| `node quota set NODE --cpu 8 --memory 16GiB [--swap 8GiB]` | CPU 코어 수(소수 가능), 메모리(RAM), 그 위에 더 쓸 swap |

관리자가 한도를 정하지 않은 서버는 가진 것을 모두 쓴다. 그 서버의 기본 한도는 CPU와 메모리(RAM과 swap)를 sfc가 따로 세지 않고, 나머지 한도는 위 괄호 안의 값이다. 기본 한도는 Raft에 쓰지 않고 구성원 정보로 모든 서버가 같게 계산한다(`show`의 `set by`가 `server default`, revision 0). 관리자가 `set`을 하면 그 값으로 바뀐다. swap을 일부만 쓰게 하려면 `--swap`으로 정한다(예: swap 16G 중 8G만: `--memory 7262MiB --swap 8GiB`). 작업이 예약할 수 있는 메모리는 `--memory`와 `--swap`의 합이다.

`set`은 그 밖의 한도도 받는다. 주지 않은 값은 지금 값을 유지하고, 처음 정할 때는 괄호 안의 값으로 시작한다.

| 옵션 | 뜻 |
|---|---|
| `--networks N` | 관리 망 수 (16) |
| `--consumers N` | 관리 망·DNS에 붙는 컨테이너 수 (64) |
| `--packet-queue N`, `--packet-queue-bytes SIZE` | TUN 망마다 쌓아 둘 패킷 수와 크기. 둘 다 0이거나 둘 다 0보다 크다 (256, 512KiB) |
| `--ingress-instances N`, `--ingress-listeners N` | ingress 인스턴스·리스너 수 (4, 16) |
| `--ingress-requests N`, `--ingress-connections N` | 동시에 처리할 ingress 요청·연결 수 (64, 256) |
| `--ingress-buffer SIZE` | ingress 버퍼 (1MiB) |

관리자가 처음 정할 때는(기본 한도 위에서도) `--cpu`와 `--memory`가 꼭 필요하다. `--swap`을 주지 않으면 지금 값(처음이면 0)을 유지한다. 이미 쓰고 있는 양보다 작게 줄이면 서버가 거절한다. 서버 전체 한도를 줄여도 작업 공간 한도는 저절로 줄지 않는다.

## 종료 코드

0 성공, 1 실패(서버 거절 포함), 2 잘못된 명령줄, 3 막혀서 보내지 않음(blocker, 사용 중인 이미지), 4 결과를 모름(`sfcli op show ID`로 확인).
