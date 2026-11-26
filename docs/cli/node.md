# mydc node: 서버

클러스터의 서버(노드)를 보고, 넣고, 빼고, 손본다. 조회 일부(`list`, `disks`, `storage list`)는 작업 공간 사용자도 쓸 수 있고, 나머지는 시스템 관리자 명령이다.

바꾸는 명령은 모두 같은 규칙을 따른다.

- 작업 ID는 CLI가 만든다(`--id`로 직접 줄 수 있다). 서버 쪽 작업 ID도 같은 값이다. 끊기면 `mydc op show ID`, `mydc op resume ID`로 이어 간다([op](op.md)).
- revision은 보내기 직전에 CLI가 읽는다. 스크립트는 `--if-revision N`으로 "그 revision일 때만"을 걸 수 있다.
- 위험한 변경(demote, drain, isolate, remove, rotate-key, images delete, storage remove)은 영향을 보여 주고 y/N을 묻는다. `-y`는 묻지 않고, `--dry-run`은 보여 주기만 한다.
- 오래 걸리는 변경(drain, isolate, restore, remove, rotate-key, images delete)은 끝날 때까지 진행을 보여 준다. Ctrl-C나 `--no-wait`이면 작업은 서버에서 계속되고 CLI만 나간다.

## 보기

| 명령 | 하는 일 |
|---|---|
| `node list` | 작업 공간이 쓸 수 있는 서버와 상태. 작업 공간이 정해지지 않았으면 `--all`과 같다 |
| `node list --all` | 모든 서버의 가입 상태, 투표 여부, 생명주기, 배치 상태(open/cordoned), 진행 중 작업 |
| `node show NODE` | 한 서버의 전체 기록(가입 정보, 생명주기, 마지막 관측). `-o json`이면 모든 값 |
| `node disks [NODE] [--all]` | 디스크 크기·여유·용도 |
| `node tenants NODE` | 작업 공간별 CPU·메모리 사용량과 할당 |
| `node diagnostics NODE [--out FILE]` | 비밀이 없는 진단 묶음(tar.gz)을 새 파일로 저장 |
| `node images NODE` | 서버에 캐시된 컨테이너 이미지와 쓰는 곳 |

## 서버 넣기

```sh
# 새 서버에서: mydcd identity 로 공개키를 확인한다
mydc node add node-b --endpoint 10.0.0.12:7443 --public-key 3f1a...   # 64자 hex
mydc node invite node-b --out node-b.invitation.json
# 새 서버에서: mydcd join --invitation node-b.invitation.json
mydc node list --all
mydc node promote node-b       # 투표 멤버로
```

`add`의 작업 ID가 초대의 join ID가 된다. 서버는 투표하지 않는 멤버로 들어오고 `promote`로 투표 멤버가 된다. `demote`는 반대이며, 남는 투표 멤버와 quorum을 먼저 보여 준다.

## 서버 빼기

```sh
mydc node cordon node-c '디스크 교체'   # 새 컨테이너를 놓지 않는다. 돌던 것은 그대로
mydc node drain node-c         # 옮길 수 있는 컨테이너를 다른 서버로 옮기고 끝날 때까지 기다린다
mydc node remove node-c        # 비어 있으면 클러스터에서 뺀다
```

- `drain`은 옮길 컨테이너 수, 옮길 수 없는 컨테이너, 막는 이유를 먼저 보여 준다. 옮길 수 없는 컨테이너가 있으면 멈춘다. `--leave-blocked`는 옮길 수 있는 것만 옮긴다.
- `remove`는 남는 투표 멤버 수와 막는 이유(`LAST_VOTER`, `QUORUM_LOSS` 등)를 보여 준다. 막히면 아무것도 보내지 않고 종료 코드 3으로 끝난다.
- `remove --force`는 다시 돌아오지 않는 서버를 뺀다. 그 서버의 컨테이너·볼륨 기록은 지우지 않고 남겨 둔다.
- `isolate`는 데이터를 둔 채 서버를 클러스터 일에서 뺀다. `restore`로 되돌린다.
- `cordon`의 사유는 선택이며 한 줄, 256자 이하다. `node list --all`의 배치 칸(`cordoned: 사유`)과 `node show`의 `Scheduling.Reason`에 보인다.
- `uncordon`은 배치를 다시 허용한다.
- isolate·restore·remove는 시작한 관리자의 권한으로 계속 진행된다. 그 권한이 사라져(계정 비활성, 역할 회수) 멈췄으면 `node renew NODE`로 지금 관리자가 같은 작업을 이어 간다. 새 작업을 만들지 않는다.

## 키 바꾸기

`node rotate-key NODE`는 서버에 새 신원 키를 준다. 새 키가 설치될 때까지 따라간다. 요청 시각과 단계는 `node show`의 `Identity`(`RequestedAt`, `Phase`)에 보인다.

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

볼륨과 내장 registry를 둘 수 있는 서버의 기존 디렉터리다. mydc는 디렉터리를 만들거나 포맷·마운트·삭제하지 않는다.

| 명령 | 하는 일 |
|---|---|
| `node storage list [NODE]` | 작업 공간이 쓸 수 있는 디렉터리 |
| `node storage list [NODE] --all` | 모든 디렉터리와 설정 |
| `node storage show NODE NAME` | 한 디렉터리 |
| `node storage space [NODE]` | 지금 관측한 파일시스템별 여유 공간(예약이 아니다) |
| `node storage add NODE NAME --path DIR [--tenants a,b] [--max-volumes N]` | 등록. 작업 공간을 주지 않으면 아무도 못 쓴다 |
| `node storage set NODE NAME (--tenants a,b \| --no-tenants) [--max-volumes N]` | 쓸 수 있는 작업 공간과 볼륨 수 |
| `node storage drain NODE NAME` | 새 볼륨을 두지 않는다 |
| `node storage remove NODE NAME` | 비운 디렉터리를 등록에서 뺀다 |

## 서버 전체 한도

한 서버에서 모든 작업 공간이 함께 쓸 수 있는 양이다. 작업 공간 한도([`tenant quota set`](tenant.md))는 이 값 안에서만 정할 수 있으므로, 서버마다 먼저 정해 둔다. 시스템 관리자 명령이다.

| 명령 | 하는 일 |
|---|---|
| `node quota show NODE` | 지금 한도. `-o json`이면 모든 값 |
| `node quota set NODE --cpu 8 --memory 16GiB` | CPU 코어 수(소수 가능)와 메모리 |

`set`은 그 밖의 한도도 받는다. 주지 않은 값은 지금 값을 유지하고, 처음 정할 때는 괄호 안의 값으로 시작한다.

| 옵션 | 뜻 |
|---|---|
| `--networks N` | 관리 망 수 (16) |
| `--consumers N` | 관리 망·DNS에 붙는 컨테이너 수 (64) |
| `--packet-queue N`, `--packet-queue-bytes SIZE` | TUN 망마다 쌓아 둘 패킷 수와 크기. 둘 다 0이거나 둘 다 0보다 크다 (256, 512KiB) |
| `--ingress-instances N`, `--ingress-listeners N` | ingress 인스턴스·리스너 수 (4, 16) |
| `--ingress-requests N`, `--ingress-connections N` | 동시에 처리할 ingress 요청·연결 수 (64, 256) |
| `--ingress-buffer SIZE` | ingress 버퍼 (1MiB) |

처음 정할 때는 `--cpu`와 `--memory`가 꼭 필요하다. 이미 쓰고 있는 양보다 작게 줄이면 서버가 거절한다. 서버 전체 한도를 줄여도 작업 공간 한도는 저절로 줄지 않는다.

## 종료 코드

0 성공, 1 실패(서버 거절 포함), 2 잘못된 명령줄, 3 막혀서 보내지 않음(blocker, 사용 중인 이미지), 4 결과를 모름(`mydc op show ID`로 확인).
