# 더한 것

## 접속 상대 확인

패치 0003, `daemon/command/seafield_peer_linux.go`.

엔진 API 소켓에 접속이 들어오면 HTTP를 읽기 전에 커널로 상대를 확인한다.

1. `SO_PEERCRED`의 uid가 0이어야 한다.
2. `SO_PEERPIDFD`로 상대 프로세스를 pidfd로 고정하고 `/proc/<pid>/exe`를 읽는다.
3. 읽은 뒤 pidfd로 signal 0을 보내 그 프로세스가 아직 같은 프로세스인지 확인한다(pid 재사용 방지).
4. 실행 파일 경로가 허용 목록에 있어야 한다. 기본은 `/usr/lib/sfc/bin/sfcd (패키지), /usr/local/lib/sfc/bin/sfcd (tar), /usr/local/bin/sfcd`.

환경 변수 `SEAFIELD_ALLOWED_PEERS`(`:`로 구분한 절대 경로)가 기본 목록을 바꾼다. 시험·진단용이다. 거절은 경고 로그 `Seafield refused an API connection`에 실행 파일 경로와 함께 남는다.

Linux 6.5 이상이 필요하다(`SO_PEERPIDFD`).

## 번호 붙은 이벤트 열

패치 0004, `daemon/seafield/eventfeed`.

업스트림 이벤트 서비스는 최근 256개만 메모리에 두고 느린 구독자에게는 버린다. Seafield는 엔진이 내는 모든 이벤트(업스트림 `/events`와 같은 내용)에 번호를 붙여 `<data-root>/seafield/events.db`에 남긴다.

- 번호(`seq`)는 1부터 오르고 다시 쓰지 않는다. 엔진을 다시 시작해도 이어진다.
- `boot`는 엔진이 시작할 때마다 바뀌는 값이다. 바뀐 것을 본 쪽은 현재 상태를 한 번 다시 읽는다.
- 최근 200,000개를 남기고 오래된 것부터 지운다. 디스크 기록이 65,536개 넘게 밀리면 그 사이 이벤트는 버리되 번호는 쓴 것으로 남겨, 읽는 쪽에 빠진 구간으로 보인다.

sfcd는 엔진 세션에서 purpose 32 `subscribe {After}`를 한 번 보낸다. 엔진은 `{Boot, Last}`로 답한 뒤, `After` 다음 번호부터 오래된 순서로 kind 16 묶음 `{Boot, Gap, Records}`를 기록이 생길 때마다 밀어 보낸다(묶음당 최대 200개, 128KiB). 세션이 끊기면 sfcd는 마지막으로 받은 번호로 다시 구독한다. HTTP `GET /seafield/events`는 없앴다(0015).

```json
{"Boot": "d0bc286ebb13ad5e", "Gap": {"From": 4, "To": 9},
 "Records": [{"seq": 10, "boot": "d0bc286ebb13ad5e", "event": {"Type": "container", "Action": "die", "Actor": {"ID": "…", "Attributes": {"exitCode": "3"}}, "time": 1795766808, "timeNano": 1795766808000000000}}]}
```

`Gap`은 요청한 번호 중 더는 없는 구간이다(지워졌거나 버려짐). 이 구간이 오면 받는 쪽은 현재 상태를 다시 읽어야 한다. 묶음의 `Records`는 빈틈 없이 이어진 번호만 담는다.

`event`는 업스트림 `events.Message` 그대로다.

## cgroup 알림 이벤트

패치 0005, `daemon/seafield/monitor`.

실행 중인 컨테이너마다 cgroup v2 파일을 커널 알림으로 지켜보고, 바뀌었을 때만 컨테이너 이벤트를 낸다. 주기 조회는 없다. 이벤트는 엔진의 컨테이너 이벤트와 같은 속성(라벨, `image`, `name`)을 달고 `/events`와 번호 붙은 이벤트 열에 들어간다.

| 동작 | 원천 | 속성 |
|---|---|---|
| `seafield.memory` | `memory.events` 변경(inotify). `low`·`high`·`max`·`oom`·`oom_kill`·`oom_group_kill` 중 하나라도 올랐을 때만 | `changed`(오른 항목, `,`로 구분), `memory.<항목>`(현재 누적값) |
| `seafield.pressure` | `cpu.pressure`·`memory.pressure`·`io.pressure`의 PSI trigger: 1초 창에서 100ms 넘게 막힘 | `resource`(`cpu`·`memory`·`io`), `some.avg10`, `some.avg60`, `full.avg10`, `full.avg60` |

- 컨테이너가 시작하면 지켜보기 시작하고 `die`·`destroy`에서 멈춘다. 이벤트 열에 빈 구간이 생기면 실행 중인 컨테이너를 다시 훑는다.
- cgroup v2가 아니면(또는 파일이 없으면) 처음 한 번 경고를 남기고 그 컨테이너는 지켜보지 않는다. 공식 지원 Ubuntu LTS는 cgroup v2다.
- 확인(2026-11-27, KVM Ubuntu 24.04 cgroup v2): 16MiB 제한 컨테이너가 넘치자 `changed` = `max` → `max,oom` → `oom_kill` 이벤트, 0.05 CPU 제한에서 바쁜 반복 4개가 `cpu` pressure 이벤트(some avg10 13.9→39.5)를 냈고 이벤트 열 번호는 빈틈없이 이어졌다.
- CPU 시간, 바이트 수처럼 커널이 알림을 주지 않는 누적값은 이 이벤트에 없다. 필요할 때 업스트림 stats API로 읽는다.

## 로그 queue

패치 0006·0010·0012, `daemon/seafield/logqueue`. 로그 드라이버 이름 `seafield-queue`.

엔진은 로그를 보관하지 않는다. 로그는 sfcd가 한곳에 모아 관리한다. 사용자는 거기서 지울 수 있고, sfcd는 컨테이너별 상한만큼만 남긴다. 엔진의 queue는 sfcd가 가져갈 때까지만 두는 임시 버퍼다(Jay 2026-11-27).

흐름:

1. 컨테이너의 stdout·stderr 한 줄마다 번호를 붙여 `<data-root>/containers/<id>/seafield-logs/`에 쌓는다.
2. 엔진은 "이 컨테이너 queue에 N번까지 들어 있다"는 이벤트만 낸다(컨테이너 이벤트 `seafield.logs`, 속성 `seq`). 이벤트에 로그 내용은 없다. [번호 붙은 이벤트 열](#번호-붙은-이벤트-열)로 sfcd에 간다.
3. sfcd가 purpose 33 `bulk`로 묶음째 가져간다. 한 줄씩 가져가는 길은 없다(Jay 2026-11-27).
4. 보관을 마친 줄은 sfcd가 purpose 34 `ack`로 알리고, 엔진은 그 줄을 지운다.

이벤트 간격(과도한 이벤트로 엔진·sfcd 전체가 마비되지 않게 하려는 것):

- 마지막 줄이 들어오고 `notify-quiet`(기본 500ms) 뒤에 낸다. 그 사이 또 줄이 들어오면 예약을 취소하고 다시 `notify-quiet` 뒤로 미룬다.
- 줄이 쉬지 않고 들어와 계속 미뤄져도, 첫 미발표 줄부터 `notify-max-wait`(기본 5초) 안에는 꼭 한 번 낸다.
- 로거가 닫힐 때(컨테이너 종료) 예약된 이벤트는 바로 낸다.
- 로그를 끈 컨테이너(`--log-driver none`)는 queue도 타이머도 이벤트도 없다.
- 두 값은 `log-opts`로 바꾼다(`notify-quiet` 10ms~10s, `notify-max-wait` 1분 이하이고 `notify-quiet` 이상). sfc는 노드별 설정(`node.yaml`)에서 받아 노드의 `daemon.json`에 쓴다.
- 엔진이 막 시작해 복원 중일 때 쌓인 줄의 이벤트는 버린다. sfcd는 엔진 `boot`가 바뀐 것을 보면 모든 queue를 한 번 가져간다.

저장:

- 번호(`seq`)는 1부터 오르고, 컨테이너가 다시 시작해도, queue를 다 비운 뒤 엔진을 다시 시작해도 이어진다(확인한 번호를 `acked` 파일에 둔다). 비정상 종료로 끝이 잘린 기록은 다음에 열 때 버린다.
- 크기 상한 `--log-opt max-size`(기본 64MiB, 최소 256KiB)를 넘으면 **가장 오래된 것부터 버린다**. 컨테이너의 쓰기는 막지 않는다. 버린 번호는 읽을 때 `gap`으로 보인다.
- 저장 단위는 상한의 1/8 크기 조각이다. ack한 번호까지만 든 조각을 지우고, 쌓인 것을 모두 ack하면 쓰는 중인 조각도 지운다. ack한 줄은 다시 읽히지 않고 `gap`으로도 보이지 않는다.
- 한 줄은 최대 1MiB이고 넘는 부분은 잘린다. 업스트림이 긴 줄을 나눠 보낸 조각에는 `partial: true`가 붙는다.
- 기록 하나: 빅엔디언 헤더 22바이트(seq 8, unixnano 8, stream 1 = stdout 1/stderr 2, partial 1, 길이 4) + 데이터. 조각 파일 이름은 첫 번호를 20자리로 채운 `<seq>.seg`.

엔진 세션에서(0015, HTTP 경로는 없앴다):

| purpose·op | 요청 | 답 |
|---|---|---|
| 33 `bulk` | `{Container, After, MaxBytes}` | `{Count, First, Last, Gap, Live, Size}` 뒤에 `Size`바이트 기록을 kind 4 조각으로, 그다음 FIN |
| 34 `ack` | `{Container, Upto}` | 빈 답 |

`bulk`는 `After` 다음 번호부터 오래된 순서로 기록을 이어 붙여 바로 돌려준다(기다리지 않는다). 본문은 조각 파일과 같은 기록 인코딩이다. `MaxBytes` 0이면 4MiB, 최대 16MiB이고, 기록 하나가 그보다 커도 한 개는 담는다. 이벤트를 받으면 `Count: 0`이 올 때까지 이어서 가져간다. `Gap`은 `After` 바로 뒤에서 버려진 번호 구간, `Live`는 그 컨테이너의 로거가 열려 있는지다. `Container`는 이름이나 ID이고 없으면 not-found. `ack`는 `Upto`번까지를 한 번에 확인한다.

클라우드 확인(0015, SFCP): 가짜 sfcd가 `seafield.logs` 사건을 받아 `MaxBytes 2000`으로 80개(1990바이트)를 가져가 ack, 다음 사건에서 81–151번을 가져감. 조각 offset·digest 확인.
클라우드 확인(0012): 400줄을 `max_bytes=2000`으로 받으면 80개씩, 5번까지 ack한 뒤 `after=0`이면 6~401번 396개가 한 번에 옴.
클라우드 확인(0010): 20ms마다 한 줄씩 8초 동안 400줄 → 이벤트는 5초 상한에서 한 번(seq 227), 멈춘 뒤 한 번(seq 400). 모두 ack하면 조각이 지워지고 다음 줄은 401로 이어짐. `--log-driver none` 컨테이너는 로그 디렉터리도 이벤트도 없음. 잘못된 `notify-quiet`는 컨테이너 생성 단계에서 거절.

## 내장 볼륨 드라이버 `sfc`

패치 0007·0009, `daemon/seafield/volumedrv`, `daemon/seafield/sfcd`.

플러그인이 아니라 엔진에 들어 있는 볼륨 드라이버다. 모든 호출을 [Seafield → sfcd 소켓](sfcd-socket.md#볼륨-드라이버-이름-sfc)으로 바로 넘긴다. 볼륨이 어디에 있고 누가 쓸 수 있는지는 sfcd가 정한다. sfcd는 경로가 아니라 연 디렉터리 fd를 준다. 엔진은 그 fd를 `open_tree`로 복제해 `<exec-root>/volumes/<mount_id>`에 붙이고(읽기 전용이면 `mount_setattr`), 그 경로를 컨테이너에 bind한다. 엔진이 경로를 다시 해석하지 않는다.

- 호출은 엔진 세션의 purpose 35(op `mount`, `unmount`, `create`, `get`, `list`, `remove`, 0015). fd는 mount 답 frame에 실린다.
- sfcd의 not-applied 이유 `not-found`·`conflict`·`invalid`는 엔진의 not found·conflict·invalid parameter로, `not-ready`(이동·복원 중, 세션 없음)는 unavailable, `not-owner`·`refused`는 forbidden으로 바뀐다.
- 컨테이너 없이 오는 마운트(엔진 내부 호출)는 거절한다. sfcd가 거절하면 컨테이너 시작이 실패한다. `remove`는 sfcd가 거절한다(sfcd가 볼륨을 직접 거둔다).
- 클라우드 확인(0015, SFCP): 가짜 sfcd로 rw·ro 마운트, ro 쓰기 실패, not-ready면 시작 실패, `volume ls`, 남은 마운트 없음.
- 해제 때 붙인 마운트를 떼고(`MNT_DETACH`) 디렉터리를 지운 뒤 sfcd에 알린다.
- 한 호출은 최대 2분 기다린다.
- 클라우드 확인(0009, fd 방식): 가짜 sfcd가 넘긴 fd로 쓰기·읽기, 읽기 전용 볼륨은 `ro` 마운트라 쓰기가 Read-only file system으로 실패, `not-ready`면 컨테이너 시작 실패, 끝나면 `<exec-root>/volumes` 마운트가 남지 않음.
- 클라우드 확인(0007): 가짜 sfcd로 `-v appdata:/data --volume-driver sfc` 컨테이너가 sfcd가 준 디렉터리에 쓰고 읽음, 마운트·해제마다 같은 `mount_id`, sfcd가 거절한 새 볼륨은 그 이유로 실패, 허용되지 않은 실행 파일이 연 소켓은 연결 단계에서 거절.

## 내장 네트워크 드라이버 `sfc`

패치 0011, `daemon/seafield/netdrv`.

업스트림 bridge 드라이버 인스턴스 하나를 `bridge`와 `sfc` 두 이름으로 등록한다. `sfc` 네트워크는 단계마다 엔진 세션의 purpose 36으로 sfcd를 동기로 부르고(0015), 답을 받기 전에는 다음 단계로 가지 않는다. `create`는 장치나 기록을 만들기 전에 묻는다.

- 만들기: sfcd가 답한 bridge 장치 이름과 MTU로 만든다. 같은 이름 장치가 이미 있으면 가져다 쓰지 않고 실패한다. masquerade는 끈다. 만든 뒤 실제 MTU·주소를 한 번 돌려준다.
- 붙기: 컨테이너 ID·이름·라벨, 주소, MAC, netns 경로, host 쪽 veth 이름을 보낸다. `allow:false`면 컨테이너 시작이 실패한다. 답의 정적 경로를 sandbox에 넣는다. sysctl은 아직 적용하지 않으므로 답에 있으면 실패한다.
- 떼기·지우기: 엔진 쪽을 먼저 떼고 지운 뒤 sfcd에 알린다(격리 규칙은 마지막에 지워진다). sfcd에 붙기를 알린 endpoint만 떼기를 한 번 알린다.
- 클라우드 확인: 가짜 sfcd로 bridge 이름·MTU 1400 적용, 답의 경로가 컨테이너 라우팅에 들어감, 라벨로 거절하면 시작 실패, 지우면 bridge가 사라짐. 이미 있는 장치 이름 거절은 아직 시험하지 않았다. SFCP로 옮긴 뒤(0015) 같은 시험 다시 통과.

## 복원 때 sfcd 기다리기

패치 0016, `daemon/command/seafield_restart.go`.

- 엔진은 컨테이너를 복원하기 전에 sfcd 세션을 최대 30초 기다린다.
- 업스트림 복원은 재시작 정책 컨테이너를 한 번만 시작하고 실패하면 다시 하지 않는다. Seafield는 sfcd 세션이 올라올 때마다, 정책이 `always`이거나 `unless-stopped`(손으로 멈추지 않음)이고 전에 시작된 적이 있는데 돌지 않는 컨테이너를 다시 시작한다(0·2·5·10·30초 간격).
- 클라우드 확인: sfcd 없이 엔진을 다시 시작하면 볼륨 때문에 복원이 실패하고, 가짜 sfcd가 뜬 뒤 3초 안에 컨테이너가 다시 돎.

## 이미지 원천

패치 0017, `daemon/seafield/imagesrc`. containerd의 `remotes.Resolver`를 sfcd 위에 둔 것이다(업스트림 [pull](https://docs.docker.com/reference/api/engine/version/v1.52/#tag/Image/operation/ImageCreate) API는 그대로).

- `POST /images/create?fromImage=<repo>&tag=sha256:…`를 받으면 엔진은 manifest와 blob을 purpose 37 `manifest`·`blob`으로 sfcd에 묻는다. 요청은 `{Repository, Digest, Offset}`, 답은 `{ContentType, Size}`와 kind 4 조각.
- Repository는 참조에 쓴 이름 그대로다(`reference.FamiliarName`: `docker.io/`·`library/` 생략형). `sfc-cluster-app/web@sha256:…` → `sfc-cluster-app/web`.
- manifest는 엔진이 digest를 다시 확인한다. blob은 containerd가 확인한다. 끊긴 내려받기는 받은 만큼의 offset으로 다시 묻는다.
- sfcd가 `not-found`로 답하면 pull은 "not found"로 끝난다. referrer는 묻지 않는다(빈 목록).
- 클라우드 확인: 가짜 sfcd가 OCI layout으로 busybox를 주고 `sfc-cluster-app/bb@sha256:…` pull·실행 성공. tag pull, 모르는 저장소, push·login·search는 거절. 가짜 sfcd가 받은 요청은 모두 저장소 `sfc-cluster-app/bb`였다.

## exec 프로세스 묶음 감독

패치 0020, `cmd/sfe-runc`, `daemon/seafield/execsup`. sfcd의 lifecycle 검사(exec)가 시간을 넘기면 첫 프로세스만이 아니라 그 exec가 띄운 모든 프로세스를 끝내려고 더했다(Jay 2026-11-28, 0.1.0 전).

업스트림 exec([ContainerExecStart](https://docs.docker.com/reference/api/engine/version/v1.52/#tag/Exec/operation/ExecStart))는 첫 프로세스가 끝나면 끝난 것으로 보고, 그 프로세스가 띄운 자식은 컨테이너 안에 남는다. 업스트림에는 exec를 끝내는 API도 없다.

- **`sfe-runc`**: 기본 runtime의 실행 파일이다(sfed와 같은 디렉터리). `runc exec`가 아니면 그대로 진짜 `runc`(`$SFE_RUNC`, 없으면 PATH의 `runc`)를 실행한다. `runc exec`면 shim이 넘긴 `--pid-file <bundle>/<exec ID>.pid`에서 exec ID를, runc의 `state.json`에서 컨테이너 init PID를 읽는다. 그 다음 컨테이너 cgroup 아래에 `sfe-exec-<exec ID>`를 만들고 `--cgroup sfe-exec-<exec ID>`를 붙여 실행한다. 프로세스를 하나 더 띄우지 않는다. 어디서든 실패하면 그 exec는 업스트림처럼 감독 없이 돈다.
- **`exec_die` 속성**(업스트림 `execID`, `exitCode` 뒤에 더함):

| 속성 | 뜻 |
|---|---|
| `seafield.stdout_bytes`, `seafield.stderr_bytes` | 그 exec가 stdout·stderr에 쓴 바이트 수. 누가 attach했는지와 상관없이 엔진이 FIFO에서 읽은 전부 |
| `seafield.tree` | `ended`: 하위 cgroup에 남은 프로세스가 없다(엔진이 cgroup을 지움). `running`: 첫 프로세스가 끝나고 2초가 지나도 남아 있다. 감독하지 않은 exec에는 없다 |
| `seafield.killed` | `1`: 끝나기 전에 sfcd가 아래 `kill`로 끝냈다 |

- **purpose 38 EngineExec**(sfed가 답함), op `kill`, 요청 `{…Request, ExecID string}`, 답 `{…Reply, Tree string}`.
  - 하위 cgroup의 `cgroup.kill`에 `1`을 쓰고, 비기를 최대 5초 기다린 뒤 cgroup을 지운다.
  - `applied` + `Tree: "ended"`: 지금 끝냈거나 이미 끝나 있었다.
  - `not-applied` `not-found`: 그런 exec가 없다.
  - `not-applied` `not-ready`: 감독하지 않는 exec가 아직 돈다(끝낼 cgroup이 없다).
  - `unknown` `kill-failed`: cgroup.kill이 실패했거나 5초 안에 비지 않았다.
  - exec_die를 기다리는 중(최대 약 4초)이면 그 뒤에 답한다.
- **cgroup v2만**. 공식 지원 Ubuntu LTS는 cgroup v2다. 하위 cgroup은 controller를 켜지 않으므로 컨테이너의 메모리·CPU 제한은 그대로 exec에도 걸린다. 컨테이너가 지워질 때 runc·systemd가 남은 하위 cgroup도 함께 지운다.
- **비용**: exec 시작마다 디렉터리 하나와 파일 두 개를 읽고 쓴다. 클라우드에서 `docker exec … true` 50번씩 세 번 쟀을 때 감독 없이 평균 68.2ms, 감독하면 68.1ms였다(차이는 측정 오차 안).
- **클라우드 확인**(cgroup v2를 마운트한 네임스페이스에서 실제 sfed, runc 1.5.3):
  - `sh -c 'echo abc; echo e >&2'`: `tree=ended`, stdout 4, stderr 2.
  - `sh -c 'sleep 77 >/dev/null 2>&1 & echo hi'`: `tree=running`, stdout 3, 컨테이너에 sleep이 남음. `kill`하면 `applied`/`ended`, sleep 없음.
  - 도는 중인 `sh -c 'sleep 77 & sleep 77'`를 `kill`하면 `exitCode=137`, `killed=1`, `tree=ended`, 손자 sleep까지 없음.
  - 모르는 exec ID는 `not-found`.
