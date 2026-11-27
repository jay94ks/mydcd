# 바꾼 것·지운 것

업스트림 `docker-v29.10.1` 대비. 패치 번호는 [series](../series) 순서다.

| 패치 | 바뀐 것 | 업스트림과 다른 동작 |
|---|---|---|
| prune + 0001 | 외부 로그 드라이버 제거: awslogs, etwlogs, fluentd, gcplogs, gelf, journald, splunk, syslog | `--log-driver`로 이 이름을 주면 "plugin not found"로 거절. 남은 것은 `json-file`, `local` |
| prune + 0002 | Swarm 모드 없음. swarm·checkpoint·plugin API 라우터 제거 | `/swarm`, `/services`, `/nodes`, `/tasks`, `/secrets`, `/configs`, `/plugins`, `/containers/{id}/checkpoints`는 404. `info`의 Swarm은 항상 `inactive`. swarm 범위 네트워크·볼륨은 조회되지 않고 만들 수 없음 |
| 0003 | 수신은 unix 소켓만 | `-H tcp://…`, `fd://` 등은 시작 거부. TLS 옵션은 쓸모없음 |
| 0003 | 소켓 권한 root `0600` | `--group`(기본 `docker`)은 무시됨. root 아닌 사용자는 접속 불가 |
| 0003 | 접속마다 상대 확인 | 허용 목록에 없는 실행 파일의 접속은 요청을 읽기 전에 끊김. [더한 것](additions.md#접속-상대-확인) |
| 0004 | 이벤트를 받을 때마다 Seafield 이벤트 열에도 기록 | 기존 `/events` API는 그대로. [더한 것](additions.md#번호-붙은-이벤트-열) |
| 0005 | 컨테이너 cgroup 알림을 이벤트로 | `/events`에 `seafield.memory`, `seafield.pressure` 동작이 더 나온다. [더한 것](additions.md#cgroup-알림-이벤트) |
| 0006, 0010, 0012 | 로그 드라이버 `seafield-queue` 추가 | 엔진은 로그를 보관하지 않는다(sfcd가 가져가 ack하면 지움). `/events`에 데이터 없는 `seafield.logs` 이벤트가 더 나온다. 이 드라이버에서는 `docker logs`(`/containers/{id}/logs`)가 "does not support reading"으로 거절된다. [더한 것](additions.md#로그-queue) |
| 0007 | 내장 볼륨 드라이버 `sfc` 등록(상대 확인 코드는 `daemon/seafield/peer`로 옮김) | `volume ls`에 `sfc` 드라이버 볼륨이 함께 보인다. sfcd가 없으면 그 드라이버의 호출만 실패한다. [더한 것](additions.md#내장-볼륨-드라이버-sfc) |

| 0008 | 빌드는 BuildKit만. classic builder를 띄우지 않음 | `version=2`가 아닌 `/build`는 "seafield builds only with BuildKit"으로 거절. `commit`·`import`의 `--change` 해석은 그대로 |
| 0008 | `features.buildkit: false`면 이 노드는 빌드하지 않음 | 업스트림은 classic builder로 바꾸지만 Seafield는 BuildKit을 띄우지 않고 `/build`, `/build/prune`, `/session`, `/grpc`를 내지 않는다(404). `system df`에 빌드 캐시가 빠진다. sfc `node.yaml`의 노드별 빌드 끄기가 이 값을 쓴다 |
| 0009 | 볼륨 마운트 설정에 컨테이너 ID를 함께 넘김(`mounts.WithContainer`), 볼륨 래퍼에 `Unwrap`·`MountFor` | 다른 드라이버의 동작은 같다. `sfc` 드라이버만 컨테이너별로 마운트한다. [더한 것](additions.md#내장-볼륨-드라이버-sfc) |
| 0011 | bridge 드라이버를 `sfc` 이름으로도 등록(`bridge.Wrappers`), endpoint에 host 쪽 veth 이름 기록, Join에 컨테이너 ID 전달 | `bridge` 네트워크의 동작은 같다. [더한 것](additions.md#내장-네트워크-드라이버-sfc) |
| 0014 | 클러스터의 `pkg/sfcp/wire`·`enginemux` 사본(`daemon/seafield/sfcp`). `seafield/sfcp-copy.sh check`로 같은지 확인 | 동작 변화 없음 |
| 0015 | 엔진 쪽 HTTP 추가 경로(`/seafield/events`, `/seafield/logs/…`)를 없애고 엔진 전용 SFCP 세션으로 옮김 | 0004·0012가 더한 HTTP 경로는 404. [sfcd 소켓](sfcd-socket.md) |
| 0016 | 복원 때 sfcd 세션을 기다리고, 그 전에 시작 못 한 재시작 정책 컨테이너를 세션이 올라오면 다시 시작 | 업스트림은 복원 시작 실패를 다시 하지 않는다. [더한 것](additions.md#복원-때-sfcd-기다리기) |
| 0013 | v1 플러그인 찾기를 끔(`/run/docker/plugins`, `/etc/docker/plugins`, `/usr/lib/docker/plugins`) | 같은 서버의 Docker용 플러그인이 붙지 않는다. `--volume-driver`·`--authorization-plugin` 등으로 외부 플러그인 이름을 주면 "plugin not found". 플러그인 설치 API는 0002에서 이미 없음 |
| 0017 | 이미지는 sfcd에서만 받는다(engine socket purpose 37). registry host·endpoint·login·search를 모두 끔 | `pull`은 `name@sha256:…`만 받는다(tag는 "pull needs name@sha256"으로 거절, 이름만 주는 전체 tag pull도 없음). `push`, `login`, `search`는 "the engine does not use registries"로 거절. BuildKit도 registry에 접속하지 않는다. `registry-mirrors`, `insecure-registries`는 쓸모없음. containerd 이미지 저장소에서만 받는다(graphdriver 저장소의 pull은 거절). [더한 것](additions.md#이미지-원천) |
| 0018 | 0014 사본 갱신(`CheckPeerExe`) | 동작 변화 없음 |
| 0019 | `--version`이 엔진 이름을 찍고, 소켓 그룹 기본값을 없앰 | `sfed --version`은 "Seafield engine (sfed) version …". `--group`(`group`) 기본값이 `docker`에서 없음으로 바뀌어 소켓 그룹은 root다(0003대로 mode 0600). |
| 0020 | 기본 runtime(`runc`, `io.containerd.runc.v2`)의 실행 파일이 sfed 옆의 `sfe-runc`. exec마다 하위 cgroup에서 돌고, `exec_die` 속성이 늘어남 | 컨테이너 실행은 같다. `runc exec`만 `--cgroup sfe-exec-<exec ID>`가 붙는다. `exec_die`는 첫 프로세스가 끝난 뒤 남은 프로세스를 최대 2초 더 기다린다(업스트림도 출력 스트림을 2초 기다린다). `sfe-runc`가 없으면 경고 한 번 남기고 업스트림처럼 `runc`를 쓴다. `docker info`의 runtime 경로가 `sfe-runc`로 보인다. [더한 것](additions.md#exec-프로세스-묶음-감독) |

## 패치하지 않고 설정으로 하는 것

노드 패키지의 `daemon.json`이 준다. 업스트림 옵션 그대로다. 견본은 [packaging](../packaging/).

| 설정 | 값 | 이유 |
|---|---|---|
| `data-root` | `/var/lib/sfe` | Docker(`/var/lib/docker`)와 겹치지 않게 |
| `exec-root`, `pidfile` | `/run/sfe`, `/run/sfe/sfed.pid` | 같은 이유 |
| `hosts` | `unix:///run/sfe/sfed.sock` | 같은 이유 |
| `userland-proxy` | `false` | 포트 공개는 sfcd(ingress)가 다룸 |
| `bridge` | `none` | 기본 bridge(`docker0`) 없음 |
| `iptables`, `ip6tables` | `false` | 방화벽 규칙은 sfcd가 다룸 |
| `log-driver` | `seafield-queue` | 로그는 sfcd가 보관 |
| `log-opts` | `{"cache-disabled": "true"}` | 엔진이 따로 읽기용 사본(dual logging)을 남기지 않게 |
| `live-restore` | `true` | 엔진을 다시 시작해도(설정 적용 등) 컨테이너는 계속 돈다 |

전용 containerd는 dockerd가 `exec-root` 아래에 직접 띄우는 것을 쓴다(시스템 containerd를 공유하지 않음).
