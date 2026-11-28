# sfed 설정 견본

sfed 바이너리와 유닛은 노드 데몬 패키지(`sfcd`)에 들어간다. 패키지 정의와 유닛 원본은 [packaging/](../../packaging/README.md)에 있다.

| 파일 | 놓는 곳 |
|---|---|
| [daemon.json](daemon.json) | `/etc/sfe/daemon.json`. 직접 두지 않는다. sfed.service가 시작 전에 node.yaml로 다시 쓴다 |

- containerd·runc는 패키지에 든 것(`…/lib/sfc/bin/`)을 쓴다. 시스템 containerd·runc 패키지에 의존하지 않는다. sfed.service가 `PATH`와 `SFE_RUNC`로 그 디렉터리를 먼저 보게 한다.
- 커널 6.5 이상(`SO_PEERPIDFD`), cgroup v2 단일 계층, PSI 켬.
- 노드별로 바꾸는 값은 `features.buildkit`(빌드 끄기), `log-opts`의 `notify-quiet`·`notify-max-wait`·`max-size`뿐이다. `node.yaml`의 `engine` 블록에 적으면 sfed.service의 `ExecStartPre`(`sfcd --config /etc/sfc/node.yaml engine-config`)가 sfed를 시작하기 전에 이 파일을 다시 쓴다(node.yaml). 견본 daemon.json은 `engine`이 비었을 때 나오는 내용과 같다(시험이 확인). 바꾸면 sfed를 다시 시작해야 하고, 로그 값은 새 컨테이너부터 적용된다(`live-restore`라 컨테이너는 계속 돈다).
- `sfed.sock`에는 sfcd만 붙는다. docker CLI로 진단하려면 unit에 `Environment=SEAFIELD_ALLOWED_PEERS=<sfcd 경로>:<docker 경로>`를 잠시 넣는다.
- sfcd와 시작 순서를 강제하지 않는다. sfed는 sfcd 세션을 30초까지 기다리고, 늦게 붙으면 막혔던 컨테이너를 그때 시작한다.
