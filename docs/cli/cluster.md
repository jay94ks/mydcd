# mydc cluster: 돌아가는 클러스터

클러스터 전체의 합의 상태와 서버 사이 연결을 보고 손본다. 이 컴퓨터의 접속 설정은 `mydc context`가 맡는다.

| 명령 | 하는 일 |
|---|---|
| `cluster status` | 리더, term, 투표 멤버·quorum·응답 수, 서버별 역할·적용 index·지연(시스템 관리자) |
| `cluster status --writes` | 리더가 지금 term에 Raft 로그에 쓴 항목 수를 종류별로 보여 준다. 가만히 있는 클러스터는 늘지 않아야 한다. 리더만 세므로, 접속한 서버가 리더가 아니면 context에 있는 리더 주소로 다시 묻는다(시스템 관리자) |
| `cluster mesh [--node NODE] [--all]` | 서버 사이 링크 상태. 기본은 작업 공간이 쓰는 서버만 |
| `cluster reconnect NODE PEER` | `mesh`에서 끊긴 NODE→PEER 링크를 다시 맺고 끝날 때까지 따라간다(시스템 관리자) |
| `cluster compact [--nodes a,b] [--minimal [--retain N]] [--parallel]` | 서버의 복제 로그를 snapshot으로 줄인다. 기본은 투표 멤버를 하나씩, 리더는 마지막(시스템 관리자) |
| `cluster cli-policy` | 서버 자신의 키로 관리 명령을 내는 것을 막았는지 본다 |
| `cluster cli-policy block\|allow` | 막거나 푼다. 바꿀 때 등록된 사용자 승인 세션이 필요하다 |

- `status`는 연결한 서버가 마지막으로 적용한 상태다. quorum 읽기를 기다리지 않으므로 STALE 열을 먼저 본다.
- `reconnect`와 `compact`는 계획을 먼저 보여 준다. `--dry-run`은 계획만, `--no-wait`은 접수만 하고 나간다. 끊기면 `mydc op show ID`.
- `compact --minimal`은 설정된 보존 개수보다 늘리지 않는다.

자세한 동작은 [합의 로그 유지보수](../reference/raft-maintenance.md), [터널 재연결](../reference/tunnel-reconnect.md), [노드 관측](../reference/node-observations.md).
