# 정족수 복구 (`sfcd recover`)

voter 과반을 **영구히** 잃었을 때(디스크가 죽어 돌아오지 않는 서버) 남은 voter만으로 클러스터를 다시 세운다. 잠시 멈춘 것(정전·재부팅)이면 쓰지 않는다. 서버가 돌아오면 그대로 이어진다. 과반이 남아 있으면 이 명령은 거부하고, 잃은 서버는 `sfcli node remove --force`로 뺀다. 설계는 devel/design/cluster-backup-and-recovery.md의 B2다.

## 절차

남은 voter **각각**에서, sfcd를 멈추고 **같은 `--voters` 목록과 같은 `--request-id`**로 실행한다.

```sh
systemctl stop sfcd
sfcd --config /etc/sfc/node.yaml recover --voters jay2 --request-id recover-20261127
systemctl start sfcd
```

1. 명령은 state root를 잠그고(sfcd가 돌고 있으면 실패) 로컬 Raft 구성, 마지막 log index와 term, 복구 뒤 voter, 잃을 서버를 보여 준다.
2. 마지막 log index를 입력해 확인한다. 터미널이 없거나 `SFC_NONINTERACTIVE=1`이면 `--confirm-index N`을 준다. 보여 준 값과 다르면 거부한다.
3. 이 서버의 신원 키로 서명한 계획을 `state_dir/control/recovery-plan.json`에 쓴다. 아직 아무것도 바꾸지 않는다.
4. 다음 `sfcd run`이 Raft를 시작하기 전에 계획을 실행한다(아래 "실행"). 결과는 `control/recovery.json`에 남는다.
5. 새 리더가 첫 구성 변경으로 서명한 계획을 클러스터에 기록한다(member report `recovered`). 각 서버는 자기 결과의 잃은 서버가 모두 `retired`로 보이면 결과 파일을 지운다(다른 서버의 계획이 기록되었어도 같다).
6. 클러스터가 다시 쓸 수 있게 되면 새 서버를 평소대로 `invite`·`join`·`promote`한다.

## 검사

| 조건 | 거부 이유 |
|---|---|
| `--voters`에 이 서버가 없음 | 자기 자신을 빼는 복구는 없다 |
| 목록에 지금 voter가 아닌 서버가 있음 | 목록은 지금 voter 중에서 고른다 |
| 목록이 voter를 하나도 빼지 않음 | 복구할 것이 없다 |
| 목록의 voter가 과반 | 정족수가 남아 있다. `node remove --force`를 쓴다 |
| 확인한 index가 마지막 log index와 다름 | 본 적 없는 상태로 계획하지 않는다 |
| 계획 뒤 로컬 Raft 구성·마지막 index·term이 바뀜 | 실행 때 다시 본다 |
| 이전 복구 결과가 아직 클러스터에 기록되지 않음 | 하나씩 한다 |

## 실행 (`cluster.Open`)

SDK의 `RecoverCluster`와 같은 일을 하되 durable FSM에 맞게 두 가지가 다르다.

- 가장 새 snapshot과 log 전체를 FSM에 다시 적용한다. 구성 항목도 FSM에 보인다. 아직 커밋되지 않았던 항목도 이때 커밋된 것으로 본다(SDK와 같다).
- 새 구성은 목록의 voter, 지금 non-voter 전부, 나머지 voter는 뺀 것이다. 구성 index는 `LastIndex+1`이다(SDK는 1). 그래야 클러스터가 기록했던 어느 구성보다 새롭다.

그 다음 결과 파일을 쓰고, 그 index·term으로 snapshot을 만들고, 계획의 마지막 index까지의 log를 지우고, 계획 파일을 지운다. snapshot을 만든 뒤 멈췄으면(계획·결과 파일과 그 snapshot이 남음) 다음 시작이 남은 단계만 마저 한다.

## 클러스터 기록

`lifecycle.Recovery`는 다음 필드를 가진다: `Schema`, `Cluster`, `RequestID`, `Node`, `Key`, `Voters`(정렬), `PreviousIndex`, `LastIndex`, `Term`, `CreatedAt`, `Signature`. 서명은 `"sfc-cluster-recovery-1\x00"` 뒤에 Signature를 뺀 JSON을 붙인 바이트에 대한 Ed25519 서명이다. member report `recovered`가 `Recovery`와 설치된 `Configuration`을 함께 보낸다. reducer(`Topology.Recover`)가 받는 조건은 다음과 같다.

- 서명이 맞고 계획의 `Node`가 새 구성의 voter이며 키가 같다.
- 새 구성의 index가 `LastIndex+1`이고 지금 topology 구성보다 크다.
- 새 구성의 멤버는 모두 지금 구성에 같은 키와 자격으로 있다.
- 새 구성의 voter가 계획의 `Voters`와 같다.

reducer는 Raft가 실제로 돌리는 구성을 볼 수 없다. 그래서 리더가 다른 서버에게서 보고를 받을 때 자기 SDK 구성(`InstalledConfiguration`)과 index·멤버·자격이 같은지 먼저 본다. 같지 않으면 받지 않는다. voter 하나의 node root만으로 아직 Raft에 있는 다른 voter를 `retired`로 만들 수 없다.

받으면 빠진 멤버는 곧바로 `retired`가 되고 노드 기록에 `Recovery`가 남는다. `node remove --force`가 끝난 뒤와 같은 상태다. SFCP 접속을 받지 않고 서버 주소(`10.254.240.0/20`)를 풀어 준다. 이름은 기록에 남아 다시 쓰지 않는다. 따로 `remove --force`를 할 필요는 없다. 빠진 서버를 기다리던 제거 작업은 정산한다.

## 잃었다던 서버가 돌아오면

결과 파일이 남아 있는 동안 runtime은 빠진 서버의 SFCP 접속을 거부한다. 기록된 뒤에는 `retired`라서 거부한다. 남은 쪽은 빠진 서버의 표나 쓰기를 받지 않는다. 하지만 빠진 서버들끼리 옛 구성의 과반을 이루면 그쪽에서 리더를 뽑아 따로 쓰기를 받을 수 있다. 그래서 돌아온 서버는 **켜기 전에** state를 지우고 새 신원·새 이름으로 다시 가입한다.

## 주의

- 서로 다른 목록으로 두 서버에서 돌리면 클러스터가 둘로 갈라진다. 모든 남은 voter에서 같은 목록을 쓴다.
- 잃었다던 서버를 그대로 켜지 않는다. 옛 state로 과반을 이루면 옛 구성으로 따로 돈다. 먼저 state를 지운다.
- 각 서버의 결과 index는 그 서버의 마지막 log에 따라 다를 수 있다. 선거에서 가장 앞선 서버가 리더가 되고, 다른 서버는 리더의 snapshot을 받는다. 리더의 계획만 기록된다.
- 업그레이드: 새 member report action과 노드 기록 필드가 생겨 모든 노드의 sfcd를 함께 바꾼다. 저장 형식은 그대로다.
