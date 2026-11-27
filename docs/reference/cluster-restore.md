# 전체 복구 (`sfcd restore`)

voter를 **모두** 잃었을 때(화재, 디스크 동시 손상, 실수로 state_dir 삭제) 새 서버 한 대에서 [클러스터 백업](cluster-backup.md) 파일로 같은 클러스터를 다시 세운다. 남은 voter가 있으면 쓰지 않는다. 과반만 잃었으면 [정족수 복구](quorum-recovery.md)를 쓴다. 설계는 devel/design/cluster-backup-and-recovery.md의 B4다.

## 절차

새 서버에서, sfcd를 켜기 전에 한 번 실행한다.

```sh
sfcd --config /etc/sfc/node.yaml restore --backup lab-20261127.sfcbak --backup-key-file ./backup.key --request-id restore-1
systemctl enable --now sfcd
sfcli context trust ...   # 새 서버의 키를 CLI context에 더한다
```

1. node.yaml은 새 서버의 것이다. `node.id`는 백업에 없는 **새 이름**이어야 한다(옛 이름은 기록에 남아 다시 쓰지 않는다). `node.listen`은 옛 서버의 주소여도 된다. state_dir은 비어 있어야 하고, 신원 디렉터리가 비어 있으면 새 신원을 만든다.
2. 명령은 백업 파일 전체를 풀어 `sfcli cluster backup verify`와 같은 검사(서명, 마스터 키, snapshot 바인딩·digest·엄격한 decode)를 한다. 키는 `--backup-key-file` 또는 `--backup-password-file`(mode 0600)로 준다.
3. 클러스터 ID, 백업 정보, 잃을 서버 목록, 이 서버가 유일한 voter가 된다는 것을 보여 준다. 클러스터 ID 앞 8자리를 입력해 확인한다. 터미널이 없거나 `SFC_NONINTERACTIVE=1`이면 `--confirm-cluster XXXXXXXX`를 준다.
4. 설치 기록(intent `restore`)을 쓰고, snapshot과 서명한 계획을 `control/`에 둔 뒤 runtime을 한 번 연다. engine이 Raft를 시작하기 전에 계획을 실행한다(아래 "실행").
5. 구성을 설치 기록에 남기고, 백업의 마스터 키를 이 서버 신원으로 봉인해 저장한 뒤 닫는다.
6. `sfcd`를 시작하면 이 서버 혼자 리더가 된다. 관리자는 같은 wallet으로 다시 로그인한다. 다른 서버는 평소대로 `invite`·`join`·`promote`한다.

같은 `--request-id`로 다시 실행하면 이미 끝난 단계는 건너뛴다.

## 실행 (`cluster.Open`)

Raft 상태가 없는 state root에 계획(`restore-plan.json`)과 snapshot(`restore-snapshot.mds1`)이 있으면:

1. snapshot을 FSM에 복원하고 계획의 digest·위치(Raft index·term)와 맞는지 본다.
2. 새 구성(이 서버만 voter)을 index `RaftIndex+1`로 두고, 같은 index에 계획의 명령(member report `restored`)을 적용한다. 평소 reducer가 그대로 검사한다. 거부되면 시작하지 않는다.
3. 그 index·term으로 첫 Raft snapshot을 만들고 Raft의 현재 term을 백업의 term으로 둔다.
4. 계획과 snapshot 파일을 지운다.

3 뒤에 멈췄으면(Raft 상태와 계획이 함께 남음) 다음 시작은 가장 새 snapshot이 계획의 것(`RaftIndex+1`, term, 이 서버만 voter)일 때만 4를 마저 한다. 그 밖에는 시작하지 않는다.

## 클러스터 기록

`lifecycle.ClusterRestore`는 `Schema`, `Cluster`, `RequestID`, `Node`, `Key`, `Endpoint`, `Backup`(백업 operation), `RaftIndex`, `Term`, `StateIndex`, `Generation`, `CreatedAt`, `Signature`를 가진다. 서명은 새 서버의 신원 키로 `"sfc-cluster-restore-1\x00"` 뒤에 Signature를 뺀 JSON을 붙인 바이트에 한다.

member report `restored`의 조건:

- 보고자가 기록의 키이고, 기록의 `StateIndex`가 지금 상태의 명령 순번과 같다. 그래서 그 snapshot 바로 뒤에서만 맞는다.
- `Generation`이 지금까지의 복원 수 + 1이다.
- 새 서버의 이름·키가 디렉터리에 없다(돌아간 서버의 키 이력 포함).
- 다른 서버가 SFCP로 보낸 `restored`는 받지 않는다. 오프라인 시작만 적용한다.

받으면:

- 백업의 모든 멤버는 `retired`가 되고 노드 기록에 `Restored`(세대)가 남는다. `node remove --force`가 끝난 뒤와 같다. SFCP 접속을 받지 않고, 서버 주소와 endpoint를 풀어 준다.
- Raft에 닿지 못한 초대는 잊는다. 그 서버는 새 초대로 가입한다.
- 빠진 서버를 기다리던 제거 작업은 정산한다.
- 새 서버는 `Restore` 기록을 가진 active voter로 디렉터리에 들어가고 새 서버 주소를 받는다.
- topology가 복원 기록 목록(`Restores`)을 가진다. 세대 번호는 그 길이다.

옛 서버가 소유하던 컨테이너·볼륨·망 기록은 force removal과 같은 규칙으로 "돌아오지 않는 서버의 기록"이 된다. 원하는 상태는 남아 있으므로 새 서버가 가입하면 배치 규칙대로 앱을 다시 놓는다. 서버와 함께 잃은 볼륨은 되살리지 않는다.

## 세대

같은 백업으로 두 번 복원하면 같은 클러스터 ID의 클러스터가 둘 생긴다. 둘은 서로의 서버를 받지 않는다. 각자의 voter 키는 상대 디렉터리에 없고, 옛 멤버는 양쪽에서 `retired`이며, 백업 뒤의 초대는 어느 쪽에도 없다. 그래도 같은 백업은 한 서버에서만 복원한다.

## 주의

- 옛 클러스터의 서버를 옛 state로 다시 켜지 않는다. 옛 voter들이 과반을 이루면 옛 구성으로 따로 돈다. state를 지우고 새 이름으로 가입한다.
- 컨테이너 엔진(Seafield `sfed`)의 상태는 클러스터 백업에 없다. 이미지·볼륨·컨테이너 로그는 서버와 함께 잃은 것으로 보고, 새 서버의 엔진은 빈 상태(`/var/lib/sfe`)에서 시작한다. sfcd가 보관한 컨테이너 로그도 백업 대상이 아니다. restore와 recover는 엔진 소켓을 쓰지 않는다. 앱은 가입한 서버에 배치 규칙대로 다시 놓이고, 이미지는 그때 registry에서 다시 받는다. 내장 registry 이미지는 [`sfcli registry export`](../cli/registry.md)로 따로 남긴다.
- 백업 뒤에 바뀐 상태는 없다. 백업 뒤에 만든 사용자·작업 공간·앱 변경은 다시 한다.
- CLI context는 옛 서버 키만 믿고 있으므로 새 서버 키를 `sfcli context trust`로 더한다. 로그인 세션은 다시 만든다.
- 업그레이드: 백업 manifest에 `Admin`, `TrustRoot`, `Genesis`가 더해져 이 버전 전의 백업 파일은 열리지 않는다. 새 member report action, 노드·디렉터리 기록 필드, 설치 intent가 생겨 모든 노드의 sfcd를 함께 바꾼다. 저장 형식은 그대로다.
