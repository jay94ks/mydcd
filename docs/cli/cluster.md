# sfcli cluster: 돌아가는 클러스터

클러스터 전체의 합의 상태와 서버 사이 연결을 보고 손본다. 이 컴퓨터의 접속 설정은 `sfcli context`가 맡는다.

| 명령 | 하는 일 |
|---|---|
| `cluster status` | 리더, term, 투표 멤버·quorum·응답 수, 서버별 역할·빌드 버전·적용 index·지연. 서버 버전이 섞여 있으면 "Versions are mixed: 0.1.0 ×2, 0.1.1 ×2" 한 줄을 더 보인다. 팔로워는 자기와 리더만 세므로, 접속한 서버가 리더가 아니면 context에 있는 리더 주소로 다시 묻는다. 리더 주소가 없거나 리더에 닿지 못하면 팔로워가 본 값을 그대로 보이고 그 이유를 한 줄 알린다(`--writes`는 오류로 끝난다)(시스템 관리자) |
| `cluster upgrade status` | 업그레이드 중 확인용. 접속한 서버와 그 빌드, 버전이 섞였는지, 클러스터 전체가 지금 쓸 수 있는 기능(모든 서버의 교집합), 서버별 빌드·기능과 다른 서버보다 모자란 기능(`lacks`)을 보인다. 아직 보고가 없는 서버는 모자라다고 하지 않는다. `-o json` 지원(시스템 관리자) |
| `cluster status --writes` | 리더가 지금 term에 Raft 로그에 쓴 항목 수를 종류별로 보여 준다. 가만히 있는 클러스터는 늘지 않아야 한다. 리더만 세므로, 접속한 서버가 리더가 아니면 context에 있는 리더 주소로 다시 묻는다(시스템 관리자) |
| `cluster mesh [--node NODE] [--all]` | 서버 사이 링크 상태. 기본은 작업 공간이 쓰는 서버만 |
| `cluster reconnect NODE PEER` | `mesh`에서 끊긴 NODE→PEER 링크를 다시 맺고 끝날 때까지 따라간다(시스템 관리자) |
| `cluster compact [--nodes a,b] [--minimal [--retain N]] [--parallel]` | 서버의 복제 로그를 snapshot으로 줄인다. 기본은 투표 멤버를 하나씩, 리더는 마지막(시스템 관리자) |
| `cluster backup create --out FILE (--backup-key-file F \| --backup-password-file F)` | 클러스터 상태와 마스터 키를 암호화한 파일 하나로 받는다(시스템 관리자). 키 파일이나 비밀번호 파일을 주지 않으면 터미널에서 비밀번호를 두 번 묻는다 |
| `cluster backup verify FILE (--backup-key-file F \| --backup-password-file F)` | 서버 없이 백업 파일을 끝까지 풀어 서명·snapshot·마스터 키를 확인한다 |
| `cluster backup keygen --out F` | 새 백업 키 파일(32바이트, hex, mode 0600)을 만든다 |
| `cluster cli-policy` | 서버 자신의 키로 관리 명령을 내는 것을 막았는지 본다 |
| `cluster cli-policy block\|allow` | 막거나 푼다. 바꿀 때 등록된 사용자 승인 세션이 필요하다 |

- `status`는 연결한 서버가 마지막으로 적용한 상태다. quorum 읽기를 기다리지 않으므로 STALE 열을 먼저 본다.
- `reconnect`와 `compact`는 계획을 먼저 보여 준다. `--dry-run`은 계획만, `--no-wait`은 접수만 하고 나간다. 끊기면 `sfcli op show ID`.
- `compact --minimal`은 설정된 보존 개수보다 늘리지 않는다.
- `backup create`는 먼저 `cluster-backup` 작업(누가, 언제)을 클러스터에 기록하고, 그 작업으로 voter에게서 파일을 받는다. 접속한 서버가 voter가 아니면 리더에게 넘긴다. 백업 키는 이 컴퓨터를 떠나지 않는다.
- cron이나 systemd timer에서는 `SFC_NONINTERACTIVE=1`, `SFC_WALLET_PASSWORD_FILE`, `--backup-key-file`로 묻지 않고 돈다. 다 받고 확인한 뒤에만 `--out` 이름으로 바꾸므로 중간에 끊겨도 반쪽 파일이 남지 않는다.
- 백업 키와 백업 파일은 클러스터 밖에 둔다. 둘을 함께 가진 사람은 클러스터의 인증서 키와 저장한 자격 증명을 모두 열 수 있다.

자세한 동작은 [클러스터 백업](../reference/cluster-backup.md), [합의 로그 유지보수](../reference/raft-maintenance.md), [터널 재연결](../reference/tunnel-reconnect.md), [노드 관측](../reference/node-observations.md).

## 방화벽

`sfcli firewall`은 node.yaml `firewall.managed: true`인 모든 서버에 같이 걸리는 클러스터 방화벽이다. 기본 정책과 공통 규칙(ID `c1`, `c2`, …)을 Raft에 두고, 각 서버는 자기 규칙 아래에 이것을 적용한다. 시스템 관리자 명령이다. 자세한 동작: [서버 방화벽](../reference/node-firewall.md#클러스터-방화벽).

| 명령 | 하는 일 |
|---|---|
| `firewall show` | 클러스터 정책, revision, 규칙(필수 먼저) |
| `firewall allow\|deny tcp/PORT\|udp/PORT\|icmp\|any [--from PREFIX]... [--required] [--comment TEXT]` | 규칙 하나 추가. `--required`면 서버 규칙보다 먼저 판정해 어느 서버도 덮어쓸 수 없다 |
| `firewall update RULE [--action] [--match] [--from]... [--from-anywhere] [--required=true\|false] [--comment]` | 준 칸만 바꾼다 |
| `firewall remove RULE...` | 규칙 빼기 |
| `firewall policy return\|drop` | 정책을 따르는(`inherit`) 서버의 안 걸린 연결. `drop`이면 한 번 묻는다(`-y`로 넘김) |

```sh
sfcli firewall allow tcp/22 --from 192.168.1.0/24 --required --comment "로컬 망 SSH"
sfcli firewall deny tcp/2375 --required --comment "엔진 API 막기"
sfcli firewall policy drop
```

읽은 revision을 붙여 보내므로 그 사이 다른 사람이 바꿨으면 거절된다. 변경은 Raft 기록과 이벤트 `cluster-firewall-changed`로 남는다.

