# 노드 대화형 shell

`mydc node shell`은 현재 MyDC 사용자 권한으로 대상 노드의 전용 OS 계정 `mydc-shell`에 접속한다. CLI→노드는 인증된 MYDCP를 사용하고, 대상 `mydcd`가 그 노드의 기존 loopback SSH 서버에 PTY를 연다. 클러스터·사용자·노드 선택은 [CLI 설정](../configuration/cli.md), 전송 형식은 [Unix API](unix-sockets/20-shell-purpose19.md)를 따른다.

## 명령

명령 사용법은 [mydc node shell](../cli/node.md#셸)에 있다. 이 명령군은 cluster/node 범위이며 기본 tenant가 대상 노드를 바꾸지 않는다. `USER`는 MyDC 계정의 `User` ID이고, OS 계정은 항상 `mydc-shell`이다.

세 정책 변경(클러스터 기본값, 서버별 설정, grant)은 모두 `node shell policy`의 **공유 Policy.Revision**을 CAS로 쓴다. CLI가 보내기 직전에 읽고, 스크립트는 `--if-revision`으로 고정한다. `RootRevision`은 준비/세션 보고도 갱신하는 저장 checkpoint revision이므로 정책 revision과 구분한다. 그래서 shell 사용자 명령은 읽은 뒤 노드 보고가 root를 옮겨도 그대로 적용된다(root가 지금보다 크면 거부). 정책 변경은 정책 revision으로, open은 지금 준비 상태로 확인한다. shell open/close는 내부 Expected=0을 사용한다. 끊긴 변경은 `mydc op show|resume ID`로 이어 간다.

새 클러스터의 기본 정책은 `Enabled=false`, `MaxSessions=4`, `IdleSeconds=1800`, `Account=mydc-shell`이다. 노드의 기본 설정은 `Shell=inherit`, `Sudo=false`다. `inherit`은 전역 기본값을 따르고 `on`/`off`는 노드에서 이를 덮어쓴다. 전역 `Enabled=false`도 명시 `on` 노드의 사용을 해제하지 않으므로, 그 노드를 닫으려면 `node shell policy NODE --shell off`를 사용한다.

## 활성화와 권한

1. 운영자가 아래 로컬 SSH 전제 조건을 준비한다.
2. 시스템 관리자가 정책을 변경한다. `mydcd`는 effective enabled인 자기 노드만 계정·키·sudo 상태를 준비하고 서명된 readiness를 보고한다.
3. 일반 사용자에게 필요한 노드 grant를 등록하고 `node shell policy`의 해당 노드 READY를 확인한다.
4. 사용자가 `node-shell` scope를 가진 현재 로그인으로 새 원 세션을 연다.

```sh
mydc --user admin node shell policy
mydc --user admin node shell policy node-a --shell on
mydc --user admin node shell grant alice node-a
mydc --user alice node shell policy
mydc --user alice node shell node-a
mydc --user alice node shell sessions
```

정책·grant 변경과 명시 강제 종료에는 현재 시스템 관리자·`ManageCluster` scope 및 credential의 해당 operation 허용이 필요하다. shell을 여는 사용자는 현재 로그인 서명/credential·issuer·계정 상태, 전역 `*` scope의 `node-shell`, 해당 노드 grant를 모두 만족해야 한다. 시스템 관리자 계정은 별도 grant 없이 노드를 선택할 수 있지만 로그인 scope·현재 정책·readiness 검사는 계속 적용된다. tenant manager 역할 자체는 노드 shell grant가 아니다. `disable_node_cli_operation`이 켜진 클러스터에서도 등록 사용자 키의 독립 승인과 현재 허용 사용자 검사를 통과해야 하며 노드 키로 이를 대신하지 않는다.

계정/credential의 operation ceiling은 open에 `open-node-shell`, 관리자 설정에 `set-node-shell-policy|set-node-shell-node|set-node-shell-grant`, 종료에 `close-node-shell`을 사용한다. 과거 로그인에 `node-shell` scope가 없다면 새 로그인으로 필요한 scope를 받아야 한다. 일반 정책 조회는 자기 grant/그 노드만, 세션 목록은 자기 기록만 공개한다. `ManageCluster` 관리자는 전체 정책·세션을 조회한다.

준비 보고는 현재 설치된 대상 노드 키가 서명하며 현재 policy revision·effective sudo와 일치하고 30초 이내여야 한다. 계정 준비나 SSH 접속 확인만으로 사용자 open 권한이 생기지 않는다. 새 open은 quorum에서 원 사용자 operation을 먼저 `queued`로 수락하고, 인증된 stream 소비가 그 원 기록의 PTY를 실제 연다. 대기·열림·종료 중 상태는 실제 `closed` 보고까지 사용자/노드 한도에 포함한다. Transport의 purpose19 handler 한도는 64개이며 정책 한도와 별개다.

관리 open의 원 거부 결과는 `Result.Code`와 `Result.Reason`으로 보존한다. `17/node-shell-disabled`, `18/node-shell-not-ready`, `19/limit`, `20/node-unreachable`이며 기존 코드 0–16은 그대로다. 사용자 권한 거부는 기존 `Forbidden`(4), 낡은 CAS는 `ConditionFailed`(1)이다. 이후 정책이나 준비 상태가 바뀌어도 원 result·snapshot·같은 ID 재실행의 거부 사유를 현재 판단으로 바꾸지 않는다. stream을 여는 경계에서도 같은 이름의 거부 코드를 사용한다. CLI의 실패 exit code와 이 관리 결과의 Code 번호를 구분한다.

## 노드의 로컬 준비

기존 `sshd`가 `127.0.0.1:22`에서 동작하고 Ed25519 host key의 공개 파일 `/etc/ssh/ssh_host_ed25519_key.pub`를 root 소유로 제공해야 한다. 운영자가 필요한 `sshd`, `useradd`, 선택 sudo용 `sudo`/`visudo`를 설치·관리한다. MyDC는 패키지 설치·sshd 시작·전역 sshd 설정 변경을 수행하지 않는다. 아래 경로/주소는 기본값이며, node.yaml의 `node_shell`로 바꿀 수 있다. 비운 항목은 기본값을 쓴다. `ssh_endpoint`는 loopback IP와 포트만, 나머지는 정리된 절대 경로만 받으며 home 아래에 원 `node.state_dir`이 있으면 안 된다. 어기면 준비되지 않은 상태(`Ready=false`)로 남는다.

```yaml
node_shell:
  ssh_endpoint: 127.0.0.1:22                            # 노드의 sshd (loopback)
  host_public_key: /etc/ssh/ssh_host_ed25519_key.pub    # root 소유 host 공개키
  home: /var/lib/mydc-shell                             # mydc-shell 계정 home
  sudoers_dir: /etc/sudoers.d                           # Sudo=true 규칙을 두는 곳
```

| 로컬 자료 | 소유와 용도 |
|---|---|
| OS `mydc-shell` | UID/GID가 0이 아닌 전용 시스템 계정, `/bin/sh`, comment `MyDC node shell`. 여러 MyDC 사용자는 이 OS 계정을 공유하며 `MYDC_USER`에 원 사용자 이름을 전달한다 |
| `/var/lib/mydc-shell` | 준비 코드가 관리하는 계정 home. 기존의 임의 동명 계정을 자동 채택하지 않는다 |
| `<원 node.state_dir>/node-shell/account.json` | root 전용 0600의 계정 UID/GID·home 소유 기록. 설치 신원 교체에도 원 경로를 사용한다 |
| 같은 디렉터리의 `ssh-key.bin` | root 전용 0600 Ed25519 seed. MyDC 사용자 wallet 키/노드 TLS 키와 별도이며 사용자 응답이나 Raft에 넣지 않는다 |
| `/var/lib/mydc-shell/.ssh/authorized_keys` | 그 키만 loopback에서 허용. agent/port/X11 forwarding과 user rc를 제한하며 예상 bytes가 다른 기존 파일은 덮어쓰지 않는다 |
| `/etc/ssh/ssh_host_ed25519_key.pub` | root 소유 공개키와 실제 loopback SSH host key를 정확히 대조한다. 접속 실패 때 무검증 host key나 다른 주소로 fallback하지 않는다 |
| `/etc/sudoers.d/mydc-shell` | `Sudo=true`일 때 `visudo` 검사 후 root 소유 0440으로 게시하는 정확한 MyDC 관리 규칙. false/disabled에서는 자기 규칙만 제거한다 |

활성 노드의 준비는 root 실행 권한을 필요로 한다. 계정/경로/키 소유권 불일치나 SSH·sudo 준비 실패는 `Ready=false`와 제한된 `NotReady` 코드로 나타난다. 대표 코드는 `account-unavailable`, `key-unavailable`, `ssh-unavailable`, `sudo-unavailable`이고, 오래된 보고나 현재 owner/정책 불일치도 준비 완료로 사용하지 않는다. 비활성 노드는 계정·키·SSH 세션을 새로 만들지 않고 자기 sudo 규칙만 회수한다.

`Sudo=true` 규칙은 `mydc-shell ALL=(root) NOPASSWD: ALL`이다. 해당 노드에서 shell 권한을 받은 사용자가 root 명령을 실행할 수 있는 정책이므로 node grant와 함께 설정한다. false의 준비 검사는 실제 `sudo -n`이 root 실행을 허용하지 않는지도 확인한다. 외부 sudo 정책이 이를 허용하면 준비가 실패한다. OS 계정 공유와 사용자별 감사 metadata는 사용자별 OS UID 격리와 구분한다.

## 세션 목록과 보존

`node-shell-sessions`는 `State`·`Node`를 선택할 수 있다. `State=open`은 `queued/opened/closing`, `closed`는 종료된 세션, 생략/빈 값은 두 종류 모두다. `Node` 생략/빈 값은 조회 가능한 모든 노드이며, 명시 값은 노드 ID다. CLI는 `--state open|closed`·`--node NODE`를 사용하고 모든 페이지를 읽어 보여 준다.

닫힌 세션의 공개 목록은 **노드별 최근 200개**다. `ClosedAt`이 큰 것부터 선택하고 시각이 같으면 SessionID 문자열 오름차순으로 선택한다. 이 보존 창은 클러스터의 노드 단위이며 사용자별 별도 200개가 아니다. 일반 사용자에게는 그 창 안의 자기 세션만 보이고 다른 사용자의 행/개수는 공개하지 않는다. 열린 세션은 이 한도로 숨기지 않는다.

현재 권한·보존 창·State/Node를 적용한 결과를 SessionID 오름차순으로 최대8개씩 반환한다. `Total`은 해당 조건의 전체 공개 행 수이며 After 이전 행도 포함한다. `Next`는 다음 페이지가 있을 때만 마지막 반환 SessionID이고, 다음 호출은 같은 필터와 `After=Next`를 사용한다. 각 호출의 Index/RootRevision을 함께 확인하며 페이지 간 상태 변경을 고정된 snapshot으로 보장하지 않는다.

목록에서 빠져도 원 operation 결과·서명·owner receipt·이벤트는 기존 수명대로 보존한다. 이 조회는 저장 상태를 삭제/변경하거나 셸 재실행 권한을 만들지 않는다. 공개 목록 한도는 기존 `control/node-shell` 공유 저장 상한을 늘리거나 대체하지 않는다.

```sh
mydc node shell sessions --state open --node node-b
mydc node shell sessions --state closed --node node-b
```

## 상태·단절·종료

`SessionID`는 `node shell`이 만든 원 작업 ID다. 공개 행은 사용자 ID/이름·노드·OS 계정·sudo·생성/열림/마지막 실제 byte 이동/종료 시각·누적 BytesIn/BytesOut·상태/종료 이유를 담는다. 시각은 Unix 초다. 화면·키 입력·명령어·SSH 원문 오류는 공유 기록/이벤트에 보관하지 않는다.

| 상태 | 의미 |
|---|---|
| `queued` | 관리 수락 완료, 실제 PTY open 보고 전 |
| `opened` | 대상 owner가 원 SSH 세션의 양성 open을 보고 |
| `closing` | 서명된 관리자/정책 변경으로 종료 요청됨. 실제 close 보고 대기 |
| `closed` | 원 owner의 종료 보고가 확정됨. 원 ID/종료 metadata는 보존 |

동일 operation의 기본 반복은 원 결과만 반환한다. 명시 재개도 같은 ID에 native receipt가 있거나 이미 열린 경우 두 번째 SSH 세션을 만들지 않는다. 자동 재접속·재attach·새 ID 발급은 없으며, 손실된 수락/보고는 현재 인증으로 `node shell sessions`와 `mydc op show ID`로 확인한다. terminal raw 모드·resize/SIGWINCH는 CLI가 관리하고 실제 exit code 0–255를 반환한다. 정상 `end` 없이 끊기면 CLI는 코드 4와 원 상태 조회 안내를 출력한다.

실제 입력/출력 byte만 LastActivity를 갱신한다. 10초 ping은 연결의 read-idle을 유지하지만 idle 제한을 연장하지 않는다. 채널은 원 session 만료·read-idle 60초·write 5초의 제한을 사용한다. owner는 현재 quorum·사용자 권한·정책을 다시 확인하며, 명시 회수/disable/sudo 변경은 원 관리자 또는 변경자의 서명된 `CloseOrigin`을 보존한다. `End.Reason=closed|policy`에는 `ClosedBy:{User,Username}`가 필수이며 CLI도 종료 주체를 표시한다. `exit|idle`에는 ClosedBy가 없다.

CLI 단절·daemon 종료·권한 상실 시 원 SSH 연결/PTY를 닫고 종료·대기와 원 receipt를 정산한다. SSH 연결 종료를 임의로 분리 실행된 모든 OS 자식의 종료 증명으로 확대하지 않는다. 같은 daemon instance의 메모리 handle 부재는 종료 증거가 아니며 원 unknown을 유지한다. 원 observations DB의 배타 재개와 이전 instance 종료가 확인된 뒤에는 보존 receipt의 종료를 보고하고 같은 ID로 새 SSH를 열지 않는다. 신원 교체 후에도 원 owner/서명/종료 근거를 바꾸지 않고 현재 설치 키로만 허용된 원 기록 정산을 수행한다.

`node-shell-denied|node-shell-opened|node-shell-closed` 이벤트는 원 operation·노드·사용자·시각·byte 수·종료 이유/코드·해당 ClosedBy만 공개한다. 조회는 [이벤트의 현재 범위 권한](events.md)을 따르며 이벤트가 실제 OS 정리 증거를 대신하지 않는다.
