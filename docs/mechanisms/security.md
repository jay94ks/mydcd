# 노드 키·사용자 자격의 신뢰 경계

## 설치 노드의 신뢰

managed cluster는 설치한 모든 노드를 높은 신뢰의 복제 구성원으로 취급한다. non-voter도 전체 관리 FSM/Snapshot을 복제하지만, 새 사용자 Session의 issuer는 현재 설치된 활성 control voter로 제한한다. voter 여부가 tenant별 격리나 낮은 신뢰 worker 구분을 뜻하지는 않는다. 노드의 TLS 키와 사용자 계정의 개인키·Session proof 키·CLI pin은 서로 다른 신원이다.

| 노드 상태 | 현재 허용되는 역할 |
|---|---|
| 미등록 | node 복제/업무 권한 없음. 별도 User 로그인 입구와 구분 |
| 가입 승인·설치 전 | 승인 키의 제한 복제/가입 동기화. 설치 Member 업무/issuer 권한은 없음 |
| 설치 Member non-voter | 전체 복제·내부 보고. 새 session 발급은 거부. 실제 업무/데이터는 WorkKey·원 Task/Binding·사용자 권한/permit 추가 확인 |
| 설치 Member의 활성 control voter | 같은 복제·실행 경계에 더해 새 session 발급. leader가 아니어도 최신 quorum barrier의 로컬 복제 prefix에서 직접 인증 |
| 격리/제거 진행 중 | 새 업무와 session 발급은 제한하되 원 결과/복구 신원·이미 커밋한 grant 검증 보존. 관리자도 격리 노드에서 새 로그인 불가 |
| 제거 확정 | 현재 membership/issuer에서 제외. 이미 수락한 원 operation/grant·역사적 서명 검증과 구분 |

정상 login handler는 사용자 credential을 검사하고 session을 발급한다. 그러나 승인 issuer의 개인키 자체가 탈취되면 정상 handler를 우회해 활성 계정의 session을 위조할 수 있다는 신뢰 전제가 있다. managed node의 일반 `Manage=false`나 tenant API의 owner 검사는 이 발급 키 침해를 방어하는 보장이 아니다. 업무 격리를 키 유출 대응의 완전한 권한 회수로 사용하면 안 된다.

Raft는 신뢰한 구성원의 장애/단절을 다루는 합의이며 악의적인 member에 대한 BFT 보장이 아니다. non-voter/설치 전 복제 승인 키가 표 수를 늘릴 수 없다는 사실만으로 모든 RPC 방해 가능성이 제거되지 않는다. 같은 이유로 전체 FSM을 가진 노드에 대해 tenant API의 읽기 필터가 복제본의 비밀 격리를 보장하지 않는다. 실제 Secret/provider 값·개인키를 공유 관리 상태에 저장하지 않는 원칙은 별도다.

### Raft 요청을 보낼 수 있는 역할

SFCP는 Raft stream을 승인된 구성원·가입 키에만 연다. 그 위에서 Raft 자체가 요청 종류별로 보낸 쪽의 역할을 다시 본다(3rd-party/raft 수정). 기준은 받는 서버의 최신 구성과 커밋된 구성이다.

| 요청 | 받는 조건 |
|---|---|
| AppendEntries·InstallSnapshot | 받는 서버가 non-voter로 아는 서버(최신·커밋 구성 어느 쪽에서도 voter가 아님)가 보낸 요청은, 받는 서버가 지금 다른 leader를 따르거나 자신이 leader이면 거절한다. 지금 leader가 없거나, 보낸 서버를 모르거나, 요청 안의 구성 entry·snapshot 구성이 그 서버를 voter로 만들면 받는다(승격 entry를 아직 못 받은 서버가 따라오는 길) |
| RequestVote | 보낸 서버가 두 구성 중 하나에서 voter. non-voter의 요청은 term을 올리기 전에 거절한다 |
| TimeoutNow | 받는 서버가 지금 따르는 leader가 보낸 것만 |

거절된 AppendEntries는 term·leader를 바꾸지 않고 로그 불일치처럼 답한다. 진짜 leader는 그 답을 보고 받는 서버의 마지막 로그부터 다시 보내므로, 뒤처진 서버도 승격 entry를 받아 따라온다. 구성이 아직 비어 있는 가입 중 서버는 SFCP 승인 키만 본다.

이 검사는 learner·가입 키가 일하는 leader를 밀어내거나 voter의 term을 끌어올리는 일을 막는다. leader가 없는 순간(선거 중)의 leader 행세나 승격 entry 위조까지 막는 BFT 보장은 아니다.

`context trust`는 CLI 접속 신뢰 변경이고 `node rotate-operations`는 업무 epoch 변경이다. 설치 개인키 회전은 `node rotate-key`(`rotate-node-identity`)이며 아래 "설치 키 회전"을 따른다. node/DB·원 owner/서명/작업을 보존하지 않은 키 파일 교체는 지원되는 회전 절차가 아니다.

### 설치 키 회전

`sfcli node rotate-key NODE`는 system-admin이 그 서버 항목의 revision을 CAS로 고정해 요청한다(`rotate-node-identity`). 단계는 Preparing → Prepared → Activated → Installed다.

| 단계 | 하는 일 |
|---|---|
| Preparing | 대상 sfcd가 새 키를 만들어 내구 저장하고, 원 operation·옛/새 공개키를 옛 키와 새 키 **둘 다**로 서명한 증명을 보고한다(새 키의 실제 소유 증명) |
| Prepared | 대상이 leader면 다른 voter에게 leader를 넘긴다. 그 뒤 활성화를 보고한다 |
| Activated | 커밋되는 순간 그 서버의 현재 키(`CurrentPeer`)가 새 키로 바뀐다. 옛 키의 SFCP 접속은 이때부터 거절된다 |
| Installed | 새 키로 다시 연 sfcd가 Root·native owner·TLS를 열었다고 새 키로 보고한다 |

옛 키가 Activated 뒤에 할 수 있는 일:

- **새 권한은 없다.** SFCP 승인, 사용자 session 발급, 노드 보고(보고의 Reporter는 인증된 SFCP 상대 키와 같아야 한다), 새 Work·배치는 현재 키만 쓴다(`MemberKey`·`WorkKey`). 역사 키는 승인에서 명시적으로 거절되고, 일반 User TLS 입구로도 넘어가지 않는다.
- **원 자원 연결만 남는다.** Task·Volume·route 같은 원 자원의 owner 필드는 바꾸지 않는다. 현재 키가 그 원 owner를 이었는지는 서명된 전환 기록(`Entry.Keys`)으로 확인한다(`OwnsResource`·`ResourceKeyForNode`). 과거 서명·snapshot 검증에는 역사 키를 쓴다.
- **로컬 원 journal.** 서버는 옛 키의 native journal·봉인 저장소를 같은 데몬 안의 역사 owner로 연다. 그 원 자원의 정리 증명·보고 본문은 원 owner 키(옛 키)로 서명될 수 있다. 하지만 클러스터에 들어가는 길은 SFCP 하나이고, 받는 쪽은 인증된 상대가 현재 키이며 그 원 owner를 이었는지(`OwnsResource`)를 먼저 본다.

- **`Entry.Peer.Key`는 원 키다.** 회전해도 이 값은 바뀌지 않고, 현재 키는 `Entry.CurrentPeer().Key`(`Entry.Keys` 마지막 전환의 새 키)다. 그래서 서버를 키로 찾거나(자기 자신 찾기, 보고자 확인, 비밀값 봉인 대상, 받는 서버, 격리) 현재 키와 비교하는 코드는 `CurrentPeer()`를 쓰고, 저장된 owner 키가 그 서버의 키였는지 보는 코드는 `ResourceKeyForNode`를 쓴다. `Peer.Key`를 그대로 쓰는 곳은 원 설치·가입 증명(합류 전 단계, 원 설치 기록 대조)과 키 유일성 검사뿐이다.
- 회전 중 서버가 Activated 뒤 돌아오지 못하면 교체는 끝나지 않는다. 이때 `sfcli node remove --force`는 그 서버의 멈춘 교체를 무시하고 그 행을 Abandoned로 닫는다(#835).

그래서 탈취된 옛 키만으로는 Activated 뒤 클러스터에 접속하거나 보고를 넣을 수 없다. 옛 키 서명은 현재 키가 들고 온 원 자원 정리 안에서만 의미가 있다. 서버 디스크 자체가 탈취됐다면 새 키도 함께 노출되므로, 그때는 `node remove`로 빼고 새로 가입시킨다.

non-voter·격리 issuer의 기존 session은 현재 요청에 사용할 수 없으므로 활성 control에서 재로그인한다. 과거 시각을 제시하는 예외는 두지 않는다. 원 accepted grant와 새 요청을 구분하며 원 결과·앱/Volume owner를 초기화하지 않는다. 로컬 committed view가 아직 수신하지 못한 회수를 이미 집행했다고 주장하지 않으며 새 업무는 기존 최신 quorum permit을 따른다. 추가 Raft RPC 필터·설치 키 회전은 이 발급 제한의 보장이 아니다.

## 독립 사용자 승인

발급된 Session의 선택 `Approval`은 등록 사용자 키가 그 grant 전체를 승인한 서명이다. private-key login은 그 사용자 키로, password/token login은 명시 `--approval-key NAME`으로 승인한다. 승인에는 cluster·계정/인증 credential·계정 revision·session ID/proof key·issuer·scopes·기한·issuer 서명이 모두 결합된다. node issuer가 같은 사용자 이름의 다른 session을 새로 서명해도 원 승인 증거를 재사용할 수 없다. 별도 승인 키로 token scope를 확대하지 않는다. 형식은 [Unix API](../reference/unix-sockets/11-section.md#로그인-증거)를 따른다.

클러스터 공통 `disable_node_cli_operation`은 기본 false이며 `manage node-cli-policy`로 조회한다. managed cluster의 system-admin이 독립 사용자 승인과 정책 revision/CAS를 갖춘 `set-node-cli-policy`로 변경한다. true이면 새 요청은 등록된 사용자 키의 승인과 system-admin 또는 대상 tenant의 manager 권한을 요구한다. 등록 node key는 사용자 승인 키로 사용할 수 없고, on/off 모두 독립 승인이 필요하다. 활성화 뒤 마지막 독립 관리자 키를 제거할 수 없다.

노드 키만으로 raw `submit/get/plan`을 호출하는 경로는 차단하며, 원 사용자 승인 relay·Raft 복제·정확한 원 owner 보고/정산은 유지한다. 합의한 목표의 실제 실행은 담당 노드가 기존 Task/Binding·permit과 Docker SDK로 수행한다. 정책 전 수락한 원 grant/result·앱/Volume은 재서명하지 않고 보존한다. 현재 계정/credential/역할 회수는 계속 적용한다. 이 옵션은 복제본·root/Docker 권한을 가진 침해 노드의 BFT/비밀 격리를 보장하지 않는다. 정책 전환을 참조한다.

## 사용자당 여러 인증 키

한 사용자 record는 여러 `private-key` credential을 가질 수 있고 password/token 방식과 혼용할 수 있다. 전체 credential은1–64개이며 사용자 내 ID와 공개키가 중복될 수 없고 활성 인증수단을 최소1개 유지한다. 공개키를 서버 계정에 등록하는 것과 Linux user의 wallet에 named private key를 넣는 것은 별도 작업이다.

같은 alice 계정에 두 공개키를 사전 등록한 경우 다음처럼 실제 키를 선택한다.

```sh
sfcli --cluster production login --user alice --method private-key --key alice-laptop
sfcli --cluster production login --user alice --method private-key --key alice-desktop
```

개인키 인증은 제출한 실제 공개키로 활성 credential을 선택한다. `--credential`은 password/token의 후보 선택에 사용하며 private-key login에 키 대신 지정하는 옵션이 아니다. `--key-file`과 wallet `--key`는 배타적이다.

현재 같은 cluster/profile/username의 wallet login은 한 record다. 같은 사용자가 다른 키로 재로그인하면 현재 session을 교체하며 키별 동시 session 슬롯을 선택하는 기능은 아니다. 서로 다른 사용자 계정의 자격은 공존하고 후보가 여러 개면 `--user`를 명시한다. 원 미정산 작업의 signer/ID는 새 로그인과 별도로 보존한다.

계정의 로그인 수단은 한 줄씩 바꾼다. `add-credential`이 키 하나를 더하고 `disable-credential`이 수단 하나를 끈다(계정 revision CAS). system-admin은 어느 계정에나(자기 계정 포함) 증명 없이 키를 더하고 어느 수단이든 끈다. 일반 사용자는 credentials scope·소유 증명을 갖춰 자기 키만 다룬다. 있는 계정의 `put-user`는 Username·Enabled·SystemAdmin만 바꾸고 로그인 수단 목록을 받지 않는다. 변경은 계정 revision을 올려 **다른 키의 session까지 포함한 기존 모든 session**을 무효화한다. 키를 추가만 하는 경우도 같다. 원 accepted grant의 후속 현재 권한 검사에도 영향이 있으나 실행 중 모든 컨테이너를 즉시 종료한다는 뜻은 아니다. 키 한 개만 선택적으로 회수하는 정책과 구분한다.

로그인/wallet 사용법은 [CLI 신원](cli-identity.md), 메시지/서명은 [Unix API](../reference/unix-sockets.md)·[SFCP](../protocol/sfcp.md), 관리 명령의 적용 대상은 [대상표](../architecture/command-targets.md)를 따른다.

다른 계정의 공개 자격 조회와 키 변경은 system-admin의 `sfcli user show`, `user key add`, `user key disable`이다([sfcli user](../cli/user.md)). 변경은 정확한 계정 revision으로 `add-credential`·`disable-credential`을 제출하며, 계정의 모든 session을 끝낸다. 같은 `--id`로 다시 실행하거나 `op resume`하면 저장한 원 요청을 이어 보낸다.

동일 client proof identity의 여러 사용자·원 Session 재결합·source 예산과 브라우저 key 소유/독립 승인의 구분은 [client 인증](../reference/client-authentication.md)을 따른다.

## 내장 registry push 자격의 유한 사용 범위

현재 계정·권한·registry run을 검증한 뒤 push-capable access token의 repository와 만료 범위를 해당 owner Store에 기록한다. 발급 응답은 이 기록 뒤에만 반환하며, 같은 token으로 blob HEAD를 수행해도 그 범위가 적용된다. 원 token·password·사용자 Session은 이 기록에 저장하지 않는다.

native GC의 원 쓰기 차단은 새 push 자격 발급을 막고 이미 기록된 구 자격의 유한 종료와 실제 요청 join을 확인한다. 자격의 최대 수명은 기존대로 300초다. 처음 연결되는 기존 저장소에는 과거 자격이 있을 수 있어 한 번의 최대 수명 창을 보존하며 재시작 때마다 갱신하지 않는다. 쓰기 차단이나 자격 만료 자체가 물리 정리 완료를 뜻하지 않는다. 사용자 삭제/GC action의 실제 연결 범위는 마일스톤을 따른다.
