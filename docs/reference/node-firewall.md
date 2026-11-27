# 서버 방화벽

sfcd는 node.yaml이 허락한 서버에서만 그 서버로 들어오는 연결(iptables `INPUT`)을 다룬다. 운영자가 넣은 iptables 규칙은 지우지도 고치지도 않는다. 서버 규칙은 그 서버에만 저장되고 Raft를 거치지 않으며, 바꾼 기록은 서명된 이벤트로 클러스터에 남는다. 모든 서버에 같이 걸리는 [클러스터 방화벽](#클러스터-방화벽)(기본 정책과 공통 규칙)은 Raft에 둔다. 설계: devel/design/node-firewall.md.

## node.yaml

```yaml
firewall:
  managed: true      # 이 서버의 방화벽을 sfcd가 다뤄도 된다
  keep_open:         # 원격 규칙과 상관없이 열어 두는 포트. 빼면 tcp/22
    - tcp/22 from 192.168.1.0/24   # 로컬 망에서만
    - tcp/2222                     # 어디서나
```

| 칸 | 뜻 |
|---|---|
| `managed` | `true`면 제어 대상이다. 없거나 `false`면 sfcd는 iptables를 건드리지 않고, 예전에 만든 `SFC-INPUT`이 남아 있으면 시작할 때 지운다. 바꾼 뒤 sfcd를 다시 시작한다 |
| `keep_open` | `tcp/PORT`·`udp/PORT` 32개까지, 뒤에 ` from PREFIX[,PREFIX]`(32개까지, 호스트 비트 없이)를 붙이면 그 출처에서만 연다. 생략하면 `tcp/22`(어디서나), `[]`이면 아무것도 열어 두지 않는다. 이 파일에서만 바꿀 수 있고 원격 규칙·클러스터 규칙·`drop` 정책으로 막을 수 없다. VPS 같은 ingress gateway를 공인 IP로 관리한다면 출처 없이 둔다 |

`iptables`·`ip6tables`·`iptables-restore`·`ip6tables-restore`가 있어야 한다(Ubuntu 기본 `iptables` 패키지). 둘 중 하나가 실패하면 두 family 모두 이전 규칙으로 돌아간다.

## 어떻게 걸리나

sfcd는 `filter` 테이블에 체인 `SFC-INPUT`을 만들고 `INPUT` 맨 위에 `-j SFC-INPUT` 한 줄만 넣는다(IPv4·IPv6 둘 다). `SFC-INPUT`은 차례로 본다.

1. 잠금 규칙(지울 수 없음): 이미 열린 연결의 응답(`ESTABLISHED,RELATED`), `lo`, Seafield 브릿지 `md*`·TUN `mt*`에서 온 패킷(되돌려서 격리 규칙이 판정), IPv6 이웃 탐색·packet-too-big, SFCP 포트(`node.listen`의 UDP, 예: 7443), `keep_open`, 이 서버 Ingress listener의 포트(HTTP/3면 UDP도).
2. 클러스터 필수 규칙: `deny` → DROP, `allow` → ACCEPT. 서버 규칙으로 덮어쓸 수 없다.
3. 서버 `deny` 규칙 → DROP
4. 서버 `allow` 규칙 → ACCEPT
5. 클러스터 일반 규칙: `deny` → DROP, `allow` → ACCEPT. 서버 규칙이 먼저라서 한 서버만 열거나 막을 수 있다.
6. 정책: 서버 정책이 `inherit`(기본값)면 클러스터 정책을 따른다. `return`이면 `INPUT`으로 돌아가 운영자 규칙이 판정하고, `drop`이면 버린다.

`SFC-INPUT`은 `iptables-restore --noflush`로 한 번에 바꾼다. 누가 체인을 비우거나 jump 줄을 옮기면 sfcd가 다음 점검에서 다시 넣는다(jump만 맨 위로 옮기고 다른 줄은 건드리지 않는다). sfcd가 멈춰도 체인은 커널에 남는다.

`drop` 정책에서는 conntrack이 응답으로 잡지 못하는 들어오는 UDP가 막힌다. 예: 서버가 DHCPv6로 주소를 받으면 `udp/546`을 allow하거나 `keep_open`에 넣는다.

운영자 규칙을 sfcd로 옮기려면: sfcd에 같은 규칙을 넣고 `show`로 적용됐는지 본 뒤, 운영자가 직접 자기 `INPUT` 규칙을 지운다. 모두 sfcd가 정하게 하려면 정책을 `drop`으로 바꾼다. 이때 운영자 규칙은 남아 있지만 쓰이지 않는다.

## 규칙

| 칸 | 값 |
|---|---|
| `ID` | 서버가 정한다: 서버 규칙 `r1`, `r2`, …, 클러스터 규칙 `c1`, `c2`, … 다시 쓰지 않는다 |
| `Action` | `allow`, `deny` |
| `Proto` | `tcp`, `udp`(포트 필요), `icmp`, `any`(포트 없음). `icmp`는 IPv6에서 ICMPv6다 |
| `Ports` | `443` 또는 `30000-30100` |
| `From` | 출처 prefix 32개까지(호스트 비트 없이). 비우면 모든 곳. IPv4 prefix는 iptables에, IPv6 prefix는 ip6tables에만 들어간다 |
| `Comment` | 한 줄 120자. iptables에는 넣지 않는다 |
| `Required` | 클러스터 규칙만. 서버 규칙보다 먼저 판정해 서버가 덮어쓸 수 없다 |

deny가 allow보다 먼저라서 순서는 없다. 서버당 256개, 같은 action·proto·ports·from인 규칙은 두 개 둘 수 없다.

## CLI

시스템 관리자 명령이다.

```sh
sfcli node firewall show vps1
sfcli node firewall allow vps1 tcp/443
sfcli node firewall allow vps1 tcp/5432 --from 10.0.0.0/8 --comment "사내만"
sfcli node firewall deny vps1 any --from 198.51.100.7/32
sfcli node firewall update vps1 r2 --from 10.0.0.0/8 --from 192.168.0.0/16
sfcli node firewall remove vps1 r2 r3
sfcli node firewall policy vps1 drop      # 또는 inherit(클러스터 값 따름), return
sfcli node firewall log vps1 [--before REVISION]
```

CLI가 먼저 `show`로 revision을 읽어 변경에 붙인다. 그 사이 다른 사람이 바꿨으면 거절하고 다시 보라고 알린다. allow 규칙이 없는데 `drop`으로 바꾸면 한 번 묻는다(`-y`로 넘김). 연결이 끊겨 결과를 모르면 종료 코드 4로 끝나고, 같은 `--id`로 다시 실행하면 한 번만 적용된다.

## 사용자 method `node-firewall`

typed user method다(`control.NodeFirewallOp` → `control.NodeFirewallResult`). 권한은 ManageCluster를 가진 시스템 관리자다. 받은 sfcd는 대상 서버로 SFCP `node-firewall-owner`를 보내고, 대상은 리더의 `node-firewall-permit`(quorum 읽기)으로 세션을 다시 확인한다.

```json
{"Node":"vps1","Action":"show"}
{"Operation":"fw-1","Node":"vps1","Action":"change","Revision":3,"Delta":{"Add":[{"Action":"allow","Proto":"tcp","Ports":"443"}],"Update":[{"ID":"r2","Action":"deny","Proto":"any","From":["198.51.100.7/32"]}],"Delete":["r1"],"Policy":"drop"}}
{"Node":"vps1","Action":"log","After":40}
```

| Op 칸 | 뜻 |
|---|---|
| `Action` | `show`, `change`, `log` |
| `Operation` | change만. 같은 ID로 다시 보내면 처음 결과를 돌려준다. 다른 내용이면 `operation-conflict` |
| `Revision` | change만. 지금 revision이어야 한다 |
| `Delta` | change만. `Add`(ID 없이), `Update`(ID와 바뀐 뒤의 모든 칸), `Delete`(ID), `Policy`(`inherit`·`return`·`drop`). 목록 전체를 보내지 않는다 |
| `After` | log만. 이 revision보다 앞의 변경. 0은 최신부터 |

`NodeFirewallResult`는 `Schema`, `Node`, `Action`, `Code`, `Error`, `View`, `Change`, `Log`, `More`다.

| `View` 칸 | 뜻 |
|---|---|
| `Managed` | false면 나머지가 비고 change는 `not-managed` |
| `Revision`, `Policy`, `Rules`, `MaxRules` | 저장된 서버 규칙 |
| `Cluster` | 이 서버가 지금 적용 중인 클러스터 방화벽(마지막으로 읽은 사본: `Revision`, `Policy`, `Rules`) |
| `Effective` | 지금 걸린 정책(`return`·`drop`). `Policy`가 `inherit`면 클러스터 값 |
| `Shadowed` | 클러스터 필수 규칙에 일부 가려지는 서버 규칙 ID(반대 action이고 같은 패킷을 잡을 수 있음) |
| `Locked` | 잠금 규칙 `{Name, Proto, Port, From, Reason}` |
| `Operator4`, `Operator6`, `OperatorTruncated` | 운영자 `INPUT` 규칙(`iptables -S INPUT` 줄, family당 200줄까지). 읽기만 한다 |
| `Applied`, `ApplyError` | 체인이 지금 저장된 규칙을 담고 있는지, 아니면 그 이유 |

`Change`·`Log` 항목은 `{Operation, User, At, From, To, Delta, Added}`다. 서버는 최근 500건을 둔다. `Log`는 한 번에 50건, 최신부터이고 `More`가 더 있음을 뜻한다.

| `Code` | 뜻 |
|---|---|
| `not-managed` | 그 서버 node.yaml이 허락하지 않음 |
| `revision` | 읽은 뒤 바뀜. `View`에 지금 revision |
| `invalid`, `duplicate`, `too-many`, `missing` | 규칙·정책 오류, 같은 규칙, 256개 초과, 없는 ID |
| `apply-failed` | iptables 적용·저장 실패. 이전 규칙이 그대로 |
| `operation-conflict` | 같은 작업 ID에 다른 내용 |

서버에 연결되지 않으면 method가 `unavailable`로 끝난다. 나중에 적용되도록 쌓아 두지 않는다.

## 기록

적용한 변경마다 대상 서버가 서명된 이벤트 `node-firewall-changed`를, 적용 실패면 `node-firewall-failed`를 남긴다(scope `node`, `Detail.Actor`=사용자, `Operation`, `FromVersion`/`ToVersion`=revision, `Reason`=변경 요약). [관측 이벤트](events.md)로 다른 서버에서도 읽는다(`sfcli events --all --kind node-firewall-changed`).

## 클러스터 방화벽

모든 managed 서버가 같이 쓰는 기본 정책과 공통 규칙이다. 서버마다 같은 값을 봐야 하므로 Raft 책 `control/firewall`에 둔다. 처음 값은 정책 `return`, 규칙 없음이다.

- 규칙은 서버 규칙과 같은 칸에 `Required`가 더해진다. 필수 규칙은 판정 순서 2번이라 어느 서버도 덮어쓸 수 없다(예: 로컬 망 SSH 열기, 엔진 API 포트 막기). 일반 규칙은 5번이라 서버 규칙이 이긴다.
- 정책은 `return`·`drop`이다(`inherit` 없음). 서버 정책이 `inherit`인 서버만 따른다.
- 바꾸기는 관리 변경 `set-cluster-firewall`이다(payload `firewall.Delta`, `Expected`=지금 revision). 시스템 관리자만. 변경은 Raft 기록과 이벤트 `cluster-firewall-changed`로 남는다.
- 각 서버는 reconcile 점검마다 커밋된 값을 읽어 체인을 맞추고, 마지막 값을 자기 `firewall.db`에 둔다. 재시작하면 그 사본을 다른 모듈보다 먼저 적용하고, Raft를 따라잡으면 새 값으로 맞춘다. `firewall.managed`가 꺼진 서버는 건드리지 않는다.
- 읽기는 사용자 method `cluster-firewall`(`control.ClusterFirewallQuery{}` → `control.ClusterFirewallView{Schema, Firewall, MaxRules}`)과 `sfcli firewall show`다.

SSH를 닫을 수 있는 변경(정책 `drop`, SSH 포트 deny)을 하기 전에, 각 서버의 `keep_open`이 SSH를 잠그고 있는지 `sfcli node firewall show`의 잠금 규칙으로 본다. 기본값 `tcp/22`는 어디서나 열려 있다.

