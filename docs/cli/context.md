# context: 어디에, 누구로, 어느 작업 공간에

context는 클러스터 하나에 접속하는 방법이다. 접속 주소(endpoint), 처음 접속할 때 확인한 클러스터 ID, 기본 사용자와 기본 tenant를 담는다. 이 컴퓨터의 Linux 사용자마다 따로 있고, 서버에 아무 권한도 주지 않는다. 서버는 모든 요청을 그때의 로그인과 권한으로 다시 확인한다.

```sh
sfcli context add lab                                   # 이 서버의 /run/sfcdp.sock
sfcli context add prod sfcp://192.168.10.11:7443 --user alice --tenant shop
sfcli context list
sfcli context use prod
sfcli context show
sfcli context set prod --tenant payments
sfcli context trust prod sfcp://192.168.10.12:7443     # 같은 클러스터의 다른 노드
sfcli context trust prod --forget node-b
sfcli context remove lab
```

다른 명령은 현재 context를 쓴다. 한 번만 다른 곳으로 보내려면 `--context NAME`, 다른 작업 공간이면 `--tenant NAME`을 붙인다.

## 노드 키 확인

`context add`와 `context trust`는 그 주소의 노드에 누구인지 묻고, 노드 공개키의 지문(`SHA256:...`)과 전체 키를 보여 준 뒤 `Trust this node? [y/N]`을 묻는다. 노드 관리자가 알려 준 값(노드에서 `sfcd identity`)과 같을 때만 y를 누른다. 다르면 그 주소에 다른 서버가 끼어 있을 수 있다.

- `-y`는 이 질문에 답하지 않는다. 키 확인은 건너뛸 수 없다.
- 터미널이 없는 스크립트는 미리 확인한 키를 `--key HEX`(64자리 hex)로 준다. 노드가 다른 키로 답하면 실패한다.
- 터미널이 없거나 `SFC_NONINTERACTIVE=1`이면 `--key`가 필요하다.
- 다른 클러스터의 노드는 trust할 수 없다.
- 노드를 다시 설치해 키가 바뀌었으면 `context trust NAME --forget NODE`로 옛 키를 지우고 다시 trust한다.

## 하위 명령

| 명령 | 하는 일 |
|---|---|
| `context add NAME [ENDPOINT]` | context를 더한다. ENDPOINT는 `sfcp://HOST:PORT`, `unix:///PATH`, `/PATH`. 생략하면 `unix:///run/sfcdp.sock`. 옵션 `--key HEX`, `--user USER`, `--tenant TENANT`, `--wallet-key KEY`. 첫 context는 현재 context가 된다 |
| `context list` | 모든 context. 현재 context에 `*` |
| `context use NAME` | 현재 context를 바꾼다 |
| `context show [NAME]` | context와 그 클러스터에서 trust한 노드 키. 생략하면 현재 context |
| `context set NAME` | `--endpoint`, `--user`, `--tenant`, `--wallet-key` 중 준 것만 바꾼다. 빈 값(`--tenant ''`)은 지운다. `--endpoint`는 주소가 바뀐 노드(`node set-endpoint`)를 따라갈 때 쓰고, 그다음 `context trust NAME`으로 새 주소의 같은 키를 확인한다 |
| `context trust NAME [ENDPOINT]` | 같은 클러스터의 노드를 더 trust한다. 생략하면 context의 주소. `--forget NODE`는 trust를 지운다(확인 질문) |
| `context remove NAME` | 이 컴퓨터에서 context를 지운다(확인 질문). 저장된 로그인과 보낸 작업 목록은 남는다. 그 클러스터를 쓰는 context가 더 없으면 trust 목록도 지운다 |

## 파일

```yaml
# ~/.sfc/config.yaml
version: 1
current: prod
contexts:
  prod:
    endpoint: sfcp://192.168.10.11:7443
    cluster: 0101...        # 처음 접속 때 확인한 클러스터 ID
    user: alice
    tenant: shop
    key: alice-laptop       # sfcli login이 쓰는 wallet 키(선택)
```

```yaml
# ~/.sfc/trust/<클러스터 ID>.yaml
version: 1
cluster: 0101...
nodes:
  - id: node-a
    key: 9f2c...            # 노드 공개키 hex
    endpoints: [sfcp://192.168.10.11:7443]
    how: fingerprint        # fingerprint(터미널에서 확인), out-of-band(--key), relayed-login(아래)
    at: 2026-11-24T17:00:00Z
```

`relayed-login`: 투표하지 않는 서버(예: 공개 gateway)로 개인 키 로그인하면 그 서버가 leader에게 넘기고 leader가 세션을 발급한다. 발급한 leader를 아직 신뢰하지 않으면, 넘겨 준 서버가 클러스터 멤버 목록에서 알려 준 leader의 키와 주소를 이 표시로 trust에 더하고 `Trusted session issuer ...`를 알린다. 그 서버를 이미 신뢰하므로 다시 묻지 않는다. 지우려면 `context trust NAME --forget NODE`.

`~/.sfc`는 0700, 파일은 0600이다. config.yaml은 사람이 고쳐도 되지만 trust 파일은 `context` 명령으로만 바꾼다. 로그인 기록과 작업 journal은 클러스터 ID로 나뉘므로 context 이름이나 주소를 바꿔도 이어서 쓴다.
