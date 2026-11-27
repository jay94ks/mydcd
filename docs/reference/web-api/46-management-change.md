# 관리 변경 (UI-A1)

`sfcli manage apply`의 변경 파일로 할 수 있는 일을 화면 조작만으로 하게 하는 끝점이다. 동작과 칸 정의는 sfcd가 받는 입력 형식에서 그대로 뽑으므로 따로 맞출 목록이 없다. 코드는 [ops_actions.go](../../../internal/web/server/ops_actions.go)와 [input_catalog.go](../../../internal/cluster/control/input_catalog.go)에 있다.

## 동작 목록: `GET /ops/actions`

```json
{"items":[{"action":"set-nodes","key":"access","category":"tenants","offer":"here","base":"current",
  "fields":[{"name":"Tenant","type":"string"},{"name":"Add","type":"list","items":{"type":"string"}},{"name":"Remove","type":"list","items":{"type":"string"}}]}]}
```

sfcd가 받는 동작 전체를 이름순으로 돌려준다.

| 칸 | 뜻 |
|---|---|
| `action` | 변경 파일의 `action` |
| `key` | sfcd가 `expected`를 비교하는 범위(command key에서 `control/`을 뗀 것). 표시용 |
| `category` | `users`, `tenants`, `nodes`, `networks`, `reservations`, `storage`, `apps`, `registry`, `builds`, `vault`, `checks`, `shell`, `certificates`, `ingress` 중 하나 |
| `offer` | `here`: 이 화면에서 보낸다. `no`: 조각 올리기·비밀 값·셸 열기처럼 폼에 담을 수 없는 단계. 목록에는 보이되 보내기는 막는다 |
| `base` | `expected`를 채우는 방법. `zero`: 새로 만들기라 0. `current`: 아래 base 끝점으로 읽는다. `input`: 사람이 넣는다 |
| `fields` | payload의 칸. sfcd의 JSON 키 그대로 |

칸(Field)은 `{name, type, format?, length?, replace?, items?, fields?}`다.

- `type`: `string`, `integer`, `number`, `boolean`, `bytes`(base64), `json`(아무 JSON), `list`(원소는 `items`), `map`(키는 문자열, 값은 `items`), `object`(하위 칸은 `fields`).
- `format`: `cidr`, `ip`, `ip-port`, `time`(RFC 3339), `duration`(정수, 나노초). 없을 수 있다.
- `length`: 길이가 정해진 목록(예 32바이트 다이제스트는 길이 32인 정수 목록).
- `replace: true`: 값 전체를 바꾸는 칸. 비어 있어도 꼭 보낸다(빈 목록은 `null`이 아니라 `[]`). 빠지면 보내기가 400이다.
- `items`의 칸에는 `name`이 없다.

화면 이름과 설명은 프런트엔드가 정한다. 권한은 sfcd가 판단하므로 목록에 싣지 않는다.

## 기준 리비전: `POST /ops/actions/{action}/base`

요청 `{"payload":{...}}` → `{"expected":7,"found":true,"current":{...}}`

지금까지 넣은 칸으로 대상을 찾아, 그 변경이 비교될 리비전(`expected`)과 대상의 지금 값(`current`, 그 대상을 읽는 조회 끝점의 모양)을 돌려준다. 웹이 기존 조회(사용자, 멤버십, 작업 공간, 서버 CLI·셸 정책, 실행 예약, 망, 서버 저장소)로 읽는다. 대상이 아직 없으면 `found:false`, `expected:0`이다.

| 동작 | 찾는 칸 | `expected` |
|---|---|---|
| `put-user` | `ID` | 사용자 리비전 |
| `set-account-scope`, `add-credential`, `disable-credential`, `revoke-session` | `User` | 사용자 리비전 |
| `set-membership` | `Tenant`, `User` | 멤버십 리비전(관리자에게 저절로 주어진 멤버십은 없는 것으로 본다) |
| `set-nodes`, `set-trust` | `Tenant` | 작업 공간 리비전 |
| `set-node-cli-policy`, `set-node-shell-*` | (없음) | 정책 리비전 |
| `set-node-quota` | `Tenant`, `Node` | 그 한도의 리비전 |
| `create-tun-network`, `join-tun-network`, `set-network-toggle` | `Tenant`, `Name` | 그 작업 공간의 망 전체 리비전 |
| `drain-network` | `Tenant`, `ID` | 그 망 구성원의 리비전 |
| `configure-network-dns` | `Tenant`, `Network` | 그 망 DNS 설정의 리비전(아직 없으면 0) |
| `set-node-storage-policy`, `drain-node-storage`, `remove-node-storage` | `Node`, `ID` | 저장소 리비전 |

- `add-credential`은 시스템 관리자가 증명 없이 키를 더하는 경우다(본인 키 추가는 계정 화면이 증명을 서명한다).
- 목록의 `base`가 `current`가 아닌 동작은 `422 unsupported`, 없는 동작은 `404 not-found`다.
- 묶음에서 앞 변경에 기대는 리비전은 앞 변경이 확정된 뒤 다시 읽는다.

## 보내기

[작업](04-operation.md)의 `POST /ops`를 그대로 쓴다.

- `principal`을 비우면 로그인한 사용자다(`sfcli manage apply`와 같다).
- payload는 `sfcli manage apply`가 변경 파일을 읽듯 읽어 sfcd가 받는 꼴로 다시 쓴다. 없는 칸, 틀린 형식, 빠진 `replace` 칸은 `400 bad-payload`이고 보내지 않는다.
- 사유는 머리글 `X-SFC-Reason`·`X-SFC-Incident`로 싣는다.
- 한 묶음으로 보낸 변경은 같은 `batch`(소문자 UUID v4)를 싣는다. 각 변경은 여전히 따로 서명한 요청이고 `requestId`도 따로다. `GET /ops?batch=`가 그 묶음만 보여 준다.
- 묶음 순서와 "첫 거부·불명 뒤 멈춤"은 브라우저가 한다.

변경 파일을 불러오고 내보내는 형식은 CLI와 같다: `{"schema":1,"action":...,"expected":...,"payload":{...}}`, 여러 개면 그 배열.
