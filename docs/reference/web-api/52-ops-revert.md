# 변경 되돌리기 (UI-A4)

작업 기록의 확정된 변경을 바꾸기 전 값으로 되돌린다. 되돌리기는 같은 대상에 보내는 새 변경이다. 지금 값에서 시작해 고른 칸만 바꾸기 전 값으로 바꾸고, 지금 읽은 revision을 `expected`로 보낸다. 되돌리는 사람이 서명하고, 되돌리기도 작업 기록에 남아 다시 되돌릴 수 있다. 코드는 [ops_revert.go](../../../internal/web/server/ops_revert.go)에 있다.

웹은 아래 표의 동작을 보내기 직전에 그 대상을 읽어 작업 기록에 함께 둔다(변경 payload 모양, 비밀 값 없음). 이 기록이 있어야 되돌릴 수 있다. 이 기능 전에 보낸 작업이나 그때 읽지 못한 작업은 `no-record`다.

## 작업 행의 표시

[작업](04-operation.md)의 op 보기에 두 칸이 붙는다.

| 칸 | 뜻 |
|---|---|
| `revert` | 메뉴 ‘이 변경 되돌리기’를 켤지. `here`: 이 끝점으로 되돌린다. `link`: 다른 화면이 되돌린다(아래 `link`). `no`: 되돌릴 수 없거나 아직 이 화면이 모르는 동작 |
| `revertOf` | 이 op가 되돌린 op의 ID |

`here`여도 계획을 읽으면 `created`, `nothing`, `target-gone`일 수 있다. 확정되지 않은 작업과 배포 묶음의 단계 행은 늘 `no`다.

## 계획: `GET /ops/{id}/revert`

내 작업만 된다(없으면 `404`). 대상을 지금 읽어 되돌릴 칸을 돌려준다.

```json
{"revert":"here","action":"configure-network-dns","target":"shop-net","expected":16,
 "fields":[
  {"path":"Policy.Upstreams","kind":"value","before":["1.1.1.1:53"],"after":["10.0.0.53:53"],"now":["10.0.0.53:53"],"changedSince":false},
  {"path":"Policy.TTL","kind":"value","before":10,"after":30,"now":60,"changedSince":true},
  {"path":"Policy.Records","kind":"set","before":[...],"after":[...],"now":[...],
   "added":[{"Name":"www.mesh.internal.","Type":"CNAME","Value":"example.org."}],"changedSince":false}]}
```

| 칸 | 뜻 |
|---|---|
| `revert` | `here`, `link`, `no` |
| `reason` | `revert`가 `here`가 아닐 때 왜인지(아래 표) |
| `link` | `revert: link`일 때 `{kind, tenant?, app?}`. `kind`는 `app-revisions`(앱 › 버전 기록의 ‘이 버전으로 되돌리기’), `archived-apps`(내린 앱) |
| `action`, `target` | 원 작업의 동작과 표시용 대상 |
| `expected` | 지금 대상의 revision. 되돌리기를 보낼 때 그대로 싣는다 |
| `fields[]` | 원 작업이 바꾼 칸만. 순서는 동작마다 정해져 있다 |
| `fields[].path` | payload 안의 칸 이름(sfcd JSON 키, 하위 칸은 `.`으로). 화면 이름은 프런트엔드가 정한다 |
| `fields[].kind` | `value`: 값 하나. `set`: 순서 없는 줄 목록 |
| `before`, `after`, `now` | 바꾸기 전, 원 작업이 남긴 값, 지금 값. `null`일 수 있다 |
| `added`, `removed` | `set` 칸에서 원 작업이 더한 줄과 뺀 줄 |
| `changedSince` | 원 작업 뒤에 누가 그 칸을 또 바꿨는지. `value`는 지금 값이 `after`와 다르면, `set`은 더한 줄이 지금 없거나 뺀 줄이 지금 있으면 참이다. 화면은 참인 칸을 기본으로 끈다 |

| `reason` | 뜻 |
|---|---|
| `unsettled` | 결과 불명. 먼저 결과를 확인한다 |
| `not-applied` | 실패했거나 거부된 작업. 바뀐 것이 없다 |
| `irreversible` | 되돌릴 수 없다: 데이터·볼륨·백업 지우기, 원장·앱 기록 교체, 키·세션 회수, 비밀값 폐기, 이미지·캐시 정리, 로그 지우기, 서버 빼기 |
| `unsupported` | 아직 이 화면이 되돌리지 못하는 동작(아래 표에 없는 것) |
| `no-record` | 보낼 때의 대상 기록이 없다 |
| `created` | 원 작업이 대상을 새로 만들었다. 그 화면에서 지운다 |
| `target-gone` | 대상이 지워졌다 |
| `nothing` | 원 작업이 바꾼 칸이 없다 |

## 되돌리기: `POST /ops/{id}/revert`

```json
{"opId":"…","expected":16,"fields":["Policy.Upstreams"]}
```

- `opId`는 새 작업의 ID다(UUID v4, 소문자). 같은 opId·같은 내용이면 저장된 op를 돌려주고, 다른 내용이면 `409 op-conflict`.
- 웹은 대상을 다시 읽어 계획을 다시 만든다. 지금 revision이 `expected`와 다르면 `409 stale`이고 보내지 않는다. 계획을 다시 읽는다.
- 고른 칸: `value`는 `before` 값으로, `set`은 지금 줄에서 `added`를 빼고 `removed`를 더한다. 고르지 않은 칸은 지금 값 그대로다. 그래서 그 뒤 다른 사람이 바꾼 칸은 고르지 않으면 건드리지 않는다.
- `fields`가 비었거나 `expected`가 없으면 `400`, 원 작업이 바꾸지 않은 칸이면 `422 invalid`, 되돌릴 수 없는 작업이면 `422 not-revertible`.
- 사유 머리글 `X-SFC-Reason`·`X-SFC-Incident`를 받는다.
- 응답은 `POST /ops`와 같은 `{op}`이고 `op.revertOf`가 원 작업 ID다. 권한은 sfcd가 판단하므로 거절은 `rejected`/`failed`로 온다.

관리 변경 묶음(같은 `batch`)을 되돌릴 때는 브라우저가 확정된 변경만 뒤에서부터 하나씩 계획을 읽고 보낸다. 앞 것이 거부·불명이면 멈춘다. 결과 불명인 것은 건드리지 않는다.

## 되돌릴 수 있는 동작

| 동작 | 대상 | 칸 |
|---|---|---|
| `configure-network-dns` | 망 DNS 설정 | `Policy.Enabled`, `Reverse`, `Zone`, `ClientZone`, `TTL`, `NegativeTTL`, `Transports`, `Upstreams`, `MaxQueries`, `MaxCacheEntries`, `MaxResponseBytes`, `MaxConnections`, `RequestTimeoutMS`, `Policy.Records`(set). 직접 더한 레코드(`PATCH …/dns/records`)도 이 동작이다 |
| `set-network-toggle` | 망 토글 하나 | `On` |
| `set-node-quota` | 작업 공간의 서버 사용 한도 | `Capacity`, `Networks`, `MaxConsumers`, `PacketQueuePackets`, `PacketQueueBytes`, `MaxIngressInstances`, `MaxIngressListeners`, `MaxIngressRequests`, `MaxIngressConnections`, `IngressBufferBytes`, `Swap` |
| `set-membership` | 작업 공간 멤버십 | `Role`, `Enabled` |
| `set-nodes` | 작업 공간이 쓰는 서버 | `Nodes`(set) |
| `set-account-scope` | 계정의 동작 범위 | `Operations`(set, 비면 제한 없음), `KeyOnly`. 보내는 것은 지금 범위에서의 변경분이다: 원 작업이 더한 것은 `Remove`, 뺀 것은 `Add`, 되돌린 결과 제한이 없어지면 `Unlimited`, `KeyOnly`는 바뀔 때만 |
| `set-node-cli-policy` | 서버 CLI 정책 | `disable_node_cli_operation` |
| `set-node-shell-policy` | 서버 셸 정책 | `Enabled`, `MaxSessions`, `IdleSeconds` |
| `set-node-shell-node` | 서버 하나의 셸 | `Shell`, `Sudo` |
| `set-node-shell-grant` | 사용자의 셸 허용 서버 | `Nodes`(set) |
| `put-cluster-app-route`, `remove-cluster-app-route` | 클러스터 앱 외부 접속 경로 | `Ingress`(경로 정의 전체). 되돌리면 그 전 정의를 다시 넣거나, 전에 없었으면 뺀다 |

앱 배포는 `link: app-revisions`, 앱 내리기는 `link: archived-apps`로 이어 준다. 외부 도메인 레코드는 외부 도메인 화면의 되돌리기 지점을 쓴다(웹 작업 기록의 op가 아니다). 다른 동작은 아직 `unsupported`다.

남이 보낸 작업은 웹 작업 기록이 사람마다 따로라 이 끝점으로 되돌리지 않는다. 같은 대상을 관리 변경 화면에서 바꾼다.
