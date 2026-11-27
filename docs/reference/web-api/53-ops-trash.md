# 지운 것 되살리기 (UI-A5)

실수로 지운 정의를 보관 기간 동안 되살린다. 웹이 지운 정의를 bbolt에 남기고, 되살리기는 같은 정의를 다시 만든다. sfcd에 새 기능은 없다. 비밀 값(서명 비밀, 토큰, OAuth 로그인)은 남기지 않으므로 되살린 뒤 새로 넣는다. 코드는 [trash.go](../../../internal/web/server/trash.go)에 있다.

보관 기간은 웹 앱 설정의 `trashRetentionDays`(1–30일, 0이면 7일)다. 지난 것은 한 시간마다 비운다.

## 무엇이 남나

| `kind` | 언제 남나 | 되살리기 | 못 되살리는 것 |
|---|---|---|---|
| `webhook` | `DELETE /webhooks/{name}` | 웹 bbolt에 정의와 연결을 다시 넣는다. 전송 기록은 없다 | HMAC 서명 비밀(새로 만들어 응답에 한 번 준다), 헤더 토큰(꺼진 채로 되살리고 `disabledReason: restored`, 새 토큰을 넣고 켠다) |
| `mcp-server` | `DELETE /system/mcp/{name}` | 정의·도구 설정을 다시 넣고, 그 서버를 쓰던 지침의 `mcpServers`에 다시 더한다 | 토큰(`bearer`는 꺼진 채 `error: token needed`), OAuth 로그인(`needsLogin`) |
| `guide` | `DELETE /guides/…` | 지침과 지난 버전을 모두 다시 넣는다 | 없음 |
| `dns-record` | 망 DNS에 직접 더한 레코드를 뺀 변경이 확정될 때(`PATCH …/dns/records`의 `remove`, 설정 바꾸기 포함). 같은 이름·종류를 함께 더한 것은 고치기라 남기지 않는다(그 변경의 [되돌리기](52-ops-revert.md)를 쓴다) | `configure-network-dns` 변경 | 없음 |
| `cluster-app-route` | `remove-cluster-app-route`가 확정될 때 | 그 전 경로 정의 전체로 `put-cluster-app-route` 변경 | 없음 |

앱 ‘내리기’는 원래처럼 내린 앱 보관(`/archived`)에 남는다. 목록에는 `kind: app`, `restore: link`로 함께 보인다. 사용자는 sfcd에서 지울 수 없고 끄기만 하므로 여기 없다. 데이터 저장소의 데이터, 망·작업 공간·서버는 되살리지 않는다.

## 목록: `GET /trash`

```json
{"retentionDays":7,"items":[
 {"id":"3f0c…","kind":"dns-record","tenant":"shop","name":"cache.shop.internal. CNAME","deletedBy":"alice",
  "deletedAt":"2026-11-27T01:12:00Z","expiresAt":"2026-12-04T01:12:00Z","restore":"here",
  "detail":{"network":"shop-net","name":"cache.shop.internal.","type":"CNAME","value":"web.php.shop.internal.","ttl":0}},
 {"id":"a91b…","kind":"webhook","name":"slack-ops","deletedBy":"carol","deletedAt":"…","expiresAt":"…","restore":"here","lost":["secret"],
  "detail":{"kind":"external","role":"notify","format":"slack","sign":"hmac","url":"https://hooks.example/…","links":2}},
 {"id":"app:shop/php-legacy/…","kind":"app","tenant":"shop","name":"php-legacy","deletedBy":"alice","deletedAt":"…","restore":"link",
  "link":{"kind":"archived-apps","tenant":"shop","app":"php-legacy"}}]}
```

최신순이다. 내가 그 종류를 관리할 수 있는 범위만 보인다: 웹훅은 작업 공간 관리자(클러스터 웹훅은 시스템 관리자), 지침은 그 범위를 고칠 수 있는 사람, MCP 서버와 클러스터 앱 경로는 시스템 관리자, 망 DNS 레코드는 그 작업 공간 사람. 망 DNS 레코드와 클러스터 앱 경로의 되살리기 권한은 sfcd가 판단한다.

| 칸 | 뜻 |
|---|---|
| `op` | sfcd 정의: 그것을 뺀 내 작업 ID(토스트의 [실행 취소]가 이것으로 항목을 찾는다) |
| `restore` | `here`: 아래 끝점. `link`: `link`의 화면 |
| `lost` | 되살려도 돌아오지 않는 것: `secret`, `token`, `login` |
| `detail` | 종류별 보기. `webhook`: kind·role·format·sign·url·target·links(연결 수). `mcp-server`: url·auth·tools·guides. `guide`: scope·app·version·versions. `dns-record`: network·name·type·value·ttl. `cluster-app-route`: app·file(경로 파일 YAML) |

`GET /trash/{id}` → `{item}`. 없거나 기간이 지났거나 볼 수 없으면 `404`.

## 되살리기: `POST /trash/{id}/restore`

```json
{"opId":"…","name":"","replace":false}
```

| 칸 | 뜻 |
|---|---|
| `opId` | `dns-record`, `cluster-app-route`만. 되살리기 변경의 ID(UUID v4, 소문자) |
| `name` | 다른 이름으로 되살리기. `webhook`·`mcp-server`는 새 이름, `dns-record`는 zone 아래 이름(`www`처럼) |
| `replace` | 같은 자리에 지금 다른 것이 있으면 바꿔 넣기. `guide`는 지금 지침 위에 새 버전으로, `dns-record`는 같은 이름·종류의 지금 레코드를 빼고, `cluster-app-route`는 지금 정의를 덮는다 |

- 같은 이름·자리에 지금 무엇이 있으면 `409 exists`이고 `current`에 그것을 담는다. 화면은 ‘되살리지 않고 닫기’·‘바꿔 넣기’(`replace`)·‘다른 이름으로’(`name`)를 고르게 한다.
- 웹 자체 정의(`webhook`, `mcp-server`, `guide`) → `200 {restored:{kind, name, enabled?, version?}, secret?:{set, value}}`. `secret.value`는 이때 한 번만 준다.
- sfcd 정의(`dns-record`, `cluster-app-route`) → [작업](04-operation.md)과 같은 `{op}`. 변경이 확정되면 그 항목이 목록에서 빠진다. 거절·실패면 남는다. `dns-record`는 망이나 관리 DNS가 없으면 `422 target-gone`, zone이 바뀌었으면 `422 zone-changed`(다른 이름으로 되살린다), 같은 레코드가 이미 있으면 `422 exists`.

## 비우기: `DELETE /trash/{id}`

보관 기간 전에 지운다 → `204`. 되살릴 수 있는 사람만 할 수 있다.

## 지우기 응답

웹 자체 정의를 지우는 끝점은 `204` 대신 `200 {trash:{id, expiresAt}}`를 준다. 화면은 이 `id`로 토스트의 [실행 취소]를 바로 보낸다. sfcd 정의는 지운 변경이 확정된 뒤 `GET /trash`에 그 작업 ID(`op`)와 함께 나타난다.
