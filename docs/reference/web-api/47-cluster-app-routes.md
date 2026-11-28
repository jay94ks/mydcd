# 클러스터 앱 경로 (UI-5E)

웹 UI(sfc-web)처럼 클러스터에 하나만 도는 클러스터 앱의 ingress route는 작업 공간 앱이 아니라 클러스터 설정이다. 그래서 `/ingress` 매핑 목록에는 나오지 않는다. 이 끝점으로 따로 읽고 바꾼다. `sfcli app diff`·`deploy -f`·`app down cluster-app/web`과 같은 설정이다([CLI](../../cli/app.md)). 시스템 관리자만 읽고 바꿀 수 있고, 그 밖의 사용자는 `403`이다. 지금 route를 받는 앱은 `web` 하나이며, 다른 이름은 `404`다. 코드는 [cluster_app_routes.go](../../../internal/web/server/cluster_app_routes.go)에 있다.

## 읽기: `GET /cluster-apps/{app}/routes`

```json
{"app":"web","revision":1,"removed":false,"node":"node-a",
 "listeners":[],
 "routes":[{"id":"route-1","host":"sfc.example.com","prefix":"/","gateway":"local"}],
 "file":"name: cluster-app/web\nx-sfc:\n  ingress:\n    - node: node-a\n..."}
```

| 칸 | 뜻 |
|---|---|
| `revision` | 다음 변경의 `expected`. 0이면 아직 한 번도 정하지 않았다 |
| `removed` | 지운 설정. route 목록은 마지막 것을 보여 주고, 그 서버의 ingress는 진행 중인 요청을 마치고 닫는다 |
| `node` | route를 여는 서버 |
| `routes[].gateway` | `local`, `external`, `both` |
| `file` | 지금 설정을 route 파일로 쓴 것. 고쳐서 PUT으로 다시 보낼 수 있다. 한 번도 정하지 않았으면 없다 |

## 바꾸기: `PUT /cluster-apps/{app}/routes`

```json
{"opId":"…","expected":1,"file":"name: cluster-app/web\nx-sfc:\n  ingress: {...}"}
```

`file`은 route 파일 원문이다(최대 64KiB). `x-sfc.ingress`는 앱과 같은 route 목록이다([공유 HTTP 게이트웨이](../ingress-gateways.md)). 수신 주소는 적지 않으므로 `listeners`는 비어 있고, route 서버의 gateways 설정에서 정해진다. `name`은 `cluster-app/{app}`이어야 하고, `x-sfc.ingress`만 받는다. 서비스, Volume, Secret, 망, CD, backend(망·포트·health 경로)를 적으면 `422 invalid`다. `expected`를 빼면 지금 revision을 쓴다. 결과는 다른 변경과 같은 작업(op) 응답이다([작업](04-operation.md)). 같은 서버·수신 주소·게이트웨이에서 작업 공간 앱과 host가 같으면, prefix가 달라도 sfcd가 거절한다.

## 지우기: `DELETE /cluster-apps/{app}/routes`

```json
{"opId":"…","expected":2}
```

route를 지운다. 이미 지웠거나 한 번도 정하지 않았으면 작업이 실패로 끝난다.
