# 변경 감시 (ChangeWatch)

sfcd가 적용한 클러스터 변경 가운데 **그 세션이 읽을 수 있는 기록이 무엇인지만** 알려 주는 오래 사는 스트림이다. 내용은 보내지 않는다. 받는 쪽은 바뀐 기록을 그 기록의 평소 조회로 읽는다(읽기 권한도 그 조회가 다시 판단한다). 설계: 웹 UI 실시간 반영.

## 연결

- purpose **ChangeWatch=22**. 그 노드 자신의 연결(Unix `sfcdp.sock` 또는 직접 QUIC)에서만 받는다. 다른 노드로 중계하지 않는다: 모든 노드가 같은 변경을 적용하므로 가까운 노드를 감시하면 된다.
- 스트림 하나가 연결 하나를 끝까지 쓴다. 여러 감시를 동시에 열려면 연결(transport)을 따로 연다.
- 요청 frame(kind 1): `Envelope{Session, Body, Signature}`, Body는 `ChangeWatchRequest{Schema:1, From, Nonce, Topics}`. `Topics`는 변경에 더해 받을 사건 주제다(`report`, 알림 하나 `alarm/<이름>`, 모든 알림 `alarm/`. 모르는 주제는 무시). 보낸 뒤 쓰기 쪽을 닫는다.
- 응답 frame(kind 2): `ChangeWatchReply{Schema:1, Code, Index, Resync, Refs, Events, EventsLost}`. 세션이 끝날 때(`ExpiresAt`)까지 이어진다.

## 응답

| 필드 | 뜻 |
|---|---|
| `Code` | `ok`면 계속된다. 그 밖(`denied`: 세션이 더는 유효하지 않음, `unavailable`)은 스트림의 끝 |
| `Index` | 이 노드가 적용한 Raft index. 여기까지의 변경을 모두 보냈다 |
| `Resync` | `From` 이후 변경을 이 노드가 더는 기억하지 않는다(재시작, 4096개 적용보다 오래됨, 한 번에 512개보다 많음). 다시 읽고 이 `Index`부터 이어 간다 |
| `Refs` | 바뀐 기록 `{Kind, Tenant, Name, Deleted}` |
| `Events` | 요청한 주제의 사건 `{Topic, Kind, Node, Source, Tenant, App, Note}`(Note는 알림의 짧은 글, 256B까지). 번호가 없고 이어 받지 않는다. 사건 frame의 `Index`는 앞 frame과 같다 |
| `EventsLost` | 사건을 일부 놓쳤다(감시가 밀림, 한 번에 512개보다 많음). 그 주제로 보이는 것을 한 번 다시 읽는다 |

- 알림은 보낸 노드가 감시자에게 보내기로 고른 것(Scope.Web)만 오고, Tenant가 있으면 그 작업 공간 Read, 없으면 ManageCluster가 있어야 받는다. Node는 보낸 노드다. 저장·재전송이 없어 놓친 알림은 다시 받지 않는다.
- `From`이 0이면 지금부터 감시한다. 첫 frame은 시작 `Index`다.
- 바뀐 것이 없으면 20초마다 `Refs` 없는 frame을 보내 스트림이 살아 있음을 알린다.
- frame마다 그 세션과 카탈로그를 다시 확인한다. 세션이 폐기되면 `denied`로 끝나고, 작업 공간 권한이 빠지면 그 작업 공간의 기록은 그때부터 오지 않는다.

## 기록 종류

| Kind | Tenant | Name | 읽는 조회 | 받는 세션 |
|---|---|---|---|---|
| `app` | 작업 공간 | 앱 이름 | `apps` | 그 작업 공간 Read |
| `volume` | 작업 공간 | 볼륨 키 | `volumes` | 그 작업 공간 Read |
| `network` | 작업 공간, 시스템 네트워크 구성원은 `""` | 네트워크 ID | `resources` | 작업 공간 Read, `""`는 ManageCluster |
| `tenant` | 작업 공간 | 작업 공간 ID | `tenants` | 그 작업 공간 Read 또는 ManageCluster |
| `node` | `""` | 서버 ID | `members` | ManageCluster |
| `registry` | 작업 공간 | Registry ID | `registries` | 그 작업 공간 Read 또는 ManageRegistry |
| `registry-maintenance` | 작업 공간 | Registry ID (그 Registry의 정리·가지치기 작업이 바뀜) | `registries`, `registry-maintenance-status` | 그 작업 공간 Read 또는 ManageRegistry |
| `ingress` | 작업 공간, 클러스터 부분은 `""` | 바뀐 부분: `block/<ID>`, `host-policy`, `balance/<앱>/<경로>`, `drain/<앱>/<서버>`, `gateway/<서버>`, `cluster-app-route/<앱>`, `history` | `ingresses` | 작업 공간 Read, `""`는 ManageCluster |
| `dns` | 작업 공간 | 네트워크 ID (관리 DNS 설정) | `network-dns-names` | 그 작업 공간 Read |
| `certificate` | `""` | 인증서 ID | `certificates` | ManageCluster |
| `domain` | `""` | 도메인 이름 | `certificates` | ManageCluster |
| `acme-responder` | `""` | `acme-responder` | `certificates` | ManageCluster |

ingress 매핑(앱별 공개 경로)은 앱 목표에서 나오므로 `app` 기록이 바뀔 때 같이 바뀐다. 서버가 잰 수치(요청 수·지연·차단 적용 상태)와 관리 DNS의 서버별 반영 상태는 기록이 아니라서 여기로 오지 않는다.

기록 종류는 늘어날 수 있다. 모르는 Kind는 무시한다.

## 사건 주제

`report`: 노드 보고를 받아 저장한 값이 실제로 바뀌었다(같은 바이트 재보고·오래된 표본·30초 갱신은 사건이 아니다). 보고는 정식 구성원 노드 모두에 도착하므로 어느 노드를 감시해도 같다. 값은 싣지 않는다.

| Kind | 대상 | 받는 세션 |
|---|---|---|
| `node-observation` | `Node`의 관측 `Source`. 작업(Task)·사용량·레지스트리 가져오기면 `Tenant`/`App`도 | `Tenant`가 있으면 그 작업 공간 Read, 없으면 ManageCluster |
| `node-report` | `Node`의 작업량 보고 | ManageCluster |
| `diagnostic` | `Node`의 사건 묶음 | ManageCluster |

`engine`: 이 노드 Seafield 엔진의 사건. 다른 노드의 엔진 사건은 0.1.0에서는 오지 않는다(다른 서버는 `report`로 따라간다).

| Kind | 대상 | 받는 세션 |
|---|---|---|
| `engine.container` | `Node`의 `Container`, 작업이면 `Tenant`/`App`. `Reasons` ⊆ start, stop, die, oom, pressure, health | `Tenant`가 있으면 그 작업 공간 Read, 없으면 ManageCluster |
| `engine.node` | `Node`의 엔진. `Reasons` ⊆ boot, lag(사건을 놓침: 엔진 화면을 모두 다시 읽음), build | ManageCluster |
