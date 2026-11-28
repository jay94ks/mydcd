# sfcli ingress: 앱의 외부 접속 보기와 제어

ingress는 앱 route를 서버의 공용 게이트웨이(external·local)에 붙인다. 앱 쪽 route는 app.yaml에 쓰고, 여기 명령은 지금 상태를 보거나 운영 중에 잠시 바꾼다.

## 보기

| 명령 | 하는 일 |
|---|---|
| `sfcli ingress list [--all] [--node NODE] [--app APP]` | ingress와 서버별 상태 |
| `sfcli ingress show KEY` · `metrics KEY` · `errors KEY` | ingress 하나의 설정, 요청 지표, 최근 오류. KEY는 `list`에 나온다 |
| `sfcli ingress history` | 최근 게이트웨이·분배·drain 변경 |
| `sfcli ingress blocks` | 차단 목록과 서버별 적용 상태. 지운 차단은 상태 `removed`로 남는다 |

`--all`은 읽을 수 있는 모든 작업 공간(시스템 관리자는 클러스터 전체)을 본다.

## 차단

```sh
sfcli ingress block maint --scope route --app shop --key KEY --route web --host shop.example.com --prefix / --for 2h --reason "DB 점검"
sfcli ingress extend maint --for 4h
sfcli ingress unblock maint
```

`--scope`는 route, host, backend, instance, source, tenant, node, gateway 중 하나다. 범위마다 필요한 옵션은 `sfcli ingress block --help`에 있다. `--response`는 503(기본), 403, reset. `--cut-existing`은 이미 진행 중인 요청도 끊는다. `--for`를 주지 않으면 `unblock`할 때까지 남는다.

## 운영 중 바꾸기

| 명령 | 하는 일 |
|---|---|
| `sfcli ingress balance APP ROUTE -f balance.yaml` | route 하나의 분배 방식을 바꾼다. app.yaml보다 우선한다 |
| `sfcli ingress drain APP [--node NODE] [--grace 30s]` | 앱에 새 요청을 보내지 않는다. 진행 중인 요청은 grace 동안 끝내게 둔다(최대 1h) |
| `sfcli ingress undrain APP [--node NODE]` | 다시 요청을 보낸다 |
| `sfcli ingress gateways show NODE` | 서버의 게이트웨이 설정과 적용 여부 |
| `sfcli ingress gateways set NODE -f gateways.yaml` | 서버의 게이트웨이 설정을 바꾼다(시스템 관리자) |

바꾸는 명령은 `--id ID`를 받고, revision이 있는 대상은 `--if-revision N`도 받는다.

balance.yaml(app.yaml route의 `balance`와 같은 모양에 `version: 1`):

```yaml
version: 1
method: weighted
weights: {v1: 90, v2: 10}
```

gateways.yaml(서버 설정의 `modules.ingress.gateways`와 같은 모양):

```yaml
version: 1
external:
  enabled: true
  addresses: [203.0.113.10]
  ports: [443]
  listeners:
    - {id: public-https, address: "203.0.113.10:443", tls: true, http3: true}
local:
  enabled: true
  addresses: [10.0.0.11]
  ports: [443]
  allowed_sources: [10.0.0.0/8]
  listeners:
    - {id: internal-https, address: "10.0.0.11:443", tls: true}
```

주소 규칙은 [공유 HTTP 게이트웨이](../reference/ingress-gateways.md)에 있다.
