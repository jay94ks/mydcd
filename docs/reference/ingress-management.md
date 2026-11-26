# Ingress 조회·관측·차단

Ingress의 앱 목표는 `app.yaml`과 기존 앱 작업이 소유한다. 조회·최근 요청 지표와 일시 차단은 그 목표나 컨테이너 Task를 변경하지 않는다. 실제 관측은 해당 노드의 `mydcd`가 수집하며 Unix TLS와 네트워크 MYDCP의 동일 사용자 API에서 읽는다.

## 조회

명령과 옵션은 [mydc ingress](../cli/ingress.md)에 있다.


User Request는 `Method:"ingresses", Tenant, Ingress:{Node,Tenant,App,Key,Part,After,Offset}`다. `Part`는 `mappings`(기본), `metrics`, `errors`, `blocks`, `policies`다. 다른 User selector나 별도 Request.After와 혼합하지 않는다. 시스템 관리자도 현재 credential의 범위를 넘지 않으며, 그 외 사용자는 현재 Read 권한이 있는 tenant/node의 행과 집계만 받는다.

Reply.Ingress는 `Schema:1,Index,Epoch,RootRevision,BlockRevision,Mappings,Nodes,Blocks,HostPolicies,Next`다. 매핑 목록은 정렬된 key 순서의 한 행씩 반환하고, 목록 `Next`를 `--after`로 전달한다. 한 매핑 안의 `Next`는 숫자 `--offset`이며 listener/route/backend/block 상세를 각각 최대4개씩 이어 읽는다. blocks는8행, policies는4행씩 숫자 offset으로 이어진다. 일반 User frame의 예산 안에서 처리하며 전체 응답의 JSON은112KiB 이하이다.

`Nodes[].Listeners`는 현재 읽기 권한으로 선택한 행들의 수신 주소 수다. 같은 노드의 같은 shared listener를 여러 앱이 참조해도 한 번만 센다. 서로 다른 노드와 직접 주소는 별개이며, 미선택 tenant의 주소를 합치지 않는다. Shared listener는 앱의 MaxIngressListeners 예산에서 제외하고, 직접 listener의 TCP/UDP 포트 예약과 현재 주소 수를 구분한다.

각 매핑은 tenant/app/node/owner·현재 generation/revision·readiness/drain·관측 시각/오류·목표 Spec과 실제 Runtime을 구분한다. 실제 listener 주소·인증서·HTTP/3 상태, backend Task/node/network/address/port/weight/health와 해당 관측 시각, 적용 block ID를 포함한다. `NOT_OBSERVED`, `GENERATION_PENDING`, `MODULE_DISABLED`, `NODE_UNREACHABLE`, `OBSERVATION_UNAVAILABLE`을 Ready로 바꾸지 않는다.

`Runtime.BlockRevision`은 owner가 실제 설치한 차단 정책의 revision이다. 페이지의 `BlockRevision`(현재 정책 book 목표)과 비교하며, 제거된 목표 ID가 `Runtime.Blocks`에서 보이지 않는 것만으로 해제 적용을 판정하지 않는다. 해당 해제의 관리 revision 이상이 설치되었는지 함께 확인한다. 아직 설치하지 않았거나 관측할 수 없으면 해제 완료로 표시하지 않는다. 이 값은 현재 node-local 적용 관측이며 실행 승인이나 새 Raft 상태가 아니다.

`Runtime.Certificates`는 호스트별 `{Host,Fingerprint(인증서 ID),NotAfter,LoadedAt,Error}`의 현재 공개 적재 관측이다. 실패 때 유지 중인 이전 인증서와 오류를 함께 표시하며 개인키·복호화 키·TLS 내부 객체는 포함하지 않는다. `CertificatesTotal`과 매핑의 `Offset/Next`로 다른 상세와 같이 최대4개씩 읽는다.

Nodes는 현재 선택 범위에 보이는 모든 매핑의 instance/listener/buffer 사용량과 quota를 담는다. tenant를 지정하면 해당 tenant×node 한도이며, tenant를 생략한 일반 계정은 읽을 수 있는 tenant 한도의 합이다. 시스템 관리자의 cluster 조회는 node 전역 한도를 사용한다. 연결·동시 요청은 담당 노드에서 같은 권한 범위의 실제 전체 snapshot을 합산한다. 원 노드 응답/현재 세대 확인이 불가능하면 값은 `-1`, Enabled는 미확인으로 남는다. node 전체 사용량처럼 다른 tenant를 포함한 집계로 대체하지 않는다. 시스템 관리자의 Nodes.Gateways에는 external/local별 source 거부와 매핑되지 않은 host의404 누계도 포함한다. 이 전역 계수는 tenant 계정에게 공개하지 않는다.

`Nodes[].Gateways[].Listeners`는 실제 공유 수신 주소의 ID·Address·Gateway·HTTP3·Ready·Error와 현재 읽을 수 있는 `Hosts[{Host,Prefix,Tenant,App}]`를 제공한다. listener/host binding을 gateway별 한 순서로 최대4개씩 반환하므로 같은 listener ID가 호스트별로 반복될 수 있다. `BindingsTotal,Offset,Next`를 제공하며 같은 조회의 `Ingress.Offset`에 Next를 넣어 이어 읽는다. 시스템 관리자는 호스트가 없는 설정 listener도 한 binding으로 보며 일반 사용자는 읽을 수 있는 host가 붙은 수신 주소만 본다. source 거부·unmatched 전역 계수는 tenant 조회에 공개하지 않는다.

## 최근 요청 지표

Runtime.Metrics는 메모리에 최근60초를 유지한다. instance/route/backend/gateway/분배 조건별 요청 수·초당 rate·2xx/3xx/4xx/5xx·차단 수·수신/전송 bytes·proxy 실패 코드 수와 p50/p95/p99 지연을 제공한다. 지연 백분위는2의 거듭제곱 millisecond histogram의 상한 추정이다. `Metric.OpenConnections`는 실제 upstream Dial 성공부터 Close까지의 현재 연결 수이며 `ConnectionKind:upstream-live`로 표시한다. route/backend의 client 측 HTTP/2 공유 연결 수를 요청 수로 위장하지 않는다. client 총 활성 연결·동시 요청은 매핑 Runtime에 있다. restart 이전의 메모리 지표를 Raft에서 재구성하지 않는다.

4xx/5xx·차단·proxy 실패의 최근 오류 최대200건을 보관한다. errors는 한 페이지16건, 지표 차원은4건씩 offset으로 이어 읽는다. 오류에는 method/host/query를 제거한 path·선택 backend·실패 코드·상태·지연과 가린 source만 있다. IPv4는 /24, IPv6는 /48이고 header/body/전체 client IP를 보관하지 않는다.

## Raft 차단

CLI는 `mydc ingress block ID --scope ...`, `extend ID --for`, `unblock ID`다([사용법](../cli/ingress.md#차단)). 서버 메시지의 Block 예시:


```json
{"ID":"maintenance","Scope":"route","Tenant":"team","App":"shop","Node":"node-a","Key":"ingress/app/team/shop/http","Route":"admin","Host":"shop.example","Prefix":"/admin","Response":"503","CutExisting":false,"ExpiresAt":1800000000,"Reason":"maintenance"}
```

Scope는 route/host/backend/instance/source/tenant/node/gateway다. route는 생성 시 존재하는 rule ID와 정확한 Host+Prefix를 확인한 뒤, 해당 Host+Prefix가 재등장해도 원 차단을 적용한다. 먼저 선택된 route에 차단을 적용하며 더 짧은 prefix로 fallback하지 않는다. host는 같은 host의 모든 규칙, backend는 후보 제외, source는 tenant의 canonical CIDR와 선택 Apps에 적용한다. source의 IPv4/IPv6 `/0`은 거부한다. Gateway는 선택 사항인 external/local/both 필터이고, gateway scope 자체는 external 또는 local을 지정한다.

tenant/node/gateway 범위와 여러 tenant의 host 차단은 시스템 관리자만 수행한다. 그 외 범위는 자신의 tenant/node ManageNetwork 권한과 현재 operation 허용 목록을 검사한다. 응답은503 또는403이며 reset은 연결 종료다. CutExisting은 실제 실행 중인 요청의 취소를 동반한다. backend 차단이 모든 후보를 제거하면 다른 route로 보내지 않는다.

관리 action은 `ingress-block`, `ingress-unblock`, `ingress-block-extend`이며 `control/ingress-management`의 별도 Raft 기록이다. 생성 Expected=0, 해제/연장은 해당 block Revision CAS다. Actor/CreatedAt은 서명된 원 사용자 operation에서 고정하고, 연장은 유한 만료만 더 늦출 수 있다. 만료는 관측 시각으로 평가하며 원 레코드를 삭제하거나 같은 revision에서 다른 정책을 만들지 않는다. 같은 ID는 재사용하지 않는다.

blocks 조회는 원 Revision/Removed/Active/TargetMissing을 보여 준다. `--node`를 지정하거나 해당 매핑을 조회하면 실제 노드의 Applied/AppliedAt/Error/BlockedRequests를 읽는다. Applied 판정은 `gateway: both` 선언 자체가 아니라 실제 listener의 external/local 종류를 같은 요청 매칭 함수에 전달한다. 실제 노출되지 않은 게이트웨이를 적용 대상으로 합성하지 않는다. 원 노드 응답이 없으면 적용 성공을 합성하지 않는다. TargetMissing은 목표가 제거되었다는 뜻이며 해당 원 차단을 해제하지 않는다. 같은 정책은 재시작 후 Raft에서 다시 적용한다.

원 작업 ID의 입력과 결과는 CLI journal에 보존한다. 결과를 모르면 `mydc op show ID`로 묻고 `mydc op resume ID`로 같은 작업만 이어 보낸다. 새 ID·새 CAS·현재 계획으로 원 요청을 대체하지 않는다. 확정 차단/해제는 공개 ingress 이벤트와 기존 관리 감사를 사용한다.

## 해제 적용 상태의 비교

원 `ingress-unblock` 작업이 확정된 뒤 `ingresses` 한 페이지(또는 `ingress list/inspect`)의 **`BlockRevision`**을 목표로 읽는다. 이는 현재 차단 정책 book의 단조 revision이며 owner의 `Runtime.BlockRevision`과 같은 단위다. `RootRevision`은 저장된 관리 root의 CAS revision, `Blocks[].Revision`은 블록 하나의 CAS이므로 이 비교에 사용하지 않는다. 앱 관측·Task 변경·tenant 생성처럼 이 정책 book을 변경하지 않는 명령은 `BlockRevision`을 바꾸지 않는다.

| 서버별 관측 | 판정 |
|---|---|
| 현재 owner의 유효한 Runtime이 있고 `Runtime.BlockRevision >= BlockRevision` | 해당 페이지 목표까지 적용됨. 확정된 해제도 포함 |
| 유효한 Runtime이 있고 `Runtime.BlockRevision < BlockRevision` | 적용 대기 |
| Runtime 부재·노드 미응답·관측 오류/세대 불일치 | 관측 불가. 적용 여부를 단정하지 않음 |

목표 ID 부재만으로 적용됨을 판정하지 않는다. 여러 서버는 각 매핑 owner의 현재 관측으로 따로 비교한다. 후속 차단 정책이 추가되면 새 페이지는 그 정책까지 포함한 새 목표를 반환한다. 관측의 선후와 원 해제 작업의 확정은 별개이며 이 조회는 재제출하지 않는다.

## Tenant host 권한

CLI는 `mydc ingress hosts set --tenant team [--external-allowed] [--external a,b] [--local c]`다.


서버 메시지는 `{"Tenant":"team","Policy":{"ExternalAllowed":false,"ExternalHosts":[],"LocalHosts":["*.internal.example"]}}`다. 시스템 관리자만 `set-ingress-host-policy`로 tenant의 현재 host 권한을 변경한다. 패턴 목록 각각 최대256개, 정책 JSON 최대24KiB다. 새 shared 모드에서 미설정 정책은 external 비허용·local host 없음으로 시작한다. legacy 앱의 직접 address listener에는 이 shared host grant를 요구하지 않는다.

정책 회수는 이미 수락된 앱·원 native 참조를 삭제하지 않는다. 새 blueprint 수락/current native 실행과 실제 gateway에서 현재 권한을 확인한다. 인증서의 보호 입력과 연결 규칙은 [인증서 보관함](certificate-store.md)을 따른다.

## 이벤트

기존 [이벤트 API](events.md)의 현재 사용자 권한·cursor·서명된 source journal을 사용한다. Runtime 관측은 `Node,Gateway,Tenant?,App?,RouteID?,Host?,Prefix?`와 source 관측 시각, 필요한 `Detail.Value`를 보존한다.

| 종류 | 범위·발생 조건 |
|---|---|
| `ingress-blocked`, `ingress-unblocked` | 확정 block/extend 또는 unblock의 원 operation과 대상. 앱/tenant 대상은 해당 scope, 전역 대상은 시스템 관리자만 조회 |
| `ingress-backends-empty`, `ingress-backends-restored` | 실제 health 관측에서 route의 사용 가능한 backend가 없어지거나 돌아온 전이. 같은 상태를 매 polling마다 새 사건으로 만들지 않음 |
| `ingress-listener-up`, `ingress-listener-down` | 공유 listener의 실제 시작·종료/열기 실패. node·gateway 범위, 시스템 관리자만 조회 |
| `ingress-certificate-missing` | 해당 host/route의 인증서 공급 실패로 TLS를 거부하는 전이. [인증서 이벤트](certificate-store.md)와 같은 journal |
| `ingress-source-rejected-spike` | 로컬 gateway의 사전 source gate 거부가 source의 한 Unix 초에100회에 도달. `Detail.Value=100`, node·gateway 범위이며 tenant 정보 없음 |

5xx 비율·p95의 사용자별 기준/지속 시간과 회복 판단은 현재 웹 소비자가 위 최근 지표로 계산한다. 별도 `ingress-alert-thresholds` 관리 명령이나 `ingress-error-rate` 사건을 제공하지 않는다. 이는 요청 G에서 허용한 지표 기반 방식이며 일반 Runtime 계수를 Raft의 관리 목표로 저장하지 않는다. 웹훅 전송도 웹 소비자의 책임이다.

분배 정책 갱신이 수락되어 새 실행이 Planned여도, 다음 stage 명령이 아직 없는 동안 현재 확정 source의 정확한 key/generation/revision/value와 원 claim에 고정된 listener 신원은 유지된다. owner의 로컬 journal pin도 같은 신원이어야 한다. 새 계획의 미전송 값을 현재 source로 취급하거나 결과/새 신원을 만들지 않으며, 실제 정책 변경·재기동은 기존 현재 권한/quorum/native permit 검사를 거친다.

## Gateway·분배·drain 변경과 공개 이력

이 설정은 `control/ingress-management`의 관리 overlay다. 앱/Task/container generation과 원 Ingress native source를 바꾸지 않는다. Unix 관리 TLS와 네트워크 MYDCP의 User 요청은 같은 현재 계정·서명·권한·Raft/record CAS·원 operation journal을 사용한다.

| CLI | 관리 action / 조회 Part | 입력·범위 |
|---|---|---|
| `ingress gateways show NODE` | `ingresses` / `gateways` | 현재 시스템 관리자. 파일/클러스터 목표와 실제 적용 revision·오류 |
| `ingress gateways set NODE -f gateways.yaml` | `set-node-gateways` | `{Node,External?,Local?}`. 하나 이상 지정, `Evidence`는 사용자가 입력하지 않음 |
| `ingress balance APP ROUTE -f balance.yaml` | `set-ingress-balance` | `{Tenant,App,Route,Balance}`. 해당 tenant의 현재 Network 관리 권한 |
| `ingress drain\|undrain APP [--node NODE] [--grace 30s]` | `drain-ingress` / `undrain-ingress` | `{Tenant,App,Node?,DrainSeconds?}`. node 생략은 앱 전체 |
| `ingress history [--app APP] [--node NODE] [--all]` | `ingresses` / `history` | 현재 Read 범위의 공개 변경 이력 |

입력 파일은32KiB 이내다. 첫 record의 expected는0이며 이후 해당 gateway/balance/drain record의 `Revision`이다. CLI는 이 값을 읽어 넣고, `--if-revision`으로 직접 정할 수 있다. Raft root revision과 record revision은 별개다. 같은 `--id`로 다시 실행하면 원 입력/expected/작업 ID·서명과 gateway evidence를 그대로 보낸다. 재실행으로 새 evidence나 CAS를 붙여 같은 ID의 뜻을 바꾸지 않는다.

```json
{"Node":"node-a","External":{"Enabled":true,"Addresses":["203.0.113.10"],"Ports":[443],"Listeners":[{"ID":"public-https","Address":"203.0.113.10:443","TLS":true,"HTTP3":true}]}}
```

주소는 대상 노드의 실제 주소여야 하고 wildcard는 거부한다. 현재 work-eligible owner가 같은 node/request/user/session key/epoch/expected·이전/다음 설정에 결합된30초 이내 preflight evidence를 서명하며 reducer가 독립 검증한다. 비활성 gateway의 허용 주소/포트 목록만으로 소켓을 예약하지 않는다. 활성 listener의 TCP와 HTTP/3 UDP는 앱·단독 컨테이너 Compose `ports:`와 같은 host namespace에서 충돌을 검사한다. 현재 키 교체 뒤에도 기존 gateway claim의 원 owner를 유지하고 정확한 원 claim의 명시 CAS 교체만 허용한다.

`NodeGateways[]`는 `{Node,Source,Revision,AppliedRevision,Configuration,Error?}`다. Source는 `file` 또는 `cluster`이며 클러스터 설정이 존재하면 파일보다 우선한다. 수락과 실제 bind는 별개다. bind 실패는 Error에 남고 AppliedRevision을 목표 revision으로 위장하지 않는다. `Nodes[].Configuration`도 같은 공개 값이다.

```json
{"Tenant":"tenant","App":"shop","Route":"web","Balance":{"Method":"hash","Key":"cookie:session"}}
```

Balance는 기존 분배 규격(round-robin/least-request/hash/random, key·weights·groups·match·fallback·locality·slow-start·retry)을 사용한다. route별 관리 overlay와 `BalanceRevision`을 보여 주며 원 선언과 관리 적용 값을 구분한다. 기존 listener/컨테이너를 재생성하지 않는다.

```json
{"Tenant":"tenant","App":"shop","Node":"node-a","DrainSeconds":30}
```

drain은 신규 연결/요청과 대상 backend의 신규 선택을 막는다. 진행 요청은 deadline까지 유지하고 기한이 되면 실제 flow를 취소한다. 기본30초, 최대3600초이며 undrain은 DrainSeconds를0 또는 생략한다. 앱 전체와 node별 선언이 겹치면 마지막 관리 의도가 우선한다. 마지막 mapping을 drain해도 앱이나 native를 삭제하지 않으며 `LastMapping`, `DrainRevision`, `DrainStartedAt`, `DrainDeadline`으로 구분한다. undrain은 같은 native를 다시 사용한다. Runtime의 `ControlRevision`은 실제 설치한 관리 overlay revision이다.

History 행은 `{At,Actor,Action,Request,Tenant,App,Node,Route,Gateway,Detail,Previous}`다. 시각은 원 사용자 서명의 Unix초이며 변경 전후의 공개 설정만 제공한다. Session·승인/노드 서명 원문·비밀값은 반환하지 않는다. gateway·balance·drain/undrain·host-policy·block/unblock/extend의 수락 이력을 최신순8개, 페이지 본문 약80KiB로 제한한다. checkpoint의 이력 한도는4096건이며 포화 시 새 변경을 거부한다. query의 tenant/app/node와 현재 권한으로 걸러내고 `Next`를 `After`로 이어 읽는다. cursor는 같은 사용자/권한 기준과 필터에서만 유효하다. 이력 수락은 원 요청 성공이며 실제 노드 적용 성공을 의미하지 않는다.
