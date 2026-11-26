# 관리 자원·사용처 조회

조회는 현재 사용자 Session·계정 revision·역할·서명된 scope를 검사한다. Unix 관리 소켓과 네트워크 MYDCP의 User 요청은 같은 코어를 사용한다. 조회로 자원을 만들거나 원 operation·정리 증거를 갱신하지 않는다.

## 요청과 페이지

일반 조회 요청은 다음 구조다. `Schema=1`, 매 교환의 새 `Nonce`와 기존 User envelope의 Session/Signature가 필요하다.

```json
{"Schema":1,"Method":"network-users","Tenant":"payments","PublicRead":{"Name":"services","App":"","Node":""},"After":"","Nonce":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}
```

예시는 Nonce의 32바이트 형태를 보이며 실제 client는 교환마다 무작위 값을 만든다. 각 method가 허용한 selector만 전달한다. 공통 Request의 별도 App/Node, Secret·다른 method의 payload를 함께 전달하면 거부한다.

응답의 `PublicRead`는 `{Schema,Method,Tenant,Index,RootRevision,CatalogRevision,TenantRevision,Rows,Next,Total}`이다. Rows는 최대 8개, 행 JSON 합은 최대 96KiB다. Total은 권한으로 먼저 거른 전체 행 수다. Next가 있으면 같은 method·tenant·selector로 After에 넣는다. 원 snapshot/현재 권한이 바뀌면 cursor는 conflict가 되며 처음부터 다시 조회한다. cursor는 권한이나 변경 승인이 아니다.

각 행은 Key와 아래 지정한 단 하나의 payload만 가진다. RootRevision은 method의 상태 root CAS다. 사용자 요청의 공통 Reply.RootRevision과 CatalogRevision은 access catalog CAS다. volumes 계열은 Volumes root, 망 계열은 Resources root, lifecycle은 Lifecycle root, Vault는 Vault root, 나머지는 Catalog root를 사용한다.

| Method | PublicRead selector | 행 payload | 현재 권한 |
|---|---|---|---|
| network-users | Name=논리 망 이름 또는 멤버 ID | User | tenant Read |
| network-closure | Name=draining 멤버 망 ID, After 금지 | Closure | tenant ManageNetwork cleanup |
| volume-users | Name=Volume ID, 선택 App | User | tenant Read |
| volume-backup-limits | 선택 Node | BackupLimit | tenant Read; Tenant가 비면 system-admin |
| route-endpoints | 없음; Tenant=받는 tenant | RouteEndpoint | 어느 tenant에서든 현재 ManageRoutes |
| lifecycle-uses | Name=named script 이름 | Lifecycle | tenant ManageServices |
| vault-approvals | 선택 App; Tenant=realm | Approval | realm ManageSecrets; 빈 realm은 system-admin |
| vault-usages | Name=Secret/Group ID; Tenant=realm | SecretUsage | 위와 같음 |
| volume-retained-sources | Name=Volume ID, 선택 App | Retained | tenant Read |
| image-trust | 없음 | Image; 페이지에 Rules | tenant Read |
| volume-file-grants | 선택 Name=Volume ID, App | FileGrant | tenant manager는 해당 tenant, 나머지는 자신의 위임만 |

## 사용처와 정리 경계

`User`는 `{Kind,Tenant,App,Deployment,Service,Standalone,Node,Task,Consumer,Generation,Revision,Desired,Observed,Live,Writable?,ContainerPresent?,EndpointPresent?}`다. App 서비스와 명시 standalone owner를 구분한다. 수락된 Task·원 Binding과 아직 반환하지 않은 참조를 사용하므로 내리는 중인 앱을 먼저 숨겨 정리 가능으로 보이지 않는다. 실제 미관측 상태는 unknown 또는 필드 생략이다. `EndpointPresent`는 정확한 담당 노드의 Docker inspect에서 NetworkID와 EndpointID를 확인한 신선한 TaskFact만 사용한다. 컨테이너 running만으로 추정하지 않으며 과거 형식·만료된 관측에는 값을 만들지 않는다. Volume 사용처는 삭제 차단에 쓰는 원 State.Consumers를 그대로 순회하며, 앱 외 backup/move reader 등은 volume-operation으로 구분한다. Writable은 원 consumer 값이다.

`BackupLimit`는 `{Tenant,Node,Revision,Bytes,Count,StagingBytes,StagingCount,UsedBytes,UsedCount,UsedStagingBytes,UsedStagingCount,GlobalPresent,GlobalOriginal,Original?}`다. `GlobalOriginal`은 같은 서버의 전역 한도 행에 원본 볼륨 예산(`Original`)이 있는지만 알린다. 예산이 생긴 서버에서 `--size`가 있는 볼륨 생성은 tenant와 전역 예산이 모두 있어야 하므로 CLI가 보내기 전에 이를 확인한다. `Original:{Bytes,Count}`는 그 행의 선택 이관 원본 예산이다. 없는 행은 필드를 생략한다. 현재 한도를 수정할 때 공개 행의 Revision을 Expected로 쓰고 Original이 있으면 그대로 보존한다. Used 값은 실제 디스크 측정치가 아니라 동일한 backup/restore/move 예산 검사에서 사용하는 원 archive/staging 예약량이다. tenant 응답에는 해당 tenant 한도·사용량과 전역 한도의 존재 여부만 있고 전역 수치는 없다.

`RouteEndpoint`는 `{Tenant,Network,Node,Pool}`만 제공한다. Network는 `propose-route`가 받는 논리 망 이름이다. 현재 공개 발견 정책은 명시적으로 이름을 붙인 활성 MYDCP TUN 망의 멤버다. draining·변경 후보·원 legacy private Bridge는 제외한다. 받는 tenant의 Read를 요구하지 않으며 내부 멤버 ID·CIDR·주소·소유 키·generation은 반환하지 않는다. 제안 시 기존 propose-route가 원 카탈로그에서 다시 고정한다.

`Lifecycle`은 `{ID,Kind,App,Service,Standalone,Node,Revision}`다. named revision을 삭제 차단하는 동일 Catalog.Uses를 읽고 app-binding과 build-job을 구분한다. build-job의 앱 정보는 원 AppUseID를 따라 같은 Binding에서 가져온다.

`Approval`은 `{ID,Realm,Tenant,Group,User,App,Standalone,Deployment,Purpose,Services,Nodes,ApprovedAt,ExpiresAt,Issuer,Revoking,Consumers}`다. 시각은 Unix 초이며 ExpiresAt은 현재 Group approval-age와 원 승인 시각에서 계산한다. 비밀번호·서명 원문·provider 참조는 반환하지 않는다. `SecretUsage`는 `{ID,Realm,Tenant,User,App,Standalone,Deployment,Service,Node,Purpose,Generation,Secrets,Live}`이며 retire를 막는 동일 usage/dependency와 원 실제 release 수명을 사용한다. Group에는 해당 자손 Secret 참조가 포함된다.

`Retained`는 `{Scope,Move,Node,State}`이며 State는 retained/deleting/removed다. `volumes`의 각 행에도 `Retained:[{Move,Node,State}]`를 제공한다. 완료 move의 원 source deletion 증거를 투영하며 삭제 명령 수락을 removed로 바꾸지 않는다.

`Image`은 `{Kind,App,Deployment,Service,Standalone,Node,Reference,Rules}`다. Reference는 원 retained Task에 고정된 정규화 이미지이며 Rules는 페이지 Rules 배열의 일치 index다. 현재 tenant ImageSources와 동일 MatchImageTrust 규칙을 사용한다.

`FileGrant`는 `{Tenant,App,Volume,Prefix,User,Revision,AccountEnabled,VolumePresent,Operations}`다. `volume-file-grant/revoke`가 변경하는 기존 `Catalog.VolumeFileGrants`를 투영하며 별도 조회용 위임 저장소를 두지 않는다. Revision은 원 폴더 위임의 revision이다. 명시 revoke한 위임은 사라지고, 비활성 계정이나 제거된 Volume은 각 flag로 구분한다. Operations는 폴더 위임이 대상으로 하는 put/get/list/delete이며 현재 자격의 허용 범위를 대신하지 않는다. Credential.VolumeFiles는 별도의 자격 ceiling이고 목록 발급 원본이 아니다. Name/App을 생략하면 지정한 tenant 안에서만 목록을 넓힌다. 이는 grant의 tenant/Volume/prefix 권한에 wildcard를 허용하지 않는다. 이 목록은 새 파일 작업의 권한 증거가 아니며 실제 명령이 현재 Session/credential ceiling·원 위임·Volume·노드 권한을 다시 검사한다.

## 망 종료와 DNS

`Closure`는 `{State,NativeGone?,PendingEndpoints?,PendingFlows?,PendingPins?,Closure?}`다. State는 pending/unreachable/closed다. pending의 endpoint 수는 종료를 막는 동일 IPAM allocation book, pin 수는 원 owner journal 관측이다. 측정되지 않은 flow 수·native 부재는 null이며 0으로 추정하지 않는다. owner에 닿지 않으면 unreachable이다. closed일 때 `Closure`는 원 owner가 서명한 `tenancy.NetworkClosure` 그대로이고, `fence-network-change`·`leave-tun-network`에 복사할 수 있다. 반환 직전 현재 사용자 권한과 정확한 owner·멤버 generation/revision·native source를 다시 비교한다. 조회가 fence나 leave를 대신 실행하지 않는다.

`resources` 망 행에는 `DNS:{Revision,Policy,Resolvers,Ready?,State}`가 붙는다. Policy는 Enabled/Reverse/Zone/ClientZone/TTL/NegativeTTL/Transports/Upstreams와 MaxQueries/MaxCacheEntries/MaxResponseBytes/MaxConnections/RequestTimeoutMS 전체다. Revision은 configure-network-dns에 사용할 source CAS다. Resolvers는 현재 원 DNS owner가 실제 socket·동일 source/applied/observed revision을 확인한 주소:53만 반환한다. desired Gateway 주소로 Ready를 만들지 않으며 미기동·실패·접속 불가 시 주소 목록은 비고 Ready/State로 구분한다. 원 instance가 이미 종료된 뒤 비활성 정책 revision만 바뀐 경우에도 정책은 읽히며, 새 revision의 native 관측이 없으면 Ready를 생략하고 Resolvers를 비운다. 정책 비활성화만으로 실제 종료를 증명하지 않는다. 한 페이지의 owner 조회에는 2초의 공통 진단 예산을 사용하고 끝에 현재 권한·원 source를 한 번 재검사한다.

## 선택·노드·이벤트

`select-tenant`는 TenantRevision과 TenantAllowedNodes를 반환한다. `tenants` 행에도 AllowedNodes가 있으며 현재 Read·허용 node와 교차한 목록이다. 원 catalog slice를 외부에서 수정할 수 없다.

`node-summary` 행에는 CordonedBy/CordonedAt을 제공하며 `members`의 NodeLifecycle.Scheduling과 `node-summary`의 Scheduling에도 Enabled/Revision 및 활성 cordon의 CordonedBy/CordonedAt이 있다. 원 서명 명령의 사용자와 At를 사용하고 시각은 UTC RFC3339다. `members`의 Scheduling.Reason은 활성 cordon-node 원 명령의 Reason이다(drain으로 막힌 경우는 없음). NodeLifecycle[].Identity.RequestedAt은 마지막 rotate-node-identity 원 명령의 At(UTC RFC3339)이다. uncordon 뒤 이전 actor/time을 남기지 않는다. node-summary의 ObserveLimitSeconds는 실제 관측 freshness 한도(현재 120초)와 같으며 활성 노드의 관측이 없거나 오래되면 State=unreachable이다.

`tunnel-down`/`tunnel-up`은 현재 논리 TUN 망의 실제 노드 쌍마다 Tenant/Network/Node/PairID를 가진 tenant 범위 이벤트다. 한 transport가 여러 망을 운반하면 각 망에 별도 사건을 기록한다. 다른 tenant 이벤트는 기존 현재 권한 필터를 통과하지 못한다.

## 로그인 전 서버 판 조회

`server-version`은 `{Schema:1,Method:"server-version",Nonce:32바이트}`의 sessionless finite User 요청이다. envelope에 Session/Signature/Relay를 넣지 않는다. 응답 `ServerVersion:{Version:"1",Protocol:1,Commit?,BuildTime?}`은 접속한 mydcd 자신이다. TLS 키 pin 검증과 frame digest/EOF는 유지하며 leader로 전달하거나 quorum/login/wallet을 요구하지 않는다. `mydc version`은 로컬 CLI 판이고 `mydc server-version`은 원격 mydcd 판이다.

```sh
mydc --cluster production server-version
mydc --tenant payments manage network-users --name services
mydc --tenant payments manage network-closure --name MEMBER_ID
mydc --tenant payments volume users ledger/ledger-data
mydc --tenant payments volume backup limits --node node-a
mydc volume backup limits --all
mydc --tenant destination manage route-endpoints
mydc --tenant payments manage lifecycle-uses --name ready
mydc --tenant payments secret approvals --app ledger
mydc --tenant payments secret usages signing-keys
mydc --tenant payments manage image-trust
mydc --tenant payments volume files grants ledger/ledger-data
```
