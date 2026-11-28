# VPS 관리 (UI-12B)

서버 › VPS 관리 화면이다. VPS 공급자(iwinv) 계정을 연결하고, VPS 서버를 만들고·끄고·켜고·지우고, 월 요금 상한을 바꾼다. 시스템 관리자만 쓴다. 판단은 모두 sfcd가 한다(VPS 서버 설계, [CLI `sfcli vps`](../../cli/vps.md)). 코드는 [vps.go](../../../internal/web/server/vps.go)에 있다.

모든 변경은 `opId`(UUID v4)를 받는 보통 작업이다([작업](04-operation.md)). `expected`는 계정과 서버가 함께 쓰는 VPS 목록 revision(아래 `revision`)이고, 빼면 지금 값을 쓴다. 금액은 원(KRW, VAT 포함), 시각은 Unix 초다.

## `GET /system/vps`

```json
{"revision":3,
 "accounts":[{"name":"main","vendor":"iwinv","overageKRWPerGB":10,"keyHint":"3F2A","sshPublic":"ssh-ed25519 AAAA… sfc-main","sshKeyID":"key-1",
   "addedBy":"u-admin","addedAt":1793008000,"updatedBy":"u-admin","updatedAt":1793008000}],
 "servers":[{"name":"vps-busan-1","account":"main","zone":"KR2","image":"ubuntu-2404","flavor":"ss1-c2m4","script":"sfc-enroll",
   "capKRW":20000,"capAction":"stop","voter":false,"port":7443,"createdBy":"u-admin","createdAt":1794995200,
   "phase":"capped","phaseAt":1795514000,
   "capStop":{"at":1795513600,"month":"2026-11","capKRW":20000,"soFarKRW":20000,"projectedKRW":31400},
   "instanceID":"i-busan","publicIP":"198.51.100.9",
   "dnsHolds":[{"domain":"example.com","at":"2026-11-26T03:10:20Z",
     "sets":[{"name":"shop","type":"A","removed":["198.51.100.9"],"after":"…"}],"kept":[{"name":"blog","type":"A"}],"blocked":[]}]}],
 "dnsAuto":true,
 "status":{"leader":"node-a",
   "servers":[{"name":"vps-seoul-1","updatedAt":1795600000,"capKRW":30000,"soFarKRW":19800,"projectedKRW":24600,
     "baseSoFarKRW":19800,"baseMonthKRW":22000,"trafficSoFarKRW":0,"trafficMonthKRW":0,
     "usedGB":412,"projectedGB":460,"recentMB":412,"judgeable":true}],
   "accounts":[{"name":"main","billKRW":39900,"oursKRW":39800,"updatedAt":1795600000}]}}
```

| 칸 | 뜻 |
|---|---|
| `accounts[]` | 공급자 계정. 키는 돌려주지 않는다. `keyHint`는 Access Key 끝 네 글자. `sshPublic`은 공급자에 등록할 계정 SSH 공개키, `sshKeyID`는 등록한 키의 공급자 ID(없으면 빠짐) |
| `accounts[].overageTiers` | 공급자가 공개한 초과 트래픽 요금 `[{upToGB, krwPerGB}]`(부가세 별도, 제공량을 넘은 GB를 구간별로 센다, 마지막 구간 `upToGB` 0은 끝 없음). 있으면 `overageKRWPerGB` 대신 쓴다. iwinv: 1,000 GB까지 70원, 2,000 GB까지 60원, 3,000 GB까지 50원, 4,000 GB까지 40원, 그 위 30원 |
| `servers[].phase` | `creating`(생성) · `installing`(설치) · `running`(실행 중) · `stopping`(끄는 중, `stopAfter`가 지나면 끔) · `stopped`(중지됨) · `capped`(상한으로 중지됨) · `starting`(켜는 중) · `failed`(오류, `failure`에 코드) · `deleting`(삭제 중) |
| `servers[].joining` | `installing`이면서 초대를 받아 가입하는 중("가입 중"). 단계는 생성 → 설치 → 가입 → 실행 중(투표 희망이면 그 뒤 승격) |
| `servers[].capAction` | 상한을 넘으면: `stop`(기본, drain 없이 끔) 또는 `notify`(알림만) |
| `servers[].capStop` | 마지막 상한 중지 기록. 그 달 지금까지·예상·상한. `reason:"traffic-soon"`이면 1분 조기 감시가 21분 안에 상한에 닿는다고 보고 끈 것 |
| `accounts[].guard` | 트래픽 조기 감시 설정 `{windowMin?, averageMin?, patternOff?}`(빠지면 기본: 창 5분, 평균 60분, 패턴 켬) |
| `servers[].dnsHolds` | 중지 동안 DNS에서 임시로 뺀 것(아래 "중지할 때 DNS"). 도메인마다 뺀 레코드(`sets`), 이 서버만 받아 남긴 레코드(`kept`), 재개 때 되돌리지 못한 레코드(`blocked`) |
| `dnsAuto` | 마지막 자동 점검이 VPS 목록을 읽었는지. `false`면 DNS를 저절로 바꾸지 않는다(자동화 계정이 시스템 관리자가 아니거나 자동화가 꺼짐) |
| `status` | 리더 메모리의 10분 감시. 리더에 못 닿으면 `null`이고 `statusError`에 코드(`unavailable` 등)가 온다. 목록은 그래도 온다 |
| `status.servers[].includedGB`, `includedPeriod` | 공급자 기본 제공 트래픽(GB)과 판정 기준(`MONTH` 월간 · `DAY` 일간). 인스턴스를 읽어야 알 수 있어 감시가 한 번 돈 뒤에 온다 |
| `status.servers[].includedMonthGB`, `includedMaxGB` | 초과 요금을 세는 이번 달 제공량. 일간이면 하루 제공량 × 이번 달 서비스 일수(꺼진 날 포함)이고 월 최대(`includedMaxGB`, iwinv는 하루 제공량 × 30, 20 GB/일이면 600 GB)를 넘지 않는다. 월 사용량이 이를 넘는 만큼만 초과 요금이다 |
| `status.servers[].todayMB`, `daily[]` | 오늘(한국 시각) 사용량과 이번 달 최근 7일 일별 사용량 `{day:"YYYY-MM-DD", mb}`(오래된 날부터, 1일 이전은 읽지 않는다) |
| `status.servers[].trafficCounting` | 공급자가 트래픽을 세는 방식: `tx`(나가는 것만) · `rx+tx`(합) · 빠짐(모름). 공급자마다 정해진 값이다. iwinv는 `tx` |
| `status.servers[].guard` | 1분 조기 감시의 마지막 판정(서버가 창 하나만큼 송신량을 보고한 뒤부터). `rateMbps`·`prevMbps`·`averageMbps`(최근 창·앞 창·누적 평균 속도), `forecastGB`(앞으로 21분 예측), `patternGB`·`patternDays`·`patternUsed`(패턴 예측, 기록 날 수, 썼는지: 7일 미만이거나 기록을 아직 못 받았으면 `false`), `monthGB`(공급자 합계 + 그 뒤 서버가 잰 양), `remainingGB`(상한까지 남은 GB), `unlimited`(상한 없음 또는 초과 요금 없음), `soon`(21분 안에 닿음, 이때 `over`도 참), `soonAt`(지금 예측 속도로 닿는 시각) |
| `status.servers[].judgeable` | 한 시간치 읽기가 모였는지. `false`면 예상으로 판정하지 않는다(지금까지 요금이 상한을 넘으면 바로 판정) |
| `status.servers[].over`, `capBlocked` | 상한을 넘음. `capBlocked`는 투표 서버라 끄지 못함 |
| `status.servers[].failure`, `failureAt` | 공급자 읽기 실패 코드(`PROVIDER_UNREACHABLE` 등)와 시각. 숫자는 마지막 성공 값 |
| `status.accounts[]` | 공급자 실시간 청구(`billKRW`)와 우리 계산 합(`oursKRW`) |

오퍼의 `flavors[].traffic`은 그 타입의 트래픽 제공량 `{gb, period, maxGB, estimated}`(`maxGB` 0은 월 최대 없음)이다. 공급자 카탈로그가 알려 주지 않으면 공급자의 보통 제공량(iwinv 하루 20 GB, 월 최대 600 GB)을 `estimated:true`로 채운다. 만든 뒤에는 서버가 알려 주는 값(`status.servers[].includedGB` 등)을 쓴다.

`status.servers`에는 `running` 서버와 이번 달 요금이 계속 드는 꺼진 서버(`stopping`·`stopped`·`capped`)가 있다. 꺼진 서버는 이번 달 사용량과 요금만 보이고 판정하지 않는다(`guard` 없음). 화면은 이름으로 `servers`와 맞춘다.

## `GET /system/vps/accounts/{account}/offer?zone=`

그 계정의 공급자가 지금 파는 것을 투표 서버가 바로 읽는다. 새 VPS 서버 대화상자와 '지금 연결 확인'에 쓴다. 웹이 붙은 서버가 투표 서버가 아니거나 공급자가 키를 거부하면 `unavailable`(503)이다.

```json
{"account":"main","at":1795600000,
 "zones":[{"id":"KR1","name":"서울","usable":true}],
 "images":[{"id":"ubuntu-2404","name":"Ubuntu 24.04 LTS","kind":"os_linux","os":"UBUNTU","linux":true,"zones":["KR1","KR2"]}],
 "flavors":[{"id":"ss1-c2m4","name":"ss1.c2m4","vcpu":2,"memoryMiB":4096,"diskGB":50,"full":{"krw":22000,"per":"month"}}],
 "sshKeys":[],"scripts":[{"id":"sfc-enroll","name":"sfcli enroll"}]}
```

## 공급자 계정

| 요청 | 본문 | sfcd |
|---|---|---|
| `POST /system/vps/accounts` | `{opId, name, vendor:"iwinv", accessKey, secretKey, trafficPrice}` | 투표 서버가 키를 봉인한 뒤 `put-vps-account` |
| `POST /system/vps/accounts/{account}/rotate-key` | `{opId, accessKey, secretKey, expected?}` | 새 키로 봉인한 뒤 `put-vps-account`. 계정 SSH 키도 새로 생겨 `sshKeyID`가 지워진다 |
| `PATCH /system/vps/accounts/{account}` | `{opId, trafficPrice?, sshKeyId?, guardWindowMin?, guardAverageMin?, guardPattern?, expected?}` | `put-vps-account`(키 없이). 빠진 칸은 지금 값, `sshKeyId:""`는 지움. 감시 분 0은 기본값(창 1–60, 평균은 창의 2배 이상–1440) |
| `DELETE /system/vps/accounts/{account}` | `{opId, expected?}` | `remove-vps-account`. 그 계정의 VPS 서버가 남아 있으면 409 `in-use` |

- `trafficPrice`는 기본 제공량을 넘은 트래픽의 GB당 원이다(공급자 API가 알려 주지 않는다).
- 키는 웹 데몬에 남지 않는다. 작업 원본에는 봉인된 결과만 들어가고, 같은 `opId`를 다시 보낼 때 비교하는 digest에도 키를 넣지 않는다.
- 봉인은 웹이 붙은 서버가 투표 서버일 때만 된다. 아니면 `unavailable`이다.
- 이미 있는 이름으로 추가하면 409 `exists`, 바뀌는 것이 없으면 409 `unchanged`다.
- 새 키를 저장하기 전에 확인하는 길은 없다. 저장한 뒤 `offer`로 확인한다.

## VPS 서버

| 요청 | 본문 | sfcd |
|---|---|---|
| `POST /system/vps/servers` | `{opId, name, account, zone, image, flavor, script?, sshKeys?, capKRW, capAction?, voter?, port?}` | `create-vps-node`. 받아들여지면 바로 요금이 나오기 시작한다 |
| `POST /system/vps/servers/{name}/stop` | `{opId, dnsWaitSeconds?, expected?}` | `stop-vps-node` |
| `POST /system/vps/servers/{name}/start` | `{opId, expected?}` | `start-vps-node` |
| `POST /system/vps/servers/{name}/cap` | `{opId, capKRW?, capAction?, expected?}` | `set-vps-node-cap` |
| `DELETE /system/vps/servers/{name}` | `{opId, expected?}` | `delete-vps-node` |

- 만들기: `capAction`은 `stop`(기본) 또는 `notify`, `port`는 기본 7443. `script`가 없으면 리더가 계정 SSH 키로 설치하고, 그런 서버는 투표 서버가 될 수 없다. 같은 이름이 있으면 409 `exists`.
- 끄기: 먼저 `POST /nodes/{name}/cordon`과 `POST /nodes/{name}/drain`을 하고, drain이 모두 옮긴 뒤에 보낸다. `dnsWaitSeconds`(0–3600, 기본 300)는 DNS에서 그 서버 주소를 뺀 뒤 끄기까지 기다리는 시간이다. 투표 서버는 남은 투표 서버가 한 대 더 잃어도 버틸 때만 끈다. `running`이 아니면 409 `phase`.
- 켜기: `stopped`나 `capped`만. 상한으로 끈 서버는 새 달이거나 상한이 `capStop.projectedKRW`보다 높아야 sfcd가 받는다. 켠 뒤 `POST /nodes/{name}/uncordon`으로 작업을 다시 받게 한다.
- 상한: 빠진 칸은 지금 값. 바뀌는 것이 없으면 409 `unchanged`.
- 삭제: 클러스터에 들어온 서버는 먼저 `POST /nodes/{name}/drain`과 `/remove`로 뺀다. 이미 삭제 중이면 409 `phase`. 되돌릴 수 없다.
- `expected`를 주면 그 revision으로 보내고, 위의 단계 검사는 sfcd에 맡긴다.
- sfcd가 거절하면 작업 결과(`forbidden`·`condition-failed` 등)로 보인다.

## 중지할 때 DNS (웹이 하는 임시 변경)

외부 도메인과 DNS 공급자는 웹만의 기능이라 이 부분은 sfc-web이 한다(설계 5a). 코드는 [vps_dns.go](../../../internal/web/server/vps_dns.go)다.

- 자동화 계정의 점검(30초마다, 이 일은 1분에 한 번)이 VPS 목록을 읽는다. 자동화 계정이 VPS 목록을 읽을 수 있어야 한다(시스템 관리자).
- 서버가 `stopping`·`stopped`·`capped`이면, 그 서버가 '연결된 서버'인 외부 도메인마다 Sfc가 만든 A·AAAA 레코드에서 그 서버 주소를 뺀다. 주소는 연결의 직접 입력 주소, 없으면 외부망 게이트웨이 주소, 그것도 없으면 VPS 공인 IP다. 뺀 레코드와 뺀 뒤 지문을 웹 bbolt에 남기고 DNS 기록에도 한 줄 남긴다.
- 그 서버 주소만 있는 레코드는 빼지 않고 남긴다(`kept`).
- Sfc가 쓴 뒤 밖에서 바뀐 레코드, 공급자를 읽지 못한 도메인은 건드리지 않는다. 공급자를 읽지 못하면 다음 점검에서 다시 한다.
- 서버가 다시 `running`이 되면 뺀 주소가 밖에서 :443으로 닿는지 확인한 뒤 되돌린다. 닿지 않으면 1분마다 다시 보고, `running`이 된 지 10분이 지나면 확인 없이 되돌린다. 그 사이 레코드가 바뀌었으면(지문이 다름) 덮어쓰지 않고 `blocked`로 남기고 알림을 보낸다.
- 서버가 목록에서 사라지면(삭제) 임시 기록을 지우고 그 서버를 도메인의 연결된 서버에서 뺀다. 레코드는 되돌리지 않는다.
- 알림은 그 도메인에 서버를 연결한 사람에게 간다(종류 `vps-dns`).

### `GET /system/vps/servers/{name}/dns-plan`

중지 대화상자의 "연동된 도메인 · DNS 레코드" 표다. 아무것도 바꾸지 않는다.

```json
{"rows":[
  {"domain":"example.com","name":"shop","type":"A","value":"203.0.113.21","ttl":300,"outcome":"withdraw","others":2},
  {"domain":"example.com","name":"blog","type":"A","value":"203.0.113.21","ttl":300,"outcome":"keep-last","others":0},
  {"domain":"other.example","name":"","type":"","value":"203.0.113.21","ttl":0,"outcome":"manual","others":0}],
 "waitSeconds":300,"dnsAuto":true}
```

| `outcome` | 뜻 |
|---|---|
| `withdraw` | 중지 동안 임시로 뺌. `others`는 남는 주소 수 |
| `keep-last` | 이 서버 주소뿐이라 남김. 중지하면 그 이름은 접속되지 않는다 |
| `manual` | 공급자를 읽지 못함. 직접 고친다 |

`waitSeconds`는 빼는 레코드 중 가장 긴 TTL(없으면 300, 최대 3600)이다. 끄기 요청의 `dnsWaitSeconds`로 보낸다.

### `DELETE /system/vps/servers/{name}/dns-holds/{domain}`

되돌리지 못한 레코드 표시를 지운다('이대로 둠'). 영역은 바꾸지 않는다. 아직 중지 중이라 빼 둔 레코드가 있으면 409 `held`.

## 보유 VPS (Hostinger)

내가 공급자에서 사서 갱신하는 VPS를 붙이는 화면이다(설계). 클러스터는 사거나 지우지 않는다. 관리형 화면(`GET /system/vps`)에는 보유형 계정이 나오지 않고, 이 화면에는 관리형 계정·서버가 나오지 않는다. 모두 시스템 관리자만 쓴다.

### `GET /system/owned-vps`

`{revision, accountRevision, accounts, servers}`. `accounts`는 보유형 공급자 계정만이고 모양은 `GET /system/vps`의 계정 줄과 같다(`keyHint`는 토큰 끝 4자). `servers`는 `{name, account, instanceID, install(ssh/manual/existing), voter?, port?, protect(exclude/low-weight), phase(installing/running/failed), failure?, publicIP?, build?, invitation?, limit?{at, month, mode, usedMB, monthMB, reachAt}, restored?{at, month, by?}, request, attachedBy, attachedAt, updatedBy, updatedAt}`. 서버 변경의 Expected는 `revision`, 계정 변경은 `accountRevision`이다.

- `installSteps`: 서버 이름 → 설치 단계 1–4. 1 VPS 읽는 중, 2 확인됨(공인 IP·빌드 기록), 3 초대 발급(서버가 가입할 수 있음), 4 가입함(`running`). 0은 `failed`이고 이유는 `failure`다. `failure`: `EXPIRED`(구독이 끝나 VM이 사라짐), `INSTANCE_NOT_FOUND`, `NOT_RUNNING`, `NO_PUBLIC_IP`, `IP_MISMATCH`, `TIMEOUT`(30분 안에 가입하지 않음).
- `status`: 리더가 공급자에서 읽은 값. `{leader, servers: [{name, updatedAt, usedMB, monthMB, reachAt, plan?, zone?, image?, instanceStatus?, subscriptionStatus?, expiresAt?, autoRenew?, currency?, renewalCost?, failure?, failureAt?}]}`. 대역폭(`usedMB`·`monthMB`·`reachAt`)은 보류와 상관없이 늘 있다. `instanceStatus`는 `pending`·`active`·`working`·`off`·`error`이고, 기록이 `running`인데 `off`면 공급자 쪽에서 멈춘 것이다. `renewalCost`는 `currency`의 최소 단위(USD면 센트)다. 리더를 읽지 못하면 `status`는 `null`이고 `statusError`에 코드가 있다.
- 직접 설치 명령은 `installSteps`가 2나 3일 때 언제든 다시 보여 줄 수 있다. 초대는 기록에 남아 있어 따로 다시 받을 필요가 없다. 명령: `curl -fsS "https://CLUSTER_HOST/.well-known/sfc/node/install.sh?name=NAME" | sh`([설치](../vps-enroll.md)).

### 계정

| 요청 | 동작 |
|---|---|
| `POST /system/owned-vps/accounts` `{opId, name, vendor, token}` | 투표 서버가 API 토큰을 봉인한 뒤 `put-vps-account`. 웹은 토큰을 보관하지 않는다. `vendor`는 `hostinger`(관리형 공급자는 422) |
| `POST /system/owned-vps/accounts/{account}/rotate-key` `{opId, token, expected?}` | 토큰 교체(새 SSH 키도 받는다) |
| `GET /system/owned-vps/accounts/{account}/instances` | 붙이기 목록: 리더가 지금 공급자에서 읽은 그 계정의 VM `{instances: [{id, plan, zone, publicIP, image, status, expiresAt?, attached?}]}`. `attached`는 그 VM을 쓰는 보유 VPS 이름(비어 있으면 붙일 수 있음). 공급자에서 바꾸는 것은 없다. 없는 계정은 404, 리더나 공급자를 읽지 못하면 503 |
| `DELETE /system/owned-vps/accounts/{account}` `{opId, expected?}` | 붙은 서버가 있으면 409 `in-use` |

### 서버

| 요청 | 동작 |
|---|---|
| `POST /system/owned-vps/servers` `{opId, name, account, instanceId, install, port, voter?, protect?, expected?}` | `attach-owned-vps`. `port`는 새 서버의 SFCP 포트(`existing`이면 빼기). `install`: `ssh`(리더가 SSH로 설치, 투표 안 함), `manual`(직접 설치 명령), `existing`(이미 가입한 서버 `name`에 기록만 묶음). `voter`는 `manual`에서만. `protect` 기본 `exclude` |
| `PATCH /system/owned-vps/servers/{name}` `{opId, protect?, restore?, expected?}` | `set-owned-vps`: 월 대역폭이 다 되기 전 동작(`exclude`는 DNS·라우팅에서 잠시 뺌, `low-weight`는 다른 backend의 1/16 몫만 보냄). `restore:true`는 지금의 트래픽 보류를 바로 끝낸다(그달에는 다시 보류하지 않음, 보류 중이 아니면 409 `not-limited`) |
| `DELETE /system/owned-vps/servers/{name}` `{opId, expected?}` | `detach-owned-vps`: 기록만 지운다. VPS와 구독은 공급자에 그대로 남는다. 가입한 서버는 `node drain`·`node remove`로 따로 뺀다 |

- 트래픽 보류는 커밋된 기록을 각 서버의 ingress가 읽어 다음 요청부터 반영한다. `exclude`여도 route에 다른 backend가 없으면 그 서버 backend를 남기고 작은 몫만 보낸다.
- 구독이 끝나기 14일·3일·1일 전에 서버를 붙인 사람에게 알림(종류 `vps-subscription`)을 보낸다. 끝나는 날짜와 "갱신은 Hostinger 패널에서"를 적고, 투표 서버면 심각도가 `error`다. 갱신으로 끝나는 날짜가 바뀌면 알림을 처음부터 다시 센다.
