## 단독 컨테이너 (UI-3E·3F, REQ-29)

**sfcd 몫**: 정의 해석·검사, 컨테이너 만들기·지우기, 수명(TTL·유예·재시작 정책), 상한, 권한(만들기·바꾸기·exec는 Deploy, 보기는 Read, 다른 사람의 임시는 관리자), 정산. **웹 몫**: 정의 원문을 그대로 넘기기, 서명 원본 저장 후 보내기, 목록 거르기(아래 `all`), 소유자 이름 붙이기, '가져온 설정' 출처 보관(아래). 웹은 단독 컨테이너 상태를 저장하지 않는다. 순서는 sfcd와 같다([standalone.md](../standalone.md)): 평평한 원문을 `StandaloneDefinition`(name·lifetime·mode·restart·ttl·grace)과 서비스 하나짜리 compose 문서로 나눠 `app-plan-stream`(Standalone)으로 계획하고, 계획한 artifact를 내부 scope 아래 올린 뒤(`begin-app-upload`·`put-app-part`) `standalone-up` `AppBegin{Standalone, Target}`으로 받게 한다. 모든 바꾸기는 바로 전에 읽은 행의 관리 `Target`을 서명하므로, 그 사이 다른 변경이 있으면 sfcd가 `ConditionFailed`로 거절한다. sfcd 작업 ID(Operation)는 `op-<opId>`다.

정의 원문(YAML, 평평한 모양): `name`, `lifetime: temp|fixed`, `restart`(고정: no/on-failure/always), `ttl`·`grace`(임시), `mode: shell|entrypoint`, 그 아래 app.yaml 서비스 하나의 칸 그대로(`image`, `command`, `environment`, `networks`, `ports`, `volumes`, `secrets`, `healthcheck`, `logging`, `deploy.resources` …)와 `x-sfc: {node, ingress: {routes: [...]}}`. 작업 공간은 URL에서 온다.

| 끝점 | 뜻 |
|---|---|
| `GET /t/{t}/standalone?all=1&after=` | 목록 `{items:[S], next, revision}`. `all` 없이는 고정 전부와 **내** 임시만. `all=1`은 sfcd가 보여 주는 전부(다른 사람의 임시는 관리자만 받는다) |
| `GET /t/{t}/standalone/{name}` | `{item: S}` |
| `POST /t/{t}/standalone/plan` | `{yaml}` → `{name, scope, digest, revision, create, recreate, services, changes:[{field,before,after}], impact:[{kind,target,detail,code?,blocking}], limits?:{mine,mineMax,tenant,tenantMax,node,nodeMax}}`. 바꾸지 않는다. `scope`는 sfcd 내부 이름, `digest`는 계획한 artifact의 SHA-256, `revision`·`create`는 지금 행에서 온다. 한도에 걸리면 409 `limit-user-temp`·`limit-tenant`·`limit-node`, 같은 서버의 고정 호스트 포트가 겹치면 409 `host-port-conflict`(그 밖의 입력 오류는 422와 sfcd `inputCode`) |
| `POST /t/{t}/standalone/up` | `{opId, yaml, expected?, importedFrom?}` → `{op}`(action `standalone-up`, target = 이름, deploy처럼 `step`/`steps`/`approvals`가 있는 작업). 한 opId 아래 올리기·조각·`standalone-up`을 차례로 보내고, 같은 opId를 다시 보내면 이어 간다. 보호된 Secret Group이 있으면 `running`·`approval-required`로 멈추고 `POST /t/{t}/apps/deploy/{opId}/approve`로 승인하면 이어 간다(승인 목록의 kind는 `standalone`). 바꿀 때 `expected` = S.revision(서명되는 값이라 낡았으면 sfcd가 거절), 새 이름은 빼거나 0. 계획이 틀린 원문·한도는 서명 전에 거절된다(plan과 같은 오류). 계획 뒤 한도가 찬 것은 op `failed`. `importedFrom` = `{app, deployment?, service, items:[imageCmd·netEnv·volumes·secrets·ingress 중]}`(앱 서비스 설정을 복사해 채웠을 때) |
| `POST /t/{t}/standalone/{name}/pin` | `{opId, expected?, newName?, restart?}` → `standalone-pin` `StandaloneChange{Tenant, Name, NewName, Restart, Operation, Target}`. `restart`는 no/on-failure/always(빈 값 = on-failure) |
| `POST /t/{t}/standalone/{name}/remove` | `{opId, expected?}` → `standalone-remove` `StandaloneChange{Tenant, Name, Operation, Target}` |
| `POST /t/{t}/standalone/{name}/extend` | `{opId, expected?, ttlSeconds}` → `standalone-extend` `StandaloneExtendChange`(행의 Scope·CreatedAt·ExpiresAt·Target). 새 만료는 sfcd가 서명 시각 + ttlSeconds로 정하고, 지금 만료보다 크고 만든 뒤 24시간 이하여야 한다(아니면 op `failed`) |
| `POST /t/{t}/standalone/{name}/stop`·`start`·`restart` | `{opId, expected?}` → `task-restart-plan`을 읽고 `TaskRestartChange{Tenant, Standalone, Operation, Selection, Target, ManagementTarget}`, Expected 기본 = plan의 StandaloneRevision. 지금 적용되지 않는 동작(실행 중인데 start)은 plan이 422 |
| `POST /t/{t}/standalone/{name}/observe` | 앱의 `observe`와 같은 본문(`service`·`instance` 없음) |
| `GET /t/{t}/standalone/{name}/stream?kind=…` | 앱의 `stream`과 같다(`service` 없음) |
| `GET /t/{t}/standalone/{name}/exec?opId=…&cmd=…` | 앱의 `exec`와 같다. 작업 목록의 target은 `standalone/<이름>` |

S = `{name, tenant, lifetime, mode, image, node, state(running/exited/restarting/created/missing/pending/removed), exitCode?, restarts, restartPolicy?, expiresAt?, graceSeconds?, disconnectedAt?, connections, owner, ownerName?, revision, generation, yaml, createdAt, endedAt?, observedAt, importedFrom?}`. 시각은 sfcd의 Unix 초다. 끝난 임시는 1시간 동안 `removed`와 `endedAt`으로 남는다. `ownerName`은 작업 공간 구성원을 읽을 수 있을 때만 붙는다(아니면 자기 자신만).

`importedFrom` = `{app, deployment?, service, items, by, at}`(at은 Unix 초): 웹 bbolt에만 있는 출처 기록이다. 앱과 연결이 없는 복사라 sfcd에 넣지 않는다. 그 up이 `applied`가 된 뒤에만 보이고, 실패한 up은 보이는 값을 바꾸지 않는다. `importedFrom` 없이 적용된 up은 지운다. `standalone-remove`가 적용되면 잊고, 새 이름(`NewName`)을 준 `standalone-pin`이 적용되면 새 이름으로 옮긴다. 컨테이너 이름은 서명한 원본의 payload(`Tenant`, `Name`, `NewName`)에서 읽고, 요청의 `target`(화면 표시용)은 쓰지 않는다. CLI로 만들었거나 웹 밖에서 다시 만든 컨테이너(createdAt이 그 up의 확정 시각보다 늦음)에는 붙지 않는다.

상한 초과: op가 `failed`이고 `errorCode`가 `limit-user-temp`(내 임시 개수) 또는 `limit-tenant`(작업 공간 전체)다. 다른 거절은 결과 코드 그대로(errorCode 없음).

아직 없는 것: sfcd 쪽 전부. 웹 쪽은 없음.

