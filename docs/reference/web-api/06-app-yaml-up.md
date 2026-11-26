## 배포 (app.yaml 업로드 → up)

`POST /t/{t}/apps/deploy` `{opId, yaml, digest?, deployment?, node?, prune?}` → `{op}`

- `digest`는 yaml의 SHA-256 hex다. 미리보기 뒤 yaml이 바뀌었으면 409 `digest-mismatch`.
- 데몬이 계획으로 앱 이름을 확인한 뒤 `begin-app-upload` → `put-app-part`(조각마다) → `begin-app`을 차례로 보낸다. 단계마다 별도 원 operation(id `<opId>.<n>`, `parent`=opId)으로 **저장한 뒤 보낸다**. 업로드 ID는 `web-<opId>`.
- 묶음 op: `action:"deploy"`, `target`=앱, `step`(다음 단계)/`steps`(전체). state는 모든 단계 적용 시 `applied`, 단계가 실패/거부되면 그 상태, 단계 결과가 불명이면 `unknown`(`errorCode:"step-unknown"`).
- **이어 하기**: 같은 opId·같은 내용으로 다시 보내면 다음 단계부터 이어 간다(새로고침 뒤 이어 올리기). 불명 단계는 `POST /ops/<opId>.<n>/result`로 먼저 정산한다. 묶음 op 자체에는 result/resume이 없다(409 `job`). 업로드가 사라졌으면 409 `upload-missing`.
- 올리는 것은 yaml이 아니라 mydcd가 계획에서 돌려준 산출물(blueprint)이다. CLI와 같다. 산출물이 digest와 맞지 않으면 502 `plan-invalid`.

### 비밀번호 묶음 승인 (UI-72)

앱이 비밀번호가 걸린 묶음(protected Group)을 쓰면, `begin-app`을 보내기 전에 요청한 사람이 묶음마다 비밀번호로 승인한다. CLI `app deploy`과 같은 흐름이다.

- 데몬은 `begin-app` 원본을 한 번 서명해 묶음 op에 둔다. 산출물이 쓰는 저장소(realm)마다 그 원본으로 `vault-approval-plan`을 묻는다. 승인이 없는 묶음이 있으면 거기서 멈춘다. op는 `state:"running"`, `errorCode:"approval-required"`이고 `approvals:[{realm, group, services, state(required/approved/unknown)}]`가 붙는다. 응답은 202다.
- `POST /t/{t}/apps/deploy/{opId}/approve` `{realm?(기본 작업 공간), group, password}`: 비밀번호를 SecretInput(mode approve)으로 그 묶음의 승인 서버에 보낸다. **비밀번호는 어디에도 남기지 않는다.**
  - 승인되면 남은 묶음이 없을 때 같은 원본의 `begin-app`을 보내고 `{op}`를 돌려준다.
  - 틀린 비밀번호나 권한 없음: 403 `approval-denied`.
  - 답을 잃음: 502 `approval-unknown`. 비밀번호를 다시 보낸다.
  - 기다리는 묶음이 아님: 409 `not-required`. 이미 승인됨: 409 `already-approved`.
- 같은 opId로 deploy를 다시 보내면 계획을 새로 읽어 상태를 맞춘다.
- 승인을 오래 기다리는 동안 미리 서명한 원본이 낡거나(앱 revision이 바뀜) 세션이 만료되면, 승인 뒤 보낸 `begin-app`이 거절된다. 그러면 묶음 op가 그 단계의 상태(`failed`/`rejected`, `errorCode`는 결과 코드)로 끝난다. 같은 원본은 다시 쓸 수 없으니 새 opId로 다시 배포한다.
- `GET /t/{t}/vault/approvals` → `{items:[{opId, kind(deploy/build/registry-bind), app?, context?, build?, source?, node?, realm, group, services, state, updatedAt}]}`: 이 작업 공간에서 **내** 배포·빌드·외부 저장소 서버 연결이 기다리는 묶음 승인. 웹이 가진 기록에서 만든다. 빌드 승인 비밀번호는 `POST /t/{t}/build-approvals/{opId}/approve`로, 서버 연결 승인 비밀번호는 `POST /t/{t}/external-registries/{source}/bind/{opId}/approve`로 보낸다.
- **이미 승인된 것**: `GET /t/{t}/vault/approvals/granted?app=&after=` → `{items:[{id, realm, tenant, group, user, app?, standalone?, deployment?, purpose?, services, nodes, approvedAt, expiresAt?, issuer, revoking, consumers}], next, total, collection}`. mydcd `PublicRead` `vault-approvals` 한 쪽(8행)이고 `next`는 해석하지 않고 다음 `after`로 넘긴다. `issuer`는 비밀번호를 확인한 서버 키(hex), `revoking`은 철회가 받아들여져 쓰는 곳을 돌려받는 중이다. 철회가 끝난 것은 목록에서 빠진다. 누가 무엇을 보는지는 mydcd가 정한다(realm ManageSecrets, 빈 realm은 시스템 관리자).
  - `POST /t/{t}/vault/approvals/granted/{id}/revoke` `{opId, expected?}` → `vault-revoke-approval {ID}`. Expected 기본은 목록의 `collection`(vault 읽기의 승인 묶음 revision, `VaultApprovalRevision`). 권한은 mydcd가 정한다: 그 승인이 속한 보관함의 비밀값 관리자(작업 공간 관리자), 클러스터 보관함이면 시스템 관리자가 철회한다(`mydc secret approvals revoke`와 같다).
- **자동 배포 후보** (`mydc cd approve`와 같음): CD를 등록한 사람만 승인한다. 데몬이 `app-cd-registration`으로 등록 원본과 후보가 쓰는 realm을 읽고, 그 원본과 Selection으로 계획·승인한다. 웹은 아무것도 저장하지 않는다.
  - `GET /t/{t}/apps/{app}/cd/approvals?candidate=<hex>` (또는 `operation=<id>`) → `{app, approvals:[{realm, group, services, state(required/approved)}]}`. candidate는 앱 행의 `cd.candidateDigest`이고, 둘 다 없으면 422다. 등록한 사람이 아니면 403이다.
  - `POST /t/{t}/apps/{app}/cd/approvals` `{candidate?|operation?, realm?, group, password}` → `{app, approvals}`. 오류 코드는 배포 승인과 같다(403 `approval-denied`, 502 `approval-unknown`, 409 `not-required`/`already-approved`/`no-approver`).
  - `POST /t/{t}/apps/{app}/cd/probe {repository, branch, path, credential?}` → `{commit, size, node?}`. 자동 배포 연결 전 '읽기 확인'(REQ-56 `cd-probe`, 그 사람 세션, 아무것도 바꾸지 않음). `branch`는 이름이고 앞의 `refs/heads/`는 데몬이 뗀다. 못 읽으면 422에 코드 `auth-failed`·`no-repository`·`no-branch`·`no-file`·`no-credential`·`timeout`·`too-large`·`source-error`, 횟수 제한은 429 `rate-limited`. 권한은 mydcd(그 앱 Deploy 권한, 아니면 403), 입력 오류 422 `invalid`, 없는 앱 404.
- 가짜 어댑터: 서비스의 `x-mydc.secrets_from: [group/ID]`가 비밀번호가 있는 묶음(비밀번호 쓰기 또는 `Fake.SetGroupPassword`)을 가리키면 승인이 필요하다. 승인 없이 온 `begin-app`은 `ResultInvalid`다.

