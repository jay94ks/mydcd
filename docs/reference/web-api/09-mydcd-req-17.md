## 외부 이미지 저장소 로그인 (mydcd 실제 계약, REQ-17)

캔버스 RegistryExternal 탭(목록, 추가, 자격 교체, 읽을 서버 연결, 로그인 시험, 쓰는 곳)에 쓴다. 계약은 `docs/reference/external-registries.md`다. 저장소 정의(source)에는 보관함 참조만 있고 자격 원문은 어디에도 없다. 정의 검사, 보관함 읽기, 권한, 기록 CAS는 mydcd가 맡는다. 읽기는 작업 공간 Read 권한, 변경과 로그인 시험은 저장소 관리 권한이 필요하다(서버 연결은 그 서버의 Deploy 권한도). 시각은 Unix 초다. 변경은 모두 `{op}`를 돌려주고, expected를 안 보내면 행의 `revision`(새 ID는 0)을 쓴다.

- `GET /t/{t}/external-registries` → `{items, revision, asOf}`. 데몬이 `external-registries`를 끝까지 읽고(중간에 root revision이 바뀌면 처음부터 다시) `external-registry-pulls`를 붙인다. `revision`은 그 root revision이다. 행:
  - `id`, `authority`(host[:port]), `repository`(정확한 경로, `prefix/**`, `**`), `enabled`, `auth`(`none`/`password`/`token`), `credential?{realm, id, usernameKey, passwordKey}`, `ca?{realm, id, key}`, `revision`, `deleted`.
  - `reader?{node, owner(hex 공개키), generation, draining}`: 이 정의로 실제로 읽는 서버. 없으면 로그인 시험을 못 한다. `draining`이면 멈추는 중이다(잠시 뒤 사라진다).
  - `pulls:[{node, stage, code, completedAt, reportedAt, stale}]`: 서버마다 이 저장소에서 마지막으로 실제 받은 결과. `code`는 mydcd 코드를 소문자·`-`로 바꾼 것(`ok`, `unauthorized`, `not-found` …).
  - 지운 정의도 읽던 서버가 멈출 때까지 `deleted:true`로 남는다.
- `GET /t/{t}/external-registries/{id}/users?after=` → `{items:[{app?, deployment?, node?, service?, instance?, image, kind, match, unknown?}], next, asOf}` (`image-usages`, ExternalSource=id): 지금 이 정의로 로그인해 받는 이미지를 쓰는 앱 작업과 단독 컨테이너. `kind`는 mydcd 값(`app-execution` 등)이다.
- `PUT /t/{t}/external-registries/{id}` `{opId, authority, repository?(기본 **), enabled?(기본 true), auth, credential?, ca?, expected?}` → `put-external-registry {Spec}`. 정의 전체를 매번 보낸다. 자격 교체도 다른 보관함 참조로 다시 put하는 것이다. `password`/`token`에는 credential이 있어야 하고 `none`에는 없어야 하며, 보관함 참조는 이 작업 공간 것이어야 한다(아니면 422). 한 ID의 `authority`·`repository`는 바꿀 수 없다(409 `scope-fixed`, 새 ID로 추가한다). put하면 읽던 서버가 멈추므로 다시 연결해야 한다.
- `DELETE /t/{t}/external-registries/{id}` `{opId, expected?}` → `delete-external-registry {Tenant, ID}`. 없는 ID는 404다. 실행 중인 컨테이너는 그대로 돈다.
- `POST /t/{t}/external-registries/{id}/bind` `{opId, node}` → `external-registry-bind-plan`으로 계획을 받아 `bind-external-registry`(payload는 계획의 Selection, expected는 계획의 Expected)를 보낸다. 켜져 있고 읽는 서버가 없는 정의만 연결된다(아니면 409 `not-bindable`). CLI `registry external bind`와 같이:
  - 자격이 승인이 필요한 묶음의 Secret이면, 데몬이 원본에 한 번 서명해 웹 bbolt에 **보내지 않고** 둔다. 그 원본을 Origin으로 계획이 쓰는 realm마다 `vault-approval-plan`(ID `registry-bind/<request ID>`)을 묻는다. 승인이 남아 있으면 op는 202, `state:"running"`, `errorCode:"approval-required"`, `approvals`가 붙고 `GET /t/{t}/vault/approvals`에 `kind:"registry-bind"`, `source`, `node`로 나온다. 기다리는 op에 `resume`을 보내면 409 `approval-required`.
  - `POST /t/{t}/external-registries/{id}/bind/{opId}/approve` `{realm?, group, password}` → `{op}`. 비밀번호는 승인 서버로만 가고 저장하지 않는다. 모두 승인되면 같은 원본을 보낸다. 승인 뒤 mydcd가 거절하면 `failed`, `errorCode:"approval-rejected"`이고 새 opId로 다시 연결한다. 응답 코드는 빌드 승인과 같다.
  - 보관함 참조가 없거나 승인이 필요 없으면 바로 보낸다.
- `POST /t/{t}/external-registries/{id}/unbind` `{opId, expected?}` → `unbind-external-registry {Tenant, ID}`. 읽던 서버가 멈춘다. 읽는 서버가 없거나 이미 멈추는 중이면 409 `not-bound`.
- `POST /t/{t}/external-registries/{id}/test` `{image?}` → `{id, generation, owner, at, code, image?{normalized, registry, repository, pinned, digest, mediaType, manifestBytes, platforms?}, pull?{manifestDigest, platform, blobs, compressedBytes}}` (`registry-login-test`). op가 아니라 결과만 온다. 연결된 서버가 대신 로그인하고, image가 있으면 그 이미지를 받을 수 있는지(manifest와 레이어 HEAD까지)도 본다. 실제로 내려받거나 실행되는지는 아니다. `code`는 `ok`, `unauthorized`, `denied`, `not-found`, `unsupported`, `unavailable`, `timeout`, `cancelled`, `invalid-credential` 등이다. 연결된 서버가 없으면 409 `not-bound`.

