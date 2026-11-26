# 사용자·tenant 구성원 조회

두 method는 [Unix 소켓 API](unix-sockets.md)의 User purpose·기존 Session/요청 서명을 사용한다. 네트워크 MYDCP에서도 같은 인증·현재 catalog·quorum 읽기를 적용한다. 웹 앱에는 별도 관리 권한이 없다.

## 사용자 목록

```json
{"Schema":1,"Method":"users","Nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}
```

위 객체는 인증 envelope의 Body 내용 예시다. 실제 client는 매 요청 새 Nonce와 현재 연결 challenge의 요청 서명을 만든다. `After`만 선택 가능하며 Tenant·Node·TargetUser는 허용하지 않는다. 현재 활성 system-admin과 Session의 ManageCluster scope가 모두 필요하다.

응답의 `Users`는 ID 오름차순이며 각 행은 다음 형식이다.

| 필드 | 타입·의미 |
|---|---|
| ID, Username | 계정의 stable ID·정확한 로그인 이름 |
| Revision | 계정 revision |
| Enabled, SystemAdmin | bool |
| Credentials | ID 순 `{ID,Method,PublicKey,Enabled,Label?}` 배열. Method=password/private-key/token, PublicKey는 기존 User record와 같은 32개 숫자 배열 |

비활성 계정·credential도 관리 목적상 보인다. `VerifierRef` 필드·비밀번호·토큰·개인키는 반환하지 않는다. 기존 `user-credentials` 한 계정 상세와 공개 필드 이름·타입은 같으며 목록에는 backend 참조가 없다. 목록은 현재 catalog의 projection일 뿐 인증/로그인을 대신하지 않는다.

`UsersRevision`은 catalog의 논리 revision, `RootRevision`은 이 응답을 만든 원 FSM catalog 객체 revision이다. `UsersNext`가 비어 있으면 마지막 페이지다. 명령은 `mydc user list`이며 모든 페이지를 합쳐 보여 준다.

## tenant 구성원

```json
{"Schema":1,"Method":"tenant-members","Tenant":"shop","Nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}
```

Tenant 필수, After 선택, Node·TargetUser 금지다. 해당 tenant의 현재 ManageMembers와 동일한 Session scope가 필요하다. system-admin도 scope 교집합을 지키며 viewer나 다른 tenant의 manager는 거부된다.

| 응답 필드 | 타입·의미 |
|---|---|
| Tenant | 선택 tenant ID |
| TenantRevision | tenant 설정 자체의 revision(set-nodes/set-trust 등의 CAS 대상) |
| TenantMembersRevision | 현재 catalog revision. membership 변경도 증가하며 TenantRevision과 별개 |
| RootRevision | 동일한 원 FSM catalog 객체 revision |
| TenantMembers | User ID 순 `{User,Username,Revision,Role,Enabled,AccountEnabled,Implicit,Actions}` |
| TenantAllowedNodes | tenant 전체의 허용 node ID를 ID 순으로 나눈 이번 페이지 부분 |
| TenantMembersNext | 구성원 또는 허용 node가 더 있으면 다음 cursor |

`Revision`은 명시 membership의 CAS revision이다. 명시 membership이 없는 활성 system-admin은 `Implicit:true,Revision:0,Role:manager`로 표시한다. 비활성 명시 membership도 보이지만 Actions는 비어 있다. 계정이 비활성화되어도 Actions는 비어 있다. Actions는 계정·tenant·membership의 현재 유효 권한을 나타내며 그 사용자가 발급받은 특정 Session/token의 추가 제한은 이 표에 합성하지 않는다. 실제 요청에서는 해당 Session 제한도 검사한다. 다른 tenant의 구성원·credential 목록은 반환하지 않는다.

명령은 `mydc tenant members shop`이며 모든 페이지를 합쳐 보여 준다. 직접 읽을 때는 응답에 허용 node가 이번 페이지에 없다고 전체 허용 목록이 비어 있다고 해석하지 않으며 마지막 페이지까지 합친다.

## 페이지·충돌

- users는 최대32행·행 JSON 합96KiB, tenant-members는 구성원32행과 허용 node32개를 각각 반환한다. 큰 credential/허용 node 목록을 단일 무제한 응답으로 만들지 않는다.
- `*Next`의 URL-safe opaque cursor를 수정 없이 다음 Request.After에 넣는다. cursor는 catalog revision·method·tenant·각 목록 위치에 고정되며 최대512바이트다.
- 매 페이지 현재 인증·역할·signed scope를 다시 검사한다. 회수된 권한은 기존 cursor로 우회할 수 없다.
- catalog가 바뀌면 `Code:conflict`이고 행은 없다. 모아 둔 이전 페이지를 버리고 After 없이 다시 시작한다. 불명/다른 method·tenant cursor는 denied다.
- 내용이 비어 있는 배열은 공통 Reply의 omitempty에 따라 생략될 수 있다. 다음 cursor와 revision을 기준으로 종료를 판정한다.

관리 변경은 [명령 대상표의 typed payload](../architecture/command-targets/09-tenant-typed-payload.md)를 따른다. 조회는 새 계정·membership·tenant를 만들지 않는다.


## Credential의 동작 제한

`Credential.Operations`는 선택 typed 관리 action 이름 목록이다. 생략하면 기존 역할·Session scope를 따르고, 지정하면 그 두 권한에 더해 목록과 교집합을 검사한다. 빈 목록·중복·와일드카드는 허용하지 않는다. 관리자 `put-user`와 `manage user add-key --operations restart-task,pause-app-cd`가 이 metadata를 등록하며, 실제 action 이름을 사용한다. read query·자신의 정확한 logout은 관리 action을 새로 승인하지 않는다. 목록에 계정/키 관리 action을 주면 그 action 자체가 새 credential과 계정 정책을 바꿀 수 있으므로 자동 대응 키에는 필요한 조치 이름만 부여한다.

password/token Session에 별도 사용자 키 승인이 붙으면 로그인 credential과 승인 credential의 Operations를 모두 검사한다. 한 계정의 더 제한된 승인 키로 넓은 credential의 권한을 복원할 수 없다. 계정 revision 변경·credential 비활성화의 기존 Session 회수는 유지한다. `AutomationOnly:true`는 enabled password/token 수단을 금지하며 private-key 인증만 허용한다. 비활성 과거 수단을 지워 이력을 만들지는 않는다. node CLI 제한을 유지하는 마지막 독립 system-admin 키는 계정 정책을 복구할 `put-user` 동작을 계속 가질 수 있어야 한다.

계정 범위: `User.Operations`는 계정 전체의 action 상한이다(nil = 없음). 검사는 credential Operations와 교집합이며 역할·Session scope를 대신하지 않는다. `set-account-scope {User, Operations, KeyOnly}`(시스템 관리자, Expected = 계정 revision)가 이 상한과 `AutomationOnly`(키 전용)만 바꾸고 나머지 기록은 그대로 둔다. 계정 revision이 바뀌므로 기존 Session은 끝난다. 시스템 관리자 계정에는 상한을 둘 수 없다(설치에 쓸 수 있는 관리자를 남기기 위해). `put-user`는 전체 기록을 바꾸므로 그 payload의 Operations·AutomationOnly가 그대로 적용된다.

Operations는 공개 목록에 포함되고 보호 verifier 참조는 포함하지 않는다. 키당 최대64개 이름이며 User 공개 JSON 전체가96KiB를 넘는 정책은 거부한다. 이는128KiB frame 안에서 목록과 본인 credential 응답을 읽을 수 있게 하는 상한이다.

직접 부작용을 수행하는 경로도 같은 ceiling을 검사한다. interactive exec는 `container-exec`, OCI push는 `registry-push`, 보호 Vault write 실행은 `vault-dispatch-write`, Secret Group 승인 발급은 `vault-commit-approval`, 새 lifecycle source/module 게시·사용 permit은 `lifecycle-source-upload` 이름을 사용한다. 단순 조회와 이미 수락된 원 실행 상태 조회/정산을 새 실행 승인으로 바꾸지 않는다.
