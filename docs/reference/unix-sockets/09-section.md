## 메시지 인코딩 규칙

업무 메시지의 JSON은 UTF-8이며 [Request·Envelope·Reply](../../../internal/userauth/service.go)의 Go `encoding/json.Marshal` 결과를 그대로 사용한다. decoder는 알 수 없는 필드를 거부하고 재직렬화한 바이트와 원문까지 비교한다. 공백·필드 순서·생략 여부를 임의로 바꾼 JSON이나 중복 키는 허용 형식이 아니다. 아래 들여쓴 예시는 **구조 설명용**이며 서명 가능한 전송 원문은 compact canonical JSON으로 만든다.

| 표기 | wire JSON 형식 |
|---|---|
| `string`, `bool` | JSON 문자열, `true`/`false` |
| `uint8/uint64/int64/int` | 따옴표 없는 정수. uint64를 부동소수점으로 변환하여 정밀도를 잃지 않는다 |
| `key32`, `digest32`, `nonce32` | `[32]byte`: 0..255 정수 **32개 배열**. hex/base64 문자열이 아니다 |
| `bytes` | `[]byte`: 표준 base64 문자열. nil은 필드에 따라 `null` 또는 생략 |
| `T[]`, `map[string]T` | JSON 배열, 문자열 키의 객체 |
| `json.RawMessage` | JSON 값 자체. base64로 감싸지 않는다 |
| 선택 필드 | 타입에 `omitempty`가 있으면 nil/빈 문자열/0 등을 생략. 필수 필드와 구별 |

필드명은 아래 표의 대소문자를 그대로 사용한다. 기본은 `Schema`, `Method` 같은 PascalCase이며 Secret 승인 Target 등 명시 JSON tag가 있는 타입은 예외다. 고정 길이 배열은 `omitempty`여도 길이가32이므로 영 배열이 생략되지 않는다. 따라서 일반 Request에도 영 배열 `UserKey`가 직렬화된다.

### Envelope — 공통 요청 포장

| 필드 | 타입 | 규칙 |
|---|---|---|
| `Body` | json.RawMessage(서명한 바이트 그대로) | User면 canonical Request, SecretInput이면 SecretRequest, ContainerSession이면 ContainerSessionRequest, ImageContent이면 ImageContentRequest, NodeShell이면 NodeShellRequest JSON의 바이트 |
| `Session` | Session, 선택 | 로그인 후 요청의 현재 사용자 세션 |
| `Signature` | bytes, 선택 | 요청 서명. 인증 전 challenge 요청에는 없음 |
| `Relay` | 객체, 선택 | Unix client는 **생략**한다. node 간 relay 수신은 이 끝점에서 허용하지 않음 |

포장 순서는 `B = Marshal(Request 또는 SecretRequest)` → `E = Marshal(Envelope{Body:B,...})` → TLV1=`E`, TLV2=`SHA256(E)`다. Body는 base64 문자열이 아니라 B가 JSON 값 그대로 들어간다(B는 compact JSON이어야 하며, 받는 쪽은 그 바이트를 그대로 꺼내 서명을 확인한다). 응답 TLV2도 **원 E의 digest**이며 Reply의 digest가 아니다.

세션 요청 Signature는 `Session.Key`에 해당하는 Ed25519 개인키로 다음 바이트를 서명한다. `challenge`는 현재 서버가 낸 연결 challenge다.

```text
"sfc-user-request-1\x00" || Session.Cluster[32] ||
u64LE(len(Session.ID의 UTF-8 바이트)) || Session.ID || challenge[32] ||
u64LE(len(B)) || B
```

### Request — User kind1 입력 필드

공통 필드는 `Schema:uint8=1`, `Method:string`, `UserKey:key32`, `Nonce:nonce32`다. Nonce는 매 요청 새로 만들며 전부0이면 거부한다. UserKey는 개인키 로그인 challenge/최초 관리자 등록에서 사용하고 나머지는 영 배열이다. 나머지 필드는 선택이지만 해당 method가 요구하면 반드시 넣는다.

| 필드 | 타입·용도 |
|---|---|
| `TargetUser` | string: user-credentials의 대상 username. 현재 실행 계정은 Envelope.Session.User이며 서로 다름. 다른 method·Tenant/After/Node와 혼용 금지 |
| `Username`, `Tenant`, `After`, `Node` | string: 로그인 계정·대상 tenant·페이지 cursor·선택 node |
| `App` | 선택 string: tasks의 앱 이름 필터. 다른 method에서는 금지 |
| `AppSource` | app-source/app-revisions 전용 `{Section?,App,Deployment,Revision,Part,Digest}`. 현재 tenant Read·고정 버전의 [원문 조회](../app-source.md) |
| `Ticket`, `Proof` | Ticket, KeyProof: 로그인 증거 |
| `Operation`, `Enrollment` | UserOperation, Enrollment: 서명된 원 관리 변경·최초 관리자 등록 |
| `AuthMethod`, `Credential`, `Secret` | string, string, bytes: password/token 인증 방식·자격 ID·보호 원문 |
| `AppPlan`, `AppOperation`, `AppCDField`, `AppCDApproval`, `AppInput` | 아래 앱 입력 객체 |
| `AppCDRead` | app-cd-history/app-cd-diff 전용 `{App,Part,Digest}`. 현재 tenant Read, history만 바깥 After 허용 |
| `ServiceCall`, `ServiceInput` | service-call 전용 논리 `{App,Service,Port,Path,Method,Headers?,TimeoutMS,Scheme?,InsecureSkipVerify?}`와 `{Length,Digest}`. Body는 kind4 입력이며 JSON 객체에는 없음 |
| `CDProbe` | cd-probe 전용 `{App,Repository,Branch,Path,Credential?}`. 설치된 credential 이름만 받고 비밀값은 없음 |
| `VaultPlan`, `VaultWritePlan` | 아래 Vault 계획 입력 객체 |
| `VolumeUsage`, `VolumeSource` | `{App:string,ID:string}`: 앱 소유/관리 Volume 선택 |
| `NodeStorage` | `{Node:string,ID:string}`: 노드 저장 root 선택 |
| `CheckerUpload` | digest32 포인터: 선택 업로드 ID |
| `CheckerSource`, `CheckerModule` | 아래 source descriptor/module pin |
| `Registry` | `{ID:string,Repository:string,Actions:string[]}`: 제한된 registry 자격 요청 |
| `LogClear` | `{Selection:{App:string,Service:string,Instance:string},Operation:string}`: 로그 정리 계획/원 작업 상태 전용. 정확한 형식은 [컨테이너 API](../container-operations.md) 참조 |
| `Container` | [컨테이너 조회 Query](../container-operations.md): app/service/instance·logs/top/stats·출력 옵션 |
| `LegacySource` | `{Key:string,Revision:uint64,Generation:uint64}`: 정확한 기존 자원 참조 |

method와 전용 객체의 쌍을 검사한다. 예를 들어 `app-operation`에는 AppOperation이 필수이며 다른 method에 이를 넣을 수 없다. 로그인 후 일반 요청에는 Username/Ticket/Proof를 넣지 않는다. operation 요청의 tenant는 바깥 Tenant가 아니라 원 Change.Payload 안에서 결정한다.

