## Reply와 오류 포맷

공통 필드는 `Schema:uint8=1`, `Code:string`, `RootRevision:uint64`다. 그 외 필드는 값이 있을 때만 직렬화한다. 서버 응답에는 처리 node를 식별하는 Node가 추가된다.

| 필드 | 타입·의미 |
|---|---|
| `Node`, `RelayedBy`, `Leader`, `InputCode`, `Tenant` | string: 처리/전달 node, leader 힌트, 계획 입력 오류 분류, 선택 tenant |
| `Data` | JSON: [typed method](10-user.md#typed-method)의 응답. 그 method의 응답 타입 하나만 담는다 |
| `Ticket`, `Session` | 위 인증 객체 |
| `User`, `Tenants` | `{ID,Username,Revision,SystemAdmin}`, `{ID,Revision,Role}[]`; Role=`manager`/`viewer` |
| `Result`, `Found` | `{Code:uint8,Index:uint64,Revision:uint64,Generation:uint64}`, bool 원 결과 존재 여부 |
| `*RootRevision`, `*Revision`, `*Index`, `ModuleEpoch`, `NodeOperationEpoch` | uint64: 위 method별 명시 root/자원/관측 기준 |
| `NodeVoters`, `NodeQuorum` | int: 실제 적용된 투표 구성 |
| `Members`, `NodeLifecycle`, `Resources`, `Apps`, `Uploads` | 해당 method 표의 typed 객체 배열 |
| `*Next` | string: 다음 페이지 cursor |
| `Invitation`, `TenantRetirement`, `LegacyTarget`, `LegacyRetirement`, `AppOperation`, `AppCDField`, `AppCDRegistration`, `AppPlan`, `VaultObservation`, `VaultApproval` | method별 공개 결과 객체. 정확한 타입/필드 순서는 [Reply 선언](../../../internal/userauth/service.go) 참조 |

| Reply.Code | 의미·후속 동작 |
|---|---|
| `ok` | 요청 처리 성공. Result.Code/업무 상태까지 읽어야 실제 변경 결과를 알 수 있음 |
| `continue` | streaming 입력 수락. 이제 kind4 조각을 보낼 수 있음. 최종 성공 아님 |
| `denied` | 현재 인증·권한·대상·field 조합 등 거부 |
| `invalid` | 계획/stream 입력 부적합. InputCode가 있으면 함께 판독 |
| `unsupported` | 알 수 없거나 지원하지 않는 User Method |
| `missing` | checker recover 등에서 요청한 저장 사실을 찾지 못함. 외부 효과의 미실행을 보장하는 의미는 아님 |
| `not-leader` | leader 처리 불가. Leader가 있으면 힌트이며 비밀 입력 자동 전송 허가는 아님 |
| `unavailable` | 현재 quorum 읽기·저장/서비스 등 사용 불가 |
| `unknown` | 전송/수락된 원 작업의 확정 결과 불명. 원 ID/증거 보존 후 조회·정산 |
| `expired` | 원 요청 보존 window 만료. 과거 미실행의 증거 아님 |
| `ledger-full` | 내구 요청 기록 예산 거부. 기존 원 결과를 임의 삭제하지 않음 |

`Result.Code`는 문자열이 아니라 **숫자 enum**이다: `0=Applied`, `1=ConditionFailed`, `2=Invalid`, `3=RequestConflict`, `4=Forbidden`, `5=Expired`, `6=LedgerFull`. 예를 들어 Reply.Code=`ok`여도 Result.Code=1이면 CAS 변경은 적용되지 않았다. client의 `transport` 오류는 로컬 오류 분류이며 서버 Reply.Code가 아니다. 잘린 frame·digest 불일치·비정규 JSON·허용하지 않는 purpose 등은 Reply 없이 stream/연결 오류로 끝날 수 있다.

구조 예시(정상 원 결과와 거부 응답):

```json
{"Schema":1,"Code":"ok","Node":"<node-key>","RootRevision":7,"Result":{"Code":0,"Index":42,"Revision":7,"Generation":1},"Found":true}
```

```json
{"Schema":1,"Code":"denied","Node":"<node-key>","RootRevision":0}
```

### 실제 요청 JSON 구조 예시

아래는 인증 자료를 붙이기 전 `whoami`의 **내부 Request**다. 영 UserKey도 포함하며 예시 Nonce는 실제 호출마다 새 난수로 바꾼다.

```json
{"Params":{},"Schema":1,"Method":"whoami","UserKey":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Nonce":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}
```

이 바이트를 base64로 인코딩해 Envelope.Body에 넣고 Session/Signature를 붙인 다음, Envelope 전체를 두 TLV로 포장한다. SecretInput execute의 내부 JSON은 다음 형태다. 예시 값 `demo`의 base64=`ZGVtbw==`이며 실제 Secret을 문서/로그에 출력하지 않는다.

```json
{"Schema":1,"Realm":"demo","ID":"write-1","Mode":"execute","Nonce":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Values":{"DB_PASSWORD":"ZGVtbw=="}}
```

