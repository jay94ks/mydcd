## SecretInput 메시지 목록과 포맷

SecretInput kind1도 같은 Envelope를 사용하되 Body가 아래 SecretRequest다. 현재 Session과 공통 요청 서명이 필수이며 Relay는 허용하지 않는다. SecretInput kind2 응답은 같은 Reply 타입이다.

| SecretRequest 필드 | 타입·규칙 |
|---|---|
| `Selection` | AppApprovalSelection, 선택. 있으면 Origin 필수 |
| `Schema`, `Realm`, `ID`, `Mode` | uint8=1, string Vault tenant(전역은 빈 문자열), string 원 write/approval ID, 아래 mode |
| `Nonce` | nonce32, 영 배열 금지 |
| `Values` | map[string]bytes, 선택. 키별 값은 base64 |
| `Target` | 승인 Target, 선택 |
| `Password` | bytes, 선택. Group 비밀번호, 최대1024바이트 |
| `Origin` | 원 UserOperation, 선택 |

| Mode | 입력·제약 | 응답 |
|---|---|---|
| `execute` | 이미 확정/dispatch된 원 ID; Values 1..128개, 키 길이1..128바이트, 값 합계 최대16KiB. Target/Password/Origin/Selection 없음 | VaultObservation: 원 provider 쓰기 관측 |
| `recover` | 같은 Realm/ID. Values/Target/Password/Origin/Selection 없음 | VaultObservation: 원문 없이 원 쓰기 결과 복구 |
| `vps-credential` | `VPSCredential:{Request,Account,AccessKey,SecretKey}`, ID=Request. 받는 서버가 현재 투표 서버여야 함. 다른 필드 없음 | `VPSCredential`: 그 투표 서버가 봉인·서명한 `SealedCredential`(새로 만든 계정 SSH 키를 함께 봉인하고 공개키는 `SSHPublic`).  상태를 바꾸지 않으므로 결과를 모르면 다시 보낸다 |
| `approve` | Target 필수, ID=Target.approval_id, Realm=Target.vault_tenant_id, Values 없음; 해당 Password/Origin/Selection | VaultApproval: 승인 시점·사실·대상의 서명된 기록 |

Target은 다음 **snake_case** 이름을 사용한다. 배열 안 PolicyRef는 `{ID:string,Generation:uint64,PolicyRevision:uint64,AuthPolicy:uint64}`, NodeScope는 `{ID:string,Key:key32}`다.

```text
cluster_id:key32, vault_tenant_id:string, tenant_id:string, user_id:string,
user_policy_ref:uint64, membership_policy_ref:uint64, requester_public_key:key32,
app_id:string, deployment_id:string, group_id:string,
ancestor_policy_refs:PolicyRef[], consumer_service_ids:string[], permitted_nodes:NodeScope[],
actions:string[2], scope:string, approval_id:string, issuer_policy_ref:uint64
```

Target은 [승인 계획](../../../internal/secrets/selection.go)에서 받은 값을 그대로 사용한다. 보호 입력·비밀번호는 metadata/Raft/원 command journal에 기록하지 않는다. 이 경로는 자동 relay/redirect/재전송하지 않으며 unknown 뒤에는 원 ID를 보존한 명시 recover로 정산한다.

