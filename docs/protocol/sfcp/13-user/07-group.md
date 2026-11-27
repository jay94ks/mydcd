### Group 승인 계획·민감 확인·원 결과

현재5시험의 User `vault-approval-plan`은 Current session/tenant와 VaultApprovalPlanRequest(Realm/명시 ID/Issuer/Uses/Part/Digest)를 받는다. Scope를 바꾸거나 다른 user/requester/node key를 대입하지 못한다. reply VaultApprovalPart는 root revision/digest/전체 length/part/data이며24KiB part·4MiB 전체 상한이다. client는 같은 root/digest를 검증해 한 계획만 조립한다. 각 Target은 같은 기존 Tree.Plan/Approvals cover를 사용한다.

Compose 승인 요청은 optional Origin의 원 signed begin-app을 포함할 수 있다. Origin이 없으면 requester key는 현재 session key와 같아야 한다. Origin이 있으면 Uses를 임의로 공급하지 않고 공유 upload 또는 현재 같은 원 Execution의 Blueprint에서 ApprovalUses를 도출한다. 같은 현재 user·현재 권한/원 scope·정확한 원 signature/cluster/app/deployment를 요구한다. 미수락 원 의도는 현재 issuer/credential의 원 operation 재생 검사를, 이미 수락된 의도는 정확히 보존된 원 admission grant를 사용한다. 위조된 pending issuer·대상 확대·retired/대체 operation은 거부한다. 재로그인으로 원 requester key를 새 key로 바꾸지 않는다.

Issuer=0인 계획은 각 Group의 고정 verifier profile owner가 현재 member/등록 승인 issuer일 때 그 Peer를 optional Approver로 반환한다. CLI는 인증된 quorum 계획의 그 key/endpoint에 response-only 임시 연결을 만들어 SecretInput을 직접 보내며 저장된 연결 profile이나 node 권한을 바꾸지 않는다. Origin은 permit·approve 민감 요청·내부 VaultApprovalReport에도 optional로 결합한다. nil은 생략해 기존 형식을 유지하고 application 승인 서명 payload는 여전히 시점/사실/대상3개다.

SecretInput의 approve mode는 Values=nil·Target/Realm/ID 일치·password 최대1024B를 요구한다. password 생략은 기존 valid cover 또는 원 내구 attempt의 결과 복구에만 사용하며 신규 KDF를 우회하지 않는다. node/legacy 권한·relay로 password를 전달하지 않는다. 응답의 VaultApproval은 같은 기존 시점/사실/대상 서명 형식이며 공유 게시/현재 유효성을 확인한 후만 성공이다.

Management의 member-only `vault-approval-permit`/`vault-approve-command`/`vault-approval-result`는 기존 Latest/원 caller/1회 relay 규칙을 따른다. permit은 현재 Session/Target/At에 대해 same Target/fixed VerifierBinding/선택 Existing/원 root revision/module epoch/consumer capacity를 반환한다. 새 permit의 At는30초, 미확정 신규 report의 edge At는300초 범위를 검사한다. command는 original VaultApprovalReport/서명·actor/epoch/ID/CAS bytes를 그대로 제안한다. node report도 현재 issuer/session/target/한도를 FSM에서 검사한다. native A2의 Unknown 뒤 결과 부재/ledger 만료는 미실행이 아니며 새 서명/ID/CAS로 바꾸지 않는다.

여러 대상 node의 MaxConsumers 중 작은 현재 한도를 승인 lease capacity에 반영한다. 실제 Bindings/native 소비자의 동적 한도/반환은 별도로 연결해야 하며 승인 생성만으로 원문 fetch/mount·전체 app Ready를 주장하지 않는다.

