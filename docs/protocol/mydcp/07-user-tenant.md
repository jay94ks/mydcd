## user 인증·tenant 권한 경계

사용자 인증은 password/private-key/token을 지원하며 node proof/Gate와 분리한다. server-authenticated 제한 인증 stream에서 user/session/임시 proof 키를 결합하고 명령의 명시 tenant/current membership·relay 원 증거를 검사한다. password/token의 실제 검증은 설정한 credential backend를 사용한다. user에게 node Member/Raft/Snapshot/Tunnel 권한을 부여하지 않으며 node TLS 키를 사용자 서명으로 대체하지 않는다. 자체 schema는1을 유지하고 필수 capability/purpose/kind/필드를 지원하지 않는 peer는 명시 거부한다.

새 자원/관측/Secret 승인/route·packet admission은 확정 tenant/owner/endpoint와 결합하고 caller가 쓴 tenant ID만 신뢰하지 않는다. 각 purpose/kind와 필수 필드는 아래 wire 계약으로 검사하며 사용자 인증이 node admission을 대신하지 않는다. login 원문·token·검증자를 일반 관리 명령/로그/Raft에 넣지 않는다. registry 외부 Docker/OCI push/pull/token HTTP는 별도 adapter이며 노드 내부 명령/복구는 MYDCP를 유지한다.


