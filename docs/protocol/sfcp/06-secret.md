## Secret 보호 입력과 승인

D2 Secret Group 계약의 값/verifier provider 입력은 아래 schema1 SecretInput 목적10에 연결한다. Group 비밀번호 확인/공유 승인 API·Compose 숨김/FD 입력·[Secret CLI](../../cli/secret.md)는 아래 현재 계약을 따른다. 일반 관리 명령/로그 digest·Raft payload에는 비밀/비밀번호/hash를 넣지 않는다. 승인 payload는 시점/사실/대상만 정규 인코딩해 서명하고 현재 issuer/정책·폐기/배포 대상과 함께 검증한다. signature만으로 provider 복호화나 다른 앱/노드의 접근을 허용하지 않는다.


<a id="후속-user-인증tenant-권한-경계"></a>

