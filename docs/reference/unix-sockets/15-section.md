## 사용자 인증·관리 권한·원 결과

TLS/SFCP 인증은 연결 상대의 키를 증명한다. 계정 login은 ticket/proof와 등록된 password·개인키·token 방식을 따르며, 현재 session·account/tenant 권한·서명된 operation·CAS·quorum은 동일한 제품 코어가 검사한다. Unix 접속은 이 검사를 우회하지 않는다.

frame의 request는 통신 교환 ID다. 내구 management request/operation ID·signer·epoch·서명과 구분한다. 전송 뒤 단절·timeout·취소가 발생하면 원 결과가 Unknown일 수 있다. 원 요청을 조회/명시 재개하고 실제 효과를 정산하며, 새 ID로 자동 재실행해 성공을 만들지 않는다. [합의·원 요청 알고리즘](../../algorithms/consensus-and-requests.md)을 참조한다.

