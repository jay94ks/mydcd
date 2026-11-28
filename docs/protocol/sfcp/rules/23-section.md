## 서버 전송 실패 진단

Unix/QUIC의 서버 실패는 기존 로그에 transport·실패 단계·고정 cause·인증된 peer 공개키·검증된 purpose/kind/wire request ID로 기록한다. 오류 원문·endpoint·payload·Secret/서명은 포함하지 않는다. 정상 종료/요청 사이 유휴 close·성공 discovery는 오류와 구분하고 불완전한 record/frame·처리 중 EOF는 기록한다. 상세 형식과 SDK 관측 한계는 [Unix/API 진단 설명](../../../reference/unix-sockets/17-section.md)을 따른다. 로그는 wire 메시지·내구 operation 결과·미실행 증명·자동 재전송 허가가 아니며 기존 schema1/인증/권한/정산 계약을 유지한다.

