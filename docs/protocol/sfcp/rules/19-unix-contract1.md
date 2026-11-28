## Unix 관리 스트림 Contract1

로컬 관리 끝점은 `unix:///run/sfcdp.sock`이다. 경로·OS 권한·TLS/ALPN·SFCP handshake와 record/frame의 정확한 byte order·허용 purpose·요청/응답·EOF·예산/종료 규칙은 [Unix 소켓 끝점과 관리 프로토콜](../../../reference/unix-sockets.md)에서 규정한다. QUIC와 Unix는 같은 사용자 인증·서명·CAS/quorum 업무 코어를 사용한다.

유한 User RPC는 요청 frame 뒤 client write EOF를 검증한 뒤 응답·업무 처리를 진행한다. 빠른 거부도 같은 순서이며 trailing byte는 거부한다. continue를 먼저 보내는 app-plan/source/module stage는 자체 입력 body/EOF 경계를 유지한다. EOF 확인을 새 전송 권한이나 자동 재제출로 해석하지 않으며 원 서명·요청 ID와 Unknown 정산을 유지한다.

Unix client의 유휴 캐시는 handshake/교환 시작에서 계산한30초 재사용 기한을 검사하고 새 요청 전에 교체한다. 진행 중 교환과 원 challenge/proof·서명은 보존하며 보존 Session의 늦은 Open은 미전송 오류다. 이 교체는 전송된 요청의 자동 재제출이나 Unknown 해소가 아니다.

