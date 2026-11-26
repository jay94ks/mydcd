## 공통 규칙

- 자체 WireSchema는 **1**을 유지한다. 같은 번호만으로 이전 C++ frame과 호환된다고 판단하지 않는다. 새 협상/프레임 식별·필수 필드 검증에서 구 형식을 명시적으로 구분한다. 새 클러스터 기준으로 시작하며 혼합 클러스터/기존 DB 변환은 별도 작업이다.
- 자체 정수는 명시적 LE, 구조체 메모리/패딩을 전송하지 않는다. 아래 header·길이·kind를 body 할당 전에, 필수 필드/중복·절단을 dispatch 전에 검사한다.
- 인증 이전에는 제한된 협상/인증만 받는다. 전체 공개키와 TLS 키·challenge·클러스터 결합을 검증하고 현재 허가를 확인한다. Short ID·세션 수·높은 term은 권위를 증명하지 않는다.
- 상태 변경·Raft·터널 데이터는 인증 전/0-RTT에서 처리하지 않는다. 재접속은 새 인증 수명이다. QUIC 연결 성립은 동기화/서비스 Ready를 뜻하지 않는다.
- 요청 ID와 정규 명령 digest를 결합한다. 같은 ID의 다른 명령을 재시도로 허용하지 않는다. 결과 조회는 같은 호출자/ID/명령에 결합하고, 완료 응답은 실제 내구 결과의 위치를 포함한다.
- 송신 시작 이후 단절/timeout/cancel은 **결과 불명**이다. 상대가 실행하지 않았다는 명시 증거 없이 다른 control로 관리 변경을 자동 재전송하지 않는다. 로컬 송신 전 취소는 미전송으로 구분한다.
- 인증/요청/큐/조각은 각각 유한한 byte/item/time 예산을 갖는다. 한 stream의 정체가 heartbeat/Raft/패킷을 무제한 막지 않게 전송 목적별 예산을 설계한다. 예산의 실제 값은 연동 시 확정하며 과거 C++ 숫자를 자동 승계하지 않는다.
- TLS 신원/현재 멤버십과 Raft/Snapshot·일반 제어 admission은 앱/Volume/라우팅의 packet 권한 projection에 의존하지 않는다. 목적별 조회는 같은 현재 committed view를 사용하며 Packet/PathControl과 명시 전체 Peer 조회에서만 기존 tunnel 권한을 계산한다. 양 조회의 캐시를 분리하고 현재 권한 회수를 즉시 반영한다. packet/path owner의 원 scope·native 검사는 유지한다. wire/schema·목적 번호는 바꾸지 않는다.
- Snapshot의 길이·무결성·포함 위치 검사는 유지하지만 블록 간 prev/hash 체인·별도 head/Delta/체인 재포장은 넣지 않는다. prefix가 없으면 Raft Snapshot 후 suffix로 복구한다.

