## 예산과 종료

| 항목 | 현재 경계 |
|---|---|
| TLS+MYDCP 인증 | 최대5초 |
| 서버 관리 교환/read 대기 | 최대30초 |
| Unix 연결 | Transport당 최대64개 |
| 연결당 활성 교환 | 1개 |
| 목적별 동시성 | 해당 Transport의 기존 목적별 예산 |
| client deadline | 호출 context, 없으면 management stream 기본10초 |

client는 TLS/challenge binding을 유지하며 연결당 한 교환씩 재사용한다. 캐시 재사용 기한은 handshake/마지막 교환 시작+30초로 보수적으로 계산한다. 기한이 지난 유휴 연결은 다음 Dial에서 회수하고 새로 인증하며, 진행 중 교환은 회수하지 않는다. 보존한 Session으로 기한 뒤 직접 Open하면 전송 전 오류다. 임의 peer 단절을 모두 미리 감지한다는 보장은 없고, 송신 뒤 실패는 기존 Unknown·원 결과 조회 규칙을 따른다. 연결 교체로 이미 만든 ticket/proof·원 서명/작업을 자동 재작성하거나 재전송하지 않는다.

daemon 종료는 Unix listener의 새 입장을 막고 로컬 연결·요청 context와 자기 socket inode를 정리한다. 기존 모듈의 종료·정산에 필요한 node 간 MYDCP 통신은 그동안 유지하고, 최종 Transport 종료에서 handler/worker를 회수한다. context 취소는 이미 수락된 업무의 미실행 증명이 아니다.

