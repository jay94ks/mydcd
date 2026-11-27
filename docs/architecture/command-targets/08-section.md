## 컨테이너 운영 조회

| 명령 | 적용 대상 | 인증·입력 | 실행/종료 |
|---|---|---|---|
| `app logs APP SERVICE` | 선택 cluster/tenant의 앱 서비스/명시 instance | 현재 Read session, tail/기간/채널·바이트 상한 | owner의 정확한 Task/native 로그를 유한 조회. stdout/stderr·TTY/잘림 표시. 앱/로그 설정 변경이나 삭제 없음 |
| `app top APP SERVICE` | 같은 논리 서비스의 실제 프로세스 목록 | 같은 Read/owner 경계·선택 instance | Engine 열/행 표시. host PID 재해석·kill 없음 |
| `app stats APP SERVICE` | 같은 논리 서비스의 리소스 표본 | 같은 Read/owner 경계·선택 instance | 일회 CPU/메모리/누계·N/A 표시. limit 변경·별도 metrics DB 없음 |

세 명령의 `--json/--max-bytes/--instance`·global cluster/tenant/user와 메시지 포맷은 [운영 API](../../reference/container-operations.md)를 따른다. 실행 인스턴스가 교체되면 원 조회를 거부하며 다른 native로 자동 재연결하지 않는다.

| 명령 | 적용 대상·인증 | 원 실행·종료 |
|---|---|---|
| `app exec APP SERVICE [-i] [-t] [--id ID] -- argv...` | 선택 cluster/tenant의 현재 동일 사용자 Read+Deploy, 정확한 Task/Binding/native lifetime. 등록 사용자 proof-key intent·독립 승인 정책 | 로컬 원 기록→owner Create 전 marker/ExecID/Start 전 marker→한 번 Attach. 반복 ID는 원 상태만 조회. privileged/host shell/자동 설치 없음 |
| `app exec APP SERVICE --id ID (같은 ID 재실행)` | 같은 cluster/profile/user·현재 tenant Read+Deploy. 원 archive는 journal 선택만 | 원 owner/ExecID의 Running/실제 exit/Unknown. 원 로그인 만료나 Task 교체로 새 target에 이동하지 않음 |
| `app logs APP SERVICE --follow` | 현재 Read·고정 원 native, 기존 tail/since/channel | 새 로그 연속 출력. until 혼용 거부, 표준 채널/TTY 유지. 교체 후 자동 재접속 없음 |
| `app top/stats APP SERVICE --watch [--interval D]` | 현재 Read·고정 원 native, interval1초–1분 | 같은 조회/계산 코어의 시각별 표본. 자원 변경/지표 DB 없음 |

purpose15는 Unix/QUIC의 동일 인증을 사용하고 remote owner에는 원 사용자 proof/intent가 결합된 member relay만 허용한다. exec-status는 격리 입구의 기존 복구 조회 분류를 따르며 새 exec/follow/watch 입구는 Active여야 한다. 권한/만료/daemon/사용자 취소는 I/O를 닫지만 프로세스 종료를 뜻하지 않는다. 원 작업 재시작/재Attach·전체 컨테이너 kill로 대체하지 않는다.

### 서비스 로그 설정

기존 앱 field override의 `services/<service>/logging`은 선택한 cluster/tenant/app/service의 설정 전체를 대상으로 한다. 기존 사용자 변경 권한·원 Task anchor·revision/CAS와 CD override 차이 표시를 유지하며 노드 전역 logging 설정이나 로그 물리 삭제 명령으로 해석하지 않는다. 로그 삭제/교체는 아래 별도 동의와 원 operation 선택을 사용한다.

### 명시 로컬 로그 정리

| 명령 | 대상·주체 | 원 실행/보존 |
|---|---|---|
| app clear-logs APP [SERVICE] [--instance TASK] (확인 질문, `-y`) | 받은 서버는 tenant Read, 각 서버는 자기 상태로 Deploy | 서버마다 로그 보관소에서만 지움. 컨테이너·Raft·작업 기록 없음. 닿지 못한 서버는 같은 명령을 다시 보내 지움 |

