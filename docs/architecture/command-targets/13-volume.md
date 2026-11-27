## 단독 컨테이너·Volume 파일

| CLI / typed method | 인증·대상 | 원 결과·수명 |
|---|---|---|
| `standalone run` / `standalone-up` | 현재 tenant Deploy; 서비스 하나의 기존 app 입력 검증(Compose ports의 호스트 TCP/UDP 직접 공개 포함); run의 `--group-password-fd`·`SFC_NONINTERACTIVE`는 기존 Group 승인 | `--dry-run`은 원 artifact 읽기만 수행; run(같은 `--id`의 재개 포함)은 원 upload·accept operation과 관리 Target, 불변 내부 scope, 앱/CD 대상 제외; 원 journal 모드 보존 |
| `standalone keep/remove/stop/start/restart` | 현재 tenant Deploy, 관리 의도 Target·기대 revision CAS; 다른 사람 temp 연결·종료는 관리자 | 원 작업 ID·Task/native·StartedAt/owner boot·control receipt; 관측만의 갱신과 관리 변경 구분, keep은 native 재생성 없음; legacy strict 원 요청 보존 |
| `standalone extend NAME DURATION` / `standalone-extend` | 현재 tenant Deploy와 temp 생성자/관리자, 관리 Target·기대 revision CAS | 원 At+DURATION, 생성+86400 상한·증가만 허용, fixed/stop/cleanup/expired 거부; Task/native/Binding/grace 불변; 원 result/resume·숫자 한도/만료·이벤트 |
| `standalone list/show/logs/top/stats/inspect` | 현재 tenant Read | 기존 Task 관측, 원문 revision/digest paging |
| `standalone attach/exec` | 현재 tenant Deploy(+관측 Read), purpose15 | attach는 원 프로세스 재접속, exec는 기존 원 실행/status journal(같은 `--id` 재실행이 결과 조회) |
| `standalone clear-logs` / `logs-clear` | 각 서버의 tenant Deploy, 확인(`-y`) | 서버마다 로그 보관소에서만 지움; 컨테이너 유지 |
| `volume files put/ls/get/rm`·`op show/resume` | 현재 tenant Volume manager 또는 지정 Volume/폴더 위임+Read | purpose18 유한 스트림, 원 operation·consumer/native pin; 본문 비기록 |
| `volume files grant/revoke/grants` / `volume-file-grant/revoke` | 현재 tenant Volume manager | access Catalog CAS의 사용자별 폴더 위임. 전역 credential 변경 없음 |

