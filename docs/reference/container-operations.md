# 컨테이너 운영 API

로그·프로세스·리소스 조회는 로그인한 사용자의 현재 tenant `Read` 권한으로 처리한다. 이 경로의 대상은 MyDC가 관리하는 app/service의 실행 인스턴스이며 Docker ID나 호스트 경로로 임의 접근할 수 없다. 해당 기능의 구현·검증 상태는 루트 마일스톤/이력을 따른다.

## 유한 조회 CLI

```sh
mydc --context production --tenant team-a --user alice app logs shop web --tail 200
mydc --tenant team-a app logs shop web --stdout --timestamps --since 2026-11-21T00:00:00Z
mydc --tenant team-a app top shop web
mydc --tenant team-a app stats shop web -o json
```

공통 옵션은 `--instance TASK`, `--max-bytes N`, `-o json`이다. 명령은 `APP SERVICE` 두 이름을 받는다. instance는 같은 앱/서비스 안의 논리 Task key이며 후보가 여러 개면 명시해야 한다. 파일·배포 ID·placement 변경 옵션은 없다.

로그는 기본 최근200줄, stdout/stderr 모두이며 `--stdout` 또는 `--stderr`로 출력 채널을 선택한다. `--tail`은1–10000, `--since/--until`은 RFC3339 시각이다. 합산 출력은 기본16384바이트·최대24576바이트이며 상한에 도달하면 잘림을 표시한다. JSON의 bytes 필드는 base64다. 일반 출력은 stdout 로그를 표준 출력, stderr 로그를 표준 오류에 쓴다. TTY 컨테이너는 원래 합쳐진 출력이며 분리된 stderr를 가장하지 않는다. 드라이버가 조회를 제공하지 않으면 빈 로그 성공으로 바꾸지 않는다. 컨테이너 내부 파일에만 기록한 로그의 수집 기능은 아니다.

top은 Engine이 제공한 열 이름과 프로세스 목록을 표시한다. PID는 Engine/호스트 기준이며 컨테이너 PID namespace의 번호로 재해석하지 않는다. 컨테이너에 ps를 설치하거나 호스트 프로세스를 별도로 탐색하지 않는다. stats는 일회 표본이며 CPU baseline 확보로 약1초 대기가 추가될 수 있다. 메모리 원 사용량/한도와 cache 제외 working set, 네트워크·블록 I/O 누계의 바이트, PID 수를 구분한다. 누락/준비 중·counter reset은 N/A로 표시하고 0으로 대체하지 않는다. CPU100%는 CPU 한 개 사용량 기준이며 여러 CPU에서는100%를 넘을 수 있다. 이 조회는 resource limit을 바꾸지 않는다.

이 단발 조회의 입력에는 follow/watch/exec·로그 삭제/설정 변경을 섞지 않는다. 연속 스트림·interactive exec·명시 로그 정리는 아래 각각의 API/명령을 사용한다.

## User 메시지

기본 Unix 끝점은 `/var/run/mydc.sock`이며 네트워크 MYDCP와 같은 User 목적의 kind1 요청/ kind2 응답을 사용한다. 현재 연결 challenge에 묶인 Envelope 서명·Session, canonical JSON·요청 digest·EOF 계약은 [Unix API](unix-sockets.md)를 따른다.

`Request.Method="container-observe"`, `Tenant`와 `Container`가 필수다. `After/Node`와 다른 method 전용 payload는 허용하지 않는다.

| Container 필드 | 타입·범위 |
|---|---|
| Schema | uint8, 1 |
| Selection | `{App:string,Service:string,Instance:string}`. Instance는 생략 시 빈 문자열 |
| Kind | `logs`, `top`, `stats`, `inspect` |
| Tail | int, logs에서1–10000; 나머지는0 |
| Since, Until | string, logs의 RFC3339 timestamp 또는 빈 문자열 |
| Timestamps, Stdout, Stderr | bool, logs 전용. stdout/stderr 중 하나 이상 true |
| MaxBytes | int, 1–24576 |
| HistoryLimit | inspect 전용0(기본20) 또는1–100. 다른 종류는0 |
| Cursor | 선택 string, logs/inspect의 이전 NextCursor. 다른 조회/follow에는 금지 |

예를 들어 Envelope.Body에 정규 직렬화되는 Container 값은 다음과 같다. 바깥 Schema/Method/Tenant/Nonce와 사용자 서명은 일반 요청 계약에 따라 포함한다.

```json
{"Schema":1,"Selection":{"App":"shop","Service":"web","Instance":""},"Kind":"logs","Tail":200,"Since":"","Until":"","Timestamps":false,"Stdout":true,"Stderr":true,"MaxBytes":16384}
```

성공 Reply는 `Schema=1, Code="ok", Tenant, RootRevision, ContainerViewIndex, Container`다. ContainerViewIndex는 조회 뒤 현재 권한/대상을 확인한 FSM index이며 지표를 그 FSM에 기록했다는 뜻이 아니다.

| Result 필드 | 형식·의미 |
|---|---|
| Schema, Kind | 1, 원 조회 종류 |
| Target | Cluster/Owner/Binding=32바이트 배열; Tenant/App/Service/Node/Instance=string; Generation/Revision=uint64; NativeID/StartedAt=string |
| ObservedAt | RFC3339 timestamp |
| LogDriver | 선택 string: 실제 native Inspect의 driver/plugin 이름. 생략은 미관측/구형 peer이며 로컬 삭제 가능을 뜻하지 않음. |
| TTY, Truncated | bool: 출력 형식과 상한에 따른 잘림 |
| NextCursor | 선택 string: 같은 가림 완료 구간의 다음 페이지. 없으면 마지막 페이지 |
| Stdout, Stderr | 선택 bytes(base64), logs 전용 |
| Titles, Processes | 선택 string[]·string[][], top 전용. 행별 열 수는 Titles와 같음 |
| Stats | stats 전용 객체 |
| Detail | inspect의 완전한 [실제 설정·drift·검사 결과](container-detail.md) |
| DetailPart | inspect의 가림 완료 JSON 조각. Detail과 배타적이며 전체 검증/수집 뒤 소비 |

Stats는 SampleAt(timestamp), CPUStatus(`ok/warming-up/counter-reset/unavailable`), 선택 CPUPercent(number), MemoryBytes/MemoryWorkingSetBytes/MemoryLimitBytes, NetworkRXBytes/NetworkTXBytes, BlockReadBytes/BlockWriteBytes, PIDs(각 선택 uint64)다. 없는 수치는 생략한다. 네트워크·블록 값은 누계이며 초당 rate가 아니다. logs/follow는 [공급한 Secret 원문 가림](secret-delivery.md#로그)을 출력 제한보다 먼저 적용한다. 이외 관측 본문도 허가된 사용자에게만 전달하고 일반 진단 로그·Raft 상태에 복제하지 않는다.

관측에는 logger backend options/credential을 복사하지 않는다. driver가 local/json-file인 경우의 명시 삭제/교체는 별도 사용자 작업으로 연결하며, 이 조회 metadata만으로 컨테이너를 제거하지 않는다.

권한/입력은 denied, 모호하거나 아직 관측되지 않은 대상·driver/native 읽기 실패는 unavailable을 반환한다. 현재 Task/Binding·owner·generation과 실제 Docker ID/StartedAt를 전후 대조하며 다른 세대에 재연결하거나 미지 결과를 자동 재조회해 성공으로 바꾸지 않는다.

## 담당 노드 경유

유한 container-observe는 접속 노드의 User API를 사용한다. 현재 leader가 다른 노드면 기존 사용자 증거를 검증하는 relay를 사용하고, 실제 Docker가 다른 노드에 있으면 인증된 member Management `container-observe`를 그 owner에게 보낸다. 이 node 간 Management 경로는 로컬 Unix User API에서 직접 열 수 없다. 아래 interactive/follow/watch는 별도 purpose15의 양방향 relay를 사용한다.

내부 입력은 `ContainerRead={Session,Query,Target}`이며 사용자 session의 Read ceiling과 정확한 대상에 고정한다. native owner는 조회 전후 `container-read-permit`의 최신 quorum 판정을 받아 현재 사용자·tenant·Binding·owner를 대조한다. permit은 현재 owner의 member 연결에서만 허용하고 원 index를 확인한다. 본문/통계는 transient 응답이며 새 배포 권한이나 지속 grant가 아니다. Docker는 해당 owner의 명시된 로컬 UDS로만 접근하고 Engine API를 외부에 노출하지 않는다.

## 로그 설정·명시 삭제

서비스 `logging.driver/options`는 app.yaml 소유 설정이며 local/json-file과 문자열 max-size/max-file/compress를 받는다. 생성 시 Docker LogConfig에 적용하고 명시 option을 native Inspect와 대조한다. 생략은 daemon 상속이다. CD 앱은 기존 services/SERVICE/logging field override와 sync로 설정을 변경하며 실제 반영은 컨테이너 교체다. 호스트 daemon.json을 바꾸지 않는다.

max-size는 go-units가 해석하는 양수 크기, max-file은 양수 정수, compress는 명시 bool 문자열이다. 정책은 앱 artifact/Task/spec digest에 포함한다. Engine이 보완한 미선언 기본 옵션은 허용하고 명시 옵션의 차이는 원 Task 성공으로 처리하지 않는다. 기존 schema1에서 생략된 logging은 nil을 유지하므로 설정 추가만으로 과거 원 입력을 바꾸지 않는다.

```sh
mydc --tenant team-a app clear-logs shop web          # 영향을 보여 주고 확인을 묻는다
mydc --tenant team-a app clear-logs shop web -y --id clear-001
mydc --tenant team-a op show clear-001
```

preview는 실제 driver와 원 Task/Binding·native ID/StartedAt/세대 및 영향을 받는 입력/종속 서비스의 범위를 반환한다. Read와 Deploy 권한·활성 owner·신선한 서명 관측을 확인한다. local/json-file만 허용하며 미관측/구형 metadata를 local로 추정하지 않는다. `app clear-logs`는 영향을 먼저 보여 주고 확인을 받은 뒤(`-y`는 확인 생략) 재생성을 요청한다. 결과는 `mydc op show ID`로 다시 본다.

실행은 표시된 컨테이너와 종속 서비스의 중단·writable layer/로컬 로그의 영구 손실에 동의한 재생성이다. Volume 데이터와 외부 보관 로그는 보존한다. 기존 Inventory의 정확한 Drain/Proof/Delete·참조 반환 뒤에만 같은 고정 앱 목표를 현재 권한/CAS로 다시 실행한다. 일반 앱에 CD를 붙이지 않으며 CD 앱은 실행 중이던 선언을 사용해 정책/override/대기 Git 후보를 보존한다. 새 후보를 몰래 배포하지 않는다.

수락 성공과 실제 정리는 구분한다. 상태는 Retiring → Removed → Recreating → Succeeded이며 Removed는 원 로그/컨테이너의 긍정 종료가 확정됐지만 재시작 권한/입력이 아직 충족되지 않을 수 있는 상태다. 원 사용자/목표/서명을 보존하고 이미 제거한 로그를 복구하거나 다른 ID로 자동 배포하지 않는다. 같은 ID의 logs-clear 호출은 원 결과를 조회하며 새 native를 선택하지 않는다. 원 요청 ID는 출력에 제공하고 전송 결과가 불명하면 기존 `manage result/resume --request-id ID`로 같은 intent를 정산한다. status에는 이전 native/세대와 교체 결과를 보존하며 과거 성공이 현재 컨테이너 생존을 보장하는 것은 아니다.

User Method는 `app-log-clear-plan`과 `app-log-clear-status`다. 둘 다 Tenant와 `LogClear:{Selection:{App,Service,Instance},Operation}`을 받는다. 계획은 Operation이 빈 문자열이고 Selection.Service가 필수다. 상태는 App/Operation만 지정하고 Service/Instance는 비운다. 다른 selector·After/Node와 섞을 수 없다. 실제 실행은 별도 `submit` UserOperation의 clear-app-logs action이다.

| 형식 | 주요 필드 |
|---|---|
| LogClearPlan | Schema=1, Tenant/App, InventoryRevision, Target/SourcePlan/SourceCandidate/SourceArtifact=digest32, Container=정확한 Target, LogDriver, Impact 배열 |
| Impact | Key/Kind/Node/NativeID/StartedAt/LogDriver=string, Generation/Revision=uint64, Retained=bool |
| clear-app-logs payload | Tenant/App/Operation, Selection:{Service,Instance}, Target=digest32, Recreate=true |
| LogClearStatus | Operation/Status, Target=digest32, OldContainers/NewContainers=Impact 배열 |

Target은 원 앱 수락·선택된 native lifetime·실제 영향/고정 입력을 결합한다. health heartbeat만의 Inventory ordinal은 제외하므로 같은 대상의 관측 갱신으로 동의를 재작성하지 않는다. Change.Expected는 원 InventoryRevision, 바깥 RootRevision은 Apps root이며 신규 action은 기존 ModuleAppCAS 경계를 쓴다. 원 미정산 삭제/교체를 current target으로 재계획하거나 서명을 바꿔 제출하지 않는다. API는 승인 원문·Command·Secret·logger backend 옵션/자격을 반환하지 않는다.

완료한 일반 앱 재생성 뒤 새 명시 `app deploy`는 새로운 앱 수락으로 처리하며 과거 정리 기록을 보존한다. 아직 제거/재생성을 정산 중인 원 작업은 새 up으로 대체하지 않는다.

## interactive exec와 원 실행 조회

```sh
mydc --tenant team-a app exec shop web -i -t --id shell-001 -- /bin/sh
mydc --tenant team-a app exec shop web -i --id tool-001 -- /usr/local/bin/custom-cli 'argument with spaces'
mydc --tenant team-a app exec shop web --id tool-001 -- /usr/local/bin/custom-cli   # 같은 ID: 원 결과만 조회
```

exec는 현재 tenant Read와 Deploy가 모두 필요하다. `APP SERVICE -- argv...`를 명시하고, ID는 `--id`로 정하거나 CLI가 만든다. shell 문자열로 다시 해석하지 않으며 `--` 뒤의 빈 인자·공백·옵션처럼 생긴 인자를 그대로 전달한다. `-i`는 stdin을 연결하고 `-t`는 Docker TTY를 요청한다. `-it`처럼 붙여 쓰지 않고 `-i -t`로 쓴다. TTY+stdin이 실제 terminal이면 raw 모드·SIGWINCH resize·제어 문자 전달을 사용하고 종료/오류에서 원 terminal 상태를 복원한다. 비TTY는 stdout/stderr를 분리하고 stdin EOF 후에도 출력과 exit를 읽는다. 컨테이너에 shell이 없으면 명령이 실패하며 host shell이나 자동 설치로 대체하지 않는다. 컨테이너의 설정된 user/security를 사용하고 privileged exec override는 제공하지 않는다.

CLI는 사용자 profile에 원 ID/서명·정확한 Task/native ID/StartedAt를 저장한 뒤 제출하고 owner는 기존 private DB에 Create 전 marker·ExecID·Start 전 marker·수락/실제 종료를 저장한다. 첫 실행은 알려진 실제0–255 exit를 CLI 종료 코드로 돌려준다. 출력 EOF 뒤에도 살아 있거나 exit가 불명이면 코드4와 원 status 조회 안내를 반환한다. 같은 ID의 exec를 반복하면 새 대상을 선택하거나 Create/Attach하지 않고 원 상태 JSON을 조회한다. 명령/서비스가 다르면 충돌 오류다. exec-status도 원 기록이 필요하며 현재 같은 계정으로 인증한다. 새 로그인/원 profile archive 선택이 원 서명/대상을 바꾸지 않는다. status 조회 자체의 성공 코드는0이며 프로세스의 ExitCode는 JSON에서 확인한다.

원 기록은 노드당4096개, 로컬 profile/user당256개로 제한한다. 가득 차면 새 exec를 거부하며 불명/완료 기록을 몰래 지워 새 실행을 허용하지 않는다. 기존 원 상태 조회는 계속 제공한다. argv도 민감할 수 있으므로 원 intent는 private journal/owner DB에 두고 공개 status에는 인자를 돌려주지 않는다.

연결 단절·Ctrl-C/사용자 취소·권한 회수/만료·daemon 종료는 I/O를 닫는다. 실제 프로세스가 계속 살아 있을 수 있으며 전체 컨테이너 kill이나 자동 재접속/재Attach/새 exec로 정산하지 않는다. raw TTY의 Ctrl-C는 native terminal로 전달되고, 비TTY의 CLI signal 취소는 접속 종료다. 원 상태의 Running 생략은 관측 불가, ExitCode 생략은 종료 미확정이다. finished는 과거에 확인한 실제 결과이며 현재 컨테이너 생존을 보장하지 않는다. 원 Task 교체 뒤에도 status는 원 ExecID만 조회한다.

## logs follow·top/stats watch

```sh
mydc --tenant team-a app logs shop web --tail 200 --follow
mydc --tenant team-a app top shop web --watch --interval 2s
mydc --tenant team-a app stats shop web --watch --interval 2s -o json
```

기존 현재 Read 권한과 app/service/instance 선택 규칙을 재사용한다. follow는 새 로그를 계속 읽으며 `--until`과 함께 사용할 수 없다. watch의 interval은 기본2초·허용1초–1분이며 단발 조회에 `--interval`만 붙이면 오류다. top/stats의 표본 요약·CPU 계산 준비/N/A·누계/counter reset은 기존 코어를 사용한다. 다른 native/시작 시각으로 자동 이동하지 않는다. 교체/종료 후 새 generation을 보려면 사용자가 별도 새 명령을 실행한다.

`-o json` watch는 표본마다 Container Result JSON 한 줄(NDJSON)을 출력한다. follow JSON은 최초 실제 TTY/driver/Target Result 한 줄 뒤 stdout/stderr SessionRecord JSON을 출력하며 Data는 base64다. 일반 follow는 실제 출력 채널을 사용하고 TTY 원 로그는 합쳐진 stdout이다. 단발 Query의 `--max-bytes`는 watch 표본별 상한이며 follow 전체 누적량의 제한이 아니다. 스트림은 최대16KiB 데이터 chunk·유한 backpressure와 쓰기 기한을 적용한다. CLI의 접속 timeout은 수립 예산이고 전체 감시 시간을 제한하지 않는다. 현재 권한/원 대상·session 만료·idle/취소는 계속 적용한다.

Unix와 네트워크 MYDCP은 [purpose15 메시지 명세](unix-sockets/21-purpose15.md)를 사용한다. 접속 노드와 Docker owner가 다르면 원 사용자 intent/서명을 보존한 member relay로 전달하고 owner가 현재 quorum 허가를 재검사한다. 입력/출력 본문은 Raft/결과 DB에 보관하지 않는다. 구현/검증 완료 여부는 MILESTONES/HISTORY의 근거를 따른다.

## 로그 페이지의 원 구간

첫 logs 조회는 owner 노드에서 최대 8MiB의 가림 완료 구간을 한 번 읽고 요청한 MaxBytes로 나눈다. 더 있으면 Truncated=true와 NextCursor를 반환한다. `Container.Cursor` 또는 CLI `app logs ... --cursor CURSOR`에 그 값을 넣되 tenant/app/service/instance·tail/since/until·채널·timestamps·max-bytes를 그대로 유지한다. JSON의 NextCursor를 사용하거나 일반 출력의 stderr 안내에서 가져올 수 있다.

cursor는 무작위 window ID와 가림 뒤 바이트 위치다. 시각을 이어 읽기 기준으로 쓰지 않으므로 같은 시각의 동일 줄도 중복/누락 없이 보존한다. stdout와 stderr는 각 채널의 원 바이트 순서를 보존하며, 페이지는 stdout 뒤 stderr 순으로 나눈다. 채널 간 시간 순서 합성을 보장하지 않는다. 같은 cursor 재조회는 같은 페이지를 반환한다. 각 페이지도 현재 사용자 권한·원 Task Binding/generation/revision·native와 실행 시작 시각을 검사하고 다른 사용자/대상/옵션으로 재사용하지 못한다.

가린 구간만 owner 프로세스의 메모리에 10분 보관한다. 상세 snapshot과 공유하는 최대 16개·합계64MiB이며 기존 창을 밀어내는 대신 새 창을 `LOG_CURSOR_CAPACITY`로 거부한다. 만료는 후속 요청에서 정리하고 데몬 종료 시 모두 반환한다. 재시작/만료·다른 대상/옵션의 cursor는 `Code=invalid, InputCode=CURSOR_EXPIRED`다. 초기 구간이8MiB를 초과하면 불완전한 이어 읽기 성공을 만들지 않고 `LOG_WINDOW_LIMIT`로 거부한다. since/until로 범위를 줄이거나 follow를 사용한다. 이 오류들은 원문·가림 matcher·내부 경로를 반환하지 않는다. member owner 응답의 LogCode는 User 응답에서 위 InputCode로 변환하며 성공 Container로 전달하지 않는다.

페이지의 ObservedAt은 원 구간을 읽은 시각이다. cursor가 새 로그를 합치거나 교체된 컨테이너로 전환하지 않는다. 새 구간은 cursor 없이 명시 요청하며, 로그 정리·Task 종료로 현재 원 대상 권한을 확인할 수 없으면 기존 일반 unavailable/denied 계약도 적용한다. 이 cache는 Raft·DB·진단 로그에 본문을 저장하지 않는다.

## 다중 사용자 purpose15 상한

purpose15는 노드 Transport 전체에서 동시에8개 handler를 공유한다. 사용자별·연결별8개가 아니며 Unix와 QUIC, 같은 client 신원의 여러 사용자/여러 연결도 같은 상한을 쓴다. capabilities/resolve/status 같은 짧은 호출도 handler가 끝날 때까지 한 칸을 사용하고, follow/watch/exec open은 원 스트림이 끝날 때까지 점유한다. 원격 owner로 relay하면 접속 노드와 owner 노드 각각 한 칸을 사용한다.

상한 초과는 사용자 handler에 들어가기 전에 거부한다. QUIC은 해당 스트림 write를 code2로 취소하고, Unix는 ErrBudget으로 해당 소켓 요청을 종료한다. 이 단계에는 정상 User kind2 거부 응답이 없을 수 있으므로 client는 transport/setup 실패로 취급한다. 다른 사용자를 선택하거나 exec를 자동 재제출하지 않는다. UI client는 필요한 follow/watch만 열고 닫으며, 유한 관측으로 대체하거나 setup 실패를 표시해야 한다. 일반 로그인/User 목적의 별도 한도와 컨테이너 process의 실행 여부를 이8개 상한으로 판정하지 않는다.
