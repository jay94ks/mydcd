# 컨테이너 실제 설정 조회

최근 종료/재시작 `History`는 [내구 이벤트](events.md)와 같은 공개 ID·원 native/세대·종료 코드를 사용한다. `HistoryIncomplete:true`는 source 수집 누락 또는 이력 조회 실패를 뜻하며, 빈 이력을 정상/완전한 관측으로 취급하지 않는다.

`container-observe`의 `Container.Kind="inspect"`는 현재 tenant `Read` 권한으로 원 Task의 실제 Docker 설정을 조회한다. CLI는 다음과 같다.

```sh
sfcli --tenant team-a app inspect shop web
sfcli --tenant team-a app inspect shop web --instance workload/task/team-a/shop/web --history 5
```

출력은 JSON이다. `--history`는 기본20·1–100이며, 기록 자체의 보관 개수보다 많은 항목을 만들어 내지 않는다. `--max-bytes`는 frame별 기본24576·최대24576이다. CLI는 분할된 상세를 자동 수집해 하나의 JSON으로 출력한다. log 옵션·수동 cursor·follow/watch·배포 옵션과 혼합할 수 없다. 전체 상세를 일부 생략한 성공으로 바꾸지 않는다.

## 원 대상과 drift

동일한 현재 Task key·generation·revision·Binding·담당 node·원 Docker ID와 소유 label을 검사한다. 실제 설정을 목표와 같다고 가정하지 않는다. 메모리·권한·명령·환경·마운트·망 등의 차이는 `Drift`에 필드 이름으로 표시한다. 조회는 재시작·교체·설정 변경을 실행하거나 새로운 Start/Exit·Volume fence 증거를 만들지 않는다.

원 native의 이름이나 실행 시각이 달라져도 같은 소유 ID를 읽을 수 있다. 이것은 새 process incarnation에 제어 권한을 부여하는 동작이 아니다. 조회 전후 현재 사용자/tenant/원 대상 허가를 확인하고, 조회 중 Task가 교체되면 다른 컨테이너로 재연결하지 않는다.

성공한 `Result`는 기존 `Target/ObservedAt/LogDriver`와 `Detail`을 포함한다. `Stdout/Stderr/Processes/Stats`와 혼합하지 않는다. `ObservedAt`은 읽은 시점이며 상태가 계속 유지된다는 보장은 아니다.

| Detail 필드 | 의미 |
|---|---|
| Name, ImageReference, NativeImage, ImageID | 실제 Docker 이름·수락된 이미지 참조·native create의 image 값·실제 image ID |
| Command, Entrypoint, WorkingDir, User | 실제 실행 설정. 공급한 Secret과 일치하는 자유 문자열은 가림 |
| ReadOnlyRootFS, Privileged, CapabilitiesAdded/Dropped, SecurityOptions | 실제 권한 설정 |
| MemoryBytes, NanoCPUs | 실제 resource 상한 |
| StopSignal, StopGraceSeconds | 실제 정지 신호/유예. 미설정 timeout은 Docker 기본10초 |
| LogDriver, LogOptions | driver와 공개 rotation 옵션 max-size/max-file/compress만. backend 자격 제외 |
| Environment | 이름, Source(`literal/image/secret/native-only`), Present, Drift, 선택 Value/SecretReference |
| Mounts | 종류·논리 자원 이름·컨테이너 target·ReadOnly·관측 가능한 UID/GID/Mode. 호스트 source 제외 |
| Networks, NetworksOmitted | 소유 Bridge의 native 이름/ID·주소·aliases. 허가 망으로 검증하지 못한 연결은 이름/주소 대신 생략 개수만 표시 |
| DeclaredNetworkAliases | 앱이 이름으로 지정한 가상 망·별칭. Docker aliases와 구분 |
| DNS, DNSSearch, Ports | 실제 resolver·검색 suffix·노출/게시된 포트 |
| DeclaredIngress | 앱에 선언된 host/node/listener/backend port 연관. State=`declared`이며 remote gateway의 실제 health를 증명하지 않음 |
| Running, Paused, Restarting, OOMKilled, ExitCode, StartedAt, FinishedAt | 실제 Engine process 상태. 현재 관측이며 내구 종료 이력과 구분 |
| Drift | 목표와 다른 필드 이름 목록. 실제 값이 비밀이면 그 값을 넣지 않음 |
| Checks, ChecksTruncated | Docker health와 서비스 lifecycle 최근 결과. 합산100개 상한에 도달하면 잘림 표시 |
| History | 종료/재시작 이벤트 연결용 예약 필드. 현재 소비하지 않음 |

## 환경과 비밀값

일반 환경 변수의 `Value`는 앱에 명시한 값이 실제 값과 같은 경우에만 반환한다. 이미지 기본값·native-only 값·다르게 변한 native 값은 공개하지 않는다. Secret 환경 변수는 `SecretReference`만 반환한다. [Secret 공급·가림](secret-delivery.md)의 원 projection을 검증하고 자유 native 문자열도 같은 원문 필터를 통과시킨다. 값을 읽을 수 없으면 원문으로 fallback하지 않는다.

native Inspect 전체·labels·로그 파일 경로·호스트 bind source·provider 옵션·원 health 출력·스크립트 파라미터를 반환하지 않는다. 목표 선언의 논리 참조와 실제 native의 존재/일치 여부를 구분한다.

## 검사 결과

각 Check는 Checker/Phase/Status, At, DurationMS, 고정된 짧은 Message, 선택 ConsecutiveFailures, RunID/NativeID와 generation/revision을 포함한다. `DurationMS`는 lifecycle run의 준비부터 완료까지의 시간이고 Docker health는 Engine의 start/end 차이다. 알 수 없는 과거 연속 실패 수는 생략하며0으로 추정하지 않는다.

서비스 lifecycle은 기존 private 관측 레코드에 checker별 최근20개 완료 run을 보존한다. 반복 제어 receipt 저장은 같은 RunID를 중복 추가하지 않는다. 새 Task 세대로 바뀌어도 같은 논리 Task의 보관된 결과에는 원 세대/native를 유지한다. raw Result.Reason·스크립트/probe 출력 대신 `check passed/failed/result unavailable` 요약을 사용한다. Docker health는 Engine이 현재 보관한 최근 결과를 반환하며 보관되지 않은 과거 결과를 만들지 않는다. 앱 전체를 평가하는 checker를 개별 컨테이너의 검사 성공으로 복제하지 않는다.

통계의 시간 이력은 서버가 별도 보관하지 않는다. 기존 `stats --watch`로 client가 표본을 수집하는 방식을 사용한다. 이 문서의 검사 결과 보관과 CPU/메모리 시간 표본을 혼동하지 않는다.

## 대형 상세 분할과 수집

전체 가림 완료 상세가 MaxBytes를 넘으면 Result.Detail 대신 DetailPart를 반환한다. DetailPart는 `{Snapshot:string, Offset:int, Length:int, Digest:[32]byte, Data:bytes}`다. Snapshot은 무작위64자리 소문자 hex ID, Offset/Length는 전체 canonical JSON의 바이트 위치/길이, Digest는 그 공개 상세 JSON의 SHA-256이다. Data는 JSON에서 base64이며 길이는 MaxBytes 이하다.

남은 조각이 있으면 Truncated=true와 NextCursor를 반환한다. User API는 같은 inspect Query에 Cursor=NextCursor를 넣어 이어 읽는다. history/max-bytes·대상·사용자를 바꾸지 않는다. 각 페이지에서 현재 사용자 권한·원 Binding/Task·native ID/실행 시작 시각을 다시 검사한다. 도중 config가 바뀌어도 원 snapshot을 새 관측과 섞지 않으며, native incarnation이 바뀌면 원 cursor를 거부한다. snapshot의 ObservedAt/Target/LogDriver/TTY·ID/길이/해시는 모든 조각에서 같다.

client는 Offset 연속성·모든 고정 metadata·전체 길이/해시·canonical JSON을 검증하고 끝까지 수집한 뒤에만 완전한 Detail로 표시한다. Go client의 `InspectContainer`와 CLI `compose inspect`가 이 코어를 사용한다. `ObserveContainer`는 한 wire 페이지를 반환하므로 직접 사용하는 client는 위 수집을 수행해야 한다. 조각 일부를 완전한 설정으로 표시하지 않는다.

owner의 로그/상세 cache는 합계64MiB·16개·10분을 공유하며 상세 하나는 최대16MiB다. 상세 구간은 가림 완료 JSON만 메모리에 보관하고 원 native Inspect·Secret matcher를 cache/DB/Raft에 넣지 않는다. 용량은 `DETAIL_CURSOR_CAPACITY`, 만료/재시작/대상 변경은 `CURSOR_EXPIRED`, 상세 한도 초과는 `DETAIL_WINDOW_LIMIT`의 invalid/InputCode로 거부한다. member owner의 DetailCode는 이 User 오류로 변환하며 성공 결과로 전달하지 않는다. 새 query나 다른 snapshot으로 자동 대체하지 않는다.
