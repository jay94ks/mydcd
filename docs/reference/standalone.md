# 단독 컨테이너

앱과 단독 컨테이너의 Compose `ports:` 호스트 TCP/UDP 직접 공개는 [같은 서비스 입력](../architecture/app-and-cluster-spec.md#서비스의-호스트-포트-직접-공개)을 사용한다. published는 배치 노드의 호스트 포트이고 생략/0/선택 범위는 Docker가 할당한다. 고정 충돌은 `HOST_PORT_CONFLICT`, 실제 bind 실패는 원 작업 결과로 남는다. Ingress 공개와 직접 포트 공개는 각각의 원 native 수명을 따른다.

단독 컨테이너는 tenant 소유이며 앱 목록·앱 down·CD의 대상이 아니다. 정의는 app.yaml의 서비스 한 개와 같은 입력이다. `depends_on`, 서비스 간 참조, replica/per-node 복제, CD 설정은 받지 않는다. 망·Volume·Secret은 앱 서비스와 같은 이름 참조·현재 권한·사용량 예약·신뢰 검사를 거친다. DNS가 활성화된 관리 망에서는 `networks.<이름>.aliases`를 생략하면 원 단독 컨테이너 이름을 기본 별칭으로 사용한다. 명시한 aliases는 그 값을 사용한다. DNS 없는 망에 이 기본값 때문에 DNS capability를 요구하지 않는다. 일반 앱과 같이 관리 DNS를 사용할 수 있는 망에서만 별칭을 허용하며, 생략하면 DNS 기능을 암묵적으로 요구하지 않는다.

```sh
mydc standalone plan debug -f debug.yaml --lifetime temp --mode shell
mydc standalone up debug -f debug.yaml --lifetime temp --mode shell --operation debug-create
mydc standalone attach debug --operation first-connection -it
mydc standalone attach debug --operation reconnect -it
mydc standalone extend debug --ttl-seconds 3600 --operation extend-debug
mydc standalone pin debug --name maintenance --restart on-failure --operation keep-debug
mydc standalone get maintenance
mydc standalone stop maintenance --preview
mydc standalone stop maintenance --operation stop-maintenance
mydc standalone start maintenance --operation start-maintenance
mydc standalone remove maintenance --operation remove-maintenance
```

`up`/`resume`의 Secret Group 승인은 일반 앱과 같은 보호된 입력·원 승인 경로를 쓴다. `--group-password-fd REALM/GROUP=FD`를 그룹별로 지정하거나 숨김 터미널 입력을 사용하며 `--no-input`은 기존 승인과 명시 FD만 허용한다. FD는3 이상이고 그룹마다 별도여야 하며 비밀번호를 journal/정의/로그에 저장하지 않는다. 읽기 전용 plan/get에는 이 옵션을 받지 않는다.

`up`은 원 upload/accept 단계와 원 operation ID를 사용한다. 신규 생성은 부재 Target을, 정의 변경은 현재 관리 Target을 원 입력 journal에 저장하고 accept에 그대로 전달한다. Group 승인도 이 원 standalone-up 서명과 같은 tenant·내부 scope·deployment·requester에 고정된다. 중단한 원 입력은 `standalone resume NAME --operation ID`로 재개한다. `plan`은 실행하지 않는다. 새 `up`·pin·stop/start/restart/remove 요청은 읽은 관리 의도의 Target과 기대 revision을 함께 서명한다. 연결 수·관측 시각·기존 작업의 진행 보고만 바뀌면 같은 Target을 유지하고, 이름·수명·정의·수락된 제어/종료 의도가 바뀌면 거부한다. 기대 revision이 현재보다 앞선 요청도 거부한다. stop/start/restart는 원 Task/native·StartedAt·owner boot까지 고정한다. 같은 ID의 결과·불명 상태를 조회할 때 새 정의·Task·native를 채택하지 않는다. `control-status NAME --operation ID`는 원 stop/start/restart 진행을 보여 준다.

`temp`는 기본 TTL 3600초, 최대 86400초다. `--ttl-seconds`와 `--grace-seconds`로 생성 정책을 정하며 기본 연결 해제 유예는 600초다. TTL·프로세스 종료·연결 해제 유예 초과·remove 뒤 원 Task의 drain/proof/delete와 Binding/Volume consumer 반환을 진행한다. 접속한 적 없는 entrypoint 작업은 TTL을 사용한다. 연결 해제는 프로세스 종료나 Volume fence의 증거가 아니다. 종료가 확인되지 않은 원 작업은 Unknown과 기존 참조를 보존한다.

`extend NAME --ttl-seconds N --operation ID`는 정리가 시작되지 않은 실행 목표의 `temp`만 연장한다. 새 만료 시각은 원 서명 요청의 `At + N`이며 현재 만료보다 커야 하고 같은 생성 시각의 `CreatedAt + 86400`을 넘을 수 없다. 과거 만료가 지난 신규 제출·fixed·stop/down/정리 상태는 거부한다. 생성 시각·연결 해제 유예·원 Task/native·PID·쓰기 계층·Binding을 바꾸지 않는다. 다른 계정의 temp는 생성/종료와 같은 tenant 관리자 경계를 사용한다.

결과의 `extension`은 원 숫자 좌표(`CreatedAt`, `At`, `PreviousExpiresAt`, `ProposedExpiresAt`, `MaximumExpiresAt`, `AllowedTTLSeconds`, `RemainingExtensionSeconds`)이며 `extension_applied`와 원 `result.Code`로 실제 수락 여부를 구분한다. `STANDALONE_TTL_LIMIT` 거부는 그 요청 시각에 허용된 최대 N과 기존 만료 뒤 남은 연장 한도를 함께 보여 준다. 성공 시 남은 연장 한도는 새 만료부터 24시간 상한까지다. 목록/상세의 `RemainingSeconds`는 현재 확정 만료를 사용한다. 같은 ID의 반복은 원 결과 조회이며 이후의 연장이나 pin 값으로 원 결과를 바꾸지 않는다. 전송 결과가 불명이면 `mydc manage result --request-id standalone/extend/TENANT/ID`, 명시 재개는 `mydc manage resume --request-id standalone/extend/TENANT/ID`로 같은 서명만 사용한다. 원 결과가 확인되지 않은 제안 만료는 성공으로 표시하지 않는다.

`fixed`는 TTL이 없다. 정책은 `no`/`on-failure`/`always`, 기본은 `on-failure`다. mydcd가 원 Task·native의 실제 종료를 관측한 뒤 기존 control receipt로 시작한다. 새 시작은 현재 계정·신뢰·저장 root·Volume fence를 다시 검사한다. 담당 서버가 없어져도 다른 서버로 이동하거나 이름이 같은 컨테이너를 채택하지 않는다.

`pin`은 metadata만 바꾸며 Task·Docker ID·쓰기 계층·로그·망/Secret/Volume 참조를 보존한다. 공개 이름이 달라져도 내부 scope는 바뀌지 않는다. 명시한 별칭과 원 수락 이름에서 얻은 기본 DNS 별칭도 원 Task에 고정되며 정의 변경은 별도 up으로 수행한다.

같은 노드에서 환경변수 등 컨테이너 정의를 바꾸는 `up`도 기존 교체 절차를 사용한다. 원 Task의 drain·서명된 종료 확인·삭제·입력 참조 반환 뒤 새 Task가 Volume/Secret을 다시 예약한다. 원 종료가 불명이면 교체를 완료로 표시하거나 다른 native를 채택하지 않는다. 새 정의에는 새 명시 operation ID를 사용하며, 이미 수락한 ID의 재호출은 원 진행/결과 조회다. 정의 교체는 컨테이너 쓰기 계층과 로컬 로그를 새로 만들고 retained Volume 데이터는 유지한다.

purpose15 `attach`는 원 컨테이너의 ENTRYPOINT/CMD에 다시 연결한다. 연결을 닫거나 CLI를 종료해도 원 프로세스를 종료하지 않는다. stdin EOF나 shell의 exit 명령은 프로세스에 전달되므로 연결 해제와 구분한다. `exec`는 같은 purpose15에서 별도 명령을 실행한다. 둘 다 현재 Deploy 권한을 요구한다. Read로 logs/top/stats/inspect를 읽고 `--follow`·`--watch`로 관측할 수 있다. `logs-clear --preview`와 `logs-clear --recreate --operation ID`는 앱과 같은 명시 재생성 경로다. 재생성은 쓰기 계층과 로컬 로그를 지우며 Volume 데이터는 유지한다.

저장 원문은 `app-source`의 `Standalone` 선택과 revision/digest 고정 paging으로 읽는다. `standalone get`은 이 원문과 metadata를 함께 출력한다. `standalone-list/get`은 수명·현재 목표·연결 수·잔여 TTL과 기존 workload 상태를 제공하며, 상세 상태·종료 코드·재시작 횟수·상태 검사·이력은 같은 Task 관측을 사용한다.

계정별 temp 8개, tenant별 32개, 서버별 64개 상한을 둔다. 각각 `STANDALONE_USER_LIMIT`, `STANDALONE_TENANT_LIMIT`, `STANDALONE_NODE_LIMIT`로 구분한다. 일반 Task/Volume/망/Ingress 한도와 충돌 검사도 적용한다. 다른 계정의 temp 연결·끝내기는 tenant 관리자만 허용한다. 생성/변경 이력에는 사용자·정의 revision·서버·원 operation을 보존하고 터미널 입출력은 저장하지 않는다.

계획은 현재 Volume consumer와도 대조한다. 다른 Task가 붙잡은 writer에 대한 쓰기/읽기와, 다른 reader가 있는 Volume에 대한 쓰기는 `VOLUME_WRITER_CONFLICT`로 거부한다. 원 Task 자신의 pin은 다른 Task로 취급하지 않으며 reader끼리는 공존할 수 있다. 계획은 pin을 취득하거나 반환하지 않는다. 실제 up 수락과 Binding 생성은 현재 상태를 다시 검사하므로 계획 성공이 이후 mount/start의 성공을 보장하지 않는다. 종료가 불명인 writer의 pin도 해제하지 않는다.

자동 종료는 원 수락 시의 temp 정책을 exact owner가 서명 보고하여 같은 Inventory retirement에 연결한다. 만료한 사용자 세션을 새로 만들거나 새 사용자 down 작업으로 가장하지 않는다. 사용자 자격이 취소되어도 원 정책의 제거·정산은 가능하며 시작 권한은 생기지 않는다. 노드 actor의 mutation은 이 서명 정책에서 보존한 원 제거 명령과 전체가 일치하고 전송 상태인 경우에만 허용한다. 임의 노드 관리·생성 명령은 허용하지 않는다.

연결 수의 주기 보고가 다른 Task 생성·종료·정산을 막지 않도록, 보고 확정 뒤 최신 상태로 같은 owner pass를 계속한다. 만료·재시작을 주기 관측보다 우선하고 관측은 가장 오래된 항목부터 갱신한다.
