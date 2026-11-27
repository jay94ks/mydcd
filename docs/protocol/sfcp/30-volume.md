## 단독 컨테이너와 Volume 파일

standalone-up/pin/remove/stop/start/restart의 사용자 요청은 관리 의도 Target을 payload에 서명한다(모드는 이 Target으로 정해진다). 조회의 `StandaloneView.Target`은 pin/remove의 선택 `StandaloneChange.Target`, up은 기존 `AppBegin.Target`에 연결한다. stop/start/restart는 선택 `TaskRestartPlan.ManagementTarget`을 원 `TaskRestartChange`에 그대로 보존하고 기존 plan Target에 정확한 native/StartedAt/owner boot와 함께 포함한다. 연결 수·관측 시각·수락된 작업의 진행 보고는 관리 의도를 바꾸지 않는다. 다른 수락 관리 변경과 미래 revision은 거부하며 현재 권한·자원/정산 검사를 생략하지 않는다. [Unix 메시지 형식](../../reference/unix-sockets/11-section.md#useroperation--내구-관리-변경)을 따른다.

purpose15 `SessionSpec.Kind=attach`는 명시 standalone owner kind의 원 Task/native/StartedAt에 연결한다. argv는 비어 있어야 하며 stdin/TTY/resize와 현재 session/tenant Deploy를 검증한다. 재접속은 새 I/O 연결만 만들고 원 프로세스를 Start/ExecCreate하지 않는다. 공개 pin 이름 변경 후에도 원 불변 scope·Task·Binding·native를 재확인한다.

purpose18은 Volume 파일 스트림이다. 원 서명된 작업·세션·길이·digest에 고정한 유한 header 뒤 최대 24KiB chunk와 명시 EOF를 검증한다. 내용은 관리 record에 넣지 않는다. put/list/get/delete는 동일 VolumesKey consumer와 owner native pin을 사용하고, 응답 유실은 성공/미실행의 증거가 아니다. publication 복구는 원 staged inode receipt가 필요하다.

`standalone-policy-report`는 설치된 exact owner의 원 수락 정책 보고이며 AppsKey schema1 ModuleReport에 저장한다. TTL/연결 해제/프로세스 종료는 새 사용자 down session 없이 원 Inventory retirement를 수락한다. fixed 정책의 Start는 기존 TaskRestartRecord/ContainerControl receipt와 현재 권한·writer fence를 사용한다.

`standalone-extend`는 기존 User purpose의 서명된 submit/result/resume을 재사용한다. 현재 Target/metadata revision, 원 CreatedAt/이전 만료/TTL을 고정한다. 확정 receipt와 원 숫자 결과를 함께 반환하며 Task/native/연결 해제 유예는 바뀌지 않는다. [TTL 메시지 형식](../../reference/unix-sockets/27-volume.md#임시-단독-컨테이너-ttl-연장)과 [사용법](../../reference/standalone.md)을 따른다.

### 관리 자원 공개 조회

User의 기존 Kind1/2 JSON envelope로 [관리 자원·사용처](../../reference/resource-queries.md)를 조회한다. 신규 Purpose/버전 번호는 만들지 않는다. method별 typed Params(`Tenant?`, `Query`, `After?`)와 단일 payload, 8행/96KiB 페이지, 현재 사용자 scope·상태 root cursor를 사용한다. owner I/O가 필요한 network-closure·resources DNS는 기존 인증 member observe를 사용하고, 사용자 응답 직전에 동일 source/현재 권한을 다시 검사한다. 미관측·단절을 0/Ready/서명 완료로 치환하지 않는다. `volume-file-grants`는 동일 Catalog의 사용자별 폴더 grant/revoke를 투영한다. 자격의 VolumeFiles ceiling은 별도이며 빈 목록 selector는 지정 tenant 밖의 위임이나 wildcard 쓰기 권한을 만들지 않는다.

server-version은 같은 transport의 sessionless finite User 요청이며 Schema/Method/Nonce만 허용한다. TLS pin과 record EOF를 유지하고 응답한 sfcd 자신의 Version/Protocol 및 선택 Commit/BuildTime만 제공한다. relay·login/issuer·Raft barrier를 요구하지 않는다.


### Compose ports의 원 Task 입력

앱/standalone의 `ports:`는 기존 app artifact와 Goal/Task recipe의 선택 `Ports`로 전달한다. 각 typed 항목은 `Target`, `Published`, `HostIP`, `Protocol`, `Mode`, `Name`, `AppProtocol`이며 생략한 목록은 JSON/서명 바이트에 추가하지 않는다. 자체 schema·Purpose·User frame 번호는1을 유지한다. parser/계획/수락의 같은 정규화·고정 포트 충돌 검사를 거치며 서버 노드의 Docker PortBindings를 사용한다. 동적/범위의 실제 선택값은 Raft가 예측하지 않고 원 owner의 exact native inspect로 확인한다. source·generation/native identity와 원 result/resume을 보존하며 별도 비인증 L4 RPC/전달 프록시를 만들지 않는다. 이 연결은 [입력 계약](../../architecture/app-and-cluster-spec.md#서비스의-호스트-포트-직접-공개)을 따른다.

