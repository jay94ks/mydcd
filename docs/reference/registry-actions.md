# Registry 시작·정지 미리보기

현재 RQ4 연결 단계이며 마지막 실행 검증 전이다. 기존 내장 registry의 `start-registry`·`stop-registry` action을 사용한다. 별도 실행기나 데이터 삭제 경로를 만들지 않는다.

```sh
mydc --tenant team-a --reason '이미지 저장소 점검' registry stop private   # stopped까지 기다린다
mydc --tenant team-a registry start private                               # serving까지 기다린다
mydc --tenant team-a registry start private --no-wait --id start-private-43
mydc op show start-private-43
```

재시작은 정지 완료 후 명시 시작으로 수행한다. `stop` 응답 유실이나 deadline만으로 정지 완료를 가정하지 않으며 원 `mydc op show ID`·`registry show/wait`로 확인한다. `registry start/stop`의 같은 request ID는 원 journal·서명·record CAS를 사용하고 현재 revision으로 바꿔 재제출하지 않는다. `--resume-original`은 그 원 요청만 명시 재개한다. `--expected-revision`을 지정하면 원/현재 계획의 record revision과 같아야 한다. 전역 reason metadata는 원 서명에 포함한다.

권한은 기존 action과 같다. 정지는 현재 tenant `ManageRegistry`의 cleanup 계약, 시작은 tenant/대상 node의 `ManageRegistry`·`ManageVolumes`와 현재 node 업무 권한을 검사한다. credential 동작 제한에는 각각 `stop-registry`·`start-registry`가 필요하다. `restart-registry`라는 별도 권한으로 자동 승격하지 않는다. 기존 typed `manage apply` 경로도 같은 reducer를 사용한다.

## API

기존 Unix/네트워크 MYDCP User purpose와 서명 envelope를 사용한다. 미리보기는 실행 가능한 UserOperation을 만들거나 서명하지 않는 인증된 quorum read다.

| 필드 | 내용 |
|---|---|
| Request.Method | registry-action-plan |
| Request.Tenant | 선택한 tenant |
| Request.RegistryAction | `{Action:"start-registry" 또는 "stop-registry",ID:"private"}` |
| Request.After/Node | 비워 둠. 다른 method의 selector 혼합 금지 |
| Reply.RegistryActionPlan | 아래 계획. 오류는 denied/conflict/unavailable |

```json
{"Schema":1,"Method":"registry-action-plan","Tenant":"team-a","RegistryAction":{"Action":"stop-registry","ID":"private"}}
```

이는 추가 본문 필드의 예시다. 실제 client는 기존 Nonce·Session·채널 challenge 서명을 포함한다. JSON의 필드 이름은 위처럼 대문자로 시작하고 schema는1이다.

| Plan 필드 | 내용 |
|---|---|
| Schema, Cluster, Action, Tenant, ID | 1과 고정된 선택 |
| Expected, RootRevision, Epoch | registry record revision·공유 registry root revision·module epoch |
| Current | 기존 공개 RegistryView: Spec, Revision, Generation, Deleted, Active, Draining, Observation? |
| WouldEnable | 시작 true, 정지 false |
| DataPreserved | true. 기존 Volume·image/upload 데이터 보존 |

미리보기와 실제 reducer는 같은 권한·활성 노드/Volume 전제를 사용한다. 미리보기 이후 root/record·권한·소유 상태가 변하면 실행이 거부될 수 있다. 미리보기가 새 run·writer·Volume reservation을 생성하지 않는다.

실행은 기존 UserOperation의 `Change.Action=start-registry|stop-registry`, `Change.Expected=Expected`, `Payload={Tenant,ID}`이며 operation.RootRevision에는 현재 registry root revision을 사용한다. 기존 사용자 서명·CAS·quorum·원 request 결과를 그대로 적용한다. CLI의 `accepted`는 목표 metadata 수락이다. 실제 리스너 정지·writer join/Volume 반환 또는 새 TLS serving 관측은 기존 `registry show/wait`로 확인한다. `serving-observed`는 내장 owner 관측이며 외부 Docker pull 검증으로 표시하지 않는다.

앱 종료나 registry 정지로 Volume의 원 데이터를 지우지 않는다. 이 미리보기는 클러스터 관리 registry의 읽기 projection이며 별도 앱 소유 자원을 만들지 않는다.
