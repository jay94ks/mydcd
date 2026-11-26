## 서명된 metadata 관리 CLI

작업 공간의 한도·망·route 조회는 `mydc tenant resources`다([mydc tenant](../../cli/tenant.md)).

로그인한 `auth: user` profile에서 기존 관리 API를 사용한다. 작업 공간·사용자·망·route는 각 그룹 명령을 쓰고, 아직 옮기지 않은 action만 이 명령으로 보낸다. 실제 명령 목록은 `mydc manage --help`를 따른다. 앱 배포·Secret 원문 공급·Volume 운영은 아래 각 명령 경로에서 처리한다. manage metadata 수락만으로 그 효과를 완료한 것으로 보지 않는다.

```sh
build/mydc --config CLIENT.yaml manage apply --request-id tenant-example --change tenant.json
build/mydc --config CLIENT.yaml manage result --request-id tenant-example
build/mydc --config CLIENT.yaml manage resume --request-id tenant-example
build/mydc --config CLIENT.yaml manage prune
```

`tenant.json`은 다음과 같은 **32KiB 이하 JSON metadata**다. outer 필드 이름은 아래 그대로, payload 필드는 해당 Go 제품 타입의 정확한 JSON 이름을 사용한다. 중복/알 수 없는 필드·대소문자 alias·과도한 깊이를 거부한다. principal/outer root CAS/epoch는 파일에서 받지 않고 현재 session과 quorum API에서 얻는다.

```json
{"schema":1,"action":"create-tenant","expected":0,"payload":{"ID":"example"}}
```

`expected`는 action의 대상 revision이다. 새 tenant/user/membership/한도는0, 기존 대상 변경은 그 대상 revision을 명시한다. `rotate-ledger`는 **현재 module epoch**를 expected로 사용하고 payload는 `{"NextEpoch":현재+1}`이다. 별도 storage root CAS는 Prepare가 고정한다. 자체 schema 번호를 변경하지 않는다. `put-user`는 공개 metadata/VerifierRef만 받으며 password/token/verifier 원문 필드는 허용하지 않는다. 현재 session 자체의 폐기는 전용 `logout`을 사용한다.

앱의 terminal 이력 회수는 같은 `manage apply/result/resume`에 `rotate-app-history` action을 사용한다. `expected`는 앱 Inventory revision이고 payload는 `{"Tenant":"tenant","App":"app"}`이다. 별도 Apps root CAS와 현재 권한을 함께 검사한다. 원 제출자의 A1 epoch가 먼저 확정 전환되어야 하며 진행 중/불명·retirement·live Binding·미제거 또는 retained claim이 있는 앱은 거부한다. 원 `Retired` 앱 결과의 제한된 요약·서명 요청·전체 native claim/종료 증거·세대 floor를 유지하고 나머지 terminal 요약만 회수한다. 이는 native 자원 삭제나 새 제출 허가가 아니다. 로컬 intent 정리인 `manage prune`과 구분한다.

첫 apply는 원 서명/ID/epoch/CAS를 `$HOME/.mydc/sessions/.../operations/USER/`에 private sync한 뒤 한 번 전송한다. 같은 profile/user/request ID가 이미 있으면 apply도 **원 결과만 조회**하며 새 파일을 읽거나 재서명하지 않는다. 재전송은 명시 resume만 수행한다. 새 로그인도 원 session/actor/서명을 유지하고 현재 같은 user의 권한을 추가 검사한다. 다른 user/profile은 원 intent를 인수하지 않는다. 파일은0600, 디렉터리는0700이고 내부 symlink와 잠금 충돌을 거부한다.

확정 성공0/거부3은 원 결과와 함께 보존한다. 부재/응답 유실/만료는4와 `local_intent_preserved:true`이며 과거 미실행을 뜻하지 않는다. 로컬 결과는 과거 확인 근거이지 현재 자원 상태가 아니다. prune은 현재 quorum의 module epoch를 읽어 **확정 결과가 있고 이전 epoch인 기록만** 정리한다. Unknown은 만료돼도 보존한다. private journal 한도는256개와 ledger 전환 추가1개이며 포화 시 새 제출을 거부한다. epoch 자동 전환·새 ID/CAS 대체·Unknown 삭제를 하지 않는다. 전체 의미는 부분9시험의 현재 경계를 따른다.


Volume metadata action `create-volume/acquire-volume/release-volume`은 현재 같은 manage 명령과 원 intent 보존을 사용한다. 생성 파일은 실제 노드가 서명한 NativeReady를 담고 `expected: 0`, 획득/반환은 해당 Volume State revision을 명시한다. 원 principal은 현재 session이 결정한다. Prepare는 whoami의 VolumesRootRevision으로 별도 root CAS를 고정한다. host mountpoint/private key/비밀번호 필드는 거부한다. NativeReady/Gone의 node-side 제품 수집·자동 앱 결합과 명시 삭제는 아래 전용 Volume/Compose 계약을 따른다. 임의 unsigned YAML을 실제 준비/종료 증거로 취급하지 않는다. 현재 경계 근거를 따른다.

