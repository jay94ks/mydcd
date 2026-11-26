## SecretFetch의 원격 앱 입력

앱 파일/env 읽기는 원 AppBindingPermit의 projection ReadSet을 사용한다. 이미지 인증용 읽기는 registry-image-permit의 ExternalInputs ReadSet을 사용한다. 후자는 원 Task/Binding·현재 source·독립 RegistryGrants의 정확한 읽기 집합을 함께 해시한 공개 지문이다. 같은 AppInputFetch 형식으로 전달하되 provider는 두 집합을 혼합하지 않고 각각의 현재 권한을 검사한다. RegistryGrants 회수가 일반 projection grant를 회수하지 않으며 앱 종료 증명은 원 Binding의 두 사용 참조를 모두 반환한다.

목적11의 kind1/2는 현재 설치된 Member만 허용하고 UserAuth/Read/Respond/Manage/가입 Replicate만으로는 허용하지 않는다. datagram/0-RTT·relay kind3·관리/User stream 재해석을 거부한다. node별 동시4와 기존 stream 기한을 사용한다. 요청은 schema1·Consumer 전체 키·원 AppBindingRequest·read-set digest·최소 확정 index·realm/Secret ID의 public metadata다. 수신자는 Consumer를 인증 연결 키와 대조한다. 응답은 같은 request ID·원 public 요청 digest·ReadSet에 묶고 값은 private-purpose body에서만 전달한다. 원문/원문 hash를 Raft·관리 응답·복구 의도에 넣지 않는다.

provider는 member-only 최신 `app-input-read-permit`으로 현재 consumer binding/권한/Group 승인·전체 원 source·read-set·자기 profile key/revision/Values 역할을 조회 전후에 검사한다. 이 관리 응답에는 public leaf/reference/profile만 있고 원문이나 설치 URL/token은 없다. caller가 provider와 다르거나 Secret이 원 선택에 없으면 거부한다. consumer는 현재 write profile의 node/key를 따라 직접 연결하며 일반 relay/임의 주소/다른 HTTP RPC로 우회하지 않는다.

기존 secrets.Fetched의 일반 JSON 직렬화 거부를 유지한다. 전용 private encoder만 값 인코딩을 허용하고 응답 크기·원 요청·ReadSet·정규 형식을 검사한다. 중복/미지 field·비정규 표현을 거부하고 임시 body/값을 사용 후 지운다. provider 값 읽기는 부작용 없는 read이며 새 Secret write/승인이나 Task 재제출을 발생시키지 않는다. 실제 소비자는 기존 Materialize/ProjectionStore·원 Task/참조 수명을 사용한다. 현재 검증 범위와 원 실패는 HISTORY를 따른다.

