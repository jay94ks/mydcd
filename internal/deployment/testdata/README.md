# 배포 입력 fixture의 경계

`frozen-schema1-compose.yaml`은 과거 통합 입력의 원문이다. 과거 parser·Blueprint/Execution/Inventory 복원과 원 artifact 보존 시험에만 사용한다. 앱과 관리 자원이 함께 들어 있는 이 입력으로 새 앱/CD를 등록하지 않는다. 현재 예시는 `docs/examples/php-mysql/app.yaml`과 별도 관리 `cluster.yaml`이다.

`smallCompose`·`runFixture`는 과거 schema1 코어의 고정 입력이다. 새 제출 시험은 `ParseApp`/`CompileApp`과 현재 관리 source를 제공하는 `managedNetworkFixture` 또는 `externalFixture`를 사용한다. 원 artifact의 decoder가 새 입력 정책을 강제하거나, 새 제출이 과거 decoder만으로 수락되는 양방향 혼용을 금지한다.

CD 신규 등록/소스 갱신 fixture는 실제 관리 망을 먼저 준비하고 앱 파일만 제출한다. 과거 앱 소유 DNS/MTU override를 담은 fixture는 현재 tenant 관리 변경의 성공 근거가 아니다. 현재 앱 CD의 대상 field·권한·원 작업 시나리오는 `docs/testing/php-mysql-two-node.md`의 입력/fixture 매핑을 따르고 E6의 실제 소비에서 연결한다. 기존 입력을 현재 정책에 맞춘다는 이유로 과거 서명/ID/bytes를 덮어쓰지 않는다.

DNS가 있는 native SQL fixture는 서버 설정의 관리 준비와 앱 endpoint 등록을 명시해야 한다. `managedSampleNetworkInputs`는 DNS/runtime/client 설정이 있는 구 입력을 거부한다. DNS 설정을 버린 앱이나 비활성화한 시험으로 원 요구의 성공을 대신하지 않는다.
