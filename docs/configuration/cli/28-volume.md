## 단독 컨테이너

`standalone`은 현재 선택된 cluster/tenant와 Linux 사용자별 wallet/journal을 사용한다. 원 operation ID를 바꾸지 않고 결과/재개를 요청하며 profile archive는 journal 선택만 바꾼다. standalone attach/exec/follow/watch는 유한 설정 예산 뒤 purpose15 연결 수명을 사용한다. 자세한 문법은 [단독 컨테이너](../../reference/standalone.md)를 참고한다. 볼륨 파일은 [mydc volume](../../cli/volume.md#파일-넣고-빼기)로 옮겼다.

`mydc standalone extend NAME --ttl-seconds N --operation ID`는 현재 tenant의 실행 목표 temp 수명을 원 At+N으로 연장한다. 생성+24시간 상한과 현재 사용자·Target CAS를 사용하며 원 결과/한도와 journal을 보존한다. 같은 ID 반복은 결과 조회, 불명 제출의 명시 재개는 `mydc manage resume --request-id standalone/extend/TENANT/ID`다. [단독 컨테이너 수명](../../reference/standalone.md)을 따른다.

### 관리 자원 조회와 원격 판

`mydc server-version`은 선택 cluster/peer의 TLS pin을 검증하여 mydcd 판을 읽는다. user profile을 사용하지만 로그인·wallet 비밀번호를 요구하지 않으며 `mydc version`의 로컬 CLI 판과 다르다. `mydc --tenant TENANT manage network-users|network-closure|route-endpoints|lifecycle-uses|vault-approvals|vault-usages|image-trust`의 method별 selector/페이지·권한은 [관리 자원 조회](../../reference/resource-queries.md)를 따른다. `--name`, 선택 `--app`/`--node`, `--after`만 각 method의 허용 조합으로 사용한다. 빈 cluster realm은 명시 `--system`을 사용하며 system-admin이 필요하다. 볼륨 조회는 [mydc volume](../../cli/volume.md)을 쓴다.


