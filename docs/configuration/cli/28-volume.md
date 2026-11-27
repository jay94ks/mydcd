## 단독 컨테이너

`standalone`은 [sfcli standalone](../../cli/standalone.md)으로 옮겼다. 볼륨 파일은 [sfcli volume](../../cli/volume.md#파일-넣고-빼기)로 옮겼다.

### 관리 자원 조회와 원격 판

`sfcli server-version`은 선택 cluster/peer의 TLS pin을 검증하여 sfcd 판을 읽는다. user profile을 사용하지만 로그인·wallet 비밀번호를 요구하지 않으며 `sfcli version`의 로컬 CLI 판과 다르다. `sfcli --tenant TENANT manage network-users|network-closure|route-endpoints|lifecycle-uses|vault-approvals|vault-usages|image-trust`의 method별 selector/페이지·권한은 [관리 자원 조회](../../reference/resource-queries.md)를 따른다. `--name`, 선택 `--app`/`--node`, `--after`만 각 method의 허용 조합으로 사용한다. 빈 cluster realm은 명시 `--system`을 사용하며 system-admin이 필요하다. 볼륨 조회는 [sfcli volume](../../cli/volume.md)을 쓴다.


