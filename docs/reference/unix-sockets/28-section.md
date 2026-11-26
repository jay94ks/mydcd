## 관리 자원·사용처 공개 조회

[관리 자원 조회](../resource-queries.md)는 기존 User Kind1→Kind2 finite record와 EOF를 사용한다. Request의 `PublicRead:{Name,App,Node}`와 선택 After를 받는 method는 `network-users`, `network-closure`, `volume-users`, `volume-backup-limits`, `route-endpoints`, `lifecycle-uses`, `vault-approvals`, `vault-usages`, `volume-retained-sources`, `image-trust`, `volume-file-grants`다. 응답은 `PublicRead:{Schema,Method,Tenant,Index,RootRevision,CatalogRevision,TenantRevision,Rows,Next,Total}`이며 각 행은 Key와 해당 method의 단일 payload다. 크기·필드 목록·권한은 연결 문서의 표를 따른다. Secret 값·provider 참조·개인키를 포함하지 않는다. `volume-file-grants`는 원 Catalog의 폴더 grant/revoke 상태만 읽으며 credential ceiling을 발급 위임으로 표시하지 않는다. 빈 Name/App은 지정 tenant 내부의 목록 selector이고 권한 wildcard가 아니다.

`server-version`만 Session 없이 사용할 수 있다. 정확 Request는 Schema/Method/Nonce뿐이고 envelope Session/Signature/Relay와 모든 selector가 금지된다. 응답 ServerVersion은 `{Version:"1",Protocol:1,Commit?,BuildTime?}`다. 현재 연결의 TLS pin·digest·finite EOF를 유지하며 로그인·지갑·leader/quorum은 필요 없다.

`select-tenant`에는 TenantRevision/TenantAllowedNodes, tenants 행에는 AllowedNodes가 추가된다. resources 망 행의 DNS는 전체 정책/source revision 및 실제 owner resolver 관측, volumes 행의 Retained는 원 move별 정리 상태다. node-summary의 ObserveLimitSeconds와 Scheduling의 CordonedBy/CordonedAt, tunnel 이벤트의 Target.Network는 같은 [공개 형식](../resource-queries.md)을 따른다.


