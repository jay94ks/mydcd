## tenant 허용 저장 경로 조회

User 목적8의 `tenant-storage`는 Unix와 QUIC에서 같은 현재 사용자 인증을 사용한다. 입력은 `Tenant`(필수), `Node`·`After`(선택)만 허용하며 현재 ManageVolumes 또는 ManageRegistry와 tenant/node/root ACL을 검사한다. 응답의 `TenantStorage`·cursor·Root 참조 및 오류 계약은 [tenant 저장 경로 API](../../../reference/tenant-storage.md)를 따른다. 별도 member endpoint나 native 파일 읽기를 만들지 않고 quorum committed view를 투영한다.

