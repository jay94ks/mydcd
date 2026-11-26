## 컨테이너 운영 조회

| Method | 입력·인증 | 응답 |
|---|---|---|
| `container-observe` | S·현재 tenant Read; Tenant, Container 필수. After/Node/타 method payload 거부 | Container(로그·프로세스·통계), ContainerViewIndex, RootRevision |

Query/Result의 전체 필드·base64 출력·상한·EOF/권한·담당 노드 경유는 [컨테이너 운영 API](../container-operations.md)를 따른다. 일반 User kind1/2 교환을 사용하며 Unix에 Docker HTTP API나 node 간 Management 입구를 추가하지 않는다.


