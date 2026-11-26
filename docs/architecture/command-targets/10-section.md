## 이미지 본문 조회

| CLI | MYDCP | 대상·권한 | 효과·종료 |
|---|---|---|---|
| `image pull-content IMAGE@DIGEST --kind manifest\|config\|layer [--digest D] [-O FILE]` | ImageContent 목적16 | 선택 tenant Read 또는 ManageRegistry. 고정 manifest의 descriptor·원 Store/승인 source | 원 Session proof·현재 trust/run/read-set을 유지하는 읽기. 실제 owner one-hop relay·전체 길이/지문·최종 ok/EOF. 관리 action/request-id·자격 발급 없음 |
| 내부 FROM 본문 읽기(kind5) | ImageContent16·member QUIC | 원 수락 job의 builder → 원 source owner. signed begin의 고정 root와 현재 원 reader/권한 | [Root/Path 본문](../../reference/image-content.md#수락된-빌드의-from-본문). 같은 body verifier/원 참조 유지. 원 frozen source별 BuildKit OCIStores에서 소비. 사용자 CLI 명령·Unix 요청은 추가하지 않음 |

일반 User8 method와 구분한다. [명령·메시지·소비자 확정](../../reference/image-content.md)을 따른다.


### 원 이미지 빌드 게시 정산

| 내부 메시지 | 인증 주체·대상 | 허용 범위·효과 |
|---|---|---|
| member `image-build-publication-owner` | 현재 설치된 원 builder key, 수락된 tenant/job/snapshot의 정확한 출력 태그, 그 원 registry owner | native owner에서 fresh quorum 후 같은 retained Store의 공개 digest/media/길이만 읽음. 만료/취소/회수 이후의 원 결과 정산이며 새 push/login·임의 repository/본문/Secret을 허가하지 않음. User/Unix CLI 명령이 아니고 leader forwarding·Command·Key 입력을 받지 않음 |

조회 실패·부재·다른 digest는 원 PUT의 미실행 증거가 아니다. 미종결 원 빌드의 registry
Store/pin과 worker 원 참조는 각각의 실제 종료/공유 정산 조건에 따라 반환하며, 원 결과
관측을 새 사용자 관리 operation이나 새로운 native 실행으로 바꾸지 않는다.


