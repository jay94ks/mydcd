# SFCP

SFCP는 Seafield Cluster 노드 간 관리·복제·상태 보고·터널 데이터와 사용자 관리 API에 사용하는 바이너리 프로토콜이다. 원격 node 통신은 QUIC/TLS, 로컬 관리 접속은 [Unix TLS/record](../reference/unix-sockets.md)를 사용한다. 두 어댑터는 같은 frame/TLV와 현재 인증·권한·업무 상태 전이 코어를 공유한다. 자체 schema는1이며 기존 C++ 바이트 형식과 혼용하지 않는다.

## 공통

| 문서 | 내용 |
|---|---|
| [sfcp/00-overview.md](sfcp/00-overview.md) | 계층, 연결, 인증 |
| [sfcp/01-frame.md](sfcp/01-frame.md) | frame header, TLV, kind의 공통 뜻 |
| [sfcp/02-purposes.md](sfcp/02-purposes.md) | purpose 지도(코드 표와 시험으로 대조) |
| [sfcp/03-shapes.md](sfcp/03-shapes.md) | 대화 모양 |
| [sfcp/04-sessions.md](sfcp/04-sessions.md) | mesh, 재사용, 연락·끊김 판단 |
| [sfcp/05-reports.md](sfcp/05-reports.md) | 노드 사이 보고와 Topic 채널 |

## 기능별 규칙

기능마다 메시지 규칙을 따로 둔다. 기능의 reference 문서가 생기면 그쪽으로 옮겨 간다.

| 기능 | 파일 |
|---|---|
| User purpose 8의 기능별 method | [00-user-methods.md](sfcp/rules/00-user-methods.md) |
| 메시지 목적 | [01-section.md](sfcp/rules/01-section.md) |
| 공통 규칙 | [02-section.md](sfcp/rules/02-section.md) |
| schema=1 바이트 계약 | [03-schema-1.md](sfcp/rules/03-schema-1.md) |
| 실제 관리/전송 계약 | [04-section.md](sfcp/rules/04-section.md) |
| Volume transfer 경계 | [05-volume-transfer.md](sfcp/rules/05-volume-transfer.md) |
| Secret 보호 입력과 승인 | [06-secret.md](sfcp/rules/06-secret.md) |
| user 인증·tenant 권한 경계 | [07-user-tenant.md](sfcp/rules/07-user-tenant.md) |
| 관리 DNS의 원 owner 보고 | [08-dns-owner.md](sfcp/rules/08-dns-owner.md) |
| 동적 node admission/회수 | [09-node-admission.md](sfcp/rules/09-node-admission.md) |
| User 목적의 실제 개인키 로그인·조회 | [10-user.md](sfcp/rules/10-user.md) |
| User 목적의 서명 관리 operation | [11-user-operation.md](sfcp/rules/11-user-operation.md) |
| Managed 가입 directory 경계 | [12-managed-directory.md](sfcp/rules/12-managed-directory.md) |
| User 자원 정책·조회 | [13-user.md](sfcp/rules/13-user.md) |
| SecretFetch의 원격 앱 입력 | [14-secretfetch.md](sfcp/rules/14-secretfetch.md) |
| Volume 사용량 조회 | [15-volume.md](sfcp/rules/15-volume.md) |
| 이관 대상 실행과 전송 정산 | [16-section.md](sfcp/rules/16-section.md) |
| 이관 대상의 비공개 입력 준비 | [17-section.md](sfcp/rules/17-section.md) |
| Shared Volume backup operation | [18-shared-volume-backup-operation.md](sfcp/rules/18-shared-volume-backup-operation.md) |
| Unix 관리 스트림 Contract1 | [19-unix-contract1.md](sfcp/rules/19-unix-contract1.md) |
| 최초 등록용 공개 확인 Contract1 | [20-contract1.md](sfcp/rules/20-contract1.md) |
| Lifecycle artifact의 member 소비 | [21-lifecycle-artifact-member.md](sfcp/rules/21-lifecycle-artifact-member.md) |
| tenant 내장 registry의 관리 경계 | [22-tenant-registry.md](sfcp/rules/22-tenant-registry.md) |
| 서버 전송 실패 진단 | [23-section.md](sfcp/rules/23-section.md) |
| 노드 shell — purpose19 | [24-shell-purpose19.md](sfcp/rules/24-shell-purpose19.md) |
| 컨테이너 운영 조회 메시지 | [25-section.md](sfcp/rules/25-section.md) |
| CD 이력·원 값·서비스 변경점 | [26-cd.md](sfcp/rules/26-cd.md) |
| tenant 허용 저장 경로 조회 | [27-tenant.md](sfcp/rules/27-tenant.md) |
| Ingress 관측·Raft 차단과 CertificateMaterial | [28-ingress-raft-certificatematerial.md](sfcp/rules/28-ingress-raft-certificatematerial.md) |
| 서비스 POST·Git probe | [29-post-git-probe.md](sfcp/rules/29-post-git-probe.md) |
| 단독 컨테이너와 Volume 파일 | [30-volume.md](sfcp/rules/30-volume.md) |
| Lifecycle 편집기 source 메시지 | [31-lifecycle-source.md](sfcp/rules/31-lifecycle-source.md) |
| 내장 Secret 값 복제 VaultValue | [32-vault-value.md](sfcp/rules/32-vault-value.md) |
