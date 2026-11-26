# 이미지 빌드 job

schema1의 job은 보존 컨텍스트 version과 공개 빌드 설정을 고정하는 관리 자원이다.
계획·수락·현재 상태 조회·취소·기록 삭제와 owner 보고 경계를 설명한다. 실제 rootless
BuildKit 실행·Vault secret 공급·내장 registry push·단계 로그·cache 집행은 아직 연결 중이며,
`queued`나 관리 `Applied`는 이미지가 생성됐다는 뜻이 아니다. RQ6 실행 계획을 따른다.

## 절 목록

이 문서는 절마다 파일로 나뉘어 있다.

| 절 | 파일 |
|---|---|
| 계획과 수락 | [image-build-jobs/01-section.md](image-build-jobs/01-section.md) |
| 빌드 Secret 승인과 공급 | [image-build-jobs/02-secret.md](image-build-jobs/02-secret.md) |
| 조회·취소·기록 삭제 | [image-build-jobs/03-section.md](image-build-jobs/03-section.md) |
| owner 실행·정산 경계 | [image-build-jobs/04-owner.md](image-build-jobs/04-owner.md) |
| FROM 본문의 owner 소비 | [image-build-jobs/05-from-owner.md](image-build-jobs/05-from-owner.md) |
| 빌드 TLS 신뢰 자료 | [image-build-jobs/06-tls.md](image-build-jobs/06-tls.md) |
| 노드 작업 공간과 출력의 수명 | [image-build-jobs/07-section.md](image-build-jobs/07-section.md) |
| 빌드 로그 페이지 | [image-build-jobs/08-section.md](image-build-jobs/08-section.md) |
| 결과 registry 게시와 응답 유실 | [image-build-jobs/09-registry.md](image-build-jobs/09-registry.md) |
| 빌드 캐시 관측 페이지 | [image-build-jobs/10-section.md](image-build-jobs/10-section.md) |
| 빌드 종료 시 자동 캐시 정리 | [image-build-jobs/11-section.md](image-build-jobs/11-section.md) |
| 노드·컨텍스트별 캐시 목록 | [image-build-jobs/12-section.md](image-build-jobs/12-section.md) |
| cache ID별 보존 항목 조회 | [image-build-jobs/13-cache-id.md](image-build-jobs/13-cache-id.md) |
| 수동 캐시 정리의 수락과 대기 조회 | [image-build-jobs/14-section.md](image-build-jobs/14-section.md) |
| Automatic Git에서 수락한 job | [image-build-jobs/15-automatic-git-job.md](image-build-jobs/15-automatic-git-job.md) |
| Idle cache의 주기 정책 정리 | [image-build-jobs/16-idle-cache.md](image-build-jobs/16-idle-cache.md) |
| Tenant 종료의 물리 캐시 회수 | [image-build-jobs/17-tenant.md](image-build-jobs/17-tenant.md) |
