# 이미지 빌드 정책·컨텍스트와 업로드 metadata

Policy.Platforms는 허용 출력·base stage platform의 범위이고 Context.Platforms는 이 빌드의
출력 선택이다. 정책이 둘 다 허용하면 출력 arm64와 build stage amd64처럼 다르게 구성할 수
있다. FROM의 실제 Source.Platform은 정책 밖으로 넓힐 수 없으며 [원 job 입력](image-build-jobs/04-owner.md)에 고정한다.

이 문서는 schema1의 **컨텍스트와 관리 metadata 경계**다. 정책·컨텍스트 등록, 소유자 한정 ZIP 조각 전송·owner 확인 영수증의 수락, immutable 버전 생성 및 공개 조회를 설명한다. 실제 root pin 아래의 파일 어댑터로 전송하며 자동 만료·물리 회수/정산은 같은 owner 경계로 수행하며 Git source 확인·자동 관측과 Git archive 보관/게시 경계는 아래 절을 따른다. 자동 관측 뒤의 archive/version·build 제출은 아래 자동 빌드 절을 따른다. 전체 BuildKit/로그/cache 사용자 경로의 최종 수락은 RQ6 마지막 검증 대상이다. draft 계획/편집·파일 조각·freeze/게시의 구현 경계는 아래 절을 따른다. 따라서 컨텍스트 생성의 Applied를 실제 이미지 빌드·push 성공으로 판단하지 않는다. 연결·수락 조건을 따른다.

빌드 job의 계획/수락·조회·취소·기록 삭제와 version 사용 참조는 [job API](image-build-jobs.md)를 따른다. 실제 BuildKit 실행·Secret/push·로그/캐시 집행과 구분한다.

## 절 목록

이 문서는 절마다 파일로 나뉘어 있다.

| 절 | 파일 |
|---|---|
| 대상과 권한 | [image-build-contexts/01-section.md](image-build-contexts/01-section.md) |
| 관리 변경 | [image-build-contexts/02-section.md](image-build-contexts/02-section.md) |
| User 조회 메시지 | [image-build-contexts/03-user.md](image-build-contexts/03-user.md) |
| 보존 버전의 파일 트리·Dockerfile 조회 | [image-build-contexts/04-dockerfile.md](image-build-contexts/04-dockerfile.md) |
| ZIP 전송과 버전 생성 | [image-build-contexts/05-zip.md](image-build-contexts/05-zip.md) |
| 편집 draft의 사용자 메시지 | [image-build-contexts/06-draft.md](image-build-contexts/06-draft.md) |
| 폐기된 설정의 미완료 freeze 정리 | [image-build-contexts/07-freeze.md](image-build-contexts/07-freeze.md) |
| 미게시 생성 archive의 회수 | [image-build-contexts/08-archive.md](image-build-contexts/08-archive.md) |
| 종료된 draft 데이터 수명 회수 | [image-build-contexts/09-draft.md](image-build-contexts/09-draft.md) |
| 입력 자료의 원 root 참조와 tenant 종료 | [image-build-contexts/10-root-tenant.md](image-build-contexts/10-root-tenant.md) |
| draft 파일 조각 전송 | [image-build-contexts/11-draft.md](image-build-contexts/11-draft.md) |
| draft freeze와 보존 버전 게시 | [image-build-contexts/12-draft-freeze.md](image-build-contexts/12-draft-freeze.md) |
| draft 미사용 본문 정리 | [image-build-contexts/13-draft.md](image-build-contexts/13-draft.md) |
| Git archive와 보존 버전 게시 | [image-build-contexts/14-git-archive.md](image-build-contexts/14-git-archive.md) |
| 과거 freeze·Git 보관 결과 조회 | [image-build-contexts/15-freeze-git.md](image-build-contexts/15-freeze-git.md) |
| Git 자동 관측 | [image-build-contexts/16-git.md](image-build-contexts/16-git.md) |
| Git 자동 빌드 제출 | [image-build-contexts/17-git.md](image-build-contexts/17-git.md) |
