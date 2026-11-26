## Automatic Git에서 수락한 job

Git.Automatic 컨텍스트의 원 accepted 사용자 정의와 owner SavedGit을 함께 확인한
제출은 [자동 빌드 수락](../image-build-contexts/17-git.md)을 따른다. 공개
job view의 optional Automatic=true로 구분하며 실제 Run.Spec·worker/FROM·build
Secret/로그·취소/closure·version 사용 참조는 동일하다. 새 로그인/가짜 begin 사용자
명령을 만들지 않는다. queue 수락은 build/push 성공이 아니다.

같은 정의/policy revision/commit의 고정 job ID는 failed/deleted history에서도 다시
수락하지 않는다. 다음 자동 commit은 기존 auto job의 원 terminal을 기다린다.
cache maintenance와의 선후는 실제 제출 RootRevision을 쓰며 원 context 등록 때의
오래된 순서로 cache 정리를 앞지르지 않는다. 관리 권한은 원 accepted 시각으로,
새 Secret 승인/ReadSet은 실제 자동 수락 시각으로 확인한다. native/Secret 조회의
Snapshot은 항상 할당된 version Number를 포함한 실제 Run.Spec.Digest다. 자동 보고의
번호 제외 의도 지문을 이 값 대신 사용하지 않는다.

