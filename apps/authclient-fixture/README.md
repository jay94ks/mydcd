# 인증 경로 시험 client

RQ2의 유한 Docker 시험 입력이다. 별도 UI·상시 worker가 아니며, stdin의 최대16KiB 시험 입력으로 non-voter의 Unix 로그인 거부와 pin한 voter의 네트워크 로그인/본인 조회를 확인하고 종료한다. private key는 시험 계정의 입력이며 stdout·오류에 표시하거나 파일로 저장하지 않는다.

마일스톤 마지막 검증에서 고정 Go 도구로 정적 빌드하고 `MYDC_TEST_RQ2_AUTHCLIENT`로 실제 join/Docker fixture에 전달한다. 이미지/컨테이너는 기존 enginefixture의 정확한 owner로 생성·Wait·제거한다. 제품 빌드나 일반 시험에서 자동 컨테이너 다운로드·실행을 하지 않는다.
