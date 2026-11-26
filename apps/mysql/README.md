# MySQL 샘플 컨테이너

[main.go](main.go)는 샘플 MySQL 컨테이너 안의 nonroot bootstrap/health 명령이다. 저장소 root에서 `./apps/mysql`을 빌드해 얻은 바이너리를 이미지 패키징 도구의 `--mysql-app`으로 전달한다. 도구는 자동 빌드·다운로드를 하지 않는다.

실행/검증 조건은 PHP/MySQL 시험 입력, 배포 선언은 [app.yaml](../../docs/examples/php-mysql/app.yaml)을 따른다. 제품 엔진은 범용 컨테이너·Volume·Secret 수명을 관리한다.
