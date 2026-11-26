# 컨테이너 앱 작업 디렉터리

컨테이너에 넣는 앱 소스·이미지 정의·entrypoint·빌드 자료는 `apps/<컨테이너 이름>/`에서 관리한다. 같은 이미지의 여러 runtime 인스턴스마다 소스 디렉터리를 복제하지 않는다.

새 컨테이너 앱을 추가할 때도 이 구조를 사용한다. 디렉터리 이름은 관리하는 앱/이미지의 이름이며, job별로 생성되는 Docker runtime 이름이나 ID를 사용하지 않는다.

| 디렉터리 | 용도 |
|---|---|
| [lifecycle-compiler](lifecycle-compiler/README.md) | job이 있을 때만 기동하는 lifecycle Go 컴파일러 |
| [php](php/README.md) | PHP/PDO 샘플 웹 컨테이너 |
| [mysql](mysql/README.md) | MySQL 샘플 컨테이너의 bootstrap/health 명령 |
| [mydc-web](mydc-web/README.md) | 웹 관리 UI 데몬 컨테이너(`cmd/mydc-web`, mydc.sock 마운트) |
| [authclient-fixture](authclient-fixture/README.md) | non-voter 소켓과 pin한 voter의 유한 실제 인증 시험 client |
| [dockerbackend](dockerbackend/README.md) | 실제 Engine/Ingress 경계 시험에 넣는 컨테이너 앱 |

시험 orchestration·실패 주입·이미지 패키징 도구는 `tests/`에 둔다. PHP/MySQL의 공통 이미지 준비는 prepare_images.py가 이 디렉터리의 소스를 읽는다. 배포 입력인 [app.yaml](../docs/examples/php-mysql/app.yaml)은 `docs/examples/`에서 관리한다.

여기는 저장소의 소스 작업 위치다. 실제 node의 tenant/job별 임시 workspace·원 journal·Secret·Volume 데이터·compiled cache를 이 경로로 옮기지 않는다. runtime 경로는 승인된 node 저장 정책과 원 job의 격리를 따른다.
