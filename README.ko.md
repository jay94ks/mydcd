# MyDC

**MyDC(My Docker Cluster)** 는 직접 가진 여러 서버에 Docker 컨테이너 앱을 배포하고 운영하는 도구입니다.
앱을 Compose 스타일 `app.yaml` 하나로 적으면, MyDC가 서비스를 서버에 배치하고 망·Volume·Secret을 연결하고
계속 돌아가게 유지합니다.

[English README](README.md)

> **상태: 초기 미리보기(MVP).** 1.0 전에는 명령, 파일 형식, 통신 규약이 릴리스 사이에 이전 방법 없이 바뀔 수 있습니다.

## 기능

- **앱 하나에 파일 하나.** `app.yaml`에 서비스, 배치, 망, Volume, Secret, 배포 정책을 적습니다.
- **여러 작업 공간.** 작업 공간(tenant)마다 사용자·역할·예산을 두고, 모든 요청을 클러스터가 인증하고 권한을 판단합니다.
- **Raft 기반 제어.** 서버마다 `mydcd` 하나가 돌고 Raft로 상태를 맞춥니다. 서버 사이 통신은 인증된 QUIC 규약 MYDCP입니다.
- **필요한 것이 들어 있음.** 내장 이미지 저장소와 빌드, 인증서를 쓰는 HTTP Ingress, 서버 사이 망, Git 기반 자동 배포,
  Go로 쓰는 lifecycle 검사.
- **CLI와 웹 UI.** 스크립트와 터미널에는 `mydc`, 브라우저에는 `mydc-web`.

## 구성 요소

| 실행 파일 | 하는 일 |
|---|---|
| `mydcd` | 서버마다 하나. 클러스터 구성원, 상태, Docker와 서버 자원 |
| `mydc` | 명령줄 도구. 로컬이나 원격 `mydcd`에 붙습니다 |
| `mydc-web` | 웹 UI 데몬. 서버 앱으로 돌고, 로그인한 사용자 자신의 세션으로 `mydcd`를 부릅니다 |

## 시작하기

준비물: Linux(amd64, arm64), 앱을 돌릴 서버에는 Docker Engine 28.0 이상, 서버 사이 UDP 7443.

단일 서버 클러스터를 만들고 서버를 더하고 빼는 전체 순서는 [docs/quick.md](docs/quick.md)에 있습니다.
PHP + MySQL 예제 앱은 [docs/examples](docs/examples/README.md)에 있습니다.

## 소스에서 빌드

```sh
git clone https://github.com/jay94ks/mydcd.git
cd mydcd
make            # bin/mydcd, bin/mydc, bin/mydc-web(웹 UI 포함)
make test       # 단위 시험
```

Go 1.27과 Node.js 22가 필요합니다. 개발 흐름은 [CONTRIBUTING.md](CONTRIBUTING.md)를 보세요.

## 기여

버그 제보, 제안, PR 모두 환영합니다. 먼저 [CONTRIBUTING.md](CONTRIBUTING.md)와 [행동 강령](CODE_OF_CONDUCT.md)을 읽어 주세요.
보안 문제는 공개 이슈로 올리지 말고 [SECURITY.md](SECURITY.md)를 따라 알려 주세요.

## 라이선스

[Apache License 2.0](LICENSE)입니다. `3rd-party/`의 수정한 외부 코드는 각자의 라이선스를 따릅니다([NOTICE](NOTICE)).
릴리스마다 `THIRD_PARTY_NOTICES`와 SPDX SBOM을 함께 올립니다.
