## 서비스·Git 연결 검사

```sh
sfcli --tenant TENANT service-call APP SERVICE --port 8080 --path /check --body-file request.json
sfcli --tenant TENANT service-call APP SERVICE --port 8443 --path /check --scheme https
sfcli --tenant TENANT cd probe APP --repository https://git.example/app.git --branch main --path app.yaml --credential INSTALLED_NAME
```

`service-call`은 POST만 허용한다. `--header`는 Content-Type/X-SFC-*만 반복 지정 가능하며 `--timeout-ms`는 최대30000, body는256KiB, 응답은64KiB다. HTTPS는 노드 설치 설정 `service_cas`의 해당 tenant CA와 OS trust로 Task IP SAN을 검증하며 `--insecure-skip-verify`는 해당 호출의 명시 선택이다. 현재 CallService 권한을 사용하고 자동 재시도나 operation journal은 없다. timeout/연결 유실 뒤 앱 효과는 불명일 수 있다. `cd probe`는 현재 Deploy 권한으로 branch를 고정 commit에 해석해 Commit·file Size·Node를 읽고 CD/app을 변경하지 않는다. credential은 설치 이름만 받는다. 공개 오류 결과의 CLI 종료 코드는3이며 [입력·한도·오류 전체](../../reference/service-diagnostics.md)를 따른다.

