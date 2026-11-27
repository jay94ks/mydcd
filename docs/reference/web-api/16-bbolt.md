## 앱 내리기와 보관된 앱 (웹 bbolt)

`POST /t/{t}/apps/{app}/down` — 본문은 `/ops`와 같고(`action`은 서버가 `down-app`으로 고정) 선택 `volumes`(남는 데이터 저장소 이름)를 더 받는다. `payload`는 `control.AppDown`이어야 하고 `Tenant`·`App`이 URL의 `{t}`·`{app}`과 같아야 한다(아니면 400 `target-mismatch`). 결과가 `rejected`·`failed`면 보관 행을 지운다. `unknown`이면 남겨 두고, 나중에 `/ops/{id}/result`로 `failed`가 확인되면 지운다. 서버가 실행 중 app.yaml을 `app-source`로 받아 **보관 행을 먼저 저장한 뒤에만** down-app을 보낸다. 원문을 못 읽거나 저장하지 못하면 내리지 않는다. 응답은 `/ops`와 같다.

| 끝점 | 권한(매번 sfcd `tenants`로 확인) |
|---|---|
| `GET /t/{t}/archived` | 작업 공간 읽기. `{items:[{key, tenant, app, digest, version, volumes, downBy, downAt, downOp}]}` |
| `GET /t/{t}/archived/{key}` | 읽기. + `yaml`. 다시 올리기는 이 원문으로 일반 배포 경로(plan → 업로드 → up)를 탄다 |
| `POST /t/{t}/archived/{key}/purge` | 관리자. `{confirm:"<앱 이름>"}` → 204. 남은 데이터 저장소 삭제는 별도 `/ops` |

