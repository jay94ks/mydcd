# sfc-web 화면 (web)

sfc-web 데몬이 정적 파일로 내보내는 React + TypeScript(Vite) 화면입니다. 화면 설계는 `devel/design/web-ui-plan.md`, `devel/design/web-ui-screens.md`, API 계약은 `docs/reference/web-api.md`를 따릅니다.

## 실행

```sh
npm ci
npm run dev          # 목업 모드: 브라우저 안 가짜 응답(src/api/mock). 로그인 alice/alice, bob/bob
npm run dev:real     # 실제 모드: /api를 sfc-web 데몬으로 넘김(기본 http://127.0.0.1:8080, SFC_WEB_DAEMON으로 바꿈)
npm run build        # 실제 모드 빌드 → dist/ (데몬이 내보내는 파일)
npm run build:mock   # 목업 모드 빌드(시연용)
npm test             # 변환 계층 단위 시험
```

실제 모드는 실제 sfcd에 붙은 데몬이 필요하다(띄우는 법: [../README.md](../README.md#개발-실행)). 데몬에는 가짜 sfcd가 없다.

## 구조

| 위치 | 내용 |
|---|---|
| `src/api/dto.ts` | `/api/v1` 응답 모양(계약 그대로) |
| `src/api/types.ts` | 화면이 쓰는 보기 모델 |
| `src/api/endpoints.ts` | 조회 함수. DTO를 보기 모델로 바꾼다. 화면은 이것만 부른다 |
| `src/api/mock/` | 목업 모드 응답. 계약과 같은 경로·모양·오류. 새로고침하면 처음 상태로 돌아간다(등록한 브라우저 키만 남음) |
| `src/api/streams.ts` | 컨테이너 스트림. 로그·top·stats는 fetch로 SSE를 읽고(다시 잇기에 백그라운드 헤더), 터미널은 WebSocket. 목업은 `src/api/mock/streams.ts` |
| `src/components/ContainerConsole.tsx` | 컨테이너 하나의 로그·자원 사용·프로세스·터미널(xterm, 따로 불러옴) |
| `src/lib/appGraph.ts` | app.yaml ⇄ 그래프 모델 변환·검사·자동 정렬(UI-39). 원문 문서를 고쳐 써서 그래프가 모르는 필드·주석은 그대로 남는다 |
| `src/components/graph/` | 그래프 편집기(Rete.js v2, 따로 불러옴). 블록 위치는 `/layout`(웹 bbolt)에 저장 |
| `src/components/OpPanel.tsx` | 변경 보내기(`POST /ops`, 전용 끝점)와 결과 불명 처리(결과 조회·재개, 배포 단계 정산 뒤 이어 가기) |
| `src/auth/` | 세션, 브라우저 개인키(Ed25519, 암호 문구로 암호화해 localStorage) |
| `src/pages/` | 화면 |

## 규칙

- 변경은 다이얼로그 하나에 작업 ID(opId) 하나. 결과 불명이면 새 ID로 다시 보내지 않고 결과 조회·재개만 합니다.
- 주기 감시 기본 30초, 화면마다 ↻ 새로고침과 기준 시각.
- 목업에서 된다고 실제로 되는 것이 아닙니다. 목업에만 있는 것: 이미지 목록.
- 사람이 하지 않은 요청(주기 조회)은 `X-SFC-Background: 1`을 붙여 자리 비움 로그아웃 시계를 늘리지 않습니다(`usePoll`의 시계 틱 → `markBackground`).
- sfcd 기능이 필요하면 직접 만들지 않고 저장소 루트 `REQUEST.md` 끝에 적습니다.
