## 화면 보조 자료 (웹 bbolt)

| 끝점 | 뜻 |
|---|---|
| `GET`/`PUT /t/{t}/apps/{app}/layout?deployment=` | 그래프 편집기 블록 배치 `{layout: <JSON>}`(최대 1 MiB). 읽기는 작업 공간 읽기, 저장은 관리자 |
| `GET`/`PUT /prefs` | 사용자별 화면 설정 `{prefs: {...}}`(최대 64 KiB). 모양은 화면이 정하고 데몬은 `language`만 읽는다: `""`(정하지 않음)·`"ko"`·`"en"`, 다른 값은 400. 계정의 기본 언어다(설계 devel/design/web-i18n.md) |

