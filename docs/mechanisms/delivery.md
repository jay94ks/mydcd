# 내장 CD

내장 CD는 필요한 GitOps 동작을 선별해 Seafield Cluster 자체 명세로 제공한다. Git source의 앱 선언을 읽고 후보를 게시하며 정책에 따라 같은 앱 배포 코어를 실행한다. UI는 후속 범위다.

```text
Git source → 고정 commit/앱 artifact → 후보/계획 → 명시 승인·sync 정책
                                             → 같은 앱 배포 코어 → 관측/원 결과
```

CD가 적용하는 파일은 앱 전용 `app.yaml`이다. tenant 망·저장 root·Secret 값 등 관리 자원 변경을 앱 배포에 자동 합치지 않는다. 관리 변경은 별도 관리 명령으로 수행한다.

기본 sync/recover는 실행 의도 target CAS를 사용한다. fetch·관측으로 CD revision이 달라져도 같은 실행 의도인지 판정하며, 명시 `--expected-revision`은 기존 엄격 비교를 유지한다. 실제 대상 변경·서명·현재 권한·원 요청/epoch 검사는 유지한다.

후보별 Secret 승인·실행 원 operation·현재 native와 완료/거부 영수증은 서로 구분한다. 실패나 단절 뒤 자동 새 ID로 배포하지 않으며 원 작업의 상태와 결과를 관측한다.

[명령 대상표](../architecture/command-targets.md), [앱 입력](../architecture/app-and-cluster-spec.md), CD 상태/정책 세부 설계를 참조한다.
