# 컨테이너 보안 킬체인 감지 설계 가이드

이 문서는 이미지 취약점 목록 위에 네트워크 노출, 실행 권한, 시크릿 유출 가능성을 결합해 간단한 룰 기반 킬체인 감지 레이어를 추가하는 방법을 정리합니다. "어디서 들어올 수 있고, 들어오면 무슨 권한을 갖고, 무엇을 건드릴 수 있는지"를 기술한 뒤, 이를 연결해 공격 그래프를 생성하는 흐름을 목표로 합니다. FastAPI 응답(`Result.json`)에서는 `killchains[]` 필드가 이에 대한 근거와 함께 노출됩니다.

## 1. 필수 입력 데이터 수집 체크리스트

- **네트워크/노출 정보**
  - Dockerfile: `EXPOSE` 목록.
  - Compose/Kubernetes: `Service` 타입, `Ingress` 존재 여부로 외부 공개 여부 파악.
  - 런타임 관찰(옵션): `netstat`, `ss` 결과에서 실제 리스닝 포트와 프로세스 매핑. 감지기는 Dockerfile과 병합하여 Dockerfile에 없지만 런타임에 열린 포트를 표시합니다.
- **권한 정보**
  - Dockerfile/매니페스트: `USER` 설정, `securityContext.privileged`, `capAdd`(`CAP_SYS_ADMIN` 등), `runAsUser`.
  - `readOnlyRootFilesystem`, `allowPrivilegeEscalation` 설정.
- **시크릿/민감 자산**
  - 환경 변수 이름에 `API_KEY`, `TOKEN`, `PASSWORD`, `AWS_ACCESS_KEY_ID` 등의 패턴 탐지.
  - 볼륨/`hostPath` 마운트: `/var/run/docker.sock`, DB 데이터 디렉터리, 클라우드 자격 증명 파일.
- **애플리케이션 엔드포인트/프로세스**
  - SBOM 기반 프레임워크 식별(예: Flask, Django, Spring)로 웹 노출 여부 추정.
  -  `ps` 결과(옵션)로 주요 프로세스와 실행 사용자 확인. 런타임 사용자와 Dockerfile `USER` 불일치를 근거로 남길 수 있습니다.
- **취약점 메타데이터**
  - CVSS 공격 벡터(`AV:N` 등)와 영향 태그(RCE, auth bypass 등).
  - 패키지/버전별 CVE ↔ API 매핑(이미 `python_api_extracter`가 생성하는 `lib2cve2api.json` 활용).
  - 필요한 경우 킬체인 단계와 MITRE ATT&CK 매핑(T1059, T1203 등)을 저장해 리포트에서 근거와 함께 노출합니다.
## 2. 예시 룰 기반 킬체인 패턴

- **패턴 A: 원격 RCE → 컨테이너 탈취**
  - 조건: (1) 네트워크에서 트리거 가능한 RCE CVE(`AV:N` + RCE 태그) 존재, (2) 외부 노출 포트 존재(`EXPOSE 80`, `Service` type `LoadBalancer` 등), (3) 컨테이너가 `root` 또는 `privileged` 권한으로 실행.
  - 결과: "인터넷을 통해 포트에 접근 후 RCE를 악용하면 곧바로 컨테이너 루트 쉘 획득" 경로로 마킹.
- **패턴 B: 컨테이너 탈취 → 내부 자산/클라우드 계정 침해**
  - 조건: 패턴 A 충족 이후, (1) 환경 변수에 클라우드 키워드 존재 또는 (2) 호스트 소켓(`/var/run/docker.sock`)·DB 데이터 디렉터리 마운트.
  - 결과: "RCE → 컨테이너 장악 → 시크릿/호스트 소켓을 통한 내부 확장" 2단계 킬체인으로 승격.
- **패턴 C: 무인증 관리 엔드포인트 → 데이터 유출**
  - 조건: 웹 프레임워크 존재 + 알려진 무인증/약한 인증 경로(`/admin`, 기본 자격 증명)가 SBOM/구성에서 확인되고 외부 포트가 열려있음.
  - 결과: 데이터베이스 자격 증명이나 민감 파일에 대한 직접 접근 가능 경로로 표시.

## 3. 파이프라인 적용 예시

1. **데이터 적재**
   - Trivy 결과에서 CVSS와 영향 태그를 파싱하고, `python_api_extracter` 산출물에서 패키지별 API/CVE 연관성을 가져옵니다.
   - Dockerfile, Compose, Kubernetes 매니페스트를 파싱해 노출 포트, 권한, 볼륨, 환경 변수를 구조화합니다.
   - 선택적으로 런타임 커맨드(`ps`, `netstat`) 출력도 동일 스키마에 추가합니다. 런타임 스냅샷이 없으면 Dockerfile 정보만 사용하고, 있으면 두 정보를 병합하여 "Dockerfile에 없지만 실제 리스닝 중인 포트"를 따로 강조합니다.
2. **그래프 모델링**
   - 노드: `Internet`, `Container`, `Host`, `Secret`, `CloudAccount`, `Database` 등.
   - 엣지: `Internet --(port 80 open)--> Container`, `Container --(RCE CVE)--> Shell`, `Shell --(env AWS_*)--> CloudAccount`, `Shell --(docker.sock)--> Host`.
3. **룰 평가**
    - 위 그래프에서 특정 경로가 존재하면 패턴 A/B/C 같은 룰을 매칭하고 위험도를 부여합니다. 킬체인 단계별로 MITRE ATT&CK ID를 부여하여 리포트에서 “실행(T1059)→권한상승(T1068)” 식으로 명시할 수 있습니다.
   - 루프/중복을 방지하기 위해 노드 유형별 최대 경로 길이를 제한하거나, 동일 자산에 대한 다중 CVE는 요약 후 단일 엣지로 축약합니다.
4. **리포트 생성**
   - 매칭된 경로와 전제조건을 LLM 입력에 포함해 자연어 시나리오(공격 절차, 난이도, 영향, 완화책)를 생성합니다.
   - 리포트에는 어떤 데이터(노출 포트, 권한, 시크릿)가 근거로 사용됐는지 명시하고, 파이프라인 산출물 경로(`Result.json`, `lib2cve2api.json`, 매니페스트 경로)를 함께 링크합니다.

## 4. 최소 구현 가이드라인

- 입력 스키마를 단순 JSON으로 고정하고, 룰은 별도 YAML/JSON으로 정의해 교체 가능하게 만듭니다.
- CVE 분류 시 CVSS `AV:N` + RCE 태그, CVSS 점수 9.0+를 우선 필터로 사용해 후보를 줄입니다.
- 환경 변수/마운트 탐지 시 정규표현식 키워드 매칭 후, 필요 시 소량의 샘플 값만 해시/마스킹하여 저장합니다.
- 결과는 `high`, `medium`, `info` 등 단순 등급과 함께 공격 경로를 문자열 리스트로 반환하고, FastAPI 응답 구조(`AnalysisResult.logs` 등)에 부착하도록 확장할 수 있습니다.

## 5. 참고: 간단 구현 예시

- `app/core/killchain_detector.py`는 Dockerfile의 EXPOSE/USER/ENV/VOLUME 정보와(옵션) `netstat`/`ps` 런타임 스냅샷을 Trivy 네트워크 RCE CVE와 결합해 `Result.json`에 `killchains` 필드를 추가하는 최소 구현입니다.
- Dockerfile만으로도 포트 노출·권한·시크릿 키워드·민감 마운트(예: `/var/run/docker.sock`)를 수집해, "원격 RCE → 컨테이너 탈취"와 "탈취 후 시크릿/호스트 확장" 두 가지 룰을 자동으로 생성합니다. 런타임이 제공되면 Dockerfile에 정의되지 않은 리스닝 포트나 런타임 사용자 정보를 근거에 추가하고, 각 단계에 대응하는 ATT&CK ID를 함께 기록합니다.

이 가이드를 기반으로 기존 취약점 나열 중심 분석에 "공격 경로" 관점을 추가해,킬체인 리포트를 생성할 수 있습니다.