# System Security Project

## 1. 프로젝트 개요

이 프로젝트는 컨테이너 이미지를 입력으로 받아 **소스 코드 추출 → 취약점 스캔 → 라이브러리 API 정리 → AST 기반 보안 분석 → CVE-API 매핑 → 패치 우선순위 산정**까지 이어지는 엔드-투-엔드 보안 자동화 파이프라인을 제공합니다. 각 단계는 독립적인 모듈로 구성되어 있으며, 단일 이미지를 대상으로 한 반복 가능한 분석 흐름을 구성할 수 있습니다.

## 2. 리포지토리 구조

```
/
├── main.py                 # 전체 파이프라인을 실행하는 오케스트레이션 스크립트
├── requirements.txt        # Python 의존성 목록
├── search_source/          # 컨테이너 이미지에서 애플리케이션 소스 추출 CLI
├── ast_visualizer/         # Python AST 호출 흐름 분석 및 LLM 기반 보안 리포트 생성
├── trivy_extracter/        # Trivy 스캔 래퍼 및 취약점 설명 향상 모듈
├── python_api_extracter/   # Trivy 결과에서 라이브러리별 공개 API 목록 생성
├── cve_api_mapper/         # 복수 LLM을 활용한 CVE ↔ API 매핑 비교 분석
├── fetch_priority/         # 패치 우선순위 산정 모듈 및 CLI
├── DB/                     # 중간/최종 산출물(JSON, 리포트, 시각화 등)
├── test_target/            # 테스트용 취약 이미지(Dockerfile 포함)
└── ...
```

## 3. 실행 준비

### 3.1. 선행 조건

* Docker 및 Trivy가 설치되어 있어야 합니다.
* Python 3.10+ 환경에서 각 서브 모듈을 실행합니다.
* LLM 기능을 사용하려면 `.env` 파일에 다음 API 키를 설정합니다.

  ```bash
  cp .env.example .env
  # 필요한 키만 입력해도 되지만, 사용 예정인 기능별로 준비하세요.
  OPENAI_API_KEY=...
  ANTHROPIC_API_KEY=...
  GOOGLE_API_KEY=...
  XAI_API_KEY=...
  ```

  * `ANTHROPIC_API_KEY`는 취약점 설명 향상(`trivy_extracter`), AST 보안 분석(`ast_visualizer`), 패치 우선순위 평가(`fetch_priority`)에서 사용됩니다.
  * `OPENAI_API_KEY`, `GOOGLE_API_KEY`, `XAI_API_KEY`는 `cve_api_mapper`에서 모델 비교 분석 시 필요합니다.

* Python 패키지 의존성 설치:

  ```bash
  pip install -r requirements.txt
  ```

### 3.2. 테스트용 컨테이너 이미지 준비

```bash
cd test_target
docker build -t pyyaml-vuln .
docker save -o pyyaml-vuln.tar pyyaml-vuln
cd ..
```

## 4. 빠른 시작 (오케스트레이터)

프로젝트 루트에서 단일 명령으로 전체 파이프라인을 실행할 수 있습니다.

```bash
python main.py --image test_target/pyyaml-vuln.tar \
  --run-security-analysis \
  --enhance-trivy \
  --emit-graph
```

주요 옵션:

- `--run-security-analysis`: AST 보안 분석(Claude) 활성화
- `--enhance-trivy`: Trivy 결과 설명을 Claude로 보강
- `--emit-graph`: AST 호출 그래프를 Graphviz로 생성
- `--db-dir`: 기본 출력 디렉터리(`DB/`) 변경
- `--sources-dir`: 추출된 소스를 배치할 디렉터리 지정
- `--app-path`: 이미지 내부 애플리케이션 경로를 수동 지정
- `--no-full-scan`: Trivy 스캔을 HIGH/CRITICAL로 제한
- `--force`: 이미 존재하는 산출물이 있어도 모든 단계를 다시 실행

오케스트레이터는 단계별 산출물이 이미 존재하면 자동으로 건너뛰며, 최종 결과는 `DB/fetch_priority.json`에 저장됩니다.

## 5. 모듈별 수동 실행 (선택 사항)

각 단계의 출력은 기본적으로 `DB/` 디렉터리에 누적되며, 다음 명령을 순차 실행하면 전체 파이프라인을 재현할 수 있습니다.

### 5.1. 컨테이너 이미지에서 소스 코드 추출

`search_source` 모듈은 이미지의 레이어를 병합한 뒤 애플리케이션 소스를 자동 또는 수동으로 추출합니다.

```bash
cd search_source
python main.py ../test_target/pyyaml-vuln.tar ../DB/output --auto-detect
cd ..
```

* `--auto-detect` 옵션은 `/app`, `/usr/src/app` 등 사전 정의된 경로를 탐색하며, `--app-path`로 직접 지정할 수도 있습니다.
* 결과물은 `DB/output/` 아래에 원본 소스 구조 그대로 복사됩니다.

### 5.2. AST 기반 호출 흐름 분석 및 보안 리포트 생성

`ast_visualizer`는 추출된 소스를 분석해 외부 노출 API, 내부 전용 API, 미사용 API를 분류하고, 필요 시 LLM으로 보안 리포트를 생성합니다.

```bash
cd ast_visualizer
python main.py ../DB/output -o ../DB/ast_visualize --json --security-analysis \
  --trivy-data ../DB/trivy_analysis_result.json
cd ..
```

* 그래프 이미지는 `ast_visualize.png`, API 분류 결과는 `ast_visualize_result.json`에 저장되어 이후 단계(`fetch_priority`)가 요구하는 파일명과 일치합니다.
* `--security-analysis`를 사용하면 `ANTHROPIC_API_KEY`로 보강된 JSON 리포트(`ast_visualize_security_analysis.json`)와 텍스트 요약(`ast_visualize_security_report.txt`)이 생성됩니다.

### 5.3. Trivy 취약점 스캔 및 설명 향상

```bash
cd trivy_extracter
python main.py ../test_target/pyyaml-vuln.tar ../DB/trivy_analysis_result.json --enhance
cd ..
```

* 기본 스캔 결과는 `trivy_analysis_result.json`에 저장되며, `--enhance` 옵션을 사용하면 LLM이 CVE 설명을 한국어 친화적으로 재작성합니다.
* 향상된 데이터는 `trivy_analysis_result_enhanced.json`과 사람이 읽기 쉬운 리포트(`trivy_analysis_result_enhanced_report.txt`)로 출력됩니다.

### 5.4. 라이브러리별 공개 API 추출

`python_api_extracter`는 Trivy 결과를 기반으로 취약 라이브러리의 공개 API를 정리합니다.

```bash
cd python_api_extracter
python main.py ../DB/trivy_analysis_result.json -o ../DB/lib2cve2api.json
cd ..
```

생성된 JSON에는 `라이브러리 → 버전 → CVE 목록 → API` 구조가 포함되며, 이후 LLM 분석의 입력으로 활용됩니다.

### 5.5. LLM 기반 CVE ↔ API 매핑 비교

`cve_api_mapper`는 여러 모델을 병렬로 실행해 CVE 설명과 API 목록을 매칭하고 결과를 비교 저장합니다.

```bash
cd cve_api_mapper
python main.py  # 모델 인자를 지정하면 선택 실행 가능
cd ..
```

* 모델별 결과는 `cve_api_mapper/results/<model>_results.json`, 원본 응답은 `cve_api_mapper/raw_responses/`에 축적됩니다.
* 오케스트레이터는 GPT‑5 결과를 자동으로 `DB/gpt5_results.json`으로 복사합니다. 수동 실행 시에도 동일한 파일명을 맞춰주세요.
* 비교 요약본은 `cve_api_mapper/results/model_comparison_summary.json`에서 확인할 수 있습니다.

### 5.6. 패치 우선순위 산정

`fetch_priority` 패키지는 AST 분석, Trivy 스캔, CVE‑API 매핑 결과를 통합하여 모듈별 패치 우선순위와 권장 조치를 제공합니다.

```bash
cd fetch_priority
python -m fetch_priority ../DB
cd ..
```

* 출력 파일 `DB/patch_priorities.json`에는 모듈별 위험 점수, Docker 외부 노출 여부, 권장 패치 명령 등이 포함됩니다.
* 실행 전에 `DB/`에 다음 파일이 준비되어 있는지 확인하세요: `ast_visualize_result.json`, `gpt5_results.json`, `lib2cve2api.json`, `trivy_analysis_result.json`. 위 절차를 따르면 자동으로 해당 파일명이 맞춰집니다.
* `python -m fetch_priority --output <경로> --model <모델명>` 형태로 산출물 위치나 사용할 Claude 모델을 조정할 수 있습니다.

## 6. 산출물 요약

| 파일 | 설명 |
| --- | --- |
| `DB/output/` | 컨테이너에서 추출한 애플리케이션 소스 트리 |
| `DB/ast_visualize_result.json`, `DB/ast_visualize.png` | AST 기반 API 분류 결과 및 호출 그래프 |
| `DB/trivy_analysis_result.json` / `_enhanced.json` | Trivy 스캔 결과 및 LLM 향상 설명 |
| `DB/lib2cve2api.json` | 라이브러리별 CVE와 공개 API 매핑 |
| `cve_api_mapper/results/*.json` | 모델별 CVE↔API 매핑 결과 |
| `DB/patch_priorities.json` | 패치 우선순위와 대응 권장사항 |

## 7. 라이선스

이 프로젝트는 MIT 라이선스를 따릅니다.
