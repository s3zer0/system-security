# System Security Project Report

## 1. 프로젝트 개요

이 프로젝트는 컨테이너 이미지를 입력으로 받아 **소스 코드 추출 → 취약점 스캔 → 라이브러리 API 정리 → AST 기반 보안 분석 → CVE-API 매핑 → 패치 우선순위 산정**에 이르는 엔드-투-엔드 보안 자동화 파이프라인을 제공합니다. 각 단계는 독립 모듈로 구성되어 단일 이미지를 반복 분석하거나 필요한 단계만 선택 실행할 수 있습니다.

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

* Docker와 Trivy를 먼저 설치합니다.
* Python 3.10+ 환경에서 각 서브 모듈을 실행합니다.
* LLM 기능을 사용하려면 `.env` 파일에 다음 API 키를 설정합니다.

  ```bash
  cp .env.example .env
  # 필요한 키만 입력해도 되지만, 사용할 모듈에 맞춰 사전 준비하세요.
  OPENAI_API_KEY=...
  ANTHROPIC_API_KEY=...
  PERPLEXITY_API_KEY=...
  GOOGLE_API_KEY=...
  XAI_API_KEY=...
  ```

  * `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `PERPLEXITY_API_KEY`는 필수이며 `cve_api_mapper`와 오케스트레이터의 기본 분석 흐름에서 사용됩니다.
  * `ANTHROPIC_API_KEY`는 취약점 설명 향상(`trivy_extracter`), AST 보안 분석(`ast_visualizer`), 패치 우선순위 평가(`fetch_priority`)에도 사용됩니다.
  * `GOOGLE_API_KEY`, `XAI_API_KEY`는 추가 모델 비교를 위한 테스트용 옵션입니다.

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

프로젝트 루트에서 아래 명령을 실행하면 전체 파이프라인이 한 번에 수행됩니다.

```bash
python main.py --image test_target/pyyaml-vuln.tar   --run-security-analysis   --enhance-trivy   --emit-graph
```

주요 옵션:

- `--run-security-analysis`: AST 보안 분석(Claude)을 활성화합니다.
- `--enhance-trivy`: Trivy 결과 설명을 Claude로 보강합니다.
- `--emit-graph`: AST 호출 그래프를 Graphviz로 생성합니다.
- `--db-dir`: 기본 출력 디렉터리(`DB/`)를 변경합니다.
- `--sources-dir`: 추출된 소스를 배치할 디렉터리를 지정합니다.
- `--app-path`: 이미지 내부 애플리케이션 경로를 수동 지정합니다.
- `--no-full-scan`: Trivy 스캔을 HIGH/CRITICAL로 제한합니다.
- `--force`: 이미 존재하는 산출물이 있어도 모든 단계를 다시 실행합니다.

오케스트레이터는 단계별 산출물이 이미 존재하면 자동으로 건너뛰며, 최종 결과는 `DB/fetch_priority.json`에 저장됩니다. 공통 파이프라인 상태는 `PipelineContext` 데이터클래스로 묶어 각 단계 함수에 전달합니다.

## 5. 모듈별 수동 실행 (선택 사항)

각 단계의 출력은 기본적으로 `DB/` 디렉터리에 누적되며, 아래 명령을 순서대로 실행하면 전체 파이프라인을 수동으로 재현할 수 있습니다.

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
python main.py ../DB/output -o ../DB/ast_visualize --json --security-analysis   --trivy-data ../DB/trivy_analysis_result.json
cd ..
```

* 그래프 이미지는 `ast_visualize.png`, API 분류 결과는 `ast_visualize_result.json`에 저장되어 이후 단계(`fetch_priority`)가 요구하는 파일명과 일치합니다.
* `--emit-graph` 옵션을 추가하면 Graphviz 기반 호출 그래프를 생성합니다.
* `--security-analysis`를 사용하면 Trivy 데이터와 AST 결과를 결합해 LLM 보안 진단을 수행합니다.

### 5.3. Trivy 취약점 스캔 및 설명 향상

`trivy_extracter`는 컨테이너 이미지를 대상으로 Trivy 스캔을 수행하고, 선택적으로 LLM을 활용해 취약점 설명을 더 풍부하게 만듭니다.

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

* `build_cve_api_mapping` 함수는 `progress_callback` 인자를 통해 처리 상황을 외부에 보고할 수 있습니다. CLI에서는 `print`를 넘겨 진행 로그를 출력하고, 테스트에서는 목 콜백으로 호출 여부만 검증할 수 있습니다.

### 5.5. LLM 기반 CVE ↔ API 매핑 비교

`cve_api_mapper`는 여러 모델을 병렬로 실행해 CVE 설명과 API 목록을 매칭하고 결과를 비교 저장합니다.

```bash
cd cve_api_mapper
python main.py  # 모델 인자를 지정하면 선택 실행 가능
cd ..
```

* 모델별 결과는 `cve_api_mapper/results/<model>_results.json`, 원본 응답은 `cve_api_mapper/raw_responses/`에 축적됩니다.
* 오케스트레이터는 GPT-5 결과를 자동으로 `DB/gpt5_results.json`으로 복사합니다. 수동 실행 시에도 동일한 파일명을 맞춰주세요.
* 비교 요약본은 `cve_api_mapper/results/model_comparison_summary.json`에서 확인할 수 있습니다.

### 5.6. 패치 우선순위 산정

`fetch_priority` 패키지는 AST 분석, Trivy 스캔, CVE-API 매핑 결과를 통합하여 모듈별 패치 우선순위와 권장 조치를 제공합니다.

```bash
cd fetch_priority
python fetch_priority/main.py ../DB
cd ..
```

* 출력 파일 `DB/fetch_priority.json`에는 모듈별 위험 점수, Docker 외부 노출 여부, 권장 패치 명령 등이 포함됩니다.
* 실행 전에 `DB/`에 다음 파일이 준비되어 있는지 확인하세요: `ast_visualize_result.json`, `gpt5_results.json`, `lib2cve2api.json`, `trivy_analysis_result.json`. 위 절차를 따르면 자동으로 해당 파일명이 맞춰집니다.
* `python fetch_priority/main.py --output <경로> --model <모델명>` 형태로 산출물 위치나 사용할 Claude 모델을 조정할 수 있습니다.
* `--enable-perplexity`를 사용하면 Perplexity API를 호출해 실제 침해 사례를 수집하며, `--perplexity-api-key`로 `.env` 대신 키를 직접 전달할 수 있습니다. 결과 요약은 `DB/perplexity_raw_responses/`에 저장됩니다.
* 패치 우선순위 계산 시 FIRST EPSS 공개 API를 호출해 악용 가능성을 반영합니다. 인터넷 연결이 제한된 환경에서는 해당 단계가 0 점수로 대체됩니다.
* Claude 응답 전문은 `DB/fetch_prioiriy_raw_response.json`에 저장되며, LLM 실패 시 자동 점수 기반 폴백 로직으로 결과를 생성합니다.

## 6. 구현 진행 현황

### 6.1 파이프라인 및 공통 인프라
- `main.py`는 단계별 산출물 존재 여부를 확인해 자동으로 건너뛰고 `--force`로 재실행을 강제할 수 있게 구성했으며, 공통 상태는 `PipelineContext` 데이터클래스로 묶어 단계 함수에 전달합니다.
- `.env` 로드와 CLI 인자를 통해 DB 경로, 소스 저장 위치, 그래프 생성, 보안 분석 옵션 등을 유연하게 설정합니다.
- 공통 유틸 함수(`path_exists_and_non_empty`, `ensure_dir`, `read_json`, `write_json`, `setup_logging`)로 단계 간 파일 입출력과 로깅을 일관되게 처리합니다.
- 파이프라인 완료 시 최종 결과(`DB/fetch_priority.json`) 위치를 로깅하고, 실패 시 예외 메시지로 중단 지점을 안내합니다.

### 6.2 모듈별 정리
- `search_source`: Docker 레이어를 화이트아웃까지 반영해 병합하고 자동 탐지, 수동 경로, 확장자 필터링을 지원합니다.
- `trivy_extracter`: `--enhance` 옵션으로 Claude 기반 취약점 설명 보강과 사람이 읽기 쉬운 TXT 리포트를 생성합니다.
- `python_api_extracter`: Trivy 리포트를 패키지·버전별로 재구성하고 wheel 메타에서 라이브러리 공개 API를 수집하며, 진행 로그는 `build_cve_api_mapping`의 `progress_callback`으로 외부에 전달할 수 있습니다.
- `ast_visualizer`: 호출 그래프와 외부·내부·미사용 API 분류를 제공하고 Trivy 데이터를 입력으로 LLM 보안 진단을 수행합니다.
- `cve_api_mapper`: GPT-5를 기본으로 Claude, Gemini, Grok까지 병렬 분석하고 모델별 결과·Raw 응답·비교 요약을 보관합니다.
- `fetch_priority`: Claude 기반 우선순위 산정에 EPSS 스코어와 실제 사례 검색(Perplexity)을 결합하고, Docker 외부 노출·실제 사용 여부를 종합해 위험 점수를 계산하며 LLM 실패 시 점수 기반 폴백과 Raw 응답 로그를 제공합니다.

### 6.3 산출물 및 로그 디렉터리
- `DB/trivy_analysis_result.json`: 기본 Trivy 출력이며 `*_enhanced.json`과 `_report.txt`는 설명 보강 결과입니다.
- `DB/ast_visualize_result.json`과 `_security_analysis.json`은 호출 흐름과 LLM 진단이며 그래프는 `ast_visualize.png`로 생성됩니다.
- `DB/gpt5_results.json`과 `DB/cve_api_mapper_*/`는 CVE-API 매핑 결과와 원본 응답, 비교 요약을 제공합니다.
- `DB/fetch_priority.json` 혹은 CLI로 지정한 경로에 패치 우선순위 결과를 저장하며 필요 시 `--output`으로 변경 가능합니다.
- `DB/fetch_prioiriy_raw_response.json`에는 Claude 응답 원문과 파싱 결과, 오류 정보가 기록됩니다.
- `DB/perplexity_raw_responses/`에는 Perplexity 실제 사례 검색 응답이 케이스별로 축적됩니다.

### 6.4 테스트 및 참고 리소스
- `test_target/`: PyYAML 취약 이미지를 위한 Dockerfile과 샘플 tar 생성 스크립트를 포함합니다.
- `app.log`: CVE-API 매퍼 실행 로그를 저장하며 최근 실행 상태 확인에 활용합니다.
- `fetch_priority/module/perplexity_searcher.py`: Perplexity Raw 응답을 기본으로 `DB/perplexity_raw_responses/`에 보관합니다.
- `fetch_priority/module/evaluator.py`: EPSS 연동, LLM 폴백, Claude Raw 응답 저장 등 패치 우선순위 핵심 로직을 포함합니다.

## 7. 산출물 요약

| 파일 | 설명 |
| --- | --- |
| `DB/output/` | 컨테이너에서 추출한 애플리케이션 소스 트리 |
| `DB/ast_visualize_result.json`, `DB/ast_visualize.png` | AST 기반 API 분류 결과 및 호출 그래프 |
| `DB/trivy_analysis_result.json` / `_enhanced.json` | Trivy 스캔 결과 및 LLM 향상 설명 |
| `DB/lib2cve2api.json` | 라이브러리별 CVE와 공개 API 매핑 |
| `cve_api_mapper/results/*.json` | 모델별 CVE↔API 매핑 결과 |
| `DB/fetch_priority.json` | 패치 우선순위와 대응 권장사항 |
| `DB/fetch_prioiriy_raw_response.json` | Claude 분석 Raw 응답 및 파싱 결과(오류 포함) |
| `DB/perplexity_raw_responses/` | CVE별 Perplexity 실제 사례 검색 원문 |

## 8. 라이선스

이 프로젝트는 MIT 라이선스를 따릅니다.
