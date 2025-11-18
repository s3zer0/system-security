# system-security 코드 리딩 보고서

## 1. 개요

이 저장소는 Docker 이미지 보안 분석을 자동화하는 백엔드이다. 입력은 애플리케이션을 포함한 Docker 이미지 tar 파일이며, 출력은 취약점 분석 결과(`Result.json`, `meta.json`)와 해당 데이터를 기반으로 한 LLM Q&A 응답이다. 주요 기술 스택은 Python, FastAPI, Pydantic, Trivy CLI, Graphviz, OpenAI/Anthropic/Perplexity SDK로 구성된다.

## 2. 디렉토리 구조 및 모듈 개관

- `Backend/app/` – FastAPI 엔트리포인트(`app/main.py`), 라우터(`app/routers`), 파이프라인 오케스트레이션(`app/core/analysis_engine.py`), 응답 스키마(`app/models/analysis.py`), LLM Q&A 서비스(`app/services/qa_service.py`)가 위치한다.
- `Backend/common/` – JSON 입출력(`file_utils.py`), 로깅 설정(`logging_utils.py`), 데이터클래스 모델(`models.py`) 등 파이프라인 전반에서 공유하는 헬퍼를 제공한다.
- `Backend/search_source/` – 컨테이너 이미지 tar 에서 `/app`, `/usr/src/app` 등의 경로를 탐색해 실제 애플리케이션 소스를 추출한다. `modules/extractor.py` 가 레이어 병합과 whiteout 처리까지 담당한다.
- `Backend/trivy_extracter/` – `trivy_module/trivy_func.py` 를 통해 Trivy CLI 를 호출하여 `trivy_analysis_result.json` 을 만든다. 선택적으로 `description_enhancer` 가 Anthropic API 로 CVE 설명을 보강한다.
- `Backend/python_api_extracter/` – Trivy 결과를 입력으로 패키지/버전별 CVE-API 매핑(`lib2cve2api.json`)을 만든다. 지정 버전 패키지를 임시 가상환경에 설치해 API 목록을 추출한다.
- `Backend/ast_visualizer/` – 애플리케이션 코드 베이스에서 호출 그래프를 생성하고, 필요하면 LLM 기반 보안 보고서를 만든다. 그래프 산출물은 `ast_visualize*` 접두사 파일로 저장된다.
- `Backend/cve_api_mapper/` – GPT-5, Claude, Gemini, Grok 등을 사용해 CVE → 실제 취약 API 연결 근거를 생성하고 결과/원본 로그를 `cve_api_mapper_results/`, `cve_api_mapper_raw/` 에 기록한다.
- `Backend/fetch_priority/` – AST, Trivy, CVE-API 매핑, EPSS API, Perplexity 검색 결과를 결합해 패치 우선순위(`fetch_priority.json`)를 산출한다.
- `Backend/DB/` – 각 분석별로 디렉터리를 생성하여 `Result.json`, `meta.json`, raw 산출물, 업로드 파일 사본을 저장한다. `uploads/` 는 업로드 임시 저장소, `legacy_root/` 는 과거 데이터 덤프이다.

## 3. Backend 핵심 로직 분석

### `Backend/app/main.py` – FastAPI 엔트리포인트

- **주요 함수**: `app = FastAPI(...)`, `/health` 핸들러, `app.include_router`.
- **로직**: 앱 객체를 초기화하고 `/health` 엔드포인트를 노출한 뒤 `routers/analyses.py`, `routers/analysis.py` 를 등록한다. 실제 비즈니스 로직은 개별 라우터에 위임한다.
- **환경 의존성**: FastAPI, `app.routers` 패키지.

### `Backend/app/core/analysis_engine.py` – 파이프라인 오케스트레이션

- **주요 클래스/함수**
  - `PipelineConfig` – 이미지 경로, DB 디렉터리, 소스 출력 경로, 플래그(`full_scan`, `enhance_trivy`, `run_security_analysis`, `enable_perplexity` 등)를 담는다.
  - `PipelineContext` – 소스 추출 단계에서 사용하는 입력 묶음.
  - `step_source_extraction`, `step_trivy_scan`, `step_python_api_mapping`, `step_ast_analysis`, `step_cve_api_mapper`, `step_fetch_priority` – 각 파이프라인 단계 래퍼.
  - `_build_vulnerability_summary`, `_build_vulnerabilities`, `_build_library_api_mappings`, `_build_patch_priority_list`, `_build_pipeline_response` – Raw 파일을 `AnalysisResult` 포맷으로 변환한다.
  - `run_pipeline`, `run_security_analysis` – CLI/HTTP 공용 엔트리포인트.
- **핵심 로직/데이터 흐름**
  1. `.env` 를 로드하고 `PipelineConfig` 기반으로 DB 하위 디렉터리(`Backend/DB/{analysis_id}`)를 준비한다. 입력 tar 가 디렉터리 밖에 있으면 사본을 만든다.
  2. `step_source_extraction` 은 `search_source.modules.extractor.extract_app_layer()` 를 호출하여 `/app`, `/usr/src/app` 등의 후보에서 소스를 추출하고 `output/` 폴더를 만든다.
  3. `step_trivy_scan` 은 Trivy CLI 를 호출하여 JSON 보고서를 생성한 뒤 필요하면 `trivy_extracter.main.enhance_descriptions()` 로 설명을 보강한다.
  4. `step_python_api_mapping` 은 `python_api_extracter.extracter.api_extracter.build_cve_api_mapping()` 으로 라이브러리→버전→CVE/API 구조를 만든다.
  5. `step_ast_analysis` 는 Graphviz 를 통해 호출 그래프(`ast_visualize_result.json`)와 선택적 LLM 보안 분석(`ast_visualize_security_analysis.json`)을 생성한다.
  6. `step_cve_api_mapper` 는 `CveApiMapper` 를 호출해 GPT-5 결과를 `cve_api_mapper_results/` 와 `gpt5_results.json` 에 기록한다.
  7. `step_fetch_priority` 는 `PatchPriorityEvaluator` 로 `fetch_priority.json` 을 만들고 Perplexity raw 응답을 `perplexity_raw_responses/` 에 작성한다.
  8. `_build_pipeline_response` 가 언어 감지(`_infer_primary_language`), 취약점 요약, 라이브러리/API 매핑, 패치 우선순위를 조립해 `Result.json`, `meta.json` 으로 기록하고 `raw_reports`, `artifacts` 메타데이터를 덧붙인다.
  9. FastAPI 진입점에서는 `run_security_analysis()` 가 UUID 를 생성해 `run_pipeline()` 을 호출하고, 응답에서 `result`/`meta`만을 API 모델로 반환한다.
- **외부 의존성**: 트리거되는 각 단계에 대해 Trivy CLI, Graphviz, Anthropic(OpenAI) API, Perplexity API, EPSS HTTP API, `search_source`, `python_api_extracter`, `ast_visualizer`, `cve_api_mapper`, `fetch_priority` 모듈이 모두 필요하다.

### `Backend/app/routers/analysis.py` – 기본 CRUD + Q&A 라우터

- **주요 함수**
  - `_save_upload()` – 업로드 파일을 `DB/uploads/` 로 스트리밍 저장.
  - `_load_analysis_from_disk()` – `Result.json`, `meta.json` 을 읽어 `AnalysisResponse` 로 역직렬화.
  - `run_analysis()` – `POST /analysis`, 업로드 검증 후 `run_security_analysis()` 호출.
  - `get_analysis_detail()` – `GET /analysis/{analysis_id}`.
  - `qa_analysis()` – `POST /analysis/{analysis_id}/qa`.
- **로직**
  - 업로드 시 MIME 타입을 `ALLOWED_CONTENT_TYPES` (tar, gzip, zip, octet-stream)로 제한하고, 저장 성공 후 파이프라인을 호출한다.
  - `_load_analysis_from_disk()` 는 디렉터리 존재 여부, JSON 파싱, Pydantic 검증을 수행하고 실패 시 404/500 예외를 던진다.
  - Q&A 엔드포인트는 저장된 메타/결과를 전부 불러와 `qa_service.run_qa()` 를 await 하고, LLM 실패 시 502 를 반환한다.
- **외부 의존성**: `fastapi.UploadFile`, Pydantic, `app.core.run_security_analysis`, `qa_service`.

### `Backend/app/routers/analyses.py` – 분석 목록 라우터

- **주요 함수**: `list_analyses()`.
- **로직**: `Backend/DB/` 를 순회하며 `uploads`, `legacy_root` 를 제외한 디렉터리의 `meta.json` 을 파싱한다. JSON 파싱/파일 읽기 실패 시 해당 항목을 건너뛰고 경고 로그를 출력한다. 마지막에 `created_at` 역순으로 정렬한다.
- **외부 의존성**: 파일 시스템 접근, `AnalysisMeta`.

### `Backend/app/models/analysis.py` – API 스키마

- **주요 클래스**
  - `VulnerabilitySummary`, `Vulnerability`, `LibraryApiMapping`, `PatchPriorityItem`.
  - `AnalysisResult`, `AnalysisMeta`, `AnalysisResponse`.
  - Q&A 관련 `AnalysisQARequest`, `AnalysisQAResponse`.
- **로직**: Pydantic 모델을 통해 API 응답 구조를 강제하고, 누락 필드를 기본값으로 채운다(`Field(default_factory=list)`).
- **외부 의존성**: Pydantic, `datetime`.

### `Backend/app/services/qa_service.py` – LLM Q&A 서비스

- **주요 함수**: `_get_client()`, `run_qa()`.
- **로직**
  - `.env` 를 로드하고 `AsyncOpenAI` 기반 클라이언트를 싱글턴으로 생성한다. `OPENAI_API_KEY` 없으면 즉시 예외를 던진다.
  - `run_qa()` 는 `meta` 와 `result` 전체를 JSON으로 묶어 사용자 질문과 함께 `SYSTEM_PROMPT`(한국어, “이 JSON만이 truth” 규칙 포함)를 전달한다.
  - 응답 텍스트에서 정규표현식(`CVE-\d{4}-\d+`)으로 `used_cves` 를 추출하고, 대문자 문자열 검사로 `risk_level` 키워드를 감지한다.
- **외부 의존성**: OpenAI Chat Completions API, `dotenv`, `re`, `json`.

## 4. 파이프라인 스크립트(루트 디렉토리) 분석

- `search_source/main.py` – CLI 인자를 받아 `modules/cli.run_cli()` 를 호출한다. `modules/extractor.ImageExtractor` 가 이미지를 임시 디렉터리에 풀고 `manifest.json` 의 레이어를 순차적으로 병합하며 whiteout 파일을 처리한다. 입력은 tar 파일, 출력은 추출된 소스 디렉터리이며 FastAPI 파이프라인에서는 `Backend/DB/{analysis_id}/output/` 로 사용된다.
- `trivy_extracter/main.py` – Trivy CLI 를 호출해 `trivy_analysis_result.json` 을 생성하고, `--enhance` 플래그 사용 시 `description_enhancer.DescriptionEnhancer` 로 CVE 설명을 Anthropic API 기반으로 재작성한다. `analysis_engine.step_trivy_scan()` 이 동일 모듈을 import 하여 사용한다.
- `python_api_extracter/main.py` – Trivy JSON 을 파싱해 패키지/버전별 CVE 목록을 만들고, `extracter/package_api_extractor.py` 가 임시 가상환경에서 해당 버전을 설치한 뒤 `extract_apis.py` 스크립트를 통해 모듈별 API 리스트를 덤프한다. 출력은 `lib2cve2api.json`.
- `ast_visualizer/main.py` – 지정된 디렉터리를 순회하며 Python 파일을 모두 분석하고 `ast_visualizer/utils/ast_to_png.py` 를 사용해 호출 그래프와 그래프 이미지, API 분류를 생성한다. `--security-analysis` 옵션 시 `utils/security_analyzer.py` 가 Anthropic API 로 고위험 API, 아키텍처 이슈 등을 JSON 으로 반환한다. FastAPI 파이프라인에서는 그래프 생성 여부(`emit_graph`), 보안 분석 여부(`run_security_analysis`)에 따라 출력 파일을 제어한다.
- `cve_api_mapper/mapper/cve_api_mapper.py` – `CveApiMapper` 는 GPT-5(OpenAI), Claude(Anthropic), Gemini(Google), Grok(X.AI) 각각에 대해 공통 프롬프트(`LLMClient.create_prompt`)로 CVE와 API 사이 근거를 요청한다. 응답 JSON 을 파싱해 모델별 결과 디렉터리에 저장하고, 파싱 실패 시 raw 응답을 그대로 남긴다. `analysis_engine.step_cve_api_mapper()` 는 결과 중 `gpt-5_results.json` 을 복사해 FastAPI 응답에 포함한다.
- `fetch_priority/module/evaluator.py` – `PatchPriorityEvaluator` 는 Trivy/AST/LLM 결과를 로드하고 EPSS API, Perplexity 사례 검색기(`perplexity_searcher.py`)를 통해 실사례 정보를 수집한다. 각 CVE 에 대해 API 사용 여부(`analyze_api_usage`), 외부 노출 여부, EPSS 점수, 사례 유무를 종합하여 `modules_by_priority` 리스트를 만들고, 이를 `fetch_priority.json` 으로 저장한다. `analysis_engine.step_fetch_priority()` 가 이 파일을 최종 Result 의 `patch_priority` 로 변환한다.

## 5. 데이터 포맷 및 계약(Contract) 정리

- `Result.json` 은 파이프라인의 요약본이며 각 필드가 다음 Raw 산출물에 의존한다.
  - `language`, `overview`: `output/` 디렉터리를 기반으로 `_infer_primary_language()` 와 `_build_overview()` 가 추론한다.
  - `vulnerabilities_summary`, `vulnerabilities[]`: `trivy_analysis_result.json` 의 `vulnerability_summary` 와 `vulnerabilities` 배열을 정규화한다.
  - `libraries_and_apis[]`: `lib2cve2api.json` 의 딕셔너리를 순회하면서 패키지/버전/모듈/API를 평탄화한다.
  - `patch_priority[]`: `fetch_priority.json` 의 `modules_by_priority` 항목을 `set_no`, `score`, `urgency` 필드로 재구성한다.
  - `logs`: 추후 파이프라인 단계별 메시지를 넣을 수 있도록 빈 배열로 남겨둔다.
- `meta.json` 은 `run_pipeline()` 에서 생성한 `analysis_id`, `created_at`, 입력 tar 파일명, `_build_vulnerability_summary()` 의 위험도(`overall_risk`)를 담는다.
- Raw 산출물 간 관계

```text
image.tar
 ├─ search_source → output/ (소스 스냅샷)
 ├─ trivy_extracter → trivy_analysis_result.json
 │    └─ python_api_extracter → lib2cve2api.json
 │          └─ cve_api_mapper → cve_api_mapper_results/, gpt5_results.json
 ├─ ast_visualizer → ast_visualize_result.json (+ security_analysis)
 └─ fetch_priority (inputs: ast_result, gpt5_results, lib2cve2api, trivy, Perplexity raw)
       └─ fetch_priority.json
```

이후 `_build_pipeline_response` 는 위 모든 파일을 다시 읽어 FastAPI 응답 스키마에 매핑하고, `artifacts`/`raw_reports` 필드에 각 파일 경로를 기록한다. Q&A 엔드포인트는 `meta`/`result` JSON 을 그대로 LLM 컨텍스트로 사용하므로 Result 포맷이 곧 LLM 컨트랙트이기도 하다.

## 6. LLM QA 설계 및 한계 분석

- **설계 요약**
  - `qa_service.run_qa()` 는 `AnalysisMeta` 와 `AnalysisResult` 전체를 `qa_context` 로 만들어 사용자 질문과 함께 시스템 프롬프트(`SYSTEM_PROMPT`)에 전달한다. 프롬프트는 “JSON에 없는 내용은 답하지 않는다”, “무관한 질문은 거절 문구로 대체한다”, “한국어로 간결하게 답한다” 등 강한 규칙을 포함한다.
  - 응답 검증은 간단한 텍스트 후처리로 이루어진다. 정규표현식으로 `used_cves` 를 추출하고, 대문자 키워드 스캔으로 `CRITICAL/HIGH/MEDIUM/LOW` 중 하나를 `risk_level` 로 기록한다.
  - FastAPI 레이어에서는 `_load_analysis_from_disk()` 결과를 재사용하므로 `Result.json` 이 곧 단일 소스이며 추가 데이터 조회가 없다.
- **장점**
  - 질문 분류나 컨텍스트 슬라이싱 없이 전체 결과를 모두 넘기므로 구현과 유지보수가 단순하다.
  - 시스템 프롬프트가 “JSON 만이 진실”이라고 못 박고 있어 LLM 할루시네이션을 줄일 수 있다.
  - `AnalysisQAResponse` 는 CVE ID 및 위험도 키워드를 자동 추출하므로 추가 인덱싱 없이도 UI 에 표시할 수 있다.
- **한계**
  - `Result.json` 이 커질수록 토큰 비용과 지연이 직선적으로 증가한다. 현재는 섹션 단위 필터링이나 압축이 없다.
  - `used_cves` 추출이 응답 텍스트 패턴에만 의존하므로, LLM 이 CVE 명을 언급하지 않으면 실제 컨텍스트를 사용했더라도 감지되지 않는다.
  - 질문이 애매하거나 Result 에 없는 내용을 요청할 때 시스템 프롬프트에 의존해 거절하는데, 특정 질문 패턴에서는 여전히 모호한 답을 줄 가능성이 있다.
- **향후 개선 아이디어**
  - 질문의 의도(파라미터 추출, 특정 패키지 질의 등)를 분류해 `result` 의 관련 섹션만 추출한 뒤 LLM 에 전달하는 retrieval 레이어를 추가한다.
  - CVE, 라이브러리, 패치 추천 리스트를 별도 벡터 인덱스로 생성해 LLM 이전 단계에서 근거를 축소한다.
  - 질문 유형이 무관할 때는 단순 거절 외에도 어떤 질문이 허용되는지 안내 메시지를 주는 UX 개선을 고려한다.

## 7. 종합 평가 및 개선 제안

- **강점**
  - `Backend/DB/{analysis_id}` 구조 덕분에 각 분석의 모든 산출물을 원자적으로 보관할 수 있고, 실험/운영 데이터를 분리하기 쉽다.
  - `AnalysisMeta`/`AnalysisResult` Pydantic 모델이 API 스키마를 명확히 규정해 FastAPI, QA, LLM 간 계약이 일관된다.
  - `analysis_engine` 이 기존 CLI 툴(`search_source`, `trivy_extracter` 등)을 모두 래핑하여 FastAPI 와 재사용 가능한 CLI(`Backend/main.py`)를 동시에 만족시킨다.
- **개선 여지**
  - `analysis_engine.py` 파일이 단계 정의, 데이터 빌드, 헬퍼를 모두 포함하고 있어 800+ 라인 규모의 단일 모듈이 되었다. 서브모듈로 분리하면 테스트와 유지보수가 쉬워진다.
  - 각 단계의 외부 의존성(Trivy, Graphviz, 다양한 LLM 키)이 `.env` 로만 관리되어 있으므로 구성 유효성 검사를 중앙화할 필요가 있다.
  - `analysis_router` 의 업로드 저장/삭제 정책이 없어 디스크가 빠르게 찰 수 있다. TTL이나 스토리지 정리를 위한 배치 작업이 필요하다.
  - 자동화 테스트가 거의 없어(폴더에 테스트는 `cve_api_mapper/test/` 정도뿐) 주요 경로를 회귀 테스트하기 어렵다.
  - Q&A, 패치 우선순위 단계가 모두 동기식 장시간 작업에 의존하므로 비동기 작업 큐(Celery/BackgroundTasks)를 고려할 필요가 있다.

**제안**

1. `analysis_engine` 을 `extract.py`, `scan.py`, `postprocess.py` 등 단계별 모듈로 분할하고 공통 I/O/에러 정책을 인터페이스화한다.
2. `app/config.py` 를 도입해 LLM/CLI 관련 환경 변수를 Pydantic Settings 로 검증하고, 부족한 키가 있을 때 FastAPI 부팅을 막는다.
3. `Result.json` 일부 섹션을 인덱싱하여 Q&A 에 전달하는 JSON 크기 제한 기능을 실험하고, LLM 호출 전에 질문 의도를 판단하는 라이트급 룰 베이스를 추가한다.
4. `Backend/DB/uploads` 및 `legacy_root` 정리를 위한 관리 커맨드를 추가하여 디스크 누수를 방지한다.
5. Trivy/LLM 등 외부 호출을 `asyncio.to_thread` 나 작업 큐로 오프로딩하여 API 응답 시간을 줄이고 재시도/타임아웃 정책을 명시한다.
