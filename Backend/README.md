# System Security Backend

Backend 서비스는 Docker 이미지(`.tar`)를 업로드 받으면 전체 취약점 분석 파이프라인을 실행하고, 결과를 구조화된 JSON(`Result.json`, `meta.json`)으로 저장한 뒤 FastAPI를 통해 분석 이력 조회 및 LLM 기반 Q&A 기능을 제공합니다. 핵심 스택은 **Python**, **FastAPI**, **Pydantic**, **Trivy**, **Graphviz**, **OpenAI/Anthropic/Perplexity** 등으로 구성되어 있습니다.

- `POST /analysis` – 압축된 이미지 아카이브를 받아 파이프라인 실행
- `GET /analyses`, `GET /analysis/{analysis_id}` – 저장된 분석 이력/결과 조회
- `POST /analysis/{analysis_id}/qa` – 저장된 결과를 컨텍스트로 LLM Q&A 제공

---

## Architecture & Flow

파이프라인의 엔트리포인트는 `app/core/analysis_engine.py` 의 `run_security_analysis()` / `run_pipeline()` 입니다. 주요 단계는 아래와 같습니다.

1. **업로드 저장**
   - `POST /analysis` 는 업로드된 tar 를 `Backend/DB/uploads/` 에 저장 (`routers/analysis.py::_save_upload`).
   - UUID 기반 `analysis_id` 를 생성하고 `Backend/DB/{analysis_id}/` 디렉터리를 마련합니다.
2. **소스 추출 (`search_source/`)**
   - `step_source_extraction` 이 `search_source.modules.extractor.extract_app_layer()` 를 호출해 이미지 레이어를 병합하고 `/app`, `/usr/src/app` 등에서 애플리케이션 소스를 추출하여 `<analysis_id>/output/` 에 복사합니다.
3. **Trivy 스캔 (`trivy_extracter/`)**
   - `step_trivy_scan` 이 `trivy_extracter.trivy_module.trivy_func.scan_vulnerabilities()` 를 호출해 라이브러리 취약점 JSON (`trivy_analysis_result.json`) 을 생성하고 필요 시 `enhance_descriptions()` 로 LLM 요약을 덧붙입니다.
4. **라이브러리 → CVE → API 매핑 (`python_api_extracter/`)**
   - `step_python_api_mapping` 이 `python_api_extracter.extracter.api_extracter.build_cve_api_mapping()` 으로 `lib2cve2api.json` 을 생성합니다. 이 단계는 패키지 버전을 임시 가상환경에 설치해 모듈/API 목록을 덤프합니다.
5. **AST 호출 그래프 분석 (`ast_visualizer/`)**
   - `step_ast_analysis` 이 `ast_visualizer.utils.ast_to_png.visualize_call_flow()` 를 실행하여 `ast_visualize_result.json` 과 필요 시 Graphviz 파일, LLM 기반 보안 분석(`ast_visualize_security_analysis.json`)을 만듭니다.
6. **CVE ↔ API 상관관계 확장 (`cve_api_mapper/`)**
   - `step_cve_api_mapper` 가 `CveApiMapper` 를 호출하여 GPT-5 기반 CVE-API 근거(`cve_api_mapper_results/gpt-5_results.json`)와 원본 응답(`cve_api_mapper_raw/`)을 남기고 요약본을 `gpt5_results.json` 으로 복사합니다.
7. **패치 우선순위 산출 (`fetch_priority/`)**
   - `step_fetch_priority` 가 `fetch_priority.module.PatchPriorityEvaluator` 를 통해 AST/Trivy/LLM 산출물과 Perplexity 사례를 결합해 `fetch_priority.json` 을 생성합니다.
8. **Result/meta 생성 및 저장**
   - `_build_pipeline_response()` 가 상기 산출물을 요약해 `AnalysisResult`, `AnalysisMeta` 스키마에 맞게 구성하고 `Result.json`, `meta.json` 을 기록한 뒤 JSON 응답을 FastAPI 로 되돌립니다.

FastAPI 의 `analysis_router` 는 `_load_analysis_from_disk()` 를 통해 저장된 artefact 를 다시 읽어 `AnalysisResponse` 로 직렬화하며, Q&A 요청 시 `app/services/qa_service.py::run_qa()` 를 호출해 결과와 질문을 OpenAI Chat Completions API 에 전달합니다.

---

## DB Directory Layout

샘플 (`Backend/DB/1d74c1e038ff432aa0d3b24755d7b58a/`) 기준 구조입니다.

```text
Backend/DB/
├── {analysis_id}/
│   ├── Result.json                  # AnalysisResult 직렬화
│   ├── meta.json                    # AnalysisMeta 직렬화
│   ├── pyyaml-vuln.tar              # 업로드 아카이브 사본
│   ├── trivy_analysis_result.json   # Trivy 정제 결과
│   ├── lib2cve2api.json             # 라이브러리→CVE→API 매핑
│   ├── ast_visualize_result.json    # AST 호출 그래프 요약
│   ├── ast_visualize_security_analysis.json?  # (옵션) LLM 기반 AST 보안 분석
│   ├── gpt5_results.json            # GPT-5 CVE-API 매핑 요약본
│   ├── fetch_priority.json          # PatchPriorityEvaluator 출력
│   ├── fetch_prioiriy_raw_response.json # 패치 우선순위 LLM raw 스냅샷
│   ├── cve_api_mapper_results/
│   │   └── gpt-5_results.json       # 모델별 정밀 결과 & 비교 리포트
│   ├── cve_api_mapper_raw/
│   │   └── gpt-5_raw_responses.json # GPT-5 원본 응답
│   ├── perplexity_raw_responses/    # 실제 공격 사례 검색 raw 결과
│   ├── output/                      # 추출된 애플리케이션 소스 스냅샷
│   └── ast_visualize*               # Graphviz/PNG 출력물 접두사
├── uploads/                         # FastAPI 업로드 임시 보관소
└── legacy_root/                     # 이전 CLI/테스트 산출물 보관
```

- `legacy_root/` 는 히스토리 보존용 루트이며 `_root` 접미사의 디렉터리들(`cve_api_mapper_results_root`, `perplexity_raw_responses_root` 등)이 한꺼번에 남아 있습니다.
- API 서버는 `{analysis_id}` 내부의 `Result.json`, `meta.json` 만을 사용하지만 Raw 파일은 디버깅/후처리 용도로 유지됩니다.

---
## 저장소 암호화 옵션

- 파일 기반 산출물(`Result.json`, `meta.json`, `trivy_analysis_result.json` 등)을 AES-GCM 으로 암호화하려면 환경변수 `DB_ENCRYPTION=1` 을 설정합니다.
- 키는 `DB_ENCRYPTION_KEY`(base64 인코딩) 또는 `DB_ENCRYPTION_KEY_PATH`(16/24/32바이트 바이너리 키 파일 경로) 중 하나로 제공합니다.
- 암호화가 활성화되면 `common.file_utils.write_json/read_json` 이 자동으로 암·복호화를 적용하므로 파이프라인 코드 변경 없이 저장소 보호가 가능합니다.

---
## Result.json & meta.json Schema

`app/models/analysis.py` 의 Pydantic 모델과 샘플 산출물은 아래 구조를 따릅니다.

### `AnalysisMeta` (`meta.json`)

| 필드 | 타입 | 설명 |
| --- | --- | --- |
| `analysis_id` | `str` | UUID v4 기반 ID (디렉터리명과 동일) |
| `file_name` | `str` | 업로드한 tar 파일명 |
| `image_path` | `str` | `Backend/DB/{analysis_id}/` 내 tar 절대 경로 |
| `created_at` | `datetime` | UTC ISO8601 (`run_pipeline` 시각) |
| `risk_level` | `Literal["CRITICAL","HIGH","MEDIUM","LOW"]` | `_build_vulnerability_summary()` 산출 위험도 |

### `AnalysisResult` (`Result.json`)

- `language`: `_infer_primary_language()` 가 추출한 언어 (현재 Python/Unknown).
- `overview`: 탐지된 취약점 집계/위험도를 자연어 요약.
- `vulnerabilities_summary`: `critical/high/medium/low/overall_risk` 카운트.
- `vulnerabilities[]`: 각 항목은 `{cve_id, package, version, severity, description, direct_call, call_example}`.
- `libraries_and_apis[]`: 라이브러리별 `{package, version, module, api, related_cves[]}`.
- `patch_priority[]`: `fetch_priority.json` 기반 `{set_no, package, current_version, recommended_version, score, urgency, note}`.
- `logs[]`: 현재 비어 있으나 추후 파이프라인 메시지를 추가할 수 있도록 예약됨.

FastAPI 응답 스키마 `AnalysisResponse` 는 `{ meta: AnalysisMeta, result: AnalysisResult }` 구조이며, Q&A 응답(`AnalysisQAResponse`)은 `{analysis_id, question, answer, used_cves[], risk_level?}` 를 반환합니다.

---

## API Endpoints

### `POST /analysis`

- **Purpose**: Docker 이미지 tar/zip/gzip (`multipart/form-data` field 이름 `file`) 업로드 및 전체 파이프라인 실행.
- **Request Example**

```bash
curl -X POST http://localhost:8000/analysis \
  -H "accept: application/json" \
  -F "file=@/path/to/pyyaml-vuln.tar;type=application/x-tar"
```

- **Response**: `AnalysisResponse` (meta/result). 업로드/파이프라인 실패 시 400/500 에러 메시지를 반환합니다.

### `GET /analyses`

- **Purpose**: `Backend/DB/` 하위 분석 결과 목록을 조회.
- `app/routers/analyses.py` 가 `meta.json` 만 읽어 `AnalysisMeta` 리스트를 생성하고 `created_at` 역순으로 정렬합니다.
- **Response**: `List[AnalysisMeta]`. `uploads`, `legacy_root` 는 스킵됩니다.

### `GET /analysis/{analysis_id}`

- **Purpose**: 단일 분석 결과 반환.
- `_load_analysis_from_disk()` 가 `{analysis_id}/Result.json`, `meta.json` 을 읽고 Pydantic 검증 후 `AnalysisResponse` 를 리턴합니다.
- Artefact 누락 시 404, JSON 파싱 실패 시 500을 발생시킵니다.

### `POST /analysis/{analysis_id}/qa`

- **Purpose**: 저장된 메타+결과를 그대로 LLM 컨텍스트로 전달해 한국어 Q&A 실행.
- **Request Body** (`AnalysisQARequest`):

```json
{ "question": "이 이미지에서 가장 위험한 취약점은?" }
```

- 내부 동작: `_load_analysis_from_disk()` → `qa_service.run_qa(meta, result, question)` → OpenAI `chat.completions.create` 호출. `SYSTEM_PROMPT` 는 “Result.json 만이 truth” 라는 가드레일을 강제하며, 응답을 정규식으로 스캔해 `used_cves[]` 와 `risk_level` 키워드를 추출합니다.
- **Response Example**

```bash
curl -X POST http://localhost:8000/analysis/{analysis_id}/qa \
  -H "Content-Type: application/json" \
  -d '{"question":"최우선으로 패치해야 할 패키지는?"}'
```

```json
{
  "analysis_id": "ae36e75a0eb147838c4db562df173933",
  "question": "...",
  "answer": "이 이미지에서 ...",
  "used_cves": ["CVE-2020-14343"],
  "risk_level": "CRITICAL"
}
```

### 기타

- `GET /health` 및 `GET /analysis/ping` 은 오케스트레이션/헬스체크 용도로 단순 문자열을 반환합니다.

---

## How to Run

1. 의존성 설치

```bash
cd Backend
pip install -r ../requirements.txt
```

2. 필수 바이너리
   - [Trivy](https://aquasecurity.github.io/trivy) CLI (파이프라인에서 `trivy image` 명령을 직접 호출)
   - Graphviz (`dot`) – AST 시각화 PNG 출력을 활성화하려면 필요

3. 환경 변수 / `.env`
   - `Backend/.env` (또는 동일 키를 셸에 export)
     - `OPENAI_API_KEY`, `LLM_QA_MODEL`(옵션) – Q&A (`qa_service`)에서 사용
     - `ANTHROPIC_API_KEY` – Trivy 설명 향상, AST 보안 분석, 패치 우선순위 평가기에 필수
     - `PERPLEXITY_API_KEY` – 실제 공격 사례 검색 활성화 시 필요
     - `GOOGLE_API_KEY`, `XAI_API_KEY` – `cve_api_mapper` 가 여러 모델을 호출할 때 필요
4. 개발 서버 실행

```bash
cd Backend
uvicorn app.main:app --reload
```

5. 테스트 이미지 업로드: `curl` 예시를 이용하거나 `run_pipeline_snippet.py` 로 CLI 파이프라인을 실행할 수 있습니다.

---

## Future Work / TODO

- **Legacy DB 정리**: `Backend/DB/legacy_root/` 및 `_root` 접미사 디렉터리를 마이그레이션하거나 정리해 저장소 용량과 혼동을 줄여야 합니다.
- **구성/서비스 모듈화**: 현재 `analysis_engine` 에 집중된 설정을 `app/config.py`, `app/services/` 하위 클래스로 분리하여 의존성 주입/테스트 용이성을 높입니다.
- **LLM 컨텍스트 최적화**: Q&A 는 전체 `Result.json` 을 그대로 전송하므로 토큰이 빠르게 증가합니다. 질문 의도 파악 후 관련 섹션만 추출하는 retrieval 계층을 추가하는 것이 좋습니다.
- **타입/검증 보강**: `fetch_prioiriy_raw_response.json` 처럼 오타 난 파일명이나 optional artefact 이름을 Enum/데이터클래스로 통일하면 관리가 쉬워집니다.
- **에러 감시**: 외부 CLI/LLM 호출 실패 시 재시도 및 상태 메트릭을 추가해 운영 시그널을 확보합니다.
