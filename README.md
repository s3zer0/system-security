# System Security Project

컨테이너 이미지를 하나 입력받아 소스 추출 → 취약점 스캔 → 라이브러리 API/CVE 매핑 → AST 분석 → LLM 기반 CVE 매핑 → 패치 우선순위 산정까지 자동화하는 보안 파이프라인입니다. FastAPI 백엔드·CLI 모두 `main.py`를 통해 전체 실행이 가능하며, 각 단계는 독립 실행도 지원합니다.

## 요구사항
- Python 3.10+
- Docker, Trivy (필수), Graphviz
- `pip install -r requirements.txt`
- LLM 기능 사용 시 `.env`에 필요한 키 설정(`cp .env.example .env`, 필요한 키만 채워도 됨)

## 설정 & 샘플 이미지 준비
```bash
pip install -r requirements.txt
cp .env.example .env
cd test_target
docker build -t pyyaml-vuln .
docker save -o pyyaml-vuln.tar pyyaml-vuln
cd ..
```

## 실행 예시
```bash
python main.py --image test_target/pyyaml-vuln.tar --run-security-analysis --emit-graph
```
- 산출물은 기본적으로 `DB/` 하위에 저장됩니다.
- 기존 산출물이 있을 경우 `--force`로 재실행합니다.
- 공통 옵션은 `python main.py --help`에서 확인하세요.

## 리포지토리 구조
```
├── main.py                # 전체 파이프라인 오케스트레이터
├── Backend/
│   ├── app/               # FastAPI 엔트리포인트, 라우터, QA 서비스
│   ├── common/            # 로깅/파일 IO/공용 모델
│   ├── DB/                # 분석별 산출물 저장소
│   ├── search_source/     # 컨테이너 레이어에서 소스 추출
│   ├── trivy_extracter/   # Trivy 스캔 및 취약점 설명 보강
│   ├── python_api_extracter/ # 라이브러리 → CVE → API 매핑 생성
│   ├── ast_visualizer/    # 호출 그래프 생성 및 LLM 보안 분석
│   ├── cve_api_mapper/    # 여러 LLM 기반 CVE-API 매핑 비교
│   └── fetch_priority/    # 패치 우선순위 계산
├── Frontend/              # UI (기존 스타일 유지, agentic 플래그용 확장 예정)
├── docs/                  # 구현/설계 문서
└── test_target/           # 샘플 취약 이미지(Dockerfile 포함)
```

## 파이프라인 단계(상세)
1. **Source extraction** – `search_source`가 컨테이너 레이어를 병합하며 whiteout을 처리하고 `/app`, `/usr/src/app` 등에서 애플리케이션 소스를 `DB/{analysis_id}/output/`에 추출합니다.
2. **Vulnerability scan** – `trivy_extracter`가 Trivy CLI로 `trivy_analysis_result.json`을 생성하고, 옵션에 따라 Anthropic LLM으로 CVE 설명을 보강합니다.
3. **Library API mapping** – `python_api_extracter`가 Trivy 결과를 입력으로 패키지/버전별 CVE-API 매핑(`lib2cve2api.json`)을 만들며, 임시 가상환경에서 해당 버전을 설치해 공개 API 목록을 추출합니다.
4. **AST & security analysis** – `ast_visualizer`가 호출 그래프(`ast_visualize_result.json`), 내부/외부 API 분류, 선택적 LLM 보안 리포트(`ast_visualize_security_analysis.json`)를 생성합니다.
5. **CVE ↔ API mapping (LLM)** – `cve_api_mapper`가 GPT‑5, Claude, Gemini, Grok 등을 동일 프롬프트로 호출해 CVE-API 근거를 비교하며 `cve_api_mapper_results/`, `gpt5_results.json` 등을 저장합니다.
6. **Patch priority** – `fetch_priority`가 AST/Trivy/LLM/EPSS/Perplexity 결과를 통합해 모듈별 패치 우선순위와 사례 기반 근거를 `fetch_priority.json`으로 출력합니다.
7. **Pipeline response build** – `_build_pipeline_response`가 언어/개요 추론, 취약점 요약, 라이브러리/API 매핑, 패치 우선순위를 조립해 `Result.json`, `meta.json`을 생성하고 원본 산출물 경로를 `artifacts`/`raw_reports`에 기록합니다.

## FastAPI 백엔드 개요
- 엔트리포인트: `Backend/app/main.py` (FastAPI 초기화, `/health`, 라우터 등록)
- 라우터: `routers/analysis.py`(업로드·단건 조회·QA), `routers/analyses.py`(목록)
- 핵심 엔진: `app/core/analysis_engine.py`
  - `PipelineConfig/PipelineContext` 준비 → 단계별 실행 래퍼(`step_source_extraction`, `step_trivy_scan`, `step_python_api_mapping`, `step_ast_analysis`, `step_cve_api_mapper`, `step_fetch_priority`) → `_build_*` 헬퍼로 API 응답 변환 → `run_security_analysis()`에서 UUID 생성 후 전체 파이프라인 호출
- 데이터 계약: `app/models/analysis.py`가 `AnalysisResult`, `AnalysisMeta`, `AnalysisResponse`를 정의해 API/LLM 모두 동일 스키마 사용
- QA 서비스: `app/services/qa_service.py`가 `meta`+`result` 전체를 LLM 컨텍스트로 사용하며, 응답에서 CVE ID(`used_cves`)와 위험도 키워드를 추출

## 산출물 & 디렉터리 계약
```
image.tar
 ├─ search_source → output/                      # 소스 스냅샷
 ├─ trivy_extracter → trivy_analysis_result.json
 │    └─ python_api_extracter → lib2cve2api.json
 │          └─ cve_api_mapper → cve_api_mapper_results/, gpt5_results.json
 ├─ ast_visualizer → ast_visualize_result.json (+ security_analysis)
 └─ fetch_priority (입력: ast, gpt5, lib2cve2api, trivy, Perplexity)
       └─ fetch_priority.json
```
- `_build_pipeline_response`는 위 파일을 재조합해 `Result.json`/`meta.json`을 생성하고, `Backend/DB/{analysis_id}`에 저장합니다.
- `Backend/DB/uploads`는 업로드 임시 보관소, `legacy_root`는 과거 데이터 덤프입니다.

## Killchain 감지
- 구현: `Backend/app/core/killchain_detector.py`
- 데이터: Dockerfile의 EXPOSE/USER/ENV/VOLUME, Trivy 결과의 네트워크 RCE CVE, 선택적 런타임 스냅샷(`sources_dir/runtime/netstat.txt`, `ss.txt`, `ps.txt`)
- 규칙: **원격 RCE → 컨테이너 탈취**, **탈취 후 시크릿/호스트 확장** 경로를 생성하고 MITRE ATT&CK ID를 함께 기록합니다. Dockerfile에 없지만 런타임에 열린 포트도 근거로 포함합니다.
- 결과: `killchains[]`에 `rule_id`, `severity`, `evidences`, `attack_mappings`가 포함되므로 UI/소비자는 근거를 즉시 노출할 수 있습니다.
- 설계 가이드: 룰/그래프 모델링, 입력 체크리스트는 `docs/killcahin_pipeline.md` 참고.

## LLM Q&A 동작 요약
- 프롬프트는 “`Result.json`/`meta.json`만이 truth, 없으면 답하지 않음”을 강제하며 한국어 간결 응답을 요구합니다.
- 응답 텍스트에서 정규표현식으로 CVE ID를 추출(`used_cves`), 대문자 키워드로 위험도(`CRITICAL/HIGH/...`)를 감지합니다.
- 컨텍스트 축소 없이 전체 결과를 전달하므로 대용량 시 토큰 비용·지연이 증가할 수 있습니다.

## Agentic 확장 로드맵 (update.md 발췌)
- 목표: 기존 계약을 깨지 않고 Docker 중심 분석을 agentic 루프(Plan → Guard → Execute → Collect → Report)로 확장. 기본은 **비활성** 플래그 뒤에 배치.
- 핵심 컴포넌트 제안: planner/guard/executor/state store/registry/adapters, Docker 툴 스텁(inspect/scan/lint/SBOM), 모의 실행 모드, 구조화된 로그·trace ID.
- 가드레일: 이미지 참조 검증, 금지 레지스트리 차단, 입력/스텝 수 제한, 샌드박스 실행 원칙.
- 프론트엔드: 새 플래그 `AGENTIC_UI_ENABLED` 아래 실행 이력/세부 페이지, 스텝 타임라인, 가드 배너, 툴 출력 탭, SBOM 다운로드 링크 추가(기존 UX 유지).
- 테스트/롤아웃: planner/guard/executor/adapters 단위 테스트, 모의 툴 스모크 테스트, 스토리지/TTL 관리, 플래그 온/오프 롤백 전략.

## 문서
- 코드 리딩 및 파이프라인 상세: `docs/system_security_code_report.md`
- 킬체인 감지 설계: `docs/killcahin_pipeline.md`
- Agentic 확장 가이드: `update.md`

## 라이선스
MIT
