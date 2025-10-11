# System Security Project

컨테이너 이미지 하나를 입력으로 받아 소스 추출부터 취약점 스캔, 라이브러리 API 정리, AST 분석, LLM 기반 CVE 매핑, 패치 우선순위 산정까지 이어지는 보안 파이프라인입니다. 각 단계는 독립 실행이 가능하지만 `main.py`를 통해 한 번에 수행할 수도 있습니다.

## Repository Layout
```
├── main.py              # 전체 파이프라인 오케스트레이터
├── search_source/       # 컨테이너 레이어에서 애플리케이션 소스 추출
├── trivy_extracter/     # Trivy 스캔 및 취약점 설명 보강
├── python_api_extracter/# 라이브러리 → CVE → API 매핑 생성
├── ast_visualizer/      # 호출 그래프 생성 및 보안 분석
├── cve_api_mapper/      # 여러 LLM을 통한 CVE-API 매핑 비교
├── fetch_priority/      # 패치 우선순위 계산
├── DB/                  # 파이프라인 산출물 저장소
└── test_target/         # 샘플 취약 이미지(Dockerfile 포함)
```

## Requirements
- Python 3.10 이상
- Docker, Trivy
- `pip install -r requirements.txt`
- LLM 기능을 사용하려면 `.env`에 필요한 API 키를 추가하세요 (`cp .env.example .env`).

## Setup
```bash
pip install -r requirements.txt
cp .env.example .env  # 필요한 키만 채워도 됩니다.
cd test_target
docker build -t pyyaml-vuln .
docker save -o pyyaml-vuln.tar pyyaml-vuln
cd ..
```

## Quick Start
```bash
python main.py --image test_target/pyyaml-vuln.tar --run-security-analysis --emit-graph
```
- 기본 출력은 `DB/` 아래에 저장됩니다.
- 이미 산출물이 있다면 `--force`로 재실행할 수 있습니다.
- 공통 실행 옵션은 `python main.py --help`로 확인하세요.

## Pipeline at a Glance
1. **Source extraction** – `PipelineContext`에 모은 설정으로 `search_source`를 호출해 애플리케이션 소스를 `DB/output/`에 복사합니다.
2. **Vulnerability scan** – `trivy_extracter`가 컨테이너를 분석하고, 필요 시 LLM으로 취약점 설명을 보강합니다.
3. **Library API mapping** – `python_api_extracter`가 Trivy 결과를 기반으로 라이브러리별 CVE/공개 API 매핑을 생성하며 `progress_callback`으로 진행 상황을 알립니다.
4. **AST & security analysis** – `ast_visualizer`가 호출 그래프, 내부/외부 API 분류, 선택적 LLM 보안 리포트를 생성합니다.
5. **CVE ↔ API mapping (LLM)** – `cve_api_mapper`가 GPT‑5 등 여러 모델을 비교 실행해 결과를 `DB/gpt5_results.json` 등에 저장합니다.
6. **Patch priority** – `fetch_priority`가 AST/Trivy/LLM 결과를 모아 패치 우선순위와 권장 조치를 `DB/fetch_priority.json`으로 출력합니다.

## Documentation
자세한 단계별 설명과 산출물 구조, 모듈별 CLI 예시는 [report.md](report.md)에서 확인할 수 있습니다.

## License
MIT
