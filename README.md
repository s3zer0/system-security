# system-security
25-2 고려대학교 세종캠퍼스 시스템보안 4조

## 프로젝트 구조

### test_target/
PyYAML CVE-2020-1747 취약점 테스트용 Docker 컨테이너

### python_api_extracter/
Trivy 스캔 결과에서 CVE와 API 매핑을 추출하는 도구

```
python_api_extracter/
├── main.py                              # 메인 진입점
├── extracter/                           # 핵심 모듈들
│   ├── __init__.py                      # 패키지 초기화
│   ├── api_extracter.py                 # 통합 API
│   ├── trivy_parser.py                  # Trivy 보고서 파싱
│   ├── package_api_extractor.py         # 패키지 API 추출
│   └── config.py                        # 설정 관리
└── scripts/                             # 유틸리티 스크립트들
    ├── extract_apis.py                  # API 추출 스크립트
    └── detect_modules.py                # 모듈 탐지 스크립트
```

### DB/
분석 결과 저장소
- `trivy_analysis_result.json`: Trivy 스캔 결과
- `lib2cve2api.json`: CVE-API 매핑 결과

## 사용 방법

### 1. Docker 이미지 빌드 및 스캔

```bash
# Docker 이미지 빌드
cd test_target
docker build -t pyyaml-vuln .

# Docker 이미지를 tar 파일로 저장
docker save -o pyyaml-vuln.tar pyyaml-vuln

# Trivy로 스캔 (별도 실행 필요)
```

### 2. API 추출 도구 사용

```bash
cd python_api_extracter

# Trivy 결과에서 CVE-API 매핑 생성
python3 main.py ../DB/trivy_analysis_result.json -o ../DB/lib2cve2api.json

# 또는 표준 출력으로 결과 확인
python3 main.py ../DB/trivy_analysis_result.json
```

## 주요 기능

### python_api_extracter
- **CVE 매핑**: Trivy 결과에서 Python 패키지별 CVE 추출
- **API 추출**: 각 패키지 버전별 공개 API 목록 생성
- **통합 매핑**: CVE와 API 정보를 결합한 JSON 출력
- **모듈식 설계**: 확장 가능한 구조로 개별 모듈 재사용 가능

### 지원 형식
- **입력**: Trivy JSON 보고서 (표준/사용자 정의 형식)
- **출력**: JSON 형식의 CVE-API 매핑

## 주요 취약점
- **CVE-2020-1747**: PyYAML 5.3.1의 yaml.load() 취약점
- **External APIs**: 5개의 Flask 엔드포인트
- **Internal APIs**: 내부 yaml.load() 호출들