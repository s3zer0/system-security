# System Security Project

## 1\. 프로젝트 개요

이 프로젝트는 **컨테이너 이미지의 취약점을 분석**하고, 발견된 **CVE(Common Vulnerabilities and Exposures)가 소스 코드의 어떤 API와 관련**이 있는지 자동으로 매핑해주는 시스템입니다.

## 2\. 프로젝트 구조

```
/
├── trivy_extracter/ # Trivy를 이용한 컨테이너 취약점 스캔 및 결과 정제
├── python_api_extracter/ # Python 라이브러리의 API 목록 추출
├── cve_api_mapper/ # LLM을 이용해 CVE와 API를 매핑
├── test_target/ # 취약점 분석을 위한 테스트용 Docker 컨테이너
└── DB/ # 분석 결과 데이터베이스
```

## 3\. 시스템 워크플로우

1.  **컨테이너 이미지 스캔 (Trivy)**: `trivy_extracter`가 Docker 이미지를 스캔하여 `trivy_analysis_result.json`에 취약점 정보를 저장합니다.
2.  **API 목록 추출**: `python_api_extracter`가 스캔된 라이브러리들의 공개 API를 추출하여 `lib2cve2api.json`에 저장합니다.
3.  **CVE-API 매핑 (LLM)**: `cve_api_mapper`가 `trivy_analysis_result.json`의 CVE 설명과 `lib2cve2api.json`의 API 목록을 기반으로, LLM(GPT-4)을 통해 어떤 API가 각 CVE에 해당하는지 분석하고 `gpt5_results.json`에 저장합니다.

## 4\. 사용 방법

### 4.1. 환경 설정

  - **API 키 설정**: `.env.example` 파일을 `.env`로 복사하고, 사용하는 LLM의 API 키를 입력합니다.

### 4.2. 실행

1.  **테스트용 Docker 이미지 빌드 및 저장**:

    ```bash
    cd test_target
    docker build -t pyyaml-vuln .
    docker save -o pyyaml-vuln.tar pyyaml-vuln
    cd ..
    ```

2.  **Trivy 취약점 스캔**:

    ```bash
    cd trivy_extracter
    python main.py ../test_target/pyyaml-vuln.tar ../DB/trivy_analysis_result.json
    cd ..
    ```

3.  **라이브러리 API 추출**:

    ```bash
    cd python_api_extracter
    python main.py ../DB/trivy_analysis_result.json -o ../DB/lib2cve2api.json
    cd ..
    ```

4.  **CVE-API 매핑**:

    ```bash
    cd cve_api_mapper
    python main.py
    cd ..
    ```

## 5\. 주요 기능

  - **자동화된 취약점 분석**: Trivy를 통해 컨테이너 이미지의 취약점을 자동으로 스캔하고, 결과를 정제합니다.
  - **정확한 API 추출**: 각 라이브러리 버전별로 실제 사용 가능한 공개 API 목록을 동적으로 추출합니다.
  - **지능적인 CVE-API 매핑**: 최신 언어 모델(LLM)을 활용하여 CVE의 자연어 설명과 API 명세를 분석, 연관 관계를 추론합니다.

## 6\. 라이선스

이 프로젝트는 MIT 라이선스를 따릅니다.