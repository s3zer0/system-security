# system-security
25-2 고려대학교 세종캠퍼스 시스템보안 4조

## 프로젝트 구조

### test_target/
PyYAML CVE-2020-1747 취약점 테스트용 Docker 컨테이너

## 빌드 및 실행 방법

1. **Docker 이미지 빌드**
   ```bash
   cd test_target
   docker build -t pyyaml-vuln .
   ```

2. **Docker 이미지를 tar 파일로 저장**
   ```bash
   docker save -o test_target/pyyaml-vuln.tar pyyaml-vuln
   ```

## 주요 취약점
- **CVE-2020-1747**: PyYAML 5.3.1의 yaml.load() 취약점
- **External APIs**: 5개의 Flask 엔드포인트
- **Internal APIs**: 내부 yaml.load() 호출들
- **Unused APIs**: 사용되지 않는 취약한 함수들