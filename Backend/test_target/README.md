# PyYAML 취약점 테스트 컨테이너

간단한 PyYAML CVE-2020-1747 취약점 테스트용 Docker 컨테이너

## 구조

```
new_target_app/
├── Dockerfile
├── requirements.txt
├── app/
│   ├── __init__.py
│   ├── main.py              # 메인 엔트리포인트
│   ├── server.py            # Flask 서버 (취약한 YAML 엔드포인트)
│   └── yaml_service.py      # YAML 처리 서비스
└── tests/
    └── test_yaml.py         # 테스트 코드
```

## 빌드 및 실행

```bash
# Docker 이미지 빌드
docker build -t pyyaml-vuln .

# 컨테이너 실행
docker run -p 5000:5000 pyyaml-vuln

# tar 파일로 저장 (Trivy 스캔용)
docker save pyyaml-vuln -o pyyaml-vuln.tar
```

## Container CVE Tracker 분석

```bash
python main.py pyyaml-vuln.tar
```

## 포함된 취약점

- **CVE-2020-1747**: PyYAML 5.3.1의 yaml.load() 취약점
- **External APIs**: 5개의 Flask 엔드포인트
- **Internal APIs**: 내부 yaml.load() 호출들
- **Unused APIs**: 사용되지 않는 취약한 함수들