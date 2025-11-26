# 1. 베이스 이미지 변경 (Python 3.8 사용)
FROM python:3.8-slim

WORKDIR /app

# 2. [적당한 수준의 취약점 라이브러리 4개]
# 너무 많지 않게, 하지만 확실한 CVE가 잡히는 버전들입니다.

# - sqlparse 0.4.1 : ReDoS (정규표현식 서비스 거부 공격) 취약점
# - lxml 4.6.2     : XML XXE (외부 엔티티 주입) 취약점
# - httplib2 0.19.0: CRLF Injection (헤더 주입) 취약점
# - PyYAML 5.4     : 이전(5.3.1)과 다른 버전의 역직렬화 취약점 확인용

RUN pip install --no-cache-dir \
    sqlparse==0.4.1 \
    lxml==4.6.2 \
    httplib2==0.19.0 \
    PyYAML==5.4

# 3. 더미 실행 파일 생성
RUN echo "import sqlparse, lxml, httplib2; print('Lightweight Vuln App')" > main.py

CMD ["python", "main.py"]