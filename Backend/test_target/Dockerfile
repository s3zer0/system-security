# 간단한 PyYAML 취약점 테스트 컨테이너
FROM python:3.9-slim

WORKDIR /app

# 취약한 PyYAML 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Python 코드 복사
COPY app/ ./app/
COPY tests/ ./tests/

# 포트 노출
EXPOSE 5000

# 메인 애플리케이션 실행
CMD ["python", "/app/app/main.py"]