#!/usr/bin/env python3
"""
PyYAML 취약점 테스트 애플리케이션
CVE-2020-1747 - yaml.load() 취약점 포함
"""

import os
import sys
import yaml
from pathlib import Path

sys.path.insert(0, '/app')
from app.server import app

def main():
    """
    메인 함수 - 테스트 애플리케이션 시작점
    """
    # 애플리케이션 정보 출력
    print("PyYAML Vulnerability Test Application")
    print(f"PyYAML version: {yaml.__version__}")

    # 업로드 디렉토리 생성 및 설정
    Path('/app/uploads').mkdir(exist_ok=True)
    app.config['UPLOAD_FOLDER'] = '/app/uploads'

    # Flask 웹 서버 시작 (모든 인터페이스에서 접근 가능)
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == '__main__':
    # 스크립트가 직접 실행될 때만 메인 함수 호출
    main()