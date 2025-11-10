#!/usr/bin/env python3
"""
컨테이너 이미지 소스 추출기

간단한 진입점이며 실제 로직은 modules 패키지에서 처리됩니다.
"""

import sys
from modules import run_cli


def main():
    """
    메인 함수 - CLI 실행 및 종료 코드 반환
    """
    # CLI 실행 및 종료 코드로 프로그램 종료
    sys.exit(run_cli())


if __name__ == "__main__":
    # 스크립트가 직접 실행될 때만 메인 함수 호출
    main()

# 사용 예시: python3 main.py ../test_target/pyyaml-vuln.tar ../DB/output --auto-detect
