#!/usr/bin/env python3
"""
Container Image Source Extractor

간단한 진입점 - 모든 로직은 modules 패키지에서 처리됩니다.
"""

import sys
from modules import run_cli


def main():
    """메인 함수 - CLI 실행"""
    sys.exit(run_cli())


if __name__ == "__main__":
    main()

# Usage : python3 main.py ../test_target/pyyaml-vuln.tar ../DB/output --auto-detect