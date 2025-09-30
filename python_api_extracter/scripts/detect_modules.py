#!/usr/bin/env python3
"""
패키지의 최상위 모듈을 탐지하는 스크립트
"""
import json
import sys
from importlib.metadata import distribution

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"modules": []}))
        sys.exit(0)

    package_name = sys.argv[1]

    # 지정된 패키지의 배포 정보를 가져옴
    dist = None
    try:
        dist = distribution(package_name)
    except Exception:
        print(json.dumps({"modules": []}))
        sys.exit(0)

    files = dist.files or []
    top = set()
    for f in files:
        parts = f.parts
        # .dist-info, .egg-info로 끝나지 않는 최상위 디렉토리만 추가
        if parts and not parts[0].endswith(('.dist-info', '.egg-info')):
            # 유효한 모듈 이름만 추가 (Python 식별자 규칙 준수, 점으로 시작하지 않음)
            if parts[0].replace(".", "").isidentifier() and not parts[0].startswith("."):
                top.add(parts[0])

    # 최상위 모듈 목록을 JSON 형식으로 출력
    print(json.dumps({"modules": sorted(top)}))

if __name__ == "__main__":
    main()