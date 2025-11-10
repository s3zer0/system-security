#!/usr/bin/env python3
"""
패키지의 최상위 모듈을 탐지하는 스크립트
"""
import json
import sys
from importlib.metadata import distribution

def main():
    """
    메인 함수 - 명령줄 인자로 받은 패키지의 최상위 모듈을 탐지
    """
    # 명령줄 인자 검증 (패키지 이름 1개 필요)
    if len(sys.argv) != 2:
        print(json.dumps({"modules": []}))
        sys.exit(0)

    # 첫 번째 인자로 패키지 이름 받기
    package_name = sys.argv[1]

    # 지정된 패키지의 배포 정보를 가져옴
    dist = None
    try:
        # importlib.metadata를 사용해 패키지 메타데이터 획듍
        dist = distribution(package_name)
    except Exception:
        # 패키지를 찾을 수 없는 경우 빈 결과 반환
        print(json.dumps({"modules": []}))
        sys.exit(0)

    # 패키지에 포함된 파일 목록 가져오기
    files = dist.files or []

    # 최상위 모듈 이름을 저장할 집합
    top = set()

    # 각 파일에 대해 처리
    for f in files:
        # 파일 경로를 부분들로 분할
        parts = f.parts

        # 메타데이터 디렉토리가 아닌 최상위 디렉토리만 처리
        # (.dist-info, .egg-info로 끝나지 않는 경우)
        if parts and not parts[0].endswith(('.dist-info', '.egg-info')):
            # Python 모듈 명명 규칙에 맞는 이름만 추가
            # (식별자 규칙 준수, 점으로 시작하지 않음)
            if parts[0].replace(".", "").isidentifier() and not parts[0].startswith("."):
                top.add(parts[0])

    # 최상위 모듈 목록을 정렬해서 JSON 형식으로 출력
    print(json.dumps({"modules": sorted(top)}))

if __name__ == "__main__":
    # 스크립트가 직접 실행될 때만 메인 함수 호출
    main()