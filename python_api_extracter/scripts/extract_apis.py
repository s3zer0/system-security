#!/usr/bin/env python3
"""
패키지에서 공개 API를 재귀적으로 추출하는 스크립트
"""
import pkgutil
import importlib
import inspect
import json
import argparse
import sys

def main():
    """
    메인 함수 - 지정된 모듈에서 공개 API를 추출
    """
    # 명령줄 인자 파서 생성 및 설정
    parser = argparse.ArgumentParser(description="패키지에서 공개 API를 재귀적으로 추출")
    parser.add_argument('module', help="API를 추출할 모듈 이름")
    args = parser.parse_args()
    modname = args.module

    # 모듈 이름 유효성 검사
    # - Python 식별자 규칙 준수 확인
    # - 점으로 시작하지 않는지 확인
    if not modname.replace(".", "").isidentifier() or modname.startswith("."):
        print(json.dumps({"functions": []}))
        sys.exit(0)

    # 지정된 모듈 임포트 시도
    try:
        mod = importlib.import_module(modname)
    except ImportError:
        # 모듈을 찾을 수 없는 경우 빈 결과 반환
        print(json.dumps({"functions": []}))
        sys.exit(0)

    # API 목록을 저장할 집합
    apis = set()

    # 모듈의 공개 API 목록 결정
    # __all__이 정의되어 있으면 사용, 없으면 _로 시작하지 않는 이름 사용
    exports = getattr(mod, "__all__", None)
    names = exports if exports is not None else [n for n in dir(mod) if not n.startswith("_")]
    # 각 공개 API 이름에 대해 처리
    for name in names:
        try:
            # 객체 가져오기
            obj = getattr(mod, name)
        except Exception:
            continue

        # 호출 가능한 객체만 추가 (함수, 메서드, 내장 함수, 루틴)
        # 클래스는 제외
        if inspect.isfunction(obj) or inspect.ismethod(obj) or inspect.isbuiltin(obj) or inspect.isroutine(obj):
            apis.add(f"{name}")

    # 패키지인 경우 하위 모듈들을 재귀적으로 탐색
    if hasattr(mod, '__path__'):
        # 모든 하위 패키지와 모듈을 순회
        for finder, subname, ispkg in pkgutil.walk_packages(mod.__path__, modname + '.'):
            # 특수 모듈과 유효하지 않은 이름 필터링
            # - __pip-runner__ 모듈 제외
            # - 유효하지 않은 식별자 제외
            # - 점으로 시작하는 이름 제외
            if subname.endswith(".__pip-runner__") or not subname.replace(".", "").isidentifier() or subname.startswith("."):
                continue
            try:
                # 하위 모듈 임포트
                submod = importlib.import_module(subname)
            except ImportError:
                continue

            # 하위 모듈의 공개 API 목록 결정
            exports = getattr(submod, "__all__", None)
            names = exports if exports is not None else [n for n in dir(submod) if not n.startswith("_")]
            # 하위 모듈의 각 API에 대해 처리
            for name in names:
                try:
                    obj = getattr(submod, name)
                except Exception:
                    continue

                # 호출 가능한 객체만 추가
                if inspect.isfunction(obj) or inspect.ismethod(obj) or inspect.isbuiltin(obj) or inspect.isroutine(obj):
                    # 상대 경로로 변환 (최상위 패키지명 제거)
                    submodule_path = subname.replace(modname + '.', '')
                    apis.add(f"{submodule_path}.{name}")

    # 추출된 API 목록을 정렬해서 JSON 형식으로 출력
    print(json.dumps({"functions": sorted(apis)}))

if __name__ == "__main__":
    # 스크립트가 직접 실행될 때만 메인 함수 호출
    main()