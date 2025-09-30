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
    # 명령줄 인자를 파싱하여 모듈 이름을 받음
    parser = argparse.ArgumentParser(description="패키지에서 공개 API를 재귀적으로 추출")
    parser.add_argument('module', help="API를 추출할 모듈 이름")
    args = parser.parse_args()
    modname = args.module

    # 모듈 이름이 유효한지 확인 (Python 식별자 규칙 준수, 점으로 시작하지 않음)
    if not modname.replace(".", "").isidentifier() or modname.startswith("."):
        print(json.dumps({"functions": []}))
        sys.exit(0)

    # 모듈을 임포트 시도
    try:
        mod = importlib.import_module(modname)
    except ImportError:
        print(json.dumps({"functions": []}))
        sys.exit(0)

    apis = set()
    # __all__ 속성이 있으면 이를 사용, 없으면 비공개(_로 시작하지 않는) 이름 사용
    exports = getattr(mod, "__all__", None)
    names = exports if exports is not None else [n for n in dir(mod) if not n.startswith("_")]
    for name in names:
        try:
            obj = getattr(mod, name)
        except Exception:
            continue
        if callable(obj):
            apis.add(f"{modname}.{name}")

    # 패키지인 경우 하위 모듈을 탐색
    if hasattr(mod, '__path__'):
        for finder, subname, ispkg in pkgutil.walk_packages(mod.__path__, modname + '.'):
            # 특수 모듈(__pip-runner__) 및 유효하지 않은 이름 제외
            if subname.endswith(".__pip-runner__") or not subname.replace(".", "").isidentifier() or subname.startswith("."):
                continue
            try:
                submod = importlib.import_module(subname)
            except ImportError:
                continue
            exports = getattr(submod, "__all__", None)
            names = exports if exports is not None else [n for n in dir(submod) if not n.startswith("_")]
            for name in names:
                try:
                    obj = getattr(submod, name)
                except Exception:
                    continue
                if callable(obj):
                    apis.add(f"{subname}.{name}")

    # 추출된 API 목록을 JSON 형식으로 출력
    print(json.dumps({"functions": sorted(apis)}))

if __name__ == "__main__":
    main()