"""
핵심 분석 모듈

Python 코드 처리 및 call graph 생성을 위한 주요 분석 로직을 포함합니다.
"""

import ast
import os
import json
import logging
from collections import defaultdict

from .ast_utils import (
    collect_functions, CallVisitor, get_full_name, parse_target_calls
)
from .visualization import create_call_flow_graph


def save_analysis_results(result, output_prefix):
    """분석 결과를 JSON 파일로 저장"""
    json_filename = f"{output_prefix}_result.json"
    with open(json_filename, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    logging.info(f"Results saved to {json_filename}")


def print_analysis_results(external_apis, internal_only_apis, unused_apis):
    """분석 결과를 콘솔에 출력"""
    print("\n외부에 노출된 API들:")
    for api in external_apis:
        print(f"  {api}")
    print("\n내부에서만 사용되는 API들:")
    for api in internal_only_apis:
        print(f"  {api}")
    print("\n사용되지 않는 API들:")
    for api in unused_apis:
        print(f"  {api}")


def collect_python_files(input_path):
    """주어진 경로에서 Python 파일들을 수집"""
    if os.path.isdir(input_path):
        base = input_path.rstrip(os.sep)
        files = []
        for r, _, fns in os.walk(input_path):
            for fn in fns:
                if fn.endswith('.py'):
                    files.append(os.path.join(r, fn))
        logging.info(f"분석을 위해 {len(files)}개의 Python 파일을 수집했습니다")
        return base, files
    else:
        base = os.path.dirname(input_path) or '.'
        files = [input_path]
        logging.info(f"단일 파일 모드: {input_path}")
        return base, files


def build_function_info(file_paths, base_directory):
    """모든 파일에서 전역 함수 정보 구축"""
    global_function_info = {}

    for file_path in file_paths:
        try:
            source_code = open(file_path, encoding='utf-8').read()
            syntax_tree = ast.parse(source_code)
        except Exception:
            continue

        relative_path = os.path.relpath(file_path, base_directory)
        module_prefix = (
            relative_path.replace(os.sep, '.')[:-3]
            if file_path.endswith('.py')
            else relative_path.replace(os.sep, '.')
        )
        if not module_prefix:
            module_prefix = os.path.splitext(os.path.basename(file_path))[0]

        functions_in_file = collect_functions(syntax_tree)
        for function_name, function_info in functions_in_file.items():
            full_function_name = f"{module_prefix}.{function_name}" if module_prefix else function_name
            function_info['file'] = relative_path
            global_function_info[full_function_name] = function_info

    return global_function_info


def build_call_graph(file_paths, base_directory, global_function_info, target_call_list, force_detection):
    """call graph 구축 및 대상 호출 수집"""
    call_graph = defaultdict(set)
    collected_target_calls = []

    for file_path in file_paths:
        try:
            source_code = open(file_path, encoding='utf-8').read()
            syntax_tree = ast.parse(source_code)
        except Exception:
            continue

        relative_path = os.path.relpath(file_path, base_directory)
        module_prefix = (
            relative_path.replace(os.sep, '.')[:-3]
            if file_path.endswith('.py')
            else relative_path.replace(os.sep, '.')
        )
        if not module_prefix:
            module_prefix = os.path.splitext(os.path.basename(file_path))[0]

        visitor = CallVisitor(
            force_detection,
            module_prefix,
            source_code,
            relative_path,
            global_function_info,
            call_graph,
            target_call_list
        )
        visitor.visit(syntax_tree)

        if 'target_calls' in call_graph:
            collected_target_calls.extend(call_graph.pop('target_calls'))

    return call_graph, collected_target_calls


def identify_external_functions(global_function_info, call_graph):
    """라우트 감지 플래그를 기반으로 외부 함수들 식별"""
    ROUTE_DETECTION_FLAGS = (
        'is_route',
        'is_cli',
        'is_socketio',
        'is_restful',
    )

    external_functions = {
        fn for fn, info in global_function_info.items()
        if any(info.get(flag, False) for flag in ROUTE_DETECTION_FLAGS)
    }

    # 외부 함수 집합 확장
    extension_stack = list(external_functions)
    while extension_stack:
        current_function = extension_stack.pop()
        for callee in call_graph.get(current_function, []):
            if callee not in external_functions:
                external_functions.add(callee)
                extension_stack.append(callee)

    return external_functions


def categorize_apis(collected_target_calls, external_functions, target_call_list):
    """API들을 외부, 내부, 미사용으로 분류"""
    external_set = set()
    internal_set = set()
    for container_function, call_node, *_ in collected_target_calls:
        api_name = get_full_name(call_node.func)
        if container_function in external_functions:
            external_set.add(api_name)
        else:
            internal_set.add(api_name)

    target_labels = [f"{(m + '.') if m else ''}{f}" for m, f in target_call_list]
    externally_exposed = sorted(external_set)
    internally_only = sorted([api for api in internal_set if api not in external_set])
    unused = sorted([api for api in target_labels if api not in external_set and api not in internal_set])

    return externally_exposed, internally_only, unused


def visualize_call_flow(
    file_paths,
    base_directory,
    output_path,
    target_call_list,
    force_detection,
    no_graph=False
):
    """주요 시각화 함수"""
    logging.info(f"{base_directory}에서 {len(file_paths)}개 파일에 대한 분석을 시작합니다")

    # 전역 함수 정보 구축
    global_function_info = build_function_info(file_paths, base_directory)

    # 강제 모드: 기본 yaml 대상 처리
    if force_detection and target_call_list == [(None, 'yaml')]:
        target_call_list.clear()
        ROUTE_DETECTION_FLAGS = ('is_route', 'is_cli', 'is_socketio', 'is_restful')
        for function_name, function_info in global_function_info.items():
            if any(function_info.get(flag, False) for flag in ROUTE_DETECTION_FLAGS):
                target_call_list.append((None, function_name.split('.')[-1]))

    # call graph 구축 및 대상 호출 수집
    call_graph, collected_target_calls = build_call_graph(
        file_paths, base_directory, global_function_info, target_call_list, force_detection
    )

    # 외부 함수들 식별
    external_functions = identify_external_functions(global_function_info, call_graph)

    # 시각화 생성 (비활성화되지 않은 경우)
    if not no_graph:
        create_call_flow_graph(
            global_function_info,
            call_graph,
            collected_target_calls,
            external_functions,
            output_path
        )
    else:
        logging.info("그래프 생성을 건너뛰었습니다 (--no-graph 옵션)")

    # API 분류
    externally_exposed, internally_only, unused = categorize_apis(
        collected_target_calls, external_functions, target_call_list
    )

    return externally_exposed, internally_only, unused


def analyze_code(input_path, output_prefix, target_list, save_json=False, no_graph=False):
    """Python 코드 분석 및 결과 생성"""
    force = len(target_list) == 0
    targets = parse_target_calls(target_list)

    base, files = collect_python_files(input_path)

    external_apis, internal_only_apis, unused_apis = visualize_call_flow(
        files, base, output_prefix, targets, force, no_graph
    )

    # 결과를 콘솔에 출력
    print_analysis_results(external_apis, internal_only_apis, unused_apis)

    # 요청시 JSON으로 저장
    if save_json:
        result = {
            "external": external_apis,
            "internal": internal_only_apis,
            "unused": unused_apis
        }
        save_analysis_results(result, output_prefix)

    return external_apis, internal_only_apis, unused_apis