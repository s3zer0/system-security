"""
AST를 PNG로 시각화하고 분석하는 모듈입니다.

이 모듈은 호출 그래프 시각화와 API 분류를 담당합니다.
"""

import ast
import os
import logging
from collections import defaultdict
from graphviz import Digraph

from . import ast_utils


def get_full_name(node):
    """AST 노드에서 완전한 정규화 이름을 추출합니다."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        base_name = get_full_name(node.value)
        return f"{base_name}.{node.attr}" if base_name else node.attr
    return ''


def invert_graph(call_graph):
    """호출 그래프를 뒤집어 호출자 맵을 생성합니다."""
    inverse_map = defaultdict(set)
    for caller_function, callee_functions in call_graph.items():
        for callee_function in callee_functions:
            inverse_map[callee_function].add(caller_function)
    return inverse_map


def collect_related_functions(target_call_entries, callers_map):
    """대상 호출과 관련된 모든 함수를 수집합니다."""
    related_functions = set()
    for function_name, *_ in target_call_entries:
        related_functions.add(function_name)
        stack = [function_name]
        while stack:
            current = stack.pop()
            for parent in callers_map.get(current, []):
                if parent not in related_functions:
                    related_functions.add(parent)
                    stack.append(parent)
    return related_functions


def parse_target_calls(target_call_strings):
    """대상 API 문자열을 (모듈, 함수) 튜플로 변환합니다."""
    parsed_targets = []
    for target_string in target_call_strings:
        parts = target_string.split('.', 1)
        if len(parts) == 1:
            parsed_targets.append((None, parts[0]))
        else:
            parsed_targets.append((parts[0], parts[1]))
    return parsed_targets


def sanitize_node_identifier(name):
    """Graphviz에서 사용할 노드 이름을 정제합니다."""
    return name.replace('.', '_').replace(' ', '_').replace('/', '_')


def visualize_call_flow(
    file_paths,
    base_directory,
    output_path,
    target_call_list,
    force_detection,
    no_graph=False
):
    """
    호출 흐름을 시각화하는 메인 함수입니다.
    
    Args:
        file_paths: 분석할 Python 파일 경로 목록입니다.
        base_directory: 상대 경로 계산에 사용할 기준 디렉터리입니다.
        output_path: 그래프 출력 파일 접두사입니다.
        target_call_list: 추적할 (모듈, 함수) 튜플 목록입니다.
        force_detection: True이면 모든 API 호출을 감지합니다.
        no_graph: True이면 그래프 생성을 건너뜁니다.
        
    Returns:
        (external_apis, internal_apis, unused_apis) 튜플을 반환합니다.
    """
    logging.info(f"Starting analysis on {len(file_paths)} files in {base_directory}")
    global_function_info = {}
    call_graph = defaultdict(set)
    collected_target_calls = []

    # 플래그와 태그 간 매핑을 정의합니다.
    DETECTION_FLAG_TO_TAG = {
        'is_route':    'route',
        'is_restful':  'restful',
        'is_cli':      'cli',
        'is_socketio': 'socketio',
        'uses_req':    'uses_request',
    }
    ROUTE_DETECTION_FLAGS = (
        'is_route',
        'is_cli',
        'is_socketio',
        'is_restful',
    )

    # 함수 정의를 수집합니다.
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

        functions_in_file = ast_utils.collect_functions(syntax_tree)
        for function_name, function_info in functions_in_file.items():
            full_function_name = f"{module_prefix}.{function_name}" if module_prefix else function_name
            function_info['file'] = relative_path
            global_function_info[full_function_name] = function_info

    # 강제 모드: 기본 yaml 대상 처리를 수행합니다.
    if force_detection and target_call_list == [(None, 'yaml')]:
        target_call_list.clear()
        for function_name, function_info in global_function_info.items():
            if any(function_info.get(flag, False) for flag in ROUTE_DETECTION_FLAGS):
                target_call_list.append((None, function_name.split('.')[-1]))

    # 호출 그래프를 구축하고 대상 호출을 수집합니다.
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

        visitor = ast_utils.CallVisitor(
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

    # 외부 함수 집합을 확장합니다.
    external_functions = {
        fn for fn, info in global_function_info.items()
        if any(info.get(flag, False) for flag in ROUTE_DETECTION_FLAGS)
    }
    extension_stack = list(external_functions)
    while extension_stack:
        current_function = extension_stack.pop()
        for callee in call_graph.get(current_function, []):
            if callee not in external_functions:
                external_functions.add(callee)
                extension_stack.append(callee)

    # 그래프를 뒤집어 관련 함수를 수집합니다.
    reversed_call_map = invert_graph(call_graph)
    related_functions = collect_related_functions(collected_target_calls, reversed_call_map)

    # 시각화를 수행합니다.
    if not no_graph:
        graph = Digraph()
        graph.attr(rankdir='LR', bgcolor='white')
        graph.attr('node', style='filled')
        graph.attr('edge', fontcolor='black')

        # 함수 정의 노드를 생성합니다.
        for function_name in sorted(related_functions):
            info = global_function_info.get(function_name, {})
            label = f"{function_name}\n(file: {info.get('file','?')}, line: {info.get('line','?')})"
            tags = [
                tag for flag, tag in DETECTION_FLAG_TO_TAG.items()
                if info.get(flag, False)
            ]
            if tags:
                label += "\n[" + ",".join(tags) + "]"
            fill_color = (
                'lightgoldenrod'
                if any(info.get(flag, False) for flag in ROUTE_DETECTION_FLAGS)
                else 'white'
            )
            graph.node(sanitize_node_identifier(function_name), label=label, fillcolor=fill_color)

        # 함수 호출 노드를 생성합니다.
        for container_function, call_node, first_arg, keyword_args, relative_path in collected_target_calls:
            line_number = call_node.lineno
            api_full_name = get_full_name(call_node.func)
            call_label = f"{api_full_name}\n(file: {relative_path}, line: {line_number})"
            if first_arg:
                call_label += f"\narg0: {first_arg}"
            if keyword_args:
                call_label += "\n" + ",".join(keyword_args)
            is_external_call = container_function in external_functions
            call_label += f"\n[{'external' if is_external_call else 'internal'}]"
            call_id = sanitize_node_identifier(f"call_{container_function}_{line_number}")
            graph.node(call_id, label=call_label, shape='oval',
                       fillcolor=('lightcoral' if is_external_call else 'lightblue'))
            graph.edge(sanitize_node_identifier(container_function), call_id,
                       label=f"calls (line {line_number})")

        # 호출자-피호출자 간 엣지를 생성합니다.
        for caller_function, callee_functions in call_graph.items():
            if caller_function in related_functions:
                for callee_function in callee_functions:
                    if callee_function in related_functions:
                        graph.edge(
                            sanitize_node_identifier(caller_function),
                            sanitize_node_identifier(callee_function),
                            label='calls'
                        )

        graph.format = 'png'
        graph.render(output_path, cleanup=True)
        logging.info(f"Graph saved to {output_path}.png")
    else:
        logging.info("Graph generation skipped (--no-graph option)")

    # API를 범주화합니다.
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
