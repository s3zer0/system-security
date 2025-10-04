"""
시각화 모듈

그래프 및 시각적 표현 생성을 위한 함수들을 포함합니다.
"""

import logging
from collections import defaultdict
from graphviz import Digraph

from .ast_utils import get_full_name


def sanitize_node_identifier(name):
    """Graphviz용 노드 이름 정리"""
    return name.replace('.', '_').replace(' ', '_').replace('/', '_')


def invert_graph(call_graph):
    """call graph를 뒤집어서 호출자 맵 생성"""
    inverse_map = defaultdict(set)
    for caller_function, callee_functions in call_graph.items():
        for callee_function in callee_functions:
            inverse_map[callee_function].add(caller_function)
    return inverse_map


def collect_related_functions(target_call_entries, callers_map):
    """대상 호출과 관련된 모든 함수들 수집"""
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


def create_call_flow_graph(
    global_function_info,
    call_graph,
    collected_target_calls,
    external_functions,
    output_path
):
    """call flow 시각화 그래프 생성 및 렌더링"""
    # 플래그-태그 매핑
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

    # 그래프 역전 및 관련 함수 수집
    reversed_call_map = invert_graph(call_graph)
    related_functions = collect_related_functions(collected_target_calls, reversed_call_map)

    # 시각화 생성
    graph = Digraph()
    graph.attr(rankdir='LR', bgcolor='white')
    graph.attr('node', style='filled')
    graph.attr('edge', fontcolor='black')

    # 함수 정의 노드들 생성
    for function_name in sorted(related_functions):
        info = global_function_info.get(function_name, {})
        label = f"{function_name}\n(파일: {info.get('file','?')}, 라인: {info.get('line','?')})"
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

    # 함수 호출 노드들 생성
    for container_function, call_node, first_arg, keyword_args, relative_path in collected_target_calls:
        line_number = call_node.lineno
        api_full_name = get_full_name(call_node.func)
        call_label = f"{api_full_name}\n(파일: {relative_path}, 라인: {line_number})"
        if first_arg:
            call_label += f"\n인자0: {first_arg}"
        if keyword_args:
            call_label += "\n" + ",".join(keyword_args)
        is_external_call = container_function in external_functions
        call_label += f"\n[{'외부' if is_external_call else '내부'}]"
        call_id = sanitize_node_identifier(f"call_{container_function}_{line_number}")
        graph.node(call_id, label=call_label, shape='oval',
                   fillcolor=('lightcoral' if is_external_call else 'lightblue'))
        graph.edge(sanitize_node_identifier(container_function), call_id,
                   label=f"호출 (라인 {line_number})")

    # 호출자-피호출자 관계 엣지 생성
    for caller_function, callee_functions in call_graph.items():
        if caller_function in related_functions:
            for callee_function in callee_functions:
                if callee_function in related_functions:
                    graph.edge(
                        sanitize_node_identifier(caller_function),
                        sanitize_node_identifier(callee_function),
                        label='호출'
                    )

    graph.format = 'png'
    graph.render(output_path, cleanup=True)
    logging.info(f"그래프가 {output_path}.png에 저장되었습니다")


def create_cve_graph(package_info, cve_info, output_prefix):
    """CVE 시각화 그래프 생성 및 렌더링"""
    graph = Digraph()
    graph.attr(rankdir='TB', bgcolor='white', fontsize='12')
    graph.attr('node', style='filled', fontsize='10')
    graph.attr('edge', fontcolor='black', fontsize='8')

    # 패키지 노드들 생성
    for package_name, info in package_info.items():
        label = f"{package_name}\nv{info['version']}\n{info['cve_count']}개 CVE"
        graph.node(f"pkg_{package_name}", label=label,
                  fillcolor='lightblue', shape='box')

    # CVE 노드들과 API 노드들 생성
    for cve_id, info in cve_info.items():
        # CVE 노드
        cve_label = f"{cve_id}\n{info['package']}"
        graph.node(f"cve_{cve_id}", label=cve_label,
                  fillcolor='lightcoral', shape='diamond')

        # 패키지에서 CVE로 연결
        graph.edge(f"pkg_{info['package']}", f"cve_{cve_id}")

        # API 노드들
        for api in info['vulnerable_apis']:
            api_safe = sanitize_node_identifier(api)
            graph.node(f"api_{api_safe}", label=api,
                      fillcolor='lightyellow', shape='ellipse')

            # CVE에서 API로 연결
            graph.edge(f"cve_{cve_id}", f"api_{api_safe}")

    # 그래프 렌더링
    graph.format = 'png'
    graph.render(output_prefix, cleanup=True)
    logging.info(f"CVE 시각화가 {output_prefix}.png에 저장되었습니다")