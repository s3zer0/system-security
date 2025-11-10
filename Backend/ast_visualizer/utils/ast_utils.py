"""
AST 유틸리티 - 노드 정보 수집

이 모듈은 함수 정의와 호출 관계를 수집하기 위해 Python AST 노드를 분석하는
방문자 클래스와 유틸리티 함수를 제공합니다.
"""

import ast

# RESTful API 감지를 위한 HTTP 메서드 이름 목록
RESTFUL_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}


def is_route_decorator(decorator_node):
    """데코레이터가 Flask 라우트 데코레이터인지 확인합니다."""
    if not isinstance(decorator_node, ast.Call):
        return False
    func_node = decorator_node.func
    return (
        isinstance(func_node, ast.Attribute)
        and isinstance(func_node.value, ast.Name)
        and func_node.attr == "route"
    )


def is_cli_decorator(decorator_node):
    """데코레이터가 CLI 명령 데코레이터인지 확인합니다."""
    if not isinstance(decorator_node, ast.Call):
        return False
    func_node = decorator_node.func
    return (
        isinstance(func_node, ast.Attribute)
        and func_node.attr == "command"
        and isinstance(func_node.value, ast.Attribute)
        and func_node.value.attr == "cli"
        and isinstance(func_node.value.value, ast.Name)
    )


def is_socketio_decorator(decorator_node):
    """데코레이터가 SocketIO 데코레이터인지 확인합니다."""
    if not isinstance(decorator_node, ast.Call):
        return False
    func_node = decorator_node.func
    return (
        isinstance(func_node, ast.Attribute)
        and isinstance(func_node.value, ast.Name)
        and func_node.value.id == "socketio"
        and func_node.attr in ("on", "event")
    )


def uses_request(function_node):
    """함수가 'request' 객체를 사용하는지 확인합니다."""
    for inner_node in ast.walk(function_node):
        if isinstance(inner_node, ast.Name) and inner_node.id == 'request':
            return True
    return False


def collect_functions(syntax_tree):
    """모든 함수 정의를 메타데이터와 함께 수집합니다."""
    visitor = FuncVisitor()
    visitor.visit(syntax_tree)
    return visitor.function_info_map


class FuncVisitor(ast.NodeVisitor):
    """함수 정의와 관련 메타데이터를 수집하는 방문자 클래스입니다."""
    
    def __init__(self):
        self.current_class_name = None
        self.function_info_map = {}

    def visit_ClassDef(self, class_node):
        prev_class = self.current_class_name
        self.current_class_name = class_node.name
        self.generic_visit(class_node)
        self.current_class_name = prev_class

    def visit_FunctionDef(self, function_node):
        if self.current_class_name:
            qualified_name = f"{self.current_class_name}.{function_node.name}"
        else:
            qualified_name = function_node.name

        self.function_info_map[qualified_name] = {
            'line': function_node.lineno,
            'is_route': any(is_route_decorator(dec) for dec in function_node.decorator_list),
            'is_cli': any(is_cli_decorator(dec) for dec in function_node.decorator_list),
            'is_socketio': any(is_socketio_decorator(dec) for dec in function_node.decorator_list),
            'uses_req': uses_request(function_node),
            'is_restful': False,
        }
        self.generic_visit(function_node)


class CallVisitor(ast.NodeVisitor):
    """함수 호출을 수집하여 호출 그래프를 구축하는 방문자 클래스입니다."""
    
    def __init__(
        self,
        force_detection,
        module_prefix,
        source_code,
        relative_file_path,
        global_function_info_map,
        call_graph_map,
        target_call_specs
    ):
        self.current_function_name = None
        self.current_class_name = None
        self.force_detection = force_detection
        self.module_prefix = module_prefix
        self.source_code = source_code
        self.relative_file_path = relative_file_path
        self.global_function_info_map = global_function_info_map
        self.call_graph_map = call_graph_map
        self.target_call_specs = target_call_specs

    def visit_ClassDef(self, class_node):
        prev_class = self.current_class_name
        self.current_class_name = class_node.name
        self.generic_visit(class_node)
        self.current_class_name = prev_class

    def visit_FunctionDef(self, function_node):
        if self.current_class_name:
            short_name = f"{self.current_class_name}.{function_node.name}"
        else:
            short_name = function_node.name

        if self.module_prefix:
            self.current_function_name = f"{self.module_prefix}.{short_name}"
        else:
            self.current_function_name = short_name

        self.generic_visit(function_node)
        self.current_function_name = None

    def visit_Call(self, call_node):
        # 데코레이터 정보를 기반으로 추가 감지를 수행합니다.
        if isinstance(call_node.func, ast.Attribute):
            attribute_name = call_node.func.attr

            # socketio.on_event 핸들러를 처리합니다.
            if attribute_name == "on_event" and getattr(call_node.func.value, 'id', None) == "socketio":
                handler_node = (
                    call_node.args[1]
                    if len(call_node.args) >= 2
                    else next((kw.value for kw in call_node.keywords if kw.arg in ("handler", "callback")), None)
                )
                if isinstance(handler_node, (ast.Name, ast.Attribute)):
                    handler_name = handler_node.id if isinstance(handler_node, ast.Name) else handler_node.attr
                    for func_name in self.global_function_info_map:
                        if func_name.endswith(f".{handler_name}") or func_name == handler_name:
                            self.global_function_info_map[func_name]['is_socketio'] = True
                            break

            # flask.add_url_rule 호출을 통해 라우트를 감지합니다.
            elif attribute_name == "add_url_rule":
                view_func_node = next((kw.value for kw in call_node.keywords if kw.arg == "view_func"), None)
                if view_func_node is None:
                    if len(call_node.args) >= 3:
                        view_func_node = call_node.args[2]
                    elif len(call_node.args) == 2:
                        view_func_node = call_node.args[1]

                if view_func_node:
                    if isinstance(view_func_node, ast.Call) and getattr(view_func_node.func, 'attr', None) == "as_view":
                        class_node = view_func_node.func.value
                        class_name = getattr(class_node, 'id', getattr(class_node, 'attr', None))
                        for func_name in self.global_function_info_map:
                            if f".{class_name}." in func_name:
                                method_name = func_name.split('.')[-1]
                                if method_name in RESTFUL_HTTP_METHODS:
                                    self.global_function_info_map[func_name]['is_route'] = True
                    else:
                        func_name_candidate = (
                            view_func_node.id
                            if isinstance(view_func_node, ast.Name)
                            else view_func_node.attr
                            if isinstance(view_func_node, ast.Attribute)
                            else None
                        )
                        if func_name_candidate:
                            for fn in self.global_function_info_map:
                                if fn.endswith(f".{func_name_candidate}") or fn == func_name_candidate:
                                    self.global_function_info_map[fn]['is_route'] = True
                                    break

            # flask-restful add_resource 호출을 감지합니다.
            elif attribute_name == "add_resource":
                resource_class_node = call_node.args[0] if call_node.args else None
                if isinstance(resource_class_node, (ast.Name, ast.Attribute)):
                    class_name = (
                        resource_class_node.id
                        if isinstance(resource_class_node, ast.Name)
                        else resource_class_node.attr
                    )
                    for func_name in self.global_function_info_map:
                        if f".{class_name}." in func_name:
                            method_name = func_name.split('.')[-1]
                            if method_name in RESTFUL_HTTP_METHODS:
                                self.global_function_info_map[func_name]['is_restful'] = True

            # socketio.on 호출을 처리합니다.
            elif attribute_name == "on" and getattr(call_node.func.value, 'id', None) == "socketio":
                handler_node = (
                    call_node.args[1]
                    if len(call_node.args) >= 2
                    else next((kw.value for kw in call_node.keywords if kw.arg in ("handler", "callback")), None)
                )
                if isinstance(handler_node, (ast.Name, ast.Attribute)):
                    handler_name = handler_node.id if isinstance(handler_node, ast.Name) else handler_node.attr
                    for func_name in self.global_function_info_map:
                        if func_name.endswith(f".{handler_name}") or func_name == handler_name:
                            self.global_function_info_map[func_name]['is_socketio'] = True
                            break

        # 호출자와 피호출자 간의 관계를 기록합니다.
        if self.current_function_name is not None:
            if isinstance(call_node.func, ast.Name):
                callee_name = call_node.func.id
            elif isinstance(call_node.func, ast.Attribute):
                callee_name = call_node.func.attr
                if callee_name in {"add_url_rule", "add_resource", "on_event", "on"}:
                    callee_name = None
            else:
                callee_name = None

            if callee_name:
                for func_name in self.global_function_info_map:
                    if func_name == self.current_function_name:
                        continue
                    if func_name.endswith(f".{callee_name}") or func_name == callee_name:
                        self.call_graph_map[self.current_function_name].add(func_name)
                        break

        # 대상 API 호출을 기록합니다.
        container_name = self.current_function_name or self.module_prefix or '<module>'
        is_target_call = self.force_detection or any(
            (module_name and isinstance(call_node.func, ast.Attribute)
             and getattr(call_node.func.value, 'id', None) == module_name
             and call_node.func.attr == func_name)
            or (module_name is None and isinstance(call_node.func, ast.Name)
                and call_node.func.id == func_name)
            for module_name, func_name in self.target_call_specs
        )
        if is_target_call:
            first_arg_source = (
                ast.get_source_segment(self.source_code, call_node.args[0])
                if call_node.args else ''
            )
            keyword_arg_sources = [
                f"{kw.arg}={ast.get_source_segment(self.source_code, kw.value)}"
                for kw in call_node.keywords
            ]
            self.call_graph_map.setdefault('target_calls', []).append(
                (container_name, call_node, first_arg_source, keyword_arg_sources, self.relative_file_path)
            )

        self.generic_visit(call_node)
