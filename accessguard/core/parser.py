from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
AUTH_HINTS = {"auth", "token", "permission", "scope", "current_user", "oauth", "jwt"}


@dataclass(slots=True)
class RouteInfo:
    file_path: str
    handler_name: str
    method: str
    path: str
    calls: list[str]
    call_types: list[tuple[str, str]]
    has_auth: bool


class CallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: list[str] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = _call_name(node.func)
        if name:
            self.calls.append(name)
        self.generic_visit(node)


def parse_file_data(file_path: Path) -> tuple[list[RouteInfo], dict[str, dict[str, list[str]]]]:
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    routes: list[RouteInfo] = []
    function_map: dict[str, dict[str, list[str]]] = {}

    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        calls = _collect_calls(node)
        function_map[node.name] = {"calls": calls}

        for method, route_path, decorator in _extract_route_decorators(node):
            call_types = _classify_calls(calls)
            has_auth = _has_auth(node, decorator)
            routes.append(
                RouteInfo(
                    file_path=str(file_path),
                    handler_name=node.name,
                    method=method.upper(),
                    path=route_path,
                    calls=calls,
                    call_types=call_types,
                    has_auth=has_auth,
                )
            )

    return routes, function_map


def parse_routes_from_file(file_path: Path) -> list[RouteInfo]:
    routes, _function_map = parse_file_data(file_path)
    return routes


def parse_routes_with_calls(file_path: Path) -> list[dict[str, str | list[str]]]:
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    parsed_routes: list[dict[str, str | list[str]]] = []

    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        decorators = _extract_route_decorators(node)
        if not decorators:
            continue

        calls = _collect_calls(node)
        for method, route_path, _decorator in decorators:
            parsed_routes.append(
                {
                    "route": route_path,
                    "method": method.upper(),
                    "function": node.name,
                    "calls": calls,
                }
            )

    return parsed_routes


def parse_import_map(file_path: Path) -> dict[str, str]:
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    import_map: dict[str, str] = {}

    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                key = alias.asname or alias.name.split(".", 1)[0]
                import_map[key] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                key = alias.asname or alias.name
                import_map[key] = f"{module}.{alias.name}" if module else alias.name

    return import_map


def parse_class_and_instance_maps(
    file_path: Path,
) -> tuple[
    dict[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]],
    dict[str, str],
]:
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    import_map = parse_import_map(file_path)
    class_map: dict[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    instance_map: dict[str, str] = {}

    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods[member.name] = member
            class_map[node.name] = methods

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call):
            continue

        constructor_name = _constructor_name(node.value.func, import_map)
        if not constructor_name:
            continue

        for target in node.targets:
            if isinstance(target, ast.Name):
                instance_map[target.id] = constructor_name

    return class_map, instance_map


def _extract_route_decorators(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[str, str, ast.Call]]:
    matches: list[tuple[str, str, ast.Call]] = []

    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        if not isinstance(decorator.func, ast.Attribute):
            continue
        method = decorator.func.attr.lower()
        if method not in HTTP_METHODS:
            continue
        route_path = _first_string_arg(decorator.args) or ""
        if not route_path:
            continue
        matches.append((method, route_path, decorator))

    return matches


def _collect_calls(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    collector = CallCollector()
    for stmt in node.body:
        collector.visit(stmt)
    return collector.calls


def collect_calls(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return _collect_calls(node)


def _classify_calls(calls: list[str]) -> list[tuple[str, str]]:
    classified: list[tuple[str, str]] = []
    for call_name in calls:
        call_type = "SERVICE" if "_service" in call_name else "INTERNAL"
        classified.append((call_name, call_type))
    return classified


def _first_string_arg(args: list[ast.expr]) -> str | None:
    if not args:
        return None
    first = args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def _has_auth(node: ast.FunctionDef | ast.AsyncFunctionDef, decorator: ast.Call) -> bool:
    if _dependencies_have_depends(decorator):
        return True

    for arg in node.args.args:
        default_node = _default_for_arg(node, arg.arg)
        if isinstance(default_node, ast.Call) and _call_name(default_node.func) == "Depends":
            return True
    return False


def _default_for_arg(
    node: ast.FunctionDef | ast.AsyncFunctionDef, arg_name: str
) -> ast.expr | None:
    all_args = node.args.args
    defaults = node.args.defaults
    if not defaults:
        return None

    first_default_index = len(all_args) - len(defaults)
    for idx, arg in enumerate(all_args):
        if arg.arg != arg_name:
            continue
        if idx < first_default_index:
            return None
        return defaults[idx - first_default_index]
    return None


def _dependencies_have_depends(decorator: ast.Call) -> bool:
    for keyword in decorator.keywords:
        if keyword.arg != "dependencies":
            continue
        if isinstance(keyword.value, (ast.List, ast.Tuple)):
            for element in keyword.value.elts:
                if isinstance(element, ast.Call) and _call_name(element.func) == "Depends":
                    return True
    return False


def _depends_target_looks_auth(depends_call: ast.Call) -> bool:
    if not depends_call.args:
        return False
    target_name = _call_name(depends_call.args[0])
    if not target_name:
        return False
    lower = target_name.lower()
    return any(hint in lower for hint in AUTH_HINTS)


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return None


def _constructor_name(node: ast.AST, import_map: dict[str, str]) -> str | None:
    call_name = _call_name(node)
    if not call_name:
        return None

    if "." in call_name:
        alias, suffix = call_name.split(".", 1)
        mapped = import_map.get(alias, alias)
        resolved = f"{mapped}.{suffix}"
    else:
        resolved = import_map.get(call_name, call_name)

    return resolved.rsplit(".", 1)[-1]

