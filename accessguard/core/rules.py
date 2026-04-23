from __future__ import annotations

import ast
from dataclasses import dataclass

from accessguard.core.parser import RouteInfo, collect_calls


SENSITIVE_NODE_KEYWORDS = {"database", "billing", "admin", "token", "decrypt", "reset"}
SENSITIVE_KEYWORDS = {"billing", "token", "auth", "secret"}
HIGH_PRIV_KEYWORDS = {"admin", "delete", "reset", "token", "decrypt", "billing"}
SAFE_ROUTE_KEYWORDS = {"auth", "callback", "oauth", "login"}
SAFE_RESOURCE_KEYWORDS = {"token", "encrypt", "decrypt"}


@dataclass(slots=True)
class Risk:
    severity: str
    route_key: str
    reason: str
    score: int


def clean_node(node: str) -> str:
    return node.split(":", 1)[-1]


def detect_risks(
    routes: list[RouteInfo], sensitive_paths: list[dict[str, str | list[str]]]
) -> list[Risk]:
    risks: list[Risk] = []
    route_by_key = {f"{route.method} {route.path}": route for route in routes}

    for path_risk in sensitive_paths:
        route_key = str(path_risk["route"])
        sensitive_node = str(path_risk["sensitive_node"])
        resource = clean_node(sensitive_node)
        path = path_risk.get("path", [])
        route = route_by_key.get(route_key)

        if route is None:
            continue

        route_domain = _extract_route_domain(route.path)
        access_domains = _extract_access_domains(path)
        detected_domain = _detect_domain(access_domains, resource)
        is_mismatch = route_domain not in access_domains if route_domain else True
        is_route_admin = "admin" in route.path.lower()
        is_high_priv_resource = _access_privilege(resource) == "HIGH"
        is_allowlisted = _is_allowlisted(route.path, resource)
        is_sensitive = _has_sensitive_access(path)

        # Apply both signals to every sensitive path.
        if is_allowlisted:
            risks.append(
                Risk(
                    severity="LOW",
                    route_key=route_key,
                    reason="Sensitive access appears expected for this route",
                    score=1,
                )
            )
        elif (not is_route_admin and is_high_priv_resource) or is_mismatch:
            severity = "HIGH" if not route.has_auth else "MEDIUM"
            score = 6 if severity == "HIGH" else 4
            risks.append(
                Risk(
                    severity=severity,
                    route_key=route_key,
                    reason=(
                        f"Potential privilege escalation: route '{route.path}' "
                        f"accesses sensitive operation '{resource}'. Verify this is intended."
                    ),
                    score=score,
                )
            )
        elif is_sensitive:
            severity = "HIGH" if not route.has_auth else "MEDIUM"
            score = 5 if severity == "HIGH" else 3
            risks.append(
                Risk(
                    severity=severity,
                    route_key=route_key,
                    reason=(
                        f"Route '{route.path}' accesses '{detected_domain}' "
                        f"domain via {resource}"
                    ),
                    score=score,
                )
            )

    return _dedupe_risks_by_route_key(risks)


def _has_sensitive_access(path: object) -> bool:
    if not isinstance(path, list):
        return False

    for raw in path:
        node = clean_node(str(raw)).lower()
        if "db." in node:
            return True
        if any(keyword in node for keyword in SENSITIVE_KEYWORDS):
            return True
    return False


def _extract_route_domain(route_path: str) -> str:
    for segment in route_path.split("/"):
        if not segment:
            continue
        if segment.startswith("{") and segment.endswith("}"):
            continue
        return segment.lower()
    return ""


def _extract_access_domains(path: object) -> set[str]:
    domains: set[str] = set()
    if not isinstance(path, list):
        return domains

    for raw in path:
        raw_node = str(raw).lower()
        if raw_node.startswith("route:") or raw_node.startswith("func:"):
            continue
        node = clean_node(raw_node)
        for dot_part in node.replace("-", "_").split("."):
            for token in dot_part.split("_"):
                clean = token.strip("{}[]() ")
                if clean:
                    domains.add(clean)
    return domains


def _detect_domain(access_domains: set[str], resource: str) -> str:
    for keyword in SENSITIVE_KEYWORDS:
        if keyword in access_domains or keyword in resource.lower():
            return keyword
    if "db" in access_domains or "db." in resource.lower():
        return "db"
    if access_domains:
        return sorted(access_domains)[0]
    return "unknown"


def _access_privilege(resource: str) -> str:
    lower = resource.lower()
    if any(keyword in lower for keyword in HIGH_PRIV_KEYWORDS):
        return "HIGH"
    return "NORMAL"


def _is_allowlisted(route_path: str, resource: str) -> bool:
    route_lower = route_path.lower()
    resource_lower = resource.lower()
    route_safe = any(keyword in route_lower for keyword in SAFE_ROUTE_KEYWORDS)
    resource_safe = any(keyword in resource_lower for keyword in SAFE_RESOURCE_KEYWORDS)
    return route_safe and resource_safe


def detect_sensitive_paths(
    graph: dict[str, set[str] | list[tuple[str, str, str]]],
    routes: list[RouteInfo],
    function_map: dict[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]],
    import_maps: dict[str, dict[str, str]],
    class_map: dict[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]],
    instance_maps: dict[str, dict[str, str]],
) -> list[dict[str, str | list[str]]]:
    edges = graph.get("edges", [])
    adjacency: dict[str, list[str]] = {}
    function_nodes = {name: f"func:{name}" for name in function_map}

    if isinstance(edges, list):
        for src, dst, _etype in edges:
            adjacency.setdefault(src, []).append(dst)

    risks: list[dict[str, str | list[str]]] = []
    for route in routes:
        route_node = f"route:{route.path}"
        route_key = f"{route.method} {route.path}"
        queue: list[tuple[str, list[str], int, str | None]] = [
            (route_node, [route_node], 0, None)
        ]
        visited: set[tuple[str, str | None]] = set()
        best_match: dict[str, str | list[str]] | None = None

        while queue:
            current_node, current_path, depth, current_file = queue.pop(0)
            visit_key = (current_node, current_file)
            if visit_key in visited:
                continue
            visited.add(visit_key)

            if any(word in current_node.lower() for word in SENSITIVE_NODE_KEYWORDS):
                match = {
                    "route": route_key,
                    "path": current_path,
                    "sensitive_node": current_node,
                }
                if best_match is None or len(current_path) > len(best_match["path"]):
                    best_match = match

            if depth > 5:
                continue

            neighbors = list(adjacency.get(current_node, []))
            if current_node.startswith("call:"):
                call_name = current_node.split(":", 1)[1]
                resolved_method = _resolve_class_method(
                    call_name=call_name,
                    current_file=current_file,
                    class_map=class_map,
                    instance_maps=instance_maps,
                )
                if resolved_method:
                    _instance_name, _class_name, _method_name, method_node = resolved_method
                    method_calls = collect_calls(method_node)
                    for c in method_calls:
                        neighbors.append(f"call:{c}")

                next_node = _resolve_node_from_call(
                    call_name=call_name,
                    current_file=current_file,
                    function_nodes=function_nodes,
                    import_maps=import_maps,
                )
                if next_node:
                    neighbors.append(next_node)
            elif current_node.startswith("func:"):
                func_name = current_node.split(":", 1)[1]
                meta = function_map.get(func_name)
                if meta:
                    _file_path, func_node = meta
                    for call_name in collect_calls(func_node):
                        neighbors.append(f"call:{call_name}")

            for neighbor in neighbors:
                next_path = [*current_path, neighbor]
                if any(word in neighbor.lower() for word in SENSITIVE_NODE_KEYWORDS):
                    match = {
                        "route": route_key,
                        "path": next_path,
                        "sensitive_node": neighbor,
                    }
                    if best_match is None or len(next_path) > len(best_match["path"]):
                        best_match = match
                next_file = _node_file(neighbor, function_map) or current_file
                queue.append((neighbor, next_path, depth + 1, next_file))

        if best_match:
            risks.append(best_match)

    return risks


def _dedupe_risks_by_route_key(risks: list[Risk]) -> list[Risk]:
    severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    deduped: dict[str, Risk] = {}

    for risk in risks:
        existing = deduped.get(risk.route_key)
        if existing is None:
            deduped[risk.route_key] = risk
            continue
        if risk.score > existing.score:
            deduped[risk.route_key] = risk
            continue
        if risk.score == existing.score and severity_rank.get(
            risk.severity, 0
        ) > severity_rank.get(existing.severity, 0):
            deduped[risk.route_key] = risk

    return list(deduped.values())


def _resolve_node_from_call(
    call_name: str,
    current_file: str | None,
    function_nodes: dict[str, str],
    import_maps: dict[str, dict[str, str]],
) -> str | None:
    candidates = [call_name]
    if "." in call_name:
        candidates.append(call_name.rsplit(".", 1)[1])

    if current_file:
        file_import_map = import_maps.get(current_file, {})
        resolved = _resolve_call_via_imports(call_name, file_import_map)
        if resolved:
            candidates.append(resolved)
            if "." in resolved:
                candidates.append(resolved.rsplit(".", 1)[1])

    for candidate in candidates:
        node = function_nodes.get(candidate)
        if node:
            return node
    return None


def _resolve_class_method(
    call_name: str,
    current_file: str | None,
    class_map: dict[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]],
    instance_maps: dict[str, dict[str, str]],
) -> tuple[str, str, str, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    if not current_file or "." not in call_name:
        return None

    instance_name, method_name = call_name.split(".", 1)
    class_name = instance_maps.get(current_file, {}).get(instance_name)
    if not class_name:
        return None
    method_node = class_map.get(class_name, {}).get(method_name)
    if method_node is None:
        return None
    return (instance_name, class_name, method_name, method_node)


def _resolve_call_via_imports(call_name: str, import_map: dict[str, str]) -> str | None:
    alias = call_name.split(".", 1)[0]
    target = import_map.get(alias)
    if not target:
        return None
    if "." in call_name:
        suffix = call_name.split(".", 1)[1]
        return f"{target}.{suffix}"
    return target


def _node_file(
    node: str,
    function_map: dict[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]],
) -> str | None:
    if not node.startswith("func:"):
        return None
    func_name = node.split(":", 1)[1]
    meta = function_map.get(func_name)
    if not meta:
        return None
    return meta[0]



