from __future__ import annotations

from accessguard.core.parser import RouteInfo


def build_graph(routes: list[RouteInfo]) -> dict[str, set[str] | list[tuple[str, str, str]]]:
    nodes: set[str] = set()
    edges: list[tuple[str, str, str]] = []

    for route in routes:
        route_node = f"route:{route.path}"
        func_node = f"func:{route.handler_name}"

        nodes.add(route_node)
        nodes.add(func_node)
        edges.append((route_node, func_node, "ROUTE_TO_FUNC"))

        for call_name in route.calls:
            call_node = f"call:{call_name}"
            nodes.add(call_node)
            edges.append((func_node, call_node, "FUNC_TO_CALL"))

    return {"nodes": nodes, "edges": edges}

