from __future__ import annotations

import json
import sys

from accessguard.core.analyzer import AnalysisResult
from accessguard.core.rules import clean_node


def print_text_report(result: AnalysisResult, quiet: bool = False) -> None:
    _ensure_utf8_stdout()
    high_count = sum(1 for risk in result.risks if risk.severity == "HIGH")
    medium_count = sum(1 for risk in result.risks if risk.severity == "MEDIUM")
    low_count = sum(1 for risk in result.risks if risk.severity == "LOW")
    path_by_route = {
        str(item["route"]): item for item in result.sensitive_paths if "route" in item
    }

    if quiet:
        _print_risks(result)
        return

    print("=== AccessGuard Report ===")
    print("")
    print("Summary:")
    print(f"  Routes scanned: {len(result.routes)}")
    print(f"  Risks found: {high_count} HIGH / {medium_count} MEDIUM / {low_count} LOW")

    print("")
    print("Routes:")
    for route in result.routes:
        route_key = f"{route.method} {route.path}"
        calls = ", ".join(route.calls) if route.calls else "(no calls)"
        auth_state = "yes" if route.has_auth else "no"
        print(f"  {route_key}")
        print(f"    Handler: {route.handler_name}")
        print(f"    Auth: {auth_state}")
        print(f"    Calls: {calls}")

    print("")
    print("Graph (simplified):")
    for route in result.routes:
        route_key = f"{route.method} {route.path}"
        path_item = path_by_route.get(route_key)
        if path_item:
            flow = _flow_from_path(route_key, path_item["path"])
        else:
            flow = " -> ".join([route_key, route.handler_name, *route.calls])
        print(f"  {flow}")

    print("")
    print("Sensitive Paths:")
    if not result.sensitive_paths:
        print("  (none found)")
    else:
        for item in result.sensitive_paths:
            route_key = str(item["route"])
            resource = clean_node(str(item["sensitive_node"]))
            flow = _flow_from_path(route_key, item["path"])
            print(f"  {route_key}")
            print(f"    Resource: {resource}")
            print("    Flow:")
            print(f"      {flow}")

    print("")
    _print_risks(result)


def print_json_report(result: AnalysisResult) -> None:
    payload = {
        "summary": {
            "routes_scanned": len(result.routes),
            "high": sum(1 for risk in result.risks if risk.severity == "HIGH"),
            "medium": sum(1 for risk in result.risks if risk.severity == "MEDIUM"),
            "low": sum(1 for risk in result.risks if risk.severity == "LOW"),
        },
        "routes": [
            {
                "method": route.method,
                "path": route.path,
                "handler": route.handler_name,
                "auth": route.has_auth,
                "calls": route.calls,
            }
            for route in result.routes
        ],
        "graph": {
            "nodes": sorted(result.graph.get("nodes", [])),
            "edges": [
                {"src": src, "dst": dst, "type": edge_type}
                for src, dst, edge_type in result.graph.get("edges", [])
            ],
        },
        "sensitive_paths": [
            {
                "route": item.get("route"),
                "resource": clean_node(str(item.get("sensitive_node", ""))),
                "path": [clean_node(str(node)) for node in item.get("path", [])],
            }
            for item in result.sensitive_paths
        ],
        "risks": [
            {
                "severity": risk.severity,
                "route": risk.route_key,
                "score": risk.score,
                "reason": risk.reason,
            }
            for risk in result.risks
        ],
    }
    print(json.dumps(payload, indent=2))


def _print_risks(result: AnalysisResult) -> None:
    print("Risks:")
    if not result.risks:
        print("  No risks detected")
        return
    for risk in result.risks:
        print(f"  [{risk.severity}] {risk.route_key} (score: {risk.score})")
        print(f"    {risk.reason}")


def _flow_from_path(route_key: str, path: object) -> str:
    if not isinstance(path, list):
        return route_key
    cleaned_nodes = [clean_node(str(node)) for node in path]
    if not cleaned_nodes:
        return route_key
    flow_nodes = [route_key, *cleaned_nodes[1:]]
    compacted: list[str] = []
    for node in flow_nodes:
        if not compacted or compacted[-1] != node:
            compacted.append(node)
    return " -> ".join(compacted)


def _ensure_utf8_stdout() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
