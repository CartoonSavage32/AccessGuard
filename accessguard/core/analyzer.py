from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from accessguard.core.config import DEFAULT_CONFIG
from accessguard.core.graph import build_graph
from accessguard.core.parser import (
    RouteInfo,
    parse_class_and_instance_maps,
    parse_file_data,
    parse_import_map,
)
from accessguard.core.rules import Risk, detect_risks, detect_sensitive_paths

DEFAULT_IGNORE_PATTERNS = ["venv/", "__pycache__/", "node_modules/"]


@dataclass(slots=True)
class AnalysisResult:
    routes: list[RouteInfo]
    risks: list[Risk]
    graph: dict[str, set[str] | list[tuple[str, str, str]]]
    function_map: dict[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]
    import_maps: dict[str, dict[str, str]]
    class_map: dict[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]]
    class_file_map: dict[str, str]
    instance_maps: dict[str, dict[str, str]]
    sensitive_paths: list[dict[str, str | list[str]]]


def analyze_project(
    project_path: Path, config: dict[str, list[str]] | None = None
) -> AnalysisResult:
    effective_config = config or {key: list(values) for key, values in DEFAULT_CONFIG.items()}
    file_paths = _python_files(project_path)
    function_map = _build_function_map(file_paths)
    import_maps = _build_import_maps(file_paths)
    class_map, class_file_map, instance_maps = _build_class_and_instance_maps(file_paths)

    routes: list[RouteInfo] = []
    for file_path in file_paths:
        file_routes, _file_function_map = parse_file_data(file_path)
        routes.extend(file_routes)

    graph = build_graph(routes)
    sensitive_paths = detect_sensitive_paths(
        graph=graph,
        routes=routes,
        function_map=function_map,
        import_maps=import_maps,
        class_map=class_map,
        instance_maps=instance_maps,
        config=effective_config,
    )
    risks = detect_risks(routes, sensitive_paths, effective_config)
    return AnalysisResult(
        routes=routes,
        risks=risks,
        graph=graph,
        function_map=function_map,
        import_maps=import_maps,
        class_map=class_map,
        class_file_map=class_file_map,
        instance_maps=instance_maps,
        sensitive_paths=sensitive_paths,
    )


def _python_files(root: Path) -> list[Path]:
    ignore_patterns = _load_ignore_patterns(root)
    files: list[Path] = []

    for path in root.rglob("*.py"):
        if not path.is_file():
            continue
        if _is_ignored(path, ignore_patterns):
            continue
        files.append(path)

    return files


def _load_ignore_patterns(root: Path) -> list[str]:
    patterns = list(DEFAULT_IGNORE_PATTERNS)
    ignore_file = root / ".accessguardignore"
    if not ignore_file.exists():
        return patterns

    for line in ignore_file.read_text(encoding="utf-8").splitlines():
        pattern = line.strip()
        if not pattern or pattern.startswith("#"):
            continue
        patterns.append(pattern)
    return patterns


def _is_ignored(path: Path, patterns: list[str]) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    for pattern in patterns:
        if pattern.lower() in normalized:
            return True
    return False


def _build_function_map(
    file_paths: list[Path],
) -> dict[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    function_map: dict[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}

    for file_path in file_paths:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_map[node.name] = (str(file_path), node)

    return function_map


def _build_import_maps(file_paths: list[Path]) -> dict[str, dict[str, str]]:
    import_maps: dict[str, dict[str, str]] = {}
    for file_path in file_paths:
        import_maps[str(file_path)] = parse_import_map(file_path)
    return import_maps


def _build_class_and_instance_maps(
    file_paths: list[Path],
) -> tuple[
    dict[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]],
    dict[str, str],
    dict[str, dict[str, str]],
]:
    class_map: dict[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    class_file_map: dict[str, str] = {}
    instance_maps: dict[str, dict[str, str]] = {}

    for file_path in file_paths:
        file_class_map, file_instance_map = parse_class_and_instance_maps(file_path)
        instance_maps[str(file_path)] = file_instance_map

        for class_name, methods in file_class_map.items():
            class_map[class_name] = methods
            class_file_map[class_name] = str(file_path)

    return class_map, class_file_map, instance_maps

