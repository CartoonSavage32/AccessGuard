from __future__ import annotations

from pathlib import Path

DEFAULT_CONFIG: dict[str, list[str]] = {
    "sensitive_keywords": ["billing", "token", "auth", "secret"],
    "high_privilege_keywords": ["admin", "delete", "reset", "token", "decrypt", "billing"],
    "safe_routes": ["auth", "callback", "oauth", "login"],
}


def load_config(project_path: Path) -> tuple[dict[str, list[str]], bool]:
    """
    Load accessguard.yaml from project root and merge with defaults.

    Returns:
        (config, loaded_from_file)
    """
    config = {key: list(values) for key, values in DEFAULT_CONFIG.items()}
    config_path = project_path / "accessguard.yaml"
    if not config_path.exists():
        return config, False

    raw_config = _parse_simple_yaml(config_path.read_text(encoding="utf-8"))
    for key in DEFAULT_CONFIG:
        raw_value = raw_config.get(key)
        if isinstance(raw_value, list):
            cleaned = [str(item).strip() for item in raw_value if str(item).strip()]
            if cleaned:
                config[key] = cleaned

    return config, True


def _parse_simple_yaml(content: str) -> dict[str, list[str]]:
    """
    Parse a simple YAML file with top-level list keys.

    Expected format:
      key:
        - value
        - value2
    """
    parsed: dict[str, list[str]] = {}
    current_key: str | None = None

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.endswith(":") and not line.startswith("- "):
            current_key = line[:-1].strip()
            if current_key:
                parsed.setdefault(current_key, [])
            continue

        if line.startswith("- ") and current_key:
            value = line[2:].strip()
            if value:
                parsed.setdefault(current_key, []).append(value)

    return parsed
