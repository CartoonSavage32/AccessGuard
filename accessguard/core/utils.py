from __future__ import annotations

from pathlib import Path


def load_ignore_patterns(ignore_file: Path, defaults: list[str]) -> list[str]:
    """Load line-based ignore patterns from .accessguardignore."""
    patterns = list(defaults)
    if not ignore_file.exists():
        return patterns

    for line in ignore_file.read_text(encoding="utf-8").splitlines():
        pattern = line.strip()
        if not pattern or pattern.startswith("#"):
            continue
        patterns.append(pattern)
    return patterns
