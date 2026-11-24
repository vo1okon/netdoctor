"""netdoctor package."""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)


def _resolve_version() -> str:
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    try:
        text = pyproject.read_text(encoding="utf-8")
        match = _VERSION_RE.search(text)
        if match:
            return match.group(1).strip()
    except OSError:
        pass
    try:
        return version("netdoctor")
    except PackageNotFoundError:
        return "0.1.0-dev"


__version__ = _resolve_version()
