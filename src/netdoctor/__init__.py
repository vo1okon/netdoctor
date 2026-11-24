"""netdoctor package."""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)


def _resolve_version() -> str:
    try:
        return version("netdoctor")
    except PackageNotFoundError:
        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        try:
            text = pyproject.read_text(encoding="utf-8")
        except OSError:
            return "0.1.0-dev"
        match = _VERSION_RE.search(text)
        return match.group(1).strip() if match else "0.1.0-dev"


__version__ = _resolve_version()
