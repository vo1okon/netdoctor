"""Backward-compatible facade delegating to ``netdoctor.core.engine``.

Keeps ``GuiBackend``, helper exports, and pytest ``monkeypatch`` hooks working seamlessly.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import netdoctor.core.engine as _engine_mod
from netdoctor.core.engine import (
    DEFAULT_NETWORK_KEY,
    LOG_FILENAMES,
    MAX_PREVIEW_BYTES,
    NetdoctorEngine,
    T,
    build_elevate_command,
    elevate_gui,
    launch_gui_detached,
    resolve_gui_launcher,
)

GuiBackend = NetdoctorEngine

_FORWARD_ALIAS: dict[str, str] = {"GuiBackend": "NetdoctorEngine"}

# Mirror engine module namespace into __dict__ so pytest monkeypatch.setattr finds old values in __dict__.
for _k, _v in _engine_mod.__dict__.items():
    if not (_k.startswith("__") and _k.endswith("__")):
        globals().setdefault(_k, _v)


class _EngineProxyModule(types.ModuleType):
    def __getattr__(self, name: str) -> Any:
        target = _FORWARD_ALIAS.get(name, name)
        return getattr(_engine_mod, target)

    def __setattr__(self, name: str, value: Any) -> None:
        super().__setattr__(name, value)
        if not (name.startswith("__") and name.endswith("__")):
            target = _FORWARD_ALIAS.get(name, name)
            setattr(_engine_mod, target, value)

    def __delattr__(self, name: str) -> None:
        if name in self.__dict__:
            super().__delattr__(name)


sys.modules[__name__].__class__ = _EngineProxyModule
