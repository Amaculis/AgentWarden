"""Agent adapters (spec 027): translate a foreign agent's hook payload into the Claude Code shape.

The canonical event is the Claude Code payload; everything after the daemon's entry (rules,
policy, judge, eval) only knows Claude tool names. Each module in this package that defines
`ADAPTER` is registered under `ADAPTER.name`; the hook names the agent in the
`X-AgentWarden-Agent` header.
"""

from __future__ import annotations

import functools
import importlib
import logging
import pkgutil
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

logger = logging.getLogger("agentwarden.agents")

DEFAULT_AGENT = "claude_code"
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

EventKind = Literal["tool", "read", "prompt"]


class AdapterError(ValueError):
    """Unknown agent or a payload the adapter cannot translate safely."""


@dataclass(frozen=True)
class Adapter:
    """Declarative translation; subclass and override `normalize` for anything stranger.

    `tool_map`: foreign tool name -> canonical (Claude Code) tool name.
    `input_map`: canonical tool -> {foreign `tool_input` field: canonical field}.
    `config_paths`: path components of this agent's hook config (a file or a directory);
    they are hard-denied for writes whatever agent is running.
    `passthrough`: payloads are already canonical; unknown tools go to the judge.
    """

    name: str
    tool_map: Mapping[str, str]
    input_map: Mapping[str, Mapping[str, str]]
    config_paths: tuple[tuple[str, ...], ...]
    passthrough: bool = False
    field_aliases: Mapping[str, str] = field(default_factory=dict)
    event_names: Mapping[str, str] = field(default_factory=dict)
    # Agent bookkeeping tools with no side effects; the rules allow `<agent>:<tool>` for these.
    internal_tools: frozenset[str] = frozenset()

    def normalize(self, kind: EventKind, body: dict[str, Any]) -> dict[str, Any]:
        """A new dict in the Claude Code shape. Raises `AdapterError` on an ambiguous payload."""
        if self.passthrough:
            return body
        out = dict(body)
        for foreign, canonical in self.field_aliases.items():
            if foreign in out and canonical not in out:
                out[canonical] = out.pop(foreign)
        event_name = out.get("hook_event_name")
        if isinstance(event_name, str) and event_name in self.event_names:
            out["hook_event_name"] = self.event_names[event_name]
        if kind == "prompt":
            return out
        tool = out.get("tool_name")
        if not isinstance(tool, str):
            return out  # the model validation rejects it
        canonical_tool = self.tool_map.get(tool)
        if canonical_tool is None:
            # Never a Claude tool name: the rules `ask` it instead of guessing what it does.
            out["tool_name"] = f"{self.name}:{tool}"
            return out
        tool_input = out.get("tool_input", {})
        if not isinstance(tool_input, dict):
            raise AdapterError(f"{self.name}: tool_input is not an object")
        translated = dict(tool_input)
        for foreign, canonical in self.input_map.get(canonical_tool, {}).items():
            if foreign not in translated:
                continue
            value = translated.pop(foreign)
            if canonical in translated and translated[canonical] != value:
                raise AdapterError(f"{self.name}: both {foreign!r} and {canonical!r} given")
            translated[canonical] = value
        out["tool_name"] = canonical_tool
        out["tool_input"] = translated
        out["agent_tool_name"] = tool
        return out


def _module_names() -> list[str]:
    return sorted(m.name for m in pkgutil.iter_modules(__path__) if not m.name.startswith("_"))


def discover() -> dict[str, Adapter]:
    """Import every adapter module; a broken one is logged and left out, never fatal."""
    found: dict[str, Adapter] = {}
    for module_name in _module_names():
        try:
            module = importlib.import_module(f"{__name__}.{module_name}")
        except Exception:
            logger.exception("agent adapter %s failed to import", module_name)
            continue
        adapter = getattr(module, "ADAPTER", None)
        if not isinstance(adapter, Adapter):
            continue
        if not NAME_RE.match(adapter.name) or adapter.name in found:
            logger.error("agent adapter %s has an invalid or duplicate name", module_name)
            continue
        found[adapter.name] = adapter
    return found


@functools.cache
def registry() -> Mapping[str, Adapter]:
    return discover()


def get_adapter(name: str | None) -> Adapter:
    if not name:
        name = DEFAULT_AGENT
    if not NAME_RE.match(name):
        raise AdapterError("malformed agent name")
    adapter = registry().get(name)
    if adapter is None:
        raise AdapterError(f"unknown agent {name!r}")
    return adapter


def all_config_paths() -> tuple[tuple[str, ...], ...]:
    """Lower-cased config path patterns of every registered agent."""
    paths: dict[tuple[str, ...], None] = {}
    for adapter in registry().values():
        for parts in adapter.config_paths:
            paths[tuple(p.lower() for p in parts)] = None
    return tuple(paths)
