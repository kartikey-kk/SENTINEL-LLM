"""Lightweight response wrappers with attribute access (no pydantic dependency)."""

from __future__ import annotations

from typing import Any


class AttrDict(dict):
    """dict that also supports ``obj.key`` access, recursively."""

    def __getattr__(self, name: str) -> Any:
        try:
            return _wrap(self[name])
        except KeyError:
            raise AttributeError(name) from None

    def __getitem__(self, key: Any) -> Any:
        return _wrap(super().__getitem__(key))


def _wrap(value: Any) -> Any:
    if isinstance(value, dict) and not isinstance(value, AttrDict):
        return AttrDict(value)
    if isinstance(value, list):
        return [_wrap(v) for v in value]
    return value


class Result(AttrDict):
    """Base class for API results. ``.raw`` returns the underlying JSON dict."""

    @property
    def raw(self) -> dict[str, Any]:
        return dict(self)

    @property
    def request_id(self) -> str | None:
        return self.get("request_id")


class ChatResult(Result):
    @property
    def text(self) -> str:
        return self["text"]

    @property
    def blocked(self) -> bool:
        return bool(self["blocked"])

    @property
    def security(self) -> AttrDict:
        return self["security"]

    @property
    def decision(self) -> str:
        return self["security"]["decision"]


class InputInspection(Result):
    @property
    def decision(self) -> str:
        return self["decision"]

    @property
    def sanitized_text(self) -> str:
        return self["sanitized_text"]

    @property
    def risk_score(self) -> float:
        return float(self["risk"]["score"])

    @property
    def forwardable(self) -> bool:
        return bool(self["forwardable"])


class OutputInspection(Result):
    @property
    def decision(self) -> str:
        return self["decision"]

    @property
    def sanitized_text(self) -> str | None:
        return self.get("sanitized_text")


class ContextInspection(Result):
    @property
    def decision(self) -> str:
        return self["decision"]

    @property
    def safe_chunks(self) -> list[AttrDict]:
        return [c for c in self["chunks"] if c["included"]]


class ToolDecision(Result):
    @property
    def decision(self) -> str:
        return self["decision"]

    @property
    def allowed(self) -> bool:
        return self["decision"] == "ALLOW"
