"""SDK exceptions."""

from __future__ import annotations

from typing import Any


class SentinelError(Exception):
    """Raised for non-2xx responses. Carries the server's safe error code and request id."""

    def __init__(self, status: int, code: str, message: str, request_id: str | None = None, details: Any = None):
        super().__init__(f"[{status} {code}] {message} (request_id={request_id})")
        self.status = status
        self.code = code
        self.message = message
        self.request_id = request_id
        self.details = details


class BlockedError(Exception):
    """Raised by ``secure_chat`` when ``raise_on_block=True`` and the firewall blocked the request."""

    def __init__(self, result: Any):
        super().__init__(f"Request blocked by SentinelLLM (decision={result.decision}, request_id={result.request_id})")
        self.result = result
