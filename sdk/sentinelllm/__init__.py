"""SentinelLLM Python SDK.

    from sentinelllm import Sentinel

    firewall = Sentinel(base_url="http://localhost:8000")
    response = firewall.secure_chat(message="Explain machine learning", provider="ollama", model="qwen2.5:3b")
    print(response.text)
    print(response.security.decision)
"""

from sentinelllm.client import AsyncSentinel, Sentinel
from sentinelllm.exceptions import BlockedError, SentinelError

__all__ = ["Sentinel", "AsyncSentinel", "SentinelError", "BlockedError"]
__version__ = "0.1.0"
