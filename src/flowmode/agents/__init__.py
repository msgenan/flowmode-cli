"""Per-CLI adapters: every Claude/Codex wire format lives in one module per CLI (S2 §6)."""

from pathlib import Path
from typing import Protocol

from flowmode.hooks import HookRequest, HookResponse, HookResult
from flowmode.member_config import MemberConfig

AGENTS = ("claude", "codex")


class Adapter(Protocol):
    name: str

    def parse(self, event: str, stdin_text: str) -> HookRequest: ...

    def render(self, req: HookRequest, resp: HookResponse) -> HookResult: ...

    def install(self, repo: Path, cfg: MemberConfig) -> tuple[list[Path], list[str]]: ...


def get_adapter(agent: str) -> Adapter:
    if agent == "claude":
        from flowmode.agents.claude import ClaudeAdapter

        return ClaudeAdapter()
    if agent == "codex":
        from flowmode.agents.codex import CodexAdapter

        return CodexAdapter()
    raise ValueError(f"no adapter for agent {agent!r}")
