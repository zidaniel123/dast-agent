"""Central configuration and shared factories for the DAST agent.

Everything environment-derived lives on the frozen ``Settings`` dataclass, and
the two runtime resources that both phases need -- the Playwright MCP browser
and the LLM model handle -- are built from the factories here so they are
defined in exactly one place.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()

# The default points at the gateway model id currently in use. It is fully
# replaceable: set DAST_MODEL (or pass --model) to any model your gateway
# exposes through the OpenAI-compatible API.
DEFAULT_MODEL = "openai-responses/gpt-5.6-luna"

# Playwright MCP process definition. Runs a headless, isolated Chromium so the
# agent drives a real browser without touching a developer's profile.
PLAYWRIGHT_MCP_ARGS = [
    "@playwright/mcp@latest",
    "--headless",
    "--isolated",
    "--browser=chromium",
    "--no-sandbox",
    "--ignore-https-errors",
    # Uncomment to route traffic through an intercepting proxy for review:
    # "--proxy-server=http://127.0.0.1:8080",
]


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings resolved from the environment."""

    api_key: str | None
    base_url: str | None
    model: str
    max_turns: int = 50
    mcp_timeout_seconds: int = 600

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            api_key=os.getenv("OPENAI_API_KEY"),
            base_url=os.getenv("OPENAI_API_BASE"),
            model=os.getenv("DAST_MODEL") or DEFAULT_MODEL,
            max_turns=int(os.getenv("DAST_MAX_TURNS", "50")),
            mcp_timeout_seconds=int(os.getenv("DAST_MCP_TIMEOUT", "600")),
        )


def build_browser(settings: Settings | None = None):
    """Build the Playwright MCP stdio server used by both phases.

    Imported lazily so that modules which only need ``Settings`` (or that run in
    environments without the ``agents`` package installed) stay importable.
    """

    from agents.mcp import MCPServerStdio

    timeout = settings.mcp_timeout_seconds if settings else 600
    return MCPServerStdio(
        name="playwright",
        params={
            "command": "npx",
            "args": list(PLAYWRIGHT_MCP_ARGS),
        },
        client_session_timeout_seconds=timeout,
    )


def build_model(settings: Settings):
    """Build the OpenAI-compatible chat-completions model handle."""

    from openai import AsyncOpenAI
    from agents import OpenAIChatCompletionsModel

    openai_conn = AsyncOpenAI(api_key=settings.api_key, base_url=settings.base_url)
    return OpenAIChatCompletionsModel(model=settings.model, openai_client=openai_conn)
