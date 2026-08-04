"""Central configuration and shared factories for the DAST agent.

Everything environment-derived lives on the frozen ``Settings`` dataclass, and
the two runtime resources that both phases need -- the Playwright MCP browser
and the LLM model handle -- are built from the factories here so they are
defined in exactly one place.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()

# No built-in model id: a hard-coded gateway-specific default silently fails for
# anyone whose gateway does not expose that exact name. Set DAST_MODEL in .env or
# pass --model.
DEFAULT_MODEL = "gpt-4o"

# Playwright MCP process definition. Runs a headless, isolated Chromium so the
# agent drives a real browser without touching a developer's profile.
BASE_PLAYWRIGHT_ARGS = [
    "@playwright/mcp@latest",
    "--headless",
    "--isolated",
    "--browser=chromium",
]


def _flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    """Read an integer setting, failing with a useful message rather than a traceback."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"{name} must be an integer, got {raw!r}") from None


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings resolved from the environment."""

    # repr=False so the key cannot land in a log line, traceback frame, or
    # exception message that happens to render this dataclass.
    api_key: str | None = field(repr=False)
    base_url: str | None
    model: str
    max_turns: int = 50
    mcp_timeout_seconds: int = 600

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            api_key=os.getenv("OPENAI_API_KEY"),
            # An empty OPENAI_API_BASE must mean "use the default endpoint".
            # Passing "" straight to AsyncOpenAI makes every request fail, and
            # .env.example ships the variable blank.
            base_url=os.getenv("OPENAI_API_BASE") or None,
            model=os.getenv("DAST_MODEL") or DEFAULT_MODEL,
            max_turns=_int_env("DAST_MAX_TURNS", 50),
            mcp_timeout_seconds=_int_env("DAST_MCP_TIMEOUT", 600),
        )


def playwright_args(allowed_origins: str | None = None) -> list[str]:
    """Assemble the Playwright MCP argv for this run.

    ``allowed_origins`` is the scope fence: the browser refuses navigation
    outside it, so a redirect or an injected link in the target application
    cannot walk the scan onto a third party's site. This is a real control, not
    a prompt instruction the model may ignore.
    """
    args = list(BASE_PLAYWRIGHT_ARGS)
    if allowed_origins:
        args.append(f"--allowed-origins={allowed_origins}")
    # Both of the following weaken the browser and are therefore opt-in.
    # --no-sandbox disables the Chromium sandbox, which is the main thing
    # standing between a malicious page and the host.
    if _flag("DAST_BROWSER_NO_SANDBOX"):
        args.append("--no-sandbox")
    # Accepting invalid certificates is common on staging, but it also means the
    # scan cannot detect TLS misconfiguration and is open to interception.
    if _flag("DAST_IGNORE_HTTPS_ERRORS"):
        args.append("--ignore-https-errors")
    if proxy := os.getenv("DAST_PROXY_SERVER"):
        args.append(f"--proxy-server={proxy}")
    return args


def build_browser(settings: Settings | None = None, allowed_origins: str | None = None):
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
            "args": playwright_args(allowed_origins),
        },
        client_session_timeout_seconds=timeout,
    )


def build_model(settings: Settings):
    """Build the OpenAI-compatible chat-completions model handle."""

    from agents import OpenAIChatCompletionsModel
    from openai import AsyncOpenAI

    openai_conn = AsyncOpenAI(api_key=settings.api_key, base_url=settings.base_url)
    return OpenAIChatCompletionsModel(model=settings.model, openai_client=openai_conn)
