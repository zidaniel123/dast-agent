"""DAST agent entry point.

Orchestrates a two-phase authenticated dynamic scan:

    walk   -> log in with the test account, enumerate in-scope features, and
              emit WSTG-style security test cases (structured WalkFeatures).
    pentest -> execute the in-scope test cases against the running app, tag every
              request with the X-Pentest-Case header, and emit a structured
              vulnerability report with HTTP request/response evidence.

Behavioral instructions come from skills/<phase>/SKILL.md; runtime context
(target, scope, credentials, OpenAPI inventory) is composed on top at run time.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import sys
from pathlib import Path
from urllib.parse import urlparse

from loguru import logger

from config import Settings, build_browser, build_model
from openapi import build_endpoint_inventory
from schemas import (
    WalkFeatures,
    WalkVulns,
    features_to_markdown,
    vulns_to_markdown,
)
from skills import load_skill, reference_appendix, skill


def _configure_logging() -> None:
    """Install a log sink that cannot print local variables.

    loguru's default sink runs with ``diagnose=True``, so any exception inside a
    ``@logger.catch`` frame prints the values of locals in that frame — which
    here includes ``Settings`` and therefore the gateway API key, plus whatever
    test-account credentials were passed in auth notes.
    """
    logger.remove()
    logger.add(sys.stderr, backtrace=False, diagnose=False)


def _phase_instructions(name: str) -> str:
    """Skill body plus the reference documents that phase cites."""
    phase = skill(name)
    return (
        load_skill(phase.skill_path)
        + "\n\n## Reference appendix\n\n"
        + "The specifications cited above are inlined here and are authoritative.\n\n"
        + reference_appendix(phase.references)
    )


def _origin(base_url: str) -> str:
    """Scheme + host + port of the target, used as the browser's navigation fence."""
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SystemExit(
            f"--base-url must be an absolute http(s) URL, got {base_url!r}"
        )
    return f"{parsed.scheme}://{parsed.netloc}"


# --------------------------------------------------------------------------- #
# Prompt composition
# --------------------------------------------------------------------------- #
def _compose_walk_instructions(
    base_url: str,
    auth_notes: str,
    scope: str,
    openapi_inventory: str | None,
) -> str:
    body = _phase_instructions("walk")
    context = [
        "# Engagement context",
        f"Target application: {base_url}",
        f"Configured scope (--scope): {scope}",
        "",
        "## Authentication notes",
        auth_notes or "(none provided)",
    ]
    if openapi_inventory:
        context += [
            "",
            "## API endpoint inventory (from the supplied OpenAPI/Swagger spec)",
            "Enumerate and reason about these endpoints in addition to what you "
            "discover by walking the UI. Only exercise those within scope.",
            "",
            openapi_inventory,
        ]
    else:
        context += [
            "",
            "## API endpoint inventory",
            "No OpenAPI/Swagger spec was supplied. Discover endpoints by walking "
            "the signup/login flows in the browser.",
        ]
    return body + "\n\n" + "\n".join(context)


def _compose_pentest_instructions(
    base_url: str,
    auth_notes: str,
    scope: str,
    features_markdown: str,
) -> str:
    body = _phase_instructions("pentest")
    context = [
        "# Engagement context",
        f"Target application: {base_url}",
        f"Configured scope (--scope): {scope}",
        "Only execute the test cases that fall within the configured scope.",
        "",
        "## Authentication notes",
        auth_notes or "(none provided)",
        "",
        "## Features and security test cases (from the walk phase)",
        features_markdown,
    ]
    return body + "\n\n" + "\n".join(context)


# --------------------------------------------------------------------------- #
# Phases
# --------------------------------------------------------------------------- #
@logger.catch(reraise=True)
async def walk_app(
    settings: Settings,
    base_url: str,
    auth_notes: str,
    scope: str,
    openapi_inventory: str | None,
) -> WalkFeatures:
    from agents import Agent, Runner

    logger.info(f"Walk phase starting: {base_url} (scope: {scope})")
    model = build_model(settings)
    instructions = _compose_walk_instructions(base_url, auth_notes, scope, openapi_inventory)

    async with build_browser(settings, allowed_origins=_origin(base_url)) as browser:
        logger.info("Playwright MCP server started")
        agent = Agent(
            name="Walk Agent",
            instructions=instructions,
            mcp_servers=[browser],
            model=model,
            output_type=WalkFeatures,
        )
        result = await Runner.run(
            agent,
            f"Browse the app hosted on {base_url}",
            max_turns=settings.max_turns,
        )
        logger.success(f"Walk finished: {base_url}")
        return result.final_output


@logger.catch(reraise=True)
async def pentest_app(
    settings: Settings,
    base_url: str,
    auth_notes: str,
    scope: str,
    features_markdown: str,
) -> WalkVulns:
    from agents import Agent, Runner

    logger.info(f"Pentest phase starting: {base_url} (scope: {scope})")
    model = build_model(settings)
    instructions = _compose_pentest_instructions(base_url, auth_notes, scope, features_markdown)

    async with build_browser(settings, allowed_origins=_origin(base_url)) as browser:
        agent = Agent(
            name="Pentest Agent",
            instructions=instructions,
            mcp_servers=[browser],
            model=model,
            output_type=WalkVulns,
        )
        result = await Runner.run(
            agent,
            f"Browse the app hosted on {base_url}",
            max_turns=settings.max_turns,
        )
        logger.success("Pentest finished")
        return result.final_output


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
async def run_pipeline(args: argparse.Namespace) -> None:
    from agents import set_tracing_disabled

    set_tracing_disabled(True)

    settings = Settings.from_env()
    if args.model:
        settings = dataclasses.replace(settings, model=args.model)

    if not settings.api_key:
        raise SystemExit(
            "OPENAI_API_KEY is not set. Configure it in your environment or .env file."
        )

    auth_notes = _resolve_auth_notes(args)

    openapi_inventory: str | None = None
    if args.openapi:
        logger.info(f"Ingesting OpenAPI specification: {args.openapi}")
        openapi_inventory = build_endpoint_inventory(args.openapi)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Phase 1: walk
    features = await walk_app(
        settings,
        args.base_url,
        auth_notes,
        args.scope,
        openapi_inventory,
    )
    features_markdown = features_to_markdown(features)
    features_path = output_dir / "features.md"
    features_path.write_text(features_markdown, encoding="utf-8")
    logger.success(f"Features written to {features_path}")

    # Phase 2: pentest
    vulns = await pentest_app(
        settings,
        args.base_url,
        auth_notes,
        args.scope,
        features_markdown,
    )
    report_markdown = vulns_to_markdown(vulns)
    report_path = output_dir / "pentest_results.md"
    report_path.write_text(report_markdown, encoding="utf-8")
    logger.success(f"Vulnerability report written to {report_path}")


def _resolve_auth_notes(args: argparse.Namespace) -> str:
    if args.auth_notes_file:
        return Path(args.auth_notes_file).read_text(encoding="utf-8")
    return args.auth_notes or ""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Autonomous DAST agent: authenticated walk + pentest of an application "
            "you own or are explicitly authorized to test."
        )
    )
    parser.add_argument(
        "--base-url",
        required=True,
        help="Base URL of the target application (e.g. https://staging.example.com).",
    )
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument(
        "--auth-notes",
        help="Inline authentication notes for the test account (how to sign up / log in).",
    )
    auth_group.add_argument(
        "--auth-notes-file",
        help="Path to a file containing authentication notes.",
    )
    parser.add_argument(
        "--openapi",
        help="Path or URL to an OpenAPI/Swagger spec to ingest as an endpoint inventory.",
    )
    parser.add_argument(
        "--scope",
        default="auth,registration",
        help="Comma-separated feature scope to test (default: auth,registration).",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs",
        help="Directory for features.md and pentest_results.md (default: outputs).",
    )
    parser.add_argument(
        "--model",
        help="Override the model id (otherwise DAST_MODEL / the built-in default).",
    )
    return parser


def main() -> None:
    _configure_logging()
    args = _build_parser().parse_args()
    asyncio.run(run_pipeline(args))


if __name__ == "__main__":
    main()
