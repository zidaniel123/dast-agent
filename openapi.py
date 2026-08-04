"""OpenAPI / Swagger ingestion.

When the team supplies an API specification, we condense it into a compact
endpoint inventory (method + path + summary) and feed it to the walk agent so it
enumerates endpoints from the spec instead of relying on crawling alone.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


def _load_raw(source: str) -> str:
    """Fetch the raw spec text from a URL or read it from a local file path."""

    parsed = urlparse(source)
    if parsed.scheme in ("http", "https"):
        import httpx

        response = httpx.get(source, timeout=30.0, follow_redirects=True)
        response.raise_for_status()
        return response.text
    return Path(source).read_text(encoding="utf-8")


def _parse(text: str) -> dict:
    """Parse a spec as JSON, falling back to YAML when available."""

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # optional dependency
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise ValueError(
                "OpenAPI spec is not valid JSON. Install PyYAML to load YAML specs, "
                "or convert the spec to JSON."
            ) from exc
        parsed = yaml.safe_load(text)
        if not isinstance(parsed, dict):
            raise ValueError("OpenAPI spec did not parse to a mapping.")
        return parsed


def build_endpoint_inventory(source: str, limit: int = 250) -> str:
    """Return a Markdown bullet list of ``METHOD /path -- summary`` lines."""

    spec = _parse(_load_raw(source))
    paths = spec.get("paths", {}) or {}

    lines: list[str] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            summary = ""
            if isinstance(operation, dict):
                summary = (operation.get("summary") or operation.get("description") or "").strip()
                if summary:
                    summary = summary.splitlines()[0]
            entry = f"- {method.upper()} {path}"
            if summary:
                entry += f" -- {summary}"
            lines.append(entry)

    if not lines:
        return "(No paths found in the supplied OpenAPI specification.)"

    truncated = lines[:limit]
    if len(lines) > limit:
        truncated.append(f"- ... ({len(lines) - limit} more endpoints omitted)")
    return "\n".join(truncated)
