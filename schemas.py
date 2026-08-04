"""Structured output schemas and Markdown renderers.

The walk phase emits ``WalkFeatures`` (features + security test cases) and the
pentest phase emits ``WalkVulns`` (findings + HTTP evidence). These Pydantic
models are the contract the agents must satisfy as their structured output.
"""

from __future__ import annotations

from pydantic import BaseModel


# --------------------------------------------------------------------------- #
# Walk phase
# --------------------------------------------------------------------------- #
class SecurityTestCase(BaseModel):
    name: str
    description: str | None = None
    attack_vector: str
    cwe_id: str
    approach: str | None = None
    expected_conditions: str | None = None


class WalkFeature(BaseModel):
    name: str
    description: str | None = None
    feature_urls: list[str]
    test_cases: list[SecurityTestCase]


class WalkFeatures(BaseModel):
    features: list[WalkFeature]


# --------------------------------------------------------------------------- #
# Pentest phase
# --------------------------------------------------------------------------- #
class WalkVulnEvidences(BaseModel):
    name: str
    description: str
    http_request: str
    http_response: str


class WalkVuln(BaseModel):
    name: str
    description: str
    cwe_id: str
    observation: str
    severity: str
    evidences: list[WalkVulnEvidences]


class WalkVulns(BaseModel):
    vulnerabilities: list[WalkVuln]


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #
def _cell(value: str | None, fallback: str = "-") -> str:
    """Make model-authored text safe to drop into a Markdown table cell.

    A raw ``|`` splits the row into extra columns and a newline ends the row
    early, so a single unescaped character silently corrupts the rest of the
    table. Findings routinely contain both (payloads, SQL, stack traces).
    """
    text = (value or "").strip()
    if not text:
        return fallback
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r\n", " ")
        .replace("\n", "<br>")
        .replace("\r", " ")
    )


def features_to_markdown(walk_features: WalkFeatures) -> str:
    """Render ``WalkFeatures`` as a Markdown document."""

    lines: list[str] = []

    for feature in walk_features.features:
        lines.append(f"## {feature.name}")
        if feature.description:
            lines.append(f"\n{feature.description}\n")

        if feature.feature_urls:
            lines.append(f"\n**URLs:** {', '.join(feature.feature_urls)}\n")

        if feature.test_cases:
            lines.append("\n### Security Test Cases\n")
            lines.append(
                "| Test Name | Attack Vector | CWE ID | Description | Approach | Expected Conditions |"
            )
            lines.append(
                "|-----------|---------------|--------|-------------|----------|---------------------|"
            )
            for tc in feature.test_cases:
                lines.append(
                    "| "
                    + " | ".join(
                        (
                            _cell(tc.name),
                            _cell(tc.attack_vector),
                            _cell(tc.cwe_id),
                            _cell(tc.description),
                            _cell(tc.approach),
                            _cell(tc.expected_conditions),
                        )
                    )
                    + " |"
                )

        lines.append("\n---\n")

    return "\n".join(lines)


def vulns_to_markdown(walk_vulns: WalkVulns) -> str:
    """Render ``WalkVulns`` as a Markdown vulnerability report."""

    lines: list[str] = []

    if not walk_vulns.vulnerabilities:
        return "No vulnerabilities found."

    lines.append("# Vulnerability Report\n")
    lines.append("| # | Vulnerability | Severity | CWE ID | Description | Observation |")
    lines.append("|---|---------------|----------|--------|-------------|-------------|")

    for idx, vuln in enumerate(walk_vulns.vulnerabilities, 1):
        lines.append(
            f"| {idx} | "
            + " | ".join(
                (
                    _cell(vuln.name),
                    _cell(vuln.severity),
                    _cell(vuln.cwe_id),
                    _cell(vuln.description),
                    _cell(vuln.observation),
                )
            )
            + " |"
        )

    lines.append("\n---\n")
    lines.append("## Evidence Details\n")

    for idx, vuln in enumerate(walk_vulns.vulnerabilities, 1):
        if vuln.evidences:
            lines.append(f"### {idx}. {vuln.name}\n")
            for ev_idx, ev in enumerate(vuln.evidences, 1):
                lines.append(f"#### Evidence {ev_idx}: {ev.name}\n")
                if ev.description:
                    lines.append(f"{ev.description}\n")
                lines.append("\n**HTTP Request:**\n")
                lines.append(f"```http\n{ev.http_request}\n```\n")
                lines.append("\n**HTTP Response:**\n")
                lines.append(f"```http\n{ev.http_response}\n```\n")

    return "\n".join(lines)
