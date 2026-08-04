"""Structured output schemas and Markdown renderers.

The walk phase emits ``WalkFeatures`` (features + security test cases) and the
pentest phase emits ``WalkVulns`` (findings + HTTP evidence). These Pydantic
models are the contract the agents must satisfy as their structured output.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel


# --------------------------------------------------------------------------- #
# Walk phase
# --------------------------------------------------------------------------- #
class SecurityTestCase(BaseModel):
    name: str
    description: Optional[str] = None
    attack_vector: str
    cwe_id: str
    approach: Optional[str] = None
    expected_conditions: Optional[str] = None


class WalkFeature(BaseModel):
    name: str
    description: Optional[str] = None
    feature_urls: List[str]
    test_cases: List[SecurityTestCase]


class WalkFeatures(BaseModel):
    features: List[WalkFeature]


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
    evidences: List[WalkVulnEvidences]


class WalkVulns(BaseModel):
    vulnerabilities: List[WalkVuln]


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #
def features_to_markdown(walk_features: WalkFeatures) -> str:
    """Render ``WalkFeatures`` as a Markdown document."""

    lines: List[str] = []

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
                name = tc.name or "-"
                attack_vector = tc.attack_vector or "-"
                cwe_id = tc.cwe_id or "-"
                description = tc.description or "-"
                approach = tc.approach or "-"
                expected = tc.expected_conditions or "-"
                lines.append(
                    f"| {name} | {attack_vector} | {cwe_id} | {description} | {approach} | {expected} |"
                )

        lines.append("\n---\n")

    return "\n".join(lines)


def vulns_to_markdown(walk_vulns: WalkVulns) -> str:
    """Render ``WalkVulns`` as a Markdown vulnerability report."""

    lines: List[str] = []

    if not walk_vulns.vulnerabilities:
        return "No vulnerabilities found."

    lines.append("# Vulnerability Report\n")
    lines.append("| # | Vulnerability | Severity | CWE ID | Description | Observation |")
    lines.append("|---|---------------|----------|--------|-------------|-------------|")

    for idx, vuln in enumerate(walk_vulns.vulnerabilities, 1):
        name = vuln.name or "-"
        severity = vuln.severity or "-"
        cwe_id = vuln.cwe_id or "-"
        description = (vuln.description or "-").replace("\n", " ")
        observation = (vuln.observation or "-").replace("\n", " ")
        lines.append(f"| {idx} | {name} | {severity} | {cwe_id} | {description} | {observation} |")

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
