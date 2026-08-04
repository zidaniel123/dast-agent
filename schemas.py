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
    # Filename (relative to the output directory) of a screenshot the pentest
    # phase captured while confirming this finding. Empty when a screenshot does
    # not apply (e.g. a pure API finding with no rendered page).
    screenshot_path: str | None = None


class WalkVuln(BaseModel):
    name: str
    description: str
    cwe_id: str
    observation: str
    severity: str
    # Ordered, concrete steps to reproduce the finding against the target.
    reproduction_steps: list[str] = []
    # Concrete fix guidance: what to change and the secure pattern to adopt.
    remediation: str = ""
    # Authoritative fix references (CWE page, OWASP cheat sheet, framework docs).
    remediation_references: list[str] = []
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


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
_SEVERITY_LABELS = ("critical", "high", "medium", "low", "informational")


def _severity_rank(vuln: WalkVuln) -> int:
    return _SEVERITY_ORDER.get((vuln.severity or "").strip().lower(), 9)


def vulns_to_markdown(walk_vulns: WalkVulns) -> str:
    """Render ``WalkVulns`` as a Markdown vulnerability report.

    Findings are severity-sorted and each carries reproduction steps, HTTP and
    screenshot evidence, and remediation — the parts a developer needs to
    confirm and fix the issue, not just a one-line description.
    """

    if not walk_vulns.vulnerabilities:
        return "# Vulnerability Report\n\nNo vulnerabilities found.\n"

    vulns = sorted(walk_vulns.vulnerabilities, key=_severity_rank)
    lines: list[str] = ["# Vulnerability Report", ""]

    counts: dict[str, int] = {}
    for vuln in vulns:
        sev = (vuln.severity or "unknown").strip().lower()
        counts[sev] = counts.get(sev, 0) + 1

    lines.extend([f"- **Total findings:** {len(vulns)}", "", "## Executive summary", ""])
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in _SEVERITY_LABELS:
        if counts.get(sev):
            lines.append(f"| {sev} | {counts[sev]} |")
    for sev, count in counts.items():
        if sev not in _SEVERITY_LABELS:
            lines.append(f"| {sev} | {count} |")
    lines.append("")

    lines.append("| # | Vulnerability | Severity | CWE ID | Description |")
    lines.append("|---|---------------|----------|--------|-------------|")
    for idx, vuln in enumerate(vulns, 1):
        lines.append(
            f"| {idx} | "
            + " | ".join(
                (_cell(vuln.name), _cell(vuln.severity), _cell(vuln.cwe_id), _cell(vuln.description))
            )
            + " |"
        )
    lines.extend(["", "---", "", "## Findings", ""])

    for idx, vuln in enumerate(vulns, 1):
        lines.append(f"### {idx}. {vuln.name}")
        lines.append("")
        lines.append(f"- **Severity:** {(vuln.severity or 'unknown').strip().lower()}")
        lines.append(f"- **CWE:** {vuln.cwe_id or 'n/a'}")
        lines.append("")
        if vuln.description:
            lines.extend([vuln.description, ""])
        if vuln.observation:
            lines.extend([f"**Observation:** {vuln.observation}", ""])

        if vuln.reproduction_steps:
            lines.extend(["**Reproduction**", ""])
            lines.extend(
                f"{i}. {step.strip()}"
                for i, step in enumerate(vuln.reproduction_steps, 1)
                if step and step.strip()
            )
            lines.append("")

        for ev_idx, ev in enumerate(vuln.evidences, 1):
            lines.append(f"**Evidence {ev_idx}: {ev.name}**")
            lines.append("")
            if ev.description:
                lines.extend([ev.description, ""])
            if ev.http_request:
                lines.extend(["HTTP request:", "", f"```http\n{ev.http_request}\n```", ""])
            if ev.http_response:
                lines.extend(["HTTP response:", "", f"```http\n{ev.http_response}\n```", ""])
            if ev.screenshot_path:
                shot = ev.screenshot_path.strip()
                lines.extend([f"![{ev.name}]({shot})", ""])

        if vuln.remediation:
            lines.extend(["**Remediation**", "", vuln.remediation, ""])
            if vuln.remediation_references:
                lines.append("References:")
                lines.extend(
                    f"- {ref.strip()}" for ref in vuln.remediation_references if ref and ref.strip()
                )
                lines.append("")

        lines.extend(["---", ""])

    return "\n".join(lines).rstrip() + "\n"
