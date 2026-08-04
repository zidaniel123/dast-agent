"""Markdown rendering of findings.

Model-authored finding text routinely contains pipes (SQL, payloads, regexes)
and newlines (stack traces, raw HTTP). Both are Markdown table metacharacters,
so an unescaped one silently corrupts every remaining row of the report.
"""

from __future__ import annotations

import pytest

from schemas import (
    SecurityTestCase,
    WalkFeature,
    WalkFeatures,
    WalkVuln,
    WalkVulnEvidences,
    WalkVulns,
    _cell,
    features_to_markdown,
    vulns_to_markdown,
)


def _is_separator(line: str) -> bool:
    return line.startswith("|") and set(line) <= set("|-: ")


def data_rows(markdown: str) -> list[str]:
    """Table body rows, excluding header rows and separator lines.

    A header is the pipe-row immediately followed by a `|---|` separator.
    """
    lines = markdown.splitlines()
    rows = []
    for index, line in enumerate(lines):
        if not line.startswith("|") or _is_separator(line):
            continue
        following = lines[index + 1] if index + 1 < len(lines) else ""
        if _is_separator(following):
            continue
        rows.append(line)
    return rows


class TestCellEscaping:
    def test_pipe_is_escaped(self):
        assert _cell("a | b") == r"a \| b"

    def test_newline_becomes_a_break_not_a_row_end(self):
        assert "\n" not in _cell("line one\nline two")

    def test_carriage_returns_are_removed(self):
        assert "\r" not in _cell("line one\r\nline two")

    def test_empty_and_none_fall_back(self):
        assert _cell(None) == "-"
        assert _cell("") == "-"
        assert _cell("   ") == "-"

    def test_backslash_is_escaped_before_the_pipe(self):
        # Otherwise "a\|b" would render as an escaped backslash + a live pipe.
        assert _cell(r"a\|b") == r"a\\\|b"


class TestFeaturesTable:
    def _render(self, **overrides) -> str:
        case = SecurityTestCase(
            **{
                "name": "SQLi on login",
                "attack_vector": "POST /login",
                "cwe_id": "CWE-89",
                **overrides,
            }
        )
        return features_to_markdown(
            WalkFeatures(
                features=[
                    WalkFeature(name="Auth", feature_urls=["/login"], test_cases=[case])
                ]
            )
        )

    def test_clean_row_has_exactly_six_columns(self):
        row = data_rows(self._render())[0]
        assert row.count("|") - row.count(r"\|") == 7  # 6 cells => 7 delimiters

    def test_pipe_in_payload_does_not_add_columns(self):
        row = data_rows(self._render(approach="' OR 1=1 -- | admin"))[0]
        assert row.count("|") - row.count(r"\|") == 7

    def test_newline_in_description_does_not_split_the_row(self):
        rows = data_rows(self._render(description="step one\nstep two"))
        assert len(rows) == 1

    def test_optional_fields_render_as_dashes(self):
        row = data_rows(self._render())[0]
        assert "| - |" in row


class TestVulnReport:
    def test_empty_report_is_explicit(self):
        assert vulns_to_markdown(WalkVulns(vulnerabilities=[])) == "No vulnerabilities found."

    def _vuln(self, **overrides) -> WalkVulns:
        return WalkVulns(
            vulnerabilities=[
                WalkVuln(
                    **{
                        "name": "Reflected XSS",
                        "description": "desc",
                        "cwe_id": "CWE-79",
                        "observation": "obs",
                        "severity": "High",
                        "evidences": [],
                        **overrides,
                    }
                )
            ]
        )

    def test_pipe_in_observation_does_not_add_columns(self):
        markdown = vulns_to_markdown(self._vuln(observation="a | b | c"))
        row = data_rows(markdown)[0]
        assert row.count("|") - row.count(r"\|") == 7  # index + 5 cells

    def test_multiline_description_stays_on_one_row(self):
        markdown = vulns_to_markdown(self._vuln(description="line1\nline2"))
        assert len(data_rows(markdown)) == 1

    def test_evidence_is_rendered_in_fenced_blocks(self):
        markdown = vulns_to_markdown(
            self._vuln(
                evidences=[
                    WalkVulnEvidences(
                        name="poc",
                        description="d",
                        http_request="GET / HTTP/1.1",
                        http_response="HTTP/1.1 200 OK",
                    )
                ]
            )
        )
        assert "```http" in markdown
        assert "GET / HTTP/1.1" in markdown

    @pytest.mark.parametrize("count", [1, 3])
    def test_findings_are_numbered_from_one(self, count):
        vulns = WalkVulns(
            vulnerabilities=[
                WalkVuln(
                    name=f"v{i}",
                    description="d",
                    cwe_id="CWE-1",
                    observation="o",
                    severity="Low",
                    evidences=[],
                )
                for i in range(count)
            ]
        )
        rows = data_rows(vulns_to_markdown(vulns))
        assert rows[0].startswith("| 1 |")
        assert len(rows) == count
