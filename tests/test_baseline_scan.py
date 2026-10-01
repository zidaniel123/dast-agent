"""Baseline scanner parsing, normalization, degradation, and the scope fence.

All scanner invocation is mocked at the two seams the module uses
(``shutil.which`` and ``subprocess.run``): no test needs nuclei, ZAP, or Docker
installed, and none touches the network.
"""

from __future__ import annotations

import json
import subprocess

import pytest

import baseline_scan
from baseline_scan import (
    BaselineResult,
    alerts_to_markdown,
    baseline_disabled_by_env,
    parse_nuclei_jsonl,
    parse_zap_baseline_json,
    run_baseline,
    validate_target_origin,
)
from main import _build_parser, _compose_pentest_instructions

ORIGIN = "http://localhost:3000"
TARGET = "http://localhost:3000/app"

NUCLEI_JSONL = "\n".join(
    [
        json.dumps(
            {
                "template-id": "CVE-2021-41773",
                "info": {
                    "name": "Apache Path Traversal",
                    "severity": "HIGH",
                    "description": "Apache 2.4.49 path traversal",
                    "classification": {"cwe-id": ["CWE-22"]},
                },
                "matched-at": "http://localhost:3000/cgi-bin/",
                "matcher-name": "traversal",
            }
        ),
        "not json at all",
        "",
        json.dumps(
            {
                "template-id": "tech-detect",
                "info": {"name": "Tech Detect", "severity": "info"},
                "matched-at": "http://localhost:3000/",
            }
        ),
    ]
)

ZAP_JSON = json.dumps(
    {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "10038",
                        "alert": "Content Security Policy Header Not Set",
                        "riskcode": "2",
                        "cweid": "693",
                        "desc": "CSP header missing",
                        "instances": [
                            {"uri": "http://localhost:3000/", "evidence": ""},
                            {"uri": "http://localhost:3000/login", "evidence": ""},
                        ],
                    },
                    {
                        "pluginid": "90022",
                        "alert": "X-Frame-Options Missing",
                        "riskcode": "2",
                        "cweid": "-1",
                        "instances": [{"uri": "http://localhost:3000/", "evidence": "nosniff"}],
                    },
                ]
            }
        ]
    }
)


@pytest.fixture
def no_scanners(monkeypatch):
    """Simulate a host with neither nuclei nor docker installed."""
    monkeypatch.setattr(baseline_scan.shutil, "which", lambda name: None)


class TestNucleiParsing:
    def test_parses_findings_and_skips_bad_lines(self):
        alerts = parse_nuclei_jsonl(NUCLEI_JSONL)
        assert len(alerts) == 2
        cve = alerts[0]
        assert cve.source == "nuclei"
        assert cve.rule_id == "CVE-2021-41773"
        assert cve.name == "Apache Path Traversal"
        assert cve.severity == "high"  # normalized to lowercase
        assert cve.url == "http://localhost:3000/cgi-bin/"
        assert cve.cwe_id == "CWE-22"
        assert "traversal" in cve.evidence
        assert "Apache 2.4.49" in cve.evidence

    def test_missing_metadata_is_tolerated(self):
        alerts = parse_nuclei_jsonl(NUCLEI_JSONL)
        tech = alerts[1]
        assert tech.cwe_id is None
        assert tech.severity == "info"

    def test_alert_ids_are_deterministic(self):
        first = parse_nuclei_jsonl(NUCLEI_JSONL)
        second = parse_nuclei_jsonl(NUCLEI_JSONL)
        assert [a.alert_id for a in first] == [a.alert_id for a in second]
        assert first[0].alert_id.startswith("nuclei-")
        assert first[0].alert_id != first[1].alert_id

    def test_empty_output_is_no_alerts(self):
        assert parse_nuclei_jsonl("") == []


class TestZapParsing:
    def test_one_alert_per_affected_url(self):
        alerts = parse_zap_baseline_json(ZAP_JSON)
        assert len(alerts) == 3
        csp = [a for a in alerts if a.rule_id == "10038"]
        assert {a.url for a in csp} == {
            "http://localhost:3000/",
            "http://localhost:3000/login",
        }
        assert all(a.source == "zap" for a in alerts)

    def test_riskcode_maps_to_severity(self):
        alerts = parse_zap_baseline_json(ZAP_JSON)
        assert all(a.severity == "medium" for a in alerts)  # riskcode 2

    def test_cwe_is_normalized_and_meaningless_codes_dropped(self):
        alerts = parse_zap_baseline_json(ZAP_JSON)
        csp = next(a for a in alerts if a.rule_id == "10038")
        assert csp.cwe_id == "CWE-693"
        xfo = next(a for a in alerts if a.rule_id == "90022")
        assert xfo.cwe_id is None  # -1 means "no CWE" in ZAP

    def test_invalid_json_is_no_alerts_not_a_crash(self):
        assert parse_zap_baseline_json("{oops") == []


class TestOriginFence:
    def test_matching_origin_passes(self):
        validate_target_origin(TARGET, ORIGIN)  # no exception

    def test_different_host_is_refused(self):
        with pytest.raises(SystemExit, match="Refusing to scan"):
            validate_target_origin("https://evil.example.com/", ORIGIN)

    def test_different_port_is_refused(self):
        with pytest.raises(SystemExit, match="Refusing to scan"):
            validate_target_origin("http://localhost:9999/", ORIGIN)


class TestScannerDegradation:
    def test_no_scanners_means_skipped_baseline_not_a_crash(self, no_scanners, tmp_path):
        result = run_baseline(TARGET, ORIGIN, tmp_path)
        assert not result.disabled
        assert result.alerts == ()
        assert result.scanners_run == ()
        assert {name for name, _ in result.scanners_skipped} == {"nuclei", "zap"}
        # The normalized sidecar still lands, recording *why* there are no leads.
        written = json.loads((tmp_path / "baseline.json").read_text())
        assert written["alerts"] == []
        assert len(written["scanners_skipped"]) == 2

    def test_local_nuclei_binary_is_preferred(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            baseline_scan.shutil, "which", lambda name: f"/usr/bin/{name}"
        )
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout=NUCLEI_JSONL, stderr="")

        monkeypatch.setattr(baseline_scan.subprocess, "run", fake_run)
        result = run_baseline(TARGET, ORIGIN, tmp_path)
        nuclei_argv = calls[0]
        assert nuclei_argv[0] == "nuclei"
        assert "-jsonl" in nuclei_argv
        assert "-severity" in nuclei_argv
        sev = nuclei_argv[nuclei_argv.index("-severity") + 1]
        assert sev == "critical,high,medium"
        assert "nuclei" in result.scanners_run
        assert len(result.alerts) >= 2
        # Scanner-verbatim output is kept for auditability.
        assert (tmp_path / "nuclei.json").read_text() == NUCLEI_JSONL

    def test_docker_fallback_for_nuclei(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            baseline_scan.shutil,
            "which",
            lambda name: "/usr/bin/docker" if name == "docker" else None,
        )
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(baseline_scan.subprocess, "run", fake_run)
        run_baseline(TARGET, ORIGIN, tmp_path)
        nuclei_argv = calls[0]
        assert nuclei_argv[:4] == ["docker", "run", "--rm", "--network"]
        assert "host" in nuclei_argv
        assert "projectdiscovery/nuclei:latest" in nuclei_argv

    def test_nuclei_timeout_degrades_to_a_skip(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            baseline_scan.shutil, "which", lambda name: f"/usr/bin/{name}"
        )

        def fake_run(argv, **kwargs):
            if argv[0] == "nuclei" or "nuclei" in " ".join(argv):
                raise subprocess.TimeoutExpired(argv, 900)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(baseline_scan.subprocess, "run", fake_run)
        result = run_baseline(TARGET, ORIGIN, tmp_path)
        assert "nuclei" not in result.scanners_run
        assert any("timed out" in reason for name, reason in result.scanners_skipped if name == "nuclei")

    def test_zap_writes_report_through_the_mounted_output_dir(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            baseline_scan.shutil,
            "which",
            lambda name: "/usr/bin/docker" if name == "docker" else None,
        )

        def fake_run(argv, **kwargs):
            # zap-baseline.py exits with the alert count as its status, so the
            # runner must trust the report file, not the exit code.
            (tmp_path / "zap-baseline.json").write_text(ZAP_JSON, encoding="utf-8")
            return subprocess.CompletedProcess(argv, 2, stdout="", stderr="")

        monkeypatch.setattr(baseline_scan.subprocess, "run", fake_run)
        result = run_baseline(TARGET, ORIGIN, tmp_path)
        assert "zap" in result.scanners_run
        assert sum(1 for a in result.alerts if a.source == "zap") == 3

    def test_zap_without_a_report_is_a_skip(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            baseline_scan.shutil,
            "which",
            lambda name: "/usr/bin/docker" if name == "docker" else None,
        )
        monkeypatch.setattr(
            baseline_scan.subprocess,
            "run",
            lambda argv, **kw: subprocess.CompletedProcess(argv, 1, stdout="", stderr="boom"),
        )
        result = run_baseline(TARGET, ORIGIN, tmp_path)
        assert "zap" not in result.scanners_run
        assert any(name == "zap" for name, _ in result.scanners_skipped)


class TestOptOut:
    def test_disabled_run_never_invokes_a_scanner(self, no_scanners, tmp_path):
        result = run_baseline(TARGET, ORIGIN, tmp_path, disabled=True)
        assert result.disabled
        # No baseline.json: there is nothing to record beyond the prompt text.
        assert not (tmp_path / "baseline.json").exists()

    def test_env_flag(self, monkeypatch):
        monkeypatch.delenv("DAST_NO_BASELINE", raising=False)
        assert not baseline_disabled_by_env()
        monkeypatch.setenv("DAST_NO_BASELINE", "1")
        assert baseline_disabled_by_env()

    def test_cli_flag(self):
        args = _build_parser().parse_args(
            ["--base-url", "https://example.com", "--no-baseline"]
        )
        assert args.no_baseline
        args = _build_parser().parse_args(["--base-url", "https://example.com"])
        assert not args.no_baseline


class TestPromptRendering:
    def test_disabled_says_so_explicitly(self):
        text = alerts_to_markdown(BaselineResult(disabled=True))
        assert "disabled" in text
        assert "no scanner leads" in text

    def test_unavailable_scanners_say_so_explicitly(self):
        result = BaselineResult(scanners_skipped=(("nuclei", "not found"), ("zap", "not found")))
        text = alerts_to_markdown(result)
        assert "could **not run**" in text
        assert "nuclei: not found" in text

    def test_empty_result_is_absence_of_evidence(self):
        text = alerts_to_markdown(BaselineResult(scanners_run=("nuclei",)))
        assert "no alerts" in text.lower()
        assert "absence of evidence" in text

    def test_alerts_render_as_a_table_and_pipes_are_escaped(self):
        alerts = parse_nuclei_jsonl(NUCLEI_JSONL)
        text = alerts_to_markdown(BaselineResult(alerts=tuple(alerts), scanners_run=("nuclei",)))
        assert "| ID | Scanner | Severity | Name | URL | CWE |" in text
        assert "CVE-2021-41773" in text
        assert "2 alert(s) to confirm or refute" in text
        piped = parse_nuclei_jsonl(
            '{"template-id": "x", "info": {"name": "a|b", "severity": "low"}, "matched-at": "u"}'
        )
        text = alerts_to_markdown(BaselineResult(alerts=tuple(piped), scanners_run=("nuclei",)))
        assert "a\\|b" in text

    def test_pentest_instructions_carry_the_baseline_section(self):
        prompt = _compose_pentest_instructions(
            "https://example.com", "notes", "auth", "FEATURES", "BASELINE-BLOCK"
        )
        assert "## Deterministic scanner baseline (nuclei/ZAP)" in prompt
        assert "BASELINE-BLOCK" in prompt
        assert "FEATURES" in prompt
