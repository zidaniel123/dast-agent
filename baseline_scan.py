"""Deterministic scanner baseline (Phase 0).

Before any LLM phase runs, this module executes whatever deterministic DAST
scanners are available on the host and normalizes their output into
``BaselineAlert`` objects:

    nuclei   -> local binary on PATH, else the ``projectdiscovery/nuclei``
                Docker image (``--network host`` so the container can reach a
                target on the host's loopback), else skipped with a warning.
    ZAP      -> the ``zaproxy/zap-stable`` Docker image running
                ``zap-baseline.py``; there is no local-binary mode because a
                system ZAP install has no stable CLI contract, else skipped
                with a warning.

Both scanners are *degradable*: neither being available is a skipped baseline,
not a crash. The pipeline must still run LLM-only, exactly as before, because
the baseline exists to give the pentest phase deterministic leads -- its
absence must never take the agent down with it. The master opt-out is
``--no-baseline`` / ``DAST_NO_BASELINE=1``.

Every subprocess call goes through ``subprocess.run`` and every tool lookup
through ``shutil.which``, so tests mock those two seams and never need a real
scanner installed.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from loguru import logger

from config import _flag, _int_env

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
# Docker fallbacks. Pinned tags are deliberately *not* the default: the images
# are a convenience fallback for hosts without a local scanner, and operators
# who need a pinned supply chain set these explicitly.
NUCLEI_IMAGE = os.getenv("NUCLEI_IMAGE", "projectdiscovery/nuclei:latest")
ZAP_IMAGE = os.getenv("ZAP_IMAGE", "zaproxy/zap-stable:latest")

# Severity floor passed to nuclei. Low/informational nuclei hits (tech
# detection, exposed metadata) are noise for an LLM confirm-or-refute pass and
# cost a turn each; medium and up is where a lead is worth spending turns on.
DEFAULT_NUCLEI_SEVERITY = "critical,high,medium"

# ZAP's numeric risk codes, as emitted by zap-baseline.py JSON output.
_ZAP_RISK = {"0": "informational", "1": "low", "2": "medium", "3": "high"}


def baseline_disabled_by_env() -> bool:
    """Master opt-out via environment (``DAST_NO_BASELINE=1``)."""
    return _flag("DAST_NO_BASELINE")


# --------------------------------------------------------------------------- #
# Normalized output model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class BaselineAlert:
    """One scanner hit, normalized across nuclei and ZAP.

    ``alert_id`` is a deterministic hash of (source, rule, url) -- the pentest
    phase cites these ids in ``baseline_alert_ids`` /
    ``refuted_baseline_alert_ids``, so they must be stable across runs and must
    not depend on anything the model writes.
    """

    alert_id: str
    source: str  # "nuclei" | "zap"
    rule_id: str  # nuclei template id / ZAP plugin id
    name: str
    severity: str  # normalized lowercase
    url: str
    cwe_id: str | None = None
    evidence: str = ""


@dataclass(frozen=True)
class BaselineResult:
    """Outcome of Phase 0.

    ``disabled`` is distinct from "no scanner available": the former is the
    operator opting out, the latter is degradation, and the pentest prompt must
    say which happened so the agent knows why it has no deterministic leads.
    """

    disabled: bool = False
    alerts: tuple[BaselineAlert, ...] = ()
    scanners_run: tuple[str, ...] = ()
    # (scanner name, human-readable reason it did not run).
    scanners_skipped: tuple[tuple[str, str], ...] = ()


def _alert_id(source: str, rule_id: str, url: str) -> str:
    digest = hashlib.sha256(f"{source}|{rule_id}|{url}".encode()).hexdigest()
    return f"{source}-{digest[:12]}"


# --------------------------------------------------------------------------- #
# Parsers (pure functions over scanner output text)
# --------------------------------------------------------------------------- #
def parse_nuclei_jsonl(text: str) -> list[BaselineAlert]:
    """Parse nuclei's JSON-lines output (one finding object per line).

    Tolerates blank lines and unparseable lines: nuclei writes progress noise
    to stdout under some flags, and one bad line must not discard the rest of
    the scan.
    """
    alerts: list[BaselineAlert] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            hit = json.loads(line)
        except json.JSONDecodeError:
            logger.warning(f"Skipping unparseable nuclei output line: {line[:120]}")
            continue
        info = hit.get("info") or {}
        rule_id = hit.get("template-id") or hit.get("template_id") or "unknown"
        url = hit.get("matched-at") or hit.get("matched_at") or hit.get("host") or ""
        cwe_list = ((info.get("classification") or {}).get("cwe-id")) or []
        cwe_id = cwe_list[0] if cwe_list else None
        # Evidence: what nuclei matched, so the agent has something concrete to
        # re-test rather than re-deriving the payload from the template id.
        evidence_parts = []
        if hit.get("matcher-name"):
            evidence_parts.append(f"matcher: {hit['matcher-name']}")
        extracted = hit.get("extracted-results") or []
        if extracted:
            evidence_parts.append("extracted: " + ", ".join(str(e) for e in extracted[:5]))
        if info.get("description"):
            evidence_parts.append(info["description"])
        alerts.append(
            BaselineAlert(
                alert_id=_alert_id("nuclei", rule_id, url),
                source="nuclei",
                rule_id=rule_id,
                name=info.get("name") or rule_id,
                severity=(info.get("severity") or "unknown").strip().lower(),
                url=url,
                cwe_id=cwe_id,
                evidence=" | ".join(evidence_parts),
            )
        )
    return alerts


def parse_zap_baseline_json(text: str) -> list[BaselineAlert]:
    """Parse zap-baseline.py's JSON report.

    Structure: ``{"site": [{"alerts": [{... "instances": [...]}]}]}``. One
    alert with three affected URLs becomes three ``BaselineAlert`` records --
    the pentest phase confirms per URL, so the leads must be per URL too.
    """
    try:
        report = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("ZAP baseline output is not valid JSON; treating as no alerts")
        return []
    alerts: list[BaselineAlert] = []
    for site in report.get("site") or []:
        for alert in site.get("alerts") or []:
            rule_id = str(alert.get("pluginid") or "unknown")
            name = alert.get("alert") or alert.get("name") or rule_id
            severity = _ZAP_RISK.get(str(alert.get("riskcode")), "unknown")
            cwe_raw = str(alert.get("cweid") or "").strip()
            cwe_id = f"CWE-{cwe_raw}" if cwe_raw and cwe_raw not in {"-1", "0"} else None
            instances = alert.get("instances") or [{}]
            for instance in instances:
                url = instance.get("uri") or ""
                evidence = instance.get("evidence") or alert.get("desc") or ""
                alerts.append(
                    BaselineAlert(
                        alert_id=_alert_id("zap", rule_id, url),
                        source="zap",
                        rule_id=rule_id,
                        name=name,
                        severity=severity,
                        url=url,
                        cwe_id=cwe_id,
                        evidence=evidence,
                    )
                )
    return alerts


# --------------------------------------------------------------------------- #
# Scope fence
# --------------------------------------------------------------------------- #
def validate_target_origin(target_url: str, expected_origin: str) -> None:
    """Refuse to scan anything outside the browser's navigation fence.

    The browser is pinned to ``--allowed-origins=<origin of --base-url>``;
    the baseline scanners have no such fence of their own, so it is enforced
    here in code instead. Without this check a mistyped or redirected target
    would send scanner attack traffic to a host the operator never pointed the
    engagement at.
    """
    parsed = urlparse(target_url)
    actual = f"{parsed.scheme}://{parsed.netloc}"
    if actual != expected_origin:
        raise SystemExit(
            f"Baseline scan target {target_url!r} resolves to origin {actual!r}, "
            f"which differs from the --base-url origin {expected_origin!r}. "
            "Refusing to scan outside the engagement origin."
        )


# --------------------------------------------------------------------------- #
# Scanner invocation
# --------------------------------------------------------------------------- #
def _nuclei_argv(target_url: str) -> list[str]:
    severity = os.getenv("NUCLEI_SEVERITY", DEFAULT_NUCLEI_SEVERITY)
    scan = ["-u", target_url, "-jsonl", "-severity", severity, "-silent"]
    if shutil.which("nuclei"):
        return ["nuclei", *scan]
    if shutil.which("docker"):
        # --network host: without it a containerized nuclei cannot reach a
        # target on the host's loopback, the most common local-target setup.
        return ["docker", "run", "--rm", "--network", "host", NUCLEI_IMAGE, *scan]
    return []


def _run_nuclei(target_url: str, output_dir: Path) -> tuple[list[BaselineAlert], str | None]:
    """Returns (alerts, skip-reason). Exactly one of the two is meaningful."""
    argv = _nuclei_argv(target_url)
    if not argv:
        return [], "neither a `nuclei` binary nor `docker` found on PATH"
    timeout = _int_env("NUCLEI_TIMEOUT", 900)
    logger.info(f"Baseline: running nuclei ({argv[0]}) against {target_url}")
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], f"timed out after {timeout}s (NUCLEI_TIMEOUT)"
    if proc.returncode != 0:
        return [], f"exited {proc.returncode}: {proc.stderr.strip()[:200]}"
    # Raw output is kept verbatim so the normalization step is auditable
    # against exactly what the scanner said.
    (output_dir / "nuclei.json").write_text(proc.stdout, encoding="utf-8")
    return parse_nuclei_jsonl(proc.stdout), None


def _run_zap(target_url: str, output_dir: Path) -> tuple[list[BaselineAlert], str | None]:
    """Returns (alerts, skip-reason). Exactly one of the two is meaningful."""
    if not shutil.which("docker"):
        return [], "`docker` not found on PATH (ZAP baseline runs containerized)"
    timeout = _int_env("ZAP_TIMEOUT", 1800)
    report_name = "zap-baseline.json"
    argv = [
        "docker", "run", "--rm", "--network", "host",
        # zap-baseline.py writes into /zap/wrk inside the container; mounting
        # the run's output dir there is how the report gets back to the host.
        "-v", f"{output_dir.resolve()}:/zap/wrk:rw",
        ZAP_IMAGE, "zap-baseline.py", "-t", target_url, "-J", report_name,
    ]
    logger.info(f"Baseline: running ZAP baseline against {target_url}")
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], f"timed out after {timeout}s (ZAP_TIMEOUT)"
    # zap-baseline.py exits with the *count of alerts* as its status, so a
    # non-zero code is the normal case. The report file is the real output;
    # only its absence is a failure.
    report_path = output_dir / report_name
    if not report_path.exists():
        return [], f"exited {proc.returncode} without writing {report_name}: {proc.stderr.strip()[:200]}"
    return parse_zap_baseline_json(report_path.read_text(encoding="utf-8")), None


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def run_baseline(
    target_url: str,
    expected_origin: str,
    output_dir: Path,
    disabled: bool = False,
) -> BaselineResult:
    """Run every available baseline scanner and normalize what they find.

    Writes ``nuclei.json`` / ``zap-baseline.json`` (scanner-verbatim) and
    ``baseline.json`` (normalized) into ``output_dir``. Never raises for a
    missing or failing scanner -- degradation is a warning, because the LLM
    phases must run regardless.
    """
    if disabled:
        logger.warning(
            "Baseline scan disabled (--no-baseline / DAST_NO_BASELINE=1). "
            "The pentest phase will run with NO deterministic leads."
        )
        return BaselineResult(disabled=True)

    validate_target_origin(target_url, expected_origin)

    alerts: list[BaselineAlert] = []
    scanners_run: list[str] = []
    scanners_skipped: list[tuple[str, str]] = []

    for name, runner in (("nuclei", _run_nuclei), ("zap", _run_zap)):
        found, skip_reason = runner(target_url, output_dir)
        if skip_reason is not None:
            logger.warning(f"Baseline: {name} skipped -- {skip_reason}")
            scanners_skipped.append((name, skip_reason))
        else:
            scanners_run.append(name)
            alerts.extend(found)
            logger.info(f"Baseline: {name} produced {len(found)} alert(s)")

    result = BaselineResult(
        alerts=tuple(alerts),
        scanners_run=tuple(scanners_run),
        scanners_skipped=tuple(scanners_skipped),
    )
    normalized = {
        "disabled": False,
        "scanners_run": list(scanners_run),
        "scanners_skipped": [{"scanner": n, "reason": r} for n, r in scanners_skipped],
        "alerts": [dataclasses.asdict(a) for a in alerts],
    }
    (output_dir / "baseline.json").write_text(
        json.dumps(normalized, indent=2) + "\n", encoding="utf-8"
    )
    return result


# --------------------------------------------------------------------------- #
# Prompt rendering
# --------------------------------------------------------------------------- #
def alerts_to_markdown(result: BaselineResult) -> str:
    """Render the baseline as the compact block injected into the pentest prompt.

    The skipped/empty cases produce explicit prose, not an empty string: the
    pentest agent must be *told* it has no deterministic leads, otherwise it
    cannot distinguish "scanner found nothing" from "scanner never ran".
    """
    if result.disabled:
        return (
            "The deterministic scanner baseline was **disabled** for this run "
            "(--no-baseline / DAST_NO_BASELINE=1). You have no scanner leads; "
            "every finding must come from your own test-case execution."
        )
    if not result.scanners_run:
        reasons = "; ".join(f"{n}: {r}" for n, r in result.scanners_skipped) or "none"
        return (
            "The deterministic scanner baseline could **not run** "
            f"({reasons}). You have no scanner leads; every finding must come "
            "from your own test-case execution."
        )
    if not result.alerts:
        ran = ", ".join(result.scanners_run)
        return (
            f"The deterministic scanner baseline ran ({ran}) and reported **no "
            "alerts**. That is absence of evidence, not evidence of absence: "
            "unauthenticated scanners miss anything behind login and all "
            "business-logic flaws. Hunt normally from your test-case list."
        )

    lines = [
        f"Scanners run: {', '.join(result.scanners_run)}. "
        f"{len(result.alerts)} alert(s) to confirm or refute.",
        "",
        "| ID | Scanner | Severity | Name | URL | CWE |",
        "|----|---------|----------|------|-----|-----|",
    ]
    for a in result.alerts:
        lines.append(
            "| "
            + " | ".join(
                (
                    _md_cell(a.alert_id),
                    _md_cell(a.source),
                    _md_cell(a.severity),
                    _md_cell(a.name),
                    _md_cell(a.url),
                    _md_cell(a.cwe_id or "-"),
                )
            )
            + " |"
        )
    lines.append("")
    lines.append("Scanner evidence, where the scanner provided any:")
    for a in result.alerts:
        if a.evidence:
            lines.append(f"- `{a.alert_id}` ({a.source}:{a.rule_id}): {a.evidence}")
    return "\n".join(lines)


def _md_cell(value: str) -> str:
    """Escape scanner-authored text for a Markdown table cell (pipes, newlines)."""
    return (
        value.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r\n", " ")
        .replace("\n", " ")
        .replace("\r", " ")
    )
