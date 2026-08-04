"""Skill and reference loader.

Behavioral instructions live as Markdown files on disk (``skills/*/SKILL.md``)
and the security knowledge base lives under ``references/``. Loading them as
files -- instead of burying huge strings in Python -- keeps prompts reviewable
in version control and lets operators tune behavior without editing code.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SKILLS_DIR = Path(__file__).parent / "skills"
REFERENCES_DIR = Path(__file__).parent / "references"


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    skill_path: str


# Registry of the phases in the pipeline.
SKILLS = (
    Skill(
        name="walk",
        description="Log in with the test account and enumerate signup/login "
        "features, emitting WSTG-style security test cases.",
        skill_path="walk/SKILL.md",
    ),
    Skill(
        name="pentest",
        description="Execute the in-scope security test cases, tag traffic with "
        "the X-Pentest-Case header, and emit a vulnerability report.",
        skill_path="pentest/SKILL.md",
    ),
)


def load_skill(relative_path: str) -> str:
    """Read a SKILL.md file, guarding against path escapes."""

    path = (SKILLS_DIR / relative_path).resolve()
    if SKILLS_DIR.resolve() not in path.parents:
        raise ValueError("skill path escaped the skills directory")
    return path.read_text(encoding="utf-8")


def load_reference(relative_path: str) -> str:
    """Read a reference document, guarding against path escapes."""

    path = (REFERENCES_DIR / relative_path).resolve()
    if REFERENCES_DIR.resolve() not in path.parents:
        raise ValueError("reference path escaped the references directory")
    return path.read_text(encoding="utf-8")
