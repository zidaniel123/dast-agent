"""Skill and reference loader.

Behavioral instructions live as Markdown files on disk (``skills/*/SKILL.md``)
and the security knowledge base lives under ``references/``. Loading them as
files -- instead of burying huge strings in Python -- keeps prompts reviewable
in version control and lets operators tune behavior without editing code.

Each phase declares the references it actually cites. That keeps the prompt
small: the walk phase needs the WSTG test-case catalogue, the pentest phase
needs the evidence format, and neither pays for the other's tokens.
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
    references: tuple[str, ...] = ()


# Registry of the phases in the pipeline.
SKILLS: tuple[Skill, ...] = (
    Skill(
        name="walk",
        description="Log in with the test account and enumerate signup/login "
        "features, emitting WSTG-style security test cases.",
        skill_path="walk/SKILL.md",
        references=("authorization-and-scope.md", "web-test-cases.md"),
    ),
    Skill(
        name="pentest",
        description="Execute the in-scope security test cases, tag traffic with "
        "the X-Pentest-Case header, and emit a vulnerability report.",
        skill_path="pentest/SKILL.md",
        references=("authorization-and-scope.md", "evidence-format.md"),
    ),
)

_BY_NAME = {item.name: item for item in SKILLS}


def skill(name: str) -> Skill:
    """Look up a phase by name."""
    try:
        return _BY_NAME[name]
    except KeyError:
        raise KeyError(
            f"unknown phase {name!r}; known: {', '.join(sorted(_BY_NAME))}"
        ) from None


def _read_within(base: Path, relative_path: str) -> str:
    """Read ``base/relative_path``, refusing anything that escapes ``base``."""
    root = base.resolve()
    path = (base / relative_path).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"path escaped {root.name}/: {relative_path!r}")
    return path.read_text(encoding="utf-8")


def load_skill(relative_path: str) -> str:
    """Read a SKILL.md file."""
    return _read_within(SKILLS_DIR, relative_path)


def load_reference(relative_path: str) -> str:
    """Read a reference document."""
    return _read_within(REFERENCES_DIR, relative_path)


def reference_appendix(relative_paths: tuple[str, ...]) -> str:
    """Render the cited reference documents as one appendix block.

    Section headings reuse the same ``references/<name>`` path the skill bodies
    cite, so a citation in the prompt resolves to a heading the model can see.
    """
    if not relative_paths:
        return "(No reference documents apply to this phase.)"
    sections = [
        f"### references/{name}\n\n{load_reference(name).strip()}"
        for name in relative_paths
    ]
    return "\n\n".join(sections)
