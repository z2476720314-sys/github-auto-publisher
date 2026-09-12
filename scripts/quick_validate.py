"""Validate the packaged Skill metadata without relying on a local Codex install."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ALLOWED_FRONTMATTER = {"name", "description", "license", "allowed-tools", "metadata"}


def validate(skill_root: Path) -> tuple[bool, str]:
    skill_file = skill_root / "SKILL.md"
    metadata_file = skill_root / "agents" / "openai.yaml"
    if not skill_file.is_file() or not metadata_file.is_file():
        return False, "Required Skill metadata is missing."

    content = skill_file.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
    if match is None:
        return False, "SKILL.md frontmatter is invalid."
    frontmatter = yaml.safe_load(match.group(1))
    if not isinstance(frontmatter, dict):
        return False, "SKILL.md frontmatter must be a mapping."
    if set(frontmatter) - ALLOWED_FRONTMATTER:
        return False, "SKILL.md frontmatter contains unsupported fields."
    name = frontmatter.get("name")
    description = frontmatter.get("description")
    if not isinstance(name, str) or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) is None:
        return False, "Skill name must use hyphen-case."
    if not isinstance(description, str) or not description.strip() or len(description) > 1024:
        return False, "Skill description is invalid."

    metadata = yaml.safe_load(metadata_file.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        return False, "agents/openai.yaml must be a mapping."
    interface = metadata.get("interface")
    policy = metadata.get("policy")
    if not isinstance(interface, dict) or not all(
        isinstance(interface.get(key), str) and interface[key].strip()
        for key in ("display_name", "short_description", "default_prompt")
    ):
        return False, "agents/openai.yaml interface is incomplete."
    if not isinstance(policy, dict) or policy.get("allow_implicit_invocation") is not True:
        return False, "Implicit invocation policy is missing."
    return True, "Skill metadata is valid."


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: python quick_validate.py <skill-directory>")
        return 2
    valid, message = validate(Path(argv[1]))
    print(message)
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
