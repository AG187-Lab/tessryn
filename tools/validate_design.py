#!/usr/bin/env python3
"""Check public document links and the implementation dependency contract."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def require(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def validate_backlog() -> tuple[int, int]:
    path = ROOT / "planning/backlog.json"
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        errors.append(f"Cannot read backlog: {error}")
        return 0, 0
    milestones = data.get("milestones", [])
    issues = data.get("issues", [])
    milestone_keys = [m.get("key") for m in milestones]
    keys = [issue.get("key") for issue in issues]
    require(bool(milestones) and bool(issues), "Backlog must contain milestones and issues")
    require(len(milestone_keys) == len(set(milestone_keys)), "Duplicate milestone key")
    require(len(keys) == len(set(keys)), "Duplicate issue key")
    require(all(isinstance(key, str) and key for key in keys), "Issue keys must be nonempty strings")
    by_key = {issue.get("key"): issue for issue in issues}
    for milestone in milestones:
        require(bool(milestone.get("title")) and bool(milestone.get("description")),
                f"Milestone {milestone.get('key')} requires title and exit criteria")
    for issue in issues:
        key = issue.get("key")
        require(issue.get("milestone") in milestone_keys, f"{key}: unknown milestone")
        require(issue.get("priority") in {"P0", "P1", "P2"}, f"{key}: invalid priority")
        require(issue.get("phase") in {"Now", "Next", "Later"}, f"{key}: invalid horizon")
        require(bool(issue.get("title")) and isinstance(issue.get("body"), str), f"{key}: missing title/body")
        require(isinstance(issue.get("labels"), list) and bool(issue.get("labels")), f"{key}: missing workstream labels")
        require("- [ ]" in issue.get("body", ""), f"{key}: acceptance checkboxes required")
        require("evidence" in issue.get("body", "").lower(), f"{key}: required evidence missing")
        deps = issue.get("depends_on", [])
        require(isinstance(deps, list), f"{key}: dependencies must be a list")
        require(len(deps) == len(set(deps)), f"{key}: duplicate dependency")
        for dependency in deps:
            require(dependency in by_key, f"{key}: unknown dependency {dependency}")
            require(dependency != key, f"{key}: self dependency")
        if issue.get("parent"):
            require(issue["parent"] in by_key and issue["parent"] != key, f"{key}: invalid parent")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(key: str) -> None:
        if key in visiting:
            errors.append(f"Dependency cycle at {key}")
            return
        if key in visited or key not in by_key:
            return
        visiting.add(key)
        for dependency in by_key[key].get("depends_on", []):
            visit(dependency)
        visiting.remove(key)
        visited.add(key)

    for key in keys:
        visit(key)
    return len(milestones), len(issues)


def validate_documents() -> int:
    documents = sorted(ROOT.rglob("*.md"))
    for path in documents:
        if any(part in {".git", ".planning-cache"} for part in path.parts):
            continue
        text = path.read_text()
        require(not re.search(r"(?:/Users/|/home/)[^\s]+", text), f"{path.relative_to(ROOT)}: local workspace path")
        for destination in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
            destination = destination.strip().split(' "', 1)[0].strip("<>")
            parsed = urlsplit(destination)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            target = (path.parent / unquote(parsed.path)).resolve()
            try:
                target.relative_to(ROOT)
            except ValueError:
                errors.append(f"{path.relative_to(ROOT)}: link escapes repository: {destination}")
                continue
            require(target.exists(), f"{path.relative_to(ROOT)}: missing link target {destination}")
    return len(documents)


def main() -> int:
    milestones, issues = validate_backlog()
    documents = validate_documents()
    for path in (ROOT / "planning").glob("*.json"):
        try:
            json.loads(path.read_text())
        except (OSError, ValueError) as error:
            errors.append(f"{path.relative_to(ROOT)}: {error}")
    if errors:
        print("Design validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"Validated {documents} Markdown documents, {milestones} milestones and {issues} acyclic work items.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
