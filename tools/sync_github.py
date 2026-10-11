#!/usr/bin/env python3
"""Reconcile the planning backlog through authenticated gh; dry-run by default.

Managed bodies are replaced inside markers; text outside them is preserved.
Existing issue state, assignees, additional labels and dependencies are preserved.
No resource is deleted, closed or reopened. Remote reads, never the cache, decide
whether a resource exists. An uncertain creation is checked once, never retried.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
BEGIN, END = "<!-- tessryn:managed:start -->", "<!-- tessryn:managed:end -->"


class APIError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def api(path, method="GET", data=None, pages=False):
    command = ["gh", "api", path, "--method", method,
               "-H", "Accept: application/vnd.github+json",
               "-H", "X-GitHub-Api-Version: 2026-03-10"]
    if pages:
        command += ["--paginate", "--slurp"]
    if data is not None:
        command += ["--input", "-"]
    result = subprocess.run(command, input=json.dumps(data) if data is not None else None,
                            text=True, capture_output=True, check=False)
    if result.returncode:
        status = re.search(r"HTTP (\d+)", result.stderr)
        detail = f", HTTP {status[1]}" if status else ""
        raise APIError(f"gh API {method} {path} failed (exit {result.returncode}{detail})",
                       int(status[1]) if status else None)
    answer = json.loads(result.stdout) if result.stdout.strip() else None
    return [item for page in answer for item in page] if pages else answer


def marker(kind, key):
    return f"<!-- tessryn:{kind}:{key} -->"


def title(item):
    prefix = f"[{item['key']}]"
    return item["title"] if item["title"].startswith(prefix) else f"{prefix} {item['title']}"


def identify(items, kind, planned):
    found = {}
    field = "description" if kind == "milestone" else "body"
    for item in planned:
        matches = [remote for remote in items if
                   marker(kind, item["key"]) in (remote.get(field) or "") or
                   remote["title"].startswith(f"[{item['key']}]") or
                   (kind == "milestone" and remote["title"] == item["title"])]
        if len(matches) > 1:
            raise ValueError(f"Ambiguous remote {kind} key {item['key']}; resolve duplicates first")
        if matches:
            found[item["key"]] = matches[0]
    return found


def order_issues(issues, milestones):
    keyed = {item["key"]: item for item in issues}
    if len(keyed) != len(issues):
        raise ValueError("Duplicate issue keys")
    ordered, active, done = [], set(), set()

    def visit(key):
        if key in active:
            raise ValueError(f"Dependency cycle at {key}")
        if key not in keyed:
            raise ValueError(f"Unknown dependency {key}")
        if key in done:
            return
        item = keyed[key]
        if not re.fullmatch(r"[A-Z][A-Z0-9_-]*", key):
            raise ValueError(f"Invalid issue key {key}")
        if item["milestone"] not in milestones:
            raise ValueError(f"Unknown milestone for {key}")
        if not re.fullmatch(r"P\d+", item["priority"]) or item["phase"] not in {"Now", "Next", "Later"}:
            raise ValueError(f"Invalid priority or phase for {key}")
        if not item["title"].strip() or not item["body"].strip():
            raise ValueError(f"Empty title or body for {key}")
        active.add(key)
        for dependency in item.get("depends_on", []):
            visit(dependency)
        active.remove(key)
        done.add(key)
        ordered.append(item)

    for key in keyed:
        visit(key)
    return ordered


def issue_body(item, repo, issue_map):
    text = item["body"].strip()
    if item.get("acceptance"):
        text += "\n\n## Acceptance criteria\n\n" + "\n".join(
            f"- [ ] {criterion}" for criterion in item["acceptance"])
    text += f"\n\nDesign: [design documents](https://github.com/{repo}/tree/main/design)."
    text += f"\n\nPriority: **{item['priority']}** · Phase: **{item['phase']}**."
    dependencies = []
    for key in item.get("depends_on", []):
        remote = issue_map[key]
        dependencies.append(f"- [{key} — #{remote['number']}]({remote['html_url']})"
                            if remote.get("number") else f"- {key} (planned issue)")
    text += "\n\n## Dependencies\n\n" + ("\n".join(dependencies) or "None.")
    return f"{BEGIN}\n{marker('issue', item['key'])}\n{text}\n{END}"


def replace_managed(old, new):
    old = old or ""
    if BEGIN not in old and END not in old:
        return old.rstrip() + "\n\n" + new if old.strip() and new else new or old
    if old.count(BEGIN) != 1 or old.count(END) != 1 or old.index(BEGIN) >= old.index(END):
        raise ValueError("Malformed managed body markers; resolve manually")
    before, rest = old.split(BEGIN, 1)
    _, after = rest.split(END, 1)
    return before + new + after


class Sync:
    def __init__(self, repo, apply):
        self.repo, self.apply = repo, apply
        self.base = f"repos/{repo}"
        self.counts = Counter()

    def read(self, resource, query=""):
        separator = "&" if query else "?"
        return api(f"{self.base}/{resource}{query}{separator}per_page=100", pages=True)

    def change(self, kind, key, path, payload, existing=None, recover=None):
        action = "update" if existing else "create"
        print(f"{'APPLY' if self.apply else 'DRY-RUN'} {action} {kind} {key}", flush=True)
        self.counts[f"{kind}_{action}"] += 1
        if not self.apply:
            return existing or payload
        try:
            result = api(f"{self.base}/{path}", "PATCH" if existing else "POST", payload)
        except APIError as error:
            # POST may have committed despite a client failure. Re-read once and
            # adopt only the uniquely identified resource; never repeat the POST.
            if error.status is not None and 400 <= error.status < 500:
                raise
            result = recover() if recover and not existing else None
            if not result:
                raise
            print(f"Verified already-created {kind} {key} after uncertain response", flush=True)
        time.sleep(1)
        return result


def run(args):
    backlog = json.loads(args.backlog.read_text())
    milestones, issues = backlog["milestones"], backlog["issues"]
    milestone_keys = {item["key"] for item in milestones}
    if len(milestone_keys) != len(milestones):
        raise ValueError("Duplicate milestone keys")
    for item in milestones:
        if not re.fullmatch(r"[A-Z][A-Z0-9_-]*", item["key"]) or not item["title"].strip():
            raise ValueError(f"Invalid milestone {item['key']}")
        if not isinstance(item["description"], str):
            raise ValueError(f"Invalid milestone description {item['key']}")
    issues = order_issues(issues, milestone_keys)
    definitions = backlog.get("labels", [])
    if isinstance(definitions, dict):
        definitions = [dict(value, name=name) for name, value in definitions.items()]
    labels = {}
    for item in definitions:
        item = {"name": item} if isinstance(item, str) else item
        name = item["name"]
        if name in labels:
            raise ValueError(f"Duplicate label {name}")
        labels[name] = {"name": name, "color": item.get("color", "5319e7").lstrip("#"),
                        "description": item.get("description", "")}
    for item in issues:
        for name in item["labels"] + [f"priority:{item['priority']}", f"phase:{item['phase']}"]:
            labels.setdefault(name, {"name": name, "color": "5319e7", "description": ""})
    for label in labels.values():
        if not re.fullmatch(r"[0-9a-fA-F]{6}", label["color"]) or len(label["description"]) > 100:
            raise ValueError(f"Invalid label metadata: {label['name']}")
    if len({name.casefold() for name in labels}) != len(labels):
        raise ValueError("Label names collide when case is ignored")

    sync = Sync(args.repo, args.apply)
    remote_labels = {item["name"].casefold(): item for item in sync.read("labels")}
    milestone_map = identify(sync.read("milestones", "?state=all"), "milestone", milestones)
    issue_map = identify([item for item in sync.read("issues", "?state=all")
                          if "pull_request" not in item], "issue", issues)
    for remote in issue_map.values():
        replace_managed(remote.get("body"), "")  # Validate before any mutation.
    complete = False
    try:
        for name, payload in labels.items():
            remote = remote_labels.get(name.casefold())
            if remote and all(remote.get(key) == value for key, value in payload.items()):
                continue
            update = dict(payload)
            if remote:
                update["new_name"] = update.pop("name")
            sync.change("label", name, f"labels/{quote(remote['name'], safe='')}" if remote else "labels",
                        update, remote, lambda n=name: next(
                            (x for x in sync.read("labels") if x["name"].casefold() == n.casefold()), None))
        for item in milestones:
            key, remote = item["key"], milestone_map.get(item["key"])
            payload = {"title": title(item), "description": item["description"].rstrip() +
                       "\n\n" + marker("milestone", key)}
            if remote and all(remote.get(field) == value for field, value in payload.items()):
                continue
            milestone_map[key] = sync.change("milestone", key,
                f"milestones/{remote['number']}" if remote else "milestones", payload, remote,
                lambda i=item: identify(sync.read("milestones", "?state=all"), "milestone", [i]).get(i["key"]))
        for item in issues:
            key, remote = item["key"], issue_map.get(item["key"])
            desired_labels = set(item["labels"] + [f"priority:{item['priority']}", f"phase:{item['phase']}"])
            if remote:
                desired_labels.update(label["name"] for label in remote["labels"]
                                      if not label["name"].startswith(("priority:", "phase:")))
            payload = {"title": title(item), "body": replace_managed((remote or {}).get("body"),
                       issue_body(item, args.repo, issue_map)), "labels": sorted(desired_labels)}
            milestone_number = milestone_map[item["milestone"]].get("number")
            if milestone_number:
                payload["milestone"] = milestone_number
            unchanged = remote and remote["title"] == payload["title"] and remote.get("body") == payload["body"] 
            unchanged = unchanged and {x["name"] for x in remote["labels"]} == desired_labels
            unchanged = unchanged and (remote.get("milestone") or {}).get("number") == milestone_number
            if not unchanged:
                issue_map[key] = sync.change("issue", key, f"issues/{remote['number']}" if remote else "issues",
                    payload, remote, lambda i=item: identify([x for x in sync.read("issues", "?state=all")
                        if "pull_request" not in x], "issue", [i]).get(i["key"]))
        for item in issues:
            if not item.get("depends_on"):
                continue
            number = issue_map[item["key"]].get("number")
            existing_ids = {x["id"] for x in sync.read(f"issues/{number}/dependencies/blocked_by")} if number else set()
            for dependency in item["depends_on"]:
                blocking_id = issue_map[dependency].get("id")
                if blocking_id in existing_ids:
                    continue
                if args.apply:
                    if not isinstance(number, int) or not isinstance(blocking_id, int):
                        raise ValueError(f"Unresolved remote dependency {item['key']} → {dependency}")
                    sync.change("dependency", f"{item['key']} blocked by {dependency}",
                        f"issues/{number}/dependencies/blocked_by", {"issue_id": blocking_id},
                        recover=lambda n=number, b=blocking_id: next((x for x in sync.read(
                            f"issues/{n}/dependencies/blocked_by") if x["id"] == b), None))
                else:
                    print(f"DRY-RUN add dependency {item['key']} blocked by {dependency}", flush=True)
                    sync.counts["dependency_create"] += 1
        complete = True
    finally:
        if args.apply:
            cache = ROOT / ".planning-cache" / "github-map.json"
            cache.parent.mkdir(parents=True, exist_ok=True)
            result = {"repo": args.repo, "complete": complete, "updated_at": datetime.now(timezone.utc).isoformat(),
                      "milestones": {k: {f: v.get(f) for f in ("number", "html_url")} for k, v in milestone_map.items()},
                      "issues": {k: {f: v.get(f) for f in ("id", "number", "html_url")} for k, v in issue_map.items()}}
            temporary = cache.with_suffix(".tmp")
            temporary.write_text(json.dumps(result, indent=2) + "\n")
            temporary.replace(cache)
        print("Counts: " + json.dumps(dict(sync.counts), sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="AG187-Lab/tessryn")
    parser.add_argument("--backlog", type=Path, default=ROOT / "planning" / "backlog.json")
    parser.add_argument("--apply", action="store_true", help="Create/update GitHub resources; default is dry-run")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        parser.error("--repo must be OWNER/REPOSITORY")
    try:
        run(args)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        print(f"Stopped: {error}. No write is retried; an apply run may be partially complete.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
