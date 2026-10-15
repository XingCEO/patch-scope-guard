"""Check the scope of a committed Git change before an agent patch is merged."""

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


_POLICY_KEYS = {"allow", "deny", "max_changed_lines"}
_HASH = re.compile(rb"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_RAW = re.compile(rb":([0-7]{6}) ([0-7]{6}) ([0-9a-f]+) ([0-9a-f]+) ([AMDT]|R[0-9]{1,3})")
_HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?")
_HEADER = re.compile(r"diff --git a/([^\s]+) b/([^\s]+)")


def _policy(data):
    if not isinstance(data, dict):
        raise ValueError("policy must be a JSON object")
    unknown = set(data) - _POLICY_KEYS
    if unknown:
        raise ValueError("unknown policy fields: " + ", ".join(sorted(unknown)))
    for key in ("allow", "deny"):
        value = data.get(key, ["*"] if key == "allow" else [])
        if not isinstance(value, list) or any(not isinstance(p, str) or not p or "\0" in p for p in value):
            raise ValueError(f"{key} must be a list of nonempty string patterns")
    budget = data.get("max_changed_lines", 500)
    if type(budget) is not int or budget < 0:
        raise ValueError("max_changed_lines must be a nonnegative integer")
    return data.get("allow", ["*"]), data.get("deny", []), budget


def _report(files, policy):
    allow, deny, budget = _policy(policy)
    findings = []
    for file in files:
        for path in sorted({file["old"], file["new"]}):
            p = PurePosixPath(path)
            if (
                p.is_absolute()
                or not p.parts
                or str(p) != path
                or ".." in p.parts
                or "\\" in path
                or any(ord(c) < 32 or ord(c) == 127 for c in path)
            ):
                findings.append({"path": path, "reason": "unsafe_path"})
            if not any(fnmatch.fnmatchcase(path, pattern) for pattern in allow):
                findings.append({"path": path, "reason": "outside_allowlist"})
            if any(fnmatch.fnmatchcase(path, pattern) for pattern in deny):
                findings.append({"path": path, "reason": "denied_path"})
        if file["binary"]:
            findings.append({"path": file["new"], "reason": "binary_requires_review"})
        if "160000" in (file.get("old_mode"), file.get("new_mode")):
            findings.append({"path": file["new"], "reason": "submodule_requires_review"})
    changed = sum(file["added"] + file["deleted"] for file in files)
    if changed > budget:
        findings.append({"reason": "line_budget_exceeded", "actual": changed, "budget": budget})
    return {"within_scope": not findings, "changed_lines": changed, "files": files, "findings": findings}


def _text_files(diff):
    """Parse a strict, portable subset; ambiguous Git quoted names are rejected."""
    if not isinstance(diff, str):
        raise ValueError("diff must be a string")
    files, current, metadata = [], None, []
    remaining = [0, 0]
    saw_hunk = headers = False

    def finish():
        if remaining != [0, 0]:
            raise ValueError("truncated hunk")
        if current is not None:
            if not metadata and not saw_hunk:
                raise ValueError("diff header has no change content")
            renames = [line for line in metadata if line.startswith("rename ")]
            if current["old"] != current["new"]:
                expected = ["rename from " + current["old"], "rename to " + current["new"]]
                if renames != expected:
                    raise ValueError("rename headers must match both diff paths")
            elif renames:
                raise ValueError("unexpected rename metadata")
            if not saw_hunk and not (renames or current["binary"] or any(line.startswith(("new file mode ", "deleted file mode ")) for line in metadata) or (any(line.startswith("old mode ") for line in metadata) and any(line.startswith("new mode ") for line in metadata))):
                raise ValueError("metadata does not describe a complete change")
            if headers and not saw_hunk:
                raise ValueError("text headers without a hunk")
            files.append(current)

    lines = diff.split("\n") if diff else []
    if lines and lines[-1] == "":
        lines.pop()
    for line in lines:
        if line.startswith("diff --git "):
            finish()
            match = _HEADER.fullmatch(line)
            if not match or any(ord(c) < 33 or ord(c) > 126 or c in '\\"' for p in match.groups() for c in p):
                raise ValueError("text mode requires unquoted ASCII paths without whitespace; use --repo for other names")
            old, new = match.groups()
            current = {"old": old, "new": new, "added": 0, "deleted": 0, "binary": False}
            metadata, saw_hunk, headers = [], False, False
            remaining = [0, 0]
        elif current is None:
            raise ValueError("expected a standard two-tree Git diff header")
        elif line == "\\ No newline at end of file" and saw_hunk:
            pass
        elif remaining != [0, 0]:
            if not line or line[0] not in " +-":
                raise ValueError("invalid or truncated hunk content")
            if line[0] in " -":
                remaining[0] -= 1
            if line[0] in " +":
                remaining[1] -= 1
            if min(remaining) < 0:
                raise ValueError("hunk line count exceeds header")
            if line[0] == "+":
                current["added"] += 1
            elif line[0] == "-":
                current["deleted"] += 1
        elif line.startswith("@@ "):
            if headers is not True:
                raise ValueError("hunk requires matching --- and +++ headers")
            match = _HUNK.fullmatch(line)
            if not match:
                raise ValueError("malformed hunk header")
            remaining = [int(match[2] or 1), int(match[4] or 1)]
            saw_hunk = True
        elif not saw_hunk and line.startswith("--- "):
            if headers or line[4:] not in ("a/" + current["old"], "/dev/null"):
                raise ValueError("invalid old file header")
            headers = "old"
        elif not saw_hunk and line.startswith("+++ "):
            if headers != "old" or line[4:] not in ("b/" + current["new"], "/dev/null"):
                raise ValueError("invalid new file header")
            headers = True
        elif not saw_hunk and re.fullmatch(r"(?:new file|deleted file|old|new) mode [0-7]{6}", line):
            metadata.append(line)
            mode = line.rsplit(" ", 1)[1]
            if line.startswith("new file mode "):
                current.update(old_mode="000000", new_mode=mode)
            elif line.startswith("deleted file mode "):
                current.update(old_mode=mode, new_mode="000000")
            elif line.startswith("old mode "):
                current["old_mode"] = mode
            else:
                current["new_mode"] = mode
        elif not saw_hunk and re.fullmatch(r"index [0-9a-f]+\.\.[0-9a-f]+(?: [0-7]{6})?", line):
            metadata.append(line)
            parts = line.split()
            if len(parts) == 3:
                current.setdefault("old_mode", parts[2])
                current.setdefault("new_mode", parts[2])
        elif not saw_hunk and (re.fullmatch(r"(?:dis)?similarity index \d{1,3}%", line) or line.startswith(("rename from ", "rename to "))):
            metadata.append(line)
        elif not saw_hunk and line == f"Binary files a/{current['old']} and b/{current['new']} differ":
            current["binary"] = True
            metadata.append(line)
        else:
            raise ValueError("unsupported or malformed text diff; use --repo for authoritative Git metadata")
    finish()
    return files


def analyze(data):
    """Compatibility JSON API for strict portable unified diffs."""
    if not isinstance(data, dict) or "diff" not in data:
        raise ValueError("input must be a JSON object containing diff")
    policy = {key: value for key, value in data.items() if key != "diff"}
    _policy(policy)
    return _report(_text_files(data["diff"]), policy)


def _git(repo, arguments):
    # Do not let inherited Git routing/config variables silently select another repo.
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    environment["GIT_TERMINAL_PROMPT"] = "0"
    command = ["git", "--no-pager", "-C", str(repo), "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *arguments]
    try:
        run = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=60, check=False)
    except subprocess.TimeoutExpired as error:
        raise ValueError("Git operation exceeded 60 seconds") from error
    if run.returncode:
        detail = run.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError("Git failed: " + detail)
    return run.stdout


def _resolve(repo, revision):
    if not isinstance(revision, str) or not revision or "\0" in revision:
        raise ValueError("revision must be a nonempty string")
    value = _git(repo, ["rev-parse", "--verify", "--end-of-options", revision + "^{commit}"]).strip()
    if not _HASH.fullmatch(value):
        raise ValueError("Git did not return one commit object ID")
    return value.decode("ascii")


def _path(raw):
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("non-UTF-8 Git paths are unsupported") from error
    if not value:
        raise ValueError("empty Git path")
    return value


def _tokens(raw):
    if raw and not raw.endswith(b"\0"):
        raise ValueError("truncated NUL-delimited Git metadata")
    return raw[:-1].split(b"\0") if raw else []


def _git_files(raw, stats):
    tokens = iter(_tokens(raw))
    files = []
    try:
        for token in tokens:
            match = _RAW.fullmatch(token)
            if not match or not _HASH.fullmatch(match[3]) or not _HASH.fullmatch(match[4]):
                raise ValueError("unsupported or malformed Git raw record")
            old_mode, new_mode, _, _, status = [part.decode("ascii") for part in match.groups()]
            old = _path(next(tokens))
            new = _path(next(tokens)) if status.startswith("R") else old
            if status.startswith("R") and int(status[1:]) > 100:
                raise ValueError("invalid Git rename score")
            files.append({"old": old, "new": new, "added": 0, "deleted": 0, "binary": False, "status": status, "old_mode": old_mode, "new_mode": new_mode})
        tokens = iter(_tokens(stats))
        by_path = {(file["old"], file["new"]): file for file in files}
        if len(by_path) != len(files):
            raise ValueError("duplicate Git change records")
        for token in tokens:
            columns = token.split(b"\t", 2)
            if len(columns) != 3:
                raise ValueError("malformed Git numstat record")
            added, deleted, raw_path = columns
            if raw_path:
                old = new = _path(raw_path)
            else:
                old, new = _path(next(tokens)), _path(next(tokens))
            file = by_path.pop((old, new), None)
            if file is None:
                raise ValueError("Git raw/numstat path mismatch")
            if added == deleted == b"-":
                file["binary"] = True
            elif re.fullmatch(rb"\d+", added) and re.fullmatch(rb"\d+", deleted):
                file["added"], file["deleted"] = int(added), int(deleted)
            else:
                raise ValueError("invalid Git line counts")
        if by_path:
            raise ValueError("missing Git numstat records")
    except StopIteration as error:
        raise ValueError("truncated Git path record") from error
    return files


def analyze_repo(repo, base, head="HEAD", policy=None):
    """Compare two immutable commits; never execute a patch, diff driver or textconv."""
    policy = {} if policy is None else policy
    _policy(policy)
    base_id, head_id = _resolve(repo, base), _resolve(repo, head)
    options = ["diff", "--no-ext-diff", "--no-textconv", "--ignore-submodules=none", "--no-color", "--no-abbrev", "--find-renames=50%", "-l1000", "--no-relative", "-z"]
    raw = _git(repo, [*options, "--raw", base_id, head_id, "--"])
    stats = _git(repo, [*options, "--numstat", base_id, head_id, "--"])
    report = _report(_git_files(raw, stats), policy)
    report["comparison"] = {"base": base_id, "head": head_id}
    return report


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def _json(path):
    raw = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    return json.loads(raw, object_pairs_hook=_unique_object)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", help="legacy JSON diff input, or - for stdin")
    parser.add_argument("--repo", help="local Git repository (committed changes only)")
    parser.add_argument("--base", help="base commit or revision")
    parser.add_argument("--head", default="HEAD", help="head commit or revision (default HEAD)")
    parser.add_argument("--policy", help="JSON policy path, or - for stdin")
    parser.add_argument("--check", action="store_true", help="exit 1 if the report contains findings")
    args = parser.parse_args(argv)
    if args.repo:
        if args.input or not args.base:
            parser.error("--repo requires --base and cannot be combined with JSON diff input")
    elif args.base or args.policy or args.head != "HEAD" or not args.input:
        parser.error("provide JSON diff input, or --repo with --base")
    try:
        result = analyze_repo(args.repo, args.base, args.head, _json(args.policy) if args.policy else {}) if args.repo else analyze(_json(args.input))
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    except (OSError, ValueError, KeyError, TypeError, OverflowError) as error:
        print(f"Invalid input: {error}", file=sys.stderr)
        return 2
    return 1 if args.check and not result["within_scope"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
