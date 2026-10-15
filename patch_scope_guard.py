"""Give coding agents a reviewable boundary for every proposed patch."""

import fnmatch
import shlex
from pathlib import PurePosixPath


def analyze(data):
    files=[]; current=None; in_hunk=False
    for line in data['diff'].splitlines():
        if line.startswith(('diff --cc ','diff --combined ')):
            raise ValueError('combined diffs are unsupported; supply a two-tree diff')
        if line.startswith('diff --git '):
            parts=shlex.split(line)
            if len(parts)!=4:
                raise ValueError('malformed diff header; quote paths containing spaces')
            old,new=parts[2:]
            if not old.startswith('a/') or not new.startswith('b/'):
                raise ValueError('expected standard a/ and b/ prefixes')
            current={'old':old[2:],'new':new[2:],'added':0,'deleted':0,'binary':False}
            files.append(current); in_hunk=False
        elif current is not None:
            if line.startswith('@@ '): in_hunk=True
            elif line.startswith(('Binary files ','GIT binary patch')): current['binary']=True
            elif in_hunk and line.startswith('+'): current['added']+=1
            elif in_hunk and line.startswith('-'): current['deleted']+=1
    if data['diff'].strip() and not files:
        raise ValueError('no standard Git diff headers found')
    allow=data.get('allow',['*']); deny=data.get('deny',[])
    findings=[]
    for f in files:
        for path in sorted({f['old'],f['new']}):
            p=PurePosixPath(path)
            if p.is_absolute() or '..' in p.parts or '\\' in path or any(ord(c)<32 for c in path):
                findings.append({'path':path,'reason':'unsafe_path'})
            if not any(fnmatch.fnmatchcase(path,g) for g in allow):
                findings.append({'path':path,'reason':'outside_allowlist'})
            if any(fnmatch.fnmatchcase(path,g) for g in deny):
                findings.append({'path':path,'reason':'denied_path'})
        if f['binary']:
            findings.append({'path':f['new'],'reason':'binary_requires_review'})
    changed=sum(f['added']+f['deleted'] for f in files)
    budget=data.get('max_changed_lines',500)
    if type(budget) is not int or budget<0:
        raise ValueError('max_changed_lines must be a nonnegative integer')
    if changed>budget:
        findings.append({'reason':'line_budget_exceeded','actual':changed,'budget':budget})
    return {'within_scope':not findings,'changed_lines':changed,'files':files,'findings':findings}


def main():
    """Read one UTF-8 JSON document and emit one machine-readable report."""
    import argparse
    import json
    import sys
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="JSON input path, or - for stdin")
    args = parser.parse_args()
    try:
        raw = sys.stdin.read() if args.input == "-" else Path(args.input).read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("input must be a JSON object")
        result = analyze(data)
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    except (OSError, ValueError, KeyError, TypeError, OverflowError) as error:
        print(f"Invalid input: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
