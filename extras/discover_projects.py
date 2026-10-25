#!/usr/bin/env python3
"""Read-only project discovery. Names only: no builds, imports or network."""
import argparse
import json
import os
from pathlib import Path

MARKERS = {
    'javascript': {'package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'},
    'python': {'pyproject.toml', 'setup.py', 'setup.cfg', 'requirements.txt', 'Pipfile', 'Pipfile.lock', 'poetry.lock', 'uv.lock'},
    'java': {'pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts', 'gradle.lockfile'},
    'php': {'composer.json', 'composer.lock'},
    'go': {'go.mod', 'go.sum', 'go.work'},
    'rust': {'Cargo.toml', 'Cargo.lock'},
    'ruby': {'Gemfile', 'Gemfile.lock', 'gems.locked'},
    'dotnet': {'packages.lock.json', 'packages.config', 'global.json', 'Directory.Packages.props'},
}
EXCLUDES = {'.git', '.hg', '.svn', 'node_modules', 'vendor', '.venv', 'venv', '.gradle', '.m2', '.cache', '.tox', '__pycache__', 'target', 'build', 'dist'}
SUPPORTED = {'package-lock.json', 'composer.lock'}


def discover(roots, exclude=(), max_depth=32, max_entries=100000):
    if not isinstance(roots, list) or not roots or not all(isinstance(x, str) and x for x in roots):
        raise ValueError('roots must be a nonempty string array')
    if not isinstance(exclude, (list, tuple)) or not all(isinstance(x, str) and x and '/' not in x and '\\' not in x for x in exclude):
        raise ValueError('exclude must contain directory basenames')
    if type(max_depth) is not int or not 0 <= max_depth <= 128 or type(max_entries) is not int or max_entries < 1:
        raise ValueError('invalid discovery bounds')
    excluded=EXCLUDES | set(exclude)
    projects={}; errors=[]; visited=set(); count=0; pruned=0; symlinks=0; halted=False
    def error(path, message): errors.append({'path':str(path), 'error':str(message)})
    for raw in roots:
        root=Path(raw).expanduser().absolute()
        if any(p.is_symlink() for p in (root, *root.parents)):
            error(root,'symlink root or ancestor is not followed'); continue
        if not root.is_dir(): error(root,'root is not an accessible directory'); continue
        stack=[(root,0)]
        while stack and not halted:
            directory,depth=stack.pop()
            key=str(directory)
            if key in visited: continue
            visited.add(key)
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        count+=1
                        if count>max_entries:
                            error(directory,'entry limit exceeded; discovery incomplete'); halted=True; break
                        try:
                            if entry.is_symlink(): symlinks+=1; continue
                            if entry.is_dir(follow_symlinks=False):
                                if entry.name in excluded: pruned+=1; continue
                                if depth>=max_depth:
                                    error(entry.path,'depth limit reached; discovery incomplete'); continue
                                stack.append((Path(entry.path),depth+1)); continue
                            if not entry.is_file(follow_symlinks=False): continue
                            kinds=[kind for kind,names in MARKERS.items() if entry.name in names]
                            if entry.name.endswith(('.csproj','.fsproj','.vbproj','.sln','.slnx')): kinds.append('dotnet')
                            for kind in kinds:
                                row=projects.setdefault((key,kind),{'path':key,'kind':kind,'manifests':[],'scan_inputs':[], 'discovery_status':'found','dependency_analysis':'unsupported'})
                                row['manifests'].append(entry.path)
                                if entry.name in SUPPORTED:
                                    row['scan_inputs'].append(entry.path); row['dependency_analysis']='parser_available_not_run'
                        except OSError as exc: error(entry.path,exc)
            except OSError as exc: error(directory,exc)
        if halted: break
    rows=sorted(projects.values(),key=lambda r:(r['path'],r['kind']))
    for row in rows:
        row['manifests']=sorted(row['manifests']); row['scan_inputs']=sorted(row['scan_inputs'])
    return {'schema':'secbrief-discovery/v1','status':'degraded' if errors else 'complete','projects':rows,
            'scan_inputs':sorted({p for row in rows for p in row['scan_inputs']}),'errors':errors,
            'coverage':{'roots':roots,'excluded_directory_names':sorted(excluded),'pruned_directories':pruned,
                        'symlinks_skipped':symlinks,'entries_seen':count,'max_depth':max_depth,'max_entries':max_entries,
                        'scope':'configured roots; recognized marker files only; no dependency versions resolved'}}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',action='append',required=True)
    parser.add_argument('--exclude',action='append',default=[])
    parser.add_argument('--max-depth',type=int,default=32)
    parser.add_argument('--max-entries',type=int,default=100000)
    parser.add_argument('--output')
    args=parser.parse_args(argv)
    try:
        result=discover(args.root,args.exclude,args.max_depth,args.max_entries)
        text=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
        if args.output:
            from secbrief_extra import atomic_json
            atomic_json(Path(args.output).expanduser(),result)
        else: print(text,end='')
        return 2 if result['errors'] else 0
    except (OSError,ValueError) as exc:
        print(json.dumps({'status':'degraded','error':str(exc)})); return 2

if __name__=='__main__': raise SystemExit(main())
