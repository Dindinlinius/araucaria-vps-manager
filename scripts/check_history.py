#!/usr/bin/env python3
"""Fail on obvious credentials anywhere in git history, without printing secrets.

This is a conservative pre-publication guard, NOT a complete secret audit.
Run from the repository root with a full git clone (no shallow history).
"""

import io
import re
import subprocess
import sys
import zipfile

PATTERNS = [
    ('private key block', re.compile(rb'-----BEGIN (?:OPENSSH |RSA |EC |DSA |PGP )?PRIVATE KEY-----')),
    ('GitHub token', re.compile(rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})')),
    ('live-looking VLESS URL', re.compile(rb'vless://[0-9a-fA-F-]{36}@[A-Za-z0-9.:\[\]-]+:\d{2,5}\?', re.I)),
    ('live-looking Trojan URL', re.compile(rb'trojan://[A-Za-z0-9_%+.=-]{12,}@[A-Za-z0-9.:-]+:\d{2,5}', re.I)),
    ('credential assignment', re.compile(rb'(?im)^\s*(?:SSH_PASSWORD|XRAY_PASSWORD|API_TOKEN|SECRET_KEY)\s*=\s*["\']?[^#\s"\']{12,}\s*$')),
]
MAX_BLOB = 8 * 1024 * 1024


def git(*args):
    return subprocess.run(['git', *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def issues_in(path, content):
    issues = []
    for title, pattern in PATTERNS:
        if pattern.search(content):
            issues.append((path, title))
    if path.endswith(('.pem', '.p12', '.pfx', '/id_rsa', '/id_ed25519')):
        issues.append((path, 'private-key-like path: manual review required'))
    if path.endswith('.zip') and len(content) <= MAX_BLOB:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                for info in archive.infolist():
                    if info.file_size > MAX_BLOB or info.is_dir():
                        continue
                    data = archive.read(info)
                    issues.extend(issues_in(path + '!' + info.filename, data))
        except (zipfile.BadZipFile, OSError, RuntimeError):
            pass
    return issues


def main():
    if git('rev-parse', '--is-shallow-repository').strip() != b'false':
        print('ERROR: Need full git history (checkout fetch-depth: 0).', file=sys.stderr)
        return 2
    lines = git('rev-list', '--objects', '--all').decode('utf-8', errors='replace').splitlines()
    findings = []
    objects = set()
    for line in lines:
        sha, _, path = line.partition(' ')
        if sha in objects:
            continue
        objects.add(sha)
        if git('cat-file', '-t', sha).strip() != b'blob':
            continue
        length = int(git('cat-file', '-s', sha).strip())
        if length > MAX_BLOB:
            findings.append((path or sha, 'large blob requires manual review'))
            continue
        data = git('cat-file', 'blob', sha)
        findings.extend(issues_in(path or sha, data))
    # Commit messages may carry accidentally pasted credentials too.
    findings.extend(issues_in('git commit messages', git('log', '--all', '--pretty=format:%B')))
    if findings:
        for path, kind in sorted(set(findings)):
            print(f'REVIEW: {kind} in {path}', file=sys.stderr)
        print('Do not publish until these findings are reviewed. No secret values printed.', file=sys.stderr)
        return 1
    print(f'No obvious secrets found in {len(objects)} historical Git objects.')
    print('This check is not exhaustive; also review Git history and public release artifacts.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
