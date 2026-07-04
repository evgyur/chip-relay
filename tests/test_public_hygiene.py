#!/usr/bin/env python3
from __future__ import annotations
import pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {'.md', '.sh', '.py', '.yml', '.yaml', '.example', '.gitignore', ''}
DENY_PATTERNS = [
    re.compile(r'pplx-[A-Za-z0-9]{20,}'),
    re.compile(r'gsk_[A-Za-z0-9]{20,}'),
    re.compile(r'gh[opsu]_[A-Za-z0-9]{20,}'),
    re.compile(r'(?:sk-|sk_live_|sk_test_)[A-Za-z0-9_\-]{20,}'),
    re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    re.compile('/opt/' + 'clawd-workspace'),
    re.compile(r'/home/(?:chip|hermes)'),
    re.compile('skills/' + 'secret'),
]
ALLOW_IPS = {'127.0.0.1', '0.0.0.0'}
errors = []
for path in ROOT.rglob('*'):
    if path.is_dir() or '.git' in path.parts or '.supergoal' in path.parts:
        continue
    if path.suffix not in TEXT_SUFFIXES and path.name != 'LICENSE':
        continue
    try:
        text = path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        continue
    for pat in DENY_PATTERNS:
        for m in pat.finditer(text):
            if pat.pattern.startswith('\\b') and m.group(0) in ALLOW_IPS:
                continue
            errors.append(f'{path.relative_to(ROOT)}: denied pattern {pat.pattern}: {m.group(0)}')
if errors:
    print('\n'.join(errors))
    sys.exit(1)
print('public hygiene ok')
