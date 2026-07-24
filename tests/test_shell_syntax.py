#!/usr/bin/env python3
from __future__ import annotations
import pathlib
import subprocess
ROOT = pathlib.Path(__file__).resolve().parents[1]
scripts = sorted((ROOT / 'scripts').glob('*.sh')) + [ROOT / 'scripts' / 'chip-relay']
for script in scripts:
    subprocess.run(['bash', '-n', str(script)], check=True)
print('shell syntax ok')
