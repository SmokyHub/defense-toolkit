#!/usr/bin/env python3
"""Verify every shipped file; generated virtual environments and results are not shipped."""
import hashlib
import json
from pathlib import Path

root=Path(__file__).resolve().parent
manifest=json.loads((root/'MANIFEST.json').read_text())
errors=[]
for name,expected in manifest['files'].items():
    path=root/name
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
        errors.append(name)
if errors:raise SystemExit('Missing/changed bundle files: '+', '.join(errors))
print(f"Verified {len(manifest['files'])} shipped files.")
