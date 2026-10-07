**Python 3.10+ and Node.js 18+**, installed separately.
## Detect an app

From this folder:

```bash
python3 analyze_family3_native.py /path/to/app.apk --out analysis.json
```

For split installations, pass the complete original split directory or `.apks`, `.xapk` or ZIP
containing its APKs. A base APK alone may not contain the native libraries:

```bash
python3 analyze_family3_native.py /path/to/original-splits/ --out analysis.json
```

Extracted `.so` files/directories also work. ARM64 ELF64 little-endian libraries are analyzed;
unsupported ABIs are reported as skipped. Inputs are read locally, never executed or uploaded.
Archive paths are not extracted onto the filesystem; only bounded library bytes are staged in
a temporary directory. Analyze one app at a time when generating a response.

## Generate the same proof screen used in the Pixel tests

```bash
python3 analyze_family3_native.py /path/to/original-splits/ \
  --out analysis.json \
  --proof-response proof-response.json
```
