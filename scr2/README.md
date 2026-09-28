# Family2 — response JSON analyzer

This component works independently of family1 and the website. Keep both Python files and
`dex_response_profiles/` together. Python 3.10+ is required; 3.12 is tested.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python analyze_dex_response.py /path/application.zip \
  --semantic-python .venv/bin/python --out results/new-case --print-template
```

Include the base and ARM64 split for Flutter inputs. `--print-template` prints the filled
response JSON with `"DEX ARRAY"` instead of real DEX bytes. Reports, templates and JSON Schemas
are also saved under the new output directory. The tested default contract is
`com.apkdefense.fixture.webview.ResponseEntry.run(android.app.Activity)`.

All three reviewed NN555 Flutter ARM64 profiles (APK1, APK2 and APK3/Dart 3.12.2) and the bounded Dalvik consumer analyzer are
included. Unsupported variants report review status, not an invented schema. This is offline
static analysis: no app execution, Frida, device, server contact or upload is needed.
For profile-only matching without Androguard, use system Python with `--no-semantic`.
See `technical-notes.md` for exact coverage (its paths describe the original lab layout).

APK3 uses outer key `578`; support is statically reviewed, with no APK3 runtime validation.
