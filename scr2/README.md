# Family2 — response JSON analyzer

This component works independently of family1 and the website. Keep the Python modules and `.inc` helper together. Python 3.10+ is required; 3.12 is tested. Profiles are optional and disabled by default.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python analyze_dex_response.py /path/application.zip \
  --semantic-python .venv/bin/python --out results/new-case
```

Include the base and ARM64 split for Flutter inputs. `--print-template` prints the filled
response JSON with `"DEX ARRAY"` instead of real DEX bytes. Reports, templates and JSON Schemas
are also saved under the new output directory. The tested default contract is
`com.apkdefense.fixture.webview.ResponseEntry.run(android.app.Activity)`.

Automatic Flutter discovery also needs an installed native Blutter analyzer compatible with the
submitted Dart snapshot. Set `--blutter-dir /path/to/blutter` or `--blutter-bin /path/to/analyzer`.
No Blutter, emulator or Frida binary is bundled; discovery never downloads tooling automatically.

The automatic Flutter pass generates APK1–APK3 loader templates without application profiles.
It requires the semantic metadata extension to the compatible stock Blutter build:

```bash
python3 build_flutter_semantic_blutter.py --blutter-dir /path/to/blutter \
  --dartlib dartvm3.12.2_android_arm64 --out build/semantic-3.12.2 --install
```

Build the matching stock analyzer first; use a fresh output directory. APK2 uses the compatible
`dartvm3.11.1_android_arm64` build. The extension downloads nothing and does not execute app code.
The report retains conditional-path and JNI/library assumptions. It is a compatible static test
contract, not proof of network delivery or runtime execution. Automatic Dalvik consumer analysis can emit complete templates for
its supported bytecode patterns. Unsupported variants report review status, not an invented schema. This is offline
static analysis: no app execution, Frida, device, server contact or upload is needed.
For optional legacy operation, explicitly use the three reviewed Flutter profiles and print their complete templates:

```bash
python3 analyze_dex_response.py /path/application.zip --out results/reviewed-case \
  --reviewed-profiles --no-semantic --print-template
```

Only that legacy path requires the bundled `dex_response_profiles/` directory.
See `technical-notes.md` for exact coverage (its paths describe the original lab layout).

APK3 uses outer key `578`; support is statically reviewed, with no APK3 runtime validation.
