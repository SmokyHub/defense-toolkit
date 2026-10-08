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
are also saved under the new output directory. **`response.proof.json` is generated automatically
with the actual bundled benign DEX bytes** for the default contract, so that file is ready for
an authorized response-replacement test. The tested default contract is
`com.apkdefense.fixture.webview.ResponseEntry.run(android.app.Activity)`.

For a convenient additional copy:

```bash
.venv/bin/python analyze_dex_response.py /path/application.zip --out results/new-proof-case \
  --proof-response ready-response.json
```

The export requires one complete compatible loader and a fresh destination. Keep `fixtures/`
and `dex_response_proof.py` with the analyzer; the 5,120-byte fixture's hash is checked before use.
The proof screen displays “APK Defense: DEX executed” and a working local button, without making
a network request. Generation alone does not prove execution. Custom payload contracts or a
missing/modified fixture get an explicit reason and no proof file; ordinary templates remain
available. See `fixtures/README.md` for provenance.

Automatic Flutter discovery also needs an installed native Blutter analyzer compatible with the
submitted Dart snapshot. Set `--blutter-dir /path/to/blutter` or `--blutter-bin /path/to/analyzer`.
No Blutter, emulator or Frida binary is bundled; discovery never downloads tooling automatically.

The automatic Flutter pass generates APK1–APK3 and the tested Drift preferences-mediated
loader templates without application profiles. Keep `flutter_preferences.py` with the other modules.
It requires the semantic metadata extension to the compatible stock Blutter build:

```bash
python3 build_flutter_semantic_blutter.py --blutter-dir /path/to/blutter \
  --dartlib dartvm3.12.2_android_arm64 --out build/semantic-3.12.2 --install
```

Build the matching stock analyzer first; use a fresh output directory. APK2 uses the compatible
`dartvm3.11.1_android_arm64` build, also compatible with the tested Drift snapshot. The extension downloads nothing and does not execute app code.
The report retains conditional-path and JNI/library assumptions. It is a compatible static test
contract, not proof of network delivery or runtime execution. Automatic Dalvik consumer analysis can emit complete templates for
its supported bytecode patterns. Unsupported variants report review status, not an invented schema. This is offline
static analysis: no app execution, Frida, device, server contact or upload is needed.
Drift persists the response object's entries through asynchronous shared preferences before
reading them into its JNI loader. Its wire response takes an ordinary JSON byte array; the app
performs the intermediate Base64/UTF-8/JSON storage conversion itself. See the generated
`preferences_boundary` evidence and `technical-notes.md` for the checks and limitations.

For optional legacy operation, supply the reviewed Flutter profiles separately and print their complete templates:

```bash
python3 analyze_dex_response.py /path/application.zip --out results/reviewed-case \
  --reviewed-profiles --no-semantic --print-template
```

Only that legacy path requires a `dex_response_profiles/` directory. Default portable bundles
omit it; the repository builder offers an explicit `--include-reviewed-profiles` option.
See `technical-notes.md` for exact coverage (its paths describe the original lab layout).

APK3 uses outer key `578`; support is statically reviewed, with no APK3 runtime validation.
