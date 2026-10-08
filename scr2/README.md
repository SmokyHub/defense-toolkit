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

For a Mac where **only existing Blutter 3.12.1 is allowed and compilation is unavailable**:

```bash
.venv/bin/python analyze_dex_response.py /path/application.zip \
  --flutter-reader python --semantic-python .venv/bin/python \
  --out results/python-case --proof-response ready-response.json
```

The bundled Python reader supports the older snapshot format used by Drift and APK2
(`78da37fed6bf1489361a312568249f3f`, Android ARM64 compressed-pointer full-AOT product).
It reads the submitted ELF directly and uses no Blutter binary, compiler, SDK source,
app-specific pack or cached analysis. Your existing 3.12.1 installation can stay in place;
`--blutter-bin` is unused in explicit Python mode. Do not use `--prepare-blutter` with it.
The format identifier is shared by apps; it is not a hash allowlist of client APKs/libapp.

Default `--flutter-reader auto` first selects a compatible native analyzer, then falls
back to Python when none matches and the snapshot format is supported. This also works
with an incompatible pinned 3.12.1 analyzer. `--flutter-reader blutter` forces the native
path. Reports name the reader actually used. Other formats still need compatible native
Blutter builds for the host OS/CPU. Unknown formats or unsupported flows remain review
items; this does not make Blutter 3.12.1 itself read every snapshot version.
Python-reader validation ran on Linux against both saved apps and changed-key ELF bytes;
Mac execution has not been independently tested.

With an installed Blutter source checkout and its normal build dependencies, use this
on macOS or Linux (the initial build may take many minutes):

```bash
.venv/bin/python analyze_dex_response.py /path/application.zip \
  --blutter-dir /path/to/blutter --prepare-blutter \
  --out results/new-flutter-case --proof-response ready-response.json
```

`--prepare-blutter` asks the installed upstream Blutter wrapper to determine/build the
matching stock Dart VM if missing, then builds the bundled semantic metadata extension.
It can download toolchain sources; the APK stays local and its code is not executed.
Existing compatible semantic builds are reused. Stock builds and other versions are
preserved. Setup prints a persistent log path to stderr. The default timeout is 1,800
seconds; use `--blutter-build-timeout 3600` for slower builds. Include `libflutter.so` and
`libapp.so` from the **same ARM64 split set**. Preparation cannot fetch a Blutter checkout
or fix an upstream-unsupported snapshot; failures remain explicit.

Without `--prepare-blutter`, analysis remains offline and never starts a build. Repeat
`--blutter-dir` to search several installations; either the checkout root or its `bin/`
directory is accepted. `BLUTTER_HOME` supplies the default root; otherwise `~/tools/blutter`
and `~/blutter` are searched. `--blutter-bin` pins native selection; auto mode may use the supported Python fallback.
For native analysis, use a host-compatible binary. The Python path needs no native analyzer build.
The extension preserves the stock build's compiler and macOS architecture/SDK settings.

The automatic pass covers the tested APK1–APK3 collection/JNI paths and Drift's
preferences-mediated path without application profiles. Numeric, literal string and mixed
preference keys are derived from their use in the loader, including changed key names.
Keep `flutter_toolchain.py`, `flutter_preferences.py` and the other modules together.
This supports variations of the recognized flow; arbitrary future Flutter versions,
compiler transformations or different loaders are **not guaranteed**. Unsupported or
ambiguous flows remain `needs_review`, with no guessed proof response.

Manual extension building is still available when the matching stock VM is installed:

```bash
.venv/bin/python build_flutter_semantic_blutter.py --blutter-dir /path/to/blutter \
  --dartlib dartvm3.12.2_android_arm64 --out build/semantic-3.12.2 --install
```

Choose the stock build's actual Dart library name, not necessarily the example version.
Drift and APK2 can use the Python reader above; their native alternative is a compatible `dartvm3.11.1_android_arm64` build.
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
