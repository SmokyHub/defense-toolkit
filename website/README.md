# Runtime Code website and test APK

Independent website, CLI and TUI source. Tested host: Linux with Python 3.12. There is no
frontend build or npm step. No emulator, Frida software/server, ADB, wheelhouse or virtualenv
is included. `runtime_code/backends/` contains the application's instrumentation adapter source;
it is not a bundled Frida installation.

macOS host support uses `psutil` for process discovery instead of Linux `/proc`, retaining
the same per-target collector lock. Install the live requirements below with Python 3.12;
the launcher automatically uses `.venvs/runtime/bin/python` when present. An explicit
`RUNTIME_CODE_PYTHON` overrides that choice. Host compatibility paths have regression tests;
a complete macOS-to-Android live capture has not been validated in this lab.
ADB must be installed separately and available on `PATH`. Supply an **Android** Frida server
matching the phone's ABI, even when the host is an Apple Silicon Mac.

## Browse saved evidence

Copy the entire saved store directory from the original PC after stopping its collector/server
(SQLite files and artifact contents together). Then:

```bash
./runtime-code --store /path/copied-store runs
./runtime-code --store /path/copied-store serve --run RUN_ID
```

Open the printed local workspace URL including its token. This uses the Python standard library
and does not need Frida or a connected phone. Saved Runs are not shipped with this component.

## Test live collection with the included APK

`test-apk/runtime-flow.apk` is the exact benign obfuscated release fixture used for the
workbench: package `lab.runtimecode.flow`, min Android API 26. `test-apk/live-pack.json` is
its matching capture pack. `test-apk/SHA256SUMS` lets you verify both files. The fixture
exercises dynamic DEX input, a loopback server, parsing, AES decoding, Activity/Fragment
hops, WebView interception and the JS bridge, then attempts navigation to Google.

Use your own authorized rooted device/emulator, ADB and matching Frida installation. The
documented lab device policy is retained; the Pixel serial below is the authorized lab Pixel.
`watch` expects the stock 17.18.0 Android server file in `~/tools/frida-server/`, or in a directory
selected with `RUNTIME_CODE_SERVER_DIR`. Required filenames are
`frida-server-17.18.0-android-arm64` or `frida-server-17.18.0-android-x86_64`.
These server files must be supplied separately. The live host requirements are declared in
`requirements-live-optional.txt` if you need to prepare your own Python environment.

```bash
# On the destination PC, install dependencies separately if needed:
python3.12 -m venv .venvs/runtime
.venvs/runtime/bin/python -m pip install -r requirements-live-optional.txt
export RUNTIME_CODE_PYTHON="$PWD/.venvs/runtime/bin/python"

# Optional automatic static DEX/URL indexing:
python3.12 -m venv .venvs/analysis
.venvs/analysis/bin/python -m pip install -r requirements-analysis.txt

adb -s 33011FDH20018E install -r test-apk/runtime-flow.apk
./runtime-code watch --device 33011FDH20018E --app lab.runtimecode.flow \
  --pack test-apk/live-pack.json
```

Pass the application package using `--app`. To load your own additional Frida script
alongside the built-in capture agent, pass its filename with `--script` (absolute paths
avoid ambiguity; relative paths are resolved from this website directory):

```bash
./runtime-code watch --device 33011FDH20018E --app lab.runtimecode.flow \
  --pack test-apk/live-pack.json --script /absolute/path/my-script.js
```

Repeat `--script` for multiple files (maximum 8, 4 MiB each, 8 MiB total). These files are
analyst-selected executable instrumentation, separate from detection packs. Each loads in
its own Frida script context, with its own globals/RPC exports and an available Java bridge.
Your script may use its own `Module` global; the built-in collector uses `Process` queries.
This does not restore APIs removed by Frida 17 or prevent conflicts when two scripts hook
the same method. Source files must be compatible standalone Frida JavaScript, not Python
or an unbundled Node/TypeScript project.

Companions load after the collector script is loaded and are installed on each attached
app process. Startup remains late-attached; asynchronous hook readiness is not guaranteed.
They detach with the collector. Coverage records script names/hashes and load state;
All events shows bounded `companion.message`/`companion.error` previews. Companion binary
messages are not retained as artifacts, and dropped-message totals are reported on detach.

The website opens and the command prints its URL. Wait for instrumentation to become active,
then tap **Run encrypted web flow** or **Load dynamic DEX** in the fixture. Network/Navigation,
Crypto, Parsers, Findings and Code & URL search display the observed results. A Google failure
can be legitimate network/proxy behavior; a decrypted URL alone is not proof of a request.
Stop with Ctrl+C before starting another collector. Capture attaches late and may miss startup
events. Unknown ART/linker profiles and unavailable access fail explicitly.

Without static dependencies use `--no-static`. You can set `RUNTIME_CODE_ANALYSIS_PYTHON` to
an existing interpreter with Androguard instead of creating `.venvs/analysis`.
See `docs/` for exact supported coverage; paths there refer to the original lab layout.
On macOS the optional static index worker applies CPU/output limits and bounded input and
evaluation, plus the host's 60-second timeout; it cannot enforce Linux's hard address-space
limit. This limitation is included in each successful index result.
