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

## Configure each PC

Run `./runtime-code config init` to create `runtime-code.local.json`, then edit ADB/server
paths, the default device, Frida version/port and timeouts there.
Any connected Android device can be selected; no designated image or device allowlist is required.
`./runtime-code config show` displays the effective settings.
See [configuration examples and troubleshooting](docs/runtime-code-configuration.md), including
a Mac emulator example. Use `--config /path/mac.json` to select a different settings file.

For a freeze during instrumentation, add `--debug` to the same command. A separate local
diagnostic page opens before attachment and identifies the last startup/hook checkpoint,
host waits, missing agent heartbeats or an unresponsive Android main thread. It works
without copying logs to another PC. See [freeze diagnostics](docs/runtime-code-configuration.md#diagnose-a-freeze-on-the-same-pc).

```bash
./runtime-code run --device SERIAL --app lab.runtimecode.flow --debug
```

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
an optional matching explicit scope pack; automatic runs need no pack. `test-apk/SHA256SUMS` lets you verify both files. The fixture
contains 21 scenarios covering gated responses, decoder frequency, byte conversions, crypto,
WebViews, Custom Tabs, package filters, logcat and the original DEX/JS bridge flows.
See `test-apk/CASES.md` for the matrix; only the original encrypted flow attempts Google navigation.

Use your own authorized rooted device/emulator, ADB and matching Frida installation.
The example below selects an Android emulator.
`watch` defaults to the stock 17.18.0 Android server file in `~/tools/frida-server/`, or in a directory
selected with `RUNTIME_CODE_SERVER_DIR`. Preferred host filenames are
`frida-server-17.18.0-android-arm64` or `frida-server-17.18.0-android-x86_64`.
The same directory can instead contain a matching Android binary named `frida-server`.
If no host binary is present, `watch` can reuse or start a matching server already on
Android, including `/data/local/tmp/frida-server`; it checks the reported version and
running executable hash and respects your configured device port.
Set `frida.version` and `paths.server_dir` to use another matching host/server installation.
These server files must be supplied separately. The live host requirements are declared in
`requirements-live-optional.txt` if you need to prepare your own Python environment.
For **Frida 17.5.2**, install `requirements-live-frida-17.5.2.txt` instead, set
`frida.version` to `17.5.2` in `runtime-code.local.json`, and supply
`frida-server-17.5.2-android-arm64` for your ARM64 Android emulator. This uses compatible
`frida-tools==14.5.0` and needs no untested-version override. See the Mac configuration
example linked above.

```bash
# On the destination PC, install dependencies separately if needed:
python3.12 -m venv .venvs/runtime
.venvs/runtime/bin/python -m pip install -r requirements-live-optional.txt
export RUNTIME_CODE_PYTHON="$PWD/.venvs/runtime/bin/python"

# Optional automatic static DEX/URL indexing:
python3.12 -m venv .venvs/analysis
.venvs/analysis/bin/python -m pip install -r requirements-analysis.txt

adb -s emulator-5554 install -r test-apk/runtime-flow.apk
./runtime-code run --device emulator-5554 --app lab.runtimecode.flow
```

Pass the application package using `--app`. To load your own additional Frida script
alongside the built-in capture agent, pass its filename with `--script` (absolute paths
avoid ambiguity; relative paths are resolved from this website directory):

```bash
./runtime-code run --device emulator-5554 --app lab.runtimecode.flow --script /absolute/path/my-script.js
```

Repeat `--script` for multiple files (maximum 8, 4 MiB each, 8 MiB total). These files are
analyst-selected executable instrumentation, separate from detection packs. Each loads in
its own Frida script context, with its own globals/RPC exports and an available Java bridge.
Your script may use its own `Module` global; the built-in collector uses `Process` queries.
The companion adapter restores legacy Module lookup/enumeration through Process; it cannot prevent conflicts when two scripts hook
the same method. Source files must be compatible standalone Frida JavaScript, not Python
or an unbundled Node/TypeScript project.

Companions load after the collector reports hook readiness and are installed on each attached
app process. Startup remains late-attached; companion Java.perform callbacks can finish later.
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
The workspace includes copyable crypto values (Text/Hex/Base64), frequency-ranked decoder
candidates and CIPHER - PLAINTEXT / JSONL exports, compact flow JSON with a copy icon,
eight-hop request/parser context and package exclusions such as `-pkg:com.appsflyer`.
Use **Request backtracking** in the Explore sidebar, select a request/response and leave
**Backtrack hops** at 8 to inspect linked events, shared parser callers, JSON fields and
possible WebView/Custom Tab connections. **Decrypted strings** opens the CIPHER → PLAINTEXT
table immediately; method call counts are on the left, with copy, source-flow inspection
and mass export controls. Shared callers and readable strings remain labeled candidates.
Open **Logcat** in the header or **Session → ADB logcat** in the sidebar (scroll the
sidebar if needed). It is collected separately during live capture and has level colors
and text search. If neither button appears, restart the server from the updated website directory.
Custom Tabs share Navigation flows with WebViews: app-side launch/session/callback links,
URL provenance, failed/aborted events, postMessage and raw VIEW/session intents are traced
under the existing `webview.platform` token. Callback URLs are labeled as launch context;
browser redirects and browser-process traffic are outside these app-side observations.
See [the feature details and evidence limits](docs/runtime-code-live.md#crypto-values-decoder-candidates-flow-json-and-logcat).
Keep your existing `runtime-code.local.json` when updating this package; these features
do not require new host settings. Nonexportable keys and unobserved native/Dart crypto
retain explicit availability reasons.
On macOS the optional static index worker applies CPU/output limits and bounded input and
evaluation, plus the host's 60-second timeout; it cannot enforce Linux's hard address-space
limit. This limitation is included in each successful index result.


Default `run`/`watch` performs bounded sequential DEX pre-analysis **before** app launch and
attachment, then selects app methods and decoder candidates automatically. No pack is normally
needed. Request backtracking also shows potential static paths and conditional branch offsets
when the app never navigated. Static connections remain distinct from execution evidence.
The test APK includes campaign/consent/schema gates seven obfuscated classes deep, their allowed
control, string and byte-array decoders, exportable/nonexportable cipher keys, streamed/direct
buffer crypto, WebView errors, Custom Tabs success/failure/abort/prefetch/raw intents, SDK noise
and log levels. The original JS bridge, custom parser, wrappers and dynamic DEX cases remain.

Add `--script /path/heavy-hooks.js` for an isolated companion. Legacy module lookups use a
Process-based adapter; default native hook quota is 128 per companion, configurable using
`--script-hook-limit`. Excess attach hooks are skipped visibly. The bundled
`test-apk/companion_stress.py OUT.js` generates 3,072 distinct private native targets;
use `--namespace process` for Process-only lookups, or its default legacy mode to test
the isolated compatibility adapter. The automatic companion profile
reduces collector work. Both automatic profiles omit broad native socket hooks to avoid
contention with Java/transport locks; managed network boundaries remain active. Java hook cost and target-method conflicts
remain possible; arbitrary large scripts are not guaranteed safe. See the live workflow for limits.
