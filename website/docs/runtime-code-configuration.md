# Machine-local Runtime Code configuration

Host/device setup lives in a JSON file, separately from the pack that selects observations.
Create one on each PC, from the repository root:

```bash
scripts/runtime-code config init
scripts/runtime-code config show
```

In the portable `website/` directory use `./runtime-code` instead. `config init` creates
`runtime-code.local.json` and refuses to overwrite a file. This filename is gitignored.
Edit it in any text editor. No APK changes, emulator creation or downloads are performed.
A reference copy ships at `runtime_code/config.example.json`.

The default auto-loaded file is `runtime-code.local.json` beside the `runtime_code/`
package (repository root or portable website root). Select another file with
`--config /path/mac.json` before or after the command, or `RUNTIME_CODE_CONFIG`.
`config show` prints the selected file and effective settings without connecting to a device.
Malformed settings, unknown keys and missing explicitly selected files fail visibly.

## Example: Android Studio emulator on a Mac

Select your running Android emulator using ADB; no AVD name, model or lab image is required:

```bash
adb devices -l
adb -s emulator-5554 shell getprop ro.product.model
adb -s emulator-5554 shell getprop ro.product.cpu.abi
```

Replace the generated file with settings for that PC, or edit its existing fields:

```json
{
  "paths": {
    "adb": "~/Library/Android/sdk/platform-tools/adb",
    "server_dir": "~/tools/frida-server",
    "analysis_python": ".venvs/analysis/bin/python",
    "store": "work/runtime-code"
  },
  "device": {
    "serial": "emulator-5554"
  },
  "frida": {
    "version": "17.5.2",
    "server_port": 27043,
    "allow_untested_version": false
  },
  "timeouts": {
    "adb": 30,
    "launch": 90,
    "process": 30,
    "connect": 30,
    "attach": 30,
    "script_load": 60,
    "server_start": 15,
    "pull": 90
  }
}
```

Run with the configured device:

```bash
./runtime-code watch --app YOUR.PACKAGE --no-static
```

Remove `--no-static` to restore automatic installed-APK indexing. This option isolates live
instrumentation from host static analysis; it does not reduce the selected runtime hooks.
Use `--device` to override the configured serial. With neither set, `watch` requires exactly
one online Android device. All connected devices are listed, including TCP-connected emulators.
It does not start an emulator: start your chosen AVD in Android Studio first.

## Settings and precedence

- `paths.adb`: executable name on PATH, or a full/relative path (spaces are supported).
- `paths.server_dir`: directory holding uncompressed Android Frida server executables.
  A matching server already installed on Android can also be used without a host copy.
- `paths.analysis_python`: optional interpreter with Androguard for static indexing. Empty
  uses the existing `.venvs/analysis/bin/python`, then the lab's `~/tools/venv/bin/python`.
- `paths.store`: managed SQLite/artifact directory; `--store` overrides it.
- `device.serial`: default selected device; `--device` overrides it.
- Legacy `device.avds` and `device.serial_models` fields are ignored when reading old files.
  Device discovery and startup do not use image, model, AVD-name or serial allowlists.
- `frida.version`: exact host/server release. Defaults retain the tested Pixel's 17.18.0.
- `frida.server_port`: device loopback port. The host forwarding port is allocated separately.
  Existing conflicting listeners are left untouched.
- `frida.allow_untested_version`: false by default. The supported host releases are 17.5.2,
  17.18.0 and 17.19.0; opt-in permits other 17.x releases, recorded as untested in Coverage. This is
  not device/build validation and does not unlock unknown ART/linker profiles.
- `timeouts`: seconds, each finite and between 1 and 600. These control host waits, not
  per-hook capture budgets. Capture budgets still belong to packs.

Omitted fields retain defaults. Relative paths are relative to the selected JSON file;
`~` expands to the current user's home. Environment overrides remain available:
`RUNTIME_CODE_ADB`, `RUNTIME_CODE_SERVER_DIR`, `RUNTIME_CODE_ANALYSIS_PYTHON`, and
`RUNTIME_CODE_FRIDA_SERVER_PORT`. CLI device/store options take priority over file defaults.
The runtime interpreter is selected before loading this file: launchers prefer
`.venvs/runtime/bin/python`; `RUNTIME_CODE_PYTHON` overrides it. Use an absolute interpreter
path when launching from another directory.

## Frida versions and startup diagnostics

For **Frida 17.5.2** on an M4 Mac, install the compatible host/tools pair in the portable
website directory (instead of `requirements-live-optional.txt`, which pins 17.18.0):

```bash
python3.12 -m venv .venvs/runtime
.venvs/runtime/bin/python -m pip install -r requirements-live-frida-17.5.2.txt
```

Use `frida.version: "17.5.2"` as in the JSON example above and place the uncompressed
`frida-server-17.5.2-android-arm64` in `paths.server_dir` for an ARM64 Android emulator.
No `allow_untested_version` opt-in is needed. The older tools pin is intentional:
[frida-tools 14.5.0](https://pypi.org/pypi/frida-tools/14.5.0/json) accepts Frida 17.5.2;
[14.10.4](https://pypi.org/pypi/frida-tools/14.10.4/json) requires Frida 17.10.0 or newer.
Host API and Java-bridge checks run with the real 17.5.2 Python package; Android startup
and macOS portability paths use regression simulations, not a live M4 validation.

Changing `frida.version` does not install or download anything. Install that exact Frida
Python package in the runtime interpreter with compatible `frida-tools`, and provide
`frida-server-VERSION-android-arm64` or `frida-server-VERSION-android-x86_64` in
`paths.server_dir`. A plain `frida-server` filename in that directory is also accepted;
the version/ABI-specific host filename takes precedence when both exist.
The adapter chooses the **Android device ABI**, not the Mac CPU ABI.
It checks the installed host version, the server's reported version and the running server's
binary hash. `watch` uses the configured port; `capture --config ...` uses it too and expects
the matching rooted server to be running already.

When neither host filename exists, `watch` looks for a matching server already installed
as `/data/local/tmp/frida-server`, the version/ABI-specific name in `/data/local/tmp`,
the managed `/data/local/tmp/runtime-code-fsd-VERSION`, or `frida-server` on Android's
`PATH`. A generic device filename needs no configuration change. Its `--version` must
match `frida.version` exactly, and the listener's `/proc/PID/exe` hash must match the
selected binary before the app launches. An installed binary's matching version does
not establish an upstream/stock build; the selected binary hash and selection basis
are recorded in Coverage. The configured port is respected, and conflicting listeners
are left running. Renaming a server does not change its compatibility.

`watch` foregrounds the Activity without `am start -W`: it waits for an app PID, not the first
screen draw. Splash/network delays therefore do not consume the old 15-second draw wait.
ADB, attach and script-load failures identify their stage and limit. Server startup waits
for a listener instead of assuming that 300 ms is enough. Startup remains late attachment,
so early events may be missed. Configuration and timeout information is retained in Coverage.

A hot host or a large Flutter APK does not establish server overload. First compare the app
running without instrumentation, then use `--no-static` and omit companion scripts to isolate
the load. Record the complete error, Frida host version, Android ABI and AVD identity.
Increasing a timeout cannot fix an incompatible Frida/Android build or a crashed app.
Java/platform hooks do not provide universal visibility into Flutter's Dart AOT internals.

Host configuration/startup paths are regression-tested using simulated device responses.
A macOS Android 14 ARM emulator live run has not been validated in this lab.

## Diagnose a freeze on the same PC

Add `--debug` to `watch` or `capture`. For the portable website fixture:

```bash
./runtime-code watch --device SERIAL --app lab.runtimecode.flow \
  --pack test-apk/live-pack.json --no-static --debug
```

Debug mode opens a local HTML diagnostic page before device preparation and attachment.
`--no-open` suppresses automatic opening; its `file:///.../report.html` URL is always printed.
Each attempt writes a unique directory under `<store>/diagnostics/debug-*/`, containing
`report.html`, `status.json`, `checkpoints.jsonl`, and, after a stall, `host-threads.txt`.
The page refreshes every two seconds and gives a short status code and an explanation;
it can be read entirely on the affected PC without transferring logs. Reports retain
stall incidents after a clean shutdown. If the collector is forcibly killed, the last
report remains on disk; check its update timestamp because it cannot keep monitoring.

The host watchdog is a separate Python thread and uses neither Frida RPC nor SQLite.
After ten seconds without the expected progress, it distinguishes:

- `HOST_CALL_STALLED`: an ADB, attach, script load or another named host operation has not returned.
- `TARGET_STARTUP_STALLED`: the agent started but never reported readiness. Checkpoints bracket
  Java bridge evaluation, Java availability, entry into `Java.perform`, individual platform hook
  installation, DEX hooks and native observer installation.
- `AGENT_HEARTBEAT_MISSING`: the agent's two-second JavaScript heartbeat stopped; an agent-thread
  block, transport interruption or process failure remains possible.
- `ANDROID_MAIN_THREAD_STALLED`: JavaScript heartbeats continue, but the scheduled main-thread
  callback has not returned. Only one callback can be outstanding at a time.
- `AGENT_ERROR`: an instrumentation error was delivered; its stack is retained locally.
- `TARGET_DISCONNECTED`: no attached target remains. The warning and target table show each
  recorded PID and detach reason. `process-terminated` records process exit;
  `connection-terminated` records transport loss. Neither reason alone explains its cause.

When Frida supplies crash details on detachment, the debug page keeps the summary and an
expandable report, and the saved Run keeps the same evidence in `lifecycle.detached`.
Reports are capped at 65,536 characters with truncation marked. If Frida supplies no crash
details, the page says so; inspect the saved Logcat with **App only** disabled because Android
crash/ANR messages may come from system processes. Search for the affected PID, `AndroidRuntime`,
`Fatal signal`, or `ANR`. `collector.source.loaded` means the collector's top-level source finished
loading; it does not identify the WebView call or prove a deadlock at that line. A restart can
restore collection but leaves a gap in evidence from the previous attachment.

Heartbeats include bounded names of active Java flow/DEX callbacks, with no argument values.
Host stack dumps contain Python stack locations, not Android native thread stacks. Last-seen
checkpoints narrow the failing boundary; they do not prove a deadlock or its root cause.
The watchdog cannot recover a blocked target or continue if the host interpreter itself stops
executing. Debug mode adds timing overhead and is off by default. The main-thread probe runs
only after Java hooks are ready; inventory-only packs do not initialize a Java bridge.

Automated validation covers a blocked host call, missing agent heartbeat, an unanswered main-thread
probe, retained reports, bounded diagnostic callbacks, bootstrap ordering and JavaScript syntax.
This does not establish live Android 16 ARM/macOS compatibility or resolve an unobserved freeze.


`run` aliases `watch`. Neither needs a pack by default: installed DEX files are indexed
sequentially before launch, then bounded method/decoder scopes are selected automatically.
Startup progress reports the indexing stage. `--preanalysis-seconds` controls the total worker
budget; `--no-static` opts out. `--script /path/hooks.js` selects a reduced collector profile
when no explicit pack is supplied. `--script-hook-limit` controls its companion's native hook
quota; Java hook cost remains the script author's responsibility. Existing local settings
need no edits for these features. See [automatic discovery](runtime-code-live.md#automatic-discovery-and-companion-budgets).
