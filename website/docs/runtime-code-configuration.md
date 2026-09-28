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
`paths.server_dir`. The adapter chooses the **Android device ABI**, not the Mac CPU ABI.
It checks the installed host version, the server's reported version and the running server's
binary hash. `watch` uses the configured port; `capture --config ...` uses it too and expects
the matching rooted server to be running already.

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
