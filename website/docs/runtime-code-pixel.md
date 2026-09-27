# Pixel 7 Java-input capture

Validated on 2026-09-26: Pixel 7 `33011FDH20018E`, Android 15/API 35, arm64,
stock Frida **17.18.0** host/server, frida-tools **14.10.4**, root adbd, SELinux Enforcing.
The default 17.19.0 lab environment is preserved. On this device, 17.19.0 failed both
spawn (`setArgV0` slot) and bare attach (`agent connection closed unexpectedly`).
An isolated 17.18.0 attach and the full Java-input fixture trial succeeded.
This does not establish that every device has a 17.19.0 regression.

## Run the fixture

The dedicated interpreter is `~/tools/venv-frida-17.18.0/bin/python`.
The matching stock server is running on device loopback port 27043. To restart it after
a device reboot, first verify the Pixel identity and root access, then run:

```bash
adb -s 33011FDH20018E shell \
  'nohup /data/local/tmp/rc-test-fsd-17.18.0 -D -l 127.0.0.1:27043 >/data/local/tmp/rc-test-fsd-17.18.0.log 2>&1 </dev/null &'
```

From the workspace root:

```bash
RUNTIME_CODE_FRIDA_SERVER_PORT=27043 \
  ~/tools/venv-frida-17.18.0/bin/python scripts/validate_runtime_code.py \
  --device 33011FDH20018E \
  --pack runtime_code/packs/java-inputs.json \
  --attach --seconds 30
```

The adapter creates its own temporary host forwarding port through the verified device
serial and removes it when the Run stops, including failed starts. The setting is explicit;
it does not silently switch versions or turn spawn into attach. The same environment
setting works with `python -m runtime_code capture`. Selected device port is recorded in Coverage.

The harness installs the unchanged, non-debuggable
`test-fixtures/runtime-code/build/fixture.apk` (`lab.runtimecode.fixture`), serves local
fixture payloads, compares captures to known hashes, and removes its reverse route afterward.
It waits for Activity launch and bounded PID discovery before attempting attachment.
Failed trials retain `failure.json` with the failed stage and original exception.

## Evidence and limits

Initial successful receipt:
`work/runtime-code-validation-y0327lxk/receipt.json`, Run
`754aa230fcd24083a4e99f7e954b4a2b`: 7 DEX captures, all known hashes matched;
6 memory-loader cases and 5 file-loader cases executed successfully; no capture failures
or reported loss. Native fixture checks also passed, but this pack only inventories native
modules. File-loader execution is not evidence of file-input extraction with this pack.

This is **late-attach Java-buffer capture**. Startup may be missed. Pixel ART/linker
extraction profiles remain unsupported, and Florida has not been validated.
The isolated server came from the official Frida 17.18.0 release; its source URL and hashes
are recorded in `work/pixel-frida-17180-yjnnv49s/source.json`.
