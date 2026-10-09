# Family4 — native JSON-to-DEX response analyzer

Offline Python 3.10+ analysis for the recognized ARM64 native loader. No Blutter,
Ghidra installation, compilation, Frida, phone or network is needed to generate a
response. Keep the supplied Python modules and `fixtures/` together.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python analyze_family4_native.py /path/application.zip \
  --out analysis.json --proof-response ready-response.json
```

Inputs can be an original APK, split directory, split ZIP/APKS/XAPK/APKM, or extracted
ARM64 `.so`. Include the base and ARM64 split when the app is split. No merging or
re-signing is needed. An APK with only Java and no ARM64 native library returns review
status. The native analysis does not depend on the library's filename.

- `--out` writes the analysis, reconstructed strings, response-field roles, DEX
  guard evidence and limitations. With `--proof-response`, it also embeds the proof JSON.
- `--proof-response` writes the ready-to-use HTTP response containing the actual
  hash-pinned 5,120-byte benign DEX. There is no placeholder to replace manually.
- Both outputs must be new files. Ambiguous or unsupported inputs retain analysis
  diagnostics but do not generate a guessed proof response (exit status 2 if requested).

For the tested 5555xBasin app, configure an **exact POST URL** breakpoint in HTTP Toolkit
using the endpoint recovered in your report. At the app's request, choose **Respond
directly**, paste `ready-response.json`, and return HTTP 200 with `Content-Type:
application/json`. Set Content-Length to the UTF-8 byte length if entering it manually.
This responds locally without forwarding the request upstream. Do not add a broadly
matching rule. Force-stop the app between trials: startup requests run once per process.
A cached response can execute before a new request; preserve the original cache before
clearing only the response entry for a controlled trial. Restore your cache and remove
your test rule when finished.

The proof screen says **APK Defense: DEX executed**. Tap **Test added functionality**;
the text becomes **DEX button handler executed**. Logcat tag `APKDefenseFixture` emits
`ENTRY_CALLED`, `UI_INSTALLED` and `BUTTON_EXECUTED`. Generation alone is not execution
proof. The benign entry loads local HTML and makes no network request.

## What is recovered

The Python reader decodes distributed encrypted string descriptors from the ELF,
finds the native selector table, and associates fields with JNI name/signature arguments.
It checks the recognized validator's instruction/branch structure. It does not select
an app by SHA-256, package, library name, endpoint or stored response pack.

The tested native validator requires 112–33,554,432 decoded bytes, supported DEX magic,
header size, endianness, file/container size consistency and section/map bounds. A 64-byte
truncation and an unchanged-length DEX with a wrong declared file size were rejected at
runtime; the valid bundled DEX executed. There is **no separate JSON expected-size field**.

Recognition is deliberately conservative. Tests cover changed numeric selectors, a changed
outer selector, encrypted endpoint changes, relocated ELF addresses and changed JNI call
arguments. Unknown compiler layouts, outer-selector forms, decoding schemes or validator
changes can require review. One real app has been validated; synthetic variants are not
additional observed family members. This flags a remote-code loading capability, not
malicious intent or common ownership by itself.

The original app was validated on the lab Pixel 7 using ordinary HTTP Toolkit request
breakpoints, with no application hooks or app patches. Offline tests ran on Linux; macOS
execution has not been independently tested. Dependencies have no special Dart VM version
requirement. Reports and conservative detection rules are included under `reports/` and
`detections/`. `python3 verify.py` checks this component's shipped files.
