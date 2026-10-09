# Family4 implementation and behavior validation

The analyzer recovered a complete response contract from the original ARM64
library, and its generated response executed the bundled benign DEX inside the
original app on the authorized Pixel 7. The added button also executed. The app
was not patched, re-signed or attached to Frida. HTTP Toolkit supplied the response
locally at an exact POST/URL breakpoint; no production DEX was retrieved.

## Offline implementation checks

Run from the repository root, with the saved authorized samples available:

```bash
APK_DEFENSE_SAMPLE_TESTS=1 PYTHONPATH=scripts:scripts/tests \
  scripts/venv_python -m unittest \
  test_family4_native test_family4_portable test_family3_portable -q
```

On 2026-10-09, all **29 tests passed** (18 Family4 analyzer tests, four Family4
portable tests and seven Family3 portable regression tests). The local log is
`work/family4/tests-final.log`. Expected errors in that log exercise refusal paths.

Coverage includes original split input; nested archives and duplicate native
libraries; unsupported ABI and missing input; existing-output preservation;
incomplete or ambiguous contracts; pinned fixture integrity; and isolated ZIP
execution without workspace imports. An unsupported proof request writes available
analysis diagnostics but returns status 2 without a guessed response.

Synthetic ELF mutations test changed selector values, consistent and inconsistent
outer-selector changes, encrypted endpoint changes, rebased ELF addresses, and
different JNI argument bindings. Missing JNI evidence, duplicate selectors and
changed DEX guard instructions are rejected. These are bounded variation tests,
not additional observed family members or proof of support for every compiler.

The response contains the unchanged **5,120-byte** source-built benign fixture,
SHA-256 `8de5fb444a932ad2eb5af51fb1082f4cf6d293441808f37ab84e546e936017d0`.
The standalone build includes this fixture, its Java source, Python dependencies,
reports, detections and a SHA-256 file manifest. It includes no client APKs or
captures. Linux execution was tested; macOS execution was not independently tested.

## Runtime controls and positive proof

See [the network report](03_network_analysis.md) for all five exchanges, response
hashes, cache comparisons and evidence limitations. Each trial used a fresh target
process after preserving and clearing only its response-cache entry.

| Response | Result in the recorded observation window |
|---|---|
| Disabled outer object | Original UI; no fixture execution markers |
| 64-byte truncated DEX | Original UI; no fixture execution markers |
| Wrong declared DEX file size, stale checksums | Original UI; no fixture execution markers |
| Wrong declared DEX file size, recomputed valid checksums | Original UI; no fixture execution markers |
| Unchanged valid fixture from the generator | Entry, UI installation and interactive button execution |

All supplied responses were cached byte-for-byte, including rejected inputs.
Cache persistence alone therefore does not prove execution. Native control-flow
analysis establishes the size gate before class-loader creation; negative runtime
results alone do not identify the first rejecting function or isolate every guard.

Positive evidence is under
`captures/family4/dev.tracebasinmoss.routepearl/positive/`:

- `screen.png`: added proof screen identifying the host application.
- `button-screen.png` and `button-ui.xml`: button handler executed visibly.
- `button-logcat.txt`: `ENTRY_CALLED`, `UI_INSTALLED`, `BUTTON_EXECUTED`, PID 14078.
- `preferences-after.xml`: app-created cache equals the supplied generated JSON.

The added WebView and button belong to the benign test DEX. They demonstrate code
loading and changed behavior, not the content of an unseen production payload.

## Detection and cleanup

The YARA rule matched the original native library in both tested engines and did
not match 24 distinct local negative ELFs; see
[detection validation](04_detection_report.md). The structural Python analyzer
recovers keys and JNI bindings from the input instead of selecting a stored
response by sample hash. Unknown layouts remain `needs_review`.

After testing, the app was stopped, its original preference file was restored
byte-for-byte and the exact test breakpoint was deleted and saved. Restoration
SHA-256 is `aa7e30d2e3daaa7922162005563ccddb0f55e68a03798198454a2175e04218ef`.
HTTP Toolkit remains running. The pre-existing Frida server and SELinux Enforcing
state were unchanged. Cleanup evidence is
`captures/family4/dev.tracebasinmoss.routepearl/cleanup.json`.
