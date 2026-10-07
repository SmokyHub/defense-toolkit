# Obfuscated runtime flow fixture

Build from the workspace root with `python3 test-fixtures/runtime-flow/build.py`.
Requires SDK 36, Gradle 8.13 and JDK 17+. The release APK is non-debuggable and R8
obfuscates the preserved app test bodies. Custom Tabs SDK API names are preserved
to exercise the supported session/callback hooks; app callback classes stay obfuscated. Public build dependencies are downloaded from
Google/Maven; no client sample is uploaded.

Output: `app/build/outputs/apk/release/app-release.apk`, package `lab.runtimecode.flow`.
Use `build.py --isolated` for `lab.runtimecode.flow.validation` when the normal fixture
is already being watched. Its APK and mapping are under `app/build-validation/`.

Start an automatic capture without a pack, then use the scrollable launcher buttons:

```bash
scripts/runtime-code run --device SERIAL --app lab.runtimecode.flow --debug
```

The APK contains these 21 scenarios:

| Cases | What they exercise |
| --- | --- |
| `gate-campaign-blocked`, `gate-consent-blocked`, `gate-wrong-schema`, `gate-missing-url` | Loopback HTTP JSON containing an example.com URL, an asynchronous callback, seven obfuscated gate classes, and branches that prevent navigation. The missing-URL case tests an absent field. Request backtracking must show a possible static path with gates, without claiming it executed. |
| `gate-allowed` | Positive control for the same response path reaching WebView.loadUrl. |
| `decoder-text-frequency` | Unknown character-XOR decoder called 48 times, versus a rare decoder called once. Tests frequency ranking and distinct CIPHER - PLAINTEXT mappings. |
| `decoder-bytes-late-string` | Byte-array XOR decoder returning UTF-16LE bytes; a separate method later creates the String. Tests original ciphertext retention, hex display and later-conversion mappings. |
| `crypto-array`, `crypto-buffer`, `crypto-stream` | AES/CBC with a known exportable test key and IV; array, direct ByteBuffer, and update/doFinal overloads. Tests exact input/output/key/IV evidence and copying. |
| `crypto-nonexportable` | Android Keystore AES/GCM; plaintext and IV are observable, while unavailable key bytes have an explicit reason. |
| `webview-error` | Locally intercepted HTTP 404 and the WebView error callback. |
| `custom-tab-success`, `custom-tab-failure`, `custom-tab-aborted` | App-local Custom Tabs provider, navigation outcomes, session context and postMessage. |
| `custom-tab-prefetch` | mayLaunchUrl without launch; prefetch must not become proof of navigation. |
| `custom-tab-raw` | ACTION_VIEW with Custom Tabs session extras, without the convenience launch API. |
| `sdk-noise` | Preserved com.appsflyer.fixture origin to test `-pkg:com.appsflyer` in search, mappings and exports. |
| `logcat` | D/I/W/E messages containing SEARCH_ME for colored display, search and copying. |
| Load dynamic DEX | Root-package, one-letter class loaded through InMemoryDexClassLoader; confirms captured input and successful loading. |
| Run encrypted web flow | Raw socket exchange, nested JSON accesses including missing/null/wrong types, hand-written parser, Keystore decryption, four nested wrappers, Activities/Fragment, local WebView resource interception and a JavaScript bridge leading to the decrypted Google URL. |

The new response cases use loopback HTTP and locally intercepted WebView resources.
Custom Tabs are served by the fixture itself. The original encrypted-flow button still
navigates to Google after removing its JavaScript bridge; renderer/network success is
not asserted by the regression driver.

Run the device and browser acceptance matrix with an explicitly selected authorized device:

```bash
~/tools/venv-frida-17.18.0/bin/python scripts/validate_runtime_cases.py \
  --device 33011FDH20018E --config /path/test-config.json \
  --out work/runtime-cases-test --isolated
# Test 3,072 distinct targets with the default quota of 128 active hooks:
~/tools/venv-frida-17.18.0/bin/python scripts/validate_runtime_cases.py \
  --device 33011FDH20018E --config /path/test-config.json \
  --out work/runtime-cases-companion --isolated --companion --namespace-shadow
# Exercise all 3,072 hooks and a second companion with conflicting private names:
~/tools/venv-frida-17.18.0/bin/python scripts/validate_runtime_cases.py \
  --device 33011FDH20018E --config /path/test-config.json \
  --out work/runtime-cases-active --isolated --companion \
  --script-hook-limit 4096 --namespace-shadow
# Repeat with Process-only lookup code and an analyst-owned lexical Module name:
~/tools/venv-frida-17.18.0/bin/python scripts/validate_runtime_cases.py \
  --device 33011FDH20018E --config /path/test-config.json \
  --out work/runtime-cases-process --isolated --companion \
  --companion-namespace process --script-hook-limit 4096 --namespace-shadow
```

The driver requires Playwright/Chromium. It checks automatic scope discovery, unexecuted
static paths, crypto values, decoder frequency and byte conversions, package filtering,
Custom Tab outcomes, dynamic DEX loading, browser mapping/export buttons, clipboard
values, compact flow JSON and colored/searchable logcat. It saves a JSON receipt and
browser screenshot under the specified gitignored work directory. Its final acceptance
also rejects capture/transfer loss and incomplete snapshots.

`companion_stress.py OUT.js` generates a 3,092-line benign script with 3,072 distinct
private native code targets, four Java overloads and its own RPC exports. Every native
target is invoked and its original return checked; callback counters prove the number
of intercepted targets. Periodic sweeps continue while the fixture matrix runs.
`--namespace legacy` tests legacy Module lookups; `--namespace process` uses Process
lookups alongside a private lexical Module name. `--hooks N` changes the target count.
With the default quota, 128 targets are intercepted and the rest are skipped visibly;
the validation command's `--script-hook-limit 4096` permits all 3,072 registrations.
`--namespace-shadow` tests a second script owning Module/config/debug names and a `stop`
RPC that deliberately throws, verifying the collector's RPC still stops cleanly.
Sources load in separate contexts after collector readiness. Java hooks, callback cost
and arbitrary allocations are not automatically bounded. Native hooks target only
private test stubs, so this does not establish safety for 3,072 hot libc hooks.

The capture engine never reads the R8 mapping. Only the test driver uses it to identify
activities and expected decoder methods. The generated `build/live-pack.json` remains
an optional explicit scope oracle for deeper wrapper/lifecycle inspection; it is not
needed for the automatic matrix. Automatic object snapshots have smaller bounds than
that pack, and static links do not prove runtime data provenance.

See [live workflow](../docs/runtime-code-live.md) for capture limits and commands.
