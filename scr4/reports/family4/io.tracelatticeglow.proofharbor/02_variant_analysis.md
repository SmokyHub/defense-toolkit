# 5555xLat / Proofharbor — Family4 variant and analyzer repair

`io.tracelatticeglow.proofharbor` (5555xLat, version 1.2.0/code 10) uses the same
response-driven native DEX-loading topology as the first Family4 sample. The old
analyzer decoded 114 strings and its endpoint but refused a proof with
`ambiguous_or_unmodeled_loader_topology`. This was a coverage gap in extraction,
not a missing ARM64 split or evidence that the loader was absent.

The complete 86-APK set is saved in `samples/family4/io.tracelatticeglow.proofharbor/`.
The app-specific ARM64 library is `libl5555xlat.so` (177,136 bytes), SHA-256
`0524a385c7e9997ac0b346b3dcde8463d8cd0e1f311e625a775a875ade03b223`.
`libsigner.so` and `libandroidx.graphics.path.so` are also present. There is no
Flutter/Blutter prerequisite for this analyzer. The hash records evidence identity;
it is not used to select a response contract.

## Why the previous extractor failed

1. The parser and JSON preflight convert an integer to decimal text with a helper,
   instead of embedding a two-character outer key through `mov`/`strh`. The helper
   at original ELF VA `0x1389c` receives 53 at both call sites. The parser call is
   `0x12038`, and preflight call `0xc920` supplies its output buffer to JNI
   `NewStringUTF` at `0xc93c`. The old inline-string-only recognizer missed both.
2. The parser skips the DEX array while iterating 16-byte field records. It compares
   byte offset 16 for field index 1, instead of comparing the field index directly.
   The repaired recognizer ties this to the record stride, loop bound and stores.
3. The DEX validator shares its return block and inverts two conditional branches.
   Its checks are equivalent, but the old linear instruction template differed.
   The repaired comparator follows the acyclic instruction graph, folds direct
   jumps/equivalent zero returns and normalizes inverse branch predicates. It
   retains the actual operations, guard constants and branch destinations.

The complete decimal-conversion helper must match the reviewed implementation;
only its trailing stack-canary failure call address is excluded. The input integer
and destination buffer are recovered from call arguments. Parser and preflight
selectors must agree. Nothing special-cases the package, URL, library hash or
response keys. Different conversion algorithms or substantially different code
can still require review.

## Recovered flow and response contract

`MainActivity.onCreate` calls `RemoteConfigStore.load`, which invokes
`Androidappapi.proofharbor(Activity, new JSONObject())`. Its native bridge is
`_n70bd35a931184fdcba38`, backed by `libl5555xlat.so`. The response is consumed by
native parser `0x11f08`, loader `0x10ab8` and validator `0x125c0` (original ELF VAs;
Ghidra's imported addresses have an additional image base).

The observed request is **POST
`https://proofharbor.android-app-api.com/public/v5/kr`**. The generated response
uses outer object **`53`**, and DEX integer-array field **`329`**. It supplies the
remaining JNI/class/method fields below, then creates an in-memory class loader,
loads and constructs the entry class and invokes its instance `run(Activity)`.

| Field role | Recovered key |
|---|---|
| `loader_class` | `27` |
| `loader_constructor_signature` | `80` |
| `activity_loader_method` | `54` |
| `activity_loader_signature` | `616` |
| `load_class_method` | `249` |
| `load_class_signature` | `302` |
| `entry_class` | `573` |
| `entry_constructor_signature` | `370` |
| `entry_method` | `269` |
| `entry_signature` | `540` |
| `class_class` | `43` |
| `class_lookup_method` | `597` |
| `class_lookup_signature` | `602` |
| `constructor_name` | `353` |

The validated guard graph retains the 112–33,554,432-byte DEX bounds, version,
header/endian, declared file/container size and table bounds checks. There is no
separate response field for expected DEX size. Android's later validation is a
separate step; the native routine does not recompute the DEX checksums.

## Runtime proof on the original Pixel app

HTTP Toolkit's ordinary exact-URL POST request breakpoint supplied local HTTP 200
JSON replies. Requests were answered directly rather than forwarded to the live
backend. No Frida attachment, application patch or re-signing was used. The
existing lab trust configuration was in place; production payload behavior is
unverified.

| Trial | PID | Result |
|---|---:|---|
| Disabled outer object | 15355 | No fixture markers; original UI |
| Generator's valid benign DEX | 15430 | `ENTRY_CALLED`, `UI_INSTALLED`, `BUTTON_EXECUTED` |
| Declared file size 5124 with actual 5120 bytes, valid recomputed checksums | 15598 | No fixture markers; original UI |

For all three trials, the app-created SharedPreferences entry `53` equals the
supplied JSON bytes exactly. Rejected responses are cached too, so persistence
alone is not an execution signal. The negative trial does not dynamically identify
the first rejecting function; static control flow places native validation before
class-loader creation.

The positive response is 15,135 bytes, SHA-256
`87a4d12906b8b64eaa504fa2df01b30f883c50d61091bd55df06ee8c18e5b12a`.
Its embedded benign DEX is 5,120 bytes, SHA-256
`8de5fb444a932ad2eb5af51fb1082f4cf6d293441808f37ab84e546e936017d0`.
These are proof-fixture identifiers, not malware indicators. The screenshot
shows the host package and **DEX BUTTON HANDLER EXECUTED**. The fixture page is
local; it does not demonstrate unseen gambling or other production content.

Raw evidence remains under `captures/family4/io.tracelatticeglow.proofharbor/`:
`positive/button-screen.png`, `positive/button-ui.xml`, process-correlated
`positive/button-logcat.txt`, all three `preferences-after.xml` files and
`verification.json`. Exchange records are ordinary GUI/DOM observations, not HAR
or packet captures. No precise host/device clock synchronization is asserted.

The response preference file did not exist before testing. The generated cache
was removed afterward, the target stopped and the test rule deleted and saved.
Unrelated app data was preserved. HTTP Toolkit remains connected for lab use.

## Regression and distribution checks

All **38 tests passed**: 26 analyzer tests, five Family4 portable tests and seven
Family3 portable regressions. Command:

```bash
APK_DEFENSE_SAMPLE_TESTS=1 PYTHONPATH=scripts:scripts/tests \
  scripts/venv_python -m unittest \
  test_family4_native test_family4_portable test_family3_portable -q
```

Log: `work/family4/proofharbor-tests-final.log`. New tests include this original
sample, a changed three-digit selector, mismatched parser/preflight keys, a broken
formatter, a changed record skip, modified guard limits and reversed branch
polarity. Unsafe or unmodeled mutations remain `needs_review`. Isolated ZIP tests
cover both original apps and verify the embedded benign DEX.

The existing YARA rule also matches this original custom library; both bundled
ARM64 dependency libraries remain negative in legacy YARA. This extends the
previous limited corpus, not a population-wide false-positive claim. Network
indicators were extended for the newly observed POST endpoint. Source, component
ZIP and full portable bundle contain the repaired reader.
