# Live workflow

Use one launcher. The default remains the tested stock Frida 17.18.0 environment;
[per-PC configuration](runtime-code-configuration.md) selects paths, devices, versions and timeouts:

```bash
cd ~/Documents/apk_defense
scripts/runtime-code watch --app PACKAGE.NAME
# Explicit device when more than one authorized device is connected:
scripts/runtime-code watch --device emulator-5554 --app PACKAGE.NAME
```

The launcher prefers `.venvs/runtime/bin/python`, falling back to `~/tools/venv-frida-17.18.0`.
`RUNTIME_CODE_PYTHON` overrides it. By default, the adapter checks the selected Android device
for root access and package ownership and prepares the matching server on device loopback
port 27043. It then indexes installed DEX files sequentially, selects bounded app/decoder
methods automatically, and launches or foregrounds the launcher Activity before attaching. Startup stages are printed immediately;
Frida connection, attachment and script installation have bounded waits with stage-specific errors.
This is explicitly **late attachment**; startup events can be missed. No APK modification,
Gadget or SELinux change is performed. Unknown ART/linker profiles are never selected.
The required arm64 and x86_64 server binaries are under `~/tools/frida-server/`.

The command opens the workspace in the default browser. If browser launch is unavailable,
open the complete `workspace` URL printed by the command, including its token. If port
8765 is occupied, the live command chooses a free local port and prints that URL. The
portal polls every second, preserves filters and selection, and serializes refresh
requests to prevent older responses replacing newer data. Existing saved-Run servers are
left alone. Use `--port NUMBER` to request a port, `--no-open` to serve without launching
a browser, `--no-web` for file-only capture, or
`--seconds 60` for a bounded run. The default runs until Ctrl+C.

Every observation is retained in the managed SQLite store. The printed `live_log` JSONL
file is flushed during collection and drained on normal shutdown. A crash may leave the
JSONL behind SQLite; SQLite remains authoritative. Captured binary content stays in the
integrity-checked artifact store, referenced by snapshot IDs rather than inlined into JSONL.
The app stays running when capture ends. Saved Runs can be reopened with the same launcher:

```bash
scripts/runtime-code --store work/runtime-code runs
scripts/runtime-code --store work/runtime-code serve --run RUN_ID
```

For an analyst-owned companion Frida script, add `--script /absolute/path/script.js` to
`run` (an alias for `watch`) or `capture`; repeat for multiple files. A backend without script support rejects the
option before starting capture. Frida loads each companion in its own context after the
collector reports readiness, supplies an isolated Java bridge, and preserves the original source.
A companion-only adapter restores legacy module lookup/enumeration APIs using `Process` module
instances, following [Frida 17's API migration](https://frida.re/news/2025/05/17/frida-17-0-0-released/).
The collector retains its Process-only resolver policy. Other removed APIs may still need
manual migration. Separate globals do not prevent conflicts at shared hooked methods. Both
initial and later attached app processes receive the configured companions.

Coverage records each script's path/hash and load state. Companion messages are bounded
observations, never accepted as the collector's binary-transfer protocol. Binary messages are
counted but not retained. At most 1024 companion messages per script/process (or the pack's
smaller event budget) are emitted; overflow is reported with final counts. Scripts detach
with the session. Source limits are 8 files, 4 MiB/file and 8 MiB total.

## Automatic discovery and companion budgets

Most runs need no pack:

```bash
scripts/runtime-code run --device SERIAL --app PACKAGE.NAME --debug
scripts/runtime-code run --device SERIAL --app PACKAGE.NAME \
  --exclude-packages com.appsflyer,com.adjust --script /path/heavy-hooks.js
```

Pre-analysis uses Androguard, not JADX, and runs one worker at a time before launch.
`--preanalysis-seconds 120` is the overall default worker budget (1–600 allowed);
each worker gets at most 60 seconds, 45 CPU seconds and 32 MiB output. Linux additionally
limits address space to 2 GiB; macOS does not have that hard memory limit. Timed-out workers
are reaped before launch. Coverage reports a partial index if a worker fails; platform hooks
and available indexed scopes can still run. `--no-static` deliberately disables installed-code
indexing, leaving platform capture and any explicit scopes. `--code` indexes supplied files
before launch instead. An installed base-APK hash pins automatically selected scopes when
available; file identity is not proof of in-memory class identity.

Automatic selection caps scopes at 64 methods (32 with companions), skips common library
prefixes and high-fan-in utility helpers, and traces bounded object fields. Retained app calls
are capped at 100 per method/second and 200 total/second (30 and 60 with companions);
rate-limit losses are explicit. Busy app-call tracing also backs off when the event/owned-byte
queue approaches its bound; `app_calls_backpressured` counts those unobserved calls.
Automatic mode observes app-level byte-to-String conversions
and excludes global String constructors, void/generic utility helpers and framework-derived
UI methods unless they directly contain navigation. The event queue holds at most 512 entries. Trace bytes are reused within a token/process
after verified publication (or while the same transfer is pending), while each call keeps
its value hash and provenance; DEX load captures retain their separate histories. Persistence
acknowledges transfers asynchronously rather than blocking on a per-value RPC. Owned transfers
wait for event-ring capacity and drain in bounded batches; ring pressure alone no longer
discards queued capture bytes. Owned-byte size/count and acknowledgement timeouts still apply.
The companion profile reduces retained bytes, pending transfers and object work. Both automatic
profiles omit broad native socket hooks, which exposed contention with Java/transport locks
on the Pixel. Managed request/socket boundaries remain active; native payloads require an
explicit pack. Coverage lists selected methods, omissions and these limits.

`--script-hook-limit 128` caps active native Interceptor hooks per companion (1–4096 allowed).
Additional `attach` registrations are skipped with budget messages; over-budget replacement
attempts fail explicitly. Java hooks, callback CPU cost and arbitrary script allocations are
**not** automatically bounded. Inspect compatibility/quota messages in All events. A script
with thousands of hooks still needs appropriate scopes; the adapter cannot make arbitrary
instrumentation resource-safe. `capture` uses the default native hook quota without automatic
pre-analysis. An explicitly supplied pack retains its chosen capture scopes.

## Downloads and load status

Select an Inventory row and click **Download raw artifact** for the DEX/ELF/bytes directly,
or **Download artifact + manifest** for a provenance bundle. The bundle downloads as
a ZIP to its configured Downloads directory (or prompts if configured to ask). The ZIP
contains immutable bytes and a provenance manifest; filenames are generated by the collector,
not derived from app-controlled paths. Malformed/partial evidence remains `.bin`. Structurally
inspected DEX inputs use `.dex`; validated original ELF inputs use `.elf`. Memory regions
are not represented as reconstructed original libraries.

`dynamic_load.dynamically_loaded` is true only when a correlated Java loader call returned
in the same process instance. Otherwise it is null with a reason (`not_established` or
`load_failed`). It never means that a captured class or method executed. Capture publication
and runtime load outcome have separate timing and states. Comparisons of unrelated allocation
identities remain rejected; matching bytes alone does not merge their histories.

## Trace coverage

Automatic runs derive their platform baseline from `runtime_code/packs/live.json`,
add indexed app scopes and omit `network.native` plus global String constructors.
Explicitly selecting that pack enables its declared native hooks. Its capabilities are:

| Token capability | Observed boundaries | Limits |
| --- | --- | --- |
| `dex.input.java` | InMemoryDexClassLoader buffers | No ART-owned region tracking in this pack |
| `native.inventory` | Loaded module inventory | No original ELF extraction |
| `webview.platform` | Activity/Fragment lifecycle, WebView loads, installed client overrides, resource responses, annotated Java bridges | Synchronous nesting is observed; asynchronous associations and JS source locations may be unattributed; no complete Custom Tab/renderer trace |
| `network.platform` | URLConnection request context, Socket and returned stream metadata | No blocking Java read/write replacements or socket-metadata stack walks; payload bytes require `network.native`; independent of OkHttp/Retrofit names |
| `network.native` | Connected IPv4/IPv6 libc read/write/send/recv and exported SSL_read/SSL_write | Socket ciphertext remains ciphertext; hidden TLS, QUIC, sendmsg/recvmsg, io_uring and other-process traffic are not covered |
| `parser.json` | org.json parse input, nested field paths, absent/null/type-mismatch accesses | Arbitrary custom schemas are not inferred |
| `crypto.cipher` | Cipher byte-array inputs/outputs (including output arrays), IV and Base64 decoding | Exportable keys only when `selection.capture_keys` is true; ByteBuffer and streamed update/doFinal values are observed; native/hand-written crypto require separately captured decoder boundaries |
| `flow.java` | Default run: bounded automatic pre-launch method selection. Explicit scope: method/constructor entry and return, nested object fields and weak object identities | Stack candidates alone do not install hooks; automatic scopes come from the pre-launch index; no universal taint or individual field-access tracing |
| `parser.custom` (opt-in) | Pack-declared class/method calls and bounded input/output summaries | Accepts root-package, one-letter and obfuscated names; alternate class loaders may need additional handling |

Custom parsers do not have to use a common library. Declare the actual runtime method in a pack:

```json
{"name":"custom-parser","capability":"parser.custom","mode":"observe","trigger":"call",
 "selection":{"methods":[{"class":"a","method":"b"}]},"handlers":[]}
```

This records calls to that method, not a fabricated schema for arbitrary parsing logic.
The fixture build derives its selector from its R8 mapping to demonstrate obfuscated methods.
Production APKs do not require original class names. Discovering every hand-written parser
automatically is not implemented, and changing a name does not prevent the lower-level network
or WebView boundaries from being observed.

Payload fragments are bounded to 64 KiB (and the pack's smaller limit, if any). Larger fragments
record truncation and count skipped bytes. Hash matches between network, parser, crypto and URL
events are labeled **inferred equal bytes**, not complete taint tracking. Native I/O reports an
observed return address separately from a static call site; this pack makes no static-callsite claim.
Hook availability, exclusions and unsupported paths appear under Coverage. All events are
observational and do not create maliciousness Findings.

## Obfuscated Compose fixture

```bash
python3 test-fixtures/runtime-flow/build.py
adb -s 33011FDH20018E install --no-streaming -r test-fixtures/runtime-flow/app/build/outputs/apk/release/app-release.apk
scripts/runtime-code watch --device 33011FDH20018E --app lab.runtimecode.flow \
  --pack test-fixtures/runtime-flow/build/live-pack.json
```

After the process becomes active, tap **Load dynamic DEX** and **Run encrypted web flow**.
The release APK is non-debuggable, R8-obfuscated and uses Compose. It exercises:
Compose launcher → relay Activity → local raw-socket HTTP exchange → org.json and custom
parser → AES decryption of the URL → browser Activity → Fragment hosted from Compose →
WebView resource interception → JS-to-Java bridge → navigation to Google. The bridge is removed
before external navigation. The AES key is a source-built fixture key, not a client secret.

Reproducible device/browser validation (requires the installed Playwright Chromium):

```bash
~/tools/venv-frida-17.18.0/bin/python scripts/validate_runtime_flow.py --device 33011FDH20018E
```

This installs only the fixture, drives its two buttons, checks capture hashes and downloads,
checks missing-field states and required flow events, and saves a receipt under `work/`.
It stops the fixture and its collector after testing. The old runtime-code fixture remains
available for the validated ART/linker and transient-body tests on the exact emulator profile.

The tested device builds, receipts and limits are recorded in
[live validation](../reports/runtime_code/LIVE_VALIDATION.md).

## Crypto evidence and readable flow

The live pack explicitly sets `selection.capture_keys: true` on its `crypto.cipher` token.
This captures exportable key encodings for this selected app/Run; set it to false to disable
key-byte retention. Non-exportable Android Keystore keys are reported unavailable, never
reconstructed or guessed. Older packs without this selection keep keys disabled. Regenerate
the fixture pack after updating the default, or use the updated generated fixture pack.

Click an observation to see expanded JSON, application/bundled-library frames first, and
platform/support frames in a collapsible section. Each app frame supplies its runtime class,
method, signature, origin and available line for searching in JADX. This classification is a
visible namespace/origin heuristic; it does not recover original obfuscated names or claim a
bundled SDK is first-party code. The full stack remains available.

Crypto details show the encrypted input, output, key and IV when retained, with UTF-8 (when
valid), Base64, hex and SHA-256. Binary previews are bounded to 8192 bytes; buttons download
retained bytes. Missing, partial or non-exportable values show their reason. Source links
connect observed nesting, initialization, incremental Cipher calls, parser access and
inferred equal-byte matches. Activity hops with one matching recent intent are explicitly
labeled inferred; nested Android launch wrappers are grouped and ambiguous matches remain
unattributed. Incremental fragments are not represented as a fabricated
whole-message plaintext. Asynchronous hops without evidence remain unattributed.

The table preserves unchanged DOM rows and the selected detail text during polling, so
browser Find and text selection remain stable. Detail evidence is refreshed explicitly via
**Refresh evidence**, including when a transfer finishes after initial selection. Existing
collectors must be restarted to load new hooks; refreshing their portal cannot add evidence
to earlier events.

The same evidence view is available without the portal:

```bash
scripts/runtime-code --store work/runtime-code evidence --run RUN_ID --observation OBSERVATION_ID
```

The live queue is bounded to 512 messages and 16 MiB of pending owned bytes. Loss counters
remain authoritative; larger queues do not guarantee loss-free capture under every load.

## Engine compatibility boundaries

Unity/IL2CPP, Flutter, Hermes and Cocos module indicators, and the Cordova Java boundary,
produce explicit framework coverage notes. Observation does not traverse their internal
heaps or assume engine data is ordinary DEX. Missing optional Java classes are isolated from
other hook groups; an unavailable Java VM is reported while independent native observation
continues. Observer exceptions do not replace app method results or swallow app exceptions.

Regression tests simulate all five engine marker/missing-class cases. These are **not live
engine APK compatibility certifications**. The actual live fixture tests exercise the R8
Compose/Java/WebView app. Native engine crypto, Dart/IL2CPP/JavaScript call stacks and hidden
TLS can remain unattributed. Their appropriate static handlers are still needed for source
inspection; this view does not invent a JADX class for native or script code.

Blocking Java stream replacements were removed after intermittent concurrent-network stalls
on the tested builds. Native byte events may link to a recent same-thread stream observation;
this is explicitly inferred context, not a claim that the stream getter issued the native call.

## Concurrent sessions and isolated validation

Only one collector can own a given device/package at a time, even when stores differ. A
second collector is rejected before launch/attach. Older explicit-device CLI collectors are
also detected; they are never killed automatically. Stop the existing watch command with
Ctrl+C before restarting it with the new hooks. Other packages, saved-run portals and sibling
Frida scripts remain separate; the guard does not claim to detect all external instrumentation.

Use a distinct source-built package to validate without touching the analyst's running fixture:

```bash
python3 test-fixtures/runtime-flow/build.py --isolated
~/tools/venv-frida-17.18.0/bin/python scripts/validate_runtime_flow.py --device 33011FDH20018E --isolated
```

This builds `lab.runtimecode.flow.validation` under `app/build-validation`, preserving the
normal APK and package. The local request/response, parsing, crypto, and WebView navigation
checks work offline. Successfully requesting navigation is not proof that Google rendered;
external rendering requires internet connectivity. See the
[crypto and flow validation](../reports/runtime_code/CRYPTO_FLOW_VALIDATION.md) results.


## Following a value through app methods and objects

Crypto details prominently show the nearest app method and the next distinct outer method,
with signatures and origins for JADX. The raw synchronous stack remains available: adjacent
identical frames are folded only in the summary, because recursion and instrumentation can
both produce repeated frames. Selected method hooks also provide an **Observed enclosing calls**
chain, independent of how the stack is presented.

The **App calls & objects** tab and clickable flow graph distinguish:

- Solid edges: observed synchronous invocation nesting.
- Dashed edges: the same Java object observed at separate selected method boundaries.
- Dotted edges: equal-byte/value inference or other explicitly labeled references.

Object details show before/after boundary, object identity, obfuscated class, field path and
bounded value previews. A path such as `argument[0].a.a.a.a` can expose a URL inside three
wrappers without calling application getters. These are sequential field snapshots, **not**
proof that a particular bytecode instruction accessed a field. Seeing the same object twice
also does not prove a direct transfer between those two methods. Asynchronous intent and
value associations retain their inference labels.

Default stack discovery emits up to 64 **candidate** methods; it never expands hooks while
the app runs. Select a crypto, WebView or candidate observation and choose **Download scope
pack for these app methods**. This selects the nearest two distinct app frames when available.
An observed object also offers **Trace class** to include its declared methods and constructors.
Review the downloaded JSON, stop the collector, restart with that pack, and repeat the flow:

```bash
scripts/runtime-code watch --device emulator-5554 --app PACKAGE.NAME \
  --pack ~/Downloads/runtime-flow-scope.json
```

The equivalent terminal operation prints the next-run pack without changing active hooks:

```bash
scripts/runtime-code --store work/runtime-code scope-pack \
  --run RUN_ID --observation OBSERVATION_ID > runtime-flow-scope.json
# Add --class a to scope an observed class rather than its nearest method frames.
```

A pack can declare an app scope directly, including root-package and one-letter names:

```json
{"name":"app-flow","capability":"flow.java","mode":"observe","trigger":"call",
 "selection":{"classes":["a","bc"],"methods":[{"class":"x","method":"y"}],
 "discover_from_stacks":true,"max_methods":96,"object_depth":4,"object_fields":24,
 "object_nodes":12,"tracked_objects":512,"object_time_ms":20},"handlers":[]}
```

The hook limit counts overloads. Snapshots are bounded per boundary by depth, fields, nodes
and elapsed time. Runtime reflection calls themselves cannot be interrupted mid-call, so
the time limit is checked between operations, not a hard real-time guarantee. Platform
fields and static fields are excluded; no arbitrary getters, `equals`, `hashCode`, or
`toString` are invoked. Identity hashes select a bucket only; JNI `IsSameObject` verifies
identity through weak references. Eviction/collection ends that identity history. Limits,
unreadable fields and partial snapshots stay visible, and reflected fields are not atomic.

The graph uses the most recent 10,000 events from the same process instance, bounded to
128 ancestors and 128 descendants; the visual graph shows up to 128 nodes. Missing links
and reached limits are explicit. Classes in another class loader, inlined code, native or
script execution, events before attachment and unobserved asynchronous handoffs can remain
gaps. Do not read an unconnected event as evidence that nothing happened between steps.

The source-built fixture now decrypts custom `route=URL;` text, maps it without a conventional
JSON mapper, wraps it three times, unwraps it for an Activity handoff, reconstructs distinct
wrappers, and passes those through delivery methods to WebView. Its generated pack explicitly
selects the R8-obfuscated fixture methods. See
[object-flow validation](../reports/runtime_code/OBJECT_FLOW_VALIDATION.md) for evidence and limits.


Socket stream metadata deliberately omits stack walking after a concurrent local-socket
fixture stalled with that operation enabled. Those events report an unattributed caller.
Selected app methods can provide enclosing context, and crypto/WebView boundaries retain
their own caller stacks. The successful narrowed configuration is documented in the
object-flow validation report; it is not a guarantee against every ART/instrumentation stall.


Frida RPC waits are additionally bounded on the host to two seconds with at most four
pending calls. A timeout means target completion is unknown, not that the operation was
canceled in the app. Unanswered shutdown RPCs produce coverage gaps. The latest Pixel
flow retest suffered a native runtime crash; use the documented emulator for the currently
validated object-flow walkthrough and inspect the report before relying on Pixel stability.


## Dormant reflection, StringFog-style XOR and URL search

Code & URL search runs after typing (or Enter), and keeps result cards separate from
flow graphs. Static definitions remain searchable after clearing the displayed event
window. Runtime matches still respect that window and the package filters.
Decoded runtime values show retained input/output/key bytes, the observed decoder caller,
and exact indexed literal locations when equal input/key text or Base64 exists in the DEX.
Literal equality is an inferred association; it does not establish which definition supplied
the runtime value. Missing keys and origins stay explicit. Keys appear only when already
retained by an explicitly scoped capture token.

New static indexes retain the original arguments for supported constant XOR decoding,
including ciphertext and a second argument labeled as a key candidate. Named StringFog
references are candidates; recovered XOR strings do not establish a particular StringFog
version or family. Unknown argument roles and unsupported decoding stay unresolved.
Re-index an existing snapshot to add this metadata to an older index.

`WebView.loadUrl` is listed in Navigation flows. HTTP(S) navigation intents and observed
WebView callbacks also appear in Network, including failed-request callbacks. An intent
does not establish successful transport. A decrypted URL alone is searchable code/value
evidence, not a network request; a disconnected process may never reach its navigation call.

`watch` now copies the selected package's installed base/code APKs and indexes their DEX
members **before app launch and attachment**. Startup progress names the engine and budget.
It uses the existing Androguard analysis environment in `~/tools/venv`, through the registered
`code.references` analysis handler; no extracted application code is executed on the host.
Input DEX bytes are retained as managed immutable snapshots. An imported DEX is **not**
a dynamically loaded artifact. Imported-file identity is not automatically proof of the
class definition used by the running process.

Configuration split filenames are excluded by a visible policy. The copy is limited to
16 code APKs and 128 MiB. Use an explicitly supplied APK/DEX/split ZIP to control the input,
or disable static indexing deliberately:

```bash
scripts/runtime-code watch --device emulator-5554 --app PACKAGE.NAME
scripts/runtime-code watch --device emulator-5554 --app PACKAGE.NAME --code /path/app.apk
scripts/runtime-code watch --device emulator-5554 --app PACKAGE.NAME --no-static
```

After capture, or for additional code supplied by the analyst:

```bash
scripts/runtime-code --store work/runtime-code index-code --run RUN_ID /path/app.apk
scripts/runtime-code --store work/runtime-code search-code --run RUN_ID 'https://example.invalid/path'
```

In the portal choose **Code & URL graph**, enter a URL, string or method in the filter,
and click **Search code & flow**. Empty search lists navigation/reflection/XOR candidates.
The result includes exact DEX method identities, instruction byte offsets, field literals,
source snapshot/hash and recovered constant-decoder sites. Click a result to inspect its
expanded JSON. A static graph shows call references around the hits, including request,
parser and navigation boundaries. A separate observed graph shows retained runtime
relationships. Searching retained plaintext also finds selected decoder/Cipher events
whose observation contains hashes rather than inline plaintext. Existing DEX captures can
be indexed with **Index code references** in Inventory. TUI: `d` indexes the selected DEX;
`/` searches the same core index.

Static discovery covers direct invocation references, WebView/client subclasses and
instantiations, constant `Class.forName`/`getMethod`/constructor reflection, and recovered
constant strings. Reflection targets are attempted names/signatures: target existence,
return type and execution can remain unverified. Root-package and short names remain
eligible. Unknown reflection arguments stay unresolved; there is no claim that every
obfuscated dormant target is detectable.

The bounded evaluator handles modeled byte/char arrays, signed-byte conversion, integer
XOR/arithmetic, deterministic loops, constant helper calls and supported Base64/UTF-8
operations. Tests include repeating multi-byte keys and Base64-plus-XOR. It does not infer
an algorithm from a class name or decode merely because an XOR instruction exists.
Unknown branches/instructions, native calls, unresolved dispatch and unknown mutations
prevent a recovered-value claim. This covers tested StringFog-style patterns, **not every
StringFog version/configuration or arbitrary custom encryption**. The upstream default
[byte-array XOR implementation](https://github.com/MegatronKing/StringFog/blob/master/stringfog-ext/xor/src/main/java/com/github/megatronking/stringfog/xor/StringFogImpl.java)
and [project version history](https://github.com/MegatronKing/StringFog) informed the cases;
custom implementations and transformed layouts require additional analysis.

For runtime inputs/outputs, click **Download decoder scope** on a recovered string or XOR
candidate. Review the pack, restart with `--pack`, and repeat the flow. `crypto.custom`
retains up to eight selected String/byte-array arguments and the returned String/byte array,
with hashes/artifact links and caller context. Parameter roles and algorithm are unverified;
a key passed as a selected byte-array argument is retained but is not guessed to be a key.
For a manually declared method:

```json
{"name":"decoder","capability":"crypto.custom","mode":"observe","trigger":"call",
 "selection":{"methods":[{"class":"a","method":"x"}]},"handlers":[]}
```

Method/class scopes that overlap a custom parser/decoder hook are rejected by token name.
Select each method in one scoped token; simultaneous wrappers are not silently dropped.
The terminal scope export is:

```bash
scripts/runtime-code --store work/runtime-code code-scope --run RUN_ID \
  --snapshot SNAPSHOT_ID --method 'La;->x([B[B)Ljava/lang/String;' --decoder > decoder-pack.json
```

The runtime backend observes reflection frames at hooked targets and custom WebView client
construction at base constructors. It deliberately does **not** replace caller-sensitive
`Method.invoke`/`Constructor.newInstance`: a fixture exposed changed Java access checks when
those APIs were replaced. Optional standard Custom Tabs `launchUrl` hooks and VIEW intents
with the session extra provide observable navigation context; this is not all-browser
rendering coverage. The relevant Android API is documented in
[CustomTabsIntent](https://developer.android.com/reference/androidx/browser/customtabs/CustomTabsIntent).

Static references can describe code that never ran. Connected methods are not proof that
the same URL flowed through all of them. A server-generated or native-constructed URL may
have no literal defining class in DEX. The portal reports the available production/use
sites instead of inventing a definition. Custom parsers not using known APIs still require
selected method/object scopes for runtime data flow.

Limits: 128 MiB input/aggregate archive expansion, 256 selected archive entries, two nested
APK-container levels, standalone DEX at most 64 MiB (also constrained by the Run's pending
and retained byte budgets), 2,000,000 indexed instructions, 200,000 invocation references,
30,000 sites, 300,000 constant-evaluation steps and six helper levels. The isolated worker
has a 2 GiB address-space limit, 45 CPU seconds, 60-second host deadline and 32 MiB output
limit. Results report reached index budgets. URL search uses at most 64 analyses/32 MiB of index results, 100 static
hits, 10,000 recent observations and 256 payload snapshots/8 MiB. Its static neighborhood is
bounded to four hops, 96 nodes and 256 edges. External reference nodes identify a reference
in that snapshot, not a method body proven to reside there.

See [reflection/XOR validation](../reports/runtime_code/REFLECTION_URL_VALIDATION.md).


Custom WebViewClient/WebChromeClient construction, installation and navigation are linked
when the same Java reference is verified through the bounded weak-reference tracker.
Without that tracker, any identity-hash association is explicitly marked inferred. Client
clearing/replacement and WebView versus Chrome client assignments are kept separate.

Fixture packs generated by `test-fixtures/runtime-flow/build.py` include the matching
base APK's `apk_sha256` in the `flow.java` selection. Install that build's APK before
using its pack. Obfuscated names can refer to entirely different classes after rebuilding;
the Frida adapter rejects a fingerprint mismatch before installing scoped hooks.
Constructor hooks validate both declared signatures and bridge ownership, preventing an
inherited `Object` constructor from being installed under an app/interface name.
This hash constraint is optional for analyst-authored packs; unpinned scopes still need
to be checked against the installed build.

## Crypto values, decoder candidates, flow JSON and logcat

The web workspace keeps machine settings in the existing `runtime-code.local.json`.
These features add no configuration fields and do not replace that file. When updating
the portable `website/` folder, retain its local JSON and Python environments.

Crypto details show input, output, key and IV separately, with Text / Hex / Base64
selectors and copy icons. Copy retrieves the retained bytes rather than just the
display preview. Cipher byte-array and ByteBuffer overloads are observed without
moving the application's buffer positions. Final calls can assemble input and output fragments
from a verified, ordered same-Cipher update chain; AAD is kept separate, and the previous
final is a boundary. Missing fragments, capture limits, late initialization, disabled
key capture and nonexportable keystore keys have explicit reasons. A key that Android
will not export cannot be made available by presentation changes.

**Decrypted strings** groups retained transformations by method and observed call
frequency. Selected app-flow methods retain bounded String, byte[] and ByteBuffer
arguments and returns. A later `String(byte[])` conversion can connect a binary return
to readable text by an explicitly labeled equal-byte association, within five hops by
default (eight in the browser). Frequencies count retained observed calls, not every invocation in the app.
String output identifies a decoder candidate; only observed Cipher decrypt mode
establishes that cryptographic role. Default `run`/`watch` uses static boundaries, nearby app methods, XOR candidates and
String/byte-array signatures to select methods automatically. This is bounded discovery:
unselected, dynamically loaded, native and unsupported decoders can still be missed.
Optional next-run scopes remain available for a method outside automatic coverage.

Open **Explore → Decrypted strings** to see a CIPHER → PLAINTEXT table immediately.
The left column ranks methods by retained call count; selecting a method filters its
mapping preview. Each row offers separate copy icons, **Inspect call / flow**, and for
unverified candidates, **Trace decoder next run**. Exports in the toolbar include all
methods matching the search/package/display-window filters. Selecting a method does
not narrow the export. Method previews filter before the 200-pair limit, so a method
whose pairs fall outside the aggregate preview can still be inspected.

Export **CIPHER - PLAINTEXT** downloads one quoted pair per line; binary inputs use
`hex:`. JSONL exports add method, process, observation, classification, hashes and
conversion provenance. Both cover up to the latest 10,000 transformation events,
deduplicate identical method/input/output pairs and record limits in export metadata.
The displayed pair list is a 200-pair preview; export includes the whole retained scan
within its 24 MiB output budget. These exports can be searched in JADX or Code & URL
search; constructed byte arrays may have no matching string literal in the code.

Search accepts `-pkg:com.appsflyer -pkg:com.adjust` to exclude those package trees,
and `pkg:com.client` to include a tree. These operators work in record search, static
code search and transformation exports. Exclusions also prune flow traversal and
downloaded scope packs, so an excluded SDK node is not used as an invisible bridge.
The graph's depth control defaults to eight hops and accepts one through eight.

Flow JSON is compact by default: selected event, caller chain, method nodes, edges
and their evidence basis, plus relevant crypto status and parser context. A copy icon
copies the selected graph JSON. **Full JSON** retains access to the complete evidence.
Possible request/parser context lists shared app stack methods or classes within the
selected depth and observed JSON access paths, types and missing/default/exception
states. These are investigation leads rather than proof that a particular network
response caused a navigation. No live server response is changed.

Open **Explore → Request backtracking**, select a network request or response, and use
**Backtrack hops** (default 8, range 1–8). The summary appears above the event graph and
shows the bounded app caller chain, related JSON fields and WebView/Custom Tab candidates
even when no navigation was linked. **Network → Backtrack selected request** opens the
same view. Recorded graph links and shared-method/class candidates have separate statuses;
Custom Tabs callback URL context keeps its existing provenance label. Prefetch/warmup
alone does not establish navigation. Lookup is scoped to the selected process attachment
and the latest 10,000 events, with package exclusions applied. An absent link is not
proof that no navigation is possible; use the caller's **Search … in code** button for
unexecuted branches. The same view now searches up to eight static call hops, displaying
possible navigation paths and conditional branch offsets even when no WebView was reached.
Possible Runnable/Kotlin Function callbacks have a separate edge label. Static paths are
code references, not execution or response-provenance proof. Ubiquitous obfuscated helper
hubs are omitted to avoid connecting unrelated features through common utility methods.

Open **Logcat** in the header or **Session → ADB logcat** in the sidebar. The header
shortcut stays visible when the sidebar needs scrolling in a shorter window.
**ADB logcat** captures a separate bounded log stream for live Frida Runs, on the
explicitly selected device. It has colored levels, text search, minimum-level filtering,
app-PID filtering, scrolling control and copy. Uncheck app-only to examine system logs.
The saved Run can reopen its logs after capture ends. The stream starts after attach,
does not clear Android's log buffers, retains a rolling file of up to approximately
8 MiB and pages up to 2,000 lines; missing older lines are indicated. Older Runs without
logcat show an unavailable explanation. Frida and logcat are independent consumers.

### Custom Tabs share the navigation workbench

The existing `webview.platform` token covers WebViews and Custom Tabs. AndroidX and
legacy support-library Custom Tabs have app-side service binding, session creation,
Builder association, `launchUrl`, navigation callbacks and postMessage observations.
Raw `ACTION_VIEW` intents with the Custom Tabs session extra are detected at Activity
and Context launch boundaries, including wrappers with obfuscated library names.
Ordinary VIEW intents without this extra are not classified as Custom Tabs.

Custom Tabs appear beside WebViews in Navigation flows and Code & URL search, with
the same decoder/URL source links, app stacks, five-level graph, shared parser/schema
context, package exclusions, compact JSON, copy icons and next-run method scopes.
The URL card has its own copy icon. Session, callback and Builder relationships remain
distinct from inferred equal-byte links.

Navigation failure and aborted events are displayed separately. Prefetch and warmup
acceptance do not establish a launch or a successful request. An app-side launch
exception is a launch failure, not a fabricated browser HTTP status. Event definitions
follow the [AndroidX callback API](https://developer.android.com/reference/androidx/browser/customtabs/CustomTabsCallback).

Custom Tabs run browser rendering/network code outside the captured app process.
The app callback protocol does not supply the final navigated URL: an associated URL
is labeled as the session's last launch context, not redirect/transport evidence.
Callbacks shared across multiple observed sessions retain an ambiguity explanation.
Missing optional classes, late attachment, identity-cache evictions and obfuscated
library APIs remain coverage limits; raw intents and selected app-method scopes provide
additional app-side leads.

The source-built `test-fixtures/custom-tabs/` fixture uses the real AndroidX API with a
controlled app-local provider to test these boundaries without Internet permission.
It separately exercises normal, failed, raw Intent and missing-campaign-schema paths.
