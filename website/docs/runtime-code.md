# Runtime Code workbench

For the single live launcher, automatic portal updates, downloads and flow tracing, start
with [the live workflow](runtime-code-live.md).

This is a new, integrated analyst application in `runtime_code/`, built alongside the lab scripts.
It is an initial vertical slice of the requested platform, **not completion of the full specification**.
The terminal, keyboard TUI and local browser workspace share the same services and SQLite store.
Captured code is evidence of an observed state, not evidence of maliciousness or complete recovery.

## Run it

For the verified Pixel 7 Java-input trial using an isolated stock Frida 17.18.0 server,
see [Pixel capture instructions](runtime-code-pixel.md). This is separate from Florida validation.

The adapter also accepts a Frida **17.18.0** host for a matching Florida 17.18.0 server.
Host API/bridge compatibility is separate from live device validation: Florida capture fixtures
have **not** been validated. Exact ART/linker build checks still apply, and Coverage records this
limitation without inferring server flavor from the host version. The upstream
[Florida 17.18.0 tag](https://github.com/Ylarod/Florida/releases/tag/17.18.0) has no downloadable
server assets as checked on 2026-09-26; a trusted matching server build is required.

Use an isolated interpreter with `frida==17.18.0` and `frida-tools==14.10.4`, leaving the
default lab environment intact. Run the collector with that interpreter. The deployment helper
accepts `FRIDA_PYTHON=/path/to/isolated/bin/python` together with `--flavor florida`; it selects
`~/tools/frida-server/florida-server-17.18.0-android-<abi>` and a separate device filename.
Do not run both server flavors on the same listening endpoint. The helper's existing `start`
action attempts to change SELinux; it is not required by the collector. Preserve the lab policy.
Verify host compatibility using the selected interpreter:

```bash
/path/to/isolated/bin/python -m unittest discover -s scripts/tests -p test_frida_compatibility.py
```

Use the lab interpreter for live capture (Frida 17.19.0 and its matching `frida-tools` Java bridge):

```bash
~/tools/venv/bin/python -m runtime_code capabilities --backend frida
~/tools/venv/bin/python -m runtime_code --store work/runtime-code capture \
  --backend frida --device emulator-5554 --app lab.runtimecode.fixture \
  --pack runtime_code/packs/art-inputs-and-states.json --seconds 30 --ui-port 8765
```

The app must already be installed. The collector does not patch, sign, install Gadget, enable app
debugging, change SELinux, root a device, or silently switch from spawn to attach. `--pid` explicitly
selects late attachment. A matching, rooted Frida server must already be running. Only designated
lab serials are accepted, and model, root access, package UID and process UID are checked.

The browser URL printed by `--ui-port` contains a local authorization token in its fragment.
The server binds to `127.0.0.1`; requests require that token. Treat the URL as sensitive.
The workspace displays app/device/Run/process state and places Runtime Code below Findings.
Select a snapshot for details, export or analysis. Method variants can be exported through the terminal. Snapshot now requires a live collector and a tracked ART region. It never re-exports an
old buffer under a new timestamp. Unavailable operations return reasons.

Saved Runs remain accessible with ordinary Python (no live Frida needed):

```bash
python3 -m runtime_code --store work/runtime-code runs
python3 -m runtime_code --store work/runtime-code inventory --run RUN_ID
python3 -m runtime_code --store work/runtime-code timeline --run RUN_ID --after 0
python3 -m runtime_code --store work/runtime-code coverage --run RUN_ID
python3 -m runtime_code --store work/runtime-code relationships --run RUN_ID
python3 -m runtime_code --store work/runtime-code serve --run RUN_ID --port 8765
python3 -m runtime_code --store work/runtime-code tui --run RUN_ID
python3 -m runtime_code --store work/runtime-code analyze SNAPSHOT_ID
python3 -m runtime_code --store work/runtime-code export SNAPSHOT_ID work/new-export
python3 -m runtime_code --store work/runtime-code export-variants work/new-variants SNAPSHOT_A SNAPSHOT_B
python3 -m runtime_code --store work/runtime-code analysis-copy SNAPSHOT_ID work/new-analysis-copy
python3 -m runtime_code --store work/runtime-code export-trace --run RUN_ID --kind jni. work/new-jni-export
```

Terminal/TUI snapshot requests use a SQLite command queue, independent of the browser:

```bash
python3 -m runtime_code --store work/runtime-code snapshot --run RUN_ID --process PROCESS_ID --target ART_LOGICAL_ID
python3 -m runtime_code --store work/runtime-code command COMMAND_ID
```

`region.tracked` observations and snapshot `logical_id` fields identify targets. Command acceptance
is not capture success. Inspect the resulting observation and snapshot status. After a collector
crash, `recover --run RUN_ID` finalizes interrupted transfers as partial and records disconnection.
A filesystem lease refuses recovery while that Run still has a live collector.

## Architecture and contracts

| Layer | Responsibility |
|---|---|
| `model.py` | Declarative packs, backend-neutral TokenSpec, limits and capability negotiation |
| `service.py` | Run lifecycle, process instances, ordered ingestion, snapshot commands, shared operations |
| `store.py` | SQLite provenance, immutable SHA-256 blobs, transfer integrity, leases and staged exports |
| `analysis.py` | Bounded DEX/ELF inspection, method-variant exports, explicit analysis copies, handler registry |
| `backends/` | Frida hooks, bridge loading, pointers, ABI/build profiles and transport; observe-only tracer contract |
| `cli.py`, `tui.py`, `web.py` | Consumers of the same service; no backend-specific selection logic |

Backend factories register through `runtime_code.backends.register` or the
`runtime_code.backends` Python entry-point group. Handlers register through `register_handler`
or `runtime_code.analysis_handlers`. These are trusted installed extensions, never code from an APK.
A handler receives owned bytes and capture metadata and returns structured analysis; optional
`findings` are linked by core to the exact analysis and snapshot. The built-in structural handler
does not create maliciousness Findings. Full decompiler integrations remain follow-up work; raw
exports can already be opened with the lab's jadx/Ghidra tools.

The agent sends ordinary JSON observations separately from binary chunk messages. A transfer
declares its size and SHA-256, then supplies ordered, bounded chunks. The host verifies both before
atomically publishing the blob. Each snapshot has its own identity and triggering observation;
identical content deduplicates only storage. Incomplete, timed-out or corrupt transfers cannot become
complete artifacts. Partial bytes are retained with diagnostic status. All snapshot reads recheck
integrity. Paths and class names supplied by the target never become export filenames.

Correlations distinguish a Java loading attempt, lower ART/linker input, constructor/reader return,
and library-loader outcome. None independently proves payload execution. Host sequence means
ingestion order; device timestamps and thread IDs remain separate. It is not a synchronized global
clock or a complete cross-process causal ordering.

`packs/java-and-art.json` enables both original ByteBuffer and ART input capture. Unique matches
within the same process, load correlation and content hash are stored as relationships, preserving
both observations and artifact identities. Ambiguous associations remain unresolved.

Native JNI call sites use the decoded calling instruction, not the resolved target. Load bias is
derived from the mapped ELF's offset-zero PT_LOAD, and static addresses are `call_site - load_bias`.
The manifest specifies Ghidra image base zero. Ambiguous instructions, JIT/anonymous callers and
unsupported headers remain unattributed. Path/build-ID matches and DEX origin/method matches are
explicitly labeled inferred associations, not direct proof of byte identity at execution time.

The backend and assembled agent contain no forbidden global module namespace references. The
installed Java bridge's two legacy global-export resolver calls are redirected in memory to
process-scoped enumeration. Unknown resolver APIs cause rejection. The installed bridge itself is
not modified; the assembled agent hash is recorded in Coverage.

## Capabilities and current limits

| Token capability | Implemented scope |
|---|---|
| `dex.input.java` | InMemoryDexClassLoader single/multiple ByteBuffer overloads; heap/direct/slices; duplicate reads preserve position/limit. Explicitly narrower than ART coverage. |
| `dex.input.art` | Exact-profile DexFile constructor input copying below Java wrappers. Tested file loaders, direct DexFile, multidex and memory paths. Unknown internal builds fail by token name. |
| `dex.snapshot.runtime` | Validated DexFile begin/size fields; lifetime tracking via constructor generation and destructor; manual, polling and declared exported-function triggers. Single-copy consistency only. |
| `native.input.linker` | Exact-profile ElfReader::Read descriptor/offset capture before segment loading/constructors; regular ELF64 little-endian inputs. No descriptor seeking/closing/reopening by the collector. |
| `native.inventory` | Process module inventory and add/remove notifications, explicitly distinct from original-input capture and execution. |
| `jni.trace.selected` | Declared standard JNI table calls, bounded ring, Java stack origins, static native call sites, separate targets and processing/loss counters. Java-to-native entry tracing is not yet included. |

Packs requesting unsupported capabilities fail instead of falling back. The generic observe-only
`tracer` rejects extraction; it has no live event source configured in this release. The full
`jni.trace`, `webview.flow`, `crypto.trace`, `parser.trace`, native-mapping snapshots, custom-loader
extraction and generalized change tracking are not implemented. Their browser views are present as
navigation destinations and explain missing observations; they are not evidence of capture support.

Additional gaps:

- Already-loaded DEX object enumeration, complete Java native-entry tracing, full WebView causal
  flows, crypto input/output provenance, parser/missing-field tracing, and their fixtures remain open.
- Secondary processes with the usual package-name prefix and app UID are polled once per second
  and explicitly labeled late-attached. Isolated UIDs, arbitrary process names and complete early
  secondary-process gating remain unsupported. No retroactive startup-coverage claim is made.
- Native memory snapshots/reconstruction and custom executable-mapping discovery remain open.
- JNI selection does not trace unselected functions or recover every Java caller signature/origin.
  Backpressure, omitted paths and attribution failures are visible; this is not an exhaustive stream.
- Runtime DEX reads are not stop-the-world snapshots. Ownership/mapping checks prevent known stale
  reads, but concurrent mutation and unsupported destruction paths remain limitations.
- Polling can miss transient bodies. A declared native-function trigger was tested against a
  source-built fixture; it does not discover unknown decryption triggers automatically.
- Candidate malformed/compact DEX bytes can be retained, but are not normalized into ordinary DEX.
  DEX 041 and optimized representations are unsupported by the structural inspector.
- ELF exports cover independently bounded program/section file ranges. Trailing bytes outside those
  ranges are excluded. Native memory regions are never labeled original ELF inputs.
- In-app exceptions, loader rejection, instrumentation failures, and access failures remain distinct.
  A returned class-loader constructor can still contain a suppressed DEX-load error.

## Limits, shutdown and retention

Packs set maximum capture size, owned pending bytes, queue depth, event count, binary retention,
copy-time budget, tracked regions, transfer timeout and polling interval. Defaults are 4 MiB/capture,
8 MiB pending bytes, 64 queued events, 100,000 events, 128 MiB retained binary content, 32 tracked
regions, 100 ms copy budget and 1-second polling. Overrides have hard ceilings.

Copy-time accounting is measured, not a real-time preemption guarantee: a kernel page fault or
regular-file read cannot safely be interrupted inside the target. Oversized/deadline-exceeding
captures are skipped with loss accounting; no hook waits for host acknowledgments. Owned binary
buffers wait only in the bounded transfer queue and expire. Observation throttling and binary loss
have separate counters. Exhaustion preserves earlier evidence and lets the app continue.

The retention byte budget currently applies to unique blobs across the store. Metadata, analysis
results and analyst exports are separate. There is no automatic eviction or garbage collection;
references cannot be deleted behind saved snapshots. Long-term dependency-safe retention policy
and crash/power-loss fault injection beyond the current tests remain future work.

Shutdown stops hooks, flushes bounded notifications, detaches, drains host ingestion and finalizes
incomplete transfers. The Run records disconnect/crash outcomes and loss counters. Handler code is
trusted; a stalled custom handler can exceed the host drain deadline, which is reported rather than
claimed complete. A full isolated, cancellable analysis scheduler remains open.

## DEX inspection and export

The inspector supports standalone little-endian DEX 035, 037, 038, 039 and 040 with bounded table,
string, LEB128 and code-item traversal. It records checksum/signature consistency separately from
structural inspection. It is not an ART bytecode verifier, decompiler, or proof of loadability.
Resource-limit failures are distinct from unsupported formats and invalid structure.

Methods are keyed by class/name/signature, without class-name length or package-depth filtering.
Code-item exports include register counts, instructions, try items and encoded exception handlers;
the original snapshot retains referenced debug information and identifier tables. Native/abstract
methods are legitimate no-body states. Short void/null-return stub flags are explicitly heuristic.
Counts describe observed changes/body variants, never a percentage of program recovery.

Method-variant exports require the same process and logical DEX identity. Different load instances
are not silently merged. `export-variants` retains observed snapshots and a manifest without a combined
DEX. `analysis-copy` explicitly recomputes only the DEX SHA-1 and Adler32 fields, preserving the raw
original and recording the transformation and both hashes.

## Validation

```bash
python3 test-fixtures/runtime-code/build.py
python3 -m unittest discover -s scripts/tests -p test_runtime_code.py -v
~/tools/venv/bin/python scripts/validate_runtime_code.py --device emulator-5554
~/tools/venv/bin/python scripts/validate_runtime_code.py --device emulator-5554 \
  --pack runtime_code/packs/art-inputs-and-states.json
~/tools/venv/bin/python scripts/validate_runtime_code.py --device emulator-5554 \
  --pack runtime_code/packs/jni-and-native.json
~/tools/venv/bin/python scripts/validate_runtime_code.py --device emulator-5554 \
  --pack runtime_code/packs/fixture-transient-states.json --transient
```

The harness installs an unchanged, non-debuggable source-built APK, serves fixture payloads on
localhost through a scoped adb reverse route, and removes that route afterward. Payload DEX/JAR
inputs are outside the bootstrap APK. It checks known hashes, buffer/descriptor state, multidex,
root-package short identifiers, native dependency and constructor behavior, and static JNI call-site
addresses against independent ELF disassembly. The optional transient test uses a separate fixture
driver to invoke a source-built mutator; the production collector never writes target DEX bytes.
No client backend is contacted. Receipts and raw evidence remain under `work/`.

See [the compatibility matrix and measured results](../reports/runtime_code/VALIDATION.md).
The full acceptance criteria remain open until the unimplemented coverage above is delivered and
the additional device, lifecycle, stress and frontend tests pass.

State comparison was removed at analyst request. Raw snapshots and method-variant exports remain available.

## Search and observed string mappings

Package include/exclude fields apply across all searchable browser views and code search. Enter
`com.app.my.*` to include that namespace and descendants, or `com.adjust.*` to exclude one.
Space- or comma-separated prefixes are supported; exclusion wins. The exclusion field also accepts
`-com.abc.cff -com.adjust.*` to exclude both hierarchies. Plain prefixes still work. On the CLI,
use `--exclude-packages='-com.abc.cff -com.adjust.*'` (with `=`) for leading-minus values.
Matching uses attributed operation owners
and nearest app callers, not URL text or arbitrary content. Root-package names remain supported.
An include filter hides unattributed records; an exclusion alone retains them. These are display
filters, not deletion or changes to capture scope.

Findings includes observational encrypted/decrypted pairs for Cipher decrypt calls and input/output
pairs for custom transformations whose semantic roles are unverified. Statically recovered strings
are labeled as static evidence. Each retained runtime value links to its exact snapshot. Previews
and searchable decoded text are bounded to 8 KiB per value (512 bytes in Crypto list previews).
Missing or truncated values remain explicit; no maliciousness rating is inferred.

Failed WebView callbacks appear in Navigation flows and Network, including legacy saved callbacks.
A cleared display window still hides earlier events: use **Show earlier results** to search those
saved records. Clicking a flow node highlights its left-hand row; a stage outside the current text
filter/category is pinned with a **Selected flow stage** label. Package exclusions still apply.
The Raw JSON flow contains the same nodes and collapsed edges shown by Key stages / Show app hops.

Terminal equivalents:

```bash
python3 -m runtime_code findings --run RUN_ID --query google.com --exclude-packages 'com.adjust.*'
python3 -m runtime_code search-code --run RUN_ID google.com --include-packages 'com.app.my.*'
```
