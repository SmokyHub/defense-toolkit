# Offline DEX response analyzer

Run from any working directory with Python 3.10 or newer. Keep `scripts/dex_semantic.py`,
`scripts/flutter_semantic.py`, `scripts/flutter_contract.py`, `scripts/flutter_preferences.py`
`scripts/dart_snapshot_reader.py`, `scripts/dart_snapshot_schema.py`, `scripts/flutter_toolchain.py`
and `scripts/dex_response_proof.py`
beside the main script when copying it. **Profiles are not
loaded by default.** Automatic Dalvik analysis requires Androguard 4.1.4; Flutter discovery
requires Capstone 5.0.7 and pyelftools 0.33. Snapshot metadata comes from a compatible
native Blutter analyzer or the supported Python snapshot reader described below. The lab's
`~/tools/venv/bin/python` is selected automatically. Elsewhere, install
`scripts/requirements-dex-response.txt` in a virtual environment and select its interpreter with
`--semantic-python /path/to/venv/bin/python`. `--no-semantic` disables both discovery passes;
`--no-flutter` disables only Flutter discovery.

```bash
python3 /home/nyx/Documents/apk_defense/scripts/analyze_dex_response.py \
  /path/to/application.zip --out /path/to/new-analysis-directory
```

By default the terminal prints a status summary with paths to the generated template and schemas.
For the default benign entry contract, it also writes **`response.proof.json` with the actual
benign DEX bytes already encoded for the recovered field**. Use that file directly for an
authorized response-replacement test; no manual `DEX ARRAY` substitution is required.
The portable Family2 folder includes the hash-pinned fixture under `fixtures/`.

To export that ready-to-use response to a convenient fresh file:

```bash
python3 scripts/analyze_dex_response.py application.zip --out work/new-proof-analysis \
  --proof-response work/ready-response.json
```

The explicit export requires exactly one complete app/loader with the compatible benign
contract and refuses to overwrite a file. Default per-loader proofs remain under `--out`.
To print the filled response JSON itself, use `--print-template`:

```bash
python3 scripts/analyze_dex_response.py application.zip --out work/new-analysis --print-template
```

Files are still saved under `--out`. This mode requires exactly one complete app and loader path and is suitable
for redirecting stdout to a JSON consumer. Diagnostics go to stderr; unknown inputs produce no
stdout and exit 2, while multiple-app or multiple-loader inputs exit 1 rather than selecting an arbitrary template.
To inspect an existing run, read its `response.template.json`; no reanalysis is needed.

Inputs: a monolithic APK, ZIP of APKs, or APKS/XAPK/APKM container. ZIPs may contain nested folders
and nested APK containers. Include the base and ARM64 split for these Flutter apps. Multiple apps
are analyzed separately; conflicting versions/splits are rejected. A directory containing unpacked
analysis files is not an input. The tool reads manifests and executable members without installing,
running, uploading, or contacting the app/backend.

**The default uses automatic discovery, with different coverage for Dalvik and Flutter.**
The Dalvik/Java/Kotlin consumer analyzer derives
new JSON keys, packed method fields and app-owned entry names from bytecode without a matching
profile. Flutter analysis now emits the filled loader contracts for APK1–APK3 and the tested
preferences-mediated Drift variant without
application profiles. It derives key paths and roles from receiver/argument relationships,
lazy-initializer metadata, concrete dispatch targets and JNI bridge relocations. These are
**conditional static test contracts**, with branch and library-semantic assumptions retained
in their evidence; they are not proofs of network delivery or runtime execution.
Unknown or unsupported loaders get candidate evidence and
`needs_review`, not a guessed complete schema or a claim that loading is absent. Encrypted values
available only from an unseen server cannot be recovered from the APK.

## No compilation: Python snapshot reader alongside Blutter 3.12.1

If only your existing Blutter 3.12.1 is allowed, use:

```bash
.venv/bin/python analyze_dex_response.py /path/application.zip \
  --flutter-reader python --semantic-python .venv/bin/python \
  --out results/python-case --proof-response ready-response.json
```

This path does not run, install, download or compile any Blutter/Dart version. Your
existing 3.12.1 installation remains available for compatible apps. You may retain
`--blutter-bin /path/blutter_dartvm3.12.1_android_arm64_semantic`, but it is unused in
explicit `python` mode. Do not add `--prepare-blutter`; that combination is rejected.
The usual Python dependencies are still required.

The reader handles full-AOT, product, Android ARM64 compressed-pointer snapshots with
format `78da37fed6bf1489361a312568249f3f` and the documented feature flags. This is the
Dart 3.11.1-compatible **serialization format**, shared by Drift and the saved APK2;
it is not a libapp file hash or an app allowlist. The reader derives the object pool,
class IDs, field offsets, function entries, dispatch table and runtime stub identities
from each submitted ELF. Copied stubs require an unambiguous exact byte match to a
VM/store stub in that same ELF. No app-specific offsets, JSON keys, response packs,
saved Blutter output or SDK source are loaded at runtime.

`--flutter-reader auto` (the default) uses a compatible native analyzer if available,
otherwise falls back to Python for this supported format, including when the pinned
3.12.1 binary has a different snapshot format. `--flutter-reader blutter` requires the
native path and preserves its compatibility checks. Reports identify the actual reader
under `flutter_analysis.toolchain.reader`, and retain a native-selection diagnostic when
fallback occurred. Python mode reports no native analyzer.

This is bounded metadata recovery for the existing consumer analysis, not full Dart
source reconstruction or a universal snapshot translator. Unknown formats/features,
unsupported cluster layouts, deferred loading units and malformed records fail explicitly.
New apps using the supported format and recognized flows are analyzed from their own bytes;
new compiler/loader patterns can still return `needs_review`. The implementation is Python
and has no host-native analyzer dependency; validation ran on Linux, **not on a Mac**.
The regression tests compare metadata against saved native outputs for two distinct apps,
and reanalyze a modified ELF with changed numeric keys. See
`reports/flutter_python_reader_20261009/VALIDATION.md` in the repository.

## Outputs and automation contract

`analysis.json` has format identifier `apk-defense.dex-response/v1`. For each app it contains:

- Package/version and every input APK identity; original executable SHA-256 hashes.
- `capability.status`: `supported_by_static_evidence`, `possible`, or `unknown`.
- `schema_status`: `complete_for_test_contract` or `needs_review`.
- `automation.template_ready` and `automation.action` (`validate_template` or `manual_review`).
- Recovered keys, field roles, addresses/evidence, selected values and their provenance where established.
- `flutter_analysis`: snapshot/analyzer identities, input hashes, candidate access/call addresses,
  request context, unresolved JNI receivers, bounded-slice diagnostics and explicit limitations.
- Automatic matches carry `profile_source: automatic_consumer_dataflow`, DEX hashes, instruction
  evidence, `fixed_calls`, `resolved_contract`, and `dex_encodings`. `semantic_analysis` records
  instruction counts and diagnostics for unsupported paths. Those counts are not a coverage score.
- Flutter matches use `profile_source: automatic_flutter_consumer_inference` and
  `capability.reason: conditional_flutter_consumer_contract`. Their evidence includes the
  object/void adapters, byte conversion, JSON parser context, table-provider identity, and
  success-path conditions. `profile_id` is a legacy output-field name, not a loaded profile.
- Explicit legacy profiles additionally provide the reviewed historical endpoint/method.
- Unresolved cases: candidate loader/network strings and bounded ARM64 numeric-string construction
  hints. These are not a recovered source-to-sink path. Generic SDK/JNI hits never establish loading.

Each complete match produces these files under `<package>/<profile-id>/`:

| File | Purpose |
|---|---|
| `response.template.json` | Filled compatible loader response with literal `"DEX ARRAY"` in place of bytes |
| `response.proof.json` | Ready-to-use response containing the bundled benign DEX, when its entry contract is compatible |
| `template.schema.json` | JSON Schema 2020-12 contract accepting that placeholder template |
| `response.schema.json` | JSON Schema contract for the response after substituting the detected DEX representation |

The wire schema deliberately rejects `"DEX ARRAY"`. Depending on the recovered consumer, it expects
a byte array or a Base64/Base64URL string. Array schemas allow integer bytes and decimal-byte
strings. It validates structure, not DEX format, signature,
loadability, or the presence of the requested class/method. The proof response inserts the
existing source-built 5,120-byte fixture; it does not compile a new payload. Its SHA-256 is
`8de5fb444a932ad2eb5af51fb1082f4cf6d293441808f37ab84e546e936017d0`. Numeric-array,
Base64 and Base64URL fields are filled according to their recovered `dex_encodings`.
The fixture displays local HTML headed “APK Defense: DEX executed” and a button that changes
to “DEX button handler executed”; its entry makes no network request. A generated proof is
still a **conditional test input**, with `runtime_validated_this_run: false` in its metadata.
Actual execution and screenshots require a separate runtime test.

A custom or app-owned class/method contract that differs from the fixture retains its ordinary
template and gets an explicit proof-unavailable reason. Missing or modified fixture bytes also
prevent proof generation; the exact size/hash is checked. `--proof-response` fails explicitly
when no compatible proof is available. `--print-template` deliberately retains the placeholder
template behavior.
Unrelated UI/config settings are outside the generated **loader-branch** schema; additional object
properties are allowed. This is a compatible validation response, not the original production response.
Multiple independently resolved paths produce separate templates; incompatible alternatives are
never merged. A complete template describes the recovered branch, not every path in the application.
Inspect diagnostics for additional unresolved paths.

Default payload contract (selected by the user):

```text
com.apkdefense.fixture.webview.ResponseEntry
public no-argument constructor
public instance void run(android.app.Activity)
```

`--payload-class` and `--entry-method` can change the name selections; the default descriptor remains
`(Landroid/app/Activity;)V`. Automatically recovered app-owned names take precedence and appear in
`resolved_contract`; no response fields are invented for them. Reviewed-profile constraints can
reject an incompatible override. The other filled values
use `dalvik/system/InMemoryDexClassLoader`, its ByteBuffer/ClassLoader constructor, `getClassLoader`,
`loadClass`, and their compatible JNI descriptors. These are the values used in the benign validation,
not claims about server-only literals recovered statically.

For the original APK1, the automatic mode generates:

```json
{
  "172": {
    "552": "dalvik/system/InMemoryDexClassLoader",
    "172": "DEX ARRAY",
    "143": "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",
    "477": "getClassLoader",
    "518": "()Ljava/lang/ClassLoader;",
    "268": "loadClass",
    "217": "(Ljava/lang/String;)Ljava/lang/Class;",
    "223": "com.apkdefense.fixture.webview.ResponseEntry",
    "199": "()V",
    "33": "run",
    "218": "(Landroid/app/Activity;)V"
  }
}
```

Exit codes: **0** all apps have complete templates; **2** at least one needs review; **1** invalid
input/profile or processing error. Standard output is one JSON summary unless `--print-template`
selects the filled response. Consumers should check the
exit code and each app's `template_ready`, then follow its returned relative file paths. Do not decide
from a string hit or a file left by an earlier run. `--out` must not already exist; outputs are staged
and renamed only after successful processing. An error does not create a partial complete result.

## Automatic Flutter discovery

```bash
python3 scripts/analyze_dex_response.py application.zip --out work/automatic-case \
  --blutter-dir /path/to/blutter
```

The worker reads the Dart snapshot format hash through ELF load-segment address mapping
and chooses an installed native analyzer with the same embedded format hash and a compatible
host OS/CPU. This is **not the SHA-256 of `libapp.so`**: unrelated apps can share a snapshot
format. File SHA-256 values are recorded as evidence, not used to select application profiles.
`--blutter-bin` pins one native analyzer and must still match. Repeat `--blutter-dir` for
multiple installations; checkout roots and `bin/` paths are supported. `BLUTTER_HOME` supplies
the default root, otherwise `~/tools/blutter` and `~/blutter` are searched. Compatible semantic
builds are preferred across all roots. Version names are not allowlisted.

For explicit toolchain preparation, with upstream Blutter source already installed:

```bash
python3 scripts/analyze_dex_response.py application.zip --out work/prepared-case \
  --blutter-dir /path/to/blutter --prepare-blutter --proof-response ready-response.json
```

Preparation stages `libapp.so` and `libflutter.so` from the same ARM64 input. It reuses a
compatible semantic binary, or invokes the installed upstream wrapper to identify/build the
matching stock VM and then builds the bundled semantic extension. Builds coexist in `bin/`.
The wrapper may download Dart/toolchain sources; it does not upload the app or execute its
code. Normal Blutter compiler/dependency requirements still apply. An unsupported upstream
snapshot or extension API change fails explicitly. This flag does not install upstream Blutter.
The default build timeout is 1,800 seconds (`--blutter-build-timeout` overrides it); timeout
kills the setup process group, including compilers. A durable build log is printed to stderr
and recorded as `toolchain_preparation.log` in the Flutter result. This setup runs outside the
shorter analysis-worker limits. Existing stock binaries are preserved. Cached and freshly built semantic analyzers must produce parseable metadata and stub records on the input before preparation succeeds. The extension resolves its runtime template path to the installed upstream resources, so removing its temporary build tree does not break the installed binary.

Without the preparation flag, no fetching wrapper or build is invoked and analysis remains
offline. A 3.12.2 VM build cannot read an incompatible 3.11 snapshot merely because both are
Blutter. On macOS, build native binaries locally; the extension inherits the stock build's
compiler, architecture, SDK and deployment-target settings. Linux ELF analyzer binaries are
rejected on macOS with a specific diagnostic. Native macOS execution has not been validated
in this Linux lab; selection/header and compiler-setting behavior has unit-test coverage.

The pass disassembles AArch64 executable load segments and reconstructs direct-call, object-pool and
recoverable lazy-instance-initializer references. Numeric strings require a small-integer untagging
operation and the decimal conversion table, not merely a MOV immediate. String-literal key accesses
are also eligible. Candidate key-to-dispatch slices and bounded local register/frame copies identify
consumer call sites. JNI table slots come from the submitted bridge ELF's symbol relocations.
Nearby request construction and HTTP-related literals provide investigation context, **not proof
that a particular server response produced a particular value**.

Names, package IDs, preassigned field order and known application hashes do not select this path.
Obfuscated helper names are linked only when their metadata appears in the submitted snapshot.
The snapshot hash selects a parser format, not an application profile.

On the native path, complete contract extraction requires the metadata-exporting Blutter extension shipped as
`build_flutter_semantic_blutter.py` and `blutter_semantic_extension.inc`. After building stock
Blutter for the required Dart VM, build/install the extension once per compatible VM:

```bash
python3 scripts/build_flutter_semantic_blutter.py --blutter-dir /path/to/blutter \
  --dartlib dartvm3.12.2_android_arm64 --out work/blutter-semantic-3.12.2 --install
```

For the lab APK2 snapshot, use `dartvm3.11.1_android_arm64` in a different fresh output directory.
The helper copies stock source, reuses already-installed VM packages/build configuration, and
leaves the stock analyzer intact. This manual extension helper does not download tooling. The default selector prefers the
matching `_semantic` analyzer. Stock Blutter still provides investigation candidates but lacks the
metadata needed for a complete contract; the report names this prerequisite.

The extension exports snapshot-derived initializer addresses, object class IDs, builtin class IDs
and dispatch entries. The worker reads VM stub names as text, never executes generated IDA scripts,
and follows field values through the parent-ClassLoader call, loader construction, loadClass result,
payload construction, and Activity entry argument. It checks object identities and argument lists;
it does not assign roles by numeric-key order. A changed key is recovered from the changed binary.

Advertised automatic AOT coverage is the tested collection/JNI consumer topology: numeric or literal
map keys, decimal-string/integer list to Uint8List to direct ByteBuffer, class/method identifiers in
separate fields, instance construction and a void entry taking one Activity. Recompilation across
the tested Dart snapshots works without app hashes or obfuscated-name selectors. Automatic AOT
packed-string/array method fields, hardcoded entries, other byte encodings, other JNI libraries and
arbitrary compiler register allocations are not advertised. Such cases require review; the broader
Dalvik variations below must not be confused with AOT coverage.

The tested asynchronous preferences variant has an additional boundary: the selected JSON object
is iterated into `SharedPreferencesAsyncApi.setString`; strings are stored directly, while
nonstrings are serialized as Base64 of UTF-8 JSON. The loader reads those keys using
`SharedPreferencesAsyncApi.getString`, awaits their values, reverses the byte-array serialization,
then follows the same JNI construction chain. The response still carries a **JSON byte array**;
the Base64 form is an internal preferences representation, not the wire value. The analyzer checks
key/value packing, map iteration, the writer-to-loader handoff, codec argument flow and the
downstream JNI receivers. It derives the selectors from the submitted instructions rather than
using Drift's package name, fixed numeric keys or an application profile.

This boundary supports the tested Pigeon/async compiler topology. Other preference stores,
serialization chains, async layouts or JNI consumers remain `needs_review`. Its evidence appears
under `preferences_boundary`, including the read/write calls, codecs and explicit success-path
and standard-library assumptions. Static agreement does not prove that an actual network response
was delivered or that code executed; a separate benign runtime validation is needed for that claim.

The analysis follows a conditional success path. Concrete type/identity tests are evaluated where
modeled; unresolved branch predicates are retained as assumptions. GetGlobalEnv is checked against
ELF relocations for the exported table identity. Candidate slot records still say
`receiver_proven: false`: the pass assumes standard exported dartjni/Dart helper semantics and does
not formally verify every native wrapper or every FFI receiver. JSON parsing and request context
are located, but exact network-response byte provenance is not established. Those limitations are
included with the generated contract. Do not treat `template_ready` as authorization to modify a
live server response or as evidence that a load executed. Unknown consumers remain candidates,
never an automatically actionable replacement for a missing contract.

Limits include 256 MiB per ELF, 64 MiB object pool, four million instructions, 200,000 function hints,
512 visited graph nodes per context query, 512 slice states per access, 12,000 consumer-slice
instructions, 256 visited helper nodes, 128 numeric candidates,
120 seconds per Blutter invocation, and 180 seconds for the worker. Linux workers also use a
virtual address-space limit of 96 GiB while Blutter runs (Dart 3.12 reserves two 32 GiB guard
regions), reduced to 4 GiB for the Python analysis phase. This is not a resident-memory limit.
Budget exhaustion remains visible. These are analysis limits, not a security
sandbox for third-party parsers. Native Blutter tooling must match the host OS and architecture.

## Optional legacy reviewed profiles

```bash
python3 scripts/analyze_dex_response.py application.zip --out work/reviewed-case \
  --reviewed-profiles --print-template
```

This explicitly enables the previous guarded matching path and requires `dex_response_profiles/`
beside the script. `--profile /path/local.json` enables only the specified reviewed profile unless
`--reviewed-profiles` is also supplied. The default never reads that directory. Legacy templates
remain available as an explicit compatibility mode; automatic APK1–APK3 extraction no longer requires them.
Portable bundles omit these legacy profiles by default; a bundle can include them explicitly with
`scripts/build_portable_toolkit.py --include-reviewed-profiles`.
For legacy-only operation without worker dependencies, combine `--reviewed-profiles --no-semantic`.

## Automatic Dalvik discovery

Unless an explicitly selected native profile matches, the worker parses submitted DEX members and follows response
values through app helpers into class loading and reflective entry invocation. Covered variations:

- Nested JSON objects/arrays and new string keys, including recompiled or renamed app classes.
- Separate method fields, multiple methods in one JSON array, or methods in one delimited string
  parsed with a supported literal `String.split` delimiter. Order is derived from consumers.
- Response-controlled payload class/entry names and hardcoded names invoked through app helpers.
- Direct or reflected `InMemoryDexClassLoader` construction, `ByteBuffer.wrap`, and a fully filled
  direct buffer followed by `flip`/`rewind`.
- A complete file write followed by `DexClassLoader` consuming that same literal path.
- Android Base64/Base64URL decoding and a canonical `JSONArray.getInt` → byte-array copy loop.
- A no-argument payload constructor and instance entry accepting one `android.app.Activity`.

The currently modeled network origin is a literal HTTP(S) `java.net.URL` through
`openStream` or `openConnection`/`getInputStream`, then `readAllBytes` → String → JSON. Other
network stacks, including OkHttp/Retrofit, are not yet modeled as verified origins. This is static
evidence of a compatible path; fixtures are compiled and analyzed, never executed.

Unresolved response gates, unknown crypto/transforms, unsupported loops, unresolved app virtual
dispatch, wrong invocation receivers, and native mutation prevent that path from emitting a complete
template. Local-file URLs and constant JSON do not establish server delivery. API names alone never
produce a template. These limits favor a review result over filling fields without consumer evidence.

## Reviewed Flutter matching

The built-in profiles guard file-backed PT_LOAD bytes and their ELF mapping. The `runtime_notes_v1`
normalization ignores ELF section-table header metadata and GNU build-ID note descriptors.
It also masks the immediate bits of the 16 reviewed numeric-key construction instructions; their MOVZ/STR/BL opcodes,
call destinations, consumers, all other code, and loaded constants remain protected by SHA-256.
`libdartjni.so` must also match the reviewed dependency, allowing the same metadata normalization.
Keys are decoded from the submitted binary,
not selected by package name or copied from a report. Repeated cache/outer-map key sites must agree.
The inner DEX-list key may differ from the outer map key. Field collisions are rejected.

This recognizes repackaging, GNU build-ID changes and key rotations in those code layouts. Recompilation, different
register allocation, string keys, new packing, changed helpers, changed code/data, and unavailable
dependencies can cause a review result even if an analyst later proves equivalent behavior. Original
sample hashes are retained for provenance; matching is not solely by whole-APK hash.

For pure Flutter AOT/native inputs, schema bindings support the variations below **after their
consumers have been reviewed and a matching binary profile added**. The Dalvik backend discovers
the supported bytecode forms automatically; its compiled fixtures do not establish AOT coverage.

- Multiple method names in one JSON array: paths such as `["loader", "methods", 0]`, `[..., 1]`, `[..., 2]`.
- Name/descriptor or multiple methods in one string: `encoding: "join"`, an explicit delimiter and
  ordered values. Delimiters are never guessed; collisions are rejected.
- Nested objects and arrays, string keys, independent keys and multiple DEX fields.
- Methods already owned by the app: record them in `fixed_calls`; do not invent a corresponding
  response field. A `contract`/`value` constraint rejects incompatible CLI overrides.

The legacy profile key extractor handles reviewed ARM64 Smi-to-decimal sites only. A profile can
use literal string paths where verified code fixes those strings, with all loaded bytes guarded.
Other framework extractors need their own reviewed implementation and tests.

## Reviewed APK3 (Dart 3.12.2)

The family2 split set `apks/family2/apk3/bbottalmachingp/` is covered by
`nn555_apk3_arm64`. Its recompilation changes the loaded-code fingerprints and instruction
addresses, so older profiles correctly returned `needs_review`. The reviewed path keeps the
same loader/entry call shape with outer key `578` and byte-list path `578.578`.
The remaining fields are `190` (loader class), `253` (loader constructor), `198`/`204`
(parent method/descriptor), `432`/`117` (loadClass method/descriptor), `477` (payload class),
`574` (payload constructor), and `627`/`600` (entry method/descriptor).

See [APK3 static evidence](../reports/family2_apk3_20260928/01_code_audit.md).
Unlike APK1/APK2, APK3 has no HTTP Toolkit or payload-execution validation. Its request
metadata is labeled `static_reconstruction_not_wire_validated`; historical dynamic proof
from another APK is not attached to it. Loaded-byte/dependency guards apply in legacy profile mode; automatic inference uses the submitted code and snapshot metadata.
Rebuild only this profile with `python3 scripts/build_reviewed_dex_profiles.py --case apk3`.
The optional real-sample suite tests its full split ZIP, schema and field values, numeric
key rotation, rejection of altered call targets/bridge bytes, and missing dependencies.

## Adding a reviewed profile

Pass local JSON with `--profile /path/to/reviewed-profile.json`. Profiles in the input ZIP are
**never loaded**. Local profiles are trusted analyst configuration, not app data or independently
verified semantic proofs. They must cite evidence. A custom profile match is labeled
`custom_local_review_required` so company policy can require its own approval before acting.

Use the existing profile JSON as the format reference. Required fields include `format`, unique `id`,
`artifact_path`, `evidence`, full `segments` fingerprints, `key_sites`, and `bindings`. Key sites hold
ELF VAs. Use `fingerprint(original_bytes, key_sites, normalization)` after tracing the consumers,
with the same normalization selected by `elf_normalization`; it produces guarded
segment hashes and recovered keys. `dependencies` hold APK-relative library paths and original hashes.
Bindings use literal path components or `{"key": "site-id"}` references, a `role`, and a scalar `value`
or `{"contract": "entry_method"}` expression. Array indexes are JSON integers; numeric object keys are
JSON strings. Specify every array slot; sparse arrays are rejected.

Example binding fragments (not independently deployable profiles):

```json
[
  {"path": ["loader", "methods", 0], "role": "parent_method", "value": "getClassLoader"},
  {"path": ["loader", "methods", 1], "role": "load_class_method", "value": "loadClass"},
  {"path": ["loader", "methods", 2], "role": "entry_method", "value": {"contract": "entry_method"}},
  {"path": ["loader", "call"], "role": "entry_call", "encoding": "join", "delimiter": "|",
   "values": [{"contract": "entry_method"}, {"contract": "entry_descriptor"}]},
  {"path": ["loader", "bytes"], "role": "dex_bytes", "value": "DEX ARRAY"}
]
```

An app-owned entry name can be described as:

```json
{"owner": "app", "role": "entry_method", "contract": "entry_method", "value": "run",
 "evidence": "Report section and instruction/source location of the hardcoded name"}
```

Review requirements for a new implementation: identify network/decoded-response origin; trace
nesting, type conversions and packed-field parsing; bind each field to its consumer and argument
order; distinguish response values from hardcoded app values; confirm compatible descriptors and
entry invocation; add positive and structurally similar negative fixtures. Do not use API names alone.
The [Flutter reference](../.agents/skills/blutter-flutter-dart/references/response-loaders.md) and
[native reference](../.agents/skills/ghidra-headless-native/references/native-reconstruction.md)
describe that analysis. No complete native family1 server-response schema has been established,
so those native inputs cannot honestly be auto-filled by this version.

`python3 scripts/build_reviewed_dex_profiles.py` regenerates the bundled profiles from the three
reviewed local ELF files and reviewed reports. It verifies the original library hashes and extracts
keys at audited sites. It is a reproducibility helper, not a learner for unknown apps.

## Validation and resource limits

```bash
python3 -m unittest discover -s scripts/tests -p 'test_dex_*.py' -v
APK_DEFENSE_SAMPLE_TESTS=1 python3 -m unittest discover -s scripts/tests -p 'test_dex_*.py' -v
APK_DEFENSE_SAMPLE_TESTS=1 python3 -m unittest discover -s scripts/tests -p 'test_flutter_semantic.py' -v
```

The optional real-sample tests require the locally held originals, previous capture fixtures, generated
semantic Blutter outputs under `work/family2_apk3_analyzer/semantic-{apk1,apk2,blutter}`, and
`jsonschema` (test-only; installed in the lab's system Python). They ZIP all APK splits, validate both
generated templates against the successful HTTP Toolkit loader maps, independently validate the
JSON Schemas, and check the benign WebView fixture does not produce a positive template.

Synthetic tests cover numeric-key mutation, changed code/data rejection, dependency absence, packed
arrays/strings, app-owned names, collisions, split identity conflicts, archive traversal/symlinks,
duplicate members, nesting and expansion limits, and output handling. These are bounded regression
tests, not proof of universal static analysis or a measured false-positive rate.

`test_dex_semantic.py` compiles `test-fixtures/dex-loader-variants/LoaderVariants.java` into real DEX
using javac and Android SDK 36/d8. It checks eight supported paths without profiles, recompiles
renamed classes with changed JSON keys, validates generated schemas independently, and checks
negative paths. Android compiler tools and the Androguard interpreter are required; otherwise this
suite is skipped. `python3 scripts/build_dex_variant_fixtures.py` builds a persistent fixture in
`work/dex-loader-variants/`. The fixtures are never installed, run, or used to contact a server.

Default limits: 256 MiB/member, 1 GiB aggregate expanded contents across all nesting levels,
30,000 entries, and four nested containers. `--max-member-mib`/`--max-total-mib` adjust byte limits.
Encrypted archives are rejected. No archive member is extracted to a supplied path. Keep generated
results under `work/` in this repository because reports can contain client identifiers.
The semantic worker has a 60-second parent timeout, 100 candidate roots, a 40,000-instruction budget,
helper depth of eight, and 128 queued states per function. Budget exhaustion is reported; it is not
evidence that the app cannot load DEX.

The automatic Flutter contract suite compares all three outputs with independently reviewed
templates, checks changed-key rebinding and rejects missing dispatch metadata, a changed table
provider, removed method/copy calls and a wrong invocation receiver. Full ZIP and standalone
portable runs are recorded in `reports/family2_apk3_20260928/AUTOMATIC_DISCOVERY.md`.

### Additional preferences-key variation coverage (2026-10-08)

The async preferences recognizer now accepts string constants loaded from the Dart object
pool as well as decimal strings constructed by recognized helpers. It selects candidate
functions by their getter/wrapper call edges rather than the presence of numeric constants.
A key must still reach the actual lookup, equality guard or handoff argument. Codec, cache
receiver, map source, async completion and JNI role checks remain required.

Tests replace all numeric key constructions with renamed literal loads in the saved program's
intermediate representation and check all eleven recovered JNI roles. Mixed literal/numeric
keys also work; outer-key disagreement and role collisions fail. These are IR mutation tests,
not runtime validation of newly compiled variants. Original-byte numeric mutations and all
four saved Flutter apps are regression-tested separately. No claim of universal support for
future compiler output, storage APIs, codecs or arbitrary loading topologies is made.
