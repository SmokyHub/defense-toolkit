# Offline DEX response analyzer

Run from any working directory with Python 3.10 or newer. Keep `scripts/dex_response_profiles/`
and `scripts/dex_semantic.py` beside the main script when copying it. Reviewed-profile matching
uses the standard library; automatic Dalvik analysis requires Androguard 4.1.4. The lab's
`~/tools/venv/bin/python` is selected automatically. Elsewhere, install
`scripts/requirements-dex-response.txt` in a virtual environment and select its interpreter with
`--semantic-python /path/to/venv/bin/python`. `--no-semantic` disables this discovery pass.

```bash
python3 /home/nyx/Documents/apk_defense/scripts/analyze_dex_response.py \
  /path/to/application.zip --out /path/to/new-analysis-directory
```

By default the terminal prints a status summary with paths to the generated template and schemas.
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

**There are two analysis paths: guarded matching of the reviewed NN555 Flutter ARM64 layouts,
and bounded automatic discovery of Dalvik/Java/Kotlin response consumers.** The latter derives
new JSON keys, packed method fields and app-owned entry names from bytecode without a matching
profile. It does not independently recover these variations from pure Flutter AOT or native code.
Unknown or unsupported loaders get candidate evidence and
`needs_review`, not a guessed complete schema or a claim that loading is absent. Encrypted values
available only from an unseen server cannot be recovered from the APK.

## Outputs and automation contract

`analysis.json` has format identifier `apk-defense.dex-response/v1`. For each app it contains:

- Package/version and every input APK identity; original executable SHA-256 hashes.
- `capability.status`: `supported_by_static_evidence`, `possible`, or `unknown`.
- `schema_status`: `complete_for_test_contract` or `needs_review`.
- `automation.template_ready` and `automation.action` (`validate_template` or `manual_review`).
- Matched profile, recovered keys, field roles, addresses/evidence, selected values and their provenance.
- Automatic matches carry `profile_source: automatic_consumer_dataflow`, DEX hashes, instruction
  evidence, `fixed_calls`, `resolved_contract`, and `dex_encodings`. `semantic_analysis` records
  instruction counts and diagnostics for unsupported paths. Those counts are not a coverage score.
- The historical endpoint/method for the matched code, clearly labeled as historical evidence.
- Unresolved cases: candidate loader/network strings and bounded ARM64 numeric-string construction
  hints. These are not a recovered source-to-sink path. Generic SDK/JNI hits never establish loading.

Each complete match produces three files under `<package>/<profile-id>/`:

| File | Purpose |
|---|---|
| `response.template.json` | Filled compatible loader response with literal `"DEX ARRAY"` in place of bytes |
| `template.schema.json` | JSON Schema 2020-12 contract accepting that placeholder template |
| `response.schema.json` | JSON Schema contract for the response after substituting the detected DEX representation |

The wire schema deliberately rejects `"DEX ARRAY"`. Depending on the recovered consumer, it expects
a byte array or a Base64/Base64URL string. Array schemas allow integer bytes and decimal-byte
strings. It validates structure, not DEX format, signature,
loadability, or the presence of the requested class/method. No DEX payload is generated.
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

For the original APK1, the generated template is:

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

## Automatic Dalvik discovery

When no native profile matches, the worker parses the submitted DEX members and follows response
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

The current binary key extractor handles reviewed ARM64 Smi-to-decimal sites only. A profile can
use literal string paths where verified code fixes those strings, with all loaded bytes guarded.
Other framework extractors need their own reviewed implementation and tests.

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

`python3 scripts/build_reviewed_dex_profiles.py` regenerates the bundled profiles from the two
original local ELF files and reviewed reports. It verifies the original library hashes and extracts
keys at audited sites. It is a reproducibility helper, not a learner for unknown apps.

## Validation and resource limits

```bash
python3 -m unittest discover -s scripts/tests -p 'test_dex_*.py' -v
APK_DEFENSE_SAMPLE_TESTS=1 python3 -m unittest discover -s scripts/tests -p 'test_dex_*.py' -v
```

The optional real-sample tests require the locally held originals, previous capture fixtures, and
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
