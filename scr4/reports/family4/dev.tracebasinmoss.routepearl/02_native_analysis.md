# Family4 native analysis: 5555xBasin

The original ARM64 library implements the request, response parsing, persistence,
DEX validation and in-memory execution in native code. Its Java-facing API accepts
an Activity and a JSONObject, and returns a JSONObject. A response can select a
class loader, supply DEX bytes and select an instance method receiving the Activity.
This establishes a configurable remote-code-loading capability; it does not identify
the contents or purpose of an unobserved production payload.

## Material and evidence

- Package: `dev.tracebasinmoss.routepearl`.
- Library: `libz5555xbasin.so`, 184,824 bytes, ARM64.
- SHA-256: `260e1aec4db63cea64f5f9486db3f639c9b4b5546099def8e1c50a593513b04c`.
- Original: `work/family4/dev.tracebasinmoss.routepearl/apktool_splits/split_config.arm64_v8a/lib/arm64-v8a/libz5555xbasin.so`.
- Ghidra: `work/family4_basin_native_ghidra_out/decompiled.c` and reusable project
  `work/family4_basin_native_ghidra_proj/`.
- Decoded annotations: `work/family4/native_analysis/annotated.c`.
- Automatic results: `work/family4/native_analysis/static-result.json`.

Addresses below are ELF virtual addresses. The Ghidra export uses an additional
`0x100000` image base. All findings in this document are static unless explicitly
linked to the separate runtime validation. No sample was uploaded or backend
contacted during native analysis. Original ELF bytes were preserved.

## Entry and full flow

`JNI_OnLoad` at `0xb628` registers
`dev/tracebasinmoss/routepearl/z5555xbasin/FestDrift._n4581150eae37011bd161`
with descriptor `(Landroid/app/Activity;Lorg/json/JSONObject;)Lorg/json/JSONObject;`.
The registered entry at `0xb7e0` dispatches bounded stages through three local
thunks. This is an indirect state dispatcher, not evidence of a packer.

1. Preparation at `0xba9c` computes debugger/instrumentation risk, obtains the
   package name and opens `getSharedPreferences(packageName, 0)`.
2. Cached key `67`, if present, is passed to the native loader at `0x10e50`.
   Therefore cached execution precedes the decision whether to make a fresh request.
3. With no usable cached response, the request stage at `0xceac` creates a Java
   `URL`/`HttpURLConnection` for `https://dev.fest-drift.com/remote-config`, sets
   method `POST`, and uses `application/json; charset=utf-8`. The caller's JSON
   object is serialized via `toString()` and `getBytes("UTF-8")` and written to
   the connection output stream. Network operations use JNI into Java networking,
   not imported native sockets.
4. Response stage `0xeb6c` requires HTTP status 200, reads the stream using
   `InputStreamReader`/`BufferedReader`, constructs a JSONObject, and checks for
   the outer selector or package-named configuration. The loader path receives
   the **entire response string**, not a second DEX download URL.
5. `0x106c4` calls the native loader and stores the raw response with
   `SharedPreferences.Editor.putString("67", response).commit()`. Cache writing
   by itself is not proof that DEX execution succeeded; the loader's result is not
   the condition used to decide the cache commit.
6. Native parser `0x126d8` converts the response into a bounded parsed JSON tree,
   finds object member `67`, resolves fifteen numeric selectors from an ELF table,
   rejects duplicate recognized keys, and requires all fifteen values.
7. Array selector `474` is converted to bytes. Other fields supply class names,
   method names and JNI descriptors. The bytes must satisfy the native DEX
   validator `0x12fb4` before any class loader is instantiated.
8. The native loader resolves the selected loader class via `Class.forName`, gets
   the Activity's parent class loader, allocates a direct ByteBuffer and copies
   the validated bytes into it. It calls the chosen constructor with the buffer
   and parent, calls `loadClass`, constructs the returned payload class with a
   zero-argument constructor, then invokes the selected **instance** void method
   with the original Activity.

The native parser has a recursion-depth guard and a 192 MiB tracked allocation
budget. Its Java-string-to-UTF-8 conversion allows at most 64 MiB, rejects NUL and
invalid surrogate sequences. This limit is in the loader; the preceding line-read
accumulation is a separate allocation path.

## Response contract

The following is the statically recovered mapping, suitable for the known-benign
`ResponseEntry` fixture. The DEX itself remains in ignored artifacts/portable
fixture files rather than this report.

| Key inside object `67` | Role | Benign test value |
|---|---|---|
| `117` | Loader class, dotted Java name | `dalvik.system.InMemoryDexClassLoader` |
| `474` | DEX bytes | Unsigned integer array containing the complete benign DEX |
| `429` | Loader constructor descriptor | `(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V` |
| `650` | Activity parent-loader getter | `getClassLoader` |
| `279` | Parent-loader getter descriptor | `()Ljava/lang/ClassLoader;` |
| `50` | Class-loading method | `loadClass` |
| `249` | Class-loading descriptor | `(Ljava/lang/String;)Ljava/lang/Class;` |
| `180` | Payload class, dotted Java name | `com.apkdefense.fixture.webview.ResponseEntry` |
| `299` | Payload constructor descriptor | `()V` |
| `600` | Payload instance entry method | `run` |
| `604` | Payload entry descriptor | `(Landroid/app/Activity;)V` |
| `295` | Resolver class, JNI slash name | `java/lang/Class` |
| `154` | Static resolver method | `forName` |
| `598` | Static resolver descriptor | `(Ljava/lang/String;)Ljava/lang/Class;` |
| `4` | Constructor method name | `<init>` |

Use actual JSON strings for the fourteen string fields. The parser can serialize
certain non-string JSON values into field text, but they are unnecessary for the
proof and remain subject to length/identifier/signature checks. The DEX array
accepts integer values 0–255 and decimal strings whose parsed value is 0–255;
negative values and non-integer numeric types fail. This is an array, not Base64.
The expected byte count is **not** a separate server-controlled field.

## DEX size and structure checks

- Actual decoded length must be **112–33,554,432 bytes**, inclusive.
- Magic must be `dex\n` followed by `035`, `037`, `038`, `039`, `040` or `041`,
  followed by NUL; `036` is excluded.
- Header size must be 112, except version 041 requires 120.
- Endian tag must be `0x12345678`.
- For versions before 041, `header.file_size` must equal the actual array length.
- For 041, header file size must fit, container size must equal the full buffer,
  and header offset must be zero.
- Nonempty link, string/type/proto/field/method/class tables must start after the
  header and their count times entry size must fit the remaining bytes. Empty
  tables must have zero offsets. The data section and map list also receive bounds
  checks; map-item content is not fully validated here.
- This native function does not recompute the DEX Adler-32 checksum or SHA-1
  signature. Android's DEX implementation can perform additional checks later.

The existing 5,120-byte benign fixture satisfies this native contract. Appending
padding without correcting DEX header fields would fail the exact size check.
The proof must use the valid fixture bytes unchanged.

## Anti-analysis and persistence

The preflight inspects Java debugger state, ApplicationInfo flags,
`/proc/self/status` (`TracerPid:`), `LD_PRELOAD`, and `/proc/self/maps`.
Recovered map indicators include `frida`, `gum-js-loop`, `gadget`, `xposed`,
`lsposed`, `edxp`, `riru`, `zygisk`, `substrate`, `libhooker`, `sandhook`,
`shadowhook`. The implementation assigns weighted scores and suppresses fresh
network retrieval when the score reaches **80**, rather than rejecting every
indicator individually. Examples include connected debugger +70, waiting debugger
+60, debuggable flag +25, nonzero tracer +100 and nonempty preload +45, with
saturation. Several map indicators contribute through aggregate scoring.

No `ptrace`, `dlopen`, `dlsym`, `execve`, `system`, socket or connect import is
present. Native memory is allocated for decoded strings and response bytes, and
many buffers are zeroed before free. The anti-analysis checks do not establish an
emulator-specific rule; no device-model emulator check was identified in this
flow. Apparent lack of HTTP traffic should be investigated using both risk state
and cached configuration.

Cache file for this sample:
`/data/user/0/dev.tracebasinmoss.routepearl/shared_prefs/dev.tracebasinmoss.routepearl.xml`,
string entry `67`.

## Static extraction that survives selector changes

`scripts/family4_native.py` requires only Python, pyelftools and Capstone. It does
not run the sample, load a response pack, compile a tool or compare input hashes
against a known sample.

- Discover relocated descriptors structurally. Each contains fragment pointers,
  position-index arrays, length, three 64-bit mixing values, rotation bytes and a
  transform selector. Require bounded fragments and exact non-overlapping position
  coverage. All four observed transform modes are supported.
- Reconstruct the byte stream using the splitmix64-style mix and per-position
  rotate/add/XOR operations. These are string hiding, not evidence of standard
  payload encryption or cryptographic authentication.
- Locate a referenced table of fifteen distinct numeric selectors in the native
  JSON parser and its fifteen-element loop; recover the outer member literal from
  code. Neither the selector values nor their ELF addresses are built in.
- Find the caller of that parser and bind stack-backed parsed fields to actual
  JNI `FindClass`, `GetStaticMethodID`, `GetMethodID` and class-name-string
  conversion arguments. The single remaining field is checked against the parser's
  special array path. JNI role evidence is emitted with call-site addresses.
- Validate the DEX guard against its relocation-independent instruction template,
  retaining constants and branch topology. An altered or unrecognized guard is
  `needs_review`; it must not inherit assumed size limits.

Current support is deliberately bounded to this AArch64 topology and two-digit
outer-literal convention. Recompiled control-flow layouts, another ABI, another
string transform, changed JSON-parser storage or a new DEX guard can require an
additional reader model. The template is an implementation-pattern recognizer,
not a whole-app/lib hash allowlist and not a promise to support unseen changes.
Endpoint strings are decoded IOC candidates; independent native call-flow review
above establishes the request endpoint for the original sample.

## IOC candidates and detection implications

- `https://dev.fest-drift.com/remote-config` — native request URL.
- `dev.fest-drift.com` — candidate network indicator; no active probing performed.
- Native registered bridge descriptor `(Activity, JSONObject) -> JSONObject`,
  descriptor-fragment decoder, fifteen-key schema and direct-buffer loader flow
  — combined structural detection features, stronger than a mutable library name.

Do not classify an application as malicious from class loading or encrypted
strings alone. The useful finding is that remotely supplied bytes and invocation
metadata reach executable DEX, subject to the documented checks. Use runtime
positive/negative response trials to establish execution for the submitted app.
