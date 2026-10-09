# Family4 detection coverage

Date: 2026-10-09. Submitted app: 5555xBasin,
`dev.tracebasinmoss.routepearl` 1.0.5 (11). The delivered rule identifies the
observed ARM64 native implementation for review. The Python analyzer derives
the configurable DEX-loader contract from input bytes and supplies stronger
behavioral context. Neither finding alone establishes malicious intent or the
contents of an unobserved production DEX.

## Upstream evidence and candidates

Read [static triage](00_static_triage.md), [Java audit](01_code_audit.md), and
[native analysis](02_native_analysis.md). The Java startup path reaches a custom
native Activity/JSONObject entry; native analysis connects remote JSON to a
direct buffer, selectable class-loader constructor and Activity-taking instance
method. Its size and structure validator checks the supplied DEX before loading.
This detection work is static. Runtime trials are owned by the separate runtime
validation and are not implied by a YARA match.

| Surface | Candidate | Decision |
|---|---|---|
| Original extracted ARM64 ELF | Combined descriptor-decoder constant construction and DEX validator instructions | One conservative YARA rule, tested below |
| Original APK/split set or ELF, with Python analysis | Descriptor reconstruction, numeric-key table and JNI argument roles, recognized validator | Primary input-derived contract detector; use `scripts/analyze_family4_native.py` with `scripts/family4_native.py` |
| Network | Native POST URL and its exact host | IOC table and flat feed; alert/monitor, no blanket parent-domain blocking |
| Decompiled Java | Activity/JSONObject bridge, once flag, fallback game configuration | No Semgrep rule: these are legitimate patterns and omit the native loader's discriminating behavior |
| Shared SDKs and generic APIs | Adjust/AppsFlyer hosts, JNI_OnLoad, ByteBuffer, class loading, SplitMix constants alone | Rejected as standalone detections |

Files:

- `detections/yara/family4_native_loader.yar`
- `detections/network_iocs/family4.md`
- `detections/network_iocs/family4.txt`

## Original-byte anchors

The rule's evidence comes from **unmodified**
`work/family4/dev.tracebasinmoss.routepearl/native_libs/arm64-v8a/libz5555xbasin.so`,
SHA-256 `260e1aec4db63cea64f5f9486db3f639c9b4b5546099def8e1c50a593513b04c`.
The original split association is recorded in `native_libs/INDEX.tsv` and the
static triage. No appended decoded strings or reconstructed ELF is scanned.

| Anchor | Original ELF VA | Upstream meaning |
|---|---|---|
| `$descriptor_mix` | `0x13604`–`0x13618` | Interleaved immediate construction of the descriptor decoder's two SplitMix64 constants; native report, “Static extraction that survives selector changes” |
| `$dex_size` | `0x12fc0`–`0x12fd4` | Unsigned actual-byte-length guard, 112 through 33,554,432 inclusive; native report, “DEX size and structure checks” |
| `$dex_magic` | `0x12fd8`–`0x13000` | Four explicit byte comparisons against `dex\n` before version/header checks; same native finding |
| `$jni` | Dynamic symbol string | JNI entry context, not distinctive in isolation |

The ELF class, endianness and machine must be ELF64 little-endian AArch64, and
the extracted file must be below 32 MiB. All four anchors are required. Conditional
branch displacement nibbles/bytes are wildcarded; the condition code and opcode
remain fixed. Register assignments, instruction order and guard constants remain
fixed. The native library size bound is a scanning bound, separate from the DEX
payload size guard represented by the code.

A DEX verifier or packer could legitimately contain the validator pattern, and
a string-hiding library could legitimately contain the mixing constants. Requiring
their observed implementation combination reduces that ambiguity, but does not
make the match a maliciousness verdict. The rule is named `SUSP_` and is medium
confidence. It does not depend on this app's file hash, filename, package, domain,
response selectors or absolute code/data addresses.

## Actual validation

YARA-X CLI **1.20.0** and the installed legacy YARA Python scanner both matched
the original target. The authoring skill's linter returned no issues; atom analysis
reported good quality for all strings; `yr fmt --check` passed. YARA-X compilation
occurred as part of each successful scan. Commands from the workspace root:

```bash
yr scan detections/yara/family4_native_loader.yar work/family4/dev.tracebasinmoss.routepearl/native_libs/arm64-v8a/libz5555xbasin.so
scripts/venv_python scripts/yara_scan.py detections/yara work/family4/dev.tracebasinmoss.routepearl/native_libs/arm64-v8a/libz5555xbasin.so
scripts/venv_python .agents/skills/yara-rule-authoring/scripts/yara_lint.py --json detections/yara/family4_native_loader.yar
scripts/venv_python .agents/skills/yara-rule-authoring/scripts/atom_analyzer.py detections/yara/family4_native_loader.yar
yr fmt --check detections/yara/family4_native_loader.yar
```

The local corpus contained **25 SHA-256-distinct original ELFs**: one positive and
24 negatives. Fifteen negatives were ARM64; nine other-ABI inputs are expected
to fail the architecture condition and add no ARM64 specificity evidence.

Negative sources were the eight AndroidX/Adjust dependency ELFs from this app;
the distinct `libapp`, `libflutter`, `libdartjni`, datastore and signer libraries
from saved Drift/Family2 APK3; the Family1 `libsummitfjord.so`; and six known-benign
runtime-code fixture libraries (three ARM64, three x86_64). Dependencies shared
with the runtime-flow fixture were SHA-deduplicated. Other-family apps are
specificity controls, not goodware. This small dependency/fixture corpus is not
a clean-app false-positive rate.

Four separately labeled **synthetic, nonexecuted** ELF controls were also scanned:
adding 1000 to all fifteen numeric selectors retained the match; independently
corrupting one instruction in each of the three required code anchors removed
the match. These demonstrate selector independence and conjunction behavior,
not coverage of independently compiled variants or functioning mutated apps.

Input paths, hashes and scan outputs are saved under
`work/family4/detection_validation/{scans.json,synthetic-scans.json,legacy-scan.json,lint.json,atoms.txt,format.txt}`.
Only the report/rule/IOC files are tracked; originals and synthetic binaries remain
ignored. No sample or hash was uploaded.

## Deployment and limits

Extract every APK/split's native members before applying the ELF rule. Scanning
the compressed APK ZIP itself is unsupported. The rule is ARM64-only and tied to
the observed compiler output: instruction scheduling, register changes, revised
guards, another decoder, packing, or another ABI may evade it. A renamed/re-signed
app or changed selectors need not evade it if the native implementation remains
intact, but only the original build and synthetic selector control were tested.

For a new app with little prior knowledge, pass its complete split set to the
Family4 Python analyzer. It reconstructs descriptor text, discovers selector
values, binds them to JNI roles and verifies the supported validator shape;
unknown layouts remain `needs_review`. Its status is a conditional static
capability finding. Validate a generated benign response separately before
claiming runtime execution. Do not turn YARA matches or JNI/string anchors into
assumed response fields.

The IOC URL `https://dev.fest-drift.com/remote-config` is recovered from descriptor
VA `0x2e2b0` and connected to the POST network stage by the native review. Host
rotation evades the IOC feed. DNS/SNI can generally observe the host only; exact
method/path monitoring requires authorized HTTP visibility. No IP, JA3, production
payload, or backend selection criteria is supplied by this detection work.
