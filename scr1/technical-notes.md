# Native plaintext reconstructor regression report

Date: 2026-09-26. Scope: the two user-provided `apks/family1/` samples.

For a step-by-step explanation of finding constructors, decoder functions, keys,
plaintext, and indirect call targets, see the [analyst walkthrough](ANALYST_WALKTHROUGH.md).

Both main libraries now yield `android/content/res/AssetManager`, `getAssets`,
`dalvik/system/InMemoryDexClassLoader`, `getClassLoader`, and
`java/lang/ClassLoader` without executing JNI_OnLoad. The exact asset method is
`getAssets`, rather than a literal capitalized `GetAsset`.

## Cause and evidence

The supplied script had a missing closing parenthesis in its CLI definition.
After correcting that for baseline runs, APK2's existing XOR fallback recovered
the requested references, while APK1's did not.

APK1's observed constructor decoder uses a 32-byte key for game-related strings.
The old automatic selection retains only the most frequently observed key.
That key recovers some HTTP-related strings, but misses the loader references,
which use a **different 32-byte key**, stored at file offset `0x2a4f00`.
The recovered loader key independently decodes four full Java class names;
`getAssets` and `getClassLoader` are additional recovered strings, not discovery
anchors. APK2's loader references use a one-byte XOR key.

APK1's first constructor executes 1,383,427 instructions, versus 13,841 for APK2.
Expensive per-instruction tracing can exhaust the old wall-clock timeout before
APK1's constructor returns. Caching instruction reads and gating AES disassembly
allow all four constructors to finish with the default budget in the tested
environment. Completion remains machine-dependent and is reported explicitly.

**The originals did not require ELF header repair.** Both have readable section
tables, program headers, `PT_DYNAMIC`, and constructor metadata. This investigation
does not establish an OLLVM version or structural corruption in these originals.
The old repair's unconditional `p_filesz = p_memsz` is incorrect for ordinary BSS:
ELF requires that the excess memory be zero-filled, rather than copied from later
file bytes. See the [ELF program-header specification](https://gabi.xinuos.com/elf/07-pheader.html).

| Library | AssetManager class file offset | getAssets file offset | InMemoryDexClassLoader class file offset | Loader key length |
| --- | --- | --- | --- | --- |
| APK1 `libcard86.so` | `0x2a4a9e` | `0x2a4abf` | `0x2a4b8a` | 32 bytes |
| APK2 `libsummitfjord.so` | `0x29e486` | `0x29e4a7` | `0x29e572` | 1 byte |

Original library SHA-256 values (local computation only):

- APK1: `9d79c5563dd7a57530d1d62816b66b67f111c3f5d6e0c2d95533c76c2aa8d380`
- APK2: `d2effd8d38449c13fe0e8f0b40e631d4a244b690c2074c56b17f44532094c616`

These references are **static decoded string evidence**. Constructor execution
alone decrypted game-related strings in the tested libraries; it did not reach
the loader references. No claim is made that the asset-loading or class-loading
paths executed. These APIs also exist in legitimate apps; family classification
should use the user's wider sample context.

## Changes

- Retained the existing CLI, emulation, crypto profiles, transient capture,
  explicit keys, memory patches, offsets, and analysis ELF output.
- Added `scripts/elf_recovery.py` for bounded ELF parsing and multiple-key XOR
  discovery. Key discovery requires two non-overlapping full plaintext anchors,
  plus a stored multibyte key or sufficient repeated-key constraints. It searches
  the original file and does not depend on guessed section names or offsets.
- Default discovery lengths: `1,2,4,8,16,32`. Extend with `--xor-key-lengths` and
  `--xor-anchor`. Limits bound candidate counts; arbitrary encryption is not
  automatically supported.
- Parse constructors, REL/RELA relocations, symbols, and RELR from dynamic
  metadata; retain optional section metadata as a fallback. A broken section
  table is removed only in an output-side loader copy. Sectionless loading and
  relocation repair are tested independently of static XOR discovery.
- `--auto-fix-headers` now extends a truncated segment only when allocated,
  file-backed sections corroborate the exact mapping and bounds. It preserves
  `SHT_NOBITS`/BSS. A no-op returns the original path and creates no copy.
- Added `--static-only`, `signals.json`, evidence offsets/key fingerprints,
  constructor completion records, runtime-failure reporting, and
  `--require-signals` (exit 2 if any requested reference group is missing).
- JNI_OnLoad is explicitly opt-in, **including with `--blind`**. Use
  `--execute-jni-onload --fake-jni` to request the old blind-mode JNI step.
  `--skip-jni-onload` continues to suppress dedicated JNI options.
- `--no-discover-xor-keys` disables the new static discovery stage for baseline
  comparisons. The legacy `--auto-xor-from-transform` path remains available.

All changes are confined to the script and its helper; Qiling internals were not
patched. Tested against [Qiling 1.4.6's ELF loader](https://github.com/qilingframework/qiling/blob/1.4.6/qiling/loader/elf.py).

## Reproduce

The prepared Python environment is `work/reconstructor-venv`. To recreate it:

```bash
python3 -m venv work/reconstructor-venv
work/reconstructor-venv/bin/pip install -r scripts/requirements-reconstructor.txt
```

Fast reference recovery, with no guest execution:

```bash
work/reconstructor-venv/bin/python scripts/elf_plaintext_reconstructor.py \
  work/family1_apk1/native_libs/arm64-v8a/libcard86.so \
  --static-only --require-signals \
  --out-dir work/family1_apk1/reconstruction-static

work/reconstructor-venv/bin/python scripts/elf_plaintext_reconstructor.py \
  work/family1_apk2/native_libs/arm64-v8a/libsummitfjord.so \
  --static-only --require-signals \
  --out-dir work/family1_apk2/reconstruction-static
```

Omit `--static-only` to include constructors. `--rootfs PATH` is optional: these
samples worked with the empty rootfs created in the output directory and the
script's import models. Libraries needing real dependency implementations may
require an Android rootfs. The supplied rootfs and import models influence runtime
coverage; Qiling is not a complete Android process environment.

For a focused text output, add
`--keywords AssetManager,GetAsset,ClassLoader`.

Inspect `signals.json` for the three reference groups and their source offsets;
`manifest.json` separately records constructor completion and runtime errors.
`strings_normalised.txt` is convenient for reading; `strings.jsonl` retains raw
evidence. XOR phase scans do not patch ambiguous bytes into the original file.
The analysis ELF's optional appended overlay includes statically recovered
strings and must not be treated as proof of runtime decryption.

## Validation

Python 3.12, Qiling 1.4.6, Unicorn 2.1.4, pyelftools 0.33, Capstone 5.0.9.

```bash
work/reconstructor-venv/bin/python -m unittest discover -s scripts/tests -v
```

16 synthetic tests pass, covering ELF32/64, both byte orders in parsing/repair,
invalid bounds, stripped/damaged section tables, BSS preservation, corroborated
truncation repair, multiple/rotated XOR keys, false-positive controls, and actual
AArch64 constructor execution with dynamic RELA and RELR while static discovery
is disabled.

Local sample checks:

| Run | Requested references | Constructors | JNI_OnLoad |
| --- | --- | --- | --- |
| APK1 original | All recovered | 4/4 returned | Not executed |
| APK2 original | All recovered | 4/4 returned | Not executed |
| APK1 section table removed | All recovered | 4/4 returned | Not executed |
| APK1 section offset corrupted | All recovered | 4/4 returned | Not executed |
| APK2 section table removed | All recovered | 4/4 returned | Not executed |
| APK2 section offset corrupted | All recovered | 4/4 returned | Not executed |
| APK2 legacy XOR, new discovery disabled | All recovered | 4/4 returned | Not executed |

Results: `work/family1_apk{1,2}/reconstruction/`,
`work/family1_apk{1,2}/regression-{sectionless,bad-sections}/`,
`work/family1_apk2/regression-legacy-xor/`, and
`work/reconstructor-validation.json`. Mutated samples exist only under ignored
`work/`; original input hashes were preserved. No sample or hash was sent to
third-party reputation services, and no backend or device was contacted.

No older samples were available, so compatibility beyond these samples is
supported by synthetic regressions rather than a tested historical corpus.
Malformed program mappings with no trustworthy recovery evidence are rejected.
Android APS2 packed relocations and arbitrary/custom ciphers remain unsupported;
manual AArch64 relocation repair is not a general ARM32 relocation engine.
Static discovery cannot recover a key supplied only by an unavailable backend.
