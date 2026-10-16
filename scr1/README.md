# Family1 — native plaintext reconstructor

This component works independently of family2 and the website. Python 3.12 on Linux is
the tested environment. Install this tool's Python dependencies:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Run the corrected Python script against an extracted native library:

```bash
.venv/bin/python elf_plaintext_reconstructor.py /path/libtarget.so \
  --require-signals --out-dir results/new-case
```

Keep `elf_recovery.py` beside the main script. The helper provides bounded ELF parsing
and multiple-key XOR recovery, both before and after bounded constructor emulation.
This includes lazy string pools whose keys and ciphertext are prepared during initialization.
Input is an original `.so`, not an APK/ZIP.
The original is preserved; outputs include recovered strings, evidence metadata and an analysis ELF.

Add `--static-only` for a faster pass that does not execute guest code. It cannot recover
strings that need constructor preparation. The command above includes constructor emulation;
some apps require a separately supplied Android rootfs with `--rootfs`. JNI_OnLoad is separately
opt-in. No rootfs or emulator is bundled. The output is an analysis artifact, not a claim of a
complete or runnable app. See `technical-notes.md` for fixes and limits (its paths describe the
original lab layout; use the flat commands above in this distribution).

`strings.txt` shows file offsets, ELF virtual addresses and recovery stages.
`strings.jsonl` additionally identifies the input library and its SHA-256 on each record.
`signals.json` groups AssetManager, getAssets and ClassLoader references; `manifest.json`
records constructor completion and corroborating key evidence. `post-init-xor` means
offline decoding of constructor-prepared bytes, not execution of the classloader.
`--no-discover-xor-keys` disables both corroborated XOR discovery passes.
Use `--print-all-strings` to include strings outside the default keyword filter.
