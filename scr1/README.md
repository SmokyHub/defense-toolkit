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
  --static-only --require-signals --out-dir results/new-case
```

Keep `elf_recovery.py` beside the main script. The helper provides bounded ELF parsing
and multiple-key XOR recovery. Input is an original `.so`, not an APK/ZIP.
The original is preserved; outputs include recovered strings, evidence metadata and an analysis ELF.

`--static-only` does not execute guest code. Omit it to opt into bounded constructor emulation;
some apps require a separately supplied Android rootfs with `--rootfs`. JNI_OnLoad is separately
opt-in. No rootfs or emulator is bundled. The output is an analysis artifact, not a claim of a
complete or runnable app. See `technical-notes.md` for fixes and limits (its paths describe the
original lab layout; use the flat commands above in this distribution).
