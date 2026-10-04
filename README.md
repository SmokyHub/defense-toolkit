# APK Defense — three independent components

Copy only the folder you need. Each also has its own ZIP next to this directory.

- **family1/**: corrected `elf_plaintext_reconstructor.py`, `elf_recovery.py`, requirements and instructions.
- **family2/**: APK/ZIP analyzer, Dalvik and Flutter discovery workers, optional reviewed Flutter profiles, requirements and instructions. Automatic Flutter contracts for APK1–APK3 require a compatible Blutter build with the included semantic metadata extension; no application profiles are required.
- **website/**: Runtime Code website/CLI/TUI source, launcher, packs, and the benign **lab.runtimecode.flow** test APK with its matching pack.

There is no combined installer or analyzer. No emulator, Frida distribution/server, ADB,
Python environment or dependency wheelhouse is shipped. Install the requirements for the
component you use. The website's live instrumentation still needs separately installed Frida
and ADB; viewing saved evidence does not. See each folder's README.

Client APKs and saved captures are excluded. The only included APK is the lab's benign
runtime-flow test fixture. `python3 verify.py` checks all files in this complete directory
against `MANIFEST.json`; each separate ZIP also has a SHA-256 sidecar.
