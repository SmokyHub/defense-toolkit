#!/usr/bin/env python3
"""
Best-effort Android native-library plaintext reconstructor.

Recovers constructor-time changes under Qiling and independently discovers
multiple corroborated periodic-XOR keys. PT_DYNAMIC supplies constructors and
relocations even when section headers are stripped or invalid. Original input
bytes are never modified; any loader repair is an analysis copy in --out-dir.

Quick reference recovery (no guest execution):
    python elf_plaintext_reconstructor.py libtarget.so --static-only \
        --out-dir work/recovery --require-signals

Constructor execution plus reference recovery:
    python elf_plaintext_reconstructor.py libtarget.so \
        --rootfs /path/to/rootfs --out-dir work/recovery --require-signals

JNI_OnLoad is opt-in, including in --blind mode: --execute-jni-onload --fake-jni.
Existing symbol, offset, memory-patch, crypto-profile and explicit XOR options
remain available. An empty rootfs is created if omitted; dependency-backed
execution may require a supplied Android rootfs and additional import models.

The output ELF is an ANALYSIS artifact. Static XOR sweeps are labeled as such;
only observed memory changes patch file-backed data. The optional string overlay
also includes speculative/static results and is not a loadable replacement for
the original library. signals.json preserves evidence sources and file offsets;
manifest.json reports incomplete execution independently from string recovery.

Tested dependencies: scripts/requirements-reconstructor.txt.
Usage, limitations, and the sample regression results are documented in
reports/family1_reconstructor/README.md. Analyze only authorized samples.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import io
import json
import os
import re
import shutil
import struct
import sys
import time
import traceback
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Sequence

from elf_recovery import ElfImage, XOR_ANCHORS, discover_xor_keys, xor_bytes

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
except ImportError as exc:
    raise SystemExit(
        "pyelftools is required. Install it with: "
        "python3 -m pip install pyelftools"
    ) from exc

try:
    from qiling import Qiling
    from qiling.const import QL_INTERCEPT, QL_VERBOSE
except ImportError as exc:
    raise SystemExit(
        "Qiling is required. Install it with: "
        "python3 -m pip install qiling"
    ) from exc

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    CAPSTONE_AVAILABLE = True
except ImportError:
    Cs = None  # type: ignore[assignment]
    CS_ARCH_ARM64 = 0
    CS_MODE_ARM = 0
    CAPSTONE_AVAILABLE = False


DEFAULT_KEYWORDS = (
    "DexClassLoader,"
    "InMemoryDexClassLoader,"
    "BaseDexClassLoader,"
    "PathClassLoader,"
    "ClassLoader,"
    "AssetManager,"
    "AAssetManager,"
    "GetAsset,"
    "assets,"
    "ByteBuffer,"
    "decrypt,"
    "decryption,"
    "encrypted,"
    "aeskey,"
    "cipher,"
    "json,"
    "http://,"
    "https://,"
    "url,"
    "dex\\n"
)

ELF_MAGIC = b"\x7fELF"
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
DEX_MAGICS = (
    b"dex\n035\x00",
    b"dex\n037\x00",
    b"dex\n038\x00",
    b"dex\n039\x00",
    b"dex\n040\x00",
    b"dex\n041\x00",
)
CDEX_MAGIC = b"cdex001\x00"

PAGE_SIZE = 0x1000

AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)
AES_RCON = bytes.fromhex("01020408102040801b36")
CHACHA_CONSTANTS = (b"expand 32-byte k", b"expand 16-byte k")
ARM64_AES_MNEMONICS = {"aese", "aesd", "aesmc", "aesimc"}


@dataclasses.dataclass(frozen=True)
class CryptoTransformProfile:
    """Calling-convention description for a crypto/buffer transform API."""

    name: str
    patterns: tuple[str, ...]
    algorithm: str
    output_reg: int
    input_reg: Optional[int] = None
    length_reg: Optional[int] = None
    length_pointer_reg: Optional[int] = None
    capacity_reg: Optional[int] = None
    fixed_length: Optional[int] = None
    key_regs: tuple[int, ...] = ()
    iv_regs: tuple[int, ...] = ()
    context_regs: tuple[int, ...] = ()
    mode_reg: Optional[int] = None
    default_capacity: int = 0x1000


BUILTIN_CRYPTO_PROFILES: tuple[CryptoTransformProfile, ...] = (
    # OpenSSL/BoringSSL low-level interfaces.
    CryptoTransformProfile(
        "openssl-aes-cbc", (r"(^|_)AES_cbc_encrypt$",), "AES-CBC",
        output_reg=1, input_reg=0, length_reg=2,
        key_regs=(3,), iv_regs=(4,), mode_reg=5,
    ),
    CryptoTransformProfile(
        "openssl-aes-ctr", (r"AES_ctr128_encrypt$", r"CRYPTO_ctr128_encrypt$"),
        "AES-CTR", output_reg=1, input_reg=0, length_reg=2,
        key_regs=(3,), iv_regs=(4,),
    ),
    CryptoTransformProfile(
        "openssl-aes-ecb", (r"(^|_)AES_ecb_encrypt$",), "AES-ECB",
        output_reg=1, input_reg=0, fixed_length=16,
        key_regs=(2,), mode_reg=3,
    ),
    CryptoTransformProfile(
        "openssl-rc4", (r"(^|_)RC4$",), "RC4",
        output_reg=3, input_reg=2, length_reg=1,
        context_regs=(0,),
    ),
    CryptoTransformProfile(
        "boringssl-chacha20",
        (r"CRYPTO_chacha_20$", r"ChaCha20_ctr32$", r"chacha20_ctr32$"),
        "ChaCha20", output_reg=0, input_reg=1, length_reg=2,
        key_regs=(3,), iv_regs=(4,),
    ),

    # OpenSSL/BoringSSL EVP interfaces. outl is an int* written on return.
    CryptoTransformProfile(
        "evp-decrypt-update",
        (r"EVP_DecryptUpdate$", r"EVP_CipherUpdate$", r"EVP_EncryptUpdate$"),
        "EVP cipher update", output_reg=1, input_reg=3,
        length_pointer_reg=2, capacity_reg=4, context_regs=(0,),
    ),
    CryptoTransformProfile(
        "evp-decrypt-final",
        (r"EVP_DecryptFinal_ex$", r"EVP_CipherFinal_ex$", r"EVP_EncryptFinal_ex$"),
        "EVP cipher final", output_reg=1,
        length_pointer_reg=2, context_regs=(0,), default_capacity=0x1000,
    ),

    # mbedTLS.
    CryptoTransformProfile(
        "mbedtls-aes-cbc", (r"mbedtls_aes_crypt_cbc$",), "AES-CBC",
        output_reg=5, input_reg=4, length_reg=2,
        context_regs=(0,), iv_regs=(3,), mode_reg=1,
    ),
    CryptoTransformProfile(
        "mbedtls-aes-ctr", (r"mbedtls_aes_crypt_ctr$",), "AES-CTR",
        output_reg=6, input_reg=5, length_reg=1,
        context_regs=(0,), iv_regs=(3, 4),
    ),
    CryptoTransformProfile(
        "mbedtls-aes-ecb", (r"mbedtls_aes_crypt_ecb$",), "AES-ECB",
        output_reg=3, input_reg=2, fixed_length=16,
        context_regs=(0,), mode_reg=1,
    ),
    CryptoTransformProfile(
        "mbedtls-aes-xts", (r"mbedtls_aes_crypt_xts$",), "AES-XTS",
        output_reg=5, input_reg=4, length_reg=2,
        context_regs=(0,), iv_regs=(3,), mode_reg=1,
    ),
    CryptoTransformProfile(
        "mbedtls-chacha20", (r"mbedtls_chacha20_(?:crypt|update)$",),
        "ChaCha20", output_reg=3, input_reg=2, length_reg=1,
        context_regs=(0,),
    ),
    CryptoTransformProfile(
        "mbedtls-arc4", (r"mbedtls_arc4_crypt$",), "RC4",
        output_reg=3, input_reg=2, length_reg=1,
        context_regs=(0,),
    ),

    # libsodium-style one-shot ChaCha/XChaCha functions.
    CryptoTransformProfile(
        "libsodium-chacha-xor",
        (r"crypto_stream_(?:x?chacha20|chacha20_ietf)_xor$",),
        "ChaCha20", output_reg=0, input_reg=1, length_reg=2,
        iv_regs=(3,), key_regs=(4,),
    ),
    CryptoTransformProfile(
        "libsodium-chacha-xor-ic",
        (r"crypto_stream_(?:x?chacha20|chacha20_ietf)_xor_ic$",),
        "ChaCha20", output_reg=0, input_reg=1, length_reg=2,
        iv_regs=(3,), key_regs=(5,), mode_reg=4,
    ),
)


@dataclasses.dataclass(frozen=True)
class LoadSegment:
    index: int
    virtual_address: int
    file_offset: int
    file_size: int
    memory_size: int
    flags: int
    alignment: int

    @property
    def va_end(self) -> int:
        return self.virtual_address + self.memory_size

    @property
    def file_va_end(self) -> int:
        return self.virtual_address + self.file_size


@dataclasses.dataclass
class ElfMetadata:
    path: Path
    elf_class: int
    little_endian: bool
    machine: str
    entrypoint: int
    load_segments: list[LoadSegment]
    minimum_load_va: int
    dt_init: Optional[int]
    init_array_va: Optional[int]
    init_array_size: int
    symbols: dict[str, int]
    diagnostics: list[str] = dataclasses.field(default_factory=list)

    @property
    def pointer_size(self) -> int:
        return 8 if self.elf_class == 64 else 4


@dataclasses.dataclass(frozen=True)
class CandidateString:
    text: str
    encoding: str
    source: str
    runtime_address: Optional[int] = None
    elf_va: Optional[int] = None
    file_offset: Optional[int] = None
    function: Optional[str] = None
    transient: bool = False

    def key(self) -> tuple[Any, ...]:
        return (
            self.text,
            self.encoding,
            self.source,
            self.runtime_address,
            self.elf_va,
            self.file_offset,
            self.function,
            self.transient,
        )


@dataclasses.dataclass
class FunctionTarget:
    name: str
    elf_va: int
    arguments: tuple[int, ...] = ()


@dataclasses.dataclass
class TransformBufferProbe:
    pointer_register: int
    length_register: int
    pointer: int
    length: int
    before: bytes
    actual_length_pointer: Optional[int] = None
    actual_length_size: int = 4
    input_pointer: Optional[int] = None
    profile_name: Optional[str] = None


@dataclasses.dataclass
class TransformFrame:
    target_runtime: int
    target_elf_va: int
    caller_runtime: int
    return_address: int
    arguments: tuple[int, ...]
    probes: list[TransformBufferProbe]
    key_probes: dict[int, bytes]
    key_probe_roles: dict[int, str] = dataclasses.field(default_factory=dict)
    target_name: Optional[str] = None
    profile_name: Optional[str] = None
    algorithm: Optional[str] = None


class IntervalSet:
    """Small interval collector with lazy merging."""

    def __init__(self) -> None:
        self._raw: list[tuple[int, int]] = []

    def add(self, start: int, size: int) -> None:
        if size <= 0:
            return
        self._raw.append((start, start + size))

    def clear(self) -> None:
        self._raw.clear()

    def __bool__(self) -> bool:
        return bool(self._raw)

    def merged(self, gap: int = 0) -> list[tuple[int, int]]:
        if not self._raw:
            return []

        items = sorted(self._raw)
        output: list[list[int]] = []

        for start, end in items:
            if not output or start > output[-1][1] + gap:
                output.append([start, end])
            else:
                output[-1][1] = max(output[-1][1], end)

        return [(start, end) for start, end in output]


class JsonlWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._stream = path.open("w", encoding="utf-8")

    def write(self, record: dict[str, Any]) -> None:
        self._stream.write(json.dumps(record, sort_keys=True) + "\n")
        self._stream.flush()

    def close(self) -> None:
        self._stream.close()


def parse_int(value: str) -> int:
    return int(value, 0)


def align_down(value: int, alignment: int = PAGE_SIZE) -> int:
    return value & ~(alignment - 1)


def align_up(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def parse_key_value(items: Sequence[str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"Expected KEY=VALUE, got: {item!r}")
        key, value = item.split("=", 1)
        output[key] = value
    return output


def parse_memory_patch(spec: str) -> tuple[int, bytes]:
    try:
        address_text, hex_text = spec.split(":", 1)
        address = int(address_text, 0)
        data = bytes.fromhex(hex_text)
    except Exception as exc:
        raise argparse.ArgumentTypeError(
            "Memory patch must be ELF_VA:HEXBYTES, e.g. "
            "0x1f5000:00112233"
        ) from exc

    if not data:
        raise argparse.ArgumentTypeError("Memory patch cannot be empty")
    return address, data


def parse_stub(spec: str) -> tuple[str, int]:
    try:
        name, return_text = spec.split("=", 1)
        return name, int(return_text, 0)
    except Exception as exc:
        raise argparse.ArgumentTypeError(
            "API/syscall stub must be NAME=RETURN_VALUE"
        ) from exc


def parse_call_spec(spec: str) -> tuple[str, tuple[int, ...]]:
    """
    Syntax:
        symbol
        symbol:0x1,0x2
    """
    if ":" not in spec:
        return spec, ()

    name, arg_text = spec.split(":", 1)
    args = tuple(int(part.strip(), 0) for part in arg_text.split(",") if part.strip())
    return name, args


def parse_named_address(spec: str) -> tuple[str, int]:
    try:
        name, address_text = spec.split("=", 1)
        return name, int(address_text, 0)
    except Exception as exc:
        raise argparse.ArgumentTypeError(
            "Expected NAME=ADDRESS, e.g. INIT_0=0x1abcde"
        ) from exc


def read_elf_metadata(path: Path) -> ElfMetadata:
    image = ElfImage(path.read_bytes())
    diagnostics = []
    if image.section_error:
        diagnostics.append(f"Ignoring invalid section table: {image.section_error}")
    data = image.without_sections() if image.section_error else image.data
    elf = ELFFile(io.BytesIO(data))
    loads = [LoadSegment(p.index, p.va, p.offset, p.filesz, p.memsz, p.flags, p.align)
             for p in image.programs if p.type == 1]
    dt_init = image.dynamic.get(12)
    init_va = image.dynamic.get(25)
    init_size = image.dynamic.get(27, 0)
    symbols: dict[str, int] = {}
    try:
        # DynamicSegment works without section headers (DT_HASH/DT_GNU_HASH).
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_DYNAMIC':
                for symbol in segment.iter_symbols():
                    if symbol.name and symbol['st_value']:
                        symbols.setdefault(symbol.name, int(symbol['st_value']))
    except Exception as error:
        diagnostics.append(f"Dynamic symbols incomplete: {error}")
    try:
        for section_name in ('.dynsym', '.symtab'):
            section = elf.get_section_by_name(section_name)
            if section is not None:
                for symbol in section.iter_symbols():
                    if symbol.name and symbol['st_value']:
                        symbols.setdefault(symbol.name, int(symbol['st_value']))
        section = elf.get_section_by_name('.init_array')
        if section is not None and init_va is None:
            init_va, init_size = int(section['sh_addr']), int(section['sh_size'])
        dynamic = elf.get_section_by_name('.dynamic')
        if dynamic is not None and not image.dynamic:
            for tag in dynamic.iter_tags():
                if tag.entry.d_tag == 'DT_INIT':
                    dt_init = int(tag.entry.d_val)
                elif tag.entry.d_tag == 'DT_INIT_ARRAY':
                    init_va = int(tag.entry.d_val)
                elif tag.entry.d_tag == 'DT_INIT_ARRAYSZ':
                    init_size = int(tag.entry.d_val)
    except Exception as error:
        diagnostics.append(f"Optional section metadata incomplete: {error}")
    if init_size > 1024 * 1024 or init_size % image.word:
        diagnostics.append('Ignoring invalid/oversized init array')
        init_va, init_size = None, 0
    elif init_va is not None and not any(
        seg.virtual_address <= init_va and init_va + init_size <= seg.va_end for seg in loads
    ):
        diagnostics.append('Ignoring init array outside PT_LOAD memory')
        init_va, init_size = None, 0
    if any(tag in image.dynamic for tag in (0x6000000f, 0x60000011)):
        diagnostics.append('Android APS2 packed relocations are not repaired by this script')
    return ElfMetadata(path, image.bits, image.endian == '<', str(elf.get_machine_arch()),
                       image.entry, loads, min(align_down(p.virtual_address) for p in loads),
                       dt_init, init_va, init_size, symbols, diagnostics)


def va_to_file_offset(
    metadata: ElfMetadata,
    elf_va: int,
) -> Optional[int]:
    for segment in metadata.load_segments:
        if (
            segment.virtual_address
            <= elf_va
            < segment.virtual_address + segment.file_size
        ):
            return (
                segment.file_offset
                + elf_va
                - segment.virtual_address
            )
    return None


def segment_for_va(
    metadata: ElfMetadata,
    elf_va: int,
) -> Optional[LoadSegment]:
    for segment in metadata.load_segments:
        if segment.virtual_address <= elf_va < segment.va_end:
            return segment
    return None


def safe_read(
    ql: Qiling,
    address: int,
    size: int,
    *,
    page_size: int = PAGE_SIZE,
) -> bytes:
    """Read a region page by page, filling unreadable bytes with zero."""
    if size <= 0:
        return b""

    output = bytearray(size)
    offset = 0

    while offset < size:
        current = address + offset
        chunk_size = min(
            page_size - (current & (page_size - 1)),
            size - offset,
        )
        try:
            output[offset:offset + chunk_size] = bytes(
                ql.mem.read(current, chunk_size)
            )
        except Exception:
            pass
        offset += chunk_size

    return bytes(output)


def extract_ascii_strings(
    data: bytes,
    minimum: int,
) -> Iterator[tuple[int, str, str]]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    for match in pattern.finditer(data):
        raw = match.group()
        try:
            text = raw.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            text = raw.decode("ascii", errors="replace")
            encoding = "ascii"
        yield match.start(), text, encoding


def extract_utf16le_strings(
    data: bytes,
    minimum: int,
) -> Iterator[tuple[int, str, str]]:
    # Printable basic-Latin characters separated by zero bytes.
    pattern = re.compile(
        rb"(?:(?:[\x20-\x7e]\x00)){%d,}" % minimum
    )
    for match in pattern.finditer(data):
        raw = match.group()
        try:
            text = raw.decode("utf-16le")
        except UnicodeDecodeError:
            continue
        yield match.start(), text, "utf-16le"


def string_matches(
    text: str,
    keyword_regex: Optional[re.Pattern[str]],
    print_all: bool,
) -> bool:
    if print_all:
        return True
    if keyword_regex is None:
        return True
    return keyword_regex.search(text) is not None


JAVA_INTERNAL_NAME_PATTERN = re.compile(
    r"(?:dalvik|java|javax|android|androidx|org|com|net|io|kotlin|sun)/"
    r"[A-Za-z0-9_$]+(?:/[A-Za-z0-9_$]+)+"
)
URL_PATTERN = re.compile(
    r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+"
)
JNI_SIGNATURE_PATTERN = re.compile(
    r"\(*L(?:dalvik|java|javax|android|androidx|org|com|net|io|kotlin|sun)/"
    r"[A-Za-z0-9_$/]+;[^\x00\r\n\t ]*"
)


def normalise_signal_text(text: str) -> str:
    """Trim common printable prefix/suffix artefacts without altering raw evidence."""
    signature = JNI_SIGNATURE_PATTERN.search(text)
    if signature:
        return signature.group(0)
    internal = JAVA_INTERNAL_NAME_PATTERN.search(text)
    if internal:
        return internal.group(0)
    url = URL_PATTERN.search(text)
    if url:
        return url.group(0).rstrip(".,;:)]}")
    return text.strip("\x00\r\n\t ")


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(
        1
        for value in data
        if value in (9, 10, 13) or 0x20 <= value <= 0x7E
    )
    return printable / len(data)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Reconstructor:
    def __init__(
        self,
        args: argparse.Namespace,
        metadata: ElfMetadata,
        output_dir: Path,
    ) -> None:
        self.args = args
        self.metadata = metadata
        self.output_dir = output_dir
        self.external_dir = output_dir / "external"
        self.carved_dir = output_dir / "carved"
        self.transform_dir = output_dir / "transform_outputs"
        self.key_dir = output_dir / "key_candidates"
        self.external_dir.mkdir(parents=True, exist_ok=True)
        self.carved_dir.mkdir(parents=True, exist_ok=True)
        self.transform_dir.mkdir(parents=True, exist_ok=True)
        self.key_dir.mkdir(parents=True, exist_ok=True)

        self.events = JsonlWriter(output_dir / "events.jsonl")
        self.strings_jsonl = JsonlWriter(output_dir / "strings.jsonl")
        self.transforms_jsonl = JsonlWriter(output_dir / "transforms.jsonl")

        self.original = bytearray(metadata.path.read_bytes())
        self.input_sha256 = sha256_hex(bytes(self.original))
        self.patched = bytearray(self.original)
        self.loader_path = metadata.path
        self.runtime_error: Optional[str] = None
        self.signals_complete = False
        self.function_results: list[dict[str, Any]] = []
        self.xor_discoveries: list[dict[str, Any]] = []

        self.ql: Optional[Qiling] = None
        self.module_base = 0
        self.load_bias = 0
        self.stack_pointer = 0

        self.initial_snapshot: dict[int, bytes] = {}
        self.current_snapshot: dict[int, bytes] = {}

        self.module_dirty = IntervalSet()
        self.external_dirty = IntervalSet()
        self.pending_write_ranges = IntervalSet()

        self.candidates: OrderedDict[tuple[Any, ...], CandidateString] = (
            OrderedDict()
        )
        self.transient_seen: set[tuple[int, str]] = set()

        self.active_function: Optional[str] = None
        self.instruction_count = 0
        self.last_code_address = 0
        self.start_monotonic = time.monotonic()

        self.transform_stack: list[TransformFrame] = []
        self.transform_stats: dict[int, Counter[str]] = defaultdict(Counter)
        self.transform_key_pointers: dict[int, Counter[int]] = defaultdict(Counter)
        self.return_sentinel: Optional[int] = None
        self.return_sentinel_hit = False
        self.fake_jni_vm: Optional[int] = None

        # Qiling 1.4.6 compatibility and relocation-repair state.
        self.baseline_registers: dict[str, int] = {}
        self.import_trampolines: dict[str, int] = {}
        self.import_trampoline_region: Optional[int] = None
        self.import_trampoline_next = 0
        self.import_properties = parse_key_value(args.android_property)
        self.relocation_repairs = 0
        self.import_repairs = 0
        self.heuristic_pointer_repairs = 0
        self.auto_xor_key_pointer: Optional[int] = None
        self.auto_xor_key_target: Optional[int] = None
        self.auto_xor_key_hits: int = 0
        self.auto_xor_key_pointers: dict[int, Counter[int]] = defaultdict(Counter)

        self.address_labels: dict[int, str] = {}
        self.symbols_by_va: dict[int, list[str]] = defaultdict(list)
        self.crypto_profiles: list[CryptoTransformProfile] = list(
            BUILTIN_CRYPTO_PROFILES
        )
        self.inline_crypto_countdown = 0
        self.inline_crypto_hits = 0
        self.capstone_arm64 = (
            Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            if CAPSTONE_AVAILABLE and self.metadata.machine in ("AArch64", "ARM64")
            else None
        )
        self.crypto_signatures: list[dict[str, Any]] = []
        self._load_custom_crypto_profiles()

        self.keyword_regex = self._compile_keywords(args.keywords)

    def _load_custom_crypto_profiles(self) -> None:
        for path in self.args.crypto_profile_json:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            records = raw if isinstance(raw, list) else raw.get("profiles", [])
            if not isinstance(records, list):
                raise ValueError(f"Invalid crypto profile JSON: {path}")
            for record in records:
                if not isinstance(record, dict):
                    raise ValueError(f"Profile entry must be an object: {record!r}")
                patterns = record.get("patterns") or [record.get("match", "")]
                patterns = tuple(str(item) for item in patterns if item)
                if not patterns:
                    raise ValueError(f"Profile is missing patterns: {record!r}")
                self.crypto_profiles.append(CryptoTransformProfile(
                    name=str(record["name"]),
                    patterns=patterns,
                    algorithm=str(record.get("algorithm", "custom transform")),
                    output_reg=int(record["output_reg"]),
                    input_reg=(int(record["input_reg"]) if record.get("input_reg") is not None else None),
                    length_reg=(int(record["length_reg"]) if record.get("length_reg") is not None else None),
                    length_pointer_reg=(int(record["length_pointer_reg"]) if record.get("length_pointer_reg") is not None else None),
                    capacity_reg=(int(record["capacity_reg"]) if record.get("capacity_reg") is not None else None),
                    fixed_length=(int(record["fixed_length"]) if record.get("fixed_length") is not None else None),
                    key_regs=tuple(int(item) for item in record.get("key_regs", [])),
                    iv_regs=tuple(int(item) for item in record.get("iv_regs", [])),
                    context_regs=tuple(int(item) for item in record.get("context_regs", [])),
                    mode_reg=(int(record["mode_reg"]) if record.get("mode_reg") is not None else None),
                    default_capacity=int(record.get("default_capacity", 0x1000)),
                ))

    def _match_crypto_profile(
        self,
        target_name: Optional[str],
    ) -> Optional[CryptoTransformProfile]:
        if not target_name:
            return None
        for profile in self.crypto_profiles:
            if any(re.search(pattern, target_name, re.IGNORECASE) for pattern in profile.patterns):
                return profile
        return None

    def _discover_static_xor_key(self) -> Optional[tuple[bytes, int]]:
        """Compatibility helper; normal discovery retains all corroborated keys."""
        found = discover_xor_keys(bytes(self.original), lengths=self.args.xor_key_lengths,
                                 anchors=self.xor_anchors(), max_keys=1)
        if not found:
            return None
        key, evidence = found[0]
        offset = evidence['stored_key_file_offset']
        key_va = 0
        if offset is not None:
            for seg in self.metadata.load_segments:
                if seg.file_offset <= offset < seg.file_offset + seg.file_size:
                    key_va = seg.virtual_address + offset - seg.file_offset
                    break
        return key, key_va

    def xor_anchors(self) -> tuple[bytes, ...]:
        return tuple(dict.fromkeys((*XOR_ANCHORS, *(a.encode('utf-8') for a in self.args.xor_anchor))))

    def file_offset_to_va(self, offset: int) -> Optional[int]:
        for seg in self.metadata.load_segments:
            if seg.file_offset <= offset < seg.file_offset + seg.file_size:
                return seg.virtual_address + offset - seg.file_offset
        return None

    def discover_static_strings(self, *, post_init: bool = False) -> None:
        """Corroborated decoding of original or constructor-prepared file bytes.

        The second pass does not execute the lazy decoder or establish that a
        recovered API was called. It uses the same evidence requirements as the
        original pass, and retains the initialization outcome independently.
        """
        if not self.args.discover_xor_keys:
            return
        if post_init:
            if self.args.static_only or not self.current_snapshot:
                return
            # Use a coherent memory snapshot, not the analysis overlay, which
            # can also retain transient plaintext from earlier decoder calls.
            prepared = bytearray(self.original)
            for seg in self.metadata.load_segments:
                data = self.current_snapshot.get(seg.index, b'')[:seg.file_size]
                prepared[seg.file_offset:seg.file_offset + len(data)] = data
            if prepared == self.original:
                return
            raw = bytes(prepared)
        else:
            raw = bytes(self.original)
        stage = 'post-init-xor' if post_init else 'static-xor'
        for key, evidence in discover_xor_keys(
            raw, lengths=self.args.xor_key_lengths, anchors=self.xor_anchors(),
            max_keys=self.args.max_xor_keys,
        ):
            digest = sha256_hex(key)
            for match in evidence['anchor_matches']:
                match['elf_va'] = self.file_offset_to_va(match['file_offset'])
            key_offset = evidence['stored_key_file_offset']
            record = {'type': f'validated-{stage}-key', 'key_length': len(key),
                      'key_sha256': digest, **evidence, 'source_stage': stage,
                      'input': str(self.metadata.path), 'input_sha256': self.input_sha256,
                      'stored_key_elf_va': (self.file_offset_to_va(key_offset)
                                            if key_offset is not None else None),
                      'constructors_complete': (bool(self.function_results) and
                                               all(r['success'] for r in self.function_results)
                                               if post_init else None)}
            self.events.write(record)
            self.xor_discoveries.append(record)
            print(f"[+] {stage}: corroborated {len(key)}-byte XOR key: {len(evidence['anchor_matches'])} anchors")
            # Preserve exact anchor bounds/locations alongside general sweeps,
            # which can join a name to unrelated printable neighboring bytes.
            for match in evidence['anchor_matches']:
                self.add_candidate(CandidateString(
                    text=match['anchor'], encoding='utf-8',
                    source=f"{stage}:{digest[:16]}:anchor:phase:{match['phase']}",
                    file_offset=match['file_offset'], elf_va=match['elf_va'],
                ))
            for phase in range(len(key)):
                self.scan_bytes(xor_bytes(raw, key, phase),
                                source=f"{stage}:{digest[:16]}:phase:{phase}",
                                file_base=0)

    def _register_symbol_addresses(self) -> None:
        for name, elf_va in self.metadata.symbols.items():
            runtime = self.runtime_from_va(elf_va)
            self.address_labels.setdefault(runtime, name)
            self.symbols_by_va[elf_va].append(name)

    def _label_address(self, address: int, name: str) -> None:
        if address >= PAGE_SIZE and name:
            self.address_labels.setdefault(address, name)

    def _resolve_call_name(self, target: int) -> Optional[str]:
        exact = self.address_labels.get(target)
        if exact:
            return exact
        if self.is_module_address(target):
            elf_va = self.elf_va_from_runtime(target)
            names = self.symbols_by_va.get(elf_va)
            if names:
                return names[0]
        return None

    def _is_mapped_address(self, address: int, executable: bool = False) -> bool:
        if address < PAGE_SIZE:
            return False
        try:
            for item in getattr(self.ql.mem, "map_info", ()) if self.ql is not None else ():
                start, end = int(item[0]), int(item[1])
                permissions = str(item[2]) if len(item) > 2 else ""
                if start <= address < end:
                    return (not executable) or ("x" in permissions)
        except Exception:
            return False
        return False

    @staticmethod
    def _profile_target_key(target_runtime: int, target_elf_va: int, target_name: Optional[str]) -> str:
        if target_name:
            return target_name
        return f"elf:{target_elf_va:#x}" if target_elf_va >= 0 else f"runtime:{target_runtime:#x}"

    @staticmethod
    def _compile_keywords(value: str) -> Optional[re.Pattern[str]]:
        values = [item.strip() for item in value.split(",") if item.strip()]
        if not values:
            return None
        escaped = [re.escape(item) for item in values]
        return re.compile("|".join(escaped), re.IGNORECASE)

    def runtime_from_va(self, elf_va: int) -> int:
        return self.load_bias + elf_va

    def elf_va_from_runtime(self, runtime_address: int) -> int:
        return runtime_address - self.load_bias

    def is_module_address(self, runtime_address: int) -> bool:
        elf_va = self.elf_va_from_runtime(runtime_address)
        return segment_for_va(self.metadata, elf_va) is not None

    def is_probable_stack_address(self, address: int) -> bool:
        if not self.stack_pointer:
            return False
        window = self.args.stack_window
        return self.stack_pointer - window <= address <= self.stack_pointer + window

    def add_candidate(self, candidate: CandidateString) -> None:
        if len(candidate.text) < self.args.min_string:
            return
        if not string_matches(
            candidate.text,
            self.keyword_regex,
            self.args.print_all_strings,
        ):
            return

        key = candidate.key()
        if key in self.candidates:
            return

        self.candidates[key] = candidate

        record = dataclasses.asdict(candidate)
        record.update(input=str(self.metadata.path), input_sha256=self.input_sha256)
        self.strings_jsonl.write(record)

        address_text = ""
        if candidate.elf_va is not None:
            address_text = f" elf_va={candidate.elf_va:#x}"
        elif candidate.runtime_address is not None:
            address_text = f" runtime={candidate.runtime_address:#x}"

        transient_text = " transient" if candidate.transient else ""
        print(
            f"[string]{transient_text}{address_text} "
            f"[{candidate.encoding}] [{candidate.source}] {candidate.text}"
        )

    def scan_bytes(
        self,
        data: bytes,
        *,
        source: str,
        runtime_base: Optional[int] = None,
        function: Optional[str] = None,
        transient: bool = False,
        file_base: Optional[int] = None,
    ) -> None:
        for offset, text, encoding in extract_ascii_strings(
            data,
            self.args.min_string,
        ):
            runtime_address = (
                runtime_base + offset
                if runtime_base is not None
                else None
            )
            elf_va: Optional[int] = None
            file_offset: Optional[int] = None

            if file_base is not None:
                file_offset = file_base + offset
                elf_va = self.file_offset_to_va(file_offset)

            if runtime_address is not None and self.is_module_address(
                runtime_address
            ):
                elf_va = self.elf_va_from_runtime(runtime_address)
                file_offset = va_to_file_offset(self.metadata, elf_va)

            self.add_candidate(
                CandidateString(
                    text=text,
                    encoding=encoding,
                    source=source,
                    runtime_address=runtime_address,
                    elf_va=elf_va,
                    file_offset=file_offset,
                    function=function,
                    transient=transient,
                )
            )

        if self.args.no_utf16:
            return

        for offset, text, encoding in extract_utf16le_strings(
            data,
            self.args.min_string,
        ):
            runtime_address = (
                runtime_base + offset
                if runtime_base is not None
                else None
            )
            elf_va: Optional[int] = None
            file_offset: Optional[int] = None

            if file_base is not None:
                file_offset = file_base + offset
                elf_va = self.file_offset_to_va(file_offset)

            if runtime_address is not None and self.is_module_address(
                runtime_address
            ):
                elf_va = self.elf_va_from_runtime(runtime_address)
                file_offset = va_to_file_offset(self.metadata, elf_va)

            self.add_candidate(
                CandidateString(
                    text=text,
                    encoding=encoding,
                    source=source,
                    runtime_address=runtime_address,
                    elf_va=elf_va,
                    file_offset=file_offset,
                    function=function,
                    transient=transient,
                )
            )

    def create_qiling(self) -> None:
        env = {
            "ANDROID_DATA": "/data",
            "ANDROID_ROOT": "/system",
            **parse_key_value(self.args.env),
        }

        verbosity = {
            "off": QL_VERBOSE.OFF,
            "disabled": getattr(QL_VERBOSE, "DISABLED", QL_VERBOSE.OFF),
            "default": QL_VERBOSE.DEFAULT,
            "debug": QL_VERBOSE.DEBUG,
        }[self.args.verbose]

        kwargs: dict[str, Any] = {
            "verbose": verbosity,
            "env": env,
            "multithread": False,
        }
        if self.args.profile:
            kwargs["profile"] = self.args.profile

        self.ql = Qiling(
            [str(self.loader_path)],
            str(self.args.rootfs),
            **kwargs,
        )

        basename = os.path.basename(str(self.loader_path))
        discovered_base = self.ql.mem.get_lib_base(basename)

        if not discovered_base:
            for image in getattr(self.ql.loader, "images", ()):  # API fallback
                image_path = str(getattr(image, "path", ""))
                if os.path.basename(image_path) != basename:
                    continue
                discovered_base = getattr(image, "base", None)
                if discovered_base:
                    break

        if not discovered_base:
            raise RuntimeError(
                f"Qiling loaded the target but its module base could not "
                f"be resolved for {basename!r}"
            )

        self.module_base = int(discovered_base)
        self.load_bias = (
            self.module_base - self.metadata.minimum_load_va
        )
        self.stack_pointer = int(self.ql.arch.regs.arch_sp)

        print(f"[+] Qiling module base: {self.module_base:#x}")
        print(f"[+] Calculated load bias: {self.load_bias:#x}")
        print(f"[+] Initial stack pointer: {self.stack_pointer:#x}")

        self.events.write(
            {
                "type": "qiling-created",
                "module_base": self.module_base,
                "load_bias": self.load_bias,
                "stack_pointer": self.stack_pointer,
                "machine": self.metadata.machine,
                "elf_class": self.metadata.elf_class,
            }
        )

        self._register_symbol_addresses()
        self._setup_filesystem_mappings()
        self._setup_tls()
        self._install_stubs()

        # Qiling 1.4.6 may leave Android/AArch64 GOT, RELATIVE, RELR, and
        # low in-module function pointers unresolved. Repair those before
        # reading .init_array or executing any constructor.
        if self.args.repair_relocations:
            self._repair_relocations_and_imports()

        self._apply_memory_patches()
        self._install_hooks()
        self._capture_baseline_registers()

    def _setup_filesystem_mappings(self) -> None:
        assert self.ql is not None

        mappings = [
            ("/dev/null", "/dev/null"),
            ("/dev/urandom", "/dev/urandom"),
        ]

        for spec in self.args.fs_map:
            try:
                guest, host = spec.split("=", 1)
            except ValueError as exc:
                raise ValueError(
                    "--fs-map expects GUEST=HOST"
                ) from exc
            mappings.append((guest, host))

        for guest, host in mappings:
            try:
                if Path(host).exists():
                    self.ql.add_fs_mapper(guest, host)
            except Exception as error:
                print(
                    f"[!] Could not map {guest!r} to {host!r}: {error}"
                )

    def _find_free_space_compat(
        self,
        size: int,
        *,
        preferred_min: int = 0x10000000,
        alignment: int = PAGE_SIZE,
    ) -> int:
        """Qiling 1.4.6 compatibility allocator.

        Qiling 1.4.6 uses minaddr/maxaddr/align, while newer examples may
        show different keyword names. Try the 1.4.6 spelling first and then
        fall back to a manual gap scan. Address zero is never accepted.
        """
        assert self.ql is not None
        size = align_up(size, PAGE_SIZE)

        attempts = (
            {"minaddr": preferred_min, "align": alignment},
            {"minaddr": preferred_min},
            {},
        )
        for kwargs in attempts:
            try:
                address = int(self.ql.mem.find_free_space(size, **kwargs))
                if address >= PAGE_SIZE and address % PAGE_SIZE == 0:
                    if self.ql.mem.is_available(address, size):
                        return address
            except (TypeError, ValueError, AssertionError, Exception):
                pass

        # Deterministic manual scan around common AArch64 user-space gaps.
        starts = [
            preferred_min,
            align_up(self.module_base + 0x10000000, alignment),
            0x100000000,
            0x1000000000,
            0x7000000000,
            0x70000000000,
            0x700000000000,
        ]
        for start in starts:
            address = align_up(start, alignment)
            for _ in range(0x4000):
                try:
                    if address >= PAGE_SIZE and self.ql.mem.is_available(address, size):
                        return address
                except Exception:
                    pass
                address += alignment

        raise RuntimeError(f"Could not find {size:#x} bytes of free emulated memory")

    def _map_analysis_region(
        self,
        size: int,
        label: str,
        *,
        preferred_min: int = 0x10000000,
    ) -> int:
        assert self.ql is not None
        size = align_up(size, PAGE_SIZE)
        address = self._find_free_space_compat(
            size,
            preferred_min=preferred_min,
            alignment=PAGE_SIZE,
        )
        self.ql.mem.map(address, size, info=label)
        return address

    def _setup_tls(self) -> None:
        assert self.ql is not None

        if self.metadata.machine not in ("AArch64", "ARM64"):
            return

        try:
            current = int(self.ql.arch.regs.read("tpidr_el0"))
        except Exception:
            current = 0

        if current and not self.args.force_tls:
            return

        try:
            allocation_size = 0x5000
            tls_base = self._map_analysis_region(
                allocation_size,
                "[analysis-tls]",
                preferred_min=0x10000000,
            )
            tcb_address = tls_base + 0x1000
            bionic_tls_address = tls_base + 0x2000
            tls = struct.pack(
                "<QQQQQQQQQ",
                bionic_tls_address,
                0,
                tcb_address,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            self.ql.mem.write(tls_base, tls)
            self.ql.arch.regs.write("tpidr_el0", tcb_address)
            print(
                f"[+] Installed minimal AArch64 TLS at "
                f"{tls_base:#x}"
            )
        except Exception as error:
            print(f"[!] Minimal TLS setup failed: {error}")

    def _install_stubs(self) -> None:
        assert self.ql is not None

        api_stubs = list(self.args.stub_api)
        syscall_stubs = list(self.args.stub_syscall)

        if self.args.anti_debug:
            # These are conservative analysis defaults. They neutralise common
            # self-debugging and self-termination checks but cannot cover
            # custom inline checks.
            for item in (
                ("ptrace", 0),
                ("prctl", 0),
                ("raise", 0),
                ("kill", 0),
                ("tgkill", 0),
                ("abort", 0),
            ):
                if item not in api_stubs:
                    api_stubs.append(item)
            for item in (("ptrace", 0), ("prctl", 0), ("kill", 0), ("tgkill", 0)):
                if item not in syscall_stubs:
                    syscall_stubs.append(item)

            status_path = self.output_dir / "proc_self_status.txt"
            status_path.write_text(
                "Name:\tqiling\nState:\tR (running)\nTracerPid:\t0\n",
                encoding="utf-8",
            )
            try:
                self.ql.add_fs_mapper("/proc/self/status", str(status_path))
            except Exception as error:
                print(f"[!] Could not map fake /proc/self/status: {error}")

        for name, return_value in api_stubs:
            def api_stub(
                ql: Qiling,
                _name: str = name,
                _return_value: int = return_value,
            ) -> int:
                self.events.write(
                    {
                        "type": "stub-api",
                        "name": _name,
                        "return_value": _return_value,
                        "function": self.active_function,
                    }
                )
                return _return_value

            try:
                self.ql.os.set_api(
                    name,
                    api_stub,
                    QL_INTERCEPT.CALL,
                )
                print(
                    f"[+] Stubbed API {name} -> {return_value:#x}"
                )
            except Exception as error:
                print(f"[!] Could not stub API {name}: {error}")

        for name, return_value in syscall_stubs:
            def syscall_stub(
                ql: Qiling,
                *unused: Any,
                _name: str = name,
                _return_value: int = return_value,
            ) -> int:
                self.events.write(
                    {
                        "type": "stub-syscall",
                        "name": _name,
                        "return_value": _return_value,
                        "function": self.active_function,
                    }
                )
                return _return_value

            try:
                self.ql.os.set_syscall(
                    name,
                    syscall_stub,
                    QL_INTERCEPT.CALL,
                )
                print(
                    f"[+] Stubbed syscall {name} -> "
                    f"{return_value:#x}"
                )
            except Exception as error:
                print(
                    f"[!] Could not stub syscall {name}: {error}"
                )


    # ------------------------------------------------------------------
    # Qiling 1.4.6 relocation and import repair
    # ------------------------------------------------------------------

    def _capture_baseline_registers(self) -> None:
        """Capture a clean CPU context so one crashed target does not poison the next."""
        assert self.ql is not None

        names = [f"x{i}" for i in range(31)] if self.metadata.machine in ("AArch64", "ARM64") else [f"r{i}" for i in range(16)]
        names.extend(("sp", "tpidr_el0"))

        captured: dict[str, int] = {}
        for name in names:
            try:
                captured[name] = int(self.ql.arch.regs.read(name))
            except Exception:
                pass

        self.baseline_registers = captured
        self.stack_pointer = captured.get("sp", self.stack_pointer)

    def _restore_baseline_registers(self) -> None:
        """Restore registers before each manually invoked constructor."""
        assert self.ql is not None

        for name, value in self.baseline_registers.items():
            try:
                self.ql.arch.regs.write(name, value)
            except Exception:
                pass

        # Clear volatile argument/result registers. The target-specific
        # arguments are applied immediately afterwards.
        if self.metadata.machine in ("AArch64", "ARM64"):
            for index in range(18):
                try:
                    self.ql.arch.regs.write(f"x{index}", 0)
                except Exception:
                    pass

    def _read_c_string(self, address: int, maximum: int = 0x4000) -> bytes:
        assert self.ql is not None
        if address < PAGE_SIZE:
            return b""

        output = bytearray()
        for offset in range(maximum):
            try:
                value = bytes(self.ql.mem.read(address + offset, 1))[0]
            except Exception:
                break
            if value == 0:
                break
            output.append(value)
        return bytes(output)

    def _return_from_import(self, return_value: int = 0) -> None:
        assert self.ql is not None
        self.ql.arch.regs.write("x0", return_value & 0xFFFFFFFFFFFFFFFF)
        self.ql.arch.regs.write("pc", int(self.ql.arch.regs.read("lr")))

    def _import_callback(self, name: str):
        """Create a small AArch64 import model for common constructor APIs."""
        normalised = name.split("@", 1)[0]

        def callback(ql: Qiling) -> None:
            x = [int(ql.arch.regs.read(f"x{i}")) for i in range(8)]
            result = 0

            try:
                if normalised in ("memcpy", "memmove", "__memcpy_chk", "__memmove_chk"):
                    dst, src, length = x[0], x[1], min(x[2], self.args.max_import_copy)
                    if dst >= PAGE_SIZE and src >= PAGE_SIZE and length:
                        ql.mem.write(dst, bytes(ql.mem.read(src, length)))
                    result = dst

                elif normalised in ("memset", "__memset_chk"):
                    dst, value, length = x[0], x[1] & 0xFF, min(x[2], self.args.max_import_copy)
                    if dst >= PAGE_SIZE and length:
                        ql.mem.write(dst, bytes([value]) * length)
                    result = dst

                elif normalised == "strlen":
                    result = len(self._read_c_string(x[0]))

                elif normalised in ("strcmp", "strncmp", "memcmp"):
                    if normalised == "strcmp":
                        left = self._read_c_string(x[0])
                        right = self._read_c_string(x[1])
                    else:
                        limit = min(x[2], self.args.max_import_copy)
                        if normalised == "strncmp":
                            left = self._read_c_string(x[0], limit)[:limit]
                            right = self._read_c_string(x[1], limit)[:limit]
                        else:
                            left = bytes(ql.mem.read(x[0], limit)) if x[0] >= PAGE_SIZE else b""
                            right = bytes(ql.mem.read(x[1], limit)) if x[1] >= PAGE_SIZE else b""
                    result = 0 if left == right else (-1 if left < right else 1)

                elif normalised == "strchr":
                    haystack = self._read_c_string(x[0])
                    wanted = x[1] & 0xFF
                    index = haystack.find(bytes([wanted]))
                    result = x[0] + index if index >= 0 else 0

                elif normalised == "strstr":
                    haystack = self._read_c_string(x[0])
                    needle = self._read_c_string(x[1])
                    index = haystack.find(needle)
                    result = x[0] + index if index >= 0 else 0

                elif normalised == "getauxval":
                    aux_type = x[0]
                    if aux_type == 6:          # AT_PAGESZ
                        result = PAGE_SIZE
                    elif aux_type == 16:       # AT_HWCAP
                        result = self.args.auxv_hwcap
                    elif aux_type == 26:       # AT_HWCAP2
                        result = self.args.auxv_hwcap2
                    else:
                        result = 0

                elif normalised == "__system_property_get":
                    property_name = self._read_c_string(x[0]).decode("utf-8", errors="replace")
                    value = self.import_properties.get(property_name, "")
                    encoded = value.encode("utf-8", errors="replace")[:91]
                    if x[1] >= PAGE_SIZE:
                        ql.mem.write(x[1], encoded + b"\x00")
                    result = len(encoded)
                    self.events.write({
                        "type": "android-property",
                        "name": property_name,
                        "value": value,
                        "function": self.active_function,
                    })

                elif normalised in ("getpid", "gettid"):
                    result = 1337

                elif normalised in ("getuid", "geteuid", "getgid", "getegid"):
                    result = 0

                elif normalised in (
                    "__cxa_atexit", "__cxa_finalize", "__register_atfork",
                    "pthread_once", "pthread_mutex_lock", "pthread_mutex_unlock",
                    "pthread_rwlock_rdlock", "pthread_rwlock_wrlock",
                    "pthread_rwlock_unlock", "prctl", "ptrace", "raise", "kill",
                    "tgkill", "abort", "__stack_chk_fail"
                ):
                    result = 0

                elif normalised in ("malloc", "calloc", "realloc"):
                    # Constructor-only fallback allocator. It intentionally
                    # leaks allocations for the duration of the analysis.
                    if normalised == "calloc":
                        requested = max(1, min(x[0] * x[1], self.args.max_import_allocation))
                    elif normalised == "realloc":
                        requested = max(1, min(x[1], self.args.max_import_allocation))
                    else:
                        requested = max(1, min(x[0], self.args.max_import_allocation))
                    result = self._map_analysis_region(
                        align_up(requested),
                        f"[analysis-import-{normalised}]",
                        preferred_min=0x50000000,
                    )
                    if normalised == "calloc":
                        ql.mem.write(result, b"\x00" * requested)

                elif normalised == "free":
                    result = 0

                elif self.args.stub_unknown_imports:
                    result = 0
                else:
                    print(
                        f"[!] Unmodelled import {normalised!r} reached in "
                        f"{self.active_function}; returning zero"
                    )
                    result = 0

            except Exception as error:
                print(f"[!] Import model {normalised} failed: {error}")
                self.events.write({
                    "type": "import-model-error",
                    "name": normalised,
                    "error": str(error),
                    "function": self.active_function,
                })
                result = 0

            self.events.write({
                "type": "import-call",
                "name": normalised,
                "arguments": x,
                "return_value": result,
                "function": self.active_function,
            })
            self._return_from_import(result)

        return callback

    def _get_import_trampoline(self, name: str) -> int:
        assert self.ql is not None

        existing = self.import_trampolines.get(name)
        if existing is not None:
            return existing

        if self.import_trampoline_region is None:
            self.import_trampoline_region = self._map_analysis_region(
                0x20000,
                "[analysis-import-trampolines]",
                preferred_min=0x40000000,
            )
            self.import_trampoline_next = 0

        if self.import_trampoline_next + 0x10 > 0x20000:
            raise RuntimeError("Import trampoline region exhausted")

        address = self.import_trampoline_region + self.import_trampoline_next
        self.import_trampoline_next += 0x10

        # RET is a safe fallback if an address hook is not dispatched.
        self.ql.mem.write(address, b"\xc0\x03\x5f\xd6" + b"\x1f\x20\x03\xd5" * 3)
        self.ql.hook_address(self._import_callback(name), address)
        self.import_trampolines[name] = address
        self._label_address(address, name)
        return address

    def _write_pointer_if_needed(self, runtime_slot: int, value: int, reason: str) -> bool:
        assert self.ql is not None

        try:
            current = int.from_bytes(bytes(self.ql.mem.read(runtime_slot, 8)), "little")
        except Exception:
            return False

        if current == value:
            return False

        # Do not overwrite an already valid mapped runtime pointer unless this
        # is an explicit imported-symbol repair.
        if reason != "import" and current >= self.load_bias:
            try:
                map_info = getattr(self.ql.mem, "map_info", ())
                if any(start <= current < end for start, end, *_ in map_info):
                    return False
            except Exception:
                pass

        try:
            self.ql.mem.write(runtime_slot, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))
        except Exception as error:
            print(f"[!] Failed relocation write at {runtime_slot:#x}: {error}")
            return False

        self.events.write({
            "type": "relocation-repair",
            "runtime_slot": runtime_slot,
            "elf_va": self.elf_va_from_runtime(runtime_slot) if self.is_module_address(runtime_slot) else None,
            "old_value": current,
            "new_value": value,
            "reason": reason,
        })
        return True

    def _apply_relr_section(self, data: bytes) -> int:
        """Apply ELF64 RELR entries to the already mapped target."""
        assert self.ql is not None
        if self.metadata.pointer_size != 8:
            return 0

        count = 0
        where = 0
        word_bits = 64

        def apply_slot(elf_slot: int) -> int:
            segment = segment_for_va(self.metadata, elf_slot)
            if segment is None or elf_slot + 8 > segment.va_end:
                self.events.write({'type': 'ignored-relr-slot', 'elf_va': elf_slot})
                return 0
            runtime_slot = self.runtime_from_va(elf_slot)
            addend = int.from_bytes(bytes(self.ql.mem.read(runtime_slot, 8)), 'little')
            if addend < self.load_bias:
                return int(self._write_pointer_if_needed(runtime_slot, self.load_bias + addend, 'RELR'))
            return 0

        for offset in range(0, len(data) - 7, 8):
            entry = int.from_bytes(data[offset:offset + 8], "little")
            if (entry & 1) == 0:
                where = entry
                count += apply_slot(where)
                where += 8
            else:
                bitmap = entry
                for bit in range(1, word_bits):
                    if bitmap & (1 << bit):
                        count += apply_slot(where + (bit - 1) * 8)
                where += (word_bits - 1) * 8

        return count

    def _heuristic_rebase_function_pointers(self) -> int:
        """
        Repair low AArch64 function pointers left in writable module memory.

        This targets stripped Android objects where pointer tables and
        .init_array entries contain ELF VAs such as 0xcd660 instead of
        runtime addresses such as load_bias + 0xcd660.
        """
        assert self.ql is not None
        repaired = 0

        executable = [
            segment for segment in self.metadata.load_segments
            if segment.flags & 1
        ]
        writable = [
            segment for segment in self.metadata.load_segments
            if segment.flags & 2
        ]

        def is_exec_va(value: int) -> bool:
            return any(
                segment.virtual_address <= value < segment.va_end
                for segment in executable
            )

        for segment in writable:
            runtime_base = self.runtime_from_va(segment.virtual_address)
            data = safe_read(self.ql, runtime_base, segment.memory_size)

            for offset in range(0, max(0, len(data) - 7), 8):
                value = int.from_bytes(data[offset:offset + 8], "little")
                if value == 0 or value & 0x3:
                    continue
                if not is_exec_va(value):
                    continue

                runtime_slot = runtime_base + offset
                runtime_value = self.runtime_from_va(value)
                if self._write_pointer_if_needed(runtime_slot, runtime_value, "heuristic-function-pointer"):
                    repaired += 1

        return repaired

    def _repair_relocations_and_imports(self) -> None:
        """
        Repair relocation gaps commonly seen with Qiling 1.4.6 on stripped
        Android AArch64 shared objects.

        The repair is intentionally applied to the emulated memory only.
        """
        assert self.ql is not None

        if self.metadata.machine not in ("AArch64", "ARM64"):
            print("[!] Manual relocation repair currently targets AArch64 only")
            return

        # AArch64 ELF relocation constants.
        R_AARCH64_ABS64 = 257
        R_AARCH64_GLOB_DAT = 1025
        R_AARCH64_JUMP_SLOT = 1026
        R_AARCH64_RELATIVE = 1027
        R_AARCH64_IRELATIVE = 1032

        repaired = 0
        imports = 0
        relr = 0

        image = ElfImage(self.loader_path.read_bytes())
        rows = []
        seen_slots = set()
        try:
            for slot, typ, index, addend in image.relocations():
                name, value, defined = image.symbol(index)
                rows.append((slot, typ, addend, name, value, defined, index))
                seen_slots.add(slot)
        except ValueError as error:
            self.events.write({'type': 'relocation-warning', 'error': str(error)})
            print(f"[!] Dynamic relocation metadata incomplete: {error}")

        # Preserve section-based support, but never require a section table.
        data = image.without_sections() if image.section_error else image.data
        try:
            elf = ELFFile(io.BytesIO(data))
            for section in elf.iter_sections():
                if not isinstance(section, RelocationSection):
                    continue
                table = elf.get_section(int(section['sh_link'])) if section['sh_link'] else None
                for relocation in section.iter_relocations():
                    slot = int(relocation.entry.r_offset)
                    if slot in seen_slots:
                        continue
                    index = int(relocation.entry.r_info_sym)
                    symbol = table.get_symbol(index) if table is not None and index else None
                    name = symbol.name if symbol is not None else ''
                    value = int(symbol['st_value']) if symbol is not None else 0
                    defined = symbol is not None and symbol['st_shndx'] != 'SHN_UNDEF'
                    rows.append((slot, int(relocation.entry.r_info_type),
                                 relocation.entry.get('r_addend'), name, value, defined, index))
                    seen_slots.add(slot)
        except Exception as error:
            self.events.write({'type': 'optional-section-relocation-warning', 'error': str(error)})

        for elf_slot, rel_type, addend, symbol_name, symbol_value, symbol_defined, symbol_index in rows:
            segment = segment_for_va(self.metadata, elf_slot)
            if segment is None or elf_slot + 8 > segment.va_end:
                self.events.write({'type': 'ignored-relocation-slot', 'elf_va': elf_slot})
                continue
            runtime_slot = self.runtime_from_va(elf_slot)
            if addend is None:
                addend = int.from_bytes(bytes(self.ql.mem.read(runtime_slot, 8)), 'little')
            value = None
            reason = ''
            if rel_type == R_AARCH64_RELATIVE:
                value, reason = self.load_bias + addend, 'RELATIVE'
            elif rel_type in (R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT):
                if symbol_defined and symbol_value:
                    value, reason = self.runtime_from_va(symbol_value) + addend, 'defined-symbol'
                    self._label_address(value, symbol_name)
                elif symbol_name:
                    current = int.from_bytes(bytes(self.ql.mem.read(runtime_slot, 8)), 'little')
                    if self._is_mapped_address(current, executable=True):
                        self._label_address(current, symbol_name)
                    else:
                        value, reason = self._get_import_trampoline(symbol_name), 'import'
            elif rel_type == R_AARCH64_ABS64:
                if symbol_defined and symbol_value:
                    value, reason = self.runtime_from_va(symbol_value) + addend, 'ABS64'
                elif symbol_index == 0:
                    value, reason = self.load_bias + addend, 'ABS64'
            elif rel_type == R_AARCH64_IRELATIVE:
                # A resolver is not the resolved function. Report it without guessing.
                self.events.write({'type': 'unresolved-irelative', 'elf_va': elf_slot, 'resolver': addend})
            if value is not None and self._write_pointer_if_needed(runtime_slot, value, reason):
                repaired += 1
                imports += reason == 'import'

        relr_data = image.relr_data()
        if relr_data:
            relr += self._apply_relr_section(relr_data)
        else:
            for section_name in ('.relr.dyn', '.android.relr.dyn'):
                section = elf.get_section_by_name(section_name)
                if section is not None:
                    relr += self._apply_relr_section(section.data())

        heuristic = 0
        if self.args.heuristic_rebase_pointers:
            heuristic = self._heuristic_rebase_function_pointers()

        self.relocation_repairs += repaired + relr
        self.import_repairs += imports
        self.heuristic_pointer_repairs += heuristic

        print(
            f"[+] Relocation repair: {repaired + relr} writes, "
            f"{imports} imports, {heuristic} heuristic function pointers"
        )
        self.events.write({
            "type": "relocation-repair-summary",
            "relocation_writes": repaired + relr,
            "import_writes": imports,
            "heuristic_function_pointers": heuristic,
        })

    def _apply_memory_patches(self) -> None:
        assert self.ql is not None

        for elf_va, data in self.args.memory_patch:
            runtime = self.runtime_from_va(elf_va)
            try:
                self.ql.mem.write(runtime, data)
            except Exception as error:
                raise RuntimeError(
                    f"Failed to write memory patch at ELF VA "
                    f"{elf_va:#x}: {error}"
                ) from error

            self.events.write(
                {
                    "type": "memory-patch",
                    "elf_va": elf_va,
                    "runtime_address": runtime,
                    "size": len(data),
                    "sha256": sha256_hex(data),
                }
            )
            print(
                f"[+] Applied memory patch at ELF VA "
                f"{elf_va:#x}, {len(data)} bytes"
            )

    def _install_hooks(self) -> None:
        assert self.ql is not None
        instruction_cache: dict[int, bytes] = {}

        def on_write(
            ql: Qiling,
            access: int,
            address: int,
            size: int,
            value: int,
        ) -> None:
            if size <= 0:
                return
            # Cache hot flattened dispatcher instructions, but invalidate writes
            # to cached code so self-modifying decoders remain observable.
            for pc in range(address & ~3, address + size, 4):
                instruction_cache.pop(pc, None)
            if self.is_probable_stack_address(address):
                return

            if self.is_module_address(address):
                self.module_dirty.add(address, size)
            else:
                self.external_dirty.add(address, size)

            if self.args.realtime_writes or self.inline_crypto_countdown > 0:
                self.pending_write_ranges.add(address, size)

        self.ql.hook_mem_write(on_write)

        need_code_hook = (
            self.args.realtime_writes
            or self.args.discover_transforms
            or self.args.skip_breakpoints
            or bool(self.args.max_instructions)
        )
        if not need_code_hook:
            return

        def on_code(ql: Qiling, address: int, size: int) -> None:
            if self.args.realtime_writes:
                self._flush_pending_write_windows()

            if self.args.discover_transforms:
                self._process_transform_returns(address)

            instruction = instruction_cache.get(address)
            if instruction is None:
                instruction = safe_read(ql, address, 4)
                instruction_cache[address] = instruction
            word = (
                int.from_bytes(instruction, "little")
                if len(instruction) == 4
                else 0
            )

            if (
                self.args.detect_inline_crypto
                and self.capstone_arm64 is not None
                and len(instruction) == 4
                and (word & 0xFFFF0C00) == 0x4E280800
            ):
                try:
                    decoded = next(self.capstone_arm64.disasm(instruction, address), None)
                except Exception:
                    decoded = None
                if decoded is not None and decoded.mnemonic.lower() in ARM64_AES_MNEMONICS:
                    self.inline_crypto_countdown = max(
                        self.inline_crypto_countdown,
                        self.args.inline_crypto_window,
                    )
                    self.inline_crypto_hits += 1
                    if self.inline_crypto_hits <= self.args.max_inline_crypto_events:
                        self.events.write({
                            "type": "inline-crypto-instruction",
                            "algorithm": "ARMv8 AES",
                            "mnemonic": decoded.mnemonic,
                            "op_str": decoded.op_str,
                            "runtime_address": address,
                            "elf_va": self.elf_va_from_runtime(address) if self.is_module_address(address) else None,
                            "function": self.active_function,
                        })

            if self.args.skip_breakpoints and self.metadata.machine in ("AArch64", "ARM64"):
                # BRK #imm and HLT #imm. Patch only instructions actually
                # reached, preserving dormant traps elsewhere.
                is_brk = (word & 0xFFE0001F) == 0xD4200000
                is_hlt = (word & 0xFFE0001F) == 0xD4400000
                if is_brk or is_hlt:
                    kind = "BRK" if is_brk else "HLT"
                    print(f"[anti-debug] replacing {kind} at {address:#x} with NOP")
                    self.events.write({
                        "type": "breakpoint-bypass",
                        "kind": kind,
                        "runtime_address": address,
                        "elf_va": self.elf_va_from_runtime(address) if self.is_module_address(address) else None,
                    })
                    try:
                        ql.mem.write(address, b"\x1f\x20\x03\xd5")
                        instruction_cache.pop(address, None)
                    except Exception as error:
                        print(f"[!] Failed to patch {kind} at {address:#x}: {error}")

            if self.args.discover_transforms:
                self._observe_aarch64_call(address, word)

            if self.inline_crypto_countdown > 0:
                self.inline_crypto_countdown -= 1

            self.instruction_count += 1
            self.last_code_address = address

            if (
                self.args.max_instructions
                and self.instruction_count > self.args.max_instructions
            ):
                print("[!] Instruction limit reached; stopping current emulation run")
                ql.emu_stop()

        self.ql.hook_code(on_code)

    def _read_register(self, index: int) -> int:
        assert self.ql is not None
        try:
            return int(self.ql.arch.regs.read(f"x{index}"))
        except Exception:
            return 0

    def _normalise_call_target(self, target: int) -> Optional[int]:
        if self.is_module_address(target):
            return target
        if segment_for_va(self.metadata, target) is not None:
            return self.runtime_from_va(target)
        # Observe external calls only when a relocation/symbol label identifies
        # them as a known crypto profile. This avoids instrumenting every libc
        # call while still covering OpenSSL/BoringSSL/mbedTLS APIs.
        name = self._resolve_call_name(target)
        if name and self._match_crypto_profile(name) is not None:
            return target
        return None

    def _observe_aarch64_call(self, address: int, word: int) -> None:
        assert self.ql is not None
        if self.metadata.machine not in ("AArch64", "ARM64"):
            return

        target: Optional[int] = None

        # BL immediate
        if (word & 0xFC000000) == 0x94000000:
            imm26 = word & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 -= 0x04000000
            target = address + (imm26 << 2)

        # BLR Xn
        elif (word & 0xFFFFFC1F) == 0xD63F0000:
            register_index = (word >> 5) & 0x1F
            target = self._read_register(register_index)

        if target is None:
            return

        target = self._normalise_call_target(target)
        if target is None:
            return

        args = tuple(self._read_register(index) for index in range(8))
        target_name = self._resolve_call_name(target)
        profile = self._match_crypto_profile(target_name)
        target_elf_va = (
            self.elf_va_from_runtime(target)
            if self.is_module_address(target)
            else -target
        )

        probes: list[TransformBufferProbe] = []
        seen: set[tuple[int, int, Optional[int]]] = set()
        key_probes: dict[int, bytes] = {}
        key_roles: dict[int, str] = {}

        def add_probe(
            pointer_register: int,
            length_register: int,
            length: int,
            *,
            actual_length_pointer: Optional[int] = None,
            input_pointer: Optional[int] = None,
            profile_name: Optional[str] = None,
        ) -> None:
            pointer = args[pointer_register]
            length = min(int(length), self.args.transform_max_length)
            key = (pointer, length, actual_length_pointer)
            if key in seen:
                return
            seen.add(key)
            if pointer < PAGE_SIZE or not (
                self.args.transform_min_length <= length <= self.args.transform_max_length
            ):
                return
            try:
                before = bytes(self.ql.mem.read(pointer, length))
            except Exception:
                return
            probes.append(TransformBufferProbe(
                pointer_register=pointer_register,
                length_register=length_register,
                pointer=pointer,
                length=length,
                before=before,
                actual_length_pointer=actual_length_pointer,
                input_pointer=input_pointer,
                profile_name=profile_name,
            ))

        if profile is not None:
            output_pointer = args[profile.output_reg]
            actual_length_pointer = (
                args[profile.length_pointer_reg]
                if profile.length_pointer_reg is not None
                else None
            )
            if profile.fixed_length is not None:
                capacity = profile.fixed_length
                length_register = -1
            elif profile.length_reg is not None:
                capacity = args[profile.length_reg]
                length_register = profile.length_reg
            elif profile.capacity_reg is not None:
                capacity = args[profile.capacity_reg]
                length_register = profile.capacity_reg
            else:
                capacity = profile.default_capacity
                length_register = -1

            input_pointer = (
                args[profile.input_reg]
                if profile.input_reg is not None
                else None
            )
            if output_pointer >= PAGE_SIZE:
                add_probe(
                    profile.output_reg,
                    length_register,
                    capacity,
                    actual_length_pointer=actual_length_pointer,
                    input_pointer=input_pointer,
                    profile_name=profile.name,
                )

            role_sets = (
                (profile.key_regs, "key"),
                (profile.iv_regs, "iv/nonce"),
                (profile.context_regs, "context/key-schedule"),
            )
            for registers, role in role_sets:
                for register_index in registers:
                    pointer = args[register_index]
                    if pointer < PAGE_SIZE or self.is_probable_stack_address(pointer):
                        continue
                    try:
                        key_probes[register_index] = bytes(
                            self.ql.mem.read(pointer, self.args.key_probe_length)
                        )
                        key_roles[register_index] = role
                    except Exception:
                        pass

        # Algorithm-independent fallback for custom decoders and stripped
        # statically linked crypto. These signatures include dst/src/length,
        # in-place transforms, and several common argument orders.
        for pointer_register, length_register in (
            (0, 2), (1, 2), (0, 1), (0, 3), (1, 3),
            (0, 4), (1, 4), (3, 1), (5, 2), (6, 1),
        ):
            pointer = args[pointer_register]
            length = args[length_register]
            if pointer < PAGE_SIZE:
                continue
            input_pointer = None
            if pointer_register == 0 and len(args) > 1:
                input_pointer = args[1]
            elif pointer_register == 1:
                input_pointer = args[0]
            add_probe(
                pointer_register,
                length_register,
                length,
                input_pointer=input_pointer,
                profile_name=profile.name if profile else None,
            )

        if not probes:
            return

        # Generic key/context probes remain useful for unnamed custom ciphers.
        if not key_probes:
            for register_index in (3, 4, 5, 0):
                pointer = args[register_index]
                if pointer < PAGE_SIZE or self.is_probable_stack_address(pointer):
                    continue
                try:
                    key_probes[register_index] = bytes(
                        self.ql.mem.read(pointer, self.args.key_probe_length)
                    )
                    key_roles[register_index] = "generic candidate"
                except Exception:
                    pass

        if len(self.transform_stack) >= self.args.max_transform_depth:
            dropped = self.transform_stack.pop(0)
            self.transform_stats[dropped.target_elf_va]["aborted"] += 1

        self.transform_stack.append(TransformFrame(
            target_runtime=target,
            target_elf_va=target_elf_va,
            caller_runtime=address,
            return_address=address + 4,
            arguments=args,
            probes=probes,
            key_probes=key_probes,
            key_probe_roles=key_roles,
            target_name=target_name,
            profile_name=profile.name if profile else None,
            algorithm=profile.algorithm if profile else None,
        ))
        self.transform_stats[target_elf_va]["calls"] += 1

    def _process_transform_returns(self, current_address: int) -> None:
        if not self.transform_stack:
            return

        # Normally the matching frame is at the top. If obfuscated control flow
        # skipped one or more returns, discard only the stale inner frames.
        match_index: Optional[int] = None
        for index in range(len(self.transform_stack) - 1, -1, -1):
            if self.transform_stack[index].return_address == current_address:
                match_index = index
                break
        if match_index is None:
            return

        stale = self.transform_stack[match_index + 1:]
        if stale:
            for frame in stale:
                self.transform_stats[frame.target_elf_va]["aborted"] += 1
        frame = self.transform_stack[match_index]
        del self.transform_stack[match_index:]
        self._finish_transform_frame(frame)

    def _finish_transform_frame(self, frame: TransformFrame) -> None:
        assert self.ql is not None
        interesting_outputs: list[dict[str, Any]] = []
        changed_outputs: list[dict[str, Any]] = []

        for probe in frame.probes:
            effective_length = probe.length
            if probe.actual_length_pointer is not None:
                try:
                    actual = int.from_bytes(
                        bytes(self.ql.mem.read(
                            probe.actual_length_pointer,
                            probe.actual_length_size,
                        )),
                        "little",
                    )
                    if 0 < actual <= probe.length:
                        effective_length = actual
                except Exception:
                    pass
            try:
                after = bytes(self.ql.mem.read(probe.pointer, effective_length))
            except Exception:
                continue
            before = probe.before[:effective_length]
            if after == before:
                continue

            before_ratio = printable_ratio(before)
            after_ratio = printable_ratio(after)

            # Always preserve module-backed transformed bytes. Short chunks may
            # not look interesting by themselves but can form a long string
            # such as dalvik/system/DexClassLoader when adjacent chunks are
            # considered together.
            if self.is_module_address(probe.pointer):
                elf_va = self.elf_va_from_runtime(probe.pointer)
                segment = segment_for_va(self.metadata, elf_va)
                if segment is not None:
                    self.patch_file_backed_range(
                        segment,
                        segment_offset=elf_va - segment.virtual_address,
                        data=after,
                    )

            changed_record = {
                "pointer_register": probe.pointer_register,
                "length_register": probe.length_register,
                "pointer": probe.pointer,
                "length": effective_length,
                "capacity": probe.length,
                "actual_length_pointer": probe.actual_length_pointer,
                "input_pointer": probe.input_pointer,
                "profile_name": probe.profile_name,
                "before_printable_ratio": before_ratio,
                "after_printable_ratio": after_ratio,
                "sha256": sha256_hex(after),
            }
            changed_outputs.append(changed_record)

            # Scan the exact transformed bytes.
            self.scan_bytes(
                after,
                source=f"transform:{frame.target_name or hex(frame.target_elf_va)}",
                runtime_base=probe.pointer,
                function=self.active_function,
                transient=True,
            )

            # Also scan surrounding memory. This is crucial for families that
            # decrypt a logical string as multiple adjacent short chunks.
            context = max(0, self.args.transform_context)
            context_start = max(PAGE_SIZE, probe.pointer - context)
            context_size = min(
                effective_length + context * 2,
                self.args.max_realtime_window,
            )
            if context_size > 0:
                context_data = safe_read(
                    self.ql,
                    context_start,
                    context_size,
                )
                self.scan_bytes(
                    context_data,
                    source=f"transform-context:{frame.target_name or hex(frame.target_elf_va)}",
                    runtime_base=context_start,
                    function=self.active_function,
                    transient=True,
                )

            extracted = list(
                extract_ascii_strings(after, self.args.min_string)
            )
            extracted += list(
                extract_utf16le_strings(after, self.args.min_string)
            )
            keyword_hit = any(
                string_matches(text, self.keyword_regex, False)
                for _, text, _ in extracted
            )
            structured = (
                keyword_hit
                or after_ratio >= self.args.transform_printable_ratio
                or after_ratio - before_ratio
                >= self.args.transform_ratio_gain
                or after.startswith(
                    DEX_MAGICS
                    + (CDEX_MAGIC, ELF_MAGIC)
                    + ZIP_MAGICS
                )
            )
            if not structured:
                continue

            digest = sha256_hex(after)
            filename = (
                f"transform_{(frame.target_name or hex(frame.target_elf_va)).replace('/', '_')}_"
                f"{probe.pointer:016x}_{digest[:12]}.bin"
            )
            path = self.transform_dir / filename
            if not path.exists():
                path.write_bytes(after)

            output_record = {
                **changed_record,
                "path": str(path),
                "keyword_hit": keyword_hit,
            }
            interesting_outputs.append(output_record)

        if not changed_outputs:
            return

        stats = self.transform_stats[frame.target_elf_va]
        stats["changed"] += 1
        stats["changed_outputs"] += len(changed_outputs)

        # Count stable key pointers for every changed transformation, not only
        # for outputs that independently pass the printable-string heuristic.
        for register_index, key_data in frame.key_probes.items():
            pointer = frame.arguments[register_index]
            self.transform_key_pointers[
                frame.target_elf_va
            ][pointer] += 1
            # The rotating-XOR sweep is a family-specific fallback. Restrict
            # automatic selection to unnamed generic transforms using x3, so
            # AES/EVP context pointers are not misclassified as XOR keys.
            if frame.profile_name is None and register_index == 3:
                self.auto_xor_key_pointers[
                    frame.target_elf_va
                ][pointer] += 1

        if not interesting_outputs:
            return

        stats["interesting"] += 1
        stats["outputs"] += len(interesting_outputs)

        key_records: list[dict[str, Any]] = []
        for register_index, key_data in frame.key_probes.items():
            pointer = frame.arguments[register_index]
            digest = sha256_hex(key_data)
            filename = (
                f"key_target_{(frame.target_name or hex(frame.target_elf_va)).replace('/', '_')}_"
                f"x{register_index}_{pointer:016x}_{digest[:12]}.bin"
            )
            path = self.key_dir / filename
            if not path.exists():
                path.write_bytes(key_data)
            key_records.append({
                "register": register_index,
                "role": frame.key_probe_roles.get(register_index, "candidate"),
                "pointer": pointer,
                "length": len(key_data),
                "sha256": digest,
                "hex": key_data.hex(),
                "path": str(path),
            })

        record = {
            "type": "transform-candidate",
            "target_runtime": frame.target_runtime,
            "target_elf_va": frame.target_elf_va if frame.target_elf_va >= 0 else None,
            "target_name": frame.target_name,
            "profile_name": frame.profile_name,
            "algorithm": frame.algorithm,
            "caller_runtime": frame.caller_runtime,
            "caller_elf_va": self.elf_va_from_runtime(
                frame.caller_runtime
            ),
            "return_address": frame.return_address,
            "arguments": list(frame.arguments),
            "changed_outputs": changed_outputs,
            "outputs": interesting_outputs,
            "key_candidates": key_records,
            "active_function": self.active_function,
        }
        self.transforms_jsonl.write(record)
        self.events.write(record)

        key_summary = ", ".join(
            f"x{item['register']}={item['pointer']:#x}"
            for item in key_records
        ) or "none"
        target_display = (
            frame.target_name
            or (f"{frame.target_elf_va:#x}" if frame.target_elf_va >= 0 else f"{frame.target_runtime:#x}")
        )
        profile_display = (
            f" profile={frame.profile_name}/{frame.algorithm}"
            if frame.profile_name
            else ""
        )
        print(
            f"[transform] candidate target={target_display} "
            f"caller={self.elf_va_from_runtime(frame.caller_runtime):#x} "
            f"outputs={len(interesting_outputs)} keys={key_summary}"
            f"{profile_display}"
        )

    def _flush_pending_write_windows(self) -> None:
        assert self.ql is not None

        if not self.pending_write_ranges:
            return

        ranges = self.pending_write_ranges.merged(
            gap=self.args.write_merge_gap
        )
        self.pending_write_ranges.clear()

        for start, end in ranges:
            centre_start = align_down(
                max(0, start - self.args.write_context)
            )
            centre_end = align_up(
                end + self.args.write_context
            )
            size = min(
                centre_end - centre_start,
                self.args.max_realtime_window,
            )
            if size <= 0:
                continue

            data = safe_read(self.ql, centre_start, size)
            if not data:
                continue

            # Avoid rescanning identical write windows repeatedly.
            digest_key = (
                centre_start,
                sha256_hex(data),
            )
            if digest_key in self.transient_seen:
                continue
            self.transient_seen.add(digest_key)

            self.scan_bytes(
                data,
                source=(
                    "inline-crypto-write-window"
                    if self.inline_crypto_countdown > 0
                    else "realtime-write-window"
                ),
                runtime_base=centre_start,
                function=self.active_function,
                transient=True,
            )

            if self.args.save_realtime_windows:
                name = (
                    f"write_{centre_start:016x}_"
                    f"{sha256_hex(data)[:12]}.bin"
                )
                (self.external_dir / name).write_bytes(data)

    def snapshot_module(self) -> dict[int, bytes]:
        assert self.ql is not None
        output: dict[int, bytes] = {}

        for segment in self.metadata.load_segments:
            runtime = self.runtime_from_va(segment.virtual_address)
            output[segment.index] = safe_read(
                self.ql,
                runtime,
                segment.memory_size,
            )

        return output

    def _is_executable_elf_va(self, elf_va: int) -> bool:
        segment = segment_for_va(self.metadata, elf_va)
        return segment is not None and bool(segment.flags & 1)

    def _scan_init_array_candidates(self) -> list[tuple[int, int, list[int]]]:
        """Heuristically find pointer arrays in writable module segments.

        Returns (array_elf_va, score, target_elf_vas). This is a fallback for
        missing/tampered dynamic metadata and may produce false positives.
        """
        assert self.ql is not None
        pointer_size = self.metadata.pointer_size
        byte_order = "little" if self.metadata.little_endian else "big"
        candidates: list[tuple[int, int, list[int]]] = []

        for segment in self.metadata.load_segments:
            if not (segment.flags & 2):
                continue
            runtime = self.runtime_from_va(segment.virtual_address)
            data = safe_read(self.ql, runtime, segment.memory_size)
            values: list[Optional[int]] = []
            for offset in range(0, len(data) - pointer_size + 1, pointer_size):
                raw_value = int.from_bytes(data[offset:offset + pointer_size], byte_order)
                normalised = raw_value & ~1 if self.metadata.machine == "ARM" else raw_value
                if self.is_module_address(normalised):
                    elf_va = self.elf_va_from_runtime(normalised)
                elif self._is_executable_elf_va(normalised):
                    elf_va = normalised
                else:
                    elf_va = None
                if elf_va is not None and self._is_executable_elf_va(elf_va):
                    values.append(elf_va)
                else:
                    values.append(None)

            index = 0
            while index < len(values):
                if values[index] is None:
                    index += 1
                    continue
                start = index
                run: list[int] = []
                while index < len(values) and values[index] is not None and len(run) < self.args.max_scanned_init_targets:
                    run.append(int(values[index]))
                    index += 1
                array_va = segment.virtual_address + start * pointer_size
                unique_count = len(set(run))
                score = 10 * len(run) + unique_count
                if start == 0 or values[start - 1] is None:
                    score += 3
                if index >= len(values) or values[index] is None:
                    score += 3
                candidates.append((array_va, score, run))

        candidates.sort(key=lambda item: (-item[1], item[0]))
        for array_va, score, targets in candidates[: self.args.report_scanned_init_arrays]:
            print(
                f"[init-scan] array candidate at {array_va:#x} "
                f"score={score} targets="
                + ",".join(f"{target:#x}" for target in targets)
            )
            self.events.write({
                "type": "scanned-init-array",
                "array_elf_va": array_va,
                "score": score,
                "targets": targets,
            })
        return candidates

    def resolve_init_targets(self) -> list[FunctionTarget]:
        assert self.ql is not None

        targets: list[FunctionTarget] = []
        seen: set[int] = set()

        def add(name: str, elf_va: int, arguments: tuple[int, ...] = ()) -> None:
            elf_va = int(elf_va)
            if not elf_va or elf_va in seen:
                return
            if not self._is_executable_elf_va(elf_va):
                self.events.write({
                    "type": "ignored-non-executable-target",
                    "name": name,
                    "elf_va": elf_va,
                })
                return
            seen.add(elf_va)
            targets.append(
                FunctionTarget(
                    name=name,
                    elf_va=elf_va,
                    arguments=arguments,
                )
            )

        if self.args.execute_init and self.metadata.dt_init:
            add("DT_INIT", self.metadata.dt_init)

        if (
            self.args.execute_init
            and self.metadata.init_array_va is not None
            and self.metadata.init_array_size > 0
        ):
            runtime_array = self.runtime_from_va(
                self.metadata.init_array_va
            )
            pointer_size = self.metadata.pointer_size
            count = (
                self.metadata.init_array_size // pointer_size
            )
            byte_order = (
                "little" if self.metadata.little_endian else "big"
            )

            for index in range(count):
                raw = safe_read(
                    self.ql,
                    runtime_array + index * pointer_size,
                    pointer_size,
                )
                if len(raw) != pointer_size:
                    continue
                pointer = int.from_bytes(raw, byte_order)
                if pointer in (0, (1 << (pointer_size * 8)) - 1):
                    continue

                # ARM init-array function pointers may carry the Thumb bit.
                normalised_pointer = (
                    pointer & ~1
                    if self.metadata.machine == "ARM"
                    else pointer
                )

                if self.is_module_address(normalised_pointer):
                    elf_va = self.elf_va_from_runtime(normalised_pointer)
                elif segment_for_va(self.metadata, normalised_pointer) is not None:
                    # Some incomplete emulations leave a relative VA.
                    elf_va = normalised_pointer
                else:
                    self.events.write(
                        {
                            "type": "ignored-init-array-pointer",
                            "index": index,
                            "pointer": pointer,
                        }
                    )
                    continue

                add(f"INIT_ARRAY[{index}]", elf_va | (pointer & 1) if self.metadata.machine == "ARM" else elf_va)

        for symbol_spec in self.args.extra_symbol:
            name, arguments = parse_call_spec(symbol_spec)
            elf_va = self.metadata.symbols.get(name)
            if elf_va is None:
                print(f"[!] Symbol not found: {name}")
                continue
            add(f"symbol:{name}", elf_va, arguments)

        if self.args.execute_jni_onload and not self.args.skip_jni_onload:
            value = self.metadata.symbols.get("JNI_OnLoad")
            if value is None:
                print("[!] JNI_OnLoad symbol not found")
            else:
                jni_arguments = tuple(self.args.jni_args)
                if self.args.fake_jni:
                    jni_arguments = (self._build_fake_jni(), 0)
                add(
                    "symbol:JNI_OnLoad",
                    value,
                    jni_arguments,
                )

        for offset in self.args.extra_offset:
            add(f"offset:{offset:#x}", offset)

        for name, ghidra_address in self.args.ghidra_function:
            elf_va = ghidra_address - self.args.ghidra_image_base
            add(f"ghidra:{name}", elf_va)

        if self.args.jni_onload_address is not None and not self.args.skip_jni_onload:
            args = tuple(self.args.jni_args)
            if self.args.fake_jni:
                args = (self._build_fake_jni(), 0)
            add("address:JNI_OnLoad", self.args.jni_onload_address, args)

        if self.args.auto_init_symbols:
            patterns = [
                re.compile(r"^_?INIT_", re.IGNORECASE),
                re.compile(r"^\.?datadiv_decode", re.IGNORECASE),
            ]
            if self.args.auto_decrypt_symbols:
                patterns.append(re.compile(r"decrypt", re.IGNORECASE))
            for name, value in sorted(self.metadata.symbols.items()):
                if any(pattern.search(name) for pattern in patterns):
                    add(f"auto-symbol:{name}", value)

        if not targets and self.args.scan_init_arrays:
            scanned = self._scan_init_array_candidates()
            if self.args.execute_scanned_init_arrays:
                for array_va, score, values in scanned[: self.args.max_scanned_init_arrays]:
                    for index, value in enumerate(values):
                        add(f"SCANNED_INIT@{array_va:#x}[{index}]", value)

        return targets

    def _build_fake_jni(self) -> int:
        """Build a minimal JavaVM/JNIEnv skeleton for JNI_OnLoad.

        All JNIEnv calls return zero. JavaVM.GetEnv returns the fake JNIEnv.
        This is enough for some decrypt-before-registration JNI_OnLoad paths,
        but not for code requiring real ART objects.
        """
        assert self.ql is not None
        if self.fake_jni_vm is not None:
            return self.fake_jni_vm
        if self.metadata.machine not in ("AArch64", "ARM64"):
            raise RuntimeError("--fake-jni currently supports AArch64 only")

        base = self._map_analysis_region(0x9000, "[analysis-fake-jni]", preferred_min=0x20000000)
        vm_object = base
        vm_table = base + 0x1000
        env_object = base + 0x2000
        env_table = base + 0x3000
        generic_stub = base + 0x7000
        getenv_stub = base + 0x7010
        pointer_size = 8

        self.ql.mem.write(generic_stub, b"\x1f\x20\x03\xd5" * 4)
        self.ql.mem.write(getenv_stub, b"\x1f\x20\x03\xd5" * 4)
        self.ql.mem.write(vm_object, struct.pack("<Q", vm_table))
        self.ql.mem.write(env_object, struct.pack("<Q", env_table))
        for index in range(16):
            self.ql.mem.write(vm_table + index * pointer_size, struct.pack("<Q", generic_stub))
        for index in range(512):
            self.ql.mem.write(env_table + index * pointer_size, struct.pack("<Q", generic_stub))
        self.ql.mem.write(vm_table + 6 * pointer_size, struct.pack("<Q", getenv_stub))

        def return_zero(ql: Qiling) -> None:
            ql.arch.regs.write("x0", 0)
            ql.arch.regs.write("pc", int(ql.arch.regs.read("lr")))

        def get_env(ql: Qiling) -> None:
            out_pointer = int(ql.arch.regs.read("x1"))
            try:
                ql.mem.write(out_pointer, struct.pack("<Q", env_object))
                result = 0
            except Exception:
                result = -1 & 0xFFFFFFFFFFFFFFFF
            ql.arch.regs.write("x0", result)
            ql.arch.regs.write("pc", int(ql.arch.regs.read("lr")))

        self.ql.hook_address(return_zero, generic_stub)
        self.ql.hook_address(get_env, getenv_stub)
        self.fake_jni_vm = vm_object
        print(f"[+] Installed minimal fake JavaVM at {vm_object:#x}")
        return vm_object

    def _allocate_return_sentinel(self) -> int:
        assert self.ql is not None

        sentinel = self._map_analysis_region(
            PAGE_SIZE,
            "[analysis-return-sentinel]",
            preferred_min=0x30000000,
        )
        self.return_sentinel = sentinel

        if self.metadata.machine in ("AArch64", "ARM64"):
            self.ql.mem.write(sentinel, b"\x1f\x20\x03\xd5" * 4)
        else:
            self.ql.mem.write(sentinel, b"\x00" * 16)

        def stop_on_return(ql: Qiling) -> None:
            self.return_sentinel_hit = True
            ql.emu_stop()

        self.ql.hook_address(stop_on_return, sentinel)
        print(f"[+] Return sentinel installed at {sentinel:#x}")
        return sentinel

    def _set_function_arguments(
        self,
        arguments: Sequence[int],
    ) -> None:
        assert self.ql is not None

        if self.metadata.machine in ("AArch64", "ARM64"):
            for index, value in enumerate(arguments[:8]):
                self.ql.arch.regs.write(f"x{index}", value)
            return

        if self.metadata.machine == "ARM":
            for index, value in enumerate(arguments[:4]):
                self.ql.arch.regs.write(f"r{index}", value)
            return

        raise RuntimeError(
            f"Unsupported architecture for argument setup: "
            f"{self.metadata.machine}"
        )

    def execute_target(
        self,
        target: FunctionTarget,
        sentinel: int,
    ) -> None:
        assert self.ql is not None

        runtime = self.runtime_from_va(target.elf_va)
        self.active_function = target.name
        self.instruction_count = 0
        self.pending_write_ranges.clear()
        self.transform_stack.clear()

        # A failed constructor frequently leaves SP, LR, x16/x17, and argument
        # registers corrupted. Always start a manually invoked target from the
        # clean post-loader CPU context.
        self._restore_baseline_registers()
        self._set_function_arguments(target.arguments)

        try:
            self.ql.arch.regs.write("lr", sentinel)
        except Exception:
            try:
                self.ql.arch.regs.write("x30", sentinel)
            except Exception as error:
                raise RuntimeError(
                    f"Could not set link register: {error}"
                ) from error

        before = self.snapshot_module()
        started = time.monotonic()

        print(
            f"\n[+] Executing {target.name}: "
            f"ELF VA {target.elf_va:#x}, runtime {runtime:#x}"
        )

        self.events.write(
            {
                "type": "function-start",
                "name": target.name,
                "elf_va": target.elf_va,
                "runtime_address": runtime,
                "arguments": list(target.arguments),
            }
        )

        success = False
        error_text: Optional[str] = None

        self.return_sentinel_hit = False
        try:
            run_kwargs: dict[str, Any] = {
                "begin": runtime,
                "timeout": self.args.timeout_us,
            }
            if self.args.max_instructions:
                run_kwargs["count"] = self.args.max_instructions
            self.ql.run(**run_kwargs)
            success = self.return_sentinel_hit
            if not success:
                error_text = "emulation stopped before return sentinel"
        except Exception as error:
            error_text = f"{type(error).__name__}: {error}"
            pc = 0
            try:
                pc = int(self.ql.arch.regs.arch_pc)
            except Exception:
                try:
                    pc = int(self.ql.arch.regs.read("pc"))
                except Exception:
                    pass
            opcode = safe_read(self.ql, pc, 16) if pc else b""
            print(f"[!] Emulation failed in {target.name}: {error_text}")
            print(f"[!] Crash PC: {pc:#x}; bytes: {opcode.hex()}")
            if pc and self.is_module_address(pc):
                print(f"[!] Crash ELF VA: {self.elf_va_from_runtime(pc):#x}")
            if self.args.debug_traceback:
                traceback.print_exc()
            self.events.write({
                "type": "emulation-crash",
                "function": target.name,
                "error": error_text,
                "pc": pc,
                "elf_va": self.elf_va_from_runtime(pc) if pc and self.is_module_address(pc) else None,
                "opcode_hex": opcode.hex(),
            })
        finally:
            self._flush_pending_write_windows()

        after = self.snapshot_module()
        duration = time.monotonic() - started

        changed = self.process_snapshot_difference(
            before,
            after,
            function=target.name,
        )

        self.events.write(
            {
                "type": "function-end",
                "name": target.name,
                "success": success,
                "error": error_text,
                "duration_seconds": duration,
                "changed_bytes": changed,
                "instructions": self.instruction_count,
                "last_code_address": self.last_code_address,
            }
        )

        self.function_results.append({"name": target.name, "elf_va": target.elf_va,
                                      "success": success, "error": error_text,
                                      "instructions": self.instruction_count})
        if not success:
            print(f"[!] {target.name} incomplete: {error_text}")
        print(
            f"[+] {target.name}: changed {changed} module bytes "
            f"in {duration:.3f}s"
        )
        self.current_snapshot = after
        self.active_function = None

    def process_snapshot_difference(
        self,
        before: dict[int, bytes],
        after: dict[int, bytes],
        *,
        function: str,
    ) -> int:
        changed_total = 0

        for segment in self.metadata.load_segments:
            old = before.get(segment.index, b"")
            new = after.get(segment.index, b"")
            size = min(len(old), len(new))
            if not size:
                continue

            changed_runs: list[tuple[int, int]] = []
            run_start: Optional[int] = None

            for index in range(size):
                differs = old[index] != new[index]
                if differs and run_start is None:
                    run_start = index
                elif not differs and run_start is not None:
                    changed_runs.append((run_start, index))
                    run_start = None

            if run_start is not None:
                changed_runs.append((run_start, size))

            for start, end in changed_runs:
                changed_total += end - start
                elf_va = segment.virtual_address + start
                runtime = self.runtime_from_va(elf_va)
                data = new[start:end]

                self.events.write(
                    {
                        "type": "module-change",
                        "function": function,
                        "segment_index": segment.index,
                        "elf_va": elf_va,
                        "runtime_address": runtime,
                        "size": len(data),
                        "before_sha256": sha256_hex(old[start:end]),
                        "after_sha256": sha256_hex(data),
                        "printable_ratio": printable_ratio(data),
                    }
                )

                scan_start = max(0, start - self.args.diff_context)
                scan_end = min(
                    len(new),
                    end + self.args.diff_context,
                )
                scan_data = new[scan_start:scan_end]
                self.scan_bytes(
                    scan_data,
                    source=f"module-diff:{function}",
                    runtime_base=self.runtime_from_va(
                        segment.virtual_address + scan_start
                    ),
                    function=function,
                    transient=False,
                )

                self.patch_file_backed_range(
                    segment,
                    segment_offset=start,
                    data=data,
                )

                if end > segment.file_size:
                    external_start = max(start, segment.file_size)
                    external_data = new[external_start:end]
                    if external_data:
                        name = (
                            f"module_nobits_seg{segment.index}_"
                            f"va_{segment.virtual_address + external_start:x}_"
                            f"{sha256_hex(external_data)[:12]}.bin"
                        )
                        (self.external_dir / name).write_bytes(
                            external_data
                        )

        return changed_total

    def patch_file_backed_range(
        self,
        segment: LoadSegment,
        *,
        segment_offset: int,
        data: bytes,
    ) -> None:
        if segment_offset >= segment.file_size:
            return

        patch_size = min(
            len(data),
            segment.file_size - segment_offset,
        )
        if patch_size <= 0:
            return

        file_offset = segment.file_offset + segment_offset
        file_end = file_offset + patch_size

        if file_end > len(self.patched):
            padding_needed = file_end - len(self.patched)
            self.patched.extend(b"\x00" * padding_needed)

        self.patched[file_offset:file_end] = data[:patch_size]

    def scan_static_crypto_signatures(self) -> None:
        findings: list[dict[str, Any]] = []
        raw = bytes(self.original)

        def add_bytes(kind: str, pattern: bytes, algorithm: str) -> None:
            start = 0
            while True:
                offset = raw.find(pattern, start)
                if offset < 0:
                    break
                start = offset + 1
                elf_va = None
                for segment in self.metadata.load_segments:
                    if segment.file_offset <= offset < segment.file_offset + segment.file_size:
                        elf_va = segment.virtual_address + offset - segment.file_offset
                        break
                findings.append({
                    "type": kind,
                    "algorithm": algorithm,
                    "file_offset": offset,
                    "elf_va": elf_va,
                    "size": len(pattern),
                })

        add_bytes("aes-sbox", AES_SBOX, "AES software/table implementation")
        add_bytes("aes-rcon", AES_RCON, "possible AES key schedule")
        for constant in CHACHA_CONSTANTS:
            add_bytes("chacha-constant", constant, "ChaCha/Salsa-family implementation")

        for name, elf_va in sorted(self.metadata.symbols.items()):
            lowered = name.lower()
            if any(token in lowered for token in (
                "aes", "evp_decrypt", "evp_cipher", "chacha", "arc4", "rc4",
                "mbedtls_aes", "sodium", "decrypt", "cipher",
            )):
                findings.append({
                    "type": "crypto-symbol",
                    "algorithm": "symbol-name hint",
                    "name": name,
                    "elf_va": elf_va,
                })

        if self.capstone_arm64 is not None:
            for segment in self.metadata.load_segments:
                if not (segment.flags & 1) or not segment.file_size:
                    continue
                data = raw[
                    segment.file_offset:segment.file_offset + segment.file_size
                ]
                try:
                    instructions = self.capstone_arm64.disasm(
                        data,
                        segment.virtual_address,
                    )
                    for instruction in instructions:
                        if instruction.mnemonic.lower() in ARM64_AES_MNEMONICS:
                            findings.append({
                                "type": "armv8-aes-instruction",
                                "algorithm": "AES hardware instructions",
                                "mnemonic": instruction.mnemonic,
                                "op_str": instruction.op_str,
                                "elf_va": instruction.address,
                                "file_offset": segment.file_offset + instruction.address - segment.virtual_address,
                            })
                            if sum(1 for item in findings if item["type"] == "armv8-aes-instruction") >= self.args.max_static_crypto_instructions:
                                break
                except Exception:
                    pass

        self.crypto_signatures = findings
        path = self.output_dir / "crypto_signatures.json"
        path.write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if findings:
            counts = Counter(item["type"] for item in findings)
            summary = ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
            print(f"[+] Static crypto signatures: {summary}")
        else:
            print("[+] Static crypto signatures: none recognised")

    def collect_final_module_state(self) -> None:
        assert self.ql is not None

        final_snapshot = self.snapshot_module()
        self.process_snapshot_difference(
            self.initial_snapshot,
            final_snapshot,
            function="FINAL_CUMULATIVE_STATE",
        )

        # A byte-wise diff naturally splits strings wherever a plaintext byte
        # happens to equal its original encrypted byte. Scan each complete
        # final segment so long strings survive those unchanged-byte gaps.
        if self.args.scan_full_final_segments:
            for segment in self.metadata.load_segments:
                data = final_snapshot.get(segment.index, b"")
                if not data:
                    continue
                self.scan_bytes(
                    data,
                    source=(
                        f"full-final-segment:{segment.index}"
                    ),
                    runtime_base=self.runtime_from_va(
                        segment.virtual_address
                    ),
                    function="FINAL_CUMULATIVE_STATE",
                    transient=False,
                )

        self.current_snapshot = final_snapshot

    def collect_dirty_external_buffers(self) -> None:
        assert self.ql is not None

        ranges = self.external_dirty.merged(
            gap=self.args.external_merge_gap
        )

        for index, (start, end) in enumerate(ranges):
            if self.is_probable_stack_address(start):
                continue

            size = min(
                end - start,
                self.args.max_external_buffer,
            )
            if size <= 0:
                continue

            data = safe_read(self.ql, start, size)
            if not data or not any(data):
                continue

            digest = sha256_hex(data)
            name = f"external_{index:04d}_{start:016x}_{digest[:12]}.bin"
            path = self.external_dir / name
            path.write_bytes(data)

            self.events.write(
                {
                    "type": "external-buffer",
                    "runtime_address": start,
                    "size": len(data),
                    "sha256": digest,
                    "path": str(path),
                    "printable_ratio": printable_ratio(data),
                }
            )

            self.scan_bytes(
                data,
                source=f"external-buffer:{name}",
                runtime_base=start,
                function=None,
                transient=False,
            )

            if self.args.carve_magic:
                self.carve_magic_buffers(data, start, name)

    def carve_magic_buffers(
        self,
        data: bytes,
        runtime_base: int,
        source_name: str,
    ) -> None:
        magic_items: list[tuple[bytes, str]] = [
            *[(magic, "dex") for magic in DEX_MAGICS],
            (CDEX_MAGIC, "cdex"),
            *[(magic, "zip") for magic in ZIP_MAGICS],
            (ELF_MAGIC, "elf"),
        ]

        carved_offsets: set[tuple[int, str]] = set()

        for magic, kind in magic_items:
            search_from = 0
            while True:
                offset = data.find(magic, search_from)
                if offset < 0:
                    break
                search_from = offset + 1

                key = (offset, kind)
                if key in carved_offsets:
                    continue
                carved_offsets.add(key)

                carved = self._bounded_carve(data[offset:], kind)
                if not carved:
                    continue

                digest = sha256_hex(carved)
                suffix = {
                    "dex": ".dex",
                    "cdex": ".cdex",
                    "zip": ".zip",
                    "elf": ".so",
                }[kind]
                filename = (
                    f"{kind}_{runtime_base + offset:016x}_"
                    f"{digest[:12]}{suffix}"
                )
                path = self.carved_dir / filename
                path.write_bytes(carved)

                print(
                    f"[+] Carved {kind.upper()} from {source_name}: "
                    f"{path.name} ({len(carved)} bytes)"
                )
                self.events.write(
                    {
                        "type": "carved-buffer",
                        "kind": kind,
                        "runtime_address": runtime_base + offset,
                        "size": len(carved),
                        "sha256": digest,
                        "path": str(path),
                    }
                )

    def _bounded_carve(self, data: bytes, kind: str) -> bytes:
        if kind in ("dex", "cdex"):
            if len(data) < 0x24:
                return b""
            file_size = int.from_bytes(data[0x20:0x24], "little")
            if (
                file_size < 0x70
                or file_size > self.args.max_carve_size
                or file_size > len(data)
            ):
                return b""
            return data[:file_size]

        if kind == "elf":
            if len(data) < 0x40:
                return b""
            # Without parsing the in-memory ELF, retain a bounded window.
            return data[: min(len(data), self.args.max_carve_size)]

        if kind == "zip":
            # ZIP length requires central-directory parsing. Preserve a bounded
            # region; standard repair tools may recover truncated archives.
            return data[: min(len(data), self.args.max_carve_size)]

        return b""

    def _select_auto_xor_key(
        self,
    ) -> Optional[tuple[bytes, int, int, int]]:
        """
        Select the most frequently reused transform key pointer.

        Returns:
            (key_bytes, target_elf_va, runtime_pointer, hit_count)
        """
        assert self.ql is not None

        ranked: list[tuple[int, int, int]] = []
        for target, counter in self.auto_xor_key_pointers.items():
            for pointer, count in counter.items():
                ranked.append((count, target, pointer))

        ranked.sort(reverse=True)

        for count, target, pointer in ranked:
            if count < self.args.auto_xor_min_key_hits:
                continue
            if pointer < PAGE_SIZE:
                continue
            try:
                key = bytes(
                    self.ql.mem.read(
                        pointer,
                        self.args.auto_xor_key_length,
                    )
                )
            except Exception:
                continue
            if not key or not any(key):
                continue

            self.auto_xor_key_pointer = pointer
            self.auto_xor_key_target = target
            self.auto_xor_key_hits = count
            return key, target, pointer, count

        return None

    def run_optional_xor_sweep(self) -> None:
        key: Optional[bytes] = None
        key_source = ""
        key_pointer: Optional[int] = None
        key_target: Optional[int] = None
        key_hits = 0

        if self.args.xor_key_hex:
            key = bytes.fromhex(self.args.xor_key_hex)
            key_source = "explicit-hex"

        elif self.args.xor_key_va is not None:
            offset = va_to_file_offset(
                self.metadata,
                self.args.xor_key_va,
            )
            if offset is None:
                raise RuntimeError(
                    f"XOR key VA {self.args.xor_key_va:#x} is not "
                    "file-backed"
                )
            end = offset + self.args.xor_key_length
            key = bytes(self.original[offset:end])
            key_source = (
                f"explicit-va:{self.args.xor_key_va:#x}"
            )

        elif self.args.auto_xor_from_transform:
            selected = self._select_auto_xor_key()
            if selected is not None:
                key, key_target, key_pointer, key_hits = selected
                key_source = (
                    f"transform:{key_target:#x}@{key_pointer:#x}"
                )
            else:
                # fallback to ghidra static extraction if dynamic extraction crashed
                static_selected = self._discover_static_xor_key()
                if static_selected is not None:
                    key, key_target = static_selected
                    key_source = f"static-heuristic:{key_target:#x}"
                    key_pointer = self.runtime_from_va(key_target) if key_target else None
                    key_hits = 1

        if not key:
            return

        print(
            f"[+] Running rotating-XOR discovery sweep with "
            f"{len(key)}-byte key from {key_source}"
        )

        if key_pointer is not None:
            key_elf_va = (
                self.elf_va_from_runtime(key_pointer)
                if self.is_module_address(key_pointer)
                else None
            )
            key_va_text = (
                f"{key_elf_va:#x}"
                if key_elf_va is not None
                else "external"
            )
            print(
                f"[+] Auto key: target={key_target:#x}, "
                f"pointer={key_pointer:#x}, "
                f"elf_va={key_va_text}, hits={key_hits}"
            )

        self.events.write({
            "type": "xor-sweep",
            "key_source": key_source,
            "key_length": len(key),
            "key_sha256": sha256_hex(key),
            "target_elf_va": key_target,
            "runtime_pointer": key_pointer,
            "hit_count": key_hits,
        })

        raw = bytes(self.original)
        for phase in range(len(key)):
            self.scan_bytes(xor_bytes(raw, key, phase), source=f"xor-phase:{phase}",
                            file_base=0, transient=False)

    def write_outputs(self) -> tuple[Path, Path]:
        # This catches long strings reconstructed from multiple transient
        # decoder calls, even when no single transform output contained the
        # complete string.
        if self.args.scan_full_patched_elf:
            self.scan_bytes(
                bytes(self.patched),
                source="full-patched-analysis-elf",
                file_base=0,
                runtime_base=None,
                function=None,
                transient=False,
            )

        strings_path = self.output_dir / "strings.txt"
        normalised_strings_path = self.output_dir / "strings_normalised.txt"
        output_elf = (
            self.output_dir
            / f"{self.metadata.path.stem}_analysis.so"
        )

        lines: list[str] = []
        normalised_lines: list[str] = []
        normalised_seen: set[str] = set()
        unique_overlay_strings: OrderedDict[str, None] = OrderedDict()

        for candidate in self.candidates.values():
            location = ""
            if candidate.file_offset is not None:
                location = f"file={candidate.file_offset:#x}"
                if candidate.elf_va is not None:
                    location += f" va={candidate.elf_va:#x}"
            elif candidate.elf_va is not None:
                location = f"va={candidate.elf_va:#x}"
            elif candidate.runtime_address is not None:
                location = f"runtime={candidate.runtime_address:#x}"

            flags = []
            if candidate.transient:
                flags.append("transient")
            if candidate.function:
                flags.append(candidate.function)

            line = "\t".join(
                part
                for part in (
                    location,
                    candidate.encoding,
                    ",".join(flags),
                    candidate.source,
                    candidate.text,
                )
                if part
            )
            lines.append(line)
            unique_overlay_strings.setdefault(candidate.text, None)

            if self.args.normalise_signals:
                normalised = normalise_signal_text(candidate.text)
                if normalised and normalised not in normalised_seen:
                    normalised_seen.add(normalised)
                    normalised_lines.append(normalised)
                    if normalised != candidate.text:
                        unique_overlay_strings.setdefault(normalised, None)

        strings_path.write_text(
            "\n".join(lines) + ("\n" if lines else ""),
            encoding="utf-8",
        )
        normalised_strings_path.write_text(
            "\n".join(normalised_lines) + ("\n" if normalised_lines else ""),
            encoding="utf-8",
        )

        output_data = bytearray(self.patched)

        if not self.args.no_append_overlay and unique_overlay_strings:
            marker = (
                b"\x00\n"
                b"=== QILING_DECRYPTED_STRING_OVERLAY_ANALYSIS_ONLY ===\n"
            )
            output_data.extend(marker)
            for text in unique_overlay_strings:
                encoded = text.encode("utf-8", errors="replace")
                output_data.extend(encoded)
                output_data.append(0)
            output_data.extend(
                b"\n=== END_QILING_DECRYPTED_STRING_OVERLAY ===\n"
            )

        output_elf.write_bytes(output_data)

        transform_summary = []
        for target, stats in sorted(
            self.transform_stats.items(),
            key=lambda item: (-item[1].get("interesting", 0), -item[1].get("calls", 0), item[0]),
        ):
            transform_summary.append({
                "target_elf_va": target,
                "calls": stats.get("calls", 0),
                "interesting": stats.get("interesting", 0),
                "outputs": stats.get("outputs", 0),
                "aborted": stats.get("aborted", 0),
                "key_pointers": [
                    {"pointer": pointer, "count": count}
                    for pointer, count in self.transform_key_pointers[target].most_common()
                ],
            })
        (self.output_dir / "transform_candidates.json").write_text(
            json.dumps(transform_summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        signals = {}
        for label, pattern in (('AssetManager', r'assetmanager'), ('GetAsset', r'getassets?'),
                               ('ClassLoader', r'classloader')):
            records = []
            for candidate in self.candidates.values():
                match = re.search(pattern, candidate.text, re.IGNORECASE)
                if match:
                    kind = ('post-init-xor' if candidate.source.startswith('post-init-xor:')
                            else 'static-xor' if candidate.source.startswith(('static-xor:', 'xor-phase:'))
                            else 'static-file' if candidate.source == 'full-patched-analysis-elf'
                            else 'runtime-memory')
                    records.append({'text': candidate.text, 'source': candidate.source,
                                    'evidence_kind': kind, 'file_offset': candidate.file_offset,
                                    'matched_reference': match.group(),
                                    'match_file_offset': (candidate.file_offset + match.start() *
                                                          (2 if candidate.encoding == 'utf-16le' else 1)
                                                          if candidate.file_offset is not None else None),
                                    'elf_va': candidate.elf_va,
                                    'match_elf_va': (candidate.elf_va + match.start() *
                                                     (2 if candidate.encoding == 'utf-16le' else 1)
                                                     if candidate.elf_va is not None else None),
                                    'function': candidate.function})
            signals[label] = {'found': bool(records), 'evidence': records}
        self.signals_complete = all(record['found'] for record in signals.values())
        (self.output_dir / 'signals.json').write_text(json.dumps({
            'all_found': self.signals_complete, 'signals': signals,
            'input': str(self.metadata.path), 'input_sha256': self.input_sha256,
            'note': 'String evidence does not establish execution or maliciousness by itself.',
        }, indent=2) + '\n')
        print('[+] Target references: ' + ', '.join(f"{name}={'found' if value['found'] else 'missing'}"
                                                  for name, value in signals.items()))

        manifest = {
            "input": str(self.metadata.path),
            "output_elf": str(output_elf),
            "strings_file": str(strings_path),
            "normalised_strings_file": str(normalised_strings_path),
            "crypto_signatures_file": (str(self.output_dir / "crypto_signatures.json")
                                       if (self.output_dir / "crypto_signatures.json").exists() else None),
            "input_sha256": sha256_hex(bytes(self.original)),
            "output_sha256": sha256_hex(bytes(output_data)),
            "module_base": self.module_base,
            "load_bias": self.load_bias,
            "candidate_strings": len(self.candidates),
            "loader_input": str(self.loader_path),
            "loader_input_sha256": sha256_hex(self.loader_path.read_bytes()),
            "metadata_diagnostics": self.metadata.diagnostics,
            "static_only": self.args.static_only,
            "runtime_error": self.runtime_error,
            "constructors_complete": bool(self.function_results) and all(r['success'] for r in self.function_results),
            "functions": self.function_results,
            "target_signals_complete": self.signals_complete,
            "xor_discoveries": self.xor_discoveries,
            "analysis_only": True,
            "overlay_appended": not self.args.no_append_overlay and bool(unique_overlay_strings),
        }
        (self.output_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        return output_elf, strings_path

    def close(self) -> None:
        self.events.close()
        self.strings_jsonl.close()
        self.transforms_jsonl.close()

def prepare_loader_image(target_path: Path, output_file: Path, *, repair_sizes: bool = False) -> Path:
    """Make an analysis copy only when evidence supports a header change.

    A normal filesz < memsz describes zero-filled BSS, not truncation. Extend
    filesz only to a file-backed SHF_ALLOC section with the same VA/file mapping.
    """
    image = ElfImage(target_path.read_bytes())
    data = bytearray(image.without_sections() if image.section_error else image.data)
    if repair_sizes:
        for segment in image.programs:
            if segment.type != 1:
                continue
            end = segment.filesz
            for section in image.sections:
                _, typ, flags, va, offset, size, *_ = section
                if typ in (0, 8) or not flags & 2 or not size:
                    continue
                if (segment.va <= va and va + size <= segment.va + segment.memsz
                        and offset - segment.offset == va - segment.va):
                    end = max(end, offset + size - segment.offset)
            if end != segment.filesz:
                image.range(segment.offset, end)
                # Never consume another segment's data or the section table.
                limits = [p.offset for p in image.programs if p.type == 1 and p.offset > segment.offset]
                if image.shoff > segment.offset:
                    limits.append(image.shoff)
                if limits and segment.offset + end > min(limits):
                    continue
                location = segment.header_offset + (16 if image.bits == 32 else 32)
                struct.pack_into(image.endian + ('I' if image.bits == 32 else 'Q'), data, location, end)
                print(f"[+] Section-backed PT_LOAD repair {segment.index}: {segment.filesz:#x} -> {end:#x}")
    if data == image.data:
        return target_path
    if output_file.resolve() == target_path.resolve():
        raise ValueError('Loader copy must not overwrite the input ELF')
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_bytes(data)
    return output_file


def fix_elf_headers(target_path: Path, output_file: Optional[Path] = None) -> Path:
    """Backward-compatible entry point; a no-op always returns the input path."""
    output_file = output_file or target_path.with_name(f"{target_path.stem}_fixed{target_path.suffix}")
    return prepare_loader_image(target_path, output_file, repair_sizes=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Emulate Android ELF initialisers, reconstruct changed "
            "file-backed bytes, and collect plaintext strings."
        )
    )
    parser.add_argument("elf", type=Path)
    parser.add_argument(
        "--rootfs",
        type=Path,
        help="Qiling rootfs (default: an empty directory under the output directory)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory (default: <elf_stem>_reconstruction)",
    )
    parser.add_argument(
        "--profile",
        help="Optional Qiling profile file",
    )
    parser.add_argument(
        "--verbose",
        choices=("off", "disabled", "default", "debug"),
        default="off",
    )

    parser.add_argument(
        "--execute-init",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Execute DT_INIT and DT_INIT_ARRAY (default: true)",
    )
    parser.add_argument(
        "--execute-jni-onload",
        action="store_true",
        help="Execute exported JNI_OnLoad with --jni-args",
    )
    parser.add_argument(
        "--jni-args",
        type=parse_int,
        nargs="*",
        default=(0, 0),
        help="Arguments passed to JNI_OnLoad (default: 0 0)",
    )
    parser.add_argument(
        "--extra-symbol",
        action="append",
        default=[],
        metavar="SYMBOL[:ARG0,ARG1]",
        help="Execute an additional exported/local symbol",
    )
    parser.add_argument(
        "--extra-offset",
        type=parse_int,
        action="append",
        default=[],
        metavar="ELF_VA",
        help="Execute an additional function at an ELF virtual address",
    )
    parser.add_argument(
        "--ghidra-image-base",
        type=parse_int,
        default=0,
        help="Subtract this image base from --ghidra-function addresses",
    )
    parser.add_argument(
        "--ghidra-function",
        type=parse_named_address,
        action="append",
        default=[],
        metavar="NAME=ADDRESS",
        help="Execute a function using its displayed Ghidra address",
    )
    parser.add_argument(
        "--auto-init-symbols",
        action="store_true",
        help="Also execute symbols resembling INIT/datadiv initialisers",
    )
    parser.add_argument(
        "--auto-decrypt-symbols",
        action="store_true",
        help="Also execute symbols containing decrypt with zero/default arguments; risky",
    )
    parser.add_argument(
        "--scan-init-arrays",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Scan writable PT_LOAD regions when dynamic init metadata is absent",
    )
    parser.add_argument(
        "--execute-scanned-init-arrays",
        action="store_true",
        help="Execute heuristic init-array candidates; may include false positives",
    )
    parser.add_argument(
        "--max-scanned-init-arrays",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--max-scanned-init-targets",
        type=int,
        default=32,
    )
    parser.add_argument(
        "--report-scanned-init-arrays",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--jni-onload-address",
        type=parse_int,
        help="JNI_OnLoad ELF VA when the symbol is stripped",
    )
    parser.add_argument(
        "--fake-jni",
        action="store_true",
        help="Pass a minimal fake JavaVM to JNI_OnLoad",
    )

    parser.add_argument(
        "--memory-patch",
        type=parse_memory_patch,
        action="append",
        default=[],
        metavar="ELF_VA:HEX",
        help="Inject a flag/key/value before execution",
    )
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
    )
    parser.add_argument(
        "--fs-map",
        action="append",
        default=[],
        metavar="GUEST=HOST",
        help="Map an emulated path to a host path",
    )
    parser.add_argument(
        "--stub-api",
        type=parse_stub,
        action="append",
        default=[],
        metavar="NAME=RETURN",
    )
    parser.add_argument(
        "--stub-syscall",
        type=parse_stub,
        action="append",
        default=[],
        metavar="NAME=RETURN",
    )
    parser.add_argument(
        "--force-tls",
        action="store_true",
        help="Install the script's minimal AArch64 TLS even if one exists",
    )
    parser.add_argument(
        "--repair-relocations",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Repair AArch64 RELATIVE/GOT/PLT/RELR entries in emulated memory "
            "before resolving initialisers (default: true)"
        ),
    )
    parser.add_argument(
        "--heuristic-rebase-pointers",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Rebase low function pointers in writable PT_LOAD ranges; useful "
            "for stripped Android pointer tables (default: true)"
        ),
    )
    parser.add_argument(
        "--stub-unknown-imports",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Return zero from imported functions without a dedicated model",
    )
    parser.add_argument(
        "--android-property",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help=(
            "Value returned by __system_property_get. Repeat as needed, e.g. "
            "--android-property smey37t=3se6cq1lsm"
        ),
    )
    parser.add_argument(
        "--auxv-hwcap",
        type=parse_int,
        default=0x100,
        help="Value returned for getauxval(AT_HWCAP)",
    )
    parser.add_argument(
        "--auxv-hwcap2",
        type=parse_int,
        default=0,
        help="Value returned for getauxval(AT_HWCAP2)",
    )
    parser.add_argument(
        "--max-import-copy",
        type=parse_int,
        default=0x1000000,
    )
    parser.add_argument(
        "--max-import-allocation",
        type=parse_int,
        default=0x1000000,
    )

    parser.add_argument(
        "--anti-debug",
        action="store_true",
        help="Enable conservative ptrace/prctl/self-kill and TracerPid bypasses",
    )
    parser.add_argument(
        "--skip-breakpoints",
        action="store_true",
        help="Replace reached AArch64 BRK/HLT instructions with NOP",
    )
    parser.add_argument(
        "--debug-traceback",
        action="store_true",
        help="Print Python traceback and crash PC/opcode on emulation errors",
    )
    parser.add_argument(
        "--crypto-profile-json",
        type=Path,
        action="append",
        default=[],
        help=(
            "Load custom transform calling-convention profiles from JSON. "
            "Useful for proprietary dst/src/length APIs."
        ),
    )
    parser.add_argument(
        "--detect-inline-crypto",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Detect reached ARMv8 AES instructions and intensify write-window "
            "capture around them (default: true)"
        ),
    )
    parser.add_argument(
        "--inline-crypto-window",
        type=parse_int,
        default=512,
        help="Instruction window retained after a reached ARMv8 AES instruction",
    )
    parser.add_argument(
        "--max-inline-crypto-events",
        type=parse_int,
        default=256,
    )
    parser.add_argument(
        "--max-static-crypto-instructions",
        type=parse_int,
        default=256,
    )
    parser.add_argument(
        "--normalise-signals",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Write strings_normalised.txt with Java class/URL boundary "
            "artefacts removed while retaining raw strings.txt"
        ),
    )

    parser.add_argument(
        "--discover-transforms",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Blindly rank internal functions that turn argument buffers into structured plaintext",
    )
    parser.add_argument(
        "--transform-context",
        type=parse_int,
        default=0x100,
        help=(
            "Bytes scanned around each transformed buffer to join adjacent "
            "short decrypted chunks"
        ),
    )
    parser.add_argument(
        "--transform-min-length",
        type=parse_int,
        default=3,
    )
    parser.add_argument(
        "--transform-max-length",
        type=parse_int,
        default=0x4000,
    )
    parser.add_argument(
        "--transform-printable-ratio",
        type=float,
        default=0.70,
    )
    parser.add_argument(
        "--transform-ratio-gain",
        type=float,
        default=0.25,
    )
    parser.add_argument(
        "--key-probe-length",
        type=parse_int,
        default=32,
    )
    parser.add_argument(
        "--max-transform-depth",
        type=int,
        default=4096,
    )

    parser.add_argument(
        "--timeout-us",
        type=parse_int,
        default=10_000_000,
        help="Qiling per-function timeout in microseconds",
    )
    parser.add_argument(
        "--max-instructions",
        type=parse_int,
        default=5_000_000,
        help="Per-function instruction limit; 0 means unlimited",
    )
    parser.add_argument(
        "--stack-window",
        type=parse_int,
        default=0x800000,
        help="Exclude writes within this distance of initial SP",
    )

    parser.add_argument(
        "--realtime-writes",
        action="store_true",
        help=(
            "Scan memory after write instructions to catch transient "
            "plaintext; high overhead"
        ),
    )
    parser.add_argument(
        "--write-context",
        type=parse_int,
        default=0x80,
        help="Bytes scanned around each write",
    )
    parser.add_argument(
        "--write-merge-gap",
        type=parse_int,
        default=0x20,
    )
    parser.add_argument(
        "--max-realtime-window",
        type=parse_int,
        default=0x2000,
    )
    parser.add_argument(
        "--save-realtime-windows",
        action="store_true",
    )

    parser.add_argument(
        "--external-merge-gap",
        type=parse_int,
        default=0x40,
    )
    parser.add_argument(
        "--max-external-buffer",
        type=parse_int,
        default=0x200000,
    )
    parser.add_argument(
        "--carve-magic",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument(
        "--max-carve-size",
        type=parse_int,
        default=0x4000000,
    )

    parser.add_argument(
        "--diff-context",
        type=parse_int,
        default=0x40,
        help="Bytes scanned around each final changed run",
    )
    parser.add_argument(
        "--min-string",
        type=int,
        default=4,
    )
    parser.add_argument(
        "--keywords",
        default=DEFAULT_KEYWORDS,
        help="Comma-separated case-insensitive signal strings",
    )
    parser.add_argument(
        "--print-all-strings",
        action="store_true",
        help="Collect all strings instead of keyword matches only",
    )
    parser.add_argument(
        "--no-utf16",
        action="store_true",
    )
    parser.add_argument(
        "--no-append-overlay",
        action="store_true",
        help=(
            "Do not append recovered strings to the analysis ELF. "
            "Without the overlay, strings only sees file-backed patches."
        ),
    )

    parser.add_argument(
        "--scan-full-final-segments",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Scan complete final PT_LOAD images instead of only changed runs "
            "(default: true)"
        ),
    )
    parser.add_argument(
        "--scan-full-patched-elf",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Scan the complete reconstructed ELF before writing output "
            "(default: true)"
        ),
    )
    parser.add_argument(
        "--auto-xor-from-transform",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "Use the most frequently reused discovered key pointer for a "
            "rotating-XOR phase sweep"
        ),
    )
    parser.add_argument(
        "--auto-xor-key-length",
        type=parse_int,
        default=32,
    )
    parser.add_argument(
        "--auto-xor-min-key-hits",
        type=parse_int,
        default=8,
    )
    parser.add_argument(
        "--xor-key-hex",
        help=(
            "Optional rotating-XOR discovery key. Discovery only; "
            "does not patch ambiguous phases."
        ),
    )
    parser.add_argument(
        "--xor-key-va",
        type=parse_int,
        help="Read an optional rotating-XOR key from this ELF VA",
    )
    parser.add_argument(
        "--xor-key-length",
        type=parse_int,
        default=32,
    )

    parser.add_argument(
        "--skip-jni-onload",
        action="store_true",
        help=(
            "Suppress the dedicated JNI_OnLoad symbol/address options; "
            "constructor recovery still runs."
        ),
    )

    parser.add_argument(
        "--blind",
        action="store_true",
        help=(
            "Enable automatic init-symbol search, heuristic init-array execution, "
            "transform discovery, anti-debug stubs, and reached BRK/HLT bypass"
        ),
    )

    parser.add_argument(
        "--auto-fix-headers",
        action="store_true",
        help="Repair PT_LOAD truncation only when file-backed allocated sections corroborate it; preserve BSS",
    )

    parser.add_argument('--static-only', action='store_true',
                        help='Recover static strings and corroborated XOR keys without running constructors')
    parser.add_argument('--discover-xor-keys', action=argparse.BooleanOptionalAction, default=True,
                        help='Discover corroborated XOR keys in original and post-initialization bytes (default: true)')
    parser.add_argument('--xor-key-lengths', type=lambda value: tuple(int(v, 0) for v in value.split(',')),
                        default=(1, 2, 4, 8, 16, 32), help='Comma-separated key lengths for static discovery')
    parser.add_argument('--xor-anchor', action='append', default=[],
                        help='Additional known plaintext anchor; requires independent corroboration')
    parser.add_argument('--max-xor-keys', type=int, default=16)
    parser.add_argument('--require-signals', action='store_true',
                        help='Exit 2 unless AssetManager, GetAsset(s), and ClassLoader evidence is recovered')

    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    if not args.elf.is_file():
        raise SystemExit(f"Input ELF does not exist: {args.elf}")
    if args.rootfs is not None and not args.rootfs.is_dir():
        raise SystemExit(f"Rootfs directory does not exist: {args.rootfs}")
    if not args.xor_key_lengths or any(not 1 <= n <= 256 for n in args.xor_key_lengths):
        raise SystemExit('--xor-key-lengths must contain lengths between 1 and 256')
    if not 1 <= args.max_xor_keys <= 256:
        raise SystemExit('--max-xor-keys must be between 1 and 256')
    if not 1 <= args.auto_xor_key_length <= 256 or not 1 <= args.xor_key_length <= 256:
        raise SystemExit('XOR key lengths must be between 1 and 256')
    if args.timeout_us < 0 or args.max_instructions < 0:
        raise SystemExit('Execution limits cannot be negative')
    if args.min_string < 2:
        raise SystemExit("--min-string must be at least 2")
    if args.xor_key_hex:
        try:
            bytes.fromhex(args.xor_key_hex)
        except ValueError as exc:
            raise SystemExit("--xor-key-hex is not valid hex") from exc


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    validate_arguments(args)

    if args.blind:
        args.auto_init_symbols = True
        args.scan_init_arrays = True
        args.execute_scanned_init_arrays = True
        args.fake_jni = args.execute_jni_onload and not args.skip_jni_onload
        args.discover_transforms = True
        args.auto_xor_from_transform = True
        args.anti_debug = True
        args.skip_breakpoints = True
        args.realtime_writes = True
        args.repair_relocations = True
        args.heuristic_rebase_pointers = True
        args.stub_unknown_imports = True

    output_dir = (args.out_dir or Path(f"{args.elf.stem}_reconstruction")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    input_path = args.elf.resolve()
    metadata = read_elf_metadata(input_path)
    loader_path = input_path
    if not args.static_only:
        loader_path = prepare_loader_image(input_path, output_dir / 'loader_input.so',
                                           repair_sizes=args.auto_fix_headers)
        if loader_path != input_path:
            repaired = read_elf_metadata(loader_path)
            metadata = dataclasses.replace(repaired, path=input_path,
                                           diagnostics=metadata.diagnostics + repaired.diagnostics)
    if metadata.machine not in {'AArch64', 'ARM64', 'ARM'}:
        raise SystemExit(f'Unsupported architecture {metadata.machine!r}; expected ARM/AArch64')
    if not metadata.little_endian and not args.static_only:
        raise SystemExit('Big-endian ELF supports --static-only; runtime models require little endian')
    if args.rootfs is None:
        args.rootfs = output_dir / 'rootfs'
        args.rootfs.mkdir(exist_ok=True)
    args.rootfs = args.rootfs.resolve()
    for diagnostic in metadata.diagnostics:
        print(f'[!] {diagnostic}')

    print(f"[+] Input: {metadata.path}")
    print(f"[+] Architecture: {metadata.machine}/{metadata.elf_class}")
    print(f"[+] PT_LOAD segments: {len(metadata.load_segments)}")
    print(f"[+] Output directory: {output_dir}")

    reconstructor = Reconstructor(args, metadata, output_dir)

    reconstructor.loader_path = loader_path
    try:
        reconstructor.discover_static_strings()
        if not args.static_only:
            try:
                reconstructor.create_qiling()
                reconstructor.scan_static_crypto_signatures()
                reconstructor.initial_snapshot = reconstructor.snapshot_module()
                reconstructor.current_snapshot = reconstructor.initial_snapshot
                sentinel = reconstructor._allocate_return_sentinel()
                targets = reconstructor.resolve_init_targets()
                if not targets:
                    print('[!] No executable targets; use --extra-symbol or --extra-offset.')
                for target in targets:
                    reconstructor.execute_target(target, sentinel)
                reconstructor.collect_final_module_state()
                reconstructor.collect_dirty_external_buffers()
                reconstructor.run_optional_xor_sweep()
            except Exception as error:
                reconstructor.runtime_error = f'{type(error).__name__}: {error}'
                reconstructor.events.write({'type': 'runtime-incomplete', 'error': reconstructor.runtime_error})
                print(f'[!] Runtime analysis incomplete: {reconstructor.runtime_error}')
                if args.debug_traceback:
                    traceback.print_exc()
        elif args.xor_key_hex or args.xor_key_va is not None:
            reconstructor.run_optional_xor_sweep()

        # Keep any recovered bytes even if initialization was partial. Their
        # evidence stage and constructor completion are recorded separately.
        if not args.static_only:
            reconstructor.discover_static_strings(post_init=True)

        output_elf, strings_path = reconstructor.write_outputs()

        print("\n[+] Reconstruction complete")
        print(f"[+] Analysis ELF: {output_elf}")
        print(f"[+] Strings:      {strings_path}")
        print(f"[+] Normalised:   {output_dir / 'strings_normalised.txt'}")
        if (output_dir / 'crypto_signatures.json').exists():
            print(f"[+] Crypto hints: {output_dir / 'crypto_signatures.json'}")
        print(f"[+] Events:       {output_dir / 'events.jsonl'}")
        print(f"[+] External:     {reconstructor.external_dir}")
        print(f"[+] Carved:       {reconstructor.carved_dir}")
        print(f"[+] Transforms:   {reconstructor.transform_dir}")
        print(f"[+] Keys:         {reconstructor.key_dir}")
        print(f"[+] Ranking:      {output_dir / 'transform_candidates.json'}")
        print()
        print(
            "Run:\n"
            f"  strings -a -n {args.min_string} "
            f"{output_elf} | "
            "grep -Ei "
            "'DexClassLoader|InMemoryDexClassLoader|AssetManager|"
            "assets|decrypt|ByteBuffer|https?://|json'"
        )
        print()
        print(
            "[!] The ELF is an analysis copy. Appended overlay strings may "
            "not correspond to file-backed runtime bytes."
        )
        return 2 if args.require_signals and not reconstructor.signals_complete else 0
    finally:
        reconstructor.close()


if __name__ == "__main__":
    raise SystemExit(main())
