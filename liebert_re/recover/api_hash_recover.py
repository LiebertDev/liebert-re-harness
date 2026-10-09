"""Generic Windows API-hashing cracker: given one integer
constant found in a binary, tries every common shellcode/malware API-hash
algorithm against every export name of a chosen system DLL (default
ntoskrnl.exe for kernel targets, but any local PE export table works) and
reports which (algorithm, export name) pair reproduces the constant.

WHY this exists (measured gap, real corpus, 2026-09-26): a driver/packer that
wants to call an API without leaving its name as a plaintext string (either
to defeat static string scanning, or because it never lays the name out
contiguously) commonly replaces the name with a precomputed hash and resolves
it at runtime by hashing every export of the target module until one
matches. Recovering the API set therefore does not require decoding
anything -- it requires the REVERSE of that same hash, which is cheap and
completely generic: nothing here is specific to one binary, one driver
family, or one hash constant. Searched first for an existing hash database
(FLARE's capa/floss packages, installed in this project's .venv) before
writing this -- neither ships a bundled hash->name lookup table, only
string/capability *detection* rules, so this thin layer fills that specific
gap rather than duplicating anything already present.

Algorithms included are the ones actually observed across public malware/
loader corpora (Metasploit block_api ROR13, countless custom ROL/ROR+add
variants, FNV-1a as used by many Cobalt-Strike-style loaders, djb2, zlib
CRC32, and a plain additive/multiplicative rolling hash) -- a reusable,
target-agnostic set, not one binary's specific constant.

Pure static analysis: only ever reads local files (the suspect binary is
never touched by this module; only a system DLL's export table is read).
"""
from __future__ import annotations

import zlib
import importlib
from pathlib import Path

DEFAULT_SYSTEM_DLL = r"C:\Windows\System32\ntoskrnl.exe"
_SEED_UNSET = object()


def _ror(value, bits, width=32):
    mask = (1 << width) - 1
    value &= mask
    bits %= width
    return ((value >> bits) | (value << (width - bits))) & mask


def _rol(value, bits, width=32):
    return _ror(value, width - bits, width)


def _hash_ror13_add(name: bytes) -> int:
    # Classic Metasploit/shellcode block_api hash: h = ror(h,13) + byte, per byte, seeded 0.
    h = 0
    for b in name:
        h = (_ror(h, 13) + b) & 0xFFFFFFFF
    return h


def _hash_rol7_xor(name: bytes) -> int:
    h = 0
    for b in name:
        h = (_rol(h, 7) ^ b) & 0xFFFFFFFF
    return h


def _hash_fnv1a_32(name: bytes) -> int:
    h = 0x811C9DC5
    for b in name:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def _hash_djb2(name: bytes) -> int:
    h = 5381
    for b in name:
        h = ((h * 33) + b) & 0xFFFFFFFF
    return h


def _hash_djb2_xor(name: bytes) -> int:
    h = 5381
    for b in name:
        h = ((h * 33) ^ b) & 0xFFFFFFFF
    return h


def _hash_crc32(name: bytes) -> int:
    return zlib.crc32(name) & 0xFFFFFFFF


def _hash_add_mul(name: bytes) -> int:
    h = 0
    for b in name:
        h = ((h + b) * 0x01003F) & 0xFFFFFFFF
    return h


def _hash_xxh3_64(name: bytes, seed: int = 0) -> int:
    """Compute XXH3-64 via the optional xxhash package, importing it on demand."""
    xxhash = importlib.import_module("xxhash")
    return xxhash.xxh3_64_intdigest(name, seed=seed)


ALGORITHMS = {
    "ror13_add": _hash_ror13_add,
    "rol7_xor": _hash_rol7_xor,
    "fnv1a_32": _hash_fnv1a_32,
    "djb2": _hash_djb2,
    "djb2_xor": _hash_djb2_xor,
    "crc32": _hash_crc32,
    "add_mul": _hash_add_mul,
    "xxh3_64": _hash_xxh3_64,
}
ALGORITHM_WIDTHS = {name: (64 if name == "xxh3_64" else 32) for name in ALGORITHMS}


# status values reuse the vocabulary of liebert_re/tools/binary.py
# (kernel_triage, rip_relative_iat_scan, ...): OK, ANALYSIS_LIMITED (could not
# look), INVALID_INPUT (the caller asked wrongly). They are ADDED beside the
# existing ``error`` strings, which are unchanged.
STATUS_OK = "OK"
STATUS_NOT_LOOKED = "ANALYSIS_LIMITED"
STATUS_USAGE = "INVALID_INPUT"


def _read_export_names(dll_path):
    """Returns ``(names, error, directory_present)``. ``names`` is None on error."""
    try:
        import pefile
    except ImportError:
        return None, "PEFILE_UNAVAILABLE", None
    p = Path(str(dll_path))
    if not p.is_file():
        return None, f"DLL_NOT_FOUND:{p}", None
    pe = None
    try:
        pe = pefile.PE(str(p), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        names = []
        present = hasattr(pe, "DIRECTORY_ENTRY_EXPORT")
        if present:
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if sym.name:
                    names.append(sym.name.decode(errors="replace"))
        return names, None, present
    except Exception as exc:
        return None, f"{type(exc).__name__}:{exc}", None
    finally:
        if pe is not None:
            pe.close()


def crack_api_hash(hash_values, dll_path=DEFAULT_SYSTEM_DLL, algorithms=None,
                    case_variants=("as_is", "lower", "upper"), append_null=(False, True), seed=_SEED_UNSET):
    """Given one or more candidate hash constants, brute-force every
    (algorithm, case-variant, null-terminator-included-or-not) combination
    against every exported name of ``dll_path`` and report exact matches.

    ``hash_values``: int or iterable of ints (the suspected hash constants
    pulled from disassembly, e.g. an immediate compared against a running
    hash accumulator).
    ``dll_path``: local system DLL to hash exports of (default ntoskrnl.exe
    for kernel-driver targets; pass any PE for a user-mode target).
    Returns a structured dict; never raises. A caller with zero matches gets
    ``matches: []`` plus the exact algorithm/variant/export space searched,
    not a silent empty return.

    A supplied seed must be an unsigned 64-bit integer and requires a selected
    algorithm that accepts it (currently XXH3); omitted XXH3 seeds use zero.
    Missing xxhash leaves mixed searches partial: available algorithms' matches
    are returned with ``ok: False``, ``ANALYSIS_LIMITED`` and an explicit
    limitation identifying the unsearched algorithm. XXH3-only searches fail
    closed without reading exports.
    """
    seed_supplied = seed is not _SEED_UNSET
    if seed_supplied:
        if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 0xFFFFFFFFFFFFFFFF:
            return {"ok": False, "status": STATUS_USAGE, "error": "INVALID_SEED"}
    else:
        seed = 0
    if isinstance(hash_values, int):
        hash_values = [hash_values]
    try:
        raw_values = [int(v) for v in hash_values]
    except (TypeError, ValueError):
        return {"ok": False, "status": STATUS_USAGE, "error": "INVALID_HASH_VALUE"}
    # Negative constants retain the historical 32-bit unsigned interpretation.
    # Positive wide values stay wide so they can be matched by 64-bit algorithms,
    # and can never alias a 32-bit result through truncation.
    hash_inputs = {v if v >= 0 else v & 0xFFFFFFFF: v for v in raw_values}

    # Keep the default search compatible with installs that do not have the
    # optional package; XXH3 is selected explicitly by its algorithm name.
    selected_algorithms = algorithms if algorithms else [
        name for name in ALGORITHMS if ALGORITHM_WIDTHS[name] == 32
    ]
    algo_set = {k: fn for k, fn in ALGORITHMS.items() if k in selected_algorithms}
    unknown = [a for a in (algorithms or []) if a not in ALGORITHMS]
    if unknown:
        return {"ok": False, "status": STATUS_USAGE, "error": "UNKNOWN_ALGORITHM", "unknown": unknown,
                "available": sorted(ALGORITHMS)}

    if seed_supplied and "xxh3_64" not in algo_set:
        return {"ok": False, "status": STATUS_USAGE, "error": "UNSUPPORTED_SEED"}

    missing_dependency = {}
    search_limitations = {}
    if "xxh3_64" in algo_set:
        try:
            importlib.import_module("xxhash")
        except ImportError:
            missing_dependency = {"error": "OPTIONAL_DEPENDENCY_MISSING", "dependency": "xxhash",
                                  "algorithm": "xxh3_64"}
            del algo_set["xxh3_64"]
            if not algo_set:
                return {"ok": False, "status": STATUS_NOT_LOOKED, **missing_dependency}
            search_limitations = {"algorithms_not_searched": ["xxh3_64"],
                                  "limitations": [missing_dependency]}

    names, err, directory_present = _read_export_names(dll_path)
    if names is None:
        return {"ok": False, "status": STATUS_NOT_LOOKED, "error": err, **search_limitations}
    if not names:
        # Zero names to hash against is not "searched, found nothing": the
        # question's domain is empty, so nothing was measured. A directory that
        # is missing and one that is present but holds no names (measured on an
        # owned PE: pefile parses it with zero symbols) leave the analyst in the
        # same place, so both get this code; export_directory_present tells them apart.
        return {"ok": False, "status": STATUS_NOT_LOOKED, "error": "NO_EXPORT_DIRECTORY",
                "dll_path": str(dll_path), "export_directory_present": directory_present,
                "message": "The file has no named exports, so no hash was compared; this is not a search that found nothing.",
                **search_limitations}

    matches = []
    for name in names:
        for variant in case_variants:
            text = {"as_is": name, "lower": name.lower(), "upper": name.upper()}[variant]
            for null in append_null:
                candidate = text.encode("ascii", errors="ignore") + (b"\x00" if null else b"")
                for algo_name, fn in algo_set.items():
                    width = ALGORITHM_WIDTHS[algo_name]
                    h = fn(candidate, seed=seed) if width == 64 else fn(candidate)
                    if h in hash_inputs and h < (1 << width):
                        match = {
                            "hash_input": hex(hash_inputs[h]), "matched_hash_value": hex(h),
                            "export_name": name, "case_variant": variant,
                            "null_terminator_included": null, "algorithm": algo_name,
                        }
                        if width == 64:
                            match["seed"] = seed
                        matches.append(match)
    return {
        "ok": not bool(missing_dependency),
        "status": STATUS_NOT_LOOKED if missing_dependency else STATUS_OK,
        "dll_path": str(dll_path),
        "export_count_searched": len(names),
        "algorithms_tried": sorted(algo_set),
        "case_variants_tried": list(case_variants),
        "null_terminator_variants_tried": list(append_null),
        "hash_values_searched": [hex(v) for v in hash_inputs.values()],
        "match_count": len(matches),
        "matches": matches,
        **missing_dependency,
        **search_limitations,
    }


def self_test_round_trip(dll_path=DEFAULT_SYSTEM_DLL, sample_export="IoCreateDevice"):
    """Sanity check: compute this module's own hash of a known export name
    under every algorithm, then confirm crack_api_hash recovers that exact
    name from the raw hash value alone -- proves the forward/reverse path is
    consistent before trusting it on a real, unknown target constant.
    """
    results = {}
    for algo_name, fn in ALGORITHMS.items():
        try:
            h = fn(sample_export.encode("ascii"))
        except ImportError:
            results[algo_name] = {"status": STATUS_NOT_LOOKED,
                                  "error": "OPTIONAL_DEPENDENCY_MISSING", "dependency": "xxhash"}
            continue
        cracked = crack_api_hash(h, dll_path=dll_path, algorithms=[algo_name],
                                  case_variants=("as_is",), append_null=(False,))
        found = any(m["export_name"] == sample_export for m in cracked.get("matches", []))
        results[algo_name] = {"computed_hash": hex(h), "round_trip_recovered": found}
    return results


def api_hash_recover_tool(hash_values, dll_path=DEFAULT_SYSTEM_DLL, algorithms=None, seed=_SEED_UNSET) -> str:
    """MCP/tool-callable wrapper around crack_api_hash: JSON string in,
    JSON string out, matching this project's other tool-layer conventions.
    dll_path is intentionally NOT workspace-restricted -- this
    capability's entire purpose is reading a *local system* DLL's export
    table (ntoskrnl.exe by default for kernel targets) as a read-only
    reference dictionary; it never reads or writes the suspect binary
    itself (the caller supplies the hash constant, already extracted by
    another tool, not a file path to the target).
    """
    import json
    try:
        values = hash_values
        if isinstance(values, str):
            values = [int(v, 0) for v in values.replace(",", " ").split()]
        result = crack_api_hash(values, dll_path=dll_path, algorithms=algorithms, seed=seed)
    except (ValueError, TypeError) as exc:
        # An unparsable hash constant is the caller's input, not a failure to look.
        result = {"ok": False, "status": STATUS_USAGE, "error": type(exc).__name__, "detail": str(exc)}
    except Exception as exc:
        result = {"ok": False, "status": STATUS_NOT_LOOKED, "error": type(exc).__name__, "detail": str(exc)}
    return json.dumps(result, ensure_ascii=False)


def api_hash_recover(hash_values, dll_path=DEFAULT_SYSTEM_DLL, algorithms=None, seed=_SEED_UNSET) -> str:
    """The published tool name (FAMILIES["crypto"]) for this capability.

    A thin surface: it only forwards to ``api_hash_recover_tool`` (JSON string
    in, JSON string out), which itself calls ``crack_api_hash``. No logic lives
    here, so every refusal (``UNKNOWN_ALGORITHM``, an unreadable DLL) and every
    exception report passes through unchanged.
    """
    return api_hash_recover_tool(hash_values, dll_path=dll_path, algorithms=algorithms, seed=seed)
