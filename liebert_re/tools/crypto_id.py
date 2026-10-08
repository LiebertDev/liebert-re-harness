"""Deterministic identification of standard cryptographic / hash constants in
arbitrary bytes -- a real, generic capability this program kept re-doing by hand.

Recorded demand that produced this tool (real cases, not speculation):
  * WNL-T2-085: MD5 was identified only by an analyst eyeballing the four
    initial-state words in a disassembly listing.
  * WNL-T2-003: FNV-1a was identified only by an analyst spotting the prime
    0x01000193 as an imul immediate in a hand-disassembled decrypted blob.
  * Four further ladder entries carry a recorded "unknown/custom algorithm"
    blocker.

Same shape as tools_stackstring.py: pure static inspection, bounded output,
no external tool, and explicit about what is observed versus inferred.

WHAT A HIT PROVES, AND WHAT IT DOES NOT
---------------------------------------
A hit is an observed fact about bytes: this exact constant appears at this
exact offset. That is all it is. Attribution to an algorithm is a HYPOTHESIS,
because:

  * Constant sets are shared. MD4, MD5, SHA-1 and RIPEMD-160 all begin from
    the same four words 0x67452301/0xEFCDAB89/0x98BADCFE/0x10325476, and SHA-1
    and RIPEMD-160 additionally share 0x5A827999 and 0x6ED9EBA1. A match on
    those alone can never name one algorithm, and this tool refuses to.
  * A constant can appear as inert data, inside an unrelated table, or in a
    copied-in library that the program never calls.
  * The reverse also holds: absence is NOT evidence of absence. Implementations
    routinely compute constants at runtime (the SHA-256 K table is derived from
    cube roots), split them across instructions, or store them transformed. A
    clean scan means "these signatures were not found", never "no crypto here".

So every result carries the search scope that was actually covered, and
attribution is reported as ranked candidates with an explicit
"also_consistent_with" list rather than a single asserted answer.

CONSTANT PROVENANCE
-------------------
The table is not transcribed from memory. Every derivable constant in it is
re-derived from first principles by tests/test_crypto_constant_scan.py --
SHA-256/SHA-512 from square and cube roots of primes, the MD5 T table from
sin(), the SHA-1 round constants from square roots, the Blowfish P array from
the hex expansion of pi, the AES S-box from the GF(2^8) inverse plus affine
transform, and the FNV/TEA constants from their defining arithmetic. A typo in
this table would silently misidentify algorithms, so the derivation is a test,
not a comment.
"""
from __future__ import annotations
import json
import struct
from pathlib import Path
from liebert_re.workspace import safe_path, relative

_ALLOWED_OPS = {"scan", "list_signatures"}
_MAX_SCAN_BYTES = 64 * 1024 * 1024
_MAX_HITS_PER_SIGNATURE = 16
_MAX_TOTAL_HITS = 400

# A constant is only usable as a standalone signature if it is wide enough to be
# rare. This threshold was not chosen on theory: the first run of this tool
# against a real target (WNL-T2-085) reported 0x00000000 and 0x00000001 as
# "distinctive" constants and manufactured bogus CRC-32 and Keccak candidates
# out of them. Any value that fits in 16 bits is ubiquitous in real binaries and
# proves nothing on its own, so such values are excluded from individual
# matching and from attribution scoring. They are still used as part of an
# ordered consecutive-run match, where the whole byte blob is the evidence
# rather than any single word.
_MIN_INDIVIDUAL_VALUE = 0x10000

# --- signature table -------------------------------------------------------
# kind "words32"/"words64": integer constants, matched little- AND big-endian.
# kind "bytes": a literal byte run (tables, ASCII markers) matched as-is.
# "ordered" groups additionally report whether the words appeared consecutively
# in table order, which is much stronger evidence than a scattered match.
# "alternatives": the values are mutually exclusive variants rather than a set
# expected to appear together -- an implementation picks the 32-byte OR the
# 16-byte ChaCha sigma, the reflected OR the normal CRC polynomial. Scoring
# those by "how many of the listed values were found" would permanently cap
# them at partial coverage, so any one match counts as full coverage.
#
# Deliberately ABSENT: CRC-16 and Adler-32. Their only characteristic constants
# (0xA001/0x8408 and 0xFFF1) fit in 16 bits, which makes them far too common in
# real binaries to be evidence. Listing them would advertise coverage that does
# not exist.

_SIGNATURES = {
    "MD5": {
        "init_state": {"kind": "words32", "ordered": True,
                       "values": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]},
        "T_table_head": {"kind": "words32", "ordered": True,
                         "values": [0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE]},
    },
    "MD4": {
        "init_state": {"kind": "words32", "ordered": True,
                       "values": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]},
        "round_constants": {"kind": "words32", "ordered": False,
                            "values": [0x5A827999, 0x6ED9EBA1]},
    },
    "SHA-1": {
        "init_state": {"kind": "words32", "ordered": True,
                       "values": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]},
        "round_constants": {"kind": "words32", "ordered": True,
                            "values": [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]},
    },
    "RIPEMD-160": {
        "init_state": {"kind": "words32", "ordered": True,
                       "values": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]},
        "round_constants": {"kind": "words32", "ordered": False,
                            "values": [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E,
                                       0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9]},
    },
    "SHA-256": {
        "init_state": {"kind": "words32", "ordered": True,
                       "values": [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                                  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]},
        "K_table_head": {"kind": "words32", "ordered": True,
                         "values": [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
                                    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5]},
    },
    "SHA-224": {
        "init_state": {"kind": "words32", "ordered": True,
                       "values": [0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
                                  0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4]},
    },
    "SHA-512": {
        "init_state": {"kind": "words64", "ordered": True,
                       "values": [0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
                                  0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1]},
        "K_table_head": {"kind": "words64", "ordered": True,
                         "values": [0x428A2F98D728AE22, 0x7137449123EF65CD,
                                    0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC]},
    },
    "SHA-384": {
        "init_state": {"kind": "words64", "ordered": True,
                       "values": [0xCBBB9D5DC1059ED8, 0x629A292A367CD507,
                                  0x9159015A3070DD17, 0x152FECD8F70E5939]},
    },
    "SHA-3 / Keccak": {
        "round_constants_head": {"kind": "words64", "ordered": True,
                                 "values": [0x0000000000000001, 0x0000000000008082,
                                            0x800000000000808A, 0x8000000080008000]},
    },
    "AES / Rijndael": {
        "sbox_head": {"kind": "bytes", "ordered": True,
                      "values": [bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")]},
        "inv_sbox_head": {"kind": "bytes", "ordered": True,
                          "values": [bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")]},
        "rcon": {"kind": "bytes", "ordered": True,
                 "values": [bytes.fromhex("01020408102040801b36")]},
        "Te0_head": {"kind": "words32", "ordered": True,
                     "values": [0xC66363A5, 0xF87C7C84, 0xEE777799, 0xF67B7B8D]},
    },
    "Blowfish": {
        "P_array_head": {"kind": "words32", "ordered": True,
                         "values": [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344]},
    },
    "TEA / XTEA / XXTEA": {
        "delta": {"kind": "words32", "ordered": False, "values": [0x9E3779B9]},
        "sum_after_32_rounds": {"kind": "words32", "ordered": False, "values": [0xC6EF3720]},
    },
    "FNV-1 / FNV-1a (32-bit)": {
        "prime": {"kind": "words32", "ordered": False, "values": [0x01000193]},
        "offset_basis": {"kind": "words32", "ordered": False, "values": [0x811C9DC5]},
    },
    "FNV-1 / FNV-1a (64-bit)": {
        "prime": {"kind": "words64", "ordered": False, "values": [0x00000100000001B3]},
        "offset_basis": {"kind": "words64", "ordered": False, "values": [0xCBF29CE484222325]},
    },
    "CRC-32 (IEEE)": {
        "polynomial": {"kind": "words32", "ordered": False, "alternatives": True,
                       "values": [0xEDB88320, 0x04C11DB7]},
        "table_head": {"kind": "words32", "ordered": True,
                       "values": [0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA]},
    },
    "CRC-32C (Castagnoli)": {
        "polynomial": {"kind": "words32", "ordered": False, "alternatives": True,
                       "values": [0x82F63B78, 0x1EDC6F41]},
    },
    "MurmurHash3": {
        "mix_constants": {"kind": "words32", "ordered": True,
                          "values": [0xCC9E2D51, 0x1B873593]},
        "finalizer": {"kind": "words32", "ordered": True,
                      "values": [0x85EBCA6B, 0xC2B2AE35]},
    },
    "xxHash (32-bit)": {
        "primes": {"kind": "words32", "ordered": True,
                   "values": [0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1]},
    },
    "ChaCha / Salsa20": {
        "sigma_constant": {"kind": "bytes", "ordered": True, "alternatives": True,
                           "values": [b"expand 32-byte k", b"expand 16-byte k"]},
    },
    "Base64": {
        "standard_alphabet": {"kind": "bytes", "ordered": True, "alternatives": True,
                              "values": [b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"]},
        "url_safe_alphabet": {"kind": "bytes", "ordered": True, "alternatives": True,
                              "values": [b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"]},
    },
    "DES": {
        "initial_permutation_head": {"kind": "bytes", "ordered": True,
                                     "values": [bytes([58, 50, 42, 34, 26, 18, 10, 2,
                                                       60, 52, 44, 36, 28, 20, 12, 4])]},
    },
}


def _j(x):
    return json.dumps(x, ensure_ascii=False, indent=2, default=str)


def _parse_int(value, default=None):
    if value in (None, ""):
        return default
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _searchable(kind, value):
    """Is this constant rare enough to mean something on its own? See
    _MIN_INDIVIDUAL_VALUE -- low-entropy words are kept in the table for ordered
    run matching but never reported as individual evidence."""
    if kind == "bytes":
        return len(value) >= 4
    return value >= _MIN_INDIVIDUAL_VALUE


def _needles(kind, value):
    """Every byte encoding a constant may take. Both endiannesses are searched,
    because a big-endian-stored table is exactly the same evidence -- SHA
    constants in particular are often emitted byte-swapped."""
    if kind == "bytes":
        return [("bytes", value)]
    if kind == "words32":
        return [("le32", struct.pack("<I", value)), ("be32", struct.pack(">I", value))]
    if kind == "words64":
        return [("le64", struct.pack("<Q", value)), ("be64", struct.pack(">Q", value))]
    return []


def _find_all(data, needle, limit):
    out = []
    start = 0
    while len(out) < limit:
        i = data.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def _pe_offset_to_va(path):
    """Best-effort file-offset -> virtual-address mapper, as ``(mapper, reason)``.
    ``reason`` is None when a mapper was built; otherwise ``mapper`` is None and
    ``reason`` says why: NOT_PE (no MZ signature, the normal case for a raw
    decrypted blob), TOOL_MISSING (pefile is not installed, so a PE could not be
    mapped) or PE_PARSE_FAILED (MZ signature, but pefile rejected the file)."""
    try:
        with open(path, "rb") as stream:
            signature = stream.read(2)
    except OSError:
        return None, "PE_PARSE_FAILED"
    if signature != b"MZ":
        return None, "NOT_PE"
    try:
        import pefile
    except ImportError:
        return None, "TOOL_MISSING"
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return None, "PE_PARSE_FAILED"
    try:
        base = pe.OPTIONAL_HEADER.ImageBase
        spans = []
        for s in pe.sections:
            raw = int(s.PointerToRawData)
            size = int(s.SizeOfRawData)
            if size:
                spans.append((raw, raw + size, base + int(s.VirtualAddress),
                              s.Name.rstrip(b"\x00").decode("latin-1", "replace")))
    finally:
        pe.close()

    def mapper(off):
        for raw, end, va, name in spans:
            if raw <= off < end:
                return {"virtual_address": hex(va + (off - raw)), "section": name}
        return {"virtual_address": None, "section": None}

    return mapper, None


def _shared_index():
    """Which (kind, value) constants appear under more than one algorithm.
    Computed from the table itself so it can never drift out of sync with it."""
    owners = {}
    for algo, groups in _SIGNATURES.items():
        for group in groups.values():
            for value in group["values"]:
                key = (group["kind"], bytes(value) if group["kind"] == "bytes" else value)
                owners.setdefault(key, set()).add(algo)
    return owners


def _label(kind, value):
    if kind != "bytes":
        return hex(value)
    if all(32 <= b < 127 for b in value):
        return value.decode("latin-1")
    return value.hex()


def _consecutive_run(data, group):
    """True when the constants appear back to back, in table order, in a single
    encoding -- an actual stored table rather than scattered values."""
    for encoding_name in ("le32", "be32", "le64", "be64"):
        blob = b""
        for value in group["values"]:
            found = [n for e, n in _needles(group["kind"], value) if e == encoding_name]
            if not found:
                blob = b""
                break
            blob += found[0]
        if blob and data.find(blob) >= 0:
            return True
    return False


def _attribution(group_reports, distinctive, shared):
    """Deliberately conservative. Naming one algorithm requires a constant that
    belongs to it alone; otherwise the honest answer is a candidate set."""
    best = max(g["coverage"] for g in group_reports)
    consecutive = any(g.get("stored_consecutively_in_table_order") for g in group_reports)
    if distinctive and best >= 0.75:
        level = "STRONG_CANDIDATE"
    elif distinctive:
        level = "PARTIAL_CANDIDATE"
    elif shared:
        level = "AMBIGUOUS_SHARED_CONSTANTS"
    else:
        level = "WEAK_CANDIDATE"
    note = {
        "STRONG_CANDIDATE": "Constants unique to this algorithm were found, with most of a "
                            "constant group present. Still a hypothesis: presence of a table "
                            "does not prove the code executes it.",
        "PARTIAL_CANDIDATE": "A constant unique to this algorithm was found, but most of its "
                             "group is absent -- consistent with a partial or inlined "
                             "implementation, a copied fragment, or a coincidence.",
        "AMBIGUOUS_SHARED_CONSTANTS": "Every constant matched here is shared with at least one "
                                      "other algorithm, so this scan CANNOT distinguish between "
                                      "them. Disambiguate by inspecting the round function.",
        "WEAK_CANDIDATE": "Matched, but with no distinctive constant and low coverage.",
    }[level]
    if consecutive:
        note += (" At least one group is stored consecutively in table order, which is "
                 "stronger evidence than a scattered match.")
    return {"level": level, "note": note}


def _scan(path, offset, length, only_algorithms):
    raw = Path(path).read_bytes()
    file_size = len(raw)
    start = offset or 0
    if start < 0 or start > file_size:
        return {"status": "BAD_RANGE",
                "error": "offset %d is outside the %d-byte file" % (start, file_size)}
    end = file_size if not length else min(file_size, start + length)
    if end - start > _MAX_SCAN_BYTES:
        end = start + _MAX_SCAN_BYTES
    data = raw[start:end]

    mapper, mapper_unavailable = _pe_offset_to_va(path)
    owners = _shared_index()
    selected = set(only_algorithms or [])

    results = []
    total_hits = 0
    truncated = False
    limits_reached = set()
    for algo, groups in _SIGNATURES.items():
        if selected and algo not in selected:
            continue
        group_reports = []
        for group_name, group in groups.items():
            kind = group["kind"]
            matched = []
            skipped_as_too_common = []
            for index, value in enumerate(group["values"]):
                if total_hits >= _MAX_TOTAL_HITS:
                    truncated = True
                    limits_reached.add("total")
                    break
                if not _searchable(kind, value):
                    skipped_as_too_common.append(_label(kind, value))
                    continue
                for encoding, needle in _needles(kind, value):
                    positions = _find_all(data, needle, _MAX_HITS_PER_SIGNATURE + 1)
                    if not positions:
                        continue
                    hits_truncated = len(positions) > _MAX_HITS_PER_SIGNATURE
                    if hits_truncated:
                        positions = positions[:_MAX_HITS_PER_SIGNATURE]
                        truncated = True
                        limits_reached.add("per_signature")
                    total_hits += len(positions)
                    hits = []
                    for p in positions:
                        absolute = start + p
                        entry = {"file_offset": hex(absolute)}
                        if mapper:
                            entry.update(mapper(absolute))
                        hits.append(entry)
                    matched.append({"index": index, "constant": _label(kind, value),
                                    "encoding": encoding, "hit_count": len(positions),
                                    "hits_truncated": hits_truncated,
                                    "hits": hits})
            expected = len(group["values"])
            searchable = expected - len(skipped_as_too_common)
            if not matched or not searchable:
                continue
            found_indices = sorted({m["index"] for m in matched})
            consecutive = None
            if group.get("ordered") and kind != "bytes" and len(found_indices) > 1:
                consecutive = _consecutive_run(data, group)
            group_reports.append({
                "group": group_name,
                "constants_expected": expected,
                "constants_searchable": searchable,
                "constants_skipped_as_too_common": skipped_as_too_common,
                "constants_found": len(found_indices),
                "coverage": (1.0 if group.get("alternatives") and found_indices
                             else round(len(found_indices) / searchable, 3) if searchable else 0.0),
                "values_are_alternatives": bool(group.get("alternatives")),
                "stored_consecutively_in_table_order": consecutive,
                "matches": matched,
            })
        if not group_reports:
            continue
        distinctive = []
        shared = set()
        for report in group_reports:
            group = groups[report["group"]]
            for m in report["matches"]:
                value = group["values"][m["index"]]
                key = (group["kind"], bytes(value) if group["kind"] == "bytes" else value)
                other = owners.get(key, set()) - {algo}
                if other:
                    shared |= other
                else:
                    distinctive.append(m["constant"])
        results.append({
            "algorithm": algo,
            "matched_groups": group_reports,
            "distinctive_constants_found": sorted(set(distinctive)),
            "also_consistent_with": sorted(shared),
            "attribution": _attribution(group_reports, distinctive, shared),
        })

    results.sort(key=lambda r: (
        -max(g["coverage"] for g in r["matched_groups"]),
        -len(r["distinctive_constants_found"]),
        r["algorithm"]))
    return {
        "status": "OK",
        "scanned": {"file_size": file_size, "range_start": hex(start),
                    "range_end": hex(end), "bytes_scanned": end - start,
                    "truncated_to_max_scan_bytes": (end - start) >= _MAX_SCAN_BYTES},
        "virtual_addresses_available": mapper is not None,
        "virtual_addresses_unavailable_reason": mapper_unavailable,
        "signatures_in_table": sum(len(g["values"])
                                   for a in _SIGNATURES.values() for g in a.values()),
        "algorithms_in_table": len(_SIGNATURES),
        "candidates": results,
        "hit_output_truncated": truncated,
        "hit_limits_reached": sorted(limits_reached),
        "hit_limits": {"per_signature": _MAX_HITS_PER_SIGNATURE, "total": _MAX_TOTAL_HITS},
    }


def crypto_constant_scan(path, operation="scan", offset="", length=0, algorithms=""):
    if operation not in _ALLOWED_OPS:
        return _j({"status": "BAD_OPERATION", "allowed": sorted(_ALLOWED_OPS)})

    if operation == "list_signatures":
        table = {}
        for algo, groups in _SIGNATURES.items():
            table[algo] = {name: {
                "kind": g["kind"],
                "count": len(g["values"]),
                "values": [_label(g["kind"], v) for v in g["values"]],
            } for name, g in groups.items()}
        return _j({"status": "OK", "algorithms": len(table), "table": table,
                   "provenance": "Every derivable constant is re-derived from first principles "
                                 "by tests/test_crypto_constant_scan.py; the table is not "
                                 "transcribed from memory."})

    try:
        target = safe_path(path)
    except PermissionError as exc:
        return _j({"status": "PATH_REFUSED", "error": str(exc)})
    if not target.exists() or not target.is_file():
        return _j({"status": "NOT_FOUND", "path": str(path)})

    only = [a.strip() for a in str(algorithms).split(",") if a.strip()] if algorithms else []
    unknown = [a for a in only if a not in _SIGNATURES]
    if unknown:
        return _j({"status": "UNKNOWN_ALGORITHM", "unknown": unknown,
                   "known": sorted(_SIGNATURES)})

    try:
        result = _scan(target, _parse_int(offset, 0), _parse_int(length, 0) or 0, only)
    except OSError as exc:
        return _j({"status": "READ_FAILED", "error": str(exc)})

    result["path"] = relative(target)
    result["evidence_note"] = (
        "A hit is an observed fact about bytes (this constant is at this offset). "
        "Naming the algorithm is a hypothesis: constants are shared between algorithms, "
        "may sit in unreferenced data or an unused copied-in library, and may never execute. "
        "A clean scan is a negative search result over THIS table and THIS byte range only -- "
        "implementations that derive constants at runtime, split them across instructions, or "
        "store them transformed will not appear here, so absence is not evidence of absence.")
    return _j(result)
