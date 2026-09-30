import json
import struct
from pathlib import Path

from tools_workspace import safe_path, relative

# Dart VM "Snapshot" raw header layout, verified field-for-field against the
# authoritative dart-lang/sdk source (BSD-3-Clause), runtime/vm/snapshot.h,
# class Snapshot: kMagicOffset=0/int32, kLengthOffset=4/int64, kKindOffset=12/int64,
# kHeaderSize=20. large_length() = Read<int64>(kLengthOffset) + kMagicSize(4).
_MAGIC = 0xDCDCF5F5
_MAGIC_BYTES = struct.pack("<I", _MAGIC)
_HEADER_SIZE = 20
_KIND_NAMES = {0: "kFull", 1: "kFullJIT", 2: "kFullAOT", 3: "kModule", 4: "kInvalid"}


def _scan_headers(data, max_matches):
    matches = []
    pos = 0
    while len(matches) < max_matches:
        idx = data.find(_MAGIC_BYTES, pos)
        if idx < 0 or idx + _HEADER_SIZE > len(data):
            break
        pos = idx + 1
        length_field, kind_raw = struct.unpack_from("<qq", data, idx + 4)
        large_length = length_field + 4
        valid_kind = kind_raw in _KIND_NAMES
        # declared_length is the snapshot's own size within its containing
        # binary, not bounded by the (possibly truncated) scanned buffer --
        # so plausibility only checks the value is a sane positive size,
        # it does not require the full snapshot to be present in `data`.
        plausible_length = 0 < large_length <= (1 << 31)
        matches.append({
            "offset": idx,
            "declared_length": large_length,
            "kind_raw": kind_raw,
            "kind": _KIND_NAMES.get(kind_raw, "UNKNOWN"),
            "plausible": bool(valid_kind and plausible_length),
            "length_within_scanned_buffer": bool(idx + large_length <= len(data)),
        })
    return matches


def dart_aot_recovery(path, operation="summary", max_matches=20):
    """Real, narrowly-scoped Dart AOT snapshot header identification.

    Scans a native binary (ELF/.so, Mach-O, or raw extracted snapshot blob)
    for the Dart VM Snapshot magic (0xdcdcf5f5) and decodes the 20-byte
    header (magic/length/kind) verified against dart-lang/sdk's own
    runtime/vm/snapshot.h. Deliberately does NOT attempt to parse anything
    past the header -- the object-graph/cluster layout beyond kHeaderSize is
    undocumented upstream and changes across Dart SDK versions, so any
    further decoding would be a guess rather than evidence.
    """
    p = safe_path(path)
    if not p.is_file():
        return json.dumps({"error": f"not a file: {relative(p)}"})
    data = p.read_bytes()

    matches = _scan_headers(data, max_matches)
    plausible = [m for m in matches if m["plausible"]]

    if operation == "summary":
        return json.dumps({
            "file_size": len(data),
            "snapshot_magic_occurrences": len(matches),
            "plausible_snapshot_headers": len(plausible),
            "headers": plausible if plausible else matches[:5],
            "scope_limitation": (
                "Header/version/kind identification only (magic, declared length, "
                "Snapshot::Kind). Function names, string pool, instruction offsets, "
                "and the full object-cluster graph are NOT decoded -- that region "
                "of the Dart AOT snapshot format is undocumented upstream and is "
                "known to change across Dart SDK versions."
            ),
        })
    if operation == "headers":
        return json.dumps({"file_size": len(data), "headers": matches})
    return json.dumps({"error": f"unknown operation: {operation}"})
