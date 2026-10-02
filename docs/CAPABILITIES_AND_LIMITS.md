# Capabilities and limitations: an accurate starting picture

A record of what this repository's code does and does not do, written so that
future work starts from the real state rather than an optimistic one. It is
derived from `liebert_re/`, `tests/` and `.github/workflows/ci.yml`, not from the
prose docs. It describes capability only. It contains no procedure and proposes
no plan; [ROADMAP.md](ROADMAP.md) owns direction.

Read it with one fact in mind: **the capability set is general-purpose static
inspection of Windows user-mode files, plus a small set of format-specific
helpers. It is weak for kernel-level targets, and today it cannot analyse a
kernel-mode binary in any meaningful way.**

## Part 1: What it can do

"Partial" means the module works but stops short of what a reader might assume.
Module paths are relative to `liebert_re/`.

### PE / COFF (Windows images), the strongest area

- Headers, sections with entropy, imports, exports, resources, strings, byte
  search, hashing, Authenticode inspection (Windows hosts only):
  `tools/binary.py`.
- TLS directory and callback array: `tools/tls_directory.py`.
- RVA / VA / file-offset conversion, and dump-to-live address correlation over a
  single file: `recover/pe_address.py`, `tools/image_map.py`.
- Capstone disassembly of a PE range, with a chunked sweep for large sections:
  `tools/binary.py`, `recover/code_sweep_chunking.py`.
- CodeView / PDB identity and container parsing: `recover/codeview_rsds.py`,
  `recover/msf_pdb.py`; detection of a local PDB toolchain:
  `recover/native_pdb_toolchain.py`.
- Partial: the PE surface does not cover delay imports, base relocations, the
  rich header or exception/unwind data. `tools/binary.py` reports the subsystem
  number but nothing in the package branches on it.

### Language-runtime and legacy formats (structure recovery)

- .NET metadata and IL bodies, plus relationships: `recover/dotnet_il.py`,
  `recover/dotnet_relationships.py`, `dotnet_metadata` in `tools/binary.py`.
- VB6 native header chain and P-Code decoding: `tools/vb6.py`,
  `tools/vb6_pcode.py`.
- MSVC C++ RTTI class hierarchy, 32 and 64 bit: `tools/cpp_rtti.py`.
- Delphi class recovery, 32-bit PE only: `tools/delphi.py`. Partial: no method
  tables.
- Dart snapshot header only: `tools/dart.py`.
- Other containers: Godot `.pck`, Unreal classic `.pak`, Unity assets, ASAR, DEX,
  JVM classes, APK manifest, plist, PCAP, WebAssembly, archives, SQLite, HAR,
  logs (`tools/godot.py`, `unreal.py`, `unity.py`, `asar_parser.py`, `dex.py`,
  `jvm.py`, `android.py`, `plist.py`, `pcap.py`, `formats.py`, `archive2.py`).
  Several depend on Python packages or external tools the package does not
  declare. Partial throughout: listing and header-level reads, not bytecode or
  script decompilation.

### Non-PE native formats

- ELF and Mach-O are only identified (class, endianness, machine, file type) in
  `tools/formats.py`. There is no ELF or Mach-O section, symbol, import or
  segment parser anywhere in the package. The in-process disassembler
  (`disassemble_pe`) is PE-only; other formats reach disassembly only through
  the external rizin wrapper.

### Crash and memory artefacts

- Minidump (`MDMP`) structure, memory reads by virtual address, and a heuristic
  x86_64 stack scan: `recover/minidump_structural.py`,
  `recover/minidump_analyzer.py`.
- Offline symbolisation of one module plus RVA against a matching PDB:
  `recover/crash_symbolize.py`. Partial: public symbols only, no source lines,
  no stack unwinding.

### Constants, hashes and cryptography

- Crypto-constant identification, 21 algorithms: `tools/crypto_id.py`.
- API-hash matching against a local PE's export names, 7 algorithms, 32-bit
  values only: `recover/api_hash_recover.py`.
- Exact LLL reduction and lattice helpers (need `mpmath`): `recover/lll_exact.py`,
  `tools/lattice.py`.
- Verifying a named constant at a claimed address:
  `evidence/constant_at_address_verifier.py`.

### Packers and patching

- UPX static unpack through the external `upx` binary: `tools/upx.py`.
- Bounded LZMA1 decode: `recover/lzma1_range_decoder.py`, `tools/lzma1_decode.py`.
- Byte patch planning/apply and closed-form CRC-32 correction, via rizin and
  keystone: `tools/rizin.py`.
- Structure reads through `rz-bin` (rizin's own binary reader): import table,
  section table, header fields and relocations, as `rz_bin_imports`,
  `rz_bin_sections`, `rz_bin_headers`, `rz_bin_relocations` and `rz_bin_status`
  in `tools/rizin.py`. rz-bin reports no section entropy (use `die_entropy`),
  and an empty list from a file rz-bin did not recognise is refused rather than
  reported as zero. Not wrapped: `-z` strings, `-K` checksums, `-P` PDB.
- FLIRT signature matching, done by rizin itself (not `rz-sign` or `rz-gg`):
  `rizin_flirt_match` applies the signature sets bundled with rizin that were built for the
  binary's format, architecture and bit width, one at a time, and returns the functions it
  named with their addresses and the set that named each; `rizin_flirt_match_file` applies one
  `.sig` or `.pat` file you supply; `rizin_flirt_inventory` lists what the database holds.
  A binary no set was built for returns `NO_COMPATIBLE_SIGNATURES`, and a run whose analysis
  found no functions returns `NO_FUNCTIONS_TO_MATCH`; neither is a zero. rizin checks only the
  CPU family of a supplied file, so a zero from one is marked as not verified. Matching names
  library code only. Not wrapped: creating signature files (`Fc`) and dumping them (`Fd`).
- Packer identification (Detect It Easy) and rule scanning (YARA-X):
  `tools/die.py`, `tools/yara_x.py`.

### Decompilation and cross-references (needs a licensed IDA)

- `tools/ida.py`: `ida_query` (read-only) and `ida_status`, driving IDA Pro 9.x headless
  (`idat -A`) in a bounded subprocess. Operations: `summary`, `list_functions`, `segments`,
  `function_at_address`, `decompile_function` (Hex-Rays pseudocode), `xrefs_to` (any symbol or
  address, including import slots; calls are flagged, jumps are not calls), `imports_exports`,
  `strings`. Listings page with `offset` / `next_offset`.
- Partial, by design: symbol-server (PDB download) lookups are switched off on every launch, so names
  that exist only in a PDB are absent. IDA's auto-analysis can miss or mis-split code in obfuscated or
  packed targets, so an absent function or xref is not proof of absence. Pseudocode is IDA's reading,
  not the source. An IDA database is not accepted as input.
- The first call on a file pays for IDA's analysis (two idat sessions); later calls reuse a database
  cached by the input file's SHA-256 (`dataset/ida_cache/`, 5 GiB cap by default). `timeout_seconds`
  is one budget clamped to 5-600 s: the first analysis may use all of it (it runs once per file
  content), the session that answers a question never runs longer than 300 s. A timed-out analysis
  is discarded, not half-cached, and is reported as `TIMEOUT`, never as "nothing found". A listing
  cut short by a walk ceiling or by `max_chars` is `PARTIAL` and names the ceiling and its value.
- Not here: renaming, comments, patch planning, microcode, type-member offsets, disassembly listing,
  and any Ghidra wrapper.

### External-engine wrappers actually present

rizin (listing, function inventory, patching, rz-bin structure reads, FLIRT matching), Detect It Easy, YARA-X, capa, IDA (read-only, see above), pe-sieve (one live process, see below), UPX,
JADX, Il2CppDumper, and the API Monitor catalogue only. All are optional and
return a named tool-missing status when absent. Function inventory
(`rizin_functions`) needs rizin; it is not pure Python.

### Evidence, reporting and plumbing

- Content-hash evidence store, claim index and claim guard, provenance,
  workspace index: `evidence/*.py`.
- Analysis IR (caller-built), binary version diff and cross-binary relationships
  over IR documents, finding and validation-plan rendering:
  `recover/analysis_ir.py`, `recover/binary_version_diff.py`,
  `recover/cross_binary_relationships.py`, `recover/native_xref.py`,
  `report/analysis_findings.py`, `report/exploit_validation.py`. Partial:
  nothing in the package produces an IR from a binary.
- Workspace path sandbox, bounded subprocess with process-tree teardown, and a
  `liebert-re` CLI (`identify`, `probe`, `pe`, `disasm`, `packer`, `die`, `diestatus`,
  `capa`, `capastatus`, `ida`, `idastatus`, `rzbin`, `rzbinstatus`, `flirt`, `flirtinventory`, `sieve`, `sievestatus`, `unpack`, `scan`, `minidump`, `capabilities`):
  `workspace.py`, `bounded_subprocess.py`, `cli.py`.

### Dynamic and emulation

- Unicorn is imported only by `recover/vex.py`, which corrects AVX instruction
  execution inside an emulation session someone else sets up. No range
  emulation, tracing or slicing ships.
- `tools/pe_sieve.py` (`pe_sieve_scan`, `pe_sieve_status`; family `dynamic`): a scan of ONE running process, by PID,
  for in-memory differences from its on-disk image (patched or hooked code, IAT hooks, replaced or hollowed images, implanted PEs and shellcode). Read from pe-sieve's own `/json /jlvl 2` report, and its category names are passed through as given. Scan only: `/ofilter 2` is always passed and no dump, import-recovery, minidump or reflection switch can be. The PID is required; a missing, invalid or all-processes request is `PID_REQUIRED` and starts nothing. The 64-bit scanner is used whenever it is present, because measured on 0.4.1.1 it scans 32-bit (WOW64) targets too (and also reports the native modules those load), while the 32-bit scanner cannot scan a 64-bit target and prints an all-zero, clean-looking report; that case is `SCANNER_MISMATCH`.
  **No result here means "clean" unless it is `OK` with `anomalies_found: false`,** and even then only for the modules and regions scanned at the depth in `scan_flags`: a process that could not be opened is `ACCESS_DENIED` or `PROCESS_NOT_OPENED`, zero modules scanned is `NOTHING_SCANNED`, unread or skipped modules make `SCAN_PARTIAL` (findings still listed). The access-denied wording and a non-zero `errors` report were not reproduced on the measuring machine; they are handled from the documented shape and the tests say so. Non-executable pages, thread stacks and kernel memory are not covered by default.
- `dynamic/lab_gate.py` (`dynamic_lab_gate`, `dynamic_lab_register_owned_process`; family `dynamic`): the gate in front of every operation that touches a live process. **Behind the dynamic-lab gate (behaviour change):** `pe_sieve_scan` no longer runs on a bare PID. It needs `LIEBERT_RE_DYNAMIC_LAB=authorized` in the environment, an authorization naming who, why, this operation and this PID, the declared SHA-256 of the process image (verified against the file the process was started from), and a process the harness started (a direct child of the caller, or one registered with `dynamic_lab_register_owned_process`; CLI: `labgate`, `labregister`, `sieve --authorization JSON --sample-sha256 HEX`). Anything missing or unverifiable is refused (`AUTHORIZATION_REQUIRED`, `SAMPLE_HASH_REQUIRED`/`SAMPLE_HASH_MISMATCH`, `PROCESS_NOT_OWNED`, `RESOURCE_LIMIT_UNAVAILABLE`, ...) and nothing starts. The scanner runs under a timeout and a memory limit, and every call writes environment, user and elevation, the exact argument vector and the result to `dataset/evidence/dynamic_lab_gate/`. The gate does NOT verify an isolated guest, a snapshot or network control and says so on every call (`isolation_verified: false`); operations that execute or instrument a process (`execute_sample`, `launch_sample`, `frida_trace`, `frida_attach`, `frida_spawn`) are refused with `ISOLATION_REQUIRED`. Observing a harness-owned process is allowed without isolation, and the response gives that as the reason.
- `dynamic/apimonitor.py`: catalogue only; live tracing and trace parsing are
  unconditional refusals.
- `dynamic/frida_trace_client.py`: a guest-side launcher; no host-side driver
  ships, so nothing exercises it end to end.

### Test coverage

68 test files; a default run on this checkout gave 527 passed, 39 skipped,
157 deselected (`heavy`), before the IDA wrapper's tests were added. Fixtures are built in code
(`recover/owned_binary_fixtures.py`); no real binaries ship. Real-engine paths
skip on a clean checkout, so CI does not demonstrate them.
The IDA wrapper's default-tier tests drive the real wrapper code against a stand-in `idat` that writes
what the real tool writes (log, packed database, result file); only the `IdaRealInstallTests` class runs
a real IDA, is marked `heavy`, and skips when idat is absent.

## Part 2: Where it is weak

### Kernel-level targets are out of reach today

- `report/tool_families.py` names a `windows-kernel` family of 15 tools. Only the
  generic `tool_missing` sentinel is defined in this package; the other 14 are
  names of upstream tools that are not here. The family routes and then has
  nothing to dispatch.
- No module parses a driver's dispatch table, callback registrations, device or
  control-code definitions, or any other kernel-specific structure. A
  kernel-mode PE is handled as an ordinary PE: headers, imports, strings,
  disassembly.
- No exception/unwind data parser, so no function-boundary recovery for stripped
  x64 images.
- No bounded code-range emulation, so nothing can exercise a routine in
  isolation.
- No kernel-debugger or live-kernel integration, and no parser for kernel-dump
  formats. Only `MDMP`-format dumps are read.
- No decompiler and no cross-reference engine of its own. With a licensed IDA Pro 9.x on the
  machine, `ida_query` supplies decompiled pseudocode and cross-references from IDA's analysis of
  the real bytes (read-only, symbol-server lookups off); without IDA there is neither, and no Ghidra
  wrapper exists. `recover/native_xref.py` resolves only over an IR the caller supplies.
- The package has never been demonstrated against a real kernel-mode file. The
  only driver-flavoured artefact is a synthetic fixture in
  `recover/owned_binary_fixtures.py`; kernel-oriented wording in
  `recover/api_hash_recover.py` and `recover/code_sweep_chunking.py` refers to
  upstream tools that are absent and is history, not capability.
- Non-Windows kernels and their loadable modules have no parser at all.

### Other classes of target not reached

- Virtualised or bytecode-interpreter protections, control-flow flattening,
  encrypted-at-rest sections: no devirtualisation, deflattening or static path.
- Whole-program dataflow, taint and symbolic execution: absent.
- Imports resolved at runtime by the target itself: not recovered.
- Dalvik method bytecode, Android resource tables, signature verification
  beyond presence: absent.
- Anything needing live behaviour: tracing is refused or guest-only, and no
  debugger is driven.

### Limits of confidence

- Several results are heuristic and should stay labelled so: the stack scan,
  RTTI and Delphi recovery, framework detection.
- Development and measurement are Windows x64. Some tests assume Windows-only
  facilities and skip elsewhere.
- Corpus results quoted in other docs come from an unpublished tree and cannot
  be reproduced from this repository.

## Discrepancies: doc claims the code does not support

Checked against code on this checkout, reading the locally modified docs as they
sit on disk.

1. `README.md` introduction said the harness exposes IDA and Ghidra. An IDA wrapper now exists
   (read-only, `tools/ida.py`); no Ghidra wrapper does. The introduction, scope section and
   `INSTALL.md` now say the same thing.
2. `README.md` "What it cannot do" says "Mobile targets. No APK/DEX support".
   `tools/dex.py`, `tools/android.py` and `tools/jvm.py` ship (structure only).
   `ROADMAP.md` has the corrected wording.
3. `INSTALL.md` says core analysis, including emulation, runs on the Python
   dependencies alone. No range emulation ships; `recover/vex.py` is an
   instruction-semantics correction layer. It also lists function inventory
   there, but `rizin_functions` needs rizin.
4. `INSTALL.md` counts: "64 Python modules at the repository root", "47 test
   files", "11 standalone challenge-solution scripts in `crackme_solutions/`".
   Actual: 68 modules inside the `liebert_re/` package (CI asserts 68), 68 test
   files, and no `crackme_solutions/` directory exists or is tracked.
5. `README.md`, `BENCHMARKS.md` and `ROADMAP.md` refer to `crackme_solutions/`
   as shipped; `ROADMAP.md` "Start here" item 1 names a script that is not in
   the tree.
6. `BENCHMARKS.md` lists angr as a real in-process integration. Nothing in the
   package imports it; Unicorn is used only in `recover/vex.py`.
7. `README.md` and `INSTALL.md` omit modules that exist and run: WebAssembly
   inspection (`tools/formats.py`), `recover/native_xref.py` (IR-only) and
   `recover/code_sweep_chunking.py`. Not a false claim, but the capability table
   is not a complete inventory.
8. `report/tool_families.py` is a routing manifest, not a capability list; its
   `published_tools()` helper is the accurate view.

The README capability table is otherwise consistent with the code on the points
checked: 21 crypto algorithms, 7 hash algorithms, 32-bit-only hash constants,
x86_64-only stack scan, API Monitor refusals, and the PE directories not covered.

## Maintenance

Counts here are point-in-time (checkout of 2026-10-01). CI's wheel smoke test
asserts the shipped module count; this document is not part of that check and
adds no module.
