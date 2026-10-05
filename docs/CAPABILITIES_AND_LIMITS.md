# Capabilities and limitations: an accurate starting picture

A record of what this repository's code does and does not do, written so that
future work starts from the real state rather than an optimistic one. It is
derived from `liebert_re/`, `tests/` and `.github/workflows/ci.yml`, not from the
prose docs. It describes capability only. It contains no procedure and proposes
no plan; [ROADMAP.md](ROADMAP.md) owns direction.

Read it with one fact in mind: **the capability set is general-purpose static
inspection of Windows user-mode files, plus a small set of format-specific
helpers. It is weak for kernel-level targets: `kernel_triage` gives a first
look at whether a PE looks like a driver, but nothing here analyses a
kernel-mode binary's dispatch table, IOCTLs or callbacks.**

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
  number; the only code that branches on it is
  `kernel_triage` (native subsystem as one indicator of a driver, see Part 2).

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

- UPX static unpack through the external `upx` binary: `tools/upx.py`. `upx_status` answers whether `upx` resolves (`UPX_HOME`, `PATH`, or the per-user tools folder, named in `resolved_by`), whether it runs, and its version; it runs `upx --version` and touches no file.
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
  `tools/die.py`, `tools/yara_x.py`. `yara_x_status` is the YARA-X probe: `yr --version`, where it was
  found (`YARA_X_EXE`, `YARA_X_HOME`, `PATH`, `known_install`) and which named rule packs are installed.

### Status probes (is the tool there, and does it run)

The wrappers named below have a zero-argument `<tool>_status` that returns JSON with `ok`, `tool`, `status`, `binary`, `resolved_by`, `runnable` and `version` where the tool has one. `OK` means the tool was resolved AND started and printed its version or usage; a resolved file that does not run is `ANALYSIS_LIMITED`, a hang is `TIMEOUT`, and nothing found is `TOOL_MISSING` with a `detail` that names the environment variable to set and where else it looked. The probes added after the first six (`die_status`, `capa_status`, `rz_bin_status`, `pe_sieve_status`, `ida_status`, `rizin_status`) are `yara_x_status` and `upx_status` (family `native`), `il2cpp_status` (`game-engine`), `dex_status` (`android`), `jvm_status` (`jvm`) and `frida_status` (`dynamic`). `dex_status` and `jvm_status` both probe JADX, because each wrapper resolves it on its own; their `operations_without_the_tool` lists what keeps working without it (`summary`, `headers`, `classes`, and for DEX `strings`: only `decompile_class` needs JADX, which also needs a Java runtime). `il2cpp_status` has no version switch to call, so `version` is read from the exe's own version resource through the Windows API and is `null` (with `version_source: unavailable`) where that cannot be read. `rizin_status` keeps its older two-key shape on purpose.

`frida_status` separates two facts that are easy to merge. It reports whether THIS host has frida (the `frida` library for the interpreter that ran the call, found without importing it, and a `frida` CLI on `PATH`), and it states that the harness does not use it: the frida client is written to run only inside the isolated guest as a standalone exe with its own frida, so `host_frida_used_by_harness` is always `false` and `harness_client.guest_probed` is `false` (the guest is not checked). `OK` there means a host frida exists, never that the harness can trace; a host with no frida is `TOOL_MISSING` whose `detail` says guest tracing is not blocked by that. The answer is per interpreter: a library installed for one Python is invisible to another, which `interpreter` shows.

### Decompilation and cross-references (needs a licensed IDA)

- `tools/ida.py`: `ida_query` (read-only), `ida_microcode_cfg` (below), `ida_type_member_offset`, `ida_patch_plan` (a plan only), `ida_annotations` (reads the annotation log), the write path `ida_rename_plan` / `ida_set_comments_plan` / `ida_annotations_apply` / `ida_annotations_purge` (below) and `ida_status`, driving IDA Pro 9.x headless
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
- `ida_microcode_cfg` (CLI `idamicrocode`): one function's microcode as a control-flow graph (blocks,
  predecessors, successors, instructions; every address in the shared five-field address form) at any
  of the eight maturity levels, read in the same temporary session as a question. **Raw by default.**
  `deobfuscate=True` (CLI `--deobfuscate`) installs the third-party d810 optimizer for the generation
  and the answer then says so: `microcode_kind: d810_pass`, the d810 project that was loaded, the
  rules and optimizers that fired (d810's own counters, which do not cover every rule), the raw
  microcode of the same function from the same session, and whether the output differs from it. d810
  missing is `TOOL_MISSING`; present but not startable is `ANALYSIS_LIMITED`; in neither case is raw
  microcode returned in place of what was asked. d810's `options.json` writes go to a private
  directory and the user's copy is hashed before and after. Scope: the pass targets instruction-level
  obfuscation (MBA, opaque predicates, constant folding) and control-flow flattening patterns. It does
  not handle virtualised (VM-based) code: that logic lives in bytecode data, which microcode rules
  cannot rewrite. Rule firing and a changed listing were observed on the plugin's own sample binary
  (including with its flattening projects); whether a rewritten control flow is correct was not
  checked, so no claim is made that unflattening works. The session that builds the
  microcode never runs longer than 300 s (its own ceiling); the worker's full result goes to
  `dataset/evidence/ida_microcode_cfg/`.
- `ida_type_member_offset`: the byte offset (and bit offset, size and type text) of one direct member of a
  named struct or union, read from the type information the cached database holds, in the same temporary
  session. Both `_FOO` and `FOO` are tried. Three negatives are kept apart (no such type, not a struct or
  union, no such member; the last lists the members the type does have, cut at 100 and saying so), and
  each is an answer about the loaded type information, not about the program. A found offset is that
  definition's layout, not proof the program was built against it. Own 300 s session ceiling.
- `ida_patch_plan`: a PLAN for `force_branch` or `nop_out` at an address (`va`, `rva` or `file_offset`), in the
  same operation names, address form and answer shape as `rizin_patch_plan`; x86 and x86-64 only; the input
  file is never written. It is not a pure read: IDA's patch API is called in an in-memory copy of the database
  inside the temporary session and undone. The cached database file is hashed before and after and both
  hashes are in the answer; a difference is `PATCH_PLAN_CACHE_VIOLATION` (slot deleted, no plan returned).
  Own 300 s session ceiling. Whether the patched program behaves as intended is not checked.
- `ida_annotations`: reads the per-hash annotation log next to the cache slots. A plain file read: no IDA is
  started or needed. A list cut at `max_results` or `max_chars` says so and counts what was left out;
  unreadable lines are counted; a log with no readable line is an error, not an empty list. No log means this
  package recorded no annotation for that input, not that the database has no names. These three answers
  carry the input's hash, not its name or path.
- `ida_rename_plan` + `ida_annotations_apply`: renames that persist, as two operations (a plan, then an apply
  that cannot be called without it) over a named scope label. The plan reads the scope's current names and
  carries a digest, a base version and a per-item expectation; a stale plan is refused, never merged. An apply
  writes into a scratch copy, journals `batch_prepared` (synced) before promoting the candidate to an immutable
  version file, has a NEW engine process read the names and an in-database marker back, and only then publishes
  one manifest pointer and journals `batch_committed`. Annotated data lives in its own root
  (`dataset/ida_annotated/`, never inside the cache, never evicted; byte ceiling `LIEBERT_IDA_ANNOTATED_BYTES`,
  default 2 GiB) with its own locks. A candidate whose promotion failed is kept. Atomic is the default;
  `allow_partial=True` is an explicit choice.
- Comments use the same two steps: `ida_set_comments_plan` plans, `ida_annotations_apply` applies. Accepted
  comment kinds are `regular` and `repeatable` only; a decompiler comment is not supported and is refused with
  `UNSUPPORTED_COMMENT_KIND`. Limits:
  (a) Comment text is free operator text. The journal and the evidence file carry only its sha256 and length,
  never the text. The work files in the recovery directory do carry the full text and are removed when the
  apply returns; if removal fails, `signals.text_scrub_failures` reports it.
  (b) Verification after promotion runs in a separate process. If it fails, the version stays promoted but
  unpublished in the manifest. This `unverified` state is by design, not a defect; it is cleared as a purge
  target (`unverified-state`), and purge is currently the only way out of it.
  (c) The `regular`/`repeatable` mapping has been tested only against a stand-in for IDA; no test has run it
  against a real IDA. This is a limit, not a verified fact.
- Evidence directory naming: the comment plan's evidence is written to `dataset/evidence/ida_rename_plan/`
  (the constant is reused, so the directory name is misleading for comments). The file name ends in
  `_comment_plan.json` and its content carries `plan.kind="comments"`; read that, not the directory name.
- `ida_annotations_purge`: the only deletion of annotated data. Called without a confirmation it deletes nothing
  and reports what the scope holds and what the named targets would free; the report carries a token bound to
  the input hash, label, the exact targets and their measured state, and a changed scope is
  `STALE_CONFIRMATION`. Targets are exact names (versions, kept candidates, leftover work directories, and
  `unverified-state`, which clears an unverified scope and says it did); there is no wildcard and no "all".
  It reaches only the annotated root and journals every deletion.
- `not_purgeable` (in the purge report): purge also says what it does NOT delete. A read-only survey counts, per
  class, the files and bytes of six artifact classes that sit beside the annotated scope and are never purge
  targets: the pristine analysed-database cache (`dataset/ida_cache`, owned by the cache's own eviction and
  budget), the evidence files (`dataset/evidence/ida_*`, the ledger of what the tools reported), this target's
  write journal (counted for the input hash only; it is the record purge itself is written to), the claims
  (`dataset/claims`, the source of truth for recorded claims) and the two derived index directories
  (`dataset/metadata/claim_indexes`, `dataset/metadata/evidence_indexes`, rebuilt by their own modules). Each
  row carries `purgeable: false` and a `why_not_a_purge_target`. The survey only lists directories and reads
  sizes: it opens no file, writes nothing, deletes nothing, reads no content and returns no file name, only
  fixed relative labels, counts and byte totals. A missing directory says `present: false`; one that cannot be
  read reports `read_errors` and the error types, never an empty count.
- Not here: disassembly listing and decompiler comments. Ghidra: see the next section.
- A copy handed to an engine session is verified by hash: on a mismatch the session is not started. "The copy
  differs" (`COPY_INTEGRITY_FAILED`) and "the copy could not be checked" (`COPY_INTEGRITY_UNVERIFIABLE`) are
  separate refusals.
- When a verification session fails, a bounded, redacted tail of the engine log comes back in the answer.
  `LIEBERT_RE_KEEP_FAILED_SCRATCH` (off by default) keeps the failed scratch directory and the answer says it
  holds sensitive content.
- `ida_status` reads and reports the Lumina setting (`AutoUseLumina`). That is a CONFIGURATION READ, not an
  observation of the network.
- `pdb_lookup_declared` is a declaration about this tool's own command line, not a measurement of IDA.
  `signals.log_network_text_found` is a scan of log text for listed markers; a lookup that writes none of them
  is not seen, and the answer states that limit.

### Ghidra (headless, slice 1: status and program facts)

- `tools/ghidra.py`: `ghidra_status` and `ghidra_program_facts`, driving Ghidra's own `support/analyzeHeadless`.
  Not wired to the CLI.
- `ghidra_status` discovers the install (`GHIDRA_INSTALL_DIR`, `GHIDRA_HOME`, `PATH`, then known locations) and
  reports the version, the Java the install needs and the Java found. It does NOT launch Ghidra
  (`launcher_verified: false`): `OK` means files present and Java new enough, not that a run will succeed.
- `ghidra_program_facts` imports one file into a throw-away project and returns, read-only: loader, language,
  processor, endianness, address width, compiler spec, image base, entry points, memory blocks, function count
  (what analysis found in the time bound, not a complete inventory) and imported library names. A fact the
  script could not read is `null` and named, never guessed. The source file's SHA-256 is compared before and
  after; a changed source is refused (`SOURCE_MODIFIED`).
- **Exit code 0 is not success.** Measured: when the post-script fails, `analyzeHeadless` still exits 0. The
  wrapper scans the log for failure markers and requires the result file to exist, parse and carry the
  script's completion flag; anything less is `ANALYSIS_LIMITED`.
- The script is Java. A Jython `.py` script does not run on a stock install ("Ghidra was not started with
  PyGhidra"); PyGhidra needs a `pip install` and is not used or tested here.
- Each run has its own temporary project (Ghidra locks per project), placed outside the checkout because Ghidra
  refuses a project path with a dot-prefixed element.
- Why it was added: it is free and runs in CI (an IDA licence does not), and "answer the same question two
  ways" in the assessment order needs a second engine. Not here: decompilation, cross-references, writes.

### External-engine wrappers actually present

rizin (listing, function inventory, patching, rz-bin structure reads, FLIRT matching), Detect It Easy, YARA-X, capa, IDA (queries are read-only; annotations are written only through the plan-then-apply path, see above), pe-sieve (one live process, see below), UPX,
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
  `liebert-re` CLI (`identify`, `probe`, `pe`, `disasm`, `packer`, `die`, `rzbin`, `flirt`, `flirtinventory`,
  `sieve`, `labgate`, `labregister`, `sievestatus`, `rzbinstatus`, `diestatus`, `yarastatus`, `upxstatus`,
  `il2cppstatus`, `dexstatus`, `jvmstatus`, `capa`, `capastatus`, `ida`, `idamicrocode`, `idastatus`, `unpack`,
  `scan`, `minidump`, `capabilities`; 29 subcommands, from `cli.py`):
  `workspace.py`, `bounded_subprocess.py`, `cli.py`.

### Dynamic and emulation

- Unicorn is imported only by `recover/vex.py`, which corrects AVX instruction
  execution inside an emulation session someone else sets up. No range
  emulation, tracing or slicing ships.
- `tools/pe_sieve.py` (`pe_sieve_scan`, `pe_sieve_status`; family `dynamic`): a scan of ONE running process, by PID,
  for in-memory differences from its on-disk image (patched or hooked code, IAT hooks, replaced or hollowed images, implanted PEs and shellcode). Read from pe-sieve's own `/json /jlvl 2` report, and its category names are passed through as given. Scan only: `/ofilter 2` is always passed and no dump, import-recovery, minidump or reflection switch can be. The PID is required; a missing, invalid or all-processes request is `PID_REQUIRED` and starts nothing. The 64-bit scanner is used whenever it is present, because measured on 0.4.1.1 it scans 32-bit (WOW64) targets too (and also reports the native modules those load), while the 32-bit scanner cannot scan a 64-bit target and prints an all-zero, clean-looking report; that case is `SCANNER_MISMATCH`.
  **No result here means "clean" unless it is `OK` with `anomalies_found: false`,** and even then only for the modules and regions scanned at the depth in `scan_flags`: a process that could not be opened is `ACCESS_DENIED` or `PROCESS_NOT_OPENED`, zero modules scanned is `NOTHING_SCANNED`, unread or skipped modules make `SCAN_PARTIAL` (findings still listed). The access-denied wording and a non-zero `errors` report were not reproduced on the measuring machine; they are handled from the documented shape and the tests say so. Non-executable pages, thread stacks and kernel memory are not covered by default.
- `dynamic/lab_gate.py` (`dynamic_lab_gate`, `dynamic_lab_register_owned_process`, `frida_status`; family `dynamic`): the gate in front of every operation that touches a live process. **Behind the dynamic-lab gate (behaviour change):** `pe_sieve_scan` no longer runs on a bare PID. It needs `LIEBERT_RE_DYNAMIC_LAB=authorized` in the environment, an authorization naming who, why, this operation and this PID, the declared SHA-256 of the process image (verified against the file the process was started from), and a process the harness started (a direct child of the caller, or one registered with `dynamic_lab_register_owned_process`; CLI: `labgate`, `labregister`, `sieve --authorization JSON --sample-sha256 HEX`). Anything missing or unverifiable is refused (`AUTHORIZATION_REQUIRED`, `SAMPLE_HASH_REQUIRED`/`SAMPLE_HASH_MISMATCH`, `PROCESS_NOT_OWNED`, `RESOURCE_LIMIT_UNAVAILABLE`, ...) and nothing starts. The scanner runs under a timeout and a memory limit, and every call writes environment, user and elevation, the exact argument vector and the result to `dataset/evidence/dynamic_lab_gate/`. The gate does NOT verify an isolated guest, a snapshot or network control and says so on every call (`isolation_verified: false`); operations that execute or instrument a process (`execute_sample`, `launch_sample`, `frida_trace`, `frida_attach`, `frida_spawn`) are refused with `ISOLATION_REQUIRED`. Observing a harness-owned process is allowed without isolation, and the response gives that as the reason. The target's PID, creation time and image path are read again immediately before the scanner starts: a target that no longer matches is not scanned (`TARGET_IDENTITY_DRIFTED`), and a drift found after the run is carried in the result. If the final evidence record cannot be written the scan's result is withheld (`EVIDENCE_FINALIZE_FAILED`: it says the scan ran but was not recorded). Caller-supplied operation text never enters an evidence file name.
- `dynamic/apimonitor.py`: only `apimonitor_status` and `api_catalog` do real work. Live tracing
  and trace parsing are both `NOT_SUPPORTED`, but not for the same kind of reason, and each
  refusal says which (`restriction`, `permanent`, `reason`, `unlocks_when`, `working_operations`).
  Live tracing is a **permanent** restriction: the tool has no automation surface and live
  instrumentation sits behind the dynamic-lab isolation gate; retrying does not help. Trace
  parsing is **fixable**: the native `.apmx64`/`.apmx32` format is binary, proprietary and
  undocumented, and no verifiable sample was found. A text export from the tool's own export
  function, or a format definition, would unlock it; no format is supported today.
- `dynamic/frida_trace_client.py`: a guest-side launcher; no host-side driver
  ships, so nothing exercises it end to end. `frida_status` (in `dynamic/lab_gate.py`, so the client
  module stays the only place that imports frida) reports what frida the host has and that the
  client does not use it; it starts and attaches to nothing.

### Test coverage

81 test files (`tests/test_*.py`); an earlier default run on this checkout gave 527 passed, 39 skipped,
157 deselected (`heavy`), before the IDA wrapper's tests were added. Fixtures are built in code
(`recover/owned_binary_fixtures.py`); no real binaries ship. Real-engine paths
skip on a clean checkout, so CI does not demonstrate them.
The IDA wrapper's default-tier tests drive the real wrapper code against a stand-in `idat` that writes
what the real tool writes (log, packed database, result file); only the `IdaRealInstallTests` class runs
a real IDA, is marked `heavy`, and skips when idat is absent.

## Part 2: Where it is weak

### Kernel-level targets: a first look only

- `report/tool_families.py` names a `windows-kernel` family of 15 tools. Two are
  defined in this package: the generic `tool_missing` sentinel and
  `kernel_triage`. The other 13 are names of upstream tools that are not here;
  they are a roadmap, not capability.
- `kernel_triage` (`tools/binary.py`) is read-only and reads one PE with
  `pefile`: machine, subsystem, sections (including `INIT` and `PAGE` names),
  the import directory, resources and the debug directory. Each signal is
  reported separately as an `indicators` entry with its `confidence`
  (`deterministic` for the native subsystem and a `ntoskrnl.exe` / `hal.dll`
  import, `heuristic` for `INIT` and `PAGE` section names), and every entry
  carries `proves_driver: false`. `driver_likelihood` is `LIKELY` only when the
  native subsystem and a kernel import are both observed and the imports were
  fully readable; every other case, including conflicting or unreadable
  evidence, is `UNKNOWN`, with a `rationale` saying what is missing. It never
  returns a flat verdict because no static read of a file proves it will load
  as a driver. Fields it could not determine are `null` and listed in
  `unknown_fields`; a truncated file or an unreadable directory is
  `ANALYSIS_LIMITED`; a non-PE or an unsupported machine is refused.
- What `kernel_triage` does NOT do: it finds no dispatch routine, no IOCTL or
  control code, no callback registration, no device name, and it does not
  disassemble, emulate or run anything. It is not wired to the CLI.
- No module parses a driver's dispatch table, callback registrations, device or
  control-code definitions, or any other kernel-specific structure. Beyond the
  `kernel_triage` first look, a kernel-mode PE is handled as an ordinary PE:
  headers, imports, strings, disassembly.
- No exception/unwind data parser, so no function-boundary recovery for stripped
  x64 images.
- No bounded code-range emulation, so nothing can exercise a routine in
  isolation.
- No kernel-debugger or live-kernel integration, and no parser for kernel-dump
  formats. Only `MDMP`-format dumps are read.
- No decompiler and no cross-reference engine of its own. With a licensed IDA Pro 9.x on the
  machine, `ida_query` supplies decompiled pseudocode and cross-references from IDA's analysis of
  the real bytes (read-only, symbol-server lookups off); without IDA there is neither, and the Ghidra
  wrapper does not decompile or cross-reference (facts only). `recover/native_xref.py` resolves only over an IR the caller supplies.
- The package has never been demonstrated against a real kernel-mode file. The
  only driver-flavoured artefact is a synthetic fixture in
  `recover/owned_binary_fixtures.py`; kernel-oriented wording in
  `recover/api_hash_recover.py` and `recover/code_sweep_chunking.py` refers to
  upstream tools that are absent and is history, not capability.
- Non-Windows kernels and their loadable modules have no parser at all.

### Other classes of target not reached

- Virtualised or bytecode-interpreter protections, control-flow flattening,
  encrypted-at-rest sections: no devirtualisation, deflattening or static path. (The optional d810
  pass of `ida_microcode_cfg` runs a third-party microcode optimizer aimed at instruction-level
  obfuscation and flattening patterns; it is not a deflattener this project vouches for and does not
  touch virtualised code.)
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
   files". Actual at that check: 68 modules inside the `liebert_re/` package (CI asserts 68),
   68 test files (81 when re-counted later with `ls tests/test_*.py`). The "11 standalone challenge-solution scripts in
   `crackme_solutions/`" claim was removed; those scripts are not distributed
   in this package.
5. `BENCHMARKS.md` lists angr as a real in-process integration. Nothing in the
   package imports it; Unicorn is used only in `recover/vex.py`.
6. `README.md` and `INSTALL.md` omit modules that exist and run: WebAssembly
   inspection (`tools/formats.py`), `recover/native_xref.py` (IR-only) and
   `recover/code_sweep_chunking.py`. Not a false claim, but the capability table
   is not a complete inventory.
7. `report/tool_families.py` is a routing manifest, not a capability list; its
   `published_tools()` helper is the accurate view.

The README capability table is otherwise consistent with the code on the points
checked: 21 crypto algorithms, 7 hash algorithms, 32-bit-only hash constants,
x86_64-only stack scan, API Monitor refusals, and the PE directories not covered.

## Maintenance

Counts here are point-in-time (checkout of 2026-10-01). CI's wheel smoke test
asserts the shipped module count; this document is not part of that check and
adds no module.
