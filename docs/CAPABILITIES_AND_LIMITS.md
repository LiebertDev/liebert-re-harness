# Capabilities and limitations: an accurate starting picture

A record of what this repository's code does and does not do, written so that
future work starts from the real state rather than an optimistic one. It is
derived from `liebert_re/`, `tests/` and `.github/workflows/ci.yml`, not from the
prose docs. It describes capability only. It contains no procedure and proposes
no plan; [ROADMAP.md](ROADMAP.md) owns direction.

Read it with one fact in mind: **the capability set is general-purpose static
inspection of Windows user-mode files, plus a small set of format-specific
helpers. It is weak for kernel-level targets: `kernel_triage` gives a first
look at whether a PE looks like a driver, and four heuristic static operations
(dispatch-store candidates, import-slot references, callback-registration
imports, control-code decoding) give leads, not proofs. None of them proves a
dispatch table, a call or a registration, and none loads or runs a driver.**

## Part 1: What it can do

"Partial" means the module works but stops short of what a reader might assume.
Module paths are relative to `liebert_re/`.

### PE / COFF (Windows images), the strongest area

- Headers, sections with entropy, imports, exports, resources, strings, byte
  search, hashing, Authenticode inspection (Windows hosts only):
  `tools/binary.py`.
- TLS directory and callback array: `tools/tls_directory.py`.
- Data past the end of the last section: `pe_trailing_data` (`tools/pe_trailing.py`) reports its offset,
  size and share of the file, labels an embedded Authenticode certificate table (located, not verified)
  and a range consistent with a COFF symbol and string table (an arithmetic fit, records not decoded),
  and reports the rest as `UNKNOWN` purpose with an entropy figure; it does not classify the rest.
- RVA / VA / file-offset conversion, and dump-to-live address correlation over a
  single file: `recover/pe_address.py`, `tools/image_map.py`.
- Capstone disassembly of a PE range, with a chunked sweep for large sections:
  `tools/binary.py`, `recover/code_sweep_chunking.py`.
- CodeView / PDB identity and container parsing: `recover/codeview_rsds.py`,
  `recover/msf_pdb.py`; detection of a local PDB toolchain:
  `recover/native_pdb_toolchain.py`.
- Exception directory of a 64-bit PE: `pe_runtime_functions` / `pe_function_extent` (CLI `pdata`,
  `tools/pe_unwind.py`) give the exact begin and end of the function containing an address, from the
  file alone. Not function discovery: leaf functions get no entry, 32-bit x86 has no such table
  (`X86_NO_PDATA`), and the unwind records are not decoded.
- Partial: the PE surface does not cover delay imports, base relocations, the
  rich header or the decoded content of unwind records. `tools/binary.py` reports the subsystem
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
  `function_at_address`, `decompile_function` (Hex-Rays pseudocode), `xrefs_to` (a name is
  resolved exact, then demangled, then as an import name, and `resolved_by` says which; every candidate
  address is listed and none is chosen; code and data references are told apart by `kind`; calls are
  flagged, jumps are not calls), `xrefs_from` (references out of one address or out of a whole
  function, fall-through left out), `callers_of_import` (functions, addresses and call sites that
  reference an import's slot, one level of thunk followed; computed calls are not searched, so an
  empty list is "none found"), `read_bytes` (1..4096 bytes of the loaded database at an address; a
  byte IDA holds no value for is null, never zero), `imports_exports`, `strings`. Listings page with
  `offset` / `next_offset`.
- Read-only listing operations of `ida_query` (CLI `ida --operation ...`), each bounded and paged
  (`truncated` / `next_offset`), each refusing a malformed request before IDA starts, none calling anything
  that writes to the database (a static test parses the code and refuses a mutating call):
  `disasm_range` (up to 2000 rows from an address, or up to an end address; a row is an `instruction`
  with mnemonic and operands and no comments, defined `data`, an `undefined` run or an `inside_item`
  start, and only an instruction is ever disassembled), `basic_blocks` (IDA's flow chart: start, end,
  type, successor and predecessor starts), `callgraph` (breadth first from a function, depth 1-4, at
  most 500 nodes: direct edges, import edges and thunk jumps; a call through a register or a
  non-import memory operand is counted per node as `indirect_call_count` and never resolved, and a node
  not looked into says why), `stack_frame` (the frame IDA recorded: sizes, landmark offsets and members
  split into local, saved registers, return address and argument by those offsets; a function with no
  frame is `NO_STACK_FRAME`), `local_variables` (the decompiler's variables with type, argument or not
  and location; no Hex-Rays or a failed decompile is an error), `find_bytes` (an IDA byte pattern with
  `?` wildcards, in a range or a segment name, with the function containing each match),
  `find_immediate` (instructions with an immediate operand equal to a number, by IDA's own immediate
  search: the same constant written negated or sign-extended is another number and is not found),
  `list_structs` / `get_struct` (struct and union names of the local type library, and one type's
  members with bit-exact offsets) and `flirt_signatures` (the signature list with state and the
  matched-function count IDA recorded; listing only, no signature is applied). All of them read the
  database as IDA mapped the file, not process memory.
- Partial, by design: symbol-server (PDB download) lookups are switched off on every launch, so names
  that exist only in a PDB are absent. IDA's auto-analysis can miss or mis-split code in obfuscated or
  packed targets, so an absent function or xref is not proof of absence. Pseudocode is IDA's reading,
  not the source. An IDA database is not accepted as input.
- Two engines answer `ida_query`, chosen by `backend` (`auto` default): `idat` (the batch binary) and
  `idalib` (Hex-Rays' `idapro` package, in the interpreter named by `LIEBERT_RE_IDALIB_PYTHON`, which is
  never guessed). The operations are the same functions in both (one file, `query_program.idapy`, which the
  idalib worker loads), the cache is shared, and the answers were measured equal on the four checked
  questions (`list_functions`, `decompile_function`, `xrefs_to`, `read_bytes`) on one machine, and, for
  the read-only listing operations above, on every request of a 20-request run over one small PE on this machine, success and error answers alike once the engine-labelled envelope is set aside (`backend`, and the idalib `database_integrity` block that error answers carry); the engine
  that answered is in `backend` in every response. Limits: idalib needs a separate Python with `idapro`
  installed and activated; one worker process holds ONE database (opening a second silently saves and
  closes the first, so the worker cannot); the cached database is opened as a copy and measured before
  and after; per call it is no faster than idat (about 1 s versus 0.9 s here), and the `import idapro`
  probe that `auto` needs is cached for two minutes per process; a session that failed on the chosen
  engine is not retried on the other one. `ida_microcode_cfg`, `ida_type_member_offset`, `ida_patch_plan`
  and the annotation tools stay on idat.
- The first call on a file pays for IDA's analysis (two idat sessions, or one idalib session); later calls reuse a database
  cached by the input file's SHA-256 (`dataset/ida_cache/`, 5 GiB cap by default). `timeout_seconds`
  is one budget clamped to 5-600 s: the first analysis may use all of it (it runs once per file
  content), the session that answers a question never runs longer than 300 s. A timed-out analysis
  is discarded, not half-cached, and is reported as `TIMEOUT`, never as "nothing found". A listing
  cut short by a walk ceiling or by `max_chars` is `PARTIAL` and names the ceiling and its value.
- `ida_script` (CLI `idascript --script-file F`, also `tool run ida_script`): the one operation that runs code
  this package did not write. The caller's IDAPython runs once, in an idalib session, on a COPY of the
  cached database; the answer is the JSON value the script leaves in the variable `result`, labelled
  `result_kind: SCRIPT_REPORTED` (the script's claim). **What it verifies:** the input hash, that this
  script text ran to completion inside IDA on this input, that the session was closed without saving, and
  that the cached database file is byte-identical afterwards (hashed before and after; a change is
  `CACHE_VIOLATION`, the slot is dropped and there is no result). **What it does NOT enforce, and says so in
  every answer (`NOT_ENFORCED`): child processes, the network, the file system; the environment is
  inherited. It is not a sandbox.** An AST accident guard refuses the usual mistakes before anything starts
  (imports outside a short allow-list, `open`/`exec`/`eval`/`getattr`, attributes starting with `_`,
  `save_database` / `open_database` / `close_database`, debugger starts, file-writing and IDC-evaluating
  calls, `ida_dbg` so the sample is never run), but it is syntactic: `import json` then `json.codecs.open(...)`
  gets past it, and the test suite pins that gap on purpose. Closing it takes a different mechanism (a guest,
  a job object), not a longer list. Gates: the key `LIEBERT_RE_IDA_SCRIPT=authorized` (off by default:
  `AUTHORIZATION_REQUIRED`, nothing started), and the idalib backend (`backend="idat"` or an unconfigured
  idalib is `UNSUPPORTED`; idat opens the cache slot itself, so there is no idat path). Bounds: script
  session timeout 5-300 s (default 120; the process tree is killed, the cache slot is kept), memory polled
  against the process tree's resident size (default 4 GiB; a host that cannot measure it is
  `RESOURCE_LIMIT_UNAVAILABLE`, fail closed), stdout and stderr into a bounded buffer (never read as the
  result), `max_result_chars` for the value, `max_chars` for the response. A result that does not fit is
  withheld (`PARTIAL`, `script_result_withheld`), never cut. The full record (script text, worker result,
  stdout tail, signals) goes to `dataset/evidence/ida_script/`; if it cannot be written the result is withheld
  (`EVIDENCE_WRITE_FAILED`). Measured once, on one stock Windows PE with 501 functions on this machine: a
  function-count script returned 501, the same as `list_functions`; a script that renamed a function saw its own
  change and left the cached database's hash unchanged; a decompiler visitor script counted call expressions;
  a script with `import os` was refused before IDA started; one script call took about 2 s wall, about 1 s of it
  the session. Not done: running the script in a guest (a later slice), keeping scripts for public crackmes as
  knowledge, any allow-list of IDA APIs beyond the names the guard refuses.
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
- Not here: decompiler comments, and a disassembly listing from rizin or Ghidra into the same shape (IDA's database range is `disasm_range`). Ghidra: see the next section.
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

### Ghidra (headless: status, program facts and decompilation of selected functions)

- `tools/ghidra.py`: `ghidra_status`, `ghidra_program_facts` and `ghidra_decompile`, driving Ghidra's own
  `support/analyzeHeadless`. CLI: `ghidrastatus`, `ghidrafacts` and `ghidradecompile`.
- `ghidra_status` discovers the install (`GHIDRA_INSTALL_DIR`, `GHIDRA_HOME`, `PATH`, then known locations) and
  reports the version, the Java the install needs and the Java found. It does NOT launch Ghidra
  (`launcher_verified: false`): `OK` means files present and Java new enough, not that a run will succeed.
- `ghidra_program_facts` imports one file into a throw-away project and returns, read-only: loader, language,
  processor, endianness, address width, compiler spec, image base, entry points, memory blocks, function count
  (what analysis found in the time bound, not a complete inventory) and imported library names. A fact the
  script could not read is `null` and named, never guessed. The source file's SHA-256 is compared before and
  after; a changed source is refused (`SOURCE_MODIFIED`).
- `ghidra_decompile` runs the same import and default analysis, then decompiles at most 16 functions you name
  (an address written `0x...` or an integer, or a function name; a string not written `0x...` is always a name)
  with Ghidra's own decompiler, read-only: no transaction is opened and nothing is saved. Each request gets
  one entry: `address`, `name`, `signature`, `decompiled_signature`, `c_code`, `decompile_completed`, `warnings`
  and `error`. A function that is not found, whose name is shared by several functions
  (`AMBIGUOUS_FUNCTION_NAME`, with their addresses), that times out per function (default 30 s) or fails to
  decompile has `c_code: null` and the reason; the call is `OK` only when every function decompiled, `PARTIAL`
  when some did and `ANALYSIS_LIMITED` when none did. A `warnings` entry such as `halt_baddata` means Ghidra
  met bytes it could not decode: that C is not evidence of what the code does. The C is Ghidra's inference,
  not source. Every call pays the import and analysis again (about two minutes for a system executable
  measured on one machine), so ask for the functions you need in one call.
- **Exit code 0 is not success.** Measured: when the post-script fails, `analyzeHeadless` still exits 0. The
  wrapper scans the log for failure markers and requires the result file to exist, parse and carry the
  script's completion flag; anything less is `ANALYSIS_LIMITED`.
- The script is Java. A Jython `.py` script does not run on a stock install ("Ghidra was not started with
  PyGhidra"); PyGhidra needs a `pip install` and is not used or tested here.
- Each run has its own temporary project (Ghidra locks per project), placed outside the checkout because Ghidra
  refuses a project path with a dot-prefixed element.
- Why it was added: it is free and runs in CI (an IDA licence does not), and "answer the same question two
  ways" in the assessment order needs a second engine. Not here: cross-references, writes, a decompile of
  every function, a persistent project that skips re-analysis.

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
  `il2cppstatus`, `dexstatus`, `jvmstatus`, `capa`, `capastatus`, `ida`, `idascript`, `idamicrocode`, `idastatus`, `idaannotations`,
  `kerneltriage`, `kerneldispatch`, `kerneliat`, `kernelcallbacks`, `ioctldecode`, `ghidrastatus`, `ghidrafacts`, `ghidradecompile`, `emulate`, `unpack`,
  `scan`, `minidump`, `pdata`, `trailing`, `tool`, `capabilities`; 43 subcommands, from `cli.py`):
  `workspace.py`, `bounded_subprocess.py`, `cli.py`.

### Dynamic and emulation

- `recover/emulate.py` (`emulate_range`; family `emulation`; CLI `emulate`, or `tool run emulate_range`): bounded emulation
  of a range of an x86-64 PE32+ image with Unicorn. **What it does.** Maps the image at its preferred base (no relocation; a
  collision with the fixed stack, TEB, PEB or trap regions is `MAP_CONFLICT`), with section permissions exactly as declared
  (`perm_mode="rwx"` maps everything read-write-execute and is reported as an approximation). Points every ordinary import
  slot at its own unmapped trap address, so a call into an import stops the run as `IMPORT_CALL` with `dll!name`. Pushes a
  sentinel return address, so the entry routine returning is `RETURNED`. Runs from the `start_va` the caller gives (TLS
  callbacks and loader initialisers do not run). Provides a minimal TEB/PEB (GS base; StackBase, StackLimit, Self, the PEB
  pointer, ImageBaseAddress, BeingDebugged 0, Ldr NULL) and lists exactly which fields it assigned in `teb_peb_model`; every
  other byte is zero, which is the absence of a model, not a Windows value. Every run stops with a named `stop_reason`:
  `RETURNED`, `STOP_ADDRESS`, `IMPORT_CALL`, `SYSCALL` (a `syscall` or `sysenter`; RAX is reported), `INTERRUPT`, `INT3`,
  `UD2`, `HLT`, `PORT_IO`, `UNMAPPED_READ`/`WRITE`/`FETCH`, `WRITE_PROTECT`, `READ_PROTECT`, `FETCH_PROTECT`,
  `INVALID_INSTRUCTION`, `INSN_LIMIT`, `TIMEOUT`, `UNMODELLED_VEX`, `ENGINE_ERROR`, `ENGINE_CRASH` and `UNKNOWN_STOP`. It reports
  the instruction count, the stop-time registers, the last 64 instruction addresses, every region the code wrote (merged where
  bytes touch, with its SHA-256 and whether any instruction was executed from it after it was written, the signature of a
  self-decoding image), and per-section differences from the loaded image with the changed sections dumped as raw bytes (not a
  PE) under `dataset/emulation/<input_sha16>/<run_id>/`. Instructions are counted by a per-instruction hook. Measured on one machine, a decrypt-style XOR loop of 4.85 million
  instructions took about 8.5 seconds end to end (about 0.6 million instructions per second when the loop shares a page with
  the bytes it rewrites, 0.8 million when it writes elsewhere, 1.3 million for a loop with no writes), so the default bound of
  5 million instructions takes roughly 4 to 9 seconds, well inside the default 120 seconds. VEX-encoded instructions are executed by `recover/vex.py`, and one it does not model stops the run.
  **What it does not do.** It executes nothing natively on the host: the engine runs inside Unicorn, in a separate interpreter
  with a timeout and a memory limit. That is a process boundary and **not a sandbox**, and every response says so
  (`host_isolation`). It answers no import and no syscall (there are no API stubs, no handles, files, threads or exceptions),
  it does not read delay-load or bound imports, it refuses 32-bit images, and it does not know what a real CPU would return
  for `cpuid` or `rdtsc` (Unicorn's model answers). It is not a way to run a sample safely, and the gate is not a way to
  establish that you may analyse it. **The gate.** `target_class` is required: `public_crackme` (a challenge written to be
  solved) or `owned_target` (the caller owns it: an authorization names who authorised the run and why, and its
  `sample_sha256` must equal the file's real SHA-256, else `SAMPLE_HASH_MISMATCH`). Anything else, or nothing, is
  `TARGET_CLASS_REQUIRED`, and a third-party target is refused. A `public_crackme` whose file name matches an entry of the
  operator's own list in `~/.liebert-re/targets.txt` is `CLASS_CONFLICT`; that check is best effort and `registry_checked` says
  whether the list was read. The declaration is not verified and no environment variable opens the gate. Evidence goes under
  `dataset/evidence/emulate_range/`; if the final record cannot be written the result is withheld
  (`EVIDENCE_FINALIZE_FAILED`). A native crash of the engine process is `ENGINE_CRASH`, and what it had written is listed as
  `unverified`. Responses contain no file-system path.
- `tools/pe_sieve.py` (`pe_sieve_scan`, `pe_sieve_status`; family `dynamic`): a scan of ONE running process, by PID,
  for in-memory differences from its on-disk image (patched or hooked code, IAT hooks, replaced or hollowed images, implanted PEs and shellcode). Read from pe-sieve's own `/json /jlvl 2` report, and its category names are passed through as given. Scan only: `/ofilter 2` is always passed and no dump, import-recovery, minidump or reflection switch can be. The PID is required; a missing, invalid or all-processes request is `PID_REQUIRED` and starts nothing. The 64-bit scanner is used whenever it is present, because measured on 0.4.1.1 it scans 32-bit (WOW64) targets too (and also reports the native modules those load), while the 32-bit scanner cannot scan a 64-bit target and prints an all-zero, clean-looking report; that case is `SCANNER_MISMATCH`.
  **No result here means "clean" unless it is `OK` with `anomalies_found: false`,** and even then only for the modules and regions scanned at the depth in `scan_flags`: a process that could not be opened is `ACCESS_DENIED` or `PROCESS_NOT_OPENED`, zero modules scanned is `NOTHING_SCANNED`, unread or skipped modules make `SCAN_PARTIAL` (findings still listed). The access-denied wording and a non-zero `errors` report were not reproduced on the measuring machine; they are handled from the documented shape and the tests say so. Non-executable pages, thread stacks and kernel memory are not covered by default.
- `dynamic/lab_gate.py` (`dynamic_lab_gate`, `dynamic_lab_register_owned_process`, `frida_status`; family `dynamic`): the gate in front of every operation that touches a live process. **Behind the dynamic-lab gate (behaviour change):** `pe_sieve_scan` no longer runs on a bare PID. It needs `LIEBERT_RE_DYNAMIC_LAB=authorized` in the environment, an authorization naming who, why, this operation and this PID, the declared SHA-256 of the process image (verified against the file the process was started from), and a process the harness started (a direct child of the caller, or one registered with `dynamic_lab_register_owned_process`; CLI: `labgate`, `labregister`, `sieve --authorization JSON --sample-sha256 HEX`). Anything missing or unverifiable is refused (`AUTHORIZATION_REQUIRED`, `SAMPLE_HASH_REQUIRED`/`SAMPLE_HASH_MISMATCH`, `PROCESS_NOT_OWNED`, `RESOURCE_LIMIT_UNAVAILABLE`, ...) and nothing starts. The scanner runs under a timeout and a memory limit, and every call writes environment, user and elevation, the exact argument vector and the result to `dataset/evidence/dynamic_lab_gate/`. The gate does NOT verify an isolated guest, a snapshot or network control by itself and says so on every call (`isolation_verified: false`); operations that execute or instrument a process (`execute_sample`, `launch_sample`, `frida_trace`, `frida_attach`, `frida_spawn`) are refused with `ISOLATION_REQUIRED` unless the caller names a measurement file (`labgate --guest-measurement FILE --local-vm-id GUID [--max-age-s N]`; explicit arguments, no environment variable or default location) and `GuestAttestation.admit` judges it `VERIFIED`: fresh, the VM's adapters only on Private switches with no host adapter on them, a Standard checkpoint, Memory Integrity running in the guest, the guest reached over PowerShell Direct, and the file measured about the machine the gate runs on. `UNKNOWN` (anything missing, stale, contradictory or malformed) and `FAILED` (a measured violation) both refuse and list the reasons. The measurement is a spoofable file and `VERIFIED` opens only that one check; authorization, ownership, sample hash, bounds and evidence still apply, and the gate starts nothing. Observing a harness-owned process is allowed without isolation, and the response gives that as the reason. The target's PID, creation time and image path are read again immediately before the scanner starts: a target that no longer matches is not scanned (`TARGET_IDENTITY_DRIFTED`), and a drift found after the run is carried in the result. If the final evidence record cannot be written the scan's result is withheld (`EVIDENCE_FINALIZE_FAILED`: it says the scan ran but was not recorded). Caller-supplied operation text never enters an evidence file name.
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

Current: the test-file count is stated in one place, `docs/INSTALL.md` (pinned to a measurement by `tests/test_docs_counts_match_code.py`); `pytest --collect-only` selects 2082 of 2155 tests, with 73
deselected (`heavy`) (counted when this line was last updated; pass and skip counts are not recorded
here, run `pytest -q` for them). Historical snapshot, not current: an early run on an older checkout
gave 527 passed, 39 skipped, 157 deselected, from 81<!-- count:historic --> test files, before the IDA wrapper's tests were added. Fixtures are built in code
(`recover/owned_binary_fixtures.py`); no real binaries ship. Real-engine paths
skip on a clean checkout, so CI does not demonstrate them.
The IDA wrapper's default-tier tests drive the real wrapper code against a stand-in `idat` that writes
what the real tool writes (log, packed database, result file); only the `IdaRealInstallTests` class runs
a real IDA, is marked `heavy`, and skips when idat is absent.

## Part 2: Where it is weak

### Kernel-level targets: a first look only

- `report/tool_families.py` names a `windows-kernel` family of 19<!-- count:kernel_family_named --> tools (counted from the code).
  10<!-- count:kernel_family_defined --> are defined in this package (also counted from the code, as `published_tools("windows-kernel")`): the generic `tool_missing` sentinel, `kernel_triage`,
  five operations in `tools/binary.py`, described below (byte-pattern scans and a
  disassembly-based candidate lister whose findings never prove what they name, and
  one decoder that splits CTL_CODE integers the caller already has), `ida_query`,
  and the two exception-directory operations `pe_runtime_functions` / `pe_function_extent`
  (CLI `pdata`). The rest are names of upstream tools that are not here; they are a roadmap,
  not capability.
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
- What `kernel_triage` alone does NOT do: it finds no dispatch routine, no IOCTL or
  control code, no callback registration, no device name, and it does not
  disassemble, emulate or run anything. It is reachable from the CLI as
  `kerneltriage`. Four separate operations in `tools/binary.py` (below) cover
  part of what it leaves out.
- Four heuristic, static kernel operations (CLI `kerneldispatch`, `kerneliat`,
  `kernelcallbacks`, `ioctldecode`). None loads or runs a driver, so Memory
  Integrity (HVCI) and Core Isolation stay enabled. Each was run against real
  Microsoft drivers in a measurement session; this document records no counts
  and several drivers gave no result.
  - `driver_major_function_scan`: byte-pattern search near `DriverEntry`, no
    disassembler. It lists CANDIDATES for stores into
    `DriverObject->MajorFunction[...]`. It does not prove a dispatch table:
    `proves_dispatch` is always `false` and `dispatch_table` is only
    `CANDIDATES_ONLY` or `UNKNOWN`. A driver can give no candidate, for
    example when the stores sit at the end of a nested `call` chain or away
    from the entry point.
  - `rip_relative_iat_scan`: finds RIP-relative references to import slots.
    `proves_call` is `false`. `max_findings` defaults to 200 and a large
    driver exceeds it; the cut is reported in `truncation`.
  - `kernel_callback_registrations`: reports which of a fixed list of
    callback-registration APIs a driver references through its import table.
    `NOT_FOUND` speaks only for the names in `names_checked`, says nothing
    about other names or other ways to register, and is never returned for a
    truncated scan (that is `UNKNOWN`). The callback address is not recovered.
  - `ioctl_control_code_decode`: bit arithmetic that splits `CTL_CODE`
    integers into their fields. It does not find the integers itself; the
    caller supplies them, by hand or from `ioctl_candidate_scan` (below).
- Two further operations in `tools/binary.py`, neither with a dedicated
  subcommand: both are reached through `liebert-re tool run <name> --args '{...}'`.
  - `ioctl_candidate_scan`: the feeder for `ioctl_control_code_decode`. It
    disassembles a code region linearly from a start RVA and lists immediates
    that are compared, each split by the decoder. It lists compared
    immediates; it does not list "the driver's IOCTLs", because a compared
    value can equally be a constant, a mask or a status code.
    `proves_ioctl` is `false` in every result and there is no boolean "is an
    IOCTL" field; each candidate carries named criteria instead. Searched:
    `cmp reg, imm`, `cmp [mem], imm` and `sub reg, imm` chains. Not searched,
    and declared in `scope.patterns_not_searched`: `mov reg, imm`, register
    or memory comparisons, `lea`/`add` biases, jump-table switches, other
    operand widths, and any function-end signal other than `ret` (`int3` runs
    and `nop` padding are not treated as boundaries). The scan is linear: it
    does not follow `jmp` or `call`. A value below `0x10000`, a stack-pointer
    operand or `0xFFFFFFFF` is not admitted; each is counted by reason and
    listed in `excluded`. The scan does not stop at `ret`, because handlers
    return early and stopping would scan too little; instead every `ret`
    passed is reported (`scope.rets_passed`, capped at 50 listed with the
    total count) and every candidate and exclusion carries `rets_before`. A
    candidate with `rets_before > 0` lies after a `ret` and may belong to
    another function than the one scanned. It is not chained automatically
    from `driver_major_function_scan`: the start address is given explicitly
    and its source is recorded (`scope.start.source`, `start_note`). A
    truncated or partly undecodable scan that found nothing is `UNKNOWN`;
    `NOT_FOUND` is returned only for a complete, fully decoded scan, and its
    rationale names the patterns searched.
  - `disassemble_pe_structured`: disassembly with the same output contract as
    the rizin-backed disassembly, plus numeric `immediates` and `rip_relative`
    fields per instruction. An ARM64 image is refused with
    `STRUCTURED_UNSUPPORTED_MACHINE`.
  - Measurement, one driver, one start address, 200 instructions (a
    Microsoft-signed system driver used as a read-only sample): from the
    handler start the scan passed 5 `ret` instructions, and `sub rsp` and
    `cmp [rbx+0x38], 1` sites that it excluded lay after the fifth, at an
    address that `driver_major_function_scan` lists (heuristically) as the
    start of a different handler (`IRP_MJ_CREATE`). This shows
    the boundary report working on real code; it is one case, not a rate.
- No module proves a driver's dispatch table, callback registrations, device or
  control-code definitions, or any other kernel-specific structure. Beyond
  `kernel_triage` and the operations above, a kernel-mode PE is handled as
  an ordinary PE: headers, imports, strings, disassembly.
- Function-boundary recovery for stripped x64 images is limited to what the exception directory
  lists (`pe_function_extent`, CLI `pdata`): leaf functions have no entry, so most small functions
  are not recoverable this way, and there is no recovery for x86 images or from prologue patterns.
  The unwind records are not decoded.
- Bounded code-range emulation exists (`emulate_range`), but it stops at the first import or syscall and has no API stubs,
  so a routine that calls the operating system cannot be run through it yet; there are no traces beyond the last 64
  instruction addresses and no slicer.
- No kernel-debugger or live-kernel integration, and no parser for kernel-dump
  formats. Only `MDMP`-format dumps are read.
- No decompiler and no cross-reference engine of its own. With a licensed IDA Pro 9.x on the
  machine, `ida_query` supplies decompiled pseudocode and cross-references from IDA's analysis of
  the real bytes (read-only, symbol-server lookups off); without IDA there are no IDA answers. The Ghidra wrapper
  decompiles selected functions (`ghidra_decompile`, at most 16 per call) but has no cross-reference
  query. `recover/native_xref.py` resolves only over an IR the caller supplies.
- The kernel operations above were measured on real drivers only in a
  measurement session, with no corpus kept in the repository; the test suite
  uses synthetic fixtures, including one in
  `recover/owned_binary_fixtures.py`. Kernel-oriented wording in
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
   dependencies alone. At that check no range emulation shipped; `recover/vex.py` is an
   instruction-semantics correction layer. It also lists function inventory
   there, but `rizin_functions` needs rizin.
4. `INSTALL.md` counts: "64<!-- count:historic --> Python modules at the repository root", "47<!-- count:historic --> test
   files". Actual at that check: 68<!-- count:historic --> modules inside the `liebert_re/` package (CI asserted 68<!-- count:historic --> then),
   68<!-- count:historic --> test files (81<!-- count:historic --> when re-counted later with `ls tests/test_*.py`). The "11 standalone challenge-solution scripts in
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

Counts here are point-in-time (checkout of 2026-10-06). No module count is typed by hand
in CI: the wheel smoke test measures the shipped modules and compares them with the checkout,
and `tests/test_docs_counts_match_code.py` pins the documented figure (in `docs/INSTALL.md`)
to the same measurement. This document adds no module.
