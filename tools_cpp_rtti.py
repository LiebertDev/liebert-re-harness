"""MSVC C++ RTTI class recovery -- structured class evidence Ghidra's
decompile text alone does not give this harness. Supports both 32-bit
(absolute-VA) and 64-bit (RVA-relative) MSVC PE images.

MSVC embeds a C++ class's runtime type identity as a fixed chain of structs
sitting a few dwords ahead of its vftable, unrelated to (and predating)
Itanium/GCC's ``_ZTI``/``_ZTS`` scheme:

    TypeDescriptor          <-- mangled name (``.?AV<name>@@`` = class,
                                 ``.?AU<name>@@`` = struct)
    CompleteObjectLocator (COL)  -- points at one TypeDescriptor + one CHD
    ClassHierarchyDescriptor (CHD)  -- attributes + numBaseClasses + one
                                       BaseClassArray pointer
    BaseClassArray           -- numBaseClasses pointers to...
    BaseClassDescriptor(s)   -- one per base, each with its own
                                TypeDescriptor pointer and a PMD
                                (mdisp/pdisp/vdisp) placing that base inside
                                the derived object

== 32-bit (absolute VA) layout, hand-verified byte-for-byte in Phase 1 ==

TypeDescriptor name at TD+8 (``pVFTable``(4)+``spare``(4) ahead of the name).
COL is 20 bytes: ``signature``(0, must be 0)/``offset``(4)/``cdOffset``(8)/
``pTypeDescriptor``(12)/``pClassHierarchyDescriptor``(16), all absolute VAs.
CHD is 16 bytes: ``signature``(0, must be 0)/``attributes``(4)/
``numBaseClasses``(8)/``pBaseClassArray``(12), absolute VA. BaseClassArray is
``numBaseClasses`` consecutive 4-byte ``BaseClassDescriptor*`` absolute-VA
pointers. BaseClassDescriptor is 24 bytes: ``pTypeDescriptor``(0, absolute
VA)/``numContainedBases``(4)/``mdisp``(8, signed)/``pdisp``(12, signed)/
``vdisp``(16, signed)/``attributes``(20). Independently hand-verified against
this repo's own ``benchmarks/windows_native_ladder/corpus/tier0/
simple_crackme/crackme.exe`` before any of this was written: the ``.?AV``
strings for ``type_info``, ``std::bad_alloc``, ``std::exception`` and
``std::bad_array_new_length`` were found in ``.rdata``, and the
COL/CHD/BaseClassArray/BaseClassDescriptor chain was walked backwards from
each one by hand, byte-for-byte, confirming
``bad_array_new_length : bad_alloc : exception`` resolves through three
levels of real ``where{mdisp=0,pdisp=-1,vdisp=0}`` base entries.

== 64-bit (RVA-relative) layout, hand-verified byte-for-byte in Phase 2 ==

Every pointer field that was an absolute VA on 32-bit becomes a 32-bit RVA
(relative to the image base) on 64-bit -- ``pTypeDescriptor``,
``pClassHierarchyDescriptor``, every ``BaseClassArray`` entry, and every
BaseClassDescriptor's own ``pTypeDescriptor``. Field sizes and offsets inside
each struct are otherwise unchanged (CHD stays 16 bytes at the same offsets;
BaseClassDescriptor stays 24 bytes at the same offsets -- a published
``pClassDescriptor`` extension field for generic/template classes,
signalled by BaseClassDescriptor.attributes bit 0x40 ["HASPCHD"], was
observed set on every real BaseClassDescriptor found this session but is
NOT read here -- reading it is a later phase's problem, matching Phase 1's
own precedent of not implementing the generalized-class-descriptor
extension). Two things genuinely differ:

1. TypeDescriptor's name sits at TD+16, not TD+8: ``pVFTable`` and ``spare``
   are 8-byte pointers on 64-bit, not 4-byte ones.
2. COL grows to 24 bytes and gains a sixth field, ``pSelf`` (offset 20): the
   COL's own RVA. A genuine COL's ``pSelf`` always equals its own RVA from
   image base -- the single strongest verification anchor this format has,
   analogous to ``tools_delphi.py``'s ``vmtSelfPtr`` self-pointer check. A
   64-bit COL candidate whose ``pSelf`` does not resolve to its own address
   is rejected outright here, never merely downgraded to CANDIDATE -- see
   ``_COL_PSELF_MISMATCH`` in ``_resolve_chain``. COL's ``signature`` field
   is 1 on 64-bit (0 on 32-bit); this is checked as strictly as ``pSelf``.

Hand-verified against this repo's own
``benchmarks/windows_native_ladder/corpus/tier2/crackme_easlog/x64.exe``:
every real COL found there (``std::logic_error``, ``std::length_error``,
``std::out_of_range``, ``std::bad_exception``, ``std::runtime_error``, and
more) has ``signature == 1`` and ``pSelf`` exactly equal to its own RVA,
while every other place the same TypeDescriptor's RVA happens to occur as a
raw dword in the image (BaseClassDescriptor pointer fields, unrelated data)
fails either the signature or the ``pSelf`` check and is correctly rejected.
The full chain was walked by hand from those real COLs through their real
CHDs and BaseClassArrays, confirming
``logic_error : exception``, ``length_error : logic_error : exception`` and
``out_of_range : logic_error : exception`` -- real single, non-virtual
inheritance, ``where{mdisp=0,pdisp=-1,vdisp=0}`` on every edge, the 64-bit
counterpart of the 32-bit std:: exception chain above. See
``docs/TOOL_GAP_BACKLOG.md``'s GAP-022 section for the exact byte addresses.

== Multiple and virtual inheritance: real MSVC bytes, not just a synthetic
   fixture, as of Phase 2 ==

Phase 1 could only verify CHD ``attributes`` bit0 (multiple inheritance),
bit1 (virtual inheritance) and the "``pdisp != -1`` means a virtual base"
rule against a synthetic hand-built fixture -- no real MSVC-compiled
multiple/virtual-inheritance binary was in this repo's corpus at the time.
Phase 2 searched every RTTI-bearing target in the corpus (32 real targets,
both bitnesses) and found real ones:

- ``std::locale::_Locimp`` in ``crackme_easlog/x64.exe``: CHD attributes bit0
  set (``0b1``), three real, distinct, non-virtual (``pdisp == -1``) direct
  bases (``facet``, ``_Facet_base``, ``_Crt_new_delete``) -- genuine multiple
  inheritance, hand-verified byte-for-byte. Bit0's meaning is now PROVEN
  against real bytes, not just the published-convention/synthetic-fixture
  basis Phase 1 had.
- ``std::basic_ostream``/``std::basic_istream`` in the same target: a real,
  direct virtual base (``std::basic_ios``, reached via ``pdisp=0,vdisp=4`` --
  the classic vbtable-indirection PMD shape, not ``pdisp=-1``). The
  "``pdisp != -1`` means a virtual base" rule is now PROVEN against real
  bytes for the same reason.
- ``std::basic_stringstream`` in ``hackers_edge_crackme_v2.exe``: the full
  iostream diamond -- ``basic_iostream`` multiply inherits ``basic_istream``
  and ``basic_ostream``, and ``basic_ios`` appears exactly once in the
  flattened BaseClassArray reached from each of those two paths at the exact
  same ``mdisp/pdisp/vdisp``, i.e. it really is one shared virtual base, not
  two independent copies. CHD attributes here is ``0b11`` (both bits set).

What did NOT get proven, and is recorded as a real, byte-level contradiction
rather than smoothed over: CHD ``attributes`` bit1 ("virtual inheritance") is
NOT a reliable signal by itself. ``basic_ostream``'s own CHD in
``crackme_easlog/x64.exe`` has ``attributes == 0`` despite that class having
a real, direct ``pdisp != -1`` virtual base (``basic_ios``) -- verified
directly against the raw bytes at that CHD's own RVA, not a
misinterpretation of a different field. So bit1 is set in some genuine
virtual-inheritance cases (``basic_stringstream`` above) and NOT set in
others (``basic_ostream``) on real MSVC-compiled binaries. Because of that
direct real-bytes contradiction, bit1 alone stays an interpretive signal
(``VIRTUAL_INHERITANCE_ATTRIBUTE_SET`` in ``evidence_tier_reasons`` -- see
below) on BOTH bitnesses -- promoted no further than that, on purpose.

Bit0 (multiple inheritance) and the ``pdisp != -1`` virtual-base rule ARE
promoted, but **only on the 64-bit code path, and only because that is
where the real verification happened**. All three real hand-verified
targets above (``crackme_easlog/x64.exe``'s ``_Locimp``/``basic_ostream``/
``basic_istream``, and ``hackers_edge_crackme_v2.exe``'s
``basic_stringstream``) are AMD64 PE images -- confirmed directly from each
file's own COFF ``FILE_HEADER.Machine`` field (``0x8664``), not assumed.
This repo's corpus has NO real 32-bit MSVC-compiled binary exhibiting
multiple or virtual inheritance, so on the 32-bit path those same two
features stay CANDIDATE (``MULTIPLE_OR_VIRTUAL_INHERITANCE_UNVERIFIED_ON_32BIT``
in ``evidence_tier_reasons``) even though the identical structural
signature no longer downgrades a 64-bit class. This module's own PROVEN
bar is "hand-verified against real bytes on this exact code path", not
"matches a published ABI convention" -- verifying a rule against a 64-bit
binary proves the rule for the 64-bit code path, not for the separate
32-bit code path that happens to share the same bit positions. Promoting
32-bit uniformly on 64-bit evidence would be exactly the kind of
overclaim this tool exists to avoid, so it is deliberately not done here.

Chained verification, never a bare name match: a TypeDescriptor name string
alone is only ever reported as a CANDIDATE. It is promoted to a class with a
hierarchy only when some COL in the image points at it AND that COL's own
``pClassHierarchyDescriptor`` resolves to a CHD whose BaseClassArray entries
each independently resolve to a TypeDescriptor that itself re-passes the
same name-shape check. Any one broken link anywhere in that chain drops the
candidate back to CANDIDATE with the reason stated, never a guess. On
64-bit, a COL candidate additionally has to pass the ``pSelf`` anchor
described above before it is even considered.

Scope: the PE's own COFF machine field selects 32-bit vs 64-bit parsing;
every other machine type (e.g. ARM/ARM64) is refused outright
(``UNSUPPORTED_MACHINE``) rather than misparsed against either x86 layout.
Binary-to-binary hierarchy diffing is still a later phase, not here.

== Vtable-to-COL binding (Phase 3) ==

The MSVC ABI's own back-link -- the pointer-sized value immediately BEFORE
a vtable is always that vtable's own COL address (``vtable[-1] == &COL``) --
is walked in reverse: for every resolved class's own COL address(es), this
module scans the image for a pointer-sized occurrence of that exact address
and, if found, treats the pointer-sized value right after it as the start of
that COL's vtable.

Hand-verified byte-for-byte on 2026-08-31 against 7 real vtables across both
bitnesses before any binding code was written (see
``docs/TOOL_GAP_BACKLOG.md`` GAP-022 Phase 3 for the full walk):
``std::logic_error``/``std::length_error``/``std::out_of_range`` (2 slots
each) and ``std::basic_filebuf``/``std::basic_streambuf`` (15 slots each) on
``crackme_easlog/x64.exe`` (64-bit), plus ``simple_crackme/crackme.exe``'s
own std:: exception family (1-2 slots each, 32-bit). Two things this
confirmed, not assumed:

1. A vtable's own function-pointer slots are always plain absolute VAs, on
   BOTH bitnesses -- unlike the surrounding RTTI structures (COL/CHD/
   BaseClassArray/BaseClassDescriptor), which switch to RVA-relative fields
   on 64-bit (see above), a compiled vtable itself is never RVA-relative on
   either bitness. ``_to_va`` is deliberately NOT applied to vtable slot
   values.
2. **Termination rule, read directly off real bytes, not guessed**: a
   vtable's slot run ends at the first pointer-sized value that does not
   fall inside any of the image's own ``IMAGE_SCN_MEM_EXECUTE``-flagged
   section ranges (``_executable_ranges``/``_in_executable_range``) -- never
   a fixed ``.text``-name lookup, a hardcoded address list, or "next COL"
   specifically (in every one of the 7 real cases the terminating value
   happened to BE the next class's own vtable[-1] pointer, but the rule that
   actually decides it is purely "does this value point into an executable
   section", and that is what is implemented). Reaching this module's own
   ``MAX_VTABLE_SLOTS`` scan cap, or running off the end of the image before
   any non-executable value appears, both leave the true slot count
   genuinely undetermined and are reported CANDIDATE with a specific reason
   (``VTABLE_SLOT_SCAN_LIMIT_REACHED``/``VTABLE_SLOT_RAN_OFF_END_OF_IMAGE``),
   never a guessed PROVEN count.

**What did NOT hold, corrected before any code was written.** The working
assumption going into this phase -- "a class with genuine multiple
inheritance must have more than one vtable, one per polymorphic base
subobject" -- was tested directly against ``std::locale::_Locimp`` (Phase
2's own hand-verified real multiple-inheritance class, three direct bases:
``facet``, ``_Facet_base``, ``_Crt_new_delete``) and did NOT hold: a raw
scan for every occurrence of ``_Locimp``'s own TypeDescriptor RVA in the
whole image found exactly one genuine COL, not several. A full corpus sweep
(every RTTI-bearing class recovered from every target this module resolves)
confirms this is not specific to ``_Locimp``: **zero classes anywhere in
this repo's corpus have more than one COL/vtable.** The follow-up check that
explains it, also verified against real bytes rather than assumed: `facet`
and `_Facet_base` sit at the exact same ``mdisp`` (0) inside `_Locimp`'s own
BaseClassArray -- i.e. they are the SAME subobject address (`facet`'s own
single-inheritance chain from `_Facet_base`, not a second sibling
subobject), and `_Facet_base` independently DOES have its own standalone
COL/vtable elsewhere in the same image (proving it is genuinely polymorphic,
which refutes a simpler "non-polymorphic base" story for it specifically).
Only `_Crt_new_delete` sits at a distinct ``mdisp`` (8) and has no COL
anywhere in this image, consistent with (but not independently proof of)
having no virtual functions of its own. So the corrected rule this module's
data shape is built to respect is "one vtable per distinct polymorphic
``mdisp`` offset", not "one vtable per direct base" -- and this corpus
currently offers no class where more than one distinct ``mdisp`` offset is
independently confirmed polymorphic, so the "more than one real vtable"
case stays unobserved rather than fabricated. Each class's ``vtables`` field
is a LIST for exactly this reason: nothing about the binding logic assumes
at most one, and a future real multi-vtable sample needs no schema change to
be represented -- see ``docs/TOOL_GAP_BACKLOG.md`` GAP-022 Phase 3 for the
full byte-level record.

Each vtable binding also carries its own ``evidence_tier``/
``evidence_tier_reasons``, independent of the owning class's hierarchy
``evidence_tier`` above -- a class's inheritance-shape interpretation
(e.g. CHD bit1) says nothing about whether its vtable back-link itself
resolved cleanly, and the two are never conflated.

Hierarchy representation is an explicit adjacency list of
``(derived, base, mdisp, pdisp, vdisp, is_virtual)`` edges, never a single
``parent`` field: multiple and virtual inheritance make the real relationship
a DAG, not Delphi's single-parent VMT chain (``tools_delphi.py``), and a
schema that only had room for one parent would silently drop every base but
the last one found.

Evidence rung: ``observed_fact``. This is a static parse of the target's own
bytes -- nothing is executed, emulated, or inferred from behaviour. A class
promoted here is proof the binary's own RTTI data describes that class and
that inheritance edge; it is not proof any method on it is ever called.

Every class AND every hierarchy edge also carries its own ``evidence_tier``
(``"PROVEN"`` or ``"CANDIDATE"``) plus ``evidence_tier_reasons`` (a list of
``{"code", "detail"}``, empty iff PROVEN) directly in the tool's own output
-- never only in this docstring. ``"PROVEN"`` now covers: single, non-virtual
inheritance (only ``mdisp`` load-bearing, ``pdisp == -1`` on every base, CHD
bit0/bit1 both clear -- hand-verified byte-for-byte against real 32- and
64-bit corpus binaries), genuine multiple inheritance on the 64-bit path
ONLY (CHD bit0 set, real distinct non-virtual bases -- hand-verified
against ``_Locimp``, a 64-bit target, above), and genuine virtual
inheritance recovered purely through the ``pdisp != -1`` rule, again on the
64-bit path ONLY (hand-verified against ``basic_ostream``/``basic_istream``,
also 64-bit, above). ``"CANDIDATE"`` covers what real bytes did NOT settle:
CHD attributes bit1 set on either bitness (``VIRTUAL_INHERITANCE_ATTRIBUTE_SET``
-- real bytes actively contradict a simple reading of this bit, see above),
CHD bit0 set or a ``pdisp != -1`` base on the 32-BIT path specifically
(``MULTIPLE_OR_VIRTUAL_INHERITANCE_UNVERIFIED_ON_32BIT`` -- the same
structural signature the 64-bit path now trusts, but with no real 32-bit
binary in this corpus to verify it against), more than one COL resolving to
the same TypeDescriptor, or two different class names' COLs resolving to
the same CHD (the /OPT:ICF sharing case, still unverified against a real
ICF-folded sample this session). No code path in this module ever upgrades
one of those remaining cases to PROVEN.

== Binary-to-binary class/vtable diff (Phase 4, ``operation="diff"``) ==

A self-sufficient comparison of this module's own recovered output against
two independently parsed binaries (``path`` and ``other_path``) -- never
against ``analysis_ir.py``'s shared schema, which is deliberately not
extended with a Class/Vtable node for this still-evolving capability (lead
decision, standing since Phase 1). Classes are matched between the two
sides by mangled TypeDescriptor name, never by address: an address is only
ever stable within one build, and comparing raw VAs across two independently
compiled binaries is exactly the mistake ``binary_version_diff.py`` already
refuses to make for functions (see its own ``identity_policy``). Two images
of different bitness are refused outright (``BITNESS_MISMATCH``) rather than
compared -- a 32-bit absolute-VA class and a 64-bit RVA-relative class are
not the same kind of fact and a diff between them would not mean anything.

Findings, one per detected change:

- ``ADDED_CLASS`` / ``REMOVED_CLASS`` -- a class name present on only one side.
- ``ADDED_BASE`` / ``REMOVED_BASE`` -- a base name present in a shared
  class's hierarchy edges on only one side.
- ``CHANGED_DISPLACEMENT`` -- the same (derived, base) pair's own
  ``mdisp``/``pdisp``/``vdisp`` differs between sides: an object-layout/ABI
  change on that exact base, the kind of thing that silently breaks a
  hand-written offset patch.
- ``VTABLE_SLOT_COUNT_CHANGED`` -- a shared class's vtable has a different
  number of slots: a virtual method was added or removed.
- ``VTABLE_SLOTS_REORDERED`` -- a shared class's vtable has the exact same
  *set* of slot CONTENT-hash identities on both sides but in a different
  order. Slot identity here is derived from the bytes of the function a
  slot points at (a fixed-length prefix, ``VTABLE_SLOT_CONTENT_HASH_BYTES``
  above, hashed with sha256), never from that function's own address: an
  address is only ever stable within one build, and two independently
  compiled binaries essentially never place the same function at the same
  absolute address (the same reason class matching above uses mangled
  names, never addresses -- see ``binary_version_diff.py``'s own
  ``identity_policy`` for the same discipline applied to functions). An
  earlier version of this finding compared raw slot addresses instead and
  would therefore never fire on two genuinely independent builds, only on
  synthetic fixtures sharing one ``IMAGE_BASE`` -- content identity is what
  makes it fire for the realistic defensive case: an unmodified method
  whose vtable slot moved. It has a real, stated blind spot instead: if a
  method's own code genuinely changed between the two builds, its content
  hash changes too, so a real reorder of a method whose code ALSO changed
  is indistinguishable here from an unrelated rewrite that happens to leave
  a different, unchanged method occupying the reordered method's old slot
  position -- this rule only ever reliably catches an UNCHANGED method that
  moved. This module still never resolves what function a slot points to
  as a name or decompiles it (see ``what_this_does_not_do`` above) -- the
  hash is an opaque content fingerprint, not identification. Both blind
  spots are stated as limitations in the tool's own output, not just here.
- ``VTABLE_COUNT_CHANGED_FOR_CLASS`` -- a shared class has a different
  number of bound vtables between the two sides. No real target anywhere in
  this repo's corpus has ever had more than one vtable for one class (see
  Phase 3 above), so this specific comparison is itself unexercised on real
  bytes and always reported CANDIDATE.

Evidence-tier discipline for a diff finding mirrors the rest of this module,
never loosened: a finding is PROVEN only if every underlying class/edge/
vtable record it was built from is PROVEN on BOTH sides; if either side's
own evidence is CANDIDATE, the finding is CANDIDATE too, carrying forward
the union of both sides' own reasons (never silently upgraded, never a
fresh unexplained CANDIDATE either).
"""
from __future__ import annotations

import hashlib
import json
import re
import struct

from tools_delphi import _Image
from tools_workspace import safe_path, relative

_ALLOWED_OPS = {"classes", "diff"}

IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

# pVFTable + spare dwords/qwords sitting ahead of a TypeDescriptor's mangled
# name string: 4+4 bytes on 32-bit, 8+8 bytes on 64-bit (both fields are
# pointer-sized).
_TD_HEADER_SIZE = {32: 8, 64: 16}

# CompleteObjectLocator size and expected `signature` field value.
# 64-bit adds a sixth field, pSelf (see module docstring), and its
# signature is 1 rather than 0.
_COL_SIZE = {32: 20, 64: 24}
_COL_SIGNATURE = {32: 0, 64: 1}

_CHD_SIZE = 16   # signature, attributes, numBaseClasses, pBaseClassArray -- same both bitnesses
_BCD_SIZE = 24   # pTypeDescriptor, numContainedBases, mdisp, pdisp, vdisp, attributes -- same both bitnesses

CHD_ATTR_MULTIPLE_INHERITANCE = 0x1
CHD_ATTR_VIRTUAL_INHERITANCE = 0x2

MAX_CLASSES = 4096
MAX_BASE_CLASSES = 256
_MAX_NAME_LEN = 2048

# Phase 3 (vtable-to-COL binding). A vtable's function-pointer slots are
# always absolute VAs, on BOTH bitnesses -- unlike the RTTI structures
# themselves (COL/CHD/BaseClassArray/BaseClassDescriptor), which switch to
# RVA-relative fields on 64-bit (see the module docstring), a compiled
# vtable is a plain array of direct code addresses on 32- and 64-bit alike.
# Hand-verified against 7 real vtables across both bitnesses -- see the
# "Vtable-to-COL binding" docstring section below.
_PTR_SIZE = {32: 4, 64: 8}
IMAGE_SCN_MEM_EXECUTE = 0x20000000
MAX_VTABLE_SLOTS = 512

# Termination rule 1 (structural stop -- see _bind_vtables_for_col): a
# vtable's slot run must stop no later than the next OTHER bound vtable's
# own header (its COL back-link slot, or its own slot 0) in this image.
#
# Termination rule 2 (base-relocation validity): every vtable slot in a
# relocatable image is an absolute VA and therefore must itself be listed
# in the image's base relocation directory. IMAGE_DIRECTORY_ENTRY_BASERELOC
# is data-directory index 5; IMAGE_REL_BASED_ABSOLUTE (0) is padding, never
# a real fixup; IMAGE_REL_BASED_HIGHLOW (3) is the 32-bit fixup type,
# IMAGE_REL_BASED_DIR64 (10) the 64-bit one.
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10

# Termination rule 3 (tier decision): only rule 1 -- hitting a neighbouring
# vtable's own header -- is a genuine structural bound on where THIS vtable
# stops. Rule 2 (base-relocation validity) only proves the words at those
# slot addresses are pointers; it says nothing about which table they
# belong to, so a walk that stops on rule 2 (or on the older "first
# non-executable value"/MAX_VTABLE_SLOTS-cap fallback) is treated the same
# way for tier purposes: genuinely unbounded evidence once it runs this
# long, downgraded to CANDIDATE rather than trusted as PROVEN. This was
# corrected mid-session after ``.?AVbad_array_new_length@std@@`` in a real
# WinSxS DLL showed all 318 over-read slot addresses genuinely present in
# the base relocation directory -- relocation-exhaustion is not proof of a
# vtable's true end, only rule 1 is (see _bind_vtables_for_col).
VTABLE_UNBOUNDED_SLOT_THRESHOLD = 32

# Phase 4 (diff) slot identity. A vtable slot's identity for cross-binary
# comparison is derived from the bytes of the function it points at, never
# from that function's own address -- see the module docstring's "slot
# identity" note in the Phase 4 section. This is the fixed number of bytes
# read from a slot's target VA before hashing. Fixed-length, not "walk to
# the next `ret`" or "walk to the next slot's own target": this module
# never disassembles anything anywhere (see `what_this_does_not_do` below),
# so a length rule that would require decoding instructions to find a real
# function boundary is out of scope on the same grounds every other part of
# this module already draws that line on -- and "next slot target" is not
# usable either, since nothing here establishes that slot N's target
# function actually ends before slot N+1's target begins (they need not be
# adjacent, and the compiler owns their real layout, not this tool). A
# fixed-length prefix is simple and deterministic, which is preferred over
# either heuristic per this session's own instruction. 64 bytes is small
# enough that a short, unrelated function following the true one in memory
# rarely dominates the hash, and large enough to separate the genuinely
# distinct short functions this module's own real corpus vtables contain
# (1-15 slots, see the module docstring's Phase 3 section) from one
# another.
VTABLE_SLOT_CONTENT_HASH_BYTES = 64

# The MSVC TypeDescriptor name decoration itself: ".?AV" for a class,
# ".?AU" for a struct, followed by the mangled qualified name and always
# NUL-terminated. This exact 4-byte prefix is what makes a hit MSVC-shaped
# in the first place -- Itanium/GCC's ABI never produces it.
_TD_NAME_RE = re.compile(rb"\.\?A[VU][\x20-\x7e]{0,%d}?\x00" % _MAX_NAME_LEN)

# Positive evidence of a non-MSVC toolchain: Itanium C++ ABI mangled RTTI
# symbol prefixes (_ZTI/_ZTS/_ZTV) and libstdc++/libsupc++'s unwinder entry
# points, as MinGW-GCC or plain (non -fms-extensions) clang emit them into a
# PE. Their presence with zero ".?AV"/".?AU" hits means "not MSVC", not
# "not C++".
_ITANIUM_MARKERS = (b"_ZTI", b"_ZTS", b"_ZTV", b"__cxa_throw", b"__cxa_begin_catch", b"__cxa_end_catch")


def _j(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _render_with_truncation(result, max_chars, collection_keys):
    """Render ``result`` as JSON, halving whichever of ``collection_keys``
    (in priority order) still holds more than one item until the render
    fits ``max_chars`` or nothing is left to cut. This is the single place
    in this module that ever drops list items to satisfy a caller-supplied
    ``max_chars`` budget, and it is built so a caller can NEVER end up with
    a truncated result that looks identical to a complete one:

    - every collection's TRUE full count is captured (``full_counts``)
      before any cutting happens, from the exact same list objects that get
      shrunk in place afterwards -- so a scalar count field set earlier in
      ``result`` from ``len(that_same_list)`` (e.g. ``class_count``,
      ``hierarchy_edge_count``, ``finding_count``) is unaffected by this
      function ever running; it was already the true total.
    - a machine-readable ``result["truncation"]`` list is added, one entry
      per collection actually cut, naming the collection, its true full
      count, and how many items survived rendering -- never just a bare
      boolean side flag a caller has to know to look for.
    - ``result["truncated"]`` is a single top-level bool a caller can check
      without knowing any collection's name.
    - if truncation happened and ``result["status"]`` was ``"OK"``, it is
      changed to ``"OK_TRUNCATED"`` -- a truncated result must not present
      the exact same status a complete one does, per this module's own
      status/tier discipline (see ``evidence_tier`` elsewhere in this
      module: an interpretive gap is always named in a status/reason field,
      never left for the caller to infer from a side effect).

    Priority order (which collection gets cut first) is exactly
    ``collection_keys`` as given by the caller -- e.g. ``classes`` before
    ``type_descriptor_candidates_without_col`` before ``hierarchy_edges``
    for the single-path ``classes`` operation, so the largest and least
    load-bearing collection (a fully recovered class list) is preferred
    over silently thinning the smaller, already-scarce ones.
    """
    full_counts = {key: len(result[key]) for key in collection_keys}
    # These two keys are set here unconditionally, exactly as before -- but
    # setting them BEFORE the first render (instead of only after the loop)
    # means the common case (this result already fits under max_chars, the
    # loop body never runs) renders it only ONCE below instead of twice: the
    # measurement render already contains their final values, since nothing
    # about `result` changes between it and the return. Same dict-insertion
    # position either way (first new keys after every caller-set one), so
    # this changes nothing about the rendered JSON's key order or content --
    # only whether a second, fully redundant full-payload encode happens.
    result.setdefault("truncated", False)
    result.setdefault("truncation", [])
    rendered = _j(result)
    while len(rendered) > max_chars:
        for key in collection_keys:
            if len(result[key]) > 1:
                result[key] = result[key][: len(result[key]) // 2]
                break
        else:
            break  # nothing left with more than one item to cut further
        rendered = _j(result)
    truncation = []
    for key in collection_keys:
        rendered_count = len(result[key])
        if rendered_count < full_counts[key]:
            truncation.append({
                "collection": key,
                "full_count": full_counts[key],
                "rendered_count": rendered_count,
            })
    if not truncation:
        # Nothing was cut: `result["truncated"]`/`["truncation"]` are still
        # exactly the False/[] set above, and no other field changed since
        # `rendered` was last computed -- it IS the final output already.
        return rendered
    result["truncated"] = True
    result["truncation"] = truncation
    if result.get("status") == "OK":
        result["status"] = "OK_TRUNCATED"
    return _j(result)


def _demangled_hint(raw_name):
    """Best-effort, non-authoritative human-readable form of a TypeDescriptor
    name. Handles the common plain-class/namespace shape
    (``.?AVexception@std@@`` -> ``std::exception``) by stripping the
    ``.?A[VU]`` prefix and trailing ``@@``, splitting the remaining
    ``@``-separated segments (innermost name first, namespaces after) and
    reversing them. Templates, operator names and anonymous namespaces are
    not specially handled -- the result still comes out readable-ish and
    never crashes, but ``mangled_name`` is the authoritative field, this is
    only a hint.
    """
    body = raw_name[4:]  # strip ".?AV" / ".?AU"
    if body.endswith("@@"):
        body = body[:-2]
    parts = body.split("@") if body else []
    return "::".join(reversed(parts)) if parts else raw_name


def _kind_of(raw_name):
    if raw_name.startswith(".?AV"):
        return "class"
    if raw_name.startswith(".?AU"):
        return "struct"
    return "unknown"


def _to_va(image, raw_ptr, is64):
    """A COL/CHD/BaseClassArray/BaseClassDescriptor pointer field: an
    absolute VA on 32-bit, an image-base-relative RVA on 64-bit (see module
    docstring). Returns None for a null pointer in either scheme -- 0 is
    never a valid TypeDescriptor/CHD/BaseClassArray location, and on
    64-bit an unguarded RVA of 0 would otherwise resolve into the PE header
    instead of being rejected."""
    if not raw_ptr:
        return None
    return image.base + raw_ptr if is64 else raw_ptr


def _find_td_candidates(image, is64):
    """Every syntactically well-formed TypeDescriptor name string in the
    image, keyed by the TypeDescriptor's own VA (name string VA minus the
    bitness-appropriate pVFTable+spare header size). A name match alone is
    never promoted further here -- see ``_resolve_chain``.
    """
    data = image.data
    hdr_size = _TD_HEADER_SIZE[64 if is64 else 32]
    candidates = {}
    for match in _TD_NAME_RE.finditer(data):
        name_offset = match.start()
        td_offset = name_offset - hdr_size
        if td_offset < 0:
            continue
        raw = match.group(0)[:-1].decode("latin-1")  # drop the NUL
        td_va = image.base + td_offset
        # First (lowest-offset) hit wins if the same TD offset is somehow
        # reached twice; in practice each TD name occurs once.
        candidates.setdefault(td_va, {"td_va": td_va, "name_offset": name_offset, "mangled_name": raw})
        if len(candidates) >= MAX_CLASSES:
            break
    return candidates


def _valid_td_at(image, td_va, is64):
    """Independently re-validate that ``td_va`` is itself a well-formed
    TypeDescriptor (used to verify a BaseClassDescriptor's own
    pTypeDescriptor -- chained verification, not a bare pointer-in-bounds
    check)."""
    if not td_va:
        return None
    hdr_size = _TD_HEADER_SIZE[64 if is64 else 32]
    name = _read_cstring(image, td_va + hdr_size)
    if name and (name.startswith(".?AV") or name.startswith(".?AU")):
        return name
    return None


def _read_cstring(image, va, max_len=_MAX_NAME_LEN):
    data, base = image.data, image.base
    offset = va - base
    if not (0 <= offset < len(data)):
        return None
    end = data.find(b"\x00", offset, offset + max_len)
    if end == -1:
        return None
    raw = data[offset:end]
    if not raw or not all(0x20 <= byte < 0x7F for byte in raw):
        return None
    return raw.decode("latin-1")


def _in_bounds(image, va, size):
    if va is None:
        return False
    offset = va - image.base
    return 0 <= offset <= len(image.data) - size


def _resolve_base_class_descriptor(image, bcd_va, is64):
    """Decode + independently re-validate one BaseClassDescriptor. Returns
    None (never a half-filled record) when any link in it fails."""
    if not _in_bounds(image, bcd_va, _BCD_SIZE):
        return None
    offset = bcd_va - image.base
    raw_ptd = struct.unpack_from("<I", image.data, offset)[0]
    num_contained, mdisp, pdisp, vdisp = struct.unpack_from("<iiii", image.data, offset + 4)
    attrs = struct.unpack_from("<I", image.data, offset + 20)[0]
    ptd = _to_va(image, raw_ptd, is64)
    base_name = _valid_td_at(image, ptd, is64)
    if base_name is None:
        return None
    return {
        "base_class_descriptor_va": hex(bcd_va),
        "type_descriptor_va": hex(ptd),
        "mangled_name": base_name,
        "kind": _kind_of(base_name),
        "num_contained_bases": num_contained,
        "where": {"mdisp": mdisp, "pdisp": pdisp, "vdisp": vdisp},
        "attributes": attrs,
        "is_virtual_base": pdisp != -1,
    }


def _resolve_chain(image, td_va, col_off, is64):
    """Attempt to resolve one candidate COL occurrence into a full,
    independently-verified class record. Returns (record_or_None, reason)."""
    data, base = image.data, image.base
    col_size = _COL_SIZE[64 if is64 else 32]
    expected_sig = _COL_SIGNATURE[64 if is64 else 32]
    if col_off < 0 or col_off + col_size > len(data):
        return None, "COL_OUT_OF_BOUNDS"
    if is64:
        signature, offset_field, cd_offset, raw_ptd, raw_pchd, pself = struct.unpack_from("<IIIIII", data, col_off)
    else:
        signature, offset_field, cd_offset, raw_ptd, raw_pchd = struct.unpack_from("<IIIII", data, col_off)
        pself = None
    if signature != expected_sig:
        return None, f"COL_SIGNATURE_NOT_{expected_sig}({signature})"
    if is64:
        # pSelf is the strongest verification anchor 64-bit RTTI has: the
        # COL's own RVA. Hand-verified against every real COL found in
        # benchmarks/windows_native_ladder/corpus/tier2/crackme_easlog/
        # x64.exe (see module docstring) -- a candidate whose pSelf does not
        # equal its own offset from image base is rejected outright, never
        # merely downgraded to CANDIDATE.
        if pself != col_off:
            return None, f"COL_PSELF_MISMATCH(pself=0x{pself:x},expected=0x{col_off:x})"
    ptd = _to_va(image, raw_ptd, is64)
    if ptd != td_va:
        return None, "COL_TYPE_DESCRIPTOR_MISMATCH"
    pchd = _to_va(image, raw_pchd, is64)
    if not _in_bounds(image, pchd, _CHD_SIZE):
        return None, "CHD_OUT_OF_BOUNDS"
    chd_off = pchd - base
    chd_signature, chd_attrs, num_bases, raw_bca = struct.unpack_from("<IIII", data, chd_off)
    if chd_signature != 0:
        return None, f"CHD_SIGNATURE_NOT_ZERO({chd_signature})"
    if not (1 <= num_bases <= MAX_BASE_CLASSES):
        return None, f"IMPLAUSIBLE_NUM_BASE_CLASSES({num_bases})"
    p_bca = _to_va(image, raw_bca, is64)
    if not _in_bounds(image, p_bca, num_bases * 4):
        return None, "BASE_CLASS_ARRAY_OUT_OF_BOUNDS"
    bca_off = p_bca - base
    entries = []
    for i in range(num_bases):
        raw_bcd = struct.unpack_from("<I", data, bca_off + i * 4)[0]
        bcd_va = _to_va(image, raw_bcd, is64)
        resolved = _resolve_base_class_descriptor(image, bcd_va, is64)
        if resolved is None:
            return None, f"BASE_CLASS_DESCRIPTOR[{i}]_DID_NOT_RESOLVE"
        entries.append(resolved)
    record = {
        "col_va": hex(base + col_off),
        "col_offset_field": offset_field,
        "col_cd_offset_field": cd_offset,
        "chd_va": hex(pchd),
        "chd_attributes_raw": chd_attrs,
        "chd_multiple_inheritance": bool(chd_attrs & CHD_ATTR_MULTIPLE_INHERITANCE),
        "chd_virtual_inheritance": bool(chd_attrs & CHD_ATTR_VIRTUAL_INHERITANCE),
        "num_base_classes": num_bases,
        "base_class_array_va": hex(p_bca),
        "base_class_entries": entries,
    }
    if is64:
        record["col_pself_va"] = hex(base + pself)
    return record, None


def _build_reference_index(image, is64):
    """Build, once per image, a map from every pointer-sized VALUE that
    could possibly be a genuine RTTI/vtable back-reference to the list of
    (4-byte-aligned) offsets in ``image.data`` where that exact value
    occurs -- turning the O(candidates) repeated whole-image
    ``bytes.find()`` scans in ``_scan`` and ``_vtable_header_vas_for_col``
    (previously ~74% of this tool's wall-clock on a large real DLL, see
    ``docs/PROJECT_STATE.md``) into a single O(image_size) pass followed by
    O(1) dict lookups.

    Two independent indices, because the two callers search for
    differently-sized/aligned values:

    - ``dword_index``: 4-byte-aligned dwords. On 64-bit this is what
      ``_scan`` needs (a genuine COL's ``pTypeDescriptor`` stores the
      TypeDescriptor's 32-bit RVA there), so entries are pruned to values
      that fall inside ``[0, len(data))`` -- no genuine RVA can be anything
      else. On 32-bit this ALSO doubles as what
      ``_vtable_header_vas_for_col`` needs (``ptr_size == 4`` there too, and
      every pointer field on 32-bit is an absolute VA), so entries are
      pruned to ``[image.base, image.base + len(data))`` instead.
    - ``qword_index``: 8-byte-aligned qwords, only built on 64-bit (where
      ``_vtable_header_vas_for_col``'s ``ptr_size`` is 8 and a vtable
      back-link slot holds a genuine absolute VA). Pruned to
      ``[image.base, image.base + len(data))``. ``None`` on 32-bit.

    This was first built scanning only this image's non-executable
    sections (skipping ``.text``), on the theory that MSVC never places a
    COL/vtable back-link pointer inside code. That theory does NOT hold for
    this repo's own synthetic test fixtures (``tests/fixtures_pe_builder``
    packs its scratch RTTI blob into the same single section as the
    probe's ``code``, which is flagged executable) -- confirmed by an
    actual test regression (11 failures, all synthetic-fixture tests
    dropping to zero classes found), not by reasoning about it. Per this
    module's own correctness discipline, that regression means the
    section-exclusion assumption is not safe for every binary this tool
    must handle, so it was DROPPED rather than special-cased around: this
    scans the WHOLE image, every section, exactly like the ``bytes.find()``
    calls it replaces did. Memory is still bounded the way this module's
    caller asked -- not by skipping ``.text``, but by the VA-range prune
    below, which drops the overwhelming majority of raw 4/8-byte values in
    a real DLL (most bytes are code/instructions or string data, not
    pointers that happen to land inside this specific image's own mapped
    VA span).
    """
    data, base = image.data, image.base
    size = len(data)

    def build(item_size, fmt, in_range):
        index = {}
        aligned_end = (size // item_size) * item_size
        if aligned_end <= 0:
            return index
        for i, (val,) in enumerate(struct.iter_unpack(fmt, data[0:aligned_end])):
            if in_range(val):
                index.setdefault(val, []).append(i * item_size)
        return index

    if is64:
        dword_index = build(4, "<I", lambda v: 0 <= v < size)
        qword_index = build(8, "<Q", lambda v: base <= v < base + size)
    else:
        dword_index = build(4, "<I", lambda v: base <= v < base + size)
        qword_index = None
    return dword_index, qword_index


def _scan(image, is64, index=None):
    """Structural extraction: TypeDescriptor name candidates, each promoted
    to a PROVEN class only via a verified COL->CHD->BaseClassArray chain
    (chained verification, per this module's docstring). Returns
    (proven_classes, unresolved_candidates)."""
    base = image.base
    if index is None:
        index, _qword_index = _build_reference_index(image, is64)
    td_candidates = _find_td_candidates(image, is64)
    proven = {}
    unresolved = []
    for td_va, cand in td_candidates.items():
        # The value looked up is what a genuine COL's pTypeDescriptor field
        # actually stores: the TypeDescriptor's absolute VA on 32-bit, its
        # RVA (VA - image base) on 64-bit -- see _build_reference_index.
        needle_value = (td_va - base) if is64 else td_va
        col_records = []
        rejection_reasons = []
        for hit_offset in index.get(needle_value, ()):
            # pTypeDescriptor sits at COL+12 in both the 20-byte (32-bit)
            # and 24-byte (64-bit) COL layouts, naturally dword-aligned --
            # already guaranteed by the index's own 4-byte alignment.
            col_off = hit_offset - 12
            record, reason = _resolve_chain(image, td_va, col_off, is64)
            if record is not None:
                col_records.append(record)
            elif reason:
                rejection_reasons.append(reason)
        if col_records:
            proven[td_va] = {
                "td_va": hex(td_va),
                "mangled_name": cand["mangled_name"],
                "kind": _kind_of(cand["mangled_name"]),
                "demangled_hint": _demangled_hint(cand["mangled_name"]),
                # /OPT:ICF (or an otherwise-shared RTTI complex) can make more
                # than one COL resolve to the exact same TypeDescriptor+CHD;
                # every COL address found is kept rather than collapsed to
                # one, and every CHD seen is kept too so a genuine mismatch
                # (never observed in this session, but not ruled out) is
                # visible instead of silently dropped.
                "col_records": col_records,
            }
        else:
            unresolved.append({
                "td_va": hex(td_va),
                "mangled_name": cand["mangled_name"],
                "kind": _kind_of(cand["mangled_name"]),
                "status": "CANDIDATE",
                "reason": (
                    "no COL in this image points at this TypeDescriptor with a "
                    "structurally valid CHD/BaseClassArray chain"
                    + (f"; rejected attempts: {sorted(set(rejection_reasons))}" if rejection_reasons else "")
                ),
            })
    return proven, unresolved


def _reason(code, detail):
    return {"code": code, "detail": detail}


def _class_candidate_reasons(entry, primary, is64):
    """Every machine-readable reason this class's result is CANDIDATE, not
    PROVEN -- never a bare boolean, so a caller (or a test) can see exactly
    which interpretive call was made, not just that one was. Empty list
    means PROVEN.

    PROVEN means hand-verified against real bytes on THAT SPECIFIC code
    path, not "matches a published convention". As of Phase 2, CHD bit0
    (multiple inheritance) and the ``pdisp != -1`` virtual-base rule are
    hand-verified against real MSVC-compiled bytes -- but only on the
    64-bit path (``std::locale::_Locimp``, ``std::basic_ostream``/
    ``std::basic_istream``, both in this repo's own 64-bit corpus; see
    module docstring). No real 32-bit MSVC-compiled binary exhibiting
    multiple or virtual inheritance exists in this repo's corpus, so on
    32-bit those same two features stay CANDIDATE
    (``MULTIPLE_OR_VIRTUAL_INHERITANCE_UNVERIFIED_ON_32BIT``) even though
    they no longer downgrade a 64-bit class. CHD bit1 ("virtual
    inheritance") stays CANDIDATE on BOTH bitnesses regardless: real bytes
    from the 64-bit corpus directly contradict a simple reading of it
    (``basic_ostream``'s own CHD has bit1 clear despite a real, direct
    virtual base) -- see the code below for the specific real-bytes
    contradiction.
    """
    reasons = []
    if not is64:
        has_multiple_inheritance = primary["chd_multiple_inheritance"]
        has_virtual_base = any(
            base["is_virtual_base"] for base in primary["base_class_entries"][1:]
        )
        if has_multiple_inheritance or has_virtual_base:
            reasons.append(_reason(
                "MULTIPLE_OR_VIRTUAL_INHERITANCE_UNVERIFIED_ON_32BIT",
                "This 32-bit class has CHD.attributes bit0 (multiple inheritance) set and/or a "
                "BaseClassArray entry with pdisp != -1 (a virtual base). Both interpretations "
                "are hand-verified against real MSVC-compiled bytes -- but only on the 64-bit "
                "code path (std::locale::_Locimp and std::basic_ostream/basic_istream in "
                "benchmarks/windows_native_ladder/corpus/tier2/crackme_easlog/x64.exe and "
                "hackers_edge_crackme_v2.exe, see module docstring). This repo's corpus has no "
                "real 32-bit MSVC-compiled binary exhibiting multiple or virtual inheritance to "
                "verify the same rule against real 32-bit bytes specifically, so on the 32-bit "
                "path alone this stays an interpretation resting on the published MSVC ABI "
                "convention, not a proven fact.",
            ))
    if primary["chd_virtual_inheritance"]:
        reasons.append(_reason(
            "VIRTUAL_INHERITANCE_ATTRIBUTE_SET",
            "CHD.attributes bit1 is set. Unlike bit0 (multiple inheritance) and the "
            "'pdisp != -1' virtual-base rule -- both hand-verified against this repo's own "
            "real MSVC-compiled corpus targets, see module docstring -- bit1's meaning could "
            "NOT be corroborated: a real target "
            "(benchmarks/windows_native_ladder/corpus/tier2/crackme_easlog/x64.exe, "
            "std::basic_ostream) has a genuine pdisp!=-1 virtual base (std::basic_ios) yet its "
            "own CHD.attributes is 0, while a different real target "
            "(benchmarks/windows_native_ladder/corpus/tier2/hackers_edge_v2/"
            "hackers_edge_crackme_v2.exe, std::basic_stringstream) has bit1 set alongside bit0 "
            "on a class with a real diamond-shared virtual base. Real bytes show bit1 set in "
            "some genuine virtual-inheritance cases and not others, so this bit alone is not a "
            "reliable signal and stays interpretive.",
        ))
    if len(entry["col_records"]) > 1:
        reasons.append(_reason(
            "MULTIPLE_COL_RECORDS_FOR_ONE_TYPE_DESCRIPTOR",
            "More than one CompleteObjectLocator in this image points at this class's own "
            "TypeDescriptor. This is expected for genuine multiple inheritance (one COL per "
            "vtable), but could also be /OPT:ICF (or similar) folding distinct RTTI complexes "
            "together; no independently ICF-folded real sample was available to distinguish "
            "these two cases against real bytes, so this is reported as an interpretation, "
            "not a proven fact.",
        ))
    return reasons


def _executable_ranges(image):
    """Every ``(start_va, end_va)`` range this image's own PE section table
    actually flags executable (``IMAGE_SCN_MEM_EXECUTE``) -- not a hardcoded
    ``.text`` name lookup, so a differently-named executable section (or a
    binary with more than one) is still honoured. This is the exact
    ground-truth boundary a real vtable's slot run was hand-verified to
    respect on 7 real vtables across both bitnesses (see the module
    docstring's Phase 3 section): a slot value that does not fall in any of
    these ranges is not a virtual-method pointer, it is the end of the
    table."""
    ranges = []
    try:
        sections = image.pe.sections
    except Exception:  # noqa: BLE001
        return ranges
    for section in sections:
        if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
            start = image.base + section.VirtualAddress
            end = start + section.Misc_VirtualSize
            ranges.append((start, end))
    return ranges


def _in_executable_range(va, exec_ranges):
    return any(start <= va < end for start, end in exec_ranges)


def _relocated_addresses(image):
    """The exact set of VAs this image's own base relocation directory
    corrects at load time (termination rule 2), or ``None`` if the
    directory itself is empty/absent -- a binary stripped of relocations
    has nothing here to check a vtable slot's address against, so the
    caller must skip rule 2 entirely rather than treat an empty result as
    'nothing is relocated'. Parsed directly from this image's own flat,
    RVA-indexed ``data`` buffer (the same one every other read in this
    module uses), never via ``pefile``'s own directory parser -- ``_Image``
    is opened ``fast_load=True`` and this module never re-parses directories
    through ``pefile`` itself, see ``tools_delphi._Image``."""
    try:
        directory = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_BASERELOC]
        reloc_rva, reloc_size = directory.VirtualAddress, directory.Size
    except Exception:  # noqa: BLE001
        return None
    if not reloc_rva or not reloc_size:
        return None
    data = image.data
    end = min(reloc_rva + reloc_size, len(data))
    addresses = set()
    pos = reloc_rva
    while pos + 8 <= end:
        page_rva, block_size = struct.unpack_from("<II", data, pos)
        if block_size < 8:
            break
        entry_pos = pos + 8
        block_end = min(pos + block_size, end)
        while entry_pos + 2 <= block_end:
            word = struct.unpack_from("<H", data, entry_pos)[0]
            entry_pos += 2
            reloc_type = word >> 12
            if reloc_type in (IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_DIR64):
                addresses.add(image.base + page_rva + (word & 0x0FFF))
        pos += block_size
    return addresses


def _read_ptr(image, va, ptr_size):
    """Read one raw, bitness-width pointer-sized VALUE (not VA-adjusted --
    vtable slots are always absolute VAs, see ``_PTR_SIZE``'s comment) at
    ``va``. None if any part of it falls outside the image."""
    offset = va - image.base
    if not (0 <= offset <= len(image.data) - ptr_size):
        return None
    fmt = "<Q" if ptr_size == 8 else "<I"
    return struct.unpack_from(fmt, image.data, offset)[0]


def _slot_content_hash(image, va):
    """A vtable slot's identity for cross-binary diffing, derived from the
    TARGET FUNCTION'S OWN BYTES, never its address -- see
    ``VTABLE_SLOT_CONTENT_HASH_BYTES`` above for why a fixed-length prefix
    was chosen over a disassembled function boundary. Reads up to
    ``VTABLE_SLOT_CONTENT_HASH_BYTES`` bytes starting at ``va`` and returns
    their sha256 hex digest; a shorter run is hashed if the image itself
    ends first (never padded with anything this image does not actually
    contain). Returns None only if ``va`` is not readable at all (fully out
    of the image's own bounds) -- an unreadable slot target can never
    contribute a content identity, in either evidence tier."""
    offset = va - image.base
    if not (0 <= offset < len(image.data)):
        return None
    chunk = image.data[offset:offset + VTABLE_SLOT_CONTENT_HASH_BYTES]
    return hashlib.sha256(chunk).hexdigest()


def _vtable_header_vas_for_col(image, col_va, ptr_size, relocated_addresses=None, index=None):
    """Every VA where this specific COL's own address is found, pointer-size
    aligned -- i.e. every bound vtable's slot-0 address for this COL
    (``vtable[-1] == &COL``, the MSVC ABI's own self-identifying back link,
    see the module docstring's Phase 3 section). Usually 0 or 1 hits per
    COL. Used both to walk each such vtable's own slots
    (``_bind_vtables_for_col``) and, first, to build the whole image's set
    of every known vtable header address so one vtable's slot walk can be
    stopped by a NEIGHBOURING vtable's header (termination rule 1).

    A raw pointer-aligned byte match of ``col_va`` is not, by itself, proof
    of a genuine ``vtable[-1] -> &COL`` back-link: it is only 4 bytes wide
    on a 32-bit image, and this repo's own WinSxS corpus has produced
    coincidental matches of unrelated .rdata against a real COL's own VA --
    every one of them landing on a value that is not itself covered by the
    image's base relocation directory, because a genuine back-link slot
    holds an absolute VA and a relocatable image must always list a fixup
    for it (the same load-time-relocation fact termination rule 2 already
    relies on for slot VALUES, applied here to the back-link SLOT ITSELF).
    When ``relocated_addresses`` is given (non-``None`` -- the image's own
    base relocation directory is present and non-empty), a hit whose own
    address is not listed there is dropped as a coincidental byte match,
    never treated as a vtable header. When it is ``None`` (directory
    absent/empty, nothing here to check a hit's address against) every
    pointer-aligned hit is kept, exactly as before this filter existed.

    ``index`` is the pre-built ``dword_index``/``qword_index`` (matching
    ``ptr_size``) from ``_build_reference_index``, when the caller has one
    -- an O(1) dict lookup replacing this function's own former whole-image
    ``bytes.find()`` scan. When ``None`` (e.g. a caller with no image-wide
    index), the equivalent scan is done here, byte-for-byte identical to
    before this index existed -- alignment is checked the same way, so a
    one-off caller sees the exact same hits either way."""
    if index is not None:
        candidate_offsets = index.get(col_va, ())
    else:
        fmt = "<Q" if ptr_size == 8 else "<I"
        needle = struct.pack(fmt, col_va)
        offsets = []
        idx = 0
        while True:
            idx = image.data.find(needle, idx)
            if idx == -1:
                break
            offsets.append(idx)
            idx += 1
        candidate_offsets = offsets
    hits = []
    for hit_offset in candidate_offsets:
        if hit_offset % ptr_size:
            continue  # a real pointer field is always pointer-size aligned
        if relocated_addresses is not None and (image.base + hit_offset) not in relocated_addresses:
            continue  # not itself a relocated pointer field -- coincidental byte match
        hits.append(hit_offset)
    return hits


def _bind_vtables_for_col(image, col_va, is64, exec_ranges, all_vtable_vas, relocated_addresses, index=None):
    """Every vtable this specific COL's own address is immediately preceded
    by (``vtable[-1] == &COL``, the MSVC ABI's own self-identifying back
    link -- see the module docstring's Phase 3 section). Usually 0 or 1
    entries; kept as a list (never collapsed to "the" vtable) because
    nothing in the ABI itself rules out more than one raw occurrence, even
    though this repo's entire corpus has never produced one (see
    ``docs/TOOL_GAP_BACKLOG.md`` GAP-022 Phase 3).

    A vtable's slot run is walked immediately after that pointer, one
    pointer-width value at a time, and stops at the first of:

    1. (structural) the next slot address reaching any OTHER known bound
       vtable's own header in this image -- that vtable's COL back-link
       slot, or its own slot 0 (``all_vtable_vas``, built once across the
       whole image before any class's vtables are walked). Bounds every
       vtable except the last one in the image.
    2. (base-relocation validity) the next slot address not being listed in
       this image's own base relocation directory, when that directory is
       non-empty (``relocated_addresses``) -- a vtable slot holds an
       absolute VA, which a relocatable image must always list a fixup for.
       Bounds the last vtable in the image, where rule 1 has no next
       header to stop at.
    3. (fallback, pre-existing) the first value that does not fall inside
       any of this image's own executable sections (``exec_ranges``) --
       hand-verified against 7 real vtables across both bitnesses, see
       module docstring.

    Reaching ``MAX_VTABLE_SLOTS``, or running off the end of the image
    entirely before any stop condition is seen, both leave the true slot
    count genuinely undetermined -- CANDIDATE with a specific reason, never
    a guessed PROVEN count.

    Tier decision (rule 3): only rule 1 (a neighbouring vtable's own
    header) is a genuine structural bound on where THIS vtable stops.
    Being listed in the base relocation directory (rule 2) only proves a
    slot's word is a pointer, never which table it belongs to -- a real
    WinSxS DLL's ``.?AVbad_array_new_length@std@@`` vtable (true size 2
    slots) walked 318 slots this way, every one of them genuinely
    relocated, because they belonged to unrelated data past the vtable's
    real end. So a walk that stops on rule 2, on rule 3's own "first
    non-executable value" fallback, or on the ``MAX_VTABLE_SLOTS`` cap is
    all treated alike for tier purposes: once it exceeds
    ``VTABLE_UNBOUNDED_SLOT_THRESHOLD`` slots without ever having hit rule
    1, the count is CANDIDATE (``VTABLE_SLOT_COUNT_UNBOUNDED``), never
    PROVEN. Only a rule-1-terminated walk, or a walk of
    ``VTABLE_UNBOUNDED_SLOT_THRESHOLD`` slots or fewer regardless of which
    rule stopped it, stays PROVEN. ``stop_reason`` is recorded on the
    vtable record itself (``termination_rule``) so which terminator fired
    is auditable, not a magic boolean.
    """
    ptr_size = _PTR_SIZE[64 if is64 else 32]
    vtables = []
    for hit_offset in _vtable_header_vas_for_col(image, col_va, ptr_size, relocated_addresses, index):
        vtable_off = hit_offset + ptr_size
        vtable_va = image.base + vtable_off
        structural_stops = set()
        for other_va in all_vtable_vas:
            if other_va != vtable_va:
                structural_stops.add(other_va)
                structural_stops.add(other_va - ptr_size)
        slots = []
        content_hashes = []
        reasons = []
        slot_off = vtable_off
        stop_reason = None
        while len(slots) < MAX_VTABLE_SLOTS:
            slot_va = image.base + slot_off
            if slot_va in structural_stops:
                stop_reason = "structural"
                break
            if relocated_addresses is not None and slot_va not in relocated_addresses:
                stop_reason = "reloc"
                break
            val = _read_ptr(image, slot_va, ptr_size)
            if val is None:
                stop_reason = "eof"
                reasons.append(_reason(
                    "VTABLE_SLOT_RAN_OFF_END_OF_IMAGE",
                    "The vtable's slot run reached the end of this image's own data before any "
                    "slot value was found that falls outside an executable section -- the true "
                    "slot count is genuinely undetermined, not merely unobserved.",
                ))
                break
            if not _in_executable_range(val, exec_ranges):
                stop_reason = "exec_range"
                break
            slots.append(hex(val))
            content_hashes.append(_slot_content_hash(image, val))
            slot_off += ptr_size
        else:
            stop_reason = "cap"
            reasons.append(_reason(
                "VTABLE_SLOT_SCAN_LIMIT_REACHED",
                f"The vtable's slot run reached this tool's own {MAX_VTABLE_SLOTS}-slot scan "
                "limit without any slot value ever falling outside an executable section -- the "
                "true slot count may be larger than reported.",
            ))
        if not slots:
            reasons.append(_reason(
                "VTABLE_HAS_NO_EXECUTABLE_SLOTS",
                "The pointer-sized value immediately after this vtable[-1] -> COL back-link does "
                "not itself point into any of this image's own executable sections. No real "
                "vtable in this repo's corpus has ever produced this -- kept as a defensive "
                "CANDIDATE rather than silently reporting a zero-slot vtable as fact.",
            ))
        if stop_reason != "structural" and len(slots) > VTABLE_UNBOUNDED_SLOT_THRESHOLD:
            reasons.append(_reason(
                "VTABLE_SLOT_COUNT_UNBOUNDED",
                "This vtable's slot walk ended without rule 1's structural terminator firing "
                "(it never reached a neighbouring vtable's own header in this image) and "
                f"exceeded {VTABLE_UNBOUNDED_SLOT_THRESHOLD} slots. Being listed in the base "
                "relocation directory (rule 2, stop_reason='reloc') only proves a slot's word is "
                "a pointer, never which vtable it belongs to -- a real WinSxS DLL's "
                "std::bad_array_new_length vtable (true size 2 slots) walked 318 genuinely "
                "relocated slots belonging to unrelated data past its real end (see GAP-022's "
                "false VTABLE_SLOT_COUNT_CHANGED finding). The old 'first non-executable value' "
                "fallback (stop_reason='exec_range') and the MAX_VTABLE_SLOTS cap "
                "(stop_reason='cap') are no more conclusive. A walk this long that never hit "
                f"rule 1 (this walk's actual terminator: {stop_reason!r}) is unproven, not "
                "merely unobserved.",
            ))
        vtables.append({
            "vtable_self_ptr_va": hex(image.base + hit_offset),
            "vtable_va": hex(vtable_va),
            "slot_count": len(slots),
            "slot_vas": slots,
            "slot_content_hashes": content_hashes,
            "termination_rule": stop_reason,
            "evidence_tier": "CANDIDATE" if reasons else "PROVEN",
            "evidence_tier_reasons": reasons,
        })
    return vtables


def _build_classes_and_edges(image, proven, is64, index=None):
    classes = []
    edges = []
    prelim = []
    exec_ranges = _executable_ranges(image)
    ptr_size = _PTR_SIZE[64 if is64 else 32]
    relocated_addresses = _relocated_addresses(image)
    if index is None:
        dword_index, qword_index = _build_reference_index(image, is64)
    else:
        dword_index, qword_index = index
    # A vtable back-link slot holds an absolute VA, ptr_size wide: 8 bytes
    # on 64-bit (the qword index), 4 bytes on 32-bit (the same dword index
    # _scan already uses there, since ptr_size == 4 on 32-bit too).
    vtable_index = qword_index if is64 else dword_index
    # Termination rule 1 needs every OTHER bound vtable's own header
    # address before any one vtable's slots are walked -- so every class's
    # COLs are scanned for their vtable back-link hits first, across the
    # whole image, and only then is any slot actually read (see
    # _bind_vtables_for_col).
    all_vtable_vas = set()
    for entry in proven.values():
        for record in entry["col_records"]:
            col_va_int = int(record["col_va"], 16)
            for hit_offset in _vtable_header_vas_for_col(image, col_va_int, ptr_size, relocated_addresses, vtable_index):
                all_vtable_vas.add(image.base + hit_offset + ptr_size)
    for entry in proven.values():
        # A class's identity/attributes come from its first resolved COL
        # record; every distinct CHD actually observed across its COL
        # records is reported (see _scan's docstring note above), not just
        # the first.
        chds_seen = {record["chd_va"] for record in entry["col_records"]}
        primary = entry["col_records"][0]
        reasons = _class_candidate_reasons(entry, primary, is64)
        prelim.append((entry, primary, chds_seen, reasons))

    # /OPT:ICF (or an otherwise-shared RTTI complex) can also make two
    # DIFFERENT classes' CompleteObjectLocators resolve to the exact same
    # ClassHierarchyDescriptor VA. That cross-class sharing can only be seen
    # once every class in this image has been resolved, so it is checked
    # here as a second pass, after the per-class checks above -- never
    # silently folded into one class or dropped.
    chd_owner_names = {}
    for entry, _primary, chds_seen, _reasons in prelim:
        for chd_va in chds_seen:
            chd_owner_names.setdefault(chd_va, set()).add(entry["mangled_name"])

    for entry, primary, chds_seen, reasons in prelim:
        shared_with = set()
        for chd_va in chds_seen:
            shared_with |= chd_owner_names[chd_va]
        shared_with.discard(entry["mangled_name"])
        if shared_with:
            reasons = reasons + [_reason(
                "CLASS_HIERARCHY_DESCRIPTOR_SHARED_ACROSS_NAMES",
                "This class's ClassHierarchyDescriptor VA is also reached from a different "
                "TypeDescriptor name in this same image (" + ", ".join(sorted(shared_with)) +
                "). Most likely /OPT:ICF folding two structurally-identical RTTI complexes "
                "together; no independently confirmed ICF-folded real sample was available "
                "this session to verify that interpretation against real bytes, so this is a "
                "defensive interpretation, not a proven fact.",
            )]
        evidence_tier = "CANDIDATE" if reasons else "PROVEN"
        # Phase 3: bind this class's vtable(s) via the vtable[-1] == &COL
        # back-link, independently per COL record (a class with more than
        # one COL -- none observed in this repo's corpus, see
        # docs/TOOL_GAP_BACKLOG.md GAP-022 Phase 3 -- would surface more
        # than one entry here, never silently collapsed to one). This is
        # deliberately independent of this class's own hierarchy
        # evidence_tier above: a CANDIDATE hierarchy interpretation (e.g.
        # CHD bit1) says nothing about whether the vtable back-link itself
        # resolved cleanly.
        vtables = []
        for record in entry["col_records"]:
            col_va_int = int(record["col_va"], 16)
            for vt in _bind_vtables_for_col(image, col_va_int, is64, exec_ranges, all_vtable_vas, relocated_addresses, vtable_index):
                vtables.append({
                    "col_va": record["col_va"],
                    "col_offset_field": record["col_offset_field"],
                    "vtable_self_ptr_va": vt["vtable_self_ptr_va"],
                    "vtable_va": vt["vtable_va"],
                    "slot_count": vt["slot_count"],
                    "slot_vas": vt["slot_vas"],
                    "slot_content_hashes": vt["slot_content_hashes"],
                    "termination_rule": vt["termination_rule"],
                    "evidence_tier": vt["evidence_tier"],
                    "evidence_tier_reasons": vt["evidence_tier_reasons"],
                })
        classes.append({
            "name": entry["mangled_name"],
            "demangled_hint": entry["demangled_hint"],
            "kind": entry["kind"],
            "type_descriptor_va": entry["td_va"],
            "col_vas": [record["col_va"] for record in entry["col_records"]],
            "chd_vas": sorted(chds_seen),
            "chd_attributes_raw": primary["chd_attributes_raw"],
            "multiple_inheritance": primary["chd_multiple_inheritance"],
            "virtual_inheritance": primary["chd_virtual_inheritance"],
            "num_base_classes_incl_self": primary["num_base_classes"],
            "evidence_tier": evidence_tier,
            "evidence_tier_reasons": reasons,
            "vtables": vtables,
        })
        # BaseClassArray entry 0 is always the class's own self-identifying
        # entry (its own TypeDescriptor, mdisp=0/pdisp=-1/vdisp=0) -- not a
        # real base-class edge. Confirmed by hand against
        # simple_crackme/crackme.exe: std::exception (root, no real base)
        # still reports numBaseClasses=1 with base[0] pointing at itself.
        for base_entry in primary["base_class_entries"][1:]:
            edges.append({
                "derived": entry["mangled_name"],
                "base": base_entry["mangled_name"],
                "mdisp": base_entry["where"]["mdisp"],
                "pdisp": base_entry["where"]["pdisp"],
                "vdisp": base_entry["where"]["vdisp"],
                "is_virtual": base_entry["is_virtual_base"],
                # An edge inherits its own derived class's evidence tier
                # wholesale (never re-derives a looser one): the edge came
                # from the same CHD/BaseClassArray chain that tier was
                # computed from, so a CANDIDATE class can never contribute a
                # PROVEN edge.
                "evidence_tier": evidence_tier,
                "evidence_tier_reasons": reasons,
            })
    classes.sort(key=lambda c: c["name"])
    edges.sort(key=lambda e: (e["derived"], e["base"]))
    return classes, edges, relocated_addresses is not None


def _machine_of(image):
    try:
        return image.pe.FILE_HEADER.Machine
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------
# Phase 4: binary-to-binary class/vtable diff (operation="diff").
# --------------------------------------------------------------------------

def _analyze_path_for_diff(path):
    """Parse one binary's own MSVC RTTI classes/edges for the diff path.
    Never leaks a live ``_Image`` handle out of this function -- everything
    needed downstream is plain dicts/lists, so the image is always closed
    before this returns. Returns a dict; ``ok``/``status`` mirror the
    single-path ``classes`` flow's own vocabulary (``NOT_A_PE``,
    ``UNSUPPORTED_MACHINE``) so a caller already familiar with that flow
    recognises the same statuses here."""
    target = safe_path(path)
    try:
        image = _Image(target)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "status": "NOT_A_PE", "path": relative(target),
                "error": f"{type(exc).__name__}: {exc}"}
    try:
        machine = _machine_of(image)
        if machine == IMAGE_FILE_MACHINE_I386:
            is64, architecture = False, "x86"
        elif machine == IMAGE_FILE_MACHINE_AMD64:
            is64, architecture = True, "x64"
        else:
            return {"ok": True, "status": "UNSUPPORTED_MACHINE", "path": relative(target),
                    "machine": hex(machine) if machine is not None else None}
        dword_index, qword_index = _build_reference_index(image, is64)
        proven, _unresolved = _scan(image, is64, dword_index)
        classes, edges, relocation_directory_present = _build_classes_and_edges(
            image, proven, is64, (dword_index, qword_index))
        return {"ok": True, "status": "OK", "path": relative(target), "architecture": architecture,
                "classes": classes, "edges": edges,
                "relocation_directory_present": relocation_directory_present}
    finally:
        image.close()


def _classes_by_name(classes):
    # Last-write-wins on a duplicate mangled name (never observed in this
    # repo's corpus; a genuine /OPT:ICF-style name collision would already
    # be flagged CANDIDATE by _class_candidate_reasons on each side).
    return {entry["name"]: entry for entry in classes}


def _edges_by_derived(edges):
    out = {}
    for edge in edges:
        out.setdefault(edge["derived"], {})[edge["base"]] = edge
    return out


def _diff_tier(*records):
    """PROVEN only if every one of ``records`` is itself PROVEN; otherwise
    CANDIDATE, carrying the de-duplicated union of every record's own
    ``evidence_tier_reasons`` forward -- never a fresh, unexplained
    CANDIDATE and never silently upgraded past the weaker side."""
    tier = "PROVEN"
    reasons = []
    seen = set()
    for record in records:
        if record.get("evidence_tier") != "PROVEN":
            tier = "CANDIDATE"
        for reason in record.get("evidence_tier_reasons", []):
            key = (reason.get("code"), reason.get("detail"))
            if key not in seen:
                seen.add(key)
                reasons.append(reason)
    return tier, reasons


def _diff_findings(old, new):
    old_classes = _classes_by_name(old["classes"])
    new_classes = _classes_by_name(new["classes"])
    old_edges = _edges_by_derived(old["edges"])
    new_edges = _edges_by_derived(new["edges"])

    findings = []

    for name in sorted(set(new_classes) - set(old_classes)):
        entry = new_classes[name]
        findings.append({
            "kind": "ADDED_CLASS", "class": name,
            "evidence_tier": entry["evidence_tier"], "evidence_tier_reasons": entry["evidence_tier_reasons"],
            "detail": {"demangled_hint": entry["demangled_hint"], "kind": entry["kind"]},
        })
    for name in sorted(set(old_classes) - set(new_classes)):
        entry = old_classes[name]
        findings.append({
            "kind": "REMOVED_CLASS", "class": name,
            "evidence_tier": entry["evidence_tier"], "evidence_tier_reasons": entry["evidence_tier_reasons"],
            "detail": {"demangled_hint": entry["demangled_hint"], "kind": entry["kind"]},
        })

    for name in sorted(set(old_classes) & set(new_classes)):
        old_bases = old_edges.get(name, {})
        new_bases = new_edges.get(name, {})
        for base in sorted(set(new_bases) - set(old_bases)):
            edge = new_bases[base]
            findings.append({
                "kind": "ADDED_BASE", "class": name, "base": base,
                "evidence_tier": edge["evidence_tier"], "evidence_tier_reasons": edge["evidence_tier_reasons"],
                "detail": {"where": dict(mdisp=edge["mdisp"], pdisp=edge["pdisp"], vdisp=edge["vdisp"]),
                           "is_virtual": edge["is_virtual"]},
            })
        for base in sorted(set(old_bases) - set(new_bases)):
            edge = old_bases[base]
            findings.append({
                "kind": "REMOVED_BASE", "class": name, "base": base,
                "evidence_tier": edge["evidence_tier"], "evidence_tier_reasons": edge["evidence_tier_reasons"],
                "detail": {"where": dict(mdisp=edge["mdisp"], pdisp=edge["pdisp"], vdisp=edge["vdisp"]),
                           "is_virtual": edge["is_virtual"]},
            })
        for base in sorted(set(old_bases) & set(new_bases)):
            old_edge, new_edge = old_bases[base], new_bases[base]
            old_where = (old_edge["mdisp"], old_edge["pdisp"], old_edge["vdisp"])
            new_where = (new_edge["mdisp"], new_edge["pdisp"], new_edge["vdisp"])
            if old_where != new_where:
                tier, reasons = _diff_tier(old_edge, new_edge)
                findings.append({
                    "kind": "CHANGED_DISPLACEMENT", "class": name, "base": base,
                    "evidence_tier": tier, "evidence_tier_reasons": reasons,
                    "detail": {
                        "old_where": dict(zip(("mdisp", "pdisp", "vdisp"), old_where)),
                        "new_where": dict(zip(("mdisp", "pdisp", "vdisp"), new_where)),
                    },
                })

        old_vtables = old_classes[name].get("vtables", [])
        new_vtables = new_classes[name].get("vtables", [])
        for i in range(min(len(old_vtables), len(new_vtables))):
            old_vt, new_vt = old_vtables[i], new_vtables[i]
            if old_vt["slot_count"] != new_vt["slot_count"]:
                tier, reasons = _diff_tier(old_vt, new_vt)
                findings.append({
                    "kind": "VTABLE_SLOT_COUNT_CHANGED", "class": name, "vtable_index": i,
                    "evidence_tier": tier, "evidence_tier_reasons": reasons,
                    "detail": {"old_slot_count": old_vt["slot_count"], "new_slot_count": new_vt["slot_count"]},
                })
            else:
                # Slot identity for reordering is the TARGET FUNCTION'S OWN
                # CONTENT hash, never its address -- an address is only
                # ever stable within one build (see this module's own diff
                # docstring, Phase 4 section, and VTABLE_SLOT_CONTENT_HASH_
                # BYTES above). A None hash means that slot's target was not
                # readable at all on that side; such a slot can never
                # honestly contribute to a "same set, reordered" claim, so
                # its presence on either side rules the finding out here
                # rather than comparing an unknown against anything.
                old_hashes = old_vt.get("slot_content_hashes", [])
                new_hashes = new_vt.get("slot_content_hashes", [])
                if (
                    old_hashes != new_hashes
                    and None not in old_hashes
                    and None not in new_hashes
                    and sorted(old_hashes) == sorted(new_hashes)
                ):
                    tier, reasons = _diff_tier(old_vt, new_vt)
                    findings.append({
                        "kind": "VTABLE_SLOTS_REORDERED", "class": name, "vtable_index": i,
                        "evidence_tier": tier, "evidence_tier_reasons": reasons,
                        "detail": {
                            "old_slot_vas": old_vt["slot_vas"], "new_slot_vas": new_vt["slot_vas"],
                            "old_slot_content_hashes": old_hashes, "new_slot_content_hashes": new_hashes,
                        },
                    })
        if len(old_vtables) != len(new_vtables):
            findings.append({
                "kind": "VTABLE_COUNT_CHANGED_FOR_CLASS", "class": name,
                "evidence_tier": "CANDIDATE",
                "evidence_tier_reasons": [_reason(
                    "VTABLE_COUNT_MISMATCH_UNOBSERVED_IN_REAL_CORPUS",
                    "This class has a different number of bound vtables between the two sides. No "
                    "real target in this repo's corpus has ever had more than one vtable for one "
                    "class (see docs/TOOL_GAP_BACKLOG.md GAP-022 Phase 3), so this specific "
                    "comparison is itself unexercised on real bytes and is reported defensively.",
                )],
                "detail": {"old_vtable_count": len(old_vtables), "new_vtable_count": len(new_vtables)},
            })

    return findings


def _diff(path, other_path, max_chars):
    if not other_path:
        return _j({"ok": False, "error": "OTHER_PATH_REQUIRED", "tool": "cpp_rtti_inspect",
                   "note": "operation=\"diff\" compares two binaries; pass other_path as the second one."})

    old = _analyze_path_for_diff(path)
    new = _analyze_path_for_diff(other_path)

    if not old["ok"]:
        return _j({"ok": False, "status": old["status"], "tool": "cpp_rtti_inspect", "side": "old",
                   "path": old.get("path"), "error": old.get("error")})
    if not new["ok"]:
        return _j({"ok": False, "status": new["status"], "tool": "cpp_rtti_inspect", "side": "new",
                   "path": new.get("path"), "error": new.get("error")})
    if old["status"] == "UNSUPPORTED_MACHINE" or new["status"] == "UNSUPPORTED_MACHINE":
        side = "old" if old["status"] == "UNSUPPORTED_MACHINE" else "new"
        unsupported = old if side == "old" else new
        return _j({"ok": True, "status": "UNSUPPORTED_MACHINE", "tool": "cpp_rtti_inspect", "side": side,
                   "machine": unsupported.get("machine"), "old_path": old["path"], "new_path": new["path"]})
    if old["architecture"] != new["architecture"]:
        # Explicit refusal, per lead instruction: a 32-bit absolute-VA class
        # and a 64-bit RVA-relative class are not directly comparable facts.
        return _j({"ok": False, "status": "BITNESS_MISMATCH", "tool": "cpp_rtti_inspect",
                   "error": "Cannot meaningfully diff a 32-bit and a 64-bit image against each other.",
                   "old_path": old["path"], "old_architecture": old["architecture"],
                   "new_path": new["path"], "new_architecture": new["architecture"]})

    findings = _diff_findings(old, new)
    findings.sort(key=lambda f: (f["kind"], f.get("class", ""), f.get("base", ""), f.get("vtable_index", -1)))
    counts_by_kind = {}
    for finding in findings:
        counts_by_kind[finding["kind"]] = counts_by_kind.get(finding["kind"], 0) + 1

    result = {
        "ok": True,
        "status": "OK",
        "tool": "cpp_rtti_inspect",
        "operation": "diff",
        "old_path": old["path"],
        "new_path": new["path"],
        "architecture": old["architecture"],
        "old_class_count": len(old["classes"]),
        "new_class_count": len(new["classes"]),
        "relocation_directory_present": {
            "old": old.get("relocation_directory_present"),
            "new": new.get("relocation_directory_present"),
        },
        "finding_count": len(findings),
        "counts_by_kind": counts_by_kind,
        "findings": findings,
        "evidence_class": "observed_fact",
        "evidence_note": (
            "Every finding compares two independently RTTI-recovered class graphs by mangled "
            "TypeDescriptor name, never by address (see this module's own diff docstring section "
            "and binary_version_diff.py's identity_policy for the same discipline applied to "
            "functions). A finding is PROVEN only if the underlying evidence on BOTH sides is "
            "PROVEN; if either side's own class/edge/vtable evidence is CANDIDATE, the finding is "
            "CANDIDATE too, carrying both sides' reasons forward rather than upgrading silently."
        ),
        "limitations": [
            "VTABLE_SLOTS_REORDERED compares each slot's own CONTENT-HASH identity (a fixed-length "
            "prefix of the bytes at the slot's target VA, see VTABLE_SLOT_CONTENT_HASH_BYTES), "
            "never its address -- this is what lets the finding fire across two genuinely "
            "independent, differently-based binaries, unlike an earlier address-only comparison "
            "that could only ever fire on synthetic fixtures sharing one IMAGE_BASE. Its real, "
            "stated blind spot: if a method's own code genuinely changed between the two builds, "
            "its content hash changes too, so this rule cannot tell a real reorder of a CHANGED "
            "method apart from an unrelated rewrite that happens to leave a different UNCHANGED "
            "method in the reordered method's old slot position -- it only ever reliably catches "
            "an unchanged method that moved, never one that was also rewritten.",
            "Vtable slots are compared by content hash and raw address only, never resolved to a "
            "method name or decompiled -- a same-position slot value change that is not a pure "
            "reorder is not classified as its own finding kind.",
            "analysis_ir.py's core schema is deliberately not used or extended for this diff -- it "
            "is a self-sufficient comparison of this module's own output only.",
        ],
        "truncated": False,
        "truncation": [],
    }
    # finding_count/counts_by_kind above are computed from the full findings
    # list before this call, so they are unaffected by any cutting below --
    # this is the property that made operation="diff" immune to the
    # single-path "classes" truncation defect in the first place (see this
    # module's own truncation record discipline, _render_with_truncation).
    return _render_with_truncation(result, max_chars, ("findings",))


def cpp_rtti_inspect(path, operation="classes", max_chars=60000, other_path=None):
    """Recover MSVC C++ RTTI classes (TypeDescriptor/COL/CHD/BaseClassArray)
    from a compiled 32- or 64-bit binary's own bytes, or (``operation="diff"``)
    compare two such binaries' recovered classes/vtables (see this module's
    docstring, Phase 4 section)."""
    if operation not in _ALLOWED_OPS:
        return _j({"ok": False, "error": "UNKNOWN_OPERATION", "tool": "cpp_rtti_inspect",
                   "allowed": sorted(_ALLOWED_OPS)})
    try:
        import pefile  # noqa: F401
    except ImportError:
        return _j({"ok": False, "status": "TOOL_MISSING", "tool": "cpp_rtti_inspect",
                   "required_capability": "pefile"})

    if operation == "diff":
        return _diff(path, other_path, max_chars)

    target = safe_path(path)
    try:
        image = _Image(target)
    except Exception as exc:  # noqa: BLE001
        return _j({"ok": False, "status": "NOT_A_PE", "tool": "cpp_rtti_inspect",
                   "path": relative(target), "error": f"{type(exc).__name__}: {exc}"})

    try:
        machine = _machine_of(image)
        if machine == IMAGE_FILE_MACHINE_I386:
            is64 = False
            architecture = "x86"
        elif machine == IMAGE_FILE_MACHINE_AMD64:
            is64 = True
            architecture = "x64"
        else:
            return _j({
                "ok": True,
                "status": "UNSUPPORTED_MACHINE",
                "tool": "cpp_rtti_inspect",
                "path": relative(target),
                "machine": hex(machine) if machine is not None else None,
                "note": (
                    "This tool implements only the two MSVC RTTI layouts: 32-bit "
                    "(IMAGE_FILE_MACHINE_I386, absolute VA) and 64-bit "
                    "(IMAGE_FILE_MACHINE_AMD64, RVA-relative plus a pSelf anchor). Any other "
                    "machine type (e.g. ARM/ARM64) is refused rather than misparsed against "
                    "either x86 layout."
                ),
            })

        dword_index, qword_index = _build_reference_index(image, is64)
        proven, unresolved = _scan(image, is64, dword_index)
        classes, edges, relocation_directory_present = _build_classes_and_edges(
            image, proven, is64, (dword_index, qword_index))

        if not classes:
            has_itanium_evidence = any(marker in image.data for marker in _ITANIUM_MARKERS)
            if has_itanium_evidence:
                result = {
                    "ok": True,
                    "status": "TOOLCHAIN_NOT_MSVC",
                    "tool": "cpp_rtti_inspect",
                    "path": relative(target),
                    "note": (
                        "Itanium C++ ABI markers (_ZTI/_ZTS/_ZTV mangled RTTI symbols and/or "
                        "__cxa_throw/__cxa_begin_catch/__cxa_end_catch) were found and no "
                        "MSVC-shaped '.?AV'/'.?AU' TypeDescriptor name was found anywhere in "
                        "the image -- this is a MinGW-GCC or Itanium-ABI clang binary, not an "
                        "MSVC one. This tool only implements the MSVC RTTI layout."
                    ),
                    "classes": [],
                    "hierarchy_edges": [],
                }
            else:
                result = {
                    "ok": True,
                    "status": "ABSENT",
                    "tool": "cpp_rtti_inspect",
                    "path": relative(target),
                    "note": (
                        "No MSVC-shaped '.?AV'/'.?AU' TypeDescriptor name string was found "
                        "anywhere in the image. This means RTTI is absent from this binary "
                        "(most commonly compiled with /GR-) -- it is NOT a statement that the "
                        "binary is not C++: a C++ binary compiled without RTTI carries no "
                        "readable class table for this tool to find."
                    ),
                    "classes": [],
                    "hierarchy_edges": [],
                }
            result["architecture"] = architecture
            result["type_descriptor_candidate_count"] = len(unresolved)
            result["type_descriptor_candidates_without_col"] = unresolved
            result["truncated"] = False
            result["truncation"] = []
            return _render_with_truncation(result, max_chars, ("type_descriptor_candidates_without_col",))

        result = {
            "ok": True,
            "status": "OK",
            "tool": "cpp_rtti_inspect",
            "operation": operation,
            "path": relative(target),
            "architecture": architecture,
            "image_base": hex(image.base),
            "class_count": len(classes),
            "hierarchy_edge_count": len(edges),
            "type_descriptor_candidate_count": len(unresolved),
            "classes": classes,
            "hierarchy_edges": edges,
            "type_descriptor_candidates_without_col": unresolved,
            "relocation_directory_present": relocation_directory_present,
            "evidence_class": "observed_fact",
            "evidence_note": (
                "Every reported class was reached through a chained verification: its own "
                "TypeDescriptor name-shape check, a COL in this image whose signature matches "
                "this architecture's expected value and whose pTypeDescriptor points at exactly "
                "this TypeDescriptor (and, on 64-bit, whose pSelf resolves to its own address), "
                "that COL's pClassHierarchyDescriptor resolving to a signature-0 CHD with a "
                "plausible numBaseClasses, and every one of that CHD's BaseClassArray entries "
                "independently re-passing the TypeDescriptor name-shape check on ITS OWN "
                "pTypeDescriptor. A bare name-string match alone is never promoted -- see "
                "type_descriptor_candidates_without_col for names that did not resolve."
            ),
            "not_established": [
                "WHAT_ANY_METHOD_DOES",
                "WHICH_CLASS_IMPLEMENTS_THE_PROGRAM'S_CHECK",
            ],
            "what_this_does_not_do": (
                "No decompilation, and no support for machine types other than I386/AMD64 (see "
                "UNSUPPORTED_MACHINE). BaseClassArray entry 0 (each class's own self-identifying "
                "entry) is excluded from hierarchy_edges; only genuine base relationships are "
                "edges. Phase 3 binds each class's vtable(s) via its own COL's vtable[-1] "
                "back-link and reports every slot address plus (Phase 4) a fixed-length content "
                "hash of that slot's own target bytes (VTABLE_SLOT_CONTENT_HASH_BYTES, used for "
                "cross-binary diff identity), but does not decode, disassemble or identify what "
                "any slot's target function does -- 'vtables' is a list of addresses and opaque "
                "content hashes, not decompiled or named methods. This repo's entire corpus (32 "
                "RTTI-bearing targets scanned) has never produced a class with more than one vtable -- see "
                "docs/TOOL_GAP_BACKLOG.md GAP-022 Phase 3 for the byte-level reason why, and the "
                "data shape here stays list-valued so a future real multi-vtable sample needs no "
                "schema change."
            ),
        }
        # Priority order: classes first (the largest, least load-bearing
        # collection), then unresolved name candidates, then hierarchy
        # edges last -- edges are never observed to need cutting in this
        # repo's real corpus (class_count/hierarchy_edge_count above are
        # each the TRUE total regardless of what gets cut below), but are
        # included so a hypothetical binary with few classes and a huge
        # edge list still gets an honest truncation record instead of a
        # render that silently exceeds max_chars with no signal at all.
        return _render_with_truncation(
            result, max_chars,
            ("classes", "type_descriptor_candidates_without_col", "hierarchy_edges"),
        )
    finally:
        image.close()
