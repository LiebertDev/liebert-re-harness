# Static secret with a time-varying component, plain compare

Class: input is read with a short read; a static global is copied into a buffer; the
tail of the buffer is overwritten with a value derived from the current date; the check
is a plain string compare.

Resolved statically: the expected value depends on the local calendar date and nothing
else. Mechanism, class level only: a static string copied into a fixed buffer, tail
overwritten via the C runtime's time/localtime/strftime, plain compare.

First step: read the decompilation of the single compare function, separate the static
part from the time-derived part, and verify each "cannot be known statically" claim
against the code (an earlier such claim here was wrong).

## Odd imports and compiler runtimes

An unusual trio of imports (AddAtomA, FindAtomA, GetAtomNameA) looked like protection
and was not. The names sit beside the MinGW shared-pointer runtime, and the strings
come from GCC's w32-shared-ptr.c, which backs SJLJ exception handling. Ownership link
is an inference from adjacency and string provenance, not a measured xref; analysis
could not obtain a code xref. Rule: before building a theory on an odd import, check
whether a compiler-runtime function owns it.

What the atom table would give a protection scheme, in general: a process-global,
name-keyed store readable by other code in the process. No evidence of that use here.

## Harness limits observed (see REPORT.md)

- RESOLVED (was UNRECORDED): data past the last section was not reported. `trailing`
  now attributes it (COFF symbol and string table, consistent; records not decoded).
- IDA xrefs_to wants the exact decorated name and does not follow thunks.
- pdata refuses x86 (no exception directory); use IDA for x86 function extents.
- pe --signature output can carry shell execution-policy noise.
- UNRECORDED: no shipped operation dereferences a static data pointer; raw bytes had to
  be read with a throwaway script.
- UNRECORDED: ida decompile_function puts code in `decompiled`; `items` has only name
  and address.
