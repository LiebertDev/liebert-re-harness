# Input transformed to bit-text, compared by distance

Class: the input is converted to a bit-text form and compared with a stored reference; a
distance of zero is accepted. Surrounding length and boundary handling is weak. No packing,
crypto or anti-debug. A valid input is constructible statically for any run.

First step: find the compare, read the transform, build the input statically. A flag-like
blob in .rdata is not evidence by itself; it was not proven decoy or reference here.

## Leads that were not protection (each settled by a shipped tool)

- VirtualQuery/VirtualProtect: the MinGW pseudo-relocation fixer, not self-modifying code.
- TLS callbacks: the MinGW tlssup pattern, no debugger check.
- .rsrc: a manifest inside padding and directory, not a payload (pe --resources).
- Sleep: no caller found, only the thunk. PARTIAL: indirect calls via .rdata not excluded.

Rule: identify the compiler runtime before theorising about an odd import or section.

## Harness limits observed (see REPORT.md)

- An empty xrefs_to on an import is "unresolved", not "no callers" (now in ROADMAP).
- No import-caller or data-reference search; pdata is triage, not discovery.
