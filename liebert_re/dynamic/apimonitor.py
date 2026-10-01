"""API Monitor v2 (rohitab.com, "Portable Edition" r13) adapter -- matches
this repo's other external console-tool contract (tools_windbg.py /
tools_x64dbg.py / tools_die.py: the first two upstream-only; not part of the published package): TOOL_MISSING (never a raised exception) when
the toolchain is absent, run_bounded_process for every subprocess, structured
JSON evidence, and no fabricated confidence score.

Ground truth verified on this host BEFORE writing this module (installed at
``C:\\Tools\\APIMonitor\\API Monitor (rohitab.com)``, APIMONITOR_HOME
overrides it):

  - The install ships exactly two executables: ``apimonitor-x86.exe`` and
    ``apimonitor-x64.exe``. Both are Win32 GUI applications (MFC-style, no
    console subsystem). Probed with ``apimonitor-x64.exe /?`` under a bounded
    timeout: the process produced NO stdout/stderr output at all (an
    application with a real ``/?`` CLI help path prints synchronously and
    exits; this one did not print and had to be killed by the timeout) --
    there is no discoverable command-line help, and by extension no
    documented CLI automation surface. This matches the shipped
    ``Readme.txt``, which describes exactly one usage mode: "Run
    apimonitor-x86.exe ... OR apimonitor-x64.exe" and nothing else -- no
    ``-c``/``-cf``/headless-style flag exists the way x64dbg's
    ``headless.exe`` has one. There is no separate CLI/headless helper binary
    anywhere in the install tree (only the two GUI exes above).
  - Consequently this module does NOT fabricate a live-capture operation.
    Starting a trace requires the GUI: pick a process/executable in the
    "Monitor New Process" / "Monitor Process" dialog, and press Start -- a
    caller cannot drive that without GUI automation (window-handle/SendMessage
    scripting), which this module does not implement and which the security
    boundary below would gate anyway even if it existed. ``live_trace``
    always returns a structured, honest ``NOT_SUPPORTED`` refusal.
  - The install ships NO sample ``.apmx64``/``.apmx32`` trace file anywhere
    on this host (searched the install tree and the user profile -- none
    found), and API Monitor v2's trace-file format is proprietary/undocumented
    by rohitab.com (no published spec, no header magic-byte documentation
    shipped with this "Portable Edition", no bundled export-to-text/CSV
    command-line utility). Without a real captured file to reverse a binary
    layout from, and no documented spec to parse against, this module does
    NOT fabricate a working ``.apmx64`` binary parser -- ``parse_trace``
    always returns a structured, honest ``NOT_SUPPORTED`` refusal rather than
    guessing a byte layout. (If the GUI is later used to export a session to
    XML/CSV via its own File > Export, THAT text output is a wholly different
    -- and parseable -- artifact; this module does not assume that step
    happened.)
  - What genuinely IS present, safe, and directly useful without running
    anything: ``API/*.xml`` under the install root is a real, large,
    machine-readable catalog of every API this build of API Monitor knows how
    to hook -- verified by directly parsing it (not asserted): 2121 XML files
    total, containing 25212 ``<Api Name="...">`` definitions grouped under
    ``<Module Name="X.dll">`` elements, spanning categories (subdirectories)
    Headers, Interfaces, Internal, MAPI, MMF, Microsoft.NET, Mozilla, SMI,
    VSS, WMI, Windows, WindowsFirewall, WindowsStore. ``api_catalog`` parses
    this with the stdlib XML parser (read-only file access, nothing executed)
    and answers "which functions in module X can be traced" / "which modules
    export function Y" -- exactly the question a caller needs answered before
    deciding what to look for once a live capture (via the GUI, or via a
    future properly-driven automation path) is available.

Security boundary (same posture as tools_windbg.py/tools_x64dbg.py (upstream-only; not part of the published package), reused
rather than reinvented): this module has NO operation that launches or
attaches to a live target process at all right now -- ``live_trace`` is a
permanent, unconditional ``NOT_SUPPORTED`` refusal (no CLI/automation surface
exists to drive it), not merely gated. If a future version adds real GUI
automation (e.g. via UI Automation / SendMessage driving the actual
apimonitor-x64.exe process), that capability MUST reuse the same
``isolated_context_confirmed`` + operator-env-var double-gate
``user_mode_live_debug``/``script_run`` use, since it would launch and
control a live target exactly like they do. ``available``/``status`` (stat
files on disk only) and ``api_catalog``/``parse_trace`` (read existing files
only, never execute anything) never touch that gate because they never run a
target.
"""
from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

# bounded_subprocess.run_bounded_process is this repo's standard subprocess
# wrapper (used by tools_windbg.py/tools_x64dbg.py, both upstream-only; not part of the published package); imported here even
# though no operation in this module currently calls it, so the dependency
# is visible and ready the moment a real, verified automation path exists
# (see live_trace's docstring for why none exists yet -- it is an
# unconditional NOT_SUPPORTED refusal, not a gated-but-implemented path).
from liebert_re.bounded_subprocess import run_bounded_process  # noqa: F401
from liebert_re.workspace import safe_path, relative  # noqa: F401

from liebert_re.workspace import PROJECT_ROOT as APP_DIR
EVIDENCE = APP_DIR / "dataset" / "evidence" / "apimonitor"
EVIDENCE.mkdir(parents=True, exist_ok=True)

# Verified-installed location on this host (API Monitor v2-r13, Portable
# Edition) -- same "known install" fallback pattern as tools_die.py's
# _KNOWN_INSTALL / tools_windbg.py's _KNOWN_DEBUGGERS_DIR /
# tools_x64dbg.py's _KNOWN_INSTALL_ROOT (both upstream-only, not part of the
# published package). APIMONITOR_HOME overrides it.
_KNOWN_INSTALL_ROOT = Path(r"C:\Tools\APIMonitor\API Monitor (rohitab.com)")

_MIN_TIMEOUT_SECONDS = 5
_MAX_TIMEOUT_SECONDS = 60
_DEFAULT_TIMEOUT_SECONDS = 10
_MAX_OUTPUT_CHARS = 1024 * 1024

# api_catalog is a read-only scan over a bounded, known-size install tree
# (2121 files verified on this host); refuse absurd input rather than walk
# an attacker-controlled directory tree indefinitely.
_MAX_CATALOG_FILES = 5000


def _install_root():
    explicit = os.getenv("APIMONITOR_HOME", "").strip()
    if explicit:
        return Path(explicit)
    return _KNOWN_INSTALL_ROOT


def _exe_path(arch="x64"):
    suffix = "x64" if arch == "x64" else "x86"
    candidate = _install_root() / f"apimonitor-{suffix}.exe"
    return candidate if candidate.exists() else None


def _api_dir():
    return _install_root() / "API"


def apimonitor_available(arch="x64"):
    """True when the GUI executable for the requested architecture ("x64" or
    "x86") is present. Says nothing about live-capture capability -- there is
    none in this module, see module docstring."""
    return _exe_path(arch) is not None


def _j(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _tool_missing(operation, arch="x64", required_capability=None):
    return _j({
        "ok": False, "tool": f"apimonitor_{operation}", "status": "TOOL_MISSING",
        "required_capability": required_capability or f"API Monitor v2 GUI executable ({arch})",
        "expected_path": str(_install_root() / f"apimonitor-{'x64' if arch == 'x64' else 'x86'}.exe"),
        "remediation": (
            "Install API Monitor v2 (http://www.rohitab.com/apimonitor), or set APIMONITOR_HOME to "
            "the directory containing apimonitor-x64.exe/apimonitor-x86.exe and the API/ definitions "
            "tree."
        ),
    })


def status(arch=None):
    """Report installation status: which architecture GUI binaries are
    present, the API/ definitions tree location and whether it looks intact,
    and the version string read from Settings.ini when readable. Never spawns
    a process -- pure filesystem stat + optional small text-file read."""
    root = _install_root()
    archs = [arch] if arch else ["x64", "x86"]
    per_arch = {}
    for a in archs:
        exe = _exe_path(a)
        per_arch[a] = {"gui_binary_available": exe is not None, "gui_binary_path": exe}

    api_dir = _api_dir()
    api_dir_present = api_dir.is_dir()

    version = None
    settings = root / "Settings.ini"
    if settings.is_file():
        try:
            raw = settings.read_text(encoding="utf-16", errors="replace")
        except (OSError, UnicodeError):
            try:
                raw = settings.read_text(encoding="latin-1", errors="replace")
            except OSError:
                raw = ""
        m = re.search(r"API Monitor v(\S+)", raw)
        if m:
            version = m.group(1).rstrip("]").strip()

    any_available = any(v["gui_binary_available"] for v in per_arch.values())
    return _j({
        "ok": True, "status": "OK", "tool": "apimonitor_status",
        "install_root": str(root),
        "available": any_available,
        "version_from_settings_ini": version,
        "architectures": per_arch,
        "api_definitions_dir": str(api_dir),
        "api_definitions_dir_present": api_dir_present,
        "note": (
            "Both apimonitor-x64.exe and apimonitor-x86.exe are GUI-only executables with no "
            "discoverable command-line help or automation flag (verified against this host's "
            "install: 'apimonitor-x64.exe /?' produced no output and had to be killed by a bounded "
            "timeout). This module never launches either binary; live_trace always returns "
            "NOT_SUPPORTED. See api_catalog for the one genuinely useful read-only capability this "
            "install offers without running anything."
        ),
    })


def api_catalog(module_filter=None, category=None, max_files=_MAX_CATALOG_FILES):
    """Parse API Monitor's own ``API/*.xml`` definition tree into a
    structured catalog of {module_name: [function_name, ...]} -- the
    machine-readable answer to "which API calls can this install trace, and
    in which DLL". Pure read-only XML parsing of files shipped with the
    install; never executes anything, never requires the GUI binary itself
    to be present (only the API/ directory).

    `module_filter`: optional case-insensitive substring match against
    module (DLL) names, e.g. "advapi32" or "ws2_32".
    `category`: optional exact match against the top-level API/ subdirectory
    name (e.g. "Windows", "Interfaces", "WMI") to scope the scan.
    `max_files`: safety bound on how many XML files this call will read
    (default matches the verified real tree size on this host).
    """
    api_dir = _api_dir()
    if not api_dir.is_dir():
        return _tool_missing("api_catalog", required_capability="API/ definitions directory")

    if category:
        roots = [api_dir / category]
        roots = [r for r in roots if r.is_dir()]
        if not roots:
            return _j({
                "ok": False, "tool": "apimonitor_api_catalog", "status": "NOT_FOUND",
                "error": "UNKNOWN_CATEGORY", "category": category,
                "available_categories": sorted(p.name for p in api_dir.iterdir() if p.is_dir()),
            })
    else:
        roots = [api_dir]

    xml_files = []
    for root in roots:
        xml_files.extend(sorted(root.rglob("*.xml")))
        if len(xml_files) > max_files:
            break
    truncated_file_scan = len(xml_files) > max_files
    xml_files = xml_files[:max_files]

    module_needle = (module_filter or "").strip().lower()
    modules = {}
    parse_errors = []
    for f in xml_files:
        try:
            tree = ET.parse(f)
        except ET.ParseError as exc:
            parse_errors.append({"file": str(f), "error": str(exc)})
            continue
        # Two distinct container schemas exist in this definitions tree,
        # verified by directly reading both: <Module Name="X.dll" ...> for
        # plain DLL-exported functions (API/Windows/*, API/WMI/*, ...), and
        # <Interface Name="IFoo" ...> for COM interface methods
        # (API/Interfaces/* -- 1558 of the 2121 files on this host use this
        # shape, not <Module>; skipping it would silently drop the majority
        # of the tree). Both are surfaced the same way, distinguished by
        # "kind", since a caller asking "what can be traced here" needs both.
        for kind, tag, name_key in (("dll_module", "Module", "module"), ("com_interface", "Interface", "module")):
            for mod_el in tree.getroot().iter(tag):
                mod_name = mod_el.get("Name")
                if not mod_name:
                    continue
                if module_needle and module_needle not in mod_name.lower():
                    continue
                functions = sorted({
                    api_el.get("Name") for api_el in mod_el.iter("Api") if api_el.get("Name")
                })
                if not functions:
                    continue
                dict_key = (kind, mod_name)
                entry = modules.setdefault(dict_key, {
                    "module": mod_name,
                    "kind": kind,
                    "source_file": str(f),
                    "calling_convention": mod_el.get("CallingConvention"),
                    "base_interface": mod_el.get("BaseInterface"),
                    "functions": [],
                })
                entry["functions"] = sorted(set(entry["functions"]) | set(functions))

    module_list = sorted(modules.values(), key=lambda m: m["module"].lower())
    total_functions = sum(len(m["functions"]) for m in module_list)
    return _j({
        "ok": True, "status": "OK", "tool": "apimonitor_api_catalog",
        "api_definitions_dir": str(api_dir),
        "files_scanned": len(xml_files),
        "files_scan_truncated": truncated_file_scan,
        "parse_errors": parse_errors,
        "module_count": len(module_list),
        "total_functions": total_functions,
        "modules": module_list,
        "note": (
            "Deterministic parse of API Monitor's own <Module Name=...><Api Name=.../></Module> XML "
            "definitions -- not a probabilistic classification. A module/function only appears here "
            "because its <Api Name=...> element is literally present in the definitions file; nothing "
            "is inferred or guessed."
        ),
    })


def parse_trace(*_args, **_kwargs):
    """Always refuses. API Monitor v2's .apmx64/.apmx32 trace-file format is
    proprietary and undocumented by rohitab.com; this install ships no
    command-line export/decode utility, and no sample trace file was
    available on this host to reverse a binary layout from at the time this
    module was written. Rather than guess a byte layout and silently emit
    wrong data, this function always returns a structured, honest
    NOT_SUPPORTED refusal. Never opens or reads any file."""
    return _j({
        "ok": False, "status": "NOT_SUPPORTED", "tool": "apimonitor_parse_trace",
        "detail": (
            "API Monitor v2's .apmx64/.apmx32 trace-file format is a proprietary, undocumented "
            "binary format (no published spec, no bundled CLI export/decode tool in this "
            "'Portable Edition' install). No sample trace file was available on this host to verify "
            "a parser against."
        ),
        "remediation": (
            "Open the trace in the API Monitor GUI and use its own File > Export to XML/CSV first; "
            "that exported text file is a documented, parseable format this module could add support "
            "for once a real sample is available. This function does not fabricate a binary-format "
            "parser without verified ground truth."
        ),
        "execution_performed": False,
    })


def live_trace(*_args, **_kwargs):
    """Always refuses. Starting a live API-call capture in API Monitor v2
    requires the GUI (pick a process/executable in the Monitor dialog, press
    Start) -- there is no command-line flag or headless entry point (verified
    against this host's install: neither apimonitor-x64.exe nor
    apimonitor-x86.exe prints CLI help or offers a documented automation
    surface, unlike x64dbg's headless.exe). This module does not implement
    GUI/window automation, so there is no code path here that could launch a
    target even under an isolation override -- unconditional NOT_SUPPORTED,
    not merely gated. Never constructs a subprocess under any argument
    combination."""
    return _j({
        "ok": False, "status": "NOT_SUPPORTED", "tool": "apimonitor_live_trace",
        "detail": (
            "API Monitor v2 has no command-line/headless mode to start a capture -- verified: "
            "'apimonitor-x64.exe /?' produced no help output on this host, and the shipped Readme.txt "
            "documents only interactive GUI usage. Driving a capture requires GUI automation "
            "(window/SendMessage scripting) this module does not implement."
        ),
        "remediation": (
            "Use tools_windbg.py's user_mode_live_debug or tools_x64dbg.py's script_run for "
            "isolated, scriptable live inspection of the same target instead (both upstream-only; not part of the published package); both have "
            "a real command-line/scripting automation surface this tool lacks. If GUI automation for API "
            "Monitor is added later, it must reuse the same isolated_context_confirmed + operator-env "
            "double-gate those two modules use."
        ),
        "execution_performed": False,
    })
