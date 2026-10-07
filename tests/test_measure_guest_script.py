"""`scripts/measure_guest.ps1`: the operator measurement script is read-only, and checked statically.

The script is never run here. It is read as text, and, where a PowerShell is installed, parsed
into its AST so that the command names a regex could miss (aliases, dynamic calls) are caught.
It must emit exactly the schema `liebert_re.dynamic.guest_attestation.GuestAttestation` reads.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from liebert_re.dynamic.guest_attestation import GuestAttestation

pytestmark = pytest.mark.contract

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "measure_guest.ps1"

# Every command the script may invoke. Host reads, the guest read channel, and the one write.
ALLOWED_COMMANDS = frozenset({
    "Get-VM", "Get-VMSnapshot", "Get-VMNetworkAdapter", "Get-VMSwitch",
    "Get-VMIntegrationService", "Get-VMSecurity",
    "Get-ItemProperty", "Get-CimInstance",
    "Invoke-Command",
    "ConvertTo-Json", "Out-File",
})

MUTATING_VERBS = ("Set", "Remove", "Enable", "Disable", "New", "Start", "Stop", "Checkpoint", "Restore",
                  "Copy", "Add", "Connect", "Rename", "Save", "Update", "Import", "Export", "Move", "Clear")

DYNAMIC_PATTERNS = (r"\biex\b", r"Invoke-Expression", r"Start-Process", r"&", r"\.Invoke\(", r"Add-Type",
                    r"bcdedit", r"reg\.exe", r"\[scriptblock\]::Create", r"\.InvokeReturnAsIs",
                    r"-EncodedCommand")


def _raw() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _code() -> str:
    """The script without whole-line comments; the header may name verbs it forbids."""
    return "\n".join(ln for ln in _raw().splitlines() if not ln.lstrip().startswith("#"))


def _shells() -> list[str]:
    return [p for p in (shutil.which("pwsh"), shutil.which("powershell")) if p]


def test_commands_subset_of_allowlist():
    used = set(re.findall(r"\b[A-Z][a-z]+-[A-Z][A-Za-z]+\b", _code()))
    assert used, "no cmdlet names found; the pattern or the script is wrong"
    assert used <= ALLOWED_COMMANDS, f"cmdlets outside the allowlist: {sorted(used - ALLOWED_COMMANDS)}"


def test_no_mutating_verbs():
    pattern = re.compile(r"\b(?:" + "|".join(MUTATING_VERBS) + r")-[A-Za-z]", re.IGNORECASE)
    assert pattern.findall(_code()) == []


def test_no_dynamic_execution():
    code = _code()
    hits = [p for p in DYNAMIC_PATTERNS if re.search(p, code, re.IGNORECASE)]
    assert hits == []


def test_does_not_reference_hvci_keys():
    # AGENTS.md rule 11: neither read nor written, so the text must not name them at all.
    text = _raw()
    assert r"DeviceGuard\Scenarios" not in text
    assert "HypervisorEnforcedCodeIntegrity" not in text


def _keys_in(block: str) -> set[str]:
    return set(re.findall(r"(?<![\w$\[])([a-z_0-9]+)\s*=(?!=)", block))


def test_emits_every_schema_field():
    code = _code()
    head, *rest = re.split(r"(?m)^\$result\['(\w+)'\] = ", code)
    blocks: dict[str, str] = {"": head}
    for name, body in zip(rest[0::2], rest[1::2]):
        blocks[name] = blocks.get(name, "") + "\n" + body
    assert set(blocks) == set(GuestAttestation.SCHEMA_FIELDS), "script sections differ from SCHEMA_FIELDS"
    for section, fields in GuestAttestation.SCHEMA_FIELDS.items():
        keys = _keys_in(blocks[section])
        assert set(fields) <= keys, f"{section or 'top level'}: script never sets {sorted(set(fields) - keys)}"
    for section, fields in GuestAttestation.SCHEMA_ITEM_FIELDS.items():
        keys = _keys_in(blocks[section])
        assert set(fields) <= keys, f"{section} items: script never sets {sorted(set(fields) - keys)}"
    assert "isolation_asserted_by_operator" not in _raw()
    assert f"'{GuestAttestation.SCHEMA}'" in code


def test_vm_name_has_no_default():
    code = _code()
    assert re.search(r"Mandatory\s*=\s*\$true\s*\)\]\s*\[string\]\s*\$VMName\b", code)
    assert re.search(r"Mandatory\s*=\s*\$true\s*\)\]\s*\[string\]\s*\$OutFile\b", code)
    assert not re.search(r"\$VMName\s*=", code), "$VMName is assigned somewhere; it must have no default"


def test_header_states_scope_and_forgeability():
    header = "\n".join(ln for ln in _raw().splitlines() if ln.lstrip().startswith("#"))
    assert "spoofable: true" in header
    assert "Copy-Item -ToSession" in header
    assert "does NOT change" in header


_AST_SNIPPET = (
    "$e = $null; $t = $null; "
    "$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:MEASURE_GUEST_SCRIPT, [ref]$t, [ref]$e); "
    "if ($e.Count -gt 0) { 'PARSE_ERRORS:' + $e.Count; exit 0 }; "
    "$cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true); "
    "foreach ($c in $cmds) { $n = $c.GetCommandName(); if ($null -eq $n) { '<DYNAMIC>' } else { $n } }"
)


def test_ast_commands_match_allowlist():
    shells = _shells()
    if not shells:
        pytest.skip("no pwsh or powershell on PATH: the AST check cannot run here")
    env = dict(os.environ, MEASURE_GUEST_SCRIPT=str(SCRIPT))
    for shell in shells:
        proc = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", _AST_SNIPPET],
                              capture_output=True, text=True, timeout=120, env=env, check=False)
        assert proc.returncode == 0, f"{Path(shell).name} failed to parse: {proc.stderr.strip()[:200]}"
        names = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        assert names, f"{Path(shell).name} reported no commands"
        assert not any(n.startswith("PARSE_ERRORS:") for n in names), names
        assert "<DYNAMIC>" not in names, "a command with no static name (call operator or variable)"
        assert set(names) <= ALLOWED_COMMANDS, f"{Path(shell).name}: {sorted(set(names) - ALLOWED_COMMANDS)}"
        # The allowlisted read set is actually used, so an empty-but-passing parse cannot hide.
        assert {"Get-VM", "Invoke-Command", "Out-File"} <= set(names)
