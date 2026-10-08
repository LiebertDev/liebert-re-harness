"""`scripts/measure_guest.ps1`: the operator measurement script is read-only, and checked statically.

The script is never run here. It is read as text, and, where a PowerShell is installed, parsed
into its AST so that the command names a regex could miss (aliases, dynamic calls) are caught.
It must emit exactly the schema `liebert_re.dynamic.guest_attestation.GuestAttestation` reads.
"""
from __future__ import annotations

import json
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
    "Write-Host",  # the console summary; reads nothing
})
# Functions the script itself defines (checked against the AST, not trusted).
SCRIPT_FUNCTIONS = frozenset({"ErrInfo"})

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
    "foreach ($c in $cmds) { $n = $c.GetCommandName(); if ($null -eq $n) { '<DYNAMIC>' } else { $n } }; "
    "$fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true); "
    "foreach ($f in $fns) { 'FUNC:' + $f.Name }"
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
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        funcs = {ln[5:] for ln in lines if ln.startswith("FUNC:")}
        names = [ln for ln in lines if not ln.startswith("FUNC:")]
        assert funcs == SCRIPT_FUNCTIONS, funcs
        assert names, f"{Path(shell).name} reported no commands"
        assert not any(n.startswith("PARSE_ERRORS:") for n in names), names
        assert "<DYNAMIC>" not in names, "a command with no static name (call operator or variable)"
        extra = set(names) - ALLOWED_COMMANDS - SCRIPT_FUNCTIONS
        assert not extra, f"{Path(shell).name}: {sorted(extra)}"
        # The allowlisted read set is actually used, so an empty-but-passing parse cannot hide.
        assert {"Get-VM", "Invoke-Command", "Out-File", "Write-Host", "ErrInfo"} <= set(names)


def test_network_adapter_calls_are_the_three_read_forms():
    # The allowlist is by cmdlet name; this pins the parameter sets of the one cmdlet used three ways,
    # each read twice (the second reading is the topology consistency check).
    calls = [ln.strip() for ln in _code().splitlines() if "Get-VMNetworkAdapter" in ln]
    assert len(calls) == 6, calls
    flags = sorted(next(f for f in ("-ManagementOS", "-All", "-VMName") if f in c) for c in calls)
    assert flags == ["-All", "-All", "-ManagementOS", "-ManagementOS", "-VMName", "-VMName"]
    assert all("-ErrorAction Stop" in c for c in calls)


def test_schema_is_version_two_and_host_adapters_are_separate():
    code = _code()
    assert GuestAttestation.SCHEMA == "liebert-re.guest-measurement/2"
    assert "$result['host_adapters']" in code
    assert "kind = 'host_management'" in code
    # peers exclude the host's adapters by id (and the IsManagementOs flag), and fail if the host
    # adapters were not measured, instead of writing vm_id: null.
    assert "$hostAdapterIds -contains" in code and "IsManagementOs" in code
    assert "host adapters not measured" in code


def test_every_section_reports_error_category_and_no_message_leaves_errinfo():
    code = _code()
    assert code.count("error_category = $e.category") == 10
    assert code.count("$e = ErrInfo $_") == 10
    start = code.index("function ErrInfo")
    end = code.index("\n}\n", start)
    outside = code[:start] + code[end:]
    # .Message is read only inside ErrInfo (own, fixed "lr:" strings); it is never in a result field.
    assert ".Message" not in outside
    assert "FullyQualifiedErrorId" in code[start:end] and "FullyQualifiedErrorId" not in outside
    assert "ErrorDetails" not in code and "ScriptStackTrace" not in code and "TargetObject" not in code


def test_every_throw_marks_the_script_own_messages():
    throws = re.findall(r"InvalidOperationException\]::new\('([^']*)'", _code())
    assert throws and all(t.startswith("lr:") for t in throws), throws


def test_elevation_warning_precedes_every_measurement():
    code = _code()
    warn = code.index("not elevated: Hyper-V sections will fail")
    assert warn < code.index("$result['host'] = $null")
    assert "-not $result['elevated']" in code[max(0, warn - 120):warn]


_SUMMARY_VARS = {"$name", "$status", "$outName", "$elevatedText"}
_SUMMARY_FORBIDDEN = ("$VMName", "$OutFile", "$machineGuid", "$digest", "$GuestCredential", "identity_sha256",
                      "$env:", "COMPUTERNAME", "UserName", "$vmObj", ".id", ".Id", "vm_id", "switch_id")


def test_console_summary_prints_only_allowed_values():
    lines = [ln[ln.index("Write-Host"):].rstrip(" }") for ln in _code().splitlines() if "Write-Host" in ln]
    assert len(lines) >= 5
    for ln in lines:
        used = set(re.findall(r"\$\w+", ln))
        assert used <= _SUMMARY_VARS, (ln, used - _SUMMARY_VARS)
        assert not [bad for bad in _SUMMARY_FORBIDDEN if bad in ln], ln
    code = _code()
    assert "[System.IO.Path]::GetFileName($OutFile)" in code  # the file NAME, not the path
    assert "$outName = " in code and "$elevatedText = " in code
    # the values the variables carry: name from the section keys, category from error_category only
    assert "$result[$name]['error_category']" in code and "$result[$name]['ok']" in code
    assert code.rstrip().splitlines()[-1].lstrip().startswith("Write-Host ('output: '")


_ERRINFO_PROBE = r"""
$ErrorActionPreference = 'Stop'
$VMName = 'secretvm'
$t = $null; $e = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:MEASURE_GUEST_SCRIPT, [ref]$t, [ref]$e)
$fn = $ast.Find({ param($n) ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and ($n.Name -eq 'ErrInfo') }, $true)
Invoke-Expression $fn.Extent.Text
$out = [ordered]@{}
try { Get-Item -LiteralPath 'C:\no-such-dir-zzz\leaf-zzz.txt' -ErrorAction Stop } catch { $out['cmdlet'] = ErrInfo $_ }
$cat = [System.Management.Automation.ErrorCategory]::PermissionDenied
$out['path_id'] = ErrInfo ([System.Management.Automation.ErrorRecord]::new([System.Exception]::new('msg C:\leak-zzz'), 'C:\leak-zzz\x,Foo', $cat, $null))
$out['vm_id'] = ErrInfo ([System.Management.Automation.ErrorRecord]::new([System.Exception]::new('msg'), 'SecretVM,Foo', $cat, $null))
$out['bare_id'] = ErrInfo ([System.Management.Automation.ErrorRecord]::new([System.Exception]::new('msg'), 'AccessDenied,Foo', $cat, $null))
try { throw [System.InvalidOperationException]::new('lr:vm not resolved') } catch { $out['own'] = ErrInfo $_ }
try { throw [System.InvalidOperationException]::new('cmdlet said C:\leak-zzz') } catch { $out['foreign'] = ErrInfo $_ }
$out | ConvertTo-Json -Depth 4 -Compress
"""


def test_errinfo_reports_category_and_never_a_message(tmp_path):
    shells = _shells()
    if not shells:
        pytest.skip("no pwsh or powershell on PATH: ErrInfo cannot be exercised here")
    probe = tmp_path / "probe.ps1"
    probe.write_text(_ERRINFO_PROBE, encoding="utf-8")
    env = dict(os.environ, MEASURE_GUEST_SCRIPT=str(SCRIPT))
    for shell in shells:
        proc = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                               str(probe)], capture_output=True, text=True, timeout=120, env=env, check=False)
        assert proc.returncode == 0, f"{Path(shell).name}: {proc.stderr.strip()[:200]}"
        out = json.loads(proc.stdout)
        assert out["cmdlet"]["category"] == "ObjectNotFound/PathNotFound"
        assert out["cmdlet"]["error"].startswith("System.") and "zzz" not in out["cmdlet"]["error"]
        assert out["path_id"] == {"error": "System.Exception", "category": "PermissionDenied"}
        assert out["vm_id"] == {"error": "System.Exception", "category": "PermissionDenied"}
        assert out["bare_id"]["category"] == "PermissionDenied/AccessDenied"
        assert out["own"] == {"error": "vm not resolved", "category": "OperationStopped"}
        assert out["foreign"]["error"] == "System.InvalidOperationException"
        assert "zzz" not in proc.stdout and "leak" not in proc.stdout


def test_network_reads_are_taken_twice_and_compared():
    code = _code()
    # first reading + second reading of: own adapters, management adapters, all adapters
    assert code.count("Get-VMSwitch") == 2
    assert "InconsistentMeasurement" in code
    assert "$sigBefore" in code and "$sigAfter" in code
    # the comparison happens after every measurement and before the file is written
    assert code.index("$result['guest'] = $null") < code.index("$sigBefore = @{}") < code.index("ConvertTo-Json")


def test_device_guard_values_are_never_cast_from_null():
    code = _code()
    assert "[int]$dg[0]" not in code, "a bare [int] cast turns a null Device Guard value into 0"
    assert "$null -eq $vbsRaw" in code and "$null -eq $svcRaw" in code
    assert "device guard status null or not numeric" in code


def test_kvp_and_os_build_are_never_cast_from_null():
    code = _code()
    assert "[string]$kvp.VirtualMachineId" not in code and "[string]$os[0].BuildNumber" not in code
    assert "lr:vm id null or empty" in code and "lr:os build null or empty" in code


_DEVICE_GUARD_PROBE = r"""
$ErrorActionPreference = 'Stop'
$t = $null; $e = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:MEASURE_GUEST_SCRIPT, [ref]$t, [ref]$e)
$try = $ast.Find({ param($n) ($n -is [System.Management.Automation.Language.TryStatementAst]) -and ($n.Extent.Text.Contains('Win32_DeviceGuard')) -and (-not $n.Extent.Text.Contains('Win32_OperatingSystem')) }, $true)
if ($null -eq $try) { throw 'device guard try block not found' }
$cases = Get-Content -Raw -LiteralPath $env:MEASURE_GUEST_CASES | ConvertFrom-Json
$results = @()
foreach ($case in $cases) {
    $global:dgRecord = $case
    function Get-CimInstance { param($Namespace, $ClassName, $ErrorAction) $rec = $global:dgRecord; [pscustomobject]@{ VirtualizationBasedSecurityStatus = $rec.status; SecurityServicesRunning = $rec.services } }
    $out = @{ vm_id_from_kvp = $null; os_build = $null; vbs_status = $null; security_services_running = $null; errors = @(); categories = @() }
    Invoke-Expression $try.Extent.Text
    $results += [ordered]@{ status = $out['vbs_status']; services = $out['security_services_running']; errors = @($out['errors']) }
}
ConvertTo-Json -InputObject @($results) -Depth 5 -Compress
"""


def test_device_guard_null_or_invalid_is_an_error_and_null_not_zero(tmp_path):
    shells = _shells()
    if not shells:
        pytest.skip("no pwsh or powershell on PATH: the Device Guard block cannot be exercised here")
    cases = [
        {"status": 2, "services": [1, 2]},      # 0: valid
        {"status": 1, "services": []},          # 1: valid, no services running
        {"status": None, "services": [1]},      # 2: null status
        {"status": 2, "services": None},        # 3: null service list
        {"status": 2, "services": [1, None]},   # 4: null entry
        {"status": "abc", "services": [1]},     # 5: non-numeric status
        {"status": 2, "services": ["x"]},       # 6: non-numeric entry
    ]
    probe = tmp_path / "probe.ps1"
    probe.write_text(_DEVICE_GUARD_PROBE, encoding="utf-8")
    cases_file = tmp_path / "cases.json"
    cases_file.write_text(json.dumps(cases), encoding="utf-8")
    env = dict(os.environ, MEASURE_GUEST_SCRIPT=str(SCRIPT), MEASURE_GUEST_CASES=str(cases_file))
    for shell in shells:
        proc = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                               str(probe)], capture_output=True, text=True, timeout=120, env=env, check=False)
        assert proc.returncode == 0, f"{Path(shell).name}: {proc.stderr.strip()[:300]}"
        out = json.loads(proc.stdout)
        assert out[0]["status"] == 2 and out[0]["services"] == [1, 2] and out[0]["errors"] == []
        assert out[1]["status"] == 1 and out[1]["services"] in ([], None) and out[1]["errors"] == []
        for bad in out[2:]:
            assert bad["status"] is None and bad["services"] is None, bad
            assert bad["errors"] == ["vbs:System.InvalidOperationException"], bad


_TOPOLOGY_PROBE = r"""
$ErrorActionPreference = 'Stop'
$global:vmG = [guid]'11111111-1111-1111-1111-111111111111'
$global:peerG = [guid]'22222222-2222-2222-2222-222222222222'
$global:swA = [guid]'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
$global:swB = [guid]'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
$global:mode = $env:MEASURE_GUEST_MODE
$global:nAdapters = 0; $global:nSwitches = 0; $global:nAll = 0
function Get-VM { param($Name, $ErrorAction) [pscustomobject]@{ VMId = $global:vmG; Name = $Name; State = 'Off'; Generation = 2; AutomaticCheckpointsEnabled = $false; ParentCheckpointId = $null } }
function Get-VMSnapshot { param($VMName, $ErrorAction) }
function Get-VMIntegrationService { param($VMName, $ErrorAction) }
function Get-VMSecurity { param($VMName, $ErrorAction) [pscustomobject]@{ TpmEnabled = $false; Shielded = $false } }
function Get-VMSwitch { param($ErrorAction)
    $global:nSwitches++
    [pscustomobject]@{ Id = $global:swA; Name = 'A'; SwitchType = 'Private' }
    if (($global:mode -eq 'switch_drift') -and ($global:nSwitches -ge 2)) { [pscustomobject]@{ Id = $global:swB; Name = 'B'; SwitchType = 'Private' } }
}
function Get-VMNetworkAdapter { param($VMName, [switch]$All, [switch]$ManagementOS, $ErrorAction)
    if ($ManagementOS) { return }
    if ($All) {
        $global:nAll++
        [pscustomobject]@{ Id = 'own'; VMId = $global:vmG; SwitchId = $global:swA; IsManagementOs = $false }
        if (-not (($global:mode -eq 'peer_drift') -and ($global:nAll -ge 2))) {
            [pscustomobject]@{ Id = 'peer'; VMId = $global:peerG; SwitchId = $global:swA; IsManagementOs = $false }
        }
        return
    }
    $global:nAdapters++
    $sw = $global:swA
    if (($global:mode -eq 'adapter_drift') -and ($global:nAdapters -ge 2)) { $sw = $global:swB }
    [pscustomobject]@{ Id = 'own'; SwitchId = $sw; SwitchName = 'A'; Connected = $true }
}
& $env:MEASURE_GUEST_SCRIPT -VMName 'probevm' -OutFile $env:MEASURE_GUEST_OUT | Out-Null
"""


@pytest.mark.parametrize("mode,bad", [
    ("same", set()),
    ("adapter_drift", {"adapters"}),
    ("switch_drift", {"switches"}),
    ("peer_drift", {"switch_peers"}),
])
def test_topology_that_changes_between_the_two_reads_is_not_ok(tmp_path, mode, bad):
    shells = _shells()
    if not shells:
        pytest.skip("no pwsh or powershell on PATH: the script cannot be run against mocks here")
    probe = tmp_path / "probe.ps1"
    probe.write_text(_TOPOLOGY_PROBE, encoding="utf-8")
    out_file = tmp_path / "out.json"
    env = dict(os.environ, MEASURE_GUEST_SCRIPT=str(SCRIPT), MEASURE_GUEST_OUT=str(out_file), MEASURE_GUEST_MODE=mode)
    proc = subprocess.run([shells[0], "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                           str(probe)], capture_output=True, text=True, timeout=180, env=env, check=False)
    assert proc.returncode == 0, f"{Path(shells[0]).name}: {proc.stderr.strip()[:300]}"
    doc = json.loads(out_file.read_text(encoding="utf-8-sig"))
    for name in ("adapters", "switches", "host_adapters", "switch_peers"):
        section = doc[name]
        if name in bad:
            assert section["ok"] is False and section["error_category"] == "InconsistentMeasurement", (name, section)
            assert section["items"] == []
        else:
            assert section["ok"] is True and section["error"] is None, (name, section)
    peers = [i["vm_id"] for i in doc["switch_peers"]["items"]]
    assert peers == ([] if "switch_peers" in bad else ["22222222-2222-2222-2222-222222222222"])
