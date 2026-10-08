"""Hyper-V guest launcher: the real ``GuestLauncher`` over PowerShell Direct (guest_run, slice 3).

WHAT THIS MODULE IS. The guest side of ``debugger_run``: it starts ONE target in a lab guest suspended,
puts it in a job object, proves the assignment, resumes it, waits to a deadline, kills the job and hands
back bounded output. ``HypervGuestLauncher`` implements the seven methods of
``debugger_run.GuestLauncher`` and, like the rest of this package, never raises: every method returns a
dict, and anything it cannot confirm is ``{"ok": False, "reason": <fixed code>, ...}``.

WHAT IT IS NOT. It has NOT been run against a real guest. Everything below is written from the Win32
documentation and checked by tests that read the script text, parse it, and (on a Windows host with
``powershell.exe``) compile the C#, compare struct sizes, and RUN the agent's watchdog and pipe server
over real named pipes with a stub guard (no target, no job, no guest). Outside the suite the whole agent
was driven once on a development host, not a guest, with benign system binaries; no VM was touched.
``docs/CAPABILITIES_AND_LIMITS.md`` says the same. ``hyperv_transport`` keeps its contract of never
starting a target; this module is the separate capability, and it reuses the transport's PowerShell
Direct plumbing (credential file, runner, PowerShell executable, per-call timeout, bounded process
output, request size limit, strict result parsing) through ``HypervTransport._run_script`` so there is
one place that builds the command line.

HANDLE LIFETIME: A GUEST-RESIDENT AGENT PER RUN. The transport opens and closes a PSSession for every
call, so no handle, job or suspended thread can live in a session. Two designs were weighed:

* Re-open the job by name on every step (``OpenJobObject``). Rejected. A named job object does not
  outlive its last handle, and with ``KILL_ON_JOB_CLOSE`` (which is the point of the job) closing the
  last handle kills the target, so a step that merely closes its handle ends the run. Without that
  flag the kill-if-the-host-dies guarantee is gone. The exit code and the suspended thread also need a
  handle to a process object that nobody is holding between calls, and a bare pid can be reused.
* One small agent process per run in the guest. Chosen. It holds the process, thread and job handles
  and two output pumps for the whole run, and takes one request per PowerShell Direct call over a
  per-run named pipe (current user only). If the agent dies, the job handle closes and
  ``KILL_ON_JOB_CLOSE`` kills the target; an idle timer ends an abandoned agent the same way. The
  agent is a constant PowerShell script plus a constant C# class (``_AGENT_SCRIPT``); the host script
  (``_HOST_SCRIPT``) is also constant. The first call writes the agent into a fresh per-run directory
  next to the pushed sample, checks its SHA-256 BEFORE starting it, and starts it detached
  (``Win32_Process.Create``); each later call only carries one request line to the pipe and one reply
  line back.

A TARGET THAT HOLDS THE AGENT. The target runs under the same account as the operator, so it can open the
agent's pipe. It must not be able to stretch its own life by doing so (connect and send a request, then
never read the reply, so a blocking drain never returns and the job handle is never closed), so the agent
has two independent bounds. Every pipe wait is bounded in C# (``LrServer``): the request read, the reply
write and the wait for the client to close its end each have a fixed millisecond limit, a client that is
silent, trickling or not reading costs those limits and nothing more, and ``WaitForPipeDrain`` (which
blocks for ever on such a client) is not used. And a watchdog thread (``LrWatchdog``) that shares no lock
and no call with the pipe loop kills the job at an absolute time: ``resume`` limits it to the host's longest
allowed wait plus a margin, ``wait`` to that call's deadline plus a margin, and the agent process ends
itself a fixed time after; the times can only move earlier. The agent also refuses a pipe client that is
a member of its own job (the target and its children) and one it cannot place. The first call hands the
agent an absolute lifetime (``lifetime_seconds``) that covers every step the host may take.

WHEN THE AGENT CANNOT BE REACHED OR TRUSTED. The target has the agent's token, so it can also suspend the
agent's threads (the watchdog included) or kill the agent and take over its pipe name. Three host-side rules
do not depend on the agent being alive or honest:

* The job has a random name per run (``liebert-job-<32 hex>`` in the ``Global`` namespace, known to the host and the agent). If
  the agent does not confirm a termination (no reply, a reply that is not valid, a negative answer, or a
  server that is not the agent), the host opens a NEW PowerShell Direct session, opens the job by name
  with terminate and query rights only (``LrHostNative.KillJob``), ends it, and reads the job's own
  accounting until no process is active. That, or an absent job together with a target whose process id AND
  creation time are seen to be gone, is a confirmation (``termination_path`` ``HOST_JOB_KILL``).
* If that does not confirm either, and the target may have run (a ``resume`` was sent), the last resort is
  ``Stop-VM -TurnOff`` from the host (a separate constant script, ``_VM_OFF_SCRIPT``; the transport and the
  host script carry no cmdlet that changes VM state). It counts only when the VM then reads ``Off``, and the
  result says so: ``termination_path`` ``VM_TURNED_OFF`` with a ``termination_reason``. It can be switched
  off (``power_off_fallback=False``). A target that was never resumed (or whose job cannot exist yet) is
  never the reason to power a VM off. When nothing is proven, the run stays unconfirmed
  (``JOB_TERMINATION_NOT_CONFIRMED``).
* Who answers on the pipe is checked before anything is sent. The first call records the agent's process id
  AND creation time the moment it is started; every later call carries them, and the client script in the
  guest asks ``GetNamedPipeServerProcessId`` for the connected pipe and the creation time of that process
  and refuses (``AGENT_IDENTITY_MISMATCH``, never a success) unless both are equal. An unknown or unreadable
  expectation refuses too. ``create`` also reports the target's creation time (``target_created``), kept
  for the check above.

STEPS, host to agent (``create``, ``assign``, ``verify``, ``resume``, ``wait``, ``terminate``,
``collect``), each one PowerShell Direct call:

* ``create_suspended``: ``CreateProcessW`` with ``CREATE_SUSPENDED``, stdout and stderr on two
  anonymous pipes drained by pump threads into two files, each file capped at ``MAX_OUTPUT_CAP`` bytes
  while the pump keeps counting what the target produced.
* ``assign_to_job``: a job with ``KILL_ON_JOB_CLOSE``, an active-process limit, a per-process and a
  per-job memory limit and a CPU-time ceiling, set BEFORE the process is assigned; no breakaway.
* ``verify_job_assignment``: ``IsProcessInJob`` AND the job's own process-id list names the pid
  (``in_job``); the limits are read back with ``QueryInformationJobObject`` and must equal what was
  asked for (``limits_applied``).
* ``resume``: the agent verifies again immediately before ``ResumeThread`` and refuses if either
  check is not true; this module also refuses to send ``resume`` unless the last verify said both.
* ``wait``: ``WaitForSingleObject`` to the deadline; exit code only when the process has exited.
* ``terminate_job``: ``TerminateJobObject`` and ``TerminateProcess``, then confirm the process
  object is signalled and the job's active-process count is zero. Tried twice if the call itself fails.
* ``collect_output``: stdout then stderr, concatenated, at most ``max_bytes``; ``total_bytes`` is what
  the target produced on both streams; refused (``OUTPUT_NOT_FINAL``) unless the pumps have reached
  end of stream.

Strict replies. A PowerShell Direct call returns one ``LIEBERT_RESULT`` line (the transport's rules:
no line, two lines, duplicate key, wrong schema, non-zero exit with ``ok``, truncated output all fail)
whose only payload is the agent's reply as a string. That string is parsed again here: one line, ASCII,
size-bounded, no duplicate keys, no ``NaN``, exactly the keys of the step (a missing or extra key is a
rejection), built-in ``int``/``bool``/``str`` only, the ``run_id`` and ``op`` this call used, and the
pid ``create`` returned. A reply that does not pass is a ``reason`` code, never a guess.

Status mapping stays in ``debugger_run``: a ``verify`` that says ``in_job`` false is
``JOB_ASSIGNMENT_UNCONFIRMED``; ``wait`` with ``exited`` false is ``TIMED_OUT``; ``total_bytes`` above
the cap is ``OUTPUT_TRUNCATED``; an invalid reply, a failed step, or a termination that is not
confirmed is ``TRANSPORT_ERROR`` (cleanup outranks the cause). A ``create_suspended`` failure carries
the ``run_id`` it tried unless the failure proves nothing was made (PowerShell never ran, it failed before
the request was sent, the agent was not reachable, or the agent itself answered that creation failed), so
the orchestrator still sends ``terminate_job`` for a process whose creation reply may have been lost.

LIMITS, stated plainly. The target and the operator share one account in the guest, so the pipe ACL keeps
other accounts out, nothing more, and everything the guest agent reports (exit code, job confirmation,
output) is reported by a process the target could in principle forge or silence; the result labels it
``GUEST_REPORTED`` (``provenance``). Running the target under a separate, non-administrator account is
recommended and is NOT done here (it would change the target's behaviour). The job's name can be opened by
the target, so the limits read back at ``resume`` are the limits only up to ``resume``. The kill rights the
host asks for are terminate and query only; the job-membership refusal stops the target and its children, not a
process the target gets another service to start outside the job. Such a client can occupy the single
pipe instance and delay the host's ``terminate_job`` and ``collect_output`` until the watchdog kills the
job; the host then sees a failed or unconfirmed step (``TRANSPORT_ERROR``), never a success. The gate's
host-pid model for a guest run is still undecided (see ``debugger_run``); this module does not change it.
Handles are
inherited by the target (``bInheritHandles``) with no handle list. The job limits do not stop network
use. The job does not follow a child that escapes it before assignment (none can: the process is
suspended); grandchildren are inside the job. Disk use by the target itself is not limited, only what
the pumps keep. The agent and its files stay in the guest run directory after the run; reverting the
guest is the cleanup. Host-side state (``run_id`` to pid and step) lives in this object only, is not
thread-safe, and is bounded.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid
from collections import OrderedDict
from typing import Any, Mapping

from liebert_re import strict_json
from liebert_re.dynamic.hyperv_transport import (
    HypervTransport,
    _check_guest_path,
    _check_vm,
    _clean_failure,
)

__all__ = ["SCHEMA", "HypervGuestLauncher"]

SCHEMA = "liebert-re.hyperv-guest-launcher/1"
_RESULT_SCHEMA = "liebert-re.hyperv-guest-launcher-result/1"
_AGENT_SCHEMA = "liebert-re.guest-agent/1"

_PHASES = ("decode", "credential", "vm", "session", "session_open", "agent_start", "agent_call", "job_kill",
           "stop")

MAX_OUTPUT_CAP = 1024 * 1024          # the same ceiling debugger_run applies to a caller's cap
MAX_MEMORY_BYTES = 2 * 1024 ** 3      # likewise
MAX_TIMEOUT_S = 600.0                 # likewise; also the CPU-time ceiling written into the job
MAX_TRACKED_RUNS = 64
_RUN_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,47}")
# Phases that come before the request is sent to the agent, and failures that mean PowerShell never ran:
# a ``create`` that failed there cannot have made a process (an agent's idle timer ends any agent that did start).
_PRE_CALL_PHASES = frozenset({"decode", "credential", "vm", "session", "session_open", "agent_start"})
_NEVER_LAUNCHED = frozenset({"REQUEST_TOO_LARGE", "POWERSHELL_UNAVAILABLE", "POWERSHELL_LAUNCH_FAILED"})
_NORMAL_REPLY_CHARS = 4096
_RESULT_OVERHEAD_CHARS = 16_384
_CREATE_CONNECT_S = 60
_STEP_CONNECT_S = 15
_STEP_REPLY_S = 30
_WAIT_REPLY_MARGIN_S = 15
_TERMINATE_ATTEMPTS = 2
_DEFAULT_IDLE_S = 300
_JOB_NAME = re.compile(r"Global\\liebert-job-[0-9a-f]{32}")
# What the host-side kill from a new session can say, and which of those prove the job is gone.
_JOB_STATES = frozenset({"TERMINATED", "ABSENT", "ACTIVE_REMAIN", "OPEN_FAILED", "TERMINATE_FAILED", "QUERY_FAILED"})
TERMINATION_PATHS = ("AGENT", "HOST_JOB_KILL", "VM_TURNED_OFF")
_POWER_OFF_REASON = "AGENT_UNCONFIRMED_AND_HOST_JOB_KILL_UNCONFIRMED"
_MIN_LIFETIME_S = 60                  # the range the agent accepts for its own absolute lifetime
_MAX_LIFETIME_S = 40_000

# --------------------------------------------------------------------------- the host script (a constant)

_COMMON_HEAD = r"""
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string] $RequestB64)
$ErrorActionPreference = 'Stop'
$script:Phase = 'start'
$script:Data = [ordered]@{}
$script:Op = ''
$session = $null

function Say([string] $text) { [Console]::Out.WriteLine($text); [Console]::Out.Flush() }
function Mark([string] $name) { $script:Phase = $name; Say ('LIEBERT_PHASE ' + $name) }
function Fail([string] $code) { throw (New-Object System.InvalidOperationException ('lr:' + $code)) }
function AsciiJson($value) {
    $json = ConvertTo-Json -InputObject $value -Compress -Depth 6
    $eval = [System.Text.RegularExpressions.MatchEvaluator] { param($m) ('\u{0:x4}' -f [int][char] $m.Value) }
    return [regex]::Replace($json, '[^\x00-\x7F]', $eval)
}
function ErrInfo($rec) {
    $cat = $null; $id = $null; $ty = $null; $msg = ''
    try { $cat = $rec.CategoryInfo.Category.ToString() } catch { }
    try { $id = ([string] $rec.FullyQualifiedErrorId).Split(',')[0] } catch { }
    try { $ty = $rec.Exception.GetType().Name } catch { }
    try { $msg = [string] $rec.Exception.Message } catch { }
    $code = $null
    if (($ty -ceq 'InvalidOperationException') -and ($msg -cmatch '^lr:([A-Z0-9_]{1,48})$')) { $code = $Matches[1] }
    $low = $msg.ToLowerInvariant()
    $auth = ($low.Contains('credential is invalid') -or $low.Contains('user name or password is incorrect') -or $low.Contains('access is denied'))
    $tmo = ($low.Contains('timed out') -or $low.Contains('time out') -or $low.Contains('timeout'))
    return [ordered]@{ code = $code; category = $cat; error_id = $id; exception_type = $ty; auth_hint = $auth; timeout_hint = $tmo }
}
function Emit([bool] $ok, $failure) {
    $obj = [ordered]@{ schema = 'liebert-re.hyperv-guest-launcher-result/1'; op = $script:Op; ok = $ok; phase = $script:Phase; failure = $failure; data = $script:Data }
    Say ('LIEBERT_RESULT ' + (AsciiJson $obj))
}

"""

_HOST_SCRIPT = _COMMON_HEAD + r"""
try {
    Mark 'decode'
    $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($RequestB64))
    $req = $json | ConvertFrom-Json
    $script:Op = [string] $req.op

    Mark 'credential'
    $cred = Import-Clixml -LiteralPath ([string] $req.credential_path)
    if ($cred -isnot [System.Management.Automation.PSCredential]) { Fail 'CREDENTIAL_INVALID' }

    Mark 'vm'
    $found = @(Get-VM -ErrorAction Stop | Where-Object { $_.Name -eq [string] $req.vm })
    if ($found.Count -eq 0) { Fail 'VM_NOT_FOUND' }
    if ($found.Count -gt 1) { Fail 'VM_NOT_UNIQUE' }
    $script:Data['vm_state'] = $found[0].State.ToString()
    if ($script:Data['vm_state'] -ne 'Running') { Fail 'VM_NOT_RUNNING' }

    if (($script:Op -ne 'agent_create') -and ($script:Op -ne 'agent_step') -and ($script:Op -ne 'job_kill')) { Fail 'UNKNOWN_OPERATION' }

    # The three blocks below run INSIDE the guest. Each compiles the same small constant native helper first.
    $startBlock = {
        param($targetPath, $runId, $agentText, $configJson, $agentSha, $nativeText)
        if (-not ('LrHostNative' -as [type])) { Add-Type -TypeDefinition $nativeText -Language CSharp }
        $fi = New-Object System.IO.FileInfo ($targetPath)
        if (-not $fi.Exists) { return @{ ok = $false; code = 'TARGET_MISSING' } }
        $bad = (($fi.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
        $cur = $fi.Directory
        while ((-not $bad) -and ($null -ne $cur)) {
            if (($cur.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { $bad = $true }
            $cur = $cur.Parent
        }
        if ($bad) { return @{ ok = $false; code = 'TARGET_PATH_REPARSE' } }
        $runDir = [System.IO.Path]::Combine($fi.DirectoryName, 'liebert-run-' + $runId)
        if ([System.IO.Directory]::Exists($runDir) -or [System.IO.File]::Exists($runDir)) { return @{ ok = $false; code = 'RUN_DIR_EXISTS' } }
        [void] [System.IO.Directory]::CreateDirectory($runDir)
        $agentPath = [System.IO.Path]::Combine($runDir, 'agent.ps1')
        $configPath = [System.IO.Path]::Combine($runDir, 'config.json')
        [System.IO.File]::WriteAllText($agentPath, $agentText, [System.Text.Encoding]::ASCII)
        [System.IO.File]::WriteAllText($configPath, $configJson, [System.Text.Encoding]::ASCII)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $written = ([System.BitConverter]::ToString($sha.ComputeHash([System.IO.File]::ReadAllBytes($agentPath)))).Replace('-', '').ToLowerInvariant()
        if ($written -ne $agentSha) { return @{ ok = $false; code = 'AGENT_SCRIPT_HASH_MISMATCH' } }
        $cmd = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $agentPath + '"'
        $made = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd; CurrentDirectory = $runDir }
        if ([int] $made.ReturnValue -ne 0) { return @{ ok = $false; code = 'AGENT_START_FAILED' } }
        # who the agent is, taken the moment it exists: its process id AND its creation time (an id alone can be reused)
        $agentPid = [int64] $made.ProcessId
        $agentCreated = [int64] [LrHostNative]::Created([uint32] $agentPid)
        if (($agentPid -le 0) -or ($agentCreated -le 0)) { return @{ ok = $false; code = 'AGENT_IDENTITY_UNKNOWN' } }
        return @{ ok = $true; code = $null; agent_pid = $agentPid; agent_created = $agentCreated }
    }
    $callBlock = {
        param($pipeName, $requestJson, $connectMs, $replyMs, $maxChars, $expectedPid, $expectedCreated, $nativeText)
        if (-not ('LrHostNative' -as [type])) { Add-Type -TypeDefinition $nativeText -Language CSharp }
        $client = New-Object System.IO.Pipes.NamedPipeClientStream ('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
        try {
            try { $client.Connect([int] $connectMs) } catch { return @{ ok = $false; code = 'AGENT_NOT_REACHABLE' } }
            # Before anything is sent: is the process that answers on this pipe the agent that was started?
            $serverPid = [int64] [LrHostNative]::ServerPid($client)
            $serverCreated = [int64] -1
            if ($serverPid -gt 0) { $serverCreated = [int64] [LrHostNative]::Created([uint32] $serverPid) }
            if (([int64] $expectedPid -le 0) -or ([int64] $expectedCreated -le 0) -or ($serverPid -ne [int64] $expectedPid) -or ($serverCreated -ne [int64] $expectedCreated)) {
                return @{ ok = $false; code = 'AGENT_IDENTITY_MISMATCH' }
            }
            $out = [System.Text.Encoding]::ASCII.GetBytes($requestJson + "`n")
            $client.Write($out, 0, $out.Length)
            $client.Flush()
            $text = New-Object System.Text.StringBuilder
            $buf = New-Object byte[] 65536
            $deadline = [DateTime]::UtcNow.AddMilliseconds([double] $replyMs)
            while ($true) {
                $left = ($deadline - [DateTime]::UtcNow).TotalMilliseconds
                if ($left -le 0) { return @{ ok = $false; code = 'AGENT_REPLY_TIMEOUT' } }
                $task = $client.ReadAsync($buf, 0, $buf.Length)
                if (-not $task.Wait([int] [Math]::Min($left, 2000000000.0))) { return @{ ok = $false; code = 'AGENT_REPLY_TIMEOUT' } }
                $got = [int] $task.Result
                if ($got -le 0) { break }
                [void] $text.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $got))
                if ($text.Length -gt [int] $maxChars) { return @{ ok = $false; code = 'AGENT_REPLY_TOO_LARGE' } }
                if ($text.ToString().IndexOf("`n") -ge 0) { break }
            }
            return @{ ok = $true; code = $null; reply = $text.ToString() }
        }
        finally { $client.Dispose() }
    }
    $killBlock = {
        param($jobName, $targetPid, $targetCreated, $nativeText)
        if (-not ('LrHostNative' -as [type])) { Add-Type -TypeDefinition $nativeText -Language CSharp }
        $state = [string] [LrHostNative]::KillJob([string] $jobName)
        $alive = $null
        if (([int64] $targetPid -gt 0) -and ([int64] $targetCreated -gt 0)) {
            $alive = ([int64] [LrHostNative]::Created([uint32] $targetPid) -eq [int64] $targetCreated)
        }
        return @{ state = $state; alive = $alive }
    }

    Mark 'session'
    $session = New-PSSession -VMId $found[0].VMId -Credential $cred -ErrorAction Stop
    Mark 'session_open'
    $nativeText = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'native.cs'), [System.Text.Encoding]::ASCII)

    if ($script:Op -eq 'job_kill') {
        # From a session of its own, with nothing from the agent: open the run's job by its name and end it.
        Mark 'job_kill'
        $killed = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList @([string] $req.job_name, [int64] $req.target_pid, [int64] $req.target_created, $nativeText) -ScriptBlock $killBlock
        $script:Data['job_state'] = [string] $killed.state
        $script:Data['target_alive'] = $killed.alive
        Emit $true $null
        exit 0
    }

    $expectedPid = [int64] $req.agent_pid
    $expectedCreated = [int64] $req.agent_created
    if ($script:Op -eq 'agent_create') {
        Mark 'agent_start'
        $agentText = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'agent.ps1'), [System.Text.Encoding]::ASCII)
        $started = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList @([string] $req.target_path, [string] $req.agent_run_id, $agentText, [string] $req.config_json, [string] $req.agent_sha256, $nativeText) -ScriptBlock $startBlock
        if ($started.ok -and ($null -ne $started.agent_pid)) {
            $script:Data['agent_pid'] = [int64] $started.agent_pid
            $script:Data['agent_created'] = [int64] $started.agent_created
        }
        if (-not $started.ok) { Fail ([string] $started.code) }
        $expectedPid = [int64] $started.agent_pid
        $expectedCreated = [int64] $started.agent_created
    }

    Mark 'agent_call'
    $call = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList @([string] $req.pipe_name, [string] $req.agent_request_json, [int] $req.connect_timeout_ms, [int] $req.reply_timeout_ms, [int] $req.max_reply_chars, $expectedPid, $expectedCreated, $nativeText) -ScriptBlock $callBlock
    if (-not $call.ok) { Fail ([string] $call.code) }
    $script:Data['reply'] = [string] $call.reply

    Emit $true $null
    exit 0
}
catch {
    Emit $false (ErrInfo $_)
    exit 1
}
finally {
    if ($null -ne $session) { try { Remove-PSSession -Session $session -ErrorAction Stop } catch { } }
}
"""

_HOST_NATIVE_CS = r"""
using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading;

public static class LrHostNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct ACCOUNTING
    {
        public long TotalUserTime; public long TotalKernelTime; public long ThisPeriodTotalUserTime; public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount; public uint TotalProcesses; public uint ActiveProcesses; public uint TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr process, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenJobObjectW(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, ref ACCOUNTING info, uint size, out uint returned);

    // The process id of the server end of a connected client pipe, or -1.
    public static long ServerPid(NamedPipeClientStream client)
    {
        uint pid;
        if (!GetNamedPipeServerProcessId(client.SafePipeHandle.DangerousGetHandle(), out pid)) { return -1; }
        return (long)pid;
    }

    // The creation time (FILETIME ticks) of a process, or -1 when it cannot be read or does not exist.
    public static long Created(uint pid)
    {
        IntPtr handle = OpenProcess(0x1000, false, pid);
        if (handle == IntPtr.Zero) { return -1; }
        try
        {
            long created, exited, kernel, user;
            if (!GetProcessTimes(handle, out created, out exited, out kernel, out user)) { return -1; }
            return created;
        }
        finally { CloseHandle(handle); }
    }

    private static uint Active(IntPtr job)
    {
        ACCOUNTING info = new ACCOUNTING();
        uint returned;
        if (!QueryInformationJobObject(job, 1, ref info, (uint)Marshal.SizeOf(typeof(ACCOUNTING)), out returned)) { return 0xFFFFFFFF; }
        return info.ActiveProcesses;
    }

    // Open the named job (terminate + query rights only), end it, and read its accounting until no process
    // is left. ABSENT (error 2) means no handle to the job exists any more.
    public static string KillJob(string name)
    {
        IntPtr job = OpenJobObjectW(0x000C, false, name);
        if (job == IntPtr.Zero) { return Marshal.GetLastWin32Error() == 2 ? "ABSENT" : "OPEN_FAILED"; }
        try
        {
            if (!TerminateJobObject(job, 1)) { return "TERMINATE_FAILED"; }
            for (int i = 0; i < 100; i++)
            {
                uint active = Active(job);
                if (active == 0) { return "TERMINATED"; }
                if (active == 0xFFFFFFFF) { return "QUERY_FAILED"; }
                Thread.Sleep(100);
            }
            return "ACTIVE_REMAIN";
        }
        finally { CloseHandle(job); }
    }
}
"""

# The last resort: power the lab guest off from the Hyper-V host. A separate constant script, so that the
# host script (and the transport) never carry a cmdlet that changes VM state.
_VM_OFF_SCRIPT = _COMMON_HEAD + r"""
try {
    Mark 'decode'
    $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($RequestB64))
    $req = $json | ConvertFrom-Json
    $script:Op = [string] $req.op
    if ($script:Op -ne 'vm_off') { Fail 'UNKNOWN_OPERATION' }

    Mark 'vm'
    $found = @(Get-VM -ErrorAction Stop | Where-Object { $_.Name -eq [string] $req.vm })
    if ($found.Count -eq 0) { Fail 'VM_NOT_FOUND' }
    if ($found.Count -gt 1) { Fail 'VM_NOT_UNIQUE' }
    $id = $found[0].Id

    Mark 'stop'
    Stop-VM -VM $found[0] -TurnOff -Force -ErrorAction Stop
    $after = @(Get-VM -ErrorAction Stop | Where-Object { $_.Id -eq $id })
    if ($after.Count -ne 1) { Fail 'VM_NOT_FOUND' }
    $script:Data['vm_state'] = $after[0].State.ToString()
    if ($script:Data['vm_state'] -ne 'Off') { Fail 'VM_NOT_OFF' }

    Emit $true $null
    exit 0
}
catch {
    Emit $false (ErrInfo $_)
    exit 1
}
"""

# --------------------------------------------------------------------------- the guest agent (a constant)

_AGENT_SCRIPT = r"""
# Liebert guest agent: holds ONE suspended target, its job object and its output pumps for one run.
# Written into a fresh per-run directory by the launcher's first call, hash-checked before it starts.
# It reads config.json from its own directory, serves one request per pipe connection, and exits after
# `collect`, after an idle timeout, or after a failed `create`. Not verified on a live guest.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'

$source = @'
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

public sealed class LrFail : Exception
{
    public readonly string Code;
    public readonly int Win32;
    public LrFail(string code, int win32) : base("lr:" + code) { Code = code; Win32 = win32; }
}

public static class LrNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb; public IntPtr lpReserved; public IntPtr lpDesktop; public IntPtr lpTitle;
        public int dwX; public int dwY; public int dwXSize; public int dwYSize;
        public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags;
        public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2;
        public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit;
        public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS
    {
        public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount;
        public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation; public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    {
        public long TotalUserTime; public long TotalKernelTime; public long ThisPeriodTotalUserTime; public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount; public uint TotalProcesses; public uint ActiveProcesses; public uint TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessW(string lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, ref SECURITY_ATTRIBUTES lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetInformationJobObject(IntPtr hJob, int jobObjectInfoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool QueryInformationJobObject(IntPtr hJob, int jobObjectInfoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength, out uint lpReturnLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsProcessInJob(IntPtr hProcess, IntPtr hJob, out bool result);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CancelIoEx(IntPtr hFile, IntPtr lpOverlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetProcessTimes(IntPtr hProcess, out long created, out long exited, out long kernel, out long user);
}

// Limit() moves the moment the target is killed EARLIER, never later, and the moment this process
// kills itself follows it. The loop runs on its own thread and shares no lock and no blocking call with
// the pipe server, so a blocked pipe call can delay nothing here.
public sealed class LrWatchdog
{
    private readonly object _gate = new object();
    private readonly Action _kill;
    private readonly Action _exit;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private long _killAt = long.MaxValue;
    private long _exitAt;
    private bool _killed;
    private bool _stopped;

    public LrWatchdog(Action kill, Action exit, long exitAfterMs)
    {
        if (kill == null || exit == null) { throw new ArgumentNullException("kill"); }
        if (exitAfterMs <= 0) { throw new ArgumentOutOfRangeException("exitAfterMs"); }
        _kill = kill;
        _exit = exit;
        _exitAt = exitAfterMs;
        Thread thread = new Thread(Loop);
        thread.IsBackground = true;
        thread.Start();
    }

    public bool Killed { get { lock (_gate) { return _killed; } } }

    public void Limit(long killAfterMs, long exitGraceMs)
    {
        if (killAfterMs < 0 || exitGraceMs < 0) { throw new ArgumentOutOfRangeException("killAfterMs"); }
        lock (_gate)
        {
            long kill = _clock.ElapsedMilliseconds + killAfterMs;
            if (kill < _killAt) { _killAt = kill; }
            long exit = _killAt + exitGraceMs;
            if (exit < _exitAt) { _exitAt = exit; }
            Monitor.PulseAll(_gate);
        }
    }

    public void Stop()
    {
        lock (_gate) { _stopped = true; Monitor.PulseAll(_gate); }
    }

    private void Loop()
    {
        while (true)
        {
            bool doKill = false;
            bool doExit = false;
            lock (_gate)
            {
                if (_stopped) { return; }
                long now = _clock.ElapsedMilliseconds;
                if (now >= _exitAt) { doExit = true; }
                else if (!_killed && now >= _killAt) { _killed = true; doKill = true; }
                else
                {
                    long next = _killed ? _exitAt : Math.Min(_killAt, _exitAt);
                    long wait = Math.Min(next - now, 60000L);
                    Monitor.Wait(_gate, (int)Math.Max(1L, wait));
                    continue;
                }
            }
            if (doKill) { try { _kill(); } catch (Exception) { } }
            if (doExit)
            {
                try { _kill(); } catch (Exception) { }
                try { _exit(); } catch (Exception) { }
                return;
            }
        }
    }
}

public interface LrClientGuard { bool Allows(int clientPid); }

// One pipe instance, one client at a time, and every wait has a bound: a silent client, a slow writer
// and a client that never reads the reply each cost a fixed number of milliseconds, not the process.
public sealed class LrServer : IDisposable
{
    private const int MaxRequest = 4096;
    private readonly NamedPipeServerStream _pipe;
    private readonly int _readMs;
    private readonly int _writeMs;
    private readonly int _drainMs;
    private Task _pending;
    public LrClientGuard Guard;
    public bool IdledOut;
    public int Rejected;
    public string LastError = "";

    public LrServer(string name, int readMs, int writeMs, int drainMs)
    {
        _readMs = readMs;
        _writeMs = writeMs;
        _drainMs = drainMs;
        PipeSecurity acl = new PipeSecurity();
        acl.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User, PipeAccessRights.FullControl, AccessControlType.Allow));
        _pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 65536, 65536, acl);
    }

    // Ends the connection. An I/O call left pending (a read that timed out, a write the client never
    // drains) is cancelled and finished FIRST: disconnecting under it makes its late failure mark the
    // pipe broken after the next client has connected, and the pipe then refuses every later client.
    private void Drop()
    {
        Task pending = _pending;
        _pending = null;
        if (pending != null && !pending.IsCompleted)
        {
            try { LrNative.CancelIoEx(_pipe.SafePipeHandle.DangerousGetHandle(), IntPtr.Zero); } catch (Exception) { }
            try { pending.Wait(1000); } catch (Exception) { }
        }
        try { _pipe.Disconnect(); }
        catch (Exception ex) { LastError += "[drop:" + ex.GetType().Name + "]"; }
    }

    // The request line of the next admitted client, or null (idle: IdledOut is set; anything else:
    // nothing was admitted and the connection is already dropped).
    public string Accept(int idleMs)
    {
        IdledOut = false;
        try
        {
            IAsyncResult waiting = _pipe.BeginWaitForConnection(null, null);
            if (!waiting.AsyncWaitHandle.WaitOne(idleMs)) { IdledOut = true; return null; }
            _pipe.EndWaitForConnection(waiting);
        }
        catch (Exception ex)
        {
            LastError = "accept:" + ex.GetType().Name + ":" + ex.Message;
            Drop();
            Thread.Sleep(50);
            return null;
        }
        try
        {
            LrClientGuard guard = Guard;
            if (guard != null)
            {
                uint client;
                if (!LrNative.GetNamedPipeClientProcessId(_pipe.SafePipeHandle.DangerousGetHandle(), out client) || !guard.Allows((int)client))
                {
                    Rejected++;
                    Drop();
                    return null;
                }
            }
            string line = ReadLine();
            if (line == null) { Drop(); }
            return line;
        }
        catch (Exception ex)
        {
            LastError = "read:" + ex.GetType().Name + ":" + ex.Message;
            Drop();
            return null;
        }
    }

    private string ReadLine()
    {
        byte[] buffer = new byte[MaxRequest];
        int used = 0;
        Stopwatch clock = Stopwatch.StartNew();
        while (used < buffer.Length)
        {
            long left = _readMs - clock.ElapsedMilliseconds;
            if (left <= 0) { return null; }
            Task<int> read = _pipe.ReadAsync(buffer, used, buffer.Length - used);
            _pending = read;
            if (!read.Wait((int)left)) { return null; }
            _pending = null;
            if (read.Result <= 0) { return null; }
            used += read.Result;
            int end = Array.IndexOf(buffer, (byte)10, 0, used);
            if (end >= 0) { return Encoding.ASCII.GetString(buffer, 0, end); }
        }
        return null;
    }

    // True only when the reply was written and the client then closed its end (that is how a client
    // shows it has read it). Always drops the connection.
    public bool Reply(string line)
    {
        bool delivered = false;
        try
        {
            byte[] bytes = Encoding.ASCII.GetBytes(line + "\n");
            Task write = _pipe.WriteAsync(bytes, 0, bytes.Length);
            _pending = write;
            if (write.Wait(_writeMs))
            {
                byte[] one = new byte[1];
                Task<int> closed = _pipe.ReadAsync(one, 0, 1);
                _pending = closed;
                delivered = closed.Wait(_drainMs) && closed.Result == 0;
            }
        }
        catch (Exception) { delivered = false; }
        Drop();
        return delivered;
    }

    public void Dispose()
    {
        try { _pipe.Dispose(); } catch (Exception) { }
    }
}

public sealed class LrPump
{
    private readonly FileStream _in;
    private readonly FileStream _out;
    private readonly long _cap;
    private readonly Thread _thread;
    private long _total;
    private long _kept;
    private int _failed;

    public LrPump(IntPtr readHandle, string path, long cap)
    {
        _cap = cap;
        SafeFileHandle owned = new SafeFileHandle(readHandle, true);
        try
        {
            _out = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            _in = new FileStream(owned, FileAccess.Read, 4096, false);
        }
        catch
        {
            owned.Dispose();
            if (_out != null) { _out.Dispose(); }
            throw;
        }
        _thread = new Thread(Loop);
        _thread.IsBackground = true;
        _thread.Start();
    }

    private void Loop()
    {
        byte[] buf = new byte[8192];
        try
        {
            while (true)
            {
                int n = _in.Read(buf, 0, buf.Length);
                if (n <= 0) { break; }
                long room = _cap - Interlocked.Read(ref _kept);
                if (room > 0)
                {
                    int w = (int)Math.Min((long)n, room);
                    _out.Write(buf, 0, w);
                    Interlocked.Add(ref _kept, (long)w);
                }
                Interlocked.Add(ref _total, (long)n);
            }
        }
        catch (IOException) { Interlocked.Exchange(ref _failed, 1); }
        catch (ObjectDisposedException) { Interlocked.Exchange(ref _failed, 1); }
        finally
        {
            try { _out.Flush(); } catch (IOException) { Interlocked.Exchange(ref _failed, 1); }
            _out.Dispose();
            _in.Dispose();
        }
    }

    public long Total { get { return Interlocked.Read(ref _total); } }
    public long Kept { get { return Interlocked.Read(ref _kept); } }
    public bool Failed { get { return Interlocked.CompareExchange(ref _failed, 0, 0) != 0; } }
    public bool Finish(int ms) { return _thread.Join(ms); }
}

public sealed class LrRun : IDisposable, LrClientGuard
{
    public const uint ActiveProcessLimit = 8;
    public const long CpuSeconds = 600;
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004;
    private const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    private const uint JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
    private const uint JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200;
    private const uint JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800;
    private const uint JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const uint WantedFlags = JOB_OBJECT_LIMIT_JOB_TIME | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    private const uint ForbiddenFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;

    private readonly object _handleGate = new object();
    private static LrRun _current;
    private IntPtr _process = IntPtr.Zero;
    private IntPtr _thread = IntPtr.Zero;
    private IntPtr _job = IntPtr.Zero;
    private LrPump _outPump;
    private LrPump _errPump;
    private long _memory;
    public int Pid;
    public long Created;
    public bool InJob;
    public bool LimitsApplied;
    public long ExitCode;

    private static LrFail Fail(string code) { return new LrFail(code, Marshal.GetLastWin32Error()); }

    public static string LayoutReport()
    {
        return "STARTUPINFO=" + Marshal.SizeOf(typeof(LrNative.STARTUPINFO))
            + ";PROCESS_INFORMATION=" + Marshal.SizeOf(typeof(LrNative.PROCESS_INFORMATION))
            + ";JOBOBJECT_BASIC_LIMIT_INFORMATION=" + Marshal.SizeOf(typeof(LrNative.JOBOBJECT_BASIC_LIMIT_INFORMATION))
            + ";JOBOBJECT_EXTENDED_LIMIT_INFORMATION=" + Marshal.SizeOf(typeof(LrNative.JOBOBJECT_EXTENDED_LIMIT_INFORMATION))
            + ";JOBOBJECT_BASIC_ACCOUNTING_INFORMATION=" + Marshal.SizeOf(typeof(LrNative.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION))
            + ";SECURITY_ATTRIBUTES=" + Marshal.SizeOf(typeof(LrNative.SECURITY_ATTRIBUTES))
            + ";IntPtr=" + IntPtr.Size;
    }

    public static bool LayoutOk()
    {
        return IntPtr.Size == 8
            && Marshal.SizeOf(typeof(LrNative.STARTUPINFO)) == 104
            && Marshal.SizeOf(typeof(LrNative.PROCESS_INFORMATION)) == 24
            && Marshal.SizeOf(typeof(LrNative.JOBOBJECT_BASIC_LIMIT_INFORMATION)) == 64
            && Marshal.SizeOf(typeof(LrNative.JOBOBJECT_EXTENDED_LIMIT_INFORMATION)) == 144
            && Marshal.SizeOf(typeof(LrNative.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)) == 48
            && Marshal.SizeOf(typeof(LrNative.SECURITY_ATTRIBUTES)) == 24;
    }

    public static LrRun Create(string exe, string workDir, string outPath, string errPath, long cap)
    {
        IntPtr outRead = IntPtr.Zero, outWrite = IntPtr.Zero, errRead = IntPtr.Zero, errWrite = IntPtr.Zero, nul = IntPtr.Zero;
        LrRun run = new LrRun();
        try
        {
            LrNative.SECURITY_ATTRIBUTES sa = new LrNative.SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(typeof(LrNative.SECURITY_ATTRIBUTES));
            sa.bInheritHandle = 1;
            if (!LrNative.CreatePipe(out outRead, out outWrite, ref sa, 0)) { throw Fail("PIPE_FAILED"); }
            if (!LrNative.CreatePipe(out errRead, out errWrite, ref sa, 0)) { throw Fail("PIPE_FAILED"); }
            if (!LrNative.SetHandleInformation(outRead, 1, 0)) { throw Fail("PIPE_FAILED"); }
            if (!LrNative.SetHandleInformation(errRead, 1, 0)) { throw Fail("PIPE_FAILED"); }
            nul = LrNative.CreateFileW("NUL", 0x80000000, 3, ref sa, 3, 0, IntPtr.Zero);
            if (nul == new IntPtr(-1)) { nul = IntPtr.Zero; throw Fail("NUL_FAILED"); }
            LrNative.STARTUPINFO si = new LrNative.STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(LrNative.STARTUPINFO));
            si.dwFlags = (int)STARTF_USESTDHANDLES;
            si.hStdInput = nul;
            si.hStdOutput = outWrite;
            si.hStdError = errWrite;
            StringBuilder cmd = new StringBuilder("\"" + exe + "\"");
            LrNative.PROCESS_INFORMATION pi;
            if (!LrNative.CreateProcessW(exe, cmd, IntPtr.Zero, IntPtr.Zero, true, CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, workDir, ref si, out pi))
            {
                throw Fail("CREATE_PROCESS_FAILED");
            }
            run._process = pi.hProcess;
            run._thread = pi.hThread;
            run.Pid = pi.dwProcessId;
            long exited, kernel, user;
            if (!LrNative.GetProcessTimes(pi.hProcess, out run.Created, out exited, out kernel, out user)) { throw Fail("PROCESS_TIMES_FAILED"); }
            LrNative.CloseHandle(outWrite); outWrite = IntPtr.Zero;
            LrNative.CloseHandle(errWrite); errWrite = IntPtr.Zero;
            LrNative.CloseHandle(nul); nul = IntPtr.Zero;
            IntPtr takenOut = outRead; outRead = IntPtr.Zero;
            run._outPump = new LrPump(takenOut, outPath, cap);
            IntPtr takenErr = errRead; errRead = IntPtr.Zero;
            run._errPump = new LrPump(takenErr, errPath, cap);
            _current = run;
            return run;
        }
        catch
        {
            if (run._process != IntPtr.Zero) { LrNative.TerminateProcess(run._process, 1); }
            run.Dispose();
            throw;
        }
        finally
        {
            if (outRead != IntPtr.Zero) { LrNative.CloseHandle(outRead); }
            if (outWrite != IntPtr.Zero) { LrNative.CloseHandle(outWrite); }
            if (errRead != IntPtr.Zero) { LrNative.CloseHandle(errRead); }
            if (errWrite != IntPtr.Zero) { LrNative.CloseHandle(errWrite); }
            if (nul != IntPtr.Zero) { LrNative.CloseHandle(nul); }
        }
    }

    // The job has a name of its own, known to the host, so that the host can end it from a new session if
    // this agent stops answering. A job that already exists under that name is not ours: refused.
    public void AssignToJob(long memoryBytes, string jobName)
    {
        if (_job != IntPtr.Zero) { throw new LrFail("JOB_ALREADY_CREATED", 0); }
        if (memoryBytes <= 0) { throw new LrFail("MEMORY_LIMIT_INVALID", 0); }
        if (String.IsNullOrEmpty(jobName)) { throw new LrFail("JOB_NAME_INVALID", 0); }
        IntPtr job = LrNative.CreateJobObjectW(IntPtr.Zero, jobName);
        int created = Marshal.GetLastWin32Error();
        if (job == IntPtr.Zero) { throw new LrFail("CREATE_JOB_FAILED", created); }
        if (created == 183) { LrNative.CloseHandle(job); throw new LrFail("JOB_NAME_EXISTS", created); }
        _job = job;
        _memory = memoryBytes;
        LrNative.JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new LrNative.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = WantedFlags;
        info.BasicLimitInformation.ActiveProcessLimit = ActiveProcessLimit;
        info.BasicLimitInformation.PerJobUserTimeLimit = CpuSeconds * 10000000L;
        info.ProcessMemoryLimit = new UIntPtr((ulong)memoryBytes);
        info.JobMemoryLimit = new UIntPtr((ulong)memoryBytes);
        int size = Marshal.SizeOf(typeof(LrNative.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(info, buffer, false);
            if (!LrNative.SetInformationJobObject(_job, 9, buffer, (uint)size)) { throw Fail("SET_LIMITS_FAILED"); }
        }
        finally { Marshal.FreeHGlobal(buffer); }
        if (!LrNative.AssignProcessToJobObject(_job, _process)) { throw Fail("ASSIGN_FAILED"); }
    }

    public void Verify()
    {
        InJob = false;
        LimitsApplied = false;
        if (_job == IntPtr.Zero || _memory <= 0) { return; }
        bool member;
        if (!LrNative.IsProcessInJob(_process, _job, out member)) { throw Fail("IS_PROCESS_IN_JOB_FAILED"); }
        bool listed = false;
        int listBytes = 8 + IntPtr.Size * 64;
        IntPtr listBuffer = Marshal.AllocHGlobal(listBytes);
        try
        {
            uint returned;
            if (!LrNative.QueryInformationJobObject(_job, 3, listBuffer, (uint)listBytes, out returned)) { throw Fail("QUERY_PROCESS_LIST_FAILED"); }
            int count = Marshal.ReadInt32(listBuffer, 4);
            if (count > 64) { count = 64; }
            for (int i = 0; i < count; i++)
            {
                long id = IntPtr.Size == 8 ? Marshal.ReadInt64(listBuffer, 8 + i * 8) : (long)Marshal.ReadInt32(listBuffer, 8 + i * 4);
                if (id == (long)Pid) { listed = true; }
            }
        }
        finally { Marshal.FreeHGlobal(listBuffer); }
        InJob = member && listed;
        int size = Marshal.SizeOf(typeof(LrNative.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr limitBuffer = Marshal.AllocHGlobal(size);
        try
        {
            uint returned;
            if (!LrNative.QueryInformationJobObject(_job, 9, limitBuffer, (uint)size, out returned)) { throw Fail("QUERY_LIMITS_FAILED"); }
            LrNative.JOBOBJECT_EXTENDED_LIMIT_INFORMATION read = (LrNative.JOBOBJECT_EXTENDED_LIMIT_INFORMATION)Marshal.PtrToStructure(limitBuffer, typeof(LrNative.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            uint flags = read.BasicLimitInformation.LimitFlags;
            LimitsApplied = (flags & WantedFlags) == WantedFlags
                && (flags & ForbiddenFlags) == 0
                && read.BasicLimitInformation.ActiveProcessLimit == ActiveProcessLimit
                && read.BasicLimitInformation.PerJobUserTimeLimit == CpuSeconds * 10000000L
                && read.ProcessMemoryLimit.ToUInt64() == (ulong)_memory
                && read.JobMemoryLimit.ToUInt64() == (ulong)_memory;
        }
        finally { Marshal.FreeHGlobal(limitBuffer); }
    }

    public int Resume()
    {
        Verify();
        if (!(InJob && LimitsApplied)) { throw new LrFail("NOT_VERIFIED_AT_RESUME", 0); }
        uint previous = LrNative.ResumeThread(_thread);
        if (previous == 0xFFFFFFFF) { throw Fail("RESUME_FAILED"); }
        return (int)previous;
    }

    public bool WaitExit(uint milliseconds)
    {
        uint r = LrNative.WaitForSingleObject(_process, milliseconds);
        if (r == 0)
        {
            uint code;
            if (!LrNative.GetExitCodeProcess(_process, out code)) { throw Fail("EXIT_CODE_FAILED"); }
            ExitCode = (long)code;
            return true;
        }
        if (r == 0x102) { return false; }
        throw Fail("WAIT_FAILED");
    }

    private uint ActiveProcesses()
    {
        int size = Marshal.SizeOf(typeof(LrNative.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            uint returned;
            if (!LrNative.QueryInformationJobObject(_job, 1, buffer, (uint)size, out returned)) { return 0xFFFFFFFF; }
            LrNative.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acct = (LrNative.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)Marshal.PtrToStructure(buffer, typeof(LrNative.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
            return acct.ActiveProcesses;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public bool Terminate()
    {
        if (_job != IntPtr.Zero) { LrNative.TerminateJobObject(_job, 1); }
        LrNative.TerminateProcess(_process, 1);
        if (LrNative.WaitForSingleObject(_process, 10000) != 0) { return false; }
        if (_job == IntPtr.Zero) { return true; }
        for (int i = 0; i < 100; i++)
        {
            if (ActiveProcesses() == 0) { return true; }
            Thread.Sleep(100);
        }
        return false;
    }

    public bool FinishPumps(int ms) { return _outPump.Finish(ms) && _errPump.Finish(ms); }
    public bool PumpFailed { get { return _outPump.Failed || _errPump.Failed; } }
    public long StdoutTotal { get { return _outPump.Total; } }
    public long StderrTotal { get { return _errPump.Total; } }

    public static byte[] Combine(string first, string second, int max)
    {
        byte[] a = File.ReadAllBytes(first);
        byte[] b = File.ReadAllBytes(second);
        int n = (int)Math.Min((long)max, (long)a.Length + (long)b.Length);
        byte[] result = new byte[n];
        int fromA = Math.Min(a.Length, n);
        Buffer.BlockCopy(a, 0, result, 0, fromA);
        Buffer.BlockCopy(b, 0, result, fromA, n - fromA);
        return result;
    }

    // Called from the watchdog thread: no wait, no confirmation, only the two kill calls.
    public void HardKill()
    {
        lock (_handleGate)
        {
            if (_job != IntPtr.Zero) { LrNative.TerminateJobObject(_job, 1); }
            if (_process != IntPtr.Zero) { LrNative.TerminateProcess(_process, 1); }
        }
    }

    // The target and everything it starts is in the job once the job exists (no breakaway), so a pipe
    // client inside the job is the target or its child. It is refused. A client that cannot be placed is
    // refused too. Before the job exists nothing runs, so nothing is refused.
    public bool Allows(int clientPid)
    {
        lock (_handleGate)
        {
            if (_job == IntPtr.Zero || _process == IntPtr.Zero) { return true; }
            if (clientPid <= 0 || clientPid == Pid) { return false; }
            IntPtr client = LrNative.OpenProcess(0x1000, false, (uint)clientPid);
            if (client == IntPtr.Zero) { return false; }
            try
            {
                bool inJob;
                if (!LrNative.IsProcessInJob(client, _job, out inJob)) { return false; }
                return !inJob;
            }
            finally { LrNative.CloseHandle(client); }
        }
    }

    public static void KillCurrent()
    {
        LrRun run = _current;
        if (run != null) { run.HardKill(); }
    }

    public static void ExitSelf()
    {
        LrNative.TerminateProcess(LrNative.GetCurrentProcess(), 3);
    }

    public static LrWatchdog StartWatchdog(long lifetimeMs)
    {
        return new LrWatchdog(KillCurrent, ExitSelf, lifetimeMs);
    }

    public void Dispose()
    {
        lock (_handleGate)
        {
            if (_thread != IntPtr.Zero) { LrNative.CloseHandle(_thread); _thread = IntPtr.Zero; }
            if (_process != IntPtr.Zero) { LrNative.CloseHandle(_process); _process = IntPtr.Zero; }
            if (_job != IntPtr.Zero) { LrNative.CloseHandle(_job); _job = IntPtr.Zero; }
        }
    }
}
'@
Add-Type -TypeDefinition $source -Language CSharp

$Schema = 'liebert-re.guest-agent/1'
$cfg = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'config.json'), [System.Text.Encoding]::ASCII) | ConvertFrom-Json
$RunId = [string] $cfg.run_id
if ($RunId -cnotmatch '^[A-Za-z0-9_-]{1,64}$') { exit 2 }
$TargetPath = [string] $cfg.target_path
$Cap = [int64] $cfg.output_cap
$IdleMs = [int] ([int64] $cfg.idle_seconds * 1000)
$LifetimeMs = [int64] $cfg.lifetime_seconds * 1000
$JobName = [string] $cfg.job_name
if ($JobName -cnotmatch '^Global\\liebert-job-[0-9a-f]{32}$') { exit 2 }
if (($IdleMs -lt 10000) -or ($IdleMs -gt 3600000) -or ($Cap -lt 1) -or ($Cap -gt 1048576)) { exit 2 }
if (($LifetimeMs -lt 60000) -or ($LifetimeMs -gt 40000000)) { exit 2 }
# After `resume` the target runs for at most the host's longest allowed wait plus a margin; `wait` narrows it
# to that call's own deadline plus the margin. Past that the watchdog thread kills the job whatever the pipe
# loop is doing, and the agent process ends a fixed time after.
$RunCeilingMs = [int64] 630000
$KillGraceMs = [int64] 30000
$ExitGraceMs = [int64] 600000
$PipeName = 'liebert-run-' + $RunId
$RunDir = $PSScriptRoot
$OutFile = Join-Path $RunDir 'stdout.bin'
$ErrFile = Join-Path $RunDir 'stderr.bin'
$script:Run = $null
$script:State = 'new'
$script:Memory = [int64] 0
$script:IdleMs = $IdleMs
$script:Dog = $null

function ToJson($value) { return (ConvertTo-Json -InputObject $value -Compress -Depth 4) }
function Fail([string] $code) { throw (New-Object System.InvalidOperationException ('lr:' + $code)) }
function CodeOf($ex) {
    $e = $ex
    for ($i = 0; ($i -lt 5) -and ($null -ne $e); $i++) {
        if ($e -is [LrFail]) { return @($e.Code, [int] $e.Win32) }
        if (([string] $e.Message) -cmatch '^lr:([A-Z0-9_]{1,48})$') { return @($Matches[1], 0) }
        $e = $e.InnerException
    }
    return @('AGENT_INTERNAL_ERROR', 0)
}
function OkReply([string] $op, $fields) {
    $o = [ordered]@{ schema = $Schema; op = $op; ok = $true; run_id = $RunId; pid = [int] $script:Run.Pid }
    foreach ($k in $fields.Keys) { $o[$k] = $fields[$k] }
    return $o
}
function RunOp([string] $op, $req) {
    if ($op -ceq 'create') {
        if ($script:State -cne 'new') { Fail 'BAD_STATE' }
        if (-not [LrRun]::LayoutOk()) { Fail 'LAYOUT_MISMATCH' }
        $script:Run = [LrRun]::Create($TargetPath, [System.IO.Path]::GetDirectoryName($TargetPath), $OutFile, $ErrFile, $Cap)
        $script:Server.Guard = $script:Run
        $script:State = 'created'
        return (OkReply 'create' @{ suspended = $true; target_created = [int64] $script:Run.Created })
    }
    if ($null -eq $script:Run) { Fail 'NO_PROCESS' }
    if ($op -ceq 'assign') {
        if ($script:State -cne 'created') { Fail 'BAD_STATE' }
        $mem = [int64] $req.memory_bytes
        if (($mem -lt 1) -or ($mem -gt 2147483648)) { Fail 'MEMORY_LIMIT_INVALID' }
        $script:Run.AssignToJob($mem, $JobName)
        $script:Memory = $mem
        $script:State = 'assigned'
        return (OkReply 'assign' @{ assigned = $true })
    }
    if ($op -ceq 'verify') {
        if (($script:State -cne 'assigned') -and ($script:State -cne 'verified')) { Fail 'BAD_STATE' }
        $script:Run.Verify()
        $inJob = [bool] $script:Run.InJob
        $limits = [bool] $script:Run.LimitsApplied
        if ($inJob -and $limits) { $script:State = 'verified' }
        return (OkReply 'verify' @{ in_job = $inJob; limits_applied = $limits })
    }
    if ($op -ceq 'resume') {
        if ($script:State -cne 'verified') { Fail 'BAD_STATE' }
        $script:Dog.Limit($RunCeilingMs, $ExitGraceMs)
        $previous = [int] $script:Run.Resume()
        $script:State = 'resumed'
        return (OkReply 'resume' @{ resumed = ($previous -eq 1); previous_suspend_count = $previous })
    }
    if ($op -ceq 'wait') {
        if ($script:State -cne 'resumed') { Fail 'BAD_STATE' }
        $ms = [int64] $req.timeout_ms
        if (($ms -lt 1) -or ($ms -gt 615000)) { Fail 'TIMEOUT_INVALID' }
        $script:Dog.Limit($ms + $KillGraceMs, $ExitGraceMs)
        $exited = [bool] $script:Run.WaitExit([uint32] $ms)
        $code = $null
        if ($exited) { $code = [int64] $script:Run.ExitCode }
        return (OkReply 'wait' @{ exited = $exited; exit_code = $code })
    }
    if ($op -ceq 'terminate') {
        $done = [bool] $script:Run.Terminate()
        if ($done) { $script:State = 'terminated'; $script:IdleMs = [Math]::Min($IdleMs, 120000) }
        return (OkReply 'terminate' @{ terminated = $done })
    }
    if ($op -ceq 'collect') {
        if ($script:State -cne 'terminated') { Fail 'NOT_TERMINATED' }
        $max = [int64] $req.max_bytes
        if (($max -lt 1) -or ($max -gt 1048576)) { Fail 'MAX_BYTES_INVALID' }
        if (-not $script:Run.FinishPumps(5000)) { Fail 'OUTPUT_NOT_FINAL' }
        if ($script:Run.PumpFailed) { Fail 'OUTPUT_PUMP_FAILED' }
        $data = [LrRun]::Combine($OutFile, $ErrFile, [int] $max)
        $outTotal = [int64] $script:Run.StdoutTotal
        $errTotal = [int64] $script:Run.StderrTotal
        return (OkReply 'collect' @{ total_bytes = ($outTotal + $errTotal); kept_bytes = [int64] $data.Length; stdout_total = $outTotal; stderr_total = $errTotal; data_b64 = [System.Convert]::ToBase64String($data) })
    }
    Fail 'BAD_OP'
}
function Dispatch([string] $text) {
    $op = 'unknown'
    try {
        $req = $text | ConvertFrom-Json
        $candidate = [string] $req.op
        if ($candidate -cnotin @('create', 'assign', 'verify', 'resume', 'wait', 'terminate', 'collect')) { Fail 'BAD_OP' }
        $op = $candidate
        if (([string] $req.run_id) -cne $RunId) { Fail 'RUN_ID_MISMATCH' }
        $body = RunOp $op $req
        return @{ json = (ToJson $body); final = ($op -ceq 'collect') }
    }
    catch {
        $c = CodeOf $_.Exception
        $win32 = $null
        if ([int] $c[1] -ne 0) { $win32 = [int] $c[1] }
        $o = [ordered]@{ schema = $Schema; op = $op; ok = $false; run_id = $RunId; code = [string] $c[0]; win32_error = $win32 }
        return @{ json = (ToJson $o); final = (($op -ceq 'create') -and ($script:State -ceq 'new')) }
    }
}
$script:Server = $null
try {
    $script:Dog = [LrRun]::StartWatchdog($LifetimeMs)
    $script:Server = New-Object LrServer ($PipeName, 5000, 10000, 5000)
    $finished = $false
    while (-not $finished) {
        $text = $script:Server.Accept($script:IdleMs)
        if ($script:Server.IdledOut) { break }
        if ($null -eq $text) { continue }
        try {
            $answer = Dispatch $text
            [void] $script:Server.Reply([string] $answer.json)
            if ($answer.final) { $finished = $true }
        }
        catch { }
    }
}
finally {
    if ($null -ne $script:Run) {
        try { [void] $script:Run.Terminate() } catch { }
        try { $script:Run.Dispose() } catch { }
    }
    if ($null -ne $script:Server) { try { $script:Server.Dispose() } catch { } }
    if ($null -ne $script:Dog) { try { $script:Dog.Stop() } catch { } }
}
"""


def _wire_bytes(text: str) -> bytes:
    """The bytes a constant script has on disk: ASCII, CRLF line ends (as ``_run_script`` writes them)."""
    return text.replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii")


def _agent_sha256() -> str:
    """SHA-256 of the agent script exactly as it is written on the host and then in the guest."""
    return hashlib.sha256(_wire_bytes(_AGENT_SCRIPT)).hexdigest()


def _host_script_sha256() -> str:
    return hashlib.sha256(_HOST_SCRIPT.encode("ascii")).hexdigest()


# --------------------------------------------------------------------------- strict agent replies


def _is_pid(value: object) -> bool:
    return type(value) is int and 0 < value <= 0xFFFFFFFF


def _is_count(value: object) -> bool:
    return type(value) is int and 0 <= value <= 2 ** 53


def _is_bool(value: object) -> bool:
    return type(value) is bool


def _is_exit_code(value: object) -> bool:
    return value is None or (type(value) is int and 0 <= value <= 0xFFFFFFFF)


def _is_text(value: object) -> bool:
    return type(value) is str


def _is_filetime(value: object) -> bool:
    return type(value) is int and 0 < value < 2 ** 63


_OK_FIELDS: dict[str, dict[str, Any]] = {
    "create": {"pid": _is_pid, "suspended": _is_bool, "target_created": _is_filetime},
    "assign": {"pid": _is_pid, "assigned": _is_bool},
    "verify": {"pid": _is_pid, "in_job": _is_bool, "limits_applied": _is_bool},
    "resume": {"pid": _is_pid, "resumed": _is_bool, "previous_suspend_count": _is_count},
    "wait": {"pid": _is_pid, "exited": _is_bool, "exit_code": _is_exit_code},
    "terminate": {"pid": _is_pid, "terminated": _is_bool},
    "collect": {"pid": _is_pid, "total_bytes": _is_count, "kept_bytes": _is_count, "stdout_total": _is_count,
                "stderr_total": _is_count, "data_b64": _is_text},
}
_COMMON_KEYS = frozenset({"schema", "op", "ok", "run_id"})
_FAILURE_KEYS = _COMMON_KEYS | {"code", "win32_error"}


def _parse_agent_reply(text: object, op: str, run_id: str, pid: int | None, max_chars: int,
                       ) -> tuple[dict[str, Any] | None, str | None]:
    """``(reply, None)`` or ``(None, reason)``. One ASCII line, bounded, exactly the keys of the step."""
    if type(text) is not str or not text.strip():
        return None, "AGENT_REPLY_EMPTY"
    if len(text) > max_chars:
        return None, "AGENT_REPLY_TOO_LARGE"
    if not text.isascii():
        return None, "AGENT_REPLY_NOT_ASCII"
    line = text.rstrip("\r\n")
    if "\n" in line or "\r" in line:
        return None, "AGENT_REPLY_NOT_ONE_LINE"
    try:
        body = strict_json.loads(line)
    except strict_json.StrictJSONError as exc:
        if exc.reason == strict_json.DUPLICATE_KEY:
            return None, "AGENT_REPLY_DUPLICATE_KEY"
        return None, "AGENT_REPLY_NOT_JSON"
    if type(body) is not dict or body.get("schema") != _AGENT_SCHEMA:
        return None, "AGENT_REPLY_SCHEMA_MISMATCH"
    if body.get("op") != op or type(body.get("op")) is not str:
        return None, "AGENT_REPLY_OPERATION_MISMATCH"
    if type(body.get("run_id")) is not str or body["run_id"] != run_id:
        return None, "AGENT_REPLY_RUN_MISMATCH"
    if type(body.get("ok")) is not bool:
        return None, "AGENT_REPLY_MALFORMED"
    if body["ok"] is False:
        code, win32 = body.get("code"), body.get("win32_error")
        if (set(body) != _FAILURE_KEYS or type(code) is not str or _CODE.fullmatch(code) is None
                or not (win32 is None or (type(win32) is int and 0 <= win32 <= 0xFFFFFFFF))):
            return None, "AGENT_REPLY_MALFORMED"
        return body, None
    spec = _OK_FIELDS[op]
    if set(body) != _COMMON_KEYS | set(spec):
        return None, "AGENT_REPLY_KEYS_MISMATCH"
    for key, check in spec.items():
        if not check(body[key]):
            return None, "AGENT_REPLY_MALFORMED"
    if pid is not None and body["pid"] != pid:
        return None, "AGENT_REPLY_PID_MISMATCH"
    return body, None


# --------------------------------------------------------------------------- the launcher


class _Run:
    __slots__ = ("vm", "pid", "state", "memory_bytes", "in_job", "limits_applied", "terminated", "agent_pid",
                 "agent_created", "target_created", "job_name", "assign_attempted", "resume_attempted")

    def __init__(self, vm: str) -> None:
        self.vm = vm
        self.agent_pid: int | None = None          # who the agent is: process id AND creation time, taken at start
        self.agent_created: int | None = None
        self.target_created: int | None = None
        self.job_name = f"Global\\liebert-job-{uuid.uuid4().hex}"
        self.assign_attempted = False              # a job may exist (the reply to assign may have been lost)
        self.resume_attempted = False              # the target may be running (the reply to resume may have been lost)
        self.pid: int | None = None
        self.state = "creating"
        self.memory_bytes: int | None = None
        self.in_job = False
        self.limits_applied = False
        self.terminated = False


def _refusal(reason: str, **more: Any) -> dict[str, Any]:
    return {"ok": False, "reason": reason, **more}


class HypervGuestLauncher:
    """``debugger_run.GuestLauncher`` over PowerShell Direct, using a ``HypervTransport`` for the plumbing.

    ``transport`` supplies the credential file, the runner, the PowerShell executable and the default
    per-call timeout; this object never reads or prints the credential path. ``step_timeout_s`` is the
    wall-clock bound of one PowerShell Direct call (default: the transport's probe timeout, at least
    120 s; ``create_suspended`` gets twice that, ``wait`` gets the deadline added). ``idle_seconds`` is
    how long an agent waits for the next request before it kills its job and exits.
    """

    def __init__(self, transport: HypervTransport, *, step_timeout_s: float | None = None,
                 idle_seconds: int = _DEFAULT_IDLE_S, power_off_fallback: bool = True) -> None:
        if not isinstance(transport, HypervTransport):
            raise TypeError("transport must be a HypervTransport")
        if type(power_off_fallback) is not bool:
            raise ValueError("power_off_fallback must be a bool")
        if type(idle_seconds) is not int or not 10 <= idle_seconds <= 3600:
            raise ValueError("idle_seconds must be an int in [10, 3600]")
        default_step = max(float(getattr(transport, "_probe_timeout_s", 90.0)), 120.0)
        step = default_step if step_timeout_s is None else step_timeout_s
        if isinstance(step, bool) or not isinstance(step, (int, float)) or not 0 < step <= 3600:
            raise ValueError("step_timeout_s must be a number of seconds in (0, 3600]")
        self._transport = transport
        self._step_timeout_s = float(step)
        self._idle_seconds = idle_seconds
        self._power_off_fallback = power_off_fallback
        self._runs: OrderedDict[str, _Run] = OrderedDict()

    def __repr__(self) -> str:  # the credential path is not printed
        return "HypervGuestLauncher(transport=<REDACTED>)"

    def _lifetime_seconds(self) -> int:
        """The agent's absolute lifetime, whatever the pipe or the host does: the longest the host may spend on
        one run (create and terminate each get a second try or twice the step bound, five more steps, the
        longest wait with its margin), rounded up. A run that needs longer than this is killed by the agent,
        which the host sees as an unconfirmed result, never as a success."""
        worst = 9 * self._step_timeout_s + MAX_TIMEOUT_S + _WAIT_REPLY_MARGIN_S
        return max(_MIN_LIFETIME_S, min(_MAX_LIFETIME_S, int(worst) + 1))

    # ---- one PowerShell Direct call, one agent request

    def _exchange(self, run_id: str, run: _Run, op: str, fields: Mapping[str, Any], *, create_target: str | None,
                  connect_s: int, reply_s: float, host_timeout_s: float, reply_chars: int,
                  ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """``(validated agent reply, None)`` or ``(None, refusal)``. A refusal is what the caller returns."""
        agent_request = json.dumps({"op": op, "run_id": run_id, **fields}, separators=(",", ":"), ensure_ascii=True)
        extra: dict[str, Any] = {
            "agent_run_id": run_id, "pipe_name": f"liebert-run-{run_id}", "agent_request_json": agent_request,
            "connect_timeout_ms": int(connect_s * 1000), "reply_timeout_ms": int(reply_s * 1000),
            "max_reply_chars": reply_chars,
        }
        files: dict[str, str] = {"native.cs": _HOST_NATIVE_CS}
        script_op = "agent_step"
        if create_target is not None:
            script_op = "agent_create"
            files["agent.ps1"] = _AGENT_SCRIPT
            extra.update(
                target_path=create_target, agent_sha256=_agent_sha256(),
                config_json=json.dumps({"run_id": run_id, "target_path": create_target, "output_cap": MAX_OUTPUT_CAP,
                                        "idle_seconds": self._idle_seconds,
                                        "lifetime_seconds": self._lifetime_seconds(),
                                        "job_name": run.job_name}, separators=(",", ":")),
            )
        else:
            if run.agent_pid is None or run.agent_created is None:   # nobody to talk to: the agent was never identified
                return None, _refusal("AGENT_IDENTITY_UNKNOWN", error_class="UNKNOWN", last_phase=None, _may_exist=True)
            extra.update(agent_pid=run.agent_pid, agent_created=run.agent_created)
        phases, body, failure = self._transport._run_script(
            script_op, run.vm, extra, host_timeout_s, script=_HOST_SCRIPT, script_name="launcher.ps1",
            result_schema=_RESULT_SCHEMA, known_phases=_PHASES, extra_files=files,
            max_output_chars=reply_chars + _RESULT_OVERHEAD_CHARS)
        last = phases[-1] if phases else None
        if failure is not None:
            may_exist = not (failure[1] in _NEVER_LAUNCHED or last in _PRE_CALL_PHASES)
            return None, _refusal(failure[1] if _CODE.fullmatch(failure[1]) else "TRANSPORT_FAILURE",
                                  error_class=failure[0], last_phase=last, _may_exist=may_exist)
        assert body is not None
        if create_target is not None:
            self._note_identity(run, body.get("data"))      # kept even from a failed start: the agent may be running
        if body["ok"] is False:
            error_class, reason = self._transport._failure_of(body)
            cleaned = _clean_failure(body.get("failure"))
            if cleaned is not None and cleaned["code"] is not None:
                reason = cleaned["code"]
            may_exist = not (body.get("phase") in _PRE_CALL_PHASES or reason == "AGENT_NOT_REACHABLE")
            return None, _refusal(reason, error_class=error_class, last_phase=body.get("phase"), _may_exist=may_exist)
        data = body["data"]
        keys = set(data)
        shape_ok = keys == {"vm_state", "reply"} or (
            create_target is not None and keys == {"vm_state", "reply", "agent_pid", "agent_created"})
        if not shape_ok or data.get("vm_state") != "Running":
            return None, _refusal("LAUNCHER_RESULT_DATA_UNEXPECTED", error_class="UNKNOWN", last_phase=last,
                                  _may_exist=True)
        if create_target is not None and (run.agent_pid is None or run.agent_created is None):
            return None, _refusal("AGENT_IDENTITY_UNKNOWN", error_class="UNKNOWN", last_phase=last, _may_exist=True)
        reply, problem = _parse_agent_reply(data.get("reply"), op, run_id, run.pid, reply_chars)
        if reply is None:
            return None, _refusal(problem or "AGENT_REPLY_INVALID", error_class="UNKNOWN", last_phase=last,
                                  _may_exist=True)
        if reply["ok"] is False:       # the agent answered: a failed create left nothing (it kills what it made)
            return None, _refusal("AGENT_" + reply["code"], error_class="UNKNOWN", last_phase=last,
                                  win32_error=reply["win32_error"], _may_exist=False)
        return reply, None

    @staticmethod
    def _note_identity(run: _Run, data: object) -> None:
        """Remember who the agent is, once, from the script's own data (process id and creation time)."""
        if run.agent_pid is not None or not isinstance(data, dict):
            return
        pid, created = data.get("agent_pid"), data.get("agent_created")
        if _is_pid(pid) and _is_filetime(created):
            run.agent_pid, run.agent_created = pid, created

    def _known(self, vm: object, run_id: object, states: tuple[str, ...]) -> _Run | dict[str, Any]:
        """The run record for this step, or the refusal that stops it before any guest call."""
        if type(run_id) is not str or _RUN_ID.fullmatch(run_id) is None or run_id not in self._runs:
            return _refusal("RUN_UNKNOWN")
        run = self._runs[run_id]
        if vm != run.vm:
            return _refusal("VM_MISMATCH", run_id=run_id)
        if run.state not in states:
            return _refusal("STEP_OUT_OF_ORDER", run_id=run_id)
        return run

    def _guard(self, name: str, *args: Any) -> dict[str, Any]:
        try:
            return getattr(self, name)(*args)
        except Exception:  # noqa: BLE001 - the protocol says no method raises; a bug is a refusal
            return _refusal("LAUNCHER_INTERNAL_ERROR")

    # ---- GuestLauncher

    def create_suspended(self, vm: str, guest_path: str) -> dict[str, Any]:
        return self._guard("_create", vm, guest_path)

    def assign_to_job(self, vm: str, run_id: str, limits: Mapping[str, Any]) -> dict[str, Any]:
        return self._guard("_assign", vm, run_id, limits)

    def verify_job_assignment(self, vm: str, run_id: str) -> dict[str, Any]:
        return self._guard("_verify", vm, run_id)

    def resume(self, vm: str, run_id: str) -> dict[str, Any]:
        return self._guard("_resume", vm, run_id)

    def wait(self, vm: str, run_id: str, timeout_s: float) -> dict[str, Any]:
        return self._guard("_wait", vm, run_id, timeout_s)

    def terminate_job(self, vm: str, run_id: str) -> dict[str, Any]:
        return self._guard("_terminate", vm, run_id)

    def collect_output(self, vm: str, run_id: str, max_bytes: int) -> dict[str, Any]:
        return self._guard("_collect", vm, run_id, max_bytes)

    # ---- steps

    def _step(self, run_id: str, run: _Run, op: str, fields: Mapping[str, Any], *, reply_s: float = _STEP_REPLY_S,
              host_extra_s: float = 0.0, reply_chars: int = _NORMAL_REPLY_CHARS,
              ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        reply, refusal = self._exchange(
            run_id, run, op, fields, create_target=None, connect_s=_STEP_CONNECT_S, reply_s=reply_s,
            host_timeout_s=self._step_timeout_s + host_extra_s, reply_chars=reply_chars)
        if refusal is not None:
            refusal.pop("_may_exist", None)
            return None, {**refusal, "run_id": run_id, **({"pid": run.pid} if run.pid is not None else {})}
        return reply, None

    def _create(self, vm: str, guest_path: str) -> dict[str, Any]:
        if _check_vm(vm) is not None:
            return _refusal("VM_NAME_REJECTED")
        path, problem = _check_guest_path(guest_path, directory=False)
        if path is None:
            return _refusal(problem or "GUEST_PATH_REJECTED")
        if len(self._runs) >= MAX_TRACKED_RUNS:
            for old_id in [k for k, r in self._runs.items() if r.terminated]:
                del self._runs[old_id]
                break
            if len(self._runs) >= MAX_TRACKED_RUNS:
                return _refusal("TOO_MANY_RUNS_IN_FLIGHT")
        run_id = uuid.uuid4().hex[:16]
        run = _Run(vm)
        self._runs[run_id] = run          # recorded BEFORE the call, so a lost reply can still be terminated
        reply, refusal = self._exchange(
            run_id, run, "create", {}, create_target=path, connect_s=_CREATE_CONNECT_S, reply_s=_STEP_REPLY_S,
            host_timeout_s=self._step_timeout_s * 2, reply_chars=_NORMAL_REPLY_CHARS)
        if refusal is not None:
            if refusal.pop("_may_exist", True) is False:
                del self._runs[run_id]        # provably nothing was made: there is nothing to terminate
                return refusal
            return {**refusal, "run_id": run_id}   # it may exist: the orchestrator must still send terminate_job
        assert reply is not None
        if reply["suspended"] is not True:
            return _refusal("AGENT_REPORTED_NOT_SUSPENDED", run_id=run_id)
        run.pid, run.state, run.target_created = reply["pid"], "created", reply["target_created"]
        return {"ok": True, "run_id": run_id, "pid": run.pid, "suspended": True}

    def _assign(self, vm: str, run_id: str, limits: Mapping[str, Any]) -> dict[str, Any]:
        run = self._known(vm, run_id, ("created",))
        if isinstance(run, dict):
            return run
        memory = limits.get("memory_bytes") if isinstance(limits, Mapping) else None
        if type(memory) is not int or not 0 < memory <= MAX_MEMORY_BYTES:
            return _refusal("MEMORY_LIMIT_OUT_OF_RANGE", run_id=run_id)
        run.assign_attempted = True                    # from here a job may exist, whatever the reply says
        reply, refusal = self._step(run_id, run, "assign", {"memory_bytes": memory})
        if refusal is not None:
            return refusal
        assert reply is not None
        if reply["assigned"] is not True:
            return _refusal("AGENT_REPORTED_NOT_ASSIGNED", run_id=run_id, pid=run.pid)
        run.state, run.memory_bytes = "assigned", memory
        return {"ok": True, "run_id": run_id, "pid": run.pid}

    def _verify(self, vm: str, run_id: str) -> dict[str, Any]:
        run = self._known(vm, run_id, ("assigned", "verified"))
        if isinstance(run, dict):
            return run
        reply, refusal = self._step(run_id, run, "verify", {})
        if refusal is not None:
            return refusal
        assert reply is not None
        run.in_job, run.limits_applied = reply["in_job"], reply["limits_applied"]
        run.state = "verified" if (run.in_job and run.limits_applied) else "assigned"
        return {"ok": True, "run_id": run_id, "pid": run.pid, "in_job": run.in_job,
                "limits_applied": run.limits_applied}

    def _resume(self, vm: str, run_id: str) -> dict[str, Any]:
        run = self._known(vm, run_id, ("verified",))   # only after a verify that said both true
        if isinstance(run, dict):
            return run
        run.resume_attempted = True                    # from here the target may be running, whatever the reply says
        reply, refusal = self._step(run_id, run, "resume", {})
        if refusal is not None:
            return refusal
        assert reply is not None
        if reply["resumed"] != (reply["previous_suspend_count"] == 1):
            return _refusal("AGENT_RESUME_REPLY_INCONSISTENT", run_id=run_id, pid=run.pid)
        run.state = "resumed"                          # the thread may be running now, resumed or not
        return {"ok": True, "run_id": run_id, "pid": run.pid, "resumed": reply["resumed"]}

    def _wait(self, vm: str, run_id: str, timeout_s: float) -> dict[str, Any]:
        run = self._known(vm, run_id, ("resumed",))
        if isinstance(run, dict):
            return run
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or not 0 < timeout_s <= MAX_TIMEOUT_S:
            return _refusal("TIMEOUT_OUT_OF_RANGE", run_id=run_id)
        milliseconds = max(1, int(timeout_s * 1000 + 0.999))
        reply, refusal = self._step(run_id, run, "wait", {"timeout_ms": milliseconds},
                                    reply_s=timeout_s + _WAIT_REPLY_MARGIN_S,
                                    host_extra_s=timeout_s + _WAIT_REPLY_MARGIN_S)
        if refusal is not None:
            return refusal
        assert reply is not None
        if reply["exited"] != (reply["exit_code"] is not None):
            return _refusal("AGENT_WAIT_REPLY_INCONSISTENT", run_id=run_id, pid=run.pid)
        return {"ok": True, "run_id": run_id, "pid": run.pid, "exited": reply["exited"],
                "exit_code": reply["exit_code"]}

    def _terminate(self, vm: str, run_id: str) -> dict[str, Any]:
        run = self._known(vm, run_id, ("creating", "created", "assigned", "verified", "resumed", "terminated"))
        if isinstance(run, dict):
            return run
        last: dict[str, Any] = _refusal("TERMINATE_NOT_ATTEMPTED", run_id=run_id)
        if run.agent_pid is None:
            last = _refusal("AGENT_IDENTITY_UNKNOWN", run_id=run_id)   # no agent is known: only the host's ways remain
        else:
            for _ in range(_TERMINATE_ATTEMPTS):       # a failed call is retried; a negative answer is not
                reply, refusal = self._step(run_id, run, "terminate", {})
                if refusal is not None:
                    last = refusal
                    continue
                assert reply is not None
                if reply["terminated"] is not True:
                    last = _refusal("AGENT_TERMINATION_NOT_CONFIRMED", run_id=run_id, pid=reply["pid"], terminated=False)
                    break
                run.terminated, run.state = True, "terminated"
                run.pid = run.pid if run.pid is not None else reply["pid"]
                return {"ok": True, "run_id": run_id, "pid": reply["pid"], "terminated": True,
                        "termination_path": "AGENT"}
        # The agent did not confirm: it may be frozen, gone or replaced. Nothing it says is needed from here.
        backup = self._terminate_from_outside(vm, run_id, run)
        return backup if backup is not None else last

    def _terminate_from_outside(self, vm: str, run_id: str, run: _Run) -> dict[str, Any] | None:
        """End the run without the agent: the named job from a new session, then (only for a target that may
        have run, and only if allowed) the VM itself. A confirmation is a fact the host read, not a reply."""
        if not run.assign_attempted:
            return None                                # no job exists yet; the target was never resumed
        state, alive = self._job_kill(vm, run)
        proven = (state == "TERMINATED" and alive is not True) or (
            state == "ABSENT" and alive is False)      # an absent job proves nothing unless the target is seen gone
        if proven:
            path, reason = "HOST_JOB_KILL", None
        elif run.resume_attempted and self._power_off_fallback and self._vm_off(vm):
            path, reason = "VM_TURNED_OFF", _POWER_OFF_REASON
        else:
            return None
        run.terminated, run.state = True, "terminated"
        done: dict[str, Any] = {"ok": True, "run_id": run_id, "pid": run.pid, "terminated": True,
                                "termination_path": path}
        if reason is not None:
            done["termination_reason"] = reason
        return done

    def _job_kill(self, vm: str, run: _Run) -> tuple[str | None, bool | None]:
        """``(job state, target still alive)`` read from a session of its own, or ``(None, None)``."""
        extra = {"job_name": run.job_name, "target_pid": run.pid or 0, "target_created": run.target_created or 0}
        _, body, failure = self._transport._run_script(
            "job_kill", vm, extra, self._step_timeout_s, script=_HOST_SCRIPT, script_name="launcher.ps1",
            result_schema=_RESULT_SCHEMA, known_phases=_PHASES, extra_files={"native.cs": _HOST_NATIVE_CS},
            max_output_chars=_RESULT_OVERHEAD_CHARS)
        if failure is not None or body is None or body["ok"] is not True:
            return None, None
        data = body["data"]
        state, alive = data.get("job_state"), data.get("target_alive")
        if (set(data) != {"vm_state", "job_state", "target_alive"} or data.get("vm_state") != "Running"
                or type(state) is not str or state not in _JOB_STATES or not (alive is None or type(alive) is bool)):
            return None, None
        return state, alive

    def _vm_off(self, vm: str) -> bool:
        """Stop-VM -TurnOff through the transport's plumbing; True only when the VM reads ``Off`` afterwards."""
        _, body, failure = self._transport._run_script(
            "vm_off", vm, {}, self._step_timeout_s, script=_VM_OFF_SCRIPT, script_name="vmoff.ps1",
            result_schema=_RESULT_SCHEMA, known_phases=_PHASES, max_output_chars=_RESULT_OVERHEAD_CHARS)
        return (failure is None and body is not None and body["ok"] is True
                and body["data"] == {"vm_state": "Off"})

    def _collect(self, vm: str, run_id: str, max_bytes: int) -> dict[str, Any]:
        run = self._known(vm, run_id, ("terminated",))  # output is final only after the job is gone
        if isinstance(run, dict):
            return run
        if type(max_bytes) is not int or not 0 < max_bytes <= MAX_OUTPUT_CAP:
            return _refusal("OUTPUT_CAP_OUT_OF_RANGE", run_id=run_id)
        reply, refusal = self._step(run_id, run, "collect", {"max_bytes": max_bytes},
                                    reply_chars=4 * ((max_bytes + 2) // 3) + _NORMAL_REPLY_CHARS)
        if refusal is not None:
            return refusal
        assert reply is not None
        try:
            data = base64.b64decode(reply["data_b64"], validate=True)
        except (binascii.Error, ValueError):
            return _refusal("AGENT_OUTPUT_NOT_BASE64", run_id=run_id, pid=run.pid)
        total = reply["total_bytes"]
        if (len(data) != reply["kept_bytes"] or len(data) > max_bytes or total != reply["stdout_total"] + reply["stderr_total"]
                or total < len(data)):
            return _refusal("AGENT_OUTPUT_COUNTS_INCONSISTENT", run_id=run_id, pid=run.pid)
        self._runs.pop(run_id, None)
        return {"ok": True, "run_id": run_id, "pid": run.pid, "data": data, "total_bytes": total,
                "stdout_total": reply["stdout_total"], "stderr_total": reply["stderr_total"]}
