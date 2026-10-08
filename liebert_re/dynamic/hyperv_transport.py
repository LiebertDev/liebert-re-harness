"""Hyper-V guest transport: PowerShell Direct session, file push and pull, hash-verified.

This is the TRANSPORT layer of a future guest-run pipeline and nothing else. It opens a PowerShell
Direct session to a running guest, copies one host file in, or copies a host-chosen list of guest
files out, and proves each copy by SHA-256. It never starts a target, never starts a debugger, never
creates, restores or deletes a checkpoint, and never starts, stops or reconfigures a VM. The
embedded script is pinned by a test to a short list of cmdlets that excludes all of those.

Three operations, each returns a dict and never raises:

* ``probe(vm)``: is PowerShell Direct ready; guest computer name, user and PowerShell version.
* ``push_file(vm, host_path, guest_dir)``: SHA-256 on the host, copy to a private partial name in
  the guest, SHA-256 in the guest, compare, and only then move it to its final name. A mismatch
  removes the partial and leaves nothing under the final name. The host file is hashed again
  afterwards, so a file that changed during the copy is not reported as transferred.
* ``pull_files(vm, guest_paths, host_dir)``: only the list the host supplies. Every target name is
  generated on the host (``<run id>-<index>.guestfile``); no guest-controlled text becomes a host
  file name. A path with ``..``, a stream (``:``), a wildcard, a device name, a reparse point (the
  file or any parent), a directory, a missing file or a size over quota is rejected before anything
  is copied. Every file is copied to a ``.partial`` name, then measured on the host (size and SHA-256
  against what the guest measured) before it is published under its final name. Files that verify
  are kept even when a later one fails; ``measured.files`` says which is which.

  What "verified" means. The guest measures the hash, and the host compares its own copy with that
  report: this is TRANSFER INTEGRITY (``transfer_integrity``: the bytes that arrived are the bytes
  the guest hashed) and nothing more. It does not show the content is the content the caller
  expected, because the guest chose both the bytes and the hash. The per-file ``status`` value
  ``VERIFIED`` is kept for compatibility and means exactly that. Content is checked against a source
  only when the caller passes ``expected_sha256`` (one hex digest or ``None`` per path): then the
  host's own hash must equal it (``source_verified`` true, ``EXPECTED_SHA256_MISMATCH`` otherwise).

  Bounded copy. The copy does not trust ``Copy-Item -FromSession``, which cannot be limited while it
  runs and would let a guest that grows a file between the measurement and the copy fill the host
  disk before any check. The script instead pulls the file in 1 MiB reads at host-chosen offsets
  into a ``CreateNew`` host file and never requests or writes more than the measured size (itself
  already checked against both quotas); a short read, a long answer, or any bytes beyond the measured
  size stop the copy, delete the partial and fail with ``GUEST_FILE_CHANGED``. The host re-measures
  size and hash afterwards. The final name is created exclusively (hard link, or an ``O_EXCL``
  copy where the volume has no hard links, reported as ``publish_method``): an existing file is
  never replaced. Every component of ``host_dir`` up to the drive root must be a real directory.

Result shape (``schema`` ``liebert-re.hyperv-transport/1``): ``ok``; ``status`` (``OK``, ``FAILED``
or ``UNKNOWN``); ``error_class`` (``None`` or one of ``ERROR_CLASSES``); ``reason`` (a short fixed
code that refines the class, for example ``VM_NOT_RUNNING``); ``last_phase``; ``elapsed_s``;
``script_sha256``; ``measured``. ``status`` is ``OK`` only with ``error_class`` ``None`` and only when
this module itself re-verified every claim the script made. Anything the script says that this module
cannot confirm (no result line, two result lines, a duplicate JSON key, a wrong schema, an ``ok``
with a hash that differs, a non-zero exit with ``ok`` true, a truncated output, a killed process
after a copy began) is ``UNKNOWN``, never ``OK`` and never a guess at which failure it was.

Error classes: ``AUTH_FAILED`` (the credential file could not be used, or the guest rejected it),
``PSDIRECT_TIMEOUT`` (the session did not open in time, or a probe timed out),
``TRANSFER_FAILED`` (a copy failed, the session was lost, or a transfer timed out after the session
opened; the guest state is then not known and the result says so), ``HASH_MISMATCH``,
``QUOTA_EXCEEDED``, ``PATH_REJECTED`` (also used for a malformed VM name or host path), ``UNKNOWN``.
There is no class for "the VM is not running"; that is ``UNKNOWN`` with reason ``VM_NOT_RUNNING``.
A failed authentication is recognised from the error category or fixed English message fragments
and has NOT been reproduced live (a wrong password was deliberately not tried against the guest);
if it is not recognised it is ``UNKNOWN`` with reason ``SESSION_OPEN_FAILED``.

Credential. ``credential_path`` is an explicit constructor argument: a file written by
``Export-Clixml`` for a ``PSCredential``. It is read by PowerShell inside the script; this module
never opens it, never sees the password, and never copies the path into a result, a log or an
error. There is no environment variable and no default location.

No injection by construction. The script text is a constant. The VM name, every path and the
credential path travel as one base64 JSON argument (``-RequestB64``), whose alphabet is
``A-Za-z0-9+/=``; PowerShell decodes it into data and passes values only to ``-LiteralPath``-style
parameters or to remote script blocks as ``-ArgumentList``. No value is ever concatenated into
script text or into a command line. Tests send quotes, ``;``, ``$()`` and backticks and check that
the script hash and the command line do not change.

The PowerShell runner is injectable (``runner(argv, timeout_seconds) -> BoundedProcessResult``);
the default is ``liebert_re.bounded_subprocess.run_bounded_process`` on ``powershell.exe``
(Windows PowerShell 5.1: the Hyper-V module lives there). Elevation (Hyper-V Administrators) is the
operator's business; without it the VM query fails and the result is ``UNKNOWN``.

Limits of this layer. A hash proves the copy equals what the guest read (transfer integrity), not
that the guest is honest and not that the content is the expected one. Short (8.3) names are not expanded. A killed PowerShell does not prove the guest-side copy
stopped.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import shutil
import stat
import tempfile
import time
import unicodedata
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from liebert_re import strict_json
from liebert_re.bounded_subprocess import BoundedProcessResult, run_bounded_process

__all__ = ["ERROR_CLASSES", "SCHEMA", "HypervTransport"]

SCHEMA = "liebert-re.hyperv-transport/1"
_SCRIPT_SCHEMA = "liebert-re.hyperv-transport-result/1"

ERROR_CLASSES = (
    "AUTH_FAILED", "PSDIRECT_TIMEOUT", "TRANSFER_FAILED", "HASH_MISMATCH",
    "QUOTA_EXCEEDED", "PATH_REJECTED", "UNKNOWN",
)

Runner = Callable[[Sequence[str], float], BoundedProcessResult]

_PHASE_PREFIX = "LIEBERT_PHASE "
_RESULT_PREFIX = "LIEBERT_RESULT "
_PHASES = (
    "decode", "credential", "vm", "session", "session_open", "probe", "host_hash", "guest_prepare",
    "copy", "guest_verify", "guest_stat", "guest_hash",
)
_MAX_REQUEST_B64 = 28_000  # the Windows command line limit is 32767 characters in total
_MAX_OUTPUT_CHARS = 262_144
_MAX_PULL_FILES_HARD = 32
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,47}")
_IDENT = re.compile(r"[A-Za-z][A-Za-z0-9_.]{0,63}")
_RESERVED_NAMES = frozenset({"CON", "PRN", "AUX", "NUL"}
                            | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)})
_BAD_SEGMENT_CHARS = frozenset('<>:"|?*/\\')
_REPARSE_ATTRIBUTE = 0x400
_TRANSPORT_EXCEPTIONS = ("PSRemotingTransportException", "PSRemotingDataStructureException")

# The script is a CONSTANT. Nothing the caller supplies is ever formatted into it.
_SCRIPT = r"""
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
    $obj = [ordered]@{ schema = 'liebert-re.hyperv-transport-result/1'; op = $script:Op; ok = $ok; phase = $script:Phase; failure = $failure; data = $script:Data }
    Say ('LIEBERT_RESULT ' + (AsciiJson $obj))
}

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

    Mark 'session'
    $session = New-PSSession -VMId $found[0].VMId -Credential $cred -ErrorAction Stop
    Mark 'session_open'

    if ($script:Op -eq 'probe') {
        Mark 'probe'
        $info = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
            [ordered]@{
                computer_name = [string] $env:COMPUTERNAME
                user = [string] [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                ps_version = [string] $PSVersionTable.PSVersion.ToString()
            }
        }
        $script:Data['guest_computer_name'] = [string] $info.computer_name
        $script:Data['guest_user'] = [string] $info.user
        $script:Data['guest_ps_version'] = [string] $info.ps_version
    }
    elseif ($script:Op -eq 'push') {
        Mark 'host_hash'
        $hostHash = (Get-FileHash -LiteralPath ([string] $req.host_path) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $script:Data['host_sha256'] = $hostHash
        if ($hostHash -ne ([string] $req.host_sha256)) { Fail 'HOST_FILE_CHANGED' }

        Mark 'guest_prepare'
        $partialName = ([string] $req.guest_name) + '.' + ([string] $req.run_id) + '.partial'
        $prep = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList @([string] $req.guest_dir, [string] $req.guest_name, $partialName, [bool] $req.overwrite, [bool] $req.create_guest_dir) -ScriptBlock {
            param($dir, $name, $partialName, $overwrite, $create)
            $di = New-Object System.IO.DirectoryInfo ($dir)
            if (-not $di.Exists) {
                if (-not $create) { return @{ ok = $false; code = 'GUEST_DIR_MISSING' } }
                [void] [System.IO.Directory]::CreateDirectory($dir)
                $di = New-Object System.IO.DirectoryInfo ($dir)
            }
            $cur = $di
            while ($null -ne $cur) {
                if (($cur.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return @{ ok = $false; code = 'GUEST_PATH_REPARSE' } }
                $cur = $cur.Parent
            }
            $final = [System.IO.Path]::Combine($di.FullName, $name)
            $partial = [System.IO.Path]::Combine($di.FullName, $partialName)
            if ([System.IO.Directory]::Exists($final)) { return @{ ok = $false; code = 'GUEST_NOT_A_FILE' } }
            if ([System.IO.File]::Exists($final)) {
                if (-not $overwrite) { return @{ ok = $false; code = 'GUEST_FILE_EXISTS' } }
                if (((New-Object System.IO.FileInfo ($final)).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return @{ ok = $false; code = 'GUEST_PATH_REPARSE' } }
            }
            if ([System.IO.File]::Exists($partial)) { return @{ ok = $false; code = 'GUEST_PARTIAL_EXISTS' } }
            return @{ ok = $true; final_path = $final; partial_path = $partial }
        }
        if (-not $prep.ok) { Fail ([string] $prep.code) }
        $script:Data['guest_path'] = [string] $prep.final_path

        Mark 'copy'
        Copy-Item -LiteralPath ([string] $req.host_path) -Destination ([string] $prep.partial_path) -ToSession $session -ErrorAction Stop

        Mark 'guest_verify'
        $ver = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList @([string] $prep.partial_path, [string] $prep.final_path, [string] $req.host_sha256, [bool] $req.overwrite) -ScriptBlock {
            param($partial, $final, $expected, $overwrite)
            $h = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant()
            $len = (New-Object System.IO.FileInfo ($partial)).Length
            if ($h -ne $expected) {
                $removed = $true
                try { Remove-Item -LiteralPath $partial -Force } catch { $removed = $false }
                return @{ ok = $false; code = 'GUEST_HASH_MISMATCH'; guest_sha256 = $h; guest_size = $len; partial_removed = $removed }
            }
            if ($overwrite) { Move-Item -LiteralPath $partial -Destination $final -Force } else { Move-Item -LiteralPath $partial -Destination $final }
            return @{ ok = $true; guest_sha256 = $h; guest_size = $len }
        }
        $script:Data['guest_sha256'] = [string] $ver.guest_sha256
        $script:Data['guest_size'] = [int64] $ver.guest_size
        if (-not $ver.ok) {
            $script:Data['partial_removed'] = [bool] $ver.partial_removed
            Fail ([string] $ver.code)
        }
    }
    elseif ($script:Op -eq 'pull') {
        $paths = @($req.guest_paths | ForEach-Object { [string] $_ })
        Mark 'guest_stat'
        $stat = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList @(, $paths) -ScriptBlock {
            param($paths)
            $rows = @()
            foreach ($p in $paths) {
                $row = @{ ok = $false; code = $null; size = $null }
                $fi = New-Object System.IO.FileInfo ($p)
                if ([System.IO.Directory]::Exists($p)) { $row.code = 'GUEST_NOT_A_FILE' }
                elseif (-not $fi.Exists) { $row.code = 'GUEST_FILE_MISSING' }
                else {
                    $bad = (($fi.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
                    $cur = $fi.Directory
                    while ((-not $bad) -and ($null -ne $cur)) {
                        if (($cur.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { $bad = $true }
                        $cur = $cur.Parent
                    }
                    if ($bad) { $row.code = 'GUEST_PATH_REPARSE' } else { $row.ok = $true; $row.size = [int64] $fi.Length }
                }
                $rows += , $row
            }
            return @{ rows = $rows }
        }
        $rows = @($stat.rows)
        $files = @()
        $total = [int64] 0
        $firstCode = $null
        for ($i = 0; $i -lt $paths.Count; $i++) {
            $r = $rows[$i]
            $code = $null
            if (-not $r.ok) { $code = [string] $r.code }
            elseif ([int64] $r.size -gt [int64] $req.max_file_bytes) { $code = 'FILE_TOO_LARGE' }
            else { $total += [int64] $r.size }
            if ($null -eq $code -and $total -gt [int64] $req.max_total_bytes) { $code = 'TOTAL_TOO_LARGE' }
            if ($null -ne $code -and $null -eq $firstCode) { $firstCode = $code }
            $files += , ([ordered]@{ index = [int] $req.indexes[$i]; status = $(if ($null -eq $code) { 'STATED' } else { 'REJECTED' }); code = $code; size = $r.size })
        }
        $script:Data['files'] = $files
        if ($null -ne $firstCode) { Fail $firstCode }

        Mark 'guest_hash'
        $hashes = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList @(, $paths) -ScriptBlock {
            param($paths)
            $out = @()
            foreach ($p in $paths) {
                $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
                $out += , @{ sha256 = $h; size = [int64] (New-Object System.IO.FileInfo ($p)).Length }
            }
            return @{ rows = $out }
        }
        $hrows = @($hashes.rows)
        for ($i = 0; $i -lt $paths.Count; $i++) {
            $files[$i]['sha256'] = [string] $hrows[$i].sha256
            if ([int64] $hrows[$i].size -ne [int64] $files[$i]['size']) {
                $files[$i]['status'] = 'REJECTED'; $files[$i]['code'] = 'GUEST_FILE_CHANGED'
                $script:Data['files'] = $files
                Fail 'GUEST_FILE_CHANGED'
            }
            $files[$i]['status'] = 'HASHED'
        }
        $script:Data['files'] = $files

        Mark 'copy'
        $copiedTotal = [int64] 0
        for ($i = 0; $i -lt $paths.Count; $i++) {
            $partial = [System.IO.Path]::Combine([string] $req.host_dir, [string] $req.partial_names[$i])
            $limit = [int64] $files[$i]['size']
            $out = $null
            $created = $false
            try {
                if (($limit -gt [int64] $req.max_file_bytes) -or (($copiedTotal + $limit) -gt [int64] $req.max_total_bytes)) { Fail 'COPY_OVER_QUOTA' }
                $out = New-Object System.IO.FileStream ($partial, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                $created = $true
                $written = [int64] 0
                while ($written -lt $limit) {
                    $want = [int] [Math]::Min([int64] 1048576, $limit - $written)
                    $chunk = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList @($paths[$i], $written, $want) -ScriptBlock {
                        param($p, $offset, $count)
                        $fs = New-Object System.IO.FileStream ($p, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                        try {
                            [void] $fs.Seek([int64] $offset, [System.IO.SeekOrigin]::Begin)
                            $buf = New-Object byte[] ([int] $count)
                            $n = 0
                            while ($n -lt $count) {
                                $r = $fs.Read($buf, $n, $count - $n)
                                if ($r -le 0) { break }
                                $n += $r
                            }
                            if ($n -lt $count) { $short = New-Object byte[] $n; [System.Array]::Copy($buf, $short, $n); $buf = $short }
                            return , $buf
                        }
                        finally { $fs.Dispose() }
                    }
                    if ($null -eq $chunk) { $bytes = New-Object byte[] 0 } else { $bytes = [byte[]] @($chunk) }
                    if ($bytes.Length -ne $want) { Fail 'GUEST_FILE_CHANGED' }
                    $out.Write($bytes, 0, $bytes.Length)
                    $written += $bytes.Length
                }
                $out.Dispose()
                $out = $null
                $extra = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList @($paths[$i], $limit) -ScriptBlock {
                    param($p, $offset)
                    $fs = New-Object System.IO.FileStream ($p, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    try { return [int64] ($fs.Length - $offset) } finally { $fs.Dispose() }
                }
                if ([int64] $extra -ne 0) { Fail 'GUEST_FILE_CHANGED' }
                $copiedTotal += $written
                $files[$i]['status'] = 'COPIED'
            }
            catch {
                $copyCode = 'COPY_FAILED'
                if (([string] $_.Exception.Message) -cmatch '^lr:([A-Z0-9_]{1,48})$') { $copyCode = $Matches[1] }
                if ($null -ne $out) { try { $out.Dispose() } catch { } }
                if ($created) { try { Remove-Item -LiteralPath $partial -Force -ErrorAction Stop } catch { } }
                $files[$i]['status'] = 'COPY_FAILED'; $files[$i]['code'] = $copyCode
                $script:Data['files'] = $files
                throw
            }
        }
        $script:Data['files'] = $files
    }
    else { Fail 'UNKNOWN_OPERATION' }

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


def _script_sha256() -> str:
    """SHA-256 of the exact script text this module runs (constant for every request)."""
    return hashlib.sha256(_SCRIPT.encode("ascii")).hexdigest()


# --------------------------------------------------------------------------- validation


def _printable(text: str) -> bool:
    return all(ch.isprintable() and unicodedata.category(ch) != "Cf" for ch in text)


def _segment_problem(segment: str) -> str | None:
    if segment in ("", ".", ".."):
        return "EMPTY_OR_RELATIVE_SEGMENT"
    if any(ch in _BAD_SEGMENT_CHARS or not ch.isprintable() for ch in segment):
        return "FORBIDDEN_CHARACTER"
    if segment != segment.rstrip(" ."):
        return "TRAILING_DOT_OR_SPACE"
    if segment.split(".")[0].rstrip(" ").upper() in _RESERVED_NAMES:
        return "DEVICE_NAME"
    return None


_GUEST_PATH = re.compile(r"([A-Za-z]):\\(.+)", re.DOTALL)


def _check_guest_path(value: object, *, directory: bool) -> tuple[str | None, str | None]:
    """``(normalised path, None)`` or ``(None, reason)``. Absolute, drive-letter, backslash only."""
    if not isinstance(value, str) or not value:
        return None, "GUEST_PATH_NOT_TEXT"
    if len(value) > 259:
        return None, "GUEST_PATH_TOO_LONG"
    if directory and value.endswith("\\"):
        value = value[:-1]
    match = _GUEST_PATH.fullmatch(value)
    if match is None:
        return None, "GUEST_PATH_NOT_ABSOLUTE_DRIVE_PATH"
    segments = match.group(2).split("\\")
    for segment in segments:
        problem = _segment_problem(segment)
        if problem is not None:
            return None, f"GUEST_PATH_{problem}"
    return f"{match.group(1).upper()}:\\" + "\\".join(segments), None


def _check_vm(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip() or len(value) > 100 or not _printable(value):
        return "VM_NAME_REJECTED"
    return None


def _is_link_or_reparse(path: str | Path) -> bool | None:
    try:
        info = os.lstat(path)
    except OSError:
        return None
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE)


def _chain_problem(path: str) -> str | None:
    """Every component of ``path`` below the drive root must be a real directory.

    ``None`` when the whole chain is a plain directory chain; ``"REPARSE"`` when any component is a
    symlink or reparse point (junction, mount point); ``"UNREADABLE"`` when a component cannot be
    examined. ``..`` is refused rather than folded, because folding would skip the link it follows.
    """
    if ".." in re.split(r"[\\/]", os.path.splitdrive(path)[1]):
        return "DOTDOT"
    current = os.path.normpath(path)
    while os.path.dirname(current) != current:  # the root itself (drive or share) is not examined
        link = _is_link_or_reparse(current)
        if link is None:
            return "UNREADABLE"
        if link:
            return "REPARSE"
        current = os.path.dirname(current)
    return None


def _publish_exclusive(partial: str, final: str, claimed_sha: str, claimed_size: int,
                       ) -> tuple[str | None, str | None, str | None]:
    """``(method, error_class, reason)``: give ``partial`` its final name without replacing anything.

    A hard link fails with ``FileExistsError`` when ``final`` exists. On a volume with no hard links the
    fallback creates ``final`` with ``O_EXCL``, copies into it and re-measures it; that is reported as
    ``EXCLUSIVE_COPY``. The partial is removed by the caller's cleanup.
    """
    try:
        os.link(partial, final)
        return "HARDLINK", None, None
    except FileExistsError:
        return None, "TRANSFER_FAILED", "HOST_FINAL_NAME_EXISTS"
    except OSError:
        pass  # no hard links here: a fallback, taken and reported
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(final, flags, 0o600)
    except FileExistsError:
        return None, "TRANSFER_FAILED", "HOST_FINAL_NAME_EXISTS"
    except OSError:
        return None, "TRANSFER_FAILED", "HOST_RENAME_FAILED"
    try:
        with os.fdopen(descriptor, "wb") as out, open(partial, "rb") as source:
            shutil.copyfileobj(source, out, 1 << 20)
        again = _sha256_file(final)
        if again == (claimed_sha, claimed_size):
            return "EXCLUSIVE_COPY", None, None
    except OSError:
        pass
    try:  # the file at ``final`` is ours (O_EXCL created it), so it is ours to remove
        os.unlink(final)
    except OSError:
        pass
    return None, "TRANSFER_FAILED", "HOST_RENAME_FAILED"


def _sha256_file(path: str | Path) -> tuple[str, int] | None:
    digest = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
                size += len(block)
    except OSError:
        return None
    return digest.hexdigest(), size


def _positive_seconds(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) and 0 < number <= 86_400 else None


def _positive_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


# --------------------------------------------------------------------------- script output


def _parse_script_output(stdout: str, schema: str | None = None, known_phases: Sequence[str] | None = None,
                         ) -> tuple[list[str], dict[str, Any] | None, str | None]:
    """``(phases reached, result object, problem)``. A problem means no result may be trusted.

    ``schema`` and ``known_phases`` default to this module's own script; the guest launcher passes its own.
    """
    expected_schema = _SCRIPT_SCHEMA if schema is None else schema
    allowed_phases = _PHASES if known_phases is None else known_phases
    phases: list[str] = []
    result_lines: list[str] = []
    for line in stdout.split("\n"):
        line = line.rstrip("\r")
        if line.startswith(_PHASE_PREFIX):
            name = line[len(_PHASE_PREFIX):].strip()
            if name in allowed_phases:
                phases.append(name)
        elif line.startswith(_RESULT_PREFIX):
            result_lines.append(line[len(_RESULT_PREFIX):])
    if not result_lines:
        return phases, None, "NO_RESULT"
    if len(result_lines) > 1:
        return phases, None, "MULTIPLE_RESULTS"
    try:
        body = strict_json.loads(result_lines[0])
    except strict_json.StrictJSONError as exc:
        if exc.reason == strict_json.DUPLICATE_KEY:
            return phases, None, "RESULT_DUPLICATE_KEY"
        return phases, None, "RESULT_NOT_JSON"
    if not isinstance(body, dict) or body.get("schema") != expected_schema:
        return phases, None, "RESULT_SCHEMA_MISMATCH"
    if not isinstance(body.get("ok"), bool) or not isinstance(body.get("data"), dict):
        return phases, None, "RESULT_MALFORMED"
    return phases, body, None


def _clean_failure(raw: object) -> dict[str, Any] | None:
    """Keep only identifier-shaped fields; free text from the guest never reaches a result."""
    if not isinstance(raw, dict):
        return None

    def ident(key: str, pattern: re.Pattern[str]) -> str | None:
        value = raw.get(key)
        return value if isinstance(value, str) and pattern.fullmatch(value) else None

    return {
        "code": ident("code", _CODE),
        "category": ident("category", _IDENT),
        "error_id": ident("error_id", _IDENT),
        "exception_type": ident("exception_type", _IDENT),
        "auth_hint": raw.get("auth_hint") is True,
        "timeout_hint": raw.get("timeout_hint") is True,
    }


_CODE_CLASS = {
    "CREDENTIAL_INVALID": "AUTH_FAILED",
    "GUEST_PATH_REPARSE": "PATH_REJECTED",
    "GUEST_NOT_A_FILE": "PATH_REJECTED",
    "FILE_TOO_LARGE": "QUOTA_EXCEEDED",
    "TOTAL_TOO_LARGE": "QUOTA_EXCEEDED",
    "GUEST_DIR_MISSING": "TRANSFER_FAILED",
    "GUEST_FILE_EXISTS": "TRANSFER_FAILED",
    "GUEST_PARTIAL_EXISTS": "TRANSFER_FAILED",
    "GUEST_FILE_MISSING": "TRANSFER_FAILED",
    "COPY_FAILED": "TRANSFER_FAILED",
    "GUEST_HASH_MISMATCH": "HASH_MISMATCH",
    "GUEST_FILE_CHANGED": "HASH_MISMATCH",
    "COPY_OVER_QUOTA": "QUOTA_EXCEEDED",
    "HOST_FILE_CHANGED": "HASH_MISMATCH",
    "VM_NOT_FOUND": "UNKNOWN",
    "VM_NOT_UNIQUE": "UNKNOWN",
    "VM_NOT_RUNNING": "UNKNOWN",
}
_FILE_STATUSES = frozenset({"STATED", "REJECTED", "HASHED", "COPIED", "COPY_FAILED"})
_AUTH_CATEGORIES = frozenset({"AuthenticationError", "SecurityError", "PermissionDenied"})


def _classify_failure(failure: dict[str, Any], phase: object) -> tuple[str, str]:
    code = failure["code"]
    if code in _CODE_CLASS:
        return _CODE_CLASS[code], code
    if code is not None:  # the script named a failure this module does not know: not a guess
        return "UNKNOWN", "UNMAPPED_FAILURE_CODE"
    if phase == "credential":
        return "AUTH_FAILED", "CREDENTIAL_UNUSABLE"
    if phase == "session":
        if failure["timeout_hint"]:
            return "PSDIRECT_TIMEOUT", "SESSION_OPEN_TIMEOUT"
        if failure["auth_hint"] or failure["category"] in _AUTH_CATEGORIES:
            return "AUTH_FAILED", "SESSION_AUTH_REJECTED"
        return "UNKNOWN", "SESSION_OPEN_FAILED"
    if phase in ("probe", "guest_prepare", "copy", "guest_verify", "guest_stat", "guest_hash"):
        if failure["exception_type"] in _TRANSPORT_EXCEPTIONS or failure["category"] == "ConnectionError":
            return ("TRANSFER_FAILED" if phase != "probe" else "UNKNOWN"), "SESSION_LOST"
        if phase == "copy":
            return "TRANSFER_FAILED", "COPY_FAILED"
    return "UNKNOWN", "UNMAPPED_FAILURE"


# --------------------------------------------------------------------------- transport


class HypervTransport:
    """Transport to one Hyper-V guest over PowerShell Direct. See the module docstring.

    ``credential_path`` is required and explicit: an ``Export-Clixml`` file holding a
    ``PSCredential``, read only by PowerShell. ``runner`` replaces the process runner (tests).
    ``powershell`` overrides the ``powershell.exe`` lookup. The three timeouts are wall-clock
    bounds on the whole PowerShell process for that operation (``New-PSSession -VMId`` accepts no
    session option, so the session open has no timeout of its own inside PowerShell). Quotas are per instance and positive.
    """

    def __init__(
        self,
        credential_path: str | os.PathLike[str],
        *,
        runner: Runner | None = None,
        powershell: str | None = None,
        probe_timeout_s: float = 90.0,
        transfer_timeout_s: float = 300.0,
        max_push_bytes: int = 64 * 1024 * 1024,
        max_pull_files: int = 16,
        max_pull_file_bytes: int = 32 * 1024 * 1024,
        max_pull_total_bytes: int = 128 * 1024 * 1024,
    ) -> None:
        path = os.fspath(credential_path)
        if not isinstance(path, str) or not path or not os.path.isabs(path) or not _printable(path):
            raise ValueError("credential_path must be an absolute path to an Export-Clixml file")
        timeouts = {"probe_timeout_s": probe_timeout_s, "transfer_timeout_s": transfer_timeout_s}
        for name, value in timeouts.items():
            if _positive_seconds(value) is None:
                raise ValueError(f"{name} must be a finite number of seconds in (0, 86400]")
        for name, value in (("max_push_bytes", max_push_bytes), ("max_pull_files", max_pull_files),
                            ("max_pull_file_bytes", max_pull_file_bytes),
                            ("max_pull_total_bytes", max_pull_total_bytes)):
            if _positive_int(value) is None:
                raise ValueError(f"{name} must be a positive integer")
        if max_pull_files > _MAX_PULL_FILES_HARD:
            raise ValueError(f"max_pull_files is capped at {_MAX_PULL_FILES_HARD}")
        self._credential_path = path
        self._runner = runner
        self._powershell = powershell
        self._probe_timeout_s = float(probe_timeout_s)
        self._transfer_timeout_s = float(transfer_timeout_s)
        self._max_push_bytes = max_push_bytes
        self._max_pull_files = max_pull_files
        self._max_pull_file_bytes = max_pull_file_bytes
        self._max_pull_total_bytes = max_pull_total_bytes

    def __repr__(self) -> str:  # the credential path is not printed
        return "HypervTransport(credential_path=<REDACTED>)"

    # ---- result helpers

    @staticmethod
    def _result(op: str, started: float, error_class: str | None, reason: str | None,
                last_phase: str | None = None, **measured: Any) -> dict[str, Any]:
        if error_class is None:
            status = "OK"
        else:
            if error_class not in ERROR_CLASSES:
                error_class, reason = "UNKNOWN", "INTERNAL_BAD_CLASS"
            status = "UNKNOWN" if error_class == "UNKNOWN" else "FAILED"
        return {
            "schema": SCHEMA, "operation": op, "ok": status == "OK", "status": status,
            "error_class": error_class, "reason": reason, "last_phase": last_phase,
            "elapsed_s": round(time.monotonic() - started, 3), "script_sha256": _script_sha256(),
            "measured": measured,
        }

    # ---- one PowerShell run

    def _execute(self, op: str, vm: str, extra: Mapping[str, Any], timeout_s: float,
                 ) -> tuple[list[str], dict[str, Any] | None, tuple[str, str] | None]:
        """``(phases, script result, failure)``; failure is ``(error_class, reason)`` and means no
        script result may be used. Never raises."""
        return self._run_script(op, vm, extra, timeout_s, script=_SCRIPT, script_name="transport.ps1",
                                result_schema=_SCRIPT_SCHEMA, known_phases=_PHASES)

    def _run_script(self, op: str, vm: str, extra: Mapping[str, Any], timeout_s: float, *, script: str,
                    script_name: str, result_schema: str, known_phases: Sequence[str],
                    extra_files: Mapping[str, str] | None = None, max_output_chars: int | None = None,
                    ) -> tuple[list[str], dict[str, Any] | None, tuple[str, str] | None]:
        """One PowerShell run of a CONSTANT script, with this transport's credential, runner and
        executable, one base64 request argument, one wall-clock timeout and bounded process output.

        Shared with ``hyperv_guest_launcher`` (same package, same PowerShell Direct configuration) so
        that there is one place that builds the command line. ``extra_files`` are constant texts the
        script reads from its own directory. Returns ``(phases, script result, failure)``; failure is
        ``(error_class, reason)`` and means no script result may be used. Never raises.
        """
        request = {
            "op": op, "vm": vm, "credential_path": self._credential_path,
            "run_id": uuid.uuid4().hex[:12],
            **extra,
        }
        blob = base64.b64encode(json.dumps(request, ensure_ascii=True).encode("ascii")).decode("ascii")
        if len(blob) > _MAX_REQUEST_B64:
            return [], None, ("QUOTA_EXCEEDED", "REQUEST_TOO_LARGE")
        exe = self._powershell or shutil.which("powershell.exe") or ("powershell.exe" if self._runner else None)
        if exe is None:
            return [], None, ("UNKNOWN", "POWERSHELL_UNAVAILABLE")
        output_limit = _MAX_OUTPUT_CHARS if max_output_chars is None else max_output_chars
        runner = self._runner or (lambda argv, seconds: _default_runner(argv, seconds, output_limit))
        try:
            with tempfile.TemporaryDirectory(prefix="liebert-hvt-") as scratch:
                path = Path(scratch) / script_name
                path.write_text(script, encoding="ascii", newline="\r\n")
                for name, text in (extra_files or {}).items():
                    (Path(scratch) / name).write_text(text, encoding="ascii", newline="\r\n")
                argv = [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-File", str(path), "-RequestB64", blob]
                completed = runner(argv, timeout_s)
        except Exception as exc:  # a runner or temp-dir fault is an unknown, never a crash
            return [], None, ("UNKNOWN", f"RUNNER_FAULT_{type(exc).__name__.upper()[:30]}")
        launch_failed = getattr(completed, "launch_failed", False)  # a duck-typed fake may lack the field
        if launch_failed is True:
            return [], None, ("UNKNOWN", "POWERSHELL_LAUNCH_FAILED")
        stdout = completed.stdout if isinstance(completed.stdout, str) else ""
        phases, body, problem = _parse_script_output(stdout, result_schema, known_phases)
        if getattr(completed, "timed_out", False) is True or getattr(completed, "cancelled", False) is True:
            if op == "probe" or "session_open" not in phases:
                return phases, None, ("PSDIRECT_TIMEOUT", "PROCESS_TIMEOUT")
            return phases, None, ("TRANSFER_FAILED", "TIMEOUT_AFTER_SESSION_OPEN")
        if getattr(completed, "output_truncated", False) is True:
            return phases, None, ("UNKNOWN", "OUTPUT_TRUNCATED")
        if problem is not None or body is None:
            return phases, None, ("UNKNOWN", problem or "NO_RESULT")
        if body.get("op") != op:
            return phases, None, ("UNKNOWN", "RESULT_OPERATION_MISMATCH")
        if body["ok"] is True and completed.returncode != 0:
            return phases, None, ("UNKNOWN", "EXIT_CODE_CONTRADICTS_RESULT")
        if body["ok"] is False and completed.returncode == 0:
            return phases, None, ("UNKNOWN", "EXIT_CODE_CONTRADICTS_RESULT")
        return phases, body, None

    def _failure_of(self, body: dict[str, Any]) -> tuple[str, str]:
        failure = _clean_failure(body.get("failure"))
        if failure is None:
            return "UNKNOWN", "FAILURE_NOT_DESCRIBED"
        return _classify_failure(failure, body.get("phase"))

    def _timeout(self, override: float | None, default: float) -> float | None:
        return default if override is None else _positive_seconds(override)

    # ---- operations

    def probe(self, vm: str, *, timeout_s: float | None = None) -> dict[str, Any]:
        """Is PowerShell Direct ready for ``vm``; guest computer name, user, PowerShell version."""
        started = time.monotonic()
        if _check_vm(vm) is not None:
            return self._result("probe", started, "PATH_REJECTED", "VM_NAME_REJECTED", ready=False)
        timeout = self._timeout(timeout_s, self._probe_timeout_s)
        if timeout is None:
            return self._result("probe", started, "UNKNOWN", "TIMEOUT_REJECTED", ready=False)
        phases, body, failure = self._execute("probe", vm, {}, timeout)
        last = phases[-1] if phases else None
        if failure is not None:
            return self._result("probe", started, failure[0], failure[1], last, ready=False)
        assert body is not None
        if body["ok"] is False:
            cls, reason = self._failure_of(body)
            return self._result("probe", started, cls, reason, body.get("phase"), ready=False)
        data = body["data"]
        computer, user, version = (data.get("guest_computer_name"), data.get("guest_user"),
                                   data.get("guest_ps_version"))
        valid = (
            isinstance(computer, str) and 0 < len(computer) <= 64 and _printable(computer)
            and isinstance(user, str) and 0 < len(user) <= 256 and _printable(user)
            and isinstance(version, str) and re.fullmatch(r"\d+(\.\d+){1,3}", version) is not None
            and data.get("vm_state") == "Running"
        )
        if not valid:
            return self._result("probe", started, "UNKNOWN", "PROBE_DATA_INVALID", last, ready=False)
        return self._result("probe", started, None, None, last, ready=True, guest_computer_name=computer,
                            guest_user=user, guest_powershell_version=version, vm_state="Running")

    def push_file(self, vm: str, host_path: str | os.PathLike[str], guest_dir: str, *,
                  overwrite: bool = False, create_guest_dir: bool = False,
                  timeout_s: float | None = None) -> dict[str, Any]:
        """Copy one host file into ``guest_dir`` (absolute guest path) and prove it by SHA-256."""
        started = time.monotonic()
        measured: dict[str, Any] = {}

        def reject(cls: str, reason: str, **more: Any) -> dict[str, Any]:
            return self._result("push", started, cls, reason, **{**measured, **more})

        if _check_vm(vm) is not None:
            return reject("PATH_REJECTED", "VM_NAME_REJECTED")
        directory, problem = _check_guest_path(guest_dir, directory=True)
        if directory is None:
            return reject("PATH_REJECTED", problem or "GUEST_PATH_REJECTED")
        try:
            host = os.fspath(host_path)
        except TypeError:
            return reject("PATH_REJECTED", "HOST_PATH_NOT_TEXT")
        if not isinstance(host, str) or not host or not os.path.isabs(host) or not _printable(host):
            return reject("PATH_REJECTED", "HOST_PATH_NOT_ABSOLUTE")
        if ":" in os.path.splitdrive(host)[1]:
            return reject("PATH_REJECTED", "HOST_PATH_STREAM")
        name = os.path.basename(host)
        name_problem = _segment_problem(name) or ("NAME_TOO_LONG" if len(name) > 128 else None)
        if name_problem is not None:
            return reject("PATH_REJECTED", f"HOST_FILE_NAME_{name_problem}")
        link = _is_link_or_reparse(host)
        if link is None:
            return reject("PATH_REJECTED", "HOST_FILE_MISSING")
        if link:
            return reject("PATH_REJECTED", "HOST_FILE_REPARSE_POINT")
        if not os.path.isfile(host):
            return reject("PATH_REJECTED", "HOST_NOT_A_FILE")
        if not isinstance(overwrite, bool) or not isinstance(create_guest_dir, bool):
            return reject("PATH_REJECTED", "FLAG_NOT_BOOLEAN")
        timeout = self._timeout(timeout_s, self._transfer_timeout_s)
        if timeout is None:
            return reject("UNKNOWN", "TIMEOUT_REJECTED")
        first = _sha256_file(host)
        if first is None:
            return reject("TRANSFER_FAILED", "HOST_FILE_UNREADABLE")
        host_sha, host_size = first
        measured.update(host_sha256=host_sha, host_size=host_size)
        if host_size > self._max_push_bytes:
            return reject("QUOTA_EXCEEDED", "HOST_FILE_OVER_QUOTA", quota_bytes=self._max_push_bytes)
        extra = {"host_path": host, "host_sha256": host_sha, "guest_dir": directory, "guest_name": name,
                 "overwrite": overwrite, "create_guest_dir": create_guest_dir}
        phases, body, failure = self._execute("push", vm, extra, timeout)
        last = phases[-1] if phases else None
        if failure is not None:
            if failure[1] == "TIMEOUT_AFTER_SESSION_OPEN":
                measured["guest_state"] = "UNKNOWN"
            return self._result("push", started, failure[0], failure[1], last, **measured)
        assert body is not None
        data = body["data"]
        for key in ("guest_sha256", "guest_size", "guest_path"):
            if key in data:
                measured[f"reported_{key}"] = data[key]
        if body["ok"] is False:
            cls, reason = self._failure_of(body)
            guest_sha = data.get("guest_sha256")
            if reason == "GUEST_HASH_MISMATCH" and isinstance(guest_sha, str) and _HEX64.fullmatch(guest_sha):
                measured["guest_sha256"] = guest_sha
                measured["partial_removed"] = data.get("partial_removed") is True
            return self._result("push", started, cls, reason, body.get("phase"), **measured)
        expected_path = f"{directory}\\{name}"
        guest_sha, guest_size, guest_path = data.get("guest_sha256"), data.get("guest_size"), data.get("guest_path")
        if not (isinstance(guest_sha, str) and _HEX64.fullmatch(guest_sha)
                and isinstance(guest_size, int) and not isinstance(guest_size, bool)
                and isinstance(guest_path, str)):
            return self._result("push", started, "UNKNOWN", "PUSH_DATA_INVALID", last, **measured)
        measured.update(guest_sha256=guest_sha, guest_size=guest_size)
        if guest_path.casefold() != expected_path.casefold():
            return self._result("push", started, "UNKNOWN", "GUEST_PATH_MISMATCH", last, **measured)
        if guest_sha != host_sha or guest_size != host_size:
            return self._result("push", started, "HASH_MISMATCH", "GUEST_DIFFERS_FROM_HOST", last, **measured)
        again = _sha256_file(host)
        if again is None or again != (host_sha, host_size):
            return self._result("push", started, "HASH_MISMATCH", "HOST_FILE_CHANGED", last, **measured)
        measured.update(guest_path=expected_path, hashes_equal=True)
        measured.pop("reported_guest_sha256", None)
        measured.pop("reported_guest_size", None)
        measured.pop("reported_guest_path", None)
        return self._result("push", started, None, None, last, **measured)

    def pull_files(self, vm: str, guest_paths: Sequence[str], host_dir: str | os.PathLike[str], *,
                   timeout_s: float | None = None,
                   expected_sha256: Sequence[str | None] | None = None) -> dict[str, Any]:
        """Copy the listed guest files into ``host_dir`` under host-generated names.

        Each file's ``transfer_integrity`` says the host copy equals what the guest reported; that is
        not a check against the expected content. ``expected_sha256`` (one 64-digit hex string or
        ``None`` per path, same order) makes the host's own hash be compared with a value the caller
        brought; only then ``source_verified`` is true.
        """
        started = time.monotonic()

        def early(cls: str, reason: str, **more: Any) -> dict[str, Any]:
            return self._result("pull", started, cls, reason, requested=len(guest_paths)
                                if isinstance(guest_paths, (list, tuple)) else None, verified=0, **more)

        if _check_vm(vm) is not None:
            return early("PATH_REJECTED", "VM_NAME_REJECTED")
        if not isinstance(guest_paths, (list, tuple)) or not guest_paths:
            return early("PATH_REJECTED", "GUEST_PATH_LIST_INVALID")
        if len(guest_paths) > self._max_pull_files:
            return early("QUOTA_EXCEEDED", "TOO_MANY_FILES", quota_files=self._max_pull_files)
        normalised: list[str] = []
        rejected: list[dict[str, Any]] = []
        for index, item in enumerate(guest_paths):
            path, problem = _check_guest_path(item, directory=False)
            if path is None:
                rejected.append({"index": index, "reason": problem})
            else:
                normalised.append(path)
        if not rejected and len({p.casefold() for p in normalised}) != len(normalised):
            rejected.append({"index": None, "reason": "DUPLICATE_GUEST_PATH"})
        if rejected:
            return early("PATH_REJECTED", rejected[0]["reason"], rejected=rejected)
        expected: list[str | None] = [None] * len(normalised)
        if expected_sha256 is not None:
            if (not isinstance(expected_sha256, (list, tuple)) or len(expected_sha256) != len(normalised)
                    or not all(e is None or (isinstance(e, str) and re.fullmatch(r"[0-9a-fA-F]{64}", e))
                               for e in expected_sha256)):
                return early("PATH_REJECTED", "EXPECTED_SHA256_INVALID")
            expected = [e.lower() if e is not None else None for e in expected_sha256]
        try:
            target_dir = os.fspath(host_dir)
        except TypeError:
            return early("PATH_REJECTED", "HOST_DIR_NOT_TEXT")
        if not isinstance(target_dir, str) or not target_dir or not os.path.isabs(target_dir) \
                or not _printable(target_dir):
            return early("PATH_REJECTED", "HOST_DIR_NOT_ABSOLUTE")
        if ":" in os.path.splitdrive(target_dir)[1]:
            return early("PATH_REJECTED", "HOST_DIR_STREAM")
        if _chain_problem(target_dir) is not None or not os.path.isdir(target_dir):
            return early("PATH_REJECTED", "HOST_DIR_MISSING_OR_REPARSE")
        timeout = self._timeout(timeout_s, self._transfer_timeout_s)
        if timeout is None:
            return early("UNKNOWN", "TIMEOUT_REJECTED")

        run_tag = uuid.uuid4().hex[:12]
        finals = [os.path.join(target_dir, f"{run_tag}-{i:03d}.guestfile") for i in range(len(normalised))]
        partials = [f"{run_tag}-{i:03d}.guestfile.partial" for i in range(len(normalised))]
        partial_paths = [os.path.join(target_dir, name) for name in partials]
        extra = {
            "guest_paths": normalised, "indexes": list(range(len(normalised))), "host_dir": target_dir,
            "partial_names": partials, "max_file_bytes": self._max_pull_file_bytes,
            "max_total_bytes": self._max_pull_total_bytes,
        }
        phases, body, failure = self._execute("pull", vm, extra, timeout)
        last = phases[-1] if phases else None
        files: list[dict[str, Any]] = [
            {"index": i, "guest_path": p, "status": "NOT_ATTEMPTED", "error_class": None, "reason": None,
             "host_path": None, "size": None, "sha256": None, "transfer_integrity": False,
             "source_verified": False, "integrity_basis": None, "publish_method": None}
            for i, p in enumerate(normalised)
        ]
        verified = 0
        try:
            if failure is not None:
                return self._pull_result(started, failure[0], failure[1], last, files, verified,
                                         guest_state_unknown=failure[1] == "TIMEOUT_AFTER_SESSION_OPEN")
            assert body is not None
            reported = body["data"].get("files")
            rows = reported if isinstance(reported, list) else []
            row_by_index: dict[int, dict[str, Any]] = {}
            for row in rows:
                if isinstance(row, dict) and isinstance(row.get("index"), int) \
                        and not isinstance(row.get("index"), bool) and 0 <= row["index"] < len(files):
                    row_by_index.setdefault(row["index"], row)
            for index, row in row_by_index.items():
                code = row.get("code")
                if isinstance(code, str) and _CODE.fullmatch(code):
                    files[index]["error_class"] = _CODE_CLASS.get(code, "UNKNOWN")
                    files[index]["reason"] = code
                if row.get("status") in _FILE_STATUSES:
                    files[index]["status"] = row["status"]
                size = row.get("size")
                if isinstance(size, int) and not isinstance(size, bool):
                    files[index]["size"] = size
            if body["ok"] is False:
                cls, reason = self._failure_of(body)
                return self._pull_result(started, cls, reason, body.get("phase"), files, verified)
            # The script claims success: re-verify every file on the host before believing it.
            if len(row_by_index) != len(files) or any(r.get("status") != "COPIED" for r in row_by_index.values()):
                return self._pull_result(started, "UNKNOWN", "PULL_DATA_INCOMPLETE", last, files, verified)
            first_error: tuple[str, str] | None = None
            total = 0
            for index, entry in enumerate(files):
                row = row_by_index[index]
                claimed_sha, claimed_size = row.get("sha256"), row.get("size")
                partial = partial_paths[index]
                outcome = self._verify_pulled(partial, claimed_sha, claimed_size, total, expected[index])
                if outcome[0] is not None:
                    entry["error_class"], entry["reason"], entry["status"] = outcome[0], outcome[1], "REJECTED"
                    first_error = first_error or (outcome[0], outcome[1])
                    continue
                total += claimed_size
                method, pub_class, pub_reason = _publish_exclusive(partial, finals[index], claimed_sha, claimed_size)
                if method is None:
                    entry["error_class"], entry["reason"], entry["status"] = pub_class, pub_reason, "REJECTED"
                    first_error = first_error or (pub_class or "UNKNOWN", pub_reason or "HOST_RENAME_FAILED")
                    continue
                entry.update(status="VERIFIED", host_path=finals[index], size=claimed_size, sha256=claimed_sha,
                             transfer_integrity=True, publish_method=method,
                             source_verified=expected[index] is not None,
                             integrity_basis=("HOST_MATCHES_GUEST_REPORT_AND_CALLER_EXPECTED_SHA256"
                                              if expected[index] is not None else "HOST_MATCHES_GUEST_REPORT"))
                verified += 1
            if first_error is not None:
                return self._pull_result(started, first_error[0], first_error[1], last, files, verified)
            return self._pull_result(started, None, None, last, files, verified)
        finally:
            for partial in partial_paths:  # nothing partial is left behind, whatever happened
                try:
                    if os.path.lexists(partial):
                        os.unlink(partial)
                except OSError:
                    pass

    def _verify_pulled(self, partial: str, claimed_sha: object, claimed_size: object, total: int,
                       expected: str | None = None) -> tuple[str | None, str | None]:
        if not (isinstance(claimed_sha, str) and _HEX64.fullmatch(claimed_sha)
                and isinstance(claimed_size, int) and not isinstance(claimed_size, bool) and claimed_size >= 0):
            return "UNKNOWN", "PULL_FILE_DATA_INVALID"
        link = _is_link_or_reparse(partial)
        if link is None:
            return "TRANSFER_FAILED", "HOST_FILE_MISSING"
        if link or not os.path.isfile(partial):
            return "PATH_REJECTED", "HOST_FILE_NOT_REGULAR"
        actual = os.lstat(partial).st_size
        if actual > self._max_pull_file_bytes or total + actual > self._max_pull_total_bytes:
            return "QUOTA_EXCEEDED", "HOST_SIZE_OVER_QUOTA"
        measured = _sha256_file(partial)
        if measured is None:
            return "TRANSFER_FAILED", "HOST_FILE_UNREADABLE"
        if measured[1] != claimed_size or actual != claimed_size:
            return "HASH_MISMATCH", "SIZE_MISMATCH"
        if measured[0] != claimed_sha:
            return "HASH_MISMATCH", "SHA256_MISMATCH"
        if expected is not None and measured[0] != expected:
            return "HASH_MISMATCH", "EXPECTED_SHA256_MISMATCH"
        return None, None

    def _pull_result(self, started: float, error_class: str | None, reason: str | None, last: str | None,
                     files: list[dict[str, Any]], verified: int, **more: Any) -> dict[str, Any]:
        total = sum(f["size"] for f in files if f["status"] == "VERIFIED")
        source_verified = bool(files) and all(f["source_verified"] for f in files)
        return self._result("pull", started, error_class, reason, last, requested=len(files),
                            verified=verified, verified_bytes=total, files=files,
                            source_verified=source_verified, **more)


def _default_runner(argv: Sequence[str], timeout_seconds: float,
                    max_output_chars: int = _MAX_OUTPUT_CHARS) -> BoundedProcessResult:
    return run_bounded_process(list(argv), timeout_seconds=timeout_seconds, max_output_chars=max_output_chars)
