# measure_guest.ps1 - operator-run measurement of a Hyper-V guest, for guest attestation.
#
# Run this on the Hyper-V host, elevated, by hand. It writes one JSON file in the
# liebert-re.guest-measurement/2 shape that liebert_re.dynamic.guest_attestation reads.
#
# What it measures (read-only cmdlets only):
#   host      SHA-256 of the host machine GUID (the raw value is never written)
#   vm        identity, state, generation, automatic checkpoints, parent checkpoint
#   sections  checkpoints, network adapters, virtual switches, the host's own management
#             adapters (host_adapters), other VMs' adapters on the same switches
#             (switch_peers), integration services, VM security flags
#   guest     (only with -GuestCredential, over PowerShell Direct) the VM id the guest
#             reads from the host key-value channel, OS build, virtualization-based
#             security status and the list of running security services
#
# What it does NOT change: no VM setting, no checkpoint, no switch, no adapter, no
# integration service, no registry value, no boot or security configuration. The only
# thing it writes is the JSON file named by -OutFile.
#
# Every step has its own try/catch. A failed step becomes { ok: false, error: ... } and
# the script carries on, so a partial file is still a truthful file. An empty list from a
# query that succeeded is { ok: true, items: [] } and is distinct from a failed query.
# The network sections (adapters, switches, host_adapters, switch_peers) are read a second
# time at the end; a section whose two readings differ, or whose second reading fails, is
# ok: false with error_category InconsistentMeasurement. A null or non-numeric Device Guard
# value in the guest is an error and is recorded as null, never as 0.
# Error text is the exception type name only; messages can carry paths and account names.
# Each failed step also carries error_category: the ErrorRecord category (for example
# PermissionDenied or ObjectNotFound) and, only when it is a bare identifier, the error id
# before the first comma. An id containing anything else (a path, a space, the VM name) is
# dropped. Message text is never written. The script's own messages are the fixed strings
# marked "lr:" below; any other InvalidOperationException is reported by type name.
#
# When the script ends it prints a short summary to the console: per section ok or
# failed (<category>), whether it ran elevated, and the output file NAME (not the path). It
# prints no identity value, GUID or account name. If it is not elevated it says so first and
# carries on.
#
# Moving the file to the guest is a separate operator step and is not done here, for
# example: Copy-Item -ToSession <session> -Path <file> -Destination <guest path>.
#
# This file can be forged by anyone who can edit it. The harness says so itself: every
# verdict derived from it carries spoofable: true. Do not treat it as proof of isolation.
#
# Note: Out-File -Encoding utf8 writes a byte-order mark on Windows PowerShell 5.1;
# read the file with a decoder that tolerates one.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $VMName,

    [Parameter(Mandatory = $true)]
    [string] $OutFile,

    [System.Management.Automation.PSCredential] $GuestCredential
)

$ErrorActionPreference = 'Stop'

# One audited place that turns an ErrorRecord into { error, category }. error is a fixed
# string of this script or an exception type name; category is the ErrorRecord category and,
# for a cmdlet error, the bare error id. Nothing else of the record is read.
function ErrInfo($rec) {
    $ex = $rec.Exception
    $own = ($ex -is [System.InvalidOperationException]) -and $ex.Message.StartsWith('lr:', [System.StringComparison]::Ordinal)
    $text = if ($own) { $ex.Message.Substring(3).Trim() } else { $ex.GetType().FullName }
    $category = $rec.CategoryInfo.Category.ToString()
    if (-not $own) {
        $id = ([string]$rec.FullyQualifiedErrorId -split ',')[0]
        if (($id -cmatch '^[A-Za-z][A-Za-z0-9_.]{0,63}$') -and ($id.IndexOf($VMName, [System.StringComparison]::OrdinalIgnoreCase) -lt 0)) {
            $category = $category + '/' + $id
        }
    }
    @{ error = $text; category = $category }
}

$result = [ordered]@{
    schema_version = 'liebert-re.guest-measurement/2'
    measured_at_utc = [DateTime]::UtcNow.ToString('o')
    script_version = '2.0.0'
    elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $result['elevated']) { Write-Host 'not elevated: Hyper-V sections will fail' }

$vmObj = $null

$result['host'] = $null
try {
    $machineGuid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid' -ErrorAction Stop).MachineGuid
    if ([string]::IsNullOrEmpty([string]$machineGuid)) { throw [System.InvalidOperationException]::new('lr:machine identifier empty') }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$machineGuid))
    $sha.Dispose()
    $result['host'] = [ordered]@{
        ok = $true
        error = $null
        error_category = $null
        identity_sha256 = ([System.BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    }
}
catch {
    $e = ErrInfo $_
    $result['host'] = [ordered]@{
        ok = $false
        error = $e.error
        error_category = $e.category
        identity_sha256 = $null
    }
}

$result['vm'] = $null
try {
    $found = @(Get-VM -Name $VMName -ErrorAction Stop)
    if ($found.Count -ne 1) { throw [System.InvalidOperationException]::new('lr:VM name did not resolve to exactly one VM') }
    $vmObj = $found[0]
    $result['vm'] = [ordered]@{
        ok = $true
        error = $null
        error_category = $null
        id = $vmObj.VMId.ToString()
        name = $vmObj.Name
        state = $vmObj.State.ToString()
        generation = $vmObj.Generation
        automatic_checkpoints = if ($null -eq $vmObj.AutomaticCheckpointsEnabled) { $null } else { [bool]$vmObj.AutomaticCheckpointsEnabled }
        parent_checkpoint_id = if ($null -eq $vmObj.ParentCheckpointId) { $null } else { $vmObj.ParentCheckpointId.ToString() }
    }
}
catch {
    $vmObj = $null
    $e = ErrInfo $_
    $result['vm'] = [ordered]@{
        ok = $false
        error = $e.error
        error_category = $e.category
        id = $null
        name = $null
        state = $null
        generation = $null
        automatic_checkpoints = $null
        parent_checkpoint_id = $null
    }
}

$result['checkpoints'] = $null
try {
    if ($null -eq $vmObj) { throw [System.InvalidOperationException]::new('lr:vm not resolved') }
    $items = @()
    foreach ($c in @(Get-VMSnapshot -VMName $VMName -ErrorAction Stop)) {
        $items += [ordered]@{
            id = $c.Id.ToString()
            name = $c.Name
            vm_id = if ($null -eq $c.VMId) { $null } else { $c.VMId.ToString() }
            created_utc = if ($null -eq $c.CreationTime) { $null } else { $c.CreationTime.ToUniversalTime().ToString('o') }
            type = if ($null -eq $c.SnapshotType) { $null } else { $c.SnapshotType.ToString() }
        }
    }
    $result['checkpoints'] = [ordered]@{ ok = $true; error = $null; error_category = $null; items = @($items) }
}
catch {
    $e = ErrInfo $_
    $result['checkpoints'] = [ordered]@{
        ok = $false
        error = $e.error
        error_category = $e.category
        items = @()
    }
}

$result['adapters'] = $null
try {
    if ($null -eq $vmObj) { throw [System.InvalidOperationException]::new('lr:vm not resolved') }
    $items = @()
    foreach ($a in @(Get-VMNetworkAdapter -VMName $VMName -ErrorAction Stop)) {
        $switchId = $null
        if (($a.SwitchId -is [guid]) -and ($a.SwitchId -ne [guid]::Empty)) { $switchId = $a.SwitchId.ToString() }
        $items += [ordered]@{
            id = $a.Id.ToString()
            switch_id = $switchId
            switch_name = if ([string]::IsNullOrEmpty($a.SwitchName)) { $null } else { $a.SwitchName }
            connected = if ($null -eq $a.Connected) { $null } else { [bool]$a.Connected }
        }
    }
    $result['adapters'] = [ordered]@{ ok = $true; error = $null; error_category = $null; items = @($items) }
}
catch {
    $e = ErrInfo $_
    $result['adapters'] = [ordered]@{
        ok = $false
        error = $e.error
        error_category = $e.category
        items = @()
    }
}

$result['switches'] = $null
try {
    $items = @()
    foreach ($s in @(Get-VMSwitch -ErrorAction Stop)) {
        $items += [ordered]@{
            id = $s.Id.ToString()
            name = $s.Name
            switch_type = if ($null -eq $s.SwitchType) { $null } else { $s.SwitchType.ToString() }
        }
    }
    $result['switches'] = [ordered]@{ ok = $true; error = $null; error_category = $null; items = @($items) }
}
catch {
    $e = ErrInfo $_
    $result['switches'] = [ordered]@{
        ok = $false
        error = $e.error
        error_category = $e.category
        items = @()
    }
}

$result['host_adapters'] = $null
$hostAdapterIds = $null
try {
    $items = @()
    $ids = @()
    foreach ($h in @(Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop)) {
        $ids += $h.Id.ToString()
        if (-not (($h.SwitchId -is [guid]) -and ($h.SwitchId -ne [guid]::Empty))) { continue }
        $items += [ordered]@{
            switch_id = $h.SwitchId.ToString()
            kind = 'host_management'
        }
    }
    $hostAdapterIds = @($ids)
    $result['host_adapters'] = [ordered]@{ ok = $true; error = $null; error_category = $null; items = @($items) }
}
catch {
    $hostAdapterIds = $null
    $e = ErrInfo $_
    $result['host_adapters'] = [ordered]@{
        ok = $false
        error = $e.error
        error_category = $e.category
        items = @()
    }
}

$result['switch_peers'] = $null
try {
    if ($null -eq $vmObj) { throw [System.InvalidOperationException]::new('lr:vm not resolved') }
    if ($null -eq $hostAdapterIds) { throw [System.InvalidOperationException]::new('lr:host adapters not measured') }
    $items = @()
    foreach ($p in @(Get-VMNetworkAdapter -All -ErrorAction Stop)) {
        if (($null -ne $p.VMId) -and ($p.VMId.ToString() -eq $vmObj.VMId.ToString())) { continue }
        if (($hostAdapterIds -contains $p.Id.ToString()) -or ($p.IsManagementOs -eq $true)) { continue }
        if (-not (($p.SwitchId -is [guid]) -and ($p.SwitchId -ne [guid]::Empty))) { continue }
        $items += [ordered]@{
            switch_id = $p.SwitchId.ToString()
            vm_id = if ($null -eq $p.VMId) { $null } else { $p.VMId.ToString() }
        }
    }
    $result['switch_peers'] = [ordered]@{ ok = $true; error = $null; error_category = $null; items = @($items) }
}
catch {
    $e = ErrInfo $_
    $result['switch_peers'] = [ordered]@{
        ok = $false
        error = $e.error
        error_category = $e.category
        items = @()
    }
}

$result['integration_services'] = $null
try {
    if ($null -eq $vmObj) { throw [System.InvalidOperationException]::new('lr:vm not resolved') }
    $items = @()
    foreach ($i in @(Get-VMIntegrationService -VMName $VMName -ErrorAction Stop)) {
        $items += [ordered]@{
            id_suffix = $i.Id.ToString().Split('\')[-1]
            enabled = if ($null -eq $i.Enabled) { $null } else { [bool]$i.Enabled }
        }
    }
    $result['integration_services'] = [ordered]@{ ok = $true; error = $null; error_category = $null; items = @($items) }
}
catch {
    $e = ErrInfo $_
    $result['integration_services'] = [ordered]@{
        ok = $false
        error = $e.error
        error_category = $e.category
        items = @()
    }
}

$result['security'] = $null
try {
    if ($null -eq $vmObj) { throw [System.InvalidOperationException]::new('lr:vm not resolved') }
    $sec = @(Get-VMSecurity -VMName $VMName -ErrorAction Stop)
    if ($sec.Count -ne 1) { throw [System.InvalidOperationException]::new('lr:security query did not return exactly one record') }
    $result['security'] = [ordered]@{
        ok = $true
        error = $null
        error_category = $null
        tpm_enabled = if ($null -eq $sec[0].TpmEnabled) { $null } else { [bool]$sec[0].TpmEnabled }
        shielded = if ($null -eq $sec[0].Shielded) { $null } else { [bool]$sec[0].Shielded }
    }
}
catch {
    $e = ErrInfo $_
    $result['security'] = [ordered]@{
        ok = $false
        error = $e.error
        error_category = $e.category
        tpm_enabled = $null
        shielded = $null
    }
}

$result['guest'] = $null
try {
    if ($null -eq $GuestCredential) { throw [System.InvalidOperationException]::new('lr:no credential') }
    $raw = @(Invoke-Command -VMName $VMName -Credential $GuestCredential -ErrorAction Stop -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        $out = @{ vm_id_from_kvp = $null; os_build = $null; vbs_status = $null; security_services_running = $null; errors = @(); categories = @() }
        try {
            $kvp = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters' -Name 'VirtualMachineId' -ErrorAction Stop
            $out['vm_id_from_kvp'] = [string]$kvp.VirtualMachineId
        }
        catch { $out['errors'] += 'kvp:' + $_.Exception.GetType().FullName; $out['categories'] += 'kvp:' + $_.CategoryInfo.Category.ToString() }
        try {
            $dg = @(Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop)
            if ($dg.Count -ne 1) { throw [System.InvalidOperationException]::new('lr:device guard class did not return exactly one record') }
            # A null or non-numeric value is an error and stays null; [int]$null would be 0, which reads as a real status.
            $numTypes = @([byte], [int16], [uint16], [int32], [uint32], [int64], [uint64])
            $vbsRaw = $dg[0].VirtualizationBasedSecurityStatus
            if (($null -eq $vbsRaw) -or -not ($numTypes -contains $vbsRaw.GetType())) { throw [System.InvalidOperationException]::new('lr:device guard status null or not numeric') }
            $svcRaw = $dg[0].SecurityServicesRunning
            if ($null -eq $svcRaw) { throw [System.InvalidOperationException]::new('lr:device guard services null') }
            $running = @()
            foreach ($r in @($svcRaw)) {
                if (($null -eq $r) -or -not ($numTypes -contains $r.GetType())) { throw [System.InvalidOperationException]::new('lr:device guard service entry null or not numeric') }
                $running += [int]$r
            }
            $out['vbs_status'] = [int]$vbsRaw
            $out['security_services_running'] = $running
        }
        catch { $out['errors'] += 'vbs:' + $_.Exception.GetType().FullName; $out['categories'] += 'vbs:' + $_.CategoryInfo.Category.ToString() }
        try {
            $os = @(Get-CimInstance -ClassName 'Win32_OperatingSystem' -ErrorAction Stop)
            if ($os.Count -ne 1) { throw [System.InvalidOperationException]::new('lr:operating system class did not return exactly one record') }
            $out['os_build'] = [string]$os[0].BuildNumber
        }
        catch { $out['errors'] += 'os:' + $_.Exception.GetType().FullName; $out['categories'] += 'os:' + $_.CategoryInfo.Category.ToString() }
        $out
    })
    if ($raw.Count -ne 1) { throw [System.InvalidOperationException]::new('lr:guest returned an unexpected number of records') }
    $g = $raw[0]
    $failed = @($g['errors'])
    $result['guest'] = [ordered]@{
        ok = ($failed.Count -eq 0)
        error = if ($failed.Count -eq 0) { $null } else { 'guest steps failed: ' + ($failed -join ',') }
        error_category = if ($failed.Count -eq 0) { $null } else { @($g['categories']) -join ',' }
        vm_id_from_kvp = $g['vm_id_from_kvp']
        os_build = $g['os_build']
        vbs_status = $g['vbs_status']
        security_services_running = $g['security_services_running']
    }
}
catch {
    $e = ErrInfo $_
    $result['guest'] = [ordered]@{
        ok = $false
        error = $e.error
        error_category = $e.category
        vm_id_from_kvp = $null
        os_build = $null
        vbs_status = $null
        security_services_running = $null
    }
}

# Second reading of the network topology. The sections above were read one after another, so a
# change in between would leave them describing different moments. Adapters, switches, the host's
# management adapters and the other VMs' adapters are read again here; a section whose second
# reading differs from its first, or cannot be made, is reported ok: false. Equal readings show
# the topology was the same at both reads, not that nothing changed between them.
$sigBefore = @{}
foreach ($sec in @('adapters', 'switches', 'host_adapters', 'switch_peers')) {
    $parts = @()
    if ($result[$sec]['ok'] -eq $true) {
        foreach ($it in @($result[$sec]['items'])) {
            $fields = @()
            foreach ($v in $it.Values) { $fields += [string]$v }
            $parts += ($fields -join '|')
        }
        if ($sec -eq 'host_adapters') { foreach ($i in @($hostAdapterIds)) { $parts += ('id:' + $i) } }
        $arr = [string[]]@($parts)
        [System.Array]::Sort($arr)
        $sigBefore[$sec] = ($arr -join ';')
    }
    else { $sigBefore[$sec] = $null }
}

$sigAfter = @{ adapters = $null; switches = $null; host_adapters = $null; switch_peers = $null }
$hostIdsAfter = $null
try {
    if ($null -eq $vmObj) { throw [System.InvalidOperationException]::new('lr:vm not resolved') }
    $parts = @()
    foreach ($a in @(Get-VMNetworkAdapter -VMName $VMName -ErrorAction Stop)) {
        $switchId = $null
        if (($a.SwitchId -is [guid]) -and ($a.SwitchId -ne [guid]::Empty)) { $switchId = $a.SwitchId.ToString() }
        $switchName = if ([string]::IsNullOrEmpty($a.SwitchName)) { $null } else { $a.SwitchName }
        $connected = if ($null -eq $a.Connected) { $null } else { [bool]$a.Connected }
        $parts += ($a.Id.ToString() + '|' + [string]$switchId + '|' + [string]$switchName + '|' + [string]$connected)
    }
    $arr = [string[]]@($parts)
    [System.Array]::Sort($arr)
    $sigAfter['adapters'] = ($arr -join ';')
}
catch { $sigAfter['adapters'] = $null }
try {
    $parts = @()
    foreach ($s in @(Get-VMSwitch -ErrorAction Stop)) {
        $switchType = if ($null -eq $s.SwitchType) { $null } else { $s.SwitchType.ToString() }
        $parts += ($s.Id.ToString() + '|' + [string]$s.Name + '|' + [string]$switchType)
    }
    $arr = [string[]]@($parts)
    [System.Array]::Sort($arr)
    $sigAfter['switches'] = ($arr -join ';')
}
catch { $sigAfter['switches'] = $null }
try {
    $parts = @()
    $ids = @()
    foreach ($h in @(Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop)) {
        $ids += $h.Id.ToString()
        $parts += ('id:' + $h.Id.ToString())
        if (-not (($h.SwitchId -is [guid]) -and ($h.SwitchId -ne [guid]::Empty))) { continue }
        $parts += ($h.SwitchId.ToString() + '|host_management')
    }
    $hostIdsAfter = @($ids)
    $arr = [string[]]@($parts)
    [System.Array]::Sort($arr)
    $sigAfter['host_adapters'] = ($arr -join ';')
}
catch { $sigAfter['host_adapters'] = $null }
try {
    if ($null -eq $vmObj) { throw [System.InvalidOperationException]::new('lr:vm not resolved') }
    if ($null -eq $hostIdsAfter) { throw [System.InvalidOperationException]::new('lr:host adapters not measured') }
    $parts = @()
    foreach ($p in @(Get-VMNetworkAdapter -All -ErrorAction Stop)) {
        if (($null -ne $p.VMId) -and ($p.VMId.ToString() -eq $vmObj.VMId.ToString())) { continue }
        if (($hostIdsAfter -contains $p.Id.ToString()) -or ($p.IsManagementOs -eq $true)) { continue }
        if (-not (($p.SwitchId -is [guid]) -and ($p.SwitchId -ne [guid]::Empty))) { continue }
        $peerVm = if ($null -eq $p.VMId) { $null } else { $p.VMId.ToString() }
        $parts += ($p.SwitchId.ToString() + '|' + [string]$peerVm)
    }
    $arr = [string[]]@($parts)
    [System.Array]::Sort($arr)
    $sigAfter['switch_peers'] = ($arr -join ';')
}
catch { $sigAfter['switch_peers'] = $null }

foreach ($sec in @('adapters', 'switches', 'host_adapters', 'switch_peers')) {
    if ($null -eq $sigBefore[$sec]) { continue }   # already ok: false from its first reading
    $problem = $null
    if ($null -eq $sigAfter[$sec]) { $problem = 'second reading of the topology failed' }
    elseif ($sigAfter[$sec] -cne $sigBefore[$sec]) { $problem = 'topology differs between the two readings' }
    if ($null -ne $problem) {
        $result[$sec] = [ordered]@{
            ok = $false
            error = $problem
            error_category = 'InconsistentMeasurement'
            items = @()
        }
    }
}

$result | ConvertTo-Json -Depth 8 | Out-File -Encoding utf8 -FilePath $OutFile

$outName = [System.IO.Path]::GetFileName($OutFile)
$elevatedText = if ($result['elevated']) { 'yes' } else { 'no' }
Write-Host 'liebert-re guest measurement summary'
Write-Host ('elevated: ' + $elevatedText)
foreach ($name in @($result.Keys)) {
    if (-not ($result[$name] -is [System.Collections.IDictionary])) { continue }
    $status = if ($result[$name]['ok']) { 'ok' } elseif (($name -eq 'guest') -and ($null -eq $GuestCredential)) { 'not requested (no credential)' } else { 'failed (' + $result[$name]['error_category'] + ')' }
    Write-Host ($name + ': ' + $status)
}
Write-Host ('output: ' + $outName)
