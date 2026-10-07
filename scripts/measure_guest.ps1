# measure_guest.ps1 - operator-run measurement of a Hyper-V guest, for guest attestation.
#
# Run this on the Hyper-V host, elevated, by hand. It writes one JSON file in the
# liebert-re.guest-measurement/1 shape that liebert_re.dynamic.guest_attestation reads.
#
# What it measures (read-only cmdlets only):
#   host      SHA-256 of the host machine GUID (the raw value is never written)
#   vm        identity, state, generation, automatic checkpoints, parent checkpoint
#   sections  checkpoints, network adapters, virtual switches, other VMs' adapters on
#             the same switches, integration services, VM security flags
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
# Error text is the exception type name only; messages can carry paths and account names.
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

$result = [ordered]@{
    schema_version = 'liebert-re.guest-measurement/1'
    measured_at_utc = [DateTime]::UtcNow.ToString('o')
    script_version = '1.0.0'
    elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$vmObj = $null

$result['host'] = $null
try {
    $machineGuid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid' -ErrorAction Stop).MachineGuid
    if ([string]::IsNullOrEmpty([string]$machineGuid)) { throw [System.InvalidOperationException]::new('machine identifier empty') }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$machineGuid))
    $sha.Dispose()
    $result['host'] = [ordered]@{
        ok = $true
        error = $null
        identity_sha256 = ([System.BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    }
}
catch {
    $result['host'] = [ordered]@{
        ok = $false
        error = if ($_.Exception -is [System.InvalidOperationException]) { $_.Exception.Message } else { $_.Exception.GetType().FullName }
        identity_sha256 = $null
    }
}

$result['vm'] = $null
try {
    $found = @(Get-VM -Name $VMName -ErrorAction Stop)
    if ($found.Count -ne 1) { throw [System.InvalidOperationException]::new('VM name did not resolve to exactly one VM') }
    $vmObj = $found[0]
    $result['vm'] = [ordered]@{
        ok = $true
        error = $null
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
    $result['vm'] = [ordered]@{
        ok = $false
        error = if ($_.Exception -is [System.InvalidOperationException]) { $_.Exception.Message } else { $_.Exception.GetType().FullName }
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
    if ($null -eq $vmObj) { throw [System.InvalidOperationException]::new('vm not resolved') }
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
    $result['checkpoints'] = [ordered]@{ ok = $true; error = $null; items = @($items) }
}
catch {
    $result['checkpoints'] = [ordered]@{
        ok = $false
        error = if ($_.Exception -is [System.InvalidOperationException]) { $_.Exception.Message } else { $_.Exception.GetType().FullName }
        items = @()
    }
}

$result['adapters'] = $null
try {
    if ($null -eq $vmObj) { throw [System.InvalidOperationException]::new('vm not resolved') }
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
    $result['adapters'] = [ordered]@{ ok = $true; error = $null; items = @($items) }
}
catch {
    $result['adapters'] = [ordered]@{
        ok = $false
        error = if ($_.Exception -is [System.InvalidOperationException]) { $_.Exception.Message } else { $_.Exception.GetType().FullName }
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
    $result['switches'] = [ordered]@{ ok = $true; error = $null; items = @($items) }
}
catch {
    $result['switches'] = [ordered]@{
        ok = $false
        error = if ($_.Exception -is [System.InvalidOperationException]) { $_.Exception.Message } else { $_.Exception.GetType().FullName }
        items = @()
    }
}

$result['switch_peers'] = $null
try {
    if ($null -eq $vmObj) { throw [System.InvalidOperationException]::new('vm not resolved') }
    $items = @()
    foreach ($p in @(Get-VMNetworkAdapter -All -ErrorAction Stop)) {
        if (($null -ne $p.VMId) -and ($p.VMId.ToString() -eq $vmObj.VMId.ToString())) { continue }
        if (-not (($p.SwitchId -is [guid]) -and ($p.SwitchId -ne [guid]::Empty))) { continue }
        $items += [ordered]@{
            switch_id = $p.SwitchId.ToString()
            vm_id = if ($null -eq $p.VMId) { $null } else { $p.VMId.ToString() }
        }
    }
    $result['switch_peers'] = [ordered]@{ ok = $true; error = $null; items = @($items) }
}
catch {
    $result['switch_peers'] = [ordered]@{
        ok = $false
        error = if ($_.Exception -is [System.InvalidOperationException]) { $_.Exception.Message } else { $_.Exception.GetType().FullName }
        items = @()
    }
}

$result['integration_services'] = $null
try {
    if ($null -eq $vmObj) { throw [System.InvalidOperationException]::new('vm not resolved') }
    $items = @()
    foreach ($i in @(Get-VMIntegrationService -VMName $VMName -ErrorAction Stop)) {
        $items += [ordered]@{
            id_suffix = $i.Id.ToString().Split('\')[-1]
            enabled = if ($null -eq $i.Enabled) { $null } else { [bool]$i.Enabled }
        }
    }
    $result['integration_services'] = [ordered]@{ ok = $true; error = $null; items = @($items) }
}
catch {
    $result['integration_services'] = [ordered]@{
        ok = $false
        error = if ($_.Exception -is [System.InvalidOperationException]) { $_.Exception.Message } else { $_.Exception.GetType().FullName }
        items = @()
    }
}

$result['security'] = $null
try {
    if ($null -eq $vmObj) { throw [System.InvalidOperationException]::new('vm not resolved') }
    $sec = @(Get-VMSecurity -VMName $VMName -ErrorAction Stop)
    if ($sec.Count -ne 1) { throw [System.InvalidOperationException]::new('security query did not return exactly one record') }
    $result['security'] = [ordered]@{
        ok = $true
        error = $null
        tpm_enabled = if ($null -eq $sec[0].TpmEnabled) { $null } else { [bool]$sec[0].TpmEnabled }
        shielded = if ($null -eq $sec[0].Shielded) { $null } else { [bool]$sec[0].Shielded }
    }
}
catch {
    $result['security'] = [ordered]@{
        ok = $false
        error = if ($_.Exception -is [System.InvalidOperationException]) { $_.Exception.Message } else { $_.Exception.GetType().FullName }
        tpm_enabled = $null
        shielded = $null
    }
}

$result['guest'] = $null
try {
    if ($null -eq $GuestCredential) { throw [System.InvalidOperationException]::new('no credential') }
    $raw = @(Invoke-Command -VMName $VMName -Credential $GuestCredential -ErrorAction Stop -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        $out = @{ vm_id_from_kvp = $null; os_build = $null; vbs_status = $null; security_services_running = $null; errors = @() }
        try {
            $kvp = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters' -Name 'VirtualMachineId' -ErrorAction Stop
            $out['vm_id_from_kvp'] = [string]$kvp.VirtualMachineId
        }
        catch { $out['errors'] += 'kvp:' + $_.Exception.GetType().FullName }
        try {
            $dg = @(Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop)
            if ($dg.Count -ne 1) { throw [System.InvalidOperationException]::new('device guard class did not return exactly one record') }
            $out['vbs_status'] = [int]$dg[0].VirtualizationBasedSecurityStatus
            $running = @()
            foreach ($r in @($dg[0].SecurityServicesRunning)) { $running += [int]$r }
            $out['security_services_running'] = $running
        }
        catch { $out['errors'] += 'vbs:' + $_.Exception.GetType().FullName }
        try {
            $os = @(Get-CimInstance -ClassName 'Win32_OperatingSystem' -ErrorAction Stop)
            if ($os.Count -ne 1) { throw [System.InvalidOperationException]::new('operating system class did not return exactly one record') }
            $out['os_build'] = [string]$os[0].BuildNumber
        }
        catch { $out['errors'] += 'os:' + $_.Exception.GetType().FullName }
        $out
    })
    if ($raw.Count -ne 1) { throw [System.InvalidOperationException]::new('guest returned an unexpected number of records') }
    $g = $raw[0]
    $failed = @($g['errors'])
    $result['guest'] = [ordered]@{
        ok = ($failed.Count -eq 0)
        error = if ($failed.Count -eq 0) { $null } else { 'guest steps failed: ' + ($failed -join ',') }
        vm_id_from_kvp = $g['vm_id_from_kvp']
        os_build = $g['os_build']
        vbs_status = $g['vbs_status']
        security_services_running = $g['security_services_running']
    }
}
catch {
    $result['guest'] = [ordered]@{
        ok = $false
        error = if ($_.Exception -is [System.InvalidOperationException]) { $_.Exception.Message } else { $_.Exception.GetType().FullName }
        vm_id_from_kvp = $null
        os_build = $null
        vbs_status = $null
        security_services_running = $null
    }
}

$result | ConvertTo-Json -Depth 8 | Out-File -Encoding utf8 -FilePath $OutFile
