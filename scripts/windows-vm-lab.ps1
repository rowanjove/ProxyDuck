<#
.SYNOPSIS
  Performs a non-destructive preflight for the ProxyDuck Windows VM gate.

.DESCRIPTION
  The data-plane, Service/Named Pipe, installer and rollback checks require an
  isolated Windows VM.  This command deliberately does not create, restore or
  mutate a VM.  It records the host/VM/snapshot facts that must be true before
  a later, explicitly authorized lab runner is allowed to execute those tests.

  Exit code 0 means the requested preflight is ready.  Exit code 2 means the
  lab is blocked by the host environment (for example Hyper-V is unavailable),
  and the JSON report remains useful evidence instead of being mistaken for a
  passing data-plane test.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$VMName,
  [string]$SnapshotName,
  [string]$OutputDirectory = "release\vm-lab",
  [switch]$RequireSnapshot
)

$ErrorActionPreference = "Stop"
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$outputPath = [System.IO.Path]::GetFullPath(
  $(if ([System.IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory } else { Join-Path $workspaceRoot $OutputDirectory })
)
$workspacePrefix = $workspaceRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $outputPath.StartsWith($workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw "VM lab report must stay inside the workspace: $outputPath"
}
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

$blockers = [System.Collections.Generic.List[string]]::new()
$hyperVAvailable = $false
$vm = $null
$snapshots = @()

if ($null -eq (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
  $blockers.Add("Hyper-V PowerShell cmdlets are unavailable on this host")
} else {
  $hyperVAvailable = $true
  try {
    $vm = Get-VM -Name $VMName -ErrorAction Stop
  } catch {
    $blockers.Add("VM '$VMName' was not found: $($_.Exception.Message)")
  }
}

if ($null -ne $vm) {
  try {
    $snapshots = @(Get-VMSnapshot -VMName $VMName -ErrorAction Stop | ForEach-Object {
      [ordered]@{
        name = [string]$_.Name
        id = [string]$_.Id
        createdAt = $_.CreationTime.ToUniversalTime().ToString("o")
      }
    })
  } catch {
    $blockers.Add("Unable to enumerate snapshots for VM '$VMName': $($_.Exception.Message)")
  }

  if ([string]$vm.State -ne "Running") {
    $blockers.Add("VM '$VMName' is not running (state: $($vm.State))")
  }
  if ($RequireSnapshot -and $snapshots.Count -eq 0) {
    $blockers.Add("no checkpoint/snapshot is available for rollback tests")
  }
  if (-not [string]::IsNullOrWhiteSpace($SnapshotName) -and
      -not ($snapshots | Where-Object { $_.name -eq $SnapshotName })) {
    $blockers.Add("requested snapshot '$SnapshotName' was not found")
  }
}

$status = if ($blockers.Count -eq 0) { "ready" } else { "blocked" }
$report = [ordered]@{
  schemaVersion = 1
  generatedAt = [DateTime]::UtcNow.ToString("o")
  product = "ProxyDuck"
  purpose = "windows-vm-gate-preflight"
  vmName = $VMName
  requestedSnapshot = if ([string]::IsNullOrWhiteSpace($SnapshotName)) { $null } else { $SnapshotName }
  hyperVAvailable = $hyperVAvailable
  vmFound = $null -ne $vm
  vmState = if ($null -ne $vm) { [string]$vm.State } else { $null }
  snapshots = @($snapshots)
  status = $status
  blockers = @($blockers)
  executedTests = @()
  note = "Preflight only; no VM, driver, installer, service, or data-plane state was changed."
}

$reportFile = Join-Path $outputPath ("preflight-{0}-{1}.json" -f ($VMName -replace '[^A-Za-z0-9_.-]', '_'), (Get-Date -Format "yyyyMMdd-HHmmss"))
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportFile -Encoding UTF8
$report | ConvertTo-Json -Depth 8
Write-Host "[ProxyDuck] VM lab preflight: $status"
Write-Host "[ProxyDuck] Report: $reportFile"

if ($status -eq "blocked") {
  exit 2
}
exit 0
