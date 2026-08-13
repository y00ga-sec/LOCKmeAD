#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploys the JIT Access Manager tool to T0 admin workstations via GPO.
.DESCRIPTION
    This script reads a JSON configuration file and deploys the JIT Access Manager
    tool by publishing it to a distribution share and creating a GPO startup script
    that installs it on target machines. The tool allows admins to temporarily add
    accounts to AD groups using PAM TTL.
.PARAMETER ConfigPath
    Path to the JSON configuration file. Default: .\Config\JIT-Config.json
.PARAMETER WhatIf
    Simulation mode: displays actions without executing them.
.PARAMETER NoConfirm
    Skips the interactive confirmation prompt (used by the GUI).
.PARAMETER Server
    Explicit target domain controller. Required when this host is not domain-joined
    and no domain controller can be located automatically.
.PARAMETER Credential
    Explicit domain credential. Prompted for interactively when this host is not
    domain-joined and no credential is supplied.
.PARAMETER RememberConnection
    Persists the resolved -Server/-Credential (DPAPI-protected, current user only)
    for reuse on the next run.
.EXAMPLE
    .\Deploy-JIT.ps1
    .\Deploy-JIT.ps1 -ConfigPath "C:\Config\custom-jit.json"
    .\Deploy-JIT.ps1 -WhatIf
    .\Deploy-JIT.ps1 -Server dc01.forest.lol -Credential (Get-Credential)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "..\Config\JIT-Config.json"),
    [switch]$NoConfirm,
    [string]$Server,
    [PSCredential]$Credential,
    [switch]$RememberConnection
)

# ============================================================================
# Initialization
# ============================================================================

$ErrorActionPreference = "Stop"
$rootDir = Split-Path $PSScriptRoot -Parent

# Import JIT module
$modulePath = Join-Path $rootDir "Modules\JIT\JIT.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Host "[ERROR] JIT module not found: $modulePath" -ForegroundColor Red
    exit 1
}
Import-Module $modulePath -Force
Import-Module (Join-Path $rootDir "Modules\Common\Connection.psm1") -Force
Import-Module (Join-Path $rootDir "Modules\Common\ConfigDomain.psm1") -Force

# A refused connection must read as a clear operator error, not as an unhandled
# exception: Resolve-LOCKmeADConnection throws when the account is not a Domain Admin.
try {
    $connection = Resolve-LOCKmeADConnection -Server $Server -Credential $Credential -Remember:$RememberConnection
}
catch {
    Write-Host "`n[ERROR] $($_.Exception.Message)`n" -ForegroundColor Red
    exit 1
}

# Same conditional GroupPolicy requirement as Deploy-GPO.ps1 -- see the comment there, including
# why availability is tested with Test-LOCKmeADGroupPolicyModule and not 'Get-Module -ListAvailable'.
if (-not $connection.Credential -and -not (Test-LOCKmeADGroupPolicyModule)) {
    Write-Host "`n[ERROR] The 'GroupPolicy' module is required to deploy the JIT GPO in implicit mode." -ForegroundColor Red
    Write-Host "Install RSAT-GPMC on this host, or pass -Server/-Credential to run them on the DC.`n" -ForegroundColor Yellow
    exit 1
}
# Same reason as Deploy-GPO.ps1: auto-loading GroupPolicy fails under -WhatIf.
if (-not $connection.Credential) {
    try { Import-LOCKmeADGroupPolicyModule }
    catch {
        Write-Host "`n[ERROR] The 'GroupPolicy' module is installed but could not be loaded: $($_.Exception.Message)`n" -ForegroundColor Red
        exit 1
    }
}

# ============================================================================
# Load configuration
# ============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  JIT DEPLOYMENT TOOL - Active Directory" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""
Write-Host "  Purpose: Deploy the JIT Access Manager tool to T0 admin" -ForegroundColor DarkCyan
Write-Host "  workstations via GPO startup script. The tool allows admins" -ForegroundColor DarkCyan
Write-Host "  to temporarily add accounts to AD groups using PAM TTL." -ForegroundColor DarkCyan
Write-Host ""

try {
    $config = Import-JITConfiguration -ConfigPath $ConfigPath
    $logDir = $config.Settings.LogDirectory
    if (-not [System.IO.Path]::IsPathRooted($logDir)) {
        $logDir = Join-Path $rootDir $logDir
    }
    $runFolder = if ($global:LOCKmeAD_RunFolder) { $global:LOCKmeAD_RunFolder } else { Get-Date -Format 'yyyy-MM-dd_HH-mm-ss' }
    $logDir = Join-Path $logDir $runFolder
    Write-JITLog -Message "Configuration loaded successfully from '$ConfigPath'." -Level Success -LogDirectory $logDir
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ============================================================================
# Display environment information
# ============================================================================

Write-Host ""
Write-Host "--- Environment Information ---" -ForegroundColor White
Write-Host ""

try {
    $envInfo = Get-JITEnvironmentInfo -Server $connection.Server -Credential $connection.Credential
    $targetServer = if ($connection.Server) { $connection.Server } else { $envInfo.PDCEmulator }

    Write-Host "  Current DC        : $($envInfo.CurrentDC)" -ForegroundColor Cyan
    if ($envInfo.IsPDC) {
        Write-Host "  PDC Role          : YES (this DC is the PDC Emulator)" -ForegroundColor Green
    }
    else {
        Write-Host "  PDC Role          : NO (PDC = $($envInfo.PDCEmulator))" -ForegroundColor Yellow
    }
    Write-Host "  Target DC         : $targetServer" -ForegroundColor Cyan
    Write-Host "  Domain            : $($envInfo.DomainName)" -ForegroundColor Cyan
    Write-Host "  Domain DN         : $($envInfo.DomainDN)" -ForegroundColor Cyan
    Write-Host "  Forest            : $($envInfo.ForestName)" -ForegroundColor Cyan
    Write-Host "  Functional level  : Domain=$($envInfo.DomainMode), Forest=$($envInfo.ForestMode)" -ForegroundColor Cyan

    if ($envInfo.PamEnabled) {
        Write-Host "  PAM Feature       : ENABLED" -ForegroundColor Green
    }
    else {
        Write-Host "  PAM Feature       : NOT ENABLED" -ForegroundColor Red
        Write-Host ""
        Write-Host "  [WARNING] The Privileged Access Management feature is not enabled." -ForegroundColor Yellow
        Write-Host "  JIT group membership with TTL requires PAM. Enable it via the" -ForegroundColor Yellow
        Write-Host "  Hardening module before using the JIT Access Manager tool." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [ERROR] Unable to retrieve AD information: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ============================================================================
# Retarget the configuration onto the connected domain
# ============================================================================
# See Deploy-Hardening.ps1 for the rationale. Ordering matters here too: the summary below copies
# ToolsSharePath, the GPO link targets and the filtering OU into local variables, and everything
# downstream uses those copies rather than the configuration object.
$domainRetargeting = Sync-LOCKmeADConfigDomain -Config $config -ConfigPath $ConfigPath `
                        -Server $targetServer -Credential $connection.Credential
if ($domainRetargeting.Count -gt 0) {
    Write-JITLog -Message "$($domainRetargeting.Count) value(s) retargeted onto $($envInfo.DomainDN) for this run; '$ConfigPath' is left unchanged." -Level Warning -LogDirectory $logDir
}

# ============================================================================
# Configuration summary
# ============================================================================

$sharePath      = $config.Settings.ToolsSharePath
$installPath    = $config.Settings.InstallPath
$gpoName        = $config.Settings.GPO.Name
$gpoDescription = $config.Settings.GPO.Description
$linkTargets    = @($config.Settings.GPO.LinkTargets)
$filteringOU    = $config.Settings.FilteringGroupsOU

Write-Host ""
Write-Host "--- JIT Deployment Configuration ---" -ForegroundColor White
Write-Host ""
Write-Host "  Config file       : $ConfigPath" -ForegroundColor Cyan
Write-Host "  Log directory     : $logDir" -ForegroundColor Cyan
Write-Host "  Distribution share: $sharePath" -ForegroundColor Cyan
Write-Host "  Install path      : $installPath" -ForegroundColor Cyan
Write-Host "  GPO name          : $gpoName" -ForegroundColor Cyan
Write-Host "  Filtering OU      : $filteringOU" -ForegroundColor Cyan
Write-Host "  Link targets      : $($linkTargets.Count)" -ForegroundColor Cyan

foreach ($target in $linkTargets) {
    if (-not [string]::IsNullOrWhiteSpace($target)) {
        Write-Host "    - $target" -ForegroundColor DarkCyan
    }
}

if ($linkTargets.Count -eq 0 -or ($linkTargets.Count -eq 1 -and [string]::IsNullOrWhiteSpace($linkTargets[0]))) {
    Write-Host "    (no link targets defined - GPO will be created but not linked)" -ForegroundColor Yellow
}

# ============================================================================
# WhatIf mode: information
# ============================================================================

if ($WhatIfPreference) {
    Write-Host ""
    Write-Host "  >>> SIMULATION MODE (WhatIf) - No changes will be made <<<" -ForegroundColor Yellow
    Write-Host ""
}

# ============================================================================
# User confirmation
# ============================================================================

if (-not $WhatIfPreference -and -not $NoConfirm) {
    Write-Host ""
    $confirmation = Read-Host "Confirm deployment? (Y/N)"
    if ($confirmation -notin @("Y", "y", "Yes", "yes")) {
        Write-JITLog -Message "Deployment cancelled by user." -Level Warning -LogDirectory $logDir
        exit 0
    }
    Write-Host ""
}

# ============================================================================
# Deploy JIT Tool
# ============================================================================

Write-JITLog -Message "Starting JIT deployment..." -Level Info -LogDirectory $logDir
Write-Host ""

$stats = @{
    Published   = $false
    GPOCreated  = $false
    LinksCreated = 0
    Errors      = 0
}

# --- Step 1: Publish JIT tool to distribution share ---
Write-JITLog -Message "=== Step 1: Publish JIT tool ===" -Level Info -LogDirectory $logDir

$sourcePath = Join-Path $rootDir "Scripts\Start-JIT.ps1"
try {
    Publish-JITTool -SourcePath $sourcePath `
                    -DistributionSharePath $sharePath `
                    -Credential $connection.Credential `
                    -LogDirectory $logDir `
                    -WhatIf:$WhatIfPreference
    $stats.Published = $true
}
catch {
    Write-JITLog -Message "Tool publishing failed: $_" -Level Error -LogDirectory $logDir
    $stats.Errors++
}

# --- Step 2: Create GPO with startup script ---
Write-JITLog -Message "=== Step 2: Create deployment GPO ===" -Level Info -LogDirectory $logDir

try {
    New-JITDeploymentGPO -GPOName $gpoName `
                         -GPODescription $gpoDescription `
                         -FilteringGroupsOU $filteringOU `
                         -InstallPath $installPath `
                         -DistributionSharePath $sharePath `
                         -DomainDN $envInfo.DomainDN `
                         -Server $targetServer `
                         -Credential $connection.Credential `
                         -LogDirectory $logDir `
                         -WhatIf:$WhatIfPreference
    $stats.GPOCreated = $true
}
catch {
    Write-JITLog -Message "GPO creation failed: $_" -Level Error -LogDirectory $logDir
    $stats.Errors++
}

# --- Step 3: Link GPO to target OUs ---
$validTargets = @($linkTargets | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($validTargets.Count -gt 0) {
    Write-JITLog -Message "=== Step 3: Link GPO to target OUs ===" -Level Info -LogDirectory $logDir

    try {
        Set-JITGPOLink -GPOName $gpoName `
                       -LinkTargets $validTargets `
                       -Server $targetServer `
                       -Credential $connection.Credential `
                       -LogDirectory $logDir `
                       -WhatIf:$WhatIfPreference
        $stats.LinksCreated = $validTargets.Count
    }
    catch {
        Write-JITLog -Message "GPO linking failed: $_" -Level Error -LogDirectory $logDir
        $stats.Errors++
    }
}
else {
    Write-JITLog -Message "=== Step 3: No link targets defined, skipping GPO linking ===" -Level Warning -LogDirectory $logDir
}

# ============================================================================
# Summary
# ============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  DEPLOYMENT SUMMARY" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

$modeLabel = if ($WhatIfPreference) { " (SIMULATION)" } else { "" }

$publishLabel = if ($stats.Published) { "Yes" } else { "No" }
$gpoLabel = if ($stats.GPOCreated) { "Yes" } else { "No" }

Write-Host "  Tool published$modeLabel     : $publishLabel" -ForegroundColor Cyan
Write-Host "  GPO configured$modeLabel     : $gpoLabel" -ForegroundColor Cyan
Write-Host "  GPO links created$modeLabel        : $($stats.LinksCreated)" -ForegroundColor Cyan

if ($stats.Errors -gt 0) {
    Write-Host "  Errors                   : $($stats.Errors)" -ForegroundColor Red
}
else {
    Write-Host "  Errors                   : 0" -ForegroundColor Green
}

Write-Host ""
if ($script:LogFilePath) {
    Write-Host "  Log file: $($script:LogFilePath)" -ForegroundColor Cyan
}
Write-Host ""
Write-JITLog -Message "Deployment completed." -Level Info -LogDirectory $logDir
