#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploys Authentication Policy Silos in Active Directory.
.DESCRIPTION
    This script reads a JSON configuration file containing silo definitions and
    creates Authentication Policies, Authentication Policy Silos, and assigns
    computer and service accounts to each silo. Each silo can be individually
    enabled or disabled in the configuration.
.PARAMETER ConfigPath
    Path to the JSON configuration file. Default: .\Config\Silo-Config.json
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
    .\Deploy-Silo.ps1
    .\Deploy-Silo.ps1 -ConfigPath "C:\Config\custom-silo.json"
    .\Deploy-Silo.ps1 -WhatIf
    .\Deploy-Silo.ps1 -Server dc01.forest.lol -Credential (Get-Credential)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "..\Config\Silo-Config.json"),
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

# Import Silo module
$modulePath = Join-Path $rootDir "Modules\Silo\Silo.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Host "[ERROR] Silo module not found: $modulePath" -ForegroundColor Red
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

# ============================================================================
# Load configuration
# ============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  SILO DEPLOYMENT TOOL - Active Directory" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""
Write-Host "  Purpose: Create per-service Authentication Policy Silos" -ForegroundColor DarkCyan
Write-Host "  to prevent lateral movement in case a service account or" -ForegroundColor DarkCyan
Write-Host "  T1 server running a service/scheduled task is compromised." -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Each silo restricts which computers a service account can" -ForegroundColor DarkCyan
Write-Host "  authenticate to, limiting the blast radius to only the" -ForegroundColor DarkCyan
Write-Host "  machines explicitly assigned to that silo." -ForegroundColor DarkCyan
Write-Host ""

try {
    $config = Import-SiloConfiguration -ConfigPath $ConfigPath
    $logDir = $config.Settings.LogDirectory
    if (-not [System.IO.Path]::IsPathRooted($logDir)) {
        $logDir = Join-Path $rootDir $logDir
    }
    $runFolder = if ($global:LOCKmeAD_RunFolder) { $global:LOCKmeAD_RunFolder } else { Get-Date -Format 'yyyy-MM-dd_HH-mm-ss' }
    $logDir = Join-Path $logDir $runFolder
    Write-SiloLog -Message "Configuration loaded successfully from '$ConfigPath'." -Level Success -LogDirectory $logDir
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
    $envInfo = Get-SiloEnvironmentInfo -Server $connection.Server -Credential $connection.Credential
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
}
catch {
    Write-Host "  [ERROR] Unable to retrieve AD information: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ============================================================================
# Retarget the configuration onto the connected domain
# ============================================================================
# See Deploy-Hardening.ps1 for the rationale. Silos name their members by sAMAccountName, so this
# is normally a no-op -- kept so every deployment script behaves identically.
$domainRetargeting = Sync-LOCKmeADConfigDomain -Config $config -ConfigPath $ConfigPath `
                        -Server $targetServer -Credential $connection.Credential
if ($domainRetargeting.Count -gt 0) {
    Write-SiloLog -Message "$($domainRetargeting.Count) value(s) retargeted onto $($envInfo.DomainDN) for this run; '$ConfigPath' is left unchanged." -Level Warning -LogDirectory $logDir
}

# ============================================================================
# Configuration summary
# ============================================================================

$enabledSilos  = @($config.Silos | Where-Object { $_.Enabled -eq $true })
$disabledSilos = @($config.Silos | Where-Object { $_.Enabled -eq $false })

Write-Host ""
Write-Host "--- Authentication Policy Silos ---" -ForegroundColor White
Write-Host ""
Write-Host "  Config file       : $ConfigPath" -ForegroundColor Cyan
Write-Host "  Log directory     : $logDir" -ForegroundColor Cyan
Write-Host "  Total silos       : $($config.Silos.Count)" -ForegroundColor Cyan
Write-Host "  Enabled           : $($enabledSilos.Count)" -ForegroundColor Green
Write-Host "  Disabled          : $($disabledSilos.Count)" -ForegroundColor Yellow
Write-Host ""

foreach ($silo in $config.Silos) {
    $computerCount = if ($silo.Computers) { $silo.Computers.Count } else { 0 }
    $svcCount = if ($silo.ServiceAccounts) { $silo.ServiceAccounts.Count } else { 0 }
    $enforceLabel = if ($silo.Enforce) { "Enforce" } else { "Audit" }
    $detail = "$enforceLabel, TGT=$($silo.TGTLifetimeMinutes)min, $computerCount computers, $svcCount service accounts"

    if ($silo.Enabled) {
        Write-Host "    [ON]  $($silo.Name)" -ForegroundColor Green -NoNewline
        Write-Host " ($detail)" -ForegroundColor DarkGreen -NoNewline
        Write-Host " - $($silo.Description)" -ForegroundColor Cyan
    }
    else {
        Write-Host "    [OFF] $($silo.Name)" -ForegroundColor DarkGray -NoNewline
        Write-Host " - $($silo.Description)" -ForegroundColor DarkGray
    }
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
        Write-SiloLog -Message "Deployment cancelled by user." -Level Warning -LogDirectory $logDir
        exit 0
    }
    Write-Host ""
}

# ============================================================================
# Deploy Silos
# ============================================================================

Write-SiloLog -Message "Starting Silo deployment..." -Level Info -LogDirectory $logDir
Write-Host ""

$stats = @{
    SilosDeployed    = 0
    SilosSkipped     = 0
    AccountsAssigned = 0
    Errors           = 0
}

foreach ($silo in $config.Silos) {
    if (-not $silo.Enabled) {
        $stats.SilosSkipped++
        continue
    }

    Write-SiloLog -Message "=== Silo: $($silo.Name) ===" -Level Info -LogDirectory $logDir

    # Create or update Authentication Policy + Silo
    try {
        New-SiloAuthPolicy -Name $silo.Name `
                            -Description $silo.Description `
                            -TGTLifetimeMinutes $silo.TGTLifetimeMinutes `
                            -Enforce ([bool]$silo.Enforce) `
                            -Server $targetServer `
                            -Credential $connection.Credential `
                            -LogDirectory $logDir `
                            -WhatIf:$WhatIfPreference
        $stats.SilosDeployed++
    }
    catch {
        Write-SiloLog -Message "Silo '$($silo.Name)' failed: $_" -Level Error -LogDirectory $logDir
        $stats.Errors++
        continue
    }

    # Assign computer accounts
    if ($silo.Computers -and $silo.Computers.Count -gt 0) {
        $validComputers = @($silo.Computers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($validComputers.Count -gt 0) {
            try {
                Add-SiloMember -SiloName $silo.Name `
                                -Accounts $validComputers `
                                -Server $targetServer `
                                -Credential $connection.Credential `
                                -LogDirectory $logDir `
                                -WhatIf:$WhatIfPreference
                $stats.AccountsAssigned += $validComputers.Count
            }
            catch {
                Write-SiloLog -Message "Computer assignment for '$($silo.Name)' failed: $_" -Level Error -LogDirectory $logDir
                $stats.Errors++
            }
        }
    }

    # Assign service accounts
    if ($silo.ServiceAccounts -and $silo.ServiceAccounts.Count -gt 0) {
        $validAccounts = @($silo.ServiceAccounts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($validAccounts.Count -gt 0) {
            try {
                Add-SiloMember -SiloName $silo.Name `
                                -Accounts $validAccounts `
                                -Server $targetServer `
                                -Credential $connection.Credential `
                                -LogDirectory $logDir `
                                -WhatIf:$WhatIfPreference
                $stats.AccountsAssigned += $validAccounts.Count
            }
            catch {
                Write-SiloLog -Message "Service account assignment for '$($silo.Name)' failed: $_" -Level Error -LogDirectory $logDir
                $stats.Errors++
            }
        }
    }
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

Write-Host "  Silos deployed$modeLabel      : $($stats.SilosDeployed)" -ForegroundColor Cyan
Write-Host "  Silos skipped (disabled) : $($stats.SilosSkipped)" -ForegroundColor Yellow
Write-Host "  Accounts assigned$modeLabel        : $($stats.AccountsAssigned)" -ForegroundColor Cyan

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
Write-SiloLog -Message "Deployment completed." -Level Info -LogDirectory $logDir
