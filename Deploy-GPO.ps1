#Requires -Modules ActiveDirectory, GroupPolicy
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploys security GPOs from JSON templates.
.DESCRIPTION
    This script reads a JSON configuration file containing GPO templates and creates
    Group Policy Objects with registry-based security settings. Each GPO can be
    individually enabled or disabled in the configuration, and optionally linked
    to target OUs.
.PARAMETER ConfigPath
    Path to the JSON configuration file. Default: .\Config\GPO-Config.json
.PARAMETER WhatIf
    Simulation mode: displays actions without executing them.
.EXAMPLE
    .\Deploy-GPO.ps1
    .\Deploy-GPO.ps1 -ConfigPath "C:\Config\custom-gpo.json"
    .\Deploy-GPO.ps1 -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "Config\GPO-Config.json")
)

# ============================================================================
# Initialization
# ============================================================================

$ErrorActionPreference = "Stop"

# Import GPO module
$modulePath = Join-Path $PSScriptRoot "Modules\GPO\GPO.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Host "[ERROR] GPO module not found: $modulePath" -ForegroundColor Red
    exit 1
}
Import-Module $modulePath -Force

# ============================================================================
# Load configuration
# ============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  GPO DEPLOYMENT TOOL - Active Directory" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

try {
    $config = Import-GPOConfiguration -ConfigPath $ConfigPath
    $logDir = $config.Settings.LogDirectory
    if (-not [System.IO.Path]::IsPathRooted($logDir)) {
        $logDir = Join-Path $PSScriptRoot $logDir
    }
    Write-GPOLog -Message "Configuration loaded successfully from '$ConfigPath'." -Level Success -LogDirectory $logDir
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
    $envInfo = Get-GPOEnvironmentInfo

    Write-Host "  Current DC        : $($envInfo.CurrentDC)" -ForegroundColor Cyan
    if ($envInfo.IsPDC) {
        Write-Host "  PDC Role          : YES (this DC is the PDC Emulator)" -ForegroundColor Green
    }
    else {
        Write-Host "  PDC Role          : NO (PDC = $($envInfo.PDCEmulator))" -ForegroundColor Yellow
    }
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
# Configuration summary
# ============================================================================

$enabledGPOs  = @($config.GPOs | Where-Object { $_.Enabled -eq $true })
$disabledGPOs = @($config.GPOs | Where-Object { $_.Enabled -eq $false })

Write-Host ""
Write-Host "--- Security GPO Templates ---" -ForegroundColor White
Write-Host ""
Write-Host "  Config file       : $ConfigPath" -ForegroundColor Cyan
Write-Host "  Log directory     : $logDir" -ForegroundColor Cyan
Write-Host "  Total GPOs        : $($config.GPOs.Count)" -ForegroundColor Cyan
Write-Host "  Enabled           : $($enabledGPOs.Count)" -ForegroundColor Green
Write-Host "  Disabled          : $($disabledGPOs.Count)" -ForegroundColor Yellow
Write-Host ""

foreach ($gpo in $config.GPOs) {
    $regCount = if ($gpo.RegistrySettings) { $gpo.RegistrySettings.Count } else { 0 }
    $uraCount = if ($gpo.UserRightsAssignments) { $gpo.UserRightsAssignments.Count } else { 0 }
    $linkCount = if ($gpo.LinkTargets) { $gpo.LinkTargets.Count } else { 0 }

    $parts = @()
    if ($regCount -gt 0) { $parts += "$regCount reg" }
    if ($uraCount -gt 0) { $parts += "$uraCount URA" }
    $parts += "$linkCount links"
    $detail = $parts -join ', '

    if ($gpo.Enabled) {
        Write-Host "    [ON]  $($gpo.Name)" -ForegroundColor Green -NoNewline
        Write-Host " ($detail)" -ForegroundColor DarkGreen -NoNewline
        Write-Host " - $($gpo.Description)" -ForegroundColor Cyan
    }
    else {
        Write-Host "    [OFF] $($gpo.Name)" -ForegroundColor DarkGray -NoNewline
        Write-Host " - $($gpo.Description)" -ForegroundColor DarkGray
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

if (-not $WhatIfPreference) {
    Write-Host ""
    $confirmation = Read-Host "Confirm deployment? (Y/N)"
    if ($confirmation -notin @("Y", "y", "Yes", "yes")) {
        Write-GPOLog -Message "Deployment cancelled by user." -Level Warning -LogDirectory $logDir
        exit 0
    }
    Write-Host ""
}

# ============================================================================
# Deploy GPOs
# ============================================================================

Write-GPOLog -Message "Starting GPO deployment..." -Level Info -LogDirectory $logDir
Write-Host ""

$stats = @{
    GPOsCreated = 0
    GPOsSkipped = 0
    LinksCreated = 0
    Errors       = 0
}

foreach ($gpo in $config.GPOs) {
    if (-not $gpo.Enabled) {
        $stats.GPOsSkipped++
        continue
    }

    Write-GPOLog -Message "=== GPO: $($gpo.Name) ===" -Level Info -LogDirectory $logDir

    # Create GPO and apply registry settings
    try {
        $regSettings = if ($gpo.RegistrySettings) { $gpo.RegistrySettings } else { @() }
        New-GPOSecurityPolicy -Name $gpo.Name `
                               -Description $gpo.Description `
                               -RegistrySettings $regSettings `
                               -LogDirectory $logDir `
                               -WhatIf:$WhatIfPreference
        $stats.GPOsCreated++
    }
    catch {
        Write-GPOLog -Message "GPO '$($gpo.Name)' failed: $_" -Level Error -LogDirectory $logDir
        $stats.Errors++
        continue
    }

    # Apply User Rights Assignments
    if ($gpo.UserRightsAssignments -and $gpo.UserRightsAssignments.Count -gt 0) {
        try {
            Set-GPOUserRightsAssignment -GPOName $gpo.Name `
                                         -Assignments $gpo.UserRightsAssignments `
                                         -LogDirectory $logDir `
                                         -WhatIf:$WhatIfPreference
        }
        catch {
            Write-GPOLog -Message "URA for '$($gpo.Name)' failed: $_" -Level Error -LogDirectory $logDir
            $stats.Errors++
        }
    }

    # Link GPO to target OUs
    if ($gpo.LinkTargets -and $gpo.LinkTargets.Count -gt 0) {
        foreach ($target in $gpo.LinkTargets) {
            if ([string]::IsNullOrWhiteSpace($target)) { continue }
            try {
                Set-GPOLink -GPOName $gpo.Name `
                             -TargetOU $target `
                             -LogDirectory $logDir `
                             -WhatIf:$WhatIfPreference
                $stats.LinksCreated++
            }
            catch {
                Write-GPOLog -Message "Link '$($gpo.Name)' -> '$target' failed: $_" -Level Error -LogDirectory $logDir
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

Write-Host "  GPOs deployed$modeLabel       : $($stats.GPOsCreated)" -ForegroundColor Cyan
Write-Host "  GPOs skipped (disabled) : $($stats.GPOsSkipped)" -ForegroundColor Yellow
Write-Host "  Links created           : $($stats.LinksCreated)" -ForegroundColor Cyan

if ($stats.Errors -gt 0) {
    Write-Host "  Errors                  : $($stats.Errors)" -ForegroundColor Red
}
else {
    Write-Host "  Errors                  : 0" -ForegroundColor Green
}

Write-Host ""
if ($script:LogFilePath) {
    Write-Host "  Log file: $($script:LogFilePath)" -ForegroundColor Cyan
}
Write-Host ""
Write-GPOLog -Message "Deployment completed." -Level Info -LogDirectory $logDir
