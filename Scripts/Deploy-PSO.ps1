#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploys Fine-Grained Password Policies (PSO) in Active Directory.
.DESCRIPTION
    This script reads a JSON configuration file containing password policy definitions
    and creates Fine-Grained Password Policy objects. Each policy can be individually
    enabled or disabled in the configuration, and optionally applied to groups or users.
.PARAMETER ConfigPath
    Path to the JSON configuration file. Default: .\Config\PSO-Config.json
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
    .\Deploy-PSO.ps1
    .\Deploy-PSO.ps1 -ConfigPath "C:\Config\custom-pso.json"
    .\Deploy-PSO.ps1 -WhatIf
    .\Deploy-PSO.ps1 -Server dc01.forest.lol -Credential (Get-Credential)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "..\Config\PSO-Config.json"),
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

# Import PSO module
$modulePath = Join-Path $rootDir "Modules\PSO\PSO.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Host "[ERROR] PSO module not found: $modulePath" -ForegroundColor Red
    exit 1
}
Import-Module $modulePath -Force
Import-Module (Join-Path $rootDir "Modules\Common\Connection.psm1") -Force

$connection = Resolve-LOCKmeADConnection -Server $Server -Credential $Credential -Remember:$RememberConnection

# ============================================================================
# Load configuration
# ============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  PSO DEPLOYMENT TOOL - Active Directory" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

try {
    $config = Import-PSOConfiguration -ConfigPath $ConfigPath
    $logDir = $config.Settings.LogDirectory
    if (-not [System.IO.Path]::IsPathRooted($logDir)) {
        $logDir = Join-Path $rootDir $logDir
    }
    $runFolder = if ($global:LOCKmeAD_RunFolder) { $global:LOCKmeAD_RunFolder } else { Get-Date -Format 'yyyy-MM-dd_HH-mm-ss' }
    $logDir = Join-Path $logDir $runFolder
    Write-PSOLog -Message "Configuration loaded successfully from '$ConfigPath'." -Level Success -LogDirectory $logDir
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
    $envInfo = Get-PSOEnvironmentInfo -Server $connection.Server -Credential $connection.Credential
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
# Configuration summary
# ============================================================================

$enabledPolicies  = @($config.Policies | Where-Object { $_.Enabled -eq $true })
$disabledPolicies = @($config.Policies | Where-Object { $_.Enabled -eq $false })

Write-Host ""
Write-Host "--- Password Policies (PSO) ---" -ForegroundColor White
Write-Host ""
Write-Host "  Config file       : $ConfigPath" -ForegroundColor Cyan
Write-Host "  Log directory     : $logDir" -ForegroundColor Cyan
Write-Host "  Total policies    : $($config.Policies.Count)" -ForegroundColor Cyan
Write-Host "  Enabled           : $($enabledPolicies.Count)" -ForegroundColor Green
Write-Host "  Disabled          : $($disabledPolicies.Count)" -ForegroundColor Yellow
Write-Host ""

foreach ($policy in $config.Policies) {
    $subjectCount = if ($policy.AppliesTo) { $policy.AppliesTo.Count } else { 0 }
    $detail = "Precedence: $($policy.Precedence), $subjectCount subjects"

    if ($policy.Enabled) {
        Write-Host "    [ON]  $($policy.Name)" -ForegroundColor Green -NoNewline
        Write-Host " ($detail)" -ForegroundColor DarkGreen -NoNewline
        Write-Host " - $($policy.Description)" -ForegroundColor Cyan
    }
    else {
        Write-Host "    [OFF] $($policy.Name)" -ForegroundColor DarkGray -NoNewline
        Write-Host " - $($policy.Description)" -ForegroundColor DarkGray
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
        Write-PSOLog -Message "Deployment cancelled by user." -Level Warning -LogDirectory $logDir
        exit 0
    }
    Write-Host ""
}

# ============================================================================
# Deploy PSOs
# ============================================================================

Write-PSOLog -Message "Starting PSO deployment..." -Level Info -LogDirectory $logDir
Write-Host ""

$stats = @{
    PoliciesCreated  = 0
    PoliciesSkipped  = 0
    SubjectsApplied  = 0
    Errors           = 0
}

foreach ($policy in $config.Policies) {
    if (-not $policy.Enabled) {
        $stats.PoliciesSkipped++
        continue
    }

    Write-PSOLog -Message "=== PSO: $($policy.Name) ===" -Level Info -LogDirectory $logDir

    # Create or update the PSO
    try {
        New-PSOPasswordPolicy -Name $policy.Name `
                               -Description $policy.Description `
                               -Precedence $policy.Precedence `
                               -ComplexityEnabled ([bool]$policy.ComplexityEnabled) `
                               -MinPasswordLength $policy.MinPasswordLength `
                               -MinPasswordAgeDays $policy.MinPasswordAgeDays `
                               -MaxPasswordAgeDays $policy.MaxPasswordAgeDays `
                               -PasswordHistoryCount $policy.PasswordHistoryCount `
                               -LockoutThreshold $policy.LockoutThreshold `
                               -LockoutDurationMinutes $policy.LockoutDurationMinutes `
                               -LockoutObservationWindowMinutes $policy.LockoutObservationWindowMinutes `
                               -ReversibleEncryptionEnabled ([bool]$policy.ReversibleEncryptionEnabled) `
                               -ProtectedFromAccidentalDeletion ([bool]$policy.ProtectedFromAccidentalDeletion) `
                               -Server $targetServer `
                               -Credential $connection.Credential `
                               -LogDirectory $logDir `
                               -WhatIf:$WhatIfPreference
        $stats.PoliciesCreated++
    }
    catch {
        Write-PSOLog -Message "PSO '$($policy.Name)' failed: $_" -Level Error -LogDirectory $logDir
        $stats.Errors++
        continue
    }

    # Apply to subjects
    if ($policy.AppliesTo -and $policy.AppliesTo.Count -gt 0) {
        $validSubjects = @($policy.AppliesTo | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($validSubjects.Count -gt 0) {
            try {
                Add-PSOSubject -PolicyName $policy.Name `
                                -Subjects $validSubjects `
                                -Server $targetServer `
                                -Credential $connection.Credential `
                                -LogDirectory $logDir `
                                -WhatIf:$WhatIfPreference
                $stats.SubjectsApplied += $validSubjects.Count
            }
            catch {
                Write-PSOLog -Message "Subject assignment for '$($policy.Name)' failed: $_" -Level Error -LogDirectory $logDir
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

Write-Host "  PSOs deployed$modeLabel       : $($stats.PoliciesCreated)" -ForegroundColor Cyan
Write-Host "  PSOs skipped (disabled) : $($stats.PoliciesSkipped)" -ForegroundColor Yellow
Write-Host "  Subjects applied        : $($stats.SubjectsApplied)" -ForegroundColor Cyan

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
Write-PSOLog -Message "Deployment completed." -Level Info -LogDirectory $logDir
