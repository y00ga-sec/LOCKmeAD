#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploys Active Directory hardening remediation tasks.
.DESCRIPTION
    This script reads a JSON configuration file and executes a sequence of
    hardening tasks on the Active Directory environment. Each task can be
    individually enabled or disabled in the configuration.
.PARAMETER ConfigPath
    Path to the JSON configuration file. Default: .\Config\Hardening-Config.json
.PARAMETER WhatIf
    Simulation mode: displays actions without executing them.
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
    .\Deploy-Hardening.ps1
    .\Deploy-Hardening.ps1 -ConfigPath "C:\Config\custom-hardening.json"
    .\Deploy-Hardening.ps1 -WhatIf
    .\Deploy-Hardening.ps1 -Server dc01.forest.lol -Credential (Get-Credential)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "..\Config\Hardening-Config.json"),
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

# Import Hardening module
$modulePath = Join-Path $rootDir "Modules\Hardening\Hardening.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Host "[ERROR] Hardening module not found: $modulePath" -ForegroundColor Red
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
Write-Host "  HARDENING DEPLOYMENT TOOL - Active Directory" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

try {
    $config = Import-HardeningConfiguration -ConfigPath $ConfigPath
    $logDir = $config.Settings.LogDirectory
    if (-not [System.IO.Path]::IsPathRooted($logDir)) {
        $logDir = Join-Path $rootDir $logDir
    }
    $runFolder = if ($global:LOCKmeAD_RunFolder) { $global:LOCKmeAD_RunFolder } else { Get-Date -Format 'yyyy-MM-dd_HH-mm-ss' }
    $logDir = Join-Path $logDir $runFolder
    Write-HardeningLog -Message "Configuration loaded successfully from '$ConfigPath'." -Level Success -LogDirectory $logDir
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
    $envInfo = Get-HardeningEnvironmentInfo -Server $connection.Server -Credential $connection.Credential
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
# The same in-memory retargeting the GUI performs at start-up, so a configuration written against
# one domain deploys against another instead of failing DN by DN. It sits before the summary below
# because that summary displays -- and in some modules validates against AD -- the very values
# being corrected. $ConfigPath itself is never rewritten: see Sync-LOCKmeADConfigDomain.
$domainRetargeting = Sync-LOCKmeADConfigDomain -Config $config -ConfigPath $ConfigPath `
                        -Server $targetServer -Credential $connection.Credential
if ($domainRetargeting.Count -gt 0) {
    Write-HardeningLog -Message "$($domainRetargeting.Count) value(s) retargeted onto $($envInfo.DomainDN) for this run; '$ConfigPath' is left unchanged." -Level Warning -LogDirectory $logDir
}

# ============================================================================
# Configuration summary
# ============================================================================

$enabledTasks  = @($config.Tasks | Where-Object { $_.Enabled -eq $true })
$disabledTasks = @($config.Tasks | Where-Object { $_.Enabled -eq $false })

Write-Host ""
Write-Host "--- Hardening tasks ---" -ForegroundColor White
Write-Host ""
Write-Host "  Config file       : $ConfigPath" -ForegroundColor Cyan
Write-Host "  Log directory     : $logDir" -ForegroundColor Cyan
Write-Host "  Total tasks       : $($config.Tasks.Count)" -ForegroundColor Cyan
Write-Host "  Enabled           : $($enabledTasks.Count)" -ForegroundColor Green
Write-Host "  Disabled          : $($disabledTasks.Count)" -ForegroundColor Yellow
Write-Host ""

foreach ($task in $config.Tasks) {
    if ($task.Enabled) {
        Write-Host "    [ON]  $($task.Name)" -ForegroundColor Green -NoNewline
        Write-Host " - $($task.Description)" -ForegroundColor Cyan
    }
    else {
        Write-Host "    [OFF] $($task.Name)" -ForegroundColor DarkGray -NoNewline
        Write-Host " - $($task.Description)" -ForegroundColor DarkGray
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
        Write-HardeningLog -Message "Deployment cancelled by user." -Level Warning -LogDirectory $logDir
        exit 0
    }
    Write-Host ""
}

# ============================================================================
# Execute hardening tasks
# ============================================================================

Write-HardeningLog -Message "Starting Hardening deployment..." -Level Info -LogDirectory $logDir
Write-Host ""

$stats = @{
    TasksExecuted = 0
    TasksSkipped  = 0
    Errors        = 0
}

foreach ($task in $config.Tasks) {
    if (-not $task.Enabled) {
        $stats.TasksSkipped++
        continue
    }

    Write-HardeningLog -Message "=== Task: $($task.Name) ===" -Level Info -LogDirectory $logDir

    try {
        switch ($task.Name) {
            'SetMachineAccountQuota' {
                Set-HardeningMachineAccountQuota -Server $targetServer -Credential $connection.Credential `
                                                  -LogDirectory $logDir `
                                                  -WhatIf:$WhatIfPreference
            }
            'RaiseDomainFunctionalLevel' {
                Set-HardeningDomainFunctionalLevel -TargetDomainLevel $task.Parameters.TargetDomainLevel `
                                                    -Server $targetServer -Credential $connection.Credential `
                                                    -LogDirectory $logDir `
                                                    -WhatIf:$WhatIfPreference
            }
            'RaiseForestFunctionalLevel' {
                Set-HardeningForestFunctionalLevel -TargetForestLevel $task.Parameters.TargetForestLevel `
                                                    -Server $targetServer -Credential $connection.Credential `
                                                    -LogDirectory $logDir `
                                                    -WhatIf:$WhatIfPreference
            }
            'EnableRecycleBin' {
                Enable-HardeningRecycleBin -Server $targetServer -Credential $connection.Credential `
                                            -LogDirectory $logDir `
                                            -WhatIf:$WhatIfPreference
            }
            'EnablePAMFeature' {
                Enable-HardeningPAMFeature -Server $targetServer -Credential $connection.Credential `
                                            -LogDirectory $logDir `
                                            -WhatIf:$WhatIfPreference
            }
            'DisableAnonymousAccess' {
                Disable-HardeningAnonymousAccess -Server $targetServer -Credential $connection.Credential `
                                                  -LogDirectory $logDir `
                                                  -WhatIf:$WhatIfPreference
            }
            'DeployT0AuthPolicy' {
                $enforce = if ($null -ne $task.Parameters.Enforce) { $task.Parameters.Enforce } else { $true }
                $tgtLifetime = if ($task.Parameters.TGTLifetimeMinutes) { $task.Parameters.TGTLifetimeMinutes } else { 240 }

                New-HardeningT0AuthPolicy -PolicyName $task.Parameters.PolicyName `
                                           -SiloName $task.Parameters.SiloName `
                                           -TGTLifetimeMinutes $tgtLifetime `
                                           -Enforce $enforce `
                                           -Server $targetServer -Credential $connection.Credential `
                                           -LogDirectory $logDir `
                                           -WhatIf:$WhatIfPreference
            }
            'EnableReplicationNotify' {
                Set-HardeningReplicationNotify -Server $targetServer -Credential $connection.Credential `
                                                -LogDirectory $logDir `
                                               -WhatIf:$WhatIfPreference
            }
            'ConfigureCentralStore' {
                Set-HardeningCentralStore -Server $targetServer -Credential $connection.Credential `
                                           -LogDirectory $logDir `
                                           -WhatIf:$WhatIfPreference
            }
            'ExtendLAPSSchema' {
                Update-HardeningLAPSSchema -Server $targetServer -Credential $connection.Credential `
                                            -LogDirectory $logDir `
                                            -WhatIf:$WhatIfPreference
            }
            'ConfigureLAPSADPermissions' {
                # The Set-LapsAD* cmdlets have no -Credential parameter, so the credential is
                # honored by dispatching each call to $targetServer over WinRM — see
                # Invoke-HardeningLapsCommand in the Hardening module.
                Set-HardeningLAPSADPermissions `
                    -SelfPermissionOUs       @($task.Parameters.SelfPermissionOUs) `
                    -ReadPasswordOUs         @($task.Parameters.ReadPasswordOUs) `
                    -ReadPasswordPrincipals  @($task.Parameters.ReadPasswordPrincipals) `
                    -ResetPasswordOUs        @($task.Parameters.ResetPasswordOUs) `
                    -ResetPasswordPrincipals @($task.Parameters.ResetPasswordPrincipals) `
                    -Server $targetServer -Credential $connection.Credential `
                    -LogDirectory $logDir `
                    -WhatIf:$WhatIfPreference
            }
            'RestrictDNSDynamicUpdate' {
                Set-HardeningDNSDynamicUpdate -Server $targetServer -Credential $connection.Credential `
                                               -LogDirectory $logDir `
                                               -WhatIf:$WhatIfPreference
            }
            'AddDNSSecurityRecords' {
                Set-HardeningDNSSecurityRecords -ZoneName $task.Parameters.ZoneName `
                                                -WpadIPAddress $task.Parameters.WpadIPAddress `
                                                -WildcardTXTValue $task.Parameters.WildcardTXTValue `
                                                -Server $targetServer -Credential $connection.Credential `
                                                -LogDirectory $logDir `
                                                -WhatIf:$WhatIfPreference
            }
            'FixDNSRecordOwnership' {
                Set-HardeningDNSRecordOwnership -Server $targetServer -Credential $connection.Credential `
                                                -LogDirectory $logDir `
                                                -WhatIf:$WhatIfPreference
            }
            'ResetADObjectOwnership' {
                Set-HardeningADObjectOwnership -Server $targetServer -Credential $connection.Credential `
                                               -LogDirectory $logDir `
                                               -WhatIf:$WhatIfPreference
            }
        }
        $stats.TasksExecuted++
    }
    catch {
        Write-HardeningLog -Message "Task '$($task.Name)' failed: $_" -Level Error -LogDirectory $logDir
        $stats.Errors++
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

Write-Host "  Tasks executed$modeLabel         : $($stats.TasksExecuted)" -ForegroundColor Cyan
Write-Host "  Tasks skipped (disabled)  : $($stats.TasksSkipped)" -ForegroundColor Yellow

if ($stats.Errors -gt 0) {
    Write-Host "  Errors                    : $($stats.Errors)" -ForegroundColor Red
}
else {
    Write-Host "  Errors                    : 0" -ForegroundColor Green
}

Write-Host ""
if ($script:LogFilePath) {
    Write-Host "  Log file: $($script:LogFilePath)" -ForegroundColor Cyan
}
Write-Host ""
Write-HardeningLog -Message "Deployment completed." -Level Info -LogDirectory $logDir
