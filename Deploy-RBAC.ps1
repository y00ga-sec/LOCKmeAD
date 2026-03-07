#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploys RBAC roles in Active Directory using the AGDLP method.
.DESCRIPTION
    This script reads a JSON configuration file, creates Global and DomainLocal groups,
    establishes AGDLP memberships, and applies permissions (NTFS and AD delegation).
.PARAMETER ConfigPath
    Path to the JSON configuration file. Default: .\Config\RBAC-Config.json
.PARAMETER WhatIf
    Simulation mode: displays actions without executing them.
.EXAMPLE
    .\Deploy-RBAC.ps1
    .\Deploy-RBAC.ps1 -ConfigPath "C:\Config\custom.json"
    .\Deploy-RBAC.ps1 -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "Config\RBAC-Config.json")
)

# ============================================================================
# Initialization
# ============================================================================

$ErrorActionPreference = "Stop"

# Import RBAC module
$modulePath = Join-Path $PSScriptRoot "Modules\RBAC\RBAC.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Host "[ERROR] RBAC module not found: $modulePath" -ForegroundColor Red
    exit 1
}
Import-Module $modulePath -Force

# ============================================================================
# Load configuration
# ============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  RBAC DEPLOYMENT TOOL - Active Directory (AGDLP)" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

try {
    $config = Import-RBACConfiguration -ConfigPath $ConfigPath
    $logDir = $config.Settings.LogDirectory
    if (-not [System.IO.Path]::IsPathRooted($logDir)) {
        $logDir = Join-Path $PSScriptRoot $logDir
    }
    Write-RBACLog -Message "Configuration loaded successfully from '$ConfigPath'." -Level Success -LogDirectory $logDir
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
    $envInfo = Get-RBACEnvironmentInfo

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

Write-Host ""
Write-Host "--- Configuration to deploy ---" -ForegroundColor White
Write-Host ""
Write-Host "  Config file       : $ConfigPath" -ForegroundColor Cyan
Write-Host "  Global prefix     : $($config.Settings.GroupPrefixes.Global)" -ForegroundColor Cyan
Write-Host "  DomainLocal prefix: $($config.Settings.GroupPrefixes.DomainLocal)" -ForegroundColor Cyan
Write-Host "  Default Global OU : $($config.Settings.DefaultOU.Global)" -ForegroundColor Cyan
Write-Host "  Default DL OU     : $($config.Settings.DefaultOU.DomainLocal)" -ForegroundColor Cyan
Write-Host "  Number of roles   : $($config.Roles.Count)" -ForegroundColor Cyan
Write-Host "  Log directory     : $logDir" -ForegroundColor Cyan

Write-Host ""
Write-Host "  Roles:" -ForegroundColor White
foreach ($role in $config.Roles) {
    $dlCount = $role.DomainLocalGroups.Count
    $permCount = ($role.DomainLocalGroups | ForEach-Object { $_.Permissions.Count } | Measure-Object -Sum).Sum
    Write-Host "    - $($role.Name) : 1 GG + $dlCount DL, $permCount permission(s)" -ForegroundColor Cyan
}

if ($config.RootGroups) {
    Write-Host ""
    Write-Host "  Root groups (DL -> DL nesting):" -ForegroundColor White
    foreach ($rootGroup in $config.RootGroups) {
        $memberOfCount = $rootGroup.MemberOf.Count
        Write-Host "    - $($rootGroup.Name) : member of $memberOfCount DL group(s)" -ForegroundColor Cyan
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
        Write-RBACLog -Message "Deployment cancelled by user." -Level Warning -LogDirectory $logDir
        exit 0
    }
    Write-Host ""
}

# ============================================================================
# Execute deployment
# ============================================================================

Write-RBACLog -Message "Starting RBAC deployment..." -Level Info -LogDirectory $logDir
Write-Host ""

$stats = @{
    GroupsCreated            = 0
    MembershipsSet           = 0
    RootGroupsMemberships    = 0
    NTFSPermissionsSet       = 0
    ADPermissionsSet         = 0
    ADCSPermissionsSet       = 0
    Errors                   = 0
}

foreach ($role in $config.Roles) {
    Write-RBACLog -Message "=== Processing role '$($role.Name)' ===" -Level Info -LogDirectory $logDir

    # --- Global Group ---
    $ggOU = if ($role.GlobalGroup.OU) { $role.GlobalGroup.OU } else { $config.Settings.DefaultOU.Global }

    try {
        New-RBACGroup -Name $role.GlobalGroup.Name `
                      -Description $role.GlobalGroup.Description `
                      -GroupScope Global `
                      -OU $ggOU `
                      -LogDirectory $logDir `
                      -WhatIf:$WhatIfPreference
        $stats.GroupsCreated++
    }
    catch {
        Write-RBACLog -Message "Failed to create Global group '$($role.GlobalGroup.Name)': $_" -Level Error -LogDirectory $logDir
        $stats.Errors++
        continue
    }

    # --- Domain Local Groups ---
    foreach ($dlGroup in $role.DomainLocalGroups) {
        $dlOU = if ($dlGroup.OU) { $dlGroup.OU } else { $config.Settings.DefaultOU.DomainLocal }

        # Create DL group
        try {
            New-RBACGroup -Name $dlGroup.Name `
                          -Description $dlGroup.Description `
                          -GroupScope DomainLocal `
                          -OU $dlOU `
                          -LogDirectory $logDir `
                          -WhatIf:$WhatIfPreference
            $stats.GroupsCreated++
        }
        catch {
            Write-RBACLog -Message "Failed to create DL group '$($dlGroup.Name)': $_" -Level Error -LogDirectory $logDir
            $stats.Errors++
            continue
        }

        # Add GG into DL (AGDLP)
        try {
            Add-RBACGroupMember -GlobalGroupName $role.GlobalGroup.Name `
                                -DomainLocalGroupName $dlGroup.Name `
                                -LogDirectory $logDir `
                                -WhatIf:$WhatIfPreference
            $stats.MembershipsSet++
        }
        catch {
            Write-RBACLog -Message "Failed to add membership '$($role.GlobalGroup.Name)' -> '$($dlGroup.Name)': $_" -Level Error -LogDirectory $logDir
            $stats.Errors++
        }

        # Apply permissions
        foreach ($perm in $dlGroup.Permissions) {
            try {
                switch ($perm.Type) {
                    "NTFS" {
                        Set-RBACNTFSPermission -GroupName $dlGroup.Name `
                                               -Permission $perm `
                                               -LogDirectory $logDir `
                                               -WhatIf:$WhatIfPreference
                        $stats.NTFSPermissionsSet++
                    }
                    "AD" {
                        Set-RBACADPermission -GroupName $dlGroup.Name `
                                             -Permission $perm `
                                             -LogDirectory $logDir `
                                             -WhatIf:$WhatIfPreference
                        $stats.ADPermissionsSet++
                    }
                    "ADCS" {
                        Set-RBACADCSPermission -GroupName $dlGroup.Name `
                                               -Permission $perm `
                                               -LogDirectory $logDir `
                                               -WhatIf:$WhatIfPreference
                        $stats.ADCSPermissionsSet++
                    }
                    default {
                        Write-RBACLog -Message "Unknown permission type: '$($perm.Type)'" -Level Warning -LogDirectory $logDir
                    }
                }
            }
            catch {
                Write-RBACLog -Message "Failed to apply permission '$($perm.Type)' on '$($dlGroup.Name)': $_" -Level Error -LogDirectory $logDir
                $stats.Errors++
            }
        }
    }
}

# ============================================================================
# Root groups (DL -> DL nesting)
# ============================================================================

if ($config.RootGroups) {
    Write-Host ""
    Write-RBACLog -Message "=== Processing root groups ===" -Level Info -LogDirectory $logDir

    foreach ($rootGroup in $config.RootGroups) {
        $rgOU = if ($rootGroup.OU) { $rootGroup.OU } else { $config.Settings.DefaultOU.DomainLocal }

        # Create root group (DomainLocal)
        try {
            New-RBACGroup -Name $rootGroup.Name `
                          -Description $rootGroup.Description `
                          -GroupScope DomainLocal `
                          -OU $rgOU `
                          -LogDirectory $logDir `
                          -WhatIf:$WhatIfPreference
            $stats.GroupsCreated++
        }
        catch {
            Write-RBACLog -Message "Failed to create root group '$($rootGroup.Name)': $_" -Level Error -LogDirectory $logDir
            $stats.Errors++
            continue
        }

        # Add root group into each target DL group (DL -> DL nesting)
        foreach ($targetDL in $rootGroup.MemberOf) {
            try {
                Add-RBACGroupMember -GlobalGroupName $rootGroup.Name `
                                    -DomainLocalGroupName $targetDL `
                                    -LogDirectory $logDir `
                                    -WhatIf:$WhatIfPreference
                $stats.RootGroupsMemberships++
            }
            catch {
                Write-RBACLog -Message "Failed to add root membership '$($rootGroup.Name)' -> '$targetDL': $_" -Level Error -LogDirectory $logDir
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

Write-Host "  Groups created$modeLabel          : $($stats.GroupsCreated)" -ForegroundColor Cyan
Write-Host "  AGDLP memberships$modeLabel       : $($stats.MembershipsSet)" -ForegroundColor Cyan
Write-Host "  Root memberships$modeLabel        : $($stats.RootGroupsMemberships)" -ForegroundColor Cyan
Write-Host "  NTFS permissions$modeLabel        : $($stats.NTFSPermissionsSet)" -ForegroundColor Cyan
Write-Host "  AD delegations$modeLabel          : $($stats.ADPermissionsSet)" -ForegroundColor Cyan
Write-Host "  ADCS permissions$modeLabel        : $($stats.ADCSPermissionsSet)" -ForegroundColor Cyan

if ($stats.Errors -gt 0) {
    Write-Host "  Errors                     : $($stats.Errors)" -ForegroundColor Red
}
else {
    Write-Host "  Errors                     : 0" -ForegroundColor Green
}

Write-Host ""
if ($script:LogFilePath) {
    Write-Host "  Log file: $($script:LogFilePath)" -ForegroundColor Cyan
}
Write-Host ""
Write-RBACLog -Message "Deployment completed." -Level Info -LogDirectory $logDir
