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
    .\Deploy-RBAC.ps1
    .\Deploy-RBAC.ps1 -ConfigPath "C:\Config\custom.json"
    .\Deploy-RBAC.ps1 -WhatIf
    .\Deploy-RBAC.ps1 -Server dc01.forest.lol -Credential (Get-Credential)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "..\Config\RBAC-Config.json"),
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

# Import RBAC module
$modulePath = Join-Path $rootDir "Modules\RBAC\RBAC.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Host "[ERROR] RBAC module not found: $modulePath" -ForegroundColor Red
    exit 1
}
Import-Module $modulePath -Force
Import-Module (Join-Path $rootDir "Modules\Common\Connection.psm1") -Force

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
Write-Host "  RBAC DEPLOYMENT TOOL - Active Directory (AGDLP)" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

try {
    $config = Import-RBACConfiguration -ConfigPath $ConfigPath
    $logDir = $config.Settings.LogDirectory
    if (-not [System.IO.Path]::IsPathRooted($logDir)) {
        $logDir = Join-Path $rootDir $logDir
    }
    $runFolder = if ($global:LOCKmeAD_RunFolder) { $global:LOCKmeAD_RunFolder } else { Get-Date -Format 'yyyy-MM-dd_HH-mm-ss' }
    $logDir = Join-Path $logDir $runFolder
    Write-RBACLog -Message "Configuration loaded successfully from '$ConfigPath'." -Level Success -LogDirectory $logDir
    $logFilePath = Get-ChildItem $logDir -Filter "RBAC_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
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
    $envInfo = Get-RBACEnvironmentInfo -Server $connection.Server -Credential $connection.Credential
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
# Load GUID resolution maps
# ============================================================================

Write-Host ""
Write-Host "--- Loading GUID maps ---" -ForegroundColor White
Write-Host ""

try {
    Get-RBACGuidMap -Server $targetServer -Credential $connection.Credential
    Get-RBACExtendedRightMap -Server $targetServer -Credential $connection.Credential
    Write-RBACLog -Message "GUID maps loaded (schema attributes + extended rights)." -Level Success -LogDirectory $logDir
}
catch {
    Write-RBACLog -Message "Could not load GUID maps: $_. ObjectType/InheritedObjectType fields must contain raw GUIDs." -Level Warning -LogDirectory $logDir
}

$backupDir = Join-Path $logDir "Backups"

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
    Write-Host "  Root groups:" -ForegroundColor White
    foreach ($rootGroup in $config.RootGroups) {
        $membersCount = if ($rootGroup.Members) { $rootGroup.Members.Count } else { 0 }
        $memberOfCount = if ($rootGroup.MemberOf) { $rootGroup.MemberOf.Count } else { 0 }
        Write-Host "    - $($rootGroup.Name) : $membersCount GG members, member of $memberOfCount DL group(s)" -ForegroundColor Cyan
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

# Connection splat reused by the group existence pre-checks below.
$connParam = @{ Server = $targetServer }
if ($connection.Credential) { $connParam.Credential = $connection.Credential }

function Test-RBACGroupPresent([string]$Name) {
    <#
    .SYNOPSIS
        Returns whether an AD group already exists, so the caller can tell "created" from
        "already there" before calling New-RBACGroup.
    .DESCRIPTION
        New-RBACGroup returns the group object whether it created it or found it, so the
        caller cannot otherwise distinguish the two: a no-op re-run reported a full
        deployment, and a config that references the same DL group from two roles (which
        RBAC-Config.json does, by design) inflated the count even on a first run.

        -ErrorAction SilentlyContinue is NOT enough here: Get-ADGroup -Identity raises
        ADIdentityNotFoundException as a TERMINATING error, which SilentlyContinue does not
        suppress. Same typed-catch idiom, and for the same reason, as
        Deploy-TieringOUStructure.
    #>
    try   { return $null -ne (Get-ADGroup -Identity $Name @connParam -ErrorAction Stop) }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { return $false }
}

$stats = @{
    GroupsCreated            = 0
    GroupsExisting           = 0
    MembershipsSet           = 0
    RootGroupsMemberships    = 0
    NTFSPermissionsSet       = 0
    SharePermissionsSet      = 0
    ADPermissionsSet         = 0
    ADCSPermissionsSet       = 0
    Errors                   = 0
}

foreach ($role in $config.Roles) {
    Write-RBACLog -Message "=== Processing role '$($role.Name)' ===" -Level Info -LogDirectory $logDir

    # --- Global Group ---
    $ggOU = if ($role.GlobalGroup.OU) { $role.GlobalGroup.OU } else { $config.Settings.DefaultOU.Global }

    $ggPresent = Test-RBACGroupPresent $role.GlobalGroup.Name
    try {
        New-RBACGroup -Name $role.GlobalGroup.Name `
                      -Description $role.GlobalGroup.Description `
                      -GroupScope Global `
                      -OU $ggOU `
                      -Server $targetServer `
                                        -Credential $connection.Credential `
                      -LogDirectory $logDir `
                      -WhatIf:$WhatIfPreference
        if ($ggPresent) { $stats.GroupsExisting++ } else { $stats.GroupsCreated++ }
    }
    catch {
        Write-RBACLog -Message "Failed to create Global group '$($role.GlobalGroup.Name)': $_" -Level Error -LogDirectory $logDir
        $stats.Errors++
        continue
    }

    # Add GG into existing AD groups (MemberOf)
    if ($role.GlobalGroup.MemberOf) {
        foreach ($targetGroup in $role.GlobalGroup.MemberOf) {
            try {
                Add-RBACGroupMember -GlobalGroupName $role.GlobalGroup.Name `
                                    -DomainLocalGroupName $targetGroup `
                                    -Server $targetServer `
                                        -Credential $connection.Credential `
                                    -LogDirectory $logDir `
                                    -WhatIf:$WhatIfPreference
                $stats.MembershipsSet++
            }
            catch {
                Write-RBACLog -Message "Failed to add '$($role.GlobalGroup.Name)' -> '$targetGroup': $_" -Level Error -LogDirectory $logDir
                $stats.Errors++
            }
        }
    }

    # --- Domain Local Groups ---
    foreach ($dlGroup in $role.DomainLocalGroups) {
        $dlOU = if ($dlGroup.OU) { $dlGroup.OU } else { $config.Settings.DefaultOU.DomainLocal }

        # Create DL group
        $dlPresent = Test-RBACGroupPresent $dlGroup.Name
        try {
            New-RBACGroup -Name $dlGroup.Name `
                          -Description $dlGroup.Description `
                          -GroupScope DomainLocal `
                          -OU $dlOU `
                          -Server $targetServer `
                                        -Credential $connection.Credential `
                          -LogDirectory $logDir `
                          -WhatIf:$WhatIfPreference
            if ($dlPresent) { $stats.GroupsExisting++ } else { $stats.GroupsCreated++ }
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
                                -Server $targetServer `
                                        -Credential $connection.Credential `
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
                                               -Server $targetServer `
                                        -Credential $connection.Credential `
                                               -LogDirectory $logDir `
                                               -WhatIf:$WhatIfPreference
                        $stats.NTFSPermissionsSet++
                    }
                    "AD" {
                        Set-RBACADPermission -GroupName $dlGroup.Name `
                                             -Permission $perm `
                                             -Server $targetServer `
                                        -Credential $connection.Credential `
                                             -LogDirectory $logDir `
                                             -BackupDirectory $backupDir `
                                             -WhatIf:$WhatIfPreference
                        $stats.ADPermissionsSet++
                    }
                    "ADCS" {
                        Set-RBACADCSPermission -GroupName $dlGroup.Name `
                                               -Permission $perm `
                                               -Server $targetServer `
                                        -Credential $connection.Credential `
                                               -LogDirectory $logDir `
                                               -WhatIf:$WhatIfPreference
                        $stats.ADCSPermissionsSet++
                    }
                    "Share" {
                        Set-RBACSharePermission -GroupName $dlGroup.Name `
                                                -Permission $perm `
                                                -Server $targetServer `
                                        -Credential $connection.Credential `
                                                -LogDirectory $logDir `
                                                -WhatIf:$WhatIfPreference
                        $stats.SharePermissionsSet++
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
        $rgPresent = Test-RBACGroupPresent $rootGroup.Name
        try {
            New-RBACGroup -Name $rootGroup.Name `
                          -Description $rootGroup.Description `
                          -GroupScope DomainLocal `
                          -OU $rgOU `
                          -Server $targetServer `
                                        -Credential $connection.Credential `
                          -LogDirectory $logDir `
                          -WhatIf:$WhatIfPreference
            if ($rgPresent) { $stats.GroupsExisting++ } else { $stats.GroupsCreated++ }
        }
        catch {
            Write-RBACLog -Message "Failed to create root group '$($rootGroup.Name)': $_" -Level Error -LogDirectory $logDir
            $stats.Errors++
            continue
        }

        # Add GG groups into root group (GG -> DL_Tx nesting for tiering)
        if ($rootGroup.Members) {
            foreach ($ggName in $rootGroup.Members) {
                try {
                    Add-RBACGroupMember -GlobalGroupName $ggName `
                                        -DomainLocalGroupName $rootGroup.Name `
                                        -Server $targetServer `
                                        -Credential $connection.Credential `
                                        -LogDirectory $logDir `
                                        -WhatIf:$WhatIfPreference
                    $stats.RootGroupsMemberships++
                }
                catch {
                    Write-RBACLog -Message "Failed to add member '$ggName' -> '$($rootGroup.Name)': $_" -Level Error -LogDirectory $logDir
                    $stats.Errors++
                }
            }
        }

        # Add root group into each target DL group (DL -> DL nesting)
        if ($rootGroup.MemberOf) {
            foreach ($targetDL in $rootGroup.MemberOf) {
                try {
                    Add-RBACGroupMember -GlobalGroupName $rootGroup.Name `
                                        -DomainLocalGroupName $targetDL `
                                        -Server $targetServer `
                                        -Credential $connection.Credential `
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
Write-Host "  Groups already present     : $($stats.GroupsExisting)" -ForegroundColor DarkGray
Write-Host "  AGDLP memberships$modeLabel       : $($stats.MembershipsSet)" -ForegroundColor Cyan
Write-Host "  Root memberships$modeLabel        : $($stats.RootGroupsMemberships)" -ForegroundColor Cyan
Write-Host "  NTFS permissions$modeLabel        : $($stats.NTFSPermissionsSet)" -ForegroundColor Cyan
Write-Host "  Share permissions$modeLabel       : $($stats.SharePermissionsSet)" -ForegroundColor Cyan
Write-Host "  AD delegations$modeLabel          : $($stats.ADPermissionsSet)" -ForegroundColor Cyan
Write-Host "  ADCS permissions$modeLabel        : $($stats.ADCSPermissionsSet)" -ForegroundColor Cyan

if ($stats.Errors -gt 0) {
    Write-Host "  Errors                     : $($stats.Errors)" -ForegroundColor Red
}
else {
    Write-Host "  Errors                     : 0" -ForegroundColor Green
}

Write-Host ""
if ($logFilePath) {
    Write-Host "  Log file: $logFilePath" -ForegroundColor Cyan
}
Write-Host ""
Write-RBACLog -Message "Deployment completed." -Level Info -LogDirectory $logDir

# Generate CSV report from log
if ($logFilePath -and (Test-Path $logFilePath)) {
    $csvPath = Export-RBACDeploymentReport -LogPath $logFilePath
    if ($csvPath) {
        Write-Host "  CSV report: $csvPath" -ForegroundColor Cyan
        Write-Host ""
    }
}
