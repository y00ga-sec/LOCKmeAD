#Requires -Modules ActiveDirectory
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
    .\Deploy-GPO.ps1
    .\Deploy-GPO.ps1 -ConfigPath "C:\Config\custom-gpo.json"
    .\Deploy-GPO.ps1 -WhatIf
    .\Deploy-GPO.ps1 -Server dc01.forest.lol -Credential (Get-Credential)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "..\Config\GPO-Config.json"),
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

# Import GPO module
$modulePath = Join-Path $rootDir "Modules\GPO\GPO.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Host "[ERROR] GPO module not found: $modulePath" -ForegroundColor Red
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

# The GroupPolicy module is required in THIS session only in implicit mode. With an explicit
# credential every GroupPolicy cmdlet is executed on the target DC through a WinRM session
# (they accept no -Credential), so it only has to exist there. Hence a runtime check here
# rather than a static '#Requires -Modules GroupPolicy', which refused to start off-domain.
#
# The availability test goes through Test-LOCKmeADGroupPolicyModule rather than
# 'Get-Module -ListAvailable', which reports nothing under PowerShell 7 even when the module is
# installed and working -- see that function for the full reason.
if (-not $connection.Credential -and -not (Test-LOCKmeADGroupPolicyModule)) {
    Write-Host "`n[ERROR] The 'GroupPolicy' module is required to deploy GPOs in implicit mode." -ForegroundColor Red
    Write-Host "Install RSAT-GPMC on this host, or pass -Server/-Credential to run them on the DC.`n" -ForegroundColor Yellow
    exit 1
}
# Loaded up front instead of on first use: under -WhatIf, letting command discovery auto-load it
# fails outright -- see Import-LOCKmeADGroupPolicyModule for why.
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
Write-Host "  GPO DEPLOYMENT TOOL - Active Directory" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

try {
    $config = Import-GPOConfiguration -ConfigPath $ConfigPath
    $logDir = $config.Settings.LogDirectory
    if (-not [System.IO.Path]::IsPathRooted($logDir)) {
        $logDir = Join-Path $rootDir $logDir
    }
    $runFolder = if ($global:LOCKmeAD_RunFolder) { $global:LOCKmeAD_RunFolder } else { Get-Date -Format 'yyyy-MM-dd_HH-mm-ss' }
    $logDir = Join-Path $logDir $runFolder
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
    $envInfo = Get-GPOEnvironmentInfo -Server $connection.Server -Credential $connection.Credential
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
# See Deploy-Hardening.ps1 for the rationale. The ordering is not optional here: the summary below
# resolves FilteringGroupsOU against AD, and a DN still naming the previous domain would be found
# missing -- which does not merely warn, it disables filtering group deployment for the whole run
# while Authenticated Users is still removed, leaving every GPO applying to nobody.
$domainRetargeting = Sync-LOCKmeADConfigDomain -Config $config -ConfigPath $ConfigPath `
                        -Server $targetServer -Credential $connection.Credential
if ($domainRetargeting.Count -gt 0) {
    Write-GPOLog -Message "$($domainRetargeting.Count) value(s) retargeted onto $($envInfo.DomainDN) for this run; '$ConfigPath' is left unchanged." -Level Warning -LogDirectory $logDir
}

# ============================================================================
# Configuration summary
# ============================================================================

$enabledGPOs  = @($config.GPOs | Where-Object { $_.Enabled -eq $true })
$disabledGPOs = @($config.GPOs | Where-Object { $_.Enabled -eq $false })

# Validate Filtering Groups OU
$filteringOU = $config.Settings.FilteringGroupsOU
$filteringEnabled = -not [string]::IsNullOrWhiteSpace($filteringOU)
if ($filteringEnabled) {
    if ($filteringOU -notmatch '(?i)(tier|t)[-_. ]?(0|zero)') {
        Write-Host ""
        Write-Host "  [WARNING] FilteringGroupsOU '$filteringOU' does not reference a Tier 0 location. Consider placing filtering groups in a Tier 0 OU for proper security boundaries." -ForegroundColor Yellow
        Write-GPOLog -Message "FilteringGroupsOU '$filteringOU' does not reference a Tier 0 location. Filtering groups will still be deployed." -Level Warning -LogDirectory $logDir
    }
    # Verify the target exists in AD (target PDC to avoid replication lag when Tiering just created it).
    #
    # Resolved with Get-ADObject, NOT Get-ADOrganizationalUnit: despite the setting's name the
    # target does not have to be an organizationalUnit. CN=Users -- the domain's default group
    # container, and the value this config ships with -- has objectClass 'container', which
    # Get-ADOrganizationalUnit never matches, so the check raised ADIdentityNotFoundException on a
    # perfectly valid, existing target.
    #
    # The consequence was not a harmless warning. Filtering groups were skipped, while the else
    # branch further down still called Remove-GPOAuthenticatedUsers -- so every GPO deployed with
    # this setting ended up granted to nobody at all: Authenticated Users stripped, and no Apply
    # group created to take its place.
    #
    # Resolving is not sufficient on its own, so the class is checked too: a leaf object would
    # resolve here and only fail later inside New-ADGroup -Path, far from the setting that caused
    # it. ObjectClass comes back on Get-ADObject by default, no -Properties needed.
    try {
        $ouCheckParam = @{ Server = $targetServer }
        if ($connection.Credential) { $ouCheckParam.Credential = $connection.Credential }
        $filteringTarget = Get-ADObject -Identity $filteringOU @ouCheckParam -ErrorAction Stop

        $groupHolderClasses = @('organizationalUnit', 'container', 'domainDNS')
        if ($filteringTarget.ObjectClass -notin $groupHolderClasses) {
            Write-Host ""
            Write-Host "  [ERROR] FilteringGroupsOU '$filteringOU' is a '$($filteringTarget.ObjectClass)' object, which cannot contain groups. Filtering groups will NOT be deployed." -ForegroundColor Red
            Write-GPOLog -Message "FilteringGroupsOU '$filteringOU' resolved to objectClass '$($filteringTarget.ObjectClass)', which cannot hold group objects (expected one of: $($groupHolderClasses -join ', ')). Skipping filtering group deployment." -Level Error -LogDirectory $logDir
            $filteringEnabled = $false
        }
    }
    catch {
        Write-Host ""
        Write-Host "  [ERROR] FilteringGroupsOU '$filteringOU' not found in AD. Filtering groups will NOT be deployed." -ForegroundColor Red
        Write-GPOLog -Message "FilteringGroupsOU '$filteringOU' not found in AD (queried $targetServer). Skipping filtering group deployment." -Level Error -LogDirectory $logDir
        $filteringEnabled = $false
    }
}

Write-Host ""
Write-Host "--- Security GPO Templates ---" -ForegroundColor White
Write-Host ""
Write-Host "  Config file       : $ConfigPath" -ForegroundColor Cyan
Write-Host "  Log directory     : $logDir" -ForegroundColor Cyan
Write-Host "  Total GPOs        : $($config.GPOs.Count)" -ForegroundColor Cyan
Write-Host "  Enabled           : $($enabledGPOs.Count)" -ForegroundColor Green
Write-Host "  Disabled          : $($disabledGPOs.Count)" -ForegroundColor Yellow
if ($filteringEnabled) {
    Write-Host "  Filtering groups  : $filteringOU" -ForegroundColor Cyan
}
else {
    Write-Host "  Filtering groups  : (not configured)" -ForegroundColor DarkGray
}
Write-Host ""

foreach ($gpo in $config.GPOs) {
    $regCount = if ($gpo.RegistrySettings) { $gpo.RegistrySettings.Count } else { 0 }
    $regPrefCount = if ($gpo.RegistryPreferences) { $gpo.RegistryPreferences.Count } else { 0 }
    $secOptCount = if ($gpo.SecurityOptions) { $gpo.SecurityOptions.Count } else { 0 }
    $uraCount = if ($gpo.UserRightsAssignments) { $gpo.UserRightsAssignments.Count } else { 0 }
    $rgCount = if ($gpo.RestrictedGroups) { $gpo.RestrictedGroups.Count } else { 0 }
    $svcCount = if ($gpo.SystemServices) { $gpo.SystemServices.Count } else { 0 }
    $scriptCount = if ($gpo.Scripts) { $gpo.Scripts.Count } else { 0 }
    $linkCount = if ($gpo.LinkTargets) { $gpo.LinkTargets.Count } else { 0 }

    $parts = @()
    if ($regCount -gt 0) { $parts += "$regCount reg" }
    if ($regPrefCount -gt 0) { $parts += "$regPrefCount pref" }
    if ($secOptCount -gt 0) { $parts += "$secOptCount SO" }
    if ($uraCount -gt 0) { $parts += "$uraCount URA" }
    if ($rgCount -gt 0) { $parts += "$rgCount RG" }
    if ($svcCount -gt 0) { $parts += "$svcCount SVC" }
    if ($scriptCount -gt 0) { $parts += "$scriptCount script" }
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

if (-not $WhatIfPreference -and -not $NoConfirm) {
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

# Connection splat reused by the filtering group existence pre-checks below.
$connParam = @{ Server = $targetServer }
if ($connection.Credential) { $connParam.Credential = $connection.Credential }

function Test-GPOFilteringGroupPresent([string]$Name) {
    <#
    .SYNOPSIS
        Returns whether a filtering group already exists, so the caller can tell "created"
        from "already there" before calling New-GPOFilteringGroup.
    .DESCRIPTION
        New-GPOFilteringGroup returns the group object whether it created it or found an
        existing one, so incrementing the counter unconditionally made every re-run claim it
        had created all of them -- 44 groups on a 22-GPO config where nothing was created.
        Same defect, and same fix, as Deploy-RBAC.ps1 and Deploy-TieringOUStructure.

        -ErrorAction SilentlyContinue is NOT enough: Get-ADGroup -Identity raises
        ADIdentityNotFoundException as a TERMINATING error that SilentlyContinue does not
        suppress, hence the typed catch.
    #>
    try   { return $null -ne (Get-ADGroup -Identity $Name @connParam -ErrorAction Stop) }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { return $false }
}

$stats = @{
    GPOsCreated    = 0
    GPOsSkipped    = 0
    LinksCreated   = 0
    LinksExisting  = 0
    GroupsCreated  = 0
    GroupsExisting = 0
    Errors         = 0
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
        $gpoStatus = if ($gpo.GpoStatus) { $gpo.GpoStatus } else { "AllSettingsEnabled" }
        New-GPOSecurityPolicy -Name $gpo.Name `
                               -Description $gpo.Description `
                               -RegistrySettings $regSettings `
                               -GpoStatus $gpoStatus `
                               -Server $targetServer `
                                        -Credential $connection.Credential `
                               -LogDirectory $logDir `
                               -WhatIf:$WhatIfPreference
        $stats.GPOsCreated++
    }
    catch {
        Write-GPOLog -Message "GPO '$($gpo.Name)' failed: $_" -Level Error -LogDirectory $logDir
        $stats.Errors++
        continue
    }

    # Apply Registry Preferences
    if ($gpo.RegistryPreferences -and $gpo.RegistryPreferences.Count -gt 0) {
        try {
            Set-GPORegistryPreferences -GPOName $gpo.Name `
                                         -RegistryPreferences $gpo.RegistryPreferences `
                                         -Server $targetServer `
                                        -Credential $connection.Credential `
                                         -LogDirectory $logDir `
                                         -WhatIf:$WhatIfPreference
        }
        catch {
            Write-GPOLog -Message "Registry Preferences for '$($gpo.Name)' failed: $_" -Level Error -LogDirectory $logDir
            $stats.Errors++
        }
    }

    # Apply User Rights Assignments
    if ($gpo.UserRightsAssignments -and $gpo.UserRightsAssignments.Count -gt 0) {
        try {
            Set-GPOUserRightsAssignment -GPOName $gpo.Name `
                                         -Assignments $gpo.UserRightsAssignments `
                                         -Server $targetServer `
                                        -Credential $connection.Credential `
                                         -LogDirectory $logDir `
                                         -WhatIf:$WhatIfPreference
        }
        catch {
            Write-GPOLog -Message "URA for '$($gpo.Name)' failed: $_" -Level Error -LogDirectory $logDir
            $stats.Errors++
        }
    }

    # Apply Restricted Groups
    if ($gpo.RestrictedGroups -and $gpo.RestrictedGroups.Count -gt 0) {
        try {
            Set-GPORestrictedGroups -GPOName $gpo.Name `
                                     -RestrictedGroups $gpo.RestrictedGroups `
                                     -Server $targetServer `
                                        -Credential $connection.Credential `
                                     -LogDirectory $logDir `
                                     -WhatIf:$WhatIfPreference
        }
        catch {
            Write-GPOLog -Message "Restricted Groups for '$($gpo.Name)' failed: $_" -Level Error -LogDirectory $logDir
            $stats.Errors++
        }
    }

    # Apply Security Options
    if ($gpo.SecurityOptions -and $gpo.SecurityOptions.Count -gt 0) {
        try {
            Set-GPOSecurityOptions -GPOName $gpo.Name `
                                     -SecurityOptions $gpo.SecurityOptions `
                                     -Server $targetServer `
                                        -Credential $connection.Credential `
                                     -LogDirectory $logDir `
                                     -WhatIf:$WhatIfPreference
        }
        catch {
            Write-GPOLog -Message "Security Options for '$($gpo.Name)' failed: $_" -Level Error -LogDirectory $logDir
            $stats.Errors++
        }
    }

    # Apply System Services
    if ($gpo.SystemServices -and $gpo.SystemServices.Count -gt 0) {
        try {
            Set-GPOSystemServices -GPOName $gpo.Name `
                                    -SystemServices $gpo.SystemServices `
                                    -Server $targetServer `
                                        -Credential $connection.Credential `
                                    -LogDirectory $logDir `
                                    -WhatIf:$WhatIfPreference
        }
        catch {
            Write-GPOLog -Message "System Services for '$($gpo.Name)' failed: $_" -Level Error -LogDirectory $logDir
            $stats.Errors++
        }
    }

    # Deploy Scripts (Startup / Shutdown)
    if ($gpo.Scripts -and $gpo.Scripts.Count -gt 0) {
        try {
            Set-GPOScript -GPOName $gpo.Name `
                           -Scripts $gpo.Scripts `
                           -Server $targetServer `
                                        -Credential $connection.Credential `
                           -LogDirectory $logDir `
                           -WhatIf:$WhatIfPreference
        }
        catch {
            Write-GPOLog -Message "Scripts for '$($gpo.Name)' failed: $_" -Level Error -LogDirectory $logDir
            $stats.Errors++
        }
    }

    # Create filtering groups and set GPO permissions
    if ($filteringEnabled) {
        $applyGroupName = "GPO_Apply_$($gpo.Name)"
        $denyGroupName  = "GPO_Deny_$($gpo.Name)"

        try {
            $applyPresent = Test-GPOFilteringGroupPresent $applyGroupName
            $denyPresent  = Test-GPOFilteringGroupPresent $denyGroupName

            New-GPOFilteringGroup -Name $applyGroupName `
                                   -Description "Apply group for GPO '$($gpo.Name)'" `
                                   -OU $filteringOU `
                                   -Server $targetServer `
                                        -Credential $connection.Credential `
                                   -LogDirectory $logDir `
                                   -WhatIf:$WhatIfPreference
            New-GPOFilteringGroup -Name $denyGroupName `
                                   -Description "Deny group for GPO '$($gpo.Name)'" `
                                   -OU $filteringOU `
                                   -Server $targetServer `
                                        -Credential $connection.Credential `
                                   -LogDirectory $logDir `
                                   -WhatIf:$WhatIfPreference
            foreach ($wasPresent in @($applyPresent, $denyPresent)) {
                if ($wasPresent) { $stats.GroupsExisting++ } else { $stats.GroupsCreated++ }
            }

            Set-GPOFilteringPermission -GPOName $gpo.Name `
                                        -ApplyGroupName $applyGroupName `
                                        -DenyGroupName $denyGroupName `
                                        -Server $targetServer `
                                        -Credential $connection.Credential `
                                        -LogDirectory $logDir `
                                        -WhatIf:$WhatIfPreference
        }
        catch {
            Write-GPOLog -Message "Filtering groups for '$($gpo.Name)' failed: $_" -Level Error -LogDirectory $logDir
            $stats.Errors++
        }
    }
    else {
        # Filtering groups are not deployed, but Authenticated Users must still be removed
        # so the GPO cannot silently apply to every machine in linked OUs.
        try {
            Remove-GPOAuthenticatedUsers -GPOName $gpo.Name `
                                          -Server $targetServer `
                                        -Credential $connection.Credential `
                                          -LogDirectory $logDir `
                                          -WhatIf:$WhatIfPreference
        }
        catch {
            Write-GPOLog -Message "Failed to remove Authenticated Users from '$($gpo.Name)': $_" -Level Error -LogDirectory $logDir
            $stats.Errors++
        }
    }

    # Link GPO to target OUs
    if ($gpo.LinkTargets -and $gpo.LinkTargets.Count -gt 0) {
        foreach ($target in $gpo.LinkTargets) {
            if ([string]::IsNullOrWhiteSpace($target)) { continue }
            try {
                # Set-GPOLink reports whether it actually created the link ($false = the GPO
                # was already linked there), so a no-op re-run no longer reports links it
                # did not create.
                $linkCreated = Set-GPOLink -GPOName $gpo.Name `
                             -TargetOU $target `
                             -Server $targetServer `
                                        -Credential $connection.Credential `
                             -LogDirectory $logDir `
                             -WhatIf:$WhatIfPreference
                if ($linkCreated) { $stats.LinksCreated++ } else { $stats.LinksExisting++ }
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
Write-Host "  Filtering groups created: $($stats.GroupsCreated)" -ForegroundColor Cyan
Write-Host "  Filtering groups present: $($stats.GroupsExisting)" -ForegroundColor DarkGray
Write-Host "  Links created           : $($stats.LinksCreated)" -ForegroundColor Cyan
Write-Host "  Links already present   : $($stats.LinksExisting)" -ForegroundColor DarkGray

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
