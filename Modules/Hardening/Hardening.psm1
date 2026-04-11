#Requires -Modules ActiveDirectory

# ============================================================================
# Hardening Module - Functions for deploying AD hardening remediation tasks
# ============================================================================

# Module variable for the current log file path
$script:LogFilePath = $null

function Write-HardeningLog {
    <#
    .SYNOPSIS
        Writes a message to the console and to a log file.
    .PARAMETER Message
        The message to write.
    .PARAMETER Level
        The message level: Info, Success, Warning, Error.
    .PARAMETER LogDirectory
        The directory where the log file is written.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Level = "Info",

        [string]$LogDirectory
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Console output with colors
    switch ($Level) {
        "Info"    { Write-Host $logEntry -ForegroundColor Cyan }
        "Success" { Write-Host $logEntry -ForegroundColor Green }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
    }

    # Write to log file
    if ($LogDirectory) {
        if (-not (Test-Path $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }
        if (-not $script:LogFilePath) {
            $logFileName = "Hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            $script:LogFilePath = Join-Path $LogDirectory $logFileName
        }
        $logEntry | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8
    }
}

# ============================================================================
# Configuration
# ============================================================================

function Import-HardeningConfiguration {
    <#
    .SYNOPSIS
        Reads and validates the hardening JSON configuration file.
    .PARAMETER ConfigPath
        Path to the JSON configuration file.
    .OUTPUTS
        PSCustomObject representing the configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigPath
    )

    if (-not (Test-Path $ConfigPath)) {
        throw "Configuration file '$ConfigPath' not found."
    }

    try {
        $config = Get-Content -Path $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "JSON parsing error in '$ConfigPath': $_"
    }

    # Structure validation
    if (-not $config.Settings) {
        throw "The 'Settings' section is missing from the configuration."
    }
    if (-not $config.Tasks -or $config.Tasks.Count -eq 0) {
        throw "The 'Tasks' section is missing or empty."
    }

    $validTaskNames = @(
        'SetMachineAccountQuota',
        'RaiseFunctionalLevel',
        'EnableRecycleBin',
        'EnablePAMFeature',
        'DisableAnonymousAccess',
        'DeployT0AuthPolicy',
        'EnableReplicationNotify',
        'ConfigureCentralStore',
        'ExtendLAPSSchema',
        'RestrictDNSDynamicUpdate'
    )

    foreach ($task in $config.Tasks) {
        if (-not $task.Name) {
            throw "A task is missing the 'Name' property."
        }
        if ($task.Name -notin $validTaskNames) {
            throw "Unknown task name: '$($task.Name)'. Valid names: $($validTaskNames -join ', ')"
        }
        if ($null -eq $task.Enabled) {
            throw "Task '$($task.Name)' is missing the 'Enabled' property."
        }

        # Validate required parameters per task
        switch ($task.Name) {
            'SetMachineAccountQuota' {
                if (-not $task.Parameters -or $null -eq $task.Parameters.Quota) {
                    throw "Task '$($task.Name)' requires Parameters.Quota."
                }
            }
            'RaiseFunctionalLevel' {
                if (-not $task.Parameters -or -not $task.Parameters.TargetDomainLevel -or -not $task.Parameters.TargetForestLevel) {
                    throw "Task '$($task.Name)' requires Parameters.TargetDomainLevel and Parameters.TargetForestLevel."
                }
            }
            'DeployT0AuthPolicy' {
                if (-not $task.Parameters -or -not $task.Parameters.PolicyName -or -not $task.Parameters.SiloName) {
                    throw "Task '$($task.Name)' requires Parameters.PolicyName and Parameters.SiloName."
                }
            }
        }
    }

    return $config
}

# ============================================================================
# Environment
# ============================================================================

function Get-HardeningEnvironmentInfo {
    <#
    .SYNOPSIS
        Retrieves Active Directory environment information.
    .OUTPUTS
        PSCustomObject with environment information.
    #>
    [CmdletBinding()]
    param()

    try {
        $domain = Get-ADDomain
        $forest = Get-ADForest
        $currentDC = $env:COMPUTERNAME
        $pdcEmulator = $domain.PDCEmulator

        $isPDC = $pdcEmulator -like "$currentDC.*"

        return [PSCustomObject]@{
            CurrentDC    = $currentDC
            IsPDC        = $isPDC
            PDCEmulator  = $pdcEmulator
            DomainName   = $domain.DNSRoot
            DomainDN     = $domain.DistinguishedName
            ForestName   = $forest.Name
            ForestMode   = $forest.ForestMode
            DomainMode   = $domain.DomainMode
        }
    }
    catch {
        throw "Unable to retrieve Active Directory information: $_"
    }
}

# ============================================================================
# Task: SetMachineAccountQuota
# ============================================================================

function Set-HardeningMachineAccountQuota {
    <#
    .SYNOPSIS
        Sets ms-DS-MachineAccountQuota to the specified value.
    .PARAMETER Quota
        The quota value to set (typically 0).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [int]$Quota,

        [string]$LogDirectory
    )

    $domainDN = (Get-ADDomain).DistinguishedName

    # Check current value
    $currentQuota = (Get-ADObject -Identity $domainDN -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"
    if ($currentQuota -eq $Quota) {
        Write-HardeningLog -Message "ms-DS-MachineAccountQuota is already set to $Quota." -Level Warning -LogDirectory $LogDirectory
        return
    }

    if ($PSCmdlet.ShouldProcess($domainDN, "Set ms-DS-MachineAccountQuota to $Quota (current: $currentQuota)")) {
        try {
            Set-ADDomain -Identity $domainDN -Replace @{ "ms-DS-MachineAccountQuota" = $Quota }
            Write-HardeningLog -Message "ms-DS-MachineAccountQuota set to $Quota (was $currentQuota)." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error setting ms-DS-MachineAccountQuota: $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] ms-DS-MachineAccountQuota would be set to $Quota (current: $currentQuota)." -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# Task: RaiseFunctionalLevel
# ============================================================================

function Set-HardeningFunctionalLevel {
    <#
    .SYNOPSIS
        Raises domain and forest functional levels to the specified targets.
    .PARAMETER TargetDomainLevel
        Target domain functional level (e.g. Windows2016Domain).
    .PARAMETER TargetForestLevel
        Target forest functional level (e.g. Windows2016Forest).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$TargetDomainLevel,

        [Parameter(Mandatory)]
        [string]$TargetForestLevel,

        [string]$LogDirectory
    )

    # --- Domain functional level ---
    $domain = Get-ADDomain
    $currentDomainMode = $domain.DomainMode.ToString()

    if ($currentDomainMode -eq $TargetDomainLevel) {
        Write-HardeningLog -Message "Domain functional level is already at '$TargetDomainLevel'." -Level Warning -LogDirectory $LogDirectory
    }
    elseif ($PSCmdlet.ShouldProcess($domain.DistinguishedName, "Raise domain functional level to '$TargetDomainLevel' (current: $currentDomainMode)")) {
        try {
            Set-ADDomainMode -Identity $domain.DistinguishedName -DomainMode $TargetDomainLevel -Confirm:$false
            Write-HardeningLog -Message "Domain functional level raised to '$TargetDomainLevel' (was '$currentDomainMode')." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error raising domain functional level: $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] Domain functional level would be raised to '$TargetDomainLevel' (current: $currentDomainMode)." -Level Info -LogDirectory $LogDirectory
    }

    # --- Forest functional level ---
    $forest = Get-ADForest
    $currentForestMode = $forest.ForestMode.ToString()

    if ($currentForestMode -eq $TargetForestLevel) {
        Write-HardeningLog -Message "Forest functional level is already at '$TargetForestLevel'." -Level Warning -LogDirectory $LogDirectory
    }
    elseif ($PSCmdlet.ShouldProcess($forest.Name, "Raise forest functional level to '$TargetForestLevel' (current: $currentForestMode)")) {
        try {
            Set-ADForestMode -Identity $forest.Name -ForestMode $TargetForestLevel -Confirm:$false
            Write-HardeningLog -Message "Forest functional level raised to '$TargetForestLevel' (was '$currentForestMode')." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error raising forest functional level: $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] Forest functional level would be raised to '$TargetForestLevel' (current: $currentForestMode)." -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# Task: EnableRecycleBin
# ============================================================================

function Enable-HardeningRecycleBin {
    <#
    .SYNOPSIS
        Enables the Active Directory Recycle Bin optional feature.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory
    )

    $forest = Get-ADForest
    $featureName = "Recycle Bin Feature"
    $targetServer = (Get-ADDomain -Identity $forest.RootDomain).PDCEmulator

    # Check if already enabled
    $feature = Get-ADOptionalFeature -Filter { Name -eq "Recycle Bin Feature" } -Server $targetServer
    if ($feature.EnabledScopes.Count -gt 0) {
        Write-HardeningLog -Message "AD Recycle Bin is already enabled." -Level Warning -LogDirectory $LogDirectory
        return
    }

    if ($PSCmdlet.ShouldProcess($forest.Name, "Enable AD Recycle Bin (via $targetServer)")) {
        try {
            Enable-ADOptionalFeature -Identity $featureName -Scope ForestOrConfigurationSet -Target $forest.Name -Server $targetServer -Confirm:$false
            Write-HardeningLog -Message "AD Recycle Bin enabled on forest '$($forest.Name)' (via $targetServer)." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error enabling AD Recycle Bin: $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] AD Recycle Bin would be enabled on forest '$($forest.Name)' (via $targetServer)." -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# Task: EnablePAMFeature
# ============================================================================

function Enable-HardeningPAMFeature {
    <#
    .SYNOPSIS
        Enables the Privileged Access Management (PAM) optional feature.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory
    )

    $forest = Get-ADForest
    $featureName = "Privileged Access Management Feature"
    $targetServer = (Get-ADDomain -Identity $forest.RootDomain).PDCEmulator

    # Check if already enabled
    $feature = Get-ADOptionalFeature -Filter { Name -eq "Privileged Access Management Feature" } -Server $targetServer
    if ($feature.EnabledScopes.Count -gt 0) {
        Write-HardeningLog -Message "AD PAM Feature is already enabled." -Level Warning -LogDirectory $LogDirectory
        return
    }

    if ($PSCmdlet.ShouldProcess($forest.Name, "Enable AD PAM Feature (via $targetServer)")) {
        try {
            Enable-ADOptionalFeature -Identity $featureName -Scope ForestOrConfigurationSet -Target $forest.Name -Server $targetServer -Confirm:$false
            Write-HardeningLog -Message "AD PAM Feature enabled on forest '$($forest.Name)' (via $targetServer)." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error enabling AD PAM Feature: $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] AD PAM Feature would be enabled on forest '$($forest.Name)' (via $targetServer)." -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# Task: DisableAnonymousAccess
# ============================================================================

function Disable-HardeningAnonymousAccess {
    <#
    .SYNOPSIS
        Removes ANONYMOUS LOGON (S-1-5-7) from the Pre-Windows 2000 Compatible Access group.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory
    )

    $groupName = "Pre-Windows 2000 Compatible Access"
    $anonymousSID = "S-1-5-7"

    # Check if ANONYMOUS LOGON is a member
    try {
        $members = Get-ADGroupMember -Identity $groupName -ErrorAction Stop
        $anonymousMember = $members | Where-Object { $_.SID.Value -eq $anonymousSID }
    }
    catch {
        Write-HardeningLog -Message "Error reading members of '$groupName': $_" -Level Error -LogDirectory $LogDirectory
        throw
    }

    if (-not $anonymousMember) {
        Write-HardeningLog -Message "ANONYMOUS LOGON is not a member of '$groupName'. Already secure." -Level Warning -LogDirectory $LogDirectory
        return
    }

    if ($PSCmdlet.ShouldProcess($groupName, "Remove ANONYMOUS LOGON (S-1-5-7)")) {
        try {
            Remove-ADGroupMember -Identity $groupName -Members $anonymousMember -Confirm:$false
            Write-HardeningLog -Message "ANONYMOUS LOGON removed from '$groupName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error removing ANONYMOUS LOGON from '$groupName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] ANONYMOUS LOGON would be removed from '$groupName'." -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# Task: DeployT0AuthPolicy
# ============================================================================

function New-HardeningT0AuthPolicy {
    <#
    .SYNOPSIS
        Creates a dedicated Authentication Policy and Silo for Tier 0 accounts.
    .PARAMETER PolicyName
        Name of the Authentication Policy.
    .PARAMETER SiloName
        Name of the Authentication Policy Silo.
    .PARAMETER TGTLifetimeMinutes
        TGT lifetime in minutes for user accounts (default: 240).
    .PARAMETER Enforce
        Whether to enforce the policy (default: true).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName,

        [Parameter(Mandatory)]
        [string]$SiloName,

        [int]$TGTLifetimeMinutes = 240,

        [bool]$Enforce = $false,

        [string]$LogDirectory
    )

    # --- Authentication Policy ---
    $existingPolicy = Get-ADAuthenticationPolicy -Filter { Name -eq $PolicyName } -ErrorAction SilentlyContinue
    if ($existingPolicy) {
        Write-HardeningLog -Message "Authentication Policy '$PolicyName' already exists." -Level Warning -LogDirectory $LogDirectory
    }
    elseif ($PSCmdlet.ShouldProcess($PolicyName, "Create Authentication Policy (TGT=${TGTLifetimeMinutes}min, Enforce=$Enforce)")) {
        try {
            $siloCondition = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "{0}"))' -f $SiloName
            New-ADAuthenticationPolicy -Name $PolicyName `
                                       -UserTGTLifetimeMins $TGTLifetimeMinutes `
                                       -UserAllowedToAuthenticateFrom $siloCondition `
                                       -Enforce:$Enforce `
                                       -ProtectedFromAccidentalDeletion $true
            Write-HardeningLog -Message "Authentication Policy '$PolicyName' created (TGT=${TGTLifetimeMinutes}min, Enforce=$Enforce, Silo condition='$SiloName')." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error creating Authentication Policy '$PolicyName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] Authentication Policy '$PolicyName' would be created (TGT=${TGTLifetimeMinutes}min, Enforce=$Enforce, Silo condition='$SiloName')." -Level Info -LogDirectory $LogDirectory
    }

    # --- Authentication Policy Silo ---
    $existingSilo = Get-ADAuthenticationPolicySilo -Filter { Name -eq $SiloName } -ErrorAction SilentlyContinue
    if ($existingSilo) {
        Write-HardeningLog -Message "Authentication Policy Silo '$SiloName' already exists." -Level Warning -LogDirectory $LogDirectory
    }
    elseif ($PSCmdlet.ShouldProcess($SiloName, "Create Authentication Policy Silo linked to '$PolicyName'")) {
        try {
            New-ADAuthenticationPolicySilo -Name $SiloName `
                                           -UserAuthenticationPolicy $PolicyName `
                                           -ComputerAuthenticationPolicy $PolicyName `
                                           -ServiceAuthenticationPolicy $PolicyName `
                                           -Enforce:$Enforce `
                                           -ProtectedFromAccidentalDeletion $true
            Write-HardeningLog -Message "Authentication Policy Silo '$SiloName' created and linked to '$PolicyName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error creating Authentication Policy Silo '$SiloName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] Authentication Policy Silo '$SiloName' would be created and linked to '$PolicyName'." -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# Task: EnableReplicationNotify
# ============================================================================

function Set-HardeningReplicationNotify {
    <#
    .SYNOPSIS
        Enables the Change Notification flag (USE_NOTIFY) on all inter-site replication links.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory
    )

    try {
        $siteLinks = Get-ADReplicationSiteLink -Filter * -Properties Options
    }
    catch {
        Write-HardeningLog -Message "Error retrieving replication site links: $_" -Level Error -LogDirectory $LogDirectory
        throw
    }

    if (-not $siteLinks) {
        Write-HardeningLog -Message "No replication site links found." -Level Warning -LogDirectory $LogDirectory
        return
    }

    foreach ($link in $siteLinks) {
        $currentOptions = if ($link.Options) { $link.Options } else { 0 }
        $useNotifyBit = 1  # Bit 0 = USE_NOTIFY

        if ($currentOptions -band $useNotifyBit) {
            Write-HardeningLog -Message "Site link '$($link.Name)' already has Change Notification enabled (Options=$currentOptions)." -Level Warning -LogDirectory $LogDirectory
            continue
        }

        $newOptions = $currentOptions -bor $useNotifyBit

        if ($PSCmdlet.ShouldProcess($link.Name, "Enable Change Notification (Options: $currentOptions -> $newOptions)")) {
            try {
                Set-ADReplicationSiteLink -Identity $link -Replace @{ Options = $newOptions }
                Write-HardeningLog -Message "Change Notification enabled on site link '$($link.Name)' (Options: $currentOptions -> $newOptions)." -Level Success -LogDirectory $LogDirectory
            }
            catch {
                Write-HardeningLog -Message "Error enabling Change Notification on '$($link.Name)': $_" -Level Error -LogDirectory $LogDirectory
                throw
            }
        }
        else {
            Write-HardeningLog -Message "[WhatIf] Change Notification would be enabled on site link '$($link.Name)' (Options: $currentOptions -> $newOptions)." -Level Info -LogDirectory $LogDirectory
        }
    }
}

# ============================================================================
# Task: ConfigureCentralStore
# ============================================================================

function Set-HardeningCentralStore {
    <#
    .SYNOPSIS
        Creates the Group Policy Central Store by copying PolicyDefinitions to SYSVOL.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory
    )

    $domainDNS = (Get-ADDomain).DNSRoot
    $centralStorePath = "\\$domainDNS\SYSVOL\$domainDNS\Policies\PolicyDefinitions"
    $sourcePath = "$env:SystemRoot\PolicyDefinitions"

    if (-not (Test-Path $sourcePath)) {
        Write-HardeningLog -Message "Source PolicyDefinitions not found at '$sourcePath'." -Level Error -LogDirectory $LogDirectory
        throw "Source PolicyDefinitions not found at '$sourcePath'."
    }

    if (Test-Path $centralStorePath) {
        Write-HardeningLog -Message "Central Store already exists at '$centralStorePath'." -Level Warning -LogDirectory $LogDirectory
        return
    }

    if ($PSCmdlet.ShouldProcess($centralStorePath, "Create GPO Central Store from '$sourcePath'")) {
        try {
            Copy-Item -Path $sourcePath -Destination $centralStorePath -Recurse -Force
            Write-HardeningLog -Message "GPO Central Store created at '$centralStorePath'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error creating GPO Central Store: $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] GPO Central Store would be created at '$centralStorePath' from '$sourcePath'." -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# Task: ExtendLAPSSchema
# ============================================================================

function Update-HardeningLAPSSchema {
    <#
    .SYNOPSIS
        Extends the Active Directory schema for Windows LAPS.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory
    )

    # Check if schema is already extended by looking for the ms-LAPS-Password attribute
    $schemaNC = (Get-ADRootDSE).schemaNamingContext
    $lapsAttribute = Get-ADObject -SearchBase $schemaNC -Filter { Name -eq "ms-LAPS-Password" } -ErrorAction SilentlyContinue

    if ($lapsAttribute) {
        Write-HardeningLog -Message "LAPS schema extension is already present (ms-LAPS-Password attribute exists)." -Level Warning -LogDirectory $LogDirectory
        return
    }

    if ($PSCmdlet.ShouldProcess($schemaNC, "Extend schema for Windows LAPS")) {
        try {
            Update-LapsADSchema -Confirm:$false
            Write-HardeningLog -Message "AD schema extended for Windows LAPS." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error extending LAPS schema: $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] AD schema would be extended for Windows LAPS." -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# Task: RestrictDNSDynamicUpdate
# ============================================================================

function Set-HardeningDNSDynamicUpdate {
    <#
    .SYNOPSIS
        Restricts DNS dynamic update registration to Domain Computers only.
    .DESCRIPTION
        By default, Authenticated Users (S-1-5-11) can create dnsNode objects
        inside AD-integrated DNS zones, which lets any domain user register
        arbitrary DNS records. This function removes that CreateChild right
        from Authenticated Users and grants it exclusively to Domain Computers,
        so only computer accounts can perform dynamic DNS registration.
        Targets all dnsZone objects under MicrosoftDNS in both
        DomainDNSZones and ForestDNSZones application partitions.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory
    )

    # Authenticated Users: well-known SID S-1-5-11 (no domain resolution needed)
    $authenticatedUsersSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-11")

    $domain    = Get-ADDomain
    $domainDN  = $domain.DistinguishedName

    # Domain Computers: well-known RID 515, relative to the domain SID
    $domainComputersSid = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::AccountComputersSid,
        $domain.DomainSID
    )

    $containers = @(
        "CN=MicrosoftDNS,DC=DomainDNSZones,$domainDN",
        "CN=MicrosoftDNS,DC=ForestDNSZones,$domainDN"
    )

    foreach ($containerDN in $containers) {
        if (-not (Test-Path "AD:\$containerDN")) {
            Write-HardeningLog -Message "DNS container not found: '$containerDN'. Skipping." -Level Warning -LogDirectory $LogDirectory
            continue
        }

        Write-HardeningLog -Message "Processing container '$containerDN'..." -Level Info -LogDirectory $LogDirectory

        try {
            $zones = Get-ADObject -SearchBase $containerDN `
                                   -Filter { objectClass -eq 'dnsZone' } `
                                   -SearchScope OneLevel `
                                   -ErrorAction Stop
        }
        catch {
            Write-HardeningLog -Message "Error enumerating DNS zones under '$containerDN': $_" -Level Error -LogDirectory $LogDirectory
            continue
        }

        if (-not $zones) {
            Write-HardeningLog -Message "No DNS zones found under '$containerDN'." -Level Warning -LogDirectory $LogDirectory
            continue
        }

        foreach ($zone in $zones) {
            $zonePath = "AD:\$($zone.DistinguishedName)"

            try {
                $acl = Get-Acl -Path $zonePath

                # Resolve the SID of an ACE identity, returns $null on failure
                $resolveSid = {
                    param($ace)
                    if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                        return $ace.IdentityReference
                    }
                    try { return $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) }
                    catch { return $null }
                }

                # Find explicit Allow CreateChild ACEs belonging to Authenticated Users
                $aceToRemove = @($acl.Access | Where-Object {
                    if ($_.IsInherited) { return $false }
                    if ($_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
                    if (-not ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild)) { return $false }
                    $sid = & $resolveSid $_
                    $sid -and $sid.Value -eq $authenticatedUsersSid.Value
                })

                # Find stale class-scoped CreateChild ACEs for Domain Computers (e.g. dnsNode-only from a previous run)
                $staleAces = @($acl.Access | Where-Object {
                    if ($_.IsInherited) { return $false }
                    if ($_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
                    if (-not ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild)) { return $false }
                    if ($_.ObjectType -eq [Guid]::Empty) { return $false }  # already correct scope, keep it
                    $sid = & $resolveSid $_
                    $sid -and $sid.Value -eq $domainComputersSid.Value
                })

                # Check if Domain Computers already has a CreateChild (all child objects) ACE
                $domainComputersAceExists = [bool]($acl.Access | Where-Object {
                    if ($_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
                    if (-not ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild)) { return $false }
                    if ($_.ObjectType -ne [Guid]::Empty) { return $false }
                    $sid = & $resolveSid $_
                    $sid -and $sid.Value -eq $domainComputersSid.Value
                })

                if ($aceToRemove.Count -eq 0 -and $staleAces.Count -eq 0 -and $domainComputersAceExists) {
                    Write-HardeningLog -Message "  Zone '$($zone.Name)': Already configured correctly." -Level Warning -LogDirectory $LogDirectory
                    continue
                }

                if ($PSCmdlet.ShouldProcess($zone.DistinguishedName, "Restrict DNS dynamic update (remove Authenticated Users CreateChild, add Domain Computers CreateChild all child objects)")) {
                    foreach ($ace in $aceToRemove) {
                        $acl.RemoveAccessRule($ace) | Out-Null
                    }
                    foreach ($ace in $staleAces) {
                        $acl.RemoveAccessRule($ace) | Out-Null
                    }

                    if (-not $domainComputersAceExists) {
                        $newAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                            $domainComputersSid,
                            [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
                            [System.Security.AccessControl.AccessControlType]::Allow,
                            [Guid]::Empty,
                            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
                        )
                        $acl.AddAccessRule($newAce)
                    }

                    Set-Acl -Path $zonePath -AclObject $acl
                    Write-HardeningLog -Message "  Zone '$($zone.Name)': DNS dynamic update restricted to Domain Computers only." -Level Success -LogDirectory $LogDirectory
                }
                else {
                    Write-HardeningLog -Message "  [WhatIf] Zone '$($zone.Name)': Authenticated Users CreateChild would be removed, Domain Computers CreateChild (all child objects) would be added." -Level Info -LogDirectory $LogDirectory
                }
            }
            catch {
                Write-HardeningLog -Message "  Error modifying ACL on zone '$($zone.Name)': $_" -Level Error -LogDirectory $LogDirectory
            }
        }
    }
}

# Export module functions
Export-ModuleMember -Function @(
    'Write-HardeningLog',
    'Import-HardeningConfiguration',
    'Get-HardeningEnvironmentInfo',
    'Set-HardeningMachineAccountQuota',
    'Set-HardeningFunctionalLevel',
    'Enable-HardeningRecycleBin',
    'Enable-HardeningPAMFeature',
    'Disable-HardeningAnonymousAccess',
    'New-HardeningT0AuthPolicy',
    'Set-HardeningReplicationNotify',
    'Set-HardeningCentralStore',
    'Update-HardeningLAPSSchema',
    'Set-HardeningDNSDynamicUpdate'
)
