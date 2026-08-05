# ============================================================================
# GPO Module - Functions for deploying security GPOs from JSON templates
# ============================================================================
# No #Requires -Modules here (ActiveDirectory/GroupPolicy) -- every entry point
# (LOCKmeAD.ps1, Launch-GUI.ps1, each Scripts\Deploy-*.ps1) already checks that
# both modules are available before importing this one, so a per-module #Requires
# would only be a redundant second layer.

Import-Module (Join-Path $PSScriptRoot "..\Common\Connection.psm1") -Force

# Module variable for the current log file path
$script:LogFilePath = $null

function Get-GPOWithRetry {
    <#
    .SYNOPSIS
        Resolves a GPO's Id (GUID) by display name, via its AD container object.
    .DESCRIPTION
        Get-GPO cannot be used here when an explicit credential is in play: the
        GroupPolicy module's cmdlets (Get-GPO, New-GPO, Set-GPRegistryValue, etc.)
        have no -Credential parameter at all -- confirmed against Microsoft's own
        cmdlet reference -- unlike the ActiveDirectory module. So a GPO lookup that
        must work off-domain goes through Get-ADObject instead, reading the GPO's
        groupPolicyContainer object directly: its Name (== CN) is the GUID, in
        "{GUID}" form, which System.Guid parses as-is.

        When called right after creation, the GPO was written via New-GPO's GPMC
        API inside a separate remote (WinRM) session -- a fresh LDAP query issued
        immediately afterward from this session has occasionally not observed it
        yet, so a short retry absorbs that instead of failing outright.
    .PARAMETER Name
        Display name of the GPO to look up.
    .PARAMETER ConnParam
        Splat hashtable with Server/Credential, as built by the caller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [hashtable]$ConnParam = @{}
    )

    $domainDN = (Get-ADDomain @ConnParam).DistinguishedName

    $attempts = 5
    for ($i = 1; $i -le $attempts; $i++) {
        $container = Get-ADObject -SearchBase "CN=Policies,CN=System,$domainDN" -SearchScope OneLevel `
                        -Filter { objectClass -eq 'groupPolicyContainer' -and displayName -eq $Name } `
                        -Properties displayName @ConnParam -ErrorAction SilentlyContinue
        if ($container) {
            return [PSCustomObject]@{
                Id          = [guid]$container.Name
                DisplayName = $container.DisplayName
            }
        }
        if ($i -lt $attempts) { Start-Sleep -Milliseconds 500 }
    }

    throw "GPO '$Name' could not be found (no groupPolicyContainer object with that displayName under CN=Policies,CN=System,$domainDN, after $attempts attempt(s))."
}

function Write-GPOLog {
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
            $logFileName = "GPO_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            $script:LogFilePath = Join-Path $LogDirectory $logFileName
        }
        $logEntry | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8
    }
}

# ============================================================================
# Configuration
# ============================================================================

function Import-GPOConfiguration {
    <#
    .SYNOPSIS
        Reads and validates the GPO JSON configuration file.
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
    if (-not $config.GPOs -or $config.GPOs.Count -eq 0) {
        throw "The 'GPOs' section is missing or empty."
    }

    $validTypes = @('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')

    foreach ($gpo in $config.GPOs) {
        if (-not $gpo.Name) {
            throw "A GPO entry is missing the 'Name' property."
        }
        if ($null -eq $gpo.Enabled) {
            throw "GPO '$($gpo.Name)' is missing the 'Enabled' property."
        }

        # Validate GpoStatus if provided
        if ($gpo.GpoStatus) {
            $validStatuses = @('AllSettingsEnabled', 'UserSettingsDisabled', 'ComputerSettingsDisabled', 'AllSettingsDisabled')
            if ($gpo.GpoStatus -notin $validStatuses) {
                throw "GPO '$($gpo.Name)': invalid 'GpoStatus' value '$($gpo.GpoStatus)'. Valid values: $($validStatuses -join ', ')"
            }
        }

        $hasRegistry = $gpo.RegistrySettings -and $gpo.RegistrySettings.Count -gt 0
        $hasRegPref = $gpo.RegistryPreferences -and $gpo.RegistryPreferences.Count -gt 0
        $hasURA = $gpo.UserRightsAssignments -and $gpo.UserRightsAssignments.Count -gt 0
        $hasRG = $gpo.RestrictedGroups -and $gpo.RestrictedGroups.Count -gt 0
        $hasSecOpt = $gpo.SecurityOptions -and $gpo.SecurityOptions.Count -gt 0
        $hasSysSvc = $gpo.SystemServices -and $gpo.SystemServices.Count -gt 0
        $hasScripts = $gpo.Scripts -and $gpo.Scripts.Count -gt 0

        if (-not $hasRegistry -and -not $hasRegPref -and -not $hasURA -and -not $hasRG -and -not $hasSecOpt -and -not $hasSysSvc -and -not $hasScripts) {
            throw "GPO '$($gpo.Name)' has no 'RegistrySettings', 'RegistryPreferences', 'SecurityOptions', 'UserRightsAssignments', 'RestrictedGroups', 'SystemServices', or 'Scripts' defined."
        }

        # Validate registry settings
        if ($hasRegistry) {
            foreach ($setting in $gpo.RegistrySettings) {
                if (-not $setting.Key) {
                    throw "GPO '$($gpo.Name)': a registry setting is missing the 'Key' property."
                }
                if (-not $setting.ValueName) {
                    throw "GPO '$($gpo.Name)': a registry setting is missing the 'ValueName' property."
                }
                if ($null -eq $setting.Value) {
                    throw "GPO '$($gpo.Name)': registry setting '$($setting.ValueName)' is missing the 'Value' property."
                }
                if (-not $setting.Type -or $setting.Type -notin $validTypes) {
                    throw "GPO '$($gpo.Name)': registry setting '$($setting.ValueName)' has an invalid 'Type'. Valid types: $($validTypes -join ', ')"
                }
            }
        }

        # Validate Registry Preferences
        if ($hasRegPref) {
            foreach ($setting in $gpo.RegistryPreferences) {
                if (-not $setting.Key) {
                    throw "GPO '$($gpo.Name)': a registry preference is missing the 'Key' property."
                }
                if (-not $setting.ValueName) {
                    throw "GPO '$($gpo.Name)': a registry preference is missing the 'ValueName' property."
                }
                if ($null -eq $setting.Value) {
                    throw "GPO '$($gpo.Name)': registry preference '$($setting.ValueName)' is missing the 'Value' property."
                }
                if (-not $setting.Type -or $setting.Type -notin $validTypes) {
                    throw "GPO '$($gpo.Name)': registry preference '$($setting.ValueName)' has an invalid 'Type'. Valid types: $($validTypes -join ', ')"
                }
            }
        }

        # Validate User Rights Assignments
        if ($hasURA) {
            foreach ($assignment in $gpo.UserRightsAssignments) {
                if (-not $assignment.Right) {
                    throw "GPO '$($gpo.Name)': a User Rights Assignment is missing the 'Right' property."
                }
                if ($gpo.Enabled -and (-not $assignment.Groups -or $assignment.Groups.Count -eq 0)) {
                    throw "GPO '$($gpo.Name)': User Rights Assignment '$($assignment.Right)' has no 'Groups' defined."
                }
            }
        }

        # Validate Security Options
        if ($hasSecOpt) {
            foreach ($secOpt in $gpo.SecurityOptions) {
                if (-not $secOpt.Key) {
                    throw "GPO '$($gpo.Name)': a Security Option is missing the 'Key' property."
                }
                if ($secOpt.Key -notmatch '^MACHINE\\') {
                    throw "GPO '$($gpo.Name)': Security Option key '$($secOpt.Key)' must start with 'MACHINE\'. Use 'MACHINE\...' paths (not 'HKLM\...')."
                }
                if (-not $secOpt.ValueName) {
                    throw "GPO '$($gpo.Name)': a Security Option is missing the 'ValueName' property."
                }
                if ($null -eq $secOpt.Value) {
                    throw "GPO '$($gpo.Name)': Security Option '$($secOpt.ValueName)' is missing the 'Value' property."
                }
                if (-not $secOpt.Type -or $secOpt.Type -notin $validTypes) {
                    throw "GPO '$($gpo.Name)': Security Option '$($secOpt.ValueName)' has an invalid 'Type'. Valid types: $($validTypes -join ', ')"
                }
            }
        }

        # Validate Restricted Groups
        if ($hasRG) {
            foreach ($rg in $gpo.RestrictedGroups) {
                if (-not $rg.Group) {
                    throw "GPO '$($gpo.Name)': a RestrictedGroup entry is missing the 'Group' property."
                }
                if ($gpo.Enabled -and (-not $rg.Members -or $rg.Members.Count -eq 0)) {
                    throw "GPO '$($gpo.Name)': RestrictedGroup '$($rg.Group)' has no 'Members' defined."
                }
            }
        }

        # Validate System Services
        if ($hasSysSvc) {
            $validStartupTypes = @(2, 3, 4)
            foreach ($svc in $gpo.SystemServices) {
                if (-not $svc.Name) {
                    throw "GPO '$($gpo.Name)': a SystemService entry is missing the 'Name' property."
                }
                if ($null -eq $svc.StartupType -or $svc.StartupType -notin $validStartupTypes) {
                    throw "GPO '$($gpo.Name)': SystemService '$($svc.Name)' has an invalid 'StartupType'. Valid values: 2 (Automatic), 3 (Manual), 4 (Disabled)"
                }
            }
        }

        # Validate Scripts
        if ($hasScripts) {
            $validScriptTypes = @('Startup', 'Shutdown')
            foreach ($s in $gpo.Scripts) {
                if (-not $s.Type -or $s.Type -notin $validScriptTypes) {
                    throw "GPO '$($gpo.Name)': a Script entry has an invalid 'Type'. Valid values: Startup, Shutdown."
                }
                if (-not $s.ScriptName) {
                    throw "GPO '$($gpo.Name)': a Script entry is missing the 'ScriptName' property."
                }
                if (-not $s.ScriptPath) {
                    throw "GPO '$($gpo.Name)': Script '$($s.ScriptName)' is missing the 'ScriptPath' property."
                }
            }
        }
    }

    return $config
}

# ============================================================================
# Environment
# ============================================================================

function Get-GPOEnvironmentInfo {
    <#
    .SYNOPSIS
        Retrieves Active Directory environment information.
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    .OUTPUTS
        PSCustomObject with environment information.
    #>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    try {
        $domain = Get-ADDomain @serverParam
        $forest = Get-ADForest @serverParam
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
# Filtering Groups
# ============================================================================

function New-GPOFilteringGroup {
    <#
    .SYNOPSIS
        Creates a DomainLocal security group for GPO filtering (Apply or Deny).
    .PARAMETER Name
        Group name.
    .PARAMETER Description
        Group description.
    .PARAMETER OU
        Destination OU for the group.
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Description = "",

        [Parameter(Mandatory)]
        [string]$OU,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    # Check if group already exists
    try {
        $existingGroup = Get-ADGroup -Identity $Name @serverParam -ErrorAction Stop
        Write-GPOLog -Message "Filtering group '$Name' already exists in '$($existingGroup.DistinguishedName)'." -Level Warning -LogDirectory $LogDirectory
        return $existingGroup
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        # Group does not exist, proceed with creation
    }

    if ($PSCmdlet.ShouldProcess($Name, "Create DomainLocal filtering group")) {
        try {
            $newGroup = New-ADGroup -Name $Name `
                                     -SamAccountName $Name `
                                     -GroupScope DomainLocal `
                                     -GroupCategory Security `
                                     -Description $Description `
                                     -Path $OU `
                                     @serverParam `
                                     -PassThru
            Write-GPOLog -Message "Filtering group '$Name' created in '$OU'." -Level Success -LogDirectory $LogDirectory
            return $newGroup
        }
        catch {
            Write-GPOLog -Message "Error creating filtering group '$Name': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-GPOLog -Message "[WhatIf] Filtering group '$Name' would be created in '$OU'." -Level Info -LogDirectory $LogDirectory
    }
}

function Set-GPOFilteringPermission {
    <#
    .SYNOPSIS
        Sets security filtering ACEs on a GPO for Apply and Deny groups.
    .DESCRIPTION
        Removes Authenticated Users from the GPO security filtering, then grants
        the Apply group Allow Read + Apply Group Policy on the GPO object and
        grants the Deny group Deny Apply Group Policy on the GPO object.
    .PARAMETER GPOName
        Name of the GPO to configure.
    .PARAMETER ApplyGroupName
        Name of the Apply filtering group.
    .PARAMETER DenyGroupName
        Name of the Deny filtering group.
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [string]$ApplyGroupName,

        [Parameter(Mandatory)]
        [string]$DenyGroupName,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    # Apply Group Policy extended right GUID
    $applyGPORight = [guid]"edacfd8f-ffb3-11d1-b41d-00a0c968f939"

    if ($PSCmdlet.ShouldProcess($GPOName, "Set filtering ACEs (Apply: $ApplyGroupName, Deny: $DenyGroupName)")) {
        try {
            $gpo      = Get-GPOWithRetry -Name $GPOName -ConnParam $serverParam
            $adDomain = Get-ADDomain @serverParam
            $domainDN = $adDomain.DistinguishedName
            $domainName = $adDomain.DNSRoot
            $gpoDN    = "CN={$($gpo.Id.ToString().ToUpper())},CN=Policies,CN=System,$domainDN"
            $gpoGuid  = $gpo.Id.ToString().ToUpper()
            $adDrive  = Get-LOCKmeADDrive -Server $Server -Credential $Credential
            $acl      = Get-Acl -Path "${adDrive}\$gpoDN" -ErrorAction Stop

            # --- Remove Authenticated Users (S-1-5-11) from security filtering ---
            $authUsersSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
            $rulesToRemove = @($acl.Access | Where-Object {
                $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $authUsersSID.Value
            })
            foreach ($rule in $rulesToRemove) {
                $acl.RemoveAccessRule($rule) | Out-Null
            }
            if ($rulesToRemove.Count -gt 0) {
                Write-GPOLog -Message "  Removed Authenticated Users from GPO '$GPOName' security filtering ($($rulesToRemove.Count) ACE(s))." -Level Success -LogDirectory $LogDirectory
            }

            # --- Apply group: Allow Read + Apply Group Policy ---
            $applyGroup = Get-ADGroup -Identity $ApplyGroupName @serverParam -ErrorAction Stop
            $applySID = [System.Security.Principal.SecurityIdentifier]$applyGroup.SID

            # Allow Read (GenericRead)
            $readRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $applySID,
                [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.AddAccessRule($readRule)

            # Allow Apply Group Policy (ExtendedRight)
            $applyRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $applySID,
                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                [System.Security.AccessControl.AccessControlType]::Allow,
                $applyGPORight
            )
            $acl.AddAccessRule($applyRule)

            Write-GPOLog -Message "  ACE: Allow Read + Apply Group Policy -> $ApplyGroupName" -Level Success -LogDirectory $LogDirectory

            # --- Deny group: Deny Apply Group Policy ---
            $denyGroup = Get-ADGroup -Identity $DenyGroupName @serverParam -ErrorAction Stop
            $denySID = [System.Security.Principal.SecurityIdentifier]$denyGroup.SID

            $denyRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $denySID,
                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                [System.Security.AccessControl.AccessControlType]::Deny,
                $applyGPORight
            )
            $acl.AddAccessRule($denyRule)

            Write-GPOLog -Message "  ACE: Deny Apply Group Policy -> $DenyGroupName" -Level Success -LogDirectory $LogDirectory

            # Commit AD ACL
            Set-Acl -Path "${adDrive}\$gpoDN" -AclObject $acl
            Write-GPOLog -Message "Filtering permissions applied to GPO '$GPOName' (AD object)." -Level Success -LogDirectory $LogDirectory

            # --- Sync SYSVOL folder ACL ---
            $sysvolRoot = Get-LOCKmeADSysvolDrive -DomainDNSRoot $domainName -Credential $Credential
            $sysvolPath = "$sysvolRoot\$domainName\Policies\{$gpoGuid}"
            if (Test-Path $sysvolPath) {
                $sysvolAcl = Get-Acl -Path $sysvolPath

                # Remove Authenticated Users from SYSVOL
                $sysvolAuthRules = @($sysvolAcl.Access | Where-Object {
                    try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $authUsersSID.Value } catch { $false }
                })
                foreach ($rule in $sysvolAuthRules) { $sysvolAcl.RemoveAccessRule($rule) | Out-Null }

                # Grant Apply group Read & Execute (inherited through all subdirectories)
                $fsReadRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $applySID,
                    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                    ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $sysvolAcl.AddAccessRule($fsReadRule)

                Set-Acl -Path $sysvolPath -AclObject $sysvolAcl
                Write-GPOLog -Message "  SYSVOL ACL synced: Authenticated Users removed, ReadAndExecute granted to $ApplyGroupName." -Level Success -LogDirectory $LogDirectory
            }
            else {
                Write-GPOLog -Message "  SYSVOL path not accessible, skipping SYSVOL ACL sync: $sysvolPath" -Level Warning -LogDirectory $LogDirectory
            }
        }
        catch {
            Write-GPOLog -Message "Error setting filtering permissions on GPO '$GPOName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-GPOLog -Message "[WhatIf] Filtering ACEs would be set on GPO '$GPOName':" -Level Info -LogDirectory $LogDirectory
        Write-GPOLog -Message "  [WhatIf] Authenticated Users would be removed from AD object and SYSVOL ACL" -Level Info -LogDirectory $LogDirectory
        Write-GPOLog -Message "  [WhatIf] Allow Read + Apply Group Policy (AD) + ReadAndExecute (SYSVOL) -> $ApplyGroupName" -Level Info -LogDirectory $LogDirectory
        Write-GPOLog -Message "  [WhatIf] Deny Apply Group Policy -> $DenyGroupName" -Level Info -LogDirectory $LogDirectory
    }
}

function Remove-GPOAuthenticatedUsers {
    <#
    .SYNOPSIS
        Removes Authenticated Users from a GPO's security filtering ACL.
    .DESCRIPTION
        Called when filtering groups are not deployed so that the GPO cannot apply
        to any machine via the default Authenticated Users grant, preventing
        unintended mass application to all computers in linked OUs.
    .PARAMETER GPOName
        Name of the GPO to harden.
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    if ($PSCmdlet.ShouldProcess($GPOName, "Remove Authenticated Users from security filtering")) {
        try {
            $gpo        = Get-GPOWithRetry -Name $GPOName -ConnParam $serverParam
            $adDomain   = Get-ADDomain @serverParam
            $domainDN   = $adDomain.DistinguishedName
            $domainName = $adDomain.DNSRoot
            $gpoGuid    = $gpo.Id.ToString().ToUpper()
            $gpoDN      = "CN={$gpoGuid},CN=Policies,CN=System,$domainDN"
            $adDrive    = Get-LOCKmeADDrive -Server $Server -Credential $Credential

            $acl          = Get-Acl -Path "${adDrive}\$gpoDN"
            $authUsersSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
            $rulesToRemove = @($acl.Access | Where-Object {
                $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $authUsersSID.Value
            })

            if ($rulesToRemove.Count -gt 0) {
                foreach ($rule in $rulesToRemove) {
                    $acl.RemoveAccessRule($rule) | Out-Null
                }
                Set-Acl -Path "${adDrive}\$gpoDN" -AclObject $acl
                Write-GPOLog -Message "Removed Authenticated Users from GPO '$GPOName' AD object ($($rulesToRemove.Count) ACE(s))." -Level Success -LogDirectory $LogDirectory
            }
            else {
                Write-GPOLog -Message "Authenticated Users already absent from GPO '$GPOName' AD object." -Level Info -LogDirectory $LogDirectory
            }

            # --- Sync SYSVOL folder ACL ---
            $sysvolRoot = Get-LOCKmeADSysvolDrive -DomainDNSRoot $domainName -Credential $Credential
            $sysvolPath = "$sysvolRoot\$domainName\Policies\{$gpoGuid}"
            if (Test-Path $sysvolPath) {
                $sysvolAcl = Get-Acl -Path $sysvolPath
                $sysvolAuthRules = @($sysvolAcl.Access | Where-Object {
                    try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $authUsersSID.Value } catch { $false }
                })
                if ($sysvolAuthRules.Count -gt 0) {
                    foreach ($rule in $sysvolAuthRules) { $sysvolAcl.RemoveAccessRule($rule) | Out-Null }
                    Set-Acl -Path $sysvolPath -AclObject $sysvolAcl
                    Write-GPOLog -Message "Removed Authenticated Users from SYSVOL ACL for GPO '$GPOName' ($($sysvolAuthRules.Count) ACE(s))." -Level Success -LogDirectory $LogDirectory
                }
                else {
                    Write-GPOLog -Message "Authenticated Users already absent from SYSVOL ACL for GPO '$GPOName'." -Level Info -LogDirectory $LogDirectory
                }
            }
            else {
                Write-GPOLog -Message "SYSVOL path not accessible, skipping SYSVOL ACL sync: $sysvolPath" -Level Warning -LogDirectory $LogDirectory
            }
        }
        catch {
            Write-GPOLog -Message "Error removing Authenticated Users from GPO '$GPOName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-GPOLog -Message "[WhatIf] Authenticated Users would be removed from GPO '$GPOName' AD object and SYSVOL ACL." -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# GPO Creation
# ============================================================================

function New-GPOSecurityPolicy {
    <#
    .SYNOPSIS
        Creates a security GPO from a template and applies registry-based policy settings.
    .DESCRIPTION
        Creates the GPO if it does not exist, then applies all defined registry settings
        using Set-GPRegistryValue. If the GPO already exists, settings are reapplied to
        ensure consistency with the template.
    .PARAMETER Name
        Name of the GPO to create.
    .PARAMETER Description
        Description/comment for the GPO.
    .PARAMETER RegistrySettings
        Array of registry setting objects with Key, ValueName, Value, Type, and optional Description.
    .PARAMETER GpoStatus
        GPO status: AllSettingsEnabled, UserSettingsDisabled, ComputerSettingsDisabled, AllSettingsDisabled.
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Description,

        [array]$RegistrySettings = @(),

        [ValidateSet("AllSettingsEnabled", "UserSettingsDisabled", "ComputerSettingsDisabled", "AllSettingsDisabled")]
        [string]$GpoStatus = "AllSettingsEnabled",

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    # Get-GPO/New-GPO/Set-GPRegistryValue have no -Credential parameter at all (unlike
    # the ActiveDirectory module) -- route them through a remote WinRM session against
    # -Server when an explicit credential is in play.
    $gpoServer = if ($Credential) { $null } else { $Server }
    $existingGPO = Invoke-LOCKmeADRemote -Server $Server -Credential $Credential -ArgumentList $Name, $gpoServer -ScriptBlock {
        param($Name, $Server)
        $p = @{}
        if ($Server) { $p.Server = $Server }
        Get-GPO -Name $Name @p -ErrorAction SilentlyContinue
    }
    $action = if ($existingGPO) { "Update" } else { "Create" }

    if ($existingGPO) {
        Write-GPOLog -Message "GPO '$Name' already exists (ID: $($existingGPO.Id)). Ensuring settings are applied." -Level Warning -LogDirectory $LogDirectory
    }

    $settingLabel = if ($RegistrySettings.Count -gt 0) { "$($RegistrySettings.Count) registry settings" } else { "no registry settings" }

    if ($PSCmdlet.ShouldProcess($Name, "$action security GPO ($settingLabel)")) {
        try {
            if (-not $existingGPO) {
                $existingGPO = Invoke-LOCKmeADRemote -Server $Server -Credential $Credential -ArgumentList $Name, $Description, $gpoServer -ScriptBlock {
                    param($Name, $Description, $Server)
                    $p = @{}
                    if ($Server) { $p.Server = $Server }
                    New-GPO -Name $Name -Comment $Description @p
                }
                Write-GPOLog -Message "GPO '$Name' created." -Level Success -LogDirectory $LogDirectory
            }

            # Set GPO status via AD flags attribute
            # 0 = AllSettingsEnabled, 1 = UserSettingsDisabled, 2 = ComputerSettingsDisabled, 3 = AllSettingsDisabled
            if ($GpoStatus -ne "AllSettingsEnabled") {
                $flagsMap = @{
                    'AllSettingsEnabled'        = 0
                    'UserSettingsDisabled'      = 1
                    'ComputerSettingsDisabled'  = 2
                    'AllSettingsDisabled'       = 3
                }
                $targetFlags = $flagsMap[$GpoStatus]
                $gpoObj = $existingGPO
                if (-not $gpoObj) {
                    $gpoObj = Get-GPOWithRetry -Name $Name -ConnParam $serverParam
                }
                $gpoGuid = "{$($gpoObj.Id.ToString().ToUpper())}"
                $domainDN = (Get-ADDomain @serverParam).DistinguishedName
                $gpoDN = "CN=$gpoGuid,CN=Policies,CN=System,$domainDN"
                $currentFlags = (Get-ADObject -Identity $gpoDN -Properties flags @serverParam).flags
                if ($currentFlags -ne $targetFlags) {
                    Set-ADObject -Identity $gpoDN -Replace @{ flags = $targetFlags } @serverParam
                    Write-GPOLog -Message "  GPO status set to '$GpoStatus' on '$Name'." -Level Success -LogDirectory $LogDirectory
                }
            }

            foreach ($setting in $RegistrySettings) {
                Invoke-LOCKmeADRemote -Server $Server -Credential $Credential -ArgumentList $Name, $setting.Key, $setting.ValueName, $setting.Value, $setting.Type, $gpoServer -ScriptBlock {
                    param($Name, $Key, $ValueName, $Value, $Type, $Server)
                    $p = @{}
                    if ($Server) { $p.Server = $Server }
                    Set-GPRegistryValue -Name $Name -Key $Key -ValueName $ValueName -Value $Value -Type $Type @p | Out-Null
                } | Out-Null

                $desc = if ($setting.Description) { " ($($setting.Description))" } else { "" }
                Write-GPOLog -Message "  Set: $($setting.ValueName) = $($setting.Value)$desc" -Level Success -LogDirectory $LogDirectory
            }
        }
        catch {
            Write-GPOLog -Message "Error configuring GPO '$Name': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-GPOLog -Message "[WhatIf] GPO '$Name' would be $(if ($existingGPO) { 'updated' } else { 'created' }) ($settingLabel):" -Level Info -LogDirectory $LogDirectory
        if ($GpoStatus -ne "AllSettingsEnabled") {
            Write-GPOLog -Message "  [WhatIf] GPO status would be set to '$GpoStatus'." -Level Info -LogDirectory $LogDirectory
        }
        foreach ($setting in $RegistrySettings) {
            $desc = if ($setting.Description) { " - $($setting.Description)" } else { "" }
            Write-GPOLog -Message "  [WhatIf] $($setting.Key)\$($setting.ValueName) = $($setting.Value)$desc" -Level Info -LogDirectory $LogDirectory
        }
    }
}

# ============================================================================
# Registry Preferences (GPO Preferences > Windows Settings > Registry)
# ============================================================================

function Set-GPORegistryPreferences {
    <#
    .SYNOPSIS
        Applies registry preference items to a GPO using Set-GPPrefRegistryValue.
    .DESCRIPTION
        Writes registry settings as GPO Preferences (Computer Configuration >
        Preferences > Windows Settings > Registry). Unlike RegistrySettings
        (Administrative Templates), Preferences do not tattoo the registry and
        are cleanly removed when the GPO is unlinked. Use this for arbitrary
        registry keys outside the SOFTWARE\Policies namespace.
    .PARAMETER GPOName
        Name of an existing GPO to configure.
    .PARAMETER RegistryPreferences
        Array of objects with Key (HKLM\...), ValueName, Value, Type, optional
        Description, and optional Action (Create, Replace, Update, Delete).
        Defaults to Replace when Action is omitted.
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [array]$RegistryPreferences,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $target = "$GPOName ($($RegistryPreferences.Count) registry preference(s))"
    $gpoServer = if ($Credential) { $null } else { $Server }

    if ($PSCmdlet.ShouldProcess($target, "Set Registry Preferences via GPO Preferences")) {
        try {
            $order = 1
            foreach ($setting in $RegistryPreferences) {
                $action = if ($setting.Action) { $setting.Action } else { "Replace" }
                Invoke-LOCKmeADRemote -Server $Server -Credential $Credential `
                    -ArgumentList $GPOName, $action, $setting.Key, $setting.ValueName, $setting.Value, $setting.Type, $order, $gpoServer `
                    -ScriptBlock {
                        param($GPOName, $Action, $Key, $ValueName, $Value, $Type, $Order, $Server)
                        $p = @{}
                        if ($Server) { $p.Server = $Server }
                        Set-GPPrefRegistryValue -Name $GPOName -Context Computer -Action $Action `
                            -Key $Key -ValueName $ValueName -Value $Value -Type $Type -Order $Order @p | Out-Null
                    } | Out-Null

                $desc = if ($setting.Description) { " ($($setting.Description))" } else { "" }
                Write-GPOLog -Message "  Pref [$action]: $($setting.ValueName) = $($setting.Value)$desc" -Level Success -LogDirectory $LogDirectory
                $order++
            }
        }
        catch {
            Write-GPOLog -Message "Error setting Registry Preferences on '$GPOName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-GPOLog -Message "[WhatIf] Registry Preferences would be set on GPO '$GPOName':" -Level Info -LogDirectory $LogDirectory
        foreach ($setting in $RegistryPreferences) {
            $action = if ($setting.Action) { $setting.Action } else { "Replace" }
            $desc = if ($setting.Description) { " - $($setting.Description)" } else { "" }
            Write-GPOLog -Message "  [WhatIf] [$action] $($setting.Key)\$($setting.ValueName) = $($setting.Value)$desc" -Level Info -LogDirectory $LogDirectory
        }
    }
}

# ============================================================================
# GPO Linking
# ============================================================================

function Set-GPOLink {
    <#
    .SYNOPSIS
        Links a GPO to a target OU. Skips if the link already exists.
    .PARAMETER GPOName
        Name of the GPO to link.
    .PARAMETER TargetOU
        Distinguished Name of the target OU.
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [string]$TargetOU,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    # Get-GPInheritance/New-GPLink have no -Credential parameter at all (unlike the
    # ActiveDirectory module) -- route them through a remote WinRM session against
    # -Server when an explicit credential is in play.
    $gpoServer = if ($Credential) { $null } else { $Server }

    # Check if link already exists.
    # DisplayName must be projected to a plain string INSIDE the remote scriptblock. PowerShell
    # remoting serializes each GpoLink object down to its ToString() value, so a GpoLinks
    # collection that crosses the session boundary arrives as an ArrayList of String whose
    # .DisplayName is empty -- filtering on the near side therefore never matched, and every
    # re-run tried to re-create links that already existed (only reachable in explicit-credential
    # mode; domain-joined runs stay in-process and never serialize).
    try {
        $linkedNames = @(Invoke-LOCKmeADRemote -Server $Server -Credential $Credential -ArgumentList $TargetOU, $gpoServer -ScriptBlock {
            param($TargetOU, $Server)
            $p = @{}
            if ($Server) { $p.Server = $Server }
            (Get-GPInheritance -Target $TargetOU @p).GpoLinks | ForEach-Object { $_.DisplayName }
        })
        if ($linkedNames -contains $GPOName) {
            Write-GPOLog -Message "GPO '$GPOName' is already linked to '$TargetOU'." -Level Warning -LogDirectory $LogDirectory
            return $false
        }
    }
    catch {
        Write-GPOLog -Message "Error checking GPO links for '$TargetOU': $_" -Level Error -LogDirectory $LogDirectory
        throw
    }

    if ($PSCmdlet.ShouldProcess($TargetOU, "Link GPO '$GPOName'")) {
        try {
            Invoke-LOCKmeADRemote -Server $Server -Credential $Credential -ArgumentList $GPOName, $TargetOU, $gpoServer -ScriptBlock {
                param($GPOName, $TargetOU, $Server)
                $p = @{}
                if ($Server) { $p.Server = $Server }
                New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled Yes @p | Out-Null
            } | Out-Null
            Write-GPOLog -Message "GPO '$GPOName' linked to '$TargetOU'." -Level Success -LogDirectory $LogDirectory
            return $true
        }
        catch {
            Write-GPOLog -Message "Error linking GPO '$GPOName' to '$TargetOU': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-GPOLog -Message "[WhatIf] GPO '$GPOName' would be linked to '$TargetOU'." -Level Info -LogDirectory $LogDirectory
        return $true
    }
}

# ============================================================================
# Security Template Helper (GptTmpl.inf section merge)
# ============================================================================

function Write-SecurityTemplateSection {
    <#
    .SYNOPSIS
        Merges a section into a GptTmpl.inf file, preserving existing sections.
    .DESCRIPTION
        Reads the existing GptTmpl.inf (if any), parses it into sections, adds or
        replaces the specified section, and writes the merged result. Creates the
        file and directory if they do not exist. Uses UTF-16LE encoding as required
        by the Windows Security CSE.
    .PARAMETER InfPath
        Full path to the GptTmpl.inf file.
    .PARAMETER SectionName
        Name of the section to write (e.g. "Privilege Rights", "Group Membership").
    .PARAMETER SectionLines
        Array of lines to place under the section header.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$InfPath,

        [Parameter(Mandatory)]
        [string]$SectionName,

        [Parameter(Mandatory)]
        [string[]]$SectionLines
    )

    $sections = [ordered]@{}

    # Parse existing file if present
    if (Test-Path $InfPath) {
        $currentSection = $null
        foreach ($line in [System.IO.File]::ReadAllLines($InfPath, [System.Text.Encoding]::Unicode)) {
            if ($line -match '^\[(.+)\]$') {
                $currentSection = $Matches[1]
                if (-not $sections.Contains($currentSection)) {
                    $sections[$currentSection] = [System.Collections.ArrayList]::new()
                }
            }
            elseif ($currentSection -and $line.Trim() -ne '') {
                [void]$sections[$currentSection].Add($line)
            }
        }
    }

    # Ensure standard headers exist
    if (-not $sections.Contains("Unicode")) {
        $sections.Insert(0, "Unicode", [System.Collections.ArrayList]@("Unicode=yes"))
    }
    if (-not $sections.Contains("Version")) {
        $sections.Insert(1, "Version", [System.Collections.ArrayList]@('signature="$CHICAGO$"', "Revision=1"))
    }

    # Update or add the target section
    $sections[$SectionName] = [System.Collections.ArrayList]@($SectionLines)

    # Rebuild file content
    $lines = [System.Collections.ArrayList]::new()
    foreach ($key in $sections.Keys) {
        [void]$lines.Add("[$key]")
        foreach ($sLine in $sections[$key]) {
            [void]$lines.Add($sLine)
        }
    }

    $content = ($lines -join "`r`n") + "`r`n"

    # Ensure directory exists
    $dir = Split-Path $InfPath -Parent
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    [System.IO.File]::WriteAllText($InfPath, $content, [System.Text.Encoding]::Unicode)
}

# ============================================================================
# User Rights Assignments
# ============================================================================

function Set-GPOUserRightsAssignment {
    <#
    .SYNOPSIS
        Applies User Rights Assignments to a GPO by writing GptTmpl.inf to SYSVOL.
    .DESCRIPTION
        Resolves AD group names to SIDs, builds a GptTmpl.inf security template,
        writes it to the GPO's SYSVOL path, and updates the GPO's CSE list and
        version number so the Security CSE processes the settings.
    .PARAMETER GPOName
        Name of an existing GPO to configure.
    .PARAMETER Assignments
        Array of assignment objects with Right (privilege constant) and Groups (array of AD group names).
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [array]$Assignments,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    # Resolve group names to SIDs
    $privilegeLines = @()
    foreach ($assignment in $Assignments) {
        $sids = @()
        foreach ($groupName in $assignment.Groups) {
            try {
                $group = Get-ADGroup -Identity $groupName @serverParam -ErrorAction Stop
                $sids += "*$($group.SID.Value)"
            }
            catch {
                Write-GPOLog -Message "Group '$groupName' not found in AD. Ensure the group exists before deploying this GPO." -Level Error -LogDirectory $LogDirectory
                throw "Group '$groupName' not found in Active Directory."
            }
        }
        $privilegeLines += "$($assignment.Right) = $($sids -join ',')"
    }

    $target = "$GPOName ($($Assignments.Count) right assignments)"

    if ($PSCmdlet.ShouldProcess($target, "Set User Rights Assignments via GptTmpl.inf")) {
        try {
            # Get GPO details
            $gpo = Get-GPOWithRetry -Name $GPOName -ConnParam $serverParam
            $gpoGuid = "{$($gpo.Id.ToString().ToUpper())}"
            $domainDNS = (Get-ADDomain @serverParam).DNSRoot
            $domainDN = (Get-ADDomain @serverParam).DistinguishedName

            # Build SYSVOL path
            $sysvolRoot = Get-LOCKmeADSysvolDrive -DomainDNSRoot $domainDNS -Credential $Credential
            $sysvolBase = "$sysvolRoot\$domainDNS\Policies\$gpoGuid"
            $infPath = "$sysvolBase\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            # Write [Privilege Rights] section (merges with existing sections)
            Write-SecurityTemplateSection -InfPath $infPath -SectionName "Privilege Rights" -SectionLines $privilegeLines

            foreach ($assignment in $Assignments) {
                $desc = if ($assignment.Description) { " ($($assignment.Description))" } else { "" }
                Write-GPOLog -Message "  URA: $($assignment.Right) -> $($assignment.Groups -join ', ')$desc" -Level Success -LogDirectory $LogDirectory
            }

            # Update gPCMachineExtensionNames to include Security CSE
            $gpoDN = "CN=$gpoGuid,CN=Policies,CN=System,$domainDN"
            $gpoAD = Get-ADObject -Identity $gpoDN -Properties gPCMachineExtensionNames, versionNumber @serverParam

            $securityCSE = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"
            $currentExt = if ($gpoAD.gPCMachineExtensionNames) { $gpoAD.gPCMachineExtensionNames } else { "" }

            if ($currentExt -notlike "*827D319E*") {
                $newExt = $currentExt + $securityCSE
                Set-ADObject -Identity $gpoDN -Replace @{ gPCMachineExtensionNames = $newExt } @serverParam
            }

            # Increment machine version (lower 16 bits)
            $currentVersion = if ($gpoAD.versionNumber) { [int]$gpoAD.versionNumber } else { 0 }
            $userVersion = ($currentVersion -shr 16) -band 0xFFFF
            $machineVersion = ($currentVersion -band 0xFFFF) + 1
            $newVersion = ($userVersion -shl 16) -bor $machineVersion
            Set-ADObject -Identity $gpoDN -Replace @{ versionNumber = $newVersion } @serverParam

            # Update GPT.INI version to match
            $gptIniPath = "$sysvolBase\GPT.INI"
            if (Test-Path $gptIniPath) {
                $gptContent = Get-Content $gptIniPath -Raw
                $gptContent = $gptContent -replace 'Version=\d+', "Version=$newVersion"
                Set-Content -Path $gptIniPath -Value $gptContent -Encoding ASCII
            }

            Write-GPOLog -Message "User Rights Assignments applied to GPO '$GPOName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-GPOLog -Message "Error setting User Rights Assignments on '$GPOName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-GPOLog -Message "[WhatIf] User Rights Assignments would be set on GPO '$GPOName':" -Level Info -LogDirectory $LogDirectory
        foreach ($assignment in $Assignments) {
            $desc = if ($assignment.Description) { " ($($assignment.Description))" } else { "" }
            Write-GPOLog -Message "  [WhatIf] $($assignment.Right) -> $($assignment.Groups -join ', ')$desc" -Level Info -LogDirectory $LogDirectory
        }
    }
}

# ============================================================================
# Restricted Groups
# ============================================================================

function Set-GPORestrictedGroups {
    <#
    .SYNOPSIS
        Applies Restricted Groups settings to a GPO by writing the [Group Membership]
        section to GptTmpl.inf in SYSVOL.
    .DESCRIPTION
        Resolves local group names to well-known SIDs and AD group names to domain SIDs,
        then writes a [Group Membership] section to enforce local group membership via
        Restricted Groups policy. Uses __Members to replace the full membership of the
        target local group (excluding the built-in Administrator which Windows protects).
    .PARAMETER GPOName
        Name of an existing GPO to configure.
    .PARAMETER RestrictedGroups
        Array of objects with Group (local group name or SID) and Members (array of AD group names).
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [array]$RestrictedGroups,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    # Well-known local group SID lookup
    $wellKnownSIDs = @{
        "Administrators"                  = "S-1-5-32-544"
        "Users"                           = "S-1-5-32-545"
        "Guests"                          = "S-1-5-32-546"
        "Power Users"                     = "S-1-5-32-547"
        "Backup Operators"                = "S-1-5-32-551"
        "Remote Desktop Users"            = "S-1-5-32-555"
        "Network Configuration Operators" = "S-1-5-32-556"
        "Event Log Readers"               = "S-1-5-32-573"
        "Hyper-V Administrators"          = "S-1-5-32-578"
    }

    # Resolve groups and build [Group Membership] lines
    $membershipLines = @()
    $logDetails = @()

    foreach ($rg in $RestrictedGroups) {
        # Resolve local group to well-known SID
        $groupSID = $wellKnownSIDs[$rg.Group]
        if (-not $groupSID) {
            if ($rg.Group -match '^S-1-') {
                $groupSID = $rg.Group
            }
            else {
                Write-GPOLog -Message "Unknown local group '$($rg.Group)'. Use a well-known name (Administrators, Users, etc.) or a SID." -Level Error -LogDirectory $LogDirectory
                throw "Unknown local group '$($rg.Group)'."
            }
        }

        # Resolve AD group members to SIDs
        $memberSIDs = @()
        foreach ($memberName in $rg.Members) {
            try {
                $adGroup = Get-ADGroup -Identity $memberName @serverParam -ErrorAction Stop
                $memberSIDs += "*$($adGroup.SID.Value)"
            }
            catch {
                Write-GPOLog -Message "Group '$memberName' not found in AD. Ensure the group exists before deploying this GPO." -Level Error -LogDirectory $LogDirectory
                throw "Group '$memberName' not found in Active Directory."
            }
        }

        $membershipLines += "*$groupSID`__Members = $($memberSIDs -join ',')"
        $membershipLines += "*$groupSID`__Memberof ="

        $desc = if ($rg.Description) { " ($($rg.Description))" } else { "" }
        $logDetails += @{ Group = $rg.Group; Members = $rg.Members; Desc = $desc }
    }

    $target = "$GPOName ($($RestrictedGroups.Count) restricted group(s))"

    if ($PSCmdlet.ShouldProcess($target, "Set Restricted Groups via GptTmpl.inf")) {
        try {
            # Get GPO details
            $gpo = Get-GPOWithRetry -Name $GPOName -ConnParam $serverParam
            $gpoGuid = "{$($gpo.Id.ToString().ToUpper())}"
            $domainDNS = (Get-ADDomain @serverParam).DNSRoot
            $domainDN = (Get-ADDomain @serverParam).DistinguishedName

            # Build SYSVOL path
            $sysvolRoot = Get-LOCKmeADSysvolDrive -DomainDNSRoot $domainDNS -Credential $Credential
            $sysvolBase = "$sysvolRoot\$domainDNS\Policies\$gpoGuid"
            $infPath = "$sysvolBase\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            # Write [Group Membership] section (merges with existing sections)
            Write-SecurityTemplateSection -InfPath $infPath -SectionName "Group Membership" -SectionLines $membershipLines

            foreach ($detail in $logDetails) {
                Write-GPOLog -Message "  RG: $($detail.Group) -> $($detail.Members -join ', ')$($detail.Desc)" -Level Success -LogDirectory $LogDirectory
            }

            # Update gPCMachineExtensionNames to include Security CSE
            $gpoDN = "CN=$gpoGuid,CN=Policies,CN=System,$domainDN"
            $gpoAD = Get-ADObject -Identity $gpoDN -Properties gPCMachineExtensionNames, versionNumber @serverParam

            $securityCSE = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"
            $currentExt = if ($gpoAD.gPCMachineExtensionNames) { $gpoAD.gPCMachineExtensionNames } else { "" }

            if ($currentExt -notlike "*827D319E*") {
                $newExt = $currentExt + $securityCSE
                Set-ADObject -Identity $gpoDN -Replace @{ gPCMachineExtensionNames = $newExt } @serverParam
            }

            # Increment machine version (lower 16 bits)
            $currentVersion = if ($gpoAD.versionNumber) { [int]$gpoAD.versionNumber } else { 0 }
            $userVersion = ($currentVersion -shr 16) -band 0xFFFF
            $machineVersion = ($currentVersion -band 0xFFFF) + 1
            $newVersion = ($userVersion -shl 16) -bor $machineVersion
            Set-ADObject -Identity $gpoDN -Replace @{ versionNumber = $newVersion } @serverParam

            # Update GPT.INI version to match
            $gptIniPath = "$sysvolBase\GPT.INI"
            if (Test-Path $gptIniPath) {
                $gptContent = Get-Content $gptIniPath -Raw
                $gptContent = $gptContent -replace 'Version=\d+', "Version=$newVersion"
                Set-Content -Path $gptIniPath -Value $gptContent -Encoding ASCII
            }

            Write-GPOLog -Message "Restricted Groups applied to GPO '$GPOName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-GPOLog -Message "Error setting Restricted Groups on '$GPOName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-GPOLog -Message "[WhatIf] Restricted Groups would be set on GPO '$GPOName':" -Level Info -LogDirectory $LogDirectory
        foreach ($detail in $logDetails) {
            Write-GPOLog -Message "  [WhatIf] $($detail.Group) -> $($detail.Members -join ', ')$($detail.Desc)" -Level Info -LogDirectory $LogDirectory
        }
    }
}

# ============================================================================
# Security Options ([Registry Values] in GptTmpl.inf)
# ============================================================================

function Set-GPOSecurityOptions {
    <#
    .SYNOPSIS
        Applies Security Options to a GPO by writing the [Registry Values]
        section to GptTmpl.inf in SYSVOL.
    .DESCRIPTION
        Builds [Registry Values] entries from the SecurityOptions array and
        writes them to GptTmpl.inf using the Security CSE format. These
        settings appear under Computer Configuration > Windows Settings >
        Security Settings > Security Options in the Group Policy Editor.
    .PARAMETER GPOName
        Name of an existing GPO to configure.
    .PARAMETER SecurityOptions
        Array of objects with Key (MACHINE\...), ValueName, Value, Type, and optional Description.
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [array]$SecurityOptions,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    # Map friendly type names to GptTmpl.inf numeric codes
    $typeMap = @{
        'String'       = 1
        'ExpandString'  = 2
        'Binary'       = 3
        'DWord'        = 4
        'MultiString'  = 7
        'QWord'        = 11
    }

    # Build [Registry Values] lines
    $registryValueLines = @()
    foreach ($opt in $SecurityOptions) {
        $typeCode = $typeMap[$opt.Type]
        if (-not $typeCode) {
            throw "Unsupported Security Option type '$($opt.Type)' for '$($opt.ValueName)'."
        }

        $formattedValue = switch ($opt.Type) {
            'String'      { "$typeCode,`"$($opt.Value)`"" }
            'ExpandString' { "$typeCode,`"$($opt.Value)`"" }
            'MultiString' { "$typeCode,$($opt.Value -join ',')" }
            default       { "$typeCode,$($opt.Value)" }
        }

        $registryValueLines += "$($opt.Key)\$($opt.ValueName)=$formattedValue"
    }

    $target = "$GPOName ($($SecurityOptions.Count) security option(s))"

    if ($PSCmdlet.ShouldProcess($target, "Set Security Options via GptTmpl.inf")) {
        try {
            # Get GPO details
            $gpo = Get-GPOWithRetry -Name $GPOName -ConnParam $serverParam
            $gpoGuid = "{$($gpo.Id.ToString().ToUpper())}"
            $domainDNS = (Get-ADDomain @serverParam).DNSRoot
            $domainDN = (Get-ADDomain @serverParam).DistinguishedName

            # Build SYSVOL path
            $sysvolRoot = Get-LOCKmeADSysvolDrive -DomainDNSRoot $domainDNS -Credential $Credential
            $sysvolBase = "$sysvolRoot\$domainDNS\Policies\$gpoGuid"
            $infPath = "$sysvolBase\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            # Write [Registry Values] section (merges with existing sections)
            Write-SecurityTemplateSection -InfPath $infPath -SectionName "Registry Values" -SectionLines $registryValueLines

            foreach ($opt in $SecurityOptions) {
                $desc = if ($opt.Description) { " ($($opt.Description))" } else { "" }
                Write-GPOLog -Message "  SO: $($opt.ValueName) = $($opt.Value)$desc" -Level Success -LogDirectory $LogDirectory
            }

            # Update gPCMachineExtensionNames to include Security CSE
            $gpoDN = "CN=$gpoGuid,CN=Policies,CN=System,$domainDN"
            $gpoAD = Get-ADObject -Identity $gpoDN -Properties gPCMachineExtensionNames, versionNumber @serverParam

            $securityCSE = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"
            $currentExt = if ($gpoAD.gPCMachineExtensionNames) { $gpoAD.gPCMachineExtensionNames } else { "" }

            if ($currentExt -notlike "*827D319E*") {
                $newExt = $currentExt + $securityCSE
                Set-ADObject -Identity $gpoDN -Replace @{ gPCMachineExtensionNames = $newExt } @serverParam
            }

            # Increment machine version (lower 16 bits)
            $currentVersion = if ($gpoAD.versionNumber) { [int]$gpoAD.versionNumber } else { 0 }
            $userVersion = ($currentVersion -shr 16) -band 0xFFFF
            $machineVersion = ($currentVersion -band 0xFFFF) + 1
            $newVersion = ($userVersion -shl 16) -bor $machineVersion
            Set-ADObject -Identity $gpoDN -Replace @{ versionNumber = $newVersion } @serverParam

            # Update GPT.INI version to match
            $gptIniPath = "$sysvolBase\GPT.INI"
            if (Test-Path $gptIniPath) {
                $gptContent = Get-Content $gptIniPath -Raw
                $gptContent = $gptContent -replace 'Version=\d+', "Version=$newVersion"
                Set-Content -Path $gptIniPath -Value $gptContent -Encoding ASCII
            }

            Write-GPOLog -Message "Security Options applied to GPO '$GPOName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-GPOLog -Message "Error setting Security Options on '$GPOName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-GPOLog -Message "[WhatIf] Security Options would be set on GPO '$GPOName':" -Level Info -LogDirectory $LogDirectory
        foreach ($opt in $SecurityOptions) {
            $desc = if ($opt.Description) { " - $($opt.Description)" } else { "" }
            Write-GPOLog -Message "  [WhatIf] $($opt.Key)\$($opt.ValueName) = $($opt.Value)$desc" -Level Info -LogDirectory $LogDirectory
        }
    }
}

# ============================================================================
# System Services ([Service General Setting] in GptTmpl.inf)
# ============================================================================

function Set-GPOSystemServices {
    <#
    .SYNOPSIS
        Applies System Service startup settings to a GPO by writing the
        [Service General Setting] section to GptTmpl.inf in SYSVOL.
    .DESCRIPTION
        Builds [Service General Setting] entries and writes them to GptTmpl.inf
        using the Security CSE format. These settings appear under Computer
        Configuration > Windows Settings > Security Settings > System Services
        in the Group Policy Editor.
    .PARAMETER GPOName
        Name of an existing GPO to configure.
    .PARAMETER SystemServices
        Array of objects with Name (service name), StartupType (2=Automatic, 3=Manual, 4=Disabled),
        and optional Description.
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [array]$SystemServices,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $startupLabels = @{ 2 = 'Automatic'; 3 = 'Manual'; 4 = 'Disabled' }

    # Build [Service General Setting] lines
    # Format: "ServiceName",StartupType,""
    $serviceLines = @()
    foreach ($svc in $SystemServices) {
        $serviceLines += "`"$($svc.Name)`",$($svc.StartupType),`"`""
    }

    $target = "$GPOName ($($SystemServices.Count) system service(s))"

    if ($PSCmdlet.ShouldProcess($target, "Set System Services via GptTmpl.inf")) {
        try {
            # Get GPO details
            $gpo = Get-GPOWithRetry -Name $GPOName -ConnParam $serverParam
            $gpoGuid = "{$($gpo.Id.ToString().ToUpper())}"
            $domainDNS = (Get-ADDomain @serverParam).DNSRoot
            $domainDN = (Get-ADDomain @serverParam).DistinguishedName

            # Build SYSVOL path
            $sysvolRoot = Get-LOCKmeADSysvolDrive -DomainDNSRoot $domainDNS -Credential $Credential
            $sysvolBase = "$sysvolRoot\$domainDNS\Policies\$gpoGuid"
            $infPath = "$sysvolBase\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            # Write [Service General Setting] section (merges with existing sections)
            Write-SecurityTemplateSection -InfPath $infPath -SectionName "Service General Setting" -SectionLines $serviceLines

            foreach ($svc in $SystemServices) {
                $label = $startupLabels[[int]$svc.StartupType]
                $desc = if ($svc.Description) { " ($($svc.Description))" } else { "" }
                Write-GPOLog -Message "  SVC: $($svc.Name) = $label$desc" -Level Success -LogDirectory $LogDirectory
            }

            # Update gPCMachineExtensionNames to include Security CSE
            $gpoDN = "CN=$gpoGuid,CN=Policies,CN=System,$domainDN"
            $gpoAD = Get-ADObject -Identity $gpoDN -Properties gPCMachineExtensionNames, versionNumber @serverParam

            $securityCSE = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"
            $currentExt = if ($gpoAD.gPCMachineExtensionNames) { $gpoAD.gPCMachineExtensionNames } else { "" }

            if ($currentExt -notlike "*827D319E*") {
                $newExt = $currentExt + $securityCSE
                Set-ADObject -Identity $gpoDN -Replace @{ gPCMachineExtensionNames = $newExt } @serverParam
            }

            # Increment machine version (lower 16 bits)
            $currentVersion = if ($gpoAD.versionNumber) { [int]$gpoAD.versionNumber } else { 0 }
            $userVersion = ($currentVersion -shr 16) -band 0xFFFF
            $machineVersion = ($currentVersion -band 0xFFFF) + 1
            $newVersion = ($userVersion -shl 16) -bor $machineVersion
            Set-ADObject -Identity $gpoDN -Replace @{ versionNumber = $newVersion } @serverParam

            # Update GPT.INI version to match
            $gptIniPath = "$sysvolBase\GPT.INI"
            if (Test-Path $gptIniPath) {
                $gptContent = Get-Content $gptIniPath -Raw
                $gptContent = $gptContent -replace 'Version=\d+', "Version=$newVersion"
                Set-Content -Path $gptIniPath -Value $gptContent -Encoding ASCII
            }

            Write-GPOLog -Message "System Services applied to GPO '$GPOName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-GPOLog -Message "Error setting System Services on '$GPOName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-GPOLog -Message "[WhatIf] System Services would be set on GPO '$GPOName':" -Level Info -LogDirectory $LogDirectory
        foreach ($svc in $SystemServices) {
            $label = $startupLabels[[int]$svc.StartupType]
            $desc = if ($svc.Description) { " - $($svc.Description)" } else { "" }
            Write-GPOLog -Message "  [WhatIf] $($svc.Name) = $label$desc" -Level Info -LogDirectory $LogDirectory
        }
    }
}

# ============================================================================
# Scripts (Computer Configuration > Windows Settings > Scripts)
# ============================================================================

function Set-GPOScript {
    <#
    .SYNOPSIS
        Deploys PowerShell scripts to a GPO via SYSVOL (Startup or Shutdown).
    .DESCRIPTION
        Writes each script's Content to the GPO's SYSVOL Machine\Scripts\<Type>
        directory, updates psscripts.ini with the ordered entries, registers the
        Scripts CSE on the GPO AD object, and increments the version number so
        Group Policy processes the change on next refresh.
    .PARAMETER GPOName
        Name of an existing GPO to configure.
    .PARAMETER Scripts
        Array of script objects with Type (Startup|Shutdown), ScriptName, ScriptPath
        (path relative to the tool root), optional Parameters, and optional Description.
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [array]$Scripts,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $target = "$GPOName ($($Scripts.Count) script(s))"

    if ($PSCmdlet.ShouldProcess($target, "Deploy PowerShell scripts to SYSVOL")) {
        try {
            $gpo = Get-GPOWithRetry -Name $GPOName -ConnParam $serverParam
            $gpoGuid = "{$($gpo.Id.ToString().ToUpper())}"
            $domainDNS = (Get-ADDomain @serverParam).DNSRoot
            $domainDN = (Get-ADDomain @serverParam).DistinguishedName

            $sysvolRoot = Get-LOCKmeADSysvolDrive -DomainDNSRoot $domainDNS -Credential $Credential
            $sysvolBase = "$sysvolRoot\$domainDNS\Policies\$gpoGuid"
            $machineScriptsPath = "$sysvolBase\Machine\Scripts"

            # Resolve tool root: Modules\GPO\ -> tool root (two levels up)
            $toolRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

            # Group scripts by type, preserving declaration order
            $scriptsByType = [ordered]@{}
            foreach ($s in $Scripts) {
                if (-not $scriptsByType.Contains($s.Type)) { $scriptsByType[$s.Type] = @() }
                $scriptsByType[$s.Type] += $s
            }

            # Copy script files and build psscripts.ini content
            $iniLines = [System.Collections.Generic.List[string]]::new()
            $isFirst = $true

            foreach ($type in $scriptsByType.Keys) {
                # Script goes in Machine\Scripts\<Type>\ inside the GPO policy folder
                # This directory is cached locally on each machine — accessible at Shutdown
                # without network, and treated as a local path by PowerShell (no execution
                # policy restriction on unsigned scripts).
                $typeDir = "$machineScriptsPath\$type"
                if (-not (Test-Path $typeDir)) {
                    New-Item -Path $typeDir -ItemType Directory -Force | Out-Null
                    Write-GPOLog -Message "  Created GPO scripts directory: '$typeDir'" -Level Info -LogDirectory $LogDirectory
                }

                if (-not $isFirst) { $iniLines.Add("") }
                $iniLines.Add("[$type]")

                $scriptIdx = 0
                foreach ($s in $scriptsByType[$type]) {
                    # Resolve source path and copy to GPO policy folder
                    $sourcePath = if ([System.IO.Path]::IsPathRooted($s.ScriptPath)) {
                        $s.ScriptPath
                    } else {
                        Join-Path $toolRoot $s.ScriptPath
                    }
                    if (-not (Test-Path $sourcePath)) {
                        throw "Script source not found: '$sourcePath'"
                    }
                    $destPath = "$typeDir\$($s.ScriptName)"
                    Copy-Item -Path $sourcePath -Destination $destPath -Force
                    Write-GPOLog -Message "  Copied '$sourcePath' -> '$destPath'" -Level Success -LogDirectory $LogDirectory

                    # psscripts.ini uses just the filename — gpscript.exe resolves it
                    # relative to the GPO's local cached scripts folder
                    $params = if ($s.Parameters) { $s.Parameters } else { "" }
                    $iniLines.Add("${scriptIdx}CmdLine=$($s.ScriptName)")
                    $iniLines.Add("${scriptIdx}Parameters=$params")
                    $scriptIdx++
                }
                $isFirst = $false
            }

            # Write psscripts.ini in Machine\Scripts\ (Unicode as required by GPO engine)
            if (-not (Test-Path $machineScriptsPath)) {
                New-Item -Path $machineScriptsPath -ItemType Directory -Force | Out-Null
            }
            $iniContent = ($iniLines -join "`r`n") + "`r`n"
            [System.IO.File]::WriteAllText("$machineScriptsPath\psscripts.ini", $iniContent, [System.Text.Encoding]::Unicode)
            Write-GPOLog -Message "  psscripts.ini written to '$machineScriptsPath'" -Level Info -LogDirectory $LogDirectory

            # Update gPCMachineExtensionNames to include Scripts CSE
            $scriptsCse = "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]"
            $gpoDN = "CN=$gpoGuid,CN=Policies,CN=System,$domainDN"
            $gpoAD = Get-ADObject -Identity $gpoDN -Properties gPCMachineExtensionNames, versionNumber @serverParam
            $currentExt = if ($gpoAD.gPCMachineExtensionNames) { $gpoAD.gPCMachineExtensionNames } else { "" }

            if ($currentExt -notlike "*42B5FAAE*") {
                $newExt = $currentExt + $scriptsCse
                Set-ADObject -Identity $gpoDN -Replace @{ gPCMachineExtensionNames = $newExt } @serverParam
                Write-GPOLog -Message "  Updated gPCMachineExtensionNames with Scripts CSE." -Level Info -LogDirectory $LogDirectory
            }

            # Increment machine version (lower 16 bits)
            $currentVersion = if ($gpoAD.versionNumber) { [int]$gpoAD.versionNumber } else { 0 }
            $userVersion = ($currentVersion -shr 16) -band 0xFFFF
            $machineVersion = ($currentVersion -band 0xFFFF) + 1
            $newVersion = ($userVersion -shl 16) -bor $machineVersion
            Set-ADObject -Identity $gpoDN -Replace @{ versionNumber = $newVersion } @serverParam

            # Update GPT.INI version to match
            $gptIniPath = "$sysvolBase\GPT.INI"
            if (Test-Path $gptIniPath) {
                $gptContent = Get-Content $gptIniPath -Raw
                $gptContent = $gptContent -replace 'Version=\d+', "Version=$newVersion"
                Set-Content -Path $gptIniPath -Value $gptContent -Encoding ASCII
            }

            foreach ($s in $Scripts) {
                $desc = if ($s.Description) { " ($($s.Description))" } else { "" }
                Write-GPOLog -Message "  Script [$($s.Type)]: $($s.ScriptName)$desc" -Level Success -LogDirectory $LogDirectory
            }

            Write-GPOLog -Message "Scripts applied to GPO '$GPOName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-GPOLog -Message "Error deploying scripts to GPO '$GPOName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-GPOLog -Message "[WhatIf] Scripts would be deployed to GPO '$GPOName':" -Level Info -LogDirectory $LogDirectory
        foreach ($s in $Scripts) {
            $desc = if ($s.Description) { " - $($s.Description)" } else { "" }
            Write-GPOLog -Message "  [WhatIf] [$($s.Type)] $($s.ScriptName)$desc" -Level Info -LogDirectory $LogDirectory
        }
    }
}

# Export module functions
Export-ModuleMember -Function @(
    'Write-GPOLog',
    'Import-GPOConfiguration',
    'Get-GPOEnvironmentInfo',
    'New-GPOFilteringGroup',
    'Set-GPOFilteringPermission',
    'Remove-GPOAuthenticatedUsers',
    'New-GPOSecurityPolicy',
    'Set-GPORegistryPreferences',
    'Set-GPOScript',
    'Set-GPOUserRightsAssignment',
    'Set-GPORestrictedGroups',
    'Set-GPOSecurityOptions',
    'Set-GPOSystemServices',
    'Set-GPOLink'
)
