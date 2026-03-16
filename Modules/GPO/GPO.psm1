#Requires -Modules ActiveDirectory, GroupPolicy

# ============================================================================
# GPO Module - Functions for deploying security GPOs from JSON templates
# ============================================================================

# Module variable for the current log file path
$script:LogFilePath = $null

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

        $hasRegistry = $gpo.RegistrySettings -and $gpo.RegistrySettings.Count -gt 0
        $hasURA = $gpo.UserRightsAssignments -and $gpo.UserRightsAssignments.Count -gt 0

        if (-not $hasRegistry -and -not $hasURA) {
            throw "GPO '$($gpo.Name)' has no 'RegistrySettings' or 'UserRightsAssignments' defined."
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

        # Validate User Rights Assignments
        if ($hasURA) {
            foreach ($assignment in $gpo.UserRightsAssignments) {
                if (-not $assignment.Right) {
                    throw "GPO '$($gpo.Name)': a User Rights Assignment is missing the 'Right' property."
                }
                if (-not $assignment.Groups -or $assignment.Groups.Count -eq 0) {
                    throw "GPO '$($gpo.Name)': User Rights Assignment '$($assignment.Right)' has no 'Groups' defined."
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

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

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

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

    # Apply Group Policy extended right GUID
    $applyGPORight = [guid]"edacfd8f-ffb3-11d1-b41d-00a0c968f939"

    if ($PSCmdlet.ShouldProcess($GPOName, "Set filtering ACEs (Apply: $ApplyGroupName, Deny: $DenyGroupName)")) {
        try {
            $gpo = Get-GPO -Name $GPOName @serverParam -ErrorAction Stop
            $domainDN = (Get-ADDomain @serverParam).DistinguishedName
            $gpoDN = "CN={$($gpo.Id.ToString().ToUpper())},CN=Policies,CN=System,$domainDN"

            $acl = Get-Acl -Path "AD:\$gpoDN"

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

            # Commit ACL
            Set-Acl -Path "AD:\$gpoDN" -AclObject $acl
            Write-GPOLog -Message "Filtering permissions applied to GPO '$GPOName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-GPOLog -Message "Error setting filtering permissions on GPO '$GPOName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-GPOLog -Message "[WhatIf] Filtering ACEs would be set on GPO '$GPOName':" -Level Info -LogDirectory $LogDirectory
        Write-GPOLog -Message "  [WhatIf] Authenticated Users would be removed from security filtering" -Level Info -LogDirectory $LogDirectory
        Write-GPOLog -Message "  [WhatIf] Allow Read + Apply Group Policy -> $ApplyGroupName" -Level Info -LogDirectory $LogDirectory
        Write-GPOLog -Message "  [WhatIf] Deny Apply Group Policy -> $DenyGroupName" -Level Info -LogDirectory $LogDirectory
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

        [string]$Server,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

    $existingGPO = Get-GPO -Name $Name @serverParam -ErrorAction SilentlyContinue
    $action = if ($existingGPO) { "Update" } else { "Create" }

    if ($existingGPO) {
        Write-GPOLog -Message "GPO '$Name' already exists (ID: $($existingGPO.Id)). Ensuring settings are applied." -Level Warning -LogDirectory $LogDirectory
    }

    $settingLabel = if ($RegistrySettings.Count -gt 0) { "$($RegistrySettings.Count) registry settings" } else { "no registry settings" }

    if ($PSCmdlet.ShouldProcess($Name, "$action security GPO ($settingLabel)")) {
        try {
            if (-not $existingGPO) {
                New-GPO -Name $Name -Comment $Description @serverParam | Out-Null
                Write-GPOLog -Message "GPO '$Name' created." -Level Success -LogDirectory $LogDirectory
            }

            foreach ($setting in $RegistrySettings) {
                Set-GPRegistryValue -Name $Name `
                                    -Key $setting.Key `
                                    -ValueName $setting.ValueName `
                                    -Value $setting.Value `
                                    -Type $setting.Type `
                                    @serverParam | Out-Null

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
        foreach ($setting in $RegistrySettings) {
            $desc = if ($setting.Description) { " - $($setting.Description)" } else { "" }
            Write-GPOLog -Message "  [WhatIf] $($setting.Key)\$($setting.ValueName) = $($setting.Value)$desc" -Level Info -LogDirectory $LogDirectory
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

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

    # Check if link already exists
    try {
        $inheritance = Get-GPInheritance -Target $TargetOU @serverParam
        $existingLink = $inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $GPOName }
        if ($existingLink) {
            Write-GPOLog -Message "GPO '$GPOName' is already linked to '$TargetOU'." -Level Warning -LogDirectory $LogDirectory
            return
        }
    }
    catch {
        Write-GPOLog -Message "Error checking GPO links for '$TargetOU': $_" -Level Error -LogDirectory $LogDirectory
        throw
    }

    if ($PSCmdlet.ShouldProcess($TargetOU, "Link GPO '$GPOName'")) {
        try {
            New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled Yes @serverParam | Out-Null
            Write-GPOLog -Message "GPO '$GPOName' linked to '$TargetOU'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-GPOLog -Message "Error linking GPO '$GPOName' to '$TargetOU': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-GPOLog -Message "[WhatIf] GPO '$GPOName' would be linked to '$TargetOU'." -Level Info -LogDirectory $LogDirectory
    }
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

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

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
            $gpo = Get-GPO -Name $GPOName @serverParam -ErrorAction Stop
            $gpoGuid = "{$($gpo.Id.ToString().ToUpper())}"
            $domainDNS = (Get-ADDomain @serverParam).DNSRoot
            $domainDN = (Get-ADDomain @serverParam).DistinguishedName

            # Build SYSVOL path
            $sysvolBase = "\\$domainDNS\SYSVOL\$domainDNS\Policies\$gpoGuid"
            $secEditPath = "$sysvolBase\Machine\Microsoft\Windows NT\SecEdit"
            $infPath = "$secEditPath\GptTmpl.inf"

            if (-not (Test-Path $secEditPath)) {
                New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
            }

            # Build GptTmpl.inf content
            $infLines = @(
                "[Unicode]"
                "Unicode=yes"
                "[Version]"
                'signature="$CHICAGO$"'
                "Revision=1"
                "[Privilege Rights]"
            )
            $infLines += $privilegeLines
            $infContent = ($infLines -join "`r`n") + "`r`n"

            # Write GptTmpl.inf (UTF-16LE as Windows Security CSE expects)
            [System.IO.File]::WriteAllText($infPath, $infContent, [System.Text.Encoding]::Unicode)

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

# Export module functions
Export-ModuleMember -Function @(
    'Write-GPOLog',
    'Import-GPOConfiguration',
    'Get-GPOEnvironmentInfo',
    'New-GPOFilteringGroup',
    'Set-GPOFilteringPermission',
    'New-GPOSecurityPolicy',
    'Set-GPOUserRightsAssignment',
    'Set-GPOLink'
)
