#Requires -Modules ActiveDirectory

# ============================================================================
# RBAC Module - Functions for deploying RBAC roles in Active Directory
# ============================================================================

# Module variable for the current log file path
$script:LogFilePath = $null

function Write-RBACLog {
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
            $logFileName = "RBAC_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            $script:LogFilePath = Join-Path $LogDirectory $logFileName
        }
        $logEntry | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8
    }
}

function Import-RBACConfiguration {
    <#
    .SYNOPSIS
        Reads and validates the JSON configuration file.
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
    if (-not $config.Settings.GroupPrefixes) {
        throw "The 'Settings.GroupPrefixes' section is missing."
    }
    if (-not $config.Settings.DefaultOU) {
        throw "The 'Settings.DefaultOU' section is missing."
    }
    if (-not $config.Roles -or $config.Roles.Count -eq 0) {
        throw "The 'Roles' section is missing or empty."
    }

    # Validate each role
    foreach ($role in $config.Roles) {
        if (-not $role.Name) {
            throw "A role is missing the 'Name' property."
        }
        if (-not $role.GlobalGroup) {
            throw "Role '$($role.Name)' is missing 'GlobalGroup'."
        }
        if (-not $role.GlobalGroup.Name) {
            throw "Role '$($role.Name)': GlobalGroup.Name is missing."
        }
        if (-not $role.DomainLocalGroups -or $role.DomainLocalGroups.Count -eq 0) {
            throw "Role '$($role.Name)' is missing 'DomainLocalGroups'."
        }
        foreach ($dlGroup in $role.DomainLocalGroups) {
            if (-not $dlGroup.Name) {
                throw "Role '$($role.Name)' contains a DomainLocalGroup without 'Name'."
            }
        }
    }

    # Optional RootGroups validation
    if ($config.RootGroups) {
        foreach ($rootGroup in $config.RootGroups) {
            if (-not $rootGroup.Name) {
                throw "A RootGroup is missing the 'Name' property."
            }
            if (-not $rootGroup.MemberOf -or $rootGroup.MemberOf.Count -eq 0) {
                throw "RootGroup '$($rootGroup.Name)' is missing 'MemberOf' or the list is empty."
            }
        }
    }

    return $config
}

function Get-RBACEnvironmentInfo {
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

function New-RBACGroup {
    <#
    .SYNOPSIS
        Creates an Active Directory group.
    .PARAMETER Name
        Group name.
    .PARAMETER Description
        Group description.
    .PARAMETER GroupScope
        Group scope: Global or DomainLocal.
    .PARAMETER OU
        Destination OU for the group.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Description = "",

        [Parameter(Mandatory)]
        [ValidateSet("Global", "DomainLocal")]
        [string]$GroupScope,

        [Parameter(Mandatory)]
        [string]$OU,

        [string]$LogDirectory
    )

    # Check if group already exists
    try {
        $existingGroup = Get-ADGroup -Identity $Name -ErrorAction Stop
        Write-RBACLog -Message "Group '$Name' already exists in '$($existingGroup.DistinguishedName)'." -Level Warning -LogDirectory $LogDirectory
        return $existingGroup
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        # Group does not exist, proceed with creation
    }

    if ($PSCmdlet.ShouldProcess($Name, "Create AD group ($GroupScope)")) {
        try {
            $params = @{
                Name           = $Name
                SamAccountName = $Name
                GroupScope     = $GroupScope
                GroupCategory  = "Security"
                Description    = $Description
                Path           = $OU
            }
            $newGroup = New-ADGroup @params -PassThru
            Write-RBACLog -Message "Group '$Name' ($GroupScope) created in '$OU'." -Level Success -LogDirectory $LogDirectory
            return $newGroup
        }
        catch {
            Write-RBACLog -Message "Error creating group '$Name': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-RBACLog -Message "[WhatIf] Group '$Name' ($GroupScope) would be created in '$OU'." -Level Info -LogDirectory $LogDirectory
    }
}

function Add-RBACGroupMember {
    <#
    .SYNOPSIS
        Adds a Global group as a member of a DomainLocal group.
    .PARAMETER GlobalGroupName
        Name of the Global group to add.
    .PARAMETER DomainLocalGroupName
        Name of the target DomainLocal group.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GlobalGroupName,

        [Parameter(Mandatory)]
        [string]$DomainLocalGroupName,

        [string]$LogDirectory
    )

    # Check if member is already present
    try {
        $members = Get-ADGroupMember -Identity $DomainLocalGroupName -ErrorAction Stop
        $alreadyMember = $members | Where-Object { $_.SamAccountName -eq $GlobalGroupName }
        if ($alreadyMember) {
            Write-RBACLog -Message "'$GlobalGroupName' is already a member of '$DomainLocalGroupName'." -Level Warning -LogDirectory $LogDirectory
            return
        }
    }
    catch {
        # DL group may not exist yet in WhatIf mode
    }

    if ($PSCmdlet.ShouldProcess("$GlobalGroupName -> $DomainLocalGroupName", "Add member")) {
        try {
            Add-ADGroupMember -Identity $DomainLocalGroupName -Members $GlobalGroupName
            Write-RBACLog -Message "'$GlobalGroupName' added as member of '$DomainLocalGroupName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-RBACLog -Message "Error adding '$GlobalGroupName' to '$DomainLocalGroupName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-RBACLog -Message "[WhatIf] '$GlobalGroupName' would be added as member of '$DomainLocalGroupName'." -Level Info -LogDirectory $LogDirectory
    }
}

function Set-RBACNTFSPermission {
    <#
    .SYNOPSIS
        Applies an NTFS ACE on a path.
    .PARAMETER GroupName
        Name of the group to grant permissions to.
    .PARAMETER Permission
        Permission object from JSON containing Path, Rights, InheritanceFlags, PropagationFlags, AccessControlType.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [PSCustomObject]$Permission,

        [string]$LogDirectory
    )

    $path = $Permission.Path
    $rights = $Permission.Rights
    $inheritanceFlags = $Permission.InheritanceFlags
    $propagationFlags = $Permission.PropagationFlags
    $accessControlType = $Permission.AccessControlType

    if ($PSCmdlet.ShouldProcess("$path", "Apply NTFS ACE ($rights) for '$GroupName'")) {
        if (-not (Test-Path $path)) {
            Write-RBACLog -Message "Path '$path' is inaccessible or does not exist." -Level Error -LogDirectory $LogDirectory
            return
        }

        try {
            $acl = Get-Acl -Path $path
            $identity = (Get-ADDomain).NetBIOSName + "\$GroupName"

            $aceRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $identity,
                [System.Security.AccessControl.FileSystemRights]$rights,
                [System.Security.AccessControl.InheritanceFlags]$inheritanceFlags,
                [System.Security.AccessControl.PropagationFlags]$propagationFlags,
                [System.Security.AccessControl.AccessControlType]$accessControlType
            )

            $acl.AddAccessRule($aceRule)
            Set-Acl -Path $path -AclObject $acl
            Write-RBACLog -Message "NTFS ACE '$rights' applied on '$path' for '$GroupName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-RBACLog -Message "Error applying NTFS ACE on '$path': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-RBACLog -Message "[WhatIf] NTFS ACE '$rights' would be applied on '$path' for '$GroupName'." -Level Info -LogDirectory $LogDirectory
    }
}

function Set-RBACADPermission {
    <#
    .SYNOPSIS
        Applies a delegation ACE on an Active Directory object.
    .PARAMETER GroupName
        Name of the group to grant permissions to.
    .PARAMETER Permission
        Permission object from JSON containing TargetOU, ADRights, ObjectType, InheritanceType, InheritedObjectType, AccessControlType.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [PSCustomObject]$Permission,

        [string]$LogDirectory
    )

    $targetOU = $Permission.TargetOU
    $adRights = $Permission.ADRights
    $objectType = $Permission.ObjectType
    $inheritanceType = $Permission.InheritanceType
    $inheritedObjectType = $Permission.InheritedObjectType
    $accessControlType = $Permission.AccessControlType

    if ($PSCmdlet.ShouldProcess("$targetOU", "Apply AD delegation ($adRights) for '$GroupName'")) {
        try {
            # Retrieve the group SID
            $group = Get-ADGroup -Identity $GroupName
            $groupSID = New-Object System.Security.Principal.SecurityIdentifier($group.SID)

            # Build the AD ACE
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $groupSID,
                [System.DirectoryServices.ActiveDirectoryRights]$adRights,
                [System.Security.AccessControl.AccessControlType]$accessControlType,
                [Guid]$objectType,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]$inheritanceType,
                [Guid]$inheritedObjectType
            )

            # Apply the ACE on the target OU
            $ouPath = "AD:\$targetOU"
            $acl = Get-Acl -Path $ouPath
            $acl.AddAccessRule($ace)
            Set-Acl -Path $ouPath -AclObject $acl

            Write-RBACLog -Message "AD delegation '$adRights' applied on '$targetOU' for '$GroupName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-RBACLog -Message "Error applying AD delegation on '$targetOU': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-RBACLog -Message "[WhatIf] AD delegation '$adRights' would be applied on '$targetOU' for '$GroupName'." -Level Info -LogDirectory $LogDirectory
    }
}

function Set-RBACADCSPermission {
    <#
    .SYNOPSIS
        Applies an ADCS permission (ManageCA, ManageCertificates, Enroll) on a Certificate Authority.
    .DESCRIPTION
        Modifies the CA security descriptor via the remote registry of the CA server.
        Supported rights: ManageCA (0x01), ManageCertificates (0x02), Enroll (0x04), Read (0x100).
        Requires remote registry access (Remote Registry) on the CA server.
    .PARAMETER GroupName
        Name of the group to grant permissions to.
    .PARAMETER Permission
        Permission object from JSON containing CAName, CAHostname, Right.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [PSCustomObject]$Permission,

        [string]$LogDirectory
    )

    $caName = $Permission.CAName
    $caHostname = $Permission.CAHostname
    $right = $Permission.Right
    $caConfig = "$caHostname\$caName"

    # ADCS access masks (ACTRL_CERTSRV_*)
    $rightMask = switch ($right) {
        "ManageCA"            { 0x01 }
        "ManageCertificates"  { 0x02 }
        "Enroll"              { 0x04 }
        "Read"                { 0x100 }
        default {
            Write-RBACLog -Message "Unknown ADCS right: '$right'. Valid values: ManageCA, ManageCertificates, Enroll, Read." -Level Error -LogDirectory $LogDirectory
            return
        }
    }

    if ($PSCmdlet.ShouldProcess("$caConfig", "Apply ADCS right '$right' for '$GroupName'")) {
        try {
            # Retrieve the group SID
            $group = Get-ADGroup -Identity $GroupName
            $groupSID = $group.SID

            # Open the remote registry on the CA server
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine,
                $caHostname
            )
            $regPath = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName"
            $key = $reg.OpenSubKey($regPath, $true)

            if (-not $key) {
                throw "Registry key not found: HKLM:\$regPath on $caHostname. Verify the CA name and connectivity."
            }

            # Read the current security descriptor
            $sdBytes = [byte[]]$key.GetValue("Security")
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sdBytes, 0)

            # Check if the ACE already exists
            $aceExists = $false
            foreach ($existingAce in $sd.DiscretionaryAcl) {
                if ($existingAce.SecurityIdentifier -eq $groupSID -and
                    $existingAce.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed -and
                    ($existingAce.AccessMask -band $rightMask) -eq $rightMask) {
                    $aceExists = $true
                    break
                }
            }

            if ($aceExists) {
                Write-RBACLog -Message "ADCS right '$right' already exists on '$caConfig' for '$GroupName'." -Level Warning -LogDirectory $LogDirectory
                $key.Close()
                $reg.Close()
                return
            }

            # Create the new ACE (Allow)
            $ace = New-Object System.Security.AccessControl.CommonAce(
                [System.Security.AccessControl.AceFlags]::None,
                [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                $rightMask,
                $groupSID,
                $false,
                $null
            )

            # Add the ACE to the DACL
            $sd.DiscretionaryAcl.InsertAce($sd.DiscretionaryAcl.Count, $ace)

            # Write the modified SD back to the registry
            $newSdBytes = New-Object byte[] $sd.BinaryLength
            $sd.GetBinaryForm($newSdBytes, 0)
            $key.SetValue("Security", [byte[]]$newSdBytes, [Microsoft.Win32.RegistryValueKind]::Binary)

            $key.Close()
            $reg.Close()

            # Restart CertSvc service to apply changes
            Write-RBACLog -Message "Restarting CertSvc service on '$caHostname'..." -Level Info -LogDirectory $LogDirectory
            Get-Service -ComputerName $caHostname -Name CertSvc | Restart-Service -Force

            Write-RBACLog -Message "ADCS right '$right' applied on '$caConfig' for '$GroupName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-RBACLog -Message "Error applying ADCS right '$right' on '$caConfig': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-RBACLog -Message "[WhatIf] ADCS right '$right' would be applied on '$caConfig' for '$GroupName'." -Level Info -LogDirectory $LogDirectory
    }
}

# Export module functions
Export-ModuleMember -Function @(
    'Write-RBACLog',
    'Import-RBACConfiguration',
    'Get-RBACEnvironmentInfo',
    'New-RBACGroup',
    'Add-RBACGroupMember',
    'Set-RBACNTFSPermission',
    'Set-RBACADPermission',
    'Set-RBACADCSPermission'
)
