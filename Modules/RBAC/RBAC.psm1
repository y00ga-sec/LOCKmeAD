# ============================================================================
# RBAC Module - Functions for deploying RBAC roles in Active Directory
# ============================================================================
# No #Requires -Modules ActiveDirectory here -- every entry point (LOCKmeAD.ps1,
# each Scripts\Deploy-*.ps1, Web\Start-LOCKmeADWeb.ps1) already checks for it
# before importing this module, and Pode's internal per-runspace module re-import
# (Import-PodeModulesInternal) can fail a module's own #Requires check in a fresh
# worker runspace even when the module is genuinely installed (confirmed against
# GPO.psm1/JIT.psm1's GroupPolicy requirement) -- removed here too for consistency.

Import-Module (Join-Path $PSScriptRoot "..\Common\Connection.psm1") -Force

# Module variable for the current log file path
$script:LogFilePath = $null

# GUID resolution maps — populated by Get-RBACGuidMap / Get-RBACExtendedRightMap
$script:GuidMap         = @{}
$script:ExtendedRightMap = @{}

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
        if ($role.DomainLocalGroups) {
            foreach ($dlGroup in $role.DomainLocalGroups) {
                if (-not $dlGroup.Name) {
                    throw "Role '$($role.Name)' contains a DomainLocalGroup without 'Name'."
                }
            }
        }
    }

    # Optional RootGroups validation
    if ($config.RootGroups) {
        foreach ($rootGroup in $config.RootGroups) {
            if (-not $rootGroup.Name) {
                throw "A RootGroup is missing the 'Name' property."
            }
            # Empty root groups are allowed (tier may have no roles yet)
        }
    }

    return $config
}

function Get-RBACEnvironmentInfo {
    <#
    .SYNOPSIS
        Retrieves Active Directory environment information.
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
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
        [ValidateSet("Global", "DomainLocal")]
        [string]$GroupScope,

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
            $newGroup = New-ADGroup @params @serverParam -PassThru
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
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GlobalGroupName,

        [Parameter(Mandatory)]
        [string]$DomainLocalGroupName,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    # Check if member is already present
    try {
        $members = Get-ADGroupMember -Identity $DomainLocalGroupName @serverParam -ErrorAction Stop
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
            Add-ADGroupMember -Identity $DomainLocalGroupName -Members $GlobalGroupName @serverParam
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
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [PSCustomObject]$Permission,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $path = $Permission.Path
    $rights = $Permission.Rights
    $inheritanceFlags = $Permission.InheritanceFlags
    $propagationFlags = $Permission.PropagationFlags
    $accessControlType = $Permission.AccessControlType

    $shareName  = $Permission.ShareName
    $shareRight = $Permission.ShareRight

    # Extract the file server from the original UNC path before any drive substitution below.
    $fileServer = if ($path -match '^\\\\([^\\]+)') { $Matches[1] } else { $null }

    # Plain filesystem cmdlets can't carry alternate credentials on a UNC path — when an
    # explicit credential is supplied, map the target share first so Get-Acl/Set-Acl/Test-Path
    # authenticate as that account instead of the current (possibly non-domain) session.
    if ($Credential -and $path -match '^(\\\\[^\\]+\\[^\\]+)') {
        $shareRoot = $Matches[1]
        $ntfsDriveName = "LOCKmeADNTFS"
        if (-not (Get-PSDrive -Name $ntfsDriveName -ErrorAction SilentlyContinue)) {
            try {
                New-PSDrive -Name $ntfsDriveName -PSProvider FileSystem -Root $shareRoot -Credential $Credential -Scope Global -ErrorAction Stop | Out-Null
            }
            catch {
                Write-RBACLog -Message "Could not map '$shareRoot' with the supplied credential: $_" -Level Error -LogDirectory $LogDirectory
                throw
            }
        }
        $path = $path -replace [regex]::Escape($shareRoot), "${ntfsDriveName}:"
    }

    if ($PSCmdlet.ShouldProcess("$path", "Apply NTFS ACE ($rights) for '$GroupName'")) {
        if (-not (Test-Path $path)) {
            Write-RBACLog -Message "Path '$path' is inaccessible or does not exist." -Level Error -LogDirectory $LogDirectory
            return
        }

        try {
            $acl = Get-Acl -Path $path
            $identity = (Get-ADDomain @serverParam).NetBIOSName + "\$GroupName"

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

        if ($shareName) {
            if (-not $fileServer) {
                Write-RBACLog -Message "SMB share permission skipped: path '$path' is not a UNC path. Use \\server\share format." -Level Warning -LogDirectory $LogDirectory
            }
            else {
                $identity = (Get-ADDomain @serverParam).NetBIOSName + "\$GroupName"
                try {
                    Invoke-LOCKmeADRemote -Server $fileServer -Credential $Credential -AlwaysRemote -ArgumentList $shareName, $identity, $shareRight -ScriptBlock {
                        param($sn, $acct, $right)
                        Grant-SmbShareAccess -Name $sn -AccountName $acct -AccessRight $right -Force -ErrorAction Stop
                    } | Out-Null
                    Write-RBACLog -Message "SMB share permission '$shareRight' applied on '\\$fileServer\$shareName' for '$GroupName'." -Level Success -LogDirectory $LogDirectory
                }
                catch {
                    Write-RBACLog -Message "Error applying SMB share permission on '\\$fileServer\$shareName': $_" -Level Error -LogDirectory $LogDirectory
                    throw
                }
            }
        }
    }
    else {
        Write-RBACLog -Message "[WhatIf] NTFS ACE '$rights' would be applied on '$path' for '$GroupName'." -Level Info -LogDirectory $LogDirectory
        if ($shareName) {
            Write-RBACLog -Message "[WhatIf] SMB share permission '$shareRight' would be applied on share '$shareName' for '$GroupName'." -Level Info -LogDirectory $LogDirectory
        }
    }
}

function Backup-RBACAdPermission {
    <#
    .SYNOPSIS
        Snapshots the current ACL of an AD object to an XML file before modification.
    .PARAMETER TargetOU
        Distinguished name of the OU whose ACL will be backed up.
    .PARAMETER BackupDirectory
        Directory where the backup XML file will be written.
    .OUTPUTS
        Full path of the created backup file, or $null on failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetOU,

        [Parameter(Mandatory)]
        [string]$BackupDirectory,

        [string]$Server,
        [PSCredential]$Credential
    )

    if (-not (Test-Path $BackupDirectory)) {
        New-Item -Path $BackupDirectory -ItemType Directory -Force | Out-Null
    }

    $adDrive = Get-LOCKmeADDrive -Server $Server -Credential $Credential

    try {
        $acl       = Get-Acl -Path "${adDrive}\$TargetOU" -ErrorAction Stop
        $sddl      = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
        $sanitized = $TargetOU -replace '[\\/:*?"<>|,=]', '_'
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $backupFile = Join-Path $BackupDirectory "ACL_${timestamp}_${sanitized}.xml"

        $auditUser = if ($Credential) { $Credential.UserName } else { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
        @{
            OU        = $TargetOU
            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            User      = $auditUser
            SDDL      = $sddl
        } | Export-Clixml -Path $backupFile -Force

        return $backupFile
    }
    catch {
        Write-Warning "Backup-RBACAdPermission: failed to back up ACL for '$TargetOU': $_"
        return $null
    }
}

function Restore-RBACAdPermission {
    <#
    .SYNOPSIS
        Restores the ACL of an AD object from a backup XML file.
    .DESCRIPTION
        Fully replaces the current DACL with the one captured at backup time.
        Any ACEs added after the backup are removed. This is intentionally destructive.
    .PARAMETER BackupFile
        Full path to the XML backup file produced by Backup-RBACAdPermission.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$BackupFile,

        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    if ([string]::IsNullOrWhiteSpace($BackupFile)) {
        throw "Backup file path is null or empty."
    }
    if (-not (Test-Path $BackupFile)) {
        throw "Backup file not found: '$BackupFile'"
    }

    $adDrive = Get-LOCKmeADDrive -Server $Server -Credential $Credential

    try {
        $data = Import-Clixml -Path $BackupFile

        # Resolve SDDL: new backups store SDDL directly; legacy backups stored the ACL object
        # which PowerShell serializes with a Sddl NoteProperty we can still read.
        $sddl = if ($data.SDDL) {
            $data.SDDL
        } elseif ($data.ACL -and $data.ACL.PSObject.Properties['Sddl'] -and $data.ACL.Sddl) {
            $data.ACL.Sddl
        } else {
            throw "Backup file '$BackupFile' is in an unsupported format (no SDDL). Re-deploy to generate a new backup."
        }

        $targetPath = "${adDrive}\$($data.OU)"

        if ($PSCmdlet.ShouldProcess($data.OU, "Restore AD ACL from '$BackupFile' (taken $($data.Timestamp) by $($data.User))")) {
            $acl = Get-Acl -Path $targetPath -ErrorAction Stop
            $acl.SetSecurityDescriptorSddlForm($sddl)
            Set-Acl -Path $targetPath -AclObject $acl -ErrorAction Stop
            Write-RBACLog -Message "ACL restored on '$($data.OU)' from '$BackupFile' (backup: $($data.Timestamp), user: $($data.User))." -Level Success -LogDirectory $LogDirectory
            return $true
        }
        else {
            Write-RBACLog -Message "[WhatIf] ACL would be restored on '$($data.OU)' from '$BackupFile'." -Level Info -LogDirectory $LogDirectory
            return $false
        }
    }
    catch {
        Write-RBACLog -Message "Error restoring ACL from '$BackupFile': $_" -Level Error -LogDirectory $LogDirectory
        throw
    }
}

function Get-RBACGuidMap {
    <#
    .SYNOPSIS
        Builds a name→GUID map from the AD schema (attributes and classes).
    .PARAMETER Server
        Target DC for all AD operations.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential)

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $script:GuidMap = @{}
    $script:DefaultServer = $Server
    $script:DefaultCredential = $Credential
    $schemaNamingContext = (Get-ADRootDSE @serverParam).schemaNamingContext

    Get-ADObject -SearchBase $schemaNamingContext `
                 -LDAPFilter "(|(objectClass=classSchema)(objectClass=attributeSchema))" `
                 -Properties lDAPDisplayName, schemaIDGUID @serverParam |
        ForEach-Object {
            if ($_.lDAPDisplayName -and $_.schemaIDGUID) {
                try {
                    $script:GuidMap[$_.lDAPDisplayName.ToLower()] = [System.Guid][byte[]]$_.schemaIDGUID
                } catch { }
            }
        }
}

function Get-RBACExtendedRightMap {
    <#
    .SYNOPSIS
        Builds a name→GUID map from the AD configuration partition (extended rights).
    .PARAMETER Server
        Target DC for all AD operations.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential)

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $script:ExtendedRightMap = @{}
    $configNamingContext = (Get-ADRootDSE @serverParam).configurationNamingContext

    Get-ADObject -SearchBase $configNamingContext `
                 -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" `
                 -Properties displayName, rightsGuid @serverParam |
        ForEach-Object {
            if ($_.displayName -and $_.rightsGuid) {
                try {
                    $script:ExtendedRightMap[$_.displayName.ToLower()] = [System.Guid]$_.rightsGuid
                } catch { }
            }
        }
}

function Resolve-RBACNameToGuid {
    <#
    .SYNOPSIS
        Resolves an attribute/class name or extended right name to its AD GUID.
    .DESCRIPTION
        Looks up the name in the schema map (Get-RBACGuidMap) then the extended rights
        map (Get-RBACExtendedRightMap). If the input is already a valid GUID it is
        returned as-is. If empty or the all-zeros GUID, returns the all-zeros GUID.
        Requires the maps to be populated first.
    .PARAMETER Name
        Human-readable name (e.g. "user", "ms-Mcs-AdmPwd", "Reset Password")
        or a raw GUID string.
    #>
    [CmdletBinding()]
    param([string]$Name)

    $nullGuid = [Guid]::Empty.ToString()

    if ([string]::IsNullOrWhiteSpace($Name) -or $Name -eq $nullGuid) {
        return $nullGuid
    }

    # Pass-through: input is already a GUID
    if ($Name -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        return $Name.ToLower()
    }

    $key = $Name.Trim().ToLower()

    if ($script:GuidMap.ContainsKey($key)) {
        return $script:GuidMap[$key].ToString()
    }

    if ($script:ExtendedRightMap.ContainsKey($key)) {
        return $script:ExtendedRightMap[$key].ToString()
    }

    # Cache miss — query AD directly as fallback
    try {
        $rootDseParams = @{ ErrorAction = 'Stop' }
        if ($script:DefaultServer)     { $rootDseParams['Server']     = $script:DefaultServer }
        if ($script:DefaultCredential) { $rootDseParams['Credential'] = $script:DefaultCredential }
        $rootDse = Get-ADRootDSE @rootDseParams

        $schemaParams = @{
            SearchBase  = $rootDse.schemaNamingContext
            LDAPFilter  = "(lDAPDisplayName=$Name)"
            Properties  = @('schemaIDGUID')
            ErrorAction = 'Stop'
        }
        if ($script:DefaultServer)     { $schemaParams['Server']     = $script:DefaultServer }
        if ($script:DefaultCredential) { $schemaParams['Credential'] = $script:DefaultCredential }

        $schemaObj = Get-ADObject @schemaParams | Select-Object -First 1
        if ($schemaObj -and $schemaObj.schemaIDGUID) {
            $guid = [System.Guid][byte[]]$schemaObj.schemaIDGUID
            $script:GuidMap[$key] = $guid
            return $guid.ToString()
        }

        $rightParams = @{
            SearchBase  = $rootDse.configurationNamingContext
            LDAPFilter  = "(&(objectclass=controlAccessRight)(displayName=$Name))"
            Properties  = @('rightsGuid')
            ErrorAction = 'Stop'
        }
        if ($script:DefaultServer)     { $rightParams['Server']     = $script:DefaultServer }
        if ($script:DefaultCredential) { $rightParams['Credential'] = $script:DefaultCredential }

        $rightObj = Get-ADObject @rightParams | Select-Object -First 1
        if ($rightObj -and $rightObj.rightsGuid) {
            $guid = [System.Guid]$rightObj.rightsGuid
            $script:ExtendedRightMap[$key] = $guid
            return $guid.ToString()
        }
    }
    catch { }

    Write-Warning "Resolve-RBACNameToGuid: '$Name' not found in AD schema or extended rights. The class/attribute may not exist in this environment."
    return $null
}

function Set-RBACADPermission {
    <#
    .SYNOPSIS
        Applies a delegation ACE on an Active Directory object.
    .PARAMETER GroupName
        Name of the group to grant permissions to.
    .PARAMETER Permission
        Permission object from JSON containing TargetOU, ADRights, ObjectType, InheritanceType, InheritedObjectType, AccessControlType.
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [PSCustomObject]$Permission,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory,

        [string]$BackupDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $targetOU            = $Permission.TargetOU
    $adRights            = $Permission.ADRights
    $inheritanceType     = $Permission.InheritanceType
    $accessControlType   = $Permission.AccessControlType

    $objectType          = Resolve-RBACNameToGuid -Name $Permission.ObjectType
    $inheritedObjectType = Resolve-RBACNameToGuid -Name $Permission.InheritedObjectType

    # Fail fast: a named type that couldn't be resolved would produce a null-GUID ACE
    # (= applies to ALL object types), which is dangerously overbroad.
    if ($null -eq $objectType) {
        throw "Cannot apply AD permission on '$targetOU': ObjectType '$($Permission.ObjectType)' could not be resolved. The schema class/attribute may not exist in this environment."
    }
    if ($null -eq $inheritedObjectType) {
        throw "Cannot apply AD permission on '$targetOU': InheritedObjectType '$($Permission.InheritedObjectType)' could not be resolved. The schema class may not exist in this environment."
    }

    if ($BackupDirectory) {
        $backupFile = Backup-RBACAdPermission -TargetOU $targetOU -BackupDirectory $BackupDirectory -Server $Server -Credential $Credential
        if ($backupFile) {
            Write-RBACLog -Message "ACL backup created: '$backupFile'." -Level Info -LogDirectory $LogDirectory
        }
    }

    $adDrive = Get-LOCKmeADDrive -Server $Server -Credential $Credential

    if ($PSCmdlet.ShouldProcess("$targetOU", "Apply AD delegation ($adRights) for '$GroupName'")) {
        try {
            # Retrieve the group SID
            $group = Get-ADGroup -Identity $GroupName @serverParam
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
            $ouPath = "${adDrive}\$targetOU"
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
        Requires remote registry access (Remote Registry) on the CA server when running
        domain-joined/implicit. When an explicit -Credential is supplied (e.g. running
        off-domain), the raw remote-registry API can't carry delegated credentials, so this
        instead runs the same logic inside an Invoke-Command -Credential session against
        -CAHostname — which requires WinRM (5985/5986) reachable on the CA server, in
        addition to the RPC/DCOM (135) needed for the implicit-mode remote registry path.
    .PARAMETER GroupName
        Name of the group to grant permissions to.
    .PARAMETER Permission
        Permission object from JSON containing CAName, CAHostname, Right.
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [PSCustomObject]$Permission,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

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

    # The ACE-building/registry logic is identical whether it runs locally against the
    # remote-registry handle (implicit mode) or inside an Invoke-Command session (explicit
    # credential) — expressed once here and invoked either directly or remotely below.
    $applyAceScript = {
        param($caName, $caHostname, $groupSID, $rightMask, $right, $groupName, $caConfig)

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
            $key.Close()
            $reg.Close()
            return "AlreadyExists"
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
        Restart-Service -Name CertSvc -Force
        return "Applied"
    }

    if ($PSCmdlet.ShouldProcess("$caConfig", "Apply ADCS right '$right' for '$GroupName'")) {
        try {
            # Retrieve the group SID
            $group = Get-ADGroup -Identity $GroupName @serverParam
            $groupSID = $group.SID

            $scriptArgs = @($caName, $caHostname, $groupSID, $rightMask, $right, $GroupName, $caConfig)
            if ($Credential) {
                Write-RBACLog -Message "Applying ADCS right '$right' on '$caConfig' via remote session (explicit credential)..." -Level Info -LogDirectory $LogDirectory
            }
            $result = Invoke-LOCKmeADRemote -Server $caHostname -Credential $Credential -ArgumentList $scriptArgs -ScriptBlock $applyAceScript

            if ($result -eq "AlreadyExists") {
                Write-RBACLog -Message "ADCS right '$right' already exists on '$caConfig' for '$GroupName'." -Level Warning -LogDirectory $LogDirectory
                return
            }

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

function Export-RBACDeploymentReport {
    <#
    .SYNOPSIS
        Parses an RBAC deployment log file and exports a CSV summary report.
    .PARAMETER LogPath
        Full path to the RBAC_*.log file to parse.
    .PARAMETER OutputPath
        Optional CSV output path. Defaults to the same directory as the log file with a .csv extension.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogPath,

        [string]$OutputPath
    )

    if (-not (Test-Path $LogPath)) {
        Write-RBACLog -Message "Log file not found: '$LogPath'. Cannot generate CSV report." -Level Warning
        return $null
    }

    if (-not $OutputPath) {
        $OutputPath = [System.IO.Path]::ChangeExtension($LogPath, '.csv')
    }

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
    $logPattern = '^\[(?<ts>[^\]]+)\] \[(?<level>[^\]]+)\] (?<msg>.+)$'

    foreach ($line in (Get-Content $LogPath -Encoding UTF8)) {
        if ($line -notmatch $logPattern) { continue }
        $ts    = $Matches['ts']
        $level = $Matches['level']
        $msg   = $Matches['msg']

        $isWhatIf = $msg -match '^\[WhatIf\] '
        if ($isWhatIf) { $msg = $msg -replace '^\[WhatIf\] ', '' }

        $row = $null

        if ($msg -match "^Group '(?<name>[^']+)' \((?<scope>Global|DomainLocal)\) (?:created|would be created) in '(?<ou>[^']+)'") {
            $row = [PSCustomObject]@{
                Timestamp = $ts
                Category  = 'GroupCreated'
                Status    = if ($isWhatIf) { 'Simulated' } else { 'Created' }
                Name      = $Matches['name']
                Scope     = $Matches['scope']
                Target    = $Matches['ou']
                Details   = ''
            }
        }
        elseif ($msg -match "^Group '(?<name>[^']+)' already exists in '(?<dn>[^']+)'") {
            $row = [PSCustomObject]@{
                Timestamp = $ts
                Category  = 'GroupCreated'
                Status    = 'AlreadyExists'
                Name      = $Matches['name']
                Scope     = ''
                Target    = $Matches['dn']
                Details   = ''
            }
        }
        elseif ($msg -match "^'(?<member>[^']+)' (?:added as|would be added as) member of '(?<target>[^']+)'") {
            $row = [PSCustomObject]@{
                Timestamp = $ts
                Category  = 'MembershipSet'
                Status    = if ($isWhatIf) { 'Simulated' } else { 'Added' }
                Name      = $Matches['member']
                Scope     = ''
                Target    = $Matches['target']
                Details   = ''
            }
        }
        elseif ($msg -match "^'(?<member>[^']+)' is already a member of '(?<target>[^']+)'") {
            $row = [PSCustomObject]@{
                Timestamp = $ts
                Category  = 'MembershipSet'
                Status    = 'AlreadyExists'
                Name      = $Matches['member']
                Scope     = ''
                Target    = $Matches['target']
                Details   = ''
            }
        }
        elseif ($msg -match "^NTFS ACE '(?<rights>[^']+)' (?:applied|would be applied) on '(?<path>[^']+)' for '(?<group>[^']+)'") {
            $row = [PSCustomObject]@{
                Timestamp = $ts
                Category  = 'NTFSPermission'
                Status    = if ($isWhatIf) { 'Simulated' } else { 'Applied' }
                Name      = $Matches['group']
                Scope     = ''
                Target    = $Matches['path']
                Details   = $Matches['rights']
            }
        }
        elseif ($msg -match "^AD delegation '(?<rights>[^']+)' (?:applied|would be applied) on '(?<ou>[^']+)' for '(?<group>[^']+)'") {
            $row = [PSCustomObject]@{
                Timestamp = $ts
                Category  = 'ADDelegation'
                Status    = if ($isWhatIf) { 'Simulated' } else { 'Applied' }
                Name      = $Matches['group']
                Scope     = ''
                Target    = $Matches['ou']
                Details   = $Matches['rights']
            }
        }
        elseif ($msg -match "^ADCS right '(?<right>[^']+)' (?:applied|would be applied) on '(?<ca>[^']+)' for '(?<group>[^']+)'") {
            $row = [PSCustomObject]@{
                Timestamp = $ts
                Category  = 'ADCSPermission'
                Status    = if ($isWhatIf) { 'Simulated' } else { 'Applied' }
                Name      = $Matches['group']
                Scope     = ''
                Target    = $Matches['ca']
                Details   = $Matches['right']
            }
        }
        elseif ($level -eq 'Error') {
            $row = [PSCustomObject]@{
                Timestamp = $ts
                Category  = 'Error'
                Status    = 'Error'
                Name      = ''
                Scope     = ''
                Target    = ''
                Details   = $msg
            }
        }

        if ($null -ne $row) { $rows.Add($row) }
    }

    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-RBACLog -Message "CSV report generated: '$OutputPath' ($($rows.Count) entries)." -Level Success
    return $OutputPath
}

function Set-RBACSharePermission {
    <#
    .SYNOPSIS
        Applies an SMB share permission for a group on a remote file server.
    .PARAMETER GroupName
        Name of the group to grant permissions to.
    .PARAMETER Permission
        Permission object containing ShareServer, ShareName, ShareRight.
    .PARAMETER Server
        Target DC for AD queries (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [PSCustomObject]$Permission,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam  = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $fileServer = $Permission.ShareServer
    $shareName  = $Permission.ShareName
    $shareRight = $Permission.ShareRight

    if ($PSCmdlet.ShouldProcess("\\$fileServer\$shareName", "Apply SMB share permission ($shareRight) for '$GroupName'")) {
        $identity = (Get-ADDomain @serverParam).NetBIOSName + "\$GroupName"
        try {
            Invoke-LOCKmeADRemote -Server $fileServer -Credential $Credential -AlwaysRemote -ArgumentList $shareName, $identity, $shareRight -ScriptBlock {
                param($sn, $acct, $right)
                Grant-SmbShareAccess -Name $sn -AccountName $acct -AccessRight $right -Force -ErrorAction Stop
            } | Out-Null
            Write-RBACLog -Message "SMB share permission '$shareRight' applied on '\\$fileServer\$shareName' for '$GroupName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-RBACLog -Message "Error applying SMB share permission on '\\$fileServer\$shareName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-RBACLog -Message "[WhatIf] SMB share permission '$shareRight' would be applied on '\\$fileServer\$shareName' for '$GroupName'." -Level Info -LogDirectory $LogDirectory
    }
}

# Export module functions
Export-ModuleMember -Function @(
    'Write-RBACLog',
    'Import-RBACConfiguration',
    'Get-RBACEnvironmentInfo',
    'Get-RBACGuidMap',
    'Get-RBACExtendedRightMap',
    'Resolve-RBACNameToGuid',
    'Backup-RBACAdPermission',
    'Restore-RBACAdPermission',
    'New-RBACGroup',
    'Add-RBACGroupMember',
    'Set-RBACNTFSPermission',
    'Set-RBACSharePermission',
    'Set-RBACADPermission',
    'Set-RBACADCSPermission',
    'Export-RBACDeploymentReport'
)
