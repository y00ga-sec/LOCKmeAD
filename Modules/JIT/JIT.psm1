# ============================================================================
# JIT Module - Functions for deploying JIT Access Manager via GPO
# ============================================================================
# No #Requires -Modules here (ActiveDirectory/GroupPolicy) -- every entry point
# (LOCKmeAD.ps1, Launch-GUI.ps1, each Scripts\Deploy-*.ps1) already checks that
# both modules are available before importing this one, so a per-module #Requires
# would only be a redundant second layer.

Import-Module (Join-Path $PSScriptRoot "..\Common\Connection.psm1") -Force
# Remove-GPOAuthenticatedUsers is reused for this module's own GPO -- see step 3 in
# New-JITDeploymentGPO for why Set-GPPermission cannot do that job.
Import-Module (Join-Path $PSScriptRoot "..\GPO\GPO.psm1") -Force

# Module variable for the current log file path
$script:LogFilePath = $null

function Write-JITLog {
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

    # Write to log file.
    # -WhatIf:$false on both calls: they are ShouldProcess-aware and inherit $WhatIfPreference from
    # the calling scope, so a line emitted by another function of this module running under -WhatIf
    # was silently dropped -- see Write-GPOLog in Modules\GPO\GPO.psm1 for the full rationale.
    if ($LogDirectory) {
        if (-not (Test-Path $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force -WhatIf:$false | Out-Null
        }
        if (-not $script:LogFilePath) {
            $logFileName = "JIT_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            $script:LogFilePath = Join-Path $LogDirectory $logFileName
        }
        $logEntry | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8 -WhatIf:$false
    }
}

# ============================================================================
# Configuration
# ============================================================================

function Import-JITConfiguration {
    <#
    .SYNOPSIS
        Reads and validates the JIT JSON configuration file.
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
    if (-not $config.Settings.ToolsSharePath) {
        throw "Settings.ToolsSharePath is missing or empty."
    }
    if (-not $config.Settings.InstallPath) {
        throw "Settings.InstallPath is missing or empty."
    }
    if (-not $config.Settings.FilteringGroupsOU) {
        throw "Settings.FilteringGroupsOU is missing or empty."
    }
    if (-not $config.Settings.GPO) {
        throw "Settings.GPO section is missing."
    }
    if (-not $config.Settings.GPO.Name) {
        throw "Settings.GPO.Name is missing or empty."
    }
    if (-not ($config.Settings.GPO.PSObject.Properties.Name -contains 'LinkTargets')) {
        throw "Settings.GPO.LinkTargets is missing (use an empty array if none)."
    }

    return $config
}

# ============================================================================
# Environment
# ============================================================================

function Get-JITEnvironmentInfo {
    <#
    .SYNOPSIS
        Retrieves Active Directory environment information including PAM feature status.
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

        $pamFeature = Get-ADOptionalFeature -Filter { Name -eq 'Privileged Access Management Feature' } @serverParam -ErrorAction SilentlyContinue
        $pamEnabled = ($pamFeature -and $pamFeature.EnabledScopes.Count -gt 0)

        return [PSCustomObject]@{
            CurrentDC    = $currentDC
            IsPDC        = $isPDC
            PDCEmulator  = $pdcEmulator
            DomainName   = $domain.DNSRoot
            DomainDN     = $domain.DistinguishedName
            ForestName   = $forest.Name
            ForestMode   = $forest.ForestMode
            DomainMode   = $domain.DomainMode
            PamEnabled   = $pamEnabled
        }
    }
    catch {
        throw "Unable to retrieve Active Directory information: $_"
    }
}

# ============================================================================
# Tool Publishing
# ============================================================================

function Publish-JITTool {
    <#
    .SYNOPSIS
        Publishes the JIT Access Manager tool to a distribution share.
    .DESCRIPTION
        Copies Start-JIT.ps1 to the distribution share and writes a version.txt
        file with the current timestamp so target machines can detect updates.
    .PARAMETER SourcePath
        Path to the local Start-JIT.ps1 script.
    .PARAMETER DistributionSharePath
        UNC path to the distribution share (e.g., \\DOMAIN\NETLOGON\JIT).
    .PARAMETER LogDirectory
        Log directory.
    .PARAMETER Credential
        Explicit credential to authenticate with when publishing to the share.
        Required when not domain-joined (plain filesystem cmdlets can't carry
        alternate credentials on a UNC path directly, so this maps the share with
        the credential first).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$DistributionSharePath,

        [string]$LogDirectory,
        [PSCredential]$Credential
    )

    if ($Credential -and $DistributionSharePath -match '^(\\\\[^\\]+\\[^\\]+)') {
        # Mount a PSDrive purely for its side effect: the FileSystem provider's
        # -Credential handling establishes a real authenticated SMB session for this
        # UNC path, not just a PowerShell-internal abstraction -- so the plain UNC
        # path (not the PSDrive name) can be used directly afterward, which also
        # keeps it safe for any raw .NET file I/O that doesn't understand PSDrives.
        $shareRoot = $Matches[1]
        $driveName = "LOCKmeADJITShare"
        if (-not (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name $driveName -PSProvider FileSystem -Root $shareRoot -Credential $Credential -Scope Global | Out-Null
        }
    }

    if (-not (Test-Path $SourcePath)) {
        Write-JITLog -Message "Source file not found: '$SourcePath'" -Level Error -LogDirectory $LogDirectory
        throw "Source file not found: '$SourcePath'"
    }

    if ($PSCmdlet.ShouldProcess($DistributionSharePath, "Publish JIT tool from '$SourcePath'")) {
        try {
            # Create the target directory on the share if it doesn't exist
            if (-not (Test-Path $DistributionSharePath)) {
                New-Item -Path $DistributionSharePath -ItemType Directory -Force | Out-Null
                Write-JITLog -Message "Created distribution share directory: '$DistributionSharePath'" -Level Info -LogDirectory $LogDirectory
            }

            # Copy Start-JIT.ps1 to the share
            Copy-Item -Path $SourcePath -Destination $DistributionSharePath -Force
            Write-JITLog -Message "Copied '$SourcePath' to '$DistributionSharePath'" -Level Info -LogDirectory $LogDirectory

            # Write a version.txt with current timestamp
            $versionFile = Join-Path $DistributionSharePath "version.txt"
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $timestamp | Set-Content -Path $versionFile -Encoding UTF8 -Force
            Write-JITLog -Message "Published JIT tool to '$DistributionSharePath' (version: $timestamp)" -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-JITLog -Message "Error publishing JIT tool: $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-JITLog -Message "[WhatIf] JIT tool would be published from '$SourcePath' to '$DistributionSharePath'" -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# GPO Creation
# ============================================================================

function New-JITDeploymentGPO {
    <#
    .SYNOPSIS
        Creates a GPO to deploy the JIT Access Manager via startup script.
    .DESCRIPTION
        Creates the GPO, configures security filtering with a dedicated DomainLocal
        group, and sets up a PowerShell startup script that copies the tool from a
        distribution share to target machines. Idempotent: updates existing GPOs.
    .PARAMETER GPOName
        Name of the GPO to create.
    .PARAMETER GPODescription
        Description for the GPO.
    .PARAMETER FilteringGroupsOU
        Distinguished Name of the OU where the filtering group is created.
    .PARAMETER InstallPath
        Local installation path on target machines.
    .PARAMETER DistributionSharePath
        UNC path to the distribution share containing the tool.
    .PARAMETER DomainDN
        Distinguished Name of the domain.
    .PARAMETER Server
        Target DC for all AD and GP operations.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [string]$GPODescription = "",

        [Parameter(Mandatory)]
        [string]$FilteringGroupsOU,

        [Parameter(Mandatory)]
        [string]$InstallPath,

        [Parameter(Mandatory)]
        [string]$DistributionSharePath,

        [Parameter(Mandatory)]
        [string]$DomainDN,

        [string]$Server,

        [PSCredential]$Credential,
        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    # Get-GPO/New-GPO/Set-GPPermission have no -Credential parameter at all (unlike the
    # ActiveDirectory module) -- route them through a remote WinRM session against
    # -Server when an explicit credential is in play.
    $gpoServer = if ($Credential) { $null } else { $Server }

    $filteringGroupName = "DL_JIT_Tool_Machines"

    # --- Step 1: Create or reuse GPO ---
    $existingGPO = Invoke-LOCKmeADRemote -Server $Server -Credential $Credential -ArgumentList $GPOName, $gpoServer -ScriptBlock {
        param($GPOName, $Server)
        $p = @{}
        if ($Server) { $p.Server = $Server }
        Get-GPO -Name $GPOName @p -ErrorAction SilentlyContinue
    }
    if ($existingGPO) {
        Write-JITLog -Message "GPO '$GPOName' already exists. Continuing with existing GPO." -Level Warning -LogDirectory $LogDirectory
    }
    else {
        if ($PSCmdlet.ShouldProcess($GPOName, "Create GPO")) {
            try {
                $existingGPO = Invoke-LOCKmeADRemote -Server $Server -Credential $Credential -ArgumentList $GPOName, $GPODescription, $gpoServer -ScriptBlock {
                    param($GPOName, $GPODescription, $Server)
                    $p = @{}
                    if ($Server) { $p.Server = $Server }
                    New-GPO -Name $GPOName -Comment $GPODescription @p
                }
                Write-JITLog -Message "GPO '$GPOName' created." -Level Success -LogDirectory $LogDirectory
            }
            catch {
                Write-JITLog -Message "Error creating GPO '$GPOName': $_" -Level Error -LogDirectory $LogDirectory
                throw
            }
        }
        else {
            Write-JITLog -Message "[WhatIf] GPO '$GPOName' would be created." -Level Info -LogDirectory $LogDirectory
        }
    }

    # --- Step 2: Create filtering group (idempotent) ---
    $existingGroup = $null
    try {
        $existingGroup = Get-ADGroup -Identity $filteringGroupName @serverParam -ErrorAction SilentlyContinue
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        # Group does not exist
    }
    catch {
        # Silently continue
    }

    if ($existingGroup) {
        Write-JITLog -Message "Filtering group '$filteringGroupName' already exists." -Level Warning -LogDirectory $LogDirectory
    }
    else {
        if ($PSCmdlet.ShouldProcess($filteringGroupName, "Create DomainLocal security group in '$FilteringGroupsOU'")) {
            try {
                New-ADGroup -Name $filteringGroupName `
                    -GroupScope DomainLocal `
                    -GroupCategory Security `
                    -Path $FilteringGroupsOU `
                    -Description "Machines receiving JIT Access Manager tool via GPO" `
                    @serverParam
                Write-JITLog -Message "Filtering group '$filteringGroupName' created in '$FilteringGroupsOU'." -Level Success -LogDirectory $LogDirectory
            }
            catch {
                Write-JITLog -Message "Error creating filtering group '$filteringGroupName': $_" -Level Error -LogDirectory $LogDirectory
                throw
            }
        }
        else {
            Write-JITLog -Message "[WhatIf] Filtering group '$filteringGroupName' would be created in '$FilteringGroupsOU'." -Level Info -LogDirectory $LogDirectory
        }
    }

    # --- Step 3: Remove Authenticated Users from GPO security filtering ---
    #
    # This deliberately does NOT use Set-GPPermission. Removing Authenticated Users makes that
    # cmdlet raise its own KB3163622 warning through ShouldContinue, which -Confirm:$false does
    # not suppress (that only governs ShouldProcess) and which no -Force can bypass, because
    # Set-GPPermission has no -Force parameter. The consequences are not cosmetic: with a console
    # attached the deployment stops waiting for a keypress the GUI cannot surface, and with none
    # it fails outright with "PowerShell is in NonInteractive mode" -- so a scheduled task or a
    # GUI launched from a shortcut could never deploy this module.
    #
    # Remove-GPOAuthenticatedUsers does the same job by editing the GPO's AD ACL and syncing
    # SYSVOL directly. That is already how the 22 GPOs of the GPO module get filtered, which is
    # why none of them ever prompts.
    if ($PSCmdlet.ShouldProcess($GPOName, "Remove Authenticated Users from GPO security filtering")) {
        try {
            Remove-GPOAuthenticatedUsers -GPOName $GPOName `
                                         -Server $Server `
                                         -Credential $Credential `
                                         -LogDirectory $LogDirectory
            Write-JITLog -Message "Removed 'Authenticated Users' from GPO '$GPOName' security filtering." -Level Info -LogDirectory $LogDirectory
        }
        catch {
            Write-JITLog -Message "Could not remove 'Authenticated Users' from GPO '$GPOName' (may already be removed): $_" -Level Warning -LogDirectory $LogDirectory
        }
    }
    else {
        Write-JITLog -Message "[WhatIf] 'Authenticated Users' would be removed from GPO '$GPOName' security filtering." -Level Info -LogDirectory $LogDirectory
    }

    # --- Step 4: Add filtering group with GpoApply ---
    if ($PSCmdlet.ShouldProcess($GPOName, "Grant GpoApply to '$filteringGroupName'")) {
        try {
            Invoke-LOCKmeADRemote -Server $Server -Credential $Credential -ArgumentList $GPOName, $filteringGroupName, $gpoServer -ScriptBlock {
                param($GPOName, $filteringGroupName, $Server)
                $p = @{}
                if ($Server) { $p.Server = $Server }
                Set-GPPermission -Name $GPOName -PermissionLevel GpoApply -TargetType Group -TargetName $filteringGroupName @p
            } | Out-Null
            Write-JITLog -Message "Granted GpoApply on GPO '$GPOName' to '$filteringGroupName'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-JITLog -Message "Error granting GpoApply to '$filteringGroupName' on GPO '$GPOName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-JITLog -Message "[WhatIf] GpoApply would be granted to '$filteringGroupName' on GPO '$GPOName'." -Level Info -LogDirectory $LogDirectory
    }

    # --- Step 5: Configure startup script on GPO SYSVOL ---
    if ($PSCmdlet.ShouldProcess($GPOName, "Configure PowerShell startup script in SYSVOL")) {
        try {
            # Reuse the GPO object from Step 1 where possible; otherwise resolve its GUID via
            # its AD container object rather than Get-GPO (which has no -Credential parameter
            # at all -- unlike the ActiveDirectory module -- so it cannot be used here when an
            # explicit credential is in play).
            $gpo = $existingGPO
            if (-not $gpo) {
                # A fresh LDAP query issued immediately after New-GPO (written via its GPMC
                # API inside a separate remote/WinRM session) has occasionally not observed
                # the new object yet -- a short retry absorbs that.
                $attempts = 5
                for ($i = 1; $i -le $attempts -and -not $gpo; $i++) {
                    $container = Get-ADObject -SearchBase "CN=Policies,CN=System,$DomainDN" -SearchScope OneLevel `
                                    -Filter { objectClass -eq 'groupPolicyContainer' -and displayName -eq $GPOName } `
                                    -Properties displayName @serverParam -ErrorAction SilentlyContinue
                    if ($container) { $gpo = [PSCustomObject]@{ Id = [guid]$container.Name } }
                    elseif ($i -lt $attempts) { Start-Sleep -Milliseconds 500 }
                }
                if (-not $gpo) {
                    throw "GPO '$GPOName' could not be found (no groupPolicyContainer object with that displayName under CN=Policies,CN=System,$DomainDN, after $attempts attempt(s))."
                }
            }
            $gpoId = "{" + $gpo.Id.ToString() + "}"
            $domain = (Get-ADDomain @serverParam).DNSRoot
            $sysvolRoot = Get-LOCKmeADSysvolDrive -DomainDNSRoot $domain -Credential $Credential
            $sysvolBase = "$sysvolRoot\$domain\Policies\$gpoId"
            $scriptsPath = "$sysvolBase\Machine\Scripts\Startup"

            # Create scripts directory
            if (-not (Test-Path $scriptsPath)) {
                New-Item -Path $scriptsPath -ItemType Directory -Force | Out-Null
                Write-JITLog -Message "Created SYSVOL scripts directory: '$scriptsPath'" -Level Info -LogDirectory $LogDirectory
            }

            # Copy Deploy-JITTool.ps1 from JIT/ folder (relative to module's root) to the SYSVOL scripts path
            $moduleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $deployScript = Join-Path $moduleRoot "JIT\Deploy-JITTool.ps1"
            if (-not (Test-Path $deployScript)) {
                Write-JITLog -Message "Deploy script not found: '$deployScript'" -Level Error -LogDirectory $LogDirectory
                throw "Deploy script not found: '$deployScript'"
            }
            Copy-Item -Path $deployScript -Destination $scriptsPath -Force
            Write-JITLog -Message "Copied '$deployScript' to '$scriptsPath'" -Level Info -LogDirectory $LogDirectory

            # Write psscripts.ini in Machine\Scripts\ (not in Startup\ subfolder)
            $machineScriptsPath = "$sysvolBase\Machine\Scripts"
            $iniContent = @"
[Startup]
0CmdLine=Deploy-JITTool.ps1
0Parameters=-SourcePath "$DistributionSharePath" -InstallPath "$InstallPath"
"@
            $iniContent | Set-Content -Path "$machineScriptsPath\psscripts.ini" -Encoding Unicode
            Write-JITLog -Message "Created psscripts.ini in '$machineScriptsPath'" -Level Info -LogDirectory $LogDirectory

            # --- Step 6: Register the Scripts CSE, then bump the version in AD and SYSVOL together ---
            #
            # The two counters have to move as a pair. This previously incremented GPT.INI only
            # (Version=n+1, by regex) and never wrote the groupPolicyContainer's versionNumber,
            # so AD stayed at 0 forever while SYSVOL climbed one per deployment. The Group Policy
            # client keys its "has this GPO changed?" decision on the AD versionNumber: left at 0
            # the GPO reads as empty, the startup script is not reliably processed, and a later
            # update to the published tool is never picked up at all.
            #
            # Same idiom as Set-GPOScript in the GPO module: machine version in the lower 16 bits,
            # user version in the upper 16, and GPT.INI carrying the identical combined value.
            $cse = "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]"
            $gpoObj = Get-ADObject -Filter { Name -eq $gpoId } -SearchBase "CN=Policies,CN=System,$DomainDN" -Properties gPCMachineExtensionNames, versionNumber @serverParam
            $existing = $gpoObj.gPCMachineExtensionNames
            if (-not $existing -or $existing -notlike "*42B5FAAE*") {
                $newExt = if ($existing) { "$existing$cse" } else { $cse }
                Set-ADObject -Identity $gpoObj -Replace @{ gPCMachineExtensionNames = $newExt } @serverParam
                Write-JITLog -Message "Updated gPCMachineExtensionNames with Scripts CSE on GPO '$GPOName'." -Level Info -LogDirectory $LogDirectory
            }
            else {
                Write-JITLog -Message "Scripts CSE already present on GPO '$GPOName'." -Level Warning -LogDirectory $LogDirectory
            }

            $currentVersion = if ($gpoObj.versionNumber) { [int]$gpoObj.versionNumber } else { 0 }
            $userVersion    = ($currentVersion -shr 16) -band 0xFFFF
            $machineVersion = ($currentVersion -band 0xFFFF) + 1
            $newVersion     = ($userVersion -shl 16) -bor $machineVersion
            Set-ADObject -Identity $gpoObj -Replace @{ versionNumber = $newVersion } @serverParam

            $gptIniPath = "$sysvolBase\GPT.INI"
            if (Test-Path $gptIniPath) {
                $gptContent = (Get-Content $gptIniPath -Raw) -replace 'Version=\d+', "Version=$newVersion"
                Set-Content -Path $gptIniPath -Value $gptContent -Encoding ASCII
            }
            Write-JITLog -Message "GPO '$GPOName' version bumped to $newVersion (AD object and GPT.INI in sync)." -Level Info -LogDirectory $LogDirectory

            Write-JITLog -Message "GPO '$GPOName' startup script configured successfully." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-JITLog -Message "Error configuring startup script on GPO '$GPOName': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-JITLog -Message "[WhatIf] PowerShell startup script would be configured on GPO '$GPOName'." -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# GPO Linking
# ============================================================================

function Set-JITGPOLink {
    <#
    .SYNOPSIS
        Links a GPO to one or more target OUs.
    .DESCRIPTION
        For each target OU, checks if the GPO is already linked. If not, creates
        the link. Idempotent: skips existing links.
    .PARAMETER GPOName
        Name of the GPO to link.
    .PARAMETER LinkTargets
        Array of target OU Distinguished Names.
    .PARAMETER Server
        Target DC for all GP operations.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [string[]]$LinkTargets,

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

    foreach ($ou in $LinkTargets) {
        if ([string]::IsNullOrWhiteSpace($ou)) { continue }

        # Check if already linked
        $alreadyLinked = $false
        try {
            # DisplayName must be projected to a plain string INSIDE the remote scriptblock:
            # remoting serializes each GpoLink down to its ToString() value, so reading
            # .DisplayName after the collection has crossed the session boundary yields empty
            # strings and the "already linked" check silently never matches.
            $linkedNames = @(Invoke-LOCKmeADRemote -Server $Server -Credential $Credential -ArgumentList $ou, $gpoServer -ScriptBlock {
                param($ou, $Server)
                $p = @{}
                if ($Server) { $p.Server = $Server }
                (Get-GPInheritance -Target $ou @p).GpoLinks | ForEach-Object { $_.DisplayName }
            })
            if ($linkedNames -contains $GPOName) {
                $alreadyLinked = $true
            }
        }
        catch {
            Write-JITLog -Message "Error checking GPO inheritance for '$ou': $_" -Level Warning -LogDirectory $LogDirectory
        }

        if ($alreadyLinked) {
            Write-JITLog -Message "GPO '$GPOName' is already linked to '$ou'." -Level Warning -LogDirectory $LogDirectory
            continue
        }

        if ($PSCmdlet.ShouldProcess($ou, "Link GPO '$GPOName'")) {
            try {
                Invoke-LOCKmeADRemote -Server $Server -Credential $Credential -ArgumentList $GPOName, $ou, $gpoServer -ScriptBlock {
                    param($GPOName, $ou, $Server)
                    $p = @{}
                    if ($Server) { $p.Server = $Server }
                    New-GPLink -Name $GPOName -Target $ou -LinkEnabled Yes @p
                } | Out-Null
                Write-JITLog -Message "GPO '$GPOName' linked to '$ou'." -Level Success -LogDirectory $LogDirectory
            }
            catch {
                Write-JITLog -Message "Error linking GPO '$GPOName' to '$ou': $_" -Level Error -LogDirectory $LogDirectory
                throw
            }
        }
        else {
            Write-JITLog -Message "[WhatIf] GPO '$GPOName' would be linked to '$ou'." -Level Info -LogDirectory $LogDirectory
        }
    }
}

# Export module functions
Export-ModuleMember -Function @(
    'Write-JITLog',
    'Import-JITConfiguration',
    'Get-JITEnvironmentInfo',
    'Publish-JITTool',
    'New-JITDeploymentGPO',
    'Set-JITGPOLink'
)
