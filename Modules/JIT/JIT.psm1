#Requires -Modules ActiveDirectory, GroupPolicy

# ============================================================================
# JIT Module - Functions for deploying JIT Access Manager via GPO
# ============================================================================

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

    # Write to log file
    if ($LogDirectory) {
        if (-not (Test-Path $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }
        if (-not $script:LogFilePath) {
            $logFileName = "JIT_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            $script:LogFilePath = Join-Path $LogDirectory $logFileName
        }
        $logEntry | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8
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

        $pamFeature = Get-ADOptionalFeature -Filter { Name -eq 'Privileged Access Management Feature' } -ErrorAction SilentlyContinue
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
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$DistributionSharePath,

        [string]$LogDirectory
    )

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
        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

    $filteringGroupName = "DL_JIT_Tool_Machines"

    # --- Step 1: Create or reuse GPO ---
    $existingGPO = Get-GPO -Name $GPOName @serverParam -ErrorAction SilentlyContinue
    if ($existingGPO) {
        Write-JITLog -Message "GPO '$GPOName' already exists. Continuing with existing GPO." -Level Warning -LogDirectory $LogDirectory
    }
    else {
        if ($PSCmdlet.ShouldProcess($GPOName, "Create GPO")) {
            try {
                $existingGPO = New-GPO -Name $GPOName -Comment $GPODescription @serverParam
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
    if ($PSCmdlet.ShouldProcess($GPOName, "Remove Authenticated Users from GPO security filtering")) {
        try {
            Set-GPPermission -Name $GPOName -PermissionLevel None -TargetType Group -TargetName "Authenticated Users" -Replace @serverParam
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
            Set-GPPermission -Name $GPOName -PermissionLevel GpoApply -TargetType Group -TargetName $filteringGroupName @serverParam
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
            $gpo = Get-GPO -Name $GPOName @serverParam
            $gpoId = "{" + $gpo.Id.ToString() + "}"
            $domain = (Get-ADDomain @serverParam).DNSRoot
            $sysvolBase = "\\$domain\SYSVOL\$domain\Policies\$gpoId"
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

            # --- Step 6: Update GPT.INI version ---
            $gptIniPath = "$sysvolBase\GPT.INI"
            $content = Get-Content $gptIniPath -Raw
            if ($content -match 'Version=(\d+)') {
                $oldVer = [int]$Matches[1]
                $newVer = $oldVer + 1
                $content = $content -replace "Version=$oldVer", "Version=$newVer"
                $content | Set-Content $gptIniPath -Encoding ASCII
                Write-JITLog -Message "Updated GPT.INI version from $oldVer to $newVer." -Level Info -LogDirectory $LogDirectory
            }

            # --- Step 7: Update gPCMachineExtensionNames (Scripts CSE) ---
            $cse = "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]"
            $gpoObj = Get-ADObject -Filter { Name -eq $gpoId } -SearchBase "CN=Policies,CN=System,$DomainDN" -Properties gPCMachineExtensionNames @serverParam
            $existing = $gpoObj.gPCMachineExtensionNames
            if (-not $existing -or $existing -notlike "*42B5FAAE*") {
                $newExt = if ($existing) { "$existing$cse" } else { $cse }
                Set-ADObject -Identity $gpoObj -Replace @{ gPCMachineExtensionNames = $newExt } @serverParam
                Write-JITLog -Message "Updated gPCMachineExtensionNames with Scripts CSE on GPO '$GPOName'." -Level Info -LogDirectory $LogDirectory
            }
            else {
                Write-JITLog -Message "Scripts CSE already present on GPO '$GPOName'." -Level Warning -LogDirectory $LogDirectory
            }

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
        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

    foreach ($ou in $LinkTargets) {
        if ([string]::IsNullOrWhiteSpace($ou)) { continue }

        # Check if already linked
        $alreadyLinked = $false
        try {
            $inheritance = Get-GPInheritance -Target $ou @serverParam
            $linkedNames = @($inheritance.GpoLinks | ForEach-Object { $_.DisplayName })
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
                New-GPLink -Name $GPOName -Target $ou -LinkEnabled Yes @serverParam
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
