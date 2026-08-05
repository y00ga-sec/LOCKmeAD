# ============================================================================
# Tiering Module - Functions for deploying the AD tiering OU structure
# ============================================================================
# No #Requires -Modules ActiveDirectory here -- every entry point (LOCKmeAD.ps1,
# Launch-GUI.ps1, each Scripts\Deploy-*.ps1) already checks that the module is
# available before importing this one, so a per-module #Requires would only be a
# redundant second layer.

# Module variable for the current log file path
$script:LogFilePath = $null

function Write-TieringLog {
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
            $logFileName = "Tiering_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            $script:LogFilePath = Join-Path $LogDirectory $logFileName
        }
        $logEntry | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8
    }
}

# ============================================================================
# Private function for recursive OU node validation
# ============================================================================

function Test-TieringOUNode {
    <#
    .SYNOPSIS
        Recursively validates the structure of an OU node in the configuration.
    .PARAMETER Node
        The OU node to validate.
    .PARAMETER ParentPath
        The parent path for error messages.
    #>
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Node,

        [string]$ParentPath = "root"
    )

    if (-not $Node.Name) {
        throw "An OU in '$ParentPath' is missing the 'Name' property."
    }

    $currentPath = "$ParentPath > $($Node.Name)"

    if ($Node.Children) {
        foreach ($child in $Node.Children) {
            Test-TieringOUNode -Node $child -ParentPath $currentPath
        }
    }
}

function Import-TieringConfiguration {
    <#
    .SYNOPSIS
        Reads and validates the tiering JSON configuration file.
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
    if (-not $config.Settings.BaseDN) {
        throw "The 'Settings.BaseDN' section is missing."
    }
    if (-not $config.OUStructure -or $config.OUStructure.Count -eq 0) {
        throw "The 'OUStructure' section is missing or empty."
    }

    # Recursive validation of each OU node
    foreach ($node in $config.OUStructure) {
        Test-TieringOUNode -Node $node
    }

    return $config
}

function Get-TieringEnvironmentInfo {
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

function New-TieringOU {
    <#
    .SYNOPSIS
        Creates an Organizational Unit (OU) in Active Directory.
    .PARAMETER Name
        OU name.
    .PARAMETER Description
        OU description.
    .PARAMETER ParentDN
        DN of the parent container where the OU will be created.
    .PARAMETER ProtectedFromAccidentalDeletion
        Protects the OU from accidental deletion.
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
        [string]$ParentDN,

        [bool]$ProtectedFromAccidentalDeletion = $true,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $targetDN = "OU=$Name,$ParentDN"

    # Check if the OU already exists
    try {
        $existingOU = Get-ADOrganizationalUnit -Identity $targetDN @serverParam -ErrorAction Stop
        Write-TieringLog -Message "OU '$Name' already exists in '$ParentDN'." -Level Warning -LogDirectory $LogDirectory
        return $existingOU
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        # OU does not exist, proceed with creation
    }

    if ($PSCmdlet.ShouldProcess($targetDN, "Create OU")) {
        try {
            $params = @{
                Name                            = $Name
                Path                            = $ParentDN
                Description                     = $Description
                ProtectedFromAccidentalDeletion = $ProtectedFromAccidentalDeletion
            }
            $newOU = New-ADOrganizationalUnit @params @serverParam -PassThru
            Write-TieringLog -Message "OU '$Name' created in '$ParentDN'." -Level Success -LogDirectory $LogDirectory
            return $newOU
        }
        catch {
            Write-TieringLog -Message "Error creating OU '$Name' in '$ParentDN': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-TieringLog -Message "[WhatIf] OU '$Name' would be created in '$ParentDN'." -Level Info -LogDirectory $LogDirectory
    }
}

function Deploy-TieringOUStructure {
    <#
    .SYNOPSIS
        Recursively deploys an OU tree in Active Directory.
    .DESCRIPTION
        Traverses the OU node tree depth-first and creates each OU
        under its parent. If a node defines a DistinguishedNameBase, it is used
        as the parent DN instead of the inherited ParentDN.
    .PARAMETER OUNodes
        Array of OU nodes to deploy.
    .PARAMETER ParentDN
        DN of the parent container for this level.
    .PARAMETER DefaultProtection
        Default value for ProtectedFromAccidentalDeletion.
    .PARAMETER Server
        Target DC for all AD operations (avoids replication lag).
    .PARAMETER LogDirectory
        Log directory.
    .PARAMETER Depth
        Current depth in the tree (for log indentation).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$OUNodes,

        [Parameter(Mandatory)]
        [string]$ParentDN,

        [bool]$DefaultProtection = $true,

        [string]$Server,

        [PSCredential]$Credential,

        [string]$LogDirectory,

        [int]$Depth = 0
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $results = @{
        OUsCreated  = 0
        OUsExisting = 0
        Errors      = 0
    }

    foreach ($node in $OUNodes) {
        # Determine the effective parent DN
        $effectiveParent = if ($node.DistinguishedNameBase) { $node.DistinguishedNameBase } else { $ParentDN }

        # Determine deletion protection
        $protection = if ($null -ne $node.ProtectedFromAccidentalDeletion) {
            $node.ProtectedFromAccidentalDeletion
        } else {
            $DefaultProtection
        }

        # Indentation for display
        $indent = "  " * $Depth

        try {
            Write-TieringLog -Message "${indent}Processing OU '$($node.Name)' in '$effectiveParent'..." -Level Info -LogDirectory $LogDirectory

            # Resolve created-vs-already-present BEFORE the call: New-TieringOU returns the OU
            # object in both cases, so the caller cannot otherwise tell them apart. Counting
            # every processed node as "created" made a no-op re-run report a full deployment,
            # and made a -WhatIf run against the wrong domain look like it would succeed.
            # -ErrorAction SilentlyContinue is NOT enough here: Get-ADOrganizationalUnit
            # -Identity raises ADIdentityNotFoundException as a TERMINATING error, which
            # SilentlyContinue does not suppress. Left unguarded it escapes to the per-node
            # catch below, which logs "Failed to create OU" and skips the node and all its
            # children -- i.e. no OU is ever created on a fresh domain. Same typed-catch
            # idiom as New-TieringOU just below.
            $alreadyPresent = $false
            try {
                $alreadyPresent = $null -ne (Get-ADOrganizationalUnit -Identity "OU=$($node.Name),$effectiveParent" @serverParam -ErrorAction Stop)
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                $alreadyPresent = $false
            }

            New-TieringOU -Name $node.Name `
                          -Description $node.Description `
                          -ParentDN $effectiveParent `
                          -ProtectedFromAccidentalDeletion $protection `
                          -Server $Server `
                          -Credential $Credential `
                          -LogDirectory $LogDirectory `
                          -WhatIf:$WhatIfPreference

            if ($alreadyPresent) { $results.OUsExisting++ } else { $results.OUsCreated++ }
        }
        catch {
            Write-TieringLog -Message "${indent}Failed to create OU '$($node.Name)' in '$effectiveParent': $_" -Level Error -LogDirectory $LogDirectory
            $results.Errors++
            continue  # Skip children if the parent fails
        }

        # Recursive processing of children
        if ($node.Children) {
            $childParentDN = "OU=$($node.Name),$effectiveParent"
            $childResults = Deploy-TieringOUStructure -OUNodes $node.Children `
                                                       -ParentDN $childParentDN `
                                                       -DefaultProtection $DefaultProtection `
                                                       -Server $Server `
                                                       -Credential $Credential `
                                                       -LogDirectory $LogDirectory `
                                                       -Depth ($Depth + 1) `
                                                       -WhatIf:$WhatIfPreference
            $results.OUsCreated  += $childResults.OUsCreated
            $results.OUsExisting += $childResults.OUsExisting
            $results.Errors      += $childResults.Errors
        }
    }

    return $results
}

# Export module functions
Export-ModuleMember -Function @(
    'Write-TieringLog',
    'Import-TieringConfiguration',
    'Get-TieringEnvironmentInfo',
    'New-TieringOU',
    'Deploy-TieringOUStructure'
)
