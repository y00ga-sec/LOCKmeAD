# ============================================================================
# Silo Module - Functions for deploying Authentication Policy Silos
# ============================================================================
# No #Requires -Modules ActiveDirectory here -- every entry point (LOCKmeAD.ps1,
# Launch-GUI.ps1, each Scripts\Deploy-*.ps1) already checks that the module is
# available before importing this one, so a per-module #Requires would only be a
# redundant second layer.

# Module variable for the current log file path
$script:LogFilePath = $null

function Write-SiloLog {
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
            $logFileName = "Silo_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            $script:LogFilePath = Join-Path $LogDirectory $logFileName
        }
        $logEntry | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8
    }
}

# ============================================================================
# Configuration
# ============================================================================

function Import-SiloConfiguration {
    <#
    .SYNOPSIS
        Reads and validates the Silo JSON configuration file.
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
    if (-not $config.Silos -or $config.Silos.Count -eq 0) {
        throw "The 'Silos' section is missing or empty."
    }

    foreach ($silo in $config.Silos) {
        if (-not $silo.Name) {
            throw "A silo entry is missing the 'Name' property."
        }
        if ($null -eq $silo.Enabled) {
            throw "Silo '$($silo.Name)' is missing the 'Enabled' property."
        }
        if ($null -eq $silo.TGTLifetimeMinutes -or $silo.TGTLifetimeMinutes -lt 45) {
            throw "Silo '$($silo.Name)': 'TGTLifetimeMinutes' must be >= 45 (AD minimum)."
        }
        if (-not ($silo.PSObject.Properties.Name -contains 'ServiceAccounts')) {
            throw "Silo '$($silo.Name)' is missing the 'ServiceAccounts' property (use an empty array if none)."
        }
        if (-not ($silo.PSObject.Properties.Name -contains 'Computers')) {
            throw "Silo '$($silo.Name)' is missing the 'Computers' property (use an empty array if none)."
        }
        # Default Enforce to false (audit mode) if omitted from config
        if ($null -eq $silo.Enforce) {
            $silo | Add-Member -MemberType NoteProperty -Name 'Enforce' -Value $false -Force
        }
    }

    return $config
}

# ============================================================================
# Environment
# ============================================================================

function Get-SiloEnvironmentInfo {
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
# Authentication Policy & Silo Creation
# ============================================================================

function New-SiloAuthPolicy {
    <#
    .SYNOPSIS
        Creates or updates an Authentication Policy and Authentication Policy Silo.
    .DESCRIPTION
        Creates the Auth Policy if it does not exist. If it already exists, updates
        enforce mode and TGT lifetime. Then creates the Auth Policy Silo linked to
        the policy. Idempotent.
    .PARAMETER Name
        Base name used for both the policy and silo (suffixed with -Policy and -Silo).
    .PARAMETER Description
        Description for the policy and silo.
    .PARAMETER TGTLifetimeMinutes
        TGT lifetime in minutes for user accounts.
    .PARAMETER Enforce
        Whether to enforce the policy (false = audit mode).
    .PARAMETER Server
        Target DC for all AD operations.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Description = "",

        [int]$TGTLifetimeMinutes = 240,

        [bool]$Enforce = $false,

        [string]$Server,

        [PSCredential]$Credential,
        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $policyName = "$Name-Policy"
    $siloName   = "$Name-Silo"
    $enforceLabel = if ($Enforce) { "Enforce" } else { "Audit" }

    # --- Authentication Policy ---
    $existingPolicy = Get-ADAuthenticationPolicy -Filter { Name -eq $policyName } @serverParam -ErrorAction SilentlyContinue
    if ($existingPolicy) {
        Write-SiloLog -Message "Authentication Policy '$policyName' already exists. Updating settings." -Level Warning -LogDirectory $LogDirectory

        if ($PSCmdlet.ShouldProcess($policyName, "Update Authentication Policy (TGT=${TGTLifetimeMinutes}min, $enforceLabel)")) {
            try {
                $siloCondition = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "{0}"))' -f $siloName
                Set-ADAuthenticationPolicy -Identity $policyName `
                    -UserTGTLifetimeMins $TGTLifetimeMinutes `
                    -ComputerTGTLifetimeMins $TGTLifetimeMinutes `
                    -ServiceTGTLifetimeMins $TGTLifetimeMinutes `
                    -UserAllowedToAuthenticateFrom $siloCondition `
                    -Enforce:$Enforce `
                    @serverParam
                Write-SiloLog -Message "Authentication Policy '$policyName' updated (TGT=${TGTLifetimeMinutes}min, $enforceLabel)." -Level Success -LogDirectory $LogDirectory
            }
            catch {
                Write-SiloLog -Message "Error updating Authentication Policy '$policyName': $_" -Level Error -LogDirectory $LogDirectory
                throw
            }
        }
        else {
            Write-SiloLog -Message "[WhatIf] Authentication Policy '$policyName' would be updated (TGT=${TGTLifetimeMinutes}min, $enforceLabel)." -Level Info -LogDirectory $LogDirectory
        }
    }
    else {
        if ($PSCmdlet.ShouldProcess($policyName, "Create Authentication Policy (TGT=${TGTLifetimeMinutes}min, $enforceLabel)")) {
            try {
                $siloCondition = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "{0}"))' -f $siloName
                New-ADAuthenticationPolicy -Name $policyName `
                    -Description $Description `
                    -UserTGTLifetimeMins $TGTLifetimeMinutes `
                    -ComputerTGTLifetimeMins $TGTLifetimeMinutes `
                    -ServiceTGTLifetimeMins $TGTLifetimeMinutes `
                    -UserAllowedToAuthenticateFrom $siloCondition `
                    -Enforce:$Enforce `
                    -ProtectedFromAccidentalDeletion $true `
                    @serverParam
                Write-SiloLog -Message "Authentication Policy '$policyName' created (TGT=${TGTLifetimeMinutes}min, $enforceLabel, Silo condition='$siloName')." -Level Success -LogDirectory $LogDirectory
            }
            catch {
                Write-SiloLog -Message "Error creating Authentication Policy '$policyName': $_" -Level Error -LogDirectory $LogDirectory
                throw
            }
        }
        else {
            Write-SiloLog -Message "[WhatIf] Authentication Policy '$policyName' would be created (TGT=${TGTLifetimeMinutes}min, $enforceLabel, Silo condition='$siloName')." -Level Info -LogDirectory $LogDirectory
        }
    }

    # --- Authentication Policy Silo ---
    $existingSilo = Get-ADAuthenticationPolicySilo -Filter { Name -eq $siloName } @serverParam -ErrorAction SilentlyContinue
    if ($existingSilo) {
        Write-SiloLog -Message "Authentication Policy Silo '$siloName' already exists. Updating settings." -Level Warning -LogDirectory $LogDirectory

        if ($PSCmdlet.ShouldProcess($siloName, "Update Authentication Policy Silo ($enforceLabel)")) {
            try {
                Set-ADAuthenticationPolicySilo -Identity $siloName `
                    -UserAuthenticationPolicy $policyName `
                    -ComputerAuthenticationPolicy $policyName `
                    -ServiceAuthenticationPolicy $policyName `
                    -Enforce:$Enforce `
                    @serverParam
                Write-SiloLog -Message "Authentication Policy Silo '$siloName' updated ($enforceLabel, linked to '$policyName')." -Level Success -LogDirectory $LogDirectory
            }
            catch {
                Write-SiloLog -Message "Error updating Authentication Policy Silo '$siloName': $_" -Level Error -LogDirectory $LogDirectory
                throw
            }
        }
        else {
            Write-SiloLog -Message "[WhatIf] Authentication Policy Silo '$siloName' would be updated ($enforceLabel, linked to '$policyName')." -Level Info -LogDirectory $LogDirectory
        }
    }
    else {
        if ($PSCmdlet.ShouldProcess($siloName, "Create Authentication Policy Silo linked to '$policyName'")) {
            try {
                New-ADAuthenticationPolicySilo -Name $siloName `
                    -Description $Description `
                    -UserAuthenticationPolicy $policyName `
                    -ComputerAuthenticationPolicy $policyName `
                    -ServiceAuthenticationPolicy $policyName `
                    -Enforce:$Enforce `
                    -ProtectedFromAccidentalDeletion $true `
                    @serverParam
                Write-SiloLog -Message "Authentication Policy Silo '$siloName' created and linked to '$policyName' ($enforceLabel)." -Level Success -LogDirectory $LogDirectory
            }
            catch {
                Write-SiloLog -Message "Error creating Authentication Policy Silo '$siloName': $_" -Level Error -LogDirectory $LogDirectory
                throw
            }
        }
        else {
            Write-SiloLog -Message "[WhatIf] Authentication Policy Silo '$siloName' would be created and linked to '$policyName' ($enforceLabel)." -Level Info -LogDirectory $LogDirectory
        }
    }
}

# ============================================================================
# Silo Member Assignment
# ============================================================================

function Add-SiloMember {
    <#
    .SYNOPSIS
        Grants silo access and assigns accounts to an Authentication Policy Silo.
    .DESCRIPTION
        For each account, grants access to the silo and assigns the account.
        Supports computer, gMSA, and user accounts. Accounts ending with $
        are resolved as computer first, then gMSA. Idempotent: skips accounts
        already assigned to the silo.
    .PARAMETER SiloName
        Base name of the silo (will be suffixed with -Silo).
    .PARAMETER Accounts
        Array of account names (computer SAM names with $ or user SAM names).
    .PARAMETER Server
        Target DC for all AD operations.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SiloName,

        [Parameter(Mandatory)]
        [string[]]$Accounts,

        [string]$Server,

        [PSCredential]$Credential,
        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $fullSiloName = "$SiloName-Silo"

    foreach ($account in $Accounts) {
        if ([string]::IsNullOrWhiteSpace($account)) { continue }

        # Resolve account: try as computer first, then gMSA, then user
        $adObject = $null
        $accountType = $null

        # Accounts ending with $ can be computers or gMSAs
        if ($account.EndsWith('$')) {
            $baseName = $account.TrimEnd('$')
            try {
                $adObject = Get-ADComputer -Identity $baseName -Properties 'msDS-AssignedAuthNPolicySilo' @serverParam -ErrorAction Stop
                $accountType = "Computer"
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                # Not found as computer, try as gMSA
                try {
                    $adObject = Get-ADServiceAccount -Identity $baseName -Properties 'msDS-AssignedAuthNPolicySilo' @serverParam -ErrorAction Stop
                    $accountType = "gMSA"
                }
                catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                    # Not found as gMSA either
                }
                catch {
                    Write-SiloLog -Message "  Error looking up service account '$account': $_" -Level Error -LogDirectory $LogDirectory
                    continue
                }
            }
            catch {
                Write-SiloLog -Message "  Error looking up computer '$account': $_" -Level Error -LogDirectory $LogDirectory
                continue
            }
        }
        else {
            try {
                $adObject = Get-ADUser -Identity $account -Properties 'msDS-AssignedAuthNPolicySilo' @serverParam -ErrorAction Stop
                $accountType = "User"
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                # Not found as user
            }
            catch {
                Write-SiloLog -Message "  Error looking up user '$account': $_" -Level Error -LogDirectory $LogDirectory
                continue
            }
        }

        if (-not $adObject) {
            Write-SiloLog -Message "  Account '$account' not found in AD." -Level Error -LogDirectory $LogDirectory
            continue
        }

        # Check if already assigned to this silo
        $currentSilo = $adObject.'msDS-AssignedAuthNPolicySilo'
        if ($currentSilo) {
            # Extract silo name from DN
            $currentSiloName = ($currentSilo -split ',')[0] -replace '^CN=', ''
            if ($currentSiloName -eq $fullSiloName) {
                Write-SiloLog -Message "  $accountType '$account' is already assigned to silo '$fullSiloName'." -Level Warning -LogDirectory $LogDirectory
                continue
            }
        }

        if ($PSCmdlet.ShouldProcess($account, "Assign $accountType to Authentication Policy Silo '$fullSiloName'")) {
            try {
                # Grant access to the silo
                Grant-ADAuthenticationPolicySiloAccess -Identity $fullSiloName -Account $adObject @serverParam
                Write-SiloLog -Message "  Granted silo access for $accountType '$account' on '$fullSiloName'." -Level Info -LogDirectory $LogDirectory

                # Assign the account to the silo
                Set-ADAccountAuthenticationPolicySilo -Identity $adObject -AuthenticationPolicySilo $fullSiloName @serverParam
                Write-SiloLog -Message "  $accountType '$account' assigned to silo '$fullSiloName'." -Level Success -LogDirectory $LogDirectory
            }
            catch {
                Write-SiloLog -Message "  Error assigning $accountType '$account' to silo '$fullSiloName': $_" -Level Error -LogDirectory $LogDirectory
            }
        }
        else {
            Write-SiloLog -Message "  [WhatIf] $accountType '$account' would be assigned to silo '$fullSiloName'." -Level Info -LogDirectory $LogDirectory
        }
    }
}

# Export module functions
Export-ModuleMember -Function @(
    'Write-SiloLog',
    'Import-SiloConfiguration',
    'Get-SiloEnvironmentInfo',
    'New-SiloAuthPolicy',
    'Add-SiloMember'
)
