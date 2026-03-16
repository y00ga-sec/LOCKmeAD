#Requires -Modules ActiveDirectory

# ============================================================================
# PSO Module - Functions for deploying Fine-Grained Password Policies
# ============================================================================

# Module variable for the current log file path
$script:LogFilePath = $null

function Write-PSOLog {
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
            $logFileName = "PSO_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            $script:LogFilePath = Join-Path $LogDirectory $logFileName
        }
        $logEntry | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8
    }
}

# ============================================================================
# Configuration
# ============================================================================

function Import-PSOConfiguration {
    <#
    .SYNOPSIS
        Reads and validates the PSO JSON configuration file.
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
    if (-not $config.Policies -or $config.Policies.Count -eq 0) {
        throw "The 'Policies' section is missing or empty."
    }

    foreach ($policy in $config.Policies) {
        if (-not $policy.Name) {
            throw "A policy entry is missing the 'Name' property."
        }
        if ($null -eq $policy.Enabled) {
            throw "Policy '$($policy.Name)' is missing the 'Enabled' property."
        }
        if ($null -eq $policy.Precedence -or $policy.Precedence -lt 1) {
            throw "Policy '$($policy.Name)' has an invalid 'Precedence' (must be a positive integer)."
        }

        # Validate numeric duration fields if present
        $dayFields = @('MinPasswordAgeDays', 'MaxPasswordAgeDays')
        foreach ($field in $dayFields) {
            $val = $policy.$field
            if ($null -ne $val -and $val -lt 0) {
                throw "Policy '$($policy.Name)': '$field' must be >= 0."
            }
        }
        $minuteFields = @('LockoutDurationMinutes', 'LockoutObservationWindowMinutes')
        foreach ($field in $minuteFields) {
            $val = $policy.$field
            if ($null -ne $val -and $val -lt 0) {
                throw "Policy '$($policy.Name)': '$field' must be >= 0."
            }
        }
    }

    return $config
}

# ============================================================================
# Environment
# ============================================================================

function Get-PSOEnvironmentInfo {
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
# PSO Creation
# ============================================================================

function New-PSOPasswordPolicy {
    <#
    .SYNOPSIS
        Creates or updates a Fine-Grained Password Policy (PSO) in Active Directory.
    .DESCRIPTION
        Creates the PSO if it does not exist. If it already exists, updates all
        settings to match the configuration. Idempotent.
    .PARAMETER Name
        Name of the PSO.
    .PARAMETER Description
        Description of the PSO.
    .PARAMETER Precedence
        Precedence value (lower = higher priority).
    .PARAMETER ComplexityEnabled
        Whether password complexity is required.
    .PARAMETER MinPasswordLength
        Minimum password length.
    .PARAMETER MinPasswordAgeDays
        Minimum password age in days.
    .PARAMETER MaxPasswordAgeDays
        Maximum password age in days.
    .PARAMETER PasswordHistoryCount
        Number of previous passwords remembered.
    .PARAMETER LockoutThreshold
        Number of failed attempts before lockout (0 = no lockout).
    .PARAMETER LockoutDurationMinutes
        Duration of account lockout in minutes (0 = manual unlock required).
    .PARAMETER LockoutObservationWindowMinutes
        Observation window for failed attempts in minutes.
    .PARAMETER ReversibleEncryptionEnabled
        Whether to store passwords with reversible encryption.
    .PARAMETER ProtectedFromAccidentalDeletion
        Whether the PSO is protected from accidental deletion.
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

        [Parameter(Mandatory)]
        [int]$Precedence,

        [bool]$ComplexityEnabled = $true,
        [int]$MinPasswordLength = 8,
        [int]$MinPasswordAgeDays = 1,
        [int]$MaxPasswordAgeDays = 42,
        [int]$PasswordHistoryCount = 24,
        [int]$LockoutThreshold = 0,
        [int]$LockoutDurationMinutes = 30,
        [int]$LockoutObservationWindowMinutes = 30,
        [bool]$ReversibleEncryptionEnabled = $false,
        [bool]$ProtectedFromAccidentalDeletion = $true,

        [string]$Server,
        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

    # Convert days/minutes to TimeSpan
    $minPwdAge    = [TimeSpan]::FromDays($MinPasswordAgeDays)
    $maxPwdAge    = [TimeSpan]::FromDays($MaxPasswordAgeDays)
    $lockDuration = [TimeSpan]::FromMinutes($LockoutDurationMinutes)
    $lockWindow   = [TimeSpan]::FromMinutes($LockoutObservationWindowMinutes)

    $existingPSO = $null
    try {
        $existingPSO = Get-ADFineGrainedPasswordPolicy -Identity $Name @serverParam -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        # PSO does not exist, proceed with creation
    }

    if ($existingPSO) {
        Write-PSOLog -Message "PSO '$Name' already exists (Precedence: $($existingPSO.Precedence)). Updating settings." -Level Warning -LogDirectory $LogDirectory

        if ($PSCmdlet.ShouldProcess($Name, "Update Fine-Grained Password Policy")) {
            try {
                Set-ADFineGrainedPasswordPolicy -Identity $Name `
                    -Description $Description `
                    -Precedence $Precedence `
                    -ComplexityEnabled $ComplexityEnabled `
                    -MinPasswordLength $MinPasswordLength `
                    -MinPasswordAge $minPwdAge `
                    -MaxPasswordAge $maxPwdAge `
                    -PasswordHistoryCount $PasswordHistoryCount `
                    -LockoutThreshold $LockoutThreshold `
                    -LockoutDuration $lockDuration `
                    -LockoutObservationWindow $lockWindow `
                    -ReversibleEncryptionEnabled $ReversibleEncryptionEnabled `
                    -ProtectedFromAccidentalDeletion $ProtectedFromAccidentalDeletion `
                    @serverParam

                Write-PSOLog -Message "PSO '$Name' updated." -Level Success -LogDirectory $LogDirectory
            }
            catch {
                Write-PSOLog -Message "Error updating PSO '$Name': $_" -Level Error -LogDirectory $LogDirectory
                throw
            }
        }
        else {
            Write-PSOLog -Message "[WhatIf] PSO '$Name' would be updated." -Level Info -LogDirectory $LogDirectory
        }
    }
    else {
        if ($PSCmdlet.ShouldProcess($Name, "Create Fine-Grained Password Policy (Precedence: $Precedence)")) {
            try {
                # Create without ProtectedFromAccidentalDeletion first, then set it separately
                # (AD rejects setting protection during creation on some environments)
                New-ADFineGrainedPasswordPolicy -Name $Name `
                    -Description $Description `
                    -Precedence $Precedence `
                    -ComplexityEnabled $ComplexityEnabled `
                    -MinPasswordLength $MinPasswordLength `
                    -MinPasswordAge $minPwdAge `
                    -MaxPasswordAge $maxPwdAge `
                    -PasswordHistoryCount $PasswordHistoryCount `
                    -LockoutThreshold $LockoutThreshold `
                    -LockoutDuration $lockDuration `
                    -LockoutObservationWindow $lockWindow `
                    -ReversibleEncryptionEnabled $ReversibleEncryptionEnabled `
                    @serverParam

                if ($ProtectedFromAccidentalDeletion) {
                    Set-ADFineGrainedPasswordPolicy -Identity $Name `
                        -ProtectedFromAccidentalDeletion $true @serverParam
                }

                Write-PSOLog -Message "PSO '$Name' created (Precedence: $Precedence)." -Level Success -LogDirectory $LogDirectory
            }
            catch {
                Write-PSOLog -Message "Error creating PSO '$Name': $_" -Level Error -LogDirectory $LogDirectory
                throw
            }
        }
        else {
            Write-PSOLog -Message "[WhatIf] PSO '$Name' would be created (Precedence: $Precedence)." -Level Info -LogDirectory $LogDirectory
        }
    }
}

# ============================================================================
# PSO Subject Assignment
# ============================================================================

function Add-PSOSubject {
    <#
    .SYNOPSIS
        Applies a PSO to one or more groups or users.
    .PARAMETER PolicyName
        Name of the PSO to apply.
    .PARAMETER Subjects
        Array of group or user names to apply the PSO to.
    .PARAMETER Server
        Target DC for all AD operations.
    .PARAMETER LogDirectory
        Log directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName,

        [Parameter(Mandatory)]
        [string[]]$Subjects,

        [string]$Server,
        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

    # Get current subjects to avoid duplicates
    $pso = Get-ADFineGrainedPasswordPolicy -Identity $PolicyName -Properties AppliesTo @serverParam -ErrorAction Stop
    $currentSubjectDNs = @($pso.AppliesTo)

    foreach ($subject in $Subjects) {
        if ([string]::IsNullOrWhiteSpace($subject)) { continue }

        # Resolve subject: try as group first, then as user
        $adObject = $null
        try {
            $adObject = Get-ADGroup -Identity $subject @serverParam -ErrorAction Stop
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            try {
                $adObject = Get-ADUser -Identity $subject @serverParam -ErrorAction Stop
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                # Not found as group or user
            }
            catch {
                Write-PSOLog -Message "  Error looking up user '$subject': $_" -Level Error -LogDirectory $LogDirectory
                continue
            }
        }
        catch {
            Write-PSOLog -Message "  Error looking up group '$subject': $_" -Level Error -LogDirectory $LogDirectory
            continue
        }

        if (-not $adObject) {
            Write-PSOLog -Message "  Subject '$subject' not found in AD (must be a group or user)." -Level Error -LogDirectory $LogDirectory
            continue
        }

        # Check if already applied
        if ($adObject.DistinguishedName -in $currentSubjectDNs) {
            Write-PSOLog -Message "  PSO '$PolicyName' is already applied to '$subject'." -Level Warning -LogDirectory $LogDirectory
            continue
        }

        if ($PSCmdlet.ShouldProcess($subject, "Apply PSO '$PolicyName'")) {
            try {
                Add-ADFineGrainedPasswordPolicySubject -Identity $PolicyName -Subjects $adObject @serverParam
                Write-PSOLog -Message "  PSO '$PolicyName' applied to '$subject'." -Level Success -LogDirectory $LogDirectory
            }
            catch {
                Write-PSOLog -Message "  Error applying PSO '$PolicyName' to '$subject': $_" -Level Error -LogDirectory $LogDirectory
            }
        }
        else {
            Write-PSOLog -Message "  [WhatIf] PSO '$PolicyName' would be applied to '$subject'." -Level Info -LogDirectory $LogDirectory
        }
    }
}

# Export module functions
Export-ModuleMember -Function @(
    'Write-PSOLog',
    'Import-PSOConfiguration',
    'Get-PSOEnvironmentInfo',
    'New-PSOPasswordPolicy',
    'Add-PSOSubject'
)
