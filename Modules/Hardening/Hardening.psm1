# ============================================================================
# Hardening Module - Functions for deploying AD hardening remediation tasks
# ============================================================================
# No #Requires -Modules ActiveDirectory here -- every entry point (LOCKmeAD.ps1,
# Launch-GUI.ps1, each Scripts\Deploy-*.ps1) already checks that the module is
# available before importing this one, so a per-module #Requires would only be a
# redundant second layer.

Import-Module (Join-Path $PSScriptRoot "..\Common\Connection.psm1") -Force

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

    # Write to log file.
    # -WhatIf:$false on both calls: they are ShouldProcess-aware and inherit $WhatIfPreference from
    # the calling scope, so a line emitted by another function of this module running under -WhatIf
    # was silently dropped -- see Write-GPOLog in Modules\GPO\GPO.psm1 for the full rationale.
    if ($LogDirectory) {
        if (-not (Test-Path $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force -WhatIf:$false | Out-Null
        }
        if (-not $script:LogFilePath) {
            $logFileName = "Hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            $script:LogFilePath = Join-Path $LogDirectory $logFileName
        }
        $logEntry | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8 -WhatIf:$false
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
        'RaiseDomainFunctionalLevel',
        'RaiseForestFunctionalLevel',
        'EnableRecycleBin',
        'EnablePAMFeature',
        'DisableAnonymousAccess',
        'DeployT0AuthPolicy',
        'EnableReplicationNotify',
        'ConfigureCentralStore',
        'ExtendLAPSSchema',
        'ConfigureLAPSADPermissions',
        'RestrictDNSDynamicUpdate',
        'AddDNSSecurityRecords',
        'FixDNSRecordOwnership',
        'ResetADObjectOwnership'
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

        # Validate required parameters per task.
        #
        # The first branch used to test 'RaiseFunctionalLevel' -- a name absent from
        # $validTaskNames since that task was split into the Domain/Forest pair -- so it never
        # matched and neither level task was validated. A config missing TargetDomainLevel got
        # all the way to Set-HardeningDomainFunctionalLevel, whose -TargetDomainLevel is
        # Mandatory, and stalled there on a parameter prompt instead of failing here.
        #
        # Only enabled tasks are checked: a task the operator turned off is a deliberate no-op,
        # and rejecting the whole file over its Parameters block would abort every other task
        # with it, since a failed Import-* exits the deployment script outright.
        if ($task.Enabled) {
            switch ($task.Name) {
                'RaiseDomainFunctionalLevel' {
                    if (-not $task.Parameters -or -not $task.Parameters.TargetDomainLevel) {
                        throw "Task '$($task.Name)' requires Parameters.TargetDomainLevel."
                    }
                }
                'RaiseForestFunctionalLevel' {
                    if (-not $task.Parameters -or -not $task.Parameters.TargetForestLevel) {
                        throw "Task '$($task.Name)' requires Parameters.TargetForestLevel."
                    }
                }
                'DeployT0AuthPolicy' {
                    if (-not $task.Parameters -or -not $task.Parameters.PolicyName -or -not $task.Parameters.SiloName) {
                        throw "Task '$($task.Name)' requires Parameters.PolicyName and Parameters.SiloName."
                    }
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
# Tasks: RaiseDomainFunctionalLevel / RaiseForestFunctionalLevel — Prerequisites
# ============================================================================

function Test-HardeningDomainFunctionalLevelPrerequisites {
    <#
    .SYNOPSIS
        Checks all prerequisites before raising the domain functional level.
    .PARAMETER TargetDomainLevel
        Target domain functional level (e.g. Windows2016Domain).
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    .OUTPUTS
        Array of PSCustomObject with Name, Passed, Message properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetDomainLevel,

        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Minimum OS build required per domain functional level
    $minBuildMap = @{
        'Windows2000Domain'   = 2195
        'Windows2003Domain'   = 3790
        'Windows2008Domain'   = 6001
        'Windows2008R2Domain' = 7600
        'Windows2012Domain'   = 9200
        'Windows2012R2Domain' = 9600
        'Windows2016Domain'   = 14393
        'Windows2025Domain'   = 26040
    }

    # Numeric ordering for functional level comparison
    $domainLevelOrder = @{
        'Windows2000Domain'        = 0
        'Windows2003InterimDomain' = 1
        'Windows2003Domain'        = 2
        'Windows2008Domain'        = 3
        'Windows2008R2Domain'      = 4
        'Windows2012Domain'        = 5
        'Windows2012R2Domain'      = 6
        'Windows2016Domain'        = 7
        'Windows2025Domain'        = 9
    }
    # --- Check 1: AD connectivity ---
    $domain = $null
    try {
        $domain = Get-ADDomain @serverParam
        $results.Add([PSCustomObject]@{
            Name    = "Active Directory connectivity"
            Passed  = $true
            Message = "Connected to domain '$($domain.DNSRoot)'"
        })
    }
    catch {
        $results.Add([PSCustomObject]@{
            Name    = "Active Directory connectivity"
            Passed  = $false
            Message = "Cannot connect to Active Directory: $_"
        })
        return $results
    }

    # --- Check 2: PDC Emulator reachable ---
    try {
        $pdcFQDN = $domain.PDCEmulator
        $pdcReachable = Test-Connection -ComputerName $pdcFQDN -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($pdcReachable) {
            $results.Add([PSCustomObject]@{
                Name    = "PDC Emulator reachable"
                Passed  = $true
                Message = "PDC Emulator '$pdcFQDN' is reachable"
            })
        }
        else {
            $results.Add([PSCustomObject]@{
                Name    = "PDC Emulator reachable"
                Passed  = $false
                Message = "PDC Emulator '$pdcFQDN' did not respond — ensure it is online and network access is allowed"
            })
        }
    }
    catch {
        $results.Add([PSCustomObject]@{
            Name    = "PDC Emulator reachable"
            Passed  = $false
            Message = "Error checking PDC Emulator connectivity: $_"
        })
    }

    # --- Check 3: Target domain level is valid and current level can be raised ---
    $currentDomainMode  = $domain.DomainMode.ToString()
    $currentDomainOrder = $domainLevelOrder[$currentDomainMode]
    $targetDomainOrder  = $domainLevelOrder[$TargetDomainLevel]

    if ($null -eq $targetDomainOrder) {
        $results.Add([PSCustomObject]@{
            Name    = "Target domain functional level"
            Passed  = $false
            Message = "Unrecognized target domain functional level: '$TargetDomainLevel'"
        })
    }
    elseif ($null -ne $currentDomainOrder -and $currentDomainOrder -gt $targetDomainOrder) {
        $results.Add([PSCustomObject]@{
            Name    = "Target domain functional level"
            Passed  = $false
            Message = "Current level '$currentDomainMode' is already above target '$TargetDomainLevel' — functional levels cannot be lowered"
        })
    }
    elseif ($null -ne $currentDomainOrder -and $currentDomainOrder -eq $targetDomainOrder) {
        $results.Add([PSCustomObject]@{
            Name    = "Target domain functional level"
            Passed  = $true
            Message = "Domain is already at '$TargetDomainLevel' — this step will be skipped automatically"
        })
    }
    else {
        $results.Add([PSCustomObject]@{
            Name    = "Target domain functional level"
            Passed  = $true
            Message = "Current level '$currentDomainMode' can be raised to '$TargetDomainLevel'"
        })
    }

    # --- Check 4: All DCs meet minimum OS requirement for target domain level ---
    $minBuild = $minBuildMap[$TargetDomainLevel]
    if ($null -ne $minBuild) {
        try {
            $dcs = @(Get-ADDomainController -Filter * @serverParam)
            $nonCompliant = @()
            $unknownBuild = @()

            foreach ($dc in $dcs) {
                $osVer = $dc.OperatingSystemVersion
                if ($osVer -match '\((\d+)\)') {
                    $build = [int]$Matches[1]
                    if ($build -lt $minBuild) {
                        $nonCompliant += "$($dc.Name) (build $build — $($dc.OperatingSystem))"
                    }
                }
                else {
                    $unknownBuild += "$($dc.Name) (version string: '$osVer')"
                }
            }

            if ($nonCompliant.Count -eq 0 -and $unknownBuild.Count -eq 0) {
                $results.Add([PSCustomObject]@{
                    Name    = "All DCs meet minimum OS version"
                    Passed  = $true
                    Message = "All $($dcs.Count) DC(s) meet the minimum OS requirement (build >= $minBuild) for '$TargetDomainLevel'"
                })
            }
            elseif ($nonCompliant.Count -gt 0) {
                $results.Add([PSCustomObject]@{
                    Name    = "All DCs meet minimum OS version"
                    Passed  = $false
                    Message = "Non-compliant DC(s) — build >= $minBuild required: $($nonCompliant -join '; ')"
                })
            }
            else {
                $results.Add([PSCustomObject]@{
                    Name    = "All DCs meet minimum OS version"
                    Passed  = $false
                    Message = "Could not determine OS build for: $($unknownBuild -join '; ')"
                })
            }
        }
        catch {
            $results.Add([PSCustomObject]@{
                Name    = "All DCs meet minimum OS version"
                Passed  = $false
                Message = "Error enumerating domain controllers: $_"
            })
        }
    }

    # --- Check 5: Domain Admins membership ---
    try {
        $domainAdminsGroup = Get-ADGroup "Domain Admins" @serverParam
        if ($Credential) {
            # Running with an explicit credential (e.g. not domain-joined): the local
            # Windows logon token does not reflect the AD account's own group membership,
            # so resolve it directly from AD via the tokenGroups constructed attribute
            # (also correctly resolves nested group membership).
            $identityName    = $Credential.UserName
            $accountName     = $Credential.UserName -replace '^.*[\\@]', ''
            $userDN          = (Get-ADUser -Identity $accountName @serverParam).DistinguishedName
            # tokenGroups is a constructed attribute: it can only be read via an explicit
            # base-scope search (Get-ADUser/-Object -Identity does not reliably issue one
            # remotely, and fails with "only supported for base searches").
            $userTokenGroups = (Get-ADObject -SearchBase $userDN -SearchScope Base -Filter * -Properties tokenGroups @serverParam).tokenGroups
            $sidValues       = foreach ($tg in $userTokenGroups) {
                if ($tg -is [System.Security.Principal.SecurityIdentifier]) { $tg.Value }
                else { ([System.Security.Principal.SecurityIdentifier]::new([byte[]]$tg, 0)).Value }
            }
            $isDomainAdmin = $domainAdminsGroup.SID.Value -in $sidValues
        }
        else {
            $identity      = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $identityName  = $identity.Name
            $isDomainAdmin = $identity.Groups.Value -contains $domainAdminsGroup.SID.Value
        }
        if ($isDomainAdmin) {
            $results.Add([PSCustomObject]@{
                Name    = "Domain Admins membership"
                Passed  = $true
                Message = "Running as '$identityName' — member of Domain Admins"
            })
        }
        else {
            $results.Add([PSCustomObject]@{
                Name    = "Domain Admins membership"
                Passed  = $false
                Message = "Running as '$identityName' — NOT a member of Domain Admins (required for Set-ADDomainMode)"
            })
        }
    }
    catch {
        $results.Add([PSCustomObject]@{
            Name    = "Domain Admins membership"
            Passed  = $false
            Message = "Error checking Domain Admins membership: $_"
        })
    }

    # --- Check 6: SYSVOL is replicated via DFSR, not FRS ---
    try {
        $pdcNetBIOS  = ($domain.PDCEmulator -split '\.')[0]
        $dfsrSubPath = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=$pdcNetBIOS,OU=Domain Controllers,$($domain.DistinguishedName)"
        $dfsrSub     = Get-ADObject -Identity $dfsrSubPath -Properties "msDFSR-Enabled" @serverParam -ErrorAction SilentlyContinue
        # Query the PDC's FRS service remotely via CIM (not the local machine — this task
        # may run from an admin workstation, not the DC itself) using the same explicit
        # credential when supplied.
        # Get-CimInstance doesn't accept -ComputerName and -Credential together — route
        # through an explicit CIM session (over WinRM) when an explicit credential is used.
        $cimParam = @{ ErrorAction = 'SilentlyContinue' }
        if ($Credential) {
            $cimSession = New-LOCKmeADCimSession -ComputerName $domain.PDCEmulator -Credential $Credential
            if (-not $cimSession) {
                throw "Could not establish a CIM session to PDC Emulator '$($domain.PDCEmulator)' with the supplied credential — ensure WinRM (5985/5986) is reachable there."
            }
            $cimParam.CimSession = $cimSession
        }
        else {
            $cimParam.ComputerName = $domain.PDCEmulator
        }
        $frsService  = Get-CimInstance -ClassName Win32_Service -Filter "Name='NtFrs'" @cimParam
        $frsRunning  = $frsService -and ($frsService.State -eq "Running")

        if ($frsRunning) {
            $results.Add([PSCustomObject]@{
                Name    = "SYSVOL replication uses DFSR"
                Passed  = $false
                Message = "FRS service (NtFrs) is still running on this DC — run 'dfsrmig /SetGlobalState 3' to reach the Eliminated state"
            })
        }
        elseif ($dfsrSub -and $dfsrSub.'msDFSR-Enabled') {
            $frsStatus = if ($frsService) { "FRS service is stopped/disabled" } else { "FRS service is not installed" }
            $results.Add([PSCustomObject]@{
                Name    = "SYSVOL replication uses DFSR"
                Passed  = $true
                Message = "DFSR SYSVOL subscription is active on PDC Emulator '$pdcNetBIOS' — $frsStatus on this DC"
            })
        }
        else {
            $detail = if (-not $dfsrSub) {
                "DFSR SYSVOL subscription object not found for PDC Emulator '$pdcNetBIOS'"
            } else {
                "DFSR SYSVOL subscription exists but is not enabled (msDFSR-Enabled = false)"
            }
            $results.Add([PSCustomObject]@{
                Name    = "SYSVOL replication uses DFSR"
                Passed  = $false
                Message = "$detail — run 'dfsrmig /GetMigrationState' to diagnose"
            })
        }
    }
    catch {
        $results.Add([PSCustomObject]@{
            Name    = "SYSVOL replication uses DFSR"
            Passed  = $false
            Message = "Error checking SYSVOL replication state: $_"
        })
    }

    return $results
}

function Test-HardeningForestFunctionalLevelPrerequisites {
    <#
    .SYNOPSIS
        Checks all prerequisites before raising the forest functional level.
    .PARAMETER TargetForestLevel
        Target forest functional level (e.g. Windows2016Forest).
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    .OUTPUTS
        Array of PSCustomObject with Name, Passed, Message properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetForestLevel,

        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $domainLevelOrder = @{
        'Windows2000Domain'        = 0
        'Windows2003InterimDomain' = 1
        'Windows2003Domain'        = 2
        'Windows2008Domain'        = 3
        'Windows2008R2Domain'      = 4
        'Windows2012Domain'        = 5
        'Windows2012R2Domain'      = 6
        'Windows2016Domain'        = 7
        'Windows2025Domain'        = 9
    }
    $forestLevelOrder = @{
        'Windows2000Forest'        = 0
        'Windows2003InterimForest' = 1
        'Windows2003Forest'        = 2
        'Windows2008Forest'        = 3
        'Windows2008R2Forest'      = 4
        'Windows2012Forest'        = 5
        'Windows2012R2Forest'      = 6
        'Windows2016Forest'        = 7
        'Windows2025Forest'        = 9
    }

    # --- Check 1: AD connectivity ---
    $domain = $null
    $forest = $null
    try {
        $domain = Get-ADDomain @serverParam
        $forest = Get-ADForest @serverParam
        $results.Add([PSCustomObject]@{
            Name    = "Active Directory connectivity"
            Passed  = $true
            Message = "Connected to domain '$($domain.DNSRoot)' in forest '$($forest.Name)'"
        })
    }
    catch {
        $results.Add([PSCustomObject]@{
            Name    = "Active Directory connectivity"
            Passed  = $false
            Message = "Cannot connect to Active Directory: $_"
        })
        return $results
    }

    # --- Check 2: PDC Emulator reachable ---
    try {
        $pdcFQDN     = $domain.PDCEmulator
        $pdcReachable = Test-Connection -ComputerName $pdcFQDN -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($pdcReachable) {
            $results.Add([PSCustomObject]@{
                Name    = "PDC Emulator reachable"
                Passed  = $true
                Message = "PDC Emulator '$pdcFQDN' is reachable"
            })
        }
        else {
            $results.Add([PSCustomObject]@{
                Name    = "PDC Emulator reachable"
                Passed  = $false
                Message = "PDC Emulator '$pdcFQDN' did not respond — ensure it is online and network access is allowed"
            })
        }
    }
    catch {
        $results.Add([PSCustomObject]@{
            Name    = "PDC Emulator reachable"
            Passed  = $false
            Message = "Error checking PDC Emulator connectivity: $_"
        })
    }

    # --- Check 3: Target forest level valid and raiseable ---
    $currentForestMode  = $forest.ForestMode.ToString()
    $currentForestOrder = $forestLevelOrder[$currentForestMode]
    $targetForestOrder  = $forestLevelOrder[$TargetForestLevel]

    if ($null -eq $targetForestOrder) {
        $results.Add([PSCustomObject]@{
            Name    = "Target forest functional level"
            Passed  = $false
            Message = "Unrecognized target forest functional level: '$TargetForestLevel'"
        })
    }
    elseif ($null -ne $currentForestOrder -and $currentForestOrder -gt $targetForestOrder) {
        $results.Add([PSCustomObject]@{
            Name    = "Target forest functional level"
            Passed  = $false
            Message = "Current level '$currentForestMode' is already above '$TargetForestLevel' — functional levels cannot be lowered"
        })
    }
    elseif ($null -ne $currentForestOrder -and $currentForestOrder -eq $targetForestOrder) {
        $results.Add([PSCustomObject]@{
            Name    = "Target forest functional level"
            Passed  = $true
            Message = "Forest is already at '$TargetForestLevel' — this step will be skipped automatically"
        })
    }
    else {
        $results.Add([PSCustomObject]@{
            Name    = "Target forest functional level"
            Passed  = $true
            Message = "Current level '$currentForestMode' can be raised to '$TargetForestLevel'"
        })
    }

    # --- Check 4: All domains in the forest are at the required domain functional level ---
    $requiredDomainLevel = $TargetForestLevel -replace 'Forest$', 'Domain'
    $requiredDomainOrder = $domainLevelOrder[$requiredDomainLevel]
    if ($null -ne $requiredDomainOrder) {
        try {
            $forestDomains       = @($forest.Domains)
            $nonCompliantDomains = @()
            foreach ($domainDNS in $forestDomains) {
                try {
                    $d     = Get-ADDomain -Identity $domainDNS @serverParam
                    $dMode = $d.DomainMode.ToString()
                    $dOrder = $domainLevelOrder[$dMode]
                    if ($null -eq $dOrder -or $dOrder -lt $requiredDomainOrder) {
                        $nonCompliantDomains += "$domainDNS (level: $dMode)"
                    }
                }
                catch {
                    $nonCompliantDomains += "$domainDNS (error: $_)"
                }
            }
            if ($nonCompliantDomains.Count -eq 0) {
                $results.Add([PSCustomObject]@{
                    Name    = "All forest domains at required level"
                    Passed  = $true
                    Message = "All $($forestDomains.Count) domain(s) are at '$requiredDomainLevel' or above"
                })
            }
            else {
                $results.Add([PSCustomObject]@{
                    Name    = "All forest domains at required level"
                    Passed  = $false
                    Message = "Domain(s) not yet at '$requiredDomainLevel': $($nonCompliantDomains -join '; ')"
                })
            }
        }
        catch {
            $results.Add([PSCustomObject]@{
                Name    = "All forest domains at required level"
                Passed  = $false
                Message = "Error checking forest domain levels: $_"
            })
        }
    }

    # --- Check 5: Enterprise Admins membership ---
    try {
        $forestRootDomain = Get-ADDomain -Identity $forest.RootDomain @serverParam
        $rootParam        = $serverParam.Clone()
        $rootParam.Server = $forestRootDomain.PDCEmulator
        $enterpriseAdminsGroup = Get-ADGroup "Enterprise Admins" @rootParam
        if ($Credential) {
            # See Check 5 in Test-HardeningDomainFunctionalLevelPrerequisites for why this
            # can't rely on the local Windows logon token when an explicit credential is used.
            $identityName    = $Credential.UserName
            $accountName     = $Credential.UserName -replace '^.*[\\@]', ''
            $userDN          = (Get-ADUser -Identity $accountName @serverParam).DistinguishedName
            # tokenGroups is a constructed attribute: it can only be read via an explicit
            # base-scope search — see Check 5 in Test-HardeningDomainFunctionalLevelPrerequisites.
            $userTokenGroups = (Get-ADObject -SearchBase $userDN -SearchScope Base -Filter * -Properties tokenGroups @rootParam).tokenGroups
            $sidValues       = foreach ($tg in $userTokenGroups) {
                if ($tg -is [System.Security.Principal.SecurityIdentifier]) { $tg.Value }
                else { ([System.Security.Principal.SecurityIdentifier]::new([byte[]]$tg, 0)).Value }
            }
            $isEnterpriseAdmin = $enterpriseAdminsGroup.SID.Value -in $sidValues
        }
        else {
            $identity          = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $identityName      = $identity.Name
            $isEnterpriseAdmin = $identity.Groups.Value -contains $enterpriseAdminsGroup.SID.Value
        }
        if ($isEnterpriseAdmin) {
            $results.Add([PSCustomObject]@{
                Name    = "Enterprise Admins membership"
                Passed  = $true
                Message = "Running as '$identityName' — member of Enterprise Admins"
            })
        }
        else {
            $results.Add([PSCustomObject]@{
                Name    = "Enterprise Admins membership"
                Passed  = $false
                Message = "Running as '$identityName' — NOT a member of Enterprise Admins (required for Set-ADForestMode)"
            })
        }
    }
    catch {
        $results.Add([PSCustomObject]@{
            Name    = "Enterprise Admins membership"
            Passed  = $false
            Message = "Error checking Enterprise Admins membership: $_"
        })
    }

    # --- Check 6: SYSVOL is replicated via DFSR, not FRS ---
    try {
        $pdcNetBIOS  = ($domain.PDCEmulator -split '\.')[0]
        $dfsrSubPath = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=$pdcNetBIOS,OU=Domain Controllers,$($domain.DistinguishedName)"
        $dfsrSub     = Get-ADObject -Identity $dfsrSubPath -Properties "msDFSR-Enabled" @serverParam -ErrorAction SilentlyContinue
        # Get-CimInstance doesn't accept -ComputerName and -Credential together — route
        # through an explicit CIM session (over WinRM) when an explicit credential is used.
        $cimParam = @{ ErrorAction = 'SilentlyContinue' }
        if ($Credential) {
            $cimSession = New-LOCKmeADCimSession -ComputerName $domain.PDCEmulator -Credential $Credential
            if (-not $cimSession) {
                throw "Could not establish a CIM session to PDC Emulator '$($domain.PDCEmulator)' with the supplied credential — ensure WinRM (5985/5986) is reachable there."
            }
            $cimParam.CimSession = $cimSession
        }
        else {
            $cimParam.ComputerName = $domain.PDCEmulator
        }
        $frsService  = Get-CimInstance -ClassName Win32_Service -Filter "Name='NtFrs'" @cimParam
        $frsRunning  = $frsService -and ($frsService.State -eq "Running")

        if ($frsRunning) {
            $results.Add([PSCustomObject]@{
                Name    = "SYSVOL replication uses DFSR"
                Passed  = $false
                Message = "FRS service (NtFrs) is still running on this DC — run 'dfsrmig /SetGlobalState 3' to reach the Eliminated state"
            })
        }
        elseif ($dfsrSub -and $dfsrSub.'msDFSR-Enabled') {
            $frsStatus = if ($frsService) { "FRS service is stopped/disabled" } else { "FRS service is not installed" }
            $results.Add([PSCustomObject]@{
                Name    = "SYSVOL replication uses DFSR"
                Passed  = $true
                Message = "DFSR SYSVOL subscription is active on PDC Emulator '$pdcNetBIOS' — $frsStatus on this DC"
            })
        }
        else {
            $detail = if (-not $dfsrSub) {
                "DFSR SYSVOL subscription object not found for PDC Emulator '$pdcNetBIOS'"
            } else {
                "DFSR SYSVOL subscription exists but is not enabled (msDFSR-Enabled = false)"
            }
            $results.Add([PSCustomObject]@{
                Name    = "SYSVOL replication uses DFSR"
                Passed  = $false
                Message = "$detail — run 'dfsrmig /GetMigrationState' to diagnose"
            })
        }
    }
    catch {
        $results.Add([PSCustomObject]@{
            Name    = "SYSVOL replication uses DFSR"
            Passed  = $false
            Message = "Error checking SYSVOL replication state: $_"
        })
    }

    return $results
}

# ============================================================================
# Task: SetMachineAccountQuota
# ============================================================================

function Set-HardeningMachineAccountQuota {
    <#
    .SYNOPSIS
        Sets ms-DS-MachineAccountQuota to 0.
    .PARAMETER LogDirectory
        Log directory.
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $Quota = 0
    $domainDN = (Get-ADDomain @serverParam).DistinguishedName

    $currentQuota = (Get-ADObject -Identity $domainDN -Properties "ms-DS-MachineAccountQuota" @serverParam)."ms-DS-MachineAccountQuota"
    if ($currentQuota -eq $Quota) {
        Write-HardeningLog -Message "ms-DS-MachineAccountQuota is already set to 0." -Level Warning -LogDirectory $LogDirectory
        return
    }

    if ($PSCmdlet.ShouldProcess($domainDN, "Set ms-DS-MachineAccountQuota to 0 (current: $currentQuota)")) {
        try {
            Set-ADDomain -Identity $domainDN -Replace @{ "ms-DS-MachineAccountQuota" = $Quota } @serverParam
            Write-HardeningLog -Message "ms-DS-MachineAccountQuota set to 0 (was $currentQuota)." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error setting ms-DS-MachineAccountQuota: $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] ms-DS-MachineAccountQuota would be set to 0 (current: $currentQuota)." -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# Tasks: RaiseDomainFunctionalLevel / RaiseForestFunctionalLevel
# ============================================================================

function Set-HardeningDomainFunctionalLevel {
    <#
    .SYNOPSIS
        Raises the domain functional level to the specified target.
    .PARAMETER TargetDomainLevel
        Target domain functional level (e.g. Windows2016Domain).
    .PARAMETER LogDirectory
        Log directory.
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$TargetDomainLevel,

        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $prereqResults = Test-HardeningDomainFunctionalLevelPrerequisites -TargetDomainLevel $TargetDomainLevel -Server $Server -Credential $Credential
    $failedChecks  = @($prereqResults | Where-Object { -not $_.Passed })
    if ($failedChecks.Count -gt 0) {
        foreach ($check in $failedChecks) {
            Write-HardeningLog -Message "Prerequisite not met — $($check.Name): $($check.Message)" `
                -Level Error -LogDirectory $LogDirectory
        }
        throw "Prerequisites for RaiseDomainFunctionalLevel not met ($($failedChecks.Count) check(s) failed). Task aborted."
    }

    $domain            = Get-ADDomain @serverParam
    $currentDomainMode = $domain.DomainMode.ToString()

    if ($currentDomainMode -eq $TargetDomainLevel) {
        Write-HardeningLog -Message "Domain functional level is already at '$TargetDomainLevel'." -Level Warning -LogDirectory $LogDirectory
    }
    elseif ($PSCmdlet.ShouldProcess($domain.DistinguishedName, "Raise domain functional level to '$TargetDomainLevel' (current: $currentDomainMode)")) {
        try {
            Set-ADDomainMode -Identity $domain.DistinguishedName -DomainMode $TargetDomainLevel -Confirm:$false @serverParam
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
}

function Set-HardeningForestFunctionalLevel {
    <#
    .SYNOPSIS
        Raises the forest functional level to the specified target.
    .PARAMETER TargetForestLevel
        Target forest functional level (e.g. Windows2016Forest).
    .PARAMETER LogDirectory
        Log directory.
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$TargetForestLevel,

        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $prereqResults = Test-HardeningForestFunctionalLevelPrerequisites -TargetForestLevel $TargetForestLevel -Server $Server -Credential $Credential
    $failedChecks  = @($prereqResults | Where-Object { -not $_.Passed })
    if ($failedChecks.Count -gt 0) {
        foreach ($check in $failedChecks) {
            Write-HardeningLog -Message "Prerequisite not met — $($check.Name): $($check.Message)" `
                -Level Error -LogDirectory $LogDirectory
        }
        throw "Prerequisites for RaiseForestFunctionalLevel not met ($($failedChecks.Count) check(s) failed). Task aborted."
    }

    $forest            = Get-ADForest @serverParam
    $currentForestMode = $forest.ForestMode.ToString()

    if ($currentForestMode -eq $TargetForestLevel) {
        Write-HardeningLog -Message "Forest functional level is already at '$TargetForestLevel'." -Level Warning -LogDirectory $LogDirectory
    }
    elseif ($PSCmdlet.ShouldProcess($forest.Name, "Raise forest functional level to '$TargetForestLevel' (current: $currentForestMode)")) {
        try {
            Set-ADForestMode -Identity $forest.Name -ForestMode $TargetForestLevel -Confirm:$false @serverParam
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
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $forest = Get-ADForest @serverParam
    $featureName = "Recycle Bin Feature"
    $targetServer = (Get-ADDomain -Identity $forest.RootDomain @serverParam).PDCEmulator
    $rootParam = $serverParam.Clone()
    $rootParam.Server = $targetServer

    # Check if already enabled
    $feature = Get-ADOptionalFeature -Filter { Name -eq "Recycle Bin Feature" } @rootParam
    if ($feature.EnabledScopes.Count -gt 0) {
        Write-HardeningLog -Message "AD Recycle Bin is already enabled." -Level Warning -LogDirectory $LogDirectory
        return
    }

    if ($PSCmdlet.ShouldProcess($forest.Name, "Enable AD Recycle Bin (via $targetServer)")) {
        try {
            Enable-ADOptionalFeature -Identity $featureName -Scope ForestOrConfigurationSet -Target $forest.Name -Confirm:$false @rootParam
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
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $forest = Get-ADForest @serverParam
    $featureName = "Privileged Access Management Feature"
    $targetServer = (Get-ADDomain -Identity $forest.RootDomain @serverParam).PDCEmulator
    $rootParam = $serverParam.Clone()
    $rootParam.Server = $targetServer

    # Check if already enabled
    $feature = Get-ADOptionalFeature -Filter { Name -eq "Privileged Access Management Feature" } @rootParam
    if ($feature.EnabledScopes.Count -gt 0) {
        Write-HardeningLog -Message "AD PAM Feature is already enabled." -Level Warning -LogDirectory $LogDirectory
        return
    }

    if ($PSCmdlet.ShouldProcess($forest.Name, "Enable AD PAM Feature (via $targetServer)")) {
        try {
            Enable-ADOptionalFeature -Identity $featureName -Scope ForestOrConfigurationSet -Target $forest.Name -Confirm:$false @rootParam
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

function Get-HardeningAnonymousLogonMemberDN {
    <#
    .SYNOPSIS
        Private. Returns the DN(s) of the group's members that stand for ANONYMOUS LOGON
        (S-1-5-7), or an empty array.
    .DESCRIPTION
        Shared by the deployment task and its verification so the two halves cannot disagree about
        whether the remediation is applied.

        ANONYMOUS LOGON is reachable through TWO distinct directory objects carrying the same
        objectSid, and a 'member' value may legitimately name either:

          CN=Anonymous Logon,CN=WellKnown Security Principals,CN=Configuration,<forest>
              the forest-wide catalogue entry, named after the friendly name;
          CN=S-1-5-7,CN=ForeignSecurityPrincipals,<domainDN>
              the per-domain stub, named after the SID, created on demand when the SID is placed
              into a domain group.

        Matching the DN as a string therefore cannot be trusted: it recognises one form and
        silently misses the other, which on a security remediation means reporting "already
        secure" over a domain where anonymous access is still open -- a failure mode worse than an
        error, because nothing surfaces. The SID is the only stable identity, so each candidate is
        resolved and compared on objectSid.

        The DN whose leading component IS the SID settles itself, so the common case costs no
        extra query.
    .PARAMETER Group
        The group object, read with -Properties member.
    .PARAMETER ConnParam
        Splat hashtable with Server/Credential, as built by the caller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Group,
        [hashtable]$ConnParam = @{}
    )

    $anonymousSid = 'S-1-5-7'

    return @(
        foreach ($memberDN in @($Group.member)) {
            if ($memberDN -like "CN=$anonymousSid,*") { $memberDN; continue }

            $obj = Get-ADObject -Identity $memberDN -Properties objectSid @ConnParam -ErrorAction SilentlyContinue
            if ($obj -and $obj.objectSid -and $obj.objectSid.Value -eq $anonymousSid) { $memberDN }
        }
    )
}

function Disable-HardeningAnonymousAccess {
    <#
    .SYNOPSIS
        Removes ANONYMOUS LOGON (S-1-5-7) from the Pre-Windows 2000 Compatible Access group.
    .PARAMETER LogDirectory
        Log directory.
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    # Resolved by its well-known SID, never by name. "Pre-Windows 2000 Compatible Access" is a
    # BUILTIN group whose name is localized by the DC's installation language ("Accès compatible
    # pré-Windows 2000", "Prä-Windows 2000 kompatibler Zugriff", ...), so a name lookup raises
    # ADIdentityNotFoundException on every non-English forest. S-1-5-32-554 is the same everywhere.
    $groupSid = "S-1-5-32-554"

    try {
        $group = Get-ADGroup -Identity $groupSid -Properties member @serverParam -ErrorAction Stop
    }
    catch {
        Write-HardeningLog -Message "Error reading the Pre-Windows 2000 Compatible Access group ($groupSid): $_" -Level Error -LogDirectory $LogDirectory
        throw
    }

    # Membership is read from the raw 'member' attribute, and the removal writes that same
    # attribute directly, because ANONYMOUS LOGON cannot survive a round-trip through the
    # membership cmdlets.
    #
    # It is a foreignSecurityPrincipal, not a real account. Get-ADGroupMember returns it with an
    # EMPTY distinguishedName, an EMPTY objectClass and an all-zero objectGUID -- only the SID and
    # the name the local LSA resolved from it are populated. Feeding that object back to
    # Remove-ADGroupMember -Members leaves the cmdlet with no usable identity to build the
    # modification from, and it fails with a bare "Object reference not set to an instance of an
    # object": a .NET null dereference inside the cmdlet, with nothing naming the group, the member
    # or the cause. It fails that way even under -WhatIf, i.e. before any write is attempted, so
    # deployments simply lost this task on every domain where the remediation was needed.
    #
    # Which DN stands for ANONYMOUS LOGON is not obvious -- see Get-HardeningAnonymousLogonMemberDN.
    $anonymousDNs = Get-HardeningAnonymousLogonMemberDN -Group $group -ConnParam $serverParam

    if ($anonymousDNs.Count -eq 0) {
        Write-HardeningLog -Message "ANONYMOUS LOGON is not a member of '$($group.Name)'. Already secure." -Level Warning -LogDirectory $LogDirectory
        return
    }

    if ($PSCmdlet.ShouldProcess($group.Name, "Remove ANONYMOUS LOGON (S-1-5-7)")) {
        try {
            Set-ADObject -Identity $group.DistinguishedName -Remove @{ member = $anonymousDNs } @serverParam -ErrorAction Stop
            Write-HardeningLog -Message "ANONYMOUS LOGON removed from '$($group.Name)'." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error removing ANONYMOUS LOGON from '$($group.Name)': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] ANONYMOUS LOGON would be removed from '$($group.Name)'." -Level Info -LogDirectory $LogDirectory
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
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName,

        [Parameter(Mandatory)]
        [string]$SiloName,

        [int]$TGTLifetimeMinutes = 240,

        [bool]$Enforce = $false,

        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    # --- Authentication Policy ---
    $existingPolicy = Get-ADAuthenticationPolicy -Filter { Name -eq $PolicyName } @serverParam -ErrorAction SilentlyContinue
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
                                       -ProtectedFromAccidentalDeletion $true `
                                       @serverParam
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
    $existingSilo = Get-ADAuthenticationPolicySilo -Filter { Name -eq $SiloName } @serverParam -ErrorAction SilentlyContinue
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
                                           -ProtectedFromAccidentalDeletion $true `
                                           @serverParam
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
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    try {
        $siteLinks = Get-ADReplicationSiteLink -Filter * -Properties Options @serverParam
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
                Set-ADReplicationSiteLink -Identity $link -Replace @{ Options = $newOptions } @serverParam
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
#
# The ADMX download and install run ON the target domain controller itself, inside a WinRM
# session opened via Invoke-LOCKmeADRemote -AlwaysRemote -- never on whatever machine happens
# to run LOCKmeAD. Two problems this fixes at once:
#   - the operator's own PolicyDefinitions folder (the local seed copy) is often thin,
#     mismatched, or plain absent on a non-domain-joined admin machine, whereas every DC
#     ships one;
#   - the previous code reached out to Microsoft's download center from the operator's own
#     machine, then wrote the result over SYSVOL — functionally equivalent, but the network
#     egress now happens from the host actually meant to be centrally managed.
#
# Trade-off, and the reason this task logs a Warning before it runs: the chosen DC needs
# outbound HTTPS to www.microsoft.com / download.microsoft.com to fetch the templates, and
# plenty of hardened estates deliberately deny domain controllers internet access. When that
# egress is blocked, the remote block below catches the failure and falls back to the DC's
# own local PolicyDefinitions only — see the Warning it logs in that case.

function Set-HardeningCentralStore {
    <#
    .SYNOPSIS
        Creates or updates the Group Policy Central Store in SYSVOL.
    .DESCRIPTION
        Runs entirely on the target domain controller (-Server), inside a WinRM session
        opened via Invoke-LOCKmeADRemote -AlwaysRemote. On that DC:
          1. Copies its own local PolicyDefinitions folder into the Central Store.
          2. Downloads the latest Windows Administrative Templates from Microsoft and
             overlays them (overwrites with newer versions).
        If step 2 fails — most commonly because the DC has no outbound internet access — the
        task completes with a warning using the DC's local PolicyDefinitions only.

        -Server is required: this task always needs one specific DC to run on and download
        from, regardless of whether the host running LOCKmeAD is itself domain-joined.
    .PARAMETER LogDirectory
        Log directory.
    .PARAMETER Server
        Target domain controller the Central Store is built on. Required — see DESCRIPTION.
        That DC needs outbound internet access for step 2 to succeed.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory,

        [Parameter(Mandatory)]
        [string]$Server,

        [PSCredential]$Credential
    )

    $serverParam = @{ Server = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    $domainDNS        = (Get-ADDomain @serverParam).DNSRoot
    $centralStorePath = "\\$domainDNS\SYSVOL\$domainDNS\Policies\PolicyDefinitions"

    Write-HardeningLog -Message "ConfigureCentralStore runs ON '$Server': that domain controller needs outbound internet access (HTTPS to www.microsoft.com and download.microsoft.com) to fetch the latest Windows ADMX templates. Without it, the task falls back to '$Server''s own local PolicyDefinitions only." `
        -Level Warning -LogDirectory $LogDirectory

    if ($PSCmdlet.ShouldProcess($centralStorePath, "Create/update GPO Central Store (executed on $Server)")) {
        try {
            $remote = Invoke-LOCKmeADRemote -Server $Server -Credential $Credential -AlwaysRemote -ScriptBlock {
                param($CentralStorePath)

                # Self-contained: this block crosses a remoting boundary (see
                # Invoke-LOCKmeADRemote's own doc), so it cannot call back into the Hardening
                # module — everything it needs, including its own log buffer, lives in here.
                $log = [System.Collections.Generic.List[PSCustomObject]]::new()
                function Add-RemoteLog([string]$Level, [string]$Message) {
                    $log.Add([PSCustomObject]@{ Level = $Level; Message = $Message })
                }

                $sourcePath   = "$env:SystemRoot\PolicyDefinitions"
                $storeExisted = Test-Path $CentralStorePath
                if (-not (Test-Path $sourcePath)) {
                    throw "Source PolicyDefinitions not found at '$sourcePath' on $env:COMPUTERNAME."
                }

                if (-not $storeExisted) {
                    New-Item -Path $CentralStorePath -ItemType Directory -Force | Out-Null
                    Add-RemoteLog 'Info' "Central Store directory created at '$CentralStorePath'."
                }

                # Pass 1: this DC's own local PolicyDefinitions (includes server-specific ADMX files)
                Copy-Item -Path "$sourcePath\*" -Destination $CentralStorePath -Recurse -Force
                Add-RemoteLog 'Info' "$env:COMPUTERNAME's local PolicyDefinitions copied to Central Store."

                # Pass 2: latest Windows ADMX from Microsoft, downloaded and extracted on this DC
                # (overlays / overwrites with newest versions). Failure here is not fatal to the
                # task -- see the Warning below and the module-level comment above this function.
                try {
                    # Last-known-good fallback — update when Microsoft releases a new version.
                    $fallbackPageId = "108394"
                    $fallbackMsiUrl = "https://download.microsoft.com/download/f35d3000-b6c9-4ca6-bedc-5e4ec15a6b7a/Administrative%20Templates%20(admx)%20for%20Windows%2011%20Sep%202025%20Update.msi"

                    $downloadPageId = $null
                    try {
                        # Query the Microsoft Download Center search (sorted newest first) and
                        # validate each candidate by checking that its surrounding HTML context
                        # mentions both "Administrative Templates" and ".admx".
                        $searchUrl  = "https://www.microsoft.com/en-us/download/search?q=Administrative+Templates+admx+Windows&p=0&r=10&t=All&s=Date&o=Descending"
                        $searchPage = Invoke-WebRequest -Uri $searchUrl -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
                        foreach ($m in [regex]::Matches($searchPage.Content, 'details\.aspx\?id=(\d+)')) {
                            $start   = [Math]::Max(0, $m.Index - 300)
                            $length  = [Math]::Min(600, $searchPage.Content.Length - $start)
                            $context = $searchPage.Content.Substring($start, $length)
                            if ($context -imatch 'administrative[\s\-]+templates' -and $context -imatch '\.admx') {
                                $downloadPageId = $m.Groups[1].Value
                                break
                            }
                        }
                        if (-not $downloadPageId) { throw "No Administrative Templates download page found in search results." }
                    }
                    catch {
                        Add-RemoteLog 'Warning' "Auto-detection of the latest ADMX page ID failed on $env:COMPUTERNAME`: $_ — using last known ID ($fallbackPageId)."
                        $downloadPageId = $fallbackPageId
                    }

                    # Microsoft now loads the download button URL via JavaScript, so basic HTML
                    # scraping often finds nothing. Try both the confirmation and details pages,
                    # then fall back to the hardcoded last-known-good URL.
                    $downloadUrl = $null
                    foreach ($pageUrl in @(
                        "https://www.microsoft.com/en-us/download/confirmation.aspx?id=$downloadPageId",
                        "https://www.microsoft.com/en-us/download/details.aspx?id=$downloadPageId"
                    )) {
                        try {
                            $dlPage = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
                            $downloadUrl = [regex]::Match($dlPage.Content, 'https://download\.microsoft\.com/download/[^"''<>\s]+\.msi').Value
                            if ($downloadUrl) { break }
                        }
                        catch { }
                    }
                    if (-not $downloadUrl) {
                        Add-RemoteLog 'Warning' "MSI URL not found in page HTML on $env:COMPUTERNAME (Microsoft loads it via JS) — using last-known-good URL."
                        $downloadUrl = $fallbackMsiUrl
                    }

                    $tempDir    = Join-Path $env:TEMP "LOCKmeAD_ADMX_$(Get-Date -Format 'yyyyMMddHHmmss')"
                    $msiPath    = Join-Path $tempDir "AdminTemplates.msi"
                    $extractDir = Join-Path $tempDir "Extracted"
                    try {
                        New-Item -Path $tempDir    -ItemType Directory -Force | Out-Null
                        New-Item -Path $extractDir -ItemType Directory -Force | Out-Null

                        Invoke-WebRequest -Uri $downloadUrl -OutFile $msiPath -ErrorAction Stop

                        $proc = Start-Process -FilePath "msiexec.exe" `
                                              -ArgumentList "/a `"$msiPath`" /qn TARGETDIR=`"$extractDir`"" `
                                              -Wait -PassThru -WindowStyle Hidden
                        if ($proc.ExitCode -notin @(0, 3010)) {
                            throw "msiexec admin install failed with exit code $($proc.ExitCode)."
                        }

                        $policyDefDir = Get-ChildItem -Path $extractDir -Filter "PolicyDefinitions" -Recurse -Directory |
                                        Select-Object -First 1
                        if (-not $policyDefDir) {
                            throw "PolicyDefinitions folder not found in extracted MSI content at '$extractDir'."
                        }

                        Copy-Item -Path "$($policyDefDir.FullName)\*" -Destination $CentralStorePath -Recurse -Force

                        $admxCount = (Get-ChildItem -Path $CentralStorePath -Filter "*.admx" -ErrorAction SilentlyContinue).Count
                        Add-RemoteLog 'Success' "Latest Windows ADMX templates downloaded and applied by $env:COMPUTERNAME ($admxCount .admx files)."
                    }
                    finally {
                        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    Add-RemoteLog 'Warning' "$env:COMPUTERNAME could not download the latest Windows ADMX from Microsoft (likely no outbound internet access from this DC): $_ — Central Store populated from its local PolicyDefinitions only."
                }

                return [PSCustomObject]@{ StoreExisted = $storeExisted; Log = $log }
            } -ArgumentList $centralStorePath

            foreach ($entry in $remote.Log) {
                Write-HardeningLog -Message $entry.Message -Level $entry.Level -LogDirectory $LogDirectory
            }

            $pastVerb = if ($remote.StoreExisted) { "updated" } else { "created" }
            Write-HardeningLog -Message "GPO Central Store $pastVerb at '$centralStorePath' (executed on $Server)." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error configuring GPO Central Store on '$Server': $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] GPO Central Store would be created/updated at '$centralStorePath', executed on '$Server' — that DC would need outbound internet access to fetch the latest Windows ADMX; its own local PolicyDefinitions would be used as the base either way." -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# LAPS command dispatch (shared by ExtendLAPSSchema / ConfigureLAPSADPermissions)
# ============================================================================

function Invoke-HardeningLapsCommand {
    <#
    .SYNOPSIS
        Runs a Windows LAPS module command, either in-process or inside a WinRM session on
        the target domain controller.
    .DESCRIPTION
        The LAPS module's cmdlets (Update-LapsADSchema, Set-LapsAD*, Find-LapsADExtendedRights)
        accept -Server but never -Credential -- exactly the gap the GroupPolicy module has,
        and handled here the same way: Invoke-LOCKmeADRemote runs the scriptblock in-process
        when there is no credential (zero behavior change for a domain-joined run), and inside
        a WinRM session on -Server when there is one, so the cmdlet executes under that domain
        identity's own Windows token instead of a credential it cannot accept.

        This replaces the previous guidance of launching the whole tool under
        'runas /netonly': runas.exe reads its password straight from the console and cannot
        be handed a PSCredential, so the credential collected by the GUI could never reach it.

        Consequence worth knowing: with an explicit credential the LAPS module only needs to
        be present on the target DC, not on the host running LOCKmeAD.
    .PARAMETER Command
        Name of the LAPS cmdlet to invoke.
    .PARAMETER Parameters
        Splat hashtable for that cmdlet. -Server is added here rather than by the caller,
        because whether it is wanted at all depends on where the command ends up running.
    .PARAMETER Server
        Target domain controller.
    .PARAMETER Credential
        Explicit credential. When $null, the command runs in-process.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Command,

        [hashtable]$Parameters = @{},

        [string]$Server,

        [PSCredential]$Credential
    )

    # In explicit-credential mode the cmdlet already runs ON $Server, so it must bind to that
    # host's own directory service: adding -Server would turn a local bind into a second
    # network hop, which the remote session's token cannot authenticate (the classic WinRM
    # double-hop). In implicit mode there is no session, so -Server is what targets the DC.
    $effectiveParams = @{}
    foreach ($key in $Parameters.Keys) { $effectiveParams[$key] = $Parameters[$key] }
    if (-not $Credential -and $Server) { $effectiveParams.Server = $Server }

    Invoke-LOCKmeADRemote -Server $Server -Credential $Credential -ArgumentList $Command, $effectiveParams -ScriptBlock {
        param($Command, $Parameters)

        if (-not (Get-Module -ListAvailable -Name LAPS)) {
            throw "The Windows LAPS PowerShell module is not available on '$env:COMPUTERNAME'. It ships in-box with Windows Server 2019+ and Windows 10+ from the April 11 2023 update onward -- install the latest cumulative update on that host."
        }
        Import-Module LAPS -ErrorAction Stop
        & $Command @Parameters
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
    .PARAMETER Server
        Target DC for the AD pre-check. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. The LAPS cmdlets have no -Credential
        parameter of their own, so the extension itself is dispatched to the schema master
        over WinRM by Invoke-HardeningLapsCommand -- see that function for why.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    # A schema object carries two different names and they are NOT interchangeable in a
    # filter: cn/name is the hyphenated form ("ms-LAPS-Password") while lDAPDisplayName is
    # the camelCase form ("msLAPS-Password"). Filtering lDAPDisplayName here keeps this
    # consistent with Test-HardeningLAPSSchema and makes which form is meant unambiguous --
    # 'Name -eq "msLAPS-Password"' silently matches nothing and would make this idempotency
    # check never fire.
    $schemaNC = (Get-ADRootDSE @serverParam).schemaNamingContext
    $lapsAttribute = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(lDAPDisplayName=msLAPS-Password)" @serverParam -ErrorAction SilentlyContinue

    if ($lapsAttribute) {
        Write-HardeningLog -Message "LAPS schema extension is already present (msLAPS-Password attribute exists)." -Level Warning -LogDirectory $LogDirectory
        return
    }

    # Only the schema master owns the schema partition. Targeting it explicitly also keeps the
    # remote call to a single hop: the cmdlet binds to the directory service of the very host
    # its WinRM session is running on.
    $schemaMaster = (Get-ADForest @serverParam).SchemaMaster

    # Say plainly that the account cannot do this, instead of letting Update-LapsADSchema fail
    # somewhere inside a WinRM session with an error that never names the missing membership.
    # Reached only when the schema is NOT already extended -- the idempotency check above returns
    # first otherwise -- so this costs nothing on a converged forest. The GUI shows the same
    # notice on this task's card.
    $priv = Test-LOCKmeADPrivilege -Server $Server -Credential $Credential
    if ($priv.Determined -and -not $priv.IsSchemaAdmin) {
        Write-HardeningLog -Message "'$($priv.Identity)' is not a member of Schema Admins on the forest root. Extending the schema is reserved to that group, so this task will fail; every other task is unaffected." -Level Warning -LogDirectory $LogDirectory
    }

    if ($PSCmdlet.ShouldProcess($schemaNC, "Extend schema for Windows LAPS (via $schemaMaster)")) {
        try {
            Invoke-HardeningLapsCommand -Command 'Update-LapsADSchema' `
                                        -Parameters @{ Confirm = $false } `
                                        -Server $schemaMaster `
                                        -Credential $Credential | Out-Null
            Write-HardeningLog -Message "AD schema extended for Windows LAPS (via $schemaMaster)." -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error extending LAPS schema: $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] AD schema would be extended for Windows LAPS (via $schemaMaster)." -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# Task: ConfigureLAPSADPermissions
# ============================================================================

function Set-HardeningLAPSADPermissions {
    <#
    .SYNOPSIS
        Configures LAPS Active Directory permissions on target OUs.
    .DESCRIPTION
        Runs three LAPS permission cmdlets in sequence:
        - Set-LapsADComputerSelfPermission : grants computer objects the right to
          update their own LAPS attributes in AD.
        - Set-LapsADReadPasswordPermission : grants specified principals read
          access to the LAPS-managed password stored in AD.
        - Set-LapsADResetPasswordPermission : grants specified principals the
          right to reset the LAPS password expiration time.

        Identity accepts either a distinguished name (OU=...,DC=...) or a simple
        OU name. Principals must be fully qualified (DOMAIN\Group, UPN, or SID),
        except for well-known built-in accounts such as Domain Admins.
    .PARAMETER SelfPermissionOUs
        OUs on which Set-LapsADComputerSelfPermission is applied. One DN or name
        per entry.
    .PARAMETER ReadPasswordOUs
        OUs on which Set-LapsADReadPasswordPermission is applied.
    .PARAMETER ReadPasswordPrincipals
        Users or groups granted read access to LAPS passwords. Must be fully
        qualified (e.g. forest\GDL-LAPS-Pwd-Read, admin@forest.lol, or SID).
    .PARAMETER ResetPasswordOUs
        OUs on which Set-LapsADResetPasswordPermission is applied.
    .PARAMETER ResetPasswordPrincipals
        Users or groups granted permission to reset the LAPS password expiration.
        Must be fully qualified.
    .PARAMETER LogDirectory
        Log directory.
    .PARAMETER Server
        Target DC for all LAPS operations.
    .PARAMETER Credential
        Explicit credential to authenticate with. The Set-LapsAD* cmdlets have no
        -Credential parameter of their own, so each call is dispatched to -Server over WinRM
        by Invoke-HardeningLapsCommand -- see that function for why.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string[]]$SelfPermissionOUs       = @(),
        [string[]]$ReadPasswordOUs         = @(),
        [string[]]$ReadPasswordPrincipals  = @(),
        [string[]]$ResetPasswordOUs        = @(),
        [string[]]$ResetPasswordPrincipals = @(),
        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    # --- Set-LapsADComputerSelfPermission ---
    foreach ($ou in $SelfPermissionOUs) {
        if ([string]::IsNullOrWhiteSpace($ou)) { continue }
        if ($PSCmdlet.ShouldProcess($ou, "Set-LapsADComputerSelfPermission")) {
            try {
                Invoke-HardeningLapsCommand -Command 'Set-LapsADComputerSelfPermission' `
                                            -Parameters @{ Identity = $ou } `
                                            -Server $Server -Credential $Credential | Out-Null
                Write-HardeningLog -Message "Set LAPS computer self-permission on '$ou'." -Level Success -LogDirectory $LogDirectory
            }
            catch {
                Write-HardeningLog -Message "Error setting LAPS computer self-permission on '$ou': $_" -Level Error -LogDirectory $LogDirectory
                throw
            }
        }
        else {
            Write-HardeningLog -Message "[WhatIf] Would run Set-LapsADComputerSelfPermission on '$ou'." -Level Info -LogDirectory $LogDirectory
        }
    }

    # --- Set-LapsADReadPasswordPermission ---
    if ($ReadPasswordPrincipals.Count -gt 0) {
        foreach ($ou in $ReadPasswordOUs) {
            if ([string]::IsNullOrWhiteSpace($ou)) { continue }
            $principalList = $ReadPasswordPrincipals -join ', '
            if ($PSCmdlet.ShouldProcess($ou, "Set-LapsADReadPasswordPermission for: $principalList")) {
                try {
                    Invoke-HardeningLapsCommand -Command 'Set-LapsADReadPasswordPermission' `
                                                -Parameters @{ Identity = $ou; AllowedPrincipals = $ReadPasswordPrincipals } `
                                                -Server $Server -Credential $Credential | Out-Null
                    Write-HardeningLog -Message "Set LAPS read permission on '$ou' for: $principalList." -Level Success -LogDirectory $LogDirectory
                }
                catch {
                    Write-HardeningLog -Message "Error setting LAPS read permission on '$ou': $_" -Level Error -LogDirectory $LogDirectory
                    throw
                }
            }
            else {
                Write-HardeningLog -Message "[WhatIf] Would run Set-LapsADReadPasswordPermission on '$ou' for: $principalList." -Level Info -LogDirectory $LogDirectory
            }
        }
    }
    else {
        Write-HardeningLog -Message "Skipping read permission delegation (ReadPasswordPrincipals is empty)." -Level Warning -LogDirectory $LogDirectory
    }

    # --- Set-LapsADResetPasswordPermission ---
    if ($ResetPasswordPrincipals.Count -gt 0) {
        foreach ($ou in $ResetPasswordOUs) {
            if ([string]::IsNullOrWhiteSpace($ou)) { continue }
            $principalList = $ResetPasswordPrincipals -join ', '
            if ($PSCmdlet.ShouldProcess($ou, "Set-LapsADResetPasswordPermission for: $principalList")) {
                try {
                    Invoke-HardeningLapsCommand -Command 'Set-LapsADResetPasswordPermission' `
                                                -Parameters @{ Identity = $ou; AllowedPrincipals = $ResetPasswordPrincipals } `
                                                -Server $Server -Credential $Credential | Out-Null
                    Write-HardeningLog -Message "Set LAPS reset permission on '$ou' for: $principalList." -Level Success -LogDirectory $LogDirectory
                }
                catch {
                    Write-HardeningLog -Message "Error setting LAPS reset permission on '$ou': $_" -Level Error -LogDirectory $LogDirectory
                    throw
                }
            }
            else {
                Write-HardeningLog -Message "[WhatIf] Would run Set-LapsADResetPasswordPermission on '$ou' for: $principalList." -Level Info -LogDirectory $LogDirectory
            }
        }
    }
    else {
        Write-HardeningLog -Message "Skipping reset permission delegation (ResetPasswordPrincipals is empty)." -Level Warning -LogDirectory $LogDirectory
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
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    $adDrive = Get-LOCKmeADDrive -Server $Server -Credential $Credential

    # Authenticated Users: well-known SID S-1-5-11 (no domain resolution needed)
    $authenticatedUsersSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-11")

    $domain    = Get-ADDomain @serverParam
    $domainDN  = $domain.DistinguishedName

    # Domain Computers: RID 515, relative to the domain SID
    $domainComputersSid = [System.Security.Principal.SecurityIdentifier]::new("$($domain.DomainSID.Value)-515")

    $containers = @(
        "CN=MicrosoftDNS,DC=DomainDNSZones,$domainDN",
        "CN=MicrosoftDNS,DC=ForestDNSZones,$domainDN"
    )

    foreach ($containerDN in $containers) {
        if (-not (Test-Path "${adDrive}\$containerDN")) {
            Write-HardeningLog -Message "DNS container not found: '$containerDN'. Skipping." -Level Warning -LogDirectory $LogDirectory
            continue
        }

        Write-HardeningLog -Message "Processing container '$containerDN'..." -Level Info -LogDirectory $LogDirectory

        try {
            $zones = Get-ADObject -SearchBase $containerDN `
                                   -Filter { objectClass -eq 'dnsZone' } `
                                   -SearchScope OneLevel `
                                   @serverParam `
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
            $zonePath = "${adDrive}\$($zone.DistinguishedName)"

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

                    Set-Acl -Path $zonePath -AclObject $acl -ErrorAction Stop
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

# ============================================================================
# Task: AddDNSSecurityRecords
# ============================================================================

function Set-HardeningDNSSecurityRecords {
    <#
    .SYNOPSIS
        Adds a WPAD sinkhole A record and a wildcard TXT record to a DNS zone.
    .DESCRIPTION
        WPAD A record: prevents WPAD hijacking by registering a controlled A record
        that sinks WPAD auto-discovery queries before an attacker can answer them.
        Wildcard TXT record: blocks wildcard DNS abuse by pre-registering a * TXT
        entry, preventing arbitrary subdomains from resolving to attacker-controlled
        hosts via wildcard delegation.
        If ZoneName is empty, the domain's primary DNS zone is used automatically.
    .PARAMETER ZoneName
        Target DNS zone (e.g. "contoso.com"). Leave empty to auto-detect.
    .PARAMETER WpadIPAddress
        IPv4 address for the WPAD A record. Default: 0.0.0.0 (sinkhole).
    .PARAMETER WildcardTXTValue
        Text value for the wildcard TXT record. Default: ".".
    .PARAMETER LogDirectory
        Log directory.
    .PARAMETER Server
        DNS server to target. Required when not domain-joined (this task otherwise
        targets the local machine's DNS Server role, which only makes sense when run
        on a DC). Requires WinRM reachable on that server when paired with -Credential.
    .PARAMETER Credential
        Explicit credential to authenticate with. Used to open a remote CIM session
        to -Server (the DnsServer module cmdlets don't accept -Credential directly).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$ZoneName,

        [string]$WpadIPAddress = "0.0.0.0",

        [string]$WildcardTXTValue = ".",

        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }

    # DnsServer cmdlets don't accept -Credential; route through an explicit CIM session instead.
    $dnsCimParam = @{}
    if ($Server -and $Credential) {
        $dnsCimSession = New-LOCKmeADCimSession -ComputerName $Server -Credential $Credential
        if (-not $dnsCimSession) {
            throw "Could not establish a CIM session to '$Server' with the supplied credential — ensure WinRM (5985/5986) is reachable there."
        }
        $dnsCimParam.CimSession = $dnsCimSession
    }
    elseif ($Server) {
        $dnsCimParam.ComputerName = $Server
    }

    if ([string]::IsNullOrWhiteSpace($ZoneName)) {
        $ZoneName = (Get-ADDomain @serverParam).DNSRoot
        Write-HardeningLog -Message "ZoneName not specified — using domain primary zone '$ZoneName'." -Level Info -LogDirectory $LogDirectory
    }

    # Verify the zone exists on the target DNS server
    $zone = Get-DnsServerZone -Name $ZoneName @dnsCimParam -ErrorAction SilentlyContinue
    if (-not $zone) {
        throw "DNS zone '$ZoneName' not found on the target DNS server. Verify the zone name, that the server is authoritative for it, and (when off-domain) that -Server points at a DNS server with WinRM reachable."
    }

    Write-HardeningLog -Message "Applying DNS security records to zone '$ZoneName'..." -Level Info -LogDirectory $LogDirectory

    # --- WPAD A record ---
    $wpadExists = Get-DnsServerResourceRecord -ZoneName $ZoneName -Name "wpad" -RRType A @dnsCimParam -ErrorAction SilentlyContinue
    if ($wpadExists) {
        Write-HardeningLog -Message "WPAD A record already exists in '$ZoneName' — skipped." -Level Warning -LogDirectory $LogDirectory
    }
    elseif ($PSCmdlet.ShouldProcess($ZoneName, "Add WPAD A record -> $WpadIPAddress")) {
        try {
            Add-DnsServerResourceRecord -ZoneName $ZoneName -Name "wpad" -A -IPv4Address $WpadIPAddress @dnsCimParam -ErrorAction Stop
            Write-HardeningLog -Message "WPAD A record added: wpad.$ZoneName -> $WpadIPAddress" -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error adding WPAD A record: $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] WPAD A record would be added: wpad.$ZoneName -> $WpadIPAddress" -Level Info -LogDirectory $LogDirectory
    }

    # --- Wildcard TXT record ---
    $wildcardExists = Get-DnsServerResourceRecord -ZoneName $ZoneName -Name "*" -RRType TXT @dnsCimParam -ErrorAction SilentlyContinue
    if ($wildcardExists) {
        Write-HardeningLog -Message "Wildcard TXT record already exists in '$ZoneName' — skipped." -Level Warning -LogDirectory $LogDirectory
    }
    elseif ($PSCmdlet.ShouldProcess($ZoneName, "Add wildcard TXT record -> '$WildcardTXTValue'")) {
        try {
            Add-DnsServerResourceRecord -ZoneName $ZoneName -Name "*" -Txt -DescriptiveText $WildcardTXTValue @dnsCimParam -ErrorAction Stop
            Write-HardeningLog -Message "Wildcard TXT record added: *.$ZoneName -> '$WildcardTXTValue'" -Level Success -LogDirectory $LogDirectory
        }
        catch {
            Write-HardeningLog -Message "Error adding wildcard TXT record: $_" -Level Error -LogDirectory $LogDirectory
            throw
        }
    }
    else {
        Write-HardeningLog -Message "[WhatIf] Wildcard TXT record would be added: *.$ZoneName -> '$WildcardTXTValue'" -Level Info -LogDirectory $LogDirectory
    }
}

# ============================================================================
# Task: FixDNSRecordOwnership
# ============================================================================

function Test-HasDynamicHostRecord {
    # Returns $true if the dnsRecord attribute contains at least one dynamic
    # A (type 1) or AAAA (type 28) record.
    #
    # DNS_RPC_RECORD binary layout (all fields little-endian):
    #   Offset 0  WORD  DataLength
    #   Offset 2  WORD  Type          (1 = A, 28 = AAAA, ...)
    #   Offset 4  BYTE  Version
    #   Offset 5  BYTE  Rank
    #   Offset 6  WORD  Flags
    #   Offset 8  DWORD Serial
    #   Offset 12 DWORD TtlSeconds
    #   Offset 16 DWORD Reserved
    #   Offset 20 DWORD dwTimeStamp   (0 = static, non-zero = dynamic)
    #   Offset 24 ...   rdata
    param([object[]]$DnsRecordAttr)

    if (-not $DnsRecordAttr) { return $false }

    foreach ($record in $DnsRecordAttr) {
        $bytes = [byte[]]$record
        if ($bytes.Length -lt 24) { continue }

        $type      = [BitConverter]::ToUInt16($bytes, 2)
        $timestamp = [BitConverter]::ToUInt32($bytes, 20)

        if ($type -in @(1, 28) -and $timestamp -ne 0) { return $true }
    }
    return $false
}

function Set-HardeningDNSRecordOwnership {
    <#
    .SYNOPSIS
        Sets the owner of each DNS node in AD-integrated zones to the matching
        domain computer account.
    .DESCRIPTION
        For every dnsNode object whose name matches a domain-joined computer
        (e.g. SRV01 -> SRV01$), this function checks the current AD security
        descriptor owner. If the owner is not the computer account itself, it
        is corrected. Covers both DomainDNSZones and ForestDNSZones partitions.
        Requires SeRestorePrivilege to set ownership to an arbitrary account —
        the function enables it automatically via P/Invoke.
    .PARAMETER LogDirectory
        Log directory.
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    $adDrive = Get-LOCKmeADDrive -Server $Server -Credential $Credential

    # Enable SeRestorePrivilege so we can set the owner of an AD object to an
    # arbitrary account (not just the current user). This is a LOCAL Windows privilege
    # on the process token running the script — granted by default to local
    # Administrators (which #Requires -RunAsAdministrator already guarantees) — and is
    # unrelated to the AD account used for the LDAP operations above, so it applies the
    # same way whether running domain-joined or with an explicit -Credential.
    $privCSrc = @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class LOCKmeAD_Priv {
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string host, string name, ref long luid);
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr hProc, int access, ref IntPtr hTok);
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr hTok, bool disableAll,
        ref TOKEN_PRIVILEGES tp, int bufLen, IntPtr prev, IntPtr relen);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct TOKEN_PRIVILEGES { public int Count; public long Luid; public int Attributes; }

    const int TOKEN_ADJUST_PRIVILEGES = 0x20;
    const int TOKEN_QUERY             = 0x08;
    const int SE_PRIVILEGE_ENABLED    = 0x02;

    public static void Enable(string privilege) {
        IntPtr hTok = IntPtr.Zero;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref hTok)) return;
        var tp = new TOKEN_PRIVILEGES();
        tp.Count = 1; tp.Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue(null, privilege, ref tp.Luid);
        AdjustTokenPrivileges(hTok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
'@
    if (-not ([System.Management.Automation.PSTypeName]'LOCKmeAD_Priv').Type) {
        Add-Type -TypeDefinition $privCSrc -ErrorAction Stop
    }
    [LOCKmeAD_Priv]::Enable("SeRestorePrivilege")

    $domain   = Get-ADDomain @serverParam
    $domainDN = $domain.DistinguishedName

    Write-HardeningLog -Message "Loading domain computers..." -Level Info -LogDirectory $LogDirectory
    $computerMap = @{}
    Get-ADComputer -Filter * -Properties SID @serverParam | ForEach-Object {
        $computerMap[$_.Name.ToUpper()] = $_
    }
    Write-HardeningLog -Message "$($computerMap.Count) domain computer(s) loaded." -Level Info -LogDirectory $LogDirectory

    $stats = @{ Updated = 0; AlreadyCorrect = 0; Skipped = 0; Errors = 0 }

    $zoneContainers = @(
        "CN=MicrosoftDNS,DC=DomainDNSZones,$domainDN"
        "CN=MicrosoftDNS,DC=ForestDNSZones,$domainDN"
    )

    foreach ($containerDN in $zoneContainers) {
        $zones = Get-ADObject -SearchBase $containerDN -SearchScope OneLevel `
                              -Filter { objectClass -eq 'dnsZone' } `
                              @serverParam `
                              -ErrorAction SilentlyContinue
        if (-not $zones) { continue }

        foreach ($zone in $zones) {
            # Skip infrastructure zones (_msdcs, _sites, _tcp, _udp, etc.)
            if ($zone.Name -match '^_') { continue }

            Write-HardeningLog -Message "Processing zone '$($zone.Name)'..." -Level Info -LogDirectory $LogDirectory

            $nodes = Get-ADObject -SearchBase $zone.DistinguishedName -SearchScope OneLevel `
                                  -Filter { objectClass -eq 'dnsNode' } `
                                  -Properties dnsRecord `
                                  @serverParam `
                                  -ErrorAction SilentlyContinue
            if (-not $nodes) { continue }

            foreach ($node in $nodes) {
                $nodeName = $node.Name

                # Skip zone apex, wildcards and SRV/infrastructure subzones
                if ($nodeName -in @('@', '*') -or $nodeName -match '^_') {
                    $stats.Skipped++
                    continue
                }

                $computer = $computerMap[$nodeName.ToUpper()]
                if (-not $computer) {
                    $stats.Skipped++
                    continue
                }

                # Only process nodes that have at least one dynamic A or AAAA record
                # (dwTimeStamp != 0 in the dnsRecord binary attribute)
                if (-not (Test-HasDynamicHostRecord -DnsRecordAttr $node.dnsRecord)) {
                    $stats.Skipped++
                    continue
                }

                try {
                    $aclPath = "${adDrive}\$($node.DistinguishedName)"
                    $acl     = Get-Acl -Path $aclPath -ErrorAction Stop

                    $currentOwnerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
                    $expectedSid     = [System.Security.Principal.SecurityIdentifier]::new($computer.SID.Value)

                    if ($currentOwnerSid.Value -eq $expectedSid.Value) {
                        $stats.AlreadyCorrect++
                        continue
                    }

                    $currentOwnerDisplay = try { $acl.Owner } catch { $currentOwnerSid.Value }

                    if ($PSCmdlet.ShouldProcess($node.DistinguishedName,
                            "Set owner '$currentOwnerDisplay' -> '$nodeName`$'")) {
                        $acl.SetOwner($expectedSid)
                        Set-Acl -Path $aclPath -AclObject $acl -ErrorAction Stop
                        Write-HardeningLog -Message "  $nodeName ($($zone.Name)): owner set to '$nodeName`$' (was '$currentOwnerDisplay')" `
                            -Level Success -LogDirectory $LogDirectory
                        $stats.Updated++
                    }
                    else {
                        Write-HardeningLog -Message "  [WhatIf] $nodeName ($($zone.Name)): owner '$currentOwnerDisplay' -> '$nodeName`$'" `
                            -Level Info -LogDirectory $LogDirectory
                    }
                }
                catch {
                    Write-HardeningLog -Message "  Error on '$nodeName' ($($zone.Name)): $_" -Level Error -LogDirectory $LogDirectory
                    $stats.Errors++
                }
            }
        }
    }

    $level = if ($stats.Errors -gt 0) { 'Warning' } else { 'Success' }
    Write-HardeningLog -Message "DNS ownership: $($stats.Updated) updated, $($stats.AlreadyCorrect) already correct, $($stats.Skipped) no match, $($stats.Errors) error(s)." `
        -Level $level -LogDirectory $LogDirectory
}

# ============================================================================
# Task: ResetADObjectOwnership
# ============================================================================

function Set-HardeningADObjectOwnership {
    <#
    .SYNOPSIS
        Resets the owner of all user and computer objects in AD to Domain Admins.
    .DESCRIPTION
        Enumerates every user and computer object in the domain and sets its AD
        security descriptor owner to the Domain Admins group. Objects already
        owned by Domain Admins are skipped. Requires SeRestorePrivilege, which
        is enabled automatically via P/Invoke.
    .PARAMETER LogDirectory
        Log directory.
    .PARAMETER Server
        Target DC for all AD operations. Required when not domain-joined.
    .PARAMETER Credential
        Explicit credential to authenticate with. Required when not domain-joined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogDirectory,
        [string]$Server,
        [PSCredential]$Credential
    )

    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    $adDrive = Get-LOCKmeADDrive -Server $Server -Credential $Credential

    $privCSrc = @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class LOCKmeAD_Priv {
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string host, string name, ref long luid);
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr hProc, int access, ref IntPtr hTok);
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr hTok, bool disableAll,
        ref TOKEN_PRIVILEGES tp, int bufLen, IntPtr prev, IntPtr relen);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct TOKEN_PRIVILEGES { public int Count; public long Luid; public int Attributes; }

    const int TOKEN_ADJUST_PRIVILEGES = 0x20;
    const int TOKEN_QUERY             = 0x08;
    const int SE_PRIVILEGE_ENABLED    = 0x02;

    public static void Enable(string privilege) {
        IntPtr hTok = IntPtr.Zero;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref hTok)) return;
        var tp = new TOKEN_PRIVILEGES();
        tp.Count = 1; tp.Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue(null, privilege, ref tp.Luid);
        AdjustTokenPrivileges(hTok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
'@
    if (-not ([System.Management.Automation.PSTypeName]'LOCKmeAD_Priv').Type) {
        Add-Type -TypeDefinition $privCSrc -ErrorAction Stop
    }
    [LOCKmeAD_Priv]::Enable("SeRestorePrivilege")

    $domainAdminsGroup = Get-ADGroup "Domain Admins" @serverParam
    $domainAdminsSid   = [System.Security.Principal.SecurityIdentifier]::new($domainAdminsGroup.SID.Value)
    # SID.Translate(NTAccount) resolves via the local machine's LSA lookup, which requires
    # domain join/trust and fails off-domain ("could not be translated"). Build the name
    # from the AD query results instead, which we already have.
    $domainNetBIOS     = (Get-ADDomain @serverParam).NetBIOSName
    $domainAdminsName  = "$domainNetBIOS\$($domainAdminsGroup.SamAccountName)"

    Write-HardeningLog -Message "Target owner: '$domainAdminsName' ($($domainAdminsSid.Value))" -Level Info -LogDirectory $LogDirectory

    Write-HardeningLog -Message "Loading user and computer objects..." -Level Info -LogDirectory $LogDirectory
    $objects  = @(Get-ADUser     -Filter * @serverParam)
    $objects += @(Get-ADComputer -Filter * @serverParam)
    Write-HardeningLog -Message "$($objects.Count) object(s) to process." -Level Info -LogDirectory $LogDirectory

    $stats = @{ Updated = 0; AlreadyCorrect = 0; Errors = 0 }

    foreach ($obj in $objects) {
        try {
            $aclPath = "${adDrive}\$($obj.DistinguishedName)"
            $acl     = Get-Acl -Path $aclPath -ErrorAction Stop

            $currentOwnerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])

            if ($currentOwnerSid.Value -eq $domainAdminsSid.Value) {
                $stats.AlreadyCorrect++
                continue
            }

            $currentOwnerDisplay = try { $acl.Owner } catch { $currentOwnerSid.Value }

            if ($PSCmdlet.ShouldProcess($obj.DistinguishedName,
                    "Set owner '$currentOwnerDisplay' -> '$domainAdminsName'")) {
                $acl.SetOwner($domainAdminsSid)
                Set-Acl -Path $aclPath -AclObject $acl -ErrorAction Stop
                Write-HardeningLog -Message "  $($obj.SamAccountName): owner -> '$domainAdminsName' (was '$currentOwnerDisplay')" `
                    -Level Success -LogDirectory $LogDirectory
                $stats.Updated++
            }
            else {
                Write-HardeningLog -Message "  [WhatIf] $($obj.SamAccountName): owner '$currentOwnerDisplay' -> '$domainAdminsName'" `
                    -Level Info -LogDirectory $LogDirectory
            }
        }
        catch {
            Write-HardeningLog -Message "  Error on '$($obj.SamAccountName)' ($($obj.DistinguishedName)): $_" -Level Error -LogDirectory $LogDirectory
            $stats.Errors++
        }
    }

    $level = if ($stats.Errors -gt 0) { 'Warning' } else { 'Success' }
    Write-HardeningLog -Message "AD object ownership: $($stats.Updated) updated, $($stats.AlreadyCorrect) already correct, $($stats.Errors) error(s)." `
        -Level $level -LogDirectory $LogDirectory
}

# ============================================================================
# Hardening verification functions
# ============================================================================

function New-HardeningCheckResult {
    param([string]$Status, [string]$Message = '')
    [PSCustomObject]@{ Status = $Status; Message = $Message }
}

function Test-HardeningTask {
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [object]$TaskParameters,
        [string]$Server,
        [PSCredential]$Credential
    )
    switch ($TaskName) {
        'SetMachineAccountQuota'     { Test-HardeningMachineAccountQuota -Server $Server -Credential $Credential }
        'RaiseDomainFunctionalLevel' { Test-HardeningDomainFunctionalLevel -Server $Server -Credential $Credential }
        'RaiseForestFunctionalLevel' { Test-HardeningForestFunctionalLevel -Server $Server -Credential $Credential }
        'EnableRecycleBin'           { Test-HardeningRecycleBin -Server $Server -Credential $Credential }
        'EnablePAMFeature'           { Test-HardeningPAMFeature -Server $Server -Credential $Credential }
        'DisableAnonymousAccess'     { Test-HardeningAnonymousAccess -Server $Server -Credential $Credential }
        'DeployT0AuthPolicy'         { Test-HardeningT0AuthPolicy -Server $Server -Credential $Credential }
        'EnableReplicationNotify'    { Test-HardeningReplicationNotify -Server $Server -Credential $Credential }
        'ConfigureCentralStore'      { Test-HardeningCentralStore -Server $Server -Credential $Credential }
        'ExtendLAPSSchema'           { Test-HardeningLAPSSchema -Server $Server -Credential $Credential }
        'ConfigureLAPSADPermissions' {
            Test-HardeningLAPSADPermissions `
                -SelfPermissionOUs      @($TaskParameters.SelfPermissionOUs) `
                -ReadPasswordOUs        @($TaskParameters.ReadPasswordOUs) `
                -ReadPasswordPrincipals @($TaskParameters.ReadPasswordPrincipals) `
                -ResetPasswordOUs       @($TaskParameters.ResetPasswordOUs) `
                -ResetPasswordPrincipals @($TaskParameters.ResetPasswordPrincipals) `
                -Server $Server -Credential $Credential
        }
        'RestrictDNSDynamicUpdate'   { Test-HardeningDNSDynamicUpdate -Server $Server -Credential $Credential }
        'AddDNSSecurityRecords'      {
            Test-HardeningDNSSecurityRecords `
                -ZoneName         $TaskParameters.ZoneName `
                -WpadIPAddress    $TaskParameters.WpadIPAddress `
                -WildcardTXTValue $TaskParameters.WildcardTXTValue `
                -Server $Server -Credential $Credential
        }
        'FixDNSRecordOwnership'      { Test-HardeningDNSRecordOwnership -Server $Server -Credential $Credential }
        'ResetADObjectOwnership'     { Test-HardeningADObjectOwnership -Server $Server -Credential $Credential }
        default { New-HardeningCheckResult -Status 'Error' -Message "Unknown task: $TaskName" }
    }
}

function Test-HardeningMachineAccountQuota {
    param([string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    try {
        $domain = Get-ADDomain @serverParam
        $quota = (Get-ADObject $domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' @serverParam).'ms-DS-MachineAccountQuota'
        if ($quota -eq 0) {
            New-HardeningCheckResult -Status 'OK' -Message "ms-DS-MachineAccountQuota = 0"
        } else {
            New-HardeningCheckResult -Status 'NotOK' -Message "ms-DS-MachineAccountQuota = $quota (expected 0)"
        }
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningDomainFunctionalLevel {
    param([string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    try {
        $current = (Get-ADDomain @serverParam).DomainMode.ToString()
        New-HardeningCheckResult -Status 'Info' -Message "Domain functional level: $current"
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningForestFunctionalLevel {
    param([string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    try {
        $current = (Get-ADForest @serverParam).ForestMode.ToString()
        New-HardeningCheckResult -Status 'Info' -Message "Forest functional level: $current"
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningRecycleBin {
    param([string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    try {
        $feature = Get-ADOptionalFeature -Filter { Name -eq 'Recycle Bin Feature' } @serverParam
        if ($feature -and $feature.EnabledScopes.Count -gt 0) {
            New-HardeningCheckResult -Status 'OK' -Message "Recycle Bin is enabled"
        } else {
            New-HardeningCheckResult -Status 'NotOK' -Message "Recycle Bin is not enabled"
        }
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningPAMFeature {
    param([string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    try {
        $feature = Get-ADOptionalFeature -Filter { Name -eq 'Privileged Access Management Feature' } @serverParam
        if ($feature -and $feature.EnabledScopes.Count -gt 0) {
            New-HardeningCheckResult -Status 'OK' -Message "PAM feature is enabled"
        } else {
            New-HardeningCheckResult -Status 'NotOK' -Message "PAM feature is not enabled"
        }
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningAnonymousAccess {
    param([string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    try {
        # Resolved by well-known SID and read from the raw 'member' attribute, for the same two
        # reasons as Disable-HardeningAnonymousAccess -- see the comments there. Matching the
        # LSA-resolved display name was doubly fragile: it is localized on a non-English DC, and
        # Get-ADGroupMember is the very cmdlet that mangles foreign security principals. Both
        # halves of the task go through the same member resolver so they cannot disagree about
        # whether it is applied.
        $group   = Get-ADGroup -Identity "S-1-5-32-554" -Properties member @serverParam -ErrorAction Stop
        $hasAnon = @(Get-HardeningAnonymousLogonMemberDN -Group $group -ConnParam $serverParam).Count -gt 0
        if (-not $hasAnon) {
            New-HardeningCheckResult -Status 'OK' -Message "ANONYMOUS LOGON not in '$($group.Name)'"
        } else {
            New-HardeningCheckResult -Status 'NotOK' -Message "ANONYMOUS LOGON is still a member of '$($group.Name)'"
        }
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningT0AuthPolicy {
    param([string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    try {
        $t0Pattern = 'T[-_]?0|Tier[-_]?0'
        $allSilos = @(Get-ADAuthenticationPolicySilo -Filter * @serverParam -ErrorAction SilentlyContinue)
        $t0Silos  = @($allSilos | Where-Object { $_.Name -match $t0Pattern })
        if ($t0Silos.Count -gt 0) {
            $names = $t0Silos.Name -join ', '
            New-HardeningCheckResult -Status 'Info' -Message "Tier 0 silo(s) found: $names"
        } else {
            New-HardeningCheckResult -Status 'NotOK' -Message "No authentication policy silo matching T0/Tier0 found"
        }
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningReplicationNotify {
    param([string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    try {
        $configNC = (Get-ADRootDSE @serverParam).configurationNamingContext
        $siteLinks = @(Get-ADObject -Filter { objectClass -eq 'siteLink' } -SearchBase "CN=Sites,$configNC" -Properties Options @serverParam)
        if ($siteLinks.Count -eq 0) {
            return New-HardeningCheckResult -Status 'OK' -Message "No site links found"
        }
        $missing = @($siteLinks | Where-Object { ($_.Options -band 1) -eq 0 })
        if ($missing.Count -eq 0) {
            New-HardeningCheckResult -Status 'OK' -Message "USE_NOTIFY enabled on all $($siteLinks.Count) site link(s)"
        } elseif ($missing.Count -lt $siteLinks.Count) {
            New-HardeningCheckResult -Status 'Partial' -Message "$($missing.Count)/$($siteLinks.Count) site link(s) missing USE_NOTIFY"
        } else {
            New-HardeningCheckResult -Status 'NotOK' -Message "USE_NOTIFY not enabled on any site link"
        }
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningCentralStore {
    param([string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    try {
        $domain = Get-ADDomain @serverParam
        $sysvolRoot = Get-LOCKmeADSysvolDrive -DomainDNSRoot $domain.DNSRoot -Credential $Credential
        $sysvol = "$sysvolRoot\$($domain.DNSRoot)\Policies\PolicyDefinitions"
        if (Test-Path $sysvol) {
            New-HardeningCheckResult -Status 'OK' -Message "Central Store exists"
        } else {
            New-HardeningCheckResult -Status 'NotOK' -Message "Central Store not found at $sysvol"
        }
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningLAPSSchema {
    param([string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    try {
        $schema = (Get-ADRootDSE @serverParam).schemaNamingContext

        # Attributes added by Update-LapsADSchema per MS official documentation
        # (msLAPS-CurrentPasswordVersion is WS2025+ only and excluded from this check)
        $expected = @(
            'msLAPS-Password',
            'msLAPS-PasswordExpirationTime',
            'msLAPS-EncryptedPassword',
            'msLAPS-EncryptedPasswordHistory',
            'msLAPS-EncryptedDSRMPassword',
            'msLAPS-EncryptedDSRMPasswordHistory'
        )

        $missing = @()
        foreach ($attr in $expected) {
            $obj = Get-ADObject -LDAPFilter "(lDAPDisplayName=$attr)" -SearchBase $schema @serverParam -ErrorAction SilentlyContinue
            if (-not $obj) { $missing += $attr }
        }

        if ($missing.Count -eq 0) {
            New-HardeningCheckResult -Status 'OK' -Message "All $($expected.Count) Windows LAPS schema attributes present"
        } elseif ($missing.Count -lt $expected.Count) {
            New-HardeningCheckResult -Status 'Partial' -Message "Missing schema attribute(s): $($missing -join ', ')"
        } else {
            New-HardeningCheckResult -Status 'NotOK' -Message "Windows LAPS schema not extended — no msLAPS-* attributes found"
        }
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningLAPSADPermissions {
    param(
        [string[]]$SelfPermissionOUs,
        [string[]]$ReadPasswordOUs,
        [string[]]$ReadPasswordPrincipals,
        [string[]]$ResetPasswordOUs,
        [string[]]$ResetPasswordPrincipals,
        [string]$Server,
        [PSCredential]$Credential
    )
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    try {
        $domain   = Get-ADDomain @serverParam
        $allOUDNs = @(Get-ADOrganizationalUnit -Filter * @serverParam -ErrorAction Stop | Select-Object -ExpandProperty DistinguishedName)
        $defaultContainers = @($domain.ComputersContainer, $domain.UsersContainer) | Where-Object { $_ }
        $allTargets = ($allOUDNs + $defaultContainers) | Sort-Object -Unique

        $lines = @()
        foreach ($dn in $allTargets) {
            try {
                $rights = Invoke-HardeningLapsCommand -Command 'Find-LapsADExtendedRights' `
                                                      -Parameters @{ Identity = $dn; ErrorAction = 'Stop' } `
                                                      -Server $Server -Credential $Credential
                $delegated = @($rights.ExtendedRightHolders | Where-Object { $_ -notmatch '^NT AUTHORITY\\' })
                if ($delegated.Count -gt 0) {
                    $lines += "$dn`n  $($delegated -join ', ')"
                }
            } catch { continue }
        }

        $msg = if ($lines.Count -gt 0) { $lines -join "`n`n" } else { "No LAPS extended rights delegated to any principal" }
        New-HardeningCheckResult -Status 'Info' -Message $msg
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningDNSDynamicUpdate {
    param([string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    $adDrive = Get-LOCKmeADDrive -Server $Server -Credential $Credential
    try {
        $domainDN    = (Get-ADDomain @serverParam).DistinguishedName
        # Both application partitions, to match what Set-HardeningDNSDynamicUpdate actually
        # modifies. Checking DomainDnsZones alone silently ignored every forest-wide zone --
        # _msdcs.<domain> lives in ForestDnsZones -- so the task could report "OK" having never
        # looked at a zone it had just re-ACLed.
        $zones = @()
        foreach ($partition in 'DomainDnsZones', 'ForestDnsZones') {
            $zones += @(Get-ADObject -Filter { objectClass -eq 'dnsZone' } `
                -SearchBase "CN=MicrosoftDNS,DC=$partition,$domainDN" -SearchScope OneLevel `
                @serverParam -ErrorAction SilentlyContinue)
        }

        if ($zones.Count -eq 0) {
            return New-HardeningCheckResult -Status 'Error' -Message "No AD-integrated DNS zones found"
        }

        $zoneWithAuthUsers = @()
        foreach ($zone in $zones) {
            $acl = Get-Acl -Path "${adDrive}\$($zone.DistinguishedName)" -ErrorAction SilentlyContinue
            if ($acl) {
                $bad = $acl.Access | Where-Object {
                    $_.IdentityReference -match 'Authenticated Users' -and
                    $_.ActiveDirectoryRights -match 'CreateChild'
                }
                if ($bad) { $zoneWithAuthUsers += $zone.Name }
            }
        }

        if ($zoneWithAuthUsers.Count -eq 0) {
            New-HardeningCheckResult -Status 'OK' -Message "Authenticated Users has no CreateChild on $($zones.Count) DNS zone(s)"
        } else {
            New-HardeningCheckResult -Status 'NotOK' -Message "Authenticated Users still has CreateChild on: $($zoneWithAuthUsers -join ', ')"
        }
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningDNSSecurityRecords {
    param([string]$ZoneName, [string]$WpadIPAddress, [string]$WildcardTXTValue, [string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    try {
        $domainDN = (Get-ADDomain @serverParam).DistinguishedName

        if ([string]::IsNullOrWhiteSpace($ZoneName)) {
            $ZoneName = (Get-ADDomain @serverParam).DNSRoot
        }

        # Locate the zone — wrap each partition separately so an inaccessible
        # partition doesn't abort the whole check with a terminating error
        $zoneDN = $null
        foreach ($container in @("CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN", "CN=MicrosoftDNS,DC=ForestDnsZones,$domainDN")) {
            try {
                $zoneObj = Get-ADObject -Filter "objectClass -eq 'dnsZone' -and Name -eq '$ZoneName'" `
                    -SearchBase $container -SearchScope OneLevel @serverParam -ErrorAction Stop
                if ($zoneObj) { $zoneDN = $zoneObj.DistinguishedName; break }
            } catch { continue }
        }

        if (-not $zoneDN) {
            return New-HardeningCheckResult -Status 'Error' -Message "Zone '$ZoneName' not found in AD"
        }

        # Fetch all dnsNode children and filter client-side — avoids LDAP escaping
        # issues with '*' and does not require the DnsServer module
        $allNodes     = @(Get-ADObject -Filter { objectClass -eq 'dnsNode' } `
            -SearchBase $zoneDN -SearchScope OneLevel @serverParam -ErrorAction SilentlyContinue)
        $wpadNode     = $allNodes | Where-Object { $_.Name -eq 'wpad' }
        $wildcardNode = $allNodes | Where-Object { $_.Name -eq '*' }

        if ($wpadNode -and $wildcardNode) {
            New-HardeningCheckResult -Status 'OK' -Message "WPAD A record and wildcard TXT record exist in $ZoneName"
        } elseif ($wpadNode -or $wildcardNode) {
            New-HardeningCheckResult -Status 'Partial' -Message "WPAD: $([bool][object]$wpadNode), Wildcard TXT: $([bool][object]$wildcardNode)"
        } else {
            New-HardeningCheckResult -Status 'NotOK' -Message "Neither WPAD nor wildcard TXT record found in $ZoneName"
        }
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningDNSRecordOwnership {
    param([string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    $adDrive = Get-LOCKmeADDrive -Server $Server -Credential $Credential
    try {
        $domain   = Get-ADDomain @serverParam
        $domainDN = $domain.DistinguishedName

        # Build computer map: lowercase name -> ADComputer object (with SID)
        $computerMap = @{}
        Get-ADComputer -Filter * -Properties SID @serverParam -ErrorAction SilentlyContinue | ForEach-Object {
            $computerMap[$_.Name.ToLower()] = $_
        }

        $zoneContainers = @(
            "CN=MicrosoftDNS,DC=DomainDNSZones,$domainDN"
            "CN=MicrosoftDNS,DC=ForestDNSZones,$domainDN"
        )

        $relevant = 0; $wrong = 0

        foreach ($container in $zoneContainers) {
            # Wrap per-partition so an inaccessible partition doesn't abort the whole check
            $zones = $null
            try {
                $zones = @(Get-ADObject -Filter { objectClass -eq 'dnsZone' } -SearchBase $container `
                    -SearchScope OneLevel @serverParam -ErrorAction Stop)
            } catch { continue }

            foreach ($zone in $zones) {
                if ($zone.Name -match '^_') { continue }

                $nodes = @(Get-ADObject -Filter { objectClass -eq 'dnsNode' } `
                    -SearchBase $zone.DistinguishedName -SearchScope OneLevel `
                    -Properties dnsRecord @serverParam -ErrorAction SilentlyContinue)

                foreach ($node in $nodes) {
                    if ($node.Name -in @('@', '*') -or $node.Name -match '^_') { continue }

                    $computer = $computerMap[$node.Name.ToLower()]
                    if (-not $computer) { continue }

                    if (-not (Test-HasDynamicHostRecord -DnsRecordAttr $node.dnsRecord)) { continue }

                    $relevant++

                    # Matches the path format used by the hardening action; without the
                    # backslash Get-Acl may fail on application-partition DNs
                    $acl = Get-Acl -Path "${adDrive}\$($node.DistinguishedName)" -ErrorAction SilentlyContinue
                    if ($acl) {
                        try {
                            $currentSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
                            if ($currentSid.Value -ne $computer.SID.Value) { $wrong++ }
                        } catch { $wrong++ }
                    }
                }
            }
        }

        if ($relevant -eq 0) {
            New-HardeningCheckResult -Status 'OK' -Message "No dynamic DNS nodes with a matching computer account found"
        } elseif ($wrong -eq 0) {
            New-HardeningCheckResult -Status 'OK' -Message "All $relevant dynamic DNS node(s) owned by their matching computer account"
        } else {
            New-HardeningCheckResult -Status 'NotOK' -Message "$wrong/$relevant dynamic DNS node(s) not owned by their matching computer account"
        }
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

function Test-HardeningADObjectOwnership {
    param([string]$Server, [PSCredential]$Credential)
    $serverParam = @{}
    if ($Server)     { $serverParam.Server     = $Server }
    if ($Credential) { $serverParam.Credential = $Credential }
    $adDrive = Get-LOCKmeADDrive -Server $Server -Credential $Credential
    try {
        $objects = @(Get-ADObject -Filter { objectClass -eq 'user' -or objectClass -eq 'computer' } `
            @serverParam -ErrorAction SilentlyContinue)

        if ($objects.Count -eq 0) {
            return New-HardeningCheckResult -Status 'Error' -Message "No user/computer objects found"
        }

        # Compare owners by SID, exactly like Set-HardeningADObjectOwnership does.
        #
        # This used to test the display string ($acl.Owner -notmatch 'Domain Admins'), which only
        # works where the local LSA can resolve a domain SID to a name. Run from a host that is
        # not domain-joined -- the very scenario -Credential exists for -- .Owner comes back as
        # the raw "O:S-1-5-21-...-512" SDDL form, matched nothing, and the check reported every
        # single object as wrongly owned while the deployment task correctly reported them all as
        # already correct. Resolving the group once and comparing SID values removes the
        # dependency on name resolution entirely, and is immune to a localized group name.
        $domainAdminsSid = (Get-ADGroup -Identity "$((Get-ADDomain @serverParam).DomainSID.Value)-512" @serverParam).SID.Value

        $wrong = 0
        foreach ($obj in $objects) {
            # Drive-qualified with the separator, like every other Get-Acl call in this module.
            $acl = Get-Acl -Path "${adDrive}\$($obj.DistinguishedName)" -ErrorAction SilentlyContinue
            if (-not $acl) { continue }
            $ownerSid = try { $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { $null }
            if ($ownerSid -ne $domainAdminsSid) { $wrong++ }
        }

        if ($wrong -eq 0) {
            New-HardeningCheckResult -Status 'OK' -Message "All $($objects.Count) user/computer objects owned by Domain Admins"
        } else {
            New-HardeningCheckResult -Status 'NotOK' -Message "$wrong/$($objects.Count) objects not owned by Domain Admins"
        }
    } catch { New-HardeningCheckResult -Status 'Error' -Message $_.Exception.Message }
}

# Export module functions
Export-ModuleMember -Function @(
    'Write-HardeningLog',
    'Import-HardeningConfiguration',
    'Get-HardeningEnvironmentInfo',
    'Test-HardeningDomainFunctionalLevelPrerequisites',
    'Test-HardeningForestFunctionalLevelPrerequisites',
    'Set-HardeningMachineAccountQuota',
    'Set-HardeningDomainFunctionalLevel',
    'Set-HardeningForestFunctionalLevel',
    'Enable-HardeningRecycleBin',
    'Enable-HardeningPAMFeature',
    'Disable-HardeningAnonymousAccess',
    'New-HardeningT0AuthPolicy',
    'Set-HardeningReplicationNotify',
    'Set-HardeningCentralStore',
    'Update-HardeningLAPSSchema',
    'Set-HardeningLAPSADPermissions',
    'Set-HardeningDNSDynamicUpdate',
    'Set-HardeningDNSSecurityRecords',
    'Set-HardeningDNSRecordOwnership',
    'Set-HardeningADObjectOwnership',
    'New-HardeningCheckResult',
    'Test-HardeningTask'
)
