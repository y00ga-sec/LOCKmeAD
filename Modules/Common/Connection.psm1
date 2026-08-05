#Requires -Version 7.0

# ============================================================================
# Common Connection Module - Resolves how LOCKmeAD authenticates to AD
# ============================================================================
#
# LOCKmeAD normally runs on a domain-joined host as an already-authenticated
# domain user (implicit Kerberos SSO). This module lets it also run from a
# non-domain-joined host by falling back to an explicit target DC + PSCredential,
# using the same -Server/-Credential parameters the ActiveDirectory and
# GroupPolicy PowerShell modules' cmdlets (and the ActiveDirectory PSProvider)
# already support natively for an explicit authenticated bind.

function Test-LOCKmeADDomainJoined {
    <#
    .SYNOPSIS
        Returns $true if a domain controller can be located and reached without
        any explicit credentials (domain-joined, or otherwise able to authenticate
        implicitly), $false otherwise.
    #>
    [CmdletBinding()]
    param()

    try {
        $ctx = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('Domain')
        [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne(
            $ctx,
            [System.DirectoryServices.ActiveDirectory.LocatorOptions]'ForceRediscovery, WriteableRequired'
        ) | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Get-LOCKmeADConnectionProfilePath {
    [CmdletBinding()]
    param()
    return Join-Path $env:LOCALAPPDATA "LOCKmeAD\connection.xml"
}

function Save-LOCKmeADConnection {
    <#
    .SYNOPSIS
        Persists a resolved connection for reuse on the next run.
    .DESCRIPTION
        Serializes via Export-Clixml, which DPAPI-protects SecureString/PSCredential
        content under the current Windows user profile — the same current-user-scoped
        protection as any other locally-persisted Windows credential. Nothing is
        ever written in plaintext.
    .PARAMETER Connection
        Object with Server and Credential, as returned by Resolve-LOCKmeADConnection.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Connection
    )

    $profilePath = Get-LOCKmeADConnectionProfilePath
    $profileDir  = Split-Path $profilePath -Parent
    if (-not (Test-Path $profileDir)) {
        New-Item -Path $profileDir -ItemType Directory -Force | Out-Null
    }
    $Connection | Export-Clixml -Path $profilePath -Force
}

function Remove-LOCKmeADConnection {
    <#
    .SYNOPSIS
        Deletes any persisted connection profile.
    #>
    [CmdletBinding()]
    param()

    $profilePath = Get-LOCKmeADConnectionProfilePath
    if (Test-Path $profilePath) {
        Remove-Item $profilePath -Force
    }
}

function Resolve-LOCKmeADConnection {
    <#
    .SYNOPSIS
        Resolves the AD connection to use for this run: implicit (domain-joined)
        or explicit (Server + Credential), prompting interactively if needed.
    .DESCRIPTION
        Resolution order:
          1. Explicit -Server/-Credential passed by the caller always win.
          2. A previously saved connection profile (see -Remember), if present.
          3. Auto-detect: if a domain controller can be silently located, use
             implicit mode (Server/Credential both $null — every downstream
             cmdlet call falls back to normal domain-joined behavior).
          4. Otherwise, the host is not domain-joined: prompt for a target
             server and Get-Credential prompts for domain credentials. A
             plaintext password is never accepted as a parameter.
    .PARAMETER Server
        Explicit target domain controller (hostname or IP).
    .PARAMETER Credential
        Explicit PSCredential to authenticate with.
    .PARAMETER Remember
        Persists the resolved connection (DPAPI-protected, current Windows user
        only) for reuse on the next run.
    .PARAMETER Forget
        Deletes any persisted connection profile and returns an implicit
        connection instead of resolving one.
    .OUTPUTS
        PSCustomObject with Server (string or $null) and Credential (PSCredential or $null).
    #>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential,
        [switch]$Remember,
        [switch]$Forget
    )

    if ($Forget) {
        Remove-LOCKmeADConnection
        return [PSCustomObject]@{ Server = $null; Credential = $null }
    }

    # Explicit parameters always win
    if ($Server -or $Credential) {
        if (-not $Credential) {
            $Credential = Get-Credential -Message "Domain credentials for $Server"
        }
        $conn = [PSCustomObject]@{ Server = $Server; Credential = $Credential }
        if ($Remember) { Save-LOCKmeADConnection -Connection $conn }
        return $conn
    }

    # A previously saved profile, if any
    $profilePath = Get-LOCKmeADConnectionProfilePath
    if (Test-Path $profilePath) {
        try {
            $saved = Import-Clixml -Path $profilePath
            if ($saved.Server -and $saved.Credential) {
                return [PSCustomObject]@{ Server = $saved.Server; Credential = $saved.Credential }
            }
        }
        catch { }
    }

    # Auto-detect: domain-joined / a DC silently reachable -> implicit mode
    if (Test-LOCKmeADDomainJoined) {
        return [PSCustomObject]@{ Server = $null; Credential = $null }
    }

    # Not joined and nothing supplied: require an explicit connection
    Write-Host ""
    Write-Host "This host is not domain-joined (or no domain controller could be located automatically)." -ForegroundColor Yellow
    Write-Host "Provide a target domain controller and domain credentials to continue." -ForegroundColor Yellow
    Write-Host ""
    $Server = Read-Host "Domain controller (hostname or IP)"
    if ([string]::IsNullOrWhiteSpace($Server)) {
        throw "A target domain controller is required when the host is not domain-joined. Re-run with -Server and -Credential."
    }
    $Credential = Get-Credential -Message "Domain credentials for $Server"

    $conn = [PSCustomObject]@{ Server = $Server; Credential = $Credential }
    if ($Remember) { Save-LOCKmeADConnection -Connection $conn }
    return $conn
}

function New-LOCKmeADConnectionParam {
    <#
    .SYNOPSIS
        Builds a splat hashtable ({Server; Credential}) from a resolved connection,
        omitting keys that are null so cmdlets fall back to implicit auth.
    .PARAMETER Connection
        Object with Server and Credential, as returned by Resolve-LOCKmeADConnection.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject]$Connection
    )

    $connParam = @{}
    if ($Connection -and $Connection.Server)     { $connParam.Server     = $Connection.Server }
    if ($Connection -and $Connection.Credential) { $connParam.Credential = $Connection.Credential }
    return $connParam
}

function Get-LOCKmeADSysvolDrive {
    <#
    .SYNOPSIS
        Authenticates access to the target domain's SYSVOL share with explicit
        credentials when running off-domain, and returns the plain UNC path to it.
    .DESCRIPTION
        When a credential is supplied, mounts a PSDrive against the SYSVOL UNC path
        purely for its side effect: the FileSystem provider's -Credential handling
        establishes a real authenticated SMB session for that UNC path (the same
        mechanism as `net use`), not just a PowerShell-internal abstraction. The
        function then returns the plain "\\domain\SYSVOL" UNC string rather than the
        PSDrive name ("LOCKmeADSysvol:") -- deliberately, because raw .NET file I/O
        ([System.IO.File]::WriteAllText/ReadAllLines, used by the GptTmpl.inf/
        psscripts.ini writers) has no knowledge of PowerShell PSDrives and fails with
        "the filename, directory name, or volume label syntax is incorrect" if given
        one; only PowerShell's own provider cmdlets (Copy-Item, Set-Content,
        Test-Path) understand that syntax. The plain UNC path works for both once the
        SMB session above has authenticated it, so every caller can use one form.
    .PARAMETER DomainDNSRoot
        DNS name of the domain whose SYSVOL share is being accessed (e.g. forest.lol).
    .PARAMETER Credential
        Explicit PSCredential. When $null, returns the plain \\<domain>\SYSVOL UNC
        path unchanged (implicit/domain-joined behavior, no drive mapping needed).
    .OUTPUTS
        String: the SYSVOL root path (always a plain UNC path) to build further paths from.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDNSRoot,

        [PSCredential]$Credential
    )

    $sysvolUNC = "\\$DomainDNSRoot\SYSVOL"

    if (-not $Credential) {
        return $sysvolUNC
    }

    $driveName = "LOCKmeADSysvol"
    $existing = Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-PSDrive -Name $driveName -PSProvider FileSystem -Root $sysvolUNC -Credential $Credential -Scope Global | Out-Null
    }
    return $sysvolUNC
}

function Get-LOCKmeADDrive {
    <#
    .SYNOPSIS
        Returns the AD: path prefix to use for Get-Acl/Set-Acl calls against the
        ActiveDirectory PSProvider. In implicit mode this is the default "AD:"
        drive. When running off-domain with explicit credentials, mounts (once)
        and returns a dedicated drive bound to the target server/credential,
        since the default "AD:" drive is only bound correctly on a domain-joined
        host.
    .PARAMETER Server
        Explicit target domain controller. When $null, returns "AD:" unchanged.
    .PARAMETER Credential
        Explicit PSCredential paired with -Server.
    .OUTPUTS
        String: the drive prefix (e.g. "AD:" or "LOCKmeADAD:") to prepend to a DN.
    #>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    if (-not $Server -and -not $Credential) {
        return "AD:"
    }

    $driveName = "LOCKmeADAD"
    $existing = Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue
    if (-not $existing) {
        $driveParam = @{
            Name       = $driveName
            PSProvider = 'ActiveDirectory'
            Root       = "//RootDSE/"
            Scope      = 'Global'
        }
        if ($Server)     { $driveParam.Server     = $Server }
        if ($Credential)  { $driveParam.Credential = $Credential }
        New-PSDrive @driveParam | Out-Null
    }
    return "${driveName}:"
}

function Invoke-LOCKmeADRemote {
    <#
    .SYNOPSIS
        Runs a scriptblock locally, or via a remote WinRM session against -Server
        using -Credential, for cmdlets that have no -Credential parameter of their
        own -- notably the entire GroupPolicy module (Get-GPO, New-GPO,
        Set-GPRegistryValue, Set-GPPrefRegistryValue, New-GPLink, Get-GPInheritance,
        etc. only ever accept -Server/-Domain, never -Credential; confirmed against
        Microsoft's own cmdlet reference -- unlike the ActiveDirectory module, whose
        cmdlets support -Credential natively).
    .DESCRIPTION
        In implicit mode (no Credential), runs the scriptblock directly in the
        current session -- zero behavior change for the domain-joined case. In
        explicit mode, opens a WinRM session to -Server with -Credential and runs
        the scriptblock there, so it executes under that domain identity's own
        Windows token instead of trying to pass a credential the target cmdlets
        can't accept. Requires WinRM (5985/5986) reachable on -Server, in addition
        to the AD/RPC connectivity the rest of the tool needs.

        Kerberos is always attempted first (-Authentication Kerberos). This fails
        outright on a non-domain-joined host with no realm/KDC configured (see
        'ksetup /setrealm' + 'ksetup /addkdc' to fix that at the host level) --
        WinRM does not fall back to NTLM on its own the way interactive logons do.
        On first failure this session, the user is asked once whether to allow
        falling back to NTLM (-Authentication Negotiate) for the rest of the run;
        the answer is cached at global scope so it survives this module being
        re-imported by each LOCKmeAD module and isn't asked again per-GPO/task.
    .PARAMETER ScriptBlock
        The scriptblock to run. Must be self-contained (only reference its own
        -ArgumentList parameters) since it may cross a remoting boundary.
    .PARAMETER Server
        Target host for the remote session. Required when -Credential is supplied.
    .PARAMETER Credential
        Explicit credential. When $null, the scriptblock runs locally/implicitly.
    .PARAMETER ArgumentList
        Arguments passed positionally into the scriptblock.
    .PARAMETER AlwaysRemote
        Forces remoting to -Server even without -Credential (implicit/Kerberos-SSO
        Invoke-Command), for scriptblocks that must run on a specific different host
        regardless of auth mode (e.g. a file server for Grant-SmbShareAccess) -- as
        opposed to the default use (GroupPolicy cmdlets), where -Server alone with no
        -Credential means "run locally, the cmdlet reaches the domain by itself."
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [string]$Server,

        [PSCredential]$Credential,

        [object[]]$ArgumentList = @(),

        [switch]$AlwaysRemote
    )

    if (-not $Credential -and -not $AlwaysRemote) {
        return & $ScriptBlock @ArgumentList
    }

    if (-not $Server) {
        throw "Invoke-LOCKmeADRemote: -Server is required to establish the remote session."
    }

    if (-not $Credential) {
        # Implicit/Kerberos-SSO remoting to a specific different host -- no credential
        # to negotiate, so no Kerberos-vs-NTLM decision needed here.
        $session = Get-LOCKmeADRemoteSession -Server $Server
        return Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    }

    if ($global:LOCKmeADAllowNtlmFallback -eq $true) {
        $session = Get-LOCKmeADRemoteSession -Server $Server -Credential $Credential -Authentication Negotiate
        return Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    }

    try {
        $session = Get-LOCKmeADRemoteSession -Server $Server -Credential $Credential -Authentication Kerberos
        return Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
    }
    catch {
        $kerberosError = $_

        # Only a genuine authentication failure is worth retrying over NTLM. A transport or
        # transient failure (WinRM under load, timeout, host unreachable) is NOT an auth
        # problem: re-authenticating cannot fix it, and converting it into an NTLM prompt
        # both hides the real cause and blocks non-interactive callers. Drop the cached
        # session so the next call rebuilds it, then surface the original error unchanged.
        if (-not (Test-LOCKmeADAuthenticationError -ErrorRecord $kerberosError)) {
            Remove-LOCKmeADRemoteSession -Server $Server -Credential $Credential -Authentication Kerberos
            throw
        }

        if (-not (Request-LOCKmeADNtlmFallback -Target $Server -Reason $kerberosError)) {
            throw "Kerberos authentication to '$Server' failed and NTLM fallback was not permitted: $kerberosError"
        }

        $session = Get-LOCKmeADRemoteSession -Server $Server -Credential $Credential -Authentication Negotiate
        Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    }
}

function Get-LOCKmeADRemoteSession {
    <#
    .SYNOPSIS
        Returns a reusable PSSession for -Server, creating it on first use and caching it
        for the rest of the run.
    .DESCRIPTION
        Invoke-LOCKmeADRemote is called once per remote cmdlet invocation, and a single GPO
        deployment issues hundreds of them (per GPO: Get-GPO, New-GPO, one Set-GPRegistryValue
        per setting, then Get-GPInheritance/New-GPLink). Opening a brand-new WinRM session for
        each one is both slow and fragile -- that session churn is what produced intermittent
        remoting failures during GPO link creation. Caching one session per
        target+auth+identity removes the churn entirely.

        The cache lives at global scope so it survives this module being re-imported by each
        LOCKmeAD feature module (same reasoning as $global:LOCKmeADAllowNtlmFallback). A
        cached session is reused only while it is genuinely usable (Opened + Available);
        otherwise it is discarded and rebuilt.
    .PARAMETER Server
        Target host for the session.
    .PARAMETER Credential
        Explicit credential. When $null, an implicit/SSO session is created.
    .PARAMETER Authentication
        WinRM authentication mechanism (e.g. Kerberos, Negotiate). Omit for the default.
    .OUTPUTS
        A PSSession ready to pass to Invoke-Command -Session.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Server,

        [PSCredential]$Credential,

        [string]$Authentication
    )

    if (-not $global:LOCKmeADSessionCache) { $global:LOCKmeADSessionCache = @{} }

    $key = Get-LOCKmeADRemoteSessionKey -Server $Server -Credential $Credential -Authentication $Authentication

    $existing = $global:LOCKmeADSessionCache[$key]
    if ($existing -and $existing.State -eq 'Opened' -and $existing.Availability -eq 'Available') {
        return $existing
    }
    if ($existing) {
        Remove-PSSession -Session $existing -ErrorAction SilentlyContinue
        $global:LOCKmeADSessionCache.Remove($key)
    }

    $sessionParam = @{ ComputerName = $Server; ErrorAction = 'Stop' }
    if ($Credential)     { $sessionParam.Credential     = $Credential }
    if ($Authentication) { $sessionParam.Authentication = $Authentication }

    $session = New-PSSession @sessionParam
    $global:LOCKmeADSessionCache[$key] = $session
    return $session
}

function Get-LOCKmeADRemoteSessionKey {
    <#
    .SYNOPSIS
        Builds the cache key identifying a remote session (target + auth mechanism + identity).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Server,

        [PSCredential]$Credential,

        [string]$Authentication
    )

    $identity = if ($Credential) { $Credential.UserName } else { '<implicit>' }
    $authKey  = if ($Authentication) { $Authentication } else { '<default>' }
    return "$Server|$authKey|$identity"
}

function Remove-LOCKmeADRemoteSession {
    <#
    .SYNOPSIS
        Drops one cached session (when it has gone bad), or every cached session when called
        with no -Server.
    .DESCRIPTION
        Call the parameterless form at the end of a run to release WinRM sessions on the
        target instead of leaving them to idle-timeout.
    #>
    [CmdletBinding()]
    param(
        [string]$Server,

        [PSCredential]$Credential,

        [string]$Authentication
    )

    if (-not $global:LOCKmeADSessionCache) { return }

    if (-not $Server) {
        foreach ($session in @($global:LOCKmeADSessionCache.Values)) {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
        $global:LOCKmeADSessionCache = @{}
        return
    }

    $key = Get-LOCKmeADRemoteSessionKey -Server $Server -Credential $Credential -Authentication $Authentication
    $existing = $global:LOCKmeADSessionCache[$key]
    if ($existing) {
        Remove-PSSession -Session $existing -ErrorAction SilentlyContinue
        $global:LOCKmeADSessionCache.Remove($key)
    }
}

function Test-LOCKmeADAuthenticationError {
    <#
    .SYNOPSIS
        Returns $true only when an error genuinely represents an authentication failure that
        retrying over NTLM could plausibly fix.
    .DESCRIPTION
        Invoke-LOCKmeADRemote previously treated ANY Invoke-Command failure as "Kerberos
        failed" and offered NTLM fallback. That misclassifies transport and transient errors
        (WinRM under load, timeouts, unreachable hosts), which NTLM cannot fix -- and in a
        non-interactive context the resulting prompt turns a recoverable, clearly-diagnosable
        error into an opaque one. Transient signatures are checked first so that a transport
        error mentioning the word "authentication" is still classified as transport.
    .PARAMETER ErrorRecord
        The ErrorRecord captured from the failed remote call.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $ErrorRecord
    )

    $text = @(
        $ErrorRecord.Exception.Message
        $ErrorRecord.FullyQualifiedErrorId
        $ErrorRecord.CategoryInfo.Reason
    ) -join ' '

    # Transport / transient -- NTLM fallback would not help.
    $transientPatterns = @(
        'timed out', 'timeout', 'is busy', 'cannot connect', 'unable to connect',
        'network path', 'rpc server is unavailable', 'maximum number of concurrent',
        'connection.*(closed|reset|aborted)', 'not.*listening', 'shell.*not.*found',
        'winrm.*(service|client).*(not|cannot)'
    )
    foreach ($pattern in $transientPatterns) {
        if ($text -imatch $pattern) { return $false }
    }

    # Genuine authentication / authorization failures.
    $authPatterns = @(
        'kerberos', '\bkdc\b', 'realm', '\bspn\b', 'service principal name',
        'authentication', 'access is denied', 'logon failure',
        'user name or password', 'credential', 'unauthorized',
        '0x8009030c', '0x8009030e', '0x80090322'
    )
    foreach ($pattern in $authPatterns) {
        if ($text -imatch $pattern) { return $true }
    }

    return $false
}

function Request-LOCKmeADNtlmFallback {
    <#
    .SYNOPSIS
        Decides whether NTLM fallback is allowed after a Kerberos auth failure,
        asking the user interactively at most once per session.
    .DESCRIPTION
        Shared by Invoke-LOCKmeADRemote and New-LOCKmeADCimSession so a decision
        made via one code path (e.g. GPO remoting) is honored by the other (e.g.
        CIM sessions) without re-prompting. Cached at global scope so it survives
        this module being re-imported by each LOCKmeAD module.
    .PARAMETER Target
        The remote host Kerberos auth failed against, for the prompt/error text.
    .PARAMETER Reason
        The underlying Kerberos error, shown to the user for context.
    .OUTPUTS
        Boolean: whether the caller should retry with -Authentication Negotiate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        $Reason
    )

    if ($global:LOCKmeADAllowNtlmFallback -eq $true)  { return $true }
    if ($global:LOCKmeADAllowNtlmFallback -eq $false) { return $false }

    # No console to prompt on (scheduled task, CI): never block, and never let Read-Host's
    # raw "PowerShell is in NonInteractive mode" error escape as if it were the underlying
    # failure. Record the decision as denied so the caller fails fast with the real Kerberos
    # error instead.
    if (-not [Environment]::UserInteractive) {
        Write-Warning "Kerberos authentication to '$Target' failed and there is no console available to ask about NTLM fallback; treating it as denied. Fix the Kerberos realm/KDC configuration on this host ('ksetup /setrealm', 'ksetup /addkdc'), or run from an interactive session to be asked. Reason: $Reason"
        $global:LOCKmeADAllowNtlmFallback = $false
        return $false
    }

    # Not yet decided this session -- ask once, then cache the answer at global scope.
    Write-Host ""
    Write-Host "Kerberos authentication to '$Target' failed:" -ForegroundColor Yellow
    Write-Host "  $Reason" -ForegroundColor Yellow
    Write-Host "This is expected if the Kerberos realm/KDC isn't configured on this host." -ForegroundColor Yellow
    Write-Host "Fix: run 'ksetup /setrealm <REALM>' and 'ksetup /addkdc <REALM> <kdc-host>' as admin, then reboot." -ForegroundColor Yellow
    try {
        $answer = Read-Host "Allow falling back to NTLM for the rest of this session? (y/N)"
    }
    catch {
        # UserInteractive can still be $true in a host that cannot actually read input.
        Write-Warning "Could not prompt for the NTLM fallback decision ($_). Treating it as denied."
        $global:LOCKmeADAllowNtlmFallback = $false
        return $false
    }
    $global:LOCKmeADAllowNtlmFallback = ($answer -match '^(y|yes)$')
    return $global:LOCKmeADAllowNtlmFallback
}

function New-LOCKmeADCimSession {
    <#
    .SYNOPSIS
        Opens a CIM session against -ComputerName with -Credential, trying Kerberos
        first and falling back to NTLM under the same one-time-prompt policy as
        Invoke-LOCKmeADRemote (New-CimSession has the identical default-auth-
        negotiation gap from a non-domain-joined host as Invoke-Command does).
    .PARAMETER ComputerName
        Target host for the CIM session.
    .PARAMETER Credential
        Explicit credential to authenticate with.
    .OUTPUTS
        A CimSession, or $null if it could not be established (Kerberos failed and
        NTLM fallback was declined, or NTLM itself also failed).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [PSCredential]$Credential
    )

    if ($global:LOCKmeADAllowNtlmFallback -eq $true) {
        return New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication Negotiate -ErrorAction SilentlyContinue
    }

    $session = New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication Kerberos -ErrorAction SilentlyContinue
    if ($session) { return $session }

    if (-not (Request-LOCKmeADNtlmFallback -Target $ComputerName -Reason "Kerberos CIM session could not be established")) {
        return $null
    }

    New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication Negotiate -ErrorAction SilentlyContinue
}

Export-ModuleMember -Function @(
    'Test-LOCKmeADDomainJoined',
    'Resolve-LOCKmeADConnection',
    'Save-LOCKmeADConnection',
    'Remove-LOCKmeADConnection',
    'New-LOCKmeADConnectionParam',
    'Get-LOCKmeADSysvolDrive',
    'Get-LOCKmeADDrive',
    'Invoke-LOCKmeADRemote',
    'Get-LOCKmeADRemoteSession',
    'Remove-LOCKmeADRemoteSession',
    'Test-LOCKmeADAuthenticationError',
    'Request-LOCKmeADNtlmFallback',
    'New-LOCKmeADCimSession'
)
