#Requires -Version 7.0

# ============================================================================
# Config Domain Module - retargets a loaded configuration onto the domain
# LOCKmeAD is actually connected to
# ============================================================================
#
# Every module resolves its targets from the literal DNs written in Config\*.json, so a
# configuration authored against one domain fails object by object against another: an OU "not
# found" here, a group created nowhere there, a delegation applied to a DN that does not exist --
# all for a reason that has nothing to do with the policy being deployed. The shipped samples make
# the point on their own: they mix DC=forest,DC=lol and DC=corp,DC=local in the same tree.
#
# The rewrite is therefore driven by what each string actually contains, not by a single
# "source domain" setting: every DN is retargeted onto the connected domain regardless of which
# domain it used to name, which also repairs a configuration that was already internally
# inconsistent.
#
# Everything happens in memory on the loaded configuration objects. Nothing is written to disk
# here -- the caller's normal save path is what persists it, so opening the GUI to look around
# leaves Config\*.json untouched.

# Prefixes that look like a "DOMAIN\name" pair but are not domain-qualified principals. Without
# this guard the NetBIOS rule would happily rewrite registry keys, since MACHINE\System and
# CORP\DL_T2_Admins are the same shape.
$script:NonDomainPrefixes = @('HKLM', 'HKCU', 'HKCR', 'HKU', 'HKCC', 'MACHINE', 'USER', 'BUILTIN')

function Resolve-LOCKmeADDomainDNRewrite {
    <#
    .SYNOPSIS
        Private. Analyses one string as a distinguished name and returns its source domain DN
        together with the retargeted form, or $null when the string is not a DN.
    .OUTPUTS
        PSCustomObject with SourceDomainDN and Rewritten, or $null.
    #>
    [CmdletBinding()]
    param(
        [string]$Value,
        [string]$TargetDomainDN,
        [string]$TargetDnsRoot
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    # A candidate must OPEN with a DN component. This single guard is what keeps the rewriter away
    # from everything else a configuration holds -- registry keys (HKLM\..., MACHINE\...), UNC
    # paths, group names, and prose that merely quotes a DN, such as the RBAC description
    # "DL T0 - Computer object management in OU=Servers,OU=T0-Prod".
    if ($Value -notmatch '^\s*(CN|OU|DC)=') { return $null }

    # ... and CLOSE with a chain of DC= components, which is the part naming the domain.
    if ($Value -notmatch '(DC=[^,]+(?:,DC=[^,]+)*)\s*$') { return $null }
    $chain = $Matches[1]

    # An application-partition DN carries its partition head inside that chain
    # (CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local): only the tail names the domain.
    # Replacing the whole chain would silently drop DC=DomainDnsZones and yield a DN that resolves
    # to nothing -- the RBAC config delegates DNS rights through exactly these DNs.
    $partitionHead  = ''
    $sourceDomainDN = $chain
    if ($sourceDomainDN -match '^(DC=(?:Domain|Forest)DnsZones),(.+)$') {
        $partitionHead  = "$($Matches[1]),"
        $sourceDomainDN = $Matches[2]
    }

    $prefix    = $Value.Substring(0, $Value.LastIndexOf($chain))
    $rewritten = "$prefix$partitionHead$TargetDomainDN"

    # A dnsZone object names the zone in its leading component (DC=corp.local,CN=MicrosoftDNS,...
    # and DC=_msdcs.corp.local,...). That name is the DNS form of the source domain, so it goes
    # stale exactly like the DN suffix does, and a half-rewritten DN would be worse than the
    # original: syntactically plausible, pointing at a zone of the old domain.
    if ($rewritten -match ',CN=MicrosoftDNS,') {
        $sourceDnsRoot = ($sourceDomainDN -replace 'DC=', '') -replace ',', '.'
        $escapedRoot   = [regex]::Escape($sourceDnsRoot)
        $rewritten     = $rewritten -replace "^DC=(?<sub>(?:_msdcs\.)?)$escapedRoot(?=,)", "DC=`${sub}$TargetDnsRoot"
    }

    return [PSCustomObject]@{
        SourceDomainDN = $sourceDomainDN
        Rewritten      = $rewritten
    }
}

function ConvertTo-LOCKmeADDomainDN {
    <#
    .SYNOPSIS
        Retargets a single distinguished name onto the given domain. Returns the value unchanged
        when it is not a DN, or already targets that domain.
    .PARAMETER Value
        The candidate string.
    .PARAMETER TargetDomainDN
        Distinguished name of the domain to point at (e.g. DC=forest,DC=lol).
    .PARAMETER TargetDnsRoot
        DNS name of that same domain (e.g. forest.lol), needed for DNS zone DNs.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory)][string]$TargetDomainDN,
        [Parameter(Mandatory)][string]$TargetDnsRoot
    )

    $result = Resolve-LOCKmeADDomainDNRewrite -Value $Value -TargetDomainDN $TargetDomainDN -TargetDnsRoot $TargetDnsRoot
    if ($null -eq $result) { return $Value }
    return $result.Rewritten
}

function ConvertTo-LOCKmeADDomainValue {
    <#
    .SYNOPSIS
        Private. Retargets one configuration value: distinguished names, UNC paths, NetBIOS-
        qualified principals, and bare DNS domain names.
    .DESCRIPTION
        The three non-DN forms are only rewritten when they name a domain the DNs of the same
        configuration set already referenced (-SourceDomain). Nothing else can distinguish
        "\\corp.local\NETLOGON\JIT", which must follow the domain, from a deliberate reference to
        an unrelated file server -- so the rule is: retarget what the configuration itself proves
        is the old domain, and leave every other host name alone.
    #>
    [CmdletBinding()]
    param(
        [string]$Value,
        [PSCustomObject[]]$SourceDomain,
        [string]$TargetDomainDN,
        [string]$TargetDnsRoot,
        [string]$TargetNetBIOS
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }

    # --- 1. Distinguished names ---
    $dn = Resolve-LOCKmeADDomainDNRewrite -Value $Value -TargetDomainDN $TargetDomainDN -TargetDnsRoot $TargetDnsRoot
    if ($null -ne $dn) { return $dn.Rewritten }

    if (-not $SourceDomain -or $SourceDomain.Count -eq 0) { return $Value }
    $dnsRoots = @($SourceDomain.DnsRoot)
    $netBios  = @($SourceDomain.NetBIOS)

    # --- 2. UNC paths: \\corp.local\NETLOGON\JIT ---
    # The host may be spelled either way, so both the DNS root and the NetBIOS name are accepted;
    # the DNS form is what gets written back, since it is the one that survives a forest with
    # several domains sharing a short name.
    if ($Value -match '^\\\\(?<host>[^\\]+)(?<rest>\\.*)?$') {
        $uncHost = $Matches['host']
        $rest    = $Matches['rest']
        if ($dnsRoots -contains $uncHost -or $netBios -contains $uncHost) {
            return "\\$TargetDnsRoot$rest"
        }
        return $Value
    }

    # --- 3. NetBIOS-qualified principals: CORP\DL_T2_Workstations_Manage ---
    # Deliberately anchored to a single backslash: a registry key (HKLM\SOFTWARE\Policies\...) has
    # more than one and is excluded by the pattern itself, on top of the prefix allow-list.
    if ($Value -match '^(?<nb>[A-Za-z0-9._-]+)\\(?<name>[^\\]+)$') {
        $prefix = $Matches['nb']
        $name   = $Matches['name']
        if ($script:NonDomainPrefixes -notcontains $prefix.ToUpper() -and $netBios -contains $prefix) {
            return "$TargetNetBIOS\$name"
        }
        return $Value
    }

    # --- 4. Bare DNS domain name: the Hardening ZoneName parameter ---
    # Matched on the whole string only. A substring rule would rewrite prose and, worse, any
    # unrelated FQDN that merely ends with the old domain name.
    if ($Value -match '^(?<sub>_msdcs\.)?(?<root>[A-Za-z0-9._-]+)$') {
        if ($dnsRoots -contains $Matches['root']) {
            return "$($Matches['sub'])$TargetDnsRoot"
        }
    }

    return $Value
}

function Get-LOCKmeADConfigDomainDNNode {
    # Private. Read-only walk collecting the source domain DN of every distinguished name found.
    param($Node, $Collected)

    if ($null -eq $Node -or $Node -is [ValueType]) { return }

    if ($Node -is [string]) {
        # Target values are irrelevant here: only SourceDomainDN is read, so any syntactically
        # valid placeholder does the job.
        $dn = Resolve-LOCKmeADDomainDNRewrite -Value $Node -TargetDomainDN 'DC=x' -TargetDnsRoot 'x'
        if ($null -ne $dn) { [void]$Collected.Add($dn.SourceDomainDN) }
        return
    }

    if ($Node -is [System.Collections.IList]) {
        foreach ($item in $Node) { Get-LOCKmeADConfigDomainDNNode -Node $item -Collected $Collected }
        return
    }

    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        foreach ($prop in @($Node.PSObject.Properties)) {
            Get-LOCKmeADConfigDomainDNNode -Node $prop.Value -Collected $Collected
        }
    }
}

function Get-LOCKmeADConfigDomainDN {
    <#
    .SYNOPSIS
        Returns the distinct domain DNs referenced by the distinguished names of a configuration.
    .DESCRIPTION
        Used as a discovery pass before rewriting: it is what tells the rewriter which host names
        and NetBIOS prefixes elsewhere in the file belong to the old domain rather than to some
        third-party server. Run it over every configuration first, then feed the union to
        Update-LOCKmeADConfigDomain, so a domain named only in RBAC still retargets the JIT share.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config)

    $collected = [System.Collections.Generic.List[string]]::new()
    Get-LOCKmeADConfigDomainDNNode -Node $Config -Collected $collected
    return @($collected | Sort-Object -Unique)
}

function Update-LOCKmeADConfigDomainNode {
    # Private. Rewrites strings in place, depth-first, recording every change.
    param($Node, [string]$Label, $SourceDomain, [string]$TargetDomainDN, [string]$TargetDnsRoot, [string]$TargetNetBIOS, $Changes)

    if ($null -eq $Node -or $Node -is [string] -or $Node -is [ValueType]) { return }

    if ($Node -is [System.Collections.IList]) {
        for ($i = 0; $i -lt $Node.Count; $i++) {
            $item = $Node[$i]
            if ($item -is [string]) {
                $new = ConvertTo-LOCKmeADDomainValue -Value $item -SourceDomain $SourceDomain `
                            -TargetDomainDN $TargetDomainDN -TargetDnsRoot $TargetDnsRoot -TargetNetBIOS $TargetNetBIOS
                if ($new -cne $item) {
                    $Node[$i] = $new
                    [void]$Changes.Add([PSCustomObject]@{ Path = "$Label[$i]"; From = $item; To = $new })
                }
            }
            else {
                Update-LOCKmeADConfigDomainNode -Node $item -Label "$Label[$i]" -SourceDomain $SourceDomain `
                    -TargetDomainDN $TargetDomainDN -TargetDnsRoot $TargetDnsRoot -TargetNetBIOS $TargetNetBIOS -Changes $Changes
            }
        }
        return
    }

    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        foreach ($prop in @($Node.PSObject.Properties)) {
            $childLabel = if ($Label) { "$Label.$($prop.Name)" } else { $prop.Name }
            if ($prop.Value -is [string]) {
                $new = ConvertTo-LOCKmeADDomainValue -Value $prop.Value -SourceDomain $SourceDomain `
                            -TargetDomainDN $TargetDomainDN -TargetDnsRoot $TargetDnsRoot -TargetNetBIOS $TargetNetBIOS
                if ($new -cne $prop.Value) {
                    $from = $prop.Value
                    $prop.Value = $new
                    [void]$Changes.Add([PSCustomObject]@{ Path = $childLabel; From = $from; To = $new })
                }
            }
            else {
                Update-LOCKmeADConfigDomainNode -Node $prop.Value -Label $childLabel -SourceDomain $SourceDomain `
                    -TargetDomainDN $TargetDomainDN -TargetDnsRoot $TargetDnsRoot -TargetNetBIOS $TargetNetBIOS -Changes $Changes
            }
        }
    }
}

function Update-LOCKmeADConfigDomain {
    <#
    .SYNOPSIS
        Retargets a loaded configuration object onto the given domain, in place, and returns the
        list of changes.
    .PARAMETER Config
        The configuration object, as produced by ConvertFrom-Json.
    .PARAMETER SourceDomain
        Domains the configuration set is known to reference, each with DomainDN, DnsRoot and
        NetBIOS -- see Get-LOCKmeADConfigDomainDN. Only used for the non-DN forms; distinguished
        names are retargeted from their own suffix and need no prior knowledge.
    .PARAMETER TargetDomainDN
        DN of the domain to retarget onto.
    .PARAMETER TargetDnsRoot
        DNS name of that domain.
    .PARAMETER TargetNetBIOS
        NetBIOS name of that domain.
    .OUTPUTS
        A list of PSCustomObject with Path, From and To. Empty when nothing had to change.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Config,
        [PSCustomObject[]]$SourceDomain = @(),
        [Parameter(Mandatory)][string]$TargetDomainDN,
        [Parameter(Mandatory)][string]$TargetDnsRoot,
        [Parameter(Mandatory)][string]$TargetNetBIOS,
        [string]$Label = ''
    )

    $changes = [System.Collections.Generic.List[PSCustomObject]]::new()
    Update-LOCKmeADConfigDomainNode -Node $Config -Label $Label -SourceDomain $SourceDomain `
        -TargetDomainDN $TargetDomainDN -TargetDnsRoot $TargetDnsRoot -TargetNetBIOS $TargetNetBIOS -Changes $changes
    return $changes
}

function New-LOCKmeADSourceDomain {
    <#
    .SYNOPSIS
        Turns the domain DNs discovered by Get-LOCKmeADConfigDomainDN into the {DomainDN, DnsRoot,
        NetBIOS} records Update-LOCKmeADConfigDomain expects.
    .DESCRIPTION
        NetBIOS is derived as the first DN label, upper-cased. That is a convention, not a rule --
        a domain can be given any NetBIOS name at creation -- but it is only ever used to RECOGNISE
        the old domain in "DOMAIN\principal" and UNC strings, never to build the new value, which
        comes from the live directory. A wrong guess therefore leaves a value untouched for the
        operator to fix; it cannot produce a wrong one.
    #>
    [CmdletBinding()]
    param([string[]]$DomainDN = @())

    foreach ($dn in $DomainDN) {
        if ([string]::IsNullOrWhiteSpace($dn)) { continue }
        $dnsRoot = ($dn -replace 'DC=', '') -replace ',', '.'
        [PSCustomObject]@{
            DomainDN = $dn
            DnsRoot  = $dnsRoot
            NetBIOS  = (($dnsRoot -split '\.')[0]).ToUpper()
        }
    }
}

function Get-LOCKmeADConfigDomainSource {
    <#
    .SYNOPSIS
        Discovers the domains referenced by every *-Config.json sitting beside the given
        configuration file.
    .DESCRIPTION
        Discovery deliberately spans the whole configuration SET, not just the file being
        deployed, because the evidence and the value needing it are routinely in different files:
        JIT-Config.json names the distribution share as \\<domain>\NETLOGON\JIT but carries few
        DNs, while the DNs proving which domain that is live in RBAC-Config.json. This is what
        gives a single Deploy-*.ps1 run the same result as the GUI, which loads all seven.

        Siblings are located from -ConfigPath's own directory, so a custom configuration set kept
        elsewhere is discovered from its own neighbours rather than from the shipped one. A file
        that cannot be read or parsed is skipped: discovery must never be the thing that stops a
        deployment.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath)

    $collected = [System.Collections.Generic.List[string]]::new()
    $directory = Split-Path -Path $ConfigPath -Parent

    $configFiles = @()
    if ($directory -and (Test-Path $directory)) {
        $configFiles = @(Get-ChildItem -Path $directory -Filter '*-Config.json' -File -ErrorAction SilentlyContinue)
    }
    if ($configFiles.Count -eq 0 -and (Test-Path $ConfigPath)) {
        $configFiles = @(Get-Item -Path $ConfigPath)
    }

    foreach ($file in $configFiles) {
        try   { $parsed = Get-Content -Path $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json }
        catch { continue }
        foreach ($dn in (Get-LOCKmeADConfigDomainDN -Config $parsed)) { [void]$collected.Add($dn) }
    }

    return @(New-LOCKmeADSourceDomain -DomainDN @($collected | Sort-Object -Unique))
}

function Sync-LOCKmeADConfigDomain {
    <#
    .SYNOPSIS
        Retargets an already-loaded configuration onto the connected domain and returns the list
        of changes. One call, for the deployment scripts.
    .DESCRIPTION
        In-memory only: -ConfigPath is read for discovery and to locate the sibling configurations,
        never written back. A CLI deployment therefore corrects the DNs for the run it is about to
        perform without silently editing the operator's files -- the same contract as the GUI,
        where the corrected values only reach disk through an explicit Save or a deployment.

        A domain that cannot be read is reported and the configuration is left exactly as written,
        rather than aborting: the deployment scripts already fail with a far more precise message
        the moment they touch the directory.
    .PARAMETER Config
        The loaded configuration object to retarget in place.
    .PARAMETER ConfigPath
        Path the configuration was read from, used to find its sibling *-Config.json files.
    .PARAMETER Server
        Target DC for the domain lookup.
    .PARAMETER Credential
        Explicit credential for that lookup.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][string]$ConfigPath,
        [string]$Server,
        [PSCredential]$Credential
    )

    $connParam = @{}
    if ($Server)     { $connParam.Server     = $Server }
    if ($Credential) { $connParam.Credential = $Credential }

    try {
        $domain = Get-ADDomain @connParam -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not read the connected domain, so the configuration is deployed exactly as written: $($_.Exception.Message)"
        return @()
    }

    $sourceDomains = Get-LOCKmeADConfigDomainSource -ConfigPath $ConfigPath

    return Update-LOCKmeADConfigDomain -Config $Config `
                -SourceDomain   $sourceDomains `
                -TargetDomainDN $domain.DistinguishedName `
                -TargetDnsRoot  $domain.DNSRoot `
                -TargetNetBIOS  $domain.NetBIOSName
}

Export-ModuleMember -Function @(
    'ConvertTo-LOCKmeADDomainDN',
    'Get-LOCKmeADConfigDomainDN',
    'Get-LOCKmeADConfigDomainSource',
    'New-LOCKmeADSourceDomain',
    'Sync-LOCKmeADConfigDomain',
    'Update-LOCKmeADConfigDomain'
)
