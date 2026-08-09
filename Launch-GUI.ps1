#Requires -Version 7.0

<#
.SYNOPSIS
    Launches the LOCKmeAD Manager graphical interface.
.DESCRIPTION
    Unified WPF GUI for managing Hardening, Tiering, and RBAC configurations.
    Allows enabling/disabling tasks, editing OU structures, managing RBAC roles,
    and deploying each module with WhatIf support.
.PARAMETER Server
    Explicit target domain controller. Used when this host is not domain-joined
    and no domain controller can be located automatically. If not supplied and the
    host isn't domain-joined, a connection dialog is shown at startup.
.PARAMETER Credential
    Explicit domain credential, paired with -Server.
.PARAMETER RememberConnection
    Persists the resolved connection (DPAPI-protected, current user only) for reuse
    on the next launch.
#>

param(
    [string]$Server,
    [PSCredential]$Credential,
    [switch]$RememberConnection
)

$ErrorActionPreference = "Stop"

# --- Check required modules ---
# GroupPolicy is intentionally only a warning here -- see the same check in LOCKmeAD.ps1 for why.
if (-not (Get-Module -Name ActiveDirectory) -and -not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "`n[ERROR] The required module 'ActiveDirectory' is not available." -ForegroundColor Red
    Write-Host "`nInstall RSAT (or run on a domain controller) and try again.`n" -ForegroundColor Yellow
    exit 1
}
if (-not (Get-Module -Name GroupPolicy) -and -not (Get-Module -ListAvailable -Name GroupPolicy)) {
    Write-Host "`n[WARNING] The 'GroupPolicy' module is not available on this host." -ForegroundColor Yellow
    Write-Host "  GPO/JIT deployment needs it locally only in implicit (domain-joined) mode.`n" -ForegroundColor DarkGray
}
$scriptRoot = $PSScriptRoot

Import-Module (Join-Path $scriptRoot "Modules\Common\Connection.psm1") -Force

# Load WPF assemblies
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# Load GUI components
. "$scriptRoot\GUI\Views.ps1"
. "$scriptRoot\GUI\Controller.ps1"

# Resolve the AD connection: implicit if domain-joined, otherwise explicit
# -Server/-Credential, or a connection dialog if neither was supplied.
if ($Server -or $Credential) {
    $script:Connection = Resolve-LOCKmeADConnection -Server $Server -Credential $Credential -Remember:$RememberConnection
}
else {
    # A saved profile is consulted BEFORE anything else. This branch used to jump straight to the
    # connection dialog whenever the host was not domain-joined, so the "Remember this connection"
    # checkbox wrote a profile that the GUI then never read -- the operator re-typed the same
    # credentials at every launch. Resolve-LOCKmeADConnection could not be used here: with nothing
    # to resolve it falls back to Read-Host/Get-Credential on the console, which is exactly what a
    # GUI must not do.
    #
    # The profile is verified before being trusted: a stored credential goes stale as soon as the
    # password changes, and an unchecked one would leave every module failing on authentication
    # errors with no obvious cause. On failure the dialog opens, pre-filled with the saved server.
    $script:Connection = $null
    $saved = Get-LOCKmeADSavedConnection
    if ($saved) {
        if (-not (Test-LOCKmeADConnection -Connection $saved)) {
            Write-Host "  The saved connection for $($saved.Server) no longer authenticates; asking again." -ForegroundColor Yellow
        }
        else {
            # A profile saved before the privilege gate existed, or an account since removed from
            # Domain Admins, must not be trusted just because it still authenticates.
            try {
                $null = Assert-LOCKmeADPrivilege -Connection $saved
                $script:Connection = $saved
                Write-Host "  Using the saved connection for $($saved.Server) ($($saved.Credential.UserName))." -ForegroundColor DarkGray
            }
            catch {
                Write-Host "  Saved connection rejected: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }

    if (-not $script:Connection -and (Test-LOCKmeADDomainJoined)) {
        $script:Connection = Resolve-LOCKmeADConnection
    }

    if (-not $script:Connection) {
        $script:Connection = Show-GUIConnectionDialog -DefaultServer $(if ($saved) { $saved.Server } else { '' })
        if (-not $script:Connection) {
            Write-Host "  Connection cancelled." -ForegroundColor Yellow
            exit 0
        }
    }
}

# Parse XAML
$xaml = Get-MainWindowXaml
[xml]$xamlDoc = $xaml
$reader = [System.Xml.XmlNodeReader]::new($xamlDoc)
$script:Window = [System.Windows.Markup.XamlReader]::Load($reader)

# Resolve all named elements
$script:UI = @{}
$xamlDoc.SelectNodes('//*[@Name]') | ForEach-Object {
    $name = $_.Name
    $el = $script:Window.FindName($name)
    if ($el) { $script:UI[$name] = $el }
}

# Config file paths
$script:ConfigPaths = @{
    Hardening = Join-Path $scriptRoot "Config\Hardening-Config.json"
    GPO       = Join-Path $scriptRoot "Config\GPO-Config.json"
    Tiering   = Join-Path $scriptRoot "Config\Tiering-Config.json"
    RBAC      = Join-Path $scriptRoot "Config\RBAC-Config.json"
    PSO       = Join-Path $scriptRoot "Config\PSO-Config.json"
    Silo      = Join-Path $scriptRoot "Config\Silo-Config.json"
    JIT       = Join-Path $scriptRoot "Config\JIT-Config.json"
}
$script:ScriptPaths = @{
    Hardening = Join-Path $scriptRoot "Scripts\Deploy-Hardening.ps1"
    GPO       = Join-Path $scriptRoot "Scripts\Deploy-GPO.ps1"
    Tiering   = Join-Path $scriptRoot "Scripts\Deploy-Tiering.ps1"
    RBAC      = Join-Path $scriptRoot "Scripts\Deploy-RBAC.ps1"
    PSO       = Join-Path $scriptRoot "Scripts\Deploy-PSO.ps1"
    Silo      = Join-Path $scriptRoot "Scripts\Deploy-Silo.ps1"
    JIT       = Join-Path $scriptRoot "Scripts\Deploy-JIT.ps1"
}

# Runtime state
$script:Configs = @{}
$script:HardeningToggles = @()
$script:HardeningParamControls = @{}
$script:GPOToggles = @()
$script:GPOLinkControls = @{}
$script:PSOToggles = @()
$script:PSOParamControls = @{}
$script:PSOAppliesToControls = @{}
$script:SiloToggles = @()
$script:SiloParamControls = @{}
$script:SiloComputerControls = @{}
$script:SiloServiceAccountControls = @{}
$script:UnsavedChanges = @{ Hardening = $false; GPO = $false; Tiering = $false; RBAC = $false; PSO = $false; Silo = $false; JIT = $false }
$script:isUpdatingSelection = $false
$script:RemovedDLGroups = @()

# Initialize and show
Initialize-GUI
Register-GUIEvents
$script:Window.ShowDialog() | Out-Null
