#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Starts the LOCKmeAD web interface (replaces the WPF GUI).
.DESCRIPTION
    Launches a local-only (127.0.0.1) Pode web server hosting the LOCKmeAD web UI, then opens
    the default browser to it. Every route is a thin wrapper around the same Modules/*.psm1
    functions and Scripts/Deploy-*.ps1 scripts the CLI already uses -- this replaces only the
    presentation layer, not any deployment logic.
.PARAMETER Server
    Explicit target domain controller. Required when this host is not domain-joined and no
    domain controller can be located automatically. If omitted here, the web UI's connection
    form collects it instead of blocking this console.
.PARAMETER Credential
    Explicit domain credential.
.PARAMETER RememberConnection
    Persists the resolved -Server/-Credential (DPAPI-protected, current user only) for reuse
    on the next run.
.PARAMETER Port
    Local TCP port to listen on. Default: 8080.
.PARAMETER NoBrowser
    Don't automatically open the default browser after the server starts.
.EXAMPLE
    .\Web\Start-LOCKmeADWeb.ps1
    .\Web\Start-LOCKmeADWeb.ps1 -Server dc01.forest.lol -Credential (Get-Credential)
    .\Web\Start-LOCKmeADWeb.ps1 -Port 9090
#>
[CmdletBinding()]
param(
    [string]$Server,
    [PSCredential]$Credential,
    [switch]$RememberConnection,
    [int]$Port = 8080,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$rootDir = Split-Path $PSScriptRoot -Parent

# --- Check required modules ---
$requiredModules = @("ActiveDirectory", "GroupPolicy", "Pode")
$missingModules  = $requiredModules | Where-Object { -not (Get-Module -Name $_) -and -not (Get-Module -ListAvailable -Name $_) }
if ($missingModules) {
    Write-Host "`n[ERROR] The following required modules are not available: $($missingModules -join ', ')" -ForegroundColor Red
    Write-Host "`nInstall them and try again:" -ForegroundColor Yellow
    if ($missingModules -contains "Pode") {
        Write-Host "  Install-Module -Name Pode -Scope CurrentUser" -ForegroundColor Cyan
    }
    $rsatMissing = $missingModules | Where-Object { $_ -ne "Pode" }
    if ($rsatMissing) {
        Write-Host "  Import-Module $($rsatMissing -join ', ')" -ForegroundColor Cyan
    }
    Write-Host ""
    exit 1
}

Import-Module Pode

# Connection.psm1 is imported LAST, after every feature module -- not before.
# Each feature module does its own internal `Import-Module ..\Common\Connection.psm1
# -Force` to reach those functions for its own use, and when Module B imports
# Module X with -Force from within B's own module scope (rather than the top-level
# script scope), PowerShell attaches the re-imported X as a nested module scoped to
# B, tearing down and replacing whatever was previously registered globally under
# that same module name. Importing Connection.psm1 first and the feature modules
# after it (as an earlier version of this script did) left Resolve-LOCKmeADConnection
# invisible at the top level once the last feature module's internal re-import ran --
# confirmed empirically. Every Scripts\Deploy-*.ps1 already avoids this by importing
# Connection.psm1 last, after its own single feature module; this does the same
# thing across all seven.
Import-Module (Join-Path $rootDir "Modules\Hardening\Hardening.psm1") -Force
Import-Module (Join-Path $rootDir "Modules\GPO\GPO.psm1") -Force
Import-Module (Join-Path $rootDir "Modules\Tiering\Tiering.psm1") -Force
Import-Module (Join-Path $rootDir "Modules\RBAC\RBAC.psm1") -Force
Import-Module (Join-Path $rootDir "Modules\PSO\PSO.psm1") -Force
Import-Module (Join-Path $rootDir "Modules\Silo\Silo.psm1") -Force
Import-Module (Join-Path $rootDir "Modules\JIT\JIT.psm1") -Force
Import-Module (Join-Path $rootDir "Modules\Common\Connection.psm1") -Force

# Resolve the connection without blocking this console on Read-Host/Get-Credential --
# if it can't be resolved silently (explicit params, saved profile, or domain-joined
# auto-detect), the web UI's own connection form collects it via POST /api/connect.
$initialConnection = Resolve-LOCKmeADConnection -Server $Server -Credential $Credential -Remember:$RememberConnection -NonInteractive

$webRoot = $PSScriptRoot
$url = "http://127.0.0.1:$Port"

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  LOCKmeAD Web Interface" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""
Write-Host "  Listening on : $url (127.0.0.1 only, not reachable from the network)" -ForegroundColor Cyan
if ($initialConnection) {
    $mode = if ($initialConnection.Server) { "explicit ($($initialConnection.Server))" } else { "implicit (domain-joined)" }
    Write-Host "  Connection   : resolved, $mode" -ForegroundColor Green
}
else {
    Write-Host "  Connection   : not resolved yet -- use the Connect form in the browser" -ForegroundColor Yellow
}
Write-Host ""

if (-not $NoBrowser) {
    # Start-PodeServer blocks for the life of the server, so the browser must be
    # opened from a background job started beforehand rather than after it returns.
    Start-Job -ScriptBlock {
        param($Url)
        Start-Sleep -Seconds 2
        Start-Process $Url
    } -ArgumentList $url | Out-Null
}

Start-PodeServer -Threads 4 -StatusPageExceptions Show {
    # Note: Pode's Start-PodeServer scriptblock runs with -NoNewClosure, so the
    # normal PowerShell $using: scope modifier does NOT work here (confirmed against
    # Pode 2.13.4 -- it throws "A Using variable cannot be retrieved"). Outer script
    # variables (Port, rootDir, initialConnection, webRoot) are instead referenced by
    # plain name, which Pode does make available inside THIS top-level setup
    # scriptblock (it runs synchronously, once, as part of Start-PodeServer's own
    # invocation).
    #
    # This does NOT extend to Add-PodeRoute/Add-PodeTask -ScriptBlock bodies, though:
    # those are deferred and re-invoked later via Invoke-PodeScriptBlock -NoNewClosure,
    # in a runspace that only inherits what's in Pode's initial session-state snapshot.
    # Plain variables and functions merely dot-sourced during this setup block's
    # one-time execution do NOT survive into that snapshot (confirmed empirically:
    # both throw/return null inside a route body) -- any state a route or task needs
    # goes through Set-PodeState/Get-PodeState instead, hence registering the
    # module->config-file and module->deploy-script maps there rather than as plain
    # variables inside Routes\Config.ps1/Routes\Deploy.ps1.
    #
    # Import-Module'd functions don't reliably survive into that snapshot either,
    # it turns out: Pode's own automatic propagation of already-loaded modules into
    # its runspace pools is order-dependent and got tripped up by the same
    # nested-module-scoping behavior described above (each feature module's own
    # internal `Import-Module ..\Common\Connection.psm1 -Force` re-scopes Connection
    # away from whatever Pode captured as "global" when it isn't imported last).
    # Import-PodeModule is Pode's own documented mechanism for this exact problem --
    # "Imports a Module into the current, and all runspaces that Pode uses" -- so
    # every module gets explicitly re-imported through it here, rather than relying
    # on Pode's implicit propagation of the plain Import-Module calls above.
    Add-PodeEndpoint -Address 127.0.0.1 -Port $Port -Protocol Http

    Import-PodeModule -Path (Join-Path $rootDir "Modules\Hardening\Hardening.psm1")
    Import-PodeModule -Path (Join-Path $rootDir "Modules\GPO\GPO.psm1")
    Import-PodeModule -Path (Join-Path $rootDir "Modules\Tiering\Tiering.psm1")
    Import-PodeModule -Path (Join-Path $rootDir "Modules\RBAC\RBAC.psm1")
    Import-PodeModule -Path (Join-Path $rootDir "Modules\PSO\PSO.psm1")
    Import-PodeModule -Path (Join-Path $rootDir "Modules\Silo\Silo.psm1")
    Import-PodeModule -Path (Join-Path $rootDir "Modules\JIT\JIT.psm1")
    Import-PodeModule -Path (Join-Path $rootDir "Modules\Common\Connection.psm1")

    New-PodeLoggingMethod -Terminal | Enable-PodeErrorLogging

    Set-PodeState -Name 'RootDir' -Value $rootDir | Out-Null
    Set-PodeState -Name 'Connection' -Value $initialConnection | Out-Null
    Set-PodeState -Name 'GuidToNameMap' -Value @{} | Out-Null
    Set-PodeState -Name 'DeployJobs' -Value ([hashtable]::Synchronized(@{})) | Out-Null
    Set-PodeState -Name 'ConfigModuleMap' -Value @{
        Hardening = 'Hardening-Config.json'
        GPO       = 'GPO-Config.json'
        Tiering   = 'Tiering-Config.json'
        RBAC      = 'RBAC-Config.json'
        PSO       = 'PSO-Config.json'
        Silo      = 'Silo-Config.json'
        JIT       = 'JIT-Config.json'
    } | Out-Null
    Set-PodeState -Name 'DeployScriptMap' -Value @{
        Hardening = 'Deploy-Hardening.ps1'
        GPO       = 'Deploy-GPO.ps1'
        Tiering   = 'Deploy-Tiering.ps1'
        RBAC      = 'Deploy-RBAC.ps1'
        PSO       = 'Deploy-PSO.ps1'
        Silo      = 'Deploy-Silo.ps1'
        JIT       = 'Deploy-JIT.ps1'
    } | Out-Null

    Add-PodeStaticRoute -Path '/' -Source (Join-Path $webRoot 'wwwroot') -Defaults @('index.html')

    . (Join-Path $webRoot 'Routes\Connection.ps1')
    . (Join-Path $webRoot 'Routes\Dashboard.ps1')
    . (Join-Path $webRoot 'Routes\Config.ps1')
    . (Join-Path $webRoot 'Routes\Deploy.ps1')
}
