#Requires -Version 7.0

<#
.SYNOPSIS
    Launches the LOCKmeAD Manager graphical interface.
.DESCRIPTION
    Unified WPF GUI for managing Hardening, Tiering, and RBAC configurations.
    Allows enabling/disabling tasks, editing OU structures, managing RBAC roles,
    and deploying each module with WhatIf support.
#>

$ErrorActionPreference = "Stop"

# --- Check required modules ---
$requiredModules = @("ActiveDirectory", "GroupPolicy")
$missingModules  = $requiredModules | Where-Object { -not (Get-Module -Name $_) -and -not (Get-Module -ListAvailable -Name $_) }
if ($missingModules) {
    Write-Host "`n[ERROR] The following required modules are not available: $($missingModules -join ', ')" -ForegroundColor Red
    Write-Host "`nImport them in your current session and try again:" -ForegroundColor Yellow
    Write-Host "  Import-Module $($missingModules -join ', ')`n" -ForegroundColor Cyan
    exit 1
}
$scriptRoot = $PSScriptRoot

# Load WPF assemblies
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# Load GUI components
. "$scriptRoot\GUI\Views.ps1"
. "$scriptRoot\GUI\Controller.ps1"

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
