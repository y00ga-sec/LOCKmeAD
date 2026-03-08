#Requires -Version 7.0

<#
.SYNOPSIS
    Launches the AD-RBAC Manager graphical interface.
.DESCRIPTION
    Unified WPF GUI for managing Hardening, Tiering, and RBAC configurations.
    Allows enabling/disabling tasks, editing OU structures, managing RBAC roles,
    and deploying each module with WhatIf support.
#>

$ErrorActionPreference = "Stop"
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
    Tiering   = Join-Path $scriptRoot "Config\Tiering-Config.json"
    RBAC      = Join-Path $scriptRoot "Config\RBAC-Config.json"
}
$script:ScriptPaths = @{
    Hardening = Join-Path $scriptRoot "Deploy-Hardening.ps1"
    Tiering   = Join-Path $scriptRoot "Deploy-Tiering.ps1"
    RBAC      = Join-Path $scriptRoot "Deploy-RBAC.ps1"
}

# Runtime state
$script:Configs = @{}
$script:HardeningToggles = @()
$script:HardeningParamControls = @{}
$script:UnsavedChanges = @{ Hardening = $false; Tiering = $false; RBAC = $false }
$script:isUpdatingSelection = $false
$script:RemovedDLGroups = @()

# Initialize and show
Initialize-GUI
Register-GUIEvents
$script:Window.ShowDialog() | Out-Null
