#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploys a tiering OU structure in Active Directory.
.DESCRIPTION
    This script reads a JSON configuration file and creates an OU hierarchy
    to implement the AD tiering model (Tier 0, Tier 1, Tier 2).
.PARAMETER ConfigPath
    Path to the JSON configuration file. Default: .\Config\Tiering-Config.json
.PARAMETER Server
    Explicit target domain controller. Required when this host is not domain-joined
    and no domain controller can be located automatically.
.PARAMETER Credential
    Explicit domain credential. Prompted for interactively when this host is not
    domain-joined and no credential is supplied.
.PARAMETER RememberConnection
    Persists the resolved -Server/-Credential (DPAPI-protected, current user only)
    for reuse on the next run.
.PARAMETER WhatIf
    Simulation mode: displays actions without executing them.
.EXAMPLE
    .\Deploy-Tiering.ps1
    .\Deploy-Tiering.ps1 -ConfigPath "C:\Config\custom-tiering.json"
    .\Deploy-Tiering.ps1 -WhatIf
    .\Deploy-Tiering.ps1 -Server dc01.forest.lol -Credential (Get-Credential)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "..\Config\Tiering-Config.json"),
    [switch]$NoConfirm,
    [string]$Server,
    [PSCredential]$Credential,
    [switch]$RememberConnection
)

# ============================================================================
# Initialization
# ============================================================================

$ErrorActionPreference = "Stop"
$rootDir = Split-Path $PSScriptRoot -Parent

# Import Tiering module
$modulePath = Join-Path $rootDir "Modules\Tiering\Tiering.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Host "[ERROR] Tiering module not found: $modulePath" -ForegroundColor Red
    exit 1
}
Import-Module $modulePath -Force
Import-Module (Join-Path $rootDir "Modules\Common\Connection.psm1") -Force

# Resolve the AD connection: implicit (domain-joined) or explicit (-Server/-Credential),
# prompting interactively when this host is not domain-joined and nothing was supplied.
$connection = Resolve-LOCKmeADConnection -Server $Server -Credential $Credential -Remember:$RememberConnection

# ============================================================================
# Load configuration
# ============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  TIERING DEPLOYMENT TOOL - Active Directory" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

try {
    $config = Import-TieringConfiguration -ConfigPath $ConfigPath
    $logDir = $config.Settings.LogDirectory
    if (-not [System.IO.Path]::IsPathRooted($logDir)) {
        $logDir = Join-Path $rootDir $logDir
    }
    $runFolder = if ($global:LOCKmeAD_RunFolder) { $global:LOCKmeAD_RunFolder } else { Get-Date -Format 'yyyy-MM-dd_HH-mm-ss' }
    $logDir = Join-Path $logDir $runFolder
    Write-TieringLog -Message "Configuration loaded successfully from '$ConfigPath'." -Level Success -LogDirectory $logDir
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ============================================================================
# Display environment information
# ============================================================================

Write-Host ""
Write-Host "--- Environment Information ---" -ForegroundColor White
Write-Host ""

try {
    $envInfo = Get-TieringEnvironmentInfo -Server $connection.Server -Credential $connection.Credential
    # An explicit -Server always wins (the host may only be able to reach that one DC);
    # otherwise target the PDC Emulator as before to avoid replication lag.
    $targetServer = if ($connection.Server) { $connection.Server } else { $envInfo.PDCEmulator }

    Write-Host "  Current DC        : $($envInfo.CurrentDC)" -ForegroundColor Cyan
    if ($envInfo.IsPDC) {
        Write-Host "  PDC Role          : YES (this DC is the PDC Emulator)" -ForegroundColor Green
    }
    else {
        Write-Host "  PDC Role          : NO (PDC = $($envInfo.PDCEmulator))" -ForegroundColor Yellow
    }
    Write-Host "  Target DC         : $targetServer" -ForegroundColor Cyan
    Write-Host "  Domain            : $($envInfo.DomainName)" -ForegroundColor Cyan
    Write-Host "  Domain DN         : $($envInfo.DomainDN)" -ForegroundColor Cyan
    Write-Host "  Forest            : $($envInfo.ForestName)" -ForegroundColor Cyan
    Write-Host "  Functional level  : Domain=$($envInfo.DomainMode), Forest=$($envInfo.ForestMode)" -ForegroundColor Cyan
}
catch {
    Write-Host "  [ERROR] Unable to retrieve AD information: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ============================================================================
# Configuration summary
# ============================================================================

# Local function to count the total number of OUs in the tree
function Get-OUCount {
    param([PSCustomObject[]]$Nodes)
    $count = 0
    foreach ($node in $Nodes) {
        $count++
        if ($node.Children) { $count += Get-OUCount -Nodes $node.Children }
    }
    return $count
}

# Local function to display the OU tree
function Show-OUTree {
    param(
        [PSCustomObject[]]$Nodes,
        [int]$Indent = 2
    )
    foreach ($node in $Nodes) {
        $prefix = " " * $Indent
        $childCount = if ($node.Children) { $node.Children.Count } else { 0 }
        $childLabel = if ($childCount -gt 0) { " ($childCount sub-OU)" } else { " (leaf)" }
        Write-Host "${prefix}- OU=$($node.Name)$childLabel" -ForegroundColor Cyan
        if ($node.Children) {
            Show-OUTree -Nodes $node.Children -Indent ($Indent + 4)
        }
    }
}

$totalOUs = Get-OUCount -Nodes $config.OUStructure
$defaultProtection = if ($config.Settings.OUDefaults -and $null -ne $config.Settings.OUDefaults.ProtectedFromAccidentalDeletion) {
    $config.Settings.OUDefaults.ProtectedFromAccidentalDeletion
} else {
    $true
}

Write-Host ""
Write-Host "--- Configuration to deploy ---" -ForegroundColor White
Write-Host ""
Write-Host "  Config file       : $ConfigPath" -ForegroundColor Cyan
Write-Host "  Base DN           : $($config.Settings.BaseDN)" -ForegroundColor Cyan
Write-Host "  Deletion protection: $defaultProtection" -ForegroundColor Cyan
Write-Host "  Log directory     : $logDir" -ForegroundColor Cyan
Write-Host "  Total OU count    : $totalOUs" -ForegroundColor Cyan
Write-Host ""
Write-Host "  OU tree:" -ForegroundColor White

Show-OUTree -Nodes $config.OUStructure

# ============================================================================
# WhatIf mode: information
# ============================================================================

if ($WhatIfPreference) {
    Write-Host ""
    Write-Host "  >>> SIMULATION MODE (WhatIf) - No changes will be made <<<" -ForegroundColor Yellow
    Write-Host ""
}

# ============================================================================
# User confirmation
# ============================================================================

if (-not $WhatIfPreference -and -not $NoConfirm) {
    Write-Host ""
    $confirmation = Read-Host "Confirm deployment? (Y/N)"
    if ($confirmation -notin @("Y", "y", "Yes", "yes")) {
        Write-TieringLog -Message "Deployment cancelled by user." -Level Warning -LogDirectory $logDir
        exit 0
    }
    Write-Host ""
}

# ============================================================================
# Execute deployment
# ============================================================================

Write-TieringLog -Message "Starting Tiering deployment..." -Level Info -LogDirectory $logDir
Write-Host ""

$results = Deploy-TieringOUStructure -OUNodes $config.OUStructure `
                                      -ParentDN $config.Settings.BaseDN `
                                      -DefaultProtection $defaultProtection `
                                      -Server $targetServer `
                                      -Credential $connection.Credential `
                                      -LogDirectory $logDir `
                                      -WhatIf:$WhatIfPreference

# ============================================================================
# Summary
# ============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  DEPLOYMENT SUMMARY" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

$modeLabel = if ($WhatIfPreference) { " (SIMULATION)" } else { "" }

Write-Host "  OUs created$modeLabel             : $($results.OUsCreated)" -ForegroundColor Cyan
Write-Host "  OUs already present        : $($results.OUsExisting)" -ForegroundColor DarkGray

if ($results.Errors -gt 0) {
    Write-Host "  Errors                     : $($results.Errors)" -ForegroundColor Red
}
else {
    Write-Host "  Errors                     : 0" -ForegroundColor Green
}

Write-Host ""
if ($script:LogFilePath) {
    Write-Host "  Log file: $($script:LogFilePath)" -ForegroundColor Cyan
}
Write-Host ""
Write-TieringLog -Message "Deployment completed." -Level Info -LogDirectory $logDir
