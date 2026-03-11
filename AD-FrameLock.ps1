#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD-FrameLock - Active Directory Security Framework.
.DESCRIPTION
    Main entry point for the AD-FrameLock tool suite. Displays a menu to launch
    individual deployment modules (Hardening, GPO, Tiering, RBAC) or the GUI.
.PARAMETER Module
    Directly launch a specific module: Hardening, GPO, Tiering, RBAC, or GUI.
.PARAMETER WhatIf
    Simulation mode: passed through to deployment scripts.
.EXAMPLE
    .\AD-FrameLock.ps1
    .\AD-FrameLock.ps1 -Module GUI
    .\AD-FrameLock.ps1 -Module Hardening -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("Hardening", "GPO", "Tiering", "RBAC", "All", "GUI")]
    [string]$Module
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Display logo
# ============================================================================

function Show-Logo {
    $logoPath = Join-Path $PSScriptRoot "Assets\logo.txt"
    if (Test-Path $logoPath) {
        Write-Host ""
        $logo = Get-Content $logoPath -Raw
        Write-Host $logo -ForegroundColor DarkCyan
    }
    Write-Host "         A D - F r a m e L o c k" -ForegroundColor Cyan
    Write-Host "       Active Directory Security Framework" -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================================================
# Deploy All (safe order: Hardening > Tiering > RBAC > GPO)
# ============================================================================

function Start-AllDeployments {
    $modules = @(
        @{ Name = "Hardening"; Script = "Deploy-Hardening.ps1" }
        @{ Name = "Tiering";   Script = "Deploy-Tiering.ps1" }
        @{ Name = "RBAC";      Script = "Deploy-RBAC.ps1" }
        @{ Name = "GPO";       Script = "Deploy-GPO.ps1" }
    )
    foreach ($mod in $modules) {
        $path = Join-Path $PSScriptRoot "Scripts\$($mod.Script)"
        if (Test-Path $path) {
            Write-Host ""
            Write-Host "  ============================================" -ForegroundColor White
            Write-Host "  Deploying: $($mod.Name)" -ForegroundColor Cyan
            Write-Host "  ============================================" -ForegroundColor White
            & $path -WhatIf:$WhatIfPreference
        }
        else {
            Write-Host "  [ERROR] Script not found: $path" -ForegroundColor Red
        }
    }
}

# ============================================================================
# Direct module launch
# ============================================================================

if ($Module) {
    Show-Logo
    switch ($Module) {
        "GUI" { & "$PSScriptRoot\Launch-GUI.ps1" }
        "All" { Start-AllDeployments }
        default {
            $scriptPath = Join-Path $PSScriptRoot "Scripts\Deploy-$Module.ps1"
            if (Test-Path $scriptPath) {
                & $scriptPath -WhatIf:$WhatIfPreference
            }
            else {
                Write-Host "  [ERROR] Script not found: $scriptPath" -ForegroundColor Red
            }
        }
    }
    return
}

# ============================================================================
# Interactive menu with arrow-key navigation
# ============================================================================

$menuItems = @(
    @{ Label = "Deploy All"; Desc = "Hardening > Tiering > RBAC > GPO" }
    @{ Label = "Hardening";  Desc = "AD remediation tasks" }
    @{ Label = "Tiering";    Desc = "OU structure deployment" }
    @{ Label = "RBAC";       Desc = "Role-based access control" }
    @{ Label = "GPO";        Desc = "Security GPO deployment" }
    @{ Label = "GUI";        Desc = "Launch graphical interface" }
    @{ Label = "Quit";       Desc = "" }
)

$selected = 0
$esc = [char]27
$menuCount = $menuItems.Count

Show-Logo
Write-Host "  Select a module (use arrow keys, Enter to confirm):" -ForegroundColor White
Write-Host ""

# Build formatted lines
$lines = @()
foreach ($item in $menuItems) {
    $text = "$($item.Label)"
    if ($item.Desc) { $text += "   - $($item.Desc)" }
    $lines += $text
}

# Draw full menu
function Draw-Menu([int]$sel) {
    # Move cursor up to top of menu area
    Write-Host "$esc[$menuCount`A" -NoNewline
    for ($i = 0; $i -lt $menuCount; $i++) {
        # Clear line, then write
        Write-Host "$esc[2K" -NoNewline
        if ($i -eq $sel) {
            Write-Host "  >  $($lines[$i])" -ForegroundColor Cyan
        }
        else {
            Write-Host "     $($lines[$i])" -ForegroundColor DarkGray
        }
    }
}

# Initial draw
for ($i = 0; $i -lt $menuCount; $i++) {
    if ($i -eq $selected) {
        Write-Host "  >  $($lines[$i])" -ForegroundColor Cyan
    }
    else {
        Write-Host "     $($lines[$i])" -ForegroundColor DarkGray
    }
}

try { [Console]::CursorVisible = $false } catch {}

while ($true) {
    $key = [Console]::ReadKey($true)

    switch ($key.Key) {
        'UpArrow' {
            $selected = if ($selected -le 0) { $menuCount - 1 } else { $selected - 1 }
        }
        'DownArrow' {
            $selected = if ($selected -ge $menuCount - 1) { 0 } else { $selected + 1 }
        }
        'Enter' { break }
    }
    if ($key.Key -eq 'Enter') { break }

    Draw-Menu $selected
}

try { [Console]::CursorVisible = $true } catch {}
Write-Host ""

switch ($selected) {
    0 { Start-AllDeployments }
    1 { & "$PSScriptRoot\Scripts\Deploy-Hardening.ps1" -WhatIf:$WhatIfPreference }
    2 { & "$PSScriptRoot\Scripts\Deploy-Tiering.ps1" -WhatIf:$WhatIfPreference }
    3 { & "$PSScriptRoot\Scripts\Deploy-RBAC.ps1" -WhatIf:$WhatIfPreference }
    4 { & "$PSScriptRoot\Scripts\Deploy-GPO.ps1" -WhatIf:$WhatIfPreference }
    5 { & "$PSScriptRoot\Launch-GUI.ps1" }
    6 { Write-Host "  Exiting." -ForegroundColor DarkGray }
}
