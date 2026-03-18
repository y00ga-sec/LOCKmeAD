#Requires -RunAsAdministrator

<#
.SYNOPSIS
    LOCKmeAD - Active Directory Security Framework.
.DESCRIPTION
    Main entry point for the LOCKmeAD tool suite. Displays a menu to launch
    individual deployment modules (Hardening, GPO, Tiering, RBAC) or the GUI.
    Multiple modules can be selected and are executed in safe dependency order:
    Hardening > Tiering > RBAC > GPO.
.PARAMETER Module
    One or more modules to deploy: Hardening, GPO, Tiering, RBAC, All, or GUI.
    Accepts a comma-separated list (e.g. -Module Tiering,GPO).
.PARAMETER WhatIf
    Simulation mode: passed through to deployment scripts.
.EXAMPLE
    .\LOCKmeAD.ps1
    .\LOCKmeAD.ps1 -Module GUI
    .\LOCKmeAD.ps1 -Module Hardening -WhatIf
    .\LOCKmeAD.ps1 -Module Tiering,GPO
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("Hardening", "GPO", "Tiering", "RBAC", "PSO", "Silo", "All", "GUI", "JIT")]
    [string[]]$Module
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
    Write-Host "            L O C K m e A D" -ForegroundColor Cyan
    Write-Host "       Active Directory Security Framework" -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================================================
# Deploy selected modules (safe order: Hardening > Tiering > RBAC > PSO > Silo > GPO > JIT)
# ============================================================================

# Canonical execution order: infrastructure first, then OU-dependent modules
$script:SafeOrder = @(
    @{ Name = "Hardening"; Script = "Deploy-Hardening.ps1" }
    @{ Name = "Tiering";   Script = "Deploy-Tiering.ps1" }
    @{ Name = "RBAC";      Script = "Deploy-RBAC.ps1" }
    @{ Name = "PSO";       Script = "Deploy-PSO.ps1" }
    @{ Name = "Silo";      Script = "Deploy-Silo.ps1" }
    @{ Name = "GPO";       Script = "Deploy-GPO.ps1" }
    @{ Name = "JIT";       Script = "Deploy-JIT.ps1" }
)

function Start-SelectedDeployments([string[]]$Selected) {
    # Filter and keep safe order
    $toRun = $script:SafeOrder | Where-Object { $Selected -contains $_.Name }
    if ($toRun.Count -eq 0) {
        Write-Host "  No modules selected." -ForegroundColor Yellow
        return
    }
    foreach ($mod in $toRun) {
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
    if ($Module -contains "GUI") {
        & "$PSScriptRoot\Launch-GUI.ps1"
        return
    }
    $selected = @($Module | ForEach-Object { if ($_ -eq "All") { "Hardening","Tiering","RBAC","PSO","Silo","GPO","JIT" } else { $_ } }) | Select-Object -Unique
    Start-SelectedDeployments $selected
    return
}

# ============================================================================
# Interactive menu with multi-select (Space to toggle, Enter to deploy)
# ============================================================================

$menuItems = @(
    @{ Label = "Hardening"; Desc = "AD remediation tasks";     Checked = $false }
    @{ Label = "Tiering";   Desc = "OU structure deployment";  Checked = $false }
    @{ Label = "RBAC";      Desc = "Role-based access control"; Checked = $false }
    @{ Label = "PSO";       Desc = "Password policy objects";     Checked = $false }
    @{ Label = "Silo";      Desc = "Authentication policy silos"; Checked = $false }
    @{ Label = "GPO";       Desc = "Security GPO deployment";    Checked = $false }
    @{ Label = "JIT";       Desc = "JIT tool deployment (GPO)";  Checked = $false }
)
$extraItems = @(
    @{ Label = "Deploy"; Desc = "Deploy selected modules" }
    @{ Label = "All";    Desc = "Select all and deploy" }
    @{ Label = "GUI";    Desc = "Launch graphical interface" }
    @{ Label = "Quit";   Desc = "" }
)

$cursor = 0
$esc = [char]27
$totalLines = $menuItems.Count + 1 + $extraItems.Count  # +1 for separator
$deployItems = $menuItems.Count

Show-Logo
Write-Host "  Select modules (Space/Enter to toggle, A = all, N = none):" -ForegroundColor White
Write-Host "  Execution order: Hardening > Tiering > RBAC > PSO > Silo > GPO > JIT" -ForegroundColor DarkGray
Write-Host ""

function Get-MenuLine([int]$i, [int]$cur) {
    $isCursor = ($i -eq $cur)
    $arrow = if ($isCursor) { ">" } else { " " }

    if ($i -lt $deployItems) {
        $item = $menuItems[$i]
        $check = if ($item.Checked) { "[X]" } else { "[ ]" }
        $text = "$check $($item.Label)   - $($item.Desc)"
        $color = if ($isCursor) { "Cyan" } elseif ($item.Checked) { "Green" } else { "DarkGray" }
    }
    elseif ($i -eq $deployItems) {
        # Separator line (not selectable, just for display)
        return @{ Text = "     ---"; Color = "DarkGray" }
    }
    else {
        $extra = $extraItems[$i - $deployItems - 1]
        $text = "    $($extra.Label)"
        if ($extra.Desc) { $text += "   - $($extra.Desc)" }
        $color = if ($isCursor) { "Cyan" } else { "DarkGray" }
    }

    return @{ Text = "  $arrow  $text"; Color = $color }
}

# Initial draw
for ($i = 0; $i -lt $totalLines; $i++) {
    $line = Get-MenuLine $i $cursor
    Write-Host $line.Text -ForegroundColor $line.Color
}

function Draw-MultiMenu([int]$cur) {
    Write-Host "$esc[$totalLines`A" -NoNewline
    for ($i = 0; $i -lt $totalLines; $i++) {
        Write-Host "$esc[2K" -NoNewline
        $line = Get-MenuLine $i $cur
        Write-Host $line.Text -ForegroundColor $line.Color
    }
}

try { [Console]::CursorVisible = $false } catch {}

$action = $null
while ($true) {
    $key = [Console]::ReadKey($true)

    switch ($key.Key) {
        'UpArrow' {
            $cursor = if ($cursor -le 0) { $totalLines - 1 } else { $cursor - 1 }
            # Skip separator
            if ($cursor -eq $deployItems) {
                $cursor = if ($cursor -le 0) { $totalLines - 1 } else { $cursor - 1 }
            }
        }
        'DownArrow' {
            $cursor = if ($cursor -ge $totalLines - 1) { 0 } else { $cursor + 1 }
            # Skip separator
            if ($cursor -eq $deployItems) {
                $cursor = if ($cursor -ge $totalLines - 1) { 0 } else { $cursor + 1 }
            }
        }
        'Spacebar' {
            if ($cursor -lt $deployItems) {
                $menuItems[$cursor].Checked = -not $menuItems[$cursor].Checked
            }
        }
        'A' {
            # Select all
            foreach ($item in $menuItems) { $item.Checked = $true }
        }
        'N' {
            # Deselect all
            foreach ($item in $menuItems) { $item.Checked = $false }
        }
        'Enter' {
            if ($cursor -lt $deployItems) {
                # Enter on a module item = toggle (same as Space)
                $menuItems[$cursor].Checked = -not $menuItems[$cursor].Checked
            }
            elseif ($cursor -eq ($deployItems + 1)) {
                # Deploy selected
                $action = "deploy"
                break
            }
            elseif ($cursor -eq ($deployItems + 2)) {
                # All: select all modules and deploy
                foreach ($item in $menuItems) { $item.Checked = $true }
                $action = "deploy"
                break
            }
            elseif ($cursor -eq ($deployItems + 3)) {
                # GUI
                $action = "gui"
                break
            }
            elseif ($cursor -eq ($deployItems + 4)) {
                # Quit
                $action = "quit"
                break
            }
        }
    }
    if ($action) { break }

    Draw-MultiMenu $cursor
}

try { [Console]::CursorVisible = $true } catch {}
Write-Host ""

switch ($action) {
    "deploy" {
        $selected = @($menuItems | Where-Object { $_.Checked } | ForEach-Object { $_.Label })
        if ($selected.Count -eq 0) {
            Write-Host "  No modules selected." -ForegroundColor Yellow
        }
        else {
            Write-Host "  Deploying: $($selected -join ' > ')" -ForegroundColor Cyan
            Write-Host ""
            Start-SelectedDeployments $selected
        }
    }
    "gui" { & "$PSScriptRoot\Launch-GUI.ps1" }
    "quit" { Write-Host "  Exiting." -ForegroundColor DarkGray }
}
