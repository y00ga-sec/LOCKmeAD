<#
.SYNOPSIS
    GPO startup script that installs and updates the JIT Access Manager tool.
.DESCRIPTION
    This script is deployed via Group Policy as a machine startup script. It checks
    whether the JIT Access Manager tool needs to be installed or updated by comparing
    the version.txt on the distribution share with the local copy. If they differ
    (or the local copy doesn't exist), the tool is copied to the local install path
    and shortcuts are created on the Public Desktop and Start Menu.
.PARAMETER SourcePath
    UNC path to the distribution share containing the tool files.
.PARAMETER InstallPath
    Local path where the tool is installed. Default: C:\Program Files\JIT-Access
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SourcePath,

    [string]$InstallPath = "C:\Program Files\JIT-Access"
)

# ============================================================================
# Version check
# ============================================================================

$remoteVersionFile = Join-Path $SourcePath "version.txt"
$localVersionFile  = Join-Path $InstallPath "version.txt"

# Read remote version
$remoteVersion = $null
if (Test-Path $remoteVersionFile) {
    $remoteVersion = (Get-Content -Path $remoteVersionFile -Raw).Trim()
}
else {
    # No version file on share, nothing to deploy
    exit 0
}

# Read local version
$localVersion = $null
if (Test-Path $localVersionFile) {
    $localVersion = (Get-Content -Path $localVersionFile -Raw).Trim()
}

# Compare versions
if ($localVersion -eq $remoteVersion) {
    # Already up to date, nothing to do
    exit 0
}

# ============================================================================
# Install / Update
# ============================================================================

try {
    # Create install directory if needed
    if (-not (Test-Path $InstallPath)) {
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
    }

    # Copy all files from the distribution share to the install path
    Copy-Item -Path "$SourcePath\*" -Destination $InstallPath -Recurse -Force

    # Log to Windows Event Log
    $eventSource = "LOCKmeAD-JIT"
    if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
        [System.Diagnostics.EventLog]::CreateEventSource($eventSource, "Application")
    }
    $message = "JIT Access Manager installed/updated. Version: $remoteVersion. Source: $SourcePath. Path: $InstallPath."
    Write-EventLog -LogName "Application" -Source $eventSource -EventId 1000 -EntryType Information -Message $message
}
catch {
    # Attempt to log the error
    try {
        $eventSource = "LOCKmeAD-JIT"
        if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
            [System.Diagnostics.EventLog]::CreateEventSource($eventSource, "Application")
        }
        Write-EventLog -LogName "Application" -Source $eventSource -EventId 1001 -EntryType Error -Message "JIT Access Manager install failed: $_"
    }
    catch {
        # Cannot log, exit silently (startup script)
    }
    exit 1
}

# ============================================================================
# Create shortcuts
# ============================================================================

$shortcutName = "JIT Access Manager.lnk"
$targetExe    = "powershell.exe"
$arguments    = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallPath\Start-JIT.ps1`""

# Public Desktop shortcut
$desktopPath = Join-Path $env:PUBLIC "Desktop"
$desktopShortcut = Join-Path $desktopPath $shortcutName

if (-not (Test-Path $desktopShortcut)) {
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($desktopShortcut)
        $shortcut.TargetPath = $targetExe
        $shortcut.Arguments = $arguments
        $shortcut.WorkingDirectory = $InstallPath
        $shortcut.Description = "JIT Access Manager - Temporary AD group membership"
        $shortcut.Save()
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    }
    catch {
        # Non-fatal: continue even if shortcut creation fails
    }
}

# Start Menu shortcut
$startMenuPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
$startMenuShortcut = Join-Path $startMenuPath $shortcutName

if (-not (Test-Path $startMenuShortcut)) {
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($startMenuShortcut)
        $shortcut.TargetPath = $targetExe
        $shortcut.Arguments = $arguments
        $shortcut.WorkingDirectory = $InstallPath
        $shortcut.Description = "JIT Access Manager - Temporary AD group membership"
        $shortcut.Save()
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    }
    catch {
        # Non-fatal: continue even if shortcut creation fails
    }
}
