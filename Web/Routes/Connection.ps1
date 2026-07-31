# ============================================================================
# Connection routes -- web equivalent of GUI/Controller.ps1's Show-GUIConnectionDialog
# ============================================================================
# Dot-sourced inside Start-LOCKmeADWeb.ps1's Start-PodeServer scriptblock.
#
# Resolve-LOCKmeADConnection/Remove-LOCKmeADConnection (Modules/Common/Connection.psm1)
# are NOT reliably resolvable inside a route body even via Import-PodeModule -- the
# same nested-module-scoping issue documented in HANDOFF.md gotcha #3 (each of the 7
# feature modules' own internal `Import-Module Connection.psm1 -Force` can re-nest
# Connection under itself again when Pode recaptures its runspace-pool module
# snapshot, undoing the "import Connection last" fix). Confirmed in practice: it broke
# Dashboard.ps1's New-LOCKmeADConnectionParam call (fixed by inlining it there) and
# then broke here too, on Resolve-LOCKmeADConnection. Resolve-LOCKmeADConnection is too
# large/stateful to inline like that helper was.
#
# First attempt was `. (Join-Path $rootDir '...\Connection.psm1')` (plain dot-source of
# the file by path) -- worked on the first /api/connect call after a server restart,
# then failed again ("not recognized") on a later connect in the same still-running
# server. Root cause: once any of the 7 feature modules' own internal
# `Import-Module Connection.psm1 -Force` has registered that *same file path* as a
# real module somewhere in this runspace (which normal use of the app triggers), a
# later plain `.` dot-source of that identical path stops behaving like independent
# script execution -- PowerShell's module system reuses/rebinds it, so the functions
# never land back in THIS scriptblock's own scope. Confirmed by the "worked once,
# then didn't, on the same running server" pattern.
#
# Fix: load the file's raw text and compile it into a brand-new anonymous scriptblock
# via [scriptblock]::Create() before dot-sourcing that. An anonymous scriptblock has
# no file-path identity for PowerShell's module system to recognize or rebind, so this
# is immune to the above regardless of what else has loaded/nested Connection.psm1
# elsewhere in the runspace -- every call gets fresh, independent function
# definitions in this scriptblock's own scope, deterministically.
#
# This has to be inlined at the top of every route body that needs it, not factored
# into a shared function here -- per gotcha #2, a function merely dot-sourced during
# this file's one-time setup-time execution is itself invisible inside a route body.

Add-PodeRoute -Method Get -Path '/api/connection' -ScriptBlock {
    $conn = Get-PodeState -Name 'Connection'
    if (-not $conn) {
        Write-PodeJsonResponse -Value @{ connected = $false; mode = 'none'; server = $null }
        return
    }
    $mode = if ($conn.Server) { 'explicit' } else { 'implicit' }
    Write-PodeJsonResponse -Value @{ connected = $true; mode = $mode; server = $conn.Server }
}

Add-PodeRoute -Method Post -Path '/api/connect' -ScriptBlock {
    $data       = $WebEvent.Data
    $serverName = "$($data.server)".Trim()
    $username   = "$($data.username)".Trim()
    $password   = "$($data.password)"
    $remember   = [bool]$data.remember

    if ([string]::IsNullOrWhiteSpace($serverName)) {
        Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Domain controller is required.' }
        return
    }
    if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {
        Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Username and password are required.' }
        return
    }

    try {
        $rootDir = Get-PodeState -Name 'RootDir'
        $connSrc = Get-Content -Path (Join-Path $rootDir 'Modules\Common\Connection.psm1') -Raw
        try { . ([scriptblock]::Create($connSrc)) } catch { }

        $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
        $cred   = [PSCredential]::new($username, $secure)
        $conn   = Resolve-LOCKmeADConnection -Server $serverName -Credential $cred -Remember:$remember
        Set-PodeState -Name 'Connection' -Value $conn | Out-Null
        Write-PodeJsonResponse -Value @{ connected = $true; mode = 'explicit'; server = $conn.Server }
    }
    catch {
        Write-PodeJsonResponse -StatusCode 400 -Value @{ error = "$_" }
    }
}

Add-PodeRoute -Method Post -Path '/api/disconnect' -ScriptBlock {
    $data = $WebEvent.Data
    if ([bool]$data.forget) {
        $rootDir = Get-PodeState -Name 'RootDir'
        $connSrc = Get-Content -Path (Join-Path $rootDir 'Modules\Common\Connection.psm1') -Raw
        try { . ([scriptblock]::Create($connSrc)) } catch { }
        Remove-LOCKmeADConnection
    }
    Set-PodeState -Name 'Connection' -Value $null | Out-Null
    Write-PodeJsonResponse -Value @{ connected = $false }
}
