# ============================================================================
# Config routes -- generic GET/PUT for Config/*.json
# ============================================================================
# Mirrors GUI/Controller.ps1's Load-AllConfigs/Save-AllConfigs pattern: the
# frontend owns the JSON shape entirely (loads it, mutates it via forms, saves
# it back whole) -- these routes are a thin, module-agnostic read/write layer,
# not a per-module business-logic layer. Structural validation happens at
# deploy time via each module's own Import-*Configuration function, same as
# it always has for hand-edited JSON.
#
# The module->filename map lives in Pode state ('ConfigModuleMap', set in
# Start-LOCKmeADWeb.ps1), not a plain variable here -- route -ScriptBlock bodies
# are deferred and re-invoked per-request in a runspace that doesn't inherit
# plain variables from this file's one-time dot-sourced execution (see the note
# in Start-LOCKmeADWeb.ps1).
#
# Dot-sourced inside Start-LOCKmeADWeb.ps1's Start-PodeServer scriptblock.

Add-PodeRoute -Method Get -Path '/api/config/:module' -ScriptBlock {
    $moduleName = $WebEvent.Parameters['module']
    $fileName   = (Get-PodeState -Name 'ConfigModuleMap')[$moduleName]
    if (-not $fileName) {
        Write-PodeJsonResponse -StatusCode 404 -Value @{ error = "Unknown module '$moduleName'." }
        return
    }

    $rootDir = Get-PodeState -Name 'RootDir'
    $path    = Join-Path $rootDir "Config\$fileName"
    if (-not (Test-Path $path)) {
        Write-PodeJsonResponse -StatusCode 404 -Value @{ error = "Config file not found: $path" }
        return
    }

    try {
        $json = Get-Content -Path $path -Raw -Encoding UTF8 | ConvertFrom-Json
        Write-PodeJsonResponse -Value $json -Depth 20
    }
    catch {
        Write-PodeJsonResponse -StatusCode 500 -Value @{ error = "Unable to read config: $_" }
    }
}

Add-PodeRoute -Method Put -Path '/api/config/:module' -ScriptBlock {
    $moduleName = $WebEvent.Parameters['module']
    $fileName   = (Get-PodeState -Name 'ConfigModuleMap')[$moduleName]
    if (-not $fileName) {
        Write-PodeJsonResponse -StatusCode 404 -Value @{ error = "Unknown module '$moduleName'." }
        return
    }

    $rootDir = Get-PodeState -Name 'RootDir'
    $path    = Join-Path $rootDir "Config\$fileName"

    try {
        # $WebEvent.Data is the whole request body, already JSON-parsed by Pode --
        # re-serialize it back to disk, same approach as Controller.ps1's
        # Save-AllConfigs (ConvertTo-Json | Set-Content).
        $json = $WebEvent.Data | ConvertTo-Json -Depth 20
        Set-Content -Path $path -Value $json -Encoding UTF8
        Write-PodeJsonResponse -Value @{ saved = $true }
    }
    catch {
        Write-PodeJsonResponse -StatusCode 500 -Value @{ error = "Unable to save config: $_" }
    }
}
