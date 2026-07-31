# ============================================================================
# Dashboard route -- web equivalent of GUI/Controller.ps1's Populate-Dashboard
# ============================================================================
# Dot-sourced inside Start-LOCKmeADWeb.ps1's Start-PodeServer scriptblock. The
# OU-counting helper is defined *inside* the route's own -ScriptBlock (as a
# self-referencing local scriptblock, not a top-level function) because route
# bodies are deferred and re-invoked per-request in a runspace that doesn't
# inherit functions or variables from this file's one-time dot-sourced
# execution -- only what's captured within that same deferred invocation
# survives (see the note in Start-LOCKmeADWeb.ps1).

Add-PodeRoute -Method Get -Path '/api/dashboard' -ScriptBlock {
    $conn = Get-PodeState -Name 'Connection'
    if (-not $conn) {
        Write-PodeJsonResponse -StatusCode 409 -Value @{ error = 'Not connected. POST /api/connect first.' }
        return
    }

    $rootDir = Get-PodeState -Name 'RootDir'

    try {
        # Built inline rather than via Connection.psm1's New-LOCKmeADConnectionParam --
        # that function doesn't reliably survive the module-scoping/runspace-snapshot
        # issue described in Start-LOCKmeADWeb.ps1 (same reason $countOUs below is a
        # local scriptblock instead of an imported function).
        $connParam = @{}
        if ($conn.Server)     { $connParam.Server     = $conn.Server }
        if ($conn.Credential) { $connParam.Credential = $conn.Credential }
        $domain      = Get-ADDomain @connParam
        $forest      = Get-ADForest @connParam
        $currentHost = if ($conn.Server) { $conn.Server } else { $env:COMPUTERNAME }
        $envInfo = @{
            currentDC   = $currentHost
            pdcEmulator = $domain.PDCEmulator
            domain      = $domain.DNSRoot
            forest      = $forest.Name
            domainMode  = $domain.DomainMode.ToString()
            forestMode  = $forest.ForestMode.ToString()
        }
    }
    catch {
        Write-PodeJsonResponse -StatusCode 502 -Value @{ error = "Unable to retrieve Active Directory information: $_" }
        return
    }

    $configPaths = @{
        Hardening = Join-Path $rootDir 'Config\Hardening-Config.json'
        GPO       = Join-Path $rootDir 'Config\GPO-Config.json'
        Tiering   = Join-Path $rootDir 'Config\Tiering-Config.json'
        RBAC      = Join-Path $rootDir 'Config\RBAC-Config.json'
        PSO       = Join-Path $rootDir 'Config\PSO-Config.json'
        Silo      = Join-Path $rootDir 'Config\Silo-Config.json'
        JIT       = Join-Path $rootDir 'Config\JIT-Config.json'
    }

    $summary = @{}

    try {
        if (Test-Path $configPaths.Hardening) {
            $cfg = Get-Content $configPaths.Hardening -Raw -Encoding UTF8 | ConvertFrom-Json
            $summary.Hardening = @{
                enabled = @($cfg.Tasks | Where-Object { $_.Enabled }).Count
                total   = $cfg.Tasks.Count
                label   = 'tasks enabled'
            }
        }
        if (Test-Path $configPaths.GPO) {
            $cfg = Get-Content $configPaths.GPO -Raw -Encoding UTF8 | ConvertFrom-Json
            $summary.GPO = @{
                enabled = @($cfg.GPOs | Where-Object { $_.Enabled }).Count
                total   = $cfg.GPOs.Count
                label   = 'GPOs enabled'
            }
        }
        if (Test-Path $configPaths.Tiering) {
            $cfg = Get-Content $configPaths.Tiering -Raw -Encoding UTF8 | ConvertFrom-Json
            # Self-referencing local scriptblock (mirrors Controller.ps1's
            # Count-TieringOUs) -- see file header for why this can't be a
            # top-level function here.
            $countOUs = {
                param($Nodes)
                $count = 0
                foreach ($node in $Nodes) {
                    $count++
                    if ($node.Children) { $count += (& $countOUs -Nodes $node.Children) }
                }
                return $count
            }
            $summary.Tiering = @{
                count = & $countOUs -Nodes $cfg.OUStructure
                label = 'OUs defined'
            }
        }
        if (Test-Path $configPaths.RBAC) {
            $cfg = Get-Content $configPaths.RBAC -Raw -Encoding UTF8 | ConvertFrom-Json
            $summary.RBAC = @{
                count = $cfg.Roles.Count
                label = 'roles defined'
            }
        }
        if (Test-Path $configPaths.PSO) {
            $cfg = Get-Content $configPaths.PSO -Raw -Encoding UTF8 | ConvertFrom-Json
            $summary.PSO = @{
                enabled = @($cfg.Policies | Where-Object { $_.Enabled }).Count
                total   = $cfg.Policies.Count
                label   = 'policies enabled'
            }
        }
        if (Test-Path $configPaths.Silo) {
            $cfg = Get-Content $configPaths.Silo -Raw -Encoding UTF8 | ConvertFrom-Json
            $summary.Silo = @{
                enabled = @($cfg.Silos | Where-Object { $_.Enabled }).Count
                total   = $cfg.Silos.Count
                label   = 'silos enabled'
            }
        }
        if (Test-Path $configPaths.JIT) {
            $cfg = Get-Content $configPaths.JIT -Raw -Encoding UTF8 | ConvertFrom-Json
            $summary.JIT = @{
                gpoConfigured = [bool]$cfg.Settings.GPO.Name
                linkCount     = @($cfg.Settings.GPO.LinkTargets).Count
                label         = 'link targets'
            }
        }
    }
    catch {
        Write-PodeJsonResponse -StatusCode 500 -Value @{ error = "Unable to read configuration files: $_" }
        return
    }

    Write-PodeJsonResponse -Value @{ environment = $envInfo; summary = $summary }
}
