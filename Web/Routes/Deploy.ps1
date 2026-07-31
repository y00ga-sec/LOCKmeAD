# ============================================================================
# Deploy routes -- runs Scripts/Deploy-*.ps1 in the background and streams its
# output live to the browser via SSE.
# ============================================================================
# Mirrors GUI/Controller.ps1's Start-SingleDeployment: same -ConfigPath/-NoConfirm/
# -Server/-Credential/-WhatIf splat, same script per module. The one thing this
# fixes rather than ports: Start-SingleDeployment's `2>&1` only merges the error
# stream, so it never actually captured Write-Host output (every Write-*Log
# function in every module writes via Write-Host, which targets the Information
# stream). This uses `*>&1` -- confirmed empirically to capture Write-Host,
# Write-Warning, Write-Error, and Write-Output uniformly, including the
# Write-Host ForegroundColor via InformationRecord.MessageData.
#
# The module->script filename map lives in Pode state ('DeployScriptMap', set in
# Start-LOCKmeADWeb.ps1), not a plain variable here -- see the note there on why
# route/task -ScriptBlock bodies can't rely on plain variables from this file's
# one-time dot-sourced execution.
#
# Dot-sourced inside Start-LOCKmeADWeb.ps1's Start-PodeServer scriptblock.

# Registered once at server startup (Start-LOCKmeADWeb.ps1); triggered per
# deployment via Invoke-PodeTask with per-call -ArgumentList.
Add-PodeTask -Name 'RunLOCKmeADDeploy' -ScriptBlock {
    param($JobId, $ScriptPath, $ConfigPath, $Server, $Credential, $WhatIf)

    $deployJobs = Get-PodeState -Name 'DeployJobs'
    $job = $deployJobs[$JobId]

    function ConvertTo-LOCKmeADWebLogLine {
        param($Item)
        if ($Item -is [System.Management.Automation.InformationRecord]) {
            return @{ text = "$($Item.MessageData)"; color = "$($Item.MessageData.ForegroundColor)" }
        }
        if ($Item -is [System.Management.Automation.ErrorRecord]) {
            return @{ text = "$Item"; color = 'Red' }
        }
        if ($Item -is [System.Management.Automation.WarningRecord]) {
            return @{ text = "$Item"; color = 'Yellow' }
        }
        return @{ text = "$Item"; color = 'Gray' }
    }

    $callParams = @{
        ConfigPath = $ConfigPath
        NoConfirm  = $true
    }
    if ($Server)     { $callParams.Server     = $Server }
    if ($Credential) { $callParams.Credential = $Credential }
    if ($WhatIf)      { $callParams.WhatIf     = $true }

    try {
        & $ScriptPath @callParams *>&1 | ForEach-Object {
            $line = ConvertTo-LOCKmeADWebLogLine -Item $_
            $job.Lines.Enqueue($line)
            Send-PodeSseEvent -Name 'deploy' -Group $JobId -Data $line
        }
        $job.Success = $true
    }
    catch {
        $errLine = @{ text = "$_"; color = 'Red' }
        $job.Lines.Enqueue($errLine)
        Send-PodeSseEvent -Name 'deploy' -Group $JobId -Data $errLine
        $job.Success = $false
    }
    finally {
        $job.Completed = $true
        Send-PodeSseEvent -Name 'deploy' -Group $JobId -Data @{ done = $true; success = $job.Success } -EventType 'done'
        Close-PodeSseConnection -Name 'deploy' -Group $JobId
    }
}

Add-PodeRoute -Method Post -Path '/api/deploy/:module' -ScriptBlock {
    $moduleName = $WebEvent.Parameters['module']
    $scriptFile = (Get-PodeState -Name 'DeployScriptMap')[$moduleName]
    if (-not $scriptFile) {
        Write-PodeJsonResponse -StatusCode 404 -Value @{ error = "Unknown module '$moduleName'." }
        return
    }

    $conn = Get-PodeState -Name 'Connection'
    if (-not $conn) {
        Write-PodeJsonResponse -StatusCode 409 -Value @{ error = 'Not connected. POST /api/connect first.' }
        return
    }

    $rootDir   = Get-PodeState -Name 'RootDir'
    $scriptPath = Join-Path $rootDir "Scripts\$scriptFile"
    $configPath = Join-Path $rootDir "Config\$moduleName-Config.json"
    $whatIf     = [bool]($WebEvent.Data.whatIf)

    if (-not (Test-Path $scriptPath)) {
        Write-PodeJsonResponse -StatusCode 500 -Value @{ error = "Deploy script not found: $scriptPath" }
        return
    }

    # Unlike every other route in this app, this one used to have no try/catch: any
    # exception here (bad script/config path, Invoke-PodeTask failure, etc.) fell
    # through to Pode's own HTML error page instead of Write-PodeJsonResponse. The
    # frontend's `await res.json()` (app.js deploy()) then throws "SyntaxError:
    # Unexpected token '<' ... is not valid JSON" trying to parse that HTML as JSON --
    # confirmed by reproducing it directly against Pode. Wrapping this in try/catch,
    # like Connection.ps1/Config.ps1/Dashboard.ps1 already do, guarantees a JSON
    # response either way.
    try {
        $jobId = [guid]::NewGuid().ToString()
        $deployJobs = Get-PodeState -Name 'DeployJobs'
        $deployJobs[$jobId] = @{
            Lines     = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
            Completed = $false
            Success   = $null
        }

        Invoke-PodeTask -Name 'RunLOCKmeADDeploy' -ArgumentList @{
            JobId      = $jobId
            ScriptPath = $scriptPath
            ConfigPath = $configPath
            Server     = $conn.Server
            Credential = $conn.Credential
            WhatIf     = $whatIf
        } | Out-Null

        Write-PodeJsonResponse -Value @{ jobId = $jobId }
    }
    catch {
        Write-PodeJsonResponse -StatusCode 500 -Value @{ error = "Unable to start deployment: $_" }
    }
}

Add-PodeRoute -Method Get -Path '/api/deploy/:jobId/stream' -ScriptBlock {
    $jobId = $WebEvent.Parameters['jobId']
    $deployJobs = Get-PodeState -Name 'DeployJobs'
    if (-not $deployJobs.ContainsKey($jobId)) {
        Write-PodeJsonResponse -StatusCode 404 -Value @{ error = 'Unknown deployment job.' }
        return
    }

    ConvertTo-PodeSseConnection -Name 'deploy' -Group $jobId -Scope Global -Force

    # Replay everything captured so far -- covers the race where the browser's
    # EventSource connects after the task has already produced output (the task
    # starts immediately on POST, before the client has had a chance to open the
    # stream), and lets a page refresh mid-deployment see the full log again.
    $job = $deployJobs[$jobId]
    foreach ($line in $job.Lines.ToArray()) {
        Send-PodeSseEvent -Name 'deploy' -Group $jobId -Data $line
    }
    if ($job.Completed) {
        Send-PodeSseEvent -Name 'deploy' -Group $jobId -Data @{ done = $true; success = $job.Success } -EventType 'done'
        Close-PodeSseConnection -Name 'deploy' -Group $jobId
    }
}
