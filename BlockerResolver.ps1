<<#
.SYNOPSIS
    Ocean Anticheat Universal Blocker Neutralizer
.DESCRIPTION
    Behavior-based detection engine that identifies and destroys ANY process,
    script, or WMI subscription attempting to terminate or block applications
    signed by Gaston Dallavalle / Inspect Element Ltd.
    Resilient against filename changes, encoding obfuscation, and process renaming.
.NOTES
    Must be run as Administrator.
#>

#Requires -RunAsAdministrator

# ==================== CONFIGURATION ====================
$TARGET_SIGNERS = @("Gaston Dallavalle", "Inspect Element Ltd")
$KILL_DNA       = @('Stop-Process','Terminate()','taskkill','wmi.*Terminate','Kill()','TerminateProcess')
$WMI_DNA        = @('__InstanceCreationEvent','__InstanceDeletionEvent','Register-WmiEvent')
$LOG_PATH       = "$env:TEMP\OceanGuardian_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$SCAN_INTERVAL  = 1

# ==================== BANNER ====================
function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "   ███╗  ██╗ ██████╗ ███╗   ███╗███████╗    ███████╗███████╗" -ForegroundColor Green
    Write-Host "   ████╗ ██║██╔══██╗████╗ ████║██╔════╝    ██╔════╝██╔════╝" -ForegroundColor Green
    Write-Host "   ██╔██╗██║██████╔╝██╔████╔██║█████╗      ███████╗███████╗" -ForegroundColor Green
    Write-Host "   ██║╚████║██╔══██╗██║╚██╔╝██║██╔══╝      ╚════██║╚════██║" -ForegroundColor Green
    Write-Host "   ██║ ╚███║██████╔╝██║ ╚═╝ ██║███████╗    ███████║███████║" -ForegroundColor Green
    Write-Host "   ╚═╝  ╚══╝╚═════╝ ╚═╝     ╚═╝╚══════╝    ╚══════╝╚══════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "   Ocean Anticheat Universal Blocker Neutralizer" -ForegroundColor Cyan
    Write-Host "   Detection Mode: BEHAVIORAL + SIGNATURE DNA" -ForegroundColor Yellow
    Write-Host "   Countermeasures: ACTIVE INTERDICTION + LIVE GUARD" -ForegroundColor Magenta
    Write-Host ""
}

# ==================== LOGGING ====================
function Write-GuardLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $LOG_PATH -Value $line -ErrorAction SilentlyContinue
    switch ($Level) {
        "OK"      { Write-Host $line -ForegroundColor Green }
        "WARN"    { Write-Host $line -ForegroundColor Yellow }
        "ALERT"   { Write-Host $line -ForegroundColor Magenta }
        "KILL"    { Write-Host $line -ForegroundColor Red }
        "GUARD"   { Write-Host $line -ForegroundColor Cyan }
        default   { Write-Host $line -ForegroundColor White }
    }
}

# ==================== COMMAND LINE FETCHER ====================
function Get-ProcessCommandLine {
    param([int]$ProcessId)
    try {
        $p = Get-WmiObject Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
        return $p.CommandLine
    } catch { return $null }
}

# ==================== DNA ANALYZER ====================
function Test-BlockerDNA {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
    
    $decoded = $null
    $sample = $CommandLine
    
    # If encoded, decode it
    if ($CommandLine -match '-(?:EncodedCommand|e[c]?)\s+([A-Za-z0-9+/=]{100,})') {
        try {
            $b64 = $matches[1].Trim('"').Trim("'")
            $decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
            $sample = $decoded
        } catch {}
    }
    
    # Must contain a target signer
    $hasSigner = $false
    foreach ($signer in $TARGET_SIGNERS) {
        if ($sample -like "*$signer*") { $hasSigner = $true; break }
    }
    if (-not $hasSigner) { return $false }
    
    # Must contain a kill/terminate mechanism
    $hasKill = $false
    foreach ($pattern in $KILL_DNA) {
        if ($sample -match $pattern) { $hasKill = $true; break }
    }
    
    # Must contain WMI process monitoring OR direct process/signature enumeration
    $hasWmi = $false
    foreach ($pattern in $WMI_DNA) {
        if ($sample -like "*$pattern*") { $hasWmi = $true; break }
    }
    $hasEnum = $sample -match 'Get-Process|Get-WmiObject.*Win32_Process|Get-AuthenticodeSignature'
    
    return ($hasSigner -and $hasKill -and ($hasWmi -or $hasEnum))
}

# ==================== THREAT HUNTER ====================
function Find-BlockerThreats {
    $threats = @()
    
    # 1. PowerShell / Pwsh processes with blocker DNA
    Get-Process -Name "powershell","pwsh" -ErrorAction SilentlyContinue | ForEach-Object {
        $procId = $_.Id
        $cmd = Get-ProcessCommandLine -ProcessId $procId
        if (Test-BlockerDNA -CommandLine $cmd) {
            $threats += [PSCustomObject]@{
                Id   = $procId
                Name = $_.Name
                Type = "Encoded_Blocker"
                DNA  = "Signer+Kill+WMI"
                Cmd  = if ($cmd) { $cmd.Substring(0, [Math]::Min(200, $cmd.Length)) } else { "N/A" }
            }
        }
    }
    
    # 2. WScript / CScript launching PowerShell from temp (universal script launcher detection)
    Get-Process -Name "wscript","cscript" -ErrorAction SilentlyContinue | ForEach-Object {
        $procId = $_.Id
        $cmd = Get-ProcessCommandLine -ProcessId $procId
        if ($cmd -and ($cmd -like "*$env:TEMP*" -or $cmd -like "*powershell*" -or $cmd -like "*-EncodedCommand*")) {
            $isSuspicious = $false
            # Try to read the script file if path is in command line
            if ($cmd -match '"([^"]+\.(vbs|js|wsf|hta))"') {
                $scriptPath = $matches[1]
                if (Test-Path $scriptPath) {
                    $content = Get-Content $scriptPath -Raw -ErrorAction SilentlyContinue
                    if ($content -and (
                        ($content -like "*powershell*") -or
                        ($content -like "*CreateObject*") -or
                        ($content -like "*Shell*")
                    )) { $isSuspicious = $true }
                }
            } else {
                $isSuspicious = $true
            }
            
            if ($isSuspicious) {
                $threats += [PSCustomObject]@{
                    Id   = $procId
                    Name = $_.Name
                    Type = "Script_Launcher"
                    DNA  = "TempScript+PSLauncher"
                    Cmd  = if ($cmd) { $cmd.Substring(0, [Math]::Min(200, $cmd.Length)) } else { "N/A" }
                }
            }
        }
    }
    
    # 3. Any process with Register-WmiEvent + signer in command line
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('powershell','pwsh','wscript','cscript') } | ForEach-Object {
        $procId = $_.Id
        $cmd = Get-ProcessCommandLine -ProcessId $procId
        if ($cmd -and $cmd -like "*Register-WmiEvent*" -and $cmd -like "*__Instance*") {
            if (Test-BlockerDNA -CommandLine $cmd) {
                $threats += [PSCustomObject]@{
                    Id   = $procId
                    Name = $_.Name
                    Type = "WMI_Host"
                    DNA  = "Register-WmiEvent+Signer"
                    Cmd  = $cmd.Substring(0, [Math]::Min(200, $cmd.Length))
                }
            }
        }
    }
    
    # 4. Permanent WMI subscriptions (rare but dangerous)
    try {
        $bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
        foreach ($b in $bindings) {
            $filter = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "__PATH='$($b.Filter)'" -ErrorAction SilentlyContinue
            $consumer = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -Filter "__PATH='$($b.Consumer)'" -ErrorAction SilentlyContinue
            if ($filter -and $consumer) {
                $fText = "$($filter.Query) $($consumer.CommandLineTemplate) $($consumer.ScriptText)"
                if (Test-BlockerDNA -CommandLine $fText) {
                    Write-GuardLog "PERMANENT WMI SUBSCRIPTION DETECTED: $($filter.Name)" "ALERT"
                    Remove-WmiObject -Path $b.__PATH -ErrorAction SilentlyContinue
                    Remove-WmiObject -Path $filter.__PATH -ErrorAction SilentlyContinue
                    Remove-WmiObject -Path $consumer.__PATH -ErrorAction SilentlyContinue
                    Write-GuardLog "Destroyed permanent WMI subscription." "KILL"
                }
            }
        }
    } catch {}
    
    return $threats
}

# ==================== NEUTRALIZER ====================
function Stop-ThreatProcess {
    param([int]$ProcessId, [string]$ProcessName)
    
    Write-GuardLog "NEUTRALIZING: $ProcessName (PID:$ProcessId)" "KILL"
    
    # Layer 1: Standard
    try { Stop-Process -Id $ProcessId -Force -ErrorAction Stop } catch {}
    
    # Layer 2: WMI terminate
    if (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) {
        try {
            $wmi = Get-WmiObject Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
            if ($wmi) { $wmi.Terminate() | Out-Null }
        } catch {}
    }
    
    # Layer 3: Taskkill
    if (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) {
        Start-Process -FilePath "taskkill.exe" -ArgumentList "/F /PID $ProcessId" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
    }
    
    # Verify
    if (-not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) {
        Write-GuardLog "Neutralized PID $ProcessId successfully." "OK"
    } else {
        Write-GuardLog "PID $ProcessId may be protected. Escalation may be required." "WARN"
    }
}

# ==================== TEMP SCRUBBER ====================
function Scrub-TempScripts {
    $patterns = @('*.vbs','*.js','*.wsf','*.hta','*.ps1','*.bat','*.cmd')
    Get-ChildItem -Path $env:TEMP -Include $patterns -File -ErrorAction SilentlyContinue | 
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-60) } | ForEach-Object {
            $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if (-not $content) { return }
            
            $hasSigner = $false
            foreach ($s in $TARGET_SIGNERS) { if ($content -like "*$s*") { $hasSigner = $true; break } }
            
            $hasLauncher = ($content -like "*powershell*") -and (
                ($content -like "*-EncodedCommand*") -or ($content -like "*-e *")
            )
            $hasWmi = $content -like "*Register-WmiEvent*" -or $content -like "*__InstanceCreationEvent*"
            $hasShell = $content -like "*WScript.Shell*" -or $content -like "*CreateObject*"
            
            if ($hasSigner -or ($hasLauncher -and $hasShell) -or $hasWmi) {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                Write-GuardLog "Scrubbed suspicious script: $($_.Name)" "OK"
            }
        }
}

# ==================== OCEAN PROCESS FINDER ====================
function Find-OceanProcesses {
    $ocean = @()
    foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
        try {
            if ($proc.Path -and (Test-Path $proc.Path)) {
                $sig = Get-AuthenticodeSignature -FilePath $proc.Path -ErrorAction SilentlyContinue
                if ($sig.SignerCertificate) {
                    $subj = $sig.SignerCertificate.Subject
                    foreach ($signer in $TARGET_SIGNERS) {
                        if ($subj -like "*$signer*") {
                            $ocean += [PSCustomObject]@{
                                Id     = $proc.Id
                                Name   = $proc.Name
                                Path   = $proc.Path
                                Signer = $signer
                            }
                            break
                        }
                    }
                }
            }
        } catch {}
    }
    return $ocean
}

# ==================== LIVE INTERCEPTION ====================
function Start-ProcessInterceptor {
    # Watch for new process creation
    $createQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
    $createAction = {
        $inst = $Event.SourceEventArgs.NewEvent.TargetInstance
        $name = $inst.Name
        $procId = $inst.ProcessId
        $cmd = $inst.CommandLine
        
        # Intercept wscript/cscript from temp that launches PowerShell
        if ($name -match 'wscript|cscript') {
            if ($cmd -like "*$env:TEMP*" -and ($cmd -like "*powershell*" -or $cmd -like "*.vbs*" -or $cmd -like "*.js*")) {
                Start-Sleep -Milliseconds 300
                try { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue } catch {
                    try { (Get-WmiObject Win32_Process -Filter "ProcessId = $procId").Terminate() | Out-Null } catch {}
                }
                Write-Host "[INTERCEPT] Killed suspicious script launcher PID $procId" -ForegroundColor Magenta
            }
        }
        
        # Intercept encoded PowerShell with blocker DNA
        if ($name -match 'powershell|pwsh') {
            if ($cmd -like "*-EncodedCommand*" -or $cmd -like "*-e *") {
                try {
                    $b64 = ($cmd -split '-(?:EncodedCommand|e[c]?)\s+')[1].Trim().Trim('"').Trim("'")
                    $decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
                    $hasSigner = $false
                    foreach ($s in @("Gaston Dallavalle","Inspect Element Ltd")) {
                        if ($decoded -like "*$s*") { $hasSigner = $true; break }
                    }
                    $hasKill = $decoded -match 'Stop-Process|Terminate|taskkill|Kill'
                    if ($hasSigner -and $hasKill) {
                        Start-Sleep -Milliseconds 300
                        try { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue } catch {
                            try { (Get-WmiObject Win32_Process -Filter "ProcessId = $procId").Terminate() | Out-Null } catch {}
                        }
                        Write-Host "[INTERCEPT] Killed blocker DNA PowerShell PID $procId" -ForegroundColor Magenta
                    }
                } catch {}
            }
        }
    }
    
    # Watch for Ocean process deletion (detect killer)
    $deleteQuery = "SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
    $deleteAction = {
        $inst = $Event.SourceEventArgs.NewEvent.TargetInstance
        $name = $inst.Name
        $procId = $inst.ProcessId
        
        $wasOcean = $false
        if ($name -like "*Ocean*" -or $name -like "*anticheat*" -or $name -like "*AC*") {
            $wasOcean = $true
        }
        
        if ($wasOcean) {
            Write-Host "[ALERT] Ocean process TERMINATED: $name (PID:$procId)" -ForegroundColor Red
            Write-Host "[ALERT] Emergency purge recommended. Press [K] to purge." -ForegroundColor Yellow
        }
    }
    
    try {
        Unregister-Event -SourceIdentifier "OceanCreateIntercept" -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier "OceanDeleteWatch" -ErrorAction SilentlyContinue
        Register-WmiEvent -Query $createQuery -SourceIdentifier "OceanCreateIntercept" -Action $createAction | Out-Null
        Register-WmiEvent -Query $deleteQuery -SourceIdentifier "OceanDeleteWatch" -Action $deleteAction | Out-Null
        Write-GuardLog "Live process interception active." "GUARD"
    } catch {
        Write-GuardLog "Interceptor setup failed: $_" "WARN"
    }
}

# ==================== FILE SYSTEM WATCHER ====================
function Start-TempWatch {
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $env:TEMP
    $watcher.Filter = "*.*"
    $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite -bor [System.IO.NotifyFilters]::CreationTime
    $watcher.EnableRaisingEvents = $true
    
    $action = {
        $path = $Event.SourceEventArgs.FullPath
        $ext = [System.IO.Path]::GetExtension($path).ToLower()
        if ($ext -notin @('.vbs','.js','.wsf','.hta','.ps1','.bat','.cmd')) { return }
        
        Start-Sleep -Milliseconds 300
        $content = Get-Content $path -Raw -ErrorAction SilentlyContinue
        if (-not $content) { return }
        
        $hasSigner = $false
        foreach ($s in @("Gaston Dallavalle","Inspect Element Ltd")) {
            if ($content -like "*$s*") { $hasSigner = $true; break }
        }
        $hasLauncher = ($content -like "*powershell*") -and (($content -like "*-EncodedCommand*") -or ($content -like "*-e *"))
        $hasWmi = $content -like "*Register-WmiEvent*" -or $content -like "*__InstanceCreationEvent*"
        $hasShell = $content -like "*WScript.Shell*" -or $content -like "*CreateObject*"
        
        if ($hasSigner -or ($hasLauncher -and $hasShell) -or $hasWmi) {
            Remove-Item $path -Force -ErrorAction SilentlyContinue
            $fname = [System.IO.Path]::GetFileName($path)
            Write-Host "[FILEWATCH] Incinerated suspicious drop: $fname" -ForegroundColor Green
        }
    }
    
    Register-ObjectEvent -InputObject $watcher -EventName "Created" -SourceIdentifier "TempFileGuard" -Action $action | Out-Null
    Write-GuardLog "Temp file system watcher active (all script extensions)." "GUARD"
    return $watcher
}

# ==================== MAIN GUARDIAN ====================
function Start-Guardian {
    Show-Banner
    Write-GuardLog "Guardian initialized." "GUARD"
    Write-GuardLog "Protected Signers: $($TARGET_SIGNERS -join ', ')" "GUARD"
    Write-GuardLog "Log: $LOG_PATH" "GUARD"
    
    # Initial sweep
    Write-GuardLog "========== INITIAL BEHAVIORAL SWEEP ==========" "GUARD"
    $threats = Find-BlockerThreats
    if ($threats) {
        Write-GuardLog "Detected $($threats.Count) blocker threat(s)." "ALERT"
        $threats | Format-Table Id, Name, Type, DNA -AutoSize | Out-String | ForEach-Object { Write-GuardLog $_ "ALERT" }
        $threats | ForEach-Object { Stop-ThreatProcess -ProcessId $_.Id -ProcessName $_.Name }
    } else {
        Write-GuardLog "No active blocker threats detected." "OK"
    }
    Scrub-TempScripts
    
    # Ocean status
    $ocean = Find-OceanProcesses
    if ($ocean) {
        Write-GuardLog "Ocean processes running: $($ocean.Count)" "OK"
        $ocean | ForEach-Object { Write-GuardLog "  -> $($_.Name) (PID:$($_.Id)) [$($_.Signer)]" "OK" }
    } else {
        Write-GuardLog "No Ocean processes running. Start Ocean Anticheat when ready." "WARN"
    }
    
    # Start live defenses
    Start-ProcessInterceptor
    $fsWatcher = Start-TempWatch
    
    Write-GuardLog "========== LIVE GUARD ACTIVE ==========" "GUARD"
    Write-GuardLog "Controls: [Q]uit | [K]ill sweep | [S]tatus" "GUARD"
    
    $lastOceanCount = $ocean.Count
    
    while ($true) {
        if ($host.UI.RawUI.KeyAvailable) {
            $key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
            if ($key -eq 'q' -or $key -eq 'Q') { break }
            if ($key -eq 'k' -or $key -eq 'K') {
                Write-GuardLog "Manual purge triggered." "ALERT"
                Find-BlockerThreats | ForEach-Object { Stop-ThreatProcess -ProcessId $_.Id -ProcessName $_.Name }
                Scrub-TempScripts
            }
            if ($key -eq 's' -or $key -eq 'S') {
                $o = Find-OceanProcesses
                $b = Find-BlockerThreats
                Write-GuardLog "Status: Ocean=$($o.Count) | Blockers=$($b.Count)" "GUARD"
            }
        }
        
        # Periodic sweep
        $sweep = Find-BlockerThreats
        if ($sweep) {
            Write-GuardLog "Periodic sweep found $($sweep.Count) blocker(s)!" "ALERT"
            $sweep | ForEach-Object { Stop-ThreatProcess -ProcessId $_.Id -ProcessName $_.Name }
            Scrub-TempScripts
        }
        
        # Ocean health check
        $oceanNow = Find-OceanProcesses
        if ($lastOceanCount -gt 0 -and $oceanNow.Count -eq 0) {
            Write-GuardLog "OCEAN PROCESSES KILLED! Running emergency purge." "ALERT"
            Find-BlockerThreats | ForEach-Object { Stop-ThreatProcess -ProcessId $_.Id -ProcessName $_.Name }
            Scrub-TempScripts
        }
        $lastOceanCount = $oceanNow.Count
        
        Start-Sleep -Seconds $SCAN_INTERVAL
    }
    
    # Cleanup
    Unregister-Event -SourceIdentifier "OceanCreateIntercept" -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier "OceanDeleteWatch" -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier "TempFileGuard" -ErrorAction SilentlyContinue
    $fsWatcher.EnableRaisingEvents = $false
    $fsWatcher.Dispose()
    Write-GuardLog "Guardian stopped. Log: $LOG_PATH" "GUARD"
    Write-Host "`nGuardian deactivated. Log preserved at: $LOG_PATH" -ForegroundColor Cyan
}

# ==================== ENTRY ====================
try {
    Start-Guardian
} catch {
    Write-GuardLog "CRITICAL ERROR: $_" "WARN"
    Write-Host "Critical Error: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
}
