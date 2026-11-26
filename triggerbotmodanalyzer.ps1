#Requires -Version 5.1
using namespace System.IO
using namespace System.IO.Compression
param([string]$Path)

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
$Script:Sw = [Diagnostics.Stopwatch]::StartNew()
$UA = 'ModScanner/2.0'

# -- Banner -----------------------------------------------------------
Clear-Host
Write-Host ""
Write-Host "   ███╗  ██╗ ██████╗ ███╗   ███╗███████╗    ███████╗███████╗" -ForegroundColor Green
Write-Host "   ████╗ ██║██╔══██╗████╗ ████║██╔════╝    ██╔════╝██╔════╝" -ForegroundColor Green
Write-Host "   ██╔██╗██║██████╔╝██╔████╔██║█████╗      ███████╗███████╗" -ForegroundColor Green
Write-Host "   ██║╚████║██╔══██╗██║╚██╔╝██║██╔══╝      ╚════██║╚════██║" -ForegroundColor Green
Write-Host "   ██║ ╚███║██████╔╝██║ ╚═╝ ██║███████╗    ███████║███████║" -ForegroundColor Green
Write-Host "   ╚═╝  ╚══╝╚═════╝ ╚═╝     ╚═╝╚══════╝    ╚══════╝╚══════╝" -ForegroundColor Green
Write-Host ""
Write-Host "        mod scanner  |  v2.0 HTML report  |  made by claude.ai" -ForegroundColor Green
Write-Host ""

function Show-Status([string]$Msg) { Write-Host ("`r   {0,-95}" -f $Msg) -ForegroundColor DarkGray -NoNewline }
function Clear-Status { Write-Host ("`r" + (' ' * 100) + "`r") -NoNewline }

# -- Indicator tables -------------------------------------------------
$Trigger = @{ field_1692='Crosshair target / aimed entity'; method_2918='Attack entity'; method_6104='Swing hand'; class_1829='SwordItem'; class_1743='AxeItem'; method_7261='Attack cooldown' }
$SelfD   = @{ getProtectionDomain='Checks JAR origin / sandbox permissions'; getCodeSource='Locates its own JAR file path'; setLastModified='Modifies file timestamps'; deleteOnExit='Schedules JAR deletion on exit'; ProcessBuilder='Launches external processes' }
$Combo   = @{ getCodeSource='Locates its own JAR'; FileOutputStream='Writes to disk'; openStream='Downloads remote payload' }
$Net     = @{ 'java/net/Socket'='Raw TCP socket'; 'java/net/ServerSocket'='Opens local server socket'; 'java/net/DatagramSocket'='UDP socket'; 'java/net/HttpURLConnection'='HTTP connection'; 'java/net/URLConnection'='Generic URL connection'; 'javax/net/ssl/SSLSocket'='Encrypted SSL socket'; 'java/net/InetAddress'='DNS hostname resolution'; 'java/nio/channels/SocketChannel'='NIO socket channel' }
$Susp    = @('mixin','handler','keyboard','input','event','hook','inject','listener','callback')
$AgentKeys = @{ 'Premain-Class'='Java agent entry point'; 'Agent-Class'='Attach-API agent'; 'Boot-Class-Path'='Injects JAR into bootstrap classpath'; 'Can-Redefine-Classes'='Can replace loaded class bytecode'; 'Can-Retransform-Classes'='Can retransform loaded classes'; 'Can-Set-Native-Method-Prefix'='Can hook native JVM methods' }
$ObfSigs = @{ 'allatori'='Allatori'; 'ZKM'='Zelix KlassMaster'; 'me/lpk/'='SkidFuscator'; 'zenix/skid'='Zenix SkidFuscator'; 'radon/'='Radon'; 'bozar'='Bozar'; 'branchlock'='Branchlock'; 'com/preemptive'='DashO'; 'superblaubeere'='Superblaubeere27'; 'javaguard'='JavaGuard'; 'com/yworks/yguard'='yGuard'; 'dev/skidfuscator'='Skidfuscator'; 'Paramorphism'='Paramorphism'; 'sim0n/Caesium'='Caesium'; 'com/binscure'='Binscure'; 'QProtect'='QProtect'; 'com/zelix'='Zelix KlassMaster'; 'com/licel/stringer'='Stringer'; 'JNIC'='JNIC'; 'ScutiObf'='Scuti'; 'SmokeObf'='Smoke' }
$Legit   = @('gui','api','id','io','os','ui','vm','db','ai','mq','fx','tk','ok','url','tcp','udp','dns','tls','ssl','eof','nio','rpc','csv','xml','cli','cdn','crc','jwt','aes','rsa','md5','sha','png','gif','zip','gzip')
$Tables  = @{ Trigger=$Trigger; SelfD=$SelfD; Combo=$Combo; Net=$Net; Susp=$Susp; AgentKeys=$AgentKeys; ObfSigs=$ObfSigs; Legit=$Legit }

$FeatherIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
'feather','featherclient','feather-fabric','featherfabric','feather-api','featherapi','feather-companion','feathermc','featherapp' | ForEach-Object { [void]$FeatherIds.Add($_) }

# -- Helpers ----------------------------------------------------------
function Test-IsAdmin {
    if ($null -ne $Script:IsAdmin) { return $Script:IsAdmin }
    $Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    return $Script:IsAdmin
}

function Get-FileSHA1([string]$P) {
    $s = $null
    try { $s = [File]::OpenRead($P); $h = [Security.Cryptography.SHA1]::Create(); return ([BitConverter]::ToString($h.ComputeHash($s))).Replace('-', '').ToLower() }
    catch { return $null } finally { if ($s) { $s.Close() } }
}

function Get-ModMeta([string]$JarPath) {
    $m = @{ Id = $null; Name = $null; Version = $null }; $fs = $null; $z = $null
    try {
        $fs = [File]::OpenRead($JarPath)
        $z  = New-Object ZipArchive($fs, [ZipArchiveMode]::Read, $false)
        foreach ($n in 'fabric.mod.json', 'quilt.mod.json', 'META-INF/mods.toml') {
            $e = $z.GetEntry($n); if (-not $e) { continue }
            $sr = New-Object StreamReader($e.Open()); $t = $sr.ReadToEnd(); $sr.Dispose()
            if ($n -like '*.json') {
                if ($t -match '"id"\s*:\s*"([^"]+)"')      { $m.Id      = $Matches[1].ToLower() }
                if ($t -match '"name"\s*:\s*"([^"]+)"')    { $m.Name    = $Matches[1] }
                if ($t -match '"version"\s*:\s*"([^"]+)"') { $m.Version = $Matches[1] }
            } else {
                if ($t -match 'modId\s*=\s*"([^"]+)"')       { $m.Id      = $Matches[1].ToLower() }
                if ($t -match 'displayName\s*=\s*"([^"]+)"') { $m.Name    = $Matches[1] }
                if ($t -match 'version\s*=\s*"([^"]+)"')     { $m.Version = $Matches[1] }
            }
        }
    } catch {} finally { if ($z) { $z.Dispose() }; if ($fs) { $fs.Close() } }
    return $m
}

function Get-ModrinthBatch([string[]]$Hashes) {
    $map = @{}; $Script:ModrinthOk = $false
    if (-not $Hashes -or $Hashes.Count -eq 0) { $Script:ModrinthOk = $true; return $map }
    try {
        $body = ConvertTo-Json -InputObject @{ hashes = @($Hashes); algorithm = 'sha1' } -Compress -Depth 3
        $vs   = Invoke-RestMethod 'https://api.modrinth.com/v2/version_files' -Method Post -Body $body -ContentType 'application/json' -UserAgent $UA -TimeoutSec 30
        $ids  = @($vs.PSObject.Properties | ForEach-Object { $_.Value.project_id } | Select-Object -Unique)
        $proj = @{}
        for ($i = 0; $i -lt $ids.Count; $i += 100) {
            $chunk = @($ids[$i..([Math]::Min($i + 99, $ids.Count - 1))])
            $q = [uri]::EscapeDataString((ConvertTo-Json -InputObject $chunk -Compress))
            foreach ($p in @(Invoke-RestMethod "https://api.modrinth.com/v2/projects?ids=$q" -UserAgent $UA -TimeoutSec 30)) { $proj[$p.id] = $p }
        }
        foreach ($prop in $vs.PSObject.Properties) {
            $p = $proj[$prop.Value.project_id]
            $map[$prop.Name.ToLower()] = @{ title = if ($p) { $p.title } else { $prop.Value.name }; slug = if ($p) { $p.slug } else { $null }; version = $prop.Value.version_number }
        }
        $Script:ModrinthOk = $true
    } catch {}
    return $map
}

function Get-DownloadSource([string]$FilePath) {
    $ev = @(); $raw = [Path]::GetFileName($FilePath).ToLower()
    try {
        $ads = Get-Content -Path $FilePath -Stream Zone.Identifier -ErrorAction SilentlyContinue
        $hostUrl = ''; $ref = ''
        foreach ($l in $ads) { if ($l -match '^HostUrl=(.+)') { $hostUrl = $Matches[1].Trim() } elseif ($l -match '^ReferrerUrl=(.+)') { $ref = $Matches[1].Trim() } }
        if ($hostUrl) {
            $src = if ($hostUrl -match 'modrinth\.com') { 'Modrinth' } elseif ($hostUrl -match 'curseforge\.com') { 'CurseForge' } elseif ($hostUrl -match 'github\.com') { 'GitHub' } elseif ($hostUrl -match 'discordapp|discord\.com') { 'Discord CDN' } elseif ($hostUrl -match 'mediafire\.com') { 'MediaFire' } elseif ($hostUrl -match 'mega\.nz') { 'MEGA' } elseif ($hostUrl -match 'dropbox\.com') { 'Dropbox' } elseif ($hostUrl -match 'drive\.google\.com') { 'Google Drive' } elseif ($hostUrl -match 'https?://(?:www\.)?([^/]+)') { $Matches[1] } else { $hostUrl }
            $ev += "Downloaded from $src"; $ev += "URL: $hostUrl"
        }
        if ($ref) { $ev += "Referrer: $ref" }
    } catch {}
    if ($raw -match '^download\d*(\.\w+)?$')  { $ev += 'Generic "download" filename' }
    if ($raw -match 'discord')                { $ev += 'Filename references Discord' }
    if ($raw -match '^[a-f0-9]{8,}(\.\w+)?$') { $ev += 'Hash-style filename' }
    if ($ev.Count -eq 0) { $ev += 'No download trace found' }
    return $ev
}

function Format-Span([TimeSpan]$T) {
    $s = [Math]::Abs($T.TotalSeconds)
    if ($s -lt 60) { return ('{0:N0}s' -f $s) } elseif ($s -lt 3600) { return ('{0:N0} min' -f ($s / 60)) } elseif ($s -lt 86400) { return ('{0:N1} h' -f ($s / 3600)) } else { return ('{0:N0} d' -f ($s / 86400)) }
}
function Fmt([datetime]$D) { return $D.ToLocalTime().ToString('MMM dd HH:mm:ss') }

# -- Deep scan (runs inside runspaces for speed) ----------------------
$ScanBlock = {
    param([string]$JarPath, $T)
    Add-Type -AssemblyName System.IO.Compression
    $r = @{ Trigger = @{}; SelfD = @{}; Combo = @(); Net = @{}; Urls = @(); Jvm = @(); Agent = @(); Tools = @(); Flags = @(); Pct = 0; Grade = 'CLEAN'; Err = $null }
    $latin = [Text.Encoding]::GetEncoding('iso-8859-1')
    $ic = [StringComparison]::OrdinalIgnoreCase; $oc = [StringComparison]::Ordinal
    $c = @{ tot = 0; num = 0; uni = 0; fw = 0; jp = 0; s1 = 0; s2 = 0; gib = 0; nov = 0; conf = 0; pkg = 0; short = 0 }
    $tools = New-Object 'System.Collections.Generic.HashSet[string]'
    $legit = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($l in $T.Legit) { [void]$legit.Add($l) }
    function Add-Hit($h, $k, $f) {
        if (-not $h.ContainsKey($k)) { $h[$k] = New-Object 'System.Collections.Generic.List[string]' }
        if ($h[$k].Count -lt 50 -and -not $h[$k].Contains($f)) { $h[$k].Add($f) }
    }
    $fs = $null; $zip = $null
    try {
        $fs  = [IO.File]::OpenRead($JarPath)
        $zip = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Read, $false)
        $mf = $zip.GetEntry('META-INF/MANIFEST.MF')
        if ($mf) {
            $sr = New-Object IO.StreamReader($mf.Open()); $m = $sr.ReadToEnd(); $sr.Dispose()
            foreach ($k in $T.AgentKeys.Keys) {
                if ($m -match ("(?m)^" + [regex]::Escape($k) + "\s*:\s*(.+)$")) {
                    $v = $Matches[1].Trim()
                    if ($k -like 'Can-*' -and $v -ine 'true') { continue }
                    $r.Agent += ("{0}: {1} ({2})" -f $k, $v, $T.AgentKeys[$k])
                }
            }
            if ($m -match '-javaagent:')    { $r.Jvm += '-javaagent flag in manifest' }
            if ($m -match 'Xbootclasspath') { $r.Jvm += 'Xbootclasspath override in manifest' }
        }
        foreach ($e in $zip.Entries) {
            $full = $e.FullName
            if (-not $full.EndsWith('.class', $ic) -or $e.Length -gt 3MB) { continue }
            $ms = New-Object IO.MemoryStream; $es = $e.Open(); $es.CopyTo($ms); $es.Dispose()
            $txt = $latin.GetString($ms.GetBuffer(), 0, [int]$ms.Length); $ms.Dispose()
            $c.tot++
            $segs = $full.Substring(0, $full.Length - 6).Split('/'); $cn = $segs[$segs.Length - 1]
            if ([regex]::IsMatch($cn, '^\d+$')) { $c.num++ }
            if ([regex]::IsMatch($cn, '[^\x00-\x7F]')) { $c.uni++ }
            if ([regex]::IsMatch($cn, '[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]')) { $c.fw++ }
            if ([regex]::IsMatch($cn, '[\u3040-\u30FF]')) { $c.jp++ }
            if ([regex]::IsMatch($cn, '^[a-zA-Z]$')) { $c.s1++ }
            if ([regex]::IsMatch($cn, '^[a-zA-Z]{2}$')) { $c.s2++ }
            if ([regex]::IsMatch($cn, '^[Il1O0]+$|^_+$')) { $c.conf++ }
            if ($cn.Length -ge 3 -and $cn.Length -le 8 -and [regex]::IsMatch($cn, '^[a-zA-Z]+$')) {
                $vow = [regex]::Matches($cn, '[aeiouAEIOU]').Count
                if ($vow -eq 0) { $c.nov++ }
                if ([regex]::IsMatch($cn, '[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]{3,}') -and ($vow / $cn.Length) -lt 0.3) { $c.gib++ }
            }
            for ($i = 0; $i -lt $segs.Length - 1; $i++) { if ($segs[$i].Length -eq 1) { $c.pkg++ } }
            $base = $cn -replace '\$.*$', ''
            if ($base.Length -ge 1 -and $base.Length -le 2 -and $base -match '^[a-zA-Z]+$' -and -not $legit.Contains($base)) { $c.short++ }

            foreach ($s in $T.ObfSigs.Keys) {
                $cmp = if ($s.Length -le 4) { $oc } else { $ic }
                if ($full.IndexOf($s, $ic) -ge 0 -or $txt.IndexOf($s, $cmp) -ge 0) { [void]$tools.Add($T.ObfSigs[$s]) }
            }
            if ($txt.Contains('-javaagent:'))    { $r.Jvm += "Hardcoded -javaagent in $full" }
            if ($txt.Contains('Xbootclasspath')) { $r.Jvm += "Bootclasspath string in $full" }
            foreach ($k in $T.Trigger.Keys) { if ($txt.Contains($k)) { Add-Hit $r.Trigger $k $full } }
            foreach ($k in $T.SelfD.Keys)   { if ($txt.Contains($k)) { Add-Hit $r.SelfD $k $full } }
            $hits = @($T.Combo.Keys | Where-Object { $txt.Contains($_) })
            if ($hits.Count -ge 2) { $r.Combo += ,@($full, ($hits -join ' + ')) }

            $low = $full.ToLowerInvariant(); $sus = $false
            foreach ($s in $T.Susp) { if ($low.Contains($s)) { $sus = $true; break } }
            if ($sus) {
                foreach ($u in [regex]::Matches($txt, 'https?://[\x21-\x7e]{4,140}')) { if ($r.Urls.Count -lt 40) { $r.Urls += ,@($u.Value, $full) } }
                foreach ($k in $T.Net.Keys) { if ($txt.Contains($k)) { Add-Hit $r.Net $k $full } }
            }
        }
        $n = $c.tot
        if ($n -ge 5) {
            $p = { param($x) [Math]::Round($x / $n * 100) }
            $F = @()
            if ((& $p $c.num)  -ge 20) { $F += "Numeric class names ($(& $p $c.num)%)" }
            if ((& $p $c.uni)  -ge 10) { $F += "Non-ASCII class names ($(& $p $c.uni)%)" }
            if ($c.fw -gt 0)           { $F += "Fullwidth Unicode class names ($($c.fw))" }
            if ($c.jp -gt 0)           { $F += "Japanese-script class names ($($c.jp))" }
            if ((& $p $c.s1)   -ge 15) { $F += "Single-letter class names ($(& $p $c.s1)%)" }
            if ((& $p $c.s2)   -ge 20) { $F += "Two-letter class names ($(& $p $c.s2)%)" }
            if ((& $p $c.gib)  -ge 5)  { $F += "Gibberish class names ($(& $p $c.gib)%)" }
            if ((& $p $c.nov)  -ge 8)  { $F += "Vowel-less class names ($(& $p $c.nov)%)" }
            if ((& $p $c.conf) -ge 3)  { $F += "Confusable names Il1O0/_ ($(& $p $c.conf)%)" }
            if ($c.pkg -ge 6)          { $F += "Single-character package paths ($($c.pkg))" }
            $ratio = $c.short / $n
            $bonus = if ($ratio -gt 0.7) { 10 } elseif ($ratio -gt 0.5) { 5 } else { 0 }
            $r.Pct = [Math]::Min(100, [Math]::Round($ratio * 60) + [Math]::Min(35, $tools.Count * 17) + $bonus + [Math]::Min(25, $F.Count * 5))
            $r.Grade = if ($r.Pct -ge 80) { 'HEAVILY OBFUSCATED' } elseif ($r.Pct -ge 50) { 'OBFUSCATED' } elseif ($r.Pct -ge 20) { 'LIGHTLY OBFUSCATED' } else { 'CLEAN' }
            $r.Flags = $F
        }
        $r.Tools = @($tools); $r.Jvm = @($r.Jvm | Select-Object -Unique)
    } catch { $r.Err = $_.Exception.Message } finally { if ($zip) { $zip.Dispose() }; if ($fs) { $fs.Close() } }
    return $r
}

function Invoke-ParallelScan($Mods) {
    if ($Mods.Count -eq 0) { return }
    $threads = [Math]::Max(2, [Math]::Min(8, [Environment]::ProcessorCount))
    $pool = [runspacefactory]::CreateRunspacePool(1, $threads); $pool.Open()
    $sb = $ScanBlock.ToString()
    $jobs = foreach ($m in $Mods) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($sb).AddArgument($m.Path).AddArgument($Tables)
        [pscustomobject]@{ Mod = $m; PS = $ps; H = $ps.BeginInvoke() }
    }
    do {
        $left = @($jobs | Where-Object { -not $_.H.IsCompleted }).Count
        Show-Status ("Deep scanning with {0} threads: {1}/{2} done" -f $threads, ($jobs.Count - $left), $jobs.Count)
        if ($left -gt 0) { Start-Sleep -Milliseconds 150 }
    } while ($left -gt 0)
    foreach ($j in $jobs) {
        try { $res = $j.PS.EndInvoke($j.H); if ($res.Count -gt 0) { $j.Mod.Scan = $res[0] } } catch {}
        $j.PS.Dispose()
    }
    $pool.Close(); Clear-Status
}

# -- Minecraft process detection --------------------------------------
function Get-MinecraftJavaProcesses {
    if ($null -ne $Script:McProcs) { return $Script:McProcs }
    $list = @()
    try { $all = @(Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" -ErrorAction Stop) } catch { $all = @() }
    foreach ($p in $all) {
        $cmd = [string]$p.CommandLine; $conf = 0; $hint = ''
        if     ($cmd -match 'net\.minecraft\.client\.main\.Main')                   { $conf = 100; $hint = 'Vanilla' }
        elseif ($cmd -match 'cpw\.mods\.modlauncher\.Launcher|launchwrapper\.Launch') { $conf = 100; $hint = 'Forge' }
        elseif ($cmd -match 'fabricmc.*KnotClient')                                  { $conf = 100; $hint = 'Fabric' }
        elseif ($cmd -match 'quiltmc.*KnotClient')                                   { $conf = 100; $hint = 'Quilt' }
        elseif ($cmd -match '(?i)feather')                                           { $conf = 90;  $hint = 'Feather' }
        elseif ($cmd -match '(?i)\.minecraft')                                       { $conf = 80;  $hint = '.minecraft path' }
        elseif ($cmd -match '(?i)lwjgl')                                             { $conf = 70;  $hint = 'LWJGL' }
        elseif ($cmd -match '(?i)minecraft|fabric|forge|quilt|lunar|badlion')        { $conf = 60;  $hint = 'Generic hint' }
        if ($conf -eq 0 -and $p.ParentProcessId) {
            try {
                $par = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" -ErrorAction SilentlyContinue
                if ($par -and $par.Name -match '(?i)minecraft|feather|lunar|badlion|multimc|prism|curseforge|atlauncher|gdlauncher') { $conf = 75; $hint = "Parent: $($par.Name)" }
            } catch {}
        }
        if ($conf -eq 0 -and ($p.WorkingSetSize / 1MB) -gt 800) { $conf = 40; $hint = 'High-memory Java' }
        if ($conf -gt 0) { $list += [pscustomobject]@{ ProcessId = $p.ProcessId; Name = $p.Name; CommandLine = $cmd; CreationDate = $p.CreationDate; Confidence = $conf; LauncherHint = $hint } }
    }
    $Script:McProcs = @($list | Sort-Object Confidence, CreationDate -Descending)
    return $Script:McProcs
}

function Find-LogFile([string]$ModsPath) {
    $c = @(); $cur = $ModsPath
    for ($i = 0; $i -lt 5; $i++) {
        $cur = Split-Path $cur -Parent; if (-not $cur) { break }
        foreach ($rel in 'logs\latest.log', '.minecraft\logs\latest.log') { $x = Join-Path $cur $rel; if (Test-Path $x) { $c += $x } }
    }
    $std = Join-Path $env:APPDATA '.minecraft\logs\latest.log'; if (Test-Path $std) { $c += $std }
    if ($c.Count -gt 0) { return ($c | Sort-Object { (Get-Item $_).LastWriteTime } -Descending | Select-Object -First 1) }
    return $null
}

# -- USN journal ------------------------------------------------------
function ConvertFrom-HexReason([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw)) { return [long]0 }
    $h = $Raw.Trim().Trim('"'); if ($h -match '^0[xX](.+)$') { $h = $Matches[1] }
    try { return [Convert]::ToInt64($h, 16) } catch { return [long]0 }
}
function Normalize-HexId([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw)) { return '' }
    $s = $Raw.Trim().Trim('"').ToLower(); if ($s -match '^0x(.+)$') { $s = $Matches[1] }
    $s = $s.TrimStart('0'); if ($s -eq '') { $s = '0' }; return $s
}

function Get-UsnEvidence([string]$ModsPath, $CurrentNames, $LaunchUtc) {
    $ev = @{}
    if (-not (Test-IsAdmin)) { return $ev }
    $tmp = Join-Path $env:TEMP ("usn_" + [guid]::NewGuid().ToString('N') + '.csv')
    try {
        $root = ([Path]::GetPathRoot((Resolve-Path $ModsPath).Path)).TrimEnd('\')
        Start-Process cmd.exe -ArgumentList "/c fsutil usn readjournal `"$root`" csv > `"$tmp`" 2>nul" -WindowStyle Hidden -Wait
        if (-not (Test-Path $tmp)) { return $ev }

        # Stream the file and keep only the header + .jar lines (large journals stay fast)
        $sr = New-Object StreamReader($tmp, [Console]::OutputEncoding); $keep = New-Object 'System.Collections.Generic.List[string]'; $gotHdr = $false
        while ($null -ne ($l = $sr.ReadLine())) {
            if (-not $gotHdr) { if ($l -match 'usn' -and $l -match 'file name' -and $l -match 'reason') { $gotHdr = $true; $keep.Add($l.TrimStart([char]0xFEFF)) } }
            elseif ($l -like '*.jar*') { $keep.Add($l) }
        }
        $sr.Dispose()
        if ($keep.Count -lt 2) { return $ev }
        $rows = @($keep | ConvertFrom-Csv)
        if ($rows.Count -eq 0) { return $ev }
        $pn = $rows[0].PSObject.Properties.Name
        $cName = $pn | Where-Object { $_ -match '^file\s*name$' } | Select-Object -First 1
        $cNum  = $pn | Where-Object { $_ -match '^reason\s*#' } | Select-Object -First 1
        $cTxt  = $pn | Where-Object { $_ -match '^reason$' } | Select-Object -First 1
        $cTime = $pn | Where-Object { $_ -match '^time\s*stamp$' } | Select-Object -First 1
        $cPar  = $pn | Where-Object { $_ -match '^parent\s*file\s*id$' } | Select-Object -First 1
        if (-not $cName -or (-not $cNum -and -not $cTxt)) { return $ev }

        $folderRef = $null
        try { $q = (& fsutil file queryfileid "$ModsPath" 2>$null) -join ' '; if ($q -match '0x([0-9a-fA-F]+)') { $folderRef = Normalize-HexId $Matches[1] } } catch {}

        $entries = New-Object 'System.Collections.Generic.List[object]'
        foreach ($row in $rows) {
            $fn = ([string]$row.$cName).Trim('"'); if ($fn -notlike '*.jar') { continue }
            if ($folderRef -and $cPar -and (Normalize-HexId $row.$cPar) -ne $folderRef -and -not $CurrentNames.Contains($fn)) { continue }
            [long]$rv = 0
            if ($cNum) { $rv = ConvertFrom-HexReason $row.$cNum }
            if ($rv -eq 0 -and $cTxt) {
                $tl = ([string]$row.$cTxt).ToLower()
                if ($tl -match 'data overwrite') { $rv = $rv -bor 0x1L }; if ($tl -match 'data extend') { $rv = $rv -bor 0x2L }
                if ($tl -match 'data truncation') { $rv = $rv -bor 0x4L }; if ($tl -match 'file create') { $rv = $rv -bor 0x100L }
                if ($tl -match 'file delete') { $rv = $rv -bor 0x200L }; if ($tl -match 'rename.*new') { $rv = $rv -bor 0x2000L }
                if ($tl -match 'basic info') { $rv = $rv -bor 0x8000L }; if ($tl -match '\bclose\b') { $rv = $rv -bor 0x80000000L }
            }
            $ts = [datetime]::MinValue
            if ($cTime) { $s = ([string]$row.$cTime).Trim('"'); try { $ts = [datetime]::Parse($s, [Globalization.CultureInfo]::CurrentCulture) } catch { try { $ts = [datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture) } catch {} } }
            $entries.Add([pscustomobject]@{ FileName = $fn; Reason = $rv; Time = $ts })
        }

        foreach ($g in ($entries | Group-Object FileName)) {
            $t = @{}; $sessData = @(); $sessBasic = @(); $last = $null
            foreach ($x in ($g.Group | Sort-Object Time)) {
                $r = $x.Reason; $ts = $x.Time
                if ($r -band 0x200L)      { $t.del = $ts }
                if ($r -band 0x100L)      { $t.cre = $ts }
                if ($r -band 0x1L)        { $t.ovw = $ts }
                if ($r -band 0x2L)        { $t.ext = $ts }
                if ($r -band 0x4L)        { $t.trn = $ts }
                if ($r -band 0x8000L)     { $t.bas = $ts }
                if ($r -band 0x2000L)     { $t.rnn = $ts }
                if ($r -band 0x80000000L) { $t.cls = $ts }
                $last = $ts
                if ($LaunchUtc -and $ts -ne [datetime]::MinValue -and $ts.ToUniversalTime() -gt $LaunchUtc) {
                    if ($r -band 0x2307L) { $sessData += ("{0}  {1}" -f (Fmt $ts), (@(if ($r -band 0x100L) { 'created' }; if ($r -band 0x200L) { 'deleted' }; if ($r -band 0x2000L) { 'renamed in' }; if ($r -band 0x7L) { 'content changed' }) -join ', ')) }
                    elseif ($r -band 0x8000L) { $sessBasic += (Fmt $ts) }
                }
            }
            $dx = $t.ContainsKey('ext') -or $t.ContainsKey('trn')
            $score = 0; $fl = @()
            if ($t.ContainsKey('del') -and $t.ContainsKey('cre')) { $score += 3; $fl += "Deleted $(Fmt $t.del), recreated $(Fmt $t.cre)" }
            if ($t.ContainsKey('cre') -and $dx) { $score += 2; $fl += 'Content changed after creation' }
            if ($dx -and $t.ContainsKey('bas')) { $score += 3; $fl += 'File rewritten (data changed + attributes updated)' }
            if ($t.ContainsKey('ovw') -and $dx -and $t.ContainsKey('bas')) { $score += 4; $fl += 'In-place rewrite (strong replacement signal)' }
            elseif ($t.ContainsKey('ovw') -and $dx -and $t.ContainsKey('cls')) { $score += 2; $fl += 'Overwritten in place' }
            elseif ($t.ContainsKey('bas') -and -not $dx) { $score += 1; $fl += 'Attributes / size info changed' }
            if ($t.ContainsKey('rnn')) { $score += 2; $fl += 'Renamed from another name (download then rename?)' }
            $delOnly = $t.ContainsKey('del') -and -not $t.ContainsKey('cre')
            if ($delOnly) { $score += 1; $fl += "Deleted $(Fmt $t.del), not recreated" }
            if ($t.ContainsKey('cre') -and -not $t.ContainsKey('del') -and -not $dx) { $score += 1; $fl += "New file created $(Fmt $t.cre)" }
            if ($LaunchUtc -and $t.ContainsKey('cre') -and $t.cre.ToUniversalTime() -gt $LaunchUtc) { $score += 1 }
            if ($score -gt 0 -or $sessData.Count -gt 0 -or $sessBasic.Count -gt 0) {
                $ev[$g.Name] = @{ Score = $score; Flags = $fl; SessData = $sessData; SessBasic = $sessBasic; DelOnly = $delOnly; DelTime = $t.del; Count = $g.Count }
            }
        }
    } catch {} finally { if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } }
    return $ev
}

# -- Missing + injected mods ------------------------------------------
function Get-LiveClasspathJars {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in (Get-MinecraftJavaProcesses)) {
        if ([string]::IsNullOrWhiteSpace($p.CommandLine)) { continue }
        if ($p.CommandLine -match '(?:^|\s)-{1,2}(?:cp|classpath)\s+("?)([^"]+?)\1(?:\s|$)') {
            foreach ($x in ($Matches[2] -split ';')) { $x = $x.Trim().Trim('"'); if ($x -like '*.jar') { [void]$set.Add([Environment]::ExpandEnvironmentVariables($x)) } }
        }
    }
    return @($set)
}

function Get-JvmInjectedMods([string]$ModsPath) {
    $out = @(); $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $pats = @{
        '-Dfabric\.addMods(?:\.extra)?=["'']?([^"''\s]+)' = '-Dfabric.addMods'
        '-Dloader\.addMods(?:\.extra)?=["'']?([^"''\s]+)' = '-Dloader.addMods (Quilt)'
        '-Dfabric\.extraMods=["'']?([^"''\s]+)'           = '-Dfabric.extraMods'
        '-javaagent:["'']?([^="''\s]+\.jar)'              = '-javaagent'
        '-Xbootclasspath/[ap]:["'']?([^"''\s]+)'          = '-Xbootclasspath'
        '-DlegacyClassPath=["'']?([^"''\s]+)'             = '-DlegacyClassPath'
    }
    $modsRes = ''; try { $modsRes = (Resolve-Path $ModsPath).Path.TrimEnd('\') + '\' } catch {}
    foreach ($p in (Get-MinecraftJavaProcesses)) {
        foreach ($pat in $pats.Keys) {
            foreach ($m in [regex]::Matches($p.CommandLine, $pat, 'IgnoreCase')) {
                foreach ($jp in ($m.Groups[1].Value -split ';' | Where-Object { $_ -like '*.jar' })) {
                    if (-not $seen.Add($jp)) { continue }
                    $ex = Test-Path $jp -ErrorAction SilentlyContinue
                    $inF = $false; if ($ex -and $modsRes) { try { $inF = (Resolve-Path $jp).Path.StartsWith($modsRes, [StringComparison]::OrdinalIgnoreCase) } catch {} }
                    $hsh = $null; if ($ex) { $hsh = Get-FileSHA1 $jp }
                    $isev = 'med'; if (-not $inF) { $isev = 'high' }
                    $out += @{ name = [Path]::GetFileName($jp); path = $jp; arg = $pats[$pat]; exists = [bool]$ex; inMods = $inF; pid = $p.ProcessId; launcher = $p.LauncherHint; sha1 = $hsh; sev = $isev }
                }
            }
        }
    }
    return $out
}

# ======================================================================
# == MAIN ==============================================================
# ======================================================================
if (-not $Path) { Write-Host "   Paste your mods folder path and press Enter" -ForegroundColor Cyan; $Path = (Read-Host "   Path") }
$Path = $Path.Trim().Trim('"')
if (-not (Test-Path $Path)) { Write-Host "   [ERROR] Path not found: $Path" -ForegroundColor Red; pause; exit }
$jars = @(Get-ChildItem -Path $Path -Filter '*.jar' -File -Recurse -ErrorAction SilentlyContinue)
if ($jars.Count -eq 0) { Write-Host "   No .jar files found." -ForegroundColor Yellow; pause; exit }
Write-Host "   Found $($jars.Count) mod(s) to analyze" -ForegroundColor DarkGray

# Feather list (single quick request, static fallback already loaded)
try { foreach ($p in @(Invoke-RestMethod 'https://api.modrinth.com/v2/organization/feathermc/projects' -UserAgent $UA -TimeoutSec 5)) { [void]$FeatherIds.Add($p.slug); [void]$FeatherIds.Add($p.id) } } catch {}

# Minecraft instance / launch time
$procs = @(Get-MinecraftJavaProcesses)
$launchUtc = $null; $launchSource = 'none'
if ($procs.Count -gt 0) { $launchUtc = $procs[0].CreationDate.ToUniversalTime(); $launchSource = "live process (PID $($procs[0].ProcessId), $($procs[0].LauncherHint))" }
else {
    $lf = Find-LogFile $Path
    if ($lf) { $launchUtc = (Get-Item $lf).CreationTimeUtc; $launchSource = 'latest.log (last session)' }
}
if ($launchUtc) { Write-Host ("   Session start: {0}  [{1}]" -f (Fmt $launchUtc), $launchSource) -ForegroundColor Cyan }
else            { Write-Host "   No Minecraft session found - session-modification check skipped" -ForegroundColor DarkYellow }
$admin = Test-IsAdmin
if (-not $admin) { Write-Host "   [Note] Not running as admin - USN journal checks disabled" -ForegroundColor DarkYellow }

$names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($j in $jars) { [void]$names.Add($j.Name) }

# Stage 1: hash + metadata
$mods = New-Object 'System.Collections.Generic.List[hashtable]'; $i = 0
foreach ($j in $jars) {
    $i++; if ($i % 4 -eq 1) { Show-Status "Hashing & reading metadata: $i/$($jars.Count)" }
    $meta = Get-ModMeta $j.FullName
    $mods.Add(@{ Jar = $j; Name = $j.Name; Path = $j.FullName; Size = $j.Length; Sha1 = (Get-FileSHA1 $j.FullName); Id = $meta.Id; ModName = $meta.Name; Version = $meta.Version; Status = 'unknown'; Mr = $null; Scan = $null; Sev = 'low'; Session = $false; F = (New-Object 'System.Collections.Generic.List[object]') })
}
Clear-Status
foreach ($m in $mods) { if ($m.Id -and $FeatherIds.Contains($m.Id)) { $m.Status = 'feather' } }

# Stage 2: one batched Modrinth request
Show-Status 'Verifying against Modrinth (batched)...'
$mr = Get-ModrinthBatch @($mods | Where-Object { $_.Status -ne 'feather' -and $_.Sha1 } | ForEach-Object { $_.Sha1 })
Clear-Status
foreach ($m in $mods) { if ($m.Status -ne 'feather' -and $m.Sha1 -and $mr.ContainsKey($m.Sha1)) { $m.Status = 'verified'; $m.Mr = $mr[$m.Sha1] } }
$nVer = @($mods | Where-Object { $_.Status -eq 'verified' }).Count; $nFea = @($mods | Where-Object { $_.Status -eq 'feather' }).Count
Write-Host "   $nFea Feather official, $nVer verified on Modrinth, $($mods.Count - $nFea - $nVer) need deep scan$(if (-not $Script:ModrinthOk) { '  [Modrinth unreachable]' })" -ForegroundColor Green

# Stage 3: USN journal + parallel deep scan
$usn = @{}
if ($admin) { Show-Status 'Reading USN journal...'; $usn = Get-UsnEvidence -ModsPath $Path -CurrentNames $names -LaunchUtc $launchUtc; Clear-Status; Write-Host "   USN journal: $($usn.Count) .jar file(s) with activity" -ForegroundColor DarkGray }
Invoke-ParallelScan @($mods | Where-Object { $_.Status -eq 'unknown' })

# Stage 4: findings
function Add-F($m, $sev, $title, $items = @()) { $m.F.Add(@{ sev = $sev; title = $title; items = @($items) }) }
$rank = @{ ok = 0; low = 1; med = 2; high = 3; crit = 4 }
foreach ($m in $mods) {
    $j = $m.Jar
    if ($launchUtc) {
        $it = @()
        if ($j.CreationTimeUtc  -gt $launchUtc) { $it += "Created $(Fmt $j.CreationTimeUtc), $(Format-Span ($j.CreationTimeUtc - $launchUtc)) after launch" }
        if ($j.LastWriteTimeUtc -gt $launchUtc) { $it += "Last written $(Fmt $j.LastWriteTimeUtc), $(Format-Span ($j.LastWriteTimeUtc - $launchUtc)) after launch" }
        $u = $usn[$m.Name]; if ($u -and $u.SessData.Count -gt 0) { foreach ($s in $u.SessData) { $it += "USN: $s" } }
        if ($it.Count -gt 0) { $m.Session = $true; Add-F $m 'crit' 'Modified during this Minecraft session' (@("Session started $(Fmt $launchUtc)") + $it) }
        elseif ($u -and $u.SessBasic.Count -gt 0) { Add-F $m 'med' 'Attributes touched during session (USN)' @("Basic-info change at $($u.SessBasic -join ', ')") }
    }
    $u = $usn[$m.Name]
    if ($u -and $u.Score -ge 2) { Add-F $m 'high' "Replacement suspect (USN score $($u.Score))" $u.Flags }
    elseif ($u -and $u.Flags.Count -gt 0) { Add-F $m 'low' 'USN journal activity' $u.Flags }

    $s = $m.Scan
    if ($s) {
        if ($s.Err) { Add-F $m 'med' 'Could not fully read JAR' @($s.Err) }
        if ($s.Trigger.Count -gt 0) { Add-F $m $(if ($s.Trigger.Count -ge 2) { 'crit' } else { 'high' }) 'Combat / aim code patterns (triggerbot indicators)' @($s.Trigger.Keys | ForEach-Object { "$_ - $($Trigger[$_]) ($($s.Trigger[$_].Count) class(es), e.g. $($s.Trigger[$_][0]))" }) }
        if ($s.SelfD.Count -gt 0 -or $s.Combo.Count -gt 0) {
            $n = $s.SelfD.Count + $(if ($s.Combo.Count -gt 0) { 2 } else { 0 })
            Add-F $m $(if ($n -ge 3) { 'high' } else { 'med' }) 'Self-destruct / self-replace capability' (@($s.SelfD.Keys | ForEach-Object { "$_ - $($SelfD[$_]) ($($s.SelfD[$_].Count) class(es))" }) + @($s.Combo | Select-Object -First 3 | ForEach-Object { "Self-replace combo in $($_[0]): $($_[1])" }))
        }
        if ($s.Agent.Count -gt 0 -or $s.Jvm.Count -gt 0) { Add-F $m 'high' 'JVM agent / injection hooks' (@($s.Agent) + @($s.Jvm)) }
        if ($s.Pct -ge 20) { Add-F $m $(if ($s.Pct -ge 50) { 'high' } else { 'med' }) "Obfuscation $($s.Pct)% - $($s.Grade.ToLower())" (@($s.Flags) + $(if ($s.Tools.Count -gt 0) { "Tool signatures: $($s.Tools -join ', ')" })) }
        if ($s.Net.Count -gt 0) { Add-F $m 'med' 'Network code in hook-style classes' @($s.Net.Keys | ForEach-Object { "$_ - $($Net[$_]) ($($s.Net[$_].Count) class(es))" }) }
        if ($s.Urls.Count -gt 0) { $uq = @($s.Urls | Sort-Object { $_[0] } -Unique); Add-F $m 'med' "Embedded URLs ($($uq.Count))" @($uq | Select-Object -First 6 | ForEach-Object { "$($_[0])  -  $($_[1])" }) }
    }
    if ($m.Status -eq 'unknown') {
        $src = Get-DownloadSource $m.Path
        Add-F $m 'low' 'Not on Modrinth - unknown origin' $src
    } elseif ($m.F.Count -eq 0) {
        Add-F $m 'ok' $(if ($m.Status -eq 'feather') { 'Official Feather mod ID' } else { 'SHA-1 matches Modrinth' }) @()
    }
    $top = 'ok'; foreach ($f in $m.F) { if ($rank[$f.sev] -gt $rank[$top]) { $top = $f.sev } }
    if ($m.Status -eq 'unknown' -and $rank[$top] -lt 1) { $top = 'low' }
    $m.Sev = $top
}

# Missing mods
$missing = @(); $seenMiss = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
if ($procs.Count -gt 0) {
    $mp = (Resolve-Path $Path).Path.TrimEnd('\') + '\'
    foreach ($lj in (Get-LiveClasspathJars)) {
        if ($lj.StartsWith($mp, [StringComparison]::OrdinalIgnoreCase) -and -not (Test-Path $lj) -and $seenMiss.Add([Path]::GetFileName($lj))) {
            $missing += @{ name = [Path]::GetFileName($lj); reason = 'Referenced in JVM classpath but missing from disk'; source = 'live'; sev = 'high' }
        }
    }
}
foreach ($k in $usn.Keys) {
    if ($usn[$k].DelOnly -and -not $names.Contains($k) -and $seenMiss.Add($k)) {
        $missing += @{ name = $k; reason = "Deleted from mods folder at $(Fmt $usn[$k].DelTime) (USN, not recreated)"; source = 'usn'; sev = 'med' }
    }
}
$logf = Find-LogFile $Path
if ($logf) {
    $have = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($m in $mods) { if ($m.Id) { [void]$have.Add($m.Id) } }
    $skip = 'java', 'minecraft', 'fabricloader', 'forge', 'quilt_loader', 'quilt-loader', 'mixin', 'fabric-api', 'fabric-api-base'
    try {
        $in = $false
        foreach ($line in (Get-Content $logf -Encoding UTF8 -ErrorAction Stop)) {
            if ($line -match 'Loading\s+\d+\s+mods?:') { $in = $true; continue }
            $id = $null
            if ($in -and $line -match '^\s*-\s+([a-z][a-z0-9_-]*)\s+\d') { $id = $Matches[1] }
            elseif ($in -and $line -match '^\S') { $in = $false }
            if (-not $id -and $line -match 'Loading mod\s+([a-z][a-z0-9_-]*)') { $id = $Matches[1] }
            if ($id -and $skip -notcontains $id -and -not $have.Contains($id) -and $seenMiss.Add("id:$id")) {
                $missing += @{ name = "Unknown (mod ID: $id)"; reason = 'Loaded in last session per latest.log, but no matching JAR'; source = 'log'; sev = 'med' }
            }
        }
    } catch {}
}
$inject = @(Get-JvmInjectedMods $Path)

# -- HTML report (content is rendered here; the page script only adds filtering) --
$secs = [Math]::Round($Script:Sw.Elapsed.TotalSeconds, 1)
function Enc($s) { if ($null -eq $s) { return '' }; return [System.Net.WebUtility]::HtmlEncode([string]$s) }
$sevName = @{ crit = 'Critical'; high = 'High'; med = 'Review'; low = 'Unknown'; ok = 'Verified' }
$cnt = @{ crit = 0; high = 0; med = 0; low = 0; ok = 0 }
foreach ($m in $mods) { $cnt[$m.Sev]++ }
$sessN = @($mods | Where-Object { $_.Session }).Count
$top = 'ok'
if ($cnt.med -gt 0) { $top = 'med' }
if ($cnt.high -gt 0 -or @($inject | Where-Object { $_.sev -eq 'high' }).Count -gt 0 -or @($missing | Where-Object { $_.sev -eq 'high' }).Count -gt 0) { $top = 'high' }
if ($cnt.crit -gt 0) { $top = 'crit' }
$heads = @{ crit = 'Critical findings - review before allowing'; high = 'High-risk indicators found'; med = 'Some mods need a closer look'; ok = 'No suspicious mods found' }
$subLine = "$($mods.Count) mods scanned in ${secs}s"
if ($sessN -gt 0) { $subLine += " &middot; <b>$sessN modified during the Minecraft session</b>" }
elseif ($launchUtc) { $subLine += ' &middot; none modified after launch' }
else { $subLine += ' &middot; no session found, session check skipped' }
if (-not $Script:ModrinthOk) { $subLine += ' &middot; Modrinth unreachable, hash verification skipped' }

$launchTxt = 'not detected'; if ($launchUtc) { $launchTxt = $launchUtc.ToLocalTime().ToString('MMM dd yyyy HH:mm:ss') }
$usnTxt = 'skipped (run as admin)'; if ($admin) { $usnTxt = 'read' }
$mrTxt = 'unreachable'; if ($Script:ModrinthOk) { $mrTxt = 'reachable' }
$info = @( @('Folder', $Path), @('Session start', $launchTxt), @('Session source', $launchSource), @('USN journal', $usnTxt), @('Modrinth', $mrTxt), @('Computer', $env:COMPUTERNAME) )
$cards = @( @('all', 'All mods', $mods.Count), @('session', 'Modified in session', $sessN), @('crit', 'Critical', $cnt.crit), @('high', 'High', $cnt.high), @('med', 'Review', $cnt.med), @('low', 'Unknown', $cnt.low), @('ok', 'Verified', $cnt.ok) )

$sb = New-Object System.Text.StringBuilder
[void]$sb.Append('<div class="verdict ' + $top + '"><h2>' + $heads[$top] + '</h2><p>' + $subLine + '</p></div>')
[void]$sb.Append('<div class="info">')
foreach ($r in $info) { [void]$sb.Append('<div><span>' + (Enc $r[0]) + '</span>' + (Enc $r[1]) + '</div>') }
[void]$sb.Append('</div><div class="stats">')
foreach ($c in $cards) {
    $style = ''; if ($c[0] -eq 'session' -and $c[2] -gt 0) { $style = ' style="color:var(--crit)"' }
    [void]$sb.Append('<button type="button" class="stat" data-f="' + $c[0] + '"><b' + $style + '>' + $c[2] + '</b><span>' + $c[1] + '</span></button>')
}
[void]$sb.Append('</div>')

if ($missing.Count -gt 0) {
    [void]$sb.Append('<h3>Missing mods (' + $missing.Count + ')</h3>')
    foreach ($x in $missing) { [void]$sb.Append('<div class="f ' + $x.sev + '"><b>' + (Enc $x.name) + ' <span class="tag">' + (Enc $x.source) + '</span></b>' + (Enc $x.reason) + '</div>') }
}
if ($inject.Count -gt 0) {
    [void]$sb.Append('<h3>Live JVM argument injection (' + $inject.Count + ')</h3>')
    foreach ($x in $inject) {
        $ex = 'NOT found on disk'; if ($x.exists) { $ex = 'Exists on disk' }
        $loc = 'OUTSIDE mods folder'; if ($x.inMods) { $loc = 'inside mods folder' }
        $li = '<li class="mono">' + (Enc $x.path) + '</li><li>' + $ex + ' - ' + $loc + '</li><li>PID ' + $x.pid + ' - ' + (Enc $x.launcher) + '</li>'
        if ($x.sha1) { $li += '<li class="mono">SHA-1 ' + $x.sha1 + '</li>' }
        [void]$sb.Append('<div class="f ' + $x.sev + '"><b>' + (Enc $x.name) + ' <span class="tag">' + (Enc $x.arg) + '</span></b><ul>' + $li + '</ul></div>')
    }
}

[void]$sb.Append('<h3>Mods</h3><div class="tools"><input type="search" id="q" placeholder="Search mods, mod IDs, findings" aria-label="Search"><button class="btn" id="expand" type="button">Expand all</button><button class="btn" id="print" type="button">Print</button></div><div id="list">')
$sorted = @($mods | Sort-Object @{ Expression = { -[int]$rank[$_.Sev] } }, @{ Expression = { $_.Name } })
foreach ($m in $sorted) {
    $title = $m.ModName; if ($m.Mr) { $title = $m.Mr.title }; if (-not $title) { $title = $m.Name }
    $sf = '0'; if ($m.Session) { $sf = '1' }
    $tags = ''
    if ($m.Session) { $tags += '<span class="tag hot">modified in session</span>' }
    if ($m.Status -eq 'feather') { $tags += '<span class="tag">Feather</span>' }
    if ($m.Status -eq 'verified') { $tags += '<span class="tag">Modrinth</span>' }
    [void]$sb.Append('<details class="mod" data-sev="' + $m.Sev + '" data-session="' + $sf + '"><summary><span class="pill ' + $m.Sev + '">' + $sevName[$m.Sev] + '</span><span class="nm"><b>' + (Enc $title) + '</b><small class="mono">' + (Enc $m.Name) + '</small></span><span class="tags">' + $tags + '</span><span class="chev">&#9656;</span></summary><div class="detail">')
    $ver = ''; if ($m.Version) { $ver = ' &middot; v' + (Enc $m.Version) }
    $dl2 = '<dt>Path</dt><dd class="mono">' + (Enc $m.Path) + '</dd><dt>Mod ID</dt><dd>' + (Enc $m.Id) + $ver + '</dd><dt>Created</dt><dd>' + $m.Jar.CreationTime.ToString('MMM dd yyyy HH:mm:ss') + '</dd><dt>Last written</dt><dd>' + $m.Jar.LastWriteTime.ToString('MMM dd yyyy HH:mm:ss') + '</dd><dt>Size</dt><dd>' + [Math]::Round($m.Size / 1KB, 1) + ' KB</dd><dt>SHA-1</dt><dd class="mono">' + (Enc $m.Sha1) + '</dd>'
    if ($m.Mr -and $m.Mr.slug) { $dl2 += '<dt>Modrinth</dt><dd><a href="https://modrinth.com/mod/' + (Enc $m.Mr.slug) + '" target="_blank" rel="noopener">modrinth.com/mod/' + (Enc $m.Mr.slug) + '</a></dd>' }
    [void]$sb.Append('<dl class="meta">' + $dl2 + '</dl>')
    foreach ($f in $m.F) {
        $lis = ''
        foreach ($it in $f.items) { $lis += '<li>' + (Enc $it) + '</li>' }
        if ($lis) { $lis = '<ul>' + $lis + '</ul>' }
        [void]$sb.Append('<div class="f ' + $f.sev + '"><b>' + (Enc $f.title) + '</b>' + $lis + '</div>')
    }
    [void]$sb.Append('</div></details>')
}
[void]$sb.Append('</div><div class="empty" id="empty" hidden>No mods match this filter.</div>')

$Template = @'
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mod Scan Report</title>
<style>
:root{--bg:#eef1f5;--panel:#fff;--ink:#16202e;--mute:#5d6b7e;--line:#d9dfe7;--accent:#2f5bea;--crit:#c62828;--high:#d9480f;--med:#a8740d;--low:#5d6b7e;--ok:#1f8a5b;--crit-bg:#fdeaea;--high-bg:#fff0e6;--med-bg:#fff6dd;--low-bg:#eef1f5;--ok-bg:#e4f5ec;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f1620;--panel:#17212e;--ink:#e6ebf2;--mute:#92a0b4;--line:#27344a;--accent:#7fa2ff;--crit:#ff6b6b;--high:#ff9a5c;--med:#f2c35b;--low:#92a0b4;--ok:#4cd694;--crit-bg:#3a1c22;--high-bg:#3a2619;--med-bg:#37301a;--low-bg:#1f2a3a;--ok-bg:#16322a;color-scheme:dark}}
:root[data-theme=dark]{--bg:#0f1620;--panel:#17212e;--ink:#e6ebf2;--mute:#92a0b4;--line:#27344a;--accent:#7fa2ff;--crit:#ff6b6b;--high:#ff9a5c;--med:#f2c35b;--low:#92a0b4;--ok:#4cd694;--crit-bg:#3a1c22;--high-bg:#3a2619;--med-bg:#37301a;--low-bg:#1f2a3a;--ok-bg:#16322a;color-scheme:dark}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
.mono{font-family:Consolas,"Cascadia Mono",ui-monospace,monospace}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:18px clamp(16px,4vw,40px)}
h1{font-size:20px;margin:0;font-weight:600}h1 small{font-weight:400;color:var(--mute);font-size:13px;margin-left:8px}
main{max-width:1080px;margin:0 auto;padding:0 clamp(16px,4vw,40px) 60px}
button,input{font:inherit;color:inherit}.btn{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:7px 14px;cursor:pointer}.btn:hover{border-color:var(--accent)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.verdict{border-radius:14px;padding:18px 22px;border:1px solid var(--line);background:var(--panel);border-left:6px solid var(--ok)}
.verdict.crit{border-left-color:var(--crit)}.verdict.high{border-left-color:var(--high)}.verdict.med{border-left-color:var(--med)}
.verdict h2{margin:0;font-size:20px;font-weight:600}.verdict p{margin:2px 0 0;color:var(--mute);font-size:14px}
.info{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px 18px;margin:12px 0;padding:12px 16px;background:var(--panel);border:1px solid var(--line);border-radius:12px;font-size:13px;word-break:break-all}
.info span{color:var(--mute);display:block}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:14px 0}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;cursor:pointer;text-align:left}
.stat b{display:block;font-size:26px;font-weight:600;line-height:1.1}.stat span{font-size:13px;color:var(--mute)}.stat.on{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
h3{margin:22px 0 8px;font-size:15px;font-weight:600}
.tools{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.tools input{flex:1 1 220px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 12px}
.mod{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin-bottom:8px;overflow:hidden;border-left:5px solid var(--low)}
.mod[data-sev=crit]{border-left-color:var(--crit)}.mod[data-sev=high]{border-left-color:var(--high)}.mod[data-sev=med]{border-left-color:var(--med)}.mod[data-sev=ok]{border-left-color:var(--ok)}
.mod>summary{display:grid;grid-template-columns:90px 1fr auto 18px;gap:14px;align-items:center;padding:12px 16px;cursor:pointer;list-style:none}
.mod>summary::-webkit-details-marker{display:none}
.pill{font-size:12px;font-weight:600;padding:3px 10px;border-radius:99px;text-align:center}
.pill.crit{background:var(--crit-bg);color:var(--crit)}.pill.high{background:var(--high-bg);color:var(--high)}.pill.med{background:var(--med-bg);color:var(--med)}.pill.low{background:var(--low-bg);color:var(--low)}.pill.ok{background:var(--ok-bg);color:var(--ok)}
.nm{min-width:0}.nm b{font-weight:500;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.nm small{color:var(--mute);font-size:12.5px}
.tags{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}.tag{font-size:12px;border:1px solid var(--line);border-radius:6px;padding:1px 7px;color:var(--mute);white-space:nowrap}.tag.hot{border-color:var(--crit);color:var(--crit);font-weight:600}
.chev{transition:transform .15s;color:var(--mute)}.mod[open] .chev{transform:rotate(90deg)}
.detail{padding:4px 18px 16px;border-top:1px solid var(--line);font-size:14px}
.meta{display:grid;grid-template-columns:auto 1fr;gap:3px 14px;margin:12px 0;font-size:13px}.meta dt{color:var(--mute)}.meta dd{margin:0;word-break:break-all}
.f{border-radius:8px;padding:9px 12px;margin:8px 0;background:var(--low-bg)}.f.crit{background:var(--crit-bg)}.f.high{background:var(--high-bg)}.f.med{background:var(--med-bg)}.f.ok{background:var(--ok-bg)}
.f b{display:block;font-weight:600}.f ul{margin:4px 0 0;padding-left:18px;color:var(--mute);font-size:13px;word-break:break-all}
.empty{text-align:center;color:var(--mute);padding:30px}footer{margin-top:24px;text-align:center;color:var(--mute);font-size:13px}
@media (max-width:640px){.mod>summary{grid-template-columns:80px 1fr 18px}.tags{display:none}}
@media print{.tools,#theme{display:none!important}body{background:#fff}}
</style></head><body>
<header><h1>Mod Scan Report <small>__SUB__</small></h1><button class="btn" id="theme" type="button">Theme</button></header>
<main>
__BODY__
<footer>Heuristic scanner. Manual verification is always recommended.</footer>
</main>
<script>
(function(){
  var F='all',q=document.getElementById('q'),mods=document.querySelectorAll('.mod'),stats=document.querySelectorAll('.stat');
  function apply(){var t=q.value.toLowerCase(),n=0;
    for(var i=0;i<mods.length;i++){var m=mods[i];
      var okf=F==='all'||(F==='session'?m.getAttribute('data-session')==='1':m.getAttribute('data-sev')===F);
      var okq=!t||m.textContent.toLowerCase().indexOf(t)>-1;
      m.hidden=!(okf&&okq);if(!m.hidden)n++;}
    document.getElementById('empty').hidden=n>0;}
  for(var i=0;i<stats.length;i++){stats[i].addEventListener('click',function(){F=this.getAttribute('data-f');
    for(var j=0;j<stats.length;j++)stats[j].classList.remove('on');this.classList.add('on');apply();});}
  q.addEventListener('input',apply);
  document.getElementById('expand').addEventListener('click',function(){
    var open=false;for(var i=0;i<mods.length;i++)if(!mods[i].open)open=true;
    for(var k=0;k<mods.length;k++)mods[k].open=open;this.textContent=open?'Collapse all':'Expand all';});
  document.getElementById('print').addEventListener('click',function(){window.print();});
  window.addEventListener('beforeprint',function(){for(var i=0;i<mods.length;i++)mods[i].open=true;});
  document.getElementById('theme').addEventListener('click',function(){
    var r=document.documentElement;r.setAttribute('data-theme',getComputedStyle(r).colorScheme==='dark'?'light':'dark');});
})();
</script></body></html>
'@
$pageSub = (Enc $env:COMPUTERNAME) + ' - ' + (Get-Date).ToString('MMM dd yyyy HH:mm')
$html = $Template.Replace('__SUB__', $pageSub).Replace('__BODY__', $sb.ToString())

$dl = $null
try { $dl = (New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path } catch {}
if (-not $dl -or -not (Test-Path $dl)) { $dl = Join-Path $env:USERPROFILE 'Downloads' }
if (-not (Test-Path $dl)) { New-Item -ItemType Directory -Path $dl -Force | Out-Null }
$report = Join-Path $dl ("ModScan_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
[File]::WriteAllText($report, $html, (New-Object Text.UTF8Encoding($false)))

# -- Console summary --------------------------------------------------
$c = @{ crit = 0; high = 0; med = 0; low = 0; ok = 0 }; foreach ($m in $mods) { $c[$m.Sev]++ }
$sess = @($mods | Where-Object { $_.Session }).Count
Write-Host ""
Write-Host ("   Scanned {0} mods in {1}s" -f $mods.Count, $secs) -ForegroundColor White
Write-Host ("   Critical: {0}   High: {1}   Review: {2}   Unknown: {3}   Verified: {4}" -f $c.crit, $c.high, $c.med, $c.low, $c.ok) -ForegroundColor $(if ($c.crit -gt 0) { 'Red' } elseif ($c.high -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ("   Modified during session: {0}   Missing: {1}   JVM-injected: {2}" -f $sess, $missing.Count, $inject.Count) -ForegroundColor $(if ($sess -gt 0) { 'Red' } else { 'DarkGray' })
Write-Host "   Report saved: $report" -ForegroundColor Cyan
Write-Host "   MANUAL VERIFICATION IS ALWAYS RECOMMENDED" -ForegroundColor Red
try { Start-Process $report } catch {}
Write-Host ""
pause
