#Requires -Version 5.1
using namespace System.IO
using namespace System.IO.Compression

Add-Type -AssemblyName "System.IO.Compression"
Add-Type -AssemblyName "System.IO.Compression.FileSystem"

$Script:CachedMcProcesses = $null
$Script:RawProcesses      = $null
$Script:AdminChecked      = $false
$Script:IsAdmin           = $false

# ======================================================================
# == CONFIG ============================================================
# ======================================================================
$TriggerIndicators = @{
    "field_1692"="Crosshair target / aimed entity";"method_2918"="Attack entity";"method_6104"="Swing hand"
    "class_1829"="SwordItem";"class_1743"="AxeItem";"method_7261"="Attack cooldown"
}
$SelfDestructIndicators = @{
    "getProtectionDomain"="Checks JAR origin / sandbox";"getCodeSource"="Locates its own JAR path"
    "setLastModified"="Modifies file timestamps";"deleteOnExit"="Schedules JAR deletion on exit"
    "ProcessBuilder"="Launches external processes"
}
$SelfReplaceCombo = @{
    "getCodeSource"="Locates its own JAR";"FileOutputStream"="Writes to disk (self-overwrite)";"openStream"="Downloads remote payload"
}
$NetworkIndicators = [ordered]@{
    "java/net/Socket"="Raw TCP socket";"java/net/ServerSocket"="Opens local server socket"
    "java/net/DatagramSocket"="UDP socket (beacon/DNS)";"java/net/HttpURLConnection"="HTTP connection"
    "java/net/URLConnection"="Generic URL connection";"javax/net/ssl/SSLSocket"="Encrypted SSL socket"
    "java/net/InetAddress"="DNS hostname resolution";"java/nio/channels/SocketChannel"="NIO socket channel"
}
$SuspiciousClassFragments = @("mixin","handler","keyboard","input","event","hook","inject","listener","callback")
$ManifestAgentKeys = [ordered]@{
    "Premain-Class"="Java agent entry point";"Agent-Class"="Attach-API agent"
    "Boot-Class-Path"="Injects JAR into bootstrap classpath";"Can-Redefine-Classes"="Can replace loaded class bytecode"
    "Can-Retransform-Classes"="Can retransform any loaded class";"Can-Set-Native-Method-Prefix"="Can hook native JVM methods"
}
$ObfuscatorSignatures = [ordered]@{
    "allatori"="Allatori";"ZKM"="Zelix KlassMaster";"me/lpk/"="SkidFuscator (LPK)";"zenix/skid"="Zenix SkidFuscator"
    "radon/"="Radon";"bozar"="Bozar";"branchlock"="Branchlock";"com/preemptive"="DashO";"superblaubeere27"="Superblaubeere27"
    "stringer"="Stringer";"javaguard"="JavaGuard";"de/xbrowniecodez"="Branchlock/XBrownie";"com/yworks/yguard"="yGuard"
    "proguard"="ProGuard";"dev/skidfuscator"="Skidfuscator";"skidfuscator.dev"="Skidfuscator";"Paramorphism"="Paramorphism"
    "paramorphism-"="Paramorphism";"ItzSomebody/Radon"="Radon";"sim0n/Caesium"="Caesium";"vimasig/Bozar"="Bozar"
    "branchlock.dev"="Branchlock";"com/binscure"="Binscure";"superblaubeere"="SuperBlaubeere";"QProtect"="QProtect"
    "mdma.dev/qprotect"="QProtect";"ZKMFLOW"="Zelix KlassMaster";"ZelixKlassMaster"="Zelix KlassMaster";"com/zelix"="Zelix KlassMaster"
    "StringerJavaObfuscator"="Stringer";"com/licel/stringer"="Stringer";"JNIC"="JNIC";"jnic.obf"="JNIC"
    "jnic-obfuscator"="JNIC";"ScutiObf"="Scuti";"scuti.obf"="Scuti";"SmokeObf"="Smoke";"smoke.obf"="Smoke"
}
$LegitShortNames = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@("GUI","API","ID","IO","OS","UI","VM","DB","AI","MQ","FX","TK","OK","URL","TCP","UDP","DNS","TLS","SSL",
                "EOF","NIO","RPC","CSV","XML","CLI","CDN","CRC","JWT","AES","RSA","MD5","SHA","PNG","GIF","ZIP","GZip"),
    [System.StringComparer]::OrdinalIgnoreCase
)

# ======================================================================
# == HELPERS ===========================================================
# ======================================================================
function Get-ClassStrings([byte[]]$Bytes) {
    $text = [System.Text.Encoding]::GetEncoding('iso-8859-1').GetString($Bytes)
    return [regex]::Matches($text, '[\x20-\x7e]{4,}') | ForEach-Object { $_.Value }
}
function Get-FileSHA1([string]$Path) {
    try { return (Get-FileHash -Path $Path -Algorithm SHA1 -ErrorAction Stop).Hash } catch { return $null }
}
function ConvertTo-HtmlText([string]$s) {
    if ([string]::IsNullOrEmpty($s)) { return "" }
    return $s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace('"',"&quot;").Replace("'","&#39;")
}
function Get-ModId([string]$JarPath) {
    $stream = $null; $archive = $null
    try {
        $stream  = [File]::OpenRead($JarPath)
        $archive = New-Object ZipArchive($stream, [ZipArchiveMode]::Read, $false)
        foreach ($name in @("fabric.mod.json","quilt.mod.json")) {
            $entry = $archive.GetEntry($name)
            if ($entry) {
                $r = New-Object StreamReader($entry.Open()); $json = $r.ReadToEnd(); $r.Dispose()
                if ($json -match '"id"\s*:\s*"([^"]+)"') { return $Matches[1].ToLower() }
            }
        }
        $entry = $archive.GetEntry("META-INF/mods.toml")
        if ($entry) {
            $r = New-Object StreamReader($entry.Open()); $toml = $r.ReadToEnd(); $r.Dispose()
            if ($toml -match 'modId\s*=\s*"([^"]+)"') { return $Matches[1].ToLower() }
        }
    } catch {} finally { if ($archive) { $archive.Dispose() }; if ($stream) { $stream.Close() } }
    return $null
}

# ======================================================================
# == MODRINTH (PARALLEL) ===============================================
# ======================================================================
function Invoke-ModrinthBatch {
    param([array]$Items)
    $results = [System.Collections.Generic.List[object]]::new()
    if ($Items.Count -eq 0) { return $results }

    $maxThreads = [Math]::Min(10, [Math]::Max(2, $Items.Count))
    $pool = [runspacefactory]::CreateRunspacePool(1, $maxThreads)
    $pool.Open()

    $jobs = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Items) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript({
            param($sha1)
            try {
                $v = Invoke-RestMethod "https://api.modrinth.com/v2/version_file/$sha1" -Method Get -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
                if ($v.project_id) {
                    $p = Invoke-RestMethod "https://api.modrinth.com/v2/project/$($v.project_id)" -Method Get -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
                    [PSCustomObject]@{ Found=$true; Name=$p.title; Slug=$p.slug; Author=$p.author; Url="https://modrinth.com/mod/$($p.slug)"; Version=$v.name }
                    return
                }
            } catch {}
            [PSCustomObject]@{ Found=$false }
        }).AddArgument($item.SHA1)
        $jobs.Add([PSCustomObject]@{ PS=$ps; Handle=$ps.BeginInvoke(); Item=$item })
    }
    foreach ($job in $jobs) {
        try {
            $out = $job.PS.EndInvoke($job.Handle)
            $m = if ($out -and $out.Count -gt 0) { $out[0] } else { [PSCustomObject]@{ Found=$false } }
            $results.Add([PSCustomObject]@{ Jar=$job.Item.Jar; ModId=$job.Item.ModId; SHA1=$job.Item.SHA1; Modrinth=$m })
        } catch {
            $results.Add([PSCustomObject]@{ Jar=$job.Item.Jar; ModId=$job.Item.ModId; SHA1=$job.Item.SHA1; Modrinth=[PSCustomObject]@{ Found=$false } })
        } finally { $job.PS.Dispose() }
    }
    $pool.Close(); $pool.Dispose()
    return $results
}

# ======================================================================
# == DOWNLOAD SOURCE ===================================================
# ======================================================================
function Get-DownloadSource([string]$FilePath) {
    $evidence = [System.Collections.Generic.List[string]]::new()
    $fileItem = Get-Item $FilePath -ErrorAction SilentlyContinue
    $rawName  = [Path]::GetFileName($FilePath).ToLower()
    try {
        $ads = Get-Content -Path $FilePath -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($ads) {
            $hostUrl=""; $referrerUrl=""; $zoneId=""
            foreach ($line in $ads) {
                if ($line -match "^ZoneId=(\d)") { $zoneId=$Matches[1] }
                elseif ($line -match "^HostUrl=(.+)") { $hostUrl=$Matches[1].Trim() }
                elseif ($line -match "^ReferrerUrl=(.+)") { $referrerUrl=$Matches[1].Trim() }
            }
            if ($hostUrl) {
                $src = $hostUrl
                if ($hostUrl -match "modrinth\.com")           { $src="Modrinth" }
                elseif ($hostUrl -match "curseforge\.com")     { $src="CurseForge" }
                elseif ($hostUrl -match "github\.com")         { $src="GitHub" }
                elseif ($hostUrl -match "discordapp|discord\.com") { $src="Discord CDN" }
                elseif ($hostUrl -match "mediafire\.com")      { $src="MediaFire" }
                elseif ($hostUrl -match "mega\.nz")            { $src="MEGA" }
                elseif ($hostUrl -match "dropbox\.com")        { $src="Dropbox" }
                elseif ($hostUrl -match "drive\.google\.com")  { $src="Google Drive" }
                elseif ($hostUrl -match "https?://(?:www\.)?([^/]+)") { $src=$Matches[1] }
                $evidence.Add("Source: $src"); $evidence.Add("URL: $hostUrl")
            }
            if ($referrerUrl) { $evidence.Add("Referer: $referrerUrl") }
            if ($zoneId -eq "3" -and -not $hostUrl) { $evidence.Add("Downloaded from Internet (Zone 3)") }
        }
    } catch {}
    if ($rawName -match "^download\d*(\.\w+)?$")   { $evidence.Add("[Name] Generic download filename") }
    if ($rawName -match "discord|discordapp")       { $evidence.Add("[Name] Filename references Discord") }
    if ($rawName -match "^[a-f0-9]{8,}(\.\w+)?$")  { $evidence.Add("[Name] Hash-style filename") }
    if ($evidence.Count -eq 0) { return @("No download trace found") }
    return $evidence
}

# ======================================================================
# == MANIFEST SCAN =====================================================
# ======================================================================
function Invoke-ManifestScan([string]$JarPath) {
    $result = [PSCustomObject]@{ AgentEntries=[System.Collections.Generic.List[object]]::new(); JvmFlags=[System.Collections.Generic.List[string]]::new(); HasFindings=$false }
    $stream=$null; $archive=$null
    try {
        $stream  = [File]::OpenRead($JarPath)
        $archive = New-Object ZipArchive($stream, [ZipArchiveMode]::Read, $false)
        $mfEntry = $archive.GetEntry("META-INF/MANIFEST.MF")
        if ($mfEntry) {
            $r = New-Object StreamReader($mfEntry.Open()); $mf = $r.ReadToEnd(); $r.Dispose()
            foreach ($key in $ManifestAgentKeys.Keys) {
                $pattern = "(?m)^$([regex]::Escape($key))\s*:\s*(.+)$"
                if ($mf -match $pattern) {
                    $val = $Matches[1].Trim()
                    if ($key -match "^Can-" -and $val -ine "true") { continue }
                    $result.AgentEntries.Add([PSCustomObject]@{ Key=$key; Value=$val; Meaning=$ManifestAgentKeys[$key] })
                }
            }
            if ($mf -match "-javaagent:")    { $result.JvmFlags.Add("-javaagent flag found") }
            if ($mf -match "Xbootclasspath") { $result.JvmFlags.Add("Xbootclasspath override") }
        }
    } catch {} finally { if ($archive) { $archive.Dispose() }; if ($stream) { $stream.Close() } }
    $result.HasFindings = ($result.AgentEntries.Count -gt 0) -or ($result.JvmFlags.Count -gt 0)
    return $result
}

# ======================================================================
# == JAR DEEP SCAN =====================================================
# ======================================================================
function Invoke-JarScan([string]$JarPath) {
    $result = [PSCustomObject]@{
        Triggerbot=[System.Collections.Generic.List[object]]::new()
        SelfDestruct=[System.Collections.Generic.List[object]]::new()
        SuspiciousURLs=[System.Collections.Generic.List[object]]::new()
        NetworkCode=[System.Collections.Generic.List[object]]::new()
        JvmArgStrings=[System.Collections.Generic.List[string]]::new()
        Obfuscation=[PSCustomObject]@{
            Grade="CLEAN"; Percent=0; KnownTools=[System.Collections.Generic.List[string]]::new()
            Flags=[System.Collections.Generic.List[string]]::new(); TotalClasses=0
            NumericCount=0; UnicodeCount=0; FullwidthCount=0; JapaneseCount=0
            SingleLetterCount=0; TwoLetterCount=0; GibberishCount=0; NoVowelCount=0
            ConfusionCount=0; SingleCharPkg=0; EntropyNote=""; ShortClasses=0
        }
    }
    $stream=$null; $archive=$null
    try {
        $stream  = [File]::OpenRead($JarPath)
        $archive = New-Object ZipArchive($stream, [ZipArchiveMode]::Read, $false)
        $contentSample = [System.Text.StringBuilder]::new()
        $sampleSize = 0

        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -notlike "*.class") { continue }
            $es = $entry.Open(); $ms = New-Object MemoryStream; $es.CopyTo($ms); $bytes = $ms.ToArray(); $es.Dispose(); $ms.Dispose()
            $strings = Get-ClassStrings $bytes
            $entryShort = $entry.FullName; $entryLower = $entryShort.ToLower()
            $obf = $result.Obfuscation; $obf.TotalClasses++
            $className = [System.IO.Path]::GetFileNameWithoutExtension(($entryShort -split "[/\\]")[-1])

            if ($className -match "^\d+$") { $obf.NumericCount++ }
            if ($className -match "[^\x00-\x7F]") { $obf.UnicodeCount++ }
            if ($className -match "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]") { $obf.FullwidthCount++ }
            if ($className -match "[\u3040-\u309F\u30A0-\u30FF]") { $obf.JapaneseCount++ }
            if ($className -match "^[a-zA-Z]$") { $obf.SingleLetterCount++ }
            if ($className -match "^[a-zA-Z]{2}$") { $obf.TwoLetterCount++ }
            if ($className -match "^[Il1O0]+$" -or $className -match "^[_]+$") { $obf.ConfusionCount++ }
            if ($className.Length -ge 3 -and $className.Length -le 8 -and $className -match "^[a-zA-Z]+$") {
                $vowels = ($className.ToCharArray() | Where-Object { $_ -match "[aeiouAEIOU]" }).Count
                if ($vowels -eq 0) { $obf.NoVowelCount++ }
                if ($className -match "[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]{3,}" -and ($vowels / $className.Length) -lt 0.3) { $obf.GibberishCount++ }
            }
            $segs = ($entryShort -replace "\.class$", "") -split "[/\\]"
            foreach ($seg in $segs[0..($segs.Count - 2)]) { if ($seg.Length -eq 1) { $obf.SingleCharPkg++ } }
            $baseName = $segs[-1] -replace '\$.*$',''
            if ($baseName.Length -le 2 -and $baseName.Length -ge 1 -and $baseName -match "^[a-zA-Z]+$" -and -not $LegitShortNames.Contains($baseName)) { $obf.ShortClasses++ }

            $combinedCtx = ($entryLower + " " + ($strings -join " ")).ToLower()
            foreach ($sig in $ObfuscatorSignatures.Keys) {
                if ($combinedCtx.Contains($sig.ToLower())) {
                    $tool = $ObfuscatorSignatures[$sig]
                    if (-not $obf.KnownTools.Contains($tool)) { [void]$obf.KnownTools.Add($tool) }
                }
            }
            if ($sampleSize -lt 150000 -and $entry.Length -lt 100000 -and $entry.Length -gt 100) {
                [void]$contentSample.Append([System.Text.Encoding]::ASCII.GetString($bytes)); $sampleSize += $bytes.Length
            }
            foreach ($s in $strings) {
                if ($s -match "-javaagent:" -and -not ($result.JvmArgStrings | Where-Object { $_ -match [regex]::Escape($entryShort) })) {
                    [void]$result.JvmArgStrings.Add("Hardcoded -javaagent in: $entryShort")
                }
                if ($s -match "Xbootclasspath" -and -not ($result.JvmArgStrings | Where-Object { $_ -match [regex]::Escape($entryShort) })) {
                    [void]$result.JvmArgStrings.Add("Bootclasspath string in: $entryShort")
                }
            }
            $isSuspicious = $SuspiciousClassFragments | Where-Object { $entryLower -match $_ }

            foreach ($ind in $TriggerIndicators.Keys) {
                if ($strings -match [regex]::Escape($ind)) {
                    [void]$result.Triggerbot.Add([PSCustomObject]@{ Code=$ind; Meaning=$TriggerIndicators[$ind]; File=$entryShort })
                }
            }
            foreach ($ind in $SelfDestructIndicators.Keys) {
                if ($strings -match [regex]::Escape($ind)) {
                    [void]$result.SelfDestruct.Add([PSCustomObject]@{ Code=$ind; Meaning=$SelfDestructIndicators[$ind]; File=$entryShort; IsCombo=$false })
                }
            }
            $comboScore=0; $comboHit=[System.Collections.Generic.List[string]]::new()
            foreach ($token in $SelfReplaceCombo.Keys) {
                if ($strings -match [regex]::Escape($token)) { $comboScore++; [void]$comboHit.Add("$token ($($SelfReplaceCombo[$token]))") }
            }
            if ($comboScore -ge 2) {
                [void]$result.SelfDestruct.Add([PSCustomObject]@{ Code="[COMBO] Self-replace"; Meaning="$comboScore/3 matched: $($comboHit -join ' | ')"; File=$entryShort; IsCombo=$true })
            }
            if ($isSuspicious) {
                foreach ($s in $strings) {
                    if ($s -match "^https?://") { [void]$result.SuspiciousURLs.Add([PSCustomObject]@{ Code=$s.Substring(0,[Math]::Min($s.Length,140)); File=$entryShort }) }
                }
                foreach ($ind in $NetworkIndicators.Keys) {
                    if ($strings -match [regex]::Escape($ind)) {
                        [void]$result.NetworkCode.Add([PSCustomObject]@{ Code=$ind; Meaning=$NetworkIndicators[$ind]; File=$entryShort })
                    }
                }
            }
        }

        $obf = $result.Obfuscation
        if ($obf.TotalClasses -ge 5) {
            $pct = { param($n) [math]::Round(($n / $obf.TotalClasses) * 100) }
            if ((& $pct $obf.NumericCount) -ge 20)        { $obf.Flags.Add("Numeric class names ($(& $pct $obf.NumericCount)%)") }
            if ((& $pct $obf.UnicodeCount) -ge 10)        { $obf.Flags.Add("Unicode class names ($(& $pct $obf.UnicodeCount)%)") }
            if ($obf.FullwidthCount -gt 0)                { $obf.Flags.Add("Fullwidth Unicode ($(& $pct $obf.FullwidthCount)%)") }
            if ($obf.JapaneseCount -gt 0)                 { $obf.Flags.Add("Japanese char names ($(& $pct $obf.JapaneseCount)%)") }
            if ((& $pct $obf.SingleLetterCount) -ge 15)   { $obf.Flags.Add("Single-letter names ($(& $pct $obf.SingleLetterCount)%)") }
            if ((& $pct $obf.TwoLetterCount) -ge 20)      { $obf.Flags.Add("Two-letter names ($(& $pct $obf.TwoLetterCount)%)") }
            if ((& $pct $obf.GibberishCount) -ge 5)       { $obf.Flags.Add("Gibberish names ($(& $pct $obf.GibberishCount)%)") }
            if ((& $pct $obf.NoVowelCount) -ge 8)         { $obf.Flags.Add("No-vowel names ($(& $pct $obf.NoVowelCount)%)") }
            if ((& $pct $obf.ConfusionCount) -ge 3)       { $obf.Flags.Add("Confusion chars ($(& $pct $obf.ConfusionCount)%)") }
            if ($obf.SingleCharPkg -ge 6)                 { $obf.Flags.Add("Single-char packages ($($obf.SingleCharPkg) segs)") }
            $fwStringMatches = [regex]::Matches($contentSample.ToString(), "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]{2,}")
            if ($fwStringMatches.Count -gt 0) { $obf.Flags.Add("Fullwidth strings in bytecode ($($fwStringMatches.Count))") }
            $sampleStr = $contentSample.ToString()
            foreach ($sig in $ObfuscatorSignatures.Keys) {
                if ($sampleStr.Contains($sig)) {
                    $tool = $ObfuscatorSignatures[$sig]
                    if (-not $obf.KnownTools.Contains($tool)) { [void]$obf.KnownTools.Add($tool) }
                }
            }
        }
        $ratio = if ($obf.TotalClasses -gt 0) { $obf.ShortClasses / $obf.TotalClasses } else { 0 }
        if ($obf.TotalClasses -gt 5 -and $ratio -gt 0.35) { $obf.EntropyNote = "$($obf.ShortClasses)/$($obf.TotalClasses) short names ({0:P0})" -f $ratio }
        $basePct = [math]::Round($ratio * 60)
        $toolPct = [math]::Min(35, $obf.KnownTools.Count * 17)
        $bonus   = if ($ratio -gt 0.70) { 10 } elseif ($ratio -gt 0.50) { 5 } else { 0 }
        $flagBonus = [math]::Min(25, $obf.Flags.Count * 5)
        $obf.Percent = [math]::Min(100, $basePct + $toolPct + $bonus + $flagBonus)
        if      ($obf.Percent -ge 80) { $obf.Grade = "HEAVILY OBFUSCATED" }
        elseif  ($obf.Percent -ge 50) { $obf.Grade = "OBFUSCATED" }
        elseif  ($obf.Percent -ge 20) { $obf.Grade = "LIGHTLY OBFUSCATED" }
        else                          { $obf.Grade = "CLEAN" }
    } catch {
        Write-Host "      [!] Cannot read $([Path]::GetFileName($JarPath)): $_" -ForegroundColor DarkRed
    } finally { if ($archive) { $archive.Dispose() }; if ($stream) { $stream.Close() } }
    return $result
}

# ======================================================================
# == PROCESS DETECTION (CACHED) ========================================
# ======================================================================
function Get-MinecraftJavaProcesses {
    if ($Script:CachedMcProcesses -ne $null) { return $Script:CachedMcProcesses }

    if ($null -eq $Script:RawProcesses) {
        try { $Script:RawProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop) } catch { $Script:RawProcesses = @() }
    }
    $allProcs = $Script:RawProcesses

    $candidates = [System.Collections.Generic.List[object]]::new()
    $seenPids   = [System.Collections.Generic.HashSet[int]]::new()

    function Add-Candidate($ProcId,$Name,$CmdLine,$CreationDate,$Confidence,$LauncherHint,$WorkingSetMB) {
        if ($seenPids.Contains($ProcId)) { return }
        [void]$seenPids.Add($ProcId)
        $normalizedDate = $null
        if ($CreationDate -is [datetime]) { $normalizedDate = $CreationDate }
        elseif ($CreationDate -is [string] -and -not [string]::IsNullOrWhiteSpace($CreationDate)) {
            try { $normalizedDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($CreationDate) } catch { $normalizedDate = [datetime]::Now }
        } else { $normalizedDate = [datetime]::Now }
        [void]$candidates.Add([PSCustomObject]@{ ProcessId=$ProcId; Name=$Name; CommandLine=$CmdLine; CreationDate=$normalizedDate; Confidence=$Confidence; LauncherHint=$LauncherHint; WorkingSetMB=$WorkingSetMB })
    }

    foreach ($proc in ($allProcs | Where-Object { $_.Name -match '^java(w)?\.exe$' })) {
        $cmd = if ($proc.CommandLine) { $proc.CommandLine } else { "" }
        $isMc=$false; $confidence=0; $launcherHint=""; $memMB=0
        if ($cmd -match '(?i)net\.minecraft\.client\.main\.Main') { $isMc=$true; $confidence=100; $launcherHint="Vanilla" }
        elseif ($cmd -match '(?i)net\.minecraft\.launchwrapper\.Launch') { $isMc=$true; $confidence=100; $launcherHint="Legacy Forge" }
        elseif ($cmd -match '(?i)cpw\.mods\.modlauncher\.Launcher') { $isMc=$true; $confidence=100; $launcherHint="Modern Forge" }
        elseif ($cmd -match '(?i)net\.fabricmc\.loader\.impl\.launch\.knot\.KnotClient') { $isMc=$true; $confidence=100; $launcherHint="Fabric" }
        elseif ($cmd -match '(?i)net\.fabricmc\.loader\.launch\.knot\.KnotClient') { $isMc=$true; $confidence=100; $launcherHint="Fabric (legacy)" }
        elseif ($cmd -match '(?i)org\.quiltmc\.loader\.impl\.launch\.knot\.KnotClient') { $isMc=$true; $confidence=100; $launcherHint="Quilt" }
        elseif ($cmd -match '(?i)\.minecraft') { $isMc=$true; $confidence=80; $launcherHint=".minecraft path" }
        elseif ($cmd -match '(?i)lwjgl') { $isMc=$true; $confidence=70; $launcherHint="LWJGL" }
        elseif ($cmd -match '(?i)feather') { $isMc=$true; $confidence=90; $launcherHint="Feather" }
        elseif ($cmd -match '(?i)minecraft|fabric|forge|quilt|lunar|badlion') { $isMc=$true; $confidence=60; $launcherHint="Generic hint" }
        if (-not $isMc -and $proc.ParentProcessId) {
            $parent = $allProcs | Where-Object { $_.ProcessId -eq $proc.ParentProcessId } | Select-Object -First 1
            if ($parent -and $parent.Name.ToLower() -match 'minecraft|feather|lunar|badlion|multimc|prismlauncher|curseforge|atlauncher|gdlauncher') {
                $isMc=$true; $confidence=75; $launcherHint="Parent: $($parent.Name)"
            }
        }
        try {
            $memMB = [math]::Round($proc.WorkingSetSize / 1MB, 0)
            if ($memMB -gt 400 -and $confidence -ge 50) { $confidence += 10 }
            if (-not $isMc -and $memMB -gt 800) { $isMc=$true; $confidence=40; $launcherHint="High memory Java ($memMB MB)" }
        } catch {}
        if ($isMc) { Add-Candidate -ProcId $proc.ProcessId -Name $proc.Name -CmdLine $cmd -CreationDate $proc.CreationDate -Confidence $confidence -LauncherHint $launcherHint -WorkingSetMB $memMB }
    }

    try {
        $windowMatches = Get-Process | Where-Object {
            ($_.MainWindowTitle -match 'Minecraft') -or ($_.MainWindowTitle -match 'Feather Client') -or
            ($_.MainWindowTitle -match 'Lunar Client') -or ($_.MainWindowTitle -match 'Badlion Client')
        }
        foreach ($wp in $windowMatches) {
            $wmiProc = $allProcs | Where-Object { $_.ProcessId -eq $wp.Id } | Select-Object -First 1
            if ($wp.Name -match '^java' -or ($wp.Path -and $wp.Path -match '\\bin\\java')) {
                $cmd = if ($wmiProc -and $wmiProc.CommandLine) { $wmiProc.CommandLine } else { $wp.Path }
                $startTime = $null; try { $startTime = $wp.StartTime } catch {}
                Add-Candidate -ProcId $wp.Id -Name ($wp.Name + ".exe") -CmdLine $cmd -CreationDate (if ($wmiProc) { $wmiProc.CreationDate } else { $startTime }) -Confidence 70 -LauncherHint "Window: $($wp.MainWindowTitle)" -WorkingSetMB ([math]::Round($wp.WorkingSet64 / 1MB, 0))
            }
            $children = $allProcs | Where-Object { $_.ParentProcessId -eq $wp.Id -and $_.Name -match '^java(w)?\.exe$' }
            foreach ($child in $children) {
                $cmd = if ($child.CommandLine) { $child.CommandLine } else { "" }
                Add-Candidate -ProcId $child.ProcessId -Name $child.Name -CmdLine $cmd -CreationDate $child.CreationDate -Confidence 85 -LauncherHint "Child of $($wp.Name)" -WorkingSetMB (if ($child.WorkingSetSize) { [math]::Round($child.WorkingSetSize / 1MB, 0) } else { 0 })
            }
        }
    } catch {}

    $Script:CachedMcProcesses = @($candidates | Sort-Object Confidence, CreationDate -Descending)
    return $Script:CachedMcProcesses
}

function Get-MinecraftLaunchTimeUtc {
    $procs = Get-MinecraftJavaProcesses
    if (-not $procs -or $procs.Count -eq 0) { return $null }
    return $procs[0].CreationDate.ToUniversalTime()
}
function Test-IsAdmin {
    if ($Script:AdminChecked) { return $Script:IsAdmin }
    $Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $Script:AdminChecked = $true
    return $Script:IsAdmin
}

# ======================================================================
# == USN JOURNAL =======================================================
# ======================================================================
$USN_REASON_DATA_OVERWRITE        = [uint32]0x00000001
$USN_REASON_DATA_EXTEND           = [uint32]0x00000002
$USN_REASON_DATA_TRUNCATION       = [uint32]0x00000004
$USN_REASON_FILE_CREATE           = [uint32]0x00000100
$USN_REASON_FILE_DELETE           = [uint32]0x00000200
$USN_REASON_RENAME_OLD_NAME       = [uint32]0x00001000
$USN_REASON_RENAME_NEW_NAME       = [uint32]0x00002000
$USN_REASON_BASIC_INFO_CHANGE     = [uint32]0x00008000
$USN_REASON_CLOSE                 = [uint32]0x80000000L

function Normalize-HexId([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw)) { return "" }
    $s = $Raw.Trim().Trim('"').ToLower()
    if ($s -match '^0[xX](.+)$') { $s = $Matches[1] }
    $s = $s.TrimStart('0'); if ($s -eq "") { $s = "0" }
    return $s
}
function ConvertFrom-HexReason([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw)) { return [uint32]0 }
    $hex = $Raw.Trim(); if ($hex -match '^0[xX](.+)$') { $hex = $Matches[1] }
    try { return [convert]::ToUInt32($hex, 16) } catch { try { return [uint32]::Parse($hex, [System.Globalization.NumberStyles]::HexNumber) } catch { return [uint32]0 } }
}
function Get-UsnJournalRaw([string]$DriveRoot) {
    $tmp = Join-Path $env:TEMP ("usn_" + [guid]::NewGuid().ToString("N") + ".csv")
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "cmd.exe"; $psi.Arguments = "/c fsutil usn readjournal `"$DriveRoot`" csv > `"$tmp`" 2>nul"
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi); $proc.WaitForExit()
        if ($proc.ExitCode -ne 0 -or -not (Test-Path $tmp)) { return @() }
        [byte[]]$bytes = [System.IO.File]::ReadAllBytes($tmp)
        $oemEncoding = [Console]::OutputEncoding
        return ($oemEncoding.GetString($bytes) -split "`r?`n")
    } catch { return @() } finally { if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } }
}

function Get-UsnJournalData([string]$ModsPath, [System.Collections.Generic.HashSet[string]]$CurrentJarNames) {
    $entries = [System.Collections.Generic.List[object]]::new()
    if (-not (Test-IsAdmin)) { return $entries }
    try {
        if (-not (Test-Path $ModsPath)) { return $entries }
        $resolved = Resolve-Path $ModsPath -ErrorAction Stop
        $root = ([Path]::GetPathRoot($resolved.Path)).TrimEnd('\')
        if (-not $root) { return $entries }
        $lines = Get-UsnJournalRaw -DriveRoot $root
        if (-not $lines -or ($lines.Count -eq 1 -and [string]::IsNullOrWhiteSpace($lines[0]))) { return $entries }

        $headerIdx = -1
        for ($i=0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]; if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line -match '\s*:\s*' -and $line -notmatch ',') { continue }
            $lower = $line.ToLower()
            if ($lower -match 'usn' -and $lower -match 'file name' -and $lower -match 'reason') { $headerIdx = $i; break }
        }
        if ($headerIdx -lt 0) { return $entries }

        $headerLine = $lines[$headerIdx] -replace "^\xEF\xBB\xBF","" -replace "^\xFE\xFF","" -replace "^\xFF\xFE",""
        $hdr = $headerLine -split ',' | ForEach-Object { $_.Trim().Trim('"') }
        $idxName=-1; $idxReason=-1; $idxReasonNum=-1; $idxTime=-1; $idxFileID=-1; $idxParentID=-1
        for ($h=0; $h -lt $hdr.Count; $h++) {
            $col = $hdr[$h].ToLower().Trim()
            if ($col -eq 'filename' -or $col -eq 'file name') { $idxName = $h }
            if ($col -eq 'reason') { $idxReason = $h }
            if ($col -eq 'reason #' -or $col -eq 'reason#') { $idxReasonNum = $h }
            if ($col -eq 'timestamp' -or $col -eq 'time stamp') { $idxTime = $h }
            if ($col -eq 'fileid' -or $col -eq 'file id') { $idxFileID = $h }
            if ($col -eq 'parentfileid' -or $col -eq 'parent file id') { $idxParentID = $h }
        }
        if ($idxName -lt 0 -or ($idxReason -lt 0 -and $idxReasonNum -lt 0)) { return $entries }

        $folderRef = $null
        try {
            $batFile = Join-Path $env:TEMP ("qfi_" + [guid]::NewGuid().ToString("N") + ".bat")
            '@echo off' | Out-File -FilePath $batFile -Encoding ASCII
            ('fsutil file queryfileid "' + $ModsPath + '"') | Out-File -FilePath $batFile -Append -Encoding ASCII
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "cmd.exe"; $psi.Arguments = '/c "' + $batFile + '"'
            $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $q = $proc.StandardOutput.ReadToEnd(); $proc.StandardError.ReadToEnd() | Out-Null; $proc.WaitForExit()
            Remove-Item $batFile -Force -ErrorAction SilentlyContinue
            $q = $q.Trim()
            if ($q -match '0x([0-9a-fA-F]+)') { $folderRef = Normalize-HexId $Matches[1] }
        } catch {}

        for ($i = $headerIdx + 1; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]; if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line -match '\s*:\s*' -and $line -notmatch ',') { continue }
            $parts = [System.Collections.Generic.List[string]]::new(); $current=""; $inQuotes=$false
            for ($c=0; $c -lt $line.Length; $c++) {
                $ch = $line[$c]
                if ($ch -eq '"') { $inQuotes = -not $inQuotes; continue }
                if ($ch -eq ',' -and -not $inQuotes) { $parts.Add($current.Trim()); $current = ""; continue }
                $current += $ch
            }
            $parts.Add($current.Trim())
            if ($parts.Count -le $idxName) { continue }
            $filename = $parts[$idxName].Trim('"')
            if ($filename -notlike "*.jar") { continue }
            [uint32]$reasonVal = 0; $reasonHex=""; $reasonText=""
            if ($idxReasonNum -ge 0 -and $parts.Count -gt $idxReasonNum) {
                $rawHex = $parts[$idxReasonNum].Trim('"'); $reasonVal = ConvertFrom-HexReason $rawHex
                if ($reasonVal -ne 0) { $reasonHex = $rawHex }
            }
            if ($idxReason -ge 0 -and $parts.Count -gt $idxReason) { $reasonText = $parts[$idxReason].Trim('"') }
            $timestampStr = ""
            if ($idxTime -ge 0 -and $parts.Count -gt $idxTime) { $timestampStr = $parts[$idxTime].Trim('"') }
            $fileID = $null; if ($idxFileID -ge 0 -and $parts.Count -gt $idxFileID) { $fileID = Normalize-HexId $parts[$idxFileID] }
            $parentFileID = $null; if ($idxParentID -ge 0 -and $parts.Count -gt $idxParentID) { $parentFileID = Normalize-HexId $parts[$idxParentID] }

            $parentMatch = $false; $nameMatch = $false
            if ($folderRef -and $parentFileID -and $parentFileID -eq $folderRef) { $parentMatch = $true }
            if ($CurrentJarNames -and $CurrentJarNames.Count -gt 0 -and $CurrentJarNames.Contains($filename)) { $nameMatch = $true }
            if ($folderRef -and -not $parentMatch -and -not $nameMatch) { continue }

            $timestamp = [datetime]::MinValue
            if (-not [string]::IsNullOrWhiteSpace($timestampStr)) {
                try { $timestamp = [datetime]::Parse($timestampStr, [System.Globalization.CultureInfo]::CurrentCulture) } catch {}
            }
            [void]$entries.Add([PSCustomObject]@{
                FileName=$filename; ReasonHex=$reasonHex; ReasonValue=$reasonVal; ReasonText=$reasonText
                TimeStamp=$timestamp; FileID=$fileID; ParentFileID=$parentFileID
                MatchedByParent=$parentMatch; MatchedByName=$nameMatch
            })
        }
    } catch {}
    return $entries
}

function Get-UsnReplacementEvidence([string]$ModsPath, [nullable[datetime]]$MinecraftLaunchUtc, [System.Collections.Generic.HashSet[string]]$CurrentJarNames) {
    $evidence = @{}
    $allEntries = Get-UsnJournalData -ModsPath $ModsPath -CurrentJarNames $CurrentJarNames
    if ($allEntries.Count -eq 0) { return $evidence }
    foreach ($g in ($allEntries | Group-Object -Property FileName)) {
        $name = $g.Name; $sorted = $g.Group | Sort-Object TimeStamp
        $hasDelete=$false; $hasCreate=$false; $hasOverwrite=$false; $hasDataExtend=$false
        $hasDataTruncation=$false; $hasBasicInfoChange=$false; $hasRenameNew=$false; $hasClose=$false
        $deleteTime=$null; $createTime=$null; $overwriteTime=$null; $extendTime=$null; $truncationTime=$null; $basicInfoTime=$null; $lastActivity=$null
        foreach ($entry in $sorted) {
            $r = $entry.ReasonValue
            if ($r -band $USN_REASON_FILE_DELETE)       { $hasDelete=$true; $deleteTime=$entry.TimeStamp }
            if ($r -band $USN_REASON_FILE_CREATE)       { $hasCreate=$true; $createTime=$entry.TimeStamp }
            if ($r -band $USN_REASON_DATA_OVERWRITE)    { $hasOverwrite=$true; $overwriteTime=$entry.TimeStamp }
            if ($r -band $USN_REASON_DATA_EXTEND)       { $hasDataExtend=$true; $extendTime=$entry.TimeStamp }
            if ($r -band $USN_REASON_DATA_TRUNCATION)   { $hasDataTruncation=$true; $truncationTime=$entry.TimeStamp }
            if ($r -band $USN_REASON_BASIC_INFO_CHANGE) { $hasBasicInfoChange=$true; $basicInfoTime=$entry.TimeStamp }
            if ($r -band $USN_REASON_RENAME_NEW_NAME)   { $hasRenameNew=$true }
            if ($r -band $USN_REASON_CLOSE)             { $hasClose=$true }
            $lastActivity = $entry.TimeStamp
        }
        $flags = [System.Collections.Generic.List[string]]::new(); $score = 0
        if ($hasDelete -and $hasCreate) { $score+=3; [void]$flags.Add("FILE DELETED then RECREATED") }
        if ($hasCreate -and ($hasDataExtend -or $hasDataTruncation)) { $score+=2; [void]$flags.Add("FILE CONTENT CHANGED after creation") }
        if (($hasDataExtend -or $hasDataTruncation) -and $hasBasicInfoChange) { $score+=3; [void]$flags.Add("FILE REWRITTEN (data + basic info)") }
        if ($hasOverwrite -and ($hasDataExtend -or $hasDataTruncation) -and $hasBasicInfoChange) { $score+=4; [void]$flags.Add("IN-PLACE REWRITE (strong signal)") }
        if ($hasOverwrite -and ($hasDataExtend -or $hasDataTruncation) -and $hasClose) {
            if (-not ($hasOverwrite -and ($hasDataExtend -or $hasDataTruncation) -and $hasBasicInfoChange)) { $score+=2; [void]$flags.Add("FILE OVERWRITTEN in-place") }
        }
        if ($hasBasicInfoChange) {
            if (-not (($hasDataExtend -or $hasDataTruncation) -and $hasBasicInfoChange) -and -not ($hasOverwrite -and ($hasDataExtend -or $hasDataTruncation) -and $hasBasicInfoChange)) {
                $score+=1; [void]$flags.Add("BASIC INFO CHANGED")
            }
        }
        if ($hasRenameNew) { $score+=2; [void]$flags.Add("FILE RENAMED") }
        if ($hasCreate -and $MinecraftLaunchUtc -ne $null -and $createTime -gt $MinecraftLaunchUtc) { $score+=1; [void]$flags.Add("Created AFTER Minecraft launch") }
        if ($hasDelete -and -not $hasCreate) { $score+=1; [void]$flags.Add("FILE DELETED and not recreated") }
        if ($hasCreate -and -not $hasDelete -and -not ($hasDataExtend -or $hasDataTruncation)) { $score+=1; [void]$flags.Add("NEW FILE created") }
        if ($score -gt 0) {
            $evidence[$name] = [PSCustomObject]@{ Score=$score; Flags=$flags; LastActivity=$lastActivity; EntryCount=$sorted.Count }
        }
    }
    return $evidence
}

function Get-UsnMissingMods([string]$ModsPath, [hashtable]$UsnEvidence, [System.IO.FileInfo[]]$CurrentJars) {
    $result = [System.Collections.Generic.List[object]]::new()
    if (-not $UsnEvidence) { return @() }
    $currentNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($jar in $CurrentJars) { [void]$currentNames.Add($jar.Name) }
    foreach ($name in $UsnEvidence.Keys) {
        $ev = $UsnEvidence[$name]; $wasDeletedOnly = $false
        foreach ($flag in $ev.Flags) { if ($flag -match "FILE DELETED and not recreated") { $wasDeletedOnly = $true; break } }
        if ($wasDeletedOnly -and -not $currentNames.Contains($name)) {
            [void]$result.Add([PSCustomObject]@{ JarName=$name; FullPath="N/A"; Reason="Deleted from mods folder (USN: FILE DELETE, no recreation)"; Source="usn" })
        }
    }
    return @($result)
}

# ======================================================================
# == MOD METADATA + REPLACEMENT AUDIT ==================================
# ======================================================================
function Get-ModNameAndClassRoots([string]$JarPath) {
    $roots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $modId=$null; $modName=$null; $ver=$null
    $stream=$null; $archive=$null
    try {
        $stream  = [File]::OpenRead($JarPath)
        $archive = New-Object ZipArchive($stream, [ZipArchiveMode]::Read, $false)
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -like "*.class") {
                $path = $entry.FullName -replace '\.class$',''
                $parts = $path -split '[/\\]'
                if ($parts.Count -ge 2) { [void]$roots.Add(($parts[0..($parts.Count-2)] -join '.')) }
            }
        }
        foreach ($jsonFile in @("fabric.mod.json","quilt.mod.json")) {
            $entry = $archive.GetEntry($jsonFile)
            if ($entry) {
                $r = New-Object StreamReader($entry.Open()); $json = $r.ReadToEnd(); $r.Dispose()
                if ($json -match '"id"\s*:\s*"([^"]+)"')       { $modId = $Matches[1].ToLower() }
                if ($json -match '"name"\s*:\s*"([^"]+)"')    { $modName = $Matches[1] }
                if ($json -match '"version"\s*:\s*"([^"]+)"') { $ver = $Matches[1] }
            }
        }
        $entry = $archive.GetEntry("META-INF/mods.toml")
        if ($entry) {
            $r = New-Object StreamReader($entry.Open()); $toml = $r.ReadToEnd(); $r.Dispose()
            if ($toml -match 'modId\s*=\s*"([^"]+)"')       { $modId = $Matches[1].ToLower() }
            if ($toml -match 'displayName\s*=\s*"([^"]+)"') { $modName = $Matches[1] }
            if ($toml -match 'version\s*=\s*"([^"]+)"')     { $ver = $Matches[1] }
        }
    } catch {} finally { if ($archive) { $archive.Dispose() }; if ($stream) { $stream.Close() } }
    return [pscustomobject]@{ ModId=$modId; Name=$modName; Version=$ver; Roots=@($roots) }
}

function Get-ModReplacementAudit {
    param(
        [Parameter(Mandatory)][string]$JarPath,
        [nullable[datetime]]$MinecraftLaunchUtc = $null,
        [hashtable]$UsnEvidence = $null,
        [System.IO.FileInfo]$JarInfo = $null,
        [string]$PrecomputedSha1 = $null,
        [string]$PrecomputedModId = $null
    )
    $reasons  = [System.Collections.Generic.List[string]]::new()
    $evidence = [System.Collections.Generic.List[string]]::new()

    if (-not (Test-Path $JarPath)) {
        [void]$reasons.Add("File missing on disk")
        return [pscustomobject]@{
            Path=$JarPath; Exists=$false; Suspected=$true; Score=999
            Reasons=@($reasons); Evidence=@($evidence); SHA1=$null
            ModId=$null; Version=$null; Name=$null; LastWriteUtc=$null; CreationTimeUtc=$null
            Size=$null; UsnFound=$false; UsnScore=0
            ModifiedDuringSession=$false; ModifiedDuringSessionDetails=@()
        }
    }

    $item = if ($JarInfo) { $JarInfo } else { Get-Item $JarPath -ErrorAction Stop }
    $sha1 = if ($PrecomputedSha1) { $PrecomputedSha1 } else { Get-FileSHA1 $JarPath }
    $modId = $PrecomputedModId
    $info  = $null
    if (-not $modId) { $info = Get-ModNameAndClassRoots $JarPath; $modId = $info.ModId }

    $score = 0; $usnScore = 0; $leafName = [Path]::GetFileName($JarPath)
    $lw = $item.LastWriteTimeUtc; $ct = $item.CreationTimeUtc
    $modifiedDuringSession = $false
    $mdsDetails = [System.Collections.Generic.List[string]]::new()

    if ($MinecraftLaunchUtc -ne $null) {
        if ($ct -gt $MinecraftLaunchUtc) {
            $score += 3
            $modifiedDuringSession = $true
            [void]$reasons.Add("[SESSION] Created AFTER Minecraft launched")
            [void]$mdsDetails.Add("Created: $($ct.ToString('yyyy-MM-dd HH:mm:ss')) UTC")
            [void]$evidence.Add("[SESSION] LaunchUtc: $($MinecraftLaunchUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC")
        }
        if ($lw -gt $MinecraftLaunchUtc) {
            $score += 2
            $modifiedDuringSession = $true
            [void]$reasons.Add("[SESSION] Modified AFTER Minecraft launched")
            [void]$mdsDetails.Add("Modified: $($lw.ToString('yyyy-MM-dd HH:mm:ss')) UTC")
        }
    }

    $usnFound = $false
    if ($UsnEvidence -and $UsnEvidence.ContainsKey($leafName)) {
        $usnFound = $true; $usn = $UsnEvidence[$leafName]; $usnScore = $usn.Score; $score += $usn.Score
        foreach ($flag in $usn.Flags) { [void]$reasons.Add("[USN] $flag") }
        [void]$evidence.Add("[USN] $($usn.EntryCount) journal entries")
        if ($usn.LastActivity -and $usn.LastActivity -ne [datetime]::MinValue) {
            [void]$evidence.Add("[USN] Last activity: $($usn.LastActivity.ToString('yyyy-MM-dd HH:mm:ss'))")
            if ($MinecraftLaunchUtc -ne $null -and $usn.LastActivity.ToUniversalTime() -gt $MinecraftLaunchUtc) {
                $modifiedDuringSession = $true
                [void]$mdsDetails.Add("USN activity: $($usn.LastActivity.ToString('yyyy-MM-dd HH:mm:ss'))")
            }
        }
    }
    if (-not (Test-IsAdmin)) { [void]$evidence.Add("[USN] Admin required for journal access") }
    if (-not $info -and ($score -gt 0 -or -not $modId)) { $info = Get-ModNameAndClassRoots $JarPath; if (-not $modId) { $modId = $info.ModId } }

    return [pscustomobject]@{
        Path=$JarPath; Exists=$true; Suspected=($score -ge 2); Score=$score
        Reasons=@($reasons | Select-Object -Unique); Evidence=@($evidence | Select-Object -Unique)
        SHA1=$sha1; ModId=$modId; Version=$info.Version; Name=$info.Name
        LastWriteUtc=$item.LastWriteTimeUtc; CreationTimeUtc=$item.CreationTimeUtc
        Size=$item.Length; UsnFound=$usnFound; UsnScore=$usnScore
        ModifiedDuringSession=$modifiedDuringSession
        ModifiedDuringSessionDetails=@($mdsDetails)
    }
}

# ======================================================================
# == LIVE CLASSPATH / JVM INJECTION / LOG FALLBACK =====================
# ======================================================================
function Get-LiveClasspathMods {
    $procs = Get-MinecraftJavaProcesses
    $classpathJars = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $procs) {
        $cmd = $p.CommandLine; if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
        $patterns = @('(?:^|\s)-cp\s+("?)([^"]+?)\1(?:\s|$)','(?:^|\s)-classpath\s+("?)([^"]+?)\1(?:\s|$)','(?:^|\s)--classpath\s+("?)([^"]+?)\1(?:\s|$)')
        foreach ($pattern in $patterns) {
            if ($cmd -match $pattern) {
                $cpValue = $Matches[2].Trim('"')
                foreach ($path in ($cpValue -split ';')) {
                    $trimmed = $path.Trim().Trim('"')
                    if ($trimmed -like "*.jar") { try { [void]$classpathJars.Add([Environment]::ExpandEnvironmentVariables($trimmed)) } catch {} }
                }
                break
            }
        }
    }
    return @($classpathJars)
}
function Get-MissingModsLive([string]$ModsPath, [System.IO.FileInfo[]]$CurrentJars) {
    $result = [System.Collections.Generic.List[object]]::new()
    $liveJars = Get-LiveClasspathMods
    if ($liveJars.Count -eq 0) { return @() }
    $currentPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($jar in $CurrentJars) { [void]$currentPaths.Add($jar.FullName) }
    $modsPathResolved = $null
    try { $modsPathResolved = (Resolve-Path $ModsPath).Path } catch { return @() }
    foreach ($liveJar in $liveJars) {
        $normalizedLive = $liveJar
        try { if (Test-Path $liveJar) { $normalizedLive = (Resolve-Path $liveJar).Path } } catch {}
        $prefix = $modsPathResolved; if (-not $prefix.EndsWith('\')) { $prefix += '\' }
        if (-not $normalizedLive.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if (-not $currentPaths.Contains($normalizedLive)) {
            [void]$result.Add([PSCustomObject]@{ JarName=[Path]::GetFileName($liveJar); FullPath=$liveJar; Reason="Referenced in JVM classpath but missing from disk"; Source="live" })
        }
    }
    return @($result)
}
function Get-JvmInjectedMods {
    param([string]$ModsPath = "")
    $procs = Get-MinecraftJavaProcesses
    $injected = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $argPatterns = [ordered]@{
        '(?:^|\s)-Dfabric\.addMods=(?:["'']?)([^"''\s;]+(?:;[^"''\s;]+)*)'        = "-Dfabric.addMods"
        '(?:^|\s)-Dfabric\.addMods\.extra=(?:["'']?)([^"''\s;]+(?:;[^"''\s;]+)*)' = "-Dfabric.addMods.extra"
        '(?:^|\s)-Dloader\.addMods=(?:["'']?)([^"''\s;]+(?:;[^"''\s;]+)*)'        = "-Dloader.addMods (Quilt)"
        '(?:^|\s)-Dloader\.addMods\.extra=(?:["'']?)([^"''\s;]+(?:;[^"''\s;]+)*)' = "-Dloader.addMods.extra (Quilt)"
        '(?:^|\s)-Dfabric\.extraMods=(?:["'']?)([^"''\s;]+(?:;[^"''\s;]+)*)'      = "-Dfabric.extraMods"
        '(?:^|\s)-javaagent:(?:["'']?)([^="''\s]+\.jar)(?:=[^"''\s]*)?'            = "-javaagent"
        '(?:^|\s)-Xbootclasspath/[ap]:(?:["'']?)([^"''\s;]+(?:;[^"''\s;]+)*)'       = "-Xbootclasspath"
        '(?:^|\s)-DlegacyClassPath=(?:["'']?)([^"''\s;]+(?:;[^"''\s;]+)*)'         = "-DlegacyClassPath"
    }
    $modsResolved = ""
    if (-not [string]::IsNullOrWhiteSpace($ModsPath)) { try { $modsResolved = (Resolve-Path $ModsPath -ErrorAction Stop).Path } catch {} }
    foreach ($proc in $procs) {
        $cmd = $proc.CommandLine; if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
        foreach ($pattern in $argPatterns.Keys) {
            $rxMatches = [regex]::Matches($cmd, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($m in $rxMatches) {
                $rawValue = $m.Groups[1].Value.Trim('"').Trim("'").Trim()
                if ([string]::IsNullOrWhiteSpace($rawValue)) { continue }
                $paths = $rawValue -split ';' | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ -ne "" }
                foreach ($jarPath in $paths) {
                    if ($jarPath -notlike "*.jar") { continue }
                    if (-not $seenPaths.Add($jarPath)) { continue }
                    $exists = Test-Path $jarPath -ErrorAction SilentlyContinue
                    $sha1 = if ($exists) { Get-FileSHA1 $jarPath } else { $null }
                    $inFolder = $false
                    if ($modsResolved -and $exists) {
                        try {
                            $res = (Resolve-Path $jarPath -ErrorAction SilentlyContinue).Path
                            $prefix = $modsResolved; if (-not $prefix.EndsWith('\')) { $prefix += '\' }
                            if ($res) { $inFolder = $res.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase) }
                        } catch {}
                    }
                    [void]$injected.Add([PSCustomObject]@{
                        JarPath=$jarPath; JarName=[System.IO.Path]::GetFileName($jarPath); ArgType=$argPatterns[$pattern]
                        Exists=$exists; SHA1=$sha1; ProcessId=$proc.ProcessId; LauncherHint=$proc.LauncherHint; InModsFolder=$inFolder
                    })
                }
            }
        }
    }
    return @($injected)
}
function Find-LogFile([string]$ModsPath) {
    $candidates = [System.Collections.Generic.List[string]]::new()
    $current = $ModsPath
    for ($i=0; $i -lt 5; $i++) {
        $current = Split-Path $current -Parent; if (-not $current) { break }
        $c1 = Join-Path $current "logs\latest.log"; if (Test-Path $c1) { [void]$candidates.Add($c1) }
        $c2 = Join-Path $current ".minecraft\logs\latest.log"; if (Test-Path $c2) { [void]$candidates.Add($c2) }
    }
    $std = Join-Path $env:APPDATA ".minecraft\logs\latest.log"
    if (Test-Path $std) { [void]$candidates.Add($std) }
    if ($candidates.Count -gt 0) { return ($candidates | Sort-Object { (Get-Item $_).LastWriteTime } -Descending | Select-Object -First 1) }
    return $null
}
function Get-ModIdsFromLog([string]$LogPath) {
    $modIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try { $lines = Get-Content -Path $LogPath -Encoding UTF8 -ErrorAction Stop } catch { return @() }
    $inModList = $false
    for ($i=0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match 'Loading\s+\d+\s+mods?:') { $inModList = $true; continue }
        if ($inModList -and $line -match '^\s*-\s+([a-z][a-z0-9_-]*)\s+\d') {
            $modId = $Matches[1].ToLower()
            if ($modId -notin @('java','minecraft','fabricloader','forge','quilt_loader','quilt-loader','mixin','fabric-api','fabric-api-base')) { [void]$modIds.Add($modId) }
        }
        if ($inModList -and $line -match '^\S' -and $line -notmatch 'Loading\s+\d+\s+mods?:' -and $line -notmatch '^\s*-\s+[a-z]') { $inModList = $false }
        if ($line -match 'Loading mod\s+([a-z][a-z0-9_-]*)') { [void]$modIds.Add($Matches[1].ToLower()) }
    }
    return @($modIds)
}
function Get-MissingModsFromLog([string]$ModsPath, [System.IO.FileInfo[]]$CurrentJars) {
    $result = [System.Collections.Generic.List[object]]::new()
    $logFile = Find-LogFile -ModsPath $ModsPath
    if (-not $logFile) { return @() }
    Write-Host "   Log fallback: $logFile" -ForegroundColor DarkGray
    $logModIds = Get-ModIdsFromLog -LogPath $logFile
    if ($logModIds.Count -eq 0) { return @() }
    $currentModIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($jar in $CurrentJars) { $modId = Get-ModId $jar.FullName; if ($modId) { [void]$currentModIds.Add($modId.ToLower()) } }
    foreach ($logModId in $logModIds) {
        if (-not $currentModIds.Contains($logModId)) {
            [void]$result.Add([PSCustomObject]@{ JarName="Unknown (mod ID: $logModId)"; FullPath="N/A"; Reason="Loaded in last session, JAR missing"; Source="log" })
        }
    }
    return @($result)
}

# ======================================================================
# == HTML REPORT BUILDER ===============================================
# ======================================================================
function Get-Badge($text, $color) {
    $cls = @{red="badge-red"; green="badge-green"; yellow="badge-yellow"; orange="badge-orange"; purple="badge-purple"; blue="badge-blue"; cyan="badge-cyan"; gray="badge-gray"}[$color]
    if (-not $cls) { $cls = "badge-blue" }
    return "<span class=""badge $cls"">$(ConvertTo-HtmlText $text)</span>"
}
function Get-ModCardHtml {
    param($Jar, $Replace, $ExtraBadges, $Body)
    $name = ConvertTo-HtmlText $Jar.Name
    $path = ConvertTo-HtmlText $Jar.FullName
    $badges = if ($ExtraBadges) { $ExtraBadges -join "" } else { "" }
    $mdsBadge = ""
    if ($Replace -and $Replace.ModifiedDuringSession) { $mdsBadge = Get-Badge "Modified During Session" "orange" }
    $searchAttr = (ConvertTo-HtmlText ($Jar.Name + ' ' + $Jar.FullName)) -replace '"',''
    $card = @"
<div class="card" data-search="$searchAttr">
  <div class="card-header"><span class="card-title">$name</span><div class="badge-group">$mdsBadge $badges</div></div>
  <div class="card-path">$path</div>
  $Body
</div>
"@
    return $card
}
function Get-DetailsHtml {
    param([hashtable]$Fields, [array]$Reasons, [array]$Evidence)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<details class="details"><summary>Details</summary><div class="detail-grid">')
    foreach ($k in $Fields.Keys) {
        $v = $Fields[$k]; if ($null -eq $v -or $v -eq "") { continue }
        [void]$sb.Append("<div class=""detail-item""><div class=""detail-label"">$(ConvertTo-HtmlText $k)</div><div class=""detail-value"">$(ConvertTo-HtmlText ([string]$v))</div></div>")
    }
    [void]$sb.Append('</div>')
    if ($Reasons -and $Reasons.Count -gt 0) {
        [void]$sb.Append('<div class="sub-label">Reasons</div><ul class="reason-list">')
        foreach ($r in $Reasons) { [void]$sb.Append("<li>$(ConvertTo-HtmlText $r)</li>") }
        [void]$sb.Append('</ul>')
    }
    if ($Evidence -and $Evidence.Count -gt 0) {
        [void]$sb.Append('<div class="sub-label">Evidence</div><ul class="evidence-list">')
        foreach ($e in $Evidence) { [void]$sb.Append("<li>$(ConvertTo-HtmlText $e)</li>") }
        [void]$sb.Append('</ul>')
    }
    [void]$sb.Append('</details>')
    return $sb.ToString()
}
function Get-SectionHtml {
    param([string]$Id, [string]$Title, [string]$Color, [int]$Count, [string]$Content, [string]$EmptyText, [switch]$Open)
    $openAttr = if ($Open) { " open" } else { "" }
    if (-not $Content -or $Count -eq 0) { $Content = "<div class=""empty"">$(ConvertTo-HtmlText $EmptyText)</div>" }
    return @"
<details class="section" id="$Id"$openAttr>
  <summary>
    <span class="section-title">$(ConvertTo-HtmlText $Title)</span>
    $(Get-Badge "$Count" $Color)
  </summary>
  <div class="cards">$Content</div>
</details>
"@
}

function New-HtmlReport {
    param([string]$OutputPath, $Report)

    $stats = @(
        @{n=$Report.TotalScanned; l="Total Scanned"; c="#58a6ff"},
        @{n=$Report.Flagged.Count; l="Flagged Threats"; c="#f85149"},
        @{n=$Report.ModifiedDuringSession.Count; l="Modified During Session"; c="#ff7b45"},
        @{n=$Report.ReplacementSuspects.Count; l="Replacement Suspects"; c="#bc8cff"},
        @{n=$Report.MissingMods.Count; l="Missing Mods"; c="#d29922"},
        @{n=$Report.JvmInjected.Count; l="JVM Injection"; c="#f85149"},
        @{n=$Report.Verified.Count; l="Verified Modrinth"; c="#3fb950"},
        @{n=$Report.UnknownClean.Count; l="Unknown Clean"; c="#58a6ff"}
    )
    $dashSb = [System.Text.StringBuilder]::new()
    foreach ($s in $stats) {
        [void]$dashSb.Append("<div class=""stat"" style=""--accent:$($s.c)""><div class=""stat-number"">$($s.n)</div><div class=""stat-label"">$(ConvertTo-HtmlText $s.l)</div></div>")
    }

    # --- Modified During Session ---
    $mdsSb = [System.Text.StringBuilder]::new()
    foreach ($entry in $Report.ModifiedDuringSession) {
        $rep = $entry.Replace
        $fields = @{}
        if ($rep.ModId)   { $fields["Mod ID"] = $rep.ModId }
        if ($rep.Name)    { $fields["Name"]   = $rep.Name }
        if ($rep.Version) { $fields["Version"] = $rep.Version }
        if ($rep.CreationTimeUtc) { $fields["Created (UTC)"]  = $rep.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') }
        if ($rep.LastWriteUtc)    { $fields["Modified (UTC)"] = $rep.LastWriteUtc.ToString('yyyy-MM-dd HH:mm:ss') }
        if ($rep.Size)            { $fields["Size"] = "{0:N0} bytes" -f $rep.Size }
        if ($rep.SHA1)            { $fields["SHA1"] = $rep.SHA1 }
        $mdsReasons = @($rep.ModifiedDuringSessionDetails)
        foreach ($r in $rep.Reasons) { if ($r -match '^\[USN\]') { $mdsReasons += $r } }
        [void]$mdsSb.Append((Get-ModCardHtml -Jar $entry.Jar -Replace $rep -ExtraBadges @((Get-Badge "After MC Launch" "orange")) -Body (Get-DetailsHtml -Fields $fields -Reasons $mdsReasons -Evidence $rep.Evidence)))
    }

    # --- Flagged Threats ---
    $flagSb = [System.Text.StringBuilder]::new()
    foreach ($e in $Report.Flagged) {
        $scan = $e.Scan; $manifest = $e.Manifest
        $body = [System.Text.StringBuilder]::new()
        if ($e.SHA1) { [void]$body.Append("<div class=""detail-item"" style=""margin-bottom:8px;""><div class=""detail-label"">SHA1</div><div class=""detail-value"">$($e.SHA1)</div></div>") }
        $sources = Get-DownloadSource $e.Jar.FullName
        if ($sources -and $sources[0] -notmatch "No download trace") {
            [void]$body.Append('<ul class="reason-list">')
            foreach ($s in $sources) { [void]$body.Append("<li>$(ConvertTo-HtmlText $s)</li>") }
            [void]$body.Append('</ul>')
        }
        if ($manifest -and $manifest.HasFindings) {
            [void]$body.Append('<ul class="reason-list">')
            foreach ($ae in $manifest.AgentEntries) { [void]$body.Append("<li>Manifest: <b>$(ConvertTo-HtmlText $ae.Key)</b> = $(ConvertTo-HtmlText $ae.Value) - $(ConvertTo-HtmlText $ae.Meaning)</li>") }
            foreach ($f in $manifest.JvmFlags) { [void]$body.Append("<li>JVM flag: $(ConvertTo-HtmlText $f)</li>") }
            [void]$body.Append('</ul>')
        }
        if ($scan.JvmArgStrings.Count -gt 0) {
            [void]$body.Append('<ul class="reason-list">')
            foreach ($j in ($scan.JvmArgStrings | Select-Object -Unique)) { [void]$body.Append("<li>JVM inject: $(ConvertTo-HtmlText $j)</li>") }
            [void]$body.Append('</ul>')
        }
        if ($scan.Obfuscation.Grade -ne "CLEAN") {
            $obf = $scan.Obfuscation
            [void]$body.Append("<ul class=""reason-list""><li>Obfuscation: <b>$($obf.Percent)%</b> ($(ConvertTo-HtmlText $obf.Grade))</li>")
            foreach ($f in $obf.Flags) { [void]$body.Append("<li>$(ConvertTo-HtmlText $f)</li>") }
            if ($obf.KnownTools.Count -gt 0) { [void]$body.Append("<li>Tools: $(ConvertTo-HtmlText ($obf.KnownTools -join ', '))</li>") }
            [void]$body.Append('</ul>')
        }
        if ($scan.NetworkCode.Count -gt 0) {
            [void]$body.Append('<ul class="reason-list">')
            foreach ($h in ($scan.NetworkCode | Select-Object -First 8)) { [void]$body.Append("<li>Net: $(ConvertTo-HtmlText $h.Code) - $(ConvertTo-HtmlText $h.Meaning)</li>") }
            if ($scan.NetworkCode.Count -gt 8) { [void]$body.Append("<li>...and $($scan.NetworkCode.Count - 8) more</li>") }
            [void]$body.Append('</ul>')
        }
        if ($scan.Triggerbot.Count -gt 0) {
            [void]$body.Append('<ul class="reason-list">')
            foreach ($h in ($scan.Triggerbot | Select-Object -First 6)) { [void]$body.Append("<li>Triggerbot: $(ConvertTo-HtmlText $h.Code) - $(ConvertTo-HtmlText $h.Meaning)</li>") }
            [void]$body.Append('</ul>')
        }
        if ($scan.SelfDestruct.Count -gt 0) {
            [void]$body.Append('<ul class="reason-list">')
            foreach ($h in ($scan.SelfDestruct | Select-Object -First 6)) { [void]$body.Append("<li>Self-destruct: $(ConvertTo-HtmlText $h.Code) - $(ConvertTo-HtmlText $h.Meaning)</li>") }
            [void]$body.Append('</ul>')
        }
        if ($scan.SuspiciousURLs.Count -gt 0) {
            [void]$body.Append('<ul class="reason-list">')
            foreach ($h in ($scan.SuspiciousURLs | Select-Object -First 6)) { [void]$body.Append("<li>URL: $(ConvertTo-HtmlText $h.Code)</li>") }
            [void]$body.Append('</ul>')
        }
        $badges = @((Get-Badge "NOT on Modrinth" "purple"))
        [void]$flagSb.Append((Get-ModCardHtml -Jar $e.Jar -Replace $null -ExtraBadges $badges -Body $body.ToString()))
    }

    # --- Replacement Suspects ---
    $repSb = [System.Text.StringBuilder]::new()
    foreach ($r in $Report.ReplacementSuspects) {
        $rep = $r.Replace
        $fields = @{ "Score"=$rep.Score; "Category"=$r.Category }
        if ($rep.ModId)   { $fields["Mod ID"] = $rep.ModId }
        if ($rep.Name)    { $fields["Name"] = $rep.Name }
        if ($rep.CreationTimeUtc) { $fields["Created"]  = $rep.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') + " UTC" }
        if ($rep.LastWriteUtc)    { $fields["Modified"] = $rep.LastWriteUtc.ToString('yyyy-MM-dd HH:mm:ss') + " UTC" }
        if ($rep.SHA1)    { $fields["SHA1"] = $rep.SHA1 }
        $badges = @((Get-Badge $r.Category "purple"))
        [void]$repSb.Append((Get-ModCardHtml -Jar $r.Jar -Replace $rep -ExtraBadges $badges -Body (Get-DetailsHtml -Fields $fields -Reasons $rep.Reasons -Evidence $rep.Evidence)))
    }

    # --- Missing Mods ---
    $missSb = [System.Text.StringBuilder]::new()
    foreach ($m in $Report.MissingMods) {
        $srcColor = switch ($m.Source) { "live" { "red" } "usn" { "cyan" } default { "yellow" } }
        $fields = @{ "Source" = $m.Source; "Reason" = $m.Reason }
        if ($m.FullPath -ne "N/A") { $fields["Path"] = $m.FullPath }
        $junk = [PSCustomObject]@{ Name = $m.JarName; FullName = $(if ($m.FullPath -ne "N/A") { $m.FullPath } else { "N/A" }) }
        [void]$missSb.Append((Get-ModCardHtml -Jar $junk -Replace $null -ExtraBadges @((Get-Badge "MISSING" $srcColor)) -Body (Get-DetailsHtml -Fields $fields -Reasons @() -Evidence @())))
    }

    # --- JVM Injection ---
    $injSb = [System.Text.StringBuilder]::new()
    foreach ($inj in $Report.JvmInjected) {
        $fields = @{
            "Arg Type" = $inj.ArgType
            "Path"     = $inj.JarPath
            "Exists"   = if ($inj.Exists) { "Yes" } else { "No" }
            "Location" = if ($inj.InModsFolder) { "Inside mods folder" } else { "OUTSIDE mods folder" }
            "PID"      = $inj.ProcessId
            "Launcher" = $inj.LauncherHint
            "SHA1"     = $inj.SHA1
        }
        $junk = [PSCustomObject]@{ Name = $inj.JarName; FullName = $inj.JarPath }
        $badges = @((Get-Badge "JVM INJECTION" "red"))
        [void]$injSb.Append((Get-ModCardHtml -Jar $junk -Replace $null -ExtraBadges $badges -Body (Get-DetailsHtml -Fields $fields -Reasons @() -Evidence @())))
    }

    # --- USN Activity Only ---
    $usnSb = [System.Text.StringBuilder]::new()
    foreach ($u in $Report.UsnActivityOnly) {
        $rep = $u.Replace
        $fields = @{ "USN Score" = $rep.UsnScore; "Category" = $u.Category }
        if ($rep.ModId)  { $fields["Mod ID"] = $rep.ModId }
        if ($rep.SHA1)   { $fields["SHA1"] = $rep.SHA1 }
        if ($rep.LastWriteUtc)    { $fields["Modified"] = $rep.LastWriteUtc.ToString('yyyy-MM-dd HH:mm:ss') + " UTC" }
        if ($rep.CreationTimeUtc) { $fields["Created"]  = $rep.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') + " UTC" }
        [void]$usnSb.Append((Get-ModCardHtml -Jar $u.Jar -Replace $rep -ExtraBadges @((Get-Badge "USN Activity" "cyan")) -Body (Get-DetailsHtml -Fields $fields -Reasons $rep.Reasons -Evidence $rep.Evidence)))
    }

    # --- Verified on Modrinth ---
    $verSb = [System.Text.StringBuilder]::new()
    foreach ($v in $Report.Verified) {
        $fields = @{ "Name"=$v.Modrinth.Name; "Author"=$v.Modrinth.Author; "Version"=$v.Modrinth.Version; "URL"=$v.Modrinth.Url; "SHA1"=$v.SHA1 }
        $badges = @((Get-Badge "Verified" "green"))
        $rep = if ($v.PSObject.Properties['Replace']) { $v.Replace } else { $null }
        if ($rep -and $rep.ModifiedDuringSession) { $badges += (Get-Badge "Modified During Session" "orange") }
        [void]$verSb.Append((Get-ModCardHtml -Jar $v.Jar -Replace $rep -ExtraBadges $badges -Body (Get-DetailsHtml -Fields $fields -Reasons @() -Evidence @())))
    }

    # --- Unknown Clean ---
    $ucSb = [System.Text.StringBuilder]::new()
    foreach ($u in $Report.UnknownClean) {
        $rep = if ($u.PSObject.Properties['Replace']) { $u.Replace } else { $null }
        $fields = @{}
        if ($rep) {
            if ($rep.ModId)  { $fields["Mod ID"] = $rep.ModId }
            if ($rep.Name)   { $fields["Name"] = $rep.Name }
            if ($rep.SHA1)   { $fields["SHA1"] = $rep.SHA1 }
            if ($rep.LastWriteUtc)    { $fields["Modified"] = $rep.LastWriteUtc.ToString('yyyy-MM-dd HH:mm:ss') + " UTC" }
            if ($rep.CreationTimeUtc) { $fields["Created"]  = $rep.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') + " UTC" }
            if ($rep.Score -gt 0)     { $fields["Replacement Score"] = $rep.Score }
        }
        $sources = Get-DownloadSource $u.Jar.FullName
        $ev = @()
        if ($sources -and $sources[0] -notmatch "No download trace") { $ev = $sources }
        [void]$ucSb.Append((Get-ModCardHtml -Jar $u.Jar -Replace $rep -ExtraBadges @((Get-Badge "Clean" "blue")) -Body (Get-DetailsHtml -Fields $fields -Reasons @() -Evidence $ev)))
    }

    $mcLine = if ($Report.McRunning) {
        "Minecraft session detected - launch time: $($Report.MinecraftLaunchUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    } else {
        "No active Minecraft session - session-modification checks skipped"
    }
    $adminLine = if ($Report.IsAdmin) { "USN journal: enabled (admin)" } else { "USN journal: disabled (not admin)" }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>nbme-ss - Mod Scan Report - $($Report.ScanDate.ToString('yyyy-MM-dd HH:mm'))</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6;padding:32px 24px;-webkit-font-smoothing:antialiased}
.container{max-width:1200px;margin:0 auto}
header{padding:8px 0 24px;border-bottom:1px solid #21262d;margin-bottom:28px}
h1{font-size:1.75em;font-weight:600;color:#c9d1d9;letter-spacing:-.02em}
h1 span{color:#58a6ff}
.subtitle{color:#7d8590;margin-top:10px;font-size:.86em;line-height:1.7}
.subtitle b{color:#c9d1d9;font-weight:500}
.dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:24px}
.stat{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px 12px;text-align:center;transition:border-color .2s ease}
.stat:hover{border-color:#30363d}
.stat-number{font-size:1.7em;font-weight:600;line-height:1.1;color:var(--accent)}
.stat-label{font-size:.7em;color:#7d8590;text-transform:uppercase;letter-spacing:.06em;margin-top:6px}
.toolbar{display:flex;gap:8px;margin-bottom:18px;align-items:center;flex-wrap:wrap}
.toolbar input{flex:1;min-width:200px;padding:9px 12px;background:#161b22;border:1px solid #21262d;border-radius:6px;color:#c9d1d9;font-size:.9em;outline:none;transition:border-color .15s ease}
.toolbar input:focus{border-color:#58a6ff}
.toolbar button{padding:9px 14px;background:#161b22;border:1px solid #21262d;border-radius:6px;color:#c9d1d9;cursor:pointer;font-size:.85em;transition:background .15s ease,border-color .15s ease}
.toolbar button:hover{background:#21262d;border-color:#30363d}
.section{margin-bottom:10px}
.section>summary{cursor:pointer;padding:12px 16px;background:#161b22;border:1px solid #21262d;border-radius:8px;font-size:.94em;font-weight:500;list-style:none;display:flex;align-items:center;gap:10px;transition:background .15s ease}
.section>summary:hover{background:#1c2128}
.section>summary::-webkit-details-marker{display:none}
.section>summary::before{content:'\203A';font-size:1.1em;color:#7d8590;flex-shrink:0;display:inline-block;transition:transform .2s ease;transform:rotate(0deg)}
.section[open]>summary::before{transform:rotate(90deg)}
.section[open]>summary{border-radius:8px 8px 0 0;border-bottom:none}
.section-title{flex:1}
.cards{background:#0d1117;border:1px solid #21262d;border-top:none;border-radius:0 0 8px 8px;padding:12px}
.empty{color:#7d8590;padding:20px;text-align:center;font-size:.9em}
.card{background:#161b22;border:1px solid #21262d;border-left:3px solid #30363d;border-radius:6px;padding:12px 14px;margin-bottom:8px;transition:border-left-color .2s ease}
.card:last-child{margin-bottom:0}
.card:hover{border-left-color:#58a6ff}
.card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;flex-wrap:wrap;gap:8px}
.card-title{font-size:.97em;font-weight:500;word-break:break-all;flex:1;min-width:0;color:#e6edf3}
.badge-group{display:flex;gap:5px;flex-wrap:wrap}
.card-path{color:#7d8590;font-size:.75em;margin-bottom:6px;word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.67em;font-weight:600;text-transform:uppercase;letter-spacing:.03em;white-space:nowrap}
.badge-red{background:rgba(248,81,73,.12);color:#f85149;border:1px solid rgba(248,81,73,.28)}
.badge-green{background:rgba(63,185,80,.12);color:#3fb950;border:1px solid rgba(63,185,80,.28)}
.badge-yellow{background:rgba(210,153,34,.12);color:#d29922;border:1px solid rgba(210,153,34,.28)}
.badge-orange{background:rgba(255,123,69,.14);color:#ff7b45;border:1px solid rgba(255,123,69,.32)}
.badge-purple{background:rgba(188,140,255,.12);color:#bc8cff;border:1px solid rgba(188,140,255,.28)}
.badge-blue{background:rgba(88,166,255,.12);color:#58a6ff;border:1px solid rgba(88,166,255,.28)}
.badge-cyan{background:rgba(57,197,207,.12);color:#39c5cf;border:1px solid rgba(57,197,207,.28)}
.badge-gray{background:rgba(125,133,144,.12);color:#7d8590;border:1px solid rgba(125,133,144,.28)}
.details{margin-top:6px}
.details summary{cursor:pointer;color:#7d8590;font-size:.8em;padding:4px 0;list-style:none;transition:color .15s ease}
.details summary:hover{color:#c9d1d9}
.details summary::-webkit-details-marker{display:none}
.details summary::before{content:'\203A ';display:inline-block;transition:transform .15s ease}
.details[open] summary::before{transform:rotate(90deg)}
.sub-label{margin-top:12px;font-size:.7em;color:#7d8590;text-transform:uppercase;letter-spacing:.06em}
.detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:6px;margin-top:6px}
.detail-item{background:#0d1117;padding:7px 10px;border-radius:5px;border:1px solid #21262d}
.detail-label{font-size:.67em;color:#7d8590;text-transform:uppercase;letter-spacing:.04em;margin-bottom:2px}
.detail-value{font-size:.83em;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all;color:#e6edf3}
.reason-list,.evidence-list{list-style:none;margin-top:5px}
.reason-list li{padding:5px 9px;margin:2px 0;background:rgba(210,153,34,.06);border-left:2px solid #d29922;border-radius:3px;font-size:.81em}
.evidence-list li{padding:5px 9px;margin:2px 0;background:rgba(57,197,207,.05);border-left:2px solid #39c5cf;border-radius:3px;font-size:.81em;font-family:ui-monospace,monospace}
.footer{margin-top:28px;padding:20px;text-align:center;color:#7d8590;font-size:.8em;border-top:1px solid #21262d}
.footer strong{color:#ff7b45}
.footer .brand{color:#58a6ff;font-weight:600}
</style>
</head>
<body>
<div class="container">
<header>
<h1><span>nbme-ss</span> - Mod Scan Report</h1>
<div class="subtitle">
Scanned <b>$($Report.TotalScanned)</b> mods in <b>$(ConvertTo-HtmlText $Report.ModsPath)</b><br>
Generated <b>$($Report.ScanDate.ToString('yyyy-MM-dd HH:mm:ss'))</b><br>
$mcLine &nbsp;&middot;&nbsp; $adminLine<br>
<span class="brand">nbme-ss</span> &nbsp;&middot;&nbsp; made by claude.ai &amp; deepseek
</div>
</header>

<div class="dashboard">$($dashSb.ToString())</div>

<div class="toolbar">
<input type="search" id="search" placeholder="Filter mods by name, path, ID...">
<button onclick="expandAll()">Expand All</button>
<button onclick="collapseAll()">Collapse All</button>
</div>

$(Get-SectionHtml -Id "mds" -Title "Modified During Minecraft Session" -Color "orange" -Count $Report.ModifiedDuringSession.Count -Content $mdsSb.ToString() -EmptyText "No mods modified after Minecraft launched" -Open)
$(Get-SectionHtml -Id "flag" -Title "Flagged Threats" -Color "red" -Count $Report.Flagged.Count -Content $flagSb.ToString() -EmptyText "No threats detected" -Open)
$(Get-SectionHtml -Id "rep" -Title "Replacement Suspects" -Color "purple" -Count $Report.ReplacementSuspects.Count -Content $repSb.ToString() -EmptyText "No replacement activity detected" -Open)
$(Get-SectionHtml -Id "miss" -Title "Missing Mods" -Color "yellow" -Count $Report.MissingMods.Count -Content $missSb.ToString() -EmptyText "No missing mods detected")
$(Get-SectionHtml -Id "inj" -Title "JVM Argument Injection" -Color "red" -Count $Report.JvmInjected.Count -Content $injSb.ToString() -EmptyText "No JVM injection detected")
$(Get-SectionHtml -Id "usn" -Title "USN Journal Activity" -Color "cyan" -Count $Report.UsnActivityOnly.Count -Content $usnSb.ToString() -EmptyText "No additional USN activity")
$(Get-SectionHtml -Id "ver" -Title "Verified on Modrinth" -Color "green" -Count $Report.Verified.Count -Content $verSb.ToString() -EmptyText "None verified")
$(Get-SectionHtml -Id "uc" -Title "Unknown - Passed Deep Scan" -Color "blue" -Count $Report.UnknownClean.Count -Content $ucSb.ToString() -EmptyText "No unknown-clean mods")

<div class="footer">
<strong>MANUAL VERIFICATION IS ALWAYS RECOMMENDED</strong><br>
<span class="brand">nbme-ss</span> &nbsp;&middot;&nbsp; made by claude.ai &amp; deepseek<br>
mod scanner v2.0 &middot; $($Report.ScanDate.ToString('yyyy-MM-dd HH:mm:ss'))
</div>
</div>
<script>
const searchInput = document.getElementById('search');
searchInput.addEventListener('input', function(e) {
    const q = e.target.value.toLowerCase();
    document.querySelectorAll('.card').forEach(card => {
        const txt = (card.getAttribute('data-search') || '').toLowerCase();
        card.style.display = txt.includes(q) ? '' : 'none';
    });
});
function expandAll() { document.querySelectorAll('details').forEach(d => d.open = true); }
function collapseAll() { document.querySelectorAll('details').forEach(d => d.open = false); }
</script>
</body>
</html>
"@
    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($false))
}

# ======================================================================
# == MAIN ==============================================================
# ======================================================================
Clear-Host
Write-Host ""
Write-Host "   ███╗  ██╗ ██████╗ ███╗   ███╗███████╗    ███████╗███████╗" -ForegroundColor Green
Write-Host "   ████╗ ██║██╔══██╗████╗ ████║██╔════╝    ██╔════╝██╔════╝" -ForegroundColor Green
Write-Host "   ██╔██╗██║██████╔╝██╔████╔██║█████╗      ███████╗███████╗" -ForegroundColor Green
Write-Host "   ██║╚████║██╔══██╗██║╚██╔╝██║██╔══╝      ╚════██║╚════██║" -ForegroundColor Green
Write-Host "   ██║ ╚███║██████╔╝██║ ╚═╝ ██║███████╗    ███████║███████║" -ForegroundColor Green
Write-Host "   ╚═╝  ╚══╝╚═════╝ ╚═╝     ╚═╝╚══════╝    ╚══════╝╚══════╝" -ForegroundColor Green
Write-Host ""
Write-Host "           mod scanner  |  v2.0  |  made by claude.ai & deepseek" -ForegroundColor Green
Write-Host "                       HTML report edition  ·  nbme-ss" -ForegroundColor DarkGreen
Write-Host ""

Write-Host "   Paste your mods folder path and press Enter" -ForegroundColor Cyan
$path = (Read-Host "   Path").Trim().Trim('"')
if (-not (Test-Path $path)) { Write-Host "   [ERROR] Path not found: $path" -ForegroundColor Red; pause; exit }

$jars = Get-ChildItem -Path $path -Filter "*.jar" -File -Recurse -ErrorAction SilentlyContinue
if ($jars.Count -eq 0) { Write-Host "   No .jar files found." -ForegroundColor Yellow; pause; exit }
Write-Host "   Found $($jars.Count) mod(s) to analyze" -ForegroundColor DarkGray

$mcLaunchUtc = Get-MinecraftLaunchTimeUtc
$mcRunning   = $mcLaunchUtc -ne $null
if ($mcRunning) { Write-Host ("   Minecraft launch time: {0}" -f $mcLaunchUtc.ToString("u")) -ForegroundColor Cyan }
else            { Write-Host "   No live Minecraft process detected" -ForegroundColor DarkYellow }
if (-not (Test-IsAdmin)) { Write-Host "   [Note] Not running as admin - USN checks disabled" -ForegroundColor DarkYellow }
Write-Host ""

# --- Live JVM injection ---
Write-Host "   Checking live JVM for argument-injected mods..." -ForegroundColor Cyan
$jvmInjected = Get-JvmInjectedMods -ModsPath $path
if ($jvmInjected.Count -gt 0) { Write-Host "   [WARNING] $($jvmInjected.Count) injected JAR(s)!" -ForegroundColor Red }
else { Write-Host "   No JVM argument injection detected" -ForegroundColor DarkGray }
Write-Host ""

$currentJarNameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($jar in $jars) { [void]$currentJarNameSet.Add($jar.Name) }

# --- USN journal ---
$Script:UsnEvidence = $null
if (Test-IsAdmin) {
    Write-Host "   Reading USN journal..." -ForegroundColor Cyan
    $Script:UsnEvidence = Get-UsnReplacementEvidence -ModsPath $path -MinecraftLaunchUtc $mcLaunchUtc -CurrentJarNames $currentJarNameSet
    Write-Host "   USN: $($Script:UsnEvidence.Count) file(s) with activity" -ForegroundColor DarkGray
} else {
    Write-Host "   [Note] Admin required for USN journal" -ForegroundColor DarkYellow
}
Write-Host ""

# --- Pass 0: metadata ---
Write-Host "   Pass 0 - metadata..." -ForegroundColor Cyan
$toProcess = [System.Collections.Generic.List[object]]::new()
$spinner = @("|","/","-","\"); $idx = 0
foreach ($jar in $jars) {
    Write-Host "`r   $($spinner[$idx++ % 4])  Reading: $($jar.Name)$((' ' * 40))" -ForegroundColor DarkGray -NoNewline
    $modId = Get-ModId $jar.FullName
    [void]$toProcess.Add([PSCustomObject]@{ Jar=$jar; ModId=$modId })
}
Write-Host "`r$(' ' * 90)`r   $($toProcess.Count) mods ready for further checks$((' ' * 20))" -ForegroundColor Green

# --- Missing mods ---
$missingMods = [System.Collections.Generic.List[object]]::new()
$seenKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$liveRan = $false; $logRan = $false
if ($mcRunning) {
    Write-Host "   Live check: scanning JVM classpath..." -ForegroundColor Cyan
    $liveMissing = Get-MissingModsLive -ModsPath $path -CurrentJars $jars
    foreach ($m in $liveMissing) { if ($seenKeys.Add($m.JarName.ToLower())) { [void]$missingMods.Add($m) } }
    $liveRan = $true
}
$logMissing = Get-MissingModsFromLog -ModsPath $path -CurrentJars $jars
$logFile    = Find-LogFile -ModsPath $path
$logRan     = $logFile -ne $null
foreach ($m in $logMissing) {
    $key = if ($m.JarName -match 'mod ID: ([^)]+)') { $Matches[1].ToLower() } else { $m.JarName.ToLower() }
    if ($seenKeys.Add($key)) { [void]$missingMods.Add($m) }
}
if ($Script:UsnEvidence) {
    $usnMissing = Get-UsnMissingMods -ModsPath $path -UsnEvidence $Script:UsnEvidence -CurrentJars $jars
    foreach ($m in $usnMissing) { if ($seenKeys.Add($m.JarName.ToLower())) { [void]$missingMods.Add($m) } }
}
Write-Host ""

# --- Pass 1: Parallel Modrinth ---
Write-Host "   Pass 1 - Verifying against Modrinth (parallel)..." -ForegroundColor Cyan
$hashedItems = [System.Collections.Generic.List[object]]::new()
$idx = 0
foreach ($entry in $toProcess) {
    Write-Host "`r   $($spinner[$idx++ % 4])  Hashing: $($entry.Jar.Name)$((' ' * 40))" -ForegroundColor DarkGray -NoNewline
    $sha1 = Get-FileSHA1 $entry.Jar.FullName
    $hashedItems.Add([PSCustomObject]@{ Jar=$entry.Jar; ModId=$entry.ModId; SHA1=$sha1 })
}
Write-Host "`r$(' ' * 90)`r   Hashing complete. Querying Modrinth...$((' ' * 20))" -ForegroundColor DarkGray
$modrinthResults = Invoke-ModrinthBatch -Items $hashedItems
$verified = [System.Collections.Generic.List[object]]::new()
$unknown  = [System.Collections.Generic.List[object]]::new()
foreach ($r in $modrinthResults) {
    if ($r.Modrinth.Found) { [void]$verified.Add([PSCustomObject]@{ Jar=$r.Jar; ModId=$r.ModId; Modrinth=$r.Modrinth; SHA1=$r.SHA1 }) }
    else { [void]$unknown.Add([PSCustomObject]@{ Jar=$r.Jar; ModId=$r.ModId; SHA1=$r.SHA1; Scan=$null; Manifest=$null; Replace=$null }) }
}
Write-Host "   $($verified.Count) verified on Modrinth, $($unknown.Count) unrecognised" -ForegroundColor Green
Write-Host ""

# --- Pass 2: Replacement evidence ---
Write-Host "   Pass 2 - Replacement evidence scan (ALL mods)..." -ForegroundColor Cyan
$replacementSuspects = [System.Collections.Generic.List[object]]::new()
$usnActivityOnly     = [System.Collections.Generic.List[object]]::new()
$idx = 0
$allEntriesForAudit = @()
$allEntriesForAudit += $verified | ForEach-Object { [PSCustomObject]@{ Entry=$_; Category="Verified on Modrinth" } }
$allEntriesForAudit += $unknown  | ForEach-Object { [PSCustomObject]@{ Entry=$_; Category="Unknown" } }

foreach ($w in $allEntriesForAudit) {
    $entry = $w.Entry; $jar = $entry.Jar
    Write-Host "`r   $($spinner[$idx++ % 4])  Auditing: $($jar.Name)$((' ' * 34))" -ForegroundColor DarkGray -NoNewline
    $replace = Get-ModReplacementAudit -JarPath $jar.FullName -MinecraftLaunchUtc $mcLaunchUtc -UsnEvidence $Script:UsnEvidence -JarInfo $jar -PrecomputedSha1 $entry.SHA1 -PrecomputedModId $entry.ModId
    $entry | Add-Member -NotePropertyName Replace -NotePropertyValue $replace -Force
    if ($replace.Suspected)      { [void]$replacementSuspects.Add([PSCustomObject]@{ Jar=$jar; Replace=$replace; SHA1=$entry.SHA1; Category=$w.Category }) }
    elseif ($replace.UsnFound)   { [void]$usnActivityOnly.Add([PSCustomObject]@{ Jar=$jar; Replace=$replace; SHA1=$entry.SHA1; Category=$w.Category }) }
}
Write-Host "`r$(' ' * 90)`r   $($replacementSuspects.Count) suspect(s), $($usnActivityOnly.Count) with USN activity$((' ' * 20))" -ForegroundColor Green
Write-Host ""

# --- Pass 3: Deep scan ---
Write-Host "   Pass 3 - Deep scan (manifest, obfuscation, cheats)..." -ForegroundColor Cyan
$flagged      = [System.Collections.Generic.List[object]]::new()
$unknownClean = [System.Collections.Generic.List[object]]::new()
$idx = 0
foreach ($entry in $unknown) {
    $jar = $entry.Jar
    Write-Host "`r   $($spinner[$idx++ % 4])  Scanning: $($jar.Name)$((' ' * 40))" -ForegroundColor DarkGray -NoNewline
    $manifest = Invoke-ManifestScan $jar.FullName
    $scan     = Invoke-JarScan      $jar.FullName
    $entry.Manifest = $manifest; $entry.Scan = $scan
    $dirty = ($scan.Triggerbot.Count -gt 0) -or ($scan.SelfDestruct.Count -gt 0) -or
             ($scan.SuspiciousURLs.Count -gt 0) -or ($scan.NetworkCode.Count -gt 0) -or
             ($scan.JvmArgStrings.Count -gt 0) -or ($manifest.HasFindings) -or
             ($scan.Obfuscation.Grade -ne "CLEAN")
    if ($dirty) { [void]$flagged.Add([PSCustomObject]@{ Jar=$jar; Scan=$scan; Manifest=$manifest; SHA1=$entry.SHA1 }) }
    else        { [void]$unknownClean.Add($entry) }
}
Write-Host "`r$(' ' * 90)`r   Deep scan complete. $($flagged.Count) flagged.$((' ' * 30))" -ForegroundColor Green
Write-Host ""

# --- Collect Modified-During-Session ---
$modifiedDuringSession = [System.Collections.Generic.List[object]]::new()
foreach ($e in ($verified + $unknown)) {
    $rep = if ($e.PSObject.Properties['Replace']) { $e.Replace } else { $null }
    if ($rep -and $rep.ModifiedDuringSession) { [void]$modifiedDuringSession.Add($e) }
}

# --- Build report object ---
$Report = [PSCustomObject]@{
    ScanDate             = (Get-Date)
    ModsPath             = $path
    MinecraftLaunchUtc   = $mcLaunchUtc
    McRunning            = $mcRunning
    IsAdmin              = (Test-IsAdmin)
    TotalScanned         = $jars.Count
    Verified             = $verified
    UnknownClean         = $unknownClean
    Flagged              = $flagged
    MissingMods          = $missingMods
    JvmInjected          = $jvmInjected
    ReplacementSuspects  = $replacementSuspects
    UsnActivityOnly      = $usnActivityOnly
    ModifiedDuringSession= $modifiedDuringSession
}

# --- Output path ---
$downloads = Join-Path ([Environment]::GetFolderPath("UserProfile")) "Downloads"
if (-not (Test-Path $downloads)) { New-Item -ItemType Directory -Path $downloads -Force | Out-Null }
$stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
$outFile = Join-Path $downloads "mod-scan-$stamp.html"

Write-Host "   Generating HTML report..." -ForegroundColor Cyan
New-HtmlReport -OutputPath $outFile -Report $Report

Write-Host ""
Write-Host "   ==============================================================" -ForegroundColor Green
Write-Host "    SCAN COMPLETE" -ForegroundColor Green
Write-Host "   ==============================================================" -ForegroundColor Green
Write-Host "    Report saved to:" -ForegroundColor Green
Write-Host "    $outFile" -ForegroundColor White
Write-Host "   --------------------------------------------------------------" -ForegroundColor Green
Write-Host "    nbme-ss  |  made by claude.ai & deepseek" -ForegroundColor Green
Write-Host "   ==============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "   Summary:" -ForegroundColor Cyan
Write-Host "     Total scanned          : $($jars.Count)" -ForegroundColor White
Write-Host "     Modified during session: $($modifiedDuringSession.Count)" -ForegroundColor $(if ($modifiedDuringSession.Count -gt 0) { "DarkYellow" } else { "DarkGray" })
Write-Host "     Flagged threats        : $($flagged.Count)" -ForegroundColor $(if ($flagged.Count -gt 0) { "Red" } else { "DarkGray" })
Write-Host "     Replacement suspects   : $($replacementSuspects.Count)" -ForegroundColor $(if ($replacementSuspects.Count -gt 0) { "Magenta" } else { "DarkGray" })
Write-Host "     Missing mods           : $($missingMods.Count)" -ForegroundColor $(if ($missingMods.Count -gt 0) { "DarkYellow" } else { "DarkGray" })
Write-Host "     JVM injection          : $($jvmInjected.Count)" -ForegroundColor $(if ($jvmInjected.Count -gt 0) { "Red" } else { "DarkGray" })
Write-Host "     Verified Modrinth      : $($verified.Count)" -ForegroundColor Green
Write-Host ""

try { Start-Process $outFile } catch { Write-Host "   Open manually: $outFile" -ForegroundColor Yellow }
pause
