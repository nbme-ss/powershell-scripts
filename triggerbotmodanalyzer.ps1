#Requires -Version 5.1
using namespace System.IO
using namespace System.IO.Compression

Add-Type -AssemblyName "System.IO.Compression"
Add-Type -AssemblyName "System.IO.Compression.FileSystem"

# ── Caches ──────────────────────────────────────────────────────────
$Script:CachedMcProcesses = $null
$Script:AdminChecked      = $false
$Script:IsAdmin           = $false

# ── Banner ──────────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "   ███╗  ██╗ ██████╗ ███╗   ███╗███████╗    ███████╗███████╗" -ForegroundColor Green
Write-Host "   ████╗ ██║██╔══██╗████╗ ████║██╔════╝    ██╔════╝██╔════╝" -ForegroundColor Green
Write-Host "   ██╔██╗██║██████╔╝██╔████╔██║█████╗      ███████╗███████╗" -ForegroundColor Green
Write-Host "   ██║╚████║██╔══██╗██║╚██╔╝██║██╔══╝      ╚════██║╚════██║" -ForegroundColor Green
Write-Host "   ██║ ╚███║██████╔╝██║ ╚═╝ ██║███████╗    ███████║███████║" -ForegroundColor Green
Write-Host "   ╚═╝  ╚══╝╚═════╝ ╚═╝     ╚═╝╚══════╝    ╚══════╝╚══════╝" -ForegroundColor Green
Write-Host ""
Write-Host "           mod scanner  |  v1.2  |  made by claude.ai" -ForegroundColor Green
Write-Host ""

# ── Feather Whitelist ───────────────────────────────────────────────
$FeatherModrinthSlugs = @(
    "feathermc","featherapp","featherclient",
    "feather","feather-client","feather-mc"
)

$FeatherStaticFallback = @(
    "feather","featherclient","feather-fabric","featherfabric",
    "feather-api","featherapi","feather-companion"
)

$Script:FeatherIds = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

function Initialize-FeatherWhitelist {
    foreach ($id in $FeatherStaticFallback) { [void]$Script:FeatherIds.Add($id) }

    $fetched = $false
    foreach ($slug in $FeatherModrinthSlugs) {
        if ($fetched) { break }
        foreach ($ep in @("organization","user","team")) {
            try {
                $uri      = "https://api.modrinth.com/v2/$ep/$slug/projects"
                $projects = Invoke-RestMethod $uri -Method Get -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
                if ($projects -and $projects.Count -gt 0) {
                    foreach ($p in $projects) {
                        if ($p.slug) { [void]$Script:FeatherIds.Add($p.slug) }
                        if ($p.id)   { [void]$Script:FeatherIds.Add($p.id)   }
                    }
                    Write-Host ("   [Feather] Fetched {0} official mod(s) via {1} '{2}'" -f $projects.Count,$ep,$slug) -ForegroundColor DarkGray
                    $fetched = $true; break
                }
            } catch {}
        }
    }

    if (-not $fetched) {
        Write-Host ("   [Feather] Using static fallback ({0} IDs)" -f $Script:FeatherIds.Count) -ForegroundColor DarkYellow
    }
}

function Test-FeatherOfficial([string]$ModId) {
    return (-not [string]::IsNullOrWhiteSpace($ModId)) -and $Script:FeatherIds.Contains($ModId)
}

# ── Indicators ────────────────────────────────────────────────────
$TriggerIndicators = @{
    "field_1692"    = "Crosshair target / aimed entity"
    "method_2918"   = "Attack entity"
    "method_6104"   = "Swing hand"
    "class_1829"    = "SwordItem"
    "class_1743"    = "AxeItem"
    "method_7261"   = "Attack cooldown"
}

$SelfDestructIndicators = @{
    "getProtectionDomain" = "Checks JAR origin / sandbox permissions"
    "getCodeSource"       = "Locates its own JAR file path"
    "setLastModified"     = "Modifies file timestamps"
    "deleteOnExit"        = "Schedules JAR deletion on exit"
    "ProcessBuilder"      = "Launches external processes"
}

$SelfReplaceCombo = @{
    "getCodeSource"    = "Locates its own JAR"
    "FileOutputStream" = "Writes to disk (self-overwrite)"
    "openStream"       = "Downloads remote payload"
}

$NetworkIndicators = [ordered]@{
    "java/net/Socket"                 = "Raw TCP socket"
    "java/net/ServerSocket"           = "Opens local server socket"
    "java/net/DatagramSocket"         = "UDP socket (beacon/DNS)"
    "java/net/HttpURLConnection"      = "HTTP connection"
    "java/net/URLConnection"          = "Generic URL connection"
    "javax/net/ssl/SSLSocket"         = "Encrypted SSL socket"
    "java/net/InetAddress"            = "DNS hostname resolution"
    "java/nio/channels/SocketChannel" = "NIO socket channel"
}

$SuspiciousClassFragments = @(
    "mixin","handler","keyboard","input","event",
    "hook","inject","listener","callback"
)

$ManifestAgentKeys = [ordered]@{
    "Premain-Class"                = "Java agent entry point"
    "Agent-Class"                  = "Attach-API agent"
    "Boot-Class-Path"              = "Injects JAR into bootstrap classpath"
    "Can-Redefine-Classes"         = "Can replace loaded class bytecode"
    "Can-Retransform-Classes"      = "Can retransform any loaded class"
    "Can-Set-Native-Method-Prefix" = "Can hook native JVM methods"
}

# ── Merged Obfuscator Signatures ──────────────────────────────────
$ObfuscatorSignatures = [ordered]@{
    "allatori"               = "Allatori"
    "ZKM"                    = "Zelix KlassMaster"
    "me/lpk/"                = "SkidFuscator (LPK)"
    "zenix/skid"             = "Zenix SkidFuscator"
    "radon/"                 = "Radon"
    "bozar"                  = "Bozar"
    "branchlock"             = "Branchlock"
    "com/preemptive"         = "DashO"
    "superblaubeere27"       = "Superblaubeere27"
    "stringer"               = "Stringer"
    "javaguard"              = "JavaGuard"
    "de/xbrowniecodez"       = "Branchlock/XBrownie"
    "com/yworks/yguard"      = "yGuard"
    "proguard"               = "ProGuard"
    "dev/skidfuscator"       = "Skidfuscator"
    "skidfuscator.dev"       = "Skidfuscator"
    "Paramorphism"           = "Paramorphism"
    "paramorphism-"          = "Paramorphism"
    "ItzSomebody/Radon"      = "Radon"
    "sim0n/Caesium"          = "Caesium"
    "vimasig/Bozar"          = "Bozar"
    "branchlock.dev"         = "Branchlock"
    "com/binscure"           = "Binscure"
    "superblaubeere"         = "SuperBlaubeere"
    "QProtect"               = "QProtect"
    "mdma.dev/qprotect"      = "QProtect"
    "ZKMFLOW"                = "Zelix KlassMaster"
    "ZelixKlassMaster"       = "Zelix KlassMaster"
    "com/zelix"              = "Zelix KlassMaster"
    "StringerJavaObfuscator" = "Stringer"
    "com/licel/stringer"     = "Stringer"
    "JNIC"                   = "JNIC"
    "jnic.obf"               = "JNIC"
    "jnic-obfuscator"        = "JNIC"
    "ScutiObf"               = "Scuti"
    "scuti.obf"              = "Scuti"
    "SmokeObf"               = "Smoke"
    "smoke.obf"              = "Smoke"
}

$LegitShortNames = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@("GUI","API","ID","IO","OS","UI","VM","DB","AI","MQ","FX","TK",
                "OK","URL","TCP","UDP","DNS","TLS","SSL","EOF","NIO","RPC",
                "CSV","XML","CLI","CDN","CRC","JWT","AES","RSA","MD5","SHA",
                "PNG","GIF","ZIP","GZip"),
    [System.StringComparer]::OrdinalIgnoreCase
)

# ── Helpers ───────────────────────────────────────────────────────
function Get-ClassStrings([byte[]]$Bytes) {
    $text = [System.Text.Encoding]::GetEncoding('iso-8859-1').GetString($Bytes)
    return [regex]::Matches($text, '[\x20-\x7e]{4,}') | ForEach-Object { $_.Value }
}

function Get-FileSHA1([string]$Path) {
    try { return (Get-FileHash -Path $Path -Algorithm SHA1 -ErrorAction Stop).Hash }
    catch { return $null }
}

function Get-ModId([string]$JarPath) {
    $stream = $null; $archive = $null
    try {
        $stream  = [File]::OpenRead($JarPath)
        $archive = New-Object ZipArchive($stream, [ZipArchiveMode]::Read, $false)

        foreach ($name in @("fabric.mod.json","quilt.mod.json")) {
            $entry = $archive.GetEntry($name)
            if ($entry) {
                $r = New-Object StreamReader($entry.Open())
                $json = $r.ReadToEnd(); $r.Dispose()
                if ($json -match '"id"\s*:\s*"([^"]+)"') { return $Matches[1].ToLower() }
            }
        }

        $entry = $archive.GetEntry("META-INF/mods.toml")
        if ($entry) {
            $r = New-Object StreamReader($entry.Open())
            $toml = $r.ReadToEnd(); $r.Dispose()
            if ($toml -match 'modId\s*=\s*"([^"]+)"') { return $Matches[1].ToLower() }
        }
    } catch {}
    finally {
        if ($archive) { $archive.Dispose() }
        if ($stream)  { $stream.Close() }
    }
    return $null
}

function Query-Modrinth([string]$Hash) {
    try {
        $v = Invoke-RestMethod "https://api.modrinth.com/v2/version_file/$Hash" -Method Get -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        if ($v.project_id) {
            $p = Invoke-RestMethod "https://api.modrinth.com/v2/project/$($v.project_id)" -Method Get -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
            return @{ Found=$true; Name=$p.title; Slug=$p.slug; Author=$p.author; Url="https://modrinth.com/mod/$($p.slug)"; Version=$v.name }
        }
    } catch {}
    return @{ Found=$false }
}

function Get-DownloadSource([string]$FilePath) {
    $evidence = [System.Collections.Generic.List[string]]::new()
    $fileItem = Get-Item $FilePath -ErrorAction SilentlyContinue
    $rawName  = [Path]::GetFileName($FilePath).ToLower()

    try {
        $ads = Get-Content -Path $FilePath -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($ads) {
            $zoneId=""; $hostUrl=""; $referrerUrl=""
            foreach ($line in $ads) {
                if      ($line -match "^ZoneId=(\d)")      { $zoneId      = $Matches[1] }
                elseif  ($line -match "^HostUrl=(.+)")     { $hostUrl     = $Matches[1].Trim() }
                elseif  ($line -match "^ReferrerUrl=(.+)") { $referrerUrl = $Matches[1].Trim() }
            }
            if ($hostUrl) {
                $src = $hostUrl
                if      ($hostUrl -match "modrinth\.com")           { $src = "Modrinth" }
                elseif  ($hostUrl -match "curseforge\.com")         { $src = "CurseForge" }
                elseif  ($hostUrl -match "github\.com")             { $src = "GitHub" }
                elseif  ($hostUrl -match "discordapp|discord\.com") { $src = "Discord CDN" }
                elseif  ($hostUrl -match "mediafire\.com")          { $src = "MediaFire" }
                elseif  ($hostUrl -match "mega\.nz")                { $src = "MEGA" }
                elseif  ($hostUrl -match "dropbox\.com")            { $src = "Dropbox" }
                elseif  ($hostUrl -match "drive\.google\.com")      { $src = "Google Drive" }
                elseif  ($hostUrl -match "https?://(?:www\.)?([^/]+)") { $src = $Matches[1] }
                $evidence.Add("Source : $src")
                $evidence.Add("URL    : $hostUrl")
            }
            if ($referrerUrl) { $evidence.Add("Referer: $referrerUrl") }
            if ($zoneId -eq "3" -and -not $hostUrl) { $evidence.Add("Downloaded from Internet (Zone 3)") }
        }
    } catch {}

    if ($rawName -match "^download\d*(\.\w+)?$")   { $evidence.Add("[Name] Generic download filename") }
    if ($rawName -match "discord|discordapp")       { $evidence.Add("[Name] Filename references Discord") }
    if ($rawName -match "^[a-f0-9]{8,}(\.\w+)?$")  { $evidence.Add("[Name] Hash-style filename") }

    try {
        $shell = New-Object -ComObject Shell.Application
        $dir   = $shell.Namespace($fileItem.DirectoryName)
        $item  = $dir.ParseName($fileItem.Name)
        for ($i=0; $i -lt 400; $i++) {
            $val = $dir.GetDetailsOf($item,$i)
            if ([string]::IsNullOrWhiteSpace($val)) { continue }
            if ($val -match "https?://\S{10,}") { $evidence.Add("[Shell] Origin URL in property #$i"); break }
        }
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    } catch {}

    if ($evidence.Count -eq 0) { return @("No download trace found") }
    return $evidence
}

# ── Manifest Scan ───────────────────────────────────────────────────
function Invoke-ManifestScan([string]$JarPath) {
    $result = [PSCustomObject]@{
        AgentEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
        JvmFlags     = [System.Collections.Generic.List[string]]::new()
        HasFindings  = $false
    }

    $stream = $null; $archive = $null
    try {
        $stream  = [File]::OpenRead($JarPath)
        $archive = New-Object ZipArchive($stream, [ZipArchiveMode]::Read, $false)
        $mfEntry = $archive.GetEntry("META-INF/MANIFEST.MF")

        if ($mfEntry) {
            $r  = New-Object StreamReader($mfEntry.Open())
            $mf = $r.ReadToEnd(); $r.Dispose()

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
    } catch {}
    finally {
        if ($archive) { $archive.Dispose() }
        if ($stream)  { $stream.Close() }
    }

    $result.HasFindings = ($result.AgentEntries.Count -gt 0) -or ($result.JvmFlags.Count -gt 0)
    return $result
}

# ── JAR Deep Scan ─────────────────────────────────────────────────
function Invoke-JarScan([string]$JarPath) {
    $result = [PSCustomObject]@{
        Triggerbot     = [System.Collections.Generic.List[PSCustomObject]]::new()
        SelfDestruct   = [System.Collections.Generic.List[PSCustomObject]]::new()
        SuspiciousURLs = [System.Collections.Generic.List[PSCustomObject]]::new()
        NetworkCode    = [System.Collections.Generic.List[PSCustomObject]]::new()
        JvmArgStrings  = [System.Collections.Generic.List[string]]::new()
        Obfuscation    = [PSCustomObject]@{
            Grade             = "CLEAN"
            Percent           = 0
            KnownTools        = [System.Collections.Generic.List[string]]::new()
            Flags             = [System.Collections.Generic.List[string]]::new()
            TotalClasses      = 0
            NumericCount      = 0
            UnicodeCount      = 0
            FullwidthCount    = 0
            JapaneseCount     = 0
            SingleLetterCount = 0
            TwoLetterCount    = 0
            GibberishCount    = 0
            NoVowelCount      = 0
            ConfusionCount    = 0
            SingleCharPkg     = 0
            EntropyNote       = ""
            ShortClasses      = 0
        }
    }

    $stream = $null; $archive = $null
    try {
        $stream  = [File]::OpenRead($JarPath)
        $archive = New-Object ZipArchive($stream, [ZipArchiveMode]::Read, $false)

        $contentSample = [System.Text.StringBuilder]::new()
        $sampleSize    = 0

        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -notlike "*.class") { continue }

            $es = $entry.Open()
            $ms = New-Object MemoryStream
            $es.CopyTo($ms)
            $bytes = $ms.ToArray()
            $es.Dispose(); $ms.Dispose()

            $strings    = Get-ClassStrings $bytes
            $entryShort = $entry.FullName
            $entryLower = $entryShort.ToLower()

            $obf = $result.Obfuscation
            $obf.TotalClasses++

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
                $hasCluster = $className -match "[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]{3,}"
                if ($hasCluster -and ($vowels / $className.Length) -lt 0.3) { $obf.GibberishCount++ }
            }

            $segs = ($entryShort -replace "\.class$", "") -split "[/\\]"
            foreach ($seg in $segs[0..($segs.Count - 2)]) {
                if ($seg.Length -eq 1) { $obf.SingleCharPkg++ }
            }

            $simpleName = $segs[-1]
            $baseName   = $simpleName -replace '\$.*$',''
            if ($baseName.Length -le 2 -and $baseName.Length -ge 1 -and
                $baseName -match "^[a-zA-Z]+$" -and
                -not $LegitShortNames.Contains($baseName)) {
                $obf.ShortClasses++
            }

            $combinedCtx = ($entryLower + " " + ($strings -join " ")).ToLower()
            foreach ($sig in $ObfuscatorSignatures.Keys) {
                if ($combinedCtx -match [regex]::Escape($sig.ToLower())) {
                    $tool = $ObfuscatorSignatures[$sig]
                    if (-not $obf.KnownTools.Contains($tool)) {
                        [void]$obf.KnownTools.Add($tool)
                    }
                }
            }

            if ($sampleSize -lt 150000 -and $entry.Length -lt 100000 -and $entry.Length -gt 100) {
                [void]$contentSample.Append([System.Text.Encoding]::ASCII.GetString($bytes))
                $sampleSize += $bytes.Length
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

            $comboScore = 0
            $comboHit   = [System.Collections.Generic.List[string]]::new()
            foreach ($token in $SelfReplaceCombo.Keys) {
                if ($strings -match [regex]::Escape($token)) {
                    $comboScore++
                    [void]$comboHit.Add("$token ($($SelfReplaceCombo[$token]))")
                }
            }
            if ($comboScore -ge 2) {
                [void]$result.SelfDestruct.Add([PSCustomObject]@{
                    Code    = "[COMBO] Self-replace"
                    Meaning = "$comboScore/3 matched: $($comboHit -join ' | ')"
                    File    = $entryShort
                    IsCombo = $true
                })
            }

            if ($isSuspicious) {
                foreach ($s in $strings) {
                    if ($s -match "^https?://") {
                        [void]$result.SuspiciousURLs.Add([PSCustomObject]@{ Code=$s.Substring(0,[Math]::Min($s.Length,140)); File=$entryShort })
                    }
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

            $numPct  = & $pct $obf.NumericCount
            $uniPct  = & $pct $obf.UnicodeCount
            $fwPct   = & $pct $obf.FullwidthCount
            $jpPct   = & $pct $obf.JapaneseCount
            $s1Pct   = & $pct $obf.SingleLetterCount
            $s2Pct   = & $pct $obf.TwoLetterCount
            $gibPct  = & $pct $obf.GibberishCount
            $novPct  = & $pct $obf.NoVowelCount
            $confPct = & $pct $obf.ConfusionCount

            if ($numPct  -ge 20) { $obf.Flags.Add("Numeric class names — $numPct% have numeric-only names ($($obf.NumericCount) classes)") }
            if ($uniPct  -ge 10) { $obf.Flags.Add("Unicode class names — $uniPct% use non-ASCII characters ($($obf.UnicodeCount) classes)") }
            if ($fwPct   -gt  0) { $obf.Flags.Add("Fullwidth Unicode class names — $fwPct% use fullwidth chars ($($obf.FullwidthCount) classes)") }
            if ($jpPct   -gt  0) { $obf.Flags.Add("Japanese obfuscation — $jpPct% use hiragana/katakana ($($obf.JapaneseCount) classes)") }
            if ($s1Pct   -ge 15) { $obf.Flags.Add("Single-letter class names — $s1Pct% ($($obf.SingleLetterCount) classes)") }
            if ($s2Pct   -ge 20) { $obf.Flags.Add("Two-letter class names — $s2Pct% ($($obf.TwoLetterCount) classes)") }
            if ($gibPct  -ge  5) { $obf.Flags.Add("Gibberish class names — $gibPct% no vowels + consonant clusters ($($obf.GibberishCount) classes)") }
            if ($novPct  -ge  8) { $obf.Flags.Add("No-vowel class names — $novPct% ($($obf.NoVowelCount) classes)") }
            if ($confPct -ge  3) { $obf.Flags.Add("Confusion-char names (Il1O0/_) — $confPct% ($($obf.ConfusionCount) classes)") }
            if ($obf.SingleCharPkg -ge 6) { $obf.Flags.Add("Single-char package paths — $($obf.SingleCharPkg) segments like a/b/c") }

            $fwStringMatches = [regex]::Matches($contentSample.ToString(), "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]{2,}")
            if ($fwStringMatches.Count -gt 0) {
                $examples = ($fwStringMatches | Select-Object -First 3 | ForEach-Object { $_.Value }) -join ", "
                $obf.Flags.Add("Fullwidth strings in bytecode — $($fwStringMatches.Count) occurrences (e.g. $examples)")
            }

            $sampleStr = $contentSample.ToString()
            foreach ($sig in $ObfuscatorSignatures.Keys) {
                if ($sampleStr.Contains($sig)) {
                    $tool = $ObfuscatorSignatures[$sig]
                    if (-not $obf.KnownTools.Contains($tool)) {
                        [void]$obf.KnownTools.Add($tool)
                    }
                }
            }
        }

        $ratio = if ($obf.TotalClasses -gt 0) { $obf.ShortClasses / $obf.TotalClasses } else { 0 }

        if ($obf.TotalClasses -gt 5 -and $ratio -gt 0.35) {
            $obf.EntropyNote = "$($obf.ShortClasses)/$($obf.TotalClasses) short names ({0:P0})" -f $ratio
        }

        $basePct   = [math]::Round($ratio * 60)
        $toolPct   = [math]::Min(35, $obf.KnownTools.Count * 17)
        $bonus     = if ($ratio -gt 0.70) { 10 } elseif ($ratio -gt 0.50) { 5 } else { 0 }
        $flagBonus = [math]::Min(25, $obf.Flags.Count * 5)

        $obf.Percent = [math]::Min(100, $basePct + $toolPct + $bonus + $flagBonus)

        if      ($obf.Percent -ge 80) { $obf.Grade = "HEAVILY OBFUSCATED" }
        elseif  ($obf.Percent -ge 50) { $obf.Grade = "OBFUSCATED" }
        elseif  ($obf.Percent -ge 20) { $obf.Grade = "LIGHTLY OBFUSCATED" }
        else                          { $obf.Grade = "CLEAN" }

    } catch {
        Write-Host "      [!] Cannot read $([Path]::GetFileName($JarPath)): $_" -ForegroundColor DarkRed
    } finally {
        if ($archive) { $archive.Dispose() }
        if ($stream)  { $stream.Close() }
    }

    return $result
}

# ── Minecraft Process Detection ─────────────────────────────────────
function Get-MinecraftJavaProcesses {
    if ($Script:CachedMcProcesses -ne $null) { return $Script:CachedMcProcesses }

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

        [void]$candidates.Add([PSCustomObject]@{
            ProcessId=$ProcId; Name=$Name; CommandLine=$CmdLine; CreationDate=$normalizedDate
            Confidence=$Confidence; LauncherHint=$LauncherHint; WorkingSetMB=$WorkingSetMB
        })
    }

    try {
        $allJava = Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.Name -match '^java(w)?\.exe$' }
        foreach ($proc in $allJava) {
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
                try {
                    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction SilentlyContinue
                    if ($parent -and $parent.Name.ToLower() -match 'minecraft|feather|lunar|badlion|multimc|prismlauncher|curseforge|atlauncher|gdlauncher') {
                        $isMc=$true; $confidence=75; $launcherHint="Parent: $($parent.Name)"
                    }
                } catch {}
            }

            try {
                $memMB = [math]::Round($proc.WorkingSetSize / 1MB, 0)
                if ($memMB -gt 400 -and $confidence -ge 50) { $confidence += 10 }
                if (-not $isMc -and $memMB -gt 800) { $isMc=$true; $confidence=40; $launcherHint="High memory Java ($memMB MB)" }
            } catch {}

            if ($isMc) { Add-Candidate -ProcId $proc.ProcessId -Name $proc.Name -CmdLine $cmd -CreationDate $proc.CreationDate -Confidence $confidence -LauncherHint $launcherHint -WorkingSetMB $memMB }
        }
    } catch {}

    try {
        $windowMatches = Get-Process | Where-Object {
            ($_.MainWindowTitle -match 'Minecraft') -or
            ($_.MainWindowTitle -match 'Feather Client') -or
            ($_.MainWindowTitle -match 'Lunar Client') -or
            ($_.MainWindowTitle -match 'Badlion Client')
        }
        foreach ($wp in $windowMatches) {
            $wmiProc = $null
            try { $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId=$($wp.Id)" -ErrorAction SilentlyContinue } catch {}

            if ($wp.Name -match '^java' -or ($wp.Path -and $wp.Path -match '\\bin\\java')) {
                $cmd = if ($wmiProc -and $wmiProc.CommandLine) { $wmiProc.CommandLine } else { $wp.Path }
                $startTime = $null; try { $startTime = $wp.StartTime } catch {}
                Add-Candidate -ProcId $wp.Id -Name ($wp.Name + ".exe") -CmdLine $cmd `
                    -CreationDate (if ($wmiProc) { $wmiProc.CreationDate } else { $startTime }) `
                    -Confidence 70 -LauncherHint "Window: $($wp.MainWindowTitle)" -WorkingSetMB ([math]::Round($wp.WorkingSet64 / 1MB, 0))
            }

            try {
                $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($wp.Id)" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^java(w)?\.exe$' }
                foreach ($child in $children) {
                    $cmd = if ($child.CommandLine) { $child.CommandLine } else { "" }
                    Add-Candidate -ProcId $child.ProcessId -Name $child.Name -CmdLine $cmd -CreationDate $child.CreationDate -Confidence 85 -LauncherHint "Child of $($wp.Name)" -WorkingSetMB (if ($child.WorkingSetSize) { [math]::Round($child.WorkingSetSize / 1MB, 0) } else { 0 })
                }
            } catch {}
        }
    } catch {}

    try {
        $highMem = Get-Process | Where-Object {
            ($_.Name -match '^java' -or ($_.Path -and $_.Path -match '\\bin\\java')) -and
            ([math]::Round($_.WorkingSet64 / 1MB, 0) -gt 600)
        }
        foreach ($hm in $highMem) {
            if ($seenPids.Contains($hm.Id)) { continue }
            $wmiProc = $null; try { $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId=$($hm.Id)" -ErrorAction SilentlyContinue } catch {}
            $cmd = if ($wmiProc -and $wmiProc.CommandLine) { $wmiProc.CommandLine } else { $hm.Path }
            $hasGameHint = $cmd -match '(?i)minecraft|lwjgl|fabric|forge|quilt|mcp|net\.minecraft'
            if ($hasGameHint -or [math]::Round($hm.WorkingSet64 / 1MB, 0) -gt 1200) {
                $startTime = $null; try { $startTime = $hm.StartTime } catch {}
                Add-Candidate -ProcId $hm.Id -Name ($hm.Name + ".exe") -CmdLine $cmd `
                    -CreationDate (if ($wmiProc) { $wmiProc.CreationDate } else { $startTime }) `
                    -Confidence (if ($hasGameHint) { 60 } else { 45 }) `
                    -LauncherHint "High memory ($([math]::Round($hm.WorkingSet64 / 1MB, 0)) MB)" -WorkingSetMB ([math]::Round($hm.WorkingSet64 / 1MB, 0))
            }
        }
    } catch {}

    try {
        $launcherProcs = Get-Process | Where-Object {
            $_.ProcessName -match 'feather|lunar|badlion|prismlauncher|multimc|gdlauncher|atlauncher|curseforge' -or
            $_.MainWindowTitle -match 'Feather|Lunar|Badlion|Prism|MultiMC'
        }
        foreach ($lp in $launcherProcs) {
            try {
                $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($lp.Id)" -ErrorAction SilentlyContinue
                foreach ($child in $children) {
                    if ($child.Name -match '^java(w)?\.exe$') {
                        $cmd = if ($child.CommandLine) { $child.CommandLine } else { "" }
                        Add-Candidate -ProcId $child.ProcessId -Name $child.Name -CmdLine $cmd -CreationDate $child.CreationDate -Confidence 90 -LauncherHint "Launcher: $($lp.ProcessName)" -WorkingSetMB (if ($child.WorkingSetSize) { [math]::Round($child.WorkingSetSize / 1MB, 0) } else { 0 })
                    }
                    try {
                        $grandchildren = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($child.ProcessId)" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^java(w)?\.exe$' }
                        foreach ($gc in $grandchildren) {
                            $cmd = if ($gc.CommandLine) { $gc.CommandLine } else { "" }
                            Add-Candidate -ProcId $gc.ProcessId -Name $gc.Name -CmdLine $gc.CommandLine -CreationDate $gc.CreationDate -Confidence 85 -LauncherHint "Launcher: $($lp.ProcessName)" -WorkingSetMB (if ($gc.WorkingSetSize) { [math]::Round($gc.WorkingSetSize / 1MB, 0) } else { 0 })
                        }
                    } catch {}
                }
            } catch {}
        }
    } catch {}

    try {
        $pathMatches = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            ($_.Name -match '^java(w)?\.exe$') -and ($_.ExecutablePath -match '\\.minecraft\\' -or $_.CommandLine -match '\\.minecraft\\')
        }
        foreach ($pm in $pathMatches) {
            if ($seenPids.Contains($pm.ProcessId)) { continue }
            $cmd = if ($pm.CommandLine) { $pm.CommandLine } else { "" }
            Add-Candidate -ProcId $pm.ProcessId -Name $pm.Name -CmdLine $cmd -CreationDate $pm.CreationDate -Confidence 75 -LauncherHint ".minecraft path" -WorkingSetMB (if ($pm.WorkingSetSize) { [math]::Round($pm.WorkingSetSize / 1MB, 0) } else { 0 })
        }
    } catch {}

    $Script:CachedMcProcesses = @($candidates | Sort-Object Confidence, CreationDate -Descending)
    return $Script:CachedMcProcesses
}

function Get-MinecraftLaunchTimeUtc {
    $procs = Get-MinecraftJavaProcesses
    if (-not $procs -or $procs.Count -eq 0) { return $null }

    foreach ($p in $procs) {
        Write-Host ("   [DEBUG] PID {0} ({1}) — confidence {2}% — {3} — {4} MB" -f $p.ProcessId, $p.Name, $p.Confidence, $p.LauncherHint, $p.WorkingSetMB) -ForegroundColor DarkGray
    }
    return $procs[0].CreationDate.ToUniversalTime()
}

function Test-IsAdmin {
    if ($Script:AdminChecked) { return $Script:IsAdmin }
    $Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $Script:AdminChecked = $true
    return $Script:IsAdmin
}

# ════════════════════════════════════════════════════════════════════
# ══ USN JOURNAL PARSING ════════════════════════════════════════════
# ════════════════════════════════════════════════════════════════════

# ── USN Reason Constants ────────────────────────────────────────────
$USN_REASON_DATA_OVERWRITE        = [uint32]0x00000001
$USN_REASON_DATA_EXTEND           = [uint32]0x00000002
$USN_REASON_DATA_TRUNCATION       = [uint32]0x00000004
$USN_REASON_NAMED_DATA_OVERWRITE  = [uint32]0x00000010
$USN_REASON_NAMED_DATA_TRUNCATION = [uint32]0x00000020
$USN_REASON_FILE_CREATE           = [uint32]0x00000100
$USN_REASON_FILE_DELETE           = [uint32]0x00000200
$USN_REASON_EA_CHANGE             = [uint32]0x00000400
$USN_REASON_SECURITY_CHANGE       = [uint32]0x00000800
$USN_REASON_RENAME_OLD_NAME       = [uint32]0x00001000
$USN_REASON_RENAME_NEW_NAME       = [uint32]0x00002000
$USN_REASON_INDEXABLE_CHANGE      = [uint32]0x00004000
$USN_REASON_BASIC_INFO_CHANGE     = [uint32]0x00008000
$USN_REASON_HARD_LINK_CHANGE      = [uint32]0x00010000
$USN_REASON_COMPRESSION_CHANGE    = [uint32]0x00020000
$USN_REASON_ENCRYPTION_CHANGE     = [uint32]0x00040000
$USN_REASON_OBJECT_ID_CHANGE      = [uint32]0x00080000
$USN_REASON_REPARSE_POINT_CHANGE  = [uint32]0x00100000
$USN_REASON_STREAM_CHANGE         = [uint32]0x00200000
$USN_REASON_TRANSACTED_CHANGE     = [uint32]0x00400000
$USN_REASON_INTEGRITY_CHANGE      = [uint32]0x00800000
$USN_REASON_CLOSE = [uint32]0x80000000L

# ── Helper: parse a hex reason string into uint32 safely ────────────
# FIX: Convert.ToUInt32(str, 16) does NOT accept a "0x" prefix and
#      silently throws, leaving $reasonVal = 0 and all bitmask checks
#      false. This helper strips the prefix before conversion.
function ConvertFrom-HexReason([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw)) { return [uint32]0 }
    $hex = $Raw.Trim()
    # Strip 0x / 0X prefix
    if ($hex -match '^0[xX](.+)$') { $hex = $Matches[1] }
    try   { return [convert]::ToUInt32($hex, 16) }
    catch {
        try { return [uint32]::Parse($hex, [System.Globalization.NumberStyles]::HexNumber) }
        catch { return [uint32]0 }
    }
}

# ── Helper: decode human-readable "Reason" text into a bitmask ──────
# FIX: When the numeric "Reason #" column is absent or zero we fall
#      back to OR-ing bits from the text "Reason" column, e.g.
#      "Data extend | Basic info change | Close"
function ConvertFrom-ReasonText([string]$Text) {
    [uint32]$val = 0
    if ([string]::IsNullOrWhiteSpace($Text)) { return $val }
    $tl = $Text.ToLower()
    if ($tl -match 'data overwrite')    { $val = $val -bor [uint32]0x00000001 }
    if ($tl -match 'data extend')       { $val = $val -bor [uint32]0x00000002 }
    if ($tl -match 'data truncation')   { $val = $val -bor [uint32]0x00000004 }
    if ($tl -match 'file create')       { $val = $val -bor [uint32]0x00000100 }
    if ($tl -match 'file delete')       { $val = $val -bor [uint32]0x00000200 }
    if ($tl -match 'rename.*old')       { $val = $val -bor [uint32]0x00001000 }
    if ($tl -match 'rename.*new')       { $val = $val -bor [uint32]0x00002000 }
    if ($tl -match 'basic info change') { $val = $val -bor [uint32]0x00008000 }
    if ($tl -match '\bclose\b')         { $val = $val -bor [uint32]0x80000000 }
    return $val
}

# ── Read fsutil USN journal output (handles OEM encoding correctly) ─
function Get-UsnJournalRaw([string]$DriveRoot) {
    $tmp = Join-Path $env:TEMP ("usn_" + [guid]::NewGuid().ToString("N") + ".csv")
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = "cmd.exe"
        $psi.Arguments              = "/c fsutil usn readjournal `"$DriveRoot`" csv > `"$tmp`" 2>nul"
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true
        $psi.RedirectStandardOutput = $false
        $psi.RedirectStandardError  = $false

        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.WaitForExit()

        if ($proc.ExitCode -ne 0) {
            Write-Host "      [USN] fsutil exit code $($proc.ExitCode)" -ForegroundColor DarkYellow
            return @()
        }
        if (-not (Test-Path $tmp)) {
            Write-Host "      [USN] Temp file not created" -ForegroundColor DarkYellow
            return @()
        }
        [byte[]]$bytes = [System.IO.File]::ReadAllBytes($tmp)
        $oemEncoding   = [Console]::OutputEncoding
        $text          = $oemEncoding.GetString($bytes)
        $lines         = $text -split "`r?`n"
        return $lines
    } catch {
        Write-Host "      [USN] fsutil temp-file read failed: $_" -ForegroundColor DarkRed
        return @()
    } finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

# ── Parse USN journal and filter for .jar files ─────────────────────
function Get-UsnJournalData([string]$ModsPath) {
    $entries = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (-not (Test-IsAdmin)) {
        Write-Host "      [USN] Not running as admin — skipping journal read" -ForegroundColor DarkYellow
        return $entries
    }

    try {
        if (-not (Test-Path $ModsPath)) {
            Write-Host "      [USN] Mods path not found: $ModsPath" -ForegroundColor DarkYellow
            return $entries
        }
        $root = ([Path]::GetPathRoot((Resolve-Path $ModsPath))).TrimEnd('\\')
        if (-not $root) {
            Write-Host "      [USN] Could not resolve drive root from $ModsPath" -ForegroundColor DarkYellow
            return $entries
        }

        Write-Host "      [USN] Reading journal for $root ..." -ForegroundColor DarkGray

        # Diagnostic: check journal status
        try {
            $qjOutput = & cmd /c "fsutil usn queryjournal $root 2>&1"
            $qjStr    = $qjOutput -join " "
            if ($qjStr -match "Next Usn") {
                Write-Host "      [USN] Journal active on $root" -ForegroundColor DarkGray
            } else {
                Write-Host "      [USN] queryjournal: $qjStr" -ForegroundColor DarkYellow
            }
        } catch {
            Write-Host "      [USN] queryjournal failed: $_" -ForegroundColor DarkYellow
        }

        $lines = Get-UsnJournalRaw -DriveRoot $root

        if ($lines.Count -eq 0 -or ($lines.Count -eq 1 -and [string]::IsNullOrWhiteSpace($lines[0]))) {
            Write-Host "      [USN] fsutil returned empty output — journal may be empty or disabled" -ForegroundColor DarkYellow
            return $entries
        }
        Write-Host "      [USN] fsutil returned $($lines.Count) line(s)" -ForegroundColor DarkGray

        for ($i = 0; $i -lt [Math]::Min($lines.Count, 15); $i++) {
            $preview = $lines[$i]
            if ($preview.Length -gt 140) { $preview = $preview.Substring(0, 140) + "..." }
            Write-Host "      [USN] Line $i : [$preview]" -ForegroundColor DarkGray
        }

        # Find CSV header
        $headerIdx = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line -match '\s*:\s*' -and $line -notmatch ',') { continue }
            $lowerLine = $line.ToLower()
            if ($lowerLine -match 'usn' -and $lowerLine -match 'file name' -and $lowerLine -match 'reason') {
                $headerIdx = $i
                Write-Host "      [USN] CSV header candidate at line $i : [$line]" -ForegroundColor DarkGray
                break
            }
        }

        if ($headerIdx -lt 0) {
            Write-Host "      [USN] Could not find CSV header in journal output" -ForegroundColor DarkYellow
            return $entries
        }

        # Parse header — strip BOM if present
        $headerLine = $lines[$headerIdx]
        $headerLine = $headerLine -replace "^\xEF\xBB\xBF", ""
        $headerLine = $headerLine -replace "^\xFE\xFF", ""
        $headerLine = $headerLine -replace "^\xFF\xFE", ""

        $hdr = $headerLine -split ',' | ForEach-Object { $_.Trim().Trim('"').Trim() }
        Write-Host "      [USN] Split headers ($($hdr.Count) parts): [$($hdr -join ' | ')]" -ForegroundColor DarkGray

        # Locate columns
        $idxName      = -1
        $idxReason    = -1   # text column  e.g. "Data extend | Close"
        $idxReasonNum = -1   # hex column   e.g. 0x00000082
        $idxTime      = -1
        $idxFileID    = -1
        $idxParentID  = -1

        for ($h = 0; $h -lt $hdr.Count; $h++) {
            $col = $hdr[$h].ToLower().Trim()
            if ($col -eq 'filename'    -or $col -eq 'file name')         { $idxName      = $h }
            if ($col -eq 'reason')                                        { $idxReason    = $h }
            if ($col -eq 'reason #'    -or $col -eq 'reason#')           { $idxReasonNum = $h }
            if ($col -eq 'timestamp'   -or $col -eq 'time stamp')        { $idxTime      = $h }
            if ($col -eq 'fileid'      -or $col -eq 'file id')           { $idxFileID    = $h }
            if ($col -eq 'parentfileid'-or $col -eq 'parent file id')    { $idxParentID  = $h }
        }

        Write-Host "      [USN] Columns — Name=$idxName Reason(text)=$idxReason Reason#(hex)=$idxReasonNum Time=$idxTime FileID=$idxFileID ParentFileID=$idxParentID" -ForegroundColor DarkGray

        if ($idxName -lt 0) {
            Write-Host "      [USN] Required column (FileName) missing — cannot parse" -ForegroundColor DarkYellow
            return $entries
        }
        if ($idxReason -lt 0 -and $idxReasonNum -lt 0) {
            Write-Host "      [USN] Neither Reason nor Reason# column found — cannot parse" -ForegroundColor DarkYellow
            return $entries
        }

        # Get mods folder FileID for parent-based filtering
        $folderRef = $null
        try {
            $batFile = Join-Path $env:TEMP ("qfi_" + [guid]::NewGuid().ToString("N") + ".bat")
            '@echo off' | Out-File -FilePath $batFile -Encoding ASCII
            ('fsutil file queryfileid "' + $ModsPath + '"') | Out-File -FilePath $batFile -Append -Encoding ASCII

            $psi                    = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName           = "cmd.exe"
            $psi.Arguments          = '/c "' + $batFile + '"'
            $psi.UseShellExecute    = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError  = $true
            $psi.CreateNoWindow     = $true
            $proc  = [System.Diagnostics.Process]::Start($psi)
            $q     = $proc.StandardOutput.ReadToEnd()
            $errTx = $proc.StandardError.ReadToEnd()
            $proc.WaitForExit()
            Remove-Item $batFile -Force -ErrorAction SilentlyContinue

            $q = $q.Trim()
            Write-Host "      [USN] queryfileid raw: [$q]" -ForegroundColor DarkGray
            if ($errTx) { Write-Host "      [USN] queryfileid stderr: [$errTx]" -ForegroundColor DarkGray }
            if ($q -match '0x([0-9a-fA-F]+)') {
                $folderRef = $Matches[1].ToLower().TrimStart('0')
                Write-Host "      [USN] Mods folder FileID: [$folderRef]" -ForegroundColor DarkGray
            } else {
                Write-Host "      [USN] Could not parse folder FileID — will scan all .jar entries" -ForegroundColor DarkYellow
            }
        } catch {
            Write-Host "      [USN] queryfileid failed: $_ — will scan all .jar entries" -ForegroundColor DarkYellow
        }

        $parsed     = 0
        $jarHits    = 0
        $folderHits = 0

        for ($i = $headerIdx + 1; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line -match '\s*:\s*' -and $line -notmatch ',') { continue }

            $parsed++

            # CSV-aware split (handles quoted fields)
            $parts    = [System.Collections.Generic.List[string]]::new()
            $current  = ""
            $inQuotes = $false
            for ($c = 0; $c -lt $line.Length; $c++) {
                $ch = $line[$c]
                if ($ch -eq '"') { $inQuotes = -not $inQuotes; continue }
                if ($ch -eq ',' -and -not $inQuotes) { $parts.Add($current.Trim()); $current = ""; continue }
                $current += $ch
            }
            $parts.Add($current.Trim())

            if ($parts.Count -le $idxName) { continue }
            $filename = $parts[$idxName].Trim('"')
            if ($filename -notlike "*.jar") { continue }
            $jarHits++

            # ── FIX: Reason value resolution ────────────────────────
            # Priority: hex column ("Reason #") → text column ("Reason")
            # The old code passed "0x00008000" directly to ToUInt32(...,16)
            # which threw because the 0x prefix is not legal in that overload.
            # ConvertFrom-HexReason strips the prefix first.
            [uint32]$reasonVal = 0
            $reasonHex         = ""
            $reasonText        = ""

            if ($idxReasonNum -ge 0 -and $parts.Count -gt $idxReasonNum) {
                $rawHex    = $parts[$idxReasonNum].Trim('"')
                $reasonVal = ConvertFrom-HexReason $rawHex
                if ($reasonVal -ne 0) { $reasonHex = $rawHex }
            }

            if ($idxReason -ge 0 -and $parts.Count -gt $idxReason) {
                $reasonText = $parts[$idxReason].Trim('"')
            }

            # Text fallback: if hex gave us nothing, decode the text column
            if ($reasonVal -eq 0 -and -not [string]::IsNullOrWhiteSpace($reasonText)) {
                $reasonVal = ConvertFrom-ReasonText $reasonText
            }
            # ────────────────────────────────────────────────────────

            $timestampStr = ""
            if ($idxTime -ge 0 -and $parts.Count -gt $idxTime) {
                $timestampStr = $parts[$idxTime].Trim('"')
            }

            $fileID = $null
            if ($idxFileID -ge 0 -and $parts.Count -gt $idxFileID) {
                $fileID = $parts[$idxFileID].Trim('"').ToLower().TrimStart('0').Replace("0x","")
            }

            $parentFileID = $null
            if ($idxParentID -ge 0 -and $parts.Count -gt $idxParentID) {
                $parentFileID = $parts[$idxParentID].Trim('"').ToLower().TrimStart('0').Replace("0x","")
            }

            if ($folderRef -and $parentFileID) {
                if ($parentFileID -ne $folderRef) { continue }
                $folderHits++
            }

            $timestamp = [datetime]::MinValue
            if (-not [string]::IsNullOrWhiteSpace($timestampStr)) {
                foreach ($fmt in @(
                    { [datetime]::Parse($timestampStr, [System.Globalization.CultureInfo]::CurrentCulture, [System.Globalization.DateTimeStyles]::None) },
                    { [datetime]::Parse($timestampStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None) },
                    { [datetime]::ParseExact($timestampStr, "yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture) }
                )) {
                    try { $timestamp = & $fmt; break } catch {}
                }
            }

            [void]$entries.Add([PSCustomObject]@{
                FileName     = $filename
                ReasonHex    = $reasonHex
                ReasonValue  = $reasonVal
                ReasonText   = $reasonText
                TimeStamp    = $timestamp
                FileID       = $fileID
                ParentFileID = $parentFileID
            })
        }

        Write-Host "      [USN] Parsed $parsed data rows, $jarHits .jar hits, $folderHits in target folder, $($entries.Count) kept" -ForegroundColor DarkGray
    } catch {
        Write-Host "      [!] USN journal read failed: $_" -ForegroundColor DarkRed
    }

    return $entries
}

# ── Analyze USN entries for replacement patterns ────────────────────
function Get-UsnReplacementEvidence([string]$ModsPath, [nullable[datetime]]$MinecraftLaunchUtc) {
    $evidence   = @{}
    $allEntries = Get-UsnJournalData -ModsPath $ModsPath

    if ($allEntries.Count -eq 0) {
        Write-Host "      [USN] No journal entries for .jar files in mods folder — will use filesystem timestamps as backup" -ForegroundColor DarkYellow
        return $evidence
    }

    Write-Host "      [USN] Analyzing $($allEntries.Count) entries for replacement patterns..." -ForegroundColor DarkGray
    $grouped = $allEntries | Group-Object -Property FileName

    foreach ($g in $grouped) {
        $name    = $g.Name
        $sorted  = $g.Group | Sort-Object TimeStamp

        $hasDelete         = $false
        $hasCreate         = $false
        $hasOverwrite      = $false
        $hasDataExtend     = $false
        $hasDataTruncation = $false
        $hasBasicInfoChange= $false
        $hasRenameOld      = $false
        $hasRenameNew      = $false
        $hasClose          = $false
        $deleteTime        = $null
        $createTime        = $null
        $overwriteTime     = $null
        $extendTime        = $null
        $truncationTime    = $null
        $basicInfoTime     = $null
        $lastActivity      = $null

        foreach ($entry in $sorted) {
            $r = $entry.ReasonValue
            if ($r -band $USN_REASON_FILE_DELETE)       { $hasDelete          = $true; $deleteTime      = $entry.TimeStamp }
            if ($r -band $USN_REASON_FILE_CREATE)       { $hasCreate          = $true; $createTime      = $entry.TimeStamp }
            if ($r -band $USN_REASON_DATA_OVERWRITE)    { $hasOverwrite       = $true; $overwriteTime   = $entry.TimeStamp }
            if ($r -band $USN_REASON_DATA_EXTEND)       { $hasDataExtend      = $true; $extendTime      = $entry.TimeStamp }
            if ($r -band $USN_REASON_DATA_TRUNCATION)   { $hasDataTruncation  = $true; $truncationTime  = $entry.TimeStamp }
            if ($r -band $USN_REASON_BASIC_INFO_CHANGE) { $hasBasicInfoChange = $true; $basicInfoTime   = $entry.TimeStamp }
            if ($r -band $USN_REASON_RENAME_OLD_NAME)   { $hasRenameOld       = $true }
            if ($r -band $USN_REASON_RENAME_NEW_NAME)   { $hasRenameNew       = $true }
            if ($r -band $USN_REASON_CLOSE)             { $hasClose           = $true }
            $lastActivity = $entry.TimeStamp
        }

        $flags = [System.Collections.Generic.List[string]]::new()
        $score = 0

        # Pattern 1: Deleted then recreated (classic replacement)
        if ($hasDelete -and $hasCreate) {
            $score += 3
            [void]$flags.Add("FILE DELETED then RECREATED")
            if ($deleteTime -and $createTime) {
                [void]$flags.Add("Deleted: $($deleteTime.ToString('MM/dd HH:mm:ss')) | Recreated: $($createTime.ToString('MM/dd HH:mm:ss'))")
            }
        }

        # Pattern 2: Data extend/truncation after creation (file content changed)
        if ($hasCreate -and ($hasDataExtend -or $hasDataTruncation)) {
            $score += 2
            [void]$flags.Add("FILE CONTENT CHANGED after creation (extend/truncation)")
            if ($extendTime)     { [void]$flags.Add("Extended  : $($extendTime.ToString('MM/dd HH:mm:ss'))") }
            if ($truncationTime) { [void]$flags.Add("Truncated : $($truncationTime.ToString('MM/dd HH:mm:ss'))") }
        }

        # ── FIX: Pattern 2b ─────────────────────────────────────────
        # Data extend/truncation + basic info change together = the
        # canonical Windows file-replace fingerprint. Score +3 so this
        # combination alone crosses the Suspected threshold (>= 3).
        # Previously this combo only scored +1+1 = 2 and was silently
        # dropped.
        if (($hasDataExtend -or $hasDataTruncation) -and $hasBasicInfoChange) {
            $score += 3
            if ($hasDataExtend -and $hasDataTruncation) {
                [void]$flags.Add("FILE REWRITTEN — data extended AND truncated + basic info changed")
            } elseif ($hasDataExtend) {
                [void]$flags.Add("FILE GROWN — data extended + basic info changed (content added / replaced)")
            } else {
                [void]$flags.Add("FILE SHRUNK — data truncated + basic info changed (content stripped / replaced)")
            }
            if ($extendTime)     { [void]$flags.Add("Extended  : $($extendTime.ToString('MM/dd HH:mm:ss'))") }
            if ($truncationTime) { [void]$flags.Add("Truncated : $($truncationTime.ToString('MM/dd HH:mm:ss'))") }
            if ($basicInfoTime)  { [void]$flags.Add("BasicInfo : $($basicInfoTime.ToString('MM/dd HH:mm:ss'))") }
        }
        # ─────────────────────────────────────────────────────────────

        # Pattern 3: Overwritten in place
        if ($hasOverwrite -and ($hasDataExtend -or $hasDataTruncation) -and $hasClose) {
            $score += 2
            [void]$flags.Add("FILE OVERWRITTEN in-place")
            if ($overwriteTime) { [void]$flags.Add("Overwritten: $($overwriteTime.ToString('MM/dd HH:mm:ss'))") }
        }

        # Pattern 4: Basic info change alone (size/attributes modified)
        if ($hasBasicInfoChange) {
            $score += 1
            [void]$flags.Add("BASIC INFO CHANGED (size/attributes modified)")
            if ($basicInfoTime) { [void]$flags.Add("BasicInfoChange: $($basicInfoTime.ToString('MM/dd HH:mm:ss'))") }
        }

        # Pattern 5: Renamed from another name
        if ($hasRenameNew) {
            $score += 2
            [void]$flags.Add("FILE RENAMED from another name (possible download -> mod rename)")
        }

        # Pattern 6: Created after Minecraft launch
        if ($hasCreate -and $MinecraftLaunchUtc -ne $null -and $createTime -gt $MinecraftLaunchUtc) {
            $score += 1
            [void]$flags.Add("Created AFTER Minecraft launch at $($createTime.ToString('MM/dd HH:mm:ss'))")
        }

        # Pattern 7: Deleted and not recreated
        if ($hasDelete -and -not $hasCreate) {
            $score += 1
            [void]$flags.Add("FILE DELETED and not recreated at $($deleteTime.ToString('MM/dd HH:mm:ss'))")
        }

        # Pattern 8: New file dropped in (no prior delete)
        if ($hasCreate -and -not $hasDelete) {
            $score += 1
            [void]$flags.Add("NEW FILE created at $($createTime.ToString('MM/dd HH:mm:ss'))")
        }

        # Pattern 9: Data extend
        if ($hasDataExtend) {
            $score += 1
            [void]$flags.Add("DATA EXTENDED (new content appended)")
        }

        # Pattern 10: Data truncation
        if ($hasDataTruncation) {
            $score += 1
            [void]$flags.Add("DATA TRUNCATED (file shortened)")
        }

        if ($score -gt 0) {
            $evidence[$name] = [PSCustomObject]@{
                Score        = $score
                Flags        = $flags
                LastActivity = $lastActivity
                EntryCount   = $sorted.Count
            }
        }
    }

    Write-Host "      [USN] Found $($evidence.Count) file(s) with replacement activity" -ForegroundColor DarkGray
    return $evidence
}

function Get-UsnMissingMods([string]$ModsPath, [hashtable]$UsnEvidence, [System.IO.FileInfo[]]$CurrentJars) {
    $result = [System.Collections.Generic.List[object]]::new()
    if (-not $UsnEvidence) { return @() }

    $currentNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($jar in $CurrentJars) { [void]$currentNames.Add($jar.Name) }

    foreach ($name in $UsnEvidence.Keys) {
        $ev              = $UsnEvidence[$name]
        $wasDeletedOnly  = $false
        foreach ($flag in $ev.Flags) {
            if ($flag -match "FILE DELETED and not recreated") { $wasDeletedOnly = $true; break }
        }
        if ($wasDeletedOnly -and -not $currentNames.Contains($name)) {
            [void]$result.Add([PSCustomObject]@{
                JarName  = $name
                FullPath = "N/A"
                Reason   = "Deleted from mods folder (USN journal shows FILE DELETE without recreation)"
                Source   = "usn"
            })
        }
    }

    return @($result)
}

# ════════════════════════════════════════════════════════════════════

function Get-ModNameAndClassRoots([string]$JarPath) {
    $roots   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $modId   = $null; $modName = $null; $ver = $null
    $stream  = $null; $archive = $null
    try {
        $stream  = [File]::OpenRead($JarPath)
        $archive = New-Object ZipArchive($stream, [ZipArchiveMode]::Read, $false)
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -like "*.class") {
                $path  = $entry.FullName -replace '\.class$',''
                $parts = $path -split '[/\\]'
                if ($parts.Count -ge 2) { [void]$roots.Add(($parts[0..($parts.Count-2)] -join '.')) }
            }
        }
        foreach ($jsonFile in @("fabric.mod.json","quilt.mod.json")) {
            $entry = $archive.GetEntry($jsonFile)
            if ($entry) {
                $r    = New-Object StreamReader($entry.Open())
                $json = $r.ReadToEnd(); $r.Dispose()
                if ($json -match '"id"\s*:\s*"([^"]+)"')     { $modId   = $Matches[1].ToLower() }
                if ($json -match '"name"\s*:\s*"([^"]+)"')   { $modName = $Matches[1] }
                if ($json -match '"version"\s*:\s*"([^"]+)"'){ $ver     = $Matches[1] }
            }
        }
        $entry = $archive.GetEntry("META-INF/mods.toml")
        if ($entry) {
            $r    = New-Object StreamReader($entry.Open())
            $toml = $r.ReadToEnd(); $r.Dispose()
            if ($toml -match 'modId\s*=\s*"([^"]+)"')      { $modId   = $Matches[1].ToLower() }
            if ($toml -match 'displayName\s*=\s*"([^"]+)"'){ $modName = $Matches[1] }
            if ($toml -match 'version\s*=\s*"([^"]+)"')    { $ver     = $Matches[1] }
        }
    } catch {}
    finally {
        if ($archive) { $archive.Dispose() }
        if ($stream)  { $stream.Close() }
    }
    return [pscustomobject]@{ ModId=$modId; Name=$modName; Version=$ver; Roots=@($roots) }
}

function Get-ModReplacementAudit {
    param(
        [Parameter(Mandatory)][string]$JarPath,
        [nullable[datetime]]$MinecraftLaunchUtc = $null,
        [hashtable]$UsnEvidence                 = $null
    )

    $reasons  = [System.Collections.Generic.List[string]]::new()
    $evidence = [System.Collections.Generic.List[string]]::new()

    if (-not (Test-Path $JarPath)) {
        [void]$reasons.Add("File missing on disk")
        return [pscustomobject]@{
            Path=$JarPath; Exists=$false; Suspected=$true; Score=999
            Reasons=@($reasons); Evidence=@($evidence); SHA1=$null
            ModId=$null; Version=$null; Name=$null; LastWriteUtc=$null; CreationTimeUtc=$null; Size=$null; UsnFound=$false
        }
    }

    $item     = Get-Item $JarPath -ErrorAction Stop
    $sha1     = Get-FileSHA1 $JarPath
    $info     = Get-ModNameAndClassRoots $JarPath
    $modId    = Get-ModId $JarPath
    if (-not $modId) { $modId = $info.ModId }
    $score    = 0
    $leafName = [Path]::GetFileName($JarPath)

    # ── Filesystem timestamp fallback ─────────────────────────────
    $lw = $item.LastWriteTimeUtc
    $ct = $item.CreationTimeUtc
    if ($MinecraftLaunchUtc -ne $null) {
        if ($ct -gt $MinecraftLaunchUtc) {
            $score += 3
            [void]$reasons.Add("[BACKUP] File CREATED after Minecraft launch (CreationTimeUtc > LaunchTime)")
            [void]$evidence.Add("[BACKUP] CreationTimeUtc = $($ct.ToString('o'))  |  LaunchUtc = $($MinecraftLaunchUtc.ToString('o'))")
            [void]$evidence.Add("[BACKUP] This file was put in the mods folder AFTER the game started running")
        }
        if ($lw -gt $MinecraftLaunchUtc) {
            $score += 2
            [void]$reasons.Add("[BACKUP] File MODIFIED after Minecraft launch (LastWriteTimeUtc > LaunchTime)")
            [void]$evidence.Add("[BACKUP] LastWriteUtc = $($lw.ToString('o'))  |  LaunchUtc = $($MinecraftLaunchUtc.ToString('o'))")
        }
        if ($ct -gt $MinecraftLaunchUtc -and [math]::Abs(($ct - $lw).TotalSeconds) -lt 5) {
            $score += 1
            [void]$reasons.Add("[BACKUP] Brand-new file dropped in after launch (CreationTime ≈ LastWriteTime)")
        }
    }

    # ── USN journal evidence ──────────────────────────────────────
    $usnFound = $false
    if ($UsnEvidence -and $UsnEvidence.ContainsKey($leafName)) {
        $usnFound  = $true
        $usn       = $UsnEvidence[$leafName]
        $score    += $usn.Score
        foreach ($flag in $usn.Flags) { [void]$reasons.Add("[USN] $flag") }
        [void]$evidence.Add("[USN] $($usn.EntryCount) journal entries")
        if ($usn.LastActivity -and $usn.LastActivity -ne [datetime]::MinValue) {
            [void]$evidence.Add("[USN] Last activity: $($usn.LastActivity.ToString('o'))")
        }
    }

    if (-not (Test-IsAdmin)) {
        [void]$evidence.Add("[USN] Admin required for journal access — using filesystem timestamps as backup")
    }

    return [pscustomobject]@{
        Path=$JarPath; Exists=$true; Suspected=($score -ge 3); Score=$score
        Reasons=@($reasons | Select-Object -Unique); Evidence=@($evidence | Select-Object -Unique)
        SHA1=$sha1; ModId=$modId; Version=$info.Version; Name=$info.Name
        LastWriteUtc=$item.LastWriteTimeUtc; CreationTimeUtc=$item.CreationTimeUtc; Size=$item.Length; UsnFound=$usnFound
    }
}

# ── Live Classpath Mods ───────────────────────────────────────────
function Get-LiveClasspathMods {
    $procs         = Get-MinecraftJavaProcesses
    $classpathJars = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $procs) {
        $cmd = $p.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
        $patterns = @(
            '(?:^|\s)-cp\s+("?)([^"]+?)\1(?:\s|$)',
            '(?:^|\s)-classpath\s+("?)([^"]+?)\1(?:\s|$)',
            '(?:^|\s)--classpath\s+("?)([^"]+?)\1(?:\s|$)'
        )
        foreach ($pattern in $patterns) {
            if ($cmd -match $pattern) {
                $cpValue = $Matches[2].Trim('"')
                $paths   = $cpValue -split ';'
                foreach ($path in $paths) {
                    $trimmed = $path.Trim().Trim('"')
                    if ($trimmed -like "*.jar") {
                        try { [void]$classpathJars.Add([Environment]::ExpandEnvironmentVariables($trimmed)) } catch {}
                    }
                }
                break
            }
        }
    }
    return @($classpathJars)
}

function Get-MissingModsLive([string]$ModsPath, [System.IO.FileInfo[]]$CurrentJars) {
    $result       = [System.Collections.Generic.List[object]]::new()
    $liveJars     = Get-LiveClasspathMods
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
            [void]$result.Add([PSCustomObject]@{
                JarName  = [Path]::GetFileName($liveJar)
                FullPath = $liveJar
                Reason   = "Referenced in JVM classpath but missing from disk"
                Source   = "live"
            })
        }
    }
    return @($result)
}

# ── Log Fallback ────────────────────────────────────────────────────
function Find-LogFile([string]$ModsPath) {
    $candidates = [System.Collections.Generic.List[string]]::new()
    $current = $ModsPath
    for ($i=0; $i -lt 5; $i++) {
        $current = Split-Path $current -Parent
        if (-not $current) { break }
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
            if ($modId -notin @('java','minecraft','fabricloader','forge','quilt_loader','quilt-loader','mixin','fabric-api','fabric-api-base')) {
                [void]$modIds.Add($modId)
            }
        }
        if ($inModList -and $line -match '^\S' -and $line -notmatch 'Loading\s+\d+\s+mods?:' -and $line -notmatch '^\s*-\s+[a-z]') { $inModList = $false }
        if ($line -match 'Loading mod\s+([a-z][a-z0-9_-]*)') { [void]$modIds.Add($Matches[1].ToLower()) }
        if ($line -match '\[main/INFO\]:\s+([a-z][a-z0-9_-]+)\s+v?\d+\.\d+') {
            $modId = $Matches[1].ToLower()
            if ($modId -notin @('java','minecraft','fabricloader','forge','quilt_loader','mixin','fabric-api')) { [void]$modIds.Add($modId) }
        }
    }
    return @($modIds)
}

function Get-MissingModsFromLog([string]$ModsPath, [System.IO.FileInfo[]]$CurrentJars) {
    $result  = [System.Collections.Generic.List[object]]::new()
    $logFile = Find-LogFile -ModsPath $ModsPath
    if (-not $logFile) { return @() }
    Write-Host "   Log fallback: parsing $logFile" -ForegroundColor DarkGray
    $logModIds = Get-ModIdsFromLog -LogPath $logFile
    if ($logModIds.Count -eq 0) { Write-Host "   No mod list found in log" -ForegroundColor DarkGray; return @() }
    Write-Host "   Found $($logModIds.Count) mod IDs in last session log" -ForegroundColor DarkGray

    $currentModIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($jar in $CurrentJars) {
        $modId = Get-ModId $jar.FullName
        if ($modId) { [void]$currentModIds.Add($modId.ToLower()) }
    }
    foreach ($logModId in $logModIds) {
        if (-not $currentModIds.Contains($logModId)) {
            [void]$result.Add([PSCustomObject]@{
                JarName  = "Unknown (mod ID: $logModId)"
                FullPath = "N/A"
                Reason   = "Loaded in last session per log, but JAR missing"
                Source   = "log"
            })
        }
    }
    return @($result)
}

# ── Box Drawing ───────────────────────────────────────────────────
$BoxW = 72
function Box-Top($title,$color) {
    $pad = [Math]::Max(0, $BoxW - $title.Length - 1)
    Write-Host "   ┌─ $title$("─" * $pad)┐" -ForegroundColor $color
}
function Box-Sep($color) { Write-Host "   ├$("─" * ($BoxW + 3))┤" -ForegroundColor $color }
function Box-Bot($color) { Write-Host "   └$("─" * ($BoxW + 3))┘" -ForegroundColor $color }
function Box-Line($text,$color) {
    $pad = $BoxW - $text.Length
    if ($pad -lt 0) { $text = $text.Substring(0, $BoxW); $pad = 0 }
    Write-Host "   │  $text$(" " * $pad) │" -ForegroundColor $color
}
function Truncate([string]$s,[int]$max) {
    if ($s.Length -gt $max) { return $s.Substring(0, $max - 3) + "..." }
    return $s
}

# ── Entry Point ───────────────────────────────────────────────────
Write-Host "   Fetching Feather official mod list from Modrinth..." -ForegroundColor Cyan
Initialize-FeatherWhitelist
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

if (-not (Test-IsAdmin)) { Write-Host "   [Note] Not running as admin — USN checks disabled" -ForegroundColor DarkYellow }
Write-Host ""

# ── USN Journal Pre-Scan ──────────────────────────────────────────
$Script:UsnEvidence = $null
if (Test-IsAdmin) {
    Write-Host "   Reading USN journal for replacement & missing mod detection..." -ForegroundColor Cyan
    $Script:UsnEvidence = Get-UsnReplacementEvidence -ModsPath $path -MinecraftLaunchUtc $mcLaunchUtc
    if ($Script:UsnEvidence.Count -gt 0) {
        Write-Host "   USN journal: $($Script:UsnEvidence.Count) .jar file(s) with replacement activity" -ForegroundColor DarkGray
    } else {
        Write-Host "   USN journal: no replacement activity detected" -ForegroundColor DarkGray
    }
} else {
    Write-Host "   [Note] Admin required for USN journal replacement detection" -ForegroundColor DarkYellow
}
Write-Host ""

# ── Pass 0: Feather + Missing Mods ──────────────────────────────────
Write-Host "   Pass 0 — Feather check & missing-mod detection..." -ForegroundColor Cyan
$featherOfficial = [System.Collections.Generic.List[object]]::new()
$toProcess       = [System.Collections.Generic.List[object]]::new()
$spinner = @("|","/","-","\"); $idx = 0

foreach ($jar in $jars) {
    Write-Host "`r   $($spinner[$idx++ % 4])  Reading metadata: $($jar.Name)$((' ' * 40))" -ForegroundColor DarkGray -NoNewline
    $modId = Get-ModId $jar.FullName
    if ($modId -and (Test-FeatherOfficial $modId)) { [void]$featherOfficial.Add([PSCustomObject]@{ Jar=$jar; ModId=$modId }) }
    else                                           { [void]$toProcess.Add($jar) }
}
Write-Host "`r$(' ' * 90)`r   $($featherOfficial.Count) Feather official, $($toProcess.Count) require further checks" -ForegroundColor Green

$missingMods = [System.Collections.Generic.List[object]]::new()
$seenKeys    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$liveRan     = $false; $logRan = $false

if ($mcRunning) {
    Write-Host "   Live check: scanning JVM classpath for missing mods..." -ForegroundColor Cyan
    $liveMissing = Get-MissingModsLive -ModsPath $path -CurrentJars $jars
    foreach ($m in $liveMissing) { if ($seenKeys.Add($m.JarName.ToLower())) { [void]$missingMods.Add($m) } }
    $liveRan = $true
    if ($liveMissing.Count -eq 0) { Write-Host "   All classpath mods present on disk" -ForegroundColor DarkGray }
    else                          { Write-Host "   [CRITICAL] $($liveMissing.Count) mod(s) referenced in JVM but missing!" -ForegroundColor Red }
}

$logMissing = Get-MissingModsFromLog -ModsPath $path -CurrentJars $jars
$logFile    = Find-LogFile -ModsPath $path
$logRan     = $logFile -ne $null
foreach ($m in $logMissing) {
    $key = if ($m.JarName -match 'mod ID: ([^)]+)') { $Matches[1].ToLower() } else { $m.JarName.ToLower() }
    if ($seenKeys.Add($key)) { [void]$missingMods.Add($m) }
}

if (-not $liveRan -and -not $logRan) { Write-Host "   Detection unavailable (no process, no log)" -ForegroundColor DarkYellow }
elseif (-not $liveRan -and $logRan -and $logMissing.Count -eq 0) { Write-Host "   Log fallback: no missing mods from last session" -ForegroundColor DarkGray }

if ($Script:UsnEvidence) {
    $usnMissing = Get-UsnMissingMods -ModsPath $path -UsnEvidence $Script:UsnEvidence -CurrentJars $jars
    foreach ($m in $usnMissing) {
        $key = $m.JarName.ToLower()
        if ($seenKeys.Add($key)) { [void]$missingMods.Add($m) }
    }
    if ($usnMissing.Count -gt 0) {
        Write-Host "   [CRITICAL] $($usnMissing.Count) mod(s) deleted from folder per USN journal!" -ForegroundColor Red
    }
}
Write-Host ""

# ── Pass 1: Modrinth SHA1 ─────────────────────────────────────────
Write-Host "   Pass 1 — Verifying against Modrinth SHA1 database..." -ForegroundColor Cyan
$verified = [System.Collections.Generic.List[object]]::new()
$unknown  = [System.Collections.Generic.List[object]]::new()
$idx = 0

foreach ($jar in $toProcess) {
    Write-Host "`r   $($spinner[$idx++ % 4])  Checking: $($jar.Name)$((' ' * 40))" -ForegroundColor DarkGray -NoNewline
    $sha1     = Get-FileSHA1 $jar.FullName
    $modrinth = if ($sha1) { Query-Modrinth $sha1 } else { @{ Found=$false } }
    if ($modrinth.Found) { [void]$verified.Add([PSCustomObject]@{ Jar=$jar; Modrinth=$modrinth; SHA1=$sha1 }) }
    else                 { [void]$unknown.Add([PSCustomObject]@{ Jar=$jar; SHA1=$sha1; Scan=$null; Manifest=$null; Replace=$null }) }
}
Write-Host "`r$(' ' * 90)`r   $($verified.Count) verified on Modrinth, $($unknown.Count) unrecognised" -ForegroundColor Green

# ── Pass 2: Replacement Evidence ──────────────────────────────────
Write-Host "   Pass 2 — Replacement evidence scan (ALL mods)..." -ForegroundColor Cyan
$replacementSuspects = [System.Collections.Generic.List[object]]::new()
$replacementClean    = [System.Collections.Generic.List[object]]::new()
$idx = 0

foreach ($entry in $featherOfficial) {
    $jar = $entry.Jar
    Write-Host "`r   $($spinner[$idx++ % 4])  Replacement scan: $($jar.Name)$((' ' * 34))" -ForegroundColor DarkGray -NoNewline
    $replace = Get-ModReplacementAudit -JarPath $jar.FullName -MinecraftLaunchUtc $mcLaunchUtc -UsnEvidence $Script:UsnEvidence
    $entry | Add-Member -NotePropertyName Replace -NotePropertyValue $replace -Force
    if ($replace.Suspected) { [void]$replacementSuspects.Add([PSCustomObject]@{ Jar=$jar; Replace=$replace; SHA1=$null; Category="Feather Official" }) }
    else                    { [void]$replacementClean.Add($entry) }
}

foreach ($entry in $verified) {
    $jar = $entry.Jar
    Write-Host "`r   $($spinner[$idx++ % 4])  Replacement scan: $($jar.Name)$((' ' * 34))" -ForegroundColor DarkGray -NoNewline
    $replace = Get-ModReplacementAudit -JarPath $jar.FullName -MinecraftLaunchUtc $mcLaunchUtc -UsnEvidence $Script:UsnEvidence
    $entry | Add-Member -NotePropertyName Replace -NotePropertyValue $replace -Force
    if ($replace.Suspected) { [void]$replacementSuspects.Add([PSCustomObject]@{ Jar=$jar; Replace=$replace; SHA1=$entry.SHA1; Category="Verified on Modrinth" }) }
    else                    { [void]$replacementClean.Add($entry) }
}

foreach ($entry in $unknown) {
    $jar = $entry.Jar
    Write-Host "`r   $($spinner[$idx++ % 4])  Replacement scan: $($jar.Name)$((' ' * 34))" -ForegroundColor DarkGray -NoNewline
    $replace       = Get-ModReplacementAudit -JarPath $jar.FullName -MinecraftLaunchUtc $mcLaunchUtc -UsnEvidence $Script:UsnEvidence
    $entry.Replace = $replace
    if ($replace.Suspected) { [void]$replacementSuspects.Add([PSCustomObject]@{ Jar=$jar; Replace=$replace; SHA1=$entry.SHA1; Category="Unknown" }) }
    else                    { [void]$replacementClean.Add($entry) }
}
Write-Host "`r$(' ' * 90)`r   Replacement scan complete. $($replacementSuspects.Count) suspect(s)." -ForegroundColor Green
Write-Host ""

# ── Pass 3: Deep Scan ─────────────────────────────────────────────
Write-Host "   Pass 3 — Deep scan: manifest, obfuscation, cheat indicators..." -ForegroundColor Cyan
$flagged      = [System.Collections.Generic.List[object]]::new()
$unknownClean = [System.Collections.Generic.List[object]]::new()
$idx = 0

foreach ($entry in $unknown) {
    $jar = $entry.Jar
    Write-Host "`r   $($spinner[$idx++ % 4])  Scanning: $($jar.Name)$((' ' * 40))" -ForegroundColor DarkGray -NoNewline

    $manifest = Invoke-ManifestScan $jar.FullName
    $scan     = Invoke-JarScan      $jar.FullName

    $entry.Manifest = $manifest
    $entry.Scan     = $scan

    $dirty = ($scan.Triggerbot.Count     -gt 0) -or
             ($scan.SelfDestruct.Count   -gt 0) -or
             ($scan.SuspiciousURLs.Count -gt 0) -or
             ($scan.NetworkCode.Count    -gt 0) -or
             ($scan.JvmArgStrings.Count  -gt 0) -or
             ($manifest.HasFindings)            -or
             ($scan.Obfuscation.Grade -ne "CLEAN")

    if ($dirty) { [void]$flagged.Add([PSCustomObject]@{ Jar=$jar; Scan=$scan; Manifest=$manifest; SHA1=$entry.SHA1 }) }
    else        { [void]$unknownClean.Add($entry) }
}

Write-Host "`r$(' ' * 90)`r   Deep scan complete. $($flagged.Count) flagged." -ForegroundColor Green
Write-Host ""

# ── Output ──────────────────────────────────────────────────────────
Box-Top "FEATHER OFFICIAL  ($($featherOfficial.Count))" Blue
if ($featherOfficial.Count -eq 0) { Box-Line "(none)" DarkGray }
else {
    foreach ($f in $featherOfficial) {
        if ($f.Replace -and $f.Replace.Suspected) {
            Box-Line (Truncate "> $($f.ModId)  |  $($f.Jar.Name)  [REPLACEMENT SUSPECT]" $BoxW) Red
        } else {
            Box-Line (Truncate "> $($f.ModId)  |  $($f.Jar.Name)" $BoxW) Blue
        }
    }
}
Box-Bot Blue
Write-Host ""

Box-Top "MISSING MODS  ($($missingMods.Count))" Yellow
if ($missingMods.Count -eq 0) {
    if (-not $liveRan -and -not $logRan) { Box-Line "(detection unavailable)" DarkGray }
    else { Box-Line "(none detected)" DarkGray }
} else {
    foreach ($m in $missingMods) {
        $sourceTag = if ($m.Source -eq "live") { " [LIVE]" } elseif ($m.Source -eq "usn") { " [USN]" } else { " [LOG]" }
        Box-Line (Truncate "> $($m.JarName)$sourceTag  [MISSING]" $BoxW) Red
        if ($m.FullPath -ne "N/A") { Box-Line "  Path: $($m.FullPath)" DarkGray }
        Box-Line "  $($m.Reason)" Yellow
        if ($m -ne $missingMods[$missingMods.Count - 1]) { Box-Sep Yellow }
    }
}
Box-Bot Yellow
Write-Host ""

Box-Top "VERIFIED ON MODRINTH  ($($verified.Count))" Green
if ($verified.Count -eq 0) { Box-Line "(none)" DarkGray }
else {
    foreach ($v in $verified) {
        if ($v.Replace -and $v.Replace.Suspected) {
            Box-Line (Truncate "> $($v.Modrinth.Name)  |  $($v.Jar.Name)  [REPLACEMENT SUSPECT]" $BoxW) Red
        } else {
            Box-Line (Truncate "> $($v.Modrinth.Name)  |  $($v.Jar.Name)" $BoxW) Green
        }
    }
}
Box-Bot Green
Write-Host ""

Box-Top "REPLACEMENT SUSPECTS  ($($replacementSuspects.Count))" Magenta
if ($replacementSuspects.Count -eq 0) { Box-Line "None detected." DarkGray }
else {
    for ($ri = 0; $ri -lt $replacementSuspects.Count; $ri++) {
        $r   = $replacementSuspects[$ri]
        $jar = $r.Jar; $rep = $r.Replace
        Box-Line "! [$($r.Category)] $($jar.Name)" White
        $fp = $jar.FullName; if ($fp.Length -gt $BoxW - 8) { $fp = "..." + $fp.Substring($fp.Length - ($BoxW - 11)) }
        Box-Line "  Path: $fp" DarkGray
        Box-Line "  Score: $($rep.Score)" DarkMagenta
        if ($rep.ModId)   { Box-Line "  ModId: $($rep.ModId)" DarkGray }
        if ($rep.Name)    { Box-Line "  Name : $($rep.Name)" DarkGray }
        if ($rep.Version) { Box-Line "  Ver  : $($rep.Version)" DarkGray }
        if ($rep.LastWriteUtc)    { Box-Line "  LastWrite : $($rep.LastWriteUtc.ToString('MM/dd HH:mm:ss')) UTC" DarkGray }
        if ($rep.CreationTimeUtc) { Box-Line "  Created   : $($rep.CreationTimeUtc.ToString('MM/dd HH:mm:ss')) UTC" DarkGray }
        foreach ($reason in $rep.Reasons) { Box-Line (Truncate "  - $reason" $BoxW) Yellow }
        if ($rep.Evidence.Count -gt 0) { foreach ($ev in $rep.Evidence) { Box-Line (Truncate "  > $ev" $BoxW) DarkCyan } }
        if ($rep.UsnFound) { Box-Line "  USN journal activity detected" Cyan }
        if ($ri -lt $replacementSuspects.Count - 1) { Box-Sep Magenta }
    }
}
Box-Bot Magenta
Write-Host ""

if ($unknownClean.Count -gt 0) {
    Box-Top "UNKNOWN — CLEAN SCAN  ($($unknownClean.Count))" Yellow
    $ucList = @($unknownClean)
    for ($ui = 0; $ui -lt $ucList.Count; $ui++) {
        $u = $ucList[$ui]; $jar = $u.Jar
        Box-Line "? $($jar.Name)" White
        $fn = $jar.FullName; if ($fn.Length -gt $BoxW - 8) { $fn = "..." + $fn.Substring($fn.Length - ($BoxW - 11)) }
        Box-Line "  Path: $fn" DarkGray
        if ($u.Replace) {
            if ($u.Replace.ModId)         { Box-Line "  ModId: $($u.Replace.ModId)" DarkGray }
            if ($u.Replace.LastWriteUtc)    { Box-Line "  LastWrite : $($u.Replace.LastWriteUtc.ToString('MM/dd HH:mm:ss')) UTC" DarkGray }
            if ($u.Replace.CreationTimeUtc) { Box-Line "  Created   : $($u.Replace.CreationTimeUtc.ToString('MM/dd HH:mm:ss')) UTC" DarkGray }
            if ($u.Replace.Score -gt 0)   { Box-Line "  [INFO] Replacement score: $($u.Replace.Score)" DarkYellow }
        }
        if ($u.Scan -and $u.Scan.Obfuscation.Grade -ne "CLEAN") {
            $obf = $u.Scan.Obfuscation
            Box-Line "  [INFO] Obfuscation: $($obf.Percent)% ($($obf.Grade))" DarkYellow
        }
        $sources = Get-DownloadSource $jar.FullName
        foreach ($src in $sources) { Box-Line (Truncate "  > $src" $BoxW) Yellow }
        if ($ui -lt $ucList.Count - 1) { Box-Sep Yellow }
    }
    Box-Bot Yellow
    Write-Host ""
}

Box-Top "DETECTED THREATS  ($($flagged.Count))" Red
if ($flagged.Count -eq 0) { Box-Line "None detected." Green; Box-Bot Red }
else {
    for ($fi = 0; $fi -lt $flagged.Count; $fi++) {
        $entry    = $flagged[$fi]
        $jar      = $entry.Jar
        $scan     = $entry.Scan
        $manifest = $entry.Manifest

        Box-Line "! $($jar.Name)" White
        $fp = $jar.FullName; if ($fp.Length -gt $BoxW - 8) { $fp = "..." + $fp.Substring($fp.Length - ($BoxW - 11)) }
        Box-Line "  Path: $fp" DarkGray
        Box-Line "  Status: NOT on Modrinth — unknown origin" Magenta
        Box-Sep Red

        $sources = Get-DownloadSource $jar.FullName
        if ($sources -and $sources[0] -notmatch "No download trace") {
            Box-Line "SOURCE" Yellow
            foreach ($src in $sources) { Box-Line (Truncate "  > $src" $BoxW) Yellow }
            Box-Sep Red
        }

        if ($manifest -and $manifest.HasFindings) {
            $total = $manifest.AgentEntries.Count + $manifest.JvmFlags.Count
            Box-Line "JVM AGENT / MANIFEST  ($total indicator(s))" DarkYellow
            foreach ($ae in $manifest.AgentEntries) {
                Box-Line "  $($ae.Key): $(Truncate $ae.Value ($BoxW - 20))" Yellow
                Box-Line "    -> $($ae.Meaning)" DarkYellow
            }
            foreach ($flag in $manifest.JvmFlags) { Box-Line "  [!] $(Truncate $flag ($BoxW - 4))" Yellow }
            Box-Sep Red
        }

        if ($scan.JvmArgStrings.Count -gt 0) {
            Box-Line "JVM ARG INJECTION  ($($scan.JvmArgStrings.Count) hit(s))" DarkYellow
            foreach ($j in ($scan.JvmArgStrings | Select-Object -Unique)) { Box-Line (Truncate "  [!] $j" $BoxW) Yellow }
            Box-Sep Red
        }

        if ($scan.Obfuscation.Grade -ne "CLEAN") {
            $obf = $scan.Obfuscation
            $pct = $obf.Percent
            $bar = ("█" * [math]::Round($pct / 10)) + ("░" * (10 - [math]::Round($pct / 10)))
            Box-Line "OBFUSCATION  [$bar]  $pct%  ($($obf.Grade))" Magenta
            if ($obf.EntropyNote) { Box-Line (Truncate "  Entropy : $($obf.EntropyNote)" $BoxW) DarkMagenta }

            if ($obf.Flags.Count -gt 0) {
                Box-Line "  Detection flags:" DarkMagenta
                foreach ($flag in $obf.Flags) { Box-Line (Truncate "    ⚑ $flag" $BoxW) Yellow }
            }

            if ($obf.KnownTools.Count -gt 0) {
                Box-Line "  Tool signatures: $($obf.KnownTools -join ', ')" DarkMagenta
            }
            Box-Sep Red
        }

        if ($scan.NetworkCode.Count -gt 0) {
            $ncFiles = ($scan.NetworkCode | Select-Object -Property File -Unique).Count
            Box-Line "NETWORK CODE  ($($scan.NetworkCode.Count) hit(s) in $ncFiles class(es))" Cyan
            foreach ($g in ($scan.NetworkCode | Group-Object -Property File)) {
                $fn = $g.Name; if ($fn.Length -gt ($BoxW - 38)) { $fn = "..." + $fn.Substring($fn.Length - ($BoxW - 41)) }
                Box-Line "  $fn" DarkGray
                foreach ($hit in $g.Group | Sort-Object Code) { Box-Line (Truncate "    $($hit.Code) -> $($hit.Meaning)" $BoxW) DarkCyan }
            }
            Box-Sep Red
        }

        if ($scan.Triggerbot.Count -gt 0) {
            $tbFiles = ($scan.Triggerbot | Select-Object -Property File -Unique).Count
            Box-Line "TRIGGERBOT  ($($scan.Triggerbot.Count) hit(s) in $tbFiles class(es))" Red
            foreach ($g in ($scan.Triggerbot | Group-Object -Property File)) {
                $fn = $g.Name; if ($fn.Length -gt ($BoxW - 38)) { $fn = "..." + $fn.Substring($fn.Length - ($BoxW - 41)) }
                Box-Line "  $fn" DarkGray
                foreach ($hit in $g.Group | Sort-Object Code) { Box-Line "    $($hit.Code) -> $($hit.Meaning)" DarkRed }
            }
            Box-Sep Red
        }

        if ($scan.SelfDestruct.Count -gt 0) {
            $sdFiles = ($scan.SelfDestruct | Select-Object -Property File -Unique).Count
            Box-Line "SELF-DESTRUCT  ($($scan.SelfDestruct.Count) hit(s) in $sdFiles class(es))" Magenta

            $uniqueSigs = $scan.SelfDestruct | Where-Object { -not $_.IsCombo } | Select-Object -ExpandProperty Code -Unique
            $hasCombo   = ($scan.SelfDestruct | Where-Object { $_.IsCombo }).Count -gt 0

            $riskParts = [System.Collections.Generic.List[string]]::new()
            if ($uniqueSigs -contains "getCodeSource")       { $riskParts.Add("locate its own JAR") }
            if ($uniqueSigs -contains "setLastModified")     { $riskParts.Add("modify timestamps") }
            if ($uniqueSigs -contains "deleteOnExit")        { $riskParts.Add("delete itself on exit") }
            if ($uniqueSigs -contains "ProcessBuilder")      { $riskParts.Add("launch external processes") }
            if ($uniqueSigs -contains "getProtectionDomain") { $riskParts.Add("check sandbox permissions") }
            if ($hasCombo)                                   { $riskParts.Add("overwrite itself with remote payload") }

            if ($riskParts.Count -gt 0) { Box-Line (Truncate "  Risk: Can $($riskParts -join ', ')." $BoxW) DarkMagenta }

            foreach ($g in ($scan.SelfDestruct | Group-Object -Property File)) {
                $fn = $g.Name; if ($fn.Length -gt ($BoxW - 38)) { $fn = "..." + $fn.Substring($fn.Length - ($BoxW - 41)) }
                Box-Line "  $fn" DarkGray
                foreach ($hit in $g.Group | Sort-Object Code) { Box-Line "    $($hit.Code) -> $($hit.Meaning)" DarkMagenta }
            }
            Box-Sep Red
        }

        if ($scan.SuspiciousURLs.Count -gt 0) {
            $urlFiles = ($scan.SuspiciousURLs | Select-Object -Property File -Unique).Count
            Box-Line "SUSPICIOUS URLS  ($($scan.SuspiciousURLs.Count) hit(s) in $urlFiles class(es))" Cyan
            foreach ($g in ($scan.SuspiciousURLs | Group-Object -Property File)) {
                $fn = $g.Name; if ($fn.Length -gt ($BoxW - 38)) { $fn = "..." + $fn.Substring($fn.Length - ($BoxW - 41)) }
                Box-Line "  $fn" DarkGray
                foreach ($hit in $g.Group) { Box-Line (Truncate "    $($hit.Code)" $BoxW) DarkCyan }
            }
            Box-Sep Red
        }

        if ($fi -lt $flagged.Count - 1) { Box-Line "" DarkGray }
    }
    Box-Bot Red
}

Write-Host ""
Box-Top "SCAN COMPLETE" White
Box-Line "$($featherOfficial.Count)  Feather official  (live-verified)" Blue
if ($missingMods.Count -gt 0) {
    $liveCount = ($missingMods | Where-Object { $_.Source -eq "live" }).Count
    $logCount  = ($missingMods | Where-Object { $_.Source -eq "log"  }).Count
    $usnCount  = ($missingMods | Where-Object { $_.Source -eq "usn"  }).Count
    if      ($liveCount -gt 0 -and $logCount -gt 0 -and $usnCount -gt 0) { Box-Line "$($missingMods.Count)  Missing mods  ($liveCount live + $logCount log + $usnCount USN)" Yellow }
    elseif  ($liveCount -gt 0 -and $logCount -gt 0) { Box-Line "$($missingMods.Count)  Missing mods  ($liveCount live + $logCount log)" Yellow }
    elseif  ($liveCount -gt 0 -and $usnCount -gt 0) { Box-Line "$($missingMods.Count)  Missing mods  ($liveCount live + $usnCount USN)" Yellow }
    elseif  ($logCount  -gt 0 -and $usnCount -gt 0) { Box-Line "$($missingMods.Count)  Missing mods  ($logCount log + $usnCount USN)" Yellow }
    elseif  ($usnCount  -gt 0) { Box-Line "$($missingMods.Count)  Missing mods  ($usnCount USN journal)" Yellow }
    elseif  ($liveCount -gt 0) { Box-Line "$($missingMods.Count)  Missing mods  (live JVM check)" Yellow }
    else                       { Box-Line "$($missingMods.Count)  Missing mods  (last session log)" Yellow }
} else {
    if (-not $liveRan -and -not $logRan) { Box-Line "0  Missing mods  (unavailable)" Yellow }
    else                                 { Box-Line "0  Missing mods  (none detected)" Yellow }
}
Box-Line "$($verified.Count)  Verified on Modrinth  (SHA1 match)" Green
Box-Line "$($replacementSuspects.Count)  Replacement suspects  (USN journal + timestamp)" Magenta
Box-Line "$($unknownClean.Count)  Unknown — passed deep scan" Yellow
Box-Line "$($flagged.Count)  Flagged  (cheat / malware indicators)" Red
Box-Sep White
Box-Line "MANUAL VERIFICATION IS ALWAYS RECOMMENDED" Red
Box-Bot White
Write-Host ""
pause
