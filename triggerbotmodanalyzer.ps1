#Requires -Version 5.1
using namespace System.IO
using namespace System.IO.Compression

Add-Type -AssemblyName "System.IO.Compression"
Add-Type -AssemblyName "System.IO.Compression.FileSystem"

# ════════════════════════════════════════════════════════════════════
#   Banner
# ════════════════════════════════════════════════════════════════════
Clear-Host
Write-Host ""
Write-Host "   ███╗  ██╗ ██████╗ ███╗   ███╗███████╗    ███████╗███████╗" -ForegroundColor Green
Write-Host "   ████╗ ██║██╔══██╗████╗ ████║██╔════╝    ██╔════╝██╔════╝" -ForegroundColor Green
Write-Host "   ██╔██╗██║██████╔╝██╔████╔██║█████╗      ███████╗███████╗" -ForegroundColor Green
Write-Host "   ██║╚████║██╔══██╗██║╚██╔╝██║██╔══╝      ╚════██║╚════██║" -ForegroundColor Green
Write-Host "   ██║ ╚███║██████╔╝██║ ╚═╝ ██║███████╗    ███████║███████║" -ForegroundColor Green
Write-Host "   ╚═╝  ╚══╝╚═════╝ ╚═╝     ╚═╝╚══════╝    ╚══════╝╚══════╝" -ForegroundColor Green
Write-Host ""
Write-Host "           mod scanner  |  v2.0  |  made by claude.ai" -ForegroundColor Green
Write-Host ""

# ════════════════════════════════════════════════════════════════════
#   Feather Official — Live Modrinth API Verification
#
#   The ONLY mods whitelisted as "Feather Official" are those that
#   belong to Feather's own Modrinth team or organisation.
#
#   Community mods (Sodium, Lithium, Iris, FabricAPI, etc.) that
#   happen to run inside Feather are NOT Feather-authored and must
#   pass SHA1 verification or a deep scan like every other mod.
# ════════════════════════════════════════════════════════════════════

# Possible Modrinth team/org slugs for Feather (feathermc.com)
$FeatherModrinthSlugs = @(
    "feathermc", "featherapp", "featherclient",
    "feather",   "feather-client", "feather-mc"
)

# Minimal static fallback — ONLY IDs from actual Feather-distributed JARs.
# Do NOT add third-party mods here.
$FeatherStaticFallback = @(
    "feather",          # core Feather client mod
    "featherclient",    # alternate core ID
    "feather-fabric",   # Fabric loader bridge
    "featherfabric",
    "feather-api",      # Feather API companion
    "featherapi",
    "feather-companion"
)

$Script:FeatherIds = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

function Initialize-FeatherWhitelist {
    # Seed with static fallback
    foreach ($id in $FeatherStaticFallback) {
        $Script:FeatherIds.Add($id) | Out-Null
    }

    $fetched = $false
    foreach ($slug in $FeatherModrinthSlugs) {
        if ($fetched) { break }
        foreach ($ep in @("organization", "user", "team")) {
            try {
                $uri      = "https://api.modrinth.com/v2/$ep/$slug/projects"
                $projects = Invoke-RestMethod $uri `
                    -Method Get -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop

                if ($projects -and $projects.Count -gt 0) {
                    foreach ($p in $projects) {
                        if ($p.slug) { $Script:FeatherIds.Add($p.slug) | Out-Null }
                        if ($p.id)   { $Script:FeatherIds.Add($p.id)   | Out-Null }
                    }
                    Write-Host ("   [Feather] Live-fetched {0} official mod(s) " +
                                "via Modrinth {1} '{2}'" -f $projects.Count, $ep, $slug) `
                        -ForegroundColor DarkGray
                    $fetched = $true
                    break
                }
            } catch {}
        }
    }

    if (-not $fetched) {
        Write-Host ("   [Feather] Modrinth org lookup found no results — " +
                    "using static fallback ({0} IDs)" -f $Script:FeatherIds.Count) `
            -ForegroundColor DarkYellow
    }
}

function Test-FeatherOfficial([string]$ModId) {
    return (-not [string]::IsNullOrWhiteSpace($ModId)) -and
           $Script:FeatherIds.Contains($ModId)
}

# ════════════════════════════════════════════════════════════════════
#   Cheat Indicators — Triggerbot
# ════════════════════════════════════════════════════════════════════
$TriggerIndicators = @{
    "field_1692"  = "Crosshair target / aimed entity"
    "method_2918" = "Attack entity"
    "method_6104" = "Swing hand"
    "class_1829"  = "SwordItem"
    "class_1743"  = "AxeItem"
    "method_7261" = "Attack cooldown"
}

# ════════════════════════════════════════════════════════════════════
#   Malware Indicators — Self-Destruct / Self-Replace
# ════════════════════════════════════════════════════════════════════
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

# ════════════════════════════════════════════════════════════════════
#   Network Code — suspicious only when inside hook/event classes
# ════════════════════════════════════════════════════════════════════
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

# Class filename fragments that raise suspicion when they also contain network/URL code
$SuspiciousClassFragments = @(
    "mixin", "handler", "keyboard", "input", "event",
    "hook",  "inject",  "listener", "callback"
)

# ════════════════════════════════════════════════════════════════════
#   MANIFEST.MF — JVM Agent / Injection Keys
# ════════════════════════════════════════════════════════════════════
$ManifestAgentKeys = [ordered]@{
    "Premain-Class"                = "Java agent entry point (injects before main class)"
    "Agent-Class"                  = "Attach-API agent (runtime JVM injection)"
    "Boot-Class-Path"              = "Injects JAR into JVM bootstrap classpath"
    "Can-Redefine-Classes"         = "Can replace loaded class bytecode at runtime"
    "Can-Retransform-Classes"      = "Can retransform any loaded class"
    "Can-Set-Native-Method-Prefix" = "Can hook native JVM methods"
}

# ════════════════════════════════════════════════════════════════════
#   Obfuscation Fingerprints
#   Keys are matched against class path segments AND extracted strings
# ════════════════════════════════════════════════════════════════════
$ObfuscatorSignatures = [ordered]@{
    "allatori"            = "Allatori Obfuscator"
    "ZKM"                 = "Zelix KlassMaster"
    "me/lpk/"             = "SkidFuscator (LPK variant)"
    "zenix/skid"          = "Zenix SkidFuscator"
    "radon/"              = "Radon Obfuscator"
    "bozar"               = "Bozar Obfuscator"
    "branchlock"          = "Branchlock Obfuscator"
    "com/preemptive"      = "DashO Obfuscator"
    "superblaubeere27"    = "Superblaubeere27 Obfuscation Tools"
    "stringer"            = "Stringer Obfuscator"
    "javaguard"           = "JavaGuard Obfuscator"
    "de/xbrowniecodez"    = "Branchlock / XBrownie Variant"
    "com/yworks/yguard"   = "yGuard Obfuscator"
    "proguard"            = "ProGuard Obfuscator"
}

# Known short-name abbreviations that are NOT signs of obfuscation
$LegitShortNames = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@("GUI","API","ID","IO","OS","UI","VM","DB","AI","MQ","FX","TK",
                "OK","URL","TCP","UDP","DNS","TLS","SSL","EOF","NIO","RPC",
                "CSV","XML","CLI","CDN","CRC","JWT","AES","RSA","MD5","SHA",
                "PNG","GIF","ZIP","GZip"),
    [System.StringComparer]::OrdinalIgnoreCase
)

# ════════════════════════════════════════════════════════════════════
#   Helpers
# ════════════════════════════════════════════════════════════════════
function Get-ClassStrings([byte[]]$Bytes) {
    $text = [System.Text.Encoding]::GetEncoding('iso-8859-1').GetString($Bytes)
    return [regex]::Matches($text, '[\x20-\x7e]{4,}') | ForEach-Object { $_.Value }
}

function Get-FileSHA1([string]$Path) {
    try { return (Get-FileHash -Path $Path -Algorithm SHA1 -ErrorAction Stop).Hash }
    catch { return $null }
}

function Get-ModId([string]$JarPath) {
    try {
        $stream  = [File]::OpenRead($JarPath)
        $archive = New-Object ZipArchive($stream, [ZipArchiveMode]::Read, $false)

        foreach ($name in @("fabric.mod.json", "quilt.mod.json")) {
            $entry = $archive.GetEntry($name)
            if ($entry) {
                $r    = New-Object StreamReader($entry.Open())
                $json = $r.ReadToEnd(); $r.Dispose()
                if ($json -match '"id"\s*:\s*"([^"]+)"') {
                    $id = $Matches[1]
                    $archive.Dispose(); $stream.Close()
                    return $id.ToLower()
                }
            }
        }

        $entry = $archive.GetEntry("META-INF/mods.toml")
        if ($entry) {
            $r    = New-Object StreamReader($entry.Open())
            $toml = $r.ReadToEnd(); $r.Dispose()
            if ($toml -match 'modId\s*=\s*"([^"]+)"') {
                $id = $Matches[1]
                $archive.Dispose(); $stream.Close()
                return $id.ToLower()
            }
        }

        $archive.Dispose(); $stream.Close()
    } catch {}
    return $null
}

function Query-Modrinth([string]$Hash) {
    try {
        $v = Invoke-RestMethod "https://api.modrinth.com/v2/version_file/$Hash" `
            -Method Get -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        if ($v.project_id) {
            $p = Invoke-RestMethod "https://api.modrinth.com/v2/project/$($v.project_id)" `
                -Method Get -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
            return @{
                Found   = $true
                Name    = $p.title
                Slug    = $p.slug
                Author  = $p.author
                Url     = "https://modrinth.com/mod/$($p.slug)"
                Version = $v.name
            }
        }
    } catch {}
    return @{ Found = $false }
}

function Get-DownloadSource([string]$FilePath) {
    $evidence = [System.Collections.Generic.List[string]]::new()
    $fileItem = Get-Item $FilePath -ErrorAction SilentlyContinue
    $rawName  = [Path]::GetFileName($FilePath).ToLower()

    try {
        $ads = Get-Content -Path $FilePath -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($ads) {
            $zoneId = ""; $hostUrl = ""; $referrerUrl = ""
            foreach ($line in $ads) {
                if      ($line -match "^ZoneId=(\d)")      { $zoneId      = $Matches[1] }
                elseif  ($line -match "^HostUrl=(.+)")     { $hostUrl     = $Matches[1].Trim() }
                elseif  ($line -match "^ReferrerUrl=(.+)") { $referrerUrl = $Matches[1].Trim() }
            }
            if ($hostUrl) {
                $src = $hostUrl
                if      ($hostUrl -match "modrinth\.com")          { $src = "Modrinth"     }
                elseif  ($hostUrl -match "curseforge\.com")        { $src = "CurseForge"   }
                elseif  ($hostUrl -match "github\.com")            { $src = "GitHub"       }
                elseif  ($hostUrl -match "discordapp|discord\.com"){ $src = "Discord CDN"  }
                elseif  ($hostUrl -match "mediafire\.com")         { $src = "MediaFire"    }
                elseif  ($hostUrl -match "mega\.nz")               { $src = "MEGA"         }
                elseif  ($hostUrl -match "dropbox\.com")           { $src = "Dropbox"      }
                elseif  ($hostUrl -match "drive\.google\.com")     { $src = "Google Drive" }
                elseif  ($hostUrl -match "https?://(?:www\.)?([^/]+)") { $src = $Matches[1] }
                $evidence.Add("Source : $src")
                $evidence.Add("URL    : $hostUrl")
            }
            if ($referrerUrl) { $evidence.Add("Referer: $referrerUrl") }
            if ($zoneId -eq "3" -and -not $hostUrl) {
                $evidence.Add("Downloaded from Internet (Zone 3 — URL not recorded)")
            }
        }
    } catch {}

    if ($rawName -match "^download\d*(\.\w+)?$")  {
        $evidence.Add("[Name] Generic download filename (Discord/CDN typical)")
    }
    if ($rawName -match "discord|discordapp") {
        $evidence.Add("[Name] Filename references Discord")
    }
    if ($rawName -match "^[a-f0-9]{8,}(\.\w+)?$") {
        $evidence.Add("[Name] Hash-style filename (CDN / temporary download)")
    }

    try {
        $shell = New-Object -ComObject Shell.Application
        $dir   = $shell.Namespace($fileItem.DirectoryName)
        $item  = $dir.ParseName($fileItem.Name)
        for ($i = 0; $i -lt 400; $i++) {
            $val = $dir.GetDetailsOf($item, $i)
            if ([string]::IsNullOrWhiteSpace($val)) { continue }
            if ($val -match "https?://\S{10,}") {
                $evidence.Add("[Shell] Origin URL in shell property #$i")
                break
            }
        }
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    } catch {}

    if ($evidence.Count -eq 0) {
        return @("No download trace found (file may have been moved or source stripped)")
    }
    return $evidence
}

# ════════════════════════════════════════════════════════════════════
#   MANIFEST.MF Scan — JVM Agent / Injection Detection
#   Only reads the manifest file; class scanning is in Invoke-JarScan
# ════════════════════════════════════════════════════════════════════
function Invoke-ManifestScan([string]$JarPath) {
    $result = [PSCustomObject]@{
        AgentEntries  = [System.Collections.Generic.List[PSCustomObject]]::new()
        JvmFlags      = [System.Collections.Generic.List[string]]::new()
        HasFindings   = $false
    }

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
                    # Can-* keys only matter if explicitly set to true
                    if ($key -match "^Can-" -and $val -ine "true") { continue }
                    $result.AgentEntries.Add([PSCustomObject]@{
                        Key     = $key
                        Value   = $val
                        Meaning = $ManifestAgentKeys[$key]
                    })
                }
            }

            if ($mf -match "-javaagent:")    { $result.JvmFlags.Add("-javaagent flag found in MANIFEST.MF") }
            if ($mf -match "Xbootclasspath") { $result.JvmFlags.Add("Xbootclasspath override in MANIFEST.MF") }
        }

        $archive.Dispose(); $stream.Close()
    } catch {}

    $result.HasFindings = ($result.AgentEntries.Count -gt 0) -or ($result.JvmFlags.Count -gt 0)
    return $result
}

# ════════════════════════════════════════════════════════════════════
#   JAR Deep Scan — Single Pass Over All Class Files
#   Detects: triggerbot · self-destruct · URLs · network code ·
#            JVM arg strings · obfuscation (entropy + tool sigs)
# ════════════════════════════════════════════════════════════════════
function Invoke-JarScan([string]$JarPath) {
    $result = [PSCustomObject]@{
        Triggerbot     = [System.Collections.Generic.List[PSCustomObject]]::new()
        SelfDestruct   = [System.Collections.Generic.List[PSCustomObject]]::new()
        SuspiciousURLs = [System.Collections.Generic.List[PSCustomObject]]::new()
        NetworkCode    = [System.Collections.Generic.List[PSCustomObject]]::new()
        JvmArgStrings  = [System.Collections.Generic.List[string]]::new()
        Obfuscation    = [PSCustomObject]@{
            Grade        = "CLEAN"
            Score        = 0
            KnownTools   = [System.Collections.Generic.List[string]]::new()
            EntropyNote  = ""
            ShortClasses = 0
            TotalClasses = 0
        }
    }

    $stream = $null; $archive = $null
    try {
        $stream  = [File]::OpenRead($JarPath)
        $archive = New-Object ZipArchive($stream, [ZipArchiveMode]::Read, $false)

        # Pre-build a flat string of all class paths for obfuscator sig scanning
        $allClassPaths = ($archive.Entries |
            Where-Object { $_.FullName -like "*.class" } |
            ForEach-Object { $_.FullName }) -join " "

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

            # ── Obfuscation: class name entropy ───────────────────────────
            $result.Obfuscation.TotalClasses++
            $nameParts  = ($entryShort -replace "\.class$", "") -split "[/\\]"
            $simpleName = $nameParts[-1]

            # Strip inner-class suffix ($1, $SomeInner) for the check
            $baseName = $simpleName -replace '\$.*$', ''

            # Flag 1-2 char names that aren't known legitimate abbreviations
            if ($baseName.Length -le 2 -and
                $baseName.Length -ge 1 -and
                $baseName -match "^[a-zA-Z]+$" -and
                -not $LegitShortNames.Contains($baseName)) {
                $result.Obfuscation.ShortClasses++
            }

            # ── Obfuscation: known tool signatures (path + string pool) ───
            $combinedCtx = ($entryLower + " " + ($strings -join " ")).ToLower()
            foreach ($sig in $ObfuscatorSignatures.Keys) {
                if ($combinedCtx -match [regex]::Escape($sig.ToLower())) {
                    $tool = $ObfuscatorSignatures[$sig]
                    if (-not $result.Obfuscation.KnownTools.Contains($tool)) {
                        $result.Obfuscation.KnownTools.Add($tool)
                    }
                }
            }

            # ── JVM arg injection strings in bytecode ─────────────────────
            foreach ($s in $strings) {
                if ($s -match "-javaagent:" -and
                    -not ($result.JvmArgStrings | Where-Object { $_ -match [regex]::Escape($entryShort) })) {
                    $result.JvmArgStrings.Add("Hardcoded -javaagent flag in: $entryShort")
                }
                if ($s -match "Xbootclasspath" -and
                    -not ($result.JvmArgStrings | Where-Object { $_ -match [regex]::Escape($entryShort) })) {
                    $result.JvmArgStrings.Add("Bootclasspath override string in: $entryShort")
                }
            }

            # ── Is this a suspicious class context? ───────────────────────
            $isSuspicious = $SuspiciousClassFragments | Where-Object { $entryLower -match $_ }

            # ── Triggerbot ─────────────────────────────────────────────────
            foreach ($ind in $TriggerIndicators.Keys) {
                if ($strings -match [regex]::Escape($ind)) {
                    $result.Triggerbot.Add([PSCustomObject]@{
                        Code    = $ind
                        Meaning = $TriggerIndicators[$ind]
                        File    = $entryShort
                    })
                }
            }

            # ── Self-Destruct ──────────────────────────────────────────────
            foreach ($ind in $SelfDestructIndicators.Keys) {
                if ($strings -match [regex]::Escape($ind)) {
                    $result.SelfDestruct.Add([PSCustomObject]@{
                        Code    = $ind
                        Meaning = $SelfDestructIndicators[$ind]
                        File    = $entryShort
                        IsCombo = $false
                    })
                }
            }

            $comboScore = 0
            $comboHit   = [System.Collections.Generic.List[string]]::new()
            foreach ($token in $SelfReplaceCombo.Keys) {
                if ($strings -match [regex]::Escape($token)) {
                    $comboScore++
                    $comboHit.Add("$token ($($SelfReplaceCombo[$token]))")
                }
            }
            if ($comboScore -ge 2) {
                $result.SelfDestruct.Add([PSCustomObject]@{
                    Code    = "[COMBO] Self-replace"
                    Meaning = "$comboScore/3 matched: $($comboHit -join ' | ')"
                    File    = $entryShort
                    IsCombo = $true
                })
            }

            # ── Suspicious URLs + Network code (hook/event classes only) ──
            if ($isSuspicious) {
                foreach ($s in $strings) {
                    if ($s -match "^https?://") {
                        $result.SuspiciousURLs.Add([PSCustomObject]@{
                            Code = $s.Substring(0, [Math]::Min($s.Length, 140))
                            File = $entryShort
                        })
                    }
                }

                foreach ($ind in $NetworkIndicators.Keys) {
                    if ($strings -match [regex]::Escape($ind)) {
                        $result.NetworkCode.Add([PSCustomObject]@{
                            Code    = $ind
                            Meaning = $NetworkIndicators[$ind]
                            File    = $entryShort
                        })
                    }
                }
            }
        }

        # ── Finalize obfuscation score and grade ──────────────────────────
        $obf = $result.Obfuscation
        if ($obf.TotalClasses -gt 5) {
            $ratio = $obf.ShortClasses / $obf.TotalClasses
            if ($ratio -gt 0.60) {
                $obf.EntropyNote = "$($obf.ShortClasses)/$($obf.TotalClasses) classes obfuscated ({0:P0})" -f $ratio
                $obf.Score += 3
            } elseif ($ratio -gt 0.35) {
                $obf.EntropyNote = "$($obf.ShortClasses)/$($obf.TotalClasses) short class names ({0:P0}) — partial" -f $ratio
                $obf.Score += 1
            }
        }
        $obf.Score += ($obf.KnownTools.Count * 2)

        if      ($obf.Score -ge 5) { $obf.Grade = "HEAVILY OBFUSCATED" }
        elseif  ($obf.Score -ge 3) { $obf.Grade = "OBFUSCATED"         }
        elseif  ($obf.Score -ge 1) { $obf.Grade = "LIGHTLY OBFUSCATED" }

    } catch {
        Write-Host "      [!] Cannot read $([Path]::GetFileName($JarPath)): $_" -ForegroundColor DarkRed
    } finally {
        if ($archive) { $archive.Dispose() }
        if ($stream)  { $stream.Close() }
    }

    return $result
}

# ════════════════════════════════════════════════════════════════════
#   Box Drawing Helpers  (50-char content width)
# ════════════════════════════════════════════════════════════════════
$BoxW = 50
function Box-Top($title, $color) {
    $pad = [Math]::Max(0, $BoxW - $title.Length - 1)
    Write-Host "   ┌─ $title$("─" * $pad)┐" -ForegroundColor $color
}
function Box-Sep($color) {
    Write-Host "   ├$("─" * ($BoxW + 3))┤" -ForegroundColor $color
}
function Box-Bot($color) {
    Write-Host "   └$("─" * ($BoxW + 3))┘" -ForegroundColor $color
}
function Box-Line($text, $color) {
    $pad = $BoxW - $text.Length
    if ($pad -lt 0) { $text = $text.Substring(0, $BoxW); $pad = 0 }
    Write-Host "   │  $text$(" " * $pad) │" -ForegroundColor $color
}
function Truncate([string]$s, [int]$max) {
    if ($s.Length -gt $max) { return $s.Substring(0, $max - 3) + "..." }
    return $s
}

# ════════════════════════════════════════════════════════════════════
#   Entry Point
# ════════════════════════════════════════════════════════════════════
Write-Host "   Fetching Feather official mod list from Modrinth..." -ForegroundColor Cyan
Initialize-FeatherWhitelist
Write-Host ""

Write-Host "   Paste your mods folder path and press Enter" -ForegroundColor Cyan
$path = (Read-Host "   Path").Trim().Trim('"')

if (-not (Test-Path $path)) {
    Write-Host "   [ERROR] Path not found: $path" -ForegroundColor Red
    pause; exit
}

$jars = Get-ChildItem -Path $path -Filter "*.jar" -File -Recurse -ErrorAction SilentlyContinue
if ($jars.Count -eq 0) {
    Write-Host "   No .jar files found in that folder." -ForegroundColor Yellow
    pause; exit
}

Write-Host "   Found $($jars.Count) mod(s) to analyze" -ForegroundColor DarkGray

# ════════════════════════════════════════════════════════════════════
#   Pass 0 — Feather Official Check (live-verified IDs only)
# ════════════════════════════════════════════════════════════════════
Write-Host "   Pass 0 — Checking Feather official mod list..." -ForegroundColor Cyan

$featherOfficial = [System.Collections.Generic.List[object]]::new()
$toProcess       = [System.Collections.Generic.List[object]]::new()
$spinner = @("|", "/", "-", "\"); $idx = 0

foreach ($jar in $jars) {
    Write-Host "`r   $($spinner[$idx++ % 4])  Reading metadata: $($jar.Name)$((' ' * 40))" `
        -ForegroundColor DarkGray -NoNewline

    $modId = Get-ModId $jar.FullName

    if ($modId -and (Test-FeatherOfficial $modId)) {
        $featherOfficial.Add([PSCustomObject]@{ Jar = $jar; ModId = $modId })
    } else {
        $toProcess.Add($jar)
    }
}
Write-Host "`r$(' ' * 90)`r   $($featherOfficial.Count) Feather official, $($toProcess.Count) require further checks" `
    -ForegroundColor Green

# ════════════════════════════════════════════════════════════════════
#   Pass 1 — Modrinth SHA1 Verification
# ════════════════════════════════════════════════════════════════════
Write-Host "   Pass 1 — Verifying against Modrinth SHA1 database..." -ForegroundColor Cyan

$verified = [System.Collections.Generic.List[object]]::new()
$unknown  = [System.Collections.Generic.List[object]]::new()
$idx = 0

foreach ($jar in $toProcess) {
    Write-Host "`r   $($spinner[$idx++ % 4])  Checking: $($jar.Name)$((' ' * 40))" `
        -ForegroundColor DarkGray -NoNewline

    $sha1     = Get-FileSHA1 $jar.FullName
    $modrinth = if ($sha1) { Query-Modrinth $sha1 } else { @{ Found = $false } }

    if ($modrinth.Found) {
        $verified.Add([PSCustomObject]@{ Jar = $jar; Modrinth = $modrinth; SHA1 = $sha1 })
    } else {
        $unknown.Add([PSCustomObject]@{
            Jar      = $jar
            SHA1     = $sha1
            Scan     = $null
            Manifest = $null
        })
    }
}
Write-Host "`r$(' ' * 90)`r   $($verified.Count) verified on Modrinth, $($unknown.Count) unrecognised" `
    -ForegroundColor Green

# ════════════════════════════════════════════════════════════════════
#   Pass 2 — Deep Scan
#   manifest · obfuscation · JVM args · network · cheat indicators
# ════════════════════════════════════════════════════════════════════
Write-Host "   Pass 2 — Deep scan: manifest, obfuscation, cheat indicators..." -ForegroundColor Cyan

$flagged      = [System.Collections.Generic.List[object]]::new()
$unknownClean = [System.Collections.Generic.List[object]]::new()
$idx = 0

foreach ($entry in $unknown) {
    $jar = $entry.Jar
    Write-Host "`r   $($spinner[$idx++ % 4])  Scanning: $($jar.Name)$((' ' * 40))" `
        -ForegroundColor DarkGray -NoNewline

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
             ($scan.Obfuscation.Score    -ge 3)

    if ($dirty) {
        $flagged.Add([PSCustomObject]@{
            Jar      = $jar
            Scan     = $scan
            Manifest = $manifest
            SHA1     = $entry.SHA1
        })
    } else {
        $unknownClean.Add($entry)
    }
}

Write-Host "`r$(' ' * 90)`r   Deep scan complete. $($flagged.Count) flagged." -ForegroundColor Green
Write-Host ""

# ════════════════════════════════════════════════════════════════════
#   Output — Feather Official
# ════════════════════════════════════════════════════════════════════
Box-Top "FEATHER OFFICIAL  ($($featherOfficial.Count))" Blue
if ($featherOfficial.Count -eq 0) {
    Box-Line "(none — no Feather JARs detected in this folder)" DarkGray
} else {
    foreach ($f in $featherOfficial) {
        Box-Line (Truncate "> $($f.ModId)  |  $($f.Jar.Name)" $BoxW) Blue
    }
}
Box-Bot Blue
Write-Host ""

# ════════════════════════════════════════════════════════════════════
#   Output — Verified on Modrinth
# ════════════════════════════════════════════════════════════════════
Box-Top "VERIFIED ON MODRINTH  ($($verified.Count))" Green
if ($verified.Count -eq 0) {
    Box-Line "(none)" DarkGray
} else {
    foreach ($v in $verified) {
        Box-Line (Truncate "> $($v.Modrinth.Name)  |  $($v.Jar.Name)" $BoxW) Green
    }
}
Box-Bot Green
Write-Host ""

# ════════════════════════════════════════════════════════════════════
#   Output — Unknown (passed deep scan)
# ════════════════════════════════════════════════════════════════════
if ($unknownClean.Count -gt 0) {
    Box-Top "UNKNOWN — CLEAN SCAN  ($($unknownClean.Count))" Yellow
    $ucList = @($unknownClean)
    for ($ui = 0; $ui -lt $ucList.Count; $ui++) {
        $u   = $ucList[$ui]
        $jar = $u.Jar
        Box-Line "? $($jar.Name)" White

        $fn = $jar.FullName
        if ($fn.Length -gt $BoxW - 8) { $fn = "..." + $fn.Substring($fn.Length - ($BoxW - 11)) }
        Box-Line "  Path: $fn" DarkGray

        # Show obfuscation grade even for clean mods if not fully clean
        if ($u.Scan -and $u.Scan.Obfuscation.Grade -ne "CLEAN") {
            Box-Line "  [INFO] Obfuscation: $($u.Scan.Obfuscation.Grade)" DarkYellow
        }

        $sources = Get-DownloadSource $jar.FullName
        foreach ($src in $sources) {
            Box-Line (Truncate "  > $src" $BoxW) Yellow
        }

        if ($ui -lt $ucList.Count - 1) { Box-Sep Yellow }
    }
    Box-Bot Yellow
    Write-Host ""
}

# ════════════════════════════════════════════════════════════════════
#   Output — Flagged Threats  (continuous box)
# ════════════════════════════════════════════════════════════════════
Box-Top "DETECTED THREATS  ($($flagged.Count))" Red

if ($flagged.Count -eq 0) {
    Box-Line "None detected." Green
    Box-Bot Red
} else {
    for ($fi = 0; $fi -lt $flagged.Count; $fi++) {
        $entry    = $flagged[$fi]
        $jar      = $entry.Jar
        $scan     = $entry.Scan
        $manifest = $entry.Manifest

        # ── Header ────────────────────────────────────────────────────
        Box-Line "! $($jar.Name)" White
        $fp = $jar.FullName
        if ($fp.Length -gt $BoxW - 8) { $fp = "..." + $fp.Substring($fp.Length - ($BoxW - 11)) }
        Box-Line "  Path: $fp" DarkGray
        Box-Line "  Status: NOT on Modrinth — unknown origin" Magenta
        Box-Sep Red

        # ── Download Source ───────────────────────────────────────────
        $sources = Get-DownloadSource $jar.FullName
        if ($sources -and $sources[0] -notmatch "No download trace") {
            Box-Line "SOURCE" Yellow
            foreach ($src in $sources) {
                Box-Line (Truncate "  > $src" $BoxW) Yellow
            }
            Box-Sep Red
        }

        # ── JVM Agent (MANIFEST.MF) ───────────────────────────────────
        if ($manifest -and $manifest.HasFindings) {
            $total = $manifest.AgentEntries.Count + $manifest.JvmFlags.Count
            Box-Line "JVM AGENT / MANIFEST  ($total indicator(s))" DarkYellow

            foreach ($ae in $manifest.AgentEntries) {
                Box-Line "  $($ae.Key): $(Truncate $ae.Value 30)" Yellow
                Box-Line "    -> $($ae.Meaning)" DarkYellow
            }
            foreach ($flag in $manifest.JvmFlags) {
                Box-Line "  [!] $(Truncate $flag 46)" Yellow
            }
            Box-Sep Red
        }

        # ── JVM Arg Strings in Bytecode ───────────────────────────────
        if ($scan.JvmArgStrings.Count -gt 0) {
            Box-Line "JVM ARG INJECTION  ($($scan.JvmArgStrings.Count) hit(s))" DarkYellow
            foreach ($j in ($scan.JvmArgStrings | Select-Object -Unique)) {
                Box-Line (Truncate "  [!] $j" $BoxW) Yellow
            }
            Box-Sep Red
        }

        # ── Obfuscation ───────────────────────────────────────────────
        if ($scan.Obfuscation.Grade -ne "CLEAN") {
            $obf = $scan.Obfuscation
            Box-Line "OBFUSCATION  Grade: $($obf.Grade)" Magenta
            if ($obf.EntropyNote) {
                Box-Line (Truncate "  Entropy : $($obf.EntropyNote)" $BoxW) DarkMagenta
            }
            foreach ($tool in $obf.KnownTools) {
                Box-Line "  Tool sig: $tool" DarkMagenta
            }
            Box-Sep Red
        }

        # ── Network Code (in hook/event classes) ──────────────────────
        if ($scan.NetworkCode.Count -gt 0) {
            $ncFiles = ($scan.NetworkCode | Select-Object -Property File -Unique).Count
            Box-Line "NETWORK CODE  ($($scan.NetworkCode.Count) hit(s) in $ncFiles class(es))" Cyan
            foreach ($g in ($scan.NetworkCode | Group-Object -Property File)) {
                $fn = $g.Name
                if ($fn.Length -gt 38) { $fn = "..." + $fn.Substring($fn.Length - 35) }
                Box-Line "  $fn" DarkGray
                foreach ($hit in $g.Group | Sort-Object Code) {
                    Box-Line (Truncate "    $($hit.Code) -> $($hit.Meaning)" $BoxW) DarkCyan
                }
            }
            Box-Sep Red
        }

        # ── Triggerbot ────────────────────────────────────────────────
        if ($scan.Triggerbot.Count -gt 0) {
            $tbFiles = ($scan.Triggerbot | Select-Object -Property File -Unique).Count
            Box-Line "TRIGGERBOT  ($($scan.Triggerbot.Count) hit(s) in $tbFiles class(es))" Red
            foreach ($g in ($scan.Triggerbot | Group-Object -Property File)) {
                $fn = $g.Name
                if ($fn.Length -gt 38) { $fn = "..." + $fn.Substring($fn.Length - 35) }
                Box-Line "  $fn" DarkGray
                foreach ($hit in $g.Group | Sort-Object Code) {
                    Box-Line "    $($hit.Code) -> $($hit.Meaning)" DarkRed
                }
            }
            Box-Sep Red
        }

        # ── Self-Destruct ─────────────────────────────────────────────
        if ($scan.SelfDestruct.Count -gt 0) {
            $sdFiles = ($scan.SelfDestruct | Select-Object -Property File -Unique).Count
            Box-Line "SELF-DESTRUCT  ($($scan.SelfDestruct.Count) hit(s) in $sdFiles class(es))" Magenta

            $uniqueSigs = $scan.SelfDestruct |
                Where-Object { -not $_.IsCombo } |
                Select-Object -ExpandProperty Code -Unique
            $hasCombo   = ($scan.SelfDestruct | Where-Object { $_.IsCombo }).Count -gt 0

            $riskParts = [System.Collections.Generic.List[string]]::new()
            if ($uniqueSigs -contains "getCodeSource")       { $riskParts.Add("locate its own JAR") }
            if ($uniqueSigs -contains "setLastModified")     { $riskParts.Add("modify timestamps") }
            if ($uniqueSigs -contains "deleteOnExit")        { $riskParts.Add("delete itself on exit") }
            if ($uniqueSigs -contains "ProcessBuilder")      { $riskParts.Add("launch external processes") }
            if ($uniqueSigs -contains "getProtectionDomain") { $riskParts.Add("check sandbox permissions") }
            if ($hasCombo)                                   { $riskParts.Add("overwrite itself with remote payload") }

            if ($riskParts.Count -gt 0) {
                Box-Line (Truncate "  Risk: Can $($riskParts -join ', ')." $BoxW) DarkMagenta
            }

            foreach ($g in ($scan.SelfDestruct | Group-Object -Property File)) {
                $fn = $g.Name
                if ($fn.Length -gt 38) { $fn = "..." + $fn.Substring($fn.Length - 35) }
                Box-Line "  $fn" DarkGray
                foreach ($hit in $g.Group | Sort-Object Code) {
                    Box-Line "    $($hit.Code) -> $($hit.Meaning)" DarkMagenta
                }
            }
            Box-Sep Red
        }

        # ── Suspicious URLs ───────────────────────────────────────────
        if ($scan.SuspiciousURLs.Count -gt 0) {
            $urlFiles = ($scan.SuspiciousURLs | Select-Object -Property File -Unique).Count
            Box-Line "SUSPICIOUS URLS  ($($scan.SuspiciousURLs.Count) hit(s) in $urlFiles class(es))" Cyan
            foreach ($g in ($scan.SuspiciousURLs | Group-Object -Property File)) {
                $fn = $g.Name
                if ($fn.Length -gt 38) { $fn = "..." + $fn.Substring($fn.Length - 35) }
                Box-Line "  $fn" DarkGray
                foreach ($hit in $g.Group) {
                    Box-Line (Truncate "    $($hit.Code)" $BoxW) DarkCyan
                }
            }
            Box-Sep Red
        }

        if ($fi -lt $flagged.Count - 1) { Box-Line "" DarkGray }
    }
    Box-Bot Red
}

# ════════════════════════════════════════════════════════════════════
#   Summary
# ════════════════════════════════════════════════════════════════════
Write-Host ""
Box-Top "SCAN COMPLETE" White
Box-Line "$($featherOfficial.Count)  Feather official  (live-verified via Modrinth)" Blue
Box-Line "$($verified.Count)  Verified on Modrinth  (SHA1 match)" Green
Box-Line "$($unknownClean.Count)  Unknown — passed deep scan" Yellow
Box-Line "$($flagged.Count)  Flagged  (cheat / malware indicators found)" Red
Box-Sep White
Box-Line "v2 NEW  Obfuscation  (name entropy + tool fingerprints)" DarkGray
Box-Line "v2 NEW  JVM agent injection  (MANIFEST.MF + bytecode)" DarkGray
Box-Line "v2 NEW  Network code in hook / event classes" DarkGray
Box-Line "        Zone.Identifier ADS = download source" DarkGray
Box-Line "        Modrinth SHA1       = official mod hash" DarkGray
Box-Line "        Feather Modrinth    = live org verification" DarkGray
Box-Bot White
Write-Host ""
pause
