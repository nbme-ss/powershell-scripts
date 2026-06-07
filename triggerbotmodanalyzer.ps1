#Requires -Version 5.1
using namespace System.IO
using namespace System.IO.Compression

Add-Type -AssemblyName "System.IO.Compression"
Add-Type -AssemblyName "System.IO.Compression.FileSystem"

# ════════════════════════════════════════════════════════════════════
#   Banner  (block art, green, fixed spelling)
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
Write-Host "           mod scanner  |  v1.0  |  made by claude.ai" -ForegroundColor Green
Write-Host ""

# ════════════════════════════════════════════════════════════════════
#   Feather Official Mod Whitelist
# ════════════════════════════════════════════════════════════════════
$FeatherWhitelist = @(
    "teamtracker","animations","armorbar","armorstatus","attackindicator",
    "autohidehud","autoperspective","autotext","backups","blockindicator",
    "blockoverlay","bossbar","brightness","camera","colorsaturation",
    "combodisplay","coordinates","cps","crosshair","culllogs",
    "customadvancementsscreen","customchat","customf3","customfog",
    "damageindicator","darkmode","deathinfo","direction","discordrp",
    "dropprevention","elytras","fovchanger","fps","glint","hearts",
    "hitbox","hitindicator","horses","hypixel","inventory","itemcounter",
    "itemdespawn","iteminfo1","itemphysic","jumpreset","keystrokes",
    "lightleveloverlay","lootbeams","moboverlay","motionblur",
    "mousestrokes","nametags","nickhider","packdisplay","packorganizer",
    "perspective","ping","playermodel","playtime","potioneffects",
    "reachdisplay","reconnect","saturation","scoreboard","screenshot",
    "searchkeybind","serveraddress","shulkertooltips","snaplook",
    "soundfilters","speedmeter","stopwatch1","subtitles","systemresources",
    "tablist","tiertagger","time","timechanger","titletweaker","tnttimer",
    "toastcontrol","togglesprint","tooltips","totem","tps","uhcoverlay",
    "uiscaling","viewmodel","voice","waypoints","weatherchanger","zoom",
    "sodium","lithium","starlight","iris","fabric-api","fabricapi",
    "fabric-language-kotlin","fabriclanguagekotlin","indium","architectury",
    "entityculling","ferritecore","languagereload","lazydfu","memoryleakfix",
    "nofade","phosphor","smoothboot","dynamicfps","dynamic_fps",
    "enhancedblockentities","midnightlib","cloth-config","clothconfig",
    "cloth-api","completeconfig","modmenu","culllessleaves","cull-leaves",
    "lambdabettergrass","lambdynamiclights","borderlessmining",
    "dontclearhistory","dcch","debugify","fastopenlinks","fastopenlinksandfolders",
    "littletweaks","mainmenucredits","midnightcontrols","mixinconflicthelper",
    "mixintrace","morechathistory","nochatreports","notenoughcrashes",
    "youroptions","youroptionshallberespected","wizoom","zoomify",
    "appleskin","betterbeds","blur","craftpresence","enchantedtooltips",
    "horsestats","wthit","bettermounthud","slightguimodifications",
    "advancementsenlarger","bobby","fastchest","carpet","craftpresence",
    "feather","featherclient"
)

# ════════════════════════════════════════════════════════════════════
#   Indicators
# ════════════════════════════════════════════════════════════════════
$TriggerIndicators = @{
    "field_1692"  = "Crosshair target / aimed entity"
    "method_2918" = "Attack entity"
    "method_6104" = "Swing hand"
    "class_1829"  = "SwordItem"
    "class_1743"  = "AxeItem"
    "method_7261" = "Attack cooldown"
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

$SuspiciousClassFragments = @(
    "mixin", "handler", "keyboard", "input", "event",
    "hook", "inject", "listener", "callback"
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

        $entry = $archive.GetEntry("fabric.mod.json")
        if ($entry) {
            $r = New-Object StreamReader($entry.Open())
            $json = $r.ReadToEnd(); $r.Dispose()
            if ($json -match '"id"\s*:\s*"([^"]+)"') { 
                $id = $Matches[1]
                $archive.Dispose(); $stream.Close()
                return $id.ToLower()
            }
        }

        $entry = $archive.GetEntry("quilt.mod.json")
        if ($entry) {
            $r = New-Object StreamReader($entry.Open())
            $json = $r.ReadToEnd(); $r.Dispose()
            if ($json -match '"id"\s*:\s*"([^"]+)"') { 
                $id = $Matches[1]
                $archive.Dispose(); $stream.Close()
                return $id.ToLower()
            }
        }

        $entry = $archive.GetEntry("META-INF/mods.toml")
        if ($entry) {
            $r = New-Object StreamReader($entry.Open())
            $toml = $r.ReadToEnd(); $r.Dispose()
            if ($toml -match 'modId\s*=\s*"([^"]+)"') { 
                $id = $Matches[1]
                $archive.Dispose(); $stream.Close()
                return $id.ToLower()
            }
        }

        $archive.Dispose(); $stream.Close()
    } catch { }
    return $null
}

function Test-FeatherWhitelist([string]$ModId) {
    if ([string]::IsNullOrWhiteSpace($ModId)) { return $false }
    return $FeatherWhitelist -contains $ModId.ToLower()
}

function Query-Modrinth([string]$Hash) {
    try {
        $versionInfo = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$Hash" `
            -Method Get -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        if ($versionInfo.project_id) {
            $projectInfo = Invoke-RestMethod `
                -Uri "https://api.modrinth.com/v2/project/$($versionInfo.project_id)" `
                -Method Get -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
            return @{
                Found    = $true
                Name     = $projectInfo.title
                Slug     = $projectInfo.slug
                Author   = $projectInfo.author
                Url      = "https://modrinth.com/mod/$($projectInfo.slug)"
                Version  = $versionInfo.name
            }
        }
    } catch { }
    return @{ Found = $false; Name = ""; Slug = ""; Author = ""; Url = ""; Version = "" }
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
                if      ($line -match "^ZoneId=(\d)")      { $zoneId = $Matches[1] }
                elseif  ($line -match "^HostUrl=(.+)")     { $hostUrl = $Matches[1].Trim() }
                elseif  ($line -match "^ReferrerUrl=(.+)") { $referrerUrl = $Matches[1].Trim() }
            }

            if ($hostUrl) {
                $sourceName = $hostUrl
                if      ($hostUrl -match "modrinth\.com")     { $sourceName = "Modrinth" }
                elseif  ($hostUrl -match "curseforge\.com")   { $sourceName = "CurseForge" }
                elseif  ($hostUrl -match "github\.com")       { $sourceName = "GitHub" }
                elseif  ($hostUrl -match "cdn\.discordapp\.com|discordapp\.com|discord\.com") { $sourceName = "Discord CDN" }
                elseif  ($hostUrl -match "mediafire\.com")    { $sourceName = "MediaFire" }
                elseif  ($hostUrl -match "mega\.nz")          { $sourceName = "MEGA" }
                elseif  ($hostUrl -match "dropbox\.com")      { $sourceName = "Dropbox" }
                elseif  ($hostUrl -match "drive\.google\.com") { $sourceName = "Google Drive" }
                elseif  ($hostUrl -match "https?://(?:www\.)?([^/]+)") { $sourceName = $Matches[1] }

                $evidence.Add("Source : $sourceName")
                $evidence.Add("URL    : $hostUrl")
            }
            if ($referrerUrl) { $evidence.Add("Referer: $referrerUrl") }
            if ($zoneId -eq "3" -and -not $hostUrl) {
                $evidence.Add("Downloaded from Internet (Zone 3)")
            }
        }
    } catch { }

    if ($rawName -match "^download\d*(\.\w+)?$") {
        $evidence.Add("[Name] Generic 'download' filename typical of Discord/CDN links")
    }
    if ($rawName -match "discord|cdn\.discordapp") {
        $evidence.Add("[Name] Filename references Discord")
    }
    if ($rawName -match "^[a-f0-9]{8,}(\.\w+)?$") {
        $evidence.Add("[Name] Filename is a hash — typical of temporary/CDN downloads")
    }

    try {
        $shell = New-Object -ComObject Shell.Application
        $dir   = $shell.Namespace($fileItem.DirectoryName)
        $item  = $dir.ParseName($fileItem.Name)
        for ($i = 0; $i -lt 400; $i++) {
            $val = $dir.GetDetailsOf($item, $i)
            if ([string]::IsNullOrWhiteSpace($val)) { continue }
            if ($val -match "https?://\S{10,}") {
                $evidence.Add("[Shell] Origin URL found in property #$i")
                break
            }
        }
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    } catch { }

    if ($evidence.Count -eq 0) { return @("No download trace found — file may have been moved or source stripped") }
    return $evidence
}

function Invoke-JarScan([string]$JarPath) {
    $result = [PSCustomObject]@{
        Triggerbot     = [System.Collections.Generic.List[PSCustomObject]]::new()
        SelfDestruct   = [System.Collections.Generic.List[PSCustomObject]]::new()
        SuspiciousURLs = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    $stream  = $null
    $archive = $null

    try {
        $stream  = [File]::OpenRead($JarPath)
        $archive = New-Object ZipArchive($stream, [ZipArchiveMode]::Read, $false)

        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -notlike "*.class") { continue }

            $es = $entry.Open()
            $ms = New-Object MemoryStream
            $es.CopyTo($ms)
            $bytes = $ms.ToArray()
            $es.Dispose(); $ms.Dispose()

            $strings    = Get-ClassStrings $bytes
            $entryShort = $entry.FullName

            foreach ($ind in $TriggerIndicators.Keys) {
                if ($strings -match [regex]::Escape($ind)) {
                    $result.Triggerbot.Add([PSCustomObject]@{
                        Code    = $ind
                        Meaning = $TriggerIndicators[$ind]
                        File    = $entryShort
                    })
                }
            }

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

            $classNameLower = $entryShort.ToLower()
            $isSuspiciousClass = $SuspiciousClassFragments | Where-Object { $classNameLower -match $_ }
            if ($isSuspiciousClass) {
                foreach ($str in $strings) {
                    if ($str -match "^https?://") {
                        $url = $str.Substring(0, [Math]::Min($str.Length, 140))
                        $result.SuspiciousURLs.Add([PSCustomObject]@{
                            Code = $url
                            File = $entryShort
                        })
                    }
                }
            }
        }
    } catch {
        Write-Host "      [!] Cannot read $([Path]::GetFileName($JarPath)): $_" -ForegroundColor DarkRed
    } finally {
        if ($archive) { $archive.Dispose() }
        if ($stream)  { $stream.Close() }
    }
    return $result
}

# ════════════════════════════════════════════════════════════════════
#   Box Drawing Helpers  (tight 50-char content width)
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

# ════════════════════════════════════════════════════════════════════
#   Entry
# ════════════════════════════════════════════════════════════════════
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
#   Pass 0 — Feather Whitelist
# ════════════════════════════════════════════════════════════════════
Write-Host "   Pass 0 — Checking Feather official mod whitelist..." -ForegroundColor Cyan

$featherOfficial = [System.Collections.Generic.List[object]]::new()
$toProcess       = [System.Collections.Generic.List[object]]::new()

$spinner = @("|", "/", "-", "\")
$idx = 0

foreach ($jar in $jars) {
    $spin = $spinner[$idx % 4]
    $idx++
    Write-Host "`r   $spin  Reading metadata: $($jar.Name)                                              " -ForegroundColor DarkGray -NoNewline

    $modId = Get-ModId $jar.FullName

    if ($modId -and (Test-FeatherWhitelist $modId)) {
        $featherOfficial.Add([PSCustomObject]@{
            Jar   = $jar
            ModId = $modId
        })
    } else {
        $toProcess.Add($jar)
    }
}

Write-Host "`r$(" " * 90)`r   $($featherOfficial.Count) Feather official, $($toProcess.Count) require further checks" -ForegroundColor Green

# ════════════════════════════════════════════════════════════════════
#   Pass 1 — Modrinth SHA1 Verification
# ════════════════════════════════════════════════════════════════════
Write-Host "   Pass 1 — Verifying mods on Modrinth..." -ForegroundColor Cyan

$verified = [System.Collections.Generic.List[object]]::new()
$unknown  = [System.Collections.Generic.List[object]]::new()
$flagged  = [System.Collections.Generic.List[object]]::new()

$idx = 0
foreach ($jar in $toProcess) {
    $spin = $spinner[$idx % 4]
    $idx++
    Write-Host "`r   $spin  Checking Modrinth: $($jar.Name)                                              " -ForegroundColor DarkGray -NoNewline

    $sha1 = Get-FileSHA1 $jar.FullName
    $modrinth = @{ Found = $false }

    if ($sha1) {
        $modrinth = Query-Modrinth $sha1
    }

    if ($modrinth.Found) {
        $verified.Add([PSCustomObject]@{
            Jar      = $jar
            Modrinth = $modrinth
            SHA1     = $sha1
        })
    } else {
        $unknown.Add([PSCustomObject]@{
            Jar      = $jar
            SHA1     = $sha1
        })
    }
}

Write-Host "`r$(" " * 90)`r   $($verified.Count) verified on Modrinth, $($unknown.Count) unknown" -ForegroundColor Green

# ════════════════════════════════════════════════════════════════════
#   Pass 2 — Deep Scan
# ════════════════════════════════════════════════════════════════════
Write-Host "   Pass 2 — Deep-scanning unknown mods for cheat indicators..." -ForegroundColor Cyan

$idx = 0
foreach ($entry in $unknown) {
    $jar  = $entry.Jar
    $spin = $spinner[$idx % 4]
    $idx++
    Write-Host "`r   $spin  Scanning: $($jar.Name)                                              " -ForegroundColor DarkGray -NoNewline

    $scan  = Invoke-JarScan $jar.FullName
    $dirty = ($scan.Triggerbot.Count -gt 0) -or
             ($scan.SelfDestruct.Count -gt 0) -or
             ($scan.SuspiciousURLs.Count -gt 0)

    if ($dirty) {
        $flagged.Add([PSCustomObject]@{
            Jar      = $jar
            Scan     = $scan
            SHA1     = $entry.SHA1
            Modrinth = @{ Found = $false }
        })
    }
}

$unknown = $unknown | Where-Object {
    $u = $_.Jar.Name
    ($flagged | Where-Object { $_.Jar.Name -eq $u }).Count -eq 0
}

Write-Host "`r$(" " * 90)`r   Scan complete." -ForegroundColor Green
Write-Host ""

# ════════════════════════════════════════════════════════════════════
#   Output — Feather Official
# ════════════════════════════════════════════════════════════════════
Box-Top "FEATHER OFFICIAL  ($($featherOfficial.Count))" Blue
if ($featherOfficial.Count -eq 0) {
    Box-Line "(none)" DarkGray
} else {
    foreach ($f in $featherOfficial) {
        $txt = "> $($f.ModId)  |  $($f.Jar.Name)"
        if ($txt.Length -gt $BoxW) { $txt = $txt.Substring(0, $BoxW) }
        Box-Line $txt Blue
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
        $txt = "> $($v.Modrinth.Name) v$($v.Modrinth.Version)  |  $($v.Jar.Name)"
        if ($txt.Length -gt $BoxW) { $txt = $txt.Substring(0, $BoxW) }
        Box-Line $txt Green
    }
}
Box-Bot Green
Write-Host ""

# ════════════════════════════════════════════════════════════════════
#   Output — Unknown
# ════════════════════════════════════════════════════════════════════
if ($unknown.Count -gt 0) {
    Box-Top "UNKNOWN MODS  ($($unknown.Count))" Yellow
    foreach ($u in $unknown) {
        $jar = $u.Jar
        Box-Line "? $($jar.Name)" White
        Box-Line "  Path: $($jar.FullName)" DarkGray
        $sources = Get-DownloadSource $jar.FullName
        foreach ($src in $sources) {
            Box-Line "  > $src" Yellow
        }
        if ($u -ne $unknown[-1]) { Box-Sep Yellow }
    }
    Box-Bot Yellow
    Write-Host ""
}

# ════════════════════════════════════════════════════════════════════
#   Output — Flagged Threats  (CONTINUOUS BOX)
# ════════════════════════════════════════════════════════════════════
Box-Top "DETECTED THREATS  ($($flagged.Count))" Red

if ($flagged.Count -eq 0) {
    Box-Line "None detected." Green
    Box-Bot Red
} else {
    for ($fi = 0; $fi -lt $flagged.Count; $fi++) {
        $entry = $flagged[$fi]
        $jar  = $entry.Jar
        $scan = $entry.Scan

        # Header
        Box-Line "! $($jar.Name)" White
        Box-Line "  Path: $($jar.FullName)" DarkGray
        if (-not $entry.Modrinth.Found) {
            Box-Line "  Status: NOT on Modrinth — unknown origin" Magenta
        }
        Box-Sep Red

        # Download Source
        $sources = Get-DownloadSource $jar.FullName
        if ($sources -and ($sources[0] -notmatch "No download trace")) {
            Box-Line "SOURCE" Yellow
            foreach ($src in $sources) {
                Box-Line "  > $src" Yellow
            }
            Box-Sep Red
        }

        # Triggerbot
        if ($scan.Triggerbot.Count -gt 0) {
            $tbFiles = ($scan.Triggerbot | Select-Object -Property File -Unique).Count
            Box-Line "TRIGGERBOT  ($($scan.Triggerbot.Count) hits in $tbFiles class(es))" Red
            $tbGroups = $scan.Triggerbot | Group-Object -Property File
            foreach ($g in $tbGroups) {
                $fn = $g.Name
                if ($fn.Length -gt 38) { $fn = "..." + $fn.Substring($fn.Length - 35) }
                Box-Line "  $fn" DarkGray
                foreach ($hit in $g.Group | Sort-Object Code) {
                    Box-Line "    $($hit.Code) -> $($hit.Meaning)" DarkRed
                }
            }
            Box-Sep Red
        }

        # Self-Destruct
        if ($scan.SelfDestruct.Count -gt 0) {
            $sdFiles = ($scan.SelfDestruct | Select-Object -Property File -Unique).Count
            Box-Line "SELF-DESTRUCT  ($($scan.SelfDestruct.Count) hits in $sdFiles class(es))" Magenta

            $uniqueSigs = $scan.SelfDestruct | Where-Object { -not $_.IsCombo } | Select-Object -ExpandProperty Code -Unique
            $hasCombo   = ($scan.SelfDestruct | Where-Object { $_.IsCombo }).Count -gt 0
            $riskParts  = [System.Collections.Generic.List[string]]::new()
            if ($uniqueSigs -contains "getCodeSource")       { $riskParts.Add("locate its own JAR") }
            if ($uniqueSigs -contains "setLastModified")     { $riskParts.Add("modify timestamps") }
            if ($uniqueSigs -contains "deleteOnExit")        { $riskParts.Add("delete itself on exit") }
            if ($uniqueSigs -contains "ProcessBuilder")     { $riskParts.Add("launch external processes") }
            if ($uniqueSigs -contains "getProtectionDomain") { $riskParts.Add("check sandbox permissions") }
            if ($hasCombo) { $riskParts.Add("overwrite itself with a remote payload") }

            if ($riskParts.Count -gt 0) {
                Box-Line "  Risk: Can $($riskParts -join ', ')." DarkMagenta
            }

            $sdGroups = $scan.SelfDestruct | Group-Object -Property File
            foreach ($g in $sdGroups) {
                $fn = $g.Name
                if ($fn.Length -gt 38) { $fn = "..." + $fn.Substring($fn.Length - 35) }
                Box-Line "  $fn" DarkGray
                foreach ($hit in $g.Group | Sort-Object Code) {
                    Box-Line "    $($hit.Code) -> $($hit.Meaning)" DarkMagenta
                }
            }
            Box-Sep Red
        }

        # Suspicious URLs
        if ($scan.SuspiciousURLs.Count -gt 0) {
            $urlFiles = ($scan.SuspiciousURLs | Select-Object -Property File -Unique).Count
            Box-Line "SUSPICIOUS URLS  ($($scan.SuspiciousURLs.Count) hits in $urlFiles class(es))" Cyan
            $urlGroups = $scan.SuspiciousURLs | Group-Object -Property File
            foreach ($g in $urlGroups) {
                $fn = $g.Name
                if ($fn.Length -gt 38) { $fn = "..." + $fn.Substring($fn.Length - 35) }
                Box-Line "  $fn" DarkGray
                foreach ($hit in $g.Group) {
                    $u = $hit.Code
                    if ($u.Length -gt 44) { $u = $u.Substring(0, 41) + "..." }
                    Box-Line "    $u" DarkCyan
                }
            }
            Box-Sep Red
        }

        if ($fi -lt $flagged.Count - 1) {
            Box-Line "" DarkGray
        }
    }
    Box-Bot Red
}

# ════════════════════════════════════════════════════════════════════
#   Summary
# ════════════════════════════════════════════════════════════════════
Write-Host ""
Box-Top "SCAN COMPLETE" White
Box-Line "$($featherOfficial.Count)  Feather official (whitelisted)" Blue
Box-Line "$($verified.Count)  Verified on Modrinth" Green
Box-Line "$($unknown.Count)  Unknown (clean scan)" Yellow
Box-Line "$($flagged.Count)  Flagged (cheat indicators found)" Red
Box-Sep White
Box-Line "Zone.Identifier ADS = download source detection" DarkGray
Box-Line "Modrinth SHA1 hash  = official mod verification" DarkGray
Box-Line "Feather whitelist   = built-in & bundled mod IDs" DarkGray
Box-Bot White
Write-Host ""
pause
