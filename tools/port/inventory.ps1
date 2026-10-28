# Lists every gta_sa.exe address literal used by the client and shows which ones already have an
# entry in src/client/shared/game/version/Addresses.cpp.
#
#   powershell -ExecutionPolicy Bypass -File tools/port/inventory.ps1
#   powershell -ExecutionPolicy Bypass -File tools/port/inventory.ps1 -All
#   powershell -ExecutionPolicy Bypass -File tools/port/inventory.ps1 -OutFile docs/port/addresses.csv
#
# This finds literals only. Addresses computed as "addr::TheCamera + 0x150" are covered by the
# base entry and a range entry; add the base to Addresses.cpp and mark it with a range there.
param(
    [string]$OutFile = "",
    [switch]$All,
    [switch]$FailOnMissing
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$addrFile = Join-Path $root "src/client/shared/game/version/Addresses.cpp"
if (-not (Test-Path $addrFile)) { throw "not found: $addrFile" }

# Only the v10 address of each row is a client address; v30 values belong to 3.0 and must not be
# counted as uncovered 1.0 literals.
$known = @{}
$entryNames = @{}
foreach ($m in [regex]::Matches((Get-Content $addrFile -Raw),
        '\{\s*"([^"]+)",\s*0x([0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+|0),')) {
    $v = [Convert]::ToUInt32($m.Groups[2].Value, 16)
    $known[$v] = $true
    $entryNames[$v] = $m.Groups[1].Value
}

$sites = @()
foreach ($dir in @("src/client", "src/common")) {
    Get-ChildItem -Recurse -File (Join-Path $root $dir) |
        Where-Object {
            $_.Extension -in ".cpp", ".h" -and
            $_.FullName -notlike "*\shared\game\version\*"
        } |
        ForEach-Object {
            $lineNo = 0
            foreach ($line in Get-Content $_.FullName) {
                $lineNo++
                foreach ($m in [regex]::Matches($line, '0x([0-9A-Fa-f]{6,8})')) {
                    $v = [Convert]::ToUInt32($m.Groups[1].Value, 16)
                    if ($v -ge 0x401000 -and $v -lt 0xC98000) {
                        $sites += [pscustomobject]@{
                            Address = ('0x{0:X}' -f $v)
                            Value   = $v
                            Covered = $known.ContainsKey($v)
                            File    = $_.FullName.Substring($root.Length + 1).Replace('\', '/')
                            Line    = $lineNo
                        }
                    }
                }
            }
        }
}

$unique = $sites | Group-Object Value | Sort-Object Name
$covered = @($unique | Where-Object { $known.ContainsKey([uint32]$_.Name) }).Count
$missing = $unique.Count - $covered
"game address literals: $($sites.Count) references, $($unique.Count) unique"
"address table entries: $($known.Count); covered literals: $covered / $($unique.Count) ($missing missing)"

$rows = foreach ($g in $unique) {
    $first = $g.Group[0]
    $v = [uint32]$g.Name
    $name = if ($entryNames.ContainsKey($v)) { $entryNames[$v] } else { "" }
    [pscustomobject]@{
        Address = ('0x{0:X}' -f $v)
        Covered = $known.ContainsKey($v)
        Entry   = $name
        Refs    = $g.Count
        First   = "$($first.File):$($first.Line)"
    }
}

if ($OutFile) {
    $path = Join-Path $root $OutFile
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    "written: $path"
} elseif ($All) {
    $rows | Format-Table -AutoSize | Out-String -Width 200
} else {
    $rows | Where-Object { -not $_.Covered } | Select-Object -First 25 |
        Format-Table -AutoSize | Out-String -Width 200
    if ($missing -gt 25) { "... and $($missing - 25) more; use -All or -OutFile" }
}

if ($FailOnMissing -and $missing -gt 0) {
    exit 1
}
