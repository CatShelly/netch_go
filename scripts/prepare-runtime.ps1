param (
    [Parameter()]
    [ValidateSet('Debug', 'Release')]
    [string]
    $Configuration = 'Release',

    [Parameter()]
    [switch]
    $BuildNative,

    [Parameter()]
    [string]
    $PlatformToolset = '',

    [Parameter()]
    [switch]
    $CleanRuntime
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$netchGoRoot = Split-Path $scriptDir -Parent
$repoRoot = $netchGoRoot

if ($BuildNative) {
    & (Join-Path $scriptDir 'build-native.ps1') -Configuration $Configuration -PlatformToolset $PlatformToolset -CleanRuntime:$CleanRuntime
}

$runtimeBin = Join-Path $netchGoRoot 'runtime\bin'
$runtimeRules = Join-Path $netchGoRoot 'runtime\rules'
New-Item -ItemType Directory -Force $runtimeBin, $runtimeRules | Out-Null

function Copy-Artifact {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    if (-not (Test-Path $Source)) {
        return $false
    }

    Copy-Item -Force $Source $Target
    $srcLen = (Get-Item -LiteralPath $Source).Length
    $dstLen = (Get-Item -LiteralPath $Target).Length
    if ($srcLen -ne $dstLen) {
        throw "copy verify failed: $Source -> $Target (source=$srcLen target=$dstLen)"
    }
    Write-Host "copied $Target ($dstLen bytes)"
    return $true
}

function Test-ProcessRuleFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -eq '.json') {
        try {
            $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
            $type = $json.type
            if ($type -is [double] -or $type -is [int]) {
                return ([int]$type -eq 0)
            }
            $typeText = [string]$type
            return ($typeText -ieq 'ProcessMode' -or $typeText -eq '0')
        } catch {
            return $false
        }
    }

    return $false
}

if ($CleanRuntime) {
    $cleanTargets = @(
        (Join-Path $runtimeBin 'Redirector.bin'),
        (Join-Path $runtimeBin 'nfapi.dll')
    )
    foreach ($target in $cleanTargets) {
        if (Test-Path $target) {
            Remove-Item -LiteralPath $target -Force
            Write-Host "removed stale $target"
        }
    }
}

$copyPairs = @(
    @{ Source = Join-Path $repoRoot 'Redirector\static\nfapi.dll'; Target = Join-Path $runtimeBin 'nfapi.dll' },
    @{ Source = Join-Path $repoRoot "Redirector\bin\$Configuration\Redirector.bin"; Target = Join-Path $runtimeBin 'Redirector.bin' }
)

foreach ($pair in $copyPairs) {
    [void](Copy-Artifact -Source $pair.Source -Target $pair.Target)
}

$driverTarget = Join-Path $runtimeBin 'nfdriver.sys'
if (-not (Test-Path $driverTarget)) {
    $driverCandidates = @(
        (Join-Path $repoRoot 'nfdriver.sys'),
        (Join-Path $repoRoot 'Storage\nfdriver.sys'),
        (Join-Path $repoRoot 'Redirector\static\nfdriver.sys')
    )
    foreach ($candidate in $driverCandidates) {
        if (Copy-Artifact -Source $candidate -Target $driverTarget) {
            break
        }
    }
}

if (-not (Test-Path $driverTarget)) {
    Write-Warning "nfdriver.sys not found. Please place it at $repoRoot\\nfdriver.sys or runtime\\bin\\nfdriver.sys"
}

$legacyMode = Join-Path $repoRoot 'Storage\mode'
if (Test-Path $legacyMode) {
    Get-ChildItem -LiteralPath $legacyMode -Recurse -File | ForEach-Object {
        $relative = $_.FullName.Substring($legacyMode.Length).TrimStart('\', '/')
        if ($relative -match '(^|\\)TUNTAP(\\|$)') {
            return
        }
        if (-not (Test-ProcessRuleFile -Path $_.FullName)) {
            return
        }
        $target = Join-Path $runtimeRules $relative
        New-Item -ItemType Directory -Force (Split-Path -Parent $target) | Out-Null
        [void](Copy-Artifact -Source $_.FullName -Target $target)
    }
    Write-Host 'merged process rule files'
}

Write-Host 'runtime preparation finished'
