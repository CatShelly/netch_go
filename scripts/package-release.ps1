param (
    [Parameter()]
    [ValidateSet('Debug', 'Release')]
    [string]
    $Configuration = 'Release',

    [Parameter()]
    [string]
    $PlatformToolset = '',

    [Parameter()]
    [string]
    $OutputDir = 'dist',

    [Parameter()]
    [string]
    $PackageName = 'netch_go',

    [Parameter()]
    [switch]
    $SkipNativeBuild,

    [Parameter()]
    [switch]
    $PrepareRuntime,

    [Parameter()]
    [switch]
    $CleanRuntime,

    [Parameter()]
    [switch]
    $Clean
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$repoRoot = Split-Path $scriptDir -Parent
$runtimeRoot = Join-Path $repoRoot 'runtime'
$runtimeBin = Join-Path $runtimeRoot 'bin'
$outputRoot = Join-Path $repoRoot $OutputDir
$stageDir = Join-Path $outputRoot "$PackageName-win-x64"
$buildDir = Join-Path $outputRoot '.build'
$exeName = "$PackageName.exe"
$exePath = Join-Path $buildDir $exeName
$wailsBinCandidates = @(
    (Join-Path $repoRoot "build\\bin\\$PackageName"),
    (Join-Path $repoRoot "build\\bin\\$exeName")
)
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$zipPath = Join-Path $outputRoot "$PackageName-win-x64-$timestamp.zip"

function New-CleanDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
}

function Copy-Artifact {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        throw "artifact not found: $Source"
    }

    New-Item -ItemType Directory -Path (Split-Path -Parent $Target) -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Target -Force

    $srcLen = (Get-Item -LiteralPath $Source).Length
    $dstLen = (Get-Item -LiteralPath $Target).Length
    if ($srcLen -ne $dstLen) {
        throw "copy verify failed: $Source -> $Target (source=$srcLen target=$dstLen)"
    }
}

function Copy-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDir,
        [Parameter(Mandatory = $true)]
        [string]$TargetDir
    )

    if (-not (Test-Path -LiteralPath $SourceDir)) {
        return
    }
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    Copy-Item -Path (Join-Path $SourceDir '*') -Destination $TargetDir -Recurse -Force
}

function Copy-PackagedRules {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceRoot,
        [Parameter(Mandatory = $true)]
        [string]$TargetRoot
    )

    New-Item -ItemType Directory -Path $TargetRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $TargetRoot 'custom') -Force | Out-Null

    if (-not (Test-Path -LiteralPath $SourceRoot)) {
        return
    }

    Get-ChildItem -LiteralPath $SourceRoot -File | ForEach-Object {
        Copy-Artifact -Source $_.FullName -Target (Join-Path $TargetRoot $_.Name)
    }
}

function Resolve-FirstExisting {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string[]]$Candidates
    )

    foreach ($candidate in $Candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw "missing runtime dependency: $Name. candidates: $($Candidates -join ', ')"
}

function Write-DefaultConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $cfg = [ordered]@{
        servers = @()
        customRuleSets = @()
        selection = [ordered]@{
            serverId = ''
            ruleSetId = ''
        }
        proxy = [ordered]@{
            filterLoopback = $false
            filterIntranet = $true
            filterParent = $false
            filterICMP = $false
            filterTCP = $true
            filterUDP = $true
            filterDNS = $true
            handleOnlyDns = $false
            dnsProxy = $false
            remoteDns = '1.1.1.1:53'
            icmpDelay = 10
        }
        dns = [ordered]@{
            enabled = $false
            listen = '127.0.0.1:53'
            domesticUpstream = 'tcp://223.5.5.5:53'
            proxyUpstream = 'tcp://1.1.1.1:53'
            ruleFile = ''
            applySystemDns = $false
            managedAdapters = @()
            restoreOnStop = $true
        }
        ui = [ordered]@{
            autoImportLegacy = $true
        }
    }

    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    $json = $cfg | ConvertTo-Json -Depth 8
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}

if ($Clean -and (Test-Path -LiteralPath $outputRoot)) {
    Remove-Item -LiteralPath $outputRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
New-CleanDirectory -Path $buildDir
New-CleanDirectory -Path $stageDir

if (-not $SkipNativeBuild) {
    $nativeSplat = @{
        Configuration  = $Configuration
        SkipRuntimeCopy = $true
    }
    if ($PlatformToolset) {
        $nativeSplat.PlatformToolset = $PlatformToolset
    }
    Write-Host "Building native core ($Configuration)..."
    & (Join-Path $scriptDir 'build-native.ps1') @nativeSplat
    if ($LASTEXITCODE -ne 0) {
        throw "build-native.ps1 failed (exit code: $LASTEXITCODE)"
    }
} else {
    Write-Host 'Skipping native build (using existing native artifacts).'
}

if ($PrepareRuntime) {
    $prepareSplat = @{
        Configuration = $Configuration
    }
    if ($PlatformToolset) {
        $prepareSplat.PlatformToolset = $PlatformToolset
    }
    if ($CleanRuntime) {
        $prepareSplat.CleanRuntime = $true
    }

    Write-Host "Preparing runtime assets ($Configuration)..."
    & (Join-Path $scriptDir 'prepare-runtime.ps1') @prepareSplat
    if ($LASTEXITCODE -ne 0) {
        throw "prepare-runtime.ps1 failed (exit code: $LASTEXITCODE)"
    }
} else {
    Write-Host 'Skipping runtime prepare (packaging direct artifacts).'
}

$requiredRuntimeFiles = @('Redirector.bin', 'nfapi.dll', 'nfdriver.sys')
$resolvedRuntime = @{
    'Redirector.bin' = Resolve-FirstExisting -Name 'Redirector.bin' -Candidates @(
        (Join-Path $repoRoot "Redirector\bin\$Configuration\Redirector.bin"),
        (Join-Path $runtimeBin 'Redirector.bin')
    )
    'nfapi.dll' = Resolve-FirstExisting -Name 'nfapi.dll' -Candidates @(
        (Join-Path $repoRoot "Redirector\bin\$Configuration\nfapi.dll"),
        (Join-Path $repoRoot 'Redirector\static\nfapi.dll'),
        (Join-Path $runtimeBin 'nfapi.dll')
    )
    'nfdriver.sys' = Resolve-FirstExisting -Name 'nfdriver.sys' -Candidates @(
        (Join-Path $runtimeBin 'nfdriver.sys'),
        (Join-Path $repoRoot 'nfdriver.sys'),
        (Join-Path $repoRoot 'Storage\nfdriver.sys'),
        (Join-Path $repoRoot 'Redirector\static\nfdriver.sys')
    )
}
if (-not (Get-Command wails -ErrorAction SilentlyContinue)) {
    throw 'wails CLI was not found in PATH. Please install Wails CLI or run in an environment where `wails` is available.'
}

Write-Host "Building executable with Wails ($exeName)..."
Push-Location $repoRoot
try {
    $wailsArgs = @('build', '-clean', '-s', '-trimpath', '-o', $PackageName)
    if ($Configuration -eq 'Debug') {
        $wailsArgs += '-debug'
    }
    & wails @wailsArgs
    if ($LASTEXITCODE -ne 0) {
        throw "wails build failed (exit code: $LASTEXITCODE)"
    }
} finally {
    Pop-Location
}

 $wailsBinPath = $null
foreach ($candidate in $wailsBinCandidates) {
    if (Test-Path -LiteralPath $candidate) {
        $wailsBinPath = $candidate
        break
    }
}
if (-not $wailsBinPath) {
    throw "wails output not found. checked: $($wailsBinCandidates -join ', ')"
}
Copy-Artifact -Source $wailsBinPath -Target $exePath
Copy-Artifact -Source $exePath -Target (Join-Path $stageDir $exeName)

$stageRuntimeBin = Join-Path $stageDir 'runtime\bin'
foreach ($name in $requiredRuntimeFiles) {
    Copy-Artifact -Source $resolvedRuntime[$name] -Target (Join-Path $stageRuntimeBin $name)
}

Copy-PackagedRules -SourceRoot (Join-Path $runtimeRoot 'rules') -TargetRoot (Join-Path $stageDir 'runtime\rules')

Write-DefaultConfig -Path (Join-Path $stageDir 'data\config.json')

$readme = @(
    'Netch Go Windows Package'
    ''
    'Contents:'
    '- netch_go.exe'
    '- runtime\bin (Redirector.bin / nfapi.dll / nfdriver.sys)'
    '- runtime\rules'
    '- data\config.json (default config)'
    ''
    'Usage:'
    '1. Right click netch_go.exe and choose "Run as administrator".'
    '2. Configure SOCKS server and rule set in the UI, then start session.'
) -join [Environment]::NewLine
Set-Content -LiteralPath (Join-Path $stageDir 'README.txt') -Value $readme -Encoding utf8

if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}

Write-Host "Creating zip: $zipPath"
Compress-Archive -Path $stageDir -DestinationPath $zipPath -CompressionLevel Optimal -Force

Write-Host "Package ready: $zipPath"
