param (
    [Parameter()]
    [ValidateSet('Debug', 'Release')]
    [string]
    $Configuration = 'Release',

    [Parameter()]
    [string]
    $PlatformToolset = '',

    [Parameter()]
    [switch]
    $CleanRuntime,

    [Parameter()]
    [switch]
    $SkipRuntimeCopy
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$netchGoRoot = Split-Path $scriptDir -Parent
$repoRoot = $netchGoRoot

function Normalize-PathEnvironment {
    $pathValue = [Environment]::GetEnvironmentVariable('Path', 'Process')
    if ([string]::IsNullOrWhiteSpace($pathValue)) {
        return
    }

    # Some shells inject both PATH and Path, which can break MSBuild tool tasks.
    [Environment]::SetEnvironmentVariable('PATH', $null, 'Process')
    [Environment]::SetEnvironmentVariable('Path', $pathValue, 'Process')
}

Normalize-PathEnvironment

function Resolve-MSBuild {
    $cmd = Get-Command msbuild -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $installPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($installPath) {
            $candidate = Join-Path $installPath 'MSBuild\Current\Bin\MSBuild.exe'
            if (Test-Path $candidate) {
                return $candidate
            }
        }
    }

    throw 'MSBuild was not found. Please install Visual Studio Build Tools (C++ workload) or run from Developer PowerShell.'
}

function Resolve-PlatformToolset {
    param (
        [Parameter(Mandatory = $true)]
        [string]$VcRoot,

        [Parameter(Mandatory = $false)]
        [string]$Preferred
    )

    if (-not (Test-Path $VcRoot)) {
        if ($Preferred) { return $Preferred }
        return ''
    }

    $vcVersions = @(Get-ChildItem $VcRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^v\d+$' } |
        Sort-Object {
            [int](($_.Name -replace '[^0-9]', ''))
        } -Descending)

    foreach ($vcVersion in $vcVersions) {
        $toolsetRoot = Join-Path $vcVersion.FullName 'Platforms\x64\PlatformToolsets'
        if (-not (Test-Path $toolsetRoot)) {
            continue
        }

        $installed = @(Get-ChildItem $toolsetRoot -Directory | Select-Object -ExpandProperty Name)
        if ($Preferred -and ($installed -contains $Preferred)) {
            return $Preferred
        }

        if (-not $Preferred -and ($installed -contains 'v143')) {
            return 'v143'
        }

        $sorted = @($installed | Sort-Object {
            [int](($_ -replace '[^0-9]', ''))
        } -Descending)
        if ($sorted.Count -gt 0) {
            return $sorted[0]
        }
    }

    if ($Preferred) {
        return $Preferred
    }
    return ''
}

function Get-SanitizedProcessEnvironment {
    $envMap = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $key = [string]$entry.Key
        if (-not $envMap.ContainsKey($key)) {
            $envMap[$key] = [string]$entry.Value
        }
    }
    if (-not $envMap.ContainsKey('Path')) {
        $envMap['Path'] = [Environment]::GetEnvironmentVariable('Path', 'Process')
    }
    return $envMap
}

function Invoke-MSBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MSBuildPath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    # Invoke directly to avoid Start-Process -Wait hanging on long-lived child processes.
    $invokeArgs = @($Arguments + '/nodeReuse:false')
    & $MSBuildPath @invokeArgs
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "Build $DisplayName failed (exit code: $exitCode)"
    }
}

$msbuild = Resolve-MSBuild
Write-Host "Using MSBuild: $msbuild"

$msbuildBin = Split-Path $msbuild -Parent
$msbuildRoot = Split-Path (Split-Path $msbuildBin -Parent) -Parent
$vcRoot = Join-Path $msbuildRoot 'Microsoft\VC'
$resolvedToolset = Resolve-PlatformToolset -VcRoot $vcRoot -Preferred $PlatformToolset

if ($resolvedToolset) {
    Write-Host "Using PlatformToolset: $resolvedToolset"
} elseif ($PlatformToolset) {
    Write-Host "Requested PlatformToolset '$PlatformToolset' was not found. Continue with project default."
}

$runtimeBin = Join-Path $netchGoRoot 'runtime\bin'
if (-not $SkipRuntimeCopy) {
    New-Item -ItemType Directory -Force $runtimeBin | Out-Null
}

$requiredPaths = @(
    (Join-Path $repoRoot 'Redirector\Redirector.vcxproj'),
    (Join-Path $repoRoot 'Redirector\lib\nfapi.lib'),
    (Join-Path $repoRoot 'Redirector\include\nfapi.h')
)
foreach ($requiredPath in $requiredPaths) {
    if (-not (Test-Path $requiredPath)) {
        throw "missing dependency: $requiredPath"
    }
}

function Copy-Artifact {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    if (-not (Test-Path $Source)) {
        throw "artifact not found: $Source"
    }

    Copy-Item -Force $Source $Target

    $srcLen = (Get-Item -LiteralPath $Source).Length
    $dstLen = (Get-Item -LiteralPath $Target).Length
    if ($srcLen -ne $dstLen) {
        throw "copy verify failed: $Source -> $Target (source=$srcLen target=$dstLen)"
    }
    Write-Host "copied $Target ($dstLen bytes)"
}

if ($CleanRuntime -and -not $SkipRuntimeCopy) {
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

$redirectorArgs = @(
    "$repoRoot\Redirector\Redirector.vcxproj",
    "/property:Configuration=$Configuration",
    "/property:Platform=x64"
)
if ($resolvedToolset) {
    $redirectorArgs += "/property:PlatformToolset=$resolvedToolset"
}

Write-Host "Building Redirector ($Configuration|x64)..."
Invoke-MSBuild -MSBuildPath $msbuild -Arguments $redirectorArgs -DisplayName 'Redirector'

$redirectorOut = Join-Path $repoRoot "Redirector\bin\$Configuration\Redirector.bin"
$nfapiOut = Join-Path $repoRoot "Redirector\bin\$Configuration\nfapi.dll"

if ($SkipRuntimeCopy) {
    Write-Host 'native build finished (skip runtime copy)'
    exit 0
}

Copy-Artifact -Source $redirectorOut -Target (Join-Path $runtimeBin 'Redirector.bin')
Copy-Artifact -Source $nfapiOut -Target (Join-Path $runtimeBin 'nfapi.dll')

if (-not (Test-Path (Join-Path $runtimeBin 'nfapi.dll'))) {
    $fallback = Join-Path $repoRoot 'Redirector\static\nfapi.dll'
    if (Test-Path $fallback) {
        Copy-Artifact -Source $fallback -Target (Join-Path $runtimeBin 'nfapi.dll')
    }
}

$driverTarget = Join-Path $runtimeBin 'nfdriver.sys'
if (-not (Test-Path $driverTarget)) {
    $driverCandidates = @(
        (Join-Path $repoRoot 'nfdriver.sys'),
        (Join-Path $repoRoot 'Storage\nfdriver.sys'),
        (Join-Path $repoRoot 'Redirector\static\nfdriver.sys')
    )
    foreach ($candidate in $driverCandidates) {
        if (Test-Path $candidate) {
            Copy-Artifact -Source $candidate -Target $driverTarget
            break
        }
    }
}

if (-not (Test-Path $driverTarget)) {
    Write-Warning "nfdriver.sys not found. Please place it at $repoRoot\\nfdriver.sys or runtime\\bin\\nfdriver.sys"
}

Write-Host 'native runtime build finished'
