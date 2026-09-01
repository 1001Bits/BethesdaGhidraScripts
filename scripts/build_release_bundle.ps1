<#
.SYNOPSIS
    Build a self-contained local source bundle for a GitHub release.

.DESCRIPTION
    Supports both a normal Git checkout and an expanded release/source bundle
    with no .git metadata. The resulting archive contains expanded, lock-declared
    source trees and license files, while excluding local tools, projects,
    executables, generated evidence, and other machine-specific artifacts.

    This script only creates local files. It never publishes or uploads them.
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [string]$Version = "",
    [ValidateSet('Auto', 'Git', 'Expanded')]
    [string]$SourceMode = 'Auto'
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if ($Version -and $Version -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
    throw 'Version may contain only letters, digits, dot, underscore, and hyphen.'
}
if (-not $OutputDir) {
    $OutputDir = Join-Path $RepoRoot 'release'
}
if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

function Assert-ChildPath([string]$Parent, [string]$Child) {
    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $childFull = [IO.Path]::GetFullPath($Child)
    $prefix = $parentFull + [IO.Path]::DirectorySeparatorChar
    if (-not $childFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing path outside output directory: $childFull"
    }
}

function Remove-StagedDirectory([string]$StageRoot, [string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return
    }
    $stageFull = [IO.Path]::GetFullPath($StageRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $pathFull = [IO.Path]::GetFullPath($Path)
    if (-not $pathFull.StartsWith(
            $stageFull + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to scrub outside stage: $pathFull"
    }
    Remove-Item -LiteralPath $pathFull -Recurse -Force
}

Push-Location $RepoRoot
try {
    $gitProbe = & git -C $RepoRoot rev-parse --is-inside-work-tree 2>$null
    $GitMetadataPresent = ($LASTEXITCODE -eq 0 -and
                           ($gitProbe | Select-Object -First 1) -eq 'true')
    if ($SourceMode -eq 'Git' -and -not $GitMetadataPresent) {
        throw 'Git source mode requested, but this is not a Git working tree.'
    }
    $UseGitArchive = ($SourceMode -eq 'Git' -or
                      ($SourceMode -eq 'Auto' -and $GitMetadataPresent))
    if ($GitMetadataPresent) {
        $shortRevision = (& git -C $RepoRoot rev-parse --short HEAD).Trim()
        $headRevision = (& git -C $RepoRoot rev-parse HEAD).Trim()
        $sourceRevision = if ($UseGitArchive) {
            $headRevision
        } else {
            "expanded working tree based on $headRevision (may include local changes)"
        }
    } else {
        $shortRevision = 'expanded-source'
        $sourceRevision = 'expanded source bundle (Git metadata unavailable)'
    }
    if (-not $Version) {
        $Version = 'v{0}-{1}' -f (Get-Date -Format 'yyyy.MM.dd'),$shortRevision
    }

    $stageName = "BethesdaGhidraScripts-$Version"
    $stagePath = Join-Path $OutputDir $stageName
    $zipPath = Join-Path $OutputDir "$stageName.zip"
    $zipChecksumPath = "$zipPath.sha256"
    Assert-ChildPath $OutputDir $stagePath
    Assert-ChildPath $OutputDir $zipPath
    Assert-ChildPath $OutputDir $zipChecksumPath

    if (Test-Path -LiteralPath $stagePath) {
        Remove-StagedDirectory $OutputDir $stagePath
    }
    if (Test-Path -LiteralPath $zipPath -PathType Leaf) {
        Remove-Item -LiteralPath $zipPath -Force
    }
    if (Test-Path -LiteralPath $zipChecksumPath -PathType Leaf) {
        Remove-Item -LiteralPath $zipChecksumPath -Force
    }
    New-Item -ItemType Directory -Path $stagePath | Out-Null

    Write-Host "=== Building local bundle $Version ==="
    Write-Host "Source mode: $(if ($UseGitArchive) { 'Git archive' } else { 'expanded working tree' })"
    Write-Host "Stage: $stagePath"

    Write-Host 'Step 1/6: staging source tree...'
    if ($UseGitArchive) {
        $tarPath = Join-Path $env:TEMP "bgs-stage-$shortRevision.tar"
        git -C $RepoRoot archive --format=tar -o $tarPath HEAD
        if ($LASTEXITCODE -ne 0) { throw 'git archive failed' }
        tar -xf $tarPath -C $stagePath
        if ($LASTEXITCODE -ne 0) { throw 'source archive extraction failed' }
        Remove-Item -LiteralPath $tarPath -Force
    } else {
        $topLevelExcludes = @(
            '.git', '.agents', '.codex', '.claude', '.release_validation',
            '.pytest_cache', '.audit', '.tmp', '__pycache__', 'bsim', 'exes',
            'ghidraprojects', 'ghidrascripts', 'scripts_tmp', 'symbols', 'tools',
            'release'
        )
        $repoPrefix = $RepoRoot.TrimEnd('\') + '\'
        if ($OutputDir.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            $outputRelative = $OutputDir.Substring($repoPrefix.Length)
            $outputTop = $outputRelative.Split([IO.Path]::DirectorySeparatorChar)[0]
            if ($outputTop) { $topLevelExcludes += $outputTop }
        }
        $robocopy = Get-Command robocopy.exe -ErrorAction SilentlyContinue
        if ($robocopy) {
            $excludedPaths = @($topLevelExcludes | Sort-Object -Unique |
                ForEach-Object { Join-Path $RepoRoot $_ })
            $copyArgs = @(
                $RepoRoot, $stagePath, '/E', '/COPY:DAT', '/DCOPY:DAT',
                '/R:1', '/W:1', '/XJ', '/NFL', '/NDL', '/NJH', '/NJS', '/NP',
                '/XD', '.git'
            ) + $excludedPaths
            & $robocopy.Source @copyArgs
            $copyExit = $LASTEXITCODE
            if ($copyExit -ge 8) {
                throw "robocopy staging failed with exit code $copyExit"
            }
        } else {
            Get-ChildItem -LiteralPath $RepoRoot -Force | Where-Object {
                $_.Name -notin $topLevelExcludes
            } | ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination $stagePath -Recurse -Force
            }
        }
    }

    Write-Host 'Step 2/6: expanding/verifying locked source trees...'
    $toolchainLock = Get-Content -LiteralPath (
        Join-Path $RepoRoot 'toolchain.lock.json') -Raw | ConvertFrom-Json
    $submodules = $toolchainLock.submodules.PSObject.Properties |
        Sort-Object Name | ForEach-Object {
            [PSCustomObject]@{ Sha = [string]$_.Value; Path = $_.Name }
        }
    foreach ($source in $submodules) {
        $sourcePath = Join-Path $RepoRoot $source.Path
        $stagedSource = Join-Path $stagePath $source.Path
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) {
            throw "Locked source tree is missing: $($source.Path)"
        }
        Write-Host "  $($source.Sha.Substring(0,7))  $($source.Path)"
        if ($UseGitArchive) {
            $actual = (& git -C $sourcePath rev-parse HEAD).Trim()
            if ($LASTEXITCODE -ne 0 -or $actual -ne $source.Sha) {
                throw "Locked source revision mismatch: $($source.Path)"
            }
            if (-not (Test-Path -LiteralPath $stagedSource)) {
                New-Item -ItemType Directory -Path $stagedSource | Out-Null
            }
            $sourceTar = Join-Path $env:TEMP (
                "bgs-source-{0}.tar" -f $source.Sha.Substring(0,12))
            git -C $sourcePath archive --format=tar -o $sourceTar HEAD
            if ($LASTEXITCODE -ne 0) {
                throw "Could not archive locked source: $($source.Path)"
            }
            tar -xf $sourceTar -C $stagedSource
            if ($LASTEXITCODE -ne 0) {
                throw "Could not extract locked source: $($source.Path)"
            }
            Remove-Item -LiteralPath $sourceTar -Force
        } elseif (-not (Test-Path -LiteralPath $stagedSource -PathType Container)) {
            throw "Expanded locked source tree was not staged: $($source.Path)"
        }
    }

    Write-Host 'Step 3/6: scrubbing local and game-derived artifacts...'
    $scrubDirectoryNames = @(
        '.git', '.audit', '.pytest_cache', '.release_validation', '.tmp', '__pycache__',
        'bsim', 'ghidraprojects', 'ghidrascripts', 'scripts_tmp', 'exes',
        'symbols', 'tools', 'release'
    )
    $directories = @(Get-ChildItem -LiteralPath $stagePath -Recurse -Directory -Force |
        Where-Object { $_.Name -in $scrubDirectoryNames } |
        Sort-Object { $_.FullName.Length } -Descending)
    foreach ($directory in $directories) {
        Remove-StagedDirectory $stagePath $directory.FullName
    }

    $localEvidenceDirectories = @(
        (Join-Path $stagePath 'extras\normalized'),
        (Join-Path $stagePath 'scripts\creationkit\refs\generated')
    )
    foreach ($directory in $localEvidenceDirectories) {
        Remove-StagedDirectory $stagePath $directory
    }

    $localEvidencePatterns = @(
        'ida-import-fallout4.zip', 'ida-import-fallout4-*.py',
        'IDAImportNames_*.py', '*_to_creationkit_*.csv*'
    )
    foreach ($pattern in $localEvidencePatterns) {
        $files = @(Get-ChildItem -LiteralPath $stagePath -Filter $pattern -File -Recurse -Force `
            -ErrorAction SilentlyContinue)
        foreach ($file in $files) { Remove-Item -LiteralPath $file.FullName -Force }
    }

    $binaryPatterns = @(
        '*.pdb', '*.relib', '*.rar', '*.7z', '*.exe', '*.dll', '*.pyc',
        '*.bgs-ed25519-private.pem', '.last_run_state', '*.last_*.log'
    )
    foreach ($pattern in $binaryPatterns) {
        $files = @(Get-ChildItem -LiteralPath $stagePath -Filter $pattern -File -Recurse -Force `
            -ErrorAction SilentlyContinue)
        foreach ($file in $files) { Remove-Item -LiteralPath $file.FullName -Force }
    }
    Get-ChildItem -LiteralPath $stagePath -File -Force |
        Where-Object { $_.Name -like '.last_*' -or $_.Name -like 'tmp_*' } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
    $gitmodules = Join-Path $stagePath '.gitmodules'
    if (Test-Path -LiteralPath $gitmodules) {
        Remove-Item -LiteralPath $gitmodules -Force
    }

    Write-Host 'Step 4/6: writing source provenance...'
    $sourceLines = @(
        "BethesdaGhidraScripts $Version",
        "Built locally: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ssK')",
        'Source repo: https://github.com/1001Bits/BethesdaGhidraScripts',
        'Upstream: https://github.com/doodlum/BethesdaGhidraScripts',
        "Source revision: $sourceRevision",
        '',
        'Lock-declared expanded source trees:'
    )
    $sourceLines += $submodules | ForEach-Object { "  $($_.Sha)  $($_.Path)" }
    $sourceLines | Set-Content -LiteralPath (Join-Path $stagePath 'SOURCES.txt') `
        -Encoding utf8NoBOM

    Write-Host 'Step 5/6: verifying licenses and writing content hashes...'
    $requiredLicenses = @(
        'LICENSE', 'NOTICE.md', 'extern/CommonLibSSE/LICENSE',
        'extern/CommonLibF4/LICENSE', 'extern/CommonLibSF/COPYING',
        'extern/CommonLibSF/EXCEPTIONS', 'extern/CommonLibVR/LICENSE',
        'extern/CommonLibF4VR/LICENSE', 'extern/DirectXMath/LICENSE',
        'extern/DirectXTK/LICENSE'
    )
    $missingLicenses = @($requiredLicenses | Where-Object {
        -not (Test-Path -LiteralPath (Join-Path $stagePath $_) -PathType Leaf)
    })
    if ($missingLicenses.Count) {
        throw "Bundle is missing required licenses: $($missingLicenses -join ', ')"
    }

    $contentsManifest = Join-Path $stagePath 'BUNDLE_CONTENTS.sha256'
    $manifestBuilder = Join-Path $RepoRoot 'scripts\build_content_manifest.py'
    & python $manifestBuilder --root $stagePath --output $contentsManifest
    if ($LASTEXITCODE -ne 0) {
        throw 'content-manifest generation failed'
    }

    Write-Host 'Step 6/6: creating local zip...'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $stagePath, $zipPath, [IO.Compression.CompressionLevel]::Optimal, $false)
    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$zipHash  $([IO.Path]::GetFileName($zipPath))" |
        Set-Content -LiteralPath $zipChecksumPath -Encoding ascii
    $stageSize = [Math]::Round(((Get-ChildItem -LiteralPath $stagePath -Recurse -File -Force |
        Measure-Object Length -Sum).Sum / 1MB), 1)
    $zipSize = [Math]::Round((Get-Item -LiteralPath $zipPath).Length / 1MB, 1)

    Write-Host '=== Local bundle complete ==='
    Write-Host "Stage size: $stageSize MB"
    Write-Host "Zip size: $zipSize MB"
    Write-Host "SHA-256: $zipHash"
    Write-Host "Zip: $zipPath"
    Write-Host "Checksum: $zipChecksumPath"
    Write-Host 'No files were published or uploaded.'
}
finally {
    Pop-Location
}
