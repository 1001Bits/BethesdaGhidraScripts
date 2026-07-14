<#
.SYNOPSIS
    Build a self-contained source bundle for GitHub releases.

.DESCRIPTION
    Produces a zip containing:
      - The current commit of BethesdaGhidraScripts (HEAD)
      - All submodules expanded in-tree at their pinned commits
      - Pre-built address-library files (publicly distributed)
      - All third-party LICENSE / COPYING / EXCEPTIONS files preserved
      - Top-level LICENSE (GPL v3) and NOTICE.md

    Excludes:
      - .git / .gitmodules (replaced by a SOURCES.txt manifest)
      - Local build/analysis artifacts (.audit/, .last_*.log, __pycache__,
        bsim/, ghidraprojects/, exes/, tools/)
      - Anything that looks like a game-derived binary (*.exe, *.dll, *.pdb,
        *.relib, *.rar) — users supply these from their own install.

.PARAMETER OutputDir
    Directory to write the zip into. Defaults to release/ at repo root.

.PARAMETER Version
    Version tag to embed in the bundle filename. Defaults to
    "v$(Get-Date -Format yyyy.MM.dd)" plus the short SHA.

.EXAMPLE
    pwsh .\scripts\build_release_bundle.ps1

.EXAMPLE
    pwsh .\scripts\build_release_bundle.ps1 -Version v0.2.0
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [string]$Version   = ""
)

$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if (-not $OutputDir) {
    $OutputDir = Join-Path $RepoRoot 'release'
}
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

Push-Location $RepoRoot
try {
    $sha = (git rev-parse --short HEAD).Trim()
    if (-not $Version) {
        $date = Get-Date -Format 'yyyy.MM.dd'
        $Version = "v$date-$sha"
    }

    $stageName = "BethesdaGhidraScripts-$Version"
    $stagePath = Join-Path $OutputDir $stageName
    $zipPath   = Join-Path $OutputDir "$stageName.zip"

    if (Test-Path $stagePath) {
        Write-Host "Removing previous stage: $stagePath"
        Remove-Item -Recurse -Force $stagePath
    }
    if (Test-Path $zipPath) {
        Write-Host "Removing previous zip: $zipPath"
        Remove-Item -Force $zipPath
    }

    Write-Host ""
    Write-Host "=== Building bundle $Version ==="
    Write-Host "Repo root:  $RepoRoot"
    Write-Host "Stage path: $stagePath"
    Write-Host "Zip path:   $zipPath"
    Write-Host ""

    # 1. git archive of HEAD into stage (respects .gitattributes export-ignore)
    Write-Host "Step 1/6: git archive HEAD..."
    New-Item -ItemType Directory -Path $stagePath | Out-Null
    $tarPath = Join-Path $env:TEMP "bgs-stage-$sha.tar"
    git archive --format=tar -o $tarPath HEAD
    tar -xf $tarPath -C $stagePath
    Remove-Item $tarPath

    # 2. Submodule archives, expanded under their original paths
    Write-Host "Step 2/6: archiving submodules..."
    $submodules = git submodule status | ForEach-Object {
        $line = $_.Trim()
        # format: [+|-]<sha> <path> [(branch)]
        if ($line -match '^[+\-U ]?([0-9a-f]+)\s+(\S+)') {
            [PSCustomObject]@{ Sha = $matches[1]; Path = $matches[2] }
        }
    }
    foreach ($sm in $submodules) {
        $smAbs = Join-Path $RepoRoot $sm.Path
        $smOut = Join-Path $stagePath $sm.Path
        if (-not (Test-Path $smAbs)) {
            Write-Warning "  Submodule $($sm.Path) not initialized — skipping."
            continue
        }
        Write-Host "  - $($sm.Path) @ $($sm.Sha.Substring(0,7))"
        if (-not (Test-Path $smOut)) {
            New-Item -ItemType Directory -Path $smOut | Out-Null
        }
        $smTar = Join-Path $env:TEMP "bgs-sm-$($sm.Sha.Substring(0,7)).tar"
        Push-Location $smAbs
        try {
            git archive --format=tar -o $smTar HEAD
        } finally {
            Pop-Location
        }
        tar -xf $smTar -C $smOut
        Remove-Item $smTar
    }

    # 3. Scrub anything that snuck through git-archive (in case .gitattributes
    #    isn't set up). git archive already respects export-ignore, but we
    #    belt-and-suspenders these directories in case any are tracked.
    Write-Host "Step 3/6: scrubbing development artifacts..."
    $scrubDirs = @(
        '.audit', '__pycache__', 'bsim', 'ghidraprojects', 'exes', 'tools',
        'release'
    )
    foreach ($d in $scrubDirs) {
        Get-ChildItem -Path $stagePath -Filter $d -Recurse -Directory `
            -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "  rm dir  $($_.FullName.Substring($stagePath.Length + 1))"
            Remove-Item -Recurse -Force $_.FullName
        }
    }

    $scrubPatterns = @(
        '*.last_*.log', '.last_run_state',
        '*.pdb', '*.relib', '*.rar', '*.exe', '*.dll'
    )
    foreach ($p in $scrubPatterns) {
        Get-ChildItem -Path $stagePath -Filter $p -Recurse -File `
            -ErrorAction SilentlyContinue | ForEach-Object {
            $rel = $_.FullName.Substring($stagePath.Length + 1)
            # Leave LLVM / Ghidra-related files in submodule tree alone if they
            # are licensed text. In practice none of these submodules ship .pdb
            # / .exe / .dll / .relib / .rar, so the blanket scrub is safe.
            Write-Host "  rm file $rel"
            Remove-Item -Force $_.FullName
        }
    }

    # Also drop our own .last_*.log files (literal prefix match)
    Get-ChildItem -Path $stagePath -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '.last_*' } | ForEach-Object {
        Write-Host "  rm file $($_.Name)"
        Remove-Item -Force $_.FullName
    }

    # 4. SOURCES.txt: pinned submodule SHAs so users can verify provenance.
    Write-Host "Step 4/6: writing SOURCES.txt..."
    $sourcesPath = Join-Path $stagePath 'SOURCES.txt'
    $headerLines = @(
        "BethesdaGhidraScripts $Version",
        "Built: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ssK')",
        "Source repo:  https://github.com/1001Bits/BethesdaGhidraScripts",
        "Upstream:     https://github.com/doodlum/BethesdaGhidraScripts",
        "",
        "HEAD commit:  $(git rev-parse HEAD)",
        "",
        "Submodules (pinned commits):"
    )
    $smLines = $submodules | ForEach-Object { "  $($_.Sha)  $($_.Path)" }
    ($headerLines + $smLines) | Set-Content -Path $sourcesPath -Encoding UTF8

    # 5. Verify license files are present in the bundle
    Write-Host "Step 5/6: verifying license files..."
    $expectedLicenses = @(
        'LICENSE',
        'NOTICE.md',
        'extern/CommonLibSSE/LICENSE',
        'extern/CommonLibF4/LICENSE',
        'extern/CommonLibSF/COPYING',
        'extern/CommonLibSF/EXCEPTIONS',
        'extern/CommonLibVR/LICENSE',
        'extern/CommonLibF4VR/LICENSE',
        'extern/DirectXMath/LICENSE',
        'extern/DirectXTK/LICENSE'
    )
    $missing = @()
    foreach ($l in $expectedLicenses) {
        $full = Join-Path $stagePath $l
        if (-not (Test-Path $full)) {
            $missing += $l
        }
    }
    if ($missing.Count -gt 0) {
        Write-Host ""
        Write-Host "ERROR: missing license files in bundle:" -ForegroundColor Red
        $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        throw "Bundle missing required license files. Refusing to package."
    }
    Write-Host "  All required licenses present."

    # 6. Zip
    Write-Host "Step 6/6: zipping..."
    Compress-Archive -Path (Join-Path $stagePath '*') `
                     -DestinationPath $zipPath -CompressionLevel Optimal

    $stageSizeMB = [Math]::Round(
        ((Get-ChildItem -Path $stagePath -Recurse -File |
          Measure-Object -Property Length -Sum).Sum / 1MB), 1)
    $zipSizeMB = [Math]::Round((Get-Item $zipPath).Length / 1MB, 1)

    Write-Host ""
    Write-Host "=== Bundle complete ==="
    Write-Host "Stage size: $stageSizeMB MB"
    Write-Host "Zip size:   $zipSizeMB MB"
    Write-Host "Zip path:   $zipPath"
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Review SOURCES.txt inside the zip."
    Write-Host "  2. Test in a clean working dir:"
    Write-Host "       Expand-Archive '$zipPath' -DestinationPath C:\tmp\bgs-test"
    Write-Host "       cd C:\tmp\bgs-test && python run.py"
    Write-Host "  3. Upload to GitHub releases:"
    Write-Host "       gh release create $Version '$zipPath' --title '$Version' --notes 'See CHANGELOG'"
}
finally {
    Pop-Location
}
