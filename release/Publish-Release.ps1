<#
.SYNOPSIS
    Builds and publishes a Ducks in a Row release to the staging mirror or the
    public repo.

.DESCRIPTION
    Two phase flow, matching the three repo model (private dev, staging,
    public):

      -Stage staging (default)
        Builds the installers from the current commit, computes SHA256
        checksums, assembles a public safe source snapshot (only committed,
        tracked files, with the private-only paths in $ExcludePaths stripped),
        and publishes all of it to the private staging mirror
        (lethe377/Ducks-in-a-Row) as a tagged prerelease. Review and test the
        staging release before promoting it.

      -Stage public
        Re-uses the exact artifacts and source tree already published to
        staging for the given tag (never rebuilds), and publishes them
        unchanged to the public repo (haruspexsystems/Ducks-in-a-Row). This
        guarantees the public release is bit for bit what was verified on
        staging.

    Neither stage force-pushes or rewrites history. Each release is a normal
    fast-forward commit plus an annotated tag on the target repo's main branch.

    Known limitation: the "public" stage needs a gh session with write access
    to haruspexsystems/Ducks-in-a-Row. As of this writing the lethe377 account
    only has read access there, so this stage must be run under whichever
    account actually administers the Haruspex org. The script checks this and
    fails with a clear message rather than a confusing 404.

.PARAMETER Version
    The release version, e.g. "0.9.0-beta.1". Must satisfy semver
    (major.minor.patch with an optional -prerelease suffix). The git tag is
    "v$Version".

.PARAMETER Stage
    "staging" (default) or "public".

.PARAMETER SkipBuild
    Reuse the existing artifacts/ directory instead of running build.ps1
    again. Staging stage only; public stage never builds.

.PARAMETER DryRun
    Do everything except push to the target repo or create the GitHub
    release: build (unless -SkipBuild), checksum, assemble the snapshot, and
    print what would be published and where the temp snapshot can be
    inspected. Nothing is published to any repo.

.EXAMPLE
    ./release/Publish-Release.ps1 -Version 0.9.0-beta.1 -DryRun
    ./release/Publish-Release.ps1 -Version 0.9.0-beta.1
    ./release/Publish-Release.ps1 -Version 0.9.0-beta.1 -Stage public
#>

param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$')]
    [string]$Version,

    [ValidateSet("staging", "public")]
    [string]$Stage = "staging",

    [switch]$SkipBuild,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$StagingRepo = "lethe377/Ducks-in-a-Row"
$PublicRepo  = "haruspexsystems/Ducks-in-a-Row"
$Tag = "v$Version"
$TargetRepo = if ($Stage -eq "staging") { $StagingRepo } else { $PublicRepo }

# Tracked paths that must never leave the private dev repo: Claude Code
# tooling, internal workflow notes, the self-hosted CI workflow, and the
# Certus Flow pull script. Reviewed each release against `git ls-files`;
# anything gitignored (build output, graphify-out/, node_modules/, etc.) is
# already excluded by using `git archive`, which only ever contains committed,
# tracked content.
$ExcludePaths = @(
    ".claude",
    ".config",
    ".design-sync",
    ".github",
    ".vscode",
    ".graphifyignore",
    "CLAUDE.md",
    "CONTEXT.md",
    "REFERENCES.md",
    "scripts",
    "docs/ducksinarow-dashboard-delta.md"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Ducks in a Row Release Publisher" -ForegroundColor Cyan
Write-Host "  Version: $Version  Tag: $Tag" -ForegroundColor Cyan
Write-Host "  Stage: $Stage -> $TargetRepo" -ForegroundColor Cyan
if ($DryRun) { Write-Host "  DRY RUN — nothing will be pushed or published" -ForegroundColor Yellow }
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ScratchDir = Join-Path ([System.IO.Path]::GetTempPath()) "ducks-release-$Version-$Stage"
if (Test-Path $ScratchDir) { Remove-Item $ScratchDir -Recurse -Force }
New-Item -ItemType Directory -Path $ScratchDir -Force | Out-Null

function Read-BuildPropsVersionPrefix {
    $propsPath = Join-Path $RepoRoot "Directory.Build.props"
    [xml]$props = Get-Content $propsPath
    $prefix = $props.Project.PropertyGroup.VersionPrefix | Where-Object { $_ } | Select-Object -First 1
    if (-not $prefix) {
        Write-Host "  ERROR: VersionPrefix not found in $propsPath" -ForegroundColor Red
        exit 1
    }
    return $prefix
}

function Get-ChangelogUnreleasedNotes {
    $changelogPath = Join-Path $RepoRoot "CHANGELOG.md"
    $text = Get-Content $changelogPath -Raw
    $match = [regex]::Match($text, '(?ms)^## \[Unreleased\]\s*\r?\n(.*?)(?=^## \[|\z)')
    if (-not $match.Success) {
        Write-Host "  WARNING: could not extract an Unreleased section from CHANGELOG.md; using a placeholder release body." -ForegroundColor Yellow
        return "See CHANGELOG.md."
    }
    return $match.Groups[1].Value.Trim()
}

# ---------------------------------------------------------------------------
# Stage: staging — build, checksum, snapshot, publish
# ---------------------------------------------------------------------------
if ($Stage -eq "staging") {

    Write-Host "[1/6] Preflight checks..." -ForegroundColor Yellow

    $gitStatus = git -C $RepoRoot status --porcelain
    if ($gitStatus) {
        Write-Host "  ERROR: working tree is not clean. Commit or stash changes before cutting a release." -ForegroundColor Red
        exit 1
    }

    $branch = git -C $RepoRoot rev-parse --abbrev-ref HEAD
    if ($branch -ne "main") {
        Write-Host "  ERROR: not on main (currently on '$branch'). Releases are cut from main." -ForegroundColor Red
        exit 1
    }

    git -C $RepoRoot fetch origin --quiet
    $behind = git -C $RepoRoot rev-list --count HEAD..origin/main
    if ($behind -gt 0) {
        Write-Host "  ERROR: local main is $behind commit(s) behind origin/main. Pull first." -ForegroundColor Red
        exit 1
    }

    $versionPrefix = Read-BuildPropsVersionPrefix
    $expectedPrefix = $Version -replace '-.*$', ''
    if ($versionPrefix -ne $expectedPrefix) {
        Write-Host "  ERROR: Directory.Build.props VersionPrefix is '$versionPrefix', but -Version $Version expects '$expectedPrefix'." -ForegroundColor Red
        Write-Host "         Bump VersionPrefix to '$expectedPrefix' in Directory.Build.props via its own commit, ship it, then re-run this script." -ForegroundColor Red
        exit 1
    }
    Write-Host "  VersionPrefix matches ($versionPrefix)" -ForegroundColor Green

    $pushPermission = gh api "repos/$StagingRepo" --jq ".permissions.push" 2>&1
    if ($pushPermission -ne "true") {
        Write-Host "  ERROR: the authenticated gh session does not have push access to $StagingRepo." -ForegroundColor Red
        exit 1
    }

    $existingTag = git -C $RepoRoot ls-remote --tags "https://github.com/$StagingRepo.git" "refs/tags/$Tag"
    if ($existingTag) {
        Write-Host "  ERROR: tag $Tag already exists on $StagingRepo. Bump -Version or delete the existing tag first." -ForegroundColor Red
        exit 1
    }
    Write-Host "  Preflight OK" -ForegroundColor Green
    Write-Host ""

    if (-not $SkipBuild) {
        Write-Host "[2/6] Building installers (./build.ps1)..." -ForegroundColor Yellow
        Push-Location $RepoRoot
        try {
            & "$RepoRoot/build.ps1" -Configuration Release
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  ERROR: build.ps1 failed." -ForegroundColor Red
                exit 1
            }
        } finally {
            Pop-Location
        }
    } else {
        Write-Host "[2/6] Skipping build (-SkipBuild)" -ForegroundColor DarkGray
    }

    $MsiPath = Join-Path $RepoRoot "artifacts/Ducks-in-a-Row.msi"
    $SetupPath = Join-Path $RepoRoot "artifacts/Ducks-in-a-Row-Setup.exe"
    foreach ($p in @($MsiPath, $SetupPath)) {
        if (-not (Test-Path $p)) {
            Write-Host "  ERROR: expected artifact missing: $p" -ForegroundColor Red
            exit 1
        }
    }
    Write-Host ""

    Write-Host "[3/6] Computing checksums..." -ForegroundColor Yellow
    $sumsPath = Join-Path $RepoRoot "artifacts/SHA256SUMS"
    $lines = foreach ($p in @($MsiPath, $SetupPath)) {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $p).Hash.ToLowerInvariant()
        "$hash  $(Split-Path -Leaf $p)"
    }
    $lines | Out-File -FilePath $sumsPath -Encoding ASCII
    $lines | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    Write-Host ""

    Write-Host "[4/6] Assembling the public source snapshot..." -ForegroundColor Yellow
    $snapshotZip = Join-Path $ScratchDir "source.zip"
    $snapshotDir = Join-Path $ScratchDir "snapshot"
    git -C $RepoRoot archive --format=zip -o $snapshotZip HEAD
    Expand-Archive -Path $snapshotZip -DestinationPath $snapshotDir -Force
    foreach ($rel in $ExcludePaths) {
        $target = Join-Path $snapshotDir $rel
        if (Test-Path $target) {
            Remove-Item $target -Recurse -Force
            Write-Host "  excluded $rel" -ForegroundColor DarkGray
        }
    }
    Write-Host "  Snapshot assembled at $snapshotDir" -ForegroundColor Green
    Write-Host ""

    if ($DryRun) {
        Write-Host "[5/6] Dry run — skipping publish." -ForegroundColor Yellow
        Write-Host "  Inspect the snapshot at: $snapshotDir" -ForegroundColor Gray
        Write-Host "  Artifacts: $MsiPath, $SetupPath, $sumsPath" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Dry run complete. Nothing was published." -ForegroundColor Cyan
        exit 0
    }

    Write-Host "[5/6] Publishing source snapshot to $StagingRepo..." -ForegroundColor Yellow
    $cloneDir = Join-Path $ScratchDir "clone"
    git clone --quiet "https://github.com/$StagingRepo.git" $cloneDir

    Get-ChildItem $cloneDir -Force | Where-Object { $_.Name -ne ".git" } | Remove-Item -Recurse -Force
    Copy-Item "$snapshotDir/*" $cloneDir -Recurse -Force

    Push-Location $cloneDir
    try {
        git add -A
        $hasChanges = git status --porcelain
        if (-not $hasChanges) {
            Write-Host "  ERROR: snapshot is identical to what is already on $StagingRepo. Nothing to release." -ForegroundColor Red
            exit 1
        }
        git commit --quiet -m "Ducks in a Row $Version"
        git tag -a $Tag -m "Ducks in a Row $Version"
        git push --quiet origin main
        git push --quiet origin $Tag
    } finally {
        Pop-Location
    }
    Write-Host "  Pushed main and tag $Tag to $StagingRepo" -ForegroundColor Green
    Write-Host ""

    Write-Host "[6/6] Creating the GitHub prerelease on $StagingRepo..." -ForegroundColor Yellow
    $notes = Get-ChangelogUnreleasedNotes
    $notesPath = Join-Path $ScratchDir "release-notes.md"
    $notes | Out-File -FilePath $notesPath -Encoding UTF8

    gh release create $Tag $MsiPath $SetupPath $sumsPath `
        --repo $StagingRepo `
        --title "Ducks in a Row $Version" `
        --notes-file $notesPath `
        --prerelease

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Staging release published" -ForegroundColor Green
    Write-Host "  https://github.com/$StagingRepo/releases/tag/$Tag" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Review and test it, then run:" -ForegroundColor Gray
    Write-Host "  ./release/Publish-Release.ps1 -Version $Version -Stage public" -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# Stage: public — reuse staging's verified artifacts and tree, publish as is
# ---------------------------------------------------------------------------
else {

    Write-Host "[1/4] Preflight checks..." -ForegroundColor Yellow

    $pushPermission = gh api "repos/$PublicRepo" --jq ".permissions.push" 2>&1
    if ($pushPermission -ne "true") {
        Write-Host "  ERROR: the authenticated gh session does not have push access to $PublicRepo." -ForegroundColor Red
        Write-Host "         Run this stage from a session signed in as whichever account administers" -ForegroundColor Red
        Write-Host "         the haruspexsystems GitHub org, or grant this account write access first." -ForegroundColor Red
        exit 1
    }

    $stagingRelease = gh release view $Tag --repo $StagingRepo --json tagName 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERROR: no release for tag $Tag found on $StagingRepo. Run the staging stage first." -ForegroundColor Red
        exit 1
    }

    $existingTag = git ls-remote --tags "https://github.com/$PublicRepo.git" "refs/tags/$Tag"
    if ($existingTag) {
        Write-Host "  ERROR: tag $Tag already exists on $PublicRepo." -ForegroundColor Red
        exit 1
    }
    Write-Host "  Preflight OK" -ForegroundColor Green
    Write-Host ""

    Write-Host "[2/4] Downloading the verified release assets from $StagingRepo..." -ForegroundColor Yellow
    $assetsDir = Join-Path $ScratchDir "assets"
    New-Item -ItemType Directory -Path $assetsDir -Force | Out-Null
    gh release download $Tag --repo $StagingRepo --dir $assetsDir
    $assetFiles = Get-ChildItem $assetsDir -File
    Write-Host "  Downloaded: $($assetFiles.Name -join ', ')" -ForegroundColor Gray
    Write-Host ""

    Write-Host "[3/4] Publishing the verified source tree to $PublicRepo..." -ForegroundColor Yellow
    $cloneDir = Join-Path $ScratchDir "clone"
    git clone --quiet "https://github.com/$PublicRepo.git" $cloneDir

    $stagingTreeDir = Join-Path $ScratchDir "staging-tree"
    git clone --quiet --branch $Tag --depth 1 "https://github.com/$StagingRepo.git" $stagingTreeDir

    Get-ChildItem $cloneDir -Force | Where-Object { $_.Name -ne ".git" } | Remove-Item -Recurse -Force
    Get-ChildItem $stagingTreeDir -Force | Where-Object { $_.Name -ne ".git" } | Copy-Item -Destination $cloneDir -Recurse -Force

    if ($DryRun) {
        Write-Host "[4/4] Dry run — skipping publish." -ForegroundColor Yellow
        Write-Host "  Tree staged at: $cloneDir" -ForegroundColor Gray
        Write-Host "  Assets staged at: $assetsDir" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Dry run complete. Nothing was published." -ForegroundColor Cyan
        exit 0
    }

    Push-Location $cloneDir
    try {
        git add -A
        $hasChanges = git status --porcelain
        if (-not $hasChanges) {
            Write-Host "  ERROR: tree is identical to what is already on $PublicRepo. Nothing to release." -ForegroundColor Red
            exit 1
        }
        git commit --quiet -m "Ducks in a Row $Version"
        git tag -a $Tag -m "Ducks in a Row $Version"
        git push --quiet origin main
        git push --quiet origin $Tag
    } finally {
        Pop-Location
    }
    Write-Host "  Pushed main and tag $Tag to $PublicRepo" -ForegroundColor Green
    Write-Host ""

    Write-Host "[4/4] Creating the GitHub prerelease on $PublicRepo..." -ForegroundColor Yellow
    $stagingNotes = gh release view $Tag --repo $StagingRepo --json body --jq ".body"
    $notesPath = Join-Path $ScratchDir "release-notes.md"
    $stagingNotes | Out-File -FilePath $notesPath -Encoding UTF8

    gh release create $Tag @($assetFiles.FullName) `
        --repo $PublicRepo `
        --title "Ducks in a Row $Version" `
        --notes-file $notesPath `
        --prerelease

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Public release published" -ForegroundColor Green
    Write-Host "  https://github.com/$PublicRepo/releases/tag/$Tag" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
}
