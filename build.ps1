<#
.SYNOPSIS
    Builds the Certus installer package.

.DESCRIPTION
    This script:
    1. Builds the React frontend (npm run build → wwwroot)
    2. Publishes the .NET Service project
    3. Optionally builds the WiX MSI installer
    4. Optionally wraps the MSI in the Burn setup bundle, which embeds the
       ASP.NET Core Hosting Bundle so a clean offline server installs with
       one file (issue #87)

.PARAMETER Configuration
    Build configuration. Default: Release

.PARAMETER SkipFrontend
    Skip the frontend build (useful if node/npm not installed)

.PARAMETER SkipMsi
    Skip the MSI build (useful if WiX not installed)

.PARAMETER SkipBundle
    Skip the setup bundle build (the MSI is still built). The bundle build
    downloads the pinned ASP.NET Core Hosting Bundle (about 100 MB) on first
    run and caches it in installer/redist. -SkipMsi implies -SkipBundle
    because the bundle wraps the MSI.

.PARAMETER Runtime
    Target runtime identifier. Default: win-x64

.EXAMPLE
    .\build.ps1
    .\build.ps1 -SkipFrontend -SkipMsi
    .\build.ps1 -Configuration Debug
#>

param(
    [string]$Configuration = "Release",
    [switch]$SkipFrontend,
    [switch]$SkipMsi,
    [switch]$SkipBundle,
    [switch]$IncludeTests,
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"

# Captured at script entry. Used by the stale artifact assertion below to
# decide whether the publish output is genuinely fresh or whether the compile
# silently no-opped and we are about to package last week's DLLs again.
$BuildStartUtc = (Get-Date).ToUniversalTime()

$RepoRoot = $PSScriptRoot
$FrontendDir = Join-Path $RepoRoot "src/frontend"
$ServiceProject = Join-Path $RepoRoot "src/Certus.Service/Certus.Service.csproj"
$WwwrootDir = Join-Path $RepoRoot "src/Certus.Web/wwwroot"
$PublishDir = Join-Path $RepoRoot "artifacts/publish"
$InstallerDir = Join-Path $RepoRoot "installer"

# ---- Setup bundle payload pin (issue #87) -----------------------------------
# The bootstrapper embeds the ASP.NET Core Hosting Bundle so installs work on
# an offline server. The exe is about 100 MB and is never committed to git: it
# is pinned to an exact version and SHA-512 here, downloaded on demand, and
# cached in installer/redist (gitignored) so later builds reuse it. Always
# bump the version and the hash together; the published hash for each release
# is in https://builds.dotnet.microsoft.com/dotnet/release-metadata/8.0/releases.json
$HostingBundleVersion = "8.0.28"
$HostingBundleSha512 = "b192a0a73c5fc5c3ea5f3d8ab05020261b456cd34c692558fe996d8c2fd1ffe31dbb3a53d815fae863a1c2586ada77ffea01cfa935f7bbe2983741940cecc692"
$HostingBundleUrl = "https://builds.dotnet.microsoft.com/dotnet/aspnetcore/Runtime/$HostingBundleVersion/dotnet-hosting-$HostingBundleVersion-win.exe"
$RedistDir = Join-Path $InstallerDir "redist"
$HostingBundleExe = Join-Path $RedistDir "dotnet-hosting-$HostingBundleVersion-win.exe"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Certus Build Script" -ForegroundColor Cyan
Write-Host "  Configuration: $Configuration" -ForegroundColor Cyan
Write-Host "  Runtime: $Runtime" -ForegroundColor Cyan
Write-Host "  Started: $($BuildStartUtc.ToString('o'))" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 0: Clean bin/obj to force a full rebuild
# MSBuild's incremental up-to-date check has misfired in the QA pipeline,
# causing stale DLLs from earlier commits to be re-packaged into every MSI.
# Removing bin/obj eliminates that class of failure at the cost of one
# extra full compile per run.
Write-Host "[0/5] Cleaning bin/obj directories..." -ForegroundColor Yellow
$cleanRoots = @(
    (Join-Path $RepoRoot "src"),
    (Join-Path $RepoRoot "tests")
)
foreach ($root in $cleanRoots) {
    if (Test-Path $root) {
        # NOTE: deliberately no -ErrorAction SilentlyContinue here. A locked
        # file or permission denial in the QA pipeline was previously swallowed,
        # leaving stale DLLs in bin/ that the next publish then re-packaged
        # into a fresh MSI. Surface the failure instead.
        Get-ChildItem -Path $root -Recurse -Directory -Force |
            Where-Object { $_.Name -in 'bin','obj' } |
            ForEach-Object { Remove-Item $_.FullName -Recurse -Force }
    }
}
Write-Host "  bin/obj cleaned" -ForegroundColor Green
Write-Host ""

# Step 1: Build frontend
if (-not $SkipFrontend) {
    Write-Host "[1/5] Building React frontend..." -ForegroundColor Yellow

    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        Write-Host "  npm not found — skipping frontend build" -ForegroundColor DarkYellow
        Write-Host "  Install Node.js and run 'npm install' in src/frontend first" -ForegroundColor DarkYellow
    } else {
        Push-Location $FrontendDir
        try {
            npm ci --silent
            npm run build

            # Validate that the build produced output
            $indexHtml = Join-Path $WwwrootDir "index.html"
            if (-not (Test-Path $indexHtml)) {
                Write-Host "  ERROR: npm run build did not produce wwwroot/index.html" -ForegroundColor Red
                exit 1
            }
            Write-Host "  Frontend built → $WwwrootDir" -ForegroundColor Green
        } finally {
            Pop-Location
        }
    }
} else {
    Write-Host "[1/5] Skipping frontend build (--SkipFrontend)" -ForegroundColor DarkGray
}

# Step 2: Publish .NET Service
Write-Host ""
Write-Host "[2/5] Publishing Certus.Service..." -ForegroundColor Yellow

# Clean previous publish
if (Test-Path $PublishDir) {
    Remove-Item $PublishDir -Recurse -Force
}

# Force a clean restore. A stale obj/project.assets.json or a silent NU1902
# vulnerability error has previously presented as a successful publish that
# ships nothing new. Capture the restore output to a log so the next failure
# is diagnosable from a single artifact.
Write-Host "  Restoring NuGet packages (force, no-cache)..." -ForegroundColor Gray
$ArtifactsDir = Join-Path $RepoRoot "artifacts"
if (-not (Test-Path $ArtifactsDir)) {
    New-Item -Path $ArtifactsDir -ItemType Directory -Force | Out-Null
}
$restoreLog = Join-Path $ArtifactsDir "restore.log"
dotnet restore $ServiceProject --force --no-cache 2>&1 | Tee-Object -FilePath $restoreLog | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Restore failed! See $restoreLog" -ForegroundColor Red
    exit 1
}
Write-Host "  Restore complete (log: $restoreLog)" -ForegroundColor Green

dotnet publish $ServiceProject `
    -c $Configuration `
    -r $Runtime `
    --self-contained false `
    -o $PublishDir `
    /p:PublishReadyToRun=true

if ($LASTEXITCODE -ne 0) {
    Write-Host "  Publish failed!" -ForegroundColor Red
    exit 1
}

# Diagnostic: log the LastWriteTimeUtc of Certus.Adcs.dll inside the project's
# bin/ directory. If this is older than the build start, the compiler itself
# was a no-op and the cleanup in step 0 did not reach this folder.
$adcsBinDll = Join-Path $RepoRoot "src/Certus.Adcs/bin/$Configuration/net8.0-windows/Certus.Adcs.dll"
if (Test-Path $adcsBinDll) {
    $adcsBin = Get-Item $adcsBinDll
    Write-Host "  src/Certus.Adcs/bin Certus.Adcs.dll LastWriteUtc: $($adcsBin.LastWriteTimeUtc.ToString('o'))" -ForegroundColor Gray
} else {
    Write-Host "  WARNING: $adcsBinDll not found after publish" -ForegroundColor Yellow
}

# Stale artifact assertion. If the publish output is older than the build
# start (with 60 seconds of slack for clock skew), the publish quietly shipped
# last week's binary inside a fresh MSI. Fail loudly so the QA pipeline does
# not waste another cycle testing a stale deploy.
$svcDll = Join-Path $PublishDir "DucksInARow.Service.dll"
if (-not (Test-Path $svcDll)) {
    Write-Host "  ERROR: $svcDll missing after publish." -ForegroundColor Red
    exit 1
}
$svc = Get-Item $svcDll
$cutoff = $BuildStartUtc.AddSeconds(-60)
Write-Host "  artifacts/publish DucksInARow.Service.dll LastWriteUtc: $($svc.LastWriteTimeUtc.ToString('o'))" -ForegroundColor Gray
if ($svc.LastWriteTimeUtc -lt $cutoff) {
    Write-Host "  ERROR: Stale DucksInARow.Service.dll in publish output." -ForegroundColor Red
    Write-Host "         LastWriteUtc:  $($svc.LastWriteTimeUtc.ToString('o'))" -ForegroundColor Red
    Write-Host "         Build started: $($BuildStartUtc.ToString('o'))" -ForegroundColor Red
    Write-Host "         The clean step did not take effect or the compile was a no-op." -ForegroundColor Red
    exit 1
}

# Copy wwwroot into publish output if it exists
if (Test-Path $WwwrootDir) {
    $publishWwwroot = Join-Path $PublishDir "wwwroot"
    if (-not (Test-Path $publishWwwroot)) {
        New-Item -Path $publishWwwroot -ItemType Directory | Out-Null
    }
    Copy-Item "$WwwrootDir\*" $publishWwwroot -Recurse -Force
    Write-Host "  wwwroot copied to publish output" -ForegroundColor Green
}

# Hard guard: the published payload must contain wwwroot/index.html, otherwise
# the SPA returns 404 in production (issue #8 item 2).
$publishedIndex = Join-Path $PublishDir "wwwroot/index.html"
if (-not (Test-Path $publishedIndex)) {
    Write-Host "  ERROR: $publishedIndex is missing." -ForegroundColor Red
    Write-Host "  The frontend build was skipped or produced no output." -ForegroundColor Red
    Write-Host "  Run 'npm install' and 'npm run build' in src/frontend, then re-run build.ps1." -ForegroundColor Red
    exit 1
}

Write-Host "  Published → $PublishDir" -ForegroundColor Green

# Step 3: Build MSI
if (-not $SkipMsi) {
    Write-Host ""
    Write-Host "[3/5] Building MSI installer..." -ForegroundColor Yellow

    if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
        Write-Host "  WiX Toolset not found — skipping MSI build" -ForegroundColor DarkYellow
        Write-Host "  Install: dotnet tool install --global wix" -ForegroundColor DarkYellow
    } else {
        $MsiOutput = Join-Path $RepoRoot "artifacts/Ducks-in-a-Row.msi"
        $WxsFile = Join-Path $InstallerDir "Certus.wxs"
        $UiWxsFile = Join-Path $InstallerDir "CertusUi.wxs"
        $HarvestWxs = Join-Path $InstallerDir "PublishFiles.wxs"
        $BrandingDir = Join-Path $InstallerDir "branding"

        # Ensure the WiX extensions the authoring needs are installed globally.
        # Firewall: service firewall rules. UI: the install wizard dialog set.
        # Util: the InternetShortcut and the completion-screen browser launch.
        $requiredExtensions = @(
            "WixToolset.Firewall.wixext",
            "WixToolset.UI.wixext",
            "WixToolset.Util.wixext"
        )
        if (-not $SkipBundle) {
            # Bal: the bundle bootstrapper application (WixStdBA).
            # Netfx: DotNetCoreSearch for the runtime detect condition.
            $requiredExtensions += "WixToolset.Bal.wixext"
            $requiredExtensions += "WixToolset.Netfx.wixext"
        }
        # Pin every extension to the CLI's own version. An unpinned add pulls
        # the newest NuGet package, which an older wix CLI refuses to load and
        # reports as "damaged"; a stray newer version also wins the unversioned
        # -ext lookup and breaks the build the same way, so a wrong version
        # install is removed before the pinned add.
        $wixVersion = ((wix --version) -split '\+')[0]
        $installedExtensions = (wix extension list --global 2>$null) -join "`n"
        foreach ($ext in $requiredExtensions) {
            if ($installedExtensions -match "$([regex]::Escape($ext)) $([regex]::Escape($wixVersion))") {
                continue
            }
            if ($installedExtensions -match "$([regex]::Escape($ext)) ") {
                Write-Host "  Removing wrong version WiX extension $ext ..." -ForegroundColor DarkYellow
                wix extension remove $ext --global
                if ($LASTEXITCODE -ne 0) {
                    Write-Host "  Failed to remove WiX extension $ext" -ForegroundColor Red
                    exit 1
                }
            }
            Write-Host "  Adding WiX extension $ext $wixVersion ..." -ForegroundColor Gray
            wix extension add "$ext/$wixVersion" --global
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  Failed to add WiX extension $ext" -ForegroundColor Red
                exit 1
            }
        }

        # Generate PublishFiles.wxs from the publish output (recursive)
        # Lists every file except DucksInARow.Service.exe (handled by ServiceComponent)
        Write-Host "  Generating file manifest from publish output..." -ForegroundColor Gray
        $xmlLines = @()
        $xmlLines += '<?xml version="1.0" encoding="UTF-8"?>'
        $xmlLines += '<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">'
        $xmlLines += '  <Fragment>'

        # Declare subdirectories so WiX knows where to place files
        $subdirs = Get-ChildItem $PublishDir -Directory -Recurse
        foreach ($dir in $subdirs) {
            $relativePath = $dir.FullName.Substring($PublishDir.Length + 1)
            $dirId = "Dir_" + ($relativePath -replace '[^a-zA-Z0-9_]', '_')
            $parentRelative = Split-Path $relativePath -Parent
            $parentId = if ([string]::IsNullOrEmpty($parentRelative)) {
                "INSTALLFOLDER"
            } else {
                "Dir_" + ($parentRelative -replace '[^a-zA-Z0-9_]', '_')
            }
            $xmlLines += "    <DirectoryRef Id=`"$parentId`">"
            $xmlLines += "      <Directory Id=`"$dirId`" Name=`"$($dir.Name)`" />"
            $xmlLines += "    </DirectoryRef>"
        }

        $xmlLines += '    <ComponentGroup Id="PublishFiles" Directory="INSTALLFOLDER">'

        # Add all files recursively. Exclude DucksInARow.Service.exe (handled by
        # ServiceComponent) and every .pdb. Packaging the symbol files installs
        # them next to their DLLs, where the CLR reads them and prints the build
        # host's absolute source path in customer logs (issue #104). PDBs stay
        # in artifacts/publish for local debugging; they just never ship.
        $allFiles = Get-ChildItem $PublishDir -File -Recurse | Where-Object { $_.Name -ne "DucksInARow.Service.exe" -and $_.Extension -ne ".pdb" }
        $fileCount = 0
        foreach ($file in $allFiles) {
            $relativePath = $file.FullName.Substring($PublishDir.Length + 1)
            $relativeDir = Split-Path $relativePath -Parent
            $safeId = "File_" + ($relativePath -replace '[^a-zA-Z0-9_]', '_')
            $dirRef = if ([string]::IsNullOrEmpty($relativeDir)) {
                "INSTALLFOLDER"
            } else {
                "Dir_" + ($relativeDir -replace '[^a-zA-Z0-9_]', '_')
            }
            $xmlLines += "      <Component Directory=`"$dirRef`">"
            $xmlLines += "        <File Id=`"$safeId`" Source=`"$relativePath`" />"
            $xmlLines += "      </Component>"
            $fileCount++
        }

        $xmlLines += '    </ComponentGroup>'
        $xmlLines += '  </Fragment>'
        $xmlLines += '</Wix>'

        # Hard guard: no .pdb may ever reach the MSI file manifest (issue #104).
        # If the harvest filter above regresses, fail loudly rather than ship a
        # symbol file that leaks the build host's source path.
        if ($xmlLines -match '\.pdb') {
            Write-Host "  ERROR: PDB file entered the MSI file manifest. The harvest filter regressed." -ForegroundColor Red
            exit 1
        }

        $xmlLines | Out-File -FilePath $HarvestWxs -Encoding UTF8
        Write-Host "  Generated $fileCount file entries ($($subdirs.Count) directories)" -ForegroundColor Gray

        # The MSI ProductVersion comes from the shared VersionPrefix in
        # Directory.Build.props, so the installer can never drift from the
        # assemblies it ships. The fourth field stays 0 (MSI ignores it for
        # upgrade detection anyway).
        $buildProps = [xml](Get-Content (Join-Path $RepoRoot "Directory.Build.props"))
        $versionPrefix = $buildProps.Project.PropertyGroup.VersionPrefix | Where-Object { $_ } | Select-Object -First 1
        if (-not $versionPrefix) {
            Write-Host "  ERROR: VersionPrefix not found in Directory.Build.props" -ForegroundColor Red
            exit 1
        }
        $productVersion = "$versionPrefix.0"
        Write-Host "  MSI ProductVersion: $productVersion" -ForegroundColor Gray

        wix build $WxsFile $UiWxsFile $HarvestWxs -d "ProductVersion=$productVersion" -o $MsiOutput -bindpath $PublishDir -bindpath $BrandingDir -ext WixToolset.Firewall.wixext -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext -arch x64

        if ($LASTEXITCODE -ne 0) {
            Write-Host "  MSI build failed!" -ForegroundColor Red
            if (Test-Path $HarvestWxs) { Remove-Item $HarvestWxs -Force }
            exit 1
        }
        Write-Host "  MSI built to $MsiOutput" -ForegroundColor Green

        # Clean up generated file
        if (Test-Path $HarvestWxs) { Remove-Item $HarvestWxs -Force }

        # Step 4: Setup bundle (issue #87). Wraps the MSI just built in a Burn
        # bootstrapper that chains the embedded ASP.NET Core Hosting Bundle
        # first, so a clean offline server installs from one file. Lives
        # inside the MSI branch on purpose: wix presence, $MsiOutput, and
        # $productVersion are established here, and -SkipMsi (used by CI)
        # skips the bundle too, so CI never downloads the payload.
        if (-not $SkipBundle) {
            Write-Host ""
            Write-Host "[4/5] Building setup bundle..." -ForegroundColor Yellow

            # Drift guard: the embedded runtime major must match the service
            # target framework major, or the bundle would install a runtime
            # the app cannot run on. Parse the csproj itself (net8.0-windows),
            # not Directory.Build.props, which the service overrides. Runs
            # before the download so a drifted pin fails without pulling
            # 100 MB first.
            $svcXml = [xml](Get-Content $ServiceProject)
            $tfm = $svcXml.Project.PropertyGroup.TargetFramework |
                Where-Object { $_ } | Select-Object -First 1
            if ($tfm -notmatch '^net(\d+)\.') {
                Write-Host "  ERROR: cannot parse TargetFramework '$tfm' from $ServiceProject" -ForegroundColor Red
                exit 1
            }
            $appMajor = [int]$Matches[1]
            $runtimeMajor = [int]$HostingBundleVersion.Split('.')[0]
            if ($appMajor -ne $runtimeMajor) {
                Write-Host "  ERROR: pinned Hosting Bundle $HostingBundleVersion does not match the app target net$appMajor.x." -ForegroundColor Red
                Write-Host "         Update HostingBundleVersion and HostingBundleSha512 near the top of build.ps1." -ForegroundColor Red
                exit 1
            }

            # Acquire the Hosting Bundle exe. A cache hit requires a hash
            # match; a failed check always deletes the file so a corrupt or
            # tampered cache cannot poison later builds. Downloads go to a
            # temp name first so a partial download never looks like a valid
            # cache entry. (Get-FileHash returns uppercase; PowerShell -eq is
            # case insensitive, so the lowercase published hash compares fine.)
            if (-not (Test-Path $RedistDir)) {
                New-Item -Path $RedistDir -ItemType Directory -Force | Out-Null
            }
            $haveHostingBundle = $false
            if (Test-Path $HostingBundleExe) {
                $hash = (Get-FileHash $HostingBundleExe -Algorithm SHA512).Hash
                if ($hash -eq $HostingBundleSha512) {
                    Write-Host "  Hosting Bundle $HostingBundleVersion found in cache (hash verified)" -ForegroundColor Green
                    $haveHostingBundle = $true
                } else {
                    Write-Host "  Cached Hosting Bundle failed the hash check; deleting it" -ForegroundColor DarkYellow
                    Remove-Item $HostingBundleExe -Force
                }
            }
            if (-not $haveHostingBundle) {
                Write-Host "  Downloading Hosting Bundle $HostingBundleVersion (about 100 MB)..." -ForegroundColor Gray
                $tmpDownload = "$HostingBundleExe.download"
                $prevProgress = $ProgressPreference
                try {
                    $ProgressPreference = 'SilentlyContinue'
                    Invoke-WebRequest -Uri $HostingBundleUrl -OutFile $tmpDownload
                } catch {
                    if (Test-Path $tmpDownload) { Remove-Item $tmpDownload -Force }
                    Write-Host "  ERROR: could not download the ASP.NET Core Hosting Bundle." -ForegroundColor Red
                    Write-Host "         URL: $HostingBundleUrl" -ForegroundColor Red
                    Write-Host "         On an offline machine, download it elsewhere and place it at:" -ForegroundColor Red
                    Write-Host "         $HostingBundleExe" -ForegroundColor Red
                    Write-Host "         Or re-run with -SkipBundle to build the MSI only." -ForegroundColor Red
                    exit 1
                } finally {
                    $ProgressPreference = $prevProgress
                }
                $hash = (Get-FileHash $tmpDownload -Algorithm SHA512).Hash
                if ($hash -ne $HostingBundleSha512) {
                    Remove-Item $tmpDownload -Force
                    Write-Host "  ERROR: downloaded Hosting Bundle failed the SHA-512 check." -ForegroundColor Red
                    Write-Host "         Expected: $HostingBundleSha512" -ForegroundColor Red
                    Write-Host "         Actual:   $hash" -ForegroundColor Red
                    exit 1
                }
                Move-Item $tmpDownload $HostingBundleExe -Force
                Write-Host "  Downloaded and verified → $HostingBundleExe" -ForegroundColor Green
            }

            $BundleWxs = Join-Path $InstallerDir "Bundle.wxs"
            $BundleOutput = Join-Path $RepoRoot "artifacts/Ducks-in-a-Row-Setup.exe"

            wix build $BundleWxs -d "ProductVersion=$productVersion" -d "HostingBundleVersion=$HostingBundleVersion" -d "HostingBundleMajor=$runtimeMajor" -d "HostingBundleExe=$HostingBundleExe" -d "MsiPath=$MsiOutput" -o $BundleOutput -ext WixToolset.Bal.wixext -ext WixToolset.Netfx.wixext -arch x64

            if ($LASTEXITCODE -ne 0) {
                Write-Host "  Bundle build failed!" -ForegroundColor Red
                exit 1
            }
            Write-Host "  Bundle built to $BundleOutput" -ForegroundColor Green
        } else {
            Write-Host ""
            Write-Host "[4/5] Skipping setup bundle (--SkipBundle)" -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host "[3/5] Skipping MSI build (--SkipMsi)" -ForegroundColor DarkGray
}

# Step 4 (optional): Build test projects
if ($IncludeTests) {
    Write-Host ""
    Write-Host "[5/5] Building test projects..." -ForegroundColor Yellow

    $testProjects = @(
        (Join-Path $RepoRoot "tests/Certus.Core.Tests/Certus.Core.Tests.csproj"),
        (Join-Path $RepoRoot "tests/Certus.Web.Tests/Certus.Web.Tests.csproj")
    )

    foreach ($testProj in $testProjects) {
        $projName = Split-Path $testProj -Leaf
        dotnet build $testProj -c $Configuration --nologo -v quiet
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  $projName build failed!" -ForegroundColor Red
            exit 1
        }
        Write-Host "  $projName built" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Build complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
