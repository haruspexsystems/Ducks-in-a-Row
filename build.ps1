<#
.SYNOPSIS
    Builds the Certus installer package.

.DESCRIPTION
    This script:
    1. Builds the React frontend (npm run build → wwwroot)
    2. Publishes the .NET Service project
    3. Generates the CycloneDX SBOM for what was published (issue #396)
    4. Optionally builds the WiX MSI installer
    5. Optionally wraps the MSI in the Burn setup bundle, which embeds the
       ASP.NET Core Hosting Bundle so a clean offline server installs with
       one file (issue #87)

    With -Sign it also signs and timestamps every binary the MSI installs,
    the MSI itself, and the setup bundle together with its Burn engine
    (issue #337). Without -Sign it signs nothing.

.PARAMETER Configuration
    Build configuration. Default: Release

.PARAMETER SkipFrontend
    Skip the frontend build (useful if node/npm not installed). Implies
    -SkipSbom, because the npm half of the bill of materials is generated
    from the node_modules that step installs.

.PARAMETER SkipMsi
    Skip the MSI build (useful if WiX not installed)

.PARAMETER SkipBundle
    Skip the setup bundle build (the MSI is still built). The bundle build
    downloads the pinned ASP.NET Core Hosting Bundle (about 100 MB) on first
    run and caches it in installer/redist. -SkipMsi implies -SkipBundle
    because the bundle wraps the MSI.

.PARAMETER SkipSbom
    Skip SBOM generation. For a fast local loop only: neither continuous
    integration nor release/Publish-Release.ps1 passes it, and the release
    script refuses to publish without the file this step writes.

.PARAMETER Sign
    Sign and timestamp what this build produces with the Haruspex Systems B.V.
    code signing certificate (issue #337): every .dll and .exe the MSI
    installs, the MSI, and the setup bundle together with its Burn engine.

    Sign or fail. With this switch any problem stops the build, and there is
    no fallback to an unsigned build. Without it the build never looks for a
    certificate and never runs signtool, which is how continuous integration,
    contributors and a build from the public source snapshot all behave.

    release/Publish-Release.ps1 passes it. A plain build deliberately does not
    sign whenever a certificate happens to be present: the release box is
    also the development box, so that would sign every everyday build, dirty
    trees included, whenever a SimplySign session was connected.

    Needs a clean git checkout, so every signed binary traces to a commit;
    the Windows SDK signing tools, for signtool.exe; and a connected
    SimplySign Desktop session, which is what makes the certificate in
    Cert:\CurrentUser\My usable. The session is connected by hand with a
    phone token and lasts about two hours. The card is pinless, so nothing
    prompts during the build.

.PARAMETER Runtime
    Target runtime identifier. Default: win-x64

.PARAMETER CommitSha
    The commit identifier to stamp into the published assemblies' version
    metadata (issue #112). Overrides the automatic resolution described in
    Resolve-CommitSha below. Passing it explicitly always wins, so
    -CommitSha "" forces a build with no stamp even in a git checkout, which
    is how to reproduce a release source snapshot build without deleting .git.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -SkipFrontend -SkipMsi
    .\build.ps1 -Configuration Debug
    .\build.ps1 -Sign
#>

param(
    [string]$Configuration = "Release",
    [switch]$SkipFrontend,
    [switch]$SkipMsi,
    [switch]$SkipBundle,
    [switch]$SkipSbom,
    [switch]$Sign,
    [switch]$IncludeTests,
    [string]$Runtime = "win-x64",
    [string]$CommitSha = ""
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
$SbomDir = Join-Path $RepoRoot "artifacts/sbom"
$ToolsDir = Join-Path $RepoRoot "artifacts/tools"
$InstallerDir = Join-Path $RepoRoot "installer"
$SigningDir = Join-Path $RepoRoot "artifacts/signing"

# The two deliverables. Resolved here rather than inside the MSI branch, where
# they used to live, because a -Sign build deletes both before it starts
# (issue #337). A failed build then cannot leave an older signed installer
# where the release script looks for one.
$MsiOutput = Join-Path $RepoRoot "artifacts/Ducks-in-a-Row.msi"
$BundleOutput = Join-Path $RepoRoot "artifacts/Ducks-in-a-Row-Setup.exe"

# The three Certus.Web host files the publish drags along but the MSI never
# installs (issue #305; the reason is at the harvest filter in step 4). One
# list, read by that filter and by the signing selection (issue #337), so the
# set of files that is signed cannot drift from the set that is installed.
$NeverInstalledFiles = @(
    "Certus.Web.exe",
    "Certus.Web.deps.json",
    "Certus.Web.runtimeconfig.json"
)

# ---- Setup bundle payload pin (issue #87) -----------------------------------
# The bootstrapper embeds the ASP.NET Core Hosting Bundle so installs work on
# an offline server. The exe is about 100 MB and is never committed to git: it
# is pinned to an exact version and SHA-512 here, downloaded on demand, and
# cached in installer/redist (gitignored) so later builds reuse it. Always
# bump the version and the hash together; the published hash for each release
# is in https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json
$HostingBundleVersion = "10.0.10"
$HostingBundleSha512 = "11e66d71e01a32794051437124df4f63585d40ff80b837a9520e4a0bf9ce18b750765e25398b42455745183b972fa0541426fdf4f9ea253d61e129302f21460e"
$HostingBundleUrl = "https://builds.dotnet.microsoft.com/dotnet/aspnetcore/Runtime/$HostingBundleVersion/dotnet-hosting-$HostingBundleVersion-win.exe"
$RedistDir = Join-Path $InstallerDir "redist"
$HostingBundleExe = Join-Path $RedistDir "dotnet-hosting-$HostingBundleVersion-win.exe"

# ---- SBOM generator pin (issue #396) ----------------------------------------
# Both generators are pinned here and installed into the same gitignored tool
# path, so the two halves of the bill of materials are acquired the same way.
#
# The .NET one is here rather than in .config/dotnet-tools.json beside
# dotnet-ef, because that manifest is stripped from the public source snapshot
# by release/Publish-Release.ps1's $ExcludePaths and this script is required to
# build from that snapshot, so a dotnet tool restore would break every build of
# the source we publish. Same reason the Hosting Bundle above is pinned in this
# file: what the build needs, the build names.
#
# The npm one is deliberately NOT a devDependency of src/frontend: it drags in
# 167 packages, 145 of them the optional libxmljs2 chain that exists for XML
# schema validation we never ask for, and they would land in the product's own
# package-lock.json, which is one of the files the SBOM is generated FROM.
# --omit=optional at install time reduces that to 22 and leaves the lockfile
# alone. Both invocations produce byte identical output either way; this was
# measured rather than assumed.
$CycloneDxPackage = "CycloneDX"
$CycloneDxVersion = "6.2.0"
$CycloneDxExe = Join-Path $ToolsDir "dotnet-CycloneDX.exe"
$CycloneDxNpmVersion = "6.0.1"
$CycloneDxNpmCli = Join-Path $ToolsDir "node_modules/@cyclonedx/cyclonedx-npm/bin/cyclonedx-npm-cli.js"

# ---- Code signing pin (issue #337) ------------------------------------------
# Read only when -Sign is passed. The certificate is chosen by this name, never
# by a thumbprint written down here, because the Certum certificate lasts 459
# days and its reissue is a new certificate with a new thumbprint. Both its CN
# and its O must equal the name exactly; see Select-SigningCertificate below.
# release/Publish-Release.ps1 checks the published installers against the same
# name, and its self test asserts that the two files agree.
$SigningCertificateName = "Haruspex Systems B.V."
# RFC 3161 with SHA-256, from Certum's own timestamp authority, proven on the
# release box under issue #390. Plain HTTP is normal for a timestamp authority,
# because the response is itself signed.
$TimestampUrl = "http://time.certum.pl"
# /d is what the UAC prompt shows as the program name. Without it an MSI is
# named by whatever temporary file name Windows cached it under.
$SignatureDescription = "Ducks in a Row"
$SignatureUrl = "https://github.com/haruspexsystems/Ducks-in-a-Row"
# A -Sign build warns when the certificate has fewer days left than this, so
# that cutting a release is also the reminder to start the reissue. The
# validation data behind the certificate expires about two months before the
# certificate itself does, and the reissue probably needs it renewed first.
$SigningExpiryWarningDays = 90

# ---- Commit stamp (issue #112) ----------------------------------------------
# Resolves the commit identity to stamp into the published assemblies. This
# script owns the git lookup, not MSBuild: Directory.Build.props keeps
# EnableSourceControlManagerQueries off for the #104 source-path privacy
# reason, and the value travels in as /p:SourceRevisionId on the publish below.
#
# The stamp is best effort by design. A build from the release source snapshot
# (release/Publish-Release.ps1 ships a `git archive`, which has no .git) has
# nothing to resolve, and must still succeed. It builds without a stamp and the
# gate after the publish is skipped rather than failed.
#
# A dirty tree stamps "<sha>.dirty" so a developer build never claims to be a
# clean commit. Releases can never carry it: Publish-Release.ps1 refuses to run
# on a dirty tree.
function Resolve-CommitSha {
    param(
        [string]$Override,
        [switch]$OverrideProvided
    )

    # An explicitly passed -CommitSha always wins, including an empty one. The
    # caller has to tell us it was passed, because the parameter's own default
    # is "" and PowerShell cannot tell "" apart from omitted on its own. That
    # is what makes -CommitSha "" a real "no stamp" switch rather than a
    # silent fall through to git.
    if ($OverrideProvided) {
        if ([string]::IsNullOrWhiteSpace($Override)) {
            return $null
        }
        return [pscustomobject]@{ Sha = $Override.Trim(); Source = "-CommitSha parameter" }
    }

    if (Get-Command git -ErrorAction SilentlyContinue) {
        # A source-only tree has no .git, so this fails rather than throws us
        # off the rails. -ErrorAction Stop is deliberately not used.
        $sha = & git -C $RepoRoot rev-parse HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and $sha) {
            $sha = $sha.Trim()
            $dirty = & git -C $RepoRoot status --porcelain 2>$null
            if ($LASTEXITCODE -eq 0 -and $dirty) {
                return [pscustomobject]@{ Sha = "$sha.dirty"; Source = "git HEAD (working tree is dirty)" }
            }
            return [pscustomobject]@{ Sha = $sha; Source = "git HEAD" }
        }
    }

    if ($env:CERTUS_COMMIT_SHA) {
        return [pscustomobject]@{ Sha = $env:CERTUS_COMMIT_SHA; Source = "CERTUS_COMMIT_SHA" }
    }

    if ($env:GITHUB_SHA) {
        return [pscustomobject]@{ Sha = $env:GITHUB_SHA; Source = "GITHUB_SHA" }
    }

    return $null
}

# ---- Pure helpers (issue #396) ----------------------------------------------
# Both take every input as a parameter and return a value rather than printing
# or exiting, because tests/build/Test-BuildScripts.ps1 lifts them out of this
# file through the AST and drives them directly. A helper that grew a dependency
# on $RepoRoot or called exit would stop being testable, which is the same
# contract release/Publish-Release.ps1 states for its own pure functions.

function Get-ProductVersionInfo {
    <#
    .SYNOPSIS
        The one place Directory.Build.props is decomposed for this script.
    .DESCRIPTION
        XPath rather than $props.Project.PropertyGroup.VersionPrefix. The file
        carries two PropertyGroup elements, so the dotted path is member
        enumeration over an array: it works in this script, which sets no
        StrictMode, and THROWS under Set-StrictMode -Version Latest, which the
        self test runs. release/Publish-Release.ps1 learned this the same way
        and keeps a planted defect pinning it. XPath also separates "the element
        is absent", which is the required state for a non prerelease version,
        from "present and empty".

        Two forms come out of one parse because they are two different things.
        SemVer is what the assemblies report and what the SBOM is named after;
        MsiVersion is the strict four part numeric that WiX demands and must
        never carry a prerelease suffix.

        Read here rather than inside the MSI branch, where it lived until issue
        #396: -SkipMsi never enters that branch, and the SBOM stage needs the
        version on exactly that path, which is the one CI runs.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $PropsPath)

    if (-not (Test-Path -LiteralPath $PropsPath -PathType Leaf)) {
        return [pscustomobject]@{ Ok = $false; Error = "Directory.Build.props not found at $PropsPath"
            Prefix = ''; Suffix = ''; SemVer = ''; MsiVersion = '' }
    }

    $props = [xml][System.IO.File]::ReadAllText($PropsPath, [System.Text.Encoding]::UTF8)
    $prefixNodes = @($props.SelectNodes('/Project/PropertyGroup/VersionPrefix'))
    $suffixNodes = @($props.SelectNodes('/Project/PropertyGroup/VersionSuffix'))

    $prefix = if ($prefixNodes.Count -gt 0) { $prefixNodes[0].InnerText.Trim() } else { '' }
    if (-not $prefix) {
        # Never fall back to a literal. A silent default is the failure this
        # function exists to remove.
        return [pscustomobject]@{ Ok = $false; Error = "VersionPrefix not found (or empty) in $PropsPath"
            Prefix = ''; Suffix = ''; SemVer = ''; MsiVersion = '' }
    }

    # Absent and present-but-empty must both yield a bare "1.0.0".
    # release/Set-ReleaseVersion.ps1 deletes the element outright for a non
    # prerelease, so this is the 1.0.0 path and not a hypothetical. Appending
    # unconditionally is how docs/generate_guide.py once stamped "1.0.0-None"
    # on all 26 pages of the guide; see docs/guide_manifest.py.
    $suffix = if ($suffixNodes.Count -gt 0) { $suffixNodes[0].InnerText.Trim() } else { '' }

    [pscustomobject]@{
        Ok         = $true
        Error      = ''
        Prefix     = $prefix
        Suffix     = $suffix
        SemVer     = $(if ($suffix) { "$prefix-$suffix" } else { $prefix })
        MsiVersion = "$prefix.0"
    }
}

function Merge-CycloneDxBom {
    <#
    .SYNOPSIS
        Merges the NuGet and npm CycloneDX documents into the one BOM that ships.
    .DESCRIPTION
        JSON text in, JSON text out, so the self test can drive every case
        without running a build.

        Deliberately not cyclonedx-cli, which is the project's own merge tool:
        it is not a NuGet dotnet tool but a standalone GitHub release binary,
        and pulling an unpinned third party binary into the build is what this
        script does not do. Compare the Hosting Bundle above, pinned to both a
        version and a SHA-512.

        Hierarchical, and no bom-ref is ever rewritten. Each half's own
        metadata.component becomes an ordinary component of the result, so that
        half's dependency graph stays rooted and intact, and a new product
        component sits above both and depends on them. Rewriting refs is where a
        hand rolled merge goes wrong; not rewriting them is what makes this
        auditable against the two inputs, which the build keeps on disk.

        THIS FUNCTION IS THE DETERMINISM BOUNDARY. It builds the output document
        itself and copies no metadata from either half, which matters because
        the .NET generator stamps a metadata.timestamp that no flag removes.
        No serialNumber and no timestamp are emitted, and components,
        dependencies and every dependsOn are sorted ordinally, so the same
        commit produces the same bytes. That
        is not cosmetic: the file is hashed into artifacts/SHA256SUMS, and
        release/Publish-Release.ps1 -Stage public republishes staging's exact
        bytes, so a random serial number would be the one artifact that could
        not be reproduced. The commit goes into metadata.properties instead of a
        timestamp, which is the same issue #112 stamp the binaries carry.

        Contains throughout, never dotted access and never ContainsKey. Almost
        every field here is optional in CycloneDX, and under Set-StrictMode
        -Version Latest a dotted read of a missing key throws
        PropertyNotFoundException, so this would pass in build.ps1 and fail in
        the self test. ContainsKey is the obvious choice and is WRONG: three
        dictionary shapes reach this function, and only two of them have it.
        ConvertFrom-Json -AsHashtable yields an OrderedHashtable and a caller's
        [ordered]@{} yields a System.Collections.Specialized.OrderedDictionary,
        which has no ContainsKey at all. Contains is IDictionary's own method
        and is present on all three.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string] $NugetBomJson,
        [Parameter(Mandatory)][AllowEmptyString()][string] $NpmBomJson,
        [Parameter(Mandatory)][string] $ProductName,
        [Parameter(Mandatory)][string] $ProductVersion,
        [string] $SpecVersion = '1.6',
        [string] $CommitSha = '',
        [object[]] $ExtraComponents = @()
    )

    function New-MergeFailure {
        param([string] $Message)
        [pscustomobject]@{ Ok = $false; Error = $Message; Json = ''
            NugetCount = 0; NpmCount = 0; ComponentCount = 0 }
    }

    function Sort-OrdinalByKey {
        <#
            Two wrong ways to do this, both of which were written here first.

            Sort-Object is the obvious one. Even with -CaseSensitive it compares
            through the current culture, so two hosts with different locales
            order 'pkg:npm/@fontsource/...' against 'pkg:nuget/...' differently
            and the SBOM stops being byte reproducible between the build box and
            the continuous integration runner, which is the one property this
            whole function exists to provide.

            [System.Array]::Sort($keys, $items, $comparer) is the second. It
            looks right and it silently half works: PowerShell's parameter
            binding converts the object[] of items into a NEW array to match the
            overload, so the sort reorders that copy while the keys array, which
            needed no conversion, is sorted in place. The caller gets its items
            back untouched and no error is raised.

            LINQ has neither problem. It takes the comparer explicitly and
            returns a new sequence rather than mutating anything, so there is no
            in place write for a binding copy to swallow. Return the array
            unrolled and let the call site wrap it in @(): returning ,$array
            hands back a nested array instead, which is how the caller ends up
            indexing an array by the string 'ref'.
        #>
        param([object[]] $Items, [string] $Key)
        $selector = [System.Func[object, string]] { param($item) "$($item[$Key])" }
        [System.Linq.Enumerable]::ToArray(
            [System.Linq.Enumerable]::OrderBy([object[]]$Items, $selector, [System.StringComparer]::Ordinal))
    }

    $halves = @(
        [pscustomobject]@{ Name = 'NuGet'; Json = $NugetBomJson; PurlPrefix = 'pkg:nuget/' }
        [pscustomobject]@{ Name = 'npm';   Json = $NpmBomJson;   PurlPrefix = 'pkg:npm/'   }
    )

    $docs = @{}
    foreach ($half in $halves) {
        if ([string]::IsNullOrWhiteSpace($half.Json)) {
            return New-MergeFailure "the $($half.Name) BOM is empty."
        }
        $doc = $null
        try {
            # -AsHashtable returns an OrderedHashtable on PowerShell 7, so key
            # order survives the round trip and the output stays byte stable.
            $doc = $half.Json | ConvertFrom-Json -AsHashtable
        } catch {
            return New-MergeFailure "the $($half.Name) BOM is not valid JSON: $($_.Exception.Message)"
        }
        if (-not $doc.Contains('bomFormat') -or $doc['bomFormat'] -ne 'CycloneDX') {
            return New-MergeFailure "the $($half.Name) BOM is not a CycloneDX document."
        }
        # The guard that catches a generator changing its default under us. The
        # .NET tool defaults to 1.7 and the npm tool cannot read or write above
        # 1.6, so both are pinned to the lower ceiling and a drift has to fail
        # here rather than produce a document claiming a version half of it is
        # not written to.
        if (-not $doc.Contains('specVersion') -or $doc['specVersion'] -ne $SpecVersion) {
            $got = if ($doc.Contains('specVersion')) { $doc['specVersion'] } else { '(absent)' }
            return New-MergeFailure ("the $($half.Name) BOM is CycloneDX $got, expected $SpecVersion. " +
                'Both generators must be pinned to the same spec version.')
        }
        $docs[$half.Name] = $doc
    }

    $components = @()
    $dependencies = @()
    $subRoots = @()
    $counts = @{ 'NuGet' = 0; 'npm' = 0 }

    foreach ($half in $halves) {
        $doc = $docs[$half.Name]

        if ($doc.Contains('metadata') -and $doc['metadata'].Contains('component')) {
            $subRoot = $doc['metadata']['component']
            if ($subRoot.Contains('bom-ref')) { $subRoots += "$($subRoot['bom-ref'])" }
            $components += , $subRoot
        }
        if ($doc.Contains('components')) {
            foreach ($component in @($doc['components'])) {
                $components += , $component
                if ($component.Contains('purl') -and
                    "$($component['purl'])".StartsWith($half.PurlPrefix, [StringComparison]::Ordinal)) {
                    $counts[$half.Name]++
                }
            }
        }
        if ($doc.Contains('dependencies')) {
            $dependencies += @($doc['dependencies'])
        }
    }

    $productRef = "$ProductName@$ProductVersion"

    # Components the generators cannot see, declared from a pin rather than
    # discovered. Today that is the ASP.NET Core Hosting Bundle the Burn
    # bootstrapper embeds: a binary the product genuinely installs, which is
    # neither a NuGet package nor an npm one, so an SBOM without it understates
    # what lands on the machine. They depend on nothing, which is a claim about
    # our knowledge and is why the entry is empty rather than absent.
    foreach ($extra in @($ExtraComponents)) {
        $components += , $extra
        if ($extra.Contains('bom-ref')) {
            $subRoots += "$($extra['bom-ref'])"
            $dependencies += , ([ordered]@{ ref = "$($extra['bom-ref'])"; dependsOn = @() })
        }
    }

    # A bom-ref that means two different things in one document is not
    # mergeable. It cannot happen across pkg:nuget and pkg:npm, which is exactly
    # why refusing costs nothing and why the guard is worth having: it is the
    # assumption the no-rewrite design rests on, so it should be checked rather
    # than believed.
    # An ordinal set, not @{}. A PowerShell hashtable compares keys case
    # INsensitively, which would read two refs differing only in case as one and
    # refuse a merge that is perfectly legal. It would also disagree with the
    # ordinal sort a few lines down, which treats them as two.
    $seenRefs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($component in $components) {
        if (-not $component.Contains('bom-ref')) { continue }
        $ref = "$($component['bom-ref'])"
        if ($seenRefs.Contains($ref)) {
            return New-MergeFailure ("bom-ref '$ref' appears more than once; refusing to collapse two " +
                'different components onto one reference.')
        }
        [void]$seenRefs.Add($ref)
    }

    # The backstop for a generator that succeeded and found nothing. The .NET
    # tool exits 0 and writes a BOM with zero components when it cannot read
    # obj/project.assets.json, so an exit code alone does not prove the step
    # worked. This is the issue's own spot check reduced to a machine check.
    if ($counts['NuGet'] -eq 0) { return New-MergeFailure 'the merged BOM carries no pkg:nuget component.' }
    if ($counts['npm'] -eq 0) { return New-MergeFailure 'the merged BOM carries no pkg:npm component.' }

    # Ordinal sort, so the order the halves happened to be read in cannot reach
    # the bytes, and neither can the locale of the machine that built them.
    #
    # Both lists are sorted, and dependsOn with them, because in CycloneDX the
    # order of any of the three carries no meaning. Canonicalising all of it
    # costs three lines and buys a document that diffs cleanly between two
    # releases, which is what a reader comparing versions for new or changed
    # dependencies actually wants.
    $components = @(Sort-OrdinalByKey -Items $components -Key 'bom-ref')

    $metadata = [ordered]@{
        component = [ordered]@{
            'bom-ref' = $productRef
            type      = 'application'
            name      = $ProductName
            version   = $ProductVersion
        }
    }
    if ($CommitSha) {
        $metadata['properties'] = @( [ordered]@{ name = 'ducksinarow:commit'; value = $CommitSha } )
    }

    $dependencies = @( , ([ordered]@{ ref = $productRef; dependsOn = @($subRoots) }) ) + $dependencies
    $dependencies = @($dependencies | ForEach-Object {
            # A List I own, so Sort really is in place; see Sort-OrdinalByKey
            # on why [System.Array]::Sort is not trustworthy through parameter
            # binding here.
            $on = [System.Collections.Generic.List[string]]@(
                if ($_.Contains('dependsOn')) { $_['dependsOn'] } else { @() })
            $on.Sort([System.StringComparer]::Ordinal)
            [ordered]@{ ref = "$($_['ref'])"; dependsOn = @($on) }
        })
    $dependencies = @(Sort-OrdinalByKey -Items $dependencies -Key 'ref')

    $bom = [ordered]@{
        bomFormat    = 'CycloneDX'
        specVersion  = $SpecVersion
        version      = 1
        metadata     = $metadata
        components   = $components
        dependencies = $dependencies
    }

    # -Depth 100 is load bearing and measured, not defensive. ConvertTo-Json
    # defaults to depth 2, at which a nested array such as a component's hashes
    # or licenses does not merely truncate: [1,2,3] serialises as the STRING
    # "1 2 3". The result is still valid JSON and still a plausible looking BOM.
    # It emits a warning rather than an error, so $ErrorActionPreference = Stop
    # does not catch it and the build would ship a gutted document.
    [pscustomobject]@{
        Ok             = $true
        Error          = ''
        Json           = ($bom | ConvertTo-Json -Depth 100)
        NugetCount     = $counts['NuGet']
        NpmCount       = $counts['npm']
        ComponentCount = $components.Count
    }
}

# ---- Code signing helpers (issue #337) --------------------------------------
# The first five are pure, like the two above and for the same reason: the self
# test lifts them out through the AST and drives them with records it builds
# itself, so none of them may touch the certificate store, the disk or
# signtool. Invoke-SignTool and Invoke-SignFiles, last, are the impure half.
# They run processes, so nothing lifts them for testing; a real -Sign build is
# what exercises them.

function Get-NameAttributeValues {
    <#
    .SYNOPSIS
        Every value one attribute takes in a distinguished name, read by the
        name parser rather than by matching text.
    .DESCRIPTION
        The comparison this exists to avoid is a text match. The name
        "CN=Haruspex Systems B.V. Test" contains "Haruspex Systems B.V.", and
        so does a subject whose O is that name while its CN is something else.
        signtool's own /n selection is exactly such a substring match.

        Ok is false when the name does not parse, or when a component holds
        more than one value (OU=IT+CN=x), so the caller refuses rather than
        guessing which value was meant. The order the components come back in
        does not matter to anything that calls this.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string] $Name,
        [Parameter(Mandatory)][string] $AttributeOid
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return [pscustomobject]@{ Ok = $false; Values = @() }
    }
    try {
        $parsed = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Name)
        $values = [System.Collections.Generic.List[string]]::new()
        foreach ($rdn in $parsed.EnumerateRelativeDistinguishedNames()) {
            if ($rdn.HasMultipleElements) {
                return [pscustomobject]@{ Ok = $false; Values = @() }
            }
            if ($rdn.GetSingleElementType().Value -eq $AttributeOid) {
                $values.Add($rdn.GetSingleElementValue())
            }
        }
        return [pscustomobject]@{ Ok = $true; Values = $values.ToArray() }
    } catch {
        return [pscustomobject]@{ Ok = $false; Values = @() }
    }
}

function Select-SigningCertificate {
    <#
    .SYNOPSIS
        Chooses the certificate a -Sign build signs with, from records of the
        certificates in the store.
    .DESCRIPTION
        Records, not X509Certificate2 objects, so the self test can describe
        any store it likes. The call site maps each certificate to Subject,
        Issuer, Thumbprint, NotBefore, NotAfter, HasPrivateKey and EkuOids.

        A certificate qualifies only when all of these hold:
          - its CN and its O each equal the expected name exactly, one value
            each, read by Get-NameAttributeValues and never by a text match;
          - it carries the code signing usage, 1.3.6.1.5.5.7.3.3;
          - a private key is linked to it;
          - it is valid at -Now;
          - it is not self issued.

        The issuer is deliberately not pinned. The reissue due around day 459
        may come from a newer Certum intermediate, and a pin would stop the
        first release after it for no gain: a certificate that merely carries
        this name cannot produce a signature that verifies as Valid unless a
        trusted authority issued it, and both this build and the release check
        require Valid.

        HasPrivateKey says a key is linked, not that it can be reached. With the
        SimplySign session disconnected, the certificate stays in the store and
        still reports HasPrivateKey True (measured on 2026-09-19), which is why
        the -Sign preflight proves the key by signing a throwaway file instead
        of trusting this flag.

        When more than one qualifies, which is what the overlap around a
        reissue looks like, the latest NotAfter wins, then the latest
        NotBefore, then the lowest thumbprint, so the choice is never left to
        chance. The winner goes to signtool as /sha1, never as /n: /n matches
        any subject that contains the text, and without /a it expects exactly
        one valid match, so it would stop working during that overlap.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Certificates,
        [Parameter(Mandatory)][string] $ExpectedName,
        [Parameter(Mandatory)][datetime] $Now
    )

    $codeSigningOid = '1.3.6.1.5.5.7.3.3'
    $qualified = @()
    $rejected = @()
    foreach ($candidate in @($Certificates)) {
        $cn = Get-NameAttributeValues -Name "$($candidate.Subject)" -AttributeOid '2.5.4.3'
        $o = Get-NameAttributeValues -Name "$($candidate.Subject)" -AttributeOid '2.5.4.10'
        $reason = if (-not $cn.Ok -or -not $o.Ok) {
            'its subject does not parse as a distinguished name'
        } elseif (@($cn.Values).Count -ne 1 -or
            -not [string]::Equals($cn.Values[0], $ExpectedName, [StringComparison]::Ordinal)) {
            "its CN is not exactly '$ExpectedName'"
        } elseif (@($o.Values).Count -ne 1 -or
            -not [string]::Equals($o.Values[0], $ExpectedName, [StringComparison]::Ordinal)) {
            "its O is not exactly '$ExpectedName'"
        } elseif (@($candidate.EkuOids) -notcontains $codeSigningOid) {
            'it does not carry the code signing usage'
        } elseif (-not $candidate.HasPrivateKey) {
            'no private key is linked to it'
        } elseif ($candidate.NotBefore -gt $Now) {
            "it is not valid until $($candidate.NotBefore.ToString('yyyy-MM-dd'))"
        } elseif ($candidate.NotAfter -le $Now) {
            "it expired on $($candidate.NotAfter.ToString('yyyy-MM-dd'))"
        } elseif ([string]::Equals("$($candidate.Issuer)", "$($candidate.Subject)", [StringComparison]::Ordinal)) {
            'it is self issued'
        } else {
            $null
        }
        if ($reason) {
            $rejected += [pscustomobject]@{
                Thumbprint = "$($candidate.Thumbprint)"; Subject = "$($candidate.Subject)"; Reason = $reason }
        } else {
            $qualified += $candidate
        }
    }

    if ($qualified.Count -eq 0) {
        return [pscustomobject]@{
            Ok         = $false
            Error      = ("no certificate in the store qualifies. One needs a CN and an O that are both exactly " +
                "'$ExpectedName', the code signing usage, a linked private key, a current validity period, " +
                'and an issuer other than itself.')
            Thumbprint = ''
            NotAfter   = $null
            DaysLeft   = 0
            Qualified  = @()
            Rejected   = $rejected
        }
    }

    # Sort-Object is safe here, unlike in Merge-CycloneDxBom: the keys that
    # decide are dates, which carry no culture, and the thumbprint only breaks
    # an exact tie between two certificates that could both sign.
    $ordered = @($qualified | Sort-Object -Property `
            @{ Expression = { $_.NotAfter }; Descending = $true },
            @{ Expression = { $_.NotBefore }; Descending = $true },
            @{ Expression = { "$($_.Thumbprint)" }; Descending = $false })
    $chosen = $ordered[0]
    [pscustomobject]@{
        Ok         = $true
        Error      = ''
        Thumbprint = "$($chosen.Thumbprint)"
        NotAfter   = $chosen.NotAfter
        DaysLeft   = [int][math]::Floor(($chosen.NotAfter - $Now).TotalDays)
        Qualified  = $ordered
        Rejected   = $rejected
    }
}

function Select-SignToolPath {
    <#
    .SYNOPSIS
        Picks the signtool.exe a -Sign build runs, from the candidate files the
        call site found under the Windows SDK.
    .DESCRIPTION
        signtool is not on PATH on the release box. The Windows SDK installs it
        under Windows Kits\10\bin\<version>\<architecture>, and the version
        folder changes with every SDK update, so the path cannot be written
        down. The call site lists the files that exist and this picks one.

        Only an x64 copy is taken. The same bin folder holds arm64 and x86
        copies too.

        Versions are compared as [version], never as text: as text,
        10.0.9200.0 sorts above 10.0.26100.0. An older SDK layout without a
        version folder (bin\x64\signtool.exe) is accepted, below any versioned
        copy. A candidate that fits neither shape is ignored; the call site
        falls back to PATH on its own when nothing here qualifies.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]] $Candidates)

    $ranked = @(foreach ($path in @($Candidates)) {
            if ([string]::IsNullOrWhiteSpace($path)) { continue }
            $parts = @($path -split '[\\/]' | Where-Object { $_ })
            if ($parts.Count -lt 3) { continue }
            if ($parts[-1] -ne 'signtool.exe' -or $parts[-2] -ne 'x64') { continue }
            $version = $null
            if ([version]::TryParse($parts[-3], [ref]$version)) {
                [pscustomobject]@{ Path = $path; Rank = 2; Version = $version }
            } elseif ($parts[-3] -eq 'bin') {
                [pscustomobject]@{ Path = $path; Rank = 1; Version = [version]'0.0' }
            }
        })
    if ($ranked.Count -eq 0) {
        return [pscustomobject]@{ Ok = $false; Path = ''; Error = 'no x64 signtool.exe was found under the Windows SDK.' }
    }
    $best = @($ranked | Sort-Object -Property `
            @{ Expression = { $_.Rank }; Descending = $true },
            @{ Expression = { $_.Version }; Descending = $true })[0]
    [pscustomobject]@{ Ok = $true; Path = $best.Path; Error = '' }
}

function Get-SigningTargets {
    <#
    .SYNOPSIS
        The files in the publish tree that a -Sign build signs: every .dll and
        .exe the MSI installs.
    .DESCRIPTION
        Every one, third party included, and that is a measured decision rather
        than a default (issue #337). The publish runs with PublishReadyToRun,
        and crossgen rewrites every assembly it compiles, which drops whatever
        Authenticode signature the vendor shipped. The NuGet copy of
        Microsoft.Data.Sqlite.dll verifies as Valid; the published copy is
        NotSigned and about 2.5 times the size. So before this step every
        installed binary was unsigned, Microsoft's and BouncyCastle's included,
        and a customer running App Control for Business (WDAC) or AppLocker
        could not allow the install by publisher at all. Signed here, one rule
        for Haruspex Systems B.V. covers all of it, and since the bytes are
        this build's own crossgen output, the signature names who produced them.

        Takes records with a Name rather than FileInfo objects, so the self
        test can describe a publish tree without building one. The files the
        MSI never installs are skipped by the same list the harvest filter
        reads. Refuses when the service's executable or its entry assembly is
        missing, because a selection that lost them would sign everything
        except the one thing that matters.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Files,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $NeverInstalled
    )

    $targets = @(@($Files) | Where-Object {
            $extension = [System.IO.Path]::GetExtension("$($_.Name)")
            ($extension -eq '.dll' -or $extension -eq '.exe') -and ($NeverInstalled -notcontains "$($_.Name)")
        })
    $names = @($targets | ForEach-Object { "$($_.Name)" })
    foreach ($required in @('DucksInARow.Service.exe', 'DucksInARow.Service.dll')) {
        if ($names -notcontains $required) {
            return [pscustomobject]@{ Ok = $false; Targets = @()
                Error = "$required is not among the files to sign, so the selection is wrong or the publish is incomplete." }
        }
    }
    [pscustomobject]@{ Ok = $true; Targets = $targets; Error = '' }
}

function Get-SignatureFindings {
    <#
    .SYNOPSIS
        What is wrong with a signature this build has just applied: one finding
        per problem, an empty array when there is none.
    .DESCRIPTION
        Takes a record shaped like Get-AuthenticodeSignature's output (Status,
        SignerCertificate, TimeStamperCertificate), so the self test can drive
        every case without signing anything.

        Three independent checks, because each can pass while another fails:
          - Valid alone is met by any trusted signer, so a file someone else
            signed, or a stale file signed earlier, would pass. Hence the
            thumbprint of the certificate this build chose.
          - The thumbprint alone is met by a signature that no longer verifies;
            a file changed after signing reads HashMismatch.
          - Neither says whether the timestamp step ran. Without a timestamp
            the signature dies with the certificate, 459 days after issue,
            which is the failure timestamping exists to prevent.

        Returns the bare array, so the call site must wrap it in @(): an empty
        array unrolls to $null on the way out.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Signature,
        [Parameter(Mandatory)][string] $ExpectedThumbprint
    )

    $findings = @()
    $status = "$($Signature.Status)"
    if ($status -ne 'Valid') {
        $findings += [pscustomobject]@{ Check = 'NotValid'; Message = "the signature status is $status, not Valid" }
    }
    $signer = if ($Signature.SignerCertificate) { "$($Signature.SignerCertificate.Thumbprint)" } else { '' }
    if (-not [string]::Equals($signer, $ExpectedThumbprint, [StringComparison]::OrdinalIgnoreCase)) {
        $shown = if ($signer) { "certificate $signer" } else { 'nobody' }
        $findings += [pscustomobject]@{ Check = 'WrongSigner'; Message = "it is signed by $shown, not by $ExpectedThumbprint" }
    }
    if (-not $Signature.TimeStamperCertificate) {
        $findings += [pscustomobject]@{ Check = 'NoTimestamp'; Message = 'the signature carries no timestamp' }
    }
    return $findings
}

function Get-PeSecurityDirectory {
    <#
    .SYNOPSIS
        Where a PE image says its Authenticode signature is: the file offset
        and size held in the security entry of its data directory.
    .DESCRIPTION
        Pure over the bytes, so the self test can hand it a synthetic image.
        Ok is false when the bytes are not a PE image this can read, or when
        the image declares too few data directories to have a security entry.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]] $Bytes)

    $unreadable = [pscustomobject]@{ Ok = $false; EntryOffset = 0; Address = 0; Size = 0 }
    if ($Bytes.Length -lt 0x40 -or $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { return $unreadable }
    $pe = [BitConverter]::ToInt32($Bytes, 0x3C)
    if ($pe -lt 0x40 -or $pe + 26 -gt $Bytes.Length) { return $unreadable }
    if ($Bytes[$pe] -ne 0x50 -or $Bytes[$pe + 1] -ne 0x45 -or $Bytes[$pe + 2] -ne 0 -or $Bytes[$pe + 3] -ne 0) {
        return $unreadable
    }
    $optional = $pe + 24
    $directories = switch ([BitConverter]::ToUInt16($Bytes, $optional)) {
        0x20B { $optional + 112 }
        0x10B { $optional + 96 }
        default { -1 }
    }
    if ($directories -lt 0 -or $directories + 40 -gt $Bytes.Length) { return $unreadable }
    if ([BitConverter]::ToInt32($Bytes, $directories - 4) -lt 5) { return $unreadable }
    $entry = $directories + 4 * 8
    [pscustomobject]@{
        Ok          = $true
        EntryOffset = $entry
        Address     = [BitConverter]::ToInt32($Bytes, $entry)
        Size        = [BitConverter]::ToInt32($Bytes, $entry + 4)
    }
}

function Test-SignedEngineCarried {
    <#
    .SYNOPSIS
        Whether the engine detached from a finished bundle carries the
        signature this build put on the engine before reattaching it.
    .DESCRIPTION
        The detached engine cannot simply be asked, and that was measured on
        the release box on 2026-09-19. wix burn reattach clears the engine's
        pointer to its own signature, so that the bundle can be signed as a
        whole, and rewrites a few fields in the .wixburn section. wix burn
        detach then copies the finished bundle's header back out unchanged,
        so the detached engine's pointer names the outer signature, past its
        own end, and Get-AuthenticodeSignature reads it as NotSigned. Burn
        itself restores all of it whenever it copies its engine out: the clean
        room copy it relaunched from during a /layout run was byte identical
        to the engine this build had signed, and verified as Valid. That copy
        is what the UAC prompt shows, and what Burn caches to run repair and
        uninstall.

        So the check is on the bytes rather than on a verdict. The signed
        engine's certificate table, which ends that file, must sit byte for
        byte at the same offset in the detached copy, and the two must be the
        same length. An unsigned engine reattached by mistake is shorter and
        carries no table; an engine signed by another build carries another.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]] $SignedEngine,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]] $DetachedEngine
    )

    $signature = Get-PeSecurityDirectory -Bytes $SignedEngine
    if (-not $signature.Ok) {
        return [pscustomobject]@{ Ok = $false; Error = 'the signed engine is not a PE image this can read' }
    }
    if ($signature.Address -le 0 -or $signature.Size -le 0 -or ($signature.Address + $signature.Size) -ne $SignedEngine.Length) {
        return [pscustomobject]@{ Ok = $false; Error = 'the signed engine carries no certificate table at its end' }
    }
    if ($DetachedEngine.Length -ne $SignedEngine.Length) {
        return [pscustomobject]@{ Ok = $false
            Error = "the engine in the bundle is $($DetachedEngine.Length) bytes and the signed engine $($SignedEngine.Length)" }
    }
    for ($i = $signature.Address; $i -lt $signature.Address + $signature.Size; $i++) {
        if ($DetachedEngine[$i] -ne $SignedEngine[$i]) {
            return [pscustomobject]@{ Ok = $false
                Error = "the certificate table in the bundle differs from the signed engine's at byte $i" }
        }
    }
    [pscustomobject]@{ Ok = $true; Error = '' }
}

function Invoke-SignTool {
    <#
    .SYNOPSIS
        Runs signtool once, with a time limit, and returns its exit code and
        output.
    .DESCRIPTION
        ProcessStartInfo.ArgumentList, not Start-Process: Start-Process joins
        its arguments with spaces and quotes nothing, so /d "Ducks in a Row"
        would arrive as three arguments.

        The time limit is load bearing, and measured. On 2026-09-19, with the
        SimplySign session disconnected, signtool did not fail: SimplySign put
        a login prompt on the desktop and signtool waited on it, until this
        limit ended the call 120 seconds in. Without it a lapsed session would
        hold an unattended build for ever. An operator who logs in through
        that prompt within the limit lets the signing carry on.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $SignToolPath,
        [Parameter(Mandatory)][string[]] $Arguments,
        [int] $TimeoutSeconds = 120
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new($SignToolPath)
    foreach ($argument in $Arguments) { $psi.ArgumentList.Add($argument) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    # Both streams are read asynchronously. Reading one to the end while the
    # other fills its pipe buffer would deadlock against the child.
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try { $process.Kill($true) } catch { }
        return [pscustomobject]@{ ExitCode = -1; TimedOut = $true
            Output = "signtool did not finish within $TimeoutSeconds seconds and was stopped." }
    }
    $process.WaitForExit()
    [pscustomobject]@{
        ExitCode = $process.ExitCode
        TimedOut = $false
        Output   = ($stdout.Result + $stderr.Result).Trim()
    }
}

function Invoke-SignFiles {
    <#
    .SYNOPSIS
        Signs, timestamps and verifies each file in turn. Returns the first
        failure, or Ok.
    .DESCRIPTION
        Signing and timestamping are two signtool calls on purpose, so that
        only the timestamp is ever retried. A timestamp authority that fails
        once often answers the next request, and retrying it never touches the
        cloud key. A signing failure is not retried: on the release box it
        almost always means the SimplySign session has lapsed, and waiting
        will not reconnect it.

        Every non zero exit is a failure, including 2, which is signtool's
        "completed with warnings".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]] $Paths,
        [Parameter(Mandatory)][string] $SignToolPath,
        [Parameter(Mandatory)][string] $Thumbprint,
        [Parameter(Mandatory)][string] $TimestampUrl,
        [Parameter(Mandatory)][string] $Description,
        [Parameter(Mandatory)][string] $Url
    )

    foreach ($path in $Paths) {
        $name = Split-Path -Leaf $path
        $signed = Invoke-SignTool -SignToolPath $SignToolPath -TimeoutSeconds 120 -Arguments @(
            'sign', '/sha1', $Thumbprint, '/fd', 'sha256', '/d', $Description, '/du', $Url, $path)
        if ($signed.TimedOut) {
            return [pscustomobject]@{ Ok = $false; File = $name; Output = $signed.Output
                Error = ("signing $name timed out. With the SimplySign session disconnected, signtool waits on " +
                    "SimplySign's login prompt rather than failing, so this almost always means the session has lapsed.") }
        }
        if ($signed.ExitCode -ne 0) {
            return [pscustomobject]@{ Ok = $false; File = $name; Output = $signed.Output
                Error = "signing $name failed (signtool exit $($signed.ExitCode))." }
        }

        $stamp = $null
        $delays = @(5, 20, 45)
        for ($attempt = 1; $attempt -le 4; $attempt++) {
            $stamp = Invoke-SignTool -SignToolPath $SignToolPath -TimeoutSeconds 60 -Arguments @(
                'timestamp', '/tr', $TimestampUrl, '/td', 'sha256', $path)
            if ($stamp.ExitCode -eq 0) { break }
            if ($attempt -lt 4) {
                Write-Host "    timestamping $name failed (attempt $attempt of 4), retrying in $($delays[$attempt - 1]) s" -ForegroundColor DarkYellow
                Start-Sleep -Seconds $delays[$attempt - 1]
            }
        }
        if ($stamp.ExitCode -ne 0) {
            return [pscustomobject]@{ Ok = $false; File = $name; Output = $stamp.Output
                Error = "timestamping $name failed four times at $TimestampUrl (signtool exit $($stamp.ExitCode))." }
        }

        $findings = @(Get-SignatureFindings -Signature (Get-AuthenticodeSignature -LiteralPath $path) -ExpectedThumbprint $Thumbprint)
        if ($findings.Count -gt 0) {
            return [pscustomobject]@{ Ok = $false; File = $name; Output = ''
                Error = "$name did not verify after signing: $(($findings | ForEach-Object Message) -join '; ')." }
        }
        Write-Host "    signed and timestamped: $name" -ForegroundColor DarkGray
    }
    [pscustomobject]@{ Ok = $true; File = ''; Output = ''; Error = '' }
}

function Write-SigningFailure {
    <#
    .SYNOPSIS
        Prints a failed Invoke-SignFiles result, with signtool's own words.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Result)

    Write-Host "  ERROR: $($Result.Error)" -ForegroundColor Red
    if ($Result.Output) {
        foreach ($line in ($Result.Output -split "`r?`n")) { Write-Host "         $line" -ForegroundColor Red }
    }
    Write-Host "         If the SimplySign session has lapsed, reconnect it and run the build again." -ForegroundColor Red
}

$commitStamp = Resolve-CommitSha -Override $CommitSha -OverrideProvided:$PSBoundParameters.ContainsKey('CommitSha')

# Both forms of the version, resolved once here rather than inside the MSI
# branch where the read used to live. -SkipMsi never enters that branch, and
# the SBOM stage needs the version on exactly that path (issue #396).
$versionInfo = Get-ProductVersionInfo -PropsPath (Join-Path $RepoRoot "Directory.Build.props")
if (-not $versionInfo.Ok) {
    Write-Host "  ERROR: $($versionInfo.Error)" -ForegroundColor Red
    exit 1
}
$ProductSemVer = $versionInfo.SemVer          # 0.10.0-beta.2, what the SBOM is named after
$MsiProductVersion = $versionInfo.MsiVersion  # 0.10.0.0, the four part version WiX demands

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Certus Build Script" -ForegroundColor Cyan
Write-Host "  Configuration: $Configuration" -ForegroundColor Cyan
Write-Host "  Version: $ProductSemVer" -ForegroundColor Cyan
Write-Host "  Runtime: $Runtime" -ForegroundColor Cyan
Write-Host "  Started: $($BuildStartUtc.ToString('o'))" -ForegroundColor Cyan
if ($commitStamp) {
    Write-Host "  Commit: $($commitStamp.Sha) (from $($commitStamp.Source))" -ForegroundColor Cyan
} else {
    Write-Host "  Commit: none resolved (binaries will carry no commit stamp)" -ForegroundColor Yellow
}
if ($Sign) {
    Write-Host "  Signing: requested (-Sign)" -ForegroundColor Cyan
} else {
    Write-Host "  Signing: not requested (unsigned build)" -ForegroundColor Cyan
}
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Signing preflight (issue #337). Everything a -Sign build needs is proven here,
# before a build of several minutes, and every failure is fatal, because -Sign
# means sign or fail. Without -Sign all of this is skipped, and the build never
# looks for a certificate or for signtool.
$signing = $null
$signingCertificate = $null
$SignedSummary = @()
if ($Sign) {
    Write-Host "Signing preflight..." -ForegroundColor Yellow

    # Only a clean commit is signed, so every signed binary traces to one. That
    # rules out a dirty tree, and also a -CommitSha or environment stamp, which
    # nothing here can check against the tree actually being built.
    if (-not $commitStamp -or $commitStamp.Source -ne 'git HEAD') {
        $why = if (-not $commitStamp) { 'no commit could be resolved' } else { "the commit stamp came from $($commitStamp.Source)" }
        Write-Host "  ERROR: -Sign needs a clean git checkout, and $why." -ForegroundColor Red
        Write-Host "         Every signed binary has to trace to a commit. Commit or stash your changes, then run it again." -ForegroundColor Red
        exit 1
    }

    # signtool is looked for under the Windows SDK root the registry names,
    # because it is not on PATH and its version folder moves with every SDK
    # update. PATH is the last resort.
    $kitsRoot = $null
    foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots')) {
        $value = (Get-ItemProperty -LiteralPath $key -Name KitsRoot10 -ErrorAction SilentlyContinue).KitsRoot10
        if ($value) { $kitsRoot = $value; break }
    }
    if (-not $kitsRoot -and ${env:ProgramFiles(x86)}) { $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10' }
    $signToolFiles = @()
    if ($kitsRoot) {
        $signToolFiles = @(Get-ChildItem -Path (Join-Path $kitsRoot 'bin\*\x64\signtool.exe') -File -ErrorAction SilentlyContinue) +
            @(Get-ChildItem -Path (Join-Path $kitsRoot 'bin\x64\signtool.exe') -File -ErrorAction SilentlyContinue)
    }
    $signTool = Select-SignToolPath -Candidates @($signToolFiles | ForEach-Object { $_.FullName })
    $signToolPath = if ($signTool.Ok) { $signTool.Path } else { (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source }
    if (-not $signToolPath) {
        Write-Host "  ERROR: signtool.exe was not found under the Windows SDK or on PATH." -ForegroundColor Red
        Write-Host "         Install the Windows SDK with its signing tools." -ForegroundColor Red
        exit 1
    }
    Write-Host "  signtool: $signToolPath" -ForegroundColor Gray

    $storeRecords = @(Get-ChildItem -Path Cert:\CurrentUser\My | ForEach-Object {
            $certificate = $_
            [pscustomobject]@{
                Subject       = $certificate.Subject
                Issuer        = $certificate.Issuer
                Thumbprint    = $certificate.Thumbprint
                NotBefore     = $certificate.NotBefore
                NotAfter      = $certificate.NotAfter
                HasPrivateKey = $certificate.HasPrivateKey
                EkuOids       = @($certificate.Extensions |
                    Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
                    ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
            }
        })
    $signingCertificate = Select-SigningCertificate -Certificates $storeRecords -ExpectedName $SigningCertificateName -Now (Get-Date)
    if (-not $signingCertificate.Ok) {
        Write-Host "  ERROR: $($signingCertificate.Error)" -ForegroundColor Red
        # A text match is fine here and only here: it picks which refusals are
        # worth printing, and decides nothing.
        foreach ($near in @($signingCertificate.Rejected | Where-Object { $_.Subject.Contains($SigningCertificateName) })) {
            Write-Host "         $($near.Thumbprint) $($near.Subject): $($near.Reason)" -ForegroundColor Red
        }
        Write-Host "         Is SimplySign Desktop connected? The certificate is read from Cert:\CurrentUser\My." -ForegroundColor Red
        exit 1
    }
    Write-Host "  Certificate: $($signingCertificate.Thumbprint) ($SigningCertificateName), expires $($signingCertificate.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
    if (@($signingCertificate.Qualified).Count -gt 1) {
        Write-Host "  $(@($signingCertificate.Qualified).Count) certificates qualify; the one that expires last was chosen:" -ForegroundColor Gray
        foreach ($q in $signingCertificate.Qualified) {
            Write-Host "    $($q.Thumbprint), valid $($q.NotBefore.ToString('yyyy-MM-dd')) to $($q.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
        }
    }
    if ($signingCertificate.DaysLeft -lt $SigningExpiryWarningDays) {
        Write-Host "  WARNING: the signing certificate expires in $($signingCertificate.DaysLeft) days. Start the reissue now:" -ForegroundColor Yellow
        Write-Host "           the validation data behind it lapses first, and the reissue probably needs it renewed." -ForegroundColor Yellow
    }

    # A failed -Sign build must not leave an older signed installer where the
    # release script looks for one.
    foreach ($stale in @($MsiOutput, $BundleOutput)) {
        if (Test-Path -LiteralPath $stale) { Remove-Item -LiteralPath $stale -Force }
    }
    if (Test-Path -LiteralPath $SigningDir) { Remove-Item -LiteralPath $SigningDir -Recurse -Force }
    New-Item -Path $SigningDir -ItemType Directory -Force | Out-Null

    # Splatted into every Invoke-SignFiles call below.
    $signing = @{
        SignToolPath = $signToolPath
        Thumbprint   = $signingCertificate.Thumbprint
        TimestampUrl = $TimestampUrl
        Description  = $SignatureDescription
        Url          = $SignatureUrl
    }

    # Prove the key and the timestamp authority now, by signing a throwaway
    # script. The certificate being in the store proves neither: it stays
    # there, key and all, while the SimplySign session is disconnected, and
    # signtool then waits instead of failing. This probe and its time limit
    # turn a lapsed session into a clear error two minutes in, instead of a
    # build that fails halfway or never finishes.
    $probe = Join-Path $SigningDir "preflight.ps1"
    Set-Content -LiteralPath $probe -Value "# Signing preflight for commit $($commitStamp.Sha). Deleted once the check passes." -Encoding ascii
    $result = Invoke-SignFiles -Paths @($probe) @signing
    if (-not $result.Ok) {
        Write-SigningFailure -Result $result
        Write-Host "         Nothing was built. The SimplySign session is connected by hand and lasts about two hours." -ForegroundColor Red
        exit 1
    }
    Remove-Item -LiteralPath $probe -Force
    Write-Host "  Preflight signature verified: the key and the timestamp authority both answer" -ForegroundColor Green
    Write-Host ""
}

# Step 0: Clean bin/obj to force a full rebuild
# MSBuild's incremental up-to-date check has misfired in the QA pipeline,
# causing stale DLLs from earlier commits to be re-packaged into every MSI.
# Removing bin/obj eliminates that class of failure at the cost of one
# extra full compile per run.
Write-Host "[0/6] Cleaning bin/obj directories..." -ForegroundColor Yellow
$cleanRoots = @(
    (Join-Path $RepoRoot "src"),
    (Join-Path $RepoRoot "tests")
)
foreach ($root in $cleanRoots) {
    if (-not (Test-Path $root)) { continue }

    # Clean only the .NET project directories. A blanket recursive sweep for any
    # directory named bin or obj also reaches into src/frontend/node_modules and
    # deletes package bin folders, typescript/bin/tsc among them, which breaks
    # 'npm run build' with a confusing "Cannot find module" until 'npm ci' is run
    # again. Step 1 normally reinstalls and masks the damage, but -SkipFrontend
    # leaves the developer's node_modules broken.
    $projectDirs = Get-ChildItem -Path $root -Recurse -File -Filter '*.csproj' -Force |
        Where-Object { $_.FullName -notlike '*\node_modules\*' } |
        Select-Object -ExpandProperty DirectoryName -Unique

    foreach ($projectDir in $projectDirs) {
        foreach ($name in 'bin','obj') {
            $target = Join-Path $projectDir $name
            if (Test-Path $target) {
                # NOTE: deliberately no -ErrorAction SilentlyContinue here. A locked
                # file or permission denial in the QA pipeline was previously swallowed,
                # leaving stale DLLs in bin/ that the next publish then re-packaged
                # into a fresh MSI. Surface the failure instead.
                Remove-Item $target -Recurse -Force
            }
        }
    }
}
Write-Host "  bin/obj cleaned" -ForegroundColor Green
Write-Host ""

# Step 1: Build frontend
if (-not $SkipFrontend) {
    Write-Host "[1/6] Building React frontend..." -ForegroundColor Yellow

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
    Write-Host "[1/6] Skipping frontend build (--SkipFrontend)" -ForegroundColor DarkGray
}

# Step 2: Publish .NET Service
Write-Host ""
Write-Host "[2/6] Publishing Certus.Service..." -ForegroundColor Yellow

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

# /p:SourceRevisionId is what puts "+<sha>" on AssemblyInformationalVersion and
# from there into the Win32 ProductVersion resource of every published assembly
# (issue #112). Omitted entirely when nothing resolved, so a source-only build
# behaves exactly as it did before.
$publishArgs = @(
    "-c", $Configuration,
    "-r", $Runtime,
    "--self-contained", "false",
    "-o", $PublishDir,
    "/p:PublishReadyToRun=true"
)
if ($commitStamp) {
    $publishArgs += "/p:SourceRevisionId=$($commitStamp.Sha)"
}

dotnet publish $ServiceProject @publishArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host "  Publish failed!" -ForegroundColor Red
    exit 1
}

# Diagnostic: log the LastWriteTimeUtc of Certus.Adcs.dll inside the project's
# bin/ directory. If this is older than the build start, the compiler itself
# was a no-op and the cleanup in step 0 did not reach this folder.
$adcsBinDll = Join-Path $RepoRoot "src/Certus.Adcs/bin/$Configuration/net10.0-windows/Certus.Adcs.dll"
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

# Commit stamp assertion (issue #112). This is the check #108 did not have: its
# verification was "Release test suite green, 0 failing", and no test asserts on
# version metadata, so losing the stamp went unnoticed for two QA cycles. The
# stamp is only assertable where the sha is known, which is here and not in the
# test suite, because `dotnet test` also has to pass on a source-only tree.
#
# ProductVersion is read off the Win32 resource, which is written from
# AssemblyInformationalVersion. Verified to survive the ReadyToRun crossgen this
# publish runs with. Both the entry assembly and Certus.Web are checked:
# Certus.Web is the one SettingsController reads to answer /api/settings/info,
# so it is the assembly a regression would actually reach a user through.
#
# Deliberately placed before the MSI step, not inside it, so CI exercises it:
# .github/workflows/pr-build.yml runs ./build.ps1 -SkipMsi.
if ($commitStamp) {
    Write-Host "  Verifying the commit stamp in ProductVersion..." -ForegroundColor Gray
    foreach ($name in @("DucksInARow.Service.dll", "Certus.Web.dll")) {
        $stampedDll = Join-Path $PublishDir $name
        if (-not (Test-Path $stampedDll)) {
            Write-Host "  ERROR: $stampedDll missing after publish." -ForegroundColor Red
            exit 1
        }
        $productVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($stampedDll).ProductVersion
        # Ordinal substring, deliberately not -like. The sha can arrive from
        # CERTUS_COMMIT_SHA or GITHUB_SHA, which nothing here validates, and a
        # wildcard character in it would turn -like into a pattern that matches
        # far more than the literal stamp, so the gate would pass on a binary
        # that never carried it. The null check keeps a missing version
        # resource from reporting as a plain stamp mismatch.
        if ([string]::IsNullOrEmpty($productVersion) -or
            -not $productVersion.Contains($commitStamp.Sha, [StringComparison]::Ordinal)) {
            Write-Host "  ERROR: $name carries no commit stamp (issue #112)." -ForegroundColor Red
            Write-Host "         ProductVersion: '$productVersion'" -ForegroundColor Red
            Write-Host "         Expected it to contain: $($commitStamp.Sha)" -ForegroundColor Red
            Write-Host "         SourceRevisionId did not reach the compiler. Check that" -ForegroundColor Red
            Write-Host "         IncludeSourceRevisionInInformationalVersion is still true in" -ForegroundColor Red
            Write-Host "         Directory.Build.props and that the publish was not a no-op." -ForegroundColor Red
            exit 1
        }
        Write-Host "    $name ProductVersion: $productVersion" -ForegroundColor Gray
    }
    Write-Host "  Commit stamp verified" -ForegroundColor Green
} else {
    Write-Host "  WARNING: no commit resolved, so the published binaries carry no" -ForegroundColor Yellow
    Write-Host "           commit stamp and the #112 check is skipped. Expected when" -ForegroundColor Yellow
    Write-Host "           building from a source snapshot with no .git; pass" -ForegroundColor Yellow
    Write-Host "           -CommitSha or set CERTUS_COMMIT_SHA to stamp anyway." -ForegroundColor Yellow
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

# Signing point 1 of 3 (issue #337): every binary the MSI installs. It has to
# happen here, before the MSI harvest in step 4, because the MSI embeds its
# cabinet: a file signed after the MSI is built never reaches a customer.
if ($Sign) {
    Write-Host "  Signing the binaries the MSI installs..." -ForegroundColor Gray
    $selection = Get-SigningTargets -Files @(Get-ChildItem -Path $PublishDir -File -Recurse) -NeverInstalled $NeverInstalledFiles
    if (-not $selection.Ok) {
        Write-Host "  ERROR: $($selection.Error)" -ForegroundColor Red
        exit 1
    }
    $result = Invoke-SignFiles -Paths @($selection.Targets | ForEach-Object { $_.FullName }) @signing
    if (-not $result.Ok) { Write-SigningFailure -Result $result; exit 1 }
    $SignedSummary += "$(@($selection.Targets).Count) binaries"
    Write-Host "  Signed and timestamped $(@($selection.Targets).Count) binaries" -ForegroundColor Green
}

# Step 3: SBOM (issue #396)
#
# Deliberately between the publish and the MSI. The publish above leaves
# obj/project.assets.json holding the exact graph that was published, which
# -dpr below reuses rather than resolving a second and possibly different one;
# npm ci in step 1 leaves the node_modules the dashboard was built from; and
# .github/workflows/pr-build.yml runs ./build.ps1 -SkipMsi, so CI proves this
# step on every pull request.
#
# It writes to artifacts/sbom and NEVER to artifacts/publish. The MSI harvest
# below generates PublishFiles.wxs from everything under the publish tree, and
# its guards refuse .pdb and .exe but not .json, so a BOM written there would
# silently install itself onto customer machines.
if ($SkipFrontend -and -not $SkipSbom) {
    # The same shape as "-SkipMsi implies -SkipBundle" above. The npm generator
    # reads src/frontend/node_modules, so without step 1 that tree is absent or,
    # worse, stale from an older lockfile. Stale is the dangerous case: it
    # yields a plausible SBOM describing dependencies the shipped bundle was not
    # built from. Skipping keeps the invariant that matters, which is that a
    # file that exists covers both ecosystems.
    Write-Host ""
    Write-Host "  NOTE: -SkipFrontend implies -SkipSbom. This build will produce no SBOM." -ForegroundColor Yellow
    $SkipSbom = $true
}

if (-not $SkipSbom) {
    Write-Host ""
    Write-Host "[3/6] Generating the SBOM..." -ForegroundColor Yellow

    # Wiped rather than written over. artifacts/ survives between builds and
    # only artifacts/publish is cleaned above, so a BOM from an older version
    # would sit here indefinitely and trip the "exactly one match" assertion in
    # release/Publish-Release.ps1 with a confusing message weeks later.
    if (Test-Path $SbomDir) { Remove-Item $SbomDir -Recurse -Force }
    New-Item -Path $SbomDir -ItemType Directory -Force | Out-Null

    $NugetBomPath = Join-Path $SbomDir "nuget.cdx.json"
    $NpmBomPath = Join-Path $SbomDir "npm.cdx.json"
    # Only the merged file carries the product prefix. The two ecosystem
    # sources deliberately do not, because release/Publish-Release.ps1 globs
    # Ducks-in-a-Row-*.cdx.json and asserts exactly one match.
    $MergedBomPath = Join-Path $SbomDir "Ducks-in-a-Row-$ProductSemVer.cdx.json"

    if (-not (Test-Path $CycloneDxExe)) {
        Write-Host "  Installing the pinned SBOM generator ($CycloneDxPackage $CycloneDxVersion)..." -ForegroundColor Gray
        dotnet tool install $CycloneDxPackage --tool-path $ToolsDir --version $CycloneDxVersion
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $CycloneDxExe)) {
            Write-Host "  ERROR: could not install the CycloneDX generator." -ForegroundColor Red
            Write-Host "         It is pinned in this script rather than in .config/dotnet-tools.json," -ForegroundColor Red
            Write-Host "         because that manifest is stripped from the public source snapshot" -ForegroundColor Red
            Write-Host "         and this script has to build from that snapshot." -ForegroundColor Red
            exit 1
        }
    }

    # -dpr means "trust the assets file", and the generator does not fail when
    # there is none: it prints "No packages found" per project, exits 0, and
    # writes a BOM with zero components. Checking the precondition here turns
    # that into an error at the point the operator can act on. The merge below
    # refuses a BOM with no pkg:nuget component as a second line of defence.
    $ServiceAssets = Join-Path $RepoRoot "src/Certus.Service/obj/project.assets.json"
    if (-not (Test-Path $ServiceAssets)) {
        Write-Host "  ERROR: $ServiceAssets is missing, so the SBOM would be empty." -ForegroundColor Red
        Write-Host "         The publish above should have written it. Run 'dotnet restore' and re-run." -ForegroundColor Red
        exit 1
    }

    # -rs   follow project references: Core, Adcs and Web. Nothing else ships.
    #       The tool prints a hint suggesting this is redundant because the root
    #       assets file already holds the full closure. On this repo that hint is
    #       wrong and was measured: without -rs the BOM drops from 69 components
    #       to 31, losing System.Formats.Cbor, the Microsoft.Extensions family
    #       and everything else Certus.Core pulls in through a ProjectReference.
    #       Do not take the hint.
    # -ed   drop packages flagged developmentDependency, which is what takes
    #       Microsoft.EntityFrameworkCore.Design out of a runtime bill. It does
    #       not take that package's own transitive closure with it, so roughly
    #       fifteen design time packages (Microsoft.CodeAnalysis.*, Newtonsoft.Json,
    #       System.Composition.*) are listed here but are not in the product.
    #       The tool's -ef filter would remove them AND their transitives, which
    #       sounds right and is not: measured, it also removes
    #       Microsoft.Extensions.Logging, .Options and .DependencyInjection,
    #       which the service is built on. Over-stating a bill of materials is
    #       recoverable; under-stating one is the failure that matters, so the
    #       filter is deliberately absent.
    # -t    exclude test projects.
    # -rt   the same RID the publish used, so the graph is the one that shipped.
    # -spv  1.6 explicitly: this tool defaults to 1.7 and the npm one cannot go
    #       above 1.6, so both are pinned to the lower ceiling.
    # -ns   no serial number. The merge drops the timestamp, which no flag here
    #       removes; see Merge-CycloneDxBom on why both matter.
    # -sv   the real version, because the tool otherwise names the root 0.0.0.
    Write-Host "  NuGet dependencies..." -ForegroundColor Gray
    & $CycloneDxExe $ServiceProject `
        -o $SbomDir -fn "nuget.cdx.json" -F Json -spv 1.6 `
        -ns -dpr -rs -ed -t -rt $Runtime -sv $ProductSemVer
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $NugetBomPath)) {
        Write-Host "  ERROR: the NuGet SBOM was not generated." -ForegroundColor Red
        exit 1
    }

    # Step 1 above only WARNS when npm is missing, and leaves $SkipFrontend
    # false, so the implication at the top of this stage does not fire and we
    # arrive here on a box with no npm. Say so plainly rather than reporting it
    # as a failed install. Failing is right: half a bill of materials is the one
    # outcome this stage must never produce silently. -SkipSbom is the way to
    # build the installer on such a box, which is what -SkipFrontend was for
    # before this stage existed.
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        Write-Host "  ERROR: npm was not found, so the npm half of the SBOM cannot be generated." -ForegroundColor Red
        Write-Host "         Install Node.js, or re-run with -SkipSbom to build without a bill of materials." -ForegroundColor Red
        exit 1
    }

    if (-not (Test-Path $CycloneDxNpmCli)) {
        Write-Host "  Installing the pinned npm SBOM generator ($CycloneDxNpmVersion)..." -ForegroundColor Gray
        # --no-save and --no-package-lock so nothing is written back into the
        # tool path as a project, and --omit=optional for the reason given at
        # the pin above. Invoked through node against the resolved path rather
        # than through npx, so the version that runs is the pinned one and
        # nothing is resolved from the registry at generation time.
        npm install --no-save --no-package-lock --omit=optional `
            --prefix $ToolsDir "@cyclonedx/cyclonedx-npm@$CycloneDxNpmVersion"
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $CycloneDxNpmCli)) {
            Write-Host "  ERROR: could not install the npm SBOM generator." -ForegroundColor Red
            exit 1
        }
    }
    # --omit dev: the BOM describes what the dashboard ships. vite, eslint,
    # vitest and this generator itself are build tooling and are not in it.
    # --output-reproducible drops both the serial number and the timestamp.
    Write-Host "  npm dependencies..." -ForegroundColor Gray
    Push-Location $FrontendDir
    try {
        & node $CycloneDxNpmCli `
            --output-format JSON --spec-version 1.6 --output-reproducible `
            --omit dev --mc-type application `
            --output-file $NpmBomPath
    } finally {
        Pop-Location
    }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $NpmBomPath)) {
        Write-Host "  ERROR: the npm SBOM was not generated." -ForegroundColor Red
        exit 1
    }

    # Declared from the pin above rather than discovered, because it is neither
    # a NuGet package nor an npm one: the Burn bootstrapper embeds this exe, so
    # the product installs it and a bill of materials that omitted it would
    # understate what lands on the machine. Added unconditionally, including on
    # the -SkipMsi path, so the SBOM CI proves is the SBOM a release ships.
    $HostingBundleComponent = [ordered]@{
        'bom-ref'   = "pkg:generic/dotnet-hosting@$HostingBundleVersion"
        type        = 'framework'
        name        = 'Microsoft ASP.NET Core Hosting Bundle'
        version     = $HostingBundleVersion
        publisher   = 'Microsoft'
        description = 'Embedded in the setup bundle so a clean offline server installs with one file (issue #87).'
        purl        = "pkg:generic/dotnet-hosting@$HostingBundleVersion"
        hashes      = @( [ordered]@{ alg = 'SHA-512'; content = $HostingBundleSha512 } )
        externalReferences = @( [ordered]@{ type = 'distribution'; url = $HostingBundleUrl } )
    }

    $mergedBom = Merge-CycloneDxBom `
        -NugetBomJson ([System.IO.File]::ReadAllText($NugetBomPath, [System.Text.Encoding]::UTF8)) `
        -NpmBomJson ([System.IO.File]::ReadAllText($NpmBomPath, [System.Text.Encoding]::UTF8)) `
        -ProductName "Ducks in a Row" `
        -ProductVersion $ProductSemVer `
        -SpecVersion '1.6' `
        -CommitSha $(if ($commitStamp) { $commitStamp.Sha } else { '' }) `
        -ExtraComponents @($HostingBundleComponent)
    if (-not $mergedBom.Ok) {
        Write-Host "  ERROR: the SBOM merge failed: $($mergedBom.Error)" -ForegroundColor Red
        exit 1
    }

    [System.IO.File]::WriteAllText($MergedBomPath, $mergedBom.Json, [System.Text.UTF8Encoding]::new($false))
    Write-Host "  SBOM → $MergedBomPath" -ForegroundColor Green
    Write-Host "    $($mergedBom.ComponentCount) components: $($mergedBom.NugetCount) NuGet, $($mergedBom.NpmCount) npm, 1 declared" -ForegroundColor Gray
} else {
    Write-Host ""
    Write-Host "[3/6] Skipping SBOM generation (--SkipSbom)" -ForegroundColor DarkGray
}

# Step 4: Build MSI
if (-not $SkipMsi) {
    Write-Host ""
    Write-Host "[4/6] Building MSI installer..." -ForegroundColor Yellow

    if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
        if ($Sign) {
            # Without -Sign a missing WiX only warns, and the build still
            # reports success. A signed build that quietly produced no
            # installer would read the same way, so here it is fatal.
            Write-Host "  ERROR: WiX Toolset not found, so the signed installers cannot be built." -ForegroundColor Red
            Write-Host "         Install: dotnet tool install --global wix --version 4.0.6" -ForegroundColor Red
            exit 1
        }
        Write-Host "  WiX Toolset not found — skipping MSI build" -ForegroundColor DarkYellow
        Write-Host "  Install: dotnet tool install --global wix" -ForegroundColor DarkYellow
    } else {
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

        # Add all files recursively, minus three groups.
        #
        # DucksInARow.Service.exe is handled by ServiceComponent in Certus.wxs.
        #
        # Every .pdb: packaging the symbol files installs them next to their
        # DLLs, where the CLR reads them and prints the build host's absolute
        # source path in customer logs (issue #104). PDBs stay in
        # artifacts/publish for local debugging; they just never ship.
        #
        # The three Certus.Web host files (issue #305). Certus.Web is the
        # development host: it hard wires MockAdcsClient and is never registered
        # as a service, but it is an Sdk.Web project, so the SDK builds it an
        # apphost and the Service publish drags it along. Installed, it opens
        # the service's own database, which is exactly what PR #304's journal
        # mode conversion cannot tolerate. Dropping the apphost alone is not
        # enough: runtimeconfig.json and deps.json are all "dotnet
        # Certus.Web.dll" needs, so all three go and the launch fails in the
        # host before managed code runs. Certus.Web.dll itself stays, because
        # the service loads it for controller and middleware discovery. The
        # three names live in $NeverInstalledFiles at the top, which the
        # signing selection reads too (issue #337).
        $allFiles = Get-ChildItem $PublishDir -File -Recurse | Where-Object {
            $_.Name -ne "DucksInARow.Service.exe" -and
            $_.Extension -ne ".pdb" -and
            $_.Name -notin $NeverInstalledFiles
        }
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

        # Hard guard: no executable may reach the harvested manifest (issue
        # #305). The one executable this product installs is ServiceExe, listed
        # by hand in Certus.wxs, so anything with an .exe extension arriving
        # here is a stowaway. Stated as the invariant rather than as a list of
        # names on purpose: a denylist only catches the apphost we already know
        # about, and the next project referenced into the service would ship its
        # own host silently. If a future release genuinely needs to install a
        # second executable, add it to Certus.wxs as a named component and
        # allow it here deliberately.
        $exeEntries = $xmlLines -match '<File [^>]*Source="[^"]*\.exe"'
        if ($exeEntries) {
            Write-Host "  ERROR: an executable entered the MSI file manifest. The harvest filter regressed (issue #305)." -ForegroundColor Red
            foreach ($entry in $exeEntries) {
                Write-Host "    $($entry.Trim())" -ForegroundColor Red
            }
            exit 1
        }

        $xmlLines | Out-File -FilePath $HarvestWxs -Encoding UTF8
        Write-Host "  Generated $fileCount file entries ($($subdirs.Count) directories)" -ForegroundColor Gray

        # The MSI ProductVersion comes from the shared VersionPrefix in
        # Directory.Build.props, so the installer can never drift from the
        # assemblies it ships. The fourth field stays 0 (MSI ignores it for
        # upgrade detection anyway). Resolved at the top of this script since
        # issue #396; the value WiX gets is unchanged. It is deliberately not
        # $ProductSemVer: a prerelease suffix is not a legal MSI version.
        Write-Host "  MSI ProductVersion: $MsiProductVersion" -ForegroundColor Gray

        wix build $WxsFile $UiWxsFile $HarvestWxs -d "ProductVersion=$MsiProductVersion" -o $MsiOutput -bindpath $PublishDir -bindpath $BrandingDir -ext WixToolset.Firewall.wixext -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext -arch x64

        if ($LASTEXITCODE -ne 0) {
            Write-Host "  MSI build failed!" -ForegroundColor Red
            if (Test-Path $HarvestWxs) { Remove-Item $HarvestWxs -Force }
            exit 1
        }
        Write-Host "  MSI built to $MsiOutput" -ForegroundColor Green

        # Clean up generated file
        if (Test-Path $HarvestWxs) { Remove-Item $HarvestWxs -Force }

        # Signing point 2 of 3 (issue #337): the MSI, before the bundle below is
        # built. The bundle embeds the MSI as it is at bundle build time, so
        # signing it afterwards would ship an unsigned copy inside Setup.exe
        # beside a signed one: two different MSIs under one version.
        if ($Sign) {
            $result = Invoke-SignFiles -Paths @($MsiOutput) @signing
            if (-not $result.Ok) { Write-SigningFailure -Result $result; exit 1 }
            $SignedSummary += "the MSI"
            Write-Host "  MSI signed and timestamped" -ForegroundColor Green
        }

        # Step 5: Setup bundle (issue #87). Wraps the MSI just built in a Burn
        # bootstrapper that chains the embedded ASP.NET Core Hosting Bundle
        # first, so a clean offline server installs from one file. Lives
        # inside the MSI branch on purpose: wix presence and $MsiOutput are
        # established here, and -SkipMsi (used by CI) skips the bundle too, so
        # CI never downloads the payload.
        if (-not $SkipBundle) {
            Write-Host ""
            Write-Host "[5/6] Building setup bundle..." -ForegroundColor Yellow

            # Drift guard: the embedded runtime major must match the service
            # target framework major, or the bundle would install a runtime
            # the app cannot run on. Parse the csproj itself (net10.0-windows),
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

            wix build $BundleWxs -d "ProductVersion=$MsiProductVersion" -d "HostingBundleVersion=$HostingBundleVersion" -d "HostingBundleMajor=$runtimeMajor" -d "HostingBundleExe=$HostingBundleExe" -d "MsiPath=$MsiOutput" -o $BundleOutput -bindpath $BrandingDir -ext WixToolset.Bal.wixext -ext WixToolset.Netfx.wixext -arch x64

            if ($LASTEXITCODE -ne 0) {
                Write-Host "  Bundle build failed!" -ForegroundColor Red
                exit 1
            }
            Write-Host "  Bundle built to $BundleOutput" -ForegroundColor Green

            # Signing point 3 of 3 (issue #337): the Burn engine, then the
            # bundle. A bundle is its engine with the payload container
            # attached, and the engine needs a signature of its own: Burn
            # caches it at install and runs that cached copy for repair, modify
            # and uninstall, and the stub WiX ships is unsigned. So the engine
            # is detached, signed and reattached, and the result is signed as a
            # whole. The Hosting Bundle exe inside is never signed here:
            # Microsoft signed it, and this script pins it by SHA-512.
            if ($Sign) {
                Write-Host "  Signing the bundle and its engine..." -ForegroundColor Gray
                $engine = Join-Path $SigningDir "engine.exe"
                $reattached = Join-Path $SigningDir "Ducks-in-a-Row-Setup.exe"
                wix burn detach $BundleOutput -engine $engine
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $engine)) {
                    Write-Host "  ERROR: wix burn detach failed (exit $LASTEXITCODE)." -ForegroundColor Red
                    exit 1
                }
                $result = Invoke-SignFiles -Paths @($engine) @signing
                if (-not $result.Ok) { Write-SigningFailure -Result $result; exit 1 }
                wix burn reattach $BundleOutput -engine $engine -o $reattached
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $reattached)) {
                    Write-Host "  ERROR: wix burn reattach failed (exit $LASTEXITCODE)." -ForegroundColor Red
                    exit 1
                }
                $result = Invoke-SignFiles -Paths @($reattached) @signing
                if (-not $result.Ok) { Write-SigningFailure -Result $result; exit 1 }

                # Two proofs about what is inside the signed bundle, since the
                # outer signature says nothing about either. The engine detached
                # again from the finished file must carry the signature this
                # build put on the engine, which shows the reattach used the
                # signed engine; Test-SignedEngineCarried explains why that is
                # read from the bytes rather than asked of Windows. And one
                # payload must be byte identical to the signed MSI, which shows
                # the bundle was built after the MSI was signed. wix burn
                # extract names payloads by their id (a0, a1) with no
                # extension, so the match is by hash, never by name.
                $engineCheck = Join-Path $SigningDir "engine-check.exe"
                wix burn detach $reattached -engine $engineCheck
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $engineCheck)) {
                    Write-Host "  ERROR: wix burn detach of the signed bundle failed (exit $LASTEXITCODE)." -ForegroundColor Red
                    exit 1
                }
                $carried = Test-SignedEngineCarried -SignedEngine ([System.IO.File]::ReadAllBytes($engine)) `
                    -DetachedEngine ([System.IO.File]::ReadAllBytes($engineCheck))
                if (-not $carried.Ok) {
                    Write-Host "  ERROR: the finished bundle does not carry the engine this build signed: $($carried.Error)." -ForegroundColor Red
                    exit 1
                }
                $extractDir = Join-Path $SigningDir "extract"
                wix burn extract $reattached -o $extractDir
                if ($LASTEXITCODE -ne 0) {
                    Write-Host "  ERROR: wix burn extract of the signed bundle failed (exit $LASTEXITCODE)." -ForegroundColor Red
                    exit 1
                }
                $signedMsiHash = (Get-FileHash -LiteralPath $MsiOutput -Algorithm SHA256).Hash
                $embeddedMsi = @(Get-ChildItem -Path $extractDir -File -Recurse |
                        Where-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash -eq $signedMsiHash })
                if ($embeddedMsi.Count -ne 1) {
                    Write-Host "  ERROR: the bundle does not carry the signed MSI byte for byte ($($embeddedMsi.Count) payloads match it)." -ForegroundColor Red
                    Write-Host "         The MSI has to be signed before the bundle is built." -ForegroundColor Red
                    exit 1
                }

                Move-Item -LiteralPath $reattached -Destination $BundleOutput -Force
                $SignedSummary += "the bundle and its engine"
                Write-Host "  Bundle and engine signed and timestamped; the MSI inside is the signed one" -ForegroundColor Green
            }
        } else {
            Write-Host ""
            Write-Host "[5/6] Skipping setup bundle (--SkipBundle)" -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host "[4/6] Skipping MSI build (--SkipMsi)" -ForegroundColor DarkGray
}

# Step 6 (optional): Build test projects
if ($IncludeTests) {
    Write-Host ""
    Write-Host "[6/6] Building test projects..." -ForegroundColor Yellow

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

# The signing scratch folder holds the detached engines and the extracted
# payloads, about 140 MB, and nothing in it ships.
if ($Sign -and (Test-Path -LiteralPath $SigningDir)) {
    Remove-Item -LiteralPath $SigningDir -Recurse -Force
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Build complete!" -ForegroundColor Green
if ($Sign) {
    Write-Host "  Signed and timestamped: $($SignedSummary -join ', ')" -ForegroundColor Green
    Write-Host "  Certificate: $($signingCertificate.Thumbprint) ($SigningCertificateName), expires $($signingCertificate.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Green
} else {
    Write-Host "  Unsigned build (-Sign was not passed)" -ForegroundColor Gray
}
Write-Host "========================================" -ForegroundColor Cyan
