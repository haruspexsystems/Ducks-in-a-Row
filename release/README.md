# Publishing a release

`Publish-Release.ps1` moves a release from the private dev repo (this one)
through the staging mirror to the public repo, in two phases you run
separately so you can test staging before anyone outside sees it.

```
Certus (private, this repo)
  --[staging phase]--> lethe377/Ducks-in-a-Row (staging mirror)
                              --[public phase]--> haruspexsystems/Ducks-in-a-Row (public)
```

## What each phase does

**Staging** (`-Stage staging`, the default): builds the installers with
`build.ps1`, computes a `SHA256SUMS` file, assembles a source snapshot from the
current commit's tracked files with the private only paths stripped (see
`$ExcludePaths` at the top of the script), and publishes all of it to the
staging repo as a tagged GitHub prerelease. This is the point to actually
install the built MSI or bundle somewhere and confirm it behaves like you
expect, since staging is private and nobody else sees it.

**Public** (`-Stage public`): does not rebuild anything. It downloads the exact
assets already published to staging for the given tag and pushes the exact
same source tree, so what goes public is bit for bit what you already tested
on staging.

Use `-DryRun` on either phase to do everything except push or create the
GitHub release, so you can inspect the assembled snapshot and computed
checksums first.

## Before you cut a release

1. **Bump `VersionPrefix` in `Directory.Build.props`** to match the release,
   as its own normal reviewed commit. For `-Version 0.10.0-beta.1` that means
   `VersionPrefix` must be `0.10.0` (the script checks this and refuses to
   build otherwise). WiX needs a plain four part numeric version, so the
   `-beta.1` part only ever appears in the git tag and the release title, not
   in the file version Windows shows.
2. Be on a clean `main` that is up to date with `origin/main`.
3. Make sure `CHANGELOG.md` has real content under `## [Unreleased]` — the
   script pulls that section verbatim as the release notes.

## The public phase needs your own GitHub session

`haruspexsystems/Ducks-in-a-Row` is a repo under the Haruspex org. As of this
writing the `lethe377` account (used for `gh` in most automated contexts) has
only read access there, not write, so the public phase's push and
`gh release create` will fail with a clear permission error under that
session. Run `-Stage public` from a session authenticated as whichever account
actually administers the Haruspex org, or grant `lethe377` write access to the
repo first if you'd rather that account handle it end to end.

## Examples

```powershell
# Validate everything without publishing anything
./release/Publish-Release.ps1 -Version 0.10.0-beta.1 -DryRun

# Cut the beta to staging, then go test the installer
./release/Publish-Release.ps1 -Version 0.10.0-beta.1

# Once staging looks good, promote the same bits to the public repo
./release/Publish-Release.ps1 -Version 0.10.0-beta.1 -Stage public
```
