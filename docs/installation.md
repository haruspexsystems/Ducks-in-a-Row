# Installation

Two ways to install. Use the setup bundle unless you have a reason not to.

| Installer | What it does | When to use it |
|---|---|---|
| `Ducks-in-a-Row-Setup.exe` | Installs or updates the ASP.NET Core 10 runtime when the server's is missing or older, then runs the MSI | Almost always, including on servers with no internet access |
| `Ducks-in-a-Row.msi` | The application only. Fails to start if the runtime is absent | Deployment systems that manage the runtime themselves |

The setup bundle carries the runtime inside it, so an offline server installs
from the one file. It installs that runtime, as the full ASP.NET Core Hosting
Bundle with the ASP.NET Core Module for IIS, when the server has no ASP.NET Core
10 runtime or only an older update of it, which it replaces, and skips it when
the server already has the same update or a later one. It never
removes the runtime on uninstall, because other applications on the server may
be using it.

Two things to know when the bundle installs or updates the runtime:

- **ASP.NET Core sites in IIS restart.** On a server that already has the
  runtime, IIS itself keeps running, but the worker processes that host ASP.NET
  Core sites are stopped while the ASP.NET Core Module is replaced, and start
  again on their next request. Run the setup in a quiet period on such a server.
- **The setup never restarts the server for the runtime.** The runtime
  installer can ask for a restart, for example when a file it replaces is in
  use. The setup then carries on, installs Ducks in a Row, and finishes as a
  success (exit code 0) with no restart prompt. The only sign is in the setup
  log: the line for the `AspNetCoreHostingBundle` package says
  `exited with code: 0xbc2` (3010). If you find it, restart the server when it
  suits you, so the runtime update is complete.

The bare MSI does not install the runtime. Without it the service fails before
any managed code runs, and the installer reports **Error 1920**, which almost
never means what it says. See [troubleshooting](troubleshooting.md).

## Check the download

Both installers are signed by Haruspex Systems B.V. and timestamped. Check a
download before you run it. The same commands work on the MSI.

```powershell
$signature = Get-AuthenticodeSignature .\Ducks-in-a-Row-Setup.exe
$signature.Status                           # Valid
$signature.SignerCertificate.Subject        # CN=Haruspex Systems B.V., O=Haruspex Systems B.V., ...
$signature.TimeStamperCertificate.Subject   # a Certum timestamp authority
```

The status must be `Valid`, the signer must be Haruspex Systems B.V., and the
timestamp must be there: it is what keeps the signature valid after the signing
certificate itself expires. Anything else, such as `NotSigned`, `HashMismatch`,
or a different signer, means the file is not the one we published. Do not run
it.

Compare the checksum too, against the `SHA256SUMS` file on the release page:

```powershell
Get-FileHash .\Ducks-in-a-Row-Setup.exe -Algorithm SHA256
```

When you run a signed installer, the Windows permission prompt names Haruspex
Systems B.V. as the verified publisher. Windows SmartScreen may still warn about
a new release while the signing certificate builds up a reputation with
Microsoft. If it does, **More info** should name the same publisher. If it names
anyone else, or an unknown publisher, do not run the file.

Every `.exe` and `.dll` the installer puts in the application folder carries the
same signature, so an App Control for Business (WDAC) or AppLocker policy can
allow everything it installs with one publisher rule. The setup program itself
also runs a few helpers from a temporary folder while it works; those are signed
by their own publishers, the WiX Toolset and Microsoft.

Releases up to and including 0.10.0-beta.1 were not signed. For those, the
checksum is the only check.

## What the installer does

| Action | Details |
|---|---|
| Install the application | `C:\Program Files\Ducks in a Row\`, or the folder you choose |
| Create the data folder | `C:\ProgramData\Ducks in a Row\`, or the folder you choose. Its location is recorded in the registry so the service can find it |
| Create the log folder | `logs\` inside the data folder |
| Register the service | `DucksInARow`, display name "Ducks in a Row Certificate Proxy", starts automatically, runs as LocalSystem |
| Set service recovery | Restart after the first and second failures, nothing after the third, failure count reset after a day. See [if the service stops](#if-the-service-stops) |
| Start the service | Immediately after install, unless you clear the option |
| Record the instance mode | The registry value `Mode`, `monitor` or `full`, beside the data folder's location. See [monitor mode](monitor-mode.md) |
| Create the modules folder | `modules\` inside the application folder, empty, with the application folder's permissions. The [paid module](licence.md) installs into it |
| Record the module contract | The registry value `ModuleContractVersion`, for example `1.0`, beside the data folder's location. The paid module's installer reads it to check that the module fits this release |
| Open firewall rules | Inbound TCP 5000 and TCP 5001 |
| Add a Start Menu shortcut | Opens the web interface |

The data folder is not removed when you uninstall. See
[uninstalling](uninstall.md).

## The install wizard

Running either installer interactively gives you five choices:

1. The destination folder, default `C:\Program Files\Ducks in a Row\`.
2. The data folder for the database, logs and runtime configuration, default
   `C:\ProgramData\Ducks in a Row\`.
3. Whether to start the service immediately.
4. Whether to run in [monitor mode](monitor-mode.md): watch the CA, never issue
   or revoke. Unchecked by default. It is the low risk way to start on a
   production CA, and switching to issuance later needs no reinstall.
5. Whether to open the setup page in your browser from the final screen.

Choose the data folder now. Moving it during a later upgrade is not supported.
It holds the database too, which cannot be moved out of it on its own, so if
the data belongs on another disk, choose a folder on that disk here. Use a
local disk: a network share is not supported.

An upgrade keeps the folders and the mode chosen before, and on a monitor mode
server the monitor mode box is already ticked. If someone set the registry value
`Mode` by hand to something the service cannot use, setup stops and names it;
see [troubleshooting](troubleshooting.md#setup-stops-the-registry-value-mode-cannot-be-used).

If the server has the [paid module](licence.md) installed, and the new release
needs a module built for it, the wizard opens with a warning page before
anything else. After such an upgrade the installed module does not load, so the
paid features stay off until you install the module built for the new release.
Certificate issuance and renewal are not affected. **Continue** upgrades anyway;
**Cancel** leaves the installed version as it is.

## Unattended install

```powershell
msiexec /i Ducks-in-a-Row.msi /qn `
  INSTALLFOLDER="D:\Ducks in a Row" `
  DATAFOLDER="D:\DucksData" `
  START_SERVICE=0 `
  /l*v "C:\temp\ducks-install.log"
```

| Property | Default | Meaning |
|---|---|---|
| `INSTALLFOLDER` | `C:\Program Files\Ducks in a Row` | Where the application goes |
| `DATAFOLDER` | `C:\ProgramData\Ducks in a Row` | Where the database, logs and settings go |
| `START_SERVICE` | `1` | `0` registers the service but leaves it stopped until the next boot or a manual start |
| `MONITOR_ONLY` | not set | `1` installs in [monitor mode](monitor-mode.md). Leave it out for full mode; on an upgrade, leaving it out keeps the mode the server already has. Any other value is refused |
| `ALLOW_INCOMPATIBLE_MODULE` | not set | `1` lets an unattended upgrade go ahead although the installed [paid module](licence.md) will not load after it. Without it such an upgrade stops and says why. It is never remembered, and any other value is refused |

The prompt to open the setup page appears only in the interactive wizard, so a
`/qn` install never launches a browser. The same goes for the paid module
warning page: an install with no wizard, which includes the setup bundle's
`/quiet` and `/passive`, stops instead of asking, unless you pass
`ALLOW_INCOMPATIBLE_MODULE=1`.

The setup bundle passes the same five properties to the MSI. Give them on its own
command line:

```powershell
Ducks-in-a-Row-Setup.exe /quiet /norestart MONITOR_ONLY=1 START_SERVICE=0 /log "C:\temp\ducks-bundle.log"
```

Keep `/norestart` on unattended runs of the setup bundle. The runtime update
never restarts the server, but the Ducks in a Row installer itself can still ask
for a restart if a file it replaces stays in use. With `/norestart` the setup
then exits with code 3010 and you restart when it suits you; without it,
`/quiet` and `/passive` restart the server for that. Exit code 0 means done.

## If the service stops

The installer sets the service to recover by itself, twice:

| Failure | What Windows does |
|---|---|
| First | Restarts the service after 30 seconds |
| Second | Restarts the service after 30 seconds |
| Third and later | Nothing: the service stays stopped |

Windows forgets the count once a day passes with no failure. Check what is set
with:

```powershell
sc.exe qfailure DucksInARow
```

**Why two restarts.** The [paid module](licence.md) runs inside the service. A
fault in it can end the service's process outright, and the service notes each
time that happens while the module is starting up. After the second time it sets
that version of the module aside, and starts without it from then on. So two
restarts bring the service back with certificate issuance and renewal working,
whatever the module did. The paid features stay off until the module is fixed,
and the licence page says so.

**Why not more.** Almost every other way this service stops is a fault it found
while starting, usually a configuration it cannot work with. It writes the
reason to the log and stops. A restart does not fix a configuration, so a third
restart would only have it reach the same fault again, and you would be left
watching it flap rather than seeing it plainly down with the reason in the log.

**A configuration the service refuses at startup is not restarted at all.**
Windows records it as a service that failed to start (System log events 7009 and
7000 from the Service Control Manager) rather than one that ended unexpectedly
(7031), and runs no recovery action for it. The service stays stopped, with the
reason in its log. This was measured with a `Mode` value the service refuses,
not reasoned about.

**The failure flag stays off.** Windows runs these actions when a service ends
without reporting that it stopped. A service that does report stopped, with an
error code, counts as a failure only when the failure flag is on, and the
installer leaves it off.

Every install, repair and upgrade sets these actions again, and replaces any you
set yourself with `sc.exe failure`. None of this is a substitute for reading the
log. The reason the service stopped is in `logs\ducks-<date>.log` in the data
folder.

Releases before 1.1 configured no recovery at all.

## After installing

The service serves the setup wizard until you complete it, and every CA
operation answers 503 until then. Open `https://your-server:5001` and work
through the wizard; the [quickstart](quickstart.md) walks through each step.

Then confirm the install is healthy with [verifying your
installation](verifying.md).

## Upgrading

Ducks in a Row never checks for a new release and never installs one by itself.
It makes no connection to us or to anyone else, so there is no automatic update
setting to turn off. You learn that a release exists from the
[releases page](https://github.com/haruspexsystems/Ducks-in-a-Row/releases), the
repository's security advisories, the [changelog](../CHANGELOG.md), or the
security notices list you can sign up for; [SUPPORT.md](../SUPPORT.md) says
how. A security fix ships as its own patch release of the latest release where
that is feasible, and upgrading to it is free of charge; see
[SECURITY.md](../SECURITY.md).

To upgrade:

1. Take a copy of the data folder first, as
   [backup and restore](backup-and-restore.md) describes. An upgrade keeps it,
   and the copy is what you fall back on if anything goes wrong.
2. [Check the download](#check-the-download): the signature, the signer and
   the checksum, exactly as for a first install.
3. Run the new `Ducks-in-a-Row-Setup.exe` on the server, over the existing
   installation, interactively or unattended with the same command as a fresh
   install. The bundle first brings the ASP.NET Core runtime up to the update
   it carries when the server's is missing or older; the start of this page
   says what that means for IIS sites and a restart. The bare MSI never does,
   so with the MSI, install the runtime the release notes name before you run
   it. The wizard shows the
   folders chosen before and the monitor mode box as the server has it, so
   nothing has to be chosen again; leaving `MONITOR_ONLY` out of an unattended
   upgrade keeps the mode. Moving the data folder during an upgrade is not
   supported.
4. If the server has the [paid module](licence.md) installed and the new
   release needs a module built for it, the wizard opens with a warning page
   first, and an unattended upgrade stops unless you pass
   `ALLOW_INCOMPATIBLE_MODULE=1`. See [the install wizard](#the-install-wizard)
   for what the warning means; certificate issuance and renewal are not
   affected either way.
5. The installer stops the service, removes the previous version, installs the
   new one, and starts the service again. ACME clients and the dashboard lose
   their connection while that runs, and a client retries on its next renewal
   attempt. An older release cannot be
   installed over a newer one; the installer refuses with "A newer version of
   Ducks in a Row is already installed".

What an upgrade keeps:

- The data folder, with the database, the logs, `settings.json`,
  `ducks-setup.json` and the Data Protection keyring in `keys\`. Your CA
  connection, templates, policies, ACME accounts, alert settings and history
  all live there.
- The install folder and the data folder you chose, and the instance mode.
- The server's HTTPS certificate in the machine store, and the thumbprint in
  `settings.json` that names it.
- The firewall rules, the service registration and its recovery actions, which
  the installer sets again.
- A paid module in the `modules\` folder, which loads again only if it was
  built for the new release.

Afterwards, run [verifying your installation](verifying.md): the first check
confirms the installed files carry our signature, and the health check that the
service is up. Then read the [changelog](../CHANGELOG.md) entry for the
release, and `logs\ducks-<date>.log` once: a setting the new release finds
wrong is reported there as a startup warning that names it.
