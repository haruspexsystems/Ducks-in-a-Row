# Installation

Two ways to install. Use the setup bundle unless you have a reason not to.

| Installer | What it does | When to use it |
|---|---|---|
| `Ducks-in-a-Row-Setup.exe` | Installs the ASP.NET Core 10 runtime if it is missing, then runs the MSI | Almost always, including on servers with no internet access |
| `Ducks-in-a-Row.msi` | The application only. Fails to start if the runtime is absent | Deployment systems that manage the runtime themselves |

The setup bundle carries the runtime inside it, so an offline server installs
from the one file. It detects an existing ASP.NET Core 10 runtime and skips the
install when one is present, and it never removes the runtime on uninstall,
because other applications on the server may be using it.

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
| Start the service | Immediately after install, unless you clear the option |
| Open firewall rules | Inbound TCP 5000 and TCP 5001 |
| Add a Start Menu shortcut | Opens the web interface |

The data folder is not removed when you uninstall. See
[uninstalling](uninstall.md).

## The install wizard

Running either installer interactively gives you four choices:

1. The destination folder, default `C:\Program Files\Ducks in a Row\`.
2. The data folder for the database, logs and runtime configuration, default
   `C:\ProgramData\Ducks in a Row\`.
3. Whether to start the service immediately.
4. Whether to open the setup page in your browser from the final screen.

Choose the data folder now. Moving it during a later upgrade is not supported.

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

The prompt to open the setup page appears only in the interactive wizard, so a
`/qn` install never launches a browser.

The setup bundle accepts the same silent switches through its own command line:

```powershell
Ducks-in-a-Row-Setup.exe /quiet /log "C:\temp\ducks-bundle.log"
```

## If the service stops

**The installer deliberately does not configure automatic service recovery.** A
service that stops stays stopped until something starts it.

The reason is what this service does when it fails. Almost every way it stops is
a fault it found while starting, and usually that is a configuration it cannot
work with. It writes the reason to the log, sets a nonzero exit code and stops.
A restart policy does not help there: the configuration is still wrong, so the
service reaches the same fault again, and you are left watching it flap instead
of seeing it plainly down with the reason waiting in the log.

There is a second reason, and it decides whether a restart policy does anything
at all. Windows runs recovery actions when a service dies without reporting that
it stopped. A service that does report stopped, and carries an error code with
it, counts as a failure only once you turn the failure flag on as well. Which of
those two a fault here produces is worth checking on your own box before you
rely on a restart policy, because the difference decides whether it ever fires.

If you want the restart policy anyway, set it yourself, once, after installing:

```powershell
sc.exe failure DucksInARow reset= 86400 `
  actions= restart/5000/restart/10000/restart/30000
```

That restarts the service after five seconds on the first failure, ten on the
second and thirty thereafter, and forgets the failure count after a day. Add the
failure flag if you also want a stop that reports an error to count:

```powershell
sc.exe failureflag DucksInARow 1
```

Neither is a substitute for reading the log. A service that keeps failing on a
bad configuration keeps failing after a restart, and the reason is in
`logs\ducks-<date>.log` in the data folder.

## After installing

The service serves the setup wizard until you complete it, and every CA
operation answers 503 until then. Open `https://your-server:5001` and work
through the wizard; the [quickstart](quickstart.md) walks through each step.

Then confirm the install is healthy with [verifying your
installation](verifying.md).
