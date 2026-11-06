# Uninstalling

Remove Ducks in a Row through Add or remove programs, or from the command line:

```powershell
msiexec /x Ducks-in-a-Row.msi
```

If you installed with the setup bundle, uninstall the bundle rather than the
MSI, so the entry in Add or remove programs is cleaned up too.

## What is removed

- Every application file from `C:\Program Files\Ducks in a Row\`, and the
  folder itself.
- The `modules` folder in it, when it is empty. If the [paid module](licence.md)
  is installed, the folder stays until the paid module's own installer removes
  it.
- The `DucksInARow` service registration. The service is stopped first, which
  frees ports 5000 and 5001: the service holds them only while it runs, and
  there is no HTTP.sys binding or URL reservation to remove.
- The registry key `HKLM\Software\Haruspex Systems\Ducks in a Row` with every
  value in it: the install and data folder locations, the instance mode, the
  module contract version and the two installer markers.
- The firewall rules the installer created.
- The Start Menu shortcut and its folder.
- The entry in Add or remove programs.

## What is kept

- The SQLite database, `ducks.db` in the data folder.
- The log files in `logs\`.
- `settings.json` and `ducks-setup.json`.
- The Data Protection keyring in `keys\`.
- The self signed certificate the service generated, `ducks-selfsigned.bin`,
  encrypted with the keyring.
- The `licence` folder, when a licence was installed, and the `modules` folder
  the paid module keeps its state in, when one was installed.
- The data folder itself, by default `C:\ProgramData\Ducks in a Row\`, which
  holds all of the above.

Keeping the data folder is deliberate. It means an uninstall and reinstall, or
an upgrade that goes through one, does not lose your CA configuration,
your ACME accounts or your alert history.

Three more things stay, outside the data folder:

- **The HTTPS certificate in the machine store.** When the setup wizard, the
  Renew button or the automatic renewal enrolled the server's certificate from
  your CA, that certificate and its private key stay in `LocalMachine\My`,
  with the friendly name `Ducks in a Row HTTPS`. A certificate somebody else
  installed and you chose in monitor mode was never ours to remove.
- **The event log source `DucksInARow`**, a registry key under
  `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application`, which the
  service registers the first time it runs.
- **The rights granted to the server's computer account** on the CA and on the
  certificate templates. They live on the CA and in Active Directory, and
  nothing on this server can remove them.

**The ASP.NET Core runtime is never removed**, even if the setup bundle
installed it. Other applications on the server may be using it.

This list was measured on a lab server, not read from the installer's source:
a fresh install, the setup wizard completed and the server's certificate
enrolled from the CA, then an uninstall and an inventory of the registry, the
file system, the certificate stores, HTTP.sys, the firewall and the CA.

## The -wal and -shm files are gone, and that is correct

While the service is running you will see `ducks.db-wal` and `ducks.db-shm`
beside the database. After an uninstall they are gone.

That is a good sign, not a loss. The database uses write ahead logging, and
SQLite writes that log back into `ducks.db` and removes both files when the last
connection closes, which is exactly what happens when the uninstaller stops the
service. Their absence means every committed change reached `ducks.db`, and that
`ducks.db` on its own is now a complete database you can copy or restore.

## Removing everything

Uninstalling, then deleting the data folder, returns the server to the state it
was in before Ducks in a Row was installed, apart from the runtime and the
three items below. Delete the folder by hand after uninstalling:

```powershell
Remove-Item -Recurse -Force "C:\ProgramData\Ducks in a Row"
```

> [!WARNING]
> **Take a copy first if you might reinstall.** The `keys\` folder in there is
> the Data Protection keyring, and it is the only thing that can decrypt stored
> EAB secrets and a dashboard saved SMTP password. Deleting it is not
> recoverable by reinstalling. See [backup and restore](backup-and-restore.md).

Deleting the folder takes the database, the logs, the configuration files, the
keyring, the self signed certificate, the `licence` folder and the paid
module's state with it. Then, from an elevated Windows PowerShell session:

1. **Remove the HTTPS certificate** the service enrolled, with its private key.
   Only certificates carrying the service's friendly name are matched, so a
   certificate somebody else installed is left alone:

   ```powershell
   Get-ChildItem Cert:\LocalMachine\My |
     Where-Object FriendlyName -eq 'Ducks in a Row HTTPS' |
     Remove-Item -DeleteKey
   ```

   `-DeleteKey` removes the private key with the certificate; without it the
   key container stays on disk.

   The same certificate can be removed in `certlm.msc`, under Personal. If you
   want it to stop working as well as to disappear, revoke it at the CA before
   you delete it; it stays valid at the CA until it expires otherwise.

2. **Remove the event log source.** `Remove-EventLog` exists in Windows
   PowerShell 5.1, not in PowerShell 7:

   ```powershell
   Remove-EventLog -Source DucksInARow
   ```

3. **Ask the CA team to take back the rights** the server's computer account
   was granted: Enroll on each exposed template, Read and Request Certificates
   on the CA, and Issue and Manage Certificates if revocation was enabled.
   [What to ask your AD and CA team](ad-and-ca-team-request.md) lists each
   right and where it was granted, so the same page serves as the list to
   revoke. If the server itself is being decommissioned, disabling or deleting
   its computer account removes them all at once.

The ASP.NET Core runtime stays, as above. Remove it through Add or remove
programs only if nothing else on the server uses it.

## Certificates already issued are not affected

Uninstalling removes the proxy, not the certificates it obtained. Every
certificate already issued stays valid until it expires, and stays in the CA's
own database. Nothing is revoked.

That cuts both ways: if you are decommissioning the server and want the
certificates it obtained to stop working, revoke them **before** you uninstall,
while the dashboard can still reach them. See [revocation](revocation.md).
