# Uninstalling

Remove Ducks in a Row through Add or remove programs, or from the command line:

```powershell
msiexec /x Ducks-in-a-Row.msi
```

If you installed with the setup bundle, uninstall the bundle rather than the
MSI, so the entry in Add or remove programs is cleaned up too.

## What is removed

- Every application file from `C:\Program Files\Ducks in a Row\`.
- The `DucksInARow` service registration. The service is stopped first.
- The firewall rules the installer created.
- The Start Menu shortcut.

## What is kept

- The SQLite database, `ducks.db` in the data folder.
- The log files in `logs\`.
- `settings.json` and `ducks-setup.json`.
- The Data Protection keyring in `keys\`.
- The data folder itself, by default `C:\ProgramData\Ducks in a Row\`.

Keeping the data folder is deliberate. It means an uninstall and reinstall, or
an upgrade that goes through one, does not lose your CA configuration,
your ACME accounts or your alert history.

**The ASP.NET Core runtime is never removed**, even if the setup bundle
installed it. Other applications on the server may be using it.

## The -wal and -shm files are gone, and that is correct

While the service is running you will see `ducks.db-wal` and `ducks.db-shm`
beside the database. After an uninstall they are gone.

That is a good sign, not a loss. The database uses write ahead logging, and
SQLite writes that log back into `ducks.db` and removes both files when the last
connection closes, which is exactly what happens when the uninstaller stops the
service. Their absence means every committed change reached `ducks.db`, and that
`ducks.db` on its own is now a complete database you can copy or restore.

## Removing everything

To remove the data as well, delete the folder by hand after uninstalling:

```powershell
Remove-Item -Recurse -Force "C:\ProgramData\Ducks in a Row"
```

> [!WARNING]
> **Take a copy first if you might reinstall.** The `keys\` folder in there is
> the Data Protection keyring, and it is the only thing that can decrypt stored
> EAB secrets and a dashboard saved SMTP password. Deleting it is not
> recoverable by reinstalling. See [backup and restore](backup-and-restore.md).

## Certificates already issued are not affected

Uninstalling removes the proxy, not the certificates it obtained. Every
certificate already issued stays valid until it expires, and stays in the CA's
own database. Nothing is revoked.

That cuts both ways: if you are decommissioning the server and want the
certificates it obtained to stop working, revoke them **before** you uninstall,
while the dashboard can still reach them. See [revocation](revocation.md).
