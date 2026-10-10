# Backup and restore

Everything worth backing up is in one folder. One thing in it does not survive
being moved to another machine, and knowing which is the whole of this page.

## What to back up

The data folder, by default `C:\ProgramData\Ducks in a Row\`. If you chose a
different one at install time it is recorded in the registry under
`HKLM\SOFTWARE\Haruspex Systems\Ducks in a Row`, value `DataDirectory`.

| Item | What it holds | Survives a move to another machine |
|---|---|---|
| `ducks.db` | ACME accounts, orders, certificate inventory, alert history, EAB credential records, device attestation profiles | Yes |
| `settings.json` | CA connection string, external URL, alert transport | Yes |
| `ducks-setup.json` | Enabled templates, allowed domains, EAB enforcement mode, revocation scope | Yes |
| `logs\` | Serilog daily files, 30 retained | Yes |
| `keys\` | The Data Protection keyring | **No** |
| `ducks-selfsigned.pfx` | The fallback HTTPS certificate | Regenerated if absent |

The application folder under Program Files does not need backing up.
Reinstalling replaces it, and it holds nothing you configured.

## Taking a backup

Stop the service first, so the database is quiescent and the write ahead log
has been folded back in:

```powershell
Stop-Service DucksInARow
Copy-Item -Recurse "C:\ProgramData\Ducks in a Row" "D:\Backups\ducks-$(Get-Date -Format yyyyMMdd)"
Start-Service DucksInARow
```

If you cannot stop the service, back up the whole folder including the
`ducks.db-wal` and `ducks.db-shm` files. Copying `ducks.db` on its own while
the service is running gives you a database missing every change still in the
write ahead log.

Stopping the service is the simpler answer, and it is quick.

> **A backup tool that cannot cope with the sidecar files** can be accommodated
> by setting `Certus:EnableWalMode` to `false`, which converts the database to
> rollback journal mode on the next start and leaves a single file. See
> [configuration](configuration.md).

## Restoring onto the same machine

Copy the folder back and start the service. Everything works, including the
encrypted secrets, because the Data Protection keyring came back with it and
the machine it is tied to has not changed.

Copy it back as an administrator, so the restored files are owned by the
Administrators group. The service ignores `settings.json` and
`ducks-setup.json` if anyone else owns them or may write them; if the log says
it has, see
[Troubleshooting](troubleshooting.md#the-service-ignores-a-configuration-file).

## Restoring onto a different machine

Everything works **except anything that was encrypted**, because the keyring is
tied to the machine that created it. On the new machine:

- **EAB credential secrets** cannot be verified. Clients get 403 `unauthorized`
  and the log tells you to regenerate.
- **An SMTP password saved from the dashboard** cannot be read, so email alerts
  do not send.

This is by design. It means a copy of your data folder is not, by itself, a
copy of your credentials, and someone who obtains the backup does not thereby
obtain the secrets in it.

Recovering takes two steps, and neither loses history:

1. On the ACME page, regenerate each EAB credential. The key id, name, expiry,
   namespace and owner are all stored in the clear and come across unchanged, so
   only the HMAC key needs redistributing. See
   [external account binding](external-account-binding.md).
2. On the Settings page, enter the SMTP password again and save.

Everything else, including every issued certificate, every ACME account and the
whole alert history, is intact.

> [!IMPORTANT]
> **Do not try to move the keyring.** Copying `keys\` to the new
> machine does not help, because the files in it are themselves protected with
> the original machine's DPAPI key. Regenerating is the supported recovery, and
> it is quicker than any alternative.

## What a backup does not protect

The certificates themselves live in the certificate authority's database, not
in this one. Ducks in a Row keeps an inventory of them, not the authority.

So restoring a backup does not reissue, revoke or otherwise change a single
certificate. It restores the record of them. Backing up the CA is a separate
job and a more important one; if you have not got a CA backup, that is the gap
worth closing first.
