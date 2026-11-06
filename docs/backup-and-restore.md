# Backup and restore

Everything worth backing up is in one folder. One thing in it does not survive
being moved to another machine, and knowing which is the whole of this page.

## What to back up

The data folder, by default `C:\ProgramData\Ducks in a Row\`. If you chose a
different one at install time it is recorded in the registry under
`HKLM\SOFTWARE\Haruspex Systems\Ducks in a Row`, value `DataDirectory`.

| Item | What it holds | Survives a move to another machine |
|---|---|---|
| `ducks.db` | ACME accounts, orders, certificate inventory, alert history, EAB credential records, device attestation profiles; see [what it keeps, and for how long](#what-the-database-keeps-and-for-how-long) | Yes |
| `settings.json` | CA connection string, external URL, alert transport | Yes |
| `ducks-setup.json` | Enabled templates, allowed domains, EAB enforcement mode, revocation scope | Yes |
| `logs\` | Serilog daily files, 30 retained | Yes |
| `keys\` | The Data Protection keyring | **No**, and not to another service account on the same machine |
| `licence\` | The installed licence file and the previous one | Yes; a licence bound to a forest works only in that forest |
| `modules\` | The paid module's load record and its own state | Yes |
| `ducks-selfsigned.bin` | The fallback HTTPS certificate, encrypted with the keyring | Regenerated when it is absent or cannot be read |

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
the machine and the service account it is tied to have not changed. The
keyring is protected with DPAPI under the account the service runs as, not
under the machine's own scope, so the same machine with the service running
as a different account counts as a different machine for the secrets: see the
next section.

Copy it back as an administrator, so the restored files are owned by the
Administrators group. The service ignores `settings.json` and
`ducks-setup.json` if anyone else owns them or may write them; if the log says
it has, see
[Troubleshooting](troubleshooting.md#the-service-ignores-a-configuration-file).

## Restoring onto a different machine

Everything works **except anything that was encrypted**, because the keyring is
tied to the machine and the service account that created it. On the new
machine:

- **EAB credential secrets** cannot be verified. Clients get 403 `unauthorized`
  and the log tells you to regenerate.
- **An SMTP password saved from the dashboard** cannot be read, so email alerts
  do not send.
- **The fallback HTTPS certificate** cannot be read either. The service notices
  at start, generates a new one and logs it, so a browser that had accepted
  the old one asks again. A server with a CA issued certificate configured is
  unaffected.

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
> DPAPI under the original service account on the original machine.
> Regenerating is the supported recovery, and it is quicker than any
> alternative.

## A backup taken from 1.0.0 or earlier

Releases up to 1.0.0 kept the fallback HTTPS certificate as
`ducks-selfsigned.pfx`, a PFX under a password that was the same in every
copy of the product. Anyone holding such a backup holds that private key.
The service now deletes that file when it finds one and keeps the
replacement, `ducks-selfsigned.bin`, encrypted with the keyring. Nothing is
needed from you beyond accepting the new certificate once in your browser;
if the old key is a concern, the backup is the only place it still exists,
so remove the file from old backups, or re-encrypt them. A server that
serves a CA issued certificate never used the file for anything.

## What a backup does not protect

The certificates themselves live in the certificate authority's database, not
in this one. Ducks in a Row keeps an inventory of them, not the authority.

So restoring a backup does not reissue, revoke or otherwise change a single
certificate. It restores the record of them. Backing up the CA is a separate
job and a more important one; if you have not got a CA backup, that is the gap
worth closing first.

## What the database keeps, and for how long

`ducks.db` is the one place the product keeps records of its own, and some of
them are personal data: the contact address on an ACME account, the serial
number of a device, the name of the person a credential was handed to, the
requester of a certificate in the CA. Your organisation is the controller of
that data. This section says what is stored, which of it is personal, how long
each class is kept by default, how to change the periods, and how to erase one
account's personal data. It is also the statement of the data's security
properties the [intended use](intended-use.md) page refers to.

| Class | What it holds | Personal data in it | Kept |
|---|---|---|---|
| ACME accounts | The account's public key, status, contact list, and which EAB credential it is bound to | The contact addresses | While the account is valid. A deactivated account loses its contacts one year after deactivation, and its row is deleted once its last order has gone |
| ACME orders, authorizations and challenges | The identifiers an order asked for, the stored CSR, the challenge tokens and validation results, and for a device order the attested facts (serial number, UDID) and the attestation object | The identifier values and attested facts of a device order. Hostnames are the names of servers | The authorizations and challenges go 90 days after the order finished (reached `valid` or `invalid`). An invalid order goes with them. A valid order's own row stays with its certificate record, below |
| Issued certificate records | The certificate Ducks in a Row issued, its serial number, the CA request id, and the revocation stamp | Whatever the certificate names: a device certificate carries the device serial in its subject, as the CA's own copy does | 90 days after the certificate expired. Renewal information (ARI), `replaces` on a renewal order and ACME revocation all find a live certificate through this record, so it outlives its order |
| EAB credentials | The key id, a name, the MAC secret in protected form, and an optional linked Active Directory principal (SID, name and type) | The principal link | Never deleted, because bound accounts refer to them. The principal link is cleared by an account erasure |
| The CA inventory mirror | Every certificate and request the CA holds: subject, alternative names, template, requester, dates, status, and the certificate itself | Requester names, the subjects of user certificates, and the user certificates themselves | Not subject to retention. It mirrors the CA's database, which keeps the same records, and the next sync would recreate any row removed. It includes user certificates because the inventory exists to show every certificate the CA issued, which is what the dashboard and the expiry alerts are for |
| Alert history | Which alert was sent about which certificate, CRL or licence, when, to which channels, and whether every channel accepted it | None beyond the subject of the certificate concerned | Two years after the alert was sent |
| Administrator audit trail | Every change made through the dashboard or its API: who made it, when, what it touched, and the value before and after. Also the count of refused dashboard sign ins per source address and hour | The administrator's Windows identity, and whatever a change named: an account id, a device serial on an allowlist entry, the owner of a credential. Never a secret or a password | Two years after the action, and never less than 90 days. See the [hardening page](hardening.md#the-administrator-audit-trail) |
| Policy rejections | The identifiers an order was refused, the account, the client address, and the stage of the refusal | The client address | The newest 1,000 rows; older ones are removed as new ones arrive |
| Device attestation profiles, allowlist and trust anchors | Administrator configuration: which templates attest, which device serials may enrol, which roots are trusted | An allowlist entry is a device serial or UDID | Until an administrator removes them |
| Log files | The service log | Account ids, hostnames, device serials, and the Windows identity of an administrator in the lines that record an administrative action | 30 daily files, in `logs\` |

### The daily pass

Once a day, five minutes after the service starts and every 24 hours after
that, a retention pass removes what has run out its period, in batches of 500
rows so that ACME traffic and the dashboard never wait on it, and writes one
line to the service log with the counts for each class. It runs in monitor mode
too: it writes to this database, never to the CA.

A finished order has no recorded finishing instant, so the pass measures from
the facts it has, each a bound from above on the real one: a valid order
finished when its certificate was stored, and an invalid order finished no
later than its own expiry, seven days after it was created. Measuring from an
upper bound never removes anything early; an invalid order may be kept up to a
week longer than the period says.

Two consequences are worth knowing. A valid order whose authorizations have
gone still answers a client that fetches it, with an empty authorizations
list; clients do not revisit an order once they hold its certificate. And an
alert history row is also what stops the same warning being sent twice, so a
condition that is still true two years after its alert, such as a CRL that was
never republished or a lapsed licence that was never replaced, is warned about
once more when its row goes.

### Changing the periods

Each period is a setting in `settings.json`, in days, and `0` keeps that class
for ever. The settings and their defaults are on the
[configuration page](configuration.md#data-retention). The pass reads them at
startup, so restart the service after a change. The CA inventory mirror has no
setting because it is not subject to retention.

### Erasing one account

An administrator can remove one ACME account's personal data while keeping the
records the CA audit needs. Two steps, both through the API, and both need the
dashboard administrator role:

1. **Deactivate the account.** Erasure refuses a valid account, because its
   client is still using the contacts and identifiers, and deactivation already
   cancels the account's open orders. The Deactivate button on the ACME tab
   does this too.
2. **Erase it.** `POST /api/acme/accounts/{id}/erase`, where `{id}` is the
   row id the account list shows. From PowerShell, as an administrator of the
   dashboard:

   ```powershell
   Invoke-RestMethod -Method Post -UseDefaultCredentials -Headers @{ 'X-Certus-Csrf' = '1' } -Uri https://your-server:5001/api/acme/accounts/42/erase
   ```

What goes: the account's contact addresses; the Active Directory principal
link on the credential the account is bound to; and the identifiers its orders
carried, meaning every identifier value in each order, the stored CSR, each
authorization's identifier value, attested key and attested facts, and each
challenge's attestation object.

What stays: the account row with its public key and the instant of erasure;
every order row with its id, status, template, CA request id and timestamps;
and every certificate record, the issued certificate included. The certificate
names what it was issued to, exactly as the CA's own copy does, and it is what
renewal information, `replaces` and ACME revocation still need while it is
live. The identifier list keeps each identifier's type with an empty value, so
the record still says a device order was a device order.

One EAB credential may bind many accounts, and its principal link names the
person the credential was handed to. Erasing one account clears that link for
every account bound to the same credential.

The erasure is recorded in the administrator audit trail, in the same database
transaction as the erasure itself, with the administrator's Windows identity
and the account id, and written to the service log at Warning level, so a
raised log level does not drop it. A second erase request for the same account
answers with the first erasure's instant, changes nothing and writes no second
row. The audit row names the account by its id, which the erasure keeps, and
never the data it removed.
