# Licence and paid module

Ducks in a Row is free to use. The paid tier is switched on by a licence file,
which a separately installed paid module checks. The Licence card on the
Settings page is where you install the file and see what the paid module makes
of it.

**Certificate issuance and renewal never depend on the licence or on the paid
module.** A missing, expired or damaged licence, or a paid module that fails to
start, changes nothing about the certificates Ducks in a Row issues and renews.
Every warning the card and the banner show ends by saying so.

**The free tier is the product as released.** One installation connects to one
certificate authority, and an estate with more than one issuing CA runs one
installation per CA, as [several certificate authorities](several-cas.md)
describes. The certificate inventory, the dashboard, expiry alerts,
CRL watching and monitor mode never depend on the licence either, and nothing a
release shipped on the free tier moves behind the licence later. The paid tier
adds capabilities beside the core, such as covering more than one certificate
authority; [ducksinarow.dev](https://ducksinarow.dev) lists the tiers.

## What you need

- **The paid module.** It comes with its own installer, which installs
  whatever the state of your licence; see
  [security updates and your licence](#security-updates-and-your-licence).
  Until it is installed, the card reads "Free tier. No paid module is
  installed."
- **A licence file** from Haruspex Systems. It is a small text file naming your
  organisation, your tier, how many CAs it covers, and its dates.

The order does not matter. A licence installed before the paid module is kept,
and checked as soon as the module runs.

Before it loads the paid module, the service verifies that every file of the
module carries a valid, timestamped Authenticode signature by Haruspex Systems
B.V., and a module whose signature it cannot verify is not loaded; the Licence
card then names the file.

## Security updates and your licence

Every release of the paid module can be downloaded and installed whatever the
state of your licence: valid, expiring, lapsed, or none at all. That includes
its security releases, which are free of charge, as every security fix for
Ducks in a Row is. The licence only switches paid features on. It never decides
what you may install, so a lapsed licence changes nothing about which release
of the module you can run, and the module's installer does not ask for one.
Where the module's releases are published is announced with its first release.

The paid module is a product of its own, with its own support period and its
own security policy. Its support period is published with its first release.
It is not the 31 December 2031 date that applies to Ducks in a Row itself, which
[SECURITY.md](../SECURITY.md) states; until the module's own date is published,
do not read that date as covering the module.

Each release of the module is built against a module contract that a release
of Ducks in a Row carries. A module whose contract does not fit the installed
release does not load, as described
[below](#when-the-paid-module-is-not-running), and the installer warns before an
upgrade of Ducks in a Row that would cause it. So a security release of the
module may need a newer release of Ducks in a Row, and that upgrade is free as
well.

## Installing a licence

1. Open **Settings**. The Licence card comes straight after the About block.
2. Choose **Upload a licence**, or **Replace the licence** when one is already
   installed. Drop the file on the card, choose it, or paste its text.
3. The card asks the paid module to check the file and shows what it found: who
   it is licensed to, the tier, how many CAs it covers, its dates, the forests it
   is bound to, and the forest this server is in. Nothing is installed yet.
4. Choose **Activate**.

If the paid module judges the new file worse than the licence installed now (a
lower stage, an earlier end date, fewer features or fewer CAs), the card shows
the two side by side and asks you to confirm before installing it. The licence it
replaces is kept, so **Restore previous licence** can undo the change.

A file the paid module cannot use is not offered for activation. The card says
why, in plain words.

With no paid module running there is nothing to check the file, so the button
reads **Store it** instead. The file is kept and checked once the module runs.

### Pasting the text

Pasted text is used exactly as pasted. A licence file is one long line, and mail
programs often wrap long lines, so a pasted licence that went through a mail
program can arrive changed. The card then refuses it, says a mail program may have
wrapped a long line, and suggests choosing the file instead: save the attachment
and choose it.

## What the card says

| State | What the card says | Paid features |
|---|---|---|
| No paid module, no licence | Free tier. No paid module is installed. | Off |
| No paid module, licence stored | A licence is stored but not checked, because the paid module is not installed. | Off |
| Paid module, no licence | The paid module is installed. Upload your licence file. | Off |
| Valid | Licensed to (name) (reference). (Tier), up to (n) CAs. Valid until (date). | On |
| Expiring | Your licence expires on (date), in (n) days. | On |
| Grace | Your licence expired on (date). Paid features switch off on (date). | On |
| Lapsed | Your licence lapsed on (date). Paid features are off. | Off |
| Not yet valid | Your licence starts on (date). | Off |
| Bound to another forest | This licence is for (forests). This server is in (forest). | Off |
| Not usable | This licence file cannot be used, and why. | Off |
| Paid module not running | What happened to the module, and what to do. See below. | Off |

Dates are shown in UTC, written year first, for example 2027-10-28. Day counts
come from the paid module on the server. The dashboard never counts days itself,
and reads the status again every hour, so a page left open overnight shows the
server's count rather than a stale one.

The card also warns when this server's clock looks more than a day behind the
date the licence was issued, and when the paid module does not know the
licence's tier, which a newer paid module fixes.

## Warning, grace and lapse

A licence carries its own warning and grace periods, 30 days each unless it says
otherwise.

- **Expiring.** From the start of the warning period until the end date. Paid
  features stay on, and an amber banner shows the days left.
- **Grace.** From the end date until the grace period ends. Paid features stay
  on, and the banner turns red.
- **Lapsed.** After the grace period. Paid features are off, and a grey banner
  says so. You can dismiss it for the rest of the browser session.

A lapse deletes nothing and reconfigures nothing. Whatever the paid features hold
is kept, and a renewed licence switches everything back on as it was.

With an email or webhook channel configured, Ducks in a Row also sends an alert
at each warning inside the warning period, when the licence ends, and when it
lapses. See [licence alerts](alerts.md#licence).

## The banner

The banner runs across the top of every page, and links to the Licence card. It
appears only when a licence is stored, so an installation on the free tier never
sees one.

- **Amber:** the licence is expiring, has not started yet, or is stored while
  no paid module is installed.
- **Red:** the licence is in grace, cannot be used, or is bound to another
  forest; or the paid module is not running; or the licence folder cannot be
  trusted.
- **Grey:** the licence has lapsed. Only this one can be dismissed.

## Removing and restoring

**Remove the licence** asks first, then switches paid features off. The licence
it removed is kept as the previous one.

**Restore previous licence** puts the previous licence back. It undoes a removal
or a replacement. One previous licence is kept.

## When the paid module is not running

The card says what happened, and shows the service's own reason beneath it.

- **It failed to start, stopped responding, or was set aside after failing to
  start twice.** Choose **Retry the paid module**. The service restarts to try
  again, and the dashboard and ACME clients lose their connection for a few
  seconds. If the service cannot restart itself, the card says so: restart it by
  hand with `Restart-Service DucksInARow`.
- **It was built for another release.** The card names the contract version the
  module was built for and the one this release needs. Install the paid module
  built for this release, then restart the service. Retry is not offered,
  because a restart alone cannot change it. Setup warns before an upgrade that
  would cause this; see [installation](installation.md#the-install-wizard).
- **It was not loaded, because non-administrators can change its folder.**
  Repair the paid module's installation, then restart the service. Retry is not
  offered here either.
- **Its signature could not be verified.** The card names the file: it is not
  signed, was signed by someone other than Haruspex Systems, or was changed
  after it was signed. Reinstall the paid module from a release Haruspex
  Systems published, then choose **Retry the paid module**.

The paid module is looked for only when the service starts, so after installing,
repairing or removing it, restart the service with `Restart-Service DucksInARow`
if its installer did not.
- **More than one module folder is present.** Only one paid module may be
  installed. Remove the extra folder from the `modules` folder in the program
  folder, then restart the service.

## Forest binding

A licence can be bound to one or more Active Directory forests. A bound licence
switches paid features on only on a server joined to one of them; on a server in
another forest, or one not joined to a domain, it switches nothing on. A licence
with no binding works on any server, and that is the default.

Once the paid module is installed, the card shows the forest this server is in,
so you can quote it when you buy a bound licence. The paid module reads it from
the server itself and asks no domain controller, so a domain controller outage
does not change the result.

## Installing a licence without the dashboard

An administrator can copy a licence file to `licence.json` in the `licence`
folder of the data folder, by default
`C:\ProgramData\Ducks in a Row\licence\licence.json`, for example from a script
or by group policy. The service picks it up within about a minute.

This way skips the downgrade check and keeps no previous licence, so prefer the
card when you can. The service creates the `licence` folder the first time a
licence is installed from the card.

> [!WARNING]
> Do not create the `licence` folder by hand. The service refuses a licence
> folder that anyone other than SYSTEM and Administrators owns or can write to,
> and a folder you create may be owned by your own account.

## The licence folder cannot be trusted

If the card says the licence folder cannot be trusted, someone other than SYSTEM
and Administrators owns it or can write to it. The service then reads no licence
from it, and never repairs it, because resetting the permissions on a folder
someone else prepared would itself be unsafe.

1. Find the folder the service log names. By default it is
   `C:\ProgramData\Ducks in a Row\licence`.
2. Delete it.
3. Install the licence again from the card. The service creates the folder with
   the right permissions.

## Backup and restore

The `licence` folder is part of the data folder, so it travels with every backup.
An unbound licence works on any server it is restored to; a bound one works on a
server in the same forest. See [backup and restore](backup-and-restore.md).
