# Security Policy

Ducks in a Row sits in front of a certificate authority, so we take security
reports seriously and ask you to report privately.

## Reporting a vulnerability

Email **security@haruspex.systems** with:

- a description of the issue and the impact you believe it has,
- the version or commit you tested,
- clear steps to reproduce, and
- any proof of concept, logs, or configuration that help us confirm it.

Please do **not** open a public GitHub issue, discussion, or pull request for a
suspected vulnerability. Give us a chance to fix it before it is disclosed.

## What to expect

- We aim to acknowledge your report within three working days.
- We will tell you whether we accept the report and give you an expected
  timeline for a fix.
- We practise coordinated disclosure: we agree a disclosure date with you,
  normally the day the release that fixes your report ships, and credit you
  in the advisory and the release notes unless you prefer to stay anonymous.

## Advisories for fixed vulnerabilities

Every vulnerability we fix gets a GitHub Security Advisory on the public
repository once the release that fixes it is out, whether it was reported to us
or we found it ourselves, and the release notes name it. The advisory describes
the vulnerability, names the affected versions, states its impact and severity,
and says how to remediate it.

A fix counts as a vulnerability fix when someone without administrator rights
on the server, its CA or Active Directory could use the flaw on purpose to read,
change or block what they otherwise could not, including through a weak
default. Other security fixes, such as those that limit what an administrator
can do or correct a fault nobody can bring about on purpose, get no advisory;
the release notes name those an operator would notice.

We delay an advisory only where publishing it would put users at more risk than
it protects them from, and then only until they have had the chance to update.
That holds for a disclosure date agreed with a reporter too.

To be notified, watch the repository's security advisories and releases, or
sign up for security notices at https://ducksinarow.dev/notices.

## Regulator reporting under the EU Cyber Resilience Act

Haruspex Systems B.V. is the manufacturer of Ducks in a Row under the EU Cyber
Resilience Act. From 11 September 2026, if a vulnerability in Ducks in a Row is
being actively exploited, or a severe incident affects the security of the
product, we notify ENISA and the Dutch coordinator CSIRT on the statutory
clocks, starting with an early warning within 24 hours of becoming aware. The
process we follow is published in
[docs/cra-reporting-process.md](docs/cra-reporting-process.md).

Two things this means for you. If you report a vulnerability and your report
shows active exploitation, we may notify regulators within hours of your email;
that notification is confidential, goes to authorities rather than the public,
and does not change the coordinated disclosure we agree with you. And when an
actively exploited vulnerability or severe incident affects users, we do not
wait for the fix: we tell them without undue delay through a GitHub Security
Advisory, with any mitigation they can apply meanwhile, and carry the fix in
release notes. If that brings forward a disclosure date we agreed with you, we
tell you before the advisory is published.

## Scope

In scope: the ACME server and endpoints, the dashboard and its API, the setup
wizard, the Windows service, the installer, and the path that talks to ADCS.

Out of scope: hardening of your own Active Directory, ADCS, DNS, or network. We
are happy to receive reports where our defaults make those things less safe than
they should be.

## Support period

Ducks in a Row receives security fixes until 31 December 2031, at least five
years after 1.0.0 became generally available, delivered through upgrades to the
latest release, with no backports.

Until that date we handle reported vulnerabilities as this policy describes and
publish each fix in a new release.

## Supported versions

Security fixes go into the **latest release**. Upgrading to it is how you
receive them, and there are no backports to earlier releases.

That is a deliberately narrow promise. We are a small team, and a support
commitment we cannot keep is worse for you than a modest one we can: a missed
backport on a published promise leaves you believing you are covered when you
are not.

Where technically feasible, a security fix ships as its own patch release of the
latest release, with no new features. Upgrading to it is free of charge for
every user, whichever release they run now.

| Version | Receives security fixes |
|---|---|
| The latest release | Yes, until 31 December 2031 |
| Anything earlier | No. Upgrade to receive them |

## What we ship with

A release never ships with a known vulnerability of High or Critical severity
(CVSS 7.0 or more) in a default installation. A Medium or Low one may ship when
the release notes name it under Known Issues with a workaround, and the fix is
scheduled. When a vulnerability in the latest release is fixed on `main`, a
patch release carrying the fix ships within 30 days of the fix merging, sooner
when the risk asks for it, and the advisory is published with that release.

A default installation is what the installer sets up on its own: the installer's
defaults, with none of the opt in lockdowns in the
[hardening guide](docs/hardening.md) applied. Severity is the CVSS 3.1 base
score the advisory carries.
