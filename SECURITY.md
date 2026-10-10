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
- We practise coordinated disclosure: we will agree a disclosure date with you
  and credit you in the release notes unless you prefer to stay anonymous.

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
actively exploited vulnerability or severe incident affects users, we publish a
GitHub Security Advisory on the public repository and carry the fix in release
notes; watch the repository's security advisories and releases to be notified.

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

| Version | Receives security fixes |
|---|---|
| The latest release | Yes, until 31 December 2031 |
| Anything earlier | No. Upgrade to receive them |
