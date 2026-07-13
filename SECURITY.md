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

## Scope

In scope: the ACME server and endpoints, the dashboard and its API, the setup
wizard, the Windows service, the installer, and the path that talks to ADCS.

Out of scope: hardening of your own Active Directory, ADCS, DNS, or network. We
are happy to receive reports where our defaults make those things less safe than
they should be.

## Supported versions

Until the first stable release, only the latest commit on the default branch is
supported. Once v1.0.0 ships, this section will list the versions that receive
security fixes.
