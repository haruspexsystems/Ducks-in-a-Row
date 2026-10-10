# Ducks in a Row documentation

If you run Active Directory Certificate Services (ADCS) with a small team,
certificate renewals tend to live in scripts and calendar reminders. Ducks in a
Row is one Windows service in front of the ADCS certificate authority you
already run: your machines request and renew their own certificates from it
with a standard ACME client, and it warns you by email or webhook before any
certificate in the CA's inventory expires. Nothing phones home, and your
existing ADCS trust chain stays exactly as it is.

## Start here

- **[Quickstart](quickstart.md):** install, point it at your CA, and issue your
  first certificate.
- **[Connecting ACME clients](acme-clients.md):** certbot, win-acme, Caddy,
  Traefik, Posh-ACME and cert-manager, with the directory URL pattern and
  challenge types.
- **[Kubernetes and OpenShift](kubernetes.md):** certificates for cluster
  workloads from your ADCS chain through cert-manager: Issuer or ClusterIssuer,
  the EAB secret, trust, HTTP-01 through an ingress, and what is known about
  OpenShift.
- **[Glossary](glossary.md):** plain explanations of ACME, ADCS, templates,
  challenges, and the other key terms.

## Install and configure

- **[System requirements](system-requirements.md):** what the server needs,
  including the network ports and the Server 2022 servicing floor.
- **[Installation](installation.md):** the setup bundle, the bare MSI, silent
  install, and what the installer actually does.
- **[ADCS configuration](adcs-setup.md):** the CA connection string, template
  permissions, and the two rights the machine account needs.
- **[Configuration](configuration.md):** every setting, where to put it, and
  which file wins.
- **[Verifying your installation](verifying.md):** seven checks, in the order
  worth running them.

## Administer

- **[External account binding](external-account-binding.md):** control who may
  register an ACME account, with credentials, namespaces, and expiry.
- **[Device attestation](device-attestation.md):** issue certificates to Apple
  managed devices with the `device-attest-01` challenge.
- **[Revocation](revocation.md):** the capability ceiling you cannot raise, the
  scope you choose, and the one automatic revocation.
- **[Expiry alerts](alerts.md):** email and webhook notification before a
  certificate expires.
- **[Backup and restore](backup-and-restore.md):** what to copy, and the one
  thing that does not survive a move to another machine.

## When something is wrong

- **[Troubleshooting](troubleshooting.md):** health states, common failures,
  and how to read the logs.
- **[Hardening](hardening.md):** optional lockdowns and the tradeoffs behind
  the defaults, starting with challenge validation egress.

## Reference

- **[Installation and Configuration Guide](Ducks-in-a-Row-Installation-Guide.pdf):**
  every page above, as a single printable PDF. It is generated from these files,
  so the two cannot disagree.
- **[Changelog](../CHANGELOG.md):** what changed in each release.
- **[Development setup](dev-setup.md):** building and testing from source.

## Project

- **[License](../LICENSE)** and the plain-language
  **[licensing summary](../LICENSING.md):** Business Source License 1.1, source
  available.
- **[Support](../SUPPORT.md):** where to ask questions and report bugs.
- **[Security policy](../SECURITY.md):** how to report a vulnerability.
- **[Contributing](../CONTRIBUTING.md):** ways to help. Pull requests are not
  accepted.
