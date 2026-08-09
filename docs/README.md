# Ducks in a Row documentation

ACME-to-ADCS certificate lifecycle management. Make your internal Microsoft CA
work like Let's Encrypt.

## Start here

- **[Quickstart](quickstart.md):** install, point it at your CA, and issue your
  first certificate.
- **[Connecting ACME clients](acme-clients.md):** certbot, win-acme, Caddy,
  Traefik, and Posh-ACME, with the directory URL pattern and challenge types.
- **[Device attestation](device-attestation.md):** issue certificates to Apple
  managed devices with the `device-attest-01` challenge.
- **[Troubleshooting](troubleshooting.md):** health states, common failures,
  and how to read the logs.
- **[Glossary](glossary.md):** plain explanations of ACME, ADCS, templates,
  challenges, and the other key terms.

## Reference

- **[Installation and Configuration Guide](Ducks-in-a-Row-Installation-Guide.pdf):**
  the full reference covering install, configuration, ADCS permissions, alerts,
  and uninstall.
- **[Hardening](hardening.md):** optional lockdowns and the tradeoffs behind
  the defaults, starting with challenge validation egress.
- **[Development setup](dev-setup.md):** building and testing from source.

## Project

- **[License](../LICENSE)** and the plain-language
  **[licensing summary](../LICENSING.md):** Business Source License 1.1, source
  available.
- **[Support](../SUPPORT.md):** where to ask questions and report bugs.
- **[Security policy](../SECURITY.md):** how to report a vulnerability.
- **[Contributing](../CONTRIBUTING.md):** how to propose changes.
