# The free surface

Every API route the service maps and every dashboard area the frontend ships, each with the date of
its free decision and the reason. `FreeSurfaceTests` beside this file fails when the product has a
route or an area this list does not name, or this list names one the product no longer has.

Free is one CA. Run is free, on production too; prove and integrate are paid (the free product
boundary, Sean's decision of 2026-10-22, lethe377/Certus#652). A new route or area is a new
capability, and a capability is paid unless a row here says otherwise. So a pull request that adds
one adds its row too, citing the boundary row it rests on, and the merge gate's free boundary lens
reads that reason. A capability the boundary reserves for the paid tier belongs in the paid module,
not in this list.

Rows dated 2026-10-22 rest on the boundary's first row: everything 1.0.0 shipped is free for life.
Rows dated 2026-10-26 landed after the 1.0.0 cut and were placed against a boundary row when this
list was first written (#655); Sean reverses any of them by exception.

| kind | surface | decided | decision |
| --- | --- | --- | --- |
| api | `ANY /acme/{template}/{**path}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `ANY /api/{**path}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `ANY /health` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `ANY /health/live` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `DELETE /api/acme/credentials/{id:int}/principal` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `DELETE /api/acme/device-attestation/allowlist/{entryId:int}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `DELETE /api/acme/device-attestation/profiles/{id:int}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `DELETE /api/acme/device-attestation/trust-anchors/{id:int}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `DELETE /api/settings/licence` | 2026-10-26 | free: the licence card and banner, the one licence status reader the boundary allows (#652 enforcement b), #493 |
| api | `GET /acme/{template}/directory` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /acme/{template}/issuer-cert` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /acme/{template}/new-nonce` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /acme/{template}/renewalInfo/{certId}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Alerts/certificate/{certificateId:int}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Alerts/config` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Alerts/history` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Alerts/summary` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Certificates` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Certificates/stats` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Certificates/sync-status` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Certificates/{id:int}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Certificates/{id:int}/der` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Certificates/{id:int}/pem` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Dashboard/activity` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Dashboard/health` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Dashboard/registrations` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Dashboard/validation` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Setup/config` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Setup/discover-cas` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/Setup/existing-certificates` | 2026-10-26 | free: monitor mode setup, named in the free sentence ("Monitor-only mode"), #533 |
| api | `GET /api/Setup/status` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/acme/accounts` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/acme/credentials` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/acme/credentials/{id:int}/accounts` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/acme/device-attestation/profiles` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/acme/device-attestation/profiles/{id:int}/allowlist` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/acme/device-attestation/trust-anchors` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/acme/directory-principals` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/acme/eab/enforcement` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/audit/actors` | 2026-10-26 | free: security hardening (boundary row "Security fixes, hardening, CRA work"), the administrator audit trail, #634 |
| api | `GET /api/audit/entries` | 2026-10-26 | free: security hardening (boundary row "Security fixes, hardening, CRA work"), the administrator audit trail, #634 |
| api | `GET /api/audit/sign-in-failures` | 2026-10-26 | free: security hardening (boundary row "Security fixes, hardening, CRA work"), the administrator audit trail, #634 |
| api | `GET /api/settings/allowed-domains` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/settings/ca-certificates` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/settings/ca-certificates/chain/p7b` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/settings/ca-certificates/chain/pem` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/settings/ca-certificates/{thumbprint}/der` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/settings/ca-certificates/{thumbprint}/pem` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/settings/crl-status` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/settings/external-url` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/settings/https-certificate` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/settings/info` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/settings/licence` | 2026-10-26 | free: the licence card and banner, the one licence status reader the boundary allows (#652 enforcement b), #493 |
| api | `GET /api/settings/revocation-scope` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/settings/service-rights` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /api/templates` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `GET /{*path:nonfile}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `HEAD /acme/{template}/directory` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `HEAD /acme/{template}/issuer-cert` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `HEAD /acme/{template}/new-nonce` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `HEAD /acme/{template}/renewalInfo/{certId}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `HEAD /{*path:nonfile}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /acme/{template}/acct/{accountId}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /acme/{template}/acct/{accountId}/orders` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /acme/{template}/authz/{authzId}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /acme/{template}/cert/{certId}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /acme/{template}/chall/{challengeId}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /acme/{template}/issuer-cert` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /acme/{template}/key-change` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /acme/{template}/new-account` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /acme/{template}/new-order` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /acme/{template}/order/{orderId}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /acme/{template}/order/{orderId}/finalize` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /acme/{template}/revoke-cert` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/Alerts/config/apply` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/Alerts/test` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/Certificates/sync` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/Certificates/{id:int}/revoke` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/Setup/complete` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/Setup/draft` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/Setup/existing-certificates/keep-self-signed` | 2026-10-26 | free: monitor mode setup, named in the free sentence ("Monitor-only mode"), #533 |
| api | `POST /api/Setup/existing-certificates/use` | 2026-10-26 | free: monitor mode setup, named in the free sentence ("Monitor-only mode"), #533 |
| api | `POST /api/Setup/service-rights` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/Setup/templates` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/Setup/test-connection` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/Setup/tls-certificate` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/Setup/tls-certificate/apply` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/Setup/tls-certificate/discard` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/Setup/validate-url` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/acme/accounts/{id:int}/deactivate` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/acme/accounts/{id:int}/erase` | 2026-10-26 | free: CRA and privacy work (boundary row "Security fixes, hardening, CRA work"), per account erasure, #637 |
| api | `POST /api/acme/credentials` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/acme/credentials/{id:int}/regenerate` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/acme/credentials/{id:int}/revoke` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/acme/device-attestation/profiles` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/acme/device-attestation/profiles/{id:int}/allowlist` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/acme/device-attestation/trust-anchors` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/settings/https-certificate/apply` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/settings/https-certificate/renew` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `POST /api/settings/licence/inspect` | 2026-10-26 | free: the licence card and banner, the one licence status reader the boundary allows (#652 enforcement b), #493 |
| api | `POST /api/settings/licence/restore-previous` | 2026-10-26 | free: the licence card and banner, the one licence status reader the boundary allows (#652 enforcement b), #493 |
| api | `POST /api/settings/licence/retry-module` | 2026-10-26 | free: the licence card and banner, the one licence status reader the boundary allows (#652 enforcement b), #493 |
| api | `POST /api/settings/service-rights/check` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `PUT /api/Alerts/config` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `PUT /api/acme/credentials/{id:int}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `PUT /api/acme/credentials/{id:int}/principal` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `PUT /api/acme/device-attestation/allowlist/{entryId:int}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `PUT /api/acme/device-attestation/profiles/{id:int}` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `PUT /api/acme/eab/enforcement` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `PUT /api/settings/allowed-domains` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `PUT /api/settings/external-url` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| api | `PUT /api/settings/licence` | 2026-10-26 | free: the licence card and banner, the one licence status reader the boundary allows (#652 enforcement b), #493 |
| api | `PUT /api/settings/revocation-scope` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/AcmePage.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/AuditPage.tsx` | 2026-10-26 | free: security hardening (boundary row "Security fixes, hardening, CRA work"), the administrator audit trail, #634 |
| area | `component pages/CertificateDetailPage.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/CertificateListPage.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/DashboardPage.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/SettingsPage.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/acme/AcmeAccountsPage.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/acme/DeviceAttestationCard.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/acme/EabCredentialsCard.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/acme/EabEnforcementCard.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/settings/AlertsCard.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/settings/AllowedDomainsCard.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/settings/CaCertificatesCard.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/settings/CrlStatusCard.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/settings/ExternalUrlCard.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/settings/HttpsCertificateSection.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/settings/LicenceCard.tsx` | 2026-10-26 | free: the licence card and banner, the one licence status reader the boundary allows (#652 enforcement b), #493 |
| area | `component pages/settings/RevocationScopeCard.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/settings/ServiceRightsCard.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/setup/AllowedDomainsStep.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/setup/ConnectionStep.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/setup/ExternalUrlStep.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/setup/ReviewStep.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/setup/SetupWizard.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/setup/TemplatesStep.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `component pages/setup/WelcomeStep.tsx` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `route *` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `route /` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `route /acme` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `route /audit` | 2026-10-26 | free: security hardening (boundary row "Security fixes, hardening, CRA work"), the administrator audit trail, #634 |
| area | `route /certificates` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `route /certificates/:id` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `route /settings` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
| area | `route /setup` | 2026-10-22 | free: shipped in 1.0.0, free for life (boundary row "Everything 1.0.0 ships") |
