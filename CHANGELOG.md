# Changelog

All notable changes to Ducks in a Row are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-08

The first general release. Both installers, and every binary the MSI installs,
are signed by Haruspex Systems B.V. and timestamped. A CycloneDX 1.6 software
bill of materials, `Ducks-in-a-Row-1.0.0.cdx.json`, ships beside them, listed in
`SHA256SUMS`. Ducks in a Row receives security fixes until 31 December 2031, at
least five years after 1.0.0 became generally available, delivered through
upgrades to the latest release, with no backports. Everything here is free for
production use on infrastructure you own or operate, or administer for customers
as part of a managed IT service, with no limit on certificates, under the
Business Source License 1.1, which turns each version into Apache License 2.0
four years after release. Paid modules are separate, and none is part of 1.0.0.

Upgrading from 0.10.0-beta.1 is an in place upgrade designed to keep your data
folder, but it was not tested end to end for this release. Back up the data
folder first, as the Backup and Restore chapter of the installation guide
describes. Every server running a beta should upgrade: 1.0.0 closes a local
privilege escalation through the data folder (#489), and the upgrade locks that
folder down on its own. Since the beta the server also watches every
certificate revocation list in the CA chain, the offline root's included
(#447), checks the service's own rights on the CA before first use and says
which it could prove (#440), and has a Kubernetes and OpenShift chapter for
cert-manager (#439). Read the Known Issues section at the foot of these notes
before installing.

### Added

- A Kubernetes and OpenShift page (#439). A cluster that gets its certificates
  from cert-manager can point cert-manager's built in ACME issuer at Ducks in a
  Row, and its workloads then chain to the ADCS root the organisation already
  trusts, with no plugin in the cluster. The new chapter covers choosing an
  Issuer or a ClusterIssuer, the EAB secret and the namespace it belongs in,
  trusting the server with `caBundle`, the path an HTTP-01 check takes through
  an ingress and the one firewall rule it needs, the key settings that match
  each template, getting the root to pods, and renewal with ARI. It says plainly
  which parts our test cycle has run and which it has not, and the OpenShift
  section states only what upstream documents, marked as not run here. See
  [Kubernetes and OpenShift](docs/kubernetes.md).

- The setup wizard proves what it can of the service's rights on the CA before
  first use, and says plainly what it cannot (#440). A passing Test Connection
  used to be the only evidence an operator had, and it proves one right. Now the
  Connection step shows what the service's own computer account may do on the
  CA as soon as the test passes, and the Review step checks everything again,
  with one row for each template you chose. Each row is Proven, Inferred,
  Unproven, Failed or Skipped:
  - Request Certificates is proven by Test Connection itself.
  - The certificate inventory's view is proven by opening it.
  - Issue and Manage Certificates is reported by the CA.
  - Enroll on each template is read from the template's permissions.
  - The HTTPS certificate on the External URL step, when it is enrolled, proves
    its own template.

  Completing setup without that proof asks you to acknowledge what stays
  unproven, and never blocks. The new **Service rights on the CA** card on the
  Settings page runs the same check later, with **Check again**, for when a right
  changes. See
  [verifying your installation](docs/verifying.md#the-services-rights).

- Certificate revocation lists are watched, the offline root's included (#447).
  A certificate expiring breaks one service; a CRL expiring breaks revocation
  checking for everything the CA that signed it ever signed, at once, and for an
  offline root nothing automatic replaces it. Ducks in a Row now reads the CRLs
  of every CA in the chain of the connected CA, from the CA itself and from the
  distribution points named on the chain, over both LDAP and HTTP, and warns
  through the same email and webhook channels as certificate expiry. Each copy
  is watched separately, so a root CRL renewed into the directory but never
  copied to the web server is reported with the location named, which is the
  commonest way a root CRL renewal goes wrong. A CRL a CA replaces on a timer is
  only reported when the CA misses that timer, and again if it expires; a CRL
  somebody publishes by hand gets the usual 30, 14, 7 and 1 day ladder, because
  an offline root means a ceremony rather than a service restart. The new
  **Revocation lists** card on the Settings page shows everything being watched
  and every place it is published, and the CA certificate list now shows how
  long each certificate has left. See [alerts](docs/alerts.md).

- The installer is branded (#339). The setup wizard carries the Ducks in a Row
  mascot on its welcome and completion pages and on every interior banner, and
  the product now has an icon: in Apps and Features, on
  `Ducks-in-a-Row-Setup.exe` itself in Explorer, and on the Windows permission
  prompt beside the publisher name the signing added. The icon is wired in two
  places on purpose. Installed through the setup file, the MSI hides its own
  Apps and Features row so a single entry is listed, which means the row a user
  sees takes its icon from the bundle rather than from the MSI; the bare MSI
  keeps its own. All four assets are generated from the mascot the dashboard and
  the printed guide already use, so the three surfaces cannot drift apart. The
  small icon sizes are scaled down from the full mascot.

- The installers are code signed (#337). `Ducks-in-a-Row-Setup.exe`, the Burn
  engine inside it, `Ducks-in-a-Row.msi`, and every `.exe` and `.dll` the MSI
  installs are signed by Haruspex Systems B.V. and carry an RFC 3161 timestamp,
  so the signatures stay valid after the certificate expires. The Windows
  permission prompt now names Haruspex Systems B.V. as the verified publisher,
  and an App Control for Business (WDAC) or AppLocker policy can allow
  everything the installer puts on disk with one publisher rule. The third party
  libraries are signed as
  well, because the ReadyToRun compilation the build uses rewrites them and
  drops their vendors' own signatures. Check a download with
  `Get-AuthenticodeSignature`; the installation guide shows how. SmartScreen may
  still warn about a new release while the certificate builds up a reputation
  with Microsoft. Releases up to and including 0.10.0-beta.1 were not signed.

- A software bill of materials, generated on every build and published with
  every release (#396). `build.ps1` writes
  `artifacts/sbom/Ducks-in-a-Row-<version>.cdx.json` in CycloneDX 1.6, covering
  the NuGet closure of the published service, the runtime npm packages the
  dashboard is built from, and the ASP.NET Core Hosting Bundle the setup file
  embeds, which is declared from the version and SHA-512 the build already pins.
  It is uploaded as a release asset and listed in `SHA256SUMS` beside the MSI
  and the setup file. Build tooling is left out on both sides, so the document
  describes what ships rather than what built it, apart from the design time
  packages listed under Known Issues. Two builds of one commit produce byte
  identical output: no serial number, no
  timestamp, and every list ordinally sorted, which also makes two releases
  diffable against each other. The EU Cyber Resilience Act asks for this from
  December 2027, and a supply chain reviewer asks for it today.

- ACME Renewal Information (ARI, RFC 9773) (#281). The directory advertises
  `renewalInfo`, and an unauthenticated GET of `{renewalInfo}/{certID}` returns
  a suggested renewal window for any certificate issued through ACME: two
  thirds of the way through the certificate's lifetime, about 2% of that
  lifetime wide, with a deterministic per certificate offset so a fleet issued
  in one batch does not renew in one batch. A revoked certificate answers with
  a window entirely in the past, which ARI aware clients (simple-acme, certbot
  from 4.1.0, lego, Caddy from 2.8.0, and cert-manager from 1.21 with its alpha
  `ACMEUseARI` gate on) read as "renew immediately", so a revocation
  reaches the fleet without anyone touching a client. The `Retry-After` header
  carries the six hour polling interval. New-order requests may now carry the
  RFC 9773 §5 `replaces` member naming the certificate being renewed; the
  server verifies it (same account, a shared identifier), reflects it on the
  order, and refuses a second live order for the same certificate with HTTP 409
  `alreadyReplaced`, which is what stops duplicate renewal loops. The renew now
  signal fires however the certificate was revoked, including directly at the
  CA with certutil, because the endpoint reads the synced inventory's
  revocation record beside the ACME row; and an abandoned renewal order stops
  blocking `replaces` once it passes its own expiry, so a crashed client never
  locks a certificate out. The
  development host's mock CA now stamps an Authority Key Identifier on its
  leaves and a Subject Key Identifier on its root, as real ADCS does, so ARI
  identifiers can be computed against it.

- A finalize that reaches a certificate authority which is down, or a device
  order whose attestation profile was disabled mid flight, is now answered as
  what it is (#324). A CA outage answers 503 `serviceUnavailable` and leaves the
  order alone to be retried, which is word for word what the template lookup and
  revoke-cert already answered. The finalize also releases its claim on the
  order in that case, so the order returns to `ready` rather than sitting in
  `processing` for ever. That release fires only when the CA was never reached;
  an outage after the request id is saved leaves the order alone, because the
  certificate may well exist and the pending sweep will finish it. A device
  order refused because its profile is gone now answers `rejectedIdentifier`
  with a subproblem naming the device, instead of `badCSR`, which sent the
  client away to rebuild a request that was never the problem.

- The mock certificate authority used by the development host now copies the
  subject alternative name a request asked for onto the certificate it mints,
  and can hold a comma in its own name (#295). The subject alternative name is
  the one extension a real CA takes from the requester rather than from the
  template, so a mock that dropped it could not exercise the paths that read it
  back. Separately, a CA name containing a comma is legal and permitted by the
  connection string, and the mock could not construct at all for one.

- Abandoning a server certificate enrolment no longer strands a certificate at
  the certificate authority (#326). The caller's cancellation is read for the
  last time on the line above the submit: up to there nothing has reached the CA
  and abandoning is free, and past there the submit, the fetch, the key check
  and the store install all run to completion. A submit is not idempotent, so
  giving up half way left a live certificate at the CA with nothing on the
  server naming it, one more for every cancelled attempt.

- An order that died because its account was deactivated now says so (#320). The
  deactivation writes the `unauthorized` problem document RFC 8555 section 7.1.3
  gives the order at the same moment it writes the status, so the two cannot
  disagree. No ACME client reads an order level error today, so this is a record
  for an operator rather than a change any client will see.

- An order the certificate authority is holding for manager approval is now
  finished when the approval happens (#319). A template configured to hold every
  request is an ordinary ADCS setting that the setup wizard warns about and then
  lets you use, so an order sitting in `processing` was a normal outcome with no
  way out. A background sweep now re-asks the CA and completes, fails or
  abandons the order accordingly. It asks the CA before applying the order's
  expiry, so an order that aged out while its certificate already existed is
  delivered rather than abandoned, and abandoning never revokes: the CA request
  id is logged and the decision is left to an operator.

- A finalize whose client hangs up part way through no longer loses the
  certificate it just asked for (#321). Nothing past the point where the order
  is claimed reads the caller's cancellation any more. What this closed was not
  the submit but the save immediately after it: a token cancelled while the
  request was at the CA threw out of that save, the failure path marked the
  order invalid, and the reload that came with it discarded the request id the
  throw had left unsaved, leaving a live certificate that the inventory showed
  with no order behind it.

- A certificate is served, and advertised, only while its order still names it
  (#318). Both halves moved together on purpose: gating the download without
  gating the order response would hand a client a URL that then refused it,
  which is worse than not offering one.

- A finalize refused by the certificate authority now answers with the error the
  refusal actually is (#313). `badCSR` is for the certificate request and
  nothing else. A CA that refuses on policy answers 500 `serverInternal` and
  carries the CA's own explanation, and that is the same answer whether the
  refusal is discovered at finalize or later by the pending sweep, so one
  refusal reads the same way wherever you meet it.

- An order whose certificate request is already at the certificate authority can
  no longer be demoted out from under itself (#312). Deactivating an
  authorization or an account after that point does not invalidate the order,
  because the issuance decision was already taken and a deactivated
  authorization was not its basis. A client that wants the certificate dead uses
  revoke-cert. This is safe only because an order in `processing` is no longer a
  resting state, which the pending approval sweep above is what changed.

- The development host is no longer packaged into the MSI, and its certificate
  authority guard can see the CA it is guarding (#305).

- A certificate whose subject holds a value ending in a backslash is no longer
  read under a name it does not carry (#296). Windows renders such a value bare,
  with no quotes around it, so the backslash lands immediately in front of the
  separator that starts the next component. The common name reader treated that
  backslash as an escape, stepped over the separator behind it, and never found
  the component boundary. A certificate whose common name is `CORP\` and whose
  organisation is `Example` was shown as `CORP, O=Example`.

  It has a second half that needs no unusual component order. A certificate
  authority encodes a name general to specific, so the organisation comes ahead
  of the common name, and a trailing backslash there swallowed the common name
  outright: the reader found none at all and every consumer fell back to showing
  the whole subject. On a template with enrollee supplies subject the requester
  chooses these values, which is what made this the same blast radius as the two
  reader defects before it (#231 and #238): the inventory, the detail heading,
  the activity feed, the revoke dialog's typed name confirmation, and the
  supersession lineage key.

  Truncation made the first half reachable without an unusual order either. An
  over-long subject is stored as the common name followed by a marker, which
  moves the name to the front and puts a separator right behind the backslash,
  and that rewrite is applied to stored rows at every start.

  A backslash is now an ordinary character everywhere in the reader, in the
  service and in the dashboard alike. Windows has no backslash escape in either
  direction, so every backslash that reaches these readers is part of the name.
  Quoted values are unaffected, which is what still carries a common name
  containing a comma. The one visible change on an existing install is confined
  to installs that ran with `Certus:UseMockCa` before the mock started rendering
  subjects the way every other producer does: rows synced by the old mock hold a
  different spelling and will read differently now. Those rows describe
  certificates from a mock authority that announces at every start that
  everything it issues is fake, so they are left as they are.

- Setting `Certus:EnableWalMode` to `false` now takes an existing database out
  of write ahead logging mode (#283). The pragma that sets journal mode only ever
  ran on the true branch, and journal mode is persisted in the database file, so
  a database created with the option on stayed in WAL mode however the option was
  later set. The operator got no error: the line that would have said "WAL mode
  enabled" simply stopped appearing, which reads like it worked. The setting only
  ever worked on a database created for the first time with it already off.

  A second half of the same gap nobody reported is closed with it. The pragma
  answers with the mode the database ended up in, and that row is the only way to
  tell a switch that happened from one that was refused; the code discarded it.
  So on a filesystem that had silently refused WAL, which is the exact filesystem
  the option exists for, the log said "SQLite WAL mode enabled" just as
  confidently as on one where it had taken. The startup line now reports the mode
  the database itself reports, and says whether anything changed.

  A change that cannot be applied is a warning naming both modes, not a failed
  start. Journal mode needs the database file exclusively, so anything else
  holding it open at startup refuses the change, and a database in the wrong
  journal mode still answers every query correctly. Refusing to start would take
  a working install down over a preference, and would do it in a loop, because a
  restart does not close whatever handle refused the switch. It is retried on the
  next start instead. The off state is `delete`, SQLite's own default, so a
  converted database is indistinguishable from one created with the option off.

  This does not rescue a database that is already on a filesystem WAL cannot use.
  Such a database will not open at all, so there is no start on which it could be
  converted, and there was never a WAL mode there to leave in the first place.
  What changes for that case is that the enable path stops reporting a success it
  did not have. The conversion has to happen before the move, and
  `docs/troubleshooting.md` now gives that sequence.

- An ACME client's request to deactivate an authorization now takes effect
  (#268). `POST` to an authorization URL carrying `{"status":"deactivated"}`
  (RFC 8555 section 7.5.2) answered 200 and returned the unchanged
  authorization, because the endpoint implemented only the read half and never
  looked at the request payload. A client relinquishing its authorization for an
  identifier it no longer controls was told it had succeeded while the
  authorization stayed usable for issuance. This is the same false success the
  account resource had in #168, one resource down, and it was filed separately
  out of that fix rather than found later.

  Two ways a deactivation could be undone after the fact are closed with it. The
  background validator sweeps challenges on their own status, so a challenge
  that was already in flight when the deactivation landed still reached the
  validator, and its success path wrote the authorization back to `valid`; it
  now abandons such a challenge instead. And a client could still drive a
  deactivated authorization's pending challenge into validation, which fed that
  same path; that is now refused. Section 7.5.2 also requires that a deactivated
  authorization never be sufficient for issuance, so finalize refuses one, at
  the endpoint and again in front of the CA.

  Deactivation is accepted from `pending` as well as `valid`. Section 7.5.2
  names no source status, and refusing `pending` would leave a client no way to
  abandon a validation it no longer wants. A terminal authorization is refused
  rather than reported as deactivated, and a repeat of a deactivation that
  already applied is accepted and writes nothing.
- A template recording an `ECDH_P256` key algorithm now enrolls, on the curve
  that name carries, instead of being refused (#277). Reading the algorithm from
  where ADCS really stores it (#213) turned up an elliptic curve web server
  template recording `ECDH_P256` rather than `ECDSA_P256`, and the enroller
  refuses any algorithm it cannot generate rather than quietly substituting RSA.
  That refusal was correct in shape and wrong in this one case, so the server's
  own HTTPS certificate could not be issued from such a template and the wizard
  and the ACME tab printed a note where a client command belonged.

  Three things make this different from the substitution #213 was filed about,
  and the last of them is why the change waited. A certificate request is self
  signed, so it cannot carry an encryption only key at all, which means no
  enrollment client anywhere can produce the key the old message asked for. Per
  RFC 5480 both keys encode identically, as `id-ecPublicKey` plus a named curve,
  so the bytes a CA reads are the same either way and the curve is the whole of
  what the template constrains. And the CA was asked directly rather than
  reasoned about: one request was submitted twice, against the ECDH template and
  against a control differing only in that setting, and both were issued. An RSA
  key would still contradict such a template, and is still refused, as are `DSA`,
  `DH`, and anything else outside the set the server can generate.

  The template is nevertheless misconfigured, so the enrollment says so instead
  of hiding it. ADCS records an ECDH algorithm when a template's Purpose on the
  Request Handling tab is "Signature and encryption" rather than "Signature",
  which the same run confirmed by changing only that setting and watching both
  the recorded algorithm and the private key usage move with it. The service logs
  a warning naming that setting, the wizard's Templates and Review steps say the
  same in place, and the generated client commands are correct as printed,
  because the key those clients already produce is the only key that could ever
  have gone in the request.

- A certificate template whose display name carries an invisible character is
  diagnosable rather than a silent outage (#235). The URL character guard added
  in #233 refuses any path carrying a control, line separator, or formatting
  character, and issue #17 deliberately lets an ACME client address a template by
  its display name. Display names come out of Active Directory as unfiltered free
  text and are routinely typed by pasting, and a word processor leaves U+00AD
  SOFT HYPHEN at hyphenation points, so a template that had resolved for years
  became a hard 400 for every client configured with it. Nothing pointed at the
  cause: the response named nothing, and the character is invisible in the
  Certificate Templates console, on the dashboard, and in the client's own
  configuration file alike.

  The guard is unchanged and deliberately so. Refusing a bidirectional override
  in a URL is the whole point of it, and narrowing it to admit soft hyphens would
  reopen what #233 closed. What changed is that the refusal now explains itself
  and that the configuration problem is visible before a client ever hits it. On
  the /acme surface the 400 answers an RFC 8555 problem document naming the class,
  the code point, and the position, and saying to use the programmatic name; that
  is the same envelope, and the same reasoning, as the routing and rate limit
  refusals #147 gave a body to, and a bare `{"error":...}` shape is nothing an
  ACME client can render. Non ACME paths are byte for byte unchanged. The detail
  carries no part of the path and never the character itself, on the same
  discipline the log warning has always kept.

  The setup wizard's template step flags the selected template under "ACME
  readiness", naming the code point and the position and pointing at the General
  tab, alongside the checks that were already there. A template whose
  *programmatic* name carries one is a worse case and gets different treatment:
  ADCS matches a request on that name and Ducks in a Row will not build a request
  attribute string from it, so nothing can be enrolled against such a template on
  any path, and completion refused to record it anyway. Those are now hidden from
  the picker and counted separately, which removes a dead end where the wizard
  offered a template and then refused it four steps later. One warning near
  startup names any affected template that is actually exposed over ACME, and a
  healthy install stays silent. No message anywhere prints the name, because
  writing it would put the characters into the log that the refusal exists to
  keep out of it.

  Resolution itself is untouched: a display name carrying a soft hyphen still
  resolves, and a test pins that, so a later reading of this issue cannot take
  issue #17's dual form promise away to fix a name that never reaches the
  resolver.

- `GET /api/alerts/config` no longer returns the SMTP username, which closes the
  Known Issue published against 0.10.0-beta.1 (#261). `hasCredentials` is now the
  only thing the endpoint says about the relay account name, matching how
  `hasPassword` has always worked two fields away. The endpoint always required
  an administrator session and the password was never affected, so nothing here
  was reachable by an unauthenticated caller, but an SMTP username is the account
  half of a credential and several providers derive it from a real key rather
  than a name, so presence is the right amount to say. The error redactor had
  already been treating it that way: it has listed the username as a value that
  must never reach an error message since #161, which left the config endpoint as
  the one surface disagreeing.

  Returning the value was a deliberate choice when the transport became dashboard
  writable, not an oversight, and it was load bearing: a form has to post back
  what it cannot change, and an empty username meant "contact the relay
  anonymously". Simply withholding the value would therefore have dropped relay
  authentication the first time an operator saved an unrelated field, with no
  error and nothing in the response to notice it by. So the write side changed
  with it. The username now has the same three states the password has had all
  along, and an omitted or empty one means "keep what is stored"; the new
  `clearUsername` flag, surfaced as a "Remove the saved username" checkbox beside
  the field, is the only way to blank it. Setting and clearing in one request is
  refused, the stored name is carried forward under the same lock that protects
  the password blob from a racing save, and a test send with the box left empty
  authenticates with the stored name rather than anonymously. Changes to either
  half of the credential are logged as a state transition, never a value.

  Anyone driving `PUT /api/alerts/config` directly should note the semantic
  change: sending `"username": ""` used to blank the account name and now
  preserves it. That is the safe direction, and `clearUsername` covers the case
  it displaces.

- The write ahead log is now checkpointed into the database when a host stops,
  and the Known Issue published against 0.10.0-beta.1 about uninstalling losing
  recent data is withdrawn (#215). Those notes said the uninstall keeps `ducks.db`
  but takes the `ducks.db-shm` and `ducks.db-wal` sidecar files with it, and that
  an un-checkpointed log therefore loses committed transactions silently. The
  reading was backwards. Stopping the service, with no uninstall
  involved at all, removes both sidecars on its own and leaves `ducks.db` byte for
  byte identical. SQLite deletes them when the last connection to the database
  closes, and it only does that after writing the log back into the database file,
  so a missing sidecar is evidence that every committed transaction reached
  `ducks.db`, not evidence that any were discarded. All the uninstall contributes
  is stopping the service first, which is precisely what the published workaround
  asked the operator to do by hand. The installer never touches the data directory
  and could not: the database appears in no WiX File table, the data directory
  component is a bare `CreateFolder`, and there is no `RemoveFile` anywhere in the
  installer sources.

  The investigation did turn up something worth changing. That guarantee rested on
  process teardown rather than on anything the code asked for, and inside a running
  process that final checkpoint never happens: Microsoft.Data.Sqlite pools
  connections by default, so disposing a database context hands the connection
  back to the pool with its handle still open and SQLite never sees a last
  connection close. Both hosts now run
  `PRAGMA wal_checkpoint(TRUNCATE)` and close their pooled connections on stop,
  ordered to run after every background worker has finished writing. The tests pin
  the property the issue was worried about the direct way, by deleting both
  sidecars outright and then reading a committed row back out of `ducks.db` alone.

- A template that does not take `device-attest-01` orders no longer betrays that
  the feature exists (#193). The identifier loop in `new-order` inspected a
  `permanent-identifier` value before it asked whether the template offered
  device orders at all, so a client sending a deliberately bad value got a
  device specific `malformed` error where a server without the feature would
  answer `unsupportedIdentifier`. Three probes reached that ordering: a value
  over the 253 character ceiling, an empty or
  whitespace only value, and a device identifier mixed with a `dns` one, which
  drew the "exactly one identifier" rule. Each of them distinguished a build in
  a single order request, with the feature switched off. The probe needs an ACME
  account, since the identifier checks run after the request is authenticated,
  but registration is self service on any template that does not require
  external account binding. The offered check now opens the device branch and
  reads nothing before it, so all three refuse
  at the same point in the loop, with the same body, as an identifier type the
  server has never heard of. Once an administrator enables the profile, a bad
  value gets the grammar error it earned, unchanged.

  What this protects is narrower than the code used to claim, and the comment
  now says so: every build since the device attestation train ships the feature
  compiled in, and the documentation describes it, so the product never hid that
  the draft is implemented. What a client must not learn is whether a given
  template has it turned on.

- A template that requires an elliptic curve key is no longer reported as RSA
  (#213). The readiness check asked Active Directory for an attribute named
  `msPKI-Asymmetric-Algorithm`, and there is no such attribute in the schema.
  The read therefore came back empty every time, and a fallback meant for the
  oldest template schemas answered "RSA" for anything on a Key Storage
  Provider, which is every modern template. An ECDSA only template was offered
  as viable, the wizard generated an RSA key for it, and the request was denied
  by the policy module with nothing naming the cause. The algorithm is in fact
  a property packed inside the `msPKI-RA-Application-Policies` attribute, as
  backtick separated triples, and that is where it is now read from. Which
  templates carry those triples is not decided by schema version alone, which
  is the part worth spelling out: version 3 always does, and version 4 does
  unless it is pinned to a legacy provider. Version 4 is what duplicating a
  template with "Server 2012 R2 or later" compatibility produces, so reading
  only version 3 would have left the common case on a current CA still wrong.
  Certificate issuance over ACME was never affected: an ACME client supplies
  its own key and its own CSR.

- A template whose key algorithm cannot be determined now says so, instead of
  claiming RSA (#213). This is the half of the defect that made a failed read
  indistinguishable from a real answer, and it is why the wrong key was
  generated with no warning anywhere. The wizard's checklist and the API now
  report the algorithm as unverified in that case. Enrollment still generates
  an RSA key when nothing contradicts it, because the stock templates are RSA
  and refusing would turn a directory outage into a configuration error, but it
  no longer asserts that the template asked for one.

- The certbot command the wizard prints no longer asks for a key smaller than
  2048 bits (#213). It took the template's stated minimum at face value, so a
  template recording 1024 produced a command an operator would run that asked
  for a 1024 bit key. The server already clamped its own key generation to
  2048; the printed command now clamps the same way.

- The client setup snippets on the ACME tab follow the selected template's key
  algorithm (#213). They hardcoded an RSA 2048 request, with a comment
  explaining that the default template issues RSA, so on an elliptic curve
  template certbot, acme.sh and Caddy were each handed a command that asks for
  the wrong key. All three now read the template's own requirement, and say
  plainly when a client cannot produce the key at all rather than printing a
  flag that will not work.

- The directory search for template attributes now carries deadlines (#213). It
  had none, so a domain controller that accepted the connection and then stopped
  answering could hold a thread pool thread for the operating system's own TCP
  timeout. The principal picker has had this pair of limits since it was
  written; the template lookup was missed.

- The server's own HTTPS certificate now enrolls against a template recorded by
  its display name (#194). ADCS matches a request against the template's
  programmatic name (its AD `cn`) alone, but the recorded template may hold
  either form: the ACME path resolves it and issues fine, while the settings
  page provision and the background renewal submitted the string verbatim. An
  install whose enabled set held `Web Server ACME` therefore issued to ACME
  clients all day and failed every renewal of its own certificate with `Denied
  by Policy Module 0x80094800`, which names neither the cause nor the fix. The
  enroller now resolves the configured value against the CA's own published
  list before it submits anything, so both forms work on every path, and it
  records what it submitted, so an affected install converges on the
  programmatic name at its next successful renewal. The resolution also runs
  before the template's key requirements are read, which the display name had
  been missing in the same way. A CA that answers its template list and does not
  publish the template is now refused by name rather than left to the policy
  module's opaque denial; a template list that cannot be read at all still
  enrolls with the configured name, so a CA or directory outage is never
  reported as a configuration error.

- ACME account update and deactivation now take effect (#168). A `POST` to an
  account URL carrying a contact change (RFC 8555 §7.3.2) or a deactivation
  (§7.3.6) answered 200 and discarded the payload: the handler implemented only
  the read half, so it authenticated the request and echoed the unchanged
  account back. The contact case was inert. The deactivation case was not: a
  client retiring a compromised account key was told the account was dead, and
  it could still create orders. That is a false revocation, and it is the reason
  this was called out separately in the 0.10.0-beta.1 known issues as the one
  defect there reachable by any ACME client rather than only by an authenticated
  administrator. Deactivation now goes through the same service the dashboard
  Deactivate button already used, so it is terminal and it cancels the account's
  open orders in the same write, and the response that performs it reports
  `deactivated` rather than `valid`.

### Changed

- Dashboard error responses now name problem types we can answer for (#402).
  The ten RFC 9457 problem types the dashboard API defines for itself, from a
  certificate that is already revoked to a CA that cannot be reached, now sit
  under `https://ducksinarow.dev/problems/`, and each has a short page there
  saying what it means and what to do. The earlier betas used
  `https://ducksinarow.app/problems/`, a domain Haruspex Systems has never held
  and that now belongs to an unrelated site, so following a type from an error
  led somewhere that had nothing to do with this product. The dashboard itself
  matches on the last part of the type and is unaffected; a script that
  compares the full type string needs the new base. ACME errors are unchanged
  and keep their RFC 8555 `urn:ietf:params:acme:error:` types.

- Test Connection now says why it failed (#440). It used to answer "CA is not
  accessible" for a CA that refused the service's account, a CA that could not
  be reached, and a server missing RSAT-ADCS-Mgmt alike, so an operator was sent
  to check the firewall for a missing permission. Each now gets its own message
  and its own hint. The setup wizard's welcome page no longer promises "less than
  5 minutes": setup takes about five minutes of clicking once the approvals are
  in place, and the approvals are usually the lead time.

- `SECURITY.md` now declares a support period (#407): Ducks in a Row receives
  security fixes until 31 December 2031, at least five years after 1.0.0 became
  generally available, delivered through upgrades to the latest release, with
  no backports. The servicing rule beside it said fixes go into the latest
  minor release while its own table said the latest release; both now say the
  latest release.

- The project does not accept pull requests, and `CONTRIBUTING.md` now says so
  plainly (#341). It previously said that code contributions were not being
  accepted while a Contributor License Agreement was under legal review, and
  promised to enable a CLA Assistant bot and start merging pull requests once
  that review finished, with no date against it. The draft agreement was never
  reviewed and no signature was ever accepted against it, so `CLA.md` has been
  removed rather than shipped with a draft banner on it. Bug reports, feature
  requests, and questions are unaffected and still welcome; `SUPPORT.md` says
  where each one goes.

- The licensing summary now says plainly how the paid tier is delivered (#397).
  The paid tier is not part of this repository and is not covered by the BSL: it
  ships as separate, closed source modules under a commercial license, and the
  four year conversion to Apache 2.0 applies to the source available core. The
  README and SECURITY.md no longer describe a beta.

- A refused ACME request now says which limit refused it (#263). Four rate limit
  policies shared one `Too many requests` problem detail and nothing wrote a log
  line at all, so neither the client nor the operator could tell which of the
  four settings to change: the limiter's own message is written at Debug under a
  source both hosts pin to Warning. The problem document now names the policy,
  for example `Too many new account requests.`, and the service logs a Warning
  naming the policy, the path, the caller's address and the setting to raise.
  That log line is written at most once per policy per minute and reports how
  many refusals it did not log, because a line per refused request would let a
  flood fill the log file using the very traffic the limiter exists to shed
  cheaply. Setting `Certus:RateLimiting:HelpUrl` adds the RFC 8555 section 6.6
  `Link` header pointing at your own documentation; nothing is sent anywhere by
  default.

- Authorization and order polling now have their own rate limit budget,
  `Certus:RateLimiting:PollLimit`, defaulting to 300 per window (#263). Polling
  is the one ACME activity whose request count is set by how long validation
  takes rather than by how many certificates were asked for, and a client
  polling once a second through a twenty five second validation spends twenty
  five to fifty requests on a single certificate. Authorization polling was
  being charged to the general budget of 100, so a small number of concurrent
  issuances could exhaust it part way through, while the order poll beside it
  was exempt from every limit and could not be refused however hard it was hit.
  Both are now on the poll budget. The general budget is unchanged, because with
  polling moved out of it the requests that remain are five or six per issuance.

- ACME rate limiting now uses a sliding window rather than a fixed one, in
  `Certus:RateLimiting:SegmentsPerWindow` steps, defaulting to six (#263). A
  fixed window lets twice the limit through across a boundary and releases every
  permit at the same instant, so a refused fleet retries in lockstep; permits now
  come back gradually instead. `Retry-After` reports one step rather than the
  whole window, so a caller that can proceed sooner is told so. Requests are
  still never queued: queueing on a window this long would hold a connection
  open until the window replenished instead of answering, which is worse for the
  client and for the server than an immediate refusal it can act on.

- The ACME rate limiter is registered in one place for both hosts instead of as
  a byte identical block in each host's `Program.cs` (#263). Only one of the two
  is the deployed host, so a change made to whichever copy happened to be in
  front of you could silently miss production.

- The installation guide PDF is now generated from the markdown documentation
  rather than carrying its own copy of the prose. The two used to drift, and had:
  the guide told readers that no external account binding was ever required long
  after the markdown had been corrected to say it depends on the enforcement
  mode, and it stated the RSA key requirement as universal after the product had
  learned to enrol on a curve. It also stamped a version two releases old on all
  26 pages. The guide now covers sixteen chapters rather than ten, including
  device attestation, external account binding, revocation and backup, and it
  records a digest of the files it is generated from, so
  `docs/check_guide_current.py` can tell when it has fallen behind them.

- Seven parts of the guide that existed only inside the PDF generator are now
  documentation pages in their own right, and readable on the web for the first
  time: system requirements, installation, configuration, ADCS configuration,
  verifying an installation, expiry alerts and uninstalling. Alerting is the one
  worth calling out, because SMTP and webhook configuration had no web page at
  all.

- Three subjects that had no user facing documentation anywhere now have a page
  each: revocation, external account binding as an administrator sees it, and
  backup and restore.

- Log lines, certificate authority permission errors and the dashboard's
  authentication messages now call the product Ducks in a Row rather than
  Certus. Certus remains the code identity, so the `Certus:` configuration keys,
  the `X-Certus-` headers and the assembly names are deliberately unchanged: a
  rename there would break every existing `settings.json`.

- The default alert sender address is now `ducks@localhost` rather than
  `certus@localhost`. This changes behaviour only on an install that enabled
  email alerts without setting a sender address, which the configuration
  validator refuses to save from the dashboard anyway.

- The documented setup wizard was five steps and the wizard has six. The Allowed
  Domains step shipped two days after the guide's screenshots were captured and
  neither the prose nor the images caught up. The screenshot files are renumbered
  to match.

- The developer setup guide described the ADCS integration as using the typed
  `ICertRequest2`, `ICertAdmin2` and `ICertView2` interfaces. It uses none of
  them, deliberately: every call is late bound through `IDispatch`, because
  `ICertRequest2` does not resolve at all on the supported Windows builds and
  the v1 interfaces are dual, so a typed managed declaration lands four vtable
  slots short and corrupts the call. The guide now explains the late bound
  design and why a typed interface must not come back.

- The guide's Service Recovery section described automatic restart on failure
  with escalating delays. The installer does not configure that, and never has;
  the escalating delays belong to a development only script the MSI does not
  run. The installation page now says the service has no automatic recovery and
  gives the one command that adds it.

- Leaving automatic service recovery out of the installer is now recorded as a
  decision rather than an omission (#338). The installation page says why: the
  service's usual failure is a configuration fault it finds while starting,
  which it logs before stopping, so a restart policy would return it to the
  same fault rather than fix anything. The page keeps the `sc.exe failure`
  command for administrators who want it, and now gives `sc.exe failureflag`
  alongside, because Windows does not count a stop that reports an error as a
  failure until that flag is set.

- A `POST` to an authorization URL carrying a `status` the server does not act on
  is refused with 400 `malformed`, where it was previously accepted with 200 and
  discarded (#268). This is a deliberate divergence from the account endpoint,
  which ignores the same shape: RFC 8555 §7.3.2 tells the server to ignore an
  unrecognised status on an account, and §7.5.2 gives no such instruction for an
  authorization, so a 200 there would recreate the false success that issue
  reports. A payload with no `status` member at all, including a bare `{}`, is
  still read as a POST-as-GET, so clients that poll that way are unaffected.

- Deactivating an authorization moves its order to `invalid`, unless the order
  has already reached `valid` or `invalid` (#268). The order can never be
  finalized once one of its authorizations is gone, and leaving it reporting
  `ready` while finalize refuses would be the same "cannot tell a no-op from a
  real state" problem in reverse. An order that already holds a certificate is
  never touched. Deactivating an authorization does **not** revoke a certificate
  already issued from that order; §7.6 revocation is a separate operation.

- A `POST` to a challenge whose authorization has been deactivated is refused
  with 403 `unauthorized` (#268). Reading the challenge is unaffected; only
  putting it back to work is refused.

- A request from a deactivated ACME account is refused with 401 rather than 403
  (#168). RFC 8555 §7.3.6 names that status specifically: "If a server receives
  a POST or POST-as-GET from a deactivated account, it MUST return an error
  response with status code 401 (Unauthorized)". The problem type is unchanged
  (`urn:ietf:params:acme:error:unauthorized`), and a signature that does not
  match the account still answers 403, so the two refusals stay tellable apart.
  `new-account` signed by a deactivated account's key is refused the same way
  instead of returning that account; it could never have registered a fresh
  account with that key regardless, but deactivation should not have an
  exception a reader has to know about.

- An account contact list is capped at 10 entries of at most 255 characters
  each, on registration and on update alike (#168). Until now `contact` was
  written once at registration and never validated. Making it updatable turns it
  into a field any account key holder can rewrite at will, so it needed a bound.
  This is a size guard only: nothing here checks the scheme or the address, and
  a registration carrying a list within the cap behaves exactly as before.

### Fixed

- The cert-manager setup the dashboard writes could not work against a server
  whose own certificate came from the ADCS CA, which is the normal case (#439).
  It carried no `caBundle`, and cert-manager trusts only public roots unless
  told otherwise. It now carries a placeholder that `kubectl apply` refuses
  until it is replaced, with the commands that produce the real value. It also
  left out the template's key: cert-manager defaults to RSA 2048, so on an ECDSA
  template every order was refused by the CA. The manifest now adds a sample
  Certificate whose key matches the template, and says which namespace the EAB
  secret belongs in.
- Three statements in the documentation contradicted the server (#439). The
  list of clients that read ACME Renewal Information named cert-manager, which
  reads it only behind an alpha feature gate in 1.21, and dated certbot's
  support to 2.x rather than 4.1.0. The configuration reference said ACME URLs
  follow the host a client connects to, when a configured `Certus:ExternalUrl`
  decides them. And two pages advised keeping EAB Required and device
  attestation on separate templates, which cannot be done: the enforcement mode
  is one setting for the whole server and an account works on every template,
  so device attestation needs the mode at Off or Optional.
- The message logged when the CA refuses to hand over its own revocation lists
  told the operator to grant Read on the CA, which fixes nothing (#440). Those
  reads go through the CA's request interface, which answers only an account
  holding Request Certificates: measured on a test CA, an account with Read but
  without Request Certificates was refused them. The message now names Request
  Certificates, and the refusal the CA actually sends for it
  (`CERTSRV_E_ENROLL_DENIED`) is recognised as one.
- `AdcsQiProbe` was described, here under 0.10.0-beta.1 and in its own notes, as
  calling no CertAdmin method at all. Since #440 it calls the two that only read,
  `GetMyRoles` and `GetCAProperty`. Nothing that changes a CA is ever called.

### Security

- A standard local user could take over the service's configuration and make
  themselves a dashboard administrator (#489). The data folder inherited the
  permissions of `C:\ProgramData`, which let any local user create files in it
  and own what they created, and the service saved `settings.json` and
  `ducks-setup.json` through a fixed temporary file name. A user who created
  that file first ended up owning the saved file, and could then name their own
  group in `Auth:AdminGroup`, or widen the ACME policy. Three changes close it:
  - **Protected folders.** The installer gives the data folder and the
    installation folder permissions of their own, inheriting nothing: SYSTEM and
    Administrators have full control, and Users may read and run the
    installation folder. Users can no longer open the data folder at all, logs
    included. On a server first installed by an earlier version, the service
    re-applies these permissions to the data folder and everything in it when it
    next starts, so an upgrade cleans up a folder that was open before.
  - **Unpredictable temporary files.** Both files are saved through a temporary
    file with a random name, opened only if it does not already exist, then
    moved into place.
  - **Untrusted files are ignored.** The service reads either file only when its
    owner is SYSTEM or Administrators and no one else may write it. Otherwise it
    logs a Critical line, treats the file as absent and runs on. So on a server
    that was tampered with before the upgrade, nothing in the file takes effect.
    See
    [Troubleshooting](docs/troubleshooting.md#the-service-ignores-a-configuration-file).

  A normal upgrade needs nothing from you: the files the service wrote are owned
  by SYSTEM and stay trusted. `settings.json` remains the place to edit your
  configuration, every key in it included.

- The template OID a certificate authority publishes is now scanned for the
  same deceptive characters as the two template names (#292). It is the third
  value `CR_PROP_TEMPLATES` carries and it was the only one no guard read, so a
  bidirectional override in it reordered the setup wizard's template row and
  could leave the row naming a different template than the one it selects. This
  is a hardening gap rather than an observed failure: an OID is dotted decimal
  in every healthy deployment, but `msPKI-Cert-Template-OID` is a directory
  string, so nothing constrains what an administrator or a template tool writes
  there.

  Nothing is refused and nothing is rewritten, which is the difference from the
  two names. The OID decides neither what can be enrolled nor how a template is
  addressed, so a template carrying a deceptive one issues certificates and
  serves ACME clients exactly as before; it is simply noted, on the wizard's
  template row and in the one warning near startup, naming the code point and
  the position and never the value. The wizard also isolates each of the three
  values it renders, so such a character can no longer reorder the text around
  it whichever of them carries it.

- An ACME `new-order` now validates a `dns` identifier against a host name
  grammar before it creates anything (#345). Until now the only checks on the
  value were that it was not empty and that it was not `localhost` or a
  parseable address in a blocked range, so an IP address, a URL, a path
  fragment, a name carrying a port, and shell metacharacters were all accepted
  as domain names, became authorizations, and reached the HTTP-01 validator's
  fetch URL verbatim. Labels are now letters, digits, hyphens and underscores,
  1 to 63 characters each, 253 characters in all, ASCII only, with at most one
  leading `*.` for a wildcard. Two forms a client might reasonably send are
  refused rather than rewritten: a trailing dot, which is a legal DNS
  presentation form but is accepted today and then always fails finalize, and a
  Unicode name in its U label form, which a client should send as punycode.
  Underscores are deliberately kept: Windows DNS
  accepts them, AD CS issues for names that carry them, and an administrator
  can already put such a name in the allowed domain list. A value the grammar
  cannot read answers 400 `malformed`; an IP address, which reads perfectly
  well and is simply not a name this server issues for, answers 400
  `rejectedIdentifier`, the same answer `127.0.0.1` already gave. A refusal
  never repeats the value back to the client, so it cannot carry the client's
  own text into a problem document, the service log, and the screens that
  render them.

  This matters most on a default install. The challenge validator's egress
  guard vets the address it finally connects to, but it does not fence the
  RFC 1918 private ranges unless an operator turns `BlockPrivateRanges` on, so
  before this change nothing at all stood between an order naming
  `192.168.2.1` and an outbound connection to it. Order time is the one place
  this can be closed without breaking the internal certificate authority case,
  because refusing an address is not the same as refusing the many perfectly
  ordinary internal names that resolve to one.

- The HTTP-01 validator now builds its challenge URL through `Uri` and checks
  what came back, and challenge connections are refused on any port other than
  80 or 443 (#345). The URL was previously assembled by string interpolation,
  and the egress guard reads the host of a connection and nothing else, so an
  identifier such as `10.0.0.5:22` put its own port into the authority and
  steered the validator at an arbitrary internal service, with the challenge
  result reporting whether anything was listening there. An identifier ending
  in `#` did something quieter: it cut the well known path off into a fragment,
  so the request that actually went out asked the host for `/`. Port 80 is the
  port RFC 8555 §8.3 makes the request on and 443 stays reachable because the
  same section permits a redirect to HTTPS. The grammar above already refuses
  every identifier that could reach either of these, which is the point of
  having both: a later loosening of the grammar cannot silently reopen the
  authority.

- A `new-order` payload whose `identifiers` array contained a JSON `null`
  returned a 500 (#345). It now answers 400 `malformed` like any other
  unreadable request body.

### Known Issues

Known in this release and not yet fixed.

- **Pointing an install at a different certificate authority can attach
  revocation records to the wrong certificates (#442).** Ducks in a Row pairs
  each certificate it issued over ACME with its row in the CA inventory by the
  CA's request number, and a request number is only unique within one CA. After
  an install is pointed at another CA, the new CA numbers its requests from 1
  again, so a pair can join two unrelated certificates. A certificate revoked
  at the old CA can then lose its revoked mark in Ducks in a Row, so ACME
  renewal information stops asking clients to replace it and revoke-cert no
  longer answers that it is already revoked. And a revocation through ACME can
  mark an unrelated certificate, from either CA, as revoked in the dashboard's
  inventory. Neither certificate authority's own records change. After such a
  move, treat the certificate authority, not the dashboard, as the record of
  what is revoked, or start again from an empty data folder, which means setting
  up ACME accounts and credentials again.

- **The requester shown on the dashboard is not checked for hidden characters
  (#429).** The requester column is copied from the certificate authority's
  database without the character check the subject, common name and template
  columns get, so a name containing an invisible formatting character, such as
  a bidirectional override, can read differently from the account that
  enrolled. The certificate authority records the name, and an ACME client
  cannot set it: Ducks in a Row submits every ACME request under the server's
  own computer account. Where the requester matters, confirm it at the
  certificate authority.

- **Saving a setting can fail while another program has the setup file open
  (#420).** Finishing the setup wizard, saving its progress between steps, and
  saving the external URL, the allowed domains, the external account binding
  enforcement mode or the revocation scope all rewrite `ducks-setup.json`,
  which sits in the data folder or beside a relocated database, by writing a
  new copy and moving it over the old one. If
  another program, typically an antivirus scanner or a search indexer, has the
  file open at that moment, Windows refuses the move and the save reports an
  error. The file is not damaged, and saving again completes the change.

- **A database folder outside the data folder is not locked down on upgrade
  (#506).** The permissions 1.0.0 gives the data folder, and re-applies when an
  upgraded service first starts, reach that folder alone. Where
  `Certus:DatabasePath` points somewhere else, `ducks-setup.json` lives beside
  the database, and that folder keeps the permissions it had; it is locked down
  only when the service itself created it. The file is still checked before it
  is read: if anyone other than SYSTEM or Administrators may write it, the
  service logs a Critical line, treats the file as absent and offers no template
  over ACME until the permissions are corrected, as the Troubleshooting page
  describes. The default layout, with the database inside the data folder, is
  unaffected.

- **The HTTPS endpoint accepts TLS 1.0 and TLS 1.1 where Windows allows them
  (#484).** The service does not choose its TLS versions, so everything it
  serves over HTTPS (port 5001 by default), the dashboard, the setup wizard,
  the Windows sign in behind them and ACME alike, accepts whatever the server's
  Windows allows, and a default Windows Server 2019 or 2025 install allows both
  old versions. Current browsers no longer offer either. To close it now, add
  `"Kestrel": { "Endpoints": { "Https": { "SslProtocols": ["Tls12",
  "Tls13"] } } }` to `settings.json` in the data folder and restart the
  service, or disable TLS 1.0 and TLS 1.1 for the server in Windows' SCHANNEL
  settings.

- **The software bill of materials lists about fifteen packages that are not
  installed (#434).** They are design time dependencies of the database
  tooling, among them `Newtonsoft.Json` and the `Microsoft.CodeAnalysis` and
  `System.Composition` packages, so a scanner reading the bill can report
  findings against software that is not on the server. It errs toward listing
  too much on purpose: the filter that would remove them also removes packages
  the service does use.


## [0.10.0-beta.1] - 2026-08-09

This is a beta. The installer is not code signed yet, so Windows SmartScreen and
Microsoft Defender will warn you when you run it. Verify the download against
the SHA256 checksum on the release page. A signed 1.0 will follow this beta.
Read the Known Issues section at the foot of these notes before installing.

**Verified on Windows Server 2019 and Windows Server 2025. Not verified on
Windows Server 2022 in this release**, and Server 2022 has a servicing floor
that did not exist before; see the .NET 10 entry under Changed.

### Added

- A persistent way to reach the project, at the foot of every dashboard page
  and of the setup wizard (#242). The product collects no telemetry, so every
  word we get back is one an operator chose to send, which makes it our own
  problem if the way to send it is hard to find. It was: the only in app
  feedback link sat on the Settings page, one of four tabs, and GitHub
  Discussions was named in the support documentation but linked nowhere in the
  interface at all. The footer now carries both. The setup wizard carries it
  too, deliberately, because an operator who gives up partway through setup is
  the one we can least afford to lose and the one no other channel will ever
  hear from. Nothing about this sends anything: the feedback link opens a draft
  in the operator's own mail client, with the subject filled in and the body
  left alone so nothing the app knows rides along uninvited, and the
  Discussions link is an ordinary navigation the operator chooses to make,
  carrying `rel="noopener noreferrer"` so GitHub is not even told where the
  click came from. The Privacy section of the README is unchanged and stays
  true word for word.

- An Alerts card on the Settings page, so the alerting engine is finally visible
  (#161). The product shipped complete expiry monitoring, email and webhook
  notifiers, and an alert history table, and the dashboard referenced none of
  it, so an operator could not find out whether alerting was on, what thresholds
  were in force, who was being told, or whether sending had been failing. The
  card shows all of that plus the most recent alerts, with failures and their
  error text called out, and it says plainly when monitoring is switched off or
  when monitoring is on with nothing configured to send over, which is the state
  a default install is in. The card also has a Send a test button, which delivers
  over every configured channel and reports per channel success or failure,
  because SMTP fails quietly and an alerting system nobody has seen work is one
  nobody should trust. The test is unmistakable at both ends: the email subject
  leads with `[Ducks in a Row TEST]` and says on its first line that no
  certificate is expiring, and the webhook payload is the distinct `test.alert`
  event carrying `test: true` and no certificate list. It goes through the same
  signing path as a real alert, so it proves the real path rather than a
  shortcut. It writes nothing to the alert history, deliberately: that table has
  no way to mark a row as a test, and a test row would consume a real
  certificate's slot in the unique index and permanently suppress its actual
  warning. Roughly a minute of cooldown sits between tests, shared across
  everyone signed in.

- Alert configuration is now writable from the Settings page (#162). It could
  previously only be changed by hand editing `appsettings.json` on the server,
  which is why the card above named that file in four places. Expiry monitoring,
  the check interval, the warning thresholds, the SMTP relay host, the sender
  address and the recipient list are all editable and saved through the settings
  overlay. The load bearing part is not the endpoint but how a saved value is
  applied: .NET flattens a JSON array into indexed keys and merges one index at
  a time, so an overlay saving two thresholds over the four the product ships
  would have yielded four, silently, with every value positive, distinct and
  correctly ordered. Arrays are therefore replaced wholesale rather than merged.

- The whole SMTP transport is configurable from the same card (PR #252). The send
  path always supported the port, transport security and authentication; the
  configuration plumbing stopped at three fields, which left an operator who
  needed a nonstandard port or a credential editing a file on the server for a
  channel the dashboard otherwise owns. Port, an explicit TLS mode (none,
  STARTTLS, implicit), username, password and sender display name are now part
  of the writable set. TLS became a choice instead of a derivation: with no mode
  stored the old rule based on the port still applies, so an install configured
  before the mode existed keeps exactly the behaviour it had, and the card always
  shows the mode a send would actually use. The password is write only end to
  end. It is protected with the Data Protection keyring before it reaches the
  store, and no response, list, log line or error body ever carries it in any
  form, ciphertext included. A save that does not mention the password carries
  the stored one forward, because every save rewrites the whole alert block.
  The webhook block stays file only.

- ACME device attestation (`device-attest-01`, draft-ietf-acme-device-attest-08)
  for issuing to hardware attested devices that present a `permanent-identifier`
  instead of a `dns` name (#139 to #146). Administration lives in a device
  attestation card on the ACME dashboard tab, and the profiles, allowlist, and
  trust anchors are stored in the database, so every change hot applies to in
  flight orders without a restart. Apple is the only attestation format in this
  release; the verifier is a plugin registry keyed on the CBOR format string,
  and TPM and hardware module formats are deferred. The feature is off by
  default and fails closed: a template with no enabled device attestation
  profile does not offer `device-attest-01` at all, so a device order is refused
  as `unsupportedIdentifier` exactly as if the feature were absent. An allowlist
  gates which devices may enrol and an empty allowlist issues to nobody. The
  gate is re-checked at new order, at challenge validation, and at finalize,
  each writing a policy audit row the dashboard labels as blocked by the device
  attestation policy. The attested public key must equal the CSR public key, any
  `dns` SAN on a device order is refused, and the Apple root is embedded and
  pinned, with custom trust anchors allowed only as additions that can never
  shadow or replace it. Documented in docs/device-attestation.md.

- Automatic renewal of the server's own TLS certificate (#105). The wizard
  enrols a TLS certificate for the host from the connected CA, but nothing
  renewed it, so at the end of its validity the host fell back to the self
  signed certificate and trust broke for every browser and ACME client at once.
  A daily background service now re-enrols the certificate inside a renewal
  window, using the same template and computer account path as setup. Renewal
  never restarts the host on its own: a successful renewal installs the new
  certificate and stages it, and the dashboard carries the pending change behind
  an Apply button, which is the announced restart. The window is capped at a
  third of the certificate's validity so a short lived template does not renew
  on every check, and the server's own certificate is kept out of the product's
  expiry alerting.

- Provisioning the server TLS certificate from the Settings page (#106). Once
  setup completes the wizard's one click enrolment is locked, so an installed
  instance previously had no way to provision or re-provision its certificate
  and the certificate warning was inert. The Settings page now offers a Provision
  certificate action on a host that never enrolled one, sharing the same enrol
  and restart flow as renewal, and the external URL certificate warning links
  straight to it.

- Dashboard revocation scope modes (#262). Which certificates the dashboard will
  revoke is now an administrator choice: `ducks-managed` (the default), `custom`
  with a selected template list, or `all`. Every mode sits under the TLS
  capability ceiling described below and none of them can widen it. A status file
  written before the setting existed reads as `ducks-managed` with an empty list,
  so an upgraded install starts narrow rather than wide. Ducks managed is a
  union: a certificate this product issued over ACME, or one whose template is in
  the enabled set. The setting is read fresh on each decision, so a change
  applies without a restart, and the startup log reports the active mode. ACME
  `revoke-cert` is deliberately exempt: a client revoking its own certificate
  keeps its RFC 8555 authorization and must never wait on a dashboard setting,
  because that path is how a key compromise gets answered.

- Private range egress blocking for challenge validation (#102): one setting,
  `Certus:Acme:ChallengeValidation:BlockPrivateRanges`, adds the RFC 1918
  ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) to the HTTP-01 and
  TLS-ALPN-01 egress block list without hand listing CIDRs. Off by default,
  because an internal CA usually validates hosts on exactly these ranges; the
  new hardening guide (docs/hardening.md) documents that tradeoff and the
  `AdditionalBlockedCidrs` recipe for anything else, carrier grade NAT for
  example. With the flag on, an order for a private IP literal is refused at
  order time and a name resolving to a private address fails validation as a
  policy rejection, not a retried transport error.

- Optional AD principal link on EAB credentials (#132): a credential can
  record which directory account (user, computer, or group) it was issued
  to, picked through a debounced type ahead over Active Directory and shown
  on the credential row as "Owner: name (type)". Display and audit only;
  nothing enforces against the link. Only the SID travels on save: the
  server re-resolves it and stores the directory's answer, refusing a SID
  that does not resolve. The name and type are captured at link time, so
  rows stay readable when the directory is unreachable, and a host that
  cannot reach a domain simply shows no picker results. Revoked credentials
  refuse the change like every other edit.

- Client setup snippets for EAB credentials (#131): the dashboard writes
  ready to paste setup for certbot, win-acme, acme.sh, Posh-ACME,
  cert-manager, and Caddy, with a template picker, copy, and download as a
  file. The panel shown right after create or regenerate inlines the real
  secret; afterwards each credential row's Client setup action shows the same
  snippets with a paste placeholder, because the server never returns a
  stored secret. The client docs gained a mode aware external account binding
  section with the per client flags (Traefik included), and troubleshooting
  now covers externalAccountRequired, the unauthorized causes, namespace
  refusals, and recovering EAB secrets after a data folder move (regenerate;
  the key id and namespace survive).

- Per credential domain namespaces for external account binding (#130): an
  EAB credential can carry a domain list, and accounts bound to it may only
  order certificates inside those domains (each entry covering itself and its
  subdomains, the allowed domains matching rules), across every template.
  When the global allowed domain list is on it stays the ceiling and a
  namespace narrows within it; an empty namespace adds no restriction.
  Refusals return the compound rejectedIdentifier response naming the
  credential and show on the dashboard activity feed under their own stages
  (`newOrder-eab`, `finalize-eab`). Credentials also became editable: a new
  edit panel (and PUT endpoint) replaces the name, expiry, and namespace on
  the same key id and secret, applied to the next ACME request immediately;
  moving the expiry forward revives an expired credential, and a revoked one
  stays terminal.

- ACME dashboard tab (#129): a new top level page for who may register and
  order. An enforcement card switches external account binding between off,
  optional, and required (applied to the next ACME request, no restart), with
  a note showing how many existing accounts a Required mode grandfathers. A
  credentials card creates, rotates, and revokes EAB credentials; the MAC
  secret is shown exactly once, right after create or regenerate, and no API
  response ever carries a stored secret. An accounts card lists every ACME
  account with search, a bound and unbound filter, and paging, and can
  deactivate an account, which also invalidates its open orders. The bare
  `/acme` path now serves this page; ACME protocol URLs keep their own 404
  under `/acme/{template}/`.

- External account binding (RFC 8555 section 7.3.4), protocol core: ACME
  account registrations can be bound to administrator issued credentials (a
  key identifier plus a MAC key, HS256/HS384/HS512). Enforcement is a three
  mode setting in the wizard status file: off (the default, and what upgraded
  installs read), optional (a presented binding is verified and recorded,
  unbound registration still allowed), and required (the directory advertises
  externalAccountRequired and unbound registrations are refused). Accounts
  that already exist without a binding keep working; re-registering with a
  valid binding adopts it. Revoking a credential, or its optional expiry,
  blocks new registrations and suspends new orders and finalize for the
  accounts bound to it, until the credential is restored. MAC secrets are
  stored encrypted at rest (Data Protection keyring next to the database,
  DPAPI protected on Windows). The management API and dashboard page follow
  in the next part (#129); this part is the protocol and storage (#128).

- Allowed domains: restrict which DNS names ACME clients can order
  certificates for. Each entry covers the domain and all of its subdomains.
  Managed from the Settings page or the setup wizard, applied immediately
  without a restart, and every refused order appears on the dashboard
  activity feed as Rejected. New installs on a domain joined server start
  restricted to the AD domain; existing installs stay unrestricted until the
  policy is turned on.

- The ACME page is split into tabs, and the accounts list is rebuilt as a
  proper inventory (PR #256). The page was four stacked cards in one scroll, so
  the account inventory an administrator visits daily sat under about a thousand
  lines of configure once settings. The accounts tab is now a URL driven list in
  the shape the certificate inventory already uses: filters on status, credential,
  activity and two date ranges, column sorting, and a page size selector, all
  carried in the query string so a filtered view can be bookmarked and shared.
  The tab itself rides in the query string rather than a path segment, which is
  load bearing: everything below the first `/acme` segment belongs to the ACME
  protocol on this server, so a dashboard route at `/acme/accounts` would answer
  404 on a hard load and never render.

- A page size selector and a sortable Issued column on the certificate inventory
  (PR #241). The list had a fixed page size of 25 and no issue date column at
  all. It now offers 25, 50, 100 or 200 rows per page and sorts on the issue
  date, backed by new indexes on the two sort keys that had none. Pending,
  denied and failed rows render a dash in the new column, as they already do for
  the serial and expiry cells.

- A dark mode toggle across the whole application (#163). Dark readiness was
  much thinner than it looked: it was carried by six tokens that only six
  dashboard components imported, while 45 other files hand rolled light colours
  with no dark variant and 27 sites applied colours as inline styles that no
  class can reach. A toggle alone would have lit the dashboard and left every
  other route white. The theme is now semantic custom properties flipped by a
  single class, with every light value the exact colour it replaced, so light
  mode is unchanged and dark is purely additive. The class is set before first
  paint from a separate same origin file rather than an inline script, so the
  content security policy stays intact and there is no flash of the wrong theme.

- Certificate detail now hands the administrator the certificate itself (#158).
  There was no download, no PEM, no thumbprint and nothing about the key, so
  anyone checking whether a host was serving the certificate Ducks believed it
  was had to leave the product. The detail page now offers the certificate as a
  download and as PEM text, and shows the SHA-256 thumbprint, key algorithm and
  size, signature algorithm, and the extended key usages.

- Revoking a certificate from its detail page (#159). Revocation already worked
  for ACME clients and no human could reach it, so an administrator holding a
  compromised certificate opened the Certification Authority console instead.
  This is the highest blast radius write in the product, because the CA will
  revoke any certificate in its database whether Ducks issued it or not, the
  free tier has no role separation, and Certificate Hold is the only reversible
  reason. The design answers that rather than assuming good aim: the reason is
  chosen explicitly, the consequence is stated before the action, and the scope
  of what may be revoked at all is bounded by the TLS capability ceiling and the
  revocation scope modes described elsewhere in these notes.

- Filtering the certificate list by expiry state (#155). Expiry is the reason
  people open a certificate manager and it was the one thing the list could not
  filter on, so "what is about to expire" meant sorting by the Expires column
  and reading down the page. Four chips now sit above the table (Valid, Expiring
  soon, Expired, Revoked), backed by a single state parameter the server
  resolves, and the dashboard Quick Actions point at the same filters.

- The inventory says which certificates Ducks issued through ACME (#153). The
  list mixed two populations and rendered them identically. A certificate issued
  through Ducks by an ACME client renews itself; one discovered in the CA
  database came from autoenrolment, the Certification Authority console, or a
  person with certreq, and nothing in Ducks will ever renew it. To an operator
  those are opposite kinds of object and now look it.

- Supersession is inferred and labelled as an inference (#154). The inventory was
  flat, so the question that matters most, has this been replaced, could not be
  answered: an expired certificate renewed six times since and an expiring one
  with no successor looked identical. The CA database does not record renewals,
  so the relationship is worked out locally from certificates sharing a template
  and subject, and the interface says plainly that it is inferred rather than
  read from the CA.

- The CA's own explanation for a stuck request is surfaced (#151). The dashboard
  showed a status word and nothing else for a request that pended, was denied or
  failed, while the CA had recorded its reason all along in a column nothing
  queried. Pending, denied and failed requests are now synced at all, which they
  previously were not, and their detail pages carry the CA's disposition message
  and status code.

- Certificate crypto detail is captured from the DER already in hand (#150).
  Every sync already pulled the full certificate bytes from the CA and parsed
  them for a display subject and a SAN list, discarding the key algorithm, key
  size, signature algorithm, SHA-256 thumbprint, extended key usages and key
  usage bits carried in the same blob. All of it is now captured, at no extra
  round trip to the CA. This is what the TLS capability ceiling later reads.

- The expiry warning ladder on the certificate detail page (#160). Ducks records
  every expiry notification it sends, failures included, and none of it reached
  the browser, so an administrator could not tell whether anyone had been warned
  that a certificate was about to expire. The page now shows the whole configured
  threshold ladder rather than only the alerts that happen to exist, because a
  bare list cannot show the case that matters: a certificate five days from
  expiry should have warned at 30, 14 and 7, and a gap in that ladder is the
  thing worth seeing.

### Changed

- The whole product now builds and ships on .NET 10 LTS (#169), and the
  version moves to 0.10.0. .NET 8 support ends on 2026-11-10, and the #149
  episode showed what that deadline means in practice: two advisories against
  an 8.0.x package turned every build red, and a fix existed only because the
  8.0.x train was still serviced. After the end date that class of break has
  no fix inside the train. .NET 10 is the current LTS, serviced until
  November 2028. The setup bundle now embeds the ASP.NET Core 10.0.10
  Hosting Bundle, pinned by version and SHA-512 as before; an upgrade in
  place leaves the existing 8 runtime alone (we never uninstall runtimes)
  and installs the 10 runtime beside it. Along the way every certificate
  parse moved from the obsoleted X509Certificate2 constructors to
  X509CertificateLoader (the native SQLite advisory this upgrade also
  cleared is under Security below), and AdcsQiProbe gained a CertAdmin row,
  activation and QI only because every CertAdmin method mutates a live CA,
  so the coclass that revocation dispatches through is now checked on the
  new runtime alongside the existing CertView method invocation probe.

  **This raises the floor on Windows Server 2022.** The .NET 10 runtime
  requires Control-flow Enforcement Technology (CET) there, and a Server 2022
  installation that has not been serviced since early 2022 does not provide it.
  On such a host the service crashes inside `coreclr.dll` with exception code
  `0x80131506` before it writes a single line of its own log, and Windows
  Installer reports that as **Error 1920, "Verify that you have sufficient
  privileges to start system services"**, which is misleading: the installer is
  already elevated and the problem is not permissions. A Server 2022 host at
  build 20348.587 is confirmed too old. Check yours with `winver`. Install
  current Windows updates before installing Ducks in a Row on Server 2022.
  Server 2019 predates the CET requirement and is unaffected; Server 2025 ships
  with it. If a service will not start, the real error is always in
  `C:\ProgramData\Ducks in a Row\logs\ducks-<date>.log`, not in the installer
  dialog.

- `GET /api/alerts/config` no longer returns the webhook address, its custom
  header names, or the SMTP host, port, TLS flag, from address and from name
  (#161). None of it was ever read by the dashboard. The webhook address is
  treated as sensitive because it routinely carries an access token in the URL,
  which is how most webhook services authenticate, and the SMTP transport
  settings belong to whoever provisioned the host. What remains is the recipient
  list, which an operator needs to see, and presence flags for a host, a
  credential, and a signing secret. Anyone reading that JSON directly should
  expect the narrower shape. One field escaped this narrowing and was published
  as a Known Issue below; it was fixed after this release, see #261 in the
  1.0.0 notes.

### Fixed

- The ACME `up` link target accepts POST-as-GET, so a client that walks the
  certificate chain can finish issuing (#373). `/acme/{template}/issuer-cert`
  is the `up` target RFC 8555 §7.4.2 makes mandatory on a certificate
  download, and it accepted only GET and HEAD. A client that followed the link
  the way §7.1 describes, with POST-as-GET, got 405 and could not assemble the
  chain, so issuance failed after validation had already succeeded. Caddy
  (acmez) and Apache mod_md both fail exactly there; every other client the
  suite covers takes the whole chain from the certificate response body
  instead, which is why this went unnoticed. The path now also answers an
  authenticated POST-as-GET returning the same chain. The two methods cache
  deliberately differently: the anonymous GET stays publicly cacheable, which
  is what keeps it from being an amplification vector against the CA, while the
  authenticated POST carries a fresh `Replay-Nonce` (§6.5) and `no-store` like
  every other ACME response.

- Recorded alert errors are stripped of configured secrets before they are shown
  (#161). The webhook notifier builds its failure text from the receiver's whole
  response body, and on an exception it passed the exception message through
  verbatim, so a DNS or TLS failure produced an error naming the webhook address
  and any token embedded in it. That string reached the browser through the
  alert history and, since #160, through the per certificate alert ladder on the
  detail page. It is now redacted and length capped on every read path.

- Honest empty states and sync context on the certificate pages (#157). The
  certificate list now distinguishes a fresh install that has never synced from
  a filter combination that matches nothing: the first names the sync state and
  offers a Sync now button, the second names the active filters and offers to
  clear them. The certificate list and dashboard headers show the connected CA
  name and how long ago the inventory last synced, and a failed sync is visible
  instead of silently swallowed: the header flips to a failure state and a
  dismissible notice carries the problem detail, so a CA that is unreachable
  reads differently from a CA that denied view access, with the exact
  permission fix in the access denied text. Also fixes a regression from #185
  where the manual sync endpoint reported success with zero counts while the
  CA was down, because the per pass catch swallowed the typed CA exceptions.

- The last column of the certificate list named one thing, was labelled another,
  and rendered a third (#156). It was keyed `requestor`, headed "ACME Contact",
  and showed the ACME account's email, which only certificates issued through
  Ducks have, so on a real CA the column was mostly empty and the CA's own record
  of who asked for a certificate never appeared in the list at all. The column is
  now the CA requester throughout, headed "CA Requester" to match the detail page,
  and it sorts in both directions. The ACME contact keeps its place on the detail
  page beside the same field. Sorting by expiry gained a case of its own in the
  query: the Expires header had been sorting correctly only because the fallback
  happened to order by the same column, so any later change to that fallback
  would have broken it silently. An unrecognised sort key still falls through to
  the default rather than failing, which is deliberate.

- Pending and denied requests now carry a real name (#186). Since #151 the sync
  stores pending, denied and failed requests so their detail pages can show the
  CA's explanation, but those rows arrived with an empty subject, so an
  administrator filtering the inventory to Denied saw rows identifiable only by a
  request number and a template. The CA schema carries the subject twice: the
  bare columns hold the issued certificate's name and stay empty until issuance,
  while the request's own names live under the request table. Reading both is
  what made them collide, because stripping the table qualifier keys them
  identically. Both are now read and the request pair is used when the issued
  pair is absent.

- Two simultaneous revocations of the same certificate can no longer both reach
  the CA (#203). The revocation service was a check then act sequence with
  nothing across it: two requests arriving together each got their own database
  context, both read the row as issued, both passed every guard, and both called
  the CA for the same serial. A per serial gate now spans the read, the CA call
  and the resync, so the loser re-reads after the winner's write has landed and
  gets the existing 409 already revoked response. No API or interface change.

- The common name is read past a comma inside a quoted subject (#231). Four
  places pulled the common name out of a stored subject by stopping at the first
  comma, and all four returned a fragment when the name carried one of its own. A
  comma is legal inside a common name and neither encoder that feeds this
  codebase drops it: Windows wraps the whole value in double quotes, and the RFC
  4514 form puts a backslash in front. On a template with enrollee supplies
  subject the common name is whatever the request asked for, so a requester
  decides when this happens. One parser now decides where a name ends and the
  three server readers and the frontend mirror all defer to it.

- Hex escape sequences are no longer decoded out of a stored subject (#238), a
  regression from the fix above. The parser resolved the RFC 4514 `\hh` byte
  form, but neither encoder that reaches it ever writes that form, so the only
  way such a sequence arrived was a requester putting those characters in the
  name and the CA storing them verbatim. Decoding them turned a literal the
  requester chose into a different character the certificate never contained.

- The Alerts card's restart banner clears once the restart it asked for lands
  (PR #246). The banner is derived by the server on every read and clears
  correctly after a restart, but the card never asked again: applying a change
  printed the response and neither polled for the restarted process nor
  invalidated the cached configuration query, whose five minute freshness window
  the whole application shares. So after the service had restarted and the change
  was in force, the banner kept claiming a restart was owed until the operator
  hard reloaded the page. It now polls and invalidates, matching the sibling
  flows that already did this correctly.

- Wizard navigation is locked through the mid wizard TLS restart (PR #248). The
  External URL step's one click TLS enrolment restarts the service, and the
  shell's Next button stayed enabled throughout, because it only checked that the
  URL had been validated, which the administrator earned before starting the
  enrolment. Clicking Next landed on Review, where every request failed: nothing
  answers during the restart, and where the new certificate does not cover the
  host the page is on, that origin never answers again for this browser. The
  step's own panel explained this and offered a continue link, but the enabled
  button right below it silently promised a forward path that does not exist.
  Next is now held until the restart completes and routes to the origin the new
  certificate actually covers.

- Fonts are emitted as files instead of inlined, so the content security policy
  stops blocking them (#255). The bundler inlines any asset under a size limit as
  a data URI, and twenty two of the dashboard's font faces fell under the default,
  so they were emitted as `data:` URIs inside the built stylesheet. The security
  headers send `font-src 'self'` with no `data:` source, so the browser refused
  every one of them, which is the roughly twenty console errors seen on every page
  load. Font extensions are now excluded from inlining specifically, leaving the
  default limit in place for small images, which the image policy already permits.

- "Expiring soon" has one source of truth (#152). It meant 30 days in seven
  independent places and none of them read the operator's configured alert
  thresholds, so an administrator who set the threshold to 60 days received
  warning emails about certificates the dashboard reported as fine, and the
  Expiring Soon stat card could read zero while alerts were going out. All seven
  now read the configured thresholds.

- The email channel no longer reports itself enabled with no sender address
  (#209). The enabled check tested the relay host and the recipient list but not
  the sender, so a configuration with a host, recipients and a blank sender
  reported the channel as working: the certificate detail page said the install
  warns over email, the settings card stayed silent, and the truth only surfaced
  at the relay, where it read as a delivery fault rather than a configuration
  one. The settings card now names this state specifically, rather than using the
  shared "nothing is configured to send over" wording, which is wrong here
  because something is configured, it just cannot build a message. One behaviour
  change worth knowing: with email the only channel and the sender blank, the
  expiry monitor now returns before writing alert history rows, where it
  previously burned a row per threshold on a send that could only fail. The alert
  fires once the configuration is fixed instead of being recorded as permanently
  failed.

- ACME requests refused before they reach a handler now answer the status RFC
  8555 asks for, with a problem document (#147). A POST carrying the wrong
  `Content-Type` returned a bodiless 404 instead of 415, and a plain `GET` on a
  POST only resource returned the same 404 instead of 405, so a client
  integrating against the server was told "not found" for what was really a
  wrong media type or a wrong method. Both are settled by endpoint routing
  rather than by ACME code: the protocol fallback that keeps unknown ACME paths
  off the dashboard shell is an unconstrained catch all, which left it a valid
  route candidate and suppressed the 405 and 415 the framework would otherwise
  have produced. The fallback now works out why the request missed and answers
  404, 405, or 415 with an `urn:ietf:params:acme:error:malformed` document, and
  a 405 carries the `Allow` header. The dashboard API fallback shares the defect
  and gets the same treatment for method mismatches. A rate limited ACME request
  also gains an `urn:ietf:params:acme:error:rateLimited` document and a
  `Retry-After` header instead of a bare 429. Finally, `new-account` and
  `new-order` resolve their template through the same guard the directory
  already used, so an unreachable CA answers 503 `serviceUnavailable` rather
  than faulting to a bare 500.

- The build stamps the commit it was built from back into the shipped binaries
  (#112). The PDB privacy work in 0.9.0-beta.1 turned off the SDK's source
  control lookup, which had the side effect of dropping the commit id from every
  DLL's Product version, leaving a running install with no way to say which build
  it was. The commit now travels independently of that lookup, so the privacy fix
  stays in place and a build from the release source archive, which has no
  repository to read, still succeeds without a stamp. The Settings page shows the
  commit as its own field under the version, and the build fails if a stamped
  build somehow ships without it. The MSI's own version is unchanged and still
  carries no commit: Windows Installer versions are four numbers and cannot hold
  one.

### Security

- A TLS capability ceiling now governs both issuance and dashboard revocation
  (PR #243). A certificate is only revocable through the dashboard, and an ACME
  order only deliverable, when its extended key usage set is non empty and a
  subset of server authentication plus client authentication, its key usage
  carries no certificate or CRL signing, and it is not a CA certificate.
  Undetermined capability blocks rather than passes: no stored certificate and no
  parsed columns, or a certificate that will not decode, is refused. This is
  unconditional and no administrator setting can widen it, which is the point.
  Ducks in a Row syncs the whole CA, so without this a dashboard operator could
  revoke a domain controller certificate, a code signing certificate or the CA's
  own certificate through a product meant to manage TLS server certificates. The
  ordering of the checks is chosen so the refusal message names the most serious
  reason first. Absent key usage and absent basic constraints both pass, because
  both are routine on real TLS leaves.

- ACME finalize now rejects a CSR that carries any non DNS SAN entry (#100,
  SEC-E1). The standard `dns` finalize path previously extracted only dNSName
  entries and submitted the raw CSR to ADCS unchanged, so an iPAddress,
  rfc822Name, directoryName, or UPN otherName rode through unvalidated; on a
  template that honours an enrollee supplied subject the CA would issue that
  identity, and a UPN otherName is usable for Active Directory authentication.
  Both finalize paths now share one audited CSR parser, a CSR with any non DNS
  SAN or a PermanentIdentifier is refused with badCSR before the ADCS submit,
  and the order stays ready for retry.

- ACME finalize also validates the CSR subject common name (#167). After the fix
  above the `dns` path checked SAN entries against the order but never read the
  subject, so a CSR with an authorized SAN and a subject naming a different host
  was forwarded to ADCS, and a template honouring the enrollee supplied subject
  issued it. The no SAN fallback read only the first common name, so a second and
  different one rode through the same way. Every common name present must now be
  one of the order's own dns identifiers, normalized the same way the SAN
  comparison is, and the order stays ready for a retry.

- The enabled template policy fails closed (#101, SEC-E4). A missing, empty, or
  unparseable `ducks-setup.json` previously read as allow all and exposed every
  published CA template over ACME. A null or empty recorded set now exposes
  nothing, an unreadable file keeps the last known set for the request and logs
  the closed posture, and `Certus:Acme:ExposeAllTemplates=true` is the explicit,
  unshipped break glass override.

- Control characters are refused in the ADCS request attribute string (#175).
  Ducks in a Row builds that string as `CertificateTemplate:{templateName}`, and
  ADCS separates attribute pairs with newlines, so a name carrying one could
  append attributes the caller never sent. CVE-2026-54121 ("CertiGhost") is why
  that matters: the `cdc` and `rmd` attributes point the CA's identity lookup at
  an attacker controlled host and yield a domain controller certificate. The ACME
  path was already safe, because a client supplied template string is resolved to
  the CA's own published name before an order is created, so a remote value only
  ever selects a template. The setup wizard was not: its TLS certificate endpoint
  passed a template name from the request body through to the attribute string
  with only a non empty check. That endpoint is administrator authenticated and
  locks once setup completes, so this is defence in depth rather than an open
  door, but it was the one caller handing ADCS an unexamined value.

- Control characters are refused in the CA connection string (#220). The value is
  administrator supplied and was checked only for non emptiness, and it is
  written verbatim into the log file on every ordinary CA operation: info reads,
  template queries, chain reads, submissions, revocations, the connectivity test,
  setup completion and every wizard draft save. A carriage return or line feed
  there forges entries in the log an operator reads to reconstruct what happened,
  and a bidirectional override makes the CA identity render as a different host
  wherever it is echoed. This is not an attribute smuggling vector: the
  connection string is a separate submission parameter and is never concatenated
  into the request attribute string.

- Format characters above the Basic Multilingual Plane are now caught (#228). Two
  scanners read the Unicode category from a character rather than from the
  string, so a format character above the BMP walked straight past them: those
  arrive as a surrogate pair, and the category of a lone surrogate is Surrogate
  and never Format, so a per character lookup cannot see the class at all. The
  tag block U+E0020 to U+E007F is the one that matters, because it encodes
  arbitrary ASCII invisibly, so a value could carry hidden text through every
  screen that displays it.

- Every subject that reaches the stored certificate inventory is sanitized
  (#224). An earlier fix sanitized every subject source on a request row and
  deliberately left the issued and revoked branch untouched so it would not
  rewrite rows that had already synced, which left the same exposure open on a
  different row type. On a template with enrollee supplies subject the common
  name is whatever the request asked for and the CA signs it rather than
  rewriting it, so a signature does not vouch for how a name renders. Ducks also
  syncs the whole CA, so a certificate enrolled by something else entirely still
  reaches the dashboard. Six writers were involved, not the one originally
  reported.

- Control and formatting characters are refused in the URL path (#174). An
  unauthenticated request for a path containing an encoded line feed forged log
  lines: ASP.NET decodes the path before anything reads it, so the escape is a
  real line feed by the time the request logger renders it into the plain text
  file, and one log line became three with the caller writing the middle two.
  Nothing reached the CA, because the ACME template segment only selects a
  template. What it cost was the integrity of the log, which is precisely what
  the hardening guide tells a deployer to read when reconstructing a CertiGhost
  attempt afterwards. Found by live injection testing rather than by source
  review, which a passing test suite would never have surfaced.

- Bumped Microsoft.AspNetCore.Authentication.Negotiate to 8.0.29 (#164, #165) to
  clear two high severity elevation of privilege advisories in the Negotiate
  authentication handler (CVE-2026-47300 and CVE-2026-47303, reported as
  NU1903). Dependency only, no code changed.

- Lifted the native SQLite library past a high severity advisory in its
  bundled SQLite (GHSA-2m69-gcr7-jv3q, reported as NU1903 by the transitive
  dependency audit that .NET 10 turns on by default) by pinning
  SQLitePCLRaw.bundle_e_sqlite3 to 2.1.12, the first version outside the
  advisory range (#169). Dependency only, no code changed.

### Known Issues

Known and reproduced against this build on Windows Server 2019. All are fixed in
a following release, with one exception: the uninstall data loss entry (#215) was
withdrawn as a false positive rather than fixed, and its entry below says so.
All but one need an authenticated administrator session to reach; the ACME
account deactivation defect (#168) is reachable by any ACME client holding a
valid account key, and is called out as such below.

- **The alerts configuration endpoint returns the SMTP username (#261).**
  `GET /api/alerts/config` includes the configured SMTP username in plaintext in
  the response body, alongside the presence flag that was meant to replace it.
  The password is not affected and never leaves the server in any form. The
  endpoint requires an administrator session.

- **Uninstalling through the bundle can lose recent data (#215).**
  **Withdrawn: a false positive, not a defect.** A missing `ducks.db-wal` after
  an uninstall is evidence that every committed transaction reached `ducks.db`,
  not that any were discarded. SQLite deletes the sidecars only after writing the
  log back into the database file, and the installer never touches the data
  directory. The full correction, and the checkpoint on stop that was added
  alongside it, are in the 1.0.0 notes above. Nothing
  below needs acting on; it is kept as a record of what was published against
  this build.

  As published: the data directory and `ducks.db` survive an uninstall, as
  intended, but the `ducks.db-shm` and `ducks.db-wal` sidecar files do not. The
  database runs in write ahead logging mode, so if it was not cleanly
  checkpointed the write ahead log holds committed transactions that are not yet
  in the main file. Removing it discards them silently: `ducks.db` still opens
  afterwards and the missing rows look like they were never written rather than
  like a failed uninstall. Stop the service cleanly before uninstalling so the
  database checkpoints first, and take a copy of the whole data directory if the
  data matters.

- **Templates with an ECDSA key are reported as RSA (#213).** The template
  readiness check reads a directory attribute that does not exist in the Active
  Directory schema and falls back to reporting RSA for every provider. A template
  configured to accept only ECDSA is therefore offered as viable, the wizard
  generates an RSA key for it, and a correctly configured CA denies the request.
  This affects the server's own TLS enrolment through the wizard and the Settings
  page. Certificate issuance over ACME is not affected: an ACME client supplies
  its own key and its own CSR.

- **ACME account update and deactivation take no effect (#168).** `POST` to an
  account URL returns 200 for a contact change or a deactivation request, but
  neither is persisted. A client that deactivates its account is told the
  deactivation succeeded and can still create orders with it. Revoke the account's
  external account binding credential, or deactivate the account from the ACME
  dashboard tab, both of which do take effect.

- **Two narrow character guard gaps remain (#232, #234).** The line and paragraph
  separators U+2028 and U+2029 are neither control nor format characters, so they
  pass every one of the character guards described under Security above; log
  readers that split on them, which the standard permits, would see one line as
  two. Separately, the certificate download filename strips characters that are
  invalid in a Windows filename but not Unicode format characters, so a
  bidirectional override in a certificate's common name can make the filename in
  the browser's download bar read differently from what the file is. Both are low
  severity and neither affects issuance.

## [0.9.0-beta.1] - 2026-07-13

The first public release of Ducks in a Row. It ships unsigned: Haruspex
Systems B.V. is still being set up, so a code signing certificate is not
available yet. A signed 1.0 follows this beta.

### Added

- ACME server (RFC 8555) that proxies certificate enrolment to Active Directory
  Certificate Services.
- A directory per ADCS template at `/acme/{template}/directory`.
- HTTP-01, DNS-01, and TLS-ALPN-01 challenge validation.
- React dashboard showing the full certificate inventory read from the ADCS CA
  database.
- Expiry monitoring with email (SMTP) and webhook alerts.
- Guided, browser based setup wizard that discovers the CAs published in Active
  Directory, live tests the connection, applies the configuration, and restarts
  the service to load it.
- Windows Integrated Authentication on the dashboard, gated to a configured
  administrator group.
- MSI installer and Windows service for production deployment, with a data
  folder prompt (also settable unattended via `DATAFOLDER=`).
- EF Core schema migrations: existing databases upgrade in place at service
  start; databases from before migrations were introduced are adopted when
  their schema matches, otherwise startup fails with a documented reset.
- Certificate revocation tracking: a dashboard tile and filtered view for
  revoked certificates, with the revocation date and reason shown whether the
  certificate was revoked through ACME or directly on the CA console.
- One click TLS certificate enrollment for the server itself during setup,
  issued from your own CA, so the dashboard and ACME clients trust the
  connection without a manual certificate.
- The setup wizard checks each certificate template for ACME readiness and
  explains any issue, restricts the list to templates that will actually
  work, and resumes where you left off if interrupted partway through.
- Change the external URL from the dashboard Settings page any time after
  setup, without hand editing configuration files.
- Manual certificate renewal and CA certificate chain download from the
  dashboard.
- On demand inventory sync: a Refresh button, plus an automatic sync right
  after any issuance or revocation, so the dashboard catches up in seconds
  rather than waiting for the next scheduled cycle.

### Changed

- Default sync interval lowered from 15 to 5 minutes, so a certificate
  revoked directly on the CA console appears on the dashboard within about
  five minutes instead of up to sixteen.
- The Fleet Health score reads "No certificates yet" rather than a
  misleading 100% healthy before anything has been issued.
- Dashboard mascot and browser tab icon updated to the duck knight artwork.

- **Clean break rename** of everything user visible from Certus to Ducks in a
  Row: install folder `C:\Program Files\Ducks in a Row`, data folder
  `C:\ProgramData\Ducks in a Row`, Windows service `DucksInARow`, executable
  `DucksInARow.Service.exe`, database `ducks.db`, log files `ducks-*.log`,
  installer `Ducks-in-a-Row.msi`. Existing pre release installs are not
  migrated: uninstall the old product, install the new MSI, and delete the old
  `C:\ProgramData\Certus` folder when you no longer need it.
- An empty CA connection string no longer falls back to the mock CA. The
  service starts unconfigured (CA operations answer 503 until the setup wizard
  connects a CA); the mock now requires the explicit `Certus:UseMockCa=true`
  and shows a banner in the dashboard.
- Same version rebuilds of the MSI now replace the installed product instead
  of installing beside it. Installing the new MSI also removes stacked
  duplicate installs from earlier builds and stops the orphaned service they
  left behind; uninstall reliably stops and removes the service again.
