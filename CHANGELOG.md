# Changelog

All notable changes to Ducks in a Row are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  expect the narrower shape. See the Known Issues section: one field still
  escapes this narrowing.

### Fixed

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
a following release. All but one need an authenticated administrator session to
reach; the ACME account deactivation defect (#168) is reachable by any ACME
client holding a valid account key, and is called out as such below.

- **The alerts configuration endpoint returns the SMTP username (#261).**
  `GET /api/alerts/config` includes the configured SMTP username in plaintext in
  the response body, alongside the presence flag that was meant to replace it.
  The password is not affected and never leaves the server in any form. The
  endpoint requires an administrator session.

- **Uninstalling through the bundle can lose recent data (#215).** The data
  directory and `ducks.db` survive an uninstall, as intended, but the
  `ducks.db-shm` and `ducks.db-wal` sidecar files do not. The database runs in
  write ahead logging mode, so if it was not cleanly checkpointed the write ahead
  log holds committed transactions that are not yet in the main file. Removing it
  discards them silently: `ducks.db` still opens afterwards and the missing rows
  look like they were never written rather than like a failed uninstall. Stop the
  service cleanly before uninstalling so the database checkpoints first, and take
  a copy of the whole data directory if the data matters.

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
