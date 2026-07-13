# Troubleshooting

Where to look first:

- **Logs:** `logs\ducks-*.log` in the data folder (default
  `C:\ProgramData\Ducks in a Row`; daily files, 30 day retention).
- **Windows Event Log:** Application channel, source `DucksInARow.Service`.
- **Health:** `Invoke-RestMethod https://your-server:5001/health` returns
  `Healthy`, `Degraded`, or `Unhealthy`.
- **Service:** `Get-Service DucksInARow`.

| Health result | Meaning |
|---|---|
| Healthy | Database is accessible and the CA connection works |
| Degraded | Database works but the CA is not reachable |
| Unhealthy | Database is not accessible |

## CA operations answer 503, or the dashboard sends me to the setup wizard

No CA is configured yet. The service starts unconfigured on a fresh install:
it serves the setup wizard and answers 503 for every CA operation until the
wizard connects a CA. Complete the wizard at `http://localhost:5000/setup`; it
discovers the CAs in Active Directory, tests the connection, writes the
configuration to `settings.json` in the data folder, and restarts the service.

If the wizard says setup is already complete but the dashboard still reports
the CA unavailable, check `settings.json` in the data folder for
`Certus:CaConnectionString`, then restart:

```powershell
Restart-Service DucksInARow
```

## DISP_E_MEMBERNOTFOUND (0x80020003) in the logs

The ADCS COM classes are not registered on the Ducks in a Row server. Install
the ADCS Remote Administration Tools and restart the service. This feature is
required even though this server is not the CA:

```powershell
Install-WindowsFeature RSAT-ADCS-Mgmt
Restart-Service DucksInARow
```

## Health is Degraded (CA not reachable)

- Confirm `Certus:CaConnectionString` (in `settings.json` in the data folder)
  is in `CAHOST\CA Name` form.
- Confirm the server is domain joined and can reach the CA.
- Confirm DCOM and RPC are allowed to the CA: TCP 135 plus the dynamic range
  49152 to 65535.
- Test from the Ducks in a Row server:

  ```powershell
  certutil -config "CA01.corp.example.com\Corp Issuing CA" -ping
  ```

## The dashboard is empty

- The machine account needs **Read** permission on the CA (Certification
  Authority console, CA properties, Security tab). Enrolment can work without
  it, but the inventory sync cannot read the CA database. The log reports
  "CA view access denied" in that case.
- The first sync may not have run yet. Sync runs every
  `Certus:SyncIntervalMinutes` (default 5). Restart the service to force one.

## A certificate request fails with "unknown certificate template"

The template name in the directory URL must match a template the CA publishes,
either by its programmatic name (AD `cn`) or its display name. Names are matched
case insensitively. Check the exact names in the setup wizard's template list.
Also confirm the template is published to Active Directory and the machine
account has **Enroll** on it.

## An ACME client reports a TLS or certificate trust error

The HTTPS endpoint uses a self signed certificate by default
(`ducks-selfsigned.pfx` in the data folder). ACME clients reject untrusted
TLS on the ACME server. Either:

- give Ducks in a Row a certificate your clients trust (Kestrel HTTPS
  certificate in `appsettings.json`), or
- add that certificate's root to each client's trust store, or
- for a quick lab test, use the per client switch to skip the check (see
  [Connecting ACME clients](acme-clients.md)).

## An ACME client gets "connection refused"

- The service is running: `Get-Service DucksInARow`.
- The firewall rules exist:

  ```powershell
  Get-NetFirewallRule -DisplayName "Ducks in a Row Certificate Proxy*"
  ```

- The client reaches the server on the right port (5001 for HTTPS, 5000 for
  HTTP).

## The service will not start

- Check the log files and the Application event log.
- Validate `appsettings.json` for JSON errors (a trailing comma or missing quote
  will stop startup).
- Confirm ports 5000 and 5001 are not already in use.
- Run the executable directly from an elevated prompt to see the error:

  ```powershell
  & "C:\Program Files\Ducks in a Row\DucksInARow.Service.exe"
  ```

## Database schema mismatch

The service refuses to start and the log ends with "The existing database was
created by an earlier version and its schema does not match this version".

The database predates the introduction of schema migrations and cannot be
upgraded automatically. Reset it (adjust the path if you chose a different
data folder at install time):

```powershell
Stop-Service DucksInARow
Get-ChildItem "C:\ProgramData\Ducks in a Row\ducks.db*" | Rename-Item -NewName { $_.Name + '.old' }
Start-Service DucksInARow
```

The service recreates the database at the current schema on start. The synced
certificate inventory repopulates from the CA on the next sync. ACME accounts,
orders, challenge state, and alert history are lost; ACME clients register
again automatically on their next run.

Databases created by any version that shipped with migrations upgrade in place
automatically; this reset is only ever needed for databases from before that
point.

## Cannot reach the dashboard, or get a 401

The dashboard and setup API use Windows Integrated Authentication and are
limited to the administrator group. Sign in as a member of the built in
Administrators group, or set `Auth:AdminGroup` to the Windows or Active
Directory group you want to allow, then restart the service.

## Still stuck

Ask in [GitHub Discussions](https://github.com/haruspexsystems/Ducks-in-a-Row/discussions)
or open an [issue](https://github.com/haruspexsystems/Ducks-in-a-Row/issues). For a
suspected security problem, follow [SECURITY.md](../SECURITY.md) instead.
