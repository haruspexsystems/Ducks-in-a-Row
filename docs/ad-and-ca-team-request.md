# What to ask your AD and CA team

Ducks in a Row is a Windows service that sends certificate requests to your
existing Active Directory Certificate Services CA as its own computer account,
the same way any domain member enrols. It holds none of the CA's keys and needs
no domain administrator rights, no schema change, and no service account or
password.

This page lists everything the server needs from the people who run Active
Directory, the CA and the network, so you can forward it to them before you
install. Setup takes about five minutes of clicking once these are in place, and
the approvals are usually the lead time, so ask for them first. The
[change request](#the-change-request) at the end is ready to copy.

## The account the CA sees

The service runs as LocalSystem. On the network LocalSystem acts as the server's
computer account, so every right on this page is granted to that account,
written `DOMAIN\SERVERNAME$`. For a server named `DUCKS-SERVER` in the `CORP`
domain that is `CORP\DUCKS-SERVER$`. No person's account is involved, and there
is no password to store, rotate or leak.

Computer accounts do not appear in the Windows object picker until you add
**Computers** to the object types.

### Granting to a group

You can grant each right to a group that holds the computer account rather than
to the account itself. If the server is ever rebuilt under a new computer
account, you then change one group membership instead of every grant. Use a
group of its own for this, not Domain Computers: a right held by every computer
in the domain is the kind of broad grant the
[hardening guide](hardening.md#reduce-the-blast-radius) warns about.

A computer picks up a new group membership only when its Kerberos tickets are
renewed, which in practice means a restart. After adding the server's account to
a group, restart the server, or purge the system's tickets and restart the
service:

```powershell
klist -li 0x3e7 purge
Restart-Service DucksInARow
```

Until then the CA still sees the old membership. The setup wizard's rights check
reads group membership from the directory, so a template's Enroll row can read
Inferred through the new group while the CA is still refusing it, and the rows
the CA answers itself keep failing until the restart.

## What to ask for

Each row is one thing to ask for. The rights are named exactly as they appear on
the Security tabs of the Windows consoles, so whoever grants them can find them.

| What | Why it is needed | Who usually grants it and where | Needed when |
|---|---|---|---|
| **Enroll** on each certificate template you expose over ACME | The CA checks it on every request. The server's own HTTPS certificate comes from the first template you choose at setup and is renewed from it, so keep Enroll on that one even if you later stop exposing it | The template owner or CA administrator, in the Certificate Templates console (certtmpl.msc), the template's Properties, Security tab | Always, once per template |
| **Request Certificates** on the CA | Submitting requests, the wizard's Test Connection, the template list, downloading the CA's certificates, CRL watching, and collecting a certificate the CA held for approval | The CA administrator, in the Certification Authority console (certsrv.msc), the CA's Properties, Security tab | Always. Authenticated Users hold it on a default CA, so ask only that nobody removed it |
| **Read** on the CA | The certificate inventory and the expiry alerts built on it. Read alone opens the whole certificate database, and neither this right nor Request Certificates implies the other | The CA administrator, on the same Security tab | Always. Without it issuance works and the dashboard stays empty |
| **Issue and Manage Certificates** on the CA (optional) | Every revocation the product makes: from the dashboard, by an ACME client revoking its own certificate, and the automatic revocation of a certificate that breaks the capability ceiling. It also lets the account approve and deny requests the CA holds | The CA administrator, on the same Security tab | Only if you want revocation. See below for what is lost without it |
| Membership of the CA server's **Certificate Service DCOM Access** group | The CA is called over DCOM, and on the CA server this group is what lets an ordinary account activate it from the network. On a default CA, Authenticated Users is a member, which covers every domain computer | The CA server's administrator, in Computer Management, Local Users and Groups | Always. Ask only that nobody removed Authenticated Users |
| The ADCS Remote Administration Tools (RSAT-ADCS-Mgmt) on the Ducks in a Row server | They register the ADCS COM classes the service uses to talk to the CA | Whoever administers the Ducks in a Row server | Always, before setup |
| Domain membership in the CA's forest | The CA authenticates the server's computer account through Active Directory, and the service reads certificate templates from the forest's directory | A domain administrator, or an account delegated to join computers | Always |
| TCP 135 and TCP 49152 to 65535 from the Ducks in a Row server to the CA | DCOM and RPC: the endpoint mapper first, then a dynamic port | The network team, and the CA server's own firewall | Always |
| TCP 5001 from ACME clients and administrators to the Ducks in a Row server, and TCP 5000 if you want it | 5001 serves ACME and the dashboard over HTTPS. With the default settings 5000 only redirects to 5001. The installer opens both in this server's own firewall, and nothing upstream | The network team | 5001 always. 5000 only for people who type an http address |
| TCP 80 and TCP 443 from the Ducks in a Row server to the names being validated, and DNS to the server's own DNS servers | The server performs ACME validation itself: TCP 80 for HTTP-01, TCP 443 for TLS-ALPN-01, and for DNS-01 its own DNS servers on port 53, TCP and UDP, which must be able to resolve the names being validated | The network team | Only for the challenge types your clients use. None for device-attest-01 |
| HTTP (TCP 80), LDAP (TCP 389), and HTTPS (TCP 443) for any https location, from the Ducks in a Row server to the CRL distribution points | CRL expiry alerts read every published copy of each CRL. A parent CA's CRL, such as an offline root's, is read only from these locations | The network team, and whoever runs the web server that publishes your CRLs | Optional. Without it the connected CA's own CRLs are still read from the CA |
| SMTP (TCP 587 by default) and your webhook endpoints, from the Ducks in a Row server | Expiry alerts by email and by webhook | The mail and network teams | Only when alerts are configured |
| A group for the dashboard's administrators (optional) | Auth:AdminGroup names the Windows or Active Directory group whose members may sign in to the dashboard. Left unset, it is this server's local Administrators group | An Active Directory administrator | Optional |

Install the tools from an elevated PowerShell session on the Ducks in a Row
server. They are needed even though this server is not the CA:

```powershell
Install-WindowsFeature RSAT-ADCS-Mgmt
```

**Without Issue and Manage Certificates**, issuance, the inventory and alerts
keep working, and every revocation fails with a permission error naming the
right. That includes an ACME client revoking a certificate whose key it believes
is compromised, and the automatic revocation at finalize: a certificate that
breaks the ceiling then stays valid at the CA, and the service log names its
serial number and asks for it to be revoked by hand. The client still never
receives it. See [what the CA has to allow](revocation.md#what-the-ca-has-to-allow)
before you decide.

> **A CA installed on a domain controller.** The defaults above were checked on
> CAs installed on member servers. A domain controller has no local groups, so
> there the Certificate Service DCOM Access group is the domain's group of that
> name, in the Builtin container of Active Directory Users and Computers. Check
> its members rather than assuming.

## What is not being asked for

- No **Autoenroll** on any template. Nothing here autoenrols.
- No **Write** or **Full Control** on a template, and no change to any template.
- No **Manage CA**, and no change to the CA's settings or flags. In particular,
  never `EDITF_ATTRIBUTESUBJECTALTNAME2`: the product does not need it, and it
  lets any requester add any subject alternative name on every template.
- **Issue and Manage Certificates** only if you want revocation through Ducks in
  a Row, the automatic revocation at finalize included.
- In [monitor mode](monitor-mode.md), no **Enroll** and no **Issue and Manage
  Certificates** at all. Read on the CA, plus the Request Certificates a default
  CA already grants, is the whole request, which makes it the easier first ask on
  a production CA.
- No rights in Active Directory. The service reads certificate templates, the
  CA's enrollment record and its own group memberships with the read access
  every domain computer already has.
- No domain administrator, no schema extension, and no service account.

## The change request

Fill in the three placeholders and delete the lines you do not need.

```
Change request: rights for the Ducks in a Row certificate service

Ducks in a Row is a Windows service that sends certificate requests to
our CA as its own computer account. It holds no CA keys and needs no
domain administrator rights, no schema change and no service account.

Computer account:  <COMPUTER ACCOUNT>   (for example CORP\DUCKS-SERVER$)
CA:                <CA>
Templates:         <TEMPLATES>

Please grant, to the computer account or to a group that holds it:

1. Enroll, and not Autoenroll, on each template listed above.
   Certificate Templates console, template Properties, Security tab.
2. Read on the CA.
   Certification Authority console, CA Properties, Security tab.
3. Only if we revoke through Ducks in a Row, the automatic revocation at
   finalize included: Issue and Manage Certificates on the CA, on the same
   tab.

Please confirm these defaults are still in place:

4. Request Certificates on the CA, held by Authenticated Users or
   granted to the computer account.
5. Authenticated Users, or the computer account, in the CA server's
   Certificate Service DCOM Access group.

Network:

6. TCP 135 and TCP 49152 to 65535 from the Ducks in a Row server to
   the CA.
7. TCP 5001 from ACME clients and administrators to the Ducks in a Row
   server.
8. Only for what we use: TCP 80 and 443 to the names being validated,
   DNS to our own DNS servers, the CRL distribution points (TCP 80,
   389, and 443 for an https location), SMTP, webhooks.

Not requested: Autoenroll, Write or Full Control on any template, Manage
CA, any change to the CA's flags, any right in Active Directory.

If you grant through a group, please tell us: the server needs a
restart before the CA sees the new membership.

How we will confirm it: the setup wizard checks the service's own
rights after Test Connection and again on its Review step, and the
"Service rights on the CA" card on the Settings page repeats the check.

Rollback: remove the grants above. Nothing else on the CA or in the
directory is changed.
```

What each status in that check means, and how each right is established, is in
[the service's rights](verifying.md#the-services-rights).
