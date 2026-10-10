# ADCS configuration

What to set up on the certificate authority side. Most of this is done once,
and the setup wizard handles the parts it can.

## Finding your CA connection string

The connection string is `hostname\CA Name`. The wizard finds it for you, so
you rarely need to build one by hand. These are the fallbacks.

**Let the wizard discover it.** Open `https://your-server:5001` after
installing. The wizard lists the CAs published in Active Directory and lets you
pick one. It then tests the connection through the same DCOM path the service
uses in production, as the service's own account, and checks what else that
account may do on the CA (see [the service's rights](verifying.md#the-services-rights)).
This is the recommended route and needs nothing typed.

**Read it off the CA.** Open the Certification Authority console
(`certsrv.msc`) on the CA server. The CA name is the node in the console tree.
The connection string is the CA server's hostname, a backslash, then that name.

**Ask the forest.** On any domain joined machine:

```powershell
certutil -config - -ping
```

That lists the available CAs with their connection strings already in the right
form.

Use the fully qualified host name. The short form has not been verified to
work.

> **A CA name may contain a comma or a space.** Both are legal and both are
> handled. Quote the whole string when you pass it to a command line tool.

## Certificate template permissions

The service runs as LocalSystem, so the identity the CA sees is the server's
machine account, written `DOMAIN\SERVERNAME$`. That account needs **Enroll** on
every template you want to expose over ACME.

Template permissions live in the Certificate Templates console, not in the
Certification Authority console:

1. On the CA server, run `certtmpl.msc`. You can also get there from
   `certsrv.msc` by right clicking **Certificate Templates** and choosing
   **Manage**.
2. Right click the template and choose **Properties**.
3. Open the **Security** tab.
4. Add the Ducks in a Row server's machine account, for example
   `DUCKS-SERVER$`. Machine accounts do not appear in the object picker until
   you add **Computers** to the object types.
5. Grant **Enroll**. Do not grant **Autoenroll**: nothing here autoenrols, and
   granting it widens what the account can do for no benefit.
6. Click OK, and repeat for each template you intend to expose.

The wizard's template step checks each published template for ACME readiness and
tells you what is missing. It does not check this permission. The Review step
does: it reads each chosen template's permissions as the service's account and
reports Enroll as **Inferred**, which is a reading and not a proof. Only an
enrolment proves it. In the wizard that is the HTTPS certificate on the External
URL step, for the template it uses; otherwise it is the first ACME order.

## CA read permission

The machine account also needs **Read** on the CA itself: Certification
Authority console, right click the CA, **Properties**, **Security** tab.

Read is what lets the dashboard sync the certificate inventory. Without it
enrolment still works and clients get certificates, but the dashboard stays
empty, which reads like a broken install and is not one.

**Issue and Manage Certificates** is a separate right, needed only for
revocation from the dashboard. See [revocation](revocation.md) before granting
it.

## Template URL mapping

Each template is its own ACME endpoint:

```
https://your-server:5001/acme/<template>/directory
```

`<template>` is the template's programmatic name, which is its Active Directory
`cn`, or its display name. Display names containing spaces work; the client URL
encodes them. A display name carrying an invisible character, such as a soft
hyphen pasted in from a word processor, is refused with a 400 rather than
silently mismatching. Use the programmatic name in that case, and see
[troubleshooting](troubleshooting.md).

No template is reachable over ACME until the wizard records a selection. On a
fresh install every template's directory URL answers 403 until then, which is
deliberate.

## Key algorithm

An ACME client must request the key type the template asks for, and templates
differ. A template built on an RSA provider needs an RSA key; an `ECDSA_P256`
template needs a key on that curve. Requesting the wrong type is refused by the
CA policy module at finalize. See [reading a denial](#reading-a-denial) below for
what that refusal tells you.

You do not have to work this out yourself. The wizard's template step reports
the key algorithm it read from the template, and the **Client setup** snippets
on the ACME page of the dashboard are generated with the right flags for that
template already filled in. Copy them from there rather than from memory.

See [connecting ACME clients](acme-clients.md) for the per client flags.

## Reading a denial

When ADCS refuses a request it records two things: its own message, and a status
code giving the reason. Ducks in a Row reports both, because the message on its
own is often worth very little. A template Enroll denial on a stock Windows CA
answers with the bare string `Denied by Policy Module` and nothing else.

The reason appears wherever the refusal does: in the setup wizard, in the service
log at `C:\ProgramData\Ducks in a Row\logs\ducks-<date>.log`, and in the problem
document an ACME client receives. It reads like this:

    Denied by Policy Module. 0x80094012: The permissions on the certificate
    template do not allow the current user to enroll for this type of certificate.

The codes you are most likely to meet:

| Code | What to do |
| --- | --- |
| `0x80094011` | The CA's own permissions refuse the account. Grant **Request Certificates** on the Security tab of the CA in `certsrv.msc`. |
| `0x80094012` | The template's permissions refuse the account. Grant **Enroll** as described under [certificate template permissions](#certificate-template-permissions). |
| `0x80094014` | A certificate manager denied a request that was waiting for approval. Nothing is misconfigured; this was a decision. |
| `0x80094800` | The template is not published by this CA. Add it under **Certificate Templates** in `certsrv.msc`, and check you named the template rather than its display name. |
| `0x80094811` | The key is smaller than the template's minimum. The wizard's template step reports that minimum. |
| `0x8009480A` | The template requires enrollment agent signatures, which an ACME request never carries. Use a different template. |

A code Ducks in a Row does not have a description for is still reported as a
number. `certutil -error 0x80094012` names any of them.

To confirm the same values at the CA itself:

    certutil -view -restrict "RequestId=109" -out "Request.DispositionMessage,Request.StatusCode"

## Templates that hold requests for approval

A template configured to require manager approval answers every submission
"pending" rather than issuing. That is an ordinary ADCS setting, and it works:
the ACME order stays in `processing` until an operator approves or denies the
request at the CA, and Ducks in a Row finishes the order when that happens.

The wizard warns when a template you select is configured this way, so the
behaviour is not a surprise. Nothing needs configuring for it to work.
