# Licensing in plain language

Ducks in a Row is published under the [Business Source License 1.1](LICENSE)
(BSL). The BSL is **source available**, not OSI open source. This page
summarizes what that means for you. The [LICENSE](LICENSE) file is the binding
text; if anything here disagrees with it, the LICENSE wins.

## What you can do for free

You can read, modify, build, and **run Ducks in a Row in production at no
charge** to manage the lifecycle of certificates — discovery, issuance,
renewal, revocation, monitoring, and alerting — for:

- infrastructure that you own or operate, or
- infrastructure that you administer for your customers as part of a broader
  managed IT service (for example, as a managed service provider).

You do not owe us anything to use the free tier this way, no matter how many
certificates you manage.

## What requires a commercial license

You need a commercial license from Haruspex Systems B.V. if you want to:

- offer Ducks in a Row to third parties as a **hosted or managed service**
  whose value comes mainly from the software itself, or
- **resell or redistribute** it as a competing commercial certificate
  lifecycle management product.

If that describes you, contact us about a commercial license rather than using
the work under the BSL.

## The paid tier is separate

This repository holds the core of Ducks in a Row, and everything in it is
published under the BSL as this page describes. The paid tier is not part of
this repository and is not covered by the BSL: it ships as separate, closed
source modules that install alongside the core, under a commercial license from
Haruspex Systems B.V. The four year conversion to Apache 2.0 described below
applies to the core.

## It becomes open source over time

Each released version of Ducks in a Row automatically converts to the
**Apache License 2.0** four years after that version was first made available.
At that point the version is fully open source.

## Why BSL and not MIT or Apache from day one

We want the source to be readable so you can audit exactly what talks to your
certificate authority, and we want it free for real production use. BSL gives
you both, while preventing someone from reselling our work against us before it
ages into open source. It is the honest middle ground between closed source and
permissive open source.

## Commercial licensing and questions

Contact Haruspex Systems B.V. (Zevenaar, the Netherlands, KVK 42142878) at
licensing@haruspex.systems.
