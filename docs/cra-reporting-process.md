# Reporting to regulators under the EU Cyber Resilience Act

Status: adopted 3 September 2026, amended 12 September 2026 to name the platform
and the Dutch coordinator now that both are published. Owner: the director of
Haruspex Systems B.V. Reviewed at least annually, and whenever ENISA or the
coordinator CSIRT publish new guidance that touches it. This document describes
our process in plain language; where it and Regulation (EU) 2024/2847 differ,
the Regulation prevails.

## What this document is

Haruspex Systems B.V. (Zevenaar, the Netherlands, KVK 42142878) is the
manufacturer of Ducks in a Row and treats it as a product with digital elements
within the scope of the EU Cyber Resilience Act. From 11 September 2026,
Article 14 of that Regulation obliges us to notify regulators about two kinds
of event on fixed clocks. [SECURITY.md](../SECURITY.md) explains how to report
a vulnerability **to us**; this document explains what we report **onward**, to
whom, and when.

## The two triggers

**An actively exploited vulnerability.** A vulnerability in Ducks in a Row for
which we have reliable evidence that someone has used it against a system
without the consent of its owner. A vulnerability report on its own is not
this; evidence of real use is what makes it this.

**A severe incident having an impact on the security of Ducks in a Row.** An
incident that negatively affects, or is capable of affecting, the product's
ability to protect the availability, authenticity, integrity or
confidentiality of sensitive or important data or functions, or that has led,
or is capable of leading, to the introduction or execution of malicious code
in the product, in the build and release path it ships through, or in the
network and information systems of users of the product.

Everything else, in particular ordinary vulnerability reports with no evidence
of exploitation, is handled under the coordinated disclosure process in
SECURITY.md and is not reported under Article 14. We may still notify
vulnerabilities or incidents voluntarily where that is useful (Article 15).

## Who decides, and how

The director decides whether a trigger is met. The moment the company becomes
aware of facts meeting a trigger is recorded, because every clock below runs
from it. Two standing rules: when in doubt, report, because an early warning
is cheap and silence is not; and a report is never delayed to finish a fix,
because the fix has its own deadline.

## The clocks

| Stage | Actively exploited vulnerability | Severe incident |
|---|---|---|
| Early warning | Within 24 hours of awareness, indicating where applicable the Member States in which the product has been made available | Within 24 hours of awareness, stating at least whether unlawful or malicious acts are suspected and indicating, where applicable, the Member States in which the product has been made available |
| Notification | Within 72 hours of awareness: general information about the product, the general nature of the exploit and the vulnerability, corrective or mitigating measures taken, measures users can take, and where applicable an indication of how sensitive we consider the notified information to be | Within 72 hours of awareness: general information about the nature of the incident, an initial assessment, corrective or mitigating measures taken, and measures users can take |
| Final report | No later than 14 days after a corrective or mitigating measure is available: a description of the vulnerability including severity and impact, information on any exploiting actor where available, and details of the fix | Within one month after the 72 hour notification: a detailed description including severity and impact, the type of threat or root cause likely to have triggered it, and applied and ongoing mitigations |

## Where reports go

Reports are submitted through the **Single Reporting Platform** operated by
ENISA at
[portal.cra-srp.enisa.europa.eu](https://portal.cra-srp.enisa.europa.eu/),
which delivers each notification simultaneously to ENISA and to the CSIRT
designated as coordinator for the Netherlands, where Haruspex Systems B.V. has
its main establishment. ENISA published the list of coordinators on 10
September 2026; the coordinator for the Netherlands is the
[NCSC](https://www.ncsc.nl/contact). The platform has been operational since 11
September 2026. Haruspex Systems B.V. is registered on it, with the director as
its Assigned Representative, which is the platform's own name for the person
who submits on a manufacturer's behalf. No account therefore has to be set up
while a clock is running.

If the platform is temporarily unavailable, we wait and submit as soon as it is
restored, because the notification goes through the platform in any case, and
we contact the NCSC directly in the meantime if the matter cannot wait.

Reporting to regulators is not public disclosure. It does not change the
coordinated disclosure agreed with a reporter under SECURITY.md, and it does
not publish any detail of a vulnerability.

## How users are informed

When an actively exploited vulnerability or a severe incident affects users,
we inform them without undue delay through:

- a **GitHub Security Advisory** on the public repository
  (`haruspexsystems/Ducks-in-a-Row`), naming the affected versions, the risk,
  any mitigation available now, and the fix once it exists; and
- the **release notes** of the release that carries the fix.

Where a mitigation exists before a fix, the advisory carries the mitigation so
users can protect themselves while the fix is built. To receive these notices,
watch the repository's security advisories and releases.

## Records

For each Article 14 event we keep: the awareness timestamp, the decisions
taken with their reasons, a copy of each submission and acknowledgment, and
the user notice. These records are kept with the product's technical
documentation.
