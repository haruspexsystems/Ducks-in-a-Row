// support.ts — the canonical outward facing URLs for the project, in one place
// so the surfaces that link out cannot drift apart.
//
// Three facts these encode, all load bearing:
//
// 1. They point at the PUBLIC repository or at our website, ducksinarow.dev.
//    The development repository is private, so a link to it in a shipped build
//    is a 404 for every operator. Nothing here may ever reference it.
// 2. The support URLs and address appear in SUPPORT.md too, which tells
//    operators where these links go, and the two move together. The one
//    exception is MONITOR_MODE_URL, which explains a mode rather than offering
//    help, so it lives with the dashboard's problem type pages instead.
// 3. A URL ships inside every build that carries it and cannot be changed
//    afterwards. A page these name is therefore a contract for as long as that
//    build is installed: a later release may point somewhere new, but the old
//    page has to keep working for the builds already out there.
//
// Everything here is a plain string handed to an anchor. The app requests none
// of it: a mailto: is handed to the operator's own mail client, and a web link
// is a navigation the operator chooses to make. That is what keeps the Privacy
// section of README.md literally true.

/** The public repository. */
export const SUPPORT_GITHUB_URL = 'https://github.com/haruspexsystems/Ducks-in-a-Row';

/** Questions, feature ideas, and general discussion. */
export const SUPPORT_DISCUSSIONS_URL = `${SUPPORT_GITHUB_URL}/discussions`;

/**
 * Feedback by email. The subject is prefilled so replies are easy to sort; the
 * body deliberately is not, so nothing the app knows about the operator rides
 * along uninvited.
 */
export const FEEDBACK_MAILTO =
  'mailto:feedback@haruspex.systems?subject=Ducks%20in%20a%20Row%20feedback';

/**
 * The sign up for security notices (issue #242): the list we email when a
 * release fixes a vulnerability, with what is affected and which release
 * fixes it. The product collects no telemetry, so this list is the only way we
 * can tell an operator about a fix.
 *
 * It is a page of its own on our website, for an operator who has already
 * installed; what the form offers is the website's to describe, in its
 * README and in the privacy notice. No release has linked anywhere else:
 * 1.0.0 was cut before this constant existed. The product posts nothing to it:
 * the operator's browser opens the page, and the operator decides. The URL
 * carries no parameter, so the page cannot tell which installation sent the
 * visitor.
 */
export const SECURITY_NOTICES_URL = 'https://ducksinarow.dev/notices';

/**
 * Security advisories on the public repository, for an operator who would
 * rather watch GitHub than give us an address. SECURITY.md promises one for every
 * fixed vulnerability.
 */
export const SECURITY_ADVISORIES_URL = `${SUPPORT_GITHUB_URL}/security/advisories`;

/**
 * The releases on the public repository (issue #623). The product never
 * contacts the internet, so it cannot check for a newer release; the Settings
 * About block shows how old the installed one is and points here instead,
 * and the Setup Complete page says the same once. A link out, never a fetch,
 * like every other address in this file.
 */
export const RELEASES_URL = `${SUPPORT_GITHUB_URL}/releases`;

/**
 * What monitor mode is (issue #470), linked from the dashboard's monitor mode
 * badge. It is also the problem type every monitor mode refusal on the
 * dashboard API carries (DashboardProblemType.MonitorMode on the server), so
 * the badge and a refusal lead to the same page, which the site publishes
 * under its problem types.
 */
export const MONITOR_MODE_URL = 'https://ducksinarow.dev/problems/monitor-mode';
