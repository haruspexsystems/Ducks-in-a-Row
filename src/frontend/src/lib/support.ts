// support.ts — the canonical outward facing URLs for the project, in one place
// so the surfaces that link out cannot drift apart.
//
// Two facts these encode, both load bearing:
//
// 1. They point at the PUBLIC repository. The development repository is
//    private, so a link to it in a shipped build is a 404 for every operator.
//    Nothing here may ever reference it.
// 2. The same URLs and address appear in SUPPORT.md, which tells operators
//    where these links go. The two move together.
//
// Everything here is a plain string handed to an anchor. The app requests none
// of it: a mailto: is handed to the operator's own mail client, and a
// github.com link is a navigation the operator chooses to make. That is what
// keeps the Privacy section of README.md literally true.

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
