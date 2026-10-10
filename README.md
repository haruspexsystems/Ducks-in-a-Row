# The ducksinarow.dev website

This `gh-pages` branch is the website of Ducks in a Row, served by GitHub Pages
at https://ducksinarow.dev. It shares no history with `main`, which holds the
product and is rewritten by the release process on every release. Nothing here
ships in the product.

Plain HTML and one stylesheet. There is no build step: what is on this branch is
what is served.

## Rules

- **No trackers and no scripts.** The product promises that nothing phones home,
  and its website keeps the same promise. The sign-up form needs no exception: it
  is a plain HTML form that posts to our own list server, `lists.ducksinarow.dev`.
- **The sign-up forms are a contract with the list server.** `download.html` and
  `notices.html` carry the same two `l` values, the UUIDs of the Security notices
  and Newsletter lists. The list server redirects to `next` only when it matches a
  URL in its Trusted URLs setting exactly: `/download` sends people to `/thanks`,
  and `/notices` to `/subscribed`. Change any of them on both sides together.
- **`/notices` is a contract.** Ducks in a Row releases from 1.1.0 on link it from
  the Setup Complete and Settings pages, so it may be reworded but never renamed
  or removed.
- **No prices.** Pricing is shared on request, not published.
- **Claims follow the release.** Every claim on the home page is true of the latest public
  release, never of the roadmap. The support period sentence is the one in the product's
  `SECURITY.md`, word for word: change both together.
- **`/thanks` links `releases/latest`.** That is right from 1.0.0 on, the first release that
  is not a prerelease. Before it, `releases/latest` led only to the releases list.
- **`/problems/<slug>` is a contract.** Every Ducks in a Row release from 1.0.0
  on names these addresses as the `type` of the problem documents its dashboard
  returns, so a page may be reworded or restyled but never renamed or removed. A
  new problem type in the product needs its page here in the same release.

## Layout

| Path | What it is |
| --- | --- |
| `index.html` | The home page, the product page that launch posts link to |
| `download.html` | The download page: the sign-up form for the security list, with the newsletter as an unticked option |
| `thanks.html` | Where the list server sends people after they sign up on `/download`; it holds the download link and is not indexed |
| `notices.html` | The security notices sign up, linked from the product, with the newsletter as an unticked option |
| `subscribed.html` | Where the list server sends people after they sign up on `/notices`; it says how to confirm and is not indexed |
| `privacy.html` | The privacy notice, served at `/privacy` and linked from every footer |
| `problems/index.html` | The list of problem types |
| `problems/<slug>.html` | One page per problem type, served at `/problems/<slug>` |
| `404.html` | Served by GitHub Pages for any address with no page |
| `assets/site.css` | The only stylesheet |
| `assets/duck-128.png`, `assets/duck-256.png` | The mascot on the home page, at 1x and 2x |
| `assets/og-image.png` | The 1200 by 630 picture link previews show, named by the home page's `og:image` |
| `favicon.ico`, `apple-touch-icon.png` | The site icons; browsers fetch both from the root on every page, so no page links them |
| `.nojekyll` | Tells GitHub Pages to serve the files as they are |
| `CNAME` | Written by GitHub when the custom domain is set; do not edit |

Changes arrive as pull requests against this branch.

Copyright 2026 Haruspex Systems B.V. "Ducks in a Row" is a trademark of Haruspex
Systems B.V.
