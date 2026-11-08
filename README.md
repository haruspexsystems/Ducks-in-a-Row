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
  Nor does the `<script type="application/ld+json">` block in the home page's head:
  it is structured data for search engines, and browsers never execute that type.
  It is the only `<script` element allowed on the site.
- **Every request stays on this domain.** Fonts and images are served from
  `/assets`, never from a font service or a CDN. The two fonts are the dashboard's
  own, Hanken Grotesk and JetBrains Mono, latin subset, under the SIL Open Font
  License; their licence files sit beside them and must stay there.
- **One header and one footer.** Every page carries the same header and footer,
  copied from `index.html`. Change them on every page together.
- **The look follows the dashboard.** The colours in `site.css` are the product's
  (slate chrome, duck yellow for the one highlight, teal for links). Yellow is a
  fill behind slate text or a highlight on the dark band, never text on white,
  so every pairing passes WCAG AA.
- **No lab names in pictures either.** `assets/dashboard.webp` and `.png` are a
  dashboard capture with the CA name removed. A new screenshot shows RFC 2606 names
  only and no host, CA or domain from a lab.
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
- **The use case pages follow the docs.** `/acme-for-adcs`, `/crl-expiry-monitoring`
  and `/cert-manager-adcs` are written for people searching for the problem. Every
  claim on them is true of the latest public release and backed by a page in its
  `docs/`, which they link. Where the docs say something has not been run, such as
  parts of cert-manager, the page says so too.
- **Search engines see one address per page.** Every indexable page carries a
  `<link rel="canonical">` with its extensionless address (`/download`, not
  `/download.html`), its own `og:` tags, and an entry in `sitemap.xml`. A new page
  gets all three; a removed page leaves the sitemap. `/thanks`, `/subscribed` and
  `404.html` stay `noindex` or unlisted and carry none of them. The sitemap is kept
  by hand and lists addresses only, no dates. The home page's JSON-LD names no
  price and no version, so it needs no change at a release.
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
| `acme-for-adcs.html`, `crl-expiry-monitoring.html`, `cert-manager-adcs.html` | The use case pages, linked from the home page and the footer's Use cases column |
| `robots.txt` | Lets every crawler in and names the sitemap |
| `sitemap.xml` | Every indexable address, kept by hand |
| `problems/index.html` | The list of problem types |
| `problems/<slug>.html` | One page per problem type, served at `/problems/<slug>` |
| `404.html` | Served by GitHub Pages for any address with no page |
| `assets/site.css` | The only stylesheet |
| `assets/fonts/` | The two self-hosted fonts and their OFL licence files |
| `assets/dashboard.webp`, `assets/dashboard.png` | The dashboard screenshot in the home page's hero, WebP with a PNG fallback |
| `assets/duck-128.png` | The mascot in the header and footer of every page |
| `assets/duck-256.png` | The mascot at 2x; no page uses it since the redesign, kept for links from elsewhere |
| `assets/og-image.png` | The 1200 by 630 picture link previews show, named by the home page's `og:image` |
| `favicon.ico`, `apple-touch-icon.png` | The site icons; browsers fetch both from the root on every page, so no page links them |
| `.nojekyll` | Tells GitHub Pages to serve the files as they are |
| `CNAME` | Written by GitHub when the custom domain is set; do not edit |

Changes arrive as pull requests against this branch.

Copyright 2026 Haruspex Systems B.V. "Ducks in a Row" is a trademark of Haruspex
Systems B.V.
