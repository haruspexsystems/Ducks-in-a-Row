# The ducksinarow.dev website

This `gh-pages` branch is the website of Ducks in a Row, served by GitHub Pages
at https://ducksinarow.dev. It shares no history with `main`, which holds the
product and is rewritten by the release process on every release. Nothing here
ships in the product.

Plain HTML and one stylesheet. There is no build step: what is on this branch is
what is served.

## Rules

- **No trackers and no third party scripts.** The product promises that nothing
  phones home, and its website keeps the same promise. The one planned exception
  is the newsletter signup form's own code.
- **No prices.** Pricing is shared on request, not published.
- **`/problems/<slug>` is a contract.** Every Ducks in a Row release from 1.0.0
  on names these addresses as the `type` of the problem documents its dashboard
  returns, so a page may be reworded or restyled but never renamed or removed. A
  new problem type in the product needs its page here in the same release.

## Layout

| Path | What it is |
| --- | --- |
| `index.html` | The home page |
| `privacy.html` | The privacy notice, served at `/privacy` and linked from every footer |
| `problems/index.html` | The list of problem types |
| `problems/<slug>.html` | One page per problem type, served at `/problems/<slug>` |
| `404.html` | Served by GitHub Pages for any address with no page |
| `assets/site.css` | The only stylesheet |
| `.nojekyll` | Tells GitHub Pages to serve the files as they are |
| `CNAME` | Written by GitHub when the custom domain is set; do not edit |

Changes arrive as pull requests against this branch.

Copyright 2026 Haruspex Systems B.V. "Ducks in a Row" is a trademark of Haruspex
Systems B.V.
