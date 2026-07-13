# Documentation images

The guides reference the screenshots below. They are not committed yet. Capture
them from a running instance (a real CA or the mock CA), then save them here with
the exact file names so the references in the guides resolve.

Capture guidance: browser at 1280 wide, light theme, no personal host names or
addresses visible.

| File name | Where it is used | Screen to capture | What to highlight |
|---|---|---|---|
| `setup-01-welcome.png` | quickstart, step list | Setup wizard, Welcome step | The "What you'll need" checklist |
| `setup-02-connection.png` | quickstart, step 2 | Setup wizard, CA Connection step | A discovered CA and the Test connection button |
| `setup-03-templates.png` | quickstart, step 3 | Setup wizard, Templates step | The selected template and one green readiness check |
| `setup-04-external-url.png` | quickstart, step 4 | Setup wizard, External URL step | The prefilled URL and the one-click TLS certificate button |
| `setup-05-review.png` | quickstart, step 5 | Setup wizard, Review step | The generated certbot command block |
| `dashboard-overview.png` | quickstart, "Confirm it worked" | Dashboard after the first sync | The certificate inventory and the expiry tiles |

Once the images are in place, they also appear in the browser guides on GitHub.
If you want them in the PDF as well, tell me and I will add them to
`docs/generate_guide.py`.
