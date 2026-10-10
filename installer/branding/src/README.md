# Hand drawn marks for the installer icon

Drop either file here and re-run
`python scripts/branding/New-InstallerBranding.py`. Both are optional; without
them the script composites the mascot onto a teal-to-navy squircle at every
size, which is what ships today.

| File | Replaces the generated tile at | Why it exists |
| ---- | ------------------------------ | ------------- |
| `mark-small.png` | 32 px and below | A downscale of the mascot stops reading as a helmeted duck somewhere under 32 px. This is the file that matters. |
| `mark-full.png` | 48 px and above | Only needed if the mascot is redrawn as clean vector shapes. The composited tile is adequate at these sizes. |

Both are square RGBA PNGs, 256 px or larger, transparent outside the tile. The
crossover is `SMALL_MAX` in the script.

Nothing here reaches the web UI, the favicons or the printed guide. Those still
render `src/frontend/src/assets/duck-logo.png` and the `favicon-*.png` set, and
adopting a redrawn mark there is separate work.

## The brief, if you are asking a model to draw one

Attach `src/frontend/public/favicon-512.png` and ask for a Design Artifact. Note
that claude.ai/design is the sync target for the dashboard component library,
not an image generator: it holds the palette and the components, no mascot
vector and no marketing artwork. So this goes in an ordinary chat.

> I need a Windows application icon family for a product called **Ducks in a
> Row**, an ACME to Active Directory Certificate Services certificate lifecycle
> manager. It is a serious Windows Server admin tool with a mascot: a yellow
> rubber duck wearing a knight's helmet with a magenta plume, winking. The
> attached `favicon-512.png` is the existing hand-drawn mascot, and it is the
> character I want kept, not a different duck.
>
> Brand palette, already shipping in the product's dashboard and printed guide:
> teal `#14B8A6` is the accent, `#0F766E` the darker teal that reads on white,
> `#0C1322` the deep navy used for chrome and the guide cover, `#0f172a` ink,
> `#64748b` muted grey. Typeface is Hanken Grotesk, though this icon carries no
> text.
>
> Design a single coherent icon family as a **rounded-square app tile**: a
> squircle in a teal-to-navy treatment with the duck knight inside it, sized so
> the mark reads as one confident shape rather than a photo pasted on a tile.
> Give me two variants:
>
> 1. **Full detail, for 256 px down to 48 px.** The mascot with its helmet,
>    plume and wink intact, redrawn as clean vector shapes rather than traced
>    pencil texture. Keep the warmth and the wink; lose the sketchy edges, which
>    alias badly at small sizes.
> 2. **Simplified, for 32 px and below.** The same character reduced to the
>    fewest shapes that still read as a helmeted duck: strong silhouette, high
>    contrast against the tile, no interior line work thinner than a sixteenth
>    of the canvas. Judge it at 16 px, not at 256.
>
> Deliver both as **SVG on a 256x256 viewBox with no text elements and no
> embedded raster**, plus PNG exports at 256 and 32 with transparent corners
> outside the squircle. Show them side by side at 256, 48, 32 and 16 px so I can
> judge the crossover point between the two variants.

Save the returned PNGs here as `mark-full.png` and `mark-small.png`. There is no
SVG rasteriser on the build box, so the script reads the PNGs; keep the SVG
beside them if you want an editable original.
