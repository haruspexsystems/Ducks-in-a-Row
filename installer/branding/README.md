# Installer branding assets

These four files are **generated, not hand edited**. They are built from the
product's own mascot by:

```
python scripts/branding/New-InstallerBranding.py
```

Re-run it after changing the mascot or the marks in [`src/`](src/), and commit
the result. `--check` regenerates into memory and exits 1 if any committed file
differs from a fresh build, so the assets can be proved without writing
anything.

| File | Size | Format | Consumed by |
| ---- | ---- | ------ | ----------- |
| `banner.bmp` | 493 x 58 | 24-bit BMP, no alpha | `WixVariable WixUIBannerBmp` in [`../Certus.wxs`](../Certus.wxs) |
| `dialog.bmp` | 493 x 312 | 24-bit BMP, no alpha | `WixVariable WixUIDialogBmp` in [`../Certus.wxs`](../Certus.wxs) |
| `ducks.ico` | 16, 20, 24, 32, 40, 48, 64, 256 | ICO, 32-bit DIB frames up to 64 px, PNG at 256 | `Icon`/`ARPPRODUCTICON` in [`../Certus.wxs`](../Certus.wxs) **and** `Bundle/@IconSourceFile` in [`../Bundle.wxs`](../Bundle.wxs) |
| `logo.png` | 64 x 64 | PNG, alpha | `bal:WixStandardBootstrapperApplication/@LogoFile` in [`../Bundle.wxs`](../Bundle.wxs) |

`build.ps1` passes this folder as a `wix build -bindpath` on both the MSI and
the bundle, so the WXS files name the assets **bare** (`banner.bmp`, not
`branding/banner.bmp`, which would resolve through that bindpath as
`branding/branding/banner.bmp`).

## The icon is wired twice, deliberately

`ARPPRODUCTICON` covers the bare MSI only. Installed through
`Ducks-in-a-Row-Setup.exe` the MSI carries `ARPSYSTEMCOMPONENT=1` and shows no
Apps and Features row of its own, so `Bundle/@IconSourceFile` is the icon a user
normally sees. It is also the icon Explorer, the download and the UAC prompt put
on the setup executable itself.

## Where the artwork may go

The wizard draws dark Tahoma text straight over `dialog.bmp`, so this is a
layout constraint and not a matter of taste. `WelcomeDlg` is 370 x 270 dialog
units against a 493 x 312 px bitmap, which makes one dialog unit 1.333 px:

- **Title** at X=135 Y=20 W=220 H=60 and **Description** at X=135 Y=80 cover
  **x 180-473, y 27-187**.
- On `ExitDialog`, `WIXUI_EXITDIALOGOPTIONALCHECKBOX` adds **x 180-473,
  y 253-307**.

So the artwork gets a **175 px left column** and everything right of it stays a
flat light field. `dialog.bmp` uses a navy panel with a teal seam on the left
and plain white from x=175. The panel's hard bottom edge at y=312 is the stock
look: `BottomLine` draws on exactly that row and the dialog paints its own white
background below it.

`banner.bmp` is tighter. [`../CertusUi.wxs`](../CertusUi.wxs) puts **Title** at
X=15 W=220 and **Description** at X=25 W=290 of a 370 x 44 dlu control, so text
can span **x 20-420 px** of 493 and only the right 73 px is free. The mascot
sits at 46 px inside that, with a teal rule along the bottom edge.

No asset carries text. The wizard supplies every word, and baking text in would
mean rendering Hanken Grotesk, which ships only as `.woff2`.

## Source artwork

The master is [`../../src/frontend/public/favicon-512.png`](../../src/frontend/public/favicon-512.png),
the duck knight at 512 px. It is the same artwork as
`src/frontend/src/assets/duck-logo.png` at twice the resolution, and the same
mascot the PDF guide puts on its cover.

**`src/frontend/public/certus.svg` is not the source logo.** It is an orphaned
Certus-era blue shield that nothing in the product references; `index.html`
links only the duck favicons.

### Optional hand drawn marks, in `src/`

| File | Replaces the generated tile at |
| ---- | ------------------------------ |
| `src/mark-full.png` | 48 px and above |
| `src/mark-small.png` | 32 px and below |

Both are square RGBA PNGs, 256 px or larger, transparent outside the tile. When
neither is present the script composites the mascot onto a teal-to-navy squircle
at every size, which is what ships today.

`mark-small.png` is the one that matters. A downscale of the mascot stops
reading as a helmeted duck somewhere under 32 px, so the small sizes want a
simplified redraw: strong silhouette, high contrast, no interior line work
thinner than a sixteenth of the canvas. Dropping that file in and re-running the
script is the whole adoption path.
