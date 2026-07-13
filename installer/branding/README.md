# Installer branding assets

Drop the three files below into this folder, then uncomment the branding block in
[`../Certus.wxs`](../Certus.wxs) (search for "Branding assets"). Until the files
exist and that block is uncommented, the wizard builds and runs with the stock
WiX images, and Add/Remove Programs shows no custom icon.

`build.ps1` already adds this folder as a `wix build -bindpath`, so the file names
below resolve once present.

| File          | Used for                          | Required format                          |
| ------------- | --------------------------------- | ---------------------------------------- |
| `banner.bmp`  | Top banner on the interior pages  | **493 x 58 px**, 24-bit BMP (no alpha)   |
| `dialog.bmp`  | Left image on Welcome / Completion | **493 x 312 px**, 24-bit BMP (no alpha)  |
| `certus.ico`  | Product icon in Add/Remove Programs | `.ico`, include 16/32/48 px sizes        |

Notes:

- BMP must be 24-bit. WiX does not accept PNG or 32-bit (alpha) BMP for these.
- The dialog image's lower-right area is covered by text on the Welcome and
  Completion pages, so keep important artwork to the left and top.
- Source logo for reference: [`../../src/frontend/public/certus.svg`](../../src/frontend/public/certus.svg).
