"""
Generate the Ducks in a Row Installation & Configuration Guide as a PDF.
Uses ReportLab to produce a professional multi-page document.
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable, ListFlowable, ListItem,
    Frame, PageTemplate, BaseDocTemplate, Image
)
from reportlab.platypus.doctemplate import PageTemplate, BaseDocTemplate
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.colors import Color
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase.pdfmetrics import stringWidth
from xml.sax.saxutils import escape
import os
import re
import xml.etree.ElementTree as ET

import guide_markdown as md
import guide_manifest as manifest

# Product version, stamped on the cover and every page footer. It lives in
# guide_manifest so the staleness check can read it without importing
# ReportLab, and it is read from Directory.Build.props rather than written
# here: the literal this replaced claimed the guide "never drifts from the
# release it documents" while sitting two releases behind, on all 26 pages.
VERSION = manifest.read_version()

# Brand colors aligned with the web UI palette
# (src/frontend/src/features/dashboard/lib/colors.ts and tailwind.config.js),
# so the printed guide matches the dashboard.
CERTUS_NAVY = HexColor("#0C1322")         # deep-navy nav chrome (cover, table headers)
CERTUS_BLUE = HexColor("#14B8A6")         # brand accent (teal)
CERTUS_ACCENT_TEXT = HexColor("#0F766E")  # accent text legible on white
CERTUS_LIGHT_BLUE = HexColor("#f0fdfa")   # teal tint for note boxes
CERTUS_GRAY = HexColor("#64748b")         # muted text (slate-500)
CERTUS_LIGHT_GRAY = HexColor("#f1f5f9")   # light row shading (slate-100)
CERTUS_DARK = HexColor("#0f172a")         # primary text / ink (slate-900)
CERTUS_GREEN = HexColor("#10B981")        # success
CERTUS_AMBER = HexColor("#F59E0B")        # warning
CERTUS_RED = HexColor("#DC2626")          # danger
CERTUS_WHITE = HexColor("#ffffff")

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "Ducks-in-a-Row-Installation-Guide.pdf")
LOGO_PATH = os.path.join(
    os.path.dirname(__file__), "..", "src", "frontend", "src", "assets", "duck-logo.png"
)
IMAGES_DIR = os.path.join(os.path.dirname(__file__), "images")
DOCS_DIR = os.path.dirname(os.path.abspath(__file__))


class GuideDocTemplate(BaseDocTemplate):
    """Document template that feeds the table of contents live page numbers.

    Each numbered section heading notifies the TOC of its final page, so the
    contents page stays correct no matter how the content reflows. Requires a
    multi-pass build (see build_document).
    """

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name == "SectionTitle":
            text = flowable.getPlainText()
            # Only the numbered top-level sections, not "Table of Contents".
            if text[:1].isdigit():
                self.notify("TOCEntry", (0, text, self.page))


def build_styles():
    """Create custom paragraph styles for the document."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="CoverTitle",
        fontName="Helvetica-Bold",
        fontSize=36,
        leading=44,
        textColor=CERTUS_WHITE,
        alignment=TA_LEFT,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="CoverSubtitle",
        fontName="Helvetica",
        fontSize=16,
        leading=22,
        textColor=HexColor("#94a3b8"),
        alignment=TA_LEFT,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="CoverVersion",
        fontName="Helvetica",
        fontSize=11,
        leading=16,
        textColor=HexColor("#64748b"),
        alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        name="SectionTitle",
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=28,
        textColor=CERTUS_NAVY,
        spaceBefore=24,
        spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        name="SubSection",
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=20,
        textColor=CERTUS_DARK,
        spaceBefore=16,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="SubSubSection",
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=16,
        textColor=CERTUS_GRAY,
        spaceBefore=12,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="BodyText2",
        fontName="Helvetica",
        fontSize=10,
        leading=15,
        textColor=CERTUS_DARK,
        alignment=TA_LEFT,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="CodeBlock",
        fontName="Courier",
        fontSize=8.5,
        leading=13,
        textColor=HexColor("#e2e8f0"),
        backColor=HexColor("#1e293b"),
        borderPadding=(8, 10, 8, 10),
        spaceAfter=10,
        spaceBefore=4,
    ))
    styles.add(ParagraphStyle(
        name="CodeInline",
        fontName="Courier",
        fontSize=9,
        leading=14,
        textColor=CERTUS_DARK,
        backColor=CERTUS_LIGHT_GRAY,
    ))
    styles.add(ParagraphStyle(
        name="Note",
        fontName="Helvetica",
        fontSize=9,
        leading=14,
        textColor=CERTUS_ACCENT_TEXT,
        backColor=CERTUS_LIGHT_BLUE,
        borderPadding=(8, 10, 8, 10),
        spaceAfter=10,
        spaceBefore=6,
    ))
    styles.add(ParagraphStyle(
        name="Warning",
        fontName="Helvetica",
        fontSize=9,
        leading=14,
        textColor=HexColor("#92400e"),
        backColor=HexColor("#fef3c7"),
        borderPadding=(8, 10, 8, 10),
        spaceAfter=10,
        spaceBefore=6,
    ))
    styles.add(ParagraphStyle(
        name="TableHeader",
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=CERTUS_WHITE,
        alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        name="TableCell",
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=CERTUS_DARK,
        alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        name="TableCellCode",
        fontName="Courier",
        fontSize=8,
        leading=12,
        textColor=CERTUS_DARK,
        alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        name="Footer",
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=CERTUS_GRAY,
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="BulletText",
        fontName="Helvetica",
        fontSize=10,
        leading=15,
        textColor=CERTUS_DARK,
        leftIndent=20,
        bulletIndent=8,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="StepNumber",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=18,
        textColor=CERTUS_BLUE,
        spaceBefore=14,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="Caption",
        fontName="Helvetica-Oblique",
        fontSize=8.5,
        leading=12,
        textColor=CERTUS_GRAY,
        alignment=TA_CENTER,
        spaceBefore=4,
        spaceAfter=12,
    ))
    return styles


def figure(filename, caption, styles, max_width=5.5 * inch, max_height=4.6 * inch):
    """Flowables for a captioned screenshot.

    Returns the image and caption when the screenshot exists in docs/images, or
    an empty list when it does not, so the guide builds cleanly before the
    screenshots are captured. Regenerate the guide after adding the PNG and the
    figure appears in place. The image is scaled to fit within both bounds,
    preserving aspect ratio and never enlarging beyond its natural size, so a
    tall screenshot does not take over a whole page.
    """
    path = os.path.join(IMAGES_DIR, filename)
    if not os.path.exists(path):
        return []
    iw, ih = ImageReader(path).getSize()
    scale = min(max_width / iw, max_height / ih, 1.0)
    img = Image(path, width=iw * scale, height=ih * scale)
    img.hAlign = "CENTER"
    block = KeepTogether([img, Paragraph(caption, styles["Caption"])])
    return [Spacer(1, 10), block]


def add_header_footer(canvas_obj, doc):
    """Draw header line and footer on each page (not the cover)."""
    if doc.page > 1:
        canvas_obj.saveState()
        # Header line
        canvas_obj.setStrokeColor(CERTUS_BLUE)
        canvas_obj.setLineWidth(1.5)
        canvas_obj.line(
            doc.leftMargin, letter[1] - 45,
            letter[0] - doc.rightMargin, letter[1] - 45
        )
        # Header text
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.setFillColor(CERTUS_GRAY)
        canvas_obj.drawString(doc.leftMargin, letter[1] - 40,
                              "Ducks in a Row")
        canvas_obj.drawRightString(letter[0] - doc.rightMargin, letter[1] - 40,
                                   "Installation & Configuration Guide")
        # Footer
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.setFillColor(CERTUS_GRAY)
        canvas_obj.drawCentredString(
            letter[0] / 2, 30,
            f"Page {doc.page}"
        )
        canvas_obj.drawString(doc.leftMargin, 30, f"Ducks in a Row {VERSION}")
        canvas_obj.drawRightString(letter[0] - doc.rightMargin, 30,
                                   "github.com/haruspexsystems/Ducks-in-a-Row")
        canvas_obj.restoreState()


def make_cover(styles):
    """Build the cover page elements."""
    elements = []
    elements.append(Spacer(1, 1.4 * inch))
    if os.path.exists(LOGO_PATH):
        logo = Image(LOGO_PATH, width=1.1 * inch, height=1.1 * inch)
        logo.hAlign = "LEFT"
        elements.append(logo)
        elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph("Ducks in a Row", styles["CoverTitle"]))
    elements.append(Paragraph(
        "Certificate Lifecycle Automation &amp; Management for ADCS",
        styles["CoverSubtitle"]))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph(
        "Installation &amp; Configuration Guide",
        ParagraphStyle(
            "CoverGuideTitle",
            parent=styles["CoverSubtitle"],
            fontSize=20,
            leading=26,
            textColor=CERTUS_WHITE,
            fontName="Helvetica-Bold",
        )
    ))
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(Paragraph(
        "Make ADCS work like Let's Encrypt for your internal network.",
        ParagraphStyle(
            "CoverTagline",
            parent=styles["CoverSubtitle"],
            fontSize=13,
            leading=18,
            textColor=HexColor("#cbd5e1"),
            fontName="Helvetica-Oblique",
        )
    ))
    elements.append(Spacer(1, 1.5 * inch))
    elements.append(Paragraph(f"Version {VERSION}", styles["CoverVersion"]))
    elements.append(Paragraph("2026", styles["CoverVersion"]))
    elements.append(PageBreak())
    return elements


def make_cover_bg(canvas_obj, doc):
    """Draw the dark cover background."""
    if doc.page == 1:
        canvas_obj.saveState()
        canvas_obj.setFillColor(CERTUS_NAVY)
        canvas_obj.rect(0, 0, letter[0], letter[1], fill=1)
        # Accent bar
        canvas_obj.setFillColor(CERTUS_BLUE)
        canvas_obj.rect(0, letter[1] - 8, letter[0], 8, fill=1)
        # Bottom line
        canvas_obj.setStrokeColor(HexColor("#334155"))
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(60, 180, letter[0] - 60, 180)
        canvas_obj.restoreState()
    add_header_footer(canvas_obj, doc)


def code(text):
    """Wrap text in inline code styling."""
    return f'<font face="Courier" size="9" color="#1e293b">{text}</font>'


def bold(text):
    return f"<b>{text}</b>"


def code_block(text, styles):
    """Render a multi-line code block, preserving line breaks and indentation.

    A plain ReportLab Paragraph collapses newlines and runs of spaces into a
    single space, which would put every command and comment on one line and
    strip JSON indentation. We escape the XML special characters, keep the
    leading indentation with non-breaking spaces, and join the lines with
    explicit <br/> breaks. Long lines still wrap inside the box.
    """
    lines = []
    for line in text.split("\n"):
        esc = escape(line)
        stripped = esc.lstrip(" ")
        indent = "&#160;" * (len(esc) - len(stripped))
        lines.append(indent + stripped)
    cb_style = styles["CodeBlock"]
    return Paragraph("<br/>".join(lines), cb_style)


# Cell paragraph styles for make_table. Wrapping cell text in a Paragraph is
# what lets ReportLab word wrap it; a raw string cell is drawn on one line and
# overflows the column.
_TABLE_HEADER_STYLE = ParagraphStyle(
    "TableHeaderCell", fontName="Helvetica-Bold", fontSize=9, leading=13,
    textColor=CERTUS_WHITE, alignment=TA_LEFT,
)
_TABLE_CELL_STYLE = ParagraphStyle(
    "TableBodyCell", fontName="Helvetica", fontSize=9, leading=13,
    textColor=CERTUS_DARK, alignment=TA_LEFT,
)


def make_table(headers, rows, col_widths=None):
    """Create a styled table."""
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), CERTUS_NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), CERTUS_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
        ("LEADING", (0, 0), (-1, -1), 13),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
    ]
    # Alternate row shading
    for i in range(1, len(rows) + 1):
        if i % 2 == 0:
            style_commands.append(
                ("BACKGROUND", (0, i), (-1, i), CERTUS_LIGHT_GRAY)
            )

    # Wrap plain string cells in Paragraphs so long text wraps inside the
    # column instead of overflowing the page. Cells that are already flowables
    # (for example inline code built with code()) are left untouched.
    header_cells = [
        c if not isinstance(c, str) else Paragraph(c, _TABLE_HEADER_STYLE)
        for c in headers
    ]
    body_rows = [
        [c if not isinstance(c, str) else Paragraph(c, _TABLE_CELL_STYLE) for c in row]
        for row in rows
    ]
    data = [header_cells] + body_rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle(style_commands))
    return t


# --------------------------------------------------------------------------
# Markdown to flowables
#
# The guide is built from the markdown in this folder so the two cannot say
# different things. guide_markdown.py owns the grammar; everything below owns
# how a block looks on the page.
# --------------------------------------------------------------------------

# The generated PDF. A link to it from inside itself is meaningless, so those
# degrade to plain text rather than pointing a reader at the file they are
# already reading.
SELF_REFERENCE = "Ducks-in-a-Row-Installation-Guide.pdf"

# Where a link to a repo file that is not a guide chapter should send a reader.
REPO_BLOB_URL = "https://github.com/haruspexsystems/Ducks-in-a-Row/blob/main/"

# The built in Type1 fonts this document uses are WinAnsi encoded, so a
# character outside cp1252 is drawn as a black box. Failing the build instead
# means a stray arrow or emoji is caught here rather than in print.
ENCODING = "cp1252"


# The manifest lives in guide_manifest so the staleness check can read the
# chapter list without the rendering toolchain installed.
Chapter = manifest.Chapter
CHAPTERS = manifest.CHAPTERS


def _check_encoding(text, source, what):
    """Refuse a character the guide's fonts cannot draw."""
    try:
        text.encode(ENCODING)
    except UnicodeEncodeError as exc:
        bad = text[exc.start:exc.end]
        raise SystemExit(
            "%s: %s contains %r (U+%04X), which the guide's WinAnsi fonts "
            "cannot draw. Replace it in the markdown."
            % (source, what, bad, ord(bad[0]))
        )


def _destination(filename, anchor):
    """A PDF destination name unique to one heading in one chapter.

    Heading slugs collide across chapters. Five do today, and one of them is
    reachable: acme-clients.md has a section "External account binding" and
    there is also a chapter of that name, so both would emit the same
    destination and the link meaning "the section below" could land on the other
    chapter instead. Qualifying by file makes the name unique by construction
    rather than by nobody happening to reuse a heading.
    """
    stem = filename[:-3] if filename.endswith(".md") else filename
    return "%s--%s" % (md.slug(stem), anchor)


def build_anchor_index(chapters, docs_dir):
    """Map (file, anchor) to the destination the renderer will emit.

    Built in a pre-pass so a link written for the web docs, such as one to
    another chapter's section, resolves inside the PDF too. Keyed on the file as
    well as the anchor so a bare "#section" resolves within the document that
    wrote it, which is what it means on the web.
    """
    index = {}
    for chapter in chapters:
        title_anchor = md.slug(chapter.title)
        # The chapter itself, for a link that names the file with no anchor.
        index[(chapter.filename, None)] = _destination(
            chapter.filename, title_anchor
        )
        for block in md.parse_file(os.path.join(docs_dir, chapter.filename)):
            if block["kind"] != md.HEADING:
                continue
            if block["level"] == 1:
                # The renderer titles the chapter from the manifest, so register
                # the file's own h1 slug against the same destination; a link
                # written against either name resolves.
                index[(chapter.filename, md.slug(block["text"]))] = index[
                    (chapter.filename, None)
                ]
                continue
            anchor = md.slug(block["text"])
            index[(chapter.filename, anchor)] = _destination(
                chapter.filename, anchor
            )
    return index


def _resolve_link(href, source, anchors):
    """Return the ReportLab href for a markdown link target, or None for plain.

    Four classes, and they behave differently: an external URL passes through,
    a link to another chapter or to an anchor becomes an internal jump, a link
    to a repo file that is not a chapter goes to the public repo, and a link to
    this very PDF stops being a link at all.
    """
    if href.startswith(("http://", "https://", "mailto:")):
        return href

    if SELF_REFERENCE in href:
        return None

    if href.startswith("#"):
        # Within the document that wrote it, as on the web.
        target = anchors.get((source, href[1:]))
        if target is None:
            raise SystemExit(
                "%s: link to %s does not match any heading in that file"
                % (source, href)
            )
        return "#" + target

    filename, _, anchor = href.partition("#")

    if anchor:
        target = anchors.get((filename, anchor))
        if target is not None:
            return "#" + target
        # A section of a file the guide does not carry: send the reader to the
        # repo rather than dropping the link.
        return REPO_BLOB_URL + "docs/" + href

    if (filename, None) in anchors:
        return "#" + anchors[(filename, None)]

    if filename.startswith("../"):
        return REPO_BLOB_URL + filename[3:]

    return REPO_BLOB_URL + "docs/" + filename


def inline_markup(runs, source, anchors):
    """Turn parsed inline runs into the mini HTML a Paragraph understands."""
    out = []
    for run in runs:
        kind = run[0]
        if kind == md.TEXT:
            out.append(escape(run[1]))
        elif kind == md.CODE_SPAN:
            out.append(code(escape(run[1])))
        elif kind == md.BOLD:
            out.append(bold(inline_markup(run[1], source, anchors)))
        elif kind == md.ITALIC:
            out.append("<i>%s</i>" % inline_markup(run[1], source, anchors))
        elif kind == md.LINK:
            inner = inline_markup(run[1], source, anchors)
            href = _resolve_link(run[2], source, anchors)
            if href is None:
                out.append(inner)
            else:
                out.append(
                    '<link href="%s" color="#0F766E">%s</link>'
                    % (escape(href), inner)
                )
        else:
            raise SystemExit("%s: unknown inline run %r" % (source, kind))
    return "".join(out)


def _plain_cell(cell):
    """The visible text of a table cell, with the markdown markup removed."""
    return "".join(md._plain(run) for run in md.parse_inline(cell))


def _measure(text, font="Helvetica"):
    """Width of a string in points, in the font the cell actually uses.

    make_table sets header cells in Helvetica-Bold and body cells in Helvetica,
    both at 9pt, and inline code renders in Courier. Measuring a bold header
    with the regular face under-reads it, which is what broke "Outbound" across
    two lines on the challenge table.
    """
    return stringWidth(text, font, 9)


def _cell_font(raw):
    """Courier if the cell is inline code, because Courier is the wider face."""
    return "Courier" if "`" in raw else "Helvetica"


def _fair_share(minimum, total):
    """Max min fair division of a width that cannot satisfy every column."""
    settled = [None] * len(minimum)
    pending = list(range(len(minimum)))
    remaining = float(total)

    while pending:
        share = remaining / len(pending)
        modest = [i for i in pending if minimum[i] <= share]
        if not modest:
            # Everything left is greedy, so they split what is left evenly.
            for i in pending:
                settled[i] = share
            break
        for i in modest:
            settled[i] = minimum[i]
            remaining -= minimum[i]
            pending.remove(i)

    return settled


def auto_col_widths(headers, rows, total=6.5 * inch):
    """Pick column widths, because markdown carries none.

    Two measurements per column. The natural width is how wide the longest cell
    would like to be, and it decides how the spare width is shared. The minimum
    width is the longest single token, and it is a floor: a column narrower than
    its longest word does not wrap, it breaks the word. That is what turned
    "cert-manager" into "cert-ma nager" and "HTTP-01" into "HTTP-0 1" in the
    first draft of this.

    Every column starts at its floor and the remainder is shared in proportion
    to what each column still wants. Allocating proportionally first and
    repairing afterwards does not work: the repair has to be renormalised to fit
    the table width, and the renormalisation is what undoes the repair.

    CHAPTERS carries a per table override for anything this still reads wrong.
    """
    columns = len(headers)
    # make_table sets LEFTPADDING and RIGHTPADDING to 8 each, plus 2pt of slack
    # so a column that measures exactly wide enough is not tipped over by
    # rounding. Under-counting this is the difference between a column that
    # wraps and one that breaks a word in half: at exactly 16.0 the widest
    # client name landed on the boundary and rendered as "cert-ma nager".
    padding = 18.0

    natural = []
    minimum = []
    for i in range(columns):
        header = headers[i]
        body = [row[i] for row in rows]

        widths = [_measure(_plain_cell(header), "Helvetica-Bold")]
        widths += [_measure(_plain_cell(c), _cell_font(c)) for c in body]
        natural.append(max(widths) + padding)

        tokens = [(t, "Helvetica-Bold") for t in _plain_cell(header).split()]
        for cell in body:
            tokens += [(t, _cell_font(cell)) for t in _plain_cell(cell).split()]
        longest_token = max((_measure(t, f) for t, f in tokens), default=0.0)
        # A column never needs more room than it would use on a single line.
        minimum.append(min(longest_token + padding, natural[-1]))

    floor_total = sum(minimum)
    if floor_total >= total:
        # More unbreakable text than the page is wide, so something has to
        # break. Sharing in proportion is the wrong way to choose: it shaves
        # every column equally, so a modest column loses the few points that
        # kept its longest word whole while a greedy one keeps most of its
        # surplus. Breaking a 35 character identifier is expected; breaking
        # "cert-manager" reads as a bug.
        #
        # Max min fairness picks the other way round. Each column takes an
        # equal share of what is left, anything that fits inside its share is
        # settled at exactly what it needs, and the rest divide the remainder
        # again. Small columns come out whole and the long identifiers absorb
        # the shortfall.
        return _fair_share(minimum, total)

    spare = total - floor_total
    want = [natural[i] - minimum[i] for i in range(columns)]
    want_total = sum(want)
    if want_total <= 0.01:
        return [w + spare / columns for w in minimum]
    return [minimum[i] + spare * want[i] / want_total for i in range(columns)]


def indented_code_block(text, styles, indent):
    """A code block that sits inside a list item keeps the item's indent."""
    if not indent:
        return code_block(text, styles)
    style = ParagraphStyle(
        "CodeBlockIndent%d" % indent,
        parent=styles["CodeBlock"],
        leftIndent=styles["CodeBlock"].leftIndent + 14,
    )
    shim = {"CodeBlock": style}
    return code_block(text, shim)


def bullet_paragraph(markup, styles, depth, marker):
    """One list item. Ordered items carry their own number as the bullet."""
    style = styles["BulletText"]
    if depth:
        style = ParagraphStyle(
            "BulletTextNested%d" % depth,
            parent=style,
            leftIndent=style.leftIndent + 18 * depth,
            bulletIndent=style.bulletIndent + 18 * depth,
        )
    glyph = "%s." % marker if marker else "&bull;"
    return Paragraph("<bullet>%s</bullet>%s" % (glyph, markup), style)


def render_chapter(chapter, number, styles, anchors, docs_dir):
    """Render one markdown file as the flowables of one numbered chapter."""
    path = os.path.join(docs_dir, chapter.filename)
    blocks = md.parse_file(path)
    source = chapter.filename

    story = []
    seen_h1 = False
    table_ordinal = 0

    for block in blocks:
        kind = block["kind"]

        if kind == md.HEADING:
            _check_encoding(block["text"], source, "a heading")
            markup = inline_markup(
                md.parse_inline(block["text"]), source, anchors
            )
            if block["level"] == 1:
                # The manifest title wins over the file's own h1, so the guide
                # can read "Quick Start" where the web page reads "Quickstart".
                seen_h1 = True
                story.append(
                    Paragraph(
                        '<a name="%s"/>%d. %s'
                        % (
                            _destination(source, md.slug(chapter.title)),
                            number,
                            escape(chapter.title),
                        ),
                        styles["SectionTitle"],
                    )
                )
                continue

            anchor = md.slug(block["text"])
            # A numbered h2 keeps the teal step treatment the guide already
            # used for walkthrough steps.
            style = (
                styles["StepNumber"]
                if block["level"] == 2 and re.match(r"^\d+\.\s", block["text"])
                else styles["SubSection" if block["level"] == 2 else "SubSubSection"]
            )
            story.append(
                Paragraph(
                    '<a name="%s"/>%s' % (_destination(source, anchor), markup),
                    style,
                )
            )
            continue

        if kind == md.PARA:
            _check_encoding(block["text"], source, "a paragraph")
            story.append(
                Paragraph(
                    inline_markup(md.parse_inline(block["text"]), source, anchors),
                    styles["BodyText2"],
                )
            )
            continue

        if kind == md.QUOTE:
            _check_encoding(block["text"], source, "a callout")
            story.append(
                Paragraph(
                    inline_markup(md.parse_inline(block["text"]), source, anchors),
                    styles["Warning" if block["severity"] == "warning" else "Note"],
                )
            )
            continue

        if kind == md.CODE:
            _check_encoding(block["text"], source, "a code block")
            story.append(
                indented_code_block(block["text"], styles, block["indent"])
            )
            continue

        if kind == md.BULLET:
            _check_encoding(block["text"], source, "a list item")
            story.append(
                bullet_paragraph(
                    inline_markup(md.parse_inline(block["text"]), source, anchors),
                    styles,
                    block["depth"],
                    block["marker"],
                )
            )
            continue

        if kind == md.TABLE:
            table_ordinal += 1
            headers = block["headers"]
            rows = block["rows"]
            for cell in headers + [c for row in rows for c in row]:
                _check_encoding(cell, source, "a table cell")
            widths = chapter.col_widths.get(
                table_ordinal, auto_col_widths(headers, rows)
            )
            story.append(Spacer(1, 6))
            story.append(
                make_table(
                    [inline_markup(md.parse_inline(h), source, anchors)
                     for h in headers],
                    [[inline_markup(md.parse_inline(c), source, anchors)
                      for c in row] for row in rows],
                    widths,
                )
            )
            story.append(Spacer(1, 10))
            continue

        if kind == md.IMAGE:
            _check_encoding(block["alt"], source, "an image caption")
            name = block["src"].rsplit("/", 1)[-1]
            story.extend(figure(name, block["alt"], styles))
            continue

        raise SystemExit("%s: unknown block %r" % (source, kind))

    if not seen_h1:
        raise SystemExit(
            "%s: no top level heading, so the chapter has no title" % source
        )
    return story


def build_document():
    """Build the complete PDF document."""
    styles = build_styles()

    doc = GuideDocTemplate(
        OUTPUT_PATH,
        pagesize=letter,
        leftMargin=60,
        rightMargin=60,
        topMargin=60,
        bottomMargin=55,
        title="Ducks in a Row Installation & Configuration Guide",
        author="DucksInARow",
        subject="ACME-to-ADCS Certificate Proxy",
        # Fixes the creation timestamp and document id, so regenerating
        # unchanged sources produces byte identical output. That is what
        # lets CI diff the committed PDF and fail when it has drifted from
        # the markdown it is built from.
        invariant=1,
    )

    frame = Frame(
        doc.leftMargin, doc.bottomMargin,
        doc.width, doc.height,
        id="normal"
    )
    doc.addPageTemplates([
        PageTemplate(id="all", frames=frame, onPage=make_cover_bg)
    ])

    story = []

    # === COVER ===
    story.extend(make_cover(styles))

    # === TABLE OF CONTENTS ===
    # Entries and page numbers are filled in on the build passes from the
    # section headings (see GuideDocTemplate.afterFlowable), so they always
    # match the real pagination.
    story.append(Paragraph("Table of Contents", styles["SectionTitle"]))
    story.append(Spacer(1, 6))
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(
            "TOCEntry",
            parent=styles["BodyText2"],
            fontSize=11,
            leading=20,
            leftIndent=10,
            firstLineIndent=-10,
        ),
    ]
    story.append(toc)
    story.append(PageBreak())

    # === CHAPTERS ===
    # Every chapter is rendered from its markdown file in this folder, so the
    # guide and the web docs cannot disagree about what the product does. The
    # chapter number comes from the position in CHAPTERS and is never written
    # down, so reordering the guide cannot strand a stale number.
    anchors = build_anchor_index(CHAPTERS, DOCS_DIR)
    for number, chapter in enumerate(CHAPTERS, 1):
        story.extend(render_chapter(chapter, number, styles, anchors, DOCS_DIR))
        story.append(PageBreak())

    # The colophon shares the last chapter's page, as it did when the prose
    # lived here, so drop the break the loop just added.
    if story and isinstance(story[-1], PageBreak):
        story.pop()

    story.append(Spacer(1, 1.0 * inch))
    # Final footer
    story.append(HRFlowable(width="100%", thickness=1, color=CERTUS_BLUE))
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        f'{bold("Ducks in a Row")} | Source available ACME-to-ADCS Proxy<br/>'
        f'github.com/haruspexsystems/Ducks-in-a-Row | Business Source License 1.1',
        ParagraphStyle(
            "FinalFooter",
            parent=styles["BodyText2"],
            fontSize=9,
            alignment=TA_CENTER,
            textColor=CERTUS_GRAY,
        )
    ))

    # Build the PDF. multiBuild runs the extra passes the table of contents
    # needs to resolve its page numbers.
    doc.multiBuild(story)

    # Record the digest of everything the guide was rendered from, so CI can
    # tell a stale PDF from a current one without rebuilding it. Comparing
    # the PDF bytes instead would be a stronger claim than the toolchain
    # supports: ReportLab's output differs between its own versions and
    # between Python versions, so a guide regenerated on another machine is
    # byte different while being word for word identical.
    manifest.write_digest()
    print(f"PDF generated: {OUTPUT_PATH}")
    print(f"Inputs digest: {manifest.read_digest()}")


if __name__ == "__main__":
    build_document()
