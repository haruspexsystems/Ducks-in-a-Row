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
from xml.sax.saxutils import escape
import os

# Product version, stamped on the cover and footer. Kept in one place so the
# guide never drifts from the release it documents.
VERSION = "0.9.0-beta.1"

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

    # === 1. QUICK START ===
    story.append(Paragraph("1. Quick Start", styles["SectionTitle"]))
    story.append(Paragraph(
        "Get Ducks in a Row from a fresh download to a working ACME proxy. Plan for about "
        "fifteen minutes the first time, most of it spent on Active Directory permissions.",
        styles["BodyText2"]
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Step 1: Install Prerequisites", styles["StepNumber"]))
    story.append(Paragraph(
        f"If you install with {bold('Ducks-in-a-Row-Setup.exe')} (recommended), the "
        f"ASP.NET Core 8.0 runtime is installed for you, offline, from the installer "
        f"itself. If you install the bare MSI instead, first download and install the "
        f"{bold('ASP.NET Core 8.0 Hosting Bundle')} from the official .NET download "
        f"page. Either way, install the ADCS management tools and reboot the server "
        f"if prompted.",
        styles["BodyText2"]
    ))
    story.append(code_block(
        "# Bare MSI only: download and install the .NET 8 Hosting Bundle from:\n"
        "# https://dotnet.microsoft.com/download/dotnet/8.0\n\n"
        "# Then install ADCS Remote Administration Tools (elevated PowerShell):\n"
        "Install-WindowsFeature RSAT-ADCS-Mgmt", styles))
    story.append(Paragraph(
        f'{bold("Critical:")} The ADCS RSAT tools must be installed on the Ducks in a Row server '
        f'even though it is not the CA server. Ducks in a Row communicates with ADCS through the '
        f'ADCS COM classes, which are registered by the RSAT feature. Without them, CA '
        f'connectivity fails with COM activation errors.',
        styles["Warning"]
    ))

    story.append(Paragraph("Step 2: Run the Installer", styles["StepNumber"]))
    story.append(Paragraph(
        "Run Ducks-in-a-Row-Setup.exe. It installs the ASP.NET Core runtime when the "
        "server does not have it, then opens the install wizard. On a server that "
        "already has the runtime, the bare MSI also works, either directly or from "
        "an elevated command prompt:",
        styles["BodyText2"]
    ))
    story.append(code_block("msiexec /i Ducks-in-a-Row.msi", styles))
    story.append(Paragraph(
        "The install wizard asks for the destination folder, the data folder (database, logs, "
        "and runtime configuration), and whether to start the service immediately.",
        styles["BodyText2"]
    ))

    story.append(Paragraph("Step 3: Run the Setup Wizard", styles["StepNumber"]))
    story.append(Paragraph(
        "Open the setup page (the completion screen offers to open it for you) and sign in "
        "as a member of the administrator group. The wizard discovers the CAs published in "
        "Active Directory, tests the connection to the CA you pick, lists its templates and "
        "lets you choose one, validates the external URL, then applies the configuration "
        "and restarts the service by itself.",
        styles["BodyText2"]
    ))
    for fn, cap in [
        ("setup-01-welcome.png", "Welcome step: what you need before you start."),
        ("setup-02-connection.png", "Connection step: pick a discovered CA and test it."),
        ("setup-03-templates.png", "Templates step: choose a template and check ACME readiness."),
        ("setup-04-external-url.png",
         "External URL step: confirm the URL and, optionally, enrol an HTTPS certificate."),
        ("setup-05-review.png", "Review step: apply the configuration and copy the certbot command."),
    ]:
        story.extend(figure(fn, cap, styles))

    story.append(Paragraph("Step 4: Verify", styles["StepNumber"]))
    story.append(Paragraph(
        "Open a browser and navigate to the following URLs:",
        styles["BodyText2"]
    ))
    story.append(code_block(
        "https://your-server:5001/health    (should return Healthy)\n"
        "https://your-server:5001/setup     (setup wizard)\n"
        "https://your-server:5001           (dashboard)", styles))
    story.append(Paragraph(
        "The HTTPS endpoint uses a self signed certificate out of the box, so your browser "
        "warns on first visit. Plain HTTP on port 5000 is available for lab use.",
        styles["BodyText2"]
    ))

    story.append(Paragraph(
        f"{bold('Note:')} Until the setup wizard completes, the service runs unconfigured: the "
        f"wizard and dashboard are reachable, and CA operations answer 503.",
        styles["Note"]
    ))

    # === 2. SYSTEM REQUIREMENTS ===
    story.append(Paragraph("2. System Requirements", styles["SectionTitle"]))

    story.append(Paragraph("Server Requirements", styles["SubSection"]))
    req_table = make_table(
        ["Requirement", "Details"],
        [
            ["Operating System", "Windows Server 2016 or later (2019, 2022, 2025)"],
            ["Runtime", "ASP.NET Core 8.0 (installed automatically by Ducks-in-a-Row-Setup.exe; "
                        "install the Hosting Bundle manually only for the bare MSI)"],
            ["Windows Feature", "RSAT-ADCS-Mgmt (ADCS Remote Administration Tools)"],
            ["Processor", "2 x64 cores minimum. The work is mostly I/O bound (COM and RPC "
                          "calls to the CA, plus SQLite), with short bursts of certificate crypto"],
            ["Memory", "1 GB minimum, 2 GB recommended"],
            ["Disk", "About 500 MB for the application and the .NET runtime. Plan at least 5 GB "
                     "free for database growth, logs and upgrades. At roughly 1000 ACME accounts "
                     "renewing over 3 years the database reaches the low hundreds of MB; log "
                     "files are capped at 30 daily files"],
            ["Network", "TCP 5000 (HTTP) and TCP 5001 (HTTPS), both configurable"],
            ["Domain", "Must be domain-joined for ADCS connectivity"],
        ],
        col_widths=[1.8 * inch, 4.7 * inch]
    )
    story.append(req_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Installing Prerequisites", styles["SubSection"]))
    story.append(Paragraph(
        "Run the following commands in an elevated PowerShell session on the Ducks in a Row "
        "server before installing:",
        styles["BodyText2"]
    ))
    story.append(code_block(
        "# Install ADCS Remote Administration Tools\n"
        "Install-WindowsFeature RSAT-ADCS-Mgmt\n\n"
        "# Verify the feature is installed\n"
        "Get-WindowsFeature RSAT-ADCS-Mgmt\n\n"
        "# Verify the .NET 8 runtime is installed (after the setup bundle or\n"
        "# a manual Hosting Bundle install)\n"
        "dotnet --list-runtimes", styles))
    story.append(Paragraph(
        f'{bold("Why RSAT-ADCS-Mgmt is required:")} Ducks in a Row communicates with the ADCS '
        f'Certification Authority through the ADCS COM classes, which are registered on the '
        f'system by the ADCS Remote Server Administration Tools. Without this feature '
        f'installed, the COM objects cannot be instantiated and the service fails with '
        f'{code("DISP_E_MEMBERNOTFOUND")} (0x80020003) errors during certificate sync and '
        f'CA queries.',
        styles["Note"]
    ))
    story.append(Spacer(1, 8))

    story.append(Paragraph("ADCS Requirements", styles["SubSection"]))
    story.append(Paragraph(
        "To issue certificates through ADCS, the following must be in place:",
        styles["BodyText2"]
    ))
    adcs_bullets = [
        "An Active Directory Certificate Services (ADCS) Certification Authority (Enterprise CA)",
        "ADCS Remote Administration Tools (RSAT-ADCS-Mgmt) installed on the Ducks in a Row server",
        "DCOM/RPC network access from the Ducks in a Row server to the CA server (TCP 135 + dynamic ports 49152-65535)",
        "The server's machine account must have Enroll permission on the target certificate templates",
        "The server's machine account must have Read permission on the CA itself, or the dashboard inventory stays empty",
        "Certificate templates must be published to Active Directory",
    ]
    for item in adcs_bullets:
        story.append(Paragraph(
            f"<bullet>&bull;</bullet>{item}",
            styles["BulletText"]
        ))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Network Ports", styles["SubSection"]))
    story.append(Paragraph(
        "The following network ports must be open between the Ducks in a Row server and other systems:",
        styles["BodyText2"]
    ))
    ports_table = make_table(
        ["Direction", "Port", "Protocol", "Purpose"],
        [
            ["Inbound to the server", "5000, 5001", "TCP", "ACME clients and dashboard browsers (HTTP and HTTPS)"],
            ["Outbound to CA", "135", "TCP", "DCOM/RPC endpoint mapper"],
            ["Outbound to CA", "49152-65535", "TCP", "DCOM/RPC dynamic ports"],
            ["Outbound to targets", "80", "TCP", "HTTP-01 challenge validation"],
            ["Outbound to DNS", "53", "TCP/UDP", "DNS-01 challenge validation"],
            ["Outbound to targets", "443", "TCP", "TLS-ALPN-01 challenge validation"],
        ],
        col_widths=[1.5 * inch, 1.2 * inch, 0.9 * inch, 2.9 * inch]
    )
    story.append(ports_table)

    story.append(PageBreak())

    # === 3. INSTALLATION ===
    story.append(Paragraph("3. Installation", styles["SectionTitle"]))

    story.append(Paragraph("What the Installer Does", styles["SubSection"]))
    story.append(Paragraph(
        "The Ducks in a Row MSI installer performs the following actions automatically:",
        styles["BodyText2"]
    ))

    install_table = make_table(
        ["Action", "Details"],
        [
            ["Install application files", "C:\\Program Files\\Ducks in a Row\\ (or the folder you choose)"],
            ["Create the data folder", "C:\\ProgramData\\Ducks in a Row\\ (or the folder you choose; recorded in the registry)"],
            ["Create logs directory", "logs\\ inside the data folder"],
            ["Register Windows Service", "DucksInARow (auto-start, runs as LocalSystem)"],
            ["Start the service", "Service starts immediately after install (optional)"],
            ["Create firewall rules", "Inbound TCP 5000 and 5001 (Ducks in a Row Certificate Proxy)"],
            ["Add a Start Menu shortcut", "Ducks in a Row shortcut that opens the web UI"],
        ],
        col_widths=[2.0 * inch, 4.5 * inch]
    )
    story.append(install_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Silent Installation", styles["SubSection"]))
    story.append(Paragraph(
        "For automated deployments, use a silent install with logging. INSTALLFOLDER, "
        "DATAFOLDER, and START_SERVICE are optional properties:",
        styles["BodyText2"]
    ))
    story.append(code_block(
        'msiexec /i Ducks-in-a-Row.msi /qn INSTALLFOLDER="D:\\Ducks in a Row" '
        'DATAFOLDER="D:\\DucksData" START_SERVICE=0 /l*v "C:\\temp\\ducks-install.log"', styles))
    story.append(Paragraph(
        f'{code("INSTALLFOLDER")} and {code("DATAFOLDER")} default to the Program Files and '
        f'ProgramData folders shown above. Choose the data folder at install time; moving it '
        f'on a later upgrade is not supported. {code("START_SERVICE=0")} registers the service '
        f'but leaves it stopped. A {code("/qn")} install never launches a browser.',
        styles["BodyText2"]
    ))

    story.append(Paragraph("Service Recovery", styles["SubSection"]))
    story.append(Paragraph(
        "The Ducks in a Row service is configured to restart automatically on failure. "
        "The recovery policy uses escalating delays:",
        styles["BodyText2"]
    ))
    recovery_table = make_table(
        ["Failure", "Action", "Delay"],
        [
            ["First failure", "Restart the service", "5 seconds"],
            ["Second failure", "Restart the service", "10 seconds"],
            ["Subsequent failures", "Restart the service", "30 seconds"],
        ],
        col_widths=[2.0 * inch, 2.5 * inch, 2.0 * inch]
    )
    story.append(recovery_table)

    story.append(PageBreak())

    # === 4. CONFIGURATION ===
    story.append(Paragraph("4. Configuration", styles["SectionTitle"]))

    story.append(Paragraph(
        f'Configuration is layered. Shipped defaults live in {code("appsettings.json")} in the '
        f'installation folder. The setup wizard writes instance settings (the CA connection '
        f'string and external URL) to {code("settings.json")} in the data folder, which '
        f'overrides the defaults and survives upgrades. Environment variables override both. '
        f'After editing either file, restart the service for changes to take effect.',
        styles["BodyText2"]
    ))

    story.append(Paragraph("Core Settings", styles["SubSection"]))
    core_table = make_table(
        ["Setting", "Default", "Description"],
        [
            [Paragraph(code("CaConnectionString"), styles["TableCell"]),
             "null", "ADCS CA connection string in hostname\\CAName format; the setup wizard sets it"],
            [Paragraph(code("DatabasePath"), styles["TableCell"]),
             "ducks.db in the data folder", "Full path to the SQLite database file"],
            [Paragraph(code("ExternalUrl"), styles["TableCell"]),
             "null", "Public URL that ACME clients use to reach the server; the setup wizard sets it"],
            [Paragraph(code("SyncIntervalMinutes"), styles["TableCell"]),
             "5", "How often to sync certificates from the ADCS CA database"],
            [Paragraph(code("EnableWalMode"), styles["TableCell"]),
             "true", "Enable SQLite WAL mode for better concurrent performance"],
        ],
        col_widths=[1.8 * inch, 0.8 * inch, 3.9 * inch]
    )
    story.append(core_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Authentication Settings", styles["SubSection"]))
    story.append(Paragraph(
        "The dashboard and setup API use Windows Integrated Authentication and are limited "
        "to the administrator group.",
        styles["BodyText2"]
    ))
    auth_table = make_table(
        ["Setting", "Default", "Description"],
        [
            [Paragraph(code("Auth:Mode"), styles["TableCell"]),
             "Negotiate", "Windows Integrated Authentication for the dashboard"],
            [Paragraph(code("Auth:AdminGroup"), styles["TableCell"]),
             "null", "Group allowed into the dashboard and setup; null means the built in Administrators group"],
            [Paragraph(code("Auth:RequireHttps"), styles["TableCell"]),
             "true", "HSTS and HTTP to HTTPS redirect outside development"],
            [Paragraph(code("Auth:TrustedProxies"), styles["TableCell"]),
             "[]", "Reverse proxy IPs whose X-Forwarded-* headers are trusted"],
        ],
        col_widths=[1.8 * inch, 0.8 * inch, 3.9 * inch]
    )
    story.append(auth_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Minimum Required Configuration", styles["SubSection"]))
    story.append(Paragraph(
        "The setup wizard writes everything the service needs. For reference, after setup the "
        f'{code("settings.json")} file in the data folder looks like this:',
        styles["BodyText2"]
    ))
    story.append(code_block(
        '{\n'
        '  "Certus": {\n'
        '    "CaConnectionString": "CA-SERVER\\\\MyCA",\n'
        '    "ExternalUrl": "https://ducks.yourdomain.local:5001"\n'
        '  }\n'
        '}', styles))
    story.append(Paragraph(
        f'{bold("Important:")} The {code("ExternalUrl")} must be reachable by ACME clients on your '
        f'network. This URL is embedded in ACME directory responses and challenge URLs. Use HTTPS '
        f'in production environments.',
        styles["Warning"]
    ))

    story.append(Paragraph("Kestrel Web Server", styles["SubSection"]))
    story.append(Paragraph(
        f'By default, Ducks in a Row listens on all interfaces on TCP 5000 (HTTP) and TCP 5001 '
        f'(HTTPS). The HTTPS endpoint uses a self signed certificate out of the box, generated '
        f'in the data folder as {code("ducks-selfsigned.pfx")}, so browsers warn on first '
        f'visit and ACME clients will not trust it.',
        styles["BodyText2"]
    ))
    story.append(Paragraph(
        f'{bold("The easiest fix is built in.")} On the external URL step, the setup wizard can '
        f'enrol an HTTPS certificate for this server from the CA you connected, install it, and '
        f'reload the service. The Settings page can renew it later. Use that first.',
        styles["Note"]
    ))
    story.append(Paragraph(
        "If you would rather supply your own certificate, point Kestrel at one your clients "
        "already trust (for example, a certificate issued by your own CA whose root your "
        "clients trust):",
        styles["BodyText2"]
    ))
    story.append(code_block(
        '"Kestrel": {\n'
        '  "Endpoints": {\n'
        '    "Https": {\n'
        '      "Url": "https://0.0.0.0:5001",\n'
        '      "Certificate": {\n'
        '        "Path": "C:\\\\ProgramData\\\\Ducks in a Row\\\\ducks.pfx",\n'
        '        "Password": "your-pfx-password"\n'
        '      }\n'
        '    }\n'
        '  }\n'
        '}', styles))
    story.append(Paragraph(
        f'For a quick lab test only, you can set {code("Auth:RequireHttps")} to '
        f'{code("false")} and use plain HTTP on port 5000 instead.',
        styles["BodyText2"]
    ))

    story.append(Paragraph("Logging", styles["SubSection"]))
    story.append(Paragraph(
        f'Ducks in a Row uses Serilog for structured logging. Logs are written to '
        f'{code("logs\\")} in the data folder with daily rotation and a 30-day '
        f'retention policy. Adjust the minimum log level in the Serilog configuration section:',
        styles["BodyText2"]
    ))
    story.append(code_block(
        '"Serilog": {\n'
        '  "MinimumLevel": {\n'
        '    "Default": "Information",\n'
        '    "Override": {\n'
        '      "Microsoft.AspNetCore": "Warning",\n'
        '      "Microsoft.EntityFrameworkCore": "Warning"\n'
        '    }\n'
        '  }\n'
        '}', styles))

    story.append(PageBreak())

    # === 5. ADCS CONFIGURATION ===
    story.append(Paragraph("5. ADCS Configuration", styles["SectionTitle"]))

    story.append(Paragraph("Finding Your CA Connection String", styles["SubSection"]))
    story.append(Paragraph(
        "The CA connection string follows the format "
        f'{code("hostname\\CAName")}. The setup wizard finds it for you, so you rarely need '
        f'to build it by hand. The manual options below are a fallback.',
        styles["BodyText2"]
    ))

    story.append(Paragraph("Option A: Let the Setup Wizard Discover It", styles["SubSubSection"]))
    story.append(Paragraph(
        f'Open {code("https://your-server:5001/setup")} after installation. The wizard '
        f'discovers the ADCS CAs published in Active Directory, lets you pick one, and tests '
        f'connectivity through the same path the service uses. This is the recommended way and '
        f'needs no connection string typed by hand.',
        styles["BodyText2"]
    ))

    story.append(Paragraph("Option B: From the CA Server", styles["SubSubSection"]))
    story.append(Paragraph(
        f'Open the Certification Authority MMC snap-in ({code("certsrv.msc")}) on your CA server. '
        f'The CA name appears in the console tree. The connection string is the CA server hostname '
        f'followed by a backslash and the CA name.',
        styles["BodyText2"]
    ))

    story.append(Paragraph("Option C: Using PowerShell", styles["SubSubSection"]))
    story.append(Paragraph(
        "Run this on any domain-joined machine to discover CAs in your forest:",
        styles["BodyText2"]
    ))
    story.append(code_block(
        "certutil -config - -ping", styles))
    story.append(Paragraph(
        "This displays a list of available CAs. The output includes the connection "
        "string in the required format.",
        styles["BodyText2"]
    ))

    story.append(Paragraph("Certificate Template Permissions", styles["SubSection"]))
    story.append(Paragraph(
        "For Ducks in a Row to issue certificates on behalf of ACME clients, the server's "
        "machine account needs Enroll permission on each certificate template you plan to use. "
        "To configure this:",
        styles["BodyText2"]
    ))
    template_steps = [
        f'Open the Certification Authority MMC ({code("certsrv.msc")}) on your CA server.',
        "Right-click the target certificate template and select Properties.",
        "Go to the Security tab.",
        f'Add the Ducks in a Row server machine account (e.g., {code("DUCKS-SERVER$")}).',
        "Grant the Enroll permission. Do not grant Autoenroll.",
        "Click OK and repeat for each template.",
    ]
    for i, step in enumerate(template_steps, 1):
        story.append(Paragraph(
            f"<bullet>{i}.</bullet>{step}",
            styles["BulletText"]
        ))

    story.append(Spacer(1, 8))
    story.append(Paragraph("CA Read Permission", styles["SubSection"]))
    story.append(Paragraph(
        "The machine account also needs Read permission on the CA itself (Certification "
        "Authority console, CA properties, Security tab). Read is what lets the dashboard "
        "sync the certificate inventory. Without it, enrolment still works but the dashboard "
        "stays empty.",
        styles["BodyText2"]
    ))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Template URL Mapping", styles["SubSection"]))
    story.append(Paragraph(
        "Each ADCS certificate template is exposed as its own ACME directory endpoint. "
        "ACME clients target the URL for the specific template they need:",
        styles["BodyText2"]
    ))
    template_table = make_table(
        ["Template Name", "ACME Directory URL"],
        [
            ["WebServer", "https://your-server:5001/acme/WebServer/directory"],
            ["(your template name)", "https://your-server:5001/acme/{template-name}/directory"],
        ],
        col_widths=[2.0 * inch, 4.5 * inch]
    )
    story.append(template_table)

    story.append(Paragraph(
        f"{bold('Note:')} The template segment is the template's programmatic name (its AD cn) "
        f"or its display name, matched case insensitively. Display names with spaces work; "
        f"the client URL encodes them.",
        styles["Note"]
    ))

    story.append(PageBreak())

    # === 6. TESTING YOUR INSTALLATION ===
    story.append(Paragraph("6. Testing Your Installation", styles["SectionTitle"]))

    story.append(Paragraph("Service Status", styles["SubSection"]))
    story.append(Paragraph(
        "Verify the Ducks in a Row service is running:",
        styles["BodyText2"]
    ))
    story.append(code_block(
        "Get-Service DucksInARow\n\n"
        "# Expected output:\n"
        "# Status   Name          DisplayName\n"
        "# ------   ----          -----------\n"
        "# Running  DucksInARow   Ducks in a Row Certificate Proxy", styles))

    story.append(Paragraph("Health Endpoint", styles["SubSection"]))
    story.append(Paragraph(
        "The health check endpoint reports the status of the database and CA connectivity:",
        styles["BodyText2"]
    ))
    story.append(code_block(
        "Invoke-RestMethod https://your-server:5001/health\n\n"
        "# Returns: Healthy, Degraded, or Unhealthy", styles))
    health_table = make_table(
        ["Status", "Meaning"],
        [
            ["Healthy", "Database is accessible and CA connection is working"],
            ["Degraded", "Database is working but CA is not reachable"],
            ["Unhealthy", "Database is not accessible"],
        ],
        col_widths=[1.5 * inch, 5.0 * inch]
    )
    story.append(health_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("ACME Directory", styles["SubSection"]))
    story.append(Paragraph(
        "Test that ACME endpoints are responding correctly:",
        styles["BodyText2"]
    ))
    story.append(code_block(
        "Invoke-RestMethod https://your-server:5001/acme/WebServer/directory | ConvertTo-Json\n\n"
        '# Expected: JSON with newNonce, newAccount, newOrder URLs', styles))

    story.append(Paragraph("Firewall Verification", styles["SubSection"]))
    story.append(Paragraph(
        "Confirm the firewall rules (HTTP and HTTPS) were created by the installer:",
        styles["BodyText2"]
    ))
    story.append(code_block(
        'Get-NetFirewallRule -DisplayName "Ducks in a Row Certificate Proxy*"', styles))

    story.append(Paragraph("Dashboard Access", styles["SubSection"]))
    story.append(Paragraph(
        f'Open {code("https://your-server:5001")} in a browser and sign in as a member of '
        f'the administrator group. The dashboard displays certificate inventory, expiry '
        f'status, and template information. On first access, you may be redirected to the '
        f'setup wizard at {code("/setup")}.',
        styles["BodyText2"]
    ))
    story.extend(figure(
        "dashboard-overview.png",
        "The dashboard after the first sync, showing the certificate inventory and expiry tiles.",
        styles,
    ))

    story.append(Paragraph("CA Connectivity Test", styles["SubSection"]))
    story.append(Paragraph(
        f'The setup wizard at {code("https://your-server:5001/setup")} includes a built in '
        f'connectivity test. Click {bold("Test Connection")} to verify DCOM/RPC communication '
        f'with your ADCS CA. The test will report the CA name, server, and available templates.',
        styles["BodyText2"]
    ))

    story.append(PageBreak())

    # === 7. CONNECTING ACME CLIENTS ===
    story.append(Paragraph("7. Connecting ACME Clients", styles["SectionTitle"]))
    story.append(Paragraph(
        "Ducks in a Row implements RFC 8555 (ACME), so any standard ACME client works out of "
        "the box. No agent or proprietary software is needed on your endpoints. Use the HTTPS "
        "endpoint (5001) in production; plain HTTP (5000) is for lab use only. The example "
        "commands are representative; exact flags vary by client version, so check each "
        "client's own documentation for your release.",
        styles["BodyText2"]
    ))
    story.append(Paragraph(
        f"{bold('Trusting the server TLS:')} ACME clients reject an untrusted TLS certificate "
        f"on the ACME server itself. Give Ducks in a Row a certificate your clients already "
        f"trust (for example, one chained to your internal CA root), or add that root to each "
        f"client's trust store. The examples below note the per client switch for a lab where "
        f"the server still uses its self signed certificate.",
        styles["Note"]
    ))

    story.append(Paragraph("Certbot (Linux)", styles["SubSection"]))
    story.append(code_block(
        "# HTTP-01, certbot answers the challenge itself on port 80\n"
        "certbot certonly --standalone \\\n"
        "  --server https://your-server:5001/acme/WebServer/directory \\\n"
        "  --email you@example.com \\\n"
        "  -d host.corp.example.com \\\n"
        "  --key-type rsa --rsa-key-size 2048", styles))
    story.append(Paragraph(
        f"{bold('Key type:')} If your ADCS template uses an RSA CSP (the default Web Server "
        f"ACME template does), your ACME client must request an RSA key. Most modern clients "
        f"default to elliptic curve keys, which the CA policy module rejects at finalize with "
        f"{code('Denied by Policy Module')}. The last line above forces RSA for certbot. "
        f"Other clients: lego {code('--key-type rsa2048')}, acme.sh {code('--keylength 2048')}, "
        f"dehydrated {code('KEY_ALGO=&quot;rsa&quot;')}.",
        styles["Warning"]
    ))
    story.append(Paragraph(
        f"Accounts do not need to be registered in advance and no external account binding is "
        f"required; the client creates an account from its own key on first use. For a lab "
        f"server with an untrusted TLS certificate, set {code('REQUESTS_CA_BUNDLE')} to your "
        f"CA root PEM so certbot trusts the endpoint.",
        styles["BodyText2"]
    ))

    story.append(Paragraph("win-acme (Windows)", styles["SubSection"]))
    story.append(Paragraph(
        "Run wacs.exe and, in the menu, set the ACME server to the template directory URL, "
        "then create a certificate. Unattended example:",
        styles["BodyText2"]
    ))
    story.append(code_block(
        "wacs.exe --source iis --siteid 1 ^\n"
        "  --baseuri https://your-server:5001/acme/WebServer/directory", styles))
    story.append(Paragraph(
        "win-acme uses the Windows certificate trust store, so import your CA root on the "
        "machine running it if the server certificate is not already trusted.",
        styles["BodyText2"]
    ))

    story.append(Paragraph("Caddy", styles["SubSection"]))
    story.append(code_block(
        "# Caddyfile\n"
        "{\n"
        "  acme_ca https://your-server:5001/acme/WebServer/directory\n"
        "  # For an internal CA, point Caddy at the root so it trusts the ACME endpoint\n"
        "  acme_ca_root /etc/ssl/certs/corp-root.pem\n"
        "  email you@example.com\n"
        "}\n\n"
        "host.corp.example.com {\n"
        '  respond "Hello from Caddy"\n'
        "}", styles))

    story.append(Paragraph("Traefik", styles["SubSection"]))
    story.append(code_block(
        "# traefik.yml\n"
        "certificatesResolvers:\n"
        "  ducks:\n"
        "    acme:\n"
        "      caServer: https://your-server:5001/acme/WebServer/directory\n"
        "      email: you@example.com\n"
        "      storage: /etc/traefik/acme.json\n"
        "      httpChallenge:\n"
        "        entryPoint: web", styles))
    story.append(Paragraph(
        "Traefik uses the host or container trust store. Add your CA root there if the ACME "
        "endpoint certificate is not already trusted.",
        styles["BodyText2"]
    ))

    story.append(Paragraph("Posh-ACME (PowerShell)", styles["SubSection"]))
    story.append(code_block(
        "Import-Module Posh-ACME\n\n"
        "# Point Posh-ACME at the template directory.\n"
        "# Add -SkipCertificateCheck only for a lab server with untrusted TLS.\n"
        "Set-PAServer -DirectoryUrl https://your-server:5001/acme/WebServer/directory\n\n"
        "New-PAAccount -Contact you@example.com -AcceptTOS\n\n"
        "New-PACertificate -Domain host.corp.example.com -Plugin WebRoot `\n"
        "  -PluginArgs @{ WebRootPath = 'C:\\inetpub\\wwwroot' }", styles))

    story.append(Paragraph("Challenge Types", styles["SubSection"]))
    challenge_table = make_table(
        ["Type", "Use Case", "How It Works"],
        [
            ["HTTP-01", "Standard web servers",
             "Fetches http://{domain}/.well-known/acme-challenge/{token}"],
            ["DNS-01", "Wildcards, hosts with no inbound HTTP",
             "Looks up the TXT record at _acme-challenge.{domain}"],
            ["TLS-ALPN-01", "TLS only environments",
             "Opens a TLS connection on port 443 and checks the ALPN certificate"],
        ],
        col_widths=[1.2 * inch, 1.8 * inch, 3.5 * inch]
    )
    story.append(challenge_table)
    story.append(Paragraph(
        "The Ducks in a Row server is the party that performs validation, so the server "
        "needs outbound reachability to the domain or DNS being validated.",
        styles["BodyText2"]
    ))

    story.append(PageBreak())

    # === 8. ALERT CONFIGURATION ===
    story.append(Paragraph("8. Alert Configuration", styles["SectionTitle"]))
    story.append(Paragraph(
        "Ducks in a Row monitors certificate expiry and sends notifications through email "
        "and webhooks. Alerts are included in the free tier with no limits.",
        styles["BodyText2"]
    ))

    story.append(Paragraph("Alert Thresholds", styles["SubSection"]))
    story.append(Paragraph(
        "By default, alerts fire at 30, 14, 7, and 1 day(s) before certificate expiry. "
        "Each certificate receives at most one alert per threshold (no duplicates). The "
        "monitor checks for expiring certificates every 60 minutes by default "
        f'({code("CheckIntervalMinutes")}).',
        styles["BodyText2"]
    ))

    story.append(Paragraph("SMTP Email Alerts", styles["SubSection"]))
    story.append(code_block(
        '"Certus:Alerts": {\n'
        '  "Enabled": true,\n'
        '  "CheckIntervalMinutes": 60,\n'
        '  "ThresholdDays": [30, 14, 7, 1],\n'
        '  "Smtp": {\n'
        '    "Host": "smtp.yourdomain.local",\n'
        '    "Port": 587,\n'
        '    "UseSsl": true,\n'
        '    "Username": "ducks@yourdomain.local",\n'
        '    "Password": "your-smtp-password",\n'
        '    "FromAddress": "ducks@yourdomain.local",\n'
        '    "Recipients": ["admin@yourdomain.local"]\n'
        '  }\n'
        '}', styles))

    story.append(Paragraph("Webhook Alerts", styles["SubSection"]))
    story.append(Paragraph(
        "Webhooks send a JSON payload via HTTP POST. The payload is signed with HMAC-SHA256 "
        f'using the configured secret. The signature is sent in the {code("X-Certus-Signature")} header.',
        styles["BodyText2"]
    ))
    story.append(code_block(
        '"Webhook": {\n'
        '  "Url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",\n'
        '  "Secret": "your-hmac-secret",\n'
        '  "Headers": {\n'
        '    "X-Custom-Header": "value"\n'
        '  }\n'
        '}', styles))

    story.append(Paragraph("Alert History", styles["SubSection"]))
    story.append(Paragraph(
        f'Sent alerts are recorded and available through the API at '
        f'{code("GET /api/alerts/history")} and {code("GET /api/alerts/summary")}. '
        f'This beta does not yet include a dedicated Alerts page in the dashboard.',
        styles["BodyText2"]
    ))

    story.append(PageBreak())

    # === 9. TROUBLESHOOTING ===
    story.append(Paragraph("9. Troubleshooting", styles["SectionTitle"]))

    trouble_items = [
        (
            "Service fails to start",
            f'Check the Windows Event Log (Application) and the log files at '
            f'{code("logs\\")} in the data folder. Common causes: missing .NET 8 runtime, '
            f'invalid {code("appsettings.json")} or {code("settings.json")} syntax (trailing '
            f'commas, missing quotes), or ports 5000 or 5001 already in use by another process. '
            f'To see the actual error, run the executable directly from an elevated PowerShell: '
            f'{code("&amp; &quot;C:\\Program Files\\Ducks in a Row\\DucksInARow.Service.exe&quot;")}'
        ),
        (
            "CA operations answer 503, or the dashboard routes to the setup wizard",
            "No CA is configured yet. The service starts unconfigured and never falls back to a "
            "fake CA on its own. Complete the setup wizard; it discovers the CAs in Active "
            "Directory, tests the connection, applies the configuration, and restarts the "
            "service."
        ),
        (
            "COM activation or DISP_E_MEMBERNOTFOUND errors during CA operations",
            f'The ADCS COM classes are not registered on the Ducks in a Row server. Install the '
            f'ADCS Remote Administration Tools: '
            f'{code("Install-WindowsFeature RSAT-ADCS-Mgmt")} and then restart the service. '
            f'This feature must be installed even though this server is not the CA server. '
            f'The COM class registrations are provided by the RSAT feature package.'
        ),
        (
            "Health endpoint returns Degraded",
            "The database is working but the CA is not reachable. Verify the "
            f'{code("CaConnectionString")} (in {code("settings.json")} in the data folder) is '
            f'correct and uses the format {code("hostname\\CAName")}. Confirm DCOM/RPC traffic '
            f'is not blocked by a firewall (TCP 135 and dynamic ports 49152-65535), and the '
            f'server has network access to the CA. Test with: '
            f'{code("certutil -config &quot;SERVER\\CA&quot; -ping")}'
        ),
        (
            "Health endpoint returns Unhealthy",
            f'The SQLite database is not accessible. Verify the {code("DatabasePath")} points to a '
            f'valid, writable location. Check that the data folder exists and the LocalSystem '
            f'account has write access.'
        ),
        (
            "ACME client gets connection refused",
            'Verify the service is running (' + code("Get-Service DucksInARow") + '), the firewall rule '
            'exists (' + code("Get-NetFirewallRule -DisplayName &quot;Ducks in a Row*&quot;") + '), and the '
            '' + code("ExternalUrl") + ' in configuration matches how clients reach the server.'
        ),
        (
            "Certificate request fails with template error",
            "The template name in the directory URL must match a template the CA publishes, "
            "either by its programmatic name (AD cn) or its display name; names are matched "
            "case insensitively. Confirm the template is published to Active Directory and "
            "the server's machine account has Enroll permission."
        ),
        (
            "ACME client reports a TLS or certificate trust error",
            f'The HTTPS endpoint uses a self signed certificate by default '
            f'({code("ducks-selfsigned.pfx")} in the data folder), and ACME clients reject '
            f'untrusted TLS on the ACME server. Give Ducks in a Row a certificate your '
            f'clients trust, or add that certificate root to each client trust store.'
        ),
        (
            "Cannot reach the dashboard, or get a 401",
            f'The dashboard and setup API use Windows Integrated Authentication and are '
            f'limited to the administrator group. Sign in as a member of the built in '
            f'Administrators group, or set {code("Auth:AdminGroup")} to the Windows or '
            f'Active Directory group you want to allow, then restart the service.'
        ),
        (
            "DCOM authentication errors",
            "The Ducks in a Row server must be domain joined. Verify the machine account has not "
            "been disabled or moved to a restricted OU. Check that DCOM port ranges (TCP 135 + "
            "dynamic ports 49152-65535) are open between this server and the CA server."
        ),
        (
            "Service exits silently with no log output",
            f'Run the executable directly to see the error: '
            f'{code("dotnet &quot;C:\\Program Files\\Ducks in a Row\\DucksInARow.Service.dll&quot;")} '
            f'Common causes include malformed JSON in {code("appsettings.json")} or '
            f'{code("settings.json")} (use a JSON validator to check syntax), missing .NET '
            f'runtime, or file permission issues. '
            f'Set the environment variable {code("ASPNETCORE_ENVIRONMENT=Development")} '
            f'before running to enable detailed error output.'
        ),
        (
            "Dashboard shows no certificates",
            f'The machine account needs Read permission on the CA (Certification Authority '
            f'console, CA properties, Security tab); without it, enrolment still works but the '
            f'inventory sync cannot read the CA database and the log reports "CA view access '
            f'denied". The sync also runs only every {code("SyncIntervalMinutes")} (default '
            f'5), so wait for the first cycle or restart the service to force one.'
        ),
    ]

    for title, desc in trouble_items:
        story.append(Paragraph(title, styles["SubSection"]))
        story.append(Paragraph(desc, styles["BodyText2"]))

    story.append(PageBreak())

    # === 10. UNINSTALLING ===
    story.append(Paragraph("10. Uninstalling", styles["SectionTitle"]))
    story.append(Paragraph(
        "Ducks in a Row can be removed through Windows Add/Remove Programs or from the command line:",
        styles["BodyText2"]
    ))
    story.append(code_block(
        "msiexec /x Ducks-in-a-Row.msi", styles))

    story.append(Paragraph("What the uninstaller removes:", styles["SubSection"]))
    remove_items = [
        "All application files from C:\\Program Files\\Ducks in a Row\\",
        "The DucksInARow Windows Service registration (the service is stopped first)",
        "The Ducks in a Row Certificate Proxy firewall rules",
    ]
    for item in remove_items:
        story.append(Paragraph(
            f"<bullet>&bull;</bullet>{item}",
            styles["BulletText"]
        ))

    story.append(Spacer(1, 8))
    story.append(Paragraph("What the uninstaller preserves:", styles["SubSection"]))
    keep_items = [
        "The SQLite database (ducks.db in the data folder)",
        "Log files (logs\\ in the data folder)",
        "The data folder itself (default C:\\ProgramData\\Ducks in a Row\\)",
    ]
    for item in keep_items:
        story.append(Paragraph(
            f"<bullet>&bull;</bullet>{item}",
            styles["BulletText"]
        ))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "To perform a complete removal including all data, delete the data directory manually "
        "after uninstalling:",
        styles["BodyText2"]
    ))
    story.append(code_block(
        'Remove-Item -Recurse -Force "C:\\ProgramData\\Ducks in a Row"', styles))

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
    print(f"PDF generated: {OUTPUT_PATH}")


if __name__ == "__main__":
    build_document()
