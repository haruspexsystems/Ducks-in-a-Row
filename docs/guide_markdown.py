"""Parse the markdown in this folder into blocks the guide generator renders.

This exists so the installation guide PDF and the markdown docs cannot say
different things. Before it, the guide's prose lived in Python string literals
in generate_guide.py, and the two drifted: the PDF told readers that no external
account binding was ever required long after the markdown had been corrected to
say it depends on the enforcement mode, and it stated the RSA key requirement as
universal after the product had learned to enrol on a curve.

The parser is deliberately hand written and deliberately strict. It covers only
what the docs in this folder actually use, and it raises GuideSyntaxError on any
line it cannot classify. That matters more than convenience: a general purpose
library hands back a node type the renderer does not know, the renderer drops it,
and the guide quietly loses a paragraph. That silent loss is the failure this
whole arrangement exists to prevent, so an unknown construct has to stop the
build instead.

Switch to a library (mistune reads closest to this block model) if the docs ever
grow nested blockquotes, HTML blocks, footnotes, reference style links or
definition lists. Until then the grammar below is the whole language.

Contains no reportlab import on purpose, so the parser can be exercised on its
own. generate_guide.py owns every decision about how a block looks on a page.
"""

import io
import re


class GuideSyntaxError(Exception):
    """A line the parser will not guess at.

    Carries the file and line number because the whole point is that a build
    failure should say what to fix, not merely that something is wrong.
    """

    def __init__(self, path, lineno, line, reason):
        self.path = path
        self.lineno = lineno
        self.line = line
        self.reason = reason
        super().__init__(
            "%s:%d: %s\n    %s" % (path, lineno, reason, line.rstrip())
        )


# --------------------------------------------------------------------------
# Blocks
#
# A block is a small dict rather than a class, because the renderer dispatches
# on "kind" and nothing here needs behaviour.
# --------------------------------------------------------------------------

HEADING = "heading"      # level (1..3), text
PARA = "para"            # text
CODE = "code"            # text, lang, indent
BULLET = "bullet"        # text, depth, marker (None = unordered)
TABLE = "table"          # headers, rows
QUOTE = "quote"          # text, severity ("note" | "warning")
IMAGE = "image"          # src, alt


# --------------------------------------------------------------------------
# Line shapes
# --------------------------------------------------------------------------

_FENCE = re.compile(r"^(\s*)```\s*([A-Za-z0-9_+-]*)\s*$")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_BULLET = re.compile(r"^(\s*)-\s+(.*)$")
_ORDERED = re.compile(r"^(\s*)(\d+)\.\s+(.*)$")
_TABLE_ROW = re.compile(r"^\s*\|(.*)\|\s*$")
_TABLE_SEP = re.compile(r"^\s*\|[\s:|-]+\|\s*$")
_QUOTE = re.compile(r"^>\s?(.*)$")
_IMAGE = re.compile(r"^\s*!\[([^\]]*)\]\(([^)]+)\)\s*$")

# GitHub alert markers. Unmarked stays a note, so nothing in the existing docs
# has to change; only a blockquote that wants the amber treatment adds one.
_ALERT = re.compile(r"^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$")
_WARNING_ALERTS = {"IMPORTANT", "WARNING", "CAUTION"}


def _severity(marker):
    return "warning" if marker in _WARNING_ALERTS else "note"


# --------------------------------------------------------------------------
# Inline runs
#
# Emitted as typed runs rather than by rewriting the string, so escaping happens
# once at render time and the order of operations stops being a hazard. That is
# what keeps a backslash or an angle bracket placeholder inside backticks from
# reaching the renderer as markup.
# --------------------------------------------------------------------------

TEXT = "text"
CODE_SPAN = "code"
BOLD = "bold"
ITALIC = "italic"
LINK = "link"            # children, href

_INLINE_CODE = re.compile(r"`([^`]+)`")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_BOLD = re.compile(r"\*\*(.+?)\*\*", re.DOTALL)
_ITALIC = re.compile(r"(?<!\*)\*([^*]+)\*(?!\*)")

# Code spans are lifted out before any structure is read and put back
# afterwards. Doing it the other way round breaks both directions: extracting
# code first splits the string, so the pair in **bold with `code` inside** never
# matches and the asterisks render literally; reading structure first lets an
# asterisk inside a code span be mistaken for emphasis. Masking is what makes a
# code span atomic without making it a barrier.
_MASK_OPEN = "\x00"
_MASK = re.compile("\x00(\\d+)\x00")


def parse_inline(text):
    """Split a joined paragraph into typed runs.

    Precedence after unmasking is links, then bold, then italic, with code spans
    restored at whatever depth they were lifted from. Link text is parsed again
    so a bold word inside a link survives.
    """
    if _MASK_OPEN in text:
        # Never seen in practice, but the sentinel has to be unambiguous and a
        # wrong answer here would be silent.
        raise ValueError("markdown source contains a NUL byte, which the "
                         "inline parser reserves as a code span sentinel")

    spans = []

    def stash(match):
        spans.append(match.group(1))
        return "\x00%d\x00" % (len(spans) - 1)

    masked = _INLINE_CODE.sub(stash, text)
    return _restore(_split(masked, (_LINK, _BOLD, _ITALIC)), spans)


def _split(text, patterns):
    if not patterns:
        return [(TEXT, text)] if text else []

    pattern, rest = patterns[0], patterns[1:]
    runs = []
    pos = 0
    for match in pattern.finditer(text):
        if match.start() > pos:
            runs.extend(_split(text[pos:match.start()], rest))
        if pattern is _LINK:
            runs.append((LINK, _split(match.group(1), rest), match.group(2)))
        elif pattern is _BOLD:
            runs.append((BOLD, _split(match.group(1), rest)))
        else:
            runs.append((ITALIC, _split(match.group(1), rest)))
        pos = match.end()
    if pos < len(text):
        runs.extend(_split(text[pos:], rest))
    return runs


def _restore(runs, spans):
    out = []
    for run in runs:
        if run[0] == TEXT:
            out.extend(_restore_text(run[1], spans))
        elif run[0] == LINK:
            out.append((LINK, _restore(run[1], spans), run[2]))
        else:
            out.append((run[0], _restore(run[1], spans)))
    return out


def _restore_text(text, spans):
    out = []
    pos = 0
    for match in _MASK.finditer(text):
        if match.start() > pos:
            out.append((TEXT, text[pos:match.start()]))
        out.append((CODE_SPAN, spans[int(match.group(1))]))
        pos = match.end()
    if pos < len(text):
        out.append((TEXT, text[pos:]))
    return out


# --------------------------------------------------------------------------
# Block parser
# --------------------------------------------------------------------------

def parse_file(path):
    """Return the blocks of one markdown file, in document order."""
    with io.open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    return parse_lines(lines, path)


def parse_lines(lines, path="<string>"):
    blocks = []
    i = 0
    total = len(lines)

    while i < total:
        line = lines[i]
        stripped = line.strip()

        # Blank lines separate blocks and carry no meaning of their own.
        if not stripped:
            i += 1
            continue

        # Fenced code. Checked before everything else, because a fence body can
        # contain any character sequence at all, including lines that look like
        # headings. Reading acme-clients.md without this finds four h1s where
        # there is one; the other three are shell comments inside bash fences.
        fence = _FENCE.match(line)
        if fence:
            indent, lang = len(fence.group(1)), fence.group(2)
            body, i = _read_fence(lines, i, indent, path)
            blocks.append(
                {"kind": CODE, "text": body, "lang": lang, "indent": indent}
            )
            continue

        # Image on a line of its own, at any indent. Indented ones sit inside
        # ordered list items in quickstart.md.
        image = _IMAGE.match(line)
        if image:
            blocks.append(
                {"kind": IMAGE, "alt": image.group(1), "src": image.group(2)}
            )
            i += 1
            continue

        heading = _HEADING.match(line)
        if heading:
            level = len(heading.group(1))
            if level > 3:
                raise GuideSyntaxError(
                    path, i + 1, line,
                    "heading level %d is deeper than the guide renders" % level,
                )
            blocks.append(
                {"kind": HEADING, "level": level, "text": heading.group(2).strip()}
            )
            i += 1
            continue

        if _QUOTE.match(line):
            block, i = _read_quote(lines, i)
            blocks.append(block)
            continue

        # A table is a row followed by a separator row. Testing the next line
        # keeps a lone pipe in prose from being read as a table.
        if _TABLE_ROW.match(line) and i + 1 < total and _TABLE_SEP.match(lines[i + 1]):
            block, i = _read_table(lines, i, path)
            blocks.append(block)
            continue

        # A pipe line that is not a table start is almost always a table whose
        # header was absorbed by the paragraph above it, because the author left
        # no blank line between the two. Refuse it rather than rendering a row
        # of pipes as prose.
        if _TABLE_ROW.match(line):
            raise GuideSyntaxError(
                path, i + 1, line,
                "table row with no separator row beneath it; a table needs a "
                "blank line before its header",
            )

        bullet = _BULLET.match(line)
        ordered = _ORDERED.match(line)
        if bullet or ordered:
            produced, i = _read_list_item(lines, i, path)
            blocks.extend(produced)
            continue

        # Anything left is a paragraph, which ends at a blank line or at the
        # start of any other construct.
        block, i = _read_paragraph(lines, i, path)
        blocks.append(block)

    return blocks


def _read_fence(lines, i, indent, path):
    opener = i
    i += 1
    body = []
    while i < len(lines):
        candidate = _FENCE.match(lines[i])
        if candidate and candidate.group(2) == "":
            return "\n".join(body), i + 1
        # Strip only the fence's own indent, so code keeps its inner shape.
        body.append(lines[i][indent:] if lines[i][:indent].isspace() else lines[i])
        i += 1
    raise GuideSyntaxError(
        path, opener + 1, lines[opener], "code fence is never closed"
    )


def _read_quote(lines, i):
    collected = []
    while i < len(lines) and _QUOTE.match(lines[i]):
        collected.append(_QUOTE.match(lines[i]).group(1))
        i += 1

    severity = "note"
    if collected:
        alert = _ALERT.match(collected[0].strip())
        if alert:
            severity = _severity(alert.group(1))
            collected = collected[1:]

    return (
        {"kind": QUOTE, "text": _join(collected), "severity": severity},
        i,
    )


def _read_table(lines, i, path):
    def cells(row):
        return [c.strip() for c in _TABLE_ROW.match(row).group(1).split("|")]

    headers = cells(lines[i])
    i += 2  # header row and separator row
    rows = []
    while i < len(lines) and _TABLE_ROW.match(lines[i]):
        row = cells(lines[i])
        if len(row) != len(headers):
            raise GuideSyntaxError(
                path, i + 1, lines[i],
                "table row has %d cells, header has %d" % (len(row), len(headers)),
            )
        rows.append(row)
        i += 1
    return {"kind": TABLE, "headers": headers, "rows": rows}, i


def _read_list_item(lines, i, path):
    """Read one list item, plus any fenced code or image indented under it."""
    bullet = _BULLET.match(lines[i])
    ordered = _ORDERED.match(lines[i])
    if bullet:
        indent, marker, text = len(bullet.group(1)), None, bullet.group(2)
    else:
        indent, marker, text = (
            len(ordered.group(1)),
            ordered.group(2),
            ordered.group(3),
        )

    i += 1
    continuation = [text]
    produced = []

    # A continuation line is indented past the marker and is not itself the
    # start of another construct.
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            # A blank line inside an item is only a break if what follows is
            # not still indented under it.
            following = _next_content(lines, i)
            if following is None:
                break
            if _line_indent(lines[following]) <= indent:
                break
            i += 1
            continue

        if _line_indent(line) <= indent:
            break

        fence = _FENCE.match(line)
        if fence:
            body, i = _read_fence(lines, i, len(fence.group(1)), path)
            produced.append(
                {
                    "kind": CODE,
                    "text": body,
                    "lang": fence.group(2),
                    "indent": len(fence.group(1)),
                }
            )
            continue

        image = _IMAGE.match(line)
        if image:
            produced.append(
                {"kind": IMAGE, "alt": image.group(1), "src": image.group(2)}
            )
            i += 1
            continue

        nested_bullet = _BULLET.match(line)
        nested_ordered = _ORDERED.match(line)
        if nested_bullet or nested_ordered:
            nested, i = _read_list_item(lines, i, path)
            produced.extend(nested)
            continue

        continuation.append(line.strip())
        i += 1

    item = {
        "kind": BULLET,
        "text": _join(continuation),
        "depth": 1 if indent >= 2 else 0,
        "marker": marker,
    }
    return [item] + produced, i


def _read_paragraph(lines, i, path):
    collected = []
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            break
        if (
            _FENCE.match(line)
            or _HEADING.match(line)
            or _QUOTE.match(line)
            or _BULLET.match(line)
            or _ORDERED.match(line)
            or _IMAGE.match(line)
            or _TABLE_SEP.match(line)
        ):
            break
        collected.append(line.strip())
        i += 1
    if not collected:
        # Every other branch in parse_lines consumes at least one line, so a
        # paragraph that collects nothing leaves the outer loop on the same line
        # for ever. Raising turns a hung build into a located error, and keeps
        # any break condition added above from reintroducing the spin.
        raise GuideSyntaxError(
            path, i + 1, lines[i],
            "line starts no construct the parser knows and cannot be read as "
            "prose",
        )
    return {"kind": PARA, "text": _join(collected)}, i


def _join(parts):
    """Undo the hard wrap before any inline parsing happens.

    Emphasis spans the wrap in several docs, so a per line inline pass would see
    a stray asterisk and leave the markup showing.
    """
    return " ".join(p.strip() for p in parts if p.strip())


def _line_indent(line):
    return len(line) - len(line.lstrip())


def _next_content(lines, i):
    j = i
    while j < len(lines) and not lines[j].strip():
        j += 1
    return j if j < len(lines) else None


# --------------------------------------------------------------------------
# Heading anchors
#
# GitHub's slug algorithm, so an anchor written for the web docs resolves to the
# same destination inside the PDF.
# --------------------------------------------------------------------------

_SLUG_STRIP = re.compile(r"[^\w\s-]")


def slug(text):
    """Slugify a heading the way GitHub does."""
    plain = "".join(_plain(run) for run in parse_inline(text))
    plain = _SLUG_STRIP.sub("", plain.lower())
    return re.sub(r"[\s]+", "-", plain.strip())


def _plain(run):
    kind = run[0]
    if kind in (TEXT, CODE_SPAN):
        return run[1]
    if kind == LINK:
        return "".join(_plain(r) for r in run[1])
    return "".join(_plain(r) for r in run[1])
