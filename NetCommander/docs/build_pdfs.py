"""Rebuild the plain-text guide and every PDF in docs/ from the .txt sources.

The .txt files under docs/overview, install, usage and support are the source of truth.
This script
  1. concatenates them (in GUIDE_ORDER) into docs/guide/NetCommander-Guide.txt, and
  2. renders each .txt, and the combined guide, to a PDF next to it.

Usage (needs ReportLab, which is not a runtime dependency):

    pip install reportlab
    python docs/build_pdfs.py

Text format understood
  TITLE line + "====" underline        document title ("NETCOMMANDER x.y.z - NAME")
  "N. NAME" + "----" underline         numbered chapter (guide only)
  unindented line after a blank line   sub-heading
  "  - text" (+ 4-space continuation)  bullet
  "  1. text" (+ 5-space continuation) numbered step
  4-space indented lines               code block
  "NOTE:" followed by indented lines   note paragraph
  anything else                        paragraph (lines are joined)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

DOCS = Path(__file__).resolve().parent
GUIDE_ORDER = [
    ("overview/what-it-does.txt", "What NetCommander does"),
    ("install/requirements.txt", "Requirements"),
    ("install/windows.txt", "Installing on Windows"),
    ("install/linux.txt", "Installing on Linux"),
    ("install/optional-extras.txt", "Optional extras"),
    ("usage/first-run.txt", "First run"),
    ("support/troubleshooting.txt", "Troubleshooting"),
    ("support/limits.txt", "Important limits"),
]
GUIDE = DOCS / "guide" / "NetCommander-Guide.txt"
_TITLE = re.compile(r"^NETCOMMANDER (\S+) - (.+)$")


def read(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n").split("\n")


def version_of(lines: list[str]) -> str:
    m = _TITLE.match(lines[0].strip())
    if not m:
        raise SystemExit(f"first line is not a 'NETCOMMANDER x.y.z - NAME' title: {lines[0]!r}")
    return m.group(1)


def build_guide_text() -> str:
    first = read(DOCS / GUIDE_ORDER[0][0])
    title = f"NETCOMMANDER {version_of(first)} - WHAT IT DOES AND HOW TO INSTALL IT"
    out = [title, "=" * len(title), ""]
    for n, (rel, name) in enumerate(GUIDE_ORDER, 1):
        lines = read(DOCS / rel)
        body = lines[2:]
        while body and not body[0].strip():
            body.pop(0)
        while body and not body[-1].strip():
            body.pop()
        head = f"{n}. {name.upper()}"
        out += ["", head, "-" * len(head), "", *body, ""]
    return "\r\n".join(out) + "\r\n"


# ---------------------------------------------------------------- parsing
def blocks(lines: list[str]) -> list[tuple[str, object]]:
    """Turn text lines into (kind, payload) blocks."""
    out: list[tuple[str, object]] = []
    i, n = 0, len(lines)
    prev_blank = True
    while i < n:
        line = lines[i]
        nxt = lines[i + 1] if i + 1 < n else ""
        if not line.strip():
            i, prev_blank = i + 1, True
            continue
        if nxt.strip() and set(nxt.strip()) == {"="}:
            out.append(("title", line.strip()))
            i += 2
        elif nxt.strip() and set(nxt.strip()) == {"-"} and re.match(r"^\d+\. ", line):
            out.append(("chapter", line.strip()))
            i += 2
        elif line.strip() == "NOTE:":
            i += 1
            text = []
            while i < n and lines[i].startswith("  ") and lines[i].strip():
                text.append(lines[i].strip())
                i += 1
            out.append(("note", " ".join(text)))
        elif re.match(r"^  - ", line):
            items = []
            while i < n and re.match(r"^  - ", lines[i]):
                text = [lines[i][4:].strip()]
                i += 1
                while i < n and lines[i].startswith("    ") and lines[i].strip():
                    text.append(lines[i].strip())
                    i += 1
                items.append(_join(text))
            out.append(("bullets", items))
        elif re.match(r"^  \d+\. ", line):
            items = []
            while i < n and re.match(r"^  \d+\. ", lines[i]):
                text = [re.sub(r"^  \d+\. ", "", lines[i]).strip()]
                i += 1
                while i < n and lines[i].startswith("     ") and lines[i].strip():
                    text.append(lines[i].strip())
                    i += 1
                items.append(_join(text))
            out.append(("steps", items))
        elif line.startswith("    "):
            code = []
            while i < n and (lines[i].startswith("    ") or (not lines[i].strip() and i + 1 < n
                                                              and lines[i + 1].startswith("    "))):
                code.append(lines[i][4:])
                i += 1
            out.append(("code", code))
        elif prev_blank and not line.startswith(" ") and (not nxt.strip()):
            out.append(("heading", line.strip()))
            i += 1
        else:
            text = []
            while i < n and lines[i].strip() and not lines[i].startswith("  "):
                text.append(lines[i].strip())
                i += 1
            out.append(("para", _join(text)))
        prev_blank = False
    return out


def _join(parts: list[str]) -> str:
    """Join wrapped lines; a line ending in '-' after a letter was a hyphenation split."""
    text = ""
    for p in parts:
        if text.endswith("-") and len(text) > 1 and text[-2].isalpha() and p[:1].isalpha() and p[:1].isupper():
            text += p                                  # "IOS-" + "XR" -> "IOS-XR"
        elif text.endswith("-") and len(text) > 1 and text[-2].isalpha() and p[:1].islower():
            text += p                                  # "passphrase-" + "protected"
        else:
            text = f"{text} {p}" if text else p
    return text


def _chapter_name(chapter: str) -> str:
    """'1. WHAT NETCOMMANDER DOES' -> '1. What NetCommander does' (names come from GUIDE_ORDER)."""
    num, upper = chapter.split(". ", 1)
    for _rel, name in GUIDE_ORDER:
        if name.upper() == upper:
            return f"{num}. {name}"
    return f"{num}. {upper.capitalize()}"


# ---------------------------------------------------------------- rendering
def render(src_lines: list[str], target: Path, version: str, doc_title: str, guide: bool) -> None:
    from reportlab.lib.colors import HexColor
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        KeepTogether,
        ListFlowable,
        ListItem,
        PageBreak,
        Paragraph,
        Preformatted,
        SimpleDocTemplate,
        Spacer,
    )

    navy, blue, grey = HexColor("#1F3B63"), HexColor("#2B5FA8"), HexColor("#666666")
    body = ParagraphStyle("body", fontName="Helvetica", fontSize=9.5, leading=13.5, spaceAfter=4)
    st = {
        "kicker": ParagraphStyle("kicker", parent=body, alignment=TA_CENTER, textColor=blue, fontSize=11),
        "title": ParagraphStyle("title", parent=body, alignment=TA_CENTER, fontName="Helvetica-Bold",
                                fontSize=22, leading=26, textColor=navy, spaceAfter=10),
        "chapter": ParagraphStyle("chapter", parent=body, fontName="Helvetica-Bold", fontSize=15, leading=19,
                                  textColor=navy, spaceBefore=6, spaceAfter=8),
        "heading": ParagraphStyle("heading", parent=body, fontName="Helvetica-Bold", fontSize=11, leading=15,
                                  textColor=blue, spaceBefore=8, spaceAfter=4),
        "note": ParagraphStyle("note", parent=body, backColor=HexColor("#F2F5FA"), borderColor=HexColor("#C9D6EA"),
                               borderWidth=0.6, borderPadding=6, spaceBefore=4, spaceAfter=10),
        "code": ParagraphStyle("code", fontName="Courier", fontSize=8.8, leading=11.5, leftIndent=10,
                               backColor=HexColor("#F4F4F4"), borderPadding=5, spaceBefore=2, spaceAfter=8),
        "toc": ParagraphStyle("toc", parent=body, alignment=TA_CENTER, fontSize=12, leading=24),
    }
    footer = f"NetCommander {version} - what it does and how to install it"

    def on_page(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(grey)
        canvas.drawString(18 * mm, 10 * mm, footer)
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    def p(text: str, style: ParagraphStyle) -> Paragraph:
        return Paragraph(escape(text), style)

    story: list = []
    parsed = blocks(src_lines)
    if guide:
        chapters = [t for k, t in parsed if k == "chapter"]
        story += [Spacer(1, 40 * mm), p("NetCommander", st["title"]), p(f"Version {version}", st["kicker"]),
                  Spacer(1, 6 * mm), p("What it does and how to install it on Windows and Linux", st["kicker"]),
                  Spacer(1, 14 * mm)]
        story += [p(_chapter_name(c), st["toc"]) for c in chapters]
    else:
        story += [p(f"NetCommander {version}", st["kicker"]), p(doc_title, st["title"])]

    for kind, payload in parsed:
        if kind == "title":
            continue
        if kind == "chapter":
            story += [PageBreak(), p(_chapter_name(str(payload)), st["chapter"])]
        elif kind == "heading":
            story.append(p(str(payload), st["heading"]))
        elif kind == "para":
            story.append(p(str(payload), body))
        elif kind == "note":
            story.append(Paragraph("<b>Note.</b> " + escape(str(payload)), st["note"]))
        elif kind in ("bullets", "steps"):
            items = [ListItem(p(t, body), leftIndent=14) for t in payload]  # type: ignore[union-attr]
            story.append(ListFlowable(items, bulletType="bullet" if kind == "bullets" else "1",
                                      start="•" if kind == "bullets" else None, leftIndent=14,
                                      bulletFontSize=8 if kind == "steps" else 9, bulletColor=grey))
        elif kind == "code":
            story.append(KeepTogether([Preformatted("\n".join(payload), st["code"])]))  # type: ignore[arg-type]

    doc = SimpleDocTemplate(str(target), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=18 * mm,
                            title=f"NetCommander {version} {'guide' if guide else doc_title}", author="NetCommander")
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)


def main() -> int:
    try:
        import reportlab  # noqa: F401
    except ImportError:
        print("ReportLab is needed to build the PDFs: pip install reportlab", file=sys.stderr)
        return 2
    GUIDE.write_text(build_guide_text(), encoding="utf-8", newline="")
    for rel, name in GUIDE_ORDER:
        src = DOCS / rel
        lines = read(src)
        render(lines, src.with_suffix(".pdf"), version_of(lines), name, guide=False)
        print("wrote", src.with_suffix(".pdf").relative_to(DOCS.parent))
    lines = read(GUIDE)
    render(lines, GUIDE.with_suffix(".pdf"), version_of(lines), "Guide", guide=True)
    print("wrote", GUIDE.with_suffix(".pdf").relative_to(DOCS.parent))
    return 0


if __name__ == "__main__":
    sys.exit(main())
