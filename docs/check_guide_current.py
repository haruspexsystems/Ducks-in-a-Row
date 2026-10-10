"""Fail if the committed installation guide is stale against the markdown.

Run by continuous integration. Imports no ReportLab, so it needs nothing
installed and answers in milliseconds; the point is to catch a markdown edit
that was never rendered, not to rebuild the guide.

Exit codes: 0 current, 1 stale or never generated.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import guide_manifest as manifest  # noqa: E402

PDF = os.path.join(manifest.DOCS_DIR, "Ducks-in-a-Row-Installation-Guide.pdf")


def main():
    if not os.path.exists(PDF):
        print("::error::%s is missing. Run 'python docs/generate_guide.py'." % PDF)
        return 1

    recorded = manifest.read_digest()
    if recorded is None:
        print(
            "::error::docs/guide-inputs.sha256 is missing, so there is no record "
            "of what the committed guide was built from. Run "
            "'python docs/generate_guide.py' and commit the result."
        )
        return 1

    current = manifest.input_digest()
    if recorded != current:
        print(
            "::error::The installation guide is out of date. The markdown in "
            "docs/ has changed since it was last generated. Run "
            "'python docs/generate_guide.py' and commit both the PDF and "
            "docs/guide-inputs.sha256."
        )
        print("  recorded: %s" % recorded)
        print("  current:  %s" % current)
        return 1

    print("Installation guide is current (%s)." % current[:16])
    return 0


if __name__ == "__main__":
    sys.exit(main())
