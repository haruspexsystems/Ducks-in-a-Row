"""Which markdown files the installation guide is built from, and in what order.

Separate from generate_guide.py, and free of any ReportLab import, so the
staleness check can read the manifest without needing the rendering toolchain
installed. That is what lets continuous integration answer "is the committed PDF
current" without building it.
"""

import hashlib
import io
import os
import xml.etree.ElementTree as ET

DOCS_DIR = os.path.dirname(os.path.abspath(__file__))
IMAGES_DIR = os.path.join(DOCS_DIR, "images")
BUILD_PROPS_PATH = os.path.join(DOCS_DIR, "..", "Directory.Build.props")
DIGEST_PATH = os.path.join(DOCS_DIR, "guide-inputs.sha256")


class Chapter:
    """One chapter of the guide, and the markdown file it is built from.

    Chapter numbers come from position in CHAPTERS, never from a field, so
    reordering the guide cannot leave a stale number behind. col_widths is the
    escape hatch for the few tables the auto sizer reads wrong; markdown carries
    no column widths at all.
    """

    def __init__(self, filename, title, col_widths=None):
        self.filename = filename
        self.title = title
        self.col_widths = col_widths or {}


CHAPTERS = [
    # Order is the reader's order, and the chapter number is the position in
    # this list. Getting started, then setting up, then the things you
    # administer once it runs, then what to do when it misbehaves.
    Chapter("quickstart.md", "Quick Start"),
    Chapter("system-requirements.md", "System Requirements"),
    Chapter("installation.md", "Installation"),
    Chapter("configuration.md", "Configuration"),
    Chapter("adcs-setup.md", "ADCS Configuration"),
    Chapter("verifying.md", "Verifying Your Installation"),
    Chapter("acme-clients.md", "Connecting ACME Clients"),
    Chapter("kubernetes.md", "Kubernetes and OpenShift"),
    Chapter("external-account-binding.md", "External Account Binding"),
    Chapter("device-attestation.md", "Device Attestation"),
    Chapter("revocation.md", "Revocation"),
    Chapter("alerts.md", "Expiry Alerts"),
    Chapter("hardening.md", "Hardening"),
    Chapter("backup-and-restore.md", "Backup and Restore"),
    Chapter("troubleshooting.md", "Troubleshooting"),
    Chapter("uninstall.md", "Uninstalling"),
    Chapter("glossary.md", "Glossary"),
]

# The renderer and the parser are inputs too: a change to either can change the
# rendered guide without any markdown moving.
SOURCE_FILES = ["generate_guide.py", "guide_markdown.py", "guide_manifest.py"]


def read_version(props_path=BUILD_PROPS_PATH):
    """Return the product version, matching what the running app reports.

    Mirrors build.ps1 and release/Publish-Release.ps1: take the first non empty
    value, because the file carries two PropertyGroups and only the first holds
    the version (the second is conditional on ContinuousIntegrationBuild).

    VersionSuffix is optional by design. Directory.Build.props says to drop it
    entirely for a non prerelease version like 1.0.0, so both an absent element
    and an empty one must yield a bare "1.0.0". Testing the text for content is
    what buys that; reading el.text alone would stamp "1.0.0-None" on every
    page.

    The tag comparison tolerates a namespace because MSBuild files are commonly
    written with one. This one has none today, and a future edit that adds it
    would otherwise return None silently and put the wrong version in print.
    """
    root = ET.parse(props_path).getroot()

    def first(tag):
        for element in root.iter():
            if element.tag == tag or element.tag.endswith("}" + tag):
                if element.text and element.text.strip():
                    return element.text.strip()
        return None

    prefix = first("VersionPrefix")
    if not prefix:
        # Never fall back to a literal. A silent default is exactly the failure
        # this function exists to remove.
        raise SystemExit("VersionPrefix not found in %s" % props_path)

    suffix = first("VersionSuffix")
    return "%s-%s" % (prefix, suffix) if suffix else prefix


def input_digest():
    """Digest every input the guide is rendered from.

    This is what the staleness gate compares, rather than the bytes of the PDF
    itself. Byte equality would be a stronger claim than the gate needs and one
    the toolchain does not support: ReportLab's output varies between its own
    versions and between Python versions, so a PDF regenerated on a different
    machine differs even though its content is identical. Digesting the inputs
    answers the question that actually matters, which is whether the committed
    PDF was built from the markdown currently in the tree.
    """
    digest = hashlib.sha256()

    # The version is stamped on the cover and every footer, so a bump without a
    # regenerate leaves the guide stale even though no markdown moved.
    digest.update(read_version().encode("utf-8"))

    for name in SOURCE_FILES:
        digest.update(name.encode("utf-8"))
        digest.update(_text_bytes(os.path.join(DOCS_DIR, name)))

    for chapter in CHAPTERS:
        digest.update(chapter.filename.encode("utf-8"))
        digest.update(chapter.title.encode("utf-8"))
        digest.update(_text_bytes(os.path.join(DOCS_DIR, chapter.filename)))

    # Images are inputs as well, and a recaptured screenshot is exactly the kind
    # of change that would otherwise slip through.
    for name in sorted(os.listdir(IMAGES_DIR)):
        if not name.lower().endswith(".png"):
            continue
        digest.update(name.encode("utf-8"))
        digest.update(_raw_bytes(os.path.join(IMAGES_DIR, name)))

    return digest.hexdigest()


def _text_bytes(path):
    """Read a text file with newlines normalised, so a checkout setting cannot
    alter the digest. Everything hashed here is committed with LF, but git is
    configured with `* text=auto` and a future attribute change should not
    start failing the gate on every machine at once."""
    with io.open(path, "rb") as handle:
        return handle.read().replace(b"\r\n", b"\n")


def write_digest():
    with io.open(DIGEST_PATH, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(input_digest() + "\n")


def _raw_bytes(path):
    """Read a binary file exactly as it is. An image is an input to the
    guide, so it belongs in the digest, but it is not text and must not be
    newline normalised on the way in."""
    with io.open(path, "rb") as handle:
        return handle.read()


def read_digest():
    if not os.path.exists(DIGEST_PATH):
        return None
    with io.open(DIGEST_PATH, encoding="utf-8") as handle:
        return handle.read().strip()
