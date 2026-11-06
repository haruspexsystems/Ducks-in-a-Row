"""Which markdown files the installation guide is built from, and in what order.

Separate from generate_guide.py, and free of any ReportLab import, so the
chapter list and the version reader can be read without the rendering
toolchain installed.
"""

import os
import xml.etree.ElementTree as ET

DOCS_DIR = os.path.dirname(os.path.abspath(__file__))
IMAGES_DIR = os.path.join(DOCS_DIR, "images")
BUILD_PROPS_PATH = os.path.join(DOCS_DIR, "..", "Directory.Build.props")


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
    Chapter("intended-use.md", "Intended Use"),
    Chapter("system-requirements.md", "System Requirements"),
    Chapter("ad-and-ca-team-request.md", "What to Ask Your AD and CA Team"),
    Chapter("installation.md", "Installation"),
    # Right after Installation, because the choice is made in the installer and
    # a reader needs what it means before the Configuration reference.
    Chapter("monitor-mode.md", "Monitor Mode"),
    # Beside Monitor Mode, because the OT pattern it describes is a monitor
    # mode installation against a second issuing CA.
    Chapter("several-cas.md", "Several Certificate Authorities"),
    Chapter("configuration.md", "Configuration"),
    Chapter("adcs-setup.md", "ADCS Configuration"),
    Chapter("verifying.md", "Verifying Your Installation"),
    Chapter("acme-clients.md", "Connecting ACME Clients"),
    Chapter("kubernetes.md", "Kubernetes and OpenShift"),
    Chapter("external-account-binding.md", "External Account Binding"),
    Chapter("device-attestation.md", "Device Attestation"),
    Chapter("revocation.md", "Revocation"),
    Chapter("alerts.md", "Expiry Alerts"),
    Chapter("licence.md", "Licence and Paid Module"),
    Chapter("hardening.md", "Hardening"),
    Chapter("backup-and-restore.md", "Backup and Restore"),
    Chapter("troubleshooting.md", "Troubleshooting"),
    Chapter("uninstall.md", "Uninstalling"),
    Chapter("glossary.md", "Glossary"),
]


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
