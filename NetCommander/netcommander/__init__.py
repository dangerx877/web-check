"""Uptime Funk (formerly NetCommander Pro) - homelab & infrastructure management: multi-vendor network
automation plus servers, VMs, containers, NAS, monitoring, automation and backups, with an encrypted vault,
MFA login and role-based access.

The import package keeps the name ``netcommander`` so existing installs, data folders, environment variables
and scripts keep working; only the product name changed.

Importing this package never pulls in the GUI stack; only ``netcommander.ui``
(and :func:`netcommander.__main__.main` when it starts the window) does.
"""

__version__ = "4.0.0"
BRAND = "Uptime Funk"
TAGLINE = "Don't believe me, just watch."
