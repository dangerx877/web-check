"""Uptime Funk homelab & infrastructure platform (4.0).

Headless, GUI-free modules that extend the original network tooling to servers, hypervisors,
containers, storage, monitoring, automation and backups. Layout:

* :mod:`.core`            shared infrastructure (database, events, tasks, secrets, transports, authz)
* :mod:`.models` / :mod:`.inventory`   the unified asset inventory
* :mod:`.discovery`, :mod:`.servers`, :mod:`.virtualization`, :mod:`.containers`, :mod:`.storage`,
  :mod:`.netmgmt`, :mod:`.monitoring`, :mod:`.automation`, :mod:`.backups`   domain modules
* :mod:`.platform`        wires the modules together (like :class:`netcommander.services.Services`)
* :mod:`.api`             the management HTTP API and the web dashboard

Every module talks to devices through a small injectable seam (HTTP transport, command runner),
so the whole platform is testable without hardware.
"""
