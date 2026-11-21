"""Start the API + web dashboard against a SIMULATED homelab (fake device transports) for UI testing.

    python tests/e2e/demo_server.py <data-dir> <port>

Writes <data-dir>/demo-credentials.json with the admin e-mail, password and TOTP secret.
All devices shown are simulated; nothing on the network is contacted.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE.parent.parent)]

from homelab_fixtures import PW, build_platform, make_auth, populate  # noqa: E402

from netcommander.homelab.api.server import ApiServer  # noqa: E402


def main() -> None:
    root, port = Path(sys.argv[1]), int(sys.argv[2])
    root.mkdir(parents=True, exist_ok=True)
    p = build_platform(root)
    populate(p)
    from homelab_fixtures import ADMIN, OPER
    p.run_discovery(OPER, ["10.0.0.0/27"])
    p.monitor_cycle()
    for _ in range(3):
        p.poll_integration("pve")
    p.ipam.add_subnet("10.0.0.0/24", "lan", vlan=10, gateway="10.0.0.1")
    p.ipam.set_vlan(10, "LAN")
    p.save_backup_job(ADMIN, {"name": "offsite USB", "platform": "manual", "max_age_hours": 168})
    p.backup_cycle()
    p.run_script(OPER, "builtin-restart-service", [p.inventory.search("10.0.0.5")[0].id], {"service": "nginx"})
    auth, secrets = make_auth(root)
    (root / "demo-credentials.json").write_text(json.dumps({"email": "admin@example.com", "password": PW,
                                                            "totp": secrets["admin@example.com"]}))
    srv = ApiServer(p, auth, bind="127.0.0.1", port=port)
    print(f"ready {srv.url}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
