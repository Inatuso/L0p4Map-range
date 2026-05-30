"""Embedded-web-service fingerprinting + default-credential check.

Ported from the standalone Scanner_Web project. Given an IP, runs every
registered Service (iLO, InfoPrint, XPort, SATO, Zebra) and returns a compact
summary that the network scanner attaches to each host dict, so detected
services (and any default creds that work) show up on the topology graph.
"""

import os

from .services import ALL_SERVICES, SERVICES_BY_NAME  # noqa: F401  (re-export)

_DATA_DIR = None


def _data_dir():
    global _DATA_DIR
    if _DATA_DIR is None:
        from pathlib import Path
        _DATA_DIR = Path(os.path.dirname(__file__)) / "data"
    return _DATA_DIR


def scan_services(ip: str, check_auth: bool = False, only: list[str] | None = None) -> dict:
    """Run web-service fingerprinting against a single IP.

    Returns:
        {
            "services_detected": ["XPort", ...],
            "creds_found": [{"service": "XPort", "user": "root", "password": ""}],
            "errors": {"iLO": "no open web ports", ...},
        }
    """
    classes = ALL_SERVICES
    if only:
        wanted = {n.strip().lower() for n in only if n.strip()}
        classes = [c for c in ALL_SERVICES if c.name.lower() in wanted]

    data_dir = _data_dir()
    detected: list[str] = []
    creds: list[dict] = []
    errors: dict[str, str] = {}

    for cls in classes:
        try:
            r = cls(data_dir).scan(ip, check_auth=check_auth)
        except Exception as e:  # never let a service kill host enrichment
            errors[cls.name] = f"exception: {e}"
            continue
        if r.detected:
            detected.append(r.service)
            if r.winner:
                creds.append(
                    {"service": r.service, "user": r.winner[0], "password": r.winner[1] or ""}
                )
        if r.error:
            errors[r.service] = r.error

    return {"services_detected": detected, "creds_found": creds, "errors": errors}
