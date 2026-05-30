# CLAUDE.md — project context & handoff

> Auto-loaded by Claude Code. This file is the handoff between machines/sessions:
> the work below was implemented and verified on a Windows box, then pushed here so
> it could be tested on a Linux (Kali) VM, which is the only place the live
> scanning and GUI can actually run.

## What this repo is

`L0p4Map-range` — an **extended build of [HaxL0p4/L0p4Map](https://github.com/HaxL0p4/L0p4Map)** (GPL-3.0).
The original is a local-only, ARP-based network mapper (Python 3.11 + PyQt6, Linux + root).
This build adds two things on top:

1. **Arbitrary-range cartography** — scan any IP / CIDR / range and get a topology
   map, **including routed ranges across routers** (original only saw the local L2 segment).
2. **Embedded-web-service fingerprinting + default-credential testing** — iLO /
   InfoPrint / XPort / SATO / Zebra, surfaced on the graph (ported from *Scanner_Web*).

License stays **GPL-3.0**. Original credit: **HaxL0p4**.

## Where the new code lives

| File | What was added |
|---|---|
| `core/scanner.py` | `discover_range()` (entry point), `expand_target()`, `_local_networks()`/`_is_local()` (local-vs-routed split), `_ping_host()` (ICMP+TCP-SYN sweep), `_traceroute()` (scapy, increasing TTL), `_blank_host()`. `_enrich_host()` + `scan_network()` gained `do_service_scan` / `service_auth`. New host-dict keys: `services_detected`, `creds_found`, `scan_mode` (`"arp"`/`"routed"`), `hops`. |
| `core/services/` | Embedded-service scanner ported from *Scanner_Web*: `base.py` (`Service` class + `ScanResult`), `ilo.py`, `infoprint.py`, `xport.py`, `sato.py`, `zebra.py`, `__init__.py` (registry `ALL_SERVICES`). |
| `core/data/*.creds.example.json` | Vendor-default creds. `base.py:_load_creds()` falls back to the `.example.json` when a real `*.creds.json` is absent — so it works out of the box. |
| `core/service_scan.py` | `scan_services(ip, check_auth, only)` — runs all services against one IP, returns `{services_detected, creds_found, errors}`. |
| `ui/app.py` | `RangeScanWorker`, `_blank_router_node()` (module-level), toolbar widgets (`range_input`, `svc_check`, `max_hosts_input`, `timeout_input`, `dedup_check`), `_start_scan()` branches on the range field, and `_build_topology_routed()` (traceroute → hierarchy). `_build_topology()` dispatches to it when any host has `hops`. |
| `ui/assets/graph.html` | Tooltip `SERVICES` / `⚠ DEFAULT CREDS` rows; node highlight — cyan accent when a service is detected, red node + `⚠ default creds` label when default creds work. |

## How the routed map is built

ARP can't cross a router, so routed discovery uses **ICMP + TCP-SYN ping-sweep** to
find live hosts, then a **traceroute per host**. `_build_topology_routed()` then:
- makes each distinct hop a synthetic `router` node (added to `devices` + `intermediates`),
- chains routers as `backbone` edges up to the first hop (the `gateway` → `internet` `uplink`),
- attaches each host to its **last-hop router** as a `client` edge,
- draws one `/24` **subnet box** per discovered segment,
- hosts with no usable path (local/ARP or untraceable) attach directly to the gateway.

Output dict shape is unchanged (`devices/gateway/edges/intermediates/subnets`), so
`graph.html` renders it without modification.

> Routed hosts have **no MAC/vendor** — ARP can't reach across a router. That's expected, not a bug.

## Status

**Done, committed, pushed.** Verified on Windows (no root/GUI there):
- `py_compile` of all changed files; `expand_target`, `_is_local`, `_blank_host` keys;
  service registry + creds example-fallback (all 5 load);
- full `ui/app.py` import under PyQt6; real `_build_topology_routed()` against sample
  data incl. the untraceable-host edge case; `RangeScanWorker` signature.

**NOT yet tested — needs this Linux VM (root + raw sockets):**
- live ARP / ICMP / TCP-SYN / traceroute scanning,
- the PyQt6 GUI actually rendering the graph.

## Test checklist (run on Kali, as root)

```bash
sudo python3 __main__.py        # or: sudo ./L0p4Map.sh
```

1. **Regression** — leave the toolbar range field *empty*, `[ SCAN ]` → original local ARP map still works.
2. **Local range** — type your LAN CIDR (e.g. `192.168.1.0/24`) → same map via the new path.
3. **Routed range** — a CIDR behind a router → hosts grouped under last-hop router, backbone links to gateway, `/24` boxes. Tune `max-hosts` / `timeout` / `dedup`.
4. **Services** — tick `svc` → detected devices cyan; default-cred hits turn **red** with `⚠ default creds` + tooltip.

If the routed hierarchy or node styling looks off against real traceroute output,
capture the host/edge data (or a screenshot) — `_build_topology_routed()` and the
`graph.html` styling are the spots to adjust.

## Conventions / gotchas

- Match the surrounding code style; service classes are pluggable (subclass `Service`, register in `services/__init__.py`).
- **Never commit real creds** — `*.creds.json` is git-ignored; only `*.creds.example.json` ships.
- No new runtime deps beyond `requirements.txt` (`scapy`, `requests`, `urllib3`, `psutil`, `PyQt6`, `PyQt6-WebEngine`). Also needs system `nmap`.
- Don't write IP octets with leading zeros (e.g. `10.0.0.05`) — Python's `ipaddress` rejects them (CVE-2021-29921).
