import csv as _csv
import ipaddress
import os
import socket
import struct
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil
from scapy.all import ARP, ICMP, TCP, UDP, Ether, conf, sniff, sr1, srp
from scapy.all import IP as ScapyIP

_vendor_cache: dict[str, str] = {}
_oui_db: dict[str, str] = {}

TOPOLOGY_PROBE_PORTS = [80, 443, 22, 23, 53, 8080, 8443, 179, 161, 8291, 2601, 4786]

NETWORK_DEVICE_VENDORS = [
    "cisco",
    "mikrotik",
    "ubiquiti",
    "juniper",
    "fortinet",
    "palo alto",
    "aruba",
    "ruckus",
    "meraki",
    "extreme",
    "brocade",
    "h3c",
    "huawei",
    "zyxel",
    "dlink",
    "tp-link",
    "netgear",
    "linksys",
    "tenda",
    "openwrt",
    "dd-wrt",
    "edgecore",
    "cambium",
    "aerohive",
]

PC_VENDORS = [
    "intel",
    "dell",
    "lenovo",
    "hp",
    "hewlett",
    "acer",
    "gigabyte",
    "msi",
    "asrock",
    "asus",
    "supermicro",
    "fujitsu",
]

MOBILE_VENDORS = [
    "samsung",
    "xiaomi",
    "oneplus",
    "oppo",
    "realme",
    "motorola",
    "lg electronics",
    "sony mobile",
    "zte",
]


def capture_traffic(iface: str, duration: int = 15) -> list[dict]:
    connections = defaultdict(
        lambda: {"packets": 0, "bytes": 0, "proto": "OTHER", "port": "-"}
    )

    def process(pkt):
        if ScapyIP not in pkt:
            return
        src = pkt[ScapyIP].src
        dst = pkt[ScapyIP].dst
        size = len(pkt)
        proto = "OTHER"
        port = "-"

        if TCP in pkt:
            proto = "TCP"
            port = str(pkt[TCP].dport)
        elif UDP in pkt:
            proto = "UDP"
            port = str(pkt[UDP].dport)

        key = tuple(sorted([src, dst]))
        connections[key]["packets"] += 1
        connections[key]["bytes"] += size
        connections[key]["proto"] = proto
        connections[key]["port"] = port

    sniff(iface=iface, prn=process, timeout=duration, store=False, filter="ip")

    edges = []
    for (src, dst), data in connections.items():
        edges.append(
            {
                "src": src,
                "dst": dst,
                "packets": data["packets"],
                "bytes": data["bytes"],
                "proto": data["proto"],
                "port": data["port"],
                "weight": min(data["packets"] / 10, 10),
            }
        )

    return sorted(edges, key=lambda e: e["packets"], reverse=True)


def _load_oui_db():
    global _oui_db
    if _oui_db:
        return
    db_path = os.path.join(os.path.dirname(__file__), "oui.csv")
    if not os.path.exists(db_path):
        return
    with open(db_path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = _csv.DictReader(f)
        for row in reader:
            oui = row.get("Assignment", "").upper().strip()
            name = row.get("Organization Name", "").strip()
            if oui and name:
                _oui_db[oui] = name


def get_network_interfaces():
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for iface, addr_list in addrs.items():
        if iface not in stats or not stats[iface].isup:
            continue
        ip = None
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ip = addr.address
        if not ip or ip.startswith("127."):
            continue
        interfaces.append({"name": iface, "ip": ip})
    return interfaces


def check_root():
    if os.getuid() != 0:
        raise PermissionError("Execute the program with SUDO!")


def get_local_subnet(iface_name=None) -> str:
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    if iface_name:
        if iface_name not in interfaces:
            raise RuntimeError(f"Interface '{iface_name}' not found.")
        if not stats[iface_name].isup:
            raise RuntimeError(f"Interface '{iface_name}' not active.")
        for addr in interfaces[iface_name]:
            if addr.family == socket.AF_INET:
                return str(
                    ipaddress.IPv4Network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    )
                )
        raise RuntimeError(f"No IPv4 address on '{iface_name}'.")
    for nome, indirizzi in interfaces.items():
        if not stats[nome].isup:
            continue
        for addr in indirizzi:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if ip.startswith("127."):
                    continue
                return str(ipaddress.IPv4Network(f"{ip}/{addr.netmask}", strict=False))
    raise RuntimeError("No active interface found.")


def get_default_gateway() -> str | None:
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) < 3:
                    continue
                if fields[1] == "00000000":
                    gw_hex = fields[2]
                    gw_int = int(gw_hex, 16)
                    gw = socket.inet_ntoa(struct.pack("<I", gw_int))
                    if gw and not gw.startswith("0."):
                        return gw
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for token in out.split():
            if token not in ("default", "via", "dev", "proto", "metric", "src"):
                try:
                    ipaddress.ip_address(token)
                    return token
                except ValueError:
                    pass
    except Exception:
        pass
    return None


def get_vendor(mac: str) -> str:
    global _vendor_cache
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    if oui in _vendor_cache:
        return _vendor_cache[oui]
    _load_oui_db()
    if oui in _oui_db:
        vendor = _oui_db[oui]
        _vendor_cache[oui] = vendor
        return vendor
    _vendor_cache[oui] = "Unknown"
    return "Unknown"


def _dns_hostname(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except socket.herror:
        pass
    return None


def _netbios_hostname(ip: str) -> str | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        query = (
            b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            b"\x00\x00!\x00\x01"
        )
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 72:
            name = data[57:72].decode("ascii", errors="ignore").strip()
            name = "".join(c for c in name if c.isprintable()).strip()
            if name:
                return name
    except Exception:
        pass
    return None


def _mdns_hostname(ip: str) -> str | None:
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1)
        name = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old_timeout)
        if name and name != ip:
            return name
    except Exception:
        pass
    return None


def resolve_hostname(ip: str) -> str:
    name = _dns_hostname(ip)
    if name:
        return name
    name = _netbios_hostname(ip)
    if name:
        return name
    name = _mdns_hostname(ip)
    if name:
        return name
    return ip


def _probe_ttl(ip: str) -> int | None:
    try:
        pkt = ScapyIP(dst=ip, ttl=64) / ICMP()
        reply = sr1(pkt, timeout=1, verbose=False)
        if reply and ICMP in reply:
            return reply[ScapyIP].ttl
    except Exception:
        pass
    return None


def _ttl_to_os_hint(ttl: int | None) -> str:
    if ttl is None:
        return "unknown"
    if ttl <= 64:
        return "linux/macos"
    if ttl <= 128:
        return "windows"
    return "network_device"


def _probe_open_ports(ip: str, ports: list[int], timeout: float = 0.5) -> list[int]:
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
    return open_ports


def _infer_role(
    ip: str,
    vendor: str,
    hostname: str,
    ttl: int | None,
    open_ports: list[int],
    is_gateway: bool,
) -> str:
    v = vendor.lower()
    h = hostname.lower()
    os_hint = _ttl_to_os_hint(ttl)

    if is_gateway:
        return "gateway"

    if h in ("router", "gateway", "_gateway", "default-gateway"):
        return "gateway"

    if any(
        k in v
        for k in [
            "cisco",
            "mikrotik",
            "ubiquiti",
            "juniper",
            "fortinet",
            "edgecore",
            "brocade",
            "h3c",
        ]
    ):
        if any(p in open_ports for p in [22, 23, 179, 8291, 2601, 4786]):
            return "router"
        return "router"

    if any(
        k in v
        for k in [
            "tp-link",
            "netgear",
            "dlink",
            "linksys",
            "tenda",
            "zyxel",
            "aruba",
            "ruckus",
            "meraki",
            "cambium",
            "aerohive",
            "ubiquiti",
        ]
    ):
        if any(p in open_ports for p in [80, 443, 8080, 8443]):
            return "ap"
        return "ap"

    if any(
        k in h
        for k in [
            "router",
            "gw",
            "gateway",
            "firewall",
            "pfsense",
            "opnsense",
            "vyos",
            "mikrotik",
        ]
    ):
        return "router"

    if any(
        k in h
        for k in [
            "ap",
            "wifi",
            "wlan",
            "wireless",
            "access-point",
            "access_point",
            "hotspot",
            "ssid",
        ]
    ):
        return "ap"

    if any(k in h for k in ["switch", "sw-", "sw_", "core-sw", "dist-sw"]):
        return "switch"

    if any(k in v for k in ["raspberry"]) or "raspberry" in h:
        return "raspberry"

    if any(k in v for k in ["vmware", "virtualbox", "proxmox", "parallels"]):
        return "vm"

    if any(k in v for k in ["apple"]) or any(
        k in h for k in ["iphone", "ipad", "macbook", "imac", "apple"]
    ):
        return "apple"

    if any(
        k in v
        for k in [
            "samsung",
            "xiaomi",
            "oneplus",
            "oppo",
            "realme",
            "motorola",
            "lg electronics",
            "sony mobile",
            "zte",
        ]
    ):
        return "mobile"
    if any(k in h for k in ["android", "iphone", "phone", "mobile"]):
        return "mobile"

    if os_hint == "network_device":
        if any(p in open_ports for p in [80, 443, 8080]):
            return "ap"
        return "router"

    if any(k in v for k in PC_VENDORS):
        return "pc"
    if any(
        k in h
        for k in [
            "desktop",
            "pc-",
            "-pc",
            "workstation",
            "laptop",
            "linux",
            "windows",
            "ubuntu",
            "debian",
            "fedora",
        ]
    ):
        return "pc"

    if os_hint == "linux/macos" and 22 in open_ports:
        return "pc"

    if os_hint == "windows" and any(p in open_ports for p in [135, 139, 445]):
        return "pc"

    return "unknown"


def _probe_snmp_sysdescr(ip: str) -> str | None:
    try:
        community = b"public"
        oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
        request = (
            b"\x30\x29"
            b"\x02\x01\x00"
            b"\x04" + bytes([len(community)]) + community + b"\xa0\x1c"
            b"\x02\x04\x00\x00\x00\x01"
            b"\x02\x01\x00"
            b"\x02\x01\x00"
            b"\x30\x0e"
            b"\x30\x0c"
            b"\x06\x08" + oid + b"\x05\x00"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(request, (ip, 161))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if data and len(data) > 30:
            payload = data[30:]
            try:
                return payload.decode("ascii", errors="ignore").strip()
            except Exception:
                pass
    except Exception:
        pass
    return None


def _enrich_host(
    host: dict,
    known_gateway_ip: str | None,
    do_service_scan: bool = False,
    service_auth: bool = False,
) -> dict:
    ip = host["ip"]
    host["hostname"] = resolve_hostname(ip)
    host["vendor"] = get_vendor(host["mac"])

    ttl = _probe_ttl(ip)
    host["ttl"] = ttl
    host["os_hint"] = _ttl_to_os_hint(ttl)

    open_ports = _probe_open_ports(ip, TOPOLOGY_PROBE_PORTS, timeout=0.4)
    host["open_ports"] = open_ports

    snmp_desc = None
    if 161 in open_ports or ttl is None or (ttl is not None and ttl > 128):
        snmp_desc = _probe_snmp_sysdescr(ip)
    host["snmp_desc"] = snmp_desc or ""

    vendor_for_role = host["vendor"]
    if snmp_desc:
        vendor_for_role = snmp_desc + " " + vendor_for_role

    is_gw = ip == known_gateway_ip
    host["role"] = _infer_role(
        ip,
        vendor_for_role,
        host["hostname"],
        ttl,
        open_ports,
        is_gw,
    )

    # Embedded-web-service fingerprinting (iLO/InfoPrint/XPort/SATO/Zebra).
    # Opt-in: only worth it when a web port is open. Failures stay contained.
    if do_service_scan and any(p in open_ports for p in (80, 443, 8080, 8443)):
        try:
            from .service_scan import scan_services

            svc = scan_services(ip, check_auth=service_auth)
            host["services_detected"] = svc["services_detected"]
            host["creds_found"] = svc["creds_found"]
        except Exception:
            host.setdefault("services_detected", [])
            host.setdefault("creds_found", [])

    return host


def scan_network(
    subnet: str,
    do_service_scan: bool = False,
    service_auth: bool = False,
) -> list[dict]:
    conf.verb = 0

    known_gateway = get_default_gateway()

    pacchetto = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    risposte, _ = srp(pacchetto, timeout=2, retry=2, inter=0.01, verbose=False)

    seen_macs: dict[str, str] = {}
    for _, risposta in risposte:
        mac = risposta[Ether].src
        ip = risposta[ARP].psrc
        if mac not in seen_macs:
            seen_macs[mac] = ip

    if known_gateway and known_gateway not in seen_macs.values():
        gw_mac = _arp_resolve_mac(known_gateway, subnet)
        if gw_mac:
            seen_macs[gw_mac] = known_gateway

    hosts = []
    for mac, ip in seen_macs.items():
        hosts.append(
            {
                "ip": ip,
                "mac": mac,
                "hostname": ip,
                "vendor": "...",
                "ttl": None,
                "os_hint": "unknown",
                "open_ports": [],
                "role": "unknown",
                "snmp_desc": "",
                "services_detected": [],
                "creds_found": [],
            }
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {
            executor.submit(
                _enrich_host, host, known_gateway, do_service_scan, service_auth
            ): host
            for host in hosts
        }
        results = []
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                results.append(futures[future])

    results.sort(key=lambda h: [int(x) for x in h["ip"].split(".")])
    return results


def _arp_resolve_mac(ip: str, subnet: str) -> str | None:
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=1, retry=1, verbose=False)
        for _, reply in ans:
            return reply[Ether].src
    except Exception:
        pass


# --------------------------------------------------------------------------
# Arbitrary-range discovery (local ARP + routed ping-sweep / traceroute)
# --------------------------------------------------------------------------

def expand_target(spec: str) -> list[str]:
    """Expand 'a.b.c.d' | 'a.b.c.d/N' | 'a.b.c.d-e' | 'a.b.c.d-a.b.c.e' into IPs.

    Ported from the Scanner_Web targets.py helper.
    """
    spec = spec.strip()
    if not spec:
        return []

    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
            return hosts or [str(net.network_address)]
        except ValueError:
            return []

    if "-" in spec:
        try:
            start_str, end_str = (s.strip() for s in spec.split("-", 1))
            start = ipaddress.IPv4Address(start_str)
            if "." not in end_str:
                base = ".".join(start_str.split(".")[:-1])
                end_str = f"{base}.{end_str}"
            end = ipaddress.IPv4Address(end_str)
            if int(end) < int(start):
                start, end = end, start
            return [str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1)]
        except ValueError:
            return []

    try:
        ipaddress.IPv4Address(spec)
        return [spec]
    except ValueError:
        return []


def _local_networks() -> list:
    """Every IPv4 network this host is directly attached to (for local/routed split)."""
    nets = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name, addr_list in addrs.items():
        if name not in stats or not stats[name].isup:
            continue
        for addr in addr_list:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                try:
                    nets.append(
                        ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                    )
                except Exception:
                    pass
    return nets


def _is_local(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def _blank_host(ip: str, mac: str, scan_mode: str = "arp") -> dict:
    return {
        "ip": ip,
        "mac": mac,
        "hostname": ip,
        "vendor": "...",
        "ttl": None,
        "os_hint": "unknown",
        "open_ports": [],
        "role": "unknown",
        "snmp_desc": "",
        "services_detected": [],
        "creds_found": [],
        "scan_mode": scan_mode,   # "arp" (local) or "routed"
        "hops": [],               # L3 path (routed hosts only)
    }


def _ping_host(ip: str, tcp_ports=(80, 443, 22, 3389), timeout: float = 1.0) -> bool:
    """Liveness check for a routed host: ICMP echo, then TCP-SYN fallback."""
    try:
        if sr1(ScapyIP(dst=ip) / ICMP(), timeout=timeout, verbose=False) is not None:
            return True
    except Exception:
        pass
    for port in tcp_ports:
        try:
            reply = sr1(
                ScapyIP(dst=ip) / TCP(dport=port, flags="S"),
                timeout=timeout,
                verbose=False,
            )
            if reply is not None and reply.haslayer(TCP) and (reply[TCP].flags & 0x12) == 0x12:
                return True
        except Exception:
            pass
    return False


def _traceroute(ip: str, max_hops: int = 20, timeout: float = 1.0) -> list:
    """Return the ordered list of router IPs on the L3 path to `ip` (unknown hops dropped)."""
    hops = []
    for ttl in range(1, max_hops + 1):
        try:
            reply = sr1(ScapyIP(dst=ip, ttl=ttl) / ICMP(), timeout=timeout, verbose=False)
        except Exception:
            reply = None
        if reply is None:
            continue  # silent hop — skip but keep climbing TTL
        src = reply[ScapyIP].src
        hops.append(src)
        # Reached the target (echo-reply) or address matches — stop.
        if (reply.haslayer(ICMP) and reply[ICMP].type == 0) or src == ip:
            break
    return hops


def discover_range(
    target,
    do_service_scan: bool = False,
    service_auth: bool = False,
    max_routed_hosts: int = 512,
    probe_timeout: float = 1.0,
    dedup_per_subnet: bool = False,
) -> list[dict]:
    """Discover hosts across an arbitrary target (IP/CIDR/range), local or routed.

    Local targets use ARP (keeps MAC/vendor); routed targets use an ICMP/TCP
    ping-sweep plus traceroute so the topology can group hosts under their
    last-hop router. `target` may be a string or a list of specs.

    Tuning:
        max_routed_hosts  cap on routed addresses probed (protects huge ranges)
        probe_timeout     per-packet timeout for ping-sweep and traceroute (s)
        dedup_per_subnet  traceroute only one host per /24 and reuse the router
                          path for its neighbours (much faster on big ranges)
    """
    conf.verb = 0
    known_gateway = get_default_gateway()
    local_nets = _local_networks()

    specs = target.split() if isinstance(target, str) else list(target)
    ips: list[str] = []
    seen = set()
    for spec in specs:
        for ip in expand_target(spec):
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)

    local_ips = [ip for ip in ips if _is_local(ip, local_nets)]
    local_set = set(local_ips)
    routed_ips = [ip for ip in ips if ip not in local_set]

    hosts: list[dict] = []

    # --- local segment: ARP sweep over the requested addresses ---
    if local_ips:
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=local_ips),
                timeout=2,
                retry=1,
                inter=0.01,
                verbose=False,
            )
            seen_macs: dict[str, str] = {}
            for _, reply in ans:
                seen_macs.setdefault(reply[Ether].src, reply[ARP].psrc)
            for mac, ip in seen_macs.items():
                hosts.append(_blank_host(ip, mac, scan_mode="arp"))
        except Exception:
            pass

    # --- routed segments: ping-sweep to find live hosts, then traceroute ---
    if routed_ips:
        targets = routed_ips[:max_routed_hosts]
        live: list[str] = []
        with ThreadPoolExecutor(max_workers=64) as pool:
            futs = {pool.submit(_ping_host, ip, timeout=probe_timeout): ip for ip in targets}
            for fut in as_completed(futs):
                try:
                    if fut.result():
                        live.append(futs[fut])
                except Exception:
                    pass

        # Which hosts actually get a traceroute. With dedup, one per /24.
        if dedup_per_subnet:
            trace_ips = []
            seen_nets = set()
            for ip in live:
                net = ".".join(ip.split(".")[:3])
                if net not in seen_nets:
                    seen_nets.add(net)
                    trace_ips.append(ip)
        else:
            trace_ips = live

        paths: dict[str, list] = {}
        with ThreadPoolExecutor(max_workers=32) as pool:
            futs = {pool.submit(_traceroute, ip, timeout=probe_timeout): ip for ip in trace_ips}
            for fut in as_completed(futs):
                ip = futs[fut]
                try:
                    paths[ip] = fut.result()
                except Exception:
                    paths[ip] = []

        # Reuse the representative router path for neighbours in the same /24.
        net_routers: dict[str, list] = {}
        for ip, path in paths.items():
            net = ".".join(ip.split(".")[:3])
            net_routers[net] = [hp for hp in path if hp and hp != ip]

        for ip in live:
            host = _blank_host(ip, "", scan_mode="routed")
            if ip in paths:
                host["hops"] = paths[ip]
            else:
                net = ".".join(ip.split(".")[:3])
                host["hops"] = net_routers.get(net, []) + [ip]
            hosts.append(host)

    # --- enrich everything (hostname, ttl, ports, snmp, optional services) ---
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {
            executor.submit(
                _enrich_host, host, known_gateway, do_service_scan, service_auth
            ): host
            for host in hosts
        }
        results = []
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                results.append(futures[future])

    results.sort(key=lambda h: [int(x) for x in h["ip"].split(".")])
    return results
