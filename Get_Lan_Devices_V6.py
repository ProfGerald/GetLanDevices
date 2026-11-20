# -*- coding: utf-8 -*-
"""
Created on Fri Nov 20 00:00:34 2026

@author: ProfGerald
"""

# -*- coding: utf-8 -*-
"""
Created on Thu Nov 19 13:03:01 2026

@author: ProfGerald
"""

import concurrent.futures
import csv
import ipaddress
import os
import re
import openpyxl
import socket
import pandas as pd
import subprocess
import urllib.request
from datetime import datetime

OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"
SCRIPT_DIR = os.path.dirname(os.path.abspath(os.getcwd()))
OUI_CACHE_FILE = os.path.join(SCRIPT_DIR, "oui_cache.csv")

# Built-in fallback prefixes if offline on first run
FALLBACK_OUIS = {
    "000393": "Apple, Inc.",
    "A45E60": "Apple, Inc.",
    "F01898": "Apple, Inc.",
    "286C07": "Xiaomi Communications Co Ltd",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Trading Ltd",
    "E45F01": "Raspberry Pi Trading Ltd",
    "240AC4": "Espressif Inc.",
    "30AEA4": "Espressif Inc.",
    "7C9EBD": "Espressif Inc.",
    "001BA9": "Brother Industries, LTD.",
    "30055C": "Brother Industries, LTD.",
    "F43909": "HP Inc.",
    "9C73B1": "HP Inc.",
    "000048": "Seiko Epson Corporation",
    "1866DA": "Dell Inc.",
    "F8BC12": "Dell Inc.",
    "005056": "VMware, Inc.",
    "080027": "Oracle Corporation (VirtualBox)",
    "24A43C": "Ubiquiti Inc.",
    "788A20": "Ubiquiti Inc.",
    "F09FC2": "Ubiquiti Inc.",
    "B4FBE4": "Ubiquiti Inc.",
    "C025E9": "TP-Link Corporation Limited",
    "50C7BF": "TP-Link Corporation Limited",
    "001132": "Synology Incorporated",
    "44650D": "Amazon Technologies Inc.",
    "F0F0A4": "Amazon Technologies Inc.",
}


def load_oui_database():
    """Load OUI -> Manufacturer map from local cache, or download from IEEE."""
    oui_map = dict(FALLBACK_OUIS)

    if not os.path.exists(OUI_CACHE_FILE):
        print("Downloading IEEE OUI manufacturer database (one-time setup)...")
        try:
            req = urllib.request.Request(
                OUI_CSV_URL,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                lines = response.read().decode("utf-8", errors="ignore").splitlines()

            reader = csv.DictReader(lines)
            downloaded = {}
            for row in reader:
                assignment = (row.get("Assignment") or "").strip().upper()
                org_name = (row.get("Organization Name") or "").strip()
                if len(assignment) == 6 and org_name:
                    downloaded[assignment] = org_name

            if downloaded:
                with open(OUI_CACHE_FILE, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["prefix", "manufacturer"])
                    for k, v in sorted(downloaded.items()):
                        writer.writerow([k, v])
                oui_map.update(downloaded)
                print(f"Cached {len(downloaded):,} OUI prefixes to {OUI_CACHE_FILE}.")
                return oui_map
        except Exception as e:
            print(f"Could not download IEEE OUI list ({e}). Using built-in fallback list.")
            return oui_map

    try:
        with open(OUI_CACHE_FILE, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                prefix = (row.get("prefix") or "").strip().upper()
                mfg = (row.get("manufacturer") or "").strip()
                if prefix and mfg:
                    oui_map[prefix] = mfg
    except Exception:
        pass

    return oui_map


def lookup_manufacturer(mac, oui_map):
    """Look up manufacturer name from MAC address; detect randomized/private MACs."""
    if not mac or mac == "N/A":
        return "Unknown"

    clean_mac = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(clean_mac) < 6:
        return "Unknown"

    prefix = clean_mac[:6]
    if prefix in oui_map:
        return oui_map[prefix]

    # Check locally administered address (LAA) bit (2nd hex digit in {2, 6, A, E})
    if clean_mac[1] in {"2", "6", "A", "E"}:
        return "Randomized / Private MAC"

    return "Unknown Vendor"


def get_local_ipv4_and_cidr():
    """Detect active local IPv4 address on Windows and calculate subnet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()

    try:
        output = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
        blocks = output.split("\r\n\r\n")
        for block in blocks:
            if local_ip in block:
                mask_match = re.search(r"Subnet Mask[.\s:]+(\d+\.\d+\.\d+\.\d+)", block)
                if mask_match:
                    net = ipaddress.IPv4Network(f"{local_ip}/{mask_match.group(1)}", strict=False)
                    return local_ip, net
    except Exception:
        pass

    return local_ip, ipaddress.IPv4Network(f"{local_ip}/24", strict=False)


def get_default_gateway():
    """Extract default IPv4 gateway from ipconfig."""
    try:
        output = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
        matches = re.findall(r"Default Gateway[.\s:]+(\d+\.\d+\.\d+\.\d+)", output)
        for gw in matches:
            if gw != "0.0.0.0":
                return gw
    except Exception:
        pass
    return None


def ping_host(ip_str, timeout_ms=700):
    """Ping a single IP on Windows. Returns True if reachable."""
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip_str]
    result = subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return result.returncode == 0


def get_arp_table():
    """Parse Windows 'arp -a' output into a dict mapping IP -> MAC address."""
    arp_map = {}
    output = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
    for line in output.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", line)
        if match:
            ip, mac = match.group(1), match.group(2).upper().replace("-", ":")
            if mac != "FF:FF:FF:FF:FF:FF" and not ip.startswith("224.") and not ip.startswith("239."):
                arp_map[ip] = mac
    return arp_map


def resolve_hostname(ip_str):
    """Attempt reverse DNS lookup for hostname."""
    try:
        name, _, _ = socket.gethostbyaddr(ip_str)
        return name
    except Exception:
        return "Unknown"


def is_port_open(ip_str, port, timeout=0.25):
    """Quick TCP connect check to help infer device role."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((ip_str, port)) == 0


def infer_device_type(ip_str, hostname, manufacturer, is_active, local_ip, gateway_ip):
    """Classify device type using IP role, hostname, full manufacturer name, and open ports."""
    if ip_str == local_ip:
        return "This PC (Local Host)"
    if gateway_ip and ip_str == gateway_ip:
        return "Router / Gateway"

    h = (hostname or "").lower()
    mfg = (manufacturer or "").lower()

    # 1. Hostname clues
    if any(k in h for k in ["printer", "laserjet", "officejet", "deskjet", "epson", "canon", "brother"]):
        return "Printer"
    if any(k in h for k in ["iphone", "ipad", "android", "pixel", "galaxy", "phone"]):
        return "Mobile Device"
    if any(k in h for k in ["macbook", "imac", "desktop-", "laptop-", "pc-", "workstation", "server"]):
        return "Computer / Server"
    if any(k in h for k in ["tv", "roku", "firetv", "chromecast", "echo", "alexa", "sonos", "nest"]):
        return "Smart TV / IoT"

    # 2. Full Manufacturer Name clues
    if any(k in mfg for k in ["brother", "seiko epson", "canon", "lexmark", "xerox", "ricoh", "kyocera"]):
        return "Printer"
    if any(k in mfg for k in ["ubiquiti", "cisco", "netgear", "tp-link", "aruba", "juniper", "mikrotik", "linksys", "asus", "d-link"]):
        return "Network Equipment"
    if any(k in mfg for k in ["synology", "qnap", "western digital", "buffalo"]):
        return "NAS / Storage"
    if any(k in mfg for k in ["espressif", "tuya", "shenzhen", "ring", "nest", "sonos", "ecobee", "philips lighting", "signify", "wyze", "arlo"]):
        return "Smart Home / IoT"
    if "raspberry pi" in mfg:
        return "Single-Board Computer / IoT"
    if any(k in mfg for k in ["nintendo", "sony interactive", "valve"]):
        return "Gaming Console"
    if any(k in mfg for k in ["vmware", "virtualbox", "proxmox", "qemu", "parallels"]):
        return "Virtual Machine"
    if "apple" in mfg:
        if is_active and is_port_open(ip_str, 62078):
            return "Mobile Device (iOS)"
        return "Apple Device (Mac / iOS)"
    if any(k in mfg for k in ["dell", "lenovo", "intel", "micro-star", "gigabyte", "hewlett packard enterprise", "hp inc"]):
        if is_active and (is_port_open(ip_str, 9100) or is_port_open(ip_str, 631)):
            return "Printer"
        return "Computer / Workstation"
    if "randomized / private mac" in mfg:
        return "Mobile / Modern Client (Private MAC)"

    # 3. Port probes fallback when active
    if is_active:
        if is_port_open(ip_str, 9100) or is_port_open(ip_str, 631):
            return "Printer"
        if is_port_open(ip_str, 3389) or is_port_open(ip_str, 445) or is_port_open(ip_str, 22):
            return "Computer / Server"
        if is_port_open(ip_str, 8009) or is_port_open(ip_str, 8008):
            return "Smart TV / IoT"

    return "Unknown"


def scan_network(max_workers=64):
    oui_map = load_oui_database()
    local_ip, subnet = get_local_ipv4_and_cidr()
    gateway_ip = get_default_gateway()
    hosts = [str(ip) for ip in subnet.hosts()]

    print(f"Scanning {subnet} ({len(hosts)} addresses) from {local_ip}...")

    ping_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in hosts}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                ping_results[ip] = future.result()
            except Exception:
                ping_results[ip] = False

    arp_table = get_arp_table()

    candidate_ips = sorted(
        set(ip for ip, alive in ping_results.items() if alive) | set(arp_table.keys()),
        key=lambda x: tuple(int(part) for part in x.split(".")),
    )

    records = []
    for ip in candidate_ips:
        is_active = ping_results.get(ip, False)
        status = "active" if is_active else " Inactive"
        mac = arp_table.get(ip, "N/A")
        manufacturer = lookup_manufacturer(mac, oui_map)
        hostname = resolve_hostname(ip) if is_active else "Unknown"
        device_type = infer_device_type(ip, hostname, manufacturer, is_active, local_ip, gateway_ip)

        records.append({
            "name": hostname,
            "ip address": ip,
            "type": device_type,
            "manufacturer": manufacturer,
            "macadress": mac,
            "status": status,
        })

    return records


def print_table(records):
    headers = ["name", "ip address", "type", "manufacturer", "macadress", "status"]
    col_widths = {
        h: max(len(h), *(len(str(r.get(h, ""))) for r in records)) if records else len(h)
        for h in headers
    }

    line = " | ".join(h.ljust(col_widths[h]) for h in headers)
    sep = "-+-".join("-" * col_widths[h] for h in headers)
    print("\n" + line)
    print(sep)
    for r in records:
        print(" | ".join(str(r[h]).ljust(col_widths[h]) for h in headers))


def save_csv(records, filename=None):
    if not filename:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(SCRIPT_DIR, f"network_devices_{stamp}.csv")

    fieldnames = ["name", "ip address", "type", "manufacturer", "macadress", "status"]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
    return filename


def save_excel(records, filename=None):
    """
    Save network scan results to an Excel workbook.

    Parameters
    ----------
    records : list[dict]
        List of device records returned by scan_networkx().
    filename : str, optional
        Output .xlsx file path.

    Returns
    -------
    str
        Path to saved Excel file.
    """
    import os
    from datetime import datetime
    import pandas as pd

    if not filename:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(
            SCRIPT_DIR,
            f"network_devices_{stamp}.xlsx"
        )

    fieldnames = [
        "name",
        "ip address",
        "type",
        "manufacturer",
        "macadress",
        "status"
    ]

    df = pd.DataFrame(records)

    # Ensure columns appear in desired order
    for col in fieldnames:
        if col not in df.columns:
            df[col] = ""

    df = df[fieldnames]

    with pd.ExcelWriter(filename, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Devices")

        # Optional formatting
        ws = writer.sheets["Devices"]

        for column in ws.columns:
            max_len = max(
                len(str(cell.value)) if cell.value is not None else 0
                for cell in column
            )
            ws.column_dimensions[column[0].column_letter].width = min(max_len + 2, 50)

    return filename


if __name__ == "__main__":
    results = scan_network()
    print_table(results)
    csv_path = save_csv(results)
    print(f"\nSaved results to {csv_path}")
    exc_path = save_excel(results)
    print(f"\nAlso Saved results to {exc_path}")
    
    
    
    
    
