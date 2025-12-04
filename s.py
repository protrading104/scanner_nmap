#!/usr/bin/env python3

import ipaddress
import os
import random
import re
import shutil
import subprocess
import sys
import time
import multiprocessing

from rw import *


def resolve_nmap_path():
    """Return a usable path to nmap or raise a helpful error."""

    env_path = os.environ.get("NMAP_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    detected = shutil.which("nmap")
    if detected:
        return detected

    for path in (
        r"C:\\Program Files\\Nmap\\nmap.exe",
        r"C:\\Program Files (x86)\\Nmap\\nmap.exe",
    ):
        if os.path.isfile(path):
            return path

    raise FileNotFoundError(
        "nmap executable not found. Install Nmap and/or set NMAP_PATH to the executable path."
    )

NMAP_CMD = None
DNS_SERVERS = []
ALIVE_SCAN_DELAY = "500ms"
SPOOF_MAC = None
SPOOF_SOURCE_IP = None


def init_worker(nmap_cmd, dns_servers, scan_delay=None, spoof_mac=None, source_ip=None):
    """Configure global settings inside worker processes."""

    global NMAP_CMD, DNS_SERVERS, ALIVE_SCAN_DELAY, SPOOF_MAC, SPOOF_SOURCE_IP
    NMAP_CMD = nmap_cmd
    DNS_SERVERS = dns_servers
    if scan_delay is not None:
        ALIVE_SCAN_DELAY = scan_delay
    if spoof_mac is not None:
        SPOOF_MAC = spoof_mac
    if source_ip is not None:
        SPOOF_SOURCE_IP = source_ip


def random_mac(prefix=None):
    """Generate a random MAC address, optionally using the provided OUI prefix."""

    def random_byte():
        return f"{random.randint(0x00, 0xFF):02x}"

    if prefix:
        cleaned = prefix.replace("-", ":").lower()
        parts = cleaned.split(":")
        if len(parts) != 3 or any(len(p) != 2 for p in parts):
            raise ValueError("Prefix must look like 'aa:bb:cc'")
        base = parts
    else:
        base = [random_byte() for _ in range(3)]

    tail = [random_byte() for _ in range(3)]
    return ":".join(base + tail)


def random_source_ip(network):
    """Return a random usable host address from the given network."""

    net = ipaddress.ip_network(network, strict=False)
    candidates = [ip for ip in net.hosts()]
    if not candidates:
        raise ValueError(f"Network {network} has no usable hosts")
    return str(random.choice(candidates))

ress = {
"rdp": {"good": "Hosts with open RDP", "bad": "Hosts have RDP port open.", "innmap": "yes", "condition": "3389", "state": "open", "message": "no", "additional": "no"},
"smb": {"good": "Hosts with open SMB",  "bad": "Hosts have SMB port open.", "innmap": "yes", "condition": "445", "state": "open", "message": "no", "additional": "ghost"},
"etn": {"good": "Hosts Vulnerable to EternalBlue",  "bad": "Hosts are Vulnerable to EternalBlue.", "innmap": "yes", "condition": "eternalblue", "state": "yes", "message": "   > Vulnerable to EternalBlue!", "additional": "os"},
"ghost": {"good": "Hosts Vulnerable to SMBGhost",  "bad": "Hosts are Vulnerable to SMBGhost.", "innmap": "no"}
}

def parse(key, host, hosts):
    try:
        if ress[key]["innmap"] == "yes" and hosts[host][ress[key]["condition"]] == ress[key]["state"]:
            with open("%s.txt" % key, "a") as f:
                f.write("%s\n" % host)
            if ress[key]["message"] != "no":
                print(ress[key]["message"])
            if ress[key]["additional"] == "os":
                try:
                    print('   >%s' % hosts[host]["os"])
                except:
                    pass
            elif ress[key]["additional"] == "ghost":
                try:
                    if IsTargetVulnerable(host, 445):
                        with open("ghost.txt", "a") as f:
                            f.write("%s\n" % host)
                        print("   > Vulnerable to SMBGhost!")
                except:
                    pass
    except KeyError:
        pass

def parallel_routes(routes):
    while True:
        x = len(routes)
        for i in routes:
            if int(i.split('/')[1]) < 24:
                c = list(ipaddress.ip_network(i).subnets())
                routes.append(str(ipaddress.IPv4Network(c[0])))
                routes.append(str(ipaddress.IPv4Network(c[1])))
                routes.remove(i)
        if x == len(routes):
            break
    return routes

def clear_subnets(ips):
    while True:
        c = len(ips)
        for i in ips:
            for b in ips:
                if i != b and ipaddress.ip_network(i).subnet_of(ipaddress.ip_network(b)):
                    ips.remove(i)
        if c == len(ips):
            break
    return ips


def resolve_alive_sweep_settings():
    """Return (workers, delay) for alive host discovery with optional env overrides."""

    # Windows multiprocessing pools cannot wait on more than 63 handles
    # (WinAPI WaitForMultipleObjects limit). Keep the default and ceiling
    # below that threshold to avoid ``ValueError: need at most 63 handles``
    # when spawning worker processes on Windows.
    windows_worker_cap = 61

    default_workers = windows_worker_cap if os.name == "nt" else 64
    max_workers = windows_worker_cap if os.name == "nt" else 512
    default_delay = 0.0

    env_workers = os.environ.get("ALIVE_WORKERS")
    env_delay = os.environ.get("ALIVE_BATCH_DELAY")

    workers = default_workers
    if env_workers:
        try:
            workers = int(env_workers)
        except ValueError:
            print("[!] Invalid ALIVE_WORKERS value; using default: %s" % default_workers)
        else:
            if workers > max_workers:
                print(
                    "[!] ALIVE_WORKERS capped at %s on this platform (requested %s)"
                    % (max_workers, workers)
                )
                workers = max_workers
            workers = max(1, workers)

    try:
        batch_delay = max(0.0, float(env_delay)) if env_delay is not None else default_delay
    except ValueError:
        print("[!] Invalid ALIVE_BATCH_DELAY value; using default: %.2f" % default_delay)
        batch_delay = default_delay

    return workers, batch_delay


def resolve_alive_scan_delay():
    """Return the nmap --scan-delay value for alive host discovery."""

    default_delay = "500ms"
    env_delay = os.environ.get("ALIVE_SCAN_DELAY")

    if env_delay is None:
        return default_delay

    cleaned = env_delay.strip()
    if not cleaned:
        print("[!] ALIVE_SCAN_DELAY is empty; falling back to default: %s" % default_delay)
        return default_delay

    return cleaned


def resolve_spoofing_settings():
    """Resolve MAC and source IP spoofing settings from environment variables."""

    random_mac_flag = os.environ.get("ALIVE_RANDOM_MAC")
    mac_prefix = os.environ.get("ALIVE_MAC_PREFIX")
    source_ip = os.environ.get("ALIVE_SOURCE_IP")
    source_net = os.environ.get("ALIVE_SOURCE_NET")

    spoof_mac = None
    spoof_source_ip = None

    try:
        if (random_mac_flag and random_mac_flag.lower() not in ("0", "false", "no")) or mac_prefix:
            spoof_mac = random_mac(mac_prefix)
    except ValueError as exc:
        print("[!] Invalid ALIVE_MAC_PREFIX: %s; MAC spoofing disabled" % exc)
        spoof_mac = None

    try:
        if source_ip:
            spoof_source_ip = source_ip.strip()
        elif source_net:
            spoof_source_ip = random_source_ip(source_net)
    except ValueError as exc:
        print("[!] Invalid ALIVE_SOURCE_NET: %s; source IP spoofing disabled" % exc)
        spoof_source_ip = None

    return spoof_mac, spoof_source_ip


def confirm_startup():
    """Ask for confirmation before starting the monitoring loop."""

    while True:
        answer = input("[?] Start route monitoring and scanning? (y/N): ").strip().lower()
        if answer in ("y", "n", ""):
            return answer == "y"
        print("Please enter 'y' to confirm or 'n' to cancel.")



def choose_action():
    """Show an interactive menu after route discovery and return the user's choice."""

    prompt = (
        "[%s][?] Select an action:\n"
        "   0. Stop and exit\n"
        "   1. Run alive host discovery\n"
        "   2. Run port and vulnerability scan\n"
        "Enter 0, 1 or 2: "
    ) % time.strftime("%H:%M:%S", time.localtime())

    while True:
        answer = input(prompt).strip()
        if answer in ("0", "1", "2"):
            return answer
        print("Please enter 0, 1 or 2.")

def render_progress(current, total, last_finished=None):
    percent = int((current / total) * 100) if total else 0
    bar_length = 30
    filled_length = int(bar_length * percent / 100)
    bar = "#" * filled_length + "-" * (bar_length - filled_length)
    progress = "[%s][=] Progress: |%s| %s%% (%s/%s)" % (
        time.strftime("%H:%M:%S", time.localtime()), bar, percent, current, total
    )
    if last_finished:
        progress += " - completed %s" % last_finished
    print(progress)


def discover_dns_servers():
    """Try several strategies to locate DNS servers for nmap."""

    env_value = os.environ.get("DNS_SERVERS")
    if env_value:
        servers = [server.strip() for server in env_value.split(",") if server.strip()]
        if servers:
            return servers

    servers = []

    if os.name == "nt":
        try:
            output = subprocess.check_output("ipconfig /all", text=True, errors="ignore")
        except Exception:
            output = ""

        current_section = False
        for line in output.splitlines():
            if line.lower().strip().startswith("dns servers"):
                current_section = True
                possible = line.split(":", 1)[-1].strip()
                if possible:
                    servers.append(possible)
                continue

            if current_section:
                stripped = line.strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", stripped):
                    servers.append(stripped)
                    continue

                if not stripped:
                    break

    resolv_conf = "/etc/resolv.conf"
    if os.path.exists(resolv_conf):
        try:
            with open(resolv_conf, "r", encoding="utf-8", errors="ignore") as resolv:
                for line in resolv:
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(parts[1].strip())
        except OSError:
            pass

    return list(dict.fromkeys(server for server in servers if server))


def discover_alive_hosts(routes):
    """Run an ICMP ping sweep across all discovered routes and record alive hosts."""

    if not NMAP_CMD:
        raise RuntimeError("Nmap executable path is not configured in worker process")

    output_path = "alive_hosts.txt"
    try:
        os.remove(output_path)
    except FileNotFoundError:
        pass

    hosts_to_scan = [str(ip) for route in routes for ip in ipaddress.ip_network(route, strict=False).hosts()]
    total_hosts = len(hosts_to_scan)
    scanned_hosts = 0
    alive_hosts = []

    print(
        "[%s][*] Searching for alive hosts across %s routes (%s hosts total) ..."
        % (time.strftime("%H:%M:%S", time.localtime()), len(routes), total_hosts)
    )

    workers, batch_delay = resolve_alive_sweep_settings()
    scan_delay = resolve_alive_scan_delay()
    spoof_mac, spoof_source_ip = resolve_spoofing_settings()

    global ALIVE_SCAN_DELAY, SPOOF_MAC, SPOOF_SOURCE_IP
    ALIVE_SCAN_DELAY = scan_delay
    SPOOF_MAC = spoof_mac
    SPOOF_SOURCE_IP = spoof_source_ip

    print(
        "[%s][*] Launching ping sweep with %s parallel workers%s ..."
        % (
            time.strftime("%H:%M:%S", time.localtime()),
            workers,
            " and %.2fs pacing" % batch_delay if batch_delay else "",
        )
    )

    print("[%s][*] Using nmap --scan-delay %s" % (time.strftime("%H:%M:%S", time.localtime()), scan_delay))
    if SPOOF_MAC:
        print("[%s][!] Spoofing MAC address: %s" % (time.strftime("%H:%M:%S", time.localtime()), SPOOF_MAC))
    if SPOOF_SOURCE_IP:
        print(
            "[%s][!] Spoofing source IP: %s" % (time.strftime("%H:%M:%S", time.localtime()), SPOOF_SOURCE_IP)
        )

    try:
        with multiprocessing.Pool(
            workers,
            initializer=init_worker,
            initargs=(NMAP_CMD, DNS_SERVERS, ALIVE_SCAN_DELAY, SPOOF_MAC, SPOOF_SOURCE_IP),
        ) as pool:
            for scanned_hosts, result in enumerate(
                pool.imap_unordered(ping_host, hosts_to_scan), start=1
            ):
                if result:
                    alive_hosts.append(result)

                if scanned_hosts == total_hosts or scanned_hosts % 20 == 0:
                    remaining = total_hosts - scanned_hosts
                    print(
                        "\r[%s][*] Progress: %s/%s scanned, %s remaining"
                        % (
                            time.strftime("%H:%M:%S", time.localtime()),
                            scanned_hosts,
                            total_hosts,
                            remaining,
                        ),
                        end="",
                        flush=True,
                    )
                    if batch_delay:
                        time.sleep(batch_delay)
    except KeyboardInterrupt:
        print("\n[!] User interrupted alive host discovery; stopping worker pool ...")
        raise

    print()

    alive_count = len(alive_hosts)
    alive_hosts.sort()
    with open(output_path, "w") as alive_file:
        if alive_hosts:
            alive_file.write("\n".join(alive_hosts) + "\n")

    print(
        "[%s][+] Alive host discovery complete: %s host(s) alive. Results saved to %s."
        % (time.strftime("%H:%M:%S", time.localtime()), alive_count, output_path)
    )

    return alive_count


def ping_host(ip):
    """Probe a single host with nmap ping scan and return the IP if alive."""

    if not NMAP_CMD:
        return None

    cmd = [NMAP_CMD, "-sn", "-PR", "--scan-delay", ALIVE_SCAN_DELAY, str(ip)]

    if SPOOF_MAC:
        cmd.extend(["--spoof-mac", SPOOF_MAC])

    if SPOOF_SOURCE_IP:
        cmd.extend(["-S", SPOOF_SOURCE_IP])

    result = subprocess.run(cmd, capture_output=True, text=True)
    return str(ip) if "Host is up" in result.stdout else None

def scan(ip):
    if not NMAP_CMD:
        raise RuntimeError("Nmap executable path is not configured in worker process")

    print("[%s][>] Scanning %s ..." % (time.strftime("%H:%M:%S", time.localtime()), ip))
    hosts = {}
    cmd = [
        NMAP_CMD,
        "--open",
        "-PE",
        "-T5",
        "-p445,3389",
        "--script",
        "smb-vuln-ms17-010",
        "--script",
        "smb-os-discovery",
        ip,
    ]

    if DNS_SERVERS:
        cmd[1:1] = ["--dns-servers", ",".join(DNS_SERVERS)]
        print("[!] Using custom DNS servers: %s" % ", ".join(DNS_SERVERS))
    for line in subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True).stdout.read().splitlines():
        if line.startswith('Nmap scan report for '):
            if line.count('(') == 1 and line.count(')') == 1:
                hosts.update({line.split('(')[1].replace(')', '') : {'ResolvedName' : line.split(' ')[4]}})
                host = line.split('(')[1].replace(')', '')
            else:
                hosts.update({line.split(' ')[4] : {'ResolvedName' : ''}})
                host = line.split(' ')[4]
        elif line.startswith('445/tcp'):
            hosts[host].update({'445' : 'open'})
        elif line.startswith('3389/tcp'):
            hosts[host].update({'3389' : 'open'})
        elif line.count('smb-vuln-ms17-010') == 1:
            hosts[host].update({'eternalblue' : 'yes'})
        elif line.count(' OS: ') == 1:
            hosts[host].update({'os' : line.split(':')[1]})
    for host in hosts:
        if hosts[host]['ResolvedName'] != '':
            print('%s (%s)' % (host, hosts[host]['ResolvedName']))
        else:
            print(host)
        for i in ress:
            parse(i, host, hosts)

    print("[%s][>] Finished %s" % (time.strftime("%H:%M:%S", time.localtime()), ip))

def scan_with_label(ip):
    scan(ip)
    return ip

def parse_res(var, string1, string2):
    try:
        with open("%s.txt" % var, 'r') as file:
            tempvar = file.readlines()
        string = "[+] %s (%s):" % (string1, len(tempvar))
        for i in tempvar:
            string+='%s, ' % i.replace('\n', '')
        print(string[:string.rfind(',')])
    except:
        print("[-] 0 %s" % string2)

def get_routes(routes_output):
    """Extract IPv4 network routes from Windows or Linux route output."""

    diaps = []
    lines = str(routes_output).splitlines()

    is_windows_output = any("IPv4 Route Table" in line for line in lines)

    if is_windows_output:
        parsing = False
        for line in lines:
            if not parsing and "IPv4 Route Table" in line:
                parsing = True
                continue

            if parsing and line.count(".") >= 3:
                parts = [part for part in line.split(" ") if part]
                if len(parts) < 2:
                    continue

                destination, netmask = parts[0], parts[1]

                if (
                    destination in ("0.0.0.0", "127.0.0.0")
                    or netmask in ("0.0.0.0", "240.0.0.0", "255.255.255.255")
                    or destination.startswith("169.")
                    or destination.startswith("10.212.134")
                ):
                    continue

                network = ipaddress.IPv4Network(f"{destination}/{netmask}", strict=False)
                if str(network) not in diaps:
                    diaps.append(str(network))
    else:
        for line in lines:
            if not line:
                continue

            if line.startswith("default"):
                # If the only change is a default route (common for PPP/VPN links),
                # capture the gateway as a /32 so we can still treat it as a new
                # reachable host. This avoids ignoring interfaces that only add
                # a default route without advertising specific networks.
                parts = line.split()
                if "via" in parts:
                    via_index = parts.index("via") + 1
                    if via_index < len(parts):
                        gateway = parts[via_index]
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$", gateway):
                            candidate = f"{gateway}/32"
                            if candidate not in diaps:
                                diaps.append(candidate)
                # Skip further processing of this default route entry.
                continue

            parts = line.split()
            if not parts:
                continue

            candidate = parts[0]
            if "/" not in candidate:
                # Linux adds host routes for point-to-point interfaces (e.g. PPP)
                # in the form of a plain IP without CIDR notation. Treat them as
                # /32 networks so they can be picked up for scanning.
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", candidate):
                    candidate = f"{candidate}/32"
                else:
                    continue

            try:
                network = ipaddress.IPv4Network(candidate, strict=False)
            except ValueError:
                continue

            if (
                network == ipaddress.IPv4Network("0.0.0.0/0")
                or network.is_loopback
                or network.is_link_local
            ):
                continue

            if str(network) not in diaps:
                diaps.append(str(network))

    return diaps, routes_output


def get_route_output():
    """Return the platform-appropriate route table output as text."""

    if os.name == "nt":
        command = ["route", "print", "-4"]
    else:
        command = ["ip", "-4", "route", "list"]

    return subprocess.check_output(command, text=True, errors="ignore")

if __name__ == "__main__":
    try:
        try:
            NMAP_CMD = resolve_nmap_path()
        except FileNotFoundError as exc:
            print("[!] %s" % exc)
            sys.exit(1)

        DNS_SERVERS = discover_dns_servers()
        if not DNS_SERVERS:
            print("[!] DNS servers were not detected automatically; nmap will rely on its defaults.")

        print("[%s][!] Parsing default routes ..." % time.strftime("%H:%M:%S", time.localtime()))
        default_routes, default_data = get_routes(get_route_output())
        current_routes = list(default_routes)
        old_data = default_data
        for i in default_routes:
            print('   > %s' % i)

        if not confirm_startup():
            print("[%s][-] Startup cancelled by user." % time.strftime("%H:%M:%S", time.localtime()))
            sys.exit(0)

        while True:
            print("[%s][*] Waiting for route changes ..." % time.strftime("%H:%M:%S", time.localtime()))
            time.sleep(1)
            routes, new_data = get_routes(get_route_output())
            if new_data != old_data:
                if default_data == new_data:
                    print("[%s][!] Default route configuration restored!" % time.strftime("%H:%M:%S", time.localtime()))
                    current_routes = list(default_routes)
                    old_data = new_data
                else:
                    new_routes = [route for route in routes if route not in current_routes]
                    if not new_routes:

                        old_data = new_data
                        continue

                    print("[%s][+] Changes detected, following routes added:" % time.strftime("%H:%M:%S", time.localtime()))
                    extra_routes = clear_subnets(new_routes)
                    for i in ress:
                        try:
                            os.remove('%s.txt' % i)
                        except:
                            pass
                    for i in extra_routes:
                        print('   > %s' % i)
                    extra_routes = parallel_routes(extra_routes)
                    print("[%s][*] Final routes to scan:" % time.strftime("%H:%M:%S", time.localtime()))
                    for route in extra_routes:
                        print('   > %s' % route)
                    while True:
                        action = choose_action()
                        if action == "0":
                            print("[%s][-] Scan cancelled by user request." % time.strftime("%H:%M:%S", time.localtime()))
                            sys.exit(0)

                        if action == "1":
                            alive_count = discover_alive_hosts(extra_routes)
                            print(
                                "[%s][*] Alive hosts found: %s. Returning to main menu."
                                % (time.strftime("%H:%M:%S", time.localtime()), alive_count)
                            )
                            continue

                        # action == "2": выполнить сканирование портов
                        total_routes = len(extra_routes)
                        if len(extra_routes) == 1:
                            print("[%s][+] Launching single-threaded scan against %s ..." % (time.strftime("%H:%M:%S", time.localtime()), extra_routes[0]))
                            render_progress(0, total_routes)
                            scan(extra_routes[0])
                            render_progress(total_routes, total_routes, extra_routes[0])
                        else:
                            if len(extra_routes) < 60:
                                threads =  len(extra_routes)
                            else:
                                threads = 60
                            print("[%s][+] Launching multithreader scan with %s threads against %s routes ..."  % (time.strftime("%H:%M:%S", time.localtime()), threads, total_routes))
                            render_progress(0, total_routes)
                            p = multiprocessing.Pool(
                                threads, initializer=init_worker, initargs=(NMAP_CMD, DNS_SERVERS)
                            )
                            try:
                                for idx, finished_ip in enumerate(
                                    p.imap_unordered(scan_with_label, extra_routes), start=1
                                ):
                                    render_progress(idx, total_routes, finished_ip)
                            except KeyboardInterrupt:
                                print("[!] User interrupted! Stopping active scans ...")
                                p.terminate()
                                p.join()
                                sys.exit(1)
                            else:
                                p.close()
                                p.join()
                        for i in ress:
                            parse_res(i, ress[i]["good"], ress[i]["bad"])
                        break

                    current_routes = list(routes)
                    old_data = new_data
    except KeyboardInterrupt:
        print("User interrupted!\t\t\t\t\t")
