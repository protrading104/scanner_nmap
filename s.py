import ipaddress
import os
import shutil
import subprocess
import sys
import time
import multiprocessing
import re

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


def init_worker(nmap_cmd, dns_servers):
    """Configure global settings inside worker processes."""

    global NMAP_CMD, DNS_SERVERS
    NMAP_CMD = nmap_cmd
    DNS_SERVERS = dns_servers

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


def confirm_scan(routes):
    """Ask the user to confirm scanning the discovered routes."""

    prompt = "[%s][?] Start scanning %s routes? (y/N): " % (
        time.strftime("%H:%M:%S", time.localtime()),
        len(routes),
    )

    while True:
        answer = input(prompt).strip().lower()
        if answer in ("y", "n", ""):
            return answer == "y"
        print("Please enter 'y' to confirm or 'n' to cancel.")

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

def get_routes(routes):
    diaps = []
    ro = False
    for i in str(routes).split('\\r\\n'):
        if i.count('.') >= 9 and ro == True:
            s = i.split(' ')
            while s.count('') != 0:
                s.remove('')
            if s[1] != '255.255.255.255' and s[1] != '240.0.0.0' and s[0] != '0.0.0.0' and s[1] != '0.0.0.0' and s[0] != '127.0.0.0' and diaps.count(str(ipaddress.IPv4Network('%s/%s' % (s[0], s[1]), False))) == 0 and s[0].startswith('169.') == False and s[0].startswith('10.212.134') == False:
                diaps.append(str(ipaddress.IPv4Network('%s/%s' % (s[0], s[1]), False)))
        elif ro == False and i.count('IPv4 Route Table') == 1:
            ro = True
    return diaps, routes

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
        default_routes, default_data = get_routes(str(subprocess.check_output("route print -4")))
        old_data = default_data
        for i in default_routes:
            print('   > %s' % i)
        while True:
            print("[%s][*] Waiting for route changes ..." % time.strftime("%H:%M:%S", time.localtime()))
            time.sleep(1)
            routes, new_data = get_routes(str(subprocess.check_output("route print -4")))
            if new_data != old_data:
                if default_data == new_data:
                    print("[%s][!] Default route configuration restored!" % time.strftime("%H:%M:%S", time.localtime()))
                    old_data = default_data
                elif default_routes == routes:
                    print("[%s][-] Changes detected, but no new routes added!" % time.strftime("%H:%M:%S", time.localtime()))
                    old_data = default_data
                elif default_routes != routes:
                    print("[%s][+] Changes detected, following routes added:" % time.strftime("%H:%M:%S", time.localtime()))
                    for i in default_routes:
                        routes.remove(i)
                    routes = clear_subnets(routes)
                    for i in ress:
                        try:
                            os.remove('%s.txt' % i)
                        except:
                            pass
                    for i in routes:
                        print('   > %s' % i)
                    routes = parallel_routes(routes)
                    print("[%s][*] Final routes to scan:" % time.strftime("%H:%M:%S", time.localtime()))
                    for route in routes:
                        print('   > %s' % route)
                    if not confirm_scan(routes):
                        print("[%s][-] Scan cancelled; waiting for further route changes." % time.strftime("%H:%M:%S", time.localtime()))
                        old_data = new_data
                        continue
                    total_routes = len(routes)
                    if len(routes) == 1:
                        print("[%s][+] Launching single-threaded scan against %s ..." % (time.strftime("%H:%M:%S", time.localtime()), routes[0]))
                        render_progress(0, total_routes)
                        scan(routes[0])
                        render_progress(total_routes, total_routes, routes[0])
                    else:
                        if len(routes) < 60:
                            threads =  len(routes)
                        else:
                            threads = 60
                        print("[%s][+] Launching multithreader scan with %s threads against %s routes ..."  % (time.strftime("%H:%M:%S", time.localtime()), threads, total_routes))
                        render_progress(0, total_routes)
                        p = multiprocessing.Pool(
                            threads, initializer=init_worker, initargs=(NMAP_CMD, DNS_SERVERS)
                        )
                        try:
                            for idx, finished_ip in enumerate(
                                p.imap_unordered(scan_with_label, routes), start=1
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
                    old_data = new_data
    except KeyboardInterrupt:
        print("User interrupted!\t\t\t\t\t")
