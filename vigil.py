import nvdlib
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import srp, Ether, ARP, conf, show_interfaces, sniff, sr1, IP, TCP, sendp, UDP, ICMP
import threading
import argparse
import socket
import time
import json
import sys
import ipaddress
import ssl
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse
try:
    from rich.console import Console, Group
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn
    from rich.layout import Layout
    from rich.columns import Columns
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

banner = """
██╗   ██╗██╗ ██████╗ ██╗██╗     
██║   ██║██║██╔════╝ ██║██║     
██║   ██║██║██║  ███╗██║██║     
╚██╗ ██╔╝██║██║   ██║██║██║     
 ╚████╔╝ ██║╚██████╔╝██║███████╗
  ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝
"""

timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
print_lock = threading.Lock()
found_ports = []
heuristic_findings = []
open_port_results = []
heuristic_records = []
cve_cache = {}
syn_counter = {}
scan_counter = {}
udp_counter = {}
icmp_counter = {}
arp_table = {}
scan_header_printed = False
live_table_enabled = False
vigilant_log = []
vigilant_alerts = []
console = Console() if RICH_AVAILABLE else None

with open("vendors.json", "r", encoding="utf-8") as f:
    vendors_dict = json.load(f)

def scan_port(
    target_ip,
    port,
    verbose=False,
    host_header=None,
    timeout=0.7,
    enable_heuristics=True,
    enable_cve=True,
):
    try:
        start_time = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            latency_ms = (time.perf_counter() - start_time) * 1000

            if not host_header:
                host_header = target_ip
            
            if result == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except:
                    service = "unknown"
                
                banner = ""
                if verbose:
                    try:
                        banner = grab_service_banner(
                            sock=sock,
                            target_ip=target_ip,
                            host_header=host_header,
                            port=port,
                            service=service
                        )
                    except:
                        banner = ""

                cve_ids = lookup_cve(banner) if banner and enable_cve else []

                findings = []
                score = 0
                risk = "LOW"
                if enable_heuristics:
                    findings, score = run_heuristics(
                        target_ip=target_ip,
                        host_header=host_header,
                        port=port,
                        service=service,
                        latency_ms=latency_ms
                    )
                    risk = detect_risk_level(score)

                with print_lock:
                    history_msg = f"{port} is open | {service}"
                    if banner:
                        history_msg += f" | {banner}"

                    print_scan_row(port, service, banner, risk, score, cve_ids)
                    found_ports.append(history_msg)
                    open_port_results.append(
                        {
                            "port": port,
                            "service": service,
                            "banner": banner if banner else "-",
                            "cve": ", ".join(cve_ids) if cve_ids else "-",
                        }
                    )
                if enable_heuristics:
                    record_heuristic_result(port, service, score, findings, emit=False)

    except Exception:
        pass


def grab_service_banner(sock, target_ip, host_header, port, service):
    http_like = service == "http" or "https" in service or port in [80, 443, 8080, 8443]
    if http_like:
        payload = f"HEAD / HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n".encode()

        # HTTPS ports need TLS handshake before sending HTTP payload.
        if port in [443, 8443] or "https" in service:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=host_header) as tls_sock:
                tls_sock.settimeout(2)
                tls_sock.sendall(payload)
                raw_response = tls_sock.recv(2048).decode(errors="ignore")
        else:
            sock.sendall(payload)
            raw_response = sock.recv(2048).decode(errors="ignore")

        for line in raw_response.split("\r\n"):
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()

        return raw_response.splitlines()[0].strip() if raw_response else ""

    # SSH daemon usually returns banner right after TCP connect.
    if service == "ssh" or port == 22:
        try:
            sock.settimeout(1.5)
            ssh_banner = sock.recv(2048).decode(errors="ignore").strip()
            if ssh_banner:
                return ssh_banner.replace("\n", " ")
        except Exception:
            return ""

    try:
        sock.settimeout(1.5)
        generic_banner = sock.recv(1024).decode(errors="ignore").strip()
        return generic_banner.replace("\n", " ")
    except Exception:
        return ""


def detect_risk_level(score):
    if score >= 8:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def record_heuristic_result(port, service, score, findings, emit=True):
    risk = detect_risk_level(score)
    findings_text = "; ".join(findings) if findings else "No obvious weak behavior"
    with print_lock:
        if emit:
            print_heuristic_result(port, risk, score, findings_text)
        heuristic_findings.append(
            f"{port} | {service} | risk={risk} ({score}) | {findings_text}"
        )
        heuristic_records.append(
            {
                "port": port,
                "service": service,
                "risk": risk,
                "score": score,
                "details": findings_text,
            }
        )


def print_scan_row(port, service, banner_text, risk, score, cve_ids):
    global scan_header_printed
    if RICH_AVAILABLE and live_table_enabled:
        return
    if RICH_AVAILABLE:
        if not scan_header_printed:
            console.print("[bold cyan]Port   Service         Risk     Score  Banner                          CVE[/]")
            console.print("[dim]-----  --------------  -------  -----  ------------------------------  --------------------------[/]")
            scan_header_printed = True

        risk_text = risk
        if risk == "HIGH":
            risk_text = "[red]HIGH[/]"
        elif risk == "MEDIUM":
            risk_text = "[yellow]MEDIUM[/]"
        elif risk == "LOW":
            risk_text = "[green]LOW[/]"

        clean_banner = banner_text if banner_text else "-"
        if len(clean_banner) > 30:
            clean_banner = clean_banner[:27] + "..."
        cve_text = ", ".join(cve_ids) if cve_ids else "-"
        if len(cve_text) > 26:
            cve_text = cve_text[:23] + "..."

        console.print(
            f"{str(port):>5}  "
            f"{service:<14}  "
            f"{risk_text:<7}  "
            f"{str(score):>5}  "
            f"{clean_banner:<30}  "
            f"{cve_text}"
        )
        return
    if not scan_header_printed:
        print("Port   Service         Risk     Score  Banner                          CVE")
        print("-----  --------------  -------  -----  ------------------------------  --------------------------")
        scan_header_printed = True
    cve_text = ", ".join(cve_ids) if cve_ids else "-"
    msg = (
        f"{port:>5}  {service:<14}  {risk:<7}  {score:>5}  "
        f"{(banner_text if banner_text else '-')[:30]:<30}  {cve_text[:26]}"
    )
    print(msg)


def build_live_scan_table():
    table = Table(title="Live Scan Findings", box=box.SIMPLE_HEAVY, show_lines=False)
    table.add_column("Port", justify="right", style="cyan", width=6)
    table.add_column("Service", style="green", width=14)
    table.add_column("Risk", width=8)
    table.add_column("Score", justify="right", width=5)
    table.add_column("Banner", style="white", width=32, overflow="ellipsis")
    table.add_column("CVE", style="magenta", width=38, overflow="ellipsis")

    with print_lock:
        rows = sorted(open_port_results, key=lambda item: item["port"])
        risk_map = {item["port"]: item for item in heuristic_records}

    for row in rows:
        risk_row = risk_map.get(row["port"], {})
        risk = risk_row.get("risk", "-")
        score = str(risk_row.get("score", "-"))
        risk_text = risk
        if risk == "HIGH":
            risk_text = "[red]HIGH[/]"
        elif risk == "MEDIUM":
            risk_text = "[yellow]MEDIUM[/]"
        elif risk == "LOW":
            risk_text = "[green]LOW[/]"
        table.add_row(
            str(row["port"]),
            row.get("service", "-"),
            risk_text,
            score,
            row.get("banner", "-"),
            row.get("cve", "-"),
        )
    return table


def print_open_port(port, service, banner_text):
    if RICH_AVAILABLE:
        message = f"[bold green]OPEN[/] [cyan]{port}[/] [white]{service}[/]"
        if banner_text and banner_text != "-":
            message += f" [dim]| {banner_text}[/]"
        console.print(message)
        return
    msg = f"\033[1;32m✓\033[0m {port} is \033[1;32mopen\033[0m | {service}"
    if banner_text and banner_text != "-":
        msg += f" | {banner_text}"
    print(msg)


def print_heuristic_result(port, risk, score, findings_text):
    if RICH_AVAILABLE:
        risk_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(risk, "white")
        console.print(
            f"  [bold {risk_color}]Risk[/]: port [cyan]{port}[/] -> "
            f"[{risk_color}]{risk} ({score})[/]"
        )
        return
    print(f"└──> Heuristic Risk: {risk} ({score}) | {findings_text}")


def run_heuristics(target_ip, host_header, port, service, latency_ms):
    findings = []
    score = 0

    port_findings, port_score = evaluate_port_behavior(port, service, latency_ms)
    findings.extend(port_findings)
    score += port_score

    if port in [80, 443, 8080, 8443] or service in ["http", "https"]:
        http_findings, http_score = evaluate_http_security(target_ip, host_header, port)
        findings.extend(http_findings)
        score += http_score

    if port in [443, 8443] or "https" in service:
        tls_findings, tls_score = evaluate_tls_posture(target_ip, host_header, port)
        findings.extend(tls_findings)
        score += tls_score

    return findings, score


def evaluate_port_behavior(port, service, latency_ms):
    findings = []
    score = 0

    if service == "unknown" and port >= 49152:
        findings.append("Unknown service exposed on dynamic high port")
        score += 2

    if latency_ms > 500:
        findings.append(f"Slow handshake response ({int(latency_ms)} ms)")
        score += 1

    return findings, score


def evaluate_http_security(target_ip, host_header, port):
    findings = []
    score = 0

    try:
        scheme = "https" if port in [443, 8443] else "http"
        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Connection: close\r\n\r\n"
        )

        raw_response = send_request(target_ip, port, request, use_tls=(scheme == "https"), server_name=host_header)
        if not raw_response:
            findings.append("No HTTP response on an HTTP-like open port")
            return findings, score + 1

        headers = parse_http_headers(raw_response)
        lower_headers = {k.lower(): v for k, v in headers.items()}

        if port in [443, 8443] and "strict-transport-security" not in lower_headers:
            findings.append("Missing HSTS on HTTPS endpoint")
            score += 2

        if "content-security-policy" not in lower_headers:
            findings.append("Missing Content-Security-Policy header")
            score += 1

        if "x-frame-options" not in lower_headers:
            findings.append("Missing X-Frame-Options header")
            score += 1

        if "x-content-type-options" not in lower_headers:
            findings.append("Missing X-Content-Type-Options header")
            score += 1

        trace_response = send_request(
            target_ip,
            port,
            f"TRACE / HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n",
            use_tls=(scheme == "https"),
            server_name=host_header
        )
        if trace_response.startswith("HTTP/") and " 200 " in trace_response.splitlines()[0]:
            findings.append("TRACE method appears enabled")
            score += 2
    except Exception:
        findings.append("HTTP heuristic probe failed")
        score += 1

    return findings, score


def evaluate_tls_posture(target_ip, host_header, port):
    findings = []
    score = 0

    try:
        base_context = ssl.create_default_context()
        base_context.check_hostname = False
        base_context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target_ip, port), timeout=2) as raw_sock:
            with base_context.wrap_socket(raw_sock, server_hostname=host_header) as tls_sock:
                cert = tls_sock.getpeercert()
                negotiated = tls_sock.version()

                if negotiated in ["TLSv1", "TLSv1.1"]:
                    findings.append(f"Weak protocol accepted: {negotiated}")
                    score += 3

                expiry = cert.get("notAfter")
                if expiry:
                    expiry_dt = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    if expiry_dt < datetime.now(timezone.utc):
                        findings.append("TLS certificate is expired")
                        score += 3
                else:
                    findings.append("TLS certificate details unavailable (could not parse notAfter)")

                issuer = cert.get("issuer", ())
                subject = cert.get("subject", ())
                if issuer and subject and issuer == subject:
                    findings.append("TLS certificate appears self-signed")
                    score += 2

        if accepts_legacy_tls(target_ip, host_header, port):
            findings.append("Legacy TLS negotiation accepted (TLSv1/TLSv1.1)")
            score += 3

    except Exception:
        findings.append("TLS heuristic probe failed")
        score += 1

    return findings, score


def accepts_legacy_tls(target_ip, host_header, port):
    legacy_versions = []
    if hasattr(ssl.TLSVersion, "TLSv1"):
        legacy_versions.append(ssl.TLSVersion.TLSv1)
    if hasattr(ssl.TLSVersion, "TLSv1_1"):
        legacy_versions.append(ssl.TLSVersion.TLSv1_1)

    for version in legacy_versions:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # Probe legacy protocols intentionally; suppress deprecation noise.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                context.minimum_version = version
                context.maximum_version = version
            with socket.create_connection((target_ip, port), timeout=2) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=host_header):
                    return True
        except Exception:
            continue
    return False


def send_request(target_ip, port, payload, use_tls=False, server_name=None):
    with socket.create_connection((target_ip, port), timeout=2) as sock:
        conn = sock
        tls_sock = None
        try:
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                tls_sock = context.wrap_socket(sock, server_hostname=server_name or target_ip)
                conn = tls_sock

            conn.sendall(payload.encode())
            raw = conn.recv(4096).decode(errors="ignore")
            return raw
        finally:
            if tls_sock:
                tls_sock.close()


def parse_http_headers(raw_response):
    headers = {}
    for line in raw_response.split("\r\n")[1:]:
        if not line.strip():
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers


def print_heuristic_summary():
    if not heuristic_findings:
        return
    high_count = sum(1 for line in heuristic_findings if "risk=HIGH" in line)
    medium_count = sum(1 for line in heuristic_findings if "risk=MEDIUM" in line)
    low_count = sum(1 for line in heuristic_findings if "risk=LOW" in line)
    if RICH_AVAILABLE:
        table = Table(title="Heuristic Summary", show_header=True, header_style="bold magenta")
        table.add_column("Risk", style="bold")
        table.add_column("Count", justify="right")
        table.add_row("[red]HIGH[/]", str(high_count))
        table.add_row("[yellow]MEDIUM[/]", str(medium_count))
        table.add_row("[green]LOW[/]", str(low_count))
        console.print(table)
        return
    print("\nHeuristic Summary")
    print(f"- HIGH   : {high_count}")
    print(f"- MEDIUM : {medium_count}")
    print(f"- LOW    : {low_count}")


def print_scan_results_summary():
    if not open_port_results:
        return

    heuristic_by_port = {}
    for item in heuristic_records:
        heuristic_by_port[item["port"]] = item

    if RICH_AVAILABLE:
        table = Table(title="Scan Findings", show_lines=False)
        table.add_column("Port", justify="right", style="cyan")
        table.add_column("Service", style="green")
        table.add_column("Banner", style="white")
        table.add_column("Risk", style="bold")
        table.add_column("Score", justify="right")
        table.add_column("Heuristic Details", style="dim")
        table.add_column("CVE", style="magenta")
        for row in sorted(open_port_results, key=lambda item: item["port"]):
            risk_row = heuristic_by_port.get(row["port"], {})
            risk = risk_row.get("risk", "-")
            score = str(risk_row.get("score", "-"))
            details = risk_row.get("details", "-")
            if risk == "HIGH":
                risk = "[red]HIGH[/]"
            elif risk == "MEDIUM":
                risk = "[yellow]MEDIUM[/]"
            elif risk == "LOW":
                risk = "[green]LOW[/]"
            table.add_row(str(row["port"]), row["service"], row["banner"], risk, score, details, row.get("cve", "-"))
        console.print(table)
        console.print(
            Panel.fit(
                f"Open ports found: [bold green]{len(open_port_results)}[/]",
                title="Scan Complete",
                border_style="green"
            )
        )
        return
    print("\nScan Findings")
    print("PORT  SERVICE        BANNER                 RISK    SCORE  DETAILS                     CVE")
    for row in sorted(open_port_results, key=lambda item: item["port"]):
        risk_row = heuristic_by_port.get(row["port"], {})
        risk = risk_row.get("risk", "-")
        score = str(risk_row.get("score", "-"))
        details = risk_row.get("details", "-")
        cve_text = row.get("cve", "-")
        print(f"{row['port']:<5} {row['service']:<14} {row['banner'][:22]:<22} {risk:<7} {score:<6} {details[:25]:<25} {cve_text}")
    print(f"\nScan complete. Open ports found: {len(open_port_results)}")

def lookup_cve(banner):
    if banner in cve_cache:
        return cve_cache[banner]

    clean_keyword = banner
    if banner.startswith("SSH-"):
        parts = banner.split('-')
        if len(parts) >= 3:
            clean_keyword = "-".join(parts[2:])
            
    clean_keyword = clean_keyword.split('(')[0].replace('_', ' ').replace('/', ' ').strip()
    
    words = clean_keyword.split()
    if len(words) >= 2:
        clean_keyword = f"{words[0]} {words[1]}"
    elif len(words) == 1:
        clean_keyword = words[0]
    else:
        return []

    if len(clean_keyword) < 4 or "HTTP/" in clean_keyword:
        return []

    try:
        r = nvdlib.searchCVE(keywordSearch=clean_keyword, limit=3)
        cve_ids = []
        for eachCVE in r:
            cve_ids.append(eachCVE.id)
        cve_cache[banner] = cve_ids
        return cve_ids
    except Exception:
        return []
        

def discover_network(discover, interface, verbose=False):
    try:
        # Parse targets into a list of individual IPs for the thread pool
        try:
            # If discovery is a CIDR block, get all host IPs
            if "/" in discover:
                net = ipaddress.ip_network(discover, strict=False)
                targets = [str(ip) for ip in net.hosts()]
            else:
                targets = [discover]
        except ValueError:
            targets = [discover]

        if RICH_AVAILABLE:
            console.print(f"[bold cyan]🔍 Live Discovering active hosts on network:[/] [green]{discover}[/]")
            table = Table(
                title=f"Network Discovery - {discover}",
                box=box.ROUNDED,
                header_style="bold magenta",
                border_style="blue",
                show_lines=True
            )
            table.add_column("IP Address", style="cyan", justify="left")
            table.add_column("Hostname", style="green", justify="left")
            table.add_column("MAC Address", style="yellow", justify="left")
            table.add_column("Vendor", style="white", justify="left")
        else:
            print(f"[*] Discovering active hosts on network: {discover}")

        found_count = 0

        def probe_ip(ip):
            """Helper to probe a single IP and return result if active."""
            try:
                packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                # Shorter timeout per IP probe to keep it snappy
                answered, _ = srp(packet, timeout=1.5, verbose=False, iface=interface)
                if answered:
                    received = answered[0][1]
                    mac = received.hwsrc
                    oiu_prefix = mac[:8].lower()
                    vendor = vendors_dict.get(oiu_prefix, "Unknown Vendor")
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = "unknown"
                    return (ip, hostname, mac, vendor)
            except:
                pass
            return None

        if RICH_AVAILABLE:
            # Progress bar for discovery to show it's working
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=None),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=console
            )
            task_id = progress.add_task(f"[cyan]Probing {len(targets)} hosts...", total=len(targets))
            
            def get_discovery_display():
                return Group(table, progress)

            with Live(get_discovery_display(), console=console, refresh_per_second=10):
                # Using 50 workers for a fast, responsive live scan
                with ThreadPoolExecutor(max_workers=50) as executor:
                    futures = [executor.submit(probe_ip, ip) for ip in targets]
                    for future in as_completed(futures):
                        res = future.result()
                        progress.update(task_id, advance=1)
                        if res:
                            table.add_row(*res)
                            found_count += 1
            
            console.print(f"\n[bold blue]Summary:[/] Discovery complete. Found [bold green]{found_count}[/] active hosts.")
        else:
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(probe_ip, ip) for ip in targets]
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        print(f"\033[1;32m✓\033[0m {res[0]} is active | {res[1]} | {res[3]}")
                        found_count += 1
            print(f"discovery complete, found {found_count} hosts")

    except PermissionError:
        if RICH_AVAILABLE:
            console.print("[bold red][!] Permission denied. Run as administrator/root.[/]")
        else:
            print("[+] Permission denied. Run as root")
    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"[bold red][!] Error:[/] {e}")
        else:
            print(f"[!] Error: {e}")

def build_vigilant_dashboard(interface, bpf_filter, alert_threshold):
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body")
    )
    layout["body"].split_row(
        Layout(name="logs", ratio=2),
        Layout(name="security", ratio=1)
    )

    # Header Panel
    filter_text = bpf_filter if bpf_filter else "None"
    header_content = (
        f"[bold blue]Interface:[/] {interface}  |  "
        f"[bold blue]BPF Filter:[/] {filter_text}  |  "
        f"[bold blue]Threshold:[/] {alert_threshold}"
    )
    layout["header"].update(Panel(header_content, title="VIGILANT MODE STATUS", border_style="cyan"))

    # Logs Table
    log_table = Table(expand=True, box=box.SIMPLE)
    log_table.add_column("Time", style="dim", width=12)
    log_table.add_column("Packet Summary", style="green")
    
    with print_lock:
        for timestamp, summary in vigilant_log[-12:]:
            log_table.add_row(timestamp, summary)
    
    layout["logs"].update(Panel(log_table, title="Live Network Traffic", border_style="green"))

    # Alerts Table
    alert_table = Table(expand=True, box=box.SIMPLE)
    alert_table.add_column("Type", style="bold red")
    alert_table.add_column("Message", style="yellow")
    
    with print_lock:
        for alert_type, msg in vigilant_alerts[-8:]:
            alert_table.add_row(alert_type, msg)
            
    layout["security"].update(Panel(alert_table, title="Security Alerts", border_style="red"))

    return layout

def vigilant_mode(interface, bpf_filter=None, alert_threshold=25, vigilant_output=None):
    try:
        if RICH_AVAILABLE:
            console.print(Panel(f"Vigilant mode enabled on interface [bold cyan]{interface}[/]\nMonitoring network traffic...", title="VIGIL", border_style="red"))
            
            with Live(build_vigilant_dashboard(interface, bpf_filter, alert_threshold), console=console, refresh_per_second=4) as live:
                sniff(
                    iface=interface,
                    filter=bpf_filter,
                    prn=lambda pkt: process_vigilant_packet(pkt, alert_threshold, vigilant_output, live, interface),
                    store=False
                )
        else:
            print(f"\033[1;31m⍻\033[0m Vigilant mode enabled on interface {interface}")
            print(f"\033[1;31m⍻\033[0m Monitoring network traffic...")
            sniff(
                iface=interface,
                filter=bpf_filter,
                prn=lambda pkt: process_vigilant_packet(pkt, alert_threshold, vigilant_output),
                store=False
            )

    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            console.print("\n[bold red]⍻[/] Vigilant mode disabled")
        else:
            print(f"\n\033[1;31m⍻\033[0m Vigilant mode disabled")
    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"[bold red][!] Vigilant mode error:[/] {e}")
        else:
            print(f"[!] Vigilant mode error: {e}")


def process_vigilant_packet(packet, alert_threshold, vigilant_output, live=None, interface=None):
    now = time.time()
    summary = packet.summary()
    time_str = datetime.now().strftime("%H:%M:%S")

    # Update Global Log
    with print_lock:
        vigilant_log.append((time_str, summary))
        if len(vigilant_log) > 50: vigilant_log.pop(0)

    if vigilant_output:
        with open(vigilant_output, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {summary}\n")

    detect_syn_burst(packet, now, alert_threshold)
    detect_port_scan(packet, now, alert_threshold)
    detect_udp_flood(packet, now, alert_threshold)
    detect_icmp_flood(packet, now, alert_threshold)
    detect_arp_spoof(packet)

    if RICH_AVAILABLE and live and interface:
        live.update(build_vigilant_dashboard(interface, None, alert_threshold)) # Simplified filter for layout update


def detect_syn_burst(packet, now, alert_threshold):
    if IP in packet and TCP in packet and (packet[TCP].flags & 0x02): # Check for SYN bit explicitly
        src = packet[IP].src
        entries = syn_counter.get(src, [])
        entries = [t for t in entries if now - t <= 10]
        entries.append(now)
        syn_counter[src] = entries

        if len(entries) >= alert_threshold:
            msg = f"Src {src} ({len(entries)} SYNs in 10s)"
            with print_lock:
                vigilant_alerts.append(("SYN BURST", msg))
                if len(vigilant_alerts) > 20: vigilant_alerts.pop(0)
            
            if not RICH_AVAILABLE:
                print(f"\033[1;33m[ALERT]\033[0m Possible SYN burst from {src}")
            syn_counter[src] = []


def detect_port_scan(packet, now, alert_threshold):
    if IP in packet and TCP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        dport = packet[TCP].dport

        records = scan_counter.get(src, [])
        records = [(ts, target, port) for ts, target, port in records if now - ts <= 15]
        records.append((now, dst, dport))
        scan_counter[src] = records

        unique_ports = {(target, port) for _, target, port in records}
        if len(unique_ports) >= alert_threshold:
            msg = f"Src {src} ({len(unique_ports)} ports in 15s)"
            with print_lock:
                vigilant_alerts.append(("PORT SCAN", msg))
                if len(vigilant_alerts) > 20: vigilant_alerts.pop(0)
                
            if not RICH_AVAILABLE:
                print(f"\033[1;33m[ALERT]\033[0m Possible port scan from {src}")
            scan_counter[src] = []


def detect_udp_flood(packet, now, alert_threshold):
    if IP in packet and UDP in packet:
        src = packet[IP].src
        entries = udp_counter.get(src, [])
        entries = [t for t in entries if now - t <= 10]
        entries.append(now)
        udp_counter[src] = entries

        if len(entries) >= alert_threshold:
            msg = f"Src {src} ({len(entries)} UDPs in 10s)"
            with print_lock:
                vigilant_alerts.append(("UDP FLOOD", msg))
                if len(vigilant_alerts) > 20: vigilant_alerts.pop(0)
            
            if not RICH_AVAILABLE:
                print(f"\033[1;33m[ALERT]\033[0m Possible UDP flood from {src}")
            udp_counter[src] = []


def detect_icmp_flood(packet, now, alert_threshold):
    if IP in packet and ICMP in packet:
        # Check for Echo Request (type 8)
        if packet[ICMP].type in [0, 8]:
            src = packet[IP].src
            entries = icmp_counter.get(src, [])
            entries = [t for t in entries if now - t <= 10]
            entries.append(now)
            icmp_counter[src] = entries


            if len(entries) >= alert_threshold:
                msg = f"Src {src} ({len(entries)} ICMPs in 10s)"
                with print_lock:
                    vigilant_alerts.append(("ICMP FLOOD", msg))
                    if len(vigilant_alerts) > 20: vigilant_alerts.pop(0)
                
                if not RICH_AVAILABLE:
                    print(f"\033[1;33m[ALERT]\033[0m Possible ICMP flood from {src}")
                icmp_counter[src] = []


def detect_arp_spoof(packet):
    if ARP not in packet or packet[ARP].op != 2:
        return

    ip = packet[ARP].psrc
    mac = packet[ARP].hwsrc.lower()
    previous = arp_table.get(ip)

    if previous and previous != mac:
        msg = f"IP {ip}: {previous} -> {mac}"
        with print_lock:
            vigilant_alerts.append(("ARP SPOOF", msg))
            if len(vigilant_alerts) > 20: vigilant_alerts.pop(0)
            
        if not RICH_AVAILABLE:
            print(f"\033[1;33m[ALERT]\033[0m Possible ARP spoof detected for IP {ip}")
    arp_table[ip] = mac

def parse_ports(port_input):
    if not port_input:
        return list(range(1, 65536))

    selected_ports = set()
    chunks = [chunk.strip() for chunk in port_input.split(",") if chunk.strip()]

    for chunk in chunks:
        if "-" in chunk:
            start_port, end_port = chunk.split("-", 1)
            start_port = int(start_port)
            end_port = int(end_port)

            if start_port > end_port:
                raise ValueError(f"invalid port range: {chunk}")

            for port in range(start_port, end_port + 1):
                if port < 1 or port > 65535:
                    raise ValueError(f"port out of range: {port}")
                selected_ports.add(port)
        else:
            port = int(chunk)
            if port < 1 or port > 65535:
                raise ValueError(f"port out of range: {port}")
            selected_ports.add(port)

    return sorted(selected_ports)


def normalize_target(target):
    if not target:
        return None, None

    raw_target = target.strip()
    parsed_target = raw_target

    if "://" in raw_target:
        parsed = urlparse(raw_target)
        parsed_target = parsed.hostname or ""

    if not parsed_target:
        raise ValueError("target URL/hostname is empty")

    try:
        ipaddress.ip_address(parsed_target)
        return parsed_target, parsed_target
    except ValueError:
        pass

    try:
        resolved_ip = socket.gethostbyname(parsed_target)
        return resolved_ip, parsed_target
    except socket.gaierror:
        raise ValueError(f"unable to resolve target: {target}")

def main():
    arg = argparse.ArgumentParser(
        description="VIGIL - Virtual Interface for Gateway Inspection & Listening",
        epilog="Example: vigil -t [IP_ADDRESS] -w 30 -o output.txt"
    )
    arg.add_argument("--target", "-t", required=False)
    arg.add_argument("--discover", "-d", required=False, type=str, default=None, help="discover active hosts in a network")
    arg.add_argument("--interface", "-i", required=False, type=str, default=None, help="interface to use for discovery")
    arg.add_argument("--show-interfaces", "-si", action="store_true", help="show available interfaces")
    arg.add_argument(
        "--ports",
        "-p",
        required=False,
        type=str,
        default=None,
        help="ports to scan (examples: 80, 22,80,443, 1-1024, 22,80-90)"
    )
    arg.add_argument("--vigilant", "-v", action="store_true", help="enable vigilant mode")
    arg.add_argument("--bpf", required=False, type=str, default=None, help="BPF filter for vigilant mode (example: tcp or arp)")
    arg.add_argument("--alert-threshold", required=False, type=int, default=25, help="alert threshold for vigilant detection (default: 25)")
    arg.add_argument("--vigilant-output", required=False, type=str, default=None, help="log vigilant packets to file")
    arg.add_argument("--verbose", "-vv", action="store_true", help="enable verbose mode")
    arg.add_argument("--threads", "-w", required=False, type=int, default=100, help="number of threads (default: 100)")
    arg.add_argument("--timeout", required=False, type=float, default=0.5, help="socket timeout in seconds (default: 0.5)")
    arg.add_argument("--fast", action="store_true", help="speed mode: disable heavy checks and lower timeout")
    arg.add_argument("--no-cve", action="store_true", help="disable CVE lookup for faster scan")
    arg.add_argument("--no-heuristic", action="store_true", help="disable heuristic checks for faster scan")
    arg.add_argument("--output", "-o", required=False, type=str, default=None, help="output file")
    args = arg.parse_args()

    target = args.target
    thread = args.threads
    output = args.output
    discover = args.discover
    interface = args.interface
    display_iface = args.show_interfaces
    vigilant = args.vigilant
    verbose = args.verbose
    ports = args.ports
    timeout = args.timeout
    fast_mode = args.fast
    disable_cve = args.no_cve
    disable_heuristic = args.no_heuristic
    bpf_filter = args.bpf
    alert_threshold = args.alert_threshold
    vigilant_output = args.vigilant_output

    if fast_mode:
        timeout = min(timeout, 0.25)
        disable_cve = True
        disable_heuristic = True
        verbose = False

    if len(sys.argv) == 1:
        print(banner)
        arg.print_help()
        sys.exit()

    scan_target_ip = None
    scan_target_host = None

    if target:
        try:
            scan_target_ip, scan_target_host = normalize_target(target)
        except ValueError as e:
            print(f"[!] {e}")
            sys.exit(1)

    if RICH_AVAILABLE:
        console.print(Panel.fit(banner.strip(), title="VIGIL", border_style="cyan"))
    else:
        print(banner)
    if target:
        if RICH_AVAILABLE:
            console.print(f"[bold]Scanning[/] {target} at [dim]{timestamp}[/]")
        else:
            print(f"Scanning {target} at time {timestamp}")
    if RICH_AVAILABLE:
        console.print("[dim]Visit : https://github.com/muhzahidazmy[/]\n")
    else:
        print(f"Visit : https://github.com/muhzahidazmy\n")

    if display_iface:
        show_interfaces()

    if interface:
        conf.iface = interface

    if discover:
        discover_network(discover, interface, verbose)
        return

    if vigilant:
        vigilant_mode(interface, bpf_filter, alert_threshold, vigilant_output)
        return

    if verbose:
        print(f"\033[1;32m✓\033[0m Verbose mode enabled (Banner Grabbing & Scapy Debug)")
        print(f"[*] Input Target   : {target}")
        print(f"[*] Resolved IP    : {scan_target_ip}")
        print(f"[*] Thread Count   : {thread}")
        print(f"[*] Port Selection : {ports if ports else '1-65535'}")
        print(f"[*] Timeout        : {timeout}s")
        print(f"[*] Interface      : {interface if interface else 'Default'}")
        print(f"[*] Output File    : {output if output else 'None'}")
        print(f"[*] Scapy L3 Conf  : {conf.iface}")
        print(f"[*] Start scanning ports...\n")
    elif fast_mode:
        print("[*] Fast mode enabled (heuristics, CVE, verbose probes disabled)")

    if target:
        try:
            scan_ports = parse_ports(ports)
            
            # Enable live table mode BEFORE starting threads to prevent duplicate/leaked output
            if RICH_AVAILABLE:
                global live_table_enabled
                live_table_enabled = True

            with ThreadPoolExecutor(max_workers=thread) as executor:
                futures = [
                    executor.submit(
                        scan_port,
                        scan_target_ip,
                        port,
                        verbose,
                        scan_target_host,
                        timeout,
                        not disable_heuristic,
                        not disable_cve
                    )
                    for port in scan_ports
                ]
                
                if RICH_AVAILABLE:
                    # Create a progress bar for port scanning
                    progress = Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(bar_width=None),
                        MofNCompleteColumn(),
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        TimeElapsedColumn(),
                        console=console
                    )
                    
                    task_id = progress.add_task(f"[cyan]Scanning {len(scan_ports)} ports...", total=len(scan_ports))
                    
                    # Group the findings table and the progress bar for Live display
                    def get_live_display():
                        return Group(
                            build_live_scan_table(),
                            progress
                        )

                    with Live(get_live_display(), console=console, refresh_per_second=10) as live:
                        for _ in as_completed(futures):
                            progress.update(task_id, advance=1)
                            live.update(get_live_display())
                            
                    live_table_enabled = False
                else:
                    for future in as_completed(futures):
                        future.result()
            print_scan_results_summary()
            print_heuristic_summary()
            if output:
                with open(output, "w") as f:
                    f.write(f"Scan completed at {timestamp}\n")
                    f.write(f"Target: {target} ({scan_target_ip})\n")
                    for port in found_ports:
                        f.write(f"{port}\n")
                    if heuristic_findings:
                        f.write("\nHeuristic Findings:\n")
                        for finding in heuristic_findings:
                            f.write(f"{finding}\n")

        except KeyboardInterrupt:
            print(f"\033[1;31m⍻\033[0m Canceled by user")
        except ValueError as e:
            print(f"[!] Invalid ports format: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()