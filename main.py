import os
import socket
import sys
import whois
import requests
import threading
import ssl
import subprocess

# Funktion zur Anzeige des Banners
def display_banner():
    print(r"""

  __  .__                                 
_/  |_|  |__ _____    ____   ____  ______
\   __\  |  \\__  \  /    \ /  _ \/  ___/
 |  | |   Y  \/ __ \|   |  (  <_> )___ \ 
 |__| |___|  (____  /___|  /\____/____  >
           \/     \/     \/           \/ 

    """)

# Funktion zur Anzeige der Hilfe
def display_help():
    print("""
Usage:
    python script.py -P <Target IP>          : Perform a port scan on the specified IP address.
    python script.py -W <Domain or IP>       : Perform a WHOIS lookup on the specified domain or IP.
    python script.py -R <IP Address>         : Perform a reverse DNS lookup on the specified IP address.
    python script.py -H <URL>                : Fetch HTTP headers of the specified URL.
    python script.py -S <Domain>             : Fetch SSL certificate details of the specified domain.
    python script.py -T <Domain or IP>       : Perform a traceroute to the specified domain or IP.
    python script.py -h                      : Show this help message.

Example:
    python script.py -P 192.168.1.1
    python script.py -W example.com
    python script.py -R 8.8.8.8
    python script.py -H https://example.com
    python script.py -S example.com
    python script.py -T example.com
""")

# Funktion: Reverse DNS Lookup
def reverse_dns_lookup(ip_address):
    print(f"\nPerforming reverse DNS lookup for {ip_address}...\n")
    try:
        hostname, alias, _ = socket.gethostbyaddr(ip_address)
        print(f"Hostname: {hostname}")
        print(f"Alias: {', '.join(alias) if alias else 'None'}")
    except socket.herror as e:
        print(f"Error: {e}")

# Funktion: SSL Certificate Information
def ssl_certificate_info(domain):
    print(f"\nFetching SSL certificate info for {domain}...\n")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(f"Issuer: {cert['issuer']}")
                print(f"Valid From: {cert['notBefore']}")
                print(f"Valid Until: {cert['notAfter']}")
                print(f"Subject: {cert['subject']}")
    except Exception as e:
        print(f"Error: {e}")

# Funktion: Traceroute
def traceroute(domain_or_ip):
    print(f"\nPerforming traceroute to {domain_or_ip}...\n")
    try:
        result = subprocess.run(["tracert", domain_or_ip], capture_output=True, text=True, encoding='utf-8', errors='ignore')
        print(result.stdout)
    except Exception as e:
        print(f"Error: {e}")

# Funktion: Website Scan
def website_scan(domain_or_ip):
    print(f"\nPerforming WHOIS lookup for {domain_or_ip}...\n")
    try:
        w = whois.whois(domain_or_ip)  # WHOIS-Abfrage mit dem whois-Modul
        print(w)
    except Exception as e:
        print(f"Error: {e}")
    try:
        ip = socket.gethostbyname(domain_or_ip)
        print(f"Website IP Address: {ip}")
    except socket.gaierror:
        print(f"Error: Unable to resolve the domain {domain_or_ip}.")

# Funktion: HTTP Header Check
def check_http_headers(url):
    print(f"\nFetching HTTP headers for {url}...\n")
    try:
        response = requests.get(url, timeout=5)
        for header, value in response.headers.items():
            print(f"{header}: {value}")
    except requests.RequestException as e:
        print(f"Error: {e}")

# Funktion: Port-Scan
def port_scan(target_ip):
    print(f"\nPerforming port scan on {target_ip}...\n")
    open_ports = []
    for port in range(1, 1025):  # Scanne Ports von 1 bis 1024
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout auf 1 Sekunde setzen
        result = sock.connect_ex((target_ip, port))  # Versuche, eine Verbindung zum Port herzustellen
        if result == 0:  # Wenn die Verbindung erfolgreich ist, ist der Port offen
            open_ports.append(port)
        sock.close()
    
    if open_ports:
        print(f"Open ports: {', '.join(map(str, open_ports))}")
    else:
        print("No open ports found.")

# Hauptfunktion
def main():
    os.system("color 04")
    display_banner()

    if len(sys.argv) < 2:
        display_help()
        return

    if sys.argv[1] == "-h":  # Hilfe anzeigen
        display_help()
        return

    if sys.argv[1] == "-P":  # Port-Scan durchführen
        if len(sys.argv) < 3:
            print("Usage: python script.py -P <Target IP>")
            return
        target_ip = sys.argv[2]
        port_scan(target_ip)

    elif sys.argv[1] == "-W":  # WHOIS-Abfrage durchführen
        if len(sys.argv) < 3:
            print("Usage: python script.py -W <Domain or IP>")
            return
        domain_or_ip = sys.argv[2]
        website_scan(domain_or_ip)

    elif sys.argv[1] == "-R":  # Reverse DNS Lookup
        if len(sys.argv) < 3:
            print("Usage: python script.py -R <IP Address>")
            return
        reverse_dns_lookup(sys.argv[2])

    elif sys.argv[1] == "-H":  # HTTP Header Check
        if len(sys.argv) < 3:
            print("Usage: python script.py -H <URL>")
            return
        check_http_headers(sys.argv[2])

    elif sys.argv[1] == "-S":  # SSL Certificate Info
        if len(sys.argv) < 3:
            print("Usage: python script.py -S <Domain>")
            return
        ssl_certificate_info(sys.argv[2])

    elif sys.argv[1] == "-T":  # Traceroute
        if len(sys.argv) < 3:
            print("Usage: python script.py -T <Domain or IP>")
            return
        traceroute(sys.argv[2])

    else:
        print("Invalid argument. Use -P for Port Scan, -W for WHOIS Lookup, -R for Reverse DNS Lookup, -H for HTTP Header Check, -S for SSL Certificate Info, -T for Traceroute, or -h for Help.")

if __name__ == "__main__":
    main()
