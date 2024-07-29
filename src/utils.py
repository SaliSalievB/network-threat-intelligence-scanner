import platform
import subprocess
import requests
import re
import os

def get_network_connections():
    os_type = platform.system()
    if os_type == "Windows":
        return get_windows_connections()
    elif os_type == "Linux":
        return get_linux_connections()
    elif os_type == "Darwin":
        return get_macos_connections()
    else:
        raise NotImplementedError(f"Unsupported OS: {os_type}")

def get_windows_connections():
    result = subprocess.run(["netstat", "-an"], capture_output=True, text=True)
    connections = parse_netstat_output(result.stdout)
    return connections

def get_linux_connections():
    result = subprocess.run(["ss", "-tun"], capture_output=True, text=True)
    connections = parse_ss_output(result.stdout)
    return connections

def get_macos_connections():
    result = subprocess.run(["netstat", "-an"], capture_output=True, text=True)
    connections = parse_netstat_output(result.stdout)
    return connections

def parse_netstat_output(output):
    connections = []
    for line in output.splitlines():
        if line.startswith("  TCP") or line.startswith("  UDP"):
            parts = re.split(r'\s+', line)
            ip_port = parts[3]  # Assuming parts[2] contains the address and port
            ip = ip_port.rsplit(':', 1)[0]  # Remove the port
            ip = clean_ip(ip)
            if not is_local_ip(ip):
                connections.append(ip)
    print(connections)
    return connections

def parse_ss_output(output):
    connections = []
    for line in output.splitlines():
        if line.startswith("tcp") or line.startswith("udp"):
            parts = re.split(r'\s+', line)
            ip_port = parts[4]  # Assuming parts[4] contains the address and port
            ip = ip_port.rsplit(':', 1)[0]  # Remove the port
            ip = clean_ip(ip)
            if not is_local_ip(ip):
                connections.append(ip)
    return connections

def clean_ip(ip):
    # Remove IPv6 zone index
    if '%' in ip:
        ip = ip.split('%')[0]
    # Remove brackets for IPv6 addresses
    ip = ip.strip('[]')
    return ip

def is_local_ip(ip):
    local_ips = ['127.0.0.1', '::1', '0.0.0.0', '::', '*']
    return (ip in local_ips or
            ip.startswith('192.168.') or
            ip.startswith('10.') or
            ip.startswith('172.16.') or
            ip.startswith('172.31.') or
            ip.startswith('169.254.') or
            ip.startswith('fe80:') or  # Link-local IPv6 addresses
            ip.startswith('fc00:') or  # Unique local IPv6 addresses
            ip.startswith('fd00:'))


def check_ip_threat(ip):
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        raise ValueError("API key for AbuseIPDB not found in environment variables.")

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    response = requests.get(url, headers=headers, params=params)
    return response.json()
