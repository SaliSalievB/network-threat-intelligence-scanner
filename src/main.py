from utils import get_network_connections, check_ip_threat


def main():
    connections = get_network_connections()
    unique_ips = set(connections)  # Deduplicate IPs
    threats = []
    for ip in unique_ips:
        result = check_ip_threat(ip)
        if result['data']['abuseConfidenceScore'] > 0:
            threats.append((ip, result['data']['abuseConfidenceScore']))

    print("Potential Threats Found:")
    for ip, score in threats:
        print(f"IP: {ip}, Score: {score}")


if __name__ == "__main__":
    main()
