import scapy.all as scapy

def scan_network(target_ip, target_ports):
    results = []
    
    # Create IP packet
    ip_packet = scapy.IP(dst=target_ip)
    
    for port in target_ports:
        # Create TCP SYN packet
        tcp_packet = scapy.TCP(dport=port, flags='S')
        
        # Combine IP and TCP packets
        packet = ip_packet / tcp_packet
        
        # Send packet and capture response
        response = scapy.sr1(packet, timeout=1, verbose=0)
        
        if response is not None:
            if response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 'SA':
                results.append((port, 'Open'))
            else:
                results.append((port, 'Closed'))
        else:
            results.append((port, 'Filtered'))

    return results



target_ip = input("Enter target IP address: ")
target_ports = [22, 80, 443]  # Specify the ports you want to scan

scan_results = scan_network(target_ip, target_ports)

print("Scan results:")
for port, status in scan_results:
    print(f"Port {port}: {status}")