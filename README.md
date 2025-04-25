# ICMP Ping Flood Detection Project

This project detects ICMP Ping Flood attacks on a network.

## Tools Used
- Python
- Scapy (for simulating the attack)
- Wireshark (for capturing packets)
- SQLite (for storing suspicious IPs)
- Matplotlib (for visualization)

## Project Structure
- `simulate_ping_flood.py` → Simulates a ping flood attack
- `icmp_data.csv` → Captured packets (exported from Wireshark)
- `detect_icmp_attack.py` → Analyzes and detects suspicious activity
- `icmp_attacks.db` → SQLite database containing attack logs
- `README.md` → Project description

## How to Run It
1. Run `simulate_ping_flood.py` to simulate an attack
2. Capture packets with Wireshark and export them as CSV
3. Run `detect_icmp_attack.py` to detect and log suspicious activity
4. View the visualization with matplotlib
