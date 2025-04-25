import pandas as pd
import sqlite3
import matplotlib.pyplot as plt

# Define the expected columns based on your CSV structure
columns = ['timestamp_raw', 'source_ip', 'destination_ip', 'icmp_type', 'icmp_code']

# Load the ICMP packet data from CSV
df = pd.read_csv("icmp_data.csv", header=None, names=columns)

# Clean the timestamp field (remove timezone text like "Θερινή ώρα GTB")
df['timestamp'] = df['timestamp_raw'].str.extract(r'^(.*)\sΘερινή ώρα')[0]

# Convert timestamp to datetime objects
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

# Convert ICMP type/code columns to numeric (if they were strings)
df['icmp_type'] = pd.to_numeric(df['icmp_type'], errors='coerce')
df['icmp_code'] = pd.to_numeric(df['icmp_code'], errors='coerce')

# Filter only ICMP Echo Requests (type 8)
df_filtered = df[df['icmp_type'] == 8].copy()

# Create a new column representing time floored to the nearest second
df_filtered['second'] = df_filtered['timestamp'].dt.floor('s')

# Group by source IP and second, count how many packets were sent
grouped = df_filtered.groupby(['source_ip', 'second']).size().reset_index(name='packet_count')

# Identify suspicious IPs sending more than 100 ICMP Echo Requests in 1 second
suspects = grouped[grouped['packet_count'] > 100]

print("\n--- Suspect IP address(es) ---")
print(suspects)

# ------------------ Store suspects in SQLite database ------------------

# Connect to or create SQLite database
conn = sqlite3.connect('icmp_attacks.db')
cursor = conn.cursor()

# Create table if it doesn't already exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT,
    timestamp TEXT,
    packet_count INTEGER
)
''')

# Insert suspect data into the database
for _, row in suspects.iterrows():
    cursor.execute('''
        INSERT INTO attacks (source_ip, timestamp, packet_count)
        VALUES (?, ?, ?)
    ''', (row['source_ip'], str(row['second']), row['packet_count']))

# Commit and close connection
conn.commit()
conn.close()
print("\n✔ Data stored in database icmp_attacks.db")

# ------------------ Visualization with matplotlib ------------------

# Group total ICMP Echo Requests per second
icmp_per_sec = df_filtered.groupby('second').size()
print("\nICMP Echo Requests per Second:")
print(icmp_per_sec)

# Plot the activity
plt.figure(figsize=(10, 5))
plt.plot(icmp_per_sec.index, icmp_per_sec.values, marker='o')
plt.title("ICMP Echo Requests per Second")
plt.xlabel("Time (second)")
plt.ylabel("Number of Packets")
plt.grid(True)
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()
