import pandas as pd
from collections import defaultdict
import sqlite3

columns = ['timestamp', 'timezone', 'source_ip', 'destination_ip', 'icmp_type', 'icmp_code']
df = pd.read_csv("icmp_data.csv", header=None, names=columns)
print(df.head())

df_filtered = df[df['icmp_type'] == 8].copy()

df_filtered['timestamp'] = pd.to_datetime(df_filtered['timestamp'])

df_filtered['second'] = df_filtered['timestamp'].dt.floor('S')
grouped = df_filtered.groupby(['source_ip', 'second']).size().reset_index(name='packet_count')

suspects = grouped[grouped['packet_count'] > 100]

print("\n--- Suspect IP address ---")
print(suspects)

conn = sqlite3.connect('icmp_attacks.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT,
    timestamp TEXT,
    packet_count INTEGER
)
''')

for _, row in suspects.iterrows():
    cursor.execute('''
        INSERT INTO attacks (source_ip, timestamp, packet_count)
        VALUES (?, ?, ?)
    ''', (row['source_ip'], str(row['second']), row['packet_count']))

conn.commit()
conn.close()
print("\n Data stored in database icmp_attacks.db")
