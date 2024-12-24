import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from ipaddress import ip_address

# Step 1: Load data into a DataFrame
df = pd.read_csv("network_traffic.csv")

# Step 2: Preprocess IP addresses and ports
def extract_ip(ip_port):
    # Extract the IP part before the colon
    return ip_port.split(":")[0].strip()

def extract_port(ip_port):
    # Extract the port part after the colon
    return int(ip_port.split(":")[1].strip())

def ip_to_int(ip):
    # Convert IP address to integer
    return int(ip_address(ip))

# Apply IP and port extraction
df["src_ip_numeric"] = df["src_ip"].apply(lambda x: ip_to_int(extract_ip(x)))
df["src_port"] = df["src_ip"].apply(lambda x: extract_port(x))
df["dest_ip_numeric"] = df["dest_ip"].apply(lambda x: ip_to_int(extract_ip(x)))
df["dest_port"] = df["dest_ip"].apply(lambda x: extract_port(x))

# Step 3: Prepare the final data for Isolation Forest
# Include the numeric IPs, ports, and packet size as features
X = df[["src_ip_numeric", "src_port", "dest_ip_numeric", "dest_port", "pkt_size"]]

# Step 4: Apply Isolation Forest
iso_forest = IsolationForest(contamination=0.25, random_state=42)  # Contamination is % of anomalies expected
iso_forest.fit(X)

# Predict anomalies (-1 means anomaly, 1 means normal)
df["anomaly"] = iso_forest.predict(X)

# Step 5: Output the results
# print(df[["src_ip", "dest_ip", "pkt_size", "anomaly"]])

# Step 5: Filter and print only anomalies
anomalies = df[df["anomaly"] == -1]
print(anomalies[["src_ip", "dest_ip", "pkt_size"]])