import pandas as pd
import numpy as np
from sklearn.neighbors import LocalOutlierFactor
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
loc = LocalOutlierFactor(n_neighbors=20, contamination=0.25)  # Contamination is % of anomalies expected
df["anomaly"] = loc.fit_predict(X)  # -1 for anomalies, 1 for normal

# Step 5: Output the results
# print(df[["src_ip", "dest_ip", "pkt_size", "anomaly"]])

# Step 5: Filter and print only anomalies
print(df[df["anomaly"] == -1][["src_ip", "dest_ip", "pkt_size"]])
