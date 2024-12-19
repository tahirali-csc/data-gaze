import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import socket
import struct
import io  

# Helper function to convert IP addresses to integers
def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip.strip()))[0]
    except OSError:
        return np.nan

# Step 1: Load data into a DataFrame
df = pd.read_csv("network_traffic.csv")

# Step 2: Preprocess the data
# Convert IPs to integers
df['src_ip_int'] = df['src_ip'].apply(ip_to_int)
df['dest_ip_int'] = df['dest_ip'].apply(ip_to_int)

# Drop rows with invalid IPs (if any)
df.dropna(inplace=True)

# Features to use for the model
features = df[['src_ip_int', 'dest_ip_int', 'pkt_size']]

# Scale the features
scaler = StandardScaler()
scaled_features = scaler.fit_transform(features)

# Step 3: Train the Isolation Forest model
model = IsolationForest(contamination=0.1, random_state=42)
df['anomaly'] = model.fit_predict(scaled_features)

# Step 4: Identify anomalies
anomalies = df[df['anomaly'] == -1]

# Step 5: Output results
print("Original DataFrame:")
print(df)
print("\nAnomalies Detected:")
print(anomalies)
