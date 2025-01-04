# Importing necessary libraries
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Simulating the dataset
# data = {
#     "src_ip": ["91.189.91.157:123", "192.168.1.254:53", "10.0.2.15:12345", "203.0.113.5:22", "192.168.0.1:80"],
#     "dest_ip": ["10.0.2.15:48466", "10.0.2.15:36863", "91.189.91.157:80", "10.0.2.15:22", "172.16.0.2:443"],
#     "pkt_size": [1509949440, 2751463424, 120, 500, 750]  # Unusual values and normal sizes
# }

# Convert to DataFrame
# df = pd.DataFrame(data)
df = pd.read_csv("network_traffic.csv")

# Simulate target variable `is_malicious` based on packet size thresholds
# Mark packets with sizes > 10,000 as malicious for demonstration
df['is_malicious'] = (df['pkt_size'] > 3926196224).astype(int)
# df['is_malicious'] = (df['dest_ip'] == "10.0.2.15:49722").astype(int)

# Features and target
X = df[['pkt_size']]
y = df['is_malicious']

# Feature Scaling
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train/Test split
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Logistic Regression Model
model = LogisticRegression()
model.fit(X_train, y_train)

# Generate predictions and probabilities for visualization
X_full = np.linspace(min(df['pkt_size']), max(df['pkt_size']), 500).reshape(-1, 1)
X_full_scaled = scaler.transform(X_full)
y_prob = model.predict_proba(X_full_scaled)[:, 1]  # Probability of being malicious

# Plotting
plt.figure(figsize=(10, 6))

# Scatter plot of original data
malicious = df[df['is_malicious'] == 1]
legitimate = df[df['is_malicious'] == 0]
plt.scatter(malicious['pkt_size'], malicious['is_malicious'], color='red', label='Malicious', alpha=0.6)
plt.scatter(legitimate['pkt_size'], legitimate['is_malicious'], color='blue', label='Legitimate', alpha=0.6)

# Logistic Regression decision boundary (sigmoid curve)
plt.plot(X_full, y_prob, color='green', label='Logistic Regression Curve')

# Labels and legend
plt.title("Logistic Regression - Packet Size vs Malicious Traffic")
plt.xlabel("Packet Size (bytes)")
plt.ylabel("Probability of Being Malicious")
plt.axhline(0.5, color='gray', linestyle='--', label='Decision Threshold (0.5)')
plt.legend()
plt.grid(True)
plt.show()
