import numpy as np
import pandas as pd

# Seed for reproducibility
np.random.seed(0)

# Generate synthetic data
data = {
    'src_ip': np.random.randint(1, 255, 1000),
    'dst_ip': np.random.randint(1, 255, 1000),
    'pkt_size': np.random.randint(50, 1500, 1000),
    'label': np.random.choice([0, 1], 1000, p=[0.95, 0.05])  # 5% anomalies
}

df = pd.DataFrame(data)
df.to_csv('network_traffic.csv', index=False)
print("Data generated and saved to 'network_traffic.csv'")
