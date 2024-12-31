import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt

# Step 1: Load data into a DataFrame
df = pd.read_csv("network_traffic.csv")

# Split IP and port for both source and destination
df[['src_ip_address', 'src_port']] = df['src_ip'].str.split(':', expand=True)
df[['dest_ip_address', 'dest_port']] = df['dest_ip'].str.split(':', expand=True)

# Convert ports to numeric
df['src_port'] = df['src_port'].astype(int)
df['dest_port'] = df['dest_port'].astype(int)

# Encode IP addresses using LabelEncoder
encoder_ip = LabelEncoder()
df['src_ip_encoded'] = encoder_ip.fit_transform(df['src_ip_address'])
df['dest_ip_encoded'] = encoder_ip.fit_transform(df['dest_ip_address'])

# Prepare the features for DBSCAN
features = df[['src_ip_encoded', 'src_port', 'dest_ip_encoded', 'dest_port', 'pkt_size']]
scaler = StandardScaler()
features_scaled = scaler.fit_transform(features)

# Apply DBSCAN
dbscan = DBSCAN(eps=1.5, min_samples=2)  # Adjust eps and min_samples as needed
clusters = dbscan.fit_predict(features_scaled)

# Add cluster labels to the original DataFrame
df['cluster'] = clusters

# Perform PCA to reduce dimensions to 2D for visualization
pca = PCA(n_components=2)
features_pca = pca.fit_transform(features_scaled)

# Plot the clusters
plt.figure(figsize=(8, 6))
scatter = plt.scatter(features_pca[:, 0], features_pca[:, 1], c=clusters, cmap='viridis', s=100)
plt.colorbar(scatter, label='Cluster Label')
plt.title('DBSCAN Clustering Results (2D Projection via PCA)')
plt.xlabel('PCA Component 1')
plt.ylabel('PCA Component 2')
plt.grid()
print("showing the data")
plt.show()

# Display the result
# print(df)