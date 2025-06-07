import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Load dataset
df = pd.read_csv("malicious_phish.csv")

# Encode categorical labels
label_encoder = LabelEncoder()
df["label"] = label_encoder.fit_transform(df["type"])  # Converts to binary (Safe=0, Malicious=1)

# Keep only URL and label for BERT input
df = df[["url", "label"]]

# Save processed dataset
df.to_csv("malicious_phish_preprocessed.csv", index=False)

print("✅ Dataset is preprocessed and ready for tokenization.")


