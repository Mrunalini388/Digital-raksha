import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load dataset
df = pd.read_csv('Phishing_dataset.csv')

print("Columns in CSV:", df.columns)

# Drop 'id' and label from features
X = df.drop(columns=['id', 'CLASS_LABEL'])
y = df['CLASS_LABEL']

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Save the trained model
joblib.dump(model, 'model.joblib')

print("Model trained and saved successfully.")



