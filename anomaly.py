import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
import seaborn as sns
from joblib import dump

# Load and combine data
df1 = pd.read_csv('merged.csv')
df2 = pd.read_csv('anomaly2.csv')
data = pd.concat([df1, df2], ignore_index=True)

# Assuming 'data' is your combined DataFrame after concatenation and initial column drop
metrics_columns = [
    'dur', 'proto', 'state', 'spkts', 'dpkts', 'sbytes', 'rate', 'sttl', 'dttl', 'sload', 'dload', 'sinpkt', 'swin', 'dwin', 'stcpb', 'dtcpb', 'tcprtt','label'
]

# Keep only the specified metrics in the DataFrame
data = data[metrics_columns]

# Randomly select 110,000 unique rows for both label = 0 and label = 1
data_label_0 = data[data['label'] == 0]
data_label_1 = data[data['label'] == 1]

sampled_data_label_0 = data_label_0.sample(n=110000, random_state=42, replace=False)
sampled_data_label_1 = data_label_1.sample(n=110000, random_state=42, replace=False)

# Concatenate the selected rows for both label = 0 and label = 1
balanced_data = pd.concat([sampled_data_label_0, sampled_data_label_1])

# Shuffle the rows in the balanced dataset
balanced_data = balanced_data.sample(frac=1, random_state=42)

# Drop rows with NaN values
balanced_data.dropna(inplace=True)

# Label encoding for categorical columns
label_encoders = {}
categorical_columns = ['proto', 'state']

for col in categorical_columns:
    le = LabelEncoder()
    balanced_data[col] = le.fit_transform(balanced_data[col])
    label_encoders[col] = le

# Split the data into features (X) and target (y)
X = balanced_data.drop(columns=['label'])
y = balanced_data['label']

# Apply SMOTE
sm = SMOTE(random_state=42)
X_res, y_res = sm.fit_resample(X, y)

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_res, y_res, test_size=0.2, random_state=42)

# Define the Random Forest model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)

# Train the Random Forest model
rf_model.fit(X_train, y_train)

# Evaluate the Random Forest model
y_pred = rf_model.predict(X_test)

print(classification_report(y_test, y_pred))

# Plot Confusion Matrix
conf_matrix = confusion_matrix(y_test, y_pred)
sns.heatmap(conf_matrix, annot=True, fmt="d", cmap='Blues')
plt.xlabel('Predicted')
plt.ylabel('True')
plt.title('Confusion Matrix')
plt.show()

# Save the model with compression
compression_method = 'lzma'
dump(rf_model, 'random_forest_model_anomaly_check.joblib', compress=compression_method)

# Save the label encoders
dump(label_encoders, 'label_encoders.joblib', compress=compression_method)

# Calculate accuracy
accuracy = accuracy_score(y_test, y_pred)
accuracy_percentage = accuracy * 100
print(f"Accuracy: {accuracy_percentage:.2f}%")


