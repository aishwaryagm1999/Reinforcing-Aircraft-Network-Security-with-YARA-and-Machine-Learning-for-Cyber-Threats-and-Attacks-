import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from imblearn.over_sampling import SMOTE
import joblib
from sklearn.feature_extraction import FeatureHasher

# Load and combine data
df1 = pd.read_csv('merged.csv')
df2 = pd.read_csv('anomaly2.csv')
df = pd.concat([df1, df2], ignore_index=True)

# Keep only specified columns
specified_columns = [
    'dur', 'proto', 'state', 'spkts', 'dpkts', 'sbytes', 'rate', 'sttl',
    'dttl', 'sload', 'dload', 'sinpkt', 'swin', 'dwin', 'stcpb', 'dtcpb', 'tcprtt', 'attack_cat'
]
df = df[specified_columns]

# Encode categorical variables
label_encoders = {}
for column in df.select_dtypes(include=['object']).columns:
    label_encoders[column] = LabelEncoder()
    df[column] = label_encoders[column].fit_transform(df[column])

# Convert the dataframe into a list of dictionaries
data_dicts = df.drop('attack_cat', axis=1).to_dict(orient='records')

# Initialize the FeatureHasher
h = FeatureHasher(n_features=1024, input_type='dict')

# Transform your data using FeatureHasher
X_transformed = h.transform(data_dicts)

# Target variable
y = df['attack_cat']

# Balancing the dataset using SMOTE
smote = SMOTE()
X_balanced, y_balanced = smote.fit_resample(X_transformed, y)

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_balanced, y_balanced, test_size=0.2, random_state=42)

# Standardize the features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train.toarray())  # Convert to dense array to fit the scaler
X_test_scaled = scaler.transform(X_test.toarray())  # Convert to dense array to apply the transformation

# Initialize the Random Forest Classifier
rf_classifier = RandomForestClassifier(random_state=42)

# Train the model
rf_classifier.fit(X_train_scaled, y_train)

# Save the Random Forest model, scaler, and label encoders with lzma compression
compression_method = 'lzma'
joblib.dump(rf_classifier, 'random_forest_classifier2.joblib', compress=compression_method)
joblib.dump(scaler, 'scaler2.joblib', compress=compression_method)
joblib.dump(label_encoders, 'label_encoders2.joblib', compress=compression_method)

# Predict on the test data
y_pred = rf_classifier.predict(X_test_scaled)

# Calculate the accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f'Accuracy: {accuracy * 100:.2f}%')
