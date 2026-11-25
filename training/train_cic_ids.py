import pandas as pd
import numpy as np
import xgboost as xgb
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

# Path to CSE-CIC-IDS2018 CSV data
DATA_PATH = "./data/cic_ids_2018/"
FEATURES = ['Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'Fwd Pkt Len Max']

full_data_list = []

if os.path.exists(DATA_PATH):
    files = [f for f in os.listdir(DATA_PATH) if f.endswith('.csv')]
    print(f"[*] Found {len(files)} dataset files. Processing chunks...")
    
    for file in files:
        try:
            df_chunk = pd.read_csv(os.path.join(DATA_PATH, file), usecols=FEATURES + ['Label'])
            for col in FEATURES:
                df_chunk[col] = pd.to_numeric(df_chunk[col], errors='coerce')
            df_chunk = df_chunk.replace([np.inf, -np.inf], np.nan).dropna()
            sample_size = min(len(df_chunk), 100000)
            full_data_list.append(df_chunk.sample(n=sample_size, random_state=42))
        except Exception as e:
            print(f"    [!] Error reading {file}: {e}")

    df = pd.concat(full_data_list, ignore_index=True)
    X = df[FEATURES].astype('float32')
    attack_encoder = LabelEncoder()
    y = attack_encoder.fit_transform(df['Label'])

    # Stratified 80/20 train-test split to preserve rare attack class distributions
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    print(f"[*] Training XGBoost Classifier on {len(X_train)} samples...")
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        tree_method='hist',
        objective='multi:softprob'
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n[+] Model Evaluation Report:")
    print(classification_report(y_test, y_pred, target_names=attack_encoder.classes_))

    os.makedirs("./models", exist_ok=True)
    joblib.dump(model, "./models/phase1_model.pkl")
    joblib.dump(attack_encoder, "./models/attack_encoder.pkl")
    joblib.dump(FEATURES, "./models/feature_columns.pkl")
    print("[*] Successfully exported model artifacts to ./models/")
else:
    print(f"[!] Please place CSE-CIC-IDS2018 CSV files in {DATA_PATH} to run training.")
