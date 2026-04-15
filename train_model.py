"""
train_model.py - Treina modelo de detecção de fraude usando o dataset creditcard.csv
Usa Random Forest com balanceamento de classes para lidar com o desbalanceamento do dataset.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os


def train():
    print("[1/5] Carregando dataset...")
    df = pd.read_csv("creditcard.csv")
    print(f"  → {len(df)} transações carregadas")
    print(f"  → Fraudes: {df['Class'].sum()} ({df['Class'].mean()*100:.2f}%)")

    print("[2/5] Preparando dados...")
    X = df.drop("Class", axis=1)
    y = df["Class"].astype(int)

    scaler = StandardScaler()
    X[["Time", "Amount"]] = scaler.fit_transform(X[["Time", "Amount"]])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("[3/5] Treinando modelo Random Forest...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    print("[4/5] Avaliando modelo...")
    y_pred = model.predict(X_test)
    print("\nMatriz de Confusão:")
    print(confusion_matrix(y_test, y_pred))
    print("\nRelatório de Classificação:")
    print(classification_report(y_test, y_pred, target_names=["Legítima", "Fraude"]))

    print("[5/5] Salvando modelo...")
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/fraud_model.pkl")
    joblib.dump(scaler, "models/scaler.pkl")
    print("  → Modelo salvo em models/fraud_model.pkl")
    print("  → Scaler salvo em models/scaler.pkl")
    print("\nTreinamento concluído!")


if __name__ == "__main__":
    train()
