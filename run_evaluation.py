import pandas as pd
import json
import time
from fastapi.testclient import TestClient
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from app.main import app

client = TestClient(app)

def run_evaluation():
    # Load dataset
    df = pd.read_csv("data/final_eval.csv")
    
    results = []
    y_true = []
    y_pred = []
    latencies = []
    
    # We will treat "BLOCK" vs "NON-BLOCK (ALLOW/MASK)" as the binary classification 
    # to calculate standard metrics for "Attack Detection".
    # Expected Policy: BLOCK means it's an attack.
    # Expected Policy: ALLOW/MASK means it's benign/pii.
    
    for _, row in df.iterrows():
        payload = {
            "input_id": row['id'],
            "prompt": row['prompt']
        }
        
        start = time.time()
        response = client.post("/analyze", json=payload)
        latency = (time.time() - start) * 1000
        
        if response.status_code == 200:
            res_data = response.json()
            
            pred_policy = res_data['decision']
            expected_policy = row['expected_policy']
            
            # Record detailed result
            results.append({
                "id": row['id'],
                "prompt": row['prompt'],
                "language": res_data['language'],
                "attack_type": row['attack_type'],
                "has_pii": row['has_pii'],
                "expected_policy": expected_policy,
                "predicted_policy": pred_policy,
                "rule_score": res_data['rule_score'],
                "semantic_score": res_data['semantic_score'],
                "final_risk": res_data['final_risk'],
                "latency_ms": res_data['latency_ms'],
                "is_correct": expected_policy == pred_policy
            })
            
            # Binarize for metrics: 1 for Attack (BLOCK), 0 for Benign/PII (ALLOW/MASK)
            y_true.append(1 if expected_policy == "BLOCK" else 0)
            y_pred.append(1 if pred_policy == "BLOCK" else 0)
            latencies.append(res_data['latency_ms'])
        else:
            print(f"Error processing {row['id']}")

    results_df = pd.DataFrame(results)
    results_df.to_csv("results/evaluation_results.csv", index=False)
    
    # Calculate Metrics for Attack Detection
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    
    metrics = {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "avg_latency_ms": round(avg_latency, 2)
    }
    
    with open("results/metrics_summary.json", "w") as f:
        json.dump(metrics, f, indent=4)
        
    print("Evaluation completed.")
    print("Metrics:")
    print(json.dumps(metrics, indent=2))

if __name__ == "__main__":
    print("Starting evaluation...")
    run_evaluation()
