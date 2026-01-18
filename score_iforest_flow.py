import joblib
import pandas as pd
from train_iforest_flow import build_features  # keep feature logic identical

pipe = joblib.load("iforest_flow_pipeline.joblib")

df = pd.read_csv("./flows/distcc_exec_backdoor.csv")
X = build_features(df)

# IsolationForest: predict returns 1 (inlier) or -1 (outlier)
pred = pipe.predict(X)
score = pipe.decision_function(X)  # higher = more normal, lower = more anomalous

out = df.copy()
out["iforest_pred"] = pred
out["iforest_score"] = score
out["is_anomaly"] = (pred == -1)

out.to_csv("scored_flows.csv", index=False)
print("Wrote scored_flows.csv")
print("Anomaly rate:", out["is_anomaly"].mean())