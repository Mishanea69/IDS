import argparse
import joblib
import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder


COMMON_SERVICE_PORTS = {
    80: "http", 443: "https", 53: "dns", 22: "ssh", 25: "smtp",
    110: "pop3", 143: "imap", 21: "ftp", 23: "telnet", 3389: "rdp",
}

def port_bucket(p: int) -> str:
    if p <= 0:
        return "unknown"
    if p <= 1023:
        return "well_known"
    if p <= 49151:
        return "registered"
    return "ephemeral"

def build_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    base_numeric = [
        "packets", "bytes", "payload_bytes",
        "duration_s", "iat_mean_s", "iat_min_s", "iat_max_s",
        "tcp_syn", "tcp_fin", "tcp_rst", "tcp_ack",
        "src_port", "dst_port", "proto",
    ]
    for c in base_numeric:
        if c not in df.columns:
            df[c] = 0
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

    df["bytes_per_packet"] = df["bytes"] / np.maximum(df["packets"], 1)
    df["payload_ratio"] = df["payload_bytes"] / np.maximum(df["bytes"], 1)
    df["pps"] = df["packets"] / np.maximum(df["duration_s"], 1e-9)
    df["bps"] = df["bytes"] / np.maximum(df["duration_s"], 1e-9)

    df["syn_rate"] = df["tcp_syn"] / np.maximum(df["packets"], 1)
    df["rst_rate"] = df["tcp_rst"] / np.maximum(df["packets"], 1)

    proto_map = {6: "tcp", 17: "udp"}
    df["proto_name"] = df["proto"].map(proto_map).fillna("other")

    df["dst_port_bucket"] = df["dst_port"].astype(int).map(port_bucket)
    df["service_guess"] = df["dst_port"].astype(int).map(COMMON_SERVICE_PORTS).fillna("other")

    # Drop raw IPs for v0 (they cause overfitting across datasets)
    for c in ["src_ip", "dst_ip"]:
        if c in df.columns:
            df = df.drop(columns=[c])

    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", default="flows_all.csv")
    ap.add_argument("--normal-pattern", default="normal", help="substring to identify 'normal' pcaps, e.g. 'normal'")
    ap.add_argument("--model-out", default="iforest_flow_pipeline.joblib")
    ap.add_argument("--contamination", type=float, default=0.02, help="expected anomaly fraction in NORMAL training data")
    ap.add_argument("--random-state", type=int, default=42)
    args = ap.parse_args()

    df = pd.read_csv(args.in_csv)

    if "pcap_file" not in df.columns:
        raise SystemExit("flows_all.csv must include pcap_file column (run combine_flows.py).")

    normal_df = df[df["pcap_file"].str.contains(args.normal_pattern, case=False, na=False)].copy()
    if len(normal_df) == 0:
        raise SystemExit(f"No rows matched normal-pattern='{args.normal_pattern}'. "
                         f"Check your filenames (e.g., normal.pcap, normal2.pcap).")

    X_train = build_features(normal_df)

    cat_cols = [c for c in ["proto_name", "dst_port_bucket", "service_guess"] if c in X_train.columns]
    num_cols = [c for c in X_train.columns if c not in cat_cols and c not in ["pcap_file"]]

    pre = ColumnTransformer(
        transformers=[
            ("num", MinMaxScaler(), num_cols),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), cat_cols),
        ],
        remainder="drop",
    )

    model = IsolationForest(
        n_estimators=300,
        contamination=args.contamination,
        random_state=args.random_state,
        n_jobs=-1,
    )

    pipe = Pipeline(steps=[("pre", pre), ("iforest", model)])
    pipe.fit(X_train)

    joblib.dump(pipe, args.model_out)
    print(f"Saved model pipeline to: {args.model_out}")
    print(f"Trained on {len(X_train)} normal flows from pcaps matching '{args.normal_pattern}'")


if __name__ == "__main__":
    main()