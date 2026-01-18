import glob
import os
import pandas as pd

rows = []
for path in sorted(glob.glob("flows/*.csv")):
    df = pd.read_csv(path)
    df["pcap_file"] = os.path.basename(path).replace(".csv", ".pcap")
    rows.append(df)

all_df = pd.concat(rows, ignore_index=True)
all_df.to_csv("flows_all.csv", index=False)
print("Wrote flows_all.csv with", len(all_df), "rows")