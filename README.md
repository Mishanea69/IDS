# Hybrid Intrusion Detection System (IDS)

A lightweight, dual-mode intrusion detection system combining **signature-based detection** and **machine learning anomaly detection**, optimized for Raspberry Pi deployment.

## Features

### 🎯 Signature-Based Detection (`pcap2alerts`)
- **Pattern matching**: ASCII (case-sensitive/insensitive) and HEX byte patterns
- **Threshold-based rules**: Detects port scans, brute force attempts, and DDoS via TCP flag rate analysis
- **Fast processing**: Zero-copy packet parsing, ~1M+ packets/sec
- **Multi-protocol**: TCP, UDP with support for Ethernet and Linux cooked capture formats
- **Flexible rules**: SID-based system for easy rule management and severity classification

### 🤖 Anomaly Detection (`train_iforest_flow` / `score_iforest_flow`)
- **Isolation Forest** model trained on normal network flows
- **Flow-based features**: packet counts, bytes, duration, inter-arrival times, TCP flags
- **Unsupervised learning**: No attack labels needed for training
- **Low resource**: Minimal dependencies, suitable for RPi

### 📊 Analysis & Reporting (`analyze_alerts.py`)
- Comprehensive alert dashboards with severity breakdowns
- Per-capture detection statistics
- False positive vs. attack detection rates
- Rule effectiveness metrics

## Architecture

### Processing Pipeline

```
PCAP File
    ↓
[Flow Extraction] → flows.csv
    ↓
[Signature Detection] → alerts.csv (immediate, real-time)
    ↓
[Anomaly Scoring] → scored_flows.csv (post-analysis)
    ↓
[Alert Analysis] → Dashboard (summary statistics)
```

### Three-Layer Detection

1. **Layer 1: Signature Matching** - Known attack patterns (malware, exploits, backdoors)
2. **Layer 2: Threshold Rules** - Behavioral anomalies (port scans, brute force, DDoS)
3. **Layer 3: ML Anomaly** - Statistical deviation from normal flows (zero-day detection)

## Installation

### Prerequisites

**Linux (Ubuntu/Debian/RPi OS):**
```bash
# Install build tools
sudo apt-get update
sudo apt-get install -y build-essential cmake libpcap-dev

# Optional: Python dependencies for ML
sudo apt-get install -y python3 python3-pip
pip3 install pandas scikit-learn numpy joblib
```

**macOS:**
```bash
brew install cmake libpcap
```

### Build

```bash
cd /path/to/IDS
mkdir -p build
cd build
cmake ..
make -j4
cd ..
```

This builds two executables:
- `build/pcap2flows` - Extract network flows from PCAP
- `build/pcap2alerts` - Signature-based IDS engine

## Usage

### Quick Start: Analyze a PCAP File

```bash
# 1. Generate signature-based alerts
./build/pcap2alerts capture.pcap rules.txt alerts.csv

# 2. Extract flows and train ML model (one-time)
bash pcap_to_csv.sh
python3 combine_flows.py
python3 train_iforest_flow.py --in-csv flows_all.csv --normal-pattern normal

# 3. Score specific capture for anomalies
python3 score_iforest_flow.py  # (modify input CSV path in script)

# 4. View summary
python3 analyze_alerts.py
```

### Batch Process Multiple PCAPs

```bash
# Generate alerts from all captures in captures/ directory
sudo ./generate_alerts.sh

# Analyze results
python3 analyze_alerts.py
```

## Rules Format

### Signature Rules (Payload Matching)

```
<SID> <PROTO> [src_port=N] [dst_port=N] [nocase] (ascii|hex) "<pattern>" [msg="description"]
```

**Examples:**

```
# Detect SSH banner
1001 tcp dst_port=22 ascii "SSH-2.0" msg="SSH banner detected"

# Detect SMB protocol (hex pattern)
2001 tcp dst_port=139 hex "ff534d42" msg="SMB1 header (NetBIOS)"

# Detect shell injection attempt (case-insensitive)
2003 tcp nocase ascii "/bin/bash" msg="Bash shell in payload"

# BlackEnergy C&C beacon
4008 tcp dst_port=80 nocase ascii "POST /stat.php" msg="BlackEnergy C&C beacon"
```

### Threshold Rules (Event Counting)

```
<SID> tcp [dst_port=N] event=<TYPE> threshold=N seconds=S track=<MODE> msg="description"
```

**Event types**: `syn`, `fin`, `rst`, `null`, `xmas`  
**Track modes**: `src` (from attacker), `dst` (to target), `both`

**Examples:**

```
# Detect SSH brute force (30 SYN packets to port 22 in 60 seconds from same source)
9001 tcp dst_port=22 event=syn threshold=30 seconds=60 track=src msg="SSH brute force"

# Detect port scan (100 SYN packets in 10 seconds from one source)
9006 tcp event=syn threshold=100 seconds=10 track=src msg="Port scan detected"

# Detect SYN flood (200 SYN packets to one destination in 10 seconds)
9011 tcp event=syn threshold=200 seconds=10 track=dst msg="SYN flood to target"
```

## Output Formats

### Alerts CSV (`alerts/*.csv`)

```csv
ts,rule_sid,rule_msg,proto,src_ip,src_port,dst_ip,dst_port,match_type,match_value,match_offset,payload_len
1705600000.123,1001,"SSH banner detected",tcp,192.168.1.100,49821,10.0.0.1,22,ascii,"SSH-2.0",0,512
1705600001.456,9001,"SSH brute force",tcp,192.168.1.100,0,10.0.0.1,22,threshold,"event=syn n=30 s=60",0,0
```

### Flows CSV (`flows.csv` / `flows_all.csv`)

```csv
src_ip,dst_ip,src_port,dst_port,proto,packets,bytes,payload_bytes,duration_s,iat_mean_s,iat_min_s,iat_max_s,tcp_syn,tcp_fin,tcp_rst,tcp_ack
192.168.1.100,10.0.0.1,49821,22,6,142,8956,3421,15.234,0.107,0.001,0.512,1,1,0,42
```

### Scored Flows (`scored_flows.csv`)

```csv
...,iforest_pred,iforest_score,is_anomaly
...,1,0.75,False
...,-1,-0.42,True
```

## Detection Statistics

Current performance on test dataset (27 captures):

```
Detection Rate: 23/25 attacks detected (92.0%)
False Positives: 0 on normal traffic ✅

Top Attacks Detected:
  - SSH brute force (Hydra)     : 3,090 alerts
  - FTP brute force (Hydra)     :   128 alerts
  - Port scans (UnrealIRCd)     :   120 alerts
  - SMB exploitation (NetBIOS)  :    86 alerts
  - VSFTPD backdoor             :    84 alerts
  - BlackEnergy C&C             :    66 alerts
  - Tomcat manager brute force  :    15 alerts
  - Java RMI exploitation       :     2 alerts

Missed (0-day / distributed DDoS without payload):
  - 0day exploit                :     0 alerts
  - Mirai (pure SYN flood)      :     0 alerts (threshold-based detection applicable)
```

## Performance Characteristics

### Resource Usage (Raspberry Pi 4)

| Metric | Value |
|--------|-------|
| Memory (pcap2alerts) | ~50-100 MB |
| CPU Load (single core) | 15-25% |
| Processing Speed | ~500K-1M packets/sec |
| Rules Loaded | 51 rules |
| Avg Rule Evaluation Time | <1µs per rule |

### Packet Parsing Breakdown

- **Ethernet + IPv4 + TCP/UDP parsing**: <100ns per packet
- **Pattern matching** (simple string search): O(payload_len × pattern_len)
- **Threshold tracking**: O(1) hash table insert + deque management

## Development

### Project Structure

```
IDS/
├── src/
│   ├── pcap2flows.cpp      # Flow extraction engine
│   └── pcap2alerts.cpp     # Signature-based IDS
├── CMakeLists.txt          # Build configuration
├── rules.txt               # Signature and threshold rules
├── combine_flows.py        # Combine per-PCAP flows into single CSV
├── train_iforest_flow.py   # Train Isolation Forest model
├── score_iforest_flow.py   # Score flows with trained model
├── analyze_alerts.py       # Alert analysis dashboard
├── generate_alerts.sh      # Batch processing script
├── ARCHITECTURE.md         # Detailed technical documentation
└── README.md               # This file
```

### Adding New Rules

1. Edit `rules.txt`
2. Use SID range 1000-9999:
   - 1000-1999: Protocol detection
   - 2000-2999: Exploit signatures
   - 3000-3999: Backdoors & RCE
   - 4000-4999: Malware & C&C
   - 5000-5999: Auth attacks
   - 6000-6999: Reconnaissance
   - 7000-7999: Data exfiltration
   - 9000-9999: Threshold rules

3. Rebuild and test:
   ```bash
   ./build/pcap2alerts test.pcap rules.txt alerts.csv
   python3 analyze_alerts.py
   ```

### Adding New Features

**Threshold-based detection enhancements:**
- Support additional TCP flags (ECE, CWR, etc.)
- Add UDP-based events (DNS queries, NTP amplification)
- Implement packet size anomalies

**Signature improvements:**
- Add regex pattern support (advanced mode)
- Implement domain name pattern matching
- Add protocol state machine (TCP handshake verification)

**ML enhancements:**
- Train separate models per protocol/port
- Implement DBSCAN or Isolation Forest ensembles
- Add online learning for streaming data

## Limitations

- **IPv4 only** in v0 (IPv6 support planned)
- **No packet reassembly** (fragmented packets skipped)
- **No stateful protocol parsing** (simple payload matching only)
- **No encrypted traffic analysis** (plaintext only)
- **Mirai detection**: Requires threshold rule tuning per network baseline

## Raspberry Pi Optimization Tips

1. **Reduce rule count** if memory is critical (compile rules subset)
2. **Lower ML complexity**: Set `n_estimators=150` in `train_iforest_flow.py`
3. **Batch processing**: Process PCAPs overnight or in off-hours
4. **Use lighter Python**: Replace pandas with pure Python if RAM < 512MB
5. **Compile with optimizations**: `cmake -DCMAKE_BUILD_TYPE=Release ..`

## Testing

### Test Dataset

Download CICIDS2017 or use local captures:
```bash
# Generate synthetic attack traffic
# or use provided sample captures in captures/
```

### Validation

```bash
# Test against known attack
./build/pcap2alerts captures/hydra_ssh.pcap rules.txt test_alerts.csv

# Check for alerts
grep -c "6005" test_alerts.csv  # Should detect Hydra SSH

# Analyze
python3 analyze_alerts.py
```

## Security Considerations

- **False positives**: Rule tuning required for your network baseline
- **Rule bypass**: Attackers can obfuscate patterns (use threshold rules as complementary defense)
- **Resource exhaustion**: Threshold rules prevent CPU exhaustion from event counting
- **Data privacy**: Analyze captures on isolated network, no cloud transmission


## References

- [libpcap documentation](https://www.tcpdump.org/papers/sniffing-faq.html)
- [Snort/Suricata rule format](https://suricata.io/documentation/rules/)
- [Isolation Forest paper](https://arxiv.org/abs/1012.6224)
- [TCP/IP packet structure](https://www.ietf.org/rfc/rfc791.txt)

## Support

For issues or questions:
1. Check [ARCHITECTURE.md](ARCHITECTURE.md) for technical details
2. Review existing rules in [rules.txt](rules.txt) for examples
3. Run `analyze_alerts.py` to debug detection issues

