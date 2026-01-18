# pcap2alerts.cpp - Hybrid IDS Engine Explanation

## Architecture Overview

`pcap2alerts.cpp` is a **signature-based and threshold-based intrusion detection engine** that reads packet capture (PCAP) files and generates security alerts. It implements two detection methods:

1. **Payload-based detection** - pattern matching (ASCII/HEX) in packet content
2. **Threshold-based detection** - counting TCP flag events (SYN, FIN, RST, etc.) to detect scans/floods

---

## Phase 1: Initialization & Setup

### 1.1 Packet Structure Definitions
```cpp
struct EthHdr { ... }  // Ethernet frame header
struct Ipv4Hdr { ... } // IPv4 packet header  
struct TcpHdr { ... }  // TCP segment header
struct UdpHdr { ... }  // UDP datagram header
```
These are **packed structures** (no padding) that overlay directly onto raw packet bytes, enabling zero-copy parsing via `reinterpret_cast`.

### 1.2 Rule Objects
Two key structures maintain detection state:

**AlertKey** - Deduplicates payload matches:
- Tracks `(SID, src_ip, dst_ip, src_port, dst_port, proto)` 
- Prevents alert spam for same flow + rule

**ThKey** - Tracks threshold rule state:
- Similar but flexible based on `track` mode (src/dst/both)
- Maintains history deque of timestamps for rate calculations

---

## Phase 2: Rule Parsing

### 2.1 Rule File Format
```
<SID> <PROTO> [options] (ascii|hex) "<pattern>" [msg="..."]

Examples:
1001 tcp dst_port=22 ascii "SSH-2.0" msg="SSH banner"
9001 tcp dst_port=22 event=syn threshold=30 seconds=60 track=src msg="SSH brute force"
```

### 2.2 parse_rule_line() - Token-by-Token Parsing
```
Input:   "1001 tcp dst_port=22 ascii \"SSH-2.0\" msg=\"SSH banner\""
Tokens:  ["1001", "tcp", "dst_port=22", "ascii", "\"SSH-2.0\"", "msg=\"SSH banner\""]
```

**Tokenizer features:**
- Preserves quoted strings as single tokens
- Strips comments with `#`
- Trims whitespace

**Handlers parse:**
- `dst_port=N` → integer destination port
- `nocase` → case-insensitive matching flag
- `ascii "pattern"` → convert string to bytes
- `hex "ff534d42"` → convert hex string to bytes
- `event=syn threshold=30 seconds=60` → threshold rule config

**Pattern types:**
- **ASCII**: String search (optionally case-insensitive)
- **HEX**: Raw bytes (e.g., `ff 53 4d 42` = SMB header)

---

## Phase 3: Main Packet Processing Loop

### 3.1 Datalink Layer Handling
```cpp
if (dlt == DLT_EN10MB) {
    // Ethernet frame: [MAC dst|MAC src|EtherType|...]
    const EthHdr* eth = reinterpret_cast<const EthHdr*>(data);
    ethertype = ntohs(eth->ethertype);
    offset += 14; // skip Ethernet header
    
    // Handle VLAN tags (0x8100)
    // Keep skipping VLAN headers until we find actual protocol
}
else if (dlt == 113) { // DLT_LINUX_SLL
    // Linux cooked capture: different header format (used in mirai.pcap)
    const SllHdr* sll = reinterpret_cast<const SllHdr*>(data);
    ethertype = ntohs(sll->protocol);
    offset += 16; // skip SLL header
}
```

### 3.2 IPv4 Header Parsing
```cpp
const Ipv4Hdr* ip = reinterpret_cast<const Ipv4Hdr*>(data + offset);

// Extract version (high 4 bits) and IHL (low 4 bits)
uint8_t ver = ip->ver_ihl >> 4;        // Should be 4
uint8_t ihl = (ip->ver_ihl & 0x0F) * 4; // Header length in bytes (20-60)

// Skip fragmented packets (reordering not supported)
uint16_t frag_off = ntohs(ip->flags_frag) & 0x1FFF;
if (frag_off != 0) continue;
```

### 3.3 TCP/UDP Header Parsing
```cpp
if (proto == IPPROTO_TCP) {
    // Extract TCP header at offset: ethernet + IP header
    const TcpHdr* tcp = reinterpret_cast<const TcpHdr*>(data + l4_off);
    
    src_port = ntohs(tcp->src_port);
    dst_port = ntohs(tcp->dst_port);
    tcp_flags = tcp->flags;  // SYN, ACK, FIN, RST, etc.
    
    // Data offset is in high 4 bits: multiply by 4 to get bytes (20-60)
    l4_hdr_len = ((tcp->data_offset_reserved >> 4) & 0x0F) * 4;
}
else if (proto == IPPROTO_UDP) {
    // Simpler: fixed 8-byte header
    const UdpHdr* udp = reinterpret_cast<const UdpHdr*>(data + l4_off);
    src_port = ntohs(udp->src_port);
    dst_port = ntohs(udp->dst_port);
    l4_hdr_len = 8;
}
```

### 3.4 Payload Extraction
```cpp
// Where does the payload start?
size_t l4_payload_off = l4_off + l4_hdr_len;

// How much payload was captured?
size_t cap_payload_len = hdr->caplen - l4_payload_off;

// How much payload was actually in the packet? (from IP total_len)
int computed = total_len - (ihl + l4_hdr_len);

// Take the minimum (truncate if needed)
size_t payload_len = std::min(cap_payload_len, (size_t)computed);
const uint8_t* payload = data + l4_payload_off;
```

---

## Phase 4: Rule Matching

### 4.1 Threshold-Based Rules (Port Scans, Brute Force, DDoS)

When a rule has `is_threshold=true`:

```cpp
// 1. Check if this TCP flag event matches
bool syn = (tcp_flags & 0x02) != 0;  // SYN bit set?
bool ack = (tcp_flags & 0x10) != 0;  // ACK bit set?
match_event = (syn && !ack);         // SYN packet, not SYN-ACK

// 2. Build tracking key based on "track" mode
ThKey k{sid, ip->src, ip->dst, src_port, dst_port, proto};
if (r.track == "src") {
    // Track by source IP (detect attacks FROM a source)
}
else if (r.track == "dst") {
    // Track by destination IP (detect attacks TO a target)
}

// 3. Maintain sliding window of timestamps
auto& dq = th_hist[k];  // deque<double> of timestamps

// Remove timestamps older than threshold_s
while (!dq.empty() && (ts - dq.front()) > threshold_s) {
    dq.pop_front();
}

// Add current timestamp
dq.push_back(ts);

// 4. Check if threshold is exceeded AND enough time passed
if (dq.size() >= threshold_n && (ts - th_last_alert[k]) >= threshold_s) {
    th_last_alert[k] = ts;
    // ALERT!
}
```

**Example**: Rule 9001 = "SSH brute force"
- `event=syn threshold=30 seconds=60 track=src`
- If **30 SYN packets** arrive within **60 seconds** from same source → ALERT
- Prevents spam: only alert once every 60s per source

### 4.2 Payload Pattern Matching (Malware Signatures, Exploits)

When a rule has `is_threshold=false`:

```cpp
// 1. Search for pattern in payload
size_t off_match;
if (r.ptype == PatternType::ASCII && r.nocase) {
    // Case-insensitive search
    off_match = find_bytes_nocase(payload, payload_len, r.pat_bytes);
} else {
    // Case-sensitive or HEX pattern
    off_match = find_bytes(payload, payload_len, r.pat_bytes);
}

if (off_match == npos) continue; // No match, try next rule

// 2. Deduplicate: don't re-alert same flow + rule within 60s
AlertKey ak{sid, ip->src, ip->dst, src_port, dst_port, proto};
auto it = alert_last_ts.find(ak);
if (it != alert_last_ts.end() && (ts - it->second) < 60.0) {
    continue; // Already alerted recently, skip
}
alert_last_ts[ak] = ts;

// 3. Write alert to CSV
out << ts << "," << sid << "," << msg << ","
    << (proto == IPPROTO_TCP ? "tcp" : "udp") << ","
    << ipv4_to_string(ip->src) << "," << src_port << ","
    << ipv4_to_string(ip->dst) << "," << dst_port << ","
    << (r.ptype == PatternType::ASCII ? "ascii" : "hex") << ","
    << "\"" << r.pat_text << "\"" << ","
    << off_match << "," << payload_len << "\n";
```

**Example**: Rule 4008 = "BlackEnergy C&C beacon"
- Pattern: `POST /stat.php`
- Found in payload at offset 127 bytes
- Log: `ts, 4008, "BlackEnergy C&C beacon", tcp, 192.168.1.5, 49821, 10.0.0.1, 80, ascii, "POST /stat.php", 127, 256`

---

## Phase 5: Output CSV Format

```
ts                    → Unix timestamp (floating point)
rule_sid              → Rule ID (1001-9999)
rule_msg              → Human-readable rule name
proto                 → "tcp" or "udp"
src_ip                → Source IP (attacker)
src_port              → Source port
dst_ip                → Destination IP (target)
dst_port              → Destination port
match_type            → "ascii", "hex", or "threshold"
match_value           → Pattern matched or threshold config
match_offset          → Byte offset in payload where pattern found
payload_len           → Total payload size
```

---

## Key Design Decisions

### 1. **Zero-Copy Parsing**
- Packet bytes directly recast to struct pointers
- No copying data → fast processing
- **Trade-off**: Must handle endianness (`ntohs()` for network byte order)

### 2. **Bounded Memory**
- `alert_last_ts` pre-allocated for 200K flows
- `th_hist` grows dynamically but bounded by unique 5-tuples
- Suitable for Raspberry Pi with limited RAM

### 3. **Two-Phase Detection**
- **Payload rules**: Find exact signatures in traffic
- **Threshold rules**: Count events over time windows
- Catches both "known bad" patterns and anomalous behavior

### 4. **Time-Window Deduplication**
- Re-alert after 60 seconds (not permanent silence)
- Matches real IDS behavior (ongoing attacks should trigger again)
- Prevents alert fatigue from single incident

### 5. **Careful Packet Validation**
- Check `caplen` before every pointer dereference
- Handle fragmented packets separately (skipped in v0)
- Handles VLAN tags transparently

---

## Summary: IDS Detection Pipeline

```
PCAP File
    ↓
[Load Rules from rules.txt]
    ↓
For each Packet:
    ├─ Parse Ethernet/SLL → IP → TCP/UDP
    ├─ Extract payload (payload_start, payload_len)
    ├─ For each Rule:
    │   ├─ Check protocol match
    │   ├─ Check port match
    │   ├─ If threshold rule:
    │   │   └─ Count TCP flags in sliding window
    │   │       └─ Alert if threshold_n events in threshold_s seconds
    │   │
    │   └─ If payload rule:
    │       └─ Search for pattern (ASCII/HEX, case-sensitive/insensitive)
    │           └─ Alert if found + time window allows
    │
    └─ Write matching alerts to CSV
    
Output: alerts/capture.csv
```

This hybrid approach makes the IDS **both signature-fast** (known threats) **and anomaly-aware** (DoS, scans).
