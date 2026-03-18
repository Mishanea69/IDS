#include <pcap.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <atomic>
#include <chrono>

// Global flag for signal handling (graceful shutdown in live mode)
std::atomic<bool> g_keep_running{true};
pcap_t* g_live_pcap = nullptr;

void signal_handler(int signum) {
    (void)signum;
    const char msg[] = "\n[*] Caught signal, shutting down gracefully...\n";
    ssize_t ignored = write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)ignored;
    g_keep_running = false;
    if (g_live_pcap != nullptr) {
        pcap_breakloop(g_live_pcap);
    }
}

#pragma pack(push, 1)
struct SllHdr {
    uint16_t pkttype;
    uint16_t hatype;
    uint16_t halen;
    uint8_t  addr[8];
    uint16_t protocol; // like Ethernet ethertype, network order
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthHdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
};

struct VlanTag {
    uint16_t tci;
    uint16_t ethertype;
};

struct Ipv4Hdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t hdr_checksum;
    uint32_t src;
    uint32_t dst;
};

struct TcpHdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset_reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

struct UdpHdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};
#pragma pack(pop)

struct AlertKey {
    int sid;
    uint32_t src;
    uint32_t dst;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;

    bool operator==(const AlertKey& o) const {
        return sid==o.sid && src==o.src && dst==o.dst &&
            sport==o.sport && dport==o.dport && proto==o.proto;
    }
};

struct AlertKeyHash {
    size_t operator()(const AlertKey& k) const noexcept {
        size_t h = 1469598103934665603ULL;
        auto mix = [&](uint64_t v){
        h ^= v + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2);
        };
        mix((uint64_t)k.sid);
        mix((uint64_t)k.src);
        mix((uint64_t)k.dst);
        mix(((uint64_t)k.sport<<16) | k.dport);
        mix((uint64_t)k.proto);
        return h;
    }
};

struct ThKey {
    int sid;
    uint32_t src;
    uint32_t dst;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;

    bool operator==(const ThKey& o) const {
        return sid==o.sid && src==o.src && dst==o.dst && sport==o.sport && dport==o.dport && proto==o.proto;
    }
};

struct ThKeyHash {
    size_t operator()(const ThKey& k) const noexcept {
        size_t h = 1469598103934665603ULL;
        auto mix = [&](uint64_t v){
        h ^= v + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2);
        };
        mix((uint64_t)k.sid);
        mix((uint64_t)k.src);
        mix((uint64_t)k.dst);
        mix(((uint64_t)k.sport<<16) | k.dport);
        mix((uint64_t)k.proto);
        return h;
    }
};

static inline double ts_to_seconds(const timeval& tv) {
    return static_cast<double>(tv.tv_sec) + static_cast<double>(tv.tv_usec) / 1e6;
}

static std::string ipv4_to_string(uint32_t ip_be) {
    char buf[INET_ADDRSTRLEN];
    in_addr a;
    a.s_addr = ip_be;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return std::string(buf);
}

enum class Proto { Any, TCP, UDP };
enum class PatternType { ASCII, HEX };

struct Rule {
    int sid = 0;
    Proto proto = Proto::Any;
    int src_port = -1; // -1 means any
    int dst_port = -1;
    bool nocase = false;
    PatternType ptype = PatternType::ASCII;
    std::vector<uint8_t> pat_bytes; // for HEX, raw bytes; for ASCII, bytes of pattern
    std::string pat_text;           // for debugging / output
    std::string msg;
    // threshold (optional)
    bool is_threshold = false;
    std::string event;     // supports "syn", "fin", "rst", "null", "xmas"
    int threshold_n = 0;
    double threshold_s = 0.0;
    std::string track = "src"; // "src", "dst", or "both"
};

// --- Small tokenizer that preserves quoted strings ---
static std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> toks;
    std::string cur;
    bool in_quotes = false;

    for (size_t i = 0; i < line.size(); i++) {
        char c = line[i];
        if (c == '"') {
        in_quotes = !in_quotes;
        cur.push_back(c);
        continue;
        }
        if (!in_quotes && std::isspace(static_cast<unsigned char>(c))) {
        if (!cur.empty()) {
            toks.push_back(cur);
            cur.clear();
        }
        continue;
        }
        cur.push_back(c);
    }
    if (!cur.empty()) toks.push_back(cur);
    return toks;
}

static bool is_quoted(const std::string& s) {
    return s.size() >= 2 && s.front() == '"' && s.back() == '"';
}

static std::string unquote(const std::string& s) {
    if (is_quoted(s)) return s.substr(1, s.size() - 2);
    return s;
}

static std::optional<int> parse_int(const std::string& s) {
    try {
        size_t pos = 0;
        int v = std::stoi(s, &pos, 10);
        if (pos != s.size()) return std::nullopt;
        return v;
    } catch (...) {
        return std::nullopt;
    }
}

static std::optional<std::vector<uint8_t>> parse_hex_bytes(std::string hex) {
    // allow spaces inside the quoted hex string
    hex.erase(std::remove_if(hex.begin(), hex.end(),
                    [](unsigned char c){ return std::isspace(c); }),
                hex.end());

    // optional 0x prefix
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex = hex.substr(2);
    }
    if (hex.size() % 2 != 0) return std::nullopt;

    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };

    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hexval(hex[i]);
        int lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

static Proto parse_proto(const std::string& s) {
    if (s == "tcp") return Proto::TCP;
    if (s == "udp") return Proto::UDP;
    if (s == "any") return Proto::Any;
    return Proto::Any;
}

static std::optional<Rule> parse_rule_line(const std::string& line_raw) {
    std::string line = line_raw;
    // strip comments
    auto hash = line.find('#');
    if (hash != std::string::npos) line = line.substr(0, hash);

    // trim
    auto ltrim = [](std::string& s){
        s.erase(s.begin(), std::find_if(s.begin(), s.end(),
        [](unsigned char ch){ return !std::isspace(ch); }));
    };
    auto rtrim = [](std::string& s){
        s.erase(std::find_if(s.rbegin(), s.rend(),
        [](unsigned char ch){ return !std::isspace(ch); }).base(), s.end());
    };
    ltrim(line); rtrim(line);
    if (line.empty()) return std::nullopt;

    auto toks = tokenize(line);
    if (toks.size() < 4) return std::nullopt;

    Rule r;

    // Format:
    // <sid> <proto> [src_port=N] [dst_port=N] [nocase] (ascii|hex) "<pattern>" [msg="..."]
    auto sid = parse_int(toks[0]);
    if (!sid) return std::nullopt;
    r.sid = *sid;

    r.proto = parse_proto(toks[1]);

    bool saw_type = false;
    for (size_t i = 2; i < toks.size(); i++) {
        const std::string& t = toks[i];

        if (t.rfind("src_port=", 0) == 0) {
        auto v = parse_int(t.substr(std::string("src_port=").size()));
        if (!v) return std::nullopt;
        r.src_port = *v;
        continue;
        }
        if (t.rfind("dst_port=", 0) == 0) {
        auto v = parse_int(t.substr(std::string("dst_port=").size()));
        if (!v) return std::nullopt;
        r.dst_port = *v;
        continue;
        }
        if (t == "nocase") {
        r.nocase = true;
        continue;
        }
        if (t.rfind("msg=", 0) == 0) {
        std::string mv = t.substr(4);
        r.msg = unquote(mv);
        continue;
        }
        if (t.rfind("event=", 0) == 0) {
        r.event = t.substr(6);
        r.is_threshold = true;
        continue;
        }
        if (t.rfind("threshold=", 0) == 0) {
        auto v = parse_int(t.substr(10));
        if (!v) return std::nullopt;
        r.threshold_n = *v;
        r.is_threshold = true;
        continue;
        }
        if (t.rfind("seconds=", 0) == 0) {
        try {
            r.threshold_s = std::stod(t.substr(8));
        } catch (...) { return std::nullopt; }
        r.is_threshold = true;
        continue;
        }
        if (t.rfind("track=", 0) == 0) {
        r.track = t.substr(6);
        r.is_threshold = true;
        continue;
        }
        if (t == "ascii" || t == "hex") {
        if (i + 1 >= toks.size()) return std::nullopt;
        std::string pat = toks[i + 1];
        if (!is_quoted(pat)) return std::nullopt;
        pat = unquote(pat);
        r.pat_text = pat;

        if (t == "ascii") {
            r.ptype = PatternType::ASCII;
            r.pat_bytes.assign(pat.begin(), pat.end());
        } else {
            r.ptype = PatternType::HEX;
            auto bytes = parse_hex_bytes(pat);
            if (!bytes) return std::nullopt;
            r.pat_bytes = *bytes;
        }
        saw_type = true;
        i++; // consumed pattern
        continue;
        }
    }

    if (!saw_type || r.pat_bytes.empty()) return std::nullopt;

    if (r.is_threshold) {
        if (r.event.empty() || r.threshold_n <= 0 || r.threshold_s <= 0.0) return std::nullopt;
        if (!(r.track == "src" || r.track == "dst" || r.track == "both")) return std::nullopt;
    } else {
        if (!saw_type || r.pat_bytes.empty()) return std::nullopt;
    }

    return r;
}

static std::vector<Rule> load_rules(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("Failed to open rules file: " + path);
    }
    std::vector<Rule> rules;
    std::string line;
    size_t ln = 0;
    while (std::getline(in, line)) {
        ln++;
        auto r = parse_rule_line(line);
        if (!r) continue;
        rules.push_back(*r);
    }
    return rules;
}

static inline uint8_t tolower_ascii(uint8_t c) {
    if (c >= 'A' && c <= 'Z') return static_cast<uint8_t>(c - 'A' + 'a');
    return c;
}

// Returns first match offset or npos
static size_t find_bytes_nocase(const uint8_t* hay, size_t hay_len, const std::vector<uint8_t>& needle) {
    if (needle.empty() || hay_len < needle.size()) return std::string::npos;
    for (size_t i = 0; i + needle.size() <= hay_len; i++) {
        bool ok = true;
        for (size_t j = 0; j < needle.size(); j++) {
        if (tolower_ascii(hay[i + j]) != tolower_ascii(needle[j])) {
            ok = false; break;
        }
        }
        if (ok) return i;
    }
    return std::string::npos;
    }

static size_t find_bytes(const uint8_t* hay, size_t hay_len, const std::vector<uint8_t>& needle) {
    if (needle.empty() || hay_len < needle.size()) return std::string::npos;
    auto it = std::search(hay, hay + hay_len, needle.begin(), needle.end());
    if (it == hay + hay_len) return std::string::npos;
    return static_cast<size_t>(it - hay);
}

static bool proto_matches(Proto r, uint8_t pkt_proto) {
    if (r == Proto::Any) return true;
    if (r == Proto::TCP) return pkt_proto == IPPROTO_TCP;
    if (r == Proto::UDP) return pkt_proto == IPPROTO_UDP;
    return false;
}

// Unified packet processor for both file and live capture modes
class PacketProcessor {
public:
    PacketProcessor(const std::vector<Rule>& rules, std::ofstream& out_stream, double alert_window = 60.0)
        : rules_(rules), out_(out_stream), alert_window_s_(alert_window) {
        alert_last_ts_.reserve(20000);
    }

    void process_packet(const pcap_pkthdr* hdr, const u_char* data, int dlt) {
        pkt_seen_++;
        
        if (hdr->caplen < sizeof(EthHdr)) return;
        double ts = ts_to_seconds(hdr->ts);

        size_t offset = 0;
        uint16_t ethertype = 0;

        if (dlt == DLT_EN10MB) {
            if (hdr->caplen < sizeof(EthHdr)) return;
            const EthHdr* eth = reinterpret_cast<const EthHdr*>(data);
            ethertype = ntohs(eth->ethertype);
            offset += sizeof(EthHdr);

            // VLAN handling (single or stacked tags)
            bool drop = false;
            while (ethertype == 0x8100 || ethertype == 0x88A8) {
                if (hdr->caplen < offset + sizeof(VlanTag)) { drop = true; break; }
                const VlanTag* vlan = reinterpret_cast<const VlanTag*>(data + offset);
                ethertype = ntohs(vlan->ethertype);
                offset += sizeof(VlanTag);
            }
            if (drop) return;
        } else if (dlt == 113 /* DLT_LINUX_SLL */) {
            if (hdr->caplen < sizeof(SllHdr)) return;
            const SllHdr* sll = reinterpret_cast<const SllHdr*>(data);
            ethertype = ntohs(sll->protocol);
            offset += sizeof(SllHdr);
        }

        if (ethertype != 0x0800) return; // IPv4 only
        if (hdr->caplen < offset + sizeof(Ipv4Hdr)) return;

        const Ipv4Hdr* ip = reinterpret_cast<const Ipv4Hdr*>(data + offset);
        uint8_t ver = ip->ver_ihl >> 4;
        uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
        if (ver != 4 || ihl < 20) return;
        if (hdr->caplen < offset + ihl) return;

        uint16_t total_len = ntohs(ip->total_len);
        if (total_len < ihl) return;

        uint16_t flags_frag = ntohs(ip->flags_frag);
        uint16_t frag_off = flags_frag & 0x1FFF;
        if (frag_off != 0) return;

        uint8_t proto = ip->protocol;

        size_t ip_off = offset;
        size_t l4_off = ip_off + ihl;

        uint16_t src_port = 0, dst_port = 0;
        uint8_t tcp_flags = 0;
        size_t l4_hdr_len = 0;

        if (proto == IPPROTO_TCP) {
            if (hdr->caplen < l4_off + sizeof(TcpHdr)) return;
            const TcpHdr* tcp = reinterpret_cast<const TcpHdr*>(data + l4_off);
            src_port = ntohs(tcp->src_port);
            dst_port = ntohs(tcp->dst_port);
            tcp_flags = tcp->flags;
            l4_hdr_len = ((tcp->data_offset_reserved >> 4) & 0x0F) * 4;
            if (l4_hdr_len < 20) return;
            if (hdr->caplen < l4_off + l4_hdr_len) return;
        } else if (proto == IPPROTO_UDP) {
            if (hdr->caplen < l4_off + sizeof(UdpHdr)) return;
            const UdpHdr* udp = reinterpret_cast<const UdpHdr*>(data + l4_off);
            src_port = ntohs(udp->src_port);
            dst_port = ntohs(udp->dst_port);
            l4_hdr_len = 8;
            if (hdr->caplen < l4_off + l4_hdr_len) return;
        } else {
            return;
        }

        pkt_processed_++;

        // Compute payload bounds carefully (caplen-limited)
        size_t l4_payload_off = l4_off + l4_hdr_len;
        if (hdr->caplen < l4_payload_off) return;

        size_t cap_payload_len = hdr->caplen - l4_payload_off;

        // payload len based on IPv4 total_len (may exceed captured)
        int computed = static_cast<int>(total_len) - static_cast<int>(ihl + l4_hdr_len);
        if (computed < 0) computed = 0;

        size_t payload_len = std::min(cap_payload_len, static_cast<size_t>(computed));
        const uint8_t* payload = reinterpret_cast<const uint8_t*>(data + l4_payload_off);

        // Apply rules
        for (const auto& r : rules_) {
            if (!proto_matches(r.proto, proto)) continue;
            if (r.src_port != -1 && r.src_port != static_cast<int>(src_port)) continue;
            if (r.dst_port != -1 && r.dst_port != static_cast<int>(dst_port)) continue;

            // Threshold rule: TCP flag events (no payload needed)
            if (r.is_threshold) {
            if (proto != IPPROTO_TCP) continue;
            
            bool match_event = false;
            if (r.event == "syn") {
                bool syn = (tcp_flags & 0x02) != 0;
                bool ack = (tcp_flags & 0x10) != 0;
                match_event = (syn && !ack);
            } else if (r.event == "fin") {
                match_event = (tcp_flags & 0x01) != 0;
            } else if (r.event == "rst") {
                match_event = (tcp_flags & 0x04) != 0;
            } else if (r.event == "null") {
                match_event = (tcp_flags == 0);
            } else if (r.event == "xmas") {
                match_event = ((tcp_flags & 0x29) == 0x29); // FIN|PSH|URG
            } else {
                continue;
            }
            
            if (!match_event) continue;

            // Build key based on track mode
            ThKey k{r.sid, 0, 0, 0, 0, proto};
            if (r.track == "src") {
                k.src = ip->src;
                k.dst = ip->dst;
                k.sport = src_port;
                k.dport = dst_port;
            } else if (r.track == "dst") {
                k.src = ip->dst;
                k.dst = ip->src;
                k.sport = dst_port;
                k.dport = src_port;
            } else { // "both"
                k.src = ip->src;
                k.dst = ip->dst;
                k.sport = src_port;
                k.dport = dst_port;
            }

            auto& dq = th_hist_[k];

            while (!dq.empty() && (ts - dq.front()) > r.threshold_s) dq.pop_front();
            dq.push_back(ts);

            double last = th_last_alert_.count(k) ? th_last_alert_[k] : -1e18;
            if ((int)dq.size() >= r.threshold_n && (ts - last) >= r.threshold_s) {
                th_last_alert_[k] = ts;
                out_ << ts << ","
                    << r.sid << ","
                    << "\"" << r.msg << "\"" << ","
                    << "tcp" << ","
                    << ipv4_to_string(ip->src) << ","
                    << src_port << ","
                    << ipv4_to_string(ip->dst) << ","
                    << dst_port << ","
                    << "threshold" << ","
                    << "\"event=" << r.event << " n=" << r.threshold_n << " s=" << r.threshold_s << "\"" << ","
                    << 0 << ","
                    << 0
                    << "\n";
                alert_count_++;
            }

            continue;
            }

            if (payload_len == 0) continue;

            size_t off_match = std::string::npos;
            if (r.ptype == PatternType::ASCII && r.nocase) {
                off_match = find_bytes_nocase(payload, payload_len, r.pat_bytes);
            } else {
                off_match = find_bytes(payload, payload_len, r.pat_bytes);
            }
            if (off_match == std::string::npos) continue;

            AlertKey ak{r.sid, ip->src, ip->dst, src_port, dst_port, proto};
            auto it = alert_last_ts_.find(ak);
            if (it != alert_last_ts_.end() && (ts - it->second) < alert_window_s_) continue;
            alert_last_ts_[ak] = ts;

            // Alert
            out_ << ts << ","
                << r.sid << ","
                << "\"" << r.msg << "\"" << ","
                << (proto == IPPROTO_TCP ? "tcp" : "udp") << ","
                << ipv4_to_string(ip->src) << ","
                << src_port << ","
                << ipv4_to_string(ip->dst) << ","
                << dst_port << ","
                << (r.ptype == PatternType::ASCII ? "ascii" : "hex") << ","
                << "\"" << r.pat_text << "\"" << ","
                << off_match << ","
                << payload_len
                << "\n";
            alert_count_++;
        }
    }

    uint64_t get_packet_count() const { return pkt_seen_; }
    uint64_t get_processed_count() const { return pkt_processed_; }
    uint64_t get_alert_count() const { return alert_count_; }

private:
    const std::vector<Rule>& rules_;
    std::ofstream& out_;
    double alert_window_s_;
    
    uint64_t alert_count_ = 0;
    uint64_t pkt_seen_ = 0;
    uint64_t pkt_processed_ = 0;

    std::unordered_map<AlertKey, double, AlertKeyHash> alert_last_ts_;
    std::unordered_map<ThKey, std::deque<double>, ThKeyHash> th_hist_;
    std::unordered_map<ThKey, double, ThKeyHash> th_last_alert_;
};

// File mode: process PCAP file
int run_file_mode(const std::string& in_pcap, const std::string& rules_path, const std::string& out_csv) {
    std::vector<Rule> rules;
    try {
        rules = load_rules(rules_path);
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }
    std::cerr << "[*] Loaded " << rules.size() << " rules from " << rules_path << "\n";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p = pcap_open_offline(in_pcap.c_str(), errbuf);
    if (!p) {
        std::cerr << "[ERROR] pcap_open_offline failed: " << errbuf << "\n";
        return 1;
    }

    int dlt = pcap_datalink(p);
    if (!(dlt == DLT_EN10MB || dlt == 113 /* DLT_LINUX_SLL */)) {
        std::cerr << "[ERROR] Unsupported datalink type: " << dlt << " (supported: Ethernet=1, SLL=113)\n";
        pcap_close(p);
        return 1;
    }

    std::ofstream out(out_csv);
    if (!out) {
        std::cerr << "[ERROR] Failed to open output: " << out_csv << "\n";
        pcap_close(p);
        return 1;
    }

    out << "ts,rule_sid,rule_msg,proto,src_ip,src_port,dst_ip,dst_port,match_type,match_value,match_offset,payload_len\n";

    PacketProcessor processor(rules, out);

    const u_char* data = nullptr;
    pcap_pkthdr* hdr = nullptr;
    uint64_t captured_packets = 0;

    std::cerr << "[*] Processing PCAP file: " << in_pcap << "\n";

    while (true) {
        int rc = pcap_next_ex(p, &hdr, &data);
        if (rc == 0) continue;
        if (rc == -1) {
            std::cerr << "[ERROR] pcap_next_ex error: " << pcap_geterr(p) << "\n";
            break;
        }
        if (rc == -2) break; // EOF

        captured_packets++;
        processor.process_packet(hdr, data, dlt);
    }

    pcap_close(p);
    std::cerr << "[*] Captured " << captured_packets
              << ", Seen " << processor.get_packet_count()
              << ", Processed " << processor.get_processed_count() << " packets. ";
    std::cerr << "Wrote " << processor.get_alert_count() << " alerts to " << out_csv << "\n";
    return 0;
}

// Live mode: capture from network interface
int run_live_mode(const std::string& interface, const std::string& rules_path, const std::string& out_csv,
                  int snaplen = 65535, bool promisc = true, int timeout_ms = 1000, const std::string& filter = "") {
    g_keep_running = true;
    
    std::vector<Rule> rules;
    try {
        rules = load_rules(rules_path);
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }
    std::cerr << "[*] Loaded " << rules.size() << " rules from " << rules_path << "\n";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p = pcap_open_live(interface.c_str(), snaplen, promisc ? 1 : 0, timeout_ms, errbuf);
    if (!p) {
        std::cerr << "[ERROR] pcap_open_live failed: " << errbuf << "\n";
        std::cerr << "[HINT] Make sure you have permission to capture on " << interface << " (may need sudo)\n";
        return 1;
    }

    int dlt = pcap_datalink(p);
    if (!(dlt == DLT_EN10MB || dlt == 113 /* DLT_LINUX_SLL */)) {
        std::cerr << "[ERROR] Unsupported datalink type: " << dlt << " (supported: Ethernet=1, SLL=113)\n";
        pcap_close(p);
        return 1;
    }

    // Apply BPF filter if provided
    if (!filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(p, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "[ERROR] pcap_compile failed: " << pcap_geterr(p) << "\n";
            pcap_close(p);
            return 1;
        }
        if (pcap_setfilter(p, &fp) == -1) {
            std::cerr << "[ERROR] pcap_setfilter failed: " << pcap_geterr(p) << "\n";
            pcap_freecode(&fp);
            pcap_close(p);
            return 1;
        }
        pcap_freecode(&fp);
        std::cerr << "[*] Applied BPF filter: " << filter << "\n";
    }

    std::ofstream out(out_csv);
    if (!out) {
        std::cerr << "[ERROR] Failed to open output: " << out_csv << "\n";
        pcap_close(p);
        return 1;
    }

    out << "ts,rule_sid,rule_msg,proto,src_ip,src_port,dst_ip,dst_port,match_type,match_value,match_offset,payload_len\n";
    out.flush();

    PacketProcessor processor(rules, out);
    g_live_pcap = p;

    // Setup signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::cerr << "[*] Starting live capture on interface: " << interface << "\n";
    std::cerr << "[*] Snaplen: " << snaplen << ", Promisc: " << (promisc ? "yes" : "no") << ", Timeout: " << timeout_ms << "ms\n";
    std::cerr << "[*] Press Ctrl+C to stop...\n";

    const u_char* data = nullptr;
    pcap_pkthdr* hdr = nullptr;
    uint64_t captured_packets = 0;

    auto last_stats_time = std::chrono::steady_clock::now();
    const int stats_interval_sec = 5;

    while (g_keep_running) {
        int rc = pcap_next_ex(p, &hdr, &data);
        if (rc == -1) {
            std::cerr << "[ERROR] pcap_next_ex error: " << pcap_geterr(p) << "\n";
            break;
        }
        if (rc == -2) break; // should not happen in live mode

        if (rc == 1) {
            captured_packets++;
            processor.process_packet(hdr, data, dlt);
        }

        // Print periodic statistics
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time).count();
        if (elapsed >= stats_interval_sec) {
            struct pcap_stat ps;
            if (pcap_stats(p, &ps) == 0) {
                std::cerr << "[*] Stats: Captured=" << ps.ps_recv
                          << ", Seen=" << processor.get_packet_count()
                          << ", Processed=" << processor.get_processed_count()
                          << ", Alerts=" << processor.get_alert_count()
                          << ", Dropped=" << ps.ps_drop
                          << ", IfDropped=" << ps.ps_ifdrop << "\n";
            }
            out.flush();
            last_stats_time = now;
        }
    }

    std::cerr << "\n[*] Shutting down...\n";
    
    // Final statistics
    struct pcap_stat ps;
    if (pcap_stats(p, &ps) == 0) {
        std::cerr << "[*] Final stats - Received: " << ps.ps_recv
                  << ", Dropped: " << ps.ps_drop
                  << ", Interface dropped: " << ps.ps_ifdrop << "\n";
    }

    g_live_pcap = nullptr;
    pcap_close(p);
    std::cerr << "[*] Captured " << captured_packets
              << ", Seen " << processor.get_packet_count()
              << ", Processed " << processor.get_processed_count() << " packets. ";
    std::cerr << "Wrote " << processor.get_alert_count() << " alerts to " << out_csv << "\n";
    return 0;
}

void print_usage(const char* prog) {
    std::cerr << "pcap2alerts - Network packet analyzer with dual-mode operation\n\n";
    std::cerr << "USAGE:\n";
    std::cerr << "  File mode:  " << prog << " file <input.pcap> <rules.txt> <alerts.csv>\n";
    std::cerr << "  Live mode:  " << prog << " live <interface> <rules.txt> <alerts.csv> [options]\n\n";
    std::cerr << "LIVE MODE OPTIONS:\n";
    std::cerr << "  --snaplen=N         Snapshot length (default: 65535)\n";
    std::cerr << "  --no-promisc        Disable promiscuous mode (default: enabled)\n";
    std::cerr << "  --timeout=N         Read timeout in milliseconds (default: 1000)\n";
    std::cerr << "  --filter=\"...\"      BPF filter expression (e.g., \"tcp port 80\")\n\n";
    std::cerr << "RULE FORMAT:\n";
    std::cerr << "  <sid> <proto> [src_port=N] [dst_port=N] [nocase] (ascii|hex) \"<pattern>\" [msg=\"...\"]\n";
    std::cerr << "  <sid> <proto> event=<event> threshold=N seconds=S [track=src|dst|both] msg=\"...\"\n\n";
    std::cerr << "EXAMPLES:\n";
    std::cerr << "  # Process PCAP file\n";
    std::cerr << "  " << prog << " file capture.pcap rules.txt alerts.csv\n\n";
    std::cerr << "  # Live capture on eth0\n";
    std::cerr << "  sudo " << prog << " live eth0 rules.txt alerts.csv\n\n";
    std::cerr << "  # Live capture with custom options\n";
    std::cerr << "  sudo " << prog << " live eth0 rules.txt alerts.csv --snaplen=1514 --filter=\"tcp\"\n\n";
    std::cerr << "  # List available interfaces\n";
    std::cerr << "  " << prog << " interfaces\n\n";
}

void list_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[ERROR] pcap_findalldevs failed: " << errbuf << "\n";
        return;
    }

    if (!alldevs) {
        std::cerr << "[*] No interfaces found\n";
        return;
    }

    std::cerr << "Available network interfaces:\n";
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::cerr << "  " << d->name;
        if (d->description) {
            std::cerr << " (" << d->description << ")";
        }
        std::cerr << "\n";
    }

    pcap_freealldevs(alldevs);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "interfaces") {
        list_interfaces();
        return 0;
    }

    if (mode == "file") {
        if (argc < 5) {
            std::cerr << "[ERROR] File mode requires: file <input.pcap> <rules.txt> <alerts.csv>\n";
            return 1;
        }
        return run_file_mode(argv[2], argv[3], argv[4]);
    }

    if (mode == "live") {
        if (argc < 5) {
            std::cerr << "[ERROR] Live mode requires: live <interface> <rules.txt> <alerts.csv> [options]\n";
            return 1;
        }

        std::string interface = argv[2];
        std::string rules_path = argv[3];
        std::string out_csv = argv[4];

        // Parse optional arguments
        int snaplen = 65535;
        bool promisc = true;
        int timeout_ms = 1000;
        std::string filter;

        for (int i = 5; i < argc; i++) {
            std::string arg = argv[i];
            if (arg.rfind("--snaplen=", 0) == 0) {
                snaplen = std::stoi(arg.substr(10));
            } else if (arg == "--no-promisc") {
                promisc = false;
            } else if (arg.rfind("--timeout=", 0) == 0) {
                timeout_ms = std::stoi(arg.substr(10));
            } else if (arg.rfind("--filter=", 0) == 0) {
                filter = arg.substr(9);
                // Remove surrounding quotes if present
                if (filter.size() >= 2 && filter.front() == '"' && filter.back() == '"') {
                    filter = filter.substr(1, filter.size() - 2);
                }
            } else {
                std::cerr << "[WARNING] Unknown option: " << arg << "\n";
            }
        }

        return run_live_mode(interface, rules_path, out_csv, snaplen, promisc, timeout_ms, filter);
    }

    std::cerr << "[ERROR] Unknown mode: " << mode << "\n";
    print_usage(argv[0]);
    return 1;
}
