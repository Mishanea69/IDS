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

// ============================================================
// Named constants (eliminates magic numbers throughout)
// ============================================================
#ifndef DLT_LINUX_SLL
static constexpr int      DLT_LINUX_SLL   = 113;
#endif
static constexpr uint16_t ETHERTYPE_IP    = 0x0800;
static constexpr uint16_t ETHERTYPE_VLAN  = 0x8100;
static constexpr uint16_t ETHERTYPE_QINQ  = 0x88A8;
static constexpr uint8_t  TCP_FLAG_FIN    = 0x01;
static constexpr uint8_t  TCP_FLAG_SYN    = 0x02;
static constexpr uint8_t  TCP_FLAG_RST    = 0x04;
static constexpr uint8_t  TCP_FLAG_PSH    = 0x08;
static constexpr uint8_t  TCP_FLAG_ACK    = 0x10;
static constexpr uint8_t  TCP_FLAG_URG    = 0x20;
static constexpr uint8_t  TCP_FLAGS_XMAS  = TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG;

// ============================================================
// Signal handling (graceful shutdown in live mode)
// ============================================================
std::atomic<bool>    g_keep_running{true};
std::atomic<pcap_t*> g_live_pcap{nullptr};   // FIX: was raw ptr, now atomic

void signal_handler(int signum) {
    (void)signum;
    const char msg[] = "\n[*] Caught signal, shutting down gracefully...\n";
    ssize_t ignored = write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)ignored;
    g_keep_running = false;
    pcap_t* p = g_live_pcap.load();
    if (p) pcap_breakloop(p);
}

// ============================================================
// Packet header structs
// ============================================================
#pragma pack(push, 1)
struct SllHdr {
    uint16_t pkttype;
    uint16_t hatype;
    uint16_t halen;
    uint8_t  addr[8];
    uint16_t protocol;
};

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

// ============================================================
// FIX: Merged AlertKey / ThKey into a single FlowKey.
// track= controls which fields are populated (zeroed = wildcard).
// ============================================================
struct FlowKey {
    int      sid   = 0;
    uint32_t src   = 0;
    uint32_t dst   = 0;
    uint16_t sport = 0;
    uint16_t dport = 0;
    uint8_t  proto = 0;

    bool operator==(const FlowKey& o) const {
        return sid == o.sid && src == o.src && dst == o.dst &&
               sport == o.sport && dport == o.dport && proto == o.proto;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept {
        size_t h = 1469598103934665603ULL;
        auto mix = [&](uint64_t v) {
            h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        };
        mix((uint64_t)k.sid);
        mix((uint64_t)k.src);
        mix((uint64_t)k.dst);
        mix(((uint64_t)k.sport << 16) | k.dport);
        mix((uint64_t)k.proto);
        return h;
    }
};

// ============================================================
// Helpers
// ============================================================
static inline double ts_to_seconds(const timeval& tv) {
    return static_cast<double>(tv.tv_sec) +
           static_cast<double>(tv.tv_usec) / 1e6;
}

static void ipv4_to_buf(uint32_t ip_be, char buf[INET_ADDRSTRLEN]) {
    in_addr a;
    a.s_addr = ip_be;
    inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN);
}

// ============================================================
// Rule model
// ============================================================
enum class Proto       { Any, TCP, UDP };
enum class PatternType { ASCII, HEX };

// Port list: supports single ports and comma-separated groups like [80,443,8080]
struct PortSet {
    bool any = true;                     // true  → match any port
    std::unordered_set<int> ports;       // false → must be in this set

    bool matches(int p) const {
        return any || ports.count(p) > 0;
    }
};

struct Rule {
    int         sid        = 0;
    Proto       proto      = Proto::Any;
    PortSet     src_ports;               // replaces single src_port int
    PortSet     dst_ports;               // replaces single dst_port int
    bool        nocase     = false;
    PatternType ptype      = PatternType::ASCII;
    std::vector<uint8_t> pat_bytes;
    std::string pat_text;
    std::string msg;

    // Threshold fields
    bool        is_threshold = false;
    std::string event;                   // "syn","fin","rst","null","xmas"
    int         threshold_n  = 0;
    double      threshold_s  = 0.0;
    std::string track        = "src";    // "src","dst","both"
};

// ============================================================
// Tokenizer (preserves quoted strings, strips # comments)
// ============================================================
static std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> toks;
    std::string cur;
    bool in_quotes = false;
    for (char c : line) {
        if (c == '"') { in_quotes = !in_quotes; cur.push_back(c); continue; }
        if (!in_quotes && std::isspace((unsigned char)c)) {
            if (!cur.empty()) { toks.push_back(cur); cur.clear(); }
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
    return is_quoted(s) ? s.substr(1, s.size() - 2) : s;
}
static std::optional<int> parse_int(const std::string& s) {
    try {
        size_t pos = 0;
        int v = std::stoi(s, &pos, 10);
        if (pos != s.size()) return std::nullopt;
        return v;
    } catch (...) { return std::nullopt; }
}

static std::optional<std::vector<uint8_t>> parse_hex_bytes(std::string hex) {
    hex.erase(std::remove_if(hex.begin(), hex.end(),
              [](unsigned char c) { return std::isspace(c); }), hex.end());
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        hex = hex.substr(2);
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
        int hi = hexval(hex[i]), lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

// Parse a Suricata-style hex content like "|ff 53 4d 42|"
static std::optional<std::vector<uint8_t>> parse_pipe_hex(const std::string& s) {
    // Extract the bytes between | |
    std::string inner;
    for (char c : s) {
        if (c == '|') continue;
        inner.push_back(c);
    }
    return parse_hex_bytes(inner);
}

static bool has_pipe_hex(const std::string& s) {
    return s.find('|') != std::string::npos;
}

// Parse port spec: "any", "80", "[80,443,8080]"
static PortSet parse_port_spec(const std::string& s) {
    PortSet ps;
    if (s == "any") return ps;          // ps.any = true

    ps.any = false;
    std::string inner = s;
    // strip brackets
    if (!inner.empty() && inner.front() == '[') inner = inner.substr(1);
    if (!inner.empty() && inner.back()  == ']') inner.pop_back();

    std::istringstream ss(inner);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
        // strip whitespace
        tok.erase(std::remove_if(tok.begin(), tok.end(),
                  [](unsigned char c){ return std::isspace(c); }), tok.end());
        auto v = parse_int(tok);
        if (v) ps.ports.insert(*v);
    }
    if (ps.ports.empty()) ps.any = true; // fallback
    return ps;
}

static Proto parse_proto(const std::string& s) {
    if (s == "tcp")  return Proto::TCP;
    if (s == "udp")  return Proto::UDP;
    return Proto::Any;
}

// ============================================================
// Rule parser — supports BOTH old format and Suricata format
//
// Old format:
//   <sid> <proto> [src_port=N] [dst_port=N] [nocase] (ascii|hex) "<pat>" [msg="..."]
//   <sid> <proto> event=<e> threshold=N seconds=S [track=x] msg="..."
//
// Suricata format:
//   alert <proto> <src_ip> <src_port> -> <dst_ip> <dst_port> (options;)
//   where options include: msg:"..."; content:"..."; nocase; sid:N; threshold:...; etc.
// ============================================================
static std::optional<Rule> parse_suricata_rule(const std::string& line) {
    // Must start with "alert"
    auto toks = tokenize(line);
    if (toks.size() < 8) return std::nullopt;
    if (toks[0] != "alert") return std::nullopt;

    Rule r;
    r.proto = parse_proto(toks[1]);
    // toks[2]=src_ip, toks[3]=src_port, toks[4]="->", toks[5]=dst_ip, toks[6]=dst_port
    r.src_ports = parse_port_spec(toks[3]);
    r.dst_ports = parse_port_spec(toks[6]);

    // Everything from toks[7] onward is the options block (may be "(opt1; opt2;)")
    // Re-join to parse as a single options string
    std::string opts_raw;
    for (size_t i = 7; i < toks.size(); i++) {
        if (i > 7) opts_raw += ' ';
        opts_raw += toks[i];
    }
    // Strip outer parens
    {
        size_t a = opts_raw.find('(');
        size_t b = opts_raw.rfind(')');
        if (a != std::string::npos && b != std::string::npos && b > a)
            opts_raw = opts_raw.substr(a + 1, b - a - 1);
    }

    // Split options on ';' (but not inside quotes)
    std::vector<std::string> opts;
    {
        std::string cur;
        bool inq = false;
        for (char c : opts_raw) {
            if (c == '"') inq = !inq;
            if (c == ';' && !inq) {
                // trim cur
                size_t s2 = cur.find_first_not_of(" \t");
                if (s2 != std::string::npos) {
                    size_t e2 = cur.find_last_not_of(" \t");
                    opts.push_back(cur.substr(s2, e2 - s2 + 1));
                }
                cur.clear();
            } else {
                cur.push_back(c);
            }
        }
        if (!cur.empty()) {
            size_t s2 = cur.find_first_not_of(" \t");
            if (s2 != std::string::npos) opts.push_back(cur.substr(s2));
        }
    }

    bool saw_content = false;
    bool saw_sid     = false;

    // Threshold accumulation
    std::string th_track;
    int    th_count   = 0;
    double th_seconds = 0.0;
    bool   th_present = false;

    for (const auto& opt : opts) {
        // msg:"..."
        if (opt.rfind("msg:", 0) == 0) {
            std::string v = opt.substr(4);
            r.msg = unquote(v);
            continue;
        }
        // content:"|xx xx|" or content:"text"
        if (opt.rfind("content:", 0) == 0) {
            std::string v = unquote(opt.substr(8));
            if (has_pipe_hex(v)) {
                // Suricata pipe-delimited hex embedded in content string
                // Extract all pipe-hex segments and combine into pat_bytes
                r.ptype = PatternType::HEX;
                // Build clean hex from pipe sections
                std::string hex_accum;
                bool in_pipe = false;
                for (char c : v) {
                    if (c == '|') { in_pipe = !in_pipe; continue; }
                    if (in_pipe) hex_accum.push_back(c);
                }
                auto bytes = parse_hex_bytes(hex_accum);
                if (!bytes) continue;
                r.pat_bytes = *bytes;
                r.pat_text  = v;
            } else {
                r.ptype = PatternType::ASCII;
                r.pat_bytes.assign(v.begin(), v.end());
                r.pat_text = v;
            }
            if (!saw_content) saw_content = true; // use first content keyword
            continue;
        }
        // nocase
        if (opt == "nocase") { r.nocase = true; continue; }
        // sid:N
        if (opt.rfind("sid:", 0) == 0) {
            auto v = parse_int(opt.substr(4));
            if (v) { r.sid = *v; saw_sid = true; }
            continue;
        }
        // flags: (ignored — we infer from event= in threshold rules)
        if (opt.rfind("flags:", 0) == 0) continue;
        // threshold: type threshold, track by_src, count N, seconds S
        if (opt.rfind("threshold:", 0) == 0) {
            th_present = true;
            std::string th_body = opt.substr(10);
            // parse sub-fields separated by commas
            std::istringstream ss2(th_body);
            std::string part;
            while (std::getline(ss2, part, ',')) {
                // trim
                size_t a2 = part.find_first_not_of(" \t");
                if (a2 == std::string::npos) continue;
                part = part.substr(a2);

                if (part.rfind("track by_src", 0) == 0) th_track = "src";
                else if (part.rfind("track by_dst", 0) == 0) th_track = "dst";
                else if (part.rfind("track by_both", 0) == 0) th_track = "both";
                else if (part.rfind("count ", 0) == 0) {
                    auto v = parse_int(part.substr(6));
                    if (v) th_count = *v;
                } else if (part.rfind("seconds ", 0) == 0) {
                    try { th_seconds = std::stod(part.substr(8)); } catch (...) {}
                }
            }
            continue;
        }
        // classtype, rev, depth, offset, distance, within, dsize, rawbytes,
        // pcre, http_method, http_header, http_uri, http_user_agent — skip
        // (not needed for our engine)
    }

    if (!saw_sid) return std::nullopt;

    // Threshold rule — infer event from flags keyword presence
    // We detect threshold rules by the presence of threshold: option and
    // a flags: option in the raw opts list, or explicit event= keyword.
    if (th_present) {
        r.is_threshold = true;
        r.threshold_n  = th_count > 0 ? th_count : 10;
        r.threshold_s  = th_seconds > 0 ? th_seconds : 10.0;
        r.track        = th_track.empty() ? "src" : th_track;

        // Infer event from the flags: option we skipped
        // Re-scan raw opts for flags:
        for (const auto& opt : opts) {
            if (opt.rfind("flags:", 0) != 0) continue;
            std::string f = opt.substr(6);
            // strip mask suffix (e.g. "S,12" → "S")
            size_t comma = f.find(',');
            if (comma != std::string::npos) f = f.substr(0, comma);
            // trim
            f.erase(std::remove_if(f.begin(), f.end(),
                    [](unsigned char c){ return std::isspace(c); }), f.end());
            if (f == "S" || f == "s")          r.event = "syn";
            else if (f == "F" || f == "f")     r.event = "fin";
            else if (f == "R" || f == "r")     r.event = "rst";
            else if (f == "0")                 r.event = "null";
            else if (f == "FPU" || f == "fpu") r.event = "xmas";
        }
        if (r.event.empty()) r.event = "syn"; // safe default
        return r;
    }

    if (!saw_content || r.pat_bytes.empty()) return std::nullopt;
    return r;
}

static std::optional<Rule> parse_old_format_rule(const std::vector<std::string>& toks,
                                                  const std::string& line_raw) {
    if (toks.size() < 4) return std::nullopt;

    Rule r;
    auto sid = parse_int(toks[0]);
    if (!sid) return std::nullopt;
    r.sid   = *sid;
    r.proto = parse_proto(toks[1]);

    bool saw_type = false;
    for (size_t i = 2; i < toks.size(); i++) {
        const std::string& t = toks[i];

        if (t.rfind("src_port=", 0) == 0) {
            auto v = parse_int(t.substr(9));
            if (!v) return std::nullopt;
            r.src_ports.any = false;
            r.src_ports.ports.insert(*v);
            continue;
        }
        if (t.rfind("dst_port=", 0) == 0) {
            auto v = parse_int(t.substr(9));
            if (!v) return std::nullopt;
            r.dst_ports.any = false;
            r.dst_ports.ports.insert(*v);
            continue;
        }
        if (t == "nocase")           { r.nocase = true; continue; }
        if (t.rfind("msg=", 0) == 0) { r.msg = unquote(t.substr(4)); continue; }
        if (t.rfind("event=", 0) == 0) {
            r.event = t.substr(6); r.is_threshold = true; continue;
        }
        if (t.rfind("threshold=", 0) == 0) {
            auto v = parse_int(t.substr(10));
            if (!v) return std::nullopt;
            r.threshold_n = *v; r.is_threshold = true; continue;
        }
        if (t.rfind("seconds=", 0) == 0) {
            try { r.threshold_s = std::stod(t.substr(8)); }
            catch (...) { return std::nullopt; }
            r.is_threshold = true; continue;
        }
        if (t.rfind("track=", 0) == 0) {
            r.track = t.substr(6); r.is_threshold = true; continue;
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
            i++;
            continue;
        }
    }

    if (r.is_threshold) {
        if (r.event.empty() || r.threshold_n <= 0 || r.threshold_s <= 0.0)
            return std::nullopt;
        if (r.track != "src" && r.track != "dst" && r.track != "both")
            return std::nullopt;
    } else {
        if (!saw_type || r.pat_bytes.empty()) return std::nullopt;
    }
    return r;
}

static std::optional<Rule> parse_rule_line(const std::string& line_raw, size_t line_no) {
    std::string line = line_raw;

    // Strip # comments
    {
        bool inq = false;
        for (size_t i = 0; i < line.size(); i++) {
            if (line[i] == '"') inq = !inq;
            if (!inq && line[i] == '#') { line = line.substr(0, i); break; }
        }
    }
    // trim
    auto trim = [](std::string& s) {
        size_t a = s.find_first_not_of(" \t\r\n");
        if (a == std::string::npos) { s.clear(); return; }
        size_t b = s.find_last_not_of(" \t\r\n");
        s = s.substr(a, b - a + 1);
    };
    trim(line);
    if (line.empty()) return std::nullopt;

    // Detect format: Suricata rules start with "alert"
    auto toks = tokenize(line);
    if (!toks.empty() && toks[0] == "alert") {
        auto r = parse_suricata_rule(line);
        if (!r) {
            std::cerr << "[WARN] Could not parse Suricata rule at line " << line_no
                      << ": " << line.substr(0, 80) << "\n";
        }
        return r;
    }

    // Old format
    auto r = parse_old_format_rule(toks, line);
    if (!r && !line.empty()) {
        std::cerr << "[WARN] Could not parse rule at line " << line_no
                  << ": " << line.substr(0, 80) << "\n";
    }
    return r;
}

static std::vector<Rule> load_rules(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("Failed to open rules file: " + path);
    std::vector<Rule> rules;
    std::string line;
    size_t ln = 0;
    while (std::getline(in, line)) {
        ln++;
        auto r = parse_rule_line(line, ln);
        if (r) rules.push_back(*r);
    }
    return rules;
}

// ============================================================
// Pattern matching helpers
// ============================================================
static inline uint8_t tolower_ascii(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<uint8_t>(c - 'A' + 'a') : c;
}

static size_t find_bytes_nocase(const uint8_t* hay, size_t hay_len,
                                 const std::vector<uint8_t>& needle) {
    if (needle.empty() || hay_len < needle.size()) return std::string::npos;
    for (size_t i = 0; i + needle.size() <= hay_len; i++) {
        bool ok = true;
        for (size_t j = 0; j < needle.size(); j++) {
            if (tolower_ascii(hay[i + j]) != tolower_ascii(needle[j])) { ok = false; break; }
        }
        if (ok) return i;
    }
    return std::string::npos;
}

static size_t find_bytes(const uint8_t* hay, size_t hay_len,
                          const std::vector<uint8_t>& needle) {
    if (needle.empty() || hay_len < needle.size()) return std::string::npos;
    auto it = std::search(hay, hay + hay_len, needle.begin(), needle.end());
    return (it == hay + hay_len) ? std::string::npos
                                 : static_cast<size_t>(it - hay);
}

static bool proto_matches(Proto r, uint8_t pkt_proto) {
    if (r == Proto::Any) return true;
    if (r == Proto::TCP) return pkt_proto == IPPROTO_TCP;
    if (r == Proto::UDP) return pkt_proto == IPPROTO_UDP;
    return false;
}

// ============================================================
// PacketProcessor — unified for file and live modes
// ============================================================
class PacketProcessor {
public:
    // alert_window_s: dedup window for content rules.
    //   File mode: 60 s  (packets span hours, suppress repeats)
    //   Live mode:  3 s  (FIX: was also 60s, which killed live-mode alerts)
    explicit PacketProcessor(const std::vector<Rule>& rules,
                             std::ofstream& out_stream,
                             double alert_window_s = 60.0)
        : rules_(rules), out_(out_stream), alert_window_s_(alert_window_s)
    {
        alert_last_ts_.reserve(20000);
    }

    void process_packet(const pcap_pkthdr* hdr, const u_char* data, int dlt) {
        pkt_seen_++;

        // Minimum viable check before we do anything else
        if (hdr->caplen < 4) return;
        double ts = ts_to_seconds(hdr->ts);

        size_t   offset    = 0;
        uint16_t ethertype = 0;

        if (dlt == DLT_EN10MB) {
            if (hdr->caplen < sizeof(EthHdr)) return;
            const EthHdr* eth = reinterpret_cast<const EthHdr*>(data);
            ethertype = ntohs(eth->ethertype);
            offset   += sizeof(EthHdr);

            // VLAN / QinQ unwrap
            bool drop = false;
            while (ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ) {
                if (hdr->caplen < offset + sizeof(VlanTag)) { drop = true; break; }
                const VlanTag* vlan = reinterpret_cast<const VlanTag*>(data + offset);
                ethertype = ntohs(vlan->ethertype);
                offset   += sizeof(VlanTag);
            }
            if (drop) return;
        } else if (dlt == DLT_LINUX_SLL) {
            if (hdr->caplen < sizeof(SllHdr)) return;
            const SllHdr* sll = reinterpret_cast<const SllHdr*>(data);
            ethertype = ntohs(sll->protocol);
            offset   += sizeof(SllHdr);
        } else {
            return;
        }

        if (ethertype != ETHERTYPE_IP) return;
        if (hdr->caplen < offset + sizeof(Ipv4Hdr)) return;

        const Ipv4Hdr* ip  = reinterpret_cast<const Ipv4Hdr*>(data + offset);
        uint8_t ver  = ip->ver_ihl >> 4;
        uint8_t ihl  = (ip->ver_ihl & 0x0F) * 4;
        if (ver != 4 || ihl < 20) return;
        if (hdr->caplen < offset + ihl) return;

        uint16_t total_len  = ntohs(ip->total_len);
        if (total_len < ihl) return;

        uint16_t flags_frag = ntohs(ip->flags_frag);
        if ((flags_frag & 0x1FFF) != 0) return; // skip non-first fragments

        uint8_t  proto   = ip->protocol;
        size_t   l4_off  = offset + ihl;

        uint16_t src_port   = 0, dst_port = 0;
        uint8_t  tcp_flags  = 0;
        size_t   l4_hdr_len = 0;

        if (proto == IPPROTO_TCP) {
            if (hdr->caplen < l4_off + sizeof(TcpHdr)) return;
            const TcpHdr* tcp = reinterpret_cast<const TcpHdr*>(data + l4_off);
            src_port    = ntohs(tcp->src_port);
            dst_port    = ntohs(tcp->dst_port);
            tcp_flags   = tcp->flags;
            l4_hdr_len  = ((tcp->data_offset_reserved >> 4) & 0x0F) * 4;
            if (l4_hdr_len < 20) return;
            if (hdr->caplen < l4_off + l4_hdr_len) return;
        } else if (proto == IPPROTO_UDP) {
            if (hdr->caplen < l4_off + sizeof(UdpHdr)) return;
            const UdpHdr* udp = reinterpret_cast<const UdpHdr*>(data + l4_off);
            src_port   = ntohs(udp->src_port);
            dst_port   = ntohs(udp->dst_port);
            l4_hdr_len = 8;
            if (hdr->caplen < l4_off + l4_hdr_len) return;
        } else {
            return;
        }

        pkt_processed_++;

        size_t l4_payload_off = l4_off + l4_hdr_len;
        if (hdr->caplen < l4_payload_off) return;

        size_t cap_payload_len = hdr->caplen - l4_payload_off;
        int    computed = static_cast<int>(total_len) -
                          static_cast<int>(ihl + l4_hdr_len);
        if (computed < 0) computed = 0;

        size_t        payload_len = std::min(cap_payload_len,
                                             static_cast<size_t>(computed));
        const uint8_t* payload   = data + l4_payload_off;

        char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
        bool ip_strings_ready = false; // lazy — only compute when we emit an alert

        for (const auto& r : rules_) {
            if (!proto_matches(r.proto, proto)) continue;
            if (!r.src_ports.matches(static_cast<int>(src_port))) continue;
            if (!r.dst_ports.matches(static_cast<int>(dst_port))) continue;

            // ---- Threshold / flag-event rule ----
            if (r.is_threshold) {
                if (proto != IPPROTO_TCP) continue;

                bool match_event = false;
                if      (r.event == "syn")  match_event = (tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK);
                else if (r.event == "fin")  match_event = (tcp_flags & TCP_FLAG_FIN) != 0;
                else if (r.event == "rst")  match_event = (tcp_flags & TCP_FLAG_RST) != 0;
                else if (r.event == "null") match_event = (tcp_flags == 0);
                else if (r.event == "xmas") match_event = (tcp_flags & TCP_FLAGS_XMAS) == TCP_FLAGS_XMAS;
                else continue;

                if (!match_event) continue;

                // FIX: Key construction respects track= properly.
                // For track=src: only key on src_ip (aggregate across all dst).
                // For track=dst: only key on dst_ip.
                // For track=both: full 5-tuple.
                FlowKey k;
                k.sid   = r.sid;
                k.proto = proto;
                if (r.track == "src") {
                    k.src   = ip->src;
                    k.dst   = 0;       // wildcard — aggregate across all destinations
                    k.sport = 0;
                    k.dport = 0;
                } else if (r.track == "dst") {
                    k.src   = 0;
                    k.dst   = ip->dst; // aggregate across all sources to this target
                    k.sport = 0;
                    k.dport = 0;
                } else { // "both"
                    k.src   = ip->src;
                    k.dst   = ip->dst;
                    k.sport = src_port;
                    k.dport = dst_port;
                }

                auto& dq = th_hist_[k];
                while (!dq.empty() && (ts - dq.front()) > r.threshold_s)
                    dq.pop_front();
                dq.push_back(ts);

                double last = th_last_alert_.count(k) ? th_last_alert_[k] : -1e18;
                if ((int)dq.size() >= r.threshold_n && (ts - last) >= r.threshold_s) {
                    th_last_alert_[k] = ts;
                    if (!ip_strings_ready) {
                        ipv4_to_buf(ip->src, src_buf);
                        ipv4_to_buf(ip->dst, dst_buf);
                        ip_strings_ready = true;
                    }
                    out_ << ts << ','
                         << r.sid << ','
                         << '"' << r.msg << '"' << ','
                         << "tcp" << ','
                         << src_buf << ',' << src_port << ','
                         << dst_buf << ',' << dst_port << ','
                         << "threshold" << ','
                         << '"' << "event=" << r.event
                         << " n=" << r.threshold_n
                         << " s=" << r.threshold_s << '"' << ','
                         << 0 << ',' << 0 << '\n';
                    alert_count_++;
                }

                // FIX: Evict empty deques to prevent unbounded map growth in live mode
                if (dq.empty()) th_hist_.erase(k);

                continue;
            }

            // ---- Content / pattern rule ----
            if (payload_len == 0) continue;

            size_t off_match;
            if (r.ptype == PatternType::ASCII && r.nocase)
                off_match = find_bytes_nocase(payload, payload_len, r.pat_bytes);
            else
                off_match = find_bytes(payload, payload_len, r.pat_bytes);

            if (off_match == std::string::npos) continue;

            // Dedup: suppress repeated alerts for same (sid, flow) within window
            FlowKey ak;
            ak.sid   = r.sid;
            ak.src   = ip->src;
            ak.dst   = ip->dst;
            ak.sport = src_port;
            ak.dport = dst_port;
            ak.proto = proto;

            auto it = alert_last_ts_.find(ak);
            if (it != alert_last_ts_.end() && (ts - it->second) < alert_window_s_)
                continue;
            alert_last_ts_[ak] = ts;

            if (!ip_strings_ready) {
                ipv4_to_buf(ip->src, src_buf);
                ipv4_to_buf(ip->dst, dst_buf);
                ip_strings_ready = true;
            }

            out_ << ts << ','
                 << r.sid << ','
                 << '"' << r.msg << '"' << ','
                 << (proto == IPPROTO_TCP ? "tcp" : "udp") << ','
                 << src_buf << ',' << src_port << ','
                 << dst_buf << ',' << dst_port << ','
                 << (r.ptype == PatternType::ASCII ? "ascii" : "hex") << ','
                 << '"' << r.pat_text << '"' << ','
                 << off_match << ','
                 << payload_len << '\n';
            alert_count_++;
        }

        // FIX: Periodically evict stale alert_last_ts_ entries to cap memory.
        // Run every 65536 processed packets.
        if ((pkt_processed_ & 0xFFFF) == 0) {
            evict_alert_cache(ts);
        }
    }

    uint64_t get_packet_count()    const { return pkt_seen_;      }
    uint64_t get_processed_count() const { return pkt_processed_; }
    uint64_t get_alert_count()     const { return alert_count_;    }

private:
    void evict_alert_cache(double now) {
        for (auto it = alert_last_ts_.begin(); it != alert_last_ts_.end(); ) {
            if ((now - it->second) > alert_window_s_)
                it = alert_last_ts_.erase(it);
            else
                ++it;
        }
    }

    const std::vector<Rule>& rules_;
    std::ofstream&           out_;
    double                   alert_window_s_;

    uint64_t alert_count_   = 0;
    uint64_t pkt_seen_      = 0;
    uint64_t pkt_processed_ = 0;

    // FIX: Both maps now use the unified FlowKey / FlowKeyHash
    std::unordered_map<FlowKey, double,               FlowKeyHash> alert_last_ts_;
    std::unordered_map<FlowKey, std::deque<double>,   FlowKeyHash> th_hist_;
    std::unordered_map<FlowKey, double,               FlowKeyHash> th_last_alert_;
};

// ============================================================
// File mode
// ============================================================
int run_file_mode(const std::string& in_pcap,
                  const std::string& rules_path,
                  const std::string& out_csv) {
    std::vector<Rule> rules;
    try { rules = load_rules(rules_path); }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n"; return 1;
    }
    std::cerr << "[*] Loaded " << rules.size() << " rules from " << rules_path << "\n";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p = pcap_open_offline(in_pcap.c_str(), errbuf);
    if (!p) {
        std::cerr << "[ERROR] pcap_open_offline failed: " << errbuf << "\n"; return 1;
    }

    int dlt = pcap_datalink(p);
    if (dlt != DLT_EN10MB && dlt != DLT_LINUX_SLL) {
        std::cerr << "[ERROR] Unsupported datalink type: " << dlt << "\n";
        pcap_close(p); return 1;
    }

    std::ofstream out(out_csv);
    if (!out) {
        std::cerr << "[ERROR] Failed to open output: " << out_csv << "\n";
        pcap_close(p); return 1;
    }
    out << "ts,rule_sid,rule_msg,proto,src_ip,src_port,dst_ip,dst_port,"
           "match_type,match_value,match_offset,payload_len\n";

    // File mode: 60 s dedup window (packet timestamps span the whole capture)
    PacketProcessor processor(rules, out, 60.0);

    const u_char*  data = nullptr;
    pcap_pkthdr*   hdr  = nullptr;
    uint64_t captured = 0;
    std::cerr << "[*] Processing PCAP file: " << in_pcap << "\n";

    while (true) {
        int rc = pcap_next_ex(p, &hdr, &data);
        if (rc == 0)  continue;
        if (rc == -1) {
            std::cerr << "[ERROR] pcap_next_ex: " << pcap_geterr(p) << "\n"; break;
        }
        if (rc == -2) break; // EOF
        captured++;
        processor.process_packet(hdr, data, dlt);
    }
    pcap_close(p);

    std::cerr << "[*] Captured " << captured
              << ", Seen " << processor.get_packet_count()
              << ", Processed " << processor.get_processed_count()
              << " packets. Wrote " << processor.get_alert_count()
              << " alerts to " << out_csv << "\n";
    return 0;
}

// ============================================================
// Live mode
// ============================================================
int run_live_mode(const std::string& interface,
                  const std::string& rules_path,
                  const std::string& out_csv,
                  int snaplen    = 65535,
                  bool promisc   = true,
                  int timeout_ms = 1000,
                  const std::string& filter = "",
                  double alert_window = 3.0) {  // FIX: 3s default for live mode
    g_keep_running = true;

    std::vector<Rule> rules;
    try { rules = load_rules(rules_path); }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n"; return 1;
    }
    std::cerr << "[*] Loaded " << rules.size() << " rules from " << rules_path << "\n";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p = pcap_open_live(interface.c_str(), snaplen, promisc ? 1 : 0,
                                timeout_ms, errbuf);
    if (!p) {
        std::cerr << "[ERROR] pcap_open_live failed: " << errbuf << "\n";
        std::cerr << "[HINT] May need sudo or CAP_NET_RAW on " << interface << "\n";
        return 1;
    }

    int dlt = pcap_datalink(p);
    if (dlt != DLT_EN10MB && dlt != DLT_LINUX_SLL) {
        std::cerr << "[ERROR] Unsupported datalink type: " << dlt << "\n";
        pcap_close(p); return 1;
    }

    if (!filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(p, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "[ERROR] pcap_compile: " << pcap_geterr(p) << "\n";
            pcap_close(p); return 1;
        }
        if (pcap_setfilter(p, &fp) == -1) {
            std::cerr << "[ERROR] pcap_setfilter: " << pcap_geterr(p) << "\n";
            pcap_freecode(&fp); pcap_close(p); return 1;
        }
        pcap_freecode(&fp);
        std::cerr << "[*] Applied BPF filter: " << filter << "\n";
    }

    std::ofstream out(out_csv);
    if (!out) {
        std::cerr << "[ERROR] Failed to open output: " << out_csv << "\n";
        pcap_close(p); return 1;
    }
    out << "ts,rule_sid,rule_msg,proto,src_ip,src_port,dst_ip,dst_port,"
           "match_type,match_value,match_offset,payload_len\n";
    out.flush();

    // FIX: pass the live-mode alert window (short, e.g. 3 s)
    PacketProcessor processor(rules, out, alert_window);
    g_live_pcap.store(p);

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    std::cerr << "[*] Starting live capture on: " << interface << "\n";
    std::cerr << "[*] Alert dedup window: " << alert_window << " s\n";
    std::cerr << "[*] Snaplen=" << snaplen
              << " Promisc=" << (promisc ? "yes" : "no")
              << " Timeout=" << timeout_ms << "ms\n";
    std::cerr << "[*] Press Ctrl+C to stop...\n";

    const u_char* data = nullptr;
    pcap_pkthdr*  hdr  = nullptr;
    uint64_t      captured = 0;

    auto last_stats = std::chrono::steady_clock::now();
    constexpr int STATS_INTERVAL = 5;

    while (g_keep_running) {
        int rc = pcap_next_ex(p, &hdr, &data);
        if (rc == -1) {
            std::cerr << "[ERROR] pcap_next_ex: " << pcap_geterr(p) << "\n"; break;
        }
        if (rc == -2) break;
        if (rc == 1) {
            captured++;
            processor.process_packet(hdr, data, dlt);
        }

        auto now     = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                           now - last_stats).count();
        if (elapsed >= STATS_INTERVAL) {
            struct pcap_stat ps;
            if (pcap_stats(p, &ps) == 0) {
                std::cerr << "[*] Stats:"
                          << " Recv="    << ps.ps_recv
                          << " Seen="    << processor.get_packet_count()
                          << " Processed=" << processor.get_processed_count()
                          << " Alerts="  << processor.get_alert_count()
                          << " Dropped=" << ps.ps_drop
                          << " IfDrop="  << ps.ps_ifdrop << "\n";
            }
            out.flush();
            last_stats = now;
        }
    }

    std::cerr << "\n[*] Shutting down...\n";
    {
        struct pcap_stat ps;
        if (pcap_stats(p, &ps) == 0) {
            std::cerr << "[*] Final: Recv=" << ps.ps_recv
                      << " Drop=" << ps.ps_drop
                      << " IfDrop=" << ps.ps_ifdrop << "\n";
        }
    }
    g_live_pcap.store(nullptr);
    pcap_close(p);

    std::cerr << "[*] Captured " << captured
              << ", Seen " << processor.get_packet_count()
              << ", Processed " << processor.get_processed_count()
              << " packets. Wrote " << processor.get_alert_count()
              << " alerts to " << out_csv << "\n";
    return 0;
}

// ============================================================
// Usage / interface listing
// ============================================================
void print_usage(const char* prog) {
    std::cerr << "pcap2alerts - Network IDS with file and live capture modes\n\n"
              << "USAGE:\n"
              << "  File mode:  " << prog << " file <input.pcap> <rules> <alerts.csv>\n"
              << "  Live mode:  " << prog << " live <iface>  <rules> <alerts.csv> [opts]\n\n"
              << "LIVE MODE OPTIONS:\n"
              << "  --snaplen=N          Snapshot length (default: 65535)\n"
              << "  --no-promisc         Disable promiscuous mode\n"
              << "  --timeout=N          Read timeout ms (default: 1000)\n"
              << "  --filter=\"...\"       BPF filter (e.g. \"tcp\")\n"
              << "  --alert-window=N     Alert dedup window in seconds (default: 3)\n\n"
              << "RULE FORMATS SUPPORTED:\n"
              << "  Suricata: alert <proto> <src> <sport> -> <dst> <dport> (options;)\n"
              << "  Legacy:   <sid> <proto> [src_port=N] [dst_port=N] [nocase] ascii|hex \"<pat>\" msg=\"...\"\n"
              << "  Legacy:   <sid> <proto> event=<e> threshold=N seconds=S [track=src|dst|both] msg=\"...\"\n\n"
              << "EXAMPLES:\n"
              << "  " << prog << " file capture.pcap rules.rules alerts.csv\n"
              << "  sudo " << prog << " live eth0 rules.rules alerts.csv\n"
              << "  sudo " << prog << " live eth0 rules.rules alerts.csv --alert-window=5\n"
              << "  " << prog << " interfaces\n\n";
}

void list_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[ERROR] pcap_findalldevs: " << errbuf << "\n"; return;
    }
    if (!alldevs) { std::cerr << "[*] No interfaces found\n"; return; }
    std::cerr << "Available interfaces:\n";
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        std::cerr << "  " << d->name;
        if (d->description) std::cerr << " (" << d->description << ")";
        std::cerr << "\n";
    }
    pcap_freealldevs(alldevs);
}

// ============================================================
// main
// ============================================================
int main(int argc, char** argv) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    std::string mode = argv[1];

    if (mode == "interfaces") { list_interfaces(); return 0; }

    if (mode == "file") {
        if (argc < 5) {
            std::cerr << "[ERROR] file mode: file <pcap> <rules> <output.csv>\n"; return 1;
        }
        return run_file_mode(argv[2], argv[3], argv[4]);
    }

    if (mode == "live") {
        if (argc < 5) {
            std::cerr << "[ERROR] live mode: live <iface> <rules> <output.csv> [opts]\n"; return 1;
        }
        std::string interface  = argv[2];
        std::string rules_path = argv[3];
        std::string out_csv    = argv[4];

        int    snaplen      = 65535;
        bool   promisc      = true;
        int    timeout_ms   = 1000;
        double alert_window = 3.0;   // FIX: short default for live mode
        std::string filter;

        for (int i = 5; i < argc; i++) {
            std::string arg = argv[i];
            if      (arg.rfind("--snaplen=", 0) == 0)
                snaplen = std::stoi(arg.substr(10));
            else if (arg == "--no-promisc")
                promisc = false;
            else if (arg.rfind("--timeout=", 0) == 0)
                timeout_ms = std::stoi(arg.substr(10));
            else if (arg.rfind("--alert-window=", 0) == 0)
                alert_window = std::stod(arg.substr(15));
            else if (arg.rfind("--filter=", 0) == 0) {
                filter = arg.substr(9);
                if (filter.size() >= 2 && filter.front() == '"' && filter.back() == '"')
                    filter = filter.substr(1, filter.size() - 2);
            } else {
                std::cerr << "[WARNING] Unknown option: " << arg << "\n";
            }
        }

        return run_live_mode(interface, rules_path, out_csv,
                             snaplen, promisc, timeout_ms, filter, alert_window);
    }

    std::cerr << "[ERROR] Unknown mode: " << mode << "\n";
    print_usage(argv[0]);
    return 1;
}
