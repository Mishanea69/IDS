#include <pcap.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <unordered_map>
#include <cmath>

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
    uint8_t  ver_ihl;      // version(4) + IHL(4)
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;   // flags(3) + frag offset(13)
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
    uint8_t  data_offset_reserved; // data offset in high 4 bits
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

static inline double ts_to_seconds(const timeval& tv) {
    return static_cast<double>(tv.tv_sec) + static_cast<double>(tv.tv_usec) / 1e6;
}

struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;

    bool operator==(const FlowKey& o) const {
        return src_ip == o.src_ip && dst_ip == o.dst_ip &&
            src_port == o.src_port && dst_port == o.dst_port &&
            proto == o.proto;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept {
        // Simple hash combine
        size_t h = 1469598103934665603ULL;
        auto mix = [&](uint64_t v) {
        h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        };
        mix(k.src_ip);
        mix(k.dst_ip);
        mix((static_cast<uint32_t>(k.src_port) << 16) | k.dst_port);
        mix(k.proto);
        return h;
    }
};

struct FlowStats {
    double first_ts = 0.0;
    double last_ts  = 0.0;
    double last_pkt_ts = 0.0;

    uint64_t packets = 0;
    uint64_t bytes   = 0;

    // Inter-arrival time (IAT)
    double iat_sum = 0.0;
    double iat_min = std::numeric_limits<double>::infinity();
    double iat_max = 0.0;

    // TCP flags counts (if proto==TCP)
    uint64_t tcp_syn = 0;
    uint64_t tcp_fin = 0;
    uint64_t tcp_rst = 0;
    uint64_t tcp_ack = 0;

    // Payload bytes (L4 payload)
    uint64_t payload_bytes = 0;
};

static std::string ipv4_to_string(uint32_t ip_be) {
    char buf[INET_ADDRSTRLEN];
    in_addr a;
    a.s_addr = ip_be;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return std::string(buf);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input.pcap|pcapng> <output.csv>\n";
        return 1;
    }
    const std::string in_path  = argv[1];
    const std::string out_path = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p = pcap_open_offline(in_path.c_str(), errbuf);
    if (!p) {
        std::cerr << "pcap_open_offline failed: " << errbuf << "\n";
        return 1;
    }

    int dlt = pcap_datalink(p);
    if (dlt != DLT_EN10MB) {
        std::cerr << "Unsupported datalink type: " << dlt << " (expected Ethernet)\n";
        pcap_close(p);
        return 1;
    }

    std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flows;
    flows.reserve(200000);

    const u_char* data = nullptr;
    pcap_pkthdr* hdr = nullptr;

    while (true) {
    int rc = pcap_next_ex(p, &hdr, &data);
    if (rc == 0) continue;
    if (rc == -1) {
        std::cerr << "pcap_next_ex error: " << pcap_geterr(p) << "\n";
        break;
    }
    if (rc == -2) break;

    if (hdr->caplen < sizeof(EthHdr)) continue;

    double ts = ts_to_seconds(hdr->ts);

    size_t offset = 0;
    const EthHdr* eth = reinterpret_cast<const EthHdr*>(data);
    uint16_t ethertype = ntohs(eth->ethertype);
    offset += sizeof(EthHdr);

    // VLAN handling (single or stacked tags)
    bool drop = false;
    while (ethertype == 0x8100 || ethertype == 0x88A8) {
        if (hdr->caplen < offset + sizeof(VlanTag)) { drop = true; break; }
        const VlanTag* vlan = reinterpret_cast<const VlanTag*>(data + offset);
        ethertype = ntohs(vlan->ethertype);
        offset += sizeof(VlanTag);
    }
    if (drop) continue;

    // IPv4 only for v0
    if (ethertype != 0x0800) continue;
    if (hdr->caplen < offset + sizeof(Ipv4Hdr)) continue;

    const Ipv4Hdr* ip = reinterpret_cast<const Ipv4Hdr*>(data + offset);
    uint8_t ver = ip->ver_ihl >> 4;
    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ver != 4 || ihl < 20) continue;
    if (hdr->caplen < offset + ihl) continue;

    uint16_t total_len = ntohs(ip->total_len);
    if (total_len < ihl) continue;

    uint16_t flags_frag = ntohs(ip->flags_frag);
    uint16_t frag_off = flags_frag & 0x1FFF;
    if (frag_off != 0) continue; // skip fragmented for v0

    uint8_t proto = ip->protocol;

    // L4 parsing
    size_t ip_off = offset;
    size_t l4_off = ip_off + ihl;

    uint16_t src_port = 0, dst_port = 0;
    uint8_t tcp_flags = 0;
    size_t l4_hdr_len = 0;

    if (proto == IPPROTO_TCP) {
        if (hdr->caplen < l4_off + sizeof(TcpHdr)) continue;
        const TcpHdr* tcp = reinterpret_cast<const TcpHdr*>(data + l4_off);
        src_port = ntohs(tcp->src_port);
        dst_port = ntohs(tcp->dst_port);
        tcp_flags = tcp->flags;
        l4_hdr_len = ((tcp->data_offset_reserved >> 4) & 0x0F) * 4;
        if (l4_hdr_len < 20) continue;
        if (hdr->caplen < l4_off + l4_hdr_len) continue;
    } else if (proto == IPPROTO_UDP) {
        if (hdr->caplen < l4_off + sizeof(UdpHdr)) continue;
        const UdpHdr* udp = reinterpret_cast<const UdpHdr*>(data + l4_off);
        src_port = ntohs(udp->src_port);
        dst_port = ntohs(udp->dst_port);
        l4_hdr_len = 8;
    } else {
        continue; // ignore non TCP/UDP in v0
    }

    FlowKey key{ip->src, ip->dst, src_port, dst_port, proto};
    auto& st = flows[key];

    if (st.packets == 0) {
        st.first_ts = ts;
        st.last_pkt_ts = ts;
    } else {
        double iat = ts - st.last_pkt_ts;
        st.iat_sum += iat;
        if (iat < st.iat_min) st.iat_min = iat;
        if (iat > st.iat_max) st.iat_max = iat;
        st.last_pkt_ts = ts;
    }

    st.last_ts = ts;
    st.packets += 1;
    st.bytes += hdr->len;

    int payload = static_cast<int>(total_len) - static_cast<int>(ihl + l4_hdr_len);
    if (payload > 0) st.payload_bytes += static_cast<uint64_t>(payload);

    if (proto == IPPROTO_TCP) {
        if (tcp_flags & 0x02) st.tcp_syn++;
        if (tcp_flags & 0x01) st.tcp_fin++;
        if (tcp_flags & 0x04) st.tcp_rst++;
        if (tcp_flags & 0x10) st.tcp_ack++;
    }
    }



    pcap_close(p);

    std::ofstream out(out_path);
    if (!out) {
        std::cerr << "Failed to open output: " << out_path << "\n";
        return 1;
    }

    out << "src_ip,dst_ip,src_port,dst_port,proto,"
            "packets,bytes,payload_bytes,"
            "duration_s,iat_mean_s,iat_min_s,iat_max_s,"
            "tcp_syn,tcp_fin,tcp_rst,tcp_ack\n";

    for (const auto& kv : flows) {
        const FlowKey& k = kv.first;
        const FlowStats& st = kv.second;

        double duration = (st.packets > 0) ? (st.last_ts - st.first_ts) : 0.0;
        double iat_mean = (st.packets > 1) ? (st.iat_sum / static_cast<double>(st.packets - 1)) : 0.0;
        double iat_min  = (st.packets > 1 && std::isfinite(st.iat_min)) ? st.iat_min : 0.0;
        double iat_max  = (st.packets > 1) ? st.iat_max : 0.0;

        out << ipv4_to_string(k.src_ip) << ","
            << ipv4_to_string(k.dst_ip) << ","
            << k.src_port << ","
            << k.dst_port << ","
            << static_cast<int>(k.proto) << ","
            << st.packets << ","
            << st.bytes << ","
            << st.payload_bytes << ","
            << duration << ","
            << iat_mean << ","
            << iat_min << ","
            << iat_max << ","
            << st.tcp_syn << ","
            << st.tcp_fin << ","
            << st.tcp_rst << ","
            << st.tcp_ack
            << "\n";
    }

    std::cerr << "Wrote " << flows.size() << " flows to " << out_path << "\n";
    return 0;
}