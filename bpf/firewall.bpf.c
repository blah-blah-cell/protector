/* SPDX-License-Identifier: GPL-2.0
 *
 * zqfw.bpf.c — zero-trust quarantine firewall kernel probes.
 *
 * XDP probe (SEC("xdp")): ingress line-rate inspection. Parses L2-L4 headers,
 * performs light L7 classification, maintains per-flow metrics in `flows`,
 * and enforces the blocklist maps (`blocklist`, `blocklist_ip`).
 * TC probe (SEC("classifier")): egress (and ingress) enforcement on the skb
 * path so outbound malicious traffic is dropped as well.
 *
 * The user-space Rust daemon consumes `events` (ringbuf) for new flows and
 * quarantine hits, and pushes block decisions into the blocklist maps.
 */

#include <linux/bpf.h>
#include <linux/types.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

/* ------------------------------------------------------------------ */
/* constants                                                           */
/* ------------------------------------------------------------------ */

/* tc actions (from <linux/pkt_cls.h>, avoided to skip kernel-internal
 * header dependencies) */
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_REDIRECT 7

#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_P_IP     0x0800
#define ETH_P_IPV6   0x86DD

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define IPPROTO_ICMPV6 58

#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_ACK 0x10

#define MAX_FLOWS 262144
#define MAX_BLOCKLIST 262144
#define RINGBUF_BYTES (1u << 22) /* 4 MiB */

/* control / config flags */
#define ZQFW_MODE_MONITOR 0u
#define ZQFW_MODE_ENFORCE 1u
#define ZQFW_FLAG_BLOCK_IP (1u << 0)
#define ZQFW_FLAG_HIT_EVENTS (1u << 1)

/* event kinds */
#define EV_NEW_FLOW 1
#define EV_BLOCK_HIT 2
#define EV_FLOW_EXPIRED 3
#define EV_DROP 4

/* L7 app ids */
#define L7_NONE 0
#define L7_HTTP 1
#define L7_TLS 2
#define L7_DNS 3
#define L7_SSH 4
#define L7_DHCP 5
#define L7_QUIC 6
#define L7_UNKNOWN_TCP 10
#define L7_UNKNOWN_UDP 11

/* block reason codes (mirrored in userspace audit logs) */
#define REASON_TRIAGE 1
#define REASON_IP_QUARANTINE 2
#define REASON_RATE_LIMIT 3
#define REASON_MANUAL 4
#define REASON_EXFIL 5

/* ------------------------------------------------------------------ */
/* data structures (layouts must match userspace)                      */
/* ------------------------------------------------------------------ */

struct flow_key {
    __u32 saddr[4]; /* 16 bytes, ipv4 in [0] */
    __u32 daddr[4];
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 dir; /* 0 = as captured, 1 = reversed */
};

struct flow_metrics {
    __u64 packets;
    __u64 bytes;
    __u64 sum_pkt_len;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u32 max_pkt_len;
    __u32 min_pkt_len;
    __u32 syn_count;
    __u32 fin_count;
    __u32 rst_count;
    __u16 tcp_flags_or;
    __u16 l7_app;
    __u16 l7_info;
    __u8 proto;
    __u8 emitted;
};

struct block_entry {
    __u32 reason;
    __u32 ts_ns;
    __u32 ttl_ns;
    __u32 seq;
};

struct ip_key {
    __u32 addr[4];
};

struct zqfw_cfg {
    __u32 mode;
    __u32 flags;
    __u32 block_ttl_ns;
    __u32 reserved;
};

struct zqfw_counter {
    __u64 pass;
    __u64 drop;
    __u64 block_hits;
    __u64 new_flows;
    __u64 malformed;
    __u64 events_lost;
};

struct zqfw_event {
    __u32 kind;
    __u32 ts_ns;
    __u32 len;
    __u32 cpu;
    struct flow_key key;
    __u16 l7_app;
    __u16 l7_info;
};

/* ------------------------------------------------------------------ */
/* maps                                                                */
/* ------------------------------------------------------------------ */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_metrics);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKLIST);
    __type(key, struct flow_key);
    __type(value, struct block_entry);
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKLIST);
    __type(key, struct ip_key);
    __type(value, struct block_entry);
} blocklist_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_BYTES);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct zqfw_cfg);
} ctl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct zqfw_counter);
} counters SEC(".maps");

/* ------------------------------------------------------------------ */
/* parsed packet context                                               */
/* ------------------------------------------------------------------ */

struct pkt_ctx {
    struct flow_key key;
    __u32 len;
    __u8 l4_proto;
    __u16 tcp_flags;
    __u8 is_udp;
    __u16 l7_app;
    __u16 l7_info;
};

/* ------------------------------------------------------------------ */
/* L7 classification helpers                                           */
/* ------------------------------------------------------------------ */

static __always_inline __u8 classify_udp_l7(const void *data,
                                            const void *data_end,
                                            __u16 sport,
                                            __u16 dport,
                                            __u16 *info)
{
    if (sport == 53 || dport == 53) {
        /* DNS: parse query name length to catch tunneling-ish sizes. */
        const __u8 *hdr = (const __u8 *)data;
        if ((const void *)(hdr + 12) <= data_end) {
            __u16 flags = (hdr[2] << 8) | hdr[3];
            if (!(flags & 0x8000)) { /* not a response */
                __u32 qlen = 0;
                const __u8 *p = hdr + 12;
                __u32 i;
                for (i = 0; i < 4; i++) { /* bounded: max 4 labels */
                    if ((const void *)(p + 1) > data_end)
                        break;
                    __u8 l = *p;
                    if (l == 0)
                        break;
                    if (l & 0xC0)
                        break; /* compressed pointer */
                    qlen += l + 1;
                    p += l + 1;
                }
                *info = (__u16)(qlen > 255 ? 255 : qlen);
            }
        }
        return L7_DNS;
    }
    if (sport == 67 || dport == 67 || sport == 68 || dport == 68)
        return L7_DHCP;
    if (sport == 443 || dport == 443) {
        /* QUIC initial packet: first byte 0xc0-0xff */
        const __u8 *b = (const __u8 *)data;
        if (b + 1 <= (const __u8 *)data_end && (*b & 0xC0) == 0xC0)
            return L7_QUIC;
    }
    return L7_UNKNOWN_UDP;
}

static __always_inline __u16 classify_tcp_l7(const void *data,
                                             const void *data_end,
                                             __u16 *info)
{
    const __u8 *p = (const __u8 *)data;
    const __u8 *end = (const __u8 *)data_end;
    if (p >= end || (const void *)(p + 8) > data_end)
        return L7_UNKNOWN_TCP;

    /* HTTP method prefix */
    static const __u8 http_methods[8][4] = {
        {'G', 'E', 'T', ' '}, {'P', 'O', 'S', 'T'}, {'H', 'E', 'A', 'D'},
        {'P', 'U', 'T', ' '}, {'D', 'E', 'L', 'E'}, {'O', 'P', 'T', 'I'},
        {'P', 'A', 'T', 'C'}, {'C', 'O', 'N', 'N'},
    };
    __u32 i;
    for (i = 0; i < 8; i++) {
        if (end - p >= 4 && p[0] == http_methods[i][0] &&
            p[1] == http_methods[i][1] && p[2] == http_methods[i][2] &&
            p[3] == http_methods[i][3]) {
            *info = (__u16)(i + 1);
            return L7_HTTP;
        }
    }

    /* TLS handshake record: 0x16 0x03 0x01..0x04 */
    if (p[0] == 0x16 && p[1] == 0x03 && p[2] >= 0x01 && p[2] <= 0x04) {
        *info = (__u16)((p[3] << 8) | p[4]);
        return L7_TLS;
    }

    /* SSH banner */
    if (end - p >= 4 && p[0] == 'S' && p[1] == 'S' && p[2] == 'H' && p[3] == '-')
        return L7_SSH;

    return L7_UNKNOWN_TCP;
}

/* ------------------------------------------------------------------ */
/* packet parser                                                       */
/* ------------------------------------------------------------------ */

static __always_inline int parse_ipv4(const void *data, const void *data_end,
                                      struct pkt_ctx *ctx)
{
    const __u8 *ip = (const __u8 *)data;
    if ((const void *)(ip + 20) > data_end)
        return -1;
    __u8 ihl = ip[0] & 0x0F;
    if (ihl < 5)
        return -1;
    const __u8 *l4 = ip + ((__u32)ihl * 4);
    if ((const void *)l4 > data_end)
        return -1;

    ctx->key.proto = ip[9];
    ctx->key.saddr[0] = bpf_ntohl(*(__u32 *)(ip + 12));
    ctx->key.daddr[0] = bpf_ntohl(*(__u32 *)(ip + 16));
    ctx->l4_proto = ip[9];

    if (ctx->l4_proto == IPPROTO_TCP) {
        if ((const void *)(l4 + 14) > data_end)
            return -1;
        ctx->key.sport = bpf_ntohs(*(__u16 *)(l4 + 0));
        ctx->key.dport = bpf_ntohs(*(__u16 *)(l4 + 2));
        ctx->tcp_flags = l4[13];
        const __u8 *pay = l4 + ((l4[12] >> 4) & 0x0F) * 4;
        if ((const void *)pay < data_end)
            ctx->l7_app = classify_tcp_l7(pay, data_end, &ctx->l7_info);
        else
            ctx->l7_app = L7_UNKNOWN_TCP;
    } else if (ctx->l4_proto == IPPROTO_UDP) {
        if ((const void *)(l4 + 8) > data_end)
            return -1;
        ctx->key.sport = bpf_ntohs(*(__u16 *)(l4 + 0));
        ctx->key.dport = bpf_ntohs(*(__u16 *)(l4 + 2));
        ctx->is_udp = 1;
        const __u8 *pay = l4 + 8;
        if ((const void *)pay < data_end)
            ctx->l7_app = classify_udp_l7(pay, data_end,
                                          ctx->key.sport, ctx->key.dport,
                                          &ctx->l7_info);
        else
            ctx->l7_app = L7_UNKNOWN_UDP;
    } else {
        ctx->l7_app = L7_NONE;
    }
    return 0;
}

static __always_inline int parse_ipv6(const void *data, const void *data_end,
                                      struct pkt_ctx *ctx)
{
    const __u8 *ip = (const __u8 *)data;
    if ((const void *)(ip + 40) > data_end)
        return -1;
    __u8 nxthdr = ip[6];
    const __u8 *l4 = ip + 40;

    /* skip extension headers (bounded) */
    __u32 guard = 0;
    while ((nxthdr == 0 || nxthdr == 43 || nxthdr == 44 || nxthdr == 51 ||
            nxthdr == 60) &&
           (const void *)(l4 + 8) <= data_end) {
        if (guard++ > 3)
            return -1;
        __u8 hlen = (nxthdr == 44) ? 8 : ((l4[1] + 1) * 8);
        __u8 next = l4[0];
        l4 += hlen;
        nxthdr = next;
    }

    ctx->key.proto = nxthdr;
    __u32 i;
    for (i = 0; i < 4; i++)
        ctx->key.saddr[i] = bpf_ntohl(*(__u32 *)(ip + 8 + i * 4));
    for (i = 0; i < 4; i++)
        ctx->key.daddr[i] = bpf_ntohl(*(__u32 *)(ip + 24 + i * 4));
    ctx->l4_proto = nxthdr;

    if (ctx->l4_proto == IPPROTO_TCP) {
        if ((const void *)(l4 + 14) > data_end)
            return -1;
        ctx->key.sport = bpf_ntohs(*(__u16 *)(l4 + 0));
        ctx->key.dport = bpf_ntohs(*(__u16 *)(l4 + 2));
        ctx->tcp_flags = l4[13];
        const __u8 *pay = l4 + ((l4[12] >> 4) & 0x0F) * 4;
        if ((const void *)pay < data_end)
            ctx->l7_app = classify_tcp_l7(pay, data_end, &ctx->l7_info);
        else
            ctx->l7_app = L7_UNKNOWN_TCP;
    } else if (ctx->l4_proto == IPPROTO_UDP) {
        if ((const void *)(l4 + 8) > data_end)
            return -1;
        ctx->key.sport = bpf_ntohs(*(__u16 *)(l4 + 0));
        ctx->key.dport = bpf_ntohs(*(__u16 *)(l4 + 2));
        ctx->is_udp = 1;
        const __u8 *pay = l4 + 8;
        if ((const void *)pay < data_end)
            ctx->l7_app = classify_udp_l7(pay, data_end,
                                          ctx->key.sport, ctx->key.dport,
                                          &ctx->l7_info);
        else
            ctx->l7_app = L7_UNKNOWN_UDP;
    } else {
        ctx->l7_app = L7_NONE;
    }
    return 0;
}

/* Returns 0 on success (ctx filled), -1 on malformed. */
static __always_inline int parse_packet(void *data, void *data_end,
                                        struct pkt_ctx *ctx)
{
    const __u8 *eth = (const __u8 *)data;
    if ((const void *)(eth + 14) > data_end)
        return -1;
    __u16 proto = eth[12] << 8 | eth[13];

    if (proto == ETH_P_8021Q || proto == ETH_P_8021AD) {
        if ((const void *)(eth + 18) > data_end)
            return -1;
        proto = eth[16] << 8 | eth[17];
        eth += 4;
    }

    if (proto == ETH_P_IP)
        return parse_ipv4((const void *)(eth + 14), data_end, ctx);
    if (proto == ETH_P_IPV6)
        return parse_ipv6((const void *)(eth + 14), data_end, ctx);
    return -1;
}

/* ------------------------------------------------------------------ */
/* event emission                                                      */
/* ------------------------------------------------------------------ */

static __always_inline void emit_event(__u32 kind, struct pkt_ctx *ctx,
                                       __u32 len)
{
    struct zqfw_event ev = {};
    ev.kind = kind;
    ev.ts_ns = bpf_ktime_get_ns();
    ev.len = len;
    ev.cpu = bpf_get_smp_processor_id();
    ev.key = ctx->key;
    ev.l7_app = ctx->l7_app;
    ev.l7_info = ctx->l7_info;
    if (bpf_ringbuf_output(&events, &ev, sizeof(ev), 0) != 0) {
        __u32 zero = 0;
        struct zqfw_counter *c = bpf_map_lookup_elem(&counters, &zero);
        if (c)
            __sync_fetch_and_add(&c->events_lost, 1);
    }
}

/* ------------------------------------------------------------------ */
/* core inspection / enforcement                                       */
/* ------------------------------------------------------------------ */

enum act { ACT_PASS = 0, ACT_DROP = 1 };

static __always_inline enum act inspect(void *data, void *data_end, __u32 len)
{
    struct pkt_ctx ctx = {};
    if (parse_packet(data, data_end, &ctx) != 0) {
        __u32 zero4 = 0;
        struct zqfw_counter *c = bpf_map_lookup_elem(&counters, &zero4);
        if (c)
            __sync_fetch_and_add(&c->malformed, 1);
        return ACT_PASS;
    }

    __u32 zero = 0;
    struct zqfw_cfg *cfg = bpf_map_lookup_elem(&ctl, &zero);
    __u32 mode = cfg ? cfg->mode : ZQFW_MODE_ENFORCE;
    __u32 flags = cfg ? cfg->flags : 0;

    /* 1. exact 5-tuple blocklist */
    struct block_entry *be = bpf_map_lookup_elem(&blocklist, &ctx.key);
    if (be) {
        __u32 zero = 0;
        struct zqfw_counter *c = bpf_map_lookup_elem(&counters, &zero);
        if (c) {
            __sync_fetch_and_add(&c->drop, 1);
            __sync_fetch_and_add(&c->block_hits, 1);
        }
        if (flags & ZQFW_FLAG_HIT_EVENTS)
            emit_event(EV_BLOCK_HIT, &ctx, len);
        return mode == ZQFW_MODE_ENFORCE ? ACT_DROP : ACT_PASS;
    }

    /* 2. whole-source-IP quarantine */
    if (flags & ZQFW_FLAG_BLOCK_IP) {
        struct ip_key ipk = {};
        __u32 i;
        for (i = 0; i < 4; i++)
            ipk.addr[i] = ctx.key.saddr[i];
        struct block_entry *be_ip = bpf_map_lookup_elem(&blocklist_ip, &ipk);
        if (be_ip) {
            __u32 zero = 0;
            struct zqfw_counter *c = bpf_map_lookup_elem(&counters, &zero);
            if (c) {
                __sync_fetch_and_add(&c->drop, 1);
                __sync_fetch_and_add(&c->block_hits, 1);
            }
            if (flags & ZQFW_FLAG_HIT_EVENTS)
                emit_event(EV_BLOCK_HIT, &ctx, len);
            return mode == ZQFW_MODE_ENFORCE ? ACT_DROP : ACT_PASS;
        }
    }

    /* 3. flow metrics */
    struct flow_metrics *m = bpf_map_lookup_elem(&flows, &ctx.key);
    if (!m) {
        struct flow_metrics init = {};
        init.packets = 1;
        init.bytes = len;
        init.sum_pkt_len = len;
        init.first_seen_ns = bpf_ktime_get_ns();
        init.last_seen_ns = init.first_seen_ns;
        init.max_pkt_len = len;
        init.min_pkt_len = len;
        init.tcp_flags_or = ctx.tcp_flags;
        init.l7_app = ctx.l7_app;
        init.l7_info = ctx.l7_info;
        init.proto = ctx.l4_proto;
        if (ctx.l4_proto == IPPROTO_TCP) {
            if (ctx.tcp_flags & TCP_FLAG_SYN)
                init.syn_count = 1;
        }
        if (bpf_map_update_elem(&flows, &ctx.key, &init,
                                BPF_ANY) == 0) {
            __u32 zero2 = 0;
            struct zqfw_counter *c = bpf_map_lookup_elem(&counters, &zero2);
            if (c)
                __sync_fetch_and_add(&c->new_flows, 1);
            emit_event(EV_NEW_FLOW, &ctx, len);
        }
    } else {
        __sync_fetch_and_add(&m->packets, 1);
        __sync_fetch_and_add(&m->bytes, len);
        __sync_fetch_and_add(&m->sum_pkt_len, len);
        m->last_seen_ns = bpf_ktime_get_ns();
        if (len > m->max_pkt_len)
            m->max_pkt_len = len;
        if (len < m->min_pkt_len || m->min_pkt_len == 0)
            m->min_pkt_len = len;
        if (ctx.l4_proto == IPPROTO_TCP) {
            m->tcp_flags_or |= ctx.tcp_flags;
            if (ctx.tcp_flags & TCP_FLAG_SYN)
                __sync_fetch_and_add(&m->syn_count, 1);
            if (ctx.tcp_flags & TCP_FLAG_FIN)
                __sync_fetch_and_add(&m->fin_count, 1);
            if (ctx.tcp_flags & TCP_FLAG_RST)
                __sync_fetch_and_add(&m->rst_count, 1);
        }
        if (m->l7_app == L7_NONE && ctx.l7_app != L7_NONE) {
            m->l7_app = ctx.l7_app;
            m->l7_info = ctx.l7_info;
        }
    }

    __u32 zeroc = 0;
    struct zqfw_counter *c = bpf_map_lookup_elem(&counters, &zeroc);
    if (c)
        __sync_fetch_and_add(&c->pass, 1);
    return ACT_PASS;
}

/* ------------------------------------------------------------------ */
/* programs                                                            */
/* ------------------------------------------------------------------ */

SEC("xdp")
int zqfw_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    enum act a = inspect(data, data_end, ctx->data_end - ctx->data);
    return a == ACT_DROP ? XDP_DROP : XDP_PASS;
}

SEC("classifier")
int zqfw_tc(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    enum act a = inspect(data, data_end, skb->len);
    return a == ACT_DROP ? TC_ACT_SHOT : TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
