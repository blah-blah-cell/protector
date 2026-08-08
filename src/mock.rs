//! Rootless mock data plane used by `--mock` mode.
//!
//! Implements the same [`DataPlane`] contract as the BPF manager so the entire
//! triage/enforcement/audit pipeline can be exercised without kernel access
//! (CI, demos, development).

use std::collections::{HashMap, HashSet};

use anyhow::Result;

use crate::bpf::DataPlane;
use crate::config::Config;
use crate::protocol::*;

pub struct MockDataPlane {
    pub flows: HashMap<FlowKey, FlowMetrics>,
    pub blocklist: HashSet<FlowKey>,
    pub blocklist_ip: HashSet<IpKey>,
    pub counters: CounterVec,
    pub enforce: bool,
}

impl MockDataPlane {
    pub fn new() -> Self {
        MockDataPlane {
            flows: HashMap::new(),
            blocklist: HashSet::new(),
            blocklist_ip: HashSet::new(),
            counters: CounterVec::default(),
            enforce: false,
        }
    }

    /// Feed one packet into the mock plane, mirroring what the kernel probe
    /// would do: check the blocklists, update counters, maintain flow metrics.
    pub fn process_packet(&mut self, key: &FlowKey, len: u32, ts_ns: u64, flags: u8) -> bool {
        let is_blocked =
            self.blocklist.contains(key) || self.blocklist_ip.contains(&IpKey::from_ip(key.src_ip()));
        if is_blocked {
            self.counters.drop += 1;
            self.counters.block_hits += 1;
            return self.enforce; // true => "would drop"
        }
        self.counters.pass += 1;
        let m = self.flows.entry(*key).or_insert_with(|| FlowMetrics {
            packets: 0,
            bytes: 0,
            sum_pkt_len: 0,
            first_seen_ns: ts_ns,
            last_seen_ns: ts_ns,
            max_pkt_len: 0,
            min_pkt_len: 0,
            syn_count: 0,
            fin_count: 0,
            rst_count: 0,
            tcp_flags_or: 0,
            l7_app: 0,
            l7_info: 0,
            proto: key.proto,
            emitted: 0,
        });
        m.packets += 1;
        m.bytes += len as u64;
        m.sum_pkt_len += len as u64;
        m.last_seen_ns = ts_ns;
        m.max_pkt_len = m.max_pkt_len.max(len);
        m.min_pkt_len = if m.min_pkt_len == 0 { len } else { m.min_pkt_len.min(len) };
        if key.proto == 6 {
            m.tcp_flags_or |= flags as u16;
            if flags & 0x02 != 0 && flags & 0x10 == 0 {
                m.syn_count += 1;
            }
            if flags & 0x01 != 0 {
                m.fin_count += 1;
            }
            if flags & 0x04 != 0 {
                m.rst_count += 1;
            }
        }
        false
    }
}

impl DataPlane for MockDataPlane {
    fn block_flow(&mut self, key: &FlowKey, _entry: BlockEntry) -> Result<()> {
        self.blocklist.insert(*key);
        Ok(())
    }

    fn unblock_flow(&mut self, key: &FlowKey) -> Result<()> {
        self.blocklist.remove(key);
        Ok(())
    }

    fn block_ip(&mut self, ip: &IpKey, _entry: BlockEntry) -> Result<()> {
        self.blocklist_ip.insert(*ip);
        Ok(())
    }

    fn unblock_ip(&mut self, ip: &IpKey) -> Result<()> {
        self.blocklist_ip.remove(ip);
        Ok(())
    }

    fn apply_control(&mut self, enforce: bool, _cfg: &Config) -> Result<()> {
        self.enforce = enforce;
        Ok(())
    }

    fn snapshot_flows(&mut self) -> Vec<(FlowKey, FlowMetrics)> {
        self.flows.iter().map(|(k, v)| (*k, *v)).collect()
    }

    fn snapshot_counters(&mut self) -> CounterVec {
        self.counters
    }

    fn ingest_packet(&mut self, key: &FlowKey, len: u32, ts_ns: u64, flags: u8) -> bool {
        self.process_packet(key, len, ts_ns, flags)
    }
}

impl Default for MockDataPlane {
    fn default() -> Self {
        Self::new()
    }
}
