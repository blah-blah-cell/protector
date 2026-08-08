//! Real kernel data plane: loads the eBPF object, attaches the XDP and TC
//! probes, and exposes typed handles over the shared maps.

use std::os::fd::AsFd as _;

use anyhow::{Context, Result};
use aya::include_bytes_aligned;
use aya::maps::{Array, HashMap, MapData, RingBuf};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader};

use crate::config::Config;
use crate::protocol::*;

pub struct BpfManager {
    /// Kept alive: holds the programs and their attach links.
    #[allow(dead_code)]
    ebpf: Ebpf,
    #[allow(dead_code)]
    xdp: Option<Xdp>,
    #[allow(dead_code)]
    tc_ingress: Option<SchedClassifier>,
    #[allow(dead_code)]
    tc_egress: Option<SchedClassifier>,
    pub flows: HashMap<MapData, FlowKey, FlowMetrics>,
    pub blocklist: HashMap<MapData, FlowKey, BlockEntry>,
    pub blocklist_ip: HashMap<MapData, IpKey, BlockEntry>,
    pub events: RingBuf<MapData>,
    pub ctl: Array<MapData, ControlCfg>,
    pub counters: Array<MapData, CounterVec>,
}

impl BpfManager {
    pub fn load(cfg: &Config) -> Result<Self> {
        let obj = include_bytes_aligned!(env!("ZQFW_BPF_OBJ"));

        let mut loader = EbpfLoader::new();
        loader.verifier_log_level(aya::VerifierLogLevel::DISABLE);
        let mut ebpf = loader
            .load(obj)
            .context("failed to load eBPF object into the kernel")?;

        // XDP probe (ingress, line-rate inspection + enforcement).
        let xdp: &mut Xdp = ebpf
            .program_mut("zqfw_xdp")
            .context("missing zqfw_xdp program")?
            .try_into()?;
        xdp.load().context("failed to load XDP program")?;
        let xdp_mode = match cfg.cli.xdp_mode.as_str() {
            "skb" => XdpMode::Skb,
            "driver" => XdpMode::Driver,
            _ => XdpMode::Default,
        };
        xdp.attach(&cfg.cli.iface, xdp_mode)
            .context("failed to attach XDP program")?;

        // TC classifier (egress enforcement on the skb path).
        let tc: &mut SchedClassifier = ebpf
            .program_mut("zqfw_tc")
            .context("missing zqfw_tc program")?
            .try_into()?;
        tc.load().context("failed to load TC program")?;
        tc.attach(&cfg.cli.iface, TcAttachType::Ingress)
            .context("failed to attach TC ingress program")?;
        tc.attach(&cfg.cli.iface, TcAttachType::Egress)
            .context("failed to attach TC egress program")?;

        // Move the maps out of the loader so they can be used independently.
        let flows: HashMap<MapData, FlowKey, FlowMetrics> =
            HashMap::try_from(ebpf.take_map("flows").context("missing flows map")?)?;
        let blocklist: HashMap<MapData, FlowKey, BlockEntry> =
            HashMap::try_from(ebpf.take_map("blocklist").context("missing blocklist map")?)?;
        let blocklist_ip: HashMap<MapData, IpKey, BlockEntry> =
            HashMap::try_from(ebpf.take_map("blocklist_ip").context("missing blocklist_ip map")?)?;
        let events: RingBuf<MapData> =
            RingBuf::try_from(ebpf.take_map("events").context("missing events map")?)?;
        let ctl: Array<MapData, ControlCfg> =
            Array::try_from(ebpf.take_map("ctl").context("missing ctl map")?)?;
        let counters: Array<MapData, CounterVec> =
            Array::try_from(ebpf.take_map("counters").context("missing counters map")?)?;

        Ok(BpfManager {
            ebpf,
            xdp: None,
            tc_ingress: None,
            tc_egress: None,
            flows,
            blocklist,
            blocklist_ip,
            events,
            ctl,
            counters,
        })
    }

    /// Read a raw event from the ring buffer if one is pending.
    pub fn try_read_event(&mut self) -> Option<KernelEvent> {
        let item = self.events.next()?;
        let bytes: &[u8] = &item;
        if bytes.len() < std::mem::size_of::<KernelEvent>() {
            return None;
        }
        // SAFETY: layout matches the kernel-published struct; length checked.
        Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const KernelEvent) })
    }

    pub fn ringbuf_fd(&self) -> std::os::fd::OwnedFd {
        self.events
            .as_fd()
            .try_clone_to_owned()
            .expect("ringbuf fd clone")
    }

    pub fn apply_control(&mut self, enforce: bool, cfg: &Config) -> Result<()> {
        let ctl_cfg = ControlCfg {
            mode: if enforce { MODE_ENFORCE } else { MODE_MONITOR },
            flags: (if cfg.block_ip { FLAG_BLOCK_IP } else { 0 })
                | (if cfg.cli.hit_events { FLAG_HIT_EVENTS } else { 0 }),
            block_ttl_ns: cfg.block_ttl_ns as u32,
            reserved: 0,
        };
        self.ctl.set(CTL_INDEX, ctl_cfg, 0)?;
        Ok(())
    }
}

/// Thin in-process interface every data plane implements, so the supervisor
/// logic is identical for real BPF and the rootless mock/simulator.
pub trait DataPlane {
    fn block_flow(&mut self, key: &FlowKey, entry: BlockEntry) -> Result<()>;
    fn unblock_flow(&mut self, key: &FlowKey) -> Result<()>;
    fn block_ip(&mut self, ip: &IpKey, entry: BlockEntry) -> Result<()>;
    fn unblock_ip(&mut self, ip: &IpKey) -> Result<()>;
    fn apply_control(&mut self, enforce: bool, cfg: &Config) -> Result<()>;
    fn snapshot_flows(&mut self) -> Vec<(FlowKey, FlowMetrics)>;
    fn snapshot_counters(&mut self) -> CounterVec;
    /// Drain any pending kernel events (ring buffer). Real planes return the
    /// number drained; the mock plane returns 0 (events arrive via channel).
    fn poll_events(&mut self, out: &mut Vec<KernelEvent>) -> Result<usize> {
        out.clear();
        Ok(0)
    }
    /// An fd that becomes readable when kernel events are pending. `None` for
    /// planes that source events from a channel instead.
    fn event_fd(&self) -> Option<std::os::fd::OwnedFd> {
        None
    }
    /// Simulate a packet entering the data plane. The real BPF plane ignores
    /// this (the kernel probes do the work); the mock plane uses it to build
    /// flow metrics. Returns `true` if the packet is dropped in enforce mode.
    fn ingest_packet(&mut self, _key: &FlowKey, _len: u32, _ts_ns: u64, _flags: u8) -> bool {
        false
    }
}

impl DataPlane for BpfManager {
    fn block_flow(&mut self, key: &FlowKey, entry: BlockEntry) -> Result<()> {
        self.blocklist.insert(key, entry, 0)?;
        Ok(())
    }

    fn unblock_flow(&mut self, key: &FlowKey) -> Result<()> {
        let _ = self.blocklist.remove(key);
        Ok(())
    }

    fn block_ip(&mut self, ip: &IpKey, entry: BlockEntry) -> Result<()> {
        self.blocklist_ip.insert(ip, entry, 0)?;
        Ok(())
    }

    fn unblock_ip(&mut self, ip: &IpKey) -> Result<()> {
        let _ = self.blocklist_ip.remove(ip);
        Ok(())
    }

    fn apply_control(&mut self, enforce: bool, cfg: &Config) -> Result<()> {
        BpfManager::apply_control(self, enforce, cfg)
    }

    fn snapshot_flows(&mut self) -> Vec<(FlowKey, FlowMetrics)> {
        let mut out = Vec::new();
        for r in self.flows.iter() {
            if let Ok((k, v)) = r {
                out.push((k, v));
            }
        }
        out
    }

    fn snapshot_counters(&mut self) -> CounterVec {
        self.counters.get(&0, 0).unwrap_or_default()
    }

    fn poll_events(&mut self, out: &mut Vec<KernelEvent>) -> Result<usize> {
        let mut n = 0;
        while let Some(ev) = self.try_read_event() {
            out.push(ev);
            n += 1;
        }
        Ok(n)
    }

    fn event_fd(&self) -> Option<std::os::fd::OwnedFd> {
        Some(self.ringbuf_fd())
    }
}

#[cfg(test)]
mod tests {
    use aya_obj::Object;

    /// Parsing the compiled ELF is enough to prove aya can load it at runtime
    /// (loading/attaching itself additionally requires root).
    #[test]
    fn bpf_object_parses_with_programs_and_maps() {
        let bytes = std::fs::read(env!("ZQFW_BPF_OBJ")).expect("compiled bpf object");
        let obj = Object::parse(&bytes).expect("aya-obj should parse the object");
        assert!(
            obj.programs.contains_key("zqfw_xdp"),
            "missing xdp program section"
        );
        assert!(
            obj.programs.contains_key("zqfw_tc"),
            "missing tc program section"
        );
        for name in [
            "flows",
            "blocklist",
            "blocklist_ip",
            "events",
            "ctl",
            "counters",
        ] {
            assert!(obj.maps.contains_key(name), "missing map {name}");
        }
    }
}
