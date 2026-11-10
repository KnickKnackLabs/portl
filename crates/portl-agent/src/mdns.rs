//! Network policy for the process-wide mDNS service (not a per-interface firewall).

use std::net::IpAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use futures_util::StreamExt;
use ipnet::IpNet;
use iroh::Watcher as _;
use iroh::address_lookup::{
    AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, EndpointData, Error, Item,
};
use iroh_base::EndpointId;
use iroh_mdns_address_lookup::MdnsAddressLookup;
use n0_future::boxed::BoxStream;
use n0_future::task::AbortOnDropHandle;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LocalDiscovery {
    Enabled(bool),
    Policy(LocalPolicy),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalPolicy {
    pub enabled: bool,
    pub allow: Vec<NetworkRule>,
    pub deny: Vec<NetworkRule>,
    /// None means allow without rules, deny with rules.
    pub unknown: Option<UnknownNetwork>,
}

impl Default for LocalPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            allow: Vec::new(),
            deny: Vec::new(),
            unknown: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnknownNetwork {
    Allow,
    Deny,
}

/// Fields in a rule are `ANDed`; separate rules are `ORed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRule {
    pub ssid: Option<String>,
    pub interface: Option<String>,
    /// Matches an address assigned to this interface, not the default route.
    pub subnet: Option<IpNet>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkIdentity {
    pub links: Vec<NetworkLink>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkLink {
    pub interface: String,
    pub ssid: Option<String>,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdnsSnapshot {
    pub active: bool,
    pub reason: String,
    pub network: NetworkIdentity,
}

impl Default for MdnsSnapshot {
    fn default() -> Self {
        Self {
            active: false,
            reason: "not started".into(),
            network: NetworkIdentity::default(),
        }
    }
}

/// Shared only with the status reader, never keeps a lookup or endpoint alive.
#[derive(Debug, Clone, Default)]
pub struct MdnsStatus(Arc<Mutex<MdnsSnapshot>>);

impl MdnsStatus {
    pub fn snapshot(&self) -> MdnsSnapshot {
        self.0.lock().expect("mDNS status lock").clone()
    }

    fn update(&self, snapshot: MdnsSnapshot) {
        let mut previous = self.0.lock().expect("mDNS status lock");
        if *previous != snapshot {
            tracing::info!(active = snapshot.active, reason = %snapshot.reason,
                network = ?snapshot.network, "mDNS network policy transition");
            *previous = snapshot;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Match {
    Yes,
    No,
    Unknown,
}

impl NetworkRule {
    fn matches(&self, link: &NetworkLink) -> Match {
        if self
            .interface
            .as_ref()
            .is_some_and(|name| name != &link.interface)
            || self
                .subnet
                .is_some_and(|net| !link.addresses.iter().any(|ip| net.contains(ip)))
        {
            return Match::No;
        }
        match (&self.ssid, &link.ssid) {
            (Some(expected), Some(actual)) if expected != actual => Match::No,
            (Some(_), None) => Match::Unknown,
            _ => Match::Yes,
        }
    }
}

impl LocalPolicy {
    pub fn validate(&self) -> anyhow::Result<()> {
        for rule in self.allow.iter().chain(&self.deny) {
            anyhow::ensure!(
                rule.ssid.is_some() || rule.interface.is_some() || rule.subnet.is_some(),
                "mDNS network rule must specify ssid, interface or subnet"
            );
            anyhow::ensure!(
                !rule.ssid.as_ref().is_some_and(String::is_empty)
                    && !rule.interface.as_ref().is_some_and(String::is_empty),
                "mDNS ssid/interface matcher must not be empty"
            );
        }
        Ok(())
    }

    fn unknown_allowed(&self) -> bool {
        self.unknown
            .unwrap_or(if self.allow.is_empty() && self.deny.is_empty() {
                UnknownNetwork::Allow
            } else {
                UnknownNetwork::Deny
            })
            == UnknownNetwork::Allow
    }

    pub fn evaluate(&self, network: &NetworkIdentity) -> (bool, &'static str) {
        if !self.enabled {
            return (false, "disabled by configuration");
        }
        // A definite deny anywhere beats an allow (including unknown=allow).
        if network
            .links
            .iter()
            .any(|link| self.deny.iter().any(|r| r.matches(link) == Match::Yes))
        {
            return (false, "deny rule matched");
        }
        if network.links.is_empty() {
            return (self.unknown_allowed(), "unknown network default");
        }
        for link in &network.links {
            if self.deny.iter().any(|r| r.matches(link) == Match::Unknown)
                && !self.unknown_allowed()
            {
                return (false, "deny rule identity unavailable");
            }
            // Unknown deny is not a definite allow: still enforce the allowlist.
            if !self.allow.is_empty() && !self.allow.iter().any(|r| r.matches(link) == Match::Yes) {
                if self.allow.iter().any(|r| r.matches(link) == Match::Unknown) {
                    if !self.unknown_allowed() {
                        return (false, "allow rule identity unavailable");
                    }
                } else {
                    return (false, "network not in allowlist");
                }
            }
        }
        (true, "network policy permits mDNS")
    }
}

#[derive(Debug)]
pub struct ScopedMdns {
    pub policy: LocalPolicy,
    pub advertise: bool,
    pub status: MdnsStatus,
}

#[derive(Debug)]
struct Inner {
    lookup: Option<MdnsAddressLookup>,
    data: Option<EndpointData>,
    ready: bool,
    generation: watch::Sender<u64>,
}

impl Inner {
    fn stop(&mut self) {
        self.lookup = None; // Last owner: abort mDNS actor and its swarm-discovery sockets.
        self.generation.send_modify(|generation| *generation += 1);
    }
}

#[derive(Debug)]
struct GatedLookup {
    inner: Arc<Mutex<Inner>>,
    _task: AbortOnDropHandle<()>,
}

impl AddressLookupBuilder for ScopedMdns {
    fn into_address_lookup(
        self,
        endpoint: &iroh::Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        let inner = Arc::new(Mutex::new(Inner {
            lookup: None,
            data: None,
            ready: false,
            generation: watch::channel(0).0,
        }));
        let weak = Arc::downgrade(&inner);
        let id = endpoint.id();
        let closed = endpoint.closed();
        let task = tokio::spawn(async move {
            tokio::select! {
                () = closed => {},
                () = self.run(id, &weak) => {},
            }
            if let Some(inner) = weak.upgrade() {
                let mut inner = inner.lock().expect("mDNS lock");
                inner.ready = true;
                inner.stop();
            }
        });
        Ok(GatedLookup {
            inner,
            _task: AbortOnDropHandle::new(task),
        })
    }
}

impl AddressLookup for GatedLookup {
    fn publish(&self, data: &EndpointData) {
        let mut inner = self.inner.lock().expect("mDNS lock");
        if let Some(lookup) = &inner.lookup {
            lookup.publish(data);
        }
        inner.data = Some(data.clone());
    }

    fn resolve(&self, id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        let inner = self.inner.lock().expect("mDNS lock");
        let mut generation = inner.generation.subscribe();
        let initial = if inner.ready {
            Some(inner.lookup.as_ref()?.resolve(id)?)
        } else {
            None
        };
        drop(inner);
        let weak = Arc::downgrade(&self.inner);
        // A local-only CLI can resolve immediately after bind, before the initial
        // asynchronous policy check. Wait for that check instead of losing the query.
        let start = async move {
            if let Some(stream) = initial {
                return Some((generation, stream));
            }
            loop {
                let inner = weak.upgrade()?;
                {
                    let inner = inner.lock().expect("mDNS lock");
                    if inner.ready {
                        let stream = inner.lookup.as_ref()?.resolve(id)?;
                        generation.borrow_and_update();
                        return Some((generation, stream));
                    }
                }
                drop(inner);
                generation.changed().await.ok()?;
            }
        };
        // Never yield cached or in-flight answers after the policy generation changes.
        let stream = futures_util::stream::once(start)
            .filter_map(futures_util::future::ready)
            .flat_map(|(generation, stream)| {
                futures_util::stream::unfold(
                    (generation, stream),
                    |(mut generation, mut stream)| async move {
                        tokio::select! {
                            biased;
                            _ = generation.changed() => None,
                            item = stream.next() => item.map(|item| (item, (generation, stream))),
                        }
                    },
                )
            });
        Some(Box::pin(stream))
    }
}

impl ScopedMdns {
    fn quiesce(&self, inner: &Mutex<Inner>, reason: &str) {
        inner.lock().expect("mDNS lock").stop();
        self.status.update(MdnsSnapshot {
            active: false,
            reason: reason.into(),
            network: NetworkIdentity::default(),
        });
    }

    fn apply(&self, id: EndpointId, inner: &Mutex<Inner>, network: NetworkIdentity) {
        let (allowed, reason) = self.policy.evaluate(&network);
        let mut reason = reason.to_owned();
        let active = {
            let mut inner = inner.lock().expect("mDNS lock");
            if !allowed {
                inner.stop();
            } else if inner.lookup.is_none() {
                match MdnsAddressLookup::builder()
                    .advertise(self.advertise)
                    .build(id)
                {
                    Ok(lookup) => {
                        if let Some(data) = &inner.data {
                            lookup.publish(data);
                        }
                        inner.lookup = Some(lookup);
                    }
                    Err(_) => reason = "mDNS socket initialization failed".into(),
                }
            }
            if !inner.ready {
                inner.ready = true;
                inner.generation.send_modify(|generation| *generation += 1);
            }
            inner.lookup.is_some()
        };
        self.status.update(MdnsSnapshot {
            active,
            reason,
            network,
        });
    }

    async fn run(&self, id: EndpointId, weak: &Weak<Mutex<Inner>>) {
        let Ok(monitor) = netwatch::netmon::Monitor::new().await else {
            self.status.update(MdnsSnapshot {
                reason: "network monitor unavailable".into(),
                ..MdnsSnapshot::default()
            });
            return;
        };
        let mut interfaces = monitor.interface_state();
        // netwatch suppresses equal IP/interface state: SSID-only roams need a recheck.
        let mut recheck = tokio::time::interval(Duration::from_secs(10));
        recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        recheck.reset();
        let mut previous_network = NetworkIdentity::default();
        loop {
            let state = interfaces.get();
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let network = tokio::select! {
                network = identify(&state) => network,
                result = interfaces.updated() => {
                    self.quiesce(&inner, "network changed during identity detection");
                    if result.is_err() { return; }
                    continue;
                },
            };
            // Never enable using identity captured before a concurrent route change.
            if interfaces.update() {
                self.quiesce(&inner, "network changed during identity detection");
                continue;
            }
            if previous_network != network {
                inner.lock().expect("mDNS lock").stop();
            }
            previous_network = network.clone();
            self.apply(id, &inner, network);
            tokio::select! {
                result = interfaces.updated() => {
                    if result.is_err() {
                        self.quiesce(&inner, "network monitor stopped");
                        return;
                    }
                    // Quiesce before asynchronous identity detection on the new network.
                    self.quiesce(&inner, "network changed; checking policy");
                },
                _ = recheck.tick() => {},
            }
        }
    }
}

async fn identify(state: &netwatch::netmon::State) -> NetworkIdentity {
    let mut links = Vec::new();
    for interface in state.interfaces.values().filter(|i| i.is_up()) {
        let mut addresses: Vec<_> = interface
            .addrs()
            .map(|a| a.addr())
            .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
            .collect();
        if addresses.is_empty() {
            continue;
        }
        addresses.sort_unstable();
        links.push(NetworkLink {
            interface: interface.name().into(),
            ssid: ssid(interface.name()).await,
            addresses,
        });
    }
    links.sort_by(|a, b| a.interface.cmp(&b.interface));
    NetworkIdentity { links }
}

async fn command(program: &str, args: &[&str]) -> Option<String> {
    let mut command = tokio::process::Command::new(program);
    command.args(args).env("LC_ALL", "C").kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(2), command.output())
        .await
        .ok()?
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn visible_ssid(value: &str) -> Option<String> {
    // Keep meaningful SSID whitespace. Ambiguously escaped tool output is
    // unknown rather than a false nonmatch against a configured deny rule.
    (!value.is_empty() && !value.contains("<redacted>") && !value.contains("\\x") && value != "--")
        .then(|| value.to_owned())
}

// Return the raw field so callers distinguish absent from explicitly redacted.
fn ssid_field<'a>(output: &'a str, prefix: &str) -> Option<&'a str> {
    output
        .lines()
        .find_map(|line| line.trim_start().strip_prefix(prefix))
}

#[cfg(target_os = "macos")]
async fn ssid(interface: &str) -> Option<String> {
    if let Some(summary) = command("/usr/sbin/ipconfig", &["getsummary", interface]).await {
        if let Some(ssid) = ssid_field(&summary, "SSID : ") {
            return visible_ssid(ssid);
        }
    }
    let output = command("/usr/sbin/networksetup", &["-getairportnetwork", interface]).await?;
    ssid_field(&output, "Current Wi-Fi Network: ").and_then(visible_ssid)
}

#[cfg(target_os = "linux")]
async fn ssid(interface: &str) -> Option<String> {
    if let Some(link) = command("iw", &["dev", interface, "link"]).await
        && let Some(ssid) = ssid_field(&link, "SSID: ")
    {
        return visible_ssid(ssid);
    }
    // /proc/net/wireless identifies Wi-Fi interfaces but does not contain the SSID.
    let wireless = tokio::fs::read_to_string("/proc/net/wireless").await.ok()?;
    if !wireless
        .lines()
        .any(|l| l.trim_start().starts_with(&format!("{interface}:")))
    {
        return None;
    }
    let output = command(
        "nmcli",
        &[
            "-t",
            "--escape",
            "no",
            "-f",
            "ACTIVE,SSID",
            "device",
            "wifi",
            "list",
            "ifname",
            interface,
            "--rescan",
            "no",
        ],
    )
    .await?;
    ssid_field(&output, "yes:").and_then(visible_ssid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn ssid(_interface: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(ssid: Option<&str>, address: &str) -> NetworkIdentity {
        NetworkIdentity {
            links: vec![NetworkLink {
                interface: "en0".into(),
                ssid: ssid.map(str::to_owned),
                addresses: vec![address.parse().unwrap()],
            }],
        }
    }

    fn policy(text: &str) -> LocalPolicy {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn deny_wins_and_every_active_network_must_be_allowed() {
        let p = policy("allow = [{ interface = 'en0' }]\ndeny = [{ ssid = 'TCB-BYOD' }]");
        assert!(!p.evaluate(&network(Some("TCB-BYOD"), "10.61.176.2")).0);
        assert!(p.evaluate(&network(Some("home"), "192.168.1.4")).0);
        let mut two = network(Some("home"), "192.168.1.4");
        two.links.push(NetworkLink {
            interface: "eth0".into(),
            ssid: None,
            addresses: vec!["10.0.0.2".parse().unwrap()],
        });
        assert!(!p.evaluate(&two).0);
        let p = policy("unknown = 'allow'\ndeny = [{ ssid = 'TCB-BYOD' }]");
        assert!(!p.evaluate(&network(Some("TCB-BYOD"), "10.61.176.2")).0);
    }

    #[test]
    fn unavailable_ssid_is_not_a_nonmatch_and_defaults_fail_closed_with_rules() {
        let hidden = network(None, "192.168.1.4");
        assert!(LocalPolicy::default().evaluate(&hidden).0);
        assert!(
            LocalPolicy::default()
                .evaluate(&NetworkIdentity::default())
                .0
        );
        for text in [
            "deny = [{ ssid = 'TCB-BYOD' }]",
            "allow = [{ ssid = 'home' }]",
        ] {
            let mut p = policy(text);
            assert!(!p.evaluate(&hidden).0);
            assert!(!p.evaluate(&NetworkIdentity::default()).0);
            p.unknown = Some(UnknownNetwork::Allow);
            assert!(p.evaluate(&hidden).0);
        }
        // A definite allow cannot bypass a deny whose SSID could not be read.
        let p = policy("allow = [{ interface = 'en0' }]\ndeny = [{ ssid = 'TCB-BYOD' }]");
        assert!(!p.evaluate(&hidden).0);
        let p = policy("enabled = false\nunknown = 'allow'");
        assert!(!p.evaluate(&hidden).0);
    }

    #[test]
    fn interface_and_cidr_fallbacks_work_without_ssid_and_rules_are_conjunctions() {
        let p = policy("deny = [{ interface = 'en0', subnet = '10.61.176.0/20' }]");
        for ip in ["10.61.176.1", "10.61.191.255"] {
            assert!(!p.evaluate(&network(None, ip)).0);
        }
        for ip in ["10.61.175.255", "10.61.192.0"] {
            assert!(p.evaluate(&network(None, ip)).0);
        }
        let p = policy("allow = [{ interface = 'en0', subnet = 'fd12:3456::/48' }]");
        assert!(p.evaluate(&network(None, "fd12:3456:0:2::1")).0);
        assert!(!p.evaluate(&network(None, "fd12:3456:1::1")).0);
        let mut wrong_interface = network(None, "fd12:3456::1");
        wrong_interface.links[0].interface = "en1".into();
        assert!(!p.evaluate(&wrong_interface).0);
    }

    #[test]
    fn local_shorthand_and_policy_validate_and_redaction_stays_unknown() {
        #[derive(Deserialize)]
        struct Config {
            local: LocalDiscovery,
        }
        for enabled in [true, false] {
            let c: Config = toml::from_str(&format!("local = {enabled}")).unwrap();
            assert_eq!(c.local, LocalDiscovery::Enabled(enabled));
        }
        let c: Config =
            toml::from_str("[local]\ndeny = [{ ssid = 'TCB-BYOD' }]\nunknown = 'deny'").unwrap();
        let LocalDiscovery::Policy(p) = c.local else {
            panic!("policy expected")
        };
        p.validate().unwrap();
        assert!(policy("deny = [{}]").validate().is_err());
        assert!(policy("allow = [{ interface = '' }]").validate().is_err());
        assert!(toml::from_str::<LocalPolicy>("deny = [{ subnet = '10.0.0.1/33' }]").is_err());
        assert!(toml::from_str::<LocalPolicy>("unknown = 'ignore'").is_err());
        for value in ["", "<redacted>", " <redacted> ", "--"] {
            assert_eq!(visible_ssid(value), None);
        }
        assert_eq!(visible_ssid("TCB-BYOD"), Some("TCB-BYOD".into()));
        for (output, prefix) in [
            ("  SSID : TCB-BYOD\n  Security : None", "SSID : "),
            (
                "Current Wi-Fi Network: TCB-BYOD\n",
                "Current Wi-Fi Network: ",
            ),
            (
                "Connected to 00:00:00:00:00:00\n\tSSID: TCB-BYOD\n",
                "SSID: ",
            ),
            ("no:other\nyes:TCB-BYOD\n", "yes:"),
        ] {
            assert_eq!(
                ssid_field(output, prefix).map(visible_ssid),
                Some(Some("TCB-BYOD".into()))
            );
        }
        assert_eq!(
            ssid_field("SSID : <redacted>", "SSID : ").map(visible_ssid),
            Some(None)
        );
        assert_eq!(
            ssid_field("yes:Home ", "yes:").and_then(visible_ssid),
            Some("Home ".into())
        );
        assert_eq!(
            ssid_field("SSID: Home\\x20", "SSID: ").and_then(visible_ssid),
            None
        );
        assert_eq!(
            ssid_field(
                "You are not associated with an AirPort network.",
                "Current Wi-Fi Network: "
            ),
            None
        );
    }

    #[tokio::test]
    async fn runtime_gate_closes_inflight_resolution_and_reopens_on_allowed_network() {
        let id = iroh_base::SecretKey::generate().public();
        let inner = Arc::new(Mutex::new(Inner {
            lookup: None,
            data: None,
            ready: false,
            generation: watch::channel(0).0,
        }));
        let gate = GatedLookup {
            inner: inner.clone(),
            _task: AbortOnDropHandle::new(tokio::spawn(std::future::pending())),
        };
        let scoped = ScopedMdns {
            policy: policy("deny = [{ subnet = '10.61.176.0/20' }]"),
            advertise: true,
            status: MdnsStatus::default(),
        };
        let peer = iroh_base::SecretKey::generate().public();
        let mut early = gate.resolve(peer).expect("query waits for initial policy");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), early.next())
                .await
                .is_err()
        );
        scoped.apply(id, &inner, network(None, "192.168.1.4"));
        assert!(scoped.status.snapshot().active);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), early.next())
                .await
                .is_err()
        );
        let mut pending = gate.resolve(peer).expect("allowed network resolves");
        scoped.apply(id, &inner, network(None, "10.61.176.2"));
        assert!(!scoped.status.snapshot().active);
        assert!(gate.resolve(peer).is_none());
        assert!(early.next().await.is_none());
        assert!(
            tokio::time::timeout(Duration::from_secs(1), pending.next())
                .await
                .unwrap()
                .is_none()
        );
        scoped.apply(id, &inner, network(None, "192.168.1.4"));
        assert!(scoped.status.snapshot().active);
        assert!(gate.resolve(peer).is_some());
    }
}
