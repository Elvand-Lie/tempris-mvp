use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAddress {
    pub interface: String,
    pub ip: String,
    pub prefix: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkState {
    pub observed_at: String,
    pub addresses: Vec<NetworkAddress>,
}

pub fn observe() -> io::Result<NetworkState> {
    let mut addresses = Vec::new();
    for iface in get_if_addrs::get_if_addrs()? {
        if iface.is_loopback() {
            continue;
        }
        let (ip, prefix) = match iface.addr {
            get_if_addrs::IfAddr::V4(addr) => (IpAddr::V4(addr.ip), u32::from(addr.netmask).count_ones() as u8),
            get_if_addrs::IfAddr::V6(addr) => (IpAddr::V6(addr.ip), u128::from(addr.netmask).count_ones() as u8),
        };
        if ip.is_unspecified() {
            continue;
        }
        addresses.push(NetworkAddress { interface: iface.name, ip: ip.to_string(), prefix });
    }
    Ok(NetworkState {
        observed_at: Utc::now().to_rfc3339(),
        addresses,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_returns_valid_prefixes_and_parses_back() {
        let state = observe().expect("interface enumeration should succeed on a live host");
        for address in &state.addresses {
            let ip: IpAddr = address.ip.parse().expect("address must parse");
            match ip {
                IpAddr::V4(_) => assert!(address.prefix <= 32),
                IpAddr::V6(_) => assert!(address.prefix <= 128),
            }
            assert!(!address.interface.is_empty());
        }
        let json = serde_json::to_string(&state).expect("network state must serialize");
        let parsed: NetworkState = serde_json::from_str(&json).expect("network state must round-trip");
        assert_eq!(parsed.addresses.len(), state.addresses.len());
    }
}
