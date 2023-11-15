use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;
use wireguard_keys::{Privkey, Pubkey};

#[derive(Eq, PartialEq, Debug)]
pub struct WireguardConfig {
    pub private_key: Privkey,
    pub if_address: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
    pub public_key: Pubkey,
    pub allowed_ipv4_range: IpRange<Ipv4Net>,
    pub allowed_ipv6_range: IpRange<Ipv6Net>,
    pub endpoint: String,
    pub routing_id: [u8; 3],
}

impl Display for WireguardConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        macro_rules! write_kv {
            ($k:expr, $v:expr) => {
                writeln!(f, "{} = {}", $k, $v)
            };
        }

        write!(f, "# routing-id: 0x")?;
        write!(f, "{:02x?}", &self.routing_id[0])?;
        write!(f, "{:02x?}", &self.routing_id[1])?;
        writeln!(f, "{:02x?}", &self.routing_id[2])?;

        writeln!(f, "[Interface]")?;
        write_kv!("PrivateKey", self.private_key.to_base64())?;

        for addr in &self.if_address {
            write_kv!("Address", addr.to_string())?;
        }
        for dns in &self.dns {
            write_kv!("DNS", dns.to_string())?;
        }

        write_kv!("MTU", self.mtu.to_string())?;

        writeln!(f)?;
        writeln!(f, "[Peer]")?;
        write_kv!("PublicKey", self.public_key.to_base64())?;

        for cidr in self.allowed_ipv6_range.iter() {
            write_kv!("AllowedIPs", cidr.to_string())?;
        }
        for cidr in self.allowed_ipv4_range.iter() {
            write_kv!("AllowedIPs", cidr.to_string())?;
        }

        write_kv!("Endpoint", self.endpoint.to_string())?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr};

    use ipnet::{IpNet, Ipv4Net};
    use iprange::IpRange;
    use wireguard_keys::{Privkey, Pubkey};

    use crate::registration::WG_MTU;
    use crate::wireguard_config::WireguardConfig;

    #[test]
    fn test_wg_profile_generation() {
        let privkey = Privkey::parse("iHtAU4H3BRyVqrw3dNd9Exwh4eZvsiOgw0Gqb0oHB3U=").unwrap();
        let pubkey = Pubkey::parse("bmXOC+F1FxEMF9dyjK2H5/1SUtzH0JuVo51h2wPfgyo=").unwrap();

        let profile = r#"
# routing-id: 0x010203
[Interface]
PrivateKey = iHtAU4H3BRyVqrw3dNd9Exwh4eZvsiOgw0Gqb0oHB3U=
Address = 172.0.0.1/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = bmXOC+F1FxEMF9dyjK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = ::/0
AllowedIPs = 0.0.0.0/0
Endpoint = engage.cloudflareclient.com
    "#;
        let mut v4range = IpRange::new();
        v4range.add("0.0.0.0/0".parse().unwrap());
        let mut v6range = IpRange::new();
        v6range.add("::/0".parse().unwrap());
        let cfg = WireguardConfig {
            private_key: privkey,
            if_address: vec![IpNet::V4(
                Ipv4Net::new(Ipv4Addr::new(172, 0, 0, 1), 32).unwrap(),
            )],
            dns: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            mtu: WG_MTU,
            public_key: pubkey,
            allowed_ipv4_range: v4range,
            allowed_ipv6_range: v6range,
            endpoint: String::from("engage.cloudflareclient.com"),
            routing_id: [1, 2, 3],
        };

        assert_eq!(profile.trim(), format!("{}", cfg).trim());
    }
}
