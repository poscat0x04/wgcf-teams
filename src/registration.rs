use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use anyhow::Context;
use chrono::{DateTime, Local, Utc};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;
use serde::{Deserialize, Serialize};
use serde_json::{to_string_pretty, Value};
use serde_with::base64::Base64;
use serde_with::serde_as;
use wireguard_keys::{Privkey, Pubkey};

use crate::wireguard_config::WireguardConfig;

pub const WG_MTU: u16 = 1420;
const V4_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
const V6_DNS: IpAddr = IpAddr::V6(Ipv6Addr::new(
    0x2606, 0x4700, 0x4700, 0x0, 0x0, 0x0, 0x0, 0x1111,
));

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Registration {
    #[serde(rename = "key")]
    pubkey: Pubkey,
    tos: DateTime<Local>,
    model: String,
    fcm_token: String,
    device_token: String,
}

impl Registration {
    pub fn new(privkey: Privkey) -> Self {
        Registration {
            pubkey: privkey.pubkey(),
            tos: Local::now(),
            model: String::from("iPad13,8"),
            fcm_token: String::new(),
            device_token: String::new(),
        }
    }
}

// The error type representing a failed request to the cloudflare API
// Result<T, RequestFailure> should be isomorphic to CFResp<T>
#[derive(Eq, PartialEq, Debug)]
pub struct RequestFailure {
    errors: Vec<CFError>,
    messages: Vec<Value>,
}

impl Display for RequestFailure {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Request to Cloudflare API has failed with errors:")?;
        for err in &self.errors {
            writeln!(f)?;
            writeln!(
                f,
                "{}",
                to_string_pretty(err).expect("Impossible, failed to pretty print error")
            )?;
        }
        writeln!(f)?;
        writeln!(f, "And messages:")?;
        for msg in &self.messages {
            writeln!(f)?;
            writeln!(
                f,
                "{}",
                to_string_pretty(msg).expect("Impossible, failed to pretty print error")
            )?;
        }
        Ok(())
    }
}

impl Error for RequestFailure {}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct CFError {
    code: u16,
    message: String,
    other: Option<HashMap<String, Value>>,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct CFResp<T> {
    result: Option<T>,
    success: bool,
    errors: Vec<CFError>,
    messages: Vec<Value>,
}

impl<T> CFResp<T> {
    pub fn get_result(self) -> anyhow::Result<T, RequestFailure> {
        match self.result {
            Some(t) => Ok(t),
            None => Err(RequestFailure {
                errors: self.errors,
                messages: self.messages,
            }),
        }
    }
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct RegistrationResult {
    id: String,
    version: String,
    updated: DateTime<Utc>,
    #[serde(rename = "type")]
    _type: String,
    #[serde(rename = "key")]
    privkey: String,
    policy: WarpPolicy,
    token: String,
    locale: String,
    config: WarpConfig,
    created: DateTime<Utc>,
    // TODO: Value
    override_codes: Value,
    // TODO: Value
    account: Value,
    install_id: String,
    name: String,
    model: String,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct WarpPolicy {
    app_url: String,
    captive_portal: u32,
    allowed_to_leave: bool,
    switch_locked: bool,
    fallback_domains: Vec<FallbackDomain>,
    service_mode_v2: Value,
    allow_updates: bool,
    support_url: String,
    // TODO: Value
    exclude: Value,
    gateway_unique_id: String,
    allow_mode_switch: bool,
    auto_connect: u8,
    disable_auto_fallback: bool,
    organization: String,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct FallbackDomain {
    suffix: String,
}

#[serde_as]
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct WarpConfig {
    #[serde_as(as = "Base64")]
    client_id: [u8; 3],
    peers: Vec<WgPeer>,
    interface: WgIFConfig,
    metrics: Metrics,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct WgPeer {
    public_key: Pubkey,
    endpoint: WgEndpoint,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct WgEndpoint {
    host: String,
    v4: SocketAddrV4,
    v6: SocketAddrV6,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct WgIFConfig {
    addresses: IFAddrs,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct IFAddrs {
    v4: Ipv4Addr,
    v6: Ipv6Addr,
}

impl IFAddrs {
    pub fn to_inet_vec(&self) -> Vec<IpNet> {
        let mut v = Vec::new();
        let v6inet = Ipv6Net::new(self.v6, 128)
            .expect("Impossible, 128 is a valid netmask length for ipv6 addresses");
        let v4inet = Ipv4Net::new(self.v4, 32)
            .expect("Impossible, 32 is a valid netmask length for ipv4 addresses");
        v.push(IpNet::V6(v6inet));
        v.push(IpNet::V4(v4inet));
        v
    }
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct Services {
    http_proxy: SocketAddr,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct Metrics {
    report: u16,
    ping: u16,
}

impl WgIFConfig {
    pub fn to_inet_vec(&self) -> Vec<IpNet> {
        self.addresses.to_inet_vec()
    }
}

// TODO: add ip range exclusion logic
impl WarpConfig {
    pub fn to_wg_config(&self, privkey: Privkey) -> anyhow::Result<WireguardConfig> {
        let peer = self.peers.first().with_context(|| {
            format!(
                "Warp config contains no peers: {}",
                to_string_pretty(&self)
                    .expect("Impossible, failed to serialize a WarpConfig to JSON")
            )
        })?;
        let addrs = self.interface.to_inet_vec();

        let mut v4range: IpRange<Ipv4Net> = IpRange::new();
        v4range.add(
            "0.0.0.0/0"
                .parse()
                .expect("Impossible, failed to parse '0.0.0.0/0'"),
        );

        let mut v6range: IpRange<Ipv6Net> = IpRange::new();
        v6range.add("::/0".parse().expect("Impossible, failed to parse '::/0'"));

        let dns = vec![V4_DNS, V6_DNS];

        Ok(WireguardConfig {
            private_key: privkey,
            public_key: peer.public_key,
            endpoint: peer.endpoint.host.clone(),
            dns,
            mtu: WG_MTU,
            if_address: addrs,
            allowed_ipv4_range: v4range,
            allowed_ipv6_range: v6range,
            routing_id: self.client_id,
        })
    }
}

impl RegistrationResult {
    pub fn to_wg_config(&self, privkey: Privkey) -> anyhow::Result<WireguardConfig> {
        self.config.to_wg_config(privkey)
    }
}

#[cfg(test)]
mod test {
    use serde_json::*;
    use wireguard_keys::Privkey;

    use crate::registration::{CFResp, RegistrationResult, V4_DNS, V6_DNS};

    const TEST_FILE: &str = r#"
{
  "result" : {
    "id" : "t.a849f2f4-61dd-11ed-8b7d-3acbb31d7d51",
    "version" : "6.16",
    "updated" : "2022-11-11T16:26:56.002100164Z",
    "type" : "i",
    "key" : "/V3c9pAqcqy6SpZRq9bck69mmfFzsTi7mG8TFXW/NwU=",
    "policy" : {
      "app_url" : "https://poscat.cloudflareaccess.com",
      "captive_portal" : 180,
      "allowed_to_leave" : true,
      "switch_locked" : false,
      "fallback_domains" : [
        {
          "suffix" : "home.arpa"
        },
        {
          "suffix" : "intranet"
        },
        {
          "suffix" : "internal"
        },
        {
          "suffix" : "private"
        },
        {
          "suffix" : "localdomain"
        },
        {
          "suffix" : "domain"
        },
        {
          "suffix" : "lan"
        },
        {
          "suffix" : "home"
        },
        {
          "suffix" : "host"
        },
        {
          "suffix" : "corp"
        },
        {
          "suffix" : "local"
        },
        {
          "suffix" : "localhost"
        },
        {
          "suffix" : "invalid"
        },
        {
          "suffix" : "test"
        }
      ],
      "service_mode_v2" : {
        "mode" : "warp"
      },
      "allow_updates" : false,
      "support_url" : "",
      "exclude" : [
        {
          "address" : "10.0.0.0/8"
        },
        {
          "address" : "100.64.0.0/10"
        },
        {
          "address" : "169.254.0.0/16"
        },
        {
          "address" : "172.16.0.0/12"
        },
        {
          "address" : "192.0.0.0/24"
        },
        {
          "address" : "192.168.0.0/16"
        },
        {
          "address" : "224.0.0.0/24"
        },
        {
          "address" : "240.0.0.0/4"
        },
        {
          "address" : "255.255.255.255/32"
        },
        {
          "address" : "fe80::/10"
        },
        {
          "address" : "fd00::/8"
        },
        {
          "address" : "ff01::/16"
        },
        {
          "address" : "ff02::/16"
        },
        {
          "address" : "ff03::/16"
        },
        {
          "address" : "ff04::/16"
        },
        {
          "address" : "ff05::/16"
        },
        {
          "host" : "bilibili.com"
        },
        {
          "host" : "live.bilibili.com"
        }
      ],
      "gateway_unique_id" : "07248f8927685cade2b3b4eb853a8c57",
      "allow_mode_switch" : true,
      "auto_connect" : 0,
      "disable_auto_fallback" : false,
      "organization" : "poscat"
    },
    "token" : "21b87a20-cd76-4305-a5f0-0bf40b8fdc51",
    "locale" : "en-US",
    "config" : {
      "client_id" : "9agP",
      "peers" : [
        {
          "public_key" : "bmXOC+F1FxEMF9dyjK2H5/1SUtzH0JuVo51h2wPfgyo=",
          "endpoint" : {
            "host" : "engage.cloudflareclient.com:2408",
            "v4" : "162.159.193.6:0",
            "v6" : "[2606:4700:100::a29f:c106]:0"
          }
        }
      ],
      "services" : {
        "http_proxy" : "172.16.0.1:2480"
      },
      "interface" : {
        "addresses" : {
          "v4" : "172.16.0.2",
          "v6" : "2606:4700:110:8d80:5ee:f514:1b65:ecfe"
        }
      },
      "metrics" : {
        "report" : 900,
        "ping" : 900
      }
    },
    "created" : "2022-11-11T16:26:56.002100164Z",
    "override_codes" : {
      "disable_for_time" : {
        "seconds" : 86400,
        "secret" : "dfad7ec220d2e0187781d41229114081"
      }
    },
    "account" : {
      "managed" : "not_api_managed",
      "id" : "07248f8927685cace2beb4eb853a8c57",
      "organization" : "poscat",
      "account_type" : "team"
    },
    "install_id" : "",
    "name" : "",
    "model" : "iPad13,8"
  },
  "success" : true,
  "errors" : [

  ],
  "messages" : [

  ]
}
"#;

    #[test]
    fn test_response_parsing() {
        let res: Result<CFResp<RegistrationResult>> = from_str(TEST_FILE);
        assert!(res.is_ok());
        println!("Parse succeeded: {:?}", res.unwrap());
    }

    //noinspection ALL
    #[test]
    fn test_wg_profile_conversion() {
        let res: RegistrationResult = from_str::<CFResp<_>>(TEST_FILE)
            .unwrap()
            .get_result()
            .unwrap();
        let privkey = Privkey::parse("iHtAU4H3BRyVqrw3dNd9Exwh4eZvsiOgw0Gqb0oHB3U=").unwrap();

        let wg_profile = r#"
# routing-id: 0xf5a80f
[Interface]
PrivateKey = iHtAU4H3BRyVqrw3dNd9Exwh4eZvsiOgw0Gqb0oHB3U=
Address = 2606:4700:110:8d80:5ee:f514:1b65:ecfe/128
Address = 172.16.0.2/32
DNS = 1.1.1.1
DNS = 2606:4700:4700::1111
MTU = 1420

[Peer]
PublicKey = bmXOC+F1FxEMF9dyjK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = ::/0
AllowedIPs = 0.0.0.0/0
Endpoint = engage.cloudflareclient.com:2408
        "#;

        let wg_cfg = res.config.to_wg_config(privkey).unwrap();
        assert_eq!(format!("{wg_cfg}").trim(), wg_profile.trim());
    }

    #[test]
    fn test_dns_server_const() {
        assert_eq!(V4_DNS.to_string(), "1.1.1.1");
        assert_eq!(V6_DNS.to_string(), "2606:4700:4700::1111");
    }
}
