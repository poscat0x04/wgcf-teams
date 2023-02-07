use std::{fmt, io};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Local, Utc};
use clap::Parser;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;
use reqwest::Client;
use reqwest::header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, CONNECTION, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{to_string_pretty, Value};
use serde_with::{base64::Base64, serde_as};
use tokio;
use wireguard_keys::{Privkey, Pubkey};

const API_ENDPOINT: &str = "https://api.cloudflareclient.com/v0i2209280024/reg";
const INSTRUCTION_URL: &str = "https://github.com/poscat0x04/wgcf-teams/blob/master/guide.md";
const WG_MTU: u16 = 1420;
const V4_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
const V6_DNS: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0x0, 0x0, 0x0, 0x0, 0x1111));

#[derive(Parser)]
#[command(author, version)]
#[command(about = "Generate wireguard config for WARP for teams")]
struct Arg {
    // @formatter:off
    #[arg(
        long,
        help = "the name of your zero trust organization"
    )]
    // @formatter:on
    org: String,
    // @formatter:off
    #[arg(
        short = 'p',
        long,
        default_value_t = false,
        help = "prompt for wireguard private key instead of randomly generating one"
    )]
    // @formatter:on
    prompt: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let arg = Arg::parse();

    let privkey = get_wg_privkey(arg.prompt)?;
    let token =
        get_jwt_token(&arg.org[..]).await
            .context("Failed to get jwt token")?;

    let client =
        build_client().await
            .context("Failed to build reqwest client")?;
    let reg = Registration::new(privkey);
    let req =
        client
            .post(API_ENDPOINT)
            .json(&reg)
            .header("Cf-Access-Jwt-Assertion", token.trim())
            .build()
            .context("Failed to build request to cloudflare API")?;
    let raw_resp =
        client
            .execute(req).await
            .context("Request to cloudflare API failed")?;
    let resp: CFResp<RegistrationResult> =
        raw_resp
            .json().await
            .context("Failed to parse the result returned by cloudflare")?;
    let result =
        resp
            .get_result()
            .context("Request failed")?;
    let wg_config = result.to_wg_config(privkey)?;

    println!("{wg_config}");
    Ok(())
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct Registration {
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
struct RequestFailure {
    errors: Vec<CFError>,
    messages: Vec<Value>,
}

impl Display for RequestFailure {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Request to Cloudflare API has failed with errors:")?;
        for err in &self.errors {
            writeln!(f, "")?;
            writeln!(f, "{}",
                     to_string_pretty(err)
                         .expect("Impossible, failed to pretty print error")
            )?;
        }
        writeln!(f, "")?;
        writeln!(f, "And messages:")?;
        for msg in &self.messages {
            writeln!(f, "")?;
            writeln!(f, "{}",
                     to_string_pretty(msg)
                         .expect("Impossible, failed to pretty print error")
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
struct CFResp<T> {
    result: Option<T>,
    success: bool,
    errors: Vec<CFError>,
    messages: Vec<Value>,
}

impl<T> CFResp<T> {
    fn get_result(self) -> Result<T, RequestFailure> {
        match self.result {
            Some(t) => Ok(t),
            None => Err(RequestFailure {
                errors: self.errors,
                messages: self.messages,
            })
        }
    }
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct RegistrationResult {
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
    pub fn to_inet_vec(self) -> Vec<IpNet> {
        let mut v = Vec::new();
        let v6inet =
            Ipv6Net::new(self.v6, 128)
                .expect("Impossible, 128 is a valid netmask length for ipv6 addresses");
        let v4inet =
            Ipv4Net::new(self.v4, 32)
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

#[derive(Eq, PartialEq, Debug)]
struct WireguardConfig {
    private_key: Privkey,
    if_address: Vec<IpNet>,
    dns: Vec<IpAddr>,
    mtu: u16,
    public_key: Pubkey,
    allowed_ipv4_range: IpRange<Ipv4Net>,
    allowed_ipv6_range: IpRange<Ipv6Net>,
    endpoint: String,
    routing_id: [u8; 3],
}

impl Display for WireguardConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        macro_rules! write_kv {
            ($k:expr, $v:expr) => {
                writeln!(f, "{} = {}", $k, $v)
            }
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

        writeln!(f, "")?;
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

impl WgIFConfig {
    pub fn to_inet_vec(self) -> Vec<IpNet> {
        self.addresses.to_inet_vec()
    }
}

// TODO: add ip range exclusion logic
impl WarpConfig {
    pub fn to_wg_config(mut self, privkey: Privkey) -> Result<WireguardConfig> {
        let peer =
            self.peers.pop()
                .with_context(|| format!(
                    "Warp config contains no peers: {}",
                    to_string_pretty(&self)
                        .expect("Impossible, failed to serialize a WarpConfig to JSON")
                ))?;
        let addrs = self.interface.to_inet_vec();

        let mut v4range: IpRange<Ipv4Net> = IpRange::new();
        v4range.add("0.0.0.0/0".parse().expect("Impossible, failed to parse '0.0.0.0/0'"));

        let mut v6range: IpRange<Ipv6Net> = IpRange::new();
        v6range.add("::/0".parse().expect("Impossible, failed to parse '::/0'"));

        let mut dns = Vec::new();
        dns.push(V4_DNS);
        dns.push(V6_DNS);

        Ok(WireguardConfig {
            private_key: privkey,
            public_key: peer.public_key,
            endpoint: peer.endpoint.host,
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
    pub fn to_wg_config(self, privkey: Privkey) -> Result<WireguardConfig> {
        self.config.to_wg_config(privkey)
    }
}

pub async fn build_client() -> reqwest::Result<Client> {
    let mut hdr = HeaderMap::new();
    hdr.insert(ACCEPT_ENCODING, HeaderValue::from_str("gzip").unwrap());
    hdr.insert(ACCEPT_LANGUAGE, HeaderValue::from_str("en-US,en;q=0.9").unwrap());
    hdr.insert(ACCEPT, HeaderValue::from_str("*/*").unwrap());
    hdr.insert(CONNECTION, HeaderValue::from_str("keep-alive").unwrap());
    hdr.insert(HeaderName::from_bytes(b"CF-Client-Version").unwrap()
               , HeaderValue::from_str("i-6.16-2209280024.1").unwrap());
    Client::builder()
        .user_agent("1.1.1.1/2209280024.1 CFNetwork/1399 Darwin/22.1.0")
        .default_headers(hdr)
        .cookie_store(true)
        .gzip(true)
        .timeout(Duration::from_secs(10))
        .build()
}

pub fn get_wg_privkey(prompt: bool) -> Result<Privkey> {
    if prompt {
        eprintln!("Please paste your wireguard private key to register for and press enter:");
        let mut str = String::new();
        io::stdin().read_line(&mut str)
            .context("Failed to read from stdin")?;
        Privkey::parse(str.trim_end())
            .context("Failed to parse wireguard private key")
    } else {
        Ok(Privkey::generate())
    }
}

pub async fn get_jwt_token(org: &str) -> io::Result<String> {
    eprintln!("Please log in to warp, paste the JWT token and press enter.");
    eprintln!("For a detailed instruction on where to find the JWT token after login, see {}.", INSTRUCTION_URL);
    tokio::time::sleep(Duration::from_secs(5)).await;
    webbrowser::open(format!("https://{org}.cloudflareaccess.com/warp").as_str())?;
    let mut str = String::new();
    io::stdin().read_line(&mut str)?;
    Ok(str)
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr};

    use ipnet::{IpNet, Ipv4Net};
    use iprange::IpRange;
    use serde_json::*;
    use wireguard_keys::{Privkey, Pubkey};

    use crate::{CFResp, RegistrationResult, V4_DNS, V6_DNS, WG_MTU, WireguardConfig};

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
        let res: RegistrationResult = from_str::<CFResp<_>>(TEST_FILE).unwrap().get_result().unwrap();
        let privkey =
            Privkey::parse("iHtAU4H3BRyVqrw3dNd9Exwh4eZvsiOgw0Gqb0oHB3U=").unwrap();

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

    //noinspection ALL
    #[test]
    fn test_wg_profile_generation() {
        let privkey =
            Privkey::parse("iHtAU4H3BRyVqrw3dNd9Exwh4eZvsiOgw0Gqb0oHB3U=").unwrap();
        let pubkey =
            Pubkey::parse("bmXOC+F1FxEMF9dyjK2H5/1SUtzH0JuVo51h2wPfgyo=").unwrap();

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
            if_address: vec![IpNet::V4(Ipv4Net::new(Ipv4Addr::new(172, 0, 0, 1), 32).unwrap())],
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
